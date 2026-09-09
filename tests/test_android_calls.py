"""Phase 7 functional tests for authenticated Android call management."""

from __future__ import annotations

import asyncio
import inspect
import json
import unittest
from datetime import timedelta

from jarvis_devices import (
    AuditLogger,
    ConfirmationManager,
    DeviceActionManager,
    DeviceToolRegistry,
    PermissionPolicy,
    Platform,
    PlatformRegistry,
    ToolContext,
    new_execution_id,
)
from jarvis_devices.android_bridge import (
    AndroidCapabilityUnavailableError,
    AndroidDeviceNotConnectedError,
    AndroidDeviceRevokedError,
    AndroidDeviceStaleError,
    AndroidDeviceUnknownError,
)
from jarvis_devices.android_call_tools import (
    ANDROID_CALL_TOOL_NAMES,
    PHONE_NUMBER_ARGUMENT,
    CallDialTool,
    build_android_call_tools,
)
from jarvis_devices.android_calls import (
    MAX_E164_DIGITS,
    MAX_PHONE_NUMBER_INPUT_LENGTH,
    AndroidCallFailedError,
    AndroidCallInvalidStateError,
    AndroidCallTimeoutError,
    AndroidCallState,
    CallStateMachine,
    CallStateTransitionError,
    PhoneNumberValidationError,
    redact_phone_number,
    validate_phone_number,
)
from jarvis_devices.android_protocol import (
    CAPABILITY_CALL_DIAL,
    CAPABILITY_CALL_STATUS,
    MessageType,
)
from jarvis_devices.enums import RiskLevel, ToolResultStatus
from jarvis_devices.errors import ErrorCode
from jarvis_devices.permissions import PERMISSION_ANDROID_CALL_CONTROL, PERMISSION_ANDROID_CALL_READ

try:
    from .android_call_support import (
        DEFAULT_CALL_CAPABILITIES,
        CallCapablePhone,
        answered,
        call_phone_pair,
    )
    from .android_support import FakeAndroidBridge, complete_pairing, requires_crypto
    from .support import FakeAdapter, FakeClock
except ImportError:  # pragma: no cover
    from android_call_support import DEFAULT_CALL_CAPABILITIES, CallCapablePhone, answered, call_phone_pair
    from android_support import FakeAndroidBridge, complete_pairing, requires_crypto
    from support import FakeAdapter, FakeClock

VALID_DEVICE = "adev-" + "a" * 32
VALID_NUMBER = "+14155552671"


def context(name: str) -> ToolContext:
    return ToolContext(execution_id=new_execution_id(), tool_name=name, platform=Platform.PC)


def confirmation_manager(*, clock=None) -> tuple[DeviceActionManager, CallDialTool]:
    """Manager wired with a harmless available bridge for confirmation-only tests."""
    tool = CallDialTool(build_android_call_tools(FakeAndroidBridge())[0].control)
    registry = DeviceToolRegistry()
    registry.register(tool)
    platforms = PlatformRegistry()
    platforms.register(FakeAdapter(Platform.PC))
    confirmations = ConfirmationManager(
        clock=clock or FakeClock(), default_ttl=timedelta(seconds=30)
    )
    manager = DeviceActionManager(
        registry,
        PermissionPolicy((PERMISSION_ANDROID_CALL_CONTROL,)),
        confirmations,
        platforms,
        AuditLogger(enabled=False),
    )
    return manager, tool


class PhoneNumberValidationTests(unittest.TestCase):
    def test_e164_formatting_is_canonicalized_without_changing_digits(self) -> None:
        self.assertEqual(validate_phone_number("+1 (415) 555-2671"), VALID_NUMBER)
        self.assertEqual(validate_phone_number(" +91 90000-00000 "), "+919000000000")

    def test_e164_boundaries_are_enforced(self) -> None:
        self.assertEqual(validate_phone_number("+" + "1" * 7), "+" + "1" * 7)
        self.assertEqual(validate_phone_number("+" + "9" * MAX_E164_DIGITS), "+" + "9" * MAX_E164_DIGITS)
        for value in ("+123456", "+" + "1" * (MAX_E164_DIGITS + 1)):
            with self.subTest(value_length=len(value)):
                with self.assertRaises(PhoneNumberValidationError):
                    validate_phone_number(value)

    def test_hostile_or_ambiguous_destinations_are_refused_without_echo(self) -> None:
        bad_values = (
            "14155552671", "tel:+14155552671", "sip:alice@example.com",
            "https://example.invalid", "127.0.0.1", "localhost", "8.8.8.8",
            "+14155552671; rm -rf /", "$(whoami)", "adb shell input", "cmd.exe /c calc",
            "powershell -c x", "+14155552671\nnext", "+14155552671\x00",
            "+١٤١٥٥٥٥٢٦٧١", "+14155552671#", "+14155552671*", "api.method",
            "+" + "1" * (MAX_PHONE_NUMBER_INPUT_LENGTH + 1),
        )
        for value in bad_values:
            with self.subTest(kind=value[:12]):
                with self.assertRaises(PhoneNumberValidationError) as caught:
                    validate_phone_number(value)
                self.assertNotIn(value, str(caught.exception))

    def test_redaction_never_returns_the_full_value(self) -> None:
        redacted = redact_phone_number(VALID_NUMBER)
        self.assertNotIn(VALID_NUMBER, redacted)
        self.assertTrue(redacted.startswith("[redacted]"))
        self.assertEqual(redact_phone_number("bad"), "[redacted]")


class DeclarationTests(unittest.TestCase):
    def test_five_dedicated_tools_have_narrow_permissions_and_arguments(self) -> None:
        tools = build_android_call_tools(FakeAndroidBridge())
        self.assertEqual(tuple(tool.name for tool in tools), ANDROID_CALL_TOOL_NAMES)
        self.assertEqual(len(tools), 5)
        self.assertEqual(len(set(ANDROID_CALL_TOOL_NAMES)), 5)
        expected = {
            "android.call.status": (RiskLevel.SAFE, PERMISSION_ANDROID_CALL_READ, ("device",), None, False),
            "android.call.dial": (RiskLevel.EXTERNAL_ACTION, PERMISSION_ANDROID_CALL_CONTROL, ("device", "phone_number"), True, True),
            "android.call.answer": (RiskLevel.EXTERNAL_ACTION, PERMISSION_ANDROID_CALL_CONTROL, ("device",), True, False),
            "android.call.reject": (RiskLevel.EXTERNAL_ACTION, PERMISSION_ANDROID_CALL_CONTROL, ("device",), True, False),
            "android.call.end": (RiskLevel.EXTERNAL_ACTION, PERMISSION_ANDROID_CALL_CONTROL, ("device",), True, False),
        }
        for tool in tools:
            risk, permission, arguments, confirmation, mandatory = expected[tool.name]
            with self.subTest(tool=tool.name):
                self.assertIs(tool.risk_level, risk)
                self.assertEqual(tool.required_permissions, (permission,))
                self.assertEqual(tool.argument_schema.names, arguments)
                self.assertEqual(tool.requires_confirmation, confirmation)
                self.assertEqual(tool.confirmation_mandatory, mandatory)
                self.assertIs(tool.platform, Platform.PC)

    def test_dial_schema_has_only_device_and_bounded_phone_number(self) -> None:
        self.assertEqual(PHONE_NUMBER_ARGUMENT.max_length, MAX_PHONE_NUMBER_INPUT_LENGTH)
        tool = build_android_call_tools(FakeAndroidBridge())[1]
        for extra in (
            {"call_id": "x"}, {"session": "x"}, {"method": "x"}, {"api": "x"},
            {"url": "x"}, {"host": "x"}, {"confirm": False}, {"retry": True},
        ):
            with self.subTest(extra=next(iter(extra))):
                _, errors = tool.argument_schema.validate(
                    {"device": VALID_DEVICE, "phone_number": VALID_NUMBER, **extra}
                )
                self.assertTrue(errors)

    def test_confirmation_function_requires_an_explicit_approval_argument(self) -> None:
        import Jarvis_device_control as bridge

        self.assertEqual(
            inspect.signature(bridge.resolve_device_confirmation).parameters["approved"].default,
            inspect.Parameter.empty,
        )


class ConfirmationBindingTests(unittest.IsolatedAsyncioTestCase):
    async def test_dial_is_pending_and_binds_canonical_device_number_and_operation(self) -> None:
        manager, _ = confirmation_manager()
        result = await manager.request(
            "android.call.dial", {"device": VALID_DEVICE, "phone_number": "+1 (415) 555-2671"}
        )
        self.assertEqual(result.status, ToolResultStatus.PENDING_CONFIRMATION)
        request = manager.confirmations.require(result.data["confirmation_id"])
        self.assertEqual(request.action, "android.call.dial")
        self.assertEqual(request.arguments, {"device": VALID_DEVICE, "phone_number": VALID_NUMBER})
        self.assertIn(VALID_DEVICE, request.target)
        self.assertIn(VALID_NUMBER, request.target)
        self.assertIn("Place call", request.target)
        # The target is confirmation UI state, not an audit/debug field.
        self.assertNotIn(VALID_NUMBER, request.describe())
        self.assertNotIn(VALID_NUMBER, repr(manager.audit.records))

    async def test_invalid_number_is_refused_before_confirmation_or_bridge_use(self) -> None:
        manager, _ = confirmation_manager()
        bad = "tel:+14155552671"
        result = await manager.request("android.call.dial", {"device": VALID_DEVICE, "phone_number": bad})
        self.assertEqual(result.status, ToolResultStatus.INVALID_ARGUMENT)
        self.assertEqual(result.error_code, ErrorCode.INVALID_ARGUMENT)
        self.assertNotIn(bad, result.message)
        self.assertEqual(manager.confirmations.pending(), ())

    async def test_confirmation_cannot_migrate_between_normalized_numbers_or_devices(self) -> None:
        manager, _ = confirmation_manager()
        pending = await manager.request(
            "android.call.dial", {"device": VALID_DEVICE, "phone_number": VALID_NUMBER}
        )
        cid = pending.data["confirmation_id"]
        manager.confirmations.confirm(cid)
        number_changed = await manager.request(
            "android.call.dial", {"device": VALID_DEVICE, "phone_number": "+14155552672"}, confirmation_id=cid
        )
        device_changed = await manager.request(
            "android.call.dial", {"device": "adev-" + "b" * 32, "phone_number": VALID_NUMBER}, confirmation_id=cid
        )
        self.assertEqual(number_changed.error_code, ErrorCode.CONFIRMATION_MISMATCH)
        self.assertEqual(device_changed.error_code, ErrorCode.CONFIRMATION_MISMATCH)

    async def test_expired_confirmation_never_executes(self) -> None:
        clock = FakeClock()
        manager, _ = confirmation_manager(clock=clock)
        pending = await manager.request(
            "android.call.dial", {"device": VALID_DEVICE, "phone_number": VALID_NUMBER}
        )
        clock.advance(timedelta(seconds=31))
        result = await manager.resolve_confirmation(pending.data["confirmation_id"], True)
        self.assertEqual(result.error_code, ErrorCode.CONFIRMATION_EXPIRED)

    async def test_confirmed_and_consumed_dial_confirmation_cannot_be_reused(self) -> None:
        manager, _ = confirmation_manager()
        pending = await manager.request(
            "android.call.dial", {"device": VALID_DEVICE, "phone_number": VALID_NUMBER}
        )
        cid = pending.data["confirmation_id"]
        manager.confirmations.confirm(cid)
        self.assertTrue(manager.confirmations.consume(cid))
        result = await manager.request(
            "android.call.dial", {"device": VALID_DEVICE, "phone_number": VALID_NUMBER}, confirmation_id=cid
        )
        self.assertEqual(result.error_code, ErrorCode.CONFIRMATION_REUSED)

    @requires_crypto
    async def test_explicit_approval_executes_only_the_bound_canonical_dial_once(self) -> None:
        bridge, phone, _, _, _ = await call_phone_pair()
        tools = build_android_call_tools(bridge)
        registry = DeviceToolRegistry()
        for tool in tools:
            registry.register(tool)
        platforms = PlatformRegistry()
        platforms.register(FakeAdapter(Platform.PC))
        manager = DeviceActionManager(
            registry,
            PermissionPolicy((PERMISSION_ANDROID_CALL_READ, PERMISSION_ANDROID_CALL_CONTROL)),
            ConfirmationManager(),
            platforms,
            AuditLogger(enabled=False),
        )
        pending = await manager.request(
            "android.call.dial", {"device": phone.device_id, "phone_number": "+1 (415) 555-2671"}
        )
        self.assertEqual(pending.status, ToolResultStatus.PENDING_CONFIRMATION)
        # No frame/action before an explicit yes.
        self.assertEqual(phone.call_controller.calls, [])
        result = await answered(manager.resolve_confirmation(pending.data["confirmation_id"], True), phone)
        self.assertTrue(result.success)
        self.assertEqual(phone.call_controller.state, AndroidCallState.DIALING)
        self.assertEqual(phone.call_controller.calls, [("dial", ("[redacted]71",))])

    @requires_crypto
    async def test_declined_dial_confirmation_never_sends_a_frame(self) -> None:
        bridge, phone, _, _, _ = await call_phone_pair()
        tools = build_android_call_tools(bridge)
        registry = DeviceToolRegistry()
        for tool in tools:
            registry.register(tool)
        platforms = PlatformRegistry()
        platforms.register(FakeAdapter(Platform.PC))
        manager = DeviceActionManager(
            registry,
            PermissionPolicy((PERMISSION_ANDROID_CALL_READ, PERMISSION_ANDROID_CALL_CONTROL)),
            ConfirmationManager(),
            platforms,
            AuditLogger(enabled=False),
        )
        pending = await manager.request(
            "android.call.dial", {"device": phone.device_id, "phone_number": VALID_NUMBER}
        )
        result = await manager.resolve_confirmation(pending.data["confirmation_id"], False)
        self.assertEqual(result.status, ToolResultStatus.DENIED)
        self.assertEqual(phone.call_controller.calls, [])


class StateMachineTests(unittest.TestCase):
    def test_valid_state_paths_and_invalid_jump(self) -> None:
        machine = CallStateMachine()
        machine.observe(VALID_DEVICE, AndroidCallState.IDLE)
        for state in (AndroidCallState.DIALING, AndroidCallState.ACTIVE, AndroidCallState.ENDING, AndroidCallState.IDLE):
            self.assertEqual(machine.observe(VALID_DEVICE, state), state)
        machine.observe(VALID_DEVICE, AndroidCallState.RINGING)
        self.assertEqual(machine.observe(VALID_DEVICE, AndroidCallState.ACTIVE), AndroidCallState.ACTIVE)
        other = CallStateMachine()
        other.observe(VALID_DEVICE, AndroidCallState.IDLE)
        with self.assertRaises(CallStateTransitionError):
            other.observe(VALID_DEVICE, AndroidCallState.ACTIVE)


@requires_crypto
class CallControlFunctionalTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.bridge, self.phone, self.control, self.pc_side, _ = await call_phone_pair()
        self.did = self.phone.device_id

    async def call(self, coro):
        return await answered(coro, self.phone)

    async def test_status_dial_active_and_end_flow_over_the_real_protocol(self) -> None:
        initial = await self.call(self.control.status(self.did))
        self.assertEqual(initial["state"], "idle")
        dialing = await self.call(self.control.dial(self.did, "+1 (415) 555-2671"))
        self.assertEqual(dialing["state"], "dialing")
        frame = json.loads(bytes(self.pc_side.sent[-1]).decode("utf-8"))
        self.assertEqual(frame["message_type"], MessageType.CALL_DIAL.value)
        self.assertEqual(frame["payload"], {"phone_number": VALID_NUMBER})
        self.phone.call_controller.complete_dial()
        active = await self.call(self.control.status(self.did))
        self.assertEqual(active["state"], "active")
        ending = await self.call(self.control.end(self.did))
        self.assertTrue(ending["ended"])
        self.assertEqual(ending["state"], "ending")
        self.phone.call_controller.complete_end()
        idle = await self.call(self.control.status(self.did))
        self.assertEqual(idle["state"], "idle")

    async def test_ringing_answer_and_reject_flow(self) -> None:
        self.phone.call_controller.begin_ringing()
        status = await self.call(self.control.status(self.did))
        self.assertEqual((status["state"], status["direction"]), ("ringing", "incoming"))
        answer = await self.call(self.control.answer(self.did))
        self.assertEqual(answer["state"], "active")
        # End and complete the answered call before exercising an independent
        # incoming/reject path; all transitions remain allowlisted.
        await self.call(self.control.end(self.did))
        self.phone.call_controller.complete_end()
        await self.call(self.control.status(self.did))
        self.phone.call_controller.begin_ringing()
        await self.call(self.control.status(self.did))
        reject = await self.call(self.control.reject(self.did))
        self.assertTrue(reject["rejected"])
        self.assertEqual(reject["state"], "idle")

    async def test_end_when_idle_never_claims_success(self) -> None:
        result = await self.call(self.control.end(self.did))
        self.assertFalse(result["ended"])
        tools = {tool.name: tool for tool in build_android_call_tools(self.bridge)}
        tool_result = await self.call(tools["android.call.end"].execute({"device": self.did}, context("android.call.end")))
        self.assertFalse(tool_result.success)
        self.assertEqual(tool_result.error_code, ErrorCode.ANDROID_CALL_NO_ACTIVE_CALL)

    async def test_device_failures_and_timeout_are_structured_without_retry(self) -> None:
        for name, method in (("dial", self.control.dial), ("answer", self.control.answer), ("reject", self.control.reject), ("end", self.control.end)):
            with self.subTest(operation=name):
                self.phone.call_controller.failing.add(name)
                args = (self.did, VALID_NUMBER) if name == "dial" else (self.did,)
                with self.assertRaises(AndroidCallFailedError):
                    await self.call(method(*args))
                self.phone.call_controller.failing.discard(name)
        sent_before = self.bridge._counters["frames_sent"]
        self.phone.silent = True
        with self.assertRaises(AndroidCallTimeoutError):
            await self.call(self.control.dial(self.did, VALID_NUMBER))
        self.assertEqual(self.bridge._counters["frames_sent"], sent_before + 1)

    async def test_capability_device_and_stale_gates_run_before_a_request(self) -> None:
        with self.assertRaises(AndroidDeviceUnknownError):
            await self.control.status("adev-" + "0" * 32)
        self.bridge.revoke(self.did)
        with self.assertRaises(AndroidDeviceRevokedError):
            await self.control.status(self.did)

    async def test_unadvertised_capability_and_disconnect_are_refused(self) -> None:
        bridge, phone, control, _, _ = await call_phone_pair(capabilities=("bridge.protocol", CAPABILITY_CALL_STATUS))
        with self.assertRaises(AndroidCapabilityUnavailableError):
            await control.dial(phone.device_id, VALID_NUMBER)
        bridge2, phone2, control2, _, _ = await call_phone_pair()
        await answered(bridge2.disconnect(phone2.device_id), phone2)
        with self.assertRaises(AndroidDeviceNotConnectedError):
            await control2.status(phone2.device_id)

    async def test_stale_device_is_refused_before_send(self) -> None:
        clock = FakeClock()
        bridge, phone, control, _, _ = await call_phone_pair(
            clock=clock, heartbeat_interval_seconds=10, stale_after_seconds=30
        )
        clock.advance(timedelta(seconds=31))
        with self.assertRaises(AndroidDeviceStaleError):
            await control.status(phone.device_id)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
