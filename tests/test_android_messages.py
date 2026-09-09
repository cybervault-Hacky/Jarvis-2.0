"""Phase 8 functional tests for authenticated Android text messaging."""

from __future__ import annotations

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
from jarvis_devices.android_message_tools import (
    ANDROID_MESSAGE_TOOL_NAMES,
    MESSAGE_CONTENT_ARGUMENT,
    MESSAGE_RECIPIENT_ARGUMENT,
    MessageSendTool,
    build_android_message_tools,
)
from jarvis_devices.android_messages import (
    MAX_MESSAGE_CHARACTERS,
    MAX_MESSAGE_UTF8_BYTES,
    AndroidMessageFailedError,
    AndroidMessageOperationConflictError,
    AndroidMessagePermissionDeniedError,
    AndroidMessageTimeoutError,
    AndroidMessageUnavailableError,
    MessageContentValidationError,
    MessageDeliveryState,
    new_message_operation_id,
    validate_message_content,
)
from jarvis_devices.android_protocol import (
    CAPABILITY_MESSAGE_STATUS,
    MessageType,
)
from jarvis_devices.enums import RiskLevel, ToolResultStatus
from jarvis_devices.errors import ErrorCode
from jarvis_devices.permissions import PERMISSION_ANDROID_MESSAGE_READ, PERMISSION_ANDROID_MESSAGE_SEND

try:
    from .android_message_support import answered, message_phone_pair
    from .android_support import FakeAndroidBridge, requires_crypto
    from .support import FakeAdapter, FakeClock
except ImportError:  # pragma: no cover
    from android_message_support import answered, message_phone_pair
    from android_support import FakeAndroidBridge, requires_crypto
    from support import FakeAdapter, FakeClock

VALID_DEVICE = "adev-" + "a" * 32
VALID_RECIPIENT = "+14155552671"
VALID_MESSAGE = "Hello, नमस्ते 👋"


def context(name: str) -> ToolContext:
    return ToolContext(execution_id=new_execution_id(), tool_name=name, platform=Platform.PC)


def message_confirmation_manager(*, clock=None) -> tuple[DeviceActionManager, MessageSendTool]:
    """Confirmation-only manager with a harmless fake available bridge."""
    tool = MessageSendTool(build_android_message_tools(FakeAndroidBridge())[0].control)
    registry = DeviceToolRegistry()
    registry.register(tool)
    platforms = PlatformRegistry()
    platforms.register(FakeAdapter(Platform.PC))
    manager = DeviceActionManager(
        registry,
        PermissionPolicy((PERMISSION_ANDROID_MESSAGE_SEND,)),
        ConfirmationManager(clock=clock or FakeClock(), default_ttl=timedelta(seconds=30)),
        platforms,
        AuditLogger(enabled=False),
    )
    return manager, tool


class MessageContentValidationTests(unittest.TestCase):
    def test_unicode_and_command_looking_text_are_preserved_as_opaque_content(self) -> None:
        text = "नमस्ते 👋 — python -c 'print(1)'; https://example.invalid"
        self.assertEqual(validate_message_content(text), text)

    def test_empty_control_and_invalid_message_values_are_refused_without_echo(self) -> None:
        bad_values = (None, "", "   ", "hello\nworld", "hello\x00world", "hello\x1b[2J")
        for value in bad_values:
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(MessageContentValidationError) as caught:
                    validate_message_content(value)
                if isinstance(value, str) and value:
                    self.assertNotIn(value, str(caught.exception))

    def test_character_and_utf8_bounds_are_enforced(self) -> None:
        with self.assertRaises(MessageContentValidationError):
            validate_message_content("a" * (MAX_MESSAGE_CHARACTERS + 1))
        # Fewer than the character cap but over the explicit UTF-8 payload cap.
        with self.assertRaises(MessageContentValidationError):
            validate_message_content("😀" * ((MAX_MESSAGE_UTF8_BYTES // 4) + 1))


class DeclarationTests(unittest.TestCase):
    def test_two_dedicated_tools_have_narrow_permissions_and_arguments(self) -> None:
        tools = build_android_message_tools(FakeAndroidBridge())
        self.assertEqual(tuple(tool.name for tool in tools), ANDROID_MESSAGE_TOOL_NAMES)
        self.assertEqual(len(set(ANDROID_MESSAGE_TOOL_NAMES)), 2)
        expected = {
            "android.message.status": (RiskLevel.SAFE, PERMISSION_ANDROID_MESSAGE_READ, ("device",), None, False),
            "android.message.send": (RiskLevel.EXTERNAL_ACTION, PERMISSION_ANDROID_MESSAGE_SEND, ("device", "recipient", "message"), True, True),
        }
        for tool in tools:
            risk, permission, arguments, confirmation, mandatory = expected[tool.name]
            with self.subTest(tool=tool.name):
                self.assertIs(tool.risk_level, risk)
                self.assertEqual(tool.required_permissions, (permission,))
                self.assertEqual(tool.argument_schema.names, arguments)
                self.assertEqual(tool.requires_confirmation, confirmation)
                self.assertEqual(tool.confirmation_mandatory, mandatory)
        self.assertEqual(MESSAGE_RECIPIENT_ARGUMENT.max_length, 64)
        self.assertEqual(MESSAGE_CONTENT_ARGUMENT.max_length, MAX_MESSAGE_CHARACTERS)

    def test_send_schema_rejects_ids_methods_destinations_and_confirmation_escape_hatches(self) -> None:
        tool = build_android_message_tools(FakeAndroidBridge())[1]
        for extra in (
            {"operation_id": "msgop-" + "a" * 32}, {"message_id": "m-1"}, {"call_id": "c-1"},
            {"method": "sendText"}, {"api": "sms"}, {"url": "https://example.invalid"},
            {"host": "example.invalid"}, {"socket": "x"}, {"confirm": False}, {"retry": True},
        ):
            with self.subTest(extra=next(iter(extra))):
                _, errors = tool.argument_schema.validate(
                    {"device": VALID_DEVICE, "recipient": VALID_RECIPIENT, "message": "Hi", **extra}
                )
                self.assertTrue(errors)

    def test_confirmation_function_still_requires_explicit_boolean_approval(self) -> None:
        import Jarvis_device_control as bridge

        self.assertEqual(
            inspect.signature(bridge.resolve_device_confirmation).parameters["approved"].default,
            inspect.Parameter.empty,
        )


class ConfirmationBindingTests(unittest.IsolatedAsyncioTestCase):
    async def test_send_is_pending_and_binds_device_canonical_recipient_and_exact_message(self) -> None:
        manager, _ = message_confirmation_manager()
        result = await manager.request(
            "android.message.send",
            {"device": VALID_DEVICE, "recipient": "+1 (415) 555-2671", "message": VALID_MESSAGE},
            target="attempt to hide the real confirmation target",
        )
        self.assertEqual(result.status, ToolResultStatus.PENDING_CONFIRMATION)
        request = manager.confirmations.require(result.data["confirmation_id"])
        self.assertEqual(
            request.arguments,
            {"device": VALID_DEVICE, "recipient": VALID_RECIPIENT, "message": VALID_MESSAGE},
        )
        self.assertIn("Send message", request.target)
        self.assertIn(VALID_DEVICE, request.target)
        self.assertIn(VALID_RECIPIENT, request.target)
        self.assertIn(VALID_MESSAGE, request.target)
        self.assertNotIn(VALID_RECIPIENT, request.describe())
        self.assertNotIn(VALID_MESSAGE, request.describe())
        self.assertNotIn(VALID_RECIPIENT, repr(manager.audit.records))
        self.assertNotIn(VALID_MESSAGE, repr(manager.audit.records))

    async def test_send_permission_is_required_before_confirmation_or_bridge_use(self) -> None:
        manager, _ = message_confirmation_manager()
        manager.permissions = PermissionPolicy((PERMISSION_ANDROID_MESSAGE_READ,))
        result = await manager.request(
            "android.message.send", {"device": VALID_DEVICE, "recipient": VALID_RECIPIENT, "message": "Hi"}
        )
        self.assertEqual(result.status, ToolResultStatus.PERMISSION_DENIED)
        self.assertEqual(manager.confirmations.pending(), ())

    async def test_invalid_recipient_or_message_is_refused_before_confirmation(self) -> None:
        manager, _ = message_confirmation_manager()
        for recipient, message in (("sms:+14155552671", "Hello"), (VALID_RECIPIENT, ""), (VALID_RECIPIENT, "bad\x00text")):
            with self.subTest(recipient_kind=recipient[:4], message_length=len(message)):
                result = await manager.request(
                    "android.message.send", {"device": VALID_DEVICE, "recipient": recipient, "message": message}
                )
                self.assertEqual(result.status, ToolResultStatus.INVALID_ARGUMENT)
                self.assertEqual(manager.confirmations.pending(), ())

    async def test_confirmation_cannot_migrate_recipient_message_or_device(self) -> None:
        manager, _ = message_confirmation_manager()
        pending = await manager.request(
            "android.message.send", {"device": VALID_DEVICE, "recipient": VALID_RECIPIENT, "message": "Hello"}
        )
        cid = pending.data["confirmation_id"]
        manager.confirmations.confirm(cid)
        variants = (
            {"device": VALID_DEVICE, "recipient": "+14155552672", "message": "Hello"},
            {"device": VALID_DEVICE, "recipient": VALID_RECIPIENT, "message": "Changed"},
            {"device": "adev-" + "b" * 32, "recipient": VALID_RECIPIENT, "message": "Hello"},
        )
        for arguments in variants:
            with self.subTest(arguments=arguments["device"][-2:]):
                result = await manager.request("android.message.send", arguments, confirmation_id=cid)
                self.assertEqual(result.error_code, ErrorCode.CONFIRMATION_MISMATCH)

    async def test_expired_and_reused_confirmation_never_sends(self) -> None:
        clock = FakeClock()
        manager, _ = message_confirmation_manager(clock=clock)
        pending = await manager.request(
            "android.message.send", {"device": VALID_DEVICE, "recipient": VALID_RECIPIENT, "message": "Hello"}
        )
        clock.advance(timedelta(seconds=31))
        expired = await manager.resolve_confirmation(pending.data["confirmation_id"], True)
        self.assertEqual(expired.error_code, ErrorCode.CONFIRMATION_EXPIRED)

        fresh, _ = message_confirmation_manager()
        pending = await fresh.request(
            "android.message.send", {"device": VALID_DEVICE, "recipient": VALID_RECIPIENT, "message": "Hello"}
        )
        cid = pending.data["confirmation_id"]
        fresh.confirmations.confirm(cid)
        self.assertTrue(fresh.confirmations.consume(cid))
        reused = await fresh.request(
            "android.message.send", {"device": VALID_DEVICE, "recipient": VALID_RECIPIENT, "message": "Hello"}, confirmation_id=cid
        )
        self.assertEqual(reused.error_code, ErrorCode.CONFIRMATION_REUSED)

    @requires_crypto
    async def test_explicit_approval_executes_only_the_bound_message_once(self) -> None:
        bridge, phone, _, _, _ = await message_phone_pair()
        registry = DeviceToolRegistry()
        for tool in build_android_message_tools(bridge):
            registry.register(tool)
        platforms = PlatformRegistry()
        platforms.register(FakeAdapter(Platform.PC))
        manager = DeviceActionManager(
            registry,
            PermissionPolicy((PERMISSION_ANDROID_MESSAGE_READ, PERMISSION_ANDROID_MESSAGE_SEND)),
            ConfirmationManager(),
            platforms,
            AuditLogger(enabled=False),
        )
        pending = await manager.request(
            "android.message.send",
            {"device": phone.device_id, "recipient": "+1 (415) 555-2671", "message": VALID_MESSAGE},
        )
        self.assertEqual(phone.message_controller.messages, [])
        result = await answered(manager.resolve_confirmation(pending.data["confirmation_id"], True), phone)
        self.assertTrue(result.success)
        self.assertEqual(len(phone.message_controller.messages), 1)
        _, recipient, message = phone.message_controller.messages[0]
        self.assertEqual((recipient, message), (VALID_RECIPIENT, VALID_MESSAGE))

    @requires_crypto
    async def test_declined_confirmation_never_sends_a_message(self) -> None:
        bridge, phone, _, _, _ = await message_phone_pair()
        registry = DeviceToolRegistry()
        for tool in build_android_message_tools(bridge):
            registry.register(tool)
        platforms = PlatformRegistry()
        platforms.register(FakeAdapter(Platform.PC))
        manager = DeviceActionManager(
            registry,
            PermissionPolicy((PERMISSION_ANDROID_MESSAGE_READ, PERMISSION_ANDROID_MESSAGE_SEND)),
            ConfirmationManager(),
            platforms,
            AuditLogger(enabled=False),
        )
        pending = await manager.request(
            "android.message.send", {"device": phone.device_id, "recipient": VALID_RECIPIENT, "message": "Hello"}
        )
        result = await manager.resolve_confirmation(pending.data["confirmation_id"], False)
        self.assertEqual(result.status, ToolResultStatus.DENIED)
        self.assertEqual(phone.message_controller.messages, [])


@requires_crypto
class MessageControlFunctionalTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.bridge, self.phone, self.control, self.pc_side, _ = await message_phone_pair()
        self.did = self.phone.device_id

    async def call(self, coro):
        return await answered(coro, self.phone)

    async def test_status_and_unicode_send_use_real_protocol_and_honest_accepted_semantics(self) -> None:
        status = await self.call(self.control.status(self.did))
        self.assertEqual(status["mode"], "text")
        self.assertTrue(status["send_supported"])
        result = await self.call(self.control.send(self.did, "+1 (415) 555-2671", VALID_MESSAGE))
        self.assertEqual(result["delivery_state"], MessageDeliveryState.ACCEPTED.value)
        self.assertFalse(result["duplicate"])
        self.assertNotIn("recipient", result)
        frame = json.loads(bytes(self.pc_side.sent[-1]).decode("utf-8"))
        self.assertEqual(frame["message_type"], MessageType.MESSAGE_SEND.value)
        self.assertEqual(set(frame["payload"]), {"recipient", "message", "operation_id"})
        self.assertEqual(frame["payload"]["recipient"], VALID_RECIPIENT)
        self.assertEqual(frame["payload"]["message"], VALID_MESSAGE)
        self.assertTrue(frame["payload"]["operation_id"].startswith("msgop-"))

    async def test_only_explicitly_attested_sent_or_delivered_states_are_reported(self) -> None:
        self.phone.message_controller.delivery_state = MessageDeliveryState.SENT
        sent = await self.call(self.control.send(self.did, VALID_RECIPIENT, "One"))
        self.assertEqual(sent["delivery_state"], "sent")
        self.phone.message_controller.delivery_state = MessageDeliveryState.DELIVERED
        delivered = await self.call(self.control.send(self.did, VALID_RECIPIENT, "Two"))
        self.assertEqual(delivered["delivery_state"], "delivered")

    async def test_companion_unavailable_and_permission_denied_are_distinct(self) -> None:
        self.phone.message_controller.unavailable.add("send")
        with self.assertRaises(AndroidMessageUnavailableError):
            await self.call(self.control.send(self.did, VALID_RECIPIENT, "Hi"))
        self.phone.message_controller.unavailable.clear()
        self.phone.message_controller.denied.add("send")
        with self.assertRaises(AndroidMessagePermissionDeniedError):
            await self.call(self.control.send(self.did, VALID_RECIPIENT, "Hi"))
        self.phone.message_controller.denied.clear()
        self.phone.message_controller.available = False
        tools = {tool.name: tool for tool in build_android_message_tools(self.bridge)}
        status = await self.call(
            tools["android.message.status"].execute({"device": self.did}, context("android.message.status"))
        )
        self.assertEqual(status.status, ToolResultStatus.UNAVAILABLE)
        self.assertEqual(status.error_code, ErrorCode.ANDROID_MESSAGE_UNAVAILABLE)

    async def test_failure_timeout_and_no_automatic_resend(self) -> None:
        self.phone.message_controller.failing.add("send")
        with self.assertRaises(AndroidMessageFailedError):
            await self.call(self.control.send(self.did, VALID_RECIPIENT, "One"))
        self.phone.message_controller.failing.clear()
        calls_before = len(self.phone.message_controller.messages)
        frames_before = self.bridge._counters["frames_sent"]
        self.phone.silent = True
        with self.assertRaises(AndroidMessageTimeoutError):
            await self.call(self.control.send(self.did, VALID_RECIPIENT, "One"))
        self.assertEqual(self.bridge._counters["frames_sent"], frames_before + 1)
        self.assertEqual(len(self.phone.message_controller.messages), calls_before)

    async def test_duplicate_operation_id_is_recognized_without_a_second_send(self) -> None:
        operation_id = new_message_operation_id()
        first = await self.call(self.control._send_with_operation(self.did, VALID_RECIPIENT, "Hello", operation_id=operation_id))
        second = await self.call(self.control._send_with_operation(self.did, VALID_RECIPIENT, "Hello", operation_id=operation_id))
        self.assertFalse(first["duplicate"])
        self.assertTrue(second["duplicate"])
        self.assertEqual(len(self.phone.message_controller.messages), 1)
        with self.assertRaises(AndroidMessageOperationConflictError):
            await self.call(self.control._send_with_operation(self.did, VALID_RECIPIENT, "Different", operation_id=operation_id))
        self.assertEqual(len(self.phone.message_controller.messages), 1)

    async def test_capability_unavailable_revoked_disconnected_and_stale_gates_prevent_send(self) -> None:
        bridge, phone, control, _, _ = await message_phone_pair(capabilities=("bridge.protocol", CAPABILITY_MESSAGE_STATUS))
        with self.assertRaises(AndroidCapabilityUnavailableError):
            await control.send(phone.device_id, VALID_RECIPIENT, "Hi")
        _, phone_status_missing, control_status_missing, _, _ = await message_phone_pair(
            capabilities=("bridge.protocol", "message.send")
        )
        with self.assertRaises(AndroidCapabilityUnavailableError):
            await control_status_missing.send(phone_status_missing.device_id, VALID_RECIPIENT, "Hi")
        self.bridge.revoke(self.did)
        with self.assertRaises(AndroidDeviceRevokedError):
            await self.control.send(self.did, VALID_RECIPIENT, "Hi")
        bridge2, phone2, control2, _, _ = await message_phone_pair()
        await answered(bridge2.disconnect(phone2.device_id), phone2)
        with self.assertRaises(AndroidDeviceNotConnectedError):
            await control2.status(phone2.device_id)
        clock = FakeClock()
        bridge3, phone3, control3, _, _ = await message_phone_pair(
            clock=clock, heartbeat_interval_seconds=10, stale_after_seconds=30
        )
        clock.advance(timedelta(seconds=31))
        with self.assertRaises(AndroidDeviceStaleError):
            await control3.send(phone3.device_id, VALID_RECIPIENT, "Hi")

    async def test_unknown_device_never_falls_back_to_the_connected_phone(self) -> None:
        with self.assertRaises(AndroidDeviceUnknownError):
            await self.control.status("adev-" + "0" * 32)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
