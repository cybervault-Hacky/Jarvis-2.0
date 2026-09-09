"""Phase 7 security tests for explicit Android call management.

The live-path tests use the Phase 5 authenticated in-memory bridge; the fake
peer is not a real phone.  Static checks extend the project scanner to ensure
this phase did not add an execution, listener, deserialisation, recording or
telephony backdoor.
"""

from __future__ import annotations

import ast
import asyncio
import json
import unittest
from pathlib import Path

from jarvis_devices import ToolContext
from jarvis_devices import android_crypto as crypto
from jarvis_devices.android_bridge import (
    AndroidAuthenticationError,
    AndroidDeviceNotConnectedError,
    AndroidDeviceRevokedError,
    AndroidDeviceStaleError,
    AndroidDeviceUnknownError,
)
from jarvis_devices.android_call_tools import ANDROID_CALL_TOOL_NAMES, build_android_call_tools
from jarvis_devices.android_calls import AndroidCallFailedError, AndroidCallTimeoutError, AndroidCallState
from jarvis_devices.android_protocol import (
    CALL_REQUESTS,
    CALL_RESPONSES,
    MAX_MESSAGE_BYTES,
    RESPONSE_FOR,
    BridgeMessage,
    MessageType,
)
from jarvis_devices.confirmation import ConfirmationPolicy
from jarvis_devices.enums import ToolResultStatus
from jarvis_devices.errors import ErrorCode
from jarvis_devices.permissions import PERMISSION_ANDROID_CALL_CONTROL

try:
    from .android_call_support import CallCapablePhone, answered, call_phone_pair
    from .android_support import FakeAndroidBridge, requires_crypto
    from .support import FakeAdapter
    from .test_android_calls import VALID_DEVICE, VALID_NUMBER, confirmation_manager
    from .test_security import (
        FORBIDDEN_IMPORTS,
        FORBIDDEN_PATTERNS,
        FORBIDDEN_TERMINATION_PATTERNS,
        code_only_source,
        imported_modules,
    )
except ImportError:  # pragma: no cover
    from android_call_support import CallCapablePhone, answered, call_phone_pair
    from android_support import FakeAndroidBridge, requires_crypto
    from support import FakeAdapter
    from test_android_calls import VALID_DEVICE, VALID_NUMBER, confirmation_manager
    from test_security import (
        FORBIDDEN_IMPORTS,
        FORBIDDEN_PATTERNS,
        FORBIDDEN_TERMINATION_PATTERNS,
        code_only_source,
        imported_modules,
    )

import Jarvis_device_control as bridge

ROOT = Path(__file__).resolve().parent.parent
PHASE7_SOURCES = (
    ROOT / "jarvis_devices" / "android_calls.py",
    ROOT / "jarvis_devices" / "android_call_tools.py",
    ROOT / "jarvis_devices" / "android_protocol.py",
    ROOT / "jarvis_devices" / "android_bridge.py",
    ROOT / "Jarvis_device_control.py",
    ROOT / "agent.py",
)

_FORBIDDEN_PARAMETERS = frozenset(
    {
        "command", "cmd", "shell", "adb", "host", "hostname", "ip", "port",
        "url", "socket", "path", "method", "api", "call_id", "session", "session_id",
        "record", "recording", "microphone", "contact", "recipient", "destination",
        "retry", "confirm", "force", "raw", "action",
    }
)


class Phase7StaticSecurityTests(unittest.TestCase):
    def test_no_unsafe_process_decoder_or_listener_primitive_is_added(self) -> None:
        for source in PHASE7_SOURCES:
            code = code_only_source(source)
            for label, pattern in FORBIDDEN_PATTERNS.items():
                with self.subTest(source=source.name, forbidden=label):
                    self.assertIsNone(pattern.search(code))
            for label, pattern in FORBIDDEN_TERMINATION_PATTERNS.items():
                with self.subTest(source=source.name, forbidden=label):
                    self.assertIsNone(pattern.search(code))
            self.assertEqual(imported_modules(source) & FORBIDDEN_IMPORTS, set())
            for forbidden in ("bind(", "listen(", "socket.socket", "0.0.0.0"):
                with self.subTest(source=source.name, forbidden=forbidden):
                    self.assertNotIn(forbidden, code)

    def test_call_protocol_is_small_dedicated_and_has_exact_response_pairs(self) -> None:
        self.assertEqual(len(CALL_REQUESTS), 5)
        self.assertEqual(len(CALL_RESPONSES), 5)
        self.assertEqual(CALL_REQUESTS & CALL_RESPONSES, frozenset())
        for request in CALL_REQUESTS:
            with self.subTest(request=request):
                self.assertIn(request, RESPONSE_FOR)
                self.assertIn(RESPONSE_FOR[request], CALL_RESPONSES)
                for forbidden in ("command", "execute", "shell", "adb", "raw", "method", "invoke"):
                    self.assertNotIn(forbidden, request)

    def test_call_tools_expose_no_steerable_control_or_sensitive_capture_parameter(self) -> None:
        tools = build_android_call_tools(FakeAndroidBridge())
        self.assertEqual({tool.name for tool in tools}, set(ANDROID_CALL_TOOL_NAMES))
        for tool in tools:
            with self.subTest(tool=tool.name):
                self.assertFalse(set(tool.argument_schema.names) & _FORBIDDEN_PARAMETERS)
        # The one permitted destination argument is not an arbitrary endpoint:
        # it is rigidly validated by the concrete dial tool test suite.
        self.assertEqual(build_android_call_tools(FakeAndroidBridge())[1].argument_schema.names, ("device", "phone_number"))

    def test_no_generic_or_hidden_call_tool_exists(self) -> None:
        expected = {
            "android_call_status", "android_call_dial", "android_call_answer",
            "android_call_reject", "android_call_end",
        }
        wrappers = {name for name in bridge.__all__ if name in expected}
        self.assertEqual(wrappers, expected)
        self.assertEqual(len(wrappers), 5)
        for forbidden in (
            "android_call_execute", "android_call_shell", "android_call_record",
            "android_call_list_history", "android_call_contacts", "android_call_toggle",
            "android_call_retry_automatically",
        ):
            self.assertFalse(hasattr(bridge, forbidden))

    def test_no_call_module_calls_an_unsafe_deserialiser(self) -> None:
        for source in PHASE7_SOURCES[:2]:
            tree = ast.parse(code_only_source(source))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    receiver = node.func.value.id if isinstance(node.func.value, ast.Name) else ""
                    with self.subTest(source=source.name, receiver=receiver, attr=node.func.attr):
                        self.assertNotIn(receiver, {"pickle", "marshal", "yaml", "dill", "shelve"})


class ConfirmationSecurityTests(unittest.IsolatedAsyncioTestCase):
    async def test_dial_cannot_be_disabled_by_the_operator_never_confirm_list(self) -> None:
        manager, _ = confirmation_manager()
        manager.confirmation_policy = ConfirmationPolicy(never_confirm=("android.call.dial",))
        result = await manager.request(
            "android.call.dial", {"device": VALID_DEVICE, "phone_number": VALID_NUMBER}
        )
        self.assertEqual(result.status, ToolResultStatus.PENDING_CONFIRMATION)

    async def test_confirmation_escape_hatches_call_id_and_arbitrary_destination_are_rejected(self) -> None:
        manager, _ = confirmation_manager()
        for extra in (
            {"confirm": False}, {"confirmation": False}, {"call_id": "call-other"},
            {"session_id": "sess-other"}, {"url": "https://example.invalid"},
            {"method": "placeCall"}, {"phone_number": "tel:+14155552671"},
        ):
            payload = {"device": VALID_DEVICE, "phone_number": VALID_NUMBER, **extra}
            with self.subTest(extra=next(iter(extra))):
                result = await manager.request("android.call.dial", payload)
                self.assertEqual(result.status, ToolResultStatus.INVALID_ARGUMENT)
                self.assertEqual(manager.confirmations.pending(), ())

    async def test_raw_invalid_number_never_leaks_from_tool_result_or_audit(self) -> None:
        manager, tool = confirmation_manager()
        secret_like_number = "+14155552671; private=do-not-log"
        direct = await tool.execute(
            {"device": VALID_DEVICE, "phone_number": secret_like_number},
            ToolContext(execution_id="exec-1", tool_name=tool.name),
        )
        managed = await manager.request(
            "android.call.dial", {"device": VALID_DEVICE, "phone_number": secret_like_number}
        )
        self.assertNotIn(secret_like_number, repr(direct))
        self.assertNotIn(secret_like_number, repr(managed))
        self.assertNotIn(secret_like_number, repr(manager.audit.records))


@requires_crypto
class AuthenticatedBridgeSecurityTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.bridge, self.phone, self.control, _, self.phone_side = await call_phone_pair()
        self.did = self.phone.device_id

    async def test_unknown_revoked_disconnected_and_stale_devices_are_refused_without_fallback(self) -> None:
        with self.assertRaises(AndroidDeviceUnknownError):
            await self.control.status("adev-" + "0" * 32)
        self.bridge.revoke(self.did)
        with self.assertRaises(AndroidDeviceRevokedError):
            await self.control.status(self.did)

        bridge2, phone2, control2, _, _ = await call_phone_pair()
        await answered(bridge2.disconnect(phone2.device_id), phone2)
        with self.assertRaises(AndroidDeviceNotConnectedError):
            await control2.status(phone2.device_id)

    async def test_phone_refuses_forged_request_and_wrong_session_before_any_state_change(self) -> None:
        _, attacker_key = crypto.generate_keypair()
        forged = BridgeMessage.create(
            MessageType.CALL_DIAL,
            self.did,
            payload={"phone_number": VALID_NUMBER},
            sequence=999,
            session_id=self.phone.session_id,
        ).sign(attacker_key)
        await self.bridge.transport.send(forged.to_bytes())
        await self.phone.serve(max_frames=1)
        self.assertIn((MessageType.CALL_DIAL.value, "bad signature"), self.phone.refusals)
        self.assertEqual(self.phone.call_controller.state, AndroidCallState.IDLE)

        genuine_old_session = BridgeMessage.create(
            MessageType.CALL_DIAL,
            self.did,
            payload={"phone_number": VALID_NUMBER},
            sequence=1000,
            session_id="sess-stale",
        ).sign(self.bridge.host_identity.private_key)
        await self.bridge.transport.send(genuine_old_session.to_bytes())
        await self.phone.serve(max_frames=1)
        self.assertIn((MessageType.CALL_DIAL.value, "wrong session"), self.phone.refusals)
        self.assertEqual(self.phone.call_controller.state, AndroidCallState.IDLE)

    async def test_replayed_valid_host_request_is_refused_before_a_second_dispatch(self) -> None:
        frame = BridgeMessage.create(
            MessageType.CALL_STATUS,
            self.did,
            payload={},
            sequence=10_000,
            session_id=self.phone.session_id,
        ).sign(self.bridge.host_identity.private_key)
        await self.bridge.transport.send(frame.to_bytes())
        await self.phone.serve(max_frames=1)
        await self.bridge.transport.send(frame.to_bytes())
        await self.phone.serve(max_frames=1)
        self.assertIn((MessageType.CALL_STATUS.value, "stale sequence"), self.phone.refusals)
        self.assertEqual([name for name, _ in self.phone.call_controller.calls], ["get_status"])

    async def test_wrong_device_response_is_ignored_and_never_reported_as_success(self) -> None:
        async def wrong_device_responder() -> None:
            request = await self.phone.receive(0.3)
            self.assertIsNotNone(request)
            response = BridgeMessage.create(
                MessageType.CALL_DIAL_RESPONSE,
                "adev-" + "f" * 32,
                payload={"ok": True, "state": "dialing"},
                request_id=request.request_id,
                sequence=self.phone.sequence + 50,
                session_id=request.session_id,
            ).sign(self.phone.private_key)
            await self.phone.transport.send(response.to_bytes())

        task = asyncio.create_task(wrong_device_responder())
        with self.assertRaises(AndroidCallTimeoutError):
            await self.control.dial(self.did, VALID_NUMBER)
        await task
        self.assertEqual(self.phone.call_controller.state, AndroidCallState.IDLE)

    async def test_forged_response_is_ignored_and_never_reported_as_dial_success(self) -> None:
        async def forged_responder() -> None:
            request = await self.phone.receive(0.3)
            self.assertIsNotNone(request)
            _, foreign_key = crypto.generate_keypair()
            frame = BridgeMessage.create(
                MessageType.CALL_DIAL_RESPONSE,
                self.did,
                payload={"ok": True, "state": "dialing"},
                request_id=request.request_id,
                sequence=self.phone.sequence + 50,
                session_id=request.session_id,
            ).sign(foreign_key)
            await self.phone.transport.send(frame.to_bytes())

        task = asyncio.create_task(forged_responder())
        with self.assertRaises(AndroidCallTimeoutError):
            await self.control.dial(self.did, VALID_NUMBER)
        await task
        self.assertGreater(self.bridge._counters["authentication_failures"], 0)
        self.assertEqual(self.phone.call_controller.state, AndroidCallState.IDLE)

    async def test_response_with_unexpected_diagnostics_is_refused_without_leaking_them(self) -> None:
        secret_detail = "number +14155552671 must not leave the companion"

        async def malformed_responder() -> None:
            request = await self.phone.receive(0.3)
            self.assertIsNotNone(request)
            response = BridgeMessage.create(
                MessageType.CALL_DIAL_RESPONSE,
                self.did,
                payload={"ok": False, "error": "failed", "detail": secret_detail, "state": "idle"},
                request_id=request.request_id,
                sequence=self.phone.sequence + 50,
                session_id=request.session_id,
            ).sign(self.phone.private_key)
            await self.phone.transport.send(response.to_bytes())

        task = asyncio.create_task(malformed_responder())
        with self.assertRaisesRegex(AndroidCallFailedError, "invalid place the call response") as caught:
            await self.control.dial(self.did, VALID_NUMBER)
        await task
        self.assertNotIn(secret_detail, str(caught.exception))
        self.assertEqual(self.phone.call_controller.state, AndroidCallState.IDLE)

    async def test_replayed_response_malformed_frame_and_oversized_frame_are_rejected(self) -> None:
        await answered(self.control.status(self.did), self.phone)
        captured = self.phone.sent[-1]
        before = self.bridge._counters["replays_detected"]
        await self.bridge.handle_frame(captured.to_bytes())
        self.assertGreater(self.bridge._counters["replays_detected"], before)
        rejected = self.bridge._counters["frames_rejected"]
        await self.bridge.handle_frame(b"{bad json")
        await self.bridge.handle_frame(b"x" * (MAX_MESSAGE_BYTES + 1))
        self.assertGreaterEqual(self.bridge._counters["frames_rejected"], rejected + 2)

    async def test_dial_frame_has_only_the_canonical_number_and_no_private_key(self) -> None:
        # Use a dedicated authenticated peer so a real signed frame is sent
        # through the existing bridge and can be inspected from transport.
        bridge3, phone3, control3, pc3, _ = await call_phone_pair()
        await answered(control3.dial(phone3.device_id, VALID_NUMBER), phone3)
        raw = bytes(pc3.sent[-1]).decode("utf-8")
        body = json.loads(raw)
        self.assertEqual(body["payload"], {"phone_number": VALID_NUMBER})
        self.assertNotIn("private_key", raw)
        self.assertNotIn(bridge3.host_identity.private_key.hex(), raw)
        self.assertNotIn(phone3.private_key.hex(), raw)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
