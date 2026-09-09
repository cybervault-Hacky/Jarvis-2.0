"""Phase 8 security tests for the narrow Android text-message surface."""

from __future__ import annotations

import ast
import asyncio
import json
import unittest
from datetime import timedelta
from pathlib import Path

from jarvis_devices import ToolContext
from jarvis_devices import android_crypto as crypto
from jarvis_devices.android_bridge import (
    AndroidDeviceNotConnectedError,
    AndroidDeviceRevokedError,
    AndroidDeviceStaleError,
    AndroidDeviceUnknownError,
)
from jarvis_devices.android_message_tools import ANDROID_MESSAGE_TOOL_NAMES, build_android_message_tools
from jarvis_devices.android_messages import (
    MAX_MESSAGE_CHARACTERS,
    AndroidMessageFailedError,
    AndroidMessageTimeoutError,
)
from jarvis_devices.android_protocol import (
    MAX_MESSAGE_BYTES,
    MESSAGE_REQUESTS,
    MESSAGE_RESPONSES,
    RESPONSE_FOR,
    BridgeMessage,
    MessageType,
)
from jarvis_devices.confirmation import ConfirmationPolicy
from jarvis_devices.enums import ToolResultStatus

try:
    from .android_message_support import answered, message_phone_pair
    from .android_support import FakeAndroidBridge, requires_crypto
    from .support import FakeClock
    from .test_android_messages import (
        VALID_DEVICE,
        VALID_MESSAGE,
        VALID_RECIPIENT,
        message_confirmation_manager,
    )
    from .test_security import (
        FORBIDDEN_IMPORTS,
        FORBIDDEN_PATTERNS,
        FORBIDDEN_TERMINATION_PATTERNS,
        code_only_source,
        imported_modules,
    )
except ImportError:  # pragma: no cover
    from android_message_support import answered, message_phone_pair
    from android_support import FakeAndroidBridge, requires_crypto
    from support import FakeClock
    from test_android_messages import VALID_DEVICE, VALID_MESSAGE, VALID_RECIPIENT, message_confirmation_manager
    from test_security import FORBIDDEN_IMPORTS, FORBIDDEN_PATTERNS, FORBIDDEN_TERMINATION_PATTERNS, code_only_source, imported_modules

import Jarvis_device_control as bridge

ROOT = Path(__file__).resolve().parent.parent
PHASE8_SOURCES = (
    ROOT / "jarvis_devices" / "android_messages.py",
    ROOT / "jarvis_devices" / "android_message_tools.py",
    ROOT / "jarvis_devices" / "android_protocol.py",
    ROOT / "Jarvis_device_control.py",
    ROOT / "agent.py",
)

_FORBIDDEN_PARAMETERS = frozenset(
    {
        "command", "cmd", "shell", "adb", "host", "hostname", "ip", "port", "url", "socket",
        "path", "method", "api", "intent", "contact", "contact_id", "message_id", "call_id",
        "operation_id", "session", "session_id", "history", "notification", "record", "microphone",
        "camera", "location", "retry", "confirm", "force", "raw", "action",
    }
)


class Phase8StaticSecurityTests(unittest.TestCase):
    def test_no_unsafe_process_decoder_listener_or_network_primitive_is_added(self) -> None:
        for source in PHASE8_SOURCES:
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

    def test_message_protocol_is_small_dedicated_and_has_exact_response_pairs(self) -> None:
        self.assertEqual(len(MESSAGE_REQUESTS), 2)
        self.assertEqual(len(MESSAGE_RESPONSES), 2)
        self.assertEqual(MESSAGE_REQUESTS & MESSAGE_RESPONSES, frozenset())
        for request in MESSAGE_REQUESTS:
            with self.subTest(request=request):
                self.assertIn(request, RESPONSE_FOR)
                self.assertIn(RESPONSE_FOR[request], MESSAGE_RESPONSES)
                for forbidden in ("command", "execute", "shell", "adb", "raw", "method", "invoke", "intent"):
                    self.assertNotIn(forbidden, request)

    def test_message_tools_expose_no_steerable_metadata_or_private_capture_parameter(self) -> None:
        tools = build_android_message_tools(FakeAndroidBridge())
        self.assertEqual({tool.name for tool in tools}, set(ANDROID_MESSAGE_TOOL_NAMES))
        for tool in tools:
            with self.subTest(tool=tool.name):
                self.assertFalse(set(tool.argument_schema.names) & _FORBIDDEN_PARAMETERS)
        self.assertEqual(tools[1].argument_schema.names, ("device", "recipient", "message"))

    def test_no_history_contacts_notifications_or_generic_message_tool_exists(self) -> None:
        expected = {"android_message_status", "android_message_send"}
        self.assertEqual({name for name in bridge.__all__ if name in expected}, expected)
        for forbidden in (
            "android_message_history", "android_message_list", "android_message_contacts",
            "android_message_notifications", "android_message_forward", "android_message_reply",
            "android_message_execute", "android_message_raw", "android_message_retry",
        ):
            self.assertFalse(hasattr(bridge, forbidden))

    def test_message_modules_do_not_call_unsafe_deserializers(self) -> None:
        for source in PHASE8_SOURCES[:2]:
            tree = ast.parse(code_only_source(source))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    receiver = node.func.value.id if isinstance(node.func.value, ast.Name) else ""
                    with self.subTest(source=source.name, receiver=receiver, attr=node.func.attr):
                        self.assertNotIn(receiver, {"pickle", "marshal", "yaml", "dill", "shelve"})


class ConfirmationSecurityTests(unittest.IsolatedAsyncioTestCase):
    async def test_send_cannot_be_disabled_by_never_confirm_or_target_override(self) -> None:
        manager, _ = message_confirmation_manager()
        manager.confirmation_policy = ConfirmationPolicy(never_confirm=("android.message.send",))
        result = await manager.request(
            "android.message.send",
            {"device": VALID_DEVICE, "recipient": VALID_RECIPIENT, "message": VALID_MESSAGE},
            target="hidden target",
        )
        self.assertEqual(result.status, ToolResultStatus.PENDING_CONFIRMATION)
        self.assertIn(VALID_RECIPIENT, result.data["target"])
        self.assertIn(VALID_MESSAGE, result.data["target"])

    async def test_confirmation_bypass_ids_and_arbitrary_destinations_are_rejected(self) -> None:
        manager, _ = message_confirmation_manager()
        dangerous = (
            {"confirm": False}, {"confirmation": False}, {"operation_id": "msgop-" + "a" * 32},
            {"message_id": "message-other"}, {"call_id": "call-other"}, {"method": "sendText"},
            {"api": "sms"}, {"url": "https://example.invalid"}, {"recipient": "tel:+14155552671"},
            {"recipient": "sms:+14155552671"}, {"recipient": "smsto:+14155552671"},
            {"recipient": "mms:+14155552671"}, {"recipient": "sip:alice@example.com"},
        )
        for extra in dangerous:
            payload = {"device": VALID_DEVICE, "recipient": VALID_RECIPIENT, "message": "Hi", **extra}
            with self.subTest(extra=next(iter(extra))):
                result = await manager.request("android.message.send", payload)
                self.assertEqual(result.status, ToolResultStatus.INVALID_ARGUMENT)
                self.assertEqual(manager.confirmations.pending(), ())

    async def test_hostile_recipient_forms_oversized_body_and_control_abuse_are_refused(self) -> None:
        manager, _ = message_confirmation_manager()
        hostile_recipients = (
            "tel:+14155552671", "sms:+14155552671", "smsto:+14155552671", "mms:+14155552671",
            "sip:alice@example.com", "https://example.invalid", "127.0.0.1", "localhost",
            "+14155552671; rm -rf /", "adb shell input text", "cmd.exe /c calc", "powershell -c x",
        )
        for recipient in hostile_recipients:
            with self.subTest(recipient=recipient[:8]):
                result = await manager.request(
                    "android.message.send", {"device": VALID_DEVICE, "recipient": recipient, "message": "Hi"}
                )
                self.assertEqual(result.status, ToolResultStatus.INVALID_ARGUMENT)
                self.assertNotIn(recipient, result.message)
        for message in ("x" * (MAX_MESSAGE_CHARACTERS + 1), "bad\x00body"):
            with self.subTest(message_length=len(message)):
                result = await manager.request(
                    "android.message.send", {"device": VALID_DEVICE, "recipient": VALID_RECIPIENT, "message": message}
                )
                self.assertEqual(result.status, ToolResultStatus.INVALID_ARGUMENT)
                self.assertNotIn(message, result.message)
        self.assertEqual(manager.confirmations.pending(), ())

    async def test_sensitive_recipient_and_content_never_leak_to_result_or_audit(self) -> None:
        manager, tool = message_confirmation_manager()
        secret_recipient = "+14155552671; private=do-not-log"
        secret_message = "secret body must not be logged\x00"
        direct = await tool.execute(
            {"device": VALID_DEVICE, "recipient": secret_recipient, "message": secret_message},
            ToolContext(execution_id="exec-message", tool_name=tool.name),
        )
        managed = await manager.request(
            "android.message.send", {"device": VALID_DEVICE, "recipient": VALID_RECIPIENT, "message": secret_message}
        )
        for value in (secret_recipient, secret_message):
            self.assertNotIn(value, repr(direct))
            self.assertNotIn(value, repr(managed))
            self.assertNotIn(value, repr(manager.audit.records))


@requires_crypto
class AuthenticatedMessageSecurityTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.bridge, self.phone, self.control, _, self.phone_side = await message_phone_pair()
        self.did = self.phone.device_id

    async def test_unknown_unpaired_revoked_disconnected_and_stale_devices_are_refused_without_fallback(self) -> None:
        with self.assertRaises(AndroidDeviceUnknownError):
            await self.control.status("adev-" + "0" * 32)
        self.bridge.revoke(self.did)
        with self.assertRaises(AndroidDeviceRevokedError):
            await self.control.send(self.did, VALID_RECIPIENT, "Hi")

        unpaired_bridge, unpaired_phone, unpaired_control, _, _ = await message_phone_pair(paired_and_connected=False)
        with self.assertRaises(AndroidDeviceUnknownError):
            await unpaired_control.status(unpaired_phone.device_id)

        bridge2, phone2, control2, _, _ = await message_phone_pair()
        await answered(bridge2.disconnect(phone2.device_id), phone2)
        with self.assertRaises(AndroidDeviceNotConnectedError):
            await control2.status(phone2.device_id)

        clock = FakeClock()
        _, phone3, control3, _, _ = await message_phone_pair(
            clock=clock, heartbeat_interval_seconds=10, stale_after_seconds=30
        )
        clock.advance(timedelta(seconds=31))
        with self.assertRaises(AndroidDeviceStaleError):
            await control3.send(phone3.device_id, VALID_RECIPIENT, "Hi")

    async def test_phone_refuses_forged_request_wrong_session_and_replayed_request(self) -> None:
        _, attacker_key = crypto.generate_keypair()
        forged = BridgeMessage.create(
            MessageType.MESSAGE_SEND,
            self.did,
            payload={"recipient": VALID_RECIPIENT, "message": "Hi", "operation_id": "msgop-" + "a" * 32},
            sequence=9_999,
            session_id=self.phone.session_id,
        ).sign(attacker_key)
        await self.bridge.transport.send(forged.to_bytes())
        await self.phone.serve(max_frames=1)
        self.assertIn((MessageType.MESSAGE_SEND.value, "bad signature"), self.phone.refusals)

        wrong_session = BridgeMessage.create(
            MessageType.MESSAGE_SEND,
            self.did,
            payload={"recipient": VALID_RECIPIENT, "message": "Hi", "operation_id": "msgop-" + "b" * 32},
            sequence=10_000,
            session_id="sess-stale",
        ).sign(self.bridge.host_identity.private_key)
        await self.bridge.transport.send(wrong_session.to_bytes())
        await self.phone.serve(max_frames=1)
        self.assertIn((MessageType.MESSAGE_SEND.value, "wrong session"), self.phone.refusals)

        replay = BridgeMessage.create(
            MessageType.MESSAGE_STATUS,
            self.did,
            payload={},
            sequence=10_001,
            session_id=self.phone.session_id,
        ).sign(self.bridge.host_identity.private_key)
        await self.bridge.transport.send(replay.to_bytes())
        await self.phone.serve(max_frames=1)
        await self.bridge.transport.send(replay.to_bytes())
        await self.phone.serve(max_frames=1)
        self.assertIn((MessageType.MESSAGE_STATUS.value, "stale sequence"), self.phone.refusals)
        self.assertEqual(self.phone.message_controller.messages, [])

    async def test_forged_and_wrong_device_responses_are_ignored_without_send_success(self) -> None:
        async def forged_responder() -> None:
            request = await self.phone.receive(0.3)
            self.assertIsNotNone(request)
            _, foreign_key = crypto.generate_keypair()
            frame = BridgeMessage.create(
                MessageType.MESSAGE_SEND_RESPONSE,
                self.did,
                payload={"ok": True, "operation_id": request.payload["operation_id"], "delivery_state": "accepted", "duplicate": False},
                request_id=request.request_id,
                sequence=self.phone.sequence + 50,
                session_id=request.session_id,
            ).sign(foreign_key)
            await self.phone.transport.send(frame.to_bytes())

        task = asyncio.create_task(forged_responder())
        with self.assertRaises(AndroidMessageTimeoutError):
            await self.control.send(self.did, VALID_RECIPIENT, "Hi")
        await task
        self.assertGreater(self.bridge._counters["authentication_failures"], 0)
        self.assertEqual(self.phone.message_controller.messages, [])

        async def wrong_device_responder() -> None:
            request = await self.phone.receive(0.3)
            self.assertIsNotNone(request)
            frame = BridgeMessage.create(
                MessageType.MESSAGE_SEND_RESPONSE,
                "adev-" + "f" * 32,
                payload={"ok": True, "operation_id": request.payload["operation_id"], "delivery_state": "accepted", "duplicate": False},
                request_id=request.request_id,
                sequence=self.phone.sequence + 51,
                session_id=request.session_id,
            ).sign(self.phone.private_key)
            await self.phone.transport.send(frame.to_bytes())

        task = asyncio.create_task(wrong_device_responder())
        with self.assertRaises(AndroidMessageTimeoutError):
            await self.control.send(self.did, VALID_RECIPIENT, "Hi")
        await task
        self.assertEqual(self.phone.message_controller.messages, [])

    async def test_replayed_response_malformed_oversized_and_hostile_payloads_are_refused(self) -> None:
        await answered(self.control.status(self.did), self.phone)
        captured = self.phone.sent[-1]
        before = self.bridge._counters["replays_detected"]
        await self.bridge.handle_frame(captured.to_bytes())
        self.assertGreater(self.bridge._counters["replays_detected"], before)
        rejected = self.bridge._counters["frames_rejected"]
        await self.bridge.handle_frame(b"{bad json")
        await self.bridge.handle_frame(b"x" * (MAX_MESSAGE_BYTES + 1))
        self.assertGreaterEqual(self.bridge._counters["frames_rejected"], rejected + 2)

        # A real authenticated response carrying unexpected diagnostic content
        # is rejected and its content is never surfaced.
        secret_detail = "private message +14155552671"
        async def hostile_responder() -> None:
            request = await self.phone.receive(0.3)
            self.assertIsNotNone(request)
            frame = BridgeMessage.create(
                MessageType.MESSAGE_SEND_RESPONSE,
                self.did,
                payload={"ok": False, "error": "failed", "detail": secret_detail},
                request_id=request.request_id,
                sequence=self.phone.sequence + 52,
                session_id=request.session_id,
            ).sign(self.phone.private_key)
            await self.phone.transport.send(frame.to_bytes())

        task = asyncio.create_task(hostile_responder())
        with self.assertRaisesRegex(AndroidMessageFailedError, "invalid send message response") as caught:
            await self.control.send(self.did, VALID_RECIPIENT, "Hi")
        await task
        self.assertNotIn(secret_detail, str(caught.exception))

    async def test_timeout_cannot_be_reported_as_success_or_trigger_an_automatic_duplicate(self) -> None:
        tools = {tool.name: tool for tool in build_android_message_tools(self.bridge)}
        self.phone.silent = True
        result = await answered(
            tools["android.message.send"].execute(
                {"device": self.did, "recipient": VALID_RECIPIENT, "message": "Hi"},
                ToolContext(execution_id="exec-timeout", tool_name="android.message.send"),
            ),
            self.phone,
        )
        self.assertEqual(result.status, ToolResultStatus.TIMEOUT)
        self.assertFalse(result.success)
        self.assertIn("not resent", result.message)
        self.assertEqual(self.phone.message_controller.messages, [])

    async def test_message_frame_is_minimal_and_contains_no_private_key(self) -> None:
        bridge2, phone2, control2, pc2, _ = await message_phone_pair()
        await answered(control2.send(phone2.device_id, VALID_RECIPIENT, VALID_MESSAGE), phone2)
        raw = bytes(pc2.sent[-1]).decode("utf-8")
        body = json.loads(raw)
        self.assertEqual(set(body["payload"]), {"recipient", "message", "operation_id"})
        self.assertEqual(body["payload"]["recipient"], VALID_RECIPIENT)
        self.assertEqual(body["payload"]["message"], VALID_MESSAGE)
        self.assertNotIn("private_key", raw)
        self.assertNotIn(bridge2.host_identity.private_key.hex(), raw)
        self.assertNotIn(phone2.private_key.hex(), raw)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
