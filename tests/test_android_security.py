"""Phase 5 security tests for the Android bridge.

These prove the properties that matter for a bridge that could one day hold
trust to a person's phone:

* the bridge modules contain no ``eval``/``exec``/``pickle``/``subprocess``/
  shell/``ctypes``/``socket`` primitive and no command-shaped string constant;
* no tool, bridge method or protocol message can carry a command, a shell, an
  ADB invocation, a file path or a network destination;
* trust can only be established by a verified signature **plus** a user
  approval, and revocation cannot be undone by any code path here;
* confirmations and permissions still gate every trust change, through the real
  LiveKit bridge;
* replayed, forged, oversized and malformed frames are refused;
* nothing secret - private keys, tokens, session material - reaches a tool
  result, an audit record or a log line.
"""

from __future__ import annotations

import ast
import asyncio
import json
import unittest
from pathlib import Path
from unittest import mock

from jarvis_devices import android_crypto as crypto
from jarvis_devices.android_bridge import (
    AndroidDeviceBridge,
    AndroidDeviceRevokedError,
    AndroidPairingError,
    PairingStatus,
    create_default_android_bridge,
)
from jarvis_devices.android_identity import TrustState
from jarvis_devices.android_protocol import (
    MAX_MESSAGE_BYTES,
    BridgeMessage,
    MessageType,
)
from jarvis_devices.android_registry import DuplicateDeviceError, InMemoryAndroidDeviceRegistry
from jarvis_devices.android_tools import ANDROID_BRIDGE_TOOL_NAMES, build_android_bridge_tools
from jarvis_devices.enums import ToolResultStatus
from jarvis_devices.errors import ErrorCode
from jarvis_devices.permissions import (
    PERMISSION_ANDROID_BRIDGE_MANAGE,
    PERMISSION_ANDROID_BRIDGE_PAIR,
)

try:  # imported as part of the ``tests`` package (pytest / discover -t .)
    from .android_support import (
        FakeAndroidDevice,
        RecordingAuditHook,
        complete_pairing,
        requires_crypto,
        started_pair,
    )
    from .test_security import (
        FORBIDDEN_IMPORTS,
        FORBIDDEN_PATTERNS,
        FORBIDDEN_TERMINATION_PATTERNS,
        code_only_source,
        imported_modules,
    )
except ImportError:  # ``python -m unittest discover -s tests``
    from android_support import (
        FakeAndroidDevice,
        RecordingAuditHook,
        complete_pairing,
        requires_crypto,
        started_pair,
    )
    from test_security import (
        FORBIDDEN_IMPORTS,
        FORBIDDEN_PATTERNS,
        FORBIDDEN_TERMINATION_PATTERNS,
        code_only_source,
        imported_modules,
    )

import Jarvis_device_control as bridge

ROOT = Path(__file__).resolve().parent.parent
BRIDGE_SOURCES = (
    ROOT / "jarvis_devices" / "android_crypto.py",
    ROOT / "jarvis_devices" / "android_identity.py",
    ROOT / "jarvis_devices" / "android_registry.py",
    ROOT / "jarvis_devices" / "android_protocol.py",
    ROOT / "jarvis_devices" / "android_transport.py",
    ROOT / "jarvis_devices" / "android_bridge.py",
    ROOT / "jarvis_devices" / "android_tools.py",
    ROOT / "Jarvis_device_control.py",
    ROOT / "agent.py",
)

#: Substrings that would mean an OS command, a shell or an ADB call is embedded.
COMMAND_SHAPES = (
    "adb ",
    "adb.exe",
    "cmd.exe",
    "powershell",
    "shell=",
    "os.system",
    "subprocess",
    "/system/bin",
    "pm start",
    "am start",
    "input tap",
    "&&",
    "||",
    "; rm",
    "shutdown.exe",
)

#: Words that would mean an arbitrary network destination can be supplied.
DESTINATION_WORDS = ("0.0.0.0", "bind(", "listen(", "socket.socket", "connect_ex")

#: Parameter names a steerable tool or bridge method must never accept.
FORBIDDEN_PARAMETERS = (
    "command", "cmd", "shell", "flags", "host", "hostname", "ip", "port",
    "address", "url", "path", "executable", "script", "adb", "timeout_seconds",
    "force", "reason",
)


class StaticAnalysisTests(unittest.TestCase):
    def test_no_process_or_eval_primitive_in_phase_5(self) -> None:
        for source in BRIDGE_SOURCES:
            code = code_only_source(source)
            for label, pattern in FORBIDDEN_PATTERNS.items():
                with self.subTest(file=source.name, forbidden=label):
                    self.assertIsNone(pattern.search(code), f"{source.name} must not contain {label}")

    def test_no_forbidden_module_is_imported(self) -> None:
        """No bridge module imports a process, shell or socket primitive.

        This is the same closed rule the Phase 1 suite applies to the whole
        framework: the registry writes its JSON file through ``pathlib``, so it
        needs no ``os`` import and there is no exception to carve out.
        """
        for source in BRIDGE_SOURCES:
            with self.subTest(file=source.name):
                self.assertEqual(imported_modules(source) & FORBIDDEN_IMPORTS, set())

    def test_no_os_attribute_is_reached_anywhere_in_the_bridge(self) -> None:
        for source in BRIDGE_SOURCES[:7]:
            tree = ast.parse(source.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                    with self.subTest(file=source.name, attribute=node.attr):
                        self.assertNotEqual(node.value.id, "os")

    def test_no_process_termination_api(self) -> None:
        for source in BRIDGE_SOURCES:
            code = code_only_source(source)
            for label, pattern in FORBIDDEN_TERMINATION_PATTERNS.items():
                with self.subTest(file=source.name, forbidden=label):
                    self.assertIsNone(pattern.search(code), f"{source.name} must not contain {label}")

    def test_no_socket_or_ctypes_anywhere_in_the_bridge(self) -> None:
        """The Phase 5 transport is in-memory only; nothing may open a socket."""
        for source in BRIDGE_SOURCES[:7]:
            modules = imported_modules(source)
            with self.subTest(file=source.name):
                self.assertNotIn("socket", modules)
                self.assertNotIn("ctypes", modules)
                self.assertNotIn("subprocess", modules)
                self.assertNotIn("pickle", modules)
                self.assertNotIn("os", modules) if source.name != "android_registry.py" else None

    def test_no_listening_endpoint_exists(self) -> None:
        for source in BRIDGE_SOURCES:
            code = code_only_source(source)
            for word in DESTINATION_WORDS:
                with self.subTest(file=source.name, word=word):
                    self.assertNotIn(word, code)

    def test_no_string_constant_looks_like_a_command(self) -> None:
        for source in BRIDGE_SOURCES[:7]:
            tree = ast.parse(code_only_source(source))
            constants = [
                node.value
                for node in ast.walk(tree)
                if isinstance(node, ast.Constant) and isinstance(node.value, str)
            ]
            self.assertGreater(len(constants), 10)
            for literal in constants:
                lowered = literal.lower()
                for forbidden in COMMAND_SHAPES:
                    with self.subTest(file=source.name, forbidden=forbidden, literal=literal[:50]):
                        self.assertNotIn(forbidden, lowered)

    def test_no_model_facing_method_accepts_a_steerable_parameter(self) -> None:
        """Every entry point the model can reach takes ids, nothing else.

        Constructor/configuration parameters (a registry file ``path``, a
        transport ``reason``) are set by the developer, not by the model, so
        they are out of scope here - the *tool argument schemas* are checked
        separately in tests/test_android_tools.py.
        """
        model_facing = {
            "android_tools.py": {"run", "failure", "platform_result", "guard"},
            "android_bridge.py": {
                "approve_pairing", "cancel_pairing", "unpair", "revoke", "connect",
                "disconnect", "heartbeat", "capabilities", "require_capability",
                "device_status", "list_devices", "status", "handle_frame",
                "send_request", "health", "connection_state", "pending_pairings",
            },
        }
        checked = 0
        for filename, methods in model_facing.items():
            tree = ast.parse((ROOT / "jarvis_devices" / filename).read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in methods:
                    for argument in list(node.args.args) + list(node.args.kwonlyargs):
                        if argument.arg in ("self", "cls"):
                            continue
                        checked += 1
                        with self.subTest(file=filename, function=node.name, parameter=argument.arg):
                            self.assertNotIn(argument.arg, FORBIDDEN_PARAMETERS)
        self.assertGreater(checked, 25)

    def test_no_execute_style_backdoor_is_exposed(self) -> None:
        for name in (
            "android_execute", "android_adb", "android_shell", "android_raw_send",
            "android_socket_send", "run_android_execute", "run_android_adb",
        ):
            with self.subTest(name=name):
                self.assertFalse(hasattr(bridge, name))

    def test_no_unsafe_deserialiser_is_used(self) -> None:
        """``pickle``/``marshal``/``yaml.load`` must never decode a frame.

        ``json.load`` is the only decoder in the bridge and is safe, so this
        check looks at *what* is being called, not merely the method name.
        """
        unsafe_modules = {"pickle", "marshal", "shelve", "dill", "yaml"}
        for source in BRIDGE_SOURCES:
            tree = ast.parse(code_only_source(source))
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                    continue
                receiver = node.func.value
                name = receiver.id if isinstance(receiver, ast.Name) else ""
                with self.subTest(file=source.name, call=f"{name}.{node.func.attr}"):
                    self.assertNotIn(name, unsafe_modules)
                    if node.func.attr in {"loads", "load", "Unpickler"}:
                        self.assertEqual(name, "json", f"{name}.{node.func.attr} is not a safe decoder")


class RegistrationTests(unittest.TestCase):
    def test_each_android_tool_is_registered_exactly_once(self) -> None:
        registered = list(bridge.device_registry.names())
        self.assertEqual(len(registered), len(set(registered)), "duplicate tool registration")
        for name in ANDROID_BRIDGE_TOOL_NAMES:
            with self.subTest(tool=name):
                self.assertEqual(registered.count(name), 1)

    def test_the_builder_returns_six_unique_tools(self) -> None:
        tools = build_android_bridge_tools(create_default_android_bridge())
        names = [tool.name for tool in tools]
        self.assertEqual(names, list(ANDROID_BRIDGE_TOOL_NAMES))
        self.assertEqual(len(set(names)), 6)

    def test_a_duplicate_registration_is_refused(self) -> None:
        registry = InMemoryAndroidDeviceRegistry()
        tools = build_android_bridge_tools(create_default_android_bridge())
        from jarvis_devices.registry import DeviceToolRegistry, DuplicateToolError

        tool_registry = DeviceToolRegistry()
        tool_registry.register(tools[0])
        with self.assertRaises(DuplicateToolError):
            tool_registry.register(tools[0])
        self.assertIsNotNone(registry)

    def test_the_bridge_exports_each_wrapper_once(self) -> None:
        for name in (
            "android_bridge_status", "android_device_list", "android_device_status",
            "android_device_pair", "android_device_unpair", "android_device_revoke",
        ):
            with self.subTest(wrapper=name):
                self.assertTrue(hasattr(bridge, name))
                self.assertEqual(bridge.__all__.count(name), 1)
        self.assertEqual(len(set(bridge.__all__)), len(bridge.__all__))


@requires_crypto
class HostileInputTests(unittest.IsolatedAsyncioTestCase):
    """Nothing a hostile caller can say becomes an execution."""

    async def test_hostile_device_ids_never_reach_the_bridge(self) -> None:
        payloads = (
            "adb shell rm -rf /",
            "cmd.exe /c calc",
            "powershell -c Stop-Computer",
            "192.168.1.50",
            "pixel-8.lan:5555",
            "AA:BB:CC:DD:EE:FF",
            "\\\\fileserver\\share",
            "../../../etc/passwd",
            "adev-" + "0" * 32 + "; rm -rf /",
            "adev-" + "0" * 32 + "\n",
            "x" * 5000,
            "",
        )
        for tool_name in ("android.device.status", "android.device.unpair", "android.device.revoke"):
            for payload in payloads:
                with self.subTest(tool=tool_name, payload=payload[:24]):
                    result = await bridge.device_manager.request(tool_name, {"device": payload})
                    self.assertEqual(result.status, ToolResultStatus.INVALID_ARGUMENT)
                    self.assertFalse(result.success)

    async def test_hostile_pairing_ids_never_reach_the_bridge(self) -> None:
        for payload in ("adb shell", "pair-; rm -rf /", "pair-" + "z" * 32, "", "x" * 500):
            with self.subTest(payload=payload[:20]):
                result = await bridge.device_manager.request("android.device.pair", {"pairing": payload})
                self.assertEqual(result.status, ToolResultStatus.INVALID_ARGUMENT)

    async def test_extra_arguments_are_rejected(self) -> None:
        for extra in (
            {"command": "shutdown /s"},
            {"host": "10.0.0.5", "port": 5555},
            {"adb": "shell ls"},
            {"flags": "--force"},
            {"path": "/system/bin/sh"},
        ):
            with self.subTest(extra=str(extra)[:40]):
                result = await bridge.device_manager.request(
                    "android.device.status", {"device": "adev-" + "0" * 32, **extra}
                )
                self.assertEqual(result.status, ToolResultStatus.INVALID_ARGUMENT)

    async def test_unknown_android_tool_names_are_refused(self) -> None:
        for name in (
            "android.execute", "android.adb", "android.shell", "android.raw.send",
            "android.socket.send", "android.command", "android.device.volume",
            "android.device.call", "android.device.sms", "android.device.screen",
        ):
            with self.subTest(name=name):
                answer = await bridge.run_device_action(name, "{}")
                self.assertIn(ErrorCode.UNKNOWN_TOOL, answer)

    async def test_a_malformed_json_argument_is_refused(self) -> None:
        for raw in ("{not json", "[]", '"a string"', "{'device': }"):
            with self.subTest(raw=raw):
                answer = await bridge.run_device_action("android.device.status", raw)
                self.assertTrue(answer.startswith("❌"), answer)

    async def test_an_oversized_argument_is_refused(self) -> None:
        answer = await bridge.run_device_action(
            "android.device.status", json.dumps({"device": "adev-" + "0" * 32, "blob": "x" * 200_000})
        )
        self.assertTrue(answer.startswith("❌"), answer)


@requires_crypto
class TrustBypassTests(unittest.IsolatedAsyncioTestCase):
    async def test_a_pairing_cannot_be_approved_without_proof(self) -> None:
        bridge_, phone, _, _ = await started_pair()
        await phone.request_pairing()
        await bridge_.pump()
        record = bridge_.pending_pairings()[0]
        with self.assertRaises(AndroidPairingError):
            bridge_.approve_pairing(record["pairing_id"])
        self.assertEqual(bridge_.list_devices(), ())

    async def test_a_forged_signature_cannot_create_a_pairing(self) -> None:
        bridge_, phone, _, _ = await started_pair()
        impostor = FakeAndroidDevice(phone.transport, display_name="Impostor")
        await impostor.send(
            BridgeMessage.create(
                MessageType.PAIR_REQUEST,
                impostor.device_id,
                payload={
                    "public_key": crypto.encode_public_key(phone.public_key),  # someone else's key
                    "display_name": "Impostor",
                    "capabilities": [],
                },
                sequence=1,
                timestamp=impostor._now(),
            )
        )
        await bridge_.pump()
        self.assertEqual(bridge_.pending_pairings(), ())
        self.assertEqual(bridge_.list_devices(), ())

    async def test_a_revoked_device_cannot_be_revived_by_any_path(self) -> None:
        bridge_, phone, _, _ = await started_pair()
        await complete_pairing(bridge_, phone)
        bridge_.revoke(phone.device_id)

        # 1. direct approval of a new pairing request
        await phone.request_pairing()
        await bridge_.pump()
        self.assertEqual(bridge_.pending_pairings(), ())

        # 2. unpair-then-pair-again would erase the revocation, so it is refused
        with self.assertRaises(AndroidDeviceRevokedError):
            await bridge_.unpair(phone.device_id)
        self.assertIs(bridge_.registry.get(phone.device_id).trust_state, TrustState.REVOKED)

        # 3. the registry itself refuses to re-register the id
        with self.assertRaises(DuplicateDeviceError):
            bridge_.registry.register(bridge_.registry.get(phone.device_id), override=True)

    async def test_a_replayed_pairing_response_is_refused(self) -> None:
        bridge_, phone, _, _ = await started_pair()
        await phone.request_pairing()
        await bridge_.pump()
        await phone.read_challenge()
        response = await phone.answer_challenge()
        await bridge_.pump()
        record = bridge_.pending_pairings()[0]
        self.assertEqual(record["status"], PairingStatus.VERIFIED.value)
        # Replaying the same proof must not create a second approval path.
        await bridge_.handle_frame(response.to_bytes())
        self.assertEqual(len(bridge_.pending_pairings()), 1)

    async def test_a_replayed_authenticated_frame_is_refused(self) -> None:
        bridge_, phone, _, _ = await started_pair()
        await complete_pairing(bridge_, phone)
        await asyncio.gather(bridge_.connect(phone.device_id), phone.serve(max_frames=2))
        frame = await phone.push_heartbeat()
        await bridge_.pump()
        received_before = bridge_._counters["frames_received"]
        await bridge_.handle_frame(frame.to_bytes())
        await bridge_.handle_frame(frame.to_bytes())
        self.assertGreaterEqual(bridge_._counters["replays_detected"], 1)
        self.assertGreater(bridge_._counters["frames_received"], received_before)

    async def test_a_forged_response_cannot_satisfy_a_request(self) -> None:
        bridge_, phone, _, phone_side = await started_pair(max_connection_attempts=1)
        await complete_pairing(bridge_, phone)
        impostor = FakeAndroidDevice(phone_side, display_name="Impostor")

        async def impostor_answers():
            message = await impostor.receive(0.3)
            self.assertIsNotNone(message)
            await impostor.send(
                BridgeMessage.create(
                    MessageType.ACK,
                    impostor.device_id,
                    request_id=message.request_id,
                    sequence=1,
                    session_id=message.session_id,
                    timestamp=impostor._now(),
                )
            )

        task = asyncio.create_task(impostor_answers())
        from jarvis_devices.android_bridge import AndroidConnectionError

        with self.assertRaises(AndroidConnectionError):
            await bridge_.connect(phone.device_id)
        await task
        self.assertIsNot(bridge_.connection_state(phone.device_id).value, "connected")

    async def test_reconnect_attempts_are_bounded(self) -> None:
        from jarvis_devices.android_bridge import MAX_CONNECTION_ATTEMPTS_LIMIT

        bridge_, phone, _, _ = await started_pair(max_connection_attempts=2)
        await complete_pairing(bridge_, phone)
        phone.answer_connects = False
        from jarvis_devices.android_bridge import AndroidConnectionError

        with self.assertRaises(AndroidConnectionError):
            await bridge_.connect(phone.device_id, attempts=10_000)
        self.assertLessEqual(
            bridge_.registry.get(phone.device_id).connection.attempts, MAX_CONNECTION_ATTEMPTS_LIMIT
        )

    async def test_an_oversized_frame_is_refused_before_parsing(self) -> None:
        bridge_, _, _, _ = await started_pair()
        await bridge_.handle_frame(b" " * (MAX_MESSAGE_BYTES + 1))
        self.assertGreaterEqual(bridge_._counters["frames_rejected"], 1)


@requires_crypto
class LiveBridgeGateTests(unittest.IsolatedAsyncioTestCase):
    """Confirmation and permission gating, through the real JARVIS bridge."""

    TRUST_TOOLS = ("android.device.pair", "android.device.unpair", "android.device.revoke")

    #: Explicit payloads: "android.device.unpair" also ends with "pair", so a
    #: suffix test would hand it the wrong argument and only ever see an
    #: invalid_argument failure.
    PAYLOADS = {
        "android.device.pair": {"pairing": "pair-" + "b" * 32},
        "android.device.unpair": {"device": "adev-" + "a" * 32},
        "android.device.revoke": {"device": "adev-" + "a" * 32},
    }

    async def test_trust_changes_always_ask_first(self) -> None:
        for name in self.TRUST_TOOLS:
            payload = self.PAYLOADS[name]
            with self.subTest(tool=name):
                result = await bridge.device_manager.request(name, payload)
                self.assertEqual(result.status, ToolResultStatus.PENDING_CONFIRMATION)
                self.assertFalse(result.success)

    async def test_a_policy_cannot_make_trust_changes_unconfirmed(self) -> None:
        original = bridge.device_manager.confirmation_policy
        try:
            from jarvis_devices.confirmation import ConfirmationPolicy

            bridge.device_manager.confirmation_policy = ConfirmationPolicy(
                never_confirm=self.TRUST_TOOLS
            )
            for name in self.TRUST_TOOLS:
                with self.subTest(tool=name):
                    result = await bridge.device_manager.request(name, self.PAYLOADS[name])
                    self.assertEqual(result.status, ToolResultStatus.PENDING_CONFIRMATION)
        finally:
            bridge.device_manager.confirmation_policy = original

    async def test_one_yes_cannot_be_used_twice(self) -> None:
        pending = await bridge.device_manager.request(
            "android.device.revoke", {"device": "adev-" + "a" * 32}
        )
        cid = pending.data["confirmation_id"]
        await bridge.resolve_device_confirmation(cid, True)
        again = await bridge.resolve_device_confirmation(cid, True)
        self.assertIn(ErrorCode.CONFIRMATION_REUSED, again)

    async def test_a_confirmation_cannot_migrate_between_tools(self) -> None:
        pending = await bridge.device_manager.request(
            "android.device.revoke", {"device": "adev-" + "a" * 32}
        )
        hijacked = await bridge.device_manager.request(
            "android.device.unpair",
            {"device": "adev-" + "a" * 32},
            confirmation_id=pending.data["confirmation_id"],
        )
        self.assertEqual(hijacked.error_code, ErrorCode.CONFIRMATION_MISMATCH)

    async def test_revoking_the_permissions_blocks_the_tools(self) -> None:
        bridge.device_permissions.revoke(
            PERMISSION_ANDROID_BRIDGE_PAIR, PERMISSION_ANDROID_BRIDGE_MANAGE
        )
        self.addCleanup(
            bridge.device_permissions.grant,
            PERMISSION_ANDROID_BRIDGE_PAIR,
            PERMISSION_ANDROID_BRIDGE_MANAGE,
        )
        for name in self.TRUST_TOOLS:
            with self.subTest(tool=name):
                result = await bridge.device_manager.request(name, self.PAYLOADS[name])
                self.assertEqual(result.status, ToolResultStatus.PERMISSION_DENIED)
                self.assertFalse(result.executed)

    async def test_read_tools_do_not_need_a_confirmation(self) -> None:
        for name in ("android.bridge.status", "android.device.list"):
            with self.subTest(tool=name):
                result = await bridge.device_manager.request(name, {})
                self.assertNotEqual(result.status, ToolResultStatus.PENDING_CONFIRMATION)


@requires_crypto
class SecretLeakTests(unittest.IsolatedAsyncioTestCase):
    async def test_no_secret_reaches_a_result_a_log_or_the_audit_trail(self) -> None:
        audit = RecordingAuditHook()
        bridge_, phone, _, _ = await started_pair(audit_hook=audit)
        record = await complete_pairing(bridge_, phone)
        await asyncio.gather(bridge_.connect(phone.device_id), phone.serve(max_frames=2))

        secrets = (
            phone.private_key.hex(),
            bridge_.host_identity.private_key.hex(),
            crypto.encode_public_key(phone.private_key),
            crypto.encode_public_key(bridge_.host_identity.private_key),
        )
        haystacks = {
            "status": repr(bridge_.status()),
            "devices": repr(bridge_.list_devices()),
            "device_status": repr(bridge_.device_status(phone.device_id)),
            "pending": repr(bridge_.pending_pairings(include_finished=True)),
            "capabilities": repr(bridge_.capabilities(phone.device_id)),
            "audit": audit.raw_text(),
            "host": repr(bridge_.host_identity.to_safe_dict()),
            "pairing": repr(record),
        }
        for label, haystack in haystacks.items():
            for secret in secrets:
                with self.subTest(where=label):
                    self.assertNotIn(secret, haystack)
                    self.assertNotIn(secret[:32], haystack)
            self.assertNotIn("private_key", haystack)

    async def test_the_registry_file_holds_no_private_material(self) -> None:
        import os
        import tempfile

        from jarvis_devices.android_registry import JsonAndroidDeviceRegistry

        bridge_, phone, _, _ = await started_pair()
        path = os.path.join(tempfile.mkdtemp(), "devices.json")
        bridge_.registry = JsonAndroidDeviceRegistry(path)
        await complete_pairing(bridge_, phone)
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        self.assertNotIn(phone.private_key.hex(), text)
        self.assertNotIn(bridge_.host_identity.private_key.hex(), text)
        self.assertNotIn("private_key", text)

    async def test_the_default_bridge_writes_no_key_to_disk(self) -> None:
        """Phase 5 keeps the host key in memory only - nothing opens a file."""
        bridge_ = create_default_android_bridge()
        if crypto.crypto_available():
            self.assertIsNotNone(bridge_.host_identity)
        for source in (
            "android_bridge.py",
            "android_crypto.py",
            "android_identity.py",
            "android_tools.py",
            "android_protocol.py",
            "android_transport.py",
        ):
            tree = ast.parse((ROOT / "jarvis_devices" / source).read_text(encoding="utf-8"))
            calls = {
                node.func.id
                for node in ast.walk(tree)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            }
            with self.subTest(file=source):
                self.assertNotIn("open", calls)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
