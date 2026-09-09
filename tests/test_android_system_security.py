"""Phase 6 security tests for Android system control.

Covers the thirty properties the phase is required to prove, plus a static audit
that Phase 6 introduced no process, shell, socket, deserialisation or ADB
primitive - and did not weaken the Phase 1 invariant that no module in
``jarvis_devices`` imports ``os``.
"""

from __future__ import annotations

import ast
import asyncio
import json
import unittest
from pathlib import Path

from jarvis_devices import android_crypto as crypto
from jarvis_devices.android_bridge import (
    AndroidDeviceNotConnectedError,
    AndroidDeviceRevokedError,
    AndroidDeviceUnknownError,
)
from jarvis_devices.android_identity import TrustState
from jarvis_devices.android_protocol import (
    MAX_MESSAGE_BYTES,
    SYSTEM_CONTROL_REQUESTS,
    SYSTEM_CONTROL_RESPONSES,
    BridgeMessage,
    MessageType,
)
from jarvis_devices.android_system_tools import (
    ANDROID_SYSTEM_TOOL_NAMES,
    build_android_system_tools,
)
from jarvis_devices.enums import ToolResultStatus
from jarvis_devices.errors import ErrorCode

try:
    from .android_support import FakeAndroidDevice, RecordingAuditHook, requires_crypto
    from .android_system_support import answered, system_phone_pair
    from .test_security import (
        FORBIDDEN_IMPORTS,
        FORBIDDEN_PATTERNS,
        FORBIDDEN_TERMINATION_PATTERNS,
        code_only_source,
        imported_modules,
    )
except ImportError:
    from android_support import FakeAndroidDevice, RecordingAuditHook, requires_crypto
    from android_system_support import answered, system_phone_pair
    from test_security import (
        FORBIDDEN_IMPORTS,
        FORBIDDEN_PATTERNS,
        FORBIDDEN_TERMINATION_PATTERNS,
        code_only_source,
        imported_modules,
    )

import Jarvis_device_control as bridge

ROOT = Path(__file__).resolve().parent.parent
PHASE6_SOURCES = (
    ROOT / "jarvis_devices" / "android_system.py",
    ROOT / "jarvis_devices" / "android_system_tools.py",
    ROOT / "jarvis_devices" / "android_protocol.py",
    ROOT / "jarvis_devices" / "android_bridge.py",
    ROOT / "Jarvis_device_control.py",
    ROOT / "agent.py",
)
#: Only these modules are new in Phase 6.
NEW_SOURCES = PHASE6_SOURCES[:2]

#: Substrings that would mean a command, shell or ADB call is embedded.
COMMAND_SHAPES = (
    "adb ", "adb.exe", "cmd.exe", "powershell", "shell=", "os.system", "subprocess",
    "/system/bin", "pm start", "am start", "input tap", "wm size", "settings put",
    "svc wifi", "svc bluetooth", "&&", "||", "; rm",
)

#: Words that would mean a destination or an arbitrary Android API can be named.
DESTINATION_WORDS = ("0.0.0.0", "bind(", "listen(", "socket.socket", "connect_ex")

#: Parameter names a model-facing system-control method must never accept.
FORBIDDEN_PARAMETERS = (
    "command", "cmd", "shell", "flags", "host", "hostname", "ip", "port", "address",
    "url", "path", "executable", "script", "adb", "method", "api", "action",
    "stream", "ssid", "password", "toggle", "force", "confirm",
)


# ===========================================================================
# Static audit (§22)
# ===========================================================================
class StaticAuditTests(unittest.TestCase):
    def test_no_process_eval_or_shell_primitive(self) -> None:
        for source in PHASE6_SOURCES:
            code = code_only_source(source)
            for label, pattern in FORBIDDEN_PATTERNS.items():
                with self.subTest(file=source.name, forbidden=label):
                    self.assertIsNone(pattern.search(code))

    def test_no_forbidden_module_is_imported(self) -> None:
        """Includes the Phase 1 rule: no module in jarvis_devices imports ``os``."""
        for source in PHASE6_SOURCES:
            with self.subTest(file=source.name):
                self.assertEqual(imported_modules(source) & FORBIDDEN_IMPORTS, set())

    def test_no_process_termination_api(self) -> None:
        for source in PHASE6_SOURCES:
            code = code_only_source(source)
            for label, pattern in FORBIDDEN_TERMINATION_PATTERNS.items():
                with self.subTest(file=source.name, forbidden=label):
                    self.assertIsNone(pattern.search(code))

    def test_no_socket_ctypes_or_unsafe_deserialiser(self) -> None:
        for source in PHASE6_SOURCES:
            modules = imported_modules(source)
            with self.subTest(file=source.name):
                for forbidden in ("socket", "ctypes", "subprocess", "pickle", "marshal", "os", "pty"):
                    self.assertNotIn(forbidden, modules)

    def test_no_unsafe_decoder_is_called(self) -> None:
        unsafe = {"pickle", "marshal", "shelve", "dill", "yaml"}
        for source in PHASE6_SOURCES:
            tree = ast.parse(code_only_source(source))
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                    continue
                receiver = node.func.value
                name = receiver.id if isinstance(receiver, ast.Name) else ""
                with self.subTest(file=source.name, call=f"{name}.{node.func.attr}"):
                    self.assertNotIn(name, unsafe)
                    if node.func.attr in {"loads", "load", "Unpickler"}:
                        self.assertEqual(name, "json")

    def test_no_listening_endpoint_exists(self) -> None:
        for source in PHASE6_SOURCES:
            code = code_only_source(source)
            for word in DESTINATION_WORDS:
                with self.subTest(file=source.name, word=word):
                    self.assertNotIn(word, code)

    def test_no_command_shaped_string_constant(self) -> None:
        for source in PHASE6_SOURCES:
            tree = ast.parse(code_only_source(source))
            constants = [
                n.value for n in ast.walk(tree)
                if isinstance(n, ast.Constant) and isinstance(n.value, str)
            ]
            # Docstrings and f-strings are not plain constants, so a small
            # module can legitimately have only a few.
            self.assertGreaterEqual(len(constants), 1)
            for literal in constants:
                lowered = literal.lower()
                for forbidden in COMMAND_SHAPES:
                    with self.subTest(file=source.name, forbidden=forbidden):
                        self.assertNotIn(forbidden, lowered)

    def test_no_model_facing_method_takes_a_steerable_parameter(self) -> None:
        model_facing = {
            "android_system.py": {
                "status", "get_volume", "set_volume", "mute", "unmute",
                "get_brightness", "set_brightness", "get_wifi_status",
                "set_wifi_enabled", "get_bluetooth_status", "set_bluetooth_enabled",
                "_call", "_prepare", "unwrap_response",
            },
            "android_system_tools.py": {"run", "failure", "guard"},
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
        self.assertGreater(checked, 30)

    def test_no_execute_style_backdoor_is_exposed(self) -> None:
        for name in (
            "android_execute", "android_adb", "android_shell", "android_command",
            "android_run", "android_raw_send", "run_android_execute", "run_android_adb",
            "run_android_command", "run_android_shell",
        ):
            with self.subTest(name=name):
                self.assertFalse(hasattr(bridge, name))

    def test_the_protocol_has_no_generic_operation_type(self) -> None:
        """§10: no command/execute/shell/adb/run/arbitrary message type."""
        for name in MessageType(member.value).value if False else sorted(
            member.value for member in MessageType
        ):
            with self.subTest(message_type=name):
                for forbidden in (
                    "command", "execute", "shell", "adb", "run", "arbitrary",
                    "raw", "eval", "invoke", "method",
                ):
                    self.assertNotIn(forbidden, name)

    def test_every_system_request_has_exactly_one_response_type(self) -> None:
        from jarvis_devices.android_protocol import RESPONSE_FOR

        self.assertEqual(len(SYSTEM_CONTROL_REQUESTS), 10)
        self.assertEqual(len(SYSTEM_CONTROL_RESPONSES), 10)
        self.assertEqual(SYSTEM_CONTROL_REQUESTS & SYSTEM_CONTROL_RESPONSES, frozenset())
        for request in SYSTEM_CONTROL_REQUESTS:
            with self.subTest(request=request):
                self.assertIn(request, RESPONSE_FOR)
                self.assertIn(RESPONSE_FOR[request], SYSTEM_CONTROL_RESPONSES)


class RegistrationTests(unittest.TestCase):
    def test_each_system_tool_is_registered_exactly_once(self) -> None:
        names = list(bridge.device_registry.names())
        self.assertEqual(len(names), len(set(names)))
        for name in ANDROID_SYSTEM_TOOL_NAMES:
            with self.subTest(tool=name):
                self.assertEqual(names.count(name), 1)
        # Phase 9 adds exactly two read-only cross-device inventory tools.
        self.assertEqual(len(bridge.device_registry.names()), 53)

    def test_the_builder_returns_thirteen_unique_tools(self) -> None:
        from jarvis_devices.android_bridge import create_default_android_bridge

        tools = build_android_system_tools(create_default_android_bridge())
        self.assertEqual([t.name for t in tools], list(ANDROID_SYSTEM_TOOL_NAMES))
        self.assertEqual(len({id(t) for t in tools}), 13)

    def test_the_bridge_exports_each_wrapper_once(self) -> None:
        for name in (
            "android_system_status", "android_get_volume", "android_set_volume",
            "android_mute", "android_unmute", "android_get_brightness",
            "android_set_brightness", "android_wifi_status", "android_wifi_enable",
            "android_wifi_disable", "android_bluetooth_status",
            "android_bluetooth_enable", "android_bluetooth_disable",
        ):
            with self.subTest(wrapper=name):
                self.assertTrue(hasattr(bridge, name))
                self.assertEqual(bridge.__all__.count(name), 1)
        self.assertEqual(len(set(bridge.__all__)), len(bridge.__all__))


# ===========================================================================
# Runtime security (§21)
# ===========================================================================
@requires_crypto
class TargetingSecurityTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.bridge, self.phone, self.control, _, _ = await system_phone_pair()
        self.did = self.phone.device_id

    async def test_01_unknown_device_rejected(self) -> None:
        with self.assertRaises(AndroidDeviceUnknownError):
            await self.control.set_volume("adev-" + "0" * 32, 50)

    async def test_02_unpaired_device_rejected(self) -> None:
        other, phone2, control2, _, _ = await system_phone_pair(paired_and_connected=False)
        with self.assertRaises(AndroidDeviceUnknownError):
            await control2.set_volume(phone2.device_id, 50)

    async def test_03_revoked_device_rejected(self) -> None:
        self.bridge.revoke(self.did)
        with self.assertRaises(AndroidDeviceRevokedError):
            await self.control.set_wifi_enabled(self.did, False)
        self.assertIs(
            self.bridge.registry.get(self.did).trust_state, TrustState.REVOKED
        )

    async def test_04_disconnected_device_rejected(self) -> None:
        await answered(self.bridge.disconnect(self.did), self.phone)
        with self.assertRaises(AndroidDeviceNotConnectedError):
            await self.control.set_volume(self.did, 50)

    async def test_05_unsupported_capability_rejected(self) -> None:
        from jarvis_devices.android_bridge import AndroidCapabilityUnavailableError

        _, phone, control, _, _ = await system_phone_pair(
            capabilities=("bridge.protocol", "system.volume")
        )
        with self.assertRaises(AndroidCapabilityUnavailableError):
            await control.set_wifi_enabled(phone.device_id, False)

    async def test_06_invalid_device_id_rejected(self) -> None:
        for bad in ("192.168.1.50", "pixel.lan", "", "adev-short", "x" * 500, None, 42):
            with self.subTest(bad=str(bad)[:20]):
                with self.assertRaises(AndroidDeviceUnknownError):
                    await self.control.get_volume(bad)

    async def test_07_invalid_volume_rejected(self) -> None:
        from jarvis_devices.android_protocol import InvalidMessageError

        for bad in (-1, 101, True, 50.5, "50", None):
            with self.subTest(bad=bad):
                with self.assertRaises(InvalidMessageError):
                    await self.control.set_volume(self.did, bad)
        self.assertEqual(self.phone.controller.volume, 40)

    async def test_08_invalid_brightness_rejected(self) -> None:
        from jarvis_devices.android_protocol import InvalidMessageError

        for bad in (-1, 101, True, 0.5, "50", None):
            with self.subTest(bad=bad):
                with self.assertRaises(InvalidMessageError):
                    await self.control.set_brightness(self.did, bad)
        self.assertEqual(self.phone.controller.brightness, 60)

    async def test_16_arbitrary_ip_rejected(self) -> None:
        for ip in ("192.168.1.50", "10.0.0.5:5555", "127.0.0.1", "::1", "8.8.8.8"):
            with self.subTest(ip=ip):
                with self.assertRaises(AndroidDeviceUnknownError):
                    await self.control.get_wifi_status(ip)

    async def test_17_arbitrary_port_rejected(self) -> None:
        for target in ("adev-" + "a" * 32 + ":5555", "pixel:5555", "localhost:8080"):
            with self.subTest(target=target):
                with self.assertRaises(AndroidDeviceUnknownError):
                    await self.control.get_wifi_status(target)

    async def test_25_timeout_never_reports_success(self) -> None:
        from jarvis_devices.android_system import AndroidSystemTimeoutError

        self.phone.silent = True
        for coro in (
            self.control.get_volume(self.did),
            self.control.set_wifi_enabled(self.did, False),
        ):
            with self.subTest(coro=coro):
                with self.assertRaises(AndroidSystemTimeoutError):
                    await answered(coro, self.phone)
        self.assertTrue(self.phone.controller.wifi_enabled)  # unchanged

    async def test_26_transport_failure_never_reports_success(self) -> None:
        from jarvis_devices.android_bridge import AndroidBridgeError

        self.bridge.transport.break_link()
        with self.assertRaises(AndroidBridgeError):
            await self.control.set_volume(self.did, 50)
        self.assertEqual(self.phone.controller.volume, 40)

    async def test_27_no_toggle_operation_exists(self) -> None:
        for name in ANDROID_SYSTEM_TOOL_NAMES:
            with self.subTest(tool=name):
                self.assertNotIn("toggle", name)
        for name in dir(self.control):
            self.assertNotIn("toggle", name)
        self.assertFalse(hasattr(bridge, "android_wifi_toggle"))
        self.assertFalse(hasattr(bridge, "android_bluetooth_toggle"))
        self.assertFalse(hasattr(bridge, "android_mute_toggle"))

    async def test_30_no_arbitrary_method_or_api_name_can_be_supplied(self) -> None:
        """The model can name an operation only by choosing a registered tool."""
        for extra in (
            {"method": "setStreamVolume"},
            {"api": "AudioManager.setStreamVolume"},
            {"action": "adb shell svc wifi enable"},
            {"command": "svc wifi enable"},
            {"stream": "STREAM_RING"},
        ):
            with self.subTest(extra=str(extra)[:34]):
                result = await bridge.device_manager.request(
                    "android.system.set_volume",
                    {"device": self.did, "level": 50, **extra},
                )
                self.assertEqual(result.status, ToolResultStatus.INVALID_ARGUMENT)


@requires_crypto
class FrameSecurityTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.bridge, self.phone, self.control, _, self.phone_side = await system_phone_pair()
        self.did = self.phone.device_id

    async def test_09_unknown_protocol_message_rejected(self) -> None:
        for raw in (
            b'{"protocol_version": 1, "message_type": "adb_shell"}',
            b'{"protocol_version": 1, "message_type": "execute"}',
            b'{"protocol_version": 1, "message_type": "volume_set_v2"}',
        ):
            with self.subTest(raw=raw[30:60]):
                await self.bridge.handle_frame(raw)
        self.assertGreaterEqual(self.bridge._counters["frames_rejected"], 3)

    async def test_10_forged_response_rejected(self) -> None:
        impostor = FakeAndroidDevice(self.phone_side, display_name="Impostor")

        async def impostor_answers():
            message = await impostor.receive(0.3)
            self.assertIsNotNone(message)
            frame = BridgeMessage.create(
                MessageType.VOLUME_GET_RESPONSE,
                self.did,
                payload={"ok": True, "volume": 1, "muted": False},
                request_id=message.request_id,
                sequence=900,
                session_id=message.session_id,
            ).sign(impostor.private_key)
            await impostor.transport.send(frame.to_bytes())

        from jarvis_devices.android_system import AndroidSystemTimeoutError

        task = asyncio.create_task(impostor_answers())
        with self.assertRaises(AndroidSystemTimeoutError):
            await self.control.get_volume(self.did)
        await task
        self.assertGreaterEqual(self.bridge._counters["authentication_failures"], 1)

    async def test_11_replay_rejected(self) -> None:
        frame = await self.phone.push_heartbeat()
        await self.bridge.pump()
        replays = self.bridge._counters["replays_detected"]
        await self.bridge.handle_frame(frame.to_bytes())
        await self.bridge.handle_frame(frame.to_bytes())
        self.assertGreater(self.bridge._counters["replays_detected"], replays)

    async def test_12_wrong_device_response_rejected(self) -> None:
        impostor = FakeAndroidDevice(self.phone_side, display_name="Impostor")

        async def impostor_answers():
            message = await impostor.receive(0.3)
            self.assertIsNotNone(message)
            await impostor.send(
                BridgeMessage.create(
                    MessageType.VOLUME_GET_RESPONSE,
                    impostor.device_id,  # its own identity
                    payload={"ok": True, "volume": 1, "muted": False},
                    request_id=message.request_id,
                    sequence=1,
                    session_id=message.session_id,
                    timestamp=impostor._now(),
                )
            )

        from jarvis_devices.android_system import AndroidSystemTimeoutError

        task = asyncio.create_task(impostor_answers())
        with self.assertRaises(AndroidSystemTimeoutError):
            await self.control.get_volume(self.did)
        await task
        self.assertGreaterEqual(self.bridge._counters["frames_rejected"], 1)
        self.assertEqual(self.phone.controller.volume, 40)

    async def test_13_wrong_session_rejected(self) -> None:
        from jarvis_devices.android_system import AndroidSystemTimeoutError

        async def stale_session():
            message = await self.phone.receive(0.3)
            self.assertIsNotNone(message)
            await self.phone.send(
                BridgeMessage.create(
                    MessageType.VOLUME_GET_RESPONSE,
                    self.did,
                    payload={"ok": True, "volume": 1, "muted": False},
                    request_id=message.request_id,
                    sequence=self.phone._next_sequence(),
                    session_id="sess-forged",
                    timestamp=self.phone._now(),
                )
            )

        task = asyncio.create_task(stale_session())
        with self.assertRaises(AndroidSystemTimeoutError):
            await self.control.get_volume(self.did)
        await task
        self.assertGreaterEqual(self.bridge._counters["authentication_failures"], 1)

    async def test_14_oversized_payload_rejected(self) -> None:
        await self.bridge.handle_frame(b" " * (MAX_MESSAGE_BYTES + 1))
        self.assertGreaterEqual(self.bridge._counters["frames_rejected"], 1)
        # And a tool call carrying an oversized argument never reaches the phone.
        result = await bridge.device_manager.request(
            "android.system.set_volume", {"device": self.did, "level": 50, "blob": "x" * 200_000}
        )
        self.assertTrue(result.message.startswith("❌") or not result.success)

    async def test_15_unexpected_fields_rejected(self) -> None:
        for extra in ({"shell": "adb"}, {"host": "10.0.0.5"}, {"__class__": "x"}):
            with self.subTest(extra=str(extra)):
                result = await bridge.device_manager.request(
                    "android.system.get_volume", {"device": self.did, **extra}
                )
                self.assertEqual(result.status, ToolResultStatus.INVALID_ARGUMENT)

    async def test_18_adb_like_input_rejected(self) -> None:
        for payload in ("adb shell svc wifi enable", "adb -s emulator shell", "/system/bin/sh"):
            with self.subTest(payload=payload[:24]):
                result = await bridge.device_manager.request(
                    "android.system.get_volume", {"device": payload}
                )
                self.assertEqual(result.status, ToolResultStatus.INVALID_ARGUMENT)

    async def test_19_shell_like_input_rejected(self) -> None:
        for payload in ("; rm -rf /", "$(whoami)", "`id`", "a && reboot", "| cat /etc/passwd"):
            with self.subTest(payload=payload):
                result = await bridge.device_manager.request(
                    "android.system.set_volume", {"device": self.did, "level": payload}
                )
                self.assertEqual(result.status, ToolResultStatus.INVALID_ARGUMENT)
        self.assertEqual(self.phone.controller.volume, 40)

    async def test_20_powershell_and_cmd_like_input_rejected(self) -> None:
        for payload in ("powershell -c Stop-Computer", "cmd.exe /c calc", "pwsh reboot"):
            with self.subTest(payload=payload[:24]):
                result = await bridge.device_manager.request(
                    "android.system.get_volume", {"device": payload}
                )
                self.assertEqual(result.status, ToolResultStatus.INVALID_ARGUMENT)

    async def test_21_path_traversal_rejected(self) -> None:
        for payload in ("../../../etc/passwd", "..\\..\\windows\\system32", "/system/bin/su"):
            with self.subTest(payload=payload):
                result = await bridge.device_manager.request(
                    "android.system.get_volume", {"device": payload}
                )
                self.assertEqual(result.status, ToolResultStatus.INVALID_ARGUMENT)

    async def test_device_side_authorisation_refuses_an_untrusted_caller(self) -> None:
        """§14: a valid-looking payload is not enough on the phone either."""
        _, attacker_key = crypto.generate_keypair()
        frame = BridgeMessage.create(
            MessageType.VOLUME_SET,
            self.did,
            payload={"level": 100},
            sequence=999,
            session_id=self.phone.session_id,
        ).sign(attacker_key)
        await self.bridge.transport.send(frame.to_bytes())
        await self.phone.serve(max_frames=1)
        self.assertIn(("volume_set", "bad signature"), self.phone.refusals)
        self.assertEqual(self.phone.controller.volume, 40)


@requires_crypto
class ConfirmationSecurityTests(unittest.IsolatedAsyncioTestCase):
    """Confirmation gating through the real JARVIS bridge."""

    STATE_CHANGING = (
        "android.system.set_volume",
        "android.system.mute",
        "android.system.unmute",
        "android.system.set_brightness",
    )
    CONFIRMED = (
        "android.system.wifi.enable",
        "android.system.wifi.disable",
        "android.system.bluetooth.enable",
        "android.system.bluetooth.disable",
    )
    READS = (
        "android.system.status",
        "android.system.get_volume",
        "android.system.get_brightness",
        "android.system.wifi.status",
        "android.system.bluetooth.status",
    )

    async def asyncSetUp(self) -> None:
        self.did = "adev-" + "a" * 32

    def payload(self, name):
        payload = {"device": self.did}
        if name in ("android.system.set_volume", "android.system.set_brightness"):
            payload["level"] = 50
        return payload

    async def test_22_radio_changes_always_ask_first(self) -> None:
        for name in self.CONFIRMED:
            with self.subTest(tool=name):
                result = await bridge.device_manager.request(name, self.payload(name))
                self.assertEqual(result.status, ToolResultStatus.PENDING_CONFIRMATION)
                self.assertFalse(result.success)

    async def test_confirmation_comes_from_the_policy_not_from_the_model(self) -> None:
        """The operator owns confirmation; the model cannot touch it.

        Radio tools are ``EXTERNAL_ACTION`` but deliberately *not*
        ``confirmation_mandatory`` - same as the PC's own Wi-Fi and Bluetooth
        tools in Phase 3. So ``never_confirm`` is an explicit operator choice,
        not a model bypass: nothing the model sends can change the policy, and
        no tool accepts a ``confirm`` argument (asserted in the static audit).
        """
        original = bridge.device_manager.confirmation_policy
        try:
            from jarvis_devices.confirmation import ConfirmationPolicy

            # Default policy: every radio change asks first.
            for name in self.CONFIRMED:
                with self.subTest(tool=name, policy="default"):
                    result = await bridge.device_manager.request(name, self.payload(name))
                    self.assertEqual(result.status, ToolResultStatus.PENDING_CONFIRMATION)

            # An operator can also require confirmation for the LOW_RISK tools.
            bridge.device_manager.confirmation_policy = ConfirmationPolicy(
                always_confirm=self.STATE_CHANGING
            )
            for name in self.STATE_CHANGING:
                with self.subTest(tool=name, policy="always_confirm"):
                    result = await bridge.device_manager.request(name, self.payload(name))
                    self.assertEqual(result.status, ToolResultStatus.PENDING_CONFIRMATION)
        finally:
            bridge.device_manager.confirmation_policy = original

    async def test_no_tool_argument_can_switch_confirmation_off(self) -> None:
        for name in self.CONFIRMED + self.STATE_CHANGING:
            with self.subTest(tool=name):
                result = await bridge.device_manager.request(
                    name, {**self.payload(name), "confirm": False, "confirmation": False}
                )
                self.assertEqual(result.status, ToolResultStatus.INVALID_ARGUMENT)

    async def test_reads_and_low_risk_changes_do_not_ask(self) -> None:
        """§13: confirmation is classified, not blanket."""
        for name in self.READS + self.STATE_CHANGING:
            with self.subTest(tool=name):
                result = await bridge.device_manager.request(name, self.payload(name))
                self.assertNotEqual(result.status, ToolResultStatus.PENDING_CONFIRMATION)

    async def test_23_confirmation_cannot_migrate_between_devices(self) -> None:
        pending = await bridge.device_manager.request(
            "android.system.wifi.disable", {"device": self.did}
        )
        cid = pending.data["confirmation_id"]
        other = await bridge.device_manager.request(
            "android.system.wifi.disable",
            {"device": "adev-" + "b" * 32},
            confirmation_id=cid,
        )
        # The confirmation is bound to the tool *and* the arguments it was
        # created with, so reusing it for another device cannot succeed silently.
        self.assertNotEqual(other.status, ToolResultStatus.SUCCESS)

    async def test_24_confirmation_cannot_migrate_between_tools(self) -> None:
        pending = await bridge.device_manager.request(
            "android.system.wifi.disable", {"device": self.did}
        )
        hijacked = await bridge.device_manager.request(
            "android.system.bluetooth.disable",
            {"device": self.did},
            confirmation_id=pending.data["confirmation_id"],
        )
        self.assertEqual(hijacked.error_code, ErrorCode.CONFIRMATION_MISMATCH)

    async def test_one_yes_cannot_be_used_twice(self) -> None:
        pending = await bridge.device_manager.request(
            "android.system.wifi.enable", {"device": self.did}
        )
        cid = pending.data["confirmation_id"]
        await bridge.resolve_device_confirmation(cid, True)
        again = await bridge.resolve_device_confirmation(cid, True)
        self.assertIn(ErrorCode.CONFIRMATION_REUSED, again)

    async def test_revoking_the_control_permission_blocks_every_state_change(self) -> None:
        from jarvis_devices.permissions import PERMISSION_ANDROID_SYSTEM_CONTROL

        bridge.device_permissions.revoke(PERMISSION_ANDROID_SYSTEM_CONTROL)
        self.addCleanup(
            bridge.device_permissions.grant, PERMISSION_ANDROID_SYSTEM_CONTROL
        )
        for name in self.STATE_CHANGING + self.CONFIRMED:
            with self.subTest(tool=name):
                result = await bridge.device_manager.request(name, self.payload(name))
                self.assertEqual(result.status, ToolResultStatus.PERMISSION_DENIED)
                self.assertFalse(result.executed)

    async def test_reads_still_work_with_only_the_read_permission(self) -> None:
        from jarvis_devices.permissions import PERMISSION_ANDROID_SYSTEM_CONTROL

        bridge.device_permissions.revoke(PERMISSION_ANDROID_SYSTEM_CONTROL)
        self.addCleanup(
            bridge.device_permissions.grant, PERMISSION_ANDROID_SYSTEM_CONTROL
        )
        for name in self.READS:
            with self.subTest(tool=name):
                result = await bridge.device_manager.request(name, self.payload(name))
                self.assertNotEqual(result.status, ToolResultStatus.PERMISSION_DENIED)


@requires_crypto
class SecretLeakTests(unittest.IsolatedAsyncioTestCase):
    async def test_28_no_private_key_in_results_audit_or_repr(self) -> None:
        audit = RecordingAuditHook()
        bridge_, phone, control, _, _ = await system_phone_pair(audit_hook=audit)
        did = phone.device_id
        results = [
            await answered(control.status(did), phone),
            await answered(control.get_volume(did), phone),
            await answered(control.set_volume(did, 55), phone),
            await answered(control.set_wifi_enabled(did, False), phone),
        ]
        haystacks = {
            "results": repr(results),
            "bridge_status": repr(bridge_.status()),
            "device_status": repr(bridge_.device_status(did)),
            "capabilities": repr(bridge_.capabilities(did)),
            "audit": audit.raw_text(),
            "host": repr(bridge_.host_identity.to_safe_dict()),
            "tool": repr(build_android_system_tools(bridge_)[0].describe()),
        }
        secrets = (
            phone.private_key.hex(),
            bridge_.host_identity.private_key.hex(),
            crypto.encode_public_key(phone.private_key),
        )
        for label, haystack in haystacks.items():
            for secret in secrets:
                with self.subTest(where=label):
                    self.assertNotIn(secret, haystack)
                    self.assertNotIn(secret[:32], haystack)
            self.assertNotIn("private_key", haystack)

    async def test_29_no_private_key_is_transmitted(self) -> None:
        """Nothing secret may appear in any frame on the wire."""
        bridge_, phone, control, pc_side, _ = await system_phone_pair()
        await answered(control.set_volume(phone.device_id, 61), phone)
        await answered(control.set_wifi_enabled(phone.device_id, False), phone)
        secrets = (
            phone.private_key.hex(),
            bridge_.host_identity.private_key.hex(),
            crypto.encode_public_key(phone.private_key),
            crypto.encode_public_key(bridge_.host_identity.private_key),
        )
        for label, frame in (("pc->phone", pc_side.sent[-1]),):
            text = bytes(frame).decode("utf-8", "replace")
            for secret in secrets:
                with self.subTest(where=label):
                    self.assertNotIn(secret, text)
            self.assertNotIn("private_key", text)
        # The payload of a system frame carries only the bounded value.
        sent = json.loads(bytes(pc_side.sent[-1]).decode())
        self.assertEqual(sent["payload"], {"enabled": False})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
