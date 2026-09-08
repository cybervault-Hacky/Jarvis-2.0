"""Phase 3 security tests for the PC system controls.

These prove the properties that matter for a voice controlled agent:

* the new modules contain no shell, process, ``eval``/``exec`` or ``ctypes``
  primitive, and import no module that could provide one;
* no tool argument can carry a command, a path, a program name or a network
  configuration string - the only argument in the whole phase is ``level``;
* every operation still goes through registry -> validation -> permissions ->
  platform -> confirmation -> backend -> structured result, when called through
  the real LiveKit bridge;
* unsupported hardware can never be reported as a success;
* the legacy shell based ``Jarvis_window_CTRL.open()`` is not reachable from the
  new code.
"""

from __future__ import annotations

import ast
import asyncio
import unittest
from pathlib import Path
from unittest import mock

from jarvis_devices import (
    AuditLogger,
    ConfirmationManager,
    ConfirmationPolicy,
    DeviceActionManager,
    DeviceToolRegistry,
    ErrorCode,
    PermissionPolicy,
    Platform,
    PlatformRegistry,
    ToolResultStatus,
)
from jarvis_devices.pc_system import PC_SYSTEM_TOOL_NAMES, ConnectivityState, build_pc_system_tools
from jarvis_devices.permissions import (
    PERMISSION_BLUETOOTH_CONTROL,
    PERMISSION_DEVICE_STATUS_READ,
    PERMISSION_DISPLAY_CONTROL,
    PERMISSION_NETWORK_CONTROL,
    PERMISSION_VOLUME_CONTROL,
)

try:  # imported as part of the ``tests`` package (pytest / discover -t .)
    from .pc_system_support import FakePCSystemBackend
    from .support import AuditCapture, FakeAdapter
    from .test_security import (
        FORBIDDEN_IMPORTS,
        FORBIDDEN_PATTERNS,
        FORBIDDEN_TERMINATION_PATTERNS,
        code_only_source,
        imported_modules,
    )
except ImportError:  # ``python -m unittest discover -s tests``
    from pc_system_support import FakePCSystemBackend
    from support import AuditCapture, FakeAdapter
    from test_security import (
        FORBIDDEN_IMPORTS,
        FORBIDDEN_PATTERNS,
        FORBIDDEN_TERMINATION_PATTERNS,
        code_only_source,
        imported_modules,
    )

import Jarvis_device_control as bridge

ROOT = Path(__file__).resolve().parent.parent
PHASE3_SOURCES = (
    ROOT / "jarvis_devices" / "pc_system.py",
    ROOT / "jarvis_devices" / "pc_system_windows.py",
    ROOT / "Jarvis_device_control.py",
    ROOT / "agent.py",
)

#: Names a "change my network/power settings" backdoor would probably use.
FORBIDDEN_TOOL_WORDS = ("command", "cmd", "powershell", "script", "path", "executable", "shell")


class BridgeSystemBackend:
    """Swaps the bridge's real system backend for a scripted fake."""

    METHODS = (
        "is_available",
        "unavailable_reason",
        "capabilities",
        "system_info",
        "get_volume",
        "set_volume",
        "get_mute",
        "set_mute",
        "get_brightness",
        "set_brightness",
        "wifi_status",
        "set_wifi",
        "bluetooth_status",
        "set_bluetooth",
    )

    def __init__(self, fake: FakePCSystemBackend) -> None:
        self.fake = fake
        self._patches = []

    def __enter__(self) -> FakePCSystemBackend:
        backend = bridge.pc_system_backend
        for method in self.METHODS:
            patch = mock.patch.object(backend, method, getattr(self.fake, method))
            patch.start()
            self._patches.append(patch)
        return self.fake

    def __exit__(self, *exc_info) -> None:
        for patch in reversed(self._patches):
            patch.stop()


# ---------------------------------------------------------------------------
# Static analysis
# ---------------------------------------------------------------------------
class StaticAnalysisTests(unittest.TestCase):
    def test_no_process_or_eval_primitive_anywhere_in_phase_3(self) -> None:
        for source in PHASE3_SOURCES:
            code = code_only_source(source)
            for label, pattern in FORBIDDEN_PATTERNS.items():
                with self.subTest(file=source.name, forbidden=label):
                    self.assertIsNone(pattern.search(code), f"{source.name} must not contain {label}")

    def test_no_forbidden_module_is_imported(self) -> None:
        for source in PHASE3_SOURCES:
            with self.subTest(file=source.name):
                self.assertEqual(imported_modules(source) & FORBIDDEN_IMPORTS, set())

    def test_no_process_termination_api(self) -> None:
        for source in PHASE3_SOURCES:
            code = code_only_source(source)
            for label, pattern in FORBIDDEN_TERMINATION_PATTERNS.items():
                with self.subTest(file=source.name, forbidden=label):
                    self.assertIsNone(pattern.search(code), f"{source.name} must not contain {label}")

    def test_the_legacy_shell_path_is_not_reachable(self) -> None:
        """``Jarvis_window_CTRL`` still exists, but the new code never touches it."""
        for source in (
            ROOT / "jarvis_devices" / "pc_system.py",
            ROOT / "jarvis_devices" / "pc_system_windows.py",
            ROOT / "Jarvis_device_control.py",
        ):
            with self.subTest(file=source.name):
                self.assertNotIn("Jarvis_window_CTRL", imported_modules(source))
                self.assertNotIn("Jarvis_window_CTRL", code_only_source(source))

    def test_windows_backend_never_imports_an_execution_module(self) -> None:
        """pycaw/pywin32 are the only OS bindings, and both are guarded."""
        imported = imported_modules(ROOT / "jarvis_devices" / "pc_system_windows.py")
        self.assertNotIn("os", imported)
        self.assertNotIn("subprocess", imported)
        self.assertNotIn("ctypes", imported)
        self.assertTrue({"platform", "typing"} <= imported)

    def test_every_wql_is_a_module_constant_never_built_at_runtime(self) -> None:
        """An interpolated query would be a WQL injection; there are none.

        Two structural properties together make injection impossible:

        1. ``ExecQuery`` is called in exactly one place, and it forwards its
           ``query`` parameter - so nothing is assembled there;
        2. every call of the internal ``_query`` helper passes a module level
           constant, and those constants are plain string literals.
        """
        source = ROOT / "jarvis_devices" / "pc_system_windows.py"
        tree = ast.parse(source.read_text(encoding="utf-8"))

        string_constants = {
            node.targets[0].id
            for node in tree.body
            if isinstance(node, ast.Assign)
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
            and node.targets[0].id.endswith("QUERY")
        }
        self.assertGreaterEqual(len(string_constants), 6)

        exec_query_sites = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "ExecQuery"
        ]
        self.assertEqual(len(exec_query_sites), 1, "there must be exactly one ExecQuery call site")
        self.assertEqual(exec_query_sites[0].args[0].id, "query")  # forwarded, never built

        query_calls = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "_query"
        ]
        self.assertGreaterEqual(len(query_calls), 5)
        for node in query_calls:
            with self.subTest(line=node.lineno):
                self.assertIsInstance(node.args[1], ast.Name)
                self.assertIn(node.args[1].id, string_constants)

        # No query constant is an f-string or a concatenation with a variable.
        for node in tree.body:
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
                if node.targets[0].id.endswith("QUERY"):
                    self.assertNotIsInstance(node.value, ast.JoinedStr)
                    self.assertNotIsInstance(node.value, ast.BinOp)

    def test_no_tool_argument_can_carry_a_command(self) -> None:
        for tool in build_pc_system_tools(FakePCSystemBackend(), platform_probe=lambda: Platform.PC):
            names = tool.argument_schema.names
            with self.subTest(tool=tool.name):
                self.assertTrue(set(names) <= {"level"})
                for word in FORBIDDEN_TOOL_WORDS:
                    self.assertNotIn(word, tool.name)
                for spec in tool.argument_schema.specs:
                    self.assertIs(spec.type, int)
                    self.assertEqual((spec.min_value, spec.max_value), (0, 100))


# ---------------------------------------------------------------------------
# Live bridge behaviour
# ---------------------------------------------------------------------------
class BridgeSecurityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.fake = FakePCSystemBackend()
        self.patcher = BridgeSystemBackend(self.fake)
        self.patcher.__enter__()
        self.addCleanup(self.patcher.__exit__, None, None, None)

    # ------------------------------------------------------------------
    def test_all_fourteen_tools_are_registered(self) -> None:
        registered = set(bridge.device_registry.names())
        self.assertEqual(len(PC_SYSTEM_TOOL_NAMES), 14)
        self.assertTrue(set(PC_SYSTEM_TOOL_NAMES) <= registered)

    def test_the_bridge_grants_only_the_three_local_permissions(self) -> None:
        granted = set(bridge.device_permissions.granted_permissions)
        self.assertTrue(
            {PERMISSION_VOLUME_CONTROL, PERMISSION_DISPLAY_CONTROL, PERMISSION_NETWORK_CONTROL} <= granted
        )
        self.assertNotIn(PERMISSION_BLUETOOTH_CONTROL, granted)

    async def test_read_tools_run_without_confirmation(self) -> None:
        for name in (
            "pc.system.status",
            "pc.system.get_volume",
            "pc.system.get_mute",
            "pc.system.get_brightness",
            "pc.system.wifi.status",
            "pc.system.bluetooth.status",
        ):
            with self.subTest(tool=name):
                result = bridge.describe_result(await bridge.device_manager.request(name))
                self.assertTrue(result.startswith("✅"), result)

    async def test_local_controls_run_without_confirmation(self) -> None:
        cases = (
            ("pc.system.set_volume", {"level": 30}),
            ("pc.system.mute", {}),
            ("pc.system.unmute", {}),
            ("pc.system.set_brightness", {"level": 30}),
        )
        for name, arguments in cases:
            with self.subTest(tool=name):
                result = await bridge.device_manager.request(name, arguments)
                self.assertTrue(result.success, result.message)

    async def test_connectivity_controls_always_ask_first(self) -> None:
        for name in ("pc.system.wifi.enable", "pc.system.wifi.disable"):
            with self.subTest(tool=name):
                result = await bridge.device_manager.request(name)
                self.assertEqual(result.status, ToolResultStatus.PENDING_CONFIRMATION)
                self.assertNotIn("set_wifi:True", self.fake.calls)
                self.assertNotIn("set_wifi:False", self.fake.calls)
                bridge.device_confirmations.cancel(result.data["confirmation_id"])

    async def test_a_revoked_permission_cannot_be_bypassed_by_the_model(self) -> None:
        bridge.device_permissions.revoke(PERMISSION_VOLUME_CONTROL)
        self.addCleanup(bridge.device_permissions.grant, PERMISSION_VOLUME_CONTROL)
        result = await bridge.device_manager.request("pc.system.set_volume", {"level": 100})
        self.assertEqual(result.status, ToolResultStatus.PERMISSION_DENIED)
        self.assertEqual(result.error_code, ErrorCode.PERMISSION_DENIED)
        self.assertFalse(result.executed)
        self.assertEqual(self.fake.volume_level, 40.0)

    async def test_bluetooth_control_is_denied_by_default(self) -> None:
        result = await bridge.device_manager.request("pc.system.bluetooth.enable")
        self.assertEqual(result.status, ToolResultStatus.PERMISSION_DENIED)
        self.assertEqual(result.error_code, ErrorCode.PERMISSION_DENIED)
        self.assertNotIn("set_bluetooth:True", self.fake.calls)

    async def test_unregistered_names_are_refused(self) -> None:
        for name in (
            "pc.system.shutdown",
            "pc.system.set_volume --force",
            "pc.system.wifi.connect",
            "shutdown /s /t 0",
            "powershell Set-NetAdapter",
        ):
            with self.subTest(name=name):
                result = await bridge.device_manager.request(name, {"level": 50})
                self.assertFalse(result.success)
                self.assertEqual(result.error_code, ErrorCode.UNKNOWN_TOOL)
                self.assertFalse(result.executed)

    async def test_the_plain_coroutines_never_reach_a_shell(self) -> None:
        self.assertEqual(
            (await bridge.run_set_system_volume(20)).split(":")[0],
            "✅ pc.system.set_volume",
        )
        self.assertEqual(self.fake.volume_level, 20.0)
        pending = await bridge.run_wifi_disable()
        self.assertTrue(pending.startswith("⚠️ Confirmation required"), pending)
        self.assertNotIn("set_wifi:False", self.fake.calls)

    async def test_a_hostile_level_argument_is_refused_before_anything_runs(self) -> None:
        for payload in (
            -1, 101, "shutdown /s", "1; rm -rf /", True, float("inf"),
            "../../etc/passwd", "..\\..\\Windows\\System32", "0x32", " 50 ", [50], {"level": 50},
        ):
            with self.subTest(payload=repr(payload)):
                result = await bridge.device_manager.request("pc.system.set_volume", {"level": payload})
                self.assertEqual(result.status, ToolResultStatus.INVALID_ARGUMENT)
                self.assertFalse(result.executed)
        self.assertEqual(self.fake.volume_level, 40.0)

    async def test_undeclared_arguments_cannot_sneak_in(self) -> None:
        result = await bridge.device_manager.request(
            "pc.system.set_volume",
            {"level": 40, "command": "netsh wlan set profile", "adapter": "Wi-Fi"},
        )
        self.assertEqual(result.status, ToolResultStatus.INVALID_ARGUMENT)
        self.assertFalse(result.executed)

    async def test_unsupported_hardware_is_spoken_as_not_executed(self) -> None:
        self.fake.capability_map["volume"] = "unsupported"
        self.fake.volume_error = self.fake.unsupported("no audio endpoint")
        message = bridge.describe_result(await bridge.device_manager.request("pc.system.get_volume"))
        self.assertTrue(message.startswith("❌ Not executed (system_control_unavailable)"), message)
        self.assertFalse(message.startswith("✅"))

    async def test_a_failed_backend_call_is_spoken_as_not_executed(self) -> None:
        from jarvis_devices.pc_system import PCSystemBackendError

        self.fake.brightness_error = PCSystemBackendError("WMI is down")
        message = bridge.describe_result(
            await bridge.device_manager.request("pc.system.set_brightness", {"level": 40})
        )
        self.assertTrue(message.startswith("❌ Not executed (brightness_control_failed)"), message)

    async def test_the_read_only_default_policy_blocks_every_control_tool(self) -> None:
        """Deny by default: with_local_defaults grants nothing but status reads."""
        policy = PermissionPolicy.with_local_defaults()
        for name in (
            "pc.system.set_volume",
            "pc.system.mute",
            "pc.system.set_brightness",
        ):
            with self.subTest(tool=name):
                decision = policy.check(bridge.device_registry.get(name))
                self.assertFalse(decision.allowed)

    async def test_the_status_payload_contains_no_secrets(self) -> None:
        self.fake.system_info_map = {
            "os": "windows",
            "release": "11",
            "machine": "AMD64",
            "hostname": "SECRET-LAPTOP",
            "wifi_password": "hunter2",
        }
        result = await bridge.device_manager.request("pc.system.status")
        self.assertTrue(result.success)
        blob = repr(result.to_dict())
        self.assertNotIn("SECRET-LAPTOP", blob)
        self.assertNotIn("hunter2", blob)

    def test_framework_summary_exposes_capabilities_not_values(self) -> None:
        summary = bridge.framework_summary()
        self.assertIn("system_capabilities", summary)
        self.assertEqual(
            set(summary["system_capabilities"]),
            {"volume", "brightness", "wifi", "bluetooth"},
        )


class AuditLoggingTests(unittest.IsolatedAsyncioTestCase):
    """Phase 3 requests are audited - without leaking values or secrets."""

    ALL_PERMISSIONS = (
        PERMISSION_DEVICE_STATUS_READ,
        PERMISSION_VOLUME_CONTROL,
        PERMISSION_DISPLAY_CONTROL,
        PERMISSION_NETWORK_CONTROL,
    )

    def build(self, *, backend=None):
        self.backend = backend if backend is not None else FakePCSystemBackend()
        audit = AuditLogger(enabled=True)
        self.capture = AuditCapture(audit)
        registry = DeviceToolRegistry()
        registry.register_all(build_pc_system_tools(self.backend, platform_probe=lambda: Platform.PC))
        platforms = PlatformRegistry()
        platforms.register(FakeAdapter(Platform.PC))
        policy = ConfirmationPolicy()
        return DeviceActionManager(
            registry,
            PermissionPolicy(granted=self.ALL_PERMISSIONS),
            ConfirmationManager(policy=policy),
            platforms,
            audit,
            confirmation_policy=policy,
        )

    async def test_a_successful_action_is_audited(self) -> None:
        manager = self.build()
        result = await manager.request("pc.system.set_volume", {"level": 42})
        self.assertTrue(result.success)
        self.assertTrue(self.capture.events, "nothing was audited")
        self.assertIn("pc.system.set_volume", self.capture.raw_text())

    async def test_undeclared_arguments_never_reach_the_log(self) -> None:
        manager = self.build()
        result = await manager.request(
            "pc.system.set_volume",
            {"level": 40, "password": "hunter2", "api_key": "AIzaSyDUMMYKEY123", "note": "token=abc"},
        )
        self.assertEqual(result.status, ToolResultStatus.INVALID_ARGUMENT)
        text = self.capture.raw_text()
        for secret in ("hunter2", "AIzaSyDUMMYKEY123", "token=abc"):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, text)

    async def test_a_hostile_tool_name_is_audited_without_being_executed(self) -> None:
        manager = self.build()
        result = await manager.request("pc.system.shutdown && rm -rf /")
        self.assertEqual(result.error_code, ErrorCode.UNKNOWN_TOOL)
        self.assertFalse(result.executed)
        self.assertTrue(self.capture.events)

    async def test_the_status_payload_is_not_written_to_the_audit_log(self) -> None:
        backend = FakePCSystemBackend(
            system_info={"os": "windows", "release": "11", "machine": "AMD64", "hostname": "SECRET-LAPTOP"},
            wifi=ConnectivityState.ON,
        )
        manager = self.build(backend=backend)
        result = await manager.request("pc.system.status")
        self.assertTrue(result.success)
        self.assertNotIn("SECRET-LAPTOP", self.capture.raw_text())

    async def test_a_confirmation_request_does_not_leak_into_the_log(self) -> None:
        manager = self.build()
        asked = await manager.request("pc.system.wifi.disable")
        self.assertEqual(asked.status, ToolResultStatus.PENDING_CONFIRMATION)
        text = self.capture.raw_text()
        self.assertIn("pc.system.wifi.disable", text)
        self.assertNotIn("hunter2", text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
