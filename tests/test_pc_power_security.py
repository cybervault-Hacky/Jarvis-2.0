"""Phase 4 security tests for PC power control.

These prove the properties that matter for a voice controlled agent that can
switch a machine off:

* the new modules contain no shell, process, ``eval``/``exec`` or ``ctypes``
  primitive, no command string and no reference to ``shutdown.exe``/``cmd``/
  ``powershell``;
* no tool, coroutine or backend method accepts a command, flags, timeout, reason
  or remote host - there is nothing for hostile input to attach to;
* every operation still travels registry -> validation -> permission ->
  platform -> **confirmation** -> backend -> structured result, through the real
  LiveKit bridge;
* confirmation cannot be bypassed, reused, expired-then-used or transferred
  between operations;
* nothing is registered twice, so one "yes" cannot trigger two shutdowns;
* the audit trail identifies the operation, execution id, confirmation state and
  result - without secrets or command lines.
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
    DuplicateToolError,
    ErrorCode,
    PermissionPolicy,
    Platform,
    PlatformRegistry,
    ToolResultStatus,
)
from jarvis_devices.permissions import PERMISSION_POWER_CONTROL
from jarvis_devices.pc_power import ALL_OPERATIONS, PC_POWER_TOOL_NAMES, build_pc_power_tools

try:  # imported as part of the ``tests`` package (pytest / discover -t .)
    from .pc_power_support import FakePCPowerBackend
    from .support import AuditCapture, FakeAdapter
    from .test_security import (
        FORBIDDEN_IMPORTS,
        FORBIDDEN_PATTERNS,
        FORBIDDEN_TERMINATION_PATTERNS,
        code_only_source,
        imported_modules,
    )
except ImportError:  # ``python -m unittest discover -s tests``
    from pc_power_support import FakePCPowerBackend
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
PHASE4_SOURCES = (
    ROOT / "jarvis_devices" / "pc_power.py",
    ROOT / "jarvis_devices" / "pc_power_windows.py",
    ROOT / "Jarvis_device_control.py",
    ROOT / "agent.py",
)

#: Words that would mean "the model can steer the operating system".
FORBIDDEN_ARGUMENT_WORDS = (
    "command",
    "cmd",
    "shell",
    "flags",
    "force",
    "timeout",
    "reason",
    "host",
    "machine",
    "path",
    "executable",
    "script",
)

#: Substrings that would mean a literal command line is embedded in the code.
COMMAND_SHAPES = (
    "shutdown.exe",
    "cmd.exe",
    "powershell",
    "net.exe",
    "rundll32",
    "start /",
    " /s ",
    " /t ",
    " /f ",
    "&&",
    "||",
    "cmd /c",
    "os.system",
)

#: Words that would mean "another machine can be switched off".
REMOTE_WORDS = ("remote", "\\\\", "//", "ip_address", "hostname", "unc")


class BridgePowerBackend:
    """Swaps the bridge's real power backend for a scripted fake."""

    METHODS = (
        "is_available",
        "unavailable_reason",
        "capabilities",
        "shutdown",
        "restart",
        "sleep",
        "hibernate",
        "logoff",
    )

    def __init__(self, fake: FakePCPowerBackend) -> None:
        self.fake = fake
        self._patches = []

    def __enter__(self) -> FakePCPowerBackend:
        backend = bridge.pc_power_backend
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
    def test_no_process_or_eval_primitive_in_phase_4(self) -> None:
        for source in PHASE4_SOURCES:
            code = code_only_source(source)
            for label, pattern in FORBIDDEN_PATTERNS.items():
                with self.subTest(file=source.name, forbidden=label):
                    self.assertIsNone(pattern.search(code), f"{source.name} must not contain {label}")

    def test_no_forbidden_module_is_imported(self) -> None:
        for source in PHASE4_SOURCES:
            with self.subTest(file=source.name):
                self.assertEqual(imported_modules(source) & FORBIDDEN_IMPORTS, set())

    def test_no_process_termination_api(self) -> None:
        for source in PHASE4_SOURCES:
            code = code_only_source(source)
            for label, pattern in FORBIDDEN_TERMINATION_PATTERNS.items():
                with self.subTest(file=source.name, forbidden=label):
                    self.assertIsNone(pattern.search(code), f"{source.name} must not contain {label}")

    def test_no_string_constant_looks_like_a_command_line(self) -> None:
        """A command line would have to live in a string constant - none does.

        Raw text is the wrong lens (the word "Restart" trips a naive ``start ``
        search), so the *string constants* are inspected instead.
        """
        for source in (PHASE4_SOURCES[0], PHASE4_SOURCES[1]):
            # ``code_only_source`` drops docstrings first: the docstrings of
            # these modules state "no shutdown.exe, no shell", and that
            # documentation must not be mistaken for a command line.
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
                    with self.subTest(file=source.name, forbidden=forbidden, literal=literal[:60]):
                        self.assertNotIn(forbidden, lowered)

    def test_no_execute_command_style_backdoor_exists(self) -> None:
        for name in ("execute_power_command", "run_power_command", "power_command", "run_command"):
            with self.subTest(name=name):
                self.assertFalse(hasattr(bridge, name))

    def test_no_function_accepts_a_steerable_parameter(self) -> None:
        """Tools, bridge coroutines and backend methods take nothing to aim with."""
        trees = {
            path.name: ast.parse(path.read_text(encoding="utf-8"))
            for path in (PHASE4_SOURCES[0], PHASE4_SOURCES[1])
        }
        checked = 0
        for filename, tree in trees.items():
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    params = [arg.arg for arg in node.args.args]
                    checked += 1
                    for parameter in params:
                        with self.subTest(file=filename, function=node.name, parameter=parameter):
                            self.assertNotIn(parameter, FORBIDDEN_ARGUMENT_WORDS)
        self.assertGreater(checked, 20)

    def test_no_remote_targeting_anywhere(self) -> None:
        for source in (PHASE4_SOURCES[0], PHASE4_SOURCES[1]):
            code = code_only_source(source)
            for word in REMOTE_WORDS:
                with self.subTest(file=source.name, word=word):
                    self.assertNotIn(word, code)

    def test_every_power_tool_declares_no_arguments(self) -> None:
        for tool in build_pc_power_tools(FakePCPowerBackend(), platform_probe=lambda: Platform.PC):
            with self.subTest(tool=tool.name):
                self.assertEqual(tool.argument_schema.names, ())
                self.assertTrue(tool.confirmation_mandatory)
                self.assertTrue(tool.requires_confirmation)


# ---------------------------------------------------------------------------
# Registration integrity
# ---------------------------------------------------------------------------
class RegistrationTests(unittest.TestCase):
    def test_the_builder_returns_five_unique_tools(self) -> None:
        tools = build_pc_power_tools(FakePCPowerBackend(), platform_probe=lambda: Platform.PC)
        names = [tool.name for tool in tools]
        self.assertEqual(names, list(PC_POWER_TOOL_NAMES))
        self.assertEqual(len(set(names)), 5)

    def test_the_bridge_registered_each_power_tool_exactly_once(self) -> None:
        registered = list(bridge.device_registry.names())
        self.assertEqual(len(registered), len(set(registered)), "duplicate tool registration")
        for name in PC_POWER_TOOL_NAMES:
            with self.subTest(tool=name):
                self.assertIn(name, registered)
        power = [name for name in registered if name.startswith("pc.power.")]
        self.assertEqual(len(power), 5)

    def test_a_duplicate_registration_is_refused(self) -> None:
        registry = DeviceToolRegistry()
        tools = build_pc_power_tools(FakePCPowerBackend(), platform_probe=lambda: Platform.PC)
        registry.register(tools[0])
        with self.assertRaises(DuplicateToolError):
            registry.register(tools[0])

    def test_the_bridge_exposes_each_wrapper_once(self) -> None:
        for name in ("shutdown_pc", "restart_pc", "sleep_pc", "hibernate_pc", "logoff_pc"):
            with self.subTest(wrapper=name):
                self.assertTrue(hasattr(bridge, name))
                self.assertIn(name, bridge.__all__)
        self.assertEqual(len(set(bridge.__all__)), len(bridge.__all__), "duplicate export")


# ---------------------------------------------------------------------------
# Live bridge behaviour
# ---------------------------------------------------------------------------
class BridgeSecurityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.fake = FakePCPowerBackend()
        self.patcher = BridgePowerBackend(self.fake)
        self.patcher.__enter__()
        self.addCleanup(self.patcher.__exit__, None, None, None)

    # ------------------------------------------------------------------
    async def test_every_power_operation_asks_first_and_runs_nothing(self) -> None:
        for name in PC_POWER_TOOL_NAMES:
            with self.subTest(tool=name):
                result = await bridge.device_manager.request(name)
                self.assertEqual(result.status, ToolResultStatus.PENDING_CONFIRMATION)
        self.assertEqual(self.fake.calls, [])

    async def test_only_an_explicit_yes_reaches_the_backend(self) -> None:
        asked = await bridge.run_shutdown_pc()
        self.assertTrue(asked.startswith("⚠️ Confirmation required"), asked)
        self.assertEqual(self.fake.calls, [])

        pending = await bridge.device_manager.request("pc.power.shutdown")
        approved = await bridge.resolve_device_confirmation(pending.data["confirmation_id"], True)
        self.assertTrue(approved.startswith("✅"), approved)
        self.assertEqual(self.fake.calls, ["shutdown"])

    async def test_a_no_means_nothing_happens(self) -> None:
        pending = await bridge.device_manager.request("pc.power.restart")
        declined = await bridge.resolve_device_confirmation(pending.data["confirmation_id"], False)
        self.assertIn("confirmation_denied", declined)
        self.assertEqual(self.fake.calls, [])

    async def test_one_yes_cannot_trigger_two_shutdowns(self) -> None:
        pending = await bridge.device_manager.request("pc.power.shutdown")
        cid = pending.data["confirmation_id"]
        first = await bridge.device_manager.resolve_confirmation(cid, True)
        self.assertTrue(first.success)
        second = await bridge.device_manager.resolve_confirmation(cid, True)
        self.assertEqual(second.error_code, ErrorCode.CONFIRMATION_REUSED)
        self.assertEqual(self.fake.calls, ["shutdown"])

    async def test_a_shutdown_yes_cannot_be_used_for_a_restart(self) -> None:
        pending = await bridge.device_manager.request("pc.power.shutdown")
        hijacked = await bridge.device_manager.request(
            "pc.power.restart", {}, confirmation_id=pending.data["confirmation_id"]
        )
        self.assertEqual(hijacked.error_code, ErrorCode.CONFIRMATION_MISMATCH)
        self.assertEqual(self.fake.calls, [])

    async def test_a_policy_cannot_make_power_operations_unconfirmed(self) -> None:
        original = bridge.device_confirmation_policy
        try:
            bridge.device_manager._confirmation_policy = ConfirmationPolicy(never_confirm=PC_POWER_TOOL_NAMES)
            for name in PC_POWER_TOOL_NAMES:
                with self.subTest(tool=name):
                    result = await bridge.device_manager.request(name)
                    self.assertEqual(result.status, ToolResultStatus.PENDING_CONFIRMATION)
            self.assertEqual(self.fake.calls, [])
        finally:
            bridge.device_manager._confirmation_policy = original

    async def test_revoking_the_permission_blocks_everything(self) -> None:
        bridge.device_permissions.revoke(PERMISSION_POWER_CONTROL)
        self.addCleanup(bridge.device_permissions.grant, PERMISSION_POWER_CONTROL)
        for name in PC_POWER_TOOL_NAMES:
            with self.subTest(tool=name):
                result = await bridge.device_manager.request(name)
                self.assertEqual(result.status, ToolResultStatus.PERMISSION_DENIED)
                self.assertFalse(result.executed)
        self.assertEqual(self.fake.calls, [])

    async def test_hostile_arguments_never_reach_the_backend(self) -> None:
        payloads = (
            '{"command": "shutdown /s /t 0"}',
            '{"flags": "/f /t 999 /m \\\\\\\\server"}',
            '{"timeout": 0, "force": true}',
            '{"remote_host": "\\\\\\\\fileserver"}',
            '{"reason": "maintenance && calc"}',
            '{"level": 50}',
            'shutdown /s /t 0',
        )
        for payload in payloads:
            for name in PC_POWER_TOOL_NAMES:
                with self.subTest(tool=name, payload=payload):
                    answer = await bridge.run_device_action(name, payload)
                    self.assertTrue(
                        answer.startswith("❌ Not executed (invalid_argument)"),
                        answer,
                    )
        self.assertEqual(self.fake.calls, [])

    async def test_unknown_and_shell_like_tool_names_are_refused(self) -> None:
        for name in (
            "pc.power.force",
            "pc.power.shutdown --force",
            "pc.power.remote_shutdown",
            "pc.power.execute",
            "powershell Stop-Computer",
            "cmd /c shutdown /s",
            "pc.power.shutdown; calc",
        ):
            with self.subTest(name=name):
                answer = await bridge.run_device_action(name, "{}")
                self.assertIn(ErrorCode.UNKNOWN_TOOL, answer)
        self.assertEqual(self.fake.calls, [])

    async def test_an_unsupported_operation_is_not_reported_as_success(self) -> None:
        from jarvis_devices.pc_power import UnsupportedPowerOperationError

        self.fake.fail_with("hibernate", UnsupportedPowerOperationError("no hibernation file"))
        pending = await bridge.device_manager.request("pc.power.hibernate")
        result = await bridge.device_manager.resolve_confirmation(pending.data["confirmation_id"], True)
        self.assertEqual(result.status, ToolResultStatus.UNAVAILABLE)
        self.assertEqual(result.error_code, ErrorCode.POWER_OPERATION_UNSUPPORTED)
        self.assertFalse(result.success)

    async def test_a_backend_failure_is_not_reported_as_success(self) -> None:
        from jarvis_devices.pc_power import PCPowerBackendError

        self.fake.fail_with("shutdown", PCPowerBackendError("Windows said no"))
        pending = await bridge.device_manager.request("pc.power.shutdown")
        result = await bridge.device_manager.resolve_confirmation(pending.data["confirmation_id"], True)
        self.assertEqual(result.status, ToolResultStatus.FAILED)
        self.assertEqual(result.error_code, ErrorCode.POWER_CONTROL_FAILED)


# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------
class AuditTests(unittest.IsolatedAsyncioTestCase):
    def build(self):
        self.fake = FakePCPowerBackend()
        audit = AuditLogger(enabled=True)
        self.capture = AuditCapture(audit)
        registry = DeviceToolRegistry()
        registry.register_all(build_pc_power_tools(self.fake, platform_probe=lambda: Platform.PC))
        platforms = PlatformRegistry()
        platforms.register(FakeAdapter(Platform.PC))
        policy = ConfirmationPolicy()
        return DeviceActionManager(
            registry,
            PermissionPolicy(granted=(PERMISSION_POWER_CONTROL,)),
            ConfirmationManager(policy=policy),
            platforms,
            audit,
            confirmation_policy=policy,
        )

    async def test_a_power_operation_is_fully_audited(self) -> None:
        manager = self.build()
        asked = await manager.request("pc.power.restart")
        done = await manager.resolve_confirmation(asked.data["confirmation_id"], True)
        self.assertTrue(done.success)

        events = self.capture.events
        for expected in (
            "tool_requested",
            "permission_checked",
            "confirmation_requested",
            "confirmation_received",
            "execution_started",
            "execution_completed",
        ):
            with self.subTest(event=expected):
                self.assertIn(expected, events)

        started = next(r for r in self.capture.records if r["event"] == "execution_started")
        completed = next(r for r in self.capture.records if r["event"] == "execution_completed")
        self.assertEqual(started["tool"], "pc.power.restart")
        self.assertEqual(started["risk_level"], "external_action")
        self.assertTrue(started["execution_id"])
        self.assertTrue(started["ts"])
        self.assertEqual(completed["status"], "success")
        self.assertEqual(completed["tool"], "pc.power.restart")

    async def test_no_command_line_or_secret_reaches_the_log(self) -> None:
        manager = self.build()
        await manager.request("pc.power.shutdown", {"command": "shutdown /s /t 0", "api_key": "AIzaDUMMY"})
        text = self.capture.raw_text()
        for forbidden in ("shutdown /s", "AIzaDUMMY", "/t 0"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)
        # Argument *names* are audited, never their values.
        self.assertIn("command", text)

    async def test_a_denied_operation_is_audited_as_denied(self) -> None:
        manager = self.build()
        asked = await manager.request("pc.power.logoff")
        denied = await manager.resolve_confirmation(asked.data["confirmation_id"], False)
        self.assertFalse(denied.success)
        self.assertEqual(denied.error_code, ErrorCode.CONFIRMATION_DENIED)

        self.assertNotIn("execution_completed", self.capture.events)
        record = next(r for r in self.capture.records if r["event"] == "execution_failed")
        self.assertEqual(record["status"], "denied")
        self.assertFalse(record["success"])
        self.assertEqual(record["error_code"], ErrorCode.CONFIRMATION_DENIED)
        self.assertEqual(record["tool"], "pc.power.logoff")
        self.assertEqual(self.fake.calls, [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
