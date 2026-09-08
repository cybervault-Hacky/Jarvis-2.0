"""Phase 3 hardening tests for the *legacy* PC-control files.

Phase 3 replaced two unsafe legacy patterns rather than working around them:

1. ``Jarvis_window_CTRL.open`` used to interpolate whatever the model said into
   ``start "" "<words>"`` and run it with ``shell=True``. Launching now resolves
   the name against the secure Phase 2 application catalog and uses
   ``ShellExecute`` with an empty parameter string.
2. ``keyboard_mouse_CTRL.SafeController`` compared its activation token against a
   secret hard-coded in the source, and wrote everything the user typed verbatim
   to ``control_log.txt``. The literal is gone and typed text is redacted with
   the framework's own :class:`~jarvis_devices.audit.Redactor`.

These tests pin both fixes and the behaviour they must not break.
"""

from __future__ import annotations

import ast
import importlib
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent

try:  # imported as part of the ``tests`` package (pytest / discover -t .)
    from .test_agent_integration import THIRD_PARTY_MODULES, _install_stubs, _restore_stubs
    from .test_security import FORBIDDEN_PATTERNS, code_only_source
except ImportError:  # ``python -m unittest discover -s tests``
    from test_agent_integration import THIRD_PARTY_MODULES, _install_stubs, _restore_stubs
    from test_security import FORBIDDEN_PATTERNS, code_only_source

WINDOW_CTRL = ROOT / "Jarvis_window_CTRL.py"
KEYBOARD_CTRL = ROOT / "keyboard_mouse_CTRL.py"

#: Things the model may say that must never turn into a command line.
INJECTION_PAYLOADS = (
    "notepad & calc",
    "notepad.exe && del C:\\Windows\\*",
    'notepad" & powershell -c "Get-Process',
    "cmd /c calc",
    "powershell -Command Remove-Item -Recurse C:\\",
    "..\\..\\Windows\\System32\\cmd.exe",
    "/etc/passwd",
    "$(reboot)",
    "`whoami`",
    "chrome; rm -rf /",
    "vlc | tee secrets.txt",
    "notepad > C:\\autoexec.bat",
    "",
    "   ",
)

#: Names the legacy tool used to accept (backward compatibility).
LEGACY_NAMES = (
    "notepad",
    "calculator",
    "chrome",
    "vlc",
    "control panel",
    "settings",
    "paint",
    "vs code",
    "postman",
)


def raw(tool):
    """Call a legacy tool whether or not LiveKit wrapped it in a FunctionTool."""
    return getattr(tool, "_func", tool)


class LegacySourceTests(unittest.TestCase):
    """Static checks on the two legacy files."""

    def test_window_ctrl_has_no_shell_execution_left(self) -> None:
        """No shell, no ``os.system``, no command line built from a string."""
        code = code_only_source(WINDOW_CTRL)
        for label in ("os.system", "os.popen", "eval()", "exec()", "shell=True", "ctypes"):
            with self.subTest(forbidden=label):
                self.assertIsNone(FORBIDDEN_PATTERNS[label].search(code), f"must not contain {label}")

    def test_every_remaining_subprocess_call_is_list_form_without_a_shell(self) -> None:
        """``xdg-open`` keeps working off Windows, but only as fixed argv lists."""
        tree = ast.parse(WINDOW_CTRL.read_text(encoding="utf-8"))
        calls = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "subprocess"
        ]
        self.assertTrue(calls, "expected the xdg-open fallback to still exist")
        for node in calls:
            with self.subTest(line=node.lineno):
                self.assertEqual(node.func.attr, "call")
                self.assertIsInstance(node.args[0], ast.List)  # argv list, not a string
                self.assertEqual(
                    [keyword.arg for keyword in node.keywords],
                    [],
                    "no keyword arguments - in particular no shell=True",
                )
                self.assertNotIn("$", ast.unparse(node.args[0]))

    def test_window_ctrl_no_longer_builds_a_command_line(self) -> None:
        code = code_only_source(WINDOW_CTRL)
        self.assertNotIn("create_subprocess_shell", code)
        self.assertNotIn("create_subprocess_exec", code)
        self.assertNotIn("APP_MAPPINGS", code)  # the shell-command map is gone

    def test_window_ctrl_launches_through_the_secure_catalog(self) -> None:
        code = code_only_source(WINDOW_CTRL)
        self.assertIn("default_application_catalog", code)
        self.assertIn("_safe_launcher.launch", code)

    def test_keyboard_ctrl_has_no_shell_execution(self) -> None:
        code = code_only_source(KEYBOARD_CTRL)
        for label, pattern in FORBIDDEN_PATTERNS.items():
            with self.subTest(forbidden=label):
                self.assertIsNone(pattern.search(code), f"keyboard_mouse_CTRL.py must not contain {label}")

    def test_no_hard_coded_credential_remains(self) -> None:
        for source in (WINDOW_CTRL, KEYBOARD_CTRL):
            with self.subTest(file=source.name):
                self.assertNotIn("my_secret_token", source.read_text(encoding="utf-8"))

    def test_typed_text_is_redacted_before_it_is_logged(self) -> None:
        code = code_only_source(KEYBOARD_CTRL)
        self.assertIn("_log_redactor.redact_text", code)
        # The raw text must not be written to the log any more.
        tree = ast.parse(KEYBOARD_CTRL.read_text(encoding="utf-8"))
        logged = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and getattr(node.func, "attr", "") == "log"
            and any(isinstance(arg, ast.JoinedStr) for arg in node.args)
        ]
        for node in logged:
            text = ast.unparse(node)
            with self.subTest(line=node.lineno):
                self.assertNotIn("Typed text: {text}", text)


class LegacyOpenToolTests(unittest.IsolatedAsyncioTestCase):
    """``open()`` must only ever launch catalogued applications."""

    def setUp(self) -> None:
        self.installed = _install_stubs()
        self.addCleanup(_restore_stubs, self.installed)
        sys.modules.pop("Jarvis_window_CTRL", None)
        self.module = importlib.import_module("Jarvis_window_CTRL")
        self.launches = []

        def record(spec):
            self.launches.append(spec)

        patcher = mock.patch.object(self.module._safe_launcher, "launch", record)
        patcher.start()
        self.addCleanup(patcher.stop)

        async def no_focus(_title):
            return True

        focus_patcher = mock.patch.object(self.module, "focus_window", no_focus)
        focus_patcher.start()
        self.addCleanup(focus_patcher.stop)

    # ------------------------------------------------------------------
    async def test_a_shell_payload_is_never_launched(self) -> None:
        for payload in INJECTION_PAYLOADS:
            with self.subTest(payload=payload):
                answer = await raw(self.module.open)(payload)
                self.assertEqual(self.launches, [], f"launched something for {payload!r}")
                self.assertTrue(answer.startswith("❌"), answer)

    async def test_no_process_api_is_reachable_from_the_tool(self) -> None:
        """Even a hostile name cannot reach a real process API."""
        import asyncio
        import subprocess

        def explode(*args, **kwargs):  # pragma: no cover - must never run
            raise AssertionError("the legacy open tool tried to spawn a process")

        with mock.patch.object(subprocess, "Popen", explode), mock.patch.object(subprocess, "run", explode):
            with mock.patch.object(asyncio, "create_subprocess_shell", explode, create=True):
                for payload in ("cmd /c calc", "notepad & calc", "powershell ls"):
                    with self.subTest(payload=payload):
                        await raw(self.module.open)(payload)
        self.assertEqual(self.launches, [])

    async def test_known_names_still_launch_their_catalog_entry(self) -> None:
        for name in LEGACY_NAMES:
            self.launches.clear()
            with self.subTest(name=name):
                answer = await raw(self.module.open)(name)
                self.assertTrue(answer.startswith("🚀"), answer)
                self.assertEqual(len(self.launches), 1)
                spec = self.launches[0]
                # The target comes from the catalog, never from the model's words.
                self.assertNotIn("&", spec.launch_target)
                self.assertTrue(spec.launch_target.endswith(".exe") or spec.launch_target.endswith(":"))

    async def test_the_launch_target_is_not_the_model_string(self) -> None:
        answer = await raw(self.module.open)("settings")
        self.assertTrue(answer.startswith("🚀"), answer)
        self.assertEqual(self.launches[0].launch_target, "ms-settings:")

    async def test_a_shell_is_never_offered(self) -> None:
        for name in ("command prompt", "cmd", "terminal", "powershell"):
            self.launches.clear()
            with self.subTest(name=name):
                answer = await raw(self.module.open)(name)
                self.assertEqual(self.launches, [])
                self.assertTrue(answer.startswith("❌"), answer)

    async def test_case_and_whitespace_do_not_change_the_outcome(self) -> None:
        for name in ("  NOTEPAD  ", "NotePad", "notepad"):
            self.launches.clear()
            with self.subTest(name=name):
                answer = await raw(self.module.open)(name)
                self.assertTrue(answer.startswith("🚀"), answer)
                self.assertEqual(self.launches[0].name, "notepad")

    async def test_a_launcher_failure_is_reported_not_swallowed(self) -> None:
        def refuse(_spec):
            raise RuntimeError("ShellExecute refused notepad.exe")

        with mock.patch.object(self.module._safe_launcher, "launch", refuse):
            answer = await raw(self.module.open)("notepad")
        self.assertTrue(answer.startswith("❌"), answer)
        self.assertIn("Launch नहीं हो पाया", answer)

    async def test_the_catalog_is_the_only_source_of_targets(self) -> None:
        """The legacy alias table maps names to catalog names, not to commands."""
        for legacy, canonical in self.module.LEGACY_APP_ALIASES.items():
            with self.subTest(legacy=legacy):
                self.assertIn(canonical, self.module._application_catalog)
                self.assertNotIn(" ", self.module.LEGACY_APP_ALIASES[legacy])


class KeyboardControllerTests(unittest.TestCase):
    """The controller keeps working, without a secret and without leaking input."""

    def setUp(self) -> None:
        self.installed = _install_stubs()
        self.addCleanup(_restore_stubs, self.installed)
        sys.modules.pop("keyboard_mouse_CTRL", None)
        self.module = importlib.import_module("keyboard_mouse_CTRL")
        self.controller = self.module.SafeController()
        self.logged = []
        patcher = mock.patch.object(self.controller, "log", self.logged.append)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_activation_works_without_a_token(self) -> None:
        self.assertFalse(self.controller.is_active())
        self.controller.activate()
        self.assertTrue(self.controller.is_active())
        self.controller.deactivate()
        self.assertFalse(self.controller.is_active())

    def test_actions_are_still_gated_by_activation(self) -> None:
        import asyncio

        self.assertFalse(self.controller.is_active())
        answer = asyncio.run(self.controller.type_text("hello"))
        self.assertIn("inactive", answer)
        self.controller.activate()
        answer = asyncio.run(self.controller.type_text("hello"))
        self.assertNotIn("inactive", answer)

    def test_typed_text_is_redacted_in_the_log(self) -> None:
        import asyncio

        self.controller.activate()
        asyncio.run(self.controller.type_text("my password=hunter2 and mail a@b.com"))
        self.assertTrue(self.logged, "nothing was logged")
        entry = self.logged[-1]
        self.assertIn("Typed text:", entry)
        self.assertNotIn("hunter2", entry)
        self.assertNotIn("a@b.com", entry)
        self.assertIn("[redacted]", entry)

    def test_key_logging_is_unchanged(self) -> None:
        import asyncio

        self.controller.activate()
        asyncio.run(self.controller.press_key("enter"))
        self.assertTrue(any("Pressed key: enter" in entry for entry in self.logged))

    def test_invalid_keys_are_still_refused(self) -> None:
        import asyncio

        self.controller.activate()
        answer = asyncio.run(self.controller.press_key("not-a-key!!"))
        self.assertIn("Invalid key", answer)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
