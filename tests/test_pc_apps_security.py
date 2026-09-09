"""Phase 2 security tests - PC application control.

These pin the hard requirements:

* model controlled text can never become a command line, a shell invocation or
  an executable path,
* arbitrary PIDs cannot be terminated (no kill tool exists at all),
* nothing bypasses the registry, the permission policy or the platform check,
* the LiveKit bridge keeps plain coroutines available for testing.

All of it runs against a fake backend, so no desktop is required.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import unittest
from unittest import mock

import Jarvis_device_control as bridge
from jarvis_devices import ErrorCode
from jarvis_devices.pc_apps import (
    ApplicationSpec,
    PC_APPLICATION_TOOL_NAMES,
    WindowInfo,
    default_application_catalog,
)
from jarvis_devices.pc_system import PC_SYSTEM_TOOL_NAMES
from jarvis_devices.pc_power import PC_POWER_TOOL_NAMES
from jarvis_devices.android_tools import ANDROID_BRIDGE_TOOL_NAMES
from jarvis_devices.android_system_tools import ANDROID_SYSTEM_TOOL_NAMES
from jarvis_devices.android_call_tools import ANDROID_CALL_TOOL_NAMES

try:  # imported as part of the ``tests`` package (pytest / discover -t .)
    from .pc_support import FakePCBackend
except ImportError:  # ``python -m unittest discover -s tests``
    from pc_support import FakePCBackend

CHROME_WINDOW = WindowInfo(handle=11, title="New Tab - Google Chrome", process_id=1234, process_name="chrome.exe")
NOTEPAD_WINDOW = WindowInfo(handle=22, title="untitled - Notepad", process_id=5678, process_name="notepad.exe")

#: Text a model could try to turn into arbitrary execution.
HOSTILE_INPUTS = (
    "cmd",
    "cmd.exe",
    "command prompt",
    "powershell",
    "powershell.exe -c calc",
    r"C:\Windows\System32\cmd.exe",
    "chrome.exe && calc.exe",
    "chrome; shutdown /s /t 0",
    "$(whoami)",
    "`id`",
    "/c dir C:\\",
    "start ms-settings:",
    "notepad.exe | more",
    "..\\..\\windows\\system32\\cmd.exe",
)


class BridgeDesktop:
    """Temporarily gives the bridge's real backend a scripted fake desktop."""

    def __init__(self, fake: FakePCBackend) -> None:
        self.fake = fake
        self._patches = []

    def __enter__(self) -> FakePCBackend:
        backend = bridge.pc_application_backend
        for method in ("is_available", "list_windows", "launch", "focus_window", "close_window", "window_exists"):
            patch = mock.patch.object(backend, method, getattr(self.fake, method))
            patch.start()
            self._patches.append(patch)
        return self.fake

    def __exit__(self, *exc_info) -> None:
        for patch in reversed(self._patches):
            patch.stop()


class NoProcessSpawningTests(unittest.TestCase):
    def test_no_pc_operation_can_reach_a_process_api(self) -> None:
        """Even hostile input cannot make the framework spawn or kill anything."""
        fake = FakePCBackend((CHROME_WINDOW,))

        def explode(*args, **kwargs):  # pragma: no cover - must never be called
            raise AssertionError("a PC application tool reached a process API")

        patches = [
            mock.patch.object(subprocess, "Popen", explode),
            mock.patch.object(subprocess, "run", explode),
            mock.patch.object(subprocess, "call", explode),
            mock.patch.object(os, "system", explode),
            mock.patch.object(os, "popen", explode),
            mock.patch.object(os, "startfile", explode, create=True),
        ]
        for patch in patches:
            patch.start()
        self.addCleanup(lambda: [patch.stop() for patch in reversed(patches)])

        with BridgeDesktop(fake):
            for payload in HOSTILE_INPUTS:
                for coroutine in (
                    bridge.run_open_application(payload),
                    bridge.run_focus_application(payload),
                    bridge.run_close_application(payload),
                    bridge.run_application_status(payload),
                ):
                    with self.subTest(payload=payload):
                        answer = asyncio.run(coroutine)
                        self.assertTrue(answer.startswith("❌"), answer)
            self.assertEqual(fake.launched, [])
            self.assertEqual(fake.closed, [])


class ArbitraryExecutionTests(unittest.TestCase):
    def test_shell_like_names_are_unknown_applications(self) -> None:
        fake = FakePCBackend((CHROME_WINDOW,))
        with BridgeDesktop(fake):
            for payload in HOSTILE_INPUTS:
                with self.subTest(payload=payload):
                    answer = asyncio.run(bridge.run_open_application(payload))
                    self.assertTrue(answer.startswith("❌"), answer)
                    self.assertIn(ErrorCode.APPLICATION_NOT_FOUND, answer)
            self.assertEqual(fake.launched, [])

    def test_no_shell_is_in_the_catalog(self) -> None:
        catalog = default_application_catalog()
        haystack = " ".join(
            part
            for spec in catalog.all()
            for part in (spec.name, spec.display_name, spec.launch_target, *spec.aliases, *spec.process_names)
        ).lower()
        for forbidden in ("cmd", "powershell", "command prompt", "shell", "terminal", "wsl"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, haystack)

    def test_catalog_targets_cannot_carry_arguments(self) -> None:
        catalog = default_application_catalog()
        for spec in catalog.all():
            with self.subTest(app=spec.name):
                self.assertNotIn(" ", spec.launch_target)
                for character in "&|<>;`$\"'":
                    self.assertNotIn(character, spec.launch_target)

    def test_registering_a_shell_payload_as_an_application_is_rejected(self) -> None:
        for target in ("cmd.exe /c calc", "notepad.exe & shutdown", "powershell.exe -c x"):
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    bridge.register_application(
                        ApplicationSpec(name="evil", display_name="Evil", launch_target=target)
                    )
        self.assertNotIn("evil", bridge.pc_application_catalog)

    def test_arbitrary_pids_cannot_be_terminated(self) -> None:
        # Closed world: only the explicitly registered tools exist. Phase 3
        # added the thirteen pc.system.* tools, Phase 4 the five pc.power.* tools,
        # Phase 5 the six android.device/bridge tools and Phase 6 the thirteen
        # android.system.* tools and Phase 7 the five android.call.* tools to
        # this allow-list - anything else must be refused.
        self.assertEqual(
            set(bridge.device_registry.names()),
            set(PC_APPLICATION_TOOL_NAMES)
            | set(PC_SYSTEM_TOOL_NAMES)
            | set(PC_POWER_TOOL_NAMES)
            | set(ANDROID_BRIDGE_TOOL_NAMES)
            | set(ANDROID_SYSTEM_TOOL_NAMES)
            | set(ANDROID_CALL_TOOL_NAMES)
            | {"jarvis.framework.diagnostics"},
        )
        for tool in bridge.device_registry.list_tools():
            with self.subTest(tool=tool.name):
                self.assertNotIn("pid", tool.argument_schema.names)
                self.assertNotIn("process_id", tool.argument_schema.names)

    def test_unregistered_tools_are_rejected_by_the_bridge(self) -> None:
        answer = asyncio.run(bridge.run_device_action("pc.process.kill", '{"pid": 4}'))
        self.assertIn(ErrorCode.UNKNOWN_TOOL, answer)
        answer = asyncio.run(bridge.run_device_action("os.system", '{"command": "calc"}'))
        self.assertIn(ErrorCode.UNKNOWN_TOOL, answer)

    def test_device_action_cannot_reach_pc_tools_without_permission(self) -> None:
        bridge.device_permissions.revoke("system.app.control")
        self.addCleanup(bridge.device_permissions.grant, "system.app.control")
        fake = FakePCBackend((CHROME_WINDOW,))
        with BridgeDesktop(fake):
            answer = asyncio.run(bridge.run_device_action("pc.app.close", '{"app": "notepad"}'))
            self.assertIn(ErrorCode.PERMISSION_DENIED, answer)
            self.assertEqual(fake.closed, [])


class BridgeBehaviourTests(unittest.TestCase):
    def test_open_application_launches_a_catalogued_app(self) -> None:
        fake = FakePCBackend()
        with BridgeDesktop(fake):
            answer = asyncio.run(bridge.run_open_application("Google Chrome"))
        self.assertTrue(answer.startswith("✅"), answer)
        self.assertIn("launched", answer)
        self.assertEqual([spec.name for spec in fake.launched], ["chrome"])

    def test_open_application_focuses_an_already_running_app(self) -> None:
        fake = FakePCBackend((CHROME_WINDOW,))
        with BridgeDesktop(fake):
            answer = asyncio.run(bridge.run_open_application("chrome"))
        self.assertTrue(answer.startswith("✅"), answer)
        self.assertEqual(fake.launched, [])
        self.assertEqual(fake.focused, [CHROME_WINDOW.handle])

    def test_application_status_reports_running(self) -> None:
        fake = FakePCBackend((NOTEPAD_WINDOW,))
        with BridgeDesktop(fake):
            running = asyncio.run(bridge.run_application_status("notepad"))
            stopped = asyncio.run(bridge.run_application_status("chrome"))
        self.assertTrue(running.startswith("✅"))
        self.assertIn("running", running)
        self.assertIn("not running", stopped)

    def test_list_open_applications_reports_windows(self) -> None:
        fake = FakePCBackend((CHROME_WINDOW, NOTEPAD_WINDOW))
        with BridgeDesktop(fake):
            answer = asyncio.run(bridge.run_list_open_applications())
        self.assertTrue(answer.startswith("✅"), answer)
        self.assertIn("2 open window(s)", answer)

    def test_focus_and_close_use_the_real_framework_path(self) -> None:
        fake = FakePCBackend((NOTEPAD_WINDOW, CHROME_WINDOW))
        with BridgeDesktop(fake):
            focused = asyncio.run(bridge.run_focus_application("notepad"))
            closed = asyncio.run(bridge.run_close_application("chrome"))
        self.assertTrue(focused.startswith("✅"), focused)
        self.assertEqual(fake.focused, [NOTEPAD_WINDOW.handle])
        self.assertTrue(closed.startswith("✅"), closed)
        self.assertEqual(fake.closed, [CHROME_WINDOW.handle])

    def test_tools_report_unavailable_without_a_pc_backend(self) -> None:
        """No patching here: this machine has no Windows backend."""
        if bridge.pc_application_backend.is_available():
            self.skipTest("a real PC backend is available on this machine")
        for coroutine in (
            bridge.run_open_application("chrome"),
            bridge.run_focus_application("chrome"),
            bridge.run_close_application("chrome"),
            bridge.run_application_status("chrome"),
            bridge.run_list_open_applications(),
        ):
            with self.subTest():
                answer = asyncio.run(coroutine)
                self.assertIn(ErrorCode.TOOL_UNAVAILABLE, answer)
                self.assertTrue(answer.startswith("❌"))

    def test_livekit_wrappers_are_exported_alongside_the_coroutines(self) -> None:
        for wrapper, coroutine in (
            ("list_open_applications", "run_list_open_applications"),
            ("application_status", "run_application_status"),
            ("open_application", "run_open_application"),
            ("focus_application", "run_focus_application"),
            ("close_application", "run_close_application"),
        ):
            with self.subTest(tool=wrapper):
                self.assertTrue(hasattr(bridge, wrapper))
                self.assertTrue(callable(getattr(bridge, coroutine)))
                self.assertIn(wrapper, bridge.__all__)

    def test_registered_tool_metadata_is_exposed_for_the_model(self) -> None:
        described = {entry["name"]: entry for entry in bridge.device_registry.describe()}
        for name in PC_APPLICATION_TOOL_NAMES:
            with self.subTest(tool=name):
                self.assertEqual(described[name]["platform"], "pc")
                self.assertTrue(described[name]["description"])
                properties = described[name]["arguments"]["properties"]
                self.assertTrue({"app", "limit"} & set(properties))
                self.assertFalse(described[name]["arguments"]["additionalProperties"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
