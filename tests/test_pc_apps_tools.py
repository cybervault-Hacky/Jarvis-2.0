"""Phase 2 PC application tool tests - driven through the DeviceActionManager.

Every test injects a fake backend and a fake platform probe, so the suite never
depends on the developer's desktop, on Windows, or on any installed application.
"""

from __future__ import annotations

import unittest

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
    RiskLevel,
    ToolResultStatus,
)
from jarvis_devices.permissions import PERMISSION_APP_CONTROL, PERMISSION_DEVICE_STATUS_READ
from jarvis_devices.pc_apps import (
    ApplicationState,
    PC_APPLICATION_TOOL_NAMES,
    WindowInfo,
    build_pc_application_tools,
)

try:  # imported as part of the ``tests`` package (pytest / discover -t .)
    from .pc_support import FakePCBackend
    from .support import FakeAdapter
except ImportError:  # ``python -m unittest discover -s tests``
    from pc_support import FakePCBackend
    from support import FakeAdapter

CHROME_WINDOW = WindowInfo(handle=11, title="New Tab - Google Chrome", process_id=1234, process_name="chrome.exe")
NOTEPAD_WINDOW = WindowInfo(handle=22, title="untitled - Notepad", process_id=5678, process_name="notepad.exe")
NOTEPAD_WINDOW_2 = WindowInfo(handle=23, title="notes.txt - Notepad", process_id=5678, process_name="notepad.exe")
HIDDEN_CHROME = WindowInfo(handle=24, title="Google Chrome", process_name="chrome.exe", is_visible=False)
MINIMIZED_VSCODE = WindowInfo(
    handle=33, title="manager.py - Visual Studio Code", process_name="code.exe", is_minimized=True
)


class PCToolCase(unittest.IsolatedAsyncioTestCase):
    """Wires the Phase 2 tools into a real DeviceActionManager."""

    def build(
        self,
        *,
        windows=(),
        backend=None,
        granted=(PERMISSION_DEVICE_STATUS_READ, PERMISSION_APP_CONTROL),
        platform=Platform.PC,
        confirmation_policy=None,
        adapters=(Platform.PC,),
    ) -> DeviceActionManager:
        self.backend = backend if backend is not None else FakePCBackend(tuple(windows))
        registry = DeviceToolRegistry()
        registry.register_all(
            build_pc_application_tools(
                self.backend,
                platform_probe=lambda: platform,
                close_poll_interval=0.0,
                close_attempts=3,
            )
        )
        platforms = PlatformRegistry()
        for adapter_platform in adapters:
            platforms.register(FakeAdapter(adapter_platform))
        policy = confirmation_policy or ConfirmationPolicy()
        return DeviceActionManager(
            registry,
            PermissionPolicy(granted=granted),
            ConfirmationManager(policy=policy),
            platforms,
            AuditLogger(enabled=False),
            confirmation_policy=policy,
        )


class ToolDeclarationTests(unittest.TestCase):
    def test_tools_are_declared_for_the_pc_platform(self) -> None:
        backend = FakePCBackend()
        tools = build_pc_application_tools(backend, platform_probe=lambda: Platform.PC)
        self.assertEqual([tool.name for tool in tools], list(PC_APPLICATION_TOOL_NAMES))
        for tool in tools:
            with self.subTest(tool=tool.name):
                self.assertIs(tool.platform, Platform.PC)
                self.assertIsNone(tool.requires_confirmation)  # decided by the policy
                self.assertTrue(tool.is_available())

    def test_risk_levels_and_permissions(self) -> None:
        tools = {tool.name: tool for tool in build_pc_application_tools(FakePCBackend(), platform_probe=lambda: Platform.PC)}
        self.assertIs(tools["pc.app.list"].risk_level, RiskLevel.SAFE)
        self.assertIs(tools["pc.app.status"].risk_level, RiskLevel.SAFE)
        for name in ("pc.app.open", "pc.app.focus", "pc.app.close"):
            with self.subTest(tool=name):
                self.assertIs(tools[name].risk_level, RiskLevel.LOW_RISK)
                self.assertEqual(tools[name].required_permissions, (PERMISSION_APP_CONTROL,))
        for name in ("pc.app.list", "pc.app.status"):
            self.assertEqual(tools[name].required_permissions, (PERMISSION_DEVICE_STATUS_READ,))

    def test_tools_report_unsupported_platform_off_pc(self) -> None:
        tools = build_pc_application_tools(FakePCBackend(), platform_probe=lambda: Platform.ANDROID)
        for tool in tools:
            with self.subTest(tool=tool.name):
                blocked = tool.platform_result()
                self.assertIsNotNone(blocked)
                self.assertEqual(blocked.status, ToolResultStatus.UNAVAILABLE)
                self.assertEqual(blocked.error_code, ErrorCode.UNSUPPORTED_PLATFORM)

    def test_tools_are_unavailable_without_a_working_backend(self) -> None:
        tools = build_pc_application_tools(FakePCBackend(available=False), platform_probe=lambda: Platform.PC)
        for tool in tools:
            with self.subTest(tool=tool.name):
                self.assertFalse(tool.is_available())
                blocked = tool.platform_result()
                self.assertEqual(blocked.error_code, ErrorCode.DEVICE_UNAVAILABLE)


class ListOpenApplicationsTests(PCToolCase):
    async def test_returns_structured_window_information(self) -> None:
        manager = self.build(windows=(CHROME_WINDOW, NOTEPAD_WINDOW, MINIMIZED_VSCODE, HIDDEN_CHROME))
        result = await manager.request("pc.app.list")

        self.assertTrue(result.success)
        self.assertEqual(result.data["count"], 3)  # hidden window excluded
        self.assertEqual(result.data["applications"], [
            {"application": "Google Chrome", "windows": 1},
            {"application": "Notepad", "windows": 1},
            {"application": "Visual Studio Code", "windows": 1},
        ])
        chrome_entry = [entry for entry in result.data["windows"] if entry["application"] == "Google Chrome"][0]
        self.assertEqual(chrome_entry["window_title"], "New Tab - Google Chrome")
        self.assertEqual(chrome_entry["process_id"], 1234)
        self.assertEqual(chrome_entry["state"], "visible")
        minimized = [entry for entry in result.data["windows"] if entry["state"] == "minimized"]
        self.assertEqual(len(minimized), 1)
        self.assertEqual(minimized[0]["application"], "Visual Studio Code")

    async def test_limit_truncates_and_reports_it(self) -> None:
        manager = self.build(windows=(CHROME_WINDOW, NOTEPAD_WINDOW, NOTEPAD_WINDOW_2))
        result = await manager.request("pc.app.list", {"limit": 2})
        self.assertTrue(result.success)
        self.assertEqual(result.data["count"], 2)
        self.assertTrue(result.data["truncated"])
        self.assertEqual(result.data["total_visible_windows"], 3)

    async def test_limit_is_validated(self) -> None:
        manager = self.build()
        self.assertEqual(
            (await manager.request("pc.app.list", {"limit": 0})).status,
            ToolResultStatus.INVALID_ARGUMENT,
        )
        self.assertEqual(
            (await manager.request("pc.app.list", {"limit": 5000})).status,
            ToolResultStatus.INVALID_ARGUMENT,
        )

    async def test_backend_failure_is_structured(self) -> None:
        backend = FakePCBackend()
        backend.list_error = "desktop is locked"
        manager = self.build(backend=backend)
        result = await manager.request("pc.app.list")
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, ErrorCode.EXECUTION_FAILED)

    async def test_no_windows_is_still_a_success(self) -> None:
        manager = self.build()
        result = await manager.request("pc.app.list")
        self.assertTrue(result.success)
        self.assertEqual(result.data["count"], 0)


class ApplicationStatusTests(PCToolCase):
    async def test_running(self) -> None:
        manager = self.build(windows=(CHROME_WINDOW, HIDDEN_CHROME))
        result = await manager.request("pc.app.status", {"app": "Chrome"})
        self.assertTrue(result.success)
        self.assertEqual(result.data["state"], ApplicationState.RUNNING)
        self.assertEqual(result.data["window_count"], 1)  # hidden window ignored
        self.assertEqual(result.data["windows"][0]["process_id"], 1234)

    async def test_not_running(self) -> None:
        manager = self.build(windows=(NOTEPAD_WINDOW,))
        result = await manager.request("pc.app.status", {"app": "chrome"})
        self.assertTrue(result.success)
        self.assertEqual(result.data["state"], ApplicationState.NOT_RUNNING)
        self.assertEqual(result.data["window_count"], 0)

    async def test_unknown_application(self) -> None:
        manager = self.build()
        result = await manager.request("pc.app.status", {"app": "itunes"})
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, ErrorCode.APPLICATION_NOT_FOUND)

    async def test_unavailable_backend_reports_unknown_state(self) -> None:
        backend = FakePCBackend()
        backend.list_error = "explorer is not responding"
        manager = self.build(backend=backend)
        result = await manager.request("pc.app.status", {"app": "chrome"})
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, ErrorCode.EXECUTION_FAILED)
        self.assertEqual(result.data["state"], ApplicationState.UNKNOWN)

    async def test_unsupported_platform_reports_unknown_state(self) -> None:
        # A PC adapter is registered so the manager reaches the tool itself.
        manager = self.build(platform=Platform.ANDROID, adapters=(Platform.PC, Platform.ANDROID))
        result = await manager.request("pc.app.status", {"app": "chrome"})
        self.assertEqual(result.status, ToolResultStatus.UNAVAILABLE)
        self.assertEqual(result.error_code, ErrorCode.UNSUPPORTED_PLATFORM)
        self.assertEqual(result.data["state"], ApplicationState.UNKNOWN)

    async def test_missing_argument(self) -> None:
        manager = self.build()
        self.assertEqual(
            (await manager.request("pc.app.status", {})).status,
            ToolResultStatus.INVALID_ARGUMENT,
        )


class OpenApplicationTests(PCToolCase):
    async def test_launches_a_known_application(self) -> None:
        manager = self.build()
        result = await manager.request("pc.app.open", {"app": "Chrome"})
        self.assertTrue(result.success)
        self.assertEqual(result.data["action"], "launched")
        self.assertEqual(result.data["already_running"], False)
        self.assertEqual([spec.name for spec in self.backend.launched], ["chrome"])
        self.assertEqual(self.backend.focused, [])

    async def test_unknown_application_launches_nothing(self) -> None:
        manager = self.build()
        result = await manager.request("pc.app.open", {"app": "definitely-not-an-app"})
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, ErrorCode.APPLICATION_NOT_FOUND)
        self.assertEqual(self.backend.launched, [])

    async def test_ambiguous_application_launches_nothing(self) -> None:
        manager = self.build()
        result = await manager.request("pc.app.open", {"app": "c"})
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, ErrorCode.AMBIGUOUS_APPLICATION)
        self.assertEqual(self.backend.launched, [])

    async def test_invalid_argument(self) -> None:
        manager = self.build()
        for arguments in ({}, {"app": ""}, {"app": "x" * 200}, {"app": "chrome", "shell": True}):
            with self.subTest(arguments=arguments):
                result = await manager.request("pc.app.open", arguments)
                self.assertEqual(result.status, ToolResultStatus.INVALID_ARGUMENT)
        self.assertEqual(self.backend.launched, [])

    async def test_permission_denied(self) -> None:
        manager = self.build(granted=(PERMISSION_DEVICE_STATUS_READ,))
        result = await manager.request("pc.app.open", {"app": "chrome"})
        self.assertEqual(result.status, ToolResultStatus.PERMISSION_DENIED)
        self.assertEqual(result.error_code, ErrorCode.PERMISSION_DENIED)
        self.assertEqual(self.backend.launched, [])

    async def test_unsupported_platform(self) -> None:
        manager = self.build(platform=Platform.ANDROID, adapters=(Platform.ANDROID,))
        result = await manager.request("pc.app.open", {"app": "chrome"})
        self.assertEqual(result.status, ToolResultStatus.UNAVAILABLE)
        self.assertEqual(self.backend.launched, [])

    async def test_unavailable_backend_is_reported_by_the_manager(self) -> None:
        manager = self.build(backend=FakePCBackend(available=False))
        result = await manager.request("pc.app.open", {"app": "chrome"})
        self.assertEqual(result.status, ToolResultStatus.UNAVAILABLE)
        self.assertEqual(result.error_code, ErrorCode.TOOL_UNAVAILABLE)
        self.assertEqual(self.backend.launched, [])

    async def test_already_running_is_focused_instead_of_relaunched(self) -> None:
        manager = self.build(windows=(CHROME_WINDOW,))
        result = await manager.request("pc.app.open", {"app": "chrome"})
        self.assertTrue(result.success)
        self.assertTrue(result.data["already_running"])
        self.assertEqual(result.data["action"], "focused")
        self.assertEqual(self.backend.launched, [])
        self.assertEqual(self.backend.focused, [CHROME_WINDOW.handle])

    async def test_already_running_can_be_reported_as_an_error(self) -> None:
        manager = self.build(windows=(CHROME_WINDOW,))
        result = await manager.request("pc.app.open", {"app": "chrome", "focus_if_running": False})
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, ErrorCode.APPLICATION_ALREADY_RUNNING)
        self.assertEqual(self.backend.launched, [])
        self.assertEqual(self.backend.focused, [])

    async def test_launch_failure_is_structured(self) -> None:
        backend = FakePCBackend()
        backend.launch_error = "ShellExecute failed for chrome.exe (code 2)"
        manager = self.build(backend=backend)
        result = await manager.request("pc.app.open", {"app": "chrome"})
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, ErrorCode.EXECUTION_FAILED)
        self.assertIn("could not be launched", result.message)

    async def test_window_listing_failure_does_not_block_a_launch(self) -> None:
        backend = FakePCBackend()
        backend.list_error = "desktop busy"
        manager = self.build(backend=backend)
        result = await manager.request("pc.app.open", {"app": "notepad"})
        self.assertTrue(result.success)
        self.assertEqual([spec.name for spec in backend.launched], ["notepad"])


class FocusApplicationTests(PCToolCase):
    async def test_focuses_an_existing_window(self) -> None:
        manager = self.build(windows=(MINIMIZED_VSCODE, NOTEPAD_WINDOW))
        result = await manager.request("pc.app.focus", {"app": "vs code"})
        self.assertTrue(result.success)
        self.assertEqual(self.backend.focused, [MINIMIZED_VSCODE.handle])
        self.assertEqual(result.data["window"]["window_title"], "manager.py - Visual Studio Code")

    async def test_missing_window(self) -> None:
        manager = self.build(windows=(NOTEPAD_WINDOW,))
        result = await manager.request("pc.app.focus", {"app": "chrome"})
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, ErrorCode.APPLICATION_NOT_RUNNING)
        self.assertEqual(self.backend.focused, [])

    async def test_ambiguous_windows_are_not_guessed(self) -> None:
        manager = self.build(windows=(NOTEPAD_WINDOW, NOTEPAD_WINDOW_2))
        result = await manager.request("pc.app.focus", {"app": "notepad"})
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, ErrorCode.AMBIGUOUS_APPLICATION)
        self.assertEqual(len(result.data["windows"]), 2)
        self.assertEqual(self.backend.focused, [])

    async def test_window_title_disambiguates(self) -> None:
        manager = self.build(windows=(NOTEPAD_WINDOW, NOTEPAD_WINDOW_2))
        result = await manager.request("pc.app.focus", {"app": "notepad", "window_title": "notes.txt"})
        self.assertTrue(result.success)
        self.assertEqual(self.backend.focused, [NOTEPAD_WINDOW_2.handle])

    async def test_unknown_window_title(self) -> None:
        manager = self.build(windows=(NOTEPAD_WINDOW,))
        result = await manager.request("pc.app.focus", {"app": "notepad", "window_title": "nope"})
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, ErrorCode.WINDOW_NOT_FOUND)

    async def test_permission_failure(self) -> None:
        manager = self.build(windows=(CHROME_WINDOW,), granted=(PERMISSION_DEVICE_STATUS_READ,))
        result = await manager.request("pc.app.focus", {"app": "chrome"})
        self.assertEqual(result.status, ToolResultStatus.PERMISSION_DENIED)
        self.assertEqual(self.backend.focused, [])

    async def test_focus_failure_is_structured(self) -> None:
        backend = FakePCBackend((CHROME_WINDOW,))
        backend.focus_error = "foreground lock held by another process"
        manager = self.build(backend=backend)
        result = await manager.request("pc.app.focus", {"app": "chrome"})
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, ErrorCode.EXECUTION_FAILED)

    async def test_unknown_application(self) -> None:
        manager = self.build()
        result = await manager.request("pc.app.focus", {"app": "itunes"})
        self.assertEqual(result.error_code, ErrorCode.APPLICATION_NOT_FOUND)


class CloseApplicationTests(PCToolCase):
    async def test_graceful_close(self) -> None:
        manager = self.build(windows=(NOTEPAD_WINDOW, CHROME_WINDOW))
        result = await manager.request("pc.app.close", {"app": "notepad"})
        self.assertTrue(result.success)
        self.assertEqual(self.backend.closed, [NOTEPAD_WINDOW.handle])
        self.assertFalse(self.backend.window_exists(NOTEPAD_WINDOW.handle))
        self.assertTrue(self.backend.window_exists(CHROME_WINDOW.handle))
        self.assertEqual(result.data["action"], "closed")

    async def test_application_not_found(self) -> None:
        manager = self.build(windows=(CHROME_WINDOW,))
        result = await manager.request("pc.app.close", {"app": "notepad"})
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, ErrorCode.APPLICATION_NOT_RUNNING)
        self.assertEqual(self.backend.closed, [])

    async def test_unknown_application(self) -> None:
        manager = self.build()
        result = await manager.request("pc.app.close", {"app": "itunes"})
        self.assertEqual(result.error_code, ErrorCode.APPLICATION_NOT_FOUND)
        self.assertEqual(self.backend.closed, [])

    async def test_close_failure_is_reported_without_escalation(self) -> None:
        backend = FakePCBackend((NOTEPAD_WINDOW,))
        backend.close_is_effective = False
        manager = self.build(backend=backend)
        result = await manager.request("pc.app.close", {"app": "notepad"})
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, ErrorCode.EXECUTION_FAILED)
        self.assertIn("No process was terminated", result.message)
        self.assertEqual(backend.closed, [NOTEPAD_WINDOW.handle])  # asked once, never killed
        self.assertTrue(backend.window_exists(NOTEPAD_WINDOW.handle))

    async def test_close_request_failure(self) -> None:
        backend = FakePCBackend((NOTEPAD_WINDOW,))
        backend.close_error = "PostMessage refused"
        manager = self.build(backend=backend)
        result = await manager.request("pc.app.close", {"app": "notepad"})
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, ErrorCode.EXECUTION_FAILED)

    async def test_ambiguous_windows_are_not_closed(self) -> None:
        manager = self.build(windows=(NOTEPAD_WINDOW, NOTEPAD_WINDOW_2))
        result = await manager.request("pc.app.close", {"app": "notepad"})
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, ErrorCode.AMBIGUOUS_APPLICATION)
        self.assertEqual(self.backend.closed, [])

    async def test_window_title_selects_one_window(self) -> None:
        manager = self.build(windows=(NOTEPAD_WINDOW, NOTEPAD_WINDOW_2))
        result = await manager.request("pc.app.close", {"app": "notepad", "window_title": "untitled"})
        self.assertTrue(result.success)
        self.assertEqual(self.backend.closed, [NOTEPAD_WINDOW.handle])

    async def test_permission_failure(self) -> None:
        manager = self.build(windows=(NOTEPAD_WINDOW,), granted=(PERMISSION_DEVICE_STATUS_READ,))
        result = await manager.request("pc.app.close", {"app": "notepad"})
        self.assertEqual(result.status, ToolResultStatus.PERMISSION_DENIED)
        self.assertEqual(self.backend.closed, [])

    async def test_policy_needs_no_confirmation_by_default(self) -> None:
        manager = self.build(windows=(NOTEPAD_WINDOW,))
        result = await manager.request("pc.app.close", {"app": "notepad"})
        self.assertTrue(result.success)
        self.assertEqual(manager.pending_confirmations(), ())

    async def test_policy_can_require_confirmation_without_code_changes(self) -> None:
        policy = ConfirmationPolicy(always_confirm=("pc.app.close",))
        manager = self.build(windows=(NOTEPAD_WINDOW,), confirmation_policy=policy)

        asked = await manager.request("pc.app.close", {"app": "notepad"})
        self.assertEqual(asked.status, ToolResultStatus.PENDING_CONFIRMATION)
        self.assertEqual(self.backend.closed, [])

        confirmed = await manager.resolve_confirmation(asked.data["confirmation_id"], True)
        self.assertTrue(confirmed.success)
        self.assertEqual(self.backend.closed, [NOTEPAD_WINDOW.handle])

    async def test_declined_confirmation_closes_nothing(self) -> None:
        policy = ConfirmationPolicy(always_confirm=("pc.app.close",))
        manager = self.build(windows=(NOTEPAD_WINDOW,), confirmation_policy=policy)
        asked = await manager.request("pc.app.close", {"app": "notepad"})
        declined = await manager.resolve_confirmation(asked.data["confirmation_id"], False)
        self.assertEqual(declined.status, ToolResultStatus.DENIED)
        self.assertEqual(self.backend.closed, [])
        self.assertTrue(self.backend.window_exists(NOTEPAD_WINDOW.handle))


class UnregisteredToolTests(PCToolCase):
    async def test_only_the_five_phase_two_tools_exist(self) -> None:
        manager = self.build()
        self.assertEqual(set(manager.registry.names()), set(PC_APPLICATION_TOOL_NAMES))
        self.assertEqual(len(manager.registry.names()), 5)

    async def test_process_management_is_not_exposed(self) -> None:
        manager = self.build()
        for name in ("pc.process.kill", "kill_process", "pc.app.kill", "pc.shell.run", "pc.app.run_command"):
            with self.subTest(tool=name):
                result = await manager.request(name, {"pid": 4})
                self.assertEqual(result.error_code, ErrorCode.UNKNOWN_TOOL)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
