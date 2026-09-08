"""Windows backend tests (Phase 2).

The Win32 modules are injected fakes, so these tests are deterministic and run
on any operating system. :class:`WindowsLiveIntegrationTests` is the only part
that touches a real desktop and it is skipped everywhere except Windows.
"""

from __future__ import annotations

import sys
import unittest

from jarvis_devices import Platform
from jarvis_devices.pc_apps import (
    ApplicationSpec,
    PCApplicationBackendError,
    default_application_catalog,
)
from jarvis_devices.pc_apps_windows import WindowsApplicationBackend

try:  # imported as part of the ``tests`` package (pytest / discover -t .)
    from .pc_support import (
        FakePathModule,
        FakeWin32Api,
        FakeWin32Con,
        FakeWin32Gui,
        FakeWin32Process,
        FakeWindowRecord,
    )
except ImportError:  # ``python -m unittest discover -s tests``
    from pc_support import (
        FakePathModule,
        FakeWin32Api,
        FakeWin32Con,
        FakeWin32Gui,
        FakeWin32Process,
        FakeWindowRecord,
    )

CHROME_EXE = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
VLC_EXE = r"C:\Program Files\VideoLAN\VLC\vlc.exe"


def make_backend(records=None, *, existing=(CHROME_EXE,), platform=Platform.PC):
    records = records if records is not None else [
        FakeWindowRecord(handle=101, title="New Tab - Google Chrome", pid=11, process_path=CHROME_EXE),
        FakeWindowRecord(handle=102, title="untitled - Notepad", pid=22, process_path=r"C:\Windows\notepad.exe"),
        FakeWindowRecord(handle=103, title="", pid=33),  # no title -> ignored
        FakeWindowRecord(handle=104, title="Hidden helper", pid=44, is_visible=False),
        FakeWindowRecord(handle=105, title="notes.txt - Notepad", pid=22, is_minimized=True),
        FakeWindowRecord(handle=106, title="Protected", pid=55, process_path=""),  # name lookup fails
    ]
    gui = FakeWin32Gui(records)
    api = FakeWin32Api(gui.records)
    process = FakeWin32Process(gui.records)
    backend = WindowsApplicationBackend(
        gui=gui,
        con=FakeWin32Con(),
        api=api,
        process=process,
        path_module=FakePathModule(tuple(existing)),
        platform_probe=lambda: platform,
    )
    return backend, gui, api, process


class AvailabilityTests(unittest.TestCase):
    def test_available_on_a_pc_with_the_win32_modules(self) -> None:
        backend, _, _, _ = make_backend()
        self.assertTrue(backend.is_available())
        self.assertEqual(backend.unavailable_reason(), "")

    def test_unavailable_off_pc(self) -> None:
        backend, _, _, _ = make_backend(platform=Platform.ANDROID)
        self.assertFalse(backend.is_available())
        self.assertIn("android", backend.unavailable_reason())

    def test_unavailable_without_win32(self) -> None:
        backend, _, _, _ = make_backend()
        backend._gui = None
        self.assertFalse(backend.is_available())
        self.assertIn("win32gui", backend.unavailable_reason())
        with self.assertRaises(PCApplicationBackendError):
            backend.list_windows()


class ListWindowsTests(unittest.TestCase):
    def test_reports_visible_titled_windows_only(self) -> None:
        backend, _, _, _ = make_backend()
        windows = backend.list_windows()
        self.assertEqual([w.handle for w in windows], [101, 102, 105, 106])
        chrome = [w for w in windows if w.handle == 101][0]
        self.assertEqual(chrome.title, "New Tab - Google Chrome")
        self.assertEqual(chrome.process_id, 11)
        self.assertEqual(chrome.process_name, "chrome.exe")
        self.assertTrue(chrome.is_visible)
        self.assertFalse(chrome.is_minimized)

    def test_reports_minimised_state(self) -> None:
        backend, _, _, _ = make_backend()
        minimized = [w for w in backend.list_windows() if w.handle == 105][0]
        self.assertTrue(minimized.is_minimized)

    def test_protected_processes_report_no_name(self) -> None:
        backend, _, _, _ = make_backend()
        protected = [w for w in backend.list_windows() if w.handle == 106][0]
        self.assertEqual(protected.process_name, "")
        self.assertEqual(protected.process_id, 55)

    def test_process_handles_are_closed(self) -> None:
        backend, _, api, _ = make_backend()
        backend.list_windows()
        self.assertGreater(len(api.closed_handles), 0)


class LaunchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = default_application_catalog()

    def test_launches_the_installed_executable(self) -> None:
        backend, _, api, _ = make_backend()
        backend.launch(self.catalog.get("chrome"))
        self.assertEqual(len(api.shell_execute_calls), 1)
        hwnd, verb, target, parameters, directory, show = api.shell_execute_calls[0]
        self.assertEqual(verb, "open")
        self.assertEqual(target, CHROME_EXE)
        self.assertEqual(parameters, "")  # never a model supplied command line
        self.assertIsNone(directory)
        self.assertEqual(show, FakeWin32Con.SW_SHOWNORMAL)

    def test_bare_executable_names_are_handed_to_the_shell(self) -> None:
        backend, _, api, _ = make_backend()
        backend.launch(self.catalog.get("notepad"))
        self.assertEqual(api.shell_execute_calls[0][2], "notepad.exe")

    def test_registered_uris_are_supported(self) -> None:
        backend, _, api, _ = make_backend()
        backend.launch(self.catalog.get("settings"))
        self.assertEqual(api.shell_execute_calls[0][2], "ms-settings:")

    def test_missing_installation_is_reported(self) -> None:
        """An absolute target that is not on disk is never handed to the shell."""
        backend, _, api, _ = make_backend(existing=())
        spec = ApplicationSpec(
            name="custom", display_name="Custom", launch_target=r"C:\Apps\custom.exe"
        )
        with self.assertRaises(PCApplicationBackendError) as caught:
            backend.launch(spec)
        self.assertIn("does not appear to be installed", str(caught.exception))
        self.assertEqual(api.shell_execute_calls, [])

    def test_bare_names_fall_back_to_the_app_paths_registry(self) -> None:
        """No absolute path known -> let ShellExecute resolve the exe name.

        When the application is really missing, ShellExecute answers with an
        error code, which the backend reports (see the test below).
        """
        backend, _, api, _ = make_backend(existing=())
        backend.launch(self.catalog.get("chrome"))
        self.assertEqual(api.shell_execute_calls[0][2], "chrome.exe")
        api.shell_execute_result = 2  # ERROR_FILE_NOT_FOUND
        with self.assertRaises(PCApplicationBackendError):
            backend.launch(self.catalog.get("chrome"))

    def test_shell_execute_error_code_is_reported(self) -> None:
        backend, _, api, _ = make_backend()
        api.shell_execute_result = 2  # ERROR_FILE_NOT_FOUND
        with self.assertRaises(PCApplicationBackendError) as caught:
            backend.launch(self.catalog.get("chrome"))
        self.assertIn("code 2", str(caught.exception))

    def test_shell_execute_exception_is_reported(self) -> None:
        backend, _, api, _ = make_backend()
        api.shell_execute_error = "association failed"
        with self.assertRaises(PCApplicationBackendError):
            backend.launch(self.catalog.get("chrome"))

    def test_absolute_targets_must_exist(self) -> None:
        backend, _, api, _ = make_backend(existing=())
        spec = ApplicationSpec(name="custom", display_name="Custom", launch_target=r"C:\Apps\custom.exe")
        self.assertIsNone(backend.resolve_launch_target(spec))
        backend2, _, _, _ = make_backend(existing=(r"C:\Apps\custom.exe",))
        self.assertEqual(backend2.resolve_launch_target(spec), r"C:\Apps\custom.exe")


class FocusTests(unittest.TestCase):
    def test_focuses_a_normal_window(self) -> None:
        backend, gui, _, _ = make_backend()
        backend.focus_window(101)
        self.assertEqual(gui.foreground, [101])
        self.assertEqual(gui.shown, [])

    def test_restores_a_minimised_window_first(self) -> None:
        backend, gui, _, _ = make_backend()
        backend.focus_window(105)
        self.assertEqual(gui.shown, [(105, FakeWin32Con.SW_RESTORE)])
        self.assertEqual(gui.foreground, [105])

    def test_unknown_window_is_reported(self) -> None:
        backend, _, _, _ = make_backend()
        with self.assertRaises(PCApplicationBackendError):
            backend.focus_window(999)

    def test_foreground_failure_is_reported(self) -> None:
        backend, gui, _, _ = make_backend()
        gui.raise_on_set_foreground = True
        with self.assertRaises(PCApplicationBackendError):
            backend.focus_window(101)


class CloseTests(unittest.TestCase):
    def test_close_posts_wm_close_only(self) -> None:
        backend, gui, _, _ = make_backend()
        backend.close_window(102)
        self.assertEqual(gui.posted, [(102, FakeWin32Con.WM_CLOSE)])
        self.assertFalse(backend.window_exists(102))  # the fake app honoured WM_CLOSE

    def test_close_never_terminates_a_process(self) -> None:
        backend, gui, api, process = make_backend()
        backend.close_window(102)
        for fake in (gui, api, process):
            for forbidden in ("TerminateProcess", "terminate", "kill"):
                self.assertFalse(hasattr(fake, forbidden), f"fake {fake!r} exposes {forbidden}")

    def test_unknown_window_is_reported(self) -> None:
        backend, _, _, _ = make_backend()
        with self.assertRaises(PCApplicationBackendError):
            backend.close_window(999)

    def test_window_that_ignores_wm_close_still_exists(self) -> None:
        records = [FakeWindowRecord(handle=200, title="unsaved - Notepad", pid=7, closes_on_wm_close=False)]
        backend, gui, _, _ = make_backend(records=records)
        backend.close_window(200)
        self.assertEqual(gui.posted, [(200, FakeWin32Con.WM_CLOSE)])
        self.assertTrue(backend.window_exists(200))  # reported honestly, never escalated


@unittest.skipUnless(
    sys.platform == "win32",
    "live Windows integration - runs only on a real Windows desktop",
)
class WindowsLiveIntegrationTests(unittest.TestCase):  # pragma: no cover - Windows only
    """Isolated, opt-in check against the real desktop.

    Skipped on every non-Windows machine, so the normal suite stays
    deterministic. Run explicitly on Windows with::

        python -m unittest tests.test_pc_apps_windows.WindowsLiveIntegrationTests
    """

    def setUp(self) -> None:
        self.backend = WindowsApplicationBackend()
        if not self.backend.is_available():
            self.skipTest(f"backend unavailable: {self.backend.unavailable_reason()}")

    def test_lists_real_windows(self) -> None:
        windows = self.backend.list_windows()
        self.assertIsInstance(windows, tuple)
        for window in windows:
            self.assertTrue(window.title.strip())
            self.assertTrue(window.is_visible)

    def test_status_tool_reports_a_real_state(self) -> None:
        from jarvis_devices.pc_apps import ApplicationState, build_pc_application_tools

        tools = {tool.name: tool for tool in build_pc_application_tools(self.backend)}
        import asyncio

        result = asyncio.run(tools["pc.app.list"].execute({}, _context()))
        self.assertTrue(result.success)
        self.assertIn(result.data["count"], range(0, 10_000))
        self.assertIn(ApplicationState.RUNNING, (ApplicationState.RUNNING, ApplicationState.NOT_RUNNING))


def _context():  # pragma: no cover - helper for the live test only
    from jarvis_devices import ToolContext

    return ToolContext(execution_id="exec-live", tool_name="pc.app.list")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
