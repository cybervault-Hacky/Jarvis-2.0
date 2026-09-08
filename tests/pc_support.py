"""Test doubles for the Phase 2 PC application-control tests.

Nothing here touches a desktop: the fakes record calls so the suite stays
deterministic and runs on any operating system.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from jarvis_devices.pc_apps import (
    ApplicationSpec,
    PCApplicationBackendError,
    WindowInfo,
)


# ---------------------------------------------------------------------------
# Backend double
# ---------------------------------------------------------------------------
class FakePCBackend:
    """A scripted :class:`PCApplicationBackend`."""

    name = "fake"

    def __init__(self, windows: Tuple[WindowInfo, ...] = (), *, available: bool = True) -> None:
        self.available = available
        self.windows: List[WindowInfo] = list(windows)
        self.launched: List[ApplicationSpec] = []
        self.focused: List[int] = []
        self.closed: List[int] = []
        self.list_error: Optional[str] = None
        self.launch_error: Optional[str] = None
        self.focus_error: Optional[str] = None
        self.close_error: Optional[str] = None
        #: When ``True`` a close request actually removes the window.
        self.close_is_effective = True
        #: When ``True`` launching makes a window appear.
        self.launch_opens_window = True
        self._next_handle = 9000

    # ------------------------------------------------------------------
    def is_available(self) -> bool:
        return self.available

    def list_windows(self) -> Tuple[WindowInfo, ...]:
        if self.list_error:
            raise PCApplicationBackendError(self.list_error)
        return tuple(self.windows)

    def launch(self, spec: ApplicationSpec) -> None:
        if self.launch_error:
            raise PCApplicationBackendError(self.launch_error)
        self.launched.append(spec)
        if self.launch_opens_window:
            self._next_handle += 1
            self.windows.append(
                WindowInfo(
                    handle=self._next_handle,
                    title=f"{spec.display_name}",
                    process_id=4242,
                    process_name=(spec.process_names[0] if spec.process_names else ""),
                )
            )

    def focus_window(self, handle: int) -> None:
        if self.focus_error:
            raise PCApplicationBackendError(self.focus_error)
        self.focused.append(handle)

    def close_window(self, handle: int) -> None:
        if self.close_error:
            raise PCApplicationBackendError(self.close_error)
        self.closed.append(handle)
        if self.close_is_effective:
            self.windows = [window for window in self.windows if window.handle != handle]

    def window_exists(self, handle: int) -> bool:
        return any(window.handle == handle for window in self.windows)


# ---------------------------------------------------------------------------
# Fake win32 modules for the Windows backend
# ---------------------------------------------------------------------------
@dataclass
class FakeWindowRecord:
    handle: int
    title: str
    pid: int = 1000
    process_path: str = ""
    is_visible: bool = True
    is_minimized: bool = False
    closes_on_wm_close: bool = True


class FakeWin32Con:
    SW_SHOWNORMAL = 1
    SW_RESTORE = 9
    WM_CLOSE = 0x0010
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


class FakeWin32Gui:
    def __init__(self, records: List[FakeWindowRecord]) -> None:
        self.records: Dict[int, FakeWindowRecord] = {record.handle: record for record in records}
        self.posted: List[Tuple[int, int]] = []
        self.foreground: List[int] = []
        self.shown: List[Tuple[int, int]] = []
        self.raise_on_set_foreground = False

    def EnumWindows(self, callback, extra=None):
        for handle in list(self.records):
            callback(handle, extra)

    def IsWindowVisible(self, handle: int) -> bool:
        return self.records[handle].is_visible

    def GetWindowText(self, handle: int) -> str:
        return self.records[handle].title

    def IsIconic(self, handle: int) -> bool:
        return self.records[handle].is_minimized

    def IsWindow(self, handle: int) -> bool:
        return handle in self.records

    def ShowWindow(self, handle: int, command: int) -> None:
        self.shown.append((handle, command))
        if command == FakeWin32Con.SW_RESTORE:
            self.records[handle].is_minimized = False

    def SetForegroundWindow(self, handle: int) -> None:
        if self.raise_on_set_foreground:
            raise RuntimeError("another window owns the foreground")
        self.foreground.append(handle)

    def PostMessage(self, handle: int, message: int, wparam: int, lparam: int) -> None:
        self.posted.append((handle, message))
        record = self.records.get(handle)
        if record is not None and message == FakeWin32Con.WM_CLOSE and record.closes_on_wm_close:
            del self.records[handle]


class FakeWin32Process:
    def __init__(self, records: Dict[int, FakeWindowRecord]) -> None:
        self._records = records

    def GetWindowThreadProcessId(self, handle: int) -> Tuple[int, int]:
        record = self._records.get(handle)
        return (0, record.pid if record else 0)

    def GetModuleFileNameEx(self, process_handle: int, index: int) -> str:
        # FakeWin32Api.OpenProcess hands back the pid as the handle.
        for record in self._records.values():
            if record.pid == process_handle:
                if not record.process_path:
                    raise RuntimeError("access denied")
                return record.process_path
        raise RuntimeError("no such process")


class FakeWin32Api:
    def __init__(self, records: Dict[int, FakeWindowRecord]) -> None:
        self._records = records
        self.shell_execute_calls: List[Tuple[Any, ...]] = []
        self.shell_execute_result: Any = 42
        self.shell_execute_error: Optional[str] = None
        self.closed_handles: List[int] = []
        self._next_handle = 500

    def ShellExecute(self, hwnd, operation, target, parameters, directory, show):
        self.shell_execute_calls.append((hwnd, operation, target, parameters, directory, show))
        if self.shell_execute_error:
            raise RuntimeError(self.shell_execute_error)
        return self.shell_execute_result

    def OpenProcess(self, access, inherit, pid):
        """Return the pid as the process handle (see FakeWin32Process)."""
        return pid

    def CloseHandle(self, handle) -> None:
        self.closed_handles.append(handle)


class FakePathModule:
    """Stands in for ``ntpath`` so no real filesystem is touched."""

    sep = "\\"
    altsep = "/"

    def __init__(self, existing: Tuple[str, ...] = ()) -> None:
        self.existing = set(existing)

    def expandvars(self, value: str) -> str:
        return (
            value.replace("%PROGRAMFILES%", "C:\\Program Files")
            .replace("%PROGRAMFILES(X86)%", "C:\\Program Files (x86)")
            .replace("%LOCALAPPDATA%", "C:\\Users\\sarthak\\AppData\\Local")
        )

    def exists(self, path: str) -> bool:
        return path in self.existing

    def basename(self, path: str) -> str:
        return path.rsplit("\\", 1)[-1]
