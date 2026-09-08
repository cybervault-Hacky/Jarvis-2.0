"""Windows implementation of the PC application backend (Phase 2).

Everything that touches Windows lives in this one module, behind the
:class:`~jarvis_devices.pc_apps.PCApplicationBackend` seam, so the tools in
:mod:`jarvis_devices.pc_apps` stay platform agnostic and unit testable.

Mechanisms used - all from ``pywin32``, which the project already depends on:

* ``win32gui.EnumWindows`` / ``GetWindowText`` / ``IsWindowVisible`` /
  ``IsIconic`` - discover windows (the same approach the existing
  ``Jarvis_window_CTRL.close`` already uses).
* ``win32gui.SetForegroundWindow`` - focus a window.
* ``win32gui.PostMessage(hwnd, WM_CLOSE, 0, 0)`` - ask an application to close
  itself. This is a *graceful* close; the application can still ask the user to
  save work. Nothing here terminates a process.
* ``win32api.ShellExecute(0, "open", target, "", None, SW_SHOWNORMAL)`` - launch
  one catalogued executable or registered URI with an **empty parameter
  string**, so no command line is ever assembled from model input.

There is no ``subprocess``, no shell, no ``eval``/``exec``, no ``ctypes`` and no
``os`` import in this module.
"""

from __future__ import annotations

import ntpath
from typing import Any, List, Optional, Tuple

from .enums import Platform
from .pc_apps import (
    ApplicationSpec,
    PCApplicationBackendError,
    WindowInfo,
)
from .platform import detect_current_platform

try:  # pragma: no cover - only importable on Windows
    import win32api
    import win32con
    import win32gui
    import win32process
except ImportError:  # pragma: no cover - non-Windows development machines
    win32api = None  # type: ignore[assignment]
    win32con = None  # type: ignore[assignment]
    win32gui = None  # type: ignore[assignment]
    win32process = None  # type: ignore[assignment]

__all__ = ["WindowsApplicationBackend"]

#: ShellExecute returns values <= 32 to report an error.
SHELL_EXECUTE_ERROR_LIMIT = 32


class WindowsApplicationBackend:
    """PC application backend backed by the Win32 API.

    The Win32 module handles and the path module are injectable so the behaviour
    can be tested deterministically without a desktop.
    """

    name = "windows"

    def __init__(
        self,
        *,
        gui: Any = None,
        con: Any = None,
        api: Any = None,
        process: Any = None,
        path_module: Any = ntpath,
        platform_probe: Any = detect_current_platform,
    ) -> None:
        self._gui = gui if gui is not None else win32gui
        self._con = con if con is not None else win32con
        self._api = api if api is not None else win32api
        self._process = process if process is not None else win32process
        self._path = path_module
        self._platform_probe = platform_probe

    # ------------------------------------------------------------------
    # Availability
    # ------------------------------------------------------------------
    def is_available(self) -> bool:
        return self.unavailable_reason() == ""

    def unavailable_reason(self) -> str:
        """Explain why this backend cannot be used (empty string when it can)."""
        if self._platform_probe() is not Platform.PC:
            return f"running on {self._platform_probe().value}, not on a PC"
        missing = [
            label
            for label, module in (
                ("win32gui", self._gui),
                ("win32con", self._con),
                ("win32api", self._api),
            )
            if module is None
        ]
        if missing:
            return "missing " + ", ".join(missing)
        return ""

    # ------------------------------------------------------------------
    # Window discovery
    # ------------------------------------------------------------------
    def list_windows(self) -> Tuple[WindowInfo, ...]:
        self._require_gui()
        windows: List[WindowInfo] = []

        def collect(hwnd: int, _: Any) -> None:
            try:
                if not self._gui.IsWindowVisible(hwnd):
                    return
                title = self._gui.GetWindowText(hwnd) or ""
                if not title.strip():
                    return
                windows.append(
                    WindowInfo(
                        handle=hwnd,
                        title=title,
                        process_id=self._process_id(hwnd),
                        process_name=self._process_name(self._process_id(hwnd)),
                        is_visible=True,
                        is_minimized=bool(self._gui.IsIconic(hwnd)),
                    )
                )
            except PCApplicationBackendError:
                raise
            except Exception:  # noqa: BLE001 - one odd window must not break discovery
                return

        try:
            self._gui.EnumWindows(collect, None)
        except PCApplicationBackendError:
            raise
        except Exception as exc:  # noqa: BLE001 - framework boundary
            raise PCApplicationBackendError(f"Could not enumerate windows: {exc}") from exc
        return tuple(windows)

    def window_exists(self, handle: int) -> bool:
        self._require_gui()
        try:
            return bool(self._gui.IsWindow(handle))
        except Exception as exc:  # noqa: BLE001 - framework boundary
            raise PCApplicationBackendError(f"Could not inspect window {handle}: {exc}") from exc

    # ------------------------------------------------------------------
    # Launch
    # ------------------------------------------------------------------
    def launch(self, spec: ApplicationSpec) -> None:
        self._require_api()
        target = self.resolve_launch_target(spec)
        if target is None:
            raise PCApplicationBackendError(
                f"{spec.display_name} does not appear to be installed on this PC."
            )
        try:
            outcome = self._api.ShellExecute(
                0,
                "open",
                target,
                "",  # parameters: always empty, never model supplied
                None,
                self._constant("SW_SHOWNORMAL", 1),
            )
        except Exception as exc:  # noqa: BLE001 - pywintypes.error and friends
            raise PCApplicationBackendError(f"ShellExecute refused {target}: {exc}") from exc

        try:
            code = int(outcome)
        except (TypeError, ValueError):
            code = SHELL_EXECUTE_ERROR_LIMIT + 1  # non-numeric handles count as success
        if code <= SHELL_EXECUTE_ERROR_LIMIT:
            raise PCApplicationBackendError(f"ShellExecute failed for {target} (code {code})")

    def resolve_launch_target(self, spec: ApplicationSpec) -> Optional[str]:
        """Pick the concrete launch target for ``spec`` (never model supplied)."""
        for candidate in spec.search_paths:
            expanded = self._path.expandvars(candidate)
            try:
                if self._path.exists(expanded):
                    return expanded
            except Exception:  # noqa: BLE001 - a bad path simply does not match
                continue
        target = spec.launch_target
        if not target:
            return None
        if ":" in target and not target.lower().endswith(".exe"):
            return target  # registered URI such as ms-settings:
        separators = [self._path.sep] + ([self._path.altsep] if getattr(self._path, "altsep", None) else [])
        if any(separator and separator in target for separator in separators):
            # absolute path: only use it when it really exists
            return target if self._path.exists(target) else None
        return target  # bare executable name, resolved through the App Paths registry

    # ------------------------------------------------------------------
    # Focus
    # ------------------------------------------------------------------
    def focus_window(self, handle: int) -> None:
        self._require_gui()
        if not self.window_exists(handle):
            raise PCApplicationBackendError(f"Window {handle} no longer exists.")
        try:
            if self._gui.IsIconic(handle):
                self._gui.ShowWindow(handle, self._constant("SW_RESTORE", 9))
            self._gui.SetForegroundWindow(handle)
        except Exception as exc:  # noqa: BLE001 - framework boundary
            raise PCApplicationBackendError(f"Could not focus window {handle}: {exc}") from exc

    # ------------------------------------------------------------------
    # Graceful close
    # ------------------------------------------------------------------
    def close_window(self, handle: int) -> None:
        """Send ``WM_CLOSE`` - the application decides what happens next."""
        self._require_gui()
        if not self.window_exists(handle):
            raise PCApplicationBackendError(f"Window {handle} no longer exists.")
        try:
            self._gui.PostMessage(handle, self._constant("WM_CLOSE", 0x0010), 0, 0)
        except Exception as exc:  # noqa: BLE001 - framework boundary
            raise PCApplicationBackendError(f"Could not ask window {handle} to close: {exc}") from exc

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _require_gui(self) -> None:
        if self._gui is None or self._con is None:
            raise PCApplicationBackendError(
                f"Windows backend unavailable ({self.unavailable_reason() or 'unknown reason'})"
            )

    def _require_api(self) -> None:
        if self._api is None or self._con is None:
            raise PCApplicationBackendError(
                f"Windows backend unavailable ({self.unavailable_reason() or 'unknown reason'})"
            )

    def _constant(self, name: str, default: int) -> int:
        value = getattr(self._con, name, default)
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _process_id(self, hwnd: int) -> int:
        if self._process is None:
            return 0
        try:
            _, pid = self._process.GetWindowThreadProcessId(hwnd)
            return int(pid)
        except Exception:  # noqa: BLE001 - PID is optional information
            return 0

    def _process_name(self, pid: int) -> str:
        """Best effort executable name for ``pid`` (empty when not permitted)."""
        if self._process is None or self._api is None or pid <= 0:
            return ""
        handle = None
        try:
            handle = self._api.OpenProcess(self._constant("PROCESS_QUERY_LIMITED_INFORMATION", 0x1000), False, pid)
            full_path = self._process.GetModuleFileNameEx(handle, 0)
            return self._path.basename(full_path or "")
        except Exception:  # noqa: BLE001 - protected processes simply report no name
            return ""
        finally:
            if handle is not None:
                try:
                    self._api.CloseHandle(handle)
                except Exception:  # noqa: BLE001 - nothing useful to do here
                    pass
