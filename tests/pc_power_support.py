"""Test doubles for the Phase 4 PC power-control tests.

Nothing here touches a real machine's power state: the fakes record calls so the
suite stays deterministic, runs on any operating system, and can never shut
anything down.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from jarvis_devices.pc_power import (
    ALL_OPERATIONS,
    PCPowerBackendError,
    PowerPrivilegeError,
    UnsupportedPowerOperationError,
)
from jarvis_devices.pc_system import Capability


class FakePCPowerBackend:
    """A scripted :class:`~jarvis_devices.pc_power.PCPowerBackend`."""

    name = "fake"

    def __init__(
        self,
        *,
        available: bool = True,
        capabilities: Optional[Dict[str, str]] = None,
    ) -> None:
        self.available = available
        self.capability_map: Dict[str, str] = (
            capabilities
            if capabilities is not None
            else {operation: Capability.SUPPORTED for operation in ALL_OPERATIONS}
        )
        #: Ordered log of the operations that really reached the backend.
        self.calls: List[str] = []
        #: Per-operation error injection.
        self.errors: Dict[str, Exception] = {}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def fail_with(self, operation: str, error: Exception) -> None:
        self.errors[operation] = error

    def unsupported(self, operation: str, detail: str = "not on this fake PC") -> Exception:
        return UnsupportedPowerOperationError(detail)

    def _run(self, operation: str) -> None:
        self.calls.append(operation)
        error = self.errors.get(operation)
        if error is not None:
            raise error

    # ------------------------------------------------------------------
    # Backend protocol
    # ------------------------------------------------------------------
    def is_available(self) -> bool:
        return self.available

    def unavailable_reason(self) -> str:
        return "" if self.available else "the fake power backend is switched off"

    def capabilities(self) -> Dict[str, str]:
        return dict(self.capability_map)

    def shutdown(self) -> None:
        self._run("shutdown")

    def restart(self) -> None:
        self._run("restart")

    def sleep(self) -> None:
        self._run("sleep")

    def hibernate(self) -> None:
        self._run("hibernate")

    def logoff(self) -> None:
        self._run("logoff")


# ---------------------------------------------------------------------------
# Fake win32 modules for WindowsPCPowerBackend
# ---------------------------------------------------------------------------
class Win32Error(Exception):
    """Stands in for ``pywintypes.error``, which carries a ``winerror``."""

    def __init__(self, winerror: int, message: str = "win32 error") -> None:
        super().__init__(f"[WinError {winerror}] {message}")
        self.winerror = winerror


class FakeWin32Con:
    TOKEN_ADJUST_PRIVILEGES = 0x0020
    TOKEN_QUERY = 0x0008
    EWX_LOGOFF = 0x00
    EWX_SHUTDOWN = 0x01
    EWX_REBOOT = 0x02
    EWX_FORCE = 0x04
    EWX_POWEROFF = 0x08


class FakeWin32Api:
    """Stands in for ``win32api`` - records every power call."""

    def __init__(
        self,
        *,
        capabilities: Optional[Dict[str, Any]] = None,
        exit_windows_result: Any = 1,
        suspend_result: Any = 1,
    ) -> None:
        self.exit_windows_calls: List[Any] = []
        self.suspend_calls: List[Any] = []
        self.closed_handles: List[Any] = []
        self.capabilities_result = (
            capabilities
            if capabilities is not None
            else {
                "SystemS1": False,
                "SystemS2": False,
                "SystemS3": True,
                "SystemS4": True,
                "HiberFilePresent": True,
                "FullWake": True,
            }
        )
        self.exit_windows_result = exit_windows_result
        self.suspend_result = suspend_result
        self.exit_windows_error: Optional[Exception] = None
        self.suspend_error: Optional[Exception] = None
        self.capabilities_error: Optional[Exception] = None

    def ExitWindowsEx(self, flags, reason):
        self.exit_windows_calls.append((flags, reason))
        if self.exit_windows_error is not None:
            raise self.exit_windows_error
        return self.exit_windows_result

    def SetSystemPowerState(self, suspend, force):
        self.suspend_calls.append((suspend, force))
        if self.suspend_error is not None:
            raise self.suspend_error
        return self.suspend_result

    def GetPwrCapabilities(self):
        if self.capabilities_error is not None:
            raise self.capabilities_error
        return dict(self.capabilities_result)

    def CloseHandle(self, handle) -> None:
        self.closed_handles.append(handle)



class FakeWin32Security:
    def __init__(self) -> None:
        self.SE_PRIVILEGE_ENABLED = 0x00000002
        self.opened_tokens: List[Any] = []
        self.adjusted: List[Any] = []
        self.raise_on_adjust: Optional[Exception] = None

    def OpenProcessToken(self, process, access):
        handle = ("token", process, access)
        self.opened_tokens.append(handle)
        return handle

    def LookupPrivilegeValue(self, system, name):
        return ("luid", name)

    def AdjustTokenPrivileges(self, handle, disable_all, new_state):
        if self.raise_on_adjust is not None:
            raise self.raise_on_adjust
        self.adjusted.append((handle, disable_all, new_state))
        return []


class FakeWin32Process:
    def __init__(self, handle: Any = 4242) -> None:
        self.handle = handle

    def GetCurrentProcess(self):
        return self.handle
