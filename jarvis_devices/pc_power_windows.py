"""Windows implementation of the PC power backend (Phase 4).

Everything that touches Windows lives in this one module, behind the
:class:`~jarvis_devices.pc_power.PCPowerBackend` seam, so the tools in
:mod:`jarvis_devices.pc_power` stay platform agnostic and unit testable.

Mechanisms used - all from ``pywin32``, which the project already depends on
(verified against the real ``win32api`` binary; no new dependency):

* ``win32api.ExitWindowsEx(flags, reason)`` - log off, shut down (with power
  off) and restart. The flags are the module constants below, never built from
  anything the caller supplied. ``EWX_FORCE`` is deliberately never used, so
  Windows still lets applications ask the user to save work.
* ``win32api.SetSystemPowerState(bSuspend, bForce)`` - sleep (``bSuspend=True``)
  and hibernate (``bSuspend=False``). ``bForce`` is always ``False``.
* ``win32api.GetPwrCapabilities()`` - honest capability reporting, e.g. whether a
  hibernation file exists at all.
* ``win32security`` / ``win32process`` - enable ``SeShutdownPrivilege`` in the
  process token, best effort, before a shutdown or restart.

There is **no** ``subprocess``, no shell, no ``shutdown.exe``, no ``eval``/
``exec``, no ``ctypes`` and no ``os`` import in this module, and no remote
target of any kind: every call acts on the local machine only.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from .enums import Platform
from .pc_power import (
    PCPowerBackendError,
    PowerOperation,
    PowerPrivilegeError,
    UnsupportedPowerOperationError,
)
from .pc_system import Capability
from .platform import detect_current_platform

try:  # pragma: no cover - only importable on Windows
    import win32api
    import win32con
    import win32process
    import win32security
except ImportError:  # pragma: no cover - non-Windows development machines
    win32api = None  # type: ignore[assignment]
    win32con = None  # type: ignore[assignment]
    win32process = None  # type: ignore[assignment]
    win32security = None  # type: ignore[assignment]

__all__ = ["WindowsPCPowerBackend"]

# --- Fixed Win32 constants. Never derived from user input. -------------------
EWX_LOGOFF = 0x00
EWX_SHUTDOWN = 0x01
EWX_REBOOT = 0x02
EWX_POWEROFF = 0x08
#: ``EWX_FORCE`` (0x04) is intentionally absent: JARVIS never force-closes apps.

SHUTDOWN_FLAGS: Dict[str, int] = {
    PowerOperation.LOGOFF: EWX_LOGOFF,
    PowerOperation.SHUTDOWN: EWX_SHUTDOWN | EWX_POWEROFF,
    PowerOperation.RESTART: EWX_REBOOT,
}

#: ``SHTDN_REASON_FLAG_PLANNED`` - an application initiated, planned change.
SHUTDOWN_REASON = 0x80000000

#: The token privilege Windows requires for shutdown/restart.
SHUTDOWN_PRIVILEGE = "SeShutdownPrivilege"

#: Win32 errors that mean "this process is not allowed to do that".
PRIVILEGE_WINERRORS = frozenset({5, 1314})  # ERROR_ACCESS_DENIED, ERROR_PRIVILEGE_NOT_HELD

#: ``GetPwrCapabilities`` keys that mean "this machine can suspend".
SLEEP_STATE_KEYS = ("SystemS1", "SystemS2", "SystemS3", "SystemS4")
#: ... and the key that means "hibernation is actually available".
HIBERNATE_KEY = "HiberFilePresent"


class WindowsPCPowerBackend:
    """Power backend backed by the Win32 API.

    Every Win32 module is injectable, so the behaviour is testable without ever
    touching a real machine's power state.
    """

    name = "windows"

    def __init__(
        self,
        *,
        api: Any = None,
        con: Any = None,
        security: Any = None,
        process: Any = None,
        platform_probe: Callable[[], Platform] = detect_current_platform,
    ) -> None:
        self._api = api if api is not None else win32api
        self._con = con if con is not None else win32con
        self._security = security if security is not None else win32security
        self._process = process if process is not None else win32process
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
        if self._api is None or self._con is None:
            return "missing pywin32 (win32api / win32con)"
        return ""

    # ------------------------------------------------------------------
    # Capabilities
    # ------------------------------------------------------------------
    def capabilities(self) -> Dict[str, str]:
        """What this machine can actually do, from ``GetPwrCapabilities``."""
        powers = self._power_capabilities()
        sleep_supported = any(powers.get(key) for key in SLEEP_STATE_KEYS)
        hibernate_supported = bool(powers.get(HIBERNATE_KEY))
        return {
            PowerOperation.SHUTDOWN: Capability.SUPPORTED,
            PowerOperation.RESTART: Capability.SUPPORTED,
            PowerOperation.LOGOFF: Capability.SUPPORTED,
            PowerOperation.SLEEP: Capability.SUPPORTED if sleep_supported else Capability.UNSUPPORTED,
            PowerOperation.HIBERNATE: (
                Capability.SUPPORTED if hibernate_supported else Capability.UNSUPPORTED
            ),
            "sleep_detail": (
                "" if sleep_supported else "This PC reports no supported sleep state (S1-S4)."
            ),
            "hibernate_detail": (
                "" if hibernate_supported else "Hibernation is not enabled on this PC (no hibernation file)."
            ),
        }

    def _power_capabilities(self) -> Dict[str, Any]:
        if self._api is None or not hasattr(self._api, "GetPwrCapabilities"):
            return {}
        try:
            return dict(self._api.GetPwrCapabilities() or {})
        except Exception:  # noqa: BLE001 - an unreadable capability set is simply empty
            return {}

    # ------------------------------------------------------------------
    # Operations
    # ------------------------------------------------------------------
    def logoff(self) -> None:
        self._exit_windows(PowerOperation.LOGOFF)

    def shutdown(self) -> None:
        self._enable_shutdown_privilege()
        self._exit_windows(PowerOperation.SHUTDOWN)

    def restart(self) -> None:
        self._enable_shutdown_privilege()
        self._exit_windows(PowerOperation.RESTART)

    def sleep(self) -> None:
        self._set_suspend_state(suspend=True)

    def hibernate(self) -> None:
        powers = self._power_capabilities()
        if powers and not powers.get(HIBERNATE_KEY):
            raise UnsupportedPowerOperationError(
                "Hibernation is not enabled on this PC (there is no hibernation file)."
            )
        self._set_suspend_state(suspend=False)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _require_api(self) -> None:
        if self._api is None or self._con is None:
            raise PCPowerBackendError(
                f"Windows power backend unavailable ({self.unavailable_reason() or 'unknown reason'})"
            )

    def _exit_windows(self, operation: str) -> None:
        """One ``ExitWindowsEx`` call with fixed flags - never a command line."""
        self._require_api()
        flags = SHUTDOWN_FLAGS[operation]
        try:
            outcome = self._api.ExitWindowsEx(flags, SHUTDOWN_REASON)
        except Exception as exc:  # noqa: BLE001 - pywintypes.error and friends
            raise self._translate(exc, operation) from exc
        if outcome is not None and not bool(outcome):
            raise PCPowerBackendError(
                f"Windows refused to {operation} this PC (ExitWindowsEx returned {outcome!r})."
            )

    def _set_suspend_state(self, *, suspend: bool) -> None:
        """One ``SetSystemPowerState`` call. ``bForce`` is always ``False``."""
        self._require_api()
        call = getattr(self._api, "SetSystemPowerState", None)
        if call is None:
            raise UnsupportedPowerOperationError(
                "This Windows installation does not expose SetSystemPowerState."
            )
        try:
            outcome = call(suspend, False)
        except Exception as exc:  # noqa: BLE001 - pywintypes.error and friends
            raise self._translate(exc, "sleep" if suspend else "hibernate") from exc
        if outcome is not None and not bool(outcome):
            raise PCPowerBackendError(
                "Windows refused to change the power state "
                f"(SetSystemPowerState returned {outcome!r})."
            )

    def _enable_shutdown_privilege(self) -> None:
        """Best effort: turn on ``SeShutdownPrivilege`` for this process.

        Never fatal - if the privilege cannot be enabled, the following
        ``ExitWindowsEx`` call is the authority and reports the real error.
        """
        if self._api is None or self._security is None or self._process is None:
            return
        handle = None
        try:
            token_adjust = self._constant("TOKEN_ADJUST_PRIVILEGES", 0x0020)
            token_query = self._constant("TOKEN_QUERY", 0x0008)
            enabled = getattr(self._security, "SE_PRIVILEGE_ENABLED", 0x00000002)
            handle = self._security.OpenProcessToken(
                self._process.GetCurrentProcess(), token_adjust | token_query
            )
            luid = self._security.LookupPrivilegeValue(None, SHUTDOWN_PRIVILEGE)
            self._security.AdjustTokenPrivileges(handle, False, [(luid, enabled)])
        except Exception:  # noqa: BLE001 - the API call itself reports the real problem
            return
        finally:
            if handle is not None:
                try:
                    self._api.CloseHandle(handle)
                except Exception:  # noqa: BLE001 - nothing useful to do here
                    pass

    def _constant(self, name: str, default: int) -> int:
        value = getattr(self._con, name, default) if self._con is not None else default
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _translate(exc: Exception, operation: str) -> PCPowerBackendError:
        """Turn a Win32 error into the right framework error type."""
        winerror = getattr(exc, "winerror", None)
        if winerror in PRIVILEGE_WINERRORS:
            return PowerPrivilegeError(
                f"Windows denied the {operation} request (error {winerror}): "
                f"{SHUTDOWN_PRIVILEGE} is not held by this process."
            )
        return PCPowerBackendError(f"Windows could not {operation} this PC: {exc}")

    def describe(self) -> Dict[str, Any]:  # pragma: no cover - diagnostics helper
        return {
            "name": self.name,
            "available": self.is_available(),
            "reason": self.unavailable_reason(),
            "capabilities": self.capabilities(),
        }


def default_backend() -> Optional[WindowsPCPowerBackend]:  # pragma: no cover - convenience
    return WindowsPCPowerBackend()
