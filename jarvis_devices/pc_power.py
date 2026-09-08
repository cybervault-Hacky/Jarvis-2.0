"""PC power and session control (Phase 4).

Five operations on the PC JARVIS runs on - shut down, restart, sleep, hibernate
and log off - exposed as registered :class:`~jarvis_devices.tools.BaseDeviceTool`
objects, so every one of them travels the full Phase 1 pipeline:

    registry -> argument schema (empty) -> permissions -> platform adapter
              -> **confirmation** -> power tool -> PC power backend
              -> structured ToolResult

Safety model
------------
* **No arguments at all.** Every tool declares
  :meth:`~jarvis_devices.arguments.ArgumentSchema.empty`, so the framework
  rejects *any* argument the model tries to add. There is no timeout, no force
  flag, no reason string, no machine name, no command and no flags - nothing
  from the model reaches the operating system.
* **No command interface.** There is no ``execute_power_command`` and no path
  that accepts a string. The backend calls fixed Win32 APIs
  (:func:`ExitWindowsEx` / :func:`SetSystemPowerState`) with constants defined
  in :mod:`jarvis_devices.pc_power_windows`. Nothing is ever shelled out to.
* **Local machine only.** No parameter can name a remote host, an IP address or
  a UNC path, so remote power control is not expressible.
* **Confirmation is not optional.** All five tools set
  ``confirmation_mandatory = True`` and ``requires_confirmation = True``, and
  :class:`~jarvis_devices.confirmation.ConfirmationPolicy` checks that flag
  before ``never_confirm``. No policy configuration, and no model behaviour,
  can make a power operation run unconfirmed. Each confirmation is bound to one
  tool name, expires after the policy TTL and is single use (Phase 1
  semantics), so a shutdown confirmation cannot authorise a restart.
* **Honest results.** A tool reports ``SUCCESS`` only after the backend returns,
  and the backend returns only once the operating system has accepted the call.
  Missing privileges, a disabled hibernation file, an unsupported platform or an
  API refusal all produce a structured ``UNAVAILABLE``/``FAILED`` result with a
  precise error code - never a fake success.

Out of scope: Android power control, remote power control, force-killing
processes, BIOS/firmware changes and arbitrary command execution.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Mapping, Optional, Protocol, Tuple

from .arguments import ArgumentSchema
from .enums import Platform, RiskLevel
from .errors import ErrorCode
from .permissions import PERMISSION_POWER_CONTROL
from .platform import detect_current_platform
from .results import ToolResult
from .tools import BaseDeviceTool, ToolContext

__all__ = [
    "PowerOperation",
    "ALL_OPERATIONS",
    "OPERATION_LABELS",
    "PCPowerBackendError",
    "UnsupportedPowerOperationError",
    "PowerPrivilegeError",
    "PCPowerBackend",
    "UnavailablePCPowerBackend",
    "create_default_pc_power_backend",
    "PowerTool",
    "ShutdownTool",
    "RestartTool",
    "SleepTool",
    "HibernateTool",
    "LogoffTool",
    "build_pc_power_tools",
    "PC_POWER_TOOL_NAMES",
]


class PowerOperation:
    """The five operations this phase supports."""

    SHUTDOWN = "shutdown"
    RESTART = "restart"
    SLEEP = "sleep"
    HIBERNATE = "hibernate"
    LOGOFF = "logoff"


ALL_OPERATIONS: Tuple[str, ...] = (
    PowerOperation.SHUTDOWN,
    PowerOperation.RESTART,
    PowerOperation.SLEEP,
    PowerOperation.HIBERNATE,
    PowerOperation.LOGOFF,
)

#: Human readable labels used in the messages JARVIS speaks.
OPERATION_LABELS: Dict[str, str] = {
    PowerOperation.SHUTDOWN: "shut down",
    PowerOperation.RESTART: "restart",
    PowerOperation.SLEEP: "put to sleep",
    PowerOperation.HIBERNATE: "hibernate",
    PowerOperation.LOGOFF: "log out of",
}


class PCPowerBackendError(Exception):
    """A power operation was attempted and did not work."""


class UnsupportedPowerOperationError(PCPowerBackendError):
    """This PC/OS cannot perform the operation at all (e.g. no hibernation file).

    Mapped to ``UNAVAILABLE`` with ``POWER_OPERATION_UNSUPPORTED`` - never to a
    success and never to a generic failure.
    """


class PowerPrivilegeError(PCPowerBackendError):
    """Windows refused because the process lacks a required privilege."""


# ---------------------------------------------------------------------------
# Backend seam
# ---------------------------------------------------------------------------
class PCPowerBackend(Protocol):
    """The only place that touches the operating system's power state."""

    name: str

    def is_available(self) -> bool: ...

    def capabilities(self) -> Dict[str, str]: ...

    def shutdown(self) -> None: ...

    def restart(self) -> None: ...

    def sleep(self) -> None: ...

    def hibernate(self) -> None: ...

    def logoff(self) -> None: ...


class UnavailablePCPowerBackend:
    """Used when JARVIS is not running on a PC that can control its power state."""

    name = "unavailable"

    def __init__(
        self,
        explanation: str = "PC power control is only available on a Windows PC with pywin32 installed.",
    ) -> None:
        self.explanation = explanation

    def is_available(self) -> bool:
        return False

    def unavailable_reason(self) -> str:
        return self.explanation

    def capabilities(self) -> Dict[str, str]:
        from .pc_system import Capability

        return {operation: Capability.UNSUPPORTED for operation in ALL_OPERATIONS}

    def shutdown(self) -> None:
        raise UnsupportedPowerOperationError(self.explanation)

    def restart(self) -> None:
        raise UnsupportedPowerOperationError(self.explanation)

    def sleep(self) -> None:
        raise UnsupportedPowerOperationError(self.explanation)

    def hibernate(self) -> None:
        raise UnsupportedPowerOperationError(self.explanation)

    def logoff(self) -> None:
        raise UnsupportedPowerOperationError(self.explanation)


def create_default_pc_power_backend() -> PCPowerBackend:
    """Return the Windows backend when possible, otherwise an unavailable one."""
    from .pc_power_windows import WindowsPCPowerBackend

    backend = WindowsPCPowerBackend()
    if backend.is_available():
        return backend
    return UnavailablePCPowerBackend(
        explanation=(
            "PC power control needs Windows with pywin32 installed "
            f"(backend reported unavailable: {backend.unavailable_reason()})."
        )
    )


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
class PowerTool(BaseDeviceTool):
    """Base class for the five power tools.

    Everything they have in common is declared here: no arguments, one
    permission, ``EXTERNAL_ACTION`` risk, and confirmation that cannot be
    switched off.
    """

    platform = Platform.PC
    #: Every power operation changes the machine or ends the user's session.
    risk_level = RiskLevel.EXTERNAL_ACTION
    required_permissions = (PERMISSION_POWER_CONTROL,)
    #: Phase 1 semantics: the policy decides. Declared ``True`` so even a custom
    #: policy with empty ``risk_levels`` still asks.
    requires_confirmation = True
    #: Phase 4 requirement: no policy may opt a power operation out of asking.
    confirmation_mandatory = True
    #: No timeout, no force, no reason, no remote host, no command, no flags.
    argument_schema = ArgumentSchema.empty()

    #: Which :class:`PowerOperation` this tool performs.
    operation: str = ""

    def __init__(
        self,
        backend: PCPowerBackend,
        *,
        platform_probe: Callable[[], Platform] = detect_current_platform,
    ) -> None:
        if self.operation not in ALL_OPERATIONS:  # pragma: no cover - guards new subclasses
            raise ValueError(f"{type(self).__name__} declares an unknown operation: {self.operation!r}")
        self._backend = backend
        self._platform_probe = platform_probe

    # ------------------------------------------------------------------
    @property
    def backend(self) -> PCPowerBackend:
        return self._backend

    def is_available(self) -> bool:
        """Available when the backend is.

        Per-operation gaps (no hibernation file, no sleep state) are reported
        precisely by the tool instead of hiding the whole tool behind a generic
        ``TOOL_UNAVAILABLE``.
        """
        return self._backend.is_available()

    # ------------------------------------------------------------------
    def platform_result(self) -> Optional[ToolResult]:
        """Block when the platform/backend cannot be used at all."""
        detected = self._platform_probe()
        if detected is not Platform.PC:
            return ToolResult.unavailable(
                f"{self.name} only runs on a PC (detected: {detected.value}).",
                error_code=ErrorCode.UNSUPPORTED_PLATFORM,
                tool_name=self.name,
                data={"platform": detected.value, "operation": self.operation},
            )
        if not self._backend.is_available():
            reason = getattr(self._backend, "unavailable_reason", lambda: "")()
            return ToolResult.unavailable(
                "PC power control is unavailable on this machine.",
                error_code=ErrorCode.POWER_CONTROL_UNAVAILABLE,
                tool_name=self.name,
                data={"backend": self._backend.name, "reason": reason, "operation": self.operation},
            )
        return None

    def capability_result(self) -> Optional[ToolResult]:
        """Report ``UNSUPPORTED`` for this operation before touching the OS."""
        try:
            reported = self._backend.capabilities() or {}
        except PCPowerBackendError:
            return None  # the backend explains itself when it is really called
        except Exception:  # noqa: BLE001 - a broken capability probe must not crash
            return None
        from .pc_system import Capability

        if reported.get(self.operation) == Capability.UNSUPPORTED:
            return ToolResult.unavailable(
                f"This PC cannot {OPERATION_LABELS[self.operation]} itself.",
                error_code=ErrorCode.POWER_OPERATION_UNSUPPORTED,
                tool_name=self.name,
                data={"operation": self.operation, "detail": str(reported.get(f"{self.operation}_detail", ""))},
            )
        return None

    # ------------------------------------------------------------------
    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        blocked = self.platform_result()
        if blocked is not None:
            return blocked
        unsupported = self.capability_result()
        if unsupported is not None:
            return unsupported

        label = OPERATION_LABELS[self.operation]
        try:
            getattr(self._backend, self.operation)()
        except UnsupportedPowerOperationError as exc:
            return ToolResult.unavailable(
                f"This PC cannot {label} itself.",
                error_code=ErrorCode.POWER_OPERATION_UNSUPPORTED,
                tool_name=self.name,
                data={"operation": self.operation, "detail": str(exc)},
            )
        except PowerPrivilegeError as exc:
            return ToolResult.failure(
                f"Windows refused to {label} this PC: the required privilege is missing.",
                error=f"{type(exc).__name__}: {exc}"[:200],
                error_code=ErrorCode.POWER_PRIVILEGE_REQUIRED,
                tool_name=self.name,
                data={"operation": self.operation},
            )
        except PCPowerBackendError as exc:
            return ToolResult.failure(
                f"Could not {label} this PC.",
                error=f"{type(exc).__name__}: {exc}"[:200],
                error_code=ErrorCode.POWER_CONTROL_FAILED,
                tool_name=self.name,
                data={"operation": self.operation},
            )
        except Exception as exc:  # noqa: BLE001 - framework boundary
            return ToolResult.failure(
                f"Could not {label} this PC.",
                error=f"{type(exc).__name__}: {exc}"[:200],
                error_code=ErrorCode.POWER_CONTROL_FAILED,
                tool_name=self.name,
                data={"operation": self.operation},
            )

        # Only reached when the backend confirmed the OS accepted the call.
        return ToolResult.ok(
            f"{label.title()} accepted by Windows.",
            data={"operation": self.operation, "initiated": True},
        )


class ShutdownTool(PowerTool):
    """Shut the PC down."""

    name = "pc.power.shutdown"
    description = "Shut this PC down. Always asks the user for confirmation first."
    operation = PowerOperation.SHUTDOWN


class RestartTool(PowerTool):
    """Restart the PC."""

    name = "pc.power.restart"
    description = "Restart this PC. Always asks the user for confirmation first."
    operation = PowerOperation.RESTART


class SleepTool(PowerTool):
    """Put the PC to sleep."""

    name = "pc.power.sleep"
    description = "Put this PC to sleep. Always asks the user for confirmation first."
    operation = PowerOperation.SLEEP


class HibernateTool(PowerTool):
    """Hibernate the PC."""

    name = "pc.power.hibernate"
    description = "Hibernate this PC. Always asks the user for confirmation first."
    operation = PowerOperation.HIBERNATE


class LogoffTool(PowerTool):
    """Log the current user out (sign out)."""

    name = "pc.power.logoff"
    description = "Log the current user out of this PC. Always asks the user for confirmation first."
    operation = PowerOperation.LOGOFF


#: Tool names registered by :func:`build_pc_power_tools`.
PC_POWER_TOOL_NAMES: Tuple[str, ...] = (
    ShutdownTool.name,
    RestartTool.name,
    SleepTool.name,
    HibernateTool.name,
    LogoffTool.name,
)


def build_pc_power_tools(
    backend: Optional[PCPowerBackend] = None,
    *,
    platform_probe: Callable[[], Platform] = detect_current_platform,
) -> Tuple[BaseDeviceTool, ...]:
    """Build the five Phase 4 tools, ready for a :class:`DeviceToolRegistry`.

    Pass a fake ``backend`` in tests - no real machine is ever shut down.
    """
    active_backend = backend if backend is not None else create_default_pc_power_backend()
    shared: Mapping[str, Any] = {"backend": active_backend, "platform_probe": platform_probe}
    return (
        ShutdownTool(**shared),
        RestartTool(**shared),
        SleepTool(**shared),
        HibernateTool(**shared),
        LogoffTool(**shared),
    )
