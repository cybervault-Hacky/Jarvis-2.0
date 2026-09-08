"""PC system control (Phase 3).

Volume, mute, brightness, Wi-Fi and Bluetooth on the PC JARVIS runs on, exposed
as registered :class:`~jarvis_devices.tools.BaseDeviceTool` objects so every
operation goes through the Phase 1 pipeline:

    registry -> argument schema -> permissions -> platform -> confirmation
              -> backend -> structured ToolResult

Security model
--------------
* The model only ever supplies a **percentage** (an integer 0-100) or nothing at
  all. No tool in this module accepts a command, a program name, a path, a
  script, a device id or a network configuration string, so no model input can
  ever become an operating system command.
* All operating system interaction happens behind the
  :class:`PCSystemBackend` seam (Windows implementation in
  :mod:`jarvis_devices.pc_system_windows`). There is no shell, no
  ``subprocess``, no ``eval``/``exec``, no ``ctypes`` and no ``os`` import in
  this package, and no code path reaches ``Jarvis_window_CTRL``'s legacy shell
  based ``open()``.
* Honesty over success: when the hardware or Windows cannot do something the
  tool answers ``UNAVAILABLE``/``FAILED`` with a precise error code. A missing
  audio endpoint, a monitor without a brightness control, a PC without Wi-Fi or
  an unsupported Bluetooth radio can never be reported as "done".
* Status reporting is deliberately narrow. It reads four device states and
  nothing else - never files, browser history, stored credentials, saved Wi-Fi
  passwords, messages or process lists.

Out of scope (Phase 4): shutdown, restart, sleep, hibernate and log off are not
implemented here and no tool in this module can reach them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Mapping, Optional, Protocol, Tuple

from .arguments import ArgumentSchema, ArgumentSpec
from .enums import Platform, RiskLevel
from .errors import ErrorCode
from .permissions import (
    PERMISSION_BLUETOOTH_CONTROL,
    PERMISSION_DEVICE_STATUS_READ,
    PERMISSION_DISPLAY_CONTROL,
    PERMISSION_NETWORK_CONTROL,
    PERMISSION_VOLUME_CONTROL,
)
from .platform import detect_current_platform
from .results import ToolResult
from .tools import BaseDeviceTool, ToolContext

__all__ = [
    "Capability",
    "ConnectivityState",
    "CONNECTIVITY_STATES",
    "CAPABILITY_NAMES",
    "PERCENT_MIN",
    "PERCENT_MAX",
    "LEVEL_VERIFICATION_TOLERANCE",
    "VolumeState",
    "BrightnessState",
    "ConnectivityStatus",
    "PCSystemBackendError",
    "UnsupportedCapabilityError",
    "PCSystemBackend",
    "UnavailablePCSystemBackend",
    "create_default_pc_system_backend",
    "sanitize_percentage",
    "PCSystemTool",
    "SystemStatusTool",
    "GetVolumeTool",
    "SetVolumeTool",
    "GetMuteTool",
    "MuteTool",
    "UnmuteTool",
    "GetBrightnessTool",
    "SetBrightnessTool",
    "WifiStatusTool",
    "WifiEnableTool",
    "WifiDisableTool",
    "BluetoothStatusTool",
    "BluetoothEnableTool",
    "BluetoothDisableTool",
    "build_pc_system_tools",
    "PC_SYSTEM_TOOL_NAMES",
]

#: Inclusive range every percentage argument may use.
PERCENT_MIN = 0
PERCENT_MAX = 100

#: How far the level the hardware reports back may drift from the level that was
#: requested before JARVIS calls the change a failure. Master volume is stored
#: as a 32 bit float, so a requested 40% can come back as 40.00001%.
LEVEL_VERIFICATION_TOLERANCE = 1.0

#: Capability keys used by :meth:`PCSystemBackend.capabilities` and by
#: ``pc.system.status``.
CAPABILITY_NAMES: Tuple[str, ...] = ("volume", "brightness", "wifi", "bluetooth")


class Capability:
    """Whether this PC can perform one system capability at all."""

    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    FAILED = "failed"
    UNKNOWN = "unknown"


class ConnectivityState:
    """The four honest answers a connectivity question may have."""

    ON = "on"
    OFF = "off"
    #: An adapter exists but Windows will not tell JARVIS whether it is on.
    UNKNOWN = "unknown"
    #: There is no way to ask (no adapter, no API) - not the same as "off".
    UNAVAILABLE = "unavailable"


CONNECTIVITY_STATES: Tuple[str, ...] = (
    ConnectivityState.ON,
    ConnectivityState.OFF,
    ConnectivityState.UNKNOWN,
    ConnectivityState.UNAVAILABLE,
)


class PCSystemBackendError(Exception):
    """A system call was attempted and did not work."""


class UnsupportedCapabilityError(PCSystemBackendError):
    """This PC/Windows cannot perform the capability at all.

    Mapped to an ``UNAVAILABLE`` result - never to a success and never to a
    generic failure, so JARVIS can tell "not possible here" apart from "tried
    and it broke".
    """


# ---------------------------------------------------------------------------
# Value objects returned by the backend
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class VolumeState:
    """Master volume as the backend reports it."""

    #: 0-100, or ``None`` when the level could not be read.
    level: Optional[float] = None
    muted: Optional[bool] = None
    capability: str = Capability.UNKNOWN
    detail: str = ""

    @property
    def is_supported(self) -> bool:
        return self.capability == Capability.SUPPORTED

    def describe(self) -> Dict[str, Any]:
        return {
            "level": self.level,
            "muted": self.muted,
            "capability": self.capability,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class BrightnessState:
    """Display brightness as the backend reports it."""

    #: 0-100, or ``None`` when the level could not be read.
    level: Optional[int] = None
    capability: str = Capability.UNKNOWN
    detail: str = ""

    @property
    def is_supported(self) -> bool:
        return self.capability == Capability.SUPPORTED

    def describe(self) -> Dict[str, Any]:
        return {"level": self.level, "capability": self.capability, "detail": self.detail}


@dataclass(frozen=True)
class ConnectivityStatus:
    """Wi-Fi / Bluetooth radio state."""

    state: str = ConnectivityState.UNKNOWN
    detail: str = ""
    #: Hardware label of the adapter, when the backend knows one. Never a
    #: credential, never a saved network secret.
    adapter: str = ""

    def describe(self) -> Dict[str, Any]:
        return {"state": self.state, "detail": self.detail, "adapter": self.adapter}


def sanitize_percentage(value: Any, *, label: str = "level") -> Tuple[Optional[float], Optional[str]]:
    """Validate a percentage *reported by the hardware* (not by the model).

    Model supplied percentages are validated exactly once, by the tool's
    :class:`~jarvis_devices.arguments.ArgumentSchema`. This helper only guards
    against a driver reporting nonsense (``NaN``, 250, ``None``) so JARVIS never
    repeats a meaningless number to the user.

    Returns ``(clean_value, error_message)``; exactly one of them is ``None``.
    """
    if value is None:
        return None, f"The {label} could not be read from this PC."
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None, f"The {label} was reported as {value!r}, which is not a number."
    if number != number or number in (float("inf"), float("-inf")):  # NaN / Infinity
        return None, f"The {label} was reported as a non-finite number."
    if number < PERCENT_MIN or number > PERCENT_MAX:
        return None, f"The {label} was reported as {number}, which is outside {PERCENT_MIN}-{PERCENT_MAX}."
    return number, None


# ---------------------------------------------------------------------------
# Backend seam
# ---------------------------------------------------------------------------
class PCSystemBackend(Protocol):
    """The only place that touches the operating system."""

    name: str

    def is_available(self) -> bool: ...

    def capabilities(self) -> Dict[str, str]: ...

    def system_info(self) -> Dict[str, str]: ...

    def get_volume(self) -> VolumeState: ...

    def set_volume(self, level: float) -> VolumeState: ...

    def get_mute(self) -> bool: ...

    def set_mute(self, muted: bool) -> bool: ...

    def get_brightness(self) -> BrightnessState: ...

    def set_brightness(self, level: int) -> BrightnessState: ...

    def wifi_status(self) -> ConnectivityStatus: ...

    def set_wifi(self, enabled: bool) -> ConnectivityStatus: ...

    def bluetooth_status(self) -> ConnectivityStatus: ...

    def set_bluetooth(self, enabled: bool) -> ConnectivityStatus: ...


class UnavailablePCSystemBackend:
    """Used when JARVIS is not running on a PC that can control these settings."""

    name = "unavailable"

    def __init__(
        self,
        reason: str = "PC system control is only available on a Windows PC with pywin32 installed.",
    ) -> None:
        self.reason = reason

    def is_available(self) -> bool:
        return False

    def unavailable_reason(self) -> str:
        return self.reason

    def capabilities(self) -> Dict[str, str]:
        return {name: Capability.UNSUPPORTED for name in CAPABILITY_NAMES}

    def system_info(self) -> Dict[str, str]:
        return {}

    def get_volume(self) -> VolumeState:
        raise UnsupportedCapabilityError(self.reason)

    def set_volume(self, level: float) -> VolumeState:
        raise UnsupportedCapabilityError(self.reason)

    def get_mute(self) -> bool:
        raise UnsupportedCapabilityError(self.reason)

    def set_mute(self, muted: bool) -> bool:
        raise UnsupportedCapabilityError(self.reason)

    def get_brightness(self) -> BrightnessState:
        raise UnsupportedCapabilityError(self.reason)

    def set_brightness(self, level: int) -> BrightnessState:
        raise UnsupportedCapabilityError(self.reason)

    def wifi_status(self) -> ConnectivityStatus:
        raise UnsupportedCapabilityError(self.reason)

    def set_wifi(self, enabled: bool) -> ConnectivityStatus:
        raise UnsupportedCapabilityError(self.reason)

    def bluetooth_status(self) -> ConnectivityStatus:
        raise UnsupportedCapabilityError(self.reason)

    def set_bluetooth(self, enabled: bool) -> ConnectivityStatus:
        raise UnsupportedCapabilityError(self.reason)


def create_default_pc_system_backend() -> PCSystemBackend:
    """Return the Windows backend when possible, otherwise an unavailable one."""
    from .pc_system_windows import WindowsPCSystemBackend

    backend = WindowsPCSystemBackend()
    if backend.is_available():
        return backend
    return UnavailablePCSystemBackend(
        reason=(
            "PC system control needs Windows with pywin32 installed "
            f"(backend reported unavailable: {backend.unavailable_reason()})."
        )
    )


# ---------------------------------------------------------------------------
# Shared tool base
# ---------------------------------------------------------------------------
class PCSystemTool(BaseDeviceTool):
    """Base class for the Phase 3 tools: platform guard + honest error mapping."""

    platform = Platform.PC
    #: Which entry of :meth:`PCSystemBackend.capabilities` this tool uses.
    capability_name: str = "system"
    #: Error code when this PC cannot do the capability at all.
    unavailable_code: str = ErrorCode.SYSTEM_CONTROL_UNAVAILABLE
    #: Error code when the capability exists but the call did not work.
    failed_code: str = ErrorCode.EXECUTION_FAILED

    def __init__(
        self,
        backend: PCSystemBackend,
        *,
        platform_probe: Callable[[], Platform] = detect_current_platform,
    ) -> None:
        self._backend = backend
        self._platform_probe = platform_probe

    # ------------------------------------------------------------------
    @property
    def backend(self) -> PCSystemBackend:
        return self._backend

    def is_available(self) -> bool:
        """Available when the backend is.

        Per-capability gaps (no brightness control, no Bluetooth radio) are
        reported by the tool itself, precisely, instead of hiding the whole tool.
        """
        return self._backend.is_available()

    # ------------------------------------------------------------------
    def platform_result(self) -> Optional[ToolResult]:
        """Return a blocking result when the platform/backend cannot be used."""
        detected = self._platform_probe()
        if detected is not Platform.PC:
            return ToolResult.unavailable(
                f"{self.name} only runs on a PC (detected: {detected.value}).",
                error_code=ErrorCode.UNSUPPORTED_PLATFORM,
                tool_name=self.name,
                data={"platform": detected.value},
            )
        if not self._backend.is_available():
            reason = getattr(self._backend, "unavailable_reason", lambda: "")()
            return ToolResult.unavailable(
                f"PC system control is unavailable (backend: {self._backend.name}).",
                error_code=ErrorCode.DEVICE_UNAVAILABLE,
                tool_name=self.name,
                data={"backend": self._backend.name, "reason": reason},
            )
        return None

    # ------------------------------------------------------------------
    def unavailable(self, message: str, *, detail: str = "", data: Optional[Mapping[str, Any]] = None) -> ToolResult:
        """A capability this PC does not have - never a success."""
        payload: Dict[str, Any] = {"capability": self.capability_name, "state": Capability.UNSUPPORTED}
        payload.update(data or {})
        if detail:
            payload["detail"] = detail
        return ToolResult.unavailable(
            message,
            error_code=self.unavailable_code,
            tool_name=self.name,
            data=payload,
        )

    def failed(
        self,
        message: str,
        exc: Optional[BaseException] = None,
        *,
        error_code: Optional[str] = None,
        data: Optional[Mapping[str, Any]] = None,
    ) -> ToolResult:
        """The capability exists but the call did not work."""
        payload: Dict[str, Any] = {"capability": self.capability_name}
        payload.update(data or {})
        return ToolResult.failure(
            message,
            error=f"{type(exc).__name__}: {exc}"[:200] if exc is not None else None,
            error_code=error_code or self.failed_code,
            tool_name=self.name,
            data=payload,
        )

    def capability_gate(
        self,
        state: Any,
        *,
        unsupported_message: str,
        failed_message: str,
    ) -> Optional[ToolResult]:
        """Block when a backend reported the capability as unusable.

        ``UNSUPPORTED`` -> ``UNAVAILABLE`` (this PC cannot do it at all);
        ``FAILED`` -> ``FAILED`` (it tried and did not work). ``None`` means the
        tool may continue and inspect the value.
        """
        capability = getattr(state, "capability", Capability.UNKNOWN)
        detail = str(getattr(state, "detail", "") or "")
        if capability == Capability.UNSUPPORTED:
            return self.unavailable(unsupported_message, detail=detail)
        if capability == Capability.FAILED:
            return self.failed(failed_message, data={"detail": detail} if detail else None)
        return None

    # ------------------------------------------------------------------
    def call(
        self,
        operation: Callable[[], Any],
        *,
        failure_message: str,
        unavailable_message: str,
    ) -> Tuple[Any, Optional[ToolResult]]:
        """Run one backend call, converting exceptions into structured results."""
        blocked = self.platform_result()
        if blocked is not None:
            return None, blocked
        try:
            return operation(), None
        except UnsupportedCapabilityError as exc:
            return None, self.unavailable(unavailable_message, detail=str(exc))
        except PCSystemBackendError as exc:
            return None, self.failed(failure_message, exc)
        except Exception as exc:  # noqa: BLE001 - framework boundary
            return None, self.failed(failure_message, exc)


# ---------------------------------------------------------------------------
# pc.system.status
# ---------------------------------------------------------------------------
class SystemStatusTool(PCSystemTool):
    """Read the four system states JARVIS is allowed to look at.

    The payload is a closed set of keys - see :attr:`ALLOWED_STATUS_KEYS`. No
    file, path, browser history, credential, saved network secret, message or
    process information is ever collected or returned.
    """

    name = "pc.system.status"
    description = "Report this PC's volume, mute, brightness, Wi-Fi and Bluetooth status."
    risk_level = RiskLevel.SAFE
    required_permissions = (PERMISSION_DEVICE_STATUS_READ,)
    argument_schema = ArgumentSchema.empty()
    capability_name = "system"

    #: The only top level keys ``pc.system.status`` may ever return.
    ALLOWED_STATUS_KEYS = frozenset({"platform", "volume", "brightness", "wifi", "bluetooth", "capabilities"})
    #: The only keys the platform section may ever contain (no hostname, no user
    #: name, no environment).
    ALLOWED_PLATFORM_KEYS = ("os", "release", "machine")

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        blocked = self.platform_result()
        if blocked is not None:
            return blocked

        data: Dict[str, Any] = {"capabilities": self._capabilities()}
        data["platform"] = self._system_info()
        data["volume"] = self._volume()
        data["brightness"] = self._brightness()
        data["wifi"] = self._connectivity(self._backend.wifi_status)
        data["bluetooth"] = self._connectivity(self._backend.bluetooth_status)

        # Defensive: a future edit must not widen the payload silently.
        for key in set(data) - self.ALLOWED_STATUS_KEYS:  # pragma: no cover
            data.pop(key, None)

        return ToolResult.ok(self._summary(data), data=data)

    # ------------------------------------------------------------------
    def _capabilities(self) -> Dict[str, str]:
        try:
            reported = dict(self._backend.capabilities() or {})
        except PCSystemBackendError:
            return {name: Capability.UNKNOWN for name in CAPABILITY_NAMES}
        return {name: reported.get(name, Capability.UNKNOWN) for name in CAPABILITY_NAMES}

    def _system_info(self) -> Dict[str, str]:
        try:
            info = dict(self._backend.system_info() or {})
        except PCSystemBackendError:
            return {}
        # A closed projection: never pass through arbitrary backend fields.
        return {key: str(info[key]) for key in self.ALLOWED_PLATFORM_KEYS if info.get(key)}

    def _volume(self) -> Dict[str, Any]:
        try:
            state = self._backend.get_volume()
        except UnsupportedCapabilityError as exc:
            return {"level": None, "muted": None, "capability": Capability.UNSUPPORTED, "detail": str(exc)}
        except PCSystemBackendError as exc:
            return {"level": None, "muted": None, "capability": Capability.FAILED, "detail": str(exc)}
        level, error = sanitize_percentage(state.level)
        if error is not None and state.capability == Capability.SUPPORTED:
            return {"level": None, "muted": state.muted, "capability": Capability.FAILED, "detail": error}
        return {"level": level, "muted": state.muted, "capability": state.capability, "detail": state.detail}

    def _brightness(self) -> Dict[str, Any]:
        try:
            state = self._backend.get_brightness()
        except UnsupportedCapabilityError as exc:
            return {"level": None, "capability": Capability.UNSUPPORTED, "detail": str(exc)}
        except PCSystemBackendError as exc:
            return {"level": None, "capability": Capability.FAILED, "detail": str(exc)}
        level, error = sanitize_percentage(state.level)
        if error is not None and state.capability == Capability.SUPPORTED:
            return {"level": None, "capability": Capability.FAILED, "detail": error}
        return {
            "level": None if level is None else int(round(level)),
            "capability": state.capability,
            "detail": state.detail,
        }

    def _connectivity(self, operation: Callable[[], ConnectivityStatus]) -> Dict[str, Any]:
        try:
            status = operation()
        except UnsupportedCapabilityError as exc:
            return {"state": ConnectivityState.UNAVAILABLE, "detail": str(exc), "adapter": ""}
        except PCSystemBackendError as exc:
            return {"state": ConnectivityState.UNKNOWN, "detail": str(exc), "adapter": ""}
        return normalize_connectivity(status).describe()

    # ------------------------------------------------------------------
    @staticmethod
    def _summary(data: Mapping[str, Any]) -> str:
        parts = []
        volume = data.get("volume", {})
        level = volume.get("level")
        if level is None:
            parts.append(f"volume {volume.get('capability', Capability.UNKNOWN)}")
        else:
            parts.append(
                f"volume {int(round(level))}%" + (" (muted)" if volume.get("muted") else " (not muted)")
            )

        brightness = data.get("brightness", {})
        blevel = brightness.get("level")
        parts.append(
            f"brightness {int(blevel)}%"
            if blevel is not None
            else f"brightness {brightness.get('capability', Capability.UNKNOWN)}"
        )
        for label in ("wifi", "bluetooth"):
            parts.append(f"{label} {data.get(label, {}).get('state', ConnectivityState.UNKNOWN)}")
        return "; ".join(parts) + "."


def normalize_connectivity(status: ConnectivityStatus) -> ConnectivityStatus:
    """Force a backend answer into one of the four documented states."""
    if status.state in CONNECTIVITY_STATES:
        return status
    return ConnectivityStatus(
        state=ConnectivityState.UNKNOWN,
        detail=status.detail or "The backend reported an undocumented connectivity state.",
        adapter=status.adapter,
    )


# ---------------------------------------------------------------------------
# Volume / mute
# ---------------------------------------------------------------------------
class VolumeTool(PCSystemTool):
    """Shared metadata for the four audio tools."""

    capability_name = "volume"
    unavailable_code = ErrorCode.SYSTEM_CONTROL_UNAVAILABLE
    failed_code = ErrorCode.VOLUME_CONTROL_FAILED
    #: Message pair reused by the read and write tools.
    UNSUPPORTED_MESSAGE = "This PC has no controllable audio endpoint."
    FAILED_MESSAGE = "Could not reach the audio endpoint."


class GetVolumeTool(VolumeTool):
    """Read the master volume."""

    name = "pc.system.get_volume"
    description = "Read the PC's master volume percentage and mute state."
    risk_level = RiskLevel.SAFE
    required_permissions = (PERMISSION_DEVICE_STATUS_READ,)
    argument_schema = ArgumentSchema.empty()

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        state, blocked = self.call(
            self._backend.get_volume,
            failure_message="Could not read the master volume.",
            unavailable_message=self.UNSUPPORTED_MESSAGE,
        )
        if blocked is not None:
            return blocked
        state = state if isinstance(state, VolumeState) else VolumeState()
        gate = self.capability_gate(
            state,
            unsupported_message=self.UNSUPPORTED_MESSAGE,
            failed_message=self.FAILED_MESSAGE,
        )
        if gate is not None:
            return gate
        level, error = sanitize_percentage(state.level, label="volume")
        if error is not None:
            return self.failed(error, error_code=ErrorCode.INVALID_PERCENTAGE, data=state.describe())
        return ToolResult.ok(
            f"Master volume is {int(round(level))}%" + (" (muted)." if state.muted else "."),
            data=state.describe(),
        )


class SetVolumeTool(VolumeTool):
    """Set the master volume to an absolute percentage."""

    name = "pc.system.set_volume"
    description = "Set the PC's master volume to a percentage from 0 to 100."
    risk_level = RiskLevel.LOW_RISK
    required_permissions = (PERMISSION_VOLUME_CONTROL,)
    argument_schema = ArgumentSchema(
        ArgumentSpec(
            "level",
            type=int,
            min_value=PERCENT_MIN,
            max_value=PERCENT_MAX,
            description="Master volume percentage, 0 (silent) to 100 (loudest).",
        ),
    )

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        requested = int(arguments["level"])
        state, blocked = self.call(
            lambda: self._backend.set_volume(float(requested)),
            failure_message=f"Could not set the master volume to {requested}%.",
            unavailable_message=self.UNSUPPORTED_MESSAGE,
        )
        if blocked is not None:
            return blocked
        state = state if isinstance(state, VolumeState) else VolumeState()
        gate = self.capability_gate(
            state,
            unsupported_message=self.UNSUPPORTED_MESSAGE,
            failed_message=self.FAILED_MESSAGE,
        )
        if gate is not None:
            return gate
        level, error = sanitize_percentage(state.level, label="volume")
        if error is not None:
            return self.failed(error, error_code=ErrorCode.INVALID_PERCENTAGE, data=state.describe())
        payload = {"requested": requested, **state.describe()}
        if abs(level - requested) > LEVEL_VERIFICATION_TOLERANCE:
            # Honest reporting: the hardware says something else happened.
            return self.failed(
                f"Volume was requested at {requested}% but the PC reports {int(round(level))}%.",
                data=payload,
            )
        return ToolResult.ok(f"Master volume set to {int(round(level))}%.", data=payload)


class GetMuteTool(VolumeTool):
    """Read the mute state on its own."""

    name = "pc.system.get_mute"
    description = "Report whether the PC's master audio output is muted."
    risk_level = RiskLevel.SAFE
    required_permissions = (PERMISSION_DEVICE_STATUS_READ,)
    argument_schema = ArgumentSchema.empty()

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        muted, blocked = self.call(
            self._backend.get_mute,
            failure_message="Could not read the mute state.",
            unavailable_message=self.UNSUPPORTED_MESSAGE,
        )
        if blocked is not None:
            return blocked
        if muted is None:
            return self.failed("The audio backend did not report the mute state.")
        state = bool(muted)
        return ToolResult.ok(
            "Master audio is muted." if state else "Master audio is not muted.",
            data={"muted": state},
        )


class MuteTool(VolumeTool):
    """Mute or unmute the master output (``UnmuteTool`` flips the target)."""

    name = "pc.system.mute"
    description = "Mute the PC's master audio output."
    risk_level = RiskLevel.LOW_RISK
    required_permissions = (PERMISSION_VOLUME_CONTROL,)
    argument_schema = ArgumentSchema.empty()
    #: What this tool asks the backend to do.
    target_muted = True
    verb = "muted"

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        action = "mute" if self.target_muted else "unmute"
        muted, blocked = self.call(
            lambda: self._backend.set_mute(self.target_muted),
            failure_message=f"Could not {action} the master audio.",
            unavailable_message=self.UNSUPPORTED_MESSAGE,
        )
        if blocked is not None:
            return blocked
        if muted is None:
            return self.failed("The audio backend did not report the resulting mute state.")
        result_muted = bool(muted)
        if result_muted is not self.target_muted:
            return self.failed(
                f"{action.title()} was requested but the PC still reports "
                f"{'muted' if result_muted else 'unmuted'}.",
                data={"muted": result_muted, "requested": action},
            )
        return ToolResult.ok(
            f"Master audio output {self.verb}.",
            data={"muted": result_muted, "requested": action},
        )


class UnmuteTool(MuteTool):
    """Unmute the master output."""

    name = "pc.system.unmute"
    description = "Unmute the PC's master audio output."
    target_muted = False
    verb = "unmuted"


# ---------------------------------------------------------------------------
# Brightness
# ---------------------------------------------------------------------------
class BrightnessTool(PCSystemTool):
    """Shared metadata for the two display tools."""

    capability_name = "brightness"
    unavailable_code = ErrorCode.BRIGHTNESS_CONTROL_UNAVAILABLE
    failed_code = ErrorCode.BRIGHTNESS_CONTROL_FAILED
    UNSUPPORTED_MESSAGE = "This display does not support software brightness control."
    FAILED_MESSAGE = "Could not reach the display brightness control."


class GetBrightnessTool(BrightnessTool):
    """Read the display brightness."""

    name = "pc.system.get_brightness"
    description = "Read the PC display brightness percentage."
    risk_level = RiskLevel.SAFE
    required_permissions = (PERMISSION_DEVICE_STATUS_READ,)
    argument_schema = ArgumentSchema.empty()

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        state, blocked = self.call(
            self._backend.get_brightness,
            failure_message="Could not read the display brightness.",
            unavailable_message=self.UNSUPPORTED_MESSAGE,
        )
        if blocked is not None:
            return blocked
        state = state if isinstance(state, BrightnessState) else BrightnessState()
        gate = self.capability_gate(
            state,
            unsupported_message=self.UNSUPPORTED_MESSAGE,
            failed_message=self.FAILED_MESSAGE,
        )
        if gate is not None:
            return gate
        level, error = sanitize_percentage(state.level, label="brightness")
        if error is not None:
            return self.failed(error, error_code=ErrorCode.INVALID_PERCENTAGE, data=state.describe())
        return ToolResult.ok(f"Display brightness is {int(round(level))}%.", data=state.describe())


class SetBrightnessTool(BrightnessTool):
    """Set the display brightness to an absolute percentage."""

    name = "pc.system.set_brightness"
    description = "Set the PC display brightness to a percentage from 0 to 100."
    risk_level = RiskLevel.LOW_RISK
    required_permissions = (PERMISSION_DISPLAY_CONTROL,)
    argument_schema = ArgumentSchema(
        ArgumentSpec(
            "level",
            type=int,
            min_value=PERCENT_MIN,
            max_value=PERCENT_MAX,
            description="Display brightness percentage, 0 (darkest) to 100 (brightest).",
        ),
    )

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        requested = int(arguments["level"])
        state, blocked = self.call(
            lambda: self._backend.set_brightness(requested),
            failure_message=f"Could not set the display brightness to {requested}%.",
            unavailable_message=self.UNSUPPORTED_MESSAGE,
        )
        if blocked is not None:
            return blocked
        state = state if isinstance(state, BrightnessState) else BrightnessState()
        gate = self.capability_gate(
            state,
            unsupported_message=self.UNSUPPORTED_MESSAGE,
            failed_message=self.FAILED_MESSAGE,
        )
        if gate is not None:
            return gate
        level, error = sanitize_percentage(state.level, label="brightness")
        if error is not None:
            return self.failed(error, error_code=ErrorCode.INVALID_PERCENTAGE, data=state.describe())
        payload = {"requested": requested, **state.describe()}
        if abs(level - requested) > LEVEL_VERIFICATION_TOLERANCE:
            return self.failed(
                f"Brightness was requested at {requested}% but the PC reports {int(round(level))}%.",
                data=payload,
            )
        return ToolResult.ok(f"Display brightness set to {int(round(level))}%.", data=payload)


# ---------------------------------------------------------------------------
# Wi-Fi / Bluetooth
# ---------------------------------------------------------------------------
class ConnectivityTool(PCSystemTool):
    """Shared plumbing for the connectivity tools."""

    #: ``"wifi"`` or ``"bluetooth"`` - also the capability key.
    kind = "wifi"
    #: Human readable label used in messages.
    label = "Wi-Fi"

    # Implemented by the concrete Wi-Fi / Bluetooth base classes.
    def read_state(self) -> ConnectivityStatus:
        raise NotImplementedError

    def toggle_state(self, enabled: bool) -> ConnectivityStatus:
        raise NotImplementedError


class ConnectivityReadTool(ConnectivityTool):
    """Read-only connectivity report: SAFE, never confirmed, never guesses."""

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        status, blocked = self.call(
            self.read_state,
            failure_message=f"Could not read the {self.label} status.",
            unavailable_message=f"{self.label} status cannot be read on this PC.",
        )
        if blocked is not None:
            return blocked
        status = normalize_connectivity(status if isinstance(status, ConnectivityStatus) else ConnectivityStatus())
        payload = {**status.describe(), "capability": self.capability_name}
        if status.state == ConnectivityState.UNAVAILABLE:
            # "There is no way to ask" is not an answer, so it is not a success.
            return ToolResult.unavailable(
                f"{self.label} status is not available on this PC.",
                error_code=self.unavailable_code,
                tool_name=self.name,
                data=payload,
            )
        message = {
            ConnectivityState.ON: f"{self.label} is on.",
            ConnectivityState.OFF: f"{self.label} is off.",
            ConnectivityState.UNKNOWN: f"{self.label} state could not be determined on this PC.",
        }[status.state]
        return ToolResult.ok(message, data=payload)


class ConnectivityToggleTool(ConnectivityTool):
    """Enable/disable a radio.

    ``EXTERNAL_ACTION``, so the *existing* centralized confirmation policy asks
    the user first by default and can be reconfigured without touching this
    class. The change is verified afterwards: JARVIS only reports success when
    the radio really reports the requested state.
    """

    #: ``True`` for the "enable" tools.
    enabled = True

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        blocked = self.platform_result()
        if blocked is not None:
            return blocked

        wanted = bool(self.enabled)
        verb = "enable" if wanted else "disable"
        try:
            status = self.toggle_state(wanted)
        except UnsupportedCapabilityError as exc:
            return self.unavailable(f"{self.label} cannot be {verb}d on this PC.", detail=str(exc))
        except PCSystemBackendError as exc:
            return self.failed(f"Could not {verb} {self.label.lower()}.", exc, data={"requested": verb})
        except Exception as exc:  # noqa: BLE001 - framework boundary
            return self.failed(f"Could not {verb} {self.label.lower()}.", exc, data={"requested": verb})

        status = normalize_connectivity(status if isinstance(status, ConnectivityStatus) else ConnectivityStatus())
        expected = ConnectivityState.ON if wanted else ConnectivityState.OFF
        payload = {"requested": verb, **status.describe(), "capability": self.capability_name}
        if status.state == expected:
            return ToolResult.ok(f"{self.label} turned {expected}.", data=payload)
        if status.state == ConnectivityState.UNAVAILABLE:
            return self.unavailable(
                f"{self.label} was asked to turn {expected} but its state cannot be confirmed on this PC.",
                detail=status.detail,
                data=payload,
            )
        return self.failed(
            f"{self.label} was asked to turn {expected} but reports {status.state}.",
            data=payload,
        )


class WifiConnectivityTool(ConnectivityTool):
    """Wi-Fi flavoured metadata and backend calls."""

    kind = "wifi"
    capability_name = "wifi"
    label = "Wi-Fi"
    unavailable_code = ErrorCode.WIFI_CONTROL_UNAVAILABLE
    failed_code = ErrorCode.WIFI_CONTROL_FAILED

    def read_state(self) -> ConnectivityStatus:
        return self._backend.wifi_status()

    def toggle_state(self, enabled: bool) -> ConnectivityStatus:
        return self._backend.set_wifi(enabled)


class BluetoothConnectivityTool(ConnectivityTool):
    """Bluetooth flavoured metadata and backend calls."""

    kind = "bluetooth"
    capability_name = "bluetooth"
    label = "Bluetooth"
    unavailable_code = ErrorCode.BLUETOOTH_CONTROL_UNAVAILABLE
    failed_code = ErrorCode.BLUETOOTH_CONTROL_FAILED

    def read_state(self) -> ConnectivityStatus:
        return self._backend.bluetooth_status()

    def toggle_state(self, enabled: bool) -> ConnectivityStatus:
        return self._backend.set_bluetooth(enabled)


class WifiStatusTool(WifiConnectivityTool, ConnectivityReadTool):
    name = "pc.system.wifi.status"
    description = "Report whether the PC's Wi-Fi radio is on, off or unknown."
    risk_level = RiskLevel.SAFE
    required_permissions = (PERMISSION_DEVICE_STATUS_READ,)
    argument_schema = ArgumentSchema.empty()


class WifiEnableTool(WifiConnectivityTool, ConnectivityToggleTool):
    name = "pc.system.wifi.enable"
    description = "Turn the PC's Wi-Fi radio on."
    risk_level = RiskLevel.EXTERNAL_ACTION
    required_permissions = (PERMISSION_NETWORK_CONTROL,)
    argument_schema = ArgumentSchema.empty()
    enabled = True


class WifiDisableTool(WifiConnectivityTool, ConnectivityToggleTool):
    name = "pc.system.wifi.disable"
    description = "Turn the PC's Wi-Fi radio off."
    risk_level = RiskLevel.EXTERNAL_ACTION
    required_permissions = (PERMISSION_NETWORK_CONTROL,)
    argument_schema = ArgumentSchema.empty()
    enabled = False


class BluetoothStatusTool(BluetoothConnectivityTool, ConnectivityReadTool):
    name = "pc.system.bluetooth.status"
    description = "Report whether the PC's Bluetooth radio is on, off or unknown."
    risk_level = RiskLevel.SAFE
    required_permissions = (PERMISSION_DEVICE_STATUS_READ,)
    argument_schema = ArgumentSchema.empty()


class BluetoothEnableTool(BluetoothConnectivityTool, ConnectivityToggleTool):
    name = "pc.system.bluetooth.enable"
    description = "Turn the PC's Bluetooth radio on."
    risk_level = RiskLevel.EXTERNAL_ACTION
    required_permissions = (PERMISSION_BLUETOOTH_CONTROL,)
    argument_schema = ArgumentSchema.empty()
    enabled = True


class BluetoothDisableTool(BluetoothConnectivityTool, ConnectivityToggleTool):
    name = "pc.system.bluetooth.disable"
    description = "Turn the PC's Bluetooth radio off."
    risk_level = RiskLevel.EXTERNAL_ACTION
    required_permissions = (PERMISSION_BLUETOOTH_CONTROL,)
    argument_schema = ArgumentSchema.empty()
    enabled = False


#: Tool names registered by :func:`build_pc_system_tools`.
PC_SYSTEM_TOOL_NAMES: Tuple[str, ...] = (
    SystemStatusTool.name,
    GetVolumeTool.name,
    SetVolumeTool.name,
    GetMuteTool.name,
    MuteTool.name,
    UnmuteTool.name,
    GetBrightnessTool.name,
    SetBrightnessTool.name,
    WifiStatusTool.name,
    WifiEnableTool.name,
    WifiDisableTool.name,
    BluetoothStatusTool.name,
    BluetoothEnableTool.name,
    BluetoothDisableTool.name,
)


def build_pc_system_tools(
    backend: Optional[PCSystemBackend] = None,
    *,
    platform_probe: Callable[[], Platform] = detect_current_platform,
) -> Tuple[BaseDeviceTool, ...]:
    """Build the fourteen Phase 3 tools, ready for a :class:`DeviceToolRegistry`.

    Pass a fake ``backend`` in tests - no speaker, monitor, Wi-Fi adapter or
    Windows desktop is needed.
    """
    active_backend = backend if backend is not None else create_default_pc_system_backend()
    shared: Mapping[str, Any] = {"backend": active_backend, "platform_probe": platform_probe}
    return (
        SystemStatusTool(**shared),
        GetVolumeTool(**shared),
        SetVolumeTool(**shared),
        GetMuteTool(**shared),
        MuteTool(**shared),
        UnmuteTool(**shared),
        GetBrightnessTool(**shared),
        SetBrightnessTool(**shared),
        WifiStatusTool(**shared),
        WifiEnableTool(**shared),
        WifiDisableTool(**shared),
        BluetoothStatusTool(**shared),
        BluetoothEnableTool(**shared),
        BluetoothDisableTool(**shared),
    )
