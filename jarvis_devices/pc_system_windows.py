"""Windows implementation of the PC system backend (Phase 3).

Everything that touches Windows lives in this one module, behind the
:class:`~jarvis_devices.pc_system.PCSystemBackend` seam, so the tools in
:mod:`jarvis_devices.pc_system` stay platform agnostic and unit testable.

Mechanisms used
---------------
* **Master volume / mute** - the Core Audio ``IAudioEndpointVolume`` COM
  interface through ``pycaw`` (a small pure-Python wrapper around comtypes).
  ``pywin32`` alone cannot reach this interface: it is a plain COM class with no
  registered type library, so there is no ``win32com`` binding for it, and the
  only alternatives are hand written ``ctypes`` vtables (which this project's
  own security tests forbid) or the legacy per application WaveOut API, which
  does not control the master endpoint on modern Windows. ``pycaw`` is therefore
  the smallest honest way to read and set an *absolute* volume. It is imported
  defensively: when it is missing, volume reports ``UNAVAILABLE`` instead of
  crashing, and everything else still works.
* **Brightness** - ``pywin32`` WMI: ``root\\wmi`` ->
  ``WmiMonitorBrightness`` / ``WmiMonitorBrightnessMethods.WmiSetBrightness``,
  with a ``Win32_VideoController.CurrentBrightness`` fallback. Desktop monitors
  without DDC/CI support simply report ``UNSUPPORTED``.
* **Wi-Fi** - ``pywin32`` WMI: ``root\\StandardCimv2`` -> ``MSFT_NetAdapter``
  for the state, ``root\\cimv2`` -> ``Win32_NetworkAdapter.Enable()`` /
  ``.Disable()`` for the toggle. No ``netsh``, no PowerShell, no service calls.
* **Bluetooth** - *status only*, and even that is best effort. Windows exposes no
  supported programmatic switch for the Bluetooth radio, so toggling raises
  :class:`~jarvis_devices.pc_system.UnsupportedCapabilityError` and the tools
  answer ``UNAVAILABLE``. JARVIS does not fake it with UI automation.

Security properties
-------------------
* Every WMI query in this file is a **module level constant**. No query is ever
  built from model input, so WQL injection is structurally impossible.
* WMI namespaces are checked against :data:`WMI_NAMESPACES` before a connection
  is opened; an unknown namespace is refused.
* There is no ``subprocess``, no shell, no ``eval``/``exec``, no ``ctypes`` and
  no ``os`` import in this module, and no path to ``Jarvis_window_CTRL``'s legacy
  shell based ``open()``.
* Nothing here reads files, browser history, stored credentials, saved network
  profiles or personal documents.
"""

from __future__ import annotations

import platform as os_platform
from typing import Any, Callable, Dict, List, Optional

from .enums import Platform
from .pc_system import (
    BrightnessState,
    Capability,
    ConnectivityState,
    ConnectivityStatus,
    PCSystemBackendError,
    UnsupportedCapabilityError,
    VolumeState,
)
from .platform import detect_current_platform

try:  # pragma: no cover - only importable on Windows
    import pythoncom
except ImportError:  # pragma: no cover - non-Windows development machines
    pythoncom = None  # type: ignore[assignment]

try:  # pragma: no cover - only importable on Windows
    import win32com.client
except ImportError:  # pragma: no cover - non-Windows development machines
    win32com = None  # type: ignore[assignment]

try:  # pragma: no cover - optional dependency (volume only)
    from comtypes import CLSCTX_INPROC_SERVER
except ImportError:  # pragma: no cover - comtypes is Windows only
    CLSCTX_INPROC_SERVER = None  # type: ignore[assignment]

try:  # pragma: no cover - optional dependency (volume only)
    from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume
except ImportError:  # pragma: no cover - pycaw/comtypes are Windows only
    AudioUtilities = None  # type: ignore[assignment]
    IAudioEndpointVolume = None  # type: ignore[assignment]

__all__ = ["WindowsPCSystemBackend", "WMI_NAMESPACES", "default_wmi_connect"]

#: The only WMI namespaces this backend will ever open.
WMI_NAMESPACES = ("cimv2", "wmi", "StandardCimv2")

WMI_MONIKER_PREFIX = "winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\"

# --- Fixed WQL. Never interpolated, never model supplied. ---------------------
BRIGHTNESS_READ_QUERY = "SELECT CurrentBrightness FROM WmiMonitorBrightness"
BRIGHTNESS_METHODS_QUERY = "SELECT * FROM WmiMonitorBrightnessMethods"
BRIGHTNESS_FALLBACK_QUERY = "SELECT CurrentBrightness FROM Win32_VideoController"
WIFI_STATE_QUERY = (
    "SELECT Name, InterfaceDescription, State, PhysicalMediaType FROM MSFT_NetAdapter "
    "WHERE PhysicalMediaType LIKE '%802.11%'"
)
WIFI_ADAPTER_QUERY = (
    "SELECT Name, NetEnabled, NetConnectionStatus FROM Win32_NetworkAdapter "
    "WHERE PhysicalAdapter = True AND ("
    "Name LIKE '%Wi-Fi%' OR Name LIKE '%Wireless%' OR Name LIKE '%802.11%' OR Name LIKE '%WLAN%')"
)
BLUETOOTH_ADAPTER_QUERY = "SELECT Name, Status FROM Win32_PnPEntity WHERE PNPClass = 'Bluetooth'"

#: ``MSFT_NetAdapter.State`` values that mean "the radio is on".
WIFI_STATE_ON = frozenset({"enabled", "connected", "connecting", "disconnected"})
#: ... and the one that means "the radio is off".
WIFI_STATE_OFF = frozenset({"disabled"})

BLUETOOTH_UNAVAILABLE_REASON = (
    "Windows does not expose a supported programmatic Bluetooth radio switch, so JARVIS will not "
    "toggle it. (It refuses to use UI automation or shell commands to fake this.)"
)


def default_wmi_connect(namespace: str) -> Any:
    """Open one WMI namespace through ``pywin32``.

    ``namespace`` must be one of :data:`WMI_NAMESPACES`; anything else is
    refused, which keeps the moniker a constant in practice as well as on paper.
    """
    if namespace not in WMI_NAMESPACES:
        raise PCSystemBackendError(f"Refusing to open the WMI namespace {namespace!r}.")
    if win32com is None:
        raise PCSystemBackendError("pywin32 is not installed, so WMI cannot be reached.")
    if pythoncom is not None:
        try:
            pythoncom.CoInitialize()
        except Exception:  # noqa: BLE001 - already initialised in this thread is fine
            pass
    try:
        return win32com.client.GetObject(WMI_MONIKER_PREFIX + namespace)
    except Exception as exc:  # noqa: BLE001 - pywintypes.com_error and friends
        raise PCSystemBackendError(f"Could not open the WMI namespace {namespace!r}: {exc}") from exc


class WindowsPCSystemBackend:
    """PC system backend backed by Core Audio (pycaw) and WMI (pywin32).

    Both stacks are injectable, so the behaviour is testable without a speaker,
    a monitor, a Wi-Fi adapter or a Windows desktop.
    """

    name = "windows"

    def __init__(
        self,
        *,
        audio_utilities: Any = None,
        endpoint_volume: Any = None,
        clsctx: Any = None,
        wmi_connect: Optional[Callable[[str], Any]] = None,
        platform_probe: Callable[[], Platform] = detect_current_platform,
    ) -> None:
        self._audio = audio_utilities if audio_utilities is not None else AudioUtilities
        self._endpoint = endpoint_volume if endpoint_volume is not None else IAudioEndpointVolume
        self._clsctx = clsctx if clsctx is not None else CLSCTX_INPROC_SERVER
        self._wmi_connect = wmi_connect if wmi_connect is not None else default_wmi_connect
        self._platform_probe = platform_probe
        self._volume_interface: Any = None
        self._services: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Availability
    # ------------------------------------------------------------------
    def is_available(self) -> bool:
        return self.unavailable_reason() == ""

    def unavailable_reason(self) -> str:
        """Explain why this backend cannot be used (empty string when it can)."""
        if self._platform_probe() is not Platform.PC:
            return f"running on {self._platform_probe().value}, not on a PC"
        if not self._has_audio_stack() and not self._has_wmi_transport():
            return "missing pywin32 (and pycaw for volume)"
        return ""

    def _has_audio_stack(self) -> bool:
        return self._audio is not None and self._endpoint is not None and self._clsctx is not None

    def _has_wmi_transport(self) -> bool:
        """``True`` when something can reach WMI (pywin32, or an injected stub)."""
        return win32com is not None or self._wmi_connect is not default_wmi_connect

    def capabilities(self) -> Dict[str, str]:
        """What this machine can do at all, before any call is attempted.

        This is a *static* pre-check (is the API reachable?); whether the
        hardware really supports a capability is answered per call, as
        ``UNSUPPORTED``.
        """
        audio = Capability.SUPPORTED if self._has_audio_stack() else Capability.UNSUPPORTED
        wmi = Capability.SUPPORTED if self._has_wmi_transport() else Capability.UNSUPPORTED
        return {
            "volume": audio,
            "brightness": wmi,
            "wifi": wmi,
            # No supported radio switch exists; the tools answer UNAVAILABLE.
            "bluetooth": Capability.UNSUPPORTED,
        }

    def system_info(self) -> Dict[str, str]:
        """Operating system facts only - no hostname, no user, no environment."""
        return {
            "os": str(os_platform.system() or "").lower(),
            "release": str(os_platform.release() or ""),
            "machine": str(os_platform.machine() or ""),
        }

    # ------------------------------------------------------------------
    # Volume / mute (Core Audio)
    # ------------------------------------------------------------------
    def _endpoint_volume_interface(self) -> Any:
        if not self._has_audio_stack():
            raise UnsupportedCapabilityError(
                "pycaw/comtypes are not available, so the master volume cannot be controlled."
            )
        if self._volume_interface is not None:
            return self._volume_interface
        if pythoncom is not None:
            try:
                pythoncom.CoInitialize()
            except Exception:  # noqa: BLE001 - already initialised is fine
                pass
        try:
            speakers = self._audio.GetSpeakers()
            activated = speakers.Activate(self._endpoint._iid_, self._clsctx, None)
            self._volume_interface = activated.QueryInterface(self._endpoint)
        except UnsupportedCapabilityError:
            raise
        except Exception as exc:  # noqa: BLE001 - comtypes COM errors
            raise PCSystemBackendError(f"Could not open the audio endpoint: {exc}") from exc
        return self._volume_interface

    def get_volume(self) -> VolumeState:
        volume = self._endpoint_volume_interface()
        try:
            level = float(volume.GetMasterVolumeLevelScalar()) * 100.0
            muted = bool(volume.GetMute())
        except Exception as exc:  # noqa: BLE001 - COM boundary
            raise PCSystemBackendError(f"Could not read the master volume: {exc}") from exc
        return VolumeState(level=round(level, 1), muted=muted, capability=Capability.SUPPORTED)

    def set_volume(self, level: float) -> VolumeState:
        wanted = float(level)
        if not 0.0 <= wanted <= 100.0 or wanted != wanted:  # NaN never passes
            raise PCSystemBackendError(f"Volume must be between 0 and 100, got {level!r}.")
        volume = self._endpoint_volume_interface()
        try:
            volume.SetMasterVolumeLevelScalar(wanted / 100.0, None)
        except Exception as exc:  # noqa: BLE001 - COM boundary
            raise PCSystemBackendError(f"Could not set the master volume: {exc}") from exc
        return self.get_volume()

    def get_mute(self) -> bool:
        volume = self._endpoint_volume_interface()
        try:
            return bool(volume.GetMute())
        except Exception as exc:  # noqa: BLE001 - COM boundary
            raise PCSystemBackendError(f"Could not read the mute state: {exc}") from exc

    def set_mute(self, muted: bool) -> bool:
        volume = self._endpoint_volume_interface()
        try:
            volume.SetMute(1 if muted else 0, None)
            return bool(volume.GetMute())
        except Exception as exc:  # noqa: BLE001 - COM boundary
            raise PCSystemBackendError(f"Could not change the mute state: {exc}") from exc

    # ------------------------------------------------------------------
    # Brightness (WMI)
    # ------------------------------------------------------------------
    def get_brightness(self) -> BrightnessState:
        level = self._read_brightness()
        if level is None:
            raise UnsupportedCapabilityError(
                "This display does not expose a software brightness control (no WmiMonitorBrightness)."
            )
        return BrightnessState(level=int(level), capability=Capability.SUPPORTED)

    def set_brightness(self, level: int) -> BrightnessState:
        wanted = int(level)
        if not 0 <= wanted <= 100:
            raise PCSystemBackendError(f"Brightness must be between 0 and 100, got {level!r}.")
        service = self._service("wmi")
        methods = self._query(service, BRIGHTNESS_METHODS_QUERY)
        if not methods:
            raise UnsupportedCapabilityError(
                "This display does not expose a software brightness control (no WmiMonitorBrightnessMethods)."
            )
        try:
            # WmiSetBrightness(Timeout, Brightness) - fixed WMI method signature.
            methods[0].WmiSetBrightness(1, wanted)
        except Exception as exc:  # noqa: BLE001 - pywintypes.com_error and friends
            raise PCSystemBackendError(f"Could not set the display brightness: {exc}") from exc
        return self.get_brightness()

    def _read_brightness(self) -> Optional[int]:
        service = self._service("wmi")
        rows = self._query(service, BRIGHTNESS_READ_QUERY)
        if rows:
            value = self._int(getattr(rows[0], "CurrentBrightness", None))
            if value is not None:
                return value
        fallback = self._service("cimv2")
        for row in self._query(fallback, BRIGHTNESS_FALLBACK_QUERY):
            value = self._int(getattr(row, "CurrentBrightness", None))
            if value is not None:
                return value
        return None

    # ------------------------------------------------------------------
    # Wi-Fi (WMI)
    # ------------------------------------------------------------------
    def wifi_status(self) -> ConnectivityStatus:
        status = self._wifi_status_from_msft()
        if status is not None:
            return status
        return self._wifi_status_from_adapter()

    def set_wifi(self, enabled: bool) -> ConnectivityStatus:
        service = self._service("cimv2")
        adapters = self._query(service, WIFI_ADAPTER_QUERY)
        if not adapters:
            raise UnsupportedCapabilityError("No Wi-Fi adapter was found on this PC.")
        try:
            # Classic WMI methods on Win32_NetworkAdapter - no shell involved.
            if enabled:
                adapters[0].Enable()
            else:
                adapters[0].Disable()
        except Exception as exc:  # noqa: BLE001 - access denied, driver refusal, ...
            raise PCSystemBackendError(
                f"Windows refused to {'enable' if enabled else 'disable'} the Wi-Fi adapter: {exc}"
            ) from exc
        # Report what the radio actually does now, not what was requested.
        return self.wifi_status()

    def _wifi_status_from_msft(self) -> Optional[ConnectivityStatus]:
        try:
            service = self._service("StandardCimv2")
        except PCSystemBackendError:
            return None
        try:
            rows = self._query(service, WIFI_STATE_QUERY)
        except PCSystemBackendError:
            return None
        if not rows:
            return None
        raw = str(getattr(rows[0], "State", "") or "").strip().lower()
        if raw in WIFI_STATE_ON:
            state = ConnectivityState.ON
        elif raw in WIFI_STATE_OFF:
            state = ConnectivityState.OFF
        else:
            state = ConnectivityState.UNKNOWN
        return ConnectivityStatus(state=state, detail=f"MSFT_NetAdapter state: {raw or 'not reported'}")

    def _wifi_status_from_adapter(self) -> ConnectivityStatus:
        service = self._service("cimv2")
        rows = self._query(service, WIFI_ADAPTER_QUERY)
        if not rows:
            return ConnectivityStatus(
                state=ConnectivityState.UNAVAILABLE,
                detail="No Wi-Fi adapter was found on this PC.",
            )
        enabled = getattr(rows[0], "NetEnabled", None)
        if enabled is None:
            return ConnectivityStatus(
                state=ConnectivityState.UNKNOWN,
                detail="A Wi-Fi adapter is present but its state was not reported.",
            )
        return ConnectivityStatus(
            state=ConnectivityState.ON if bool(enabled) else ConnectivityState.OFF,
            detail="Win32_NetworkAdapter.NetEnabled: " + ("true" if bool(enabled) else "false"),
        )

    # ------------------------------------------------------------------
    # Bluetooth (status only - documented limitation)
    # ------------------------------------------------------------------
    def bluetooth_status(self) -> ConnectivityStatus:
        try:
            service = self._service("cimv2")
            rows = self._query(service, BLUETOOTH_ADAPTER_QUERY)
        except PCSystemBackendError as exc:
            return ConnectivityStatus(state=ConnectivityState.UNAVAILABLE, detail=str(exc))
        if not rows:
            return ConnectivityStatus(
                state=ConnectivityState.UNAVAILABLE,
                detail="No Bluetooth adapter is present on this PC.",
            )
        return ConnectivityStatus(
            state=ConnectivityState.UNKNOWN,
            detail=(
                "A Bluetooth adapter is present, but Windows does not expose its on/off state "
                "through a supported API."
            ),
        )

    def set_bluetooth(self, enabled: bool) -> ConnectivityStatus:
        raise UnsupportedCapabilityError(BLUETOOTH_UNAVAILABLE_REASON)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _service(self, namespace: str) -> Any:
        if namespace in self._services:
            return self._services[namespace]
        service = self._wmi_connect(namespace)
        self._services[namespace] = service
        return service

    @staticmethod
    def _query(service: Any, query: str) -> List[Any]:
        """Run one *fixed* WQL query and return its rows as a list."""
        try:
            return list(service.ExecQuery(query))
        except PCSystemBackendError:
            raise
        except Exception as exc:  # noqa: BLE001 - pywintypes.com_error and friends
            raise PCSystemBackendError(f"WMI query failed: {exc}") from exc

    @staticmethod
    def _int(value: Any) -> Optional[int]:
        try:
            number = int(value)
        except (TypeError, ValueError):
            return None
        return number if 0 <= number <= 100 else None
