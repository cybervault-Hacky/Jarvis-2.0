"""Test doubles for the Phase 3 PC system-control tests.

Nothing here touches a speaker, a monitor, a Wi-Fi adapter, a Bluetooth radio or
a Windows desktop: the fakes record calls so the suite stays deterministic and
runs on any operating system.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from jarvis_devices.pc_system import (
    BrightnessState,
    Capability,
    ConnectivityState,
    ConnectivityStatus,
    PCSystemBackendError,
    UnsupportedCapabilityError,
    VolumeState,
)


class FakePCSystemBackend:
    """A scripted :class:`~jarvis_devices.pc_system.PCSystemBackend`.

    Every capability can be individually marked unsupported, made to fail, or
    made to *not* take effect - which is how the suite proves JARVIS never
    reports a fake success.
    """

    name = "fake"

    def __init__(
        self,
        *,
        available: bool = True,
        volume: Optional[float] = 40.0,
        muted: bool = False,
        brightness: Optional[int] = 70,
        wifi: str = ConnectivityState.ON,
        bluetooth: str = ConnectivityState.UNKNOWN,
        capabilities: Optional[Dict[str, str]] = None,
        system_info: Optional[Dict[str, str]] = None,
        bluetooth_control_supported: bool = False,
    ) -> None:
        self.available = available
        self.volume_level = volume
        self.muted = muted
        self.brightness_level = brightness
        self.wifi_state = wifi
        self.bluetooth_state = bluetooth
        self.capability_map = capabilities if capabilities is not None else {
            "volume": Capability.SUPPORTED,
            "brightness": Capability.SUPPORTED,
            "wifi": Capability.SUPPORTED,
            "bluetooth": Capability.UNSUPPORTED,
        }
        self.system_info_map = system_info if system_info is not None else {
            "os": "windows",
            "release": "11",
            "machine": "AMD64",
        }
        #: Call log, in order, e.g. ``["set_volume:40.0", "get_volume"]``.
        self.calls: List[str] = []

        # --- error injection (exception instance or ``None``) ---------------
        self.volume_error: Optional[Exception] = None
        self.brightness_error: Optional[Exception] = None
        self.wifi_error: Optional[Exception] = None
        self.bluetooth_error: Optional[Exception] = None
        self.system_info_error: Optional[Exception] = None
        self.capabilities_error: Optional[Exception] = None

        # --- effectiveness flags -------------------------------------------
        #: ``False`` simulates hardware that ignores the requested level.
        self.set_volume_is_effective = True
        self.set_brightness_is_effective = True
        #: ``False`` simulates a radio that refuses to change state.
        self.wifi_toggle_is_effective = True
        self.bluetooth_toggle_is_effective = True
        #: Mirrors Windows: no supported radio switch. Flipped on to test the
        #: "a future backend supports it" path.
        self.bluetooth_control_supported = bluetooth_control_supported

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def unsupported(self, label: str) -> Exception:
        return UnsupportedCapabilityError(f"{label} is not available on this fake PC.")

    def _raise(self, error: Optional[Exception]) -> None:
        if error is not None:
            raise error

    def _volume_state(self) -> VolumeState:
        capability = self.capability_map.get("volume", Capability.UNKNOWN)
        return VolumeState(
            level=self.volume_level,
            muted=self.muted,
            capability=capability,
            detail="" if capability == Capability.SUPPORTED else "fake backend",
        )

    def _brightness_state(self) -> BrightnessState:
        capability = self.capability_map.get("brightness", Capability.UNKNOWN)
        return BrightnessState(
            level=self.brightness_level,
            capability=capability,
            detail="" if capability == Capability.SUPPORTED else "fake backend",
        )

    # ------------------------------------------------------------------
    # Backend protocol
    # ------------------------------------------------------------------
    def is_available(self) -> bool:
        return self.available

    def unavailable_reason(self) -> str:
        return "" if self.available else "the fake backend is switched off"

    def capabilities(self) -> Dict[str, str]:
        self.calls.append("capabilities")
        self._raise(self.capabilities_error)
        return dict(self.capability_map)

    def system_info(self) -> Dict[str, str]:
        self.calls.append("system_info")
        self._raise(self.system_info_error)
        return dict(self.system_info_map)

    # --- volume ---------------------------------------------------------
    def get_volume(self) -> VolumeState:
        self.calls.append("get_volume")
        self._raise(self.volume_error)
        return self._volume_state()

    def set_volume(self, level: float) -> VolumeState:
        self.calls.append(f"set_volume:{level}")
        self._raise(self.volume_error)
        if self.set_volume_is_effective:
            self.volume_level = float(level)
        return self._volume_state()

    def get_mute(self) -> bool:
        self.calls.append("get_mute")
        self._raise(self.volume_error)
        return self.muted

    def set_mute(self, muted: bool) -> bool:
        self.calls.append(f"set_mute:{muted}")
        self._raise(self.volume_error)
        if self.set_volume_is_effective:
            self.muted = bool(muted)
        return self.muted

    # --- brightness -----------------------------------------------------
    def get_brightness(self) -> BrightnessState:
        self.calls.append("get_brightness")
        self._raise(self.brightness_error)
        return self._brightness_state()

    def set_brightness(self, level: int) -> BrightnessState:
        self.calls.append(f"set_brightness:{level}")
        self._raise(self.brightness_error)
        if self.set_brightness_is_effective:
            self.brightness_level = int(level)
        return self._brightness_state()

    # --- connectivity ---------------------------------------------------
    def wifi_status(self) -> ConnectivityStatus:
        self.calls.append("wifi_status")
        self._raise(self.wifi_error)
        return ConnectivityStatus(
            state=self.wifi_state,
            detail=f"fake Wi-Fi state: {self.wifi_state}",
        )

    def set_wifi(self, enabled: bool) -> ConnectivityStatus:
        self.calls.append(f"set_wifi:{enabled}")
        self._raise(self.wifi_error)
        if self.wifi_toggle_is_effective:
            self.wifi_state = ConnectivityState.ON if enabled else ConnectivityState.OFF
        return self.wifi_status()

    def bluetooth_status(self) -> ConnectivityStatus:
        self.calls.append("bluetooth_status")
        self._raise(self.bluetooth_error)
        return ConnectivityStatus(
            state=self.bluetooth_state,
            detail=f"fake Bluetooth state: {self.bluetooth_state}",
        )

    def set_bluetooth(self, enabled: bool) -> ConnectivityStatus:
        self.calls.append(f"set_bluetooth:{enabled}")
        self._raise(self.bluetooth_error)
        if not self.bluetooth_control_supported:
            raise UnsupportedCapabilityError(
                "This fake PC has no supported Bluetooth radio switch, exactly like Windows."
            )
        if self.bluetooth_toggle_is_effective:
            self.bluetooth_state = ConnectivityState.ON if enabled else ConnectivityState.OFF
        return self.bluetooth_status()


# ---------------------------------------------------------------------------
# Fake Core Audio (pycaw) objects for the Windows backend
# ---------------------------------------------------------------------------
class FakeEndpointVolume:
    """Stands in for ``IAudioEndpointVolume``."""

    _iid_ = "fake-iid"

    def __init__(self, scalar: float = 0.4, muted: bool = False) -> None:
        self.scalar = scalar
        self.muted = muted
        self.set_calls: List[Any] = []
        self.mute_calls: List[Any] = []
        self.raise_on_get = False
        self.raise_on_set = False

    def GetMasterVolumeLevelScalar(self) -> float:
        if self.raise_on_get:
            raise RuntimeError("the audio service refused")
        return self.scalar

    def SetMasterVolumeLevelScalar(self, level, context) -> None:
        self.set_calls.append((level, context))
        if self.raise_on_set:
            raise RuntimeError("the audio service refused")
        self.scalar = float(level)

    def GetMute(self) -> bool:
        if self.raise_on_get:
            raise RuntimeError("the audio service refused")
        return self.muted

    def SetMute(self, value, context) -> None:
        self.mute_calls.append((value, context))
        if self.raise_on_set:
            raise RuntimeError("the audio service refused")
        self.muted = bool(value)


class FakeSpeakers:
    """Stands in for the ``IMMDevice`` returned by ``AudioUtilities.GetSpeakers``."""

    def __init__(self, volume: FakeEndpointVolume) -> None:
        self._volume = volume
        self.activate_calls: List[Any] = []

    def Activate(self, iid, clsctx, params):
        self.activate_calls.append((iid, clsctx, params))
        return self

    def QueryInterface(self, interface):
        return self._volume


class FakeAudioUtilities:
    """Stands in for ``pycaw.utils.AudioUtilities``."""

    def __init__(self, volume: FakeEndpointVolume) -> None:
        self._volume = volume
        self.speakers = FakeSpeakers(volume)
        self.calls = 0
        self.raise_on_get_speakers = False

    def GetSpeakers(self):
        self.calls += 1
        if self.raise_on_get_speakers:
            raise RuntimeError("no render endpoint")
        return self.speakers


class FakeEndpointVolumeClass:
    """Stands in for the ``IAudioEndpointVolume`` *class* (only ``_iid_`` is used)."""

    _iid_ = "fake-iid"


# ---------------------------------------------------------------------------
# Fake WMI for the Windows backend
# ---------------------------------------------------------------------------
class FakeWmiRow:
    """A WMI result object with attributes and optional Enable/Disable methods."""

    def __init__(self, **fields: Any) -> None:
        self.__dict__.update(fields)
        self.enabled_calls = 0
        self.disabled_calls = 0

    def Enable(self) -> None:
        self.enabled_calls += 1
        self.NetEnabled = True
        self.State = "Enabled"

    def Disable(self) -> None:
        self.disabled_calls += 1
        self.NetEnabled = False
        self.State = "Disabled"

    def WmiSetBrightness(self, timeout: int, brightness: int) -> None:
        self.wmi_calls = getattr(self, "wmi_calls", []) + [(timeout, brightness)]


class FakeWmiService:
    """Answers fixed WQL with scripted rows."""

    def __init__(self, namespace: str, answers: Dict[str, List[Any]], *, errors: Optional[Dict[str, Exception]] = None) -> None:
        self.namespace = namespace
        self.answers = answers
        self.errors = errors or {}
        self.queries: List[str] = []
        self.raise_on_any: Optional[Exception] = None

    def ExecQuery(self, query: str):
        self.queries.append(query)
        if self.raise_on_any is not None:
            raise self.raise_on_any
        if query in self.errors:
            raise self.errors[query]
        if query not in self.answers:
            raise RuntimeError(f"unexpected WQL in test: {query}")
        return list(self.answers[query])


class FakeWmiFactory:
    """Stands in for :func:`jarvis_devices.pc_system_windows.default_wmi_connect`."""

    def __init__(self, services: Dict[str, FakeWmiService]) -> None:
        self.services = services
        self.opened: List[str] = []
        self.raise_for: Dict[str, Exception] = {}

    def __call__(self, namespace: str):
        self.opened.append(namespace)
        if namespace in self.raise_for:
            raise self.raise_for[namespace]
        if namespace not in self.services:
            raise PCSystemBackendError(f"no fake WMI service for {namespace!r}")
        return self.services[namespace]


def windows_like_wmi(
    *,
    brightness: Optional[int] = 65,
    wifi_state: str = "Enabled",
    wifi_adapter_enabled: bool = True,
    bluetooth_rows: Optional[List[Any]] = None,
    msft_rows: Optional[List[Any]] = None,
) -> Dict[str, FakeWmiService]:
    """A WMI world that looks like a normal Windows 11 laptop."""
    from jarvis_devices.pc_system_windows import (
        BLUETOOTH_ADAPTER_QUERY,
        BRIGHTNESS_FALLBACK_QUERY,
        BRIGHTNESS_METHODS_QUERY,
        BRIGHTNESS_READ_QUERY,
        WIFI_ADAPTER_QUERY,
        WIFI_STATE_QUERY,
    )

    brightness_rows = [] if brightness is None else [FakeWmiRow(CurrentBrightness=brightness)]
    method_rows = [] if brightness is None else [FakeWmiRow(CurrentBrightness=brightness)]
    return {
        "wmi": FakeWmiService(
            "wmi",
            {
                BRIGHTNESS_READ_QUERY: brightness_rows,
                BRIGHTNESS_METHODS_QUERY: method_rows,
            },
        ),
        "cimv2": FakeWmiService(
            "cimv2",
            {
                BRIGHTNESS_FALLBACK_QUERY: [],
                WIFI_ADAPTER_QUERY: [
                    FakeWmiRow(Name="Intel(R) Wi-Fi 6", NetEnabled=wifi_adapter_enabled, NetConnectionStatus=2)
                ],
                BLUETOOTH_ADAPTER_QUERY: (
                    [FakeWmiRow(Name="Intel(R) Wireless Bluetooth(R)", Status="OK")]
                    if bluetooth_rows is None
                    else bluetooth_rows
                ),
            },
        ),
        "StandardCimv2": FakeWmiService(
            "StandardCimv2",
            {
                WIFI_STATE_QUERY: (
                    [FakeWmiRow(Name="Wi-Fi", InterfaceDescription="Intel(R) Wi-Fi 6", State=wifi_state, PhysicalMediaType="Native 802.11")]
                    if msft_rows is None
                    else msft_rows
                ),
            },
        ),
    }
