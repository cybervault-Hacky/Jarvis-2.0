"""Phase 3 Windows system backend tests.

The Core Audio (pycaw) and WMI (pywin32) objects are injected, so these tests
exercise the real :class:`WindowsPCSystemBackend` code paths on any operating
system, without a speaker, a monitor, a Wi-Fi adapter or a Windows desktop.
"""

from __future__ import annotations

import unittest

from jarvis_devices.enums import Platform
from jarvis_devices.pc_system import (
    Capability,
    ConnectivityState,
    PCSystemBackendError,
    UnsupportedCapabilityError,
)
from jarvis_devices.pc_system_windows import (
    BLUETOOTH_ADAPTER_QUERY,
    BRIGHTNESS_FALLBACK_QUERY,
    BRIGHTNESS_METHODS_QUERY,
    BRIGHTNESS_READ_QUERY,
    WIFI_ADAPTER_QUERY,
    WIFI_STATE_QUERY,
    WMI_NAMESPACES,
    WindowsPCSystemBackend,
    default_wmi_connect,
)

try:  # imported as part of the ``tests`` package (pytest / discover -t .)
    from .pc_system_support import (
        FakeAudioUtilities,
        FakeEndpointVolume,
        FakeEndpointVolumeClass,
        FakeWmiFactory,
        FakeWmiRow,
        FakeWmiService,
        windows_like_wmi,
    )
except ImportError:  # ``python -m unittest discover -s tests``
    from pc_system_support import (
        FakeAudioUtilities,
        FakeEndpointVolume,
        FakeEndpointVolumeClass,
        FakeWmiFactory,
        FakeWmiRow,
        FakeWmiService,
        windows_like_wmi,
    )

ALL_QUERIES = frozenset(
    {
        BRIGHTNESS_READ_QUERY,
        BRIGHTNESS_METHODS_QUERY,
        BRIGHTNESS_FALLBACK_QUERY,
        WIFI_STATE_QUERY,
        WIFI_ADAPTER_QUERY,
        BLUETOOTH_ADAPTER_QUERY,
    }
)


def backend(
    *,
    volume=None,
    audio=None,
    wmi=None,
    platform=Platform.PC,
):
    """Build a Windows backend on top of fakes."""
    endpoint = volume if volume is not None else FakeEndpointVolume()
    return WindowsPCSystemBackend(
        audio_utilities=audio if audio is not None else FakeAudioUtilities(endpoint),
        endpoint_volume=FakeEndpointVolumeClass,
        clsctx=1,
        wmi_connect=wmi if wmi is not None else FakeWmiFactory(windows_like_wmi()),
        platform_probe=lambda: platform,
    ), endpoint


class AvailabilityTests(unittest.TestCase):
    def test_unavailable_off_pc(self) -> None:
        built, _ = backend(platform=Platform.ANDROID)
        self.assertFalse(built.is_available())
        self.assertIn("not on a PC", built.unavailable_reason())

    def test_available_on_pc_with_both_stacks(self) -> None:
        built, _ = backend()
        self.assertTrue(built.is_available())
        self.assertEqual(built.unavailable_reason(), "")

    def test_capabilities_are_static_and_bluetooth_is_never_supported(self) -> None:
        built, _ = backend()
        capabilities = built.capabilities()
        self.assertEqual(
            capabilities,
            {
                "volume": Capability.SUPPORTED,
                "brightness": Capability.SUPPORTED,
                "wifi": Capability.SUPPORTED,
                "bluetooth": Capability.UNSUPPORTED,
            },
        )

    def test_capabilities_without_pycaw(self) -> None:
        built = WindowsPCSystemBackend(
            audio_utilities=None,
            endpoint_volume=None,
            clsctx=None,
            wmi_connect=FakeWmiFactory(windows_like_wmi()),
            platform_probe=lambda: Platform.PC,
        )
        self.assertEqual(built.capabilities()["volume"], Capability.UNSUPPORTED)
        self.assertEqual(built.capabilities()["brightness"], Capability.SUPPORTED)

    def test_system_info_only_reports_os_facts(self) -> None:
        built, _ = backend()
        info = built.system_info()
        self.assertEqual(set(info), {"os", "release", "machine"})


class VolumeTests(unittest.TestCase):
    def test_reads_the_master_volume_as_a_percentage(self) -> None:
        built, endpoint = backend(volume=FakeEndpointVolume(scalar=0.62, muted=True))
        state = built.get_volume()
        self.assertEqual(state.level, 62.0)
        self.assertTrue(state.muted)
        self.assertEqual(state.capability, Capability.SUPPORTED)

    def test_activates_the_endpoint_once_and_reuses_it(self) -> None:
        built, _ = backend()
        built.get_volume()
        built.get_volume()
        self.assertEqual(built._audio.calls, 1)

    def test_set_volume_converts_to_a_scalar_and_reads_back(self) -> None:
        built, endpoint = backend(volume=FakeEndpointVolume(scalar=0.4))
        state = built.set_volume(15)
        self.assertEqual(endpoint.set_calls, [(0.15, None)])
        self.assertEqual(state.level, 15.0)

    def test_rejects_out_of_range_and_nan_levels(self) -> None:
        built, endpoint = backend()
        for level in (-1, 101, float("nan")):
            with self.subTest(level=level):
                with self.assertRaises(PCSystemBackendError):
                    built.set_volume(level)
        self.assertEqual(endpoint.set_calls, [])

    def test_mute_round_trip(self) -> None:
        built, endpoint = backend(volume=FakeEndpointVolume(muted=False))
        self.assertFalse(built.get_mute())
        self.assertTrue(built.set_mute(True))
        self.assertEqual(endpoint.mute_calls, [(1, None)])
        self.assertFalse(built.set_mute(False))
        self.assertEqual(endpoint.mute_calls, [(1, None), (0, None)])

    def test_a_com_failure_is_reported_not_swallowed(self) -> None:
        built, endpoint = backend(volume=FakeEndpointVolume())
        endpoint.raise_on_get = True
        with self.assertRaises(PCSystemBackendError):
            built.get_volume()
        endpoint.raise_on_get = False
        endpoint.raise_on_set = True
        with self.assertRaises(PCSystemBackendError):
            built.set_volume(50)

    def test_without_pycaw_volume_is_unsupported_not_faked(self) -> None:
        built = WindowsPCSystemBackend(
            audio_utilities=None,
            endpoint_volume=None,
            clsctx=None,
            wmi_connect=FakeWmiFactory(windows_like_wmi()),
            platform_probe=lambda: Platform.PC,
        )
        for call in (built.get_volume, built.get_mute):
            with self.subTest(call=call.__name__):
                with self.assertRaises(UnsupportedCapabilityError):
                    call()
        with self.assertRaises(UnsupportedCapabilityError):
            built.set_volume(50)

    def test_a_missing_render_endpoint_is_a_backend_error(self) -> None:
        audio = FakeAudioUtilities(FakeEndpointVolume())
        audio.raise_on_get_speakers = True
        built, _ = backend(audio=audio)
        with self.assertRaises(PCSystemBackendError):
            built.get_volume()


class BrightnessTests(unittest.TestCase):
    def test_reads_wmi_monitor_brightness(self) -> None:
        built, _ = backend(wmi=FakeWmiFactory(windows_like_wmi(brightness=65)))
        state = built.get_brightness()
        self.assertEqual(state.level, 65)
        self.assertEqual(state.capability, Capability.SUPPORTED)

    def test_falls_back_to_the_video_controller(self) -> None:
        services = windows_like_wmi(brightness=None)
        services["cimv2"].answers[BRIGHTNESS_FALLBACK_QUERY] = [FakeWmiRow(CurrentBrightness=45)]
        built, _ = backend(wmi=FakeWmiFactory(services))
        self.assertEqual(built.get_brightness().level, 45)

    def test_no_brightness_control_is_unsupported(self) -> None:
        built, _ = backend(wmi=FakeWmiFactory(windows_like_wmi(brightness=None)))
        with self.assertRaises(UnsupportedCapabilityError):
            built.get_brightness()

    def test_set_brightness_uses_the_fixed_wmi_method_signature(self) -> None:
        services = windows_like_wmi(brightness=65)
        built, _ = backend(wmi=FakeWmiFactory(services))
        method_row = services["wmi"].answers[BRIGHTNESS_METHODS_QUERY][0]
        state = built.set_brightness(30)
        self.assertEqual(method_row.wmi_calls, [(1, 30)])
        # The level is re-read afterwards, so a lie cannot be reported.
        self.assertEqual(state.level, 65)

    def test_set_brightness_without_the_method_is_unsupported(self) -> None:
        built, _ = backend(wmi=FakeWmiFactory(windows_like_wmi(brightness=None)))
        with self.assertRaises(UnsupportedCapabilityError):
            built.set_brightness(30)

    def test_out_of_range_levels_are_refused(self) -> None:
        built, _ = backend()
        for level in (-1, 101):
            with self.subTest(level=level):
                with self.assertRaises(PCSystemBackendError):
                    built.set_brightness(level)

    def test_a_driver_value_outside_the_range_is_ignored(self) -> None:
        services = windows_like_wmi()
        services["wmi"].answers[BRIGHTNESS_READ_QUERY] = [FakeWmiRow(CurrentBrightness=999)]
        built, _ = backend(wmi=FakeWmiFactory(services))
        with self.assertRaises(UnsupportedCapabilityError):
            built.get_brightness()


class WifiTests(unittest.TestCase):
    def test_msft_state_maps_to_on(self) -> None:
        for raw in ("Enabled", "Connected", "Disconnected", "Connecting"):
            built, _ = backend(wmi=FakeWmiFactory(windows_like_wmi(wifi_state=raw)))
            with self.subTest(state=raw):
                self.assertEqual(built.wifi_status().state, ConnectivityState.ON)

    def test_disabled_maps_to_off(self) -> None:
        built, _ = backend(wmi=FakeWmiFactory(windows_like_wmi(wifi_state="Disabled")))
        self.assertEqual(built.wifi_status().state, ConnectivityState.OFF)

    def test_an_unrecognised_state_is_unknown_not_guessed(self) -> None:
        built, _ = backend(wmi=FakeWmiFactory(windows_like_wmi(wifi_state="Something New")))
        self.assertEqual(built.wifi_status().state, ConnectivityState.UNKNOWN)

    def test_falls_back_to_win32_network_adapter(self) -> None:
        services = windows_like_wmi(msft_rows=[])
        built, _ = backend(wmi=FakeWmiFactory(services))
        self.assertEqual(built.wifi_status().state, ConnectivityState.ON)
        services["cimv2"].answers[WIFI_ADAPTER_QUERY][0].NetEnabled = False
        self.assertEqual(built.wifi_status().state, ConnectivityState.OFF)

    def test_no_adapter_is_unavailable_not_off(self) -> None:
        services = windows_like_wmi(msft_rows=[])
        services["cimv2"].answers[WIFI_ADAPTER_QUERY] = []
        built, _ = backend(wmi=FakeWmiFactory(services))
        self.assertEqual(built.wifi_status().state, ConnectivityState.UNAVAILABLE)

    def test_enable_and_disable_use_the_wmi_methods(self) -> None:
        services = windows_like_wmi(wifi_state="Disabled", wifi_adapter_enabled=False)
        built, _ = backend(wmi=FakeWmiFactory(services))
        adapter = services["cimv2"].answers[WIFI_ADAPTER_QUERY][0]
        built.set_wifi(True)
        self.assertEqual(adapter.enabled_calls, 1)
        self.assertEqual(adapter.disabled_calls, 0)
        built.set_wifi(False)
        self.assertEqual(adapter.disabled_calls, 1)

    def test_a_refusal_becomes_a_backend_error(self) -> None:
        services = windows_like_wmi()
        row = services["cimv2"].answers[WIFI_ADAPTER_QUERY][0]

        def refuse():
            raise RuntimeError("access denied")

        row.Disable = refuse
        built, _ = backend(wmi=FakeWmiFactory(services))
        with self.assertRaises(PCSystemBackendError):
            built.set_wifi(False)

    def test_no_adapter_means_enable_is_unsupported(self) -> None:
        services = windows_like_wmi()
        services["cimv2"].answers[WIFI_ADAPTER_QUERY] = []
        built, _ = backend(wmi=FakeWmiFactory(services))
        with self.assertRaises(UnsupportedCapabilityError):
            built.set_wifi(True)


class BluetoothTests(unittest.TestCase):
    def test_an_adapter_without_a_state_api_is_unknown(self) -> None:
        built, _ = backend()
        status = built.bluetooth_status()
        self.assertEqual(status.state, ConnectivityState.UNKNOWN)
        self.assertIn("does not expose", status.detail)

    def test_no_adapter_is_unavailable(self) -> None:
        services = windows_like_wmi(bluetooth_rows=[])
        built, _ = backend(wmi=FakeWmiFactory(services))
        self.assertEqual(built.bluetooth_status().state, ConnectivityState.UNAVAILABLE)

    def test_control_is_always_unsupported_never_faked(self) -> None:
        built, _ = backend()
        for enabled in (True, False):
            with self.subTest(enabled=enabled):
                with self.assertRaises(UnsupportedCapabilityError) as caught:
                    built.set_bluetooth(enabled)
                self.assertIn("UI automation", str(caught.exception))


class WmiSafetyTests(unittest.TestCase):
    def test_only_whitelisted_namespaces_can_be_opened(self) -> None:
        for namespace in ("evil", "..\\root\\security", "", "cimv2; DROP"):
            with self.subTest(namespace=namespace):
                with self.assertRaises(PCSystemBackendError):
                    default_wmi_connect(namespace)

    def test_the_whitelist_is_exactly_the_three_namespaces(self) -> None:
        self.assertEqual(WMI_NAMESPACES, ("cimv2", "wmi", "StandardCimv2"))

    def test_every_query_issued_is_a_module_constant(self) -> None:
        """No WQL is ever assembled at runtime, so injection is impossible."""
        factory = FakeWmiFactory(windows_like_wmi())
        built, _ = backend(wmi=factory)
        built.get_volume()
        built.get_brightness()
        built.set_brightness(40)
        built.wifi_status()
        built.set_wifi(True)
        built.bluetooth_status()
        issued = [query for service in factory.services.values() for query in service.queries]
        self.assertTrue(issued)
        for query in issued:
            with self.subTest(query=query):
                self.assertIn(query, ALL_QUERIES)

    def test_only_known_namespaces_are_opened(self) -> None:
        factory = FakeWmiFactory(windows_like_wmi())
        built, _ = backend(wmi=factory)
        built.get_brightness()
        built.wifi_status()
        built.bluetooth_status()
        self.assertTrue(set(factory.opened) <= set(WMI_NAMESPACES))

    def test_services_are_opened_once_per_namespace(self) -> None:
        factory = FakeWmiFactory(windows_like_wmi())
        built, _ = backend(wmi=factory)
        built.get_brightness()
        built.set_brightness(20)
        self.assertEqual(factory.opened.count("wmi"), 1)

    def test_a_broken_wmi_service_surfaces_as_a_backend_error(self) -> None:
        factory = FakeWmiFactory(windows_like_wmi())
        factory.services["wmi"].raise_on_any = RuntimeError("the WMI service is down")
        built, _ = backend(wmi=factory)
        with self.assertRaises(PCSystemBackendError):
            built.get_brightness()

    def test_an_unopenable_namespace_surfaces_as_unavailable(self) -> None:
        factory = FakeWmiFactory(windows_like_wmi())
        factory.raise_for["cimv2"] = PCSystemBackendError("access denied")
        built, _ = backend(wmi=factory)
        # Bluetooth cannot be read -> UNAVAILABLE, never a guessed state.
        self.assertEqual(built.bluetooth_status().state, ConnectivityState.UNAVAILABLE)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
