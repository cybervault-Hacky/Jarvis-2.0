"""Phase 3 PC system tool tests - driven through the DeviceActionManager.

Every test injects a fake backend and a fake platform probe, so the suite never
depends on a speaker, a monitor, a Wi-Fi adapter, a Bluetooth radio, Windows or
a desktop session.
"""

from __future__ import annotations

import math
import unittest

from jarvis_devices import (
    AuditLogger,
    ConfirmationManager,
    ConfirmationPolicy,
    DeviceActionManager,
    DeviceToolRegistry,
    ErrorCode,
    PermissionPolicy,
    Platform,
    PlatformRegistry,
    RiskLevel,
    ToolResultStatus,
)
from jarvis_devices.permissions import (
    PERMISSION_BLUETOOTH_CONTROL,
    PERMISSION_DEVICE_STATUS_READ,
    PERMISSION_DISPLAY_CONTROL,
    PERMISSION_NETWORK_CONTROL,
    PERMISSION_VOLUME_CONTROL,
)
from jarvis_devices.pc_system import (
    CAPABILITY_NAMES,
    PC_SYSTEM_TOOL_NAMES,
    Capability,
    ConnectivityState,
    PCSystemBackendError,
    build_pc_system_tools,
    sanitize_percentage,
)

try:  # imported as part of the ``tests`` package (pytest / discover -t .)
    from .pc_system_support import FakePCSystemBackend
    from .support import FakeAdapter
except ImportError:  # ``python -m unittest discover -s tests``
    from pc_system_support import FakePCSystemBackend
    from support import FakeAdapter

ALL_CONTROL_PERMISSIONS = (
    PERMISSION_DEVICE_STATUS_READ,
    PERMISSION_VOLUME_CONTROL,
    PERMISSION_DISPLAY_CONTROL,
    PERMISSION_NETWORK_CONTROL,
    PERMISSION_BLUETOOTH_CONTROL,
)

READ_TOOLS = (
    "pc.system.status",
    "pc.system.get_volume",
    "pc.system.get_mute",
    "pc.system.get_brightness",
    "pc.system.wifi.status",
    "pc.system.bluetooth.status",
)
LOCAL_CONTROL_TOOLS = (
    "pc.system.set_volume",
    "pc.system.mute",
    "pc.system.unmute",
    "pc.system.set_brightness",
)
CONNECTIVITY_TOOLS = (
    "pc.system.wifi.enable",
    "pc.system.wifi.disable",
    "pc.system.bluetooth.enable",
    "pc.system.bluetooth.disable",
)


class PCSystemToolCase(unittest.IsolatedAsyncioTestCase):
    """Wires the Phase 3 tools into a real DeviceActionManager."""

    def build(
        self,
        *,
        backend=None,
        granted=ALL_CONTROL_PERMISSIONS,
        platform=Platform.PC,
        confirmation_policy=None,
        adapters=(Platform.PC,),
    ) -> DeviceActionManager:
        self.backend = backend if backend is not None else FakePCSystemBackend()
        registry = DeviceToolRegistry()
        registry.register_all(build_pc_system_tools(self.backend, platform_probe=lambda: platform))
        platforms = PlatformRegistry()
        for adapter_platform in adapters:
            platforms.register(FakeAdapter(adapter_platform))
        policy = confirmation_policy or ConfirmationPolicy()
        return DeviceActionManager(
            registry,
            PermissionPolicy(granted=granted),
            ConfirmationManager(policy=policy),
            platforms,
            AuditLogger(enabled=False),
            confirmation_policy=policy,
        )


# ---------------------------------------------------------------------------
# Declarations
# ---------------------------------------------------------------------------
class ToolDeclarationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tools = {
            tool.name: tool
            for tool in build_pc_system_tools(FakePCSystemBackend(), platform_probe=lambda: Platform.PC)
        }

    def test_the_fourteen_tools_are_declared_for_the_pc_platform(self) -> None:
        self.assertEqual(len(self.tools), 14)
        self.assertEqual(sorted(self.tools), sorted(PC_SYSTEM_TOOL_NAMES))
        for tool in self.tools.values():
            with self.subTest(tool=tool.name):
                self.assertIs(tool.platform, Platform.PC)
                self.assertIsNone(tool.requires_confirmation)  # the policy decides
                self.assertTrue(tool.is_available())

    def test_reads_are_safe_and_only_need_the_read_permission(self) -> None:
        for name in READ_TOOLS:
            with self.subTest(tool=name):
                self.assertIs(self.tools[name].risk_level, RiskLevel.SAFE)
                self.assertEqual(self.tools[name].required_permissions, (PERMISSION_DEVICE_STATUS_READ,))

    def test_local_controls_are_low_risk(self) -> None:
        expected = {
            "pc.system.set_volume": (PERMISSION_VOLUME_CONTROL,),
            "pc.system.mute": (PERMISSION_VOLUME_CONTROL,),
            "pc.system.unmute": (PERMISSION_VOLUME_CONTROL,),
            "pc.system.set_brightness": (PERMISSION_DISPLAY_CONTROL,),
        }
        for name, permissions in expected.items():
            with self.subTest(tool=name):
                self.assertIs(self.tools[name].risk_level, RiskLevel.LOW_RISK)
                self.assertEqual(self.tools[name].required_permissions, permissions)

    def test_connectivity_controls_are_external_actions(self) -> None:
        expected = {
            "pc.system.wifi.enable": (PERMISSION_NETWORK_CONTROL,),
            "pc.system.wifi.disable": (PERMISSION_NETWORK_CONTROL,),
            "pc.system.bluetooth.enable": (PERMISSION_BLUETOOTH_CONTROL,),
            "pc.system.bluetooth.disable": (PERMISSION_BLUETOOTH_CONTROL,),
        }
        for name, permissions in expected.items():
            with self.subTest(tool=name):
                self.assertIs(self.tools[name].risk_level, RiskLevel.EXTERNAL_ACTION)
                self.assertEqual(self.tools[name].required_permissions, permissions)

    def test_percentage_tools_accept_only_a_bounded_integer(self) -> None:
        for name in ("pc.system.set_volume", "pc.system.set_brightness"):
            spec = self.tools[name].argument_schema.specs[0]
            with self.subTest(tool=name):
                self.assertEqual(spec.name, "level")
                self.assertIs(spec.type, int)
                self.assertEqual((spec.min_value, spec.max_value), (0, 100))
                self.assertTrue(spec.required)

    def test_no_tool_declares_a_free_text_argument(self) -> None:
        """No shell-ish surface: the only argument in Phase 3 is ``level``."""
        for tool in self.tools.values():
            with self.subTest(tool=tool.name):
                self.assertIn(tool.argument_schema.names, ((), ("level",)))

    def test_every_capability_name_is_a_known_key(self) -> None:
        for tool in self.tools.values():
            with self.subTest(tool=tool.name):
                self.assertIn(tool.capability_name, set(CAPABILITY_NAMES) | {"system"})

    def test_platform_result_carries_the_backend_reason(self) -> None:
        """The tool names *why* system control is unavailable."""
        tools = build_pc_system_tools(FakePCSystemBackend(available=False), platform_probe=lambda: Platform.PC)
        for tool in tools:
            with self.subTest(tool=tool.name):
                result = tool.platform_result()
                self.assertIsNotNone(result)
                self.assertEqual(result.error_code, ErrorCode.DEVICE_UNAVAILABLE)
                self.assertEqual(result.data["reason"], "the fake backend is switched off")

    def test_tools_report_unsupported_platform_off_pc(self) -> None:
        tools = build_pc_system_tools(FakePCSystemBackend(), platform_probe=lambda: Platform.ANDROID)
        self.assertTrue(all(tool.is_available() for tool in tools))
        for tool in tools:
            with self.subTest(tool=tool.name):
                result = tool.platform_result()
                self.assertIsNotNone(result)
                self.assertEqual(result.error_code, ErrorCode.UNSUPPORTED_PLATFORM)


# ---------------------------------------------------------------------------
# pc.system.status
# ---------------------------------------------------------------------------
class SystemStatusTests(PCSystemToolCase):
    async def test_reports_every_capability(self) -> None:
        manager = self.build()
        result = await manager.request("pc.system.status")
        self.assertTrue(result.success)
        self.assertEqual(result.data["volume"]["level"], 40.0)
        self.assertFalse(result.data["volume"]["muted"])
        self.assertEqual(result.data["brightness"]["level"], 70)
        self.assertEqual(result.data["wifi"]["state"], ConnectivityState.ON)
        self.assertEqual(result.data["bluetooth"]["state"], ConnectivityState.UNKNOWN)
        self.assertEqual(result.data["platform"], {"os": "windows", "release": "11", "machine": "AMD64"})
        self.assertEqual(result.data["capabilities"]["bluetooth"], Capability.UNSUPPORTED)

    async def test_payload_is_a_closed_set_of_keys(self) -> None:
        manager = self.build()
        result = await manager.request("pc.system.status")
        self.assertEqual(
            set(result.data),
            {"platform", "volume", "brightness", "wifi", "bluetooth", "capabilities"},
        )

    async def test_never_collects_private_information(self) -> None:
        """Files, history, credentials, saved networks and processes are off limits."""
        backend = FakePCSystemBackend(
            system_info={
                "os": "windows",
                "release": "11",
                "machine": "AMD64",
                "hostname": "SARTHAK-LAPTOP",
                "user": "sarthak",
                "saved_wifi_password": "hunter2",
                "processes": "chrome.exe, spotify.exe",
            }
        )
        manager = self.build(backend=backend)
        result = await manager.request("pc.system.status")
        self.assertTrue(result.success)
        self.assertEqual(set(result.data["platform"]), {"os", "release", "machine"})
        blob = result.to_dict()
        self.assertNotIn("SARTHAK-LAPTOP", repr(blob))
        self.assertNotIn("hunter2", repr(blob))
        self.assertNotIn("chrome.exe", repr(blob))

    async def test_one_broken_capability_does_not_break_the_others(self) -> None:
        backend = FakePCSystemBackend(bluetooth=ConnectivityState.ON)
        backend.volume_error = PCSystemBackendError("the audio service stopped")
        backend.wifi_error = PCSystemBackendError("WMI is not answering")
        manager = self.build(backend=backend)
        result = await manager.request("pc.system.status")
        self.assertTrue(result.success)
        self.assertEqual(result.data["volume"]["capability"], Capability.FAILED)
        self.assertEqual(result.data["wifi"]["state"], ConnectivityState.UNKNOWN)
        self.assertEqual(result.data["brightness"]["level"], 70)
        self.assertEqual(result.data["bluetooth"]["state"], ConnectivityState.ON)

    async def test_unsupported_hardware_is_reported_not_hidden(self) -> None:
        backend = FakePCSystemBackend(
            volume=None,
            brightness=None,
            wifi=ConnectivityState.UNAVAILABLE,
            capabilities={name: Capability.UNSUPPORTED for name in CAPABILITY_NAMES},
        )
        manager = self.build(backend=backend)
        result = await manager.request("pc.system.status")
        self.assertTrue(result.success)  # the *read* worked; the hardware does not exist
        self.assertEqual(result.data["volume"]["capability"], Capability.UNSUPPORTED)
        self.assertIsNone(result.data["volume"]["level"])
        self.assertEqual(result.data["brightness"]["capability"], Capability.UNSUPPORTED)
        self.assertEqual(result.data["wifi"]["state"], ConnectivityState.UNAVAILABLE)

    async def test_a_nonsense_driver_value_is_not_echoed(self) -> None:
        backend = FakePCSystemBackend(volume=float("nan"), brightness=250)
        manager = self.build(backend=backend)
        result = await manager.request("pc.system.status")
        self.assertTrue(result.success)
        self.assertIsNone(result.data["volume"]["level"])
        self.assertEqual(result.data["volume"]["capability"], Capability.FAILED)
        self.assertIsNone(result.data["brightness"]["level"])


# ---------------------------------------------------------------------------
# Volume
# ---------------------------------------------------------------------------
class VolumeTests(PCSystemToolCase):
    async def test_get_volume_reports_the_real_level(self) -> None:
        backend = FakePCSystemBackend(volume=62.5, muted=True)
        manager = self.build(backend=backend)
        result = await manager.request("pc.system.get_volume")
        self.assertTrue(result.success)
        self.assertEqual(result.data["level"], 62.5)
        self.assertTrue(result.data["muted"])

    async def test_set_volume_reports_the_resulting_level(self) -> None:
        manager = self.build()
        result = await manager.request("pc.system.set_volume", {"level": 15})
        self.assertTrue(result.success)
        self.assertEqual(result.data["requested"], 15)
        self.assertEqual(result.data["level"], 15.0)
        self.assertEqual(self.backend.volume_level, 15.0)
        self.assertIn("set_volume:15.0", self.backend.calls)

    async def test_get_mute_reports_the_real_state(self) -> None:
        for muted in (True, False):
            manager = self.build(backend=FakePCSystemBackend(muted=muted))
            with self.subTest(muted=muted):
                result = await manager.request("pc.system.get_mute")
                self.assertTrue(result.success)
                self.assertIs(result.data["muted"], muted)

    async def test_get_mute_is_unavailable_without_an_audio_endpoint(self) -> None:
        backend = FakePCSystemBackend()
        backend.volume_error = backend.unsupported("no render endpoint")
        manager = self.build(backend=backend)
        result = await manager.request("pc.system.get_mute")
        self.assertEqual(result.status, ToolResultStatus.UNAVAILABLE)
        self.assertEqual(result.error_code, ErrorCode.SYSTEM_CONTROL_UNAVAILABLE)

    async def test_get_mute_reports_a_backend_failure(self) -> None:
        backend = FakePCSystemBackend()
        backend.volume_error = PCSystemBackendError("the audio service stopped")
        manager = self.build(backend=backend)
        result = await manager.request("pc.system.get_mute")
        self.assertEqual(result.status, ToolResultStatus.FAILED)
        self.assertEqual(result.error_code, ErrorCode.VOLUME_CONTROL_FAILED)

    async def test_set_volume_works_at_zero_fifty_and_a_hundred(self) -> None:
        for level in (0, 50, 100):
            manager = self.build()
            with self.subTest(level=level):
                result = await manager.request("pc.system.set_volume", {"level": level})
                self.assertTrue(result.success)
                self.assertEqual(result.data["requested"], level)
                self.assertEqual(result.data["level"], float(level))
                self.assertEqual(self.backend.volume_level, float(level))

    async def test_set_volume_accepts_the_boundaries(self) -> None:
        for level in (0, 100):
            manager = self.build()
            with self.subTest(level=level):
                result = await manager.request("pc.system.set_volume", {"level": level})
                self.assertTrue(result.success)
                self.assertEqual(result.data["level"], float(level))

    async def test_hardware_that_ignores_the_request_is_a_failure(self) -> None:
        backend = FakePCSystemBackend()
        backend.set_volume_is_effective = False
        manager = self.build(backend=backend)
        result = await manager.request("pc.system.set_volume", {"level": 90})
        self.assertEqual(result.status, ToolResultStatus.FAILED)
        self.assertEqual(result.error_code, ErrorCode.VOLUME_CONTROL_FAILED)
        self.assertIn("requested at 90%", result.message)

    async def test_a_backend_error_is_not_reported_as_success(self) -> None:
        backend = FakePCSystemBackend()
        backend.volume_error = PCSystemBackendError("the audio endpoint vanished")
        manager = self.build(backend=backend)
        for name, arguments in (("pc.system.get_volume", {}), ("pc.system.set_volume", {"level": 50})):
            with self.subTest(tool=name):
                result = await manager.request(name, arguments)
                self.assertEqual(result.status, ToolResultStatus.FAILED)
                self.assertEqual(result.error_code, ErrorCode.VOLUME_CONTROL_FAILED)

    async def test_no_audio_endpoint_answers_unavailable(self) -> None:
        backend = FakePCSystemBackend(capabilities={"volume": Capability.UNSUPPORTED, "brightness": Capability.SUPPORTED, "wifi": Capability.SUPPORTED, "bluetooth": Capability.UNSUPPORTED})
        backend.volume_error = backend.unsupported("no render endpoint")
        manager = self.build(backend=backend)
        for name, arguments in (("pc.system.get_volume", {}), ("pc.system.set_volume", {"level": 50})):
            with self.subTest(tool=name):
                result = await manager.request(name, arguments)
                self.assertEqual(result.status, ToolResultStatus.UNAVAILABLE)
                self.assertEqual(result.error_code, ErrorCode.SYSTEM_CONTROL_UNAVAILABLE)

    async def test_mute_and_unmute_round_trip(self) -> None:
        manager = self.build()
        muted = await manager.request("pc.system.mute")
        self.assertTrue(muted.success)
        self.assertTrue(muted.data["muted"])
        unmuted = await manager.request("pc.system.unmute")
        self.assertTrue(unmuted.success)
        self.assertFalse(unmuted.data["muted"])
        self.assertEqual(self.backend.calls.count("set_mute:True"), 1)
        self.assertEqual(self.backend.calls.count("set_mute:False"), 1)

    async def test_mute_that_does_not_stick_is_a_failure(self) -> None:
        backend = FakePCSystemBackend()
        backend.set_volume_is_effective = False
        manager = self.build(backend=backend)
        result = await manager.request("pc.system.mute")
        self.assertEqual(result.status, ToolResultStatus.FAILED)
        self.assertEqual(result.error_code, ErrorCode.VOLUME_CONTROL_FAILED)


class VolumeArgumentTests(PCSystemToolCase):
    async def test_rejects_every_nonsense_level(self) -> None:
        manager = self.build()
        bad_values = (-1, 101, 1000, "loud", "50", "", None, True, False, 50.5, float("nan"), float("inf"), [], {}, {"level": 5})
        for value in bad_values:
            with self.subTest(value=repr(value)):
                result = await manager.request("pc.system.set_volume", {"level": value})
                self.assertEqual(result.status, ToolResultStatus.INVALID_ARGUMENT)
                self.assertEqual(result.error_code, ErrorCode.INVALID_ARGUMENT)
                self.assertFalse(result.executed)
        self.assertEqual(self.backend.volume_level, 40.0)  # nothing ever changed

    async def test_rejects_a_missing_level(self) -> None:
        manager = self.build()
        result = await manager.request("pc.system.set_volume", {})
        self.assertEqual(result.status, ToolResultStatus.INVALID_ARGUMENT)

    async def test_rejects_undeclared_arguments(self) -> None:
        manager = self.build()
        result = await manager.request("pc.system.set_volume", {"level": 40, "command": "shutdown /s"})
        self.assertEqual(result.status, ToolResultStatus.INVALID_ARGUMENT)
        self.assertNotIn("command", self.backend.calls)

    async def test_brightness_rejects_the_same_nonsense(self) -> None:
        manager = self.build()
        for value in (-5, 105, "bright", True, 42.7, float("inf")):
            with self.subTest(value=repr(value)):
                result = await manager.request("pc.system.set_brightness", {"level": value})
                self.assertEqual(result.status, ToolResultStatus.INVALID_ARGUMENT)


# ---------------------------------------------------------------------------
# Brightness
# ---------------------------------------------------------------------------
class BrightnessTests(PCSystemToolCase):
    async def test_set_brightness_works_at_zero_and_a_hundred(self) -> None:
        for level in (0, 100):
            manager = self.build()
            with self.subTest(level=level):
                result = await manager.request("pc.system.set_brightness", {"level": level})
                self.assertTrue(result.success)
                self.assertEqual(result.data["level"], level)
                self.assertEqual(self.backend.brightness_level, level)

    async def test_get_and_set_report_the_real_level(self) -> None:
        manager = self.build()
        read = await manager.request("pc.system.get_brightness")
        self.assertTrue(read.success)
        self.assertEqual(read.data["level"], 70)

        written = await manager.request("pc.system.set_brightness", {"level": 25})
        self.assertTrue(written.success)
        self.assertEqual(written.data["level"], 25)
        self.assertEqual(self.backend.brightness_level, 25)

    async def test_a_monitor_without_brightness_control_answers_unavailable(self) -> None:
        backend = FakePCSystemBackend(
            brightness=None,
            capabilities={"volume": Capability.SUPPORTED, "brightness": Capability.UNSUPPORTED, "wifi": Capability.SUPPORTED, "bluetooth": Capability.UNSUPPORTED},
        )
        backend.brightness_error = backend.unsupported("no WmiMonitorBrightness")
        manager = self.build(backend=backend)
        for name, arguments in (("pc.system.get_brightness", {}), ("pc.system.set_brightness", {"level": 30})):
            with self.subTest(tool=name):
                result = await manager.request(name, arguments)
                self.assertEqual(result.status, ToolResultStatus.UNAVAILABLE)
                self.assertEqual(result.error_code, ErrorCode.BRIGHTNESS_CONTROL_UNAVAILABLE)
                self.assertIsNotNone(result.data["detail"])

    async def test_a_failed_brightness_call_is_failed_not_unavailable(self) -> None:
        backend = FakePCSystemBackend()
        backend.brightness_error = PCSystemBackendError("WMI refused the call")
        manager = self.build(backend=backend)
        result = await manager.request("pc.system.set_brightness", {"level": 30})
        self.assertEqual(result.status, ToolResultStatus.FAILED)
        self.assertEqual(result.error_code, ErrorCode.BRIGHTNESS_CONTROL_FAILED)

    async def test_a_monitor_that_ignores_the_change_is_a_failure(self) -> None:
        backend = FakePCSystemBackend()
        backend.set_brightness_is_effective = False
        manager = self.build(backend=backend)
        result = await manager.request("pc.system.set_brightness", {"level": 90})
        self.assertEqual(result.status, ToolResultStatus.FAILED)
        self.assertEqual(result.error_code, ErrorCode.BRIGHTNESS_CONTROL_FAILED)
        self.assertIn("requested at 90%", result.message)

    async def test_a_broken_driver_value_is_not_echoed(self) -> None:
        backend = FakePCSystemBackend(brightness=250)
        manager = self.build(backend=backend)
        result = await manager.request("pc.system.get_brightness")
        self.assertEqual(result.status, ToolResultStatus.FAILED)
        self.assertEqual(result.error_code, ErrorCode.INVALID_PERCENTAGE)


# ---------------------------------------------------------------------------
# Wi-Fi
# ---------------------------------------------------------------------------
class WifiTests(PCSystemToolCase):
    async def test_status_reports_on_off_and_unknown(self) -> None:
        for state in (ConnectivityState.ON, ConnectivityState.OFF, ConnectivityState.UNKNOWN):
            manager = self.build(backend=FakePCSystemBackend(wifi=state))
            with self.subTest(state=state):
                result = await manager.request("pc.system.wifi.status")
                self.assertTrue(result.success)
                self.assertEqual(result.data["state"], state)

    async def test_an_unreadable_radio_is_unavailable_not_off(self) -> None:
        manager = self.build(backend=FakePCSystemBackend(wifi=ConnectivityState.UNAVAILABLE))
        result = await manager.request("pc.system.wifi.status")
        self.assertEqual(result.status, ToolResultStatus.UNAVAILABLE)
        self.assertEqual(result.error_code, ErrorCode.WIFI_CONTROL_UNAVAILABLE)

    async def test_status_never_exposes_a_credential(self) -> None:
        manager = self.build()
        result = await manager.request("pc.system.wifi.status")
        self.assertTrue(result.success)
        self.assertEqual(set(result.data), {"state", "detail", "adapter", "capability"})

    async def test_enable_asks_for_confirmation_and_then_runs(self) -> None:
        manager = self.build(backend=FakePCSystemBackend(wifi=ConnectivityState.OFF))
        asked = await manager.request("pc.system.wifi.enable")
        self.assertEqual(asked.status, ToolResultStatus.PENDING_CONFIRMATION)
        self.assertEqual(self.backend.wifi_state, ConnectivityState.OFF)  # nothing happened yet
        confirmed = await manager.resolve_confirmation(asked.data["confirmation_id"], True)
        self.assertTrue(confirmed.success)
        self.assertEqual(self.backend.wifi_state, ConnectivityState.ON)

    async def test_a_declined_confirmation_changes_nothing(self) -> None:
        backend = FakePCSystemBackend(wifi=ConnectivityState.ON)
        manager = self.build(backend=backend)
        asked = await manager.request("pc.system.wifi.disable")
        self.assertEqual(asked.status, ToolResultStatus.PENDING_CONFIRMATION)
        declined = await manager.resolve_confirmation(asked.data["confirmation_id"], False)
        self.assertEqual(declined.status, ToolResultStatus.DENIED)
        self.assertEqual(backend.wifi_state, ConnectivityState.ON)
        self.assertNotIn("set_wifi:False", backend.calls)

    async def test_disable_turns_the_radio_off_after_confirmation(self) -> None:
        manager = self.build()
        asked = await manager.request("pc.system.wifi.disable")
        confirmed = await manager.resolve_confirmation(asked.data["confirmation_id"], True)
        self.assertTrue(confirmed.success)
        self.assertEqual(confirmed.data["state"], ConnectivityState.OFF)

    async def test_a_radio_that_refuses_to_change_is_a_failure(self) -> None:
        backend = FakePCSystemBackend(wifi=ConnectivityState.OFF)
        backend.wifi_toggle_is_effective = False
        manager = self.build(backend=backend)
        asked = await manager.request("pc.system.wifi.enable")
        confirmed = await manager.resolve_confirmation(asked.data["confirmation_id"], True)
        self.assertEqual(confirmed.status, ToolResultStatus.FAILED)
        self.assertEqual(confirmed.error_code, ErrorCode.WIFI_CONTROL_FAILED)

    async def test_a_missing_adapter_answers_unavailable(self) -> None:
        backend = FakePCSystemBackend(wifi=ConnectivityState.UNAVAILABLE)
        backend.wifi_error = backend.unsupported("no Wi-Fi adapter")
        manager = self.build(backend=backend)
        result = await manager.request("pc.system.wifi.status")
        self.assertEqual(result.status, ToolResultStatus.UNAVAILABLE)
        self.assertEqual(result.error_code, ErrorCode.WIFI_CONTROL_UNAVAILABLE)

    async def test_a_windows_refusal_is_a_failure_not_a_success(self) -> None:
        backend = FakePCSystemBackend()
        backend.wifi_error = PCSystemBackendError("access denied")
        manager = self.build(backend=backend)
        asked = await manager.request("pc.system.wifi.enable")
        confirmed = await manager.resolve_confirmation(asked.data["confirmation_id"], True)
        self.assertEqual(confirmed.status, ToolResultStatus.FAILED)
        self.assertEqual(confirmed.error_code, ErrorCode.WIFI_CONTROL_FAILED)

    async def test_confirmation_can_be_switched_off_by_policy_alone(self) -> None:
        policy = ConfirmationPolicy(never_confirm=("pc.system.wifi.enable",))
        manager = self.build(confirmation_policy=policy)
        result = await manager.request("pc.system.wifi.enable")
        self.assertTrue(result.success)


# ---------------------------------------------------------------------------
# Bluetooth
# ---------------------------------------------------------------------------
class BluetoothTests(PCSystemToolCase):
    async def test_status_reports_the_honest_answer(self) -> None:
        manager = self.build()
        result = await manager.request("pc.system.bluetooth.status")
        self.assertTrue(result.success)
        self.assertEqual(result.data["state"], ConnectivityState.UNKNOWN)

    async def test_control_without_a_supported_api_is_unavailable(self) -> None:
        manager = self.build()
        for name in ("pc.system.bluetooth.enable", "pc.system.bluetooth.disable"):
            with self.subTest(tool=name):
                asked = await manager.request(name)
                result = await manager.resolve_confirmation(asked.data["confirmation_id"], True)
                self.assertEqual(result.status, ToolResultStatus.UNAVAILABLE)
                self.assertEqual(result.error_code, ErrorCode.BLUETOOTH_CONTROL_UNAVAILABLE)

    async def test_control_works_when_a_backend_supports_it(self) -> None:
        backend = FakePCSystemBackend(bluetooth=ConnectivityState.OFF, bluetooth_control_supported=True)
        manager = self.build(backend=backend)
        asked = await manager.request("pc.system.bluetooth.enable")
        result = await manager.resolve_confirmation(asked.data["confirmation_id"], True)
        self.assertTrue(result.success)
        self.assertEqual(backend.bluetooth_state, ConnectivityState.ON)

    async def test_status_is_available_without_any_control_permission(self) -> None:
        manager = self.build(granted=(PERMISSION_DEVICE_STATUS_READ,))
        result = await manager.request("pc.system.bluetooth.status")
        self.assertTrue(result.success)


# ---------------------------------------------------------------------------
# Permissions / platform / availability
# ---------------------------------------------------------------------------
class PermissionAndPlatformTests(PCSystemToolCase):
    async def test_read_tools_work_with_only_the_read_permission(self) -> None:
        manager = self.build(granted=(PERMISSION_DEVICE_STATUS_READ,))
        for name in READ_TOOLS:
            with self.subTest(tool=name):
                result = await manager.request(name)
                self.assertTrue(result.success)

    async def test_every_control_tool_needs_its_own_permission(self) -> None:
        manager = self.build(granted=(PERMISSION_DEVICE_STATUS_READ,))
        expectations = {
            "pc.system.set_volume": ErrorCode.PERMISSION_DENIED,
            "pc.system.mute": ErrorCode.PERMISSION_DENIED,
            "pc.system.unmute": ErrorCode.PERMISSION_DENIED,
            "pc.system.set_brightness": ErrorCode.PERMISSION_DENIED,
        }
        for name, code in expectations.items():
            with self.subTest(tool=name):
                result = await manager.request(name, {"level": 50} if "set_" in name else {})
                self.assertEqual(result.status, ToolResultStatus.PERMISSION_DENIED)
                self.assertEqual(result.error_code, code)
                self.assertFalse(result.executed)

    async def test_bluetooth_permission_denied_when_not_granted(self) -> None:
        granted = tuple(p for p in ALL_CONTROL_PERMISSIONS if p != PERMISSION_BLUETOOTH_CONTROL)
        manager = self.build(granted=granted)
        result = await manager.request("pc.system.bluetooth.enable")
        self.assertEqual(result.status, ToolResultStatus.PERMISSION_DENIED)
        self.assertEqual(result.error_code, ErrorCode.PERMISSION_DENIED)

    async def test_connectivity_asks_before_acting_by_default(self) -> None:
        manager = self.build()
        for name in CONNECTIVITY_TOOLS:
            with self.subTest(tool=name):
                result = await manager.request(name)
                self.assertEqual(result.status, ToolResultStatus.PENDING_CONFIRMATION)

    async def test_local_controls_are_not_confirmed_by_default(self) -> None:
        manager = self.build()
        for name in LOCAL_CONTROL_TOOLS:
            with self.subTest(tool=name):
                arguments = {"level": 50} if name.startswith("pc.system.set_") else {}
                result = await manager.request(name, arguments)
                self.assertTrue(result.success)

    async def test_an_unknown_tool_is_refused(self) -> None:
        manager = self.build()
        for name in ("pc.system.shutdown", "pc.system.volume.set", "os.system", "pc.system.set_volume; rm -rf /"):
            with self.subTest(name=name):
                result = await manager.request(name, {"level": 50})
                self.assertFalse(result.success)
                self.assertEqual(result.error_code, ErrorCode.UNKNOWN_TOOL)
                self.assertFalse(result.executed)

    async def test_off_pc_every_tool_answers_unsupported_platform(self) -> None:
        """No PC adapter -> the framework blocks the call before it can run."""
        manager = self.build(platform=Platform.ANDROID, adapters=(Platform.ANDROID,))
        for name in PC_SYSTEM_TOOL_NAMES:
            with self.subTest(tool=name):
                arguments = {"level": 50} if "set_" in name else {}
                result = await manager.request(name, arguments)
                self.assertEqual(result.status, ToolResultStatus.UNAVAILABLE)
                self.assertEqual(result.error_code, ErrorCode.PLATFORM_UNAVAILABLE)
                self.assertFalse(result.executed)

    async def test_the_tools_themselves_name_the_platform_problem(self) -> None:
        """With a PC adapter present but a non-PC probe, the tool is precise."""
        tools = build_pc_system_tools(FakePCSystemBackend(), platform_probe=lambda: Platform.ANDROID)
        for tool in tools:
            with self.subTest(tool=tool.name):
                result = tool.platform_result()
                self.assertEqual(result.error_code, ErrorCode.UNSUPPORTED_PLATFORM)

    async def test_without_a_platform_adapter_the_tool_is_blocked(self) -> None:
        manager = self.build(adapters=())
        result = await manager.request("pc.system.set_volume", {"level": 40})
        self.assertFalse(result.success)

    async def test_an_unavailable_backend_answers_tool_unavailable(self) -> None:
        """``is_available()`` is False, so the framework refuses before running."""
        manager = self.build(backend=FakePCSystemBackend(available=False))
        for name in PC_SYSTEM_TOOL_NAMES:
            with self.subTest(tool=name):
                arguments = {"level": 50} if "set_" in name else {}
                result = await manager.request(name, arguments)
                self.assertEqual(result.status, ToolResultStatus.UNAVAILABLE)
                self.assertEqual(result.error_code, ErrorCode.TOOL_UNAVAILABLE)
                self.assertFalse(result.executed)


    async def test_no_power_control_tool_exists(self) -> None:
        """Phase 4 is out of scope: nothing here can shut the PC down."""
        tools = {tool.name for tool in build_pc_system_tools(FakePCSystemBackend(), platform_probe=lambda: Platform.PC)}
        for forbidden in ("shutdown", "restart", "sleep", "hibernate", "logoff", "log_off"):
            with self.subTest(word=forbidden):
                self.assertFalse(any(forbidden in name for name in tools))


class SanitizePercentageTests(unittest.TestCase):
    def test_accepts_in_range_values(self) -> None:
        for value in (0, 100, 42, 33.5):
            with self.subTest(value=value):
                clean, error = sanitize_percentage(value)
                self.assertIsNone(error)
                self.assertEqual(clean, float(value))

    def test_rejects_nonsense(self) -> None:
        for value in (None, -1, 101, float("nan"), float("inf"), float("-inf"), "loud", object()):
            with self.subTest(value=repr(value)):
                clean, error = sanitize_percentage(value)
                self.assertIsNone(clean)
                self.assertIsNotNone(error)
        self.assertTrue(math.isnan(float("nan")))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
