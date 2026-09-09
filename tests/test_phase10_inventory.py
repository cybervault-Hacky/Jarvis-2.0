"""Phase 10 closed-world production Agent and registered-capability inventory."""

from __future__ import annotations

import unittest

try:
    from livekit.agents import FunctionTool
except ImportError:  # pragma: no cover - source-only environments
    FunctionTool = None  # type: ignore[assignment,misc]

import Jarvis_device_control as bridge
from jarvis_devices.android_call_tools import ANDROID_CALL_TOOL_NAMES
from jarvis_devices.android_message_tools import ANDROID_MESSAGE_TOOL_NAMES
from jarvis_devices.android_system_tools import ANDROID_SYSTEM_TOOL_NAMES
from jarvis_devices.android_tools import ANDROID_BRIDGE_TOOL_NAMES
from jarvis_devices.cross_device import CROSS_DEVICE_TOOL_NAMES
from jarvis_devices.diagnostics import FrameworkDiagnosticsTool
from jarvis_devices.enums import RiskLevel
from jarvis_devices.pc_apps import PC_APPLICATION_TOOL_NAMES
from jarvis_devices.pc_power import PC_POWER_TOOL_NAMES
from jarvis_devices.pc_system import PC_SYSTEM_TOOL_NAMES


MODEL_TOOL_NAMES = (
    "google_search", "get_current_datetime", "get_weather",
    "list_open_applications", "application_status", "open_application", "focus_application", "close_application",
    "system_status", "get_system_volume", "set_system_volume", "mute_system", "unmute_system", "get_system_mute",
    "get_system_brightness", "set_system_brightness", "wifi_status", "wifi_enable", "wifi_disable",
    "bluetooth_status", "bluetooth_enable", "bluetooth_disable",
    "shutdown_pc", "restart_pc", "sleep_pc", "hibernate_pc", "logoff_pc",
    "android_bridge_status", "android_device_list", "android_device_status", "android_device_pair", "android_device_unpair", "android_device_revoke",
    "android_system_status", "android_get_volume", "android_set_volume", "android_mute", "android_unmute",
    "android_get_brightness", "android_set_brightness", "android_wifi_status", "android_wifi_enable", "android_wifi_disable",
    "android_bluetooth_status", "android_bluetooth_enable", "android_bluetooth_disable",
    "android_call_status", "android_call_dial", "android_call_answer", "android_call_reject", "android_call_end",
    "android_message_status", "android_message_send", "cross_device_status", "cross_device_capabilities",
)

RETIRED_MODEL_TOOLS = frozenset({
    "open", "close", "folder_file", "Play_file", "move_cursor_tool", "mouse_click_tool",
    "scroll_cursor_tool", "type_text_tool", "press_key_tool", "press_hotkey_tool",
    "control_volume_tool", "swipe_gesture_tool", "device_action", "device_confirmation",
})

REGISTERED_TOOL_NAMES = frozenset({
    FrameworkDiagnosticsTool.name,
    *PC_APPLICATION_TOOL_NAMES,
    *PC_SYSTEM_TOOL_NAMES,
    *PC_POWER_TOOL_NAMES,
    *ANDROID_BRIDGE_TOOL_NAMES,
    *ANDROID_SYSTEM_TOOL_NAMES,
    *ANDROID_CALL_TOOL_NAMES,
    *ANDROID_MESSAGE_TOOL_NAMES,
    *CROSS_DEVICE_TOOL_NAMES,
})


@unittest.skipUnless(FunctionTool is not None, "livekit-agents is not installed")
class ProductionAgentInventoryTests(unittest.TestCase):
    def test_actual_livekit_agent_has_exact_closed_tool_set(self) -> None:
        import agent

        assistant = agent.Assistant()
        actual = tuple(tool.__name__ for tool in assistant.tools)
        self.assertEqual(actual, MODEL_TOOL_NAMES)
        self.assertEqual(len(actual), len(set(actual)))
        self.assertTrue(all(isinstance(tool, FunctionTool) for tool in assistant.tools))
        self.assertTrue(RETIRED_MODEL_TOOLS.isdisjoint(actual))

    def test_generic_dispatch_and_model_confirmation_are_not_function_tools(self) -> None:
        self.assertFalse(isinstance(bridge.device_action, FunctionTool))
        self.assertFalse(isinstance(bridge.device_confirmation, FunctionTool))
        self.assertFalse(hasattr(bridge.device_action, "__livekit_tool_info"))
        self.assertFalse(hasattr(bridge.device_confirmation, "__livekit_tool_info"))


class RegisteredCapabilityInventoryTests(unittest.TestCase):
    def test_registry_matches_the_complete_closed_world_inventory(self) -> None:
        actual = {entry["name"] for entry in bridge.device_registry.describe()}
        self.assertEqual(actual, REGISTERED_TOOL_NAMES)
        self.assertEqual(len(actual), 53)

    def test_every_registered_tool_has_complete_nonsecret_inventory_metadata(self) -> None:
        described = bridge.device_registry.describe()
        for entry in described:
            with self.subTest(tool=entry["name"]):
                self.assertIn(entry["platform"], {"pc", "android", "unknown"})
                self.assertIn(entry["risk_level"], {risk.value for risk in RiskLevel})
                self.assertIsInstance(entry["required_permissions"], list)
                if entry["name"] != FrameworkDiagnosticsTool.name:
                    self.assertTrue(entry["required_permissions"])
                self.assertIsInstance(entry["available"], bool)
                self.assertIn("required", entry["arguments"])
                self.assertNotIn("key", " ".join(entry).lower())

    def test_every_external_or_destructive_registered_tool_has_mandatory_confirmation(self) -> None:
        for tool in bridge.device_registry.list_tools():
            with self.subTest(tool=tool.name):
                if tool.risk_level in {RiskLevel.EXTERNAL_ACTION, RiskLevel.DESTRUCTIVE}:
                    self.assertTrue(bridge.device_manager.confirmation_policy.is_required(tool))

    def test_android_operations_require_only_canonical_device_or_pairing_inputs(self) -> None:
        for entry in bridge.device_registry.describe():
            if not entry["name"].startswith("android."):
                continue
            properties = entry["arguments"]["properties"]
            forbidden = {"host", "hostname", "ip", "port", "url", "transport", "key", "command", "method", "api"}
            with self.subTest(tool=entry["name"]):
                self.assertTrue(forbidden.isdisjoint(properties))
                if entry["name"] not in {"android.bridge.status", "android.device.list"}:
                    self.assertTrue({"device", "pairing"} & set(properties))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
