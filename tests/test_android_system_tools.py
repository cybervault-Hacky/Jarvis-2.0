"""Phase 6 tests: the thirteen Android system-control tools."""

from __future__ import annotations

import unittest

from jarvis_devices import ToolContext, new_execution_id
from jarvis_devices.android_bridge import AndroidDeviceNotConnectedError, create_default_android_bridge
from jarvis_devices.android_protocol import InvalidMessageError
from jarvis_devices.android_system import AndroidSystemControl, AndroidSystemTimeoutError
from jarvis_devices.android_system_tools import (
    ANDROID_SYSTEM_TOOL_NAMES,
    LEVEL_ARGUMENT,
    BluetoothDisableTool,
    BluetoothEnableTool,
    BluetoothStatusTool,
    GetBrightnessTool,
    GetVolumeTool,
    MuteTool,
    SetBrightnessTool,
    SetVolumeTool,
    SystemStatusTool,
    UnmuteTool,
    WifiDisableTool,
    WifiEnableTool,
    WifiStatusTool,
    build_android_system_tools,
)
from jarvis_devices.arguments import ArgumentSchema
from jarvis_devices.enums import Platform, RiskLevel, ToolResultStatus
from jarvis_devices.errors import ErrorCode
from jarvis_devices.permissions import (
    PERMISSION_ANDROID_SYSTEM_CONTROL,
    PERMISSION_ANDROID_SYSTEM_READ,
)

try:
    from .android_support import FakeAndroidBridge, requires_crypto
    from .android_system_support import answered, system_phone_pair
except ImportError:
    from android_support import FakeAndroidBridge, requires_crypto
    from android_system_support import answered, system_phone_pair

VALID_DEVICE = "adev-" + "a" * 32

#: What each tool must declare: risk, permissions, arguments, confirmation.
DECLARATIONS = {
    "android.system.status": (RiskLevel.SAFE, PERMISSION_ANDROID_SYSTEM_READ, ("device",), None),
    "android.system.get_volume": (RiskLevel.SAFE, PERMISSION_ANDROID_SYSTEM_READ, ("device",), None),
    "android.system.set_volume": (
        RiskLevel.LOW_RISK,
        PERMISSION_ANDROID_SYSTEM_CONTROL,
        ("device", "level"),
        None,
    ),
    "android.system.mute": (RiskLevel.LOW_RISK, PERMISSION_ANDROID_SYSTEM_CONTROL, ("device",), None),
    "android.system.unmute": (RiskLevel.LOW_RISK, PERMISSION_ANDROID_SYSTEM_CONTROL, ("device",), None),
    "android.system.get_brightness": (
        RiskLevel.SAFE,
        PERMISSION_ANDROID_SYSTEM_READ,
        ("device",),
        None,
    ),
    "android.system.set_brightness": (
        RiskLevel.LOW_RISK,
        PERMISSION_ANDROID_SYSTEM_CONTROL,
        ("device", "level"),
        None,
    ),
    "android.system.wifi.status": (RiskLevel.SAFE, PERMISSION_ANDROID_SYSTEM_READ, ("device",), None),
    "android.system.wifi.enable": (
        RiskLevel.EXTERNAL_ACTION,
        PERMISSION_ANDROID_SYSTEM_CONTROL,
        ("device",),
        True,
    ),
    "android.system.wifi.disable": (
        RiskLevel.EXTERNAL_ACTION,
        PERMISSION_ANDROID_SYSTEM_CONTROL,
        ("device",),
        True,
    ),
    "android.system.bluetooth.status": (
        RiskLevel.SAFE,
        PERMISSION_ANDROID_SYSTEM_READ,
        ("device",),
        None,
    ),
    "android.system.bluetooth.enable": (
        RiskLevel.EXTERNAL_ACTION,
        PERMISSION_ANDROID_SYSTEM_CONTROL,
        ("device",),
        True,
    ),
    "android.system.bluetooth.disable": (
        RiskLevel.EXTERNAL_ACTION,
        PERMISSION_ANDROID_SYSTEM_CONTROL,
        ("device",),
        True,
    ),
}


def context(tool_name: str) -> ToolContext:
    return ToolContext(
        execution_id=new_execution_id(), tool_name=tool_name, platform=Platform.PC
    )


class DeclarationTests(unittest.TestCase):
    def test_thirteen_tools_with_the_expected_names(self) -> None:
        tools = build_android_system_tools(create_default_android_bridge())
        self.assertEqual(len(tools), 13)
        self.assertEqual(tuple(tool.name for tool in tools), ANDROID_SYSTEM_TOOL_NAMES)
        self.assertEqual(len(set(ANDROID_SYSTEM_TOOL_NAMES)), 13)

    def test_every_declaration_is_correct(self) -> None:
        for tool in build_android_system_tools(create_default_android_bridge()):
            risk, permission, arguments, confirmation = DECLARATIONS[tool.name]
            with self.subTest(tool=tool.name):
                self.assertIs(tool.risk_level, risk)
                self.assertEqual(tool.required_permissions, (permission,))
                self.assertEqual(tool.argument_schema.names, arguments)
                self.assertEqual(tool.requires_confirmation, confirmation)
                self.assertIs(tool.platform, Platform.PC)
                # No system control is confirmation-mandatory: the policy decides.
                self.assertFalse(tool.confirmation_mandatory)

    def test_no_tool_exposes_a_confirmation_bypass_flag(self) -> None:
        for tool in build_android_system_tools(create_default_android_bridge()):
            names = set(tool.argument_schema.names)
            with self.subTest(tool=tool.name):
                self.assertEqual(names & {"confirm", "confirmation", "force", "skip"}, set())

    def test_no_tool_exposes_a_destination_command_or_api_name(self) -> None:
        forbidden = {
            "host", "ip", "port", "address", "url", "socket", "command", "cmd", "shell",
            "adb", "method", "api", "action", "stream", "ssid", "password", "path",
            "flags", "toggle", "script", "executable", "reason", "timeout",
        }
        for tool in build_android_system_tools(create_default_android_bridge()):
            with self.subTest(tool=tool.name):
                self.assertEqual(set(tool.argument_schema.names) & forbidden, set())

    def test_no_toggle_operation_exists(self) -> None:
        for name in ANDROID_SYSTEM_TOOL_NAMES:
            with self.subTest(tool=name):
                self.assertNotIn("toggle", name)

    def test_the_level_argument_is_bounded(self) -> None:
        self.assertEqual(LEVEL_ARGUMENT.type, int)
        self.assertEqual(LEVEL_ARGUMENT.min_value, 0)
        self.assertEqual(LEVEL_ARGUMENT.max_value, 100)
        schema = ArgumentSchema(LEVEL_ARGUMENT)
        for good in (0, 50, 100):
            self.assertEqual(schema.validate({"level": good})[1], [])
        for bad in (-1, 101, 1000, 50.5, "50", True, None):
            with self.subTest(bad=bad):
                self.assertNotEqual(schema.validate({"level": bad})[1], [])

    def test_unknown_arguments_are_rejected(self) -> None:
        tool = SetVolumeTool(AndroidSystemControl(FakeAndroidBridge()))
        _, errors = tool.argument_schema.validate(
            {"device": VALID_DEVICE, "level": 50, "stream": "STREAM_RING"}
        )
        self.assertNotEqual(errors, [])

    def test_describe_is_safe(self) -> None:
        for tool in build_android_system_tools(create_default_android_bridge()):
            with self.subTest(tool=tool.name):
                self.assertNotIn("private", repr(tool.describe()).lower())


class GuardTests(unittest.IsolatedAsyncioTestCase):
    async def test_off_a_pc_the_tools_report_unsupported_platform(self) -> None:
        control = AndroidSystemControl(FakeAndroidBridge())
        for tool in build_android_system_tools(
            FakeAndroidBridge(), platform_probe=lambda: Platform.ANDROID
        ):
            arguments = {"device": VALID_DEVICE}
            if "level" in tool.argument_schema.names:
                arguments["level"] = 50
            with self.subTest(tool=tool.name):
                result = await tool.execute(arguments, context(tool.name))
                self.assertEqual(result.error_code, ErrorCode.UNSUPPORTED_PLATFORM)

    async def test_an_unavailable_bridge_reports_android_bridge_unavailable(self) -> None:
        for tool in build_android_system_tools(FakeAndroidBridge(available=False)):
            arguments = {"device": VALID_DEVICE}
            if "level" in tool.argument_schema.names:
                arguments["level"] = 50
            with self.subTest(tool=tool.name):
                result = await tool.execute(arguments, context(tool.name))
                self.assertEqual(result.error_code, ErrorCode.ANDROID_BRIDGE_UNAVAILABLE)


@requires_crypto
class BehaviourTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.bridge, self.phone, _, _, _ = await system_phone_pair()
        self.did = self.phone.device_id
        self.tools = {t.name: t for t in build_android_system_tools(self.bridge)}

    async def call(self, name, **arguments):
        tool = self.tools[name]
        payload = {"device": self.did, **arguments}
        # The phone has to be serving for the bridge to get an answer.
        return await answered(tool.execute(payload, context(name)), self.phone)

    async def test_status(self) -> None:
        result = await self.call("android.system.status")
        self.assertTrue(result.success)
        self.assertEqual(result.data["volume"], 40)
        self.assertIn("Pixel 8", result.message)

    async def test_volume_flow(self) -> None:
        before = await self.call("android.system.get_volume")
        self.assertEqual(before.data["volume"], 40)
        change = await self.call("android.system.set_volume", level=88)
        self.assertTrue(change.success)
        self.assertEqual(change.data["volume"], 88)
        self.assertIn("88%", change.message)
        self.assertEqual(self.phone.controller.volume, 88)

    async def test_invalid_level_is_rejected_before_anything_is_sent(self) -> None:
        for bad in (-1, 101, 50.5, "50", True):
            with self.subTest(bad=bad):
                result = await self.call("android.system.set_volume", level=bad)
                self.assertEqual(result.status, ToolResultStatus.INVALID_ARGUMENT)
                self.assertFalse(result.success)
        self.assertEqual(self.phone.controller.volume, 40)

    async def test_mute_and_unmute(self) -> None:
        muted = await self.call("android.system.mute")
        self.assertTrue(muted.data["muted"])
        unmuted = await self.call("android.system.unmute")
        self.assertFalse(unmuted.data["muted"])

    async def test_brightness_flow_reports_adaptive_mode(self) -> None:
        self.phone.controller.adaptive = True
        result = await self.call("android.system.set_brightness", level=25)
        self.assertEqual(result.data["brightness"], 25)
        self.assertTrue(result.data["adaptive"])
        self.assertIn("adaptive", result.message)
        self.assertTrue(self.phone.controller.adaptive)

    async def test_wifi_and_bluetooth(self) -> None:
        off = await self.call("android.system.wifi.disable")
        self.assertFalse(off.data["enabled"])
        self.assertIn("off", off.message)
        status = await self.call("android.system.wifi.status")
        self.assertFalse(status.data["enabled"])
        on = await self.call("android.system.bluetooth.enable")
        self.assertTrue(on.data["enabled"])
        bt = await self.call("android.system.bluetooth.status")
        self.assertTrue(bt.data["enabled"])

    async def test_a_disconnected_device_reports_structured_unavailability(self) -> None:
        await answered(self.bridge.disconnect(self.did), self.phone)
        tool = self.tools["android.system.get_volume"]
        result = await tool.execute({"device": self.did}, context(tool.name))
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, ErrorCode.ANDROID_DEVICE_NOT_CONNECTED)
        self.assertEqual(result.status, ToolResultStatus.UNAVAILABLE)

    async def test_a_timeout_never_reports_success(self) -> None:
        self.phone.silent = True
        for name in ("android.system.get_volume", "android.system.set_volume"):
            with self.subTest(tool=name):
                tool = self.tools[name]
                payload = {"device": self.did}
                if "level" in tool.argument_schema.names:
                    payload["level"] = 50
                result = await answered(tool.execute(payload, context(name)), self.phone)
                self.assertFalse(result.success)
                self.assertEqual(result.error_code, ErrorCode.ANDROID_SYSTEM_TIMEOUT)

    async def test_a_phone_refusal_is_reported_structurally(self) -> None:
        self.phone.controller.denied.add("set_wifi_enabled")
        result = await self.call("android.system.wifi.disable")
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, ErrorCode.ANDROID_SYSTEM_PERMISSION_DENIED)
        self.assertTrue(self.phone.controller.wifi_enabled)

    async def test_an_unsupported_capability_is_reported_structurally(self) -> None:
        bridge, phone, _, _, _ = await system_phone_pair(
            capabilities=("bridge.protocol", "system.volume")
        )
        tools = {t.name: t for t in build_android_system_tools(bridge)}
        tool = tools["android.system.get_brightness"]
        result = await answered(
            tool.execute({"device": phone.device_id}, context(tool.name)), phone
        )
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, ErrorCode.ANDROID_CAPABILITY_UNAVAILABLE)

    async def test_no_result_leaks_key_material(self) -> None:
        for name in ("android.system.status", "android.system.get_volume"):
            with self.subTest(tool=name):
                result = await self.call(name)
                text = repr(result)
                self.assertNotIn(self.phone.private_key.hex()[:16], text)
                self.assertNotIn(self.bridge.host_identity.private_key.hex()[:16], text)
                self.assertNotIn("private_key", text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
