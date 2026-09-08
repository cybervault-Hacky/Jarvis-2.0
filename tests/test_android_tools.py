"""Phase 5 tests: the six Android bridge tools and their declarations."""

from __future__ import annotations

import unittest

from jarvis_devices import ErrorCode
from jarvis_devices.arguments import ArgumentSchema
from jarvis_devices.android_bridge import (
    AndroidBridgeUnavailableError,
    AndroidCapabilityUnavailableError,
    AndroidConnectionError,
    AndroidDeviceNotPairedError,
    AndroidDeviceRevokedError,
    AndroidDeviceUnknownError,
    AndroidPairingError,
    AndroidPairingExpiredError,
    AndroidPairingUnknownError,
    SUPPORTED_CAPABILITIES,
    create_default_android_bridge,
)
from jarvis_devices.android_tools import (
    ANDROID_BRIDGE_TOOL_NAMES,
    DEVICE_ID_ARGUMENT,
    DEVICE_ID_PATTERN,
    PAIRING_ID_ARGUMENT,
    PAIRING_ID_PATTERN,
    BridgeStatusTool,
    DeviceListTool,
    DevicePairTool,
    DeviceRevokeTool,
    DeviceStatusTool,
    DeviceUnpairTool,
    build_android_bridge_tools,
)
from jarvis_devices.android_identity import AndroidHostIdentity, TrustState
from jarvis_devices.enums import Platform, RiskLevel, ToolResultStatus
from jarvis_devices.permissions import (
    PERMISSION_ANDROID_BRIDGE_MANAGE,
    PERMISSION_ANDROID_BRIDGE_PAIR,
    PERMISSION_DEVICE_STATUS_READ,
)

try:
    from .android_support import FakeAndroidBridge, requires_crypto, started_pair, complete_pairing
except ImportError:
    from android_support import FakeAndroidBridge, requires_crypto, started_pair, complete_pairing

VALID_DEVICE = "adev-" + "a" * 32
VALID_PAIRING = "pair-" + "b" * 32


def build(bridge, platform: Platform = Platform.PC):
    return build_android_bridge_tools(bridge, platform_probe=lambda: platform)


class DeclarationTests(unittest.TestCase):
    """The tool contract, checked without needing the signature library."""

    def test_exactly_six_tools_with_the_expected_names(self) -> None:
        tools = build(FakeAndroidBridge())
        self.assertEqual(len(tools), 6)
        self.assertEqual(tuple(tool.name for tool in tools), ANDROID_BRIDGE_TOOL_NAMES)
        self.assertEqual(len(set(ANDROID_BRIDGE_TOOL_NAMES)), 6)

    def test_no_low_level_tool_is_exposed(self) -> None:
        for name in ANDROID_BRIDGE_TOOL_NAMES:
            with self.subTest(tool=name):
                for forbidden in ("raw", "socket", "send", "execute", "adb", "shell", "command"):
                    self.assertNotIn(forbidden, name)

    def test_risk_levels_and_permissions(self) -> None:
        expected = {
            "android.bridge.status": (RiskLevel.SAFE, (PERMISSION_DEVICE_STATUS_READ,), False),
            "android.device.list": (RiskLevel.SAFE, (PERMISSION_DEVICE_STATUS_READ,), False),
            "android.device.status": (RiskLevel.SAFE, (PERMISSION_DEVICE_STATUS_READ,), False),
            "android.device.pair": (
                RiskLevel.EXTERNAL_ACTION,
                (PERMISSION_ANDROID_BRIDGE_PAIR,),
                True,
            ),
            "android.device.unpair": (
                RiskLevel.EXTERNAL_ACTION,
                (PERMISSION_ANDROID_BRIDGE_MANAGE,),
                True,
            ),
            "android.device.revoke": (
                RiskLevel.EXTERNAL_ACTION,
                (PERMISSION_ANDROID_BRIDGE_MANAGE,),
                True,
            ),
        }
        for tool in build(FakeAndroidBridge()):
            with self.subTest(tool=tool.name):
                risk, permissions, mandatory = expected[tool.name]
                self.assertIs(tool.risk_level, risk)
                self.assertEqual(tool.required_permissions, permissions)
                self.assertIs(tool.platform, Platform.PC)
                self.assertEqual(tool.confirmation_mandatory, mandatory)
                if mandatory:
                    self.assertTrue(tool.requires_confirmation)

    def test_arguments_are_only_ids(self) -> None:
        expected = {
            "android.bridge.status": (),
            "android.device.list": (),
            "android.device.status": ("device",),
            "android.device.pair": ("pairing",),
            "android.device.unpair": ("device",),
            "android.device.revoke": ("device",),
        }
        forbidden = {
            "host", "ip", "port", "address", "url", "command", "cmd", "shell",
            "flags", "path", "adb", "timeout", "force", "reason", "script",
        }
        for tool in build(FakeAndroidBridge()):
            with self.subTest(tool=tool.name):
                self.assertEqual(tool.argument_schema.names, expected[tool.name])
                self.assertEqual(set(tool.argument_schema.names) & forbidden, set())

    def test_the_id_arguments_are_strict(self) -> None:
        for spec, valid, invalid in (
            (DEVICE_ID_ARGUMENT, VALID_DEVICE, ["192.168.1.50", "pixel.lan", "AA:BB:CC:DD:EE:FF", "adev-short", "adev-" + "g" * 32, ""]),
            (PAIRING_ID_ARGUMENT, VALID_PAIRING, ["pair-short", "pair-" + "z" * 32, VALID_DEVICE, ""]),
        ):
            with self.subTest(argument=spec.name):
                self.assertEqual(spec.type, str)
                self.assertTrue(spec.required)
                self.assertEqual(spec.max_length, 37)
                schema = ArgumentSchema(spec)
                self.assertEqual(schema.validate({spec.name: valid})[1], [])
                for bad in invalid:
                    with self.subTest(bad=bad):
                        self.assertNotEqual(schema.validate({spec.name: bad})[1], [])

    def test_a_trailing_newline_cannot_sneak_through_the_pattern(self) -> None:
        schema = ArgumentSchema(DEVICE_ID_ARGUMENT)
        self.assertNotEqual(schema.validate({"device": VALID_DEVICE + "\n"})[1], [])

    def test_unknown_arguments_are_rejected(self) -> None:
        tool = DeviceStatusTool(FakeAndroidBridge())
        validated, errors = tool.argument_schema.validate(
            {"device": VALID_DEVICE, "command": "shutdown /s"}
        )
        self.assertNotEqual(errors, [])

    def test_tools_are_available_only_when_the_bridge_is(self) -> None:
        ready = FakeAndroidBridge(available=True)
        down = FakeAndroidBridge(available=False)
        for tool in build(ready):
            with self.subTest(tool=tool.name):
                self.assertTrue(tool.is_available())
        for tool in build(down):
            with self.subTest(tool=tool.name):
                self.assertFalse(tool.is_available())

    def test_describe_is_safe(self) -> None:
        for tool in build(FakeAndroidBridge()):
            summary = tool.describe()
            with self.subTest(tool=tool.name):
                self.assertEqual(summary["name"], tool.name)
                self.assertNotIn("private", repr(summary).lower())


#: Valid arguments per tool. ``execute`` validates arguments *before* it calls
#: ``run``, so a platform test has to supply them or it would only ever see an
#: ``invalid_argument`` failure.
VALID_ARGUMENTS = {
    "android.bridge.status": {},
    "android.device.list": {},
    "android.device.status": {"device": VALID_DEVICE},
    "android.device.pair": {"pairing": VALID_PAIRING},
    "android.device.unpair": {"device": VALID_DEVICE},
    "android.device.revoke": {"device": VALID_DEVICE},
}


class PlatformGuardTests(unittest.IsolatedAsyncioTestCase):
    async def test_off_a_pc_the_tools_report_unsupported_platform(self) -> None:
        for tool in build(FakeAndroidBridge(), platform=Platform.ANDROID):
            with self.subTest(tool=tool.name):
                result = await tool.execute(VALID_ARGUMENTS[tool.name], _context(tool.name))
                self.assertEqual(result.error_code, ErrorCode.UNSUPPORTED_PLATFORM)
                self.assertFalse(result.success)

    async def test_an_unavailable_bridge_reports_android_bridge_unavailable(self) -> None:
        tool = BridgeStatusTool(FakeAndroidBridge(available=False))
        result = await tool.execute({}, _context(tool.name))
        self.assertEqual(result.error_code, ErrorCode.ANDROID_BRIDGE_UNAVAILABLE)
        self.assertFalse(result.success)


def _context(tool_name: str):
    from jarvis_devices import ToolContext, new_execution_id

    return ToolContext(execution_id=new_execution_id(), tool_name=tool_name, platform=Platform.PC)


@requires_crypto
class ReadToolTests(unittest.IsolatedAsyncioTestCase):
    async def test_bridge_status_reports_the_bridge(self) -> None:
        bridge = FakeAndroidBridge()
        bridge.results["status"] = {
            "available": True,
            "protocol_version": 1,
            "transport": {"transport": "in-memory", "open": True},
            "devices": 1,
            "paired_devices": 1,
            "connected_devices": 0,
            "capabilities_understood": list(SUPPORTED_CAPABILITIES),
        }
        bridge.pairings = [{"pairing_id": VALID_PAIRING, "display_name": "Pixel 8", "status": "verified"}]
        tool = BridgeStatusTool(bridge)
        result = await tool.execute({}, _context(tool.name))
        self.assertTrue(result.success)
        self.assertEqual(result.data["devices"], 1)
        self.assertEqual(result.data["pending_pairings"][0]["display_name"], "Pixel 8")
        self.assertEqual(bridge.call_names, ["status", "pending_pairings"])
        self.assertNotIn("private", repr(result.data).lower())

    async def test_device_list_reports_an_empty_registry_honestly(self) -> None:
        bridge = FakeAndroidBridge()
        tool = DeviceListTool(bridge)
        result = await tool.execute({}, _context(tool.name))
        self.assertTrue(result.success)
        self.assertEqual(result.data["count"], 0)
        self.assertIn("No Android devices", result.message)

    async def test_device_list_reports_devices(self) -> None:
        bridge = FakeAndroidBridge()
        bridge.devices = [{"device_id": VALID_DEVICE, "display_name": "Pixel 8", "trust_state": "paired"}]
        tool = DeviceListTool(bridge)
        result = await tool.execute({}, _context(tool.name))
        self.assertEqual(result.data["count"], 1)

    async def test_device_status_needs_a_valid_id(self) -> None:
        tool = DeviceStatusTool(FakeAndroidBridge())
        for bad in ("192.168.1.50", "adb shell", "", "adev-short"):
            with self.subTest(bad=bad):
                result = await tool.execute({"device": bad}, _context(tool.name))
                self.assertEqual(result.status, ToolResultStatus.INVALID_ARGUMENT)
                self.assertFalse(result.success)

    async def test_device_status_reports_the_device(self) -> None:
        bridge = FakeAndroidBridge()
        bridge.results["device_status"] = {
            "device_id": VALID_DEVICE,
            "display_name": "Pixel 8",
            "trust_state": "paired",
            "health": "healthy",
        }
        tool = DeviceStatusTool(bridge)
        result = await tool.execute({"device": VALID_DEVICE}, _context(tool.name))
        self.assertTrue(result.success)
        self.assertIn("Pixel 8", result.message)


@requires_crypto
class TrustToolTests(unittest.IsolatedAsyncioTestCase):
    async def test_pair_approves_a_verified_pairing(self) -> None:
        bridge = FakeAndroidBridge()
        bridge.results["approve_pairing"] = {
            "device_id": VALID_DEVICE,
            "display_name": "Pixel 8",
            "fingerprint": "AAAA-BBBB",
            "trust_state": TrustState.PAIRED.value,
        }
        tool = DevicePairTool(bridge)
        result = await tool.execute({"pairing": VALID_PAIRING}, _context(tool.name))
        self.assertTrue(result.success)
        self.assertEqual(result.data["trust_state"], "paired")
        self.assertEqual(bridge.call_names, ["approve_pairing"])

    async def test_unpair_forgets_the_device(self) -> None:
        bridge = FakeAndroidBridge()
        tool = DeviceUnpairTool(bridge)
        result = await tool.execute({"device": VALID_DEVICE}, _context(tool.name))
        self.assertTrue(result.success)
        self.assertTrue(result.data["removed"])

    async def test_revoke_blocks_the_device(self) -> None:
        bridge = FakeAndroidBridge()
        tool = DeviceRevokeTool(bridge)
        result = await tool.execute({"device": VALID_DEVICE}, _context(tool.name))
        self.assertTrue(result.success)
        self.assertEqual(result.data["trust_state"], "revoked")

    async def test_bridge_errors_become_structured_results(self) -> None:
        cases = (
            (DevicePairTool, "approve_pairing", AndroidPairingUnknownError("unknown pairing"), ErrorCode.ANDROID_PAIRING_UNKNOWN),
            (DevicePairTool, "approve_pairing", AndroidPairingExpiredError("expired"), ErrorCode.ANDROID_PAIRING_EXPIRED),
            (DevicePairTool, "approve_pairing", AndroidPairingError("not verified"), ErrorCode.ANDROID_PAIRING_FAILED),
            (DeviceStatusTool, "device_status", AndroidDeviceUnknownError("unknown"), ErrorCode.ANDROID_DEVICE_UNKNOWN),
            (DeviceStatusTool, "device_status", AndroidDeviceNotPairedError("not paired"), ErrorCode.ANDROID_DEVICE_NOT_PAIRED),
            (DeviceUnpairTool, "unpair", AndroidDeviceRevokedError("revoked"), ErrorCode.ANDROID_DEVICE_REVOKED),
            (DeviceRevokeTool, "revoke", AndroidDeviceUnknownError("unknown"), ErrorCode.ANDROID_DEVICE_UNKNOWN),
        )
        for tool_class, method, error, code in cases:
            with self.subTest(tool=tool_class.__name__, error=type(error).__name__):
                bridge = FakeAndroidBridge()
                bridge.raise_on[method] = error
                tool = tool_class(bridge)
                arguments = {"pairing": VALID_PAIRING} if tool_class is DevicePairTool else {"device": VALID_DEVICE}
                result = await tool.execute(arguments, _context(tool.name))
                self.assertEqual(result.error_code, code)
                self.assertFalse(result.success)

    async def test_an_unexpected_exception_is_never_reported_as_success(self) -> None:
        """A crash becomes a structured TOOL_ERROR, never a success."""
        bridge = FakeAndroidBridge()
        bridge.raise_on["approve_pairing"] = RuntimeError("kaboom")
        tool = DevicePairTool(bridge)
        result = await tool.execute({"pairing": VALID_PAIRING}, _context(tool.name))
        self.assertFalse(result.success)
        self.assertEqual(result.status, ToolResultStatus.FAILED)
        self.assertEqual(result.error_code, ErrorCode.TOOL_ERROR)


@requires_crypto
class RealBridgeToolTests(unittest.IsolatedAsyncioTestCase):
    """The tools driving a real bridge with a real (fake) phone on the other end."""

    async def asyncSetUp(self) -> None:
        self.bridge, self.phone, _, _ = await started_pair()
        self.record = await complete_pairing(self.bridge, self.phone)
        self.tools = {tool.name: tool for tool in build(self.bridge)}

    async def run_tool(self, name, arguments=None):
        tool = self.tools[name]
        return await tool.execute(arguments or {}, _context(tool.name))

    async def test_status_and_list_see_the_real_pairing(self) -> None:
        status = await self.run_tool("android.bridge.status")
        self.assertTrue(status.success)
        self.assertEqual(status.data["devices"], 1)
        self.assertEqual(status.data["paired_devices"], 1)

        listing = await self.run_tool("android.device.list")
        self.assertEqual(listing.data["count"], 1)
        self.assertEqual(listing.data["devices"][0]["device_id"], self.phone.device_id)

        detail = await self.run_tool("android.device.status", {"device": self.phone.device_id})
        self.assertTrue(detail.success)
        self.assertEqual(detail.data["trust_state"], TrustState.PAIRED.value)

    async def test_revoke_through_the_tool_blocks_the_device(self) -> None:
        result = await self.run_tool("android.device.revoke", {"device": self.phone.device_id})
        self.assertTrue(result.success)
        detail = await self.run_tool("android.device.status", {"device": self.phone.device_id})
        self.assertEqual(detail.data["trust_state"], TrustState.REVOKED.value)

    async def test_an_unpaired_device_id_is_refused(self) -> None:
        result = await self.run_tool("android.device.status", {"device": "adev-" + "0" * 32})
        self.assertEqual(result.error_code, ErrorCode.ANDROID_DEVICE_UNKNOWN)

    async def test_no_tool_result_contains_key_material(self) -> None:
        for name, arguments in (
            ("android.bridge.status", {}),
            ("android.device.list", {}),
            ("android.device.status", {"device": self.phone.device_id}),
        ):
            with self.subTest(tool=name):
                result = await self.run_tool(name, arguments)
                text = repr(result)
                self.assertNotIn(self.phone.private_key.hex()[:16], text)
                self.assertNotIn(self.bridge.host_identity.private_key.hex()[:16], text)
                self.assertNotIn("private_key", text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
