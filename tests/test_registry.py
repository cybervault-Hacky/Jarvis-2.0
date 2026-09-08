"""Tool registry tests (Phase 1)."""

from __future__ import annotations

import unittest

from jarvis_devices import (
    ArgumentSchema,
    ArgumentSpec,
    DuplicateToolError,
    InvalidToolError,
    Platform,
    RiskLevel,
    UnknownToolError,
)
from jarvis_devices.registry import DeviceToolRegistry, validate_tool

try:  # imported as part of the ``tests`` package (pytest / discover -t .)
    from .support import BrokenTool, FakeDeviceTool, NotATool
except ImportError:  # ``python -m unittest discover -s tests``
    from support import BrokenTool, FakeDeviceTool, NotATool


class RegistryRegistrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = DeviceToolRegistry()

    def test_register_then_get_returns_same_tool(self) -> None:
        tool = FakeDeviceTool("pc.audio.volume", platform=Platform.PC)
        self.registry.register(tool)
        self.assertIs(self.registry.get("pc.audio.volume"), tool)

    def test_register_returns_the_tool(self) -> None:
        tool = FakeDeviceTool("pc.audio.volume", platform=Platform.PC)
        self.assertIs(self.registry.register(tool), tool)

    def test_register_all(self) -> None:
        tools = [
            FakeDeviceTool("pc.audio.volume", platform=Platform.PC),
            FakeDeviceTool("android.sms.send", platform=Platform.ANDROID),
        ]
        self.registry.register_all(tools)
        self.assertEqual(self.registry.names(), ("android.sms.send", "pc.audio.volume"))

    def test_lookup_is_case_insensitive_and_trimmed(self) -> None:
        tool = FakeDeviceTool("pc.audio.volume", platform=Platform.PC)
        self.registry.register(tool)
        self.assertIs(self.registry.get("  PC.Audio.Volume "), tool)

    def test_duplicate_registration_is_rejected(self) -> None:
        self.registry.register(FakeDeviceTool("pc.audio.volume", platform=Platform.PC))
        with self.assertRaises(DuplicateToolError):
            self.registry.register(FakeDeviceTool("pc.audio.volume", platform=Platform.PC))
        self.assertEqual(len(self.registry), 1)

    def test_uppercase_names_are_rejected_so_they_cannot_shadow_a_tool(self) -> None:
        self.registry.register(FakeDeviceTool("pc.audio.volume", platform=Platform.PC))
        with self.assertRaises(InvalidToolError):
            self.registry.register(FakeDeviceTool("PC.Audio.Volume", platform=Platform.PC))
        # ...but lookups stay forgiving.
        self.assertIsNotNone(self.registry.find("PC.Audio.Volume"))

    def test_duplicate_registration_allowed_with_override(self) -> None:
        first = FakeDeviceTool("pc.audio.volume", platform=Platform.PC)
        second = FakeDeviceTool("pc.audio.volume", platform=Platform.PC, risk_level=RiskLevel.LOW_RISK)
        self.registry.register(first)
        self.registry.register(second, override=True)
        self.assertIs(self.registry.get("pc.audio.volume"), second)
        self.assertEqual(len(self.registry), 1)


class RegistryValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = DeviceToolRegistry()

    def test_rejects_object_that_is_not_a_device_tool(self) -> None:
        with self.assertRaises(InvalidToolError):
            self.registry.register(NotATool())  # type: ignore[arg-type]

    def test_rejects_invalid_name(self) -> None:
        for bad_name in ("", "Bad Name", "1starts_with_digit", "semi;colon", "UPPER"):
            with self.subTest(name=bad_name):
                with self.assertRaises(InvalidToolError):
                    self.registry.register(FakeDeviceTool(bad_name, platform=Platform.PC))

    def test_rejects_missing_description(self) -> None:
        tool = FakeDeviceTool("pc.audio.volume", platform=Platform.PC)
        tool.description = "   "
        with self.assertRaises(InvalidToolError):
            self.registry.register(tool)

    def test_rejects_bad_platform_and_risk_level(self) -> None:
        bad_platform = FakeDeviceTool("pc.audio.volume", platform=Platform.PC)
        bad_platform.platform = "pc"  # type: ignore[assignment]
        with self.assertRaises(InvalidToolError):
            self.registry.register(bad_platform)

        bad_risk = FakeDeviceTool("pc.audio.volume", platform=Platform.PC)
        bad_risk.risk_level = "destructive"  # type: ignore[assignment]
        with self.assertRaises(InvalidToolError):
            self.registry.register(bad_risk)

    def test_rejects_string_permissions(self) -> None:
        tool = FakeDeviceTool("pc.audio.volume", platform=Platform.PC)
        tool.required_permissions = "device.settings.write"  # type: ignore[assignment]
        with self.assertRaises(InvalidToolError):
            self.registry.register(tool)

    def test_rejects_non_bool_confirmation_override(self) -> None:
        tool = FakeDeviceTool("pc.audio.volume", platform=Platform.PC)
        tool.requires_confirmation = "yes"  # type: ignore[assignment]
        with self.assertRaises(InvalidToolError):
            self.registry.register(tool)

    def test_rejects_missing_argument_schema(self) -> None:
        tool = FakeDeviceTool("pc.audio.volume", platform=Platform.PC)
        tool.argument_schema = {"direction": str}  # type: ignore[assignment]
        with self.assertRaises(InvalidToolError):
            self.registry.register(tool)

    def test_validate_tool_accepts_a_well_formed_tool(self) -> None:
        tool = FakeDeviceTool(
            "pc.audio.volume",
            platform=Platform.PC,
            risk_level=RiskLevel.LOW_RISK,
            required_permissions=("device.media.control",),
            argument_schema=ArgumentSchema(ArgumentSpec("direction", choices=("up", "down"))),
        )
        self.assertIsNone(validate_tool(tool))


class RegistryLookupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = DeviceToolRegistry()
        self.pc_tool = FakeDeviceTool("pc.audio.volume", platform=Platform.PC)
        self.android_tool = FakeDeviceTool("android.sms.send", platform=Platform.ANDROID)
        self.unavailable_tool = FakeDeviceTool("pc.power.shutdown", platform=Platform.PC, available=False)
        self.registry.register_all([self.pc_tool, self.android_tool, self.unavailable_tool])

    def test_missing_tool_raises_unknown_tool_error(self) -> None:
        with self.assertRaises(UnknownToolError):
            self.registry.get("does.not.exist")

    def test_find_returns_none_for_missing_tool(self) -> None:
        self.assertIsNone(self.registry.find("does.not.exist"))

    def test_list_tools_returns_everything_sorted(self) -> None:
        self.assertEqual(
            [tool.name for tool in self.registry.list_tools()],
            ["android.sms.send", "pc.audio.volume", "pc.power.shutdown"],
        )

    def test_list_tools_filters_by_platform(self) -> None:
        names = [tool.name for tool in self.registry.list_tools(platform=Platform.ANDROID)]
        self.assertEqual(names, ["android.sms.send"])

    def test_list_tools_filters_by_risk_and_availability(self) -> None:
        self.assertEqual(
            [tool.name for tool in self.registry.list_tools(available_only=True)],
            ["android.sms.send", "pc.audio.volume"],
        )
        self.assertEqual(
            [tool.name for tool in self.registry.list_tools(risk_level=RiskLevel.SAFE)],
            ["android.sms.send", "pc.audio.volume", "pc.power.shutdown"],
        )

    def test_is_available(self) -> None:
        self.assertTrue(self.registry.is_available("pc.audio.volume"))
        self.assertFalse(self.registry.is_available("pc.power.shutdown"))
        self.assertFalse(self.registry.is_available("does.not.exist"))

    def test_is_available_is_false_when_the_probe_raises(self) -> None:
        self.registry.register(BrokenTool("pc.broken", platform=Platform.PC))
        self.assertFalse(self.registry.is_available("pc.broken"))

    def test_contains_and_len(self) -> None:
        self.assertIn("pc.audio.volume", self.registry)
        self.assertNotIn("does.not.exist", self.registry)
        self.assertEqual(len(self.registry), 3)

    def test_describe_exposes_metadata(self) -> None:
        described = {entry["name"]: entry for entry in self.registry.describe()}
        self.assertEqual(described["pc.audio.volume"]["platform"], "pc")
        self.assertEqual(described["pc.audio.volume"]["risk_level"], "safe")
        self.assertFalse(described["pc.power.shutdown"]["available"])


class RegistryUnregisterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = DeviceToolRegistry()
        self.tool = FakeDeviceTool("pc.audio.volume", platform=Platform.PC)
        self.registry.register(self.tool)

    def test_unregister_by_name(self) -> None:
        self.assertTrue(self.registry.unregister("pc.audio.volume"))
        self.assertEqual(self.registry.names(), ())
        with self.assertRaises(UnknownToolError):
            self.registry.get("pc.audio.volume")

    def test_unregister_by_tool_object(self) -> None:
        self.assertTrue(self.registry.unregister(self.tool))
        self.assertEqual(len(self.registry), 0)

    def test_unregister_unknown_returns_false(self) -> None:
        self.assertFalse(self.registry.unregister("does.not.exist"))

    def test_re_register_after_unregister(self) -> None:
        self.registry.unregister(self.tool)
        self.registry.register(self.tool)  # must not be treated as a duplicate
        self.assertEqual(self.registry.names(), ("pc.audio.volume",))

    def test_clear(self) -> None:
        self.registry.clear()
        self.assertEqual(len(self.registry), 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
