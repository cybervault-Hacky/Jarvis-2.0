"""Real LiveKit wiring tests for Phase 9's intentionally read-only surface."""

from __future__ import annotations

import asyncio
import inspect
import unittest

try:  # Keep source-only verification usable without optional LiveKit.
    from livekit.agents import Agent, FunctionTool
except ImportError:  # pragma: no cover
    Agent = None  # type: ignore[assignment,misc]
    FunctionTool = None  # type: ignore[assignment,misc]


@unittest.skipUnless(FunctionTool is not None, "livekit-agents is not installed")
class LiveKitCrossDeviceToolTests(unittest.TestCase):
    def test_real_function_tools_are_zero_argument_read_only_tools(self) -> None:
        import Jarvis_device_control as bridge

        expected = ("cross_device_status", "cross_device_capabilities")
        tools = []
        for name in expected:
            tool = getattr(bridge, name)
            tools.append(tool)
            with self.subTest(name=name):
                self.assertIsInstance(tool, FunctionTool)
                self.assertEqual(tuple(inspect.signature(tool).parameters), ())
                info = getattr(tool, "__livekit_tool_info")
                self.assertEqual(info.name, name)
                self.assertTrue(info.description)
                self.assertNotIn("execute", info.name)
        agent = Agent(instructions="test", tools=tools)
        self.assertEqual([tool.__name__ for tool in agent.tools], list(expected))
        self.assertEqual(len({id(tool) for tool in tools}), 2)

    def test_real_status_wrapper_uses_registered_manager_tool_without_action(self) -> None:
        import Jarvis_device_control as bridge

        before = len(bridge.device_manager.audit.records)
        answer = asyncio.run(bridge.cross_device_status())
        self.assertTrue(answer.startswith("✅ cross.device.status:"), answer)
        events = bridge.device_manager.audit.records[before:]
        self.assertTrue(any(item.get("tool") == "cross.device.status" for item in events))
        self.assertFalse(any(item.get("event") == "cross_device_plan_submitted" for item in events))
        self.assertFalse(hasattr(bridge, "cross_device_execute"))
        self.assertFalse(hasattr(bridge, "cross_device_plan"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
