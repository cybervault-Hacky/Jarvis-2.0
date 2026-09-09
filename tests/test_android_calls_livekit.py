"""Real LiveKit FunctionTool integration harness for Phase 7."""

from __future__ import annotations

import asyncio
import inspect
import unittest

try:  # The project supports source-only test environments as well.
    from livekit.agents import Agent, FunctionTool
except ImportError:  # pragma: no cover
    Agent = None  # type: ignore[assignment,misc]
    FunctionTool = None  # type: ignore[assignment,misc]


@unittest.skipUnless(FunctionTool is not None, "livekit-agents is not installed")
class LiveKitCallToolTests(unittest.TestCase):
    def test_real_function_tools_have_exact_names_and_required_signatures(self) -> None:
        import Jarvis_device_control as bridge

        expected = {
            "android_call_status": ("device",),
            "android_call_dial": ("device", "phone_number"),
            "android_call_answer": ("device",),
            "android_call_reject": ("device",),
            "android_call_end": ("device",),
        }
        tools = []
        for name, parameters in expected.items():
            tool = getattr(bridge, name)
            tools.append(tool)
            with self.subTest(name=name):
                self.assertIsInstance(tool, FunctionTool)
                self.assertEqual(tuple(inspect.signature(tool).parameters), parameters)
                info = getattr(tool, "__livekit_tool_info")
                self.assertEqual(info.name, name)
                self.assertTrue(info.description)
        self.assertEqual(len({id(tool) for tool in tools}), 5)
        agent = Agent(instructions="test", tools=tools)
        self.assertEqual([tool.__name__ for tool in agent.tools], list(expected))

    def test_real_dial_tool_requires_approval_before_the_registered_action(self) -> None:
        import Jarvis_device_control as bridge

        async def harness() -> str:
            return await bridge.android_call_dial("adev-" + "a" * 32, "+1 (415) 555-2671")

        result = asyncio.run(harness())
        self.assertIn("Confirmation required", result)
        self.assertIn("+14155552671", result)
        # Clean up the in-memory request that the real wrapper deliberately
        # created; no device action can have occurred before a yes.
        pending = [item for item in bridge.device_confirmations.pending() if item.action == "android.call.dial"]
        self.assertTrue(pending)
        bridge.device_confirmations.cancel(pending[-1].confirmation_id)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
