"""Real LiveKit FunctionTool integration harness for Phase 8 messaging."""

from __future__ import annotations

import asyncio
import inspect
import unittest

try:  # The source-only suite remains usable without optional LiveKit installed.
    from livekit.agents import Agent, FunctionTool
except ImportError:  # pragma: no cover
    Agent = None  # type: ignore[assignment,misc]
    FunctionTool = None  # type: ignore[assignment,misc]


@unittest.skipUnless(FunctionTool is not None, "livekit-agents is not installed")
class LiveKitMessageToolTests(unittest.TestCase):
    def test_real_function_tools_have_exact_names_signatures_and_no_duplicates(self) -> None:
        import Jarvis_device_control as bridge

        expected = {
            "android_message_status": ("device",),
            "android_message_send": ("device", "recipient", "message"),
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
        agent = Agent(instructions="test", tools=tools)
        self.assertEqual([tool.__name__ for tool in agent.tools], list(expected))
        self.assertEqual(len({id(tool) for tool in tools}), 2)

    def test_real_send_wrapper_creates_exact_confirmation_before_registered_execution(self) -> None:
        import Jarvis_device_control as bridge

        async def harness() -> str:
            return await bridge.android_message_send(
                "adev-" + "a" * 32, "+1 (415) 555-2671", "Hello, नमस्ते 👋"
            )

        result = asyncio.run(harness())
        self.assertIn("Confirmation required", result)
        self.assertIn("+14155552671", result)
        self.assertIn("Hello, नमस्ते 👋", result)
        pending = [item for item in bridge.device_confirmations.pending() if item.action == "android.message.send"]
        self.assertTrue(pending)
        bridge.device_confirmations.cancel(pending[-1].confirmation_id)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
