"""Integration tests: the Phase 1 framework must not break JARVIS (Phase 1).

Two things are verified:

1. ``agent.py`` still wires up every pre-existing tool, plus the two new bridge
   tools (checked on the AST so it works whether or not LiveKit is installed).
2. ``agent.py`` and every pre-existing JARVIS module still import, and the new
   bridge is reachable from the agent module.

Third-party modules that are not installed in the current environment are
replaced by inert stubs for the duration of the import test only.
"""

from __future__ import annotations

import ast
import importlib
import sys
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

EXISTING_TOOLS = [
    "google_search",
    "get_current_datetime",
    "get_weather",
    "open",
    "close",
    "folder_file",
    "Play_file",
    "move_cursor_tool",
    "mouse_click_tool",
    "scroll_cursor_tool",
    "type_text_tool",
    "press_key_tool",
    "press_hotkey_tool",
    "control_volume_tool",
    "swipe_gesture_tool",
]

NEW_TOOLS = [
    "device_action",
    "device_confirmation",
    # Phase 2 - PC application control
    "list_open_applications",
    "application_status",
    "open_application",
    "focus_application",
    "close_application",
    # Phase 3 - PC system control
    "system_status",
    "get_system_volume",
    "set_system_volume",
    "mute_system",
    "unmute_system",
    "get_system_mute",
    "get_system_brightness",
    "set_system_brightness",
    "wifi_status",
    "wifi_enable",
    "wifi_disable",
    "bluetooth_status",
    "bluetooth_enable",
    "bluetooth_disable",
    # Phase 4 - PC power control
    "shutdown_pc",
    "restart_pc",
    "sleep_pc",
    "hibernate_pc",
    "logoff_pc",
    # Phase 5 - Android device bridge
    "android_bridge_status",
    "android_device_list",
    "android_device_status",
    "android_device_pair",
    "android_device_unpair",
    "android_device_revoke",
    # Phase 6 - Android system control
    "android_system_status",
    "android_get_volume",
    "android_set_volume",
    "android_mute",
    "android_unmute",
    "android_get_brightness",
    "android_set_brightness",
    "android_wifi_status",
    "android_wifi_enable",
    "android_wifi_disable",
    "android_bluetooth_status",
    "android_bluetooth_enable",
    "android_bluetooth_disable",
    # Phase 7 - Android calls
    "android_call_status",
    "android_call_dial",
    "android_call_answer",
    "android_call_reject",
    "android_call_end",
]

EXISTING_MODULES = [
    "Jarvis_prompts",
    "Jarvis_google_search",
    "jarvis_get_whether",
    "Jarvis_file_opner",
    "Jarvis_window_CTRL",
    "keyboard_mouse_CTRL",
    "Jarvis_device_control",
]

THIRD_PARTY_MODULES = [
    "dotenv",
    "requests",
    "fuzzywuzzy",
    "fuzzywuzzy.process",
    "pyautogui",
    "pynput",
    "pynput.keyboard",
    "pynput.mouse",
    "livekit",
    "livekit.agents",
    "livekit.plugins",
    "livekit.plugins.google",
    "livekit.plugins.noise_cancellation",
    "pygetwindow",
    "win32gui",
    "win32con",
]


class _Stub(types.ModuleType):
    """Inert stand-in for a third-party module."""

    def __getattr__(self, item):
        if item.startswith("__"):
            raise AttributeError(item)
        child = _Stub(f"{self.__name__}.{item}")
        setattr(self, item, child)
        return child

    def __call__(self, *args, **kwargs):
        # Behave like a decorator factory (@function_tool) or a plain call.
        if len(args) == 1 and not kwargs and callable(args[0]):
            return args[0]
        return _Stub(f"{self.__name__}()")

    def __mro_entries__(self, bases):
        # Allow ``class Assistant(Agent)`` when ``Agent`` is a stub.
        class _StubBase:
            def __init__(self, *args, **kwargs):
                self.args = args
                self.kwargs = kwargs

            def __getattr__(self, item):
                return _Stub(f"stub.{item}")

        return (_StubBase,)


def _install_stubs() -> dict:
    installed = {}
    for name in THIRD_PARTY_MODULES:
        try:
            importlib.import_module(name)
        except Exception:
            installed[name] = sys.modules.get(name)
            sys.modules[name] = _Stub(name)
    return installed


def _restore_stubs(installed: dict) -> None:
    for name, previous in installed.items():
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous


def _tools_declared_in_agent() -> list:
    """Read the ``tools=[...]`` list out of ``agent.py``."""
    tree = ast.parse((ROOT / "agent.py").read_text(encoding="utf-8"))
    declared = []
    for node in ast.walk(tree):
        is_super_init = (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "__init__"
            and isinstance(node.func.value, ast.Call)  # super()
            and isinstance(node.func.value.func, ast.Name)
            and node.func.value.func.id == "super"
        )
        if not is_super_init:
            continue
        for keyword in node.keywords:
            if keyword.arg == "tools" and isinstance(keyword.value, (ast.List, ast.Tuple)):
                declared.extend(
                    element.id for element in keyword.value.elts if isinstance(element, ast.Name)
                )
    return declared


class AgentWiringTests(unittest.TestCase):
    def test_existing_tools_are_still_registered(self) -> None:
        declared = _tools_declared_in_agent()
        for name in EXISTING_TOOLS:
            with self.subTest(tool=name):
                self.assertIn(name, declared)

    def test_new_bridge_tools_are_registered(self) -> None:
        declared = _tools_declared_in_agent()
        for name in NEW_TOOLS:
            with self.subTest(tool=name):
                self.assertIn(name, declared)

    def test_existing_tool_order_is_preserved(self) -> None:
        declared = [name for name in _tools_declared_in_agent() if name in EXISTING_TOOLS]
        self.assertEqual(declared, EXISTING_TOOLS)

    def test_new_tools_are_added_at_the_end(self) -> None:
        declared = _tools_declared_in_agent()
        self.assertEqual(declared[-len(NEW_TOOLS):], NEW_TOOLS)


class ImportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.installed = _install_stubs()
        self.addCleanup(_restore_stubs, self.installed)
        for name in EXISTING_MODULES + ["agent"]:
            sys.modules.pop(name, None)

    def test_every_jarvis_module_still_imports(self) -> None:
        for name in EXISTING_MODULES:
            with self.subTest(module=name):
                self.assertIsNotNone(importlib.import_module(name))

    def test_agent_module_imports_and_exposes_the_entrypoint(self) -> None:
        agent = importlib.import_module("agent")
        self.assertTrue(hasattr(agent, "Assistant"))
        self.assertTrue(callable(agent.entrypoint))

    def test_agent_reaches_the_new_bridge(self) -> None:
        agent = importlib.import_module("agent")
        bridge = importlib.import_module("Jarvis_device_control")
        self.assertIs(agent.device_action, bridge.device_action)
        self.assertIs(agent.device_confirmation, bridge.device_confirmation)

    def test_bridge_exposes_the_phase_one_framework(self) -> None:
        bridge = importlib.import_module("Jarvis_device_control")
        self.assertIsNotNone(bridge.device_manager)
        self.assertIsNotNone(bridge.device_registry)
        self.assertIn("jarvis.framework.diagnostics", bridge.device_registry.names())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
