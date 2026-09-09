"""Phase 10 repository-wide static dangerous-construct audit.

This is intentionally a small, deterministic AST check rather than a claim that
lexical scanning alone proves security.  It pins the audited production
exceptions: fixed-destination HTTP configuration and two detached legacy desktop
modules.  Test-only uses are excluded and recorded in the release report.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LEGACY_UNREACHABLE = frozenset({"Jarvis_file_opner.py", "Jarvis_window_CTRL.py"})
FIXED_DESTINATION_HTTP = frozenset({"Jarvis_google_search.py", "jarvis_get_whether.py"})


def production_sources():
    for path in ROOT.rglob("*.py"):
        if "tests" not in path.parts and ".venv" not in path.parts and ".git" not in path.parts:
            yield path.relative_to(ROOT), ast.parse(path.read_text(encoding="utf-8"))


def imported_roots(tree: ast.AST) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".")[0])
    return roots


def call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        values = []
        current = node.func
        while isinstance(current, ast.Attribute):
            values.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            values.append(current.id)
        return ".".join(reversed(values))
    return ""


class StaticDangerousConstructAuditTests(unittest.TestCase):
    def test_no_dynamic_code_or_unsafe_deserialisation_in_production(self) -> None:
        prohibited_calls = {"eval", "exec", "compile", "__import__"}
        prohibited_imports = {"pickle", "marshal", "shelve", "dill", "yaml", "socket", "socketserver", "ctypes"}
        for path, tree in production_sources():
            with self.subTest(file=str(path)):
                self.assertTrue(prohibited_imports.isdisjoint(imported_roots(tree)))
                calls = {call_name(node) for node in ast.walk(tree) if isinstance(node, ast.Call)}
                self.assertTrue(prohibited_calls.isdisjoint(calls))

    def test_subprocess_is_confined_to_detached_legacy_modules(self) -> None:
        found = {str(path) for path, tree in production_sources() if "subprocess" in imported_roots(tree)}
        self.assertEqual(found, LEGACY_UNREACHABLE)

    def test_only_fixed_destination_tools_import_requests(self) -> None:
        found = {str(path) for path, tree in production_sources() if "requests" in imported_roots(tree)}
        self.assertEqual(found, FIXED_DESTINATION_HTTP)

    def test_active_agent_does_not_import_or_register_legacy_modules(self) -> None:
        agent_path = ROOT / "agent.py"
        text = agent_path.read_text(encoding="utf-8")
        tree = ast.parse(text)
        imports = {
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        }
        self.assertTrue({"Jarvis_file_opner", "Jarvis_window_CTRL", "keyboard_mouse_CTRL"}.isdisjoint(imports))
        for retired in ("device_action", "device_confirmation", "move_cursor_tool", "folder_file"):
            self.assertNotIn(f"import {retired}", text)

    def test_no_production_socket_listener_or_hardcoded_listener_address(self) -> None:
        forbidden_text = ("socket.socket(", "asyncio.start_server(", ".listen(")
        for path, _ in production_sources():
            content = (ROOT / path).read_text(encoding="utf-8")
            with self.subTest(file=str(path)):
                for marker in forbidden_text:
                    self.assertNotIn(marker, content)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
