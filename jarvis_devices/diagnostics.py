"""A SAFE, non-device self check tool (Phase 1).

``FrameworkDiagnosticsTool`` touches no device: it only reports what the
framework currently knows (registered tools, granted permission count, adapter
availability). It exists so that

* the whole pipeline (registry -> permissions -> confirmation -> execution ->
  structured result) can be verified before any real device tool is written, and
* JARVIS can honestly answer "what can you control right now?".

It is the template a Phase 2 device tool should copy.
"""

from __future__ import annotations

from typing import Any, Callable, Dict

from .arguments import ArgumentSchema
from .enums import Platform, RiskLevel
from .results import ToolResult
from .tools import BaseDeviceTool, ToolContext

__all__ = ["FrameworkDiagnosticsTool"]


class FrameworkDiagnosticsTool(BaseDeviceTool):
    """Reports the state of the device-tool framework itself."""

    name = "jarvis.framework.diagnostics"
    description = "Report which device tools, permissions and platforms JARVIS currently has."
    platform = Platform.UNKNOWN  # runs anywhere, controls nothing
    risk_level = RiskLevel.SAFE
    required_permissions = ()
    argument_schema = ArgumentSchema.empty()

    def __init__(self, summary_provider: Callable[[], Dict[str, Any]]) -> None:
        if not callable(summary_provider):
            raise TypeError("summary_provider must be callable")
        self._summary_provider = summary_provider

    def is_available(self) -> bool:
        """Always available - it performs no device interaction."""
        return True

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        try:
            summary = dict(self._summary_provider() or {})
        except Exception as exc:  # noqa: BLE001 - diagnostics must not explode
            return ToolResult.failure(
                "Could not collect framework diagnostics.",
                error=f"{type(exc).__name__}: {exc}"[:200],
            )
        return ToolResult.ok(
            "Framework diagnostics collected; no device was touched.",
            data=summary,
        )
