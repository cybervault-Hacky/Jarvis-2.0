"""Test doubles for the Phase 1 suite.

Nothing in here touches a device, a network socket or a shell: the fakes only
record that they were called.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Mapping, Optional, Tuple

from jarvis_devices import (
    ArgumentSchema,
    BaseDeviceTool,
    Platform,
    RiskLevel,
    ToolContext,
    ToolResult,
)


class FakeClock:
    """Deterministic clock so expiry can be tested without sleeping."""

    def __init__(self, start: Optional[datetime] = None) -> None:
        self.now = start or datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> datetime:
        self.now = self.now + delta
        return self.now


class FakeDeviceTool(BaseDeviceTool):
    """A configurable, harmless tool used by the tests."""

    def __init__(
        self,
        name: str = "test.recorder",
        *,
        description: str = "Test double; performs no device action.",
        platform: Platform = Platform.UNKNOWN,
        risk_level: RiskLevel = RiskLevel.SAFE,
        required_permissions: Tuple[str, ...] = (),
        requires_confirmation: Optional[bool] = None,
        argument_schema: Optional[ArgumentSchema] = None,
        result: Optional[ToolResult] = None,
        error: Optional[Exception] = None,
        available: bool = True,
        delay: float = 0.0,
    ) -> None:
        self.name = name
        self.description = description
        self.platform = platform
        self.risk_level = risk_level
        self.required_permissions = tuple(required_permissions)
        self.requires_confirmation = requires_confirmation
        self.argument_schema = argument_schema if argument_schema is not None else ArgumentSchema.empty()
        self.result = result
        self.error = error
        self.available = available
        self.delay = delay
        self.calls: List[Tuple[Dict[str, Any], ToolContext]] = []

    # ------------------------------------------------------------------
    @property
    def call_count(self) -> int:
        return len(self.calls)

    def is_available(self) -> bool:
        return self.available

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        self.calls.append((dict(arguments), context))
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.error is not None:
            raise self.error
        if self.result is not None:
            return self.result
        return ToolResult.ok(f"{self.name} ran with {sorted(arguments)}")


class BrokenTool(FakeDeviceTool):
    """A tool whose ``is_available`` raises, to test defensive handling."""

    def is_available(self) -> bool:
        raise RuntimeError("availability probe failed")


class NotATool:
    """Deliberately not a device tool."""

    name = "test.not_a_tool"


class FakeAdapter:
    """Minimal platform adapter double."""

    def __init__(self, platform: Platform = Platform.PC, available: bool = True) -> None:
        self.platform = platform
        self.available = available
        self.calls: List[Tuple[str, Dict[str, Any]]] = []

    def is_available(self) -> bool:
        return self.available

    def capabilities(self) -> Tuple[str, ...]:
        return ()

    def describe(self) -> Dict[str, Any]:
        return {"platform": self.platform.value, "available": self.available}

    async def execute(
        self,
        tool: BaseDeviceTool,
        arguments: Mapping[str, Any],
        context: ToolContext,
    ) -> ToolResult:
        self.calls.append((tool.name, dict(arguments)))
        return await tool.execute(arguments, context)


class AuditCapture:
    """Collects the redacted lifecycle records emitted by an AuditLogger."""

    def __init__(self, audit: Any) -> None:
        self.records: List[Dict[str, Any]] = []
        audit.add_sink(self.records.append)

    @property
    def events(self) -> List[str]:
        return [record["event"] for record in self.records]

    def for_execution(self, execution_id: str) -> List[Dict[str, Any]]:
        return [r for r in self.records if r.get("execution_id") == execution_id]

    def raw_text(self) -> str:
        import json

        return "\n".join(json.dumps(record, default=str) for record in self.records)
