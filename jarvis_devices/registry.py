"""Central device-tool registry (Phase 1).

The registry is the only way a tool becomes callable. It:

* rejects duplicates,
* validates every tool against the device-tool contract,
* answers unknown names with a predictable :class:`UnknownToolError`,
* stays completely independent from the tools themselves.
"""

from __future__ import annotations

import re
from collections.abc import Iterable as _IterableABC
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

from .arguments import ArgumentSchema
from .enums import Platform, RiskLevel
from .errors import DuplicateToolError, InvalidToolError, UnknownToolError
from .tools import BaseDeviceTool

__all__ = ["DeviceToolRegistry", "validate_tool", "TOOL_NAME_PATTERN"]

TOOL_NAME_PATTERN = r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$"
_TOOL_NAME_RE = re.compile(TOOL_NAME_PATTERN)


def validate_tool(tool: Any) -> None:
    """Raise :class:`InvalidToolError` unless ``tool`` is a valid device tool."""
    if not isinstance(tool, BaseDeviceTool):
        raise InvalidToolError(
            f"Device tools must extend BaseDeviceTool, got {type(tool).__name__}"
        )

    name = getattr(tool, "name", "")
    if not isinstance(name, str) or not _TOOL_NAME_RE.match(name):
        raise InvalidToolError(
            f"Tool name {name!r} is invalid; expected lowercase {TOOL_NAME_PATTERN}"
        )

    description = getattr(tool, "description", "")
    if not isinstance(description, str) or not description.strip():
        raise InvalidToolError(f"Tool {name!r} needs a non-empty description")

    if not isinstance(getattr(tool, "platform", None), Platform):
        raise InvalidToolError(f"Tool {name!r} needs a Platform")
    if not isinstance(getattr(tool, "risk_level", None), RiskLevel):
        raise InvalidToolError(f"Tool {name!r} needs a RiskLevel")

    permissions = getattr(tool, "required_permissions", ())
    if isinstance(permissions, str) or not isinstance(permissions, _IterableABC):
        raise InvalidToolError(f"Tool {name!r} must declare required_permissions as a tuple")
    for permission in permissions:
        if not isinstance(permission, str) or not permission.strip():
            raise InvalidToolError(f"Tool {name!r} declares an invalid permission: {permission!r}")

    override = getattr(tool, "requires_confirmation", None)
    if override is not None and not isinstance(override, bool):
        raise InvalidToolError(f"Tool {name!r}: requires_confirmation must be a bool or None")

    if not isinstance(getattr(tool, "argument_schema", None), ArgumentSchema):
        raise InvalidToolError(f"Tool {name!r} needs an ArgumentSchema")


class DeviceToolRegistry:
    """Name -> tool mapping with validation and duplicate protection."""

    def __init__(self) -> None:
        self._tools: Dict[str, BaseDeviceTool] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------
    def register(self, tool: BaseDeviceTool, *, override: bool = False) -> BaseDeviceTool:
        """Register ``tool``.

        Raises :class:`DuplicateToolError` when the name is taken (unless
        ``override`` is ``True``) and :class:`InvalidToolError` when the tool
        does not satisfy the contract.
        """
        validate_tool(tool)
        name = self._key(tool.name)
        if name in self._tools and not override:
            raise DuplicateToolError(f"A tool named {name!r} is already registered")
        self._tools[name] = tool
        return tool

    def register_all(self, tools: Iterable[BaseDeviceTool]) -> Tuple[BaseDeviceTool, ...]:
        """Register many tools; stops on the first invalid/duplicate one."""
        return tuple(self.register(tool) for tool in tools)

    def unregister(self, tool_or_name: Union[BaseDeviceTool, str]) -> bool:
        """Remove a tool; return ``False`` when it was not registered."""
        name = tool_or_name.name if isinstance(tool_or_name, BaseDeviceTool) else tool_or_name
        return self._tools.pop(self._key(name), None) is not None

    def clear(self) -> None:
        """Remove every registered tool."""
        self._tools.clear()

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------
    def get(self, tool_name: str) -> BaseDeviceTool:
        """Return the tool or raise :class:`UnknownToolError`."""
        tool = self._tools.get(self._key(tool_name))
        if tool is None:
            raise UnknownToolError(f"Unknown device tool: {tool_name!r}")
        return tool

    def find(self, tool_name: str) -> Optional[BaseDeviceTool]:
        """Return the tool or ``None`` when it is not registered."""
        return self._tools.get(self._key(tool_name))

    def names(self) -> Tuple[str, ...]:
        """All registered tool names, sorted."""
        return tuple(sorted(self._tools))

    def list_tools(
        self,
        *,
        platform: Optional[Platform] = None,
        risk_level: Optional[RiskLevel] = None,
        available_only: bool = False,
    ) -> Tuple[BaseDeviceTool, ...]:
        """Return registered tools, optionally filtered."""
        tools: List[BaseDeviceTool] = []
        for tool in sorted(self._tools.values(), key=lambda t: t.name):
            if platform is not None and tool.platform is not platform:
                continue
            if risk_level is not None and tool.risk_level is not risk_level:
                continue
            if available_only and not tool.is_available():
                continue
            tools.append(tool)
        return tuple(tools)

    def is_registered(self, tool_name: str) -> bool:
        return self._key(tool_name) in self._tools

    def is_available(self, tool_name: str) -> bool:
        """``True`` when the tool is registered *and* reports itself available."""
        tool = self.find(tool_name)
        if tool is None:
            return False
        try:
            return bool(tool.is_available())
        except Exception:  # noqa: BLE001 - a broken tool is simply unavailable
            return False

    def describe(self) -> Tuple[Dict[str, Any], ...]:
        """Metadata for every registered tool."""
        return tuple(tool.describe() for tool in self.list_tools())

    # ------------------------------------------------------------------
    def __contains__(self, tool_name: object) -> bool:
        return isinstance(tool_name, str) and self._key(tool_name) in self._tools

    def __len__(self) -> int:
        return len(self._tools)

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return f"<DeviceToolRegistry tools={list(self.names())}>"

    # ------------------------------------------------------------------
    @staticmethod
    def _key(tool_name: str) -> str:
        if not isinstance(tool_name, str):
            raise UnknownToolError(f"Tool names must be strings, got {type(tool_name).__name__}")
        return tool_name.strip().lower()
