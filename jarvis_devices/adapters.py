"""Platform adapters (Phase 1 - declarations only).

These adapters carry **no** OS specific control code. They exist so that:

* the framework has a place to hang PC / Android specific behaviour later,
* "is this device reachable right now?" is answered in one place.

Phase 2+ will add the real implementations behind :meth:`is_available` /
:meth:`capabilities` without touching the core framework.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Tuple

from .enums import Platform
from .platform import detect_current_platform
from .results import ToolResult
from .tools import BaseDeviceTool, ToolContext

__all__ = ["BasePlatformAdapter", "PCDeviceAdapter", "AndroidDeviceAdapter"]


class BasePlatformAdapter:
    """Default adapter behaviour: hand the call straight to the tool."""

    platform: Platform = Platform.UNKNOWN

    def is_available(self) -> bool:
        return False

    def capabilities(self) -> Tuple[str, ...]:
        return ()

    def describe(self) -> Dict[str, Any]:
        return {
            "platform": self.platform.value,
            "adapter": type(self).__name__,
            "available": self.is_available(),
            "capabilities": list(self.capabilities()),
        }

    async def execute(
        self,
        tool: BaseDeviceTool,
        arguments: Mapping[str, Any],
        context: ToolContext,
    ) -> ToolResult:
        """Dispatch to the tool. Later phases may route this over ADB etc."""
        return await tool.execute(arguments, context)


class PCDeviceAdapter(BasePlatformAdapter):
    """Adapter for the PC JARVIS runs on."""

    platform = Platform.PC

    def is_available(self) -> bool:
        """Available only when JARVIS itself is running on a PC."""
        return detect_current_platform() is Platform.PC

    def capabilities(self) -> Tuple[str, ...]:
        # Declared, not implemented: real capabilities arrive in later phases.
        return ()


class AndroidDeviceAdapter(BasePlatformAdapter):
    """Adapter for a paired Android device."""

    platform = Platform.ANDROID

    def is_available(self) -> bool:
        """Available only when JARVIS itself is running on Android."""
        return detect_current_platform() is Platform.ANDROID

    def capabilities(self) -> Tuple[str, ...]:
        return ()
