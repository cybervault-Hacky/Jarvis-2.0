"""Platform abstraction (Phase 1).

The core framework must not know anything about Windows, macOS, Linux or
Android. This module defines the seam only:

* :func:`detect_current_platform` - generic OS detection, no device control
* :class:`DevicePlatformAdapter` - what a platform adapter has to provide
* :class:`PlatformRegistry` - which adapters JARVIS currently has

Concrete adapters (``PCDeviceAdapter``, ``AndroidDeviceAdapter``) live in
:mod:`jarvis_devices.adapters`, and the OS specific code behind them belongs to
later phases.
"""

from __future__ import annotations

import sys
from typing import Any, Dict, Mapping, Optional, Protocol, Tuple

from .enums import Platform
from .errors import UnknownPlatformError
from .results import ToolResult

__all__ = [
    "detect_current_platform",
    "DevicePlatformAdapter",
    "PlatformRegistry",
]


def detect_current_platform() -> Platform:
    """Return the platform JARVIS is running on (no device control involved)."""
    if hasattr(sys, "getandroidapilevel"):  # Android exposes this in its runtime
        return Platform.ANDROID
    if sys.platform.startswith(("win", "darwin", "linux", "freebsd")):
        return Platform.PC
    return Platform.UNKNOWN


class DevicePlatformAdapter(Protocol):
    """The last hop before an action reaches a real device."""

    platform: Platform

    def is_available(self) -> bool: ...

    def capabilities(self) -> Tuple[str, ...]: ...

    def describe(self) -> Dict[str, Any]: ...

    async def execute(self, tool: Any, arguments: Mapping[str, Any], context: Any) -> ToolResult: ...


class PlatformRegistry:
    """Keeps the adapters JARVIS knows about."""

    def __init__(self, adapters: Optional[Tuple[DevicePlatformAdapter, ...]] = None) -> None:
        self._adapters: Dict[Platform, DevicePlatformAdapter] = {}
        for adapter in adapters or ():
            self.register(adapter)

    # ------------------------------------------------------------------
    def register(self, adapter: DevicePlatformAdapter, *, override: bool = False) -> DevicePlatformAdapter:
        """Register an adapter for its platform."""
        platform = getattr(adapter, "platform", None)
        if not isinstance(platform, Platform):
            raise UnknownPlatformError(f"Adapter {adapter!r} does not declare a Platform")
        if platform is Platform.UNKNOWN:
            raise UnknownPlatformError("An adapter cannot target Platform.UNKNOWN")
        if platform in self._adapters and not override:
            raise UnknownPlatformError(f"An adapter for {platform.value!r} is already registered")
        self._adapters[platform] = adapter
        return adapter

    def unregister(self, platform: Platform) -> bool:
        return self._adapters.pop(platform, None) is not None

    def get(self, platform: Platform) -> Optional[DevicePlatformAdapter]:
        """Return the adapter for ``platform`` or ``None``."""
        return self._adapters.get(platform)

    def require(self, platform: Platform) -> DevicePlatformAdapter:
        adapter = self._adapters.get(platform)
        if adapter is None:
            raise UnknownPlatformError(f"No adapter registered for platform {platform.value!r}")
        return adapter

    def supports(self, platform: Platform) -> bool:
        """``True`` when an adapter exists and reports itself available."""
        adapter = self._adapters.get(platform)
        if adapter is None:
            return False
        try:
            return bool(adapter.is_available())
        except Exception:  # noqa: BLE001 - a broken adapter is unavailable
            return False

    def platforms(self) -> Tuple[Platform, ...]:
        return tuple(sorted(self._adapters, key=lambda p: p.value))

    def describe(self) -> Dict[str, Any]:
        """Adapter metadata for logging and diagnostics."""
        return {
            platform.value: {
                "available": self.supports(platform),
                "capabilities": list(self._adapters[platform].capabilities()),
            }
            for platform in self._adapters
        }

    def clear(self) -> None:
        self._adapters.clear()

    def __contains__(self, platform: object) -> bool:
        return platform in self._adapters

    def __len__(self) -> int:
        return len(self._adapters)
