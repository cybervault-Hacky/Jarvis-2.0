"""Centralized permission checking (Phase 1).

Flow::

    Tool request
         |
         v
    PermissionPolicy.check(tool)
         |
    +----+----+
    |         |
  allowed   denied
    |         |
    v         v
 continue   ToolResult(PERMISSION_DENIED)

Nothing in this module executes anything. It only answers "is this allowed?",
and every tool must declare the permissions it needs. Natural language from the
user never reaches this layer directly - it always arrives as a registered tool
name plus validated arguments.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, FrozenSet, Iterable, Tuple

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .tools import BaseDeviceTool

__all__ = [
    "PermissionDecision",
    "PermissionPolicy",
    # Permission identifiers future phases will declare / grant.
    "PERMISSION_DEVICE_STATUS_READ",
    "PERMISSION_SETTINGS_WRITE",
    "PERMISSION_MEDIA_CONTROL",
    "PERMISSION_APP_LAUNCH",
    "PERMISSION_MESSAGE_SEND",
    "PERMISSION_CALL_PLACE",
    "PERMISSION_POWER_CONTROL",
    "PERMISSION_APP_CONTROL",
    "PERMISSION_VOLUME_CONTROL",
    "PERMISSION_DISPLAY_CONTROL",
    "PERMISSION_NETWORK_CONTROL",
    "PERMISSION_BLUETOOTH_CONTROL",
    "PERMISSION_ANDROID_BRIDGE_PAIR",
    "PERMISSION_ANDROID_BRIDGE_MANAGE",
    "PERMISSION_ANDROID_SYSTEM_READ",
    "PERMISSION_ANDROID_SYSTEM_CONTROL",
    "READ_ONLY_PERMISSIONS",
]

# --- Permission vocabulary for future phases (identifiers only) ------------
PERMISSION_DEVICE_STATUS_READ = "device.status.read"
PERMISSION_SETTINGS_WRITE = "device.settings.write"
PERMISSION_MEDIA_CONTROL = "device.media.control"
PERMISSION_APP_LAUNCH = "system.app.launch"
PERMISSION_MESSAGE_SEND = "comms.message.send"
PERMISSION_CALL_PLACE = "comms.call.place"
PERMISSION_POWER_CONTROL = "system.power.control"
#: Phase 2 - open / focus / close a known PC application.
PERMISSION_APP_CONTROL = "system.app.control"
#: Phase 3 - master volume and mute on the PC JARVIS runs on.
PERMISSION_VOLUME_CONTROL = "system.volume.control"
#: Phase 3 - display brightness.
PERMISSION_DISPLAY_CONTROL = "system.display.control"
#: Phase 3 - Wi-Fi radio on/off (connectivity, so confirmed by the policy).
PERMISSION_NETWORK_CONTROL = "system.network.control"
#: Phase 3 - Bluetooth radio on/off (connectivity, so confirmed by the policy).
PERMISSION_BLUETOOTH_CONTROL = "system.bluetooth.control"
#: Phase 5 - approve a cryptographically verified Android pairing. Granting trust
#: to a new device is separate from merely looking at it, so it gets its own
#: permission. Bridge/device *reads* reuse :data:`PERMISSION_DEVICE_STATUS_READ`
#: rather than inventing a duplicate read permission.
PERMISSION_ANDROID_BRIDGE_PAIR = "device.android.bridge.pair"
#: Phase 5 - unpair / revoke an Android device, and manage its connection.
PERMISSION_ANDROID_BRIDGE_MANAGE = "device.android.bridge.manage"
#: Phase 6 - read Android system state (status, volume, brightness, radio state).
#: Deliberately separate from the bridge pair/manage permissions: being able to
#: look at a phone must not imply being able to change it, and being able to
#: pair a phone must not imply being able to change its settings.
PERMISSION_ANDROID_SYSTEM_READ = "device.android.system.read"
#: Phase 6 - change Android system state (volume, mute, brightness, radios).
PERMISSION_ANDROID_SYSTEM_CONTROL = "device.android.system.control"

#: The only permissions granted by :meth:`PermissionPolicy.with_local_defaults`.
READ_ONLY_PERMISSIONS: FrozenSet[str] = frozenset({PERMISSION_DEVICE_STATUS_READ})


@dataclass(frozen=True)
class PermissionDecision:
    """Outcome of one permission check."""

    allowed: bool
    missing_permissions: Tuple[str, ...] = ()
    reason: str = ""
    error_code: str = "permission_denied"

    def __bool__(self) -> bool:  # allows ``if decision:``
        return self.allowed


class PermissionPolicy:
    """Explicit allow-list of permissions, blocked tools and blocked platforms.

    The policy is deny-by-default: a tool that declares permissions JARVIS has
    not been granted is refused with an explicit reason.
    """

    def __init__(
        self,
        granted: Iterable[str] = (),
        *,
        denied: Iterable[str] = (),
        blocked_tools: Iterable[str] = (),
        blocked_platforms: Iterable[str] = (),
    ) -> None:
        self._granted = frozenset(granted)
        self._denied = frozenset(denied)
        self._blocked_tools = frozenset(_normalise(blocked_tools))
        self._blocked_platforms = frozenset(blocked_platforms)

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------
    @classmethod
    def with_local_defaults(cls) -> "PermissionPolicy":
        """Local-first defaults: read only permissions, everything else denied.

        Later phases must opt in explicitly, e.g.
        ``policy.grant(PERMISSION_MESSAGE_SEND)``.
        """
        return cls(granted=READ_ONLY_PERMISSIONS)

    # ------------------------------------------------------------------
    # Grants
    # ------------------------------------------------------------------
    @property
    def granted_permissions(self) -> FrozenSet[str]:
        return self._granted

    @property
    def denied_permissions(self) -> FrozenSet[str]:
        return self._denied

    @property
    def blocked_tools(self) -> FrozenSet[str]:
        return self._blocked_tools

    def grant(self, *permissions: str) -> None:
        """Grant one or more permissions (explicit opt-in)."""
        for permission in permissions:
            _check_permission_name(permission)
        self._granted = self._granted | frozenset(permissions)

    def revoke(self, *permissions: str) -> None:
        """Remove previously granted permissions."""
        self._granted = self._granted - frozenset(permissions)

    def deny(self, *permissions: str) -> None:
        """Hard-deny permissions even if they were granted."""
        for permission in permissions:
            _check_permission_name(permission)
        self._denied = self._denied | frozenset(permissions)

    def allow(self, *permissions: str) -> None:
        """Undo a hard deny."""
        self._denied = self._denied - frozenset(permissions)

    def is_granted(self, permission: str) -> bool:
        """Return ``True`` when ``permission`` is granted and not hard-denied."""
        return permission in self._granted and permission not in self._denied

    # ------------------------------------------------------------------
    # Blocks
    # ------------------------------------------------------------------
    def block_tool(self, *tool_names: str) -> None:
        """Refuse specific tools regardless of permissions."""
        self._blocked_tools = self._blocked_tools | frozenset(_normalise(tool_names))

    def unblock_tool(self, *tool_names: str) -> None:
        self._blocked_tools = self._blocked_tools - frozenset(_normalise(tool_names))

    def is_tool_blocked(self, tool_name: str) -> bool:
        return _normalise_name(tool_name) in self._blocked_tools

    def block_platform(self, *platforms: str) -> None:
        self._blocked_platforms = self._blocked_platforms | frozenset(platforms)

    def is_platform_blocked(self, platform: str) -> bool:
        return platform in self._blocked_platforms

    # ------------------------------------------------------------------
    # The check itself
    # ------------------------------------------------------------------
    def check(self, tool: "BaseDeviceTool") -> PermissionDecision:
        """Decide whether ``tool`` may run under this policy."""
        from .errors import ErrorCode

        name = _normalise_name(getattr(tool, "name", ""))
        if name in self._blocked_tools:
            return PermissionDecision(
                allowed=False,
                reason=f"Tool {name!r} is blocked by the permission policy.",
                error_code=ErrorCode.TOOL_BLOCKED,
            )

        platform_value = getattr(getattr(tool, "platform", None), "value", None)
        if platform_value is not None and platform_value in self._blocked_platforms:
            return PermissionDecision(
                allowed=False,
                reason=f"Platform {platform_value!r} is blocked by the permission policy.",
                error_code=ErrorCode.PLATFORM_BLOCKED,
            )

        required = tuple(getattr(tool, "required_permissions", ()) or ())
        missing = tuple(p for p in required if not self.is_granted(p))
        if missing:
            return PermissionDecision(
                allowed=False,
                missing_permissions=missing,
                reason=(
                    f"Tool {name!r} needs permission(s) {', '.join(missing)} "
                    "which have not been granted."
                ),
                error_code=ErrorCode.PERMISSION_DENIED,
            )

        return PermissionDecision(allowed=True, reason="all required permissions granted")


def _normalise(names: Iterable[str]) -> Tuple[str, ...]:
    return tuple(_normalise_name(name) for name in names)


def _normalise_name(name: str) -> str:
    return (name or "").strip().lower()


def _check_permission_name(permission: str) -> None:
    if not isinstance(permission, str) or not permission.strip():
        raise ValueError("Permission names must be non-empty strings")
