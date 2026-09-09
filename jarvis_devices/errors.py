"""Framework exceptions and machine readable error codes (Phase 1).

Every failure path in the framework raises one of these exceptions or returns a
:class:`~jarvis_devices.results.ToolResult` carrying one of the
:data:`ErrorCode` constants. There is no "silent failure" path.
"""

from __future__ import annotations

__all__ = [
    "DeviceFrameworkError",
    "ToolRegistryError",
    "UnknownToolError",
    "DuplicateToolError",
    "InvalidToolError",
    "PermissionError_",
    "ConfirmationError",
    "UnknownConfirmationError",
    "ConfirmationExpiredError",
    "ConfirmationStateError",
    "ConfirmationLimitError",
    "PlatformError",
    "UnknownPlatformError",
    "ErrorCode",
]


class DeviceFrameworkError(Exception):
    """Base class for every error raised by the device-tool framework."""


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
class ToolRegistryError(DeviceFrameworkError):
    """Base class for registry problems."""


class UnknownToolError(ToolRegistryError, KeyError):
    """Raised when a tool name is not registered.

    Inherits from :class:`KeyError` so callers that already treat registry
    lookups as dictionary lookups keep working.
    """


class DuplicateToolError(ToolRegistryError):
    """Raised when a tool name is registered twice."""


class InvalidToolError(ToolRegistryError):
    """Raised when an object does not satisfy the device-tool contract."""


# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------
class PermissionError_(DeviceFrameworkError):
    """Raised when a permission check is refused outright.

    Named with a trailing underscore to avoid shadowing the builtin
    :class:`PermissionError`.
    """


# ---------------------------------------------------------------------------
# Confirmation
# ---------------------------------------------------------------------------
class ConfirmationError(DeviceFrameworkError):
    """Base class for confirmation problems."""


class UnknownConfirmationError(ConfirmationError, KeyError):
    """Raised when a confirmation id is unknown or already forgotten."""


class ConfirmationExpiredError(ConfirmationError):
    """Raised when a pending confirmation is resolved after its deadline."""


class ConfirmationStateError(ConfirmationError):
    """Raised when a confirmation is resolved twice / in a wrong state."""


class ConfirmationLimitError(ConfirmationError):
    """Raised when too many confirmations are pending at the same time."""


# ---------------------------------------------------------------------------
# Platform
# ---------------------------------------------------------------------------
class PlatformError(DeviceFrameworkError):
    """Base class for platform problems."""


class UnknownPlatformError(PlatformError, KeyError):
    """Raised when no adapter is registered for a platform."""


class ErrorCode:
    """Stable error codes attached to failed :class:`ToolResult` objects."""

    UNKNOWN_TOOL = "unknown_tool"
    INVALID_TOOL = "invalid_tool"
    DUPLICATE_TOOL = "duplicate_tool"
    INVALID_ARGUMENT = "invalid_argument"
    PERMISSION_DENIED = "permission_denied"
    TOOL_BLOCKED = "tool_blocked"
    PLATFORM_BLOCKED = "platform_blocked"
    TOOL_UNAVAILABLE = "tool_unavailable"
    PLATFORM_UNAVAILABLE = "platform_unavailable"
    DEVICE_UNAVAILABLE = "device_unavailable"
    CONFIRMATION_REQUIRED = "confirmation_required"
    CONFIRMATION_PENDING = "confirmation_pending"
    CONFIRMATION_DENIED = "confirmation_denied"
    CONFIRMATION_CANCELLED = "confirmation_cancelled"
    CONFIRMATION_EXPIRED = "confirmation_expired"
    CONFIRMATION_REUSED = "confirmation_reused"
    CONFIRMATION_MISMATCH = "confirmation_mismatch"
    UNKNOWN_CONFIRMATION = "unknown_confirmation"
    TOOL_ERROR = "tool_error"
    NOT_IMPLEMENTED = "not_implemented"
    # Phase 2 - PC application control
    APPLICATION_NOT_FOUND = "application_not_found"
    APPLICATION_ALREADY_RUNNING = "application_already_running"
    APPLICATION_NOT_RUNNING = "application_not_running"
    AMBIGUOUS_APPLICATION = "ambiguous_application"
    WINDOW_NOT_FOUND = "window_not_found"
    UNSUPPORTED_PLATFORM = "unsupported_platform"
    EXECUTION_FAILED = "execution_failed"
    # Phase 3 - PC system control
    SYSTEM_CONTROL_UNAVAILABLE = "system_control_unavailable"
    INVALID_PERCENTAGE = "invalid_percentage"
    VOLUME_CONTROL_FAILED = "volume_control_failed"
    BRIGHTNESS_CONTROL_UNAVAILABLE = "brightness_control_unavailable"
    BRIGHTNESS_CONTROL_FAILED = "brightness_control_failed"
    WIFI_CONTROL_UNAVAILABLE = "wifi_control_unavailable"
    WIFI_CONTROL_FAILED = "wifi_control_failed"
    BLUETOOTH_CONTROL_UNAVAILABLE = "bluetooth_control_unavailable"
    BLUETOOTH_CONTROL_FAILED = "bluetooth_control_failed"
    # Phase 4 - PC power control
    POWER_CONTROL_UNAVAILABLE = "power_control_unavailable"
    POWER_OPERATION_UNSUPPORTED = "power_operation_unsupported"
    POWER_PRIVILEGE_REQUIRED = "power_privilege_required"
    POWER_CONTROL_FAILED = "power_control_failed"
    # Phase 5 - Android device bridge
    ANDROID_BRIDGE_UNAVAILABLE = "android_bridge_unavailable"
    ANDROID_DEVICE_UNKNOWN = "android_device_unknown"
    ANDROID_DEVICE_NOT_PAIRED = "android_device_not_paired"
    ANDROID_DEVICE_REVOKED = "android_device_revoked"
    ANDROID_PAIRING_UNKNOWN = "android_pairing_unknown"
    ANDROID_PAIRING_EXPIRED = "android_pairing_expired"
    ANDROID_PAIRING_FAILED = "android_pairing_failed"
    ANDROID_AUTHENTICATION_FAILED = "android_authentication_failed"
    ANDROID_PROTOCOL_ERROR = "android_protocol_error"
    ANDROID_INVALID_MESSAGE = "android_invalid_message"
    ANDROID_REPLAY_DETECTED = "android_replay_detected"
    ANDROID_CONNECTION_FAILED = "android_connection_failed"
    ANDROID_CONNECTION_TIMEOUT = "android_connection_timeout"
    ANDROID_CAPABILITY_UNAVAILABLE = "android_capability_unavailable"
    #: Phase 6 - a paired device that is not connected cannot be acted on. Kept
    #: distinct from ANDROID_CONNECTION_FAILED so "never connected" is not
    #: confused with "tried to connect and could not".
    ANDROID_DEVICE_NOT_CONNECTED = "android_device_not_connected"
    ANDROID_DEVICE_STALE = "android_device_stale"
    # Phase 6 - Android system control
    ANDROID_SYSTEM_UNAVAILABLE = "android_system_unavailable"
    ANDROID_SYSTEM_UNSUPPORTED = "android_system_unsupported"
    ANDROID_SYSTEM_PERMISSION_DENIED = "android_system_permission_denied"
    ANDROID_SYSTEM_INVALID_ARGUMENT = "android_system_invalid_argument"
    ANDROID_SYSTEM_TIMEOUT = "android_system_timeout"
    ANDROID_SYSTEM_FAILED = "android_system_failed"
    ANDROID_VOLUME_UNAVAILABLE = "android_volume_unavailable"
    ANDROID_BRIGHTNESS_UNAVAILABLE = "android_brightness_unavailable"
    ANDROID_WIFI_UNAVAILABLE = "android_wifi_unavailable"
    ANDROID_BLUETOOTH_UNAVAILABLE = "android_bluetooth_unavailable"
    # Phase 7 - Android call management. These stay distinct from system
    # control so a call permission or state failure cannot be misclassified.
    ANDROID_CALL_UNAVAILABLE = "android_call_unavailable"
    ANDROID_CALL_UNSUPPORTED = "android_call_unsupported"
    ANDROID_CALL_PERMISSION_DENIED = "android_call_permission_denied"
    ANDROID_CALL_INVALID_ARGUMENT = "android_call_invalid_argument"
    ANDROID_CALL_INVALID_STATE = "android_call_invalid_state"
    ANDROID_CALL_NO_ACTIVE_CALL = "android_call_no_active_call"
    ANDROID_CALL_TIMEOUT = "android_call_timeout"
    ANDROID_CALL_FAILED = "android_call_failed"
    # Phase 8 - Android text messaging.  These are not system/call outcomes:
    # each maps to the narrow messaging surface only.
    ANDROID_MESSAGE_UNAVAILABLE = "android_message_unavailable"
    ANDROID_MESSAGE_UNSUPPORTED = "android_message_unsupported"
    ANDROID_MESSAGE_PERMISSION_DENIED = "android_message_permission_denied"
    ANDROID_MESSAGE_INVALID_ARGUMENT = "android_message_invalid_argument"
    ANDROID_MESSAGE_TIMEOUT = "android_message_timeout"
    ANDROID_MESSAGE_OPERATION_CONFLICT = "android_message_operation_conflict"
    ANDROID_MESSAGE_FAILED = "android_message_failed"
    # Phase 9 - bounded cross-device orchestration failures.  These never
    # indicate that an action ran; final manager/bridge errors remain separate.
    CROSS_DEVICE_UNSUPPORTED = "cross_device_unsupported"
    CROSS_DEVICE_AMBIGUOUS = "cross_device_ambiguous"
    CROSS_DEVICE_TARGET_UNAVAILABLE = "cross_device_target_unavailable"
    CROSS_DEVICE_PLAN_EXPIRED = "cross_device_plan_expired"
    CROSS_DEVICE_PLAN_REPLAYED = "cross_device_plan_replayed"
    CROSS_DEVICE_PLAN_INVALIDATED = "cross_device_plan_invalidated"
    CROSS_DEVICE_PLAN_CAPACITY = "cross_device_plan_capacity"
