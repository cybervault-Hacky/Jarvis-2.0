"""JARVIS secure device-tool framework - Phase 1 (architecture only).

This package is the foundation every future device action (calls, messages,
WhatsApp, shutdown, volume, brightness, Wi-Fi, Bluetooth, app launch, Android
control, PC control) will be built on. **Phase 1 implements no device action** -
only the safe plumbing around them:

* :class:`~jarvis_devices.tools.BaseDeviceTool` - the tool contract
* :class:`~jarvis_devices.registry.DeviceToolRegistry` - explicit registration
* :class:`~jarvis_devices.permissions.PermissionPolicy` - deny-by-default checks
* :class:`~jarvis_devices.confirmation.ConfirmationManager` - human yes/no gate
* :class:`~jarvis_devices.results.ToolResult` - structured, honest outcomes
* :class:`~jarvis_devices.manager.DeviceActionManager` - the only execution path
* :class:`~jarvis_devices.platform.PlatformRegistry` - PC / Android seam
* :class:`~jarvis_devices.audit.AuditLogger` - redacted lifecycle logging

Standard library only, so it imports and runs anywhere JARVIS runs.
"""

from __future__ import annotations

from .arguments import ArgumentSchema, ArgumentSpec
from .audit import AUDIT_LOGGER_NAME, AuditLogger, Redactor
from .confirmation import (
    DEFAULT_CONFIRMATION_TTL,
    ConfirmationManager,
    ConfirmationPolicy,
    ConfirmationRequest,
)
from .enums import (
    ConfirmationStatus,
    Platform,
    RiskLevel,
    ToolLifecycleEvent,
    ToolResultStatus,
)
from .errors import (
    ConfirmationError,
    ConfirmationExpiredError,
    ConfirmationLimitError,
    ConfirmationStateError,
    DeviceFrameworkError,
    DuplicateToolError,
    ErrorCode,
    InvalidToolError,
    ToolRegistryError,
    UnknownConfirmationError,
    UnknownToolError,
)
from .ids import new_confirmation_id, new_execution_id, new_plan_id
from .manager import DeviceActionManager
from .cross_device import (
    CROSS_DEVICE_TOOL_NAMES,
    ANDROID_TOOL_CAPABILITY_POLICY,
    PC_TOOL_ALLOWLIST,
    CrossDeviceAvailability,
    CrossDeviceCapabilitiesTool,
    CrossDeviceInventory,
    CrossDeviceInventoryEntry,
    CrossDeviceInventorySnapshot,
    CrossDevicePlan,
    CrossDevicePlanStatus,
    CrossDevicePlanStore,
    CrossDevicePlanner,
    CrossDeviceResult,
    CrossDeviceStatusTool,
    build_cross_device_tools,
)
from .permissions import (
    PERMISSION_ANDROID_BRIDGE_MANAGE,
    PERMISSION_ANDROID_BRIDGE_PAIR,
    PERMISSION_ANDROID_SYSTEM_CONTROL,
    PERMISSION_ANDROID_SYSTEM_READ,
    PERMISSION_ANDROID_CALL_READ,
    PERMISSION_ANDROID_CALL_CONTROL,
    PERMISSION_ANDROID_MESSAGE_READ,
    PERMISSION_ANDROID_MESSAGE_SEND,
    PERMISSION_APP_CONTROL,
    PERMISSION_APP_LAUNCH,
    PERMISSION_BLUETOOTH_CONTROL,
    PERMISSION_CALL_PLACE,
    PERMISSION_DEVICE_STATUS_READ,
    PERMISSION_DISPLAY_CONTROL,
    PERMISSION_MEDIA_CONTROL,
    PERMISSION_MESSAGE_SEND,
    PERMISSION_NETWORK_CONTROL,
    PERMISSION_POWER_CONTROL,
    PERMISSION_SETTINGS_WRITE,
    PERMISSION_VOLUME_CONTROL,
    PermissionDecision,
    PermissionPolicy,
    READ_ONLY_PERMISSIONS,
)
from .platform import DevicePlatformAdapter, PlatformRegistry, detect_current_platform
from .registry import DeviceToolRegistry, validate_tool
from .results import ToolResult
from .tools import BaseDeviceTool, DeviceTool, ToolContext

__version__ = "1.0.0-phase1"

__all__ = [
    # enums
    "RiskLevel",
    "Platform",
    "ToolResultStatus",
    "ConfirmationStatus",
    "ToolLifecycleEvent",
    # contract
    "BaseDeviceTool",
    "DeviceTool",
    "ToolContext",
    "ArgumentSchema",
    "ArgumentSpec",
    # results
    "ToolResult",
    "ErrorCode",
    # registry
    "DeviceToolRegistry",
    "validate_tool",
    # permissions
    "PermissionPolicy",
    "PermissionDecision",
    "READ_ONLY_PERMISSIONS",
    "PERMISSION_APP_LAUNCH",
    "PERMISSION_APP_CONTROL",
    "PERMISSION_CALL_PLACE",
    "PERMISSION_DEVICE_STATUS_READ",
    "PERMISSION_MEDIA_CONTROL",
    "PERMISSION_MESSAGE_SEND",
    "PERMISSION_POWER_CONTROL",
    "PERMISSION_SETTINGS_WRITE",
    "PERMISSION_VOLUME_CONTROL",
    "PERMISSION_DISPLAY_CONTROL",
    "PERMISSION_NETWORK_CONTROL",
    "PERMISSION_BLUETOOTH_CONTROL",
    "PERMISSION_ANDROID_BRIDGE_PAIR",
    "PERMISSION_ANDROID_BRIDGE_MANAGE",
    "PERMISSION_ANDROID_SYSTEM_READ",
    "PERMISSION_ANDROID_SYSTEM_CONTROL",
    "PERMISSION_ANDROID_CALL_READ",
    "PERMISSION_ANDROID_CALL_CONTROL",
    "PERMISSION_ANDROID_MESSAGE_READ",
    "PERMISSION_ANDROID_MESSAGE_SEND",
    # confirmation
    "ConfirmationManager",
    "ConfirmationPolicy",
    "ConfirmationRequest",
    "DEFAULT_CONFIRMATION_TTL",
    # platform
    "DevicePlatformAdapter",
    "PlatformRegistry",
    "detect_current_platform",
    # orchestration
    "DeviceActionManager",
    # logging
    "AuditLogger",
    "Redactor",
    "AUDIT_LOGGER_NAME",
    # ids
    "new_execution_id",
    "new_confirmation_id",
    "new_plan_id",
    # Phase 9 cross-device orchestration
    "CrossDeviceAvailability",
    "CrossDevicePlanStatus",
    "CrossDeviceInventoryEntry",
    "CrossDeviceInventorySnapshot",
    "CrossDevicePlan",
    "CrossDeviceResult",
    "CrossDeviceInventory",
    "CrossDevicePlanStore",
    "CrossDevicePlanner",
    "CrossDeviceStatusTool",
    "CrossDeviceCapabilitiesTool",
    "ANDROID_TOOL_CAPABILITY_POLICY",
    "PC_TOOL_ALLOWLIST",
    "CROSS_DEVICE_TOOL_NAMES",
    "build_cross_device_tools",
    # errors
    "DeviceFrameworkError",
    "ToolRegistryError",
    "UnknownToolError",
    "DuplicateToolError",
    "InvalidToolError",
    "ConfirmationError",
    "UnknownConfirmationError",
    "ConfirmationExpiredError",
    "ConfirmationStateError",
    "ConfirmationLimitError",
    "__version__",
]
