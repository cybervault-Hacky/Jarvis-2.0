"""JARVIS tools for the Android bridge (Phase 5).

Six tools, and that is the whole public surface:

=================================  =================  ===============================
Tool                               Risk               What it does
=================================  =================  ===============================
``android.bridge.status``          SAFE               bridge health + pending pairings
``android.device.list``            SAFE               known devices and trust states
``android.device.status``          SAFE               one device in detail
``android.device.pair``            EXTERNAL_ACTION    approve a verified pairing
``android.device.unpair``          EXTERNAL_ACTION    forget a device
``android.device.revoke``          EXTERNAL_ACTION    permanently revoke a device
=================================  =================  ===============================

Deliberately absent, and not reachable through any of the above: raw transport
operations, frame injection, connection tuning, and anything that would carry a
command, a shell, an ADB invocation, a file path, a network address or a port.
The only arguments any of these tools accept are a **registered device id** or a
**pairing id** - both strict, both matched against state the bridge already
holds, so the model cannot aim a tool at an arbitrary destination.

Trust changes (``pair`` / ``unpair`` / ``revoke``) are ``EXTERNAL_ACTION`` *and*
``confirmation_mandatory``, so the confirmation policy asks first and cannot be
configured out of asking: a natural language request alone never grants or
removes trust.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional, Tuple

from . import android_crypto as crypto
from .android_bridge import (
    AndroidBridgeError,
    AndroidBridgeUnavailableError,
    AndroidDeviceBridge,
    SUPPORTED_CAPABILITIES,
)
from .android_identity import TrustState
from .arguments import ArgumentSchema, ArgumentSpec
from .enums import Platform, RiskLevel
from .errors import ErrorCode
from .permissions import (
    PERMISSION_ANDROID_BRIDGE_MANAGE,
    PERMISSION_ANDROID_BRIDGE_PAIR,
    PERMISSION_DEVICE_STATUS_READ,
)
from .platform import detect_current_platform
from .results import ToolResult
from .tools import BaseDeviceTool, ToolContext

__all__ = [
    "AndroidBridgeTool",
    "BridgeStatusTool",
    "DeviceListTool",
    "DeviceStatusTool",
    "DevicePairTool",
    "DeviceUnpairTool",
    "DeviceRevokeTool",
    "ANDROID_BRIDGE_TOOL_NAMES",
    "build_android_bridge_tools",
    "DEVICE_ID_ARGUMENT",
    "PAIRING_ID_ARGUMENT",
]

#: A bridge device id: ``adev-`` plus 32 hex characters. ``\Z`` (not ``$``) so a
#: trailing newline cannot sneak through.
DEVICE_ID_PATTERN = r"\Aadev-[0-9a-f]{32}\Z"
#: A pairing flow id: ``pair-`` plus 32 hex characters.
PAIRING_ID_PATTERN = r"\Apair-[0-9a-f]{32}\Z"

DEVICE_ID_ARGUMENT = ArgumentSpec(
    name="device",
    type=str,
    required=True,
    max_length=37,
    pattern=DEVICE_ID_PATTERN,
    description=(
        "The registered Android device id (adev- plus 32 hex characters), as "
        "listed by android.device.list. IP addresses, hostnames and names are "
        "not accepted."
    ),
)
PAIRING_ID_ARGUMENT = ArgumentSpec(
    name="pairing",
    type=str,
    required=True,
    max_length=37,
    pattern=PAIRING_ID_PATTERN,
    description=(
        "The pairing id from android.bridge.status. The user must have compared "
        "the pairing code on both screens before this is approved."
    ),
)


class AndroidBridgeTool(BaseDeviceTool):
    """Base class for the Android bridge tools.

    These run on the **PC** (they are the PC side of the bridge), so the
    platform is :attr:`Platform.PC`; availability is decided by the bridge, not
    by the platform probe alone.
    """

    platform = Platform.PC
    risk_level = RiskLevel.SAFE
    required_permissions: Tuple[str, ...] = (PERMISSION_DEVICE_STATUS_READ,)
    argument_schema = ArgumentSchema.empty()

    def __init__(
        self,
        bridge: AndroidDeviceBridge,
        *,
        platform_probe: Callable[[], Platform] = detect_current_platform,
    ) -> None:
        self._bridge = bridge
        self._platform_probe = platform_probe

    @property
    def bridge(self) -> AndroidDeviceBridge:
        return self._bridge

    # ------------------------------------------------------------------
    def is_available(self) -> bool:
        return self._bridge.available

    def platform_result(self) -> Optional[ToolResult]:
        """Refuse with an honest reason before doing any work."""
        detected = self._platform_probe()
        if detected is not Platform.PC:
            return ToolResult.unavailable(
                f"{self.name} only runs on the PC side of the Android bridge "
                f"(detected: {detected.value}).",
                error_code=ErrorCode.UNSUPPORTED_PLATFORM,
                tool_name=self.name,
                data={"platform": detected.value},
            )
        if not self._bridge.available:
            return ToolResult.unavailable(
                "The Android bridge is unavailable on this machine.",
                error_code=ErrorCode.ANDROID_BRIDGE_UNAVAILABLE,
                tool_name=self.name,
                data={"reason": self._bridge.unavailable_reason()[:200]},
            )
        return None

    # ------------------------------------------------------------------
    def guard(self) -> Optional[ToolResult]:
        blocked = self.platform_result()
        return blocked

    def failure(self, exc: Exception, context: ToolContext) -> ToolResult:
        """Turn a bridge error into a structured result. No internals leak."""
        code = str(getattr(exc, "error_code", ErrorCode.ANDROID_BRIDGE_UNAVAILABLE))
        message = self._public_message(exc)
        if code in (
            ErrorCode.ANDROID_BRIDGE_UNAVAILABLE,
            ErrorCode.ANDROID_CAPABILITY_UNAVAILABLE,
        ):
            # ToolResult.unavailable() takes no ``error`` keyword. Passing one
            # raised TypeError, which the framework boundary then reported as a
            # generic tool_error and lost the structured code entirely.
            return ToolResult.unavailable(
                message,
                error_code=code,
                tool_name=self.name,
                execution_id=context.execution_id,
                data={"reason": type(exc).__name__},
            )
        return ToolResult.failure(
            message,
            error=f"{type(exc).__name__}"[:80],
            error_code=code,
            tool_name=self.name,
            execution_id=context.execution_id,
        )

    @staticmethod
    def _public_message(exc: Exception) -> str:
        """A user safe sentence. Cryptographic and transport detail stays out."""
        text = str(exc).strip()
        if not text:
            return "The Android bridge could not complete that request."
        return text[:200]


# ---------------------------------------------------------------------------
# Read-only tools
# ---------------------------------------------------------------------------
class BridgeStatusTool(AndroidBridgeTool):
    name = "android.bridge.status"
    description = (
        "Report the Android bridge health: transport, protocol version, how many "
        "devices are paired and connected, and any pairing waiting for approval."
    )
    risk_level = RiskLevel.SAFE
    required_permissions = (PERMISSION_DEVICE_STATUS_READ,)

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        blocked = self.guard()
        if blocked is not None:
            return blocked
        status = self.bridge.status()
        pending = self.bridge.pending_pairings()
        summary = (
            f"Android bridge: {status['devices']} device(s) known, "
            f"{status['paired_devices']} paired, {status['connected_devices']} connected, "
            f"{len(pending)} pairing(s) awaiting approval."
        )
        return ToolResult.ok(
            summary,
            data={
                "available": status["available"],
                "protocol_version": status["protocol_version"],
                "transport": status["transport"],
                "devices": status["devices"],
                "paired_devices": status["paired_devices"],
                "connected_devices": status["connected_devices"],
                "capabilities_understood": status["capabilities_understood"],
                "pending_pairings": pending,
            },
        )


class DeviceListTool(AndroidBridgeTool):
    name = "android.device.list"
    description = "List the Android devices this JARVIS knows, with their trust state."
    risk_level = RiskLevel.SAFE
    required_permissions = (PERMISSION_DEVICE_STATUS_READ,)

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        blocked = self.guard()
        if blocked is not None:
            return blocked
        devices = self.bridge.list_devices()
        if not devices:
            return ToolResult.ok(
                "No Android devices are paired with this JARVIS yet.",
                data={"devices": [], "count": 0},
            )
        return ToolResult.ok(
            f"{len(devices)} Android device(s) known.",
            data={"devices": devices, "count": len(devices)},
        )


class DeviceStatusTool(AndroidBridgeTool):
    name = "android.device.status"
    description = "Report one paired Android device's trust state, connection and health."
    risk_level = RiskLevel.SAFE
    required_permissions = (PERMISSION_DEVICE_STATUS_READ,)
    argument_schema = ArgumentSchema(DEVICE_ID_ARGUMENT)

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        blocked = self.guard()
        if blocked is not None:
            return blocked
        try:
            payload = self.bridge.device_status(str(arguments["device"]))
        except AndroidBridgeError as exc:
            return self.failure(exc, context)
        return ToolResult.ok(
            f"{payload.get('display_name', 'Android device')}: "
            f"{payload.get('trust_state', 'unknown')}, {payload.get('health', 'unknown')}.",
            data=payload,
        )


# ---------------------------------------------------------------------------
# Trust changing tools - all confirmation locked
# ---------------------------------------------------------------------------
class DevicePairTool(AndroidBridgeTool):
    name = "android.device.pair"
    description = (
        "Approve an Android pairing that the phone has already proved "
        "cryptographically. Ask the user to confirm the pairing code matches on "
        "both screens first; approving grants that device trust."
    )
    risk_level = RiskLevel.EXTERNAL_ACTION
    required_permissions = (PERMISSION_ANDROID_BRIDGE_PAIR,)
    requires_confirmation = True
    confirmation_mandatory = True
    argument_schema = ArgumentSchema(PAIRING_ID_ARGUMENT)

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        blocked = self.guard()
        if blocked is not None:
            return blocked
        pairing_id = str(arguments["pairing"])
        try:
            device = self.bridge.approve_pairing(pairing_id)
        except AndroidBridgeError as exc:
            return self.failure(exc, context)
        return ToolResult.ok(
            f"{device.get('display_name', 'Android device')} is now paired.",
            data={
                "device_id": device.get("device_id", ""),
                "display_name": device.get("display_name", ""),
                "fingerprint": device.get("fingerprint", ""),
                "trust_state": device.get("trust_state", TrustState.PAIRED.value),
            },
        )


class DeviceUnpairTool(AndroidBridgeTool):
    name = "android.device.unpair"
    description = (
        "Unpair an Android device: disconnect it and forget it. It could pair "
        "again from scratch afterwards."
    )
    risk_level = RiskLevel.EXTERNAL_ACTION
    required_permissions = (PERMISSION_ANDROID_BRIDGE_MANAGE,)
    requires_confirmation = True
    confirmation_mandatory = True
    argument_schema = ArgumentSchema(DEVICE_ID_ARGUMENT)

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        blocked = self.guard()
        if blocked is not None:
            return blocked
        device_id = str(arguments["device"])
        try:
            result = await self.bridge.unpair(device_id)
        except AndroidBridgeError as exc:
            return self.failure(exc, context)
        return ToolResult.ok(
            "The Android device was unpaired and forgotten.",
            data={"device_id": result.get("device_id", device_id), "removed": bool(result.get("removed"))},
        )


class DeviceRevokeTool(AndroidBridgeTool):
    name = "android.device.revoke"
    description = (
        "Permanently revoke an Android device's trust. It stays on record and can "
        "never pair or act again. Use this when a phone is lost or untrusted."
    )
    risk_level = RiskLevel.EXTERNAL_ACTION
    required_permissions = (PERMISSION_ANDROID_BRIDGE_MANAGE,)
    requires_confirmation = True
    confirmation_mandatory = True
    argument_schema = ArgumentSchema(DEVICE_ID_ARGUMENT)

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        blocked = self.guard()
        if blocked is not None:
            return blocked
        device_id = str(arguments["device"])
        try:
            device = self.bridge.revoke(device_id)
        except AndroidBridgeError as exc:
            return self.failure(exc, context)
        return ToolResult.ok(
            f"{device.get('display_name', 'Android device')} has been revoked.",
            data={
                "device_id": device.get("device_id", device_id),
                "trust_state": device.get("trust_state", TrustState.REVOKED.value),
            },
        )


ANDROID_BRIDGE_TOOL_NAMES: Tuple[str, ...] = (
    BridgeStatusTool.name,
    DeviceListTool.name,
    DeviceStatusTool.name,
    DevicePairTool.name,
    DeviceUnpairTool.name,
    DeviceRevokeTool.name,
)


def build_android_bridge_tools(
    bridge: AndroidDeviceBridge,
    *,
    platform_probe: Callable[[], Platform] = detect_current_platform,
) -> Tuple[BaseDeviceTool, ...]:
    """Construct the six bridge tools sharing one bridge instance."""
    shared: Dict[str, Any] = {"bridge": bridge, "platform_probe": platform_probe}
    return (
        BridgeStatusTool(**shared),
        DeviceListTool(**shared),
        DeviceStatusTool(**shared),
        DevicePairTool(**shared),
        DeviceUnpairTool(**shared),
        DeviceRevokeTool(**shared),
    )
