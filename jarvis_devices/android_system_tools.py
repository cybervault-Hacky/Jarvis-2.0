"""JARVIS tools for Android system control (Phase 6).

Thirteen tools, all of which target a **registered device id** and nothing else:

===================================  =================  =========================
Tool                                 Risk               Permission
===================================  =================  =========================
``android.system.status``            SAFE               device.android.system.read
``android.system.get_volume``        SAFE               device.android.system.read
``android.system.set_volume``        LOW_RISK           device.android.system.control
``android.system.mute``              LOW_RISK           device.android.system.control
``android.system.unmute``            LOW_RISK           device.android.system.control
``android.system.get_brightness``    SAFE               device.android.system.read
``android.system.set_brightness``    LOW_RISK           device.android.system.control
``android.system.wifi.status``       SAFE               device.android.system.read
``android.system.wifi.enable``       EXTERNAL_ACTION    device.android.system.control
``android.system.wifi.disable``      EXTERNAL_ACTION    device.android.system.control
``android.system.bluetooth.status``  SAFE               device.android.system.read
``android.system.bluetooth.enable``  EXTERNAL_ACTION    device.android.system.control
``android.system.bluetooth.disable`` EXTERNAL_ACTION    device.android.system.control
===================================  =================  =========================

Confirmation follows the existing policy rather than a blanket rule: reading
state needs none, volume and brightness are `LOW_RISK`, and switching a radio is
`EXTERNAL_ACTION` so the policy asks first - exactly how the PC's own Wi-Fi and
Bluetooth tools in Phase 3 are classified. No tool exposes a `confirm` flag, so
nothing the model generates can switch confirmation off.

There is no `toggle` tool anywhere. Every state change names the state it wants
(``enable`` / ``disable`` / ``mute`` / ``unmute`` / an absolute level), so
re-sending a request can never produce the opposite result.

Absent by design: any argument that could name a destination, a command, a
shell, an ADB invocation, an Android API or method, an SSID, a password, a file
path or a volume stream.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional, Tuple

from .android_bridge import AndroidBridgeError, AndroidBridgeUnavailableError
from .android_system import AndroidSystemControl, AndroidSystemError
from .android_tools import DEVICE_ID_ARGUMENT
from .arguments import ArgumentSchema, ArgumentSpec
from .enums import Platform, RiskLevel
from .errors import ErrorCode
from .permissions import (
    PERMISSION_ANDROID_SYSTEM_CONTROL,
    PERMISSION_ANDROID_SYSTEM_READ,
)
from .platform import detect_current_platform
from .results import ToolResult
from .tools import BaseDeviceTool, ToolContext

__all__ = [
    "AndroidSystemTool",
    "SystemStatusTool",
    "GetVolumeTool",
    "SetVolumeTool",
    "MuteTool",
    "UnmuteTool",
    "GetBrightnessTool",
    "SetBrightnessTool",
    "WifiStatusTool",
    "WifiEnableTool",
    "WifiDisableTool",
    "BluetoothStatusTool",
    "BluetoothEnableTool",
    "BluetoothDisableTool",
    "ANDROID_SYSTEM_TOOL_NAMES",
    "build_android_system_tools",
    "LEVEL_ARGUMENT",
]

LEVEL_ARGUMENT = ArgumentSpec(
    name="level",
    type=int,
    required=True,
    min_value=0,
    max_value=100,
    description="An integer percentage from 0 to 100.",
)

#: Error codes that mean "this cannot work right now" rather than "it failed".
_UNAVAILABLE_CODES = frozenset(
    {
        ErrorCode.ANDROID_BRIDGE_UNAVAILABLE,
        ErrorCode.ANDROID_CAPABILITY_UNAVAILABLE,
        ErrorCode.ANDROID_SYSTEM_UNAVAILABLE,
        ErrorCode.ANDROID_VOLUME_UNAVAILABLE,
        ErrorCode.ANDROID_BRIGHTNESS_UNAVAILABLE,
        ErrorCode.ANDROID_WIFI_UNAVAILABLE,
        ErrorCode.ANDROID_BLUETOOTH_UNAVAILABLE,
        ErrorCode.ANDROID_DEVICE_NOT_CONNECTED,
        ErrorCode.ANDROID_DEVICE_STALE,
        ErrorCode.UNSUPPORTED_PLATFORM,
    }
)


class AndroidSystemTool(BaseDeviceTool):
    """Base class for the Android system-control tools.

    These run on the **PC** side of the bridge, so the platform is
    :attr:`Platform.PC`; whether they can work is decided by the bridge.
    """

    platform = Platform.PC
    risk_level = RiskLevel.SAFE
    required_permissions: Tuple[str, ...] = (PERMISSION_ANDROID_SYSTEM_READ,)
    argument_schema = ArgumentSchema(DEVICE_ID_ARGUMENT)

    def __init__(
        self,
        control: AndroidSystemControl,
        *,
        platform_probe: Callable[[], Platform] = detect_current_platform,
    ) -> None:
        self._control = control
        self._platform_probe = platform_probe

    @property
    def control(self) -> AndroidSystemControl:
        return self._control

    # ------------------------------------------------------------------
    def is_available(self) -> bool:
        return self._control.bridge.available

    def guard(self) -> Optional[ToolResult]:
        """Refuse honestly before touching the bridge."""
        detected = self._platform_probe()
        if detected is not Platform.PC:
            return ToolResult.unavailable(
                f"{self.name} runs on the PC side of the Android bridge "
                f"(detected: {detected.value}).",
                error_code=ErrorCode.UNSUPPORTED_PLATFORM,
                tool_name=self.name,
                data={"platform": detected.value},
            )
        if not self._control.bridge.available:
            return ToolResult.unavailable(
                "The Android bridge is unavailable on this machine.",
                error_code=ErrorCode.ANDROID_BRIDGE_UNAVAILABLE,
                tool_name=self.name,
                data={"reason": self._control.bridge.unavailable_reason()[:200]},
            )
        return None

    def failure(self, exc: Exception, context: ToolContext) -> ToolResult:
        """Turn a bridge/system error into a structured result.

        The message is the short, user-safe sentence the error carries. Raw
        exception text and stack traces never reach the model.
        """
        code = str(getattr(exc, "error_code", ErrorCode.ANDROID_SYSTEM_FAILED))
        message = str(exc).strip()[:200] or "The Android system operation did not complete."
        if code in _UNAVAILABLE_CODES:
            # ToolResult.unavailable() takes no ``error`` keyword - passing one
            # would raise TypeError and collapse this into a generic tool_error.
            return ToolResult.unavailable(
                message,
                error_code=code,
                tool_name=self.name,
                execution_id=context.execution_id,
                data={"reason": type(exc).__name__},
            )
        return ToolResult.failure(
            message,
            error=type(exc).__name__[:80],
            error_code=code,
            tool_name=self.name,
            execution_id=context.execution_id,
        )


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------
class SystemStatusTool(AndroidSystemTool):
    name = "android.system.status"
    description = (
        "Report an Android device's system state: volume, mute, brightness, "
        "Wi-Fi and Bluetooth - only the parts that device actually supports."
    )
    risk_level = RiskLevel.SAFE
    required_permissions = (PERMISSION_ANDROID_SYSTEM_READ,)

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        blocked = self.guard()
        if blocked is not None:
            return blocked
        try:
            payload = await self.control.status(str(arguments["device"]))
        except AndroidBridgeError as exc:
            return self.failure(exc, context)
        return ToolResult.ok(
            f"{payload.get('display_name', 'Android device')}: "
            + ", ".join(payload.get("reported") or ["no system details reported"])
            + ".",
            data=payload,
        )


# ---------------------------------------------------------------------------
# Volume
# ---------------------------------------------------------------------------
class GetVolumeTool(AndroidSystemTool):
    name = "android.system.get_volume"
    description = "Report an Android device's media volume and mute state."
    risk_level = RiskLevel.SAFE
    required_permissions = (PERMISSION_ANDROID_SYSTEM_READ,)

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        blocked = self.guard()
        if blocked is not None:
            return blocked
        try:
            payload = await self.control.get_volume(str(arguments["device"]))
        except AndroidBridgeError as exc:
            return self.failure(exc, context)
        state = "muted" if payload["muted"] else "not muted"
        return ToolResult.ok(f"Volume is {payload['volume']}% ({state}).", data=payload)


class SetVolumeTool(AndroidSystemTool):
    name = "android.system.set_volume"
    description = (
        "Set an Android device's media volume to an exact percentage (0-100). "
        "It sets a level rather than stepping up or down, so repeating it is safe."
    )
    risk_level = RiskLevel.LOW_RISK
    required_permissions = (PERMISSION_ANDROID_SYSTEM_CONTROL,)
    argument_schema = ArgumentSchema(DEVICE_ID_ARGUMENT, LEVEL_ARGUMENT)

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        blocked = self.guard()
        if blocked is not None:
            return blocked
        try:
            payload = await self.control.set_volume(
                str(arguments["device"]), int(arguments["level"])
            )
        except AndroidBridgeError as exc:
            return self.failure(exc, context)
        return ToolResult.ok(f"Volume set to {payload['volume']}%.", data=payload)


class MuteTool(AndroidSystemTool):
    name = "android.system.mute"
    description = "Mute an Android device. It always ends up muted - it is not a toggle."
    risk_level = RiskLevel.LOW_RISK
    required_permissions = (PERMISSION_ANDROID_SYSTEM_CONTROL,)

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        blocked = self.guard()
        if blocked is not None:
            return blocked
        try:
            payload = await self.control.mute(str(arguments["device"]))
        except AndroidBridgeError as exc:
            return self.failure(exc, context)
        return ToolResult.ok("The phone is muted.", data=payload)


class UnmuteTool(AndroidSystemTool):
    name = "android.system.unmute"
    description = (
        "Unmute an Android device. It always ends up unmuted - it is not a toggle."
    )
    risk_level = RiskLevel.LOW_RISK
    required_permissions = (PERMISSION_ANDROID_SYSTEM_CONTROL,)

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        blocked = self.guard()
        if blocked is not None:
            return blocked
        try:
            payload = await self.control.unmute(str(arguments["device"]))
        except AndroidBridgeError as exc:
            return self.failure(exc, context)
        return ToolResult.ok(f"The phone is unmuted at {payload['volume']}%.", data=payload)


# ---------------------------------------------------------------------------
# Brightness
# ---------------------------------------------------------------------------
class GetBrightnessTool(AndroidSystemTool):
    name = "android.system.get_brightness"
    description = (
        "Report an Android device's screen brightness, and whether it is in "
        "adaptive mode."
    )
    risk_level = RiskLevel.SAFE
    required_permissions = (PERMISSION_ANDROID_SYSTEM_READ,)

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        blocked = self.guard()
        if blocked is not None:
            return blocked
        try:
            payload = await self.control.get_brightness(str(arguments["device"]))
        except AndroidBridgeError as exc:
            return self.failure(exc, context)
        note = " (adaptive brightness is on)" if payload.get("adaptive") else ""
        return ToolResult.ok(f"Brightness is {payload['brightness']}%{note}.", data=payload)


class SetBrightnessTool(AndroidSystemTool):
    name = "android.system.set_brightness"
    description = (
        "Set an Android device's screen brightness to an exact percentage "
        "(0-100). This does not turn adaptive brightness off; if the phone is in "
        "adaptive mode the result says so, because Android may then adjust the "
        "value itself."
    )
    risk_level = RiskLevel.LOW_RISK
    required_permissions = (PERMISSION_ANDROID_SYSTEM_CONTROL,)
    argument_schema = ArgumentSchema(DEVICE_ID_ARGUMENT, LEVEL_ARGUMENT)

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        blocked = self.guard()
        if blocked is not None:
            return blocked
        try:
            payload = await self.control.set_brightness(
                str(arguments["device"]), int(arguments["level"])
            )
        except AndroidBridgeError as exc:
            return self.failure(exc, context)
        note = " (adaptive brightness is on)" if payload.get("adaptive") else ""
        return ToolResult.ok(f"Brightness set to {payload['brightness']}%{note}.", data=payload)


# ---------------------------------------------------------------------------
# Wi-Fi
# ---------------------------------------------------------------------------
class WifiStatusTool(AndroidSystemTool):
    name = "android.system.wifi.status"
    description = "Report whether an Android device's Wi-Fi radio is on or off."
    risk_level = RiskLevel.SAFE
    required_permissions = (PERMISSION_ANDROID_SYSTEM_READ,)

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        blocked = self.guard()
        if blocked is not None:
            return blocked
        try:
            payload = await self.control.get_wifi_status(str(arguments["device"]))
        except AndroidBridgeError as exc:
            return self.failure(exc, context)
        return ToolResult.ok(
            f"Wi-Fi is {'on' if payload['enabled'] else 'off'}.", data=payload
        )


class WifiEnableTool(AndroidSystemTool):
    name = "android.system.wifi.enable"
    description = (
        "Turn an Android device's Wi-Fi radio on. Radio state only - it does not "
        "scan, join a network or handle passwords."
    )
    risk_level = RiskLevel.EXTERNAL_ACTION
    required_permissions = (PERMISSION_ANDROID_SYSTEM_CONTROL,)
    requires_confirmation = True

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        blocked = self.guard()
        if blocked is not None:
            return blocked
        try:
            payload = await self.control.set_wifi_enabled(str(arguments["device"]), True)
        except AndroidBridgeError as exc:
            return self.failure(exc, context)
        return ToolResult.ok("Wi-Fi is on.", data=payload)


class WifiDisableTool(AndroidSystemTool):
    name = "android.system.wifi.disable"
    description = (
        "Turn an Android device's Wi-Fi radio off. This will drop the phone's "
        "internet connection."
    )
    risk_level = RiskLevel.EXTERNAL_ACTION
    required_permissions = (PERMISSION_ANDROID_SYSTEM_CONTROL,)
    requires_confirmation = True

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        blocked = self.guard()
        if blocked is not None:
            return blocked
        try:
            payload = await self.control.set_wifi_enabled(str(arguments["device"]), False)
        except AndroidBridgeError as exc:
            return self.failure(exc, context)
        return ToolResult.ok("Wi-Fi is off.", data=payload)


# ---------------------------------------------------------------------------
# Bluetooth
# ---------------------------------------------------------------------------
class BluetoothStatusTool(AndroidSystemTool):
    name = "android.system.bluetooth.status"
    description = "Report whether an Android device's Bluetooth radio is on or off."
    risk_level = RiskLevel.SAFE
    required_permissions = (PERMISSION_ANDROID_SYSTEM_READ,)

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        blocked = self.guard()
        if blocked is not None:
            return blocked
        try:
            payload = await self.control.get_bluetooth_status(str(arguments["device"]))
        except AndroidBridgeError as exc:
            return self.failure(exc, context)
        return ToolResult.ok(
            f"Bluetooth is {'on' if payload['enabled'] else 'off'}.", data=payload
        )


class BluetoothEnableTool(AndroidSystemTool):
    name = "android.system.bluetooth.enable"
    description = (
        "Turn an Android device's Bluetooth radio on. Radio state only - it does "
        "not discover or pair with other devices."
    )
    risk_level = RiskLevel.EXTERNAL_ACTION
    required_permissions = (PERMISSION_ANDROID_SYSTEM_CONTROL,)
    requires_confirmation = True

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        blocked = self.guard()
        if blocked is not None:
            return blocked
        try:
            payload = await self.control.set_bluetooth_enabled(str(arguments["device"]), True)
        except AndroidBridgeError as exc:
            return self.failure(exc, context)
        return ToolResult.ok("Bluetooth is on.", data=payload)


class BluetoothDisableTool(AndroidSystemTool):
    name = "android.system.bluetooth.disable"
    description = (
        "Turn an Android device's Bluetooth radio off. This will disconnect any "
        "Bluetooth headset or watch."
    )
    risk_level = RiskLevel.EXTERNAL_ACTION
    required_permissions = (PERMISSION_ANDROID_SYSTEM_CONTROL,)
    requires_confirmation = True

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        blocked = self.guard()
        if blocked is not None:
            return blocked
        try:
            payload = await self.control.set_bluetooth_enabled(str(arguments["device"]), False)
        except AndroidBridgeError as exc:
            return self.failure(exc, context)
        return ToolResult.ok("Bluetooth is off.", data=payload)


ANDROID_SYSTEM_TOOL_NAMES: Tuple[str, ...] = (
    SystemStatusTool.name,
    GetVolumeTool.name,
    SetVolumeTool.name,
    MuteTool.name,
    UnmuteTool.name,
    GetBrightnessTool.name,
    SetBrightnessTool.name,
    WifiStatusTool.name,
    WifiEnableTool.name,
    WifiDisableTool.name,
    BluetoothStatusTool.name,
    BluetoothEnableTool.name,
    BluetoothDisableTool.name,
)


def build_android_system_tools(
    bridge: Any,
    *,
    timeout: Optional[float] = None,
    platform_probe: Callable[[], Platform] = detect_current_platform,
) -> Tuple[BaseDeviceTool, ...]:
    """Construct the thirteen Android system-control tools over one bridge."""
    control = AndroidSystemControl(bridge, timeout=timeout)
    shared: Dict[str, Any] = {"control": control, "platform_probe": platform_probe}
    return (
        SystemStatusTool(**shared),
        GetVolumeTool(**shared),
        SetVolumeTool(**shared),
        MuteTool(**shared),
        UnmuteTool(**shared),
        GetBrightnessTool(**shared),
        SetBrightnessTool(**shared),
        WifiStatusTool(**shared),
        WifiEnableTool(**shared),
        WifiDisableTool(**shared),
        BluetoothStatusTool(**shared),
        BluetoothEnableTool(**shared),
        BluetoothDisableTool(**shared),
    )
