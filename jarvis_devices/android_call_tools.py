"""Model-facing tools for explicit Android call management (Phase 7).

The surface is intentionally limited to current-call status plus five dedicated
operations.  Every tool targets a registered ``adev-...`` identity through the
existing authenticated bridge.  There is no call identifier, contact lookup,
URI, Android API/method, transport address, command, recording, interception,
microphone or messaging parameter.

Dialing is an ``EXTERNAL_ACTION`` and ``confirmation_mandatory``.  Its
confirmation target contains the selected device and canonical E.164 number, so
a confirmation cannot be silently reused for a different destination.  Answer,
reject and end are also explicit external actions under the existing policy.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional, Tuple

from .android_bridge import AndroidBridgeError
from .android_calls import (
    MAX_PHONE_NUMBER_INPUT_LENGTH,
    AndroidCallControl,
    AndroidCallError,
    AndroidCallState,
    PhoneNumberValidationError,
    validate_phone_number,
)
from .android_tools import DEVICE_ID_ARGUMENT
from .arguments import ArgumentSchema, ArgumentSpec
from .enums import Platform, RiskLevel
from .errors import ErrorCode
from .permissions import PERMISSION_ANDROID_CALL_CONTROL, PERMISSION_ANDROID_CALL_READ
from .platform import detect_current_platform
from .results import ToolResult
from .tools import BaseDeviceTool, ToolContext

__all__ = [
    "PHONE_NUMBER_ARGUMENT",
    "AndroidCallTool",
    "CallStatusTool",
    "CallDialTool",
    "CallAnswerTool",
    "CallRejectTool",
    "CallEndTool",
    "ANDROID_CALL_TOOL_NAMES",
    "build_android_call_tools",
]

# The schema blocks obvious hostile values before they reach normalization.  The
# normalizer then applies the narrower canonical E.164 rule and removes only
# visual formatting.  `\Z` prevents a newline from matching at the end.
PHONE_NUMBER_ARGUMENT = ArgumentSpec(
    name="phone_number",
    type=str,
    required=True,
    max_length=MAX_PHONE_NUMBER_INPUT_LENGTH,
    pattern=r"\A[+0-9 ()-]+\Z",
    description=(
        "A telephone number in international E.164 form, beginning with +. "
        "Spaces, parentheses and hyphens are formatting only; URI schemes, "
        "extensions and other destinations are not accepted."
    ),
)

_UNAVAILABLE_CODES = frozenset(
    {
        ErrorCode.ANDROID_BRIDGE_UNAVAILABLE,
        ErrorCode.ANDROID_CAPABILITY_UNAVAILABLE,
        ErrorCode.ANDROID_DEVICE_NOT_CONNECTED,
        ErrorCode.ANDROID_DEVICE_STALE,
        ErrorCode.ANDROID_CALL_UNAVAILABLE,
        ErrorCode.ANDROID_CALL_UNSUPPORTED,
        ErrorCode.UNSUPPORTED_PLATFORM,
    }
)


class AndroidCallTool(BaseDeviceTool):
    """PC-side base for call tools sharing one :class:`AndroidCallControl`."""

    platform = Platform.PC
    risk_level = RiskLevel.SAFE
    required_permissions: Tuple[str, ...] = (PERMISSION_ANDROID_CALL_READ,)
    argument_schema = ArgumentSchema(DEVICE_ID_ARGUMENT)

    def __init__(
        self,
        control: AndroidCallControl,
        *,
        platform_probe: Callable[[], Platform] = detect_current_platform,
    ) -> None:
        self._control = control
        self._platform_probe = platform_probe

    @property
    def control(self) -> AndroidCallControl:
        return self._control

    def is_available(self) -> bool:
        return self._control.bridge.available

    def guard(self) -> Optional[ToolResult]:
        detected = self._platform_probe()
        if detected is not Platform.PC:
            return ToolResult.unavailable(
                f"{self.name} runs on the PC side of the Android bridge (detected: {detected.value}).",
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
        """Convert errors to safe structured results; never echo a number."""
        code = str(getattr(exc, "error_code", ErrorCode.ANDROID_CALL_FAILED))
        message = str(exc).strip()[:200] or "The Android call operation did not complete."
        if code in _UNAVAILABLE_CODES:
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

    def confirmation_target(self, arguments: Dict[str, Any]) -> str:
        """A safe, explicit target sentence for the confirmation UI."""
        return f"Perform {self.name} on Android device {arguments['device']}."


class CallStatusTool(AndroidCallTool):
    name = "android.call.status"
    description = "Report the current call state on one trusted Android device."
    risk_level = RiskLevel.SAFE
    required_permissions = (PERMISSION_ANDROID_CALL_READ,)

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        blocked = self.guard()
        if blocked is not None:
            return blocked
        try:
            payload = await self.control.status(str(arguments["device"]))
        except AndroidBridgeError as exc:
            return self.failure(exc, context)
        if payload["state"] == AndroidCallState.UNAVAILABLE.value:
            return ToolResult.unavailable(
                "Call status is unavailable on this Android device.",
                error_code=ErrorCode.ANDROID_CALL_UNAVAILABLE,
                tool_name=self.name,
                execution_id=context.execution_id,
                data=payload,
            )
        direction = f" ({payload['direction']})" if payload.get("direction") else ""
        return ToolResult.ok(f"Call state is {payload['state']}{direction}.", data=payload)


class CallDialTool(AndroidCallTool):
    name = "android.call.dial"
    description = "Place one confirmed call to a canonical international telephone number."
    risk_level = RiskLevel.EXTERNAL_ACTION
    required_permissions = (PERMISSION_ANDROID_CALL_CONTROL,)
    requires_confirmation = True
    confirmation_mandatory = True
    argument_schema = ArgumentSchema(DEVICE_ID_ARGUMENT, PHONE_NUMBER_ARGUMENT)

    def normalize_arguments(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        # This runs before the manager creates its confirmation, binding the
        # canonical destination rather than a presentation-form variant.
        return {**arguments, "phone_number": validate_phone_number(arguments["phone_number"])}

    def confirmation_target(self, arguments: Dict[str, Any]) -> str:
        # This is intentionally the one place outside the protocol where the
        # full number is shown: explicit human confirmation must see it.
        return (
            f"Place call on Android device {arguments['device']} to "
            f"{arguments['phone_number']}."
        )

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        blocked = self.guard()
        if blocked is not None:
            return blocked
        try:
            payload = await self.control.dial(
                str(arguments["device"]), arguments["phone_number"]
            )
        except AndroidBridgeError as exc:
            return self.failure(exc, context)
        # Do not repeat the destination in normal model output or audit records.
        return ToolResult.ok("The phone accepted the request and is dialing.", data=payload)


class CallAnswerTool(AndroidCallTool):
    name = "android.call.answer"
    description = "Answer the currently ringing incoming call on one Android device."
    risk_level = RiskLevel.EXTERNAL_ACTION
    required_permissions = (PERMISSION_ANDROID_CALL_CONTROL,)
    requires_confirmation = True

    def confirmation_target(self, arguments: Dict[str, Any]) -> str:
        return f"Answer the incoming call on Android device {arguments['device']}."

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        blocked = self.guard()
        if blocked is not None:
            return blocked
        try:
            payload = await self.control.answer(str(arguments["device"]))
        except AndroidBridgeError as exc:
            return self.failure(exc, context)
        return ToolResult.ok("The incoming call was answered.", data=payload)


class CallRejectTool(AndroidCallTool):
    name = "android.call.reject"
    description = "Reject the currently ringing incoming call on one Android device."
    risk_level = RiskLevel.EXTERNAL_ACTION
    required_permissions = (PERMISSION_ANDROID_CALL_CONTROL,)
    requires_confirmation = True

    def confirmation_target(self, arguments: Dict[str, Any]) -> str:
        return f"Reject the incoming call on Android device {arguments['device']}."

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        blocked = self.guard()
        if blocked is not None:
            return blocked
        try:
            payload = await self.control.reject(str(arguments["device"]))
        except AndroidBridgeError as exc:
            return self.failure(exc, context)
        return ToolResult.ok("The incoming call was rejected.", data=payload)


class CallEndTool(AndroidCallTool):
    name = "android.call.end"
    description = "End the current call on one Android device."
    risk_level = RiskLevel.EXTERNAL_ACTION
    required_permissions = (PERMISSION_ANDROID_CALL_CONTROL,)
    requires_confirmation = True

    def confirmation_target(self, arguments: Dict[str, Any]) -> str:
        return f"End the current call on Android device {arguments['device']}."

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        blocked = self.guard()
        if blocked is not None:
            return blocked
        try:
            payload = await self.control.end(str(arguments["device"]))
        except AndroidBridgeError as exc:
            return self.failure(exc, context)
        if not payload["ended"]:
            return ToolResult.failure(
                "No active call was ended.",
                error="AndroidCallNoActiveCall",
                error_code=ErrorCode.ANDROID_CALL_NO_ACTIVE_CALL,
                tool_name=self.name,
                execution_id=context.execution_id,
                data=payload,
            )
        return ToolResult.ok("The phone is ending the active call.", data=payload)


ANDROID_CALL_TOOL_NAMES: Tuple[str, ...] = (
    CallStatusTool.name,
    CallDialTool.name,
    CallAnswerTool.name,
    CallRejectTool.name,
    CallEndTool.name,
)


def build_android_call_tools(
    bridge: Any,
    *,
    timeout: Optional[float] = None,
    platform_probe: Callable[[], Platform] = detect_current_platform,
) -> Tuple[BaseDeviceTool, ...]:
    """Build the five allowlisted call tools over a single existing bridge."""
    control = AndroidCallControl(bridge, timeout=timeout)
    shared: Dict[str, Any] = {"control": control, "platform_probe": platform_probe}
    return (
        CallStatusTool(**shared),
        CallDialTool(**shared),
        CallAnswerTool(**shared),
        CallRejectTool(**shared),
        CallEndTool(**shared),
    )
