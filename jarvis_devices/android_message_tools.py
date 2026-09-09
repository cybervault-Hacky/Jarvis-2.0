"""Model-facing tools for the deliberately narrow Android messaging surface.

Only an authenticated capability/status query and one confirmed, explicit text
send exist.  There is no conversation/history/contact/notification access and
no parameter for a URI, Android intent, call/message database id, network
endpoint, transport object, API method, template, command, retry or confirmation
bypass.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional, Tuple

from .android_bridge import AndroidBridgeError
from .android_calls import validate_phone_number
from .android_messages import (
    MAX_MESSAGE_CHARACTERS,
    AndroidMessageControl,
    MessageDeliveryState,
    validate_message_content,
)
from .android_tools import DEVICE_ID_ARGUMENT
from .arguments import ArgumentSchema, ArgumentSpec
from .enums import Platform, RiskLevel
from .errors import ErrorCode
from .permissions import PERMISSION_ANDROID_MESSAGE_READ, PERMISSION_ANDROID_MESSAGE_SEND
from .platform import detect_current_platform
from .results import ToolResult
from .tools import BaseDeviceTool, ToolContext

__all__ = [
    "MESSAGE_RECIPIENT_ARGUMENT",
    "MESSAGE_CONTENT_ARGUMENT",
    "AndroidMessageTool",
    "MessageStatusTool",
    "MessageSendTool",
    "ANDROID_MESSAGE_TOOL_NAMES",
    "build_android_message_tools",
]

# Recipient syntax intentionally mirrors Phase 7 exactly.  This broad schema
# only permits harmless presentation characters; the normalizer makes it strict
# E.164 before confirmation or bridge use.
MESSAGE_RECIPIENT_ARGUMENT = ArgumentSpec(
    name="recipient",
    type=str,
    required=True,
    max_length=64,
    pattern=r"\A[+0-9 ()-]+\Z",
    description="Explicit international E.164 recipient, beginning with +; not a contact, URI or endpoint.",
)

# Unicode remains unrestricted at the schema layer.  The concrete normalizer
# applies the text/UTF-8/control bounds without altering semantic content.
MESSAGE_CONTENT_ARGUMENT = ArgumentSpec(
    name="message",
    type=str,
    required=True,
    max_length=MAX_MESSAGE_CHARACTERS,
    description="Opaque Unicode text to send exactly as written; maximum 2048 characters.",
)

_UNAVAILABLE_CODES = frozenset(
    {
        ErrorCode.ANDROID_BRIDGE_UNAVAILABLE,
        ErrorCode.ANDROID_CAPABILITY_UNAVAILABLE,
        ErrorCode.ANDROID_DEVICE_NOT_CONNECTED,
        ErrorCode.ANDROID_DEVICE_STALE,
        ErrorCode.ANDROID_MESSAGE_UNAVAILABLE,
        ErrorCode.ANDROID_MESSAGE_UNSUPPORTED,
        ErrorCode.UNSUPPORTED_PLATFORM,
    }
)


class AndroidMessageTool(BaseDeviceTool):
    """PC-side base class shared by the two Android message tools."""

    platform = Platform.PC
    risk_level = RiskLevel.SAFE
    required_permissions: Tuple[str, ...] = (PERMISSION_ANDROID_MESSAGE_READ,)
    argument_schema = ArgumentSchema(DEVICE_ID_ARGUMENT)

    def __init__(
        self,
        control: AndroidMessageControl,
        *,
        platform_probe: Callable[[], Platform] = detect_current_platform,
    ) -> None:
        self._control = control
        self._platform_probe = platform_probe

    @property
    def control(self) -> AndroidMessageControl:
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
        """Turn bridge/controller failures into safe, content-free results."""
        code = str(getattr(exc, "error_code", ErrorCode.ANDROID_MESSAGE_FAILED))
        message = str(exc).strip()[:200] or "The Android messaging operation did not complete."
        if code == ErrorCode.ANDROID_MESSAGE_TIMEOUT:
            return ToolResult.timeout(
                "The phone did not answer in time; message acceptance is unknown and it was not resent.",
                error_code=code,
                tool_name=self.name,
                execution_id=context.execution_id,
            )
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
        return f"Perform {self.name} on Android device {arguments['device']}."


class MessageStatusTool(AndroidMessageTool):
    name = "android.message.status"
    description = "Report messaging capability and availability for one trusted Android device."
    risk_level = RiskLevel.SAFE
    required_permissions = (PERMISSION_ANDROID_MESSAGE_READ,)

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        blocked = self.guard()
        if blocked is not None:
            return blocked
        try:
            payload = await self.control.status(str(arguments["device"]))
        except AndroidBridgeError as exc:
            return self.failure(exc, context)
        if not payload["available"]:
            return ToolResult.unavailable(
                "Text messaging is unavailable on this Android device.",
                error_code=ErrorCode.ANDROID_MESSAGE_UNAVAILABLE,
                tool_name=self.name,
                execution_id=context.execution_id,
                data=payload,
            )
        return ToolResult.ok(
            "Text messaging is available on this Android device."
            if payload["send_supported"]
            else "Messaging status is available, but this device cannot send text messages.",
            data=payload,
        )


class MessageSendTool(AndroidMessageTool):
    name = "android.message.send"
    description = "Send one explicitly confirmed text message to one explicit international recipient."
    risk_level = RiskLevel.EXTERNAL_ACTION
    required_permissions = (PERMISSION_ANDROID_MESSAGE_SEND,)
    requires_confirmation = True
    confirmation_mandatory = True
    confirmation_target_mandatory = True
    argument_schema = ArgumentSchema(DEVICE_ID_ARGUMENT, MESSAGE_RECIPIENT_ARGUMENT, MESSAGE_CONTENT_ARGUMENT)

    def normalize_arguments(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return {
            **arguments,
            "recipient": validate_phone_number(arguments["recipient"]),
            "message": validate_message_content(arguments["message"]),
        }

    def confirmation_target(self, arguments: Dict[str, Any]) -> str:
        # This is the explicit human-confirmation UI exception to content
        # redaction.  It contains the exact canonical recipient and untouched
        # message so the user knows precisely what they are approving.
        return (
            f"Send message from Android device {arguments['device']} to "
            f"{arguments['recipient']}: {arguments['message']}"
        )

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        blocked = self.guard()
        if blocked is not None:
            return blocked
        try:
            payload = await self.control.send(
                str(arguments["device"]), arguments["recipient"], arguments["message"]
            )
        except AndroidBridgeError as exc:
            return self.failure(exc, context)
        if payload["duplicate"]:
            return ToolResult.ok(
                "The Android messaging controller recognized the existing message operation; no additional message was sent.",
                data=payload,
            )
        delivery_state = payload["delivery_state"]
        if delivery_state == MessageDeliveryState.ACCEPTED.value:
            message = "The Android messaging controller accepted the message request; delivery is not confirmed."
        elif delivery_state == MessageDeliveryState.SENT.value:
            message = "The Android device reported the message as sent; delivery is not confirmed."
        else:  # DELIVERED is accepted only when the companion explicitly attests to it.
            message = "The Android device reported the message as delivered."
        return ToolResult.ok(message, data=payload)


ANDROID_MESSAGE_TOOL_NAMES: Tuple[str, ...] = (
    MessageStatusTool.name,
    MessageSendTool.name,
)


def build_android_message_tools(
    bridge: Any,
    *,
    timeout: Optional[float] = None,
    platform_probe: Callable[[], Platform] = detect_current_platform,
) -> Tuple[BaseDeviceTool, ...]:
    """Build the two fixed Phase 8 tools on the one existing bridge."""
    control = AndroidMessageControl(bridge, timeout=timeout)
    shared: Dict[str, Any] = {"control": control, "platform_probe": platform_probe}
    return (MessageStatusTool(**shared), MessageSendTool(**shared))
