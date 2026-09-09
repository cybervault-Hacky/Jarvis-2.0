"""Explicit Android text messaging over the authenticated device bridge.

This module is deliberately limited to two named operations: a privacy-safe
messaging capability/status query and one confirmed text send.  It reuses the
Phase 5 bridge for trust, signatures, sessions, request correlation, sequence,
nonce, timestamp and replay checks; it does not create a network path or a
messaging implementation.

Message bodies are opaque Unicode text.  This layer never interprets text as a
command, URL, template, Android intent or API invocation.  Sending is never
automatically retried: a timeout means the outcome is unknown because Android
may already have accepted the request.
"""

from __future__ import annotations

import secrets
from enum import Enum
from typing import Any, Dict, FrozenSet, Mapping, Optional, Protocol, Tuple

from .android_bridge import AndroidBridgeError, AndroidDeviceBridge
from .android_calls import validate_phone_number
from .android_identity import AndroidDeviceIdentity
from .android_protocol import (
    CAPABILITY_MESSAGE_SEND,
    CAPABILITY_MESSAGE_STATUS,
    MessageType,
)
from .errors import ErrorCode

__all__ = [
    "MAX_MESSAGE_CHARACTERS",
    "MAX_MESSAGE_UTF8_BYTES",
    "MAX_MESSAGE_OPERATION_ID_LENGTH",
    "MessageDeliveryState",
    "AndroidMessageController",
    "AndroidMessageControl",
    "AndroidMessageError",
    "AndroidMessageUnavailableError",
    "AndroidMessageUnsupportedError",
    "AndroidMessagePermissionDeniedError",
    "AndroidMessageInvalidArgumentError",
    "AndroidMessageTimeoutError",
    "AndroidMessageOperationConflictError",
    "AndroidMessageFailedError",
    "MessageContentValidationError",
    "MessageOperationIdValidationError",
    "MESSAGE_CAPABILITIES",
    "MESSAGE_CAPABILITY_FOR_OPERATION",
    "MESSAGE_DEVICE_ERROR_CODES",
    "validate_message_content",
    "new_message_operation_id",
    "validate_message_operation_id",
    "redact_message_content",
]

# A text is bounded twice: characters protect application/UI work while UTF-8
# bytes protect the signed JSON payload.  The byte cap leaves ample room below
# the bridge-wide payload/frame limits for recipient and correlation metadata.
MAX_MESSAGE_CHARACTERS = 2_048
MAX_MESSAGE_UTF8_BYTES = 4_096
MAX_MESSAGE_OPERATION_ID_LENGTH = 38  # "msgop-" + 32 lower-case hex chars
_OPERATION_ID_PREFIX = "msgop-"


class MessageDeliveryState(str, Enum):
    """Only delivery states a companion may explicitly attest to."""

    ACCEPTED = "accepted"
    SENT = "sent"
    DELIVERED = "delivered"
    FAILED = "failed"
    UNKNOWN = "unknown"


class AndroidMessageError(AndroidBridgeError):
    """Base class for narrow Android text-message failures."""

    error_code = ErrorCode.ANDROID_MESSAGE_FAILED


class AndroidMessageUnavailableError(AndroidMessageError):
    error_code = ErrorCode.ANDROID_MESSAGE_UNAVAILABLE


class AndroidMessageUnsupportedError(AndroidMessageError):
    error_code = ErrorCode.ANDROID_MESSAGE_UNSUPPORTED


class AndroidMessagePermissionDeniedError(AndroidMessageError):
    error_code = ErrorCode.ANDROID_MESSAGE_PERMISSION_DENIED


class AndroidMessageInvalidArgumentError(AndroidMessageError):
    error_code = ErrorCode.ANDROID_MESSAGE_INVALID_ARGUMENT


class AndroidMessageTimeoutError(AndroidMessageError):
    """No response arrived; it never means that a message was delivered."""

    error_code = ErrorCode.ANDROID_MESSAGE_TIMEOUT


class AndroidMessageOperationConflictError(AndroidMessageError):
    """A reused operation id was presented with different protected content."""

    error_code = ErrorCode.ANDROID_MESSAGE_OPERATION_CONFLICT


class AndroidMessageFailedError(AndroidMessageError):
    error_code = ErrorCode.ANDROID_MESSAGE_FAILED


class MessageContentValidationError(AndroidMessageInvalidArgumentError):
    """Message content failed a privacy-safe validation check."""


class MessageOperationIdValidationError(AndroidMessageInvalidArgumentError):
    """Internal message-operation correlation material was malformed."""


_ERROR_TYPES = {
    "unsupported": AndroidMessageUnsupportedError,
    "unavailable": AndroidMessageUnavailableError,
    "permission_denied": AndroidMessagePermissionDeniedError,
    "invalid_argument": AndroidMessageInvalidArgumentError,
    "operation_conflict": AndroidMessageOperationConflictError,
    "failed": AndroidMessageFailedError,
}

MESSAGE_DEVICE_ERROR_CODES: Dict[str, str] = {
    "unsupported": ErrorCode.ANDROID_MESSAGE_UNSUPPORTED,
    "unavailable": ErrorCode.ANDROID_MESSAGE_UNAVAILABLE,
    "permission_denied": ErrorCode.ANDROID_MESSAGE_PERMISSION_DENIED,
    "invalid_argument": ErrorCode.ANDROID_MESSAGE_INVALID_ARGUMENT,
    "operation_conflict": ErrorCode.ANDROID_MESSAGE_OPERATION_CONFLICT,
    "failed": ErrorCode.ANDROID_MESSAGE_FAILED,
}

MESSAGE_CAPABILITIES: Tuple[str, ...] = (
    CAPABILITY_MESSAGE_STATUS,
    CAPABILITY_MESSAGE_SEND,
)

MESSAGE_CAPABILITY_FOR_OPERATION: Mapping[MessageType, str] = {
    MessageType.MESSAGE_STATUS: CAPABILITY_MESSAGE_STATUS,
    MessageType.MESSAGE_SEND: CAPABILITY_MESSAGE_SEND,
}


class AndroidMessageController(Protocol):
    """Future Android companion contract; this repository does not send SMS.

    A real companion must independently enforce Android's own user permissions
    and messaging policy after authenticating the paired host/session.  It must
    keep ``operation_id`` deduplication durable enough for its chosen transport
    and report only a delivery state it can actually verify.
    """

    async def get_status(self) -> Dict[str, Any]: ...

    async def send(self, recipient: str, message: str, operation_id: str) -> Dict[str, Any]: ...


def validate_message_content(value: Any) -> str:
    """Accept bounded opaque Unicode text without changing its content.

    C0/C1 controls (including NUL, line separators and escape sequences) are
    refused so an input cannot poison logs or protocol-facing diagnostics.  No
    other semantic filtering occurs: URLs, JSON, code-looking text and ordinary
    Unicode letters/emoji remain exactly user content, never executable input.
    """
    if not isinstance(value, str):
        raise MessageContentValidationError("A message must be text.")
    if not value or not value.strip():
        raise MessageContentValidationError("A message must not be empty.")
    if len(value) > MAX_MESSAGE_CHARACTERS:
        raise MessageContentValidationError("The message is too long.")
    if any(ord(char) <= 31 or 127 <= ord(char) <= 159 for char in value):
        raise MessageContentValidationError("The message contains unsupported control characters.")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise MessageContentValidationError("The message is not valid Unicode text.") from exc
    if len(encoded) > MAX_MESSAGE_UTF8_BYTES:
        raise MessageContentValidationError("The encoded message is too large.")
    # Return exactly the original object value: no trimming, URL rewriting,
    # hidden prefix/suffix, signature, template expansion or other mutation.
    return value


def new_message_operation_id() -> str:
    """Create an internal, authenticated, bounded idempotency identifier."""
    return f"{_OPERATION_ID_PREFIX}{secrets.token_hex(16)}"


def validate_message_operation_id(value: Any) -> str:
    """Validate the internal operation id without accepting model-selected ids."""
    if not isinstance(value, str) or len(value) != MAX_MESSAGE_OPERATION_ID_LENGTH:
        raise MessageOperationIdValidationError("The message operation identifier is invalid.")
    suffix = value[len(_OPERATION_ID_PREFIX):]
    if not value.startswith(_OPERATION_ID_PREFIX) or any(char not in "0123456789abcdef" for char in suffix):
        raise MessageOperationIdValidationError("The message operation identifier is invalid.")
    return value


def redact_message_content(value: Any) -> str:
    """Return a non-reversible diagnostic label without preserving body text."""
    if not isinstance(value, str):
        return "[redacted message]"
    return f"[redacted message: {len(value)} characters]"


def _parse_delivery_state(value: Any) -> MessageDeliveryState:
    if not isinstance(value, str):
        raise AndroidMessageFailedError("The phone returned an invalid message delivery state.")
    try:
        return MessageDeliveryState(value)
    except ValueError as exc:
        raise AndroidMessageFailedError("The phone returned an unknown message delivery state.") from exc


class AndroidMessageControl:
    """PC-side orchestrator restricted to authenticated status and text send."""

    def __init__(self, bridge: AndroidDeviceBridge, *, timeout: Optional[float] = None) -> None:
        self._bridge = bridge
        self._timeout = timeout

    @property
    def bridge(self) -> AndroidDeviceBridge:
        return self._bridge

    def _prepare(self, device_id: str, capability: str) -> AndroidDeviceIdentity:
        # require_connected performs trusted identity, paired/revoked,
        # connection and stale-session checks before a frame can be emitted.
        device = self._bridge.require_connected(device_id)
        self._bridge.require_capability(device_id, capability)
        return device

    async def _request(
        self,
        device_id: str,
        request_type: MessageType,
        response_type: MessageType,
        capability: str,
        *,
        payload: Optional[Mapping[str, Any]] = None,
        operation: str,
        success_fields: FrozenSet[str],
    ) -> Tuple[AndroidDeviceIdentity, Dict[str, Any]]:
        device = self._prepare(device_id, capability)
        response = await self._bridge.send_request(
            device_id,
            request_type,
            payload or {},
            expect=response_type,
            timeout=self._timeout,
        )
        if response is None:
            raise AndroidMessageTimeoutError(
                f"The phone did not answer the {operation} request in time; the outcome is unknown."
            )
        return device, self._unwrap_response(
            response.payload, operation=operation, success_fields=success_fields
        )

    def _unwrap_response(
        self,
        payload: Any,
        *,
        operation: str,
        success_fields: FrozenSet[str],
    ) -> Dict[str, Any]:
        """Refuse loose/diagnostic peer data rather than leaking it upstream."""
        if not isinstance(payload, Mapping) or "ok" not in payload or not isinstance(payload["ok"], bool):
            raise AndroidMessageFailedError(f"The phone returned an invalid {operation} response.")
        fields = dict(payload)
        if not fields["ok"]:
            if set(fields) - {"ok", "error"}:
                raise AndroidMessageFailedError(f"The phone returned an invalid {operation} response.")
            reason = fields.get("error")
            if reason not in _ERROR_TYPES:
                raise AndroidMessageFailedError(f"The phone returned an invalid {operation} response.")
            raise _ERROR_TYPES[reason](f"The phone could not {operation}.")
        allowed = frozenset({"ok"}) | success_fields
        if set(fields) - allowed or not success_fields.issubset(fields):
            raise AndroidMessageFailedError(f"The phone returned an invalid {operation} response.")
        return fields

    async def status(self, device_id: str) -> Dict[str, Any]:
        """Return only capability/availability metadata, never message history."""
        device, fields = await self._request(
            device_id,
            MessageType.MESSAGE_STATUS,
            MessageType.MESSAGE_STATUS_RESPONSE,
            CAPABILITY_MESSAGE_STATUS,
            operation="report messaging status",
            success_fields=frozenset({"available", "mode", "send_supported"}),
        )
        if not isinstance(fields["available"], bool) or not isinstance(fields["send_supported"], bool):
            raise AndroidMessageFailedError("The phone returned an invalid messaging status.")
        if fields["mode"] != "text":
            raise AndroidMessageFailedError("The phone returned an unsupported messaging mode.")
        return {
            "device_id": device.device_id,
            "display_name": device.display_name,
            "available": fields["available"],
            "mode": "text",
            "send_supported": fields["send_supported"],
        }

    async def send(self, device_id: str, recipient: Any, message: Any) -> Dict[str, Any]:
        """Send once with a private internal idempotency id; never retry it."""
        return await self._send_with_operation(
            device_id,
            recipient,
            message,
            operation_id=new_message_operation_id(),
        )

    async def _send_with_operation(
        self,
        device_id: str,
        recipient: Any,
        message: Any,
        *,
        operation_id: str,
    ) -> Dict[str, Any]:
        """Internal/test seam for one already-generated operation identifier.

        There is intentionally no model-facing ``operation_id`` argument.  A
        duplicate here can only occur from a transport/client re-presentation;
        the companion recognizes it without emitting a second message.
        """
        canonical_recipient = validate_phone_number(recipient)
        text = validate_message_content(message)
        operation_id = validate_message_operation_id(operation_id)
        # A device must advertise both the privacy-safe messaging status
        # capability and the separate authority to send before a send frame
        # may leave JARVIS. This is capability verification, not a history read.
        self._prepare(device_id, CAPABILITY_MESSAGE_STATUS)
        device, fields = await self._request(
            device_id,
            MessageType.MESSAGE_SEND,
            MessageType.MESSAGE_SEND_RESPONSE,
            CAPABILITY_MESSAGE_SEND,
            payload={
                "recipient": canonical_recipient,
                "message": text,
                "operation_id": operation_id,
            },
            operation="send message",
            success_fields=frozenset({"operation_id", "delivery_state", "duplicate"}),
        )
        if fields["operation_id"] != operation_id:
            raise AndroidMessageFailedError("The phone returned a mismatched message operation identifier.")
        delivery_state = _parse_delivery_state(fields["delivery_state"])
        if delivery_state not in (MessageDeliveryState.ACCEPTED, MessageDeliveryState.SENT, MessageDeliveryState.DELIVERED):
            raise AndroidMessageFailedError("The phone did not accept the message request.")
        if not isinstance(fields["duplicate"], bool):
            raise AndroidMessageFailedError("The phone returned an invalid duplicate-message result.")
        # The operation id, recipient and message body are purposefully absent
        # from returned tool data; they remain only in the signed frame and
        # trusted companion's private send operation.
        return {
            "device_id": device.device_id,
            "delivery_state": delivery_state.value,
            "duplicate": fields["duplicate"],
        }
