"""Explicit Android call management over the authenticated Phase 5 bridge.

This module deliberately has two small, separate responsibilities:

* :class:`AndroidCallController` specifies the future Android companion surface.
  It has only five dedicated operations.  It is not an Android implementation.
* :class:`AndroidCallControl` is JARVIS's PC-side orchestrator.  It checks a
  trusted, connected device and an operation-specific advertised capability,
  then uses :class:`~jarvis_devices.android_bridge.AndroidDeviceBridge` for the
  signed request/response exchange.

There is no desktop telephony fallback, no raw telecom invocation, and no way
for model input to name a call, session, destination type, Android method, or
transport endpoint.  The only destination accepted by ``dial`` is a strictly
validated E.164 telephone number, carried solely in the dedicated dial frame.

Calls are deliberately non-retryable.  An unanswered dial, answer, reject, or
end request is reported as uncertain and is never resent by this layer.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, FrozenSet, Mapping, Optional, Protocol, Tuple

from .android_bridge import AndroidBridgeError, AndroidDeviceBridge
from .android_identity import AndroidDeviceIdentity
from .android_protocol import (
    CAPABILITY_CALL_ANSWER,
    CAPABILITY_CALL_DIAL,
    CAPABILITY_CALL_END,
    CAPABILITY_CALL_REJECT,
    CAPABILITY_CALL_STATUS,
    MessageType,
)
from .errors import ErrorCode

__all__ = [
    "MAX_PHONE_NUMBER_INPUT_LENGTH",
    "MAX_E164_DIGITS",
    "AndroidCallState",
    "CallDirection",
    "AndroidCallController",
    "AndroidCallControl",
    "AndroidCallError",
    "AndroidCallUnavailableError",
    "AndroidCallUnsupportedError",
    "AndroidCallPermissionDeniedError",
    "AndroidCallInvalidArgumentError",
    "AndroidCallInvalidStateError",
    "AndroidCallTimeoutError",
    "AndroidCallFailedError",
    "PhoneNumberValidationError",
    "CallStateTransitionError",
    "CallStateMachine",
    "CALL_CAPABILITIES",
    "CALL_CAPABILITY_FOR_OPERATION",
    "CALL_DEVICE_ERROR_CODES",
    "validate_phone_number",
    "redact_phone_number",
]

# E.164 has at most fifteen digits; a larger input cap lets us reject oversized
# hostile input before doing any normalisation while accommodating harmless
# formatting characters.  The model-facing schema uses the same bounded value.
MAX_PHONE_NUMBER_INPUT_LENGTH = 64
MAX_E164_DIGITS = 15
MIN_E164_DIGITS = 7


class AndroidCallState(str, Enum):
    """The complete, allowlisted call state vocabulary."""

    IDLE = "idle"
    RINGING = "ringing"
    DIALING = "dialing"
    ACTIVE = "active"
    ENDING = "ending"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"


class CallDirection(str, Enum):
    """The only non-sensitive direction labels a companion may report."""

    INCOMING = "incoming"
    OUTGOING = "outgoing"
    UNKNOWN = "unknown"


# Every transition is explicit and reviewable.  A first trusted status report is
# a baseline rather than a transition because JARVIS may start while a phone is
# already in a call.  Thereafter an impossible peer-reported jump is rejected.
_ALLOWED_TRANSITIONS: Mapping[AndroidCallState, FrozenSet[AndroidCallState]] = {
    AndroidCallState.IDLE: frozenset(
        {AndroidCallState.IDLE, AndroidCallState.RINGING, AndroidCallState.DIALING, AndroidCallState.FAILED, AndroidCallState.UNAVAILABLE}
    ),
    AndroidCallState.RINGING: frozenset(
        {AndroidCallState.RINGING, AndroidCallState.ACTIVE, AndroidCallState.IDLE, AndroidCallState.UNAVAILABLE}
    ),
    AndroidCallState.DIALING: frozenset(
        {
            AndroidCallState.DIALING,
            AndroidCallState.ACTIVE,
            AndroidCallState.FAILED,
            AndroidCallState.IDLE,
            AndroidCallState.UNAVAILABLE,
        }
    ),
    AndroidCallState.ACTIVE: frozenset(
        {AndroidCallState.ACTIVE, AndroidCallState.ENDING, AndroidCallState.IDLE, AndroidCallState.UNAVAILABLE}
    ),
    AndroidCallState.ENDING: frozenset(
        {AndroidCallState.ENDING, AndroidCallState.IDLE, AndroidCallState.FAILED, AndroidCallState.UNAVAILABLE}
    ),
    AndroidCallState.FAILED: frozenset(
        {AndroidCallState.FAILED, AndroidCallState.IDLE, AndroidCallState.DIALING, AndroidCallState.UNAVAILABLE}
    ),
    AndroidCallState.UNAVAILABLE: frozenset(
        {AndroidCallState.UNAVAILABLE, AndroidCallState.IDLE}
    ),
}


class AndroidCallError(AndroidBridgeError):
    """Base class for Android call-management failures."""

    error_code = ErrorCode.ANDROID_CALL_FAILED


class AndroidCallUnavailableError(AndroidCallError):
    error_code = ErrorCode.ANDROID_CALL_UNAVAILABLE


class AndroidCallUnsupportedError(AndroidCallError):
    error_code = ErrorCode.ANDROID_CALL_UNSUPPORTED


class AndroidCallPermissionDeniedError(AndroidCallError):
    error_code = ErrorCode.ANDROID_CALL_PERMISSION_DENIED


class AndroidCallInvalidArgumentError(AndroidCallError):
    error_code = ErrorCode.ANDROID_CALL_INVALID_ARGUMENT


class AndroidCallInvalidStateError(AndroidCallError):
    error_code = ErrorCode.ANDROID_CALL_INVALID_STATE


class AndroidCallTimeoutError(AndroidCallError):
    """No response arrived. It never means the requested action succeeded."""

    error_code = ErrorCode.ANDROID_CALL_TIMEOUT


class AndroidCallFailedError(AndroidCallError):
    error_code = ErrorCode.ANDROID_CALL_FAILED


class PhoneNumberValidationError(AndroidCallInvalidArgumentError):
    """A dial destination failed strict E.164 validation.

    Its message intentionally contains no submitted destination, because a
    malformed value can itself be sensitive or malicious text.
    """


class CallStateTransitionError(AndroidCallInvalidStateError):
    """A companion reported a state transition outside the allowlist."""


_ERROR_TYPES = {
    "unsupported": AndroidCallUnsupportedError,
    "unavailable": AndroidCallUnavailableError,
    "permission_denied": AndroidCallPermissionDeniedError,
    "invalid_argument": AndroidCallInvalidArgumentError,
    "invalid_state": AndroidCallInvalidStateError,
    "failed": AndroidCallFailedError,
}

#: The only error values accepted from a companion.  An invented error is not
#: surfaced verbatim and becomes a generic failure.
CALL_DEVICE_ERROR_CODES: Dict[str, str] = {
    "unsupported": ErrorCode.ANDROID_CALL_UNSUPPORTED,
    "unavailable": ErrorCode.ANDROID_CALL_UNAVAILABLE,
    "permission_denied": ErrorCode.ANDROID_CALL_PERMISSION_DENIED,
    "invalid_argument": ErrorCode.ANDROID_CALL_INVALID_ARGUMENT,
    "invalid_state": ErrorCode.ANDROID_CALL_INVALID_STATE,
    "failed": ErrorCode.ANDROID_CALL_FAILED,
}

CALL_CAPABILITIES: Tuple[str, ...] = (
    CAPABILITY_CALL_STATUS,
    CAPABILITY_CALL_DIAL,
    CAPABILITY_CALL_ANSWER,
    CAPABILITY_CALL_REJECT,
    CAPABILITY_CALL_END,
)

CALL_CAPABILITY_FOR_OPERATION: Mapping[MessageType, str] = {
    MessageType.CALL_STATUS: CAPABILITY_CALL_STATUS,
    MessageType.CALL_DIAL: CAPABILITY_CALL_DIAL,
    MessageType.CALL_ANSWER: CAPABILITY_CALL_ANSWER,
    MessageType.CALL_REJECT: CAPABILITY_CALL_REJECT,
    MessageType.CALL_END: CAPABILITY_CALL_END,
}


class AndroidCallController(Protocol):
    """Device-side contract for a future Android companion.

    A real implementation must independently authenticate the paired host,
    validate session/sequence/replay material, and enforce Android's own user
    permission and confirmation requirements before it changes call state.
    Nothing in this Python repository implements Android telephony.
    """

    async def get_status(self) -> Dict[str, Any]: ...

    async def dial(self, phone_number: str) -> Dict[str, Any]: ...

    async def answer(self) -> Dict[str, Any]: ...

    async def reject(self) -> Dict[str, Any]: ...

    async def end(self) -> Dict[str, Any]: ...


class CallStateMachine:
    """Tracks peer-reported state and refuses impossible transitions."""

    def __init__(self) -> None:
        self._states: Dict[str, AndroidCallState] = {}

    def get(self, device_id: str) -> Optional[AndroidCallState]:
        return self._states.get(device_id)

    def observe(self, device_id: str, state: AndroidCallState) -> AndroidCallState:
        previous = self._states.get(device_id)
        if previous is not None and state not in _ALLOWED_TRANSITIONS[previous]:
            raise CallStateTransitionError(
                "The phone reported an invalid call-state transition."
            )
        self._states[device_id] = state
        return state

    def forget(self, device_id: str) -> None:
        self._states.pop(device_id, None)


# Only harmless visual formatting is accepted and removed.  The leading plus is
# mandatory, avoiding country-dependent interpretation of local/national forms.
_ALLOWED_NUMBER_FORMATTING = frozenset("+0123456789 -()")


def validate_phone_number(value: Any) -> str:
    """Return a canonical E.164 number, or reject without echoing ``value``.

    Accepted input is ``+`` followed by 7--15 nonzero-leading decimal digits,
    with only spaces, ASCII hyphens and parentheses as removable presentation
    formatting.  No URI scheme, extension, DTMF character, alphabetic text,
    Unicode digit, control character, URL, host or IP representation is valid.
    """
    if not isinstance(value, str):
        raise PhoneNumberValidationError("A phone number must be a string.")
    if not value or len(value) > MAX_PHONE_NUMBER_INPUT_LENGTH:
        raise PhoneNumberValidationError("The phone number has an invalid length.")
    if not value.isascii() or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise PhoneNumberValidationError("The phone number contains invalid characters.")
    text = value.strip(" ")
    if not text or any(char not in _ALLOWED_NUMBER_FORMATTING for char in text):
        raise PhoneNumberValidationError("The phone number contains invalid characters.")
    if text.count("+") != 1 or not text.startswith("+"):
        raise PhoneNumberValidationError("The phone number must use canonical international form.")
    digits = "".join(char for char in text if "0" <= char <= "9")
    if not MIN_E164_DIGITS <= len(digits) <= MAX_E164_DIGITS or digits.startswith("0"):
        raise PhoneNumberValidationError("The phone number is not a valid E.164 destination.")
    return "+" + digits


def redact_phone_number(phone_number: str) -> str:
    """Return a minimal safe display form for non-confirmation output.

    Full values are intentionally shown only in the explicit confirmation
    target.  Normal tool results, exceptions and audit paths use this redacted
    suffix if they need to distinguish a destination at all.
    """
    try:
        canonical = validate_phone_number(phone_number)
    except PhoneNumberValidationError:
        return "[redacted]"
    return "[redacted]" + canonical[-2:]


def _parse_state(value: Any) -> AndroidCallState:
    if not isinstance(value, str):
        raise AndroidCallFailedError("The phone returned an invalid call state.")
    try:
        return AndroidCallState(value)
    except ValueError as exc:
        raise AndroidCallFailedError("The phone returned an unknown call state.") from exc


def _parse_direction(value: Any) -> CallDirection:
    if not isinstance(value, str):
        raise AndroidCallFailedError("The phone returned an invalid call direction.")
    try:
        return CallDirection(value)
    except ValueError as exc:
        raise AndroidCallFailedError("The phone returned an unknown call direction.") from exc


def _require_bool(payload: Mapping[str, Any], key: str, *, operation: str) -> bool:
    value = payload.get(key)
    if not isinstance(value, bool):
        raise AndroidCallFailedError(f"The phone returned an invalid {operation} response.")
    return value


class AndroidCallControl:
    """PC-side call orchestrator using only the authenticated Android bridge."""

    def __init__(self, bridge: AndroidDeviceBridge, *, timeout: Optional[float] = None) -> None:
        self._bridge = bridge
        self._timeout = timeout
        self._states = CallStateMachine()

    @property
    def bridge(self) -> AndroidDeviceBridge:
        return self._bridge

    @property
    def states(self) -> CallStateMachine:
        """State tracker exposed for diagnostics/tests; it never accepts model input."""
        return self._states

    def _prepare(self, device_id: str, capability: str) -> AndroidDeviceIdentity:
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
            raise AndroidCallTimeoutError(
                f"The phone did not answer the {operation} request in time; the result is uncertain."
            )
        fields = self._unwrap_response(
            response.payload, operation=operation, success_fields=success_fields
        )
        state = _parse_state(fields["state"])
        self._states.observe(device.device_id, state)
        return device, fields

    def _unwrap_response(
        self,
        payload: Any,
        *,
        operation: str,
        success_fields: FrozenSet[str],
    ) -> Dict[str, Any]:
        """Validate one strict call response envelope without exposing details."""
        if not isinstance(payload, Mapping):
            raise AndroidCallFailedError(f"The phone returned an invalid {operation} response.")
        if "ok" not in payload or not isinstance(payload["ok"], bool):
            raise AndroidCallFailedError(f"The phone returned an invalid {operation} response.")
        fields = dict(payload)
        if not fields["ok"]:
            # Failure envelopes are deliberately narrower than success
            # envelopes.  Companion diagnostics are neither accepted nor
            # surfaced: they might contain a number or implementation detail.
            if set(fields) - {"ok", "error", "state"}:
                raise AndroidCallFailedError(f"The phone returned an invalid {operation} response.")
            reason = fields.get("error")
            if reason not in _ERROR_TYPES:
                raise AndroidCallFailedError(f"The phone returned an invalid {operation} response.")
            if "state" in fields:
                _parse_state(fields["state"])
            raise _ERROR_TYPES[reason](f"The phone could not {operation}.")
        allowed = frozenset({"ok", "state"}) | success_fields
        if set(fields) - allowed or "state" not in fields:
            raise AndroidCallFailedError(f"The phone returned an invalid {operation} response.")
        _parse_state(fields["state"])
        return fields

    @staticmethod
    def _status_result(device: AndroidDeviceIdentity, fields: Mapping[str, Any]) -> Dict[str, Any]:
        state = _parse_state(fields["state"])
        result: Dict[str, Any] = {
            "device_id": device.device_id,
            "display_name": device.display_name,
            "state": state.value,
            "has_call": state
            in (AndroidCallState.RINGING, AndroidCallState.DIALING, AndroidCallState.ACTIVE, AndroidCallState.ENDING),
        }
        if "has_call" in fields:
            reported = _require_bool(fields, "has_call", operation="call status")
            if reported != result["has_call"]:
                raise AndroidCallFailedError("The phone returned an inconsistent call status.")
        if "direction" in fields:
            direction = _parse_direction(fields["direction"])
            if state in (AndroidCallState.IDLE, AndroidCallState.FAILED, AndroidCallState.UNAVAILABLE):
                raise AndroidCallFailedError("The phone returned an inconsistent call status.")
            if state is AndroidCallState.RINGING and direction is not CallDirection.INCOMING:
                raise AndroidCallFailedError("The phone returned an inconsistent call status.")
            if state is AndroidCallState.DIALING and direction is not CallDirection.OUTGOING:
                raise AndroidCallFailedError("The phone returned an inconsistent call status.")
            result["direction"] = direction.value
        return result

    async def status(self, device_id: str) -> Dict[str, Any]:
        device, fields = await self._request(
            device_id,
            MessageType.CALL_STATUS,
            MessageType.CALL_STATUS_RESPONSE,
            CAPABILITY_CALL_STATUS,
            operation="report call status",
            success_fields=frozenset({"has_call", "direction"}),
        )
        return self._status_result(device, fields)

    async def dial(self, device_id: str, phone_number: Any) -> Dict[str, Any]:
        """Request one explicit outgoing call; this method never retries it."""
        canonical = validate_phone_number(phone_number)
        device, fields = await self._request(
            device_id,
            MessageType.CALL_DIAL,
            MessageType.CALL_DIAL_RESPONSE,
            CAPABILITY_CALL_DIAL,
            payload={"phone_number": canonical},
            operation="place the call",
            success_fields=frozenset(),
        )
        if _parse_state(fields["state"]) is not AndroidCallState.DIALING:
            raise AndroidCallFailedError("The phone did not confirm that dialing began.")
        return {"device_id": device.device_id, "state": AndroidCallState.DIALING.value}

    async def answer(self, device_id: str) -> Dict[str, Any]:
        """Answer only a currently ringing incoming call; there is no call id."""
        device, fields = await self._request(
            device_id,
            MessageType.CALL_ANSWER,
            MessageType.CALL_ANSWER_RESPONSE,
            CAPABILITY_CALL_ANSWER,
            operation="answer the incoming call",
            success_fields=frozenset({"answered"}),
        )
        if not _require_bool(fields, "answered", operation="answer") or _parse_state(fields["state"]) is not AndroidCallState.ACTIVE:
            raise AndroidCallFailedError("The phone did not confirm that the incoming call was answered.")
        return {"device_id": device.device_id, "state": AndroidCallState.ACTIVE.value, "answered": True}

    async def reject(self, device_id: str) -> Dict[str, Any]:
        """Reject only a currently ringing incoming call; there is no call id."""
        device, fields = await self._request(
            device_id,
            MessageType.CALL_REJECT,
            MessageType.CALL_REJECT_RESPONSE,
            CAPABILITY_CALL_REJECT,
            operation="reject the incoming call",
            success_fields=frozenset({"rejected"}),
        )
        if not _require_bool(fields, "rejected", operation="reject") or _parse_state(fields["state"]) is not AndroidCallState.IDLE:
            raise AndroidCallFailedError("The phone did not confirm that the incoming call was rejected.")
        return {"device_id": device.device_id, "state": AndroidCallState.IDLE.value, "rejected": True}

    async def end(self, device_id: str) -> Dict[str, Any]:
        """End only the current call on ``device_id``; no session id is accepted."""
        device, fields = await self._request(
            device_id,
            MessageType.CALL_END,
            MessageType.CALL_END_RESPONSE,
            CAPABILITY_CALL_END,
            operation="end the active call",
            success_fields=frozenset({"ended"}),
        )
        ended = _require_bool(fields, "ended", operation="end")
        state = _parse_state(fields["state"])
        if ended and state is not AndroidCallState.ENDING:
            raise AndroidCallFailedError("The phone returned an inconsistent call-end response.")
        if not ended and state is not AndroidCallState.IDLE:
            raise AndroidCallFailedError("The phone returned an inconsistent call-end response.")
        return {"device_id": device.device_id, "state": state.value, "ended": ended}
