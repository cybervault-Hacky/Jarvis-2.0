"""The versioned JARVIS <-> Android bridge protocol (Phase 5).

Every frame on the wire is one JSON object with a fixed shape::

    {
      "protocol_version": 1,
      "message_type": "heartbeat",
      "request_id": "req-...",
      "device_id": "adev-...",
      "session_id": "sess-...",
      "sequence": 12,
      "nonce": "<hex>",
      "timestamp": "2026-09-08T12:00:00+00:00",
      "payload": {...},
      "signature": "<base64 Ed25519 over the canonical signed body>"
    }

Hard rules this module enforces:

* **JSON only.** There is no ``pickle``, no ``eval``, no ``yaml.load``, no
  ``marshal`` and no custom object decoding anywhere in the bridge. A payload is
  a JSON object of strings, numbers, booleans, lists and nested objects.
* **Message types are an allowlist.** An unknown type is refused before the
  payload is even looked at.
* **Every frame is signed** with the sender's Ed25519 key and the signature
  covers every field except itself, so no field can be altered in flight.
* **Bounded.** Frame size, payload size, nesting depth and key counts are all
  capped, so a hostile peer cannot exhaust memory.
* **Replay protected.** Each frame carries a fresh nonce, a monotonic per device
  sequence number, a session id and a timestamp; :class:`ReplayGuard` refuses a
  frame that repeats any of them.

Request ids correlate a response with its request. They are *not*
authentication - the signature is.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, FrozenSet, Iterable, Mapping, Optional, Tuple

from . import android_crypto as crypto
from .android_identity import is_valid_device_id, validate_device_id
from .confirmation import utcnow

__all__ = [
    "PROTOCOL_VERSION",
    "MIN_SUPPORTED_PROTOCOL_VERSION",
    "MAX_MESSAGE_BYTES",
    "MAX_PAYLOAD_BYTES",
    "MAX_PAYLOAD_DEPTH",
    "MAX_PAYLOAD_KEYS",
    "TIMESTAMP_TOLERANCE_SECONDS",
    "NONCE_BYTES",
    "MessageType",
    "MESSAGE_TYPES",
    "PRE_PAIRING_TYPES",
    "AUTHENTICATED_TYPES",
    "RESPONSE_FOR",
    "SYSTEM_CONTROL_REQUESTS",
    "SYSTEM_CONTROL_RESPONSES",
    "CALL_REQUESTS",
    "CALL_RESPONSES",
    "ALL_CAPABILITIES",
    "CAPABILITY_BRIDGE_PROTOCOL",
    "CAPABILITY_DEVICE_STATUS",
    "CAPABILITY_SYSTEM_VOLUME",
    "CAPABILITY_SYSTEM_BRIGHTNESS",
    "CAPABILITY_SYSTEM_WIFI",
    "CAPABILITY_SYSTEM_BLUETOOTH",
    "CAPABILITY_CALL_STATUS",
    "CAPABILITY_CALL_DIAL",
    "CAPABILITY_CALL_ANSWER",
    "CAPABILITY_CALL_REJECT",
    "CAPABILITY_CALL_END",
    "validate_percent",
    "PERCENT_MIN",
    "PERCENT_MAX",
    "AndroidProtocolError",
    "InvalidMessageError",
    "UnknownMessageTypeError",
    "UnsupportedProtocolVersionError",
    "OversizedMessageError",
    "MessageAuthenticationError",
    "ReplayDetectedError",
    "BridgeMessage",
    "ReplayGuard",
    "new_session_id",
]

#: Bump when the frame shape changes; older peers are refused explicitly.
PROTOCOL_VERSION = 1
MIN_SUPPORTED_PROTOCOL_VERSION = 1

#: Whole frame cap (base64 signature included).
MAX_MESSAGE_BYTES = 65_536
#: Payload cap, well inside the frame cap.
MAX_PAYLOAD_BYTES = 32_768
#: Nesting limit for payload objects/lists.
MAX_PAYLOAD_DEPTH = 6
#: Key limit per payload object.
MAX_PAYLOAD_KEYS = 64

#: How far a frame's timestamp may drift from the local clock.
TIMESTAMP_TOLERANCE_SECONDS = 300
#: Nonce length in bytes (rendered as hex on the wire).
NONCE_BYTES = 16

_REQUEST_ID_RE_LEN = 36  # "req-" + 32 hex
_NONCE_HEX_RE_LEN = NONCE_BYTES * 2


class MessageType(str, Enum):
    """The complete set of frames the bridge understands.

    Phase 6 control messages will be *added* to this enum; nothing outside it
    can ever be dispatched.
    """

    HELLO = "hello"
    PAIR_REQUEST = "pair_request"
    PAIR_CHALLENGE = "pair_challenge"
    PAIR_RESPONSE = "pair_response"
    PAIR_RESULT = "pair_result"
    CONNECT = "connect"
    DISCONNECT = "disconnect"
    HEARTBEAT = "heartbeat"
    HEARTBEAT_ACK = "heartbeat_ack"
    CAPABILITIES = "capabilities"
    DEVICE_INFO = "device_info"
    ACK = "ack"
    ERROR = "error"

    # Phase 6 - Android system control. Every operation has its own explicit
    # request/response pair. There is deliberately no generic "command",
    # "execute", "run", "shell" or "adb" type: a capability that is not in this
    # enum cannot be expressed on the wire at all.
    SYSTEM_STATUS = "system_status"
    SYSTEM_STATUS_RESPONSE = "system_status_response"
    VOLUME_GET = "volume_get"
    VOLUME_GET_RESPONSE = "volume_get_response"
    VOLUME_SET = "volume_set"
    VOLUME_SET_RESPONSE = "volume_set_response"
    MUTE_SET = "mute_set"
    MUTE_SET_RESPONSE = "mute_set_response"
    BRIGHTNESS_GET = "brightness_get"
    BRIGHTNESS_GET_RESPONSE = "brightness_get_response"
    BRIGHTNESS_SET = "brightness_set"
    BRIGHTNESS_SET_RESPONSE = "brightness_set_response"
    WIFI_STATUS = "wifi_status"
    WIFI_STATUS_RESPONSE = "wifi_status_response"
    WIFI_SET = "wifi_set"
    WIFI_SET_RESPONSE = "wifi_set_response"
    BLUETOOTH_STATUS = "bluetooth_status"
    BLUETOOTH_STATUS_RESPONSE = "bluetooth_status_response"
    BLUETOOTH_SET = "bluetooth_set"
    BLUETOOTH_SET_RESPONSE = "bluetooth_set_response"

    # Phase 7 - explicit Android call management. These are dedicated request
    # and response pairs, not an intent, telecom method or generic action.
    CALL_STATUS = "call_status"
    CALL_STATUS_RESPONSE = "call_status_response"
    CALL_DIAL = "call_dial"
    CALL_DIAL_RESPONSE = "call_dial_response"
    CALL_ANSWER = "call_answer"
    CALL_ANSWER_RESPONSE = "call_answer_response"
    CALL_REJECT = "call_reject"
    CALL_REJECT_RESPONSE = "call_reject_response"
    CALL_END = "call_end"
    CALL_END_RESPONSE = "call_end_response"


#: Explicit allowlist - the only values accepted on the wire.
MESSAGE_TYPES: FrozenSet[str] = frozenset(member.value for member in MessageType)

#: Frames that are legal before a device is paired (the handshake itself).
PRE_PAIRING_TYPES: FrozenSet[str] = frozenset(
    {
        MessageType.HELLO.value,
        MessageType.PAIR_REQUEST.value,
        MessageType.PAIR_CHALLENGE.value,
        MessageType.PAIR_RESPONSE.value,
        MessageType.PAIR_RESULT.value,
    }
)

#: Frames that only a *paired* device may send.
AUTHENTICATED_TYPES: FrozenSet[str] = MESSAGE_TYPES - PRE_PAIRING_TYPES

#: Which frame answers which request (response confusion defence).
RESPONSE_FOR: Dict[str, str] = {
    MessageType.HELLO.value: MessageType.ACK.value,
    MessageType.PAIR_REQUEST.value: MessageType.PAIR_CHALLENGE.value,
    MessageType.PAIR_RESPONSE.value: MessageType.PAIR_RESULT.value,
    MessageType.CONNECT.value: MessageType.ACK.value,
    MessageType.DISCONNECT.value: MessageType.ACK.value,
    MessageType.HEARTBEAT.value: MessageType.HEARTBEAT_ACK.value,
    MessageType.CAPABILITIES.value: MessageType.ACK.value,
    MessageType.DEVICE_INFO.value: MessageType.ACK.value,
    # Phase 6 - each system-control request has exactly one response type.
    MessageType.SYSTEM_STATUS.value: MessageType.SYSTEM_STATUS_RESPONSE.value,
    MessageType.VOLUME_GET.value: MessageType.VOLUME_GET_RESPONSE.value,
    MessageType.VOLUME_SET.value: MessageType.VOLUME_SET_RESPONSE.value,
    MessageType.MUTE_SET.value: MessageType.MUTE_SET_RESPONSE.value,
    MessageType.BRIGHTNESS_GET.value: MessageType.BRIGHTNESS_GET_RESPONSE.value,
    MessageType.BRIGHTNESS_SET.value: MessageType.BRIGHTNESS_SET_RESPONSE.value,
    MessageType.WIFI_STATUS.value: MessageType.WIFI_STATUS_RESPONSE.value,
    MessageType.WIFI_SET.value: MessageType.WIFI_SET_RESPONSE.value,
    MessageType.BLUETOOTH_STATUS.value: MessageType.BLUETOOTH_STATUS_RESPONSE.value,
    MessageType.BLUETOOTH_SET.value: MessageType.BLUETOOTH_SET_RESPONSE.value,
    # Phase 7 - every call operation has exactly one dedicated response.
    MessageType.CALL_STATUS.value: MessageType.CALL_STATUS_RESPONSE.value,
    MessageType.CALL_DIAL.value: MessageType.CALL_DIAL_RESPONSE.value,
    MessageType.CALL_ANSWER.value: MessageType.CALL_ANSWER_RESPONSE.value,
    MessageType.CALL_REJECT.value: MessageType.CALL_REJECT_RESPONSE.value,
    MessageType.CALL_END.value: MessageType.CALL_END_RESPONSE.value,
}

#: Phase 6 system-control requests (JARVIS -> phone). Everything outside this
#: set and the Phase 5 handshake is not a system operation.
SYSTEM_CONTROL_REQUESTS: FrozenSet[str] = frozenset(
    {
        MessageType.SYSTEM_STATUS.value,
        MessageType.VOLUME_GET.value,
        MessageType.VOLUME_SET.value,
        MessageType.MUTE_SET.value,
        MessageType.BRIGHTNESS_GET.value,
        MessageType.BRIGHTNESS_SET.value,
        MessageType.WIFI_STATUS.value,
        MessageType.WIFI_SET.value,
        MessageType.BLUETOOTH_STATUS.value,
        MessageType.BLUETOOTH_SET.value,
    }
)

#: Their responses (phone -> JARVIS).
SYSTEM_CONTROL_RESPONSES: FrozenSet[str] = frozenset(
    RESPONSE_FOR[name] for name in SYSTEM_CONTROL_REQUESTS
)

#: Phase 7 call-management requests (JARVIS -> phone). This intentionally
#: contains no generic execution primitive: each permitted operation is named.
CALL_REQUESTS: FrozenSet[str] = frozenset(
    {
        MessageType.CALL_STATUS.value,
        MessageType.CALL_DIAL.value,
        MessageType.CALL_ANSWER.value,
        MessageType.CALL_REJECT.value,
        MessageType.CALL_END.value,
    }
)

#: Their dedicated responses (phone -> JARVIS).
CALL_RESPONSES: FrozenSet[str] = frozenset(RESPONSE_FOR[name] for name in CALL_REQUESTS)


class AndroidProtocolError(Exception):
    """Base class for protocol problems."""


class InvalidMessageError(AndroidProtocolError):
    """The frame was malformed, or a field failed validation."""


class UnknownMessageTypeError(AndroidProtocolError):
    """The frame used a message type outside the allowlist."""


class UnsupportedProtocolVersionError(AndroidProtocolError):
    """The frame declared a protocol version this JARVIS does not speak."""


class OversizedMessageError(AndroidProtocolError):
    """The frame or its payload exceeded a size limit."""


class MessageAuthenticationError(AndroidProtocolError):
    """The signature did not verify - the frame is treated as hostile."""


class ReplayDetectedError(AndroidProtocolError):
    """The frame repeats a nonce, sequence or session already accepted."""


# --- Capability names -------------------------------------------------------
# These travel inside ``capabilities`` frames, so they are protocol vocabulary.
# They live here rather than in the bridge or the system module so neither has
# to import the other.
CAPABILITY_BRIDGE_PROTOCOL = "bridge.protocol"
CAPABILITY_DEVICE_STATUS = "device.status"
CAPABILITY_SYSTEM_VOLUME = "system.volume"
CAPABILITY_SYSTEM_BRIGHTNESS = "system.brightness"
CAPABILITY_SYSTEM_WIFI = "system.wifi"
CAPABILITY_SYSTEM_BLUETOOTH = "system.bluetooth"
# Phase 7 capabilities are deliberately operation-specific. An advertised
# call status capability never implies permission to dial or alter a call.
CAPABILITY_CALL_STATUS = "call.status"
CAPABILITY_CALL_DIAL = "call.dial"
CAPABILITY_CALL_ANSWER = "call.answer"
CAPABILITY_CALL_REJECT = "call.reject"
CAPABILITY_CALL_END = "call.end"

#: Everything this JARVIS build actually understands. A phone may advertise more
#: (``system.power``, ``comms.call``, ...); those are reported as advertised but
#: never treated as available.
ALL_CAPABILITIES: Tuple[str, ...] = (
    CAPABILITY_BRIDGE_PROTOCOL,
    CAPABILITY_DEVICE_STATUS,
    CAPABILITY_SYSTEM_VOLUME,
    CAPABILITY_SYSTEM_BRIGHTNESS,
    CAPABILITY_SYSTEM_WIFI,
    CAPABILITY_SYSTEM_BLUETOOTH,
    CAPABILITY_CALL_STATUS,
    CAPABILITY_CALL_DIAL,
    CAPABILITY_CALL_ANSWER,
    CAPABILITY_CALL_REJECT,
    CAPABILITY_CALL_END,
)

#: Bounded representation for volume and brightness: an integer percentage.
PERCENT_MIN = 0
PERCENT_MAX = 100


def validate_percent(value: Any, *, field: str = "level") -> int:
    """Return ``value`` as a 0-100 integer, or raise :class:`InvalidMessageError`.

    ``bool`` is rejected explicitly (it is an ``int`` subclass in Python), and so
    are floats, strings and anything else - a percentage is an integer or it is
    not a percentage.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidMessageError(f"{field} must be an integer, got {type(value).__name__}.")
    if value < PERCENT_MIN or value > PERCENT_MAX:
        raise InvalidMessageError(
            f"{field} must be between {PERCENT_MIN} and {PERCENT_MAX}, got {value}."
        )
    return value


def new_session_id() -> str:
    """Fresh session identifier (``sess-<32 hex>``)."""
    return f"sess-{crypto.new_nonce(16).hex()}"


# ---------------------------------------------------------------------------
# Payload validation
# ---------------------------------------------------------------------------
def validate_payload(payload: Any) -> Dict[str, Any]:
    """Return a JSON-safe payload dict, or raise :class:`InvalidMessageError`.

    Rejects bytes, functions, deeply nested structures and anything that cannot
    survive a JSON round trip. There is deliberately no way to smuggle an object
    that would be reconstructed on the far side.
    """
    if payload is None:
        return {}
    if not isinstance(payload, Mapping):
        raise InvalidMessageError("A message payload must be a JSON object.")
    if len(payload) > MAX_PAYLOAD_KEYS:
        raise InvalidMessageError(f"A payload may not have more than {MAX_PAYLOAD_KEYS} keys.")
    validated = _validate_node(dict(payload), depth=1)
    encoded = json.dumps(validated, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        raise OversizedMessageError(f"Payload exceeds {MAX_PAYLOAD_BYTES} bytes.")
    return validated


def _validate_node(value: Any, *, depth: int) -> Any:
    if depth > MAX_PAYLOAD_DEPTH:
        raise InvalidMessageError(f"Payload nests deeper than {MAX_PAYLOAD_DEPTH} levels.")
    if isinstance(value, Mapping):
        if len(value) > MAX_PAYLOAD_KEYS:
            raise InvalidMessageError(f"A payload object may not have more than {MAX_PAYLOAD_KEYS} keys.")
        return {
            _validate_key(key): _validate_node(item, depth=depth + 1) for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_PAYLOAD_KEYS:
            raise InvalidMessageError(f"A payload list may not have more than {MAX_PAYLOAD_KEYS} items.")
        return [_validate_node(item, depth=depth + 1) for item in value]
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        # NaN/Infinity are not JSON and would break a strict parser downstream.
        if value != value or value in (float("inf"), float("-inf")):
            raise InvalidMessageError("A payload may not contain NaN or Infinity.")
        return value
    if isinstance(value, str):
        if len(value) > MAX_PAYLOAD_BYTES:
            raise OversizedMessageError("A payload string is too long.")
        return value
    raise InvalidMessageError(f"Unsupported payload value of type {type(value).__name__}.")


def _validate_key(key: Any) -> str:
    if not isinstance(key, str):
        raise InvalidMessageError("Payload keys must be strings.")
    if not key or len(key) > 128 or key.startswith("__"):
        raise InvalidMessageError(f"Invalid payload key {key!r}.")
    return key


# ---------------------------------------------------------------------------
# The frame
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class BridgeMessage:
    """One signed bridge frame. Immutable; :meth:`signed` returns a new one."""

    message_type: MessageType
    device_id: str
    request_id: str
    sequence: int
    payload: Dict[str, Any] = field(default_factory=dict)
    protocol_version: int = PROTOCOL_VERSION
    session_id: str = ""
    nonce: str = ""
    timestamp: str = ""
    signature: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "payload", dict(self.payload))

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------
    @classmethod
    def create(
        cls,
        message_type: MessageType,
        device_id: str,
        *,
        payload: Optional[Mapping[str, Any]] = None,
        request_id: str = "",
        sequence: int = 1,
        session_id: str = "",
        timestamp: Optional[datetime] = None,
        nonce: str = "",
    ) -> "BridgeMessage":
        """Build an unsigned frame with fresh correlation material."""
        if not isinstance(message_type, MessageType):
            raise InvalidMessageError("message_type must be a MessageType.")
        return cls(
            message_type=message_type,
            device_id=validate_device_id(device_id),
            request_id=request_id or crypto.new_request_id(),
            sequence=sequence,
            payload=validate_payload(payload or {}),
            session_id=session_id,
            nonce=nonce or crypto.new_nonce(NONCE_BYTES).hex(),
            timestamp=(timestamp or utcnow()).isoformat(),
        )

    # ------------------------------------------------------------------
    # Canonical form and signing
    # ------------------------------------------------------------------
    def signed_body(self) -> Dict[str, Any]:
        """Every field except the signature, in a canonical shape."""
        return {
            "protocol_version": self.protocol_version,
            "message_type": self.message_type.value,
            "request_id": self.request_id,
            "device_id": self.device_id,
            "session_id": self.session_id,
            "sequence": self.sequence,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "payload": self.payload,
        }

    def signed_bytes(self) -> bytes:
        """The exact bytes a signature covers (deterministic JSON)."""
        return json.dumps(
            self.signed_body(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")

    def sign(self, private_key: bytes) -> "BridgeMessage":
        """Return a copy carrying a valid Ed25519 signature."""
        return replace(self, signature=_encode_signature(crypto.sign(private_key, self.signed_bytes())))

    def verify(self, public_key: bytes) -> bool:
        """Whether ``public_key`` really produced this frame."""
        if not self.signature:
            return False
        try:
            signature = _decode_signature(self.signature)
        except InvalidMessageError:
            return False
        return crypto.verify(public_key, self.signed_bytes(), signature)

    def require_verified(self, public_key: bytes) -> "BridgeMessage":
        if not self.verify(public_key):
            raise MessageAuthenticationError(
                f"The {self.message_type.value} frame did not verify against the device key."
            )
        return self

    # ------------------------------------------------------------------
    # Wire format
    # ------------------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        body = self.signed_body()
        body["signature"] = self.signature
        return body

    def to_json(self) -> str:
        text = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        if len(text.encode("utf-8")) > MAX_MESSAGE_BYTES:
            raise OversizedMessageError(f"Frame exceeds {MAX_MESSAGE_BYTES} bytes.")
        return text

    def to_bytes(self) -> bytes:
        return self.to_json().encode("utf-8")

    # ------------------------------------------------------------------
    @classmethod
    def parse(cls, raw: Any) -> "BridgeMessage":
        """Decode and strictly validate a frame. Raises on any problem.

        Accepts ``bytes``/``str``/``Mapping``. Nothing else - in particular not
        a pickled object, which is why this method never calls anything but
        ``json.loads``.
        """
        if isinstance(raw, (bytes, bytearray)):
            if len(raw) > MAX_MESSAGE_BYTES:
                raise OversizedMessageError(f"Frame exceeds {MAX_MESSAGE_BYTES} bytes.")
            try:
                text = bytes(raw).decode("utf-8")
            except UnicodeDecodeError as exc:
                raise InvalidMessageError("A frame must be UTF-8 encoded JSON.") from exc
            raw = text
        if isinstance(raw, str):
            if len(raw.encode("utf-8")) > MAX_MESSAGE_BYTES:
                raise OversizedMessageError(f"Frame exceeds {MAX_MESSAGE_BYTES} bytes.")
            try:
                raw = json.loads(raw)
            except ValueError as exc:
                raise InvalidMessageError(f"A frame must be valid JSON: {exc}") from exc
        if not isinstance(raw, Mapping):
            raise InvalidMessageError("A frame must be a JSON object.")

        expected_fields = {
            "protocol_version",
            "message_type",
            "request_id",
            "device_id",
            "session_id",
            "sequence",
            "nonce",
            "timestamp",
            "payload",
            "signature",
        }
        unexpected = sorted(set(raw) - expected_fields)
        if unexpected:
            raise InvalidMessageError(f"Unexpected frame fields: {unexpected}")
        missing = sorted(expected_fields - set(raw))
        if missing:
            raise InvalidMessageError(f"Missing frame fields: {missing}")

        version = raw["protocol_version"]
        if not isinstance(version, int) or isinstance(version, bool):
            raise InvalidMessageError("protocol_version must be an integer.")
        if version < MIN_SUPPORTED_PROTOCOL_VERSION or version > PROTOCOL_VERSION:
            raise UnsupportedProtocolVersionError(
                f"Protocol version {version} is not supported "
                f"(this JARVIS speaks {MIN_SUPPORTED_PROTOCOL_VERSION}-{PROTOCOL_VERSION})."
            )

        message_type = raw["message_type"]
        if not isinstance(message_type, str) or message_type not in MESSAGE_TYPES:
            raise UnknownMessageTypeError(f"Unknown bridge message type {message_type!r}.")

        device_id = raw["device_id"]
        if not is_valid_device_id(device_id):
            raise InvalidMessageError("device_id is not a valid bridge device id.")

        request_id = raw["request_id"]
        if (
            not isinstance(request_id, str)
            or len(request_id) != _REQUEST_ID_RE_LEN
            or not request_id.startswith("req-")
            or not _is_hex(request_id[4:])
        ):
            raise InvalidMessageError("request_id must look like 'req-' plus 32 hex characters.")

        sequence = raw["sequence"]
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
            raise InvalidMessageError("sequence must be a positive integer.")

        nonce = raw["nonce"]
        if (
            not isinstance(nonce, str)
            or len(nonce) != _NONCE_HEX_RE_LEN
            or not _is_hex(nonce)
        ):
            raise InvalidMessageError(f"nonce must be {NONCE_BYTES} bytes of hex.")

        session_id = raw["session_id"]
        if not isinstance(session_id, str) or len(session_id) > 64:
            raise InvalidMessageError("session_id must be a short string.")

        timestamp = raw["timestamp"]
        if not isinstance(timestamp, str) or not timestamp:
            raise InvalidMessageError("timestamp must be an ISO-8601 string.")
        try:
            datetime.fromisoformat(timestamp)
        except ValueError as exc:
            raise InvalidMessageError(f"timestamp is not ISO-8601: {exc}") from exc

        signature = raw["signature"]
        if not isinstance(signature, str) or not signature:
            raise InvalidMessageError("A frame must carry a signature.")

        return cls(
            protocol_version=version,
            message_type=MessageType(message_type),
            request_id=request_id,
            device_id=device_id,
            session_id=session_id,
            sequence=sequence,
            nonce=nonce,
            timestamp=timestamp,
            payload=validate_payload(raw["payload"]),
            signature=signature,
        )

    # ------------------------------------------------------------------
    def timestamp_dt(self) -> datetime:
        """The frame timestamp as an aware UTC datetime."""
        moment = datetime.fromisoformat(self.timestamp)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc)

    def describe(self) -> Dict[str, Any]:
        """Safe summary for logs: payload keys only, never values."""
        return {
            "protocol_version": self.protocol_version,
            "message_type": self.message_type.value,
            "request_id": self.request_id,
            "device_id": self.device_id,
            "session_id": self.session_id,
            "sequence": self.sequence,
            "payload_keys": sorted(self.payload),
            "signed": bool(self.signature),
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        # Payload values and the signature are deliberately omitted.
        return (
            f"<BridgeMessage {self.message_type.value} device={self.device_id} "
            f"seq={self.sequence} request={self.request_id}>"
        )


def _is_hex(text: str) -> bool:
    if not text:
        return False
    try:
        int(text, 16)
    except ValueError:
        return False
    return True


def _encode_signature(signature: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")


def _decode_signature(encoded: str) -> bytes:
    import base64

    padded = encoded + "=" * (-len(encoded) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:  # noqa: BLE001 - any decode failure is malformed
        raise InvalidMessageError(f"The signature is not valid base64: {exc}") from exc
    if len(raw) != crypto.SIGNATURE_BYTES:
        raise InvalidMessageError("The signature has the wrong length.")
    return raw


# ---------------------------------------------------------------------------
# Replay protection
# ---------------------------------------------------------------------------
class ReplayGuard:
    """Refuses frames that repeat a nonce, sequence or session.

    Three independent checks, all of which must pass:

    1. **Timestamp window** - a frame older than ``tolerance`` (or too far in
       the future) is refused, which bounds how long a captured frame stays
       usable at all;
    2. **Monotonic sequence** - each device's sequence must strictly increase,
       so a captured frame can never be replayed in order;
    3. **Nonce cache** - a bounded set of recently seen nonces catches an
       out-of-order replay that a future-dated sequence would otherwise slip
       past.

    The guard is stateful per device and bounded, so it cannot be grown without
    limit by a hostile peer.
    """

    def __init__(
        self,
        *,
        tolerance_seconds: int = TIMESTAMP_TOLERANCE_SECONDS,
        max_nonces: int = 4096,
        clock: Any = None,
    ) -> None:
        if tolerance_seconds < 1:
            raise ValueError("tolerance_seconds must be at least 1.")
        if max_nonces < 16:
            raise ValueError("max_nonces must be at least 16.")
        self.tolerance = timedelta(seconds=tolerance_seconds)
        self.max_nonces = max_nonces
        self._clock = clock or utcnow
        self._sequences: Dict[str, int] = {}
        self._nonces: Dict[str, Dict[str, None]] = {}

    # ------------------------------------------------------------------
    def check(self, message: BridgeMessage) -> None:
        """Raise :class:`ReplayDetectedError` if this frame is not fresh."""
        device_id = message.device_id
        now = self._clock()
        moment = message.timestamp_dt()
        drift = now - moment
        if drift > self.tolerance:
            raise ReplayDetectedError(
                f"The frame is older than {int(self.tolerance.total_seconds())} seconds."
            )
        if -drift > self.tolerance:
            raise ReplayDetectedError("The frame is timestamped too far in the future.")

        last = self._sequences.get(device_id, 0)
        if message.sequence <= last:
            raise ReplayDetectedError(
                f"Sequence {message.sequence} is not newer than the last accepted "
                f"sequence {last} for {device_id}."
            )

        seen = self._nonces.setdefault(device_id, {})
        if message.nonce in seen:
            raise ReplayDetectedError("This nonce has already been accepted.")

        # Commit only after every check passed, so a rejected frame cannot
        # advance the sequence and lock out the legitimate device.
        self._sequences[device_id] = message.sequence
        seen[message.nonce] = None
        if len(seen) > self.max_nonces:
            for stale in list(seen)[: len(seen) - self.max_nonces]:
                del seen[stale]

    # ------------------------------------------------------------------
    def last_sequence(self, device_id: str) -> int:
        return self._sequences.get(device_id, 0)

    def remember_device(self, device_id: str, sequence: int) -> None:
        """Seed the guard (e.g. after a reconnect) without accepting a frame."""
        if sequence > self._sequences.get(device_id, 0):
            self._sequences[device_id] = sequence

    def forget_device(self, device_id: str) -> None:
        self._sequences.pop(device_id, None)
        self._nonces.pop(device_id, None)

    def stats(self) -> Dict[str, Any]:
        return {
            "devices_tracked": len(self._sequences),
            "nonces_cached": sum(len(seen) for seen in self._nonces.values()),
            "max_nonces": self.max_nonces,
            "tolerance_seconds": int(self.tolerance.total_seconds()),
        }
