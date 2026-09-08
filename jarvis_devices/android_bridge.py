"""The Android device bridge (Phase 5 - foundation only).

This is the PC side of a JARVIS <-> Android companion link. It owns pairing,
trust, connection lifecycle, heartbeat, capability discovery and the request /
response correlation that sits on top of :mod:`jarvis_devices.android_protocol`.

**What this module deliberately does not do.** It cannot change a phone's
volume, brightness, Wi-Fi or Bluetooth state, launch or close an app, switch a
phone off, place a call, send a message, read a notification, a contact or a
file, capture a screen, touch a microphone, a camera or a location, and it
cannot run a shell or an ADB command. There is no code path here that carries a
command, a flag, a file path or an executable name, and the protocol has no
message type that could express one. Those features are Phase 6+.

Pairing model
-------------
Trust is established by signature plus a human comparison, never by a name, an
address or anything the model can assert:

1. the phone sends ``pair_request`` containing its Ed25519 **public** key,
   signed with the matching private key (proof of ownership);
2. JARVIS replies with a fresh random ``challenge`` and its own host
   fingerprint;
3. the phone signs an attestation binding challenge + device id + JARVIS
   fingerprint, so the signature cannot be reused for another PC or replayed
   later;
4. both sides display the same 6 character code derived from the phone's key and
   the challenge. The **user** confirms they match - that comparison is what
   defeats a man in the middle;
5. only then does ``android.device.pair`` promote the device to ``PAIRED``, and
   that tool is confirmation locked, so a natural language request alone can
   never grant trust.

Every frame after pairing is signed, sequence numbered, nonced, timestamped and
session bound; :class:`~jarvis_devices.android_protocol.ReplayGuard` refuses a
replay.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Protocol, Tuple

from . import android_crypto as crypto
from .android_identity import (
    AndroidDeviceIdentity,
    AndroidHostIdentity,
    ConnectionState,
    ConnectionInfo,
    HealthState,
    InvalidDeviceIdentityError,
    TrustState,
    UnknownDeviceError,
    validate_capabilities,
    validate_device_id,
    validate_display_name,
)
from .android_protocol import (
    AUTHENTICATED_TYPES,
    RESPONSE_FOR,
    AndroidProtocolError,
    BridgeMessage,
    InvalidMessageError,
    MessageAuthenticationError,
    MessageType,
    OversizedMessageError,
    PROTOCOL_VERSION,
    ReplayDetectedError,
    ReplayGuard,
    UnknownMessageTypeError,
    UnsupportedProtocolVersionError,
    new_session_id,
    validate_payload,
)
from .android_registry import AndroidDeviceRegistry, InMemoryAndroidDeviceRegistry
from .android_transport import (
    AndroidBridgeTransport,
    AndroidTransportError,
    UnavailableAndroidTransport,
)
from .confirmation import utcnow
from .errors import ErrorCode

__all__ = [
    "AndroidBridgeError",
    "AndroidBridgeUnavailableError",
    "AndroidDeviceUnknownError",
    "AndroidDeviceNotPairedError",
    "AndroidDeviceRevokedError",
    "AndroidPairingError",
    "AndroidPairingUnknownError",
    "AndroidPairingExpiredError",
    "AndroidAuthenticationError",
    "AndroidConnectionError",
    "AndroidConnectionTimeoutError",
    "AndroidCapabilityUnavailableError",
    "PairingStatus",
    "PendingPairing",
    "AndroidDeviceBridge",
    "create_default_android_bridge",
    "pairing_attestation_bytes",
    "BRIDGE_PROTOCOL_CAPABILITY",
    "DEVICE_STATUS_CAPABILITY",
    "DEFAULT_PAIRING_TTL_SECONDS",
    "DEFAULT_HEARTBEAT_INTERVAL_SECONDS",
    "DEFAULT_STALE_AFTER_SECONDS",
    "DEFAULT_REQUEST_TIMEOUT_SECONDS",
    "DEFAULT_MAX_CONNECTION_ATTEMPTS",
    "MAX_CONNECTION_ATTEMPTS_LIMIT",
]

#: The only capabilities Phase 5 can honestly claim to understand.
BRIDGE_PROTOCOL_CAPABILITY = "bridge.protocol"
DEVICE_STATUS_CAPABILITY = "device.status"
#: Capabilities a device may advertise during Phase 5 pairing. Anything else is
#: recorded as "advertised, not supported" - never as available.
SUPPORTED_CAPABILITIES: Tuple[str, ...] = (
    BRIDGE_PROTOCOL_CAPABILITY,
    DEVICE_STATUS_CAPABILITY,
)

DEFAULT_PAIRING_TTL_SECONDS = 120
DEFAULT_HEARTBEAT_INTERVAL_SECONDS = 30
DEFAULT_STALE_AFTER_SECONDS = 90
DEFAULT_REQUEST_TIMEOUT_SECONDS = 5.0
DEFAULT_MAX_CONNECTION_ATTEMPTS = 3
#: Hard ceiling so a misconfiguration cannot produce a retry storm.
MAX_CONNECTION_ATTEMPTS_LIMIT = 10

#: Binds a pairing signature to this protocol, the challenge, the device and the
#: specific JARVIS instance - so it cannot be replayed or reused elsewhere.
_ATTESTATION_PREFIX = b"jarvis-android-pair-v1"


def pairing_attestation_bytes(challenge: bytes, device_id: str, host_fingerprint: str) -> bytes:
    """The exact bytes a phone signs to prove it holds the pairing key."""
    if not isinstance(challenge, (bytes, bytearray)) or not challenge:
        raise AndroidPairingError("A pairing attestation needs a non-empty challenge.")
    return (
        _ATTESTATION_PREFIX
        + b"\n"
        + bytes(challenge)
        + b"\n"
        + validate_device_id(device_id).encode("ascii")
        + b"\n"
        + str(host_fingerprint).encode("ascii")
    )


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------
class AndroidBridgeError(Exception):
    """Base class for bridge failures."""

    error_code = ErrorCode.ANDROID_BRIDGE_UNAVAILABLE


class AndroidBridgeUnavailableError(AndroidBridgeError):
    """No usable bridge/transport/cryptography on this machine."""


class AndroidDeviceUnknownError(AndroidBridgeError):
    error_code = ErrorCode.ANDROID_DEVICE_UNKNOWN


class AndroidDeviceNotPairedError(AndroidBridgeError):
    error_code = ErrorCode.ANDROID_DEVICE_NOT_PAIRED


class AndroidDeviceRevokedError(AndroidBridgeError):
    error_code = ErrorCode.ANDROID_DEVICE_REVOKED


class AndroidPairingError(AndroidBridgeError):
    error_code = ErrorCode.ANDROID_PAIRING_FAILED


class AndroidPairingUnknownError(AndroidPairingError):
    error_code = ErrorCode.ANDROID_PAIRING_UNKNOWN


class AndroidPairingExpiredError(AndroidPairingError):
    error_code = ErrorCode.ANDROID_PAIRING_EXPIRED


class AndroidAuthenticationError(AndroidBridgeError):
    error_code = ErrorCode.ANDROID_AUTHENTICATION_FAILED


class AndroidConnectionError(AndroidBridgeError):
    error_code = ErrorCode.ANDROID_CONNECTION_FAILED


class AndroidConnectionTimeoutError(AndroidConnectionError):
    error_code = ErrorCode.ANDROID_CONNECTION_TIMEOUT


class AndroidCapabilityUnavailableError(AndroidBridgeError):
    error_code = ErrorCode.ANDROID_CAPABILITY_UNAVAILABLE


class PairingStatus(str, Enum):
    """Lifecycle of one pairing attempt."""

    AWAITING_RESPONSE = "awaiting_response"
    VERIFIED = "verified"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


@dataclass
class PendingPairing:
    """A pairing handshake waiting for the phone's proof, or for the user."""

    pairing_id: str
    device_id: str
    public_key: bytes
    display_name: str
    challenge: bytes
    pairing_code: str
    host_fingerprint: str
    capabilities: Tuple[str, ...] = ()
    status: PairingStatus = PairingStatus.AWAITING_RESPONSE
    requested_at: datetime = field(default_factory=utcnow)
    expires_at: datetime = field(default_factory=utcnow)
    verified_at: Optional[datetime] = None
    #: Truncated, non-technical reason when the attempt did not succeed.
    detail: str = ""

    def expired(self, *, now: Optional[datetime] = None) -> bool:
        return (now or utcnow()) >= self.expires_at

    def to_safe_dict(self) -> Dict[str, Any]:
        """User/log safe view. The public key is shown, never a private one."""
        return {
            "pairing_id": self.pairing_id,
            "device_id": self.device_id,
            "display_name": self.display_name,
            "fingerprint": crypto.fingerprint(self.public_key),
            "pairing_code": self.pairing_code,
            "status": self.status.value,
            "capabilities": list(self.capabilities),
            "requested_at": self.requested_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "detail": self.detail,
        }


@dataclass
class _PendingRequest:
    """One outbound request waiting for its correlated response."""

    request_id: str
    device_id: str
    message_type: str
    expected_response: str
    created_at: datetime = field(default_factory=utcnow)
    future: Optional[asyncio.Future] = None


class AndroidDeviceBridge:
    """PC side bridge to Android companion devices.

    Everything injectable is injectable: the transport, the device registry, the
    host identity, the clock and the replay guard. That is what lets the whole
    bridge be tested without a phone, a network, Bluetooth or ADB.
    """

    def __init__(
        self,
        transport: Optional[AndroidBridgeTransport] = None,
        registry: Optional[AndroidDeviceRegistry] = None,
        host_identity: Optional[AndroidHostIdentity] = None,
        *,
        clock: Callable[[], datetime] = utcnow,
        pairing_ttl_seconds: int = DEFAULT_PAIRING_TTL_SECONDS,
        heartbeat_interval_seconds: int = DEFAULT_HEARTBEAT_INTERVAL_SECONDS,
        stale_after_seconds: int = DEFAULT_STALE_AFTER_SECONDS,
        request_timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
        max_connection_attempts: int = DEFAULT_MAX_CONNECTION_ATTEMPTS,
        backoff_base_seconds: float = 0.5,
        backoff_cap_seconds: float = 8.0,
        replay_guard: Optional[ReplayGuard] = None,
        audit_hook: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    ) -> None:
        if pairing_ttl_seconds < 1:
            raise ValueError("pairing_ttl_seconds must be at least 1.")
        if heartbeat_interval_seconds < 1:
            raise ValueError("heartbeat_interval_seconds must be at least 1.")
        if stale_after_seconds < heartbeat_interval_seconds:
            raise ValueError("stale_after_seconds must be at least the heartbeat interval.")
        if not 1 <= max_connection_attempts <= MAX_CONNECTION_ATTEMPTS_LIMIT:
            raise ValueError(
                f"max_connection_attempts must be between 1 and {MAX_CONNECTION_ATTEMPTS_LIMIT}."
            )
        if backoff_base_seconds < 0 or backoff_cap_seconds < backoff_base_seconds:
            raise ValueError("Backoff must be non-negative and capped at or above its base.")

        self.transport = transport if transport is not None else UnavailableAndroidTransport()
        self.registry = registry if registry is not None else InMemoryAndroidDeviceRegistry()
        self.host_identity = host_identity
        self.clock = clock
        self.pairing_ttl = timedelta(seconds=pairing_ttl_seconds)
        self.heartbeat_interval = timedelta(seconds=heartbeat_interval_seconds)
        self.stale_after = timedelta(seconds=stale_after_seconds)
        self.request_timeout = request_timeout_seconds
        self.max_connection_attempts = max_connection_attempts
        self.backoff_base = backoff_base_seconds
        self.backoff_cap = backoff_cap_seconds
        self.replay_guard = replay_guard or ReplayGuard(clock=clock)
        #: Optional sink for safe bridge lifecycle events (the JARVIS audit log).
        self.audit_hook = audit_hook

        self._pairings: Dict[str, PendingPairing] = {}
        self._requests: Dict[str, _PendingRequest] = {}
        self._session_ids: Dict[str, str] = {}
        #: When we last asked a device and got no answer. A device that stops
        #: replying must stop looking healthy, even though its last *successful*
        #: contact was moments ago.
        self._heartbeat_failures: Dict[str, datetime] = {}
        #: Counters exposed by :meth:`status` - all bounded integers.
        self._counters: Dict[str, int] = {
            "frames_received": 0,
            "frames_sent": 0,
            "frames_rejected": 0,
            "replays_detected": 0,
            "authentication_failures": 0,
            "pairing_requests": 0,
            "pairings_approved": 0,
            "pairings_rejected": 0,
            "connect_attempts": 0,
            "heartbeats": 0,
        }

    # ------------------------------------------------------------------
    # Availability
    # ------------------------------------------------------------------
    @property
    def available(self) -> bool:
        """Whether pairing and connections can work at all right now."""
        return crypto.crypto_available() and self.host_identity is not None

    def unavailable_reason(self) -> str:
        if not crypto.crypto_available():
            return crypto.crypto_unavailable_reason()
        if self.host_identity is None:
            return "The Android bridge has no host identity, so it cannot authenticate itself."
        return ""

    def require_available(self) -> None:
        if not self.available:
            raise AndroidBridgeUnavailableError(self.unavailable_reason())

    # ------------------------------------------------------------------
    # Transport lifecycle
    # ------------------------------------------------------------------
    async def open(self) -> None:
        """Open the transport so inbound frames (pairing requests) can arrive.

        Without this, only JARVIS-initiated connections would work, and a phone
        that reaches out first could never start pairing.
        """
        self.require_available()
        if self.transport.is_open:
            return
        try:
            await self.transport.open()
        except AndroidTransportError as exc:
            raise AndroidBridgeUnavailableError(
                f"The Android transport could not be opened: {type(exc).__name__}"
            ) from exc

    async def close(self) -> None:
        """Close the transport. Paired devices stay paired; connections end."""
        for device_id in list(self._session_ids):
            self._session_ids.pop(device_id, None)
        try:
            await self.transport.close()
        except AndroidTransportError:  # pragma: no cover - closing must not raise
            pass

    # ------------------------------------------------------------------
    # Status / introspection (all read-only, all safe to show)
    # ------------------------------------------------------------------
    def status(self) -> Dict[str, Any]:
        """Bridge health. Never contains key material or network endpoints."""
        devices = self.registry.list_devices()
        return {
            "available": self.available,
            "unavailable_reason": self.unavailable_reason(),
            "protocol_version": PROTOCOL_VERSION,
            "transport": self.transport.describe(),
            "host": self.host_identity.to_safe_dict() if self.host_identity else None,
            "devices": len(devices),
            "paired_devices": len(self.registry.privileged_devices()),
            "connected_devices": len(
                [
                    device
                    for device in devices
                    if device.connection.state is ConnectionState.CONNECTED
                ]
            ),
            "pending_pairings": len(self.pending_pairings()),
            "capabilities_understood": list(SUPPORTED_CAPABILITIES),
            "timing": {
                "pairing_ttl_seconds": int(self.pairing_ttl.total_seconds()),
                "heartbeat_interval_seconds": int(self.heartbeat_interval.total_seconds()),
                "stale_after_seconds": int(self.stale_after.total_seconds()),
                "request_timeout_seconds": self.request_timeout,
                "max_connection_attempts": self.max_connection_attempts,
            },
            "replay_guard": self.replay_guard.stats(),
            "counters": dict(self._counters),
        }

    def list_devices(self) -> Tuple[Dict[str, Any], ...]:
        """Safe summaries of every known device, revoked ones included."""
        return tuple(device.to_safe_dict() for device in self.registry.list_devices())

    def device_status(self, device_id: str) -> Dict[str, Any]:
        device = self._require_device(device_id)
        payload = device.to_safe_dict()
        payload["health"] = self.health(device_id).value
        payload["capabilities_understood"] = [
            capability for capability in device.capabilities if capability in SUPPORTED_CAPABILITIES
        ]
        payload["capabilities_advertised_not_supported"] = [
            capability for capability in device.capabilities if capability not in SUPPORTED_CAPABILITIES
        ]
        return payload

    def pending_pairings(self, *, include_finished: bool = False) -> Tuple[Dict[str, Any], ...]:
        """Pairing attempts still needing the phone's proof or the user's yes."""
        self._expire_pairings()
        finished = {
            PairingStatus.APPROVED,
            PairingStatus.REJECTED,
            PairingStatus.CANCELLED,
            PairingStatus.EXPIRED,
        }
        return tuple(
            pairing.to_safe_dict()
            for pairing in sorted(self._pairings.values(), key=lambda item: item.pairing_id)
            if include_finished or pairing.status not in finished
        )

    # ------------------------------------------------------------------
    # Inbound frames (device -> JARVIS)
    # ------------------------------------------------------------------
    async def receive(self, timeout: float = DEFAULT_REQUEST_TIMEOUT_SECONDS) -> bool:
        """Pump one inbound frame. Returns whether a frame was handled."""
        raw = await self.transport.receive(timeout)
        if raw is None:
            return False
        await self.handle_frame(raw)
        return True

    async def pump(self, *, max_frames: int = 32, timeout: float = 0.05) -> int:
        """Drain the transport. Bounded, so it can never spin forever.

        ``timeout`` must be positive: ``asyncio.wait_for(..., 0)`` gives the
        queue getter no chance to run and would report "nothing arrived" even
        when a frame is already waiting.
        """
        if timeout <= 0:
            raise ValueError("pump() needs a positive timeout.")
        handled = 0
        while handled < max_frames:
            if not await self.receive(timeout):
                break
            handled += 1
        return handled

    async def handle_frame(self, raw: Any) -> None:
        """Validate, authenticate and dispatch one inbound frame.

        Never raises for a hostile frame: a malformed, unsigned, replayed or
        unknown frame is counted and dropped. Raising here would let a peer on
        the other end of the transport crash the bridge task.
        """
        self._counters["frames_received"] += 1
        try:
            message = BridgeMessage.parse(raw)
        except OversizedMessageError as exc:
            self._reject("oversized_frame", str(exc))
            return
        except UnknownMessageTypeError as exc:
            self._reject("unknown_message_type", str(exc))
            return
        except UnsupportedProtocolVersionError as exc:
            self._reject("unsupported_protocol_version", str(exc))
            return
        except (InvalidMessageError, AndroidProtocolError) as exc:
            self._reject("invalid_message", str(exc))
            return

        try:
            if message.message_type.value in AUTHENTICATED_TYPES:
                await self._handle_authenticated(message)
            else:
                await self._handle_pre_pairing(message)
        except AndroidBridgeError as exc:
            self._reject(type(exc).__name__, str(exc), device_id=message.device_id)
        except Exception as exc:  # noqa: BLE001 - a peer must not crash the bridge
            self._reject("handler_error", f"{type(exc).__name__}", device_id=message.device_id)

    # ------------------------------------------------------------------
    async def _handle_pre_pairing(self, message: BridgeMessage) -> None:
        if message.message_type is MessageType.PAIR_REQUEST:
            await self._handle_pair_request(message)
        elif message.message_type is MessageType.PAIR_RESPONSE:
            await self._handle_pair_response(message)
        elif message.message_type is MessageType.HELLO:
            await self._reply(message, MessageType.ACK, {"protocol_version": PROTOCOL_VERSION})
        else:
            # pair_challenge / pair_result travel PC -> phone only.
            self._reject("unexpected_direction", message.message_type.value, device_id=message.device_id)

    async def _handle_pair_request(self, message: BridgeMessage) -> None:
        self.require_available()
        payload = message.payload
        try:
            public_key = crypto.decode_public_key(str(payload.get("public_key", "")))
            display_name = validate_display_name(str(payload.get("display_name", "")))
            capabilities = validate_capabilities(payload.get("capabilities") or ())
        except (crypto.AndroidCryptoError, InvalidDeviceIdentityError) as exc:
            raise AndroidPairingError(f"The pairing request was malformed: {exc}") from exc

        derived_id = crypto.device_id_from_public_key(public_key)
        if derived_id != message.device_id:
            # The frame claims one identity and presents another key.
            raise AndroidAuthenticationError("The pairing key does not match the claimed device id.")

        # Proof of key ownership: the frame must be signed by the key it offers.
        if not message.verify(public_key):
            self._counters["authentication_failures"] += 1
            raise AndroidAuthenticationError("The pairing request signature did not verify.")

        existing = self.registry.find(derived_id)
        if existing is not None:
            if existing.trust_state is TrustState.REVOKED:
                raise AndroidDeviceRevokedError(
                    f"Device {derived_id} was revoked and may not pair again."
                )
            if existing.trust_state.privileged:
                raise AndroidPairingError(f"Device {derived_id} is already paired.")

        now = self.clock()
        challenge = crypto.new_nonce(32)
        pairing = PendingPairing(
            pairing_id=crypto.new_pairing_id(),
            device_id=derived_id,
            public_key=public_key,
            display_name=display_name,
            challenge=challenge,
            pairing_code=crypto.pairing_code(public_key, challenge),
            host_fingerprint=self.host_identity.fingerprint,
            capabilities=capabilities,
            requested_at=now,
            expires_at=now + self.pairing_ttl,
        )
        self._pairings[pairing.pairing_id] = pairing
        self._counters["pairing_requests"] += 1
        self._audit(
            "android_pairing_requested",
            device_id=derived_id,
            pairing_id=pairing.pairing_id,
            trust_state=TrustState.PAIRING.value,
        )
        await self._reply(
            message,
            MessageType.PAIR_CHALLENGE,
            {
                "pairing_id": pairing.pairing_id,
                "challenge": challenge.hex(),
                "host_fingerprint": self.host_identity.fingerprint,
                "pairing_code": pairing.pairing_code,
            },
            session_id="",
        )

    async def _handle_pair_response(self, message: BridgeMessage) -> None:
        self.require_available()
        pairing = self._pairings.get(str(message.payload.get("pairing_id", "")))
        if pairing is None:
            raise AndroidPairingUnknownError("This pairing flow is unknown or already finished.")
        if pairing.status is not PairingStatus.AWAITING_RESPONSE:
            raise AndroidPairingError(f"This pairing is already {pairing.status.value}.")
        if pairing.expired(now=self.clock()):
            pairing.status = PairingStatus.EXPIRED
            raise AndroidPairingExpiredError("The pairing flow expired before it was completed.")
        if message.device_id != pairing.device_id:
            raise AndroidAuthenticationError("The pairing response came from a different device.")

        attestation = pairing_attestation_bytes(
            pairing.challenge, pairing.device_id, pairing.host_fingerprint
        )
        if not message.verify(pairing.public_key):
            self._counters["authentication_failures"] += 1
            raise AndroidAuthenticationError("The pairing response signature did not verify.")
        signed_attestation = str(message.payload.get("attestation", ""))
        if signed_attestation != attestation.hex():
            raise AndroidAuthenticationError("The attestation does not cover this challenge and host.")

        # The code the phone computed must match ours - that is the human check.
        expected_code = crypto.pairing_code(pairing.public_key, pairing.challenge)
        provided_code = str(message.payload.get("pairing_code", ""))
        if not crypto.constant_time_equals(expected_code.encode(), provided_code.encode()):
            self._counters["pairings_rejected"] += 1
            pairing.status = PairingStatus.REJECTED
            pairing.detail = "pairing code mismatch"
            raise AndroidAuthenticationError("The device's pairing code does not match.")

        pairing.status = PairingStatus.VERIFIED
        pairing.verified_at = self.clock()
        self._audit(
            "android_pairing_verified",
            device_id=pairing.device_id,
            pairing_id=pairing.pairing_id,
        )
        # Nothing is trusted yet: the user still has to approve the pairing.

    # ------------------------------------------------------------------
    async def _handle_authenticated(self, message: BridgeMessage) -> None:
        device = self.registry.find(message.device_id)
        if device is None:
            raise AndroidDeviceUnknownError(f"No device with id {message.device_id} is registered.")
        if device.trust_state is TrustState.REVOKED:
            self._counters["authentication_failures"] += 1
            raise AndroidDeviceRevokedError(f"Device {message.device_id} has been revoked.")
        if not device.privileged:
            raise AndroidDeviceNotPairedError(f"Device {message.device_id} is not paired.")

        if not message.verify(device.public_key):
            self._counters["authentication_failures"] += 1
            raise AndroidAuthenticationError("The frame signature did not verify.")

        # A session-bound frame must belong to the live session.
        expected_session = self._session_ids.get(device.device_id, "")
        if expected_session and message.session_id and message.session_id != expected_session:
            self._counters["authentication_failures"] += 1
            raise AndroidAuthenticationError("The frame belongs to an older session.")

        try:
            self.replay_guard.check(message)
        except ReplayDetectedError:
            self._counters["replays_detected"] += 1
            raise

        self._heartbeat_failures.pop(device.device_id, None)
        device.record_heartbeat(now=self.clock())
        if message.message_type is MessageType.HEARTBEAT:
            self._counters["heartbeats"] += 1
            await self._reply(message, MessageType.HEARTBEAT_ACK, {"ack": True})
        elif message.message_type is MessageType.CAPABILITIES:
            self._apply_capabilities(device, message.payload.get("capabilities") or ())
            await self._reply(message, MessageType.ACK, {"ack": True})
        elif message.message_type is MessageType.DEVICE_INFO:
            await self._reply(message, MessageType.ACK, {"ack": True})
        elif message.message_type is MessageType.DISCONNECT:
            self._set_connection(device, ConnectionState.DISCONNECTED, last_error="device disconnected")
            self._session_ids.pop(device.device_id, None)
            await self._reply(message, MessageType.ACK, {"ack": True})
        else:
            self._resolve_pending(message)

    def _resolve_pending(self, message: BridgeMessage) -> None:
        """Correlate a response with its request, refusing confusion."""
        pending = self._requests.get(message.request_id)
        if pending is None:
            # An unsolicited or already answered frame. Counted, not fatal.
            self._counters["frames_rejected"] += 1
            return
        if pending.device_id != message.device_id:
            self._counters["frames_rejected"] += 1
            self._reject(
                "device_mismatch",
                f"response for {pending.device_id} arrived from {message.device_id}",
                device_id=message.device_id,
            )
            return
        if pending.expected_response != message.message_type.value:
            self._counters["frames_rejected"] += 1
            self._reject(
                "response_type_mismatch",
                f"expected {pending.expected_response}, got {message.message_type.value}",
                device_id=message.device_id,
            )
            return
        # Answered: remove first so a duplicate response cannot resolve twice.
        del self._requests[message.request_id]
        if pending.future is not None and not pending.future.done():
            pending.future.set_result(message)

    # ------------------------------------------------------------------
    # Outbound frames (JARVIS -> device)
    # ------------------------------------------------------------------
    async def _send(self, message: BridgeMessage) -> None:
        self.require_available()
        signed = message.sign(self.host_identity.private_key)
        try:
            await self.transport.send(signed.to_bytes())
        except AndroidTransportError as exc:
            raise AndroidConnectionError(f"The transport could not deliver the frame: {type(exc).__name__}") from exc
        self._counters["frames_sent"] += 1

    async def _reply(
        self,
        request: BridgeMessage,
        message_type: MessageType,
        payload: Mapping[str, Any],
        *,
        session_id: Optional[str] = None,
    ) -> None:
        await self._send(
            BridgeMessage.create(
                message_type,
                request.device_id,
                payload=payload,
                request_id=crypto.new_request_id(),
                sequence=1,
                session_id=session_id if session_id is not None else request.session_id,
            )
        )

    async def send_request(
        self,
        device_id: str,
        message_type: MessageType,
        payload: Optional[Mapping[str, Any]] = None,
        *,
        expect: Optional[MessageType] = None,
        timeout: Optional[float] = None,
        session_id: Optional[str] = None,
    ) -> Optional[BridgeMessage]:
        """Send a signed request and wait for its correlated response.

        Returns the response frame, or ``None`` when nothing answered in time.
        The correlation checks live in :meth:`_resolve_pending`: a response from
        another device, of another type, or a duplicate, is never accepted.
        """
        device = self._require_privileged(device_id)
        expected = (expect or MessageType(RESPONSE_FOR.get(message_type.value, ""))) if expect else None
        request_id = crypto.new_request_id()
        effective_session = session_id if session_id is not None else self._session_ids.get(device_id, "")
        message = BridgeMessage.create(
            message_type,
            device_id,
            payload=payload or {},
            request_id=request_id,
            sequence=self.replay_guard.last_sequence(device_id) + 1,
            session_id=effective_session,
        )
        pending = _PendingRequest(
            request_id=request_id,
            device_id=device_id,
            message_type=message_type.value,
            expected_response=expected.value if isinstance(expected, MessageType) else "",
        )
        loop = asyncio.get_event_loop()
        pending.future = loop.create_future() if expected is not None else None
        if expected is not None:
            self._requests[request_id] = pending
        try:
            await self._send(message)
            if pending.future is None:
                return None
            try:
                return await asyncio.wait_for(
                    self._await_response(pending), timeout=timeout or self.request_timeout
                )
            except asyncio.TimeoutError:
                return None
        finally:
            self._requests.pop(request_id, None)

    async def _await_response(self, pending: _PendingRequest) -> BridgeMessage:
        """Wait for the response, pumping the transport while waiting."""
        assert pending.future is not None
        while not pending.future.done():
            frame = await self.transport.receive(0.05)
            if frame is None:
                continue
            await self.handle_frame(frame)
        return pending.future.result()

    # ------------------------------------------------------------------
    # Pairing decisions (driven by the user, never by the model alone)
    # ------------------------------------------------------------------
    def approve_pairing(self, pairing_id: str) -> Dict[str, Any]:
        """Promote a verified pairing to PAIRED and register the device."""
        self.require_available()
        pairing = self._pairings.get(str(pairing_id))
        if pairing is None:
            raise AndroidPairingUnknownError(f"No pairing flow with id {pairing_id!r}.")
        if pairing.expired(now=self.clock()):
            pairing.status = PairingStatus.EXPIRED
            raise AndroidPairingExpiredError("The pairing flow expired; ask the phone to try again.")
        if pairing.status is PairingStatus.APPROVED:
            raise AndroidPairingError("This pairing has already been approved.")
        if pairing.status is not PairingStatus.VERIFIED:
            raise AndroidPairingError(
                f"This pairing is {pairing.status.value}; the device has not proved its key yet."
            )

        device = AndroidDeviceIdentity(
            device_id=pairing.device_id,
            public_key=pairing.public_key,
            display_name=pairing.display_name,
            trust_state=TrustState.UNKNOWN,
            capabilities=pairing.capabilities,
        )
        existing = self.registry.find(pairing.device_id)
        if existing is not None:
            if existing.trust_state is TrustState.REVOKED:
                raise AndroidDeviceRevokedError(
                    f"Device {pairing.device_id} was revoked and cannot be re-paired."
                )
            self.registry.update(pairing.device_id, trust_state=TrustState.PAIRED)
            device = self.registry.get(pairing.device_id)
        else:
            self.registry.register(device)
            device.transition_to(TrustState.PAIRING)
            device.transition_to(TrustState.PAIRED)
        pairing.status = PairingStatus.APPROVED
        self._counters["pairings_approved"] += 1
        self._audit(
            "android_device_paired",
            device_id=device.device_id,
            pairing_id=pairing.pairing_id,
            trust_state=TrustState.PAIRED.value,
        )
        return device.to_safe_dict()

    def cancel_pairing(self, pairing_id: str) -> Dict[str, Any]:
        pairing = self._pairings.get(str(pairing_id))
        if pairing is None:
            raise AndroidPairingUnknownError(f"No pairing flow with id {pairing_id!r}.")
        if pairing.status in (PairingStatus.APPROVED,):
            raise AndroidPairingError("An approved pairing cannot be cancelled; revoke the device instead.")
        pairing.status = PairingStatus.CANCELLED
        self._counters["pairings_rejected"] += 1
        self._audit("android_pairing_cancelled", device_id=pairing.device_id, pairing_id=pairing_id)
        return pairing.to_safe_dict()

    # ------------------------------------------------------------------
    # Connection lifecycle (bounded, never a busy loop)
    # ------------------------------------------------------------------
    async def connect(self, device_id: str, *, attempts: Optional[int] = None) -> Dict[str, Any]:
        """Connect with bounded retries and exponential backoff."""
        self.require_available()
        device = self._require_privileged(device_id)
        if device.connection.state is ConnectionState.CONNECTED:
            return {
                "device_id": device.device_id,
                "state": ConnectionState.CONNECTED.value,
                "attempts": 0,
                "already_connected": True,
            }

        limit = min(attempts or self.max_connection_attempts, MAX_CONNECTION_ATTEMPTS_LIMIT)
        backoff = self.backoff_base
        last_error = ""
        for attempt in range(1, limit + 1):
            self._counters["connect_attempts"] += 1
            state = ConnectionState.CONNECTING if attempt == 1 else ConnectionState.RECONNECTING
            self._set_connection(device, state, attempts=attempt)
            try:
                if not self.transport.is_open:
                    await self.transport.open()
                response = await self.send_request(
                    device_id,
                    MessageType.CONNECT,
                    {"protocol_version": PROTOCOL_VERSION},
                    expect=MessageType.ACK,
                    session_id=new_session_id(),
                )
            except AndroidConnectionError as exc:
                response, last_error = None, str(exc)
            except AndroidBridgeError as exc:
                response, last_error = None, str(exc)
            except AndroidTransportError as exc:
                # The link itself failed. Reported as a connection failure with
                # the exception *type* only - no socket or address details.
                response, last_error = None, f"transport unavailable ({type(exc).__name__})"
            if response is not None:
                session = response.session_id or new_session_id()
                self._session_ids[device_id] = session
                self.replay_guard.remember_device(device_id, response.sequence)
                device.record_heartbeat(now=self.clock())
                self._set_connection(
                    device, ConnectionState.CONNECTED, attempts=attempt, last_error="", session=session
                )
                self._audit(
                    "android_device_connected",
                    device_id=device_id,
                    trust_state=TrustState.CONNECTED.value,
                    connection_state=ConnectionState.CONNECTED.value,
                )
                return {
                    "device_id": device_id,
                    "state": ConnectionState.CONNECTED.value,
                    "attempts": attempt,
                    "already_connected": False,
                }
            if not last_error:
                last_error = "no response"
            if attempt < limit:
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, self.backoff_cap)

        self._set_connection(device, ConnectionState.FAILED, attempts=limit, last_error=last_error)
        self._audit(
            "android_connection_failed",
            device_id=device_id,
            connection_state=ConnectionState.FAILED.value,
        )
        raise AndroidConnectionError(
            f"Could not connect to {device.display_name} after {limit} attempts."
        )

    async def disconnect(self, device_id: str) -> Dict[str, Any]:
        device = self._require_device(device_id)
        if device.trust_state is TrustState.REVOKED:
            self._set_connection(device, ConnectionState.DISCONNECTED, last_error="revoked")
            return {"device_id": device_id, "state": ConnectionState.DISCONNECTED.value}
        try:
            await self.send_request(device_id, MessageType.DISCONNECT, {}, expect=MessageType.ACK)
        except AndroidBridgeError:
            pass  # A device that is already gone still ends up DISCONNECTED.
        self._session_ids.pop(device_id, None)
        self.replay_guard.forget_device(device_id)
        self._set_connection(device, ConnectionState.DISCONNECTED, last_error="")
        self._audit(
            "android_device_disconnected",
            device_id=device_id,
            connection_state=ConnectionState.DISCONNECTED.value,
        )
        return {"device_id": device_id, "state": ConnectionState.DISCONNECTED.value}

    def connection_state(self, device_id: str) -> ConnectionState:
        return self._require_device(device_id).connection.state

    # ------------------------------------------------------------------
    # Heartbeat / health
    # ------------------------------------------------------------------
    async def heartbeat(self, device_id: str) -> Dict[str, Any]:
        """Ask the device whether it is alive. Never fakes a healthy answer."""
        self.require_available()
        device = self._require_privileged(device_id)
        self._counters["heartbeats"] += 1
        response = await self.send_request(
            device_id, MessageType.HEARTBEAT, {"ping": True}, expect=MessageType.HEARTBEAT_ACK
        )
        if response is None:
            self._heartbeat_failures[device_id] = self.clock()
            self._set_connection(device, ConnectionState.CONNECTED, last_error="heartbeat timeout")
            return {
                "device_id": device_id,
                "health": self.health(device_id).value,
                "answered": False,
                "error_code": ErrorCode.ANDROID_CONNECTION_TIMEOUT,
            }
        self._heartbeat_failures.pop(device_id, None)
        device.record_heartbeat(now=self.clock())
        return {
            "device_id": device_id,
            "health": self.health(device_id).value,
            "answered": True,
            "sequence": response.sequence,
        }

    def health(self, device_id: str) -> HealthState:
        device = self._require_device(device_id)
        state = device.connection.state
        if device.trust_state is TrustState.REVOKED or state in (
            ConnectionState.DISCONNECTED,
            ConnectionState.FAILED,
        ):
            return HealthState.DISCONNECTED
        if state is not ConnectionState.CONNECTED:
            return HealthState.DISCONNECTED
        failed_at = self._heartbeat_failures.get(device_id)
        if failed_at is not None and (
            device.last_seen_at is None or failed_at >= device.last_seen_at
        ):
            # We asked and nobody answered: that is stale, whatever the clock says.
            return HealthState.STALE
        age = device.age_since_heartbeat(now=self.clock())
        if age is None:
            return HealthState.CONNECTED
        if age <= self.heartbeat_interval * 1.5:
            return HealthState.HEALTHY
        if age <= self.stale_after:
            return HealthState.REACHABLE
        return HealthState.STALE

    # ------------------------------------------------------------------
    # Capabilities
    # ------------------------------------------------------------------
    def capabilities(self, device_id: str) -> Dict[str, Any]:
        """What the device actually advertised, split into supported and not.

        Phase 5 understands only ``bridge.protocol`` and ``device.status``.
        Anything else a phone advertises is reported as advertised-but-unsupported
        rather than being quietly treated as available.
        """
        device = self._require_device(device_id)
        supported = [item for item in device.capabilities if item in SUPPORTED_CAPABILITIES]
        unsupported = [item for item in device.capabilities if item not in SUPPORTED_CAPABILITIES]
        return {
            "device_id": device_id,
            "supported": supported,
            "advertised_not_supported": unsupported,
            "bridge_understands": list(SUPPORTED_CAPABILITIES),
        }

    def require_capability(self, device_id: str, capability: str) -> None:
        device = self._require_device(device_id)
        if capability not in device.capabilities:
            raise AndroidCapabilityUnavailableError(
                f"Device {device.display_name} does not advertise {capability!r}."
            )
        if capability not in SUPPORTED_CAPABILITIES:
            raise AndroidCapabilityUnavailableError(
                f"{capability!r} is not part of the Phase 5 bridge; no control is implemented for it."
            )

    def _apply_capabilities(self, device: AndroidDeviceIdentity, raw: Iterable[Any]) -> None:
        try:
            device.capabilities = validate_capabilities(raw)
        except InvalidDeviceIdentityError:
            pass  # Keep the previously advertised set rather than trusting junk.

    # ------------------------------------------------------------------
    # Unpair / revoke
    # ------------------------------------------------------------------
    async def unpair(self, device_id: str) -> Dict[str, Any]:
        """Forget a device completely. It may pair again from scratch later.

        A **revoked** device cannot be unpaired: removing its record is how it
        would pair again from scratch, which is exactly what revocation exists
        to prevent.
        """
        device = self._require_device(device_id)
        if device.trust_state is TrustState.REVOKED:
            raise AndroidDeviceRevokedError(
                f"Device {device.display_name} is revoked; its record is kept so it cannot pair again."
            )
        await self.disconnect(device_id)
        self.replay_guard.forget_device(device_id)
        for pairing_id, pairing in list(self._pairings.items()):
            if pairing.device_id == device_id:
                del self._pairings[pairing_id]
        self.registry.remove(device_id)
        self._audit(
            "android_device_unpaired",
            device_id=device_id,
            trust_state="removed",
        )
        return {"device_id": device_id, "removed": True}

    def revoke(self, device_id: str) -> Dict[str, Any]:
        """Terminal revocation: the device stays known and permanently inert."""
        device = self._require_device(device_id)
        self._session_ids.pop(device_id, None)
        self.replay_guard.forget_device(device_id)
        self.registry.revoke(device_id)
        self._audit(
            "android_device_revoked",
            device_id=device_id,
            trust_state=TrustState.REVOKED.value,
        )
        return self.registry.get(device_id).to_safe_dict()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _require_device(self, device_id: str) -> AndroidDeviceIdentity:
        try:
            key = validate_device_id(device_id)
        except InvalidDeviceIdentityError as exc:
            raise AndroidDeviceUnknownError(str(exc)) from exc
        device = self.registry.find(key)
        if device is None:
            raise AndroidDeviceUnknownError(f"No Android device with id {key!r} is registered.")
        return device

    def _require_privileged(self, device_id: str) -> AndroidDeviceIdentity:
        device = self._require_device(device_id)
        if device.trust_state is TrustState.REVOKED:
            raise AndroidDeviceRevokedError(f"Device {device.display_name} has been revoked.")
        if not device.privileged:
            raise AndroidDeviceNotPairedError(f"Device {device.display_name} is not paired.")
        return device

    def _set_connection(
        self,
        device: AndroidDeviceIdentity,
        state: ConnectionState,
        *,
        attempts: Optional[int] = None,
        last_error: str = "",
        session: str = "",
    ) -> None:
        previous = device.connection
        info = ConnectionInfo(
            state=state,
            attempts=previous.attempts if attempts is None else attempts,
            connected_at=self.clock() if state is ConnectionState.CONNECTED else previous.connected_at,
            last_seen_at=previous.last_seen_at,
            transport=self.transport.name,
            last_error=last_error[:120],
        )
        device.connection = info
        if state is ConnectionState.CONNECTED and device.trust_state is TrustState.PAIRED:
            device.transition_to(TrustState.CONNECTED)
        elif state is ConnectionState.DISCONNECTED and device.trust_state is TrustState.CONNECTED:
            device.transition_to(TrustState.DISCONNECTED)

    def _reject(self, reason: str, detail: str, *, device_id: str = "") -> None:
        """Count and log a refused frame. Never raises, never logs payload."""
        self._counters["frames_rejected"] += 1
        self._audit(
            "android_frame_rejected",
            reason=reason,
            device_id=device_id,
            detail=detail[:120],
        )

    def _expire_pairings(self) -> None:
        now = self.clock()
        for pairing in self._pairings.values():
            if pairing.status in (PairingStatus.AWAITING_RESPONSE, PairingStatus.VERIFIED):
                if pairing.expired(now=now):
                    pairing.status = PairingStatus.EXPIRED

    def _audit(self, event: str, **fields: Any) -> None:
        """Emit a safe lifecycle event. Values here are ids and states only."""
        if self.audit_hook is None:
            return
        try:
            self.audit_hook(event, fields)
        except Exception:  # noqa: BLE001 - logging must never break the bridge
            pass


def create_default_android_bridge(
    *,
    transport: Optional[AndroidBridgeTransport] = None,
    registry: Optional[AndroidDeviceRegistry] = None,
    audit_hook: Optional[Callable[[str, Dict[str, Any]], None]] = None,
) -> AndroidDeviceBridge:
    """Build the bridge JARVIS uses at startup.

    With no cryptography available, or no transport configured, this returns a
    bridge whose :attr:`~AndroidDeviceBridge.available` is ``False`` and whose
    tools report ``android_bridge_unavailable`` - it never pretends a phone is
    connected.
    """
    host_identity = None
    if crypto.crypto_available():
        # Ephemeral by design: Phase 5 never writes a private key to disk.
        host_identity = AndroidHostIdentity.generate("jarvis-pc")
    return AndroidDeviceBridge(
        transport=transport if transport is not None else UnavailableAndroidTransport(),
        registry=registry if registry is not None else InMemoryAndroidDeviceRegistry(),
        host_identity=host_identity,
        audit_hook=audit_hook,
    )
