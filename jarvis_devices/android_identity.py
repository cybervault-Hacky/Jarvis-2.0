"""Android device identity and trust state (Phase 5).

An Android device is identified by a **bridge identity** derived from an
Ed25519 public key - never from an IP address, hostname, Bluetooth MAC or any
other mutable network property. Two consequences matter for security:

* a device that changes network keeps its identity;
* an attacker who can spoof an address cannot spoof an identity, because the
  identity is only meaningful together with a signature the key can produce.

The PC side stores **public keys only**. There is no device secret on the PC to
steal, which is the whole reason for using signatures instead of a shared
symmetric key.

Trust states (:class:`TrustState`) form a small machine with a terminal
``REVOKED`` state: once revoked, a device can never return to a privileged
state through any transition defined here.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, FrozenSet, Iterable, Mapping, Optional, Tuple

from . import android_crypto as crypto
from .confirmation import utcnow

__all__ = [
    "TrustState",
    "ConnectionState",
    "HealthState",
    "AndroidIdentityError",
    "InvalidDeviceIdentityError",
    "DuplicateDeviceError",
    "UnknownDeviceError",
    "RevokedDeviceError",
    "IllegalTrustTransitionError",
    "AndroidDeviceIdentity",
    "AndroidHostIdentity",
    "ConnectionInfo",
    "is_valid_device_id",
    "validate_display_name",
    "validate_capability",
    "validate_capabilities",
    "MAX_DISPLAY_NAME_LENGTH",
    "MAX_CAPABILITIES",
    "MAX_CAPABILITY_LENGTH",
]

#: Longest accepted display name (kept short: it is shown to a human).
MAX_DISPLAY_NAME_LENGTH = 48
#: Most capabilities a device may advertise.
MAX_CAPABILITIES = 64
#: Longest capability name.
MAX_CAPABILITY_LENGTH = 64

_DEVICE_ID_RE = re.compile(r"^adev-[0-9a-f]{32}$")
_CAPABILITY_RE = re.compile(r"^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*){0,4}$")
#: Characters that must never appear in a device supplied display name. They
#: are replaced with a space (not deleted) so "Pixel\n8" reads as "Pixel 8"
#: instead of "Pixel8"; a newline could otherwise forge a log line.
_FORBIDDEN_NAME_RE = re.compile(r"[\x00-\x1f\x7f\u2028\u2029]")


class AndroidIdentityError(Exception):
    """Base class for identity and trust problems."""


class InvalidDeviceIdentityError(AndroidIdentityError):
    """Raised for a malformed device id, name, key or capability list."""


class DuplicateDeviceError(AndroidIdentityError):
    """Raised when a device that is already registered is registered again."""


class UnknownDeviceError(AndroidIdentityError):
    """Raised when a device id is not in the registry."""


class RevokedDeviceError(AndroidIdentityError):
    """Raised when an operation is attempted for a revoked device."""


class IllegalTrustTransitionError(AndroidIdentityError):
    """Raised when a trust state change is not allowed."""


class TrustState(str, Enum):
    """Trust lifecycle of a bridge device (Phase 5 §9)."""

    #: Seen, but never paired. Privileged operations are refused.
    UNKNOWN = "unknown"
    #: A pairing handshake is in progress and not yet authorised.
    PAIRING = "pairing"
    #: Signature verified and the user authorised the pairing.
    PAIRED = "paired"
    #: Paired and currently connected.
    CONNECTED = "connected"
    #: Paired but not connected right now.
    DISCONNECTED = "disconnected"
    #: Terminal. Nothing privileged may ever run for this device again.
    REVOKED = "revoked"

    @property
    def privileged(self) -> bool:
        """Whether a device in this state may be acted upon."""
        return self in (TrustState.PAIRED, TrustState.CONNECTED, TrustState.DISCONNECTED)


#: Legal transitions. ``REVOKED`` has no outgoing edges - it is terminal.
_ALLOWED_TRUST_TRANSITIONS: Dict[TrustState, FrozenSet[TrustState]] = {
    TrustState.UNKNOWN: frozenset({TrustState.PAIRING, TrustState.REVOKED}),
    TrustState.PAIRING: frozenset({TrustState.PAIRED, TrustState.UNKNOWN, TrustState.REVOKED}),
    TrustState.PAIRED: frozenset({TrustState.CONNECTED, TrustState.REVOKED}),
    TrustState.CONNECTED: frozenset({TrustState.DISCONNECTED, TrustState.PAIRED, TrustState.REVOKED}),
    TrustState.DISCONNECTED: frozenset({TrustState.CONNECTED, TrustState.PAIRED, TrustState.REVOKED}),
    TrustState.REVOKED: frozenset(),
}


class ConnectionState(str, Enum):
    """Transport level connection lifecycle (Phase 5 §11)."""

    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    FAILED = "failed"


class HealthState(str, Enum):
    """What the heartbeat says about a device right now (Phase 5 §12)."""

    HEALTHY = "healthy"
    REACHABLE = "reachable"
    STALE = "stale"
    DISCONNECTED = "disconnected"
    CONNECTED = "connected"


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------
def is_valid_device_id(device_id: Any) -> bool:
    """Whether ``device_id`` has the exact bridge id shape."""
    return isinstance(device_id, str) and bool(_DEVICE_ID_RE.match(device_id))


def validate_device_id(device_id: Any) -> str:
    """Return ``device_id`` or raise :class:`InvalidDeviceIdentityError`."""
    if not is_valid_device_id(device_id):
        raise InvalidDeviceIdentityError(
            "A bridge device id must look like 'adev-' followed by 32 hex characters."
        )
    return str(device_id)


def validate_display_name(name: Any) -> str:
    """Normalise a device supplied display name into something safe to show.

    Control characters (including newlines, which would forge log lines) are
    removed, whitespace is collapsed and the result is length capped. A name is
    never used for authorisation - only the signature is.
    """
    if not isinstance(name, str):
        raise InvalidDeviceIdentityError("A display name must be a string.")
    cleaned = unicodedata.normalize("NFKC", name)
    cleaned = _FORBIDDEN_NAME_RE.sub(" ", cleaned)
    cleaned = " ".join(cleaned.split())
    if len(cleaned) > MAX_DISPLAY_NAME_LENGTH:
        cleaned = cleaned[:MAX_DISPLAY_NAME_LENGTH].rstrip()
    if not cleaned:
        raise InvalidDeviceIdentityError("A display name must contain at least one visible character.")
    return cleaned


def validate_capability(capability: Any) -> str:
    """Validate one capability name such as ``bridge.protocol``."""
    if not isinstance(capability, str) or not _CAPABILITY_RE.match(capability):
        raise InvalidDeviceIdentityError(
            f"Invalid capability name {capability!r}: expected dotted lower case words."
        )
    if len(capability) > MAX_CAPABILITY_LENGTH:
        raise InvalidDeviceIdentityError(f"Capability name longer than {MAX_CAPABILITY_LENGTH} characters.")
    return capability


def validate_capabilities(capabilities: Iterable[Any]) -> Tuple[str, ...]:
    """Validate a capability list; duplicates are collapsed, order preserved."""
    if isinstance(capabilities, (str, bytes)) or not isinstance(capabilities, Iterable):
        raise InvalidDeviceIdentityError("Capabilities must be a list of names.")
    seen: Dict[str, None] = {}
    for capability in capabilities:
        seen.setdefault(validate_capability(capability), None)
        if len(seen) > MAX_CAPABILITIES:
            raise InvalidDeviceIdentityError(f"More than {MAX_CAPABILITIES} capabilities advertised.")
    return tuple(seen)


# ---------------------------------------------------------------------------
# Connection metadata
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ConnectionInfo:
    """Non-secret transport metadata about one device."""

    state: ConnectionState = ConnectionState.DISCONNECTED
    attempts: int = 0
    connected_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    transport: str = ""
    #: Truncated, non-technical failure description (never a raw socket error).
    last_error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state": self.state.value,
            "attempts": self.attempts,
            "connected_at": self.connected_at.isoformat() if self.connected_at else None,
            "last_seen_at": self.last_seen_at.isoformat() if self.last_seen_at else None,
            "transport": self.transport,
            "last_error": self.last_error,
        }


# ---------------------------------------------------------------------------
# Device identity
# ---------------------------------------------------------------------------
@dataclass
class AndroidDeviceIdentity:
    """A paired (or pairing) Android device as the bridge knows it.

    Holds the device's **public** key only. There is no private key and no
    shared secret here, so a leaked registry cannot be used to impersonate a
    device.
    """

    device_id: str
    public_key: bytes
    display_name: str
    trust_state: TrustState = TrustState.UNKNOWN
    capabilities: Tuple[str, ...] = ()
    connection: ConnectionInfo = field(default_factory=ConnectionInfo)
    created_at: datetime = field(default_factory=utcnow)
    paired_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    #: Highest protocol sequence number accepted from this device (replay guard).
    last_sequence: int = 0

    def __post_init__(self) -> None:
        self.device_id = validate_device_id(self.device_id)
        if (
            not isinstance(self.public_key, (bytes, bytearray))
            or len(self.public_key) != crypto.PUBLIC_KEY_BYTES
        ):
            raise InvalidDeviceIdentityError(
                f"A device public key must be exactly {crypto.PUBLIC_KEY_BYTES} bytes."
            )
        self.public_key = bytes(self.public_key)
        derived = crypto.device_id_from_public_key(self.public_key)
        if derived != self.device_id:
            raise InvalidDeviceIdentityError(
                "The device id does not match the public key it was derived from."
            )
        self.display_name = validate_display_name(self.display_name)
        self.capabilities = validate_capabilities(self.capabilities)

    # ------------------------------------------------------------------
    # Derived, safe views
    # ------------------------------------------------------------------
    @property
    def fingerprint(self) -> str:
        return crypto.fingerprint(self.public_key)

    @property
    def privileged(self) -> bool:
        """Whether this device may be acted upon right now."""
        return self.trust_state.privileged and self.trust_state is not TrustState.REVOKED

    def to_safe_dict(self, *, include_key: bool = False) -> Dict[str, Any]:
        """A log and UI safe view. Never contains private material."""
        payload: Dict[str, Any] = {
            "device_id": self.device_id,
            "display_name": self.display_name,
            "fingerprint": self.fingerprint,
            "trust_state": self.trust_state.value,
            "capabilities": list(self.capabilities),
            "connection": self.connection.to_dict(),
            "created_at": self.created_at.isoformat(),
            "paired_at": self.paired_at.isoformat() if self.paired_at else None,
            "last_seen_at": self.last_seen_at.isoformat() if self.last_seen_at else None,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
        }
        if include_key:
            payload["public_key"] = crypto.encode_public_key(self.public_key)
        return payload

    def to_registry_record(self) -> Dict[str, Any]:
        """Serialisable form for the registry (public material only)."""
        return self.to_safe_dict(include_key=True)

    @classmethod
    def from_registry_record(cls, record: Mapping[str, Any]) -> "AndroidDeviceIdentity":
        """Rebuild an identity from :meth:`to_registry_record`."""
        if not isinstance(record, Mapping):
            raise InvalidDeviceIdentityError("A registry record must be a mapping.")
        connection_raw = record.get("connection") or {}
        connection = ConnectionInfo(
            state=ConnectionState(str(connection_raw.get("state", ConnectionState.DISCONNECTED.value))),
            attempts=int(connection_raw.get("attempts", 0) or 0),
            connected_at=_parse_timestamp(connection_raw.get("connected_at")),
            last_seen_at=_parse_timestamp(connection_raw.get("last_seen_at")),
            transport=str(connection_raw.get("transport", "")),
            last_error=str(connection_raw.get("last_error", "")),
        )
        identity = cls(
            device_id=str(record.get("device_id", "")),
            public_key=crypto.decode_public_key(str(record.get("public_key", ""))),
            display_name=str(record.get("display_name", "")),
            trust_state=TrustState(str(record.get("trust_state", TrustState.UNKNOWN.value))),
            capabilities=tuple(record.get("capabilities") or ()),
            connection=connection,
            paired_at=_parse_timestamp(record.get("paired_at")),
            revoked_at=_parse_timestamp(record.get("revoked_at")),
        )
        created = _parse_timestamp(record.get("created_at"))
        if created is not None:
            identity.created_at = created
        last_seen = _parse_timestamp(record.get("last_seen_at"))
        if last_seen is not None:
            identity.last_seen_at = last_seen
        return identity

    # ------------------------------------------------------------------
    # State transitions
    # ------------------------------------------------------------------
    def transition_to(self, state: TrustState) -> None:
        """Move to ``state`` or raise :class:`IllegalTrustTransitionError`."""
        if state is self.trust_state:
            return
        if state not in _ALLOWED_TRUST_TRANSITIONS[self.trust_state]:
            raise IllegalTrustTransitionError(
                f"Cannot move a device from {self.trust_state.value} to {state.value}."
            )
        now = utcnow()
        if state is TrustState.PAIRED and self.paired_at is None:
            self.paired_at = now
        if state is TrustState.REVOKED:
            self.revoked_at = now
            self.connection = ConnectionInfo(
                state=ConnectionState.DISCONNECTED,
                attempts=self.connection.attempts,
                transport=self.connection.transport,
                last_error="revoked",
            )
        self.trust_state = state

    def revoke(self) -> None:
        """Terminal revocation: no privileged operation is possible after this."""
        self.transition_to(TrustState.REVOKED)

    def require_privileged(self) -> None:
        """Raise unless this device may be acted upon."""
        if self.trust_state is TrustState.REVOKED:
            raise RevokedDeviceError(f"Device {self.device_id} has been revoked.")
        if not self.trust_state.privileged:
            raise InvalidDeviceIdentityError(
                f"Device {self.device_id} is in state {self.trust_state.value}, not paired."
            )

    def record_heartbeat(self, *, now: Optional[datetime] = None) -> None:
        self.last_seen_at = now or utcnow()

    def age_since_heartbeat(self, *, now: Optional[datetime] = None) -> Optional[timedelta]:
        if self.last_seen_at is None:
            return None
        return (now or utcnow()) - self.last_seen_at


def _parse_timestamp(value: Any) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# PC side identity (so the phone can authenticate JARVIS too)
# ---------------------------------------------------------------------------
@dataclass
class AndroidHostIdentity:
    """JARVIS's own bridge identity.

    Mutual authentication matters: without it, any process that can reach the
    transport could pose as JARVIS to a paired phone. The private key is held in
    memory only by default - nothing in Phase 5 writes it to disk, and it is
    never logged.
    """

    private_key: bytes
    public_key: bytes
    label: str = "jarvis-pc"
    created_at: datetime = field(default_factory=utcnow)

    @classmethod
    def generate(cls, label: str = "jarvis-pc") -> "AndroidHostIdentity":
        private_key, public_key = crypto.generate_keypair()
        return cls(private_key=private_key, public_key=public_key, label=validate_display_name(label))

    @property
    def fingerprint(self) -> str:
        return crypto.fingerprint(self.public_key)

    def sign(self, message: bytes) -> bytes:
        return crypto.sign(self.private_key, message)

    def to_safe_dict(self) -> Dict[str, Any]:
        """Public view only - the private key is never included."""
        return {
            "label": self.label,
            "algorithm": crypto.ALGORITHM,
            "fingerprint": self.fingerprint,
            "public_key": crypto.encode_public_key(self.public_key),
            "created_at": self.created_at.isoformat(),
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        # Deliberately omits both key halves.
        return f"<AndroidHostIdentity label={self.label!r} fingerprint={self.fingerprint}>"
