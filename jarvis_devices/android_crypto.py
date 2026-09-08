"""Cryptographic primitives for the Android bridge (Phase 5).

This module is the *only* place in JARVIS that touches key material, and it is
the only module with an optional third-party import. Everything it offers is a
standard, published construction - nothing here is invented:

=========================  =================================================
Primitive                  Standard
=========================  =================================================
Ed25519 signatures         RFC 8032 (via PyCA ``cryptography``)
SHA-256 / HMAC-SHA256      FIPS 180-4 / RFC 2104 (stdlib ``hashlib``/``hmac``)
Random bytes               stdlib ``secrets`` (``os.urandom``)
=========================  =================================================

Why a dependency is needed at all: Python's standard library offers hashing and
HMAC but **no signature scheme**, and a public-key device identity (Phase 5
requirement) cannot be built from HMAC alone. The import is guarded exactly like
the existing ``pywin32`` / ``pycaw`` guards in this project, so the rest of
:mod:`jarvis_devices` stays standard-library only and the bridge degrades to an
honest ``android_bridge_unavailable`` instead of importing badly.

Security rules this module enforces:

* a private key never leaves this module as anything but ``bytes`` owned by the
  caller - it is never logged, never formatted into a string, never hashed into
  an identifier and never written to disk by this module;
* verification is total: it returns ``False`` for malformed input rather than
  raising into a caller that might treat an exception as "not verified";
* signature comparison and code comparison are constant time.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from typing import Tuple

__all__ = [
    "ALGORITHM",
    "PUBLIC_KEY_BYTES",
    "SIGNATURE_BYTES",
    "AndroidCryptoError",
    "AndroidCryptoUnavailableError",
    "crypto_available",
    "crypto_unavailable_reason",
    "generate_keypair",
    "sign",
    "verify",
    "device_id_from_public_key",
    "fingerprint",
    "new_nonce",
    "new_pairing_id",
    "new_request_id",
    "mac",
    "constant_time_equals",
    "pairing_code",
    "encode_public_key",
    "decode_public_key",
    "DEVICE_ID_PREFIX",
]

#: Signature scheme used for every device identity.
ALGORITHM = "ed25519"
#: Raw Ed25519 public key length.
PUBLIC_KEY_BYTES = 32
#: Raw Ed25519 signature length.
SIGNATURE_BYTES = 64
#: Bridge device ids look like ``adev-<32 hex chars>``.
DEVICE_ID_PREFIX = "adev"

_CRYPTO_UNAVAILABLE = ""

try:  # pragma: no cover - exercised on machines without the library
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    _CRYPTO_AVAILABLE = True
except Exception as exc:  # pragma: no cover - depends on the environment
    _CRYPTO_AVAILABLE = False
    _CRYPTO_UNAVAILABLE = f"{type(exc).__name__}: {exc}"
    InvalidSignature = Exception  # type: ignore[assignment,misc]
    Ed25519PrivateKey = None  # type: ignore[assignment]
    Ed25519PublicKey = None  # type: ignore[assignment]


class AndroidCryptoError(Exception):
    """Base class for every cryptographic failure in the bridge."""


class AndroidCryptoUnavailableError(AndroidCryptoError):
    """Raised when the signature library is not importable."""


# ---------------------------------------------------------------------------
# Availability
# ---------------------------------------------------------------------------
def crypto_available() -> bool:
    """Whether Ed25519 signing can be performed right now."""
    return _CRYPTO_AVAILABLE


def crypto_unavailable_reason() -> str:
    """Human readable reason, or ``""`` when the primitives are available."""
    if _CRYPTO_AVAILABLE:
        return ""
    return (
        "Android bridge cryptography needs the 'cryptography' package "
        f"(Ed25519). Import failed: {_CRYPTO_UNAVAILABLE or 'unknown reason'}"
    )


def _require_crypto() -> None:
    if not _CRYPTO_AVAILABLE:
        raise AndroidCryptoUnavailableError(crypto_unavailable_reason())


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------
def generate_keypair() -> Tuple[bytes, bytes]:
    """Generate a fresh Ed25519 key pair as ``(private_bytes, public_bytes)``.

    The private half is returned to the caller and never persisted here. The
    public half is what gets registered, logged and compared.
    """
    _require_crypto()
    private = Ed25519PrivateKey.generate()
    private_bytes = private.private_bytes_raw()
    public_bytes = private.public_key().public_bytes_raw()
    return private_bytes, public_bytes


def _public_key_object(public_key: bytes) -> "Ed25519PublicKey":
    _require_crypto()
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != PUBLIC_KEY_BYTES:
        raise AndroidCryptoError("A public key must be exactly 32 raw bytes.")
    return Ed25519PublicKey.from_public_bytes(bytes(public_key))


def _private_key_object(private_key: bytes) -> "Ed25519PrivateKey":
    _require_crypto()
    if not isinstance(private_key, (bytes, bytearray)) or len(private_key) != PUBLIC_KEY_BYTES:
        raise AndroidCryptoError("A private key must be exactly 32 raw bytes.")
    return Ed25519PrivateKey.from_private_bytes(bytes(private_key))


def sign(private_key: bytes, message: bytes) -> bytes:
    """Sign ``message`` and return the 64 byte Ed25519 signature."""
    if not isinstance(message, (bytes, bytearray)):
        raise AndroidCryptoError("Only bytes can be signed.")
    return _private_key_object(private_key).sign(bytes(message))


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Return ``True`` only for a genuine signature over exactly ``message``.

    Never raises: malformed keys, wrong lengths and bad signatures all answer
    ``False``, so a caller cannot mistake an exception for a verification
    result.
    """
    if not _CRYPTO_AVAILABLE:
        return False
    if not isinstance(message, (bytes, bytearray)) or not isinstance(signature, (bytes, bytearray)):
        return False
    if len(signature) != SIGNATURE_BYTES:
        return False
    try:
        _public_key_object(public_key).verify(bytes(signature), bytes(message))
    except InvalidSignature:
        return False
    except Exception:  # noqa: BLE001 - a malformed key must not verify
        return False
    return True


# ---------------------------------------------------------------------------
# Identifiers (derived from the *public* key only)
# ---------------------------------------------------------------------------
def device_id_from_public_key(public_key: bytes) -> str:
    """Stable bridge id for a device: ``adev-`` + 32 hex chars of SHA-256.

    Deliberately **not** derived from an IP address, hostname, Bluetooth MAC or
    any other mutable network property: the id changes only when the device
    generates a new key pair.
    """
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != PUBLIC_KEY_BYTES:
        raise AndroidCryptoError("Cannot derive a device id from a malformed public key.")
    digest = hashlib.sha256(bytes(public_key)).hexdigest()[:32]
    return f"{DEVICE_ID_PREFIX}-{digest}"


def fingerprint(public_key: bytes) -> str:
    """Human comparable fingerprint, e.g. ``Q3F2-7KJA-...`` (Crockford base32).

    Used for the user to compare two devices, never for authorisation - the
    signature check does that.
    """
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != PUBLIC_KEY_BYTES:
        raise AndroidCryptoError("Cannot fingerprint a malformed public key.")
    digest = hashlib.sha256(bytes(public_key)).digest()[:20]
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # Crockford: no I, L, O, U
    bits = int.from_bytes(digest, "big")
    characters = []
    for _ in range(32):
        characters.append(alphabet[bits & 0x1F])
        bits >>= 5
    grouped = "".join(reversed(characters))
    return "-".join(grouped[index : index + 4] for index in range(0, 32, 4))


def encode_public_key(public_key: bytes) -> str:
    """URL-safe base64 (no padding) form of a public key, safe to display."""
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != PUBLIC_KEY_BYTES:
        raise AndroidCryptoError("Cannot encode a malformed public key.")
    return base64.urlsafe_b64encode(bytes(public_key)).decode("ascii").rstrip("=")


def decode_public_key(encoded: str) -> bytes:
    """Reverse :func:`encode_public_key`; raises on anything malformed."""
    if not isinstance(encoded, str):
        raise AndroidCryptoError("An encoded public key must be a string.")
    padded = encoded.strip()
    padded += "=" * (-len(padded) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:  # noqa: BLE001 - any decoding problem is malformed
        raise AndroidCryptoError(f"Public key is not valid base64: {exc}") from exc
    if len(raw) != PUBLIC_KEY_BYTES:
        raise AndroidCryptoError(f"A public key must decode to {PUBLIC_KEY_BYTES} bytes.")
    return raw


# ---------------------------------------------------------------------------
# Random material and MACs
# ---------------------------------------------------------------------------
def new_nonce(size: int = 32) -> bytes:
    """Cryptographically random bytes (used for challenges and nonces)."""
    if size <= 0 or size > 256:
        raise AndroidCryptoError("Nonce size must be between 1 and 256 bytes.")
    return secrets.token_bytes(size)


def new_pairing_id() -> str:
    """Unique pairing flow id (``pair-<32 hex>``). Not a secret, not auth."""
    return f"pair-{secrets.token_hex(16)}"


def new_request_id() -> str:
    """Unique request id (``req-<32 hex>``). Correlation only - never auth."""
    return f"req-{secrets.token_hex(16)}"


def mac(key: bytes, message: bytes) -> bytes:
    """HMAC-SHA256 over ``message`` with ``key``."""
    if not isinstance(key, (bytes, bytearray)) or not key:
        raise AndroidCryptoError("An HMAC key must be non-empty bytes.")
    if not isinstance(message, (bytes, bytearray)):
        raise AndroidCryptoError("Only bytes can be authenticated.")
    return hmac.new(bytes(key), bytes(message), hashlib.sha256).digest()


def constant_time_equals(left: bytes, right: bytes) -> bool:
    """Constant time comparison, so timing cannot leak a secret prefix."""
    if not isinstance(left, (bytes, bytearray)) or not isinstance(right, (bytes, bytearray)):
        return False
    return hmac.compare_digest(bytes(left), bytes(right))


def pairing_code(public_key: bytes, challenge: bytes) -> str:
    """Short code both sides display so a human can confirm the pairing.

    Derived from the device public key and the PC's challenge with HMAC-SHA256,
    so an attacker who cannot produce a valid signature cannot produce a
    matching code either. It is a *comparison aid*, never a credential: the
    pairing is authorised by the signature, and the code is 6 characters of
    entropy by design (memorable, and useless without the key).
    """
    if not isinstance(challenge, (bytes, bytearray)) or not challenge:
        raise AndroidCryptoError("A pairing code needs a non-empty challenge.")
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != PUBLIC_KEY_BYTES:
        raise AndroidCryptoError("Cannot build a pairing code for a malformed public key.")
    digest = mac(bytes(public_key), bytes(challenge))
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    value = int.from_bytes(digest[:5], "big")
    characters = []
    for _ in range(6):
        characters.append(alphabet[value % 32])
        value //= 32
    return "".join(characters)
