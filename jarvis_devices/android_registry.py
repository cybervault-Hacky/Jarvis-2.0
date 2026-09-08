"""Secure local registry of paired Android devices (Phase 5).

The registry answers "which phones does this JARVIS trust, and in what state?".
It stores **public keys only** - there is no device secret and no host private
key in here, so a leaked registry file reveals which devices were paired and
nothing that could be used to impersonate one.

Two properties are enforced deliberately:

* a revoked device stays in the registry. Forgetting it would let the same key
  pair again from scratch and silently regain trust;
* the registry is bounded (:data:`DEFAULT_MAX_DEVICES`). An attacker who can
  reach the transport cannot grow it without limit.

Persistence is opt-in and explicit: the default registry is in-memory, so
running JARVIS never writes anything to disk. When a path *is* given the file is
written atomically and validated on load.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Protocol, Tuple

from . import android_crypto as crypto
from .android_identity import (
    AndroidDeviceIdentity,
    ConnectionInfo,
    DuplicateDeviceError,
    InvalidDeviceIdentityError,
    TrustState,
    UnknownDeviceError,
    validate_capabilities,
    validate_device_id,
    validate_display_name,
)

__all__ = [
    "AndroidDeviceRegistry",
    "InMemoryAndroidDeviceRegistry",
    "JsonAndroidDeviceRegistry",
    "DEFAULT_MAX_DEVICES",
    "REGISTRY_SCHEMA_VERSION",
]

#: Registry records carry this so a future format change is detectable.
REGISTRY_SCHEMA_VERSION = 1
#: How many devices one JARVIS may keep paired.
DEFAULT_MAX_DEVICES = 32


class AndroidDeviceRegistry(Protocol):
    """Structural contract for a paired-device store."""

    def register(self, identity: AndroidDeviceIdentity, *, override: bool = False) -> AndroidDeviceIdentity: ...

    def get(self, device_id: str) -> AndroidDeviceIdentity: ...

    def find(self, device_id: str) -> Optional[AndroidDeviceIdentity]: ...

    def list_devices(
        self, *, trust_state: Optional[TrustState] = None, include_revoked: bool = True
    ) -> Tuple[AndroidDeviceIdentity, ...]: ...

    def update(self, device_id: str, **changes: Any) -> AndroidDeviceIdentity: ...

    def revoke(self, device_id: str) -> AndroidDeviceIdentity: ...

    def remove(self, device_id: str) -> bool: ...


class InMemoryAndroidDeviceRegistry:
    """Thread safe, bounded, in-memory device registry (the default)."""

    def __init__(self, *, max_devices: int = DEFAULT_MAX_DEVICES) -> None:
        if max_devices < 1:
            raise ValueError("max_devices must be at least 1.")
        self.max_devices = max_devices
        self._devices: Dict[str, AndroidDeviceIdentity] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    def __len__(self) -> int:
        with self._lock:
            return len(self._devices)

    def count(self, *, include_revoked: bool = True) -> int:
        return len(self.list_devices(include_revoked=include_revoked))

    def device_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._devices))

    # ------------------------------------------------------------------
    def register(self, identity: AndroidDeviceIdentity, *, override: bool = False) -> AndroidDeviceIdentity:
        """Add a device. Re-registering an existing id raises unless ``override``.

        Re-registering a **revoked** id is always refused: revocation survives.
        """
        if not isinstance(identity, AndroidDeviceIdentity):
            raise InvalidDeviceIdentityError("Only an AndroidDeviceIdentity can be registered.")
        with self._lock:
            existing = self._devices.get(identity.device_id)
            if existing is not None:
                if existing.trust_state is TrustState.REVOKED:
                    raise DuplicateDeviceError(
                        f"Device {identity.device_id} is revoked and cannot be registered again."
                    )
                if not override:
                    raise DuplicateDeviceError(f"Device {identity.device_id} is already registered.")
            elif len(self._devices) >= self.max_devices:
                raise InvalidDeviceIdentityError(
                    f"This JARVIS already tracks {self.max_devices} devices; "
                    "revoke or remove one before pairing another."
                )
            self._devices[identity.device_id] = identity
            self._persist()
            return identity

    def get(self, device_id: str) -> AndroidDeviceIdentity:
        found = self.find(device_id)
        if found is None:
            raise UnknownDeviceError(f"No Android device with id {device_id!r} is registered.")
        return found

    def find(self, device_id: str) -> Optional[AndroidDeviceIdentity]:
        try:
            key = validate_device_id(device_id)
        except InvalidDeviceIdentityError:
            return None
        with self._lock:
            return self._devices.get(key)

    def list_devices(
        self,
        *,
        trust_state: Optional[TrustState] = None,
        include_revoked: bool = True,
    ) -> Tuple[AndroidDeviceIdentity, ...]:
        with self._lock:
            devices: List[AndroidDeviceIdentity] = list(self._devices.values())
        if trust_state is not None:
            devices = [device for device in devices if device.trust_state is trust_state]
        if not include_revoked:
            devices = [device for device in devices if device.trust_state is not TrustState.REVOKED]
        return tuple(sorted(devices, key=lambda device: device.device_id))

    def privileged_devices(self) -> Tuple[AndroidDeviceIdentity, ...]:
        """Devices that may actually be acted upon (paired, not revoked)."""
        return tuple(device for device in self.list_devices() if device.privileged)

    # ------------------------------------------------------------------
    def update(self, device_id: str, **changes: Any) -> AndroidDeviceIdentity:
        """Apply validated changes. Unknown keys are rejected.

        ``trust_state`` changes go through the identity's state machine, so a
        revoked device cannot be moved back to a privileged state.
        """
        allowed = {"trust_state", "capabilities", "connection", "display_name"}
        unexpected = sorted(set(changes) - allowed)
        if unexpected:
            raise InvalidDeviceIdentityError(f"Cannot update unknown fields: {unexpected}")
        if not changes:
            raise InvalidDeviceIdentityError("update() needs at least one change.")
        device = self.get(device_id)
        with self._lock:
            if "display_name" in changes:
                device.display_name = validate_display_name(changes["display_name"])
            if "capabilities" in changes:
                device.capabilities = validate_capabilities(changes["capabilities"])
            if "connection" in changes:
                connection = changes["connection"]
                if not isinstance(connection, ConnectionInfo):
                    raise InvalidDeviceIdentityError("connection must be a ConnectionInfo.")
                device.connection = connection
            if "trust_state" in changes:
                state = changes["trust_state"]
                if not isinstance(state, TrustState):
                    raise InvalidDeviceIdentityError("trust_state must be a TrustState.")
                device.transition_to(state)
            self._persist()
            return device

    def revoke(self, device_id: str) -> AndroidDeviceIdentity:
        """Terminal revocation. The device stays known but permanently inert."""
        device = self.get(device_id)
        with self._lock:
            device.revoke()
            self._persist()
            return device

    def remove(self, device_id: str) -> bool:
        """Forget a device entirely; returns ``False`` when it was unknown."""
        key = validate_device_id(device_id)
        with self._lock:
            existed = self._devices.pop(key, None) is not None
            if existed:
                self._persist()
            return existed

    # ------------------------------------------------------------------
    def describe(self) -> Dict[str, Any]:
        """Safe summary for the framework diagnostics tool."""
        devices = self.list_devices()
        by_state: Dict[str, int] = {}
        for device in devices:
            by_state[device.trust_state.value] = by_state.get(device.trust_state.value, 0) + 1
        return {
            "devices": len(devices),
            "max_devices": self.max_devices,
            "by_trust_state": by_state,
            "privileged": len(self.privileged_devices()),
        }

    # ------------------------------------------------------------------
    def _persist(self) -> None:
        """Hook for subclasses that write the registry somewhere."""


class JsonAndroidDeviceRegistry(InMemoryAndroidDeviceRegistry):
    """Registry that also persists **public** material to a JSON file.

    The file contains device ids, public keys, display names, trust states,
    capabilities and timestamps - no private key, no shared secret, no token.
    It is still not something to publish: it lists which phones a user paired.
    """

    def __init__(self, path: str, *, max_devices: int = DEFAULT_MAX_DEVICES) -> None:
        super().__init__(max_devices=max_devices)
        if not isinstance(path, str) or not path.strip():
            raise ValueError("A registry path is required.")
        # ``pathlib`` rather than ``os``: the framework has a standing rule that
        # no module in this package imports ``os``, and path handling does not
        # need it. Nothing here can reach a shell or spawn a process.
        self.path = Path(path).expanduser()
        self._load()

    @property
    def path_text(self) -> str:
        """Absolute path as a string (for messages and tests)."""
        return str(self.path)

    # ------------------------------------------------------------------
    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise InvalidDeviceIdentityError(
                f"The Android device registry at {self.path} could not be read: {type(exc).__name__}."
            ) from exc
        if not isinstance(raw, dict) or raw.get("schema_version") != REGISTRY_SCHEMA_VERSION:
            raise InvalidDeviceIdentityError(
                f"The Android device registry at {self.path} has an unexpected format."
            )
        records = raw.get("devices")
        if not isinstance(records, list):
            raise InvalidDeviceIdentityError("The registry file must contain a list of devices.")
        for record in records:
            # Defence in depth: a hand edited file must not smuggle key material.
            if isinstance(record, dict) and any("private" in str(key).lower() for key in record):
                raise InvalidDeviceIdentityError(
                    "The registry file contains private key material and was refused."
                )
            try:
                identity = AndroidDeviceIdentity.from_registry_record(record)
            except (crypto.AndroidCryptoError, InvalidDeviceIdentityError, ValueError, KeyError):
                # One bad record must not make the whole registry unusable, but
                # it must not be silently trusted either - it is skipped.
                continue
            self._devices[identity.device_id] = identity

    def _persist(self) -> None:
        payload = {
            "schema_version": REGISTRY_SCHEMA_VERSION,
            "note": "Public material only. No private key is ever stored here.",
            "devices": [device.to_registry_record() for device in self.list_devices()],
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Atomic replace: a crash mid-write must not leave a truncated registry.
        temporary = self.path.with_name(self.path.name + ".tmp")
        try:
            temporary.write_text(
                json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
            )
            _restrict_permissions(temporary)
            temporary.replace(self.path)
        except OSError:
            try:
                temporary.unlink()
            except OSError:
                pass
            raise
        _restrict_permissions(self.path)


def _restrict_permissions(path: Path) -> None:
    """Best effort 0600. Not all filesystems honour it; nothing secret is here."""
    try:
        path.chmod(0o600)
    except OSError:  # pragma: no cover - filesystem dependent
        pass
