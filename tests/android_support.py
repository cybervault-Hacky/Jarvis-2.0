"""Test doubles for the Phase 5 Android bridge suite.

:class:`FakeAndroidDevice` is a simulated phone: it owns a real Ed25519 key
pair, speaks the real protocol, and replies over a real (in-memory) transport.
It is a *test double for the peer*, not a stand-in for the bridge under test -
every assertion in the suite is about real ``AndroidDeviceBridge`` code.

Nothing here opens a socket, spawns a process, shells out or touches ADB.
"""

from __future__ import annotations

import asyncio
import unittest
from typing import Any, Dict, List, Optional, Tuple

from jarvis_devices import android_crypto as crypto
from jarvis_devices.android_identity import validate_capabilities, validate_display_name
from jarvis_devices.android_protocol import (
    AUTHENTICATED_TYPES,
    BridgeMessage,
    MessageType,
    new_session_id,
)
from jarvis_devices.android_transport import InMemoryAndroidTransport

__all__ = [
    "FakeAndroidDevice",
    "FakeAndroidBridge",
    "RecordingAuditHook",
    "make_bridge_pair",
    "started_pair",
    "complete_pairing",
    "requires_crypto",
]


#: The bridge needs Ed25519. Without the ``cryptography`` package the modules
#: still import (that path is tested separately); these suites skip instead of
#: pretending to have exercised real key material.
requires_crypto = unittest.skipUnless(
    crypto.crypto_available(),
    "Android bridge tests need the 'cryptography' package (Ed25519).",
)


class RecordingAuditHook:
    """Collects the safe lifecycle events the bridge emits."""

    def __init__(self) -> None:
        self.events: List[Tuple[str, Dict[str, Any]]] = []

    def __call__(self, event: str, fields: Dict[str, Any]) -> None:
        self.events.append((event, dict(fields)))

    @property
    def names(self) -> List[str]:
        return [event for event, _ in self.events]

    def fields_for(self, event: str) -> List[Dict[str, Any]]:
        return [fields for name, fields in self.events if name == event]

    def raw_text(self) -> str:
        return repr(self.events)


class FakeAndroidDevice:
    """A simulated Android companion that speaks the real bridge protocol."""

    def __init__(
        self,
        transport: InMemoryAndroidTransport,
        *,
        display_name: str = "Pixel 8",
        capabilities: Tuple[str, ...] = ("bridge.protocol", "device.status"),
        private_key: Optional[bytes] = None,
        public_key: Optional[bytes] = None,
        clock: Any = None,
    ) -> None:
        #: Shares the bridge's clock in tests: a frame timestamped with real
        #: time would look centuries old to a bridge running on a fake one.
        self.clock = clock
        self.transport = transport
        self.display_name = validate_display_name(display_name)
        self.capabilities = validate_capabilities(capabilities)
        if private_key is not None and public_key is not None:
            self.private_key, self.public_key = private_key, public_key
        else:
            self.private_key, self.public_key = crypto.generate_keypair()
        self.device_id = crypto.device_id_from_public_key(self.public_key)
        self.sequence = 0
        self.session_id = ""
        self.received: List[BridgeMessage] = []
        #: Every frame this phone has sent, for assertions.
        self.sent: List[BridgeMessage] = []
        #: Test knobs.
        self.answer_heartbeats = True
        self.answer_connects = True
        self.heartbeat_delay = 0.0
        self.challenge: bytes = b""
        self.pairing_code = ""
        self.pairing_id = ""
        #: When set, the phone signs the pairing attestation over these bytes
        #: instead of the real ones (used to prove a forged proof is refused).
        self.attestation_override: Optional[bytes] = None
        self.code_override: Optional[str] = None

    # ------------------------------------------------------------------
    def _next_sequence(self) -> int:
        self.sequence += 1
        return self.sequence

    def _now(self):
        """Timestamp for outbound frames, using the test clock when there is one."""
        return self.clock() if self.clock is not None else None

    async def send(self, message: BridgeMessage) -> BridgeMessage:
        signed = message.sign(self.private_key)
        await self.transport.send(signed.to_bytes())
        self.sent.append(signed)
        return signed

    async def receive(self, timeout: float = 0.3) -> Optional[BridgeMessage]:
        raw = await self.transport.receive(timeout)
        if raw is None:
            return None
        message = BridgeMessage.parse(raw)
        self.received.append(message)
        return message

    # ------------------------------------------------------------------
    # Pairing (device initiated, as the real companion would)
    # ------------------------------------------------------------------
    async def request_pairing(self) -> BridgeMessage:
        """Step 1: offer our public key, signed with the matching private key."""
        return await self.send(
            BridgeMessage.create(
                MessageType.PAIR_REQUEST,
                self.device_id,
                payload={
                    "public_key": crypto.encode_public_key(self.public_key),
                    "display_name": self.display_name,
                    "capabilities": list(self.capabilities),
                },
                sequence=self._next_sequence(),
                timestamp=self._now(),
            )
        )

    async def read_challenge(self, timeout: float = 0.5) -> BridgeMessage:
        """Step 2: read JARVIS's challenge."""
        message = await self.receive(timeout)
        if message is None or message.message_type is not MessageType.PAIR_CHALLENGE:
            raise AssertionError(f"expected pair_challenge, got {message}")
        self.pairing_id = str(message.payload["pairing_id"])
        self.challenge = bytes.fromhex(str(message.payload["challenge"]))
        self.pairing_code = str(message.payload["pairing_code"])
        return message

    async def answer_challenge(self, *, attest: bool = True) -> BridgeMessage:
        """Step 3: prove we hold the private key over JARVIS's challenge."""
        from jarvis_devices.android_bridge import pairing_attestation_bytes

        attestation = self.attestation_override
        if attestation is None:
            host_fingerprint = str(
                next(
                    message.payload["host_fingerprint"]
                    for message in reversed(self.received)
                    if message.message_type is MessageType.PAIR_CHALLENGE
                )
            )
            attestation = pairing_attestation_bytes(
                self.challenge, self.device_id, host_fingerprint
            )
        payload: Dict[str, Any] = {
            "pairing_id": self.pairing_id,
            "attestation": attestation.hex(),
            "pairing_code": self.code_override if self.code_override is not None else self.pairing_code,
        }
        if not attest:
            payload["attestation"] = "00" * len(attestation)
        return await self.send(
            BridgeMessage.create(
                MessageType.PAIR_RESPONSE,
                self.device_id,
                payload=payload,
                sequence=self._next_sequence(),
                timestamp=self._now(),
            )
        )

    # ------------------------------------------------------------------
    # Serving requests from JARVIS
    # ------------------------------------------------------------------
    async def serve(self, *, max_frames: int = 4, timeout: float = 0.05) -> int:
        """Answer frames from JARVIS. Bounded, so a test can never hang."""
        handled = 0
        while handled < max_frames:
            message = await self.receive(timeout)
            if message is None:
                break
            handled += 1
            await self._reply_to(message)
        return handled

    async def _reply_to(self, message: BridgeMessage) -> None:
        if message.message_type is MessageType.CONNECT:
            if not self.answer_connects:
                return
            self.session_id = message.session_id or new_session_id()
            await self._ack(message, MessageType.ACK, {"protocol_version": 1})
        elif message.message_type is MessageType.HEARTBEAT:
            if not self.answer_heartbeats:
                return
            if self.heartbeat_delay:
                await asyncio.sleep(self.heartbeat_delay)
            await self._ack(message, MessageType.HEARTBEAT_ACK, {"battery": 81})
        elif message.message_type is MessageType.DISCONNECT:
            await self._ack(message, MessageType.ACK, {"ack": True})
        elif message.message_type is MessageType.CAPABILITIES:
            await self._ack(message, MessageType.ACK, {"capabilities": list(self.capabilities)})

    async def _ack(self, request: BridgeMessage, message_type: MessageType, payload: Dict[str, Any]) -> None:
        await self.send(
            BridgeMessage.create(
                message_type,
                self.device_id,
                payload=payload,
                request_id=request.request_id,
                sequence=self._next_sequence(),
                timestamp=self._now(),
                session_id=request.session_id or self.session_id,
            )
        )

    # ------------------------------------------------------------------
    async def push_heartbeat(self) -> BridgeMessage:
        """Device-initiated heartbeat (phones do this on their own schedule)."""
        return await self.send(
            BridgeMessage.create(
                MessageType.HEARTBEAT,
                self.device_id,
                payload={"battery": 80},
                sequence=self._next_sequence(),
                timestamp=self._now(),
                session_id=self.session_id,
            )
        )


class FakeAndroidBridge:
    """A bridge double for tool tests that should not exercise real pairing.

    It records calls and returns canned, honest answers. The *tools* under test
    are the real ones.
    """

    def __init__(self, *, available: bool = True) -> None:
        self.available = available
        self.calls: List[Tuple[str, Tuple[Any, ...], Dict[str, Any]]] = []
        self.devices: List[Dict[str, Any]] = []
        self.pairings: List[Dict[str, Any]] = []
        self.raise_on: Dict[str, Exception] = {}
        self.results: Dict[str, Any] = {}

    def _record(self, name: str, *args: Any, **kwargs: Any) -> None:
        self.calls.append((name, args, kwargs))

    def _maybe_raise(self, name: str) -> None:
        if name in self.raise_on:
            raise self.raise_on[name]

    def unavailable_reason(self) -> str:
        """The tools call this when the bridge reports itself unavailable."""
        return "" if self.available else "The Android bridge is disabled in this test."

    # --- read only -----------------------------------------------------
    def status(self) -> Dict[str, Any]:
        self._record("status")
        return self.results.get("status", {"available": self.available, "devices": len(self.devices)})

    def list_devices(self) -> Tuple[Dict[str, Any], ...]:
        self._record("list_devices")
        return tuple(self.devices)

    def device_status(self, device_id: str) -> Dict[str, Any]:
        self._record("device_status", device_id)
        self._maybe_raise("device_status")
        return self.results.get("device_status", {"device_id": device_id})

    def pending_pairings(self, *, include_finished: bool = False) -> Tuple[Dict[str, Any], ...]:
        self._record("pending_pairings")
        return tuple(self.pairings)

    def capabilities(self, device_id: str) -> Dict[str, Any]:
        self._record("capabilities", device_id)
        self._maybe_raise("capabilities")
        return self.results.get("capabilities", {"device_id": device_id, "supported": []})

    def health(self, device_id: str):
        self._record("health", device_id)
        from jarvis_devices.android_identity import HealthState

        return HealthState(self.results.get("health", "healthy"))

    # --- privileged ----------------------------------------------------
    def approve_pairing(self, pairing_id: str) -> Dict[str, Any]:
        self._record("approve_pairing", pairing_id)
        self._maybe_raise("approve_pairing")
        return self.results.get("approve_pairing", {"pairing_id": pairing_id, "trust_state": "paired"})

    def cancel_pairing(self, pairing_id: str) -> Dict[str, Any]:
        self._record("cancel_pairing", pairing_id)
        self._maybe_raise("cancel_pairing")
        return {"pairing_id": pairing_id, "status": "cancelled"}

    async def unpair(self, device_id: str) -> Dict[str, Any]:
        self._record("unpair", device_id)
        self._maybe_raise("unpair")
        return {"device_id": device_id, "removed": True}

    def revoke(self, device_id: str) -> Dict[str, Any]:
        self._record("revoke", device_id)
        self._maybe_raise("revoke")
        return {"device_id": device_id, "trust_state": "revoked"}

    async def connect(self, device_id: str, **kwargs: Any) -> Dict[str, Any]:
        self._record("connect", device_id, **kwargs)
        self._maybe_raise("connect")
        return {"device_id": device_id, "state": "connected"}

    async def disconnect(self, device_id: str) -> Dict[str, Any]:
        self._record("disconnect", device_id)
        self._maybe_raise("disconnect")
        return {"device_id": device_id, "state": "disconnected"}

    async def heartbeat(self, device_id: str) -> Dict[str, Any]:
        self._record("heartbeat", device_id)
        self._maybe_raise("heartbeat")
        return {"device_id": device_id, "health": "healthy", "answered": True}

    @property
    def call_names(self) -> List[str]:
        return [name for name, _, _ in self.calls]


def make_bridge_pair(
    *,
    display_name: str = "Pixel 8",
    capabilities: Tuple[str, ...] = ("bridge.protocol", "device.status"),
    clock: Any = None,
    **bridge_kwargs: Any,
) -> Tuple[Any, FakeAndroidDevice, InMemoryAndroidTransport, InMemoryAndroidTransport]:
    """Build a real bridge wired to a fake phone over an in-memory transport."""
    from jarvis_devices.android_bridge import AndroidDeviceBridge
    from jarvis_devices.android_identity import AndroidHostIdentity

    pc_side, phone_side = InMemoryAndroidTransport.create_pair()
    phone = FakeAndroidDevice(
        phone_side, display_name=display_name, capabilities=capabilities, clock=clock
    )
    kwargs: Dict[str, Any] = {
        "backoff_base_seconds": 0.0,
        "backoff_cap_seconds": 0.0,
        # Short, but real: timeout paths are still exercised, the suite just
        # does not spend five seconds per unanswered request.
        "request_timeout_seconds": 0.4,
        "host_identity": AndroidHostIdentity.generate("jarvis-pc-test"),
    }
    if clock is not None:
        kwargs["clock"] = clock
    kwargs.update(bridge_kwargs)
    bridge = AndroidDeviceBridge(transport=pc_side, **kwargs)
    return bridge, phone, pc_side, phone_side

async def started_pair(**kwargs: Any):
    """``make_bridge_pair`` with both transport ends already open."""
    bridge, phone, pc_side, phone_side = make_bridge_pair(**kwargs)
    await bridge.open()
    await phone_side.open()
    return bridge, phone, pc_side, phone_side


async def complete_pairing(bridge: Any, phone: FakeAndroidDevice, *, approve: bool = True) -> Dict[str, Any]:
    """Run the whole real handshake and return the pending pairing record."""
    await phone.request_pairing()
    await bridge.pump()
    await phone.read_challenge()
    await phone.answer_challenge()
    await bridge.pump()
    pending = [item for item in bridge.pending_pairings() if item["device_id"] == phone.device_id]
    if not pending:
        raise AssertionError(f"no pending pairing; events so far: {bridge.pending_pairings(include_finished=True)}")
    record = pending[0]
    if approve:
        bridge.approve_pairing(record["pairing_id"])
    return record
