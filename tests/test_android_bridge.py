"""Phase 5 tests: the Android bridge (pairing, trust, connection, heartbeat).

Every test drives the real :class:`AndroidDeviceBridge`. The phone on the other
end is a fake that speaks the real protocol over a real in-memory transport, so
signatures, sequence numbers and replay protection are genuinely exercised -
without a phone, a network, Bluetooth or ADB.
"""

from __future__ import annotations

import asyncio
import unittest
from datetime import timedelta

from jarvis_devices import android_crypto as crypto
from jarvis_devices.android_bridge import (
    DEFAULT_STALE_AFTER_SECONDS,
    SUPPORTED_CAPABILITIES,
    AndroidBridgeUnavailableError,
    AndroidCapabilityUnavailableError,
    AndroidConnectionError,
    AndroidDeviceBridge,
    AndroidDeviceNotPairedError,
    AndroidDeviceRevokedError,
    AndroidDeviceUnknownError,
    AndroidPairingError,
    AndroidPairingExpiredError,
    AndroidPairingUnknownError,
    PairingStatus,
    create_default_android_bridge,
    pairing_attestation_bytes,
)
from jarvis_devices.android_identity import (
    AndroidHostIdentity,
    ConnectionState,
    HealthState,
    TrustState,
)
from jarvis_devices.android_protocol import BridgeMessage, MessageType, ReplayGuard
from jarvis_devices.android_registry import InMemoryAndroidDeviceRegistry
from jarvis_devices.android_transport import (
    AndroidTransportClosedError,
    InMemoryAndroidTransport,
    UnavailableAndroidTransport,
)

try:
    from .android_support import (
        FakeAndroidDevice,
        RecordingAuditHook,
        complete_pairing,
        make_bridge_pair,
        requires_crypto,
        started_pair,
    )
    from .support import FakeClock
except ImportError:
    from android_support import (
        FakeAndroidDevice,
        RecordingAuditHook,
        complete_pairing,
        make_bridge_pair,
        requires_crypto,
        started_pair,
    )
    from support import FakeClock


class BridgeAvailabilityTests(unittest.TestCase):
    """Run with or without the signature library."""

    def test_a_bridge_without_a_host_identity_is_unavailable(self) -> None:
        bridge = AndroidDeviceBridge(host_identity=None)
        if crypto.crypto_available():
            self.assertFalse(bridge.available)
            self.assertIn("host identity", bridge.unavailable_reason())
        with self.assertRaises(AndroidBridgeUnavailableError):
            bridge.require_available()

    def test_a_bridge_without_a_transport_refuses_to_send(self) -> None:
        bridge = create_default_android_bridge()
        self.assertIsInstance(bridge.transport, UnavailableAndroidTransport)
        summary = bridge.status()
        self.assertEqual(summary["transport"]["transport"], "unavailable")
        self.assertEqual(summary["protocol_version"], 1)
        self.assertEqual(summary["devices"], 0)

    def test_the_default_bridge_never_claims_a_phone_is_connected(self) -> None:
        bridge = create_default_android_bridge()
        summary = bridge.status()
        self.assertEqual(summary["connected_devices"], 0)
        self.assertEqual(summary["paired_devices"], 0)
        self.assertEqual(bridge.list_devices(), ())

    def test_the_configuration_is_validated(self) -> None:
        host = AndroidHostIdentity.generate() if crypto.crypto_available() else None
        with self.assertRaises(ValueError):
            AndroidDeviceBridge(host_identity=host, pairing_ttl_seconds=0)
        with self.assertRaises(ValueError):
            AndroidDeviceBridge(host_identity=host, heartbeat_interval_seconds=0)
        with self.assertRaises(ValueError):
            AndroidDeviceBridge(host_identity=host, heartbeat_interval_seconds=60, stale_after_seconds=1)
        with self.assertRaises(ValueError):
            AndroidDeviceBridge(host_identity=host, max_connection_attempts=0)
        with self.assertRaises(ValueError):
            AndroidDeviceBridge(host_identity=host, max_connection_attempts=999)
        with self.assertRaises(ValueError):
            AndroidDeviceBridge(host_identity=host, backoff_base_seconds=-1)

    def test_opening_an_unavailable_transport_fails_honestly(self) -> None:
        bridge = create_default_android_bridge()
        if not bridge.available:
            self.skipTest("bridge unavailable for another reason")
        with self.assertRaises(AndroidBridgeUnavailableError):
            asyncio.run(bridge.open())


@requires_crypto
class PairingTests(unittest.IsolatedAsyncioTestCase):
    async def test_a_successful_pairing(self) -> None:
        bridge, phone, _, _ = await started_pair()
        record = await complete_pairing(bridge, phone)
        self.assertEqual(record["device_id"], phone.device_id)
        self.assertEqual(record["display_name"], "Pixel 8")
        device = bridge.registry.get(phone.device_id)
        self.assertIs(device.trust_state, TrustState.PAIRED)
        self.assertIsNotNone(device.paired_at)

    async def test_nothing_is_trusted_before_the_user_approves(self) -> None:
        bridge, phone, _, _ = await started_pair()
        await complete_pairing(bridge, phone, approve=False)
        self.assertEqual(bridge.list_devices(), ())
        pending = bridge.pending_pairings()[0]
        self.assertEqual(pending["status"], PairingStatus.VERIFIED.value)
        with self.assertRaises(AndroidDeviceUnknownError):
            bridge.device_status(phone.device_id)

    async def test_both_sides_derive_the_same_pairing_code(self) -> None:
        """The code is what a human compares; it must match on both screens."""
        bridge, phone, _, _ = await started_pair()
        record = await complete_pairing(bridge, phone, approve=False)
        self.assertEqual(record["pairing_code"], phone.pairing_code)
        self.assertEqual(len(record["pairing_code"]), 6)

    async def test_a_forged_signature_is_refused(self) -> None:
        bridge, phone, _, _ = await started_pair()
        # Sign the pairing request with a key that does not match the offered one.
        _, foreign_public = crypto.generate_keypair()
        await phone.send(
            BridgeMessage.create(
                MessageType.PAIR_REQUEST,
                crypto.device_id_from_public_key(foreign_public),
                payload={
                    "public_key": crypto.encode_public_key(foreign_public),
                    "display_name": "Impostor",
                    "capabilities": [],
                },
                sequence=1,
            )
        )
        await bridge.pump()
        self.assertEqual(bridge.pending_pairings(), ())
        self.assertEqual(bridge._counters["frames_rejected"], 1)

    async def test_an_invalid_proof_is_refused(self) -> None:
        bridge, phone, _, _ = await started_pair()
        await phone.request_pairing()
        await bridge.pump()
        await phone.read_challenge()
        phone.attestation_override = b"\x00" * 64  # signed over the wrong bytes
        await phone.answer_challenge()
        await bridge.pump()
        self.assertEqual(bridge.pending_pairings()[0]["status"], PairingStatus.AWAITING_RESPONSE.value)
        self.assertEqual(bridge.list_devices(), ())

    async def test_a_mismatched_pairing_code_is_refused(self) -> None:
        bridge, phone, _, _ = await started_pair()
        await phone.request_pairing()
        await bridge.pump()
        await phone.read_challenge()
        phone.code_override = "ZZZZZZ"
        await phone.answer_challenge()
        await bridge.pump()
        record = bridge.pending_pairings(include_finished=True)[0]
        self.assertEqual(record["status"], PairingStatus.REJECTED.value)
        self.assertEqual(record["detail"], "pairing code mismatch")
        with self.assertRaises(AndroidPairingError):
            bridge.approve_pairing(record["pairing_id"])

    async def test_an_unverified_pairing_cannot_be_approved(self) -> None:
        bridge, phone, _, _ = await started_pair()
        await phone.request_pairing()
        await bridge.pump()
        record = bridge.pending_pairings()[0]
        with self.assertRaises(AndroidPairingError):
            bridge.approve_pairing(record["pairing_id"])

    async def test_an_unknown_pairing_id_is_refused(self) -> None:
        bridge, _, _, _ = await started_pair()
        with self.assertRaises(AndroidPairingUnknownError):
            bridge.approve_pairing("pair-" + "0" * 32)
        with self.assertRaises(AndroidPairingUnknownError):
            bridge.cancel_pairing("not-a-pairing-id")

    async def test_a_pairing_cannot_be_approved_twice(self) -> None:
        bridge, phone, _, _ = await started_pair()
        record = await complete_pairing(bridge, phone, approve=False)
        bridge.approve_pairing(record["pairing_id"])
        with self.assertRaises(AndroidPairingError):
            bridge.approve_pairing(record["pairing_id"])
        self.assertEqual(len(bridge.list_devices()), 1)

    async def test_an_expired_pairing_flow_is_refused(self) -> None:
        clock = FakeClock()
        bridge, phone, _, _ = await started_pair(clock=clock, pairing_ttl_seconds=30)
        await phone.request_pairing()
        await bridge.pump()
        clock.advance(timedelta(seconds=31))
        await phone.read_challenge()
        await phone.answer_challenge()
        await bridge.pump()
        with self.assertRaises(AndroidPairingExpiredError):
            bridge.approve_pairing(bridge.pending_pairings(include_finished=True)[0]["pairing_id"])

    async def test_a_pairing_can_be_cancelled(self) -> None:
        bridge, phone, _, _ = await started_pair()
        record = await complete_pairing(bridge, phone, approve=False)
        bridge.cancel_pairing(record["pairing_id"])
        self.assertEqual(bridge.list_devices(), ())
        self.assertEqual(
            [item["status"] for item in bridge.pending_pairings(include_finished=True)],
            [PairingStatus.CANCELLED.value],
        )

    async def test_a_duplicate_pairing_from_an_already_paired_device_is_refused(self) -> None:
        bridge, phone, _, _ = await started_pair()
        await complete_pairing(bridge, phone)
        await phone.request_pairing()
        await bridge.pump()
        self.assertEqual(len(bridge.pending_pairings()), 0)
        self.assertEqual(bridge._counters["frames_rejected"], 1)

    async def test_a_revoked_device_can_never_pair_again(self) -> None:
        bridge, phone, _, _ = await started_pair()
        await complete_pairing(bridge, phone)
        bridge.revoke(phone.device_id)
        await phone.request_pairing()
        await bridge.pump()
        self.assertEqual(bridge.list_devices()[0]["trust_state"], TrustState.REVOKED.value)
        self.assertEqual(bridge.pending_pairings(), ())
        self.assertIs(bridge.registry.get(phone.device_id).trust_state, TrustState.REVOKED)

    async def test_a_malformed_pairing_request_is_refused(self) -> None:
        bridge, phone, _, _ = await started_pair()
        for payload in (
            {"public_key": "not-base64", "display_name": "x", "capabilities": []},
            {"public_key": crypto.encode_public_key(phone.public_key), "display_name": "", "capabilities": []},
            {"public_key": crypto.encode_public_key(phone.public_key), "display_name": "x", "capabilities": "nope"},
            {"public_key": crypto.encode_public_key(phone.public_key), "display_name": "x", "capabilities": ["bad name"]},
        ):
            with self.subTest(payload=str(payload)[:50]):
                await phone.send(
                    BridgeMessage.create(
                        MessageType.PAIR_REQUEST, phone.device_id, payload=payload, sequence=phone.sequence + 1
                    )
                )
                await bridge.pump()
                self.assertEqual(bridge.pending_pairings(), ())

    async def test_a_claimed_id_that_does_not_match_the_key_is_refused(self) -> None:
        bridge, phone, _, _ = await started_pair()
        await phone.send(
            BridgeMessage.create(
                MessageType.PAIR_REQUEST,
                "adev-" + "0" * 32,  # someone else's id, our key
                payload={
                    "public_key": crypto.encode_public_key(phone.public_key),
                    "display_name": "Spoof",
                    "capabilities": [],
                },
                sequence=1,
            )
        )
        await bridge.pump()
        self.assertEqual(bridge.pending_pairings(), ())
        self.assertEqual(bridge.list_devices(), ())

    async def test_the_attestation_binds_challenge_device_and_host(self) -> None:
        _, public_key = crypto.generate_keypair()
        device_id = crypto.device_id_from_public_key(public_key)
        challenge = crypto.new_nonce(32)
        base = pairing_attestation_bytes(challenge, device_id, "AAAA-BBBB")
        self.assertNotEqual(base, pairing_attestation_bytes(crypto.new_nonce(32), device_id, "AAAA-BBBB"))
        self.assertNotEqual(base, pairing_attestation_bytes(challenge, "adev-" + "1" * 32, "AAAA-BBBB"))
        self.assertNotEqual(base, pairing_attestation_bytes(challenge, device_id, "CCCC-DDDD"))
        with self.assertRaises(AndroidPairingError):
            pairing_attestation_bytes(b"", device_id, "AAAA-BBBB")


@requires_crypto
class ConnectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_connect_and_disconnect(self) -> None:
        bridge, phone, _, _ = await started_pair()
        await complete_pairing(bridge, phone)
        result, _ = await asyncio.gather(bridge.connect(phone.device_id), phone.serve(max_frames=2))
        self.assertEqual(result["state"], ConnectionState.CONNECTED.value)
        self.assertEqual(result["attempts"], 1)
        self.assertIs(bridge.connection_state(phone.device_id), ConnectionState.CONNECTED)
        self.assertIs(bridge.registry.get(phone.device_id).trust_state, TrustState.CONNECTED)

        outcome, _ = await asyncio.gather(bridge.disconnect(phone.device_id), phone.serve(max_frames=2))
        self.assertEqual(outcome["state"], ConnectionState.DISCONNECTED.value)
        self.assertIs(bridge.connection_state(phone.device_id), ConnectionState.DISCONNECTED)

    async def test_connecting_twice_does_nothing_the_second_time(self) -> None:
        bridge, phone, _, _ = await started_pair()
        await complete_pairing(bridge, phone)
        await asyncio.gather(bridge.connect(phone.device_id), phone.serve(max_frames=2))
        result = await bridge.connect(phone.device_id)
        self.assertTrue(result["already_connected"])
        self.assertEqual(result["attempts"], 0)

    async def test_retries_are_bounded_and_then_fail(self) -> None:
        bridge, phone, _, _ = await started_pair(max_connection_attempts=3)
        await complete_pairing(bridge, phone)
        phone.answer_connects = False  # the phone never replies
        with self.assertRaises(AndroidConnectionError):
            await bridge.connect(phone.device_id)
        self.assertIs(bridge.connection_state(phone.device_id), ConnectionState.FAILED)
        self.assertEqual(bridge.registry.get(phone.device_id).connection.attempts, 3)
        self.assertGreaterEqual(bridge._counters["connect_attempts"], 3)

    async def test_an_explicit_attempt_count_cannot_exceed_the_ceiling(self) -> None:
        bridge, phone, _, _ = await started_pair(max_connection_attempts=1)
        await complete_pairing(bridge, phone)
        phone.answer_connects = False
        with self.assertRaises(AndroidConnectionError):
            await bridge.connect(phone.device_id, attempts=10_000)
        from jarvis_devices.android_bridge import MAX_CONNECTION_ATTEMPTS_LIMIT

        self.assertLessEqual(
            bridge.registry.get(phone.device_id).connection.attempts, MAX_CONNECTION_ATTEMPTS_LIMIT
        )

    async def test_a_broken_transport_is_reported_not_retried_forever(self) -> None:
        bridge, phone, pc_side, _ = await started_pair(max_connection_attempts=2)
        await complete_pairing(bridge, phone)
        pc_side.break_link()
        with self.assertRaises(AndroidConnectionError):
            await bridge.connect(phone.device_id)
        self.assertIs(bridge.connection_state(phone.device_id), ConnectionState.FAILED)

    async def test_an_unpaired_device_cannot_connect(self) -> None:
        bridge, phone, _, _ = await started_pair()
        with self.assertRaises(AndroidDeviceUnknownError):
            await bridge.connect(phone.device_id)
        await complete_pairing(bridge, phone, approve=False)
        with self.assertRaises(AndroidDeviceUnknownError):
            await bridge.connect(phone.device_id)

    async def test_a_revoked_device_cannot_connect(self) -> None:
        bridge, phone, _, _ = await started_pair()
        await complete_pairing(bridge, phone)
        bridge.revoke(phone.device_id)
        with self.assertRaises(AndroidDeviceRevokedError):
            await bridge.connect(phone.device_id)

    async def test_the_device_can_hang_up(self) -> None:
        bridge, phone, _, _ = await started_pair()
        await complete_pairing(bridge, phone)
        await asyncio.gather(bridge.connect(phone.device_id), phone.serve(max_frames=2))
        await phone.send(
            BridgeMessage.create(
                MessageType.DISCONNECT, phone.device_id, sequence=99, session_id=phone.session_id
            )
        )
        await bridge.pump()
        self.assertIs(bridge.connection_state(phone.device_id), ConnectionState.DISCONNECTED)

    async def test_the_transport_lifecycle_is_explicit(self) -> None:
        bridge, phone, pc_side, phone_side = make_bridge_pair()
        self.assertFalse(pc_side.is_open)
        await bridge.open()
        await phone_side.open()
        self.assertTrue(pc_side.is_open)
        await bridge.open()  # idempotent
        await bridge.close()
        self.assertFalse(pc_side.is_open)


@requires_crypto
class HeartbeatTests(unittest.IsolatedAsyncioTestCase):
    async def connected(self, **kwargs):
        bridge, phone, _, _ = await started_pair(**kwargs)
        await complete_pairing(bridge, phone)
        await asyncio.gather(bridge.connect(phone.device_id), phone.serve(max_frames=2))
        return bridge, phone

    async def test_a_healthy_heartbeat(self) -> None:
        bridge, phone = await self.connected()
        result, _ = await asyncio.gather(bridge.heartbeat(phone.device_id), phone.serve(max_frames=2))
        self.assertTrue(result["answered"])
        self.assertEqual(result["health"], HealthState.HEALTHY.value)

    async def test_a_missing_answer_is_never_reported_as_healthy(self) -> None:
        bridge, phone = await self.connected()
        phone.answer_heartbeats = False
        result = await bridge.heartbeat(phone.device_id)
        self.assertFalse(result["answered"])
        self.assertNotEqual(result["health"], HealthState.HEALTHY.value)
        self.assertEqual(result["error_code"], "android_connection_timeout")

    async def test_health_degrades_to_stale_and_recovers(self) -> None:
        clock = FakeClock()
        bridge, phone, _, _ = await started_pair(
            clock=clock, heartbeat_interval_seconds=10, stale_after_seconds=30
        )
        await complete_pairing(bridge, phone)
        await asyncio.gather(bridge.connect(phone.device_id), phone.serve(max_frames=2))
        self.assertIs(bridge.health(phone.device_id), HealthState.HEALTHY)

        clock.advance(timedelta(seconds=20))
        self.assertIs(bridge.health(phone.device_id), HealthState.REACHABLE)
        clock.advance(timedelta(seconds=20))
        self.assertIs(bridge.health(phone.device_id), HealthState.STALE)

        phone.answer_heartbeats = True
        result, _ = await asyncio.gather(bridge.heartbeat(phone.device_id), phone.serve(max_frames=2))
        self.assertTrue(result["answered"])
        self.assertIs(bridge.health(phone.device_id), HealthState.HEALTHY)

    async def test_a_device_initiated_heartbeat_refreshes_health(self) -> None:
        clock = FakeClock()
        bridge, phone, _, _ = await started_pair(
            clock=clock, heartbeat_interval_seconds=10, stale_after_seconds=30
        )
        await complete_pairing(bridge, phone)
        await asyncio.gather(bridge.connect(phone.device_id), phone.serve(max_frames=2))
        clock.advance(timedelta(seconds=25))
        self.assertIs(bridge.health(phone.device_id), HealthState.REACHABLE)
        await phone.push_heartbeat()
        await bridge.pump()
        self.assertIs(bridge.health(phone.device_id), HealthState.HEALTHY)

    async def test_health_of_a_disconnected_or_revoked_device(self) -> None:
        bridge, phone, _, _ = await started_pair()
        await complete_pairing(bridge, phone)
        self.assertIs(bridge.health(phone.device_id), HealthState.DISCONNECTED)
        await asyncio.gather(bridge.connect(phone.device_id), phone.serve(max_frames=2))
        bridge.revoke(phone.device_id)
        self.assertIs(bridge.health(phone.device_id), HealthState.DISCONNECTED)

    async def test_heartbeat_needs_a_paired_device(self) -> None:
        bridge, phone, _, _ = await started_pair()
        with self.assertRaises(AndroidDeviceUnknownError):
            await bridge.heartbeat(phone.device_id)


@requires_crypto
class CapabilityTests(unittest.IsolatedAsyncioTestCase):
    async def test_capabilities_report_what_the_device_advertised(self) -> None:
        bridge, phone, _, _ = await started_pair()
        await complete_pairing(bridge, phone)
        report = bridge.capabilities(phone.device_id)
        self.assertEqual(report["supported"], list(SUPPORTED_CAPABILITIES))
        self.assertEqual(report["advertised_not_supported"], [])

    async def test_a_future_capability_is_never_reported_as_available(self) -> None:
        bridge, phone, _, _ = await started_pair(capabilities=("bridge.protocol", "system.volume"))
        await complete_pairing(bridge, phone)
        report = bridge.capabilities(phone.device_id)
        self.assertEqual(report["supported"], ["bridge.protocol"])
        self.assertEqual(report["advertised_not_supported"], ["system.volume"])
        self.assertNotIn("system.volume", report["supported"])
        with self.assertRaises(AndroidCapabilityUnavailableError):
            bridge.require_capability(phone.device_id, "system.volume")

    async def test_an_unadvertised_capability_is_refused(self) -> None:
        bridge, phone, _, _ = await started_pair(capabilities=("bridge.protocol",))
        await complete_pairing(bridge, phone)
        with self.assertRaises(AndroidCapabilityUnavailableError):
            bridge.require_capability(phone.device_id, "device.status")

    async def test_the_device_can_update_its_capabilities(self) -> None:
        bridge, phone, _, _ = await started_pair()
        await complete_pairing(bridge, phone)
        await asyncio.gather(bridge.connect(phone.device_id), phone.serve(max_frames=2))
        await phone.send(
            BridgeMessage.create(
                MessageType.CAPABILITIES,
                phone.device_id,
                payload={"capabilities": ["bridge.protocol", "device.status"]},
                sequence=phone.sequence + 1,
                session_id=phone.session_id,
            )
        )
        await bridge.pump()
        self.assertEqual(bridge.capabilities(phone.device_id)["supported"], list(SUPPORTED_CAPABILITIES))

    async def test_junk_capabilities_are_ignored(self) -> None:
        bridge, phone, _, _ = await started_pair()
        await complete_pairing(bridge, phone)
        before = bridge.capabilities(phone.device_id)["supported"]
        await phone.send(
            BridgeMessage.create(
                MessageType.CAPABILITIES,
                phone.device_id,
                payload={"capabilities": ["Bad Name", 42]},
                sequence=phone.sequence + 1,
            )
        )
        await bridge.pump()
        self.assertEqual(bridge.capabilities(phone.device_id)["supported"], before)


@requires_crypto
class FrameHandlingTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.audit = RecordingAuditHook()
        self.bridge, self.phone, _, _ = await started_pair(audit_hook=self.audit)
        await complete_pairing(self.bridge, self.phone)
        await asyncio.gather(
            self.bridge.connect(self.phone.device_id), self.phone.serve(max_frames=2)
        )

    async def test_unknown_message_types_are_dropped(self) -> None:
        raw = b'{"protocol_version": 1, "message_type": "execute_command"}'
        await self.bridge.handle_frame(raw)
        self.assertEqual(self.bridge._counters["frames_rejected"], 1)
        self.assertIn("android_frame_rejected", self.audit.names)

    async def test_malformed_frames_are_dropped(self) -> None:
        for raw in (b"not json", b"{}", b"\xff\xfe", b" " * 70_000):
            with self.subTest(raw=raw[:12]):
                await self.bridge.handle_frame(raw)
        self.assertGreaterEqual(self.bridge._counters["frames_rejected"], 4)

    async def test_a_frame_from_an_unknown_device_is_dropped(self) -> None:
        stranger = FakeAndroidDevice(self.phone.transport)
        await stranger.send(
            BridgeMessage.create(MessageType.HEARTBEAT, stranger.device_id, sequence=1)
        )
        await self.bridge.pump()
        self.assertEqual(self.bridge._counters["frames_rejected"], 1)

    async def test_a_frame_signed_with_the_wrong_key_is_dropped(self) -> None:
        impostor = FakeAndroidDevice(self.phone.transport)
        await impostor.send(
            BridgeMessage.create(MessageType.HEARTBEAT, self.phone.device_id, sequence=50)
        )
        await self.bridge.pump()
        self.assertGreaterEqual(self.bridge._counters["authentication_failures"], 1)

    async def test_a_replayed_frame_is_dropped(self) -> None:
        frame = await self.phone.push_heartbeat()
        await self.bridge.pump()
        before = self.bridge._counters["frames_received"]
        await self.bridge.handle_frame(frame.to_bytes())
        await self.bridge.handle_frame(frame.to_bytes())
        self.assertGreaterEqual(self.bridge._counters["replays_detected"], 1)

    async def test_a_frame_from_an_old_session_is_dropped(self) -> None:
        await self.phone.send(
            BridgeMessage.create(
                MessageType.HEARTBEAT,
                self.phone.device_id,
                sequence=500,
                session_id="sess-stale",
            )
        )
        await self.bridge.pump()
        self.assertGreaterEqual(self.bridge._counters["authentication_failures"], 1)

    async def test_a_revoked_device_cannot_send_anything(self) -> None:
        self.bridge.revoke(self.phone.device_id)
        await self.phone.push_heartbeat()
        await self.bridge.pump()
        self.assertGreaterEqual(self.bridge._counters["authentication_failures"], 1)

    async def test_a_handler_error_never_escapes(self) -> None:
        class Exploding(BridgeMessage):
            pass

        await self.bridge.handle_frame(b"[]")  # a JSON array
        self.assertGreaterEqual(self.bridge._counters["frames_rejected"], 1)

    async def test_the_audit_trail_records_trust_changes_without_secrets(self) -> None:
        self.assertIn("android_device_paired", self.audit.names)
        self.assertIn("android_device_connected", self.audit.names)
        text = self.audit.raw_text()
        self.assertNotIn(self.phone.private_key.hex()[:16], text)
        self.assertNotIn(self.bridge.host_identity.private_key.hex()[:16], text)
        paired = self.audit.fields_for("android_device_paired")[0]
        self.assertEqual(paired["device_id"], self.phone.device_id)
        self.assertEqual(paired["trust_state"], TrustState.PAIRED.value)

    async def test_pump_is_bounded(self) -> None:
        for _ in range(10):
            await self.phone.push_heartbeat()
        handled = await self.bridge.pump(max_frames=4)
        self.assertEqual(handled, 4)
        with self.assertRaises(ValueError):
            await self.bridge.pump(timeout=0)


@requires_crypto
class CorrelationTests(unittest.IsolatedAsyncioTestCase):
    async def test_a_response_from_the_wrong_device_is_ignored(self) -> None:
        """An impostor on the same link cannot answer a request meant for us."""
        bridge, phone, _, phone_side = await started_pair(max_connection_attempts=1)
        await complete_pairing(bridge, phone)
        impostor = FakeAndroidDevice(phone_side, display_name="Impostor")

        async def impostor_answers():
            message = await impostor.receive(0.3)  # the CONNECT meant for the phone
            self.assertIsNotNone(message)
            await impostor.send(
                BridgeMessage.create(
                    MessageType.ACK,
                    impostor.device_id,  # its own identity, not the phone's
                    request_id=message.request_id,
                    sequence=1,
                    session_id=message.session_id,
                )
            )

        # Run the impostor first and to completion: gather() would cancel it the
        # moment connect() raises, and nothing would ever be rejected.
        impostor_task = asyncio.create_task(impostor_answers())
        with self.assertRaises(AndroidConnectionError):
            await bridge.connect(phone.device_id)
        await impostor_task
        self.assertGreaterEqual(bridge._counters["frames_rejected"], 1)
        self.assertIsNot(bridge.connection_state(phone.device_id), ConnectionState.CONNECTED)

    async def test_a_response_of_the_wrong_type_is_ignored(self) -> None:
        bridge, phone, _, _ = await started_pair(max_connection_attempts=1)
        await complete_pairing(bridge, phone)

        async def wrong_type():
            message = await phone.receive(0.2)
            if message is not None:
                await phone.send(
                    BridgeMessage.create(
                        MessageType.HEARTBEAT_ACK,  # not an ACK
                        phone.device_id,
                        request_id=message.request_id,
                        sequence=phone.sequence + 1,
                        session_id=message.session_id,
                    )
                )

        with self.assertRaises(AndroidConnectionError):
            await asyncio.gather(bridge.connect(phone.device_id), wrong_type())

    async def test_a_duplicate_response_cannot_resolve_twice(self) -> None:
        bridge, phone, _, _ = await started_pair()
        await complete_pairing(bridge, phone)

        async def duplicate():
            message = await phone.receive(0.2)
            if message is not None:
                for _ in range(2):
                    await phone.send(
                        BridgeMessage.create(
                            MessageType.ACK,
                            phone.device_id,
                            request_id=message.request_id,
                            sequence=phone.sequence + 1,
                            session_id=message.session_id,
                        )
                    )

        result, _ = await asyncio.gather(bridge.connect(phone.device_id), duplicate())
        self.assertEqual(result["state"], ConnectionState.CONNECTED.value)
        self.assertEqual(bridge._requests, {})


@requires_crypto
class UnpairRevokeTests(unittest.IsolatedAsyncioTestCase):
    async def test_unpair_forgets_the_device(self) -> None:
        bridge, phone, _, _ = await started_pair()
        await complete_pairing(bridge, phone)
        await asyncio.gather(bridge.connect(phone.device_id), phone.serve(max_frames=2))
        result = await bridge.unpair(phone.device_id)
        self.assertTrue(result["removed"])
        self.assertEqual(bridge.list_devices(), ())
        with self.assertRaises(AndroidDeviceUnknownError):
            bridge.device_status(phone.device_id)

    async def test_unpair_of_an_unknown_device_is_refused(self) -> None:
        bridge, _, _, _ = await started_pair()
        with self.assertRaises(AndroidDeviceUnknownError):
            await bridge.unpair("adev-" + "0" * 32)

    async def test_revoke_keeps_the_record_and_blocks_everything(self) -> None:
        bridge, phone, _, _ = await started_pair()
        await complete_pairing(bridge, phone)
        device = bridge.revoke(phone.device_id)
        self.assertEqual(device["trust_state"], TrustState.REVOKED.value)
        self.assertEqual(len(bridge.list_devices()), 1)
        async def try_connect():
            await bridge.connect(phone.device_id)

        async def try_heartbeat():
            await bridge.heartbeat(phone.device_id)

        async def try_unpair():
            await bridge.unpair(phone.device_id)

        for call in (try_connect, try_heartbeat, try_unpair):
            with self.subTest(call=call.__name__):
                with self.assertRaises(AndroidDeviceRevokedError):
                    await call()

    async def test_a_new_device_can_still_pair_after_one_is_revoked(self) -> None:
        bridge, phone, _, phone_side = await started_pair()
        await complete_pairing(bridge, phone)
        bridge.revoke(phone.device_id)
        other = FakeAndroidDevice(phone_side, display_name="Pixel 9")
        await complete_pairing(bridge, other)
        states = {item["device_id"]: item["trust_state"] for item in bridge.list_devices()}
        self.assertEqual(states[phone.device_id], TrustState.REVOKED.value)
        self.assertEqual(states[other.device_id], TrustState.PAIRED.value)


@requires_crypto
class StatusTests(unittest.IsolatedAsyncioTestCase):
    async def test_status_is_complete_and_secret_free(self) -> None:
        bridge, phone, _, _ = await started_pair()
        await complete_pairing(bridge, phone)
        status = bridge.status()
        for key in (
            "available",
            "protocol_version",
            "transport",
            "host",
            "devices",
            "paired_devices",
            "connected_devices",
            "pending_pairings",
            "capabilities_understood",
            "timing",
            "replay_guard",
            "counters",
        ):
            self.assertIn(key, status)
        text = repr(status)
        self.assertNotIn(phone.private_key.hex()[:16], text)
        self.assertNotIn(bridge.host_identity.private_key.hex()[:16], text)
        self.assertNotIn("private_key", text)

    async def test_device_status_includes_health_and_capability_split(self) -> None:
        bridge, phone, _, _ = await started_pair(capabilities=("bridge.protocol", "system.volume"))
        await complete_pairing(bridge, phone)
        payload = bridge.device_status(phone.device_id)
        self.assertEqual(payload["health"], HealthState.DISCONNECTED.value)
        self.assertEqual(payload["capabilities_understood"], ["bridge.protocol"])
        self.assertEqual(payload["capabilities_advertised_not_supported"], ["system.volume"])

    async def test_an_unknown_device_status_is_refused(self) -> None:
        bridge, _, _, _ = await started_pair()
        for bad in ("adev-" + "0" * 32, "192.168.1.50", "", "adev-nothex"):
            with self.subTest(bad=bad):
                with self.assertRaises((AndroidDeviceUnknownError,)):
                    bridge.device_status(bad)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
