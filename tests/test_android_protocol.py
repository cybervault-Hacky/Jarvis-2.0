"""Phase 5 tests: the versioned bridge protocol and replay protection."""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timedelta, timezone

from jarvis_devices import android_crypto as crypto
from jarvis_devices.android_protocol import (
    AUTHENTICATED_TYPES,
    MAX_MESSAGE_BYTES,
    MAX_PAYLOAD_BYTES,
    MAX_PAYLOAD_DEPTH,
    MAX_PAYLOAD_KEYS,
    MESSAGE_TYPES,
    PRE_PAIRING_TYPES,
    PROTOCOL_VERSION,
    RESPONSE_FOR,
    AndroidProtocolError,
    BridgeMessage,
    InvalidMessageError,
    MessageAuthenticationError,
    MessageType,
    OversizedMessageError,
    ReplayDetectedError,
    ReplayGuard,
    UnknownMessageTypeError,
    UnsupportedProtocolVersionError,
    new_session_id,
    validate_payload,
)

try:
    from .android_support import requires_crypto
except ImportError:
    from android_support import requires_crypto


class Device:
    """One stable device identity, so a test can sign many frames as it."""

    def __init__(self) -> None:
        self.private_key, self.public_key = crypto.generate_keypair()
        self.device_id = crypto.device_id_from_public_key(self.public_key)

    def frame(
        self,
        message_type: MessageType = MessageType.HEARTBEAT,
        *,
        payload=None,
        sequence: int = 1,
        timestamp=None,
        nonce: str = "",
        session_id: str = "",
    ) -> BridgeMessage:
        return BridgeMessage.create(
            message_type,
            self.device_id,
            payload=payload,
            sequence=sequence,
            timestamp=timestamp,
            nonce=nonce,
            session_id=session_id,
        ).sign(self.private_key)


def make_signed(
    message_type: MessageType = MessageType.HEARTBEAT,
    *,
    payload=None,
    sequence: int = 1,
    timestamp=None,
    nonce: str = "",
    session_id: str = "",
):
    """Build a genuinely signed frame and return ``(message, id, pub, priv)``."""
    device = Device()
    message = device.frame(
        message_type,
        payload=payload,
        sequence=sequence,
        timestamp=timestamp,
        nonce=nonce,
        session_id=session_id,
    )
    return message, device.device_id, device.public_key, device.private_key


class MessageTypeAllowlistTests(unittest.TestCase):
    """These run without the signature library: the allowlist is data."""

    def test_the_allowlist_is_explicit_and_bounded(self) -> None:
        self.assertEqual(MESSAGE_TYPES, frozenset(member.value for member in MessageType))
        # 13 Phase 5 frames + 20 Phase 6 frames + 10 Phase 7 call frames.
        # The bound exists so the set stays enumerable and reviewable.
        self.assertLessEqual(len(MESSAGE_TYPES), 56)

    def test_no_command_shaped_message_type_exists(self) -> None:
        for name in MESSAGE_TYPES:
            with self.subTest(message_type=name):
                for forbidden in ("exec", "shell", "command", "cmd", "adb", "raw", "socket", "eval"):
                    self.assertNotIn(forbidden, name)

    def test_pre_pairing_and_authenticated_types_are_disjoint_and_complete(self) -> None:
        self.assertEqual(PRE_PAIRING_TYPES | AUTHENTICATED_TYPES, MESSAGE_TYPES)
        self.assertEqual(PRE_PAIRING_TYPES & AUTHENTICATED_TYPES, frozenset())
        self.assertEqual(PRE_PAIRING_TYPES, frozenset(MessageType(value) .value for value in (
            "hello", "pair_request", "pair_challenge", "pair_response", "pair_result"
        )))

    def test_every_request_type_has_a_declared_response(self) -> None:
        for request, response in RESPONSE_FOR.items():
            with self.subTest(request=request):
                self.assertIn(request, MESSAGE_TYPES)
                self.assertIn(response, MESSAGE_TYPES)

    def test_validate_payload_rejects_non_json_values(self) -> None:
        for bad in ({"b": b"\x00"}, {"f": len}, {"n": float("nan")}, {"n": float("inf")}, [1, 2], "text", 42):
            with self.subTest(bad=bad):
                with self.assertRaises((InvalidMessageError, OversizedMessageError)):
                    validate_payload(bad)

    def test_validate_payload_accepts_json_values(self) -> None:
        self.assertEqual(validate_payload(None), {})
        self.assertEqual(validate_payload({"a": 1, "b": "x", "c": True, "d": None}), {"a": 1, "b": "x", "c": True, "d": None})
        self.assertEqual(validate_payload({"a": {"b": [1, "x"]}}), {"a": {"b": [1, "x"]}})

    def test_validate_payload_enforces_its_limits(self) -> None:
        with self.assertRaises(InvalidMessageError):
            validate_payload({"a": {"b": {"c": {"d": {"e": {"f": {"g": 1}}}}}}})
        with self.assertRaises(InvalidMessageError):
            validate_payload({f"k{i}": 1 for i in range(MAX_PAYLOAD_KEYS + 1)})
        with self.assertRaises(InvalidMessageError):
            validate_payload({"__class__": 1})
        with self.assertRaises(InvalidMessageError):
            validate_payload({1: "x"})
        with self.assertRaises(OversizedMessageError):
            validate_payload({"k": "x" * (MAX_PAYLOAD_BYTES + 1)})
        self.assertEqual(MAX_PAYLOAD_DEPTH, 6)


@requires_crypto
class FrameTests(unittest.TestCase):
    def test_a_signed_frame_survives_the_wire(self) -> None:
        message, _, public_key, _ = make_signed(payload={"battery": 82})
        restored = BridgeMessage.parse(message.to_bytes())
        self.assertTrue(restored.verify(public_key))
        self.assertEqual(restored.payload, {"battery": 82})
        self.assertEqual(restored.message_type, MessageType.HEARTBEAT)
        self.assertEqual(restored.protocol_version, PROTOCOL_VERSION)

    def test_frames_are_json_not_pickled_objects(self) -> None:
        message, _, _, _ = make_signed()
        parsed = json.loads(message.to_bytes())
        self.assertIsInstance(parsed, dict)
        self.assertEqual(
            set(parsed),
            {
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
            },
        )

    def test_describe_and_repr_never_expose_values_or_signatures(self) -> None:
        message, _, _, _ = make_signed(payload={"secret_value": "hunter2"})
        self.assertEqual(message.describe()["payload_keys"], ["secret_value"])
        self.assertNotIn("hunter2", repr(message.describe()))
        self.assertNotIn("hunter2", repr(message))
        self.assertNotIn(message.signature, repr(message))

    def test_every_field_is_covered_by_the_signature(self) -> None:
        message, _, public_key, _ = make_signed()
        body = json.loads(message.to_bytes())
        tampering = {
            "payload": {"battery": 1},
            "sequence": 2,
            "device_id": "adev-" + "1" * 32,
            "message_type": MessageType.ACK.value,
            "request_id": "req-" + "2" * 32,
            "session_id": "sess-forged",
            "nonce": "3" * 32,
        }
        # protocol_version has no second valid value to swap in (that case is
        # covered by FrameRejectionTests), so assert it is signed over instead.
        self.assertIn("protocol_version", message.signed_body())
        for field, value in tampering.items():
            forged_body = dict(body)
            forged_body[field] = value
            with self.subTest(field=field):
                try:
                    forged = BridgeMessage.parse(json.dumps(forged_body).encode())
                except AndroidProtocolError:
                    continue  # refused outright - also a pass
                self.assertFalse(forged.verify(public_key), f"{field} is not signed")

    def test_a_signature_from_another_key_does_not_verify(self) -> None:
        message, _, public_key, other_private = make_signed()
        _, _, _, foreign_private = make_signed()
        cross = message.sign(foreign_private)
        self.assertFalse(cross.verify(public_key))
        self.assertTrue(message.verify(public_key))
        self.assertIsNotNone(other_private)

    def test_an_unsigned_frame_never_verifies(self) -> None:
        message, _, public_key, _ = make_signed()
        unsigned = BridgeMessage(**{**message.signed_body(), "message_type": message.message_type, "signature": ""})
        self.assertFalse(unsigned.verify(public_key))
        with self.assertRaises(MessageAuthenticationError):
            unsigned.require_verified(public_key)


@requires_crypto
class FrameRejectionTests(unittest.TestCase):
    def body(self):
        message, _, _, _ = make_signed()
        return json.loads(message.to_bytes())

    def parse(self, **overrides):
        body = self.body()
        body.update(overrides)
        return BridgeMessage.parse(json.dumps(body).encode())

    def test_unknown_message_types_are_refused(self) -> None:
        for value in ("execute_command", "adb", "shell", "raw_send", "", "HEARTBEAT"):
            with self.subTest(value=value):
                with self.assertRaises(UnknownMessageTypeError):
                    self.parse(message_type=value)

    def test_protocol_versions_are_checked(self) -> None:
        for version in (0, -1, PROTOCOL_VERSION + 1, 99):
            with self.subTest(version=version):
                with self.assertRaises(UnsupportedProtocolVersionError):
                    self.parse(protocol_version=version)
        for version in ("1", True, 1.0, None):
            with self.subTest(version=version):
                with self.assertRaises(InvalidMessageError):
                    self.parse(protocol_version=version)

    def test_identifiers_are_validated(self) -> None:
        with self.assertRaises(InvalidMessageError):
            self.parse(device_id="192.168.1.50")
        with self.assertRaises(InvalidMessageError):
            self.parse(device_id="adev-" + "g" * 32)
        with self.assertRaises(InvalidMessageError):
            self.parse(request_id="req-short")
        with self.assertRaises(InvalidMessageError):
            self.parse(request_id="req-" + "z" * 32)
        with self.assertRaises(InvalidMessageError):
            self.parse(nonce="xyz")
        with self.assertRaises(InvalidMessageError):
            self.parse(sequence=0)
        with self.assertRaises(InvalidMessageError):
            self.parse(sequence=-5)
        with self.assertRaises(InvalidMessageError):
            self.parse(sequence=True)
        with self.assertRaises(InvalidMessageError):
            self.parse(session_id="x" * 200)
        with self.assertRaises(InvalidMessageError):
            self.parse(timestamp="not-a-time")
        with self.assertRaises(InvalidMessageError):
            self.parse(signature="")

    def test_unexpected_and_missing_fields_are_refused(self) -> None:
        with self.assertRaises(InvalidMessageError):
            self.parse(evil="x")
        body = self.body()
        del body["nonce"]
        with self.assertRaises(InvalidMessageError):
            BridgeMessage.parse(json.dumps(body).encode())

    def test_malformed_frames_are_refused(self) -> None:
        for raw in (b"{not json", b"[1,2,3]", b'"a string"', b"42", b"", b"\xff\xfe\x00bad"):
            with self.subTest(raw=raw):
                with self.assertRaises(InvalidMessageError):
                    BridgeMessage.parse(raw)

    def test_a_pickled_object_is_not_deserialised(self) -> None:
        import pickle

        class Evil:
            def __reduce__(self):
                return (print, ("pwned",))

        with self.assertRaises(InvalidMessageError):
            BridgeMessage.parse(pickle.dumps(Evil()))

    def test_oversized_frames_are_refused(self) -> None:
        with self.assertRaises(OversizedMessageError):
            BridgeMessage.parse(b" " * (MAX_MESSAGE_BYTES + 1))
        with self.assertRaises(OversizedMessageError):
            BridgeMessage.parse(" " * (MAX_MESSAGE_BYTES + 1))

    def test_an_oversized_payload_is_refused_before_it_can_be_sent(self) -> None:
        with self.assertRaises(OversizedMessageError):
            BridgeMessage.create(MessageType.HEARTBEAT, "adev-" + "0" * 32, payload={"blob": "x" * (MAX_PAYLOAD_BYTES + 10)})
        # A list of too many items is refused for the same reason.
        with self.assertRaises(InvalidMessageError):
            BridgeMessage.create(MessageType.HEARTBEAT, "adev-" + "0" * 32, payload={"items": list(range(MAX_PAYLOAD_KEYS + 1))})


@requires_crypto
class ReplayGuardTests(unittest.TestCase):
    def test_the_first_frame_is_accepted_once(self) -> None:
        guard = ReplayGuard()
        message, device_id, _, _ = make_signed()
        guard.check(message)
        self.assertEqual(guard.last_sequence(device_id), 1)
        with self.assertRaises(ReplayDetectedError):
            guard.check(message)
        self.assertEqual(guard.last_sequence(device_id), 1)

    def test_sequences_must_increase(self) -> None:
        guard = ReplayGuard()
        device = Device()
        guard.check(device.frame(sequence=5))
        self.assertEqual(guard.last_sequence(device.device_id), 5)
        for older in (1, 4, 5):
            with self.subTest(sequence=older):
                with self.assertRaises(ReplayDetectedError):
                    guard.check(device.frame(sequence=older))
        guard.check(device.frame(sequence=6))
        self.assertEqual(guard.last_sequence(device.device_id), 6)

    def test_a_rejected_frame_does_not_advance_the_sequence(self) -> None:
        """Otherwise one bad frame could lock the real device out forever."""
        guard = ReplayGuard()
        device = Device()
        guard.check(device.frame(sequence=1))
        stale = device.frame(
            sequence=99, timestamp=datetime.now(timezone.utc) - timedelta(hours=2)
        )
        with self.assertRaises(ReplayDetectedError):
            guard.check(stale)
        self.assertEqual(guard.last_sequence(device.device_id), 1)
        guard.check(device.frame(sequence=2))
        self.assertEqual(guard.last_sequence(device.device_id), 2)

    def test_timestamps_are_windowed(self) -> None:
        guard = ReplayGuard(tolerance_seconds=60)
        old, _, _, _ = make_signed(timestamp=datetime.now(timezone.utc) - timedelta(seconds=600))
        with self.assertRaises(ReplayDetectedError):
            guard.check(old)
        future, _, _, _ = make_signed(timestamp=datetime.now(timezone.utc) + timedelta(seconds=600))
        with self.assertRaises(ReplayDetectedError):
            guard.check(future)

    def test_a_reused_nonce_is_refused_even_with_a_newer_sequence(self) -> None:
        guard = ReplayGuard()
        first, device_id, _, private = make_signed(sequence=1)
        guard.check(first)
        replayed = BridgeMessage.create(
            MessageType.HEARTBEAT, device_id, sequence=2, nonce=first.nonce
        ).sign(private)
        with self.assertRaises(ReplayDetectedError):
            guard.check(replayed)

    def test_the_nonce_cache_is_bounded(self) -> None:
        guard = ReplayGuard(max_nonces=16)
        _, device_id, _, private = make_signed()
        for sequence in range(1, 60):
            guard.check(
                BridgeMessage.create(MessageType.HEARTBEAT, device_id, sequence=sequence).sign(private)
            )
        self.assertLessEqual(guard.stats()["nonces_cached"], 16)

    def test_sequences_are_tracked_per_device(self) -> None:
        guard = ReplayGuard()
        first, first_id, _, _ = make_signed(sequence=10)
        second, second_id, _, _ = make_signed(sequence=1)
        guard.check(first)
        guard.check(second)  # a different device may start at 1
        self.assertEqual(guard.last_sequence(first_id), 10)
        self.assertEqual(guard.last_sequence(second_id), 1)

    def test_forget_and_remember(self) -> None:
        guard = ReplayGuard()
        _, device_id, _, _ = make_signed()
        guard.remember_device(device_id, 100)
        self.assertEqual(guard.last_sequence(device_id), 100)
        guard.remember_device(device_id, 5)  # never moves backwards
        self.assertEqual(guard.last_sequence(device_id), 100)
        guard.forget_device(device_id)
        self.assertEqual(guard.last_sequence(device_id), 0)
        self.assertEqual(guard.stats()["devices_tracked"], 0)

    def test_the_guard_configuration_is_validated(self) -> None:
        with self.assertRaises(ValueError):
            ReplayGuard(tolerance_seconds=0)
        with self.assertRaises(ValueError):
            ReplayGuard(max_nonces=1)


@requires_crypto
class CorrelationTests(unittest.TestCase):
    def test_request_ids_are_unique(self) -> None:
        ids = {crypto.new_request_id() for _ in range(500)}
        self.assertEqual(len(ids), 500)
        self.assertTrue(all(item.startswith("req-") for item in ids))

    def test_session_ids_are_unique(self) -> None:
        ids = {new_session_id() for _ in range(500)}
        self.assertEqual(len(ids), 500)
        self.assertTrue(all(item.startswith("sess-") for item in ids))

    def test_a_request_id_is_not_treated_as_authentication(self) -> None:
        """Guessing a request id must not make a forged frame verify."""
        message, _, public_key, _ = make_signed()
        _, _, _, attacker_private = make_signed()
        forged = BridgeMessage.create(
            MessageType.ACK,
            message.device_id,
            request_id=message.request_id,
            sequence=message.sequence,
            session_id=message.session_id,
        ).sign(attacker_private)
        self.assertFalse(forged.verify(public_key))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
