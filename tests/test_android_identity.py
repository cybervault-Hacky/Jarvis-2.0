"""Phase 5 tests: cryptographic primitives and device identity."""

from __future__ import annotations

import unittest
from datetime import timedelta

from jarvis_devices import android_crypto as crypto
from jarvis_devices.android_identity import (
    AndroidDeviceIdentity,
    AndroidHostIdentity,
    AndroidIdentityError,
    ConnectionState,
    ConnectionInfo,
    DuplicateDeviceError,
    HealthState,
    IllegalTrustTransitionError,
    InvalidDeviceIdentityError,
    RevokedDeviceError,
    TrustState,
    UnknownDeviceError,
    is_valid_device_id,
    validate_capabilities,
    validate_device_id,
    validate_display_name,
    MAX_CAPABILITIES,
    MAX_CAPABILITIES as _MAX_CAPS,
    MAX_DISPLAY_NAME_LENGTH,
)

try:  # imported as part of the ``tests`` package (pytest / discover -t .)
    from .android_support import requires_crypto
except ImportError:  # ``python -m unittest discover -s tests``
    from android_support import requires_crypto


class CryptoAvailabilityTests(unittest.TestCase):
    """These run with or without the signature library - both paths matter."""

    def test_availability_is_reported_honestly(self) -> None:
        available = crypto.crypto_available()
        reason = crypto.crypto_unavailable_reason()
        if available:
            self.assertEqual(reason, "")
        else:
            self.assertIn("cryptography", reason)

    def test_verification_never_raises_on_junk(self) -> None:
        for public_key, message, signature in (
            (b"", b"", b""),
            (b"x" * 32, b"m", b"s" * 64),
            (None, None, None),
            ("string", "string", "string"),
            (b"x" * 32, b"m", b"short"),
        ):
            with self.subTest(key=public_key, signature=signature):
                self.assertIs(crypto.verify(public_key, message, signature), False)

    def test_keypair_generation_fails_cleanly_without_the_library(self) -> None:
        if crypto.crypto_available():
            self.skipTest("cryptography is installed; the failure path is not reachable")
        with self.assertRaises(crypto.AndroidCryptoUnavailableError):
            crypto.generate_keypair()


@requires_crypto
class KeyTests(unittest.TestCase):
    def test_keypair_and_signature_roundtrip(self) -> None:
        private_key, public_key = crypto.generate_keypair()
        self.assertEqual(len(public_key), crypto.PUBLIC_KEY_BYTES)
        signature = crypto.sign(private_key, b"challenge")
        self.assertEqual(len(signature), crypto.SIGNATURE_BYTES)
        self.assertTrue(crypto.verify(public_key, b"challenge", signature))

    def test_a_signature_binds_to_the_exact_message(self) -> None:
        private_key, public_key = crypto.generate_keypair()
        signature = crypto.sign(private_key, b"challenge-1")
        self.assertFalse(crypto.verify(public_key, b"challenge-2", signature))
        self.assertFalse(crypto.verify(public_key, b"", signature))

    def test_a_signature_does_not_verify_under_another_key(self) -> None:
        private_key, public_key = crypto.generate_keypair()
        signature = crypto.sign(private_key, b"challenge")
        _, other_public_key = crypto.generate_keypair()
        self.assertFalse(crypto.verify(other_public_key, b"challenge", signature))

    def test_two_keypairs_are_different(self) -> None:
        self.assertNotEqual(crypto.generate_keypair()[1], crypto.generate_keypair()[1])

    def test_public_key_encoding_roundtrips(self) -> None:
        _, public_key = crypto.generate_keypair()
        self.assertEqual(crypto.decode_public_key(crypto.encode_public_key(public_key)), public_key)

    def test_malformed_public_keys_are_refused(self) -> None:
        for bad in (b"", b"short", "not bytes", None, b"x" * 31):
            with self.subTest(bad=bad):
                with self.assertRaises(crypto.AndroidCryptoError):
                    crypto.device_id_from_public_key(bad)
                with self.assertRaises(crypto.AndroidCryptoError):
                    crypto.fingerprint(bad)

    def test_encoded_key_of_the_wrong_length_is_refused(self) -> None:
        with self.assertRaises(crypto.AndroidCryptoError):
            crypto.decode_public_key(crypto.encode_public_key(b"x" * 32) + "AA")
        with self.assertRaises(crypto.AndroidCryptoError):
            crypto.decode_public_key("!!! not base64 !!!")

    def test_nonces_are_random(self) -> None:
        self.assertNotEqual(crypto.new_nonce(), crypto.new_nonce())
        self.assertEqual(len(crypto.new_nonce(16)), 16)
        with self.assertRaises(crypto.AndroidCryptoError):
            crypto.new_nonce(0)

    def test_mac_is_deterministic_and_key_dependent(self) -> None:
        self.assertEqual(crypto.mac(b"k", b"m"), crypto.mac(b"k", b"m"))
        self.assertNotEqual(crypto.mac(b"k", b"m"), crypto.mac(b"k2", b"m"))
        with self.assertRaises(crypto.AndroidCryptoError):
            crypto.mac(b"", b"m")

    def test_constant_time_comparison(self) -> None:
        self.assertTrue(crypto.constant_time_equals(b"abc", b"abc"))
        self.assertFalse(crypto.constant_time_equals(b"abc", b"abd"))
        self.assertFalse(crypto.constant_time_equals(b"abc", "abc"))

    def test_pairing_code_is_stable_for_one_key_and_challenge(self) -> None:
        _, public_key = crypto.generate_keypair()
        _, other_key = crypto.generate_keypair()
        challenge = crypto.new_nonce(32)
        self.assertEqual(
            crypto.pairing_code(public_key, challenge), crypto.pairing_code(public_key, challenge)
        )
        self.assertNotEqual(
            crypto.pairing_code(public_key, challenge), crypto.pairing_code(other_key, challenge)
        )
        self.assertNotEqual(
            crypto.pairing_code(public_key, challenge),
            crypto.pairing_code(public_key, crypto.new_nonce(32)),
        )
        with self.assertRaises(crypto.AndroidCryptoError):
            crypto.pairing_code(public_key, b"")


@requires_crypto
class DeviceIdTests(unittest.TestCase):
    def test_the_id_is_derived_from_the_public_key(self) -> None:
        _, public_key = crypto.generate_keypair()
        device_id = crypto.device_id_from_public_key(public_key)
        self.assertTrue(is_valid_device_id(device_id))
        self.assertEqual(device_id, crypto.device_id_from_public_key(public_key))

    def test_the_id_is_not_a_network_property(self) -> None:
        """A new key means a new id; nothing about the network can change it."""
        _, first = crypto.generate_keypair()
        _, second = crypto.generate_keypair()
        self.assertNotEqual(
            crypto.device_id_from_public_key(first), crypto.device_id_from_public_key(second)
        )
        for bad in ("192.168.1.50", "pixel-8.lan", "AA:BB:CC:DD:EE:FF", "adev-SHORT", "", None, 42):
            with self.subTest(bad=bad):
                self.assertFalse(is_valid_device_id(bad))

    def test_fingerprint_is_human_shaped_and_key_bound(self) -> None:
        _, public_key = crypto.generate_keypair()
        fingerprint = crypto.fingerprint(public_key)
        self.assertEqual(len(fingerprint), 39)  # 8 groups of 4 plus separators
        self.assertEqual(fingerprint.count("-"), 7)
        self.assertEqual(fingerprint, crypto.fingerprint(public_key))

    def test_malformed_ids_are_refused(self) -> None:
        for bad in ("adev-" + "0" * 31, "adev-" + "g" * 32, "dev-" + "0" * 32, ""):
            with self.subTest(bad=bad):
                with self.assertRaises(InvalidDeviceIdentityError):
                    validate_device_id(bad)


@requires_crypto
class IdentityTests(unittest.TestCase):
    def make(self, name: str = "Pixel 8", **kwargs):
        _, public_key = crypto.generate_keypair()
        return AndroidDeviceIdentity(
            device_id=crypto.device_id_from_public_key(public_key),
            public_key=public_key,
            display_name=name,
            **kwargs,
        )

    def test_a_forged_identity_is_refused(self) -> None:
        """Claiming someone else's id with your own key must not work."""
        _, public_key = crypto.generate_keypair()
        with self.assertRaises(InvalidDeviceIdentityError):
            AndroidDeviceIdentity(
                device_id="adev-" + "0" * 32, public_key=public_key, display_name="Evil"
            )

    def test_malformed_keys_are_refused(self) -> None:
        for bad in (b"", b"short", None, "string", b"x" * 31):
            with self.subTest(bad=bad):
                with self.assertRaises(InvalidDeviceIdentityError):
                    AndroidDeviceIdentity(
                        device_id="adev-" + "0" * 32, public_key=bad, display_name="x"
                    )

    def test_display_names_are_sanitised(self) -> None:
        self.assertEqual(validate_display_name("  Pixel   8\nPro  "), "Pixel 8 Pro")
        # An escape sequence must not survive: it would forge a log line.
        cleaned = validate_display_name("Evil\x1b[31m\r\nfake-log-line")
        self.assertNotIn("\x1b", cleaned)
        self.assertNotIn("\n", cleaned)
        self.assertNotIn("\r", cleaned)
        self.assertEqual(len(validate_display_name("x" * 500)), MAX_DISPLAY_NAME_LENGTH)
        for bad in ("", "   ", "\n\n", None, 42):
            with self.subTest(bad=bad):
                with self.assertRaises(InvalidDeviceIdentityError):
                    validate_display_name(bad)

    def test_capabilities_are_validated(self) -> None:
        self.assertEqual(
            validate_capabilities(["bridge.protocol", "device.status", "bridge.protocol"]),
            ("bridge.protocol", "device.status"),
        )
        for bad in ("not.a.list", ["Bad Name"], ["a" * 70], ["../etc/passwd"], [1], ["system;rm"]):
            with self.subTest(bad=bad):
                with self.assertRaises(InvalidDeviceIdentityError):
                    validate_capabilities(bad)
        with self.assertRaises(InvalidDeviceIdentityError):
            validate_capabilities([f"cap{i}" for i in range(_MAX_CAPS + 1)])

    def test_the_safe_view_never_contains_private_material(self) -> None:
        device = self.make()
        safe = device.to_safe_dict()
        self.assertNotIn("public_key", safe)
        self.assertIn("fingerprint", safe)
        self.assertIn("public_key", device.to_safe_dict(include_key=True))
        self.assertNotIn("private", repr(safe).lower())

    def test_registry_records_roundtrip(self) -> None:
        device = self.make("Tab S9", capabilities=("bridge.protocol",))
        device.transition_to(TrustState.PAIRING)
        device.transition_to(TrustState.PAIRED)
        restored = AndroidDeviceIdentity.from_registry_record(device.to_registry_record())
        self.assertEqual(restored.device_id, device.device_id)
        self.assertEqual(restored.public_key, device.public_key)
        self.assertEqual(restored.display_name, device.display_name)
        self.assertEqual(restored.capabilities, device.capabilities)
        self.assertIs(restored.trust_state, TrustState.PAIRED)
        self.assertIsNotNone(restored.paired_at)


@requires_crypto
class TrustStateTests(unittest.TestCase):
    def make(self):
        _, public_key = crypto.generate_keypair()
        return AndroidDeviceIdentity(
            device_id=crypto.device_id_from_public_key(public_key),
            public_key=public_key,
            display_name="Pixel",
        )

    def test_the_happy_path(self) -> None:
        device = self.make()
        self.assertIs(device.trust_state, TrustState.UNKNOWN)
        self.assertFalse(device.privileged)
        device.transition_to(TrustState.PAIRING)
        self.assertFalse(device.privileged)
        device.transition_to(TrustState.PAIRED)
        self.assertTrue(device.privileged)
        self.assertIsNotNone(device.paired_at)
        device.transition_to(TrustState.CONNECTED)
        self.assertTrue(device.privileged)
        device.transition_to(TrustState.DISCONNECTED)
        self.assertTrue(device.privileged)
        device.transition_to(TrustState.CONNECTED)
        self.assertIs(device.trust_state, TrustState.CONNECTED)

    def test_illegal_transitions_are_refused(self) -> None:
        device = self.make()
        for target in (TrustState.PAIRED, TrustState.CONNECTED, TrustState.DISCONNECTED):
            with self.subTest(target=target.value):
                with self.assertRaises(IllegalTrustTransitionError):
                    device.transition_to(target)

    def test_revocation_is_terminal(self) -> None:
        device = self.make()
        device.transition_to(TrustState.PAIRING)
        device.transition_to(TrustState.PAIRED)
        device.revoke()
        self.assertIs(device.trust_state, TrustState.REVOKED)
        self.assertIsNotNone(device.revoked_at)
        self.assertFalse(device.privileged)
        self.assertIs(device.connection.state, ConnectionState.DISCONNECTED)
        for target in TrustState:
            with self.subTest(target=target.value):
                if target is TrustState.REVOKED:
                    continue
                with self.assertRaises(IllegalTrustTransitionError):
                    device.transition_to(target)

    def test_a_revoked_device_cannot_be_acted_on(self) -> None:
        device = self.make()
        device.transition_to(TrustState.PAIRING)
        device.transition_to(TrustState.PAIRED)
        device.revoke()
        with self.assertRaises(RevokedDeviceError):
            device.require_privileged()

    def test_an_unpaired_device_cannot_be_acted_on(self) -> None:
        device = self.make()
        with self.assertRaises(InvalidDeviceIdentityError):
            device.require_privileged()

    def test_heartbeat_age(self) -> None:
        device = self.make()
        self.assertIsNone(device.age_since_heartbeat())
        device.record_heartbeat()
        self.assertIsNotNone(device.age_since_heartbeat())
        self.assertLess(device.age_since_heartbeat(), timedelta(seconds=5))


@requires_crypto
class HostIdentityTests(unittest.TestCase):
    def test_the_host_can_sign_and_never_leaks_its_key(self) -> None:
        host = AndroidHostIdentity.generate("jarvis-pc")
        signature = host.sign(b"hello")
        self.assertTrue(crypto.verify(host.public_key, b"hello", signature))
        safe = host.to_safe_dict()
        self.assertNotIn("private_key", safe)
        self.assertIn("public_key", safe)
        self.assertIn("fingerprint", safe)
        self.assertNotIn(host.private_key.hex(), repr(host))
        self.assertNotIn(host.private_key.hex(), repr(safe))

    def test_two_hosts_have_different_fingerprints(self) -> None:
        self.assertNotEqual(
            AndroidHostIdentity.generate().fingerprint, AndroidHostIdentity.generate().fingerprint
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
