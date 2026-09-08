"""Phase 5 tests: the paired-device registry."""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from jarvis_devices import android_crypto as crypto
from jarvis_devices.android_identity import (
    AndroidDeviceIdentity,
    ConnectionState,
    ConnectionInfo,
    InvalidDeviceIdentityError,
    TrustState,
    UnknownDeviceError,
)
from jarvis_devices.android_registry import (
    DEFAULT_MAX_DEVICES,
    REGISTRY_SCHEMA_VERSION,
    DuplicateDeviceError,
    InMemoryAndroidDeviceRegistry,
    JsonAndroidDeviceRegistry,
)

try:
    from .android_support import requires_crypto
except ImportError:
    from android_support import requires_crypto


def make_device(display_name: str = "Pixel 8", capabilities=()) -> AndroidDeviceIdentity:
    _, public_key = crypto.generate_keypair()
    return AndroidDeviceIdentity(
        device_id=crypto.device_id_from_public_key(public_key),
        public_key=public_key,
        display_name=display_name,
        capabilities=tuple(capabilities),
    )


@requires_crypto
class InMemoryRegistryTests(unittest.TestCase):
    def test_register_get_list(self) -> None:
        registry = InMemoryAndroidDeviceRegistry()
        device = make_device()
        registry.register(device)
        self.assertIs(registry.get(device.device_id), device)
        self.assertEqual(registry.device_ids(), (device.device_id,))
        self.assertEqual(registry.list_devices(), (device,))
        self.assertEqual(len(registry), 1)

    def test_a_duplicate_registration_is_refused(self) -> None:
        registry = InMemoryAndroidDeviceRegistry()
        device = make_device()
        registry.register(device)
        with self.assertRaises(DuplicateDeviceError):
            registry.register(device)
        registry.register(device, override=True)
        self.assertEqual(len(registry), 1)

    def test_only_real_identities_can_be_registered(self) -> None:
        registry = InMemoryAndroidDeviceRegistry()
        with self.assertRaises(InvalidDeviceIdentityError):
            registry.register({"device_id": "adev-" + "0" * 32})  # type: ignore[arg-type]

    def test_the_registry_is_bounded(self) -> None:
        registry = InMemoryAndroidDeviceRegistry(max_devices=2)
        registry.register(make_device("one"))
        registry.register(make_device("two"))
        with self.assertRaises(InvalidDeviceIdentityError):
            registry.register(make_device("three"))
        with self.assertRaises(ValueError):
            InMemoryAndroidDeviceRegistry(max_devices=0)

    def test_lookup_of_an_unknown_or_malformed_id(self) -> None:
        registry = InMemoryAndroidDeviceRegistry()
        self.assertIsNone(registry.find("adev-" + "0" * 32))
        self.assertIsNone(registry.find("192.168.1.50"))
        self.assertIsNone(registry.find(""))
        with self.assertRaises(UnknownDeviceError):
            registry.get("adev-" + "0" * 32)

    def test_update_validates_every_change(self) -> None:
        registry = InMemoryAndroidDeviceRegistry()
        device = registry.register(make_device("Pixel"))
        registry.update(
            device.device_id,
            display_name="Pixel 8 Pro",
            capabilities=("bridge.protocol",),
            trust_state=TrustState.PAIRING,
            connection=ConnectionInfo(state=ConnectionState.CONNECTING, attempts=1),
        )
        updated = registry.get(device.device_id)
        self.assertEqual(updated.display_name, "Pixel 8 Pro")
        self.assertEqual(updated.capabilities, ("bridge.protocol",))
        self.assertIs(updated.trust_state, TrustState.PAIRING)
        self.assertIs(updated.connection.state, ConnectionState.CONNECTING)

        with self.assertRaises(InvalidDeviceIdentityError):
            registry.update(device.device_id, secret="x")
        with self.assertRaises(InvalidDeviceIdentityError):
            registry.update(device.device_id)
        with self.assertRaises(InvalidDeviceIdentityError):
            registry.update(device.device_id, trust_state="paired")
        with self.assertRaises(InvalidDeviceIdentityError):
            registry.update(device.device_id, connection={"state": "connected"})

    def test_update_cannot_resurrect_a_revoked_device(self) -> None:
        registry = InMemoryAndroidDeviceRegistry()
        device = registry.register(make_device())
        device.transition_to(TrustState.PAIRING)
        device.transition_to(TrustState.PAIRED)
        registry.revoke(device.device_id)
        from jarvis_devices.android_identity import IllegalTrustTransitionError

        with self.assertRaises(IllegalTrustTransitionError):
            registry.update(device.device_id, trust_state=TrustState.PAIRED)

    def test_revoke_keeps_the_device_known_but_inert(self) -> None:
        registry = InMemoryAndroidDeviceRegistry()
        device = registry.register(make_device())
        device.transition_to(TrustState.PAIRING)
        device.transition_to(TrustState.PAIRED)
        registry.revoke(device.device_id)
        self.assertIs(registry.get(device.device_id).trust_state, TrustState.REVOKED)
        self.assertEqual(len(registry.list_devices()), 1)
        self.assertEqual(len(registry.list_devices(include_revoked=False)), 0)
        self.assertEqual(registry.privileged_devices(), ())
        with self.assertRaises(DuplicateDeviceError):
            registry.register(device)

    def test_remove(self) -> None:
        registry = InMemoryAndroidDeviceRegistry()
        device = registry.register(make_device())
        self.assertTrue(registry.remove(device.device_id))
        self.assertFalse(registry.remove(device.device_id))
        self.assertEqual(len(registry), 0)

    def test_filtering_by_trust_state(self) -> None:
        registry = InMemoryAndroidDeviceRegistry()
        paired = registry.register(make_device("paired"))
        paired.transition_to(TrustState.PAIRING)
        paired.transition_to(TrustState.PAIRED)
        registry.register(make_device("unknown"))
        self.assertEqual(len(registry.list_devices(trust_state=TrustState.PAIRED)), 1)
        self.assertEqual(len(registry.list_devices(trust_state=TrustState.UNKNOWN)), 1)
        self.assertEqual(registry.count(), 2)

    def test_describe_is_safe(self) -> None:
        registry = InMemoryAndroidDeviceRegistry()
        registry.register(make_device())
        summary = registry.describe()
        self.assertEqual(summary["devices"], 1)
        self.assertEqual(summary["max_devices"], DEFAULT_MAX_DEVICES)
        self.assertNotIn("public_key", repr(summary))


@requires_crypto
class JsonRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.mkdtemp()
        self.path = os.path.join(self.directory, "android.json")

    def test_it_persists_public_material_only(self) -> None:
        registry = JsonAndroidDeviceRegistry(self.path)
        device = registry.register(make_device("Pixel 8", ("bridge.protocol",)))
        device.transition_to(TrustState.PAIRING)
        device.transition_to(TrustState.PAIRED)

        with open(self.path, encoding="utf-8") as handle:
            raw = json.load(handle)
        self.assertEqual(raw["schema_version"], REGISTRY_SCHEMA_VERSION)
        self.assertEqual(len(raw["devices"]), 1)
        record = raw["devices"][0]
        self.assertIn("public_key", record)
        for key in record:
            self.assertNotIn("private", key.lower())
        with open(self.path, encoding="utf-8") as handle:
            self.assertNotIn("private_key", handle.read())
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)

    def test_it_reloads_what_it_wrote(self) -> None:
        registry = JsonAndroidDeviceRegistry(self.path)
        device = registry.register(make_device("Pixel 8"))
        registry.revoke(device.device_id)
        reloaded = JsonAndroidDeviceRegistry(self.path)
        self.assertEqual(reloaded.device_ids(), registry.device_ids())
        self.assertIs(reloaded.get(device.device_id).trust_state, TrustState.REVOKED)

    def test_a_missing_file_is_fine(self) -> None:
        registry = JsonAndroidDeviceRegistry(os.path.join(self.directory, "nope.json"))
        self.assertEqual(len(registry), 0)

    def test_a_wrong_schema_is_refused(self) -> None:
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump({"schema_version": 99, "devices": []}, handle)
        with self.assertRaises(InvalidDeviceIdentityError):
            JsonAndroidDeviceRegistry(self.path)

    def test_a_file_that_is_not_json_is_refused(self) -> None:
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write("not json at all")
        with self.assertRaises(InvalidDeviceIdentityError):
            JsonAndroidDeviceRegistry(self.path)

    def test_smuggled_private_key_material_is_refused(self) -> None:
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "schema_version": REGISTRY_SCHEMA_VERSION,
                    "devices": [
                        {"device_id": "adev-" + "0" * 32, "private_key": "AA==", "public_key": "AA=="}
                    ],
                },
                handle,
            )
        with self.assertRaises(InvalidDeviceIdentityError):
            JsonAndroidDeviceRegistry(self.path)

    def test_one_bad_record_does_not_poison_the_registry(self) -> None:
        good = make_device("Good")
        registry = JsonAndroidDeviceRegistry(self.path)
        registry.register(good)
        with open(self.path, encoding="utf-8") as handle:
            raw = json.load(handle)
        raw["devices"].append({"device_id": "adev-not-valid", "public_key": "!!"})
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(raw, handle)
        reloaded = JsonAndroidDeviceRegistry(self.path)
        self.assertEqual(reloaded.device_ids(), (good.device_id,))

    def test_a_path_is_required(self) -> None:
        with self.assertRaises(ValueError):
            JsonAndroidDeviceRegistry("")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
