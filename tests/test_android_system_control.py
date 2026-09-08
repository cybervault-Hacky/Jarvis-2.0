"""Phase 6 tests: the Android system-control orchestrator over the real bridge.

Every test drives the real :class:`AndroidSystemControl` and
:class:`AndroidDeviceBridge`. The phone on the other end is a fake that speaks
the real Phase 6 protocol, so signatures, sequences, sessions and replay
protection are genuinely exercised.
"""

from __future__ import annotations

import asyncio
import unittest

from jarvis_devices import android_crypto as crypto
from jarvis_devices.android_bridge import (
    AndroidBridgeError,
    AndroidCapabilityUnavailableError,
    AndroidDeviceNotConnectedError,
    AndroidDeviceNotPairedError,
    AndroidDeviceRevokedError,
    AndroidDeviceUnknownError,
)
from jarvis_devices.android_identity import ConnectionState, HealthState, TrustState
from jarvis_devices.android_protocol import BridgeMessage, MessageType
from jarvis_devices.android_system import (
    AndroidBluetoothUnavailableError,
    AndroidBrightnessUnavailableError,
    AndroidSystemFailedError,
    AndroidSystemInvalidArgumentError,
    AndroidSystemPermissionDeniedError,
    AndroidSystemTimeoutError,
    AndroidSystemUnsupportedError,
    AndroidSystemUnavailableError,
    AndroidVolumeUnavailableError,
    AndroidWifiUnavailableError,
    unwrap_response,
)

try:
    from .android_support import FakeAndroidDevice, complete_pairing, requires_crypto
    from .android_system_support import (
        DEFAULT_SYSTEM_CAPABILITIES,
        FakeAndroidSystemController,
        SystemCapablePhone,
        answered,
        system_phone_pair,
    )
except ImportError:
    from android_support import FakeAndroidDevice, complete_pairing, requires_crypto
    from android_system_support import (
        DEFAULT_SYSTEM_CAPABILITIES,
        FakeAndroidSystemController,
        SystemCapablePhone,
        answered,
        system_phone_pair,
    )


class EnvelopeTests(unittest.TestCase):
    """The response envelope, without needing the signature library."""

    def test_a_successful_envelope_returns_its_fields(self) -> None:
        self.assertEqual(
            unwrap_response({"ok": True, "volume": 40, "muted": False}, operation="get volume"),
            {"volume": 40, "muted": False},
        )

    def test_a_failure_envelope_raises_with_a_structured_code(self) -> None:
        cases = (
            ("permission_denied", AndroidSystemPermissionDeniedError),
            ("unsupported", AndroidSystemUnsupportedError),
            ("unavailable", AndroidSystemUnavailableError),
            ("invalid_argument", AndroidSystemInvalidArgumentError),
            ("failed", AndroidSystemFailedError),
            ("volume_unavailable", AndroidVolumeUnavailableError),
            ("brightness_unavailable", AndroidBrightnessUnavailableError),
            ("wifi_unavailable", AndroidWifiUnavailableError),
            ("bluetooth_unavailable", AndroidBluetoothUnavailableError),
        )
        for reason, expected in cases:
            with self.subTest(reason=reason):
                with self.assertRaises(expected):
                    unwrap_response({"ok": False, "error": reason}, operation="x")

    def test_an_invented_error_reason_collapses_to_a_generic_failure(self) -> None:
        with self.assertRaises(AndroidSystemFailedError):
            unwrap_response({"ok": False, "error": "rm -rf /", "detail": "x" * 500}, operation="x")

    def test_a_missing_or_non_boolean_ok_is_refused(self) -> None:
        for payload in ({}, {"ok": "yes"}, {"ok": 1}, {"ok": None}, "not a dict"):
            with self.subTest(payload=str(payload)[:24]):
                with self.assertRaises(AndroidSystemFailedError):
                    unwrap_response(payload, operation="x")


@requires_crypto
class HappyPathTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.bridge, self.phone, self.control, _, _ = await system_phone_pair()
        self.did = self.phone.device_id

    async def test_status_reports_only_what_the_phone_sent(self) -> None:
        payload = await answered(self.control.status(self.did), self.phone)
        self.assertTrue(payload["connected"])
        self.assertEqual(payload["volume"], 40)
        self.assertEqual(payload["brightness"], 60)
        self.assertTrue(payload["wifi_enabled"])
        self.assertFalse(payload["bluetooth_enabled"])
        self.assertEqual(payload["health"], HealthState.HEALTHY.value)
        self.assertIn("volume", payload["reported"])

    async def test_status_omits_what_the_phone_does_not_support(self) -> None:
        bridge, phone, control, _, _ = await system_phone_pair(
            capabilities=("bridge.protocol", "system.volume")
        )
        payload = await answered(control.status(phone.device_id), phone)
        self.assertIn("volume", payload)
        self.assertNotIn("brightness", payload)
        self.assertNotIn("wifi_enabled", payload)
        self.assertNotIn("bluetooth_enabled", payload)
        self.assertEqual(payload["reported"], ["muted", "volume"])

    async def test_volume_round_trip(self) -> None:
        before = await answered(self.control.get_volume(self.did), self.phone)
        self.assertEqual(before["volume"], 40)
        after = await answered(self.control.set_volume(self.did, 75), self.phone)
        self.assertEqual(after["volume"], 75)
        self.assertEqual(self.phone.controller.volume, 75)

    async def test_setting_the_same_volume_twice_is_idempotent(self) -> None:
        await answered(self.control.set_volume(self.did, 33), self.phone)
        await answered(self.control.set_volume(self.did, 33), self.phone)
        self.assertEqual(self.phone.controller.volume, 33)

    async def test_mute_and_unmute_are_explicit_states_not_toggles(self) -> None:
        await answered(self.control.mute(self.did), self.phone)
        await answered(self.control.mute(self.did), self.phone)
        self.assertTrue(self.phone.controller.muted)
        await answered(self.control.unmute(self.did), self.phone)
        await answered(self.control.unmute(self.did), self.phone)
        self.assertFalse(self.phone.controller.muted)

    async def test_brightness_round_trip_and_adaptive_is_left_alone(self) -> None:
        self.phone.controller.adaptive = True
        payload = await answered(self.control.set_brightness(self.did, 15), self.phone)
        self.assertEqual(payload["brightness"], 15)
        self.assertEqual(self.phone.controller.brightness, 15)
        # The phone was in adaptive mode and must still be.
        self.assertTrue(self.phone.controller.adaptive)
        self.assertTrue(payload["adaptive"])

    async def test_wifi_and_bluetooth_set_desired_state(self) -> None:
        await answered(self.control.set_wifi_enabled(self.did, False), self.phone)
        await answered(self.control.set_wifi_enabled(self.did, False), self.phone)
        self.assertFalse(self.phone.controller.wifi_enabled)
        await answered(self.control.set_bluetooth_enabled(self.did, True), self.phone)
        await answered(self.control.set_bluetooth_enabled(self.did, True), self.phone)
        self.assertTrue(self.phone.controller.bluetooth_enabled)
        status = await answered(self.control.get_wifi_status(self.did), self.phone)
        self.assertFalse(status["enabled"])

    async def test_the_phone_records_exactly_the_operations_it_was_asked_for(self) -> None:
        await answered(self.control.set_volume(self.did, 10), self.phone)
        await answered(self.control.get_bluetooth_status(self.did), self.phone)
        self.assertIn(("set_volume", (10,)), self.phone.controller.calls)
        self.assertIn(("get_bluetooth_status", ()), self.phone.controller.calls)

    async def test_every_operation_travels_through_the_bridge(self) -> None:
        before = self.bridge._counters["frames_sent"]
        for coro in (
            self.control.get_volume(self.did),
            self.control.get_brightness(self.did),
            self.control.get_wifi_status(self.did),
            self.control.get_bluetooth_status(self.did),
        ):
            await answered(coro, self.phone)
        self.assertEqual(self.bridge._counters["frames_sent"], before + 4)


@requires_crypto
class DeviceRefusalTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.bridge, self.phone, self.control, _, _ = await system_phone_pair()
        self.did = self.phone.device_id

    async def test_a_denied_operation_is_reported_as_denied(self) -> None:
        self.phone.controller.denied.add("set_wifi_enabled")
        with self.assertRaises(AndroidSystemPermissionDeniedError):
            await answered(self.control.set_wifi_enabled(self.did, True), self.phone)
        self.assertTrue(self.phone.controller.wifi_enabled)  # unchanged

    async def test_an_unavailable_operation_is_reported_as_unavailable(self) -> None:
        self.phone.controller.unavailable.add("set_volume")
        with self.assertRaises(AndroidSystemUnavailableError):
            await answered(self.control.set_volume(self.did, 50), self.phone)
        self.assertEqual(self.phone.controller.volume, 40)

    async def test_a_failing_operation_is_reported_as_failed(self) -> None:
        self.phone.controller.failing.add("set_brightness")
        with self.assertRaises(AndroidSystemFailedError):
            await answered(self.control.set_brightness(self.did, 50), self.phone)
        self.assertEqual(self.phone.controller.brightness, 60)

    async def test_a_phone_that_never_answers_times_out_and_never_claims_success(self) -> None:
        self.phone.silent = True
        for coro in (
            self.control.get_volume(self.did),
            self.control.set_volume(self.did, 50),
            self.control.mute(self.did),
            self.control.set_wifi_enabled(self.did, False),
        ):
            with self.subTest(coro=coro):
                with self.assertRaises(AndroidSystemTimeoutError):
                    await answered(coro, self.phone)

    async def test_a_timed_out_state_change_is_not_retried(self) -> None:
        """An ambiguous result must not be silently sent again."""
        self.phone.silent = True
        sent_before = self.bridge._counters["frames_sent"]
        with self.assertRaises(AndroidSystemTimeoutError):
            await answered(self.control.set_volume(self.did, 90), self.phone)
        # Exactly one frame went out: the timeout was not turned into a retry.
        self.assertEqual(self.bridge._counters["frames_sent"] - sent_before, 1)
        self.assertEqual(self.phone.controller.calls.count(("set_volume", (90,))), 0)

    async def test_a_malformed_response_is_refused(self) -> None:
        for payload in (
            {"volume": 40},                       # no ok
            {"ok": True},                          # no volume
            {"ok": True, "volume": "loud"},        # wrong type
            {"ok": True, "volume": 200},           # out of range
            {"ok": True, "volume": 50, "muted": "yes"},
            {"ok": "true", "volume": 50},
        ):
            with self.subTest(payload=str(payload)[:36]):
                self.phone.override_response = payload
                with self.assertRaises(AndroidSystemFailedError):
                    await answered(self.control.get_volume(self.did), self.phone)
                self.phone.override_response = None

    async def test_an_unsupported_capability_is_refused_before_anything_is_sent(self) -> None:
        bridge, phone, control, _, _ = await system_phone_pair(
            capabilities=("bridge.protocol", "system.volume")
        )
        sent_before = bridge._counters["frames_sent"]
        for coro in (
            control.get_brightness(phone.device_id),
            control.get_wifi_status(phone.device_id),
            control.get_bluetooth_status(phone.device_id),
            control.set_brightness(phone.device_id, 50),
        ):
            with self.subTest(coro=coro):
                with self.assertRaises(AndroidCapabilityUnavailableError):
                    await answered(coro, phone)
        # Refused locally: nothing was ever put on the wire.
        self.assertEqual(bridge._counters["frames_sent"], sent_before)


@requires_crypto
class TargetingTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.bridge, self.phone, self.control, _, _ = await system_phone_pair()
        self.did = self.phone.device_id

    async def test_an_unknown_device_is_refused(self) -> None:
        with self.assertRaises(AndroidDeviceUnknownError):
            await self.control.get_volume("adev-" + "0" * 32)

    async def test_an_invalid_device_id_is_refused(self) -> None:
        for bad in ("192.168.1.50", "pixel.lan:5555", "AA:BB:CC:DD:EE:FF", "adb shell", "", "x" * 500):
            with self.subTest(bad=bad[:20]):
                with self.assertRaises(AndroidDeviceUnknownError):
                    await self.control.get_volume(bad)

    async def test_a_device_that_was_never_paired_is_refused(self) -> None:
        bridge, phone, control, _, _ = await system_phone_pair(paired_and_connected=False)
        self.assertEqual(bridge.list_devices(), ())
        with self.assertRaises(AndroidDeviceUnknownError):
            await control.get_volume(phone.device_id)

    async def test_a_verified_pairing_still_grants_nothing_until_the_user_approves(self) -> None:
        """The handshake can complete, but the registry stays empty without a yes."""
        bridge, phone, control, _, _ = await system_phone_pair(paired_and_connected=False)
        record = await complete_pairing(bridge, phone, approve=False)
        self.assertEqual(record["status"], "verified")
        self.assertEqual(bridge.list_devices(), ())
        with self.assertRaises(AndroidDeviceUnknownError):
            await control.get_volume(phone.device_id)

    async def test_a_paired_but_never_connected_device_is_refused(self) -> None:
        """Registered and trusted, but with no live session to send over."""
        bridge, phone, control, _, _ = await system_phone_pair(paired_and_connected=False)
        record = await complete_pairing(bridge, phone, approve=False)
        bridge.approve_pairing(record["pairing_id"])
        self.assertIs(
            bridge.registry.get(phone.device_id).trust_state, TrustState.PAIRED
        )
        with self.assertRaises(AndroidDeviceNotConnectedError):
            await control.get_volume(phone.device_id)

    async def test_a_revoked_device_is_refused(self) -> None:
        self.bridge.revoke(self.did)
        for coro in (
            self.control.get_volume(self.did),
            self.control.set_volume(self.did, 50),
            self.control.set_wifi_enabled(self.did, False),
            self.control.status(self.did),
        ):
            with self.subTest(coro=coro):
                with self.assertRaises(AndroidDeviceRevokedError):
                    await coro

    async def test_a_disconnected_device_is_refused_immediately(self) -> None:
        await answered(self.bridge.disconnect(self.did), self.phone)
        self.assertIs(self.bridge.connection_state(self.did), ConnectionState.DISCONNECTED)
        with self.assertRaises(AndroidDeviceNotConnectedError):
            await self.control.get_volume(self.did)
        # Refused locally, so no timeout was burned.
        self.assertEqual(self.phone.controller.calls, [])

    async def test_a_broken_transport_is_reported_as_a_failure_not_a_success(self) -> None:
        self.bridge.transport.break_link()
        with self.assertRaises(AndroidBridgeError) as ctx:
            await self.control.get_volume(self.did)
        self.assertIsNotNone(ctx.exception.error_code)
        self.assertEqual(self.phone.controller.volume, 40)


@requires_crypto
class HostileFrameTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.bridge, self.phone, self.control, _, self.phone_side = await system_phone_pair()
        self.did = self.phone.device_id

    async def test_a_response_from_the_wrong_device_is_ignored(self) -> None:
        impostor = SystemCapablePhone(self.phone_side, display_name="Impostor")
        impostor.trust_host(self.bridge.host_identity.public_key)

        async def impostor_answers():
            message = await impostor.receive(0.3)
            self.assertIsNotNone(message)
            await impostor.send(
                BridgeMessage.create(
                    MessageType.VOLUME_GET_RESPONSE,
                    impostor.device_id,
                    payload={"ok": True, "volume": 99, "muted": False},
                    request_id=message.request_id,
                    sequence=1,
                    session_id=message.session_id,
                    timestamp=impostor._now(),
                )
            )

        task = asyncio.create_task(impostor_answers())
        with self.assertRaises(AndroidSystemTimeoutError):
            await self.control.get_volume(self.did)
        await task
        self.assertGreaterEqual(self.bridge._counters["frames_rejected"], 1)
        self.assertEqual(self.phone.controller.volume, 40)

    async def test_a_response_signed_with_the_wrong_key_is_ignored(self) -> None:
        impostor = SystemCapablePhone(self.phone_side, display_name="Impostor")
        impostor.trust_host(self.bridge.host_identity.public_key)

        async def impostor_answers():
            message = await impostor.receive(0.3)
            self.assertIsNotNone(message)
            frame = BridgeMessage.create(
                MessageType.VOLUME_GET_RESPONSE,
                self.did,  # claims to be the real phone
                payload={"ok": True, "volume": 99, "muted": False},
                request_id=message.request_id,
                sequence=900,
                session_id=message.session_id,
                timestamp=impostor._now(),
            ).sign(impostor.private_key)  # but signed by the impostor's key
            await impostor.transport.send(frame.to_bytes())

        task = asyncio.create_task(impostor_answers())
        with self.assertRaises(AndroidSystemTimeoutError):
            await self.control.get_volume(self.did)
        await task
        self.assertGreaterEqual(self.bridge._counters["authentication_failures"], 1)

    async def test_a_replayed_response_is_ignored(self) -> None:
        captured = []

        class Recording(SystemCapablePhone):
            async def _ack(self, request, message_type, payload):
                frame = BridgeMessage.create(
                    message_type,
                    self.device_id,
                    payload=payload,
                    request_id=request.request_id,
                    sequence=self._next_sequence(),
                    session_id=request.session_id or self.session_id,
                    timestamp=self._now(),
                ).sign(self.private_key)
                captured.append(frame)
                await self.transport.send(frame.to_bytes())

        # Same identity as the real phone: only the recording differs.
        recorder = Recording(
            self.phone_side,
            display_name="Pixel 8",
            private_key=self.phone.private_key,
            public_key=self.phone.public_key,
        )
        recorder.trust_host(self.bridge.host_identity.public_key)
        recorder.session_id = self.phone.session_id
        # Continue the phone's own sequence: the replay guard would (correctly)
        # refuse a response numbered below the last one it accepted.
        recorder.sequence = self.phone.sequence
        await answered(self.control.get_volume(self.did), recorder)
        self.assertEqual(len(captured), 1)

        # Replay the captured frame: the replay guard must refuse it.
        replays_before = self.bridge._counters["replays_detected"]
        await self.bridge.handle_frame(captured[0].to_bytes())
        await self.bridge.handle_frame(captured[0].to_bytes())
        self.assertGreater(self.bridge._counters["replays_detected"], replays_before)

        # A response numbered *below* the accepted sequence is refused too.
        stale = BridgeMessage.create(
            MessageType.VOLUME_GET_RESPONSE,
            self.did,
            payload={"ok": True, "volume": 1, "muted": False},
            request_id=captured[0].request_id,
            sequence=1,
            session_id=self.phone.session_id,
        ).sign(self.phone.private_key)
        await self.bridge.handle_frame(stale.to_bytes())
        self.assertGreater(self.bridge._counters["replays_detected"], replays_before)
        self.assertEqual(self.phone.controller.volume, 40)

    async def _attack(self, *, sign_with=None, session_id=None):
        """Send a frame toward the phone from the PC end of the link.

        This models a compromised process that can reach the transport: the
        payload is well formed, so only the phone's own checks can stop it.
        """
        _, attacker_key = crypto.generate_keypair()
        key = sign_with if sign_with is not None else attacker_key
        frame = BridgeMessage.create(
            MessageType.VOLUME_SET,
            self.did,
            payload={"level": 100},
            sequence=999,
            session_id=session_id if session_id is not None else self.phone.session_id,
        ).sign(key)
        await self.bridge.transport.send(frame.to_bytes())
        await self.phone.serve(max_frames=1)

    async def test_the_phone_refuses_a_frame_that_is_not_from_the_trusted_host(self) -> None:
        """Device-side authorisation: a valid-looking payload is not enough."""
        await self._attack()
        self.assertIn(("volume_set", "bad signature"), self.phone.refusals)
        self.assertEqual(self.phone.controller.volume, 40)

    async def test_the_phone_refuses_a_frame_from_an_old_session(self) -> None:
        await self._attack(
            sign_with=self.bridge.host_identity.private_key, session_id="sess-stale"
        )
        self.assertIn(("volume_set", "wrong session"), self.phone.refusals)
        self.assertEqual(self.phone.controller.volume, 40)

    async def test_the_phone_accepts_a_genuine_frame_from_the_trusted_host(self) -> None:
        """The same path works when the caller is authentic - so the checks are real."""
        await self._attack(sign_with=self.bridge.host_identity.private_key)
        self.assertEqual(self.phone.refusals, [])
        self.assertEqual(self.phone.controller.volume, 100)


@requires_crypto
class ArgumentValidationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.bridge, self.phone, self.control, _, _ = await system_phone_pair()
        self.did = self.phone.device_id

    async def test_invalid_volume_values_are_refused_locally(self) -> None:
        from jarvis_devices.android_protocol import InvalidMessageError

        sent_before = self.bridge._counters["frames_sent"]
        for bad in (-1, 101, 1000, True, False, 50.5, "50", None, float("nan"), float("inf")):
            with self.subTest(bad=bad):
                with self.assertRaises(InvalidMessageError):
                    await self.control.set_volume(self.did, bad)
        self.assertEqual(self.bridge._counters["frames_sent"], sent_before)

    async def test_invalid_brightness_values_are_refused_locally(self) -> None:
        from jarvis_devices.android_protocol import InvalidMessageError

        for bad in (-1, 101, True, 0.5, "10", None):
            with self.subTest(bad=bad):
                with self.assertRaises(InvalidMessageError):
                    await self.control.set_brightness(self.did, bad)

    async def test_the_boundaries_are_accepted(self) -> None:
        for level in (0, 100):
            with self.subTest(level=level):
                payload = await answered(self.control.set_volume(self.did, level), self.phone)
                self.assertEqual(payload["volume"], level)
                payload = await answered(self.control.set_brightness(self.did, level), self.phone)
                self.assertEqual(payload["brightness"], level)

    async def test_a_non_boolean_radio_flag_is_refused(self) -> None:
        for bad in (1, 0, "on", None, []):
            with self.subTest(bad=bad):
                with self.assertRaises(AndroidSystemInvalidArgumentError):
                    await self.control.set_wifi_enabled(self.did, bad)
                with self.assertRaises(AndroidSystemInvalidArgumentError):
                    await self.control.set_bluetooth_enabled(self.did, bad)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
