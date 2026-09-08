"""Confirmation framework tests (Phase 1)."""

from __future__ import annotations

import unittest
from datetime import timedelta

from jarvis_devices import (
    ConfirmationManager,
    ConfirmationPolicy,
    ConfirmationStatus,
    Platform,
    RiskLevel,
)
from jarvis_devices.errors import (
    ConfirmationExpiredError,
    ConfirmationLimitError,
    ConfirmationStateError,
    UnknownConfirmationError,
)

try:  # imported as part of the ``tests`` package (pytest / discover -t .)
    from .support import FakeClock, FakeDeviceTool
except ImportError:  # ``python -m unittest discover -s tests``
    from support import FakeClock, FakeDeviceTool

TTL = timedelta(seconds=30)


def make_manager(clock: FakeClock | None = None, **kwargs) -> ConfirmationManager:
    clock = clock or FakeClock()
    kwargs.setdefault("default_ttl", TTL)
    return ConfirmationManager(clock=clock, **kwargs)


class ConfirmationCreationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = FakeClock()
        self.manager = make_manager(self.clock)

    def test_create_returns_pending_request_with_ids(self) -> None:
        request = self.manager.create("pc.power.shutdown", "the PC", risk_level=RiskLevel.DESTRUCTIVE)
        self.assertTrue(request.confirmation_id.startswith("cfm-"))
        self.assertEqual(request.action, "pc.power.shutdown")
        self.assertEqual(request.tool_name, "pc.power.shutdown")
        self.assertEqual(request.target, "the PC")
        self.assertEqual(request.status, ConfirmationStatus.PENDING)
        self.assertEqual(request.risk_level, RiskLevel.DESTRUCTIVE)
        self.assertEqual(request.expires_at, self.clock() + TTL)

    def test_ids_are_unique(self) -> None:
        manager = make_manager(self.clock, max_pending=1000)
        ids = {manager.create("pc.power.shutdown").confirmation_id for _ in range(200)}
        self.assertEqual(len(ids), 200)

    def test_create_requires_an_action(self) -> None:
        with self.assertRaises(ValueError):
            self.manager.create("   ")

    def test_pending_request_is_found(self) -> None:
        request = self.manager.create("pc.power.shutdown")
        self.assertIs(self.manager.get(request.confirmation_id), request)
        self.assertIs(self.manager.require(request.confirmation_id), request)
        self.assertIn(request.confirmation_id, self.manager)
        self.assertEqual(len(self.manager.pending()), 1)

    def test_describe_and_to_dict_hide_argument_values(self) -> None:
        request = self.manager.create(
            "comms.sms.send",
            "Sarthak",
            arguments={"recipient": "+919000000000", "message": "secret body"},
        )
        self.assertNotIn("secret body", request.describe())
        self.assertNotIn("+919000000000", request.describe())
        payload = request.to_dict()
        self.assertEqual(payload["argument_names"], ["message", "recipient"])
        self.assertNotIn("secret body", str(payload))

    def test_not_required_helper(self) -> None:
        request = self.manager.not_required("pc.audio.volume")
        self.assertEqual(request.status, ConfirmationStatus.NOT_REQUIRED)
        self.assertTrue(request.is_resolved())
        self.assertFalse(request.is_pending())


class ConfirmationResolutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = FakeClock()
        self.manager = make_manager(self.clock)
        self.request = self.manager.create("pc.power.shutdown", "the PC")

    def test_confirm(self) -> None:
        resolved = self.manager.confirm(self.request.confirmation_id)
        self.assertEqual(resolved.status, ConfirmationStatus.CONFIRMED)
        self.assertTrue(resolved.is_resolved())
        self.assertEqual(len(self.manager.pending()), 0)

    def test_deny(self) -> None:
        self.assertEqual(
            self.manager.deny(self.request.confirmation_id).status,
            ConfirmationStatus.DENIED,
        )

    def test_cancel(self) -> None:
        self.assertEqual(
            self.manager.cancel(self.request.confirmation_id).status,
            ConfirmationStatus.CANCELLED,
        )

    def test_resolve_helper(self) -> None:
        first = self.manager.create("pc.power.shutdown")
        second = self.manager.create("pc.power.restart")
        self.assertEqual(
            self.manager.resolve(first.confirmation_id, True).status,
            ConfirmationStatus.CONFIRMED,
        )
        self.assertEqual(
            self.manager.resolve(second.confirmation_id, False).status,
            ConfirmationStatus.DENIED,
        )

    def test_resolving_twice_is_a_state_error(self) -> None:
        self.manager.confirm(self.request.confirmation_id)
        with self.assertRaises(ConfirmationStateError):
            self.manager.confirm(self.request.confirmation_id)
        with self.assertRaises(ConfirmationStateError):
            self.manager.deny(self.request.confirmation_id)

    def test_unknown_confirmation(self) -> None:
        self.assertIsNone(self.manager.get("cfm-does-not-exist"))
        with self.assertRaises(UnknownConfirmationError):
            self.manager.require("cfm-does-not-exist")
        with self.assertRaises(UnknownConfirmationError):
            self.manager.confirm("cfm-does-not-exist")

    def test_consume_marks_a_confirmation_as_used(self) -> None:
        self.manager.confirm(self.request.confirmation_id)
        self.assertFalse(self.manager.is_consumed(self.request.confirmation_id))
        self.assertTrue(self.manager.consume(self.request.confirmation_id))
        self.assertTrue(self.manager.is_consumed(self.request.confirmation_id))
        self.assertFalse(self.manager.consume(self.request.confirmation_id))


class ConfirmationExpiryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = FakeClock()
        self.manager = make_manager(self.clock)
        self.request = self.manager.create("pc.power.shutdown")

    def test_pending_before_the_deadline(self) -> None:
        self.clock.advance(TTL - timedelta(seconds=1))
        self.assertTrue(self.request.is_pending(self.clock()))
        self.assertEqual(self.manager.get(self.request.confirmation_id).status,
                         ConfirmationStatus.PENDING)

    def test_expired_after_the_deadline(self) -> None:
        self.clock.advance(TTL + timedelta(seconds=1))
        self.assertTrue(self.request.is_expired(self.clock()))
        self.assertFalse(self.request.is_pending(self.clock()))
        self.assertEqual(
            self.manager.get(self.request.confirmation_id).status,
            ConfirmationStatus.EXPIRED,
        )
        self.assertEqual(self.manager.pending(), ())

    def test_confirming_an_expired_request_raises(self) -> None:
        self.clock.advance(TTL + timedelta(seconds=1))
        with self.assertRaises(ConfirmationExpiredError):
            self.manager.confirm(self.request.confirmation_id)

    def test_expire_overdue_counts(self) -> None:
        self.manager.create("pc.power.restart")
        self.clock.advance(TTL * 2)
        self.assertEqual(self.manager.expire_overdue(), 2)
        self.assertEqual(self.manager.expire_overdue(), 0)

    def test_custom_ttl(self) -> None:
        request = self.manager.create("pc.power.shutdown", ttl=timedelta(seconds=5))
        self.clock.advance(timedelta(seconds=6))
        self.assertEqual(request.status, ConfirmationStatus.PENDING)  # untouched until read
        self.assertEqual(
            self.manager.get(request.confirmation_id).status,
            ConfirmationStatus.EXPIRED,
        )


class ConfirmationLimitTests(unittest.TestCase):
    def test_pending_limit_is_enforced(self) -> None:
        manager = make_manager(FakeClock(), max_pending=2)
        manager.create("pc.power.shutdown")
        manager.create("pc.power.restart")
        with self.assertRaises(ConfirmationLimitError):
            manager.create("pc.power.sleep")

    def test_expired_confirmations_free_their_slot(self) -> None:
        clock = FakeClock()
        manager = make_manager(clock, max_pending=1)
        manager.create("pc.power.shutdown")
        clock.advance(TTL * 2)
        self.assertIsNotNone(manager.create("pc.power.restart"))


class ConfirmationPolicyTests(unittest.TestCase):
    def test_risk_levels_decide_by_default(self) -> None:
        policy = ConfirmationPolicy()
        self.assertFalse(policy.is_required(FakeDeviceTool("t.safe", risk_level=RiskLevel.SAFE)))
        self.assertFalse(
            policy.is_required(FakeDeviceTool("t.low", risk_level=RiskLevel.LOW_RISK))
        )
        self.assertTrue(
            policy.is_required(FakeDeviceTool("t.ext", risk_level=RiskLevel.EXTERNAL_ACTION))
        )
        self.assertTrue(
            policy.is_required(FakeDeviceTool("t.des", risk_level=RiskLevel.DESTRUCTIVE))
        )

    def test_tool_override_wins_over_risk(self) -> None:
        policy = ConfirmationPolicy()
        forced = FakeDeviceTool(
            "pc.audio.volume",
            platform=Platform.PC,
            risk_level=RiskLevel.LOW_RISK,
            requires_confirmation=True,
        )
        skipped = FakeDeviceTool(
            "comms.sms.send",
            platform=Platform.ANDROID,
            risk_level=RiskLevel.EXTERNAL_ACTION,
            requires_confirmation=False,
        )
        self.assertTrue(policy.is_required(forced))
        self.assertFalse(policy.is_required(skipped))

    def test_always_and_never_lists(self) -> None:
        policy = ConfirmationPolicy(
            risk_levels=(RiskLevel.DESTRUCTIVE,),
            always_confirm=("pc.audio.volume",),
            never_confirm=("pc.power.shutdown",),
        )
        self.assertTrue(policy.is_required(FakeDeviceTool("pc.audio.volume", risk_level=RiskLevel.SAFE)))
        self.assertFalse(
            policy.is_required(FakeDeviceTool("pc.power.shutdown", risk_level=RiskLevel.DESTRUCTIVE))
        )

    def test_manager_exposes_its_policy(self) -> None:
        manager = make_manager()
        self.assertIsInstance(manager.policy, ConfirmationPolicy)
        self.assertTrue(manager.policy.is_required(FakeDeviceTool("x", risk_level=RiskLevel.DESTRUCTIVE)))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
