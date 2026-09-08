"""Permission system tests (Phase 1)."""

from __future__ import annotations

import unittest

from jarvis_devices import ErrorCode, Platform, PermissionPolicy, RiskLevel
from jarvis_devices.permissions import (
    PERMISSION_CALL_PLACE,
    PERMISSION_DEVICE_STATUS_READ,
    PERMISSION_MESSAGE_SEND,
    PERMISSION_POWER_CONTROL,
    READ_ONLY_PERMISSIONS,
)

try:  # imported as part of the ``tests`` package (pytest / discover -t .)
    from .support import FakeDeviceTool
except ImportError:  # ``python -m unittest discover -s tests``
    from support import FakeDeviceTool


class PermissionDecisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = PermissionPolicy(granted=[PERMISSION_DEVICE_STATUS_READ])

    def test_allowed_when_permission_is_granted(self) -> None:
        tool = FakeDeviceTool(
            "pc.status.read",
            platform=Platform.PC,
            required_permissions=(PERMISSION_DEVICE_STATUS_READ,),
        )
        decision = self.policy.check(tool)
        self.assertTrue(decision.allowed)
        self.assertTrue(bool(decision))
        self.assertEqual(decision.missing_permissions, ())

    def test_denied_when_permission_is_missing(self) -> None:
        tool = FakeDeviceTool(
            "comms.sms.send",
            platform=Platform.ANDROID,
            required_permissions=(PERMISSION_MESSAGE_SEND,),
        )
        decision = self.policy.check(tool)
        self.assertFalse(decision.allowed)
        self.assertFalse(bool(decision))
        self.assertEqual(decision.missing_permissions, (PERMISSION_MESSAGE_SEND,))
        self.assertEqual(decision.error_code, ErrorCode.PERMISSION_DENIED)
        self.assertIn(PERMISSION_MESSAGE_SEND, decision.reason)

    def test_denied_lists_every_missing_permission(self) -> None:
        tool = FakeDeviceTool(
            "comms.call.place",
            platform=Platform.ANDROID,
            required_permissions=(PERMISSION_CALL_PLACE, PERMISSION_POWER_CONTROL),
        )
        decision = self.policy.check(tool)
        self.assertEqual(
            set(decision.missing_permissions),
            {PERMISSION_CALL_PLACE, PERMISSION_POWER_CONTROL},
        )

    def test_tool_without_required_permissions_is_allowed(self) -> None:
        tool = FakeDeviceTool("jarvis.framework.diagnostics")
        self.assertTrue(self.policy.check(tool).allowed)


class PermissionGrantTests(unittest.TestCase):
    def test_grant_and_revoke(self) -> None:
        policy = PermissionPolicy()
        self.assertFalse(policy.is_granted(PERMISSION_POWER_CONTROL))
        policy.grant(PERMISSION_POWER_CONTROL)
        self.assertTrue(policy.is_granted(PERMISSION_POWER_CONTROL))
        policy.revoke(PERMISSION_POWER_CONTROL)
        self.assertFalse(policy.is_granted(PERMISSION_POWER_CONTROL))

    def test_hard_deny_wins_over_grant(self) -> None:
        policy = PermissionPolicy(granted=[PERMISSION_POWER_CONTROL])
        policy.deny(PERMISSION_POWER_CONTROL)
        self.assertFalse(policy.is_granted(PERMISSION_POWER_CONTROL))
        tool = FakeDeviceTool(
            "pc.power.shutdown",
            platform=Platform.PC,
            risk_level=RiskLevel.DESTRUCTIVE,
            required_permissions=(PERMISSION_POWER_CONTROL,),
        )
        self.assertFalse(policy.check(tool).allowed)
        policy.allow(PERMISSION_POWER_CONTROL)
        self.assertTrue(policy.check(tool).allowed)

    def test_invalid_permission_name_is_rejected(self) -> None:
        policy = PermissionPolicy()
        for bad in ("", "   ", None):
            with self.subTest(permission=bad):
                with self.assertRaises(ValueError):
                    policy.grant(bad)  # type: ignore[arg-type]

    def test_local_defaults_are_read_only(self) -> None:
        policy = PermissionPolicy.with_local_defaults()
        self.assertEqual(policy.granted_permissions, READ_ONLY_PERMISSIONS)
        self.assertTrue(policy.is_granted(PERMISSION_DEVICE_STATUS_READ))
        self.assertFalse(policy.is_granted(PERMISSION_MESSAGE_SEND))
        self.assertFalse(policy.is_granted(PERMISSION_POWER_CONTROL))


class PermissionBlockTests(unittest.TestCase):
    def test_blocked_tool_is_refused_even_with_permissions(self) -> None:
        policy = PermissionPolicy(granted=[PERMISSION_POWER_CONTROL])
        tool = FakeDeviceTool(
            "pc.power.shutdown",
            platform=Platform.PC,
            risk_level=RiskLevel.DESTRUCTIVE,
            required_permissions=(PERMISSION_POWER_CONTROL,),
        )
        self.assertTrue(policy.check(tool).allowed)
        policy.block_tool("PC.Power.Shutdown")
        decision = policy.check(tool)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.error_code, ErrorCode.TOOL_BLOCKED)
        policy.unblock_tool("pc.power.shutdown")
        self.assertTrue(policy.check(tool).allowed)

    def test_blocked_platform_is_refused(self) -> None:
        policy = PermissionPolicy(granted=[PERMISSION_MESSAGE_SEND])
        tool = FakeDeviceTool(
            "android.sms.send",
            platform=Platform.ANDROID,
            required_permissions=(PERMISSION_MESSAGE_SEND,),
        )
        policy.block_platform(Platform.ANDROID.value)
        decision = policy.check(tool)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.error_code, ErrorCode.PLATFORM_BLOCKED)

    def test_is_tool_blocked_and_is_platform_blocked(self) -> None:
        policy = PermissionPolicy()
        policy.block_tool("pc.power.shutdown")
        policy.block_platform("android")
        self.assertTrue(policy.is_tool_blocked("pc.power.shutdown"))
        self.assertFalse(policy.is_tool_blocked("pc.audio.volume"))
        self.assertTrue(policy.is_platform_blocked("android"))
        self.assertFalse(policy.is_platform_blocked("pc"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
