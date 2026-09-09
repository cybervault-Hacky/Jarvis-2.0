"""Phase 10 least-privilege bootstrap regressions."""

from __future__ import annotations

import ast
import asyncio
import unittest
from pathlib import Path

import Jarvis_device_control as bridge
from jarvis_devices import ConfirmationManager, ConfirmationPolicy, DeviceActionManager, DeviceToolRegistry, Platform, RiskLevel
from jarvis_devices.enums import ToolResultStatus
from jarvis_devices.permissions import PERMISSION_DEVICE_STATUS_READ, PERMISSION_POWER_CONTROL, PermissionPolicy

try:
    from .support import FakeDeviceTool
except ImportError:  # pragma: no cover
    from support import FakeDeviceTool


ROOT = Path(__file__).resolve().parent.parent
CONTROL_PERMISSIONS = frozenset({
    "system.app.control", "system.volume.control", "system.display.control",
    "system.network.control", "system.bluetooth.control", "system.power.control",
    "device.android.bridge.pair", "device.android.bridge.manage",
    "device.android.system.read", "device.android.system.control",
    "device.android.call.read", "device.android.call.control",
    "device.android.message.read", "device.android.message.send",
})


class LeastPrivilegeBootstrapTests(unittest.TestCase):
    def test_default_runtime_has_only_read_only_device_status_permission(self) -> None:
        self.assertEqual(set(bridge.device_permissions.granted_permissions), {PERMISSION_DEVICE_STATUS_READ})
        self.assertTrue(CONTROL_PERMISSIONS.isdisjoint(bridge.device_permissions.granted_permissions))

    def test_source_has_no_import_time_permission_grant(self) -> None:
        tree = ast.parse((ROOT / "Jarvis_device_control.py").read_text(encoding="utf-8"))
        grants = []
        for parent in ast.walk(tree):
            if not isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for child in ast.walk(parent):
                if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute) and child.func.attr == "grant":
                    grants.append(parent.name)
        self.assertEqual(grants, ["grant_device_permission"])

    def test_default_policy_is_read_only_and_grants_no_control_permission(self) -> None:
        policy = PermissionPolicy.with_local_defaults()
        self.assertEqual(set(policy.granted_permissions), {PERMISSION_DEVICE_STATUS_READ})
        self.assertTrue(CONTROL_PERMISSIONS.isdisjoint(policy.granted_permissions))

    def test_sensitive_request_stays_denied_until_a_trusted_host_grants_then_pending(self) -> None:
        async def exercise() -> None:
            policy = PermissionPolicy.with_local_defaults()
            registry = DeviceToolRegistry()
            tool = FakeDeviceTool(
                "test.sensitive.power",
                platform=Platform.UNKNOWN,
                risk_level=RiskLevel.DESTRUCTIVE,
                required_permissions=(PERMISSION_POWER_CONTROL,),
            )
            registry.register(tool)
            manager = DeviceActionManager(
                registry=registry,
                permissions=policy,
                confirmations=ConfirmationManager(policy=ConfirmationPolicy()),
            )

            denied = await manager.request(tool.name)
            self.assertEqual(denied.status, ToolResultStatus.PERMISSION_DENIED)
            self.assertFalse(denied.executed)
            self.assertEqual(tool.call_count, 0)

            # This represents the narrow opt-in a trusted host/UI would make;
            # the model has no Agent-exposed permission-grant tool.
            policy.grant(PERMISSION_POWER_CONTROL)
            pending = await manager.request(tool.name)
            self.assertEqual(pending.status, ToolResultStatus.PENDING_CONFIRMATION)
            self.assertFalse(pending.executed)
            self.assertEqual(tool.call_count, 0)
            manager.confirmations.cancel(pending.data["confirmation_id"])

        asyncio.run(exercise())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
