"""Phase 9 security and routing coverage for cross-device orchestration."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import threading
import unittest

from jarvis_devices.android_bridge import AndroidDeviceBridge
from jarvis_devices.arguments import ArgumentSchema, ArgumentSpec
from jarvis_devices.android_identity import AndroidDeviceIdentity, AndroidHostIdentity, ConnectionInfo, ConnectionState, TrustState
from jarvis_devices import android_crypto as crypto
from jarvis_devices.android_protocol import CAPABILITY_CALL_DIAL, CAPABILITY_MESSAGE_SEND, CAPABILITY_MESSAGE_STATUS
from jarvis_devices.android_message_tools import build_android_message_tools
from jarvis_devices.adapters import PCDeviceAdapter
from jarvis_devices.confirmation import ConfirmationManager, ConfirmationPolicy
from jarvis_devices.cross_device import (
    ANDROID_TOOL_CAPABILITY_POLICY,
    LOCAL_PC_DEVICE_ID,
    CrossDevicePlanStatus,
    CrossDevicePlanStore,
    CrossDevicePlanner,
    CrossDeviceStatusTool,
)
from jarvis_devices.enums import Platform, RiskLevel, ToolResultStatus
from jarvis_devices.errors import ErrorCode
from jarvis_devices.manager import DeviceActionManager
from jarvis_devices.permissions import (
    PERMISSION_ANDROID_MESSAGE_READ,
    PERMISSION_ANDROID_MESSAGE_SEND,
    PermissionPolicy,
)
from jarvis_devices.platform import PlatformRegistry
from jarvis_devices.registry import DeviceToolRegistry
from jarvis_devices.results import ToolResult
from jarvis_devices.tools import BaseDeviceTool, ToolContext


class _Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 9, 9, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.value

    def advance(self, duration: timedelta) -> None:
        self.value += duration


class _PCReadTool(BaseDeviceTool):
    # Reuse a real Phase 3 allowlisted capability name while keeping a harmless
    # fake implementation: arbitrary ``pc.*`` registration is not routable.
    name = "pc.system.get_volume"
    description = "test only"
    platform = Platform.PC
    risk_level = RiskLevel.SAFE

    async def run(self, arguments, context: ToolContext):
        return ToolResult.ok("read", data={"argument_count": len(arguments)})


class _PCActionTool(_PCReadTool):
    name = "pc.power.shutdown"
    risk_level = RiskLevel.EXTERNAL_ACTION
    requires_confirmation = True


class _PCNoteTool(_PCReadTool):
    name = "pc.system.get_volume"
    argument_schema = ArgumentSchema(ArgumentSpec("note", type=str, max_length=64))


class _UnlistedPCTool(_PCReadTool):
    name = "pc.test.unlisted"


class _ManagerSpy(DeviceActionManager):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.requests = []

    async def request(self, tool_name, arguments=None, **kwargs):
        self.requests.append((tool_name, dict(arguments or {})))
        return await super().request(tool_name, arguments, **kwargs)


def _manager(*tools: BaseDeviceTool, permissions=()) -> _ManagerSpy:
    registry = DeviceToolRegistry()
    for tool in tools:
        registry.register(tool)
    platforms = PlatformRegistry()
    platforms.register(PCDeviceAdapter())
    return _ManagerSpy(
        registry=registry,
        permissions=PermissionPolicy(granted=permissions),
        confirmations=ConfirmationManager(policy=ConfirmationPolicy()),
        platforms=platforms,
    )


class CrossDevicePCTests(unittest.TestCase):
    def test_local_pc_is_the_only_pc_entry_and_registered_capabilities_are_visible(self):
        manager = _manager(_PCReadTool())
        planner = CrossDevicePlanner(manager)
        snapshot = planner.status()
        self.assertEqual(len(snapshot.entries), 1)
        entry = snapshot.find(LOCAL_PC_DEVICE_ID)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.platform, Platform.PC)
        self.assertIn("pc.system.get_volume", entry.capabilities)
        self.assertNotIn("transport", entry.to_dict())
        self.assertNotIn("display_name", entry.to_dict())

    def test_pc_plan_is_immutable_and_executes_only_through_manager(self):
        manager = _manager(_PCReadTool())
        planner = CrossDevicePlanner(manager)
        planned = planner.create_plan("pc.system.get_volume")
        self.assertTrue(planned.planned)
        self.assertEqual(planned.plan.device_id, LOCAL_PC_DEVICE_ID)
        self.assertNotIn("_arguments", planned.plan.to_dict())
        result = asyncio.run(planner.execute_plan(planned.plan.plan_id))
        self.assertEqual(result.status, CrossDevicePlanStatus.SUBMITTED)
        self.assertEqual(result.tool_result.status, ToolResultStatus.SUCCESS)
        self.assertEqual(manager.requests, [("pc.system.get_volume", {})])
        replay = asyncio.run(planner.execute_plan(planned.plan.plan_id))
        self.assertEqual(replay.status, CrossDevicePlanStatus.REPLAYED)
        self.assertEqual(len(manager.requests), 1)

    def test_plan_summary_and_audit_never_include_sensitive_argument_values(self):
        manager = _manager(_PCNoteTool())
        # This test tool accepts one bounded scalar, demonstrating that planner
        # summaries/audit records retain names rather than argument values.
        planner = CrossDevicePlanner(manager)
        planned = planner.create_plan("pc.system.get_volume", {"note": "private-plan-value"})
        self.assertTrue(planned.planned)
        self.assertNotIn("private-plan-value", str(planned.plan.to_dict()))
        self.assertNotIn("private-plan-value", str(manager.audit.records))
        values = planned.plan.arguments
        values["note"] = "mutated-copy"
        self.assertEqual(planned.plan.arguments["note"], "private-plan-value")
        with self.assertRaises((AttributeError, TypeError)):
            planned.plan.device_id = "pc-other"  # type: ignore[misc]

    def test_plan_store_is_bounded(self):
        manager = _manager(_PCReadTool())
        planner = CrossDevicePlanner(manager, plan_store=CrossDevicePlanStore(max_plans=1))
        self.assertTrue(planner.create_plan("pc.system.get_volume").planned)
        full = planner.create_plan("pc.system.get_volume")
        self.assertEqual(full.status, CrossDevicePlanStatus.UNAVAILABLE)
        self.assertEqual(full.error_code, ErrorCode.CROSS_DEVICE_PLAN_CAPACITY)

    def test_plan_expiry_permission_change_and_registry_change_fail_closed(self):
        clock = _Clock()
        manager = _manager(_PCReadTool())
        planner = CrossDevicePlanner(manager, clock=clock, plan_ttl=timedelta(seconds=2))
        expired = planner.create_plan("pc.system.get_volume").plan
        clock.advance(timedelta(seconds=3))
        self.assertEqual(
            asyncio.run(planner.execute_plan(expired.plan_id)).status,
            CrossDevicePlanStatus.EXPIRED,
        )
        self.assertEqual(manager.requests, [])

        clock = _Clock()
        manager = _manager(_PCReadTool(), permissions=("demo.permission",))
        # Attach a permission after construction so planning observes it and can
        # prove execution observes a later revocation.
        tool = manager.registry.find("pc.system.get_volume")
        tool.required_permissions = ("demo.permission",)
        planner = CrossDevicePlanner(manager, clock=clock)
        permission_plan = planner.create_plan("pc.system.get_volume").plan
        manager.permissions.revoke("demo.permission")
        self.assertEqual(
            asyncio.run(planner.execute_plan(permission_plan.plan_id)).status,
            CrossDevicePlanStatus.PERMISSION_DENIED,
        )
        self.assertEqual(manager.requests, [])

        manager = _manager(_PCReadTool())
        planner = CrossDevicePlanner(manager)
        removed = planner.create_plan("pc.system.get_volume").plan
        manager.registry.unregister("pc.system.get_volume")
        self.assertEqual(
            asyncio.run(planner.execute_plan(removed.plan_id)).status,
            CrossDevicePlanStatus.INVALIDATED,
        )

    def test_external_plan_preserves_existing_confirmation_and_never_executes_early(self):
        manager = _manager(_PCActionTool())
        planner = CrossDevicePlanner(manager)
        plan = planner.create_plan("pc.power.shutdown").plan
        submitted = asyncio.run(planner.execute_plan(plan.plan_id))
        self.assertEqual(submitted.status, CrossDevicePlanStatus.SUBMITTED)
        self.assertEqual(submitted.tool_result.status, ToolResultStatus.PENDING_CONFIRMATION)
        self.assertFalse(submitted.tool_result.executed)
        confirmation_id = submitted.tool_result.data["confirmation_id"]
        confirmed = asyncio.run(manager.resolve_confirmation(confirmation_id, True))
        self.assertEqual(confirmed.status, ToolResultStatus.SUCCESS)

    def test_unknown_capability_and_explicit_remote_pc_fail_without_fallback(self):
        manager = _manager(_PCReadTool())
        planner = CrossDevicePlanner(manager)
        self.assertEqual(
            planner.create_plan("not.a.registered.tool").error_code,
            ErrorCode.CROSS_DEVICE_UNSUPPORTED,
        )
        unlisted = CrossDevicePlanner(_manager(_UnlistedPCTool())).create_plan("pc.test.unlisted")
        self.assertEqual(unlisted.error_code, ErrorCode.CROSS_DEVICE_UNSUPPORTED)
        explicit = planner.create_plan("pc.system.get_volume", device_id="pc-remote")
        self.assertEqual(explicit.status, CrossDevicePlanStatus.UNAVAILABLE)
        self.assertEqual(explicit.error_code, ErrorCode.CROSS_DEVICE_TARGET_UNAVAILABLE)


@unittest.skipUnless(crypto.crypto_available(), "cryptography is required for real bridge identities")
class CrossDeviceAndroidTests(unittest.TestCase):
    def _bridge_with_devices(self, count: int = 1, *, capabilities=None):
        host = AndroidHostIdentity.generate("cross-device-test")
        bridge = AndroidDeviceBridge(host_identity=host)
        devices = []
        for index in range(count):
            _private, public = crypto.generate_keypair()
            identity = AndroidDeviceIdentity(
                device_id=crypto.device_id_from_public_key(public),
                public_key=public,
                display_name=f"Phone {index}",
                trust_state=TrustState.CONNECTED,
                capabilities=capabilities or (CAPABILITY_MESSAGE_STATUS, CAPABILITY_MESSAGE_SEND),
                connection=ConnectionInfo(state=ConnectionState.CONNECTED),
            )
            bridge.registry.register(identity)
            devices.append(identity.device_id)
        return bridge, devices

    def _message_manager(self, bridge):
        registry = DeviceToolRegistry()
        for tool in build_android_message_tools(bridge):
            registry.register(tool)
        platforms = PlatformRegistry()
        platforms.register(PCDeviceAdapter())
        return _ManagerSpy(
            registry=registry,
            permissions=PermissionPolicy(
                granted=(PERMISSION_ANDROID_MESSAGE_READ, PERMISSION_ANDROID_MESSAGE_SEND)
            ),
            confirmations=ConfirmationManager(policy=ConfirmationPolicy()),
            platforms=platforms,
        )

    def test_android_inventory_uses_canonical_ids_registry_tools_and_no_private_transport(self):
        bridge, devices = self._bridge_with_devices()
        manager = self._message_manager(bridge)
        snapshot = CrossDevicePlanner(manager, android_bridge=bridge).status()
        entry = snapshot.find(devices[0])
        self.assertTrue(entry.device_id.startswith("adev-"))
        self.assertEqual(entry.platform, Platform.ANDROID)
        self.assertIn("android.message.status", entry.capabilities)
        self.assertIn("android.message.send", entry.capabilities)
        public = entry.to_dict()
        self.assertNotIn("capabilities_advertised", public)
        self.assertNotIn("connection", public)
        self.assertNotIn("fingerprint", public)

    def test_android_capability_and_explicit_target_are_required_without_migration(self):
        bridge, devices = self._bridge_with_devices(
            2, capabilities=(CAPABILITY_MESSAGE_STATUS,)
        )
        manager = self._message_manager(bridge)
        planner = CrossDevicePlanner(manager, android_bridge=bridge)
        unsupported = planner.create_plan(
            "android.message.send",
            {"recipient": "+14155550123", "message": "private body"},
            device_id=devices[0],
        )
        self.assertEqual(unsupported.status, CrossDevicePlanStatus.UNAVAILABLE)
        self.assertEqual(unsupported.error_code, ErrorCode.CROSS_DEVICE_TARGET_UNAVAILABLE)
        self.assertNotIn("private body", unsupported.message)

        bridge.registry.update(
            devices[1], capabilities=(CAPABILITY_MESSAGE_STATUS, CAPABILITY_MESSAGE_SEND)
        )
        explicit = planner.create_plan(
            "android.message.send",
            {"recipient": "+14155550123", "message": "private body"},
            device_id=devices[0],
        )
        self.assertEqual(explicit.status, CrossDevicePlanStatus.UNAVAILABLE)
        self.assertNotIn("private body", str(explicit.to_dict()))

    def test_multiple_android_candidates_are_ambiguous_except_opted_in_safe_read(self):
        bridge, devices = self._bridge_with_devices(2)
        manager = self._message_manager(bridge)
        planner = CrossDevicePlanner(manager, android_bridge=bridge)
        ambiguous = planner.create_plan("android.message.status")
        self.assertEqual(ambiguous.status, CrossDevicePlanStatus.AMBIGUOUS)
        self.assertEqual(ambiguous.candidates, tuple(sorted(devices)))
        safe = planner.create_plan("android.message.status", allow_read_fallback=True)
        self.assertTrue(safe.planned)
        self.assertEqual(safe.plan.device_id, sorted(devices)[0])
        external = planner.create_plan(
            "android.message.send", {"recipient": "+14155550123", "message": "one"}
        )
        self.assertEqual(external.status, CrossDevicePlanStatus.AMBIGUOUS)

    def test_revocation_disconnect_and_capability_change_invalidate_before_manager_handoff(self):
        bridge, devices = self._bridge_with_devices()
        manager = self._message_manager(bridge)
        planner = CrossDevicePlanner(manager, android_bridge=bridge)
        planned = planner.create_plan("android.message.status", device_id=devices[0]).plan
        bridge.registry.revoke(devices[0])
        result = asyncio.run(planner.execute_plan(planned.plan_id))
        self.assertEqual(result.status, CrossDevicePlanStatus.INVALIDATED)
        self.assertEqual(manager.requests, [])

        # A separate plan proves a capability downgrade is equally fail-closed.
        bridge, devices = self._bridge_with_devices()
        manager = self._message_manager(bridge)
        planner = CrossDevicePlanner(manager, android_bridge=bridge)
        planned = planner.create_plan("android.message.status", device_id=devices[0]).plan
        bridge.registry.update(devices[0], capabilities=())
        self.assertEqual(
            asyncio.run(planner.execute_plan(planned.plan_id)).status,
            CrossDevicePlanStatus.INVALIDATED,
        )
        self.assertEqual(manager.requests, [])

        bridge, devices = self._bridge_with_devices()
        manager = self._message_manager(bridge)
        planner = CrossDevicePlanner(manager, android_bridge=bridge)
        planned = planner.create_plan("android.message.status", device_id=devices[0]).plan
        bridge.registry.update(
            devices[0], connection=ConnectionInfo(state=ConnectionState.DISCONNECTED)
        )
        self.assertEqual(
            asyncio.run(planner.execute_plan(planned.plan_id)).status,
            CrossDevicePlanStatus.INVALIDATED,
        )
        self.assertEqual(manager.requests, [])

    def test_plan_id_is_not_authority_and_concurrent_submission_has_one_handoff(self):
        bridge, devices = self._bridge_with_devices()
        manager = self._message_manager(bridge)
        planner = CrossDevicePlanner(manager, android_bridge=bridge)
        plan = planner.create_plan("android.message.status", device_id=devices[0]).plan
        results = []

        def submit():
            results.append(asyncio.run(planner.execute_plan(plan.plan_id)).status)

        first, second = threading.Thread(target=submit), threading.Thread(target=submit)
        first.start(); second.start(); first.join(); second.join()
        self.assertEqual(results.count(CrossDevicePlanStatus.SUBMITTED), 1)
        self.assertEqual(results.count(CrossDevicePlanStatus.REPLAYED), 1)
        self.assertEqual(len(manager.requests), 1)

    def test_policy_is_frozen_and_covers_exactly_the_routable_android_operations(self):
        from jarvis_devices.android_call_tools import ANDROID_CALL_TOOL_NAMES
        from jarvis_devices.android_message_tools import ANDROID_MESSAGE_TOOL_NAMES
        from jarvis_devices.android_system_tools import ANDROID_SYSTEM_TOOL_NAMES

        with self.assertRaises(TypeError):
            ANDROID_TOOL_CAPABILITY_POLICY["android.evil.run"] = object()
        expected = {
            "android.device.status",
            *ANDROID_SYSTEM_TOOL_NAMES,
            *ANDROID_CALL_TOOL_NAMES,
            *ANDROID_MESSAGE_TOOL_NAMES,
        }
        self.assertEqual(set(ANDROID_TOOL_CAPABILITY_POLICY), expected)


class CrossDeviceReadToolTests(unittest.TestCase):
    def test_status_tool_is_registered_style_read_only_and_permission_aware(self):
        manager = _manager(_PCReadTool())
        planner = CrossDevicePlanner(manager)
        tool = CrossDeviceStatusTool(planner)
        denied_manager = _manager(tool)
        denied = asyncio.run(denied_manager.request("cross.device.status"))
        self.assertEqual(denied.status, ToolResultStatus.PERMISSION_DENIED)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
