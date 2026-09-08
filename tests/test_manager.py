"""DeviceActionManager tests - the safe failure matrix (Phase 1)."""

from __future__ import annotations

import unittest
from datetime import timedelta

from jarvis_devices import (
    ArgumentSchema,
    ArgumentSpec,
    AuditLogger,
    ConfirmationManager,
    ConfirmationStatus,
    DeviceActionManager,
    DeviceToolRegistry,
    ErrorCode,
    PermissionPolicy,
    Platform,
    PlatformRegistry,
    RiskLevel,
    ToolResult,
    ToolResultStatus,
)

try:  # imported as part of the ``tests`` package (pytest / discover -t .)
    from .support import AuditCapture, FakeAdapter, FakeClock, FakeDeviceTool
except ImportError:  # ``python -m unittest discover -s tests``
    from support import AuditCapture, FakeAdapter, FakeClock, FakeDeviceTool

TTL = timedelta(seconds=30)
MEDIA = "device.media.control"
POWER = "system.power.control"
MESSAGING = "comms.message.send"

DIRECTION_SCHEMA = ArgumentSchema(
    ArgumentSpec("direction", choices=("up", "down"), description="up or down")
)
MESSAGE_SCHEMA = ArgumentSchema(
    ArgumentSpec("recipient", max_length=64),
    ArgumentSpec("body", max_length=500),
)


class StringReturningTool(FakeDeviceTool):
    """A badly behaved tool that returns a plain string instead of a result."""

    async def run(self, arguments, context):  # type: ignore[override]
        self.calls.append((dict(arguments), context))
        return "I did the thing"


class ManagerCase(unittest.IsolatedAsyncioTestCase):
    """Shared wiring: PC adapter available, media + power permissions granted."""

    def build(
        self,
        *,
        granted=(MEDIA, POWER),
        adapters=None,
        execution_timeout=None,
        clock=None,
    ) -> DeviceActionManager:
        audit = AuditLogger(enabled=False)
        self.capture = AuditCapture(audit)
        self.registry = DeviceToolRegistry()
        self.platforms = PlatformRegistry()
        for adapter in (FakeAdapter(Platform.PC),) if adapters is None else adapters:
            self.platforms.register(adapter)
        self.clock = clock or FakeClock()
        manager = DeviceActionManager(
            self.registry,
            PermissionPolicy(granted=granted),
            ConfirmationManager(default_ttl=TTL, clock=self.clock),
            self.platforms,
            audit,
            execution_timeout=execution_timeout,
        )
        return manager

    def register(self, manager: DeviceActionManager, tool: FakeDeviceTool) -> FakeDeviceTool:
        manager.registry.register(tool)
        return tool


class HappyPathTests(ManagerCase):
    async def test_safe_tool_runs_through_its_platform_adapter(self) -> None:
        manager = self.build()
        adapter = self.platforms.get(Platform.PC)
        tool = self.register(
            manager,
            FakeDeviceTool(
                "pc.audio.volume",
                platform=Platform.PC,
                risk_level=RiskLevel.LOW_RISK,
                required_permissions=(MEDIA,),
                argument_schema=DIRECTION_SCHEMA,
            ),
        )

        result = await manager.request("pc.audio.volume", {"direction": "up"})

        self.assertTrue(result.success)
        self.assertEqual(result.status, ToolResultStatus.SUCCESS)
        self.assertEqual(result.tool_name, "pc.audio.volume")
        self.assertTrue(result.execution_id.startswith("exec-"))
        self.assertEqual(tool.call_count, 1)
        self.assertEqual(tool.calls[0][0], {"direction": "up"})
        self.assertIs(tool.calls[0][1].adapter, adapter)
        self.assertEqual(adapter.calls, [("pc.audio.volume", {"direction": "up"})])

    async def test_platform_agnostic_tool_runs_without_an_adapter(self) -> None:
        manager = self.build()
        tool = self.register(manager, FakeDeviceTool("jarvis.time.now"))
        result = await manager.request("jarvis.time.now")
        self.assertTrue(result.success)
        self.assertEqual(tool.call_count, 1)
        self.assertIsNone(tool.calls[0][1].adapter)

    async def test_defaults_are_filled_in_for_optional_arguments(self) -> None:
        manager = self.build()
        schema = ArgumentSchema(
            ArgumentSpec("direction", choices=("up", "down")),
            ArgumentSpec("steps", type=int, required=False, default=1, min_value=1, max_value=100),
        )
        tool = self.register(
            manager,
            FakeDeviceTool("pc.audio.volume", platform=Platform.PC, argument_schema=schema),
        )
        result = await manager.request("pc.audio.volume", {"direction": "up"})
        self.assertTrue(result.success)
        self.assertEqual(tool.calls[0][0], {"direction": "up", "steps": 1})

    async def test_session_id_reaches_the_tool_context(self) -> None:
        manager = self.build()
        tool = self.register(manager, FakeDeviceTool("jarvis.noop"))
        result = await manager.request("jarvis.noop", session_id="room-42")
        context = tool.calls[0][1]
        self.assertEqual(context.session_id, "room-42")
        self.assertEqual(context.tool_name, "jarvis.noop")
        self.assertEqual(context.execution_id, result.execution_id)


class SafeFailureTests(ManagerCase):
    async def test_unknown_tool_is_rejected_and_nothing_runs(self) -> None:
        manager = self.build()
        known = self.register(manager, FakeDeviceTool("jarvis.noop"))

        result = await manager.request("pc.power.shutdown")

        self.assertFalse(result.success)
        self.assertFalse(result.executed)
        self.assertEqual(result.status, ToolResultStatus.FAILED)
        self.assertEqual(result.error_code, ErrorCode.UNKNOWN_TOOL)
        self.assertEqual(result.data["registered_tools"], ["jarvis.noop"])
        self.assertEqual(known.call_count, 0)

    async def test_unavailable_tool_returns_unavailable(self) -> None:
        manager = self.build()
        tool = self.register(
            manager,
            FakeDeviceTool("android.sms.send", platform=Platform.ANDROID, available=False),
        )
        result = await manager.request("android.sms.send")
        self.assertEqual(result.status, ToolResultStatus.UNAVAILABLE)
        self.assertEqual(result.error_code, ErrorCode.TOOL_UNAVAILABLE)
        self.assertEqual(tool.call_count, 0)

    async def test_missing_required_argument(self) -> None:
        manager = self.build()
        tool = self.register(
            manager, FakeDeviceTool("pc.audio.volume", platform=Platform.PC, argument_schema=DIRECTION_SCHEMA)
        )
        result = await manager.request("pc.audio.volume", {})
        self.assertEqual(result.status, ToolResultStatus.INVALID_ARGUMENT)
        self.assertIn("direction", result.error)
        self.assertEqual(tool.call_count, 0)

    async def test_wrong_argument_type(self) -> None:
        manager = self.build()
        tool = self.register(
            manager, FakeDeviceTool("pc.audio.volume", platform=Platform.PC, argument_schema=DIRECTION_SCHEMA)
        )
        result = await manager.request("pc.audio.volume", {"direction": 5})
        self.assertEqual(result.status, ToolResultStatus.INVALID_ARGUMENT)
        self.assertEqual(tool.call_count, 0)

    async def test_unexpected_argument_is_rejected(self) -> None:
        manager = self.build()
        tool = self.register(
            manager, FakeDeviceTool("pc.audio.volume", platform=Platform.PC, argument_schema=DIRECTION_SCHEMA)
        )
        result = await manager.request("pc.audio.volume", {"direction": "up", "shell": "rm -rf /"})
        self.assertEqual(result.status, ToolResultStatus.INVALID_ARGUMENT)
        self.assertIn("unexpected argument", result.error)
        self.assertEqual(tool.call_count, 0)

    async def test_argument_outside_choices(self) -> None:
        manager = self.build()
        tool = self.register(
            manager, FakeDeviceTool("pc.audio.volume", platform=Platform.PC, argument_schema=DIRECTION_SCHEMA)
        )
        result = await manager.request("pc.audio.volume", {"direction": "sideways"})
        self.assertEqual(result.status, ToolResultStatus.INVALID_ARGUMENT)
        self.assertEqual(tool.call_count, 0)

    async def test_missing_permission_is_explicit(self) -> None:
        manager = self.build(granted=(MEDIA,))
        tool = self.register(
            manager,
            FakeDeviceTool(
                "comms.sms.send",
                platform=Platform.PC,
                risk_level=RiskLevel.EXTERNAL_ACTION,
                required_permissions=(MESSAGING,),
                argument_schema=MESSAGE_SCHEMA,
            ),
        )
        result = await manager.request(
            "comms.sms.send", {"recipient": "Sarthak", "body": "hello"}
        )
        self.assertEqual(result.status, ToolResultStatus.PERMISSION_DENIED)
        self.assertEqual(result.error_code, ErrorCode.PERMISSION_DENIED)
        self.assertEqual(result.data["missing_permissions"], [MESSAGING])
        self.assertIn(MESSAGING, result.message)
        self.assertEqual(tool.call_count, 0)

    async def test_blocked_tool_is_refused(self) -> None:
        manager = self.build()
        manager.permissions.block_tool("pc.audio.volume")
        tool = self.register(
            manager, FakeDeviceTool("pc.audio.volume", platform=Platform.PC, argument_schema=DIRECTION_SCHEMA)
        )
        result = await manager.request("pc.audio.volume", {"direction": "up"})
        self.assertEqual(result.status, ToolResultStatus.PERMISSION_DENIED)
        self.assertEqual(result.error_code, ErrorCode.TOOL_BLOCKED)
        self.assertEqual(tool.call_count, 0)

    async def test_missing_platform_adapter(self) -> None:
        manager = self.build()  # only a PC adapter is registered
        tool = self.register(
            manager,
            FakeDeviceTool(
                "android.sms.send",
                platform=Platform.ANDROID,
                required_permissions=(),
                argument_schema=MESSAGE_SCHEMA,
            ),
        )
        result = await manager.request(
            "android.sms.send", {"recipient": "Sarthak", "body": "hello"}
        )
        self.assertEqual(result.status, ToolResultStatus.UNAVAILABLE)
        self.assertEqual(result.error_code, ErrorCode.PLATFORM_UNAVAILABLE)
        self.assertEqual(tool.call_count, 0)

    async def test_unreachable_device(self) -> None:
        manager = self.build(adapters=(FakeAdapter(Platform.PC, available=False),))
        tool = self.register(
            manager, FakeDeviceTool("pc.audio.volume", platform=Platform.PC, argument_schema=DIRECTION_SCHEMA)
        )
        result = await manager.request("pc.audio.volume", {"direction": "up"})
        self.assertEqual(result.status, ToolResultStatus.UNAVAILABLE)
        self.assertEqual(result.error_code, ErrorCode.DEVICE_UNAVAILABLE)
        self.assertEqual(tool.call_count, 0)

    async def test_tool_exception_becomes_a_failed_result(self) -> None:
        manager = self.build()
        tool = self.register(
            manager,
            FakeDeviceTool("pc.boom", platform=Platform.PC, error=RuntimeError("device offline")),
        )
        result = await manager.request("pc.boom")
        self.assertFalse(result.success)
        self.assertEqual(result.status, ToolResultStatus.FAILED)
        self.assertEqual(result.error_code, ErrorCode.TOOL_ERROR)
        self.assertIn("device offline", result.error)
        self.assertEqual(tool.call_count, 1)

    async def test_non_result_return_value_never_counts_as_success(self) -> None:
        manager = self.build()
        self.register(manager, StringReturningTool("pc.liar", platform=Platform.PC))
        result = await manager.request("pc.liar")
        self.assertFalse(result.success)
        self.assertEqual(result.status, ToolResultStatus.FAILED)
        self.assertIn("instead of ToolResult", result.message)

    async def test_execution_timeout(self) -> None:
        manager = self.build(execution_timeout=0.05)
        self.register(manager, FakeDeviceTool("pc.slow", platform=Platform.PC, delay=1.0))
        result = await manager.request("pc.slow")
        self.assertEqual(result.status, ToolResultStatus.TIMEOUT)
        self.assertFalse(result.success)

    async def test_result_ids_are_always_stamped(self) -> None:
        manager = self.build()
        self.register(
            manager,
            FakeDeviceTool(
                "pc.audio.volume",
                platform=Platform.PC,
                result=ToolResult.ok("done"),  # no ids, no tool name
            ),
        )
        result = await manager.request("pc.audio.volume")
        self.assertEqual(result.tool_name, "pc.audio.volume")
        self.assertTrue(result.execution_id.startswith("exec-"))


class ConfirmationGateTests(ManagerCase):
    def destructive_tool(self, manager: DeviceActionManager) -> FakeDeviceTool:
        return self.register(
            manager,
            FakeDeviceTool(
                "pc.power.shutdown",
                platform=Platform.PC,
                risk_level=RiskLevel.DESTRUCTIVE,
                required_permissions=(POWER,),
            ),
        )

    async def test_sensitive_action_is_not_executed_without_confirmation(self) -> None:
        manager = self.build()
        tool = self.destructive_tool(manager)

        result = await manager.request("pc.power.shutdown")

        self.assertEqual(result.status, ToolResultStatus.PENDING_CONFIRMATION)
        self.assertFalse(result.success)
        self.assertFalse(result.executed)
        self.assertEqual(result.error_code, ErrorCode.CONFIRMATION_REQUIRED)
        self.assertTrue(result.data["confirmation_id"].startswith("cfm-"))
        self.assertEqual(tool.call_count, 0)
        self.assertEqual(len(manager.pending_confirmations()), 1)

    async def test_stored_arguments_survive_the_confirmation(self) -> None:
        manager = self.build(granted=(MESSAGING,))
        tool = self.register(
            manager,
            FakeDeviceTool(
                "comms.sms.send",
                platform=Platform.PC,
                risk_level=RiskLevel.EXTERNAL_ACTION,
                required_permissions=(MESSAGING,),
                argument_schema=MESSAGE_SCHEMA,
            ),
        )
        pending = await manager.request(
            "comms.sms.send", {"recipient": "Sarthak", "body": "on my way"}
        )
        confirmation_id = pending.data["confirmation_id"]

        result = await manager.resolve_confirmation(confirmation_id, True)

        self.assertTrue(result.success)
        self.assertEqual(tool.call_count, 1)
        self.assertEqual(tool.calls[0][0], {"recipient": "Sarthak", "body": "on my way"})

    async def test_denied_confirmation_executes_nothing(self) -> None:
        manager = self.build()
        tool = self.destructive_tool(manager)
        pending = await manager.request("pc.power.shutdown")

        result = await manager.resolve_confirmation(pending.data["confirmation_id"], False)

        self.assertEqual(result.status, ToolResultStatus.DENIED)
        self.assertFalse(result.success)
        self.assertEqual(tool.call_count, 0)
        self.assertEqual(
            manager.confirmations.get(pending.data["confirmation_id"]).status,
            ConfirmationStatus.DENIED,
        )

    async def test_cancelled_confirmation_executes_nothing(self) -> None:
        manager = self.build()
        tool = self.destructive_tool(manager)
        pending = await manager.request("pc.power.shutdown")

        result = await manager.cancel_confirmation(pending.data["confirmation_id"])

        self.assertEqual(result.status, ToolResultStatus.CANCELLED)
        self.assertEqual(tool.call_count, 0)

        replay = await manager.request(
            "pc.power.shutdown", confirmation_id=pending.data["confirmation_id"]
        )
        self.assertEqual(replay.status, ToolResultStatus.CANCELLED)
        self.assertEqual(tool.call_count, 0)

    async def test_expired_confirmation_times_out(self) -> None:
        clock = FakeClock()
        manager = self.build(clock=clock)
        tool = self.destructive_tool(manager)
        pending = await manager.request("pc.power.shutdown")
        confirmation_id = pending.data["confirmation_id"]

        clock.advance(TTL * 2)
        result = await manager.resolve_confirmation(confirmation_id, True)

        self.assertEqual(result.status, ToolResultStatus.TIMEOUT)
        self.assertEqual(result.error_code, ErrorCode.CONFIRMATION_EXPIRED)
        self.assertEqual(tool.call_count, 0)

    async def test_expired_confirmation_reported_on_the_request_path(self) -> None:
        clock = FakeClock()
        manager = self.build(clock=clock)
        tool = self.destructive_tool(manager)
        pending = await manager.request("pc.power.shutdown")
        clock.advance(TTL * 2)

        result = await manager.request(
            "pc.power.shutdown", confirmation_id=pending.data["confirmation_id"]
        )
        self.assertEqual(result.status, ToolResultStatus.TIMEOUT)
        self.assertEqual(tool.call_count, 0)

    async def test_unknown_confirmation_is_rejected(self) -> None:
        manager = self.build()
        tool = self.destructive_tool(manager)

        direct = await manager.request("pc.power.shutdown", confirmation_id="cfm-nope")
        self.assertEqual(direct.status, ToolResultStatus.FAILED)
        self.assertEqual(direct.error_code, ErrorCode.UNKNOWN_CONFIRMATION)

        resolved = await manager.resolve_confirmation("cfm-nope", True)
        self.assertEqual(resolved.status, ToolResultStatus.FAILED)
        self.assertEqual(resolved.error_code, ErrorCode.UNKNOWN_CONFIRMATION)
        self.assertEqual(tool.call_count, 0)

    async def test_confirmation_cannot_be_replayed(self) -> None:
        manager = self.build()
        tool = self.destructive_tool(manager)
        pending = await manager.request("pc.power.shutdown")
        confirmation_id = pending.data["confirmation_id"]

        first = await manager.resolve_confirmation(confirmation_id, True)
        second = await manager.resolve_confirmation(confirmation_id, True)

        self.assertTrue(first.success)
        self.assertFalse(second.success)
        self.assertEqual(second.status, ToolResultStatus.FAILED)
        self.assertEqual(second.error_code, ErrorCode.CONFIRMATION_REUSED)
        self.assertEqual(tool.call_count, 1)

    async def test_confirmation_cannot_be_used_for_another_tool(self) -> None:
        manager = self.build()
        self.destructive_tool(manager)
        self.register(
            manager,
            FakeDeviceTool(
                "pc.power.restart",
                platform=Platform.PC,
                risk_level=RiskLevel.DESTRUCTIVE,
                required_permissions=(POWER,),
            ),
        )
        pending = await manager.request("pc.power.shutdown")

        result = await manager.request(
            "pc.power.restart", confirmation_id=pending.data["confirmation_id"]
        )
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, ErrorCode.CONFIRMATION_MISMATCH)

    async def test_pending_confirmation_stays_pending(self) -> None:
        manager = self.build()
        tool = self.destructive_tool(manager)
        pending = await manager.request("pc.power.shutdown")
        again = await manager.request(
            "pc.power.shutdown", confirmation_id=pending.data["confirmation_id"]
        )
        self.assertEqual(again.status, ToolResultStatus.PENDING_CONFIRMATION)
        self.assertEqual(again.error_code, ErrorCode.CONFIRMATION_PENDING)
        self.assertEqual(tool.call_count, 0)

    async def test_low_risk_action_needs_no_confirmation(self) -> None:
        manager = self.build()
        tool = self.register(
            manager,
            FakeDeviceTool(
                "pc.audio.volume",
                platform=Platform.PC,
                risk_level=RiskLevel.LOW_RISK,
                required_permissions=(MEDIA,),
                argument_schema=DIRECTION_SCHEMA,
            ),
        )
        result = await manager.request("pc.audio.volume", {"direction": "up"})
        self.assertTrue(result.success)
        self.assertEqual(tool.call_count, 1)
        self.assertEqual(manager.pending_confirmations(), ())

    async def test_tool_can_force_a_confirmation(self) -> None:
        manager = self.build()
        tool = self.register(
            manager,
            FakeDeviceTool(
                "pc.audio.volume",
                platform=Platform.PC,
                risk_level=RiskLevel.LOW_RISK,
                requires_confirmation=True,
                argument_schema=DIRECTION_SCHEMA,
            ),
        )
        result = await manager.request("pc.audio.volume", {"direction": "up"})
        self.assertEqual(result.status, ToolResultStatus.PENDING_CONFIRMATION)
        self.assertEqual(tool.call_count, 0)


class IntrospectionTests(ManagerCase):
    async def test_list_and_describe_tools(self) -> None:
        manager = self.build()
        self.register(manager, FakeDeviceTool("pc.audio.volume", platform=Platform.PC))
        self.register(manager, FakeDeviceTool("android.sms.send", platform=Platform.ANDROID, available=False))

        self.assertEqual([tool.name for tool in manager.list_tools()], ["android.sms.send", "pc.audio.volume"])
        self.assertEqual(
            [tool.name for tool in manager.list_tools(platform=Platform.PC)],
            ["pc.audio.volume"],
        )
        described = {entry["name"]: entry for entry in manager.describe_tools()}
        self.assertFalse(described["android.sms.send"]["available"])
        self.assertTrue(described["pc.audio.volume"]["available"])

    async def test_pending_confirmations_summary_excludes_argument_values(self) -> None:
        manager = self.build(granted=(MESSAGING,))
        self.register(
            manager,
            FakeDeviceTool(
                "comms.sms.send",
                platform=Platform.PC,
                risk_level=RiskLevel.EXTERNAL_ACTION,
                required_permissions=(MESSAGING,),
                argument_schema=MESSAGE_SCHEMA,
            ),
        )
        await manager.request("comms.sms.send", {"recipient": "Sarthak", "body": "private note"})
        summary = manager.pending_confirmations()
        self.assertEqual(len(summary), 1)
        self.assertEqual(summary[0]["argument_names"], ["body", "recipient"])
        self.assertNotIn("private note", str(summary))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
