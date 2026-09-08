"""Phase 4 PC power tool tests - driven through the DeviceActionManager.

Every test injects a fake backend and a fake platform probe, so no real machine
is ever shut down, restarted, suspended or logged off - on any operating system.
"""

from __future__ import annotations

import unittest
from datetime import timedelta

from jarvis_devices import (
    AuditLogger,
    ConfirmationManager,
    ConfirmationPolicy,
    DeviceActionManager,
    DeviceToolRegistry,
    ErrorCode,
    PermissionPolicy,
    Platform,
    PlatformRegistry,
    RiskLevel,
    ToolResultStatus,
)
from jarvis_devices.permissions import PERMISSION_POWER_CONTROL
from jarvis_devices.pc_power import (
    ALL_OPERATIONS,
    PC_POWER_TOOL_NAMES,
    PCPowerBackendError,
    PowerPrivilegeError,
    UnsupportedPowerOperationError,
    build_pc_power_tools,
)
from jarvis_devices.pc_system import Capability

try:  # imported as part of the ``tests`` package (pytest / discover -t .)
    from .pc_power_support import FakePCPowerBackend
    from .support import FakeAdapter, FakeClock
except ImportError:  # ``python -m unittest discover -s tests``
    from pc_power_support import FakePCPowerBackend
    from support import FakeAdapter, FakeClock

TOOL_NAMES = {operation: f"pc.power.{operation}" for operation in ALL_OPERATIONS}
ALL_TOOLS = tuple(TOOL_NAMES.values())


class PCPowerToolCase(unittest.IsolatedAsyncioTestCase):
    """Wires the Phase 4 tools into a real DeviceActionManager."""

    def build(
        self,
        *,
        backend=None,
        granted=(PERMISSION_POWER_CONTROL,),
        platform=Platform.PC,
        confirmation_policy=None,
        adapters=(Platform.PC,),
        clock=None,
    ) -> DeviceActionManager:
        self.backend = backend if backend is not None else FakePCPowerBackend()
        registry = DeviceToolRegistry()
        registry.register_all(build_pc_power_tools(self.backend, platform_probe=lambda: platform))
        platforms = PlatformRegistry()
        for adapter_platform in adapters:
            platforms.register(FakeAdapter(adapter_platform))
        policy = confirmation_policy or ConfirmationPolicy()
        confirmations = ConfirmationManager(policy=policy) if clock is None else ConfirmationManager(
            policy=policy, clock=clock
        )
        return DeviceActionManager(
            registry,
            PermissionPolicy(granted=granted),
            confirmations,
            platforms,
            AuditLogger(enabled=False),
            confirmation_policy=policy,
        )


# ---------------------------------------------------------------------------
# Declarations
# ---------------------------------------------------------------------------
class DeclarationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tools = {
            tool.name: tool
            for tool in build_pc_power_tools(FakePCPowerBackend(), platform_probe=lambda: Platform.PC)
        }

    def test_the_five_tools_are_declared_for_the_pc_platform(self) -> None:
        self.assertEqual(len(self.tools), 5)
        self.assertEqual(sorted(self.tools), sorted(PC_POWER_TOOL_NAMES))
        self.assertEqual(sorted(self.tools), sorted(ALL_TOOLS))
        for tool in self.tools.values():
            with self.subTest(tool=tool.name):
                self.assertIs(tool.platform, Platform.PC)
                self.assertTrue(tool.is_available())

    def test_every_power_tool_is_an_external_action_needing_the_power_permission(self) -> None:
        for tool in self.tools.values():
            with self.subTest(tool=tool.name):
                self.assertIs(tool.risk_level, RiskLevel.EXTERNAL_ACTION)
                self.assertEqual(tool.required_permissions, (PERMISSION_POWER_CONTROL,))

    def test_confirmation_is_declared_and_cannot_be_switched_off(self) -> None:
        for tool in self.tools.values():
            with self.subTest(tool=tool.name):
                self.assertTrue(tool.requires_confirmation)
                self.assertTrue(tool.confirmation_mandatory)

    def test_no_power_tool_accepts_any_argument(self) -> None:
        """Simplicity is the security feature: no flags, no target, no command."""
        for tool in self.tools.values():
            with self.subTest(tool=tool.name):
                self.assertEqual(tool.argument_schema.names, ())
                self.assertEqual(len(tool.argument_schema), 0)

    def test_every_tool_maps_to_exactly_one_operation(self) -> None:
        operations = [tool.operation for tool in self.tools.values()]
        self.assertEqual(sorted(operations), sorted(ALL_OPERATIONS))
        self.assertEqual(len(set(operations)), 5)

    def test_an_unknown_operation_cannot_be_declared(self) -> None:
        from jarvis_devices.pc_power import PowerTool

        class Broken(PowerTool):
            name = "pc.power.wipe"
            description = "nope"
            operation = "wipe"

        with self.assertRaises(ValueError):
            Broken(FakePCPowerBackend())


# ---------------------------------------------------------------------------
# The full matrix, per operation
# ---------------------------------------------------------------------------
class PowerOperationMatrixTests(PCPowerToolCase):
    """Every operation gets the same nine-scenario treatment."""

    async def test_permission_is_required(self) -> None:
        manager = self.build(granted=())
        for name in ALL_TOOLS:
            with self.subTest(tool=name):
                result = await manager.request(name)
                self.assertEqual(result.status, ToolResultStatus.PERMISSION_DENIED)
                self.assertEqual(result.error_code, ErrorCode.PERMISSION_DENIED)
                self.assertFalse(result.executed)
        self.assertEqual(self.backend.calls, [])

    async def test_confirmation_is_required_first(self) -> None:
        manager = self.build()
        for name in ALL_TOOLS:
            with self.subTest(tool=name):
                result = await manager.request(name)
                self.assertEqual(result.status, ToolResultStatus.PENDING_CONFIRMATION)
                self.assertEqual(result.error_code, ErrorCode.CONFIRMATION_REQUIRED)
                self.assertIn("confirmation_id", result.data)
        self.assertEqual(self.backend.calls, [], "an unconfirmed power call reached the backend")

    async def test_an_approved_confirmation_runs_exactly_once(self) -> None:
        for name in ALL_TOOLS:
            with self.subTest(tool=name):
                manager = self.build()
                asked = await manager.request(name)
                done = await manager.resolve_confirmation(asked.data["confirmation_id"], True)
                self.assertTrue(done.success, done.message)
                self.assertTrue(done.data["initiated"])
                self.assertEqual(self.backend.calls, [name.split(".")[-1]])

    async def test_a_declined_confirmation_runs_nothing(self) -> None:
        for name in ALL_TOOLS:
            with self.subTest(tool=name):
                manager = self.build()
                asked = await manager.request(name)
                denied = await manager.resolve_confirmation(asked.data["confirmation_id"], False)
                self.assertEqual(denied.status, ToolResultStatus.DENIED)
                self.assertEqual(self.backend.calls, [])

    async def test_a_backend_failure_is_reported_honestly(self) -> None:
        for name in ALL_TOOLS:
            with self.subTest(tool=name):
                backend = FakePCPowerBackend()
                backend.fail_with(name.split(".")[-1], PCPowerBackendError("Windows said no"))
                manager = self.build(backend=backend)
                asked = await manager.request(name)
                done = await manager.resolve_confirmation(asked.data["confirmation_id"], True)
                self.assertEqual(done.status, ToolResultStatus.FAILED)
                self.assertEqual(done.error_code, ErrorCode.POWER_CONTROL_FAILED)
                self.assertFalse(done.success)

    async def test_an_unsupported_operation_is_unavailable_not_failed(self) -> None:
        for name in ALL_TOOLS:
            with self.subTest(tool=name):
                backend = FakePCPowerBackend()
                operation = name.split(".")[-1]
                backend.fail_with(operation, UnsupportedPowerOperationError("no hibernation file"))
                manager = self.build(backend=backend)
                asked = await manager.request(name)
                done = await manager.resolve_confirmation(asked.data["confirmation_id"], True)
                self.assertEqual(done.status, ToolResultStatus.UNAVAILABLE)
                self.assertEqual(done.error_code, ErrorCode.POWER_OPERATION_UNSUPPORTED)

    async def test_a_missing_privilege_is_named_as_such(self) -> None:
        for name in ALL_TOOLS:
            with self.subTest(tool=name):
                backend = FakePCPowerBackend()
                backend.fail_with(
                    name.split(".")[-1], PowerPrivilegeError("SeShutdownPrivilege is not held")
                )
                manager = self.build(backend=backend)
                asked = await manager.request(name)
                done = await manager.resolve_confirmation(asked.data["confirmation_id"], True)
                self.assertEqual(done.status, ToolResultStatus.FAILED)
                self.assertEqual(done.error_code, ErrorCode.POWER_PRIVILEGE_REQUIRED)

    async def test_an_unsupported_capability_blocks_before_the_backend_runs(self) -> None:
        for name in ALL_TOOLS:
            with self.subTest(tool=name):
                operation = name.split(".")[-1]
                capabilities = {op: Capability.SUPPORTED for op in ALL_OPERATIONS}
                capabilities[operation] = Capability.UNSUPPORTED
                manager = self.build(backend=FakePCPowerBackend(capabilities=capabilities))
                asked = await manager.request(name)
                done = await manager.resolve_confirmation(asked.data["confirmation_id"], True)
                self.assertEqual(done.status, ToolResultStatus.UNAVAILABLE)
                self.assertEqual(done.error_code, ErrorCode.POWER_OPERATION_UNSUPPORTED)
                self.assertEqual(self.backend.calls, [])


# ---------------------------------------------------------------------------
# Confirmation safety (section 7 / 19)
# ---------------------------------------------------------------------------
class ConfirmationSafetyTests(PCPowerToolCase):
    async def test_a_shutdown_confirmation_cannot_authorise_a_restart(self) -> None:
        manager = self.build()
        asked = await manager.request("pc.power.shutdown")
        # Handing that id to a different tool must not execute anything.
        hijacked = await manager.request(
            "pc.power.restart", {}, confirmation_id=asked.data["confirmation_id"]
        )
        self.assertEqual(hijacked.error_code, ErrorCode.CONFIRMATION_MISMATCH)
        self.assertFalse(hijacked.success)
        self.assertEqual(self.backend.calls, [])

    async def test_a_confirmation_cannot_be_consumed_twice(self) -> None:
        manager = self.build()
        asked = await manager.request("pc.power.shutdown")
        cid = asked.data["confirmation_id"]
        first = await manager.resolve_confirmation(cid, True)
        self.assertTrue(first.success)
        second = await manager.resolve_confirmation(cid, True)
        self.assertFalse(second.success)
        self.assertEqual(second.error_code, ErrorCode.CONFIRMATION_REUSED)
        self.assertEqual(self.backend.calls, ["shutdown"], "shutdown ran more than once")

    async def test_a_confirmation_expires(self) -> None:
        clock = FakeClock()
        manager = self.build(clock=clock)
        asked = await manager.request("pc.power.hibernate")
        clock.advance(timedelta(minutes=30))  # the default TTL is 5 minutes
        late = await manager.resolve_confirmation(asked.data["confirmation_id"], True)
        self.assertEqual(late.status, ToolResultStatus.TIMEOUT)
        self.assertEqual(late.error_code, ErrorCode.CONFIRMATION_EXPIRED)
        self.assertEqual(self.backend.calls, [])

    async def test_an_unknown_confirmation_id_is_refused(self) -> None:
        manager = self.build()
        result = await manager.resolve_confirmation("cfm-does-not-exist", True)
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, ErrorCode.UNKNOWN_CONFIRMATION)
        self.assertEqual(self.backend.calls, [])

    async def test_a_policy_cannot_switch_confirmation_off(self) -> None:
        """The whole point of ``confirmation_mandatory``."""
        for policy in (
            ConfirmationPolicy(never_confirm=ALL_TOOLS),
            ConfirmationPolicy(risk_levels=()),
            ConfirmationPolicy(risk_levels=(), never_confirm=ALL_TOOLS),
        ):
            with self.subTest(policy=repr(policy.risk_levels)):
                manager = self.build(confirmation_policy=policy)
                for name in ALL_TOOLS:
                    with self.subTest(tool=name):
                        result = await manager.request(name)
                        self.assertEqual(result.status, ToolResultStatus.PENDING_CONFIRMATION)
                        self.assertEqual(self.backend.calls, [])

    async def test_repeated_requests_create_separate_single_use_confirmations(self) -> None:
        manager = self.build()
        first = await manager.request("pc.power.logoff")
        second = await manager.request("pc.power.logoff")
        self.assertNotEqual(first.data["confirmation_id"], second.data["confirmation_id"])
        approved = await manager.resolve_confirmation(second.data["confirmation_id"], True)
        self.assertTrue(approved.success)
        # The other request is still pending and must not run on its own.
        self.assertEqual(self.backend.calls, ["logoff"])
        stale = await manager.resolve_confirmation(first.data["confirmation_id"], True)
        self.assertTrue(stale.success)  # its own explicit yes
        self.assertEqual(self.backend.calls, ["logoff", "logoff"])

    async def test_confirming_without_a_prior_request_does_nothing(self) -> None:
        manager = self.build()
        for name in ALL_TOOLS:
            with self.subTest(tool=name):
                result = await manager.request(name, {}, confirmation_id="cfm-never-issued")
                self.assertFalse(result.success)
                self.assertEqual(self.backend.calls, [])


# ---------------------------------------------------------------------------
# Platform / availability
# ---------------------------------------------------------------------------
class PlatformTests(PCPowerToolCase):
    async def test_off_pc_every_tool_answers_unsupported_platform(self) -> None:
        manager = self.build(platform=Platform.ANDROID, adapters=(Platform.ANDROID,))
        for name in ALL_TOOLS:
            with self.subTest(tool=name):
                result = await manager.request(name)
                self.assertEqual(result.status, ToolResultStatus.UNAVAILABLE)
                self.assertFalse(result.executed)

    async def test_the_tools_themselves_name_the_platform_problem(self) -> None:
        tools = build_pc_power_tools(FakePCPowerBackend(), platform_probe=lambda: Platform.ANDROID)
        for tool in tools:
            with self.subTest(tool=tool.name):
                result = tool.platform_result()
                self.assertEqual(result.error_code, ErrorCode.UNSUPPORTED_PLATFORM)

    async def test_an_unavailable_backend_answers_tool_unavailable(self) -> None:
        manager = self.build(backend=FakePCPowerBackend(available=False))
        for name in ALL_TOOLS:
            with self.subTest(tool=name):
                result = await manager.request(name)
                self.assertEqual(result.status, ToolResultStatus.UNAVAILABLE)
                self.assertEqual(result.error_code, ErrorCode.TOOL_UNAVAILABLE)
                self.assertFalse(result.executed)

    async def test_platform_result_explains_why(self) -> None:
        tools = build_pc_power_tools(FakePCPowerBackend(available=False), platform_probe=lambda: Platform.PC)
        for tool in tools:
            with self.subTest(tool=tool.name):
                result = tool.platform_result()
                self.assertEqual(result.error_code, ErrorCode.POWER_CONTROL_UNAVAILABLE)
                self.assertEqual(result.data["reason"], "the fake power backend is switched off")

    async def test_no_phase_5_operation_exists(self) -> None:
        names = {tool.name for tool in build_pc_power_tools(FakePCPowerBackend(), platform_probe=lambda: Platform.PC)}
        for forbidden in ("android", "call", "message", "sms", "whatsapp", "remote", "force", "timeout"):
            with self.subTest(word=forbidden):
                self.assertFalse(any(forbidden in name for name in names))


# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------
class ArgumentTests(PCPowerToolCase):
    async def test_every_argument_is_rejected(self) -> None:
        manager = self.build()
        hostile = (
            {"timeout": 0},
            {"force": True},
            {"flags": "/f /t 0"},
            {"command": "shutdown /s /t 0"},
            {"remote_host": "\\\\fileserver"},
            {"host": "192.168.1.50"},
            {"reason": "maintenance && calc"},
            {"level": 50},
            {"": ""},
        )
        for name in ALL_TOOLS:
            for arguments in hostile:
                with self.subTest(tool=name, arguments=arguments):
                    result = await manager.request(name, arguments)
                    self.assertEqual(result.status, ToolResultStatus.INVALID_ARGUMENT)
                    self.assertFalse(result.executed)
        self.assertEqual(self.backend.calls, [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
