"""Execution id + structured lifecycle logging tests (Phase 1)."""

from __future__ import annotations

import unittest
from datetime import timedelta

from jarvis_devices import (
    ArgumentSchema,
    ArgumentSpec,
    AuditLogger,
    ConfirmationManager,
    DeviceActionManager,
    DeviceToolRegistry,
    PermissionPolicy,
    Platform,
    PlatformRegistry,
    RiskLevel,
    ToolLifecycleEvent,
    new_confirmation_id,
    new_execution_id,
)
from jarvis_devices.audit import Redactor

try:  # imported as part of the ``tests`` package (pytest / discover -t .)
    from .support import AuditCapture, FakeAdapter, FakeDeviceTool
except ImportError:  # ``python -m unittest discover -s tests``
    from support import AuditCapture, FakeAdapter, FakeDeviceTool


class ExecutionIdTests(unittest.TestCase):
    def test_execution_ids_are_generated_with_a_prefix(self) -> None:
        execution_id = new_execution_id()
        self.assertTrue(execution_id.startswith("exec-"))
        self.assertGreater(len(execution_id), len("exec-"))

    def test_execution_ids_are_unique(self) -> None:
        ids = {new_execution_id() for _ in range(5000)}
        self.assertEqual(len(ids), 5000)

    def test_confirmation_ids_are_unique_and_distinct_from_execution_ids(self) -> None:
        ids = {new_confirmation_id() for _ in range(2000)}
        self.assertEqual(len(ids), 2000)
        self.assertTrue(all(cid.startswith("cfm-") for cid in ids))
        self.assertFalse(ids & {new_execution_id() for _ in range(2000)})

    def test_custom_prefix(self) -> None:
        self.assertTrue(new_execution_id(prefix="req").startswith("req-"))


def build_manager() -> "tuple[DeviceActionManager, AuditCapture]":
    audit = AuditLogger(enabled=False)
    capture = AuditCapture(audit)
    registry = DeviceToolRegistry()
    platforms = PlatformRegistry()
    platforms.register(FakeAdapter(Platform.PC))
    manager = DeviceActionManager(
        registry,
        PermissionPolicy(granted=("device.media.control", "system.power.control")),
        ConfirmationManager(default_ttl=timedelta(minutes=5)),
        platforms,
        audit,
    )
    return manager, capture


class LifecycleLoggingTests(unittest.IsolatedAsyncioTestCase):
    async def test_successful_run_emits_the_full_lifecycle(self) -> None:
        manager, capture = build_manager()
        tool = FakeDeviceTool(
            "pc.audio.volume",
            platform=Platform.PC,
            risk_level=RiskLevel.LOW_RISK,
            required_permissions=("device.media.control",),
            argument_schema=ArgumentSchema(ArgumentSpec("direction", choices=("up", "down"))),
        )
        manager.registry.register(tool)

        result = await manager.request("pc.audio.volume", {"direction": "up"})

        self.assertTrue(result.success)
        self.assertTrue(result.execution_id.startswith("exec-"))
        self.assertEqual(
            capture.events,
            [
                ToolLifecycleEvent.TOOL_REQUESTED.value,
                ToolLifecycleEvent.PERMISSION_CHECKED.value,
                ToolLifecycleEvent.EXECUTION_STARTED.value,
                ToolLifecycleEvent.EXECUTION_COMPLETED.value,
            ],
        )
        for record in capture.for_execution(result.execution_id):
            self.assertEqual(record.get("tool"), "pc.audio.volume")

    async def test_every_request_gets_a_distinct_execution_id(self) -> None:
        manager, capture = build_manager()
        manager.registry.register(FakeDeviceTool("pc.noop"))
        first = await manager.request("pc.noop")
        second = await manager.request("pc.noop")
        self.assertNotEqual(first.execution_id, second.execution_id)
        self.assertEqual(len({r["execution_id"] for r in capture.records}), 2)

    async def test_failed_run_emits_execution_failed(self) -> None:
        manager, capture = build_manager()
        manager.registry.register(FakeDeviceTool("pc.boom", error=RuntimeError("device offline")))
        result = await manager.request("pc.boom")
        self.assertFalse(result.success)
        self.assertEqual(capture.events[-1], ToolLifecycleEvent.EXECUTION_FAILED.value)
        self.assertIn("device offline", capture.records[-1]["error"])
        self.assertIn("did not complete", capture.records[-1]["detail"])

    async def test_rejected_requests_are_still_logged(self) -> None:
        manager, capture = build_manager()
        await manager.request("does.not.exist")
        self.assertEqual(
            capture.events,
            [ToolLifecycleEvent.TOOL_REQUESTED.value, ToolLifecycleEvent.EXECUTION_FAILED.value],
        )
        self.assertEqual(capture.records[-1]["error_code"], "unknown_tool")

    async def test_confirmation_lifecycle_events(self) -> None:
        manager, capture = build_manager()
        tool = FakeDeviceTool(
            "pc.power.shutdown",
            platform=Platform.PC,
            risk_level=RiskLevel.DESTRUCTIVE,
            required_permissions=("system.power.control",),
        )
        manager.registry.register(tool)

        pending = await manager.request("pc.power.shutdown")
        self.assertEqual(tool.call_count, 0)
        confirmation_id = pending.data["confirmation_id"]

        final = await manager.resolve_confirmation(confirmation_id, True)
        self.assertTrue(final.success)
        self.assertEqual(
            capture.events,
            [
                ToolLifecycleEvent.TOOL_REQUESTED.value,
                ToolLifecycleEvent.PERMISSION_CHECKED.value,
                ToolLifecycleEvent.CONFIRMATION_REQUESTED.value,
                ToolLifecycleEvent.TOOL_REQUESTED.value,
                ToolLifecycleEvent.PERMISSION_CHECKED.value,
                ToolLifecycleEvent.CONFIRMATION_RECEIVED.value,
                ToolLifecycleEvent.EXECUTION_STARTED.value,
                ToolLifecycleEvent.EXECUTION_COMPLETED.value,
            ],
        )


class RedactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.audit = AuditLogger(enabled=False)
        self.capture = AuditCapture(self.audit)

    def test_sensitive_keys_are_replaced(self) -> None:
        self.audit.log(
            ToolLifecycleEvent.TOOL_REQUESTED,
            api_key="AIzaSySECRETVALUE",
            password="hunter2",
            message_body="Meet me at 5pm",
            phone_number="+919000000000",
            status="success",
        )
        raw = self.capture.raw_text()
        for secret in ("AIzaSySECRETVALUE", "hunter2", "Meet me at 5pm", "+919000000000"):
            self.assertNotIn(secret, raw)
        self.assertEqual(self.capture.records[0]["api_key"], "[redacted]")

    def test_embedded_secrets_in_free_text_are_masked(self) -> None:
        redactor = Redactor()
        cleaned = redactor.redact_text("using api_key=AIzaSySECRETVALUE now")
        self.assertNotIn("AIzaSySECRETVALUE", cleaned)
        self.assertIn("[redacted]", cleaned)

    def test_emails_and_phone_numbers_are_masked(self) -> None:
        redactor = Redactor()
        self.assertNotIn("sarthak@example.com", redactor.redact_text("mail sarthak@example.com"))
        self.assertNotIn("+91 90000 00000", redactor.redact_text("call +91 90000 00000"))

    def test_long_text_is_truncated(self) -> None:
        redactor = Redactor(max_text_length=40)
        self.assertLessEqual(len(redactor.redact_text("x" * 500)), 41)

    def test_iso_timestamps_survive_redaction(self) -> None:
        self.audit.log(
            ToolLifecycleEvent.CONFIRMATION_REQUESTED,
            expires_at="2026-09-08T11:01:21.452767+00:00",
        )
        self.assertEqual(
            self.capture.records[0]["expires_at"],
            "2026-09-08T11:01:21.452767+00:00",
        )

    def test_execution_ids_survive_redaction(self) -> None:
        self.audit.log(ToolLifecycleEvent.EXECUTION_STARTED, execution_id="exec-1234567890abcdef")
        self.assertEqual(self.capture.records[0]["execution_id"], "exec-1234567890abcdef")


class ArgumentRedactionTests(unittest.IsolatedAsyncioTestCase):
    async def test_argument_values_are_never_logged(self) -> None:
        manager, capture = build_manager()
        tool = FakeDeviceTool(
            "comms.sms.send",
            platform=Platform.PC,
            risk_level=RiskLevel.SAFE,
            argument_schema=ArgumentSchema(
                ArgumentSpec("recipient"),
                ArgumentSpec("message"),
            ),
        )
        manager.registry.register(tool)

        result = await manager.request(
            "comms.sms.send",
            {"recipient": "+919000000000", "message": "the otp is 441233"},
        )

        self.assertTrue(result.success)
        raw = capture.raw_text()
        self.assertNotIn("+919000000000", raw)
        self.assertNotIn("441233", raw)
        self.assertEqual(capture.records[0]["argument_names"], ["message", "recipient"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
