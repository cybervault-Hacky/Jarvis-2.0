"""Structured tool result tests (Phase 1)."""

from __future__ import annotations

import dataclasses
import unittest

from jarvis_devices import ErrorCode, ToolResult, ToolResultStatus


class ToolResultStatusTests(unittest.TestCase):
    def test_every_required_status_exists(self) -> None:
        required = {
            "SUCCESS",
            "FAILED",
            "DENIED",
            "CANCELLED",
            "TIMEOUT",
            "UNAVAILABLE",
            "INVALID_ARGUMENT",
            "PERMISSION_DENIED",
        }
        self.assertTrue(required.issubset({status.name for status in ToolResultStatus}))

    def test_values_are_stable_strings(self) -> None:
        self.assertEqual(ToolResultStatus.SUCCESS.value, "success")
        self.assertEqual(ToolResultStatus.PERMISSION_DENIED.value, "permission_denied")


class ToolResultSuccessTests(unittest.TestCase):
    def test_ok_is_successful(self) -> None:
        result = ToolResult.ok("Volume raised.", tool_name="pc.audio.volume", execution_id="exec-1",
                               data={"level": 40})
        self.assertTrue(result.success)
        # A bare result does not claim execution; the framework stamps it.
        self.assertFalse(result.executed)
        self.assertTrue(result.marked_executed().executed)
        self.assertEqual(result.status, ToolResultStatus.SUCCESS)
        self.assertEqual(result.data, {"level": 40})
        self.assertIsNone(result.error)
        self.assertIsNone(result.error_code)

    def test_failure_is_not_successful(self) -> None:
        result = ToolResult.failure("Could not raise the volume.", error="RuntimeError: no mixer")
        self.assertFalse(result.success)
        self.assertFalse(result.executed)
        self.assertEqual(result.status, ToolResultStatus.FAILED)
        self.assertEqual(result.error_code, ErrorCode.TOOL_ERROR)
        self.assertIn("no mixer", result.error)

    def test_success_can_never_be_set_directly(self) -> None:
        result = ToolResult.failure("nope")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.success = True  # type: ignore[misc]
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.status = ToolResultStatus.SUCCESS  # type: ignore[misc]
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.executed = True  # type: ignore[misc]

    def test_non_success_statuses_are_all_failures(self) -> None:
        for status in ToolResultStatus:
            with self.subTest(status=status.value):
                result = ToolResult(status=status, message="x")
                self.assertEqual(result.success, status is ToolResultStatus.SUCCESS)


class ToolResultFactoryTests(unittest.TestCase):
    def test_permission_denied(self) -> None:
        result = ToolResult.permission_denied(
            "Needs device.settings.write",
            missing_permissions={"missing_permissions": ["device.settings.write"]},
            tool_name="pc.display.brightness",
        )
        self.assertEqual(result.status, ToolResultStatus.PERMISSION_DENIED)
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, ErrorCode.PERMISSION_DENIED)
        self.assertEqual(result.data["missing_permissions"], ["device.settings.write"])

    def test_invalid_argument(self) -> None:
        result = ToolResult.invalid_argument("missing required argument: 'direction'")
        self.assertEqual(result.status, ToolResultStatus.INVALID_ARGUMENT)
        self.assertEqual(result.error_code, ErrorCode.INVALID_ARGUMENT)
        self.assertFalse(result.success)

    def test_denied(self) -> None:
        result = ToolResult.denied("The user declined the shutdown.")
        self.assertEqual(result.status, ToolResultStatus.DENIED)
        self.assertEqual(result.error_code, ErrorCode.CONFIRMATION_DENIED)

    def test_cancelled(self) -> None:
        result = ToolResult.cancelled()
        self.assertEqual(result.status, ToolResultStatus.CANCELLED)
        self.assertEqual(result.error_code, ErrorCode.CONFIRMATION_CANCELLED)

    def test_timeout(self) -> None:
        result = ToolResult.timeout()
        self.assertEqual(result.status, ToolResultStatus.TIMEOUT)
        self.assertEqual(result.error_code, ErrorCode.CONFIRMATION_EXPIRED)

    def test_unavailable(self) -> None:
        result = ToolResult.unavailable("No Android device paired.", error_code=ErrorCode.DEVICE_UNAVAILABLE)
        self.assertEqual(result.status, ToolResultStatus.UNAVAILABLE)
        self.assertEqual(result.error_code, ErrorCode.DEVICE_UNAVAILABLE)

    def test_pending_confirmation(self) -> None:
        result = ToolResult.pending_confirmation(
            "Please confirm the shutdown.",
            confirmation_id="cfm-1",
            tool_name="pc.power.shutdown",
        )
        self.assertEqual(result.status, ToolResultStatus.PENDING_CONFIRMATION)
        self.assertFalse(result.success)
        self.assertFalse(result.executed)
        self.assertEqual(result.data["confirmation_id"], "cfm-1")
        self.assertTrue(result.data["confirmation_required"])
        self.assertEqual(result.error_code, ErrorCode.CONFIRMATION_REQUIRED)


class ToolResultCopyTests(unittest.TestCase):
    def test_with_ids_stamps_tool_and_execution(self) -> None:
        result = ToolResult.ok("done").with_ids(tool_name="pc.audio.volume", execution_id="exec-42")
        self.assertEqual(result.tool_name, "pc.audio.volume")
        self.assertEqual(result.execution_id, "exec-42")

    def test_with_ids_keeps_existing_values(self) -> None:
        result = ToolResult.ok("done", tool_name="pc.audio.volume", execution_id="exec-1")
        stamped = result.with_ids(tool_name="other", execution_id="")
        self.assertEqual(stamped.execution_id, "exec-1")
        self.assertEqual(stamped.tool_name, "other")

    def test_with_message(self) -> None:
        self.assertEqual(ToolResult.ok("a").with_message("b").message, "b")

    def test_to_dict_shape(self) -> None:
        payload = ToolResult.ok("done", tool_name="t", execution_id="e", data={"a": 1}).to_dict()
        self.assertEqual(
            set(payload),
            {
                "success",
                "status",
                "message",
                "tool_name",
                "execution_id",
                "data",
                "error",
                "error_code",
                "executed",
            },
        )
        self.assertTrue(payload["success"])
        self.assertEqual(payload["data"], {"a": 1})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
