"""Phase 10 end-to-end matrix over the real manager and signed in-memory bridge.

The Android peer is a deterministic fake, not a phone or transport deployment.
It nevertheless exercises the actual pairing identity, Ed25519 frame protocol,
manager validation/permission/confirmation order, and call/message controls.
"""

from __future__ import annotations

import asyncio
import unittest

from jarvis_devices.android_call_tools import build_android_call_tools
from jarvis_devices.android_message_tools import build_android_message_tools
from jarvis_devices.confirmation import ConfirmationManager, ConfirmationPolicy
from jarvis_devices.enums import Platform, ToolResultStatus
from jarvis_devices.manager import DeviceActionManager
from jarvis_devices.permissions import (
    PERMISSION_ANDROID_CALL_READ,
    PERMISSION_ANDROID_CALL_CONTROL,
    PERMISSION_ANDROID_MESSAGE_READ,
    PERMISSION_ANDROID_MESSAGE_SEND,
    PermissionPolicy,
)
from jarvis_devices.adapters import PCDeviceAdapter
from jarvis_devices.platform import PlatformRegistry
from jarvis_devices.registry import DeviceToolRegistry

try:
    from .android_call_support import call_phone_pair
    from .android_message_support import message_phone_pair
except ImportError:  # pragma: no cover
    from android_call_support import call_phone_pair
    from android_message_support import message_phone_pair


def manager_for(tools, permissions):
    registry = DeviceToolRegistry()
    for tool in tools:
        registry.register(tool)
    platforms = PlatformRegistry()
    platforms.register(PCDeviceAdapter())
    return DeviceActionManager(
        registry=registry,
        permissions=PermissionPolicy(granted=permissions),
        confirmations=ConfirmationManager(policy=ConfirmationPolicy()),
        platforms=platforms,
    )


class SignedAndroidEndToEndTests(unittest.IsolatedAsyncioTestCase):
    async def test_call_read_then_confirmed_dial_uses_one_bound_signed_request(self) -> None:
        bridge, phone, control, _, _ = await call_phone_pair()
        manager = manager_for(
            build_android_call_tools(bridge),
            (PERMISSION_ANDROID_CALL_READ, PERMISSION_ANDROID_CALL_CONTROL),
        )
        try:
            # Read path: the companion sees exactly one authenticated status frame.
            serve = asyncio.create_task(phone.serve(max_frames=1))
            status = await manager.request("android.call.status", {"device": phone.device_id})
            await serve
            self.assertEqual(status.status, ToolResultStatus.SUCCESS)
            self.assertTrue(status.success)
            self.assertTrue(status.executed)

            # Action path: no frame before confirmation, then the exact normalized
            # recipient is released exactly once after a human yes.
            requested = await manager.request(
                "android.call.dial", {"device": phone.device_id, "phone_number": "+1 (415) 555-2671"}
            )
            self.assertEqual(requested.status, ToolResultStatus.PENDING_CONFIRMATION)
            self.assertFalse(requested.executed)
            self.assertEqual(phone.call_controller.calls, [("get_status", ())])
            confirmation_id = requested.data["confirmation_id"]
            serve = asyncio.create_task(phone.serve(max_frames=1))
            completed = await manager.resolve_confirmation(confirmation_id, True)
            await serve
            self.assertEqual(completed.status, ToolResultStatus.SUCCESS)
            self.assertTrue(completed.executed)
            self.assertEqual(phone.call_controller.calls[-1][0], "dial")
            self.assertEqual(phone.call_controller.calls[-1][1], ("[redacted]71",))

            replay = await manager.resolve_confirmation(confirmation_id, True)
            self.assertFalse(replay.success)
            self.assertFalse(replay.executed)
            self.assertEqual(len(phone.call_controller.calls), 2)
        finally:
            await bridge.close()

    async def test_message_permission_denial_and_confirmed_acceptance_have_no_fallback(self) -> None:
        bridge, phone, _control, _, _ = await message_phone_pair()
        denied_manager = manager_for(build_android_message_tools(bridge), (PERMISSION_ANDROID_MESSAGE_READ,))
        try:
            denied = await denied_manager.request(
                "android.message.send", {"device": phone.device_id, "recipient": "+14155552671", "message": "hello"}
            )
            self.assertEqual(denied.status, ToolResultStatus.PERMISSION_DENIED)
            self.assertFalse(phone.message_controller.messages)

            manager = manager_for(
                build_android_message_tools(bridge),
                (PERMISSION_ANDROID_MESSAGE_READ, PERMISSION_ANDROID_MESSAGE_SEND),
            )
            pending = await manager.request(
                "android.message.send", {"device": phone.device_id, "recipient": "+1 (415) 555-2671", "message": "Hello, नमस्ते 👋"}
            )
            self.assertEqual(pending.status, ToolResultStatus.PENDING_CONFIRMATION)
            self.assertFalse(phone.message_controller.messages)
            serve = asyncio.create_task(phone.serve(max_frames=1))
            accepted = await manager.resolve_confirmation(pending.data["confirmation_id"], True)
            await serve
            self.assertEqual(accepted.status, ToolResultStatus.SUCCESS)
            self.assertTrue(accepted.executed)
            self.assertEqual(len(phone.message_controller.messages), 1)
        finally:
            await bridge.close()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
