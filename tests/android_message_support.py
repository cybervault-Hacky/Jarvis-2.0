"""Phase 8 deterministic fake Android messaging companion.

This is test infrastructure, not an Android implementation.  It stores only
messages explicitly submitted during the test, does not inspect any history or
contacts, and speaks the real signed/replay-protected bridge protocol by
extending the Phase 7 fake phone.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional, Tuple

from jarvis_devices.android_calls import validate_phone_number
from jarvis_devices.android_messages import (
    MESSAGE_CAPABILITIES,
    AndroidMessageControl,
    MessageDeliveryState,
    validate_message_content,
    validate_message_operation_id,
)
from jarvis_devices.android_protocol import (
    CAPABILITY_MESSAGE_SEND,
    CAPABILITY_MESSAGE_STATUS,
    MessageType,
)

try:
    from .android_call_support import CallCapablePhone, DEFAULT_CALL_CAPABILITIES, answered
except ImportError:  # pragma: no cover
    from android_call_support import CallCapablePhone, DEFAULT_CALL_CAPABILITIES, answered

__all__ = [
    "DEFAULT_MESSAGE_CAPABILITIES",
    "FakeAndroidMessageController",
    "MessageCapablePhone",
    "message_phone_pair",
    "answered",
]

DEFAULT_MESSAGE_CAPABILITIES: Tuple[str, ...] = tuple(
    dict.fromkeys(DEFAULT_CALL_CAPABILITIES + MESSAGE_CAPABILITIES)
)

_MESSAGE_GUARDS = {
    MessageType.MESSAGE_STATUS: CAPABILITY_MESSAGE_STATUS,
    MessageType.MESSAGE_SEND: CAPABILITY_MESSAGE_SEND,
}


class FakeAndroidMessageController:
    """A stateful fake of the future two-method Android messaging contract."""

    def __init__(
        self,
        *,
        capabilities: Tuple[str, ...] = DEFAULT_MESSAGE_CAPABILITIES,
        delivery_state: MessageDeliveryState = MessageDeliveryState.ACCEPTED,
    ) -> None:
        self.capabilities = tuple(capabilities)
        self.delivery_state = delivery_state
        self.available = True
        self.denied: set[str] = set()
        self.unavailable: set[str] = set()
        self.failing: set[str] = set()
        #: Test-private records only. They are never returned by a JARVIS tool.
        self.messages: List[Tuple[str, str, str]] = []
        self.calls: List[Tuple[str, Tuple[Any, ...]]] = []
        self._operations: Dict[str, Tuple[str, str, MessageDeliveryState]] = {}

    def _refusal_for(self, capability: str) -> Optional[Dict[str, Any]]:
        if capability not in self.capabilities:
            return {"ok": False, "error": "unsupported"}
        return None

    def _record(self, name: str, *args: Any) -> Optional[Dict[str, Any]]:
        # No recipient/body values are added to generic call records.
        self.calls.append((name, ()))
        if name in self.denied:
            return {"ok": False, "error": "permission_denied"}
        if name in self.unavailable:
            return {"ok": False, "error": "unavailable"}
        if name in self.failing:
            return {"ok": False, "error": "failed"}
        return None

    async def get_status(self) -> Dict[str, Any]:
        blocked = self._record("get_status") or self._refusal_for(CAPABILITY_MESSAGE_STATUS)
        if blocked:
            return blocked
        return {
            "ok": True,
            "available": self.available,
            "mode": "text",
            "send_supported": self.available and CAPABILITY_MESSAGE_SEND in self.capabilities,
        }

    async def send(self, recipient: str, message: str, operation_id: str) -> Dict[str, Any]:
        # The peer independently validates all three payload fields even after
        # authenticated transport validation, as a future Android companion must.
        blocked = self._record("send") or self._refusal_for(CAPABILITY_MESSAGE_SEND)
        if blocked:
            return blocked
        if not self.available:
            return {"ok": False, "error": "unavailable"}
        try:
            recipient = validate_phone_number(recipient)
            message = validate_message_content(message)
            operation_id = validate_message_operation_id(operation_id)
        except Exception:
            return {"ok": False, "error": "invalid_argument"}
        existing = self._operations.get(operation_id)
        if existing is not None:
            old_recipient, old_message, old_state = existing
            if (old_recipient, old_message) != (recipient, message):
                return {"ok": False, "error": "operation_conflict"}
            return {
                "ok": True,
                "operation_id": operation_id,
                "delivery_state": old_state.value,
                "duplicate": True,
            }
        if self.delivery_state not in (
            MessageDeliveryState.ACCEPTED,
            MessageDeliveryState.SENT,
            MessageDeliveryState.DELIVERED,
        ):
            return {"ok": False, "error": "failed"}
        self._operations[operation_id] = (recipient, message, self.delivery_state)
        self.messages.append((operation_id, recipient, message))
        return {
            "ok": True,
            "operation_id": operation_id,
            "delivery_state": self.delivery_state.value,
            "duplicate": False,
        }


class MessageCapablePhone(CallCapablePhone):
    """Phase 7 fake phone extended with exact Phase 8 message frames."""

    def __init__(
        self,
        transport: Any,
        *,
        message_controller: Optional[FakeAndroidMessageController] = None,
        **kwargs: Any,
    ) -> None:
        capabilities = kwargs.pop("capabilities", None)
        message_caps = tuple(capabilities or DEFAULT_MESSAGE_CAPABILITIES)
        self.message_controller = message_controller or FakeAndroidMessageController(capabilities=message_caps)
        self.message_controller.capabilities = message_caps
        super().__init__(transport, capabilities=message_caps, **kwargs)

    async def _dispatch(self, message: Any):
        guard = _MESSAGE_GUARDS.get(message.message_type)
        if guard is None:
            return await super()._dispatch(message)
        response_type = self._response_type(message.message_type)
        payload = message.payload
        if message.message_type is MessageType.MESSAGE_STATUS:
            if payload:
                return response_type, {"ok": False, "error": "invalid_argument"}
            return response_type, await self.message_controller.get_status()
        if message.message_type is MessageType.MESSAGE_SEND:
            if set(payload) != {"recipient", "message", "operation_id"}:
                return response_type, {"ok": False, "error": "invalid_argument"}
            if not all(isinstance(payload.get(key), str) for key in ("recipient", "message", "operation_id")):
                return response_type, {"ok": False, "error": "invalid_argument"}
            return response_type, await self.message_controller.send(
                payload["recipient"], payload["message"], payload["operation_id"]
            )
        return response_type, {"ok": False, "error": "invalid_argument"}


async def message_phone_pair(
    *,
    capabilities: Tuple[str, ...] = DEFAULT_MESSAGE_CAPABILITIES,
    display_name: str = "Pixel 8",
    paired_and_connected: bool = True,
    **bridge_kwargs: Any,
):
    """Create a Phase 5 bridge with one signed Phase 8 fake peer."""
    from jarvis_devices.android_bridge import AndroidDeviceBridge
    from jarvis_devices.android_identity import AndroidHostIdentity
    from jarvis_devices.android_transport import InMemoryAndroidTransport

    pc_side, phone_side = InMemoryAndroidTransport.create_pair()
    controller = FakeAndroidMessageController(capabilities=capabilities)
    phone = MessageCapablePhone(
        phone_side,
        message_controller=controller,
        display_name=display_name,
        capabilities=capabilities,
        clock=bridge_kwargs.get("clock"),
    )
    host = AndroidHostIdentity.generate("jarvis-pc-test")
    kwargs: Dict[str, Any] = {
        "backoff_base_seconds": 0.0,
        "backoff_cap_seconds": 0.0,
        "request_timeout_seconds": 0.4,
        "host_identity": host,
    }
    kwargs.update(bridge_kwargs)
    bridge = AndroidDeviceBridge(transport=pc_side, **kwargs)
    await bridge.open()
    await phone_side.open()
    phone.trust_host(host.public_key)

    if paired_and_connected:
        await phone.request_pairing()
        await bridge.pump()
        await phone.read_challenge()
        await phone.answer_challenge()
        await bridge.pump()
        pending = [item for item in bridge.pending_pairings() if item["device_id"] == phone.device_id][0]
        bridge.approve_pairing(pending["pairing_id"])
        await asyncio.gather(bridge.connect(phone.device_id), phone.serve(max_frames=2))

    return bridge, phone, AndroidMessageControl(bridge), pc_side, phone_side
