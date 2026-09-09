"""Phase 7 fake Android companion using the real authenticated protocol.

This is deterministic test infrastructure, not telephony software.  It stores
small enum values only; it never accesses Android APIs, a microphone, contacts,
call history, recordings, desktop telephony, a network endpoint, or a process.
``CallCapablePhone`` extends the Phase 6-capable fake phone and retains its
peer-side host signature, session and monotonic-sequence checks.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from jarvis_devices.android_calls import (
    CALL_CAPABILITIES,
    AndroidCallState,
    CallDirection,
    CallStateMachine,
    redact_phone_number,
    validate_phone_number,
)
from jarvis_devices.android_protocol import (
    CAPABILITY_CALL_ANSWER,
    CAPABILITY_CALL_DIAL,
    CAPABILITY_CALL_END,
    CAPABILITY_CALL_REJECT,
    CAPABILITY_CALL_STATUS,
    MessageType,
)

try:
    from .android_system_support import (
        DEFAULT_SYSTEM_CAPABILITIES,
        FakeAndroidSystemController,
        SystemCapablePhone,
        answered,
    )
except ImportError:  # pragma: no cover
    from android_system_support import (
        DEFAULT_SYSTEM_CAPABILITIES,
        FakeAndroidSystemController,
        SystemCapablePhone,
        answered,
    )

__all__ = [
    "DEFAULT_CALL_CAPABILITIES",
    "FakeAndroidCallController",
    "CallCapablePhone",
    "call_phone_pair",
    "answered",
]

DEFAULT_CALL_CAPABILITIES: Tuple[str, ...] = tuple(
    dict.fromkeys(DEFAULT_SYSTEM_CAPABILITIES + CALL_CAPABILITIES)
)

_CALL_GUARDS = {
    MessageType.CALL_STATUS: CAPABILITY_CALL_STATUS,
    MessageType.CALL_DIAL: CAPABILITY_CALL_DIAL,
    MessageType.CALL_ANSWER: CAPABILITY_CALL_ANSWER,
    MessageType.CALL_REJECT: CAPABILITY_CALL_REJECT,
    MessageType.CALL_END: CAPABILITY_CALL_END,
}


class FakeAndroidCallController:
    """Deterministic stateful fake of the five-method Android call contract."""

    _DEVICE_KEY = "fake-companion"

    def __init__(
        self,
        *,
        state: AndroidCallState = AndroidCallState.IDLE,
        capabilities: Tuple[str, ...] = DEFAULT_CALL_CAPABILITIES,
    ) -> None:
        self.capabilities = tuple(capabilities)
        self._states = CallStateMachine()
        self._states.observe(self._DEVICE_KEY, state)
        self.direction: Optional[CallDirection] = None
        #: Simulate the companion's own authority/availability/failure outcome.
        self.denied: set = set()
        self.unavailable: set = set()
        self.failing: set = set()
        #: No raw number is retained; records use a redacted destination suffix.
        self.calls: List[Tuple[str, Tuple[Any, ...]]] = []

    @property
    def state(self) -> AndroidCallState:
        current = self._states.get(self._DEVICE_KEY)
        assert current is not None
        return current

    def _transition(self, state: AndroidCallState) -> None:
        self._states.observe(self._DEVICE_KEY, state)
        if state is AndroidCallState.RINGING:
            self.direction = CallDirection.INCOMING
        elif state is AndroidCallState.DIALING:
            self.direction = CallDirection.OUTGOING
        elif state in (AndroidCallState.IDLE, AndroidCallState.FAILED, AndroidCallState.UNAVAILABLE):
            self.direction = None

    def begin_ringing(self) -> None:
        """Test-only simulation of a trusted companion observing an incoming call."""
        self._transition(AndroidCallState.RINGING)

    def complete_dial(self) -> None:
        """Test-only simulation of Android moving a dial request to active."""
        self._transition(AndroidCallState.ACTIVE)

    def complete_end(self) -> None:
        """Test-only simulation of Android finishing its ending state."""
        self._transition(AndroidCallState.IDLE)

    def _record(self, name: str, *args: Any) -> Optional[Dict[str, Any]]:
        self.calls.append((name, args))
        if name in self.denied:
            return {"ok": False, "error": "permission_denied", "state": self.state.value}
        if name in self.unavailable:
            return {"ok": False, "error": "unavailable", "state": self.state.value}
        if name in self.failing:
            if name == "dial" and self.state is AndroidCallState.IDLE:
                self._transition(AndroidCallState.DIALING)
                self._transition(AndroidCallState.FAILED)
            return {"ok": False, "error": "failed", "state": self.state.value}
        return None

    def _refusal_for(self, capability: str) -> Optional[Dict[str, Any]]:
        if capability not in self.capabilities:
            return {"ok": False, "error": "unsupported", "state": self.state.value}
        return None

    def _invalid_state(self) -> Dict[str, Any]:
        return {"ok": False, "error": "invalid_state", "state": self.state.value}

    async def get_status(self) -> Dict[str, Any]:
        blocked = self._record("get_status") or self._refusal_for(CAPABILITY_CALL_STATUS)
        if blocked:
            return blocked
        has_call = self.state in (
            AndroidCallState.RINGING,
            AndroidCallState.DIALING,
            AndroidCallState.ACTIVE,
            AndroidCallState.ENDING,
        )
        response: Dict[str, Any] = {"ok": True, "state": self.state.value, "has_call": has_call}
        if self.direction is not None:
            response["direction"] = self.direction.value
        return response

    async def dial(self, phone_number: str) -> Dict[str, Any]:
        # Keep the fake's call record privacy-safe while still proving the
        # controller receives a canonical phone number through the real frame.
        self.calls.append(("dial", (redact_phone_number(str(phone_number)),)))
        blocked = self._refusal_for(CAPABILITY_CALL_DIAL)
        if blocked:
            return blocked
        if "dial" in self.denied:
            return {"ok": False, "error": "permission_denied", "state": self.state.value}
        if "dial" in self.unavailable:
            return {"ok": False, "error": "unavailable", "state": self.state.value}
        if self.state is not AndroidCallState.IDLE:
            return self._invalid_state()
        try:
            validate_phone_number(phone_number)
        except Exception:
            return {"ok": False, "error": "invalid_argument", "state": self.state.value}
        if "dial" in self.failing:
            self._transition(AndroidCallState.DIALING)
            self._transition(AndroidCallState.FAILED)
            return {"ok": False, "error": "failed", "state": self.state.value}
        self._transition(AndroidCallState.DIALING)
        return {"ok": True, "state": self.state.value}

    async def answer(self) -> Dict[str, Any]:
        blocked = self._record("answer") or self._refusal_for(CAPABILITY_CALL_ANSWER)
        if blocked:
            return blocked
        if self.state is not AndroidCallState.RINGING:
            return self._invalid_state()
        self._transition(AndroidCallState.ACTIVE)
        return {"ok": True, "state": self.state.value, "answered": True}

    async def reject(self) -> Dict[str, Any]:
        blocked = self._record("reject") or self._refusal_for(CAPABILITY_CALL_REJECT)
        if blocked:
            return blocked
        if self.state is not AndroidCallState.RINGING:
            return self._invalid_state()
        self._transition(AndroidCallState.IDLE)
        return {"ok": True, "state": self.state.value, "rejected": True}

    async def end(self) -> Dict[str, Any]:
        blocked = self._record("end") or self._refusal_for(CAPABILITY_CALL_END)
        if blocked:
            return blocked
        if self.state is AndroidCallState.IDLE:
            return {"ok": True, "state": AndroidCallState.IDLE.value, "ended": False}
        if self.state is not AndroidCallState.ACTIVE:
            return self._invalid_state()
        self._transition(AndroidCallState.ENDING)
        return {"ok": True, "state": self.state.value, "ended": True}


class CallCapablePhone(SystemCapablePhone):
    """Phase 6 fake phone extended with dedicated Phase 7 protocol handling."""

    def __init__(
        self,
        transport: Any,
        *,
        controller: Optional[FakeAndroidSystemController] = None,
        call_controller: Optional[FakeAndroidCallController] = None,
        **kwargs: Any,
    ) -> None:
        capabilities = kwargs.pop("capabilities", None)
        call_caps = tuple(capabilities or DEFAULT_CALL_CAPABILITIES)
        self.call_controller = call_controller or FakeAndroidCallController(capabilities=call_caps)
        self.call_controller.capabilities = call_caps
        super().__init__(
            transport,
            controller=controller or FakeAndroidSystemController(capabilities=call_caps),
            capabilities=call_caps,
            **kwargs,
        )

    async def _dispatch(self, message: Any):
        guard = _CALL_GUARDS.get(message.message_type)
        if guard is None:
            return await super()._dispatch(message)
        response_type = self._response_type(message.message_type)
        payload = message.payload
        if message.message_type is MessageType.CALL_STATUS:
            if payload:
                return response_type, {"ok": False, "error": "invalid_argument", "state": self.call_controller.state.value}
            return response_type, await self.call_controller.get_status()
        if message.message_type is MessageType.CALL_DIAL:
            if set(payload) != {"phone_number"} or not isinstance(payload.get("phone_number"), str):
                return response_type, {"ok": False, "error": "invalid_argument", "state": self.call_controller.state.value}
            return response_type, await self.call_controller.dial(payload["phone_number"])
        if payload:
            return response_type, {"ok": False, "error": "invalid_argument", "state": self.call_controller.state.value}
        if message.message_type is MessageType.CALL_ANSWER:
            return response_type, await self.call_controller.answer()
        if message.message_type is MessageType.CALL_REJECT:
            return response_type, await self.call_controller.reject()
        if message.message_type is MessageType.CALL_END:
            return response_type, await self.call_controller.end()
        return response_type, {"ok": False, "error": "invalid_argument", "state": self.call_controller.state.value}


async def call_phone_pair(
    *,
    capabilities: Tuple[str, ...] = DEFAULT_CALL_CAPABILITIES,
    display_name: str = "Pixel 8",
    paired_and_connected: bool = True,
    **bridge_kwargs: Any,
):
    """Create an authenticated real bridge and a Phase 7-capable fake peer."""
    from jarvis_devices.android_bridge import AndroidDeviceBridge
    from jarvis_devices.android_identity import AndroidHostIdentity
    from jarvis_devices.android_calls import AndroidCallControl
    from jarvis_devices.android_transport import InMemoryAndroidTransport

    pc_side, phone_side = InMemoryAndroidTransport.create_pair()
    call_controller = FakeAndroidCallController(capabilities=capabilities)
    phone = CallCapablePhone(
        phone_side,
        call_controller=call_controller,
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
        import asyncio
        await asyncio.gather(bridge.connect(phone.device_id), phone.serve(max_frames=2))

    return bridge, phone, AndroidCallControl(bridge), pc_side, phone_side
