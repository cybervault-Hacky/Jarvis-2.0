"""Phase 6 test doubles: a fake Android companion that speaks the real protocol.

:class:`FakeAndroidSystemController` implements
:class:`~jarvis_devices.android_system.AndroidSystemController` - the contract a
future real companion would implement - and :class:`SystemCapablePhone` wraps the
Phase 5 :class:`~tests.android_support.FakeAndroidDevice` so it answers Phase 6
requests over the real bridge protocol.

This is **test infrastructure, not an Android implementation**. It does not call
any Android, desktop or Linux API to change real state; it holds integers.

The fake also performs the device-side checks a real companion must (§14): it
verifies the frame signature against the JARVIS host key it paired with, checks
the session id, requires a monotonic sequence, and refuses an operation the
phone has not granted. A caller who merely crafts a valid-looking payload gets
nothing.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional, Tuple

from jarvis_devices import android_crypto as crypto
from jarvis_devices.android_protocol import (
    ALL_CAPABILITIES,
    CAPABILITY_SYSTEM_BLUETOOTH,
    CAPABILITY_SYSTEM_BRIGHTNESS,
    CAPABILITY_SYSTEM_VOLUME,
    CAPABILITY_SYSTEM_WIFI,
    BridgeMessage,
    MessageType,
)

try:
    from .android_support import FakeAndroidDevice, make_bridge_pair, started_pair
except ImportError:  # pragma: no cover
    from android_support import FakeAndroidDevice, make_bridge_pair, started_pair

__all__ = [
    "FakeAndroidSystemController",
    "SystemCapablePhone",
    "system_phone_pair",
    "answered",
    "DEFAULT_SYSTEM_CAPABILITIES",
]

DEFAULT_SYSTEM_CAPABILITIES: Tuple[str, ...] = (
    "bridge.protocol",
    "device.status",
    CAPABILITY_SYSTEM_VOLUME,
    CAPABILITY_SYSTEM_BRIGHTNESS,
    CAPABILITY_SYSTEM_WIFI,
    CAPABILITY_SYSTEM_BLUETOOTH,
)

#: Which capability guards which message type.
_GUARDS = {
    MessageType.SYSTEM_STATUS: None,
    MessageType.VOLUME_GET: CAPABILITY_SYSTEM_VOLUME,
    MessageType.VOLUME_SET: CAPABILITY_SYSTEM_VOLUME,
    MessageType.MUTE_SET: CAPABILITY_SYSTEM_VOLUME,
    MessageType.BRIGHTNESS_GET: CAPABILITY_SYSTEM_BRIGHTNESS,
    MessageType.BRIGHTNESS_SET: CAPABILITY_SYSTEM_BRIGHTNESS,
    MessageType.WIFI_STATUS: CAPABILITY_SYSTEM_WIFI,
    MessageType.WIFI_SET: CAPABILITY_SYSTEM_WIFI,
    MessageType.BLUETOOTH_STATUS: CAPABILITY_SYSTEM_BLUETOOTH,
    MessageType.BLUETOOTH_SET: CAPABILITY_SYSTEM_BLUETOOTH,
}


class FakeAndroidSystemController:
    """Phone-side system state. Holds integers; changes no real setting."""

    def __init__(
        self,
        *,
        volume: int = 40,
        muted: bool = False,
        brightness: int = 60,
        adaptive: bool = False,
        wifi_enabled: bool = True,
        bluetooth_enabled: bool = False,
        capabilities: Tuple[str, ...] = DEFAULT_SYSTEM_CAPABILITIES,
    ) -> None:
        self.volume = volume
        self.muted = muted
        self.brightness = brightness
        self.adaptive = adaptive
        self.wifi_enabled = wifi_enabled
        self.bluetooth_enabled = bluetooth_enabled
        self.capabilities = tuple(capabilities)
        #: What the phone's own permission model refuses.
        self.denied: set = set()
        #: What the phone reports as unavailable.
        self.unavailable: set = set()
        #: Operations that fail with a generic error.
        self.failing: set = set()
        #: Records every call, for assertions.
        self.calls: List[Tuple[str, Tuple[Any, ...]]] = []

    # ------------------------------------------------------------------
    def _record(self, name: str, *args: Any) -> Optional[Dict[str, Any]]:
        self.calls.append((name, args))
        if name in self.denied:
            return {"ok": False, "error": "permission_denied", "detail": "Android denied this"}
        if name in self.unavailable:
            return {"ok": False, "error": "unavailable", "detail": "not available on this phone"}
        if name in self.failing:
            return {"ok": False, "error": "failed", "detail": "the system call failed"}
        return None

    def _refusal_for(self, capability: Optional[str]) -> Optional[Dict[str, Any]]:
        if capability is not None and capability not in self.capabilities:
            return {"ok": False, "error": "unsupported", "detail": f"{capability} not supported"}
        return None

    # ------------------------------------------------------------------
    async def get_status(self) -> Dict[str, Any]:
        blocked = self._record("get_status") or self._refusal_for(None)
        if blocked:
            return blocked
        result: Dict[str, Any] = {"ok": True}
        if CAPABILITY_SYSTEM_VOLUME in self.capabilities:
            result["volume"] = self.volume
            result["muted"] = self.muted
        if CAPABILITY_SYSTEM_BRIGHTNESS in self.capabilities:
            result["brightness"] = self.brightness
            result["adaptive_brightness"] = self.adaptive
        if CAPABILITY_SYSTEM_WIFI in self.capabilities:
            result["wifi_enabled"] = self.wifi_enabled
        if CAPABILITY_SYSTEM_BLUETOOTH in self.capabilities:
            result["bluetooth_enabled"] = self.bluetooth_enabled
        return result

    async def get_volume(self) -> Dict[str, Any]:
        blocked = self._record("get_volume") or self._refusal_for(CAPABILITY_SYSTEM_VOLUME)
        return blocked or {"ok": True, "volume": self.volume, "muted": self.muted}

    async def set_volume(self, level: int) -> Dict[str, Any]:
        blocked = self._record("set_volume", level) or self._refusal_for(CAPABILITY_SYSTEM_VOLUME)
        if blocked:
            return blocked
        if not isinstance(level, int) or isinstance(level, bool) or not 0 <= level <= 100:
            return {"ok": False, "error": "invalid_argument", "detail": "level must be 0-100"}
        self.volume = level
        return {"ok": True, "volume": self.volume, "muted": self.muted}

    async def mute(self) -> Dict[str, Any]:
        blocked = self._record("mute") or self._refusal_for(CAPABILITY_SYSTEM_VOLUME)
        if blocked:
            return blocked
        self.muted = True
        return {"ok": True, "volume": self.volume, "muted": self.muted}

    async def unmute(self) -> Dict[str, Any]:
        blocked = self._record("unmute") or self._refusal_for(CAPABILITY_SYSTEM_VOLUME)
        if blocked:
            return blocked
        self.muted = False
        return {"ok": True, "volume": self.volume, "muted": self.muted}

    async def get_brightness(self) -> Dict[str, Any]:
        blocked = self._record("get_brightness") or self._refusal_for(CAPABILITY_SYSTEM_BRIGHTNESS)
        return blocked or {"ok": True, "brightness": self.brightness, "adaptive": self.adaptive}

    async def set_brightness(self, level: int) -> Dict[str, Any]:
        blocked = self._record("set_brightness", level) or self._refusal_for(
            CAPABILITY_SYSTEM_BRIGHTNESS
        )
        if blocked:
            return blocked
        if not isinstance(level, int) or isinstance(level, bool) or not 0 <= level <= 100:
            return {"ok": False, "error": "invalid_argument", "detail": "level must be 0-100"}
        self.brightness = level
        # Note: adaptive mode is NOT turned off. The phone reports it instead.
        return {"ok": True, "brightness": self.brightness, "adaptive": self.adaptive}

    async def get_wifi_status(self) -> Dict[str, Any]:
        blocked = self._record("get_wifi_status") or self._refusal_for(CAPABILITY_SYSTEM_WIFI)
        return blocked or {"ok": True, "enabled": self.wifi_enabled}

    async def set_wifi_enabled(self, enabled: bool) -> Dict[str, Any]:
        blocked = self._record("set_wifi_enabled", enabled) or self._refusal_for(
            CAPABILITY_SYSTEM_WIFI
        )
        if blocked:
            return blocked
        if not isinstance(enabled, bool):
            return {"ok": False, "error": "invalid_argument", "detail": "enabled must be a boolean"}
        self.wifi_enabled = enabled
        return {"ok": True, "enabled": self.wifi_enabled}

    async def get_bluetooth_status(self) -> Dict[str, Any]:
        blocked = self._record("get_bluetooth_status") or self._refusal_for(
            CAPABILITY_SYSTEM_BLUETOOTH
        )
        return blocked or {"ok": True, "enabled": self.bluetooth_enabled}

    async def set_bluetooth_enabled(self, enabled: bool) -> Dict[str, Any]:
        blocked = self._record("set_bluetooth_enabled", enabled) or self._refusal_for(
            CAPABILITY_SYSTEM_BLUETOOTH
        )
        if blocked:
            return blocked
        if not isinstance(enabled, bool):
            return {"ok": False, "error": "invalid_argument", "detail": "enabled must be a boolean"}
        self.bluetooth_enabled = enabled
        return {"ok": True, "enabled": self.bluetooth_enabled}


class SystemCapablePhone(FakeAndroidDevice):
    """A Phase 5 fake phone extended with Phase 6 system-control handling.

    Device-side authorisation is real here: inbound frames are verified against
    the trusted JARVIS host key, the session must match, the sequence must
    increase, and the operation must be one this phone supports.
    """

    def __init__(self, transport, *, controller=None, **kwargs) -> None:
        capabilities = kwargs.pop("capabilities", None)
        self.controller = controller or FakeAndroidSystemController(
            capabilities=capabilities or DEFAULT_SYSTEM_CAPABILITIES
        )
        if capabilities:
            self.controller.capabilities = tuple(capabilities)
        kwargs.setdefault("capabilities", self.controller.capabilities)
        super().__init__(transport, **kwargs)
        #: Set from the pair_challenge frame, as a real companion would.
        self.trusted_host_key: Optional[bytes] = None
        self.last_sequence = 0
        #: Frames this phone refused, with the reason - for assertions.
        self.refusals: List[Tuple[str, str]] = []
        #: When true, answer nothing at all (simulates an unresponsive phone).
        self.silent = False
        #: When set, reply with this payload instead of asking the controller -
        #: used to feed the bridge a malformed or hostile response.
        self.override_response: Optional[Dict[str, Any]] = None

    # ------------------------------------------------------------------
    def trust_host(self, public_key: bytes) -> None:
        """Record the JARVIS host key this phone paired with.

        A real companion would do this while showing the pairing code to the
        user for comparison; the test helper does it explicitly.
        """
        self.trusted_host_key = public_key

    # ------------------------------------------------------------------
    async def serve(self, *, max_frames: int = 4, timeout: float = 0.05) -> int:
        handled = 0
        while handled < max_frames:
            message = await self.receive(timeout)
            if message is None:
                break
            handled += 1
            await self._handle_system(message)
        return handled

    async def _handle_system(self, message: BridgeMessage) -> None:
        # --- device-side authorisation (what a real companion must do) ------
        if self.trusted_host_key is None:
            self.refusals.append((message.message_type.value, "no trusted host"))
            return
        if not message.verify(self.trusted_host_key):
            self.refusals.append((message.message_type.value, "bad signature"))
            return
        if self.session_id and message.session_id and message.session_id != self.session_id:
            self.refusals.append((message.message_type.value, "wrong session"))
            return
        if message.sequence <= self.last_sequence:
            self.refusals.append((message.message_type.value, "stale sequence"))
            return
        self.last_sequence = message.sequence

        if self.silent:
            return

        response_type, payload = await self._dispatch(message)
        if response_type is None:
            return
        if self.override_response is not None:
            payload = self.override_response
        await self._ack(message, response_type, payload)

    async def _dispatch(self, message: BridgeMessage):
        handler = {
            MessageType.SYSTEM_STATUS: self.controller.get_status,
            MessageType.VOLUME_GET: self.controller.get_volume,
            MessageType.BRIGHTNESS_GET: self.controller.get_brightness,
            MessageType.WIFI_STATUS: self.controller.get_wifi_status,
            MessageType.BLUETOOTH_STATUS: self.controller.get_bluetooth_status,
        }.get(message.message_type)
        if handler is not None:
            return self._response_type(message.message_type), await handler()

        capability = _GUARDS.get(message.message_type)
        refusal = self.controller._refusal_for(capability)
        response_type = self._response_type(message.message_type)
        if refusal is not None:
            return response_type, refusal

        payload = message.payload
        if message.message_type is MessageType.VOLUME_SET:
            return response_type, await self.controller.set_volume(payload.get("level"))
        if message.message_type is MessageType.MUTE_SET:
            if payload.get("muted") is True:
                return response_type, await self.controller.mute()
            return response_type, await self.controller.unmute()
        if message.message_type is MessageType.BRIGHTNESS_SET:
            return response_type, await self.controller.set_brightness(payload.get("level"))
        if message.message_type is MessageType.WIFI_SET:
            return response_type, await self.controller.set_wifi_enabled(payload.get("enabled"))
        if message.message_type is MessageType.BLUETOOTH_SET:
            return response_type, await self.controller.set_bluetooth_enabled(
                payload.get("enabled")
            )
        # Phase 5 frames (heartbeat, capabilities, connect, disconnect).
        await self._reply_to(message)
        return None, None

    @staticmethod
    def _response_type(request: MessageType) -> MessageType:
        from jarvis_devices.android_protocol import RESPONSE_FOR

        return MessageType(RESPONSE_FOR[request.value])


async def system_phone_pair(
    *,
    capabilities: Tuple[str, ...] = DEFAULT_SYSTEM_CAPABILITIES,
    display_name: str = "Pixel 8",
    paired_and_connected: bool = True,
    **bridge_kwargs: Any,
):
    """Build a real bridge wired to a system-capable fake phone.

    Returns ``(bridge, phone, control, pc_side, phone_side)`` where ``control``
    is the :class:`~jarvis_devices.android_system.AndroidSystemControl` under
    test.
    """
    from jarvis_devices.android_bridge import AndroidDeviceBridge
    from jarvis_devices.android_identity import AndroidHostIdentity
    from jarvis_devices.android_system import AndroidSystemControl
    from jarvis_devices.android_transport import InMemoryAndroidTransport

    pc_side, phone_side = InMemoryAndroidTransport.create_pair()
    controller = FakeAndroidSystemController(capabilities=capabilities)
    phone = SystemCapablePhone(
        phone_side,
        controller=controller,
        display_name=display_name,
        capabilities=capabilities,
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
        pending = [p for p in bridge.pending_pairings() if p["device_id"] == phone.device_id][0]
        bridge.approve_pairing(pending["pairing_id"])
        await asyncio.gather(bridge.connect(phone.device_id), phone.serve(max_frames=2))

    control = AndroidSystemControl(bridge)
    return bridge, phone, control, pc_side, phone_side

async def answered(coro, phone: SystemCapablePhone, *, max_frames: int = 2):
    """Run a bridge-side coroutine while the fake phone answers it.

    The bridge has no background receive task by design, so a request only
    completes while something is serving the other end. If ``coro`` raises, the
    exception is re-raised here rather than swallowed.
    """
    results = await asyncio.gather(coro, phone.serve(max_frames=max_frames), return_exceptions=True)
    outcome = results[0]
    if isinstance(outcome, BaseException):
        raise outcome
    return outcome
