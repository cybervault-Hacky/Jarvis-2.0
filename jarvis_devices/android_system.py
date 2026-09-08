"""Android system control over the Phase 5 bridge (Phase 6).

Two halves live here, and keeping them apart is the point:

* :class:`AndroidSystemController` is the **device-side** contract - what a
  future Android companion implements. Nothing in this repository implements it
  for real; the test double in ``tests/android_system_support.py`` does, and it
  is honest about being a fake.
* :class:`AndroidSystemControl` is the **PC-side** orchestrator JARVIS actually
  uses. It never touches a transport: every operation goes through
  :meth:`AndroidDeviceBridge.send_request`, so it inherits Phase 5 Ed25519
  authentication, request/response correlation, sequence numbers, nonces,
  session binding and replay protection for free.

Flow::

    JARVIS tool
        |
    DeviceActionManager            (permissions, confirmation, audit)
        |
    AndroidSystemControl           (capability gate, bounded values, envelope)
        |
    AndroidDeviceBridge.send_request   (signature, correlation, replay guard)
        |
    Phase 5 protocol frame
        |
    Android companion -> AndroidSystemController

What is deliberately absent: no ADB, no subprocess, no socket, no shell, no
arbitrary Android API name, no SSID/password/network joining, no Bluetooth
discovery or pairing, no toggle operations. Every message type is explicit and
allowlisted in :mod:`jarvis_devices.android_protocol`.

Bounded values
--------------
Volume and brightness are integers in ``0..100``. ``bool`` is rejected (it is an
``int`` subclass), as are floats, strings and anything else. Brightness never
silently disables adaptive brightness: the device reports whether it is adaptive
and this layer changes nothing about that setting.

Idempotency
-----------
``set_volume(50)`` and ``set_wifi_enabled(True)`` express a *desired state*, so
re-sending them is safe. There is no ``toggle`` anywhere: retrying a toggle can
produce the opposite result.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional, Protocol, Tuple

from .android_bridge import (
    AndroidBridgeError,
    AndroidCapabilityUnavailableError,
    AndroidDeviceBridge,
    AndroidDeviceNotConnectedError,
)
from .android_identity import AndroidDeviceIdentity, HealthState
from .android_protocol import (
    ALL_CAPABILITIES,
    CAPABILITY_SYSTEM_BLUETOOTH,
    CAPABILITY_SYSTEM_BRIGHTNESS,
    CAPABILITY_SYSTEM_VOLUME,
    CAPABILITY_SYSTEM_WIFI,
    PERCENT_MAX,
    PERCENT_MIN,
    BridgeMessage,
    InvalidMessageError,
    MessageType,
    validate_percent,
)
from .errors import ErrorCode

__all__ = [
    "AndroidSystemError",
    "AndroidSystemUnavailableError",
    "AndroidSystemUnsupportedError",
    "AndroidSystemPermissionDeniedError",
    "AndroidSystemInvalidArgumentError",
    "AndroidSystemTimeoutError",
    "AndroidSystemFailedError",
    "AndroidVolumeUnavailableError",
    "AndroidBrightnessUnavailableError",
    "AndroidWifiUnavailableError",
    "AndroidBluetoothUnavailableError",
    "AndroidSystemController",
    "AndroidSystemControl",
    "DEVICE_ERROR_CODES",
    "unwrap_response",
    "SYSTEM_CONTROL_CAPABILITIES",
]

#: Capabilities this phase drives, and the message pair behind each.
SYSTEM_CONTROL_CAPABILITIES: Tuple[str, ...] = (
    CAPABILITY_SYSTEM_VOLUME,
    CAPABILITY_SYSTEM_BRIGHTNESS,
    CAPABILITY_SYSTEM_WIFI,
    CAPABILITY_SYSTEM_BLUETOOTH,
)

#: The only failure reasons a companion may report. Anything else is treated as
#: a generic failure, so a phone cannot invent new codes that JARVIS would then
#: surface verbatim to a user.
DEVICE_ERROR_CODES: Dict[str, str] = {
    "unsupported": ErrorCode.ANDROID_SYSTEM_UNSUPPORTED,
    "unavailable": ErrorCode.ANDROID_SYSTEM_UNAVAILABLE,
    "permission_denied": ErrorCode.ANDROID_SYSTEM_PERMISSION_DENIED,
    "invalid_argument": ErrorCode.ANDROID_SYSTEM_INVALID_ARGUMENT,
    "failed": ErrorCode.ANDROID_SYSTEM_FAILED,
    "volume_unavailable": ErrorCode.ANDROID_VOLUME_UNAVAILABLE,
    "brightness_unavailable": ErrorCode.ANDROID_BRIGHTNESS_UNAVAILABLE,
    "wifi_unavailable": ErrorCode.ANDROID_WIFI_UNAVAILABLE,
    "bluetooth_unavailable": ErrorCode.ANDROID_BLUETOOTH_UNAVAILABLE,
}


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------
class AndroidSystemError(AndroidBridgeError):
    """Base class for Android system-control failures."""

    error_code = ErrorCode.ANDROID_SYSTEM_FAILED


class AndroidSystemUnavailableError(AndroidSystemError):
    error_code = ErrorCode.ANDROID_SYSTEM_UNAVAILABLE


class AndroidSystemUnsupportedError(AndroidSystemError):
    error_code = ErrorCode.ANDROID_SYSTEM_UNSUPPORTED


class AndroidSystemPermissionDeniedError(AndroidSystemError):
    """The phone refused the operation (its own permission model said no)."""

    error_code = ErrorCode.ANDROID_SYSTEM_PERMISSION_DENIED


class AndroidSystemInvalidArgumentError(AndroidSystemError):
    error_code = ErrorCode.ANDROID_SYSTEM_INVALID_ARGUMENT


class AndroidSystemTimeoutError(AndroidSystemError):
    """No answer in time. **Never** means the operation succeeded."""

    error_code = ErrorCode.ANDROID_SYSTEM_TIMEOUT


class AndroidSystemFailedError(AndroidSystemError):
    error_code = ErrorCode.ANDROID_SYSTEM_FAILED


class AndroidVolumeUnavailableError(AndroidSystemUnavailableError):
    error_code = ErrorCode.ANDROID_VOLUME_UNAVAILABLE


class AndroidBrightnessUnavailableError(AndroidSystemUnavailableError):
    error_code = ErrorCode.ANDROID_BRIGHTNESS_UNAVAILABLE


class AndroidWifiUnavailableError(AndroidSystemUnavailableError):
    error_code = ErrorCode.ANDROID_WIFI_UNAVAILABLE


class AndroidBluetoothUnavailableError(AndroidSystemUnavailableError):
    error_code = ErrorCode.ANDROID_BLUETOOTH_UNAVAILABLE


_CODE_TO_ERROR = {
    ErrorCode.ANDROID_SYSTEM_UNSUPPORTED: AndroidSystemUnsupportedError,
    ErrorCode.ANDROID_SYSTEM_UNAVAILABLE: AndroidSystemUnavailableError,
    ErrorCode.ANDROID_SYSTEM_PERMISSION_DENIED: AndroidSystemPermissionDeniedError,
    ErrorCode.ANDROID_SYSTEM_INVALID_ARGUMENT: AndroidSystemInvalidArgumentError,
    ErrorCode.ANDROID_SYSTEM_FAILED: AndroidSystemFailedError,
    ErrorCode.ANDROID_VOLUME_UNAVAILABLE: AndroidVolumeUnavailableError,
    ErrorCode.ANDROID_BRIGHTNESS_UNAVAILABLE: AndroidBrightnessUnavailableError,
    ErrorCode.ANDROID_WIFI_UNAVAILABLE: AndroidWifiUnavailableError,
    ErrorCode.ANDROID_BLUETOOTH_UNAVAILABLE: AndroidBluetoothUnavailableError,
}


# ---------------------------------------------------------------------------
# Response envelope
# ---------------------------------------------------------------------------
def unwrap_response(payload: Mapping[str, Any], *, operation: str) -> Dict[str, Any]:
    """Validate a companion response envelope and return its fields.

    Every ``*_response`` frame carries ``{"ok": bool, ...}``. A failure carries
    ``error`` from :data:`DEVICE_ERROR_CODES` plus an optional short ``detail``.
    Unknown error reasons collapse to a generic failure rather than being
    trusted.
    """
    if not isinstance(payload, Mapping):
        raise AndroidSystemFailedError(f"The {operation} response was not an object.")
    if "ok" not in payload:
        raise AndroidSystemFailedError(f"The {operation} response did not say whether it worked.")
    ok = payload["ok"]
    if not isinstance(ok, bool):
        raise AndroidSystemFailedError(f"The {operation} response had a non-boolean 'ok'.")

    if not ok:
        reason = payload.get("error", "")
        code = DEVICE_ERROR_CODES.get(str(reason), ErrorCode.ANDROID_SYSTEM_FAILED)
        detail = str(payload.get("detail", ""))[:160]
        message = f"The phone refused to {operation}."
        if detail:
            message = f"{message} ({detail})"
        raise _CODE_TO_ERROR.get(code, AndroidSystemFailedError)(message)

    return {key: value for key, value in payload.items() if key not in ("ok", "error", "detail")}


def _require_bool(payload: Mapping[str, Any], key: str, *, operation: str) -> bool:
    value = payload.get(key)
    if not isinstance(value, bool):
        raise AndroidSystemFailedError(f"The {operation} response had no boolean {key!r}.")
    return value


def _require_percent(payload: Mapping[str, Any], key: str, *, operation: str) -> int:
    try:
        return validate_percent(payload.get(key), field=key)
    except InvalidMessageError as exc:
        raise AndroidSystemFailedError(f"The {operation} response was invalid: {exc}") from exc


# ---------------------------------------------------------------------------
# Device-side contract
# ---------------------------------------------------------------------------
class AndroidSystemController(Protocol):
    """What a future Android companion implements on the phone.

    This is a *specification*, not an implementation. Nothing in this repository
    runs it: there is no Android application here. The real companion must also
    verify, before acting, that

    * the frame is signed by the **trusted host** identity it paired with,
    * the session id matches the live session,
    * the sequence number is newer than the last one it accepted,
    * the operation is one the user granted on the phone, and
    * the payload is valid for that operation.

    A caller who merely constructs a valid-looking payload must not be able to
    change anything: authentication happens on both ends.
    """

    async def get_status(self) -> Dict[str, Any]: ...

    async def get_volume(self) -> Dict[str, Any]: ...

    async def set_volume(self, level: int) -> Dict[str, Any]: ...

    async def mute(self) -> Dict[str, Any]: ...

    async def unmute(self) -> Dict[str, Any]: ...

    async def get_brightness(self) -> Dict[str, Any]: ...

    async def set_brightness(self, level: int) -> Dict[str, Any]: ...

    async def get_wifi_status(self) -> Dict[str, Any]: ...

    async def set_wifi_enabled(self, enabled: bool) -> Dict[str, Any]: ...

    async def get_bluetooth_status(self) -> Dict[str, Any]: ...

    async def set_bluetooth_enabled(self, enabled: bool) -> Dict[str, Any]: ...


# ---------------------------------------------------------------------------
# PC-side orchestrator
# ---------------------------------------------------------------------------
class AndroidSystemControl:
    """Drives Android system state through the Phase 5 bridge.

    Every method follows the same four steps, in this order, and stops at the
    first one that fails:

    1. the device is **trusted** (paired, not revoked) - enforced by the bridge;
    2. the device is **connected** - enforced by the bridge;
    3. the device actually **advertises** the capability - checked here;
    4. only then is a signed request sent, with a bounded timeout.

    A timeout always answers as a timeout. Nothing here retries a state-changing
    operation, because "no answer" is not "it did not happen".
    """

    def __init__(self, bridge: AndroidDeviceBridge, *, timeout: Optional[float] = None) -> None:
        self._bridge = bridge
        self._timeout = timeout

    @property
    def bridge(self) -> AndroidDeviceBridge:
        return self._bridge

    # ------------------------------------------------------------------
    def _prepare(self, device_id: str, capability: str) -> AndroidDeviceIdentity:
        """Trust + connection + capability, or raise. Nothing is sent yet."""
        device = self._bridge.require_connected(device_id)
        # Raises AndroidCapabilityUnavailableError when the phone did not
        # advertise the capability, or when this JARVIS does not implement it.
        self._bridge.require_capability(device_id, capability)
        return device

    async def _call(
        self,
        device_id: str,
        request_type: MessageType,
        response_type: MessageType,
        capability: str,
        *,
        payload: Optional[Mapping[str, Any]] = None,
        operation: str = "",
    ) -> Dict[str, Any]:
        self._prepare(device_id, capability)
        response = await self._bridge.send_request(
            device_id,
            request_type,
            payload or {},
            expect=response_type,
            timeout=self._timeout,
        )
        if response is None:
            # No answer. Deliberately NOT retried and NOT reported as success.
            raise AndroidSystemTimeoutError(
                f"The phone did not answer the {operation or request_type.value} request in time; "
                "it is unknown whether anything changed."
            )
        return unwrap_response(response.payload, operation=operation or request_type.value)

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------
    async def status(self, device_id: str) -> Dict[str, Any]:
        """Everything the companion is willing to report - and only that."""
        device = self._bridge.require_connected(device_id)
        response = await self._bridge.send_request(
            device_id,
            MessageType.SYSTEM_STATUS,
            {},
            expect=MessageType.SYSTEM_STATUS_RESPONSE,
            timeout=self._timeout,
        )
        if response is None:
            raise AndroidSystemTimeoutError(
                "The phone did not answer the status request in time."
            )
        fields = unwrap_response(response.payload, operation="report system status")

        # Validate whatever the phone did send, and never invent what it omitted.
        result: Dict[str, Any] = {
            "device_id": device.device_id,
            "display_name": device.display_name,
            "connected": True,
            "health": self._bridge.health(device_id).value,
            "capabilities": list(device.capabilities),
        }
        if "volume" in fields:
            result["volume"] = _require_percent(fields, "volume", operation="report system status")
        if "muted" in fields:
            result["muted"] = _require_bool(fields, "muted", operation="report system status")
        if "brightness" in fields:
            result["brightness"] = _require_percent(
                fields, "brightness", operation="report system status"
            )
        if "adaptive_brightness" in fields:
            result["adaptive_brightness"] = _require_bool(
                fields, "adaptive_brightness", operation="report system status"
            )
        if "wifi_enabled" in fields:
            result["wifi_enabled"] = _require_bool(
                fields, "wifi_enabled", operation="report system status"
            )
        if "bluetooth_enabled" in fields:
            result["bluetooth_enabled"] = _require_bool(
                fields, "bluetooth_enabled", operation="report system status"
            )
        result["reported"] = sorted(
            key
            for key in result
            if key not in ("device_id", "display_name", "connected", "health", "capabilities")
        )
        return result

    # ------------------------------------------------------------------
    # Volume
    # ------------------------------------------------------------------
    async def get_volume(self, device_id: str) -> Dict[str, Any]:
        fields = await self._call(
            device_id,
            MessageType.VOLUME_GET,
            MessageType.VOLUME_GET_RESPONSE,
            CAPABILITY_SYSTEM_VOLUME,
            operation="report the volume",
        )
        return {
            "device_id": device_id,
            "volume": _require_percent(fields, "volume", operation="report the volume"),
            "muted": _require_bool(fields, "muted", operation="report the volume"),
        }

    async def set_volume(self, device_id: str, level: int) -> Dict[str, Any]:
        """Set the media volume to an absolute 0-100 percentage.

        Idempotent: sending the same level twice leaves the phone in the same
        state. There is no stream argument - a single media volume keeps the
        model-facing API from ever naming an Android API.
        """
        value = validate_percent(level, field="level")
        fields = await self._call(
            device_id,
            MessageType.VOLUME_SET,
            MessageType.VOLUME_SET_RESPONSE,
            CAPABILITY_SYSTEM_VOLUME,
            payload={"level": value},
            operation="set the volume",
        )
        return {
            "device_id": device_id,
            "volume": _require_percent(fields, "volume", operation="set the volume"),
            "muted": _require_bool(fields, "muted", operation="set the volume"),
        }

    async def mute(self, device_id: str) -> Dict[str, Any]:
        """Mute. Explicit desired state - never a toggle."""
        return await self._set_mute(device_id, True)

    async def unmute(self, device_id: str) -> Dict[str, Any]:
        """Unmute. Explicit desired state - never a toggle."""
        return await self._set_mute(device_id, False)

    async def _set_mute(self, device_id: str, muted: bool) -> Dict[str, Any]:
        fields = await self._call(
            device_id,
            MessageType.MUTE_SET,
            MessageType.MUTE_SET_RESPONSE,
            CAPABILITY_SYSTEM_VOLUME,
            payload={"muted": muted},
            operation="mute the phone" if muted else "unmute the phone",
        )
        return {
            "device_id": device_id,
            "volume": _require_percent(fields, "volume", operation="change mute state"),
            "muted": _require_bool(fields, "muted", operation="change mute state"),
        }

    # ------------------------------------------------------------------
    # Brightness
    # ------------------------------------------------------------------
    async def get_brightness(self, device_id: str) -> Dict[str, Any]:
        fields = await self._call(
            device_id,
            MessageType.BRIGHTNESS_GET,
            MessageType.BRIGHTNESS_GET_RESPONSE,
            CAPABILITY_SYSTEM_BRIGHTNESS,
            operation="report the brightness",
        )
        return self._brightness_result(device_id, fields, "report the brightness")

    async def set_brightness(self, device_id: str, level: int) -> Dict[str, Any]:
        """Set screen brightness to an absolute 0-100 percentage.

        This does **not** turn adaptive brightness off. The result reports
        whether the phone is in adaptive mode, because in that mode Android may
        adjust the value itself - hiding that would be a lie about the outcome.
        """
        value = validate_percent(level, field="level")
        fields = await self._call(
            device_id,
            MessageType.BRIGHTNESS_SET,
            MessageType.BRIGHTNESS_SET_RESPONSE,
            CAPABILITY_SYSTEM_BRIGHTNESS,
            payload={"level": value},
            operation="set the brightness",
        )
        return self._brightness_result(device_id, fields, "set the brightness")

    @staticmethod
    def _brightness_result(device_id: str, fields: Mapping[str, Any], operation: str) -> Dict[str, Any]:
        result = {
            "device_id": device_id,
            "brightness": _require_percent(fields, "brightness", operation=operation),
        }
        if "adaptive" in fields:
            result["adaptive"] = _require_bool(fields, "adaptive", operation=operation)
        return result

    # ------------------------------------------------------------------
    # Wi-Fi
    # ------------------------------------------------------------------
    async def get_wifi_status(self, device_id: str) -> Dict[str, Any]:
        fields = await self._call(
            device_id,
            MessageType.WIFI_STATUS,
            MessageType.WIFI_STATUS_RESPONSE,
            CAPABILITY_SYSTEM_WIFI,
            operation="report the Wi-Fi state",
        )
        return {
            "device_id": device_id,
            "enabled": _require_bool(fields, "enabled", operation="report the Wi-Fi state"),
        }

    async def set_wifi_enabled(self, device_id: str, enabled: bool) -> Dict[str, Any]:
        """Turn the Wi-Fi radio on or off. Radio state only.

        No SSID, no password, no network joining, no scanning and no arbitrary
        network configuration - none of that is expressible here.
        """
        if not isinstance(enabled, bool):
            raise AndroidSystemInvalidArgumentError("'enabled' must be a boolean.")
        fields = await self._call(
            device_id,
            MessageType.WIFI_SET,
            MessageType.WIFI_SET_RESPONSE,
            CAPABILITY_SYSTEM_WIFI,
            payload={"enabled": enabled},
            operation="turn Wi-Fi on" if enabled else "turn Wi-Fi off",
        )
        return {
            "device_id": device_id,
            "enabled": _require_bool(fields, "enabled", operation="change the Wi-Fi state"),
        }

    # ------------------------------------------------------------------
    # Bluetooth
    # ------------------------------------------------------------------
    async def get_bluetooth_status(self, device_id: str) -> Dict[str, Any]:
        fields = await self._call(
            device_id,
            MessageType.BLUETOOTH_STATUS,
            MessageType.BLUETOOTH_STATUS_RESPONSE,
            CAPABILITY_SYSTEM_BLUETOOTH,
            operation="report the Bluetooth state",
        )
        return {
            "device_id": device_id,
            "enabled": _require_bool(fields, "enabled", operation="report the Bluetooth state"),
        }

    async def set_bluetooth_enabled(self, device_id: str, enabled: bool) -> Dict[str, Any]:
        """Turn the Bluetooth radio on or off. Radio state only.

        No discovery, no pairing with other devices, no PIN handling and no data
        transfer - none of that is expressible here.
        """
        if not isinstance(enabled, bool):
            raise AndroidSystemInvalidArgumentError("'enabled' must be a boolean.")
        fields = await self._call(
            device_id,
            MessageType.BLUETOOTH_SET,
            MessageType.BLUETOOTH_SET_RESPONSE,
            CAPABILITY_SYSTEM_BLUETOOTH,
            payload={"enabled": enabled},
            operation="turn Bluetooth on" if enabled else "turn Bluetooth off",
        )
        return {
            "device_id": device_id,
            "enabled": _require_bool(fields, "enabled", operation="change the Bluetooth state"),
        }
