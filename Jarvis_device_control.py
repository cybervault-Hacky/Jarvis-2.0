"""LiveKit bridge for the JARVIS secure device-tool framework (Phase 1).

This is the *additive* integration point between the existing JARVIS agent
(``agent.py`` -> ``Agent(tools=[...])``) and the new secure framework in
:mod:`jarvis_devices`.

Existing tools (``Jarvis_google_search``, ``jarvis_get_whether``,
``Jarvis_file_opner``, ``Jarvis_window_CTRL``, ``keyboard_mouse_CTRL``) keep
working exactly as before - nothing here replaces them.

Two function tools are exposed to the model:

``device_action(tool_name, arguments_json)``
    Run a *registered* device tool. Unregistered names are rejected; arguments
    are validated against the tool's schema; permissions and confirmations are
    enforced by the framework.

``device_confirmation(confirmation_id, approved)``
    Apply the user's yes/no to a pending confirmation. When approved, the
    stored action is executed; when declined, nothing runs.

Both are thin ``@function_tool`` wrappers around plain coroutines
(:func:`run_device_action` / :func:`resolve_device_confirmation`) so the logic
stays testable whether or not LiveKit is installed.

Phase 1 registers no real device action - only a SAFE framework self check
(``jarvis.framework.diagnostics``) that touches no device. Future phases add
tools with :func:`register_device_tool`.

There is deliberately no tool here that runs shell commands, evaluates strings
or performs an action that is not an explicitly registered tool.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional, Tuple, Union

try:  # pragma: no cover - depends on the runtime environment
    from livekit.agents import function_tool
except ImportError:  # keeps this module importable for tests / tooling
    def function_tool(func):
        return func

from jarvis_devices import (
    BaseDeviceTool,
    ConfirmationManager,
    ConfirmationPolicy,
    DeviceActionManager,
    DeviceToolRegistry,
    ErrorCode,
    PermissionPolicy,
    PlatformRegistry,
    ToolResult,
    ToolResultStatus,
)
from jarvis_devices.adapters import AndroidDeviceAdapter, PCDeviceAdapter
from jarvis_devices.diagnostics import FrameworkDiagnosticsTool
from jarvis_devices.permissions import (
    PERMISSION_ANDROID_BRIDGE_MANAGE,
    PERMISSION_ANDROID_BRIDGE_PAIR,
    PERMISSION_ANDROID_SYSTEM_CONTROL,
    PERMISSION_ANDROID_SYSTEM_READ,
    PERMISSION_ANDROID_CALL_READ,
    PERMISSION_ANDROID_CALL_CONTROL,
    PERMISSION_ANDROID_MESSAGE_READ,
    PERMISSION_ANDROID_MESSAGE_SEND,
    PERMISSION_APP_CONTROL,
    PERMISSION_DISPLAY_CONTROL,
    PERMISSION_NETWORK_CONTROL,
    PERMISSION_POWER_CONTROL,
    PERMISSION_VOLUME_CONTROL,
)
from jarvis_devices.pc_apps import (
    PC_APPLICATION_TOOL_NAMES,
    ApplicationCatalog,
    ApplicationSpec,
    build_pc_application_tools,
    create_default_pc_application_backend,
    default_application_catalog,
)
from jarvis_devices.pc_system import (
    PC_SYSTEM_TOOL_NAMES,
    build_pc_system_tools,
    create_default_pc_system_backend,
)
from jarvis_devices.pc_power import (
    PC_POWER_TOOL_NAMES,
    build_pc_power_tools,
    create_default_pc_power_backend,
)
from jarvis_devices.android_bridge import (
    AndroidDeviceBridge,
    create_default_android_bridge,
)
from jarvis_devices.android_tools import (
    ANDROID_BRIDGE_TOOL_NAMES,
    build_android_bridge_tools,
)
from jarvis_devices.android_system_tools import (
    ANDROID_SYSTEM_TOOL_NAMES,
    build_android_system_tools,
)
from jarvis_devices.android_call_tools import (
    ANDROID_CALL_TOOL_NAMES,
    build_android_call_tools,
)
from jarvis_devices.android_message_tools import (
    ANDROID_MESSAGE_TOOL_NAMES,
    build_android_message_tools,
)

logger = logging.getLogger(__name__)

__all__ = [
    "device_registry",
    "device_permissions",
    "device_confirmations",
    "device_confirmation_policy",
    "device_platforms",
    "device_manager",
    "register_device_tool",
    "unregister_device_tool",
    "grant_device_permission",
    "framework_summary",
    "run_device_action",
    "resolve_device_confirmation",
    "device_action",
    "device_confirmation",
    # Phase 2 - PC application control
    "pc_application_backend",
    "pc_application_catalog",
    "pc_application_tools",
    "register_application",
    "run_list_open_applications",
    "run_application_status",
    "run_open_application",
    "run_focus_application",
    "run_close_application",
    "list_open_applications",
    "application_status",
    "open_application",
    "focus_application",
    "close_application",
    # Phase 3 - PC system control
    "pc_system_backend",
    "pc_system_tools",
    "run_system_status",
    "run_get_system_volume",
    "run_set_system_volume",
    "run_get_system_mute",
    "run_mute_system",
    "run_unmute_system",
    "run_get_system_brightness",
    "run_set_system_brightness",
    "run_wifi_status",
    "run_wifi_enable",
    "run_wifi_disable",
    "run_bluetooth_status",
    "run_bluetooth_enable",
    "run_bluetooth_disable",
    "system_status",
    "get_system_volume",
    "set_system_volume",
    "get_system_mute",
    "mute_system",
    "unmute_system",
    "get_system_brightness",
    "set_system_brightness",
    "wifi_status",
    "wifi_enable",
    "wifi_disable",
    "bluetooth_status",
    "bluetooth_enable",
    "bluetooth_disable",
    # Phase 4 - PC power control
    "pc_power_backend",
    "pc_power_tools",
    "run_shutdown_pc",
    "run_restart_pc",
    "run_sleep_pc",
    "run_hibernate_pc",
    "run_logoff_pc",
    "shutdown_pc",
    "restart_pc",
    "sleep_pc",
    "hibernate_pc",
    "logoff_pc",
    # Phase 5 - Android device bridge
    "android_bridge",
    "android_bridge_tools",
    "android_bridge_summary",
    "run_android_bridge_status",
    "run_android_device_list",
    "run_android_device_status",
    "run_android_device_pair",
    "run_android_device_unpair",
    "run_android_device_revoke",
    "android_bridge_status",
    "android_device_list",
    "android_device_status",
    "android_device_pair",
    "android_device_unpair",
    "android_device_revoke",
    # Phase 6 - Android system control
    "android_system",
    "android_system_tools",
    "run_android_system_status",
    "run_android_get_volume",
    "run_android_set_volume",
    "run_android_mute",
    "run_android_unmute",
    "run_android_get_brightness",
    "run_android_set_brightness",
    "run_android_wifi_status",
    "run_android_wifi_enable",
    "run_android_wifi_disable",
    "run_android_bluetooth_status",
    "run_android_bluetooth_enable",
    "run_android_bluetooth_disable",
    "android_system_status",
    "android_get_volume",
    "android_set_volume",
    "android_mute",
    "android_unmute",
    "android_get_brightness",
    "android_set_brightness",
    "android_wifi_status",
    "android_wifi_enable",
    "android_wifi_disable",
    "android_bluetooth_status",
    "android_bluetooth_enable",
    "android_bluetooth_disable",
    # Phase 7 - Android calls
    "android_calls",
    "android_call_tools",
    "run_android_call_status",
    "run_android_call_dial",
    "run_android_call_answer",
    "run_android_call_reject",
    "run_android_call_end",
    "android_call_status",
    "android_call_dial",
    "android_call_answer",
    "android_call_reject",
    "android_call_end",
    # Phase 8 - Android text messaging
    "android_messages",
    "android_message_tools",
    "run_android_message_status",
    "run_android_message_send",
    "android_message_status",
    "android_message_send",
]

# ---------------------------------------------------------------------------
# Framework singletons for this JARVIS instance
# ---------------------------------------------------------------------------
device_registry = DeviceToolRegistry()
device_permissions = PermissionPolicy.with_local_defaults()
device_confirmation_policy = ConfirmationPolicy()  # EXTERNAL_ACTION + DESTRUCTIVE
device_confirmations = ConfirmationManager(policy=device_confirmation_policy)
device_platforms = PlatformRegistry()
for _adapter in (PCDeviceAdapter(), AndroidDeviceAdapter()):
    device_platforms.register(_adapter)

device_manager = DeviceActionManager(
    device_registry,
    device_permissions,
    device_confirmations,
    device_platforms,
    confirmation_policy=device_confirmation_policy,
)


# ---------------------------------------------------------------------------
# Registration helpers used by later phases
# ---------------------------------------------------------------------------
def framework_summary() -> Dict[str, Any]:
    """A safe snapshot of the framework state (no argument values, no secrets)."""
    return {
        "registered_tools": list(device_registry.names()),
        "known_applications": list(pc_application_catalog.names()),
        "system_capabilities": _system_capabilities(),
        "power_capabilities": _power_capabilities(),
        "android_bridge": _android_bridge_summary(),
        "android_system_capabilities": _android_system_capabilities(),
        "android_call_capabilities": _android_call_capabilities(),
        "android_message_capabilities": _android_message_capabilities(),
        "available_tools": [tool.name for tool in device_registry.list_tools(available_only=True)],
        "granted_permission_count": len(device_permissions.granted_permissions),
        "platforms": device_platforms.describe(),
        "pending_confirmations": len(device_confirmations.pending()),
    }


def register_device_tool(tool: BaseDeviceTool, *, override: bool = False) -> BaseDeviceTool:
    """Register a device tool so JARVIS may call it.

    Example for a later phase::

        register_device_tool(PCVolumeTool())
        grant_device_permission(PERMISSION_MEDIA_CONTROL)
    """
    return device_registry.register(tool, override=override)


def unregister_device_tool(tool_or_name: Union[BaseDeviceTool, str]) -> bool:
    """Remove a device tool; returns ``False`` when it was not registered."""
    return device_registry.unregister(tool_or_name)


def grant_device_permission(*permissions: str) -> None:
    """Explicitly grant permissions required by a newly registered tool."""
    device_permissions.grant(*permissions)


# The only tool registered in Phase 1: a SAFE self check that controls nothing.
device_registry.register(FrameworkDiagnosticsTool(framework_summary))


# ---------------------------------------------------------------------------
# Phase 2 - PC application control
# ---------------------------------------------------------------------------
pc_application_backend = create_default_pc_application_backend()
pc_application_catalog = default_application_catalog()
pc_application_tools = build_pc_application_tools(pc_application_backend, pc_application_catalog)
for _pc_tool in pc_application_tools:
    device_registry.register(_pc_tool)

# Explicit opt-in for the three control operations (open / focus / close).
# Revoke it again with ``device_permissions.revoke(PERMISSION_APP_CONTROL)``.
device_permissions.grant(PERMISSION_APP_CONTROL)


def register_application(spec: ApplicationSpec) -> ApplicationSpec:
    """Add an application to the catalog JARVIS is allowed to control.

    The spec validates its own launch target, so neither model input nor a
    careless edit can introduce a command line.
    """
    return pc_application_catalog.add(spec)


# ---------------------------------------------------------------------------
# Phase 3 - PC system control (volume, mute, brightness, Wi-Fi, Bluetooth)
#
# The model never supplies a command here: every one of these tools takes either
# nothing or a single integer percentage that the tool's own ArgumentSchema
# validates, so no model input can reach a shell, a service or a network
# configuration command.
# ---------------------------------------------------------------------------
pc_system_backend = create_default_pc_system_backend()
pc_system_tools = build_pc_system_tools(pc_system_backend)
for _pc_system_tool in pc_system_tools:
    device_registry.register(_pc_system_tool)

# Explicit opt-in for the three local control capabilities. Connectivity
# (Wi-Fi / Bluetooth) is additionally gated by the confirmation policy because
# those tools are EXTERNAL_ACTION.
# Revoke any of them with ``device_permissions.revoke(<permission>)``.
device_permissions.grant(
    PERMISSION_VOLUME_CONTROL,
    PERMISSION_DISPLAY_CONTROL,
    PERMISSION_NETWORK_CONTROL,
)
# PERMISSION_BLUETOOTH_CONTROL is deliberately NOT granted: Windows exposes no
# reliable programmatic Bluetooth radio switch, so those two tools stay
# permission denied instead of pretending to work. Grant it explicitly if a
# future backend ever supports the radio.


def _system_capabilities() -> Dict[str, str]:
    """Which system capabilities this PC's backend claims (safe, no values)."""
    try:
        return dict(pc_system_backend.capabilities() or {})
    except Exception:  # noqa: BLE001 - a broken backend simply reports nothing
        return {}


# ---------------------------------------------------------------------------
# Phase 4 - PC power control (shutdown, restart, sleep, hibernate, logoff)
#
# No tool here takes an argument: the model picks an operation, nothing else.
# There is no timeout, force flag, reason string, remote host or command - so no
# model input can reach the operating system at all. Every operation is
# EXTERNAL_ACTION *and* declares itself non-negotiable, so the confirmation
# policy asks first and cannot be configured out of asking.
# ---------------------------------------------------------------------------
pc_power_backend = create_default_pc_power_backend()
pc_power_tools = build_pc_power_tools(pc_power_backend)
for _pc_power_tool in pc_power_tools:
    device_registry.register(_pc_power_tool)

# Explicit opt-in for power control. Revoke it with
# ``device_permissions.revoke(PERMISSION_POWER_CONTROL)`` - the tools then answer
# PERMISSION_DENIED and nothing can reach the operating system.
device_permissions.grant(PERMISSION_POWER_CONTROL)


def _power_capabilities() -> Dict[str, str]:
    """Which power operations this PC's backend claims (safe, no values)."""
    try:
        return {
            key: value
            for key, value in (pc_power_backend.capabilities() or {}).items()
            if not key.endswith("_detail")
        }
    except Exception:  # noqa: BLE001 - a broken backend simply reports nothing
        return {}


# ---------------------------------------------------------------------------
# Phase 5 - Android device bridge (pairing, trust, connection, capabilities)
#
# This is the PC side of a JARVIS <-> Android companion link: device identity,
# cryptographic pairing, trust states, connection lifecycle, heartbeat and
# capability discovery. It is the *foundation* only - no phone setting is
# changed by anything in this phase (no volume, brightness, Wi-Fi, Bluetooth,
# app launch, power, calls, messaging, notifications, files, screen, camera,
# microphone or location), and there is no ADB or shell path of any kind.
#
# Trust changes are EXTERNAL_ACTION *and* confirmation_mandatory, so a natural
# language request alone can never pair or revoke a device.
# ---------------------------------------------------------------------------
def _android_audit_hook(event: str, fields: Dict[str, Any]) -> None:
    """Forward safe bridge lifecycle events into the JARVIS audit log.

    The bridge only ever emits ids, states and short reasons here - never key
    material - and the audit logger redacts again on the way out.
    """
    device_manager.audit.log(event, tool_name="android.bridge", **fields)


android_bridge = create_default_android_bridge(audit_hook=_android_audit_hook)
android_bridge_tools = build_android_bridge_tools(android_bridge)
for _android_tool in android_bridge_tools:
    device_registry.register(_android_tool)

# Explicit opt-in. Revoke either permission and the matching tools answer
# PERMISSION_DENIED without touching the bridge:
#   device_permissions.revoke(PERMISSION_ANDROID_BRIDGE_MANAGE)
device_permissions.grant(PERMISSION_ANDROID_BRIDGE_PAIR, PERMISSION_ANDROID_BRIDGE_MANAGE)


def android_bridge_summary() -> Dict[str, Any]:
    """Safe snapshot of the bridge (no key material, no network endpoints)."""
    try:
        status = android_bridge.status()
    except Exception:  # noqa: BLE001 - a broken bridge reports itself unavailable
        return {"available": False}
    return {
        "available": status["available"],
        "protocol_version": status["protocol_version"],
        "transport": status["transport"]["transport"],
        "devices": status["devices"],
        "paired_devices": status["paired_devices"],
        "connected_devices": status["connected_devices"],
        "pending_pairings": status["pending_pairings"],
        "capabilities_understood": status["capabilities_understood"],
    }


#: Internal alias used by ``framework_summary`` (defined above this block).
_android_bridge_summary = android_bridge_summary


# ---------------------------------------------------------------------------
# Phase 6 - Android system control (status, volume, mute, brightness, radios)
#
# Everything here goes through the Phase 5 AndroidDeviceBridge: signed frames,
# request/response correlation, sequence numbers, nonces, session binding and
# replay protection. No tool opens a socket, runs ADB, spawns a process or
# accepts a command, a destination or an Android API name.
#
# Confirmation follows the existing policy instead of a blanket rule: reading
# state needs none, volume/brightness are LOW_RISK, and switching a radio is
# EXTERNAL_ACTION so the policy asks first - the same split the PC's own Wi-Fi
# and Bluetooth tools use. No tool takes a confirm flag, so nothing the model
# generates can switch confirmation off.
# ---------------------------------------------------------------------------
android_system_tools = build_android_system_tools(android_bridge)
#: The orchestrator all thirteen tools share (one bridge, one timeout policy).
android_system = android_system_tools[0].control
for _android_system_tool in android_system_tools:
    device_registry.register(_android_system_tool)

# Explicit opt-in. Revoke either permission and the matching tools answer
# PERMISSION_DENIED without the bridge ever being contacted:
#   device_permissions.revoke(PERMISSION_ANDROID_SYSTEM_CONTROL)
device_permissions.grant(PERMISSION_ANDROID_SYSTEM_READ, PERMISSION_ANDROID_SYSTEM_CONTROL)


def _android_system_capabilities() -> Dict[str, str]:
    """Which Android system capabilities this JARVIS build understands."""
    from jarvis_devices.android_system import SYSTEM_CONTROL_CAPABILITIES

    return {capability: "understood" for capability in SYSTEM_CONTROL_CAPABILITIES}


# ---------------------------------------------------------------------------
# Phase 7 - Android calls
#
# The five explicit call tools share the same Phase 5 AndroidDeviceBridge as
# system control.  Their only target is a registered device id and dial accepts
# only a canonical E.164 phone number.  No raw telecom API, call id, recording,
# contact lookup, microphone, messaging, shell or network endpoint is exposed.
# ---------------------------------------------------------------------------
android_call_tools = build_android_call_tools(android_bridge)
android_calls = android_call_tools[0].control
for _android_call_tool in android_call_tools:
    device_registry.register(_android_call_tool)

# Explicit, narrowly scoped opt-in.  Read and control are separate; revoking
# control blocks dial/answer/reject/end without affecting status.
device_permissions.grant(PERMISSION_ANDROID_CALL_READ, PERMISSION_ANDROID_CALL_CONTROL)


def _android_call_capabilities() -> Dict[str, str]:
    """Which explicit Android call operations this JARVIS build understands."""
    from jarvis_devices.android_calls import CALL_CAPABILITIES

    return {capability: "understood" for capability in CALL_CAPABILITIES}


# ---------------------------------------------------------------------------
# Phase 8 - Android text messaging
#
# The two fixed tools reuse the authenticated Phase 5 bridge, current registry,
# permission policy and confirmation manager.  They expose neither contacts nor
# message history; sending requires a canonical recipient and opaque text.
# ---------------------------------------------------------------------------
android_message_tools = build_android_message_tools(android_bridge)
android_messages = android_message_tools[0].control
for _android_message_tool in android_message_tools:
    device_registry.register(_android_message_tool)

device_permissions.grant(PERMISSION_ANDROID_MESSAGE_READ, PERMISSION_ANDROID_MESSAGE_SEND)


def _android_message_capabilities() -> Dict[str, str]:
    """Which explicit Android messaging capabilities this build understands."""
    from jarvis_devices.android_messages import MESSAGE_CAPABILITIES

    return {capability: "understood" for capability in MESSAGE_CAPABILITIES}


# ---------------------------------------------------------------------------
# Argument handling - JSON only, never a shell
# ---------------------------------------------------------------------------
def parse_arguments(arguments_json: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Parse the model supplied argument object.

    Returns ``(arguments, error_message)``. Only a JSON object is accepted; the
    string is never interpreted, expanded or executed.
    """
    text = (arguments_json or "").strip()
    if not text:
        return {}, None
    try:
        parsed = json.loads(text)
    except (ValueError, TypeError) as exc:
        return None, f"arguments_json must be a JSON object: {exc}"
    if not isinstance(parsed, dict):
        return None, "arguments_json must be a JSON object of name -> value"
    return parsed, None


def describe_result(result: ToolResult) -> str:
    """Turn a :class:`ToolResult` into the string JARVIS speaks back."""
    if result.success:
        return f"✅ {result.tool_name or 'action'}: {result.message}"

    if result.status is ToolResultStatus.PENDING_CONFIRMATION:
        confirmation_id = result.data.get("confirmation_id", "")
        return (
            f"⚠️ Confirmation required: {result.message} "
            f"(confirmation id: {confirmation_id})"
        )

    detail = result.error_code or result.status.value
    return f"❌ Not executed ({detail}): {result.message}"


# ---------------------------------------------------------------------------
# Implementation (plain coroutines, so they can be tested and reused directly)
# ---------------------------------------------------------------------------
async def run_device_action(tool_name: str, arguments_json: str = "") -> str:
    """Validate the JSON arguments and ask the framework to run the tool."""
    arguments, parse_error = parse_arguments(arguments_json)
    if parse_error is not None:
        return describe_result(
            ToolResult.invalid_argument(
                parse_error,
                error=parse_error,
                tool_name=str(tool_name or "").strip(),
            )
        )

    result = await device_manager.request(str(tool_name or "").strip(), arguments)
    return describe_result(result)


async def resolve_device_confirmation(confirmation_id: str, approved: bool) -> str:
    """Apply the user's yes/no to a pending confirmation."""
    confirmation_id = (confirmation_id or "").strip()
    if not confirmation_id:
        return describe_result(
            ToolResult.invalid_argument(
                "A confirmation_id is required.",
                error=ErrorCode.INVALID_ARGUMENT,
            )
        )
    if not isinstance(approved, bool):
        return describe_result(
            ToolResult.invalid_argument(
                "approved must be a boolean.", error=ErrorCode.INVALID_ARGUMENT
            )
        )
    result = await device_manager.resolve_confirmation(confirmation_id, approved)
    return describe_result(result)


# ---------------------------------------------------------------------------
# LiveKit function tools
# ---------------------------------------------------------------------------
@function_tool
async def device_action(tool_name: str, arguments_json: str = "") -> str:
    """Run one of JARVIS's registered device tools.

    Only tools that are explicitly registered in the device tool registry can
    run. Arguments must be a JSON object matching the tool's declared schema.
    Sensitive tools answer with a confirmation request instead of acting.
    """
    return await run_device_action(tool_name, arguments_json)


@function_tool
async def device_confirmation(confirmation_id: str, approved: bool) -> str:
    """Answer a pending device confirmation on the user's behalf.

    Pass ``approved=True`` only after the user has clearly said yes. Anything
    else is recorded as a refusal and no device action runs.
    """
    return await resolve_device_confirmation(confirmation_id, approved)


# ---------------------------------------------------------------------------
# Phase 2 - PC application control
#
# Plain coroutines first (testable without LiveKit), thin @function_tool
# wrappers second - the same pattern Phase 1 established, because LiveKit's
# decorator replaces the callable with a FunctionTool object.
# ---------------------------------------------------------------------------
async def _request(tool_name: str, arguments: Dict[str, Any]) -> str:
    """Run a registered device tool and describe the outcome."""
    return describe_result(await device_manager.request(tool_name, arguments))


async def run_list_open_applications(limit: int = 25) -> str:
    """List the applications that currently have an open window."""
    return await _request("pc.app.list", {"limit": int(limit)})


async def run_application_status(app: str) -> str:
    """Report whether an application is running."""
    return await _request("pc.app.status", {"app": str(app or "")})


async def run_open_application(app: str, focus_if_running: bool = True) -> str:
    """Launch a catalogued application (or focus it when it is already open)."""
    return await _request("pc.app.open", {"app": str(app or ""), "focus_if_running": bool(focus_if_running)})


async def run_focus_application(app: str, window_title: str = "") -> str:
    """Bring an open application window to the front."""
    return await _request("pc.app.focus", {"app": str(app or ""), "window_title": str(window_title or "")})


async def run_close_application(app: str, window_title: str = "") -> str:
    """Gracefully close an application window."""
    return await _request("pc.app.close", {"app": str(app or ""), "window_title": str(window_title or "")})


@function_tool
async def list_open_applications(limit: int = 25) -> str:
    """List the PC applications that currently have an open window.

    Returns each application name, its window titles and window state. This is
    read only - it never changes anything.
    """
    return await run_list_open_applications(limit)


@function_tool
async def application_status(app: str) -> str:
    """Check whether a PC application is currently running.

    Use a known application name such as Chrome, Edge, Firefox, Notepad,
    Calculator, File Explorer, VS Code, VLC, Paint, Control Panel, Windows
    Settings or Postman. Unknown names are reported instead of guessed.
    """
    return await run_application_status(app)


@function_tool
async def open_application(app: str, focus_if_running: bool = True) -> str:
    """Open (launch) a known PC application.

    Only applications from JARVIS's catalog can be opened - a command, a script
    or a file path is not accepted. When the application is already running it
    is brought to the front instead of being launched twice.
    """
    return await run_open_application(app, focus_if_running)


@function_tool
async def focus_application(app: str, window_title: str = "") -> str:
    """Bring an open PC application window to the front.

    When several windows of the same application are open, pass part of the
    window title in ``window_title`` to pick one.
    """
    return await run_focus_application(app, window_title)


@function_tool
async def close_application(app: str, window_title: str = "") -> str:
    """Gracefully close an open PC application window.

    The application is asked to close itself, so it can still offer to save
    work. No process is ever terminated. When several windows match, pass part
    of the window title in ``window_title`` to pick one.
    """
    return await run_close_application(app, window_title)


# ---------------------------------------------------------------------------
# Phase 3 - PC system control
#
# Plain coroutines first (testable without LiveKit), thin @function_tool
# wrappers second - the same pattern Phases 1 and 2 established, because
# LiveKit's decorator replaces the callable with a FunctionTool object.
# ---------------------------------------------------------------------------
async def run_system_status() -> str:
    """Report this PC's volume, mute, brightness, Wi-Fi and Bluetooth status."""
    return await _request("pc.system.status", {})


async def run_get_system_volume() -> str:
    """Read the master volume percentage and mute state."""
    return await _request("pc.system.get_volume", {})


async def run_set_system_volume(level: int) -> str:
    """Set the master volume to an absolute percentage (0-100)."""
    return await _request("pc.system.set_volume", {"level": int(level)})


async def run_get_system_mute() -> str:
    """Report whether the master audio output is muted."""
    return await _request("pc.system.get_mute", {})


async def run_mute_system() -> str:
    """Mute the master audio output."""
    return await _request("pc.system.mute", {})


async def run_unmute_system() -> str:
    """Unmute the master audio output."""
    return await _request("pc.system.unmute", {})


async def run_get_system_brightness() -> str:
    """Read the display brightness percentage."""
    return await _request("pc.system.get_brightness", {})


async def run_set_system_brightness(level: int) -> str:
    """Set the display brightness to an absolute percentage (0-100)."""
    return await _request("pc.system.set_brightness", {"level": int(level)})


async def run_wifi_status() -> str:
    """Report whether the Wi-Fi radio is on, off or unknown."""
    return await _request("pc.system.wifi.status", {})


async def run_wifi_enable() -> str:
    """Turn the Wi-Fi radio on (EXTERNAL_ACTION -> confirmation)."""
    return await _request("pc.system.wifi.enable", {})


async def run_wifi_disable() -> str:
    """Turn the Wi-Fi radio off (EXTERNAL_ACTION -> confirmation)."""
    return await _request("pc.system.wifi.disable", {})


async def run_bluetooth_status() -> str:
    """Report whether the Bluetooth radio is on, off or unknown."""
    return await _request("pc.system.bluetooth.status", {})


async def run_bluetooth_enable() -> str:
    """Turn the Bluetooth radio on (EXTERNAL_ACTION -> confirmation)."""
    return await _request("pc.system.bluetooth.enable", {})


async def run_bluetooth_disable() -> str:
    """Turn the Bluetooth radio off (EXTERNAL_ACTION -> confirmation)."""
    return await _request("pc.system.bluetooth.disable", {})


@function_tool
async def system_status() -> str:
    """Report this PC's system status: master volume, mute, display brightness,
    Wi-Fi and Bluetooth.

    Read only - it changes nothing, and it never reports files, browsing
    history, saved passwords or network credentials.
    """
    return await run_system_status()


@function_tool
async def get_system_volume() -> str:
    """Read the PC's master volume percentage and whether it is muted."""
    return await run_get_system_volume()


@function_tool
async def set_system_volume(level: int) -> str:
    """Set the PC's master volume to an exact percentage.

    ``level`` must be a whole number from 0 (silent) to 100 (loudest). JARVIS
    reports the volume the PC actually ended up at.
    """
    return await run_set_system_volume(level)


@function_tool
async def get_system_mute() -> str:
    """Report whether the PC's master audio output is currently muted."""
    return await run_get_system_mute()


@function_tool
async def mute_system() -> str:
    """Mute the PC's master audio output."""
    return await run_mute_system()


@function_tool
async def unmute_system() -> str:
    """Unmute the PC's master audio output."""
    return await run_unmute_system()


@function_tool
async def get_system_brightness() -> str:
    """Read the PC display brightness percentage.

    Monitors without software brightness control are reported as unavailable
    rather than guessed.
    """
    return await run_get_system_brightness()


@function_tool
async def set_system_brightness(level: int) -> str:
    """Set the PC display brightness to an exact percentage.

    ``level`` must be a whole number from 0 (darkest) to 100 (brightest).
    """
    return await run_set_system_brightness(level)


@function_tool
async def wifi_status() -> str:
    """Report whether the PC's Wi-Fi radio is on, off or unknown.

    Read only. It never lists saved networks and never exposes credentials.
    """
    return await run_wifi_status()


@function_tool
async def wifi_enable() -> str:
    """Turn the PC's Wi-Fi radio on.

    This changes connectivity, so it asks the user for confirmation first.
    """
    return await run_wifi_enable()


@function_tool
async def wifi_disable() -> str:
    """Turn the PC's Wi-Fi radio off.

    This changes connectivity, so it asks the user for confirmation first.
    """
    return await run_wifi_disable()


@function_tool
async def bluetooth_status() -> str:
    """Report whether the PC's Bluetooth radio is on, off or unknown."""
    return await run_bluetooth_status()


@function_tool
async def bluetooth_enable() -> str:
    """Turn the PC's Bluetooth radio on.

    Windows exposes no reliable programmatic Bluetooth switch, so this reports
    that it is unavailable instead of pretending to work.
    """
    return await run_bluetooth_enable()


@function_tool
async def bluetooth_disable() -> str:
    """Turn the PC's Bluetooth radio off.

    Windows exposes no reliable programmatic Bluetooth switch, so this reports
    that it is unavailable instead of pretending to work.
    """
    return await run_bluetooth_disable()


# ---------------------------------------------------------------------------
# Phase 4 - PC power control
#
# Plain coroutines first (testable without LiveKit), thin @function_tool
# wrappers second - the same pattern Phases 1-3 established. Note that every
# one of these returns a confirmation request on the first call; the action only
# runs after ``device_confirmation`` reports an explicit yes.
# ---------------------------------------------------------------------------
async def run_shutdown_pc() -> str:
    """Shut this PC down (requires confirmation)."""
    return await _request("pc.power.shutdown", {})


async def run_restart_pc() -> str:
    """Restart this PC (requires confirmation)."""
    return await _request("pc.power.restart", {})


async def run_sleep_pc() -> str:
    """Put this PC to sleep (requires confirmation)."""
    return await _request("pc.power.sleep", {})


async def run_hibernate_pc() -> str:
    """Hibernate this PC (requires confirmation)."""
    return await _request("pc.power.hibernate", {})


async def run_logoff_pc() -> str:
    """Log the current user out of this PC (requires confirmation)."""
    return await _request("pc.power.logoff", {})


@function_tool
async def shutdown_pc() -> str:
    """Shut this PC down.

    This ends the user's session and powers the machine off, so it always asks
    for confirmation first. Use it only when the user has clearly asked to shut
    the computer down. It takes no arguments - there is no timeout, no force
    option and no other machine.
    """
    return await run_shutdown_pc()


@function_tool
async def restart_pc() -> str:
    """Restart this PC.

    Always asks for confirmation first. It takes no arguments.
    """
    return await run_restart_pc()


@function_tool
async def sleep_pc() -> str:
    """Put this PC to sleep.

    Always asks for confirmation first. It takes no arguments.
    """
    return await run_sleep_pc()


@function_tool
async def hibernate_pc() -> str:
    """Hibernate this PC.

    Always asks for confirmation first. Machines without a hibernation file
    report that it is unavailable instead of pretending. It takes no arguments.
    """
    return await run_hibernate_pc()


@function_tool
async def logoff_pc() -> str:
    """Log the current user out of this PC (sign out).

    Always asks for confirmation first. It takes no arguments.
    """
    return await run_logoff_pc()


# ---------------------------------------------------------------------------
# Phase 5 tools - Android device bridge
#
# Six tools only. None of them accepts a network address, a port, a command, a
# shell string, an ADB invocation or a file path: the only arguments are a
# registered device id or a pairing id, both of which must already exist in the
# bridge's own state. Transport level operations are deliberately not exposed.
# ---------------------------------------------------------------------------
async def run_android_bridge_status() -> str:
    """Report Android bridge health (no confirmation needed - it changes nothing)."""
    return await _request("android.bridge.status", {})


async def run_android_device_list() -> str:
    """List the Android devices this JARVIS knows."""
    return await _request("android.device.list", {})


async def run_android_device_status(device: str) -> str:
    """Report one Android device's trust state, connection and health."""
    return await _request("android.device.status", {"device": device})


async def run_android_device_pair(pairing: str) -> str:
    """Approve a verified Android pairing (requires confirmation)."""
    return await _request("android.device.pair", {"pairing": pairing})


async def run_android_device_unpair(device: str) -> str:
    """Unpair and forget an Android device (requires confirmation)."""
    return await _request("android.device.unpair", {"device": device})


async def run_android_device_revoke(device: str) -> str:
    """Permanently revoke an Android device's trust (requires confirmation)."""
    return await _request("android.device.revoke", {"device": device})


@function_tool
async def android_bridge_status() -> str:
    """Report the Android bridge health.

    Returns the transport state, the bridge protocol version, how many Android
    devices are paired and connected, and any pairing that is waiting for the
    user to approve it. This is read only and changes nothing. It takes no
    arguments.
    """
    return await run_android_bridge_status()


@function_tool
async def android_device_list() -> str:
    """List the Android devices paired with this JARVIS.

    Returns each device's id, display name, fingerprint, trust state and
    connection state. Revoked devices are included so their status is visible.
    This is read only. It takes no arguments.
    """
    return await run_android_device_list()


@function_tool
async def android_device_status(device: str) -> str:
    """Report one Android device in detail: trust state, connection and health.

    Args:
        device: The registered device id (``adev-`` followed by 32 hex
            characters) exactly as returned by ``android_device_list``. IP
            addresses, hostnames, phone numbers and nicknames are not accepted.
    """
    return await run_android_device_status(device)


@function_tool
async def android_device_pair(pairing: str) -> str:
    """Approve an Android device pairing and grant it trust.

    Only use this after the phone has started pairing and the user has compared
    the pairing code shown on the phone with the code JARVIS reports from
    ``android_bridge_status``. The codes matching is what proves no one is
    intercepting the connection. Always asks for confirmation first, because
    approving grants the device permission to talk to JARVIS.

    Args:
        pairing: The pairing id (``pair-`` followed by 32 hex characters) from
            ``android_bridge_status``.
    """
    return await run_android_device_pair(pairing)


@function_tool
async def android_device_unpair(device: str) -> str:
    """Unpair an Android device: disconnect it and forget it.

    The device could pair again from scratch later. Use ``android_device_revoke``
    instead when a phone is lost or should never be trusted again. Always asks
    for confirmation first.

    Args:
        device: The registered device id from ``android_device_list``.
    """
    return await run_android_device_unpair(device)


@function_tool
async def android_device_revoke(device: str) -> str:
    """Permanently revoke an Android device's trust.

    The device stays on record as revoked and can never pair with or be used by
    JARVIS again. This is the right choice for a lost, sold or compromised
    phone. Always asks for confirmation first.

    Args:
        device: The registered device id from ``android_device_list``.
    """
    return await run_android_device_revoke(device)


# ---------------------------------------------------------------------------
# Phase 6 tools - Android system control
#
# Thirteen tools. The only arguments any of them accept are a registered device
# id and, for the two setters, an integer percentage from 0 to 100. No
# destination, command, shell, ADB invocation, Android API name, SSID, password,
# file path or volume stream can be supplied.
# ---------------------------------------------------------------------------
async def run_android_system_status(device: str) -> str:
    """Report an Android device's system state."""
    return await _request("android.system.status", {"device": device})


async def run_android_get_volume(device: str) -> str:
    """Report an Android device's volume and mute state."""
    return await _request("android.system.get_volume", {"device": device})


async def run_android_set_volume(device: str, level: int) -> str:
    """Set an Android device's media volume (0-100)."""
    return await _request("android.system.set_volume", {"device": device, "level": level})


async def run_android_mute(device: str) -> str:
    """Mute an Android device."""
    return await _request("android.system.mute", {"device": device})


async def run_android_unmute(device: str) -> str:
    """Unmute an Android device."""
    return await _request("android.system.unmute", {"device": device})


async def run_android_get_brightness(device: str) -> str:
    """Report an Android device's screen brightness."""
    return await _request("android.system.get_brightness", {"device": device})


async def run_android_set_brightness(device: str, level: int) -> str:
    """Set an Android device's screen brightness (0-100)."""
    return await _request("android.system.set_brightness", {"device": device, "level": level})


async def run_android_wifi_status(device: str) -> str:
    """Report an Android device's Wi-Fi radio state."""
    return await _request("android.system.wifi.status", {"device": device})


async def run_android_wifi_enable(device: str) -> str:
    """Turn an Android device's Wi-Fi radio on (requires confirmation)."""
    return await _request("android.system.wifi.enable", {"device": device})


async def run_android_wifi_disable(device: str) -> str:
    """Turn an Android device's Wi-Fi radio off (requires confirmation)."""
    return await _request("android.system.wifi.disable", {"device": device})


async def run_android_bluetooth_status(device: str) -> str:
    """Report an Android device's Bluetooth radio state."""
    return await _request("android.system.bluetooth.status", {"device": device})


async def run_android_bluetooth_enable(device: str) -> str:
    """Turn an Android device's Bluetooth radio on (requires confirmation)."""
    return await _request("android.system.bluetooth.enable", {"device": device})


async def run_android_bluetooth_disable(device: str) -> str:
    """Turn an Android device's Bluetooth radio off (requires confirmation)."""
    return await _request("android.system.bluetooth.disable", {"device": device})


@function_tool
async def android_system_status(device: str) -> str:
    """Report an Android device's system state.

    Returns volume, mute, brightness, Wi-Fi and Bluetooth - but only the parts
    that device actually supports. Nothing is invented for a device that did not
    report it. Read only; changes nothing.

    Args:
        device: The registered device id (``adev-`` followed by 32 hex
            characters) from ``android_device_list``. IP addresses, hostnames
            and nicknames are not accepted.
    """
    return await run_android_system_status(device)


@function_tool
async def android_get_volume(device: str) -> str:
    """Report an Android device's media volume and whether it is muted.

    Args:
        device: The registered device id from ``android_device_list``.
    """
    return await run_android_get_volume(device)


@function_tool
async def android_set_volume(device: str, level: int) -> str:
    """Set an Android device's media volume to an exact percentage.

    This sets an absolute level rather than stepping up or down, so asking twice
    for the same level is safe.

    Args:
        device: The registered device id from ``android_device_list``.
        level: An integer from 0 (silent) to 100 (maximum).
    """
    return await run_android_set_volume(device, level)


@function_tool
async def android_mute(device: str) -> str:
    """Mute an Android device. It always ends up muted - this is not a toggle.

    Args:
        device: The registered device id from ``android_device_list``.
    """
    return await run_android_mute(device)


@function_tool
async def android_unmute(device: str) -> str:
    """Unmute an Android device. It always ends up unmuted - this is not a toggle.

    Args:
        device: The registered device id from ``android_device_list``.
    """
    return await run_android_unmute(device)


@function_tool
async def android_get_brightness(device: str) -> str:
    """Report an Android device's screen brightness and whether it is adaptive.

    Args:
        device: The registered device id from ``android_device_list``.
    """
    return await run_android_get_brightness(device)


@function_tool
async def android_set_brightness(device: str, level: int) -> str:
    """Set an Android device's screen brightness to an exact percentage.

    This does not turn adaptive brightness off. If the phone is in adaptive mode
    the result says so, because Android may then adjust the value itself.

    Args:
        device: The registered device id from ``android_device_list``.
        level: An integer from 0 (dim) to 100 (maximum).
    """
    return await run_android_set_brightness(device, level)


@function_tool
async def android_wifi_status(device: str) -> str:
    """Report whether an Android device's Wi-Fi radio is on or off. Read only.

    Args:
        device: The registered device id from ``android_device_list``.
    """
    return await run_android_wifi_status(device)


@function_tool
async def android_wifi_enable(device: str) -> str:
    """Turn an Android device's Wi-Fi radio on.

    Radio state only: this does not scan for networks, join a network or handle
    passwords. Always asks for confirmation first.

    Args:
        device: The registered device id from ``android_device_list``.
    """
    return await run_android_wifi_enable(device)


@function_tool
async def android_wifi_disable(device: str) -> str:
    """Turn an Android device's Wi-Fi radio off.

    This drops the phone's internet connection, so it always asks for
    confirmation first.

    Args:
        device: The registered device id from ``android_device_list``.
    """
    return await run_android_wifi_disable(device)


@function_tool
async def android_bluetooth_status(device: str) -> str:
    """Report whether an Android device's Bluetooth radio is on or off. Read only.

    Args:
        device: The registered device id from ``android_device_list``.
    """
    return await run_android_bluetooth_status(device)


@function_tool
async def android_bluetooth_enable(device: str) -> str:
    """Turn an Android device's Bluetooth radio on.

    Radio state only: this does not discover or pair with other devices. Always
    asks for confirmation first.

    Args:
        device: The registered device id from ``android_device_list``.
    """
    return await run_android_bluetooth_enable(device)


@function_tool
async def android_bluetooth_disable(device: str) -> str:
    """Turn an Android device's Bluetooth radio off.

    This disconnects any Bluetooth headset or watch, so it always asks for
    confirmation first.

    Args:
        device: The registered device id from ``android_device_list``.
    """
    return await run_android_bluetooth_disable(device)


# ---------------------------------------------------------------------------
# Phase 7 tools - Android calls
#
# The model can only choose among these five fixed operations.  It cannot pass a
# call/session id, a contact, URI, host, Android API name, recording setting or
# confirmation escape hatch.  Dial validation and mandatory confirmation live
# in the registered device tool, before a signed bridge frame is sent.
# ---------------------------------------------------------------------------
async def run_android_call_status(device: str) -> str:
    """Report the current call state on one trusted Android device."""
    return await _request("android.call.status", {"device": device})


async def run_android_call_dial(device: str, phone_number: str) -> str:
    """Request a confirmed outgoing call to a strict international number."""
    return await _request(
        "android.call.dial", {"device": device, "phone_number": phone_number}
    )


async def run_android_call_answer(device: str) -> str:
    """Answer only the current incoming call on one Android device."""
    return await _request("android.call.answer", {"device": device})


async def run_android_call_reject(device: str) -> str:
    """Reject only the current incoming call on one Android device."""
    return await _request("android.call.reject", {"device": device})


async def run_android_call_end(device: str) -> str:
    """End only the current active call on one Android device."""
    return await _request("android.call.end", {"device": device})


@function_tool
async def android_call_status(device: str) -> str:
    """Report current call state on a trusted Android device. Read only.

    It reports only the current state/direction where Android safely exposes it;
    it does not expose caller history, contact data, call contents or audio.

    Args:
        device: The registered device id from ``android_device_list``.
    """
    return await run_android_call_status(device)


@function_tool
async def android_call_dial(device: str, phone_number: str) -> str:
    """Place a call on a trusted Android device after explicit confirmation.

    The number must be international E.164 (starting with ``+``); spaces,
    parentheses and hyphens are merely normalized formatting.  The confirmation
    explicitly displays the normalized number and selected device.  There is no
    URI, contact, Android API, call id or destination-type argument.

    Args:
        device: The registered device id from ``android_device_list``.
        phone_number: A strict international telephone number beginning with +.
    """
    return await run_android_call_dial(device, phone_number)


@function_tool
async def android_call_answer(device: str) -> str:
    """Answer the current incoming call on one trusted Android device.

    This asks for confirmation under the external-action policy.  It has no
    call identifier parameter and cannot select another person's call.

    Args:
        device: The registered device id from ``android_device_list``.
    """
    return await run_android_call_answer(device)


@function_tool
async def android_call_reject(device: str) -> str:
    """Reject the current incoming call on one trusted Android device.

    This asks for confirmation under the external-action policy and exposes no
    call identifier or caller/contact data.

    Args:
        device: The registered device id from ``android_device_list``.
    """
    return await run_android_call_reject(device)


@function_tool
async def android_call_end(device: str) -> str:
    """End the current active call on one trusted Android device.

    This asks for confirmation under the external-action policy.  If no call is
    active JARVIS reports that no call was ended instead of claiming success.

    Args:
        device: The registered device id from ``android_device_list``.
    """
    return await run_android_call_end(device)


# ---------------------------------------------------------------------------
# Phase 8 tools - Android text messaging
#
# The model selects only a trusted device, explicit international recipient and
# opaque message text.  It cannot send a contact id, URI, transport endpoint,
# operation id, Android API/method, retry, or confirmation bypass.
# ---------------------------------------------------------------------------
async def run_android_message_status(device: str) -> str:
    """Report privacy-safe text-messaging capability for a trusted device."""
    return await _request("android.message.status", {"device": device})


async def run_android_message_send(device: str, recipient: str, message: str) -> str:
    """Request one explicitly confirmed text message."""
    return await _request(
        "android.message.send",
        {"device": device, "recipient": recipient, "message": message},
    )


@function_tool
async def android_message_status(device: str) -> str:
    """Report text-messaging availability on a trusted Android device.

    This is read only. It returns only current messaging capability/availability
    metadata, never contacts, conversations, notifications, message history or
    message contents.

    Args:
        device: The registered device id from ``android_device_list``.
    """
    return await run_android_message_status(device)


@function_tool
async def android_message_send(device: str, recipient: str, message: str) -> str:
    """Send one text message after explicit human confirmation.

    ``recipient`` must be an international E.164 phone number starting with
    ``+``; contact names, URI schemes and endpoints are not accepted.  The
    message is bounded opaque Unicode text and is sent exactly as written.  The
    confirmation shows the selected device, canonical recipient and exact text.

    Args:
        device: The registered device id from ``android_device_list``.
        recipient: Explicit international E.164 recipient beginning with +.
        message: The exact bounded Unicode text to send.
    """
    return await run_android_message_send(device, recipient, message)
