# Jarvis-2.0

Voice based JARVIS assistant built on LiveKit Agents (Gemini realtime voice,
Google search, weather, window/file control and keyboard/mouse control).

---

## Phase 1 — Secure Device-Tool Architecture

Phase 1 adds the **foundation** that every future device action (calls, SMS,
WhatsApp, shutdown, restart, volume, brightness, Wi-Fi, Bluetooth, app launch,
Android/PC control) will run on. It contains **no device action** — only the
safe plumbing around them.

Nothing that already existed was changed apart from two additive lines in
`agent.py` (import + two new tools). Existing tools, `.env` and
`requirements.txt` are untouched.

### What Phase 1 adds

| Path | Purpose |
| --- | --- |
| `jarvis_devices/` | The framework package (standard library only) |
| `jarvis_devices/enums.py` | `RiskLevel`, `Platform`, `ToolResultStatus`, `ConfirmationStatus`, `ToolLifecycleEvent` |
| `jarvis_devices/tools.py` | `BaseDeviceTool` / `DeviceTool` contract, `ToolContext` |
| `jarvis_devices/arguments.py` | `ArgumentSpec` / `ArgumentSchema` validation |
| `jarvis_devices/results.py` | `ToolResult` (structured, honest outcomes) |
| `jarvis_devices/errors.py` | Framework exceptions + stable `ErrorCode` constants |
| `jarvis_devices/registry.py` | `DeviceToolRegistry` (register / unregister / get / list / is_available) |
| `jarvis_devices/permissions.py` | `PermissionPolicy` (deny by default) + permission vocabulary |
| `jarvis_devices/confirmation.py` | `ConfirmationRequest`, `ConfirmationPolicy`, `ConfirmationManager` |
| `jarvis_devices/platform.py` | Platform abstraction: `DevicePlatformAdapter`, `PlatformRegistry`, `detect_current_platform()` |
| `jarvis_devices/adapters.py` | `PCDeviceAdapter` / `AndroidDeviceAdapter` (declarations only, no OS code) |
| `jarvis_devices/audit.py` | `AuditLogger` + `Redactor` (lifecycle logging without secrets) |
| `jarvis_devices/manager.py` | `DeviceActionManager` — the only execution path |
| `jarvis_devices/ids.py` | Unique execution / confirmation ids |
| `jarvis_devices/diagnostics.py` | `jarvis.framework.diagnostics` — a SAFE self check that touches no device |
| `Jarvis_device_control.py` | LiveKit bridge: `device_action`, `device_confirmation` |
| `tests/` | 159 automated tests for the whole Phase 1 architecture |

### Architecture

```
JARVIS CORE (agent.py + existing tools, unchanged)
     |
     v
COMMAND / INTENT ROUTER  (the LLM picks a registered tool name + JSON arguments)
     |
     v
DEVICE ACTION MANAGER    Jarvis_device_control.device_action -> DeviceActionManager.request()
     |
     +-- 1. registry lookup ............ unknown tool -> FAILED   (unknown_tool)
     +-- 2. tool availability .......... unavailable  -> UNAVAILABLE
     +-- 3. argument validation ........ bad input    -> INVALID_ARGUMENT
     |
     v
PERMISSION CHECK         PermissionPolicy.check(tool)
     |                                    not allowed -> PERMISSION_DENIED
     +-- platform / device check ........ no adapter  -> UNAVAILABLE
     |
     v
CONFIRMATION CHECK       ConfirmationPolicy + ConfirmationManager
     |                                    needs a "yes" -> PENDING_CONFIRMATION
     v
DEVICE TOOL REGISTRY     DeviceToolRegistry.get(name)
     |
     v
PLATFORM ADAPTER         DevicePlatformAdapter.execute(tool, arguments, context)
 ┌───────────────┐
 |               |
PC            ANDROID    (Phase 2+ implementations; Phase 1 declares them only)
```

The registry lookup happens first because permissions, risk level and argument
schema are declared *by the tool* — the manager has to know which tool it is
dealing with before it can ask "is this allowed?".

### Tool contract

```python
from jarvis_devices import (
    ArgumentSchema, ArgumentSpec, BaseDeviceTool, Platform, RiskLevel, ToolResult,
)

class PCVolumeTool(BaseDeviceTool):
    name = "pc.audio.volume"
    description = "Raise or lower the PC volume."
    platform = Platform.PC
    risk_level = RiskLevel.LOW_RISK
    required_permissions = ("device.media.control",)
    requires_confirmation = None            # None = decide from risk_level
    argument_schema = ArgumentSchema(
        ArgumentSpec("direction", choices=("up", "down")),
        ArgumentSpec("steps", type=int, required=False, default=1, min_value=1, max_value=100),
    )

    async def run(self, arguments, context):
        ...  # implemented in a later phase
        return ToolResult.ok("Volume raised.")
```

`run()` is the only method a tool implements. `execute()` (the guarded entry
point) validates arguments, catches every exception and normalises the return
value, so a crash can never be reported as a completed action.

### Risk levels

| Level | Meaning | Example (future) |
| --- | --- | --- |
| `SAFE` | read only, no side effect | get device status |
| `LOW_RISK` | local, reversible change | change volume / brightness |
| `EXTERNAL_ACTION` | leaves the machine, affects other people | send a message, place a call |
| `DESTRUCTIVE` | interrupts or destroys state | shutdown, restart |

`EXTERNAL_ACTION` and `DESTRUCTIVE` require confirmation by default.

### Permission model

* Deny by default: a tool declares `required_permissions`; the policy grants them.
* `PermissionPolicy.with_local_defaults()` grants read-only permissions only
  (`device.status.read`). Everything else must be granted explicitly:

  ```python
  from Jarvis_device_control import grant_device_permission
  from jarvis_devices import PERMISSION_MEDIA_CONTROL

  register_device_tool(PCVolumeTool())
  grant_device_permission(PERMISSION_MEDIA_CONTROL)
  ```

* Permission identifiers available for later phases: `device.status.read`,
  `device.settings.write`, `device.media.control`, `system.app.launch`,
  `comms.message.send`, `comms.call.place`, `system.power.control`.
* Tools and whole platforms can also be blocked outright
  (`block_tool`, `block_platform`), and a permission can be hard-denied even
  after being granted (`deny`).
* Failures are explicit: `PERMISSION_DENIED` results list the missing
  permissions and never execute the tool.

### Confirmation model

States: `NOT_REQUIRED`, `PENDING`, `CONFIRMED`, `DENIED`, `EXPIRED`, `CANCELLED`.

A `ConfirmationRequest` carries `confirmation_id`, `action` (tool name),
`target`, `created_at`, `expires_at`, `status`, `risk_level` and the validated
arguments (kept out of `repr` and out of every log line). Default lifetime:
5 minutes; at most 64 pending at a time; a confirmation is single use and bound
to the tool that created it.

```
JARVIS : "You're asking me to shut down the PC. Please confirm."   -> PENDING_CONFIRMATION
User   : "Yes."
Model  : device_confirmation(confirmation_id, approved=True)       -> CONFIRMED -> tool runs
```

`approved=False` (or `cancel_confirmation`) leaves the action unexecuted and
returns `DENIED` / `CANCELLED`.

### Structured results

`ToolResult` = `success`, `status`, `message`, `data`, `error`, `error_code`,
`tool_name`, `execution_id`, `executed`.

Statuses: `SUCCESS`, `FAILED`, `DENIED`, `CANCELLED`, `TIMEOUT`, `UNAVAILABLE`,
`INVALID_ARGUMENT`, `PERMISSION_DENIED` plus one Phase 1 addition,
`PENDING_CONFIRMATION`, so "waiting for the human" is never reported as a
refusal.

`success` is a derived read-only property (`status is SUCCESS`) and the
dataclass is frozen, so no code path can claim an action happened that did not.
`executed` is set by the framework only when the tool was really dispatched.

### Execution ids + logging

Every request gets a unique `execution_id` (`exec-…`); confirmations get
`cfm-…`. Lifecycle events: `TOOL_REQUESTED`, `PERMISSION_CHECKED`,
`CONFIRMATION_REQUESTED`, `CONFIRMATION_RECEIVED`, `EXECUTION_STARTED`,
`EXECUTION_COMPLETED`, `EXECUTION_FAILED` — emitted as JSON lines on the
`jarvis.device.audit` logger (visible once the app configures logging, which the
existing JARVIS modules already do).

Never logged: API keys, tokens, passwords, argument *values* (only argument
names), message bodies, e-mail addresses, phone numbers. Free text is passed
through `Redactor` and truncated; identifiers survive so lines can be correlated.

### Registering a future device tool

```python
from Jarvis_device_control import register_device_tool, grant_device_permission

register_device_tool(PCShutdownTool())          # validates, rejects duplicates
grant_device_permission("system.power.control")  # explicit opt-in
```

`unregister_device_tool(name)` removes it again. The registry validates names
(`pc.audio.volume` style), descriptions, platform, risk level, permissions and
argument schema, and refuses duplicates.

### Security boundaries

* No shell, `subprocess`, `eval`, `exec`, `os.system` or `ctypes` anywhere in
  the framework — verified by `tests/test_security.py`.
* Natural language never becomes a command: only a registered tool name plus
  schema-validated JSON arguments can trigger anything.
* Undeclared arguments are rejected; unknown tools are rejected; permission
  failures are explicit; every failure returns a structured result and a log
  line (nothing fails silently).
* Sensitive actions require confirmation, which expires, is single use and is
  bound to one tool.
* No hard-coded credentials; no new environment variables; local-first.

### Tests

```bash
python -m unittest discover -s tests -t . -v    # standard library, no new dependency
python -m pytest tests -v                       # also works if pytest is installed
```

159 tests cover the registry, permissions, confirmations, results, execution
ids, the manager's safe-failure matrix, the security boundaries and the
`agent.py` integration (existing tools still wired, all modules still import).

### Out of scope for Phase 1

No phone calls, SMS/WhatsApp, shutdown/restart, volume/brightness, Wi-Fi,
Bluetooth, app launching, Android control or PC control is implemented. The
adapters in `jarvis_devices/adapters.py` declare platforms but contain no OS
specific code — that is Phase 2+.

---

## Phase 2 — PC Application Control

Phase 2 gives JARVIS safe control over PC applications. It adds **no new
dependency** (it uses `pywin32`, already in `requirements.txt`) and changes no
existing file except two additive hunks in `agent.py` and this README.

```
JARVIS (agent.py)
   ↓
LiveKit function tools      list_open_applications / application_status /
                            open_application / focus_application / close_application
   ↓
DeviceActionManager         (Phase 1: registry → permissions → confirmation → adapter)
   ↓
PC application tool         jarvis_devices/pc_apps.py  (pc.app.*)
   ↓
PC adapter + backend        PCDeviceAdapter → WindowsApplicationBackend (pywin32)
   ↓
Windows                     EnumWindows / SetForegroundWindow / WM_CLOSE / ShellExecute
```

### What Phase 2 adds

| Path | Purpose |
| --- | --- |
| `jarvis_devices/pc_apps.py` | Application catalog, resolver, backend seam and the five `pc.app.*` tools |
| `jarvis_devices/pc_apps_windows.py` | The only module that talks to Windows (pywin32), injectable for tests |
| `tests/test_pc_apps_*.py` | 117 tests covering resolver, catalog, tools, Windows backend and security |

`jarvis_devices/errors.py` gained Phase 2 error codes and
`jarvis_devices/permissions.py` gained `system.app.control`; both are additive.

### Tools

| LiveKit tool | Device tool | Purpose | Platform | Risk | Permission | Confirmation |
| --- | --- | --- | --- | --- | --- | --- |
| `list_open_applications(limit=25)` | `pc.app.list` | Open windows: app name, window title, pid, state | PC | `SAFE` | `device.status.read` | not required |
| `application_status(app)` | `pc.app.status` | `running` / `not_running` / `unknown` | PC | `SAFE` | `device.status.read` | not required |
| `open_application(app, focus_if_running=True)` | `pc.app.open` | Launch a catalogued app, or focus it if already open | PC | `LOW_RISK` | `system.app.control` | policy-decided (off by default) |
| `focus_application(app, window_title="")` | `pc.app.focus` | Bring an existing window to the front | PC | `LOW_RISK` | `system.app.control` | policy-decided (off by default) |
| `close_application(app, window_title="")` | `pc.app.close` | Graceful close (`WM_CLOSE`), never a kill | PC | `LOW_RISK` | `system.app.control` | policy-decided (off by default) |

Every tool declares `requires_confirmation = None`, so the Phase 1
`ConfirmationPolicy` decides. Making close confirmation-required later is one
line, with no change to the tools:

```python
from Jarvis_device_control import device_confirmation_policy
device_confirmation_policy.always_confirm = ("pc.app.close",)
```

### Supported applications

Shipped catalog: Chrome, Edge, Firefox, Notepad, Calculator, File Explorer,
VS Code, VLC, Paint, Control Panel, Windows Settings, Postman.

```python
from Jarvis_device_control import register_application
from jarvis_devices.pc_apps import ApplicationSpec

register_application(ApplicationSpec(
    name="spotify",
    display_name="Spotify",
    aliases=("spotify app",),
    launch_target=r"%APPDATA%\Spotify\Spotify.exe",
    process_names=("spotify.exe",),
    window_keywords=("spotify",),
))
```

Names are resolved by `ApplicationResolver`: exact name/alias → unique prefix →
a single confident typo match. Otherwise it answers `APPLICATION_NOT_FOUND`
(with suggestions) or `AMBIGUOUS_APPLICATION`; it never guesses between two
applications. "chromium" is *suggested*, not silently treated as Chrome.

### Security boundaries

* **No shell, ever.** No `subprocess`, `os.system`, `eval`, `exec`, `shell=True`
  or `ctypes` anywhere in `jarvis_devices/` or `Jarvis_device_control.py` —
  enforced by AST-level tests, not just text search.
* **The model supplies names, not commands.** A launch target only ever comes
  from the catalog. `ApplicationSpec` rejects any target containing shell
  metacharacters (ampersand, pipe, redirection, semicolon, backtick, dollar,
  quotes), any whitespace, or anything that is not an `.exe` file or a
  registered URI — so even a careless catalog edit cannot create a command
  line. `ShellExecute` is always called with an **empty parameter string**.
* **No shells in the catalog.** `cmd`, `powershell`, `terminal` and `wsl` are
  deliberately absent (the pre-existing `open()` tool in
  `Jarvis_window_CTRL.py` does map "command prompt"; it is untouched and
  independent of this framework).
* **No process management.** There is no `kill_process`, no tool takes a `pid`
  argument, and closing is `WM_CLOSE` only. If an application ignores it (for
  example it is asking to save work) the tool reports `EXECUTION_FAILED` and
  explicitly does not escalate.
* **Windows only.** Off a PC the tools report `UNAVAILABLE`
  (`UNSUPPORTED_PLATFORM` / `DEVICE_UNAVAILABLE`) without touching the OS.
* **Ambiguity is never resolved by chance** — several matching windows return
  `AMBIGUOUS_APPLICATION` with their titles so JARVIS can ask which one.
* Errors: `APPLICATION_NOT_FOUND`, `APPLICATION_ALREADY_RUNNING`,
  `APPLICATION_NOT_RUNNING`, `AMBIGUOUS_APPLICATION`, `WINDOW_NOT_FOUND`,
  `UNSUPPORTED_PLATFORM`, `PERMISSION_DENIED`, `INVALID_ARGUMENT`,
  `EXECUTION_FAILED` — all from the Phase 1 `ErrorCode` class.

### Limitations

* Window discovery is window based: an application with no visible window is
  reported as `not_running`.
* Process names come from `GetModuleFileNameEx`; protected processes simply
  report no name and fall back to title matching.
* Launching an app that is not installed surfaces the ShellExecute error code
  rather than a pre-flight install check for bare executable names.
* The Windows code paths are covered by tests that inject fake `win32` modules
  (deterministic, cross platform). `WindowsLiveIntegrationTests` exercises a
  real desktop and is skipped automatically everywhere except Windows.

### Testing status

```bash
python -m unittest discover -s tests -t . -v   # 277 tests, OK (2 Windows-only skips)
python -m pytest tests -q                      # 275 passed, 2 skipped, 602 subtests
python -m compileall .                         # clean
```

Verified against a real `livekit-agents` install: all JARVIS modules import and
`Assistant()` registers 22 tools — the 15 original tools, the 2 Phase 1 tools
and the 5 Phase 2 tools.

---

## Phase 3 — PC System Control

Phase 3 gives JARVIS safe control over the PC it runs on — master volume, mute,
display brightness, Wi-Fi and Bluetooth — through the same secure pipeline
Phases 1 and 2 established:

```
JARVIS (LiveKit tool) -> DeviceActionManager -> registry -> argument schema
   -> permissions -> platform adapter -> confirmation -> PC system tool
   -> Windows backend -> structured ToolResult
```

New code:

| File | Purpose |
| --- | --- |
| `jarvis_devices/pc_system.py` | The 13 tools, the `PCSystemBackend` seam, the value objects and the honest error mapping. Platform agnostic. |
| `jarvis_devices/pc_system_windows.py` | The only module that touches Windows (Core Audio via `pycaw`, WMI via `pywin32`). |
| `tests/pc_system_support.py` | Fake backend plus fake Core Audio / WMI objects, so no speaker, monitor, adapter or desktop is needed. |
| `tests/test_pc_system_tools.py` | Behaviour matrix (64 tests). |
| `tests/test_pc_system_windows.py` | Windows backend paths exercised with injected fakes (38 tests). |
| `tests/test_pc_system_security.py` | Static and live-bridge security audit + audit-logging (28 tests). |
| `tests/test_legacy_hardening.py` | Pins the two legacy vulnerability fixes (20 tests). |

`agent.py`, `Jarvis_device_control.py`, `jarvis_devices/permissions.py`,
`jarvis_devices/errors.py` and `jarvis_devices/__init__.py` were extended
additively — no existing tool, permission or code path was rewritten.

### Tools

| Tool | LiveKit function tool | Risk | Permission | Confirmation |
| --- | --- | --- | --- | --- |
| `pc.system.status` | `system_status` | SAFE | `device.status.read` | never |
| `pc.system.get_volume` | `get_system_volume` | SAFE | `device.status.read` | never |
| `pc.system.set_volume` | `set_system_volume(level)` | LOW_RISK | `system.volume.control` | not by default |
| `pc.system.get_mute` | `get_system_mute` | SAFE | `device.status.read` | never |
| `pc.system.mute` | `mute_system` | LOW_RISK | `system.volume.control` | not by default |
| `pc.system.unmute` | `unmute_system` | LOW_RISK | `system.volume.control` | not by default |
| `pc.system.get_brightness` | `get_system_brightness` | SAFE | `device.status.read` | never |
| `pc.system.set_brightness` | `set_system_brightness(level)` | LOW_RISK | `system.display.control` | not by default |
| `pc.system.wifi.status` | `wifi_status` | SAFE | `device.status.read` | never |
| `pc.system.wifi.enable` | `wifi_enable` | EXTERNAL_ACTION | `system.network.control` | **yes, by policy** |
| `pc.system.wifi.disable` | `wifi_disable` | EXTERNAL_ACTION | `system.network.control` | **yes, by policy** |
| `pc.system.bluetooth.status` | `bluetooth_status` | SAFE | `device.status.read` | never |
| `pc.system.bluetooth.enable` | `bluetooth_enable` | EXTERNAL_ACTION | `system.bluetooth.control` | **yes, by policy** |
| `pc.system.bluetooth.disable` | `bluetooth_disable` | EXTERNAL_ACTION | `system.bluetooth.control` | **yes, by policy** |

`level` is always a whole number from 0 to 100, validated by the tool's own
`ArgumentSchema` (`type=int`, `min_value=0`, `max_value=100`), so `-1`, `101`,
`"loud"`, `true`, `50.5`, `NaN`, `Infinity`, lists and objects are rejected
before anything runs. **No Phase 3 tool accepts any other argument** — there is
no command, path, program name, device id or network configuration string
anywhere in this phase.

Mute state is also reported by `pc.system.status`, `pc.system.get_volume` and
every mute/unmute result; `pc.system.get_mute` is the dedicated read.

### Confirmation

Nothing in this module decides confirmation itself. Every tool leaves
`requires_confirmation = None`, so the existing centralized `ConfirmationPolicy`
rules: `EXTERNAL_ACTION` (Wi-Fi / Bluetooth toggles) asks the user first, the
local controls (volume, mute, brightness) do not. Reconfigure with
`ConfirmationPolicy(always_confirm=(...))` or `never_confirm=(...)` — no code
change needed.

### Security

* **No execution surface.** The only argument in the whole phase is an integer
  percentage. There is no `subprocess`, no shell, no `eval`/`exec`, no `ctypes`
  and no `os` import in the new modules — verified by AST tests
  (`tests/test_pc_system_security.py`) rather than by prose.
* **No WQL injection.** Every WMI query is a module level string constant and
  `ExecQuery` is called in exactly one place, which forwards that constant. An
  AST test asserts both properties, and WMI namespaces are checked against a
  three entry whitelist before a connection is opened.
* **No fake success.** Hardware that cannot do something answers `UNAVAILABLE`
  with a specific code; a call that ran but did not take effect answers
  `FAILED`. `set_volume`/`set_brightness` read the level back and only report
  success when the hardware confirms it; `wifi.enable`/`disable` re-read the
  radio state the same way.
* **Deny by default.** `PermissionPolicy.with_local_defaults()` still grants
  only `device.status.read`. The bridge explicitly grants
  `system.volume.control`, `system.display.control` and `system.network.control`
  — one line each, revocable with `device_permissions.revoke(...)`.
* **No privacy creep.** `pc.system.status` returns a closed set of keys
  (`platform`, `volume`, `brightness`, `wifi`, `bluetooth`, `capabilities`) and
  never reads files, browsing history, stored credentials, saved Wi-Fi
  passwords, messages or process lists. Even the platform section is projected
  onto `os` / `release` / `machine`.
* **The legacy shell path was removed, not just avoided.** See *Legacy
  hardening* below.

### Legacy hardening

Phase 3 fixed two real vulnerabilities in the pre-existing legacy files instead
of working around them (`tests/test_legacy_hardening.py`, 20 tests):

| File | Was | Now |
| --- | --- | --- |
| `Jarvis_window_CTRL.py` | `open()` ran `start "" "<whatever JARVIS was told>"` with `shell=True`, and any name missing from `APP_MAPPINGS` was executed verbatim — `open("notepad & calc")` ran arbitrary commands. | The words are only used to *look up* an application in the Phase 2 catalog, which is launched through `ShellExecute` with an empty parameter string. No shell, no command line. `APP_MAPPINGS` became `LEGACY_APP_ALIASES`, mapping old names to catalog names. |
| `keyboard_mouse_CTRL.py` | `activate()` compared its token against the literal `my_secret_token` that every caller passed back, and `type_text` wrote everything the user typed into `control_log.txt`. | The hard-coded credential is gone (activation is an internal per-call state; the gate is `is_active()`), and typed text passes through the framework's `Redactor` before it is logged. |

Behaviour kept: the `open` tool name and signature, all previously mapped
applications (`notepad`, `calculator`, `chrome`, `vlc`, `control panel`,
`settings`, `paint`, `vs code`, `postman`, plus `explorer`/`edge`/`firefox`),
window focusing and the Hindi result messages.

Behaviour deliberately changed: an unknown name is now reported instead of
executed, and `"command prompt"` / `cmd` is no longer launchable — JARVIS does
not open a shell on request.

### Dependency change (one line)

`requirements.txt` gains **`pycaw`** (after `pywin32`). Everything else in this
phase uses dependencies the project already had:

* brightness, Wi-Fi and Bluetooth status are plain WMI through `pywin32`;
* **absolute master volume** needs the Core Audio `IAudioEndpointVolume` COM
  interface, which `pywin32` cannot reach (it is a COM class with no registered
  type library, so there is no `win32com` binding), and the alternatives are
  hand written `ctypes` vtables — forbidden by this project's own security tests
  — or the legacy per-application WaveOut API, which does not control the master
  endpoint on modern Windows. `pyautogui` can only nudge volume relatively and
  cannot read it back, so it could never satisfy "report the actual resulting
  volume". `pycaw` is pure Python, imports defensively, and when it is missing
  the volume tools answer `UNAVAILABLE` instead of crashing.

If you prefer to stay on the existing dependency list, delete that line: volume
then reports `UNAVAILABLE` and brightness, Wi-Fi and Bluetooth keep working.

### Hardware limits

* **Brightness** needs a display that exposes `WmiMonitorBrightness`
  (laptops, and desktop monitors with DDC/CI). Otherwise:
  `BRIGHTNESS_CONTROL_UNAVAILABLE`.
* **Wi-Fi toggle** uses `Win32_NetworkAdapter.Enable()`/`.Disable()`, which
  needs administrator rights; without them Windows refuses and the tool reports
  `WIFI_CONTROL_FAILED` — it never claims success.
* **Bluetooth control is not implemented, on purpose.** Windows exposes no
  supported programmatic radio switch, and faking it with UI automation was
  rejected. `pc.system.bluetooth.status` reports `on`/`off`/`unknown`/
  `unavailable`; the two control tools return
  `BLUETOOTH_CONTROL_UNAVAILABLE`. `system.bluetooth.control` is therefore not
  granted by the bridge — grant it explicitly if a future backend ever supports
  the radio.
* **Not reachable from any Phase 3 tool:** shutdown, restart, sleep, hibernate
  and log off. A test asserts no `pc.system.*` tool is named after them and that
  such names are refused as unknown tools. They were added as a separate,
  confirmation-locked namespace in [Phase 4](#phase-4--pc-power-control) below.

### Testing status

```bash
python -m unittest discover -s tests -t . -v   # 427 tests, OK (2 Windows-only skips)
python -m pytest tests -q                      # see the Phase 3 report
python -m compileall .                         # clean
```

All Phase 3 tests inject a fake backend, so they run on any OS without a
speaker, a monitor, a Wi-Fi adapter, a Bluetooth radio or a desktop session.
The Windows code paths are exercised with injected Core Audio and WMI doubles.
**No test in this phase ran against real Windows hardware** — the machine used
is Linux and headless, so real-device behaviour (actual volume change, DDC/CI
brightness, radio toggling, administrator rights) is unverified and stated as
such.

Verified against a real `livekit-agents` install: all JARVIS modules import and
`Assistant()` registers 36 tools — the 15 original tools, the 2 Phase 1 tools,
the 5 Phase 2 tools and the 14 Phase 3 tools.

---

## Phase 4 — PC Power Control

Shutdown, restart, sleep, hibernate and log off — the five operations that can
end a session — as five zero-argument tools on the same pipeline as the earlier
phases, behind a confirmation the model cannot opt out of.

### Tools

| LiveKit tool | Device tool | Risk | Permission | Arguments |
| --- | --- | --- | --- | --- |
| `shutdown_pc` | `pc.power.shutdown` | `EXTERNAL_ACTION` | `system.power.control` | none |
| `restart_pc` | `pc.power.restart` | `EXTERNAL_ACTION` | `system.power.control` | none |
| `sleep_pc` | `pc.power.sleep` | `EXTERNAL_ACTION` | `system.power.control` | none |
| `hibernate_pc` | `pc.power.hibernate` | `EXTERNAL_ACTION` | `system.power.control` | none |
| `logoff_pc` | `pc.power.logoff` | `EXTERNAL_ACTION` | `system.power.control` | none |

Every one declares `ArgumentSchema.empty()`. There is no timeout, no force flag,
no reason code, no remote host and no command anywhere in the surface: there is
nothing for hostile input to attach to. A `shutdown /s /t 0`, a `&&`, a
`\\server` UNC path or a `powershell` payload is rejected as `invalid_argument`
before validation ever reaches a backend.

### Confirmation cannot be bypassed

`BaseDeviceTool` gained one attribute, `confirmation_mandatory`, and
`ConfirmationPolicy.is_required()` checks it **first** — before the
`never_confirm` opt-out list. So a power tool stays confirmation-locked even if
a caller builds a policy that tries to exempt it; a test does exactly that and
still gets `⚠️ Confirmation required`.

Confirmations are action-specific, time-limited and single use (the existing
Phase 1 machinery): a shutdown approval handed to `pc.power.restart` is
`confirmation_mismatch`, a second use of the same id is `confirmation_reused`, an
expired one is `confirmation_expired`, and a decline executes nothing.

### Backend

`jarvis_devices/pc_power.py` is platform agnostic and holds the tools;
`jarvis_devices/pc_power_windows.py` holds the only Windows code, behind the
`PCPowerBackend` seam, so both are unit testable on any OS.

Mechanisms are all from **`pywin32`, which the project already depended on** — no
new dependency, no shell, no `ctypes`:

* `win32api.ExitWindowsEx(flags, reason)` — log off, shut down (with power off)
  and restart, using module constants only. **`EWX_FORCE` is never used**, so
  Windows still lets applications ask the user to save work.
* `win32api.SetSystemPowerState(bSuspend, bForce)` — sleep and hibernate, with
  `bForce` always `False`.
* `win32api.GetPwrCapabilities()` — honest capability reporting, e.g. whether a
  hibernation file exists at all.
* `win32security` / `win32process` — enable `SeShutdownPrivilege` in the process
  token, best effort, before a shutdown or restart.

There is **no remote power control**: no hostname, IP or UNC path is accepted or
passed to any API, and a test walks every backend method's signature to prove
none of them takes a parameter at all.

### Failures are reported, never faked

| Situation | Result |
| --- | --- |
| Not on a PC | `unsupported_platform` |
| No usable backend (e.g. Linux, no pywin32) | `power_control_unavailable` |
| Machine cannot sleep / no hibernation file | `power_operation_unsupported` |
| Missing privilege (`ERROR_ACCESS_DENIED` / `ERROR_PRIVILEGE_NOT_HELD`) | `power_privilege_required` |
| Windows refused the call | `power_control_failed` |

Success is returned only when the Win32 call itself returned success. On a
machine where the backend is unavailable the tool refuses outright and does not
even offer a confirmation — asking the user to approve something the machine
cannot do would be the wrong answer.

### Testing status

```bash
python -m unittest discover -s tests -t . -v   # 504 tests, OK (2 Windows-only skips)
python -m pytest tests -q                      # 502 passed, 2 skipped, 3190 subtests
python -m compileall .                         # clean
```

Phase 4 adds 77 tests: `test_pc_power_tools.py` (27 — the full per-operation
matrix: permission denied, confirmation required/accepted/denied/expired/
duplicate, backend success, backend failure, unsupported, hostile arguments),
`test_pc_power_windows.py` (24 — Win32 flags, `EWX_FORCE` never set, privilege
handling, capability gating, machine-local calls only) and
`test_pc_power_security.py` (26 — AST audit for shell/`eval`/`ctypes`/command
strings, no steerable parameter, no remote targeting, registration integrity,
live-bridge confirmation and audit behaviour).

Every test injects a fake backend or fake Win32 modules, so the suite runs on any
OS **without ever changing a real machine's power state** — no test fakes a
shutdown and no test shuts anything down.

**Real Windows tested: NO.** The development machine is Linux and headless, so
actual power transitions, `SeShutdownPrivilege` behaviour on a locked-down
account, DDC-free hibernation on real hardware and Fast Startup interactions are
unverified and stated as such. `EWX_FORCE` never being used means a shutdown can
still be blocked by an application prompting to save work — that is intended.

Verified against a real `livekit-agents` install: all JARVIS modules import and
`Assistant()` registers **41 tools** — the 15 original tools, the 2 Phase 1
tools, the 5 Phase 2 tools, the 14 Phase 3 tools and the 5 Phase 4 tools, with
every earlier tool still in the same order and each new tool appearing exactly
once.

**Out of scope (Phase 5):** Android power and system control, calls,
SMS/WhatsApp/messaging, remote device power, BIOS/firmware access, arbitrary
execution, force-killing arbitrary processes, account or password changes and
disabling security software. None of these is implemented or reachable. Phase 5
delivered the secure bridge *foundation* only; these remain Phase 6+.

---

## Phase 5 — Android Device Bridge

The PC side of a JARVIS ↔ Android companion link: device identity, cryptographic
pairing, trust states, connection lifecycle, heartbeat and capability discovery.
**It is the foundation only** — no phone setting is changed by anything in this
phase.

```
JARVIS
   |
DeviceActionManager
   |
AndroidDeviceBridge          <- jarvis_devices/android_bridge.py
   |
   +-- pairing / trust ....... android_identity.py, android_registry.py
   +-- protocol / replay ..... android_protocol.py
   +-- transport ............. android_transport.py  (injectable)
   +-- keys .................. android_crypto.py     (Ed25519)
   |
Android companion (does not exist in this repository yet)
```

### Tools

| LiveKit tool | Device tool | Risk | Permission | Arguments |
| --- | --- | --- | --- | --- |
| `android_bridge_status` | `android.bridge.status` | `SAFE` | `device.status.read` | none |
| `android_device_list` | `android.device.list` | `SAFE` | `device.status.read` | none |
| `android_device_status` | `android.device.status` | `SAFE` | `device.status.read` | `device` |
| `android_device_pair` | `android.device.pair` | `EXTERNAL_ACTION` | `device.android.bridge.pair` | `pairing` |
| `android_device_unpair` | `android.device.unpair` | `EXTERNAL_ACTION` | `device.android.bridge.manage` | `device` |
| `android_device_revoke` | `android.device.revoke` | `EXTERNAL_ACTION` | `device.android.bridge.manage` | `device` |

That is the whole surface. There is no `android.raw.send`, `android.socket.send`,
`android.execute` or `android.adb` — a test asserts those names do not exist. The
only arguments any tool accepts are a **registered device id** (`adev-` + 32 hex
chars) or a **pairing id** (`pair-` + 32 hex chars), both pattern-checked and both
matched against state the bridge already holds. No IP address, hostname, port,
URL, MAC address, command, flag or file path can be supplied to anything.

Read-only tools reuse the existing `device.status.read` permission rather than
inventing a duplicate read permission; pairing and device management get their own.

### Device identity

An Android device is identified by an **Ed25519 public key**, never by an IP
address, hostname, Bluetooth MAC or any other mutable network property. The
bridge id is `adev-` + 32 hex characters of SHA-256 over that public key, so it
changes only when the device generates a new key pair. A human-comparable
fingerprint (`Q3F2-7KJA-…`, Crockford base32, no I/L/O/U) is derived for display.

The PC stores **public keys only**. There is no device secret and no shared
symmetric key on the PC, so a leaked registry cannot be used to impersonate a
phone.

### Pairing

Trust is established by signature **plus** a human comparison — never by a name
or an address:

1. the phone sends `pair_request` with its public key, signed by the matching
   private key (proof of ownership);
2. JARVIS replies with a fresh random challenge and its own host fingerprint;
3. the phone signs an attestation binding `challenge + device id + JARVIS
   fingerprint`, so the signature cannot be reused for another PC or replayed;
4. both sides display the same 6-character code derived from the phone's key and
   the challenge. **The user compares them** — that comparison is what defeats a
   man in the middle;
5. only then can `android.device.pair` promote the device to `PAIRED`, and that
   tool is `confirmation_mandatory`, so a natural-language request alone can
   never grant trust. A pairing flow expires after 120 seconds.

### Trust states

`UNKNOWN → PAIRING → PAIRED → CONNECTED ⇄ DISCONNECTED`, with `REVOKED`
**terminal**: it has no outgoing transitions, so no code path can restore a
revoked device to a privileged state. A revoked device also cannot be *unpaired*
— removing its record is exactly how it would pair again from scratch.

### Connection lifecycle

`DISCONNECTED → CONNECTING → CONNECTED`, or `RECONNECTING → FAILED`. Reconnection
is bounded: 3 attempts by default, exponential backoff from 0.5 s capped at 8 s,
and a hard ceiling of 10 attempts even if a caller asks for more. There are no
busy loops, no unbounded retries and no background tasks.

### Heartbeat

A 30 s interval with a 90 s stale threshold (both configurable). Health is
`HEALTHY → REACHABLE → STALE → DISCONNECTED`. A heartbeat that goes unanswered is
never reported as healthy: a failed probe marks the device stale immediately,
whatever the clock says.

### Protocol (version 1)

One JSON object per frame: `protocol_version`, `message_type`, `request_id`,
`device_id`, `session_id`, `sequence`, `nonce`, `timestamp`, `payload`,
`signature`. The message type is a 13-entry allowlist (`hello`, `pair_request`,
`pair_challenge`, `pair_response`, `pair_result`, `connect`, `disconnect`,
`heartbeat`, `heartbeat_ack`, `capabilities`, `device_info`, `ack`, `error`) — no
command-shaped type exists, and adding one would mean adding it to that enum.

Every frame is signed with Ed25519 and the signature covers every field except
itself. Frames are rejected when the type is unknown, the version is unsupported,
a field is missing or unexpected, an id is malformed, or the frame exceeds 64 KiB
(payload 32 KiB, nesting 6 levels, 64 keys). Deserialisation is `json.loads`
only — there is no `pickle`, `marshal`, `yaml` or `eval` anywhere in the bridge.

**Replay protection** is three independent checks: a ±300 s timestamp window, a
strictly increasing per-device sequence number, and a bounded 4096-entry nonce
cache — plus session binding, so a frame from an older session is refused. A
rejected frame does not advance the sequence, so one bad frame cannot lock the
real device out.

### Capabilities

Phase 5 understands only `bridge.protocol` and `device.status`. Anything else a
phone advertises is reported as `advertised_not_supported` — never as available.
`require_capability()` raises `android_capability_unavailable` for a Phase 6
capability, so nothing can quietly start pretending a phone control exists.

### Transport

`AndroidBridgeTransport` is a seam: `open` / `close` / `send` / `receive` /
`describe`. Phase 5 ships one real implementation — `InMemoryAndroidTransport`, a
loopback pair with **no sockets at all** — plus `UnavailableAndroidTransport`,
which fails honestly. There is deliberately no network listener: with no Android
companion in this repository, one would be an unauthenticated attack surface with
nothing legitimate behind it. A future local-network, USB or Bluetooth transport
slots in here without touching the bridge.

### Security model

* No `eval`, `exec`, `pickle`, `subprocess`, `shell=True`, `ctypes` or `socket`
  in any bridge module — enforced by AST tests, including the Phase 1 rule that
  no module in `jarvis_devices` imports `os` (the registry writes its JSON file
  through `pathlib` instead).
* No ADB path of any kind: no `adb`, `adb shell`, arbitrary executable or shell
  string is accepted or constructed anywhere.
* Hostile input (`adb shell …`, `cmd.exe …`, `powershell …`, an arbitrary IP or
  port, `\server\share`, `../etc/passwd`, malformed JSON, oversized payloads,
  forged and replayed frames) is refused before it can reach any handler.
* Private keys are never logged, serialised, hashed into an identifier, included
  in a tool result or written to disk. The JARVIS host key is held **in memory
  only** in Phase 5; `AndroidHostIdentity.to_safe_dict()` and its `__repr__` both
  omit it. The optional JSON registry stores public material at 0600.
* Audit events carry ids, states and short reasons only, and pass through the
  existing `Redactor`.

### Dependency change (one line)

`cryptography` (PyCA) was added — the only new dependency in Phase 5. Python's
standard library offers hashing and HMAC but **no signature scheme**, and a
public-key device identity cannot be built from HMAC alone. Everything used is a
published standard (Ed25519 / RFC 8032, SHA-256, HMAC-SHA256); no custom
cryptographic construction is invented. The import is guarded exactly like the
existing `pywin32` / `pycaw` guards, so the rest of the package stays
standard-library only and, without the library, the bridge reports
`android_bridge_unavailable` instead of importing badly or silently downgrading.

### Testing status

```bash
python -m unittest discover -s tests -t . -v   # 711 tests, OK (3 skips)
python -m pytest tests -q                      # 708 passed, 3 skipped, 17289 subtests
python -m compileall .                         # clean
```

Phase 5 adds 207 tests: `test_android_identity` (32), `test_android_registry`
(19), `test_android_protocol` (33), `test_android_bridge` (61),
`test_android_tools` (25) and `test_android_security` (37). They run without a
phone, Wi-Fi, Bluetooth, ADB, USB or any external server — the peer is a fake
that speaks the real protocol over the in-memory transport, so signatures,
sequence numbers and replay protection are genuinely exercised.

Without `cryptography` installed the Android suites **skip** (170 skips) rather
than pretending to have exercised real key material; the availability paths still
run.

**Real Android tested: NO.** No Android device, companion app or real network
transport was involved. Android pairing on a real phone, a real transport and
real companion communication are all **unverified** and stated as such. There is
no Android companion application in this repository — Phase 5 built the PC-side
protocol and interfaces a future companion will implement.

Verified against a real `livekit-agents` install: all JARVIS modules import and
`Assistant()` registers **47 tools** — the 15 original tools, the 2 Phase 1
tools, the 5 Phase 2 tools, the 14 Phase 3 tools, the 5 Phase 4 tools and the 6
Phase 5 tools, with every earlier tool still in the same order and each new tool
appearing exactly once. The bridge registry holds 31 tools with no duplicates.

**Out of scope (Phase 6):** Android system controls (volume, brightness, Wi-Fi,
Bluetooth), Android app control, Android power control, calls, messaging,
notifications, contacts, files, screen capture, microphone, camera, location and
any form of Android shell or ADB execution. None of these is implemented,
reachable through a tool, or expressible in the protocol.
