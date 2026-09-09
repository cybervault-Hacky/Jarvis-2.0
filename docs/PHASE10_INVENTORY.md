# Phase 10 inventory — generated from the live registry
This table is generated from `Jarvis_device_control.device_registry.describe()` in the clean local verification environment. It contains no argument values, secrets, device identities, endpoint data, or transport state. `platform` is the registered execution host; Android operations are PC-hosted wrappers that require the authenticated Android bridge and a canonical `adev-...` device input.
| Registered tool | Host platform | Capability / route | Permission | Risk | Human confirmation | Target requirement |
| --- | --- | --- | --- | --- | --- | --- |
| `android.bridge.status` | `pc` | authenticated Android bridge, fixed android.bridge.status | `device.status.read` | `safe` | `no` | none |
| `android.call.answer` | `pc` | authenticated Android bridge, fixed android.call.answer | `device.android.call.control` | `external_action` | `yes` | canonical `adev-...` device |
| `android.call.dial` | `pc` | authenticated Android bridge, fixed android.call.dial | `device.android.call.control` | `external_action` | `yes` | canonical `adev-...` device |
| `android.call.end` | `pc` | authenticated Android bridge, fixed android.call.end | `device.android.call.control` | `external_action` | `yes` | canonical `adev-...` device |
| `android.call.reject` | `pc` | authenticated Android bridge, fixed android.call.reject | `device.android.call.control` | `external_action` | `yes` | canonical `adev-...` device |
| `android.call.status` | `pc` | authenticated Android bridge, fixed android.call.status | `device.android.call.read` | `safe` | `no` | canonical `adev-...` device |
| `android.device.list` | `pc` | authenticated Android bridge, fixed android.device.list | `device.status.read` | `safe` | `no` | none |
| `android.device.pair` | `pc` | authenticated Android bridge, fixed android.device.pair | `device.android.bridge.pair` | `external_action` | `yes` | validated pairing id |
| `android.device.revoke` | `pc` | authenticated Android bridge, fixed android.device.revoke | `device.android.bridge.manage` | `external_action` | `yes` | canonical `adev-...` device |
| `android.device.status` | `pc` | authenticated Android bridge, fixed android.device.status | `device.status.read` | `safe` | `no` | canonical `adev-...` device |
| `android.device.unpair` | `pc` | authenticated Android bridge, fixed android.device.unpair | `device.android.bridge.manage` | `external_action` | `yes` | canonical `adev-...` device |
| `android.message.send` | `pc` | authenticated Android bridge, fixed android.message.send | `device.android.message.send` | `external_action` | `yes` | canonical `adev-...` device |
| `android.message.status` | `pc` | authenticated Android bridge, fixed android.message.status | `device.android.message.read` | `safe` | `no` | canonical `adev-...` device |
| `android.system.bluetooth.disable` | `pc` | authenticated Android bridge, fixed android.system.bluetooth.disable | `device.android.system.control` | `external_action` | `yes` | canonical `adev-...` device |
| `android.system.bluetooth.enable` | `pc` | authenticated Android bridge, fixed android.system.bluetooth.enable | `device.android.system.control` | `external_action` | `yes` | canonical `adev-...` device |
| `android.system.bluetooth.status` | `pc` | authenticated Android bridge, fixed android.system.bluetooth.status | `device.android.system.read` | `safe` | `no` | canonical `adev-...` device |
| `android.system.get_brightness` | `pc` | authenticated Android bridge, fixed android.system.get_brightness | `device.android.system.read` | `safe` | `no` | canonical `adev-...` device |
| `android.system.get_volume` | `pc` | authenticated Android bridge, fixed android.system.get_volume | `device.android.system.read` | `safe` | `no` | canonical `adev-...` device |
| `android.system.mute` | `pc` | authenticated Android bridge, fixed android.system.mute | `device.android.system.control` | `low_risk` | `no` | canonical `adev-...` device |
| `android.system.set_brightness` | `pc` | authenticated Android bridge, fixed android.system.set_brightness | `device.android.system.control` | `low_risk` | `no` | canonical `adev-...` device |
| `android.system.set_volume` | `pc` | authenticated Android bridge, fixed android.system.set_volume | `device.android.system.control` | `low_risk` | `no` | canonical `adev-...` device |
| `android.system.status` | `pc` | authenticated Android bridge, fixed android.system.status | `device.android.system.read` | `safe` | `no` | canonical `adev-...` device |
| `android.system.unmute` | `pc` | authenticated Android bridge, fixed android.system.unmute | `device.android.system.control` | `low_risk` | `no` | canonical `adev-...` device |
| `android.system.wifi.disable` | `pc` | authenticated Android bridge, fixed android.system.wifi.disable | `device.android.system.control` | `external_action` | `yes` | canonical `adev-...` device |
| `android.system.wifi.enable` | `pc` | authenticated Android bridge, fixed android.system.wifi.enable | `device.android.system.control` | `external_action` | `yes` | canonical `adev-...` device |
| `android.system.wifi.status` | `pc` | authenticated Android bridge, fixed android.system.wifi.status | `device.android.system.read` | `safe` | `no` | canonical `adev-...` device |
| `cross.device.capabilities` | `unknown` | read-only cross-device inventory | `device.status.read` | `safe` | `no` | none |
| `cross.device.status` | `unknown` | read-only cross-device inventory | `device.status.read` | `safe` | `no` | none |
| `jarvis.framework.diagnostics` | `unknown` | framework diagnostic | `none` | `safe` | `no` | none |
| `pc.app.close` | `pc` | registered local-PC capability | `system.app.control` | `low_risk` | `no` | local host only |
| `pc.app.focus` | `pc` | registered local-PC capability | `system.app.control` | `low_risk` | `no` | local host only |
| `pc.app.list` | `pc` | registered local-PC capability | `device.status.read` | `safe` | `no` | local host only |
| `pc.app.open` | `pc` | registered local-PC capability | `system.app.control` | `low_risk` | `no` | local host only |
| `pc.app.status` | `pc` | registered local-PC capability | `device.status.read` | `safe` | `no` | local host only |
| `pc.power.hibernate` | `pc` | registered local-PC capability | `system.power.control` | `external_action` | `yes` | local host only |
| `pc.power.logoff` | `pc` | registered local-PC capability | `system.power.control` | `external_action` | `yes` | local host only |
| `pc.power.restart` | `pc` | registered local-PC capability | `system.power.control` | `external_action` | `yes` | local host only |
| `pc.power.shutdown` | `pc` | registered local-PC capability | `system.power.control` | `external_action` | `yes` | local host only |
| `pc.power.sleep` | `pc` | registered local-PC capability | `system.power.control` | `external_action` | `yes` | local host only |
| `pc.system.bluetooth.disable` | `pc` | registered local-PC capability | `system.bluetooth.control` | `external_action` | `yes` | local host only |
| `pc.system.bluetooth.enable` | `pc` | registered local-PC capability | `system.bluetooth.control` | `external_action` | `yes` | local host only |
| `pc.system.bluetooth.status` | `pc` | registered local-PC capability | `device.status.read` | `safe` | `no` | local host only |
| `pc.system.get_brightness` | `pc` | registered local-PC capability | `device.status.read` | `safe` | `no` | local host only |
| `pc.system.get_mute` | `pc` | registered local-PC capability | `device.status.read` | `safe` | `no` | local host only |
| `pc.system.get_volume` | `pc` | registered local-PC capability | `device.status.read` | `safe` | `no` | local host only |
| `pc.system.mute` | `pc` | registered local-PC capability | `system.volume.control` | `low_risk` | `no` | local host only |
| `pc.system.set_brightness` | `pc` | registered local-PC capability | `system.display.control` | `low_risk` | `no` | local host only |
| `pc.system.set_volume` | `pc` | registered local-PC capability | `system.volume.control` | `low_risk` | `no` | local host only |
| `pc.system.status` | `pc` | registered local-PC capability | `device.status.read` | `safe` | `no` | local host only |
| `pc.system.unmute` | `pc` | registered local-PC capability | `system.volume.control` | `low_risk` | `no` | local host only |
| `pc.system.wifi.disable` | `pc` | registered local-PC capability | `system.network.control` | `external_action` | `yes` | local host only |
| `pc.system.wifi.enable` | `pc` | registered local-PC capability | `system.network.control` | `external_action` | `yes` | local host only |
| `pc.system.wifi.status` | `pc` | registered local-PC capability | `device.status.read` | `safe` | `no` | local host only |

## Model-facing inventory
The separately generated production-Agent inventory is enforced by `tests/test_phase10_inventory.py`: exactly 55 actual `livekit.agents.FunctionTool` objects are present, in the listed order. The generic dispatcher (`device_action`), confirmation resolver (`device_confirmation`), legacy filesystem/window/file/input/volume wrappers, and every unlisted symbol are absent.

The safe fixed informational tools are `google_search`, `get_current_datetime`, and `get_weather`. The other 52 FunctionTool names are the fixed wrappers corresponding to the registered PC, Android, and two read-only cross-device capabilities represented above; the diagnostic is intentionally registered but not model-facing.

Exact model-facing names (55): `google_search`, `get_current_datetime`, `get_weather`, `list_open_applications`, `application_status`, `open_application`, `focus_application`, `close_application`, `system_status`, `get_system_volume`, `set_system_volume`, `mute_system`, `unmute_system`, `get_system_mute`, `get_system_brightness`, `set_system_brightness`, `wifi_status`, `wifi_enable`, `wifi_disable`, `bluetooth_status`, `bluetooth_enable`, `bluetooth_disable`, `shutdown_pc`, `restart_pc`, `sleep_pc`, `hibernate_pc`, `logoff_pc`, `android_bridge_status`, `android_device_list`, `android_device_status`, `android_device_pair`, `android_device_unpair`, `android_device_revoke`, `android_system_status`, `android_get_volume`, `android_set_volume`, `android_mute`, `android_unmute`, `android_get_brightness`, `android_set_brightness`, `android_wifi_status`, `android_wifi_enable`, `android_wifi_disable`, `android_bluetooth_status`, `android_bluetooth_enable`, `android_bluetooth_disable`, `android_call_status`, `android_call_dial`, `android_call_answer`, `android_call_reject`, `android_call_end`, `android_message_status`, `android_message_send`, `cross_device_status`, `cross_device_capabilities`.
