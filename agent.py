from dotenv import load_dotenv

from livekit import agents
from livekit.agents import AgentSession, Agent, RoomInputOptions
from livekit.plugins import (
    google,
    noise_cancellation,
)
from Jarvis_prompts import behavior_prompts, Reply_prompts
from Jarvis_google_search import google_search, get_current_datetime
from jarvis_get_whether import get_weather
from Jarvis_window_CTRL import open, close, folder_file
from Jarvis_file_opner import Play_file
from keyboard_mouse_CTRL import move_cursor_tool, mouse_click_tool, scroll_cursor_tool, type_text_tool, press_key_tool, swipe_gesture_tool, press_hotkey_tool, control_volume_tool
# Phase 1: secure device-tool framework (additive - existing tools unchanged)
from Jarvis_device_control import device_action, device_confirmation
# Phase 2: PC application control (registered device tools, no shell execution)
from Jarvis_device_control import list_open_applications, application_status, open_application, focus_application, close_application
# Phase 3: PC system control (volume / mute / brightness / Wi-Fi / Bluetooth) - registered device tools, no shell
from Jarvis_device_control import system_status, get_system_volume, set_system_volume, get_system_mute, mute_system, unmute_system
from Jarvis_device_control import get_system_brightness, set_system_brightness
from Jarvis_device_control import wifi_status, wifi_enable, wifi_disable
from Jarvis_device_control import bluetooth_status, bluetooth_enable, bluetooth_disable
# Phase 4: PC power control (shutdown / restart / sleep / hibernate / logoff) - confirmation हमेशा मांगते हैं
from Jarvis_device_control import shutdown_pc, restart_pc, sleep_pc, hibernate_pc, logoff_pc
# Phase 5: Android device bridge (status / list / pair / unpair / revoke) - trust बदलने वाले tools confirmation हमेशा मांगते हैं
from Jarvis_device_control import (
    android_bridge_status,
    android_device_list,
    android_device_status,
    android_device_pair,
    android_device_unpair,
    android_device_revoke,
)
# Phase 6: Android system control (status / volume / mute / brightness / Wi-Fi / Bluetooth)
# सब कुछ Phase 5 bridge से जाता है - कोई ADB, shell या arbitrary command नहीं
from Jarvis_device_control import (
    android_system_status,
    android_get_volume,
    android_set_volume,
    android_mute,
    android_unmute,
    android_get_brightness,
    android_set_brightness,
    android_wifi_status,
    android_wifi_enable,
    android_wifi_disable,
    android_bluetooth_status,
    android_bluetooth_enable,
    android_bluetooth_disable,
)
# Phase 7: Android Calls. These remain registered device tools over the authenticated Phase 5 bridge.
from Jarvis_device_control import (
    android_call_status,
    android_call_dial,
    android_call_answer,
    android_call_reject,
    android_call_end,
)
# Phase 8: Android messaging stays on the authenticated device bridge.
from Jarvis_device_control import (
    android_message_status,
    android_message_send,
)
load_dotenv()


class Assistant(Agent):
    def __init__(self) -> None:
        super().__init__(instructions=behavior_prompts,
                         tools=[
                            google_search,
                            get_current_datetime,
                            get_weather,
                            open, #ये apps ओपन करने के लिए हैं
                            close, 
                            folder_file, #ये folder ओपन करने के लिए है
                            Play_file,  #ये file रन करने के लिए है जैसे कि MP4, MP3, PDF, PPT, img, png etc.
                            move_cursor_tool, #ये cursor move करने के लिए है
                            mouse_click_tool, #ये mouse click करने के लिए है
                            scroll_cursor_tool, #ये cursor scroll करने के लिए है
                            type_text_tool, #ये text type करने के लिए है
                            press_key_tool, #ये key press करने के लिए है
                            press_hotkey_tool, #ये hotkey press करने के लिए है
                            control_volume_tool, #ये volume control करने के लिए है
                            swipe_gesture_tool, #ये gesture wipe करने के लिए है 
                            device_action, #ये registered device tools को secure तरीके से run करने के लिए है (Phase 1)
                            device_confirmation, #ये sensitive device actions के लिए user confirmation के लिए है (Phase 1)
                            list_open_applications, #ये currently open applications list करने के लिए है (Phase 2)
                            application_status, #ये check करने के लिए है कि कोई app running है या नहीं (Phase 2)
                            open_application, #ये catalog में मौजूद app को open करने के लिए है (Phase 2)
                            focus_application, #ये किसी open window को front में लाने के लिए है (Phase 2)
                            close_application, #ये app window को gracefully close करने के लिए है (Phase 2)
                            system_status, #ये PC का volume, mute, brightness, Wi-Fi और Bluetooth status बताने के लिए है (Phase 3)
                            get_system_volume, #ये PC का master volume percentage पढ़ने के लिए है (Phase 3)
                            set_system_volume, #ये PC का master volume 0-100 पर set करने के लिए है (Phase 3)
                            mute_system, #ये PC का master audio mute करने के लिए है (Phase 3)
                            unmute_system, #ये PC का master audio unmute करने के लिए है (Phase 3)
                            get_system_mute, #ये बताता है कि master audio muted है या नहीं (Phase 3)
                            get_system_brightness, #ये display brightness percentage पढ़ने के लिए है (Phase 3)
                            set_system_brightness, #ये display brightness 0-100 पर set करने के लिए है (Phase 3)
                            wifi_status, #ये Wi-Fi radio on/off/unknown बताने के लिए है (Phase 3)
                            wifi_enable, #ये Wi-Fi radio on करने के लिए है - confirmation मांगता है (Phase 3)
                            wifi_disable, #ये Wi-Fi radio off करने के लिए है - confirmation मांगता है (Phase 3)
                            bluetooth_status, #ये Bluetooth radio की state बताने के लिए है (Phase 3)
                            bluetooth_enable, #ये Bluetooth on करने की कोशिश करता है - Windows में supported नहीं, तो unavailable बताता है (Phase 3)
                            bluetooth_disable, #ये Bluetooth off करने की कोशिश करता है - Windows में supported नहीं, तो unavailable बताता है (Phase 3)
                            shutdown_pc, #ये PC को shut down करता है - confirmation ज़रूरी है (Phase 4)
                            restart_pc, #ये PC को restart करता है - confirmation ज़रूरी है (Phase 4)
                            sleep_pc, #ये PC को sleep में डालता है - confirmation ज़रूरी है (Phase 4)
                            hibernate_pc, #ये PC को hibernate करता है - confirmation ज़रूरी है (Phase 4)
                            logoff_pc, #ये current user को log out करता है - confirmation ज़रूरी है (Phase 4)
                            android_bridge_status, #ये Android bridge की health और pending pairings बताता है (Phase 5)
                            android_device_list, #ये paired Android devices की list बताता है (Phase 5)
                            android_device_status, #ये एक Android device का trust/connection/health बताता है (Phase 5)
                            android_device_pair, #ये verified pairing approve करता है - confirmation ज़रूरी है, पहले user से code match करवाएँ (Phase 5)
                            android_device_unpair, #ये Android device को unpair करके भुला देता है - confirmation ज़रूरी है (Phase 5)
                            android_device_revoke, #ये Android device का trust हमेशा के लिए revoke करता है - confirmation ज़रूरी है (Phase 5)
                            android_system_status, #ये Android phone की system state बताता है - सिर्फ़ जो phone actually support करता है (Phase 6)
                            android_get_volume, #ये Android phone का volume और mute state बताता है (Phase 6)
                            android_set_volume, #ये Android phone का volume 0-100 पर set करता है - toggle नहीं, इसलिए दोबारा भेजना safe है (Phase 6)
                            android_mute, #ये Android phone को mute करता है - toggle नहीं (Phase 6)
                            android_unmute, #ये Android phone को unmute करता है - toggle नहीं (Phase 6)
                            android_get_brightness, #ये Android phone की brightness और adaptive mode बताता है (Phase 6)
                            android_set_brightness, #ये Android phone की brightness 0-100 पर set करता है - adaptive brightness off नहीं करता (Phase 6)
                            android_wifi_status, #ये Android phone का Wi-Fi radio state बताता है (Phase 6)
                            android_wifi_enable, #ये Android phone का Wi-Fi radio on करता है - confirmation मांगता है, कोई network join नहीं होता (Phase 6)
                            android_wifi_disable, #ये Android phone का Wi-Fi radio off करता है - confirmation मांगता है (Phase 6)
                            android_bluetooth_status, #ये Android phone का Bluetooth radio state बताता है (Phase 6)
                            android_bluetooth_enable, #ये Android phone का Bluetooth radio on करता है - confirmation मांगता है, कोई pairing नहीं (Phase 6)
                            android_bluetooth_disable, #ये Android phone का Bluetooth radio off करता है - confirmation मांगता है (Phase 6)
                            android_call_status, #ये trusted Android phone की current call state बताता है (Phase 7)
                            android_call_dial, #ये normalized number पर call request करता है - explicit confirmation हमेशा ज़रूरी है (Phase 7)
                            android_call_answer, #ये सिर्फ current incoming call answer करता है - confirmation policy लागू है (Phase 7)
                            android_call_reject, #ये सिर्फ current incoming call reject करता है - confirmation policy लागू है (Phase 7)
                            android_call_end, #ये सिर्फ current active call end करता है - confirmation policy लागू है (Phase 7)
                            android_message_status, #ये trusted Android device की text-messaging capability बताता है (Phase 8)
                            android_message_send #ये explicit recipient को exact text send request करता है - human confirmation हमेशा ज़रूरी है (Phase 8)
                         ]
                         )


async def entrypoint(ctx: agents.JobContext):
    session = AgentSession(
        llm=google.beta.realtime.RealtimeModel(
            voice="Charon"
        )
    )
    
    await session.start(
        room=ctx.room,
        agent=Assistant(),
        room_input_options=RoomInputOptions(
            noise_cancellation=noise_cancellation.BVC(),
            video_enabled=True 
        ),
    )

    await ctx.connect()

    await session.generate_reply(
        instructions=Reply_prompts
    )


if __name__ == "__main__":
    agents.cli.run_app(agents.WorkerOptions(entrypoint_fnc=entrypoint))
