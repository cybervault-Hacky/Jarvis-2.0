import os
import subprocess
import logging
import sys
import asyncio
from fuzzywuzzy import process

# Phase 3 security fix: launching goes through the *secure* Phase 2 application
# framework (validated catalog + ShellExecute with an empty parameter string)
# instead of a shell command line built from what the model said.
from jarvis_devices.pc_apps import ApplicationResolver, default_application_catalog
from jarvis_devices.pc_apps_windows import WindowsApplicationBackend

try:
    from livekit.agents import function_tool
except ImportError:
    def function_tool(func): 
        return func

try:
    import win32gui
    import win32con
except ImportError:
    win32gui = None
    win32con = None

try:
    import pygetwindow as gw
except ImportError:
    gw = None

# Setup encoding and logger
sys.stdout.reconfigure(encoding='utf-8')
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Legacy app names -> names in the secure Phase 2 application catalog.
#
# This used to be a map of *shell command strings* (``"settings": "start
# ms-settings:"``, ``"command prompt": "cmd"``) that was interpolated into
# ``start "" "<value>"`` and run through a shell, so anything JARVIS was asked to
# open that was not in the map was executed verbatim as a command. The map now
# holds catalog *names* only: the launch target always comes from the catalog,
# never from the caller. "command prompt" is deliberately absent - JARVIS does
# not open a shell on request.
LEGACY_APP_ALIASES = {
    "notepad": "notepad",
    "calculator": "calculator",
    "chrome": "chrome",
    "vlc": "vlc",
    "control panel": "control-panel",
    "settings": "settings",
    "paint": "paint",
    "vs code": "vs-code",
    "vscode": "vs-code",
    "postman": "postman",
    "explorer": "explorer",
    "file explorer": "explorer",
    "edge": "edge",
    "firefox": "firefox",
}

_application_catalog = default_application_catalog()
_application_resolver = ApplicationResolver(_application_catalog)
_safe_launcher = WindowsApplicationBackend()

# -------------------------
# Global focus utility
# -------------------------
async def focus_window(title_keyword: str) -> bool:
    if not gw:
        logger.warning("⚠ pygetwindow")
        return False

    await asyncio.sleep(1.5)  # Give time for window to appear
    title_keyword = title_keyword.lower().strip()

    for window in gw.getAllWindows():
        if title_keyword in window.title.lower():
            if window.isMinimized:
                window.restore()
            window.activate()
            return True
    return False

# Index files/folders
async def index_items(base_dirs):
    item_index = []
    for base_dir in base_dirs:
        for root, dirs, files in os.walk(base_dir):
            for d in dirs:
                item_index.append({"name": d, "path": os.path.join(root, d), "type": "folder"})
            for f in files:
                item_index.append({"name": f, "path": os.path.join(root, f), "type": "file"})
    logger.info(f"✅ Indexed {len(item_index)} items.")
    return item_index

async def search_item(query, index, item_type):
    filtered = [item for item in index if item["type"] == item_type]
    choices = [item["name"] for item in filtered]
    if not choices:
        return None
    best_match, score = process.extractOne(query, choices)
    logger.info(f"🔍 Matched '{query}' to '{best_match}' with score {score}")
    if score > 70:
        for item in filtered:
            if item["name"] == best_match:
                return item
    return None

# File/folder actions
async def open_folder(path):
    try:
        os.startfile(path) if os.name == 'nt' else subprocess.call(['xdg-open', path])
        await focus_window(os.path.basename(path))
    except Exception as e:
        logger.error(f"❌ फ़ाइल open करने में error आया। {e}")

async def play_file(path):
    try:
        os.startfile(path) if os.name == 'nt' else subprocess.call(['xdg-open', path])
        await focus_window(os.path.basename(path))
    except Exception as e:
        logger.error(f"❌ फ़ाइल open करने में error आया।: {e}")

async def create_folder(path):
    try:
        os.makedirs(path, exist_ok=True)
        return f"✅ Folder create हो गया।: {path}"
    except Exception as e:
        return f"❌ फ़ाइल create करने में error आया।: {e}"

async def rename_item(old_path, new_path):
    try:
        os.rename(old_path, new_path)
        return f"✅ नाम बदलकर {new_path} कर दिया गया।"
    except Exception as e:
        return f"❌ नाम बदलना fail हो गया: {e}"

async def delete_item(path):
    try:
        if os.path.isdir(path):
            os.rmdir(path)
        else:
            os.remove(path)
        return f"🗑️ Deleted: {path}"
    except Exception as e:
        return f"❌ Delete नहीं हुआ।: {e}"

# App control
@function_tool
async def open(app_title: str) -> str:
    """Launch a known application - without a shell.

    Phase 3 security fix: this tool used to run ``start "" "<app_title>"`` through
    ``shell=True``, so an unknown name - or a name containing ``&``, ``|``,
    ``>`` or quotes - became an arbitrary command line. The requested name is now
    only ever used to *look up* an application in the Phase 2 catalog, and the
    catalog entry is launched with an empty parameter string.
    """
    requested = str(app_title or "").strip()
    if not requested:
        return "❌ कौन सा app खोलना है, वो बताइए।"

    lookup = LEGACY_APP_ALIASES.get(requested.lower(), requested)
    resolution = _application_resolver.resolve(lookup)
    if not resolution.ok or resolution.spec is None:
        # Nothing is executed here: an unknown name is reported, never launched.
        return f"❌ '{requested}' JARVIS की app list में नहीं है, इसलिए launch नहीं किया गया।"

    spec = resolution.spec
    try:
        await asyncio.to_thread(_safe_launcher.launch, spec)
    except Exception as e:
        return f"❌ {spec.display_name} Launch नहीं हो पाया।: {e}"

    focused = await focus_window(spec.display_name)
    if focused:
        return f"🚀 App launch हुआ और focus में है: {spec.display_name}."
    return f"🚀 {spec.display_name} Launch किया गया, लेकिन window पर focus नहीं हो पाया।"

@function_tool
async def close(window_title: str) -> str:
    if not win32gui:
        return "❌ win32gui"

    def enumHandler(hwnd, _):
        if win32gui.IsWindowVisible(hwnd):
            if window_title.lower() in win32gui.GetWindowText(hwnd).lower():
                win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)

    win32gui.EnumWindows(enumHandler, None)
    return f"❌ Window बंद हो गई है।: {window_title}"

# Jarvis command logic
@function_tool
async def folder_file(command: str) -> str:
    folders_to_index = ["D:/"]
    index = await index_items(folders_to_index)
    command_lower = command.lower()

    if "create folder" in command_lower:
        folder_name = command.replace("create folder", "").strip()
        path = os.path.join("D:/", folder_name)
        return await create_folder(path)

    if "rename" in command_lower:
        parts = command_lower.replace("rename", "").strip().split("to")
        if len(parts) == 2:
            old_name = parts[0].strip()
            new_name = parts[1].strip()
            item = await search_item(old_name, index, "folder")
            if item:
                new_path = os.path.join(os.path.dirname(item["path"]), new_name)
                return await rename_item(item["path"], new_path)
        return "❌ rename command valid नहीं है।"

    if "delete" in command_lower:
        item = await search_item(command, index, "folder") or await search_item(command, index, "file")
        if item:
            return await delete_item(item["path"])
        return "❌ Delete करने के लिए item नहीं मिला।"

    if "folder" in command_lower or "open folder" in command_lower:
        item = await search_item(command, index, "folder")
        if item:
            await open_folder(item["path"])
            return f"✅ Folder opened: {item['name']}"
        return "❌ Folder नहीं मिला।."

    item = await search_item(command, index, "file")
    if item:
        await play_file(item["path"])
        return f"✅ File opened: {item['name']}"

    return "⚠ कुछ भी match नहीं हुआ।"
