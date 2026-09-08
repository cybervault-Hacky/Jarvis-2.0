"""PC application control (Phase 2).

This module gives JARVIS safe control over PC applications *through the Phase 1
framework*: every operation is a registered :class:`BaseDeviceTool`, so it goes
through the registry, the permission policy, the confirmation policy, the
platform adapter and structured :class:`ToolResult` reporting.

Security model
--------------
* The model never supplies a command line, a path or a PID. It supplies an
  application *name* which is resolved against a developer maintained
  :class:`ApplicationCatalog`.
* :class:`ApplicationSpec` validates its launch target when it is built: shell
  operators, quotes, backticks and embedded arguments are rejected, so a target
  can only ever be one executable or one registered URI.
* All operating system interaction happens behind the
  :class:`PCApplicationBackend` seam (Windows implementation in
  :mod:`jarvis_devices.pc_apps_windows`). There is no shell, no ``subprocess``,
  no ``eval``/``exec`` and no ``os`` import in this package.
* Closing is always a graceful window close. There is no process termination
  and no ``kill_process(pid)`` tool anywhere in this module.
"""

from __future__ import annotations

import asyncio
import difflib
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Protocol, Tuple

from .arguments import ArgumentSchema, ArgumentSpec
from .enums import Platform, RiskLevel
from .errors import ErrorCode
from .permissions import PERMISSION_APP_CONTROL, PERMISSION_DEVICE_STATUS_READ
from .platform import detect_current_platform
from .results import ToolResult
from .tools import BaseDeviceTool, ToolContext

__all__ = [
    "ApplicationSpec",
    "ApplicationCatalog",
    "default_application_catalog",
    "ApplicationResolver",
    "ApplicationResolution",
    "ApplicationState",
    "WindowInfo",
    "match_windows",
    "PCApplicationBackend",
    "PCApplicationBackendError",
    "UnavailablePCApplicationBackend",
    "create_default_pc_application_backend",
    "ListOpenApplicationsTool",
    "ApplicationStatusTool",
    "OpenApplicationTool",
    "FocusApplicationTool",
    "CloseApplicationTool",
    "build_pc_application_tools",
    "PC_APPLICATION_TOOL_NAMES",
]

#: Canonical application name pattern (also the registry-safe identifier).
APPLICATION_NAME_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")

#: Characters that would give a launch target shell semantics. Rejected.
FORBIDDEN_TARGET_RE = re.compile(r"[&|<>;`$\"'\n\r\t]")

#: A registered URI scheme such as ``ms-settings:``.
URI_TARGET_RE = re.compile(r"^[a-z][a-z0-9+.-]*:$")

#: Windows verbs that are the *only* ones this module will ever use.
LAUNCH_VERB = "open"


class ApplicationState:
    """State of an application, as reported by :class:`ApplicationStatusTool`."""

    RUNNING = "running"
    NOT_RUNNING = "not_running"
    UNKNOWN = "unknown"


class PCApplicationBackendError(Exception):
    """Raised by a backend when an OS level operation cannot be performed."""


# ---------------------------------------------------------------------------
# Window information
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class WindowInfo:
    """A single top level window, as reported by a backend."""

    handle: int
    title: str = ""
    process_id: int = 0
    process_name: str = ""
    is_visible: bool = True
    is_minimized: bool = False

    def describe(self, *, max_title: int = 120) -> Dict[str, Any]:
        """A structured, trimmed view - no extra system information."""
        title = self.title or ""
        return {
            "window_title": title[:max_title] + ("…" if len(title) > max_title else ""),
            "process_id": self.process_id,
            "process_name": self.process_name,
            "state": "minimized" if self.is_minimized else "visible",
        }


# ---------------------------------------------------------------------------
# Application catalog
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ApplicationSpec:
    """One known application.

    ``launch_target`` / ``search_paths`` are developer controlled constants.
    They are validated here so that neither model input nor a careless catalog
    edit can smuggle in a command line.
    """

    name: str
    display_name: str
    aliases: Tuple[str, ...] = ()
    launch_target: str = ""
    search_paths: Tuple[str, ...] = ()
    window_keywords: Tuple[str, ...] = ()
    process_names: Tuple[str, ...] = ()
    description: str = ""

    def __post_init__(self) -> None:
        if not APPLICATION_NAME_RE.match(self.name):
            raise ValueError(f"Invalid application name: {self.name!r}")
        if not self.display_name.strip():
            raise ValueError(f"Application {self.name!r} needs a display name")

        object.__setattr__(self, "aliases", _clean_str_tuple(self.aliases))
        object.__setattr__(self, "search_paths", _clean_str_tuple(self.search_paths, lower=False))
        object.__setattr__(self, "window_keywords", _clean_str_tuple(self.window_keywords))
        object.__setattr__(self, "process_names", _clean_str_tuple(self.process_names))

        if self.launch_target:
            _validate_launch_target(self.launch_target)
        elif not self.search_paths:
            raise ValueError(f"Application {self.name!r} has no launch target")
        for path in self.search_paths:
            _validate_search_path(path)
        if not self.launch_target and not all(p.lower().endswith(".exe") for p in self.search_paths):
            raise ValueError(f"Application {self.name!r} needs an .exe search path")

    # ------------------------------------------------------------------
    @property
    def searchable_names(self) -> Tuple[str, ...]:
        """Every name a user may reasonably type for this application."""
        return (self.name, self.display_name.lower(), *self.aliases)

    def describe(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "display_name": self.display_name,
            "aliases": list(self.aliases),
            "description": self.description,
        }


class ApplicationCatalog:
    """A maintainable mapping of the applications JARVIS knows about."""

    def __init__(self, applications: Iterable[ApplicationSpec] = ()) -> None:
        self._applications: Dict[str, ApplicationSpec] = {}
        for spec in applications:
            self.add(spec)

    # ------------------------------------------------------------------
    def add(self, spec: ApplicationSpec) -> ApplicationSpec:
        if not isinstance(spec, ApplicationSpec):
            raise TypeError("ApplicationCatalog expects ApplicationSpec instances")
        if spec.name in self._applications:
            raise ValueError(f"Application {spec.name!r} is already in the catalog")
        self._applications[spec.name] = spec
        return spec

    def remove(self, name: str) -> bool:
        return self._applications.pop(str(name).strip().lower(), None) is not None

    def get(self, name: str) -> Optional[ApplicationSpec]:
        return self._applications.get(str(name).strip().lower())

    def all(self) -> Tuple[ApplicationSpec, ...]:
        return tuple(sorted(self._applications.values(), key=lambda s: s.name))

    def names(self) -> Tuple[str, ...]:
        return tuple(sorted(self._applications))

    def __len__(self) -> int:
        return len(self._applications)

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name.strip().lower() in self._applications


def default_application_catalog() -> ApplicationCatalog:
    """The applications JARVIS ships with.

    Deliberately excludes shells (``cmd``, ``powershell``): handing a voice
    assistant a shell is how arbitrary command execution happens. Extend the
    catalog with :meth:`ApplicationCatalog.add` instead of editing this list.
    """
    return ApplicationCatalog(
        (
            ApplicationSpec(
                name="chrome",
                display_name="Google Chrome",
                aliases=("google chrome", "chrome browser"),
                launch_target="chrome.exe",
                search_paths=(
                    r"%PROGRAMFILES%\Google\Chrome\Application\chrome.exe",
                    r"%PROGRAMFILES(X86)%\Google\Chrome\Application\chrome.exe",
                    r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe",
                ),
                window_keywords=("google chrome",),
                process_names=("chrome.exe",),
            ),
            ApplicationSpec(
                name="edge",
                display_name="Microsoft Edge",
                aliases=("ms edge", "microsoft edge browser"),
                launch_target="msedge.exe",
                search_paths=(
                    r"%PROGRAMFILES(X86)%\Microsoft\Edge\Application\msedge.exe",
                    r"%PROGRAMFILES%\Microsoft\Edge\Application\msedge.exe",
                ),
                window_keywords=("microsoft edge",),
                process_names=("msedge.exe",),
            ),
            ApplicationSpec(
                name="firefox",
                display_name="Firefox",
                aliases=("mozilla firefox", "mozilla"),
                launch_target="firefox.exe",
                search_paths=(
                    r"%PROGRAMFILES%\Mozilla Firefox\firefox.exe",
                    r"%PROGRAMFILES(X86)%\Mozilla Firefox\firefox.exe",
                ),
                window_keywords=("mozilla firefox",),
                process_names=("firefox.exe",),
            ),
            ApplicationSpec(
                name="notepad",
                display_name="Notepad",
                aliases=("text editor",),
                launch_target="notepad.exe",
                window_keywords=("notepad",),
                process_names=("notepad.exe", "notepad++.exe"),
            ),
            ApplicationSpec(
                name="calculator",
                display_name="Calculator",
                aliases=("calc", "windows calculator"),
                launch_target="calc.exe",
                window_keywords=("calculator",),
                process_names=("calculatorapp.exe", "calc.exe"),
            ),
            ApplicationSpec(
                name="explorer",
                display_name="File Explorer",
                aliases=("file explorer", "windows explorer", "my computer", "this pc"),
                launch_target="explorer.exe",
                window_keywords=("file explorer", "this pc"),
                process_names=("explorer.exe",),
            ),
            ApplicationSpec(
                name="vs-code",
                display_name="Visual Studio Code",
                aliases=("vs code", "vscode", "visual studio code", "code editor"),
                launch_target="code.exe",
                search_paths=(
                    r"%LOCALAPPDATA%\Programs\Microsoft VS Code\Code.exe",
                    r"%PROGRAMFILES%\Microsoft VS Code\Code.exe",
                ),
                window_keywords=("visual studio code",),
                process_names=("code.exe",),
            ),
            ApplicationSpec(
                name="vlc",
                display_name="VLC media player",
                aliases=("vlc", "vlc player", "media player"),
                launch_target="vlc.exe",
                search_paths=(
                    r"%PROGRAMFILES%\VideoLAN\VLC\vlc.exe",
                    r"%PROGRAMFILES(X86)%\VideoLAN\VLC\vlc.exe",
                ),
                window_keywords=("vlc media player",),
                process_names=("vlc.exe",),
            ),
            ApplicationSpec(
                name="paint",
                display_name="Paint",
                aliases=("ms paint", "mspaint"),
                launch_target="mspaint.exe",
                window_keywords=("paint",),
                process_names=("mspaint.exe",),
            ),
            ApplicationSpec(
                name="control-panel",
                display_name="Control Panel",
                aliases=("control panel", "control"),
                launch_target="control.exe",
                window_keywords=("control panel",),
                process_names=("control.exe",),
            ),
            ApplicationSpec(
                name="settings",
                display_name="Windows Settings",
                aliases=("windows settings", "system settings"),
                launch_target="ms-settings:",
                window_keywords=("settings",),
                process_names=("systemsettings.exe",),
            ),
            ApplicationSpec(
                name="postman",
                display_name="Postman",
                aliases=("postman app",),
                launch_target="postman.exe",
                search_paths=(r"%LOCALAPPDATA%\Postman\Postman.exe",),
                window_keywords=("postman",),
                process_names=("postman.exe",),
            ),
        )
    )


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ApplicationResolution:
    """Outcome of resolving a user supplied application name."""

    spec: Optional[ApplicationSpec] = None
    candidates: Tuple[ApplicationSpec, ...] = ()
    error_code: Optional[str] = None
    message: str = ""
    normalized_query: str = ""

    @property
    def ok(self) -> bool:
        return self.spec is not None


class ApplicationResolver:
    """Maps human friendly names onto catalog entries - safely.

    Resolution order: exact name/alias, unique prefix, then a single close
    match. Anything else is reported as unknown or ambiguous; the resolver never
    guesses between two applications.
    """

    def __init__(self, catalog: ApplicationCatalog, *, close_match_cutoff: float = 0.88) -> None:
        self.catalog = catalog
        self.close_match_cutoff = close_match_cutoff

    # ------------------------------------------------------------------
    @staticmethod
    def normalize(query: Any) -> str:
        """Lowercase, trim and collapse whitespace. Never interprets content."""
        text = str(query or "").strip().strip("\"'").lower()
        return re.sub(r"\s+", " ", text)

    # ------------------------------------------------------------------
    def resolve(self, query: Any) -> ApplicationResolution:
        normalized = self.normalize(query)
        if not normalized:
            return ApplicationResolution(
                error_code=ErrorCode.INVALID_ARGUMENT,
                message="An application name is required.",
                normalized_query=normalized,
            )

        applications = self.catalog.all()
        if not applications:
            return ApplicationResolution(
                error_code=ErrorCode.APPLICATION_NOT_FOUND,
                message="The application catalog is empty.",
                normalized_query=normalized,
            )

        # 1 - exact match on canonical name, display name or alias
        exact = [spec for spec in applications if normalized in spec.searchable_names]
        if len(exact) == 1:
            return ApplicationResolution(spec=exact[0], normalized_query=normalized)
        if len(exact) > 1:
            return self._ambiguous(normalized, tuple(exact))

        # 2 - unique prefix match
        prefixed = [
            spec
            for spec in applications
            if any(name.startswith(normalized) for name in spec.searchable_names)
        ]
        if len(prefixed) == 1:
            return ApplicationResolution(spec=prefixed[0], normalized_query=normalized)
        if len(prefixed) > 1:
            return self._ambiguous(normalized, tuple(prefixed))

        # 3 - one confident close match
        names = {name: spec for spec in applications for name in spec.searchable_names}
        close = difflib.get_close_matches(normalized, list(names), n=3, cutoff=self.close_match_cutoff)
        close_specs = tuple(dict.fromkeys(names[name] for name in close))
        if len(close_specs) == 1:
            return ApplicationResolution(spec=close_specs[0], normalized_query=normalized)
        if len(close_specs) > 1:
            return self._ambiguous(normalized, close_specs)

        suggestions = difflib.get_close_matches(normalized, list(names), n=3, cutoff=0.5)
        suggestion_names = sorted({names[name].display_name for name in suggestions})
        message = f"No application named {normalized!r} is known to JARVIS."
        if suggestion_names:
            message += " Did you mean: " + ", ".join(suggestion_names) + "?"
        return ApplicationResolution(
            error_code=ErrorCode.APPLICATION_NOT_FOUND,
            message=message,
            normalized_query=normalized,
        )

    # ------------------------------------------------------------------
    @staticmethod
    def _ambiguous(normalized: str, candidates: Tuple[ApplicationSpec, ...]) -> ApplicationResolution:
        names = ", ".join(sorted({spec.display_name for spec in candidates}))
        return ApplicationResolution(
            candidates=tuple(candidates),
            error_code=ErrorCode.AMBIGUOUS_APPLICATION,
            message=(
                f"{normalized!r} matches more than one application ({names}). "
                "Please be more specific."
            ),
            normalized_query=normalized,
        )


# ---------------------------------------------------------------------------
# Backend seam
# ---------------------------------------------------------------------------
class PCApplicationBackend(Protocol):
    """The only place that touches the operating system."""

    name: str

    def is_available(self) -> bool: ...

    def list_windows(self) -> Tuple[WindowInfo, ...]: ...

    def launch(self, spec: ApplicationSpec) -> None: ...

    def focus_window(self, handle: int) -> None: ...

    def close_window(self, handle: int) -> None: ...

    def window_exists(self, handle: int) -> bool: ...


class UnavailablePCApplicationBackend:
    """Used when JARVIS is not running on a supported PC."""

    name = "unavailable"

    def __init__(self, reason: str = "PC application control is only available on a Windows PC.") -> None:
        self.reason = reason

    def is_available(self) -> bool:
        return False

    def list_windows(self) -> Tuple[WindowInfo, ...]:
        raise PCApplicationBackendError(self.reason)

    def launch(self, spec: ApplicationSpec) -> None:
        raise PCApplicationBackendError(self.reason)

    def focus_window(self, handle: int) -> None:
        raise PCApplicationBackendError(self.reason)

    def close_window(self, handle: int) -> None:
        raise PCApplicationBackendError(self.reason)

    def window_exists(self, handle: int) -> bool:
        raise PCApplicationBackendError(self.reason)


def create_default_pc_application_backend() -> PCApplicationBackend:
    """Return the Windows backend when possible, otherwise an unavailable one."""
    from .pc_apps_windows import WindowsApplicationBackend

    backend = WindowsApplicationBackend()
    if backend.is_available():
        return backend
    return UnavailablePCApplicationBackend(
        reason=(
            "PC application control needs Windows with pywin32 installed "
            f"(backend reported unavailable: {backend.unavailable_reason()})."
        )
    )


def match_windows(spec: ApplicationSpec, windows: Iterable[WindowInfo]) -> Tuple[WindowInfo, ...]:
    """Return the visible windows that belong to ``spec``."""
    keywords = tuple(keyword.lower() for keyword in spec.window_keywords) or (spec.display_name.lower(),)
    process_names = tuple(name.lower() for name in spec.process_names)
    matched: List[WindowInfo] = []
    for window in windows:
        if not window.is_visible:
            continue
        if process_names and window.process_name and window.process_name.lower() in process_names:
            matched.append(window)
            continue
        title = (window.title or "").lower()
        if title and any(keyword in title for keyword in keywords):
            matched.append(window)
    return tuple(matched)


# ---------------------------------------------------------------------------
# Shared tool base
# ---------------------------------------------------------------------------
class PCApplicationTool(BaseDeviceTool):
    """Base class for the Phase 2 tools: platform + backend guarding."""

    platform = Platform.PC

    def __init__(
        self,
        backend: PCApplicationBackend,
        catalog: ApplicationCatalog,
        resolver: Optional[ApplicationResolver] = None,
        *,
        platform_probe: Callable[[], Platform] = detect_current_platform,
    ) -> None:
        self._backend = backend
        self._catalog = catalog
        self._resolver = resolver or ApplicationResolver(catalog)
        self._platform_probe = platform_probe

    # ------------------------------------------------------------------
    @property
    def backend(self) -> PCApplicationBackend:
        return self._backend

    @property
    def catalog(self) -> ApplicationCatalog:
        return self._catalog

    def is_available(self) -> bool:
        """Available when the backend is.

        The platform itself is reported precisely by :meth:`platform_result`, so
        an Android invocation answers ``UNSUPPORTED_PLATFORM`` instead of a
        vague "tool unavailable". (The real Windows backend already reports
        itself unavailable off Windows, which makes this ``False`` there.)
        """
        return self._backend.is_available()

    # ------------------------------------------------------------------
    def platform_result(self) -> Optional[ToolResult]:
        """Return a blocking result when the platform/backend cannot be used."""
        if self._platform_probe() is not Platform.PC:
            return ToolResult.unavailable(
                f"{self.name} only runs on a PC (detected: {self._platform_probe().value}).",
                error_code=ErrorCode.UNSUPPORTED_PLATFORM,
                tool_name=self.name,
                data={"platform": self._platform_probe().value},
            )
        if not self._backend.is_available():
            return ToolResult.unavailable(
                f"PC application control is unavailable (backend: {self._backend.name}).",
                error_code=ErrorCode.DEVICE_UNAVAILABLE,
                tool_name=self.name,
                data={"backend": self._backend.name},
            )
        return None

    # ------------------------------------------------------------------
    def resolve(self, query: Any) -> ApplicationResolution:
        return self._resolver.resolve(query)

    @staticmethod
    def missing_spec(resolution: ApplicationResolution) -> ToolResult:
        """Defensive guard: a resolution without a spec is never a success."""
        return ToolResult.failure(
            resolution.message or "The application could not be resolved.",
            error_code=resolution.error_code or ErrorCode.APPLICATION_NOT_FOUND,
        )

    def resolution_failure(self, resolution: ApplicationResolution) -> ToolResult:
        """Turn a failed resolution into a structured result."""
        data = {
            "query": resolution.normalized_query,
            "candidates": [spec.display_name for spec in resolution.candidates],
        }
        if resolution.error_code == ErrorCode.INVALID_ARGUMENT:
            return ToolResult.invalid_argument(
                resolution.message,
                error=resolution.message,
                tool_name=self.name,
            )
        return ToolResult.failure(
            resolution.message,
            error_code=resolution.error_code or ErrorCode.APPLICATION_NOT_FOUND,
            tool_name=self.name,
            data=data,
        )

    def select_window(
        self,
        spec: ApplicationSpec,
        windows: Tuple[WindowInfo, ...],
        window_title: str = "",
    ) -> Tuple[Optional[WindowInfo], Optional[ToolResult]]:
        """Pick one window, or return a structured error instead of guessing."""
        candidates = match_windows(spec, windows)
        if window_title.strip():
            wanted = window_title.strip().lower()
            narrowed = tuple(w for w in candidates if wanted in (w.title or "").lower())
            candidates = narrowed or ()
            if not candidates:
                return None, ToolResult.failure(
                    f"No {spec.display_name} window matching {window_title!r} was found.",
                    error_code=ErrorCode.WINDOW_NOT_FOUND,
                    tool_name=self.name,
                    data={"application": spec.display_name},
                )
        if not candidates:
            return None, ToolResult.failure(
                f"{spec.display_name} does not have an open window.",
                error_code=ErrorCode.APPLICATION_NOT_RUNNING,
                tool_name=self.name,
                data={"application": spec.display_name},
            )
        if len(candidates) > 1:
            return None, ToolResult.failure(
                (
                    f"{len(candidates)} {spec.display_name} windows are open; "
                    "please say which one (window_title)."
                ),
                error_code=ErrorCode.AMBIGUOUS_APPLICATION,
                tool_name=self.name,
                data={
                    "application": spec.display_name,
                    "windows": [w.describe() for w in candidates],
                },
            )
        return candidates[0], None

    # ------------------------------------------------------------------
    def backend_failure(self, message: str, exc: Exception) -> ToolResult:
        return ToolResult.failure(
            message,
            error=f"{type(exc).__name__}: {exc}"[:200],
            error_code=ErrorCode.EXECUTION_FAILED,
            tool_name=self.name,
        )


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
class ListOpenApplicationsTool(PCApplicationTool):
    """Report the applications that currently have a window open."""

    name = "pc.app.list"
    description = "List the PC applications that currently have an open window."
    risk_level = RiskLevel.SAFE
    required_permissions = (PERMISSION_DEVICE_STATUS_READ,)
    argument_schema = ArgumentSchema(
        ArgumentSpec("limit", type=int, required=False, default=25, min_value=1, max_value=100,
                     description="Maximum number of windows to report."),
    )

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        blocked = self.platform_result()
        if blocked is not None:
            return blocked
        try:
            windows = self._backend.list_windows()
        except PCApplicationBackendError as exc:
            return self.backend_failure("Could not list open windows.", exc)

        limit = int(arguments.get("limit") or 25)
        visible = tuple(w for w in windows if w.is_visible)
        listed = visible[:limit]
        entries: List[Dict[str, Any]] = []
        by_application: Dict[str, int] = {}
        for window in listed:
            spec = self._application_for(window)
            label = spec.display_name if spec else (window.process_name or "unknown")
            by_application[label] = by_application.get(label, 0) + 1
            entries.append({**window.describe(), "application": label})

        return ToolResult.ok(
            f"{len(listed)} open window(s) across {len(by_application)} application(s).",
            data={
                "count": len(listed),
                "total_visible_windows": len(visible),
                "truncated": len(visible) > len(listed),
                "applications": [
                    {"application": name, "windows": count}
                    for name, count in sorted(by_application.items())
                ],
                "windows": entries,
            },
        )

    def _application_for(self, window: WindowInfo) -> Optional[ApplicationSpec]:
        for spec in self._catalog.all():
            if match_windows(spec, (window,)):
                return spec
        return None


class ApplicationStatusTool(PCApplicationTool):
    """Report whether an application is running."""

    name = "pc.app.status"
    description = "Check whether a PC application is currently running."
    risk_level = RiskLevel.SAFE
    required_permissions = (PERMISSION_DEVICE_STATUS_READ,)
    argument_schema = ArgumentSchema(
        ArgumentSpec("app", max_length=64, description="Application name, e.g. 'Chrome'."),
    )

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        resolution = self.resolve(arguments.get("app"))
        if not resolution.ok:
            return self.resolution_failure(resolution)
        spec = resolution.spec
        if spec is None:  # pragma: no cover - resolution.ok implies a spec
            return self.missing_spec(resolution)

        blocked = self.platform_result()
        if blocked is not None:
            return ToolResult(
                status=blocked.status,
                message=f"{spec.display_name}: unknown - {blocked.message}",
                tool_name=self.name,
                execution_id=blocked.execution_id,
                data={"application": spec.display_name, "state": ApplicationState.UNKNOWN},
                error_code=blocked.error_code,
            )

        try:
            windows = match_windows(spec, self._backend.list_windows())
        except PCApplicationBackendError as exc:
            return ToolResult.failure(
                f"{spec.display_name}: unknown - could not inspect open windows.",
                error=f"{type(exc).__name__}: {exc}"[:200],
                error_code=ErrorCode.EXECUTION_FAILED,
                tool_name=self.name,
                data={"application": spec.display_name, "state": ApplicationState.UNKNOWN},
            )

        state = ApplicationState.RUNNING if windows else ApplicationState.NOT_RUNNING
        message = (
            f"{spec.display_name} is running ({len(windows)} window(s))."
            if windows
            else f"{spec.display_name} is not running."
        )
        return ToolResult.ok(
            message,
            data={
                "application": spec.display_name,
                "state": state,
                "window_count": len(windows),
                "windows": [w.describe() for w in windows],
            },
        )


class OpenApplicationTool(PCApplicationTool):
    """Launch a known application."""

    name = "pc.app.open"
    description = "Open (launch) a known PC application such as Chrome, Notepad or Calculator."
    risk_level = RiskLevel.LOW_RISK
    required_permissions = (PERMISSION_APP_CONTROL,)
    argument_schema = ArgumentSchema(
        ArgumentSpec("app", max_length=64, description="Application name, e.g. 'Chrome'."),
        ArgumentSpec("focus_if_running", type=bool, required=False, default=True,
                     description="Focus the existing window instead of launching again."),
    )

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        resolution = self.resolve(arguments.get("app"))
        if not resolution.ok:
            return self.resolution_failure(resolution)
        spec = resolution.spec
        if spec is None:  # pragma: no cover - resolution.ok implies a spec
            return self.missing_spec(resolution)

        blocked = self.platform_result()
        if blocked is not None:
            return blocked

        already_open: Tuple[WindowInfo, ...] = ()
        try:
            already_open = match_windows(spec, self._backend.list_windows())
        except PCApplicationBackendError:
            already_open = ()  # not fatal: launching may still work

        if already_open and not bool(arguments.get("focus_if_running", True)):
            return ToolResult.failure(
                f"{spec.display_name} is already running.",
                error_code=ErrorCode.APPLICATION_ALREADY_RUNNING,
                tool_name=self.name,
                data={
                    "application": spec.display_name,
                    "window_count": len(already_open),
                    "hint": "Pass focus_if_running=true to bring it to the front instead.",
                },
            )

        if already_open:
            try:
                self._backend.focus_window(already_open[0].handle)
            except PCApplicationBackendError as exc:
                return self.backend_failure(
                    f"{spec.display_name} was already running but could not be focused.", exc
                )
            return ToolResult.ok(
                f"{spec.display_name} was already running; brought it to the front.",
                data={
                    "application": spec.display_name,
                    "already_running": True,
                    "action": "focused",
                    "window": already_open[0].describe(),
                },
            )

        try:
            self._backend.launch(spec)
        except PCApplicationBackendError as exc:
            return self.backend_failure(f"{spec.display_name} could not be launched.", exc)

        return ToolResult.ok(
            f"{spec.display_name} was launched.",
            data={"application": spec.display_name, "already_running": False, "action": "launched"},
        )


class FocusApplicationTool(PCApplicationTool):
    """Bring an existing application window to the foreground."""

    name = "pc.app.focus"
    description = "Bring an open PC application window to the front."
    risk_level = RiskLevel.LOW_RISK
    required_permissions = (PERMISSION_APP_CONTROL,)
    argument_schema = ArgumentSchema(
        ArgumentSpec("app", max_length=64, description="Application name, e.g. 'VS Code'."),
        ArgumentSpec("window_title", required=False, default="", max_length=200,
                     description="Optional text identifying which window when several match."),
    )

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        resolution = self.resolve(arguments.get("app"))
        if not resolution.ok:
            return self.resolution_failure(resolution)
        spec = resolution.spec
        if spec is None:  # pragma: no cover - resolution.ok implies a spec
            return self.missing_spec(resolution)

        blocked = self.platform_result()
        if blocked is not None:
            return blocked

        try:
            windows = self._backend.list_windows()
        except PCApplicationBackendError as exc:
            return self.backend_failure("Could not inspect open windows.", exc)

        window, error = self.select_window(spec, windows, str(arguments.get("window_title") or ""))
        if error is not None or window is None:
            return error if error is not None else ToolResult.failure(
                f"No {spec.display_name} window was found.",
                error_code=ErrorCode.WINDOW_NOT_FOUND,
                tool_name=self.name,
            )

        try:
            self._backend.focus_window(window.handle)
        except PCApplicationBackendError as exc:
            return self.backend_failure(f"{spec.display_name} could not be focused.", exc)

        return ToolResult.ok(
            f"{spec.display_name} is now in the foreground.",
            data={"application": spec.display_name, "window": window.describe(), "action": "focused"},
        )


class CloseApplicationTool(PCApplicationTool):
    """Gracefully close an application window. Never terminates a process."""

    name = "pc.app.close"
    description = "Gracefully close an open PC application window (asks the app to close itself)."
    risk_level = RiskLevel.LOW_RISK
    required_permissions = (PERMISSION_APP_CONTROL,)
    argument_schema = ArgumentSchema(
        ArgumentSpec("app", max_length=64, description="Application name, e.g. 'Notepad'."),
        ArgumentSpec("window_title", required=False, default="", max_length=200,
                     description="Optional text identifying which window when several match."),
    )

    def __init__(self, *args: Any, close_poll_interval: float = 0.15, close_attempts: int = 10, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._close_poll_interval = max(0.0, close_poll_interval)
        self._close_attempts = max(1, close_attempts)

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        resolution = self.resolve(arguments.get("app"))
        if not resolution.ok:
            return self.resolution_failure(resolution)
        spec = resolution.spec
        if spec is None:  # pragma: no cover - resolution.ok implies a spec
            return self.missing_spec(resolution)

        blocked = self.platform_result()
        if blocked is not None:
            return blocked

        try:
            windows = self._backend.list_windows()
        except PCApplicationBackendError as exc:
            return self.backend_failure("Could not inspect open windows.", exc)

        window, error = self.select_window(spec, windows, str(arguments.get("window_title") or ""))
        if error is not None or window is None:
            return error if error is not None else ToolResult.failure(
                f"No {spec.display_name} window was found.",
                error_code=ErrorCode.WINDOW_NOT_FOUND,
                tool_name=self.name,
            )

        try:
            self._backend.close_window(window.handle)
        except PCApplicationBackendError as exc:
            return self.backend_failure(
                f"{spec.display_name} was asked to close but the request failed.", exc
            )

        for _ in range(self._close_attempts):
            await asyncio.sleep(self._close_poll_interval)
            try:
                still_open = self._backend.window_exists(window.handle)
            except PCApplicationBackendError:
                still_open = True
            if not still_open:
                return ToolResult.ok(
                    f"{spec.display_name} was closed.",
                    data={"application": spec.display_name, "window": window.describe(), "action": "closed"},
                )

        return ToolResult.failure(
            (
                f"{spec.display_name} was asked to close but its window is still open. "
                "It may be waiting for you to save work. No process was terminated."
            ),
            error_code=ErrorCode.EXECUTION_FAILED,
            tool_name=self.name,
            data={"application": spec.display_name, "window": window.describe(), "action": "close_failed"},
        )


#: Tool names registered by :func:`build_pc_application_tools`.
PC_APPLICATION_TOOL_NAMES: Tuple[str, ...] = (
    ListOpenApplicationsTool.name,
    ApplicationStatusTool.name,
    OpenApplicationTool.name,
    FocusApplicationTool.name,
    CloseApplicationTool.name,
)


def build_pc_application_tools(
    backend: Optional[PCApplicationBackend] = None,
    catalog: Optional[ApplicationCatalog] = None,
    *,
    platform_probe: Callable[[], Platform] = detect_current_platform,
    close_poll_interval: float = 0.15,
    close_attempts: int = 10,
) -> Tuple[BaseDeviceTool, ...]:
    """Build the five Phase 2 tools, ready for a :class:`DeviceToolRegistry`.

    ``close_poll_interval`` / ``close_attempts`` control how long
    ``pc.app.close`` waits for the application to close its own window before it
    reports a failure. It never escalates to killing a process.
    """
    active_catalog = catalog if catalog is not None else default_application_catalog()
    active_backend = backend if backend is not None else create_default_pc_application_backend()
    resolver = ApplicationResolver(active_catalog)
    shared: Mapping[str, Any] = {
        "backend": active_backend,
        "catalog": active_catalog,
        "resolver": resolver,
        "platform_probe": platform_probe,
    }
    return (
        ListOpenApplicationsTool(**shared),
        ApplicationStatusTool(**shared),
        OpenApplicationTool(**shared),
        FocusApplicationTool(**shared),
        CloseApplicationTool(**shared, close_poll_interval=close_poll_interval, close_attempts=close_attempts),
    )


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------
def _clean_str_tuple(values: Iterable[str], *, lower: bool = True) -> Tuple[str, ...]:
    cleaned = tuple(str(value).strip() for value in (values or ()))
    return tuple(value.lower() if lower else value for value in cleaned if value)


def _validate_launch_target(target: str) -> None:
    if FORBIDDEN_TARGET_RE.search(target):
        raise ValueError(f"Launch target contains forbidden characters: {target!r}")
    if " " in target.strip():
        raise ValueError(f"Launch target must be a single executable or URI, not a command line: {target!r}")
    if URI_TARGET_RE.match(target):
        return
    if not target.lower().endswith(".exe"):
        raise ValueError(f"Launch target must be an .exe or a registered URI: {target!r}")


def _validate_search_path(path: str) -> None:
    if FORBIDDEN_TARGET_RE.search(path):
        raise ValueError(f"Search path contains forbidden characters: {path!r}")
    if not path.lower().endswith(".exe"):
        raise ValueError(f"Search path must point at an .exe file: {path!r}")
