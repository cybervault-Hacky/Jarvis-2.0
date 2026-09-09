"""The device-tool contract (Phase 1).

Every future device action (call, message, volume, shutdown, ...) is expressed
as a :class:`BaseDeviceTool` subclass that declares *what it is* before it
declares *what it does*::

    class ShutdownTool(BaseDeviceTool):
        name = "pc.power.shutdown"
        description = "Shut the PC down."
        platform = Platform.PC
        risk_level = RiskLevel.DESTRUCTIVE
        required_permissions = (PERMISSION_POWER_CONTROL,)
        argument_schema = ArgumentSchema.empty()

        async def run(self, arguments, context):
            ...  # implemented in a later phase

The framework never lets natural language run arbitrary commands: only objects
that satisfy this contract, and that are explicitly registered, can execute.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Mapping, Optional, Protocol, Tuple

from .arguments import ArgumentSchema
from .confirmation import utcnow
from .enums import Platform, RiskLevel, ToolResultStatus
from .errors import ErrorCode
from .results import ToolResult

__all__ = ["ToolContext", "DeviceTool", "BaseDeviceTool"]


@dataclass(frozen=True)
class ToolContext:
    """Read-only context handed to a tool when it runs."""

    execution_id: str
    tool_name: str
    platform: Platform = Platform.UNKNOWN
    arguments: Mapping[str, Any] = field(default_factory=dict)
    session_id: str = ""
    requested_at: datetime = field(default_factory=utcnow)
    #: The platform adapter that dispatched this call, when there is one.
    adapter: Optional[Any] = None


class DeviceTool(Protocol):
    """Structural description of a device tool.

    This protocol exists for typing and documentation. Registration validation
    is done explicitly in :mod:`jarvis_devices.registry` so it works on every
    supported Python version and produces precise error messages.
    """

    name: str
    description: str
    platform: Platform
    risk_level: RiskLevel
    required_permissions: Tuple[str, ...]
    requires_confirmation: Optional[bool]
    argument_schema: ArgumentSchema

    def is_available(self) -> bool: ...

    async def execute(self, arguments: Mapping[str, Any], context: ToolContext) -> ToolResult: ...


class BaseDeviceTool(ABC):
    """Base class for all JARVIS device tools.

    Subclasses override :meth:`run`. They must not override :meth:`execute`,
    which is the guarded entry point used by the framework.
    """

    #: Registered name, e.g. ``"pc.audio.volume"``.
    name: str = ""
    #: One line, user safe description.
    description: str = ""
    #: Where the tool can run.
    platform: Platform = Platform.UNKNOWN
    #: How dangerous the tool is.
    risk_level: RiskLevel = RiskLevel.SAFE
    #: Permissions the tool needs (see :mod:`jarvis_devices.permissions`).
    required_permissions: Tuple[str, ...] = ()
    #: ``None`` = decide from :attr:`risk_level` via the confirmation policy.
    requires_confirmation: Optional[bool] = None
    #: ``True`` for operations that must *never* run unconfirmed, whatever the
    #: confirmation policy says (Phase 4 power control). The policy still owns
    #: the question, TTL and single use - this flag only removes the ability to
    #: opt the tool out via ``never_confirm``.
    confirmation_mandatory: bool = False
    #: ``True`` when a caller supplied generic confirmation target must never
    #: replace the tool's complete, user-safety-critical rendered target.
    confirmation_target_mandatory: bool = False
    #: Declared arguments.
    argument_schema: ArgumentSchema = ArgumentSchema.empty()

    # ------------------------------------------------------------------
    # Availability
    # ------------------------------------------------------------------
    def is_available(self) -> bool:
        """Whether the tool could run right now.

        Phase 1 default: a tool is available when it declares a real platform.
        Concrete tools in later phases can override this (for example to check
        that a device is paired).
        """
        return self.platform is not Platform.UNKNOWN

    # ------------------------------------------------------------------
    # Guarded entry point
    # ------------------------------------------------------------------
    async def execute(self, arguments: Mapping[str, Any], context: ToolContext) -> ToolResult:
        """Validate arguments, run the tool and normalise the result.

        Never raises: any unexpected exception becomes a ``FAILED`` result, so
        JARVIS can never mistake a crash for a successful real world action.
        """
        validated, errors = self.argument_schema.validate(arguments)
        if errors:
            return ToolResult.invalid_argument(
                f"Invalid arguments for {self.name}: " + "; ".join(errors),
                error="; ".join(errors),
                tool_name=self.name,
                execution_id=context.execution_id,
            )

        try:
            validated = self.normalize_arguments(validated)
        except Exception:  # noqa: BLE001 - normalizers are an untrusted input boundary
            return ToolResult.invalid_argument(
                f"Invalid arguments for {self.name}.",
                error_code=ErrorCode.INVALID_ARGUMENT,
                tool_name=self.name,
                execution_id=context.execution_id,
            )

        try:
            result = await self.run(validated, context)
        except Exception as exc:  # noqa: BLE001 - framework boundary
            return ToolResult.failure(
                f"Tool {self.name} raised an error and did not complete.",
                error=f"{type(exc).__name__}: {exc}"[:300],
                error_code=ErrorCode.TOOL_ERROR,
                tool_name=self.name,
                execution_id=context.execution_id,
            ).marked_executed()

        return self._normalise(result, context)

    # ------------------------------------------------------------------
    # Optional pre-execution normalization
    # ------------------------------------------------------------------
    def normalize_arguments(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Return validated arguments in their canonical form.

        Most tools leave values unchanged.  Destination-bearing tools can
        override this narrow hook so a confirmation is bound to the exact
        canonical request that will execute, rather than a presentation form.
        The action manager invokes it before permissions/confirmation and this
        guarded direct entry point invokes it again defensively.
        """
        return dict(arguments)

    def confirmation_target(self, arguments: Dict[str, Any]) -> str:
        """Human-readable confirmation target, without changing execution."""
        return self.description or self.name

    # ------------------------------------------------------------------
    # Implemented by concrete tools (later phases)
    # ------------------------------------------------------------------
    @abstractmethod
    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        """Perform the action and return an honest result."""

    # ------------------------------------------------------------------
    def _normalise(self, result: Any, context: ToolContext) -> ToolResult:
        """Force a tool's return value into a stamped :class:`ToolResult`."""
        if not isinstance(result, ToolResult):
            return ToolResult.failure(
                f"Tool {self.name} returned {type(result).__name__} instead of ToolResult.",
                error_code=ErrorCode.TOOL_ERROR,
                tool_name=self.name,
                execution_id=context.execution_id,
            ).marked_executed()
        if result.status is ToolResultStatus.SUCCESS and result.message == "":
            result = result.with_message(f"{self.name} completed.")
        return result.with_ids(
            tool_name=self.name, execution_id=context.execution_id
        ).marked_executed()

    # ------------------------------------------------------------------
    def describe(self) -> Dict[str, Any]:
        """Metadata summary (safe to show in logs and to the model)."""
        return {
            "name": self.name,
            "description": self.description,
            "platform": self.platform.value,
            "risk_level": self.risk_level.value,
            "required_permissions": list(self.required_permissions),
            "requires_confirmation": self.requires_confirmation,
            "available": self.is_available(),
            "arguments": self.argument_schema.to_json_schema(),
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return f"<{type(self).__name__} name={self.name!r} risk={self.risk_level.value}>"
