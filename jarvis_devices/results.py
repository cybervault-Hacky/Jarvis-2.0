"""Structured tool results (Phase 1).

A :class:`ToolResult` is the only thing a device tool is allowed to return. It
answers four questions:

1. did the tool actually run and succeed? (``status`` / ``success``)
2. what should JARVIS say? (``message``)
3. what came back? (``data``)
4. why did it not work? (``error`` / ``error_code``)

``success`` is a *derived* read-only property, never a settable field, so the
framework cannot report success for anything other than
:attr:`ToolResultStatus.SUCCESS`.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Dict, Mapping, Optional

from .enums import ToolResultStatus
from .errors import ErrorCode

__all__ = ["ToolResult"]


@dataclass(frozen=True)
class ToolResult:
    """Immutable outcome of one device-tool request."""

    status: ToolResultStatus
    message: str = ""
    tool_name: str = ""
    execution_id: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    error_code: Optional[str] = None
    #: Set by the framework (never by a tool) when the tool was really
    #: dispatched. A rejected request stays ``False`` even when its status is
    #: ``FAILED`` - e.g. an unknown tool never ran.
    executed: bool = False

    # ------------------------------------------------------------------
    # Derived state
    # ------------------------------------------------------------------
    @property
    def success(self) -> bool:
        """``True`` only for a genuine :attr:`ToolResultStatus.SUCCESS`."""
        return self.status is ToolResultStatus.SUCCESS

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------
    @classmethod
    def ok(
        cls,
        message: str = "",
        *,
        tool_name: str = "",
        execution_id: str = "",
        data: Optional[Mapping[str, Any]] = None,
    ) -> "ToolResult":
        """Build a successful result."""
        return cls(
            status=ToolResultStatus.SUCCESS,
            message=message,
            tool_name=tool_name,
            execution_id=execution_id,
            data=dict(data or {}),
        )

    @classmethod
    def failure(
        cls,
        message: str,
        *,
        error: Optional[str] = None,
        error_code: str = ErrorCode.TOOL_ERROR,
        tool_name: str = "",
        execution_id: str = "",
        data: Optional[Mapping[str, Any]] = None,
    ) -> "ToolResult":
        """Build a generic failure result."""
        return cls(
            status=ToolResultStatus.FAILED,
            message=message,
            tool_name=tool_name,
            execution_id=execution_id,
            data=dict(data or {}),
            error=error,
            error_code=error_code,
        )

    @classmethod
    def denied(
        cls,
        message: str,
        *,
        error_code: str = ErrorCode.CONFIRMATION_DENIED,
        tool_name: str = "",
        execution_id: str = "",
        data: Optional[Mapping[str, Any]] = None,
    ) -> "ToolResult":
        """Build a result for an action the user refused."""
        return cls(
            status=ToolResultStatus.DENIED,
            message=message,
            tool_name=tool_name,
            execution_id=execution_id,
            data=dict(data or {}),
            error_code=error_code,
        )

    @classmethod
    def permission_denied(
        cls,
        message: str,
        *,
        missing_permissions: Optional[Mapping[str, Any]] = None,
        error_code: str = ErrorCode.PERMISSION_DENIED,
        tool_name: str = "",
        execution_id: str = "",
    ) -> "ToolResult":
        """Build a result for a missing or blocked permission."""
        return cls(
            status=ToolResultStatus.PERMISSION_DENIED,
            message=message,
            tool_name=tool_name,
            execution_id=execution_id,
            data=dict(missing_permissions or {}),
            error_code=error_code,
        )

    @classmethod
    def invalid_argument(
        cls,
        message: str,
        *,
        error: Optional[str] = None,
        tool_name: str = "",
        execution_id: str = "",
    ) -> "ToolResult":
        """Build a result for arguments that failed schema validation."""
        return cls(
            status=ToolResultStatus.INVALID_ARGUMENT,
            message=message,
            tool_name=tool_name,
            execution_id=execution_id,
            error=error,
            error_code=ErrorCode.INVALID_ARGUMENT,
        )

    @classmethod
    def cancelled(
        cls,
        message: str = "The action was cancelled.",
        *,
        error_code: str = ErrorCode.CONFIRMATION_CANCELLED,
        tool_name: str = "",
        execution_id: str = "",
        data: Optional[Mapping[str, Any]] = None,
    ) -> "ToolResult":
        """Build a result for an action the user (or system) cancelled."""
        return cls(
            status=ToolResultStatus.CANCELLED,
            message=message,
            tool_name=tool_name,
            execution_id=execution_id,
            data=dict(data or {}),
            error_code=error_code,
        )

    @classmethod
    def timeout(
        cls,
        message: str = "The action timed out.",
        *,
        error_code: str = ErrorCode.CONFIRMATION_EXPIRED,
        tool_name: str = "",
        execution_id: str = "",
        data: Optional[Mapping[str, Any]] = None,
    ) -> "ToolResult":
        """Build a result for an expired confirmation or a timed out tool."""
        return cls(
            status=ToolResultStatus.TIMEOUT,
            message=message,
            tool_name=tool_name,
            execution_id=execution_id,
            data=dict(data or {}),
            error_code=error_code,
        )

    @classmethod
    def unavailable(
        cls,
        message: str,
        *,
        error_code: str = ErrorCode.TOOL_UNAVAILABLE,
        tool_name: str = "",
        execution_id: str = "",
        data: Optional[Mapping[str, Any]] = None,
    ) -> "ToolResult":
        """Build a result for a tool/platform/device that cannot run right now."""
        return cls(
            status=ToolResultStatus.UNAVAILABLE,
            message=message,
            tool_name=tool_name,
            execution_id=execution_id,
            data=dict(data or {}),
            error_code=error_code,
        )

    @classmethod
    def pending_confirmation(
        cls,
        message: str,
        *,
        confirmation_id: str,
        tool_name: str = "",
        execution_id: str = "",
        data: Optional[Mapping[str, Any]] = None,
    ) -> "ToolResult":
        """Build a result meaning "ask the user, nothing has happened yet"."""
        payload = dict(data or {})
        payload["confirmation_id"] = confirmation_id
        payload["confirmation_required"] = True
        return cls(
            status=ToolResultStatus.PENDING_CONFIRMATION,
            message=message,
            tool_name=tool_name,
            execution_id=execution_id,
            data=payload,
            error_code=ErrorCode.CONFIRMATION_REQUIRED,
        )

    # ------------------------------------------------------------------
    # Copies
    # ------------------------------------------------------------------
    def with_ids(self, *, tool_name: str = "", execution_id: str = "") -> "ToolResult":
        """Return a copy stamped with the tool name and execution id."""
        return replace(
            self,
            tool_name=tool_name or self.tool_name,
            execution_id=execution_id or self.execution_id,
        )

    def marked_executed(self) -> "ToolResult":
        """Return a copy flagged as "the tool really ran"."""
        return replace(self, executed=True)

    def with_message(self, message: str) -> "ToolResult":
        """Return a copy with a different user facing message."""
        return replace(self, message=message)

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON friendly dictionary (used by logging and tests)."""
        return {
            "success": self.success,
            "status": self.status.value,
            "message": self.message,
            "tool_name": self.tool_name,
            "execution_id": self.execution_id,
            "data": dict(self.data),
            "error": self.error,
            "error_code": self.error_code,
            "executed": self.executed,
        }
