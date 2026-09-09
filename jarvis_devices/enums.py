"""Shared enumerations for the JARVIS secure device-tool framework (Phase 1).

These enums are the vocabulary every other module in the package uses, so they
are deliberately dependency free (standard library only).
"""

from __future__ import annotations

from enum import Enum

__all__ = [
    "RiskLevel",
    "Platform",
    "ToolResultStatus",
    "ConfirmationStatus",
    "ToolLifecycleEvent",
]


class RiskLevel(str, Enum):
    """How much damage a device tool can do if it runs.

    Examples of future tools per level:

    * :attr:`SAFE` -> read device status
    * :attr:`LOW_RISK` -> change volume / brightness
    * :attr:`EXTERNAL_ACTION` -> send a message, place a call
    * :attr:`DESTRUCTIVE` -> shutdown, restart
    """

    SAFE = "safe"
    LOW_RISK = "low_risk"
    EXTERNAL_ACTION = "external_action"
    DESTRUCTIVE = "destructive"

    @property
    def rank(self) -> int:
        """Ordered severity, ``SAFE`` being the lowest."""
        return _RISK_ORDER[self]

    def at_least(self, other: "RiskLevel") -> bool:
        """Return ``True`` when this level is as risky as ``other``."""
        return self.rank >= other.rank


_RISK_ORDER = {
    RiskLevel.SAFE: 0,
    RiskLevel.LOW_RISK: 1,
    RiskLevel.EXTERNAL_ACTION: 2,
    RiskLevel.DESTRUCTIVE: 3,
}


class Platform(str, Enum):
    """Where a device tool is able to run."""

    PC = "pc"
    ANDROID = "android"
    UNKNOWN = "unknown"


class ToolResultStatus(str, Enum):
    """Outcome of a tool request.

    ``SUCCESS`` is the *only* status that may be reported to the user as
    "the action happened".
    """

    SUCCESS = "success"
    FAILED = "failed"
    DENIED = "denied"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"
    INVALID_ARGUMENT = "invalid_argument"
    PERMISSION_DENIED = "permission_denied"
    # Phase 1 addition (outside the required set): the action is waiting for a
    # human yes/no. It is kept separate from DENIED so the framework never
    # claims the user refused something they were never asked about.
    PENDING_CONFIRMATION = "pending_confirmation"


class ConfirmationStatus(str, Enum):
    """Lifecycle of a single confirmation request."""

    NOT_REQUIRED = "not_required"
    PENDING = "pending"
    CONFIRMED = "confirmed"
    DENIED = "denied"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class ToolLifecycleEvent(str, Enum):
    """Structured lifecycle events emitted by :mod:`jarvis_devices.audit`."""

    TOOL_REQUESTED = "tool_requested"
    PERMISSION_CHECKED = "permission_checked"
    CONFIRMATION_REQUESTED = "confirmation_requested"
    CONFIRMATION_RECEIVED = "confirmation_received"
    EXECUTION_STARTED = "execution_started"
    EXECUTION_COMPLETED = "execution_completed"
    EXECUTION_FAILED = "execution_failed"
    # Phase 9. These describe bounded orchestration state only; the existing
    # manager events still describe the authoritative permission/confirmation/
    # execution lifecycle of the registered device tool.
    CROSS_DEVICE_PLAN_CREATED = "cross_device_plan_created"
    CROSS_DEVICE_PLAN_SUBMITTED = "cross_device_plan_submitted"
    CROSS_DEVICE_PLAN_PENDING = "cross_device_plan_pending"
    CROSS_DEVICE_PLAN_COMPLETED = "cross_device_plan_completed"
    CROSS_DEVICE_PLAN_FAILED = "cross_device_plan_failed"
    CROSS_DEVICE_PLAN_INVALIDATED = "cross_device_plan_invalidated"
