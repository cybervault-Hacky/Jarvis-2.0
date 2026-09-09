"""Reusable confirmation framework (Phase 1).

Sensitive actions (external or destructive) must be confirmed by the human
before they run. This module only builds the *infrastructure*:

* :class:`ConfirmationRequest` - one pending question with an id and a deadline
* :class:`ConfirmationPolicy`  - decides which tools need a question at all
* :class:`ConfirmationManager` - create / confirm / deny / cancel / expire

No device action is implemented here; a future shutdown tool simply declares
``risk_level = RiskLevel.DESTRUCTIVE`` and inherits this behaviour.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, Optional, Tuple

from .enums import ConfirmationStatus, RiskLevel
from .errors import (
    ConfirmationExpiredError,
    ConfirmationLimitError,
    ConfirmationStateError,
    UnknownConfirmationError,
)
from .ids import new_confirmation_id

__all__ = [
    "DEFAULT_CONFIRMATION_TTL",
    "ConfirmationRequest",
    "ConfirmationPolicy",
    "ConfirmationManager",
    "utcnow",
]

DEFAULT_CONFIRMATION_TTL = timedelta(minutes=5)
MAX_PENDING_CONFIRMATIONS = 64


def utcnow() -> datetime:
    """Timezone aware "now" used everywhere in the framework."""
    return datetime.now(timezone.utc)


@dataclass
class ConfirmationRequest:
    """A single "are you sure?" question."""

    confirmation_id: str
    action: str
    expires_at: datetime
    created_at: datetime = field(default_factory=utcnow)
    target: str = ""
    status: ConfirmationStatus = ConfirmationStatus.PENDING
    risk_level: Optional[RiskLevel] = None
    #: Validated arguments kept so the action can run once confirmed.
    #: Excluded from ``repr`` because they can contain private content.
    arguments: Dict[str, Any] = field(default_factory=dict, repr=False)
    consumed: bool = False

    # ------------------------------------------------------------------
    @property
    def tool_name(self) -> str:
        """Alias of :attr:`action` (the registered tool name)."""
        return self.action

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        """``True`` when the deadline has passed."""
        moment = now or utcnow()
        expires_at = _aware(self.expires_at)
        return moment >= expires_at

    def is_pending(self, now: Optional[datetime] = None) -> bool:
        """``True`` while the question can still be answered."""
        if self.status is not ConfirmationStatus.PENDING:
            return False
        return not self.is_expired(now)

    def is_resolved(self) -> bool:
        """``True`` once the question is out of the way."""
        return self.status in (
            ConfirmationStatus.NOT_REQUIRED,
            ConfirmationStatus.CONFIRMED,
            ConfirmationStatus.DENIED,
            ConfirmationStatus.CANCELLED,
            ConfirmationStatus.EXPIRED,
        )

    def describe(self) -> str:
        """A loggable summary that never includes argument values.

        A dial confirmation deliberately keeps its full canonical number in
        ``target`` for the human confirmation UI, but this diagnostic summary
        must not turn that sensitive UI value into an audit/debug value.
        """
        risk = self.risk_level.value if self.risk_level else "unknown"
        target = "[sensitive confirmation target]" if self.action == "android.call.dial" else (self.target or "no target")
        return f"{self.action} ({target}) [risk={risk}]"

    def to_dict(self) -> Dict[str, Any]:
        """JSON friendly view; argument *values* are deliberately omitted."""
        return {
            "confirmation_id": self.confirmation_id,
            "action": self.action,
            "target": self.target,
            "created_at": _aware(self.created_at).isoformat(),
            "expires_at": _aware(self.expires_at).isoformat(),
            "status": self.status.value,
            "risk_level": self.risk_level.value if self.risk_level else None,
            "argument_names": sorted(self.arguments),
            "consumed": self.consumed,
        }


class ConfirmationPolicy:
    """Decides which tools need a human yes/no before running."""

    def __init__(
        self,
        risk_levels: Iterable[RiskLevel] = (RiskLevel.EXTERNAL_ACTION, RiskLevel.DESTRUCTIVE),
        *,
        always_confirm: Iterable[str] = (),
        never_confirm: Iterable[str] = (),
    ) -> None:
        self.risk_levels: Tuple[RiskLevel, ...] = tuple(risk_levels)
        self.always_confirm = frozenset(_lower(always_confirm))
        self.never_confirm = frozenset(_lower(never_confirm))

    def is_required(self, tool: Any) -> bool:
        """Return ``True`` when ``tool`` must be confirmed before execution."""
        # Phase 4: a tool that declares itself non-negotiable cannot be opted out
        # of, not even by name in ``never_confirm``. Power operations must always
        # reach a human yes/no, so this check comes first.
        if getattr(tool, "confirmation_mandatory", False):
            return True
        name = str(getattr(tool, "name", "")).strip().lower()
        if name in self.never_confirm:
            return False
        if name in self.always_confirm:
            return True
        override = getattr(tool, "requires_confirmation", None)
        if override is not None:
            return bool(override)
        return getattr(tool, "risk_level", RiskLevel.SAFE) in self.risk_levels


class ConfirmationManager:
    """In-memory store of pending confirmations with expiry."""

    def __init__(
        self,
        default_ttl: timedelta = DEFAULT_CONFIRMATION_TTL,
        *,
        clock: Callable[[], datetime] = utcnow,
        max_pending: int = MAX_PENDING_CONFIRMATIONS,
        policy: Optional[ConfirmationPolicy] = None,
    ) -> None:
        self.default_ttl = default_ttl
        self._clock = clock
        self._max_pending = max(1, max_pending)
        self.policy = policy or ConfirmationPolicy()
        self._requests: Dict[str, ConfirmationRequest] = {}

    # ------------------------------------------------------------------
    # Clock
    # ------------------------------------------------------------------
    def now(self) -> datetime:
        return self._clock()

    # ------------------------------------------------------------------
    # Creation
    # ------------------------------------------------------------------
    def create(
        self,
        action: str,
        target: str = "",
        *,
        arguments: Optional[Dict[str, Any]] = None,
        ttl: Optional[timedelta] = None,
        risk_level: Optional[RiskLevel] = None,
    ) -> ConfirmationRequest:
        """Create a new :class:`ConfirmationRequest` in ``PENDING`` state."""
        if not action or not str(action).strip():
            raise ValueError("A confirmation needs an action name")

        self.expire_overdue()
        pending_count = sum(
            1 for request in self._requests.values() if request.status is ConfirmationStatus.PENDING
        )
        if pending_count >= self._max_pending:
            raise ConfirmationLimitError(
                f"Too many pending confirmations (limit {self._max_pending})"
            )

        now = self.now()
        request = ConfirmationRequest(
            confirmation_id=new_confirmation_id(),
            action=str(action).strip().lower(),
            expires_at=now + (ttl or self.default_ttl),
            created_at=now,
            target=target,
            status=ConfirmationStatus.PENDING,
            risk_level=risk_level,
            arguments=dict(arguments or {}),
        )
        self._requests[request.confirmation_id] = request
        return request

    def not_required(self, action: str = "", target: str = "") -> ConfirmationRequest:
        """Return a throw-away request marked :attr:`ConfirmationStatus.NOT_REQUIRED`."""
        now = self.now()
        return ConfirmationRequest(
            confirmation_id="",
            action=str(action).strip().lower(),
            expires_at=now,
            created_at=now,
            target=target,
            status=ConfirmationStatus.NOT_REQUIRED,
        )

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------
    def get(self, confirmation_id: str) -> Optional[ConfirmationRequest]:
        """Return the request or ``None`` when the id is unknown."""
        request = self._requests.get((confirmation_id or "").strip())
        if request is not None and request.status is ConfirmationStatus.PENDING:
            if request.is_expired(self.now()):
                request.status = ConfirmationStatus.EXPIRED
        return request

    def require(self, confirmation_id: str) -> ConfirmationRequest:
        """Return the request or raise :class:`UnknownConfirmationError`."""
        request = self.get(confirmation_id)
        if request is None:
            raise UnknownConfirmationError(f"Unknown confirmation id: {confirmation_id!r}")
        return request

    def pending(self) -> Tuple[ConfirmationRequest, ...]:
        """All confirmations that can still be answered."""
        self.expire_overdue()
        return tuple(
            request
            for request in self._requests.values()
            if request.status is ConfirmationStatus.PENDING
        )

    # ------------------------------------------------------------------
    # Resolution
    # ------------------------------------------------------------------
    def confirm(self, confirmation_id: str) -> ConfirmationRequest:
        """Mark a pending confirmation as confirmed."""
        return self._resolve(confirmation_id, ConfirmationStatus.CONFIRMED)

    def deny(self, confirmation_id: str) -> ConfirmationRequest:
        """Mark a pending confirmation as denied (user said no)."""
        return self._resolve(confirmation_id, ConfirmationStatus.DENIED)

    def cancel(self, confirmation_id: str) -> ConfirmationRequest:
        """Mark a pending confirmation as cancelled (user gave up)."""
        return self._resolve(confirmation_id, ConfirmationStatus.CANCELLED)

    def resolve(self, confirmation_id: str, approved: bool) -> ConfirmationRequest:
        """Confirm when ``approved`` is ``True``, deny otherwise."""
        return self.confirm(confirmation_id) if approved else self.deny(confirmation_id)

    def _resolve(self, confirmation_id: str, status: ConfirmationStatus) -> ConfirmationRequest:
        request = self.require(confirmation_id)
        if request.status is ConfirmationStatus.EXPIRED:
            raise ConfirmationExpiredError(f"Confirmation {confirmation_id!r} has expired")
        if request.status is not ConfirmationStatus.PENDING:
            raise ConfirmationStateError(
                f"Confirmation {confirmation_id!r} is already {request.status.value}"
            )
        request.status = status
        return request

    def consume(self, confirmation_id: str) -> bool:
        """Mark a confirmed request as used so it cannot be replayed.

        Returns ``True`` only for the call that actually consumes it.
        """
        request = self.get(confirmation_id)
        if request is None or request.consumed:
            return False
        if request.status is not ConfirmationStatus.CONFIRMED:
            return False
        request.consumed = True
        return True

    def is_consumed(self, confirmation_id: str) -> bool:
        request = self.get(confirmation_id)
        return bool(request and request.consumed)

    # ------------------------------------------------------------------
    # Housekeeping
    # ------------------------------------------------------------------
    def expire_overdue(self) -> int:
        """Flip overdue pending confirmations to ``EXPIRED``; return the count."""
        expired = 0
        now = self.now()
        for request in self._requests.values():
            if request.status is ConfirmationStatus.PENDING and request.is_expired(now):
                request.status = ConfirmationStatus.EXPIRED
                expired += 1
        return expired

    def clear(self) -> None:
        """Forget every confirmation (used by tests and shutdown paths)."""
        self._requests.clear()

    def __len__(self) -> int:
        return len(self._requests)

    def __contains__(self, confirmation_id: object) -> bool:
        return confirmation_id in self._requests


def _aware(moment: datetime) -> datetime:
    """Make a datetime timezone aware (assumes UTC when naive)."""
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment


def _lower(names: Iterable[str]) -> Tuple[str, ...]:
    return tuple(str(name).strip().lower() for name in names)
