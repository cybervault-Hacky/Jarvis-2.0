"""Structured lifecycle logging with privacy redaction (Phase 1).

Every request emits the lifecycle events::

    TOOL_REQUESTED -> PERMISSION_CHECKED -> [CONFIRMATION_REQUESTED ->
    CONFIRMATION_RECEIVED] -> EXECUTION_STARTED -> EXECUTION_COMPLETED /
    EXECUTION_FAILED

Each line is a JSON object tied together by ``execution_id``.

What is deliberately **never** written to a log line:

* API keys, tokens, passwords or any credential looking value
* the *values* of tool arguments (only argument names are logged)
* private message bodies, phone numbers, e-mail addresses

The manager enforces this by only ever handing over argument names; the
:class:`Redactor` is a second line of defence for anything else.
"""

from __future__ import annotations

import json
import logging
import re
from collections import deque
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Deque, Dict, Iterable, Optional, Tuple

from .confirmation import utcnow
from .enums import ToolLifecycleEvent
from .results import ToolResult

__all__ = [
    "Redactor",
    "AuditLogger",
    "REDACTED",
    "SENSITIVE_KEY_RE",
    "SAFE_KEYS",
    "AUDIT_LOGGER_NAME",
]

AUDIT_LOGGER_NAME = "jarvis.device.audit"
REDACTED = "[redacted]"
MAX_TEXT_LENGTH = 200
MAX_RECORDS = 100

SENSITIVE_KEY_RE = re.compile(
    r"(?:^|[^a-zA-Z])(?:api[_-]?key|apikey|secret|token|password|passwd|pwd|credential|"
    r"authorization|auth[_-]?header|cookie|otp|cvv|pin|message|body|content|payload|text|"
    r"phone|mobile|email|contact|recipient|address|location)",
    re.IGNORECASE,
)

SECRET_TEXT_RE = re.compile(
    r"(?i)\b(api[_-]?key|apikey|secret|token|password|passwd|authorization|bearer)\b"
    r"(\s*[:=]\s*)(\S+)"
)

EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
# A leading negative lookahead keeps ISO timestamps ("2026-09-08T11:01:21")
# from being mistaken for a phone number.
PHONE_RE = re.compile(
    r"(?<![0-9a-fA-F])(?!\d{4}-\d{2}-\d{2})(?:\+?\d[\d\s-]{7,}\d)(?![0-9a-fA-F])"
)

#: Identifier-like fields that must survive redaction untouched, otherwise log
#: lines could not be correlated by execution id.
SAFE_KEYS = frozenset(
    {
        "ts",
        "event",
        "execution_id",
        "confirmation_id",
        "tool",
        "tool_name",
        "status",
        "success",
        "error_code",
        "platform",
        "risk_level",
        "allowed",
        "available",
        "argument_names",
        "registered_tools",
        "created_at",
        "expires_at",
        "requested_at",
        "duration_ms",
    }
)


class Redactor:
    """Removes secrets and personal data from anything about to be logged."""

    def __init__(self, max_text_length: int = MAX_TEXT_LENGTH) -> None:
        self.max_text_length = max(20, max_text_length)

    # ------------------------------------------------------------------
    def is_sensitive_key(self, key: Any) -> bool:
        """``True`` when a mapping key looks like it holds private data."""
        return bool(SENSITIVE_KEY_RE.search(str(key)))

    def redact_text(self, text: str) -> str:
        """Mask embedded credentials, e-mails and phone numbers."""
        cleaned = SECRET_TEXT_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", str(text))
        cleaned = EMAIL_RE.sub(REDACTED, cleaned)
        cleaned = PHONE_RE.sub(REDACTED, cleaned)
        if len(cleaned) > self.max_text_length:
            cleaned = cleaned[: self.max_text_length] + "…"
        return cleaned

    def redact_value(self, value: Any, _depth: int = 0) -> Any:
        """Recursively redact a value that is about to be logged."""
        if _depth > 4:
            return REDACTED
        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
            return value
        if isinstance(value, dict):
            return {
                str(key): (REDACTED if self.is_sensitive_key(key) else self.redact_value(val, _depth + 1))
                for key, val in value.items()
            }
        if isinstance(value, (list, tuple, set, frozenset)):
            return [self.redact_value(item, _depth + 1) for item in value]
        return self.redact_text(repr(value))


class AuditLogger:
    """Emits structured, redacted lifecycle events."""

    def __init__(
        self,
        logger: Optional[logging.Logger] = None,
        *,
        redactor: Optional[Redactor] = None,
        sinks: Iterable[Callable[[Dict[str, Any]], None]] = (),
        clock: Callable[[], datetime] = utcnow,
        keep_records: int = MAX_RECORDS,
        enabled: bool = True,
    ) -> None:
        self.logger = logger or logging.getLogger(AUDIT_LOGGER_NAME)
        self.redactor = redactor or Redactor()
        self._sinks: Tuple[Callable[[Dict[str, Any]], None], ...] = tuple(sinks)
        self._clock = clock
        self._records: Deque[Dict[str, Any]] = deque(maxlen=max(1, keep_records))
        self.enabled = enabled

    # ------------------------------------------------------------------
    def add_sink(self, sink: Callable[[Dict[str, Any]], None]) -> None:
        """Register an extra consumer (tests, UI, remote collectors)."""
        self._sinks = self._sinks + (sink,)

    @property
    def records(self) -> Tuple[Dict[str, Any], ...]:
        """The most recent redacted records (newest last)."""
        return tuple(self._records)

    def clear_records(self) -> None:
        self._records.clear()

    # ------------------------------------------------------------------
    def log(
        self,
        event: ToolLifecycleEvent,
        *,
        execution_id: str = "",
        tool_name: str = "",
        **fields: Any,
    ) -> Dict[str, Any]:
        """Emit one lifecycle event and return the redacted payload."""
        payload: Dict[str, Any] = {
            "ts": self._clock().isoformat(),
            "event": event.value if isinstance(event, ToolLifecycleEvent) else str(event),
        }
        if execution_id:
            payload["execution_id"] = execution_id
        if tool_name:
            payload["tool"] = tool_name
        for key, value in fields.items():
            if key in SAFE_KEYS:
                payload[key] = value.value if isinstance(value, Enum) else value
            elif self.redactor.is_sensitive_key(key):
                payload[key] = REDACTED
            else:
                payload[key] = self.redactor.redact_value(value)

        self._records.append(payload)
        if self.enabled:
            self.logger.info(json.dumps(payload, default=str, ensure_ascii=False))
        for sink in self._sinks:
            try:
                sink(payload)
            except Exception:  # noqa: BLE001 - logging must never break a request
                pass
        return payload

    # ------------------------------------------------------------------
    def log_result(self, event: ToolLifecycleEvent, result: ToolResult, **fields: Any) -> Dict[str, Any]:
        """Log a lifecycle event summarising a :class:`ToolResult`.

        The result message is logged under ``detail`` (redacted for embedded
        secrets, e-mails and phone numbers) rather than verbatim.
        """
        return self.log(
            event,
            execution_id=result.execution_id,
            tool_name=result.tool_name,
            status=result.status.value,
            success=result.success,
            error_code=result.error_code,
            error=result.error,
            detail=result.message,
            **fields,
        )
