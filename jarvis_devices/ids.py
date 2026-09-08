"""Identifier helpers (Phase 1).

Every tool request gets a unique ``execution_id`` and every confirmation gets a
unique ``confirmation_id``. They are used to tie lifecycle log lines together.
"""

from __future__ import annotations

import uuid

__all__ = ["new_execution_id", "new_confirmation_id", "EXECUTION_ID_PREFIX", "CONFIRMATION_ID_PREFIX"]

EXECUTION_ID_PREFIX = "exec"
CONFIRMATION_ID_PREFIX = "cfm"


def new_execution_id(prefix: str = EXECUTION_ID_PREFIX) -> str:
    """Return a unique execution id such as ``exec-4f1c...``."""
    return f"{prefix}-{uuid.uuid4().hex}"


def new_confirmation_id(prefix: str = CONFIRMATION_ID_PREFIX) -> str:
    """Return a unique confirmation id such as ``cfm-9ab2...``."""
    return f"{prefix}-{uuid.uuid4().hex}"
