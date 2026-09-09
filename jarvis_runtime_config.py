"""Non-secret runtime configuration preflight for the LiveKit worker.

Only configuration *names* are reported. Values are read from the normal process
environment so a deployment may use a secret manager instead of a dotenv file.
"""

from __future__ import annotations

import os
from typing import Mapping, Tuple

REQUIRED_RUNTIME_ENVIRONMENT: Tuple[str, ...] = (
    "LIVEKIT_URL",
    "LIVEKIT_API_KEY",
    "LIVEKIT_API_SECRET",
    "GOOGLE_API_KEY",
)


def runtime_configuration_errors(environ: Mapping[str, str] | None = None) -> Tuple[str, ...]:
    """Return missing required setting names without reading them into output."""
    source = os.environ if environ is None else environ
    return tuple(name for name in REQUIRED_RUNTIME_ENVIRONMENT if not str(source.get(name, "")).strip())


def validate_runtime_configuration(environ: Mapping[str, str] | None = None) -> None:
    """Fail before a worker starts when required configuration is incomplete."""
    missing = runtime_configuration_errors(environ)
    if missing:
        raise RuntimeError("Missing required runtime configuration: " + ", ".join(missing))
