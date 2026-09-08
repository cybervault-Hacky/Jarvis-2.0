"""Transport abstraction for the Android bridge (Phase 5).

The bridge core never opens a socket. It talks to an
:class:`AndroidBridgeTransport`, so a future implementation can move to a local
network, USB or Bluetooth without rewriting anything above this layer.

Phase 5 ships exactly one real transport - :class:`InMemoryAndroidTransport`, a
loopback pair of endpoints with no sockets at all. That is deliberate: there is
no Android companion application in this repository yet and no device to talk
to, so a network listener here would be an unauthenticated attack surface with
nothing legitimate behind it. When a real transport is added it must:

* bind to a specific interface, never ``0.0.0.0``, unless explicitly configured;
* authenticate every peer against the device registry before any frame is
  dispatched;
* enforce :data:`~jarvis_devices.android_protocol.MAX_MESSAGE_BYTES`;
* expose no generic "run this" endpoint.

:class:`UnavailableAndroidTransport` is what JARVIS uses when no transport is
configured: every operation fails honestly with ``android_bridge_unavailable``
instead of pretending a phone is connected.
"""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, Optional, Protocol, Tuple

from .confirmation import utcnow

__all__ = [
    "AndroidBridgeTransport",
    "AndroidTransportError",
    "AndroidTransportClosedError",
    "InMemoryAndroidTransport",
    "UnavailableAndroidTransport",
    "DEFAULT_RECEIVE_TIMEOUT",
]

#: How long ``receive`` waits before giving up and answering ``None``.
DEFAULT_RECEIVE_TIMEOUT = 5.0


class AndroidTransportError(Exception):
    """The transport could not carry a frame."""


class AndroidTransportClosedError(AndroidTransportError):
    """The transport is closed or the link was broken."""


class AndroidBridgeTransport(Protocol):
    """What the bridge needs from any transport."""

    name: str

    @property
    def is_open(self) -> bool: ...

    async def open(self) -> None: ...

    async def close(self) -> None: ...

    async def send(self, payload: bytes) -> None: ...

    async def receive(self, timeout: float = DEFAULT_RECEIVE_TIMEOUT) -> Optional[bytes]: ...

    def describe(self) -> Dict[str, Any]: ...


class UnavailableAndroidTransport:
    """Stand-in for "no transport configured". Fails honestly, sends nothing."""

    name = "unavailable"

    def __init__(self, reason: str = "No Android transport is configured on this machine.") -> None:
        self.reason = reason
        self._open = False

    @property
    def is_open(self) -> bool:
        return False

    async def open(self) -> None:
        raise AndroidTransportError(self.reason)

    async def close(self) -> None:
        self._open = False

    async def send(self, payload: bytes) -> None:
        raise AndroidTransportError(self.reason)

    async def receive(self, timeout: float = DEFAULT_RECEIVE_TIMEOUT) -> Optional[bytes]:
        return None

    def describe(self) -> Dict[str, Any]:
        return {"transport": self.name, "open": False, "reason": self.reason}


class _Inbox:
    """A loop-safe lazily created queue.

    ``asyncio.Queue`` binds to the running loop the first time it is awaited, so
    creating it inside a coroutine keeps a transport usable across the separate
    event loops that ``unittest.IsolatedAsyncioTestCase`` spins up.
    """

    def __init__(self) -> None:
        self._queue: Optional[asyncio.Queue] = None

    def queue(self) -> asyncio.Queue:
        if self._queue is None:
            self._queue = asyncio.Queue()
        return self._queue


@dataclass
class _Link:
    """Shared state between the two ends of an in-memory transport."""

    inboxes: Dict[str, _Inbox] = field(default_factory=lambda: {"a": _Inbox(), "b": _Inbox()})
    broken: bool = False
    #: Frames currently in flight, for test assertions.
    delivered: Deque[Tuple[str, bytes]] = field(default_factory=deque)


class InMemoryAndroidTransport:
    """Two endpoints joined by queues - a loopback link with no sockets.

    This is the transport used by the whole Phase 5 test suite, and it is also a
    legitimate runtime choice: it lets the bridge run, be exercised and be
    audited on a machine with no phone attached, without pretending one is
    there.

    Test knobs (never used in production paths): :meth:`break_link`,
    :meth:`restore_link`, :attr:`sent` and :attr:`latency`.
    """

    def __init__(
        self,
        link: _Link,
        own: str,
        peer: str,
        *,
        name: str = "in-memory",
        latency: float = 0.0,
    ) -> None:
        self._link = link
        self._own = own
        self._peer = peer
        self.name = name
        #: Artificial delay applied to sends, for exercising timeouts.
        self.latency = latency
        self._open = False
        #: Every frame this end has sent, for assertions.
        self.sent: Deque[bytes] = deque(maxlen=256)

    # ------------------------------------------------------------------
    @classmethod
    def create_pair(
        cls, *, names: Tuple[str, str] = ("jarvis", "android")
    ) -> Tuple["InMemoryAndroidTransport", "InMemoryAndroidTransport"]:
        """Return two connected endpoints (``pc_side, phone_side``)."""
        link = _Link()
        pc = cls(link, "a", "b", name=f"{names[0]}:in-memory")
        phone = cls(link, "b", "a", name=f"{names[1]}:in-memory")
        return pc, phone

    # ------------------------------------------------------------------
    @property
    def is_open(self) -> bool:
        return self._open and not self._link.broken

    async def open(self) -> None:
        if self._link.broken:
            raise AndroidTransportClosedError("The in-memory link is broken.")
        self._open = True

    async def close(self) -> None:
        self._open = False

    async def send(self, payload: bytes) -> None:
        """Hand a frame to the peer. Raises when the link is down."""
        if not isinstance(payload, (bytes, bytearray)):
            raise AndroidTransportError("Only bytes can be sent.")
        if not self._open:
            raise AndroidTransportClosedError("The transport is not open.")
        if self._link.broken:
            raise AndroidTransportClosedError("The link to the device is broken.")
        if self.latency:
            await asyncio.sleep(self.latency)
            if self._link.broken:
                raise AndroidTransportClosedError("The link dropped mid-send.")
        self.sent.append(bytes(payload))
        self._link.delivered.append((self._own, bytes(payload)))
        await self._link.inboxes[self._peer].queue().put(bytes(payload))

    async def receive(self, timeout: float = DEFAULT_RECEIVE_TIMEOUT) -> Optional[bytes]:
        """Wait for the next frame, or ``None`` when nothing arrives in time."""
        if not self._open:
            return None
        try:
            return await asyncio.wait_for(self._link.inboxes[self._own].queue().get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    def pending(self) -> int:
        """Frames waiting in this end's inbox."""
        return self._link.inboxes[self._own].queue().qsize()

    # ------------------------------------------------------------------
    # Test knobs
    # ------------------------------------------------------------------
    def break_link(self) -> None:
        """Simulate the device disappearing (Wi-Fi off, out of range)."""
        self._link.broken = True

    def restore_link(self) -> None:
        self._link.broken = False

    def describe(self) -> Dict[str, Any]:
        return {
            "transport": self.name,
            "open": self.is_open,
            "pending_frames": self.pending(),
            "frames_sent": len(self.sent),
            "broken": self._link.broken,
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return f"<InMemoryAndroidTransport {self.name} open={self.is_open}>"


def transport_created_at() -> str:
    """Timestamp helper kept here so transports can stamp their own logs."""
    return utcnow().isoformat()
