"""Per-request monotonic deadline and cancellation, carried in a context variable.

One `RequestContext` spans a search request: admission, identity, listing, code
probes, search and output. Waiters bound their waits by `remaining()` and register a
wake-up with `on_cancel`, so cancellation interrupts condition waits without polling.

The variable is deliberately NOT inherited by plain pool threads: shared work (one
future several viewers wait on) must not adopt a single viewer's deadline. Callers
that want a request-bound hop copy the context explicitly.
"""

from __future__ import annotations

import contextvars
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager


DEADLINE_REASON = "deadline_exceeded"


class RequestCancelled(Exception):
    """The request was abandoned (client gone, shutdown); not an upstream failure."""


class DeadlineExceeded(RequestCancelled):
    """The request's overall monotonic deadline elapsed."""


class RequestContext:
    def __init__(self, timeout: float | None = None):
        self.deadline = None if timeout is None else time.monotonic() + timeout
        self.reason: str | None = None
        self._cancelled = threading.Event()
        self._callbacks: list[Callable[[], None]] = []
        self._lock = threading.Lock()

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    def remaining(self) -> float | None:
        """Seconds left, floored at zero; None when the request has no deadline."""
        if self.deadline is None:
            return None
        return max(0.0, self.deadline - time.monotonic())

    def cancel(self, reason: str = "cancelled") -> None:
        with self._lock:
            if self._cancelled.is_set():
                return
            self.reason = reason
            self._cancelled.set()
            callbacks, self._callbacks = self._callbacks, []
        for callback in callbacks:
            callback()

    def on_cancel(self, callback: Callable[[], None]) -> Callable[[], None]:
        """Run `callback` once on cancellation; the returned function unregisters it."""
        with self._lock:
            if not self._cancelled.is_set():
                self._callbacks.append(callback)

                def remove() -> None:
                    with self._lock:
                        if callback in self._callbacks:
                            self._callbacks.remove(callback)

                return remove
        callback()
        return lambda: None

    def check(self) -> None:
        if self._cancelled.is_set():
            if self.reason == DEADLINE_REASON:
                raise DeadlineExceeded(DEADLINE_REASON)
            raise RequestCancelled(self.reason)
        if self.deadline is not None and time.monotonic() >= self.deadline:
            raise DeadlineExceeded(DEADLINE_REASON)

    def clamp(self, seconds: float) -> float:
        """Bound an I/O wait by the remaining budget; raises if none is left."""
        self.check()
        remaining = self.remaining()
        return seconds if remaining is None else min(seconds, remaining)


_current: contextvars.ContextVar[RequestContext | None] = contextvars.ContextVar(
    "hypersearch_request", default=None
)


def current() -> RequestContext | None:
    return _current.get()


@contextmanager
def bound(context: RequestContext) -> Iterator[RequestContext]:
    token = _current.set(context)
    try:
        yield context
    finally:
        _current.reset(token)


def checkpoint() -> None:
    """Raise if the bound request is cancelled or out of time; no-op when unbound."""
    context = _current.get()
    if context is not None:
        context.check()


def clamp(seconds: float) -> float:
    context = _current.get()
    return seconds if context is None else context.clamp(seconds)
