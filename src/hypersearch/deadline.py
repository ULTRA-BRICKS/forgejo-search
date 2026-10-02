"""One request budget shared by HTTP, authorization and search workers."""

import time
from contextlib import contextmanager
from contextvars import ContextVar
from threading import Event

_current = ContextVar("search_deadline", default=None)


class RequestTimeout(TimeoutError):
    pass


def remaining(cap):
    deadline = _current.get()
    if deadline is None:
        return cap
    deadline, cancelled = deadline
    if cancelled.is_set():
        raise RequestTimeout("Search request was cancelled")
    left = deadline - time.monotonic()
    if left <= 0:
        raise RequestTimeout("Search request deadline exceeded")
    return min(cap, left)


def check():
    remaining(float("inf"))


def active():
    return _current.get() is not None


def expired():
    deadline = _current.get()
    return deadline is not None and (deadline[1].is_set() or time.monotonic() >= deadline[0])


@contextmanager
def request_deadline(deadline):
    cancelled = Event()
    token = _current.set((deadline, cancelled))
    try:
        check()
        yield
    finally:
        cancelled.set()
        _current.reset(token)
