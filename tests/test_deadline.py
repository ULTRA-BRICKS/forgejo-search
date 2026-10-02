"""Per-request monotonic deadline and cancellation context."""

import concurrent.futures
import threading

import pytest

from hypersearch import deadline
from hypersearch.deadline import DeadlineExceeded, RequestCancelled, RequestContext


def test_deadline_follows_the_monotonic_clock(monkeypatch):
    now = [100.0]
    monkeypatch.setattr("hypersearch.deadline.time.monotonic", lambda: now[0])
    context = RequestContext(5)
    assert context.remaining() == 5
    now[0] = 103
    assert context.remaining() == 2
    context.check()
    now[0] = 105
    assert context.remaining() == 0
    with pytest.raises(DeadlineExceeded):
        context.check()
    # Wall-clock jumps must not matter: only the monotonic clock is consulted.
    monkeypatch.setattr("hypersearch.deadline.time.time", lambda: 0, raising=False)
    assert context.remaining() == 0


def test_cancel_wakes_registered_waiters_once_and_is_idempotent():
    context = RequestContext(60)
    woken = []
    context.on_cancel(lambda: woken.append("a"))
    context.on_cancel(lambda: woken.append("b"))
    context.cancel("client_disconnected")
    context.cancel("again")
    assert woken == ["a", "b"]
    assert context.cancelled
    assert context.reason == "client_disconnected"
    with pytest.raises(RequestCancelled) as raised:
        context.check()
    assert not isinstance(raised.value, DeadlineExceeded)


def test_callback_registered_after_cancel_fires_immediately_and_removal_works():
    context = RequestContext(60)
    removed = []
    remove = context.on_cancel(lambda: removed.append("never"))
    remove()
    context.cancel("x")
    assert removed == []
    late = []
    context.on_cancel(lambda: late.append(1))
    assert late == [1]


def test_clamp_bounds_socket_waits_by_the_remaining_budget(monkeypatch):
    now = [10.0]
    monkeypatch.setattr("hypersearch.deadline.time.monotonic", lambda: now[0])
    context = RequestContext(3)
    assert context.clamp(2.0) == 2.0
    now[0] = 12.5
    assert context.clamp(2.0) == pytest.approx(0.5)
    now[0] = 13
    with pytest.raises(DeadlineExceeded):
        context.clamp(2.0)


def test_unbounded_context_never_expires_but_can_be_cancelled():
    context = RequestContext(None)
    assert context.remaining() is None
    assert context.clamp(7.0) == 7.0
    context.cancel("shutdown")
    with pytest.raises(RequestCancelled):
        context.check()


def test_bound_context_is_visible_only_to_its_own_thread_of_control():
    assert deadline.current() is None
    context = RequestContext(5)
    with deadline.bound(context):
        assert deadline.current() is context
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            # A plain pool thread does not inherit the request: shared work must
            # never silently adopt one viewer's deadline.
            assert pool.submit(deadline.current).result() is None
    assert deadline.current() is None


def test_module_helpers_are_noops_without_a_bound_context():
    deadline.checkpoint()
    assert deadline.clamp(1.5) == 1.5
    context = RequestContext(5)
    context.cancel("x")
    with deadline.bound(context):
        with pytest.raises(RequestCancelled):
            deadline.checkpoint()


def test_cancel_from_another_thread_is_visible_immediately():
    context = RequestContext(30)
    seen = threading.Event()
    threading.Timer(0.05, lambda: context.cancel("c")).start()
    context.on_cancel(seen.set)
    assert seen.wait(1)
    assert context.cancelled
