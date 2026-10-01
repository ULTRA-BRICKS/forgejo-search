"""Auth boundary regressions: unavailable is neither anonymous nor a code deny."""

import urllib.error

import pytest

from hypersearch.auth import ForgejoAuth, VisibilityUnavailable


def payload(names=()):
    return {"ok": True, "data": [{"repository": {"full_name": n}} for n in names]}


@pytest.mark.parametrize("failure", [TimeoutError(), urllib.error.HTTPError("/repo/search", 503, "unavailable", {}, None)])
def test_outage_backoff_expires_and_recovers_without_anonymous_state(monkeypatch, failure):
    now = [100.0]
    monkeypatch.setattr("hypersearch.auth.time.monotonic", lambda: now[0])
    auth = ForgejoAuth()
    calls = []

    def fetch(path, cookie):
        calls.append(path)
        if now[0] < 106:
            raise failure
        return payload()

    monkeypatch.setattr(auth, "_get", fetch)
    for _ in range(10):
        with pytest.raises(VisibilityUnavailable):
            auth.visible_repositories("session=test")
    assert len(calls) == 1
    now[0] = 106
    assert auth.visible_repositories("session=test") == (True, set())
    assert len(calls) == 2


@pytest.mark.parametrize("location", ["/forgejo/user/login?redirect_to=x", "https://git.hyperide.ai/forgejo/user/login"])
def test_app_sub_url_login_redirect_is_anonymous(monkeypatch, location):
    auth = ForgejoAuth(base="http://127.0.0.1:3000/forgejo")

    def fetch(path, cookie):
        raise urllib.error.HTTPError(path, 302, "login", {"Location": location}, None)

    monkeypatch.setattr(auth, "_get", fetch)
    assert auth.visible_repositories("session=test") == (False, set())


@pytest.mark.parametrize("location", ["https://foreign.test/user/login", "//foreign.test/user/login", "https://git.hyperide.ai@foreign.test/user/login"])
def test_foreign_login_redirect_is_unavailable(monkeypatch, location):
    auth = ForgejoAuth()

    def fetch(path, cookie):
        raise urllib.error.HTTPError(path, 302, "login", {"Location": location}, None)

    monkeypatch.setattr(auth, "_get", fetch)
    with pytest.raises(VisibilityUnavailable):
        auth.visible_repositories("session=test")


@pytest.mark.parametrize("revoked", [True, False])
def test_bare_404_rechecks_identity_before_caching_a_deny(monkeypatch, revoked):
    auth = ForgejoAuth()
    valid = [True]

    def fetch(path, cookie):
        if not valid[0]:
            raise urllib.error.HTTPError(path, 302, "login", {"Location": "/user/login"}, None)
        return payload(["acme/private"] if "page=1" in path else [])

    monkeypatch.setattr(auth, "_get", fetch)
    monkeypatch.setattr(auth, "_head", lambda path, cookie: 200)
    assert auth.visible_repositories("session=test") == (True, {"acme/private"})
    assert auth.code_readable_repositories("session=test", {"acme/other"}) == {"acme/other"}
    valid[0] = not revoked

    def denied(path, cookie):
        raise urllib.error.HTTPError(path, 404, "not found", {}, None)

    monkeypatch.setattr(auth, "_head", denied)
    if revoked:
        with pytest.raises(VisibilityUnavailable):
            auth.code_readable_repositories("session=test", {"acme/private"})
        assert auth.visible_repositories("session=test") == (False, set())
        with pytest.raises(VisibilityUnavailable):
            auth.code_readable_repositories("session=test", {"acme/other"})
    else:
        assert auth.code_readable_repositories("session=test", {"acme/private"}) == set()


def test_code_grant_ttl_starts_before_probe_not_after_slow_response(monkeypatch):
    now = [100.0]
    monkeypatch.setattr("hypersearch.auth.time.monotonic", lambda: now[0])
    auth = ForgejoAuth(ttl=30)
    calls = []

    def probe(path, cookie):
        calls.append(path)
        now[0] += 5
        return 200

    monkeypatch.setattr(auth, "_head", probe)
    assert auth.code_readable_repositories("session=test", {"acme/code"}) == {"acme/code"}
    now[0] = 131
    assert auth.code_readable_repositories("session=test", {"acme/code"}) == {"acme/code"}
    assert len(calls) == 2


@pytest.mark.parametrize("status", [401, 403, 405, 500])
def test_non_success_probe_status_never_becomes_cached_deny(monkeypatch, status):
    auth = ForgejoAuth()
    monkeypatch.setattr(auth, "_head", lambda path, cookie: status)
    with pytest.raises(VisibilityUnavailable):
        auth.code_readable_repositories("session=test", {"acme/code"})


def test_probe_concurrency_bound_is_shared_across_sessions(monkeypatch):
    import concurrent.futures
    import threading

    auth = ForgejoAuth()
    entered = threading.Event()
    release = threading.Event()
    guard = threading.Lock()
    active = [0, 0]

    def probe(path, cookie):
        with guard:
            active[0] += 1
            active[1] = max(active)
            if active[0] >= 8:
                entered.set()
        release.wait(2)
        with guard:
            active[0] -= 1
        return 200

    monkeypatch.setattr(auth, "_head", probe)
    repos = {f"acme/r{i}" for i in range(16)}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as callers:
        futures = [callers.submit(auth.code_readable_repositories, f"session={i}", repos) for i in range(3)]
        try:
            assert entered.wait(1)
            # Hold all active probes while other sessions contend for admission.
            threading.Event().wait(0.05)
        finally:
            release.set()
        assert [f.result() for f in futures] == [repos] * 3
    assert active[1] <= 8


@pytest.mark.parametrize("option,value", [
    ("code_probe_budget", 0), ("code_probe_budget", float("nan")),
    ("code_probe_budget", float("inf")), ("code_probe_budget", 121),
    ("request_timeout", -1), ("request_timeout", float("nan")),
    ("code_cache_max_entries", 0), ("code_cache_max_entries", 1_000_001),
])
def test_invalid_probe_configuration_is_rejected(option, value):
    with pytest.raises(ValueError):
        ForgejoAuth(**{option: value})


def test_malformed_redirect_authority_is_unavailable_not_handler_crash(monkeypatch):
    auth = ForgejoAuth()

    def fetch(path, cookie):
        raise urllib.error.HTTPError(path, 302, "broken redirect", {"Location": "http://[invalid/user/login"}, None)

    monkeypatch.setattr(auth, "_get", fetch)
    with pytest.raises(VisibilityUnavailable):
        auth.visible_repositories("session=test")


@pytest.mark.parametrize("mode", ["slow-response", "fanout", "cached-grant"])
def test_expired_grants_never_authorize_current_request(monkeypatch, mode):
    now = [100.0]
    monkeypatch.setattr("hypersearch.auth.time.monotonic", lambda: now[0])
    auth = ForgejoAuth(ttl=30, code_probe_budget=120, code_probe_concurrency=1)

    def probe(path, cookie):
        now[0] += 40 if mode == "slow-response" else 20
        return 200

    monkeypatch.setattr(auth, "_head", probe)
    if mode == "cached-grant":
        assert auth.code_readable_repositories("session=test", {"acme/a"}) == {"acme/a"}
        now[0] = 125
    repos = {"acme/a"} if mode == "slow-response" else {"acme/a", "acme/b"}
    with pytest.raises(VisibilityUnavailable):
        auth.code_readable_repositories("session=test", repos)


@pytest.mark.parametrize("forget", ["expiry", "eviction"])
@pytest.mark.parametrize("source", ["code", "pagination"])
def test_delayed_probe_cannot_resurrect_observed_revocation(monkeypatch, forget, source):
    import concurrent.futures
    import threading

    now = [100.0]
    monkeypatch.setattr("hypersearch.auth.time.monotonic", lambda: now[0])
    auth = ForgejoAuth(max_entries=1)
    entered = threading.Event()
    release = threading.Event()

    def probe(path, cookie):
        if path == "/acme/slow/search":
            entered.set()
            assert release.wait(2)
            return 200
        return 401

    monkeypatch.setattr(auth, "_head", probe)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as callers:
        delayed = callers.submit(auth.code_readable_repositories, "session=test", {"acme/slow"})
        try:
            assert entered.wait(1)
            with pytest.raises(VisibilityUnavailable):
                if source == "code":
                    auth.code_readable_repositories("session=test", {"acme/revoked"})
                else:
                    def fetch(path, cookie):
                        if "page=1" in path:
                            return payload(["acme/slow"])
                        raise urllib.error.HTTPError(path, 401, "login", {}, None)

                    monkeypatch.setattr(auth, "_get", fetch)
                    auth.visible_repositories("session=test")
            if forget == "expiry":
                now[0] = 106
            else:
                monkeypatch.setattr(auth, "_get", lambda path, cookie: payload())
                assert auth.visible_repositories("session=other") == (True, set())
        finally:
            release.set()
        with pytest.raises(VisibilityUnavailable):
            delayed.result(timeout=2)


def test_duplicate_searches_leave_capacity_for_another_session(monkeypatch):
    import concurrent.futures
    import threading

    auth = ForgejoAuth(code_probe_concurrency=2, code_probe_budget=1)
    entered = threading.Event()
    release = threading.Event()
    calls = []

    def probe(path, cookie):
        calls.append(cookie)
        if cookie == "session=slow":
            entered.set()
            assert release.wait(2)
        return 200

    monkeypatch.setattr(auth, "_head", probe)
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as callers:
        first = callers.submit(auth.code_readable_repositories, "session=slow", {"acme/code"})
        assert entered.wait(1)
        duplicate = callers.submit(auth.code_readable_repositories, "session=slow", {"acme/code"})
        threading.Event().wait(0.05)
        other = callers.submit(auth.code_readable_repositories, "session=fast", {"acme/code"})
        try:
            assert other.result(timeout=0.5) == {"acme/code"}
        finally:
            release.set()
        assert first.result() == duplicate.result() == {"acme/code"}
    assert calls.count("session=slow") == 1


def test_released_capacity_admits_pending_work_before_slow_probe_finishes(monkeypatch):
    import concurrent.futures
    import threading

    auth = ForgejoAuth(code_probe_concurrency=2, code_probe_budget=2)
    first_entered = threading.Event()
    slow_entered = threading.Event()
    fast_entered = threading.Event()
    first_release = threading.Event()
    slow_release = threading.Event()

    def probe(path, cookie):
        if cookie == "session=first":
            first_entered.set()
            assert first_release.wait(2)
        elif path == "/acme/a/search":
            slow_entered.set()
            assert slow_release.wait(2)
        else:
            fast_entered.set()
        return 200

    monkeypatch.setattr(auth, "_head", probe)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as callers:
        first = callers.submit(auth.code_readable_repositories, "session=first", {"acme/code"})
        assert first_entered.wait(1)
        second = callers.submit(auth.code_readable_repositories, "session=second", {"acme/a", "acme/b"})
        try:
            assert slow_entered.wait(1)
            first_release.set()
            assert first.result(timeout=1) == {"acme/code"}
            assert fast_entered.wait(0.5)
        finally:
            first_release.set()
            slow_release.set()
        assert second.result(timeout=1) == {"acme/a", "acme/b"}


def test_code_outage_retries_do_not_extend_backoff(monkeypatch):
    now = [100.0]
    monkeypatch.setattr("hypersearch.auth.time.monotonic", lambda: now[0])
    auth = ForgejoAuth()
    calls = []

    def probe(path, cookie):
        calls.append(now[0])
        if len(calls) == 1:
            raise TimeoutError()
        return 200

    monkeypatch.setattr(auth, "_head", probe)
    for tick in [100, 101, 102, 104]:
        now[0] = tick
        with pytest.raises(VisibilityUnavailable):
            auth.code_readable_repositories("session=test", {"acme/code"})
    now[0] = 105
    assert auth.code_readable_repositories("session=test", {"acme/code"}) == {"acme/code"}
    assert calls == [100, 105]


def test_visibility_expiring_during_pagination_is_unavailable(monkeypatch):
    now = [100.0]
    monkeypatch.setattr("hypersearch.auth.time.monotonic", lambda: now[0])
    auth = ForgejoAuth()

    def fetch(path, cookie):
        if "page=1" in path:
            return payload(["acme/secret"])
        now[0] = 135
        return payload()

    monkeypatch.setattr(auth, "_get", fetch)
    with pytest.raises(VisibilityUnavailable):
        auth.visible_repositories("session=test")


def test_visibility_response_cannot_resurrect_concurrent_logout(monkeypatch):
    now = [100.0]
    monkeypatch.setattr("hypersearch.auth.time.monotonic", lambda: now[0])
    auth = ForgejoAuth()
    monkeypatch.setattr(auth, "_head", lambda path, cookie: 401)

    def fetch(path, cookie):
        if "page=1" in path:
            with pytest.raises(VisibilityUnavailable):
                auth.code_readable_repositories(cookie, {"acme/secret"})
            now[0] = 106
            return payload(["acme/secret"])
        return payload()

    monkeypatch.setattr(auth, "_get", fetch)
    with pytest.raises(VisibilityUnavailable):
        auth.visible_repositories("session=test")


def test_backoff_expiring_during_error_propagation_does_not_restart(monkeypatch):
    now = [100.0]
    monkeypatch.setattr("hypersearch.auth.time.monotonic", lambda: now[0])
    auth = ForgejoAuth()

    def fail(path, cookie):
        raise TimeoutError()

    monkeypatch.setattr(auth, "_head", fail)
    with pytest.raises(VisibilityUnavailable):
        auth.code_readable_repositories("session=test", {"acme/code"})
    clock = iter([104.999, 105.001])
    monkeypatch.setattr("hypersearch.auth.time.monotonic", lambda: next(clock, 105.001))
    with pytest.raises(VisibilityUnavailable):
        auth.code_readable_repositories("session=test", {"acme/code"})
    monkeypatch.setattr("hypersearch.auth.time.monotonic", lambda: 106)
    monkeypatch.setattr(auth, "_head", lambda path, cookie: 200)
    assert auth.code_readable_repositories("session=test", {"acme/code"}) == {"acme/code"}


def test_cache_filled_after_initial_miss_needs_no_worker_slot(monkeypatch):
    import concurrent.futures
    import threading
    import time

    auth = ForgejoAuth(code_probe_concurrency=1)
    paused = threading.Event()
    resume = threading.Event()
    occupied = threading.Event()
    release = threading.Event()
    real_clock = time.monotonic

    def clock():
        if threading.current_thread().name.startswith("cache-wait") and not paused.is_set():
            paused.set()
            assert resume.wait(2)
        return real_clock()

    def probe(path, cookie):
        if cookie == "session=other":
            occupied.set()
            assert release.wait(2)
        return 200

    monkeypatch.setattr("hypersearch.auth.time.monotonic", clock)
    monkeypatch.setattr(auth, "_head", probe)
    with (
        concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="cache-wait") as waiting,
        concurrent.futures.ThreadPoolExecutor(max_workers=1) as callers,
    ):
        request = waiting.submit(auth.code_readable_repositories, "session=test", {"acme/code"})
        try:
            assert paused.wait(1)
            assert auth.code_readable_repositories("session=test", {"acme/code"}) == {"acme/code"}
            other = callers.submit(auth.code_readable_repositories, "session=other", {"acme/code"})
            assert occupied.wait(1)
            resume.set()
            assert request.result(timeout=0.5) == {"acme/code"}
        finally:
            resume.set()
            release.set()
        assert other.result(timeout=1) == {"acme/code"}


def test_close_releases_retained_worker_pool(monkeypatch):
    import threading

    auth = ForgejoAuth()
    workers = []

    def probe(path, cookie):
        workers.append(threading.current_thread())
        return 200

    monkeypatch.setattr(auth, "_head", probe)
    assert auth.code_readable_repositories("session=test", {"acme/code"}) == {"acme/code"}
    auth.close()
    assert all(not worker.is_alive() for worker in workers)
    auth.close()
    with pytest.raises(VisibilityUnavailable):
        auth.code_readable_repositories("session=test", {"acme/other"})


def test_delayed_failed_future_does_not_restart_expired_backoff(monkeypatch):
    failed = [False]
    clock_reads = [0]
    auth = ForgejoAuth()

    def clock():
        if failed[0]:
            clock_reads[0] += 1
            return 100.0 if clock_reads[0] == 1 else 106.0
        return 100.0

    def probe(path, cookie):
        if not failed[0]:
            failed[0] = True
            raise TimeoutError()
        return 200

    monkeypatch.setattr("hypersearch.auth.time.monotonic", clock)
    monkeypatch.setattr(auth, "_head", probe)
    with pytest.raises(VisibilityUnavailable):
        auth.code_readable_repositories("session=test", {"acme/code"})
    assert auth.code_readable_repositories("session=test", {"acme/code"}) == {"acme/code"}


def test_waiting_searches_observe_new_code_backoff(monkeypatch):
    import concurrent.futures
    import threading
    import time

    auth = ForgejoAuth(code_probe_concurrency=1)
    entered = threading.Event()
    queued = threading.Event()
    release = threading.Event()
    calls = []
    real_clock = time.monotonic

    def clock():
        if threading.current_thread().name.startswith("queued"):
            queued.set()
        return real_clock()

    def probe(path, cookie):
        calls.append(path)
        entered.set()
        assert release.wait(2)
        raise TimeoutError()

    monkeypatch.setattr("hypersearch.auth.time.monotonic", clock)
    monkeypatch.setattr(auth, "_head", probe)
    with (
        concurrent.futures.ThreadPoolExecutor(max_workers=1) as first_pool,
        concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="queued") as waiting,
    ):
        first = first_pool.submit(auth.code_readable_repositories, "session=test", {"acme/a"})
        try:
            assert entered.wait(1)
            second = waiting.submit(auth.code_readable_repositories, "session=test", {"acme/b"})
            assert queued.wait(1)
        finally:
            release.set()
        for future in [first, second]:
            with pytest.raises(VisibilityUnavailable):
                future.result(timeout=1)
    assert calls == ["/acme/a/search"]
