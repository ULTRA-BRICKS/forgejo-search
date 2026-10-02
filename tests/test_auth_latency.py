"""Avoidable upstream work: cheap identity, parallel listing, coalesced denials, scope, cancellation.

Every test runs the real ForgejoAuth transport against the loopback Forgejo double so
request counts, concurrency and ordering are observed on the wire, not stubbed.
"""

import concurrent.futures
import threading
import time

import pytest
from fake_forgejo import FakeForgejo

from hypersearch.auth import ForgejoAuth, VisibilityUnavailable

COOKIE = "session=alice"


def names(count, owner="acme"):
    return [f"{owner}/r{index:04d}" for index in range(count)]


@pytest.fixture
def make():
    created = []

    def build(fake_kwargs=None, **auth_kwargs):
        fake = FakeForgejo(**(fake_kwargs or {}))
        auth_kwargs.setdefault("ttl", 30)
        auth = ForgejoAuth(fake.base, **auth_kwargs)
        created.append((fake, auth))
        return fake, auth

    yield build
    for fake, auth in created:
        auth.close()
        fake.close()


def test_session_only_readiness_never_enumerates_repositories(make):
    fake, auth = make({"visible": names(750), "count_delay": 0.01})
    assert auth.session_authenticated(COOKIE) is True
    assert fake.count("list") == 0
    assert fake.count("identity") == 1
    assert auth.session_authenticated(COOKIE) is True
    assert fake.count("identity") == 1
    assert auth.session_authenticated("session=stranger") is False
    assert fake.count("list") == 0


def test_readiness_failure_is_unavailable_and_backed_off_without_anonymous_state(make):
    fake, auth = make({"visible": names(3)})

    def failing(handler):
        fake._record("identity", "failing")
        handler._send(500)

    fake.server.RequestHandlerClass.do_GET = failing
    with pytest.raises(VisibilityUnavailable):
        auth.session_authenticated(COOKIE)
    assert fake.count("identity") == 1
    with pytest.raises(VisibilityUnavailable):
        auth.session_authenticated(COOKIE)
    assert fake.count("identity") == 1  # the backoff answered without upstream work
    assert not auth.cache


def test_concurrent_readiness_is_single_flight(make):
    fake, auth = make({"visible": names(10), "count_delay": 0.1})
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: auth.session_authenticated(COOKIE), range(8)))
    assert results == [True] * 8
    assert fake.count("identity") == 1


def test_readiness_identity_does_not_replace_a_full_allowlist(make):
    fake, auth = make({"visible": names(120)})
    assert auth.session_authenticated(COOKIE) is True
    authenticated, repos = auth.visible_repositories(COOKIE)
    assert authenticated is True
    assert repos == set(names(120))
    assert fake.count("list") >= 3


def test_sixteen_pages_are_fetched_in_parallel_without_losing_a_repository(make):
    # 750 visible repositories = 15 full pages + the terminating empty page = 16 requests.
    fake, auth = make({"visible": names(750), "page_delay": 0.2})
    started = time.perf_counter()
    authenticated, repos = auth.visible_repositories(COOKIE)
    elapsed = time.perf_counter() - started
    assert authenticated is True
    assert repos == set(names(750))
    assert fake.count("list") == 16
    assert elapsed < 1.4  # sequential would be 16 * 0.2 = 3.2s
    assert 1 < fake.peak <= 8


def test_visibility_concurrency_one_keeps_the_sequential_walk(make):
    fake, auth = make({"visible": names(150), "page_delay": 0.02}, visibility_concurrency=1)
    assert auth.visible_repositories(COOKIE)[1] == set(names(150))
    assert fake.peak == 1
    assert [detail for _, kind, detail in fake.events if kind == "list"] == [
        "page=1 q=", "page=2 q=", "page=3 q=", "page=4 q="
    ]


def test_missing_total_header_falls_back_to_sequential_pagination(make):
    fake, auth = make({"visible": names(150), "total_header": False, "page_delay": 0.02})
    assert auth.visible_repositories(COOKIE)[1] == set(names(150))
    assert fake.peak == 1


def test_understated_total_still_confirms_completeness_with_an_empty_page(make):
    # The advertised count only schedules requests; completeness is "walk to an empty page".
    _fake, auth = make({"visible": names(230), "total_override": 40})
    assert auth.visible_repositories(COOKIE)[1] == set(names(230))


def test_overstated_total_stays_inside_the_pagination_safety_bound(make):
    fake, auth = make({"visible": names(120), "total_override": 10_000_000})
    assert auth.visible_repositories(COOKIE)[1] == set(names(120))
    pages = {int(detail.split()[0].split("=")[1]) for _, kind, detail in fake.events if kind == "list"}
    assert max(pages) <= 21


def test_more_than_the_safety_bound_still_fails_closed_in_parallel(make):
    _fake, auth = make({"visible": names(1100), "page_delay": 0.01})
    with pytest.raises(VisibilityUnavailable):
        auth.visible_repositories(COOKIE)
    assert not auth.cache


def test_session_revoked_while_parallel_pages_are_in_flight_is_unavailable_and_uncached(make):
    fake, auth = make({"visible": names(750), "page_delay": 0.15})
    threading.Timer(0.2, fake.revoke).start()
    with pytest.raises(VisibilityUnavailable):
        auth.visible_repositories(COOKIE)
    # Never downgraded to anonymous mid-listing; the outage backoff answers without upstream work.
    listed = fake.count("list")
    with pytest.raises(VisibilityUnavailable):
        auth.visible_repositories(COOKIE)
    assert fake.count("list") == listed


def test_grant_lifetime_is_measured_from_walk_start_in_parallel(make):
    _fake, auth = make({"visible": names(750), "page_delay": 0.2}, ttl=0.3)
    with pytest.raises(VisibilityUnavailable):
        auth.visible_repositories(COOKIE)
    assert not auth.cache


def test_one_identity_confirmation_covers_every_denial_of_a_call(make):
    fake, auth = make(
        {"visible": names(60), "readable": [], "head_delay": 0.01, "count_delay": 0.05}
    )
    assert auth.code_readable_repositories(COOKIE, set(names(60))) == set()
    assert fake.count("head") == 60
    assert fake.count("list") == 0  # no full page-1 listing per denial
    assert fake.count("identity") == 1
    # Denials were cached only after that confirmation: a repeat call needs no request.
    before = fake.counts()
    assert auth.code_readable_repositories(COOKIE, set(names(60))) == set()
    assert fake.counts() == before


def test_the_confirmation_is_issued_after_the_newest_denial_of_the_call(make):
    fake, auth = make(
        {"visible": names(4), "readable": [], "head_delay": 0.02}, code_probe_concurrency=1
    )
    assert auth.code_readable_repositories(COOKIE, set(names(4))) == set()
    events = list(fake.events)
    newest_denial = max(seq for seq, kind, _ in events if kind == "head404-sent")
    identity = [seq for seq, kind, _ in events if kind == "identity"]
    assert len(identity) == 1 and identity[0] > newest_denial


def test_a_logout_explaining_a_late_404_is_caught_by_the_single_confirmation(make):
    fake, auth = make(
        {"visible": ["acme/a-quick", "acme/z-slow"], "readable": [], "anonymous_head_status": 404},
        code_probe_concurrency=2,
    )
    gate = threading.Event()
    fake.head_gates["acme/z-slow"] = gate
    fake.head_hooks["acme/z-slow"] = fake.revoke  # the session dies right before this 404
    outcome: dict = {}

    def run():
        try:
            outcome["value"] = auth.code_readable_repositories(
                COOKIE, {"acme/a-quick", "acme/z-slow"}
            )
        except VisibilityUnavailable as error:
            outcome["error"] = error

    worker = threading.Thread(target=run)
    worker.start()
    end = time.monotonic() + 2
    while fake.count("head404-sent") < 1 and time.monotonic() < end:
        time.sleep(0.01)
    assert fake.count("identity") == 0  # the quick 404 alone triggers nothing yet
    gate.set()
    worker.join(5)
    assert "error" in outcome, "a denial explained by a logout must never be cached"
    assert not auth._code_cache
    assert fake.count("identity") == 1


def test_a_confirmation_issued_before_another_requests_denial_is_never_reused(make):
    fake, auth = make(
        {"visible": ["acme/a-quick", "acme/z-slow"], "readable": [], "anonymous_head_status": 404}
    )
    fake.identity_hold = threading.Event()
    gate = threading.Event()
    fake.head_gates["acme/z-slow"] = gate
    fake.head_hooks["acme/z-slow"] = fake.revoke
    outcomes: dict = {}

    def run(name, repo):
        try:
            outcomes[name] = auth.code_readable_repositories(COOKIE, {repo})
        except VisibilityUnavailable as error:
            outcomes[name] = error

    first = threading.Thread(target=run, args=("first", "acme/a-quick"))
    second = threading.Thread(target=run, args=("second", "acme/z-slow"))
    first.start()
    second.start()
    # The first request's confirmation is issued (and answered "signed in") but held in
    # flight; only then does the second request receive its 404, after the logout.
    assert fake.identity_entered.wait(2)
    gate.set()
    end = time.monotonic() + 2
    while fake.count("head404-sent") < 2 and time.monotonic() < end:
        time.sleep(0.01)
    fake.identity_hold.set()
    first.join(5)
    second.join(5)
    assert isinstance(outcomes["second"], VisibilityUnavailable)
    assert auth._code_key(COOKIE, "acme/z-slow") not in auth._code_cache
    assert fake.count("identity") == 2


def test_repo_scope_uses_a_native_keyword_query_and_never_the_full_listing(make):
    visible = [*names(300), "acme/open", "other/open", "acme/opener"]
    fake, auth = make({"visible": visible})
    authenticated, repos = auth.visible_repositories(COOKIE, repo="Acme/Open")
    assert authenticated is True
    assert "acme/open" in repos  # case-insensitive exact candidate is guaranteed present
    assert repos <= set(visible)
    assert fake.count("list") == 0
    assert fake.count("scoped") >= 1
    assert all(detail.endswith("q=open") for _, kind, detail in fake.events if kind == "scoped")
    requests = fake.count("scoped")
    assert auth.visible_repositories(COOKIE, repo="acme/open") == (authenticated, repos)
    assert fake.count("scoped") == requests


def test_repo_scope_prefers_a_fresh_full_allowlist_without_network(make):
    fake, auth = make({"visible": [*names(60), "acme/open"]})
    _, full = auth.visible_repositories(COOKIE)
    calls = fake.counts()
    assert auth.visible_repositories(COOKIE, repo="acme/open") == (True, full)
    assert fake.counts() == calls


@pytest.mark.parametrize("repo", ["acme/caf\u00e9", "open", "acme/..", "a/b/c", "acme/op en"])
def test_unsafe_repo_scope_values_fall_back_to_the_complete_listing(make, repo):
    fake, auth = make({"visible": [*names(60), "acme/open"]})
    assert auth.visible_repositories(COOKIE, repo=repo) == (True, {*names(60), "acme/open"})
    assert fake.count("scoped") == 0
    assert fake.count("list") >= 1


def test_scoped_allowlist_does_not_survive_observed_revocation(make):
    fake, auth = make(
        {"visible": ["acme/open"], "anonymous_head_status": 302}
    )
    assert auth.visible_repositories(COOKIE, repo="acme/open")[0] is True
    fake.revoke()
    with pytest.raises(VisibilityUnavailable):
        auth.code_readable_repositories(COOKIE, {"acme/open"})
    before = fake.counts()
    assert auth.visible_repositories(COOKIE, repo="acme/open") == (False, set())
    assert fake.counts() == before


def test_expired_context_stops_listing_without_poisoning_the_session(make):
    from hypersearch.deadline import DeadlineExceeded, RequestContext, bound

    _fake, auth = make({"visible": names(750), "page_delay": 0.4})
    with bound(RequestContext(0.15)), pytest.raises(DeadlineExceeded):
        auth.visible_repositories(COOKIE)
    # A deadline is the caller's problem, not an upstream outage: no 5 second backoff.
    assert auth.visible_repositories(COOKIE)[1] == set(names(750))


def test_cancelled_leader_does_not_fail_a_follower_that_still_needs_the_listing(make):
    from hypersearch.deadline import RequestCancelled, RequestContext, bound

    _fake, auth = make({"visible": names(150), "page_delay": 0.3}, visibility_concurrency=1)
    leader_context = RequestContext(30)
    results: dict = {}

    def leader():
        with bound(leader_context):
            try:
                auth.visible_repositories(COOKIE)
            except RequestCancelled as error:
                results["leader"] = error

    def follower():
        results["follower"] = auth.visible_repositories(COOKIE)

    lead = threading.Thread(target=leader)
    lead.start()
    time.sleep(0.1)
    follow = threading.Thread(target=follower)
    follow.start()
    time.sleep(0.1)
    leader_context.cancel("client_disconnected")
    lead.join(5)
    follow.join(10)
    assert isinstance(results["leader"], RequestCancelled)
    assert results["follower"] == (True, set(names(150)))


def test_cancellation_stops_scheduling_further_code_probes(make):
    from hypersearch.deadline import RequestCancelled, RequestContext, bound

    fake, auth = make(
        {"visible": names(60), "head_delay": 0.1}, code_probe_concurrency=2, code_probe_budget=30
    )
    context = RequestContext(30)
    threading.Timer(0.25, lambda: context.cancel("client_disconnected")).start()
    with bound(context), pytest.raises(RequestCancelled):
        auth.code_readable_repositories(COOKIE, set(names(60)))
    time.sleep(0.5)
    assert fake.count("head") <= 8


def test_a_shared_probe_survives_one_requester_cancelling(make):
    from hypersearch.deadline import RequestCancelled, RequestContext, bound

    fake, auth = make({"visible": ["acme/x"], "head_delay": 0.3})
    quitter = RequestContext(30)
    threading.Timer(0.1, lambda: quitter.cancel("client_disconnected")).start()
    outcome: dict = {}

    def quitting():
        with bound(quitter):
            try:
                auth.code_readable_repositories(COOKIE, {"acme/x"})
            except RequestCancelled as error:
                outcome["quit"] = error

    thread = threading.Thread(target=quitting)
    thread.start()
    time.sleep(0.05)
    assert auth.code_readable_repositories(COOKIE, {"acme/x"}) == {"acme/x"}
    thread.join(5)
    assert isinstance(outcome["quit"], RequestCancelled)
    assert fake.count("head") == 1


def test_close_joins_listing_workers(make):
    _fake, auth = make({"visible": names(200)})
    auth.visible_repositories(COOKIE)
    workers = [t for t in threading.enumerate() if t.name.startswith("forgejo-page")]
    assert workers
    auth.close()
    assert all(not worker.is_alive() for worker in workers)
    with pytest.raises(VisibilityUnavailable):
        auth.visible_repositories("session=other")


@pytest.mark.parametrize("value", [0, 65, -1, "x"])
def test_invalid_visibility_concurrency_is_rejected(value):
    with pytest.raises(ValueError):
        ForgejoAuth(visibility_concurrency=value)


def test_identity_requests_keep_the_app_sub_url_mount(make):
    fake, auth = make({"visible": names(5), "mount": "/forgejo"})
    assert auth.session_authenticated(COOKIE) is True
    assert auth.session_authenticated("session=stranger") is False
    assert fake.count("identity") == 2


def test_overstated_total_cannot_hide_a_logout_seen_on_a_later_page(make):
    # 120 repositories end at page 4, yet the advertised count makes pages up to 21 be
    # fetched; a login redirect on a page past the empty one is still an observed logout.
    _fake, auth = make({"visible": names(120), "total_override": 10_000_000, "logout_from_page": 10})
    assert auth.code_readable_repositories(COOKIE, {"acme/r0001"}) == {"acme/r0001"}
    assert auth._code_cache
    with pytest.raises(VisibilityUnavailable):
        auth.visible_repositories(COOKIE)
    assert not auth._code_cache  # the observed logout purged the cached grant
    assert all(not record[1] for record in auth.cache.values())


def test_visibility_concurrency_bounds_first_pages_of_different_sessions(make):
    cookies = tuple(f"session=user{index}" for index in range(6))
    fake, auth = make(
        {"visible": names(40), "cookies": cookies, "page_delay": 0.1}, visibility_concurrency=2
    )
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(auth.visible_repositories, cookies))
    assert all(result == (True, set(names(40))) for result in results)
    assert fake.peak <= 2  # every request here is a listing page


def test_visibility_concurrency_bounds_sequential_fallback_pages_too(make):
    cookies = tuple(f"session=user{index}" for index in range(4))
    fake, auth = make(
        {"visible": names(120), "cookies": cookies, "page_delay": 0.05, "total_header": False},
        visibility_concurrency=2,
    )
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(auth.visible_repositories, cookies))
    assert all(result == (True, set(names(120))) for result in results)
    assert fake.peak <= 2


def test_denial_confirmation_counts_against_the_code_probe_budget(make):
    _fake, auth = make(
        {"visible": names(1), "readable": [], "count_delay": 1.0}, code_probe_budget=0.3
    )
    started = time.perf_counter()
    with pytest.raises(VisibilityUnavailable) as raised:
        auth.code_readable_repositories(COOKIE, set(names(1)))
    assert time.perf_counter() - started < 0.9
    assert "probe budget" in str(raised.value)
    assert not auth._code_cache


def test_unconfirmed_denials_are_shared_with_an_overlapping_search_of_the_same_session(make):
    repos = set(names(40))
    fake, auth = make(
        {"visible": names(40), "readable": [], "head_delay": 0.05, "count_delay": 0.05},
        code_probe_concurrency=4,
    )
    outcomes: list = []

    def search():
        outcomes.append(auth.code_readable_repositories(COOKIE, repos))

    first = threading.Thread(target=search)
    first.start()
    time.sleep(0.2)  # several 404s are in, none is confirmed before the whole call ends
    second = threading.Thread(target=search)
    second.start()
    first.join(10)
    second.join(10)
    assert outcomes == [set(), set()]
    assert fake.count("head") == 40  # typing must not re-probe a repository per keystroke


def test_a_logout_seen_by_a_prefetched_page_revokes_even_if_a_sibling_page_errors(make):
    # Page 1 authenticates and advertises many pages; page 2 is a logout, page 3 a server error.
    fake, auth = make({"visible": names(300), "page_delay": 0.05})
    assert auth.code_readable_repositories(COOKIE, {"acme/r0001"}) == {"acme/r0001"}
    assert auth._code_cache
    fake.logout_from_page = 2
    original = fake.server.RequestHandlerClass.do_GET

    def flaky(handler):
        if "page=3" in handler.path:
            fake._record("list", "page=3 q=")
            return handler._send(500)
        return original(handler)

    fake.server.RequestHandlerClass.do_GET = flaky
    with pytest.raises(VisibilityUnavailable):
        auth.visible_repositories(COOKIE)
    assert not auth._code_cache  # the observed logout purged session-wide grants
    assert fake.count("list") >= 3  # pages 2 and 3 really were fetched in parallel


def test_denial_confirmation_respects_the_parents_shorter_deadline(make):
    from hypersearch.deadline import DeadlineExceeded, RequestContext, bound

    _fake, auth = make({"visible": names(1), "readable": [], "count_delay": 1.5})
    started = time.perf_counter()
    with bound(RequestContext(0.3)), pytest.raises(DeadlineExceeded):
        auth.code_readable_repositories(COOKIE, set(names(1)))
    assert time.perf_counter() - started < 1.0


def _trickling_forgejo(byte_interval, total_bytes, *, trickle_headers=False):
    """Upstream that trickles one byte at a time: the body (200 at once) or the header block."""
    import socketserver

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.recv(65536)
            body = b'{"ok":true,"data":[' + b" " * total_bytes + b"]}"
            head = (
                b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n"
                + f"Content-Length: {len(body)}\r\n\r\n".encode()
            )
            try:
                if trickle_headers:
                    for index in range(len(head)):
                        self.request.sendall(head[index : index + 1])
                        time.sleep(byte_interval)
                    self.request.sendall(body)
                else:
                    self.request.sendall(head)
                    for index in range(len(body)):
                        self.request.sendall(body[index : index + 1])
                        time.sleep(byte_interval)
            except OSError:
                pass

    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.mark.parametrize("trickle_headers", [False, True])
def test_an_upstream_trickling_bytes_cannot_outlast_the_absolute_request_budget(trickle_headers):
    # Every byte arrives well inside the 0.5 s socket timeout, so inactivity never fires; only
    # the absolute budget (2 x request_timeout = 1 s) ends it. Unbounded it would run ~10 s.
    upstream = _trickling_forgejo(0.1, 100, trickle_headers=trickle_headers)
    auth = ForgejoAuth(f"http://127.0.0.1:{upstream.server_address[1]}", request_timeout=0.5)
    try:
        started = time.perf_counter()
        with pytest.raises(VisibilityUnavailable):
            auth.visible_repositories(COOKIE)
        assert time.perf_counter() - started < 1.8
    finally:
        auth.close()
        upstream.shutdown()
        upstream.server_close()


def test_a_bound_request_deadline_also_bounds_the_upstream_socket_lifetime():
    from hypersearch.deadline import DeadlineExceeded, RequestContext, bound

    upstream = _trickling_forgejo(0.02, 60)
    auth = ForgejoAuth(f"http://127.0.0.1:{upstream.server_address[1]}", request_timeout=2.0)
    try:
        started = time.perf_counter()
        with bound(RequestContext(0.3)), pytest.raises(DeadlineExceeded):
            auth.visible_repositories(COOKIE)
        assert time.perf_counter() - started < 0.8  # not the 2 s socket timeout, nor 1.2 s of body
    finally:
        auth.close()
        upstream.shutdown()
        upstream.server_close()
