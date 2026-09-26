import urllib.error

import pytest

from hypersearch.auth import ForgejoAuth, VisibilityUnavailable


def test_visible_repositories_authenticates_via_session_web_route_not_rest_api():
    """Reproduces the real production contract observed on git.hyperide.ai (Forgejo 16.0.3):

    - GET /api/v1/user with a browser session Cookie is rejected (401 token_required) --
      the REST API router never accepts Session auth.
    - GET /repo/search with the SAME session Cookie succeeds (200, session-authenticated
      web router) and is scoped to the signed-in user's visible repositories.
    - GET /repo/search with no/invalid cookie is redirected to /user/login (302), exactly
      like Forgejo's `reqSignIn` middleware behaves for an anonymous or revoked session.

    ForgejoAuth.visible_repositories() must authenticate via the session-authenticated
    /repo/search web route, never via /api/v1/user[/repos]. Against the unfixed
    implementation (which still calls /api/v1/user) this fails because the real REST API
    behavior (401 on cookie auth) makes every session look anonymous.
    """
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import parse_qs, urlparse

    class FakeForgejo(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            url = urlparse(self.path)
            cookie = self.headers.get("Cookie", "")
            if url.path == "/api/v1/user":
                # Real production behavior: the REST API router has no Session auth
                # method, so a browser cookie is always rejected here.
                body = b'{"message":"token is required"}'
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if url.path == "/repo/search":
                if cookie != "session=valid-session-cookie":
                    # Real production behavior: Forgejo's reqSignIn redirects an
                    # unauthenticated (or revoked/expired) session to /user/login.
                    self.send_response(302)
                    self.send_header("Location", "/user/login")
                    self.end_headers()
                    return
                page = int((parse_qs(url.query).get("page") or ["1"])[0])
                if page > 1:
                    body = b'{"ok":true,"data":[]}'
                else:
                    body = (
                        b'{"ok":true,"data":['
                        b'{"repository":{"full_name":"acme/demo","private":false}}'
                        b"]}"
                    )
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeForgejo)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        auth = ForgejoAuth(base=f"http://127.0.0.1:{server.server_port}", ttl=30)
        assert auth.visible_repositories("session=valid-session-cookie") == (
            True,
            {"acme/demo"},
        )
        assert auth.visible_repositories("session=revoked-or-missing") == (False, set())
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _search_payload(full_names):
    return {
        "ok": True,
        "data": [{"repository": {"full_name": name}} for name in full_names],
    }


class FakeAuth(ForgejoAuth):
    def __init__(self):
        super().__init__(ttl=30, negative_ttl=30, max_entries=2)
        self.calls = []

    def _get(self, path, cookie):
        self.calls.append((path, cookie))
        if cookie == "bad":
            # A genuine "not signed in" signal: Forgejo's reqSignIn redirect,
            # surfaced by our no-redirect opener as an HTTPError(302) whose
            # Location targets the login route.
            raise urllib.error.HTTPError(
                path, 302, "redirect to /user/login", {"Location": "/user/login"}, None
            )
        if "page=1" in path:
            return _search_payload(["acme/demo"])
        return _search_payload([])


def test_visible_repositories_are_cached_and_bounded():
    auth = FakeAuth()
    assert auth.visible_repositories("alice") == (True, {"acme/demo"})
    before = len(auth.calls)
    assert auth.visible_repositories("alice") == (True, {"acme/demo"})
    assert len(auth.calls) == before
    auth.visible_repositories("bob")
    auth.visible_repositories("carol")
    assert len(auth.cache) == 2


def test_failed_auth_is_negative_cached():
    auth = FakeAuth()
    assert auth.visible_repositories("bad") == (False, set())
    calls = len(auth.calls)
    assert auth.visible_repositories("bad") == (False, set())
    assert len(auth.calls) == calls


class TransientFailureAuth(ForgejoAuth):
    def __init__(self):
        super().__init__(ttl=30, negative_ttl=30)
        self.calls = []

    def _get(self, path, cookie):
        self.calls.append(path)
        raise TimeoutError


def test_transient_page_one_failure_is_unavailable_not_unauthenticated():
    # A timeout on page 1 doesn't prove the session is anonymous -- it means we
    # couldn't tell. A genuinely signed-in user must get an explicit, uncached
    # error, never a cached 401 that would incorrectly bounce a real session.
    auth = TransientFailureAuth()
    with pytest.raises(VisibilityUnavailable):
        auth.visible_repositories("alice")
    assert not auth.cache


class ServerErrorAuth(ForgejoAuth):
    def __init__(self):
        super().__init__(ttl=30, negative_ttl=30)

    def _get(self, path, cookie):
        raise urllib.error.HTTPError(path, 500, "internal server error", None, None)


def test_page_one_server_error_is_unavailable_not_unauthenticated():
    # A 5xx from Forgejo is not a login redirect -- it must not be folded into
    # the same "not authenticated" bucket as an actual reqSignIn redirect.
    auth = ServerErrorAuth()
    with pytest.raises(VisibilityUnavailable):
        auth.visible_repositories("alice")
    assert not auth.cache


class ForeignRedirectAuth(ForgejoAuth):
    def __init__(self):
        super().__init__(ttl=30, negative_ttl=30)

    def _get(self, path, cookie):
        # A generic redirect unrelated to login -- e.g. an HTTP->HTTPS upgrade or
        # canonical-host normalization in front of `base`.
        raise urllib.error.HTTPError(
            path, 301, "moved permanently", {"Location": "https://example.org" + path}, None
        )


def test_non_login_redirect_on_page_one_is_unavailable_not_unauthenticated():
    # A 3xx whose Location does NOT target /user/login must not be misread as
    # "anonymous" -- only a genuine reqSignIn login redirect proves that.
    auth = ForeignRedirectAuth()
    with pytest.raises(VisibilityUnavailable):
        auth.visible_repositories("alice")
    assert not auth.cache


class DirectUnauthorizedAuth(ForgejoAuth):
    def __init__(self):
        super().__init__(ttl=30, negative_ttl=30)

    def _get(self, path, cookie):
        raise urllib.error.HTTPError(path, 401, "unauthorized", {}, None)


def test_page_one_401_is_treated_as_unauthenticated():
    # Defensive fallback: an explicit 401/403 (not just a login redirect) also
    # unambiguously means "not signed in", should some Forgejo version answer
    # directly instead of redirecting.
    auth = DirectUnauthorizedAuth()
    assert auth.visible_repositories("alice") == (False, set())


class NoLocationRedirectAuth(ForgejoAuth):
    def __init__(self):
        super().__init__(ttl=30, negative_ttl=30)

    def _get(self, path, cookie):
        # A 3xx with no Location header at all -- must not default to "login".
        raise urllib.error.HTTPError(path, 302, "redirect", {}, None)


def test_redirect_without_location_header_is_unavailable():
    auth = NoLocationRedirectAuth()
    with pytest.raises(VisibilityUnavailable):
        auth.visible_repositories("alice")
    assert not auth.cache


class DirectForbiddenAuth(ForgejoAuth):
    def __init__(self):
        super().__init__(ttl=30, negative_ttl=30)

    def _get(self, path, cookie):
        raise urllib.error.HTTPError(path, 403, "forbidden", {}, None)


def test_page_one_403_is_unavailable_not_unauthenticated():
    # A WAF/proxy/IP block commonly answers 403 for a fully signed-in user --
    # that's "authenticated but forbidden", not proof of anonymity. It must
    # fail closed as unavailable, never a cached, misleading 401.
    auth = DirectForbiddenAuth()
    with pytest.raises(VisibilityUnavailable):
        auth.visible_repositories("alice")
    assert not auth.cache


class AbsoluteLoginRedirectAuth(ForgejoAuth):
    def __init__(self):
        super().__init__(ttl=30, negative_ttl=30)

    def _get(self, path, cookie):
        # The real Forgejo shape: an absolute URL with a redirect_to query param.
        raise urllib.error.HTTPError(
            path,
            302,
            "redirect to /user/login",
            {"Location": "https://git.hyperide.ai/user/login?redirect_to=%2Fapi%2Fhypersearch"},
            None,
        )


def test_absolute_login_redirect_with_query_is_treated_as_unauthenticated():
    auth = AbsoluteLoginRedirectAuth()
    assert auth.visible_repositories("alice") == (False, set())


class UndecodableBodyAuth(ForgejoAuth):
    def __init__(self):
        super().__init__(ttl=30, negative_ttl=30)

    def _get(self, path, cookie):
        # A misconfigured proxy answering 200 with a non-UTF-8 body (e.g. a
        # Latin-1 HTML interstitial) must fail closed, not crash the handler.
        b"\xff\xfe not valid utf-8".decode("utf-8")


def test_undecodable_page_one_body_is_unavailable_not_a_crash():
    auth = UndecodableBodyAuth()
    with pytest.raises(VisibilityUnavailable):
        auth.visible_repositories("alice")
    assert not auth.cache


class RevokedMidPaginationAuth(ForgejoAuth):
    def __init__(self):
        super().__init__(ttl=30)

    def _get(self, path, cookie):
        if "page=1" in path:
            return _search_payload([f"acme/r{i}" for i in range(50)])
        # The session was valid for page 1 but is now revoked/expired before
        # page 2 -- Forgejo redirects again, exactly like an anonymous request.
        raise urllib.error.HTTPError(
            path, 302, "redirect to /user/login", {"Location": "/user/login"}, None
        )


def test_login_redirect_mid_pagination_is_unavailable_not_downgraded():
    # Identity was already proven by page 1; a later-page redirect is a partial-
    # visibility failure (503), never a silent downgrade to "anonymous" that
    # would let a real session's search return zero results without an error.
    auth = RevokedMidPaginationAuth()
    with pytest.raises(VisibilityUnavailable):
        auth.visible_repositories("alice")
    assert not auth.cache


class ShortPageThenClampedServerAuth(ForgejoAuth):
    """Simulates a Forgejo instance whose web route enforces a SMALLER page
    size than the 50 we request (e.g. a lowered API.MaxResponseItems) --
    every page comes back shorter than `_PAGE_SIZE`, which the old
    `len(batch) == _PAGE_SIZE` heuristic would have misread as "last page"
    after page 1 alone, silently truncating the allow-list to 20 of 80."""

    def __init__(self):
        super().__init__(ttl=30)
        self.calls = []

    def _get(self, path, cookie):
        self.calls.append(path)
        if "page=1" in path:
            return _search_payload([f"acme/r{i}" for i in range(20)])
        if "page=2" in path:
            return _search_payload([f"acme/s{i}" for i in range(20)])
        if "page=3" in path:
            return _search_payload([f"acme/t{i}" for i in range(20)])
        if "page=4" in path:
            return _search_payload([f"acme/u{i}" for i in range(20)])
        if "page=5" in path:
            # Empty page confirms termination; nothing beyond 80 repos exists.
            return _search_payload([])
        raise AssertionError(f"unexpected page fetch: {path}")


def test_pagination_ignores_actual_server_page_size_and_confirms_emptiness():
    # Continuation is keyed on "was the page non-empty", not on matching our
    # requested `limit` exactly -- correct regardless of what page size
    # Forgejo's web route actually enforces server-side.
    auth = ShortPageThenClampedServerAuth()
    authenticated, repos = auth.visible_repositories("alice")
    assert authenticated is True
    assert len(repos) == 80
    for prefix, i in [("r", 0), ("s", 0), ("t", 0), ("u", 0)]:
        assert f"acme/{prefix}{i}" in repos
    assert [c for c in auth.calls] == [
        "/repo/search?limit=50&page=1",
        "/repo/search?limit=50&page=2",
        "/repo/search?limit=50&page=3",
        "/repo/search?limit=50&page=4",
        "/repo/search?limit=50&page=5",
    ]


class PartialAuth(ForgejoAuth):
    def __init__(self):
        super().__init__(ttl=30)
        self.calls = []

    def _get(self, path, cookie):
        self.calls.append(path)
        if "page=1" in path:
            return _search_payload([f"acme/r{i}" for i in range(50)])
        raise TimeoutError


def test_partial_visibility_is_not_cached_as_complete():
    auth = PartialAuth()
    with pytest.raises(VisibilityUnavailable):
        auth.visible_repositories("alice-cookie")
    assert not auth.cache


class MalformedPageTwoAuth(ForgejoAuth):
    def __init__(self):
        super().__init__(ttl=30)

    def _get(self, path, cookie):
        if "page=1" in path:
            return _search_payload([f"acme/r{i}" for i in range(50)])
        return {"ok": False}


def test_malformed_page_two_payload_is_unavailable_not_cached():
    # Identity was already established by page 1; a broken shape on a later
    # page is a partial-visibility failure (503), not a reason to downgrade an
    # authenticated user to anonymous.
    auth = MalformedPageTwoAuth()
    with pytest.raises(VisibilityUnavailable):
        auth.visible_repositories("alice")
    assert not auth.cache


class WeirdSearchPayloadAuth(FakeAuth):
    def _get(self, path, cookie):
        return []


def test_non_object_search_payload_on_page_one_is_unavailable():
    # reqSignIn already let this 200 response through the handler, so a
    # malformed body is our/Forgejo's problem, not proof the session is
    # anonymous -- fail closed with an explicit, uncached error instead of a
    # false 401.
    auth = WeirdSearchPayloadAuth()
    with pytest.raises(VisibilityUnavailable):
        auth.visible_repositories("alice")
    assert not auth.cache


class PrivateRepoAuth(FakeAuth):
    def _get(self, path, cookie):
        self.calls.append((path, cookie))
        if "page=1" not in path:
            return {"ok": True, "data": []}
        return {
            "ok": True,
            "data": [
                {"repository": {"full_name": "acme/private-demo", "private": True}},
            ],
        }


def test_private_repos_the_user_can_access_are_included():
    # Forgejo's own AccessibleRepositoryCondition already scoped /repo/search to
    # this session; a private repo it reports is trusted as visible, not filtered
    # out a second time here.
    assert PrivateRepoAuth().visible_repositories("alice") == (
        True,
        {"acme/private-demo"},
    )


class ScopedVisibilityAuth(ForgejoAuth):
    """Simulates distinct Forgejo sessions with disjoint repo visibility, plus a
    revoked/unrecognized session that Forgejo would redirect to /user/login."""

    def __init__(self):
        super().__init__(ttl=30)
        self.visible_by_cookie = {
            "alice-session": ["acme/alice-only"],
            "bob-session": ["acme/bob-only"],
        }

    def _get(self, path, cookie):
        names = self.visible_by_cookie.get(cookie)
        if names is None:
            raise urllib.error.HTTPError(
                path, 302, "redirect to /user/login", {"Location": "/user/login"}, None
            )
        return _search_payload(names if "page=1" in path else [])


def test_repos_not_visible_to_the_user_never_appear():
    auth = ScopedVisibilityAuth()
    assert auth.visible_repositories("alice-session") == (True, {"acme/alice-only"})
    assert auth.visible_repositories("bob-session") == (True, {"acme/bob-only"})
    # A revoked or unrecognized session cookie authenticates as nobody and sees
    # nothing -- including no leakage of either user's repos.
    assert auth.visible_repositories("revoked-session") == (False, set())


def test_same_cookie_visibility_is_single_flight():
    import concurrent.futures
    import threading
    import time

    class SlowAuth(ForgejoAuth):
        def __init__(self):
            super().__init__(ttl=30)
            self.calls = []
            self.lock = threading.Lock()

        def _get(self, path, cookie):
            with self.lock:
                self.calls.append(path)
            time.sleep(0.03)
            return _search_payload(["acme/demo"] if "page=1" in path else [])

    auth = SlowAuth()
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: auth.visible_repositories("same"), range(8)))
    assert results == [(True, {"acme/demo"})] * 8
    # One page-1 fetch plus one page-2 fetch to confirm no more results --
    # single-flight means only the leader thread does either, not each waiter.
    assert auth.calls.count("/repo/search?limit=50&page=1") == 1
    assert auth.calls.count("/repo/search?limit=50&page=2") == 1


def test_auth_opener_disables_proxies_and_redirects_session_cookie():
    import threading
    import urllib.request
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    leaked = []

    class Sink(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            leaked.append(self.headers.get("Cookie"))
            self.send_response(200)
            self.end_headers()

    sink = ThreadingHTTPServer(("127.0.0.1", 0), Sink)

    class Redirect(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            self.send_response(302)
            self.send_header(
                "Location",
                f"http://127.0.0.1:{sink.server_port}/leak",
            )
            self.end_headers()

    origin = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
    threads = [
        threading.Thread(target=server.serve_forever, daemon=True)
        for server in (sink, origin)
    ]
    for thread in threads:
        thread.start()
    try:
        auth = ForgejoAuth(base=f"http://127.0.0.1:{origin.server_port}")
        proxy_handlers = [
            handler
            for handler in auth._opener.handlers
            if isinstance(handler, urllib.request.ProxyHandler)
        ]
        assert all(handler.proxies == {} for handler in proxy_handlers)
        with pytest.raises(urllib.error.HTTPError) as error:
            auth._get("/redirect", "session=secret")
        assert error.value.code == 302
        assert leaked == []
    finally:
        for server in (origin, sink):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)


class ThousandReposAuth(ForgejoAuth):
    def __init__(self, overflow=False):
        super().__init__(ttl=30)
        self.overflow = overflow
        self.pages = []

    def _get(self, path, cookie):
        import re

        page = int(re.search(r"page=(\d+)", path).group(1))
        self.pages.append(page)
        if page <= 20:
            start = (page - 1) * 50
            return _search_payload([f"acme/r{i}" for i in range(start, start + 50)])
        return _search_payload(["acme/overflow"] if self.overflow else [])


def test_exactly_1000_visible_repos_are_allowed():
    auth = ThousandReposAuth()
    authenticated, repos = auth.visible_repositories("alice")
    assert authenticated is True
    assert len(repos) == 1000
    assert auth.pages[-1] == 21


def test_more_than_1000_visible_repos_fail_closed():
    auth = ThousandReposAuth(overflow=True)
    with pytest.raises(VisibilityUnavailable):
        auth.visible_repositories("alice")
