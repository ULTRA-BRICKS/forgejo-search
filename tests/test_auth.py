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


def test_code_readable_repositories_against_a_real_http_server():
    """Every other code-ACL test stubs `_head` directly; this proves the real
    `self._opener` (built with `_NoRedirect` and no ambient proxy) actually
    serves a HEAD request correctly for `/{owner}/{reponame}/search` and
    surfaces a `reqSignIn`-style login redirect as an `HTTPError` rather than
    silently following it -- the same guarantee
    `test_auth_opener_disables_proxies_and_redirects_session_cookie` proves
    generically, applied to the actual code-ACL request shape.
    """
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class FakeForgejo(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_HEAD(self):
            cookie = self.headers.get("Cookie", "")
            if self.path == "/acme/code/search":
                if cookie != "session=valid-session-cookie":
                    self.send_response(302)
                    self.send_header("Location", "/user/login")
                    self.end_headers()
                    return
                self.send_response(200)
                self.end_headers()
                return
            if self.path == "/acme/issues-only/search":
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(500)
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeForgejo)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        auth = ForgejoAuth(base=f"http://127.0.0.1:{server.server_port}", ttl=30)
        assert auth.code_readable_repositories(
            "session=valid-session-cookie", {"acme/code", "acme/issues-only"}
        ) == {"acme/code"}
        # A revoked/anonymous session mid-check must surface as unavailable,
        # not be silently followed to the login page and treated as a 200.
        with pytest.raises(VisibilityUnavailable):
            auth.code_readable_repositories("session=revoked", {"acme/code"})
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


class CodeRouteAuth(ForgejoAuth):
    def __init__(self, **kwargs):
        kwargs.setdefault("ttl", 30)
        kwargs.setdefault("negative_ttl", 5)
        super().__init__(**kwargs)
        self.code_calls = []

    def _head(self, path, cookie):
        self.code_calls.append((path, cookie))
        if "/acme/issues-only/" in path:
            return 404
        if "/acme/outage/" in path:
            raise urllib.error.URLError("temporary")
        return 200


def test_code_readable_repositories_uses_native_code_reader_route():
    auth = CodeRouteAuth()
    allowed = auth.code_readable_repositories(
        "session=alice", {"acme/code", "acme/issues-only"}
    )
    assert allowed == {"acme/code"}
    assert {path for path, _ in auth.code_calls} == {
        "/acme/code/search",
        "/acme/issues-only/search",
    }


def test_code_acl_transport_failure_fails_whole_call_closed_not_partial():
    auth = CodeRouteAuth()
    with pytest.raises(VisibilityUnavailable):
        auth.code_readable_repositories("session=alice", {"acme/code", "acme/outage"})


def test_code_acl_rejects_untrusted_repo_names_before_any_request():
    auth = CodeRouteAuth()
    with pytest.raises(VisibilityUnavailable):
        auth.code_readable_repositories("session=alice", {"acme/code", "bad/../escape"})
    assert auth.code_calls == []


def test_code_acl_rejects_repo_names_with_extra_segments_or_bad_chars():
    auth = CodeRouteAuth()
    for bad in ("acme/nested/extra", "acme/weird name", "acme/caf\u00e9%20x"):
        with pytest.raises(VisibilityUnavailable):
            auth.code_readable_repositories("session=alice", {bad})
    assert auth.code_calls == []


def test_code_acl_rejects_dot_only_path_segments():
    # The owner/repo charset alone (letters, digits, "_.-") still allows a
    # segment made entirely of dots; quote() never percent-encodes "." (an
    # RFC 3986 unreserved char), so an unfiltered ".." would build a literal
    # "/acme/../search" traversal path. Must be rejected before any request.
    auth = CodeRouteAuth()
    for bad in ("acme/..", "acme/.", "../acme", "./acme"):
        with pytest.raises(VisibilityUnavailable):
            auth.code_readable_repositories("session=alice", {bad})
    assert auth.code_calls == []


def test_code_acl_empty_cookie_or_repos_short_circuits_without_requests():
    auth = CodeRouteAuth()
    assert auth.code_readable_repositories("", {"acme/code"}) == set()
    assert auth.code_readable_repositories("session=alice", set()) == set()
    assert auth.code_calls == []


class ForbiddenCodeAuth(ForgejoAuth):
    def __init__(self):
        super().__init__(ttl=30, negative_ttl=5)

    def _head(self, path, cookie):
        raise urllib.error.HTTPError(path, 403, "forbidden", {}, None)


def test_code_acl_403_is_unavailable_not_denied():
    # Mirrors test_page_one_403_is_unavailable_not_unauthenticated: a
    # WAF/proxy/IP block answering 403 for a fully signed-in, code-reading
    # user must fail closed as unavailable, never be cached as a denial.
    auth = ForbiddenCodeAuth()
    with pytest.raises(VisibilityUnavailable):
        auth.code_readable_repositories("session=alice", {"acme/code"})
    assert not auth._code_cache


class RevokedMidCodeCheckAuth(ForgejoAuth):
    def __init__(self):
        super().__init__(ttl=30, negative_ttl=5)

    def _head(self, path, cookie):
        raise urllib.error.HTTPError(
            path, 302, "redirect to /user/login", {"Location": "/user/login"}, None
        )


def test_code_acl_login_redirect_mid_check_is_unavailable_not_downgraded():
    # The session that visible_repositories() just proved authenticated a
    # moment ago is no longer valid. Surprising/inconsistent mid-check --
    # must not be silently reinterpreted as an anonymous deny from inside
    # this per-repo helper.
    auth = RevokedMidCodeCheckAuth()
    with pytest.raises(VisibilityUnavailable):
        auth.code_readable_repositories("session=alice", {"acme/code"})
    assert not auth._code_cache


class DirectUnauthorizedCodeAuth(ForgejoAuth):
    def __init__(self):
        super().__init__(ttl=30, negative_ttl=5)

    def _head(self, path, cookie):
        raise urllib.error.HTTPError(path, 401, "unauthorized", {}, None)


def test_code_acl_401_mid_check_is_unavailable():
    auth = DirectUnauthorizedCodeAuth()
    with pytest.raises(VisibilityUnavailable):
        auth.code_readable_repositories("session=alice", {"acme/code"})


def test_code_acl_caches_positive_and_negative_results_within_ttl_window():
    auth = CodeRouteAuth()
    assert auth.code_readable_repositories("session=alice", {"acme/code"}) == {
        "acme/code"
    }
    assert (
        auth.code_readable_repositories("session=alice", {"acme/issues-only"})
        == set()
    )
    calls_after_first_round = len(auth.code_calls)
    # Repeat calls within ttl/negative_ttl must not re-request either result.
    assert auth.code_readable_repositories("session=alice", {"acme/code"}) == {
        "acme/code"
    }
    assert (
        auth.code_readable_repositories("session=alice", {"acme/issues-only"})
        == set()
    )
    assert len(auth.code_calls) == calls_after_first_round


def test_code_acl_ttl_windows_match_visibility_cache_exactly():
    import time

    auth = CodeRouteAuth(ttl=0.05, negative_ttl=0.05)
    auth.code_readable_repositories("session=alice", {"acme/code"})
    auth.code_readable_repositories("session=alice", {"acme/issues-only"})
    calls_before = len(auth.code_calls)
    time.sleep(0.08)
    # Once self.ttl/self.negative_ttl elapse, both the positive and negative
    # cache entries must expire and be re-checked -- not a separate, shorter,
    # hardcoded cap.
    auth.code_readable_repositories("session=alice", {"acme/code", "acme/issues-only"})
    assert len(auth.code_calls) == calls_before + 2


class FlippingCodeAuth(ForgejoAuth):
    def __init__(self):
        super().__init__(ttl=30, negative_ttl=30)
        self.code_calls = []
        self.denied = False

    def _head(self, path, cookie):
        self.code_calls.append(path)
        return 404 if self.denied else 200


def test_code_acl_revocation_after_cache_expiry_flips_result():
    auth = FlippingCodeAuth()
    auth.ttl = 0.05
    assert auth.code_readable_repositories("session=alice", {"acme/code"}) == {
        "acme/code"
    }
    auth.denied = True
    # Still within the ttl window -- must not re-request or flip yet.
    assert auth.code_readable_repositories("session=alice", {"acme/code"}) == {
        "acme/code"
    }
    import time

    time.sleep(0.08)
    assert auth.code_readable_repositories("session=alice", {"acme/code"}) == set()
    assert len(auth.code_calls) == 2


class BoundedConcurrencyCodeAuth(ForgejoAuth):
    def __init__(self, delay=0.05):
        import threading

        super().__init__(ttl=30, negative_ttl=5)
        self.delay = delay
        self.lock = threading.Lock()
        self.in_flight = 0
        self.peak = 0

    def _head(self, path, cookie):
        import time

        with self.lock:
            self.in_flight += 1
            self.peak = max(self.peak, self.in_flight)
        time.sleep(self.delay)
        with self.lock:
            self.in_flight -= 1
        return 200


def test_code_acl_concurrency_is_bounded_not_unbounded_or_serial():
    import time

    auth = BoundedConcurrencyCodeAuth(delay=0.05)
    repos = {f"acme/r{i}" for i in range(16)}
    started = time.perf_counter()
    allowed = auth.code_readable_repositories("session=alice", repos)
    elapsed = time.perf_counter() - started
    assert allowed == repos
    # 16 repos at max_workers=8 -> two waves of ~0.05s each, well under a
    # fully serial 16 * 0.05s = 0.8s, but genuinely bounded, not a single wave.
    assert elapsed < 0.35
    assert 1 < auth.peak <= 8


def test_code_acl_same_repo_check_is_single_flight():
    import concurrent.futures
    import threading
    import time

    class SlowCodeAuth(ForgejoAuth):
        def __init__(self):
            super().__init__(ttl=30, negative_ttl=5)
            self.calls = []
            self.lock = threading.Lock()

        def _head(self, path, cookie):
            with self.lock:
                self.calls.append(path)
            time.sleep(0.03)
            return 200

    auth = SlowCodeAuth()
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(
            pool.map(
                lambda _: auth.code_readable_repositories(
                    "session=alice", {"acme/code"}
                ),
                range(8),
            )
        )
    assert results == [{"acme/code"}] * 8
    # Single-flight: only the leader caller actually probes the repo; every
    # other concurrent caller waits on that in-flight check instead of each
    # re-issuing its own duplicate HEAD request.
    assert auth.calls.count("/acme/code/search") == 1


def test_code_acl_fails_fast_by_cancelling_pending_probes_on_first_error():
    import threading
    import time

    class FailFastAuth(ForgejoAuth):
        def __init__(self, delay):
            super().__init__(ttl=30, negative_ttl=5, request_timeout=5.0)
            self.delay = delay
            self.started = 0
            self.lock = threading.Lock()

        def _head(self, path, cookie):
            with self.lock:
                self.started += 1
            if "/acme/aaa_bad/" in path:
                raise urllib.error.HTTPError(path, 500, "boom", {}, None)
            time.sleep(self.delay)
            return 200

    # Repos are dispatched in sorted order, so "acme/aaa_bad" sorts first and
    # is guaranteed to be in the first wave of 8 concurrent probes -- making
    # the outcome deterministic instead of racing on set iteration order.
    auth = FailFastAuth(delay=0.2)
    repos = {"acme/aaa_bad"} | {f"acme/good{i:02d}" for i in range(16)}
    with pytest.raises(VisibilityUnavailable):
        auth.code_readable_repositories("session=alice", repos)
    # Only the first wave (8: acme/aaa_bad + 7 good) is guaranteed to start;
    # a freed worker thread may grab one more item before the main thread's
    # cancellation loop runs, but the remaining queued probes (at least 8 of
    # the 9 originally pending) must never start.
    assert auth.started <= 10


def test_code_acl_probe_budget_fails_closed_without_waiting_full_fanout():
    import threading
    import time

    class NeverRespondingAuth(ForgejoAuth):
        def __init__(self, budget):
            super().__init__(ttl=30, negative_ttl=5, code_probe_budget=budget)
            self.never = threading.Event()

        def _head(self, path, cookie):
            # Blocks well past code_probe_budget -- bounded by an Event
            # timeout only so a still-running background probe thread can't
            # keep the test process alive indefinitely, not because the
            # deadline logic under test is expected to let it run this long.
            self.never.wait(timeout=2.0)
            return 200

    auth = NeverRespondingAuth(budget=0.1)
    repos = {f"acme/r{i}" for i in range(16)}
    started = time.perf_counter()
    with pytest.raises(VisibilityUnavailable) as excinfo:
        auth.code_readable_repositories("session=alice", repos)
    elapsed = time.perf_counter() - started
    # Must fail well before what waiting out the full fan-out (16 repos / 8
    # workers, each hanging up to 2s) would take -- a generous margin above
    # the 0.1s budget to avoid CI scheduling flakiness while still clearly
    # distinguishing "budget enforced" from "fan-out completed".
    assert elapsed < 1.0
    assert "0.1" in str(excinfo.value)
    assert "pending" in str(excinfo.value)


def test_code_cache_max_entries_bounds_independently_of_max_entries():
    # A large max_entries (the separate, cookie-only visibility cache's
    # bound) must never leak into the code-ACL cache: it gets its own,
    # independently-enforced code_cache_max_entries bound.
    auth = ForgejoAuth(max_entries=10_000, code_cache_max_entries=5)
    auth._head = lambda path, cookie: 200
    for i in range(50):
        auth.code_readable_repositories("session=alice", {f"acme/r{i}"})
    assert len(auth._code_cache) <= 5


def test_code_acl_fully_cached_skips_threadpool_executor(monkeypatch):
    import hypersearch.auth as auth_module

    auth = ForgejoAuth()
    auth._head = lambda path, cookie: 200
    # Warm the cache for both repos via a real (uninstrumented) fan-out.
    auth.code_readable_repositories("session=alice", {"acme/a", "acme/b"})

    created = []
    original = auth_module.ThreadPoolExecutor

    def spy(*args, **kwargs):
        created.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(auth_module, "ThreadPoolExecutor", spy)
    result = auth.code_readable_repositories("session=alice", {"acme/a", "acme/b"})
    assert result == {"acme/a", "acme/b"}
    # Every candidate resolved from cache -- the fast path must return
    # without ever constructing a ThreadPoolExecutor.
    assert created == []
