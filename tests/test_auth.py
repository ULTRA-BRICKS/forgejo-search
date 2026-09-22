import pytest

from hypersearch.auth import ForgejoAuth, VisibilityUnavailable


class FakeAuth(ForgejoAuth):
    def __init__(self):
        super().__init__(ttl=30, negative_ttl=30, max_entries=2)
        self.calls = []

    def _get(self, path, cookie):
        self.calls.append((path, cookie))
        if cookie == "bad":
            raise TimeoutError
        if path == "/api/v1/user":
            return {"login": cookie}
        return [{"full_name": "acme/demo"}]


def test_visible_repositories_are_cached_and_bounded():
    auth = FakeAuth()
    assert auth.visible_repositories("alice") == ("alice", {"acme/demo"})
    before = len(auth.calls)
    assert auth.visible_repositories("alice") == ("alice", {"acme/demo"})
    assert len(auth.calls) == before
    auth.visible_repositories("bob")
    auth.visible_repositories("carol")
    assert len(auth.cache) == 2


def test_failed_auth_is_negative_cached():
    auth = FakeAuth()
    assert auth.visible_repositories("bad") == (None, set())
    calls = len(auth.calls)
    assert auth.visible_repositories("bad") == (None, set())
    assert len(auth.calls) == calls


class PartialAuth(ForgejoAuth):
    def __init__(self):
        super().__init__(ttl=30)
        self.calls = []

    def _get(self, path, cookie):
        self.calls.append(path)
        if path == "/api/v1/user":
            return {"login": "alice"}
        if "page=1" in path:
            return [{"full_name": f"acme/r{i}"} for i in range(50)]
        raise TimeoutError


def test_partial_visibility_is_not_cached_as_complete():
    auth = PartialAuth()
    with pytest.raises(VisibilityUnavailable):
        auth.visible_repositories("alice-cookie")
    assert not auth.cache


class WeirdUserAuth(FakeAuth):
    def _get(self, path, cookie):
        if path == "/api/v1/user":
            return []
        return []


def test_non_object_user_payload_fails_closed():
    assert WeirdUserAuth().visible_repositories("alice") == (None, set())


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
            if path == "/api/v1/user":
                return {"login": "alice"}
            return [{"full_name": "acme/demo"}]

    auth = SlowAuth()
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: auth.visible_repositories("same"), range(8)))
    assert results == [("alice", {"acme/demo"})] * 8
    assert auth.calls.count("/api/v1/user") == 1
    assert len([path for path in auth.calls if "/user/repos" in path]) == 1


def test_auth_opener_disables_proxies_and_redirects_session_cookie():
    import threading
    import urllib.error
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
        if path == "/api/v1/user":
            return {"login": "alice"}
        import re

        page = int(re.search(r"page=(\d+)", path).group(1))
        self.pages.append(page)
        if page <= 20:
            start = (page - 1) * 50
            return [{"full_name": f"acme/r{i}"} for i in range(start, start + 50)]
        return [{"full_name": "acme/overflow"}] if self.overflow else []


def test_exactly_1000_visible_repos_are_allowed():
    auth = ThousandReposAuth()
    login, repos = auth.visible_repositories("alice")
    assert login == "alice"
    assert len(repos) == 1000
    assert auth.pages[-1] == 21


def test_more_than_1000_visible_repos_fail_closed():
    auth = ThousandReposAuth(overflow=True)
    with pytest.raises(VisibilityUnavailable):
        auth.visible_repositories("alice")
