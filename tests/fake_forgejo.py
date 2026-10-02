"""Loopback Forgejo stand-in with request counters, ordering and fault hooks.

Models only the two native routes the search service consumes: the session-gated
`GET /repo/search` (visibility pages, `count_only` identity requests, `q` keyword
narrowing, `X-Total-Count`) and the per-repository `HEAD /{owner}/{repo}/search`
code-reader probe. Cookies and repository names are fabricated by callers.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGE_SIZE = 50


class FakeForgejo:
    def __init__(
        self,
        visible=(),
        readable=None,
        *,
        cookies=("session=alice",),
        page_delay=0.0,
        count_delay=0.0,
        head_delay=0.0,
        total_header=True,
        total_override=None,
        anonymous_head_status=302,
        logout_from_page=None,
        mount="",
    ):
        self.visible = list(visible)
        self.readable = set(self.visible if readable is None else readable)
        self.cookies = set(cookies)
        self.page_delay = page_delay
        self.count_delay = count_delay
        self.head_delay = head_delay
        self.total_header = total_header
        self.total_override = total_override
        self.anonymous_head_status = anonymous_head_status
        self.logout_from_page = logout_from_page
        self.mount = mount
        self.lock = threading.Lock()
        self.sequence = 0
        self.events: list[tuple[int, str, str]] = []
        self.head_gates: dict[str, threading.Event] = {}
        self.head_hooks: dict[str, object] = {}
        self.identity_hold: threading.Event | None = None
        self.identity_entered = threading.Event()
        self.head_entered: dict[str, threading.Event] = {}
        self.active = 0
        self.peak = 0
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, status, body=b"", headers=()):
                self.send_response(status)
                for key, value in headers:
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            def _login(self):
                self._send(302, headers=[("Location", outer.mount + "/user/login")])

            def do_GET(self):
                url = urllib.parse.urlsplit(self.path)
                if url.path != outer.mount + "/repo/search":
                    return self._send(404)
                query = urllib.parse.parse_qs(url.query)
                count_only = (query.get("count_only") or [""])[0] == "true"
                keyword = (query.get("q") or [""])[0].lower()
                page = int((query.get("page") or ["1"])[0])
                kind = "identity" if count_only else ("scoped" if keyword else "list")
                signed_in = self.headers.get("Cookie") in outer.cookies
                outer._record(kind, f"page={page} q={keyword}")
                outer._enter()
                try:
                    if count_only:
                        outer.identity_entered.set()
                        hold = outer.identity_hold
                        if hold is not None:
                            hold.wait(5)
                        time.sleep(outer.count_delay)
                    else:
                        time.sleep(outer.page_delay)
                    if not signed_in or (
                        not count_only
                        and outer.logout_from_page is not None
                        and page >= outer.logout_from_page
                    ):
                        return self._login()
                    names = [
                        name
                        for name in outer.visible
                        if keyword in name.split("/", 1)[1].lower()
                    ]
                    headers = [("Content-Type", "application/json")]
                    if outer.total_header:
                        total = len(names) if outer.total_override is None else outer.total_override
                        headers.append(("X-Total-Count", str(total)))
                    if count_only:
                        return self._send(200, b'{"ok":true}', headers)
                    chunk = names[(page - 1) * PAGE_SIZE : page * PAGE_SIZE]
                    body = json.dumps(
                        {"ok": True, "data": [{"repository": {"full_name": n}} for n in chunk]}
                    ).encode()
                    self._send(200, body, headers)
                finally:
                    outer._leave()

            def do_HEAD(self):
                parts = urllib.parse.urlsplit(self.path).path.removeprefix(outer.mount).strip("/")
                owner, repo, _ = parts.split("/")
                full_name = f"{owner}/{repo}"
                outer._record("head", full_name)
                outer._enter()
                try:
                    entered = outer.head_entered.get(full_name)
                    if entered is not None:
                        entered.set()
                    gate = outer.head_gates.get(full_name)
                    if gate is not None:
                        gate.wait(5)
                    time.sleep(outer.head_delay)
                    hook = outer.head_hooks.get(full_name)
                    if hook is not None:
                        hook()
                    if self.headers.get("Cookie") not in outer.cookies:
                        if outer.anonymous_head_status == 404:
                            outer._record("head404-sent", full_name)
                            return self._send(404)
                        return self._login()
                    status = 200 if full_name in outer.readable else 404
                    if status == 404:
                        outer._record("head404-sent", full_name)
                    self._send(status)
                finally:
                    outer._leave()

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def _record(self, kind, detail):
        with self.lock:
            self.sequence += 1
            self.events.append((self.sequence, kind, detail))

    def _enter(self):
        with self.lock:
            self.active += 1
            self.peak = max(self.peak, self.active)

    def _leave(self):
        with self.lock:
            self.active -= 1

    @property
    def base(self):
        return f"http://127.0.0.1:{self.server.server_port}{self.mount}"

    def count(self, kind):
        with self.lock:
            return sum(1 for _, event, _ in self.events if event == kind)

    def counts(self):
        with self.lock:
            totals: dict[str, int] = {}
            for _, event, _ in self.events:
                totals[event] = totals.get(event, 0) + 1
            return totals

    def revoke(self, cookie="session=alice"):
        self.cookies.discard(cookie)

    def close(self):
        for gate in self.head_gates.values():
            gate.set()
        if self.identity_hold is not None:
            self.identity_hold.set()
        self.server.shutdown()
        self.server.server_close()
        self._thread.join(timeout=2)
