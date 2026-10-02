from __future__ import annotations

import json
import sqlite3
import threading
import time
from concurrent.futures import CancelledError, ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import __version__
from .auth import VisibilityUnavailable, probe_concurrency, probe_seconds
from .db import indexed_repo_names
from .deadline import RequestTimeout, check, request_deadline
from .query import parse_query
from .search import empty_coverage, scoped_repos, search


class SearchServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, database, auth, ast_grep="ast-grep", *, request_budget=25, request_workers=8):
        self.request_budget = probe_seconds(request_budget)
        workers = probe_concurrency(request_workers)
        self._slots = threading.BoundedSemaphore(workers)
        self._requests = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="search-request")
        super().__init__(address, SearchHandler)
        self.database = database
        self.auth = auth
        self.ast_grep = ast_grep
        self.started = time.time()

    def server_close(self):
        super().server_close()
        self._requests.shutdown(wait=False, cancel_futures=True)


class SearchHandler(BaseHTTPRequestHandler):
    server_version = f"HyperSearch/{__version__}"

    def log_message(self, format, *args):
        pass

    def _json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        deadline = time.monotonic() + self.server.request_budget
        if urlparse(self.path).path == "/health":
            return self._json(*self._response())
        if not self.server._slots.acquire(blocking=False):
            return self._json(503, {"error": "search_busy"})
        try:
            future = self.server._requests.submit(self._bounded_response, deadline)
        except RuntimeError:
            self.server._slots.release()
            return self._json(503, {"error": "search_unavailable"})
        except BaseException:
            self.server._slots.release()
            raise
        future.add_done_callback(lambda _: self.server._slots.release())
        try:
            status, payload = future.result(timeout=max(0, deadline - time.monotonic()))
            if time.monotonic() >= deadline:
                raise RequestTimeout()
        except CancelledError:
            status, payload = 503, {"error": "search_unavailable"}
        except (FutureTimeout, RequestTimeout):
            status, payload = 503, {"error": "request_timeout"}
        self._json(status, payload)

    def _bounded_response(self, deadline):
        with request_deadline(deadline):
            try:
                response = self._response()
            except sqlite3.OperationalError:
                check()
                raise
            check()
            return response

    @staticmethod
    def _payload(status, payload):
        return status, payload

    def _response(self):
        # Wall-clock timer for total_ms spans the entire authenticated
        # request path, starting before the very first network round trip
        # (the session-visibility check below) through the code-ACL
        # narrowing and the search() call -- the engine-only `elapsed_ms`
        # captured further down only covers time inside search(), which
        # would understate real latency once network-bound checks run
        # before it.
        wall_started = time.perf_counter()
        url = urlparse(self.path)
        if url.path == "/health":
            with self.server.database.connection() as c:
                repos = c.execute("SELECT count(*) FROM repos").fetchone()[0]
                docs = c.execute("SELECT count(*) FROM documents").fetchone()[0]
            return self._payload(
                200,
                {
                    "service": "hypersearch",
                    "repos": repos,
                    "documents": docs,
                    "uptime": int(time.time() - self.server.started),
                },
            )
        if url.path != "/api/hypersearch":
            return self._payload(404, {"error": "not_found"})
        cookie = self.headers.get("Cookie", "")
        try:
            authenticated, allowed = self.server.auth.visible_repositories(cookie)
        except VisibilityUnavailable as error:
            return self._payload(
                503,
                {
                    "error": "visibility_unavailable",
                    "message": str(error),
                },
            )
        check()
        if not authenticated:
            return self._payload(401, {"error": "authentication_required"})
        params = parse_qs(url.query)
        query = (params.get("q") or [""])[0].strip()
        try:
            limit = int((params.get("limit") or ["30"])[0])
        except ValueError:
            limit = 30
        if not query:
            # The empty-query path is used purely as a "am I signed in?"
            # check by the frontend and always returns no rows regardless of
            # ACLs -- it must stay cheap. Code-ACL narrowing is network-bound
            # per repo, so it must never run here; only past this point, once
            # there is an actual query to execute, is it worth the cost.
            return self._payload(
                200,
                {
                    "query": "",
                    "mode": "auto",
                    "results": [],
                    "coverage": empty_coverage(limit),
                    "total_ms": round((time.perf_counter() - wall_started) * 1000, 2),
                },
            )
        q = parse_query(query)
        # Repository visibility (granted by any unit -- issues, wiki,
        # projects, releases...) is not code visibility in Forgejo: only
        # indexed repositories need the stronger, native reqRepoCodeReader
        # probe, and only now that there is a real query to run. An explicit
        # repo:/owner: qualifier narrows which repos are even candidates for
        # this query -- probing a repo the query can never match wastes a
        # network round trip for nothing; an unscoped query still needs
        # every indexed+visible repo as a candidate.
        scoped = scoped_repos(q, allowed)
        if scoped:
            with self.server.database.connection() as connection:
                indexed = indexed_repo_names(connection, scoped)
        else:
            # No candidate could possibly match (e.g. a repo:/owner:
            # qualifier naming a repo outside the visible set) -- skip the DB
            # query and the code-ACL network probe entirely.
            indexed = set()
        try:
            code_allowed = self.server.auth.code_readable_repositories(cookie, indexed)
        except VisibilityUnavailable as error:
            return self._payload(
                503,
                {"error": "code_visibility_unavailable", "message": str(error)},
            )
        check()
        started = time.perf_counter()
        result = search(
            self.server.database,
            query,
            allowed,
            limit,
            self.server.ast_grep,
            code_allowed=code_allowed,
        )
        result["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 2)
        result["total_ms"] = round((time.perf_counter() - wall_started) * 1000, 2)
        return self._payload(200, result)
