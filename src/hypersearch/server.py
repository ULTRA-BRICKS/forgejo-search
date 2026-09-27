from __future__ import annotations

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .auth import VisibilityUnavailable
from .db import indexed_repo_names
from .query import parse_query
from .search import scoped_repos, search


class SearchServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, database, auth, ast_grep="ast-grep"):
        super().__init__(address, SearchHandler)
        self.database = database
        self.auth = auth
        self.ast_grep = ast_grep
        self.started = time.time()


class SearchHandler(BaseHTTPRequestHandler):
    server_version = "HyperSearch/0.1"

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
            return self._json(
                200,
                {
                    "service": "hypersearch",
                    "repos": repos,
                    "documents": docs,
                    "uptime": int(time.time() - self.server.started),
                },
            )
        if url.path != "/api/hypersearch":
            return self._json(404, {"error": "not_found"})
        cookie = self.headers.get("Cookie", "")
        try:
            authenticated, allowed = self.server.auth.visible_repositories(cookie)
        except VisibilityUnavailable as error:
            return self._json(
                503,
                {
                    "error": "visibility_unavailable",
                    "message": str(error),
                },
            )
        if not authenticated:
            return self._json(401, {"error": "authentication_required"})
        params = parse_qs(url.query)
        query = (params.get("q") or [""])[0].strip()
        if not query:
            # The empty-query path is used purely as a "am I signed in?"
            # check by the frontend and always returns no rows regardless of
            # ACLs -- it must stay cheap. Code-ACL narrowing is network-bound
            # per repo, so it must never run here; only past this point, once
            # there is an actual query to execute, is it worth the cost.
            return self._json(
                200,
                {
                    "query": "",
                    "mode": "auto",
                    "results": [],
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
            return self._json(
                503,
                {"error": "code_visibility_unavailable", "message": str(error)},
            )
        try:
            limit = int((params.get("limit") or ["30"])[0])
        except ValueError:
            limit = 30
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
        return self._json(200, result)
