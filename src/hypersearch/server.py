from __future__ import annotations

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .auth import VisibilityUnavailable
from .search import search


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
            login, allowed = self.server.auth.visible_repositories(cookie)
        except VisibilityUnavailable as error:
            return self._json(
                503,
                {
                    "error": "visibility_unavailable",
                    "message": str(error),
                },
            )
        if not login:
            return self._json(401, {"error": "authentication_required"})
        params = parse_qs(url.query)
        query = (params.get("q") or [""])[0].strip()
        if not query:
            return self._json(
                200, {"query": "", "mode": "auto", "results": [], "user": login}
            )
        try:
            limit = int((params.get("limit") or ["30"])[0])
        except ValueError:
            limit = 30
        started = time.perf_counter()
        result = search(
            self.server.database, query, allowed, limit, self.server.ast_grep
        )
        result["user"] = login
        result["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 2)
        return self._json(200, result)
