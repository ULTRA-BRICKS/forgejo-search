from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from hypersearch.auth import VisibilityUnavailable
from hypersearch.db import open_database
from hypersearch.server import SearchServer


class FakeAuth:
    def visible_repositories(self, cookie: str):
        if cookie == "visibility-error":
            raise VisibilityUnavailable("upstream visibility failed")
        if cookie != "session=alice":
            return None, set()
        return "alice", {"acme/demo"}


@pytest.fixture
def server(tmp_path: Path):
    db = open_database(tmp_path / "search.db")
    instance = SearchServer(("127.0.0.1", 0), db, FakeAuth(), "missing-ast-grep")
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{instance.server_port}"
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=2)


def get_json(base: str, path: str, cookie: str | None = None):
    request = urllib.request.Request(base + path)
    if cookie:
        request.add_header("Cookie", cookie)
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)


def test_health_shape(server):
    status, payload = get_json(server, "/health")
    assert status == 200
    assert payload["service"] == "hypersearch"
    assert payload["repos"] == 0
    assert payload["documents"] == 0


def test_unknown_path_is_404(server):
    status, payload = get_json(server, "/nope")
    assert status == 404
    assert payload["error"] == "not_found"


def test_search_requires_existing_forgejo_session(server):
    status, payload = get_json(server, "/api/hypersearch?q=secret")
    assert status == 401
    assert payload["error"] == "authentication_required"


def test_visibility_failure_is_explicit_503(server):
    status, payload = get_json(
        server,
        "/api/hypersearch?q=secret",
        cookie="visibility-error",
    )
    assert status == 503
    assert payload["error"] == "visibility_unavailable"


def test_empty_query_keeps_identity_but_returns_no_rows(server):
    status, payload = get_json(
        server,
        "/api/hypersearch?q=",
        cookie="session=alice",
    )
    assert status == 200
    assert payload == {
        "query": "",
        "mode": "auto",
        "results": [],
        "user": "alice",
    }


def test_authenticated_query_cannot_escape_empty_index(server):
    status, payload = get_json(
        server,
        "/api/hypersearch?q=anything",
        cookie="session=alice",
    )
    assert status == 200
    assert payload["user"] == "alice"
    assert payload["results"] == []
    assert payload["elapsed_ms"] >= 0
