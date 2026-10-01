from __future__ import annotations

import json
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from pathlib import Path

import pytest

from hypersearch.auth import VisibilityUnavailable
from hypersearch.db import open_database
from hypersearch.indexer import index_all
from hypersearch.server import SearchServer


class FakeAuth:
    def visible_repositories(self, cookie: str):
        if cookie == "visibility-error":
            raise VisibilityUnavailable("upstream visibility failed")
        if cookie not in {"session=alice", "session=code-visibility-error"}:
            return False, set()
        return True, {"acme/demo"}

    def code_readable_repositories(self, cookie: str, repos: set[str]):
        if cookie == "session=code-visibility-error":
            raise VisibilityUnavailable("upstream code visibility failed")
        return set(repos)


@contextmanager
def running_server(db, auth, ast_grep="missing-ast-grep"):
    instance = SearchServer(("127.0.0.1", 0), db, auth, ast_grep)
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{instance.server_port}"
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=2)


@pytest.fixture
def server(tmp_path: Path):
    db = open_database(tmp_path / "search.db")
    with running_server(db, FakeAuth()) as base:
        yield base


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
    assert "coverage" not in payload


def test_visibility_failure_is_explicit_503(server):
    status, payload = get_json(
        server,
        "/api/hypersearch?q=secret",
        cookie="visibility-error",
    )
    assert status == 503
    assert payload["error"] == "visibility_unavailable"
    assert "coverage" not in payload


def test_empty_query_stays_authenticated_but_returns_no_rows(server):
    status, payload = get_json(
        server,
        "/api/hypersearch?q=",
        cookie="session=alice",
    )
    assert status == 200
    assert payload["query"] == ""
    assert payload["mode"] == "auto"
    assert payload["results"] == []
    # total_ms is a new, intentional field spanning the code-ACL narrowing
    # (skipped here) and search() -- it must always be present, even on the
    # empty-query fast path.
    assert payload["total_ms"] >= 0


def test_authenticated_query_cannot_escape_empty_index(server):
    status, payload = get_json(
        server,
        "/api/hypersearch?q=anything",
        cookie="session=alice",
    )
    assert status == 200
    assert payload["results"] == []
    assert payload["elapsed_ms"] >= 0


def test_code_visibility_failure_is_explicit_503(server):
    status, payload = get_json(
        server,
        "/api/hypersearch?q=secret",
        cookie="session=code-visibility-error",
    )
    assert status == 503
    assert payload["error"] == "code_visibility_unavailable"
    assert "coverage" not in payload


class CountingCodeAuth(FakeAuth):
    def __init__(self):
        self.code_calls = 0

    def code_readable_repositories(self, cookie: str, repos: set[str]):
        self.code_calls += 1
        return super().code_readable_repositories(cookie, repos)


def test_empty_query_never_triggers_code_acl_check(tmp_path):
    db = open_database(tmp_path / "search.db")
    auth = CountingCodeAuth()
    with running_server(db, auth) as base:
        status, payload = get_json(base, "/api/hypersearch?q=", cookie="session=alice")
    assert status == 200
    assert payload["results"] == []
    assert auth.code_calls == 0
    assert payload["coverage"]["version"] == 1
    assert payload["coverage"]["ast"] == {"status": "not_requested"}
    assert all(
        stage["state"] == "not_applicable"
        for stage in payload["coverage"]["limits"].values()
    )


def test_anonymous_request_never_triggers_code_acl_check(tmp_path):
    db = open_database(tmp_path / "search.db")
    auth = CountingCodeAuth()
    with running_server(db, auth) as base:
        status, _ = get_json(base, "/api/hypersearch?q=anything")
    assert status == 401
    assert auth.code_calls == 0


class SlowCodeAclAuth(FakeAuth):
    def __init__(self, delay=0.05):
        self.delay = delay

    def code_readable_repositories(self, cookie: str, repos: set[str]):
        time.sleep(self.delay)
        return super().code_readable_repositories(cookie, repos)


def test_total_ms_reflects_code_acl_latency_beyond_engine_elapsed_ms(tmp_path):
    db = open_database(tmp_path / "search.db")
    auth = SlowCodeAclAuth(delay=0.05)
    with running_server(db, auth) as base:
        status, payload = get_json(
            base, "/api/hypersearch?q=anything", cookie="session=alice"
        )
    assert status == 200
    assert payload["elapsed_ms"] >= 0
    # elapsed_ms only covers time inside search(); total_ms must also cover
    # the network-bound code-ACL check that now runs before it.
    assert payload["total_ms"] - payload["elapsed_ms"] >= 30



class SlowVisibilityAuth(FakeAuth):
    def __init__(self, delay=0.05):
        self.delay = delay

    def visible_repositories(self, cookie: str):
        time.sleep(self.delay)
        return super().visible_repositories(cookie)


def test_total_ms_reflects_initial_visibility_latency(tmp_path):
    db = open_database(tmp_path / "search.db")
    auth = SlowVisibilityAuth(delay=0.05)
    with running_server(db, auth) as base:
        status, payload = get_json(
            base, "/api/hypersearch?q=anything", cookie="session=alice"
        )
    assert status == 200
    # total_ms now starts before the very first network round trip (the
    # session-visibility check), not just before the code-ACL narrowing and
    # search() -- it must reflect that initial latency too.
    assert payload["total_ms"] >= 30


def _make_bare_repo(repos_root: Path, work_root: Path, owner: str, name: str, files):
    work = work_root / owner / name
    work.mkdir(parents=True)
    bare = repos_root / owner / f"{name}.git"
    bare.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "init", "-b", "main"], cwd=work, check=True, stdout=subprocess.DEVNULL
    )
    subprocess.run(["git", "config", "user.email", "qa@example.test"], cwd=work, check=True)
    subprocess.run(["git", "config", "user.name", "QA"], cwd=work, check=True)
    for relative, content in files.items():
        path = work / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    subprocess.run(["git", "add", "."], cwd=work, check=True)
    subprocess.run(
        ["git", "commit", "-m", "fixture"],
        cwd=work,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        ["git", "clone", "--bare", str(work), str(bare)],
        check=True,
        stdout=subprocess.DEVNULL,
    )


def _two_repo_root(tmp_path: Path) -> Path:
    repos_root = tmp_path / "repos"
    work_root = tmp_path / "work"
    _make_bare_repo(
        repos_root,
        work_root,
        "acme",
        "open",
        {"src/public.js": "export function publicHelper() {\n  return 1;\n}\n"},
    )
    _make_bare_repo(
        repos_root,
        work_root,
        "acme",
        "locked",
        {"src/hidden.js": "export function hiddenHelper() {\n  return 2;\n}\n"},
    )
    return repos_root


class TwoRepoAuth:
    """A user who is repo-visible to both repositories (e.g. via the issues
    unit) but native reqRepoCodeReader only grants code access to one."""

    def __init__(self):
        self.code_calls: list[set[str]] = []

    def visible_repositories(self, cookie: str):
        if cookie != "session=alice":
            return False, set()
        return True, {"acme/open", "acme/locked"}

    def code_readable_repositories(self, cookie: str, repos: set[str]):
        self.code_calls.append(set(repos))
        return {repo for repo in repos if repo != "acme/locked"}


def test_code_acl_narrows_content_results_but_keeps_repo_name_hit_end_to_end(tmp_path):
    root = _two_repo_root(tmp_path)
    db = open_database(tmp_path / "search.db")
    index_all(db, root)
    auth = TwoRepoAuth()
    with running_server(db, auth) as base:
        # A symbol defined only in the code-denied repo must not leak.
        status, payload = get_json(
            base, "/api/hypersearch?q=hiddenHelper", cookie="session=alice"
        )
        assert status == 200
        assert payload["results"] == []

        # The same symbol kind from the code-allowed repo must still resolve.
        status, payload = get_json(
            base, "/api/hypersearch?q=publicHelper", cookie="session=alice"
        )
        assert status == 200
        assert any(hit["repo"] == "acme/open" for hit in payload["results"])

        # Repository *existence* is not a code disclosure -- a repo-name hit
        # for the code-denied repo must still appear (it uses `allowed`, not
        # `code_scope`).
        status, payload = get_json(
            base, "/api/hypersearch?q=locked", cookie="session=alice"
        )
        assert status == 200
        assert any(
            hit["kind"] == "repository" and hit["repo"] == "acme/locked"
            for hit in payload["results"]
        )
    assert auth.code_calls == [{"acme/open", "acme/locked"}] * 3


class ScopeTrackingAuth(TwoRepoAuth):
    """Tracks the union of repo names ever passed to
    code_readable_repositories, across every call -- lets a test assert a
    query never causes any repo's code-ACL to be network-probed, without
    caring whether the (always-invoked, per contract) call itself happened
    with an empty set."""

    def __init__(self):
        super().__init__()
        self.probed_repos: set[str] = set()

    def code_readable_repositories(self, cookie: str, repos: set[str]):
        self.probed_repos |= set(repos)
        return super().code_readable_repositories(cookie, repos)


def test_repo_scoped_query_only_probes_code_acl_for_that_repo(tmp_path):
    root = _two_repo_root(tmp_path)
    db = open_database(tmp_path / "search.db")
    index_all(db, root)
    auth = TwoRepoAuth()
    with running_server(db, auth) as base:
        query = urllib.parse.quote("repo:acme/open publicHelper")
        status, payload = get_json(
            base, f"/api/hypersearch?q={query}", cookie="session=alice"
        )
        assert status == 200
        assert any(hit["repo"] == "acme/open" for hit in payload["results"])
    # A repo: qualifier must narrow the code-ACL candidate set to only the
    # named repo -- acme/locked is visible+indexed but can never match this
    # query, so it must never be probed.
    assert auth.code_calls == [{"acme/open"}]


def test_query_scoped_to_unreachable_repo_triggers_no_code_acl_probes(tmp_path):
    root = _two_repo_root(tmp_path)
    db = open_database(tmp_path / "search.db")
    index_all(db, root)
    auth = ScopeTrackingAuth()
    with running_server(db, auth) as base:
        query = urllib.parse.quote("repo:acme/ghost publicHelper")
        status, payload = get_json(
            base, f"/api/hypersearch?q={query}", cookie="session=alice"
        )
        assert status == 200
        assert payload["results"] == []
    # "acme/ghost" is neither visible nor indexed -- scoping to it must
    # short-circuit to zero DB lookups and zero code-ACL network probes,
    # for both real repos in this fixture.
    assert auth.probed_repos == set()


def test_locked_repo_name_hit_never_discloses_its_revision_sha(tmp_path):
    root = _two_repo_root(tmp_path)
    db = open_database(tmp_path / "search.db")
    index_all(db, root)
    locked_head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root / "acme" / "locked.git",
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert locked_head
    auth = TwoRepoAuth()
    with running_server(db, auth) as base:
        request = urllib.request.Request(base + "/api/hypersearch?q=locked")
        request.add_header("Cookie", "session=alice")
        with urllib.request.urlopen(request, timeout=2) as response:
            raw = response.read()
    payload = json.loads(raw)
    locked_hits = [
        hit
        for hit in payload["results"]
        if hit["kind"] == "repository" and hit["repo"] == "acme/locked"
    ]
    assert locked_hits
    assert "revision" not in locked_hits[0]
    # The raw HEAD SHA of a code-denied repo must never appear anywhere in
    # the response body, not merely be absent from one field's key.
    assert locked_head not in raw.decode()
