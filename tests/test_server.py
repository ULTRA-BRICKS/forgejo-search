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
def running_server(db, auth, ast_grep="missing-ast-grep", **kwargs):
    instance = SearchServer(("127.0.0.1", 0), db, auth, ast_grep, **kwargs)
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


def test_request_deadline_retains_worker_capacity_until_blocked_auth_finishes(tmp_path):
    entered = threading.Event()
    release = threading.Event()

    class BlockedAuth(FakeAuth):
        def visible_repositories(self, cookie):
            entered.set()
            release.wait(3)
            return super().visible_repositories(cookie)

    db = open_database(tmp_path / "search.db")
    with running_server(db, BlockedAuth(), request_budget=0.05, request_workers=1) as base:
        try:
            started = time.monotonic()
            status, body = get_json(base, "/api/hypersearch?q=test", "session=alice")
            assert entered.is_set()
            assert status == 503
            assert body == {"error": "request_timeout"}
            assert time.monotonic() - started < 0.5
            status, body = get_json(base, "/api/hypersearch?q=test", "session=alice")
            assert (status, body) == (503, {"error": "search_busy"})
            assert get_json(base, "/health")[0] == 200
        finally:
            release.set()
        for _ in range(50):
            status, body = get_json(base, "/api/hypersearch", "session=alice")
            if status == 200:
                break
            time.sleep(0.01)
        assert status == 200


def test_cold_pagination_deadline_stops_pages_and_does_not_cache_late_grant(tmp_path):
    from hypersearch.auth import ForgejoAuth
    auth = ForgejoAuth("http://unused")
    pages = []

    def fetch(cookie, page):
        pages.append(page)
        time.sleep(0.08)
        return [{"repository": {"full_name": "acme/demo"}}]

    auth._fetch_page = fetch
    db = open_database(tmp_path / "search.db")
    try:
        with running_server(db, auth, request_budget=0.03, request_workers=1) as base:
            status, body = get_json(base, "/api/hypersearch?q=test", "session=alice")
            assert (status, body) == (503, {"error": "request_timeout"})
            time.sleep(0.15)
            assert pages == [1]
            assert not auth.cache
    finally:
        auth.close()


def test_visibility_and_code_share_request_budget(tmp_path, monkeypatch):
    from hypersearch import server as server_module
    searched = []

    class SlowPhases(FakeAuth):
        def visible_repositories(self, cookie):
            time.sleep(0.04)
            return super().visible_repositories(cookie)

        def code_readable_repositories(self, cookie, repos):
            time.sleep(0.08)
            return set(repos)

    monkeypatch.setattr(server_module, "search", lambda *a, **kw: searched.append(True))
    db = open_database(tmp_path / "search.db")
    with running_server(db, SlowPhases(), request_budget=0.08) as base:
        started = time.monotonic()
        status, body = get_json(base, "/api/hypersearch?q=test", "session=alice")
        assert (status, body) == (503, {"error": "request_timeout"})
        assert time.monotonic() - started < 0.3
        time.sleep(0.1)
        assert not searched


@pytest.mark.parametrize("request_budget", [0.03, 1.0])
def test_expired_code_worker_cannot_publish_grant(request_budget):
    from hypersearch.auth import ForgejoAuth
    from hypersearch.deadline import RequestTimeout, request_deadline
    auth = ForgejoAuth("http://unused", code_probe_budget=0.03)
    finished = threading.Event()

    def head(path, cookie):
        time.sleep(0.1)
        finished.set()
        return 200

    auth._head = head
    try:
        with (
            request_deadline(time.monotonic() + request_budget),
            pytest.raises((RequestTimeout, VisibilityUnavailable)),
        ):
            auth.code_readable_repositories("session=alice", {"acme/demo"})
        assert finished.wait(1)
    finally:
        auth.close()
    assert not auth._code_cache


@pytest.mark.parametrize("phase", ["visibility", "code"])
def test_transport_deadline_does_not_poison_session_backoff(phase):
    from hypersearch.auth import ForgejoAuth
    from hypersearch.deadline import RequestTimeout, request_deadline
    auth = ForgejoAuth("http://unused")

    def expired(*args):
        time.sleep(0.04)
        raise RequestTimeout()

    auth._get = expired
    auth._head = expired
    try:
        with (
            request_deadline(time.monotonic() + 0.01),
            pytest.raises(RequestTimeout),
        ):
            if phase == "visibility":
                auth.visible_repositories("session=alice")
            else:
                auth.code_readable_repositories("session=alice", {"acme/demo"})
    finally:
        auth.close()
    assert not auth._unavailable


def test_shared_code_probe_expiry_does_not_cancel_valid_follower():
    from concurrent.futures import ThreadPoolExecutor

    from hypersearch.auth import ForgejoAuth
    from hypersearch.deadline import RequestTimeout, request_deadline
    auth = ForgejoAuth("http://unused")
    entered = threading.Event()
    calls = []

    def head(path, cookie):
        calls.append(path)
        entered.set()
        time.sleep(0.12)
        return 200

    auth._head = head

    def query(budget):
        with request_deadline(time.monotonic() + budget):
            return auth.code_readable_repositories("session=alice", {"acme/demo"})

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            leader = executor.submit(query, 0.05)
            assert entered.wait(1)
            follower = executor.submit(query, 1.0)
            with pytest.raises(RequestTimeout):
                leader.result(timeout=2)
            assert follower.result(timeout=2) == {"acme/demo"}
        assert len(calls) == 2
        assert not auth._unavailable
    finally:
        auth.close()


def test_visibility_follower_reclaims_after_cancelled_leader():
    from concurrent.futures import ThreadPoolExecutor

    from hypersearch.auth import ForgejoAuth
    from hypersearch.deadline import RequestTimeout, request_deadline
    auth = ForgejoAuth("http://unused")
    entered = threading.Event()
    calls = []

    def page(cookie, number):
        calls.append(number)
        entered.set()
        time.sleep(0.08)
        return []

    auth._fetch_page = page

    def query(budget):
        with request_deadline(time.monotonic() + budget):
            return auth.visible_repositories("session=alice")

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            leader = executor.submit(query, 0.03)
            assert entered.wait(1)
            follower = executor.submit(query, 1.0)
            with pytest.raises(RequestTimeout):
                leader.result(timeout=2)
            assert follower.result(timeout=2) == (True, set())
        assert calls == [1, 1]
    finally:
        auth.close()


def test_health_is_exempt_from_search_budget(tmp_path):
    database = open_database(tmp_path / "search.db")

    class SlowHealthDatabase:
        @contextmanager
        def connection(self):
            time.sleep(0.05)
            with database.connection() as connection:
                yield connection

    with running_server(SlowHealthDatabase(), FakeAuth(), request_budget=0.01) as base:
        status, body = get_json(base, "/health")
        assert status == 200
        assert body["service"] == "hypersearch"


def test_shutdown_submit_race_returns_controlled_response(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor

    def shutdown_submit(self, *args, **kwargs):
        raise RuntimeError("cannot schedule new futures after shutdown")

    monkeypatch.setattr(ThreadPoolExecutor, "submit", shutdown_submit)
    db = open_database(tmp_path / "search.db")
    with running_server(db, FakeAuth()) as base:
        assert get_json(base, "/api/hypersearch", "session=alice") == (
            503, {"error": "search_unavailable"}
        )


def test_service_sigterm_exits_with_timed_out_blocked_worker(tmp_path):
    import signal
    import sys

    port_file = tmp_path / "port"
    script = '''
import sys, threading
from pathlib import Path
from hypersearch.db import open_database
from hypersearch.server import SearchServer
class BlockedAuth:
    def visible_repositories(self, cookie):
        threading.Event().wait()
server = SearchServer(("127.0.0.1",0),open_database(sys.argv[1]),BlockedAuth(),request_budget=0.02)
Path(sys.argv[2]).write_text(str(server.server_port))
try:
    server.serve_forever()
finally:
    server.server_close()
'''
    process = subprocess.Popen(
        [sys.executable, "-c", script, str(tmp_path / "service.db"), str(port_file)],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    try:
        for _ in range(200):
            if port_file.exists():
                break
            if process.poll() is not None:
                pytest.fail("service exited before readiness")
            time.sleep(0.01)
        assert port_file.exists()
        base = f"http://127.0.0.1:{port_file.read_text()}"
        assert get_json(base, "/api/hypersearch", "session=alice") == (
            503, {"error": "request_timeout"}
        )
        process.terminate()
        assert process.wait(timeout=2) == -signal.SIGTERM
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=2)
        process.communicate(timeout=2)


def test_shutdown_cancelled_queue_returns_controlled_response(tmp_path, monkeypatch):
    from concurrent.futures import Future, ThreadPoolExecutor

    def cancelled_submit(self, *args, **kwargs):
        future = Future()
        future.cancel()
        return future

    monkeypatch.setattr(ThreadPoolExecutor, "submit", cancelled_submit)
    db = open_database(tmp_path / "search.db")
    with running_server(db, FakeAuth()) as base:
        assert get_json(base, "/api/hypersearch", "session=alice") == (
            503, {"error": "search_unavailable"}
        )
