import sqlite3
import stat
import threading
import time

import pytest

from hypersearch import deadline as scope
from hypersearch.db import open_database
from hypersearch.deadline import DeadlineExceeded, RequestCancelled, RequestContext

# Counts far past any budget below: about ten seconds of SQLite work if it is not stopped.
_LONG_STATEMENT = (
    "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n WHERE x < 100000000)"
    " SELECT count(*) FROM n"
)


def test_search_database_and_parent_are_private(tmp_path):
    state = tmp_path / "state"
    db = open_database(state / "search.db")
    assert db.path.exists()
    assert stat.S_IMODE(state.stat().st_mode) == 0o700
    assert stat.S_IMODE(db.path.stat().st_mode) == 0o600


def test_indexed_repo_names_chunks_large_candidate_sets(tmp_path):
    from hypersearch.db import indexed_repo_names

    db = open_database(tmp_path / "search.db")
    names = [f"acme/r{i}" for i in range(750)]
    with db.connection() as connection:
        connection.executemany(
            "INSERT INTO repos(full_name, path, default_ref, revision, indexed_at) "
            "VALUES (?, '/tmp/x', 'main', 'deadbeef', 0)",
            [(name,) for name in names],
        )
    # 750 candidates spans two 500-sized IN(...) chunks; every indexed name
    # must come back regardless of which chunk it landed in, and a
    # candidate that was never inserted must not appear.
    candidates = set(names) | {"acme/not-indexed"}
    with db.connection() as connection:
        found = indexed_repo_names(connection, candidates)
    assert found == set(names)
    assert "acme/not-indexed" not in found
    # An empty candidate set must short-circuit without touching the DB.
    with db.connection() as connection:
        assert indexed_repo_names(connection, set()) == set()


def test_a_request_past_its_deadline_does_not_stay_inside_one_sql_statement(tmp_path):
    database = open_database(tmp_path / "search.db")
    started = time.monotonic()
    with (
        scope.bound(RequestContext(0.2)),
        pytest.raises(DeadlineExceeded),
        database.connection() as connection,
    ):
        connection.execute(_LONG_STATEMENT).fetchone()
    assert time.monotonic() - started < 2.0


def test_a_cancelled_request_does_not_stay_inside_one_sql_statement(tmp_path):
    database = open_database(tmp_path / "search.db")
    context = RequestContext(60)
    timer = threading.Timer(0.2, context.cancel, ("client_disconnected",))
    started = time.monotonic()
    timer.start()
    try:
        with (
            scope.bound(context),
            pytest.raises(RequestCancelled) as raised,
            database.connection() as connection,
        ):
            connection.execute(_LONG_STATEMENT).fetchone()
    finally:
        timer.cancel()
    assert not isinstance(raised.value, DeadlineExceeded)
    assert time.monotonic() - started < 2.0


def test_index_connections_install_no_request_callback(tmp_path, monkeypatch):
    database = open_database(tmp_path / "search.db")
    installed = []
    connect = sqlite3.connect

    class Recording(sqlite3.Connection):
        def set_progress_handler(self, callback, steps):
            installed.append(steps)
            return super().set_progress_handler(callback, steps)

    monkeypatch.setattr(sqlite3, "connect", lambda *a, **kw: connect(*a, factory=Recording, **kw))
    with database.connection() as connection:
        assert connection.execute("SELECT count(*) FROM repos").fetchone()[0] == 0
    assert installed == []
    with scope.bound(RequestContext(5)), database.connection() as connection:
        assert connection.execute("SELECT count(*) FROM repos").fetchone()[0] == 0
    assert installed == [1000]
