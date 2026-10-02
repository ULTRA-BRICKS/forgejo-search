import stat

from hypersearch.db import open_database


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


def test_index_connections_do_not_install_request_progress_callback(tmp_path, monkeypatch):
    import sqlite3
    import time

    from hypersearch.deadline import request_deadline
    database = open_database(tmp_path / "deadline.db")
    callbacks = []
    original_connect = sqlite3.connect

    class RecordingConnection(sqlite3.Connection):
        def set_progress_handler(self, callback, steps):
            callbacks.append(steps)
            return super().set_progress_handler(callback, steps)

    def connect(*args, **kwargs):
        return original_connect(*args, factory=RecordingConnection, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", connect)
    with database.connection() as connection:
        assert connection.execute("SELECT count(*) FROM repos").fetchone()[0] == 0
    assert callbacks == []
    with request_deadline(time.monotonic() + 1), database.connection() as connection:
        assert connection.execute("SELECT count(*) FROM repos").fetchone()[0] == 0
    assert callbacks == [1000]
