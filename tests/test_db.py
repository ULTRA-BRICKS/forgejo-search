import stat

from hypersearch.db import open_database


def test_search_database_and_parent_are_private(tmp_path):
    state = tmp_path / "state"
    db = open_database(state / "search.db")
    assert db.path.exists()
    assert stat.S_IMODE(state.stat().st_mode) == 0o700
    assert stat.S_IMODE(db.path.stat().st_mode) == 0o600
