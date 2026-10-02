"""The search engine honours the per-request context between stages and inside subprocesses."""

import time

import pytest
from test_index_search import fixture_repo

from hypersearch.db import open_database
from hypersearch.deadline import DeadlineExceeded, RequestCancelled, RequestContext, bound
from hypersearch.indexer import index_all
from hypersearch.search import search


def test_cancelled_request_does_no_search_work(tmp_path):
    db = open_database(tmp_path / "search.db")
    context = RequestContext(30)
    context.cancel("client_disconnected")
    with bound(context):
        with pytest.raises(RequestCancelled):
            search(db, "needle", {"acme/demo"})


def test_ast_engine_is_cut_at_the_remaining_request_budget_not_its_own_two_seconds(
    tmp_path, controlled_ast
):
    root = fixture_repo(tmp_path)
    db = open_database(tmp_path / "coverage.db")
    index_all(db, root)
    executable, _ = controlled_ast("timeout")  # the stand-in sleeps five seconds
    started = time.perf_counter()
    with bound(RequestContext(0.5)):
        with pytest.raises(DeadlineExceeded):
            search(db, "ast:restoreFocus($A)", {"acme/demo"}, ast_grep=executable)
    assert time.perf_counter() - started < 1.4


def test_unbound_search_keeps_the_existing_engine_deadline_and_status(tmp_path, controlled_ast):
    root = fixture_repo(tmp_path)
    db = open_database(tmp_path / "coverage.db")
    index_all(db, root)
    executable, _ = controlled_ast("timeout")
    result = search(db, "ast:restoreFocus($A)", {"acme/demo"}, ast_grep=executable)
    assert result["coverage"]["ast"] == {"status": "timeout"}
