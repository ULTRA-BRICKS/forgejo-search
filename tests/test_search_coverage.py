"""Viewer-visible bounded coverage over real SQLite and Git fixtures.

Drive search's public response; denied indexed code must not influence metadata.
"""

import json
import subprocess

import pytest
from test_index_search import fixture_repo
from test_server import _make_bare_repo

from hypersearch.db import open_database
from hypersearch.indexer import index_all
from hypersearch.query import structural_signature
from hypersearch.search import search


def indexed_rows(tmp_path, count, *, repo="acme/needle", duplicate=False):
    db = open_database(tmp_path / "coverage.db")
    with db.connection() as connection:
        repo_id = connection.execute(
            "INSERT INTO repos(full_name,path,default_ref,revision,indexed_at) VALUES(?,?,?,?,0)",
            (repo, "/fixture", "main", "a" * 40),
        ).lastrowid
        doc_id = None
        for index in range(count):
            if not duplicate or doc_id is None:
                doc_id = connection.execute(
                    "INSERT INTO documents(repo_id,path,language,size,blob_oid) VALUES(?,?,?,?,?)",
                    (repo_id, f"needle{index:03}.js", "javascript", 10, "b" * 40),
                ).lastrowid
            content = "needle(value);"
            connection.execute(
                "INSERT INTO chunks(doc_id,line_start,content,signature) VALUES(?,1,?,?)",
                (doc_id, content, structural_signature(content)),
            )
            connection.execute(
                "INSERT INTO symbols(doc_id,name,kind,line,role,snippet) VALUES(?,?,?,1,?,?)",
                (doc_id, "needle", "function", "definition", content),
            )
    return db


@pytest.mark.parametrize("extra", [0, 1])
@pytest.mark.parametrize("stage,query,cap", [
    ("file_hits", "file needle", 3),
    ("symbol_hits", "def:needle", 3),
    ("lexical_candidates", "text:needle", 40),
])
def test_authorized_stage_exact_cap_and_sentinel(tmp_path, stage, query, cap, extra):
    db = indexed_rows(tmp_path, cap + extra)
    result = search(db, query, {"acme/needle"}, limit=3)
    assert result["coverage"]["limits"][stage] == {
        "limit": cap, "state": "truncated" if extra else "complete",
    }
    assert len(result["results"]) == 3


@pytest.mark.parametrize("extra", [0, 1])
def test_repository_cap_is_twelve_authorized_rows(tmp_path, extra):
    db = open_database(tmp_path / "coverage.db")
    allowed = {f"acme/needle{i:02}" for i in range(12 + extra)}
    with db.connection() as connection:
        for name in allowed | {"private/needle"}:
            connection.execute(
                "INSERT INTO repos(full_name,path,default_ref,revision,indexed_at) VALUES(?,?,?,?,0)",
                (name, "/fixture", "main", "a" * 40),
            )
    result = search(db, "needle", allowed, code_allowed=set())
    assert result["coverage"]["limits"]["repository_hits"] == {
        "limit": 12, "state": "truncated" if extra else "complete",
    }
    assert len(result["results"]) == 12


@pytest.mark.parametrize("extra", [0, 1])
def test_final_unique_limit_after_chunk_deduplication(tmp_path, extra):
    db = indexed_rows(tmp_path, 3, duplicate=True)
    with db.connection() as connection:
        if extra:
            connection.execute("UPDATE chunks SET line_start=2 WHERE id=3")
    result = search(db, "repo:acme/needle text:needle", {"acme/needle"}, limit=1)
    assert len(result["results"]) == 1
    assert result["coverage"]["limits"]["results"] == {
        "limit": 1, "state": "truncated" if extra else "complete",
    }


@pytest.mark.parametrize("extra", [0, 1])
def test_ast_distinct_file_cap_and_sentinel(tmp_path, controlled_ast, extra):
    root = tmp_path / "repos"
    _make_bare_repo(root, tmp_path / "work", "acme", "demo", {
        f"src/file{i:02}.js": "needle(value);\n" for i in range(20 + extra)
    })
    db = open_database(tmp_path / "coverage.db")
    index_all(db, root)
    executable, observed = controlled_ast()
    result = search(db, "ast:needle($A)", {"acme/demo"}, ast_grep=executable)
    assert result["coverage"]["ast"]["status"] == "ran"
    assert result["coverage"]["limits"]["ast_files"] == {
        "limit": 20, "state": "truncated" if extra else "complete",
    }
    assert len(json.loads(observed.read_text())) == 20
    assert len([hit for hit in result["results"] if hit["mode"] == "ast"]) == 20


@pytest.mark.parametrize("behavior,status", [
    ("positive", "ran"), ("no_match", "ran"), ("failed", "failed"),
    ("bad_json", "failed"), ("bad_shape", "failed"), ("bad_line", "failed"),
    ("timeout", "timeout"), ("missing", "unavailable"),
])
def test_ast_execution_outcomes_preserve_lexical_fallback(tmp_path, controlled_ast, behavior, status):
    root = fixture_repo(tmp_path)
    db = open_database(tmp_path / "coverage.db")
    index_all(db, root)
    executable, observed = controlled_ast(behavior)
    if behavior == "missing":
        executable += "-missing"
    result = search(db, "ast:restoreFocus($A)", {"acme/demo"}, ast_grep=executable)
    assert result["coverage"]["ast"] == {"status": status}
    assert any(hit["mode"] == "text" for hit in result["results"])
    assert any(hit["mode"] == "ast" for hit in result["results"]) == (behavior == "positive")
    assert executable not in json.dumps(result)
    assert "private diagnostic" not in json.dumps(result)
    if behavior != "missing":
        assert "restoreFocus" in observed.read_text()


def test_ast_no_candidates_does_not_claim_engine_availability(tmp_path):
    db = open_database(tmp_path / "coverage.db")
    result = search(db, "ast:needle($A)", {"acme/demo"}, ast_grep="missing-ast-grep")
    assert result["coverage"]["ast"] == {"status": "no_candidates"}
    assert result["coverage"]["limits"]["ast_files"]["state"] == "complete"


def test_missing_materialized_blob_is_unknown_not_complete(tmp_path, controlled_ast):
    db = indexed_rows(tmp_path, 1)
    executable, observed = controlled_ast()
    result = search(db, "ast:needle($A)", {"acme/needle"}, ast_grep=executable)
    assert result["coverage"]["ast"] == {"status": "failed"}
    assert result["coverage"]["limits"]["ast_files"]["state"] == "unknown"
    assert not observed.exists()


@pytest.mark.parametrize("query", ["needle", "file needle", "def:needle", "ref:needle", "text:needle", "ast:needle($A)"])
def test_denied_and_invisible_code_cannot_change_coverage(tmp_path, query):
    db = indexed_rows(tmp_path, 3)
    allowed = {"acme/needle", "acme/locked"}
    before = search(db, query, allowed, limit=2, code_allowed={"acme/needle"}, ast_grep="missing-ast-grep")
    with db.connection() as connection:
        for name in ["acme/locked", "private/needle"]:
            repo_id = connection.execute(
                "INSERT INTO repos(full_name,path,default_ref,revision,indexed_at) VALUES(?,?,?,?,0)",
                (name, "/private", "main", "c" * 40),
            ).lastrowid
            for index in range(45):
                doc_id = connection.execute(
                    "INSERT INTO documents(repo_id,path,language,size,blob_oid) VALUES(?,?,?,?,?)",
                    (repo_id, f"needle{index}.js", "javascript", 10, "d" * 40),
                ).lastrowid
                connection.execute("INSERT INTO chunks(doc_id,line_start,content,signature) VALUES(?,1,?,?)", (doc_id, "needle secret", "needle secret"))
                connection.execute("INSERT INTO symbols(doc_id,name,kind,line,role,snippet) VALUES(?,?,?,1,?,?)", (doc_id, "needle", "function", "definition", "secret"))
    after = search(db, query, allowed, limit=2, code_allowed={"acme/needle"}, ast_grep="missing-ast-grep")
    assert before["coverage"] == after["coverage"]
    assert "secret" not in json.dumps(after)


@pytest.mark.parametrize("limit,expected", [(0, 1), (150, 100), (50, 50)])
def test_reported_caps_match_clamped_limits(tmp_path, limit, expected):
    db = indexed_rows(tmp_path, 1)
    limits = search(db, "text:needle", {"acme/needle"}, limit=limit)["coverage"]["limits"]
    assert limits["results"]["limit"] == expected
    assert limits["repository_hits"]["limit"] == min(expected, 12)
    assert limits["lexical_candidates"]["limit"] == max(expected, 40)


def test_denied_corpus_ranking_cannot_change_downstream_coverage(tmp_path):
    db = open_database(tmp_path / "coverage.db")
    with db.connection() as connection:
        for name in ["acme/open", "private/denied"]:
            connection.execute(
                "INSERT INTO repos(full_name,path,default_ref,revision,indexed_at) VALUES(?,?,?,?,0)",
                (name, "/fixture", "main", "a" * 40),
            )
        for index in range(22):
            doc_id = connection.execute(
                "INSERT INTO documents(repo_id,path,language,size,blob_oid) VALUES(1,?,?,10,?)",
                (f"file{index}.js", "javascript", "b" * 40),
            ).lastrowid
            content = "alpha " * 15 + "beta" if index == 0 else "alpha " + "beta " * 15
            for repetition in range(40 if index == 0 else 1):
                connection.execute(
                    "INSERT INTO chunks(doc_id,line_start,content,signature) VALUES(?,?,?,?)",
                    (doc_id, repetition + 1, content, content),
                )
    before = search(db, "ast:alpha(beta)", {"acme/open"}, ast_grep="missing-ast-grep")
    with db.connection() as connection:
        for index in range(150):
            doc_id = connection.execute(
                "INSERT INTO documents(repo_id,path,language,size,blob_oid) VALUES(2,?,?,10,?)",
                (f"private{index}.js", "javascript", "c" * 40),
            ).lastrowid
            connection.execute(
                "INSERT INTO chunks(doc_id,line_start,content,signature) VALUES(?,1,?,?)",
                (doc_id, "alpha " * 15, "alpha " * 15),
            )
    after = search(db, "ast:alpha(beta)", {"acme/open"}, ast_grep="missing-ast-grep")
    assert before["coverage"] == after["coverage"]
    assert after["coverage"]["limits"]["lexical_candidates"]["state"] == "truncated"
    assert after["coverage"]["limits"]["ast_files"]["state"] == "unknown"
    assert after["coverage"]["limits"]["results"]["state"] == "unknown"


@pytest.mark.parametrize("extra", [0, 1])
def test_ast_scope_fallback_cap_and_sentinel(tmp_path, controlled_ast, extra):
    root = tmp_path / "repos"
    _make_bare_repo(root, tmp_path / "work", "acme", "demo", {
        f"file{index}.js": "different();\n" for index in range(40 + extra)
    })
    db = open_database(tmp_path / "coverage.db")
    index_all(db, root)
    executable, observed = controlled_ast("no_match")
    result = search(db, "ast:absent($A)", {"acme/demo"}, ast_grep=executable)
    assert result["coverage"]["limits"]["lexical_candidates"] == {
        "limit": 40, "state": "truncated" if extra else "complete",
    }
    assert result["coverage"]["limits"]["ast_files"]["state"] == (
        "unknown" if extra else "truncated"
    )
    assert result["coverage"]["ast"] == {"status": "ran"}
    assert result["results"] == []
    assert len(json.loads(observed.read_text())) == 20


def test_ast_file_cap_cannot_expose_denied_ranking_changes(tmp_path, controlled_ast):
    root = tmp_path / "repos"
    files = {
        f"match{index}.js": "alpha(beta(value)); // " + "alpha " * 15 + "\n"
        for index in range(10)
    }
    files.update({
        f"comment{index}.js": "// alpha " + "beta " * 15 + "\n"
        for index in range(11)
    })
    _make_bare_repo(root, tmp_path / "work", "acme", "open", files)
    db = open_database(tmp_path / "coverage.db")
    index_all(db, root)
    executable, observed = controlled_ast("selective")
    before = search(db, "ast:alpha(beta($A))", {"acme/open"}, ast_grep=executable)
    with db.connection() as connection:
        repo_id = connection.execute(
            "INSERT INTO repos(full_name,path,default_ref,revision,indexed_at) VALUES(?,?,?,?,0)",
            ("private/denied", "/fixture", "main", "c" * 40),
        ).lastrowid
        for index in range(150):
            doc_id = connection.execute(
                "INSERT INTO documents(repo_id,path,language,size,blob_oid) VALUES(?,?,?,?,?)",
                (repo_id, f"private{index}.js", "javascript", 10, "c" * 40),
            ).lastrowid
            connection.execute(
                "INSERT INTO chunks(doc_id,line_start,content,signature) VALUES(?,1,?,?)",
                (doc_id, "beta " * 15, "beta " * 15),
            )
    after = search(db, "ast:alpha(beta($A))", {"acme/open"}, ast_grep=executable)
    assert before["coverage"] == after["coverage"]
    assert after["coverage"]["limits"]["lexical_candidates"]["state"] == "complete"
    assert after["coverage"]["limits"]["ast_files"]["state"] == "truncated"
    assert after["coverage"]["limits"]["results"]["state"] == "unknown"
    assert len(json.loads(observed.read_text())) == 20


@pytest.mark.parametrize("behavior,limit,decode_seconds", [("positive", 30, 0.75), ("many", 1, 0.3)])
def test_ast_output_processing_shares_engine_deadline(tmp_path, controlled_ast, monkeypatch, behavior, limit, decode_seconds):
    root = fixture_repo(tmp_path)
    db = open_database(tmp_path / "coverage.db")
    index_all(db, root)
    executable, observed = controlled_ast(behavior)
    now = [0.0]

    run = subprocess.run
    loads = json.loads

    def run_engine(args, **kwargs):
        result = run(args, **kwargs)
        if args[0] == executable:
            now[0] += 1.5
        return result

    def decode_record(raw):
        result = loads(raw)
        now[0] += decode_seconds
        return result

    monkeypatch.setattr("hypersearch.search.time.monotonic", lambda: now[0])
    monkeypatch.setattr("hypersearch.search.subprocess.run", run_engine)
    monkeypatch.setattr("hypersearch.search.json.loads", decode_record)
    result = search(db, "ast:restoreFocus($A)", {"acme/demo"}, limit=limit, ast_grep=executable)
    assert observed.exists()
    assert result["coverage"]["ast"] == {"status": "timeout"}
    assert result["results"][0]["mode"] == "text"


def test_ast_json_stream_preserves_unicode_line_separators(tmp_path, controlled_ast):
    root = tmp_path / "repos"
    paths = ["normal.js", "a\u2028b.js", "a\u0085b.js", "a\u2029b.js"]
    _make_bare_repo(root, tmp_path / "work", "acme", "demo", {
        path: "needle(value);\n" for path in paths
    })
    db = open_database(tmp_path / "coverage.db")
    index_all(db, root)
    executable, observed = controlled_ast()
    result = search(db, "ast:needle($A)", {"acme/demo"}, ast_grep=executable)
    assert result["coverage"]["ast"] == {"status": "ran"}
    assert {hit["path"] for hit in result["results"] if hit["mode"] == "ast"} == set(paths)
    assert len(json.loads(observed.read_text())) == 4


def test_ast_match_surplus_does_not_discard_bounded_success(tmp_path, controlled_ast, monkeypatch):
    root = fixture_repo(tmp_path)
    db = open_database(tmp_path / "coverage.db")
    index_all(db, root)
    executable, observed = controlled_ast("many")
    now = [0.0]

    loads = json.loads

    def decode_record(raw):
        result = loads(raw)
        now[0] += 0.5
        return result

    monkeypatch.setattr("hypersearch.search.time.monotonic", lambda: now[0])
    monkeypatch.setattr("hypersearch.search.json.loads", decode_record)
    result = search(db, "ast:restoreFocus($A)", {"acme/demo"}, limit=1, ast_grep=executable)
    assert observed.exists()
    assert result["coverage"]["ast"] == {"status": "ran"}
    assert result["coverage"]["limits"]["results"]["state"] == "truncated"
    assert [(hit["mode"], hit["line"]) for hit in result["results"]] == [("ast", 1)]
