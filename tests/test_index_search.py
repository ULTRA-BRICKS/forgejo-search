import subprocess
from pathlib import Path

from hypersearch.db import open_database
from hypersearch.indexer import chunks_for, index_all, symbols_for
from hypersearch.search import search


def fixture_repo(tmp_path: Path):
    work = tmp_path / "work"
    bare = tmp_path / "repos" / "acme" / "demo.git"
    work.mkdir()
    bare.parent.mkdir(parents=True)
    subprocess.run(
        ["git", "init", "-b", "main"], cwd=work, check=True, stdout=subprocess.DEVNULL
    )
    subprocess.run(
        ["git", "config", "user.email", "qa@example.test"], cwd=work, check=True
    )
    subprocess.run(["git", "config", "user.name", "QA"], cwd=work, check=True)
    (work / "src").mkdir()
    (work / "src" / "focus.js").write_text(
        "export function restoreFocus(trigger) {\n  return trigger.focus();\n}\n"
    )
    (work / "README.md").write_text("# Demo\n")
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
    return bare.parent.parent


def test_index_and_hybrid_search(tmp_path):
    root = fixture_repo(tmp_path)
    db = open_database(tmp_path / "search.db")
    result = index_all(db, root)
    assert result[0]["documents"] == 2
    allowed = {"acme/demo"}
    symbol = search(db, "restoreFocus", allowed)
    assert any(x["kind"] == "definition" for x in symbol["results"])
    file_result = search(db, "focus.js", allowed)
    assert file_result["results"][0]["path"] == "src/focus.js"
    structural = search(
        db, "restoreFocus ( trigger )", allowed, ast_grep="missing-ast-grep"
    )
    assert any(x["path"] == "src/focus.js" for x in structural["results"])


def test_acl_is_hard_filter(tmp_path):
    root = fixture_repo(tmp_path)
    db = open_database(tmp_path / "search.db")
    index_all(db, root)
    assert search(db, "restoreFocus", set())["results"] == []


def test_unchanged_repo_skips_reindex(tmp_path):
    root = fixture_repo(tmp_path)
    db = open_database(tmp_path / "search.db")
    first = index_all(db, root)
    second = index_all(db, root)
    assert first[0]["changed"] is True
    assert second[0] == {
        "repo": "acme/demo",
        "changed": False,
        "documents": 0,
        "removed": 0,
        "symbols": 0,
    }


def test_ast_refinement_accepts_relative_ast_grep_paths(tmp_path):
    root = fixture_repo(tmp_path)
    db = open_database(tmp_path / "search.db")
    index_all(db, root)
    fake = tmp_path / "ast-grep"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import json,pathlib,sys\n"
        "root=pathlib.Path(sys.argv[-1])\n"
        "p=next(root.rglob('focus.js'))\n"
        "print(json.dumps({'file':str(p.relative_to(root)),"
        "'range':{'start':{'line':0}}}))\n"
    )
    fake.chmod(0o755)
    result = search(db, "restoreFocus(trigger)", {"acme/demo"}, ast_grep=str(fake))
    assert any(hit["kind"] == "structure" for hit in result["results"])


def test_symbol_parser_respects_language():
    line = "type Widget = string"
    assert symbols_for(line, "javascript") == []
    assert symbols_for(line, "typescript")[0][0] == "Widget"


def test_chunks_preserve_line_origins_with_overlap():
    content = "\n".join(f"line {i}" for i in range(1, 80))
    chunks = chunks_for(content)
    assert chunks[0][0] == 1
    assert chunks[1][0] == 29
    assert "line 29" in chunks[0][1]
    assert "line 29" in chunks[1][1]


def test_reindex_replaces_stale_chunks_and_symbols(tmp_path):
    root = fixture_repo(tmp_path)
    db = open_database(tmp_path / "search.db")
    index_all(db, root)

    work = tmp_path / "work"
    bare = tmp_path / "repos" / "acme" / "demo.git"
    (work / "src" / "focus.js").write_text(
        "export function restoreSelection(node) {\n  return node.focus();\n}\n"
    )
    subprocess.run(["git", "add", "."], cwd=work, check=True)
    subprocess.run(
        ["git", "commit", "-m", "rename symbol"],
        cwd=work,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        ["git", "--git-dir", str(bare), "fetch", str(work), "main:main"],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    result = index_all(db, root)
    assert result[0]["changed"] is True
    assert result[0]["documents"] == 1
    assert result[0]["removed"] == 0
    allowed = {"acme/demo"}
    assert not search(db, "restoreFocus", allowed)["results"]
    assert any(
        hit["kind"] == "definition"
        for hit in search(db, "restoreSelection", allowed)["results"]
    )


def test_prefix_search_returns_results_while_typing(tmp_path):
    root = fixture_repo(tmp_path)
    db = open_database(tmp_path / "search.db")
    index_all(db, root)
    result = search(db, "restor", {"acme/demo"})
    assert any(hit["path"] == "src/focus.js" for hit in result["results"])


def test_natural_definition_reference_and_file_search(tmp_path):
    root = fixture_repo(tmp_path)
    db = open_database(tmp_path / "search.db")
    index_all(db, root)
    allowed = {"acme/demo"}

    definition = search(db, "function restoreFocus", allowed)
    assert definition["results"][0]["kind"] == "definition"

    reference = search(db, "references restoreFocus", allowed)
    assert reference["results"] == []

    file_result = search(db, "file focus.js", allowed)
    assert file_result["results"][0]["path"] == "src/focus.js"


def test_global_repository_name_is_searchable(tmp_path):
    root = fixture_repo(tmp_path)
    db = open_database(tmp_path / "search.db")
    index_all(db, root)
    result = search(db, "demo", {"acme/demo"})
    assert any(
        hit["kind"] == "repository" and hit["repo"] == "acme/demo"
        for hit in result["results"]
    )


def test_text_hit_uses_exact_chunk_line_and_immutable_revision_url(tmp_path):
    root = fixture_repo(tmp_path)
    work = tmp_path / "work"
    bare = tmp_path / "repos" / "acme" / "demo.git"
    lines = [f"const filler{i} = {i};" for i in range(1, 37)]
    lines.append('console.log("needleLater");')
    (work / "src" / "late.js").write_text("\n".join(lines) + "\n")
    subprocess.run(["git", "add", "."], cwd=work, check=True)
    subprocess.run(
        ["git", "commit", "-m", "late line"],
        cwd=work,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    revision = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=work, text=True
    ).strip()
    subprocess.run(
        ["git", "--git-dir", str(bare), "fetch", str(work), "main:main"],
        check=True,
        stdout=subprocess.DEVNULL,
    )

    db = open_database(tmp_path / "search.db")
    index_all(db, root)
    hit = next(
        item
        for item in search(db, "needleLater", {"acme/demo"})["results"]
        if item["path"] == "src/late.js"
    )
    assert hit["line"] == 37
    assert hit["url"] == f"/acme/demo/src/commit/{revision}/src/late.js#L37"


def test_one_repo_index_failure_does_not_abort_other_repos(tmp_path, monkeypatch):
    root = fixture_repo(tmp_path)
    db = open_database(tmp_path / "search.db")
    from hypersearch import indexer

    original = indexer.index_repo

    def sometimes_fail(database, repo):
        if repo.full_name == "acme/demo":
            raise subprocess.TimeoutExpired("git ls-tree", 30)
        return original(database, repo)

    monkeypatch.setattr(indexer, "index_repo", sometimes_fail)
    results = indexer.index_all(db, root)
    assert results[0]["repo"] == "acme/demo"
    assert "error" in results[0]


def test_reference_search_returns_usages_but_not_definition(tmp_path):
    root = fixture_repo(tmp_path)
    work = tmp_path / "work"
    bare = tmp_path / "repos" / "acme" / "demo.git"
    (work / "src" / "use.js").write_text(
        "import { restoreFocus } from './focus.js';\nrestoreFocus(button);\n"
    )
    subprocess.run(["git", "add", "."], cwd=work, check=True)
    subprocess.run(
        ["git", "commit", "-m", "add usage"],
        cwd=work,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        ["git", "--git-dir", str(bare), "fetch", str(work), "main:main"],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    db = open_database(tmp_path / "search.db")
    index_all(db, root)
    result = search(db, "references restoreFocus", {"acme/demo"})
    refs = [hit for hit in result["results"] if hit["kind"] == "reference"]
    assert {(hit["path"], hit["line"]) for hit in refs} == {
        ("src/use.js", 1),
        ("src/use.js", 2),
    }
    assert all(hit["path"] != "src/focus.js" for hit in refs)


def test_ast_metavariable_keeps_literal_candidate_terms():
    from hypersearch.query import parse_query
    from hypersearch.search import _candidate_terms

    query = parse_query("ast:restoreFocus($A)")
    assert _candidate_terms(query) == ["restoreFocus"]


def test_reference_search_requires_identifier_boundaries(tmp_path):
    root = fixture_repo(tmp_path)
    work = tmp_path / "work"
    bare = tmp_path / "repos" / "acme" / "demo.git"
    (work / "src" / "similar.js").write_text(
        "restoreFocusV2(button);\nconst restoreFocusLegacy = 1;\n"
    )
    subprocess.run(["git", "add", "."], cwd=work, check=True)
    subprocess.run(
        ["git", "commit", "-m", "similar identifiers"],
        cwd=work,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        ["git", "--git-dir", str(bare), "fetch", str(work), "main:main"],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    db = open_database(tmp_path / "search.db")
    index_all(db, root)
    result = search(db, "references restoreFocus", {"acme/demo"})
    assert all(hit["path"] != "src/similar.js" for hit in result["results"])


def test_git_tree_path_validation_rejects_escape_and_git_metadata():
    from hypersearch.indexer import safe_git_path

    assert safe_git_path("src/ok.py")
    assert not safe_git_path("../escape.py")
    assert not safe_git_path("/absolute.py")
    assert not safe_git_path("src/../../escape.py")
    assert not safe_git_path(".git/config")
    assert not safe_git_path("src/.GIT/config")


def test_explicit_file_query_under_three_chars_does_not_scan(tmp_path):
    root = fixture_repo(tmp_path)
    db = open_database(tmp_path / "search.db")
    index_all(db, root)
    result = search(db, "type:file fo", {"acme/demo"})
    assert result["results"] == []


def test_missing_blob_does_not_abort_later_batch_results(tmp_path):
    fixture_repo(tmp_path)
    bare = tmp_path / "repos" / "acme" / "demo.git"
    valid = subprocess.check_output(
        ["git", "--git-dir", str(bare), "rev-parse", "HEAD:README.md"],
        text=True,
    ).strip()
    from hypersearch.search import _batch_blob_texts

    decoded = _batch_blob_texts(str(bare), ["0" * 40, valid], timeout=2)
    assert decoded[valid].startswith("# Demo")


def test_intent_ranking_prefers_definition_for_identifier(tmp_path):
    root = fixture_repo(tmp_path)
    db = open_database(tmp_path / "search.db")
    index_all(db, root)
    result = search(db, "restoreFocus", {"acme/demo"})
    assert result["results"][0]["kind"] == "definition"


def test_intent_ranking_prefers_repository_name_over_text_occurrences(tmp_path):
    root = fixture_repo(tmp_path)
    db = open_database(tmp_path / "search.db")
    index_all(db, root)
    result = search(db, "demo", {"acme/demo"})
    assert result["results"][0]["kind"] == "repository"
