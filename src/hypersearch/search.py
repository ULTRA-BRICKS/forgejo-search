"""Bounded indexed search for the authenticated HTTP handler and offline CLI.

Callers supply repository visibility and the narrower code-read scope. Sentinels
must use those same scopes; coverage never describes denied indexed contents.
"""

from __future__ import annotations

import json
import re
import shutil
import sqlite3
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass
from itertools import islice
from pathlib import Path
from urllib.parse import quote

from . import deadline as scope
from .db import Database
from .query import (
    SearchQuery,
    code_tokens,
    lexical_terms,
    parse_query,
    structural_signature,
)

_BASE_SCORE = {
    "ast": 80.0,
    "structure": 70.0,
    "symbol": 60.0,
    "repository": 55.0,
    "file": 50.0,
    "reference": 45.0,
    "text": 20.0,
}


@dataclass
class SearchHit:
    repo: str
    path: str
    language: str
    line: int
    kind: str
    score: float
    snippet: str
    mode: str
    revision: str

    def to_dict(self) -> dict:
        data = asdict(self)
        repo = "/".join(quote(part, safe="") for part in self.repo.split("/"))
        if self.kind == "repository":
            data["url"] = f"/{repo}"
            # Repository-name-only hits are built from the broader repo-
            # visibility set, not the narrower code-ACL set (repo existence
            # is visible even to a viewer denied code-read access -- see
            # `_repo_hits`'s own comment). The indexed HEAD commit SHA must
            # not leak to such a viewer: unlike a file/code hit's URL, a
            # repository hit's URL never needs it (just `/{repo}`).
            data.pop("revision", None)
            return data
        encoded_revision = quote(self.revision, safe="")
        encoded_path = "/".join(quote(part, safe="") for part in Path(self.path).parts)
        data["url"] = f"/{repo}/src/commit/{encoded_revision}/{encoded_path}"
        if self.line > 0:
            data["url"] += f"#L{self.line}"
        return data


def _allowed_clause(allowed: set[str]) -> tuple[str, list[str]]:
    # Empty code scopes must remain hard SQL denials, including sentinels.
    if not allowed:
        return "0", []
    marks = ",".join("?" for _ in allowed)
    return f"r.full_name IN ({marks})", sorted(allowed)


def _scope_clause(q: SearchQuery) -> tuple[str, list[str]]:
    clauses: list[str] = []
    args: list[str] = []
    if q.repo:
        clauses.append("r.full_name=?")
        args.append(q.repo)
    if q.owner:
        clauses.append("r.full_name LIKE ?")
        args.append(q.owner.rstrip("/") + "/%")
    if q.path:
        clauses.append("d.path LIKE ?")
        args.append("%" + q.path + "%")
    if q.lang:
        clauses.append("d.language=?")
        args.append(q.lang.lower())
    return (" AND ".join(clauses) if clauses else "1"), args


def _like_pattern_regex(pattern: str) -> re.Pattern[str]:
    """Translate a SQL `LIKE` pattern into an equivalent, case-insensitive
    regex. `_scope_clause` builds its `owner:` clause as `LIKE ?` with no
    `ESCAPE` clause, so SQLite treats a literal `%`/`_` inside `q.owner`
    itself as a wildcard, not a literal character -- this mirrors that
    exactly, rather than treating them as literal text.
    """
    parts = ["^"]
    for ch in pattern:
        if ch == "%":
            parts.append(".*")
        elif ch == "_":
            parts.append(".")
        else:
            parts.append(re.escape(ch))
    parts.append("$")
    return re.compile("".join(parts), re.IGNORECASE)


def scoped_repos(q: SearchQuery, repos: set[str]) -> set[str]:
    """Narrow `repos` to the subset an explicit `repo:`/`owner:` qualifier in
    `q` could possibly match: a case-insensitive exact match for `q.repo`,
    and for `q.owner` the exact same pattern `_scope_clause` builds for its
    `LIKE ?` clause above (`owner.rstrip("/") + "/%"`), matched via
    `_like_pattern_regex` so `%`/`_` wildcards behave identically to
    SQLite's unescaped `LIKE`. Both narrow together (ANDed), exactly like
    `_scope_clause` ANDs them into one SQL WHERE clause, when a query names
    both. This only ever intersects, never derives repo identity: with
    neither qualifier, `repos` is returned unchanged, since a
    full-text/full-index query legitimately still needs every candidate as a
    code-ACL probe target. Deliberately more permissive than `_scope_clause`
    on case (SQLite's default `=` is case-sensitive; this is not) -- safe
    because this only ever widens the *candidate set considered for probing*,
    never the final result set, which is still filtered by the real,
    case-sensitive SQL at search() time.
    """
    if not q.repo and not q.owner:
        return repos
    candidates = repos
    if q.repo:
        target = q.repo.lower()
        candidates = {repo for repo in candidates if repo.lower() == target}
    if q.owner:
        pattern = _like_pattern_regex(q.owner.rstrip("/") + "/%")
        candidates = {repo for repo in candidates if pattern.match(repo)}
    return candidates


def empty_coverage(limit: int = 30) -> dict:
    limit = max(1, min(int(limit), 100))
    return {
        "version": 1,
        "scope": "authorized_indexed_default_branch",
        "completeness": "bounded",
        "semantics": {"definitions": "pattern_based", "references": "lexical"},
        "ast": {"status": "not_requested"},
        "limits": {
            name: {"limit": cap, "state": "not_applicable"}
            for name, cap in (
                ("repository_hits", min(limit, 12)),
                ("file_hits", limit),
                ("symbol_hits", limit),
                ("lexical_candidates", max(limit, 40)),
                ("ast_files", 20),
                ("results", limit),
            )
        },
    }


def _limit_state(count: int, limit: int) -> str:
    return "truncated" if count > limit else "complete"


def _repo_hits(
    connection: sqlite3.Connection,
    q: SearchQuery,
    allowed: set[str],
    limit: int,
) -> list[SearchHit]:
    if not q.text or q.repo or q.path or q.lang or q.mode not in {"auto", "text"}:
        return []
    clause, args = _allowed_clause(allowed)
    owner_sql = ""
    if q.owner:
        owner_sql = " AND r.full_name LIKE ?"
        args.append(q.owner.rstrip("/") + "/%")
    needle = q.text.strip()
    rows = connection.execute(
        f"""SELECT r.full_name,r.revision
            FROM repos r
            WHERE {clause} {owner_sql} AND lower(r.full_name) LIKE lower(?)
            ORDER BY
              CASE
                WHEN lower(r.full_name)=lower(?) THEN 0
                WHEN lower(substr(r.full_name,instr(r.full_name,'/')+1))=lower(?) THEN 1
                WHEN lower(r.full_name) LIKE lower(?) THEN 2
                ELSE 3
              END,
              length(r.full_name),r.full_name
            LIMIT ?""",
        [*args, f"%{needle}%", needle, needle, f"%/{needle}%", limit],
    ).fetchall()
    return [
        SearchHit(
            repo=row["full_name"],
            path="",
            language="repository",
            line=0,
            kind="repository",
            score=_BASE_SCORE["repository"] - index * 0.01,
            snippet=row["full_name"],
            mode="repository",
            revision=row["revision"],
        )
        for index, row in enumerate(rows)
    ]


def _hit(
    row: sqlite3.Row,
    *,
    kind: str,
    score: float,
    mode: str,
    line: int,
) -> SearchHit:
    return SearchHit(
        repo=row["full_name"],
        path=row["path"],
        language=row["language"],
        line=max(1, int(line)),
        kind=kind,
        score=score,
        snippet=str(row["snippet"] or "")[:500],
        mode=mode,
        revision=row["revision"],
    )


def _file_hits(
    connection: sqlite3.Connection,
    q: SearchQuery,
    allowed: set[str],
    limit: int,
) -> list[SearchHit]:
    clause, args = _allowed_clause(allowed)
    scope, scope_args = _scope_clause(q)
    needle = q.text or q.path or ""
    if len(needle) < 3:
        # FTS5 trigram cannot accelerate shorter patterns; never turn a
        # search-as-you-type keystroke into an unbounded virtual-table scan.
        return []
    match = '"' + needle.replace('"', '""') + '"'
    rows = connection.execute(
        f"""SELECT r.full_name,r.revision,d.path,d.language,d.path AS snippet
            FROM paths_fts
            JOIN documents d ON d.id=paths_fts.rowid
            JOIN repos r ON r.id=d.repo_id
            WHERE paths_fts MATCH ? AND {clause} AND {scope}
            ORDER BY CASE WHEN lower(d.path)=lower(?) THEN 0
                          WHEN lower(d.path) LIKE lower(?) THEN 1 ELSE 2 END,
                     length(d.path),d.path
            LIMIT ?""",
        [match, *args, *scope_args, needle, f"%/{needle}", limit],
    ).fetchall()
    return [
        _hit(
            row,
            kind="file",
            score=_BASE_SCORE["file"] - i * 0.01,
            mode="file",
            line=1,
        )
        for i, row in enumerate(rows)
    ]


def _symbol_hits(
    connection: sqlite3.Connection,
    q: SearchQuery,
    allowed: set[str],
    limit: int,
) -> list[SearchHit]:
    clause, args = _allowed_clause(allowed)
    scope, scope_args = _scope_clause(q)
    name = q.symbol or q.text
    role_sql = " AND s.role=?" if q.symbol_role == "definition" else ""
    params = [*args, *scope_args, name]
    if role_sql:
        params.append("definition")
    params.append(limit)
    rows = connection.execute(
        f"""SELECT r.full_name,r.revision,d.path,d.language,
                   s.snippet,s.line,s.role
            FROM symbols s
            JOIN documents d ON d.id=s.doc_id
            JOIN repos r ON r.id=d.repo_id
            WHERE {clause} AND {scope} AND s.name=? COLLATE NOCASE {role_sql}
            ORDER BY CASE s.role WHEN 'definition' THEN 0 ELSE 1 END,s.line
            LIMIT ?""",
        params,
    ).fetchall()
    return [
        _hit(
            row,
            kind=row["role"],
            score=_BASE_SCORE["symbol"] - i * 0.01,
            mode="symbol",
            line=int(row["line"]),
        )
        for i, row in enumerate(rows)
    ]


def _candidate_terms(q: SearchQuery) -> list[str]:
    if q.ast_candidate:
        return [
            token
            for token in code_tokens(q.text)
            if token and not token.startswith("$") and token[0].isalpha()
        ]
    return [term for term in lexical_terms(q.text) if term]


def _fts_rows(
    connection: sqlite3.Connection,
    q: SearchQuery,
    allowed: set[str],
    limit: int,
    terms: list[str],
) -> list[sqlite3.Row]:
    pieces: list[str] = []
    for index, term in enumerate(terms):
        escaped = term.replace('"', '""')
        suffix = "*" if index == len(terms) - 1 and len(term) >= 2 else ""
        pieces.append(f'"{escaped}"{suffix}')
    match = " AND ".join(pieces)
    clause, args = _allowed_clause(allowed)
    scope, scope_args = _scope_clause(q)
    return connection.execute(
        f"""SELECT d.id AS doc_id,r.full_name,r.revision,r.path AS repo_path,
                   d.path,d.language,d.blob_oid,c.line_start,c.content,c.signature,
                   snippet(chunks_fts,0,'<mark>','</mark>',' … ',18) AS snippet,
                   bm25(chunks_fts,1.0,0.2) AS rank
            FROM chunks_fts
            JOIN chunks c ON c.id=chunks_fts.rowid
            JOIN documents d ON d.id=c.doc_id
            JOIN repos r ON r.id=d.repo_id
            WHERE chunks_fts MATCH ? AND {clause} AND {scope}
            ORDER BY rank LIMIT ?""",
        [match, *args, *scope_args, limit],
    ).fetchall()


def _ast_scope_rows(
    connection: sqlite3.Connection,
    q: SearchQuery,
    allowed: set[str],
    limit: int,
) -> list[sqlite3.Row]:
    clause, args = _allowed_clause(allowed)
    scope, scope_args = _scope_clause(q)
    return connection.execute(
        f"""SELECT d.id AS doc_id,r.full_name,r.revision,r.path AS repo_path,
                   d.path,d.language,d.blob_oid,c.line_start,c.content,c.signature,
                   c.content AS snippet,0.0 AS rank
            FROM chunks c
            JOIN documents d ON d.id=c.doc_id
            JOIN repos r ON r.id=d.repo_id
            WHERE {clause} AND {scope}
            ORDER BY d.id,c.line_start LIMIT ?""",
        [*args, *scope_args, limit],
    ).fetchall()


def _definition_keys(
    connection: sqlite3.Connection,
    q: SearchQuery,
    rows: list[sqlite3.Row],
) -> set[tuple[str, str, int]]:
    name = q.symbol or q.text
    doc_ids = sorted({int(row["doc_id"]) for row in rows})
    if not doc_ids:
        return set()
    marks = ",".join("?" for _ in doc_ids)
    definitions = connection.execute(
        f"""SELECT r.full_name,d.path,s.line
            FROM symbols s
            JOIN documents d ON d.id=s.doc_id
            JOIN repos r ON r.id=d.repo_id
            WHERE s.doc_id IN ({marks})
              AND s.name=? COLLATE NOCASE
              AND s.role='definition'""",
        [*doc_ids, name],
    ).fetchall()
    return {(row["full_name"], row["path"], int(row["line"])) for row in definitions}


def _reference_hits(
    rows: list[sqlite3.Row],
    q: SearchQuery,
    definitions: set[tuple[str, str, int]],
    limit: int,
) -> list[SearchHit]:
    needle = q.symbol or q.text
    identifier = re.compile(
        rf"(?<![\w$]){re.escape(needle)}(?![\w$])",
        re.IGNORECASE,
    )
    hits: list[SearchHit] = []
    seen: set[tuple[str, str, int]] = set()
    for row in rows:
        for offset, line in enumerate(str(row["content"]).splitlines()):
            if not identifier.search(line):
                continue
            line_no = int(row["line_start"]) + offset
            key = (row["full_name"], row["path"], line_no)
            if key in definitions or key in seen:
                continue
            seen.add(key)
            hit = _hit(
                row,
                kind="reference",
                score=_BASE_SCORE["reference"]
                + min(9.0, max(0.0, -float(row["rank"])))
                - len(hits) * 0.001,
                mode="reference",
                line=line_no,
            )
            hit.snippet = line.strip()[:500]
            hits.append(hit)
            if len(hits) >= limit:
                return hits
    return hits


def _fts_hits(rows: list[sqlite3.Row], q: SearchQuery, limit: int) -> list[SearchHit]:
    kind = "reference" if q.symbol_role == "reference" else "code"
    first = next(iter(lexical_terms(q.text)), "")
    hits: list[SearchHit] = []
    seen: set[tuple[str, str, int]] = set()
    for row in rows:
        offset = 0
        if first:
            folded = str(row["content"]).casefold()
            pos = folded.find(first.casefold())
            if pos >= 0:
                offset = folded.count("\n", 0, pos)
        line = int(row["line_start"]) + offset
        key = (row["full_name"], row["path"], line)
        if key in seen:
            continue
        seen.add(key)
        hits.append(
            _hit(
                row,
                kind=kind,
                score=_BASE_SCORE["text"] + min(9.0, max(0.0, -float(row["rank"]))),
                mode="text",
                line=line,
            )
        )
        if len(hits) >= limit:
            break
    return hits


def _signature_hits(rows: list[sqlite3.Row], q: SearchQuery) -> list[SearchHit]:
    signature = structural_signature(q.text)
    if not signature:
        return []
    hits: list[SearchHit] = []
    for row in rows:
        position = str(row["signature"]).find(signature)
        if position < 0:
            continue
        lines = str(row["content"]).splitlines()
        line_offset = 0
        if len(lines) > 1:
            token_offset = str(row["signature"])[:position].count(" ")
            for line_offset, line in enumerate(lines):
                if line_offset == len(lines) - 1:
                    break
                count = sum(1 for token in islice(code_tokens(line), token_offset + 1))
                if token_offset < count:
                    break
                token_offset -= count
        hits.append(
            _hit(
                row,
                kind="structure",
                score=_BASE_SCORE["structure"] - len(hits) * 0.01,
                mode="structure",
                line=int(row["line_start"]) + line_offset,
            )
        )
    return hits


def _decode_blob(data: bytes) -> str | None:
    if not data or b"\x00" in data[:8192]:
        return None
    text = data.decode("utf-8", "replace")
    if text.count("\ufffd") > max(3, len(text) // 200):
        return None
    return text


def _batch_blob_texts(
    repo_path: str,
    oids: list[str],
    *,
    timeout: float,
) -> dict[str, str]:
    if not oids or timeout <= 0:
        return {}
    try:
        process = subprocess.run(
            ["git", "--git-dir", repo_path, "cat-file", "--batch"],
            input=("".join(oid + "\n" for oid in oids)).encode(),
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    if process.returncode != 0:
        return {}

    output = process.stdout
    offset = 0
    decoded: dict[str, str] = {}
    for requested in oids:
        end = output.find(b"\n", offset)
        if end < 0:
            break
        header = output[offset:end].decode("ascii", "replace").split()
        offset = end + 1
        if len(header) == 2 and header[1] in {"missing", "filtered"}:
            continue
        if len(header) != 3 or header[1] != "blob":
            break
        try:
            size = int(header[2])
        except ValueError:
            break
        body = output[offset : offset + size]
        if len(body) != size:
            break
        offset += size
        if offset < len(output) and output[offset : offset + 1] == b"\n":
            offset += 1
        text = _decode_blob(body)
        if text is not None:
            decoded[requested] = text
    return decoded


def _candidate_blob_texts(rows: list[sqlite3.Row]) -> dict[tuple[str, str], str]:
    groups: dict[str, list[str]] = {}
    for row in rows:
        oids = groups.setdefault(str(row["repo_path"]), [])
        oid = str(row["blob_oid"])
        if oid not in oids:
            oids.append(oid)

    deadline = time.monotonic() + scope.clamp(1.25)
    decoded: dict[tuple[str, str], str] = {}
    for repo_path, oids in groups.items():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        for oid, content in _batch_blob_texts(
            repo_path,
            oids,
            timeout=max(0.05, remaining),
        ).items():
            decoded[(repo_path, oid)] = content
    return decoded


def _ast_hits(
    rows: list[sqlite3.Row],
    q: SearchQuery,
    limit: int,
    ast_grep: str,
    candidates_complete: bool,
) -> tuple[list[SearchHit], str, str]:
    if not rows:
        return [], "no_candidates", "complete"
    unique: dict[tuple[str, str], sqlite3.Row] = {}
    for row in rows:
        unique.setdefault((row["full_name"], row["path"]), row)
        if len(unique) > 20:
            break
    # A capped chunk prefix cannot establish file exhaustion. In particular,
    # FTS rank uses corpus statistics, so its distinct-path count is not safe
    # coverage evidence when inaccessible documents can reorder that prefix.
    files_state = (
        _limit_state(len(unique), 20) if candidates_complete else "unknown"
    )
    executable = shutil.which(ast_grep) if "/" not in ast_grep else ast_grep
    if not executable or not Path(executable).is_file():
        return [], "unavailable", files_state

    selected = list(unique.values())[:20]
    contents = _candidate_blob_texts(selected)
    with tempfile.TemporaryDirectory(prefix="hypersearch-ast-") as tmp:
        root = Path(tmp).resolve()
        mapping: dict[str, sqlite3.Row] = {}
        for index, row in enumerate(selected):
            key = (str(row["repo_path"]), str(row["blob_oid"]))
            content = contents.get(key)
            if content is None:
                continue
            namespace = (root / str(index)).resolve()
            target = (namespace / str(row["path"])).resolve()
            if not target.is_relative_to(namespace):
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            mapping[str(target)] = row
        if len(mapping) != len(selected):
            files_state = "unknown" if files_state != "truncated" else files_state
        if not mapping:
            return [], "failed", files_state
        hits, status = _run_ast(root, mapping, q, limit, executable)
        return hits, status, files_state


def _run_ast(
    root: Path,
    mapping: dict[str, sqlite3.Row],
    q: SearchQuery,
    limit: int,
    ast_grep: str,
) -> tuple[list[SearchHit], str]:
    budget = scope.clamp(2)
    deadline = time.monotonic() + budget
    try:
        process = subprocess.run(
            [
                ast_grep,
                "run",
                "--pattern",
                q.text,
                "--strictness",
                "relaxed",
                "--json=stream",
                str(root),
            ],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=budget,
            check=False,
        )
    except subprocess.TimeoutExpired:
        # The budget is the engine's own two seconds or whatever the request has left;
        # only the latter is the caller's deadline rather than an engine timeout.
        scope.checkpoint()
        return [], "timeout"
    except OSError:
        return [], "unavailable"
    except UnicodeError:
        return [], "failed"
    # ast-grep run --json=stream returns zero even for no matches.
    if process.returncode != 0:
        return [], "failed"

    hits: list[SearchHit] = []
    seen: set[tuple[str, str, int]] = set()
    resolved_files: dict[str, sqlite3.Row] = {}
    # JSON-stream framing is LF, not Unicode's broader splitlines boundaries.
    for record in re.finditer(r"[^\n]+", process.stdout):
        if time.monotonic() >= deadline:
            return [], "timeout"
        raw = record.group()
        try:
            item = json.loads(raw)
            filename = item["file"]
            if not isinstance(filename, str):
                return [], "failed"
            start = item["range"]["start"]["line"]
            if type(start) is not int or start < 0:
                return [], "failed"
            row = resolved_files.get(filename)
            if row is None:
                raw_file = Path(filename)
                resolved = (raw_file if raw_file.is_absolute() else root / raw_file).resolve()
                row = mapping.get(str(resolved))
                if row is None:
                    return [], "failed"
                resolved_files[filename] = row
        except (ValueError, TypeError, KeyError, OSError):
            return [], "failed"
        key = (row["full_name"], row["path"], start)
        if key in seen:
            continue
        seen.add(key)
        hits.append(
            _hit(
                row,
                kind="structure",
                score=_BASE_SCORE["ast"] - len(hits) * 0.01,
                mode="ast",
                line=start + 1,
            )
        )
        if len(hits) >= limit:
            break
    if time.monotonic() >= deadline:
        return [], "timeout"
    return hits, "ran"


def search(
    database: Database,
    query: str,
    allowed: set[str],
    limit: int = 30,
    ast_grep: str = "ast-grep",
    *,
    # Narrows every hit type EXCEPT repository-name hits to the subset of
    # `allowed` the caller can actually read code from (Forgejo's
    # reqRepoCodeReader / unit.TypeCode, verified upstream by
    # ForgejoAuth.code_readable_repositories before this is called). `None`
    # (the default) means "no narrower than repo visibility" -- this is what
    # cli.py's local `query` subcommand relies on: it is a trusted,
    # local/offline entry point operated by whoever passes `--allow` directly
    # on the command line, not a network-facing surface, so it intentionally
    # never has a code-ACL layer to narrow against.
    code_allowed: set[str] | None = None,
    # `allowed` is a native-narrowed candidate hint (see ForgejoAuth.visible_repositories),
    # not the viewer's full list: an empty hint then says nothing about the viewer, so the
    # inferred-intent field is kept exactly as it would be for a signed-in viewer.
    narrowed: bool = False,
) -> dict:
    q = parse_query(query)
    limit = max(1, min(int(limit), 100))
    coverage = empty_coverage(limit)
    stages = coverage["limits"]
    if not query.strip():
        return {
            "query": q.raw, "mode": q.mode, "results": [],
            **({"inferred": "text"} if allowed or narrowed else {}),
            "coverage": coverage,
        }

    code_scope = allowed if code_allowed is None else (allowed & code_allowed)
    scope.checkpoint()
    hits: list[SearchHit] = []
    candidate_limit = stages["lexical_candidates"]["limit"]
    with database.connection() as connection:
        if q.text and not (q.repo or q.path or q.lang) and q.mode in {"auto", "text"}:
            cap = stages["repository_hits"]["limit"]
            repo_hits = _repo_hits(connection, q, allowed, cap + 1)
            stages["repository_hits"]["state"] = _limit_state(len(repo_hits), cap)
            hits.extend(repo_hits[:cap])
        if q.file_candidate and len(q.text or q.path or "") >= 3:
            file_hits = _file_hits(connection, q, code_scope, limit + 1)
            stages["file_hits"]["state"] = _limit_state(len(file_hits), limit)
            hits.extend(file_hits[:limit])
        if q.symbol_candidate and q.symbol_role != "reference":
            symbol_hits = _symbol_hits(connection, q, code_scope, limit + 1)
            stages["symbol_hits"]["state"] = _limit_state(len(symbol_hits), limit)
            hits.extend(symbol_hits[:limit])
        scope.checkpoint()
        rows = []
        terms = _candidate_terms(q) if q.text and q.mode != "file" else []
        if terms:
            rows = _fts_rows(connection, q, code_scope, candidate_limit + 1, terms)
            stages["lexical_candidates"]["state"] = _limit_state(len(rows), candidate_limit)
            rows = rows[:candidate_limit]
        if q.symbol_role == "reference":
            definitions = _definition_keys(connection, q, rows)
            hits.extend(_reference_hits(rows, q, definitions, limit + 1))
        else:
            hits.extend(_fts_hits(rows, q, limit + 1))
        scope.checkpoint()
        if q.ast_candidate:
            ast_rows = rows
            if not ast_rows:
                ast_rows = _ast_scope_rows(connection, q, code_scope, candidate_limit + 1)
                stages["lexical_candidates"]["state"] = _limit_state(len(ast_rows), candidate_limit)
                ast_rows = ast_rows[:candidate_limit]
            hits.extend(_signature_hits(ast_rows, q))
            ast_hits, status, files_state = _ast_hits(
                ast_rows, q, limit + 1, ast_grep,
                stages["lexical_candidates"]["state"] == "complete",
            )
            coverage["ast"]["status"] = status
            stages["ast_files"]["state"] = files_state
            hits.extend(ast_hits)

    scope.checkpoint()
    seen: set[tuple] = set()
    merged: list[dict] = []
    for hit in sorted(hits, key=lambda item: -item.score):
        key = (hit.repo, hit.path, hit.line, hit.kind)
        if key in seen:
            continue
        seen.add(key)
        merged.append(hit.to_dict())
        if len(merged) > limit:
            break
    stages["results"]["state"] = (
        "unknown" if (
            stages["lexical_candidates"]["state"] == "truncated"
            or stages["ast_files"]["state"] in {"truncated", "unknown"}
        )
        else _limit_state(len(merged), limit)
    )

    inferred = (
        "ast"
        if q.ast_candidate
        else "file"
        if q.file_candidate
        else "symbol"
        if q.symbol_candidate
        else "text"
    )
    return {
        "query": q.raw,
        "mode": q.mode,
        **({"inferred": inferred} if allowed or narrowed else {}),
        "results": merged[:limit],
        "coverage": coverage,
    }
