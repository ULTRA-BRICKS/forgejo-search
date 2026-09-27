from __future__ import annotations

import json
import re
import shutil
import sqlite3
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import quote

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
    # Defense in depth: search() already rejects empty ACLs before SQL.
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
        [*args, f"%{needle}%", needle, needle, f"%/{needle}%", min(limit, 12)],
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
) -> list[sqlite3.Row]:
    terms = _candidate_terms(q)
    if not terms:
        return []
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
        [*args, *scope_args, min(limit, 120)],
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
    for row in rows:
        for offset, line in enumerate(str(row["content"]).splitlines()):
            if not identifier.search(line):
                continue
            line_no = int(row["line_start"]) + offset
            key = (row["full_name"], row["path"], line_no)
            if key in definitions:
                continue
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


def _fts_hits(rows: list[sqlite3.Row], q: SearchQuery) -> list[SearchHit]:
    kind = "reference" if q.symbol_role == "reference" else "code"
    first = next(iter(lexical_terms(q.text)), "")
    hits: list[SearchHit] = []
    for row in rows:
        offset = 0
        if first:
            folded = str(row["content"]).casefold()
            pos = folded.find(first.casefold())
            if pos >= 0:
                offset = folded.count("\n", 0, pos)
        hits.append(
            _hit(
                row,
                kind=kind,
                score=_BASE_SCORE["text"] + min(9.0, max(0.0, -float(row["rank"]))),
                mode="text",
                line=int(row["line_start"]) + offset,
            )
        )
    return hits


def _signature_hits(rows: list[sqlite3.Row], q: SearchQuery) -> list[SearchHit]:
    signature = structural_signature(q.text)
    if not signature:
        return []
    hits: list[SearchHit] = []
    for row in rows:
        if signature not in str(row["signature"]):
            continue
        hits.append(
            _hit(
                row,
                kind="structure",
                score=_BASE_SCORE["structure"] - len(hits) * 0.01,
                mode="structure",
                line=int(row["line_start"]),
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

    deadline = time.monotonic() + 1.25
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
    ast_grep: str = "ast-grep",
) -> list[SearchHit]:
    executable = shutil.which(ast_grep) if "/" not in ast_grep else ast_grep
    if not rows or not executable or not Path(executable).exists():
        return []

    unique: dict[tuple[str, str], sqlite3.Row] = {}
    for row in rows:
        unique.setdefault((row["repo_path"], row["blob_oid"]), row)
        if len(unique) >= 20:
            break

    selected = list(unique.values())
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
        if not mapping:
            return []
        return _run_ast(root, mapping, q, limit, executable)


def _run_ast(
    root: Path,
    mapping: dict[str, sqlite3.Row],
    q: SearchQuery,
    limit: int,
    ast_grep: str,
) -> list[SearchHit]:
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
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []

    hits: list[SearchHit] = []
    for raw in process.stdout.splitlines():
        try:
            item = json.loads(raw)
        except json.JSONDecodeError:
            continue
        raw_file = Path(str(item.get("file", "")))
        resolved = (raw_file if raw_file.is_absolute() else root / raw_file).resolve()
        row = mapping.get(str(resolved))
        if row is None:
            continue
        start = item.get("range", {}).get("start", {}).get("line", 0)
        hits.append(
            _hit(
                row,
                kind="structure",
                score=_BASE_SCORE["ast"] - len(hits) * 0.01,
                mode="ast",
                line=int(start) + 1,
            )
        )
        if len(hits) >= limit:
            break
    return hits


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
) -> dict:
    q = parse_query(query)
    limit = max(1, min(int(limit), 100))
    if not allowed:
        return {"query": q.raw, "mode": q.mode, "results": []}

    code_scope = allowed if code_allowed is None else (allowed & code_allowed)
    hits: list[SearchHit] = []
    with database.connection() as connection:
        hits.extend(_repo_hits(connection, q, allowed, limit))
        if q.file_candidate and code_scope:
            hits.extend(_file_hits(connection, q, code_scope, limit))
        if q.symbol_candidate and q.symbol_role != "reference" and code_scope:
            hits.extend(_symbol_hits(connection, q, code_scope, limit))
        rows = (
            _fts_rows(connection, q, code_scope, max(limit, 40))
            if q.text and q.mode != "file" and code_scope
            else []
        )
        if q.symbol_role == "reference":
            definitions = _definition_keys(connection, q, rows)
            hits.extend(_reference_hits(rows, q, definitions, limit))
        else:
            hits.extend(_fts_hits(rows[:limit], q))
        if q.ast_candidate:
            ast_rows = rows or (
                _ast_scope_rows(connection, q, code_scope, max(limit, 40))
                if code_scope
                else []
            )
            hits.extend(_signature_hits(ast_rows, q))
            hits.extend(_ast_hits(ast_rows, q, limit, ast_grep))

    seen: set[tuple] = set()
    merged: list[dict] = []
    for hit in sorted(hits, key=lambda item: -item.score):
        key = (hit.repo, hit.path, hit.line, hit.kind)
        if key in seen:
            continue
        seen.add(key)
        merged.append(hit.to_dict())
        if len(merged) >= limit:
            break

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
        "inferred": inferred,
        "results": merged,
    }
