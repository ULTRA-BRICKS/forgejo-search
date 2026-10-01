from __future__ import annotations

import re
import sqlite3
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .db import Database, clear_repo_documents
from .query import structural_signature

MAX_FILE_BYTES = 512 * 1024
CHUNK_LINES = 32
CHUNK_OVERLAP = 4
_SKIP_NAMES = {".DS_Store", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"}
_SKIP_DIRS = {"node_modules", "vendor", ".git", "dist"}
_LANG = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".rs": "rust",
    ".go": "go",
    ".java": "java",
    ".kt": "kotlin",
    ".swift": "swift",
    ".rb": "ruby",
    ".php": "php",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".md": "markdown",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".nix": "nix",
    ".sql": "sql",
    ".html": "html",
    ".css": "css",
}
_PATTERNS = {
    "javascript": [
        re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)"),
        re.compile(r"^\s*(?:export\s+)?class\s+([A-Za-z_$][\w$]*)"),
    ],
    "typescript": [
        re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)"),
        re.compile(r"^\s*(?:export\s+)?class\s+([A-Za-z_$][\w$]*)"),
        re.compile(r"^\s*(?:export\s+)?(?:interface|type|enum)\s+([A-Za-z_$][\w$]*)"),
    ],
    "python": [
        re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_][\w]*)"),
        re.compile(r"^\s*class\s+([A-Za-z_][\w]*)"),
    ],
    "rust": [
        re.compile(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_][\w]*)"),
        re.compile(r"^\s*(?:pub\s+)?(?:struct|enum|trait)\s+([A-Za-z_][\w]*)"),
    ],
    "go": [
        re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_][\w]*)"),
    ],
}


@dataclass(frozen=True)
class Repo:
    full_name: str
    path: Path
    default_ref: str
    revision: str


def language_for(path: str) -> str:
    return _LANG.get(Path(path).suffix.lower(), "text")


def symbols_for(content: str, language: str) -> list[tuple[str, str, int, str, str]]:
    patterns = _PATTERNS.get(language, ())
    found: list[tuple[str, str, int, str, str]] = []
    for line_no, line in enumerate(content.splitlines(), 1):
        for pattern in patterns:
            match = pattern.search(line)
            if match:
                found.append(
                    (
                        match.group(1),
                        "symbol",
                        line_no,
                        "definition",
                        line.strip()[:500],
                    )
                )
                break
    return found


def chunks_for(content: str) -> list[tuple[int, str, str]]:
    lines = content.splitlines()
    if not lines:
        return [(1, "", "")]
    step = max(1, CHUNK_LINES - CHUNK_OVERLAP)
    chunks: list[tuple[int, str, str]] = []
    for start in range(0, len(lines), step):
        block = "\n".join(lines[start : start + CHUNK_LINES])
        chunks.append((start + 1, block, structural_signature(block)))
        if start + CHUNK_LINES >= len(lines):
            break
    return chunks


def discover_repos(root: str | Path) -> list[Repo]:
    root = Path(root)
    repos: list[Repo] = []
    for git_dir in sorted(root.glob("*/*.git")):
        full_name = f"{git_dir.parent.name}/{git_dir.name[:-4]}"
        try:
            default_ref = subprocess.check_output(
                ["git", "--git-dir", str(git_dir), "symbolic-ref", "-q", "HEAD"],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=5,
            ).strip()
            revision = subprocess.check_output(
                ["git", "--git-dir", str(git_dir), "rev-parse", "HEAD"],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=5,
            ).strip()
        except (subprocess.SubprocessError, OSError):
            continue
        if revision:
            repos.append(Repo(full_name, git_dir, default_ref, revision))
    return repos


def safe_git_path(path: str) -> bool:
    pure = PurePosixPath(path)
    return not (
        pure.is_absolute()
        or any(part in {"", ".", ".."} for part in pure.parts)
        or any(part.lower() == ".git" for part in pure.parts)
    )


def _tree_entries(repo: Repo) -> list[tuple[str, int, str]]:
    raw = subprocess.check_output(
        ["git", "--git-dir", str(repo.path), "ls-tree", "-r", "-l", "-z", repo.revision],
        timeout=30,
    )
    entries: list[tuple[str, int, str]] = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        meta, path_bytes = record.split(b"\t", 1)
        parts = meta.split()
        if len(parts) != 4 or parts[1] != b"blob" or parts[3] == b"-":
            continue
        size = int(parts[3])
        path = path_bytes.decode("utf-8", "surrogateescape")
        pure = PurePosixPath(path)
        if not safe_git_path(path):
            continue
        if size > MAX_FILE_BYTES or pure.name in _SKIP_NAMES:
            continue
        if any(part.lower() in _SKIP_DIRS for part in pure.parts):
            continue
        entries.append((parts[2].decode(), size, path))
    return entries


def _read_blob(process: subprocess.Popen, oid: str, expected_size: int) -> bytes:
    assert process.stdin and process.stdout
    process.stdin.write((oid + "\n").encode())
    process.stdin.flush()
    header = process.stdout.readline().decode("ascii", "replace").strip().split()
    if len(header) != 3 or header[1] != "blob":
        return b""
    size = int(header[2])
    if size != expected_size or size > MAX_FILE_BYTES:
        process.stdout.read(size + 1)
        return b""
    data = process.stdout.read(size)
    process.stdout.read(1)
    return data


def _decode_text(data: bytes) -> str | None:
    if not data or b"\x00" in data[:8192]:
        return None
    text = data.decode("utf-8", "replace")
    if text.count("\ufffd") > max(3, len(text) // 200):
        return None
    return text


def _repo_row(connection, repo: Repo) -> tuple[int, bool]:
    row = connection.execute(
        "SELECT id,revision FROM repos WHERE full_name=?", (repo.full_name,)
    ).fetchone()
    if row and row["revision"] == repo.revision:
        return int(row["id"]), False
    now = int(time.time())
    if row:
        connection.execute(
            "UPDATE repos SET path=?,default_ref=?,revision=?,indexed_at=? WHERE id=?",
            (str(repo.path), repo.default_ref, repo.revision, now, row["id"]),
        )
        return int(row["id"]), True
    cursor = connection.execute(
        "INSERT INTO repos(full_name,path,default_ref,revision,indexed_at) VALUES(?,?,?,?,?)",
        (repo.full_name, str(repo.path), repo.default_ref, repo.revision, now),
    )
    return int(cursor.lastrowid), True


def _delete_document(connection: sqlite3.Connection, doc_id: int) -> None:
    connection.execute("DELETE FROM symbols WHERE doc_id=?", (doc_id,))
    connection.execute("DELETE FROM chunks WHERE doc_id=?", (doc_id,))
    connection.execute("DELETE FROM documents WHERE id=?", (doc_id,))


def index_repo(database: Database, repo: Repo) -> dict[str, int | str | bool]:
    with database.connection() as connection:
        row = connection.execute(
            "SELECT revision FROM repos WHERE full_name=?", (repo.full_name,)
        ).fetchone()
        if row and row["revision"] == repo.revision:
            return {
                "repo": repo.full_name,
                "changed": False,
                "documents": 0,
                "removed": 0,
                "symbols": 0,
            }

    entries = _tree_entries(repo)
    by_path = {path: (oid, size) for oid, size, path in entries}
    indexed = 0
    symbol_count = 0
    chunk_count = 0

    with database.connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        repo_id, changed = _repo_row(connection, repo)
        if not changed:
            return {
                "repo": repo.full_name,
                "changed": False,
                "documents": 0,
                "removed": 0,
                "symbols": 0,
            }

        existing_rows = connection.execute(
            "SELECT id,path,blob_oid FROM documents WHERE repo_id=?",
            (repo_id,),
        ).fetchall()
        existing = {
            row["path"]: (int(row["id"]), row["blob_oid"]) for row in existing_rows
        }
        removed = sorted(set(existing) - set(by_path))
        for path in removed:
            _delete_document(connection, existing[path][0])

        changed_entries: list[tuple[str, int, str]] = []
        for oid, size, path in entries:
            previous = existing.get(path)
            if previous and previous[1] == oid:
                continue
            if previous:
                _delete_document(connection, previous[0])
            changed_entries.append((oid, size, path))

        if not changed_entries:
            return {
                "repo": repo.full_name,
                "changed": True,
                "documents": 0,
                "removed": len(removed),
                "symbols": 0,
            }

        process = subprocess.Popen(
            ["git", "--git-dir", str(repo.path), "cat-file", "--batch"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        try:
            for oid, size, path in changed_entries:
                content = _decode_text(_read_blob(process, oid, size))
                if content is None:
                    continue
                language = language_for(path)
                cursor = connection.execute(
                    "INSERT INTO documents(repo_id,path,language,size,blob_oid) "
                    "VALUES(?,?,?,?,?)",
                    (repo_id, path, language, size, oid),
                )
                doc_id = int(cursor.lastrowid)
                chunks = chunks_for(content)
                connection.executemany(
                    "INSERT INTO chunks(doc_id,line_start,content,signature) "
                    "VALUES(?,?,?,?)",
                    [(doc_id, *chunk) for chunk in chunks],
                )
                symbols = symbols_for(content, language)
                connection.executemany(
                    "INSERT INTO symbols(doc_id,name,kind,line,role,snippet) "
                    "VALUES(?,?,?,?,?,?)",
                    [(doc_id, *symbol) for symbol in symbols],
                )
                indexed += 1
                chunk_count += len(chunks)
                symbol_count += len(symbols)
        finally:
            if process.stdin:
                process.stdin.close()
            if process.stdout:
                process.stdout.close()
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()

    return {
        "repo": repo.full_name,
        "changed": True,
        "documents": indexed,
        "removed": len(removed),
        "chunks": chunk_count,
        "symbols": symbol_count,
    }


def index_all(database: Database, root: str | Path) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    discovered = discover_repos(root)
    known = {repo.full_name for repo in discovered}
    with database.connection() as connection:
        stale = connection.execute("SELECT id,full_name FROM repos").fetchall()
        for row in stale:
            if row["full_name"] not in known:
                clear_repo_documents(connection, int(row["id"]))
                connection.execute("DELETE FROM repos WHERE id=?", (row["id"],))
    for repo in discovered:
        try:
            results.append(index_repo(database, repo))
        except (OSError, subprocess.SubprocessError, sqlite3.Error) as error:
            results.append(
                {"repo": repo.full_name, "changed": False, "error": str(error)}
            )
    return results
