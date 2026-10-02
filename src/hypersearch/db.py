from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from . import deadline as scope

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS repos(
  id INTEGER PRIMARY KEY,
  full_name TEXT NOT NULL UNIQUE,
  path TEXT NOT NULL,
  default_ref TEXT NOT NULL,
  revision TEXT NOT NULL,
  indexed_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS documents(
  id INTEGER PRIMARY KEY,
  repo_id INTEGER NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
  path TEXT NOT NULL,
  language TEXT NOT NULL,
  size INTEGER NOT NULL,
  blob_oid TEXT NOT NULL,
  UNIQUE(repo_id,path)
);
CREATE INDEX IF NOT EXISTS documents_repo_path ON documents(repo_id,path);
CREATE TABLE IF NOT EXISTS chunks(
  id INTEGER PRIMARY KEY,
  doc_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  line_start INTEGER NOT NULL,
  content TEXT NOT NULL,
  signature TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS chunks_doc_line ON chunks(doc_id,line_start);
CREATE TABLE IF NOT EXISTS symbols(
  doc_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  name TEXT NOT NULL COLLATE NOCASE,
  kind TEXT NOT NULL,
  line INTEGER NOT NULL,
  role TEXT NOT NULL,
  snippet TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS symbols_name ON symbols(name,role);
"""

FTS = """
CREATE VIRTUAL TABLE IF NOT EXISTS paths_fts USING fts5(
  path,
  content='documents',
  content_rowid='id',
  tokenize='trigram case_sensitive 0'
);
CREATE TRIGGER IF NOT EXISTS documents_ai AFTER INSERT ON documents BEGIN
  INSERT INTO paths_fts(rowid,path) VALUES(new.id,new.path);
END;
CREATE TRIGGER IF NOT EXISTS documents_ad AFTER DELETE ON documents BEGIN
  INSERT INTO paths_fts(paths_fts,rowid,path) VALUES('delete',old.id,old.path);
END;
CREATE TRIGGER IF NOT EXISTS documents_au AFTER UPDATE ON documents BEGIN
  INSERT INTO paths_fts(paths_fts,rowid,path) VALUES('delete',old.id,old.path);
  INSERT INTO paths_fts(rowid,path) VALUES(new.id,new.path);
END;

CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(
  content,
  signature,
  content='chunks',
  content_rowid='id',
  tokenize='unicode61 remove_diacritics 2'
);
CREATE TRIGGER IF NOT EXISTS chunks_ai AFTER INSERT ON chunks BEGIN
  INSERT INTO chunks_fts(rowid,content,signature)
  VALUES(new.id,new.content,new.signature);
END;
CREATE TRIGGER IF NOT EXISTS chunks_ad AFTER DELETE ON chunks BEGIN
  INSERT INTO chunks_fts(chunks_fts,rowid,content,signature)
  VALUES('delete',old.id,old.content,old.signature);
END;
CREATE TRIGGER IF NOT EXISTS chunks_au AFTER UPDATE ON chunks BEGIN
  INSERT INTO chunks_fts(chunks_fts,rowid,content,signature)
  VALUES('delete',old.id,old.content,old.signature);
  INSERT INTO chunks_fts(rowid,content,signature)
  VALUES(new.id,new.content,new.signature);
END;
"""


@dataclass(frozen=True)
class Database:
    path: Path

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        # A request-bound connection aborts its own statement once the request is cancelled
        # or out of time; index and offline connections (no bound request) are untouched.
        context = scope.current()
        if context is not None:
            connection.set_progress_handler(
                lambda: context.cancelled or context.remaining() == 0.0, 1000
            )
        try:
            with connection:
                yield connection
        except sqlite3.OperationalError:
            # An interrupted statement is the request's own deadline or cancellation.
            scope.checkpoint()
            raise
        finally:
            connection.close()


def _secure_file(path: Path) -> None:
    if path.exists():
        os.chmod(path, 0o600)


def open_database(path: str | Path) -> Database:
    target = Path(path)
    target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    # The production state directory is owned by forgejo-search. Tighten it here
    # as defense in depth; deployment also enforces 0700 via tmpfiles.
    try:
        os.chmod(target.parent, 0o700)
    except PermissionError:
        pass
    if not target.exists():
        try:
            fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
    _secure_file(target)
    database = Database(target)
    with database.connection() as connection:
        connection.executescript(SCHEMA)
        connection.executescript(FTS)
        connection.execute("PRAGMA user_version=1")
    for suffix in ("", "-wal", "-shm"):
        _secure_file(Path(str(target) + suffix))
    return database


def clear_repo_documents(connection: sqlite3.Connection, repo_id: int) -> None:
    connection.execute(
        "DELETE FROM symbols WHERE doc_id IN "
        "(SELECT id FROM documents WHERE repo_id=?)",
        (repo_id,),
    )
    connection.execute(
        "DELETE FROM chunks WHERE doc_id IN (SELECT id FROM documents WHERE repo_id=?)",
        (repo_id,),
    )
    connection.execute("DELETE FROM documents WHERE repo_id=?", (repo_id,))


# SQLite's default SQLITE_MAX_VARIABLE_NUMBER bounds how many `?` markers a
# single statement can bind; chunking keeps a single IN(...) query well
# under that regardless of how large a caller's candidate set is.
_IN_CLAUSE_CHUNK_SIZE = 500


def indexed_repo_names(connection: sqlite3.Connection, candidates: set[str]) -> set[str]:
    """Return the subset of `candidates` that are actually indexed, querying
    only that (already ACL/query-scoped) candidate set instead of scanning
    the full `repos` table -- callers are expected to have already narrowed
    `candidates` down via visibility and any query scope before calling this.
    """
    if not candidates:
        return set()
    names = sorted(candidates)
    found: set[str] = set()
    for start in range(0, len(names), _IN_CLAUSE_CHUNK_SIZE):
        chunk = names[start : start + _IN_CLAUSE_CHUNK_SIZE]
        marks = ",".join("?" for _ in chunk)
        rows = connection.execute(
            f"SELECT full_name FROM repos WHERE full_name IN ({marks})", chunk
        ).fetchall()
        found.update(row[0] for row in rows)
    return found
