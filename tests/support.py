"""Synthetic index and NDJSON client helpers shared by transport tests and benchmarks."""

from __future__ import annotations

import http.client
import json
import time
import urllib.parse
from pathlib import Path

from hypersearch.db import Database, open_database


def build_index(path, names, *, text="sharedtoken") -> Database:
    """One indexed document/chunk per repository; nothing is read from git."""
    database = open_database(path)
    with database.connection() as connection:
        for index, name in enumerate(names, start=1):
            connection.execute(
                "INSERT INTO repos(id,full_name,path,default_ref,revision,indexed_at)"
                " VALUES(?,?,?,?,?,0)",
                (index, name, f"/nonexistent/{index}.git", "refs/heads/main", "a" * 40),
            )
            connection.execute(
                "INSERT INTO documents(id,repo_id,path,language,size,blob_oid)"
                " VALUES(?,?,?,?,?,?)",
                (index, index, "src/main.py", "python", 40, f"{index:040x}"),
            )
            connection.execute(
                "INSERT INTO chunks(id,doc_id,line_start,content,signature) VALUES(?,?,?,?,?)",
                (index, index, 1, f"def handler{index}(): return {text}\n", "def"),
            )
    return database


class Stream:
    """Reads one response incrementally and timestamps every NDJSON record."""

    def __init__(self, base, query, *, accept="application/x-ndjson", cookie="session=alice",
                 timeout=10, extra=None):
        host = base.removeprefix("http://")
        self.connection = http.client.HTTPConnection(host, timeout=timeout)
        headers = {"Cookie": cookie} if cookie else {}
        if accept:
            headers["Accept"] = accept
        headers.update(extra or {})
        self.started = time.perf_counter()
        self.connection.request("GET", "/api/hypersearch?q=" + urllib.parse.quote(query), headers=headers)
        self.response = self.connection.getresponse()
        self.seen: list[tuple[float, dict]] = []
        self.raw = bytearray()

    @property
    def status(self):
        return self.response.status

    def header(self, name):
        return self.response.getheader(name)

    def next(self):
        """Next complete NDJSON record, or None at EOF."""
        line = self.response.readline()
        if not line:
            return None
        self.raw.extend(line)
        assert line.endswith(b"\n"), "every record must end with a newline"
        record = json.loads(line)
        self.seen.append((time.perf_counter() - self.started, record))
        return record

    def drain(self):
        out = []
        while (record := self.next()) is not None:
            out.append(record)
        return out

    def body(self):
        self.raw.extend(self.response.read())
        return bytes(self.raw)

    def close(self):
        self.connection.close()


def raw_exchange(port, payload: bytes, *, timeout=5, limit=1 << 20) -> bytes:
    """Send arbitrary bytes and return everything the server answers before closing."""
    import socket

    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
        sock.sendall(payload)
        out = bytearray()
        try:
            while len(out) < limit:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                out.extend(chunk)
        except (TimeoutError, ConnectionResetError):
            pass
        return bytes(out)


def temp_database(tmp_path: Path, names=(), **kwargs) -> Database:
    return build_index(tmp_path / "search.db", list(names), **kwargs)
