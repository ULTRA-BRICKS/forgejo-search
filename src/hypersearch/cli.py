"""Operator entry point for indexing, offline queries and the session-aware server.

Serve options are validated before opening the database or listening; tuning
probe capacity must never disable native code authorization.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import threading

from .auth import (
    DEFAULT_FORGEJO_PUBLIC_HOST,
    DEFAULT_FORGEJO_URL,
    ForgejoAuth,
    code_cache_entries,
    page_concurrency,
    probe_concurrency,
    probe_seconds,
)
from .db import open_database
from .indexer import index_all
from .search import search
from .server import (
    SearchServer,
    ServerSettings,
    connection_limit,
    deadline_seconds,
    heartbeat_seconds,
    queue_depth,
    worker_count,
)


def parser():
    p = argparse.ArgumentParser(prog="hypersearch")
    p.add_argument(
        "--db", default=os.getenv("HYPERSEARCH_DB", "/var/lib/forgejo-search/search.db")
    )
    sub = p.add_subparsers(dest="command", required=True)
    idx = sub.add_parser("index")
    idx.add_argument(
        "--repos",
        default=os.getenv("HYPERSEARCH_REPOS", "/var/lib/forgejo/repositories"),
    )
    serve = sub.add_parser("serve")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=3195)
    serve.add_argument(
        "--forgejo",
        default=os.getenv("HYPERSEARCH_FORGEJO", DEFAULT_FORGEJO_URL),
    )
    serve.add_argument(
        "--public-host",
        default=os.getenv("HYPERSEARCH_PUBLIC_HOST", DEFAULT_FORGEJO_PUBLIC_HOST),
    )
    serve.add_argument("--ast-grep", default="ast-grep")
    serve.add_argument(
        "--code-probe-budget", type=probe_seconds,
        default=os.getenv("HYPERSEARCH_CODE_PROBE_BUDGET", "10"),
        help="whole code-check deadline in seconds, >0..120 (env HYPERSEARCH_CODE_PROBE_BUDGET; default 10)",
    )
    serve.add_argument(
        "--code-probe-concurrency", type=probe_concurrency,
        default=os.getenv("HYPERSEARCH_CODE_PROBE_CONCURRENCY", "8"),
        help="shared code-probe workers, 1..64 (env HYPERSEARCH_CODE_PROBE_CONCURRENCY; default 8)",
    )
    serve.add_argument(
        "--request-timeout", type=probe_seconds,
        default=os.getenv("HYPERSEARCH_REQUEST_TIMEOUT", "2"),
        help="upstream socket timeout in seconds, >0..120 (env HYPERSEARCH_REQUEST_TIMEOUT; default 2)",
    )
    serve.add_argument(
        "--code-cache-max-entries", type=code_cache_entries,
        default=os.getenv("HYPERSEARCH_CODE_CACHE_MAX_ENTRIES", "8192"),
        help="code permission cache bound, 1..1000000 (env HYPERSEARCH_CODE_CACHE_MAX_ENTRIES; default 8192)",
    )
    serve.add_argument(
        "--visibility-concurrency", type=page_concurrency,
        default=os.getenv("HYPERSEARCH_VISIBILITY_CONCURRENCY", "8"),
        help="parallel Forgejo visibility-listing requests, 1..64; 1 is the sequential walk (env HYPERSEARCH_VISIBILITY_CONCURRENCY; default 8)",
    )
    serve.add_argument(
        "--request-deadline", type=deadline_seconds,
        default=os.getenv("HYPERSEARCH_REQUEST_DEADLINE", "20"),
        help="overall per-request deadline in seconds, >0..300 (env HYPERSEARCH_REQUEST_DEADLINE; default 20)",
    )
    serve.add_argument(
        "--heartbeat-interval", type=heartbeat_seconds,
        default=os.getenv("HYPERSEARCH_HEARTBEAT_INTERVAL", "2"),
        help="NDJSON heartbeat period in seconds, 0.05..30 (env HYPERSEARCH_HEARTBEAT_INTERVAL; default 2)",
    )
    serve.add_argument(
        "--search-workers", type=worker_count,
        default=os.getenv("HYPERSEARCH_SEARCH_WORKERS", "8"),
        help="concurrently running searches, 1..64 (env HYPERSEARCH_SEARCH_WORKERS; default 8)",
    )
    serve.add_argument(
        "--search-queue", type=queue_depth,
        default=os.getenv("HYPERSEARCH_SEARCH_QUEUE", "24"),
        help="searches allowed to wait for a worker, 0..256; more get 503 server_busy (env HYPERSEARCH_SEARCH_QUEUE; default 24)",
    )
    serve.add_argument(
        "--max-connections", type=connection_limit,
        default=os.getenv("HYPERSEARCH_MAX_CONNECTIONS", "64"),
        help="open client connections, 1..1024 (env HYPERSEARCH_MAX_CONNECTIONS; default 64)",
    )
    q = sub.add_parser(
        "query",
        description="Search the authorized local index; emit JSON results and bounded coverage version 1.",
    )
    q.add_argument("query")
    q.add_argument("--allow", action="append", default=[])
    q.add_argument("--limit", type=int, default=30)
    q.add_argument("--ast-grep", default="ast-grep")
    return p


def main(argv=None):
    cli = parser()
    args = cli.parse_args(argv)
    settings = None
    if args.command == "serve":
        try:
            settings = ServerSettings(
                request_deadline=args.request_deadline,
                heartbeat_interval=args.heartbeat_interval,
                search_workers=args.search_workers,
                search_queue=args.search_queue,
                max_connections=args.max_connections,
            )
        except ValueError as error:
            cli.error(str(error))
    db = open_database(args.db)
    if args.command == "index":
        print(json.dumps(index_all(db, args.repos), indent=2))
        return
    if args.command == "query":
        print(
            json.dumps(
                search(db, args.query, set(args.allow), args.limit, args.ast_grep),
                indent=2,
            )
        )
        return
    server = SearchServer(
        (args.host, args.port),
        db,
        ForgejoAuth(
            args.forgejo,
            public_host=args.public_host,
            code_probe_budget=args.code_probe_budget,
            code_probe_concurrency=args.code_probe_concurrency,
            request_timeout=args.request_timeout,
            code_cache_max_entries=args.code_cache_max_entries,
            visibility_concurrency=args.visibility_concurrency,
        ),
        args.ast_grep,
        settings,
    )
    # An orderly stop on SIGTERM: leave the accept loop, then cancel and drain below.
    signal.signal(
        signal.SIGTERM,
        lambda *_: threading.Thread(target=server.shutdown, daemon=True).start(),
    )
    print(f"HyperSearch listening on {args.host}:{args.port}", flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        server.auth.close()


if __name__ == "__main__":
    main()
