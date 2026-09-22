from __future__ import annotations

import argparse
import json
import os

from .auth import DEFAULT_FORGEJO_PUBLIC_HOST, DEFAULT_FORGEJO_URL, ForgejoAuth
from .db import open_database
from .indexer import index_all
from .search import search
from .server import SearchServer


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
    q = sub.add_parser("query")
    q.add_argument("query")
    q.add_argument("--allow", action="append", default=[])
    q.add_argument("--limit", type=int, default=30)
    q.add_argument("--ast-grep", default="ast-grep")
    return p


def main(argv=None):
    args = parser().parse_args(argv)
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
        ForgejoAuth(args.forgejo, public_host=args.public_host),
        args.ast_grep,
    )
    print(f"HyperSearch listening on {args.host}:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
