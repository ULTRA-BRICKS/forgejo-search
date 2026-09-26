# HyperSearch

Permission-aware hybrid search for Forgejo.

Core modes:
- file/path search
- symbol definitions and references
- punctuation/whitespace-insensitive structural token search
- optional AST refinement with ast-grep
- BM25-ranked full-text search through SQLite FTS5

The browser uses the existing Forgejo session. The service never creates its own
login and filters every query to repositories the current Forgejo user can see.

## Query language

Plain input is intent-detected:

- `focus.js` → file/path search
- `restoreFocus` → symbol definitions plus matching code
- `function restoreFocus` → symbol definition
- `references restoreFocus` → usages/references
- `restoreFocus ( trigger )` → structural signature plus AST refinement

Explicit filters can be combined: `repo:`, `owner:`, `path:`, `lang:`,
`def:`, `ref:`, `ast:`, `text:`, and `type:`.

The final term is prefix-matched, so search-as-you-type returns useful results
before a word is complete. File paths use an SQLite trigram index.

## Permission model

The public UI and API stay same-origin with Forgejo. Every request forwards the
existing Forgejo session cookie to Forgejo's own session-authenticated `/repo/search`
web route -- the same route Forgejo's UI uses for its repository picker -- rather than
the `/api/v1/*` REST API, which only accepts token/basic/oauth2 credentials and never a
browser session cookie. That route both confirms the session is signed in (an
anonymous or revoked session is redirected to `/user/login`, which is treated as
unauthenticated) and returns the allow-list of repositories visible to that user. Every
SQL search path folds that allow-list into its query before ranking. AST refinement
can only materialize documents that already passed the ACL-filtered FTS candidate
query.

A failed or partial Forgejo visibility lookup returns an explicit error and is
never treated as a complete permission set.

## Development

```sh
uv sync --group dev
uv run ruff check src tests
uv run pytest -q
```

The production index reads Forgejo bare repositories directly, stores 32-line
overlapping FTS chunks and lightweight symbol metadata, and skips repositories
whose HEAD revision has not changed.
