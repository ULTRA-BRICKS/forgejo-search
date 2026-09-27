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
SQL search path folds that allow-list into its query before ranking.

Repository *visibility* in Forgejo is granted by access to any unit -- issues, wiki,
projects, releases -- and is not the same as code-read access. Before any file, symbol,
AST, or full-text hit is returned, the service separately verifies Forgejo's native
`reqRepoCodeReader` (`unit.TypeCode`) permission for each visible, indexed repository by
probing that same session cookie against Forgejo's own per-repo code-search web route,
`GET /{owner}/{reponame}/search` -- the same route backing Forgejo's repository header
search box. A `404` from that route is the only trusted deny signal; any other failure
(timeout, `403`, a mid-check session flip, ...) fails the whole request closed rather
than guessing. This narrower "code-allowed" scope gates file/symbol/AST/text results;
repository-name hits still use the broader visibility allow-list, since a repository's
existence is not itself a code disclosure. This code-ACL check only runs once there is
an actual query to execute, so the empty-query "am I signed in?" fast path used by the
frontend stays cheap. AST refinement can only materialize documents that already passed
the ACL-filtered FTS candidate query.

## Development

```sh
uv sync --group dev
uv run ruff check src tests
uv run pytest -q
```

The production index reads Forgejo bare repositories directly, stores 32-line
overlapping FTS chunks and lightweight symbol metadata, and skips repositories
whose HEAD revision has not changed.
