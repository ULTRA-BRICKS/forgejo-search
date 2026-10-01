# HyperSearch

Permission-aware hybrid search for Forgejo.

Core modes:
- file/path search
- symbol definitions and references
- whitespace-normalized structural token search
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

Structural token hits link to the first matching source line, not the start of the
index chunk. AST candidates preserve distinct file paths even when files share the
same Git blob; identical contents do not collapse separate file results.

## Coverage and limits

Search is hybrid retrieval, not a language-server or exhaustive code analysis:

- Repository-name hits use indexed, visible repositories (at most 12 per query).
  There is no separate `type:repo` mode; use a plain repository name.
- File mode uses path trigrams and deliberately returns no matches below three
  characters. Definitions use selected regular-expression patterns for JavaScript,
  TypeScript, Python, Rust and Go, not every language recognized for text indexing.
- References match identifier boundaries and exclude indexed definition lines.
  They are lexical occurrences, not symbol-resolution, call-graph or rename results;
  comments, strings and imports can match.
- Structural token matching normalizes whitespace but retains punctuation tokens.
  AST refinement requires the configured `ast-grep` executable and a valid pattern.
  Both are hybrid modes: lower-ranked lexical results can remain alongside
  `mode: ast` or `mode: structure` hits. An AST query is not an AST-only result contract.
- Lexical candidate selection uses at most `max(limit, 40)` ranked chunks. AST
  refinement uses at most 20 distinct candidate files and a two-second process
  timeout; a no-literal pattern uses a bounded scoped chunk fallback. Missing or
  failed ast-grep leaves lexical/token results, not proof that no AST matches exist.
  Truncation/engine availability is not yet exposed in the response; tracked in
  [the search coverage follow-up](https://git.hyperide.ai/ultrabricks/forgejo-search/issues/13).
- `repo:` uses an exact full name. `owner:` and `path:` retain SQL LIKE wildcard
  behavior (`%` and `_`); `lang:` uses the indexed language name.
- Only the default branch HEAD is indexed, when the operator runs `hypersearch index`.
  This service does not schedule indexing or promise a freshness interval. Files
  above 512 KiB, binary data, lockfiles and generated/vendor directories are skipped.
  Results use immutable commit links; they are not live working-tree results.

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
`HEAD /{owner}/{reponame}/search` -- the same route backing Forgejo's repository header
search box. Forgejo's chi `GetHead` middleware sends HEAD through the GET handler
chain, including `reqRepoCodeReader`, without transferring the response body.
There is **no GET fallback** for a rejected HEAD: `405`/`501` and other ambiguous
statuses fail closed with `503`. The separate `/repo/search` visibility and identity
requests use GET and parse JSON; they are not a fallback code-permission probe.
A `404` is only cached as a code denial after an uncached
`/repo/search` identity check: a revoked session can also receive a bare `404`
on a private repository. A login response invalidates that session's cached
code grants and fails the current request closed. Any ambiguous failure
(timeout, `403`, malformed identity response, ...) returns `503`, with five-second
per-session code-probe backoff rather than a cached normal deny.
This narrower "code-allowed" scope gates file/symbol/AST/text results;
repository-name hits still use the broader visibility allow-list, since a repository's
existence is not itself a code disclosure. This code-ACL check only runs once there is
an actual query to execute, so the empty-query "am I signed in?" fast path used by the
frontend stays cheap. AST refinement can only materialize documents that already passed
the ACL-filtered FTS candidate query.

Transient visibility failures return `503`, not a login prompt. A bounded,
per-session unavailable cache suppresses retries for five seconds, including
failed pagination; it never reuses a partial repository list. Successful visibility
and code grants expire after 30 seconds, while anonymous/denied entries expire
after five seconds. Grant expiry is measured from check start, not response
completion, so a slow probe cannot extend the stale-permission window.
Grants must still be unexpired when the complete allow-list is returned; an expired
grant aborts the request rather than returning partial results. Observed session
revocation invalidates outstanding checks even after its negative cache entry
expires or is evicted, so a delayed successful probe cannot resurrect permission.
Configure `--forgejo` with the full internal base URL including
Forgejo's AppSubURL (for example `http://127.0.0.1:3000/forgejo`). Login redirects
must match that mount's login path and either the internal authority or
`--public-host`; redirects are never followed with the viewer's cookie.

## Probe capacity

`hypersearch serve` accepts these flags (flags override environment variables):

| Flag | Environment variable | Default | Valid range |
| --- | --- | --- | --- |
| `--code-probe-budget` | `HYPERSEARCH_CODE_PROBE_BUDGET` | 10 seconds | finite, >0 through 120 |
| `--code-probe-concurrency` | `HYPERSEARCH_CODE_PROBE_CONCURRENCY` | 8 | integer 1–64 |
| `--request-timeout` | `HYPERSEARCH_REQUEST_TIMEOUT` | 2 seconds | finite, >0 through 120 |
| `--code-cache-max-entries` | `HYPERSEARCH_CODE_CACHE_MAX_ENTRIES` | 8192 | integer 1–1000000 |

The code-probe deadline includes waiting for capacity, but not the earlier
repository-visibility pagination or search execution. Workers and admitted probes
are bounded across all sessions in one service process, not multiplied per query.
A deadline or upstream failure returns no partial result. Running probes may finish
after the caller's deadline; they retain their shared slots until completion.
Overlapping checks for the same session/repository share one future before worker
admission. Released capacity wakes pending requests even while their other probes
are still running.
The request timeout is a socket timeout, not a hard whole-response deadline.
Multiple service processes each have their own pool and caches.
The caller owns `ForgejoAuth` and must call its idempotent `close()` after stopping
HTTP requests; the CLI does so when its serve loop exits. Shutdown joins admitted
probes rather than abandoning their worker threads.
The deployment's nginx 15-second timeout is not an end-to-end authorization guarantee:
cold visibility pagination precedes the code-probe budget, and socket timeouts do not
cap total response duration. Release acceptance must measure the full authenticated
request, not label the code-probe budget as its end-to-end deadline.

Cold unscoped searches still probe **every visible, indexed repository**, not just
repositories with text matches. `repo:` and `owner:` narrow candidates before probing;
path/language terms do not. Empty queries skip code probes. Warm entries avoid HTTP
requests until expiry or eviction. Each cold `404` adds an identity recheck.
Increase capacity only with measured upstream headroom; never bypass code permission
checks or lengthen permission TTLs to hide overload.

The source package version is 0.2.0 for the additive operator controls. Deployment
still identifies the runtime by its full vendored source revision, not package
metadata: the infrastructure owner must update both REVISION and VERSION when
integrating this source. A source pull request does not update the running service.

A synthetic localhost HTTP workload with 600 indexed/visible repositories and
150 ms per HEAD measured: default 8 workers/10 seconds failed closed at 10.04 seconds;
five subsequent keystrokes returned backed-off `503` in 1.4–2.3 ms with zero new HEADs.
8 workers/20 seconds completed in 11.80 seconds; 16 workers/10 seconds in 5.99 seconds.
Warm searches took 5.6–6.7 ms with zero HEADs; a cold single-repository query took
166 ms with one HEAD. These are fixture measurements, not production guarantees.
Expiry, eviction, other sessions and identity rechecks can make later searches cold.

## Development

```sh
uv sync --group dev
uv run ruff check src tests
uv run pytest -q
```

The production index reads Forgejo bare repositories directly, stores 32-line
overlapping FTS chunks and lightweight symbol metadata, and skips repositories
whose HEAD revision has not changed.

Each indexing pass reads the discovered commit's immutable tree, even if HEAD
advances during the pass. Search result snippets and commit URLs therefore share
one revision. A subsequent pass picks up the newer HEAD.
