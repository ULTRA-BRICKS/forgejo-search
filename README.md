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
  The additive `coverage` response below exposes engine outcomes and stage limits.
- `repo:` uses an exact full name. `owner:` and `path:` retain SQL LIKE wildcard
  behavior (`%` and `_`); `lang:` uses the indexed language name.
- Only the default branch HEAD is indexed, when the operator runs `hypersearch index`.
  This service does not schedule indexing or promise a freshness interval. Files
  above 512 KiB, binary data, lockfiles and generated/vendor directories are skipped.
  Results use immutable commit links; they are not live working-tree results.

### Successful response contract: `coverage.version = 1`

HTTP and offline `hypersearch query` responses include the same `coverage` object.
The [JSON Schema](docs/search-coverage.schema.json) defines that member, not the
whole response. Existing query/mode/inferred fields, result objects, immutable
URLs and HTTP timings retain their meanings. `elapsed_ms` measures search
execution; `total_ms` includes preceding authorization. An authenticated empty
HTTP query retains its smaller envelope (`query`, `mode`, `results`, `total_ms`)
and adds stable coverage with every stage `not_applicable` and AST `not_requested`,
without code-permission probes. Fail-closed 401/503 responses contain neither
partial results nor coverage.

Coverage always declares `scope: authorized_indexed_default_branch`,
`completeness: bounded`, and
`semantics: {definitions: pattern_based, references: lexical}`. No state claims
exhaustive semantic search, index freshness or coverage of skipped files.

| Field under `coverage.limits` | Actual cap | Scope and applicability |
| --- | --- | --- |
| `repository_hits` | `min(limit, 12)` | Indexed repository names visible to the caller; eligible plain/text queries only |
| `file_hits` | `limit` | Code-readable file paths; file candidates of at least three characters |
| `symbol_hits` | `limit` | Code-readable symbol rows; definition/symbol candidates, not reference-only queries |
| `lexical_candidates` | `max(limit, 40)` | Code-readable chunks selected by FTS, or the scoped chunk fallback when AST has no lexical candidates |
| `ast_files` | 20 | Distinct code-readable repository/path pairs, never distinct blobs |
| `results` | `limit` | Final ranked merge, deduplicated by repository/path/line/kind before limiting |

`limit` is clamped to 1–100 (HTTP default/invalid integer: 30). Inactive stages
still report their cap. A single extra authorized row distinguishes `truncated`
from an exactly-full `complete` stage; sentinels never become permission probes or
cause an extra AST file to be materialized. `complete` applies only to the named
retrieval/merge stage, not to the entire installation or the skipped stages.
`not_applicable` means that mode did not request the stage. `unknown` means
exhaustion cannot be established safely: capped upstream chunks make downstream
AST-file and result coverage unknown. Truncated or unknown AST-file coverage also
makes final-result coverage unknown; skipped blob materialization makes AST-file
coverage unknown. This conservative propagation prevents global FTS ranking
statistics from turning changes in inaccessible code into changing coverage
metadata. Final merge `complete` does not override an upstream `truncated` stage
or an unavailable engine.

`coverage.ast.status` is one of:

- `not_requested`: no AST refinement for this query.
- `no_candidates`: no authorized candidate chunks, without testing engine availability.
- `ran`: successful engine invocation, with zero or more structural matches.
- `unavailable`: the executable could not be found or launched.
- `timeout`: AST execution/output processing exhausted the shared two-second budget.
- `failed`: nonzero exit, malformed consumed output, or no selected blobs could be materialized.

`ran` is not a pattern-validity or supported-language guarantee: ast-grep can
successfully emit no matches for an unsupported pattern. The exercised ast-grep
0.39.4 `run --json=stream` exits zero on both matches and no matches; nonzero
execution is not interpreted as a successful empty search. Output decoding stops
after `limit + 1` unique AST hits; surplus records cannot turn a proven bounded
success into a parse timeout. Malformed consumed records discard the AST batch,
while lexical/token fallback remains available. Raw diagnostics, executable
paths, repository totals, denied-code counts and index identifiers are not part
of coverage.
Duplicate AST records can require decoding until a unique sentinel, exhaustion,
or the shared timeout. There is no separate raw-record/byte cap: subprocess output
is still captured in memory for at most the engine budget (two seconds, or less when
the request deadline is nearer). The streaming transport's record caps bound what the
service sends, not what ast-grep emits; coverage does not claim a streaming memory bound.

Consumers should feature-detect version 1, display bounded scope and lexical/
pattern-based semantics, distinguish empty results from AST unavailability, and
surface `truncated`/`unknown` stage warnings independently of result count.
Older/missing versions must not be rendered as complete. Repository-name scope
is broader than code scope; do not infer code access from a name hit. This backend
contract does not implement the header UI; the consumer and deployed viewer proof
remain owned by [task 13](https://git.hyperide.ai/ultrabricks/forgejo-search/issues/13).

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
A `404` is only cached as a code denial after an identity check -- `GET /repo/search`
with `count_only=true`, which passes the same sign-in gate as the listing -- that was
*issued after that 404 was received*: a revoked session can also receive a bare `404`
on a private repository. A call confirms all of its `404`s with one such check, issued
after the newest of them; concurrent calls of one session share a check only if it was
issued later than the denial it confirms (ordered by an internal sequence number, not
wall-clock reads), otherwise the earlier check is waited out and a new one is issued.
A login response invalidates that session's cached code grants and fails the current
request closed. Any ambiguous failure
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
The same holds for a result that is still being built: if any request of the session
observes the logout before the search stage returns, that response is `503`
(`visibility_unavailable`) instead of the result, without a further upstream request.
This is not live freshness: a logout that no request has observed is only noticed when
the cached grants expire (30 seconds at most), as before.
Configure `--forgejo` with the full internal base URL including
Forgejo's AppSubURL (for example `http://127.0.0.1:3000/forgejo`). Login redirects
must match that mount's login path and either the internal authority or
`--public-host`; redirects are never followed with the viewer's cookie.

## Avoidable upstream work

Designed against the pinned Forgejo 16.0.5 `GET /repo/search` source (`limit` capped at
50, alphabetical order, `X-Total-Count` header, `count_only` answering `{"ok":true}`,
`q` = case-insensitive name/topic substring under the same access condition). The
previous production release 16.0.3 is not in the inspected archive, so every shortcut
falls back to the original behavior when a header or parameter is ignored.

- **Session readiness.** An empty query (the header's "signed in?" probe) and denial
  confirmations send `GET /repo/search?limit=1&page=1&count_only=true` instead of the
  full listing. `{"ok":true}` or a one-row listing means signed in, a login redirect
  means anonymous, anything else is `503`. Grants keep the 30 s / 5 s lifetimes measured
  from check start; an identity-only entry never stands in for a repository list.
- **Visibility listing.** Page 1 reports `X-Total-Count`; the remaining pages plus one
  page past the end are then fetched in parallel, in page order and at most
  `--visibility-concurrency` at a time. Every listing request of every session
  (first page, parallel page or sequential fallback page) takes one of
  `--visibility-concurrency` process-wide slots. The count only schedules requests: the
  allow-list is complete only once an empty page was reached. An understated count
  continues sequentially. An overstated one stops being followed as soon as a page comes
  back empty: no further page is issued, so the waste is the pages already issued at that
  moment (about one window past the end, not zero) instead of the whole 21-page bound.
  More than about 1000 repositories still fails closed, and a missing header or
  concurrency 1 is the original sequential walk. Every page before the empty one is still
  awaited, whatever order the answers arrive in. A login redirect on *any* fetched page,
  including one past the empty page that ends the list, fails the listing and revokes
  outstanding checks exactly as before; no partial list is ever cached.
- **`repo:` scope.** An exact `repo:owner/name` (Forgejo-safe characters only) lists
  `q=<name>` natively: a superset of the named repository, because the keyword is a
  case-insensitive substring match under the same access condition. The service still
  applies its own case-insensitive candidate filter and the case-sensitive SQL equality,
  so ranking, coverage and permissions are unchanged. `owner:` and `path:` keep SQL
  `LIKE` wildcard semantics (`%`, `_`) and have no safe native equivalent; they and
  unsafe `repo:` values use the full listing. A fresh full allow-list answers a scoped
  request without any network call, and scoped lists are discarded on observed logout.
- **Same-session coalescing.** Overlapping listings, readiness checks and probes of a
  session share one in-flight request. Followers wait in their own thread (never on a
  shared worker), a cancelled leader hands the work to a waiting follower, and shared
  probes are never cancelled while another viewer still needs them.

## Streaming transport (NDJSON v1)

A client opts in with an explicit `Accept: application/x-ndjson` (weight above zero;
`q=0`, `*/*` and `application/json` stay on JSON). The response is `200` with
`Content-Type: application/x-ndjson; charset=utf-8`, `Cache-Control: no-store, private,
no-transform`, `X-Accel-Buffering: no`, no `Content-Length` and a closing connection
(HTTP/1.0 close-delimited framing; no invented chunks), then one compact UTF-8 JSON
object per `\n`-terminated line (U+2028/2029 are escaped):

1. `{"v":1,"type":"started"}` flushed before any upstream call;
2. `{"v":1,"type":"heartbeat"}` every `--heartbeat-interval` (default 2 s) while work
   blocks -- no names, counts, stage, scope or cache state;
3. exactly one `{"v":1,"type":"result","data":<the full existing JSON response>}`;
4. `{"v":1,"type":"done"}`.

A failure after the headers is one terminal `{"v":1,"type":"error","code":...,"status":...}`
with no `done`: `authentication_required` (401), `visibility_unavailable` and
`code_visibility_unavailable` (503), `search_unavailable` (503, also for unexpected
errors and oversized results; raw exceptions are never forwarded), `deadline_exceeded`
(504), `server_busy` (503). Authorized data appears only inside the final `result`.
Records follow the shared caps: 2 MiB each, 8 MiB and 256 records per response; an
oversized result becomes `search_unavailable`, never a truncation.

Ordinary JSON errors are still returned *before* a stream opens: missing cookie `401`,
`400 query_too_long` (over 2048 characters), `400/414/431` for malformed or oversized
requests, `404`, and `503 server_busy` with `Retry-After: 1` when every worker and queue
slot is taken. JSON clients additionally see `504 {"error":"deadline_exceeded"}` past the
overall deadline and `503 {"error":"search_unavailable"}` for unexpected failures (the
connection used to be dropped); their success bodies and other statuses are unchanged.

Behind a proxy: disable response buffering and compression for this location (nginx
`proxy_buffering off; gzip off;`; the `X-Accel-Buffering: no` header already covers
buffering). The deployed 15 s read timeout is satisfied by the 2 s heartbeat; this service
does not change proxy configuration.

## Probe capacity

`hypersearch serve` accepts these flags (flags override environment variables):

| Flag | Environment variable | Default | Valid range |
| --- | --- | --- | --- |
| `--code-probe-budget` | `HYPERSEARCH_CODE_PROBE_BUDGET` | 10 seconds | finite, >0 through 120 |
| `--code-probe-concurrency` | `HYPERSEARCH_CODE_PROBE_CONCURRENCY` | 8 | integer 1–64 |
| `--request-timeout` | `HYPERSEARCH_REQUEST_TIMEOUT` | 2 seconds | finite, >0 through 120 |
| `--code-cache-max-entries` | `HYPERSEARCH_CODE_CACHE_MAX_ENTRIES` | 8192 | integer 1–1000000 |
| `--visibility-concurrency` | `HYPERSEARCH_VISIBILITY_CONCURRENCY` | 8 | integer 1–64 (1 = sequential listing) |
| `--request-deadline` | `HYPERSEARCH_REQUEST_DEADLINE` | 20 seconds | finite, >0 through 300 |
| `--heartbeat-interval` | `HYPERSEARCH_HEARTBEAT_INTERVAL` | 2 seconds | finite, 0.05 through 30 |
| `--search-workers` | `HYPERSEARCH_SEARCH_WORKERS` | 8 | integer 1–64 |
| `--search-queue` | `HYPERSEARCH_SEARCH_QUEUE` | 24 | integer 0–256 |
| `--max-connections` | `HYPERSEARCH_MAX_CONNECTIONS` | 64 | integer 1–1024 |

`--request-deadline` divided by `--heartbeat-interval` must leave room for the 256-record
stream cap (the CLI exits with status 2 otherwise). Invalid values exit before the
database is opened or the port is bound.

The code-probe budget covers only the wait for code-reader probes. One monotonic
request deadline spans admission, identity, listing, probes, search and output.
Workers and admitted probes are bounded across all sessions in one service process, not
multiplied per query. A deadline or upstream failure returns no partial result.
Overlapping checks for the same session/repository share one future before worker
admission; released capacity wakes pending requests even while their other probes are
still running. The request timeout is a socket inactivity timeout; each upstream request additionally has the absolute lifetime described under "Cancellation and resource bounds".
Multiple service processes each have their own pool and caches.
The caller owns `ForgejoAuth` and must call its idempotent `close()` after stopping
HTTP requests; the CLI does so when its serve loop exits (also on `SIGTERM`). Shutdown
joins admitted probes and listing workers rather than abandoning their threads.

Cold unscoped searches still probe **every visible, indexed repository**, not just
repositories with text matches. A `repo:` qualifier narrows candidates (and the native
listing); `owner:` narrows candidates only; path/language terms do not. Empty queries skip
code probes. Warm entries avoid HTTP requests until expiry or eviction. Increase capacity
only with measured upstream headroom; never bypass code permission checks or lengthen
permission TTLs to hide overload.

## Cancellation and resource bounds

Cancellation stops future work; it does not preempt a blocked call. Documented bounds:

| Resource | Bound after the request is cancelled or out of time |
| --- | --- |
| Handler thread / client | Answers at the deadline (`504` / terminal `error`); output writes may overrun the deadline by at most 0.5 s, and one write by at most 5 s otherwise. A vanished NDJSON reader is detected by a failed heartbeat write (at most `--heartbeat-interval` plus the write budget). A JSON client that disconnects is noticed only when the response is written: its search runs to completion or to the request deadline, because read-side EOF is a legal TCP half-close and is not treated as a disconnect. A rejected request is drained for at most 0.5 s in total. |
| Worker slot and admission | Held until the work itself ends, never released early: the blocked call below finishes, the next checkpoint raises. Total outstanding work is `--search-workers + --search-queue`. |
| Condition and flight waits | End immediately (cancellation wakes them; no polling). |
| Upstream requests (Forgejo) | Every upstream request has an ABSOLUTE lifetime of twice `--request-timeout` (4 s by default), clamped to the request's remaining deadline: a watchdog shuts the socket down at that instant, which wakes a blocked header or body read, so a peer trickling bytes inside the inactivity timeout cannot retain a worker (a single upstream response is also capped at 4 MiB). Shared code probes and identity checks that are not bound to one request use the same 4 s. **Not covered:** DNS resolution runs in the operating system's resolver (`getaddrinfo`), which Python's socket timeout does NOT bound, so a slow or hung resolver can retain the calling worker slot longer than any budget here (finite admitted capacity bounds the damage, nothing frees it early). The documented bound holds for a plain-HTTP, IP-literal `--forgejo` (the deployed local-Forgejo shape): no DNS, and the TCP connect is bounded by the socket timeout before the watchdog is armed. A TLS (`https`) base is not covered: handshakes are not separately bounded. |
| Not-yet-started shared probes | Not scheduled after cancellation; a probe in flight is never cancelled for another viewer. |
| SQLite | A statement of a request-bound connection is interrupted within about 1000 VM steps of the cancellation or deadline; cancellation is also checked between stages. Index and offline connections are never interrupted. |
| `git cat-file` | `min(1.25 s, time left)`; killed at its timeout. |
| `ast-grep` | `min(2 s, time left)`; killed at its timeout. Its stdout is captured in memory (see coverage). |
| Shutdown | `SIGTERM`/`server_close()` stops accepting, cancels open requests and waits at most 5 s for handlers and workers; stuck socket work is abandoned, not killed. |
| Queues | The work pool is bounded by admission; a queued search whose client disconnects, or that the deadline or shutdown reaches before it starts, is cancelled and returns its slot at once; the listing pool and every listing request are bounded by `--visibility-concurrency`; the probe pool by `--code-probe-concurrency`. Connections beyond `--max-connections` get an immediate `503 server_busy`. |
| Slow request headers | **Not bounded by elapsed time.** Reading a request line or header is cut after `client_timeout` (10 s) of *inactivity*, so a client that trickles one byte every few seconds can hold a connection slot (and, at `--max-connections`, make others see `503 server_busy`) until it stops. The request deadline starts after the headers are parsed. Terminate slow-header clients at the reverse proxy (nginx `client_header_timeout`). |

The package version is 0.4.0 (additive: opt-in streaming, new serve flags, `repo=` hint
and `session_authenticated()` on `ForgejoAuth`). Deployment still identifies the runtime by
its full vendored source revision, not package metadata: the infrastructure owner must
update both REVISION and VERSION when integrating this source. A source pull request does
not update the running service.

## Measurements

`benchmarks/search_latency.py` runs the real server and `ForgejoAuth` against a synthetic
loopback Forgejo with per-request counters (no credentials, no production data). Fixture
timings, not production guarantees. Cold JSON wall time and upstream requests, before
(0.3.0) and after (0.4.0); the recorded case is 750 visible repositories, 26 indexed, one
real second per listing request and 5 ms per probe; the others use 50 ms per listing page,
20 ms per probe and 50 ms per identity request:

| Workload | 0.3.0 | 0.4.0 |
| --- | --- | --- |
| 16 pages × 1 s, unscoped | 16.16 s, 16 listing + 26 probes | 3.07 s, 16 listing + 26 probes |
| 16 pages × 1 s, `repo:` | 16.12 s, 16 listing + 1 probe | 2.03 s, 2 keyword pages + 1 probe |
| 16 pages × 1 s, empty query | 16.10 s, 16 listing | 0.05 s, 1 identity request |
| 600 repositories, unscoped / `repo:` / empty | 2.80 / 0.77 / 0.76 s | 2.20 / 0.15 / 0.06 s |
| 1000 repositories, unscoped / `repo:` / empty | 4.61 / 1.23 / 1.23 s | 3.64 / 0.14 / 0.06 s |
| 600 repositories, 300 denied | 4.94 s, 313 listing | 2.27 s, 13 listing + 1 identity |

Warm searches stay at 2–8 ms with zero upstream requests. A 750-repository search with
6 s listing pages took 18.08 s end to end as a stream: first byte after 1 ms, nine
heartbeats about every 2 s, then `result` and `done`.

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
