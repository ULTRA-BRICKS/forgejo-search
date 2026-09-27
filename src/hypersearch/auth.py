from __future__ import annotations

import http.client
import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from hashlib import sha256
from urllib.parse import quote

DEFAULT_FORGEJO_URL = "http://127.0.0.1:3000"
DEFAULT_FORGEJO_PUBLIC_HOST = "git.hyperide.ai"
_MISS = object()
_PAGE_SIZE = 50
# Pagination stops the instant a page comes back empty, so this bounds the
# number of *pages* fetched before failing closed, not a repository count --
# at the default page size that's ~1000 repos, but it scales with whatever
# page size Forgejo's web route actually enforces server-side.
_MAX_PAGES = 21
# Forgejo's reqSignIn middleware unconditionally requires a session for
# /repo/search (hardcoded `SignInRequired: func() bool { return true }` in
# Forgejo's web router -- unlike routes gated by the config-dependent
# RequireSignInView setting) and redirects anonymous/revoked sessions to
# /user/login; our no-redirect opener surfaces that as an HTTPError. 401 is a
# defensive fallback should a future Forgejo version answer directly instead
# of redirecting. 403 is deliberately NOT included here: a WAF/proxy/IP
# block in front of Forgejo commonly answers 403 for a fully signed-in user,
# and that is "authenticated but forbidden", not proof of anonymity -- it
# must fail closed as unavailable (503), not a cached, misleading 401.
# A 3xx is only trusted as "not authenticated" if its Location genuinely
# targets the login route -- an unrelated redirect (HTTP->HTTPS upgrade,
# canonical-host normalization) must not be misread as "anonymous".
_LOGIN_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_LOGIN_REQUIRED_STATUSES = frozenset({401})
# Status contract for Forgejo's native per-repo code-search route
# (`/{owner}/{reponame}/search`, gated by `reqRepoCodeReader` ==
# `context.RequireRepoReader(unit.TypeCode)`, pinned web.go:1824-1836): a repo
# the actor can see but lacks TypeCode on answers ctx.NotFound (404); a repo
# that doesn't exist, or where the actor has zero access at all, 404s even
# earlier via context.RepoAssignment. 404 is therefore the ONLY clean,
# cacheable deny signal. 403 is deliberately excluded here for the same
# reason it is excluded from a login-redirect decision above: a WAF/proxy/IP
# block in front of Forgejo commonly answers 403 for a fully authorized,
# signed-in, code-reading user -- "authenticated but forbidden", not proof of
# denial. It must fall through to VisibilityUnavailable, never a cached deny.
_CODE_DENIED_STATUSES = frozenset({404})
# Defense in depth for the path built from a repository full_name: exactly
# one `/`, restricted to Forgejo's own safe owner/repo charset. `repos`
# should only ever originate from our own trusted visible_repositories()
# allow-list intersected with our locally indexed repo table, never from
# user input directly, but code_readable_repositories() validates every
# candidate up front and fails the WHOLE call closed if anything doesn't
# match, before issuing a single request.
_REPO_FULL_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
# The charset above alone still allows a segment made entirely of dots
# (".", "..", "..."...); quote() never percent-encodes "." (it is an
# RFC 3986 unreserved character), so an unfiltered ".." segment would build
# a literal path-traversal path such as "/acme/../search". Neither a real
# Forgejo owner/repo name nor our locally indexed repo table can ever
# produce this, but it is rejected explicitly here, not by accident.
_ALL_DOTS_RE = re.compile(r"^\.+$")


def _is_safe_repo_full_name(full_name: str) -> bool:
    if not _REPO_FULL_NAME_RE.fullmatch(full_name):
        return False
    owner, _, name = full_name.partition("/")
    return not (_ALL_DOTS_RE.fullmatch(owner) or _ALL_DOTS_RE.fullmatch(name))


# A page-1 request that fails transport-wise (timeout, connection error, a
# non-JSON/undecodable body, a truncated read) doesn't prove the session is
# anonymous -- ValueError covers both json.JSONDecodeError and the
# UnicodeDecodeError a non-UTF-8 body raises; HTTPException covers a
# truncated read (http.client.IncompleteRead). All must fail closed with an
# explicit, uncached VisibilityUnavailable rather than crash the handler or
# be silently treated as "not authenticated".
_TRANSPORT_ERRORS = (
    urllib.error.URLError,
    TimeoutError,
    ValueError,
    http.client.HTTPException,
)


def _redirects_to_login(error: urllib.error.HTTPError) -> bool:
    location = (error.headers or {}).get("Location", "")
    return urllib.parse.urlparse(location).path.rstrip("/") == "/user/login"


class VisibilityUnavailable(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ForgejoAuth:
    def __init__(
        self,
        base: str = DEFAULT_FORGEJO_URL,
        public_host: str = DEFAULT_FORGEJO_PUBLIC_HOST,
        *,
        ttl: float = 30.0,
        negative_ttl: float = 5.0,
        max_entries: int = 512,
        request_timeout: float = 2.0,
        code_cache_max_entries: int = 8192,
        code_probe_budget: float = 10.0,
    ):
        self.base = base.rstrip("/")
        self.public_host = public_host
        self.ttl = ttl
        self.negative_ttl = negative_ttl
        self.max_entries = max_entries
        self.request_timeout = request_timeout
        # The code-ACL cache is keyed per (cookie, repo) -- a single active
        # session searching across a large index needs far more entries than
        # the repo-visibility cache above, which is keyed per cookie alone.
        # It gets its own bound rather than sharing `max_entries` so a wide
        # index can't thrash the (much smaller) session-visibility cache.
        self.code_cache_max_entries = code_cache_max_entries
        # Explicit wall-clock deadline for the WHOLE code_readable_repositories()
        # call, independent of how many repos are pending. Bounded concurrency
        # (8 in flight) alone only bounds *fan-out*, not total wall time: an
        # implicit "ceil(N/8) * request_timeout" deadline still lets a large N
        # (e.g. 250s at N=1000, request_timeout=2s) stall the request far
        # longer than any caller should wait. This budget caps total wall time
        # regardless of N; once it elapses, the call fails closed (503) with
        # no partial allow-list, rather than serially waiting out every wave.
        self.code_probe_budget = code_probe_budget
        self.cache: OrderedDict[str, tuple[float, bool, tuple[str, ...]]] = OrderedDict()
        self._code_cache: OrderedDict[str, tuple[float, bool]] = OrderedDict()
        self._guard = threading.Lock()
        self._inflight: dict[str, threading.Event] = {}
        self._code_inflight: dict[str, threading.Event] = {}
        # Never allow Forgejo session cookies through ambient HTTP(S)_PROXY, and
        # never follow a redirect that could carry the Cookie off the local origin.
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirect(),
        )

    def _get(self, path: str, cookie: str):
        request = urllib.request.Request(
            self.base + path,
            headers={
                "Cookie": cookie,
                "Host": self.public_host,
                "X-Forwarded-Proto": "https",
                "Accept": "application/json",
            },
        )
        with self._opener.open(request, timeout=self.request_timeout) as response:
            return json.load(response)

    def _head(self, path: str, cookie: str) -> int:
        # HEAD is safe and correctly gated identically to GET for this route:
        # Forgejo's web router installs chi's global `GetHead` middleware
        # before any route group is mounted (web.go:361), which transparently
        # serves a HEAD request through the exact same GET handler chain --
        # including `reqRepoCodeReader` -- and Go's stdlib response writer
        # independently discards the body for HEAD regardless. This probes
        # identical authorization to a real GET without transferring a body.
        request = urllib.request.Request(
            self.base + path,
            method="HEAD",
            headers={
                "Cookie": cookie,
                "Host": self.public_host,
                "X-Forwarded-Proto": "https",
            },
        )
        with self._opener.open(request, timeout=self.request_timeout) as response:
            return int(response.status)

    def _remember(
        self,
        key: str,
        authenticated: bool,
        repos: set[str],
        ttl: float,
    ) -> None:
        with self._guard:
            self.cache[key] = (
                time.monotonic() + ttl,
                authenticated,
                tuple(sorted(repos)),
            )
            self.cache.move_to_end(key)
            while len(self.cache) > self.max_entries:
                self.cache.popitem(last=False)

    def _cached(self, key: str):
        with self._guard:
            cached = self.cache.get(key)
            if not cached:
                return _MISS
            if cached[0] <= time.monotonic():
                self.cache.pop(key, None)
                return _MISS
            self.cache.move_to_end(key)
            return cached[1], set(cached[2])

    def _claim(
        self, key: str, inflight: dict[str, threading.Event] | None = None
    ) -> tuple[threading.Event, bool]:
        inflight = self._inflight if inflight is None else inflight
        with self._guard:
            event = inflight.get(key)
            if event is not None:
                return event, False
            event = threading.Event()
            inflight[key] = event
            return event, True

    def _release(
        self,
        key: str,
        event: threading.Event,
        inflight: dict[str, threading.Event] | None = None,
    ) -> None:
        inflight = self._inflight if inflight is None else inflight
        with self._guard:
            if inflight.get(key) is event:
                inflight.pop(key, None)
            event.set()

    @staticmethod
    def _search_batch(payload) -> list:
        # /repo/search (Forgejo's session-authenticated web route, used by its own
        # repo picker/dropdowns; verified live against git.hyperide.ai on Forgejo
        # 16.0.3, 2026-09-26) replies {"ok": true, "data": [{"repository": {...}}]}.
        # Any other shape means we can't trust the payload, even on HTTP 200.
        # Returned as-is (not filtered) so pagination continuation below sees
        # Forgejo's real page length, not a length shrunk by dropping bad rows.
        if (
            isinstance(payload, dict)
            and payload.get("ok") is True
            and isinstance(payload.get("data"), list)
        ):
            return payload["data"]
        raise VisibilityUnavailable("Forgejo returned an unexpected repository search payload")

    @staticmethod
    def _full_names(batch: list) -> set[str]:
        names: set[str] = set()
        for row in batch:
            if not isinstance(row, dict):
                continue
            repo = row.get("repository")
            if isinstance(repo, dict) and repo.get("full_name"):
                names.add(str(repo["full_name"]))
        return names

    def visible_repositories(self, cookie: str) -> tuple[bool, set[str]]:
        if not cookie:
            return False, set()

        key = sha256(cookie.encode()).hexdigest()
        cached = self._cached(key)
        if cached is not _MISS:
            return cached

        event, leader = self._claim(key)
        if not leader:
            if not event.wait(timeout=max(10.0, self.request_timeout * 3)):
                raise VisibilityUnavailable("Forgejo visibility check timed out")
            cached = self._cached(key)
            if cached is _MISS:
                raise VisibilityUnavailable("Forgejo visibility check failed")
            return cached

        try:
            # Another leader may have filled the cache immediately before this
            # thread claimed the key.
            cached = self._cached(key)
            if cached is not _MISS:
                return cached

            # Forgejo's REST API (/api/v1/*) only accepts token/basic/oauth2 auth --
            # a browser session Cookie is always rejected there. /repo/search is a
            # *web* route behind Forgejo's session-authenticated `reqSignIn`
            # middleware (the same one that gates the repo picker in Forgejo's own
            # UI), so it is both our identity check and our visibility source in one
            # call: an anonymous or revoked session is redirected to /user/login,
            # which our no-redirect opener turns into an HTTPError below. GET
            # requests are not subject to Forgejo's CSRF check (only state-changing
            # verbs are), so no CSRF token is required here.
            try:
                payload = self._get(f"/repo/search?limit={_PAGE_SIZE}&page=1", cookie)
                batch = self._search_batch(payload)
            except urllib.error.HTTPError as error:
                if error.code in _LOGIN_REQUIRED_STATUSES or (
                    error.code in _LOGIN_REDIRECT_STATUSES and _redirects_to_login(error)
                ):
                    self._remember(key, False, set(), self.negative_ttl)
                    return False, set()
                raise VisibilityUnavailable(
                    f"Forgejo visibility check failed with HTTP {error.code} on page 1"
                ) from error
            except _TRANSPORT_ERRORS as error:
                # A transport failure, timeout, or undecodable/malformed body
                # doesn't prove the session is anonymous -- it means we
                # couldn't tell. Fail closed with an explicit, uncached error
                # rather than silently bouncing a real, signed-in session
                # with a cached 401.
                raise VisibilityUnavailable(
                    "Forgejo repository visibility check failed on page 1"
                ) from error
            # A malformed-but-200 page-1 body is likewise not proof of anonymity:
            # reqSignIn already let this request through the handler, so a bad
            # payload shape here is Forgejo (or our parsing) failing, not the
            # session being invalid. Let _search_batch's VisibilityUnavailable
            # propagate uncaught.

            repositories: set[str] = self._full_names(batch)
            # Keep paginating while a page came back non-empty, stopping the
            # instant one is empty. This proves "no more results" regardless of
            # what page size Forgejo's web route actually enforces -- it does
            # not assume `limit` is honored exactly, unlike checking
            # `len(batch) == _PAGE_SIZE`.
            if batch:
                for page in range(2, _MAX_PAGES + 1):
                    try:
                        payload = self._get(
                            f"/repo/search?limit={_PAGE_SIZE}&page={page}", cookie
                        )
                        batch = self._search_batch(payload)
                    except (urllib.error.HTTPError, *_TRANSPORT_ERRORS) as error:
                        raise VisibilityUnavailable(
                            f"Forgejo repository visibility check failed on page {page}"
                        ) from error
                    if not batch:
                        break
                    if page == _MAX_PAGES:
                        raise VisibilityUnavailable(
                            "Forgejo repository visibility exceeded the pagination "
                            f"safety bound ({_MAX_PAGES} pages fetched, page {_MAX_PAGES} "
                            "still non-empty)"
                        )
                    repositories.update(self._full_names(batch))

            self._remember(key, True, repositories, self.ttl)
            return True, repositories
        finally:
            self._release(key, event)

    def _code_key(self, cookie: str, repo: str) -> str:
        return sha256((cookie + "\0" + repo).encode()).hexdigest()

    def _code_cached(self, key: str):
        with self._guard:
            cached = self._code_cache.get(key)
            if not cached:
                return _MISS
            if cached[0] <= time.monotonic():
                self._code_cache.pop(key, None)
                return _MISS
            self._code_cache.move_to_end(key)
            return cached[1]

    def _remember_code(self, key: str, allowed: bool) -> None:
        # Same TTL / negative-TTL expiry window as the repo-visibility cache
        # above (self.ttl / self.negative_ttl) -- a revoked code-read grant
        # must disappear within the identical logout window as a revoked
        # repo-visibility grant, not a separate, shorter, hardcoded cap.
        ttl = self.ttl if allowed else self.negative_ttl
        with self._guard:
            self._code_cache[key] = (time.monotonic() + ttl, allowed)
            self._code_cache.move_to_end(key)
            while len(self._code_cache) > self.code_cache_max_entries:
                self._code_cache.popitem(last=False)

    def _code_readable(self, cookie: str, repo: str) -> bool:
        key = self._code_key(cookie, repo)
        cached = self._code_cached(key)
        if cached is not _MISS:
            return cached

        # Single-flight per (cookie, repo): search-as-you-type fires
        # overlapping requests for the same session routinely, so a cold or
        # just-expired cache entry must not let K concurrent callers each
        # probe the same repo -- exactly the coalescing visible_repositories()
        # already does for the repo-visibility cache above, keyed separately
        # so the two caches' in-flight sets never collide.
        event, leader = self._claim(key, self._code_inflight)
        if not leader:
            if not event.wait(timeout=max(10.0, self.request_timeout * 3)):
                raise VisibilityUnavailable("Forgejo code visibility check timed out")
            cached = self._code_cached(key)
            if cached is _MISS:
                raise VisibilityUnavailable("Forgejo code visibility check failed")
            return cached

        try:
            # Another leader may have filled the cache immediately before
            # this thread claimed the key.
            cached = self._code_cached(key)
            if cached is not _MISS:
                return cached

            owner, name = repo.split("/", 1)
            path = f"/{quote(owner, safe='')}/{quote(name, safe='')}/search"
            try:
                status = self._head(path, cookie)
            except urllib.error.HTTPError as error:
                if error.code in _CODE_DENIED_STATUSES:
                    self._remember_code(key, False)
                    return False
                if error.code in _LOGIN_REQUIRED_STATUSES or (
                    error.code in _LOGIN_REDIRECT_STATUSES
                    and _redirects_to_login(error)
                ):
                    # The session that visible_repositories() just proved
                    # authenticated a moment ago is no longer valid.
                    # Surprising and inconsistent mid-check -- treat as
                    # unavailable, do not silently reinterpret the whole
                    # request as anonymous from inside this per-repo helper;
                    # that is visible_repositories()'s job, not this one's.
                    raise VisibilityUnavailable(
                        "Forgejo session was no longer valid during a code "
                        "visibility check"
                    ) from error
                # Any other status -- 403 included, see _CODE_DENIED_STATUSES'
                # comment -- fails closed as unavailable, never a cached deny.
                raise VisibilityUnavailable(
                    f"Forgejo code visibility check failed with HTTP {error.code}"
                ) from error
            except _TRANSPORT_ERRORS as error:
                raise VisibilityUnavailable(
                    "Forgejo code visibility check failed"
                ) from error
            allowed = 200 <= status < 300
            self._remember_code(key, allowed)
            return allowed
        finally:
            self._release(key, event, self._code_inflight)

    def code_readable_repositories(self, cookie: str, repos: set[str]) -> set[str]:
        """Narrow a repo-visibility set to the subset the caller can actually
        read code from, per Forgejo's native `reqRepoCodeReader`
        (`unit.TypeCode`) gate on `/{owner}/{reponame}/search` (pinned
        web.go:1824-1836). Repository *visibility* (granted by any unit --
        issues, wiki, projects, releases...) does not imply code-read access;
        this is the stronger, code-specific check that must run before any
        file/symbol/AST/text search result is allowed to come from a repo.
        """
        if not cookie or not repos:
            return set()
        if any(not _is_safe_repo_full_name(repo) for repo in repos):
            raise VisibilityUnavailable(
                "Refusing to check code visibility for a malformed repository name"
            )
        readable: set[str] = set()
        pending: list[str] = []
        for repo in repos:
            cached = self._code_cached(self._code_key(cookie, repo))
            if cached is _MISS:
                pending.append(repo)
            elif cached:
                readable.add(repo)
        if not pending:
            # Fast path for the common steady state (an actively-typing
            # session between TTL windows): every candidate is already
            # resolved in cache, so skip spinning up a ThreadPoolExecutor and
            # its worker threads entirely.
            return readable

        deadline = time.monotonic() + self.code_probe_budget
        errors: list[VisibilityUnavailable] = []
        # Bounded concurrency (at most 8 in-flight per-repo checks at a
        # time) bounds *fan-out*, not total wall time -- an implicit
        # ceil(N / 8) * request_timeout deadline alone could still stall a
        # large N far longer than any caller should wait. code_probe_budget
        # is an explicit wall-clock deadline over the *entire* fan-out
        # below, tracked independently of how many waves it takes.
        executor = ThreadPoolExecutor(max_workers=min(8, len(pending)))
        try:
            futures = {
                executor.submit(self._code_readable, cookie, repo): repo
                for repo in sorted(pending)
            }
            remaining = set(futures)
            timed_out = False
            while remaining:
                budget_left = deadline - time.monotonic()
                if budget_left <= 0:
                    timed_out = True
                    break
                done, remaining = wait(remaining, timeout=budget_left, return_when=FIRST_COMPLETED)
                if not done:
                    # wait() timed out without anything completing.
                    timed_out = True
                    break
                failed = False
                for future in done:
                    try:
                        if future.result():
                            readable.add(futures[future])
                    except VisibilityUnavailable as error:
                        errors.append(error)
                        failed = True
                if failed:
                    # Fail fast: the whole call is going to raise regardless
                    # (no partial allow-list on an ambiguous failure), so
                    # cancel every not-yet-started probe instead of paying a
                    # full request_timeout for each remaining candidate.
                    for other in remaining:
                        other.cancel()
                    break
            if timed_out:
                # No partial allow-list on a budget overrun either: cancel
                # every remaining/not-yet-started probe and fail the whole
                # call closed, exactly like an ambiguous upstream failure.
                for other in remaining:
                    other.cancel()
                raise VisibilityUnavailable(
                    f"Forgejo code visibility check exceeded the "
                    f"{self.code_probe_budget}s probe budget with "
                    f"{len(remaining)} probe(s) still pending"
                )
        finally:
            # Always release the pool's worker threads even when we bail out
            # early on a timeout -- a timed-out call must not then block the
            # caller waiting for straggler threads to finish anyway.
            executor.shutdown(wait=False, cancel_futures=True)
        if errors:
            # No partial allow-list on an ambiguous upstream failure: if ANY
            # repo's check couldn't be resolved, fail the whole call closed
            # rather than silently under-scoping the result.
            raise errors[0]
        return readable

