"""Native-session authorization for the search HTTP handler.

Repository visibility is not code permission. Ambiguous upstream responses fail
closed; short unavailable backoff must never turn a valid viewer into anonymous.
"""

from __future__ import annotations

import http.client
import json
import math
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import contextmanager
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
# `context.RequireRepoReader(unit.TypeCode)`, pinned web.go:1824-1836): both
# missing code permission and anonymous private-repo access can answer 404.
# A deny is cacheable only after a fresh /repo/search identity check. 403
# is not proof of denial: a WAF/proxy/IP block may answer it for an
# authorized viewer, so it must fail closed as unavailable.
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
# explicit VisibilityUnavailable rather than crash the handler or be silently
# treated as "not authenticated".
_TRANSPORT_ERRORS = (
    urllib.error.URLError,
    TimeoutError,
    ValueError,
    http.client.HTTPException,
)


class VisibilityUnavailable(RuntimeError):
    _recorded = False


class _BackoffActive(VisibilityUnavailable):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def probe_seconds(value) -> float:
    seconds = float(value)
    if not math.isfinite(seconds) or not 0 < seconds <= 120:
        raise ValueError("probe seconds must be finite and greater than 0, at most 120")
    return seconds


def probe_concurrency(value) -> int:
    count = int(str(value))
    if not 1 <= count <= 64:
        raise ValueError("probe concurrency must be an integer from 1 to 64")
    return count


def code_cache_entries(value) -> int:
    count = int(str(value))
    if not 1 <= count <= 1_000_000:
        raise ValueError("code cache entries must be an integer from 1 to 1000000")
    return count


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
        code_probe_concurrency: int = 8,
    ):
        self.base = base.rstrip("/")
        self.public_host = public_host
        self.ttl = ttl
        self.negative_ttl = negative_ttl
        self.max_entries = max_entries
        self.request_timeout = probe_seconds(request_timeout)
        # The code-ACL cache is keyed per (cookie, repo) -- a single active
        # session searching across a large index needs far more entries than
        # the repo-visibility cache above, which is keyed per cookie alone.
        # It gets its own bound rather than sharing `max_entries` so a wide
        # index can't thrash the (much smaller) session-visibility cache.
        self.code_cache_max_entries = code_cache_entries(code_cache_max_entries)
        # Explicit wall-clock deadline for the WHOLE code_readable_repositories()
        # call, independent of how many repos are pending. Bounded concurrency
        # (8 in flight) alone only bounds *fan-out*, not total wall time: an
        # implicit "ceil(N/8) * request_timeout" deadline still lets a large N
        # (e.g. 250s at N=1000, request_timeout=2s) stall the request far
        # longer than any caller should wait. This budget caps total wall time
        # regardless of N; once it elapses, the call fails closed (503) with
        # no partial allow-list, rather than serially waiting out every wave.
        self.code_probe_budget = probe_seconds(code_probe_budget)
        self.code_probe_concurrency = probe_concurrency(code_probe_concurrency)
        self._executor: ThreadPoolExecutor | None = None
        self._closed = False
        self.cache: OrderedDict[str, tuple[float, bool, tuple[str, ...]]] = OrderedDict()
        self._code_cache: OrderedDict[str, tuple[float, bool]] = OrderedDict()
        self._code_keys: dict[str, set[str]] = {}
        self._unavailable: OrderedDict[str, tuple[float, str]] = OrderedDict()
        self._guard = threading.RLock()
        self._capacity = threading.Condition(self._guard)
        self._inflight: dict[str, threading.Event] = {}
        self._code_futures: dict[str, tuple[Future, threading.Event]] = {}
        self._active_checks: dict[str, set[threading.Event]] = {}
        # Never allow Forgejo session cookies through ambient HTTP(S)_PROXY, and
        # never follow a redirect that could carry the Cookie off the local origin.
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirect(),
        )

    def close(self) -> None:
        """Release workers after the owner stops accepting search requests."""
        with self._capacity:
            self._closed = True
            executor = self._executor
            for checks in self._active_checks.values():
                for revoked in checks:
                    revoked.set()
            self._capacity.notify_all()
        if executor is not None:
            executor.shutdown(wait=True, cancel_futures=True)

    def _redirects_to_login(self, error: urllib.error.HTTPError) -> bool:
        try:
            target = urllib.parse.urlsplit((error.headers or {}).get("Location", ""))
            base = urllib.parse.urlsplit(self.base)
        except ValueError:
            return False
        if target.scheme and target.scheme not in {"http", "https"}:
            return False
        if target.netloc and (
            target.username is not None
            or target.netloc.lower() not in {base.netloc.lower(), self.public_host.lower()}
        ):
            return False
        return target.path.rstrip("/") == base.path.rstrip("/") + "/user/login"

    def _backoff(self, key: str) -> None:
        with self._guard:
            cached = self._unavailable.get(key)
            if cached is None:
                return
            if cached[0] <= time.monotonic():
                self._unavailable.pop(key, None)
                return
            self._unavailable.move_to_end(key)
            raise _BackoffActive(cached[1])

    def _remember_unavailable(self, key: str, error: VisibilityUnavailable) -> None:
        if isinstance(error, _BackoffActive):
            return
        with self._guard:
            if error._recorded:
                return
            error._recorded = True
            now = time.monotonic()
            cached = self._unavailable.get(key)
            # Re-observing a cached failure must not postpone upstream recovery.
            if cached is not None and cached[0] > now:
                return
            self._unavailable[key] = (now + 5.0, str(error))
            self._unavailable.move_to_end(key)
            while len(self._unavailable) > self.max_entries:
                self._unavailable.popitem(last=False)

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
            if not authenticated:
                for revoked in self._active_checks.get(key, ()):
                    revoked.set()
                for code_key in self._code_keys.pop(key, ()):
                    self._code_cache.pop(code_key, None)
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

    def _fetch_page(self, cookie: str, page: int) -> list | None:
        try:
            return self._search_batch(
                self._get(f"/repo/search?limit={_PAGE_SIZE}&page={page}", cookie)
            )
        except urllib.error.HTTPError as error:
            if error.code in _LOGIN_REQUIRED_STATUSES or (
                error.code in _LOGIN_REDIRECT_STATUSES and self._redirects_to_login(error)
            ):
                return None
            raise VisibilityUnavailable(
                f"Forgejo repository visibility check failed with HTTP {error.code} on page {page}"
            ) from error
        except (*_TRANSPORT_ERRORS, VisibilityUnavailable) as error:
            raise VisibilityUnavailable(
                f"Forgejo repository visibility check failed on page {page}"
            ) from error

    def visible_repositories(self, cookie: str) -> tuple[bool, set[str]]:
        if not cookie:
            return False, set()

        key = sha256(cookie.encode()).hexdigest()
        self._backoff(key)
        cached = self._cached(key)
        if cached is not _MISS:
            return cached

        event, leader = self._claim(key)
        if not leader:
            if not event.wait(timeout=max(10.0, self.request_timeout * 3)):
                raise VisibilityUnavailable("Forgejo visibility check timed out")
            self._backoff(key)
            cached = self._cached(key)
            if cached is _MISS:
                raise VisibilityUnavailable("Forgejo visibility check failed")
            return cached

        revoked = self._start_check(key)
        try:
            # Another leader may have filled the cache immediately before this
            # thread claimed the key.
            cached = self._cached(key)
            if cached is not _MISS:
                return cached
            self._backoff(key)
            checked_at = time.monotonic()

            # Only the session-authenticated web route accepts browser cookies;
            # token-only REST routes cannot establish this viewer's identity.
            batch = self._fetch_page(cookie, 1)
            if batch is None:
                self._remember(key, False, set(), self.negative_ttl)
                return False, set()

            repositories: set[str] = self._full_names(batch)
            # Keep paginating while a page came back non-empty, stopping the
            # instant one is empty. This proves "no more results" regardless of
            # what page size Forgejo's web route actually enforces -- it does
            # not assume `limit` is honored exactly, unlike checking
            # `len(batch) == _PAGE_SIZE`.
            if batch:
                for page in range(2, _MAX_PAGES + 1):
                    batch = self._fetch_page(cookie, page)
                    if batch is None:
                        self._remember(key, False, set(), self.negative_ttl)
                        raise VisibilityUnavailable(
                            f"Forgejo session was no longer valid on page {page}"
                        )
                    if not batch:
                        break
                    if page == _MAX_PAGES:
                        raise VisibilityUnavailable(
                            "Forgejo repository visibility exceeded the pagination "
                            f"safety bound ({_MAX_PAGES} pages fetched, page {_MAX_PAGES} "
                            "still non-empty)"
                        )
                    repositories.update(self._full_names(batch))

            with self._guard:
                if revoked.is_set():
                    raise VisibilityUnavailable("Forgejo session was revoked during pagination")
                remaining = checked_at + self.ttl - time.monotonic()
                if remaining <= 0:
                    raise VisibilityUnavailable("Forgejo visibility grant expired during pagination")
                self._remember(key, True, repositories, remaining)
                return True, repositories
        except VisibilityUnavailable as error:
            self._remember_unavailable(key, error)
            raise
        finally:
            self._finish_check(key, revoked)
            self._release(key, event)

    def _code_key(self, cookie: str, repo: str) -> str:
        return sha256(cookie.encode()).hexdigest() + ":" + sha256(repo.encode()).hexdigest()

    def _session_revoked(self, cookie: str) -> None:
        key = sha256(cookie.encode()).hexdigest()
        self._remember(key, False, set(), self.negative_ttl)
        raise VisibilityUnavailable("Forgejo session was no longer valid during a code visibility check")

    def _check_session_state(self, cookie: str) -> None:
        key = sha256(cookie.encode()).hexdigest()
        self._backoff(key)
        with self._guard:
            if self._closed:
                raise VisibilityUnavailable("Forgejo authorization is closed")
            cached = self.cache.get(key)
            if cached is not None and cached[0] > time.monotonic() and not cached[1]:
                raise VisibilityUnavailable("Forgejo session is no longer valid")

    def _start_check(self, key: str) -> threading.Event:
        revoked = threading.Event()
        with self._guard:
            self._active_checks.setdefault(key, set()).add(revoked)
        return revoked

    def _finish_check(self, key: str, revoked: threading.Event) -> None:
        with self._guard:
            checks = self._active_checks[key]
            checks.remove(revoked)
            if not checks:
                self._active_checks.pop(key)

    @contextmanager
    def _session_check(self, cookie: str):
        key = sha256(cookie.encode()).hexdigest()
        revoked = self._start_check(key)
        try:
            self._check_session_state(cookie)
            yield revoked
            self._check_session_state(cookie)
            if revoked.is_set():
                raise VisibilityUnavailable("Forgejo session was revoked during authorization")
        finally:
            self._finish_check(key, revoked)

    def _drop_code(self, key: str) -> None:
        self._code_cache.pop(key, None)
        session_key = key.partition(":")[0]
        keys = self._code_keys.get(session_key)
        if keys is not None:
            keys.discard(key)
            if not keys:
                self._code_keys.pop(session_key)

    def _code_cached(self, key: str):
        with self._guard:
            cached = self._code_cache.get(key)
            if not cached:
                return _MISS
            if cached[0] <= time.monotonic():
                self._drop_code(key)
                return _MISS
            self._code_cache.move_to_end(key)
            return cached

    def _remember_code(
        self, key: str, allowed: bool, checked_at: float, revoked: threading.Event
    ) -> tuple[float, bool]:
        # Bound stale grants from probe start, not the end of a slow response.
        ttl = self.ttl if allowed else self.negative_ttl
        with self._guard:
            if revoked.is_set():
                raise VisibilityUnavailable("Forgejo session was revoked during authorization")
            session = self.cache.get(key.partition(":")[0])
            if session is not None and not session[1]:
                raise VisibilityUnavailable("Forgejo session is no longer valid")
            record = (checked_at + ttl, allowed)
            if allowed and record[0] <= time.monotonic():
                raise VisibilityUnavailable("Forgejo code grant expired during authorization")
            self._code_cache[key] = record
            self._code_keys.setdefault(key.partition(":")[0], set()).add(key)
            self._code_cache.move_to_end(key)
            while len(self._code_cache) > self.code_cache_max_entries:
                self._drop_code(next(iter(self._code_cache)))
            return record

    def _code_readable(
        self, cookie: str, repo: str, request_revoked: threading.Event
    ) -> tuple[float, bool]:
        with self._session_check(cookie) as revoked:
            if request_revoked.is_set():
                raise VisibilityUnavailable("Forgejo session was revoked before the probe started")
            return self._probe_code(cookie, repo, revoked)

    def _probe_code(
        self, cookie: str, repo: str, revoked: threading.Event
    ) -> tuple[float, bool]:
        key = self._code_key(cookie, repo)
        cached = self._code_cached(key)
        if cached is not _MISS:
            return cached

        try:
            owner, name = repo.split("/", 1)
            path = f"/{quote(owner, safe='')}/{quote(name, safe='')}/search"
            checked_at = time.monotonic()
            try:
                status = self._head(path, cookie)
            except urllib.error.HTTPError as error:
                if error.code in _LOGIN_REQUIRED_STATUSES or (
                    error.code in _LOGIN_REDIRECT_STATUSES and self._redirects_to_login(error)
                ):
                    self._session_revoked(cookie)
                status = error.code
            except _TRANSPORT_ERRORS as error:
                raise VisibilityUnavailable(
                    "Forgejo code visibility check failed"
                ) from error
            if status in _LOGIN_REQUIRED_STATUSES:
                self._session_revoked(cookie)
            if status in _CODE_DENIED_STATUSES:
                # RepoAssignment also hides private repos from expired sessions.
                # Bypass the visibility cache before classifying this as denial.
                if self._fetch_page(cookie, 1) is None:
                    self._session_revoked(cookie)
                allowed = False
            elif 200 <= status < 300:
                allowed = True
            else:
                raise VisibilityUnavailable(
                    f"Forgejo code visibility check failed with HTTP {status}"
                )
            self._check_session_state(cookie)
            return self._remember_code(key, allowed, checked_at, revoked)
        except VisibilityUnavailable as error:
            self._remember_unavailable("code:" + sha256(cookie.encode()).hexdigest(), error)
            raise

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
        try:
            with self._session_check(cookie) as revoked:
                readable = self._code_repositories(cookie, repos, revoked)
                if any(expires <= time.monotonic() for expires in readable.values()):
                    raise VisibilityUnavailable("Forgejo code grant expired during authorization")
                return set(readable)
        except VisibilityUnavailable as error:
            self._remember_unavailable("code:" + sha256(cookie.encode()).hexdigest(), error)
            raise

    def _code_repositories(
        self, cookie: str, repos: set[str], revoked: threading.Event
    ) -> dict[str, float]:
        self._backoff("code:" + sha256(cookie.encode()).hexdigest())
        if any(not _is_safe_repo_full_name(repo) for repo in repos):
            raise VisibilityUnavailable(
                "Refusing to check code visibility for a malformed repository name"
            )
        readable: dict[str, float] = {}
        pending: list[str] = []
        for repo in repos:
            cached = self._code_cached(self._code_key(cookie, repo))
            if cached is _MISS:
                pending.append(repo)
            elif cached[1]:
                readable[repo] = cached[0]
        if not pending:
            # Fast path for the common steady state (an actively-typing
            # session between TTL windows): every candidate is already
            # resolved in cache, so skip spinning up a ThreadPoolExecutor and
            # its worker threads entirely.
            return readable

        deadline = time.monotonic() + self.code_probe_budget
        with self._guard:
            if self._closed:
                raise VisibilityUnavailable("Forgejo authorization is closed")
            if self._executor is None:
                self._executor = ThreadPoolExecutor(
                    max_workers=self.code_probe_concurrency,
                    thread_name_prefix="forgejo-code",
                )
            executor = self._executor

        # Coalesce before admission: followers must not occupy shared workers.
        pending.sort(reverse=True)
        futures = {}

        def completed(key: str, future: Future) -> None:
            with self._capacity:
                record = self._code_futures.get(key)
                if record is not None and record[0] is future:
                    self._code_futures.pop(key)
                    self._finish_check(key.partition(":")[0], record[1])
                self._capacity.notify_all()

        def timeout_error() -> VisibilityUnavailable:
            return VisibilityUnavailable(
                f"Forgejo code visibility check exceeded the "
                f"{self.code_probe_budget}s probe budget with "
                f"{len(pending) + len(futures)} probe(s) still pending"
            )

        try:
            with self._capacity:
                while pending or futures:
                    if revoked.is_set():
                        raise VisibilityUnavailable("Forgejo session was revoked during authorization")
                    budget_left = deadline - time.monotonic()
                    if budget_left <= 0:
                        raise timeout_error()
                    # Consume failures before admitting more upstream work.
                    for future in list(futures):
                        if future.done():
                            repo, probe_revoked = futures.pop(future)
                            expires, allowed = future.result()
                            if probe_revoked.is_set():
                                raise VisibilityUnavailable("Forgejo session was revoked before probe publication")
                            if allowed:
                                readable[repo] = expires
                    while pending:
                        self._backoff("code:" + sha256(cookie.encode()).hexdigest())
                        repo = pending[-1]
                        key = self._code_key(cookie, repo)
                        cached = self._code_cached(key)
                        if cached is not _MISS:
                            pending.pop()
                            if cached[1]:
                                readable[repo] = cached[0]
                            continue
                        record = self._code_futures.get(key)
                        if record is None:
                            if len(self._code_futures) >= self.code_probe_concurrency:
                                break
                            session_key = key.partition(":")[0]
                            probe_revoked = self._start_check(session_key)
                            try:
                                future = executor.submit(self._code_readable, cookie, repo, probe_revoked)
                            except BaseException:
                                self._finish_check(session_key, probe_revoked)
                                raise
                            record = (future, probe_revoked)
                            self._code_futures[key] = record
                            future.add_done_callback(
                                lambda result, key=key: completed(key, result)
                            )
                        future, probe_revoked = record
                        pending.pop()
                        futures[future] = (repo, probe_revoked)
                    if (pending or futures) and not any(f.done() for f in futures):
                        self._capacity.wait(timeout=budget_left)
        except VisibilityUnavailable as error:
            self._remember_unavailable("code:" + sha256(cookie.encode()).hexdigest(), error)
            raise
        self._check_session_state(cookie)
        return readable

