"""Native-session authorization for the search HTTP handler.

Repository visibility is not code permission. Ambiguous upstream responses fail
closed; short unavailable backoff must never turn a valid viewer into anonymous.
"""

from __future__ import annotations

import contextvars
import http.client
import itertools
import json
import math
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import contextmanager
from hashlib import sha256
from typing import NamedTuple
from urllib.parse import quote

from . import deadline as scope

DEFAULT_FORGEJO_URL = "http://127.0.0.1:3000"
DEFAULT_FORGEJO_PUBLIC_HOST = "git.hyperide.ai"
_MISS = object()
_PAGE_SIZE = 50
# Pagination stops the instant a page comes back empty, so this bounds the
# number of *pages* fetched before failing closed, not a repository count --
# at the default page size that's ~1000 repos, but it scales with whatever
# page size Forgejo's web route actually enforces server-side.
_MAX_PAGES = 21
# Cheapest authenticated route request: `count_only` (pinned Forgejo 16.0.5
# routers/web/repo/repo.go SearchRepo) answers `{"ok": true}` after the same reqSignIn
# gate as the listing, without loading rows or commit statuses. An older server that
# ignores the parameter answers a one-row listing instead; both shapes are accepted.
_IDENTITY_PATH = "/repo/search?limit=1&page=1&count_only=true"
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


# Absolute monotonic deadline for the upstream request being made by this thread. A socket
# timeout only limits inactivity between bytes, so a peer trickling headers or body inside
# it could hold a worker (and a pool slot) indefinitely; the connection below arms a
# watchdog that shuts the socket down at this instant.
_socket_deadline: contextvars.ContextVar[tuple[float, list] | None] = contextvars.ContextVar(
    "hypersearch_socket_deadline", default=None
)


def _shutdown_socket(sock) -> None:
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


class _Watchdog:
    """Arms a timer that shuts the socket down at the absolute deadline in force at connect.

    urllib closes the connection object as soon as the response headers are parsed, while
    the body is still to be read from the same socket, so the timer is owned by the
    request (`ForgejoAuth._open`) and cancelled when the response is closed, not here.
    """

    def connect(self):
        armed = _socket_deadline.get()
        if armed is not None and armed[0] <= time.monotonic():
            raise TimeoutError("upstream request budget exhausted before connecting")
        super().connect()
        if armed is not None:
            timer = threading.Timer(
                max(0.0, armed[0] - time.monotonic()), _shutdown_socket, (self.sock,)
            )
            timer.daemon = True
            timer.start()
            armed[1].append(timer)


class _BoundedHTTPConnection(_Watchdog, http.client.HTTPConnection):
    pass


class _BoundedHTTPSConnection(_Watchdog, http.client.HTTPSConnection):
    pass


class _BoundedHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_BoundedHTTPConnection, req)


class _BoundedHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_BoundedHTTPSConnection, req)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _Payload(dict):
    """Decoded listing body plus Forgejo's advertised `X-Total-Count`, if any."""

    total_count: int | None = None


class _Batch(list):
    """Rows of one listing page; `total` only schedules requests, never proves completeness."""

    total: int | None = None


class _Denial(NamedTuple):
    """A 404 from the code route that is not yet known to be a real denial."""

    key: str
    checked_at: float
    received: int


class _Flight:
    """One in-flight identity request that concurrent denials may share."""

    __slots__ = ("abandoned", "error", "event", "result", "seq")

    def __init__(self, seq: int):
        self.seq = seq
        self.event = threading.Event()
        self.result = False
        self.error: VisibilityUnavailable | None = None
        self.abandoned = False


def _advertised_total(value) -> int | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text.isascii() or not text.isdigit() or len(text) > 9:
        return None
    return int(text)


def _scope_keyword(repo: str | None) -> str | None:
    """Native `q` keyword for an exact `owner/name` qualifier, or None to list everything.

    Only Forgejo-safe names qualify, so the keyword needs no escaping and cannot smuggle a
    comma (the native OR separator) or LIKE metacharacter other than `_`, which only widens.
    """
    if repo is None or not _is_safe_repo_full_name(repo):
        return None
    return repo.partition("/")[2].lower()


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


def page_concurrency(value) -> int:
    count = int(str(value))
    if not 1 <= count <= 64:
        raise ValueError("visibility concurrency must be an integer from 1 to 64")
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
        visibility_concurrency: int = 8,
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
        # Bounds parallel visibility-listing requests across all sessions; 1 keeps the
        # original strictly sequential walk.
        self.visibility_concurrency = page_concurrency(visibility_concurrency)
        self._executor: ThreadPoolExecutor | None = None
        self._closed = False
        self.cache: OrderedDict[str, tuple[float, bool, tuple[str, ...] | None]] = OrderedDict()
        self._code_cache: OrderedDict[str, tuple[float, bool]] = OrderedDict()
        self._code_keys: dict[str, set[str]] = {}
        self._unavailable: OrderedDict[str, tuple[float, str]] = OrderedDict()
        self._guard = threading.RLock()
        self._capacity = threading.Condition(self._guard)
        self._inflight: dict[str, threading.Event] = {}
        self._code_futures: dict[str, tuple[Future, threading.Event]] = {}
        self._active_checks: dict[str, set[threading.Event]] = {}
        # Monotonic order of upstream events. A denial is only confirmed by an identity
        # request issued after the denial was received, which wall-clock reads cannot prove.
        self._seq = itertools.count(1)
        self._page_executor: ThreadPoolExecutor | None = None
        self._identity_flights: dict[str, _Flight] = {}
        self._identity_done: OrderedDict[str, tuple[int, bool]] = OrderedDict()
        self._follower_wait = max(10.0, self.request_timeout * 3)
        self._provisional: OrderedDict[str, _Denial] = OrderedDict()
        self._listing_active = 0
        # Never allow Forgejo session cookies through ambient HTTP(S)_PROXY, and
        # never follow a redirect that could carry the Cookie off the local origin.
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirect(),
            _BoundedHTTPHandler(),
            _BoundedHTTPSHandler(),
        )

    def close(self) -> None:
        """Release workers after the owner stops accepting search requests."""
        with self._capacity:
            self._closed = True
            executors = [self._executor, self._page_executor]
            for checks in self._active_checks.values():
                for revoked in checks:
                    revoked.set()
            self._capacity.notify_all()
        for executor in executors:
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
        with self._open(request) as response:
            payload = json.loads(self._read_body(response))
            total = _advertised_total(response.headers.get("X-Total-Count"))
        if isinstance(payload, dict):
            payload = _Payload(payload)
            payload.total_count = total
        return payload

    @contextmanager
    def _open(self, request):
        """Open an upstream request whose WHOLE lifetime (headers and body) is bounded.

        The budget is twice the socket timeout, clamped by the bound request's remaining
        time; at that instant a watchdog shuts the socket down, which wakes a blocked read.
        Not covered: DNS resolution (blocking `getaddrinfo`, which the Python socket timeout
        does NOT bound) and TLS handshakes. The watchdog is armed after the connect returns, so
        the lifetime holds for a plain-HTTP, IP-literal base (the deployed local-Forgejo shape);
        the TCP connect to such an address is bounded by the socket timeout.
        """
        budget = scope.clamp(2 * self.request_timeout)
        timers: list = []
        token = _socket_deadline.set((time.monotonic() + budget, timers))
        try:
            try:
                response = self._opener.open(request, timeout=scope.clamp(self.request_timeout))
            finally:
                _socket_deadline.reset(token)
            with response:
                yield response
        finally:
            for timer in timers:
                timer.cancel()

    # A visibility page is at most 50 rows (tens of KiB); anything near this is not Forgejo.
    _MAX_BODY_BYTES = 4 * 1024 * 1024

    def _read_body(self, response) -> bytes:
        """Read a JSON body within an ABSOLUTE budget (twice the socket timeout) and size cap.

        A socket timeout only limits inactivity between bytes; an upstream trickling one
        byte per interval would otherwise retain a worker indefinitely. The budget is
        checked between reads, so a read in progress can overrun it by one socket timeout.
        """
        end = time.monotonic() + scope.clamp(2 * self.request_timeout)
        chunks: list[bytes] = []
        size = 0
        while chunk := response.read(65536):
            size += len(chunk)
            if size > self._MAX_BODY_BYTES:
                raise ValueError("Forgejo response exceeded the size cap")
            chunks.append(chunk)
            if time.monotonic() >= end:
                raise TimeoutError("Forgejo response body exceeded its time budget")
        if response.length:
            # read(amt) stops silently at an early EOF; json.load's read() raised here. A body
            # cut short of its declared Content-Length is not a complete answer even when the
            # prefix happens to be valid JSON (an empty list would read as "sees nothing").
            raise http.client.IncompleteRead(b"".join(chunks), response.length)
        return b"".join(chunks)

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
        with self._open(request) as response:
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
                # Scoped allow-lists belong to the same session and die with it.
                for scoped in [name for name in self.cache if name.startswith(key + ":")]:
                    self.cache.pop(scoped)
                for held in [name for name in self._provisional if name.startswith(key + ":")]:
                    self._provisional.pop(held)
                self._capacity.notify_all()
            self.cache[key] = (
                time.monotonic() + ttl,
                authenticated,
                tuple(sorted(repos)),
            )
            self.cache.move_to_end(key)
            while len(self.cache) > self.max_entries:
                self.cache.popitem(last=False)

    def _cached(self, key: str, need_repos: bool = True):
        with self._guard:
            cached = self.cache.get(key)
            if not cached:
                return _MISS
            if cached[0] <= time.monotonic():
                self.cache.pop(key, None)
                return _MISS
            self.cache.move_to_end(key)
            if cached[2] is None:
                # Identity-only grant: proves the session, never a repository list.
                return _MISS if need_repos else (cached[1], set())
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
            self._capacity.notify_all()

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
            batch = _Batch(payload["data"])
            batch.total = getattr(payload, "total_count", None)
            return batch
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

    def _failure(self, message: str) -> VisibilityUnavailable:
        # A caller's own deadline or cancellation is not an upstream outage: it must not
        # become a cached five-second "unavailable" for every other request of the session.
        scope.checkpoint()
        return VisibilityUnavailable(message)

    @contextmanager
    def _listing_slot(self):
        """Process-wide cap on in-flight listing requests (`--visibility-concurrency`).

        Every listing request takes a slot, wherever it comes from: a first page, a
        prefetched page or a sequential fallback page. The wait is woken by a release or by
        the caller's cancellation, never polled.
        """
        context = scope.current()
        unregister = context.on_cancel(self._wake) if context is not None else None
        try:
            with self._capacity:
                while self._listing_active >= self.visibility_concurrency:
                    pause = self._follower_wait
                    if context is not None:
                        context.check()
                        left = context.remaining()
                        if left is not None:
                            pause = min(pause, left)
                    self._capacity.wait(pause)
                self._listing_active += 1
        finally:
            if unregister is not None:
                unregister()
        try:
            yield
        finally:
            with self._capacity:
                self._listing_active -= 1
                self._capacity.notify_all()

    def _fetch_page(self, cookie: str, page: int, suffix: str = "") -> list | None:
        try:
            with self._listing_slot():
                payload = self._get(f"/repo/search?limit={_PAGE_SIZE}&page={page}{suffix}", cookie)
            return self._search_batch(payload)
        except urllib.error.HTTPError as error:
            if error.code in _LOGIN_REQUIRED_STATUSES or (
                error.code in _LOGIN_REDIRECT_STATUSES and self._redirects_to_login(error)
            ):
                # Session-wide invalidation happens HERE, where the login response is
                # seen, so a sibling page that errors cannot keep the grants alive.
                self._remember(
                    sha256(cookie.encode()).hexdigest(), False, set(), self.negative_ttl
                )
                return None
            raise self._failure(
                f"Forgejo repository visibility check failed with HTTP {error.code} on page {page}"
            ) from error
        except (*_TRANSPORT_ERRORS, VisibilityUnavailable) as error:
            raise self._failure(
                f"Forgejo repository visibility check failed on page {page}"
            ) from error

    def _fetch_identity(self, cookie: str) -> bool:
        """True when the session is signed in, False for a login redirect."""
        try:
            payload = self._get(_IDENTITY_PATH, cookie)
            if not (
                isinstance(payload, dict)
                and payload.get("ok") is True
                and isinstance(payload.get("data", []), list)
            ):
                raise VisibilityUnavailable("Forgejo returned an unexpected identity payload")
            return True
        except urllib.error.HTTPError as error:
            if error.code in _LOGIN_REQUIRED_STATUSES or (
                error.code in _LOGIN_REDIRECT_STATUSES and self._redirects_to_login(error)
            ):
                return False
            raise self._failure(
                f"Forgejo session identity check failed with HTTP {error.code}"
            ) from error
        except (*_TRANSPORT_ERRORS, VisibilityUnavailable) as error:
            raise self._failure("Forgejo session identity check failed") from error

    def _wake(self) -> None:
        with self._capacity:
            self._capacity.notify_all()

    def _wait_event(self, event: threading.Event, timeout: float) -> bool:
        """Wait for a shared flight in the caller's thread, without polling.

        Cancellation and the request deadline both wake the condition, so an abandoned
        request stops waiting at once; the flight itself is never cancelled.
        """
        context = scope.current()
        unregister = context.on_cancel(self._wake) if context is not None else None
        try:
            end = time.monotonic() + timeout
            with self._capacity:
                while not event.is_set():
                    if context is not None:
                        context.check()
                    left = end - time.monotonic()
                    remaining = None if context is None else context.remaining()
                    if remaining is not None:
                        left = min(left, remaining)
                    if left <= 0:
                        if context is not None:
                            context.check()
                        return False
                    self._capacity.wait(left)
            return True
        finally:
            if unregister is not None:
                unregister()

    def _page_pool(self) -> ThreadPoolExecutor:
        with self._guard:
            if self._closed:
                raise VisibilityUnavailable("Forgejo authorization is closed")
            if self._page_executor is None:
                self._page_executor = ThreadPoolExecutor(
                    max_workers=self.visibility_concurrency,
                    thread_name_prefix="forgejo-page",
                )
            return self._page_executor

    def _prefetch_pages(
        self, cookie: str, revoked: threading.Event, suffix: str, first: list
    ) -> dict[int, list | None]:
        """Fetch the pages Forgejo's advertised count says follow page 1, in parallel.

        The count only schedules requests. Completeness is still "every page up to the
        first empty one was fetched": the plan always includes one page past the last
        populated page, and the caller keeps walking sequentially if that sentinel (or a
        page after an understated count) turns out to hold rows.
        """
        total = getattr(first, "total", None)
        if self.visibility_concurrency <= 1 or total is None or not first:
            return {}
        size = len(first)
        populated = -(-total // size) if total > size else 1
        pages = list(range(2, min(populated + 1, _MAX_PAGES) + 1))
        if len(pages) < 2:
            return {}
        executor = self._page_pool()
        futures = {
            executor.submit(contextvars.copy_context().run, self._fetch_page, cookie, page, suffix): page
            for page in pages
        }
        for future in futures:
            future.add_done_callback(lambda _: self._wake())
        context = scope.current()
        unregister = context.on_cancel(self._wake) if context is not None else None
        pending = set(futures)
        results: dict[int, list | None] = {}
        try:
            with self._capacity:
                while pending:
                    for future in [future for future in pending if future.done()]:
                        pending.discard(future)
                        results[futures[future]] = future.result()
                    if not pending:
                        break
                    if revoked.is_set():
                        raise VisibilityUnavailable("Forgejo session was revoked during pagination")
                    pause = self._follower_wait
                    if context is not None:
                        context.check()
                        remaining = context.remaining()
                        if remaining is not None:
                            pause = min(pause, remaining)
                    self._capacity.wait(pause)
            return results
        except BaseException as error:
            running = [future for future in pending if not future.cancel()]
            if isinstance(error, VisibilityUnavailable) and running:
                # A page already on the wire may carry a login redirect: let it land (it
                # revokes where it is seen) instead of reporting an unrelated failure first.
                # Bounded by the socket timeout; skipped for cancellation and deadlines.
                self._drain(running)
            raise
        finally:
            if unregister is not None:
                unregister()

    def _drain(self, running: list[Future]) -> None:
        """Wait for pages already on the wire, woken by their completion (a done-callback
        already notifies `_capacity`) and by the caller's cancellation; never past the socket
        timeout or the request deadline."""
        context = scope.current()
        end = time.monotonic() + self.request_timeout
        with self._capacity:
            while any(not future.done() for future in running):
                if context is not None and (context.cancelled or context.remaining() == 0.0):
                    return
                pause = end - time.monotonic()
                if pause <= 0:
                    return
                left = None if context is None else context.remaining()
                self._capacity.wait(pause if left is None else min(pause, left))

    def _identity_check(self, cookie: str, *, after: int | None) -> bool:
        """Is this session signed in, according to a request issued after `after`?

        `after` is a sequence number taken when a denial was received. A check already in
        flight, or finished, may be shared only if it was issued strictly later: an older
        answer cannot show that the denial was not caused by a logout in between. With
        `after=None` (plain readiness) any in-flight check is shared and no finished
        answer is reused; the TTL cache governs that case.
        """
        key = sha256(cookie.encode()).hexdigest()
        for _ in range(5):
            with self._guard:
                done = self._identity_done.get(key)
                if after is not None and done is not None and done[0] > after:
                    return done[1]
                flight = self._identity_flights.get(key)
                leader = flight is None
                shares = flight is not None and (after is None or flight.seq > after)
                if leader:
                    flight = _Flight(next(self._seq))
                    self._identity_flights[key] = flight
            if leader:
                return self._lead_identity(cookie, key, flight)
            # One identity request per session at a time: a flight issued before this denial
            # cannot confirm it, but a second concurrent request would only repeat the first.
            # Wait it out; every denial that piled up meanwhile then shares the next flight.
            if not self._wait_event(flight.event, self._follower_wait):
                raise VisibilityUnavailable("Forgejo identity check timed out")
            if shares:
                if flight.error is not None:
                    raise flight.error
                if not flight.abandoned:
                    return flight.result
        raise VisibilityUnavailable("Forgejo identity check was repeatedly abandoned")

    def _lead_identity(self, cookie: str, key: str, flight: _Flight) -> bool:
        try:
            authenticated = self._fetch_identity(cookie)
            with self._guard:
                self._identity_done[key] = (flight.seq, authenticated)
                self._identity_done.move_to_end(key)
                while len(self._identity_done) > self.max_entries:
                    self._identity_done.popitem(last=False)
            flight.result = authenticated
            return authenticated
        except VisibilityUnavailable as error:
            flight.error = error
            raise
        except BaseException:
            # A cancelled leader answers nobody; a follower with budget left takes over.
            flight.abandoned = True
            raise
        finally:
            with self._guard:
                if self._identity_flights.get(key) is flight:
                    self._identity_flights.pop(key)
                flight.event.set()
                self._capacity.notify_all()

    def _remember_identity(self, key: str, ttl: float) -> None:
        with self._guard:
            existing = self.cache.get(key)
            now = time.monotonic()
            if existing is not None and existing[0] > now and existing[1]:
                return
            self.cache[key] = (now + ttl, True, None)
            self.cache.move_to_end(key)
            while len(self.cache) > self.max_entries:
                self.cache.popitem(last=False)

    def session_authenticated(self, cookie: str) -> bool:
        """Is the session signed in? One cheap request; never enumerates repositories.

        Ambiguous upstream answers raise `VisibilityUnavailable` and are never read as
        anonymous, exactly like the full listing.
        """
        if not cookie:
            return False
        key = sha256(cookie.encode()).hexdigest()
        scope.checkpoint()
        self._backoff(key)
        cached = self._cached(key, need_repos=False)
        if cached is not _MISS:
            return cached[0]
        with self._guard:
            if self._closed:
                raise VisibilityUnavailable("Forgejo authorization is closed")
        revoked = self._start_check(key)
        try:
            checked_at = time.monotonic()
            authenticated = self._identity_check(cookie, after=None)
            if not authenticated:
                self._remember(key, False, set(), self.negative_ttl)
                return False
            with self._guard:
                if revoked.is_set():
                    raise VisibilityUnavailable("Forgejo session was revoked during the identity check")
                remaining = checked_at + self.ttl - time.monotonic()
                if remaining <= 0:
                    raise VisibilityUnavailable("Forgejo identity grant expired during the check")
                self._remember_identity(key, remaining)
            return True
        except VisibilityUnavailable as error:
            self._remember_unavailable(key, error)
            raise
        finally:
            self._finish_check(key, revoked)

    def visible_repositories(self, cookie: str, repo: str | None = None) -> tuple[bool, set[str]]:
        """The repositories this session can see.

        `repo` is an optional narrowing hint (an exact `owner/name` qualifier of the
        query): the result then contains every visible repository whose full name equals
        it case-insensitively, and possibly more. Forgejo's native `q` keyword is a
        `lower_name LIKE %name%` match under the same access condition, so it can only
        add candidates, never hide the named one; the caller still applies its own exact
        filter. Other qualifiers (`owner:`, `path:`) have no safe native equivalent.
        """
        if not cookie:
            return False, set()

        session = sha256(cookie.encode()).hexdigest()
        keyword = _scope_keyword(repo)
        key = session if keyword is None else f"{session}:repo:{keyword}"
        suffix = "" if keyword is None else "&q=" + quote(keyword, safe="")
        scope.checkpoint()
        with self._guard:
            if self._closed:
                raise VisibilityUnavailable("Forgejo authorization is closed")
        for _ in range(3):
            self._backoff(session)
            if keyword is not None:
                self._backoff(key)
                # A fresh complete allow-list (or a recorded logout) answers without upstream work.
                full = self._cached(session)
                if full is not _MISS:
                    return full
            cached = self._cached(key)
            if cached is not _MISS:
                return cached

            event, leader = self._claim(key)
            if leader:
                break
            # A follower waits in its own thread (never on a shared worker). If the leader
            # was cancelled rather than failed, nothing is cached and the next pass leads.
            if not self._wait_event(event, self._follower_wait):
                raise VisibilityUnavailable("Forgejo visibility check timed out")
        else:
            raise VisibilityUnavailable("Forgejo visibility check was abandoned")

        revoked = self._start_check(session)
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
            batch = self._fetch_page(cookie, 1, suffix)
            if batch is None:
                self._remember(session, False, set(), self.negative_ttl)
                return False, set()

            repositories: set[str] = self._full_names(batch)
            # Keep paginating while a page came back non-empty, stopping the
            # instant one is empty. This proves "no more results" regardless of
            # what page size Forgejo's web route actually enforces -- it does
            # not assume `limit` is honored exactly, unlike checking
            # `len(batch) == _PAGE_SIZE`.
            if batch:
                prefetched = self._prefetch_pages(cookie, revoked, suffix, batch)
                for page, rows in prefetched.items():
                    if rows is None:
                        # A logout seen on ANY fetched page counts, even one past the empty
                        # page that ends the list: nothing may be published after it.
                        self._remember(session, False, set(), self.negative_ttl)
                        raise VisibilityUnavailable(
                            f"Forgejo session was no longer valid on page {page}"
                        )
                for page in range(2, _MAX_PAGES + 1):
                    if page in prefetched:
                        batch = prefetched.pop(page)
                    else:
                        batch = self._fetch_page(cookie, page, suffix)
                    if batch is None:
                        self._remember(session, False, set(), self.negative_ttl)
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
            self._finish_check(session, revoked)
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
    ) -> tuple[float, bool] | _Denial:
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
                raise self._failure("Forgejo code visibility check failed") from error
            # Taken the instant the status is known: only an identity request issued
            # after this point can show that a 404 was not caused by a logout.
            received = next(self._seq)
            if status in _LOGIN_REQUIRED_STATUSES:
                self._session_revoked(cookie)
            if status in _CODE_DENIED_STATUSES:
                # RepoAssignment also hides private repos from expired sessions, so a bare
                # 404 is not yet a denial. Hand it back unconfirmed: the call that wanted it
                # confirms every denial it collected with ONE identity request issued after
                # the newest of them, and only then caches them.
                denial = _Denial(key, checked_at, received)
                self._hold_denial(denial)
                return denial
            if 200 <= status < 300:
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

    def _hold_denial(self, denial: _Denial) -> None:
        """Keep an unconfirmed 404 shareable, so an overlapping search of the same session
        (the next keystroke) does not repeat the probe while the first call still runs."""
        with self._guard:
            self._provisional[denial.key] = denial
            self._provisional.move_to_end(denial.key)
            while len(self._provisional) > self.code_cache_max_entries:
                self._provisional.popitem(last=False)

    def _held_denial(self, key: str) -> _Denial | None:
        with self._guard:
            denial = self._provisional.get(key)
            if denial is None:
                return None
            if denial.checked_at + self.negative_ttl <= time.monotonic():
                self._provisional.pop(key, None)
                return None
            return denial

    def _confirm_denials(
        self,
        cookie: str,
        denials: dict[str, _Denial],
        revoked: threading.Event,
        budget_until: float,
    ) -> None:
        """Cache bare 404s as denials only after the session is shown to be still signed in.

        One identity request, issued after the newest 404 any of them was received, covers
        all of them: a logout that explained one of the 404s would have preceded it. The
        confirmation spends what is left of the code-probe budget, like the probes did.
        """
        left = budget_until - time.monotonic()
        parent = scope.current()
        budget_left = max(left, 0.0)
        if parent is not None and parent.remaining() is not None:
            budget_left = min(budget_left, parent.remaining())
        budget = scope.RequestContext(budget_left)
        unregister = (
            parent.on_cancel(lambda: budget.cancel(parent.reason)) if parent is not None else None
        )
        try:
            with scope.bound(budget):
                confirmed = self._identity_check(
                    cookie, after=max(denial.received for denial in denials.values())
                )
        except scope.DeadlineExceeded:
            if parent is not None and (parent.cancelled or parent.remaining() == 0.0):
                raise
            raise VisibilityUnavailable(
                f"Forgejo code visibility check exceeded the {self.code_probe_budget}s "
                "probe budget while confirming denials"
            ) from None
        finally:
            if unregister is not None:
                unregister()
        if not confirmed:
            self._session_revoked(cookie)
        for denial in denials.values():
            self._remember_code(denial.key, False, denial.checked_at, revoked)
            with self._guard:
                if self._provisional.get(denial.key) is denial:
                    self._provisional.pop(denial.key)

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
        scope.checkpoint()
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
        denials: dict[str, _Denial] = {}
        pending: list[str] = []
        for repo in repos:
            key = self._code_key(cookie, repo)
            cached = self._code_cached(key)
            if cached is _MISS:
                held = self._held_denial(key)
                if held is None:
                    pending.append(repo)
                else:
                    denials[repo] = held
            elif cached[1]:
                readable[repo] = cached[0]
        if not pending:
            # Fast path for the common steady state (an actively-typing
            # session between TTL windows): every candidate is already
            # resolved in cache, so skip spinning up a ThreadPoolExecutor and
            # its worker threads entirely.
            if denials:
                self._confirm_denials(
                    cookie, denials, revoked, time.monotonic() + self.code_probe_budget
                )
                self._check_session_state(cookie)
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

        context = scope.current()
        unregister = context.on_cancel(self._wake) if context is not None else None
        try:
            with self._capacity:
                while pending or futures:
                    if context is not None:
                        context.check()
                    if revoked.is_set():
                        raise VisibilityUnavailable("Forgejo session was revoked during authorization")
                    budget_left = deadline - time.monotonic()
                    if budget_left <= 0:
                        raise timeout_error()
                    # Consume failures before admitting more upstream work.
                    for future in list(futures):
                        if future.done():
                            repo, probe_revoked = futures.pop(future)
                            result = future.result()
                            if probe_revoked.is_set():
                                raise VisibilityUnavailable("Forgejo session was revoked before probe publication")
                            if isinstance(result, _Denial):
                                denials[repo] = result
                            elif result[1]:
                                readable[repo] = result[0]
                    while pending:
                        self._backoff("code:" + sha256(cookie.encode()).hexdigest())
                        repo = pending[-1]
                        key = self._code_key(cookie, repo)
                        cached = self._code_cached(key)
                        if cached is _MISS:
                            held = self._held_denial(key)
                            if held is not None:
                                pending.pop()
                                denials[repo] = held
                                continue
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
                        # Cancellation wakes this wait; the probe budget and the request
                        # deadline bound it. A shared probe in flight is never cancelled.
                        pause = budget_left
                        left = None if context is None else context.remaining()
                        if left is not None:
                            pause = min(pause, left)
                        self._capacity.wait(timeout=pause)
        except VisibilityUnavailable as error:
            self._remember_unavailable("code:" + sha256(cookie.encode()).hexdigest(), error)
            raise
        finally:
            if unregister is not None:
                unregister()
        if denials:
            self._confirm_denials(cookie, denials, revoked, deadline)
        self._check_session_state(cookie)
        return readable

