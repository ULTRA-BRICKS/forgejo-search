from __future__ import annotations

import http.client
import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict
from hashlib import sha256

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
    ):
        self.base = base.rstrip("/")
        self.public_host = public_host
        self.ttl = ttl
        self.negative_ttl = negative_ttl
        self.max_entries = max_entries
        self.request_timeout = request_timeout
        self.cache: OrderedDict[str, tuple[float, bool, tuple[str, ...]]] = OrderedDict()
        self._guard = threading.Lock()
        self._inflight: dict[str, threading.Event] = {}
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

    def _claim(self, key: str) -> tuple[threading.Event, bool]:
        with self._guard:
            event = self._inflight.get(key)
            if event is not None:
                return event, False
            event = threading.Event()
            self._inflight[key] = event
            return event, True

    def _release(self, key: str, event: threading.Event) -> None:
        with self._guard:
            if self._inflight.get(key) is event:
                self._inflight.pop(key, None)
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
