from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from collections import OrderedDict
from hashlib import sha256

DEFAULT_FORGEJO_URL = "http://127.0.0.1:3000"
DEFAULT_FORGEJO_PUBLIC_HOST = "git.hyperide.ai"
_MISS = object()


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
        self.cache: OrderedDict[str, tuple[float, str | None, tuple[str, ...]]] = (
            OrderedDict()
        )
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
        login: str | None,
        repos: set[str],
        ttl: float,
    ) -> None:
        with self._guard:
            self.cache[key] = (
                time.monotonic() + ttl,
                login,
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
    def _repo_batch(payload) -> list[dict]:
        if isinstance(payload, list):
            return [row for row in payload if isinstance(row, dict)]
        if isinstance(payload, dict) and isinstance(payload.get("data"), list):
            return [row for row in payload["data"] if isinstance(row, dict)]
        raise VisibilityUnavailable("Forgejo returned an unexpected repository payload")

    def visible_repositories(self, cookie: str) -> tuple[str | None, set[str]]:
        if not cookie:
            return None, set()

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

            try:
                user = self._get("/api/v1/user", cookie)
            except (
                urllib.error.HTTPError,
                urllib.error.URLError,
                TimeoutError,
                json.JSONDecodeError,
            ):
                self._remember(key, None, set(), self.negative_ttl)
                return None, set()
            if not isinstance(user, dict):
                self._remember(key, None, set(), self.negative_ttl)
                return None, set()

            repositories: set[str] = set()
            for page in range(1, 22):
                try:
                    payload = self._get(
                        f"/api/v1/user/repos?limit=50&page={page}",
                        cookie,
                    )
                    batch = self._repo_batch(payload)
                except (
                    urllib.error.HTTPError,
                    urllib.error.URLError,
                    TimeoutError,
                    json.JSONDecodeError,
                ) as error:
                    raise VisibilityUnavailable(
                        f"Forgejo repository visibility check failed on page {page}"
                    ) from error
                if page == 21:
                    if batch:
                        raise VisibilityUnavailable(
                            "Forgejo repository visibility exceeded the 1000-repository safety bound"
                        )
                    break
                repositories.update(
                    str(repo["full_name"])
                    for repo in batch
                    if isinstance(repo, dict) and repo.get("full_name")
                )
                if len(batch) < 50:
                    break

            login = str(user.get("login") or "")
            if not login:
                self._remember(key, None, set(), self.negative_ttl)
                return None, set()
            self._remember(key, login, repositories, self.ttl)
            return login, repositories
        finally:
            self._release(key, event)
