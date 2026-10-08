"""HTTP front end: the legacy JSON endpoint plus the opt-in NDJSON stream (wire v1).

`GET /api/hypersearch` keeps its JSON contract. A request that carries an explicit
`Accept: application/x-ndjson` (weight above zero) instead receives, on one connection
and from one writer, `started`, neutral `heartbeat`s, exactly one `result` holding the
unchanged full response, then `done` -- or one sanitized terminal `error`. The stream
opens before any upstream call, so a cold Forgejo identity/listing cannot starve the
proxy of bytes. Authorized data is only ever sent in the final `result`.

Resource model (all configurable through `ServerSettings`):

* Admission: at most `search_workers + search_queue` searches are outstanding; more get
  an immediate JSON 503 `server_busy`. A slot is released when the *work* ends, so a
  request answered at its deadline keeps its slot while the blocked call winds down.
* Connections: at most `max_connections` handler threads; idle or slow clients are cut
  after `client_timeout`.
* Deadline: one monotonic `request_deadline` (queue wait included) covers every phase.
* Output: records follow the shared v1 caps (2 MiB each, 8 MiB total, 256 records); an
  oversized result becomes a sanitized terminal error, never a truncated record.
"""

from __future__ import annotations

import errno
import json
import logging
import math
import socket
import threading
import time
import traceback
from concurrent.futures import CancelledError, ThreadPoolExecutor
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import __version__
from . import deadline as scope
from .auth import VisibilityUnavailable
from .db import indexed_repo_names
from .deadline import (
    DEADLINE_REASON,
    DeadlineExceeded,
    RequestCancelled,
    RequestContext,
)
from .query import parse_query
from .search import empty_coverage, scoped_repos, search

NDJSON = "application/x-ndjson"
MAX_RECORD_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_RECORDS = 256
# `started`, `result`, `done` and one terminal `error` always fit next to the heartbeats.
RESERVED_RECORDS = 4
MAX_QUERY_CHARS = 2048
WRITE_TIMEOUT = 5.0
# A successful write may be followed by an asynchronous TCP reset. Observe the
# confirmed error without waiting another heartbeat; EOF alone is not an error.
# Bound idle wakeups while retaining margin after the default two-second heartbeat.
DISCONNECT_CHECK_INTERVAL = 0.25
# SO_ERROR can also contain recoverable ICMP errors on an established TCP socket.
# Only a terminated connection or an invalid socket proves work has no reader.
_DISCONNECT_ERRORS = frozenset(
    {
        errno.EBADF,
        errno.ENOTSOCK,
        errno.ENOTCONN,
        errno.ECONNABORTED,
        errno.ECONNRESET,
        errno.ENETRESET,
        errno.EPIPE,
        errno.ESHUTDOWN,
        errno.ETIMEDOUT,
    }
)
# Output may outlive the request deadline by this much, never by the full write budget.
OUTPUT_GRACE = 0.5
# Total (not per-read) time spent draining a rejected request before the connection closes.
LINGER_SECONDS = 0.5
_LINGER_BYTES = 262144
logger = logging.getLogger(__name__)


def _finite(value, low, high, name, *, open_low=False) -> float:
    number = float(value)
    below = number <= low if open_low else number < low
    if not math.isfinite(number) or below or number > high:
        bound = f">{low}" if open_low else f"{low}"
        raise ValueError(f"{name} must be finite, {bound} through {high}")
    return number


def _whole(value, low, high, name) -> int:
    count = int(str(value))
    if not low <= count <= high:
        raise ValueError(f"{name} must be an integer from {low} to {high}")
    return count


def deadline_seconds(value) -> float:
    return _finite(value, 0, 300, "request deadline seconds", open_low=True)


def heartbeat_seconds(value) -> float:
    return _finite(value, 0.05, 30, "heartbeat interval seconds")


def worker_count(value) -> int:
    return _whole(value, 1, 64, "search workers")


def queue_depth(value) -> int:
    return _whole(value, 0, 256, "search queue")


def connection_limit(value) -> int:
    return _whole(value, 1, 1024, "max connections")


@dataclass(frozen=True)
class ServerSettings:
    request_deadline: float = 20.0
    heartbeat_interval: float = 2.0
    search_workers: int = 8
    search_queue: int = 24
    max_connections: int = 64
    client_timeout: float = 10.0
    shutdown_grace: float = 5.0

    def __post_init__(self):
        deadline_seconds(self.request_deadline)
        heartbeat_seconds(self.heartbeat_interval)
        worker_count(self.search_workers)
        queue_depth(self.search_queue)
        connection_limit(self.max_connections)
        _finite(self.client_timeout, 0, 120, "client timeout seconds", open_low=True)
        _finite(self.shutdown_grace, 0, 60, "shutdown grace seconds", open_low=True)
        if math.ceil(self.request_deadline / self.heartbeat_interval) + RESERVED_RECORDS > MAX_RECORDS:
            raise ValueError(
                "request deadline divided by heartbeat interval would exceed the "
                f"{MAX_RECORDS}-record stream cap"
            )


class StreamBroken(Exception):
    """The client stopped reading or went away; the request is already cancelled."""


class RecordTooLarge(Exception):
    """A record would exceed a shared stream cap; nothing was sent for it."""


def encode_record(record: dict) -> bytes:
    text = json.dumps(record, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    # JSON allows raw U+2028/U+2029 but several line splitters treat them as breaks.
    text = text.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    return text.encode("utf-8") + b"\n"


class NdjsonStream:
    """The single writer of one response body."""

    def __init__(
        self,
        send,
        context: RequestContext,
        *,
        max_record_bytes: int = MAX_RECORD_BYTES,
        max_total_bytes: int = MAX_TOTAL_BYTES,
        max_records: int = MAX_RECORDS,
    ):
        self._send = send
        self._context = context
        self._max_record = max_record_bytes
        self._max_total = max_total_bytes
        self._max_records = max_records
        self._bytes = 0
        self._records = 0
        self.broken = False

    def write(self, record: dict, *, terminal: bool = False) -> None:
        """Send one record. A terminal record (error/done) is tiny and ignores the caps."""
        if self.broken:
            raise StreamBroken
        payload = encode_record(record)
        if not terminal and (
            len(payload) > self._max_record
            or self._bytes + len(payload) > self._max_total
            or self._records + 1 > self._max_records
        ):
            raise RecordTooLarge
        try:
            self._send(payload)
        except OSError as error:  # includes socket timeouts and broken pipes
            self.broken = True
            self._context.cancel("client_disconnected")
            raise StreamBroken from error
        self._bytes += len(payload)
        self._records += 1


def wants_ndjson(values) -> bool:
    """True only for an explicit `application/x-ndjson` range with 0 < q <= 1."""
    for header in values or ():
        for part in header.split(","):
            media, _, params = part.partition(";")
            if media.strip().lower() != NDJSON:
                continue
            weight = 1.0
            for param in params.split(";"):
                name, _, value = param.partition("=")
                if name.strip().lower() == "q":
                    try:
                        weight = float(value.strip())
                    except ValueError:
                        weight = 0.0
            if 0.0 < weight <= 1.0:
                return True
    return False


@dataclass(frozen=True)
class Failure:
    status: int
    code: str
    body: dict


_UNAUTHENTICATED = Failure(401, "authentication_required", {"error": "authentication_required"})
_DEADLINE = Failure(504, "deadline_exceeded", {"error": "deadline_exceeded"})
_UNAVAILABLE = Failure(503, "search_unavailable", {"error": "search_unavailable"})


def _upstream(code: str, error: VisibilityUnavailable) -> Failure:
    return Failure(503, code, {"error": code, "message": str(error)})


class SearchServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, database, auth, ast_grep="ast-grep", settings=None):
        self.settings = settings or ServerSettings()
        super().__init__(address, SearchHandler)
        self.database = database
        self.auth = auth
        self.ast_grep = ast_grep
        self.started = time.time()
        self._state = threading.Condition()
        self._outstanding = 0
        self._connections = 0
        self._closing = False
        self._contexts: set[RequestContext] = set()
        self._pool = ThreadPoolExecutor(
            max_workers=self.settings.search_workers, thread_name_prefix="hypersearch-search"
        )

    # -- connections -------------------------------------------------------------
    def process_request(self, request, client_address):
        with self._state:
            if self._closing or self._connections >= self.settings.max_connections:
                admitted = False
            else:
                self._connections += 1
                admitted = True
        if not admitted:
            self._reject(request)
            return
        try:
            threading.Thread(
                target=self._serve_connection,
                args=(request, client_address),
                name="hypersearch-connection",
                daemon=True,
            ).start()
        except RuntimeError:
            self._connection_done()
            self._reject(request)

    def _serve_connection(self, request, client_address):
        try:
            self.process_request_thread(request, client_address)
        finally:
            self._connection_done()

    def _connection_done(self):
        with self._state:
            self._connections -= 1
            self._state.notify_all()

    def _reject(self, request):
        body = b'{"error":"server_busy"}'
        head = (
            b"HTTP/1.0 503 Service Unavailable\r\n"
            b"Content-Type: application/json; charset=utf-8\r\n"
            b"Cache-Control: no-store\r\nRetry-After: 1\r\nConnection: close\r\n"
            + b"Content-Length: %d\r\n\r\n" % len(body)
        )
        try:
            request.settimeout(0.5)
            request.sendall(head + body)
        except OSError:
            pass
        finally:
            self.shutdown_request(request)

    # -- admission and work ------------------------------------------------------
    def admit(self) -> RequestContext | None:
        """Reserve a search slot and start the request's deadline, or None when full."""
        with self._state:
            capacity = self.settings.search_workers + self.settings.search_queue
            if self._closing or self._outstanding >= capacity:
                return None
            self._outstanding += 1
            context = RequestContext(self.settings.request_deadline)
            self._contexts.add(context)
            return context

    def release(self, context: RequestContext) -> None:
        with self._state:
            self._outstanding -= 1
            self._contexts.discard(context)
            self._state.notify_all()

    def submit(self, context: RequestContext, cookie, query, limit, wall_started):
        """Queue the search; the slot is returned when the work itself finishes."""
        try:
            future = self._pool.submit(self._execute, context, cookie, query, limit, wall_started)
        except BaseException:
            self.release(context)
            raise
        future.add_done_callback(lambda _: self.release(context))
        return future

    def _execute(self, context, cookie, query, limit, wall_started):
        with scope.bound(context):
            try:
                context.check()
                return self._search(cookie, query, limit, wall_started)
            except DeadlineExceeded:
                return _DEADLINE
            except RequestCancelled:
                return _UNAVAILABLE
            except Exception as error:  # noqa: BLE001 - last resort: answer, never crash a worker
                # Never forward raw exceptions to the client: they can carry private
                # metadata. Record the type and place only, never the message.
                frame = traceback.extract_tb(error.__traceback__)[-1]
                logger.error(
                    "unexpected search failure: %s at %s:%d",
                    type(error).__name__,
                    frame.filename,
                    frame.lineno,
                )
                return _UNAVAILABLE

    def _search(self, cookie, query, limit, wall_started):
        auth = self.auth
        if not query:
            # The empty query is only an "am I signed in?" check: identity without
            # enumerating repositories, and no code probes.
            try:
                if not auth.session_authenticated(cookie):
                    return _UNAUTHENTICATED
            except VisibilityUnavailable as error:
                return _upstream("visibility_unavailable", error)
            return {
                "query": "",
                "mode": "auto",
                "results": [],
                "coverage": empty_coverage(limit),
                "total_ms": round((time.perf_counter() - wall_started) * 1000, 2),
            }
        # Grants are validated when the allow-lists are returned. A logout that any request
        # of this session observes after that, while this result is still being built, must
        # stop the publication too; it is already known, so no upstream request is spent.
        with auth.session_watch(cookie) as revoked:
            outcome = self._authorized_search(cookie, query, limit, wall_started)
            if revoked.is_set() and not isinstance(outcome, Failure):
                return _upstream(
                    "visibility_unavailable",
                    VisibilityUnavailable("Forgejo session was revoked during the search"),
                )
            return outcome

    def _authorized_search(self, cookie, query, limit, wall_started):
        auth = self.auth
        try:
            q = parse_query(query)
            if q.repo:
                authenticated, allowed = auth.visible_repositories(cookie, repo=q.repo)
            else:
                authenticated, allowed = auth.visible_repositories(cookie)
        except VisibilityUnavailable as error:
            return _upstream("visibility_unavailable", error)
        if not authenticated:
            return _UNAUTHENTICATED
        # Repository visibility (granted by any unit -- issues, wiki, projects, releases...)
        # is not code visibility in Forgejo: only indexed repositories need the stronger,
        # native reqRepoCodeReader probe. An explicit repo:/owner: qualifier narrows which
        # repos are even candidates; an unscoped query needs every indexed+visible repo.
        scoped = scoped_repos(q, allowed)
        if scoped:
            with self.database.connection() as connection:
                indexed = indexed_repo_names(connection, scoped)
        else:
            indexed = set()
        try:
            code_allowed = auth.code_readable_repositories(cookie, indexed)
        except VisibilityUnavailable as error:
            return _upstream("code_visibility_unavailable", error)
        started = time.perf_counter()
        result = search(
            self.database,
            query,
            allowed,
            limit,
            self.ast_grep,
            code_allowed=code_allowed,
            narrowed=bool(q.repo),
        )
        result["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 2)
        result["total_ms"] = round((time.perf_counter() - wall_started) * 1000, 2)
        return result

    # -- shutdown ----------------------------------------------------------------
    def server_close(self):
        """Stop accepting, cancel open requests, then wait a bounded grace period.

        Blocked upstream sockets cannot be preempted, so the wait is bounded by
        `shutdown_grace`; work still running after that is abandoned, not killed.
        """
        with self._state:
            already = self._closing
            self._closing = True
            contexts = list(self._contexts)
        if not already:
            super().server_close()
        for context in contexts:
            context.cancel("shutdown")
        grace = time.monotonic() + self.settings.shutdown_grace
        with self._state:
            while self._connections or self._outstanding:
                left = grace - time.monotonic()
                if left <= 0:
                    break
                self._state.wait(left)
        self._pool.shutdown(wait=False, cancel_futures=True)


class SearchHandler(BaseHTTPRequestHandler):
    server_version = f"HyperSearch/{__version__}"

    def setup(self):
        self.timeout = self.server.settings.client_timeout
        super().setup()
        try:
            self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

    def log_message(self, format, *args):
        pass

    def _json(self, status, payload, headers=()):
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def send_error(self, code, message=None, explain=None):
        """Protocol-level errors (malformed or oversized requests) are JSON too."""
        names = {
            400: "bad_request",
            414: "uri_too_long",
            431: "headers_too_large",
            501: "unsupported_method",
        }
        try:
            self._json(code, {"error": names.get(code, "bad_request" if code < 500 else "server_error")})
        except OSError:
            pass
        self.close_connection = True
        self._linger()

    def _linger(self):
        """Read what a rejected client is still sending so the answer is not lost to a reset.

        The whole drain has one absolute budget: a client trickling bytes cannot keep the
        connection slot, however slowly it sends.
        """
        try:
            self.connection.shutdown(socket.SHUT_WR)
            end = time.monotonic() + LINGER_SECONDS
            left = _LINGER_BYTES
            while left > 0:
                pause = end - time.monotonic()
                if pause <= 0:
                    break
                self.connection.settimeout(pause)
                chunk = self.connection.recv(min(65536, left))
                if not chunk:
                    break
                left -= len(chunk)
        except OSError:
            pass

    def do_GET(self):
        # Wall-clock timer for total_ms spans the entire authenticated request path,
        # from admission through listing, code-ACL narrowing and search().
        wall_started = time.perf_counter()
        url = urlparse(self.path)
        if url.path == "/health":
            with self.server.database.connection() as c:
                repos = c.execute("SELECT count(*) FROM repos").fetchone()[0]
                docs = c.execute("SELECT count(*) FROM documents").fetchone()[0]
            return self._json(
                200,
                {
                    "service": "hypersearch",
                    "repos": repos,
                    "documents": docs,
                    "uptime": int(time.time() - self.server.started),
                },
            )
        if url.path != "/api/hypersearch":
            return self._json(404, {"error": "not_found"})
        cookie = self.headers.get("Cookie", "")
        if not cookie:
            return self._json(401, {"error": "authentication_required"})
        params = parse_qs(url.query)
        query = (params.get("q") or [""])[0].strip()
        if len(query) > MAX_QUERY_CHARS:
            return self._json(400, {"error": "query_too_long"})
        try:
            limit = int((params.get("limit") or ["30"])[0])
        except ValueError:
            limit = 30

        context = self.server.admit()
        if context is None:
            return self._json(503, {"error": "server_busy"}, headers=[("Retry-After", "1")])
        self._context = context
        stream = None
        try:
            if wants_ndjson(self.headers.get_all("Accept")):
                stream = self._open_stream(context)
        except StreamBroken:
            self.server.release(context)
            return None
        try:
            future = self.server.submit(context, cookie, query, limit, wall_started)
        except RuntimeError:
            # The work pool is already shut down; submit() returned the slot.
            if stream is None:
                return self._json(503, {"error": "server_busy"}, headers=[("Retry-After", "1")])
            return self._respond(_UNAVAILABLE, stream)
        outcome = self._wait(future, context, stream)
        return self._respond(outcome, stream)

    # -- streaming ---------------------------------------------------------------
    def _open_stream(self, context):
        self.send_response(200)
        self.send_header("Content-Type", NDJSON + "; charset=utf-8")
        self.send_header("Cache-Control", "no-store, private, no-transform")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.close_connection = True
        stream = NdjsonStream(
            self._send,
            context,
            max_record_bytes=MAX_RECORD_BYTES,
            max_total_bytes=MAX_TOTAL_BYTES,
            max_records=MAX_RECORDS,
        )
        try:
            self.end_headers()
        except OSError as error:
            context.cancel("client_disconnected")
            raise StreamBroken from error
        stream.write({"v": 1, "type": "started"})
        return stream

    def _write_budget(self) -> float:
        """Seconds one output write may take: the write cap, bounded by the request deadline
        plus a short grace so a stalled reader cannot outlive the deadline by the full cap."""
        remaining = self._context.remaining()
        if remaining is None:
            return WRITE_TIMEOUT
        return min(WRITE_TIMEOUT, remaining + OUTPUT_GRACE)

    def _send(self, payload: bytes) -> None:
        # sendall's timeout caps the whole call, not each partial write.
        self.connection.settimeout(self._write_budget())
        self.connection.sendall(payload)

    def _client_disconnected(self) -> bool:
        try:
            error = self.connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            failed = error in _DISCONNECT_ERRORS
            if not failed:
                # Winsock can leave SO_ERROR at zero and surface a reset only on
                # recv/send. Peek without blocking or consuming request bytes.
                # Avoid select(): valid fd numbers can exceed its FD_SETSIZE.
                timeout = self.connection.gettimeout()
                try:
                    self.connection.setblocking(False)
                    self.connection.recv(1, socket.MSG_PEEK)
                    # b"" is a legal write-half-close, not proof the reader left.
                except BlockingIOError:
                    pass  # No bytes or confirmed transport error are available.
                finally:
                    self.connection.settimeout(timeout)
        except OSError as error:
            failed = error.errno in _DISCONNECT_ERRORS
        if failed:
            # SO_ERROR reads clear the pending error. Preserve confirmed disconnects
            # immediately; transient route errors do not cancel a live connection.
            self._context.cancel("client_disconnected")
        return failed

    def _wait(self, future, context, stream):
        """Block until the work ends, beating heartbeats while it runs.

        Returns the work's outcome, a deadline/shutdown `Failure`, or None when the client
        is gone. A vanished client is detected by a confirmed socket error or a failed
        heartbeat write: read-side EOF alone is a legal half-close, not a disconnect.
        The handler may
        return before the work does: the work keeps its slot until it observes the
        cancellation.
        """
        wake = threading.Event()
        future.add_done_callback(lambda _: wake.set())
        unregister = context.on_cancel(wake.set)
        interval = self.server.settings.heartbeat_interval
        next_beat = time.monotonic() + interval
        try:
            while not wake.is_set():
                # JSON has no heartbeat, but can still observe a confirmed socket reset.
                pause = DISCONNECT_CHECK_INTERVAL
                if stream is not None:
                    pause = min(pause, interval / 2, next_beat - time.monotonic())
                remaining = context.remaining()
                if remaining is not None:
                    pause = min(pause, remaining)
                if wake.wait(max(0.0, pause)):
                    break
                if context.remaining() == 0.0:
                    context.cancel(DEADLINE_REASON)
                    break
                if self._client_disconnected():
                    return None
                if stream is not None and time.monotonic() >= next_beat:
                    next_beat = time.monotonic() + interval
                    stream.write({"v": 1, "type": "heartbeat"})
        except StreamBroken:
            # The work keeps its admission slot until a worker pops it: a cancelled
            # concurrent.futures item stays in the executor's queue, so returning the slot
            # early would let dead items accumulate beyond the admission bound. A popped,
            # already-cancelled request returns at its first checkpoint.
            return None
        finally:
            unregister()
        # Completion and an asynchronous reset can wake together. Do not return a
        # publishable result after observing the reset, even if the future is done.
        if context.reason == "client_disconnected" or (
            not context.cancelled and self._client_disconnected()
        ):
            return None
        if future.cancelled():
            # Shutdown cancelled it before a worker started it.
            return _DEADLINE if context.reason == DEADLINE_REASON else _UNAVAILABLE
        if future.done():
            try:
                return future.result()
            except CancelledError:
                # Shutdown cancelled it between the check above and now.
                return _DEADLINE if context.reason == DEADLINE_REASON else _UNAVAILABLE
        if context.reason == DEADLINE_REASON:
            return _DEADLINE
        if context.reason == "client_disconnected":
            return None
        return _UNAVAILABLE

    def _respond(self, outcome, stream):
        if stream is None:
            if outcome is None:
                return None
            try:
                self.connection.settimeout(self._write_budget())
                if isinstance(outcome, Failure):
                    return self._json(outcome.status, outcome.body)
                return self._json(200, outcome)
            except OSError:
                return None
        try:
            if outcome is None:
                return None
            if isinstance(outcome, Failure):
                stream.write(_error_record(outcome), terminal=True)
                return None
            try:
                stream.write({"v": 1, "type": "result", "data": outcome})
            except (RecordTooLarge, ValueError, UnicodeError):
                stream.write(_error_record(_UNAVAILABLE), terminal=True)
                return None
            stream.write({"v": 1, "type": "done"}, terminal=True)
        except StreamBroken:
            return None
        return None


def _error_record(failure: Failure) -> dict:
    return {"v": 1, "type": "error", "code": failure.code, "status": failure.status}
