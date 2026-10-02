"""Opt-in NDJSON transport v1, bounded admission, deadline and cancellation."""

from __future__ import annotations

import json
import logging
import socket
import threading
import time
from contextlib import contextmanager

import pytest
from fake_forgejo import FakeForgejo
from support import Stream, build_index, raw_exchange

from hypersearch.auth import ForgejoAuth, VisibilityUnavailable
from hypersearch.server import SearchServer

PATH = "needle"


class ScriptedAuth:
    """Auth double whose phases can block, fail on demand and expose the bound context."""

    def __init__(self, visible=("acme/open",), *, block=False, failure=None, wait=5.0):
        self.visible = set(visible)
        self.block = block
        self.failure = failure
        self.wait = wait
        self.entered = threading.Event()
        self.release = threading.Event()
        self.contexts: list = []
        self.calls = 0
        self.guard = threading.Lock()

    def _phase(self):
        from hypersearch import deadline

        with self.guard:
            self.calls += 1
            self.contexts.append(deadline.current())
        self.entered.set()
        if self.block:
            self.release.wait(self.wait)
        if self.failure is not None:
            raise self.failure

    def session_authenticated(self, cookie):
        self._phase()
        return cookie == "session=alice"

    def visible_repositories(self, cookie, repo=None):
        self._phase()
        if cookie != "session=alice":
            return False, set()
        return True, set(self.visible)

    def code_readable_repositories(self, cookie, repos):
        return set(repos)


@contextmanager
def serving(database, auth, **settings):
    from hypersearch.server import ServerSettings

    # 10s / 0.05s of heartbeats stays inside the shared 256-record stream cap.
    settings.setdefault("request_deadline", 10.0)
    instance = SearchServer(
        ("127.0.0.1", 0), database, auth, "missing-ast-grep", ServerSettings(**settings)
    )
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    try:
        yield instance, f"http://127.0.0.1:{instance.server_port}"
    finally:
        if isinstance(auth, ScriptedAuth):
            auth.release.set()
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=3)


@pytest.fixture
def database(tmp_path):
    return build_index(tmp_path / "search.db", ["acme/open"], text="needle")


def types(records):
    return [record["type"] for record in records]


@pytest.mark.parametrize(
    "accept,streams",
    [
        ("application/x-ndjson", True),
        ("APPLICATION/X-NDJSON", True),
        ("text/html, application/x-ndjson;q=0.5", True),
        ("application/x-ndjson; q=1.0", True),
        ("application/x-ndjson;q=0", False),
        ("application/x-ndjson; q=0.0", False),
        ("application/x-ndjson;q=0.000", False),
        ("application/x-ndjson;q=abc", False),
        ("*/*", False),
        ("application/*", False),
        ("application/json", False),
        ("application/x-ndjson-extra", False),
        (None, False),
    ],
)
def test_only_an_explicit_positive_accept_opts_into_streaming(database, accept, streams):
    with serving(database, ScriptedAuth()) as (_, base):
        stream = Stream(base, PATH, accept=accept)
        try:
            content_type = stream.header("Content-Type")
            body = stream.body()
        finally:
            stream.close()
    assert stream.status == 200
    if streams:
        assert content_type == "application/x-ndjson; charset=utf-8"
        assert json.loads(body.splitlines()[0]) == {"v": 1, "type": "started"}
    else:
        assert content_type == "application/json; charset=utf-8"
        assert json.loads(body)["query"] == PATH


def test_stream_has_proxy_safe_headers_and_no_invented_framing(database):
    with serving(database, ScriptedAuth()) as (_, base):
        stream = Stream(base, PATH)
        try:
            stream.body()
            headers = {key.lower(): value for key, value in stream.response.getheaders()}
        finally:
            stream.close()
    assert headers["x-accel-buffering"] == "no"
    cache = {part.strip() for part in headers["cache-control"].split(",")}
    assert {"no-store", "no-transform", "private"} <= cache
    assert headers["x-content-type-options"] == "nosniff"
    assert "content-length" not in headers
    assert "transfer-encoding" not in headers
    assert "content-encoding" not in headers


def test_success_stream_is_started_heartbeats_one_result_then_done(database):
    auth = ScriptedAuth(block=True)
    with serving(database, auth, heartbeat_interval=0.05) as (_, base):
        stream = Stream(base, PATH)
        try:
            assert auth.entered.wait(2)
            assert stream.next() == {"v": 1, "type": "started"}
            assert stream.next() == {"v": 1, "type": "heartbeat"}
            assert stream.next() == {"v": 1, "type": "heartbeat"}
            assert not auth.release.is_set()
            auth.release.set()
            rest = stream.drain()
        finally:
            stream.close()
    assert set(types(rest[:-2])) <= {"heartbeat"}
    assert types(rest[-2:]) == ["result", "done"]
    result = rest[-2]
    assert set(result) == {"v", "type", "data"} and result["v"] == 1
    data = result["data"]
    assert data["query"] == PATH and data["coverage"]["version"] == 1
    assert [hit["repo"] for hit in data["results"]] == ["acme/open"]
    assert stream.raw.count(b"\n") == len(stream.seen)


def test_started_arrives_before_blocking_authorization_not_after(database):
    auth = ScriptedAuth(block=True, wait=1.0)
    with serving(database, auth, heartbeat_interval=0.2) as (_, base):
        stream = Stream(base, PATH)
        try:
            started = stream.next()
            elapsed = time.perf_counter() - stream.started
            assert started == {"v": 1, "type": "started"}
            assert elapsed < 0.6  # authorization stays blocked for about one second
            assert not auth.release.is_set()
        finally:
            stream.close()


def test_heartbeats_reveal_nothing(database):
    auth = ScriptedAuth(block=True, wait=0.5)
    with serving(database, auth, heartbeat_interval=0.05) as (_, base):
        stream = Stream(base, PATH)
        try:
            records = stream.drain()
        finally:
            stream.close()
    beats = [record for record in records if record["type"] == "heartbeat"]
    assert beats and all(record == {"v": 1, "type": "heartbeat"} for record in beats)


@pytest.mark.parametrize(
    "failure,code,status",
    [
        (VisibilityUnavailable("INTERNAL upstream detail"), "visibility_unavailable", 503),
        (RuntimeError("INTERNAL traceback detail"), "search_unavailable", 503),
    ],
)
def test_failures_are_terminal_sanitized_and_not_followed_by_done(database, failure, code, status):
    with serving(database, ScriptedAuth(failure=failure)) as (_, base):
        stream = Stream(base, PATH)
        try:
            records = stream.drain()
            raw = bytes(stream.raw)
        finally:
            stream.close()
    assert records == [
        {"v": 1, "type": "started"},
        {"v": 1, "type": "error", "code": code, "status": status},
    ]
    assert b"INTERNAL" not in raw


def test_code_acl_failure_has_its_own_category(database):
    class CodeFails(ScriptedAuth):
        def code_readable_repositories(self, cookie, repos):
            raise VisibilityUnavailable("INTERNAL probe detail")

    with serving(database, CodeFails()) as (_, base):
        stream = Stream(base, PATH)
        try:
            records = stream.drain()
        finally:
            stream.close()
    assert records[-1] == {"v": 1, "type": "error", "code": "code_visibility_unavailable", "status": 503}
    assert b"INTERNAL" not in bytes(stream.raw)


def test_anonymous_cookie_gets_terminal_authentication_error_without_any_data(database):
    with serving(database, ScriptedAuth()) as (_, base):
        stream = Stream(base, PATH, cookie="session=nobody")
        try:
            records = stream.drain()
        finally:
            stream.close()
    assert records == [
        {"v": 1, "type": "started"},
        {"v": 1, "type": "error", "code": "authentication_required", "status": 401},
    ]


def test_missing_cookie_is_an_immediate_json_401_before_any_stream(database):
    with serving(database, ScriptedAuth()) as (_, base):
        stream = Stream(base, PATH, cookie=None)
        try:
            body = stream.body()
            content_type = stream.header("Content-Type")
        finally:
            stream.close()
    assert stream.status == 401
    assert content_type == "application/json; charset=utf-8"
    assert json.loads(body) == {"error": "authentication_required"}


def test_json_clients_keep_existing_statuses_bodies_and_messages(database):
    cases = [
        (ScriptedAuth(failure=VisibilityUnavailable("upstream says no")), 503,
         {"error": "visibility_unavailable", "message": "upstream says no"}),
        (ScriptedAuth(), 401, {"error": "authentication_required"}),
    ]
    for auth, status, expected in cases:
        cookie = "session=alice" if status != 401 else "session=nobody"
        with serving(database, auth) as (_, base):
            stream = Stream(base, PATH, accept="application/json", cookie=cookie)
            try:
                body = json.loads(stream.body())
            finally:
                stream.close()
        assert stream.status == status
        assert body == expected


def test_overall_deadline_ends_the_stream_with_a_terminal_error_while_heartbeats_continue(database):
    auth = ScriptedAuth(block=True, wait=3.0)
    with serving(database, auth, request_deadline=0.4, heartbeat_interval=0.05) as (_, base):
        stream = Stream(base, PATH)
        try:
            records = stream.drain()
            elapsed = time.perf_counter() - stream.started
        finally:
            stream.close()
    assert records[0] == {"v": 1, "type": "started"}
    assert records[-1] == {"v": 1, "type": "error", "code": "deadline_exceeded", "status": 504}
    assert types(records[1:-1]) and set(types(records[1:-1])) == {"heartbeat"}
    assert 0.3 < elapsed < 1.5
    assert auth.contexts[0].cancelled or auth.contexts[0].remaining() <= 0


def test_json_mode_deadline_is_a_504(database):
    auth = ScriptedAuth(block=True, wait=3.0)
    with serving(database, auth, request_deadline=0.3, heartbeat_interval=0.05) as (_, base):
        stream = Stream(base, PATH, accept="application/json")
        try:
            body = json.loads(stream.body())
        finally:
            stream.close()
    assert stream.status == 504
    assert body == {"error": "deadline_exceeded"}


def test_client_disconnect_cancels_the_request_context(database):
    auth = ScriptedAuth(block=True, wait=3.0)
    with serving(database, auth, heartbeat_interval=0.05) as (_, base):
        stream = Stream(base, PATH)
        assert auth.entered.wait(2)
        assert stream.next() == {"v": 1, "type": "started"}
        stream.response.close()
        stream.close()
        context = auth.contexts[0]
        end = time.monotonic() + 2
        while not context.cancelled and time.monotonic() < end:
            time.sleep(0.02)
        assert context.cancelled and context.reason == "client_disconnected"


@pytest.mark.parametrize("accept", ["application/json", "application/x-ndjson"])
def test_a_half_closed_request_still_receives_its_response(database, accept):
    # Read-side EOF (a legal TCP half-close, e.g. `nc -N`) is not proof the reader is gone.
    auth = ScriptedAuth(block=True, wait=0.4)
    with serving(database, auth, heartbeat_interval=0.05) as (instance, _):
        sock = socket.create_connection(("127.0.0.1", instance.server_port), timeout=5)
        sock.sendall(
            b"GET /api/hypersearch?q=needle HTTP/1.0\r\nCookie: session=alice\r\n"
            + f"Accept: {accept}\r\n\r\n".encode()
        )
        sock.shutdown(socket.SHUT_WR)
        answer = bytearray()
        while chunk := sock.recv(65536):
            answer.extend(chunk)
        sock.close()
        assert not auth.contexts[0].cancelled
    head, _, body = bytes(answer).partition(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.0 200 ")
    if accept == "application/json":
        assert json.loads(body)["query"] == PATH
    else:
        records = [json.loads(line) for line in body.splitlines()]
        assert types(records)[0] == "started" and types(records)[-2:] == ["result", "done"]


@pytest.mark.parametrize("accept", ["application/x-ndjson", "application/json"])
def test_a_stalled_reader_cannot_hold_the_handler_past_deadline_plus_output_grace(
    database, monkeypatch, accept
):
    # A 24 MiB answer cannot fit any socket buffer, so the write blocks on every platform.
    monkeypatch.setattr(SearchServer, "_search", lambda self, *args: {"pad": "x" * (24 << 20)})
    monkeypatch.setattr("hypersearch.server.MAX_RECORD_BYTES", 64 << 20)
    monkeypatch.setattr("hypersearch.server.MAX_TOTAL_BYTES", 64 << 20)
    with serving(database, ScriptedAuth(), request_deadline=0.4, heartbeat_interval=0.05) as (
        instance,
        _,
    ):
        reader = socket.socket()
        reader.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        reader.connect(("127.0.0.1", instance.server_port))
        began = time.monotonic()
        reader.sendall(
            b"GET /api/hypersearch?q=needle HTTP/1.0\r\nCookie: session=alice\r\n"
            + f"Accept: {accept}\r\n\r\n".encode()
        )
        try:
            time.sleep(0.2)
            end = began + 8
            while instance._connections and time.monotonic() < end:
                time.sleep(0.02)
            # The write budget alone is five seconds; the 0.4 s request deadline plus the short
            # output grace must win.
            assert instance._connections == 0
            assert time.monotonic() - began < 2.5
        finally:
            reader.close()


def test_a_trickling_client_cannot_keep_a_rejected_connection_open(database):
    with serving(database, ScriptedAuth(), max_connections=1) as (instance, _):
        sock = socket.create_connection(("127.0.0.1", instance.server_port))
        stop = threading.Event()

        def trickle():
            try:
                sock.sendall(b"POST /x HTTP/1.0\r\nContent-Length: 0\r\n\r\n")
                while not stop.is_set():
                    sock.sendall(b"x")
                    time.sleep(0.1)
            except OSError:
                pass

        thread = threading.Thread(target=trickle, daemon=True)
        thread.start()
        try:
            end = time.monotonic() + 3
            time.sleep(0.3)
            while instance._connections and time.monotonic() < end:
                time.sleep(0.02)
            assert instance._connections == 0
        finally:
            stop.set()
            sock.close()
            thread.join(2)


def test_unexpected_failures_are_logged_by_type_and_place_never_by_message(database, caplog):
    failure = RuntimeError("cookie=SECRET-VALUE repo=acme/private")
    with caplog.at_level(logging.ERROR, logger="hypersearch.server"):
        with serving(database, ScriptedAuth(failure=failure)) as (_, base):
            stream = Stream(base, PATH, accept="application/json")
            try:
                body = json.loads(stream.body())
            finally:
                stream.close()
    assert stream.status == 503 and body == {"error": "search_unavailable"}
    assert "RuntimeError" in caplog.text
    assert "SECRET-VALUE" not in caplog.text and "acme/private" not in caplog.text


def test_saturation_is_an_immediate_json_server_busy_not_a_queue(database):
    auth = ScriptedAuth(block=True, wait=3.0)
    with serving(database, auth, search_workers=1, search_queue=0) as (instance, base):
        holder = socket.create_connection(("127.0.0.1", instance.server_port))
        holder.sendall(b"GET /api/hypersearch?q=needle HTTP/1.0\r\nCookie: session=alice\r\n\r\n")
        assert auth.entered.wait(2)
        for accept in ("application/x-ndjson", "application/json"):
            started = time.perf_counter()
            second = Stream(base, PATH, accept=accept)
            try:
                body = second.body()
            finally:
                second.close()
            assert second.status == 503
            assert second.header("Content-Type") == "application/json; charset=utf-8"
            assert second.header("Retry-After") == "1"
            assert json.loads(body) == {"error": "server_busy"}
            assert time.perf_counter() - started < 0.5
        auth.release.set()
        answer = bytearray()
        while chunk := holder.recv(65536):
            answer.extend(chunk)
        holder.close()
        assert answer.startswith(b"HTTP/1.0 200 ")
        third = Stream(base, PATH, accept="application/json")
        try:
            assert third.status == 200
        finally:
            third.close()


def test_a_request_that_ended_at_its_deadline_keeps_its_worker_slot_until_the_work_ends(database):
    auth = ScriptedAuth(block=True, wait=1.5)
    with serving(
        database, auth, search_workers=1, search_queue=0, request_deadline=0.2, heartbeat_interval=0.05
    ) as (_, base):
        first = Stream(base, PATH, accept="application/json")
        assert first.status == 504
        first.close()
        # The handler answered at the deadline, but the blocked worker is not pretended dead.
        busy = Stream(base, PATH, accept="application/json")
        try:
            assert busy.status == 503
            assert json.loads(busy.body()) == {"error": "server_busy"}
        finally:
            busy.close()
        auth.release.set()
        end = time.monotonic() + 3
        status = None
        while time.monotonic() < end:
            retry = Stream(base, PATH, accept="application/json")
            status = retry.status
            retry.close()
            if status != 503:
                break
            time.sleep(0.05)
        assert status in (200, 504)


def test_connection_cap_rejects_extra_connections_immediately(database):
    with serving(database, ScriptedAuth(), max_connections=2, client_timeout=5) as (instance, _):
        port = instance.server_port
        idle = [socket.create_connection(("127.0.0.1", port)) for _ in range(2)]
        try:
            time.sleep(0.1)
            answer = raw_exchange(port, b"GET /health HTTP/1.0\r\n\r\n")
            assert answer.startswith(b"HTTP/1.0 503 ")
            assert b'"server_busy"' in answer
        finally:
            for sock in idle:
                sock.close()
        time.sleep(0.1)
        assert raw_exchange(port, b"GET /health HTTP/1.0\r\n\r\n").startswith(b"HTTP/1.0 200 ")


def test_idle_connections_are_reclaimed_after_the_client_timeout(database):
    with serving(database, ScriptedAuth(), max_connections=1, client_timeout=0.3) as (instance, _):
        port = instance.server_port
        idle = socket.create_connection(("127.0.0.1", port))
        try:
            time.sleep(0.6)
            assert raw_exchange(port, b"GET /health HTTP/1.0\r\n\r\n").startswith(b"HTTP/1.0 200 ")
        finally:
            idle.close()


@pytest.mark.parametrize(
    "payload,expected",
    [
        (b"BAD REQUEST LINE WITH WORDS HTTP/1.0\r\n\r\n", b" 400 "),
        (b"GET /" + b"a" * 70000 + b" HTTP/1.0\r\n\r\n", b" 414 "),
        (b"GET /health HTTP/1.0\r\n" + b"X-A: b\r\n" * 150 + b"\r\n", b" 431 "),
    ],
)
def test_malformed_and_oversized_requests_get_json_errors_and_do_not_wedge_the_server(
    database, payload, expected
):
    with serving(database, ScriptedAuth()) as (instance, _):
        answer = raw_exchange(instance.server_port, payload)
        head, _, body = answer.partition(b"\r\n\r\n")
        assert expected in head.split(b"\r\n")[0]
        assert b"application/json" in head
        assert "error" in json.loads(body)
        assert raw_exchange(instance.server_port, b"GET /health HTTP/1.0\r\n\r\n").startswith(
            b"HTTP/1.0 200 "
        )


def test_oversized_query_is_rejected_before_any_stream_or_upstream_work(database):
    auth = ScriptedAuth()
    with serving(database, auth) as (_, base):
        stream = Stream(base, "a" * 5000)
        try:
            body = json.loads(stream.body())
        finally:
            stream.close()
    assert stream.status == 400
    assert body == {"error": "query_too_long"}
    assert auth.calls == 0


def test_viewers_never_receive_each_others_results_under_concurrency(tmp_path):
    db = build_index(tmp_path / "search.db", ["acme/alice-only", "acme/bob-only"], text="needle")

    class Viewers(ScriptedAuth):
        def visible_repositories(self, cookie, repo=None):
            time.sleep(0.05)
            return True, {"session=alice": {"acme/alice-only"}, "session=bob": {"acme/bob-only"}}[cookie]

        def code_readable_repositories(self, cookie, repos):
            return set(repos)

    with serving(db, Viewers(), heartbeat_interval=0.05) as (_, base):
        outcomes: dict = {}

        def run(cookie):
            stream = Stream(base, PATH, cookie=cookie)
            try:
                outcomes[cookie] = (stream.drain(), bytes(stream.raw))
            finally:
                stream.close()

        threads = [threading.Thread(target=run, args=(c,)) for c in ("session=alice", "session=bob")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
    alice, alice_raw = outcomes["session=alice"]
    bob, bob_raw = outcomes["session=bob"]
    assert b"bob-only" not in alice_raw and b"alice-only" not in bob_raw
    assert alice[-2]["data"]["results"][0]["repo"] == "acme/alice-only"
    assert bob[-2]["data"]["results"][0]["repo"] == "acme/bob-only"


def test_utf8_is_valid_and_line_separators_never_split_a_record(tmp_path):
    db = build_index(
        tmp_path / "search.db",
        ["acme/open"],
        text="needle \u2028 \u2029 \U0001f600 \u00e9 tail",
    )
    with serving(db, ScriptedAuth()) as (_, base):
        stream = Stream(base, PATH)
        try:
            records = stream.drain()
        finally:
            stream.close()
    raw = bytes(stream.raw)
    assert raw.decode("utf-8")
    assert b"\xe2\x80\xa8" not in raw and b"\xe2\x80\xa9" not in raw
    assert len(raw.split(b"\n")) == len(records) + 1 and raw.endswith(b"\n")
    text = json.dumps(records[-2]["data"], ensure_ascii=False)
    assert "\U0001f600" in text and "\u00e9" in text and "\u2028" in text


def test_oversized_result_is_a_sanitized_terminal_error_never_a_truncation(database, monkeypatch):
    monkeypatch.setattr("hypersearch.server.MAX_RECORD_BYTES", 200)
    with serving(database, ScriptedAuth()) as (_, base):
        stream = Stream(base, PATH)
        try:
            records = stream.drain()
        finally:
            stream.close()
    assert records == [
        {"v": 1, "type": "started"},
        {"v": 1, "type": "error", "code": "search_unavailable", "status": 503},
    ]


def test_a_client_that_stops_reading_is_cut_off_within_the_write_budget(tmp_path, monkeypatch):
    from hypersearch.server import SearchHandler

    repos = [f"acme/r{index:03d}" for index in range(100)]
    db = build_index(tmp_path / "search.db", repos, text="needle " + "x" * 400)
    auth = ScriptedAuth(visible=repos)
    monkeypatch.setattr("hypersearch.server.WRITE_TIMEOUT", 0.3)
    original = SearchHandler.setup

    def small_send_buffer(self):
        original(self)
        self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024)

    monkeypatch.setattr(SearchHandler, "setup", small_send_buffer)
    with serving(db, auth) as (instance, _):
        reader = socket.socket()
        reader.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
        reader.connect(("127.0.0.1", instance.server_port))
        reader.sendall(
            b"GET /api/hypersearch?q=needle&limit=100 HTTP/1.0\r\n"
            b"Cookie: session=alice\r\nAccept: application/x-ndjson\r\n\r\n"
        )
        try:
            end = time.monotonic() + 5
            while not auth.contexts and time.monotonic() < end:
                time.sleep(0.02)
            context = auth.contexts[0]
            while not context.cancelled and time.monotonic() < end:
                time.sleep(0.02)
            assert context.cancelled and context.reason == "client_disconnected"
            # The stalled connection no longer holds a handler or a worker slot.
            end = time.monotonic() + 3
            while instance._connections and time.monotonic() < end:
                time.sleep(0.02)
            assert instance._connections == 0 and instance._outstanding == 0
        finally:
            reader.close()


def test_writer_marks_a_stuck_socket_as_a_client_disconnect():
    from hypersearch.server import NdjsonStream, StreamBroken

    from hypersearch.deadline import RequestContext

    context = RequestContext(10)

    def stuck(payload):
        raise TimeoutError("send timed out")

    stream = NdjsonStream(stuck, context)
    with pytest.raises(StreamBroken):
        stream.write({"v": 1, "type": "started"})
    assert context.cancelled and context.reason == "client_disconnected"
    with pytest.raises(StreamBroken):
        stream.write({"v": 1, "type": "heartbeat"})


def test_writer_enforces_shared_record_and_total_caps():
    from hypersearch.deadline import RequestContext
    from hypersearch.server import NdjsonStream, RecordTooLarge

    sent = []
    stream = NdjsonStream(sent.append, RequestContext(10), max_record_bytes=64,
                          max_total_bytes=100, max_records=3)
    stream.write({"v": 1, "type": "started"})
    with pytest.raises(RecordTooLarge):
        stream.write({"v": 1, "type": "result", "data": "x" * 200})
    stream.write({"v": 1, "type": "heartbeat"})
    stream.write({"v": 1, "type": "heartbeat"})
    with pytest.raises(RecordTooLarge):
        stream.write({"v": 1, "type": "heartbeat"})
    assert all(chunk.endswith(b"\n") and chunk.count(b"\n") == 1 for chunk in sent)


def test_orderly_shutdown_ends_open_streams_with_a_terminal_error_and_bounds_the_wait(database):
    auth = ScriptedAuth(block=True, wait=3.0)
    with serving(database, auth, heartbeat_interval=0.05, shutdown_grace=0.5) as (instance, base):
        stream = Stream(base, PATH)
        assert auth.entered.wait(2)
        assert stream.next() == {"v": 1, "type": "started"}
        began = time.perf_counter()
        instance.shutdown()
        instance.server_close()
        elapsed = time.perf_counter() - began
        records = stream.drain()
        stream.close()
    assert records[-1] == {"v": 1, "type": "error", "code": "search_unavailable", "status": 503}
    assert elapsed < 2.0
    assert auth.contexts[0].cancelled


def test_settings_reject_unbounded_or_inconsistent_values():
    from hypersearch.server import ServerSettings

    for bad in (
        {"request_deadline": 0},
        {"request_deadline": float("inf")},
        {"request_deadline": 301},
        {"heartbeat_interval": 0.01},
        {"heartbeat_interval": 31},
        {"search_workers": 0},
        {"search_workers": 65},
        {"search_queue": -1},
        {"search_queue": 257},
        {"max_connections": 0},
        {"max_connections": 1025},
        {"client_timeout": 0},
        # 300s / 0.05s of heartbeats could never fit the shared 256-record stream cap.
        {"request_deadline": 300, "heartbeat_interval": 0.05},
    ):
        with pytest.raises(ValueError):
            ServerSettings(**bad)
    defaults = ServerSettings()
    assert (defaults.request_deadline, defaults.heartbeat_interval) == (20.0, 2.0)


def test_real_auth_streams_heartbeats_through_a_slow_cold_listing(tmp_path):
    visible = [f"acme/r{index:04d}" for index in range(750)]
    fake = FakeForgejo(visible, visible[:3], page_delay=0.15, head_delay=0.01)
    db = build_index(tmp_path / "search.db", visible[:3], text="needle")
    auth = ForgejoAuth(fake.base)
    try:
        with serving(db, auth, heartbeat_interval=0.05) as (_, base):
            stream = Stream(base, PATH)
            try:
                records = stream.drain()
            finally:
                stream.close()
    finally:
        auth.close()
        fake.close()
    assert types(records)[0] == "started" and types(records)[-2:] == ["result", "done"]
    assert types(records).count("heartbeat") >= 3
    assert len(records[-2]["data"]["results"]) == 3
    assert fake.count("list") == 16 and fake.count("identity") == 0
    first_heartbeat = next(t for t, r in stream.seen if r["type"] == "heartbeat")
    assert first_heartbeat < stream.seen[-2][0]


def test_empty_query_readiness_uses_session_identity_only(tmp_path):
    visible = [f"acme/r{index:04d}" for index in range(750)]
    fake = FakeForgejo(visible, page_delay=0.2)
    db = build_index(tmp_path / "search.db", [])
    auth = ForgejoAuth(fake.base)
    try:
        with serving(db, auth) as (_, base):
            stream = Stream(base, "", accept="application/json")
            try:
                payload = json.loads(stream.body())
            finally:
                stream.close()
    finally:
        auth.close()
        fake.close()
    assert stream.status == 200
    assert payload["results"] == [] and payload["coverage"]["ast"] == {"status": "not_requested"}
    assert set(payload) == {"query", "mode", "results", "coverage", "total_ms"}
    assert fake.count("list") == 0 and fake.count("identity") == 1
    assert payload["total_ms"] < 150


def test_repo_scoped_cold_query_never_enumerates_unrelated_repositories(tmp_path):
    visible = [f"acme/r{index:04d}" for index in range(750)] + ["acme/open"]
    fake = FakeForgejo(visible, ["acme/open"], page_delay=0.2)
    db = build_index(tmp_path / "search.db", ["acme/open", "acme/r0001"], text="needle")
    auth = ForgejoAuth(fake.base)
    try:
        with serving(db, auth) as (_, base):
            stream = Stream(base, "repo:acme/open needle", accept="application/json")
            try:
                payload = json.loads(stream.body())
            finally:
                stream.close()
    finally:
        auth.close()
        fake.close()
    assert stream.status == 200
    assert [hit["repo"] for hit in payload["results"]] == ["acme/open"]
    assert fake.count("list") == 0 and fake.count("scoped") >= 1
    assert fake.count("head") == 1
    assert payload["total_ms"] < 1000


def test_owner_and_path_wildcards_keep_sql_like_semantics_after_narrowing(tmp_path):
    visible = ["acme_x/open", "acmeQx/open", "acmeZ/open", "other/open"]
    fake = FakeForgejo(visible, visible)
    db = build_index(tmp_path / "search.db", visible, text="needle")
    auth = ForgejoAuth(fake.base)
    try:
        with serving(db, auth) as (_, base):
            stream = Stream(base, "owner:acme_x needle", accept="application/json")
            try:
                payload = json.loads(stream.body())
            finally:
                stream.close()
    finally:
        auth.close()
        fake.close()
    # `_` is an unescaped SQL LIKE wildcard: it matches exactly one character (acmeQx) but
    # neither a different length (acmeZ) nor another owner.
    assert {hit["repo"] for hit in payload["results"]} == {"acme_x/open", "acmeQx/open"}
    assert fake.count("scoped") == 0  # owner: has no safe native narrowing


def test_disconnected_queued_searches_keep_the_admission_bound_until_a_worker_pops_them(database):
    # A cancelled concurrent.futures item stays in the executor queue, so its admission
    # slot is returned when a worker pops it (instantly, as it is already cancelled) --
    # never earlier, or dead items could pile up beyond the admission bound.
    auth = ScriptedAuth(block=True, wait=3.0)
    with serving(database, auth, search_workers=1, search_queue=3, heartbeat_interval=0.05) as (
        instance,
        _,
    ):
        port = instance.server_port
        request = (
            b"GET /api/hypersearch?q=needle HTTP/1.0\r\nCookie: session=alice\r\n"
            b"Accept: application/x-ndjson\r\n\r\n"
        )
        running = socket.create_connection(("127.0.0.1", port))
        running.sendall(request)
        assert auth.entered.wait(2)
        queued = [socket.create_connection(("127.0.0.1", port)) for _ in range(3)]
        for sock in queued:
            sock.sendall(request)
        end = time.monotonic() + 2
        while instance._outstanding < 4 and time.monotonic() < end:
            time.sleep(0.02)
        assert instance._outstanding == 4
        for sock in queued:
            sock.close()
        time.sleep(0.4)
        assert instance._outstanding == 4  # still bounded: nothing was dropped from the queue
        auth.release.set()
        end = time.monotonic() + 3
        while instance._outstanding and time.monotonic() < end:
            time.sleep(0.02)
        running.close()
        assert instance._outstanding == 0  # popped dead items returned their slots at once
        assert auth.calls == 1  # and the disconnected searches never reached the upstream


def test_a_queued_request_cancelled_by_shutdown_still_gets_a_terminal_error(database):
    auth = ScriptedAuth(block=True, wait=3.0)
    with serving(
        database, auth, search_workers=1, search_queue=2, heartbeat_interval=0.05, shutdown_grace=0.2
    ) as (instance, _):
        port = instance.server_port
        request = (
            b"GET /api/hypersearch?q=needle HTTP/1.0\r\nCookie: session=alice\r\n"
            b"Accept: application/x-ndjson\r\n\r\n"
        )
        first = socket.create_connection(("127.0.0.1", port))
        first.sendall(request)
        assert auth.entered.wait(2)
        queued = socket.create_connection(("127.0.0.1", port), timeout=5)
        queued.sendall(request)
        end = time.monotonic() + 2
        while instance._outstanding < 2 and time.monotonic() < end:
            time.sleep(0.02)
        instance.shutdown()
        instance.server_close()
        answer = bytearray()
        try:
            while chunk := queued.recv(65536):
                answer.extend(chunk)
        except OSError:
            pass
        first.close()
        queued.close()
    lines = [json.loads(line) for line in bytes(answer).partition(b"\r\n\r\n")[2].splitlines() if line]
    assert lines[0] == {"v": 1, "type": "started"}
    assert lines[-1] == {"v": 1, "type": "error", "code": "search_unavailable", "status": 503}
