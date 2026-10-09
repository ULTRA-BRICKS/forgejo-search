"""Disconnect detection at production cadence, without confusing a TCP half-close."""

from __future__ import annotations

import errno
import json
import socket
import threading
import time
from concurrent.futures import Future
from types import SimpleNamespace

import pytest
from fake_forgejo import FakeForgejo
from support import build_index
from test_server_stream import ScriptedAuth, serving

from hypersearch import deadline
from hypersearch.auth import ForgejoAuth
from hypersearch.deadline import RequestContext
from hypersearch.server import NdjsonStream, SearchHandler, ServerSettings


class ObservedForgejo(FakeForgejo):
    def __init__(self, *args, **kwargs):
        self.listing_starts = []
        super().__init__(*args, **kwargs)

    def _record(self, kind, detail):
        super()._record(kind, detail)
        if kind == "list":
            with self.lock:
                self.listing_starts.append((time.monotonic(), detail))


class ObservedAuth(ForgejoAuth):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.context = None
        self.cancelled_at = None
        self.cancelled = threading.Event()

    def visible_repositories(self, cookie, repo=None):
        self.context = deadline.current()

        def cancelled():
            self.cancelled_at = time.monotonic()
            self.cancelled.set()

        unregister = self.context.on_cancel(cancelled)
        try:
            return super().visible_repositories(cookie, repo)
        finally:
            # Keep observing output-side cancellation after visibility has returned.
            # The context owns this short-lived callback until it ends.
            if self.context.cancelled:
                unregister()


def open_request(port, accept="application/x-ndjson"):
    sock = socket.create_connection(("127.0.0.1", port), timeout=8)
    sock.sendall(
        b"GET /api/hypersearch?q=needle HTTP/1.0\r\nCookie: session=alice\r\n"
        + f"Accept: {accept}\r\n\r\n".encode()
    )
    return sock


def read_until(sock, ending):
    data = bytearray()
    while not data.endswith(ending):
        chunk = sock.recv(1)  # Do not leave unread response bytes when closing normally.
        assert chunk, bytes(data)
        data.extend(chunk)
        assert len(data) < 65536
    return bytes(data)


def test_graceful_disconnect_stops_late_listing_at_default_heartbeat(tmp_path):
    visible = [f"acme/r{n:04d}" for n in range(750)]
    fake = ObservedForgejo(visible, visible[:1])
    gate, entered = threading.Event(), threading.Event()
    fake.page_gates[1], fake.page_entered[1] = gate, entered
    # The first response is intentionally held past3s: this is a fixture timeout,
    # not a change to the deployed deadline or heartbeat.
    auth = ObservedAuth(fake.base, request_timeout=10)
    database = build_index(tmp_path / "search.db", visible[:1], text="needle")
    sock = None
    try:
        with serving(database, auth, request_deadline=20, heartbeat_interval=2) as (server, _):
            sock = open_request(server.server_port)
            assert read_until(sock, b"\r\n\r\n").startswith(b"HTTP/1.0 200 ")
            assert json.loads(read_until(sock, b"\n")) == {"v": 1, "type": "started"}
            assert entered.wait(2)
            closed_at = time.monotonic()
            sock.close()  # Ordinary FIN; no forced RST/SO_LINGER shortcut.
            sock = None
            cancelled_in_bound = auth.cancelled.wait(3)
            # Still release on the failing implementation so the test actually observes
            # its late next wave instead of aborting at the first failed assertion.
            gate.wait(max(0.0, closed_at + 3.25 - time.monotonic()))
            gate.set()
            auth.cancelled.wait(3)
            end = time.monotonic() + 3
            while server._outstanding and time.monotonic() < end:
                threading.Event().wait(0.02)
            with fake.lock:
                offsets = [(round(at - closed_at, 3), detail) for at, detail in fake.listing_starts]
            trace = {
                "cancelled_after": None if auth.cancelled_at is None else auth.cancelled_at - closed_at,
                "listing_starts_after_close": offsets,
                "outstanding": server._outstanding,
            }
            assert cancelled_in_bound, trace
            assert auth.context.reason == "client_disconnected", trace
            assert not [offset for offset, _ in offsets if offset > 3], trace
            assert server._outstanding == 0, trace
    finally:
        gate.set()
        if sock is not None:
            sock.close()
        auth.close()
        fake.close()


@pytest.mark.parametrize("accept", ["application/json", "application/x-ndjson"])
def test_write_half_close_survives_multiple_heartbeat_boundaries(tmp_path, accept):
    database = build_index(tmp_path / "search.db", ["acme/open"], text="needle")
    auth = ScriptedAuth(block=True, wait=8)
    with serving(database, auth, request_deadline=20, heartbeat_interval=2) as (server, _):
        with open_request(server.server_port, accept) as sock:
            sock.shutdown(socket.SHUT_WR)
            assert auth.entered.wait(2)
            began = time.monotonic()
            release = threading.Timer(4.25, auth.release.set)
            release.start()
            try:
                answer = bytearray()
                while chunk := sock.recv(65536):
                    answer.extend(chunk)
            finally:
                auth.release.set()
                release.cancel()
                release.join()
            assert time.monotonic() - began >= 4.2
            assert all(not context.cancelled for context in auth.contexts)
        head, _, body = bytes(answer).partition(b"\r\n\r\n")
        assert head.startswith(b"HTTP/1.0 200 ")
        if accept == "application/json":
            result = json.loads(body)
        else:
            records = [json.loads(line) for line in body.splitlines()]
            kinds = [record["type"] for record in records]
            assert kinds[0] == "started" and kinds[-2:] == ["result", "done"]
            assert kinds.count("heartbeat") >= 2
            assert set(kinds[1:-2]) == {"heartbeat"}
            result = records[-2]["data"]
        assert result["query"] == "needle"
        assert [hit["repo"] for hit in result["results"]] == ["acme/open"]


@pytest.fixture
def idle_socket():
    reader, writer = socket.socketpair()
    with reader, writer:
        yield reader


@pytest.mark.parametrize("finished", [False, True])
def test_pending_transport_error_after_successful_write_stops_before_another_heartbeat(finished, idle_socket):
    # A successful send only enters the local socket buffer. The asynchronous reset
    # may arrive afterwards, including simultaneously with a completed search.
    context = RequestContext(1)
    future = Future()
    cancellations, writes = [], []
    context.on_cancel(lambda: cancellations.append(context.reason))

    class DelayedReset:
        error = 0

        def __getattr__(self, name):
            return getattr(idle_socket, name)

        def fileno(self):
            return idle_socket.fileno()

        def getsockopt(self, level, option):
            assert (level, option) == (socket.SOL_SOCKET, socket.SO_ERROR)
            error, self.error = self.error, 0  # SO_ERROR is consumed by observation.
            return error

    connection = DelayedReset()

    def send(payload):
        writes.append(json.loads(payload))
        connection.error = errno.ECONNRESET
        if finished and not future.done():
            future.set_result({"private": "must not be published"})

    handler = object.__new__(SearchHandler)
    handler.server = SimpleNamespace(settings=ServerSettings(heartbeat_interval=0.2))
    handler.connection, handler._context = connection, context
    began = time.monotonic()
    outcome = handler._wait(future, context, NdjsonStream(send, context))
    assert outcome is None
    assert cancellations == ["client_disconnected"]
    assert writes == [{"v": 1, "type": "heartbeat"}]
    assert connection.error == 0
    assert time.monotonic() - began < 0.4


@pytest.mark.parametrize("error", [errno.ECONNRESET, errno.ECONNABORTED, errno.EBADF, errno.ENOTSOCK])
def test_broken_socket_observation_cancels_without_waiting_for_output(error):
    class BrokenSocket:
        def getsockopt(self, level, option):
            raise OSError(error, "synthetic closed socket")

    handler = object.__new__(SearchHandler)
    context = RequestContext(0.5)
    handler.server = SimpleNamespace(settings=ServerSettings())
    handler.connection, handler._context = BrokenSocket(), context
    outcome = handler._wait(Future(), context, None)
    assert outcome is None
    assert context.reason == "client_disconnected"


@pytest.mark.parametrize("payload", [b"", b"next request"])
def test_socket_observation_preserves_half_close_data_and_timeout(payload):
    reader, writer = socket.socketpair()
    with reader, writer:
        reader.settimeout(0.37)
        writer.sendall(payload)
        writer.shutdown(socket.SHUT_WR)
        handler = object.__new__(SearchHandler)
        handler.connection, handler._context = reader, RequestContext(5)
        assert not handler._client_disconnected()
        assert not handler._context.cancelled
        assert reader.gettimeout() == 0.37
        assert reader.recv(65536) == payload  # Observation must consume no bytes.


def test_idle_socket_observation_does_not_wait_for_its_read_timeout(idle_socket):
    idle_socket.settimeout(2)
    handler = object.__new__(SearchHandler)
    handler.connection, handler._context = idle_socket, RequestContext(5)
    began = time.monotonic()
    assert not handler._client_disconnected()
    assert time.monotonic() - began < 0.5
    assert not handler._context.cancelled
    assert idle_socket.gettimeout() == 2


@pytest.mark.parametrize("error", [errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ECONNREFUSED])
@pytest.mark.parametrize("observation", ["so_error", "peek"])
@pytest.mark.parametrize("finished", [False, True])
def test_recoverable_socket_error_keeps_live_connection_and_result(error, observation, finished):
    # Linux SO_ERROR includes sk_err_soft: an ICMP error may coexist with an
    # established TCP connection. Inject that observation, retaining real live I/O.
    reader, peer = socket.socketpair()
    with reader, peer:
        reader.settimeout(0.37)
        peer.settimeout(1)
        observed = threading.Event()
        observed_while_pending = []

        def record_observation():
            observed_while_pending.append(not future.done())
            observed.set()

        class SoftErrorSocket:
            pending = error

            def __getattr__(self, name):
                return getattr(reader, name)

            def getsockopt(self, level, option):
                if observation == "so_error" and self.pending:
                    result, self.pending = self.pending, 0
                    record_observation()
                    return result
                return reader.getsockopt(level, option)

            def recv(self, size, flags=0):
                if observation == "peek" and self.pending:
                    result, self.pending = self.pending, 0
                    record_observation()
                    raise OSError(result, "recoverable network error")
                return reader.recv(size, flags)

        handler = object.__new__(SearchHandler)
        context = RequestContext(2)
        handler.connection, handler._context = SoftErrorSocket(), context
        handler.server = SimpleNamespace(settings=ServerSettings())
        future = Future()
        result = {"results": [{"repo": "acme/open"}]}
        def finish_after_observation():
            if observed.wait(timeout=1):
                future.set_result(result)

        release = threading.Thread(target=finish_after_observation, daemon=True)
        if finished:
            future.set_result(result)
        else:
            release.start()
        try:
            assert handler._wait(future, context, None) == result
            assert not context.cancelled
            assert handler.connection.pending == 0
            assert observed_while_pending == [not finished]
            assert reader.gettimeout() == 0.37
            handler.connection.sendall(b"response remains deliverable")
            assert peer.recv(128) == b"response remains deliverable"
        finally:
            if not finished:
                observed.set()
                release.join(timeout=2)
                assert not release.is_alive()


def test_concurrent_idle_clients_bound_observation_work_and_deliver_results():
    # A full default-sized group of stalled JSON searches should not probe each
    # socket twenty times per second. EOF/data readiness must not create a spin.
    clients = 32
    barrier = threading.Barrier(clients + 1)
    connections, peers, contexts, futures, threads, states = [], [], [], [], [], []
    outcomes, errors = [], []

    class CountedConnection:
        def __init__(self, connection):
            self.connection = connection
            self.observations = 0

        def __getattr__(self, name):
            return getattr(self.connection, name)

        def getsockopt(self, level, option):
            self.observations += 1
            return self.connection.getsockopt(level, option)

    def wait(handler, future, context):
        try:
            barrier.wait(timeout=3)
            outcomes.append(handler._wait(future, context, None))
        except (OSError, RuntimeError) as error:
            errors.append(error)

    try:
        for index in range(clients):
            connection, peer = socket.socketpair()
            connection.settimeout(0.37)
            state = ("idle", "empty_eof", "queued_data")[index % 3]
            states.append(state)
            if state == "queued_data":
                peer.sendall(b"unread")
            if state == "empty_eof" or (state == "queued_data" and index % 2 == 0):
                peer.shutdown(socket.SHUT_WR)
            counted = CountedConnection(connection)
            connections.append(counted)
            peers.append(peer)
            context, future = RequestContext(5), Future()
            contexts.append(context)
            futures.append(future)
            handler = object.__new__(SearchHandler)
            handler.connection, handler._context = counted, context
            handler.server = SimpleNamespace(settings=ServerSettings())
            thread = threading.Thread(target=wait, args=(handler, future, context), daemon=True)
            threads.append(thread)
            thread.start()
        barrier.wait(timeout=3)
        threading.Event().wait(1.15)
        for future in futures:
            future.set_result({"results": []})
        join_deadline = time.monotonic() + 2
        for thread in threads:
            thread.join(timeout=max(0, join_deadline - time.monotonic()))
        assert not errors
        assert not any(thread.is_alive() for thread in threads)
        assert outcomes == [{"results": []}] * clients
        assert not any(context.cancelled for context in contexts)
        counts = [connection.observations for connection in connections]
        assert max(counts) <= 8, counts
        for connection, state in zip(connections, states):
            assert connection.gettimeout() == 0.37
            if state == "queued_data":
                assert connection.recv(6) == b"unread"
            elif state == "empty_eof":
                assert connection.recv(1) == b""
    finally:
        for context in contexts:
            context.cancel("test_shutdown")
        join_deadline = time.monotonic() + 2
        for thread in threads:
            thread.join(timeout=max(0, join_deadline - time.monotonic()))
        for connection, peer in zip(connections, peers):
            connection.close()
            peer.close()
