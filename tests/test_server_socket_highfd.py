"""A valid high-numbered Linux socket must not crash the request wait loop."""

import socket
import sys
import threading
from concurrent.futures import Future
from types import SimpleNamespace

import pytest

from hypersearch.deadline import RequestContext
from hypersearch.server import SearchHandler, ServerSettings


@pytest.mark.skipif(sys.platform != "linux", reason="Linux fd-number/FD_SETSIZE regression; Windows uses socket handles")
@pytest.mark.parametrize("peer_state", ["idle", "half_closed", "pending_bytes"])
def test_valid_high_fd_wait_preserves_response_half_close_and_timeout(peer_state):
    import fcntl
    import resource

    minimum_fd = 1025
    soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft != resource.RLIM_INFINITY and soft <= minimum_fd:
        pytest.skip("process fd limit does not allow a descriptor at least1025")

    reader, writer = socket.socketpair()
    with reader, writer:
        # Duplicate one descriptor directly; do not open1025dummy files or raise
        # the process limit just to construct the regression.
        duplicate = fcntl.fcntl(reader.fileno(), fcntl.F_DUPFD, minimum_fd)
        with socket.socket(fileno=duplicate) as connection:
            assert connection.fileno() >= minimum_fd
            connection.settimeout(0.37)
            if peer_state == "half_closed":
                writer.shutdown(socket.SHUT_WR)
            elif peer_state == "pending_bytes":
                writer.sendall(b"queued")

            handler = object.__new__(SearchHandler)
            handler.connection = connection
            handler._context = RequestContext(2)
            handler.server = SimpleNamespace(settings=ServerSettings())
            future = Future()
            result = {"query": "needle", "results": []}
            finish = threading.Timer(0.2, lambda: future.set_result(result))
            finish.start()
            try:
                outcome = handler._wait(future, handler._context, None)
            finally:
                finish.cancel()
                finish.join()
            assert outcome == result
            assert not handler._context.cancelled
            assert connection.gettimeout() == 0.37
            if peer_state == "half_closed":
                assert connection.recv(1) == b""
            elif peer_state == "pending_bytes":
                assert connection.recv(6) == b"queued"
