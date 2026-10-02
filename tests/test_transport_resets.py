"""Socket resets are unavailable authorization, never anonymous or a code denial."""
import errno

import pytest

from hypersearch.auth import ForgejoAuth, VisibilityUnavailable


@pytest.mark.parametrize("method", ["visible_repositories", "session_authenticated", "code_readable_repositories"])
@pytest.mark.parametrize("failure", [
    ConnectionResetError(errno.ECONNRESET, "synthetic reset"),
    ConnectionAbortedError(errno.ECONNABORTED, "synthetic abort"),
    OSError(errno.EIO, "synthetic socket read failure"),
])
def test_socket_read_failure_is_unavailable_and_never_grants_or_denies(monkeypatch, method, failure):
    auth = ForgejoAuth()
    calls = []

    def fail(path, cookie):
        calls.append(path)
        raise failure

    monkeypatch.setattr(auth, "_get", fail)
    monkeypatch.setattr(auth, "_head", fail)
    try:
        args = ("session=transport-test", {"acme/private"}) if method == "code_readable_repositories" else ("session=transport-test",)
        with pytest.raises(VisibilityUnavailable):
            getattr(auth, method)(*args)
        assert calls
        assert not auth.cache
        assert not auth._code_cache
        count = len(calls)
        with pytest.raises(VisibilityUnavailable):
            getattr(auth, method)(*args)
        assert len(calls) == count
    finally:
        auth.close()
