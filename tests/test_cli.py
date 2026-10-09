import pytest

from hypersearch.cli import parser


def test_serve_public_host_is_configurable():
    args = parser().parse_args(["serve", "--public-host", "git.example.test"])
    assert args.public_host == "git.example.test"


def test_probe_controls_accept_operator_overrides(monkeypatch):
    monkeypatch.setenv("HYPERSEARCH_CODE_PROBE_BUDGET", "20")
    monkeypatch.setenv("HYPERSEARCH_CODE_PROBE_CONCURRENCY", "16")
    monkeypatch.setenv("HYPERSEARCH_REQUEST_TIMEOUT", "3")
    monkeypatch.setenv("HYPERSEARCH_CODE_CACHE_MAX_ENTRIES", "16000")
    args = parser().parse_args(["serve", "--code-probe-budget", "25"])
    assert (args.code_probe_budget, args.code_probe_concurrency,
            args.request_timeout, args.code_cache_max_entries) == (25, 16, 3, 16000)


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf", "121"])
def test_invalid_budget_environment_fails_before_serving(monkeypatch, value):
    monkeypatch.setenv("HYPERSEARCH_CODE_PROBE_BUDGET", value)
    with pytest.raises(SystemExit) as error:
        parser().parse_args(["serve"])
    assert error.value.code == 2


def test_transport_controls_have_documented_defaults(monkeypatch):
    for name in (
        "HYPERSEARCH_REQUEST_DEADLINE", "HYPERSEARCH_HEARTBEAT_INTERVAL",
        "HYPERSEARCH_SEARCH_WORKERS", "HYPERSEARCH_SEARCH_QUEUE",
        "HYPERSEARCH_MAX_CONNECTIONS", "HYPERSEARCH_VISIBILITY_CONCURRENCY",
    ):
        monkeypatch.delenv(name, raising=False)
    args = parser().parse_args(["serve"])
    assert (
        args.request_deadline, args.heartbeat_interval, args.search_workers,
        args.search_queue, args.max_connections, args.visibility_concurrency,
    ) == (20, 2, 8, 24, 64, 8)


def test_transport_controls_accept_environment_and_flag_overrides(monkeypatch):
    monkeypatch.setenv("HYPERSEARCH_REQUEST_DEADLINE", "30")
    monkeypatch.setenv("HYPERSEARCH_HEARTBEAT_INTERVAL", "1.5")
    monkeypatch.setenv("HYPERSEARCH_SEARCH_WORKERS", "4")
    monkeypatch.setenv("HYPERSEARCH_SEARCH_QUEUE", "0")
    monkeypatch.setenv("HYPERSEARCH_MAX_CONNECTIONS", "128")
    args = parser().parse_args(["serve", "--search-workers", "6", "--visibility-concurrency", "2"])
    assert (
        args.request_deadline, args.heartbeat_interval, args.search_workers,
        args.search_queue, args.max_connections, args.visibility_concurrency,
    ) == (30, 1.5, 6, 0, 128, 2)


@pytest.mark.parametrize("flag,value", [
    ("--request-deadline", "0"), ("--request-deadline", "301"), ("--request-deadline", "nan"),
    ("--heartbeat-interval", "0.01"), ("--heartbeat-interval", "31"), ("--heartbeat-interval", "inf"),
    ("--search-workers", "0"), ("--search-workers", "65"),
    ("--search-queue", "-1"), ("--search-queue", "257"),
    ("--max-connections", "0"), ("--max-connections", "1025"),
    ("--visibility-concurrency", "0"), ("--visibility-concurrency", "65"),
])
def test_invalid_transport_controls_fail_before_serving(flag, value, capsys):
    with pytest.raises(SystemExit) as error:
        parser().parse_args(["serve", flag, value])
    assert error.value.code == 2
    message = capsys.readouterr().err
    # The flag exists and rejected the value; an unknown flag would also exit 2.
    assert "unrecognized arguments" not in message
    assert f"argument {flag}" in message


def test_inconsistent_deadline_and_heartbeat_fail_before_the_database_is_opened(tmp_path):
    from hypersearch.cli import main

    database = tmp_path / "never-created" / "search.db"
    with pytest.raises(SystemExit) as error:
        main(["--db", str(database), "serve", "--request-deadline", "300",
              "--heartbeat-interval", "0.05"])
    assert error.value.code == 2
    assert not database.parent.exists()
