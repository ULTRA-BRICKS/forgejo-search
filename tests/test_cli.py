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
