"""The release version must agree everywhere it is declared, and never move backwards."""

import re
import tomllib
from pathlib import Path

from hypersearch import __version__
from hypersearch.server import SearchHandler

ROOT = Path(__file__).resolve().parents[1]


def test_release_version_agrees_across_metadata_runtime_banner_lock_and_readme():
    declared = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    assert __version__ == declared
    assert SearchHandler.server_version == f"HyperSearch/{declared}"
    locked = next(
        package["version"]
        for package in tomllib.loads((ROOT / "uv.lock").read_text())["package"]
        if package["name"] == "hypersearch"
    )
    assert locked == declared
    assert f"The package version is {declared} " in (ROOT / "README.md").read_text()


def test_release_version_is_not_rolled_back_below_the_streaming_release():
    # 0.4.0 introduced the NDJSON transport; a merge of the superseded 0.3.1 line must fail here.
    assert re.fullmatch(r"\d+\.\d+\.\d+", __version__)
    assert tuple(int(part) for part in __version__.split(".")) >= (0, 4, 0)
