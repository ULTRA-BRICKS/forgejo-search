"""Release version must agree across the source and installed package."""
import tomllib
from pathlib import Path

from hypersearch import __version__


def test_runtime_version_matches_release():
    root = Path(__file__).resolve().parents[1]
    declared = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    from hypersearch.server import SearchHandler

    assert SearchHandler.server_version == f"HyperSearch/{declared}"
    assert __version__ == declared
    assert f"The source package version is {declared}" in (root / "README.md").read_text()


def test_vendored_runtime_reads_distribution_metadata(tmp_path):
    import os
    import shutil
    import subprocess
    import sys

    root = Path(__file__).resolve().parents[1]
    declared = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "host-app"\nversion = "9.9.9"\n')
    tmp_path = tmp_path / "vendor"
    tmp_path.mkdir()
    shutil.copytree(root / "src/hypersearch", tmp_path / "hypersearch")
    metadata = tmp_path / f"hypersearch-{declared}.dist-info"
    metadata.mkdir()
    (metadata / "METADATA").write_text(f"Metadata-Version: 2.1\nName: hypersearch\nVersion: {declared}\n")
    result = subprocess.run(
        [sys.executable, "-S", "-c", "import hypersearch; print(hypersearch.__version__)"],
        cwd=tmp_path, env={**os.environ, "PYTHONPATH": str(tmp_path)},
        capture_output=True, text=True, check=True, timeout=10,
    )
    assert result.stdout.strip() == declared
