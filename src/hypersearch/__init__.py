"""Resolve the release version from source or installed distribution metadata."""
import tomllib
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

_project = Path(__file__).resolve().parents[2] / "pyproject.toml"
_declaration = tomllib.loads(_project.read_text()).get("project", {}) if _project.is_file() else {}
if _declaration.get("name") == "hypersearch":
    __version__ = _declaration["version"]
else:
    try:
        __version__ = version("hypersearch")
    except PackageNotFoundError:
        __version__ = "0+unknown"
