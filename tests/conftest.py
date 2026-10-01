"""Small real executable fixtures for engine and HTTP coverage contracts."""

import pytest


@pytest.fixture
def controlled_ast(tmp_path):
    def create(behavior="positive"):
        executable = tmp_path / "controlled-ast"
        observed = tmp_path / "materialized.json"
        executable.write_text(
            "#!/usr/bin/env python3\n"
            "import json, pathlib, sys, time\n"
            "root = pathlib.Path(sys.argv[-1])\n"
            "files = sorted(p for p in root.rglob('*') if p.is_file())\n"
            f"pathlib.Path({str(observed)!r}).write_text(json.dumps([p.read_text() for p in files]))\n"
            f"behavior = {behavior!r}\n"
            "if behavior == 'timeout': time.sleep(5)\n"
            "if behavior == 'failed':\n"
            "    print('private diagnostic', file=sys.stderr)\n"
            "    sys.exit(2)\n"
            "if behavior == 'bad_json': print('{broken'); sys.exit(0)\n"
            "if behavior == 'bad_shape': print('[]'); sys.exit(0)\n"
            "if behavior == 'bad_line':\n"
            "    print(json.dumps({'file': str(files[0]), 'range': {'start': {'line': 'secret'}}}))\n"
            "    sys.exit(0)\n"
            "if behavior == 'no_match': sys.exit(0)\n"
            "if behavior == 'many':\n"
            "    for line in range(10000):\n"
            "        print(json.dumps({'file': str(files[0]), 'range': {'start': {'line': line}}}))\n"
            "    sys.exit(0)\n"
            "for path in files:\n"
            "    if behavior == 'selective' and 'alpha(beta(' not in path.read_text(): continue\n"
            "    print(json.dumps({'file': str(path.relative_to(root)), 'range': {'start': {'line': 0}}}, ensure_ascii=False))\n"
        )
        executable.chmod(0o755)
        return str(executable), observed
    return create
