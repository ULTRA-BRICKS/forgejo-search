"""Local HTTP contract acceptance, not proof of a live Forgejo viewer session.

Exercises SearchServer through real ForgejoAuth, indexing real fixture repositories.
The synthetic cookie is accepted only by this localhost fixture.
"""

import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

from test_server import _two_repo_root, get_json, running_server

from hypersearch.auth import ForgejoAuth
from hypersearch.db import open_database
from hypersearch.indexer import index_all


@contextmanager
def native_contract_server(tmp_path, monkeypatch, ast_grep="missing-ast-grep"):
    state = {"signed_in": True, "code": {"open"}, "revoke_on_head": False, "head_status": None}
    now = [100.0]
    monkeypatch.setattr("hypersearch.auth.time.monotonic", lambda: now[0])

    class NativeContract(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            url = urlsplit(self.path)
            assert url.path == "/forgejo/repo/search"
            if not state["signed_in"]:
                self.send_response(302)
                self.send_header("Location", "/forgejo/user/login")
                self.end_headers()
                return
            page = parse_qs(url.query)["page"][0]
            names = ["acme/open", "acme/locked"] if page == "1" else []
            body = json.dumps({"ok": True, "data": [{"repository": {"full_name": n}} for n in names]}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_HEAD(self):
            if state["revoke_on_head"]:
                state["signed_in"] = False
            repo = self.path.split("/")[-2]
            status = state["head_status"] or (200 if state["signed_in"] and repo in state["code"] else 404)
            self.send_response(status)
            self.end_headers()

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), NativeContract)
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    auth = ForgejoAuth(base=f"http://127.0.0.1:{upstream.server_port}/forgejo")
    db = open_database(tmp_path / "search.db")
    index_all(db, _two_repo_root(tmp_path))
    try:
        with running_server(db, auth, ast_grep=ast_grep) as base:
            def query(text, cookie="fixture=local-native-contract"):
                return get_json(base, "/api/hypersearch?" + urlencode({"q": text}), cookie)
            yield query, state, now
    finally:
        upstream.shutdown()
        upstream.server_close()
        thread.join(timeout=2)
        auth.close()


def test_visible_without_code_access_has_no_code_metadata_in_any_mode(tmp_path, monkeypatch):
    with native_contract_server(tmp_path, monkeypatch) as context:
        query = context[0]
        status, allowed = query("def:publicHelper")
        assert status == 200
        assert allowed["results"][0]["path"] == "src/public.js"
        for text in ["hidden.js", "hiddenHelper", "def:hiddenHelper", "ref:hiddenHelper", "text:hiddenHelper", "hiddenHelper()", "ast:hiddenHelper($A)", "repo:acme/locked hiddenHelper"]:
            status, denied = query(text)
            assert status == 200
            assert denied["results"] == []
        status, visible = query("locked")
        assert status == 200
        assert [(hit["repo"], hit["kind"]) for hit in visible["results"]] == [("acme/locked", "repository")]
        assert "revision" not in visible["results"][0]
        assert visible["results"][0]["path"] == ""
        assert visible["results"][0]["snippet"] == "acme/locked"


def test_bare_404_session_revocation_aborts_then_requires_login(tmp_path, monkeypatch):
    with native_contract_server(tmp_path, monkeypatch) as context:
        query, state = context[:2]
        assert query("repo:acme/open publicHelper")[0] == 200
        state["revoke_on_head"] = True
        status, payload = query("repo:acme/locked hiddenHelper")
        assert status == 503
        assert payload["error"] == "code_visibility_unavailable"
        assert "results" not in payload
        status, payload = query("repo:acme/open publicHelper")
        assert (status, payload) == (401, {"error": "authentication_required"})


def test_logout_and_code_revocation_stop_results_within_cache_bound(tmp_path, monkeypatch):
    with native_contract_server(tmp_path, monkeypatch) as (query, state, now):
        assert query("def:publicHelper")[1]["results"]
        state["code"] = set()
        assert query("def:publicHelper")[1]["results"]
        now[0] = 131
        assert query("def:publicHelper")[1]["results"] == []
        state["code"] = {"open"}
        now[0] = 162
        assert query("def:publicHelper")[1]["results"]
        state["signed_in"] = False
        assert query("def:publicHelper", cookie=None) == (401, {"error": "authentication_required"})
        now[0] = 193
        assert query("def:publicHelper") == (401, {"error": "authentication_required"})


def test_rejected_head_fails_closed_without_get_fallback(tmp_path, monkeypatch):
    with native_contract_server(tmp_path, monkeypatch) as context:
        query, state = context[:2]
        state["head_status"] = 405
        status, payload = query("publicHelper")
        assert status == 503
        assert payload["error"] == "code_visibility_unavailable"
        assert "results" not in payload


def test_enabled_ast_only_materializes_code_authorized_contents(tmp_path, monkeypatch, controlled_ast):
    executable, observed = controlled_ast()
    with native_contract_server(tmp_path, monkeypatch, executable) as (query, state, now):
        status, allowed = query("ast:publicHelper($A)")
        assert status == 200
        assert allowed["coverage"]["ast"] == {"status": "ran"}
        ast_hits = [hit for hit in allowed["results"] if hit["mode"] == "ast"]
        assert [(hit["repo"], hit["path"]) for hit in ast_hits] == [
            ("acme/open", "src/public.js"),
        ]
        assert json.loads(observed.read_text()) == [
            "export function publicHelper() {\n  return 1;\n}\n",
        ]
        status, denied = query("ast:hiddenHelper($A)")
        assert status == 200
        assert all(hit["repo"] == "acme/open" for hit in denied["results"])
        assert "hiddenHelper" not in observed.read_text()
        state["code"] = set()
        now[0] = 131
        previous = observed.read_text()
        status, denied = query("ast:publicHelper($A)")
        assert status == 200
        assert denied["results"] == []
        assert denied["coverage"]["ast"] == {"status": "no_candidates"}
        assert observed.read_text() == previous
