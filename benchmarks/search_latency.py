"""Synthetic latency benchmark for the authenticated search endpoint.

Starts a loopback Forgejo stand-in (visibility pages, identity/count requests and
per-repository code-reader probes with configurable latency and request counters),
a synthetic local index, and the real `SearchServer` + `ForgejoAuth` from whichever
`hypersearch` package is first on PYTHONPATH. No credentials, network access or
production data are used; cookies and repository names are fabricated here.

    PYTHONPATH=src python benchmarks/search_latency.py --out report.json
    PYTHONPATH=/path/to/baseline/src python benchmarks/search_latency.py --out before.json

Numbers are fixture measurements of this process, not production guarantees.
"""

from __future__ import annotations

import argparse
import http.client
import json
import sys
import tempfile
import threading
import time
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from fake_forgejo import FakeForgejo
from support import build_index

import hypersearch
from hypersearch.auth import ForgejoAuth
from hypersearch.server import SearchServer

COOKIE = "session=bench-alice"
KINDS = {"list": "list_pages", "scoped": "scoped_pages", "identity": "identity_requests", "head": "head_probes"}


def fetch(base, query, *, ndjson=False, cookie=COOKIE, timeout=120):
    path = "/api/hypersearch?q=" + urllib.parse.quote(query)
    headers = {"Cookie": cookie}
    if ndjson:
        headers["Accept"] = "application/x-ndjson"
    started = time.perf_counter()
    connection = http.client.HTTPConnection(base.removeprefix("http://"), timeout=timeout)
    connection.request("GET", path, headers=headers)
    response = connection.getresponse()
    headers_at = time.perf_counter() - started
    record_times: list[tuple[float, str]] = []
    pending = bytearray()
    body = bytearray()
    first_byte = None
    while True:
        chunk = response.read1(65536)
        if not chunk:
            break
        arrived = time.perf_counter() - started
        if first_byte is None:
            first_byte = arrived
        body.extend(chunk)
        if ndjson:
            # Record-level timing: a read may carry several records or half of one.
            pending.extend(chunk)
            while (newline := pending.find(b"\n")) >= 0:
                line = bytes(pending[:newline])
                del pending[: newline + 1]
                try:
                    kind = json.loads(line)["type"]
                except (ValueError, KeyError, TypeError):
                    kind = "invalid"
                record_times.append((round(arrived, 3), kind))
    wall = time.perf_counter() - started
    connection.close()
    out = {
        "status": response.status,
        "content_type": response.getheader("Content-Type"),
        "headers_s": round(headers_at, 3),
        "first_byte_s": None if first_byte is None else round(first_byte, 3),
        "wall_s": round(wall, 3),
        "bytes": len(body),
    }
    if ndjson and response.getheader("Content-Type", "").startswith("application/x-ndjson"):
        lines = [json.loads(line) for line in bytes(body).decode().splitlines() if line]
        out["record_types"] = [line["type"] for line in lines]
        out["heartbeats"] = out["record_types"].count("heartbeat")
        beats = [t for t, kind in record_times if kind == "heartbeat"]
        out["heartbeat_times_s"] = beats
        out["max_heartbeat_gap_s"] = round(
            max((b - a for a, b in zip([0.0, *beats], beats, strict=False)), default=0.0), 3
        )
        for line in lines:
            if line["type"] == "result":
                out["results"] = len(line["data"]["results"])
                out["total_ms"] = line["data"].get("total_ms")
            if line["type"] == "error":
                out["error"] = {"code": line["code"], "status": line["status"]}
    else:
        try:
            payload = json.loads(bytes(body))
        except ValueError:
            payload = {}
        out["results"] = len(payload.get("results", []))
        out["total_ms"] = payload.get("total_ms")
        if "error" in payload:
            out["error"] = payload["error"]
    return out


class Rig:
    def __init__(self, tmp, *, visible, indexed, readable, page_delay, count_delay=0.05,
                 head_delay=0.02, auth_kwargs=None, server_kwargs=None, total_header=True):
        self.upstream = FakeForgejo(
            visible, readable, cookies=(COOKIE,), page_delay=page_delay,
            count_delay=count_delay, head_delay=head_delay, total_header=total_header,
        )
        self.database = build_index(Path(tmp) / "search.db", indexed)
        self.auth = ForgejoAuth(self.upstream.base, **(auth_kwargs or {}))
        self.server = SearchServer(("127.0.0.1", 0), self.database, self.auth,
                                   **(server_kwargs or {}))
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def measure(self, label, query, **kwargs):
        before = self.upstream.counts()
        result = fetch(self.base, query, **kwargs)
        after = self.upstream.counts()
        result["scenario"] = label
        result["query"] = query
        result["upstream"] = {
            name: after.get(kind, 0) - before.get(kind, 0) for kind, name in KINDS.items()
        }
        return result

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.auth.close()
        self.upstream.close()


def names(count):
    return [f"acme/r{index:04d}" for index in range(count)]


def run_fixture(report, label, *, count, page_delay, denied=0.0, indexed=None, ndjson=False,
                head_delay=0.02, auth_kwargs=None, server_kwargs=None, phases=None):
    visible = names(count)
    indexed_names = visible if indexed is None else visible[:indexed]
    step = int(1 / denied) if denied else 0
    readable = {n for i, n in enumerate(indexed_names) if not step or i % step != 0}
    workload = {
        "visible": count, "indexed": len(indexed_names), "denied_indexed": len(indexed_names) - len(readable),
        "page_delay_s": page_delay, "head_delay_s": head_delay, "ndjson": ndjson,
    }
    for phase, queries in (
        ("unscoped", ["sharedtoken", "sharedtoken"]),
        ("scoped", ["repo:acme/r0000 sharedtoken", "repo:acme/r0000 sharedtoken"]),
        ("empty", ["", ""]),
    ):
        if phases is not None and phase not in phases:
            continue
        with tempfile.TemporaryDirectory(prefix="bench-") as tmp:
            rig = Rig(tmp, visible=visible, indexed=indexed_names, readable=readable,
                      page_delay=page_delay, head_delay=head_delay,
                      auth_kwargs=auth_kwargs, server_kwargs=server_kwargs)
            try:
                for state, query in zip(("cold", "warm"), queries, strict=True):
                    row = rig.measure(f"{label}/{phase}/{state}", query, ndjson=ndjson)
                    row["workload"] = workload
                    report["scenarios"].append(row)
            finally:
                rig.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--only", default="", help="comma list: sizes,denied,real16,long")
    parser.add_argument("--ndjson", action="store_true", help="also request application/x-ndjson")
    args = parser.parse_args()
    only = set(filter(None, args.only.split(",")))
    report = {
        "package": hypersearch.__file__,
        "note": "synthetic loopback fixture; not production measurements",
        "scenarios": [],
    }

    def want(name):
        return not only or name in only

    if want("sizes"):
        for count in (0, 26, 600, 1000):
            run_fixture(report, f"repos{count}", count=count, page_delay=0.05, indexed=count,
                        ndjson=args.ndjson)
    if want("denied"):
        run_fixture(report, "denied-heavy600", count=600, page_delay=0.05, denied=0.5, indexed=600,
                    ndjson=args.ndjson)
    if want("real16"):
        # 750 visible repositories -> 15 full pages + 1 terminating empty page = 16 requests,
        # one real second each (same shape as the recorded gap measurement).
        run_fixture(report, "real16x1s", count=750, page_delay=1.0, indexed=26, head_delay=0.005,
                    ndjson=args.ndjson)
    if want("long"):
        # More than 15 seconds end to end, against the shipped 15 second proxy idle timeout.
        # Settings are explicit benchmark parameters, not a production fault injection.
        from hypersearch.server import ServerSettings

        run_fixture(report, "long-gt15s", count=750, page_delay=6.0, indexed=26, head_delay=0.005,
                    ndjson=True, phases=("unscoped",),
                    auth_kwargs={"request_timeout": 10.0, "code_probe_budget": 30.0},
                    server_kwargs={"settings": ServerSettings(request_deadline=60.0)})
    Path(args.out).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"written": args.out, "scenarios": len(report["scenarios"])}))


if __name__ == "__main__":
    main()
