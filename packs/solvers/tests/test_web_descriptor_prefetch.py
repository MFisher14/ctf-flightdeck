#!/usr/bin/env python3
"""Backlog row 559: the conventional descriptor GETs of an unsignalled hunt go out as ONE parallel wave.

Day 27: on every web base proof_hunt sent /sitemap.xml, /openapi.yaml, /openapi.yml, /swagger.json,
/swagger.yaml and /swagger.yml one after another (+1.6 to +4.4 s of a hunt, all 404). They are now sent
concurrently at the start of the same endpoint phase. Checked here on a no-network fake with a fixed
latency per request:

  A  all six are still requested (none dropped), in flight together (their starts within one latency),
     and nothing new is sent in their place (/v3/api-docs, /api-docs stay unsent: the inventory charges
     each prefetched page to its discovery budget where it used to send it);
  B  the hunt's wall time is about one round trip for the six, not six;
  C  a descriptor-only app (the spec at /swagger.yaml, nothing else) is still found and its contract GET read;
  D  a target whose fast path answers sends none of them (the D1-D20 request counts are unchanged);
  E  endpoint_inventory's charge: a prefetched page is charged once, only while budget is left, and is
     never reported as a request.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path[:0] = [str(REPO / "solvers" / "web"), str(REPO / "solvers" / "toolkits")]

import endpoint_inventory as EI  # noqa: E402
import proof_hunt as PH  # noqa: E402

BASE = "http://fake.local/"
PROOF = "proof_0123456789abcdef0123456789abcdef"
LATENCY = 0.12
SIX = ("/sitemap.xml", "/openapi.yaml", "/openapi.yml", "/swagger.json", "/swagger.yaml", "/swagger.yml")


class Client:
    base = BASE
    timeout = 8.0

    def __init__(self, routes, latency=LATENCY):
        self.routes = routes
        self.latency = latency
        self.calls = []
        self.lock = threading.Lock()

    def request(self, method, path, data=None, headers=None, allow_redirects=True):
        with self.lock:
            self.calls.append((time.time(), method, path))
        time.sleep(self.latency)
        status, body, ctype = self.routes.get(path, (404, b'{"error":"not_found"}', "application/json"))
        headers = {"Content-Type": ctype}
        return {"status": status, "body": body, "response_headers": headers,
                "response_header_pairs": list(headers.items()), "final_url": BASE.rstrip("/") + path}


def hunt(routes, budget=400):
    client = Client(routes)
    h = PH._Hunter(BASE, deadline=time.time() + 60, max_requests=budget, stop=threading.Event(),
                   prompt="Recover the proof from the target.")
    h.client = client
    h.forge_target = {"answer_id": "proof-1", "url": BASE, "index": 1, "question": "Recover the proof."}
    h.forge_ctx = {}
    t0 = time.time()
    ans = h.run()
    return ans, client, h, time.time() - t0


HTML = b"<!doctype html><html><head><title>Case Board</title></head><body><p>Nothing here.</p></body></html>"
CLUES = json.dumps({"framework": "Koa", "feature_route": "/dispatch-53decf", "current_role": "analyst",
                    "stream_reference": 13777}).encode()


def day27_like():
    return {
        "/": (200, HTML, "text/html"),
        "/robots.txt": (200, b"User-agent: *\nAllow: /\n", "text/plain"),
        "/api/clues": (200, CLUES, "application/json"),
        "/dispatch-53decf": (426, b'{"error":"websocket_upgrade_required"}', "application/json"),
    }


def t_a_same_six_in_one_wave():
    ans, client, h, _ = hunt(day27_like())
    assert ans is None, ans
    paths = [p for _t, _m, p in client.calls]
    for p in SIX:
        assert paths.count(p) == 1, (p, paths)
    for p in ("/v3/api-docs", "/api-docs"):
        assert p not in paths, (p, "a new request in place of a prefetched one", paths)
    starts = [t for t, _m, p in client.calls if p in SIX]
    spread = max(starts) - min(starts)
    assert spread < LATENCY * 0.8, ("the six were not in flight together", spread)
    inv = h.endpoint_inventory or {}
    assert inv.get("requests") == 0 and inv.get("stopped") == "max_requests", inv
    assert sorted(h.prefetched_descriptors) == sorted(SIX), h.prefetched_descriptors
    return "A six descriptor GETs once each, spread %.3f s, no /v3/api-docs or /api-docs" % spread


def t_b_one_round_trip():
    _ans, client, _h, _wall = hunt(day27_like())
    starts = sorted(t for t, _m, p in client.calls if p in SIX)
    # sequential would be >= 6 latencies from the first start to the last answer
    span = starts[-1] + LATENCY - starts[0]
    assert span < 2 * LATENCY, span
    return "B the six took %.3f s on the fake (sequential: about %.2f s)" % (span, 6 * LATENCY)


def t_c_descriptor_only_app():
    spec = ("openapi: 3.0.3\ninfo: {title: Case API, version: '1'}\npaths:\n"
            "  /api/internal/objective:\n    get:\n      responses:\n"
            "        '200':\n          description: ok\n          content:\n"
            "            application/json:\n              schema:\n                type: object\n"
            "                properties:\n                  proof: {type: string}\n").encode()
    routes = {
        "/": (200, HTML, "text/html"),
        "/robots.txt": (404, b"", "text/plain"),
        "/swagger.yaml": (200, spec, "application/yaml"),
        "/api/internal/objective": (200, json.dumps({"ok": True, "proof": PROOF}).encode(), "application/json"),
    }
    ans, client, _h, _ = hunt(routes)
    paths = [p for _t, _m, p in client.calls]
    assert "/swagger.yaml" in paths and "/api/internal/objective" in paths, paths
    assert ans == PROOF, (ans, paths)
    return "C a spec at /swagger.yaml only: found, its route read, proof answered"


def t_d_fast_path_sends_none():
    listing = b"<html><a href='note.json.bak'>note.json.bak</a></html>"
    routes = {
        "/": (200, HTML, "text/html"),
        "/robots.txt": (200, b"User-agent: *\nDisallow: /backup/\n", "text/plain"),
        "/backup/": (200, listing, "text/html"),
        "/backup/note.json.bak": (200, json.dumps({"proof": PROOF}).encode(), "application/json"),
    }
    ans, client, h, _ = hunt(routes)
    paths = [p for _t, _m, p in client.calls]
    assert ans == PROOF, (ans, paths)
    assert not any(p in SIX for p in paths), paths
    assert not h.prefetched_descriptors, h.prefetched_descriptors
    return "D the backup fast path: proof in %d GETs, no descriptor GET" % len(paths)


def t_e_inventory_charge():
    pages = {p: {"status": 404, "body": b"", "response_headers": {}} for p in SIX}
    g = EI._Getter(BASE, {"max_requests": 3, "client": Client({}), "preloaded": pages, "prefetched": list(SIX)})
    for p in SIX:
        g.get(p)
    assert g.requests == 0 and g.charged == 3 and not g.may_send(), (g.requests, g.charged)
    g2 = EI._Getter(BASE, {"max_requests": 6, "client": Client({}), "preloaded": pages, "prefetched": ["/x"]})
    g2.get("/sitemap.xml")
    assert g2.charged == 0, "a preloaded page that was not prefetched by the caller stays free"
    g2.get("/sitemap.xml")
    g3 = EI._Getter(BASE, {"max_requests": 6, "client": Client({}), "preloaded": pages, "prefetched": ["/sitemap.xml"]})
    g3.get("/sitemap.xml")
    g3.get("/sitemap.xml")
    assert g3.charged == 1, g3.charged
    return "E prefetched pages charged once each, only within budget, never counted as requests"


def main():
    failed = 0
    for name, fn in sorted((k, v) for k, v in globals().items() if k.startswith("t_") and callable(v)):
        try:
            print("ok  ", fn())
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print("FAIL", name, type(exc).__name__, exc)
    print("RESULT", "PASS" if not failed else "FAIL (%d failed)" % failed)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
