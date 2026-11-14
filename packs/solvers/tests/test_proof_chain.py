#!/usr/bin/env python3
"""B-107: the multi-layer proof-replay / mesh-protocol chain harness.

A proof-replay gauntlet (the CSCTF "Velora" 31-layer shape) gates each single-vuln layer behind a
sequential proof protocol: solving layer k yields a proof token that must be replayed -- in order,
with every earlier token -- in an ordered X-Chain header before layer k+1 is reachable.
``solvers/web/proof_chain.py`` is a harness over the existing engines: it keeps the ordered proof
header, dispatches each recognizable layer to the matching engine (``recon_router`` /
``realtime_read`` / ``state_transaction``), and surfaces the rest for the model.

These tests drive the real harness -> real ``recon_router`` -> real ``WebClient`` chain against a
synthetic loopback gauntlet this file starts on 127.0.0.1 (no live service), plus unit coverage of
the ordered-header bookkeeping, the descriptor parser, the dispatch table, the header-injecting
client, and the offline WS-mesh helpers.
"""
from __future__ import annotations

import base64
import json
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tests"))

import event_pin  # noqa: E402  (tests/event_pin.py)
event_pin.pin(globals(), "huntress")  # web answers are proof_<32 hex> (events/huntress [proof])

import web_fakes  # noqa: E402  -- uuid_proof + loopback helpers

for _p in (REPO / "solvers" / "web", REPO / "solvers" / "toolkits", REPO):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import proof_chain as pc  # noqa: E402
import web as W  # noqa: E402


# ==================================================================================================
#  A synthetic proof-replay gauntlet: two SSRF->IDOR layers behind an ordered X-Chain header,
#  then a vault that releases the terminal payoff only to the full accumulated header.
# ==================================================================================================
PROOF1 = web_fakes.uuid_proof("B107-L1")
PROOF2 = web_fakes.uuid_proof("B107-L2")
VAULT = web_fakes.uuid_proof("B107-vault")
SSEPROOF = web_fakes.uuid_proof("B107-sse")   # the payoff a realtime_read (SSE) layer closes
# layer index -> (victim object id, the exact X-Chain header the layer's exploit GET must carry, proof)
LAYERS = {
    1: ("case-77", "", PROOF1),
    2: ("case-88", PROOF1, PROOF2),
}
HEADER = "X-Chain-Proof"


class GauntletShape:
    def __init__(self):
        self.lock = threading.Lock()
        self.exploit_hits = []   # (victim, chain_header_value) seen on a destination GET
        self.vault_hits = []     # chain_header_value seen on /vault
        self.sse_hits = []       # (rid, chain_header_value) seen on the SSE control read


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_a):
        pass

    def _reply(self, status, obj, *, content_type="application/json", raw=None):
        body = raw if raw is not None else json.dumps(obj, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_GET(self):  # noqa: N802
        shape = self.server.shape
        parts = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parts.query)
        chain = self.headers.get(HEADER, "")
        if parts.path == "/proxy":
            if "destination" not in query:
                # The route's no-argument control: never a proof, header-agnostic.
                self._reply(200, {"usage": "pass ?destination=<internal url>"})
                return
            destination = query["destination"][0]
            for _index, (victim, want_header, proof) in LAYERS.items():
                if victim in destination:
                    with shape.lock:
                        shape.exploit_hits.append((victim, chain))
                    if chain == want_header:
                        self._reply(200, {"ok": True, "effect": "non_owned_case_read", "proof": proof})
                    else:
                        self._reply(403, {"error": "chain_proof_required"})
                    return
            self._reply(200, {"ok": False})
            return
        if parts.path == "/vault":
            with shape.lock:
                shape.vault_hits.append(chain)
            if chain == f"{PROOF1},{PROOF2}":
                self._reply(200, {"status": "unsealed", "flag": VAULT})
            else:
                self._reply(403, {"error": "incomplete_chain"})
            return
        if parts.path == "/events":
            # A realtime_read (SSE) layer: one correlated event whose data carries the payoff.
            rid = query.get("rid", [""])[0]
            with shape.lock:
                shape.sse_hits.append((rid, chain))
            data = json.dumps({"rid": rid, "token": SSEPROOF})
            body = ("event: proof\r\ndata: " + data + "\r\n\r\n").encode()
            self._reply(200, None, content_type="text/event-stream", raw=body)
            return
        self._reply(404, {"error": "not_found"})


def _serve(shape):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.daemon_threads = True
    server.shape = shape
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address
    return server, f"http://{host}:{port}"


@pytest.fixture
def servers():
    started = []
    yield started
    for srv in started:
        srv.shutdown()
        srv.server_close()


def _ssrf_layer(index):
    victim, _header, _proof = LAYERS[index]
    return {
        "index": index, "class": "ssrf_idor",
        "clue": {
            "/api/clues": {"feature_route": "/proxy", "fetch_parameter": "destination",
                           "current_role": "alice"},
            "/api/topology": {"case_service": "http://internal.local/cases"},
            "/api/cases": [{"id": victim, "owner": "bob"}],
        },
    }


def _sse_layer(index):
    # A realtime_read SSE layer: the harness must dispatch it to realtime_read (a second engine
    # family) through the real _dispatch / _ChainClient, and the SSE read must close it.
    return {
        "index": index, "class": "sse_read",
        "clue": {"/api/clues": {"sse_read": {
            "route": "/events", "request_id_field": "rid", "request_id": "req-1",
            "reference_field": "ref", "reference": "r1", "response_id_field": "rid",
            "event": "proof", "max_events": 4}}},
    }


def _enc(obj):
    return {"status": 200, "body": json.dumps(obj).encode(),
            "response_headers": {"Content-Type": "application/json"}}


def _run_harness(url, protocol, *, max_requests=12):
    sink = {}
    client = W.WebClient(url, timeout=5.0)
    top = {"/api/clues": _enc({"proof_chain": protocol})}
    proof = pc.solve(
        {"url": url, "answer_id": "target"},
        {"client": client, "preloaded": top, "baseline_texts": [],
         "route_allowed": lambda path, **kw: True, "deadline": time.time() + 30,
         "max_requests": max_requests, "result_sink": sink})
    return proof, sink["target"]


# ==================================================================================================
#  End-to-end: the harness walks the gauntlet
# ==================================================================================================
def test_harness_walks_a_two_layer_ssrf_gauntlet_and_returns_the_vault_payoff(servers):
    shape = GauntletShape()
    srv, url = _serve(shape)
    servers.append(srv)
    protocol = {"header": HEADER, "join": ",", "final_route": "/vault",
                "layers": [_ssrf_layer(1), _ssrf_layer(2)]}
    proof, summary = _run_harness(url, protocol)
    assert proof == VAULT, summary
    assert summary["layers_solved"] == 2 and summary["layers_total"] == 2
    assert summary["success"] is True and not summary["surfaced"]
    assert summary["chain"]["value"] == f"{PROOF1},{PROOF2}"
    # The vault only released the payoff to the full accumulated header.
    assert shape.vault_hits == [f"{PROOF1},{PROOF2}"]


def test_the_accumulated_header_is_injected_on_the_deeper_layer(servers):
    # Layer 2's exploit GET must carry the layer-1 proof; without the injection it would 403 and the
    # harness would surface layer 2 instead of reaching the vault.  This pins the header injection.
    shape = GauntletShape()
    srv, url = _serve(shape)
    servers.append(srv)
    protocol = {"header": HEADER, "join": ",", "final_route": "/vault",
                "layers": [_ssrf_layer(1), _ssrf_layer(2)]}
    proof, summary = _run_harness(url, protocol)
    assert proof == VAULT
    seen = dict(shape.exploit_hits)  # victim -> last chain header seen
    assert seen["case-77"] == ""            # layer 1 carried no prior proof
    assert seen["case-88"] == PROOF1        # layer 2 carried the accumulated layer-1 proof


def test_an_unrecognized_layer_class_is_surfaced_and_halts_the_walk(servers):
    shape = GauntletShape()
    srv, url = _serve(shape)
    servers.append(srv)
    # Layer 2 is a class no existing engine executes (a bespoke binary-mesh step).
    unknown = {"index": 2, "class": "binary_mesh_step",
               "clue": {"/api/clues": {"note": "model must reason this"}},
               "note": "31-layer velora residual"}
    protocol = {"header": HEADER, "join": ",", "final_route": "/vault",
                "layers": [_ssrf_layer(1), unknown]}
    proof, summary = _run_harness(url, protocol)
    assert proof is None
    assert summary["layers_solved"] == 1          # layer 1 was closed and banked
    assert summary["success"] is False and summary["terminal"] is True
    assert len(summary["surfaced"]) == 1
    surfaced = summary["surfaced"][0]
    assert surfaced["index"] == 2 and surfaced["class"] == "binary_mesh_step"
    assert "unrecognized" in surfaced["reason"]
    assert surfaced["chain_depth"] == 1           # the layer-1 proof was already in the chain
    # The harness never touched the vault: the walk halted at the unknown layer.
    assert shape.vault_hits == []


def test_a_recognized_layer_the_engine_cannot_close_is_surfaced(servers):
    shape = GauntletShape()
    srv, url = _serve(shape)
    servers.append(srv)
    # A layer whose victim the gauntlet does not recognize: recon_router sends but gets no proof.
    dead = {"index": 2, "class": "ssrf_idor",
            "clue": {"/api/clues": {"feature_route": "/proxy", "fetch_parameter": "destination",
                                    "current_role": "alice"},
                     "/api/topology": {"case_service": "http://internal.local/cases"},
                     "/api/cases": [{"id": "case-does-not-exist", "owner": "bob"}]}}
    protocol = {"header": HEADER, "join": ",", "final_route": "/vault",
                "layers": [_ssrf_layer(1), dead]}
    proof, summary = _run_harness(url, protocol)
    assert proof is None
    assert summary["layers_solved"] == 1
    assert len(summary["surfaced"]) == 1
    surfaced = summary["surfaced"][0]
    assert surfaced["index"] == 2 and surfaced["engine"] == "recon_router"
    assert "did not close" in surfaced["reason"]
    assert shape.vault_hits == []


def test_a_second_engine_family_is_dispatched_end_to_end_through_the_chain(servers):
    # Findings 3/6: exercise _dispatch and the _ChainClient SSE wrapper for a non-recon_router
    # engine.  Layer 1 (ssrf_idor -> recon_router) banks a proof; layer 2 (sse_read -> realtime_read)
    # is dispatched through the real _dispatch and closes via the live loopback SSE read.
    shape = GauntletShape()
    srv, url = _serve(shape)
    servers.append(srv)
    protocol = {"header": HEADER, "join": ",",
                "layers": [_ssrf_layer(1), _sse_layer(2)]}
    proof, summary = _run_harness(url, protocol)
    assert proof == SSEPROOF, summary          # the deepest layer's proof is the chain's answer
    assert summary["layers_solved"] == 2 and not summary["surfaced"]
    # Layer 2 went to realtime_read, not recon_router -- a genuinely different engine family.
    engines = {entry["index"]: entry["engine"] for entry in summary["per_layer"]}
    assert engines == {1: "recon_router", 2: "realtime_read"}
    assert summary["per_layer"][1]["success"] is True
    # The budget counter is shared across both engines (two ssrf GETs + one SSE read).
    assert summary["requests"] == sum(e["requests"] for e in summary["per_layer"])
    assert shape.sse_hits and shape.sse_hits[0][0] == "req-1"
    # The layer-1 proof is banked in the chain even though the SSE stream itself is header-agnostic.
    assert summary["chain"]["value"].split(",")[0] == PROOF1


def test_the_final_replay_is_gated_at_the_exact_request_budget_boundary(servers):
    # Finding/survivor: the shared request budget gate is `counter >= max_requests`.  Mutating it to
    # `>` lets one request past the budget -- here the final-replay GET.  Drive the walk so it reaches
    # _finish with the counter exactly at the budget, and pin that the final replay does NOT fire.
    shape = GauntletShape()
    srv, url = _serve(shape)
    servers.append(srv)
    protocol = {"header": HEADER, "join": ",", "final_route": "/vault",
                "layers": [_ssrf_layer(1), _ssrf_layer(2)]}
    # Phase 1: learn the natural request count of the full walk (both layers + the one final replay).
    full_proof, full = _run_harness(url, protocol, max_requests=50)
    assert full_proof == VAULT
    total = full["requests"]                    # == layer1 + layer2 + 1 (the final replay)
    shape2 = GauntletShape()
    srv2, url2 = _serve(shape2)
    servers.append(srv2)
    # Phase 2: a budget of total-1 is spent exactly by solving both layers; the final replay would be
    # the (total)-th request, which the gate must refuse at counter == max_requests.
    proof, summary = _run_harness(url2, protocol, max_requests=total - 1)
    assert summary["layers_solved"] == 2        # both layers still closed within the budget
    assert proof is None                         # the final replay did not fire
    assert summary["success"] is False
    assert summary["stopped"] == "max_requests"
    assert summary["requests"] == total - 1      # not one request past the budget
    assert shape2.vault_hits == []               # the vault was never reached


def test_an_unavailable_recognized_engine_is_surfaced_with_a_named_reason(servers, monkeypatch):
    # Rule 6 / finding 5: when a recognized layer class's engine failed to import, the harness must
    # surface a named "engine unavailable" reason, not re-label it as an unrecognized class.
    monkeypatch.setattr(pc, "_realtime_read", None)
    shape = GauntletShape()
    srv, url = _serve(shape)
    servers.append(srv)
    protocol = {"header": HEADER, "join": ",",
                "layers": [_ssrf_layer(1), _sse_layer(2)]}
    proof, summary = _run_harness(url, protocol)
    assert proof is None
    assert summary["layers_solved"] == 1
    assert len(summary["surfaced"]) == 1
    surfaced = summary["surfaced"][0]
    assert surfaced["index"] == 2 and surfaced["class"] == "sse_read"
    assert "engine unavailable: realtime_read" in surfaced["reason"]
    assert "unrecognized" not in surfaced["reason"]


def test_an_unavailable_state_engine_is_surfaced_with_a_named_reason(servers, monkeypatch):
    # Round-2 finding: the Rule-6 named-reason surfacing must hold for the state family too, not only
    # realtime_read.  With state_transaction unimportable, a recognized state class (e.g.
    # single_use_redemption) must surface "engine unavailable: state_transaction", never be
    # misattributed to the model as an unrecognized class.
    monkeypatch.setattr(pc, "_state_transaction", None)
    shape = GauntletShape()
    srv, url = _serve(shape)
    servers.append(srv)
    protocol = {"header": HEADER, "join": ",",
                "layers": [{"index": 1, "class": "single_use_redemption", "clue": {}}]}
    proof, summary = _run_harness(url, protocol)
    assert proof is None
    assert summary["layers_solved"] == 0
    assert len(summary["surfaced"]) == 1
    surfaced = summary["surfaced"][0]
    assert surfaced["index"] == 1 and surfaced["class"] == "single_use_redemption"
    assert "engine unavailable: state_transaction" in surfaced["reason"]
    assert "unrecognized" not in surfaced["reason"]


def test_no_proof_chain_descriptor_declines_cleanly(servers):
    shape = GauntletShape()
    srv, url = _serve(shape)
    servers.append(srv)
    sink = {}
    client = W.WebClient(url, timeout=5.0)
    proof = pc.solve({"url": url, "answer_id": "target"},
                     {"client": client, "preloaded": {"/api/clues": _enc({"framework": "Koa"})},
                      "route_allowed": lambda p, **k: True, "deadline": time.time() + 10,
                      "max_requests": 4, "result_sink": sink})
    assert proof is None
    assert sink["target"]["stopped"] == "no proof-replay protocol"
    assert sink["target"]["layers_total"] == 0


def test_a_malformed_descriptor_is_a_named_terminal_decline(servers):
    shape = GauntletShape()
    srv, url = _serve(shape)
    servers.append(srv)
    sink = {}
    client = W.WebClient(url, timeout=5.0)
    bad = {"/api/clues": _enc({"proof_chain": {"header": "X Chain Proof", "layers": []}})}
    proof = pc.solve({"url": url, "answer_id": "target"},
                     {"client": client, "preloaded": bad, "route_allowed": lambda p, **k: True,
                      "deadline": time.time() + 10, "max_requests": 4, "result_sink": sink})
    assert proof is None
    assert sink["target"]["terminal"] is True
    assert "invalid proof-replay protocol" in sink["target"]["stopped"]


# ==================================================================================================
#  ProofChain: the ordered-proof-header bookkeeping
# ==================================================================================================
def test_proof_chain_renders_the_ordered_header_and_hides_it_until_the_first_proof():
    chain = pc.ProofChain(header="X-Chain-Proof", join=",")
    assert chain.headers() == {}            # nothing to replay yet
    chain.append(1, "proof_" + "a" * 32)
    chain.append(2, "proof_" + "b" * 32)
    assert chain.header_value() == ("proof_" + "a" * 32) + "," + ("proof_" + "b" * 32)
    assert chain.headers() == {"X-Chain-Proof": chain.header_value()}
    assert chain.tokens == ["proof_" + "a" * 32, "proof_" + "b" * 32]


def test_proof_chain_indexed_and_always_send_modes():
    chain = pc.ProofChain(header="X-Chain", join="|", indexed=True, always_send=True)
    assert chain.headers() == {"X-Chain": ""}   # always sent, even empty
    chain.append(3, "tokenA")
    chain.append(7, "tokenB")
    assert chain.header_value() == "3:tokenA|7:tokenB"


def test_proof_chain_enforces_strictly_increasing_layer_order():
    chain = pc.ProofChain()
    chain.append(2, "t2")
    with pytest.raises(pc.ProofChainError):
        chain.append(2, "t2b")              # not strictly after 2
    with pytest.raises(pc.ProofChainError):
        chain.append(1, "t1")               # out of order


def test_proof_chain_rejects_an_unsafe_or_separator_bearing_token():
    chain = pc.ProofChain(join=",")
    with pytest.raises(pc.ProofChainError):
        chain.append(1, "has space")        # not header-safe
    with pytest.raises(pc.ProofChainError):
        chain.append(1, "a\r\nX-Evil: 1")   # CRLF smuggling attempt
    with pytest.raises(pc.ProofChainError):
        chain.append(1, "a,b")              # contains the join separator -> unorderable


def test_proof_chain_rejects_an_oversize_header():
    chain = pc.ProofChain(join=",")
    big = "x" * 500
    for i in range(1, 40):
        try:
            chain.append(i, big)
        except pc.ProofChainError as exc:
            assert "exceeds" in str(exc)
            return
    pytest.fail("expected the ordered header to hit its byte ceiling")


def test_proof_chain_append_rolls_back_the_entry_on_an_oversize_header():
    # Survivor: append() records the entry, then raises if the rendered header is oversize; it must
    # roll the entry back (self._entries.pop()) so a rejected append leaves the chain untouched.
    # Without the rollback, depth and the header value would carry the oversize token after the raise.
    chain = pc.ProofChain(join=",")
    big = "x" * 500
    for i in range(1, 40):
        depth_before = chain.depth
        value_before = chain.header_value()
        try:
            chain.append(i, big)
        except pc.ProofChainError as exc:
            assert "exceeds" in str(exc)
            # The failed append left the chain exactly as it was before it.
            assert chain.depth == depth_before
            assert chain.header_value() == value_before
            assert len(chain.tokens) == depth_before
            return
    pytest.fail("expected the ordered header to hit its byte ceiling")


def test_proof_chain_rejects_a_non_token_header_name():
    with pytest.raises(pc.ProofChainError):
        pc.ProofChain(header="X Chain")      # space is not an HTTP token char


# ==================================================================================================
#  ChainProtocol: parsing the descriptor
# ==================================================================================================
def test_chain_protocol_parses_a_well_formed_descriptor():
    clues = {"proof_chain": {"header": "X-Chain-Proof", "join": ",", "final_route": "/vault",
                             "layers": [_ssrf_layer(1), _ssrf_layer(2)]}}
    proto = pc.ChainProtocol.from_clues(clues, "http://t.example")
    assert proto is not None
    assert [layer.index for layer in proto.layers] == [1, 2]
    assert proto.final_route == "/vault"
    assert proto.layers[0].cls == "ssrf_idor"
    # The layer clue is carried verbatim for the engine.
    assert proto.layers[0].preloaded["/api/clues"]["feature_route"] == "/proxy"


def test_chain_protocol_is_none_without_the_key():
    assert pc.ChainProtocol.from_clues({"framework": "Koa"}, "http://t.example") is None


@pytest.mark.parametrize("bad", [
    {"header": "Bad Header", "layers": [{"index": 1, "class": "ssrf_idor"}]},
    {"join": "::", "layers": [{"index": 1, "class": "ssrf_idor"}]},
    {"layers": []},
    {"layers": [{"index": 2, "class": "ssrf_idor"}, {"index": 1, "class": "ssrf_idor"}]},
    {"layers": [{"index": 1, "class": "Bad-Class"}]},
    {"layers": [{"index": 1, "class": "ssrf_idor", "extra": 1}]},
    {"final_route": "http://evil.example/x", "layers": [{"index": 1, "class": "ssrf_idor"}]},
])
def test_chain_protocol_rejects_malformed_descriptors(bad):
    with pytest.raises(pc.ProofChainError):
        pc.ChainProtocol.from_clues({"proof_chain": bad}, "http://t.example")


# ==================================================================================================
#  engine_for: the dispatch table
# ==================================================================================================
def test_engine_for_maps_only_executable_classes():
    import recon_router
    import realtime_read
    import state_transaction
    assert pc.engine_for("ssrf_idor") is recon_router        # an exact recon_router class
    assert pc.engine_for("signed_manifest") is recon_router
    assert pc.engine_for("websocket_stateful_read") is realtime_read
    assert pc.engine_for("single_use_redemption") is state_transaction
    # A ranked/cold recon_router class is NOT executable by it -> surfaced, not dispatched.
    assert pc.engine_for("sqli") is None
    assert pc.engine_for("graphql") is None
    assert pc.engine_for("totally_unknown") is None


# ==================================================================================================
#  _ChainClient: the header-injecting client wrapper
# ==================================================================================================
class _RecordingClient:
    base = "http://t.example"
    get_only = False

    def __init__(self):
        self.calls = []

    def request(self, method, path, data=None, headers=None, allow_redirects=True):
        self.calls.append(("request", method, path, dict(headers or {})))
        return {"status": 200, "body": b"{}"}

    def get(self, path, **kw):
        self.calls.append(("get", path, dict(kw.get("headers") or {})))
        return {"status": 200, "body": b"{}"}

    def post(self, path, data=None, **kw):
        self.calls.append(("post", path, dict(kw.get("headers") or {})))
        return {"status": 200, "body": b"{}"}


def test_chain_client_injects_the_current_header_and_counts_calls():
    chain = pc.ProofChain(header="X-Chain-Proof", join=",")
    counter = [0]
    inner = _RecordingClient()
    wrapped = pc._ChainClient(inner, chain, counter)
    # Before any proof: no header injected.
    wrapped.request("GET", "/a")
    assert inner.calls[-1] == ("request", "GET", "/a", {})
    chain.append(1, "proofA")
    wrapped.get("/b", allow_redirects=False)
    wrapped.request("POST", "/c", data="x", headers={"Content-Type": "application/json"})
    # The header reflects the live chain, and a caller header is preserved alongside it.
    assert inner.calls[1][2] == {"X-Chain-Proof": "proofA"}
    assert inner.calls[2][3] == {"Content-Type": "application/json", "X-Chain-Proof": "proofA"}
    assert counter[0] == 3


def test_chain_client_does_not_let_an_engine_override_the_chain_header():
    chain = pc.ProofChain(header="X-Chain-Proof", join=",")
    chain.append(1, "realA")
    inner = _RecordingClient()
    wrapped = pc._ChainClient(inner, chain, [0])
    wrapped.request("GET", "/a", headers={"X-Chain-Proof": "forged"})
    assert inner.calls[-1][3] == {"X-Chain-Proof": "realA"}   # chain wins the merge


def test_harness_returns_the_deepest_proof_when_no_final_route(servers):
    shape = GauntletShape()
    srv, url = _serve(shape)
    servers.append(srv)
    # No final_route: the deepest layer's proof is the chain's own answer.
    protocol = {"header": HEADER, "join": ",", "layers": [_ssrf_layer(1)]}
    proof, summary = _run_harness(url, protocol)
    assert proof == PROOF1
    assert summary["success"] is True and summary["layers_solved"] == 1


# ==================================================================================================
#  WS mesh helpers (offline leads)
# ==================================================================================================
def test_negotiate_subprotocol_agreed_none_and_invalid():
    assert pc.negotiate_subprotocol(["v1.mesh", "v2.mesh"], "v2.mesh")["status"] == "agreed"
    assert pc.negotiate_subprotocol(["v1.mesh"], None)["status"] == "none"
    bad = pc.negotiate_subprotocol(["v1.mesh"], "v9.other")
    assert bad["status"] == "invalid" and bad["agreed"] is None


def test_negotiate_subprotocol_rejects_non_token_or_duplicate_offers():
    with pytest.raises(pc.ProofChainError):
        pc.negotiate_subprotocol(["bad protocol"], "x")
    with pytest.raises(pc.ProofChainError):
        pc.negotiate_subprotocol(["v1", "v1"], "v1")


def _ws_binary_frame(payload):
    n = len(payload)
    if n < 126:
        return bytes((0x82, n)) + payload
    return bytes((0x82, 126)) + n.to_bytes(2, "big") + payload


def test_infer_binary_framing_recognizes_length_prefix_and_grpc_and_opaque():
    body = b'{"layer":4}'
    u32 = len(body).to_bytes(4, "big") + body
    capture = _ws_binary_frame(u32) + _ws_binary_frame(len(body).to_bytes(4, "big") + body)
    report = pc.infer_binary_framing(capture)
    assert report["framing"] == "length-prefixed-u32" and report["binary_frames"] == 2

    grpc = bytes([0]) + (5).to_bytes(4, "big") + b"hello"
    assert pc.infer_binary_framing(_ws_binary_frame(grpc))["framing"] == "grpc-web"

    opaque = pc.infer_binary_framing(_ws_binary_frame(b"no-length-prefix-here-xyz"))
    assert opaque["framing"] == "opaque"


def test_infer_binary_framing_accepts_base64_text():
    body = b"payload-bytes"
    frame = _ws_binary_frame(len(body).to_bytes(4, "big") + body)
    report = pc.infer_binary_framing(base64.b64encode(frame).decode())
    assert report["framing"] == "length-prefixed-u32"


def test_infer_binary_framing_reports_mixed_when_frames_disagree():
    body = b"abcdefgh"
    u32 = _ws_binary_frame(len(body).to_bytes(4, "big") + body)
    opaque = _ws_binary_frame(b"no-prefix-opaque-bytes")
    report = pc.infer_binary_framing(u32 + opaque)
    assert report["framing"] == "mixed"


def test_infer_binary_framing_does_not_mislabel_trailer_or_reserved_grpc_frames():
    # Round-2 finding: the gRPC-web guard requires frames[0].flags in (0, 1); a *complete* envelope
    # that happens to span the whole payload is only gRPC-web data when its flag byte is data (0x00)
    # or compressed-data (0x01).  A trailer frame (flags 0x80) or a reserved-flag frame (e.g. 0x02)
    # has the same 5-byte-header + length-spanning shape but is NOT gRPC-web application data, so the
    # recognizer must fall through to opaque, never emit a misleading "grpc-web" triage lead.
    trailer_data = b"grpc-status:0\r\n"
    trailer = bytes([0x80]) + len(trailer_data).to_bytes(4, "big") + trailer_data
    trailer_report = pc.infer_binary_framing(_ws_binary_frame(trailer))
    assert trailer_report["framing"] != "grpc-web"
    assert trailer_report["framing"] == "opaque"

    reserved_data = b"0123456789"
    reserved = bytes([0x02]) + len(reserved_data).to_bytes(4, "big") + reserved_data
    reserved_report = pc.infer_binary_framing(_ws_binary_frame(reserved))
    assert reserved_report["framing"] != "grpc-web"
    assert reserved_report["framing"] == "opaque"


# ==================================================================================================
#  Offline CLI
# ==================================================================================================
def test_cli_mesh_triage(tmp_path, capsys):
    body = b"grpc-body"
    frame = _ws_binary_frame(bytes([0]) + len(body).to_bytes(4, "big") + body)
    descriptor = {"offered": ["v1.mesh", "v2.mesh"], "selected": "v2.mesh",
                  "frames_b64": base64.b64encode(frame).decode()}
    path = tmp_path / "mesh.json"
    path.write_text(json.dumps(descriptor))
    rc = pc._main([str(path), "--json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    report = out["mesh.json"]
    assert report["subprotocol"]["status"] == "agreed"
    assert report["framing"]["framing"] == "grpc-web"
