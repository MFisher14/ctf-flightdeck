#!/usr/bin/env python3
"""B-234: the clue-driven SSRF->IDOR chain in proof_hunt (day-27 "Internal Affairs").

Every target is a local loopback fake started on 127.0.0.1; the public ``proof_hunt.solve_targets`` entry
point and the scope-locked ``WebClient`` own every request. The fake models the SSRF server-side: its public
feature route decodes the ``target=`` query parameter and answers as the loopback case service would, so the
record of an owner != ``current_role`` (the IDOR) carries the proof and the caller's own record does not.
Nothing is ever fetched from the "internal" URL by the client itself.

What each test pins:
  - the shipped class recovers the proof, GET-only, through the GET query-param SSRF sink;
  - it nests the VICTIM id (owner != current_role), never the caller's own id;
  - it reads the sink parameter name from the feature route's own no-arg error (default + a rotated name);
  - it reads the internal base and the case list from the clue-named routes (rotated spellings), and fires
    on the conventional /api/topology + /api/cases when the clue omits the route names;
  - it stays closed when there is no cross-owner id, when current_role is absent, and when no topology/case
    signal is present at all.
"""

from __future__ import annotations

import event_pin  # noqa: E402  (tests/event_pin.py)
event_pin.pin(globals(), "huntress")  # Huntress web tests: proof_<32 hex> payoffs (events/huntress [proof])

import json
import sys
import threading
import time
import unittest
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO / "solvers" / "web"), str(REPO / "solvers" / "toolkits")]
sys.dont_write_bytecode = True

import proof_hunt  # noqa: E402


def _proof():
    return "proof_" + uuid.uuid4().hex


class Shape:
    """One Internal-Affairs variant. All route hexes, ids, owners and the SSRF slot name are per-variant."""

    def __init__(self, *, feature="/submit-90943c", status_path="/status-8f4309", sink_param="target",
                 role="analyst", name_routes=True, cases=None, service_port=None, proof=None,
                 topo_service_key="case_service"):
        self.feature = feature
        self.status_path = status_path
        self.sink_param = sink_param
        self.role = role
        self.name_routes = name_routes          # whether /api/clues names topology/case routes or omits them
        # The topology feed's key that carries the internal case-service URL. The default ``case_service`` is a
        # name the pre-existing recon-router SSRF->IDOR executor also recognizes, so on that shape EITHER engine
        # could bank the proof. An isolated variant (``topo_service_key="upstream_origin"``) is a name only the
        # B-234 chain's generic internal-URL reader accepts, so the recon-router executor declines and ONLY the
        # new chain can reach the service -- that isolates the chain for mutation testing.
        self.topo_service_key = topo_service_key
        self.cases = cases if cases is not None else [
            {"id": 4334, "owner": "analyst"},    # the caller's own record (no proof)
            {"id": 11581, "owner": "executive"}, # the victim (owner != current_role) -> proof
        ]
        self.service_port = service_port         # set to the live port once the server is bound
        self.proof = proof or _proof()
        self.hits = []
        self.lock = threading.Lock()

    def record(self, method, path, headers, body=b""):
        with self.lock:
            self.hits.append((method, path, {str(k).lower(): str(v) for k, v in headers.items()}, bytes(body)))

    @property
    def case_service(self):
        return f"http://127.0.0.1:{self.service_port}{self.status_path}"

    def victim_ids(self):
        return [str(c["id"]) for c in self.cases if str(c["owner"]).casefold() != self.role.casefold()]

    def own_ids(self):
        return [str(c["id"]) for c in self.cases if str(c["owner"]).casefold() == self.role.casefold()]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    @property
    def shape(self):
        return self.server.shape

    def _reply(self, status, value, headers=None):
        body = value if isinstance(value, bytes) else json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        for key, val in (headers or {}).items():
            self.send_header(key, val)
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        self.shape.record("POST", self.path, self.headers, self.rfile.read(length) if length else b"")
        self._reply(405, {"error": "post_not_supported"})

    def do_GET(self):  # noqa: N802
        self.shape.record("GET", self.path, self.headers)
        shape = self.shape
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        if path == "/":
            self._reply(200, {"service": "internal-affairs"})
            return
        if path in ("/robots.txt", "/openapi.json"):
            self._reply(404, {"error": "not_found"})
            return
        if path == "/api/clues":
            clues = {"framework": "Ktor", "feature_route": shape.feature, "current_role": shape.role,
                     "service_pattern": "server-side case fetch"}
            if shape.name_routes:
                clues["topology_route"] = "/api/topology"
                clues["case_directory_route"] = "/api/cases"
            self._reply(200, clues)
            return
        if path == "/api/topology":
            self._reply(200, {shape.topo_service_key: shape.case_service, "network": "loopback"})
            return
        if path == "/api/cases":
            self._reply(200, {"cases": shape.cases})
            return
        if path == shape.feature:
            query = urllib.parse.parse_qs(parsed.query)
            target = (query.get(shape.sink_param) or [None])[0]
            if not target:
                # name the SSRF slot the way the real target does, without matching _URL_REQUIRED
                self._reply(400, {"error": "target_required", "query_parameter": shape.sink_param})
                return
            self._serve_as_internal_service(target)
            return
        if path == shape.status_path:
            # A direct (non-SSRF) hit on the internal path: the client is scope-locked and never does this,
            # but answer as the loopback service so the test can assert the client never reaches it directly.
            self._serve_internal(urllib.parse.parse_qs(parsed.query))
            return
        self._reply(404, {"error": "not_found"})

    def _serve_as_internal_service(self, target):
        """Model the server-side fetch: decode the SSRF target and answer as the loopback case service."""
        inner = urllib.parse.urlsplit(target)
        if inner.scheme not in ("http", "https") or inner.hostname not in ("127.0.0.1", "localhost"):
            self._reply(200, {"ok": False, "effect": "outbound_blocked"})
            return
        if (inner.port or 80) != self.shape.service_port or inner.path != self.shape.status_path:
            self._reply(404, {"error": "not_found"})
            return
        self._serve_internal(urllib.parse.parse_qs(inner.query))

    def _serve_internal(self, inner_query):
        """The loopback case service: ``?id=<case>`` only; own case -> record (no proof), victim -> proof."""
        cid = (inner_query.get("id") or [None])[0]
        if cid is None:
            self._reply(404, {"error": "not_found"})     # path form and ?case= are the wrong shape
            return
        for case in self.shape.cases:
            if str(case["id"]) == str(cid):
                if str(case["owner"]).casefold() != self.shape.role.casefold():
                    self._reply(200, {"ok": True, "effect": "ssrf_then_object_authorization",
                                      "evidence": self.shape.proof})
                else:
                    self._reply(200, {"ok": True, "case": case})   # the caller's own record: no proof
                return
        self._reply(404, {"error": "not_found"})


def serve(shape):
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.shape = shape
    shape.service_port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    return server, f"http://{host}:{port}"


def hunt(items, seconds=15, max_requests=80):
    return proof_hunt.solve_targets(items, {"deadline": time.time() + seconds,
                                            "max_requests": max_requests,
                                            "prompt": ("Two service boundaries, one hallway. Use the public "
                                                       "fetch to knock on the internal door, then borrow "
                                                       "somebody else's records on the way out."),
                                            "challenge": "day27-internal-affairs"})


class SSRFIdorChain(unittest.TestCase):
    def tearDown(self):
        for server in getattr(self, "servers", []):
            server.shutdown()
            server.server_close()

    def _run(self, shape, **kw):
        server, url = serve(shape)
        self.servers = getattr(self, "servers", []) + [server]
        result = hunt([{"answer_id": "proof-1", "url": url,
                        "question": "Recover the proof from Target 1."}], **kw)
        return result, shape

    def test_recovers_the_cross_owner_proof_get_only(self):
        result, shape = self._run(Shape())
        self.assertEqual(result["proof-1"], shape.proof)
        # GET-only: not one POST was sent to the target.
        self.assertFalse([hit for hit in shape.hits if hit[0] == "POST"], shape.hits)

    def test_nests_the_victim_id_never_the_callers_own_id(self):
        result, shape = self._run(Shape())
        self.assertEqual(result["proof-1"], shape.proof)
        sink = []
        for method, path, _h, _b in shape.hits:
            if path.split("?", 1)[0] != shape.feature:
                continue
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
            val = (q.get(shape.sink_param) or [""])[0]
            if val:
                sink.append(val)
        self.assertTrue(sink, shape.hits)
        victim, own = shape.victim_ids()[0], shape.own_ids()[0]
        # Every SSRF target the chain sent carries a victim id; the caller's own id is never nested.
        self.assertTrue(any(victim in val for val in sink), sink)
        self.assertFalse(any(own in val for val in sink), (own, sink))
        # The client never hits the internal case-service path directly (only via the feature route's target).
        self.assertFalse([hit for hit in shape.hits if hit[1].split("?", 1)[0] == shape.status_path], shape.hits)

    def test_rotated_sink_parameter_name_is_read_from_the_error(self):
        # A variant whose SSRF slot is not the default ``target``; the no-arg 400 names it.
        result, shape = self._run(Shape(feature="/process-5880da", status_path="/status-aa11bb",
                                        sink_param="resource", role="viewer",
                                        cases=[{"id": 7, "owner": "viewer"},
                                               {"id": 42, "owner": "admin"}]))
        self.assertEqual(result["proof-1"], shape.proof)
        self.assertTrue(any(hit[1].startswith("/process-5880da?resource=") for hit in shape.hits), shape.hits)

    def test_fires_on_conventional_routes_when_clue_omits_the_names(self):
        # /api/clues names neither topology_route nor case_directory_route; only service_pattern signals it.
        result, shape = self._run(Shape(name_routes=False))
        self.assertEqual(result["proof-1"], shape.proof)
        self.assertTrue(any(hit[1] == "/api/topology" for hit in shape.hits), shape.hits)
        self.assertTrue(any(hit[1] == "/api/cases" for hit in shape.hits), shape.hits)

    def test_no_cross_owner_id_recovers_nothing(self):
        # Every case is owned by the caller: there is no victim id, so the chain banks nothing.
        result, shape = self._run(Shape(cases=[{"id": 4334, "owner": "analyst"},
                                               {"id": 9001, "owner": "analyst"}]), max_requests=40)
        self.assertIsNone(result["proof-1"])

    def test_chain_is_closed_when_current_role_is_absent(self):
        # Without an identity the owner-mismatch cannot be chosen; the chain must not guess a victim.
        class RolelessHandler(Handler):
            def do_GET(self):  # noqa: N802
                if urllib.parse.urlsplit(self.path).path == "/api/clues":
                    self.shape.record("GET", self.path, self.headers)
                    self._reply(200, {"framework": "Ktor", "feature_route": self.shape.feature,
                                      "service_pattern": "server-side case fetch",
                                      "topology_route": "/api/topology",
                                      "case_directory_route": "/api/cases"})
                    return
                super().do_GET()

        shape = Shape()
        server = ThreadingHTTPServer(("127.0.0.1", 0), RolelessHandler)
        server.shape = shape
        shape.service_port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.servers = getattr(self, "servers", []) + [server]
        url = f"http://127.0.0.1:{server.server_address[1]}"
        result = hunt([{"answer_id": "proof-1", "url": url,
                        "question": "Recover the proof from Target 1."}], max_requests=40)
        self.assertIsNone(result["proof-1"])
        # The chain never put a loopback case-service URL into the sink slot.
        self.assertFalse(any(shape.status_path in urllib.parse.unquote(hit[1])
                             and hit[1].split("?", 1)[0] == shape.feature for hit in shape.hits), shape.hits)

    def test_not_indicated_without_a_topology_or_case_signal(self):
        # A plain feature-route-only clue: the day-27 chain must not fire (unit gate).
        hunter = proof_hunt._Hunter("http://127.0.0.1:1/", max_requests=0)
        self.assertFalse(hunter._ssrf_idor_indicated({"feature_route": "/submit-x"}))
        self.assertTrue(hunter._ssrf_idor_indicated({"feature_route": "/submit-x",
                                                     "topology_route": "/api/topology",
                                                     "case_directory_route": "/api/cases"}))
        self.assertFalse(hunter._ssrf_idor_chain("/submit-x",
                                                 {"feature_route": "/submit-x"}))  # no current_role

    # -- isolation: a topology feed whose service key only the B-234 chain reads ---------------------------
    # On the default ``case_service`` shape the pre-existing recon-router SSRF->IDOR executor already banks the
    # day-27 proof, so a mutation to the new chain's victim selection, sink-param read or send loop survives
    # (the chain is never the thing that solves). These shapes name the internal case service under
    # ``upstream_origin`` -- a key the recon-router executor does not accept but the B-234 chain's generic
    # internal-URL reader does -- so the recon-router executor declines and ONLY ``_ssrf_idor_chain`` can reach
    # the service. Each assertion below then pins a distinct piece of the new chain's own logic.

    def test_isolated_chain_recovers_proof_and_nests_only_the_victim_id(self):
        # Router declines (service under ``upstream_origin``): the proof can only come from the new chain, and
        # the chain must nest the VICTIM id (owner != current_role), never the caller's own id. Kills the
        # gutted-send-loop mutation (no send -> no proof) and the inverted owner!=role selection (own id -> no
        # proof) at the integration level.
        result, shape = self._run(Shape(topo_service_key="upstream_origin"))
        self.assertEqual(result["proof-1"], shape.proof)
        sink = []
        for method, path, _h, _b in shape.hits:
            if path.split("?", 1)[0] != shape.feature:
                continue
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
            val = (q.get(shape.sink_param) or [""])[0]
            if val:
                sink.append(val)
        self.assertTrue(sink, shape.hits)
        victim, own = shape.victim_ids()[0], shape.own_ids()[0]
        self.assertTrue(any(victim in val for val in sink), sink)
        self.assertFalse(any(own in val for val in sink), (own, sink))

    def test_isolated_chain_reads_rotated_sink_param_from_the_error(self):
        # Router declines AND the SSRF slot is not the default ``target``: the chain must read the slot name
        # (``resource``) from the feature route's own no-arg 400. Kills the "_ssrf_sink_param always returns
        # 'target'" mutation at the integration level -- a hardcoded ``target`` never reaches this service.
        result, shape = self._run(Shape(feature="/process-5880da", status_path="/status-aa11bb",
                                        sink_param="resource", role="viewer", topo_service_key="upstream_origin",
                                        cases=[{"id": 7, "owner": "viewer"},
                                               {"id": 42, "owner": "admin"}]))
        self.assertEqual(result["proof-1"], shape.proof)
        self.assertTrue(any(hit[1].startswith("/process-5880da?resource=") for hit in shape.hits), shape.hits)
        # The hardcoded default slot was never put on the wire as the SSRF carrier.
        self.assertFalse(any(hit[1].startswith("/process-5880da?target=") for hit in shape.hits), shape.hits)

    def test_isolated_chain_banks_nothing_without_a_cross_owner_id(self):
        # Router declines and every case is the caller's own: the chain has no victim to nest, so it must bank
        # nothing. With the inverted-selection mutation the chain would instead nest the caller's own ids and
        # the service would return records with no proof -- still None here, but paired with the recovery test
        # above (victim present -> proof) this brackets the owner!=role branch on the isolated path.
        result, shape = self._run(Shape(topo_service_key="upstream_origin",
                                        cases=[{"id": 4334, "owner": "analyst"},
                                               {"id": 9001, "owner": "analyst"}]), max_requests=40)
        self.assertIsNone(result["proof-1"])

    def test_isolated_chain_returns_true_once_it_banks_the_proof(self):
        # The chain's return value is the dispatch short-circuit signal: _clues_dispatch stops (and the hunter
        # skips the later waves on an already-solved target) only because _ssrf_idor_chain returns True on its
        # done() branch. The proof is banked as a fetch(payoff=True) SIDE EFFECT, so merely recovering it does
        # NOT exercise the return value -- a `return True`->`return False` mutation on the done() branch leaves
        # every recovery test green. Capture the return value directly: the ONLY `return True` in the method is
        # the done() branch, so a recorded True can come from nowhere else, and under the mutation no call ever
        # returns True. (Router declines this upstream_origin shape, so the chain is the thing that solves.)
        returns = []
        original = proof_hunt._Hunter._ssrf_idor_chain

        def _recording(self, feature, clues):
            rv = original(self, feature, clues)
            returns.append(rv)
            return rv

        proof_hunt._Hunter._ssrf_idor_chain = _recording
        try:
            result, shape = self._run(Shape(topo_service_key="upstream_origin"))
        finally:
            proof_hunt._Hunter._ssrf_idor_chain = original
        self.assertEqual(result["proof-1"], shape.proof)   # the chain banked the proof (router declines here)
        self.assertTrue(returns, "the chain was never called")
        # It solved, so it reached the done() branch and must have returned True there. Under the surviving
        # mutation (done() branch returns False) the method never returns True and this assertion fails.
        self.assertIn(True, returns, returns)


class SSRFIdorChainUnits(unittest.TestCase):
    """Direct unit tests of the two pieces the integration shapes can only exercise indirectly: the
    owner!=role victim selection and the sink-parameter read. These do not depend on which engine reaches the
    service, so they kill the inverted-selection and always-``target`` mutations on the code under test itself.
    """

    def _hunter(self):
        hunter = proof_hunt._Hunter("http://127.0.0.1:1/", max_requests=0)
        hunter.allowed = lambda *a, **k: True          # the feed routes are advertised; let the reader read
        return hunter

    def _feed_page(self, route, doc):
        return {"path": route, "status": 200, "text": json.dumps(doc)}

    def test_owner_mismatch_ids_selects_only_cross_owner_in_feed_order(self):
        hunter = self._hunter()
        route = "/api/cases"
        hunter.pages[route] = self._feed_page(route, {"cases": [
            {"id": 11, "owner": "analyst"},     # caller's own -> excluded
            {"id": 22, "owner": "Executive"},   # cross-owner (case-folded) -> victim
            {"id": 33, "owner": "analyst"},     # caller's own -> excluded
            {"id": 44, "owner": "auditor"},     # cross-owner -> victim
        ]})
        # Only the owner != role ids, in feed order. If the owner==role test were inverted the result would be
        # ['11','33'] (the caller's OWN ids) -- so this assertion fails under that mutation.
        self.assertEqual(hunter._owner_mismatch_ids(route, "analyst"), ["22", "44"])

    def test_owner_mismatch_ids_empty_when_every_owner_is_the_caller(self):
        hunter = self._hunter()
        route = "/api/cases"
        hunter.pages[route] = self._feed_page(route, {"cases": [
            {"id": 11, "owner": "analyst"},
            {"id": 33, "owner": "ANALYST"},
        ]})
        # No cross-owner object -> []. Under the inverted selection this would return ['11','33'].
        self.assertEqual(hunter._owner_mismatch_ids(route, "analyst"), [])

    def test_ssrf_sink_param_reads_rotated_name_structural_and_from_error(self):
        hunter = self._hunter()
        # Structural: the no-arg 400 names the slot in ``query_parameter``.
        self.assertEqual(hunter._ssrf_sink_param(
            {"text": json.dumps({"error": "missing", "query_parameter": "resource"})}), "resource")
        # Error word: ``<param>_required`` where the word is a known SSRF slot name.
        self.assertEqual(hunter._ssrf_sink_param(
            {"text": json.dumps({"error": "endpoint_required"})}), "endpoint")
        # If the reader always returned the default ``target`` both assertions above would fail.

    def test_ssrf_sink_param_defaults_to_target_without_a_named_slot(self):
        hunter = self._hunter()
        # No structural key and no ``<slot>_required`` word -> the observed day-27 default.
        self.assertEqual(hunter._ssrf_sink_param({"text": json.dumps({"error": "bad_request"})}), "target")


if __name__ == "__main__":
    unittest.main(verbosity=2)
