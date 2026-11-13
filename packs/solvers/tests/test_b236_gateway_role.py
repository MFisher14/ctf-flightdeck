#!/usr/bin/env python3
"""B-236: header-trust / gateway-context role-header reader and the clue-advertised header-wave routes.

Every request terminates in an in-memory fake client or a fake HTTP server on 127.0.0.1.  No live
instance, Game Master session, token or model is touched.  Proof values are generated per test.
"""

from __future__ import annotations

import event_pin  # noqa: E402  (tests/event_pin.py)
event_pin.pin(globals(), "huntress")  # Huntress web tests: proof_<32 hex> payoffs (events/huntress [proof])

import json
import sys
import threading
import time
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO / "solvers" / "web"), str(REPO / "solvers" / "toolkits")]

import gateway_role as GR  # noqa: E402
import header_browser_analysis as HBA  # noqa: E402
import proof_hunt  # noqa: E402


def new_proof():
    return "proof_" + uuid.uuid4().hex


def response(status, body, path="/", headers=None):
    payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
    pairs = [("Content-Type", "application/json")]
    pairs.extend(list((headers or {}).items()))
    return {"status": status, "body": payload, "response_header_pairs": pairs,
            "response_headers": dict(pairs), "final_url": "http://fake.local" + path}


class Gateway:
    """The Day-30 two-layer contract, with every knob a test needs to break it."""

    def __init__(self, *, accept_role="administrator", role_header="x-arena-5e1f0a",
                 loopback_header="X-Forwarded-For", loopback_value="127.0.0.1",
                 first_error="gateway_context_rejected", first_vary="X-Forwarded-For",
                 second_error="topology_proof_rejected", second_vary=None,
                 policy="staff_only", clues=None, payoff=None, extra_denial=None,
                 loopback_payoff=False, payoff_headers=None, role_stage_error=None):
        self.base = "http://fake.local/"
        self.timeout = 8.0
        self.feature = "/inspect-5e1f0a"
        self.proof = new_proof()
        self.accept_role = accept_role
        self.role_header = role_header
        self.loopback_header = loopback_header
        self.loopback_value = loopback_value
        self.first_error = first_error
        self.first_vary = first_vary
        self.second_error = second_error
        self.second_vary = role_header if second_vary is None else second_vary
        self.policy = policy
        self.extra_denial = dict(extra_denial or {})
        self.loopback_payoff = loopback_payoff
        self.clues = clues if clues is not None else {
            "framework": "ASP.NET Core Blazor Server", "feature_route": self.feature,
            "component_route": "/blazor", "current_role": "analyst"}
        self.payoff = payoff
        self.payoff_headers = dict(payoff_headers or {})
        self.role_stage_error = role_stage_error
        self.log = []

    def clue_response(self):
        return response(200, self.clues, "/api/clues")

    def request(self, method, path, data=None, headers=None, allow_redirects=True):
        sent = {str(k).lower(): str(v) for k, v in dict(headers or {}).items()}
        self.log.append({"method": method, "path": path, "headers": sent, "redirects": allow_redirects})
        if method != "GET":
            return response(405, {"error": "method_not_allowed"}, path)
        if path == "/api/clues":
            return self.clue_response()
        if path != self.feature:
            return response(404, {"error": "not_found"}, path)
        if sent.get(self.loopback_header.lower()) != self.loopback_value:
            out = {"error": self.first_error, "evaluated_client": "edge-relay"}
            return response(403, out, path, {"Vary": self.first_vary} if self.first_vary else {})
        if self.loopback_payoff or (self.accept_role is not None
                                    and sent.get(self.role_header.lower()) == self.accept_role):
            body = self.payoff if self.payoff is not None else {
                "ok": True, "effect": "unseen_trust_boundary_generalized", "evidence": self.proof}
            return response(200, body, path, self.payoff_headers)
        error = self.second_error
        if self.role_stage_error and sent.get(self.role_header.lower()):
            error = self.role_stage_error  # a role value moved the target off the denial contract
        body = {"error": error, "policy": self.policy, **self.extra_denial}
        if self.policy is None:
            body.pop("policy")
        return response(403, body, path, {"Vary": self.second_vary} if self.second_vary else {})

    def sends(self):
        return [row for row in self.log if row["path"] != "/api/clues"]


def run(site, *, preloaded=None, max_requests=8, baselines=(), route_allowed=None, **extra):
    ctx = {"client": site, "max_requests": max_requests, "deadline": time.time() + 30,
           "preloaded": preloaded if preloaded is not None else {"/api/clues": site.clue_response()},
           "baseline_texts": list(baselines), "result_sink": {}, **extra}
    if route_allowed is not None:
        ctx["route_allowed"] = route_allowed
    got = GR.solve({"answer_id": "proof-1", "url": "http://fake.local/"}, ctx)
    return got, ctx["result_sink"]["proof-1"]


@pytest.fixture(autouse=True)
def _reader_on(monkeypatch):
    monkeypatch.setenv("CTF_WEB_GATEWAY_ROLE", "on")


# --- the Day-30 chain --------------------------------------------------------------------------------

def test_day30_chain_banks_the_proof_through_loopback_then_vary_named_role_header():
    site = Gateway()
    got, meta = run(site)
    assert got == site.proof
    sends = site.sends()
    assert [row["headers"] for row in sends] == [
        {},
        {"x-forwarded-for": "127.0.0.1"},
        {"x-forwarded-for": "127.0.0.1", "x-arena-5e1f0a": "administrator"},
    ]
    assert all(row["method"] == "GET" and row["redirects"] is False for row in site.log)
    assert meta["role_header"] == "x-arena-5e1f0a" and meta["role_value"] == "administrator"
    assert meta["stages"] == ["gateway_context_rejected", "topology_proof_rejected"]
    assert meta["requests"] == 3 and meta["class"] == "gateway_role"


def test_cached_feature_control_is_not_refetched():
    site = Gateway()
    first = site.request("GET", site.feature)
    site.log.clear()
    got, meta = run(site, preloaded={"/api/clues": site.clue_response(), site.feature: first})
    assert got == site.proof
    assert [row["headers"].get("x-forwarded-for") for row in site.sends()] == ["127.0.0.1", "127.0.0.1"]
    assert meta["requests"] == 2


def test_role_ladder_order_reaches_admin_then_policy_role():
    site = Gateway(accept_role="staff")
    got, _meta = run(site)
    assert got == site.proof
    assert [row["headers"].get("x-arena-5e1f0a") for row in site.sends()[2:]] == [
        "administrator", "admin", "staff"]


def test_target_named_role_is_tried_before_the_default_ladder():
    site = Gateway(accept_role="night-auditor", extra_denial={"required_role": "night-auditor"})
    got, _meta = run(site)
    assert got == site.proof
    assert [row["headers"].get("x-arena-5e1f0a") for row in site.sends()[2:]] == ["night-auditor"]


def test_role_values_are_capped_and_the_callers_own_role_is_never_sent():
    site = Gateway(accept_role="analyst")
    got, meta = run(site, max_role_values=3)
    assert got is None
    roles = [row["headers"].get("x-arena-5e1f0a") for row in site.sends()[2:]]
    assert roles == ["administrator", "admin", "staff"]
    assert meta["stopped"] == "no role value was accepted"
    site2 = Gateway(accept_role="nobody")
    run(site2, max_role_values=1)
    assert [row["headers"].get("x-arena-5e1f0a") for row in site2.sends()[2:]] == ["administrator"]


def test_role_ladder_is_pure_and_bounded():
    assert GR.role_ladder({"current_role": "analyst"}, {"policy": "staff_only"}, "analyst") == [
        "administrator", "admin", "staff"]
    assert GR.role_ladder({}, {"policy": "operators_only", "required_role": "Admin"}, "admin", 4) == [
        "administrator", "operator"]
    assert GR.role_ladder({}, {}, None, 99) == ["administrator", "admin"]
    assert GR.role_ladder({}, {"required_role": "bad value!"}, None, 1) == ["administrator"]


def test_loopback_stage_alone_banks_a_day23_shape():
    site = Gateway(first_error="loopback_only", first_vary=None, loopback_payoff=True)
    got, meta = run(site)
    assert got == site.proof
    assert len(site.sends()) == 2 and meta["role_header"] is None
    assert meta["where"] == "gateway_role:loopback"


def test_vary_named_client_address_field_is_the_one_set():
    site = Gateway(first_error="access_denied", first_vary="X-Real-IP", loopback_header="X-Real-IP")
    got, meta = run(site)
    assert got == site.proof
    assert site.sends()[1]["headers"] == {"x-real-ip": "127.0.0.1"}
    assert meta["loopback_header"] == "x-real-ip"


def test_forwarded_field_gets_the_rfc7239_loopback_form():
    site = Gateway(first_error="proxy_trust_required", first_vary="Forwarded",
                   loopback_header="Forwarded", loopback_value="for=127.0.0.1")
    got, _meta = run(site)
    assert got == site.proof
    assert site.sends()[1]["headers"] == {"forwarded": "for=127.0.0.1"}


def test_both_layers_disclosed_at_once_keep_loopback_on_every_role_request():
    site = Gateway(first_vary="X-Forwarded-For, x-arena-5e1f0a")
    got, meta = run(site)
    assert got == site.proof
    assert [row["headers"] for row in site.sends()[1:]] == [
        {"x-forwarded-for": "127.0.0.1", "x-arena-5e1f0a": "administrator"}]
    assert meta["requests"] == 2


def test_two_client_address_fields_are_ambiguity():
    site = Gateway(first_vary="X-Forwarded-For, X-Real-IP")
    got, meta = run(site)
    assert got is None and len(site.sends()) == 1
    assert meta["stopped"] == "denial named more than one client-address field"


# --- fail-closed controls ----------------------------------------------------------------------------

def test_a_denial_that_names_no_trust_layer_sends_nothing_more():
    site = Gateway(first_error="permission_denied", first_vary=None)
    got, meta = run(site)
    assert got is None and len(site.sends()) == 1
    assert meta["stopped"] == "feature denial did not name a gateway trust boundary"


def test_delegated_identity_denial_is_not_this_class():
    site = Gateway(first_error="delegated_identity_rejected", first_vary="x-delegated-user")
    got, _meta = run(site)
    assert got is None and len(site.sends()) == 1


def test_loopback_that_does_not_move_the_decision_stops():
    site = Gateway(second_error="gateway_context_rejected", second_vary="X-Forwarded-For")
    got, meta = run(site)
    assert got is None and len(site.sends()) == 2
    assert meta["stopped"] == "loopback header did not move the gateway decision"


def test_loopback_that_only_discloses_a_new_vary_role_header_still_moves_the_decision():
    # Same error word at both layers: the newly Vary-disclosed role header alone is the movement.
    site = Gateway(second_error="gateway_context_rejected")
    got, meta = run(site)
    assert got == site.proof
    assert [row["headers"].get("x-arena-5e1f0a") for row in site.sends()] == [None, None, "administrator"]
    assert meta["stages"] == ["gateway_context_rejected", "gateway_context_rejected"]
    assert meta["role_header"] == "x-arena-5e1f0a"


def test_two_disclosed_role_headers_are_ambiguity():
    site = Gateway(second_vary="x-arena-5e1f0a, x-tenant-role")
    got, meta = run(site)
    assert got is None and len(site.sends()) == 2
    assert meta["stopped"] == "more than one Vary-disclosed role header"


def test_no_disclosed_role_header_stops_after_loopback():
    site = Gateway(second_vary="Accept-Encoding")
    got, meta = run(site)
    assert got is None and len(site.sends()) == 2
    assert meta["stopped"] == "no Vary-disclosed role header"


def test_a_proof_already_in_a_control_is_not_banked():
    site = Gateway()
    got, meta = run(site, baselines=[json.dumps({"evidence": site.proof})])
    assert got is None
    assert meta["success"] is True


def test_affirmative_answer_without_ok_or_effect_is_not_read():
    site = Gateway()
    site.payoff = {"evidence": site.proof}
    got, meta = run(site)
    assert got is None
    assert meta["stopped"] == "role stage left the denial contract"


def test_two_proofs_in_the_trusted_answer_bank_nothing():
    site = Gateway()
    site.payoff = {"ok": True, "effect": "x", "evidence": site.proof, "other": new_proof()}
    got, _meta = run(site)
    assert got is None


def test_role_stage_denial_with_a_new_error_word_stops_after_one_role_request():
    site = Gateway(accept_role="staff", role_stage_error="role_value_quarantined")
    got, meta = run(site)
    assert got is None
    roles = [row["headers"].get("x-arena-5e1f0a") for row in site.sends()[2:]]
    assert roles == ["administrator"]
    assert meta["stopped"] == "role stage left the denial contract"


def test_affirmative_answer_that_also_carries_an_error_is_refused():
    site = Gateway()
    site.payoff = {"ok": True, "effect": "x", "error": "denied", "evidence": site.proof}
    got, meta = run(site)
    assert got is None
    assert GR._affirmative(response(200, site.payoff)) is None
    assert GR._affirmative(response(200, {"ok": True, "effect": "x", "evidence": site.proof})) is not None
    assert meta["stopped"] == "role stage left the denial contract"


def test_proof_in_a_sibling_carrier_is_surfaced_not_banked():
    site = Gateway(payoff_headers={"X-Evidence": "proof_" + uuid.uuid4().hex})
    site.proof = site.payoff_headers["X-Evidence"]
    site.payoff = {"ok": True, "effect": "unseen_trust_boundary_generalized"}
    evidence = []
    got, meta = run(site, evidence=evidence)
    assert got is None
    assert meta["stopped"] == "trusted anchor and proof/candidate occupied different carrier views"
    assert site.proof in meta["candidates"]
    assert any(site.proof in line and "not auto-submitted" in line for line in evidence)


def test_switch_off_budget_and_route_policy_send_nothing(monkeypatch):
    site = Gateway()
    got, meta = run(site, max_requests=2)
    assert got is None and site.sends() == []
    assert meta["stopped"] == "insufficient budget for the gateway chain"
    got, meta = run(site, route_allowed=lambda _route: False)
    assert got is None and site.sends() == []
    monkeypatch.setenv("CTF_WEB_GATEWAY_ROLE", "off")
    got, meta = run(site)
    assert got is None and site.sends() == [] and meta["stopped"] == "off"


def test_no_feature_route_in_clues_sends_nothing():
    site = Gateway(clues={"framework": "x", "current_role": "analyst"})
    got, meta = run(site)
    assert got is None and site.sends() == []
    assert meta["stopped"] == "no exact cached gateway contract"


def test_indicated_gate_is_offline_and_exact():
    assert GR.indicated(Gateway().request("GET", "/inspect-5e1f0a"))
    assert GR.indicated(Gateway(first_error="loopback_only", first_vary=None).request("GET", "/inspect-5e1f0a"))
    assert not GR.indicated(Gateway(first_error="permission_denied", first_vary=None)
                            .request("GET", "/inspect-5e1f0a"))
    assert not GR.indicated(response(200, {"ok": True}))
    assert not GR.indicated(response(403, {"error": "gateway_context_rejected", "ok": True}))
    assert not GR.indicated(response(403, {"error": "gateway_context_rejected"}, headers={"Vary": "*"}))


# --- header_browser_analysis.vary_disclosed_headers ---------------------------------------------------

def test_vary_disclosure_splits_loopback_custom_and_standard_fields():
    found = HBA.vary_disclosed_headers([("Content-Type", "application/json"),
                                        ("Vary", "Accept-Encoding, X-Forwarded-For"),
                                        ("vary", "x-arena-5e1f0a, Origin, Sec-Fetch-Mode, Host")])
    assert found.tokens == ("accept-encoding", "x-forwarded-for", "x-arena-5e1f0a", "origin",
                            "sec-fetch-mode", "host")
    assert found.loopback == ("x-forwarded-for",)
    assert found.custom == ("x-arena-5e1f0a",)
    assert not found.malformed and not found.wildcard
    assert found.to_dict()["network_requests"] == 0


def test_vary_disclosure_flags_malformed_and_wildcard():
    assert HBA.vary_disclosed_headers([("Vary", "x-ok, bad token")]).malformed
    assert HBA.vary_disclosed_headers([("Vary", "*")]).wildcard
    assert HBA.vary_disclosed_headers([("X-Other", "x-arena-1")]).tokens == ()
    with pytest.raises(HBA.HeaderAnalysisInputError):
        HBA.vary_disclosed_headers([("Vary",)])
    with pytest.raises(HBA.HeaderAnalysisInputError):
        HBA.vary_disclosed_headers([("Vary", "a")] * (HBA.MAX_HEADERS + 1))


# --- proof_hunt integration on a 127.0.0.1 fake ------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def _reply(self, status, value, headers=None):
        body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        for key, val in (headers or {}).items():
            self.send_header(key, val)
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_GET(self):  # noqa: N802
        site = self.server.site
        path = urllib.parse.urlsplit(self.path).path
        with site["lock"]:
            site["hits"].append((self.command, self.path, {k.lower(): v for k, v in self.headers.items()}))
        kind = site["kind"]
        if path == "/":
            return self._reply(200, {"service": "framework roulette"})
        if path == "/api/clues":
            return self._reply(200, site["clues"])
        if kind == "gateway" and path == site["feature"]:
            if self.headers.get("X-Forwarded-For") != "127.0.0.1":
                return self._reply(403, {"error": "gateway_context_rejected", "evaluated_client": "edge"},
                                   {"Vary": "X-Forwarded-For"})
            if self.headers.get("x-arena-77aa01") == "administrator":
                return self._reply(200, {"ok": True, "effect": "unseen_trust_boundary_generalized",
                                         "evidence": site["proof"]})
            return self._reply(403, {"error": "topology_proof_rejected", "policy": "staff_only"},
                               {"Vary": "x-arena-77aa01"})
        if kind == "advertised" and path == "/submit-proof-77aa01":
            if self.headers.get("X-Forwarded-For") == "127.0.0.1":
                return self._reply(200, {"ok": True, "effect": "proxy_trust_admin_bypass",
                                         "evidence": site["proof"]})
            return self._reply(403, {"error": "loopback_only", "evaluated_client": "edge"})
        if kind == "advertised" and path == "/about":
            return self._reply(200, {"service": "proxy-demo"})
        return self._reply(404, {"error": "not_found"})


@pytest.fixture
def serve():
    servers = []

    def start(kind, clues, feature=None):
        server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        server.site = {"kind": kind, "clues": clues, "feature": feature, "proof": new_proof(),
                       "hits": [], "lock": threading.Lock()}
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        host, port = server.server_address
        return server.site, f"http://{host}:{port}"

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


def _hunt(url, question):
    # wall-clock deadline only bounds a hung fake under load; nothing asserts an upper time bound
    return proof_hunt.solve_targets([{"answer_id": "proof-1", "url": url, "question": question}],
                                    {"deadline": time.time() + 60, "max_requests": 80,
                                     "challenge": "b236-fake"})


def test_proof_hunt_dispatches_the_gateway_role_peer(serve, monkeypatch):
    monkeypatch.setenv("CTF_WEB_GATEWAY_ROLE", "on")
    site, url = serve("gateway", {"framework": "ASP.NET Core Blazor Server",
                                  "feature_route": "/inspect-77aa01", "component_route": "/blazor",
                                  "current_role": "analyst"}, feature="/inspect-77aa01")
    result = _hunt(url, "Find the proof behind the framework's trust boundary.")
    assert result == {"proof-1": site["proof"]}
    role_hits = [hit for hit in site["hits"] if hit[2].get("x-arena-77aa01")]
    assert [hit[2]["x-arena-77aa01"] for hit in role_hits] == ["administrator"]
    assert all(hit[0] == "GET" for hit in site["hits"])


def test_proof_hunt_without_the_peer_does_not_reach_the_role_header(serve, monkeypatch):
    # The control for the test above: the switch off leaves the generic waves, which never set the header.
    monkeypatch.setenv("CTF_WEB_GATEWAY_ROLE", "off")
    site, url = serve("gateway", {"framework": "ASP.NET Core Blazor Server",
                                  "feature_route": "/inspect-77aa01", "current_role": "analyst"},
                      feature="/inspect-77aa01")
    result = _hunt(url, "Find the proof behind the framework's trust boundary.")
    assert result == {"proof-1": None}
    assert not any(hit[2].get("x-arena-77aa01") for hit in site["hits"])


def test_clue_advertised_guard_word_route_gets_the_loopback_header_get(serve):
    site, url = serve("advertised", {"feature_route": "/about", "proof_route": "/submit-proof-77aa01",
                                     "deployment": "trusted_reverse_proxy"})
    result = _hunt(url, "Recover the proof from the trusted reverse-proxy target.")
    assert result == {"proof-1": site["proof"]}
    assert any(hit[1] == "/submit-proof-77aa01" and hit[2].get("x-forwarded-for") == "127.0.0.1"
               for hit in site["hits"])


def test_advertised_route_without_a_proxy_clue_is_never_fetched(serve):
    # The control for the test above: the same advertised guard-word route, but the clue names no
    # trusted-proxy/loopback deployment, so it pays no extra advertised-route control GET.
    site, url = serve("advertised", {"feature_route": "/about", "proof_route": "/submit-proof-77aa01"})
    result = _hunt(url, "Recover the proof from the target.")
    assert result == {"proof-1": None}
    assert any(hit[1] == "/about" for hit in site["hits"])
    assert not any(hit[1] == "/submit-proof-77aa01" for hit in site["hits"])


def test_extra_advertised_controls_are_capped(serve):
    # A proxy clue advertising more guard-word routes than the cap pays only CLUE_EXTRA_CONTROLS extra GETs,
    # in sorted order; the generic route wave refuses /submit-* so nothing else reaches the rest.
    extras = {"a_route": "/submit-a1", "b_route": "/submit-b1", "c_route": "/submit-c1",
              "d_route": "/submit-d1", "e_route": "/submit-e1"}
    assert proof_hunt.CLUE_EXTRA_CONTROLS == 2
    site, url = serve("advertised", {"feature_route": "/about", "deployment": "trusted_reverse_proxy",
                                     **extras})
    _hunt(url, "Recover the proof from the trusted reverse-proxy target.")
    reached = {urllib.parse.urlsplit(hit[1]).path for hit in site["hits"]} & set(extras.values())
    assert reached == {"/submit-a1", "/submit-b1"}


def test_clue_advertised_routes_exclude_unadvertised_and_fatal_names():
    hunter = proof_hunt._Hunter("http://127.0.0.1:9/", max_requests=0)
    doc = {"feature_route": "/a", "proofRoute": "/submit-1", "note": "/submit-2",
           "query_route": "/x?y=1", "bad_route": "//evil.example/x"}
    assert hunter._clue_advertised_routes(doc) == {"/a", "/submit-1"}
    assert hunter.allowed("/submit-1", True, trusted=True)
    assert not hunter.allowed("/submit-1", True, trusted=False)
    assert not hunter.allowed("/delete-all", True, trusted=True)
