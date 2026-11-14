#!/usr/bin/env python3
"""B-149: offline regressions for the target-described contract executor.

No Game Master call, live target, token or network is used.  Tiny in-memory
apps implement only the target-published contract graphs and log every wire
method, so a mutation that should never be sent is observable as an empty log.
Fixtures are synthetic; no challenge file is read.

The three contract *classes* the retro named are modelled after their real
advertised shapes (summarised from coverage/huntress day-24/25/28 evidence),
not the executor's internal control/mutation IR:

  * Day-24 "Fail-Open Friday"  -- a GET policy route that fails open on an
    undecodable value (a read; runs under the default GET-only policy).
  * Day-25 "If a Breach Falls in a Log" -- a *state-changing POST* audit record
    whose follow-up log read reveals the novel proof (gated by BUILD-PLAN O-2).
  * Day-28 "Pass the Identity" -- a *header-trusted delegated identity*: a GET
    whose X-Delegated-User header carries the privileged owner (a read; runs
    under GET-only, no O-2 gate).
"""

import event_pin  # noqa: E402  (tests/event_pin.py)
event_pin.pin(globals(), "huntress")  # Huntress web tests: proof_<32 hex> payoffs (events/huntress [proof])

import contextlib
import json
import os
import sys
import urllib.parse
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "web"))
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import contract_executor as CE  # noqa: E402

FAILURES = []
CHECKS = [0]


def check(label, condition, detail=""):
    CHECKS[0] += 1
    print(("ok   " if condition else "FAIL ") + label
          + ("" if condition or not detail else f"  [{str(detail)[:1500]}]"))
    if not condition:
        FAILURES.append(label)


def proof():
    return "proof_" + uuid.uuid4().hex


def response(status, body, path="/", headers=None):
    if not isinstance(body, (bytes, bytearray)):
        body = json.dumps(body, separators=(",", ":")) if isinstance(body, (dict, list)) else str(body)
        body = body.encode("utf-8")
    pairs = [("Content-Type", "application/json" if bytes(body).lstrip()[:1] in (b"{", b"[")
              else "text/plain; charset=utf-8")]
    pairs.extend(list((headers or {}).items()))
    return {"status": status, "body": bytes(body), "response_header_pairs": pairs,
            "response_headers": dict(pairs), "final_url": "http://fake.local" + path}


def target():
    return {"answer_id": "proof-1", "url": "http://fake.local/", "index": 1}


@contextlib.contextmanager
def state_changing_event(flag=True):
    """Run the body as if the active event profile set web_state_changing=<flag>.

    This injects the O-2 decision the executor reads via ``ctf.event.current``;
    the pinned huntress profile ships web_state_changing=false, so a POST class
    is gated unless a profile permits it.  Works under pytest and as a script."""
    class _Rules:
        web_state_changing = bool(flag)

    class _Profile:
        slug = "test-state-changing"
        rules = _Rules()

    original = CE.ctf_event.current
    CE.ctf_event.current = lambda **kw: _Profile()
    try:
        yield
    finally:
        CE.ctf_event.current = original


class FakeClient:
    """A scope-pinned WebClient stand-in that routes to a handler and logs wire calls."""

    def __init__(self, handler):
        self.base = "http://fake.local/"
        self.application_base = self.base
        self.timeout = 8.0
        self.log = []
        self._handler = handler

    def request(self, method, path, data=None, headers=None, allow_redirects=True):
        self.log.append({"method": method, "path": path, "data": data,
                         "headers": dict(headers or {})})
        return self._handler(method, path, data, dict(headers or {}))

    @property
    def gets(self):
        return [r for r in self.log if r["method"] == "GET"]

    @property
    def posts(self):
        return [r for r in self.log if r["method"] != "GET"]


class RaiseOnceClient(FakeClient):
    """Logs the attempt, then raises a transport error on the Nth wire call."""

    def __init__(self, handler, raise_on=1, exc=ConnectionResetError):
        super().__init__(handler)
        self._raise_on = raise_on
        self._exc = exc
        self._n = 0

    def request(self, method, path, data=None, headers=None, allow_redirects=True):
        self._n += 1
        self.log.append({"method": method, "path": path, "data": data,
                         "headers": dict(headers or {})})
        if self._n == self._raise_on:
            raise self._exc("synthetic transport failure")
        return self._handler(method, path, data, dict(headers or {}))


# --- Day-24 shape: GET action, asserted fail-open effect, no follow-up -------
class PolicyFailOpen:
    def __init__(self, *, answer=None, control_proof=None, wrong_effect=False,
                 two_novel=False, inert=False):
        self.answer = answer or proof()
        self.control_proof = control_proof
        self.wrong_effect = wrong_effect
        self.two_novel = two_novel
        self.inert = inert          # control==mutation payoff; the run finds nothing
        self.route = "/policy-eval"

    def contract(self):
        graph = {"action_route": self.route, "action_method": "GET", "action_param": "policy",
                 "control": "valid-token", "mutation": "!malformed",
                 "effect": "exceptional_condition_fail_open"}
        if self.inert:
            # No asserted effect: the inert run must reach the novelty extraction
            # and the success assignment, not stop early at the effect gate.
            graph.pop("effect")
        return graph

    def __call__(self, method, path, data, headers):
        split = urllib.parse.urlsplit(path)
        if method != "GET":
            return response(405, {"error": "method_not_allowed"}, path)
        if split.path != self.route:
            return response(404, {"error": "not_found"}, path)
        value = dict(urllib.parse.parse_qsl(split.query, keep_blank_values=True)).get("policy", "")
        if self.inert:
            return response(200, {"ok": True, "effect": "standard_decision"}, path)
        if value == "valid-token":
            body = {"ok": True, "effect": "standard_decision", "decision": "allow"}
            if self.control_proof:
                body["evidence"] = self.control_proof
            return response(200, body, path)
        if value == "!malformed":
            effect = "decoder_exception" if self.wrong_effect else "exceptional_condition_fail_open"
            body = {"ok": True, "effect": effect, "evidence": self.answer}
            if self.two_novel:
                body["other"] = proof()
            return response(200, body, path)
        return response(400, {"error": "remote_policy_required"}, path)


# --- Day-25 shape: state-changing POST audit record + follow-up log read -----
class BreachAuditReport:
    """The real Day-25 class: an audit-report POST writes state, and the
    follow-up log read reveals the novel proof.  State-changing -> gated by O-2."""

    def __init__(self, *, answer=None, decoy=None):
        self.answer = answer or proof()
        self.decoy = decoy or proof()
        self.recorded = False
        self.action = "/breach-record"
        self.follow = "/breach-log"

    def contract(self):
        return {"action_route": self.action, "action_method": "POST",
                "control": {"event": "page_view"}, "mutation": {"event": "protected_export"},
                "follow_up_route": self.follow}

    def __call__(self, method, path, data, headers):
        split = urllib.parse.urlsplit(path)
        if method == "POST" and split.path == self.action:
            try:
                doc = json.loads(data or "{}")
            except Exception:
                doc = None
            if isinstance(doc, dict) and doc.get("event") == "protected_export":
                self.recorded = True
            return response(200, {"ok": True, "logged": isinstance(doc, dict)}, path)
        if method == "GET" and split.path == self.follow:
            entries = [{"id": 1, "note": "startup", "ref": self.decoy}]
            if self.recorded:
                entries.append({"id": 2, "note": "breach", "ref": self.answer})
            return response(200, {"entries": entries}, path)
        return response(404, {"error": "not_found"}, path)


# --- Day-28 shape: header-trusted delegated identity (a GET; no O-2 gate) -----
class DelegatedIdentity:
    """The real Day-28 class: a GET whose X-Delegated-User header carries the
    privileged records_owner; the feature route returns the evidence proof when
    the delegation header is trusted.  A read -> runs under the default policy."""

    def __init__(self, *, answer=None):
        self.answer = answer or proof()
        self.owner = "executive"
        self.action = "/execute-9a1f"

    def contract(self):
        return {"action_route": self.action, "action_method": "GET",
                "action_header": "X-Delegated-User",
                "control": "analyst", "mutation": self.owner,
                "effect": "delegated_identity_trusted"}

    def __call__(self, method, path, data, headers):
        split = urllib.parse.urlsplit(path)
        if method != "GET" or split.path != self.action:
            return response(404, {"error": "not_found"}, path)
        delegated = {k.lower(): v for k, v in headers.items()}.get("x-delegated-user", "")
        if delegated == self.owner:
            return response(200, {"effect": "delegated_identity_trusted", "evidence": self.answer}, path)
        return response(403, {"effect": "delegated_identity_rejected"}, path)


def run(server, **ctx_extra):
    client = FakeClient(server)
    ctx = {"client": client, "contract": server.contract(), "max_requests": 12,
           "deadline": None, "result_sink": {}}
    ctx.update(ctx_extra)
    got = CE.solve(target(), ctx)
    return got, client, ctx["result_sink"].get("proof-1") or {}


# ============================ the tests =====================================
def test_get_contract_fail_open():
    server = PolicyFailOpen()
    got, client, meta = run(server)
    check("fail-open: executor returns the novel fail-open proof", got == server.answer, (got, client.log))
    check("fail-open: only GETs on the wire, zero mutation",
          client.posts == [] and {r["method"] for r in client.log} == {"GET"}, client.log)
    check("fail-open: exactly a control value precedes the mutated value",
          len(client.gets) == 2
          and "valid-token" in client.gets[0]["path"]
          and urllib.parse.quote("!malformed", safe="") in client.gets[1]["path"], client.log)
    check("fail-open: summary names the class and records no POST",
          meta.get("class") == "target_described_contract" and meta.get("posts") == 0
          and meta.get("success") is True, meta)


def test_novelty_subtracts_control_proof():
    # The ordinary control already shows the same proof -> it is NOT novel.
    shared = proof()
    server = PolicyFailOpen(answer=shared, control_proof=shared)
    got, client, meta = run(server)
    check("novelty: a proof already shown by the control is never returned",
          got is None, (got, client.log))
    check("novelty: both control and mutation were still read (GET-only)",
          len(client.gets) == 2 and client.posts == [], client.log)
    check("novelty: success is False when nothing novel was found (non-terminal)",
          meta.get("success") is False, meta)


def test_two_novel_values_are_ambiguous():
    server = PolicyFailOpen(two_novel=True)
    got, client, meta = run(server)
    check("ambiguity: two novel payoff proofs auto-return nothing", got is None, (got, meta))
    check("ambiguity: both novel values are surfaced as candidates",
          len(meta.get("candidates") or []) >= 2, meta)
    check("ambiguity: a surfaced candidate still marks the run a success",
          meta.get("success") is True, meta)


def test_effect_must_be_confirmed():
    server = PolicyFailOpen(wrong_effect=True)
    got, client, meta = run(server)
    check("effect gate: an unconfirmed advertised effect returns no proof", got is None, (got, meta))
    check("effect gate: the stop reason names the missing effect",
          "effect" in str(meta.get("finding") or ""), meta)


def test_inert_contract_is_non_terminal():
    # A contract run that finds neither a proof nor a candidate must NOT report
    # success -- otherwise proof_hunt's _run_peer treats it as terminal and
    # suppresses the later GET waves that could still find the proof.
    server = PolicyFailOpen(inert=True)
    got, client, meta = run(server)
    check("inert: a contract that finds nothing returns no proof", got is None, (got, meta))
    check("inert: the run reached the payoff read (control + mutation both sent)",
          len(client.gets) == 2 and meta.get("finding") is None
          and "no single novel strict proof" in str(meta.get("stopped") or ""), meta)
    check("inert: and reports success=False so the run is non-terminal",
          meta.get("success") is False and not meta.get("candidates"), meta)


# --- Day-25 state-changing POST audit class (gated by O-2) -------------------
def test_audit_post_is_gated_by_default():
    server = BreachAuditReport()
    got, client, meta = run(server)
    check("gate: a state-changing POST audit record is not sent under the default policy",
          got is None and client.log == [], client.log)
    check("gate: the structured finding names the policy gate",
          "gated" in str(meta.get("finding") or "").lower() and meta.get("posts") == 0, meta)


def test_audit_post_refused_when_event_forbids_state_change():
    # Even an explicit POST policy is narrowed to GET-only unless the active
    # event profile sets web_state_changing=true (pinned huntress = false).
    server = BreachAuditReport()
    policy = CE.MutationPolicy(("POST",), "operator-approved")
    got, client, meta = run(server, mutation_policy=policy)
    check("event gate: a non-GET policy is refused when the event forbids state change",
          got is None and client.log == [], client.log)
    check("event gate: the finding names web_state_changing",
          "web_state_changing" in str(meta.get("finding") or ""), meta)


def test_audit_post_runs_under_policy_and_permissive_event():
    server = BreachAuditReport()
    policy = CE.MutationPolicy(("POST",), "operator-approved for B-149 test")
    with state_changing_event(True):
        got, client, meta = run(server, mutation_policy=policy)
    check("audit POST: the novel log entry after the state change is returned",
          got == server.answer, (got, client.log))
    check("audit POST: the pre-existing decoy entry is subtracted, not returned",
          got != server.decoy, (got, server.decoy))
    check("audit POST: exactly two POSTs (control + mutation) carried a JSON body",
          len(client.posts) == 2
          and json.loads(client.posts[0]["data"]) == {"event": "page_view"}
          and json.loads(client.posts[1]["data"]) == {"event": "protected_export"}, client.log)
    check("audit POST: each JSON body send declared Content-Type application/json",
          all(r["headers"].get("Content-Type") == "application/json" for r in client.posts), client.log)
    check("audit POST: the follow-up log was read before and after each action",
          [r["path"].split("?")[0] for r in client.log]
          == ["/breach-log", "/breach-record", "/breach-log", "/breach-record", "/breach-log"], client.log)


def test_get_only_overrides_permissive_event_and_policy():
    server = BreachAuditReport()
    policy = CE.MutationPolicy(("POST",))
    with state_changing_event(True):
        got, client, meta = run(server, mutation_policy=policy, get_only=True)
    check("get_only: the lane's GET-only flag overrides a caller POST policy and the event",
          got is None and client.log == [], client.log)
    check("get_only: the finding still names the gate and no POST left",
          "gated" in str(meta.get("finding") or "").lower() and meta.get("posts") == 0, meta)


# --- Day-28 header-trusted delegated identity (a GET; runs under GET-only) ----
def test_delegated_identity_runs_get_only():
    server = DelegatedIdentity()
    got, client, meta = run(server)
    check("delegated identity: the forged-owner GET returns the evidence proof",
          got == server.answer, (got, client.log))
    check("delegated identity: it is a read -- only GETs, zero POSTs",
          client.posts == [] and {r["method"] for r in client.log} == {"GET"}, client.log)
    check("delegated identity: the privileged owner rode the X-Delegated-User header",
          any(r["headers"].get("X-Delegated-User") == server.owner for r in client.gets)
          and any(r["headers"].get("X-Delegated-User") == "analyst" for r in client.gets), client.log)


def test_delegated_identity_header_control_precedes_mutation():
    server = DelegatedIdentity()
    got, client, meta = run(server)
    headers = [r["headers"].get("X-Delegated-User") for r in client.gets]
    check("delegated identity: control header precedes mutation header",
          headers == ["analyst", "executive"], headers)


# --- safety: route_allowed + destructive refusal -----------------------------
def test_destructive_mutation_sends_nothing():
    # A contract whose mutation names a destructive action never reaches the wire.
    graph = {"action_route": "/admin", "action_method": "GET", "action_param": "action",
             "control": "list_users", "mutation": "delete_all_users"}
    client = FakeClient(PolicyFailOpen())
    meta = {}
    got = CE.solve(target(), {"client": client, "contract": graph, "deadline": None,
                              "max_requests": 12, "result_sink": meta})
    check("destructive: a destructive mutation value is refused with no wire request",
          got is None and client.log == [], client.log)
    check("destructive: the finding names the destructive token refusal",
          "destructive" in str(meta.get("proof-1", {}).get("finding") or ""), meta.get("proof-1"))


def test_route_allowed_refusal_sends_nothing():
    # The hunter's own route_allowed is a second scope/read-action gate.
    server = PolicyFailOpen()
    client = FakeClient(server)
    meta = {}
    got = CE.solve(target(), {"client": client, "contract": server.contract(),
                              "route_allowed": lambda path, method="GET": False,
                              "deadline": None, "max_requests": 12, "result_sink": meta})
    check("route_allowed: a refusal stops the sequence with no wire request",
          got is None and client.log == [], client.log)
    check("route_allowed: the finding names the refusal",
          "route_allowed" in str(meta.get("proof-1", {}).get("finding") or ""), meta.get("proof-1"))


# --- incompleteness, disabled, clue graph -----------------------------------
def test_incomplete_contract_sends_nothing():
    cases = [
        ("missing action route", {"action_method": "GET", "control": "a", "mutation": "b"}),
        ("missing control/mutation pair", {"action_route": "/x"}),
        ("cross-origin follow-up", {"action_route": "/x", "action_param": "p", "control": "a",
                                    "mutation": "b", "follow_up_route": "http://evil.local/y"}),
        ("off-origin action route", {"action_route": "http://evil.local/x", "control": "a",
                                     "mutation": "b"}),
        ("both carriers named", {"action_route": "/x", "action_param": "p",
                                 "action_header": "X-Id", "control": "a", "mutation": "b"}),
    ]
    for label, graph in cases:
        client = FakeClient(PolicyFailOpen())
        meta = {}
        got = CE.solve(target(), {"client": client, "contract": graph, "deadline": None,
                                  "max_requests": 12, "result_sink": meta})
        check(f"incomplete: {label} -> no proof, no wire request",
              got is None and client.log == [], client.log)
        check(f"incomplete: {label} -> structured finding recorded",
              bool(meta.get("proof-1", {}).get("finding")), meta.get("proof-1"))


def test_no_differential_sends_nothing():
    server = BreachAuditReport()
    graph = server.contract()
    graph["mutation"] = graph["control"]  # no differential
    client = FakeClient(server)
    meta = {}
    got = CE.solve(target(), {"client": client, "contract": graph, "deadline": None,
                              "max_requests": 12, "result_sink": meta})
    check("no-differential: an identical control/mutation pair is refused with no wire",
          got is None and client.log == [], client.log)


def test_contract_from_preloaded_clues():
    server = PolicyFailOpen()
    client = FakeClient(server)
    clues = response(200, {"contract": server.contract()}, "/api/clues")
    meta = {}
    got = CE.solve(target(), {"client": client,
                              "preloaded": {"/api/clues": clues},
                              "deadline": None, "max_requests": 12, "result_sink": meta})
    check("clue graph: a contract read from cached /api/clues is executed",
          got == server.answer, (got, client.log))


def test_disabled_executor_is_a_named_stop():
    server = PolicyFailOpen()
    client = FakeClient(server)
    meta = {}
    old = os.environ.get("CTF_WEB_CONTRACT_EXECUTOR")
    os.environ["CTF_WEB_CONTRACT_EXECUTOR"] = "off"
    try:
        got = CE.solve(target(), {"client": client, "contract": server.contract(),
                                  "deadline": None, "result_sink": meta})
    finally:
        if old is None:
            os.environ.pop("CTF_WEB_CONTRACT_EXECUTOR", None)
        else:
            os.environ["CTF_WEB_CONTRACT_EXECUTOR"] = old
    check("disabled: an off executor fails loudly with a named reason and no wire",
          got is None and client.log == [] and meta.get("proof-1", {}).get("stopped") == "off",
          meta.get("proof-1"))


# --- mutation-survivor kills ------------------------------------------------
def test_budget_reservation_boundary():
    # Kills the under-reservation survivor (steps 2+3 -> 2+2): a follow-up POST
    # sequence reserves 5 steps.  At max_requests=4 nothing goes out; at 5 the
    # whole control+mutation+readback sequence runs and the proof is banked.
    policy = CE.MutationPolicy(("POST",))
    for budget, expect_posts, expect_proof in ((4, 0, False), (5, 2, True)):
        server = BreachAuditReport()
        client = FakeClient(server)
        meta = {}
        with state_changing_event(True):
            got = CE.solve(target(), {"client": client, "contract": server.contract(),
                                      "mutation_policy": policy, "max_requests": budget,
                                      "deadline": None, "result_sink": meta})
        check(f"budget boundary: max_requests={budget} sends {expect_posts} POST(s)",
              len(client.posts) == expect_posts, client.log)
        check(f"budget boundary: max_requests={budget} proof banked == {expect_proof}",
              (got == server.answer) is expect_proof, (got, server.answer))


def test_budget_blocks_partial_mutation():
    server = BreachAuditReport()
    policy = CE.MutationPolicy(("POST",))
    client = FakeClient(server)
    meta = {}
    with state_changing_event(True):
        got = CE.solve(target(), {"client": client, "contract": server.contract(),
                                  "mutation_policy": policy, "max_requests": 2,
                                  "deadline": None, "result_sink": meta})
    check("budget: a POST contract that cannot complete its readback sends nothing",
          got is None and client.posts == [], client.log)
    check("budget: the stop reason names the budget shortfall",
          "budget" in str(meta.get("proof-1", {}).get("stopped") or "").lower(), meta.get("proof-1"))


def test_near_deadline_refuses_mutation_sequence():
    # Kills the time-reserve survivor (gate -> if False): with a deadline that
    # leaves time to start but not to finish a mutation+readback, no POST goes
    # out.  A no-follow-up POST keeps the step count at 2 so only the time
    # reserve, not the request budget, can stop it.
    server = DelegatedIdentity()
    graph = server.contract()
    graph["action_method"] = "POST"          # force the state-changing branch
    graph.pop("action_header", None)
    graph["action_param"] = "user"
    policy = CE.MutationPolicy(("POST",))
    client = FakeClient(server)
    meta = {}
    import time as _t
    with state_changing_event(True):
        got = CE.solve(target(), {"client": client, "contract": graph,
                                  "mutation_policy": policy, "max_requests": 50,
                                  "deadline": _t.time() + 0.6, "result_sink": meta})
    check("near-deadline: a POST sequence with no time for the readback sends nothing",
          client.posts == [], client.log)
    check("near-deadline: the stop reason names the time reserve",
          "time" in str(meta.get("proof-1", {}).get("stopped") or "").lower(), meta.get("proof-1"))


def test_json_content_type_on_body():
    # Kills the Content-Type survivor (header -> None): a dict body send must
    # declare application/json.
    server = BreachAuditReport()
    policy = CE.MutationPolicy(("POST",))
    client = FakeClient(server)
    meta = {}
    with state_changing_event(True):
        CE.solve(target(), {"client": client, "contract": server.contract(),
                            "mutation_policy": policy, "max_requests": 12,
                            "deadline": None, "result_sink": meta})
    check("content-type: every JSON-body POST carried Content-Type application/json",
          len(client.posts) == 2
          and all(r["headers"].get("Content-Type") == "application/json" for r in client.posts),
          client.log)


def test_control_transport_error_stops_before_mutation():
    # Kills the transport early-return survivor (guard -> if False): when the
    # control action fails on the wire, the mutation is never attempted and the
    # finding records that the executor halted at the control.
    server = PolicyFailOpen()
    client = RaiseOnceClient(server, raise_on=1)   # the control GET is the first send
    meta = {}
    got = CE.solve(target(), {"client": client, "contract": server.contract(),
                              "deadline": None, "max_requests": 12, "result_sink": meta})
    sent = [r["path"].split("?", 1)[0] for r in client.log]
    check("transport: exactly one wire attempt was made (the failed control)",
          sent == ["/policy-eval"], client.log)
    check("transport: no mutation value reached the wire",
          all(urllib.parse.quote("!malformed", safe="") not in r["path"] for r in client.log), client.log)
    check("transport: the finding records halting at the control before the mutation",
          got is None and "control action failed" in str(meta.get("proof-1", {}).get("finding") or ""),
          meta.get("proof-1"))


# --- round-2 survivor kills -------------------------------------------------
@contextlib.contextmanager
def executor_env_unset():
    """Run with no CTF_WEB_CONTRACT_EXECUTOR override, so _class_on consults the
    workdir kill-switch file."""
    old = os.environ.pop("CTF_WEB_CONTRACT_EXECUTOR", None)
    try:
        yield
    finally:
        if old is not None:
            os.environ["CTF_WEB_CONTRACT_EXECUTOR"] = old


@contextlib.contextmanager
def patched_workdir(fn):
    original = CE.ctf_paths.workdir
    CE.ctf_paths.workdir = fn
    try:
        yield
    finally:
        CE.ctf_paths.workdir = original


def test_kill_switch_fails_closed_when_workdir_unreadable():
    # Kills `_class_on` except -> return True: an unreadable kill-switch location
    # must refuse (named "off" stop, no wire), never silently run.
    def broken_workdir(*a, **kw):
        raise RuntimeError("synthetic: no event profile, no workdir")

    server = PolicyFailOpen()
    client = FakeClient(server)
    meta = {}
    with executor_env_unset(), patched_workdir(broken_workdir):
        got = CE.solve(target(), {"client": client, "contract": server.contract(),
                                  "deadline": None, "max_requests": 12, "result_sink": meta})
    check("kill switch: an unreadable workdir fails closed with stopped=='off'",
          got is None and meta.get("proof-1", {}).get("stopped") == "off", meta.get("proof-1"))
    check("kill switch: and nothing reached the wire", client.log == [], client.log)


def test_kill_switch_off_file():
    # The `_contract_executor.off` file in the workdir disables the class; the
    # same workdir without it runs normally (so the file, not the dir, decides).
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for present in (True, False):
            marker = root / "_contract_executor.off"
            if present:
                marker.write_text("", encoding="utf-8")
            elif marker.exists():
                marker.unlink()
            server = PolicyFailOpen()
            client = FakeClient(server)
            meta = {}
            with executor_env_unset(), patched_workdir(lambda *a, **kw: root):
                got = CE.solve(target(), {"client": client, "contract": server.contract(),
                                          "deadline": None, "max_requests": 12, "result_sink": meta})
            if present:
                check("kill switch file: present -> stopped=='off' and no wire",
                      got is None and client.log == []
                      and meta.get("proof-1", {}).get("stopped") == "off", meta.get("proof-1"))
            else:
                check("kill switch file: absent -> the executor runs and banks the proof",
                      got == server.answer, (got, client.log))


def test_self_built_client_inherits_get_only():
    # Kills the self-built WebClient kwargs -> {} mutation: with no client and
    # no factory, the executor builds its own WebClient and must pass the lane's
    # get_only flag through; without the flag it passes nothing extra.
    for flag in (True, False):
        server = PolicyFailOpen()
        built = []

        def fake_webclient(url, timeout=None, **kw):
            built.append({"url": url, "kwargs": dict(kw)})
            return FakeClient(server)

        original = CE._web.WebClient
        CE._web.WebClient = fake_webclient
        meta = {}
        ctx = {"contract": server.contract(), "deadline": None, "max_requests": 12,
               "result_sink": meta}
        if flag:
            ctx["get_only"] = True
        try:
            got = CE.solve(target(), ctx)
        finally:
            CE._web.WebClient = original
        check(f"self-built client (get_only={flag}): exactly one WebClient was built",
              len(built) == 1 and built[0]["url"] == "http://fake.local/", built)
        expected = {"get_only": True} if flag else {}
        check(f"self-built client (get_only={flag}): WebClient kwargs == {expected}",
              built and built[0]["kwargs"] == expected, built)
        check(f"self-built client (get_only={flag}): the GET contract still banks the proof",
              got == server.answer, (got, meta.get("proof-1")))


def _header_run(graph):
    server = DelegatedIdentity()
    client = FakeClient(server)
    meta = {}
    got = CE.solve(target(), {"client": client, "contract": graph, "deadline": None,
                              "max_requests": 12, "result_sink": meta})
    return got, client, meta.get("proof-1") or {}


def test_header_name_must_be_a_token():
    # Kills the header-name regex -> if False mutation: a name that is not a
    # plain HTTP token never reaches the wire.
    for bad in ("X-Id: injected", "X Delegated", "X-Id\r\nHost", "-X-Id", "X_Id", ""):
        graph = DelegatedIdentity().contract()
        graph["action_header"] = bad
        got, client, meta = _header_run(graph)
        check(f"header name {bad!r}: refused with no wire",
              got is None and client.log == [], client.log)
        check(f"header name {bad!r}: finding names the unusable header",
              "header name is unusable" in str(meta.get("finding") or ""), meta)


def test_denied_headers_send_nothing():
    # A target may not pick a credential, Host or framing header as its carrier:
    # WebClient.request merges caller headers last, so it would override the
    # hunter's session cookie or the request framing.
    for name in ("Cookie", "cookie", "Authorization", "Proxy-Authorization", "Host",
                 "Content-Length", "Transfer-Encoding", "Connection", "TE", "Upgrade"):
        graph = DelegatedIdentity().contract()
        graph["action_header"] = name
        got, client, meta = _header_run(graph)
        check(f"denied header {name}: refused with no wire",
              got is None and client.log == [], client.log)
        check(f"denied header {name}: finding names the denied header",
              "denied" in str(meta.get("finding") or ""), meta)
    # Contrast: an ordinary custom header in the same position still runs.
    graph = DelegatedIdentity().contract()
    got, client, meta = _header_run(graph)
    check("denied header contrast: X-Delegated-User is allowed and sent",
          any("X-Delegated-User" in r["headers"] for r in client.log), client.log)


def test_header_value_control_chars_send_nothing():
    # Kills the control-char refusal removal: a CR/LF (or other C0/DEL) in either
    # header value is refused before the control is sent, so the wire stays empty.
    for field, value in (("mutation", "executive\r\nX-Injected: 1"),
                         ("mutation", "executive\nX-Injected: 1"),
                         ("control", "analyst\r\nCookie: stolen"),
                         ("mutation", "exec\x00utive"),
                         ("mutation", "exec\x7futive")):
        graph = DelegatedIdentity().contract()
        graph[field] = value
        got, client, meta = _header_run(graph)
        check(f"header value {field}={value!r}: refused with an empty wire log",
              got is None and client.log == [], client.log)
        check(f"header value {field}={value!r}: finding names the unusable value",
              "header value is unusable" in str(meta.get("finding") or ""), meta)


def test_header_destructive_value_sends_nothing():
    graph = DelegatedIdentity().contract()
    graph["mutation"] = "delete_all_users"
    got, client, meta = _header_run(graph)
    check("header destructive value: refused with no wire",
          got is None and client.log == [], client.log)
    check("header destructive value: finding names the destructive token",
          "destructive" in str(meta.get("finding") or ""), meta)


def test_destructive_param_name_refused_before_follow_up():
    # A destructive parameter name is refused at validation, so not even the
    # pre-follow-up read goes out.
    graph = {"action_route": "/x", "action_method": "GET", "action_param": "delete_user",
             "control": "a", "mutation": "b", "follow_up_route": "/y"}
    client = FakeClient(PolicyFailOpen())
    meta = {}
    got = CE.solve(target(), {"client": client, "contract": graph, "deadline": None,
                              "max_requests": 12, "result_sink": meta})
    check("destructive param: no wire request, not even the follow-up read",
          got is None and client.log == [], client.log)
    check("destructive param: finding names the unusable parameter",
          "parameter name is unusable" in str(meta.get("proof-1", {}).get("finding") or ""),
          meta.get("proof-1"))


def test_nested_target_query_value_never_sent():
    # Kills guard_query=True -> False: a control/mutation value that embeds a
    # URL (a nested target) is refused at the assembled query, never sent.
    server = PolicyFailOpen()
    graph = server.contract()
    graph.pop("effect")
    graph["mutation"] = "http://evil.local/steal"
    client = FakeClient(server)
    meta = {}
    got = CE.solve(target(), {"client": client, "contract": graph, "deadline": None,
                              "max_requests": 12, "result_sink": meta})
    check("nested query: the embedded-URL mutation value never reached the wire",
          got is None and all("evil" not in r["path"] for r in client.log)
          and len(client.log) == 1, client.log)
    check("nested query: the stop names the out-of-scope assembled query",
          "not in scope" in str(meta.get("proof-1", {}).get("stopped") or ""), meta.get("proof-1"))

    # The same value as the *control*: with no control response there is no
    # baseline, so the mutation is not attempted either -- nothing is sent.
    graph = server.contract()
    graph["control"] = "http://evil.local/steal"
    client = FakeClient(server)
    meta = {}
    got = CE.solve(target(), {"client": client, "contract": graph, "deadline": None,
                              "max_requests": 12, "result_sink": meta})
    check("nested control: nothing reached the wire (no control, no mutation)",
          got is None and client.log == [], client.log)
    check("nested control: finding says the mutation was not attempted",
          "mutation not attempted" in str(meta.get("proof-1", {}).get("finding") or ""),
          meta.get("proof-1"))


# --- proof_hunt wiring ------------------------------------------------------
class WiringServer:
    """A full-recon fake target that publishes a GET fail-open contract under
    /api/clues, used to prove proof_hunt dispatches the executor end-to-end."""

    def __init__(self, *, inert=False, env_proof=None):
        self.base = "http://fake.local/"
        self.application_base = self.base
        self.timeout = 8.0
        self.log = []
        self.answer = proof()
        self.env_proof = env_proof        # a proof a LATER wave (exposed .env) would find
        self.inert = inert                # contract finds nothing
        # A route name with no fatal action word, so the hunter's route_allowed
        # (allowed(..., trusted=True)) accepts this advertised feature route.
        self.route = "/api/verdict"

    @property
    def contract(self):
        if self.inert:
            return {"action_route": self.route, "action_method": "GET", "action_param": "policy",
                    "control": "valid-token", "mutation": "other-token"}
        return {"action_route": self.route, "action_method": "GET", "action_param": "policy",
                "control": "valid-token", "mutation": "!malformed",
                "effect": "exceptional_condition_fail_open"}

    @property
    def posts(self):
        return [r for r in self.log if r["method"] != "GET"]

    def request(self, method, path, data=None, headers=None, allow_redirects=True):
        self.log.append({"method": method, "path": path})
        split = urllib.parse.urlsplit(path)
        if method != "GET":
            return response(405, {"error": "method_not_allowed"}, path)
        if split.path == "/":
            return response(200, "<title>Policy</title>", path)
        if split.path == "/.env" and self.env_proof:
            return response(200, f"SECRET_TOKEN={self.env_proof}\n", path)
        if split.path in ("/robots.txt", "/openapi.json", "/api/history", "/sitemap.xml"):
            return response(404, {"error": "not_found"}, path)
        if split.path == "/api/clues":
            return response(200, {"contract": self.contract}, path)
        if split.path == self.route:
            value = dict(urllib.parse.parse_qsl(split.query, keep_blank_values=True)).get("policy", "")
            if self.inert:
                return response(200, {"ok": True, "effect": "standard_decision"}, path)
            if value == "valid-token":
                return response(200, {"ok": True, "effect": "standard_decision"}, path)
            if value == "!malformed":
                return response(200, {"ok": True, "effect": "exceptional_condition_fail_open",
                                      "evidence": self.answer}, path)
            return response(400, {"error": "remote_policy_required"}, path)
        return response(404, {"error": "not_found"}, path)


def test_proof_hunt_wiring():
    import proof_hunt as PH
    server = WiringServer()
    original = PH._web.WebClient
    PH._web.WebClient = lambda url, timeout=8.0, **kw: server
    try:
        got = PH.solve_targets([target()], {"max_requests": 40, "deadline": None})
    finally:
        PH._web.WebClient = original
    check("wiring: proof_hunt dispatches the contract executor and banks the proof",
          got == {"proof-1": server.answer}, (got, server.log))
    check("wiring: the end-to-end contract run put no mutation on the wire",
          server.posts == [], server.log)


def test_proof_hunt_inert_contract_is_non_terminal():
    # The contract run finds nothing; a later exposed wave finds /.env proof.
    # With a terminal success flag the hunt would stop and miss it.
    import proof_hunt as PH
    later = proof()
    server = WiringServer(inert=True, env_proof=later)
    original = PH._web.WebClient
    PH._web.WebClient = lambda url, timeout=8.0, **kw: server
    try:
        got = PH.solve_targets([target()], {"max_requests": 60, "deadline": None})
    finally:
        PH._web.WebClient = original
    check("non-terminal: an empty contract run does not suppress the later wave that finds the proof",
          got == {"proof-1": later}, (got, server.log))


def test_proof_hunt_forwards_get_only():
    # Kills dropping "get_only" from proof_hunt's peer ctx: the executor's ctx
    # must carry the lane's flag on the dispatch path (and not carry it when the
    # caller did not set it).  The spy only observes and delegates to the real
    # executor, which still runs and banks the proof.
    import proof_hunt as PH
    for flag in (True, False):
        server = WiringServer()
        seen = []
        real_solve = CE.solve

        def spy(target_, ctx=None):
            seen.append(bool((ctx or {}).get("get_only")))
            return real_solve(target_, ctx)

        original = PH._web.WebClient
        PH._web.WebClient = lambda url, timeout=8.0, **kw: server
        CE.solve = spy
        ctx = {"max_requests": 40, "deadline": None}
        if flag:
            ctx["get_only"] = True
        try:
            got = PH.solve_targets([target()], ctx)
        finally:
            PH._web.WebClient = original
            CE.solve = real_solve
        check(f"proof_hunt get_only={flag}: the contract executor was dispatched once",
              len(seen) == 1, seen)
        check(f"proof_hunt get_only={flag}: the peer ctx carried get_only={flag}",
              seen == [flag], seen)
        check(f"proof_hunt get_only={flag}: the GET contract proof is still banked",
              got == {"proof-1": server.answer}, (got, server.log))


def main():
    old = dict(os.environ)
    try:
        os.environ.pop("CTF_WEB_CONTRACT_EXECUTOR", None)
        test_get_contract_fail_open()
        test_novelty_subtracts_control_proof()
        test_two_novel_values_are_ambiguous()
        test_effect_must_be_confirmed()
        test_inert_contract_is_non_terminal()
        test_audit_post_is_gated_by_default()
        test_audit_post_refused_when_event_forbids_state_change()
        test_audit_post_runs_under_policy_and_permissive_event()
        test_get_only_overrides_permissive_event_and_policy()
        test_delegated_identity_runs_get_only()
        test_delegated_identity_header_control_precedes_mutation()
        test_destructive_mutation_sends_nothing()
        test_route_allowed_refusal_sends_nothing()
        test_incomplete_contract_sends_nothing()
        test_no_differential_sends_nothing()
        test_contract_from_preloaded_clues()
        test_disabled_executor_is_a_named_stop()
        test_budget_reservation_boundary()
        test_budget_blocks_partial_mutation()
        test_near_deadline_refuses_mutation_sequence()
        test_json_content_type_on_body()
        test_control_transport_error_stops_before_mutation()
        test_kill_switch_fails_closed_when_workdir_unreadable()
        test_kill_switch_off_file()
        test_self_built_client_inherits_get_only()
        test_header_name_must_be_a_token()
        test_denied_headers_send_nothing()
        test_header_value_control_chars_send_nothing()
        test_header_destructive_value_sends_nothing()
        test_destructive_param_name_refused_before_follow_up()
        test_nested_target_query_value_never_sent()
        test_proof_hunt_wiring()
        test_proof_hunt_inert_contract_is_non_terminal()
        test_proof_hunt_forwards_get_only()
    finally:
        os.environ.clear()
        os.environ.update(old)
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} of {CHECKS[0]} checks")
        return 1
    print(f"PASS: {CHECKS[0]} checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
