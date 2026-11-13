"""B-184: web contract library, fingerprint-first router and request minimization.

Every test drives the real module offline (no socket, no live service): the
fingerprint router over the shipped cold/agent/none class matrix, the route-trust
rule for clue-advertised URLs, the simplest-first forge grid with label-to-wire
mutation, the request-minimization plan, and the timed-mode replay runner driven
by an injected client and an injected step clock.  Each assertion fails when the
behaviour is wrong (a real target, a mutated fingerprint, a different ordering).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from ctf import event, paths
from ctf.engines import manifest

ROOT = paths.repo_root()
WEB = ROOT / "solvers" / "web"
for _p in (str(WEB), str(ROOT / "solvers" / "toolkits")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import contract_library as cl  # noqa: E402 -- the engine under test, on the engine path


# --------------------------------------------------------------------------- matrix loading

def test_shipped_matrix_loads_and_has_a_catch_all():
    m = cl.load_matrix()
    assert len(m.classes) >= 8
    assert any(c.is_catch_all for c in m.classes)
    # the catch-all must be an agent disposition, never a cold reader
    catch = next(c for c in m.classes if c.is_catch_all)
    assert catch.disposition == "agent"


def test_missing_matrix_fails_loudly(tmp_path):
    with pytest.raises(cl.ContractLibraryError) as e:
        cl.load_matrix(tmp_path / "nope.json")
    assert "not readable" in str(e.value)


def test_bad_json_fails_loudly(tmp_path):
    p = tmp_path / "m.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(cl.ContractLibraryError):
        cl.load_matrix(p)


def test_matrix_without_catch_all_is_refused(tmp_path):
    # a library with only a cold class and no catch-all would fail a novel bug
    # closed to nothing -- that must raise, not route silently.
    data = {"schema": 1, "threshold": 3, "classes": [
        {"id": "only", "disposition": "cold", "handler": "x", "fingerprint": {"category": ["web"]}}]}
    p = tmp_path / "m.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(cl.ContractLibraryError) as e:
        cl.load_matrix(p)
    assert "catch_all" in str(e.value)


def test_bad_disposition_is_refused(tmp_path):
    data = {"schema": 1, "classes": [
        {"id": "a", "disposition": "maybe", "handler": "x", "fingerprint": {}},
        {"id": "z", "disposition": "agent", "handler": "agent", "fingerprint": {"catch_all": True}}]}
    p = tmp_path / "m.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(cl.ContractLibraryError) as e:
        cl.load_matrix(p)
    assert "disposition" in str(e.value)


def test_duplicate_class_id_is_refused(tmp_path):
    data = {"schema": 1, "classes": [
        {"id": "a", "disposition": "cold", "handler": "x", "fingerprint": {}},
        {"id": "a", "disposition": "cold", "handler": "x", "fingerprint": {}},
        {"id": "z", "disposition": "agent", "handler": "agent", "fingerprint": {"catch_all": True}}]}
    p = tmp_path / "m.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(cl.ContractLibraryError) as e:
        cl.load_matrix(p)
    assert "duplicate" in str(e.value)


# --------------------------------------------------------------------------- disposition matrix

def test_disposition_matrix_records_cold_and_agent():
    dm = cl.disposition_matrix()
    assert dm["post_event_forge"]["disposition"] == "cold"
    assert dm["novel_web"]["disposition"] == "agent"
    assert dm["protocol_class_novel"]["disposition"] == "agent"
    assert dm["target_described_contract"]["handler"] == "web.contract_executor"


# --------------------------------------------------------------------------- fingerprint router

def test_every_fixture_routes_to_its_own_class():
    m = cl.load_matrix()
    for fid, ev in m.fixtures.items():
        cls = m.by_id(fid)
        if cls.is_catch_all:
            # the catch-all wins only through the threshold fall-through, never
            # on raw score; check its fixture resolves to it via route().
            assert cl.route(ev, m)["chosen"]["id"] == fid
            continue
        ranked = cl.fingerprint(ev, m)
        assert ranked[0].cls.id == fid, f"{fid} routed to {ranked[0].cls.id}"
        assert ranked[0].score >= m.threshold, f"{fid} did not clear the threshold"


def test_fixture_class_beats_the_others_discriminatively():
    # the post-event-forge fixture must not merely tie: it must outscore the
    # route-trust class, which shares the "web" category.
    m = cl.load_matrix()
    ev = m.fixtures["post_event_forge"]
    ranked = {mt.cls.id: mt.score for mt in cl.fingerprint(ev, m)}
    assert ranked["post_event_forge"] > ranked["route_trust_guarded"]
    assert ranked["post_event_forge"] > ranked["novel_web"]


def test_catch_all_is_always_last_and_scores_zero():
    m = cl.load_matrix()
    ev = m.fixtures["post_event_forge"]
    ranked = cl.fingerprint(ev, m)
    assert ranked[-1].cls.is_catch_all
    assert ranked[-1].score == 0


def test_unknown_evidence_falls_through_to_agent():
    m = cl.load_matrix()
    novel = {"category": "web", "clue": "an unprecedented puzzle with no known markers",
             "method": "GET", "responses": [], "advertised_routes": []}
    decision = cl.route(novel, m)
    assert decision["chosen"]["id"] == "novel_web"
    assert decision["chosen"]["disposition"] == "agent"
    assert decision["plan"]["action"] == "escalate-agent"


def test_mutating_the_fingerprint_changes_the_verdict():
    # strip the markers and status code that make the forge fixture score: the
    # forge class must lose its lead (scoring is real, not hard-coded).
    m = cl.load_matrix()
    ev = dict(m.fixtures["post_event_forge"])
    strong = cl.fingerprint(ev, m)[0].score
    ev2 = dict(ev)
    ev2["responses"] = []  # drop the 400 "missing field" marker+status
    ev2["method"] = "GET"
    weak = {mt.cls.id: mt.score for mt in cl.fingerprint(ev2, m)}["post_event_forge"]
    assert weak < strong


# --------------------------------------------------------------------------- route-trust rule

BASE = "http://target.local/"


def test_advertised_guarded_route_is_trusted():
    v = cl.route_trust("/admin/reset-token", BASE, advertised=["/admin/reset-token"])
    assert v.trusted and v.guarded
    assert "advertised" in v.reason


def test_unadvertised_guarded_route_is_refused():
    v = cl.route_trust("/admin/reset-token", BASE, advertised=[])
    assert not v.trusted and v.guarded


def test_offorigin_advertised_url_is_never_trusted():
    # the SSRF the author did not intend: advertising it must not trust it.
    url = "http://evil.example/admin/reset-token"
    v = cl.route_trust(url, BASE, advertised=[url])
    assert not v.trusted
    assert v.route is None


def test_same_origin_plain_route_is_trusted():
    v = cl.route_trust("/api/notes", BASE)
    assert v.trusted and not v.guarded


def test_structurally_unsafe_route_is_refused():
    # percent-encoded traversal that only decodes to `..` under the proxy fold:
    # advertising it must not trust it, and it has no clean same-origin route.
    url = "/app/%2e%2e/%2e%2e/admin/reset"
    v = cl.route_trust(url, BASE, advertised=[url])
    assert not v.trusted
    assert v.route is None


def test_protocol_relative_authority_route_is_refused():
    v = cl.route_trust("//evil.example/admin", BASE, advertised=["//evil.example/admin"])
    assert not v.trusted and v.route is None


def test_clue_text_can_advertise_a_route():
    clue = "Use the advertised endpoint /admin/delete-session to clear state."
    v = cl.route_trust("/admin/delete-session", BASE, advertised=[], clue=clue)
    assert v.trusted and v.guarded


# --------------------------------------------------------------------------- forge grid

def test_wire_name_variants_order_and_dedupe():
    vs = cl.wire_name_variants("Owner")
    assert vs[0] == "Owner"            # identity first
    assert "owner" in vs               # lowercase present
    assert vs.index("owner") < vs.index("user")   # mechanical before synonym
    assert len(vs) == len(set(vs))     # no duplicates


def test_forge_grid_contains_the_accepted_flat_payload_early():
    grid = cl.forge_grid({"Event": "capture", "Owner": "admin"}, max_candidates=16)
    accepted = [i for i, c in enumerate(grid)
                if c.transport == "json" and c.shape == "flat"
                and set(c.fields) == {"event", "owner"}]
    assert accepted, "flat json {event, owner} must be a candidate"
    assert accepted[0] < 10, "the accepted wire-name payload must appear early"


def test_forge_grid_is_simplest_first():
    grid = cl.forge_grid({"Event": "x", "Owner": "y"})
    comp = [c.complexity for c in grid]
    assert comp == sorted(comp), "candidates must be ordered by non-decreasing complexity"


def test_forge_grid_omits_auth_noise_labels():
    grid = cl.forge_grid({"Event": "x", "Signature": "deadbeef", "Owner": "y"})
    for c in grid:
        flat = c.fields.get("data", c.fields.get("payload", c.fields.get("event", c.fields)))
        assert "signature" not in flat and "Signature" not in flat


def test_forge_grid_includes_nested_shapes_and_is_bounded():
    grid = cl.forge_grid({"Event": "x", "Owner": "y"}, max_candidates=8)
    assert len(grid) <= 8
    big = cl.forge_grid({"Event": "x", "Owner": "y"}, max_candidates=40)
    assert any(c.shape != "flat" for c in big)


def test_forge_grid_empty_fields_is_empty():
    assert cl.forge_grid({}) == []
    assert cl.forge_grid({"Signature": "x"}) == []   # only noise -> nothing to forge


# --------------------------------------------------------------------------- minimization

def test_minimize_drops_auth_noise_first():
    plan = cl.minimize({"fields": {"event": "x", "owner": "a", "signature": "d", "nonce": "1"},
                        "transport": "json"})
    first = plan.candidates[0]
    assert set(first.fields) == {"event", "owner"}
    assert "signature" in first.dropped and "nonce" in first.dropped


def test_minimize_includes_ablations_and_a_full_fallback():
    plan = cl.minimize({"fields": {"event": "x", "owner": "a", "signature": "d"}})
    shapes = [set(c.fields) for c in plan.candidates]
    assert {"event"} in shapes and {"owner"} in shapes     # single-field ablations
    assert shapes[-1] == {"event", "owner", "signature"}   # full original is last


def test_minimize_without_noise_keeps_core():
    plan = cl.minimize({"fields": {"event": "x", "owner": "a"}})
    assert set(plan.candidates[0].fields) == {"event", "owner"}


# --------------------------------------------------------------------------- replay runner

def _forge_client(accept_fields):
    """A fake client: 200 + proof only for the exact accepted wire payload."""
    want = dict(accept_fields)

    def client(req):
        body = req.get("fields", req)
        if body == want:
            return {"status": 200, "body": "proof_" + "a" * 32}
        return {"status": 400, "body": "{\"error\": \"missing field\"}"}

    return client


def test_replay_stops_at_the_first_proof():
    grid = cl.forge_grid({"Event": "capture", "Owner": "admin"})
    plan = [{"fields": c.fields} for c in grid if c.transport == "json" and c.shape == "flat"]
    client = _forge_client({"event": "capture", "owner": "admin"})
    # huntress pays off in proof_<32 hex>; the proof predicate reads the event
    # flag format, so the proof is only recognised under an event that defines it.
    res = cl.replay(plan, client, budget=50, profile=event.load("huntress"))
    assert res.proof == "proof_" + "a" * 32
    assert res.stopped_reason == "proof"
    # it stopped at the accepted candidate, not after sending the whole plan
    assert res.sent <= len(plan)
    assert res.sent == len(res.steps)


def test_replay_budget_caps_sends():
    plan = [{"fields": {"n": i}} for i in range(20)]
    sent = {"n": 0}

    def client(_req):
        sent["n"] += 1
        return {"status": 400, "body": "no"}

    res = cl.replay(plan, client, budget=5)
    assert res.stopped_reason == "budget"
    assert res.sent == 5 and sent["n"] == 5


def test_replay_deadline_uses_the_injected_clock_not_wall_time():
    # drive time with an injected step clock so nothing depends on wall-clock
    # seconds (the suite runs under heavy, variable load). The clock advances one
    # unit per call; a deadline of 3 admits exactly the sends before tick 3.
    plan = [{"fields": {"n": i}} for i in range(20)]
    ticks = {"t": 0}

    def clock():
        ticks["t"] += 1
        return float(ticks["t"])

    def client(_req):
        return {"status": 400, "body": "no"}

    res = cl.replay(plan, client, clock=clock, deadline=3)
    assert res.stopped_reason == "deadline"
    assert res.sent == 2   # ticks 1 and 2 send; tick 3 >= deadline stops before sending


def test_default_proof_reads_the_event_proof_token():
    # the proof predicate is event-driven, never a hardcoded regex: huntress
    # defines proof_<32 hex>, so a proof token is found under huntress...
    hunt = event.load("huntress")
    assert cl.default_proof({"body": "x proof_" + "b" * 32 + " y"}, hunt) == "proof_" + "b" * 32
    assert cl.default_proof({"body": "nothing here"}, hunt) is None
    assert (cl.default_proof({"body": "", "headers": {"X-Flag": "proof_" + "c" * 32}}, hunt)
            == "proof_" + "c" * 32)


def test_default_proof_is_event_driven_not_a_hardcoded_pattern():
    # ...but csctf pays off in flags, not proof_ tokens: a proof_<hex> value is a
    # foreign shape there and must NOT be returned (the former hardcoded
    # proof_[0-9a-f]{32} regex returned it whatever the profile said).
    csctf = event.load("csctf")
    assert cl.default_proof({"body": "x proof_" + "b" * 32 + " y"}, csctf) is None
    # the active csctf flag format is read and a flag{...} is returned
    body = "flag{" + "d" * 32 + "}"
    assert cl.default_proof({"body": body}, csctf) == body


def test_default_proof_handles_null_headers():
    # a response whose headers key is explicitly None must not crash (it did:
    # None.values() -> AttributeError).
    assert cl.default_proof({"body": "flag{" + "d" * 32 + "}", "headers": None},
                            event.load("csctf")) == "flag{" + "d" * 32 + "}"


def test_default_proof_uses_the_event_flag_format():
    prof = event.load("huntress")
    # huntress [proof] is proof_<32 hex>; a flag{...} must also be recognised
    body = "flag{" + "d" * 32 + "}"
    assert cl.default_proof({"body": body}, prof) == body


def test_replay_custom_predicate_overrides_default():
    plan = [{"k": 1}, {"k": 2}]

    def client(req):
        return {"status": 200, "token": req["k"]}

    res = cl.replay(plan, client, proof_predicate=lambda r: "hit" if r.get("token") == 2 else None)
    assert res.proof == "hit" and res.sent == 2


# --------------------------------------------------------------------------- B-149 delegation

def test_target_described_contract_delegates_to_b149_with_a_ready_contract():
    m = cl.load_matrix()
    ev = m.fixtures["target_described_contract"]
    decision = cl.route(ev, m)
    assert decision["chosen"]["id"] == "target_described_contract"
    assert decision["plan"]["engine"] == "web.contract_executor"
    assert decision["plan"]["contract"]["status"] == "ready"


def test_target_described_contract_reports_an_incomplete_graph():
    m = cl.load_matrix()
    ev = dict(m.fixtures["target_described_contract"])
    # an off-origin action route cannot build into a contract
    ev["contract_graph"] = {"action_route": "http://evil.example/x",
                            "control": {"a": 1}, "mutation": {"a": 2}}
    decision = cl.route(ev, m)
    assert decision["plan"]["engine"] == "web.contract_executor"
    assert decision["plan"]["contract"]["status"] == "incomplete"


# --------------------------------------------------------------------------- router scoring boundary

def _bare(**over):
    ev = {"category": "web", "clue": "", "method": "POST", "responses": [],
          "advertised_routes": [], "base_url": "http://target.local/"}
    ev.update(over)
    return ev


def test_fixture_scoring_exactly_at_threshold_is_chosen_not_fallthrough():
    # category(+1) + one forge keyword(+1) + POST method(+1) == threshold 3, and
    # no other class reaches it. The chosen class must be the forge class, not the
    # agent catch-all: pins the `<` boundary (a `<=` mutant falls through here).
    m = cl.load_matrix()
    ev = _bare(clue="forge this request")
    top = cl.fingerprint(ev, m)[0]
    assert top.cls.id == "post_event_forge"
    assert top.score == m.threshold, f"expected exactly {m.threshold}, got {top.score}"
    assert cl.route(ev, m)["chosen"]["id"] == "post_event_forge"


def test_fixture_scoring_one_below_threshold_falls_through():
    # drop the POST method point -> score 2 == threshold-1 -> fall through to the
    # agent catch-all. Pins the boundary from below.
    m = cl.load_matrix()
    ev = _bare(clue="forge this request", method="GET")
    top = cl.fingerprint(ev, m)[0]
    assert top.score == m.threshold - 1
    assert cl.route(ev, m)["chosen"]["id"] == "novel_web"


def test_advertised_route_signal_contributes_one_point():
    # a non-destructive advertised route adds exactly the +1 has_advertised_route
    # bonus for the route-trust class (kills the `score += 1 -> += 0` mutant).
    m = cl.load_matrix()
    base = {mt.cls.id: mt.score for mt in cl.fingerprint(_bare(), m)}["route_trust_guarded"]
    adv = {mt.cls.id: mt.score
           for mt in cl.fingerprint(_bare(advertised_routes=["/api/info"]), m)}["route_trust_guarded"]
    assert adv - base == 1


def test_guarded_advertised_route_adds_three_points():
    # a guarded advertised route adds the +3 discriminator over a plain advertised
    # route (kills the `score += 3 -> += 0` mutant that leaves route_trust_guarded
    # scoring the same with or without its own discriminating signal).
    m = cl.load_matrix()
    plain = {mt.cls.id: mt.score
             for mt in cl.fingerprint(_bare(advertised_routes=["/api/info"]), m)}["route_trust_guarded"]
    guarded = {mt.cls.id: mt.score
               for mt in cl.fingerprint(_bare(advertised_routes=["/admin/reset"]), m)}["route_trust_guarded"]
    assert guarded - plain == 3


# --------------------------------------------------------------------------- route() forge plan

def test_route_forge_plan_includes_the_accepted_flat_payload():
    # the headline end-to-end acceptance: route() on the shipped forge fixture must
    # produce the accepted flat {event, owner} json candidate in its plan. The
    # clue parser must NOT turn "POST ... The form shows Event and Owner" into
    # {POST, Event, The, Owner}.
    m = cl.load_matrix()
    decision = cl.route(m.fixtures["post_event_forge"], m)
    assert decision["chosen"]["id"] == "post_event_forge"
    plan = decision["plan"]
    assert plan["action"] == "forge"
    flat = [c for c in plan["candidates"]
            if c["transport"] == "json" and c["shape"] == "flat"
            and set(c["fields"]) == {"event", "owner"}]
    assert flat, f"flat json {{event, owner}} missing from plan candidates: {plan['candidates']}"


def test_clue_field_extraction_drops_http_verbs_and_stopwords():
    f = cl._fields_from_clue("POST an Event to /api/events to forge ownership. "
                             "The form shows Event and Owner.")
    assert set(f) == {"Event", "Owner"}, f"expected just the form labels, got {set(f)}"


# --------------------------------------------------------------------------- route() trust plan

def test_route_trust_plan_lists_only_trusted_routes():
    # route()'s trust-route plan must surface ONLY trusted routes; an off-origin
    # advertised URL must never appear as actionable (kills dropping the
    # `if t.trusted` filter in _plan_for).
    m = cl.load_matrix()
    ev = dict(m.fixtures["route_trust_guarded"])
    ev["advertised_routes"] = ["/admin/reset-token", "http://evil.example/admin/reset-token"]
    decision = cl.route(ev, m)
    assert decision["chosen"]["id"] == "route_trust_guarded"
    plan = decision["plan"]
    assert plan["action"] == "trust-route"
    urls = [r["url"] for r in plan["routes"]]
    assert "/admin/reset-token" in urls
    assert all(not u.startswith("http://evil.example") for u in urls), urls


# --------------------------------------------------------------------------- route-trust floors

def test_negated_clue_mention_is_not_trusted():
    # a route named inside a negated clause is a warning, not an invitation.
    v = cl.route_trust("/admin/delete-note", BASE, advertised=[],
                       clue="Do not call /admin/delete-note under any circumstances.")
    assert not v.trusted
    # the same route invited affirmatively IS trusted (delete is guarded, not fatal)
    v2 = cl.route_trust("/admin/delete-note", BASE, advertised=[],
                        clue="Use /admin/delete-note to clean up your note.")
    assert v2.trusted and v2.guarded


def test_fatal_route_is_never_trusted_even_when_advertised():
    # the fatal floor: a catastrophic route is refused even advertised verbatim.
    v = cl.route_trust("/admin/shutdown", BASE, advertised=["/admin/shutdown"],
                       clue="Use the advertised endpoint /admin/shutdown.")
    assert not v.trusted and v.guarded
    assert "catastrophic" in v.reason


# --------------------------------------------------------------------------- forge grid query guard

def test_forge_grid_never_emits_nested_query_candidates():
    # a query string carries no nested body; no candidate may pair transport
    # 'query' with a non-flat shape (kills disabling the grid's query guard).
    grid = cl.forge_grid({"Event": "x", "Owner": "y"}, max_candidates=64)
    bad = [c for c in grid if c.transport == "query" and c.shape != "flat"]
    assert not bad, f"query+nested candidates leaked: {[c.to_dict() for c in bad]}"


# --------------------------------------------------------------------------- cold-class handlers

def test_cold_class_without_handler_is_refused(tmp_path):
    data = {"schema": 1, "classes": [
        {"id": "c", "disposition": "cold", "fingerprint": {"category": ["web"]}},
        {"id": "z", "disposition": "agent", "handler": "agent", "fingerprint": {"catch_all": True}}]}
    p = tmp_path / "m.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(cl.ContractLibraryError) as e:
        cl.load_matrix(p)
    assert "no handler" in str(e.value)


def test_shipped_cold_handlers_resolve_to_real_targets():
    # every cold class names a real closer: a module function on this engine, or
    # an engine id whose manifest exists. A typo would route to nothing.
    m = cl.load_matrix()
    cold = [c for c in m.classes if c.disposition == "cold"]
    assert cold
    for c in cold:
        assert c.handler and c.handler != "agent", c.id
        if c.handler.startswith("web.contract_library."):
            fn = c.handler.rsplit(".", 1)[-1]
            assert callable(getattr(cl, fn, None)), f"{c.id}: no function {fn}"
        else:
            man = WEB / (c.handler.split(".", 1)[1] + ".manifest.toml")
            assert man.exists(), f"{c.id}: handler {c.handler} has no manifest at {man}"
            assert manifest.load(man).id == c.handler


# --------------------------------------------------------------------------- manifest wiring

def test_manifest_is_a_valid_library_engine():
    side = WEB / "contract_library.manifest.toml"
    man = manifest.load(side)
    assert man.id == "web.contract_library"
    assert man.lane == "web"
    assert man.has("library")
    # the entry resolves to a real file and function target
    target = man.entry.target_file(ROOT)
    assert target.exists()
    assert man.routes, "a non-retired engine needs at least one route"
