"""B-201: the per-role, per-difficulty model router (ctf/router.py), its [routing] profile table
(ctf/event.py), the escalation roster it orders (ctf/escalation.py) and `ctf model-route`.

Every profile is the shipped csctf profile with a synthetic [routing] table; every ledger is synthetic.
No model is called and nothing is launched.
"""
from __future__ import annotations

import copy
import dataclasses
import json
import tomllib

import pytest

from ctf import cli, escalation, event, ledger, paths, router
from ctf.cli import escalate as cli_escalate
from tools.ledger import ab_verify, pricing

PRICES = pricing.load_prices()
BASE = tomllib.loads((paths.event_dir("csctf") / "event.toml").read_text(encoding="utf-8"))


def prof_with(routing: dict | None = None, *, models: dict | None = None, budget: dict | None = None):
    data = copy.deepcopy(BASE)
    if routing is not None:
        data["routing"] = routing
    if models is not None:
        data["models"] = {**data.get("models", {}), **models}
    if budget is not None:
        data["budget"] = {**data.get("budget", {}), **budget}
    return event.parse(data, src="test.toml")


def rt(routing=None, *, records=(), **kw) -> router.Router:
    return router.Router(prof_with(routing, **kw), prices=PRICES, records=list(records))


def approve(model: str, approved: bool = True) -> dict:
    rec = {"event": "ab_verify", "approved": approved, "by": "max"}
    if model:
        rec["approved_model"] = model
    return rec


# ----------------------------------------------------------------------------- the profile table

def test_no_routing_table_means_not_opted_in():
    p = prof_with()
    assert p.routing is None
    assert router.Router(p, prices=PRICES, records=[]).opted_in is False


def test_routing_table_parses_rules_with_wildcard_defaults():
    p = prof_with({"default_difficulty": "easy", "verify_candidate": "claude-sonnet-5-5",
                   "top_categories": ["Pwn", " crypto "],
                   "route": [{"role": "solve", "difficulty": "warmup", "model": "claude-sonnet-5-5",
                              "effort": "low"},
                             {"effort": "high", "difficulty": "hard"}]})
    r = p.routing
    assert r.default_difficulty == "easy" and r.verify_candidate == "claude-sonnet-5-5"
    assert r.top_categories == ("pwn", "crypto")
    a, b = r.rules
    assert (a.role, a.difficulty, a.harness, a.model, a.effort, a.tier, a.budget_usd, a.index) == \
        ("solve", "warmup", "*", "claude-sonnet-5-5", "low", "default", None, 0)
    assert (b.role, b.harness, b.model, b.index) == ("*", "*", None, 1)
    assert a.specificity == 3 and b.specificity == 1


@pytest.mark.parametrize("rule, msg", [
    ({"role": "reviewer", "model": "claude-opus-5-5"}, "routing.route[0].role must be one of"),
    ({"difficulty": "insane", "model": "claude-opus-5-5"}, "routing.route[0].difficulty must be one of"),
    ({"harness": "gemini", "model": "claude-opus-5-5"}, "routing.route[0].harness must be one of"),
    ({"model": "claude-opus-5-5", "effort": "ultra"}, "effort must be one of"),
    ({"role": "solve"}, "routes nothing"),
    ({"model": "Not A Model"}, "is not a model id"),
    ({"model": "gpt-6-astra", "tier": "ultrafast"}, "needs an explicit budget_usd"),
    ({"effort": "low", "tier": "ultrafast", "budget_usd": 5}, "needs a model"),
    ({"model": "gpt-6-astra", "budget_usd": 5}, "applies only to a speed tier"),
    ({"model": "gpt-6-astra", "tier": "ultrafast", "budget_usd": 0}, "must be > 0"),
    ({"model": "gpt-6-astra", "tier": "ultrafast", "budget_usd": 251}, "above budget.ceiling"),
    ({"model": "gpt-6-astra", "colour": "red"}, "unknown key(s): routing.route[0].colour"),
])
def test_bad_rules_are_refused_by_name(rule, msg):
    with pytest.raises(event.EventError) as ei:
        prof_with({"route": [rule]})
    assert msg in str(ei.value)


def test_a_repeated_rule_key_is_refused():
    with pytest.raises(event.EventError) as ei:
        prof_with({"route": [{"role": "solve", "model": "claude-opus-5-5"},
                             {"role": "solve", "effort": "low"}]})
    assert "routing.route[1] repeats role/difficulty/harness solve/*/*" in str(ei.value)
    # the same role on another difficulty is a different key
    prof_with({"route": [{"role": "solve", "model": "claude-opus-5-5"},
                         {"role": "solve", "difficulty": "hard", "effort": "low"}]})


@pytest.mark.parametrize("routing, msg", [
    ({"default_difficulty": "trivial"}, "routing.default_difficulty must be one of"),
    ({"verify_candidate": "Sonnet!"}, "routing.verify_candidate"),
    ({"colour": 1}, "unknown key(s): routing.colour"),
    ({"route": ["solve"]}, "[routing.route[0]] must be a table"),
])
def test_bad_routing_tables_are_refused(routing, msg):
    with pytest.raises(event.EventError) as ei:
        prof_with(routing)
    assert msg in str(ei.value)


# ----------------------------------------------------------------------------- price validation

@pytest.mark.parametrize("routing, models, msg", [
    ({"route": [{"model": "claude-unpriced-9"}]}, None, "routing.route[0]: model 'claude-unpriced-9' is not in"),
    ({}, {"primary": "claude-unpriced-9"}, "models.primary: model 'claude-unpriced-9'"),
    ({}, {"fallback": ["gpt-unpriced"]}, "models.fallback[0]: model 'gpt-unpriced'"),
    ({"verify_candidate": "claude-unpriced-9"}, None, "routing.verify_candidate: model"),
    ({"route": [{"harness": "codex", "model": "claude-opus-5-5"}]}, None,
     "harness 'codex' but model 'claude-opus-5-5' is a claude model"),
    ({"route": [{"model": "gpt-6.1-sol", "tier": "ultrafast", "budget_usd": 5}]}, None,
     "tier 'ultrafast' is not priced for 'gpt-6.1-sol'"),
    ({"route": [{"model": "claude-sonnet-5-5", "tier": "fast", "budget_usd": 5}]}, None,
     "tier 'fast' is not priced for 'claude-sonnet-5-5'"),
])
def test_every_model_and_tier_must_be_priced(routing, models, msg):
    with pytest.raises(router.RouterError) as ei:
        rt(routing, models=models)
    assert msg in str(ei.value)


def test_the_router_itself_refuses_a_speed_tier_without_a_budget():
    # ctf/event.py refuses this rule when it parses a profile, so build the Routing directly: a profile
    # assembled in code (not parsed) must still not reach a launch with an unbudgeted speed tier.
    base = prof_with({})
    bad = dataclasses.replace(base, routing=event.Routing(rules=(
        event.RouteRule(role="build", model="gpt-6-astra", tier="ultrafast", budget_usd=None, index=0),)))
    with pytest.raises(router.RouterError) as ei:
        router.Router(bad, prices=PRICES, records=[])
    assert "routing.route[0]: tier 'ultrafast' needs an explicit budget_usd (B-033)" in str(ei.value)
    ok = dataclasses.replace(base, routing=event.Routing(rules=(
        event.RouteRule(role="build", model="gpt-6-astra", tier="ultrafast", budget_usd=4.0, index=0),)))
    assert router.Router(ok, prices=PRICES, records=[]).resolve("build").budget_usd == 4.0


def test_a_corrupt_event_ledger_is_a_named_router_error(tmp_path):
    p = prof_with({"verify_candidate": "claude-sonnet-5-5"})
    lp = ledger.path(tmp_path)
    lp.parent.mkdir(parents=True, exist_ok=True)
    lp.write_text('{"event": "ab_verify", "approved": true}\n{not json\n', encoding="utf-8")
    with pytest.raises(router.RouterError) as ei:
        router.Router(p, prices=PRICES, workdir=tmp_path)
    msg = str(ei.value)
    assert str(lp) in msg and "cannot be read for the B-096 A/B gate" in msg and ":2: corrupt" in msg


def test_problems_are_reported_together():
    with pytest.raises(router.RouterError) as ei:
        rt({"route": [{"role": "solve", "model": "claude-unpriced-9"},
                      {"role": "build", "model": "gpt-unpriced"}]})
    assert "claude-unpriced-9" in str(ei.value) and "gpt-unpriced" in str(ei.value)


def test_priced_speed_tiers_are_accepted():
    r = rt({"route": [{"role": "build", "model": "gpt-6-astra", "tier": "ultrafast", "budget_usd": 40},
                      {"role": "doc", "model": "claude-opus-5-5", "tier": "fast", "budget_usd": 5}]})
    b = r.resolve("build", "medium")
    assert (b.model, b.tier, b.budget_usd, b.speed_tier) == ("gpt-6-astra", "ultrafast", 40.0, True)
    assert router.tiers_for("gpt-6-astra", PRICES) == ("default", "priority", "fast", "ultrafast")
    assert router.tiers_for("claude-sonnet-5-5", PRICES) == ("default",)
    assert router.model_harness("gpt-6-luna", PRICES) == "codex"


def test_the_shipped_profiles_route_cleanly():
    for slug in event.available():
        r = router.Router(event.load(slug), prices=PRICES, records=[])
        assert len(r.table()) == len(router.ROLES) * len(router.DIFFICULTIES)


# ----------------------------------------------------------------------------- built-in defaults

def test_default_effort_follows_the_b095_ramp_by_difficulty():
    r = rt({})
    got = {d: r.resolve("solve", d).effort for d in router.DIFFICULTIES}
    assert got == {"warmup": "low", "easy": "medium", "medium": "medium", "hard": "high"}
    low = rt({}, models={"effort": "minimal"})
    assert low.resolve("solve", "warmup").effort == "minimal"          # clamped at the bottom
    assert low.resolve("solve", "hard").effort == "low"
    top = rt({}, models={"effort": "max"})
    assert top.resolve("solve", "hard").effort == "max"                # clamped at the top


def test_default_models_by_role():
    r = rt({}, models={"docs": "claude-haiku-5-5"})
    assert r.resolve("solve").model == "claude-opus-5-5"
    assert r.resolve("build").model == "claude-opus-5-5"
    assert r.resolve("doc").model == "claude-haiku-5-5"                # B-097's docs model
    assert r.resolve("solve").tier == "default" and r.resolve("solve").source == "default"


def test_default_difficulty_applies_when_none_is_asked():
    r = rt({"default_difficulty": "warmup"})
    d = r.resolve("solve")
    assert d.difficulty == "warmup" and d.asked_difficulty is None and d.effort == "low"


# ----------------------------------------------------------------------------- the B-096 verify gate

def test_verify_stays_on_primary_without_an_ab_record():
    r = rt({"verify_candidate": "claude-sonnet-5-5"})
    v = r.resolve("verify")
    assert v.model == "claude-opus-5-5"
    assert any("no approving ab_verify record" in n for n in v.notes)


def test_verify_moves_to_the_candidate_after_an_approving_record():
    r = rt({"verify_candidate": "claude-sonnet-5-5"}, records=[approve("claude-sonnet-5-5")])
    assert r.resolve("verify").model == "claude-sonnet-5-5" and r.resolve("verify").notes == ()


def test_an_unapproved_record_naming_the_candidate_keeps_verify_on_primary():
    r = rt({"verify_candidate": "claude-sonnet-5-5"}, records=[approve("claude-sonnet-5-5", False)])
    assert r.resolve("verify").model == "claude-opus-5-5"


def test_an_explicit_verify_rule_is_held_on_primary_until_approved():
    rule = {"route": [{"role": "verify", "model": "claude-sonnet-5-5", "effort": "low"}]}
    held = rt(rule).resolve("verify")
    assert held.model == "claude-opus-5-5" and held.effort == "low"   # the effort still applies
    assert held.model_rule is None and held.source == "rule:0"         # the effort's rule
    assert any("verify held on claude-opus-5-5" in n for n in held.notes)
    ok = rt(rule, records=[approve("claude-sonnet-5-5")]).resolve("verify")
    assert ok.model == "claude-sonnet-5-5" and ok.model_rule == 0
    # an approval for another model does not open this one
    other = rt(rule, records=[approve("claude-haiku-5-5")]).resolve("verify")
    assert other.model == "claude-opus-5-5"


def test_the_ab_gate_reads_the_event_ledger(tmp_path):
    p = prof_with({"verify_candidate": "claude-sonnet-5-5"})
    assert router.Router(p, prices=PRICES, workdir=tmp_path).resolve("verify").model == "claude-opus-5-5"
    res = ab_verify.ABResult(1, 1, [], [])
    ab_verify.record_result(tmp_path, res, by="max", approved=True, approved_model="claude-sonnet-5-5")
    assert router.Router(p, prices=PRICES, workdir=tmp_path).resolve("verify").model == "claude-sonnet-5-5"


# ----------------------------------------------------------------------------- rule matching

ROUTES = {"route": [
    {"model": "claude-opus-5-5", "effort": "medium"},                                    # 0: any
    {"role": "solve", "difficulty": "warmup", "model": "claude-sonnet-5-5", "effort": "low"},   # 1
    {"role": "solve", "model": "claude-opus-5-5"},                                       # 2
    {"difficulty": "hard", "effort": "high"},                                            # 3
    {"role": "solve", "difficulty": "hard", "model": "claude-fable-5-1"},                 # 4
    {"harness": "codex", "role": "solve", "model": "gpt-6-astra", "effort": "medium"},   # 5
    {"harness": "codex", "role": "solve", "difficulty": "warmup", "model": "gpt-6.1-terra"},   # 6
    {"role": "build", "model": "gpt-6.1-sol", "effort": "low"},                          # 7
]}


def test_the_most_specific_rule_wins_per_field():
    r = rt(ROUTES)
    w = r.resolve("solve", "warmup")
    assert (w.model, w.effort, w.model_rule, w.effort_rule) == ("claude-sonnet-5-5", "low", 1, 1)
    h = r.resolve("solve", "hard")
    # model from the solve/hard rule (4), effort from the */hard rule (3): the most specific naming each
    assert (h.model, h.effort, h.model_rule, h.effort_rule) == ("claude-fable-5-1", "high", 4, 3)
    m = r.resolve("solve", "medium")
    assert (m.model, m.effort, m.model_rule, m.effort_rule) == ("claude-opus-5-5", "medium", 2, 0)
    o = r.resolve("orchestrate", "easy")
    assert (o.model, o.model_rule) == ("claude-opus-5-5", 0)


def test_a_harness_rule_only_matches_a_launch_on_that_harness():
    r = rt(ROUTES)
    c = r.resolve("solve", "warmup", harness="codex")
    assert (c.model, c.harness, c.effort) == ("gpt-6.1-terra", "codex", "medium")   # effort from rule 5
    assert r.resolve("solve", "warmup").model == "claude-sonnet-5-5"            # harness-free ignores 6
    assert r.resolve("solve", "warmup", harness="claude").model == "claude-sonnet-5-5"


def test_a_model_of_the_other_harness_is_not_routed_but_said():
    r = rt(ROUTES)
    b = r.resolve("build", "medium", harness="claude")      # rule 7 names a codex model
    assert b.model is None and b.harness is None and b.effort == "low"
    assert any("no route names a claude model" in n for n in b.notes)
    assert r.resolve("build", "medium", harness="codex").model == "gpt-6.1-sol"


def test_top_categories_reserve_the_hard_route():
    r = rt({**ROUTES, "top_categories": ["pwn", "crypto", "osint"]})
    web = r.resolve("solve", "hard", category="Web")
    assert web.difficulty == "medium" and web.model == "claude-opus-5-5" and web.effort == "medium"
    assert any("not in routing.top_categories" in n for n in web.notes)
    pwn = r.resolve("solve", "hard", category="PWN")
    assert pwn.difficulty == "hard" and pwn.model == "claude-fable-5-1"
    assert r.resolve("solve", "hard").difficulty == "hard"                # unknown category: as asked
    assert r.resolve("build", "hard", category="Web").difficulty == "hard"   # solve only
    no_top = rt(ROUTES)
    assert no_top.resolve("solve", "hard", category="Web").difficulty == "hard"


@pytest.mark.parametrize("call, msg", [
    (lambda r: r.resolve("reviewer"), "unknown role"),
    (lambda r: r.resolve("solve", "insane"), "unknown difficulty"),
    (lambda r: r.resolve("solve", harness="gemini"), "unknown harness"),
])
def test_unknown_inputs_are_refused(call, msg):
    with pytest.raises(router.RouterError) as ei:
        call(rt(ROUTES))
    assert msg in str(ei.value)


def test_route_ledger_fields():
    r = rt({"route": [{"role": "build", "model": "gpt-6-astra", "tier": "ultrafast", "budget_usd": 40}]})
    assert r.resolve("build", "easy", category="Misc").ledger_fields() == {
        "difficulty": "easy", "effort": "medium", "tier": "ultrafast", "route": "rule:0",
        "category": "Misc", "tier_budget_usd": 40.0}
    assert r.resolve("solve", "warmup").ledger_fields() == {"difficulty": "warmup", "effort": "low",
                                                            "tier": "default", "route": "default"}


# ----------------------------------------------------------------------------- the roster

def test_roster_is_the_route_then_harder_routes_then_the_profile():
    r = rt(ROUTES)
    assert r.roster("solve", "warmup") == ["claude-sonnet-5-5", "gpt-6.1-terra", "claude-opus-5-5",
                                           "gpt-6-astra", "claude-fable-5-1", "claude-opus-4-8"]
    assert r.roster("solve", "hard") == ["claude-fable-5-1", "gpt-6-astra", "claude-opus-5-5",
                                         "claude-opus-4-8"]


def test_roster_skips_the_hard_route_for_a_non_top_category():
    r = rt({**ROUTES, "top_categories": ["pwn"]})
    assert "claude-fable-5-1" not in r.roster("solve", "medium", category="Web")
    assert "claude-fable-5-1" in r.roster("solve", "medium", category="pwn")


# ----------------------------------------------------------------------------- escalation

def _launch(workdir, cid, ts, **fields):
    rec = {"ts": float(ts), "event": "agent_launch", "challenge_id": cid, "harness": "claude", **fields}
    p = ledger.path(workdir)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")


def _esc(p, wd, now, **kw):
    return escalation.Escalator(p, workdir=wd, clock=lambda: now, read_claims=lambda _w: ({}, []), **kw)


def test_escalation_orders_the_roster_by_the_challenges_route(tmp_path):
    p = prof_with(ROUTES)
    r = router.Router(p, prices=PRICES, records=[])
    _launch(tmp_path, "7", 1000, model="claude-sonnet-5-5", difficulty="warmup")
    made = _esc(p, tmp_path, 1000 + escalation.THIRD_S + 1, router=r).once()
    by = {d.action: d for d in made}
    # the owner is the warmup route's sonnet; the second goes to the next routed model, not models.fallback
    assert by["second"].to_model == "gpt-6.1-terra" and by["third"].to_model == "claude-opus-5-5"
    assert by["second"].from_model == "claude-sonnet-5-5"
    # the ramp starts at the warmup route's effort (low): second +1, third +2
    assert (by["second"].effort, by["third"].effort) == ("medium", "high")


def test_escalation_without_a_router_is_unchanged(tmp_path):
    p = prof_with(ROUTES)
    _launch(tmp_path, "7", 1000, model="claude-opus-5-5", difficulty="warmup")
    made = _esc(p, tmp_path, 1000 + escalation.THIRD_S + 1).once()
    by = {d.action: d for d in made}
    assert by["second"].to_model == "claude-opus-4-8" and by["second"].effort == "high"
    assert by["third"].status == escalation.STATUS_NO_MODEL


def test_escalation_reads_difficulty_and_category_from_the_first_launch(tmp_path):
    p = prof_with({**ROUTES, "top_categories": ["pwn"]})
    r = router.Router(p, prices=PRICES, records=[])
    _launch(tmp_path, "9", 1000, difficulty="hard", category="Web")
    _launch(tmp_path, "9", 1010, difficulty="warmup", category="pwn")      # a later launch: ignored
    view = _esc(p, tmp_path, 1001, router=r, record=False).show("9")
    assert view["difficulty"] == "hard" and view["category"] == "Web"
    # hard on a non-top category routes as medium: opus, at the medium effort
    assert view["owner_model"] == "claude-opus-5-5" and view["owner_effort"] == "medium"
    assert "claude-fable-5-1" not in view["roster"]


def test_the_ramp_starts_from_the_effort_the_first_launch_recorded(tmp_path):
    # A codex solve at warmup ran at "minimal" (an explicit --effort, recorded by record_route); the
    # harness-free route would say "low". The ramp steps from what actually launched.
    p = prof_with(ROUTES)
    r = router.Router(p, prices=PRICES, records=[])
    _launch(tmp_path, "7", 1000, harness="codex", model="gpt-6.1-terra", difficulty="warmup",
            effort="minimal")
    _launch(tmp_path, "7", 1010, harness="codex", model="gpt-6-astra", difficulty="warmup",
            effort="max")                                   # a later launch: not the base
    esc = _esc(p, tmp_path, 1000 + escalation.THIRD_S + 1, router=r)
    assert esc.show("7")["owner_effort"] == "minimal"
    by = {d.action: d for d in esc.once()}
    assert (by["second"].effort, by["third"].effort) == ("low", "medium")


def test_with_no_recorded_effort_the_base_is_the_launch_harness_route(tmp_path):
    # ROUTES: codex solve rule 5 (effort medium) is more specific than solve/warmup rule 1 (low), but only
    # on a codex launch; harness-free (and on claude) the warmup effort is low.
    p = prof_with(ROUTES)
    r = router.Router(p, prices=PRICES, records=[])
    _launch(tmp_path, "7", 1000, harness="codex", difficulty="warmup")
    _launch(tmp_path, "8", 1000, harness="claude", difficulty="warmup")
    _launch(tmp_path, "9", 1000, harness="", difficulty="warmup")
    esc = _esc(p, tmp_path, 1001, router=r, record=False)
    assert esc.show("7")["owner_effort"] == "medium"
    assert esc.show("8")["owner_effort"] == "low"
    assert esc.show("9")["owner_effort"] == "low"


def test_a_recorded_effort_is_ignored_without_a_router(tmp_path):
    p = prof_with(ROUTES)
    _launch(tmp_path, "7", 1000, difficulty="warmup", effort="minimal")
    view = _esc(p, tmp_path, 1001, record=False).show("7")
    assert view["owner_effort"] == p.models.effort


def test_an_explicit_escalator_effort_beats_the_route(tmp_path):
    p = prof_with(ROUTES)
    r = router.Router(p, prices=PRICES, records=[])
    _launch(tmp_path, "7", 1000, difficulty="warmup")
    made = _esc(p, tmp_path, 1000 + escalation.SECOND_S + 1, router=r, effort="high").once()
    assert made[0].effort == "max"


def test_with_no_launch_difficulty_the_default_difficulty_routes(tmp_path):
    p = prof_with({**ROUTES, "default_difficulty": "hard"})
    r = router.Router(p, prices=PRICES, records=[])
    _launch(tmp_path, "7", 1000)
    view = _esc(p, tmp_path, 1001, router=r, record=False).show("7")
    assert view["difficulty"] is None and view["owner_model"] == "claude-fable-5-1"
    assert view["owner_effort"] == "high"


def _write_profile(tmp_path, routing) -> str:
    data = copy.deepcopy(BASE)
    data["routing"] = routing
    lines = []

    def dump(prefix, d):
        scal = {k: v for k, v in d.items() if not isinstance(v, dict) and not
                (isinstance(v, list) and v and isinstance(v[0], dict))}
        tables = {k: v for k, v in d.items() if isinstance(v, dict)}
        arrays = {k: v for k, v in d.items() if isinstance(v, list) and v and isinstance(v[0], dict)}
        if prefix:
            lines.append(f"[{prefix}]")
        for k, v in scal.items():
            lines.append(f"{k} = {_toml(v)}")
        for k, v in tables.items():
            dump(f"{prefix}.{k}" if prefix else k, v)
        for k, v in arrays.items():
            for item in v:
                lines.append(f"[[{prefix}.{k}]]" if prefix else f"[[{k}]]")
                for kk, vv in item.items():
                    lines.append(f"{kk} = {_toml(vv)}")
    dump("", data)
    f = tmp_path / "event.toml"
    f.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(f)


def _toml(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, str):
        return json.dumps(v)
    if isinstance(v, list):
        return "[" + ", ".join(_toml(x) for x in v) + "]"
    if hasattr(v, "isoformat"):
        return v.isoformat().replace("+00:00", "Z")
    raise TypeError(v)


def test_ctf_escalate_uses_the_profiles_router(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    prof_file = _write_profile(tmp_path, ROUTES)
    _launch(tmp_path / "work", "7", 1.0, model="claude-sonnet-5-5", difficulty="warmup")
    rc = cli.main(["escalate", "--profile", prof_file, "once", "--json"])
    out = [json.loads(x) for x in capsys.readouterr().out.splitlines()]
    assert rc == 0
    by = {d["action"]: d for d in out}
    assert by["second"]["to_model"] == "gpt-6.1-terra" and by["second"]["effort"] == "medium"


def test_ctf_escalate_refuses_an_unpriced_routing_table(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    prof_file = _write_profile(tmp_path, {"route": [{"model": "claude-unpriced-9"}]})
    rc = cli.main(["escalate", "--profile", prof_file, "once"])
    assert rc == 2 and "claude-unpriced-9" in capsys.readouterr().err
    assert cli_escalate._router(prof_with(), tmp_path) is None       # no [routing]: no router


# ----------------------------------------------------------------------------- ctf model-route

def test_model_route_cli(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    good = _write_profile(tmp_path, ROUTES)
    assert cli.main(["model-route", "--profile", good, "check"]) == 0
    assert "routing ok" in capsys.readouterr().out
    assert cli.main(["model-route", "--profile", good, "resolve", "solve", "--difficulty", "hard",
                     "--json"]) == 0
    got = json.loads(capsys.readouterr().out)
    assert got["model"] == "claude-fable-5-1" and got["effort"] == "high" and got["source"] == "rule:4"
    assert cli.main(["model-route", "--profile", good, "show", "--harness", "codex", "--json"]) == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown["opted_in"] is True
    cell = next(x for x in shown["routes"] if x["role"] == "solve" and x["difficulty"] == "warmup")
    assert cell["model"] == "gpt-6.1-terra"
    assert len(shown["routes"]) == len(router.ROLES) * len(router.DIFFICULTIES)
    assert cli.main(["model-route", "--event", "csctf", "show"]) == 0
    assert "has no [routing] table" in capsys.readouterr().out
    bad_dir = tmp_path / "bad"
    bad_dir.mkdir()
    bad = _write_profile(bad_dir, {"route": [{"model": "gpt-6.1-sol", "tier": "ultrafast",
                                              "budget_usd": 5}]})
    assert cli.main(["model-route", "--profile", bad, "check"]) == 2
    assert "not priced for 'gpt-6.1-sol'" in capsys.readouterr().err
