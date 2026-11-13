"""B-008: pay for the build once — pre-event value ranking, the no-allowance-burn gate, and the
default pre-event plan (doctor + rehearsal hooks; B-039 filled them, tests/test_rehearsal.py tests them)."""
from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
import sys

import pytest

from ctf import buildplan as bp
from ctf import event, ledger, paths, preevent

UTC = dt.timezone.utc
START = dt.datetime(2027, 3, 1, 12, tzinfo=UTC)
END = dt.datetime(2027, 3, 3, 12, tzinfo=UTC)
PRE = dt.datetime(2027, 2, 20, tzinfo=UTC)
DURING = dt.datetime(2027, 3, 2, tzinfo=UTC)
AFTER = dt.datetime(2027, 3, 10, tzinfo=UTC)


def profile(categories=("Web", "Reverse engineering"), sectors=(), slug="demo", start=START, end=END):
    return event.parse({
        "slug": slug, "name": "Demo", "categories": list(categories), "sectors": list(sectors),
        "dates": {"start": start, "end": end},
        "platform": {"kind": "ctfd", "base_url": "https://demo.example/"},
        "flag": {"prefixes": ["DEMO"]},
        "rules": {"submit_mode": "auto", "flag_sharing": "allowed", "ai_on_platform": "allowed"},
    })


def item(iid, lane="web", effort="M", closes=0, payoff=None, **kw):
    rec = {"id": iid, "lane": lane, "effort": effort, "closes": [{"ctf": "x", "challenge": f"c{i}"}
                                                                  for i in range(closes)]}
    if payoff is not None:
        rec["payoff"] = payoff
    rec.update(kw)
    return bp.parse_item(rec)


def by_id(ranking):
    return {e.id: e for e in ranking.entries}


# ------------------------------------------------------------------------------------- parsing

def test_payoff_usd_is_the_first_dollar_figure_or_explicit_number():
    assert bp.parse_payoff_usd("$6,887.65 expected (Low $3,774.95, High $9,886.01)") == 6887.65
    assert bp.parse_payoff_usd("saves about $ 120 per event") == 120.0
    assert bp.parse_payoff_usd(250) == 250.0
    assert bp.parse_payoff_usd({"usd": 40.5}) == 40.5
    assert bp.parse_payoff_usd("closes 3 coverage rows; ~0.9M tokens (est)") is None
    assert bp.parse_payoff_usd(None) is None
    assert bp.parse_payoff_usd(True) is None


def test_item_accepts_to_build_category_as_lane_and_counts_closes():
    it = bp.parse_item({"id": "B-1", "category": "Crypto", "effort": "l", "closes": [{}, {}, {}],
                        "payoff": "$300 modeled", "priority": "P1", "title": "t", "extra": 1})
    assert (it.lane, it.effort, it.effort_units, it.closes, it.payoff_usd, it.priority) == \
        ("crypto", "L", 8.0, 3, 300.0, "P1")
    assert bp.parse_item({"id": "B-2", "lane": "web", "category": "ops", "effort": 2.5}).lane == "web"
    assert bp.parse_item({"id": "B-2", "lane": "web", "effort": 2.5}).effort_units == 2.5


@pytest.mark.parametrize("rec,key", [
    ({"lane": "web", "effort": "S"}, ".id"),
    ({"id": "B-1", "effort": "S"}, ".lane"),
    ({"id": "B-1", "lane": "web"}, ".effort"),
    ({"id": "B-1", "lane": "web", "effort": "XXL"}, ".effort"),
    ({"id": "B-1", "lane": "web", "effort": 0}, ".effort"),
    ({"id": "B-1", "lane": "web", "effort": True}, ".effort"),
    ({"id": "B-1", "lane": "web", "effort": "S", "priority": "P9"}, ".priority"),
    ({"id": "B-1", "lane": "web", "effort": "S", "closes": "3"}, ".closes"),
    ({"id": "B-1", "lane": "web", "effort": "S", "sectors": "energy"}, ".sectors"),
])
def test_bad_item_records_fail_naming_the_key(rec, key):
    with pytest.raises(bp.BuildPlanError, match=key.replace(".", r"\.")):
        bp.parse_item(rec)


def test_load_items_shapes_and_errors(tmp_path):
    p = tmp_path / "items.json"
    p.write_text(json.dumps({"items": [{"id": "B-1", "lane": "web", "effort": "S"}]}))
    assert [i.id for i in bp.load_items(p)] == ["B-1"]
    p.write_text(json.dumps([{"id": "B-1", "lane": "web", "effort": "S"},
                             {"id": "B-1", "lane": "pwn", "effort": "M"}]))
    with pytest.raises(bp.BuildPlanError, match="duplicate item id B-1"):
        bp.load_items(p)
    with pytest.raises(bp.BuildPlanError, match="item file not found"):
        bp.load_items(tmp_path / "missing.json")
    p.write_text("{not json")
    with pytest.raises(bp.BuildPlanError, match="not JSON"):
        bp.load_items(p)


def test_category_canonicalisation_covers_the_shipped_profiles():
    assert bp.canon_categories("Reverse engineering") == {"reverse"}
    assert bp.canon_categories("Mobile Android") == {"mobile"}
    assert bp.canon_categories("Metadata Forensics") == {"forensics"}
    assert bp.canon_categories("Binary") == {"reverse", "pwn"}
    assert bp.canon_categories("Steganography") == {"stego"}
    assert bp.canon_categories("Minecraft") == {"minecraft"}


# ------------------------------------------------------------------------------------- ranking

def test_rank_orders_by_modeled_value_per_effort():
    items = [
        item("B-big", effort="L", closes=10),           # 10 / 8  = 1.25
        item("B-small", effort="S", closes=2),          # 2 / 1   = 2.0
        item("B-usd", effort="M", payoff="$900 est"),   # 9 / 3   = 3.0
        item("B-none", effort="S"),                     # 1 / 1   = 1.0 (unquantified floor)
    ]
    r = bp.rank(items, profile())
    assert [e.id for e in r.entries] == ["B-usd", "B-small", "B-big", "B-none"]
    e = by_id(r)
    assert e["B-usd"].score == pytest.approx(3.0) and e["B-big"].score == pytest.approx(1.25)
    assert [x.rank for x in r.entries] == [1, 2, 3, 4]


def test_priority_weights_value():
    r = bp.rank([item("B-p3", closes=4, priority="P3"), item("B-p0", closes=1, priority="P0")], profile())
    assert [e.id for e in r.entries] == ["B-p0", "B-p3"]          # 1*4 = 4 beats 4*0.5 = 2
    assert by_id(r)["B-p0"].value == pytest.approx(4.0)


def test_relevance_from_announced_categories():
    items = [item("B-web", lane="web"), item("B-rev", lane="rev"), item("B-pwn", lane="pwn"),
             item("B-ops", lane="ops"), item("B-stego", lane="stego")]
    e = by_id(bp.rank(items, profile(categories=("Web", "Reverse engineering", "Forensics")),
                      effort_budget=100))
    assert e["B-web"].decision == "approved" and e["B-rev"].decision == "approved"
    assert e["B-ops"].decision == "approved" and "cross-cutting" in e["B-ops"].reason
    assert e["B-stego"].decision == "approved"                   # stego serves forensics
    assert e["B-pwn"].decision == "skip" and e["B-pwn"].score == 0
    assert "serves no announced category" in e["B-pwn"].reason


def test_unannounced_categories_make_lane_builds_wait_for_the_board():
    e = by_id(bp.rank([item("B-web", lane="web"), item("B-ops", lane="harness")],
                      profile(categories=()), effort_budget=100))
    assert e["B-web"].decision == "after-board" and e["B-web"].relevance == 0.5
    assert e["B-ops"].decision == "approved"


def test_sector_builds_wait_for_the_board_even_when_announced():
    items = [item("B-energy", lane="network-ics", title="Energy grid protocol pack"),
             item("B-space", lane="web", sectors=["Space"]),
             item("B-plain", lane="web", title="namespace confusion helper")]   # no word match
    prof = profile(categories=("Web", "Network"), sectors=("energy",))
    e = by_id(bp.rank(items, prof, effort_budget=100))
    assert e["B-energy"].decision == "after-board" and "energy" in e["B-energy"].reason
    assert e["B-space"].decision == "skip" and "not in the event profile" in e["B-space"].reason
    assert e["B-plain"].decision == "approved"


def test_merged_and_non_automatable_items_are_skipped():
    e = by_id(bp.rank([item("B-m", merged_into="B-x"), item("B-n", automatable="no"),
                       item("B-p", automatable="partly")], profile(), effort_budget=100))
    assert e["B-m"].decision == "skip" and "merged into B-x" in e["B-m"].reason
    assert e["B-n"].decision == "skip" and "not automatable" in e["B-n"].reason
    assert e["B-p"].decision == "approved"


def test_default_budget_approves_nothing_and_budget_is_spent_in_score_order():
    items = [item("B-a", effort="S", closes=5), item("B-b", effort="L", closes=20),
             item("B-c", effort="M", closes=3), item("B-d", effort="S", closes=1)]
    assert bp.rank(items, profile()).approved() == []
    assert {e.decision for e in bp.rank(items, profile()).entries} == {"candidate"}
    r = bp.rank(items, profile(), effort_budget=5)
    # scores: a 5, b 2.5, c 1, d 1 (tie: smaller effort first) -> a (1u, 4 left), b (8u) does not
    # fit, d (1u, 3 left), c (3u, 0 left)
    e = by_id(r)
    assert [x.id for x in r.approved()] == ["B-a", "B-d", "B-c"]
    assert e["B-b"].decision == "candidate" and "over the effort budget" in e["B-b"].reason
    with pytest.raises(bp.BuildPlanError, match="effort budget"):
        bp.rank(items, profile(), effort_budget=-1)


def test_board_overrides_profile_categories_and_weights_relevance(tmp_path):
    board = tmp_path / "board.json"
    board.write_text(json.dumps([
        {"category": "Web", "name": "a"}, {"category": "Web", "name": "b"}, {"category": "web"},
        {"category": "Cryptography", "name": "c"},
        {"category": "Forensics", "name": "Substation", "description": "an energy SCADA capture"},
    ]))
    b = bp.load_board(board)
    assert b.categories == {"web": 3, "crypto": 1, "forensics": 1}
    items = [item("B-web", lane="web"), item("B-crypto", lane="crypto"), item("B-pwn", lane="pwn"),
             item("B-energy", lane="forensics", sectors=["power"]),
             item("B-tele", lane="network", sectors=["telecom"])]
    prof = profile(categories=("Pwn",), sectors=("energy", "telecom"))
    r = bp.rank(items, prof, board=b, effort_budget=100, board_source=board)
    e = by_id(r)
    assert r.board_visible and r.board_sha256
    assert e["B-web"].relevance == 1.0 and e["B-web"].decision == "approved"
    assert e["B-crypto"].relevance == pytest.approx(0.5 + 0.5 / 3, abs=1e-3)
    assert e["B-pwn"].decision == "skip"                            # profile said Pwn; the board did not
    assert e["B-energy"].decision == "approved" and "energy" in e["B-energy"].reason
    assert e["B-tele"].decision == "skip"


def test_bad_board_files_fail_loudly(tmp_path):
    p = tmp_path / "b.json"
    p.write_text("[]")
    with pytest.raises(bp.BuildPlanError, match="non-empty list"):
        bp.load_board(p)
    p.write_text(json.dumps([{"name": "x"}]))
    with pytest.raises(bp.BuildPlanError, match=r"\[0\]\.category"):
        bp.load_board(p)
    with pytest.raises(bp.BuildPlanError, match="board file not found"):
        bp.load_board(tmp_path / "nope.json")


# ------------------------------------------------------------------------------------- record

def test_record_round_trips_and_logs(tmp_path):
    items_file = tmp_path / "items.json"
    items_file.write_text(json.dumps([{"id": "B-1", "lane": "web", "effort": "S", "closes": [{}]}]))
    r = bp.rank(bp.load_items(items_file), profile(), effort_budget=1, items_source=items_file, now=5.0)
    wd = tmp_path / "wd"
    p = bp.record(r, workdir=wd)
    assert p == wd / "build-plan" / "ranking.json"
    back = bp.load_ranking(wd)
    assert back == r
    assert back.items_sha256 and "modeled estimate" in json.loads(p.read_text())["estimate"]
    recs = list(ledger.read(wd))
    assert recs[-1]["event"] == "build_plan.rank" and recs[-1]["approved"] == ["B-1"]


def test_ranking_from_json_rejects_other_schemas():
    with pytest.raises(bp.BuildPlanError, match="schema-1"):
        bp.Ranking.from_json(json.dumps({"schema": 2, "entries": []}))
    with pytest.raises(bp.BuildPlanError, match="malformed"):
        bp.Ranking.from_json(json.dumps({"schema": 1, "event": "x", "entries": []}))


# ------------------------------------------------------------------------------------- the gate

@pytest.fixture
def recorded(tmp_path):
    items = [item("B-ok", effort="S", closes=5), item("B-over", effort="L", closes=1),
             item("B-pwn", lane="pwn")]
    wd = tmp_path / "wd"
    bp.record(bp.rank(items, profile(), effort_budget=1), workdir=wd)
    return wd


def test_gate_refuses_without_a_ranking(tmp_path):
    d = bp.check_build("B-ok", profile(), workdir=tmp_path, now=PRE)
    assert not d.allowed and d.phase == "pre-event"
    assert "no build ranking recorded" in d.reason and "build-plan rank" in d.reason
    with pytest.raises(bp.BuildRefused) as ei:
        bp.require_build("B-ok", profile(), workdir=tmp_path, now=PRE)
    assert ei.value.decision.allowed is False


def test_gate_allows_only_approved_items_pre_event(recorded):
    ok = bp.check_build("B-ok", profile(), workdir=recorded, now=PRE)
    assert ok.allowed and ok.entry.decision == "approved" and "modeled estimate" in ok.reason
    over = bp.check_build("B-over", profile(), workdir=recorded, now=PRE)
    assert not over.allowed and "'candidate'" in over.reason
    skip = bp.check_build("B-pwn", profile(), workdir=recorded, now=PRE)
    assert not skip.allowed and "'skip'" in skip.reason
    unranked = bp.check_build("B-new", profile(), workdir=recorded, now=PRE)
    assert not unranked.allowed and "no ranking record" in unranked.reason
    assert bp.require_build("B-ok", profile(), workdir=recorded, now=PRE).allowed
    checks = [r for r in ledger.read(recorded) if r["event"] == "build_plan.check"]
    assert [(r["item"], r["allowed"]) for r in checks] == \
        [("B-ok", True), ("B-over", False), ("B-pwn", False), ("B-new", False), ("B-ok", True)]


def test_gate_refuses_a_ranking_made_for_another_event(recorded):
    d = bp.check_build("B-ok", profile(slug="other"), workdir=recorded, now=PRE)
    assert not d.allowed and "for event 'demo', not 'other'" in d.reason


def test_gate_in_event_needs_a_board_ranking(recorded, tmp_path):
    d = bp.check_build("B-ok", profile(), workdir=recorded, now=DURING)
    assert not d.allowed and d.phase == "in-event" and "visible board" in d.reason
    board = tmp_path / "board.json"
    board.write_text(json.dumps([{"category": "Web"}]))
    bp.record(bp.rank([item("B-ok", effort="S", closes=5)], profile(), effort_budget=1,
                      board=bp.load_board(board)), workdir=recorded)
    assert bp.check_build("B-ok", profile(), workdir=recorded, now=DURING).allowed


def test_gate_post_event_refuses_until_the_fold_audit_can_pass(tmp_path):
    # Post-event, promotion comes first (B-038): with no promotion record the build is refused and
    # the reason says how to make one. The pass/fail branches are in tests/test_promote_foldaudit.py.
    d = bp.check_build("B-any", profile(), workdir=tmp_path, now=AFTER, master=tmp_path)
    assert not d.allowed and d.phase == "post-event"
    assert "no promotion record" in d.reason and "promote inventory" in d.reason


def test_phase_with_date_only_profile():
    prof = profile(start=dt.date(2027, 3, 1), end=dt.date(2027, 3, 1))
    assert bp.phase_of(prof, dt.datetime(2027, 2, 28, 23, 59, tzinfo=UTC)) == "pre-event"
    assert bp.phase_of(prof, dt.datetime(2027, 3, 1, 23, 0, tzinfo=UTC)) == "in-event"
    assert bp.phase_of(prof, dt.datetime(2027, 3, 2, 0, 1)) == "post-event"   # naive = UTC


# ------------------------------------------------------------------------------------- pre-event plan

def test_default_pre_event_plan_is_doctor_and_rehearsal_only():
    steps = preevent.plan(profile(), None)
    assert [(s.kind, s.name) for s in steps] == [("hook", "doctor"), ("hook", "rehearsal")]
    assert all("B-039" in s.detail for s in steps)
    # a ranking with the default budget adds nothing
    r = bp.rank([item("B-1", closes=9)], profile())
    assert [s.name for s in preevent.plan(profile(), r)] == ["doctor", "rehearsal"]


def test_pre_event_plan_appends_approved_builds_in_rank_order():
    r = bp.rank([item("B-lo", effort="S", closes=1), item("B-hi", effort="S", closes=4),
                 item("B-off", lane="pwn")], profile(), effort_budget=10)
    steps = preevent.plan(profile(), r)
    assert [s.name for s in steps] == ["doctor", "rehearsal", "B-hi", "B-lo"]
    with pytest.raises(ValueError, match="for event 'demo'"):
        preevent.plan(profile(slug="other"), r)


def test_a_stub_hook_never_passes_and_a_crashing_one_fails(monkeypatch):
    monkeypatch.setattr(preevent, "HOOKS", (("doctor", lambda p: preevent.HookResult("doctor", "stub", "later")),))
    res = preevent.run_hooks(profile())
    assert [(r.name, r.status, r.passed) for r in res] == [("doctor", "stub", False)]

    def boom(prof):
        raise RuntimeError("no codex")
    monkeypatch.setattr(preevent, "HOOKS", (("doctor", boom),
                                            ("rehearsal", lambda p: "yes"),
                                            ("x", lambda p: preevent.HookResult("x", "ok", "fine"))))
    res = preevent.run_hooks(profile())
    assert res[0].status == "fail" and "RuntimeError: no codex" in res[0].detail
    assert res[1].status == "fail" and "not a HookResult" in res[1].detail
    assert res[2].passed


# ------------------------------------------------------------------------------------- CLI

def run_ctf(*args, workdir):
    e = dict(os.environ, CTF_WORKDIR=str(workdir), CTF_EVENT="csctf", CTF_TESTING="1")
    e.pop("CODEX_BIN", None)          # the doctor hook then refuses its Codex call (never a real one)
    e["CODEX_HOME"] = str(workdir) + "/no-codex-home"   # never the operator's Codex config
    return subprocess.run([sys.executable, "-m", "ctf", "build-plan", *args], cwd=paths.repo_root(),
                          env=e, capture_output=True, text=True, timeout=60)


def test_cli_rank_record_check_and_pre_event(tmp_path):
    items = tmp_path / "items.json"
    items.write_text(json.dumps([
        {"id": "B-web", "category": "web", "effort": "S", "closes": [{}, {}], "payoff": "$500 modeled"},
        {"id": "B-sector", "category": "network-ics", "effort": "M", "title": "Telecom SS7 pack"},
        {"id": "B-big", "category": "rev", "effort": "XL", "closes": [{}]},
    ]))
    wd = tmp_path / "wd"
    r = run_ctf("rank", "--items", str(items), "--effort-budget", "1", "--record", workdir=wd)
    assert r.returncode == 0, r.stderr
    assert "MODELED ESTIMATES" in r.stdout and "$500" in r.stdout
    assert "B-sector" in r.stdout and "after-board" in r.stdout
    assert (wd / "build-plan" / "ranking.json").is_file()

    pre = "2026-11-01T00:00:00+00:00"           # before the shipped csctf profile's start
    r = run_ctf("check", "B-web", "--now", pre, workdir=wd)
    assert r.returncode == 0 and r.stdout.startswith("ALLOW  B-web  [pre-event]"), r.stdout + r.stderr
    r = run_ctf("check", "B-big", "--now", pre, workdir=wd)
    assert r.returncode == 1 and "REFUSE" in r.stdout and "candidate" in r.stdout
    r = run_ctf("check", "B-sector", "--now", pre, workdir=wd)
    assert r.returncode == 1 and "after-board" in r.stdout
    r = run_ctf("check", "B-web", "--now", "yesterday", workdir=wd)
    assert r.returncode == 2 and "ISO 8601" in r.stderr

    r = run_ctf("pre-event", workdir=wd)
    assert r.returncode == 0 and "[hook] doctor" in r.stdout and "[build] B-web" in r.stdout
    r = run_ctf("pre-event", "--run", workdir=wd)
    assert r.returncode == 3, r.stdout + r.stderr
    assert "FAIL  doctor" in r.stdout and "codex-smoke" in r.stdout and "did not pass" in r.stderr
    assert "OK    rehearsal" in r.stdout

    r = run_ctf("rank", "--items", str(tmp_path / "missing.json"), workdir=wd)
    assert r.returncode == 2 and "item file not found" in r.stderr

    r = run_ctf("rank", "--items", str(items), "--json", workdir=wd)
    assert r.returncode == 0
    data = json.loads(r.stdout)
    assert data["event"] == "csctf" and data["estimate"].startswith("modeled estimate")
    assert [e["decision"] for e in data["entries"]].count("approved") == 0   # default budget 0


def test_cli_check_without_ranking_refuses(tmp_path):
    r = run_ctf("check", "B-web", "--now", "2026-11-01T00:00:00+00:00", workdir=tmp_path)
    assert r.returncode == 1 and "no build ranking recorded" in r.stdout
