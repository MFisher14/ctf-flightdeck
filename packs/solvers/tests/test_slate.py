"""B-214: the multi-event priority scheduler (ctf/slate.py, `ctf slate`).

Every event profile, quota reading and governor state here is synthetic and lives in a temp folder; no
platform, harness, model or network is touched. The host governor is the real ctf.governor.Governor
with an injected host reading, so the cap is known.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import sys
from pathlib import Path

import pytest

from ctf import cli, event, governor, paths, quota, slate

UTC = dt.timezone.utc
T0 = dt.datetime(2026, 11, 6, 12, 0, tzinfo=UTC).timestamp()
H = 3600.0
GiB = 1024 ** 3


# ----------------------------------------------------------------------------------------- fixtures

def write_event(root: Path, slug: str, *, start="2026-11-01T00:00:00Z", end="2026-11-30T00:00:00Z",
                allowance: str = "") -> None:
    d = root / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "event.toml").write_text(f'''slug = "{slug}"
name = "{slug} test event"
dates = {{ start = {start}, end = {end} }}

[platform]
kind = "ctfd"
base_url = "https://{slug}.example"

[flag]
prefixes = ["DEMO"]

[rules]
submit_mode = "auto"
flag_sharing = "allowed"
ai_on_platform = "allowed"
{allowance}
''', encoding="utf-8")


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Events root with pink, spooky and csx; a slate state folder; workdirs under tmp."""
    root = tmp_path / "events"
    for s in ("pink", "spooky", "csx"):
        write_event(root, s)
    state = tmp_path / "slate"
    work = tmp_path / "work"
    work.mkdir()
    store = slate.Store(state, events_root=root, clock=lambda: T0)
    return {"root": root, "state": state, "work": work, "store": store, "tmp": tmp_path}


def add(e, slug, **kw):
    kw.setdefault("workdir", str(e["work"] / slug))
    return e["store"].set(slug, by="max", reason="test", **kw)


def host(**kw):
    base = dict(cpu_count=14, load1=1.0, load5=1.0, load15=1.0, total_ram_bytes=64 * GiB,
                available_ram_bytes=48 * GiB, disk_path="/", disk_free_bytes=500 * GiB,
                disk_total_bytes=1000 * GiB, pressure="normal",
                battery=governor.Battery(present=False, percent=None, plugged=True, state=""),
                thermal=governor.Thermal(speed_limit=100, warning_level=0, performance_level=0))
    base.update(kw)
    return governor.HostState(**base)


def gov(e, cap=6, alive=lambda pid: pid != 999999):
    pol = governor.GovernorPolicy(heavy_cap=cap, reserve_ram_mb=0)
    return governor.Governor(e["tmp"] / "gov", pol, probe=lambda: host(), pid_alive=alive)


def state_with(wd: Path, readings, last_ok=None):
    quota.save_state(wd, {"files": {}, "readings": [r.to_dict() for r in readings], "last_ok": last_ok or {}})


def R(harness, window, used=None, *, ts=T0 - 60, resets=None, exhausted=False):
    return quota.Reading(harness, window, ts, "test", used_pct=used, resets_at=resets, exhausted=exhausted)


def J(id, kind="solve", **kw):
    return quota.Job(id, kind, **kw)


# ------------------------------------------------------------------------------------------- paths

def test_slate_state_path_honours_the_variable_and_defaults_under_ctf_work(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_SLATE_STATE", str(tmp_path / "s"))
    assert paths.slate_state() == (tmp_path / "s").resolve()
    monkeypatch.delenv("CTF_SLATE_STATE")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    assert paths.slate_state() == (tmp_path / "home" / "ctf-work" / "_slate").resolve()
    assert slate.Store().dir == paths.slate_state()


# ------------------------------------------------------------------------------------------- store

def test_set_adds_an_event_and_logs_who_and_why(env):
    e = add(env, "pink", priority=2, max_agents=3)
    assert (e.priority, e.max_agents, e.set_by, e.reason, e.set_at) == (2, 3, "max", "test", T0)
    again = env["store"].load().get("pink")
    assert again == e
    h = env["store"].history()
    assert [r["action"] for r in h] == ["add"]
    assert h[0]["before"] is None and h[0]["after"]["max_agents"] == 3 and h[0]["by"] == "max"


def test_a_second_set_changes_only_what_it_names_and_records_before_and_after(env):
    add(env, "pink", priority=2, max_agents=3)
    env["store"].set("pink", by="max", reason="spin up more, get us to first", max_agents=None)
    e = env["store"].load().get("pink")
    assert e.priority == 2 and e.max_agents is None and e.reason == "spin up more, get us to first"
    h = env["store"].history()
    assert [r["action"] for r in h] == ["add", "set"]
    assert h[1]["before"]["max_agents"] == 3 and h[1]["after"]["max_agents"] is None


@pytest.mark.parametrize("by,reason", [("", "x"), ("  ", "x"), ("max", ""), ("max", "   ")])
def test_a_change_must_name_who_and_why(env, by, reason):
    with pytest.raises(slate.SlateError, match="who|why"):
        env["store"].set("pink", by=by, reason=reason, workdir=str(env["work"] / "pink"))
    assert not env["store"].path.exists() and env["store"].history() == []


def test_set_refuses_an_event_without_a_profile_and_an_unknown_setting(env):
    with pytest.raises(event.EventError, match="nosuch"):
        env["store"].set("nosuch", by="max", reason="x")
    with pytest.raises(slate.SlateError, match="unknown slate setting"):
        env["store"].set("pink", by="max", reason="x", colour="red")
    assert env["store"].load().entries == {}


@pytest.mark.parametrize("kw,match", [
    ({"weight": 0}, "weight"), ({"weight": float("nan")}, "weight"), ({"priority": True}, "priority"),
    ({"priority": 1.5}, "priority"), ({"max_agents": -1}, "max_agents"), ({"min_agents": -1}, "min_agents"),
    ({"min_agents": 4, "max_agents": 3}, "above max_agents"), ({"quota_cap_pct": 0}, "quota_cap_pct"),
    ({"quota_cap_pct": 100.5}, "quota_cap_pct"), ({"paused": 1}, "paused"),
    ({"workdir": "relative/dir"}, "absolute"), ({"workdir": ""}, "absolute"),
])
def test_entry_validation_names_the_bad_setting(kw, match):
    with pytest.raises(slate.SlateError, match=match):
        slate.Entry("pink", **kw)


def test_entry_accepts_the_boundaries():
    e = slate.Entry("pink", min_agents=3, max_agents=3, quota_cap_pct=100, workdir="~/w/pink")
    assert e.quota_cap_pct == 100 and e.min_agents == e.max_agents == 3


def test_pause_resume_remove_and_unknown_slug(env):
    add(env, "pink")
    env["store"].pause("pink", by="max", reason="spooky setup")
    assert env["store"].load().get("pink").paused is True
    assert env["store"].load().active() == []
    env["store"].resume("pink", by="max", reason="back")
    assert env["store"].load().get("pink").paused is False
    env["store"].remove("pink", by="max", reason="over")
    assert env["store"].load().entries == {}
    assert [r["action"] for r in env["store"].history()] == ["add", "pause", "resume", "remove"]
    for fn in (env["store"].pause, env["store"].resume, env["store"].remove):
        with pytest.raises(slate.SlateError, match="not on the slate"):
            fn("pink", by="max", reason="x")


def test_a_corrupt_slate_or_history_is_a_named_error(env):
    env["state"].mkdir(parents=True)
    env["store"].path.write_text("{nope", encoding="utf-8")
    with pytest.raises(slate.SlateError, match="corrupt slate"):
        env["store"].load()
    env["store"].path.write_text(json.dumps({"events": {"pink": {"slug": "spooky"}}}), encoding="utf-8")
    with pytest.raises(slate.SlateError, match="names slug"):
        env["store"].load()
    env["store"].path.write_text(json.dumps({"events": {"pink": {"slug": "pink", "bogus": 1}}}), encoding="utf-8")
    with pytest.raises(slate.SlateError, match="unknown key"):
        env["store"].load()
    env["store"].history_path.write_text("{}\nnot json\n", encoding="utf-8")
    with pytest.raises(slate.SlateError, match=":2: corrupt history"):
        env["store"].history()


def test_order_is_priority_then_weight_then_slug(env):
    add(env, "csx", priority=1, weight=1)
    add(env, "spooky", priority=1, weight=2)
    add(env, "pink", priority=3)
    assert [e.slug for e in env["store"].load().ordered()] == ["pink", "spooky", "csx"]


# --------------------------------------------------------------------------------------- isolation

def test_a_set_ctf_workdir_pins_every_event_to_one_folder_and_is_refused(env, monkeypatch):
    monkeypatch.setenv("CTF_WORKDIR", str(env["tmp"] / "one"))
    sl = slate.Slate({"pink": slate.Entry("pink"), "spooky": slate.Entry("spooky")})
    with pytest.raises(slate.SlateError, match="share the workdir.*CTF_WORKDIR is set"):
        slate.workspaces(sl)
    env["store"].set("pink", by="max", reason="x")          # one event alone is fine
    with pytest.raises(slate.SlateError, match="share the workdir"):
        env["store"].set("spooky", by="max", reason="x")
    assert set(env["store"].load().entries) == {"pink"}       # the refused set wrote nothing
    assert [r["slug"] for r in env["store"].history()] == ["pink"]


def test_default_workdirs_are_one_folder_per_event(env, monkeypatch):
    monkeypatch.delenv("CTF_WORKDIR", raising=False)
    monkeypatch.setenv("HOME", str(env["tmp"] / "home"))
    ws = slate.workspaces(slate.Slate({"pink": slate.Entry("pink"), "spooky": slate.Entry("spooky")}))
    base = (env["tmp"] / "home" / "ctf-work").resolve()
    assert ws == {"pink": base / "pink", "spooky": base / "spooky"}


def test_nested_and_in_repo_workdirs_are_refused(env):
    w = env["work"]
    nested = slate.Slate({"pink": slate.Entry("pink", workdir=str(w / "pink")),
                          "spooky": slate.Entry("spooky", workdir=str(w / "pink" / "sub"))})
    with pytest.raises(slate.SlateError, match="spooky's workdir .* is inside event pink's"):
        slate.workspaces(nested)
    outer = slate.Slate({"pink": slate.Entry("pink", workdir=str(w / "pink" / "sub")),
                         "spooky": slate.Entry("spooky", workdir=str(w / "pink"))})
    with pytest.raises(slate.SlateError, match="pink's workdir .* is inside event spooky's"):
        slate.workspaces(outer)
    same = slate.Slate({"pink": slate.Entry("pink", workdir=str(w / "x")),
                        "spooky": slate.Entry("spooky", workdir=str(w / "x"))})
    with pytest.raises(slate.SlateError, match="share the workdir") as ei:
        slate.workspaces(same)
    assert "CTF_WORKDIR" not in str(ei.value)                 # explicit folders: not the variable's fault
    inrepo = slate.Slate({"pink": slate.Entry("pink", workdir=str(paths.repo_root() / "rt"))})
    with pytest.raises(slate.SlateError, match="inside the repo"):
        slate.workspaces(inrepo)
    repo_itself = slate.Slate({"pink": slate.Entry("pink", workdir=str(paths.repo_root()))})
    with pytest.raises(slate.SlateError, match="inside the repo"):    # the repo root itself, not only below it
        slate.workspaces(repo_itself)
    sibling = slate.Slate({"pink": slate.Entry("pink", workdir=str(w / "pink")),
                           "spooky": slate.Entry("spooky", workdir=str(w / "pink-2"))})
    assert slate.workspaces(sibling)["spooky"] == (w / "pink-2").resolve()   # a name prefix is not nesting


def test_child_env_pins_the_event_and_its_workdir_over_whatever_was_set(env):
    add(env, "pink")
    add(env, "spooky")
    sl = env["store"].load()
    out = slate.child_env(sl, "spooky", base={"CTF_EVENT": "pink", "CTF_WORKDIR": "/elsewhere", "KEEP": "1"})
    assert out == {"CTF_EVENT": "spooky", "CTF_WORKDIR": str((env["work"] / "spooky").resolve()), "KEEP": "1"}
    with pytest.raises(slate.SlateError, match="not on the slate"):
        slate.child_env(sl, "csx", base={})


def test_fence_for_denies_every_other_events_workdir(env):
    home = env["tmp"] / "home"
    home.mkdir()
    repo = env["tmp"] / "repo"
    repo.mkdir()
    for s in ("pink", "spooky", "csx"):
        add(env, s, workdir=str(home / "ctf-work" / s))
    sl = env["store"].load()
    f = slate.fence_for(sl, "pink", events_root=env["root"], home=home, repo=repo, user_dir=None)
    assert f.workspace == (home / "ctf-work" / "pink").resolve()
    own = f.classify(home / "ctf-work" / "pink" / "12-x" / "notes.md")
    assert own.kind == "allowed"
    for other in ("spooky", "csx"):
        v = f.classify(home / "ctf-work" / other / "3-y" / "flag.txt")
        assert v.kind == "denied" and v.category == "operator", (other, v)
    alone = slate.fence_for(slate.Slate({"pink": sl.get("pink")}), "pink", events_root=env["root"],
                            home=home, repo=repo, user_dir=None)
    assert alone.classify(home / "ctf-work" / "spooky" / "flag.txt").kind != "denied"


# ------------------------------------------------------------------------------------- allocation

def S(*entries):
    return slate.Slate({e.slug: e for e in entries})


def test_the_pink_cap_then_lift_case_is_a_recorded_setting():
    capped = S(slate.Entry("pink", priority=2, max_agents=3), slate.Entry("spooky", priority=1))
    a = slate.allocate(capped, 6, {"pink": 8, "spooky": 5})
    assert (a.shares["pink"].agents, a.shares["spooky"].agents) == (3, 3)
    assert "max_agents 3" in a.shares["pink"].reason
    lifted = S(slate.Entry("pink", priority=2), slate.Entry("spooky", priority=1))
    b = slate.allocate(lifted, 6, {"pink": 8, "spooky": 5})
    assert (b.shares["pink"].agents, b.shares["spooky"].agents) == (6, 0)
    assert "more wanted" in b.shares["spooky"].reason


def test_weights_split_a_tier_in_proportion():
    sl = S(slate.Entry("pink", weight=2), slate.Entry("spooky", weight=1))
    a = slate.allocate(sl, 6, {"pink": 10, "spooky": 10})
    assert (a.shares["pink"].agents, a.shares["spooky"].agents) == (4, 2)
    b = slate.allocate(sl, 7, {"pink": 10, "spooky": 10})
    assert (b.shares["pink"].agents, b.shares["spooky"].agents) == (5, 2)
    eq = slate.allocate(S(slate.Entry("pink"), slate.Entry("spooky")), 5, {"pink": 9, "spooky": 9})
    assert (eq.shares["pink"].agents, eq.shares["spooky"].agents) == (3, 2)   # tie: slug order


def test_a_floor_keeps_a_low_priority_event_alive():
    sl = S(slate.Entry("pink", priority=2), slate.Entry("spooky", priority=1, min_agents=1))
    a = slate.allocate(sl, 4, {"pink": 10, "spooky": 5})
    assert (a.shares["pink"].agents, a.shares["spooky"].agents) == (3, 1)
    assert "floor 1" in a.shares["spooky"].reason
    none_wanted = slate.allocate(sl, 4, {"pink": 10, "spooky": 0})
    assert none_wanted.shares["spooky"].agents == 0 and none_wanted.shares["pink"].agents == 4


def test_floors_are_served_in_priority_order_when_the_cap_cannot_cover_them_all():
    sl = S(slate.Entry("spooky", priority=1, min_agents=2), slate.Entry("pink", priority=2, min_agents=2))
    a = slate.allocate(sl, 3, {"pink": 9, "spooky": 9})
    assert (a.shares["pink"].agents, a.shares["spooky"].agents) == (2, 1)   # pink's floor in full first
    one = slate.allocate(sl, 1, {"pink": 9, "spooky": 9})
    assert (one.shares["pink"].agents, one.shares["spooky"].agents) == (1, 0)


def test_unused_share_flows_down_and_demand_bounds_every_share():
    sl = S(slate.Entry("pink", priority=2), slate.Entry("spooky", priority=1), slate.Entry("csx", priority=0))
    a = slate.allocate(sl, 6, {"pink": 1, "spooky": 2, "csx": 9})
    assert {s: v.agents for s, v in a.shares.items()} == {"pink": 1, "spooky": 2, "csx": 3}
    assert sum(v.agents for v in a.shares.values()) == 6
    small = slate.allocate(sl, 6, {"pink": 1})
    assert {s: v.agents for s, v in small.shares.items()} == {"pink": 1, "spooky": 0, "csx": 0}
    assert small.shares["spooky"].reason == "no demand"


def test_paused_gets_nothing_and_over_share_running_is_not_free():
    sl = S(slate.Entry("pink", priority=2), slate.Entry("spooky", paused=True, set_by="max", reason="setup"))
    a = slate.allocate(sl, 6, {"pink": 4, "spooky": 4})
    assert a.shares["spooky"].agents == 0 and "paused by max (setup)" in a.shares["spooky"].reason
    assert a.shares["pink"].agents == 4
    over = slate.allocate(S(slate.Entry("pink", priority=2), slate.Entry("spooky", priority=1)), 4,
                          {"pink": 4, "spooky": 4}, {"spooky": 3})
    sp = over.shares["spooky"]
    assert sp.agents == 0 and sp.running == 3 and sp.free == 0 and "3 over its share" in sp.reason
    pk = over.shares["pink"]
    assert pk.agents == 4 and pk.free == 1                    # spooky's 3 still hold seats under the cap of 4
    assert "only 1 of its 4 free seats are open" in pk.reason
    assert over.to_dict()["shares"]["pink"]["free"] == 1


def test_host_room_left_by_over_share_events_goes_in_priority_order():
    sl = S(slate.Entry("pink", priority=2), slate.Entry("spooky", priority=1), slate.Entry("csx", priority=0))
    a = slate.allocate(sl, 6, {"pink": 3, "spooky": 3, "csx": 2}, {"csx": 2})
    assert {s: v.agents for s, v in a.shares.items()} == {"pink": 3, "spooky": 3, "csx": 0}
    assert {s: v.free for s, v in a.shares.items()} == {"pink": 3, "spooky": 1, "csx": 0}
    assert sum(v.free for v in a.shares.values()) == 6 - 2    # never more free seats than the cap has open
    under = slate.allocate(sl, 6, {"pink": 3, "spooky": 3}, {"pink": 1, "spooky": 1})
    assert {s: v.free for s, v in under.shares.items()} == {"pink": 2, "spooky": 2, "csx": 0}
    assert "free seats are open" not in under.shares["spooky"].reason


def test_short_room_reason_at_the_edge_one_seat_short():
    sl = S(slate.Entry("pink", priority=2), slate.Entry("spooky", priority=1))
    a = slate.allocate(sl, 4, {"pink": 4, "spooky": 1}, {"spooky": 1})
    pk = a.shares["pink"]
    assert pk.agents == 4 and pk.free == 3                    # 4 own seats, 3 open: exactly one short
    assert "only 3 of its 4 free seats are open" in pk.reason
    even = slate.allocate(sl, 4, {"pink": 3, "spooky": 1}, {"spooky": 1})
    assert even.shares["pink"].free == 3 and "free seats are open" not in even.shares["pink"].reason


def test_short_room_inside_a_tier_is_split_by_weight_not_slate_order():
    sl = S(slate.Entry("aa", priority=1, weight=2), slate.Entry("bb", priority=1, weight=1),
           slate.Entry("zz", priority=0))
    a = slate.allocate(sl, 6, {"aa": 4, "bb": 2, "zz": 3}, {"zz": 3})
    assert {s: v.agents for s, v in a.shares.items()} == {"aa": 4, "bb": 2, "zz": 0}
    assert {s: v.free for s, v in a.shares.items()} == {"aa": 2, "bb": 1, "zz": 0}   # 3 open seats, 2:1
    assert "only 1 of its 2 free seats" in a.shares["bb"].reason
    eq = S(slate.Entry("aa", priority=1), slate.Entry("bb", priority=1), slate.Entry("zz", priority=0))
    b = slate.allocate(eq, 6, {"aa": 3, "bb": 3, "zz": 4}, {"zz": 4})
    assert {s: v.free for s, v in b.shares.items()} == {"aa": 1, "bb": 1, "zz": 0}   # not both to "aa"
    # running agents count: aa already runs 2, so the open seats go to bb first
    r = slate.allocate(eq, 6, {"aa": 4, "bb": 2, "zz": 2}, {"aa": 2, "zz": 2})
    assert {s: v.agents for s, v in r.shares.items()} == {"aa": 4, "bb": 2, "zz": 0}
    assert {s: v.free for s, v in r.shares.items()} == {"aa": 0, "bb": 2, "zz": 0}
    assert "only 0 of its 2 free seats are open" in r.shares["aa"].reason


def test_allocate_refuses_bad_input():
    sl = S(slate.Entry("pink"))
    for cap in (-1, 1.5, True):
        with pytest.raises(slate.SlateError, match="cap"):
            slate.allocate(sl, cap, {})
    with pytest.raises(slate.SlateError, match="not on the slate"):
        slate.allocate(sl, 3, {"spooky": 1})
    with pytest.raises(slate.SlateError, match="demand for pink"):
        slate.allocate(sl, 3, {"pink": -2})
    assert slate.allocate(sl, 0, {"pink": 3}).shares["pink"].agents == 0


# ------------------------------------------------------------------------------ admission (Scheduler)

def test_labels_round_trip_and_other_labels_are_not_slate():
    assert slate.label_event(slate.lease_label("pink", "solve 12")) == "pink"
    for lab in ("solve 12", "slate:pink", "slate:Pink: x", "", "xslate:pink: y"):
        assert slate.label_event(lab) is None


def test_admission_follows_priority_not_arrival(env):
    add(env, "pink", priority=2)
    add(env, "spooky", priority=1)
    g = gov(env, cap=2)
    sc = slate.Scheduler(env["store"], g)
    s1 = sc.enqueue("spooky", "s1")
    s2 = sc.enqueue("spooky", "s2")
    p1 = sc.enqueue("pink", "p1")
    p2 = sc.enqueue("pink", "p2")
    assert sc.try_admit(s1) is None
    assert "spooky: 0 running, share 0" in sc.last_reason
    l1 = sc.try_admit(p1)
    l2 = sc.try_admit(p2)
    assert l1 is not None and l2 is not None
    assert sorted(x.label for x in g.leases()) == ["slate:pink: p1", "slate:pink: p2"]
    running, waiting, other = sc.census()
    assert running == {"pink": 2} and waiting == {"spooky": [s1, s2]} and other == 0
    sc.release(l1)
    plain = g.enqueue("plain governor run")     # a non-slate waiter is ahead in the host queue
    assert sc.try_admit(s1) is None
    assert "inside its share, but the host has no free slot" in sc.last_reason
    q = g.queue()
    assert [r["id"] for r in q][0] == plain and [r["label"] for r in q][1:] == ["slate:spooky: s1"]
    g.dequeue(plain)
    l3 = sc.try_admit(s1)                       # pink wants no more: its share flows down
    assert l3 is not None and l3.label == "slate:spooky: s1"
    assert sc.try_admit(s2) is None             # pink 1 + spooky 1 fill the cap of 2
    assert "spooky: 1 running, share 1" in sc.last_reason


def test_a_waiter_inside_its_share_keeps_its_place_in_the_host_queue(env):
    add(env, "pink", priority=2)
    add(env, "spooky", priority=1)
    g = gov(env, cap=2)
    sc = slate.Scheduler(env["store"], g)
    assert sc.try_admit(sc.enqueue("pink", "p1")) is not None
    plain = g.enqueue("plain governor run")          # queued ahead of the slate waiter
    s1 = sc.enqueue("spooky", "s1")
    assert sc.try_admit(s1) is None and "keeps its place in the host queue" in sc.last_reason
    late = g.enqueue("later plain run")              # queued after the slate waiter
    assert sc.try_admit(s1) is None                  # a second refused try does not lose the place
    assert [r["label"] for r in g.queue()] == ["plain governor run", "slate:spooky: s1", "later plain run"]
    g.dequeue(plain)
    assert g.try_acquire(late) is None               # the later waiter does not pass the slate waiter
    lease = sc.try_admit(s1)
    assert lease is not None and lease.label == "slate:spooky: s1"
    assert [r["id"] for r in g.queue()] == [late] and sc.census()[1] == {}


def test_a_waiter_pushed_out_of_its_share_gives_up_its_host_place(env):
    add(env, "pink", priority=2)
    add(env, "spooky", priority=1)
    g = gov(env, cap=2)
    sc = slate.Scheduler(env["store"], g)
    assert sc.try_admit(sc.enqueue("pink", "p1")) is not None
    plain = g.enqueue("plain governor run")
    s1 = sc.enqueue("spooky", "s1")
    assert sc.try_admit(s1) is None
    assert "slate:spooky: s1" in [r["label"] for r in g.queue()]
    p2 = sc.enqueue("pink", "p2")                    # higher priority arrives: spooky's share drops to 0
    assert sc.try_admit(p2) is None                  # pink's try withdraws spooky's host place
    assert [r["label"] for r in g.queue()] == ["plain governor run", "slate:pink: p2"]
    assert sc.try_admit(s1) is None and "share 0" in sc.last_reason
    sc.dequeue(p2)                                   # pink gives up: its host place goes with its ticket
    assert [r["id"] for r in g.queue()] == [plain]


class CountingGovernor:
    """The real governor, counting the host places the scheduler withdraws (a collaborator, not the
    thing under test)."""

    def __init__(self, g):
        self.g = g
        self.dequeued: list[str] = []

    def dequeue(self, ticket):
        self.dequeued.append(ticket)
        return self.g.dequeue(ticket)

    def __getattr__(self, name):
        return getattr(self.g, name)


def test_a_withdrawn_host_place_is_cleared_from_the_ticket_and_withdrawn_once(env):
    add(env, "pink", priority=2)
    add(env, "spooky", priority=1)
    g = CountingGovernor(gov(env, cap=2))
    sc = slate.Scheduler(env["store"], g)
    assert sc.try_admit(sc.enqueue("pink", "p1")) is not None
    g.enqueue("plain governor run")
    s1 = sc.enqueue("spooky", "s1")
    assert sc.try_admit(s1) is None
    rec_path = env["state"] / "queue" / f"{s1}.json"
    held = json.loads(rec_path.read_text())["gov"]             # what a held host place looks like on disk
    assert held in [r["id"] for r in g.queue()]
    p2 = sc.enqueue("pink", "p2")                              # spooky's share drops to 0
    for _ in range(3):                                         # several tries by both waiters
        assert sc.try_admit(p2) is None
        assert sc.try_admit(s1) is None
    assert "gov" not in json.loads(rec_path.read_text())       # the ticket no longer claims a host place
    assert g.dequeued.count(held) == 1                         # withdrawn once, not on every try
    assert held not in [r["id"] for r in g.queue()]


def test_acquire_timeout_and_a_dead_waiter_free_the_host_place(env):
    add(env, "pink")
    g = gov(env, cap=1)
    plain = g.enqueue("plain governor run")
    clock = iter(range(0, 1000, 5))
    sc = slate.Scheduler(env["store"], g, clock=lambda: float(next(clock)),
                         pid_alive=lambda pid: pid != 999999)
    with pytest.raises(governor.GovernorTimeout, match="host has no free slot"):
        sc.acquire("pink", "x", timeout=10, poll=1, sleep=lambda s: None)
    assert [r["id"] for r in g.queue()] == [plain] and sc.census()[1] == {}
    dead = sc.enqueue("pink", "dead", pid=999999)
    rec = json.loads((env["state"] / "queue" / f"{dead}.json").read_text())
    gt = g.enqueue("slate:pink: dead")               # what a held host place looks like on disk
    rec["gov"] = gt
    (env["state"] / "queue" / f"{dead}.json").write_text(json.dumps(rec))
    sc.census()                                      # reaps the dead ticket
    assert [r["id"] for r in g.queue()] == [plain]


def test_within_an_event_waiters_are_first_in_first_out(env):
    add(env, "pink", max_agents=1)
    sc = slate.Scheduler(env["store"], gov(env, cap=4))
    a = sc.enqueue("pink", "a")
    b = sc.enqueue("pink", "b")
    assert sc.try_admit(b) is None and "place 2" in sc.last_reason
    assert sc.try_admit(a) is not None


def test_heavy_agents_not_on_the_slate_come_off_the_cap(env):
    add(env, "pink")
    g = gov(env, cap=3)
    t = g.enqueue("plain governor run")
    assert g.try_acquire(t) is not None
    sc = slate.Scheduler(env["store"], g)
    alloc = sc.allocation()
    assert alloc.cap == 2
    assert sc.census()[2] == 1
    t = g.enqueue(slate.lease_label("csx", "left over"))      # an agent of an event since removed
    assert g.try_acquire(t) is not None
    assert sc.allocation().cap == 1                            # still holds a seat under the cap


def test_a_lost_host_place_is_taken_again(env):
    add(env, "pink")
    g = gov(env, cap=1)
    sc = slate.Scheduler(env["store"], g)
    plain = g.enqueue("plain governor run")
    t = sc.enqueue("pink", "x")
    assert sc.try_admit(t) is None
    (held,) = [r["id"] for r in g.queue() if r["id"] != plain]
    g.dequeue(held)                                            # the governor ticket went away
    assert sc.try_admit(t) is None                             # no GovernorError: a new place is taken
    assert [r["label"] for r in g.queue()] == ["plain governor run", "slate:pink: x"]
    g.dequeue(plain)
    assert sc.try_admit(t) is not None


def test_dead_and_unreadable_tickets_are_reaped(env):
    add(env, "pink")
    sc = slate.Scheduler(env["store"], gov(env), pid_alive=lambda pid: pid != 999999)
    dead = sc.enqueue("pink", "dead", pid=999999)
    (env["state"] / "queue" / "junk.json").write_text("{", encoding="utf-8")
    live = sc.enqueue("pink", "live")
    _r, waiting, _o = sc.census()
    assert waiting == {"pink": [live]}
    assert any(dead in r for r in sc.reaped) and any("junk.json (unreadable)" in r for r in sc.reaped)
    with pytest.raises(slate.SlateError, match="not queued"):
        sc.try_admit(dead)


def test_paused_event_is_never_admitted_and_acquire_times_out_cleanly(env):
    add(env, "pink")
    env["store"].pause("pink", by="max", reason="spooky setup")
    clock = iter(range(0, 1000, 5))
    sc = slate.Scheduler(env["store"], gov(env), clock=lambda: float(next(clock)))
    waits = []
    with pytest.raises(governor.GovernorTimeout, match="paused by max"):
        sc.acquire("pink", "x", timeout=10, poll=1, sleep=lambda s: None, on_wait=waits.append)
    assert waits and all("paused" in w for w in waits)
    assert sc.census()[1] == {}                 # the ticket was withdrawn
    with pytest.raises(slate.SlateError, match="poll"):
        sc.acquire("pink", "x", poll=0)


def test_acquire_admits_when_the_share_opens(env):
    add(env, "pink", priority=2)
    add(env, "spooky", priority=1)
    g = gov(env, cap=1)
    sc = slate.Scheduler(env["store"], g)
    first = sc.try_admit(sc.enqueue("pink", "p"))
    released = []

    def sleep(_s):
        if not released:
            sc.release(first)
            released.append(1)

    lease = sc.acquire("spooky", "s", timeout=None, poll=1, sleep=sleep)
    assert lease.label == "slate:spooky: s" and released


def test_removed_event_ticket_is_a_named_error(env):
    add(env, "pink")
    sc = slate.Scheduler(env["store"], gov(env))
    t = sc.enqueue("pink", "x")
    env["store"].remove("pink", by="max", reason="over")
    with pytest.raises(slate.SlateError, match="not on the slate"):
        sc.try_admit(t)
    with pytest.raises(slate.SlateError, match="not on the slate"):
        sc.enqueue("pink", "y")


# ----------------------------------------------------------------------------- budget: quota plans

def test_account_readings_merge_every_event_workdir(env):
    a, b = env["work"] / "pink", env["work"] / "spooky"
    state_with(a, [R("codex", "weekly", 40, ts=T0 - 100)], {"codex": T0 - 50})
    state_with(b, [R("codex", "weekly", 55, ts=T0 - 10), R("claude", "session", 5)], {"codex": T0 - 500})
    latest, last_ok = slate.account_readings([a, b, env["work"] / "missing"])
    assert latest[("codex", "weekly")].used_pct == 55 and ("claude", "session") in latest
    assert last_ok == {"codex": T0 - 50}


def test_priority_tiers_share_one_account_window(env):
    add(env, "pink", priority=2)
    add(env, "spooky", priority=1)
    state_with(env["work"] / "spooky", [R("codex", "weekly", 70)])     # read in spooky's workdir only
    sl = env["store"].load()
    jobs = {"spooky": [J(f"s{i}", harnesses=("codex",)) for i in range(3)],
            "pink": [J(f"p{i}", harnesses=("codex",)) for i in range(3)]}
    p = slate.plan(sl, jobs, now=T0, events_root=env["root"])
    placed = [(x.slug, x.assignment.job) for x in p.assigned]
    assert placed == [("pink", "p0"), ("pink", "p1"), ("pink", "p2"), ("spooky", "s0")]
    assert {(h.slug, h.job) for h in p.held} == {("spooky", "s1"), ("spooky", "s2")}
    assert all("100% solve limit" in h.reasons["codex"] for h in p.held)


def test_weights_interleave_jobs_within_a_tier(env):
    add(env, "pink")
    add(env, "spooky")
    state_with(env["work"] / "pink", [R("codex", "weekly", 80)])
    jobs = {"pink": [J("p0", harnesses=("codex",)), J("p1", harnesses=("codex",))],
            "spooky": [J("s0", harnesses=("codex",)), J("s1", harnesses=("codex",))]}
    p = slate.plan(env["store"].load(), jobs, now=T0, events_root=env["root"])
    assert [(x.slug, x.assignment.job) for x in p.assigned] == [("pink", "p0"), ("spooky", "s0")]


def test_one_events_release_reserves_the_window_against_anothers_solves(env):
    write_event(env["root"], "pink", allowance=f"\n[allowance]\nreleases = [{dt.datetime.fromtimestamp(T0 + 2 * H, UTC).strftime('%Y-%m-%dT%H:%M:%SZ')}]\n")
    add(env, "pink", priority=1)
    add(env, "spooky", priority=2)
    state_with(env["work"] / "spooky", [R("codex", "weekly", 62, resets=T0 + 48 * H)])
    jobs = {"spooky": [J("s0", harnesses=("codex",)), J("s1", harnesses=("codex",))]}
    p = slate.plan(env["store"].load(), jobs, now=T0, events_root=env["root"])
    assert p.next_release == pytest.approx(T0 + 2 * H)
    # 62 + 10 margin = 72: s0 brings it to 77 <= 80 (100 - reserve 20); s1 would bring it to 82
    assert [x.assignment.job for x in p.assigned] == ["s0"]
    assert "reserve held for the release" in p.held[0].reasons["codex"]
    env["store"].pause("pink", by="max", reason="x")                  # pink no longer in play
    q = slate.plan(env["store"].load(), jobs, now=T0, events_root=env["root"])
    assert q.next_release is None and len(q.assigned) == 2


def test_the_earliest_release_of_any_active_event_sets_the_reserve(env):
    def at(t):
        return dt.datetime.fromtimestamp(t, UTC).strftime('%Y-%m-%dT%H:%M:%SZ')
    write_event(env["root"], "pink", allowance=f"\n[allowance]\nreleases = [{at(T0 + 2 * H)}]\n")
    write_event(env["root"], "csx", allowance=f"\n[allowance]\nreleases = [{at(T0 + 30 * H)}]\n")
    add(env, "pink", priority=1)
    add(env, "csx", priority=0)
    add(env, "spooky", priority=2)
    # the window resets at +10 h: after pink's release at +2 h (so it is reserved for it) but before
    # csx's at +30 h (which alone would reserve nothing)
    state_with(env["work"] / "spooky", [R("codex", "weekly", 62, resets=T0 + 10 * H)])
    jobs = {"spooky": [J("s0", harnesses=("codex",)), J("s1", harnesses=("codex",))]}
    p = slate.plan(env["store"].load(), jobs, now=T0, events_root=env["root"])
    assert p.next_release == pytest.approx(T0 + 2 * H)
    assert [x.assignment.job for x in p.assigned] == ["s0"]
    assert "reserve held for the release" in p.held[0].reasons["codex"]
    env["store"].pause("pink", by="max", reason="x")        # only csx's later release is left
    q = slate.plan(env["store"].load(), jobs, now=T0, events_root=env["root"])
    assert q.next_release == pytest.approx(T0 + 30 * H) and len(q.assigned) == 2


def test_quota_cap_pct_bounds_one_events_share(env):
    add(env, "pink", quota_cap_pct=10)
    add(env, "spooky")
    state_with(env["work"] / "pink", [R("codex", "weekly", 0)])
    jobs = {"pink": [J(f"p{i}", harnesses=("codex",)) for i in range(3)],
            "spooky": [J(f"s{i}", harnesses=("codex",)) for i in range(3)]}
    p = slate.plan(env["store"].load(), jobs, now=T0, events_root=env["root"])
    assert sorted(x.assignment.job for x in p.assigned) == ["p0", "p1", "s0", "s1", "s2"]
    (hd,) = p.held
    assert hd.job == "p2" and "quota_cap_pct 10%" in hd.reasons["codex"] and "set by max" in hd.reasons["codex"]


def test_agent_share_holds_jobs_past_the_free_agents(env):
    add(env, "pink", priority=2)
    add(env, "spooky", priority=1)
    sl = env["store"].load()
    alloc = slate.allocate(sl, 3, {"pink": 2, "spooky": 3})
    jobs = {"pink": [J("p0"), J("p1")], "spooky": [J("s0"), J("s1"), J("s2")]}
    p = slate.plan(sl, jobs, now=T0, allocation=alloc, events_root=env["root"])
    assert sorted((x.slug, x.assignment.job) for x in p.assigned) == [("pink", "p0"), ("pink", "p1"), ("spooky", "s0")]
    assert {h.job for h in p.held} == {"s1", "s2"}
    assert all("no free agent in spooky's share" in h.reasons["agents"] for h in p.held)
    assert any("unmetered" in w for w in p.warnings)


def test_paused_events_jobs_are_held_with_the_players_reason(env):
    add(env, "pink")
    env["store"].pause("pink", by="max", reason="spooky setup")
    p = slate.plan(env["store"].load(), {"pink": [J("p0")]}, now=T0, events_root=env["root"])
    assert p.assigned == [] and p.held[0].reasons == {"event": "paused by max (spooky setup)"}


def test_one_probe_job_per_harness_across_all_events(env):
    add(env, "pink", priority=2)
    add(env, "spooky", priority=1)
    state_with(env["work"] / "pink", [R("codex", "weekly", exhausted=True, ts=T0 - 2 * H, resets=T0 + 72 * H)])
    jobs = {"pink": [J("p0", harnesses=("codex",))], "spooky": [J("s0", harnesses=("codex",))]}
    p = slate.plan(env["store"].load(), jobs, now=T0, events_root=env["root"])
    assert [(x.slug, x.assignment.mode) for x in p.assigned] == [("pink", "probe")]
    assert "went to pink" in p.held[0].reasons["codex"]


def test_writeups_go_first_within_an_event(env):
    add(env, "pink")
    state_with(env["work"] / "pink", [R("codex", "weekly", 85)])
    jobs = {"pink": [J("solve1", harnesses=("codex",)), J("wu", "writeup", harnesses=("codex",), est_pct=5)]}
    p = slate.plan(env["store"].load(), jobs, now=T0, events_root=env["root"])
    assert [x.assignment.job for x in p.assigned] == ["wu"]
    assert [h.job for h in p.held] == ["solve1"]


def test_held_jobs_batch_by_the_time_they_open(env):
    add(env, "pink")
    add(env, "spooky")
    state_with(env["work"] / "pink", [R("codex", "weekly", exhausted=True, ts=T0 - 60, resets=T0 + 10 * 60)])
    jobs = {"pink": [J("p0", harnesses=("codex",))], "spooky": [J("s0", harnesses=("codex",)), J("s1", "build", harnesses=("codex",))]}
    p = slate.plan(env["store"].load(), jobs, now=T0, events_root=env["root"])
    assert p.assigned == []
    (t, ids), = p.batches
    assert t == pytest.approx(T0 + 10 * 60) and set(ids) == {("pink", "p0"), ("spooky", "s0"), ("spooky", "s1")}


def test_plan_warns_about_an_event_outside_its_dates(env):
    write_event(env["root"], "csx", start="2026-12-01T00:00:00Z", end="2026-12-03T00:00:00Z")
    add(env, "csx")
    p = slate.plan(env["store"].load(), {"csx": [J("c0")]}, now=T0, events_root=env["root"])
    assert any("csx: the event has not started" in w for w in p.warnings)
    q = slate.plan(env["store"].load(), {"csx": [J("c0")]}, now=T0 + 40 * 24 * H, events_root=env["root"])
    assert any("csx: the event has ended" in w for w in q.warnings)


def test_plan_and_job_file_errors_are_named(env):
    add(env, "pink")
    sl = env["store"].load()
    with pytest.raises(slate.SlateError, match="not on the slate"):
        slate.plan(sl, {"spooky": [J("x")]}, now=T0, events_root=env["root"])
    with pytest.raises(slate.SlateError, match="duplicate job id"):
        slate.plan(sl, {"pink": [J("x"), J("x")]}, now=T0, events_root=env["root"])
    with pytest.raises(slate.SlateError, match="object"):
        slate.load_jobs([{"id": "x", "kind": "solve"}])
    with pytest.raises(slate.SlateError, match="pink: .*unknown kind"):
        slate.load_jobs({"pink": [{"id": "x", "kind": "nap"}]})
    assert [j.id for j in slate.load_jobs({"pink": [{"id": "x", "kind": "solve"}]})["pink"]] == ["x"]


def test_check_names_each_problem(env):
    assert slate.check(slate.Slate({}))[0].startswith("the slate is empty")
    add(env, "pink")
    assert slate.check(env["store"].load(), events_root=env["root"]) == []
    env["store"].pause("pink", by="max", reason="x")
    assert any("paused" in p for p in slate.check(env["store"].load(), events_root=env["root"]))
    bad = slate.Slate({"pink": slate.Entry("pink", workdir=str(env["work"] / "x")),
                       "gone": slate.Entry("gone", workdir=str(env["work"] / "x"))})
    probs = slate.check(bad, events_root=env["root"])
    assert any(p.startswith("gone:") for p in probs) and any("share the workdir" in p for p in probs)


# ---------------------------------------------------------------------------------------------- CLI

def ctf(env, *argv):
    return cli.main(["slate", "--state", str(env["state"]), "--events-root", str(env["root"]), *argv])


def test_cli_set_show_history_pause(env, capsys):
    w = str(env["work"] / "pink")
    assert ctf(env, "set", "pink", "--priority", "2", "--max-agents", "3", "--workdir", w,
               "--by", "max", "--reason", "keep it to 3") == 0
    assert ctf(env, "set", "pink", "--max-agents", "none", "--by", "max", "--reason", "spin up more") == 0
    e = slate.Store(env["state"]).load().get("pink")
    assert e.max_agents is None and e.priority == 2 and e.workdir == w
    capsys.readouterr()
    assert ctf(env, "show", "--json") == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown["events"]["pink"]["priority"] == 2 and shown["workdirs"]["pink"] == str(Path(w).resolve())
    assert ctf(env, "pause", "pink", "--by", "max", "--reason", "spooky setup") == 0
    assert "pink: paused" in capsys.readouterr().out
    assert ctf(env, "history") == 0
    out = capsys.readouterr().out
    assert "keep it to 3" in out and "spin up more" in out and "spooky setup" in out


def test_cli_errors_exit_2_with_the_reason(env, capsys):
    assert ctf(env, "set", "nosuch", "--by", "max", "--reason", "x") == 2
    assert "nosuch" in capsys.readouterr().err
    assert ctf(env, "pause", "pink", "--by", "max", "--reason", "x") == 2
    assert "not on the slate" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        ctf(env, "set", "pink", "--reason", "x")           # --by is required


def test_cli_check_fails_on_a_broken_slate(env, capsys):
    env["state"].mkdir(parents=True)
    w = str(env["work"] / "same")
    env["store"].path.write_text(json.dumps({"events": {
        "pink": slate.Entry("pink", workdir=w).to_dict(), "spooky": slate.Entry("spooky", workdir=w).to_dict()}}))
    assert ctf(env, "check") == 1
    out = capsys.readouterr().out
    assert "share the workdir" in out and "SLATE FAILED" in out
    env["store"].path.write_text(json.dumps({"events": {"pink": slate.Entry("pink", workdir=w).to_dict()}}))
    assert ctf(env, "check") == 0


def test_cli_env_prints_quoted_exports(env, capsys):
    odd = env["work"] / "it's here"
    add(env, "pink", workdir=str(odd))
    capsys.readouterr()
    assert ctf(env, "env", "pink") == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "export CTF_EVENT=pink"
    assert lines[1] == "export CTF_WORKDIR='" + str(odd.resolve()).replace("'", "'\"'\"'") + "'"


def test_cli_plan_exits_3_when_something_is_held(env, capsys, tmp_path):
    add(env, "pink", priority=2)
    add(env, "spooky", priority=1)
    jf = tmp_path / "jobs.json"
    jf.write_text(json.dumps({"pink": [{"id": "p0", "kind": "solve"}], "spooky": [{"id": "s0", "kind": "solve"}]}))
    capsys.readouterr()
    assert ctf(env, "plan", "--jobs", str(jf), "--cap", "1", "--now", str(T0), "--json") == 3
    out = json.loads(capsys.readouterr().out)
    assert [a["event"] for a in out["assigned"]] == ["pink"] and out["held"][0]["reasons"]["agents"]
    assert ctf(env, "plan", "--jobs", str(jf), "--cap", "2", "--now", str(T0)) == 0
    assert "RUN  spooky/s0" in capsys.readouterr().out
    jf.write_text("[]")
    assert ctf(env, "plan", "--jobs", str(jf), "--no-agents") == 2


def test_cli_status_and_run_go_through_the_governor(env, capsys, monkeypatch, tmp_path):
    from ctf.cli import slate as scli
    add(env, "pink", priority=2)
    add(env, "spooky", priority=1)
    g = gov(env, cap=2)
    monkeypatch.setattr(scli, "_governor", lambda: g)
    capsys.readouterr()
    assert ctf(env, "status", "--json") == 0
    st = json.loads(capsys.readouterr().out)
    assert st["cap"] == 2 and st["shares"]["pink"]["agents"] == 0       # nobody waiting: no demand
    seen = tmp_path / "seen.txt"
    code = ("import os,sys,pathlib; pathlib.Path(sys.argv[1]).write_text(os.environ['CTF_EVENT'] + '|' "
            "+ os.environ['CTF_WORKDIR']); sys.exit(7)")
    assert ctf(env, "run", "--event", "spooky", "--", sys.executable, "-c", code, str(seen)) == 7
    assert seen.read_text() == "spooky|" + str((env["work"] / "spooky").resolve())
    assert g.leases() == []                                              # the slot was freed
    env["store"].pause("spooky", by="max", reason="pink first")
    assert ctf(env, "run", "--event", "spooky", "--timeout", "0", "--poll", "0.01", "--", sys.executable,
               "-c", "raise SystemExit(0)") == 3
    assert "paused by max" in capsys.readouterr().err
    assert ctf(env, "run", "--event", "spooky") == 2
