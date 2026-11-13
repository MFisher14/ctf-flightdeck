"""B-171: harness quota meter, allowance reserve and quota-aware scheduling (ctf/quota.py, the session-log
scanner tools/ledger/quota.py, `ctf quota`, the doctor's allowance check, the [allowance] profile table).

Every reading and session log here is synthetic; no real log, harness or network is touched.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import subprocess
import sys
import tomllib
import zoneinfo
from pathlib import Path

import pytest

from ctf import doctor, event, eventscaffold, ledger, paths, quota
from ctf.cli import quota as qcli
from tools.ledger import quota as qscan
from tools.ledger import sources

UTC = dt.timezone.utc
NY = zoneinfo.ZoneInfo("America/New_York")
T0 = dt.datetime(2026, 11, 6, 12, 0, tzinfo=UTC).timestamp()
H, M = 3600.0, 60.0


def prof(**allowance):
    data = {"slug": "qdemo", "name": "Quota Demo",
            "dates": {"start": dt.datetime(2026, 11, 1, tzinfo=UTC), "end": dt.datetime(2026, 11, 30, tzinfo=UTC)},
            "platform": {"kind": "ctfd", "base_url": "https://demo.example/"}, "flag": {"prefixes": ["DEMO"]},
            "rules": {"submit_mode": "auto", "flag_sharing": "allowed", "ai_on_platform": "allowed"}}
    if allowance:
        data["allowance"] = allowance
    return event.parse(data)


def R(harness, window, used=None, *, ts=T0, resets=None, exhausted=False, minutes=None, source="test"):
    return quota.Reading(harness, window, ts, source, used_pct=used, resets_at=resets, exhausted=exhausted,
                         window_minutes=minutes)


def snap(p, readings=(), last_ok=None, now=T0):
    latest = {}
    quota.merge(latest, readings)
    return quota.build_snapshot(p, latest, last_ok or {}, now)


def J(id, kind, **kw):
    return quota.Job(id, kind, **kw)


# ------------------------------------------------------------------ the [allowance] profile table

def test_allowance_defaults_and_full_table_parse():
    a = prof().allowance
    assert (a.margin_pct, a.reserve_pct, a.build_ceiling_pct, a.recheck_minutes, a.releases, a.daily_release,
            a.tz, a.daily_usd) == (10.0, 20.0, 70.0, 30.0, (), "", "UTC", 0.0)
    a = prof(margin_pct=5, reserve_pct=30, build_ceiling_pct=60, recheck_minutes=15, tz="America/New_York",
             releases=[dt.datetime(2026, 11, 7, 12, 0), "2026-11-07T09:00:00Z"], daily_release="12:00",
             daily_usd=400).allowance
    assert (a.margin_pct, a.reserve_pct, a.build_ceiling_pct, a.recheck_minutes, a.daily_release, a.daily_usd) == \
        (5.0, 30.0, 60.0, 15.0, "12:00", 400.0)
    # sorted; the naive release is read in the allowance zone (noon New York = 17:00 UTC)
    assert [r.timestamp() for r in a.releases] == [dt.datetime(2026, 11, 7, 9, tzinfo=UTC).timestamp(),
                                                   dt.datetime(2026, 11, 7, 17, tzinfo=UTC).timestamp()]


@pytest.mark.parametrize("kw, msg", [
    ({"margin_pct": 101}, "allowance.margin_pct must be between 0 and 100"),
    ({"reserve_pct": -1}, "allowance.reserve_pct must be between 0 and 100"),
    ({"build_ceiling_pct": 150}, "allowance.build_ceiling_pct must be between 0 and 100"),
    ({"margin_pct": 50, "reserve_pct": 50}, "must stay below 100"),
    ({"recheck_minutes": 0}, "allowance.recheck_minutes must be > 0"),
    ({"daily_usd": -5}, "allowance.daily_usd must be >= 0"),
    ({"daily_release": "25:00"}, "allowance.daily_release must be"),
    ({"daily_release": "9:00"}, "allowance.daily_release must be"),
    ({"tz": "Mars/Olympus"}, "allowance.tz is not an IANA time zone"),
    ({"releases": [3]}, "allowance.releases must be a list of datetimes"),
    ({"releases": ["soon"]}, "allowance.releases holds 'soon'"),
    ({"surprise": 1}, "unknown key(s): allowance.surprise"),
    ({"margin_pct": True}, "allowance.margin_pct must be int or float, got a boolean"),
])
def test_allowance_bad_values_fail_naming_the_key(kw, msg):
    with pytest.raises(event.EventError, match=None) as ei:
        prof(**kw)
    assert msg in str(ei.value)


def test_new_event_scaffold_writes_the_allowance_table_and_it_round_trips(tmp_path):
    data = eventscaffold.profile_data("qnew", name="Q", start=dt.date(2027, 1, 1), end=dt.date(2027, 1, 2),
                                      kind="ctfd", base_url="https://q.example", prefixes=["Q"],
                                      submit_mode="auto", ai_on_platform="allowed")
    assert data["allowance"] == {"margin_pct": 10.0, "reserve_pct": 20.0, "build_ceiling_pct": 70.0,
                                 "recheck_minutes": 30.0, "releases": [], "daily_release": "", "tz": "UTC",
                                 "daily_usd": 0.0}
    p = eventscaffold.write_profile(data, tmp_path / "qnew" / "event.toml")
    assert p.allowance == event.Allowance()
    assert "[allowance]" in (tmp_path / "qnew" / "event.toml").read_text()


def test_shipped_profiles_load_their_allowance():
    """B-211 set the known release times (Huntress daily 09:00 Eastern; the two CSCTF waves); every
    other shipped profile keeps the default allowance."""
    want = {"huntress": event.Allowance(daily_release="09:00", tz="America/New_York"),
            "csctf": event.Allowance(releases=(dt.datetime(2026, 11, 6, 13, tzinfo=UTC),
                                               dt.datetime(2026, 11, 7, 13, tzinfo=UTC)))}
    for slug in event.available():
        assert event.load(slug).allowance == want.get(slug, event.Allowance()), slug


# ------------------------------------------------------------------ releases and limits

def test_next_release_is_the_earliest_ahead_of_start_listed_and_daily():
    p = prof(releases=["2026-11-06T20:00:00Z", "2026-11-09T16:00:00Z"])
    assert quota.next_release(p, T0) == dt.datetime(2026, 11, 6, 20, tzinfo=UTC).timestamp()
    assert quota.next_release(p, T0 + 9 * H) == dt.datetime(2026, 11, 9, 16, tzinfo=UTC).timestamp()
    assert quota.next_release(p, dt.datetime(2026, 12, 1, tzinfo=UTC).timestamp()) is None
    before = dt.datetime(2026, 10, 1, tzinfo=UTC).timestamp()
    assert quota.next_release(p, before) == dt.datetime(2026, 11, 1, tzinfo=UTC).timestamp()   # the start
    d = prof(daily_release="12:00", tz="America/New_York")
    # 12:00 UTC on Nov 6 is 07:00 in New York: today's noon release (17:00 UTC) is next
    assert quota.next_release(d, T0) == dt.datetime(2026, 11, 6, 17, tzinfo=UTC).timestamp()
    # past it: tomorrow's
    assert quota.next_release(d, T0 + 6 * H) == dt.datetime(2026, 11, 7, 17, tzinfo=UTC).timestamp()
    # never past the end of the event
    assert quota.next_release(d, dt.datetime(2026, 11, 30, 0, 30, tzinfo=UTC).timestamp()) is None


def test_a_date_only_event_end_keeps_the_last_days_daily_release():
    p = event.parse({"slug": "qd", "name": "Q", "dates": {"start": dt.date(2026, 11, 1), "end": dt.date(2026, 11, 6)},
                     "platform": {"kind": "ctfd", "base_url": "https://q.example"}, "flag": {"prefixes": ["Q"]},
                     "rules": {"submit_mode": "auto", "flag_sharing": "allowed", "ai_on_platform": "allowed"},
                     "allowance": {"daily_release": "16:00"}})
    assert quota.next_release(p, T0) == dt.datetime(2026, 11, 6, 16, tzinfo=UTC).timestamp()


def test_limit_per_kind_holds_the_reserve_from_solve_and_build_only():
    a = prof().allowance
    assert quota.limit_pct("writeup", True, a) == 100 and quota.limit_pct("release", True, a) == 100
    assert quota.limit_pct("solve", True, a) == 80 and quota.limit_pct("solve", False, a) == 100
    assert quota.limit_pct("build", True, a) == 70 and quota.limit_pct("build", False, a) == 70
    a2 = prof(reserve_pct=40, build_ceiling_pct=90).allowance
    assert quota.limit_pct("build", True, a2) == 60 and quota.limit_pct("build", False, a2) == 90
    with pytest.raises(quota.QuotaError, match="unknown job kind"):
        quota.limit_pct("party", False, a)


# ------------------------------------------------------------------ window state

def test_a_reading_counts_margin_higher_and_the_reserve_applies_only_when_it_outlives_the_release():
    p = prof(releases=["2026-11-06T20:00:00Z"])
    s = snap(p, [R("codex", "weekly", 40, resets=T0 + 3 * 86400), R("codex", "session", 30, resets=T0 + 2 * H)])
    w = {x.window: x for x in s.harnesses["codex"].windows}
    assert w["weekly"].status == "ok" and w["weekly"].effective_pct == 50 and w["weekly"].reserved
    assert w["session"].effective_pct == 40 and not w["session"].reserved     # resets before the release
    assert s.harnesses["codex"].status == "ok"
    assert snap(prof(), [R("codex", "weekly", 40, resets=T0 + 3 * 86400)]).harnesses["codex"].windows[0].reserved is False
    assert snap(p, [R("codex", "weekly", 95)]).harnesses["codex"].windows[0].effective_pct == 100   # capped
    # a window that resets exactly at the release gives the release a fresh window: no reserve
    rel = dt.datetime(2026, 11, 6, 20, tzinfo=UTC).timestamp()
    assert snap(p, [R("codex", "weekly", 40, resets=rel)]).harnesses["codex"].windows[0].reserved is False
    assert snap(p, [R("codex", "weekly", 40, resets=rel + 1)]).harnesses["codex"].windows[0].reserved is True


def test_a_window_whose_reset_passed_counts_as_reset_and_rolls_its_next_reset():
    s = snap(prof(), [R("codex", "session", 99, resets=T0 - 30 * M, minutes=300)])
    w = s.harnesses["codex"].windows[0]
    assert w.status == "ok" and w.effective_pct == 10 and w.resets_at == T0 - 30 * M + 300 * M
    assert "reset at" in w.note
    # two whole windows later: the next reset is the one after now, not the one after the old reset
    w = snap(prof(), [R("codex", "session", 99, resets=T0 - 7 * H, minutes=300)]).harnesses["codex"].windows[0]
    assert w.resets_at == T0 - 7 * H + 2 * 300 * M


def test_a_limit_hit_is_exhausted_until_recheck_then_probe_then_reset():
    hit = R("claude", "weekly", exhausted=True, ts=T0, resets=T0 + 3 * 86400)
    p = prof(recheck_minutes=30)
    w = snap(p, [hit], now=T0 + 10 * M).harnesses["claude"].windows[0]
    assert w.status == "exhausted" and w.open_at == T0 + 30 * M
    w = snap(p, [hit], now=T0 + 31 * M).harnesses["claude"].windows[0]
    assert w.status == "probe" and "recheck time" in w.note
    w = snap(p, [hit], now=T0 + 3 * 86400 + 1).harnesses["claude"].windows[0]
    assert w.status == "ok"
    soon = R("claude", "session", exhausted=True, ts=T0, resets=T0 + 10 * M)     # resets before recheck
    assert snap(p, [soon], now=T0 + 5 * M).harnesses["claude"].windows[0].open_at == T0 + 10 * M
    assert snap(p, [R("claude", "spend", exhausted=True)], now=T0 + 5 * M).harnesses["claude"].windows[0].open_at \
        == T0 + 30 * M                                                            # no reset named: recheck
    assert snap(p, [R("codex", "weekly", 100)], now=T0 + 5 * M).harnesses["codex"].status == "exhausted"


def test_a_response_served_after_the_hit_disproves_it_the_pink_case():
    hit = R("codex", "limit", exhausted=True, ts=T0, resets=T0 + 6 * 86400)
    s = snap(prof(), [hit], last_ok={"codex": T0 + 11 * M}, now=T0 + 12 * M)
    w = s.harnesses["codex"].windows[0]
    assert w.status == "unmetered" and "wrong or lifted" in w.note
    s = snap(prof(), [hit], last_ok={"codex": T0 - 1}, now=T0 + 12 * M)          # served before: still out
    assert s.harnesses["codex"].windows[0].status == "exhausted"


def test_a_response_logged_just_after_the_hit_was_in_flight_and_disproves_nothing():
    # a dozen agents share the account: another agent's reply logged 3 s after a weekly hit was already
    # in flight when the limit hit; the harness stays exhausted and gets no jobs
    hit = R("codex", "weekly", exhausted=True, ts=T0, resets=T0 + 3 * 86400)
    for served in (T0 + 3, T0 + quota.DISPROOF_GRACE_S):
        s = snap(prof(), [hit], last_ok={"codex": served}, now=T0 + 6 * M)
        assert s.harnesses["codex"].windows[0].status == "exhausted", served
        plan = quota.schedule(s, [J("a", "solve", harnesses=("codex",))])
        assert plan.assigned == [] and [h.job for h in plan.held] == ["a"]
    s = snap(prof(), [hit], last_ok={"codex": T0 + quota.DISPROOF_GRACE_S + 1}, now=T0 + 6 * M)
    assert s.harnesses["codex"].windows[0].status == "unmetered"


def test_a_stale_reading_is_flagged_as_a_lower_bound():
    w = snap(prof(), [R("claude", "weekly", 20, ts=T0 - 7 * H)]).harnesses["claude"].windows[0]
    assert "lower bound" in w.note
    w = snap(prof(), [R("claude", "weekly", 20, ts=T0 - 5 * H)]).harnesses["claude"].windows[0]
    assert "lower bound" not in w.note


def test_harness_status_is_its_worst_window_and_unmetered_without_readings():
    s = snap(prof(), [R("claude", "session", 10), R("claude", "weekly", exhausted=True)], now=T0 + M)
    assert s.harnesses["claude"].status == "exhausted"
    assert s.harnesses["codex"].status == "unmetered" and s.harnesses["codex"].windows == ()
    assert not snap(prof()).read and s.read


def test_newest_reading_per_window_wins_and_ties_prefer_the_fuller():
    got = {}
    assert quota.merge(got, [R("claude", "weekly", 50, ts=T0), R("claude", "weekly", 20, ts=T0 - H)]) == 1
    assert got[("claude", "weekly")].used_pct == 50
    quota.merge(got, [R("claude", "weekly", 10, ts=T0 + H)])
    assert got[("claude", "weekly")].used_pct == 10
    quota.merge(got, [R("claude", "weekly", exhausted=True, ts=T0 + H)])
    assert got[("claude", "weekly")].exhausted
    # same time, neither full: the higher percentage wins whichever comes first
    for order in ([50, 60], [60, 50]):
        got = {}
        quota.merge(got, [R("codex", "weekly", u, ts=T0) for u in order])
        assert got[("codex", "weekly")].used_pct == 60, order


def test_reading_validation():
    with pytest.raises(quota.QuotaError, match="unknown harness"):
        R("gemini", "weekly", 5)
    with pytest.raises(quota.QuotaError, match="needs a used percentage or exhausted"):
        R("claude", "weekly")
    with pytest.raises(quota.QuotaError, match="used_pct must be"):
        R("claude", "weekly", -3)
    with pytest.raises(quota.QuotaError, match="window name"):
        R("claude", " ", 3)


# ------------------------------------------------------------------ manual readings and the stored state

def test_record_writes_a_ledger_reading_that_merges_with_the_scanned_state(tmp_path):
    quota.save_state(tmp_path, {"files": {}, "readings": [R("claude", "weekly", 80, ts=T0 - H).to_dict()],
                                "last_ok": {"claude": T0 - 2 * H}})
    ledger.append("spend", workdir=tmp_path, usd=1.25, challenge_id="7")          # other events sit beside it
    rec = quota.record(tmp_path, "claude", "weekly", used_pct=30, resets_at=T0 + 86400, by="max", note="usage screen")
    ledger.append("progress", workdir=tmp_path, challenge_id="7", note="x")
    assert rec["event"] == "quota.reading" and rec["used_pct"] == 30.0 and rec["by"] == "max"
    latest, last_ok = quota.readings(tmp_path)
    assert latest[("claude", "weekly")].used_pct == 30 and latest[("claude", "weekly")].source == "manual"
    assert last_ok == {"claude": T0 - 2 * H}
    # a newer scanned reading beats the manual one
    st = quota.load_state(tmp_path)
    st["readings"] = [R("claude", "weekly", 90, ts=rec["ts"] + 5).to_dict()]
    quota.save_state(tmp_path, st)
    assert quota.readings(tmp_path)[0][("claude", "weekly")].used_pct == 90
    assert oct(quota.state_path(tmp_path).stat().st_mode & 0o777) == "0o600"


def test_record_refuses_what_is_not_a_reading(tmp_path):
    with pytest.raises(quota.QuotaError, match="name who took it"):
        quota.record(tmp_path, "claude", "weekly", used_pct=3, by=" ")
    with pytest.raises(quota.QuotaError, match="unknown harness"):
        quota.record(tmp_path, "copilot", "weekly", used_pct=3, by="max")
    with pytest.raises(quota.QuotaError, match="used percentage or exhausted"):
        quota.record(tmp_path, "claude", "weekly", by="max")
    assert list(ledger.read(tmp_path)) == []


def test_a_corrupt_state_file_raises_naming_it(tmp_path):
    quota.state_path(tmp_path).parent.mkdir(parents=True)
    quota.state_path(tmp_path).write_text("{nope")
    with pytest.raises(quota.QuotaError, match="corrupt quota state"):
        quota.readings(tmp_path)


# ------------------------------------------------------------------ scheduling

def test_writeups_are_scheduled_first_whatever_the_input_order():
    s = snap(prof(), [R("claude", "weekly", 85, resets=T0 + 86400), R("codex", "weekly", 100, resets=T0 + 86400)])
    plan = quota.schedule(s, [J("s1", "solve", est_pct=4), J("w1", "writeup", est_pct=4), J("r1", "retro", est_pct=1)])
    # claude at 95% (85 + 10 margin): room for 5; the writeup (listed second) gets 4, the retro 1, the solve none
    assert [(a.job, a.harness) for a in plan.assigned] == [("w1", "claude"), ("r1", "claude")]
    assert [h.job for h in plan.held] == ["s1"]


def test_route_to_the_healthy_harness_and_hold_with_reasons_per_harness():
    s = snap(prof(), [R("claude", "weekly", exhausted=True, resets=T0 + 2 * H), R("codex", "weekly", 20)], now=T0 + M)
    plan = quota.schedule(s, [J("a", "solve"), J("b", "solve", harnesses=("claude",))])
    assert [(a.job, a.harness, a.mode) for a in plan.assigned] == [("a", "codex", "fit")]
    hd = plan.held[0]
    assert hd.job == "b" and hd.release_at == T0 + 30 * M and "limit hit" in hd.reasons["claude"]


def test_a_held_job_waits_for_the_latest_of_its_harness_windows():
    # two limit hits on one harness: the session opens at its reset (T0 + 10 min), the weekly at its
    # recheck (T0 + 30 min); the job can run only when both are open
    s = snap(prof(recheck_minutes=30), [R("claude", "session", exhausted=True, resets=T0 + 10 * M),
                                        R("claude", "weekly", exhausted=True, resets=T0 + 3 * 86400)], now=T0 + M)
    plan = quota.schedule(s, [J("a", "solve", harnesses=("claude",))])
    assert plan.held[0].release_at == T0 + 30 * M
    # two metered windows past the limit: the session resets in 1 h, the week in 3 days
    s = snap(prof(), [R("codex", "session", 95, resets=T0 + H), R("codex", "weekly", 95, resets=T0 + 3 * 86400)])
    plan = quota.schedule(s, [J("b", "solve", harnesses=("codex",))])
    assert plan.held[0].release_at == T0 + 3 * 86400
    assert plan.batches == [(T0 + 3 * 86400, ("b",))]


def test_prefer_wins_when_it_fits_else_the_most_headroom():
    s = snap(prof(), [R("claude", "weekly", 10), R("codex", "weekly", 50)])
    plan = quota.schedule(s, [J("a", "solve", prefer="codex"), J("b", "solve")])
    assert [(a.job, a.harness) for a in plan.assigned] == [("a", "codex"), ("b", "claude")]
    assert plan.assigned[1].headroom_pct == 100 - 20 - 5
    full = snap(prof(), [R("claude", "weekly", 10), R("codex", "weekly", 89)])
    plan = quota.schedule(full, [J("a", "solve", prefer="codex", est_pct=5)])
    assert plan.assigned[0].harness == "claude"
    # most headroom, not input order of harnesses
    plan = quota.schedule(snap(prof(), [R("claude", "weekly", 60), R("codex", "weekly", 10)]), [J("c", "solve")])
    assert plan.assigned[0].harness == "codex"


def test_the_release_reserve_holds_solve_work_but_not_release_work():
    p = prof(releases=["2026-11-06T20:00:00Z"])
    s = snap(p, [R("claude", "weekly", 62, resets=T0 + 3 * 86400)])          # 72% with margin, limit 80
    plan = quota.schedule(s, [J("s", "solve", harnesses=("claude",), est_pct=10),
                              J("r", "release", harnesses=("claude",), est_pct=10)])
    assert [a.job for a in plan.assigned] == ["r"]
    held = plan.held[0]
    assert held.job == "s" and "reserve held for the release" in held.reasons["claude"]
    assert held.release_at == T0 + 3 * 86400
    # the same window resetting before the release: no reserve, the solve fits
    s = snap(p, [R("claude", "weekly", 62, resets=T0 + 2 * H)])
    plan = quota.schedule(s, [J("s", "solve", harnesses=("claude",), est_pct=10)])
    assert [a.job for a in plan.assigned] == ["s"]


def test_the_build_ceiling_holds_builds_while_solves_still_fit():
    s = snap(prof(), [R("claude", "weekly", 55, resets=T0 + 86400)])          # 65% with margin
    plan = quota.schedule(s, [J("b", "build", harnesses=("claude",), est_pct=10),
                              J("s", "solve", harnesses=("claude",), est_pct=10)])
    assert [a.job for a in plan.assigned] == ["s"] and plan.held[0].job == "b"
    assert "70% build limit" in plan.held[0].reasons["claude"]


def test_jobs_accumulate_on_a_window_so_fan_out_is_capped():
    s = snap(prof(), [R("codex", "weekly", 70)])                               # 80% with margin, room 20
    plan = quota.schedule(s, [J(f"s{i}", "solve", harnesses=("codex",), est_pct=6) for i in range(4)])
    assert [a.job for a in plan.assigned] == ["s0", "s1", "s2"]
    assert [h.job for h in plan.held] == ["s3"]
    assert [a.headroom_pct for a in plan.assigned] == pytest.approx([14, 8, 2])


def test_held_jobs_are_batched_by_the_time_they_open_soonest_first_unknown_last():
    s = snap(prof(), [R("claude", "weekly", 95, resets=T0 + 5 * H), R("codex", "session", 95, resets=T0 + 2 * H),
                      R("codex", "weekly", 20)])
    s2 = snap(prof(), [R("claude", "weekly", 95, resets=T0 + 5 * H), R("codex", "session", 95, resets=T0 + 2 * H),
                       R("codex", "spend", 99)])                               # no reset known on spend
    plan = quota.schedule(s, [J("a", "solve", harnesses=("claude",)), J("b", "solve"),
                              J("c", "solve", harnesses=("codex",))])
    assert [h.release_at for h in plan.held] == [T0 + 5 * H, T0 + 2 * H, T0 + 2 * H]
    assert plan.batches == [(T0 + 2 * H, ("b", "c")), (T0 + 5 * H, ("a",))]
    assert quota.next_wait(plan) == T0 + 2 * H
    plan = quota.schedule(s2, [J("c", "solve", harnesses=("codex",)), J("a", "solve", harnesses=("claude",))])
    assert plan.batches == [(T0 + 5 * H, ("a",)), (None, ("c",))]
    assert "no reset time known" in plan.held[0].reasons["codex"]


def test_a_probe_harness_takes_one_job_only_and_last():
    hit = R("codex", "limit", exhausted=True, ts=T0 - H, resets=T0 + 4 * 86400)
    s = snap(prof(), [hit])
    plan = quota.schedule(s, [J("a", "solve", harnesses=("codex",)), J("b", "solve", harnesses=("codex",))])
    assert [(a.job, a.mode) for a in plan.assigned] == [("a", "probe")]
    assert "probe job is already out" in plan.held[0].reasons["codex"]
    assert any("probe" in w for w in plan.warnings)
    s = snap(prof(), [hit, R("claude", "weekly", 10)])
    plan = quota.schedule(s, [J("a", "solve", prefer="codex")])
    assert plan.assigned[0].harness == "claude"


def test_an_unmetered_harness_takes_jobs_with_a_warning_after_a_metered_fit():
    s = snap(prof(), [R("claude", "weekly", 10)])
    plan = quota.schedule(s, [J("a", "solve", prefer="codex")])
    assert plan.assigned[0].harness == "claude" and not plan.warnings
    plan = quota.schedule(s, [J("a", "solve", harnesses=("codex",))])
    assert plan.assigned[0].mode == "unmetered" and plan.assigned[0].headroom_pct is None
    assert any(w.startswith("codex: no usable quota reading") for w in plan.warnings)


def test_job_validation_and_load_jobs():
    with pytest.raises(quota.QuotaError, match="unknown kind"):
        J("a", "nap")
    with pytest.raises(quota.QuotaError, match="prefer 'codex' is not one of its harnesses"):
        J("a", "solve", harnesses=("claude",), prefer="codex")
    with pytest.raises(quota.QuotaError, match="est_pct must be"):
        J("a", "solve", est_pct=0)
    with pytest.raises(quota.QuotaError, match="non-empty subset"):
        J("a", "solve", harnesses=("claude", "gemini"))
    with pytest.raises(quota.QuotaError, match="duplicate job id"):
        quota.load_jobs([{"id": "a", "kind": "solve"}, {"id": "a", "kind": "build"}])
    with pytest.raises(quota.QuotaError, match="unknown key"):
        quota.load_jobs([{"id": "a", "kind": "solve", "priority": 1}])
    with pytest.raises(quota.QuotaError, match="must be a JSON list"):
        quota.load_jobs({"nope": []})
    jobs = quota.load_jobs({"jobs": [{"id": "a", "kind": "solve", "harnesses": ["codex"], "est_pct": 3}]})
    assert jobs == [quota.Job("a", "solve", ("codex",), None, 3)] and jobs[0].est == 3
    assert J("w", "writeup").est == quota.DEFAULT_EST_PCT["writeup"]
    with pytest.raises(quota.QuotaError, match="duplicate"):
        quota.schedule(snap(prof()), [J("a", "solve"), J("a", "solve")])


# ------------------------------------------------------------------ the doctor's check

def _wd_with(tmp_path, readings, last_ok=None):
    quota.save_state(tmp_path, {"files": {}, "readings": [r.to_dict() for r in readings], "last_ok": last_ok or {}})
    return tmp_path


def test_check_warns_with_no_reading(tmp_path):
    c = quota.check(prof(), workdir=tmp_path, now=T0)
    assert c.name == "allowance" and c.status == "warn" and "no quota reading" in c.detail
    assert "quota scan" in c.fix


def test_check_fails_when_no_harness_can_take_release_work_at_the_release(tmp_path):
    p = prof(releases=["2026-11-06T20:00:00Z"])
    wd = _wd_with(tmp_path, [R("claude", "weekly", exhausted=True, ts=T0 - M, resets=T0 + 2 * 86400),
                             R("codex", "weekly", 95, resets=T0 + 86400)])
    c = quota.check(p, workdir=wd, now=T0)
    assert c.status == "fail" and "no harness can take release work at the next release" in c.detail
    # codex resets before the release: funded, so only a warning about claude
    wd = _wd_with(tmp_path, [R("claude", "weekly", exhausted=True, ts=T0 - M, resets=T0 + 2 * 86400),
                             R("codex", "weekly", 95, resets=T0 + 4 * H)])
    c = quota.check(p, workdir=wd, now=T0)
    assert c.status == "warn" and "claude is exhausted" in c.detail
    # a harness with no reading at all is not known to be blocked: warn, never fail
    wd = _wd_with(tmp_path, [R("claude", "weekly", exhausted=True, ts=T0 - M, resets=T0 + 2 * 86400)])
    c = quota.check(p, workdir=wd, now=T0)
    assert c.status == "warn" and "codex is unmetered" in c.detail
    # a hit that names no reset is not known to last past its recheck (T0 + 29 min here)
    wd = _wd_with(tmp_path, [R("claude", "spend", exhausted=True, ts=T0 - M),
                             R("codex", "weekly", 95, resets=T0 + 86400)])
    assert quota.check(prof(releases=["2026-11-06T12:10:00Z"], recheck_minutes=30), workdir=wd,
                       now=T0).status == "fail"
    assert quota.check(prof(releases=["2026-11-06T13:00:00Z"], recheck_minutes=30), workdir=wd,
                       now=T0).status == "warn"


def test_check_warns_on_an_eaten_reserve_and_passes_a_funded_release(tmp_path):
    p = prof(releases=["2026-11-06T20:00:00Z"])
    wd = _wd_with(tmp_path, [R("claude", "weekly", 75, resets=T0 + 3 * 86400), R("codex", "weekly", 10, resets=T0 + 86400)],
                  {"claude": T0, "codex": T0})
    c = quota.check(p, workdir=wd, now=T0)
    assert c.status == "warn" and "eaten into the 20% release reserve" in c.detail
    wd = _wd_with(tmp_path, [R("claude", "weekly", 60, resets=T0 + 3 * 86400), R("codex", "weekly", 10, resets=T0 + 86400)])
    c = quota.check(p, workdir=wd, now=T0)
    assert c.status == "ok" and "next release 2026-11-06 20:00 UTC" in c.detail


def test_check_warns_on_a_stale_reading(tmp_path):
    p = prof(releases=["2026-11-06T20:00:00Z"])
    wd = _wd_with(tmp_path, [R("claude", "weekly", 20, ts=T0 - 7 * H, resets=T0 + 86400),
                             R("codex", "weekly", 10, ts=T0, resets=T0 + 86400)])
    c = quota.check(p, workdir=wd, now=T0)
    assert c.status == "warn" and "claude weekly: 20% used" in c.detail and "lower bound" in c.detail
    wd = _wd_with(tmp_path, [R("claude", "weekly", 20, ts=T0 - 5 * H, resets=T0 + 86400),
                             R("codex", "weekly", 10, ts=T0, resets=T0 + 86400)])
    assert quota.check(p, workdir=wd, now=T0).status == "ok"


def test_check_warns_when_a_running_event_names_no_release(tmp_path):
    readings = [R("claude", "weekly", 20, resets=T0 + 86400), R("codex", "weekly", 10, resets=T0 + 86400)]
    wd = _wd_with(tmp_path, readings)
    c = quota.check(prof(), workdir=wd, now=T0)                                 # Nov 6: the event is running
    assert c.status == "warn" and "names no release" in c.detail and "pre-release reserve is off" in c.detail
    assert "set [allowance] releases or daily_release in events/qdemo/event.toml" in c.fix
    c = quota.check(prof(), workdir=tmp_path / "empty", now=T0)                 # no reading: said in both
    assert c.status == "warn" and "no quota reading" in c.detail and "names no release" in c.detail
    for p in (prof(daily_release="12:00"), prof(releases=["2026-11-20T12:00:00Z"])):
        assert quota.check(p, workdir=wd, now=T0).status == "ok"
    before = dt.datetime(2026, 10, 30, tzinfo=UTC).timestamp()                 # the start is the release
    after = dt.datetime(2026, 12, 2, tzinfo=UTC).timestamp()
    for now in (before, after):
        wd2 = _wd_with(tmp_path / str(int(now)), [R(h, "weekly", 10, ts=now, resets=now + 86400)
                                                  for h in ("claude", "codex")])
        c = quota.check(prof(), workdir=wd2, now=now)
        assert c.status == "ok" and "names no release" not in c.detail, now


def test_a_date_only_event_end_keeps_the_no_release_warning_through_its_last_day(tmp_path):
    # Three of the real profiles end on a bare date: the event runs to the end of that day in the
    # allowance time zone, so the warning holds all of Nov 6 (New York) and is gone on Nov 7.
    p = event.parse({"slug": "qd", "name": "Q", "dates": {"start": dt.date(2026, 11, 1), "end": dt.date(2026, 11, 6)},
                     "platform": {"kind": "ctfd", "base_url": "https://q.example"}, "flag": {"prefixes": ["Q"]},
                     "rules": {"submit_mode": "auto", "flag_sharing": "allowed", "ai_on_platform": "allowed"},
                     "allowance": {"tz": "America/New_York"}})
    def at(*args):
        return dt.datetime(*args, tzinfo=NY).timestamp()
    for now, warned in ((at(2026, 11, 6, 0, 30), True), (at(2026, 11, 6, 12), True),
                        (at(2026, 11, 6, 23, 59), True), (at(2026, 11, 7, 0, 0), False),
                        (at(2026, 11, 7, 9), False), (at(2026, 10, 31, 23, 59), False)):
        wd = _wd_with(tmp_path / str(int(now)), [R(h, "weekly", 10, ts=now, resets=now + 86400)
                                                 for h in ("claude", "codex")])
        c = quota.check(p, workdir=wd, now=now)
        assert ("names no release" in c.detail) is warned, (now, c.detail)
        assert c.status == ("warn" if warned else "ok"), (now, c.status, c.detail)


def test_check_fails_on_a_corrupt_state_and_doctor_runs_it(tmp_path, monkeypatch):
    quota.state_path(tmp_path).parent.mkdir(parents=True)
    quota.state_path(tmp_path).write_text("[")
    c = doctor.check_allowance(prof(), workdir=tmp_path, now=dt.datetime.fromtimestamp(T0, UTC))
    assert c.status == "fail" and "corrupt quota state" in c.detail
    monkeypatch.setenv("CTF_WORKDIR", str(_wd_with(tmp_path / "w", [R("claude", "weekly", 5), R("codex", "weekly", 5)])))
    cs = doctor.run_checks(prof(daily_release="12:00"), codex=False, now=dt.datetime.fromtimestamp(T0, UTC))
    allowance = [c for c in cs if c.name == "allowance"]          # B-190 appends checks after it
    assert len(allowance) == 1 and allowance[0].status == "ok"


# ------------------------------------------------------------------ the per-day ledger

def test_daily_groups_usage_by_harness_and_ledger_spend_by_category_in_the_zone():
    rows = [{"harness": "claude", "ts": "2026-11-06T23:30:00Z", "usd": 3.0},
            {"harness": "codex", "ts": "2026-11-06T10:00:00Z", "usd": 2.0},
            {"harness": "codex", "ts": "2026-11-06T11:00:00Z", "usd": None},       # unpriced
            {"harness": "claude", "ts": None, "usd": 9.0}]                          # undated

    def price(r):
        if r["usd"] is None:
            raise ValueError("no price")
        return r["usd"]
    recs = [{"event": "spend", "ts": dt.datetime(2026, 11, 6, 12, tzinfo=UTC).timestamp(), "usd": 1.5,
             "challenge_id": "7"},
            {"event": "spend", "ts": dt.datetime(2026, 11, 6, 13, tzinfo=UTC).timestamp(), "usd": 0.5,
             "category": "build"},
            {"event": "spend", "ts": dt.datetime(2026, 11, 6, 14, tzinfo=UTC).timestamp(), "usd": 0.25},
            {"event": "progress", "ts": T0, "challenge_id": "7"}]
    days, undated = quota.daily(rows, recs, price=price, tz="UTC", allowance_usd=4.0)
    assert undated == 1 and [d.date for d in days] == ["2026-11-06"]
    d = days[0]
    assert d.usage_usd == {"claude": 3.0, "codex": 2.0} and d.usage_total == 5.0 and d.unpriced == 1
    assert d.spend_usd == {"solve": 1.5, "build": 0.5, "uncategorized": 0.25} and d.spend_total == 2.25
    assert d.total == 5.0 and d.over
    days, _ = quota.daily(rows, recs, price=price, tz="Asia/Tokyo", allowance_usd=0.0)
    assert [x.date for x in days] == ["2026-11-06", "2026-11-07"]              # 23:30 UTC is the 7th in Tokyo
    assert days[1].usage_usd == {"claude": 3.0} and not any(x.over for x in days)


# ------------------------------------------------------------------ the scanner: text

def test_parse_reset_reads_every_shape_the_harnesses_print():
    ts = dt.datetime(2026, 11, 6, 15, 0, tzinfo=UTC).timestamp()              # 10:00 in New York
    assert qscan.parse_reset("Claude AI usage limit reached|1762470000", ts) == 1762470000
    assert qscan.parse_reset("5-hour limit reached ∙ resets 3pm", ts, NY) == \
        dt.datetime(2026, 11, 6, 15, tzinfo=NY).timestamp()
    assert qscan.parse_reset("5-hour limit reached ∙ resets 9am", ts, NY) == \
        dt.datetime(2026, 11, 7, 9, tzinfo=NY).timestamp()                     # already past today: tomorrow
    assert qscan.parse_reset("You've hit your limit · resets 1:50pm (America/New_York)", ts, UTC) == \
        dt.datetime(2026, 11, 6, 13, 50, tzinfo=NY).timestamp()                # the named zone wins
    assert qscan.parse_reset("Weekly limit reached ∙ resets Nov 10, 3pm", ts, NY) == \
        dt.datetime(2026, 11, 10, 15, tzinfo=NY).timestamp()
    assert qscan.parse_reset("Weekly limit reached ∙ resets Jan 2 at 12am", ts, NY) == \
        dt.datetime(2027, 1, 2, 0, tzinfo=NY).timestamp()                      # next year's
    assert qscan.parse_reset("You've hit your usage limit. Upgrade to Pro or try again at Nov 12th, 2026 11:55 AM.",
                             ts, NY) == dt.datetime(2026, 11, 12, 11, 55, tzinfo=NY).timestamp()
    assert qscan.parse_reset("You've hit your usage limit. Try again in 2 hours 5 minutes.", ts) == ts + 2 * H + 5 * M
    assert qscan.parse_reset("You've hit your usage limit. try again in 3 days 1 hour", ts) == ts + 3 * 86400 + H
    assert qscan.parse_reset("Usage limit reached", ts) is None
    # a bare time equal to the log time is tomorrow's (the reset that moment has just happened)
    assert qscan.parse_reset("5-hour limit reached ∙ resets 10am", ts, NY) == \
        dt.datetime(2026, 11, 7, 10, tzinfo=NY).timestamp()
    # a date without a year less than a day past is this year's (a late line), not next year's
    assert qscan.parse_reset("Weekly limit reached ∙ resets Nov 6, 9am", ts, NY) == \
        dt.datetime(2026, 11, 6, 9, tzinfo=NY).timestamp()
    # logged in late December, "Jan 2" is next year's and "Dec 31" this year's
    dec = dt.datetime(2026, 12, 30, 18, tzinfo=NY).timestamp()
    assert qscan.parse_reset("Weekly limit reached ∙ resets Jan 2, 1:50pm", dec, NY) == \
        dt.datetime(2027, 1, 2, 13, 50, tzinfo=NY).timestamp()
    assert qscan.parse_reset("Weekly limit reached ∙ resets Dec 31, 1:50pm", dec, NY) == \
        dt.datetime(2026, 12, 31, 13, 50, tzinfo=NY).timestamp()
    assert qscan.parse_reset("resets 25:00", ts, NY) is None


def test_limit_reading_names_the_window_and_skips_limits_that_are_not_quota():
    r = qscan.limit_reading("claude", "Weekly limit reached ∙ resets Nov 10, 3pm", T0, NY)
    assert (r.window, r.exhausted, r.source) == ("weekly", True, "claude-limit") and r.resets_at is not None
    assert qscan.limit_reading("claude", "5-hour limit reached ∙ resets 3pm", T0).window == "session"
    assert qscan.limit_reading("claude", "You've reached your spend limit", T0).window == "spend"
    assert qscan.limit_reading("codex", "You've hit your usage limit.", T0).window == "limit"
    for text in ("Concurrent subagent limit reached", "agent thread limit reached",
                 "API Error: 429 rate_limit_error", "prompt is too long: context limit reached", "all good"):
        assert qscan.limit_reading("claude", text, T0) is None, text


def _claude_err(text, ts="2026-11-06T12:00:00Z", cwd="/w", **mark):
    d = {"type": "assistant", "timestamp": ts, "cwd": cwd,
         "message": {"model": "<synthetic>", "role": "assistant", "content": [{"type": "text", "text": text}],
                     "usage": {"input_tokens": 0, "output_tokens": 0}}}
    d.update(mark)
    return json.dumps(d)


def _claude_ok(ts="2026-11-06T12:30:00Z", cwd="/w", text="done"):
    return json.dumps({"type": "assistant", "timestamp": ts, "cwd": cwd,
                       "message": {"id": "m1", "model": "claude-opus-5-5", "content": [{"type": "text", "text": text}],
                                   "usage": {"input_tokens": 5, "output_tokens": 7}}})


def test_claude_lines_only_error_lines_are_limit_hits():
    roots = sources.normalize_roots(["/w"])
    got = qscan.claude_line(_claude_err("Claude AI usage limit reached|1762470000"), roots=roots)
    assert got.readings[0].resets_at == 1762470000 and got.ok_ts is None
    marked = json.dumps({"type": "assistant", "timestamp": "2026-11-06T12:00:00Z", "isApiErrorMessage": True,
                         "message": {"model": "claude-opus-5-5", "content": [{"type": "text",
                                                                              "text": "Weekly limit reached"}]}})
    assert qscan.claude_line(marked, roots=roots).readings[0].window == "weekly"
    # an agent writing about a limit is a served response, not a hit
    quoting = qscan.claude_line(_claude_ok(text="the log said: Weekly limit reached ∙ resets 3pm"), roots=roots)
    assert quoting.readings == [] and quoting.ok_ts == dt.datetime(2026, 11, 6, 12, 30, tzinfo=UTC).timestamp()
    assert qscan.claude_line(_claude_ok(cwd="/elsewhere"), roots=roots) is None
    assert qscan.claude_line(_claude_err("Weekly limit reached", cwd="/elsewhere"), roots=roots) is None
    assert qscan.claude_line(_claude_err("API Error: 500"), roots=roots) is None
    assert qscan.claude_line(json.dumps({"type": "user", "message": "usage limit reached"}), roots=roots) is None


def _cx_count(used_p, used_s, *, ts="2026-11-06T12:00:00Z", served=True, resets_key="resets_at", rp=None, rs=None):
    def w(used, mins, r):
        return {"used_percent": used, "window_minutes": mins, resets_key: r}
    info = {"last_token_usage": {"input_tokens": 10, "output_tokens": 4}} if served else None
    return json.dumps({"timestamp": ts, "type": "event_msg", "payload": {
        "type": "token_count", "info": info,
        "rate_limits": {"primary": w(used_p, 300, rp), "secondary": w(used_s, 10080, rs)}}})


def test_codex_lines_rate_limits_errors_and_exec_streams():
    ts = dt.datetime(2026, 11, 6, 12, tzinfo=UTC).timestamp()
    got = qscan.codex_line(_cx_count(42.5, 12, rp=ts + 600, rs=ts + 86400), fallback_ts=0)
    r = {x.window: x for x in got.readings}
    assert r["session"].used_pct == 42.5 and r["session"].resets_at == ts + 600 and r["session"].window_minutes == 300
    assert r["weekly"].used_pct == 12 and r["weekly"].source == "codex-rate-limits" and got.ok_ts == ts
    got = qscan.codex_line(_cx_count(1, 2, resets_key="resets_in_seconds", rp=60, rs=120, served=False), fallback_ts=0)
    assert [x.resets_at for x in got.readings] == [ts + 60, ts + 120] and got.ok_ts is None
    err = json.dumps({"timestamp": "2026-11-06T12:00:00Z", "type": "event_msg",
                      "payload": {"type": "error", "message": "You've hit your usage limit. Try again in 3 hours."}})
    got = qscan.codex_line(err, fallback_ts=0)
    assert got.readings[0].exhausted and got.readings[0].resets_at == ts + 3 * H and not got.no_ts
    ex = json.dumps({"type": "turn.failed", "error": {"message": "You've hit your usage limit. Try again in 1 hour."}})
    got = qscan.codex_line(ex, fallback_ts=1000.0)
    assert got.no_ts and got.readings[0].ts == 1000.0 and got.readings[0].resets_at == 1000.0 + H
    assert "modification time" in got.readings[0].note
    input_only = json.loads(_cx_count(1, 2, rp=ts, rs=ts))
    input_only["payload"]["info"] = {"last_token_usage": {"input_tokens": 9, "output_tokens": 0}}
    assert qscan.codex_line(json.dumps(input_only), fallback_ts=0).ok_ts == ts
    input_only["payload"]["info"] = {"last_token_usage": {"input_tokens": 0, "output_tokens": 0}}
    assert qscan.codex_line(json.dumps(input_only), fallback_ts=0).ok_ts is None
    assert qscan.codex_line(json.dumps({"type": "turn.completed", "usage": {"input_tokens": 1}}),
                            fallback_ts=5.0).ok_ts == 5.0
    assert qscan.codex_line(json.dumps({"type": "error", "message": "agent thread limit reached"}),
                            fallback_ts=5.0) is None


# ------------------------------------------------------------------ the scanner: logs

def write(path, lines, mode="w"):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, mode) as fh:
        fh.write("".join(l + "\n" for l in lines))
    return path


@pytest.fixture
def homes(tmp_path):
    wd = (tmp_path / "work").resolve()
    (wd / "c1").mkdir(parents=True)
    ch, cx = tmp_path / "claude", tmp_path / "codex"
    (ch / "projects").mkdir(parents=True)
    (cx / "sessions").mkdir(parents=True)
    return wd, ch, cx


TID = "11111111-1111-4111-8111-111111111111"


def _snapshot_files(*dirs):
    return {p: p.read_bytes() for d in dirs for p in sorted(Path(d).rglob("*")) if p.is_file()}


def test_scan_reads_both_harnesses_incrementally_and_leaves_the_homes_untouched(homes, tmp_path):
    wd, ch, cx = homes
    proj = ch / "projects" / sources.claude_slug(str(wd / "c1"))
    clog = write(proj / "s1.jsonl", [_claude_ok(ts="2026-11-06T11:00:00Z", cwd=str(wd / "c1")),
                                     _claude_err("You've hit your weekly limit · resets Nov 10, 3pm (America/New_York)",
                                                 ts="2026-11-06T12:00:00Z", cwd=str(wd / "c1"))])
    xlog = write(cx / "sessions" / "2026" / "11" / "06" / f"rollout-2026-11-06T12-00-00-{TID}.jsonl",
                 [json.dumps({"type": "session_meta", "payload": {"id": TID, "cwd": str(wd / "c1")}}),
                  _cx_count(30, 70, rp=T0 + H, rs=T0 + 2 * 86400)])
    other = write(ch / "projects" / sources.claude_slug(str(tmp_path / "customer")) / "x.jsonl",
                  [_claude_err("Weekly limit reached", cwd=str(tmp_path / "customer"))])
    before = _snapshot_files(ch, cx)
    res = qscan.scan(wd, [wd], claude_home=ch, codex_home=cx)
    assert (res.logs, res.hits, res.served) == (2, 1, 2)
    latest, last_ok = quota.readings(wd)
    assert set(latest) == {("claude", "weekly"), ("codex", "session"), ("codex", "weekly")}
    assert latest[("claude", "weekly")].resets_at == dt.datetime(2026, 11, 10, 15, tzinfo=NY).timestamp()
    assert latest[("codex", "weekly")].used_pct == 70
    assert last_ok == {"claude": dt.datetime(2026, 11, 6, 11, tzinfo=UTC).timestamp(), "codex": T0}
    assert _snapshot_files(ch, cx) == before and other.is_file()
    # nothing new: nothing read; a later served Claude response clears the hit (status unmetered)
    again = qscan.scan(wd, [wd], claude_home=ch, codex_home=cx)
    assert (again.lines, again.hits, again.served) == (0, 0, 0)
    write(clog, [_claude_ok(ts="2026-11-06T12:20:00Z", cwd=str(wd / "c1"))], mode="a")
    with open(xlog, "a") as fh:
        fh.write(_cx_count(35, 71, ts="2026-11-06T12:21:00Z")[:40])                # a partial line waits
    third = qscan.scan(wd, [wd], claude_home=ch, codex_home=cx)
    assert (third.lines, third.served) == (1, 1)
    s = quota.snapshot(prof(), workdir=wd, now=T0 + 25 * M)
    assert s.harnesses["claude"].status == "unmetered"
    assert {w.window: w.effective_pct for w in s.harnesses["codex"].windows} == {"session": 40, "weekly": 80}


def test_scan_rereads_a_log_that_was_replaced_or_truncated(homes):
    wd, ch, cx = homes
    proj = ch / "projects" / sources.claude_slug(str(wd / "c1"))
    cwd = str(wd / "c1")
    pad = [_claude_ok(ts=f"2026-11-06T10:{i:02d}:00Z", cwd=cwd, text="x" * 200) for i in range(6)]
    log = write(proj / "s1.jsonl", pad)
    assert qscan.scan(wd, [wd], claude_home=ch, codex_home=cx).lines == 6
    # rotated: a new file (new inode) at the same path, longer than the old offset, a hit on its first line
    new = write(proj / "s1.new", [_claude_err("You've hit your weekly limit", ts="2026-11-06T11:00:00Z", cwd=cwd)]
                + pad + pad)
    old_ino = log.stat().st_ino
    os.replace(new, log)
    assert log.stat().st_ino != old_ino
    res = qscan.scan(wd, [wd], claude_home=ch, codex_home=cx)
    assert (res.lines, res.hits) == (13, 1)
    assert quota.readings(wd)[0][("claude", "weekly")].ts == dt.datetime(2026, 11, 6, 11, tzinfo=UTC).timestamp()
    # truncated in place (same inode, now shorter than the offset): read from the start again
    ino = log.stat().st_ino
    write(log, [_claude_err("5-hour limit reached ∙ resets 3pm", ts="2026-11-06T12:00:00Z", cwd=cwd)])
    assert log.stat().st_ino == ino
    res = qscan.scan(wd, [wd], claude_home=ch, codex_home=cx)
    assert (res.lines, res.hits) == (1, 1)
    assert ("claude", "session") in quota.readings(wd)[0]


def test_scan_without_roots_or_sources_fails_loudly(tmp_path, homes):
    from tools.ledger import usage
    wd, ch, cx = homes
    with pytest.raises(usage.UsageError, match="no roots"):
        qscan.scan(wd, [])
    with pytest.raises(sources.SourceError, match="no Claude Code projects folder"):
        qscan.scan(wd, [wd], claude_home=tmp_path / "nope", codex_home=cx)


# ------------------------------------------------------------------ CLI

def _args(*argv):
    p = argparse.ArgumentParser()
    qcli.add_arguments(p)
    return p.parse_args(list(argv))


@pytest.fixture
def cli_env(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "wd"))
    return tmp_path / "wd"


def test_cli_set_status_plan_and_gate(cli_env, tmp_path, capsys):
    now = "2026-11-06T12:00:00Z"
    assert qcli.run(_args("--event", "csctf", "set", "claude", "--window", "weekly", "--used", "85",
                          "--resets", "+2d", "--by", "max")) == 0
    assert qcli.run(_args("--event", "csctf", "set", "codex", "--window", "weekly", "--exhausted",
                          "--by", "max", "--note", "out")) == 0
    recs = [r for r in ledger.read(cli_env) if r["event"] == "quota.reading"]
    assert [(r["harness"], r.get("used_pct"), r["exhausted"]) for r in recs] == [("claude", 85.0, False),
                                                                                  ("codex", None, True)]
    assert recs[0]["resets_at"] == pytest.approx(recs[0]["ts"] + 2 * 86400, abs=5)
    capsys.readouterr()
    assert qcli.run(_args("--event", "csctf", "status", "--json")) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["harnesses"]["claude"]["windows"][0]["effective_pct"] == 95
    assert doc["harnesses"]["codex"]["status"] == "exhausted"
    jobs = tmp_path / "jobs.json"
    jobs.write_text(json.dumps([{"id": "s", "kind": "solve", "est_pct": 3}, {"id": "w", "kind": "writeup", "est_pct": 3}]))
    assert qcli.run(_args("--event", "csctf", "plan", "--jobs", str(jobs), "--json")) == 3
    plan = json.loads(capsys.readouterr().out)
    assert [a["job"] for a in plan["assigned"]] == ["w"] and [h["job"] for h in plan["held"]] == ["s"]
    assert qcli.run(_args("--event", "csctf", "gate", "--kind", "writeup", "--est", "2")) == 0
    assert capsys.readouterr().out.strip() == "claude"
    assert qcli.run(_args("--event", "csctf", "gate", "--kind", "build")) == 3
    assert "held until" in capsys.readouterr().err
    assert qcli.run(_args("--event", "csctf", "--now", now, "check")) == 0     # warn is not a failure
    assert "WARN  allowance" in capsys.readouterr().out


def test_cli_wait_sleeps_until_the_batch_opens_and_releases_it(cli_env, tmp_path, monkeypatch, capsys):
    slept = []
    monkeypatch.setattr(qcli, "_sleep", slept.append)
    quota.save_state(cli_env, {"files": {}, "readings": [R("claude", "weekly", 95, resets=T0 + H).to_dict(),
                                                         R("codex", "weekly", 98, resets=T0 + 3 * H).to_dict()],
                               "last_ok": {}})
    jobs = tmp_path / "jobs.json"
    jobs.write_text(json.dumps([{"id": "s", "kind": "solve"}]))
    rc = qcli.run(_args("--event", "csctf", "--now", str(T0), "wait", "--jobs", str(jobs), "--grace", "60"))
    out = capsys.readouterr()
    assert rc == 0 and slept == [H + 60] and "RELEASED s (solve) on claude" in out.out
    slept.clear()
    rc = qcli.run(_args("--event", "csctf", "--now", str(T0), "wait", "--jobs", str(jobs), "--max-wait", "600"))
    assert rc == 3 and slept == [600.0] and "past --max-wait" in capsys.readouterr().err
    jobs.write_text(json.dumps([{"id": "s", "kind": "solve", "harnesses": ["codex"], "est_pct": 50}]))
    quota.save_state(cli_env, {"files": {}, "readings": [R("codex", "spend", 98).to_dict()], "last_ok": {}})
    rc = qcli.run(_args("--event", "csctf", "--now", str(T0), "wait", "--jobs", str(jobs)))
    assert rc == 1 and "no held job has a known release time" in capsys.readouterr().err


def test_cli_named_errors_exit_2(cli_env, tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps([{"id": "a", "kind": "nap"}]))
    assert qcli.run(_args("--event", "csctf", "plan", "--jobs", str(bad))) == 2
    assert "unknown kind 'nap'" in capsys.readouterr().err
    assert qcli.run(_args("--event", "csctf", "plan", "--jobs", str(tmp_path / "none.json"))) == 2
    assert qcli.run(_args("--event", "no-such", "status")) == 2
    assert qcli.run(_args("--event", "csctf", "scan", "--log", "x")) == 2
    assert "--log needs --harness" in capsys.readouterr().err


def test_cli_daily_prices_the_usage_store_and_flags_an_over_day(cli_env, tmp_path, capsys, monkeypatch):
    store = cli_env / "usage" / "responses.jsonl"
    store.parent.mkdir(parents=True)
    row = {"key": "claude:m1", "harness": "claude", "agent": "s", "model": "claude-opus-5-5", "speed": "standard",
           "ts": "2026-11-06T12:00:00Z", "input": 0, "cache_read": 0, "cache_5m": 0, "cache_1h": 0,
           "output": 1_000_000, "web_search": 0}
    store.write_text(json.dumps(row) + "\n")
    from tools.ledger import pricing
    usd = pricing.cost(row, pricing.load_prices())
    assert qcli.run(_args("--event", "csctf", "daily", "--json")) == 0       # no allowance set: never over
    doc = json.loads(capsys.readouterr().out)
    assert doc["days"][0]["usage_usd"] == {"claude": pytest.approx(usd)} and doc["allowance_usd"] == 0.0
    real = event.load("csctf")
    import dataclasses
    capped = dataclasses.replace(real, allowance=dataclasses.replace(real.allowance, daily_usd=usd / 2))
    monkeypatch.setattr(qcli, "_profile", lambda args: capped)
    assert qcli.run(_args("daily")) == 1
    assert "OVER" in capsys.readouterr().out


def test_python_m_ctf_lists_and_runs_quota(tmp_path):
    e = dict(os.environ, CTF_WORKDIR=str(tmp_path))
    r = subprocess.run([sys.executable, "-m", "ctf", "quota", "--event", "csctf", "status"], cwd=paths.repo_root(),
                       env=e, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    assert "claude: UNMETERED" in r.stdout and "no reading" in r.stdout
