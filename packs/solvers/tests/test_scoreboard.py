"""B-099: automatic scoreboard ingestion and first-blood benchmarking.

The live paths run against ctf.fakectfd on 127.0.0.1 (never a real platform). The benchmark is
driven with synthetic store states and ledger records.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import time

import pytest

from ctf import event, ledger
from ctf import scoreboard as sb
from ctf.cli import scoreboard as cli
from ctf.fakectfd import FakeChallenge, FakeCTFd
from ctf.platform import (ChallengeSolve, NotAllowed, NotSupported, PlatformError, challenge_solves,
                          get_adapter, latency, wire)
from ctf.platform import ctfd, gamemaster, manual

UTC = dt.timezone.utc
TOKEN = "tok-b099-test"
T0 = 1_900_000_000.0                       # a synthetic release (2030)


def profile(kind="ctfd", base_url="https://demo.example/", team="us", wire_pace=None, ai="allowed"):
    plat = {"kind": kind}
    if kind != "manual":
        plat["base_url"] = base_url
    if team is not None:
        plat["team"] = team
    d = {"slug": "demo", "name": "Demo CTF", "categories": ["Web", "Crypto"],
         "dates": {"start": dt.datetime(2030, 3, 1, tzinfo=UTC), "end": dt.datetime(2030, 3, 3, tzinfo=UTC)},
         "platform": plat, "flag": {"prefixes": ["DEMO"]},
         "rules": {"submit_mode": "manual" if (kind == "manual" or ai == "forbidden") else "auto",
                   "flag_sharing": "allowed", "ai_on_platform": ai}}
    if wire_pace:
        d["wire"] = wire_pace
    return event.parse(d)


@pytest.fixture
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_TOKEN", TOKEN)
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    monkeypatch.delenv("CTF_PLATFORM_URL", raising=False)
    monkeypatch.delenv("CTF_WIRE_LANE", raising=False)
    return tmp_path / "work"


def board():
    return [
        FakeChallenge(1, "warm", "Web", flag="DEMO{w}", value=100,
                      board_solves=[("rivals", T0 + 40.0), ("us", T0 + 25.0), ("third", T0 + 90.0)]),
        FakeChallenge(2, "rsa", "Crypto", flag="DEMO{r}", value=300,
                      board_solves=[("rivals", T0 + 100.0)]),
        FakeChallenge(3, "fresh", "Web", flag="DEMO{f}", value=200),
    ]


def gate_for(fake, **kw):
    return get_adapter(profile(base_url=fake.base_url, **kw))


# ------------------------------------------------------------------------------- the fake CTFd

def test_fake_board_serves_standings_and_per_challenge_solves(env):
    with FakeCTFd(board(), token=TOKEN, team_name="us", wall=lambda: T0 + 500.0) as fake:
        # rivals 100 + 300; us and third 100 each, us first (reached it earlier)
        assert fake.standings() == [
            {"pos": 1, "account_id": 2, "account_type": "team", "name": "rivals", "score": 400},
            {"pos": 2, "account_id": 1, "account_type": "team", "name": "us", "score": 100},
            {"pos": 3, "account_id": 3, "account_type": "team", "name": "third", "score": 100}]
        a = ctfd.CTFdAdapter(fake.base_url, token=TOKEN, pacer_state_dir=env / "pace", submit_interval_s=0.0)
        assert a.scoreboard()[0].team == "rivals" and a.scoreboard()[0].score == 400
        # a correct attempt in the run puts our solve on the board at the fake's wall clock
        assert a.submit("3", "DEMO{f}").status.value == "correct"
        assert [s.account for s in a.challenge_solves("3")] == ["us"]
        assert a.challenge_solves("3")[0].at == pytest.approx(T0 + 500.0)
        assert [(r.team, r.score) for r in a.scoreboard()][:2] == [("rivals", 400), ("us", 300)]
        assert {r.kind for r in fake.log} >= {"scoreboard", "challenge_solves"}


def test_ctfd_challenge_solves_maps_and_orders_earliest_first(env):
    with FakeCTFd(board(), token=TOKEN) as fake:
        a = ctfd.CTFdAdapter(fake.base_url, token=TOKEN)
        got = a.challenge_solves("1")
    assert [(s.account, s.at) for s in got] == [("us", T0 + 25.0), ("rivals", T0 + 40.0), ("third", T0 + 90.0)]
    assert all(isinstance(s, ChallengeSolve) and s.challenge_id == "1" and s.account_id for s in got)


def test_ctfd_challenge_solves_sorts_rows_the_platform_sends_out_of_order(env):
    # FakeCTFd itself answers earliest first, so this double sends the rows shuffled, with an
    # untimed one in the middle: the adapter's own ordering is what puts them right.
    class Shuffled(FakeCTFd):
        def _route(self, method, path, body, authed):
            if path == "/api/v1/challenges/1/solves":
                return 200, "challenge_solves", {"success": True, "data": [
                    {"name": "c", "date": "2030-01-01T00:00:30Z", "account_id": 3},
                    {"name": "u", "date": None, "account_id": 4},
                    {"name": "a", "date": "2030-01-01T00:00:10Z", "account_id": 1},
                    {"name": "b", "date": "2030-01-01T00:00:20Z", "account_id": 2}]}, None
            return super()._route(method, path, body, authed)
    with Shuffled(board(), token=TOKEN) as fake:
        got = ctfd.CTFdAdapter(fake.base_url, token=TOKEN).challenge_solves("1")
    assert [s.account for s in got] == ["a", "b", "c", "u"]
    assert got[-1].at is None and got[0].at < got[1].at < got[2].at


def test_ctfd_challenge_solves_hidden_scores_is_not_supported_named(env):
    with FakeCTFd(board(), token=TOKEN, scores_hidden=True) as fake:
        a = ctfd.CTFdAdapter(fake.base_url, token=TOKEN)
        with pytest.raises(NotSupported, match=r"/challenges/1/solves -> HTTP 403"):
            a.challenge_solves("1")


def test_ctfd_solve_without_account_name_is_an_error_not_a_guess(env):
    class Nameless(FakeCTFd):
        def _route(self, method, path, body, authed):
            if path == "/api/v1/challenges/1/solves":
                return 200, "challenge_solves", {"success": True, "data": [{"date": "2030-01-01T00:00:00Z"}]}, None
            return super()._route(method, path, body, authed)
    with Nameless(board(), token=TOKEN) as fake:
        with pytest.raises(PlatformError, match="names no account") as e:
            ctfd.CTFdAdapter(fake.base_url, token=TOKEN).challenge_solves("1")
        assert not isinstance(e.value, NotSupported)


def test_gamemaster_and_manual_refuse_by_name_without_a_request(tmp_path):
    class Recorder:
        headers: dict = {}
        calls: list = []

        def request(self, *a, **k):
            self.calls.append(a)
            raise AssertionError("no request may be sent")
    gm = gamemaster.GameMasterAdapter("http://127.0.0.1:9", token="t", session=Recorder())
    with pytest.raises(NotSupported, match="Game Master publishes no other team's solves") as e:
        challenge_solves(gm, "web-day-01")
    assert not isinstance(e.value, NotAllowed)
    m = manual.make_adapter(profile(kind="manual"), drop_dir=tmp_path / "drop")
    with pytest.raises(NotAllowed, match="is manual"):
        challenge_solves(m, "1")
    assert Recorder.calls == []


def test_challenge_solves_helper_names_an_adapter_without_the_call():
    class Bare:
        kind = "odd"
    with pytest.raises(NotSupported, match="the odd adapter offers no per-challenge solves"):
        challenge_solves(Bare(), "1")


def test_wire_names_the_per_challenge_solves_op():
    base = "https://ctf.example/sub"
    assert wire.op_of("ctfd", "GET", base + "/api/v1/challenges/17/solves", base_url=base) == ("solves", "17")
    assert wire.op_class("solves") == wire.READ
    assert wire.op_of("ctfd", "GET", base + "/api/v1/challenges/17/files", base_url=base) == ("api:challenges", None)


# ------------------------------------------------------------------------------- ingest

def test_ingest_stores_board_solves_and_first_bloods(env):
    with FakeCTFd(board(), token=TOKEN) as fake:
        g = gate_for(fake)
        r = sb.ingest(g)
        kinds = [x.kind for x in fake.log]
    assert r.deferred is None and r.ok and r.board_rows == 3 and r.challenges == 3
    assert sorted(r.fetched) == ["1", "2"]                     # 3 has no solve: no read
    assert kinds.count("challenge_solves") == 2 and kinds.count("scoreboard") == 1
    st = sb.load(env)
    assert st["board"][0] == [1, "rivals", 400]
    e1 = st["challenges"]["1"]
    assert (e1["name"], e1["category"], e1["count"]) == ("warm", "Web", 3)
    assert sb.first_blood(e1)["account"] == "us"
    assert st["challenges"]["3"]["solves"] == [] and st["challenges"]["3"]["count"] == 0
    fbs = {f["challenge_id"]: f for f in r.first_bloods}
    assert fbs["1"]["ours"] is True and fbs["2"]["ours"] is False and fbs["2"]["account"] == "rivals"
    evs = sb.read_events(env)
    assert [e["event"] for e in evs] == ["board", "first_blood", "first_blood"]
    # every request was journaled under the board lane with its op
    rows, _ = wire.read_journal(env)
    assert {x["lane"] for x in rows} == {sb.LANE}
    assert {(x["op"], x["challenge"]) for x in rows if x["op"] == "solves"} == {("solves", "1"), ("solves", "2")}
    assert wire.of(g).lane is None                              # the lane was given back


def test_ingest_reads_only_changed_challenges_and_reports_new_first_blood(env):
    b = board()
    with FakeCTFd(b, token=TOKEN) as fake:
        g = gate_for(fake)
        sb.ingest(g)
        n0 = len(fake.log)
        r = sb.ingest(g)
        assert r.fetched == [] and r.first_bloods == []
        assert [x.kind for x in fake.log[n0:]] == ["scoreboard", "list"]
        b[2].board_solves.append(("rivals", T0 + 300.0))       # challenge 3 gets its first solve
        r = sb.ingest(g)
    assert r.fetched == ["3"]
    assert r.first_bloods == [{"challenge_id": "3", "account": "rivals", "at": T0 + 300.0, "ours": False}]


def test_ingest_stores_the_list_count_not_the_rows_read(env):
    # A capped or paginated solves endpoint returns fewer rows than the list's count: the stored
    # count must be the list's, or the challenge looks changed (and is re-read) every cycle.
    class Capped(FakeCTFd):
        def _row(self, c):
            row = super()._row(c)
            if c.id == 1:
                row["solves"] = 7
            return row
    with Capped(board(), token=TOKEN) as fake:
        g = gate_for(fake)
        sb.ingest(g)
        assert sb.load(env)["challenges"]["1"]["count"] == 7
        assert len(sb.load(env)["challenges"]["1"]["solves"]) == 3
        n0 = len(fake.log)
        r = sb.ingest(g)
        assert r.fetched == [] and [x.kind for x in fake.log[n0:]] == ["scoreboard", "list"]


def test_ingest_caps_solves_reads_and_reads_never_read_ones_first(env):
    b = board()
    with FakeCTFd(b, token=TOKEN) as fake:
        g = gate_for(fake)
        r = sb.ingest(g, max_solves=1)
        assert r.fetched == ["1"] and r.pending == ["2"]
        assert [x.kind for x in fake.log].count("challenge_solves") == 1
        b[0].board_solves.append(("late", T0 + 999.0))       # 1 changed too, but 2 was never read
        r2 = sb.ingest(g, max_solves=1)
        assert r2.fetched == ["2"] and r2.pending == ["1"]
        r3 = sb.ingest(g, max_solves=0)
    assert r3.fetched == [] and r3.pending == ["1"]
    with pytest.raises(ValueError):
        sb.ingest(g, max_solves=-1)


def test_ingest_snapshot_keeps_the_top_rows_and_ours(env):
    with FakeCTFd(board(), token=TOKEN) as fake:
        sb.ingest(get_adapter(profile(base_url=fake.base_url, team="third")), keep_rows=1)
    snap = sb.read_events(env)[0]
    assert snap["event"] == "board" and snap["rows"] == [[1, "rivals", 400], [3, "third", 100]]


def test_ingest_without_team_marks_first_bloods_unknown(env):
    with FakeCTFd(board(), token=TOKEN) as fake:
        r = sb.ingest(get_adapter(profile(base_url=fake.base_url, team=None)))
    assert {f["ours"] for f in r.first_bloods} == {None}


def test_ingest_defers_in_a_release_window_and_sends_nothing(env):
    with FakeCTFd(board(), token=TOKEN) as fake:
        g = gate_for(fake)
        wire.mark_releases(env, [time.time() - 5.0])
        r = sb.ingest(g)
        assert r.deferred and "release window" in r.deferred
        assert fake.log == [] and not (env / sb.DIR_NAME / sb.STATE_NAME).exists()
        r = sb.ingest(g, force=True)
        assert r.deferred is None and r.fetched


def test_ingest_defers_while_the_wire_is_paused(env):
    with FakeCTFd(board(), token=TOKEN) as fake:
        g = gate_for(fake)
        w = wire.of(g)
        with wire._locked(env):
            st = wire._read_state(env, time.time(), w.err)
            st["pause_until"] = time.time() + 600.0
            wire._write_state(env, st)
        r = sb.ingest(g)
    assert r.deferred and "paused" in r.deferred and fake.log == []


def test_ingest_uses_at_most_half_the_team_budget(env):
    pace = {"per_minute": 12, "reserve": 2}
    with FakeCTFd(board(), token=TOKEN) as fake:
        g = gate_for(fake, wire_pace=pace)
        r = sb.ingest(g)
        # the board may use half of (12 - 2) = 5: scoreboard, list and two solves reads stay under it
        assert r.fetched == ["1", "2"] and r.deferred is None
        n = len(fake.log)
        assert n == 4
        r = sb.ingest(g)                               # 4 requests in the last 60 s: one more allowed
        assert r.deferred is None
        r = sb.ingest(g)                               # now 6 >= 5: deferred, nothing sent
        assert r.deferred and "at most 5" in r.deferred
        assert len(fake.log) == n + 2


def test_ingest_stops_mid_cycle_when_the_minute_fills(env):
    pace = {"per_minute": 8, "reserve": 0}             # the board may use 4
    b = board() + [FakeChallenge(4, "x", "Web", board_solves=[("rivals", T0 + 1.0)]),
                   FakeChallenge(5, "y", "Web", board_solves=[("rivals", T0 + 2.0)])]
    with FakeCTFd(b, token=TOKEN) as fake:
        r = sb.ingest(gate_for(fake, wire_pace=pace))
        assert len(r.fetched) == 2 and len(r.pending) == 2
        assert r.deferred.startswith("stopped after 2 solves read(s)")
        assert len(fake.log) == 4
    assert set(sb.load(env)["challenges"]) == {"1", "2", "3", "4", "5"}


def test_ingest_hidden_solves_saves_standings_then_raises(env):
    class HiddenSolves(FakeCTFd):
        def _route(self, method, path, body, authed):
            if path.endswith("/solves") and "/challenges/" in path:
                return 403, "challenge_solves", {"success": False}, None
            return super()._route(method, path, body, authed)
    with HiddenSolves(board(), token=TOKEN) as fake:
        with pytest.raises(NotSupported, match="HTTP 403.*standings were saved"):
            sb.ingest(gate_for(fake))
    assert sb.load(env)["board"][0] == [1, "rivals", 400]


def test_ingest_keeps_one_failed_read_as_an_error_and_goes_on(env):
    class Flaky(FakeCTFd):
        def _route(self, method, path, body, authed):
            if path == "/api/v1/challenges/1/solves":
                return 500, "challenge_solves", {"success": False}, None
            return super()._route(method, path, body, authed)
    with Flaky(board(), token=TOKEN) as fake:
        r = sb.ingest(gate_for(fake))
    assert not r.ok and "HTTP 500" in r.errors[0] and r.fetched == ["2"]
    assert sb.load(env)["challenges"]["1"]["fetched"] is None     # read again next cycle


def test_ingest_refuses_gamemaster_and_manual_by_name(env):
    gm = get_adapter(profile(kind="gamemaster", base_url="http://127.0.0.1:9/"))
    with pytest.raises(NotSupported, match="no scoreboard op") as e:
        sb.ingest(gm)
    assert not isinstance(e.value, NotAllowed)
    assert wire.read_journal(env)[0] == []
    with pytest.raises(NotAllowed, match="is manual"):
        sb.ingest(get_adapter(profile(kind="manual")))
    with pytest.raises(NotAllowed):                     # forbidden automation is manual whatever the kind
        sb.ingest(get_adapter(profile(ai="forbidden")))


def test_corrupt_state_fails_loudly(env):
    (env / sb.DIR_NAME).mkdir(parents=True)
    (env / sb.DIR_NAME / sb.STATE_NAME).write_text("{not json")
    with pytest.raises(sb.ScoreboardError, match="not JSON"):
        sb.load(env)
    (env / sb.DIR_NAME / sb.STATE_NAME).write_text(json.dumps({"schema": 99, "challenges": {}}))
    with pytest.raises(sb.ScoreboardError, match="not schema 1"):
        sb.load(env)


def test_watch_runs_cycles_and_survives_a_platform_error(env):
    b = board()
    slept, errs, got = [], [], []

    class Flaky(FakeCTFd):
        n = 0

        def _route(self, method, path, body, authed):
            if path == "/api/v1/scoreboard":
                Flaky.n += 1
                if Flaky.n == 2:                     # the second cycle's first read fails
                    return 500, "scoreboard", {"success": False}, None
            return super()._route(method, path, body, authed)

    def tick(s):                                       # between cycles a rival solves challenge 3
        slept.append(s)
        b[2].board_solves.append(("late", T0 + 900.0 + len(slept)))
    with Flaky(b, token=TOKEN) as fake:
        out = sb.watch(gate_for(fake), cycles=3, interval_s=7.0, sleep=tick, on_error=errs.append,
                       on_result=got.append, max_solves=4)
    assert len(out) == 2 and got == out and len(errs) == 1 and "HTTP 500" in str(errs[0])
    assert slept == [7.0, 7.0]
    assert out[1].fetched == ["3"]                     # the third cycle saw the new solves
    with pytest.raises(ValueError):
        sb.watch(object(), cycles=0)


def test_watch_stops_on_not_supported():
    gm = get_adapter(profile(kind="gamemaster", base_url="http://127.0.0.1:9/"))
    with pytest.raises(NotSupported):
        sb.watch(gm, cycles=5, interval_s=1.0, sleep=lambda s: None)


# ------------------------------------------------------------------------------- bench

def _state(**challenges):
    return {"schema": 1, "board": [], "board_at": None, "updated": None,
            "challenges": {cid: {"name": f"c{cid}", "category": cat, "count": len(sol),
                                 "fetched": 1.0,
                                 "solves": [{"account": a, "at": t, "account_id": None} for a, t in sol]}
                           for cid, (cat, sol) in challenges.items()}}


def _ledger(*accepted, t0=T0):
    recs = [{"ts": t0 + 2.0, "event": "wave_open", "wave": "W1", "count": 5, "announced": t0}]
    for cid, ts in accepted:
        recs.append({"ts": t0 + 3.0, "event": "detect", "challenge_id": cid, "wave": "W1"})
        recs.append({"ts": ts, "event": "platform.submit", "challenge_id": cid, "status": "correct"})
    return recs


def test_bench_statuses_gaps_places_and_verdicts():
    st = _state(**{
        "1": ("Web", [("rivals", T0 + 40.0), ("Us", T0 + 25.0)]),          # won; board time used
        "2": ("Web", [("rivals", T0 + 100.0), ("third", T0 + 120.0), ("us", T0 + 150.0)]),   # lost, place 3
        "3": ("Crypto", [("rivals", T0 + 60.0)]),                          # unsolved by us
        "4": ("Crypto", [("us", T0 + 10.0)]),                              # uncontested
        "5": ("Web", [("rivals", T0 + 100.0)]),                            # lost: ours from the ledger only
        "6": ("Web", []),                                                  # nobody: no row
    })
    recs = _ledger(("1", T0 + 26.0), ("2", T0 + 151.0), ("5", T0 + 69.0 + 50.0))
    b = sb.bench(st, recs, team="us")
    rows = {r.challenge_id: r for r in b.rows}
    assert set(rows) == {"1", "2", "3", "4", "5"}
    r1, r2, r3, r4, r5 = (rows[c] for c in "12345")
    assert (r1.status, r1.ours_source, r1.gap_s, r1.place, r1.rival) == ("won", "board", -15.0, 1, "rivals")
    # elapsed from the ledger's clock (26 s), target = 40 * 0.7 = 28: PASS
    assert (r1.ours_elapsed_s, r1.rival_elapsed_s, r1.target_s, r1.verdict) == (26.0, 40.0, 28.0, "PASS")
    assert (r2.status, r2.gap_s, r2.place, r2.verdict) == ("lost", 50.0, 3, "FAIL")
    assert (r3.status, r3.ours_at, r3.place, r3.verdict, r3.target_s) == ("unsolved", None, None, "FAIL", 42.0)
    assert (r4.status, r4.rival, r4.gap_s, r4.verdict) == ("uncontested", None, None, "NOTARGET")
    assert (r5.status, r5.ours_source, r5.gap_s, r5.ours_elapsed_s) == ("lost", "ledger", 19.0, 119.0)
    lanes = {x.lane: x for x in b.lanes}
    web, cr = lanes["Web"], lanes["Crypto"]
    assert (web.challenges, web.won, web.lost, web.unsolved, web.passed, web.failed) == (3, 1, 2, 0, 1, 2)
    assert (web.median_gap_s, web.best_gap_s, web.worst_gap_s) == (19.0, -15.0, 50.0)
    assert web.lost_to == {"rivals": 2}
    assert (cr.unsolved, cr.uncontested, cr.failed, cr.notarget, cr.lost_to) == (1, 1, 1, 1, {"rivals": 1})
    assert b.notes == []


def test_bench_margin_moves_the_target():
    st = _state(**{"1": ("Web", [("rivals", T0 + 40.0)])})
    recs = _ledger(("1", T0 + 30.0))
    assert sb.bench(st, recs, team="us").rows[0].verdict == "FAIL"          # 30 > 28
    r = sb.bench(st, recs, team="us", margin=0.2).rows[0]
    assert (r.target_s, r.verdict) == (32.0, "PASS")
    assert sb.bench(st, _ledger(("1", T0 + 28.0)), team="us").rows[0].verdict == "PASS"   # on target
    with pytest.raises(ValueError):
        sb.bench(st, recs, team="us", margin=1.0)


def test_bench_a_tie_with_the_rival_is_a_won_first_blood():
    st = _state(**{"1": ("Web", [("rivals", T0 + 40.0), ("us", T0 + 40.0), ("third", T0 + 39.0)])})
    r = sb.bench(st, [], team="us").rows[0]
    # third was first: lost, place 2 (one solve strictly earlier), rival is third
    assert (r.status, r.place, r.rival, r.gap_s) == ("lost", 2, "third", 1.0)
    st = _state(**{"1": ("Web", [("rivals", T0 + 40.0), ("us", T0 + 40.0)])})
    r = sb.bench(st, [], team="us").rows[0]
    assert (r.status, r.place, r.gap_s) == ("won", 1, 0.0)


def test_bench_without_release_is_notarget_and_says_so():
    st = _state(**{"1": ("Web", [("rivals", T0 + 40.0), ("us", T0 + 30.0)])})
    b = sb.bench(st, [], team="us")
    assert b.rows[0].verdict == "NOTARGET" and b.rows[0].status == "won"
    assert any("release times unknown" in n for n in b.notes)
    b = sb.bench(st, [], team="us", t0=T0)
    assert (b.rows[0].ours_elapsed_s, b.rows[0].verdict) == (30.0, "FAIL")      # 30 > 40 * 0.7
    # an unsolved row with a release still fails the yardstick
    st2 = _state(**{"1": ("Web", [("rivals", T0 + 40.0)])})
    assert sb.bench(st2, [], team="us", t0=T0).rows[0].verdict == "FAIL"


def test_bench_places_an_unstaged_challenge_in_the_wave_open_at_its_first_solve():
    # Our ledger never staged 7, 8 or 9: each one's release is the last wave opened at or before its
    # first board solve (W2 opened later must not be used for 8), and none before the first wave.
    recs = [{"ts": T0 + 2.0, "event": "wave_open", "wave": "W1", "count": 2, "announced": T0},
            {"ts": T0 + 1002.0, "event": "wave_open", "wave": "W2", "count": 2, "announced": T0 + 1000.0}]
    st = _state(**{"7": ("Web", [("rivals", T0 - 50.0)]),
                   "8": ("Web", [("rivals", T0 + 500.0)]),
                   "9": ("Web", [("rivals", T0 + 1100.0)])})
    rows = {r.challenge_id: r for r in sb.bench(st, recs, team="us").rows}
    assert (rows["8"].release_at, rows["8"].rival_elapsed_s) == (T0, 500.0)
    assert (rows["9"].release_at, rows["9"].rival_elapsed_s) == (T0 + 1000.0, 100.0)
    assert (rows["7"].release_at, rows["7"].rival_elapsed_s, rows["7"].verdict) == (None, None, "NOTARGET")
    # with no wave open at its first solve the caller's t0 is used
    assert {r.challenge_id: r.release_at for r in sb.bench(st, recs, team="us", t0=T0 - 60.0).rows}["7"] == T0 - 60.0


def test_bench_needs_a_team_and_warns_on_an_unknown_name():
    st = _state(**{"1": ("Web", [("rivals", T0 + 40.0)])})
    with pytest.raises(sb.ScoreboardError, match="platform.team"):
        sb.bench(st, [], team=None)
    b = sb.bench(st, [], team="nobody")
    assert any("no solve on the board is by 'nobody'" in n for n in b.notes)


def test_bench_lane_filter():
    st = _state(**{"1": ("Web", [("rivals", T0 + 1.0)]), "2": ("Crypto", [("rivals", T0 + 2.0)])})
    assert [r.challenge_id for r in sb.bench(st, [], team="us", lane="crypto").rows] == ["2"]


def test_floor_records_feed_latency_floor_table():
    st = _state(**{"1": ("Web", [("rivals", T0 + 40.0)]), "2": ("Web", [("third", T0 + 31.5)]),
                   "3": ("Web", [("rivals", T0 - 5.0)])})     # solved before the release: no record
    b = sb.bench(st, _ledger(), team="us")
    recs = sb.floor_records(b, kind="ctfd")
    assert recs == {"ctfd": 31.5}
    table = latency.floor_table([], [], kind="ctfd", records=recs)
    assert table[0]["mode"] == "ctfd" and table[0]["record_s"] == 31.5
    gm = sb.floor_records(b, kind="gamemaster")
    assert set(gm) == {"1/base", "2/base"}


def test_floor_records_skip_a_rival_solve_before_an_explicit_t0():
    # t0 is after rival 1's solve: its elapsed time is negative, which is no first-blood record
    st = _state(**{"1": ("Web", [("rivals", T0 + 40.0)]), "2": ("Web", [("third", T0 + 130.0)])})
    b = sb.bench(st, [], team="us", t0=T0 + 100.0)
    assert {r.challenge_id: r.rival_elapsed_s for r in b.rows} == {"1": -60.0, "2": 30.0}
    assert sb.floor_records(b, kind="ctfd") == {"ctfd": 30.0}


# ------------------------------------------------------------------------------- hand entry

def _gm_ledger():
    return [{"ts": T0 + 2.0, "event": "wave_open", "wave": "W1", "count": 2, "announced": T0},
            {"ts": T0 + 3.0, "event": "detect", "challenge_id": "web-day-01", "wave": "W1"},
            {"ts": T0 + 25.0, "event": "platform.submit", "challenge_id": "web-day-01", "status": "correct"}]


def test_record_solve_gives_a_gamemaster_event_its_benchmark(tmp_path):
    wd = tmp_path / "work"
    e = sb.record_solve(wd, "web-day-01", "third", T0 + 60.0, category="Web", name="day one", team="us",
                        now=lambda: T0 + 900.0)
    assert e["solves"] == [{"account": "third", "at": T0 + 60.0, "account_id": None, "hand": True}]
    sb.record_solve(wd, "web-day-01", "rivals", T0 + 40.0, team="us", now=lambda: T0 + 901.0)
    st = sb.load(wd)
    e = st["challenges"]["web-day-01"]
    assert (e["name"], e["category"], e["fetched"]) == ("day one", "Web", None)
    assert [s["account"] for s in e["solves"]] == ["rivals", "third"]          # earliest first
    assert [(x["account"], x["source"], x["ours"]) for x in sb.read_events(wd)] == [
        ("third", "hand", False), ("rivals", "hand", False)]
    b = sb.bench(st, _gm_ledger(), team="us")
    r = b.rows[0]
    assert (r.status, r.rival, r.ours_source, r.ours_elapsed_s, r.rival_elapsed_s, r.verdict) == (
        "won", "rivals", "ledger", 25.0, 40.0, "PASS")
    assert sb.floor_records(b, kind="gamemaster") == {latency.mode_of("gamemaster", "web-day-01"): 40.0}
    assert latency.mode_of("gamemaster", "web-day-01") == "web/base"
    # recording a team again replaces its row; a later solve does not change the first blood
    sb.record_solve(wd, "web-day-01", "rivals", T0 + 35.0)
    sb.record_solve(wd, "web-day-01", "fourth", T0 + 99.0)
    e = sb.load(wd)["challenges"]["web-day-01"]
    assert [(s["account"], s["at"]) for s in e["solves"]] == [("rivals", T0 + 35.0), ("third", T0 + 60.0),
                                                              ("fourth", T0 + 99.0)]
    assert [x["at"] for x in sb.read_events(wd)] == [T0 + 60.0, T0 + 40.0, T0 + 35.0]
    # our own solve entered by hand is a hand time in the bench
    sb.record_solve(wd, "web-day-02", "Us", T0 + 10.0)
    r2 = {r.challenge_id: r for r in sb.bench(sb.load(wd), _gm_ledger(), team="us").rows}["web-day-02"]
    assert (r2.status, r2.ours_source, r2.ours_at) == ("uncontested", "hand", T0 + 10.0)


def test_record_solve_delete_and_bad_input_fail_by_name(tmp_path):
    wd = tmp_path / "work"
    sb.record_solve(wd, "c1", "rivals", T0 + 40.0)
    sb.record_solve(wd, "c1", "third", T0 + 50.0)
    e = sb.record_solve(wd, "c1", "RIVALS ", delete=True)
    assert [s["account"] for s in e["solves"]] == ["third"]
    with pytest.raises(sb.ScoreboardError, match="no hand-entered solve of challenge c1 by 'rivals'"):
        sb.record_solve(wd, "c1", "rivals", delete=True)
    with pytest.raises(sb.ScoreboardError, match="challenge nope is not in the store"):
        sb.record_solve(wd, "nope", "rivals", delete=True)
    for bad in (None, float("nan"), float("inf"), True, "123"):
        with pytest.raises(sb.ScoreboardError, match="epoch seconds"):
            sb.record_solve(wd, "c1", "x", bad)
    with pytest.raises(sb.ScoreboardError, match="team name"):
        sb.record_solve(wd, "c1", " ", T0)
    with pytest.raises(sb.ScoreboardError, match="challenge id"):
        sb.record_solve(wd, "", "x", T0)
    assert [s["account"] for s in sb.load(wd)["challenges"]["c1"]["solves"]] == ["third"]


def test_ingest_keeps_hand_rows_the_board_does_not_list(env):
    b = board()
    with FakeCTFd(b, token=TOKEN) as fake:
        g = gate_for(fake)
        sb.ingest(g)
        with pytest.raises(sb.ScoreboardError, match="board already records a solve of challenge 1 by 'Rivals'"):
            sb.record_solve(env, "1", "Rivals", T0 + 1.0)
        sb.record_solve(env, "1", "offline", T0 + 5.0)       # seen on a stream, not on this board
        b[0].board_solves.append(("late", T0 + 999.0))       # 1 changes: the next cycle re-reads it
        r = sb.ingest(g)
        assert r.fetched == ["1"] and r.first_bloods == []    # the hand row stays the first blood
        sol = sb.load(env)["challenges"]["1"]["solves"]
        assert [(s["account"], s.get("hand", False)) for s in sol] == [
            ("offline", True), ("us", False), ("rivals", False), ("third", False), ("late", False)]
        # once the board lists that team itself, its own row replaces the hand one
        b[0].board_solves.append(("offline", T0 + 7.0))
        r = sb.ingest(g)
    sol = sb.load(env)["challenges"]["1"]["solves"]
    assert [(s["account"], s["at"], s.get("hand", False)) for s in sol][:2] == [
        ("offline", T0 + 7.0, False), ("us", T0 + 25.0, False)]
    assert sum(1 for s in sol if s["account"] == "offline") == 1
    assert r.first_bloods == [{"challenge_id": "1", "account": "offline", "at": T0 + 7.0, "ours": False}]


def test_ingest_keeps_hand_rows_on_a_challenge_the_board_lists_no_solve_of(env):
    b = board()
    with FakeCTFd(b, token=TOKEN) as fake:
        g = gate_for(fake)
        sb.ingest(g)
        assert sb.load(env)["challenges"]["3"]["solves"] == []
        sb.record_solve(env, "3", "offline", T0 + 5.0)           # the board says 0 solves of 3
        sb.record_solve(env, "2", "offline", T0 + 150.0)
        b[1].board_solves.clear()                                 # the board drops its only row of 2
        r = sb.ingest(g)
        assert r.ok and r.fetched == []                           # both lists say 0: no solves read
    st = sb.load(env)["challenges"]
    hand = {"account": "offline", "account_id": None, "hand": True}
    assert st["3"]["solves"] == [{**hand, "at": T0 + 5.0}] and st["3"]["count"] == 0
    assert st["2"]["solves"] == [{**hand, "at": T0 + 150.0}] and st["2"]["count"] == 0
    assert sb.first_blood(st["3"])["account"] == "offline"


def test_ingest_merge_puts_an_untimed_board_row_after_hand_rows(env):
    # the board sends one solve without a date; merged with a hand row it is stored last
    class Untimed(FakeCTFd):
        def _route(self, method, path, body, authed):
            got = super()._route(method, path, body, authed)
            if path == "/api/v1/challenges/1/solves":
                got[2]["data"].append({"name": "nodate", "date": None, "account_id": 9})
            return got
    with Untimed(board(), token=TOKEN) as fake:
        g = gate_for(fake)
        sb.record_solve(env, "1", "offline", T0 + 50.0)          # before the first read of 1
        r = sb.ingest(g)
    assert "1" in r.fetched
    sol = sb.load(env)["challenges"]["1"]["solves"]
    assert [(s["account"], s["at"]) for s in sol] == [
        ("us", T0 + 25.0), ("rivals", T0 + 40.0), ("offline", T0 + 50.0), ("third", T0 + 90.0),
        ("nodate", None)]


def test_render_bench_names_lanes_and_rivals():
    st = _state(**{"1": ("Web", [("rivals", T0 + 40.0)])})
    text = sb.render_bench(sb.bench(st, _ledger(), team="us"))
    assert "Web" in text and "rivals x1" in text and "unsolved" in text and "FAIL" in text


# ------------------------------------------------------------------------------- CLI

def _args(argv):
    p = argparse.ArgumentParser()
    cli.add_arguments(p)
    return p.parse_args(argv)


def test_cli_ingest_show_bench_and_strict_exit(env, monkeypatch, capsys):
    with FakeCTFd(board(), token=TOKEN) as fake:
        prof = profile(base_url=fake.base_url)
        monkeypatch.setattr(cli, "_profile", lambda args: prof)
        assert cli.run(_args(["ingest"])) == 0
        out = capsys.readouterr().out
        assert "board: 3 row(s)" in out and "first blood 1: us (ours)" in out
    assert cli.run(_args(["show"])) == 0
    assert "rivals" in capsys.readouterr().out
    # our accepted times in the ledger (written as the submit gate would, at chosen times)
    with open(ledger.path(env), "a", encoding="utf-8") as fh:
        for cid, ts in (("1", T0 + 26.0), ("2", T0 + 500.0)):
            fh.write(json.dumps({"ts": ts, "event": "platform.submit", "challenge_id": cid,
                                 "status": "correct"}) + "\n")
    assert cli.run(_args(["bench", "--strict", "--json"])) == 0       # no release: NOTARGET, no FAIL
    data = json.loads(capsys.readouterr().out)
    assert {r["challenge_id"]: (r["status"], r["verdict"]) for r in data["rows"]} == {
        "1": ("won", "NOTARGET"), "2": ("lost", "NOTARGET")}
    # with a release T0, challenge 2 (ours 500 s, rival 100 s) fails the yardstick: --strict exits 1
    assert cli.run(_args(["bench", "--strict", "--t0", str(T0)])) == 1
    out = capsys.readouterr().out
    assert "First-blood benchmark for us" in out and "FAIL" in out and "PASS" in out
    assert cli.run(_args(["bench", "--t0", str(T0)])) == 0             # without --strict: 0


def test_cli_ingest_on_gamemaster_exits_2_named(env, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_profile", lambda args: profile(kind="gamemaster", base_url="http://127.0.0.1:9/"))
    assert cli.run(_args(["ingest"])) == 2
    assert "NotSupported" in capsys.readouterr().err


def test_cli_record_on_gamemaster_then_bench(env, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_profile", lambda args: profile(kind="gamemaster", base_url="http://127.0.0.1:9/"))
    when = dt.datetime.fromtimestamp(T0 + 20.0, tz=UTC).isoformat()
    assert cli.run(_args(["record", "web-day-01", "rivals", when, "--category", "Web"])) == 0
    assert "first blood now rivals" in capsys.readouterr().out
    assert cli.run(_args(["record", "web-day-01", "rivals"])) == 2              # no WHEN
    assert "needs WHEN" in capsys.readouterr().err
    assert cli.run(_args(["record", "web-day-01", "rivals", "2030-03-01T00:00:20"])) == 2   # naive time
    assert "UTC offset" in capsys.readouterr().err
    with open(ledger.path(env), "a", encoding="utf-8") as fh:
        for rec in _gm_ledger():
            fh.write(json.dumps(rec) + "\n")
    # ours 25 s from T0 vs the rival's 20 s: lost, FAIL; --strict exits 1
    assert cli.run(_args(["bench", "--strict", "--json"])) == 1
    row = json.loads(capsys.readouterr().out)["rows"][0]
    assert (row["challenge_id"], row["lane"], row["status"], row["verdict"]) == ("web-day-01", "Web", "lost", "FAIL")
    assert cli.run(_args(["record", "web-day-01", "rivals", "--delete"])) == 0
    assert "first blood now -" in capsys.readouterr().out
    assert cli.run(_args(["record", "web-day-01", "rivals", "--delete"])) == 2
    assert "no hand-entered solve" in capsys.readouterr().err


def test_cli_bench_without_team_exits_2(env, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_profile", lambda args: profile(team=None))
    assert cli.run(_args(["bench"])) == 2
    assert "platform.team" in capsys.readouterr().err


def test_cli_floors_prints_the_first_blood_record(env, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_profile", lambda args: profile())
    st = _state(**{"1": ("Web", [("rivals", T0 + 40.0)])})
    (env / sb.DIR_NAME).mkdir(parents=True)
    (env / sb.DIR_NAME / sb.STATE_NAME).write_text(json.dumps(st))
    assert cli.run(_args(["floors", "--t0", str(T0), "--json"])) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["records"] == {"ctfd": 40.0} and data["table"][0]["record_s"] == 40.0
