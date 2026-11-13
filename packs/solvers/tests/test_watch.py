"""B-017: the single no-model board watcher (ctf/watch.py, ctf/cli/watch.py).

Offline: a scripted board (a fake platform the test drives), the real CTFd adapter over a recorded
fake session, and the real manual adapter over a drop folder. A fake clock whose sleep advances time
stands in for waiting; nothing touches the network.
"""
from __future__ import annotations

import datetime as dt
import json
import os

import pytest

from ctf import event, ledger, watch
from ctf.platform import ctfd
from ctf.platform.base import Challenge, FileRef, PlatformError
from platform_fixture_session import FakeSession

T0 = 1_800_000_000.0          # a wave anchor


class Clock:
    def __init__(self, t=T0 - 100):
        self.t = t
        self.slept = []

    def __call__(self):
        return self.t

    def sleep(self, s):
        assert s >= 0
        self.slept.append(s)
        self.t += s


class HTTPErr(PlatformError):
    def __init__(self, msg, status):
        super().__init__(msg)
        self.status = status


class Board:
    """A fake platform: `rows` is what the board lists, `details` what get_challenge answers.
    `error` (an exception) makes list_challenges fail; `appear` maps an id to the clock time from
    which it is listed."""
    kind = "fake"

    def __init__(self, clock=None):
        self.clock = clock
        self.rows: dict[str, Challenge] = {}
        self.appear: dict[str, float] = {}
        self.error: Exception | None = None
        self.list_calls: list[float] = []
        self.detail_calls: list[str] = []

    def put(self, cid, name="Chal " + "x", category="Misc", points=100, description="", files=(),
            connection_info="", tags=(), solved=False, at=None):
        self.rows[cid] = Challenge(id=cid, name=name, category=category, points=points,
                                   description=description, files=tuple(files),
                                   connection_info=connection_info, tags=tuple(tags), solved_by_team=solved)
        if at is not None:
            self.appear[cid] = at

    def list_challenges(self):
        now = self.clock() if self.clock else 0
        self.list_calls.append(now)
        if self.error is not None:
            raise self.error
        out = []
        for cid, c in self.rows.items():
            if cid in self.appear and now < self.appear[cid]:
                continue
            # a listing carries no description, files or connection info (CTFd)
            out.append(Challenge(id=c.id, name=c.name, category=c.category, points=c.points,
                                 tags=c.tags, solved_by_team=c.solved_by_team))
        return out

    def get_challenge(self, cid):
        self.detail_calls.append(cid)
        if cid not in self.rows:
            raise HTTPErr(f"get_challenge: GET /challenges/{cid} -> HTTP 404", 404)
        return self.rows[cid]

    def download_files(self, cid, dest):
        raise AssertionError("the watcher never downloads")

    def submit(self, cid, flag):
        raise AssertionError("the watcher never submits")

    def team_solves(self):
        return []

    def scoreboard(self):
        return []


@pytest.fixture
def wd(tmp_path):
    return tmp_path / "work"


def kinds(evs):
    return [e["event"] for e in evs]


def by(evs, kind):
    return [e for e in evs if e["event"] == kind]


# ------------------------------------------------------------------------------------- schedule

def test_schedule_is_fast_from_lead_to_tail_and_slow_otherwise():
    s = watch.Schedule((T0,))
    assert s.interval(T0 - 20) == 1.0
    assert s.interval(T0 - 20.01) == 5.0
    assert s.interval(T0) == 1.0
    assert s.interval(T0 + 60) == 1.0
    assert s.interval(T0 + 60.01) == 5.0
    assert watch.Schedule().interval(T0) == 5.0      # no anchors: always slow


def test_slow_poll_never_steps_over_the_start_of_a_fast_window():
    s = watch.Schedule((T0,))
    assert s.next_poll(T0 - 23) == T0 - 20           # not T0 - 18
    assert s.next_poll(T0 - 30) == T0 - 25           # window not reached: plain slow step
    assert s.next_poll(T0 - 20) == T0 - 19           # a poll on the window start moves on
    two = watch.Schedule((T0, T0 + 3600))
    assert two.next_poll(T0 + 3600 - 22) == T0 + 3600 - 20
    assert two.interval(T0 + 1800) == 5.0
    assert s.next_poll(T0 + 10) == T0 + 11
    assert s.next_poll(T0 + 59.5) == T0 + 60.5       # last fast poll may overrun the tail by < fast


def test_schedule_rejects_bad_intervals():
    with pytest.raises(watch.WatchError, match="fast interval"):
        watch.Schedule(fast=0)
    with pytest.raises(watch.WatchError, match="slow interval"):
        watch.Schedule(fast=5, slow=1)
    with pytest.raises(watch.WatchError, match="lead and tail"):
        watch.Schedule(lead=-1)


def test_anchors_from_profile_start_waves_and_daily_releases():
    csctf = event.load("csctf")              # dates.start is a datetime with Z
    anchors, notes = watch.anchors_for(csctf, waves=["2026-11-07T13:00:00Z", "2026-11-07T18:00:00+00:00"])
    got = [a for a, _ in anchors]
    assert got == [dt.datetime(2026, 11, 6, 13, tzinfo=dt.timezone.utc).timestamp(),
                   dt.datetime(2026, 11, 7, 13, tzinfo=dt.timezone.utc).timestamp(),
                   dt.datetime(2026, 11, 7, 18, tzinfo=dt.timezone.utc).timestamp()]
    assert notes == []

    huntress = event.load("huntress")        # month-long, date-only: daily releases
    anchors, notes = watch.anchors_for(huntress, daily=["16:00"])
    assert len(anchors) == 31
    assert anchors[0][0] == dt.datetime(2026, 10, 1, 16, tzinfo=dt.timezone.utc).timestamp()
    assert anchors[-1][0] == dt.datetime(2026, 10, 31, 16, tzinfo=dt.timezone.utc).timestamp()
    assert any("is a date, not a time" in n for n in notes)


def test_wave_times_without_a_zone_are_refused():
    with pytest.raises(watch.WatchError, match="no time zone"):
        watch.parse_wave("2026-11-07T13:00:00")
    with pytest.raises(watch.WatchError, match="not ISO-8601"):
        watch.parse_wave("tomorrow")
    with pytest.raises(watch.WatchError, match="HH:MM"):
        watch.anchors_for(event.load("huntress"), daily=["4pm"])
    assert watch.parse_wave("1800000000") == 1_800_000_000.0


# ------------------------------------------------------------------------------------- detection

def test_closed_board_then_open_emits_one_error_then_open_and_new(wd):
    clk = Clock()
    b = Board(clk)
    b.error = HTTPErr("list_challenges: GET /challenges -> HTTP 403", 403)
    with watch.Watcher(b, workdir=wd, clock=clk, sleep=clk.sleep) as w:
        evs = w.tick() + w.tick() + w.tick()
        assert kinds(evs) == ["poll_error"]                    # repeated errors are not re-emitted
        assert evs[0]["status"] == 403
        b.error = None
        b.put("1", name="Alpha", category="Web", points=500)
        b.put("2", name="Beta", category="Pwn", points=300)
        evs = w.tick()
    assert kinds(evs)[:2] == ["poll_ok", "board_open"]
    assert evs[0]["after_errors"] == 3
    new = by(evs, "challenge_new")
    assert [(e["challenge_id"], e["name"], e["category"], e["points"]) for e in new] == \
        [("1", "Alpha", "Web", 500), ("2", "Beta", "Pwn", 300)]
    assert by(evs, "wave")[0]["new"] == ["1", "2"]
    detects = [r for r in ledger.read(wd) if r["event"] == "detect"]
    assert [(r["challenge_id"], r["source"]) for r in detects] == [("1", "watch"), ("2", "watch")]
    # the stream on disk is the same thing, seq strictly increasing
    disk = watch.read_events(wd)
    assert [e["seq"] for e in disk] == list(range(1, len(disk) + 1))
    assert kinds(disk) == ["poll_error"] + kinds(evs)


def test_error_is_re_emitted_when_it_changes_or_after_a_minute(wd):
    clk = Clock()
    b = Board(clk)
    b.error = HTTPErr("x -> HTTP 403", 403)
    with watch.Watcher(b, workdir=wd, clock=clk, sleep=clk.sleep) as w:
        assert kinds(w.tick()) == ["poll_error"]
        clk.t += 30
        assert w.tick() == []
        clk.t += 31
        assert kinds(w.tick()) == ["poll_error"]
        b.error = HTTPErr("x -> HTTP 502", 502)
        evs = w.tick()
    assert kinds(evs) == ["poll_error"] and evs[0]["status"] == 502 and evs[0]["consecutive"] == 4


def test_growth_reports_only_the_new_challenges(wd):
    clk = Clock()
    b = Board(clk)
    for i in range(3):
        b.put(str(i))
    with watch.Watcher(b, workdir=wd, clock=clk, sleep=clk.sleep) as w:
        w.tick()
        assert "challenge_new" not in kinds(w.tick())
        b.put("9", name="Late")
        evs = w.tick()
    assert [e["challenge_id"] for e in by(evs, "challenge_new")] == ["9"]
    wave = by(evs, "wave")[0]
    assert wave["new"] == ["9"] and wave["count"] == 4 and wave["previous"] == 3


def test_detection_lag_is_at_most_one_second_inside_the_window(wd):
    clk = Clock(T0 - 100)
    b = Board(clk)
    b.put("1", at=T0 + 0.3)                    # appears 0.3 s after the anchor
    sched = watch.Schedule((T0,))
    with watch.Watcher(b, workdir=wd, schedule=sched, clock=clk, sleep=clk.sleep) as w:
        w.run(until=T0 + 5)
    new = by(watch.read_events(wd), "challenge_new")
    assert len(new) == 1
    assert 0 <= new[0]["ts"] - (T0 + 0.3) <= 1.0
    # slow before the window, one-second polls from T-20 on
    calls = b.list_calls
    before = [t for t in calls if t < T0 - 20]
    assert all(b2 - a == 5.0 for a, b2 in zip(before, before[1:]))
    assert T0 - 20 in calls
    inside = [t for t in calls if T0 - 20 <= t <= T0 + 5]
    assert all(abs((b2 - a) - 1.0) < 1e-9 for a, b2 in zip(inside, inside[1:]))


def test_detection_lag_is_at_most_five_seconds_outside_any_window(wd):
    clk = Clock(T0)
    b = Board(clk)
    b.put("1", at=T0 + 1000.2)
    with watch.Watcher(b, workdir=wd, schedule=watch.Schedule(), clock=clk, sleep=clk.sleep) as w:
        w.run(until=T0 + 1010)
    new = by(watch.read_events(wd), "challenge_new")
    assert len(new) == 1 and 0 <= new[0]["ts"] - (T0 + 1000.2) <= 5.0


def test_cadence_is_timed_from_poll_start_not_end(wd):
    clk = Clock(T0)

    class Slow(Board):
        def list_challenges(self):
            out = super().list_challenges()
            clk.t += 0.4                         # a 0.4 s response
            return out

    b = Slow(clk)
    with watch.Watcher(b, workdir=wd, schedule=watch.Schedule((T0,)), clock=clk, sleep=clk.sleep) as w:
        w.run(max_polls=4)
    gaps = [round(y - x, 6) for x, y in zip(b.list_calls, b.list_calls[1:])]
    assert gaps == [1.0, 1.0, 1.0]


def test_rate_limit_backs_off_doubling(wd):
    clk = Clock(T0)
    b = Board(clk)
    b.error = HTTPErr("x -> HTTP 429", 429)
    with watch.Watcher(b, workdir=wd, schedule=watch.Schedule((T0,)), clock=clk, sleep=clk.sleep) as w:
        w.run(max_polls=7)
        gaps = [y - x for x, y in zip(b.list_calls, b.list_calls[1:])]
        assert gaps == [5.0, 10.0, 20.0, 40.0, 60.0, 60.0]   # not 1 s inside the window; capped at 60
        b.error = None
        w.run(max_polls=2)
    gaps = [y - x for x, y in zip(b.list_calls[7:], b.list_calls[8:])]
    assert gaps == [5.0]                          # answered: back to the schedule (window over)
    stream = kinds(watch.read_events(wd))
    assert stream[0] == "watch_start" and stream.count("watch_stop") == 2


def test_rate_limited_detail_fetch_backs_off_the_next_poll(wd):
    clk = Clock(T0)
    b = Board(clk)
    for i in range(3):
        b.put(str(i))

    def limited(cid):
        b.detail_calls.append(cid)
        raise HTTPErr("get_challenge -> HTTP 429", 429)

    b.get_challenge = limited
    with watch.Watcher(b, workdir=wd, schedule=watch.Schedule((T0,)), clock=clk, sleep=clk.sleep) as w:
        w.run(max_polls=2)
    assert b.detail_calls == ["0", "1"]           # one per poll: stopped at each 429, then moved on
    assert b.list_calls[1] - b.list_calls[0] == 5.0


def test_persistent_detail_rate_limit_doubles_the_backoff_then_recovers(wd):
    clk = Clock(T0)
    b = Board(clk)
    b.put("0")
    real = b.get_challenge
    state = {"limited": True}

    def detail(cid):
        if state["limited"]:
            b.detail_calls.append(cid)
            raise HTTPErr("get_challenge -> HTTP 429", 429)
        return real(cid)

    b.get_challenge = detail
    with watch.Watcher(b, workdir=wd, schedule=watch.Schedule((T0,)), clock=clk, sleep=clk.sleep) as w:
        w.run(max_polls=7)               # the listing answers every time; the detail never does
        gaps = [y - x for x, y in zip(b.list_calls, b.list_calls[1:])]
        assert gaps == [5.0, 10.0, 20.0, 40.0, 60.0, 60.0]
        state["limited"] = False
        w.run(max_polls=3)
    # poll 8 (a fresh run) gets no 429, so the next polls are back on the 5 s schedule
    gaps = [y - x for x, y in zip(b.list_calls[7:], b.list_calls[8:])]
    assert gaps == [5.0, 5.0]
    assert watch.versions(wd, "0") == [1]


def test_points_and_team_solve_and_gone_and_returning(wd):
    clk = Clock()
    b = Board(clk)
    b.put("1", points=500)
    b.put("2")
    with watch.Watcher(b, workdir=wd, clock=clk, sleep=clk.sleep) as w:
        w.tick()
        b.put("1", points=480, solved=True)
        evs = w.tick()
        assert kinds(evs) == ["points_changed", "team_solved"]
        assert (evs[0]["old"], evs[0]["new"]) == (500, 480)
        assert "brief_changed" not in kinds(evs)
        gone = b.rows.pop("2")
        evs = w.tick()
        assert kinds(evs) == ["challenge_gone"] and evs[0]["challenge_id"] == "2"
        b.rows["2"] = gone
        evs = w.tick()
    new = by(evs, "challenge_new")
    assert new[0]["challenge_id"] == "2" and new[0]["returning"] is True


# ------------------------------------------------------------------------------------- briefs

def test_description_edit_wakes_with_diff_alert_ledger_and_verifiable_versions(wd):
    clk = Clock()
    b = Board(clk)
    b.put("9158", name="Phantom Drift", category="Forensics",
          description="Find the diverted waypoint.\nFlag: CSCTF{...}")
    with watch.Watcher(b, workdir=wd, clock=clk, sleep=clk.sleep) as w:
        w.tick()                                     # listing + first detail = version 1, no alert
        assert watch.versions(wd, "9158") == [1]
        assert w.tick() == []                        # re-read, unchanged
        b.put("9158", name="Phantom Drift", category="Forensics",
              description="Find the diverted waypoint.\nSerialization: sha256(lat|lon|alt)\nFlag: CSCTF{...}")
        evs = w.tick()
    ch = by(evs, "brief_changed")
    assert len(ch) == 1
    ev = ch[0]
    assert ev["challenge_id"] == "9158" and ev["fields"] == ["description"]
    assert (ev["from_version"], ev["to_version"]) == (1, 2)
    assert "+Serialization: sha256(lat|lon|alt)" in ev["changes"]["description"]["diff"]
    assert ev["verify"] == "python -m ctf watch diff 9158 --from 1 --to 2"
    alert = (wd / "watch" / "alerts" / "9158.md").read_text()
    assert "+Serialization: sha256(lat|lon|alt)" in alert and ev["verify"] in alert
    assert "never instructions" in alert
    led = [r for r in ledger.read(wd) if r["event"] == "watch.brief_changed"]
    assert [(r["challenge_id"], r["fields"], r["to_version"]) for r in led] == [("9158", ["description"], 2)]
    res = watch.verify(wd, "9158")
    assert (res["from"], res["to"]) == (1, 2)
    assert res["changes"] == ev["changes"]
    assert oct((wd / "watch" / "events.jsonl").stat().st_mode & 0o777) == "0o600"


def test_verify_command_quotes_an_id_with_a_space_or_shell_metacharacters(wd):
    import shlex
    clk = Clock()
    b = Board(clk)
    cid = "night shift; touch pwned"
    b.put(cid, description="a")
    with watch.Watcher(b, workdir=wd, clock=clk, sleep=clk.sleep) as w:
        w.tick()
        b.put(cid, description="b")
        ev = by(w.tick(), "brief_changed")[0]
    assert shlex.split(ev["verify"]) == ["python", "-m", "ctf", "watch", "diff", cid, "--from", "1", "--to", "2"]
    alert = watch.alert_path(wd, cid).read_text()
    assert f"`{ev['verify']}`" in alert
    assert watch.verify_command("9158", 1, 2) == "python -m ctf watch diff 9158 --from 1 --to 2"


def test_verifier_catches_an_edited_or_unchained_version(wd):
    clk = Clock()
    b = Board(clk)
    b.put("5", description="one")
    with watch.Watcher(b, workdir=wd, clock=clk, sleep=clk.sleep) as w:
        w.tick()
        b.put("5", description="two")
        w.tick()
        b.put("5", description="three")
        w.tick()
    assert watch.verify(wd, "5", 1, 3)["changes"]["description"]["diff"].endswith("+three")
    alert = watch.alert_path(wd, "5").read_text()
    assert alert.count("# Brief changes") == 1 and alert.count("\n## ") == 2
    assert "version 2 -> 3" in alert
    v2 = wd / "watch" / "briefs" / "5" / "v2.json"
    rec = json.loads(v2.read_text())
    rec["fields"]["description"] = "forged"
    v2.write_text(json.dumps(rec))
    with pytest.raises(watch.WatchError, match="fails its hash"):
        watch.verify(wd, "5", 1, 3)
    # re-hashed forgery: the hash matches but v3 no longer chains to it
    rec["sha256"] = watch.fields_sha256(rec["fields"])
    v2.write_text(json.dumps(rec))
    with pytest.raises(watch.WatchError, match="does not follow version 2"):
        watch.verify(wd, "5", 1, 3)
    with pytest.raises(watch.WatchError, match="no stored brief"):
        watch.verify(wd, "nope")


def test_file_reupload_is_a_change_but_a_new_download_token_is_not(wd):
    clk = Clock()
    b = Board(clk)
    b.put("3", files=[FileRef("drop.zip", "https://b.example/files/aaa/drop.zip?token=t1")])
    with watch.Watcher(b, workdir=wd, clock=clk, sleep=clk.sleep) as w:
        w.tick()
        b.put("3", files=[FileRef("drop.zip", "https://b.example/files/aaa/drop.zip?token=t2")])
        assert w.tick() == []
        b.put("3", files=[FileRef("drop.zip", "https://b.example/files/bbb/drop.zip?token=t3")])
        evs = w.tick()
    ev = by(evs, "brief_changed")[0]
    assert ev["fields"] == ["files"]
    assert ev["changes"]["files"] == {"old": ["drop.zip /files/aaa/drop.zip"],
                                      "new": ["drop.zip /files/bbb/drop.zip"]}
    stored = "".join(p.read_text() for p in (wd / "watch").rglob("*") if p.is_file())
    assert "token=" not in stored and "t3" not in stored.split("drop.zip")[-1]


def test_connection_info_and_tags_changes_are_brief_changes(wd):
    clk = Clock()
    b = Board(clk)
    b.put("4", connection_info="nc a.example 1337", tags=["easy"])
    with watch.Watcher(b, workdir=wd, clock=clk, sleep=clk.sleep) as w:
        w.tick()
        b.put("4", connection_info="nc a.example 31337", tags=["easy", "fixed"])
        evs = w.tick()
    ev = by(evs, "brief_changed")[0]
    assert ev["fields"] == ["connection_info", "tags"]
    assert ev["changes"]["tags"]["new"] == ["easy", "fixed"]


def test_details_rotate_round_robin_and_a_renamed_challenge_jumps_the_queue(wd):
    clk = Clock()
    b = Board(clk)
    for i in range(6):
        b.put(str(i), name=f"c{i}")
    with watch.Watcher(b, workdir=wd, details_per_poll=2, clock=clk, sleep=clk.sleep) as w:
        for _ in range(3):
            w.tick()
        assert b.detail_calls == ["0", "1", "2", "3", "4", "5"]      # new ones first, each once
        w.tick()
        assert b.detail_calls[6:] == ["0", "1"]                       # then round robin
        b.put("4", name="c4 (fixed)")
        evs = w.tick()
    assert b.detail_calls[8] == "4"                                   # rename seen in the listing
    ev = by(evs, "brief_changed")[0]
    assert ev["challenge_id"] == "4" and ev["fields"] == ["name"]
    assert len(by(evs, "brief_changed")) == 1                         # reported once, not per source


def test_listing_only_mode_reports_renames_from_the_listing(wd):
    clk = Clock()
    b = Board(clk)
    b.put("1", name="Old", category="Web")
    with watch.Watcher(b, workdir=wd, details_per_poll=0, clock=clk, sleep=clk.sleep) as w:
        w.tick()
        b.put("1", name="New", category="Web")
        evs = w.tick()
    assert b.detail_calls == []
    ev = by(evs, "brief_changed")[0]
    assert ev["changes"]["name"] == {"old": "Old", "new": "New"}


def test_detail_errors_are_reported_once_and_do_not_stop_the_listing(wd):
    clk = Clock()
    b = Board(clk)
    b.put("1")

    def broken(cid):
        b.detail_calls.append(cid)
        raise HTTPErr("get_challenge: GET /challenges/1 -> HTTP 500", 500)

    b.get_challenge = broken
    with watch.Watcher(b, workdir=wd, clock=clk, sleep=clk.sleep) as w:
        e1 = w.tick()
        e2 = w.tick()
        b.put("2")
        e3 = w.tick()
    assert kinds(e1) == ["board_open", "challenge_new", "wave", "detail_error"]
    assert e1[-1]["status"] == 500
    assert e2 == []
    assert "challenge_new" in kinds(e3)


# ------------------------------------------------------------------------------------- one poller

def test_a_second_watcher_on_the_same_workdir_is_refused(wd):
    b = Board()
    with watch.Watcher(b, workdir=wd):
        with pytest.raises(watch.WatchError, match=rf"already polls this workdir \(pid {os.getpid()}"):
            watch.Watcher(b, workdir=wd).acquire()
    with watch.Watcher(b, workdir=wd):          # released: the next one may start
        pass


def test_tick_without_the_lock_is_refused(wd):
    with pytest.raises(watch.WatchError, match="acquire"):
        watch.Watcher(Board(), workdir=wd).tick()


def test_restart_resumes_without_re_announcing(wd):
    clk = Clock()
    b = Board(clk)
    b.put("1", description="a")
    with watch.Watcher(b, workdir=wd, clock=clk, sleep=clk.sleep) as w:
        w.tick()
    last = watch.read_events(wd)[-1]["seq"]
    b.put("2")
    b.put("1", description="b")
    with watch.Watcher(b, workdir=wd, clock=clk, sleep=clk.sleep) as w:
        evs = w.tick() + w.tick()
    assert [e["challenge_id"] for e in by(evs, "challenge_new")] == ["2"]
    assert "board_open" not in kinds(evs)
    assert by(evs, "brief_changed")[0]["to_version"] == 2
    assert evs[0]["seq"] == last + 1


def test_unsafe_ids_get_hashed_folder_names(wd):
    clk = Clock()
    b = Board(clk)
    b.put("../../escape", description="x")
    with watch.Watcher(b, workdir=wd, clock=clk, sleep=clk.sleep) as w:
        w.tick()
    assert not (wd.parent / "escape").exists()
    folder = watch.brief_dir(wd, "../../escape")
    assert folder.parent == wd / "watch" / "briefs" and folder.name.startswith("id-")
    assert watch.versions(wd, "../../escape") == [1]
    assert watch.safe_id("..") != ".." and watch.safe_id("9158") == "9158"
    for bad in (".", "..", "...", ".hidden", "a/b", "a b", ""):
        assert watch.safe_id(bad).startswith("id-"), bad


def test_poller_pid_names_the_running_watcher_and_a_probe_does_not_block_acquire(wd):
    import threading
    assert watch.poller_pid(wd) is None                         # no lock file yet
    with watch.Watcher(Board(), workdir=wd):
        assert watch.poller_pid(wd) == str(os.getpid())
    assert watch.poller_pid(wd) is None                         # released: no watcher runs
    # a probe's shared lock, held a moment, must not make a starting watcher fail
    import fcntl
    fd = os.open(wd / "watch" / watch.LOCK_NAME, os.O_RDONLY)
    fcntl.flock(fd, fcntl.LOCK_SH)
    t = threading.Timer(0.03, lambda: os.close(fd))
    t.start()
    try:
        with watch.Watcher(Board(), workdir=wd):
            assert watch.poller_pid(wd) == str(os.getpid())
    finally:
        t.join()


def test_board_ids_replays_the_stream(wd):
    clk = Clock()
    b = Board(clk)
    assert watch.board_ids(wd) is None                          # no stream
    b.error = HTTPErr("x -> HTTP 403", 403)
    with watch.Watcher(b, workdir=wd, clock=clk, sleep=clk.sleep) as w:
        w.tick()
        assert watch.board_ids(wd) is None                      # errors only: not open
        b.error = None
        w.tick()
        assert watch.board_ids(wd) == []                        # open, empty board
        b.put("1"), b.put("2"), b.put("3")
        w.tick()
        b.rows.pop("2")
        w.tick()
    assert watch.board_ids(wd) == ["1", "3"]


class Closed(Exception):
    pass


def test_board_reader_uses_the_stream_while_a_watcher_runs_and_the_platform_otherwise(wd):
    clk = Clock()
    b = Board(clk)
    direct_calls = []
    logs = []

    def direct():
        direct_calls.append(1)
        return ["d1", "d2"]

    read = watch.board_reader(wd, direct, Closed, logs.append)
    assert read() == ["d1", "d2"] and len(direct_calls) == 1
    b.error = HTTPErr("x -> HTTP 403", 403)
    with watch.Watcher(b, workdir=wd, clock=clk, sleep=clk.sleep) as w:
        w.tick()
        with pytest.raises(Closed, match="403"):
            read()
        b.error = None
        b.put("7")
        w.tick()
        assert read() == ["7"]
        assert len(direct_calls) == 1                           # no platform call while it runs
    assert read() == ["d1", "d2"] and len(direct_calls) == 2
    assert len(logs) == 3 and "directly" in logs[0] and f"pid {os.getpid()}" in logs[1] \
        and "directly" in logs[2]


def test_ctf_wait_rides_the_watch_stream_without_a_platform_call(tmp_path, monkeypatch, capsys):
    import argparse
    from ctf import cli
    work = tmp_path / "work"
    monkeypatch.setenv("CTF_WORKDIR", str(work))

    class NoPlatform:
        class cfg:
            @staticmethod
            def require_auth():
                return None

        def challenges(self):
            raise AssertionError("ctf wait polled the platform while ctf watch runs")

    monkeypatch.setattr(cli, "_ctfd", NoPlatform)
    clk = Clock()
    b = Board(clk)
    for i in range(3):
        b.put(str(i))
    args = argparse.Namespace(grow_from=None, not_before=None, interval=1, timeout=5)
    with watch.Watcher(b, workdir=work, clock=clk, sleep=clk.sleep) as w:
        w.tick()
        assert cli.cmd_wait(args) == 0
    out = capsys.readouterr()
    assert "3 challenges visible" in out.out and "reading its stream" in out.err
    # no watcher: the same command polls the platform (here the stub, which refuses)
    with pytest.raises(AssertionError, match="polled the platform"):
        cli.cmd_wait(args)


def test_ctf_wait_without_an_event_workdir_says_so_and_polls_directly(monkeypatch, capsys):
    import argparse
    from ctf import cli

    class Platform:
        class cfg:
            @staticmethod
            def require_auth():
                return None

        def challenges(self):
            return [{"id": 1}, {"id": 2}]

    def no_event(*a, **k):
        raise event.EventError("no event profile found under events/ and CTF_EVENT is not set")

    monkeypatch.setattr(cli, "_ctfd", Platform)
    monkeypatch.setattr(cli._paths, "workdir", no_event)
    args = argparse.Namespace(grow_from=None, not_before=None, interval=1, timeout=5)
    assert cli.cmd_wait(args) == 0
    out = capsys.readouterr()
    assert "2 challenges visible" in out.out
    assert "no event workdir" in out.err and "polling the board directly" in out.err


def test_ctf_wait_later_wave_through_the_stream(wd):
    from ctf import cli
    from ctf.client import CTFdError
    clk = Clock()
    b = Board(clk)
    b.put("1")
    with watch.Watcher(b, workdir=wd, clock=clk, sleep=clk.sleep) as w:
        w.tick()

        def sleep(s):
            clk.sleep(s)
            if clk.t >= T0 - 100 + 30:
                b.put("2")
            w.tick()

        read = watch.board_reader(wd, lambda: pytest.fail("platform polled"), CTFdError)
        code, msg = cli.wait_for_open(read, interval=10, timeout=300, grow_from="now",
                                      clock=clk, sleep=sleep, log=lambda m: None)
    assert code == 0 and "2 challenges visible (1 new since baseline 1)" in msg


# ------------------------------------------------------------------------------------- consumers

def test_follow_yields_new_events_and_skips_a_partial_line(wd):
    p = watch.events_path(wd)
    p.parent.mkdir(parents=True)
    p.write_text('{"seq":1,"ts":1,"event":"a"}\n{"seq":2,"ts":2,"event":"b"}\n{"seq":3,"ts"')
    assert [e["seq"] for e in watch.read_events(wd, since=1)] == [2]
    rounds = []

    def sleep(_):
        rounds.append(1)
        if len(rounds) == 1:
            with open(p, "a") as fh:
                fh.write(':3,"event":"c"}\n')

    got = list(watch.follow(wd, since=0, sleep=sleep, stop=lambda: len(rounds) >= 2))
    assert [e["event"] for e in got] == ["a", "b", "c"]


def test_corrupt_stream_line_fails_loudly(wd):
    p = watch.events_path(wd)
    p.parent.mkdir(parents=True)
    p.write_text('{"seq":1}\nnot json\n')
    with pytest.raises(watch.WatchError, match="corrupt stream line"):
        watch.read_events(wd)


# ------------------------------------------------------------------------------------- real adapters

BASE = "https://board.watch-test.example"


def _route(path, body, status=200, once=False):
    r = {"method": "GET", "url": BASE + "/api/v1" + path, "status": status, "body": body}
    if once:
        r["once"] = True
    return r


def test_through_the_ctfd_adapter_403_then_open_then_reupload(wd):
    detail = {"success": True, "data": {"id": 7, "name": "Drift", "category": "Forensics", "value": 560,
                                        "description": "v1", "files": ["/files/aaa/log.bin?token=one"]}}
    s = FakeSession([
        _route("/challenges", {"success": True, "data": [
            {"id": 7, "name": "Drift", "category": "Forensics", "value": 560, "solved_by_me": False}]}),
        _route("/challenges/7", detail),
    ])
    s.add(_route("/challenges", {"message": "closed"}, status=403, once=True))
    a = ctfd.CTFdAdapter(BASE, token="tok-test-value", session=s)
    clk = Clock()
    with watch.Watcher(a, workdir=wd, clock=clk, sleep=clk.sleep) as w:
        e1 = w.tick()
        e2 = w.tick()
        s.add(_route("/challenges/7", {"success": True, "data": dict(
            detail["data"], files=["/files/aaa/log.bin?token=two"])}))
        e3 = w.tick()
        s.add(_route("/challenges/7", {"success": True, "data": dict(
            detail["data"], description="v1\nspec: sha256(a|b)", files=["/files/bbb/log.bin?token=three"])}))
        e4 = w.tick()
    assert kinds(e1) == ["poll_error"] and e1[0]["status"] == 403
    assert kinds(e2) == ["poll_ok", "board_open", "challenge_new", "wave"]
    assert e3 == []
    ev = by(e4, "brief_changed")[0]
    assert ev["fields"] == ["description", "files"]
    assert ev["changes"]["files"]["new"] == ["log.bin /files/bbb/log.bin"]
    assert not any(c["method"] != "GET" for c in s.calls)        # reads only


def _manual_profile(tmp_path):
    p = tmp_path / "ev" / "event.toml"
    p.parent.mkdir(parents=True)
    p.write_text('slug = "ev"\nname = "Watch test"\n'
                 'dates = { start = 2026-11-06T13:00:00Z, end = 2026-11-07T13:00:00Z }\n'
                 '[platform]\nkind = "manual"\n[flag]\nprefixes = ["EV"]\n'
                 '[rules]\nsubmit_mode = "manual"\nflag_sharing = "forbidden"\nai_on_platform = "allowed"\n')
    return p


def test_cli_run_tail_and_diff_end_to_end_on_a_manual_drop_folder(tmp_path, monkeypatch, capsys):
    from ctf import cli
    work = tmp_path / "work"
    monkeypatch.setenv("CTF_WORKDIR", str(work))
    prof = _manual_profile(tmp_path)
    drop = work / "drop" / "ghost"
    drop.mkdir(parents=True)
    (drop / "challenge.toml").write_text('name = "Ghost"\ncategory = "Misc"\ndescription = "boo"\n')

    assert cli.main(["watch", "--profile", str(prof), "run", "--once", "--json"]) == 0
    out = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert ("challenge_new", "ghost") in [(e["event"], e.get("challenge_id")) for e in out]

    (drop / "challenge.toml").write_text('name = "Ghost"\ncategory = "Misc"\ndescription = "boo\\nnew rule"\n')
    assert cli.main(["watch", "--profile", str(prof), "run", "--once"]) == 0
    text = capsys.readouterr().out
    assert "brief_changed" in text and "python -m ctf watch diff ghost --from 1 --to 2" in text

    assert cli.main(["watch", "--profile", str(prof), "diff", "ghost"]) == 0
    text = capsys.readouterr().out
    assert "versions 1 -> 2 verified" in text and "+new rule" in text

    assert cli.main(["watch", "--profile", str(prof), "tail", "--since", "2", "--json"]) == 0
    tail = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert tail and all(e["seq"] > 2 for e in tail)
    assert "brief_changed" in [e["event"] for e in tail]

    assert cli.main(["watch", "--profile", str(prof), "diff", "nope"]) == 2
    assert "no stored brief" in capsys.readouterr().err


def test_cli_verify_command_for_a_manual_id_with_a_space_pastes_and_verifies(tmp_path, monkeypatch, capsys):
    import shlex
    from ctf import cli
    work = tmp_path / "work"
    monkeypatch.setenv("CTF_WORKDIR", str(work))
    prof = _manual_profile(tmp_path)
    drop = work / "drop" / "night shift"
    drop.mkdir(parents=True)
    (drop / "challenge.toml").write_text('name = "Night"\ndescription = "one"\n')
    assert cli.main(["watch", "--profile", str(prof), "run", "--once"]) == 0
    capsys.readouterr()
    (drop / "challenge.toml").write_text('name = "Night"\ndescription = "two"\n')
    assert cli.main(["watch", "--profile", str(prof), "run", "--once", "--json"]) == 0
    evs = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    verify = by(evs, "brief_changed")[0]["verify"]
    argv = shlex.split(verify)
    assert argv[:5] == ["python", "-m", "ctf", "watch", "diff"] and argv[5] == "night shift"
    assert cli.main(["watch", "--profile", str(prof)] + argv[4:]) == 0      # the pasted command, as parsed
    assert "versions 1 -> 2 verified" in capsys.readouterr().out


def test_cli_once_exits_1_when_the_board_cannot_be_read(tmp_path, monkeypatch, capsys):
    from ctf import cli
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))   # no drop folder: manual list fails
    prof = _manual_profile(tmp_path)
    assert cli.main(["watch", "--profile", str(prof), "run", "--once"]) == 1
    assert "poll_error" in capsys.readouterr().out


def test_cli_refuses_a_naive_wave_time(tmp_path, monkeypatch, capsys):
    from ctf import cli
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    prof = _manual_profile(tmp_path)
    assert cli.main(["watch", "--profile", str(prof), "run", "--once", "--wave", "2026-11-07T13:00"]) == 2
    assert "no time zone" in capsys.readouterr().err
