"""B-015: the claim store's solved view and the solved watcher (ctf/solved.py, ctf/cli/solved.py).

Offline. A fake platform drives the real B-017 watcher into a real event stream that carries
`team_solved` and `challenge_gone`; the solved watcher reads that stream, stops agents through the B-033
budget hook and keeps the B-004 claim store in step. No model, no platform call, nothing submitted.
"""
from __future__ import annotations

import dataclasses
import json

import pytest

from ctf import budget, dispatch, event, ledger, solved, watch
from ctf.cli import solved as cli_solved
from ctf.platform.base import Challenge, PlatformError


class HTTPErr(PlatformError):
    def __init__(self, msg, status):
        super().__init__(msg)
        self.status = status


class Board:
    """A fake CTFd-like board: the listing carries solved_by_team (what drives team_solved)."""
    kind = "fake"

    def __init__(self):
        self.rows: dict[str, Challenge] = {}

    def put(self, cid, name="Chal", category="Misc", points=100):
        self.rows[cid] = Challenge(id=cid, name=name, category=category, points=points)

    def mark_solved(self, cid):
        self.rows[cid] = dataclasses.replace(self.rows[cid], solved_by_team=True)

    def remove(self, cid):
        self.rows.pop(cid, None)

    def list_challenges(self):
        return [dataclasses.replace(c) for c in self.rows.values()]

    def get_challenge(self, cid):
        if cid not in self.rows:
            raise HTTPErr(f"GET /challenges/{cid} -> 404", 404)
        return self.rows[cid]

    def download_files(self, cid, dest):
        raise AssertionError("the solved watcher never downloads")

    def submit(self, cid, flag):
        raise AssertionError("the solved watcher never submits")


@pytest.fixture
def prof():
    return event.load("csctf")


def tick(board, wd, *, n=1, details_per_poll=4):
    """Drive the real watcher over `board` into <wd>/watch/events.jsonl for n polls."""
    w = watch.Watcher(board, workdir=wd, details_per_poll=details_per_poll, ledger=False)
    with w:
        for _ in range(n):
            w.tick()
    return watch.read_events(wd)


def stream_with_solve(wd):
    """A stream where challenge '7' appears and is then solved by the team."""
    board = Board()
    board.put("7", name="Crypto Warmup", category="Crypto")
    tick(board, wd)                 # challenge_new 7
    board.mark_solved("7")
    return tick(board, wd)          # team_solved 7


# --------------------------------------------------------------------------------- the shared solved view

def test_solved_ids_is_empty_before_any_solve(tmp_path):
    assert solved.solved_ids(tmp_path) == set()
    assert solved.is_solved("7", workdir=tmp_path) is False


def test_solved_ids_carries_every_team_solve_stop(tmp_path):
    budget.on_team_solve("7", workdir=tmp_path)
    budget.on_team_solve("9", solver="teammate", workdir=tmp_path)
    assert solved.solved_ids(tmp_path) == {"7", "9"}
    assert solved.is_solved("9", workdir=tmp_path) is True


def test_a_non_team_solve_stop_is_not_a_solve(tmp_path):
    # a manual/no-progress stop is not a solve: the challenge is not off the board
    ledger.append("stop", workdir=tmp_path, challenge_id="7", reason="manual")
    assert solved.solved_ids(tmp_path) == set()


# ----------------------------------------------------------------------------------- recording a solve

def test_record_solve_stops_every_agent_on_the_challenge(tmp_path):
    # the stop signal the gated launchers (R-09) and agent loops read must be set at once
    assert budget.is_stopped("7", workdir=tmp_path) is None
    new = solved.record_solve("7", workdir=tmp_path)
    assert new is True
    assert budget.is_stopped("7", workdir=tmp_path) == "team_solve"


def test_record_solve_marks_an_existing_claim_solved(tmp_path, prof):
    tick_board = Board(); tick_board.put("7", category="Crypto")
    tick(tick_board, tmp_path)
    d = dispatch.Dispatcher(prof, workdir=tmp_path)
    d.dispatch_new([dispatch.Detected("7", "Chal", "Crypto")])
    assert dispatch.read_claims(tmp_path)[0]["7"]["status"] == "dispatched"

    solved.record_solve("7", solver="alice", workdir=tmp_path)
    claim = dispatch.read_claims(tmp_path)[0]["7"]
    assert claim["status"] == "solved"
    assert claim["solved_by"] == "alice"
    assert "solved_at" in claim


def test_record_solve_without_a_claim_still_records_a_teammate_solve(tmp_path):
    # a teammate solved a challenge we never claimed: it must still show solved so we never dispatch on it
    new = solved.record_solve("42", solver="teammate", workdir=tmp_path)
    assert new is True
    assert solved.solved_ids(tmp_path) == {"42"}


def test_record_solve_is_idempotent(tmp_path):
    assert solved.record_solve("7", workdir=tmp_path) is True
    assert solved.record_solve("7", workdir=tmp_path) is False
    stops = [r for r in ledger.read(tmp_path)
             if r.get("event") == "stop" and r.get("challenge_id") == "7"]
    assert len(stops) == 1


def test_record_solve_marks_the_claim_solved_even_when_the_stop_already_exists(tmp_path, prof):
    # an operator ran `ctf budget stop ID --solved` (or a crashed pass wrote the stop) before the watcher
    # saw team_solved: the stop is not new, but the live claim must still be closed as solved
    dispatch.Dispatcher(prof, workdir=tmp_path).dispatch_new([dispatch.Detected("7", "Chal", "Crypto")])
    assert budget.on_team_solve("7", workdir=tmp_path) is True
    assert solved.record_solve("7", workdir=tmp_path) is False
    assert dispatch.read_claims(tmp_path)[0]["7"]["status"] == "solved"


def test_record_solve_needs_a_challenge_id(tmp_path):
    with pytest.raises(solved.SolvedError):
        solved.record_solve("  ", workdir=tmp_path)


# --------------------------------------------------------------------------------------- the watcher

def test_watcher_once_stops_agents_on_a_team_solve_from_the_stream(tmp_path):
    stream_with_solve(tmp_path)
    seen = []
    w = solved.SolvedWatcher(workdir=tmp_path, on_solve=lambda cid, new: seen.append((cid, new)))
    out = w.once()
    assert out == ["7"]
    assert seen == [("7", True)]
    assert budget.is_stopped("7", workdir=tmp_path) == "team_solve"


def test_watcher_ignores_non_solve_events(tmp_path):
    board = Board(); board.put("7"); board.put("8")
    tick(board, tmp_path)               # two challenge_new, no solve
    w = solved.SolvedWatcher(workdir=tmp_path)
    assert w.once() == []
    assert solved.solved_ids(tmp_path) == set()


def test_watcher_marks_a_vanished_challenge_gone(tmp_path, prof):
    board = Board(); board.put("7", category="Crypto")
    tick(board, tmp_path)
    dispatch.Dispatcher(prof, workdir=tmp_path).dispatch_new([dispatch.Detected("7", "Chal", "Crypto")])
    board.remove("7")
    tick(board, tmp_path)               # challenge_gone 7

    gone = []
    w = solved.SolvedWatcher(workdir=tmp_path, on_gone=lambda cid, rev: gone.append((cid, rev)))
    w.once()
    assert gone == [("7", True)]
    assert dispatch.read_claims(tmp_path)[0]["7"]["status"] == "gone"
    # a vanished challenge is not a team solve: it stays resumable, not a final team-solve stop
    assert solved.solved_ids(tmp_path) == set()


def test_a_gone_claim_is_restored_when_the_challenge_comes_back(tmp_path, prof):
    board = Board(); board.put("7", category="Crypto")
    tick(board, tmp_path)
    dispatch.Dispatcher(prof, workdir=tmp_path).dispatch_new([dispatch.Detected("7", "Chal", "Crypto")])
    gone = board.rows.pop("7")
    tick(board, tmp_path)               # challenge_gone 7
    board.rows["7"] = gone
    tick(board, tmp_path)               # challenge_new 7, returning=true

    back = []
    w = solved.SolvedWatcher(workdir=tmp_path, on_return=lambda cid, ok: back.append((cid, ok)))
    w.once()                            # replays gone then the return, in stream order
    assert back == [("7", True)]
    claim = dispatch.read_claims(tmp_path)[0]["7"]
    assert claim["status"] == "dispatched"
    assert "returned_at" in claim
    # a full replay (`ctf solved run --since 0`) lands on the same state, not on gone
    solved.SolvedWatcher(workdir=tmp_path).once()
    assert dispatch.read_claims(tmp_path)[0]["7"]["status"] == "dispatched"


def test_a_returning_challenge_does_not_revive_a_claim_that_is_not_gone(tmp_path, prof):
    dispatch.Dispatcher(prof, workdir=tmp_path).dispatch_new([dispatch.Detected("7", "Chal", "Crypto")])
    solved.record_solve("7", workdir=tmp_path)
    back = []
    w = solved.SolvedWatcher(workdir=tmp_path, on_return=lambda cid, ok: back.append((cid, ok)))
    w.handle({"event": "challenge_new", "seq": 3, "challenge_id": "7", "returning": True})
    assert back == [("7", False)]
    assert dispatch.read_claims(tmp_path)[0]["7"]["status"] == "solved"
    # a first listing (returning false) is not a return
    w.handle({"event": "challenge_new", "seq": 4, "challenge_id": "8", "returning": False})
    assert back == [("7", False)]


def test_a_solved_claim_is_not_downgraded_to_gone(tmp_path, prof):
    dispatch.Dispatcher(prof, workdir=tmp_path).dispatch_new([dispatch.Detected("7", "Chal", "Crypto")])
    solved.record_solve("7", workdir=tmp_path)
    gone = []
    w = solved.SolvedWatcher(workdir=tmp_path, on_gone=lambda cid, rev: gone.append((cid, rev)))
    w.handle({"event": "challenge_gone", "seq": 3, "challenge_id": "7"})
    assert gone == [("7", False)]
    assert dispatch.read_claims(tmp_path)[0]["7"]["status"] == "solved"


def test_a_challenge_that_returns_already_solved_stops_its_agents(tmp_path, prof):
    # 7 is listed and dispatched, leaves the board, a teammate solves it while it is away, and it comes
    # back already solved: its old row was dropped when it went, so no flip is seen; the return itself
    # must carry the team_solved, or agents on 7 keep running on a solved challenge
    board = Board(); board.put("7", category="Crypto")
    tick(board, tmp_path)               # challenge_new 7
    dispatch.Dispatcher(prof, workdir=tmp_path).dispatch_new([dispatch.Detected("7", "Chal", "Crypto")])
    away = board.rows.pop("7")
    tick(board, tmp_path)               # challenge_gone 7
    board.rows["7"] = dataclasses.replace(away, solved_by_team=True)
    evs = tick(board, tmp_path)         # challenge_new 7 returning, solved

    solves = [e for e in evs if e["event"] == "team_solved" and e["challenge_id"] == "7"]
    assert len(solves) == 1
    assert solves[0]["returning"] is True and solves[0]["first_sight"] is False
    back = [e for e in evs if e["event"] == "challenge_new" and e.get("returning")]
    assert solves[0]["seq"] > back[0]["seq"]

    assert budget.is_stopped("7", workdir=tmp_path) is None
    assert solved.SolvedWatcher(workdir=tmp_path).once() == ["7"]
    assert budget.is_stopped("7", workdir=tmp_path) == "team_solve"
    # gone -> dispatched (the return) -> solved (the solve), in stream order
    assert dispatch.read_claims(tmp_path)[0]["7"]["status"] == "solved"


def test_a_replayed_solve_keeps_the_first_solve_time(tmp_path, prof):
    dispatch.Dispatcher(prof, workdir=tmp_path).dispatch_new([dispatch.Detected("7", "Chal", "Crypto")])
    solved.record_solve("7", solver="alice", workdir=tmp_path, clock=lambda: 100.0)
    solved.record_solve("7", solver="bob", workdir=tmp_path, clock=lambda: 200.0)
    claim = dispatch.read_claims(tmp_path)[0]["7"]
    assert claim["status"] == "solved"
    assert claim["solved_at"] == 100.0
    assert claim["solved_by"] == "alice"


def test_a_replayed_gone_is_a_no_op(tmp_path, prof):
    # `ctf solved run --since 0` replays the whole stream: the second pass must not re-stamp gone_at or
    # report the claim revoked again
    board = Board(); board.put("7", category="Crypto")
    tick(board, tmp_path)
    dispatch.Dispatcher(prof, workdir=tmp_path).dispatch_new([dispatch.Detected("7", "Chal", "Crypto")])
    board.remove("7")
    tick(board, tmp_path)               # challenge_gone 7

    gone = []
    solved.SolvedWatcher(workdir=tmp_path, clock=lambda: 100.0,
                         on_gone=lambda cid, rev: gone.append((cid, rev))).once()
    solved.SolvedWatcher(workdir=tmp_path, clock=lambda: 200.0,
                         on_gone=lambda cid, rev: gone.append((cid, rev))).once()
    assert gone == [("7", True), ("7", False)]
    claim = dispatch.read_claims(tmp_path)[0]["7"]
    assert claim["status"] == "gone"
    assert claim["gone_at"] == 100.0


def test_watcher_reports_a_solve_event_with_no_challenge_id(tmp_path):
    probs = []
    w = solved.SolvedWatcher(workdir=tmp_path, on_problem=probs.append)
    assert w.handle({"event": "team_solved", "seq": 5}) is None
    assert probs and "no challenge_id" in probs[0]


def test_watcher_run_stops_when_asked_and_acts_on_a_solve(tmp_path):
    stream_with_solve(tmp_path)
    # a one-shot stop: follow reads the stream once, then stop() is true
    calls = {"n": 0}

    def stop():
        calls["n"] += 1
        return calls["n"] > 1

    out = solved.SolvedWatcher(workdir=tmp_path).run(stop=stop, poll=0, sleep=lambda s: None)
    assert out == ["7"]
    assert budget.is_stopped("7", workdir=tmp_path) == "team_solve"


# ------------------------------------------------------------------- the dispatcher never dispatches solved

def test_dispatch_new_skips_a_challenge_already_solved(tmp_path, prof):
    board = Board(); board.put("7", category="Crypto")
    tick(board, tmp_path)
    budget.on_team_solve("7", solver="teammate", workdir=tmp_path)   # solved before we ever claim it

    d = dispatch.Dispatcher(prof, workdir=tmp_path)
    claims = d.dispatch_new([dispatch.Detected("7", "Chal", "Crypto")])
    assert claims == []
    assert dispatch.claim_path(tmp_path, "7").exists() is False
    skips = [r for r in ledger.read(tmp_path)
             if r.get("event") == "dispatch_skip" and r.get("challenge_id") == "7"]
    assert skips and skips[0]["reason"] == "solved"


def test_dispatch_new_still_dispatches_an_unsolved_challenge(tmp_path, prof):
    board = Board(); board.put("7", category="Crypto"); board.put("8", category="Misc")
    tick(board, tmp_path)
    budget.on_team_solve("7", workdir=tmp_path)                     # 7 solved, 8 not

    d = dispatch.Dispatcher(prof, workdir=tmp_path)
    claims = d.dispatch_new([dispatch.Detected("7", "A", "Crypto"), dispatch.Detected("8", "B", "Misc")])
    assert [c.challenge_id for c in claims] == ["8"]
    assert dispatch.claim_path(tmp_path, "8").exists()
    assert dispatch.claim_path(tmp_path, "7").exists() is False


def _already_solved_board(wd):
    """A board whose first listing already shows challenge 7 solved (a teammate solved it before our
    watcher saw it), next to an unsolved 8."""
    board = Board(); board.put("7", category="Crypto"); board.put("8", category="Misc")
    board.mark_solved("7")
    return tick(board, wd)


def test_a_challenge_solved_on_first_sight_is_a_team_solve_in_the_stream(tmp_path):
    evs = _already_solved_board(tmp_path)
    new = {e["challenge_id"]: e for e in evs if e["event"] == "challenge_new"}
    assert new["7"]["solved"] is True and new["8"]["solved"] is False
    solves = [e for e in evs if e["event"] == "team_solved"]
    assert [e["challenge_id"] for e in solves] == ["7"]
    assert solves[0]["first_sight"] is True
    # it follows its own challenge_new, so a consumer has seen the challenge first
    assert solves[0]["seq"] > new["7"]["seq"]


def test_a_challenge_solved_on_first_sight_is_never_dispatched(tmp_path, prof):
    # the verifier's probe: watch tick -> SolvedWatcher.once -> Dispatcher.once must not claim 7
    _already_solved_board(tmp_path)
    assert solved.SolvedWatcher(workdir=tmp_path).once() == ["7"]
    assert budget.is_stopped("7", workdir=tmp_path) == "team_solve"
    claims = dispatch.Dispatcher(prof, workdir=tmp_path).once()
    assert [c.challenge_id for c in claims] == ["8"]
    assert dispatch.claim_path(tmp_path, "7").exists() is False


def test_dispatch_skips_a_first_sight_solve_before_the_solved_watcher_ran(tmp_path, prof):
    # the dispatcher can read the stream before the solved watcher has written the stop: the
    # challenge_new's own solved flag still keeps it off
    _already_solved_board(tmp_path)
    assert solved.solved_ids(tmp_path) == set()
    claims = dispatch.Dispatcher(prof, workdir=tmp_path).once()
    assert [c.challenge_id for c in claims] == ["8"]
    assert dispatch.claim_path(tmp_path, "7").exists() is False
    skips = [r for r in ledger.read(tmp_path)
             if r.get("event") == "dispatch_skip" and r.get("challenge_id") == "7"]
    assert skips and skips[0]["reason"] == "solved"


def test_detected_from_event_carries_the_solved_flag():
    assert dispatch.Detected.from_event({"challenge_id": "7", "solved": True}).solved is True
    assert dispatch.Detected.from_event({"challenge_id": "7", "solved": False}).solved is False
    assert dispatch.Detected.from_event({"challenge_id": "7"}).solved is False


def test_dispatch_new_reads_the_solved_ledger_only_when_something_is_new(tmp_path, prof, monkeypatch):
    calls = []
    real = solved.solved_ids
    monkeypatch.setattr(solved, "solved_ids", lambda wd=None: calls.append(wd) or real(wd))
    d = dispatch.Dispatcher(prof, workdir=tmp_path)
    d.dispatch_new([dispatch.Detected("8", "B", "Misc")])
    assert len(calls) == 1
    d.dispatch_new([])                                     # an idle poll
    d.dispatch_new([dispatch.Detected("8", "B", "Misc")])  # already claimed: nothing new
    assert len(calls) == 1


# --------------------------------------------------------------------------------------------- the CLI

def _args(action, **kw):
    import argparse
    ns = argparse.Namespace(action=action, event=None, profile=None, since=0, duration=None,
                            poll=0, json=False)
    ns.__dict__.update(kw)
    return ns


def test_cli_list_prints_solved_ids(tmp_path, prof, monkeypatch, capsys):
    monkeypatch.setattr(cli_solved._paths, "workdir", lambda slug=None: tmp_path)
    monkeypatch.setattr(cli_solved, "_profile", lambda a: prof)
    budget.on_team_solve("7", workdir=tmp_path)
    budget.on_team_solve("9", workdir=tmp_path)
    rc = cli_solved.run(_args("list", json=True))
    assert rc == 0
    assert json.loads(capsys.readouterr().out.strip()) == ["7", "9"]


def test_cli_once_acts_on_solves_from_the_stream(tmp_path, prof, monkeypatch, capsys):
    monkeypatch.setattr(cli_solved._paths, "workdir", lambda slug=None: tmp_path)
    monkeypatch.setattr(cli_solved, "_profile", lambda a: prof)
    stream_with_solve(tmp_path)
    rc = cli_solved.run(_args("once"))
    assert rc == 0
    assert "team solve: 7" in capsys.readouterr().out
    assert budget.is_stopped("7", workdir=tmp_path) == "team_solve"
