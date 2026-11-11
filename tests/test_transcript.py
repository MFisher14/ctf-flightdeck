"""Each lane's whole log is written when the lane ends, and for open lanes when the run closes."""

from __future__ import annotations

import json

from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import Challenge, DeckConfig, FileChange
from ctf_flightdeck.mock.world import ManualClock
from ctf_flightdeck.transcript import TranscriptLog


class Quiet:
    def __getattr__(self, name):
        return lambda *args, **kwargs: None


def deck_with_two_lanes():
    deck = Deck(DeckConfig(event="t", flag_format=r"t\{\w+\}", models=("m",)), Quiet(), ManualClock(10.0), lambda c, f: f == "t{a}")
    deck.release([Challenge("a", "Alpha", "misc", 50), Challenge("b", "Beta", "web", 100)], [QueueEntry("a", "m"), QueueEntry("b", "m")])
    return deck


def read(path):
    return [json.loads(line) for line in path.read_text(encoding="ascii").splitlines()]


def test_a_lane_that_ends_is_written_whole_at_once(tmp_path):
    deck = deck_with_two_lanes()
    log = TranscriptLog(tmp_path / "lanes")
    log.attach(deck)
    a, b = deck.lanes_on("a")[0], deck.lanes_on("b")[0]
    deck.report(a.id, TurnReport(action="cat note \x1b[31m", output="the flag is t{a}\nline two", tokens=50,
                                 files=(FileChange("solve.py", "+++ b/solve.py\n+print(1)\n", "added"),)))
    deck.report(a.id, TurnReport(action="submit t{a}", flag="t{a}", tokens=20))
    deck.apply(iv.Approve(a.id))  # solved: the lane ends
    lines = read(tmp_path / "lanes" / f"{a.id}.jsonl")
    head = lines[0]
    assert (head["challenge"], head["state"], head["turns"], head["tokens"]) == ("a", "solved", 2, 70)
    step = lines[1]
    assert (step["kind"], step["text"], step["output"]) == ("step", "cat note \x1b[31m", "the flag is t{a}\nline two")
    assert any(x.get("kind") == "note" and "correct" in x["text"] for x in lines)
    (change,) = [x for x in lines if "file" in x]
    assert (change["file"], change["status"], change["turn"]) == ("solve.py", "added", 1) and "+print(1)" in change["diff"]
    assert not (tmp_path / "lanes" / f"{b.id}.jsonl").exists()  # still running
    assert all(ord(ch) < 128 for ch in (tmp_path / "lanes" / f"{a.id}.jsonl").read_text(encoding="ascii"))


def test_lanes_still_open_are_written_when_the_run_closes(tmp_path):
    deck = deck_with_two_lanes()
    log = TranscriptLog(tmp_path / "lanes")
    log.attach(deck)
    log.close()
    assert sorted(p.name for p in (tmp_path / "lanes").iterdir()) == ["L01.jsonl", "L02.jsonl"]
    assert read(tmp_path / "lanes" / "L02.jsonl")[0]["state"] == "run"


def test_spend_after_a_lane_ended_rewrites_its_header_with_the_final_totals(tmp_path):
    # a coding-agent CLI reports a turn's cost when the turn ends, here after its lane solved mid-turn
    deck = deck_with_two_lanes()
    log = TranscriptLog(tmp_path / "lanes")
    log.attach(deck)
    a, b = deck.lanes_on("a")[0], deck.lanes_on("b")[0]
    deck.report(a.id, TurnReport(action="submit t{a}", flag="t{a}", tokens=20, dollars=0.01))
    deck.apply(iv.Approve(a.id))
    path = tmp_path / "lanes" / f"{a.id}.jsonl"
    assert read(path)[0]["dollars"] == 0.01
    deck.report(a.id, TurnReport(turn=False, tokens=300, cached_tokens=100, dollars=0.04, why="the turn it was stopped in"))
    head, *rest = read(path)
    assert (head["state"], head["turns"], head["tokens"], head["cached_tokens"]) == ("solved", 1, 320, 100)
    assert head["dollars"] == head["known_dollars"] == 0.05
    assert any(x.get("kind") == "note" and "correct" in x["text"] for x in rest)  # the rest is still there
    deck.report(b.id, TurnReport(turn=False, tokens=10, dollars=0.01))  # an open lane: written when the run closes
    assert not (tmp_path / "lanes" / f"{b.id}.jsonl").exists()
