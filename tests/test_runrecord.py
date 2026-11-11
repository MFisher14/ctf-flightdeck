"""A run read back from its folder: events, lane transcripts, and damaged lines named."""

from __future__ import annotations

import json

import pytest

from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import Challenge, DeckConfig, FileChange
from ctf_flightdeck.eventlog import EventLog
from ctf_flightdeck.mock.world import ManualClock
from ctf_flightdeck.runrecord import RunFolderError, load_run
from ctf_flightdeck.transcript import TranscriptLog


class Quiet:
    def __getattr__(self, name):
        return lambda *args, **kwargs: None


def make_run(folder):
    clock = ManualClock(0.0)
    deck = Deck(DeckConfig(event="t", flag_format=r"t\{\w+\}", models=("m",)), Quiet(), clock, lambda c, f: f == "t{a}")
    log = EventLog(folder / "events.jsonl")
    log.attach(deck)
    lanes = TranscriptLog(folder / "lanes")
    lanes.attach(deck)
    deck.release([Challenge("a", "Alpha", "misc", 50, solves=3), Challenge("b", "Beta", "web", 100)],
                 [QueueEntry("a", "m"), QueueEntry("b", "m")])
    a = deck.lanes_on("a")[0]
    clock.advance(30)
    deck.report(a.id, TurnReport(action="cat note", output="t{a}", tokens=500, dollars=0.01,
                                 files=(FileChange("x.py", "+++ b/x.py\n+1\n", "added"),)))
    deck.apply(iv.Hint(a.id, "look closer"))
    clock.advance(30)
    deck.report(a.id, TurnReport(action="submit", flag="t{a}", tokens=100, dollars=None))
    deck.apply(iv.Approve(a.id))
    lanes.close()
    log.close()
    return deck


def test_a_run_folder_reads_back_its_events_and_lanes(tmp_path):
    deck = make_run(tmp_path)
    record = load_run(tmp_path)
    assert record.problems == ()
    assert record.events[0].kind == "run-start" and record.events[-1].kind == "run-end"
    assert record.started and record.ended
    submit = record.of("submit")[0]
    assert (submit.challenge, submit.data["correct"]) == ("a", True)
    assert record.duration == 60.0
    assert list(record.lanes) == ["L01", "L02"]
    alpha = record.lanes["L01"]
    assert (alpha.challenge, alpha.name, alpha.points, alpha.state, alpha.turns, alpha.tokens) == ("a", "Alpha", 50, "solved", 2, 600)
    assert alpha.dollars is None  # the second turn had no known price
    assert alpha.actions[0].text == "cat note" and alpha.actions[0].output == "t{a}"
    assert any(x.kind == "message" and x.text == "look closer" for x in alpha.actions)
    assert alpha.files[0].file == "x.py" and "+1" in alpha.files[0].diff
    assert record.lanes["L02"].state == "run" and record.lanes["L02"].ended_at is None
    assert len(record.events) == len(deck.events) + 2


def test_damaged_lines_are_skipped_and_named_never_silently(tmp_path):
    make_run(tmp_path)
    with (tmp_path / "events.jsonl").open("a") as handle:
        handle.write('{"kind": "turn", "at": 9\n')  # a crash mid-write
        handle.write('["not", "an", "object"]\n')
    (tmp_path / "lanes" / "L03.jsonl").write_text('{"at": 1, "kind": "step"}\n')  # no header
    record = load_run(tmp_path)
    assert len(record.problems) == 3
    assert record.problems[0].startswith("events.jsonl:") and "not JSON" in record.problems[0]
    assert "not a JSON object" in record.problems[1]
    assert record.problems[2] == "L03.jsonl: no header line; skipped"
    assert "L03" not in record.lanes


def test_a_folder_without_an_event_log_is_not_a_run(tmp_path):
    with pytest.raises(RunFolderError, match="no events.jsonl"):
        load_run(tmp_path)


def test_odd_values_in_a_log_become_defaults_not_crashes(tmp_path):
    (tmp_path / "events.jsonl").write_text(json.dumps({"kind": "turn", "at": "soon", "lane": 7, "data": [1]}) + "\n")
    (tmp_path / "lanes").mkdir()
    (tmp_path / "lanes" / "L01.jsonl").write_text(json.dumps({"lane": "L01", "points": True, "dollars": "1", "ended_at": None}) + "\n")
    record = load_run(tmp_path)
    event = record.events[0]
    assert (event.at, event.lane, event.data) == (0.0, None, {})
    lane = record.lanes["L01"]
    assert (lane.points, lane.dollars, lane.ended_at, lane.attempt) == (0, None, None, 1)



@pytest.mark.parametrize("number", ["NaN", "Infinity", "-Infinity", "1e400", "9" * 400])
def test_a_count_that_is_no_usable_number_is_named_never_a_crash(tmp_path, number):
    make_run(tmp_path)
    head = json.loads((tmp_path / "lanes" / "L01.jsonl").read_text().splitlines()[0])
    line = json.dumps({**head, "lane": "L09", "turns": 0}).replace('"turns": 0', '"turns": ' + number)
    (tmp_path / "lanes" / "L09.jsonl").write_text(line + "\n")
    record = load_run(tmp_path)  # int() of NaN, Infinity or 1e400 would raise here
    assert record.lanes["L09"].turns == 0
    assert "L09.jsonl: header turns: is not a usable number; read as 0" in record.problems
