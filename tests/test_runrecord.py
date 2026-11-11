"""A run read back from its folder: events, lane transcripts, and damaged lines named; the
one rule every report credits a solve by; the run folder a player names, and its run.json."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import ME, Challenge, DeckConfig, FileChange
from ctf_flightdeck.eventlog import FORMAT, EventLog
from ctf_flightdeck.mock.world import ManualClock
from ctf_flightdeck.runrecord import (
    Credit, Released, RunFolderError, RunInfo, event_line, load_run, read_run_info, run_folder, solves, write_run_info,
)
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


# ---------------------------------------------------------------------- what the log says beyond the events


def test_a_log_names_its_format_its_event_and_every_challenge_it_released(tmp_path):
    make_run(tmp_path)
    record = load_run(tmp_path)
    assert record.format == FORMAT == 2
    assert record.event == "t"
    assert record.board == {"a": Released("a", "Alpha", "misc", 50), "b": Released("b", "Beta", "web", 100)}


def test_an_older_log_has_format_1_and_ids_only(tmp_path):
    (tmp_path / "events.jsonl").write_text(
        json.dumps({"kind": "run-start", "wall": "w", "version": "0.0.0"}) + "\n"
        + json.dumps({"kind": "release", "at": 0, "data": {"challenges": ["a", 7, "b"], "board": "not a list"}}) + "\n"
    )
    record = load_run(tmp_path)
    assert (record.format, record.event) == (1, None)
    assert record.board == {"a": Released("a"), "b": Released("b")}


def test_a_transcript_keeps_the_known_dollars_and_who_changed_each_file(tmp_path):
    make_run(tmp_path)
    alpha = load_run(tmp_path).lanes["L01"]
    assert alpha.dollars is None and alpha.known_dollars == pytest.approx(0.01)  # its priced turn still counts
    assert [(f.file, f.by) for f in alpha.files] == [("x.py", "lane")]
    head, *rest = (tmp_path / "lanes" / "L01.jsonl").read_text().splitlines()
    older = {k: v for k, v in json.loads(head).items() if k != "known_dollars"}
    (tmp_path / "lanes" / "L01.jsonl").write_text("\n".join([json.dumps(older), *rest]) + "\n")
    assert load_run(tmp_path).lanes["L01"].known_dollars is None  # an older transcript: not known, never 0


# ---------------------------------------------------------------------- who solved what: the one rule


def line(kind, cid="x", lane=None, at=1.0, **data):
    return event_line({"kind": kind, "at": at, "lane": lane, "challenge": cid, "data": data})


def test_an_accepted_flag_goes_to_the_first_l1_engine_that_reported_it_else_its_lane_else_you():
    events = [
        line("l1", "x", "L01", engine="strings", status="candidate", flags=["t{x}"]),
        line("l1", "x", "L02", engine="later", status="solved", flags=["t{x}"]),
        line("submit", "x", "L02", flag="t{x}", correct=True),  # an L1 flag, whichever lane submitted it
        line("submit", "y", "L03", flag="t{y}", correct=True),
        line("l1", "z", None, engine="late", status="solved", flags=["t{z}"]),
        line("submit", "z", None, flag="t{z}", correct=False),  # rejected: no solve
        line("submit", "w", None, flag="t{w}", correct=True),  # you submitted it by hand
    ]
    found = solves(events)
    assert {cid: (s.by, s.who, s.lane, s.index) for cid, s in found.items()} == {
        "x": ("l1", "strings", "L02", 2), "y": ("lane", "L03", "L03", 3), "w": ("player", ME, None, 6),
    }
    assert found["x"].found == 0  # the l1 event that reported it first


def test_a_flag_reported_after_it_was_accepted_is_not_l1s():
    events = [line("submit", "x", "L01", flag="t{x}", correct=True), line("l1", "x", engine="e", status="solved", flags=["t{x}"])]
    assert solves(events)["x"].by == "lane"


def test_a_solve_with_no_flag_is_a_teammates_yours_or_one_the_platform_lists():
    events = [
        line("teammate", "a", who="wren", solved=True),
        line("teammate", "b", who=ME, solved=True),
        line("teammate", "c", who="you", solved=True, source="platform", before_run=True),
        line("teammate", "d", who="your team", solved=True, source="platform"),
        line("teammate", "e", who="your team", solved=True),  # an older log: run.py's word, written as a teammate
        line("teammate", "f", who="you", solved=True),  # a teammate whose handle is "you", from the team folder
        line("teammate", "g", who="wren", claimed=True),  # a claim is no solve
    ]
    found = solves(events)
    assert {cid: (s.by, s.who, s.platform, s.before_run) for cid, s in found.items()} == {
        "a": ("teammate", "wren", False, False), "b": ("player", ME, False, False),
        "c": ("player", "you", True, True), "d": ("team", "your team", True, False),
        "e": ("team", "your team", True, False), "f": ("teammate", "you", False, False),
    }
    assert solves(events, flags_only=True) == {}


def test_the_first_solve_of_a_challenge_is_its_solve():
    events = [line("teammate", "x", who="wren", solved=True), line("submit", "x", "L01", flag="t{x}", correct=True)]
    assert solves(events)["x"].by == "teammate"
    assert solves(events, flags_only=True)["x"].by == "lane"  # a draft needs the accepted flag


def test_the_credit_reads_a_log_one_event_at_a_time():
    credit = Credit()
    submit = line("submit", "x", "L01", flag="t{x}", correct=True)
    assert credit.flag(5, submit, "t{x}").by == "lane"  # nothing reported it yet
    credit.see(6, line("l1", "x", engine="xor", status="candidate", flags=["t{x}"]))
    assert (credit.flag(7, submit, "t{x}").by, credit.flag(7, submit, "t{x}").who) == ("l1", "xor")
    assert Credit.other(8, line("turn", "x", "L01")) is None


# ---------------------------------------------------------------------- the run folder a player names


def test_the_run_folder_is_the_folder_or_the_folder_of_its_event_log(tmp_path):
    make_run(tmp_path)
    assert run_folder(tmp_path) == tmp_path
    assert run_folder(tmp_path / "events.jsonl") == tmp_path  # the path a run prints when it ends
    with pytest.raises(RunFolderError, match="not a run folder; give the run folder"):
        run_folder(tmp_path / "lanes" / "L01.jsonl")
    with pytest.raises(RunFolderError, match="no such run folder"):
        run_folder(tmp_path / "nowhere")


def test_run_json_records_the_board_and_answers_as_absolute_paths(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "run").mkdir()
    write_run_info(tmp_path / "run", board=Path("board"), answers=Path("keys/answers.json"))
    info = read_run_info(tmp_path / "run")
    assert info == RunInfo((tmp_path / "board").resolve(), (tmp_path / "keys" / "answers.json").resolve())
    with pytest.raises(FileExistsError):  # a run folder is new: run.json is created, never replaced
        write_run_info(tmp_path / "run", board=None)
    assert read_run_info(tmp_path) is None  # a run older than run.json


@pytest.mark.parametrize(
    "content, problem",
    [("[1]", "is not a JSON object"), ("{", "is not JSON"), ('{"board": 7}', "board must be a path or null"),
     (None, "is not a regular file")],
    ids=["not an object", "not json", "not a path", "a symlink"],
)
def test_a_run_json_that_cannot_be_used_says_why(tmp_path, content, problem):
    target = tmp_path / "run.json"
    if content is None:
        (tmp_path / "elsewhere.json").write_text('{"board": "/x"}')
        target.symlink_to(tmp_path / "elsewhere.json")  # a lane on the host could plant one: never followed
    else:
        target.write_text(content)
    with pytest.raises(RunFolderError, match=re.escape(problem)):
        read_run_info(tmp_path)
