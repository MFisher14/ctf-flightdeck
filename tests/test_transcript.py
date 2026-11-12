"""Each lane's whole log is written when the lane ends, and for open lanes when the run closes."""

from __future__ import annotations

import json

from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import Call, Challenge, DeckConfig, EventKind, FileChange
from ctf_flightdeck.mock.world import ManualClock
from ctf_flightdeck.transcript import TranscriptLog
from deadline import within


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


# Made-up keys, each built from pieces so no line here is shaped like a real one (.githooks/secret_scan.py).
OPENROUTER = "sk-" + "or-v1-" + "5f" * 32
GITHUB = "ghp" + "_" + "a1B2" * 9
CTFD = "ctfd" + "_" + "0f" * 32
JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.bm90LWEtcmVhbC1zaWduYXR1cmU"


def test_a_transcript_takes_out_what_is_shaped_like_a_credential_but_never_a_flag(tmp_path):
    """A host lane can read the player's keys file or another process's environment: its
    transcript keeps each name and takes out the value (credentials.py). The flags the run
    knows for the challenge stay as they are, one shaped like a credential too, and so does
    ordinary CTF content (a JWT the lane printed)."""
    flag, l1_flag = "t{TOKEN=c0ffee}", "t{SECRET=from_l1}"
    deck = Deck(DeckConfig(event="t", flag_format=r"t\{[^{}\s]+\}", models=("m",)), Quiet(), ManualClock(10.0),
                lambda c, f: f == flag)
    deck.release([Challenge("a", "Alpha", "web", 50)], [QueueEntry("a", "m")])
    log = TranscriptLog(tmp_path / "lanes")
    log.attach(deck)
    (lane,) = deck.lanes_on("a")
    deck.record_l1("a", "reader", "flag found", flags=[l1_flag], lane_id=lane.id)
    deck.report(lane.id, TurnReport(action="$ cat ~/.config/ctf-flightdeck/keys.env",
                                    output=f"OPENROUTER_API_KEY={OPENROUTER}\nCTFD_TOKEN={CTFD}", tokens=10,
                                    plan="log in with API_KEY=abc123, then read the flag"))
    deck.report(lane.id, TurnReport(action=f"$ curl -H 'Authorization: Bearer {JWT}' http://127.0.0.1:8080/admin",
                                    output=f"token: {JWT}\n{flag}\n{l1_flag}", tokens=10,
                                    files=(FileChange("env.txt", f"+++ b/env.txt\n+GITHUB_TOKEN={GITHUB}\n", "added"),)))
    deck.report(lane.id, TurnReport(action=f"submit {flag}", flag=flag, tokens=10))
    deck.apply(iv.Approve(lane.id))  # correct: the lane ends and its transcript is written
    text = (tmp_path / "lanes" / f"{lane.id}.jsonl").read_text(encoding="ascii")
    for secret in (OPENROUTER, CTFD, GITHUB, "abc123"):
        assert secret not in text
    lines = read(tmp_path / "lanes" / f"{lane.id}.jsonl")
    head, steps = lines[0], [x for x in lines if x.get("kind") == "step"]
    assert head["plan"] == "log in with API_KEY=[redacted], then read the flag"
    assert steps[0]["output"] == "OPENROUTER_API_KEY=[redacted]\nCTFD_TOKEN=[redacted]"
    assert steps[1]["text"] == "$ curl -H 'Authorization: Bearer [redacted]' http://127.0.0.1:8080/admin"
    assert steps[1]["output"] == f"token: {JWT}\n{flag}\n{l1_flag}"  # a JWT under a lower-case name, and the flags
    (change,) = [x for x in lines if "file" in x]
    assert change["diff"] == "+++ b/env.txt\n+GITHUB_TOKEN=[redacted]\n"
    said = [x["text"] for x in lines if x.get("kind") == "note"]
    assert f"candidate flag {flag}" in said and f"submitted {flag}: correct" in said
    assert any(note.startswith(f"L1 reader: flag found: {l1_flag}") for note in said)


def test_files_of_blank_header_values_never_hold_up_the_approval_that_ends_the_lane(tmp_path):
    """A handout, or a page a lane saved, can hold a header's name and a colon followed by tens
    of thousands of blanks. The lane's transcript is written while the deck handles the
    approval that ended the lane (the console waits for it), with credentials taken out of each
    file's diff: that costs time in proportion to the text. It took half a minute a file when
    the blanks were given back one at a time, each time scanning the rest of the line again.
    The same goes for the lanes still open when the run closes."""
    deck = deck_with_two_lanes()
    log = TranscriptLog(tmp_path / "lanes")
    log.attach(deck)
    a, b = deck.lanes_on("a")[0], deck.lanes_on("b")[0]
    blanks = {  # each a line of a text file under 64 KB, whose diff a lane's transcript keeps whole
        "cookie.txt": "Cookie:" + " " * 60_000,
        "auth.txt": "Authorization:" + "\t" * 60_000,
        "quoted.txt": "cookie:" + " " * 60_000 + '"',
    }
    diffs = {name: f"+++ b/{name}\n+{line}\n" for name, line in blanks.items()}
    for lane in (a, b):
        deck.report(lane.id, TurnReport(action="$ tar xf handout.tar && cat cookie.txt", output=blanks["cookie.txt"],
                                        tokens=10, files=tuple(FileChange(name, diff, "added") for name, diff in diffs.items())))
    deck.report(a.id, TurnReport(action="submit t{a}", flag="t{a}", tokens=10))
    with within(5, "approving the flag, which writes the lane's transcript"):
        assert deck.apply(iv.Approve(a.id)).ok
    with within(5, "closing the run, which writes the lane still open"):
        log.close()
    for lane in (a, b):
        lines = read(tmp_path / "lanes" / f"{lane.id}.jsonl")
        assert {x["file"]: x["diff"] for x in lines if "file" in x} == diffs  # no value in them to take out
        assert lines[1]["output"] == blanks["cookie.txt"]


def test_a_step_keeps_every_tool_call_of_its_turn_in_the_transcript_and_stays_one_step_everywhere_else(tmp_path):
    """TurnReport.calls: on the step's Action for the transcript, each call with its longer
    output and credentials taken out as from any text of the lane. The step itself (what the
    console, the detectors and events.jsonl have) is one, with the text and output it had."""
    from ctf_flightdeck.core.driver import spend_only

    deck = deck_with_two_lanes()
    log = TranscriptLog(tmp_path / "lanes")
    log.attach(deck)
    a = deck.lanes_on("a")[0]
    calls = (Call("$ ls", "note\nkeys.env"), Call("$ cat keys.env", f"OPENROUTER_API_KEY={OPENROUTER}\nthe flag is t{{a}}"))
    deck.report(a.id, TurnReport(action="$ ls  (+1 more)", output="note\nkeys.env", calls=calls, tokens=50))
    deck.report(a.id, TurnReport(action="submit t{a}", flag="t{a}", tokens=20))
    assert [(x.text, x.output) for x in a.actions if x.kind.value == "step"] == [("$ ls  (+1 more)", "note\nkeys.env"), ("submit t{a}", "")]
    assert a.actions[0].calls == calls and a.turns == 2
    turns = [e for e in deck.events if e.kind is EventKind.TURN]
    assert [e.data["action"] for e in turns] == ["$ ls  (+1 more)", "submit t{a}"] and "calls" not in turns[0].data
    deck.apply(iv.Approve(a.id))
    text = (tmp_path / "lanes" / f"{a.id}.jsonl").read_text(encoding="ascii")
    assert OPENROUTER not in text
    first, second = [x for x in read(tmp_path / "lanes" / f"{a.id}.jsonl") if x.get("kind") == "step"]
    assert (first["text"], first["output"]) == ("$ ls  (+1 more)", "note\nkeys.env")
    assert first["calls"] == [
        {"text": "$ ls", "output": "note\nkeys.env"},
        {"text": "$ cat keys.env", "output": "OPENROUTER_API_KEY=[redacted]\nthe flag is t{a}"},
    ]
    assert "calls" not in second  # none reported: the line is as it was before the field
    # a late report that carries calls is a step, not spend: dropped once the lane has ended
    assert not spend_only(TurnReport(turn=False, tokens=5, calls=calls)) and spend_only(TurnReport(turn=False, tokens=5))
