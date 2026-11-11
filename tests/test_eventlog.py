"""The run's event log: one JSON line per deck event, written from a real Deck to a real file.

The driver is a stand-in that does no work; the deck, the log and the file are real.
"""

from __future__ import annotations

import json
import math
from datetime import datetime, timedelta, timezone
from enum import IntEnum
from pathlib import Path

import pytest

import ctf_flightdeck
from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import Alert, AlertKind, Challenge, DeckConfig, Event, EventKind, LaneState
from ctf_flightdeck.eventlog import EventLog, json_safe, new_run_dir

EVENT_KEYS = {"at", "wall", "kind", "text", "lane", "challenge", "alert", "data"}


class Clock:
    def __init__(self) -> None:
        self.t = 100.0

    def now(self) -> float:
        return self.t


class Driver:
    """Accepts every call from the deck and does no work."""

    def attach(self, deck): ...
    def start(self, lane, challenge): ...
    def pause(self, lane): ...
    def resume(self, lane): ...
    def hint(self, lane, text): ...
    def redirect(self, lane, text): ...
    def escalate(self, lane, model, summary): ...
    def approved(self, lane, pending): ...
    def rejected(self, lane, flag): ...
    def declined(self, lane, pending): ...
    def stop(self, lane): ...


def make_deck() -> tuple[Deck, Clock]:
    clock = Clock()
    config = DeckConfig(event="Sample Event", max_lanes=2, flag_format=r"t\{\w+\}", models=("small", "big"))
    return Deck(config, Driver(), clock, verify=lambda cid, flag: flag == "t{good}"), clock


def release(deck: Deck) -> None:
    challenges = [Challenge(f"c{i}", f"Sample {i}", "misc", 100) for i in range(2)]
    deck.release(challenges, [QueueEntry(c.id, "small") for c in challenges])


def play(deck: Deck, clock: Clock) -> None:
    """Turns, an alert, a hint, a candidate flag and its approval: most kinds of event."""
    clock.t += 30
    deck.report("L01", TurnReport(action="ls -la", output="a.txt", tokens=1200, cached_tokens=800, dollars=0.004))
    deck.report("L01", TurnReport(action="cat a.txt", alerts=(Alert(AlertKind.LOOP, "the same command three times"),)))
    deck.apply(iv.Hint("L01", "try the other file"))
    deck.report("L02", TurnReport(action="python3 solve.py", flag="t{good}", dollars=None))
    clock.t += 5
    deck.apply(iv.Approve("L02"))


def records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="ascii").split("\n") if line]


def expected(event: Event) -> dict:
    """The line an event should become, built without the code under test."""
    return {
        "at": event.at,
        "kind": event.kind.value,
        "text": event.text,
        "lane": event.lane,
        "challenge": event.challenge,
        "alert": None if event.alert is None else event.alert.value,
        "data": json.loads(json.dumps(dict(event.data))),
    }


def wall(record: dict) -> datetime:
    when = datetime.fromisoformat(record["wall"])
    assert when.utcoffset() == timedelta(0), record["wall"]
    return when


# ---------------------------------------------------------------------- the lines


def test_opening_the_log_writes_the_run_start_line(tmp_path):
    before = datetime.now(timezone.utc)
    log = EventLog(tmp_path / "events.jsonl")
    after = datetime.now(timezone.utc)
    (start,) = records(log.path)
    assert set(start) == {"kind", "wall", "version"}
    assert (start["kind"], start["version"]) == ("run-start", ctf_flightdeck.__version__)
    assert before - timedelta(milliseconds=1) <= wall(start) <= after
    log.close()


def test_the_log_creates_its_folder(tmp_path):
    path = tmp_path / "runs" / "20261110-200000" / "events.jsonl"
    log = EventLog(path)
    assert log.path == path and path.is_file()
    log.close()


def test_every_deck_event_becomes_one_line_with_its_fields(tmp_path):
    deck, clock = make_deck()
    log = EventLog(tmp_path / "events.jsonl")
    log.attach(deck)
    release(deck)
    play(deck, clock)
    log.close()
    lines = records(log.path)
    assert [line["kind"] for line in (lines[0], lines[-1])] == ["run-start", "run-end"]
    body = lines[1:-1]
    assert len(body) == len(deck.events) > 10
    for line, event in zip(body, deck.events):
        assert set(line) == EVENT_KEYS
        wall(line)
        assert {key: value for key, value in line.items() if key != "wall"} == expected(event)
    kinds = {line["kind"] for line in body}
    assert {"release", "lane.start", "turn", "alert", "pending", "intervention", "outcome", "submit", "lane.end"} <= kinds
    alerts = {line["alert"]: line for line in body if line["kind"] == "alert"}
    assert set(alerts) == {"loop", "flag"}
    assert (alerts["loop"]["lane"], alerts["loop"]["challenge"]) == ("L01", "c0")
    assert all(line["alert"] is None for line in body if line["kind"] != "alert")
    unpriced = [line for line in body if line["kind"] == "turn" and line["lane"] == "L02"]
    assert unpriced[0]["data"]["dollars"] is None


def test_each_line_is_on_disk_as_soon_as_it_is_written(tmp_path):
    deck, _ = make_deck()
    log = EventLog(tmp_path / "events.jsonl")
    log.attach(deck)
    release(deck)
    lines = records(log.path)  # read while the log is still open
    assert len(lines) == 1 + len(deck.events)
    assert lines[-1]["kind"] == "release"
    log.close()


def test_events_from_before_attach_are_written_first(tmp_path):
    deck, clock = make_deck()
    release(deck)
    early = len(deck.events)
    log = EventLog(tmp_path / "events.jsonl")
    log.attach(deck)
    play(deck, clock)
    log.close()
    body = records(log.path)[1:-1]
    assert len(body) == len(deck.events) and early > 0
    assert [line["text"] for line in body] == [event.text for event in deck.events]


def test_close_writes_run_end_once_and_stops_listening(tmp_path):
    deck, clock = make_deck()
    log = EventLog(tmp_path / "events.jsonl")
    log.attach(deck)
    release(deck)
    log.close()
    log.close()
    written = log.path.read_text(encoding="ascii")
    play(deck, clock)  # the deck carries on, and nothing more is written
    assert log.path.read_text(encoding="ascii") == written
    lines = records(log.path)
    assert [line["kind"] for line in lines].count("run-end") == 1
    end = lines[-1]
    assert set(end) == {"kind", "wall"} and end["kind"] == "run-end"
    assert wall(end) >= wall(lines[0])


def test_the_log_works_as_a_context_manager(tmp_path):
    deck, _ = make_deck()
    with EventLog(tmp_path / "events.jsonl") as log:
        log.attach(deck)
        release(deck)
    assert records(log.path)[-1]["kind"] == "run-end"


def test_attaching_twice_or_after_close_is_refused(tmp_path):
    deck, _ = make_deck()
    log = EventLog(tmp_path / "events.jsonl")
    log.attach(deck)
    with pytest.raises(RuntimeError, match="already attached"):
        log.attach(deck)
    release(deck)
    log.close()
    with pytest.raises(RuntimeError, match="closed"):
        log.attach(make_deck()[0])
    assert len(records(log.path)) == 2 + len(deck.events)  # nothing was written twice


def test_a_log_opened_on_an_existing_file_appends(tmp_path):
    path = tmp_path / "events.jsonl"
    EventLog(path).close()
    EventLog(path).close()
    assert [line["kind"] for line in records(path)] == ["run-start", "run-end", "run-start", "run-end"]


# ---------------------------------------------------------------------- untrusted text, and nothing else


def test_untrusted_text_cannot_split_a_line_or_reach_a_terminal(tmp_path):
    """Hint text the player pasted from a challenge: newlines, Unicode line breaks, an escape
    sequence and a lone surrogate. Each line stays one ASCII line, and the text comes back exact."""
    nasty = "a\nb\rc d e\x85f\x1b[2Jg\x07h\ud800i‮j"
    deck, _ = make_deck()
    log = EventLog(tmp_path / "events.jsonl")
    log.attach(deck)
    release(deck)
    deck.apply(iv.Hint("L01", nasty))
    log.close()
    raw = log.path.read_bytes()
    assert all(byte < 0x80 for byte in raw)
    assert b"\x1b" not in raw and b"\r" not in raw and b"\x07" not in raw
    text = raw.decode("ascii")
    assert len(text.splitlines()) == len(text.split("\n")) - 1 == len(deck.events) + 2
    (hint,) = [line for line in records(log.path) if line["kind"] == "intervention"]
    assert hint["data"]["text"] == nasty


def test_the_log_holds_nothing_from_the_environment_or_the_config(monkeypatch, tmp_path):
    secret = "fake-key-value-for-tests-7781"
    monkeypatch.setenv("OPENROUTER_API_KEY", secret)
    monkeypatch.setenv("FLIGHTDECK_CONFIG", "/somewhere/private-config-path.toml")
    deck, clock = make_deck()
    log = EventLog(tmp_path / "events.jsonl")
    log.attach(deck)
    release(deck)
    play(deck, clock)
    log.close()
    text = log.path.read_text(encoding="ascii")
    assert secret not in text and "private-config-path" not in text and str(tmp_path) not in text
    assert set(records(log.path)[0]) == {"kind", "wall", "version"}


# ---------------------------------------------------------------------- JSON-safe data


class Level(IntEnum):
    LOW = 1


class Opaque:
    def __repr__(self) -> str:
        return "<opaque thing>"


WORDS = ["kilo", "alpha", "juliet", "echo", "bravo", "india", "delta", "hotel", "charlie", "golf"]


def test_json_safe_turns_any_payload_into_plain_json():
    """Sets come out sorted, so the same run writes the same line. Ten strings iterate in an
    order set by the hash seed, sorted for about one seed in 3.6 million; these ints iterate
    as 33, 12, 20, 41 whatever the seed. Either set catches a json_safe that does not sort."""
    payload = {
        "kind": EventKind.TURN,
        AlertKind.LOOP: "an enum key",
        3: "an int key",
        "level": Level.LOW,
        "tuple": (1, ("a", LaneState.RUNNING)),
        "set": set(WORDS),
        "frozen": frozenset({33, 12, 41, 20}),
        "flags": [True, False, None],
        "nan": math.nan,
        "inf": math.inf,
        "minus inf": -math.inf,
        "float": 1.25,
        "path": Path("/x/y"),
        "bytes": b"\x00\xff",
        "object": Opaque(),
        "nested": {"deeper": [{"x": (None, True, 1.5)}]},
    }
    assert json_safe(payload) == {
        "kind": "turn",
        "loop": "an enum key",
        "3": "an int key",
        "level": 1,
        "tuple": [1, ["a", "run"]],
        "set": ["alpha", "bravo", "charlie", "delta", "echo", "golf", "hotel", "india", "juliet", "kilo"],
        "frozen": [12, 20, 33, 41],
        "flags": [True, False, None],
        "nan": "nan",
        "inf": "inf",
        "minus inf": "-inf",
        "float": 1.25,
        "path": repr(Path("/x/y")),
        "bytes": repr(b"\x00\xff"),
        "object": "<opaque thing>",
        "nested": {"deeper": [{"x": [None, True, 1.5]}]},
    }
    json.dumps(json_safe(payload), allow_nan=False)


def test_json_safe_never_raises_on_data_that_refers_to_itself():
    loop: dict = {}
    loop["self"] = loop
    json.dumps(json_safe(loop), allow_nan=False)


def test_unusual_event_data_reaches_the_file_as_json(tmp_path):
    deck, _ = make_deck()
    deck.events.append(
        Event(12.5, EventKind.WARNING, "odd", "L09", "c9", AlertKind.STALL, {"state": LaneState.PAUSED, "ids": ("a", "b"), "x": math.nan})
    )
    log = EventLog(tmp_path / "events.jsonl")
    log.attach(deck)
    log.close()
    (line,) = records(log.path)[1:-1]
    assert (line["at"], line["kind"], line["alert"]) == (12.5, "warning", "stall")
    assert line["data"] == {"state": "paused", "ids": ["a", "b"], "x": "nan"}


# ---------------------------------------------------------------------- run folders


def test_a_run_folder_is_named_by_the_time_and_created(tmp_path):
    base = tmp_path / "runs"
    run = new_run_dir(base, datetime(2026, 11, 10, 20, 8, 5))
    assert run == base / "20261110-200805"
    assert run.is_dir() and list(run.iterdir()) == []


def test_a_taken_run_folder_name_gets_the_next_number(tmp_path):
    now = datetime(2026, 11, 10, 20, 8, 5)
    names = [new_run_dir(tmp_path, now).name for _ in range(3)]
    assert names == ["20261110-200805", "20261110-200805-2", "20261110-200805-3"]
    (tmp_path / "20261110-200805-4").write_text("a file, not a run")
    assert new_run_dir(tmp_path, now).name == "20261110-200805-5"


def test_a_run_folder_defaults_to_the_local_time_now(tmp_path):
    before = datetime.now().replace(microsecond=0)
    run = new_run_dir(tmp_path)
    after = datetime.now()
    assert before <= datetime.strptime(run.name, "%Y%m%d-%H%M%S") <= after


def test_a_run_folder_base_may_start_with_a_tilde(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    run = new_run_dir(Path("~/ctf-runs"), datetime(2026, 1, 2, 3, 4, 5))
    assert run == tmp_path / "ctf-runs" / "20260102-030405"
