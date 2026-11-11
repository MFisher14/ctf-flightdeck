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
from ctf_flightdeck.eventlog import FORMAT, EventLog, json_safe, new_run_dir

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
    assert set(start) == {"kind", "wall", "version", "format"}
    assert (start["kind"], start["version"]) == ("run-start", ctf_flightdeck.__version__)
    assert start["format"] == FORMAT == 2  # what the log holds: spend events, and each release names its board
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


# Made-up keys, each built from pieces so no line here is shaped like a real one (.githooks/secret_scan.py).
OPENROUTER = "sk-" + "or-v1-" + "5f" * 32
ANTHROPIC = "sk-" + "ant-api03-" + "Qx7-" * 20
GITHUB = "ghp" + "_" + "a1B2" * 9
CTFD = "ctfd" + "_" + "0f" * 32
JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.bm90LWEtcmVhbC1zaWduYXR1cmU"
SECRETS = (OPENROUTER, ANTHROPIC, GITHUB, CTFD)


def test_what_a_lane_did_is_logged_with_each_credentials_value_taken_out(tmp_path):
    """A host lane can read the player's keys file or another process's environment, and a run
    folder is read, shared and drafted into writeups. A turn's command, an alert quoting an
    output, spend outside a turn, a hint, a warning and a lane's result keep each credential's
    name and lose its value in the log (credentials.py); ordinary CTF content (a JWT the lane
    forged, under a lower-case name) stays. The deck keeps what the lane did as it was: the
    lane's model has read it already."""
    deck, _ = make_deck()
    log = EventLog(tmp_path / "events.jsonl")
    log.attach(deck)
    release(deck)
    curl = f"curl -H 'Authorization: Bearer {JWT}' http://127.0.0.1:8080/admin"
    deck.report("L01", TurnReport(action=curl, output=f"token: {JWT}"))
    deck.report("L01", TurnReport(action="cat ~/.config/ctf-flightdeck/keys.env", output=f"OPENROUTER_API_KEY={OPENROUTER}",
                                  alerts=(Alert(AlertKind.LOOP, f"The same output came back twice: OPENROUTER_API_KEY={OPENROUTER}"),)))
    deck.report("L01", TurnReport(turn=False, tokens=50, why=f"a reply dropped, which said {ANTHROPIC}"))
    deck.apply(iv.Hint("L01", f"the token: {JWT} is forged; use GITHUB_TOKEN={GITHUB}"))
    deck.warn(f"could not pull the board with CTFD_TOKEN={CTFD}")
    deck.report("L02", TurnReport(action="ls", gave_up=f"the server wants ANTHROPIC_API_KEY={ANTHROPIC}"))
    log.close()
    text = log.path.read_text(encoding="ascii")
    assert not [secret for secret in SECRETS if secret in text]
    lines = records(log.path)
    kinds: dict[str, list[dict]] = {}
    for line in lines:
        kinds.setdefault(line["kind"], []).append(line)
    turn = kinds["turn"][0]
    assert turn["text"] == "L01 turn 1: curl -H 'Authorization: Bearer [redacted]' http://127.0.0.1:8080/admin"
    assert turn["data"]["action"] == "curl -H 'Authorization: Bearer [redacted]' http://127.0.0.1:8080/admin"
    (alert,) = kinds["alert"]
    assert alert["data"]["reason"] == "The same output came back twice: OPENROUTER_API_KEY=[redacted]"
    assert alert["text"] == "L01 Loop: The same output came back twice: OPENROUTER_API_KEY=[redacted]"
    (spend,) = kinds["spend"]
    assert spend["data"]["why"] == "a reply dropped, which said sk-ant-[redacted]"
    assert spend["text"].endswith(": a reply dropped, which said sk-ant-[redacted]")
    (hint,) = kinds["intervention"]
    assert hint["data"]["text"] == f"the token: {JWT} is forged; use GITHUB_TOKEN=[redacted]"
    (warning,) = kinds["warning"]
    assert warning["text"] == "could not pull the board with CTFD_TOKEN=[redacted]"
    (end,) = kinds["lane.end"]
    assert end["data"]["result"] == "the server wants ANTHROPIC_API_KEY=[redacted]"
    assert end["text"] == "L02 gave up: the server wants ANTHROPIC_API_KEY=[redacted]"
    lane = deck.lanes["L01"]  # the deck's own record is as the lane left it
    assert [a.text for a in lane.actions[:2]] == [curl, "cat ~/.config/ctf-flightdeck/keys.env"]
    assert lane.actions[1].output == f"OPENROUTER_API_KEY={OPENROUTER}"
    assert next(e for e in deck.events if e.kind is EventKind.TURN).text == f"L01 turn 1: {curl}"


def test_the_flags_the_run_has_named_stay_whole_in_the_log(tmp_path):
    """Flags are not credentials. Once an event names a flag (an L1 result, a candidate
    waiting for the player, a submit), that event's line and every line after it keep it
    whole, one shaped like a credential too, while a credential beside it still loses its
    value. The log is written as things happen: the turn that submits a flag comes before
    the event that names it, so that line has the flag's value taken out."""
    flag, l1_flag = "t{TOKEN=c0ffee}", "t{SECRET=from_l1}"
    config = DeckConfig(event="Sample Event", max_lanes=1, flag_format=r"t\{[^{}\s]+\}", models=("small",))
    deck = Deck(config, Driver(), Clock(), verify=lambda cid, candidate: candidate == flag)
    log = EventLog(tmp_path / "events.jsonl")
    log.attach(deck)
    deck.release([Challenge("c0", "Sample 0", "misc", 100)], [QueueEntry("c0", "small")])
    deck.record_l1("c0", "reader", "flag found", flags=[l1_flag], lane_id="L01")
    deck.report("L01", TurnReport(action=f"echo {l1_flag} OPENROUTER_API_KEY={OPENROUTER}"))
    deck.report("L01", TurnReport(action=f"submit {flag}", flag=flag))
    assert deck.apply(iv.Approve("L01")).ok
    log.close()
    lines = records(log.path)
    assert OPENROUTER not in log.path.read_text(encoding="ascii")
    (l1,) = [line for line in lines if line["kind"] == "l1"]
    assert l1["data"]["flags"] == [l1_flag] and l1["text"] == f"L1 reader on Sample 0: flag found: {l1_flag}"
    assert [line["data"]["action"] for line in lines if line["kind"] == "turn"] == [
        f"echo {l1_flag} OPENROUTER_API_KEY=[redacted]",
        "submit t{TOKEN=[redacted]",  # written before the run knew the flag
    ]
    (pending,) = [line for line in lines if line["kind"] == "pending"]
    assert pending["data"]["flag"] == flag and pending["text"] == f"L01 waits for approval: submit {flag}"
    (submit,) = [line for line in lines if line["kind"] == "submit"]
    assert submit["data"]["flag"] == flag and submit["text"] == f"L01 submitted {flag} for Sample 0: correct"
    (end,) = [line for line in lines if line["kind"] == "lane.end"]
    assert end["data"]["result"] == f"solved with {flag}"


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
    start = records(log.path)[0]
    assert set(start) == {"kind", "wall", "version", "format"} and start["format"] == FORMAT  # a constant of the code


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
