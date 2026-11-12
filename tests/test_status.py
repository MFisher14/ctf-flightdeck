"""status.json: the run as it stands, for whatever is not the console (status.py).

The deck is real (test_deck's recording driver and verifier stand in for lane work and the
platform); the file is written to tmp_path and read back as a reader would."""

from __future__ import annotations

import asyncio
import json
import os
import threading
import time
from pathlib import Path

import pytest

from ctf_flightdeck import __version__
from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import Alert, AlertKind, EventKind, Pending, PendingKind
from ctf_flightdeck.status import FORMAT, MAX_NAME, MAX_TEXT, NAME, StatusFile, write_atomically

from test_deck import good_flag, lane_on, make_deck


def status_for(tmp_path: Path, deck, **kwargs) -> StatusFile:
    kwargs.setdefault("min_gap", 0.0)  # every event writes: the tests read the file right after one
    status = StatusFile(tmp_path / NAME, deck, run="20261112-101500", **kwargs)
    status.attach()
    return status


def read(tmp_path: Path) -> dict:
    return json.loads((tmp_path / NAME).read_text(encoding="ascii"))


def test_the_file_is_there_once_attached_and_says_what_the_deck_holds(tmp_path):
    deck, _, clock = make_deck(n=3, max_lanes=2)
    status_for(tmp_path, deck)
    clock.t += 12.34
    deck.report("L01", TurnReport(action="cat note.txt", tokens=1200, dollars=0.25))
    doc = read(tmp_path)
    assert (doc["format"], doc["flightdeck"], doc["run"], doc["event"]) == (FORMAT, __version__, "20261112-101500", "test")
    assert doc["closed"] is False and doc["runtime_seconds"] == round(deck.now, 1)
    assert doc["written"].endswith("+00:00")
    assert doc["lanes"] == [
        {"id": "L01", "challenge": {"id": "c0", "name": "Chall 0"}, "state": "run", "model": "small", "turns": 1,
         "tokens": 1200, "dollars": 0.25, "unpriced": False, "needs_you": False, "pending": None, "waiting": 0,
         "alerts": [], "result": ""},
        {"id": "L02", "challenge": {"id": "c1", "name": "Chall 1"}, "state": "run", "model": "small", "turns": 0,
         "tokens": 0, "dollars": 0.0, "unpriced": False, "needs_you": False, "pending": None, "waiting": 0,
         "alerts": [], "result": ""},
    ]
    assert doc["needs_you"] == [] and doc["solves"] == []
    assert doc["queue"] == {"length": 1, "held": False, "held_reason": None}
    assert doc["totals"] == {"tokens": 1200, "dollars": 0.25, "unpriced": False}
    assert doc["challenges"] == {"total": 3, "solved": 0}


def test_an_approval_and_an_alert_show_on_their_lanes_and_in_what_needs_you_most_urgent_first(tmp_path):
    deck, _, clock = make_deck(n=3, max_lanes=3)
    status_for(tmp_path, deck)
    deck.report("L01", TurnReport(action="./brute.sh", alerts=(Alert(AlertKind.LOOP, "ran ./brute.sh 6 times"),)))
    clock.t += 5
    deck.report("L03", TurnReport(action="cat flag", flag=good_flag("c2")))  # later, but a flag comes first
    doc = read(tmp_path)
    by_id = {lane["id"]: lane for lane in doc["lanes"]}
    assert by_id["L03"]["state"] == "wait" and by_id["L03"]["needs_you"] is True
    assert by_id["L03"]["pending"] == {"kind": "submit", "detail": deck.lanes["L03"].pending.detail, "flag": "t{c2}"}
    assert by_id["L03"]["alerts"] == [{"kind": "flag", "reason": "Candidate t{c2} matches the flag format."}]
    assert by_id["L01"]["alerts"] == [{"kind": "loop", "reason": "ran ./brute.sh 6 times"}] and by_id["L01"]["pending"] is None
    assert by_id["L02"]["needs_you"] is False
    assert doc["needs_you"] == [
        {"lane": "L03", "challenge": "Chall 2", "pending": "submit", "alerts": ["flag"]},
        {"lane": "L01", "challenge": "Chall 0", "pending": None, "alerts": ["loop"]},
    ]
    assert [lane.id for lane in deck.needing()] == ["L03", "L01"]  # the console's own order


def test_a_solve_a_held_queue_and_spend_with_no_price_are_all_in_it(tmp_path):
    deck, _, _ = make_deck(n=4, max_lanes=2)
    status_for(tmp_path, deck)
    deck.report("L01", TurnReport(action="solve.py", tokens=10, dollars=0.5, flag=good_flag("c0")))
    assert read(tmp_path)["solves"] == []  # found, not submitted: nobody approved it
    assert deck.apply(iv.Approve("L01")).ok
    deck.report("L02", TurnReport(action="think", tokens=700, dollars=None))
    deck.hold_queue("the model API refuses the key")
    doc = read(tmp_path)
    assert doc["solves"] == [{"id": "c0", "name": "Chall 0", "points": 100, "by": "L01", "teammate": False}]
    assert doc["challenges"] == {"total": 4, "solved": 1}
    assert doc["queue"] == {"length": len(deck.queue), "held": True, "held_reason": "the model API refuses the key"}
    by_id = {lane["id"]: lane for lane in doc["lanes"]}
    assert (by_id["L01"]["state"], by_id["L01"]["result"]) == ("solved", "solved with t{c0}")
    assert by_id["L02"]["unpriced"] is True and by_id["L02"]["dollars"] == 0.0
    assert doc["totals"] == {"tokens": sum(lane.tokens for lane in deck.lanes.values()), "dollars": 0.5, "unpriced": True}


def test_untrusted_text_is_escaped_and_long_fields_are_cut(tmp_path):
    deck, _, _ = make_deck(n=1, max_lanes=1)
    deck.challenges["c0"].name = "Note\x1b]0;pwned\x07‮" + "n" * 400
    status_for(tmp_path, deck)
    deck.report("L01", TurnReport(action="x", alerts=(Alert(AlertKind.STALL, "quiet\x1b[2J\nfor " + "z" * 2000),)))
    raw = (tmp_path / NAME).read_bytes()
    assert all(byte == 0x0A or 0x20 <= byte < 0x7F for byte in raw)  # ASCII, no control character but its own newlines
    doc = json.loads(raw)
    name = doc["lanes"][0]["challenge"]["name"]
    assert name.startswith("Note\x1b]0;pwned\x07‮nnn") and len(name) == MAX_NAME and name.endswith("...")
    reason = doc["lanes"][0]["alerts"][0]["reason"]
    assert reason.startswith("quiet\x1b[2J\nfor zzz") and len(reason) == MAX_TEXT and reason.endswith("...")


def test_it_never_holds_a_held_secret_or_a_credential_and_keeps_the_flag_that_waits(tmp_path):
    """The values are made here, when the test runs: one has no shape the pattern layer
    knows (only its value gives it away), one is a bearer token no secret map names."""
    webhook = "https://hooks.example.test/services/" + "w" * 24
    api_key = "the-api-key-of-this-run-" + "a" * 16
    bearer = "bearer-token-value-" + "b" * 20
    deck, _, _ = make_deck(n=2, max_lanes=2)
    deck.challenges["c1"].name = f"Leaky {api_key}"
    status = status_for(tmp_path, deck, held={"FLIGHTDECK_TEST_WEBHOOK": webhook, "FLIGHTDECK_TEST_API_KEY": api_key})
    # a lane's text has held secrets as [NAME] before the deck sees it; this one slipped through
    deck.report("L01", TurnReport(action="x", alerts=(Alert(
        AlertKind.LOOP, f"ran curl -H 'Authorization: Bearer {bearer}' {webhook} with {api_key} 6 times"),)))
    deck.report("L02", TurnReport(action="y", flag=good_flag("c1")))
    deck.hold_queue(f"the API at {webhook} said no")
    raw = (tmp_path / NAME).read_text()
    for secret in (webhook, api_key, bearer):
        assert secret not in raw
    doc = json.loads(raw)
    assert doc["lanes"][0]["alerts"][0]["reason"] == (
        "ran curl -H 'Authorization: Bearer [redacted]' [FLIGHTDECK_TEST_WEBHOOK] with [FLIGHTDECK_TEST_API_KEY] 6 times")
    assert doc["lanes"][1]["challenge"]["name"] == "Leaky [FLIGHTDECK_TEST_API_KEY]"
    assert doc["queue"]["held_reason"] == "the API at [FLIGHTDECK_TEST_WEBHOOK] said no"
    assert doc["lanes"][1]["pending"]["flag"] == "t{c1}" and "t{c1}" in doc["lanes"][1]["pending"]["detail"]
    assert webhook not in repr(status.__dict__["_held"])


def test_a_reader_never_sees_a_partial_file_while_the_run_writes(tmp_path):
    """A reader parses the file in a loop while the deck's events rewrite it, each document
    tens of kilobytes: every read is whole JSON of the current format, never a part of one."""
    deck, _, _ = make_deck(n=40, max_lanes=40)
    status_for(tmp_path, deck)
    path = tmp_path / NAME
    stop, seen, bad = threading.Event(), [], []

    def reader() -> None:
        while not stop.is_set():
            try:
                raw = path.read_bytes()
                doc = json.loads(raw)
                assert doc["format"] == FORMAT and len(doc["lanes"]) == 40
                seen.append(doc["lanes"][0]["turns"])
            except Exception as exc:  # a partial or empty file, or one that was missing for a moment
                bad.append(f"{type(exc).__name__}: {exc}")
                return

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    try:
        for n in range(300):
            lane = f"L{n % 40 + 1:02d}"
            deck.report(lane, TurnReport(action=f"step {n}", alerts=(Alert(AlertKind.STALL, f"round {n} " + "s" * 400),)))
    finally:
        stop.set()
        thread.join(10)
    assert bad == []
    assert len(seen) > 20 and len(set(seen)) > 1, "the reader did not read while the file changed"
    assert len(path.read_bytes()) > 20_000
    assert [p.name for p in tmp_path.iterdir()] == [NAME]  # no temp file left behind


def test_a_write_replaces_a_symbolic_link_and_never_writes_through_one(tmp_path):
    elsewhere = tmp_path / "elsewhere.txt"
    elsewhere.write_text("the player's own file\n")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / NAME).symlink_to(elsewhere)
    deck, _, _ = make_deck(n=1, max_lanes=1)
    status = status_for(run_dir, deck)
    assert status.problem == ""
    assert elsewhere.read_text() == "the player's own file\n"
    assert not (run_dir / NAME).is_symlink() and read(run_dir)["format"] == FORMAT
    assert (run_dir / NAME).stat().st_mode & 0o777 == 0o600  # it names the flags that wait: the player's own


def test_the_temp_file_is_never_opened_through_a_link_someone_left(tmp_path, monkeypatch):
    target = tmp_path / "target.txt"
    target.write_text("untouched\n")
    monkeypatch.setattr("ctf_flightdeck.status.secrets.token_hex", lambda n: "abcd1234")
    (tmp_path / f".{NAME}.{os.getpid()}.abcd1234.tmp").symlink_to(target)
    with pytest.raises(FileExistsError):
        write_atomically(tmp_path / NAME, b"{}\n")
    assert target.read_text() == "untouched\n" and not (tmp_path / NAME).exists()


def test_closing_writes_the_closed_flag_once_and_nothing_after(tmp_path):
    deck, _, _ = make_deck(n=1, max_lanes=1)
    status = status_for(tmp_path, deck)
    assert read(tmp_path)["closed"] is False
    deck.report("L01", TurnReport(action="a", tokens=5))
    status.close()
    closed = (tmp_path / NAME).read_bytes()
    doc = json.loads(closed)
    assert doc["closed"] is True and doc["lanes"][0]["tokens"] == 5
    deck.report("L01", TurnReport(action="b", tokens=7))  # it no longer follows the deck
    status.write()
    status.close()
    assert (tmp_path / NAME).read_bytes() == closed


def test_a_file_that_cannot_be_written_is_one_warning_and_the_deck_goes_on(tmp_path):
    deck, _, _ = make_deck(n=1, max_lanes=1)
    gone = tmp_path / "gone"
    gone.mkdir()
    status = status_for(gone, deck)
    (gone / NAME).unlink()
    gone.rmdir()
    for n in range(3):
        deck.report("L01", TurnReport(action=f"step {n}", tokens=1))  # each would write
    assert deck.lanes["L01"].turns == 3 and deck.listener_errors == []
    warnings = [event for event in deck.events if event.kind is EventKind.WARNING]
    assert [event.text for event in warnings] == [f"cannot write the status file {NAME} in the run folder: No such file or directory"]
    assert warnings[0].data == {"source": "status"} and status.problem == warnings[0].text
    gone.mkdir()  # the folder is back: the next write works and the problem is over
    deck.report("L01", TurnReport(action="again", tokens=1))
    assert status.problem == "" and read(gone)["lanes"][0]["turns"] == 4


def test_events_close_together_are_one_write_and_the_timer_catches_up(tmp_path):
    deck, _, _ = make_deck(n=1, max_lanes=1)
    status = status_for(tmp_path, deck, min_gap=3600.0, interval=0.01)
    deck.report("L01", TurnReport(action="a", tokens=5))
    deck.report("L01", TurnReport(action="b", tokens=5))
    assert read(tmp_path)["lanes"][0]["turns"] == 0  # written at attach; the events since wait for the timer

    async def fly() -> None:
        timer = asyncio.create_task(status.run())
        deadline = time.monotonic() + 5
        while read(tmp_path)["lanes"][0]["turns"] != 2 and time.monotonic() < deadline:
            await asyncio.sleep(0.01)
        timer.cancel()

    asyncio.run(fly())
    assert read(tmp_path)["lanes"][0]["turns"] == 2


def test_a_burst_of_events_on_the_runs_loop_is_written_once_the_gap_has_passed_without_the_timer(tmp_path):
    deck, _, _ = make_deck(n=1, max_lanes=1)
    status = status_for(tmp_path, deck, min_gap=0.1)

    async def fly() -> None:
        for n in range(5):
            deck.report("L01", TurnReport(action=f"step {n}", tokens=5))
        assert read(tmp_path)["lanes"][0]["turns"] == 0  # all five came within the gap of the write at attach
        deadline = time.monotonic() + 5
        while read(tmp_path)["lanes"][0]["turns"] != 5 and time.monotonic() < deadline:
            await asyncio.sleep(0.01)

    asyncio.run(fly())  # no timer task: the write was scheduled by the events themselves
    assert read(tmp_path)["lanes"][0]["turns"] == 5 and status.problem == ""


def test_an_approval_of_another_kind_and_the_ones_behind_it_are_counted(tmp_path):
    deck, _, _ = make_deck(n=1, max_lanes=1)
    status_for(tmp_path, deck)
    deck.report("L01", TurnReport(action="a", pending=Pending(PendingKind.LIVE_BOX, "reach the live box at 10.0.0.5")))
    deck.report("L01", TurnReport(action="b", pending=Pending(PendingKind.BUDGET, "raise the caps")))
    lane = read(tmp_path)["lanes"][0]
    assert lane["pending"] == {"kind": "live box", "detail": "reach the live box at 10.0.0.5", "flag": None}
    assert lane["waiting"] == 1 and lane_on(deck, "c0").waiting[0].kind is PendingKind.BUDGET
