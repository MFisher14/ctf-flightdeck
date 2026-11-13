"""shared.json: what each lane of each challenge tried, in the run folder (sharedfile.py).

The deck is real (test_deck's recording driver and verifier stand in for lane work and the
platform); the file is written to tmp_path and read back as a reader would."""

from __future__ import annotations

import json
import stat
from pathlib import Path

from ctf_flightdeck import __version__
from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import Alert, AlertKind, EventKind
from ctf_flightdeck.sharedfile import FORMAT, MAX_TEXT, NAME, SharedFile

from test_deck import good_flag, make_deck


def shared_for(folder: Path, deck, **kwargs) -> SharedFile:
    file = SharedFile(folder / NAME, deck, run="20261113-101500", **kwargs)
    file.attach()
    return file


def read(folder: Path) -> dict:
    return json.loads((folder / NAME).read_text(encoding="ascii"))


def test_the_file_is_written_when_a_lane_ends_and_holds_every_lanes_entry_by_challenge(tmp_path):
    deck, _, _ = make_deck(n=2, max_lanes=2)
    deck.challenges["c1"].name = "Harbor Lab: Read"
    shared_for(tmp_path, deck)
    deck.report("L01", TurnReport(action="$ zsteg -a a.png", output="(nothing)", plan="bit planes", flag="t{wrong}"))
    assert not (tmp_path / NAME).exists()  # a step is no reason to write: an entry is settled when its lane ends
    assert deck.apply(iv.Decline("L01")).ok
    assert deck.apply(iv.Kill("L01", requeue=True)).ok  # L03, a fresh attempt on c0
    doc = read(tmp_path)
    assert (doc["format"], doc["flightdeck"], doc["run"], doc["closed"]) == (FORMAT, __version__, "20261113-101500", False)
    assert list(doc["challenges"]) == ["c0", "c1"]
    c0 = doc["challenges"]["c0"]
    assert (c0["name"], c0["series"]) == ("Chall 0", None) and doc["challenges"]["c1"]["series"] == "harbor lab"
    (first,) = c0["lanes"]  # written at L01's end: the fresh lane starts after it
    assert first == {
        "lane": "L01", "challenge": "c0", "models": ["small"], "how": "", "state": "killed", "open": False,
        "ended": "killed: by the player; re-queued fresh", "turns": 1, "approach": "", "plan": "bit planes",
        "programs": [["zsteg", 1]], "steps": 1, "last_steps": [[1, "$ zsteg -a a.png", "(nothing)"]], "found": [], "files": [],
        "flags": [["t{wrong}", ["declined by the player"]]], "alerts": [],
    }
    assert stat.S_IMODE((tmp_path / NAME).stat().st_mode) == 0o600
    assert deck.apply(iv.Kill("L03", requeue=False)).ok
    again = read(tmp_path)["challenges"]["c0"]["lanes"][1]
    assert (again["lane"], again["how"], again["open"], again["ended"]) == ("L03", "attempt 2", False, "killed: by the player; parked")


def test_closing_writes_it_a_last_time_closed_and_nothing_after(tmp_path):
    deck, _, _ = make_deck(n=1, max_lanes=1)
    file = shared_for(tmp_path, deck)
    deck.report("L01", TurnReport(action="$ strings a"))
    file.close()
    doc = read(tmp_path)
    (lane,) = doc["challenges"]["c0"]["lanes"]
    assert doc["closed"] is True and (lane["steps"], lane["open"]) == (1, True)
    deck.apply(iv.Kill("L01", requeue=False))
    file.close()
    assert read(tmp_path) == doc


def test_it_never_holds_a_held_secret_or_a_credential_keeps_the_flags_and_cuts_long_text(tmp_path):
    """The values are made here, when the test runs."""
    api_key = "the-api-key-of-this-run-" + "a" * 16
    bearer = "bearer-token-value-" + "b" * 20
    deck, _, _ = make_deck(n=1, max_lanes=1)
    file = shared_for(tmp_path, deck, held={"FLIGHTDECK_TEST_API_KEY": api_key})
    # a lane's text has held secrets as [NAME] before the deck sees it; this one slipped through
    deck.report("L01", TurnReport(action=f"$ curl -H 'Authorization: Bearer {bearer}' x", output=f"key {api_key}", plan="p" * 2000,
                                  alerts=(Alert(AlertKind.LOOP, f"used {api_key} 6 times"),), flag=good_flag("c0")))
    file.close()
    raw = (tmp_path / NAME).read_text()
    assert api_key not in raw and bearer not in raw
    (lane,) = json.loads(raw)["challenges"]["c0"]["lanes"]
    assert lane["last_steps"] == [[1, "$ curl -H 'Authorization: Bearer [redacted]' x", "key [FLIGHTDECK_TEST_API_KEY]"]]
    assert lane["alerts"][0] == ["Loop", "used [FLIGHTDECK_TEST_API_KEY] 6 times"]
    assert lane["flags"] == [["t{c0}", ["waits for approval"]]]
    assert lane["plan"] == "p" * (MAX_TEXT - 3) + "..."


def test_a_file_that_cannot_be_written_is_one_warning_and_the_deck_goes_on(tmp_path):
    deck, _, _ = make_deck(n=3, max_lanes=3)
    file = shared_for(tmp_path / "gone", deck)  # a folder that is not there
    for lane in ("L01", "L02"):
        assert deck.apply(iv.Kill(lane, requeue=False)).ok  # each would write
    assert deck.listener_errors == []
    warnings = [event for event in deck.events if event.kind is EventKind.WARNING]
    assert [event.text for event in warnings] == [f"cannot write the lanes' shared record {NAME} in the run folder: No such file or directory"]
    assert warnings[0].data == {"source": "shared"} and file.problem == warnings[0].text
    (tmp_path / "gone").mkdir()  # the folder is back: the next write works and the problem is over
    assert deck.apply(iv.Kill("L03", requeue=False)).ok
    assert file.problem == "" and len(read(tmp_path / "gone")["challenges"]) == 3


def test_a_run_leaves_the_record_in_its_folder_closed(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from ctf_flightdeck import cli
    from fake_model import FakeModelServer, tool_call_reply
    from test_run import FLAG, board, config, headless, next_steps, solve_then_quit

    headless(monkeypatch, solve_then_quit)
    with FakeModelServer([tool_call_reply("submit_flag", {"flag": FLAG})]) as server:
        result = CliRunner().invoke(cli.app, ["play", str(board(tmp_path)), "--config", str(config(tmp_path, server.base_url)),
                                              "--submit", "auto"])
    assert result.exit_code == 0, result.output
    folder, _ = next_steps(result.stdout)
    doc = read(folder)
    ((cid, challenge),) = doc["challenges"].items()
    (lane,) = challenge["lanes"]
    assert doc["closed"] is True and (lane["lane"], lane["challenge"], lane["ended"]) == ("L01", cid, "solved the challenge")
    assert lane["flags"] == [[FLAG, ["correct"]]]
