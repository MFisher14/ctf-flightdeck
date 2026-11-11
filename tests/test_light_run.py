"""The light model in a real run: [light] switches the hint judge on, the alert never waits for
it, and its spend lands on the lane's meter and in the event log. Lanes and the light model
are two fake OpenAI-compatible servers (no spend); lanes run on the host in tmp_path."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from ctf_flightdeck.core.model import AlertKind, EventKind
from ctf_flightdeck.run import RunOptions, prepare_run
from fake_model import FakeModelServer, error_reply, text_reply, tool_call_reply

HINTED = "A numbers station. There is a picture in it if you scan it slowly enough."


def board(tmp_path: Path) -> Path:
    root = tmp_path / "board"
    folder = root / "static"
    folder.mkdir(parents=True)
    (folder / "audio.txt").write_text("not really audio\n")
    spec = {"name": "Static Hiss", "category": "forensics", "points": 500, "solves": 1, "description": HINTED}
    (folder / "challenge.json").write_text(json.dumps(spec))
    (root / "board.json").write_text(json.dumps({"event": "Light Test", "flag_format": r"t\{[a-z0-9_]+\}"}))
    return root


def config(tmp_path: Path, lanes_url: str, light: str) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(
        f'[api]\nbase_url = "{lanes_url}"\nkey_env = ""\n'
        '[models]\nladder = ["fake/small", "fake/big"]\n'
        '[lanes]\nmax_lanes = 1\nruntime = "host"\ntoken_cap = false\ndollar_cap = false\n'
        f'[run]\ndir = "{tmp_path / "runs"}"\n' + light
    )
    return path


def light_table(url: str) -> str:
    return f'[light]\nengine = "openai"\nmodel = "light/m"\nbase_url = "{url}"\nkey_env = ""\ntimeout = 5\n'


async def wait_for(cond, what: str, seconds: float = 20.0) -> None:
    for _ in range(int(seconds * 100)):
        if cond():
            return
        await asyncio.sleep(0.01)
    raise AssertionError(f"timed out waiting for {what}")


def lane_loops(record):
    """Every lane turn lists the folder: never the hinted technique."""
    return tool_call_reply("shell", {"command": "ls"})


def play(tmp_path: Path, light_replies, until) -> tuple:
    with FakeModelServer(responder=lane_loops) as lanes, FakeModelServer(light_replies) as judge:
        run = prepare_run(RunOptions(board=board(tmp_path), config=config(tmp_path, lanes.base_url, light_table(judge.base_url))))

        async def main():
            run.release()
            (lane,) = run.deck.lanes.values()
            await wait_for(lambda: until(run, lane, judge), "the hint judge's verdict")
            seen = lane.alert(AlertKind.HINT)
            await run.shutdown()
            return lane, seen

        lane, seen = asyncio.run(main())
        run.close()
        return run, lane, seen, judge


def asked(server) -> int:
    return len([r for r in server.requests if r["json"]])


def spends(path: Path) -> list[dict]:
    return [e for e in map(json.loads, path.read_text().splitlines()) if e.get("kind") == EventKind.SPEND.value]


def test_a_light_model_in_the_config_judges_the_hint_alert_and_its_spend_is_counted(tmp_path):
    def withdrawn(run, lane, judge):
        return asked(judge) >= 1 and not run.watch._judging and any("hint alert withdrawn" in a.text for a in lane.actions)

    run, lane, seen, judge = play(tmp_path, [text_reply("yes", prompt_tokens=200, completion_tokens=1, cost=0.0002)]
                                  + [text_reply("yes")] * 20, withdrawn)
    assert run.watch.judge is not None
    assert any(note.startswith("light model: openai light/m judges") for note in run.notes())
    assert seen is None  # the light model said the lane follows the hint: the alert came down
    hint_events = [a for a in lane.actions if a.text == AlertKind.HINT.label]
    assert hint_events, "the rules' alert went up first, before the light model answered"
    (first, *_) = spends(run.log.path)
    assert first["data"]["why"] == "the hint judge (openai light/m)" and first["data"]["model"] == "light/m"
    assert first["data"]["tokens"] == 201 and first["data"]["dollars"] == 0.0002
    assert judge.requests[0]["json"]["model"] == "light/m"


def test_a_light_model_that_fails_leaves_the_alert_up_and_the_run_says_so_once(tmp_path):
    def settled(run, lane, judge):
        alert = lane.alert(AlertKind.HINT)
        return asked(judge) >= 1 and alert is not None and "Not confirmed" in alert.reason

    run, lane, seen, judge = play(tmp_path, [error_reply(500, "light model down")] * 20, settled)
    assert seen is not None and "failed to judge it" in seen.reason
    warned = [e for e in run.deck.events if e.kind is EventKind.WARNING and e.data.get("source") == "light"]
    assert len(warned) == 1 and "The rules' answer stands" in warned[0].text
    assert lane.turns >= 5  # the lane never waited for the light model


def test_without_a_light_table_a_run_has_no_judge(tmp_path):
    with FakeModelServer(responder=lane_loops) as lanes:
        run = prepare_run(RunOptions(board=board(tmp_path), config=config(tmp_path, lanes.base_url, "")))
        assert run.watch.judge is None and not any("light model" in n for n in run.notes())
        asyncio.run(run.shutdown())
        run.close()


def test_a_light_model_that_cannot_be_made_does_not_stop_the_run(tmp_path, monkeypatch):
    monkeypatch.delenv("FLIGHTDECK_LIGHT_TEST_KEY", raising=False)
    with FakeModelServer(responder=lane_loops) as lanes:
        light = '[light]\nengine = "anthropic"\nmodel = "claude-haiku-5-5"\nkey_env = "FLIGHTDECK_LIGHT_TEST_KEY"\n'
        run = prepare_run(RunOptions(board=board(tmp_path), config=config(tmp_path, lanes.base_url, light)))
        assert run.watch.judge is None
        (note,) = [n for n in run.notes() if "light model" in n]
        assert "the light model is off for this run" in note and "FLIGHTDECK_LIGHT_TEST_KEY" in note
        asyncio.run(run.shutdown())
        run.close()
