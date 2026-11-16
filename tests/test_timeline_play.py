"""`play --waves`, `--timeline` and `--speed` (P99): a folder board released wave by wave on its
timeline, by a real run against the fake model server, on host workspaces in tmp_path. The
deck's clock is one the test moves, so no test waits for a wave's real time."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from ctf_flightdeck import cli
from ctf_flightdeck.core.model import EventKind
from ctf_flightdeck.run import RunError, RunOptions, _timeline, prepare_run

from fake_model import FakeModelServer, tool_call_reply
from test_run import config, wait_for

# id: points; the timeline puts bravo out at 10 minutes and charlie at 2 hours
CHALLENGES = {"alpha": 50, "bravo": 100, "charlie": 200}
WAVES = {"waves": [{"at": 600, "ids": ["bravo"]}, {"at": 7200, "ids": ["charlie"]}]}


def make_board(tmp_path: Path, *, timeline: dict | str | None = WAVES, answers: bool = True) -> Path:
    root = tmp_path / "board"
    for cid, points in CHALLENGES.items():
        (root / cid).mkdir(parents=True)
        (root / cid / "notes.txt").write_text("synthetic handout\n")
        (root / cid / "challenge.json").write_text(json.dumps({"name": cid.title(), "category": "misc", "points": points}))
    (root / "board.json").write_text(json.dumps({"event": "Timeline Event", "flag_format": r"t\{[a-z0-9_]+\}"}))
    if answers:
        (root / "answers.sha256.json").write_text(json.dumps({cid: "0" * 64 for cid in CHALLENGES}))
    if timeline is not None:
        (root / "timeline.json").write_text(timeline if isinstance(timeline, str) else json.dumps(timeline))
    return root


class Clock:
    """The deck's clock, at whatever time the test sets."""

    def __init__(self, t: float = 0.0) -> None:
        self.t = t

    def now(self) -> float:
        return self.t


def idle_server() -> FakeModelServer:
    """Every lane runs a long sleep, so it holds its slot and spends nothing more."""
    return FakeModelServer(responder=lambda request: tool_call_reply("shell", {"command": "sleep 240", "timeout_seconds": 300}))


def released(run) -> list[list[str]]:
    return [event.data["challenges"] for event in run.deck.events if event.kind is EventKind.RELEASE]


def fly(run, clock: Clock, steps) -> None:
    """Release the run's board, then for each (time, check): move the deck's clock to `time`
    and wait until `check(run)` holds; then shut the run down and close it."""

    async def main() -> None:
        try:
            run.release()
            for at, check, what in steps:
                clock.t = at
                await wait_for(lambda: check(run), what)
        finally:
            await run.shutdown()

    try:
        asyncio.run(main())
    finally:
        run.close()


def test_play_with_waves_releases_the_board_on_its_timeline_by_the_decks_clock(tmp_path):
    with idle_server() as server:
        run = prepare_run(RunOptions(board=make_board(tmp_path), config=config(tmp_path, server.base_url), waves=True,
                                     max_lanes=3, replay_seconds=0.01))
        clock = run.deck.clock = Clock(5.0)  # the board is released 5 s into the run: the waves count from then
        assert any(note.startswith("timeline: the board goes out in 3 waves from the board's timeline.json: "
                                   "the first at the start, the last 2h00 after it") for note in run.notes()), run.notes()
        early = []

        def at_604(run) -> bool:  # looked at 20 times, 0.01 s apart: the timeline's task ticks between them
            early.append("bravo" in run.deck.challenges)
            return len(early) >= 20

        fly(run, clock, [
            (5.0, lambda run: released(run) == [["alpha"]], "the first wave"),
            (604.9, at_604, "the clock just before the second wave"),
            (605.0, lambda run: released(run) == [["alpha"], ["bravo"]], "the second wave at 5 + 600 s"),
            (7205.0, lambda run: released(run) == [["alpha"], ["bravo"], ["charlie"]], "the last wave"),
        ])
    assert early == [False] * 20
    lines = [event.text for event in run.deck.events if event.kind is EventKind.RELEASE]
    assert lines[0].startswith("Wave 1 of 3: 1 challenge · 1 lane started") and lines[0].endswith(
        "next: Wave 2 of 3 at T+00:10:05 (1 challenge)"), lines[0]
    assert {lane.challenge_id for lane in run.deck.lanes.values()} == set(CHALLENGES)  # each wave queued and started


def test_speed_plays_the_timeline_that_many_times_as_fast(tmp_path):
    with idle_server() as server:
        run = prepare_run(RunOptions(board=make_board(tmp_path), config=config(tmp_path, server.base_url), waves=True,
                                     speed=60, max_lanes=3, replay_seconds=0.01))
        clock = run.deck.clock = Clock(0.0)
        assert any(", 60 times as fast as the event: the first at the start, the last 2m after it" in note
                   for note in run.notes()), run.notes()
        fly(run, clock, [
            (10.0, lambda run: released(run) == [["alpha"], ["bravo"]], "the wave at 600 s, at 600 / 60"),
            (120.0, lambda run: len(released(run)) == 3, "the wave at 7200 s, at 7200 / 60"),
        ])


def test_a_named_timeline_file_wins_over_the_boards(tmp_path):
    elsewhere = tmp_path / "replay.json"
    elsewhere.write_text(json.dumps({"waves": [{"at": 30, "ids": ["alpha", "charlie"]}]}))
    with idle_server() as server:
        run = prepare_run(RunOptions(board=make_board(tmp_path), config=config(tmp_path, server.base_url),
                                     timeline=elsewhere, max_lanes=3, replay_seconds=0.01))
        clock = run.deck.clock = Clock(0.0)
        assert any(f"from {elsewhere}:" in note for note in run.notes()), run.notes()
        fly(run, clock, [
            (0.0, lambda run: released(run) == [["bravo"]], "the challenges no wave lists, at the start"),
            (30.0, lambda run: released(run) == [["bravo"], ["alpha", "charlie"]], "the named file's wave"),
        ])


def test_without_waves_the_whole_board_goes_out_at_the_start_whatever_its_timeline_says(tmp_path):
    with idle_server() as server:
        run = prepare_run(RunOptions(board=make_board(tmp_path), config=config(tmp_path, server.base_url), max_lanes=3))
        clock = run.deck.clock = Clock(0.0)
        assert not any(note.startswith("timeline:") for note in run.notes())
        fly(run, clock, [(0.0, lambda run: released(run) == [list(CHALLENGES)], "the whole board")])


def test_a_timeline_of_one_wave_says_the_whole_board_goes_out_at_the_start(tmp_path):
    with FakeModelServer() as server:
        run = prepare_run(RunOptions(board=make_board(tmp_path, timeline={"waves": []}),
                                     config=config(tmp_path, server.base_url), waves=True))
        run.close()
    assert "timeline: the board's timeline.json has one wave, so the whole board goes out at the start" in run.notes()


@pytest.mark.parametrize(
    "timeline, options, expected",
    [
        (None, {"waves": True}, r"--waves: .*board/timeline\.json: no such file, so the board has no timeline to release it on"),
        ('{"waves": [{"at": 60, "ids": ["zulu"]}]}', {"waves": True},
         r'--waves: .*timeline\.json: "waves"\[0\] names challenges that are not on the board: "zulu"'),
        ("not json", {"waves": True}, r"--waves: .*timeline\.json: is not valid JSON"),
        (WAVES, {"speed": 60}, r"--speed plays a board's timeline faster or slower: give it with --waves"),
        (WAVES, {"waves": True, "speed": 0}, r"--speed must be a number above 0"),
        (WAVES, {"waves": True, "speed": float("nan")}, r"--speed must be a number above 0"),
        (WAVES, {"timeline": Path("/nonexistent/replay.json")}, r"--timeline: /nonexistent/replay\.json: no such file"),
    ],
)
def test_a_timeline_the_run_cannot_use_stops_it_before_anything_starts_and_says_why(tmp_path, timeline, options, expected):
    with FakeModelServer() as server:
        with pytest.raises(RunError, match=expected):
            prepare_run(RunOptions(board=make_board(tmp_path, timeline=timeline), config=config(tmp_path, server.base_url),
                                   **options))
        assert server.requests == []  # refused before the model API was asked anything
    assert not (tmp_path / "runs").exists()  # and before a run folder was made


@pytest.mark.parametrize("platform", ["ctfd", "gamemaster", "http", "myplatform"])
def test_an_event_whose_platform_puts_out_its_own_challenges_refuses_a_timeline(tmp_path, platform):
    with pytest.raises(RunError, match=f"--waves replays a folder board's timeline, but this event's board comes from {platform}"):
        _timeline(RunOptions(waves=True), SimpleNamespace(platform=platform), None, [])


def test_a_by_hand_event_takes_a_timeline(tmp_path):
    from ctf_flightdeck.platform.manual import load_board

    notes: list[str] = []
    board = load_board(make_board(tmp_path))
    timeline = _timeline(RunOptions(waves=True), SimpleNamespace(platform="manual"), board, notes)
    assert [wave.ids for wave in timeline.waves] == [("alpha",), ("bravo",), ("charlie",)] and notes


def test_a_folder_of_a_later_wave_touched_on_a_board_you_fill_waits_for_its_wave(tmp_path):
    root = make_board(tmp_path, answers=False)  # no answers: a board the player fills, whose folder the run watches
    with idle_server() as server:
        run = prepare_run(RunOptions(board=root, config=config(tmp_path, server.base_url), waves=True, max_lanes=3,
                                     replay_seconds=0.01))
        clock = run.deck.clock = Clock(0.0)
        assert run.by_hand

        def touched_then_scanned(run) -> bool:
            spec = root / "bravo" / "challenge.json"
            spec.write_text(spec.read_text())  # its challenge.json written again: a new mtime
            run._folders["bravo"] = -1.0  # as if the folder watch had not seen it yet
            return run.scan_board() == [] and "bravo" not in run.deck.challenges

        fly(run, clock, [
            (0.0, lambda run: released(run) == [["alpha"]], "the first wave"),
            (1.0, touched_then_scanned, "the folder watch to leave bravo to its wave"),
            (600.0, lambda run: released(run) == [["alpha"], ["bravo"]], "bravo, in its own wave"),
        ])
    assert not [event for event in run.deck.events if event.kind is EventKind.WARNING and "bravo" in event.text]


def test_play_passes_waves_timeline_and_speed_to_the_run_and_a_bad_one_exits_2_with_the_reason(tmp_path, monkeypatch):
    seen: list[RunOptions] = []

    def refuse(options: RunOptions):
        seen.append(options)
        raise RunError("stopped by the test")

    monkeypatch.setattr("ctf_flightdeck.run.prepare_run", refuse)
    root = make_board(tmp_path)
    replay_file = tmp_path / "replay.json"
    replay_file.write_text(json.dumps(WAVES))
    result = CliRunner().invoke(cli.app, ["play", str(root), "--timeline", str(replay_file), "--speed", "60"])
    assert result.exit_code == 2 and "stopped by the test" in result.output
    assert (seen[0].waves, seen[0].timeline, seen[0].speed) == (False, replay_file, 60.0)
    result = CliRunner().invoke(cli.app, ["play", str(root), "--waves"])
    assert (seen[1].waves, seen[1].timeline, seen[1].speed) == (True, None, 1.0)


def test_play_with_speed_and_no_timeline_exits_2_and_says_what_speed_needs(tmp_path):
    with FakeModelServer() as server:
        result = CliRunner().invoke(cli.app, ["play", str(make_board(tmp_path)), "--speed", "60",
                                              "--config", str(config(tmp_path, server.base_url))])
    assert result.exit_code == 2, result.output
    assert "flightdeck: --speed plays a board's timeline faster or slower: give it with --waves" in result.output
