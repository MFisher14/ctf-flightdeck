"""`flightdeck share`: the flight card of a run. It is made to be posted in public, so the
tests check what it says and, as carefully, what it never holds."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ctf_flightdeck import cli
from ctf_flightdeck.config import ApiConfig, Config, LaneConfig, LightConfig
from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.model import DeckConfig
from ctf_flightdeck.platform.manual import load_board
from ctf_flightdeck.practice_set import practice_dir
from ctf_flightdeck.run import RunOptions, _setup, api_kind
from ctf_flightdeck.runrecord import RunFolderError, read_run_setup, write_run_setup
from ctf_flightdeck.share import APPROVE_ONLY, HANDS_OFF, HANDS_ON, card, category, mode
from ctf_flightdeck.postflight import analyse
from test_postflight import BOARD, FLAGS, Script, play, write_board

SETUP = {
    "runtime": "docker", "max_lanes": 8, "submit": "confirm", "lanes": "flightdeck", "api": "OpenRouter",
    "fallback": "", "ladder": ["small", "big"], "fast": [], "light": [], "l1_engines": 2, "team": True,
    "board": "folder", "token_cap": 400_000, "dollar_cap": 2.0,
}


def lines(text: str) -> dict[str, str]:
    """The card's `key: value` lines."""
    return dict(line.split(": ", 1) for line in text.splitlines() if ": " in line and not line.startswith("  "))


@pytest.fixture
def played(tmp_path):
    return play(tmp_path)


def test_the_card_says_what_ran_and_how_it_went(played):
    _, record = played
    said = lines(card(record, SETUP, version="9.9.9"))
    assert said["flightdeck"] == "9.9.9"
    assert said["board"] == "a folder board (9 challenges)"
    assert said["setup"] == "docker, 8 lanes at once, submit confirm"
    assert said["lanes"].startswith("flightdeck's own lanes on OpenRouter")
    assert said["ladder"] == "small > big"
    assert said["L1 pack"] == "2 engines"
    assert said["lane caps"] == "400k tokens or $2.00"
    # alpha, bravo (L1), charlie and delta by this run; golf by a teammate
    assert said["solved"] == "5 of 9 (lanes 3, L1 1, outside the lanes 1)"
    assert said["by category"] == "cry 1/1, for 0/1, misc 2/2, pwn 0/1, rev 1/1, web 1/3"
    assert said["time"] == "28m for the run"


def test_the_spend_is_the_reports_and_each_model_has_its_row(played):
    _, record = played
    text = card(record, SETUP)
    flight = analyse(record)
    dollars, unpriced = flight.dollars
    assert not unpriced
    assert f"spend: 45k tokens, 25% cached, ${dollars:.2f}" in text
    rows = [line.strip() for line in text.splitlines() if line.startswith("  ")]
    assert [row.split(":")[0] for row in rows] == ["small", "big"]
    assert rows[0].endswith("1 lane solve")  # alpha, on small
    assert rows[1].endswith("2 lane solves")  # delta's fork and the escalated charlie, on big
    assert f"cost per lane solve: ${dollars / 3:.2f}" in text


def test_the_card_counts_what_the_player_did_and_calls_the_run_hands_on(played):
    _, record = played
    said = lines(card(record, SETUP))
    assert said["you approved or declined"] == "5 approved"
    # the hint to the finished lane was refused, so it is not counted
    assert said["you steered"] == "1 escalate, 1 fork, 1 hint, 1 kill, 1 redirect"
    assert said["mode"].startswith(HANDS_ON)


def approve_only_run(folder: Path):
    board = load_board(write_board(folder / "board"))
    run = Script(folder / "run", flags=FLAGS)
    run.release([b.challenge for b in board.challenges], ["alpha"])
    lane = run.lane("alpha")
    run.at(10)
    run.turn(lane, "base64 -d note", flag="t{alpha}")
    return run, lane


def test_a_run_where_the_player_only_approved_is_approve_only(tmp_path):
    run, lane = approve_only_run(tmp_path)
    run.at(20)
    run.do(iv.Approve(lane))
    record = run.close()
    assert mode(analyse(record)) == APPROVE_ONLY
    assert lines(card(record, SETUP))["you steered"] == "nothing"


def test_a_run_nobody_touched_is_hands_off(tmp_path):
    run, _ = approve_only_run(tmp_path)
    record = run.close()
    assert mode(analyse(record)) == HANDS_OFF
    assert lines(card(record, SETUP))["you approved or declined"] == "nothing"


def test_the_card_holds_no_flag_no_challenge_name_or_id_no_event_and_no_path(played, tmp_path):
    _, record = played
    text = card(record, SETUP, version="9.9.9").lower()
    for cid, name, _, _ in BOARD:
        assert cid not in text, f"the challenge {cid} is on the card"
    for flag in (*FLAGS.values(), "t{nope}"):
        assert flag.lower() not in text
    assert "t{" not in text
    assert "test ctf" not in text and "wren" not in text  # the event, a teammate's handle
    assert str(tmp_path).lower() not in text
    assert "decode the base64" not in text  # a hint's own words


def test_a_boards_own_category_name_stays_off_the_card(tmp_path):
    folder = tmp_path / "board"
    folder.mkdir()
    (folder / "one").mkdir()
    (folder / "one" / "challenge.json").write_text(json.dumps({"name": "One", "category": "Secret Sauce 2026", "points": 10}))
    board = load_board(folder)
    run = Script(tmp_path / "run")
    run.release([b.challenge for b in board.challenges])
    text = card(run.close(), SETUP)
    assert "secret sauce" not in text.lower()
    assert lines(text)["by category"] == "other 0/1"
    assert category("Crypto") == "cry" and category("Secret Sauce 2026") == "other"


def test_a_run_without_a_setup_record_says_so_and_still_gives_the_numbers(played):
    _, record = played
    said = lines(card(record, None))
    assert said["setup"].startswith("not recorded")
    assert said["solved"].startswith("5 of 9")


def test_what_a_lane_wrote_into_the_setup_file_cannot_reach_the_terminal_or_run_on(played):
    _, record = played
    setup = dict(SETUP, ladder=["small\x1b[31m\nmode: hands-off", "x" * 500], runtime=["not", "text"], max_lanes="many")
    text = card(record, setup)
    assert "\x1b" not in text
    assert sum(line.startswith("mode: ") for line in text.splitlines()) == 1  # the injected line is not a line
    assert "x" * 100 not in text
    assert lines(text)["setup"].startswith("unknown runtime, submit confirm")


# ---------------------------------------------------------------------- the setup record


def config(**api) -> Config:
    return Config(
        api=ApiConfig(**api), models=("small", "big"), prices={}, lanes=LaneConfig(), run_dir=Path("/nowhere"), source=None,
    )


def test_the_setup_names_models_and_settings_and_no_address_key_or_path(tmp_path):
    cfg = config(base_url="https://llm.corp.internal.test/v1", key_env="CORP_KEY")
    deck = DeckConfig(event="Some Event", containerized=False, max_lanes=3, submit="auto", models=cfg.models)
    setup = _setup(cfg, RunOptions(board=tmp_path), deck, cfg.models, agent=None, ctfd=False, engines=0)
    assert setup["runtime"] == "host" and setup["max_lanes"] == 3 and setup["submit"] == "auto"
    assert setup["ladder"] == ["small", "big"] and setup["api"] == "another API" and setup["board"] == "folder"
    dumped = json.dumps(setup)
    for private in ("corp.internal", "CORP_KEY", "Some Event", str(tmp_path)):
        assert private not in dumped


def test_the_setup_knows_the_practice_set_a_ctfd_event_a_coding_agent_and_the_light_model(tmp_path):
    cfg = config()
    deck = DeckConfig(event="e", models=cfg.models)
    assert _setup(cfg, RunOptions(board=practice_dir()), deck, cfg.models, agent=None, ctfd=False, engines=0)["board"] == "practice"
    agent = _setup(cfg, RunOptions(board=tmp_path), deck, ("sonnet", "opus"), agent="claude", ctfd=True, engines=4)
    assert agent["board"] == "ctfd" and agent["lanes"] == "claude" and agent["api"] == "" and agent["l1_engines"] == 4
    lit = Config(
        api=ApiConfig(), models=("small",), prices={}, lanes=LaneConfig(), run_dir=Path("/nowhere"), source=None,
        light=LightConfig(engine="openai", model="tiny", base_url="http://127.0.0.1:11434/v1"),
    )
    light = _setup(lit, RunOptions(board=tmp_path), deck, lit.models, agent=None, ctfd=False, engines=0)["light"]
    assert light == [{"engine": "openai", "model": "tiny", "jobs": ["judge"], "api": "a server on this machine"}]


@pytest.mark.parametrize(
    "url, kind",
    [
        ("https://api.anthropic.com", "the Anthropic API"),
        ("https://openrouter.ai/api/v1", "OpenRouter"),
        ("http://127.0.0.1:11434/v1", "a server on this machine"),
        ("https://models.example.test/v1", "another API"),
    ],
)
def test_an_api_is_named_by_kind_never_by_address(url, kind):
    assert api_kind(url) == kind


def test_the_setup_file_is_written_once_and_read_back_or_refused_with_the_reason(tmp_path):
    assert read_run_setup(tmp_path) is None  # an older run
    write_run_setup(tmp_path, SETUP)
    assert read_run_setup(tmp_path) == SETUP
    with pytest.raises(FileExistsError):
        write_run_setup(tmp_path, SETUP)
    (tmp_path / "setup.json").write_text("[1, 2]")
    with pytest.raises(RunFolderError, match="not a JSON object"):
        read_run_setup(tmp_path)


# ---------------------------------------------------------------------- the command


def test_share_prints_the_card_to_stdout_and_where_to_post_it_to_stderr(played):
    _, record = played
    write_run_setup(record.dir, SETUP)
    result = CliRunner().invoke(cli.app, ["share", str(record.dir), "--name", "Practice night"])
    assert result.exit_code == 0, result.output
    assert result.stdout.startswith("flightdeck flight card\nname: Practice night\n")
    assert "mode: hands-on" in result.stdout
    assert "issues/new?template=flight-card.yml" in result.stderr
    assert "issues/new" not in result.stdout  # the card alone is on stdout: `share > card.txt` holds only it


def test_share_on_a_folder_that_is_no_run_fails_in_one_line(tmp_path):
    result = CliRunner().invoke(cli.app, ["share", str(tmp_path)])
    assert result.exit_code == 2
    assert result.stderr.startswith("flightdeck: ") and "Traceback" not in result.stderr
