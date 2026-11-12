"""`latest` in place of a run folder: the newest run under the config's [run] dir, by when each
run started; what is really there under that name wins; the command says which folder it took."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ctf_flightdeck import cli
from ctf_flightdeck.config import ConfigError
from ctf_flightdeck.runrecord import (
    RunFolderError, asks_latest, latest_run, resolve_run, run_folder, run_started,
)
from test_runrecord import make_run

runner = CliRunner()
OLD, NEW = "2026-03-01T09:00:00.000+00:00", "2026-03-02T09:00:00.000+00:00"


def config_file(tmp_path: Path, runs: Path) -> Path:
    """A config whose API key variable is not set: `latest` reads [run] dir, never a key."""
    path = tmp_path / "config.toml"
    path.write_text(
        '[api]\nbase_url = "http://127.0.0.1:9/v1"\nkey_env = "FLIGHTDECK_TEST_KEY_THAT_IS_NOT_SET"\n\n'
        f'[models]\nladder = ["fake/model"]\n\n[run]\ndir = "{runs}"\n'
    )
    return path


def log_only(folder: Path, wall: object = None, *, first: str | None = None) -> Path:
    """A folder with an events.jsonl whose first line is a run-start line at `wall` (or `first`, as it is)."""
    folder.mkdir(parents=True)
    line = first if first is not None else json.dumps({"kind": "run-start", "wall": wall, "version": "0", "format": 2})
    (folder / "events.jsonl").write_text(line + "\n" + json.dumps({"kind": "run-end", "wall": "2027-01-01T00:00:00+00:00"}) + "\n")
    return folder


def started_at(folder: Path, wall: str) -> Path:
    """A real run's folder (make_run), its run-start line rewritten to say it started at `wall`."""
    log = folder / "events.jsonl"
    lines = log.read_text().splitlines()
    first = json.loads(lines[0])
    assert first["kind"] == "run-start"
    log.write_text("\n".join([json.dumps({**first, "wall": wall}), *lines[1:]]) + "\n")
    return folder


def said(lines: list[str]):
    return lines.append


@pytest.fixture
def runs(tmp_path) -> Path:
    folder = tmp_path / "runs"
    folder.mkdir()
    return folder


@pytest.fixture
def two_runs(tmp_path, runs, monkeypatch):
    """Two real runs. The one that started first has the later name and the later modification
    time, so only the run-start time picks the right one. Returns (config, older, newer)."""
    older, newer = runs / "zz-started-first", runs / "aa-started-last"
    for folder, wall in ((newer, NEW), (older, OLD)):
        folder.mkdir()
        make_run(folder)
        started_at(folder, wall)
    later = datetime(2030, 1, 1, tzinfo=timezone.utc).timestamp()
    os.utime(older, (later, later))
    os.utime(older / "events.jsonl", (later, later))
    monkeypatch.chdir(tmp_path)  # no folder named latest here
    return config_file(tmp_path, runs), older, newer


# ---------------------------------------------------------------------- the resolver


def test_latest_is_the_run_that_started_last_not_the_last_modified_or_the_last_by_name(two_runs, runs):
    config, older, newer = two_runs
    lines: list[str] = []
    assert resolve_run(Path("latest"), say=said(lines), config=config) == newer
    assert lines == [f"run: {newer} (latest: the newest of 2 runs in {runs})"]
    started_at(older, "2026-03-03T09:00:00.000+00:00")  # now the other one started last
    assert resolve_run("latest", say=said(lines), config=config) == older


def test_run_start_times_are_compared_as_instants_and_one_without_a_zone_is_utc(tmp_path, runs):
    a = log_only(runs / "a", "2026-03-02T10:00:00+02:00")  # 08:00 UTC
    b = log_only(runs / "b", "2026-03-02T08:30:00")  # 08:30 UTC, written without a zone
    c = log_only(runs / "c", "2026-03-02T03:45:00-05:00")  # 08:45 UTC
    assert run_started(a) == datetime(2026, 3, 2, 8, 0, tzinfo=timezone.utc)
    assert run_started(b) == datetime(2026, 3, 2, 8, 30, tzinfo=timezone.utc)
    assert latest_run(say=lambda line: None, config=config_file(tmp_path, runs)) == c


def test_runs_that_started_at_the_same_time_give_the_last_by_name(tmp_path, runs):
    for name in ("b", "c", "a"):
        log_only(runs / name, NEW)
    assert latest_run(say=lambda line: None, config=config_file(tmp_path, runs)) == runs / "c"


def test_an_empty_runs_folder_fails_in_one_line_naming_it_and_the_config(tmp_path, runs, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = config_file(tmp_path, runs)
    (runs / "not-a-run").mkdir()  # a folder without an events.jsonl is not a run
    (runs / "events.jsonl").write_text("{}\n")  # nor is a log lying in the runs folder itself
    lines: list[str] = []
    with pytest.raises(RunFolderError) as caught:
        resolve_run(Path("latest"), say=said(lines), config=config)
    assert str(caught.value) == f"latest: no run in {runs} ([run] dir in {config}): no folder there holds an events.jsonl"
    assert "\n" not in str(caught.value) and lines == []


def test_a_runs_folder_that_is_not_there_yet_fails_in_one_line(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = config_file(tmp_path, tmp_path / "never-made")
    with pytest.raises(RunFolderError) as caught:
        resolve_run(Path("latest"), say=pytest.fail, config=config)
    assert str(caught.value) == (
        f"latest: there is no runs folder {tmp_path / 'never-made'} ([run] dir in {config}) yet: no run has been written there"
    )


@pytest.mark.parametrize("first", [
    json.dumps({"kind": "release", "wall": NEW}),  # the log lost its run-start line
    json.dumps({"kind": "run-start"}),  # no time
    json.dumps({"kind": "run-start", "wall": "yesterday"}),
    json.dumps({"kind": "run-start", "wall": 1772442000}),
    "not json",
    "[]",
    json.dumps({"kind": "run-start", "wall": NEW, "pad": "x" * 70_000}),  # no run writes a first line this long
])
def test_a_run_whose_log_does_not_say_when_it_started_is_left_out_and_named(tmp_path, runs, first):
    good = log_only(runs / "good", OLD)
    odd = log_only(runs / "odd\x1b[31m", first=first)
    assert run_started(odd) is None
    lines: list[str] = []
    assert latest_run(say=said(lines), config=config_file(tmp_path, runs)) == good
    assert lines == [
        f"run: {good} (latest: the newest of 1 run in {runs}); left out, with no run-start time in its events.jsonl: odd^[[31m"
    ]
    assert "\x1b" not in lines[0]  # a folder's name is shown made visible


def test_when_no_run_says_when_it_started_latest_fails_rather_than_guess(tmp_path, runs):
    log_only(runs / "a", first="{}")
    log_only(runs / "b", first="{}")
    config = config_file(tmp_path, runs)
    with pytest.raises(RunFolderError) as caught:
        latest_run(say=pytest.fail, config=config)
    assert str(caught.value) == (
        f"latest: no run in {runs} ([run] dir in {config}) says when it started: 2 folders there with an events.jsonl, "
        "none with a run-start line and its time; name the run folder"
    )


def test_a_folder_really_named_latest_wins_and_the_config_is_not_read(two_runs, tmp_path):
    here = tmp_path / "latest"
    here.mkdir()
    make_run(here)
    assert not asks_latest(Path("latest"))
    missing = tmp_path / "no-such-config.toml"  # reading it would raise
    assert resolve_run(Path("latest"), say=pytest.fail, config=missing) == Path("latest")


def test_a_file_named_latest_is_taken_as_the_path_it_is(two_runs, tmp_path):
    config, _, _ = two_runs
    (tmp_path / "latest").write_text("")
    with pytest.raises(RunFolderError, match="latest: not a run folder"):
        resolve_run(Path("latest"), say=pytest.fail, config=config)


def test_only_the_bare_word_asks_for_the_newest_run(two_runs, tmp_path):
    config, _, newer = two_runs
    for arg in ("Latest", "latest.", "runs/latest", str(tmp_path / "latest")):
        assert not asks_latest(Path(arg))
        with pytest.raises(RunFolderError, match="no such run folder"):
            resolve_run(Path(arg), say=pytest.fail, config=config)
    assert asks_latest("latest") and asks_latest(Path("latest"))
    assert resolve_run(newer, say=pytest.fail, config=config) == run_folder(newer) == newer  # a path is a path, unsaid
    assert resolve_run(newer / "events.jsonl", say=pytest.fail, config=config) == newer


def test_latest_without_a_config_fails_naming_the_file_and_never_guesses_a_runs_folder(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FLIGHTDECK_CONFIG", str(tmp_path / "nowhere" / "config.toml"))
    with pytest.raises(ConfigError, match="no config file yet") as caught:
        resolve_run(Path("latest"), say=pytest.fail)
    assert str(tmp_path / "nowhere" / "config.toml") in str(caught.value)


def test_latest_reads_the_config_the_environment_names(two_runs, monkeypatch):
    config, _, newer = two_runs
    monkeypatch.setenv("FLIGHTDECK_CONFIG", str(config))
    assert resolve_run(Path("latest"), say=lambda line: None) == newer


# ---------------------------------------------------------------------- the four commands


def board(tmp_path: Path) -> Path:
    """The board make_run plays: a (50) and b (100)."""
    folder = tmp_path / "board"
    for cid, name, category, points in (("a", "Alpha", "misc", 50), ("b", "Beta", "web", 100)):
        (folder / cid).mkdir(parents=True)
        (folder / cid / "challenge.json").write_text(json.dumps({"name": name, "category": category, "points": points}))
    (folder / "board.json").write_text(json.dumps({"event": "t", "flag_format": r"t\{\w+\}"}))
    return folder


def files(folder: Path) -> set[str]:
    return {str(path.relative_to(folder)) for path in folder.rglob("*")}


@pytest.mark.parametrize(("command", "written"), [
    ("report", {"report.md"}),
    ("gaps", {"gaps.md", "gaps.json"}),
    ("writeups", {"writeups", "writeups/a.md"}),
])
def test_report_gaps_and_writeups_take_latest_say_the_folder_and_write_only_there(two_runs, runs, command, written):
    config, older, newer = two_runs
    before_old, before_new = files(older), files(newer)
    result = runner.invoke(cli.app, [command, "latest", "--config", str(config)])
    assert result.exit_code == 0, result.output
    assert result.stderr.splitlines()[0] == f"flightdeck: run: {newer} (latest: the newest of 2 runs in {runs})"
    assert files(newer) - before_new == written
    assert files(older) == before_old  # the run that started first is not touched, for all its later mtime


def test_score_takes_latest_and_says_the_folder(two_runs, runs, tmp_path):
    config, older, newer = two_runs
    (older / "events.jsonl").write_text((older / "events.jsonl").read_text().splitlines()[0] + "\n")  # an older run with no solve
    by_word = runner.invoke(cli.app, ["score", "latest", "--board", str(board(tmp_path)), "--config", str(config)])
    assert by_word.exit_code == 0, by_word.output
    assert by_word.stderr.splitlines() == [f"flightdeck: run: {newer} (latest: the newest of 2 runs in {runs})"]
    by_path = runner.invoke(cli.app, ["score", str(newer), "--board", str(tmp_path / "board")])
    assert by_word.stdout == by_path.stdout and by_word.stdout.startswith("t: solved 1 of 2 · 50 of 150 points\n")
    assert by_path.stderr == ""  # a folder the player named is not announced
    assert runner.invoke(cli.app, ["score", str(older), "--board", str(tmp_path / "board")]).stdout != by_word.stdout


def test_share_takes_latest_says_the_folder_and_writes_nothing(two_runs, runs):
    config, older, newer = two_runs
    before = files(newer)
    result = runner.invoke(cli.app, ["share", "latest", "--config", str(config)])
    assert result.exit_code == 0, result.output
    assert result.stderr.splitlines()[0] == f"flightdeck: run: {newer} (latest: the newest of 2 runs in {runs})"
    assert result.stdout.startswith("flightdeck flight card\n")
    assert files(newer) == before


@pytest.mark.parametrize("command", ["report", "gaps", "writeups", "score", "share"])
def test_each_command_fails_in_one_named_line_on_an_empty_runs_folder(tmp_path, runs, monkeypatch, command):
    monkeypatch.chdir(tmp_path)
    config = config_file(tmp_path, runs)
    result = runner.invoke(cli.app, [command, "latest", "--config", str(config)])
    assert result.exit_code == 2
    assert result.stderr == f"flightdeck: latest: no run in {runs} ([run] dir in {config}): no folder there holds an events.jsonl\n"
    assert result.stdout == ""


@pytest.mark.parametrize("command", ["report", "gaps", "writeups", "score"])
def test_each_command_reads_the_config_the_environment_names_and_fails_loudly_without_one(two_runs, runs, tmp_path, monkeypatch, command):
    config, _, newer = two_runs
    extra = ["--board", str(board(tmp_path))] if command == "score" else []
    monkeypatch.setenv("FLIGHTDECK_CONFIG", str(config))
    result = runner.invoke(cli.app, [command, "latest", *extra])
    assert result.exit_code == 0, result.output
    assert f"flightdeck: run: {newer} (latest: the newest of 2 runs in {runs})" in result.stderr.splitlines()
    monkeypatch.setenv("FLIGHTDECK_CONFIG", str(tmp_path / "gone.toml"))
    result = runner.invoke(cli.app, [command, "latest", *extra])
    assert result.exit_code == 2 and result.stdout == ""
    assert result.stderr.startswith(f"flightdeck: {tmp_path / 'gone.toml'}: no config file yet.") and result.stderr.count("\n") == 1


@pytest.mark.parametrize("command", ["report", "gaps", "writeups", "score"])
def test_each_command_takes_a_folder_really_named_latest_and_does_not_announce_it(two_runs, tmp_path, command):
    config, older, newer = two_runs
    here = tmp_path / "latest"
    here.mkdir()
    make_run(here)
    before = files(older), files(newer)
    extra = ["--board", str(board(tmp_path))] if command == "score" else []
    result = runner.invoke(cli.app, [command, "latest", "--config", str(tmp_path / "no-such-config.toml"), *extra])
    assert result.exit_code == 0, result.output
    assert "flightdeck: run:" not in result.stderr
    assert (files(older), files(newer)) == before
    if command != "score":
        assert files(here) - {"events.jsonl", "lanes", "lanes/L01.jsonl", "lanes/L02.jsonl"}  # it wrote there


@pytest.mark.parametrize("command", ["report", "gaps"])
def test_a_path_that_is_not_there_still_fails_with_the_reason(tmp_path, command):
    result = runner.invoke(cli.app, [command, str(tmp_path / "nope")])
    assert result.exit_code == 2
    assert result.stderr == f"flightdeck: {tmp_path / 'nope'}: no such run folder or events.jsonl\n"
