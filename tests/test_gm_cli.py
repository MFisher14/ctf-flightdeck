"""`flightdeck gm pull` and `flightdeck gm list`, against the fake Game Master (tests/fake_gm.py)
on 127.0.0.1.

The commands are run in-process with Typer's CliRunner; the token reaches them only through
the environment variable --token-env names. No real platform is contacted.
"""

from __future__ import annotations

import json

from typer.testing import CliRunner

from ctf_flightdeck.platform import gamemaster_cli
from ctf_flightdeck.platform.gamemaster import DEFAULT_ANSWER_FORMAT
from ctf_flightdeck.platform.manual import load_board
from fake_gm import TOKEN, FakeAttempt, FakeGM, Reply, sample

TOKEN_VAR = "FLIGHTDECK_TEST_GM_TOKEN"
ENV = {TOKEN_VAR: TOKEN}
runner = CliRunner()


def gm(*args: str, env: dict[str, str] | None = ENV):
    return runner.invoke(gamemaster_cli.app, list(args), env=env)


def pull(fake: FakeGM, dest, *args: str, env: dict[str, str] | None = ENV):
    return gm("pull", fake.url, str(dest), "--token-env", TOKEN_VAR, *args, env=env)


def test_pull_writes_a_board_starts_nothing_and_lists_what_it_left_unstarted(tmp_path):
    dest = tmp_path / "board"
    with FakeGM(sample()) as fake:
        result = pull(fake, dest, "--event", "Fake GM")
        assert [r for r in fake.requests if r.method == "POST"] == [] and fake.starts == []
    assert result.exit_code == 0, result.output
    assert 'added who-wrote-it: "Who Wrote It" (metadata, 1 file)' in result.stdout
    assert 'added two-phones-m4-a: "Two Phones (m4-a)" (mobile, 2 files)' in result.stdout
    assert f"{dest}: 4 challenges, 4 new, 2 left unstarted" in result.stdout
    assert f"answers are submitted as {DEFAULT_ANSWER_FORMAT} (board.json's flag_format)" in result.stdout
    assert ('not started: "script-day-05" ("Obfuscated"): not started: pull with --start to start it, or start it on '
            "the Game Master, then pull again") in result.stderr
    assert ('not started: "metadata-day-01/time_trial" ("Who Wrote It"): not started, and its start runs a clock: '
            "flightdeck never starts one.") in result.stderr
    board = load_board(dest)
    assert TOKEN not in result.output and board.event == "Fake GM" and board.flag_format == DEFAULT_ANSWER_FORMAT
    assert len(board.challenges) == 4


def test_pull_with_start_starts_the_plain_attempts_and_never_the_clocked_one(tmp_path):
    dest = tmp_path / "board"
    with FakeGM(sample()) as fake:
        result = pull(fake, dest, "--start")
        assert fake.starts == ["script-day-05"] and not fake.challenges["metadata-day-01/time_trial"].started
    assert result.exit_code == 0, result.output
    assert 'started "script-day-05" ("Obfuscated")' in result.stdout
    assert f"{dest}: 5 challenges, 5 new, 1 attempt started, 1 left unstarted" in result.stdout
    assert "its start runs a clock" in result.stderr and "script-day-05" not in result.stderr
    assert (dest / "obfuscated" / "challenge.json").is_file()


def test_a_second_pull_adds_what_is_new_and_keeps_the_flag_format(tmp_path):
    dest = tmp_path / "board"
    with FakeGM(sample()) as fake:
        first = pull(fake, dest, "--flag-format", r"[0-9a-f]{8,64}")
        fake.add(FakeAttempt("web-day-20", "Proof Hunt", lane="web", started=True))
        second = pull(fake, dest)
        third = pull(fake, dest, "--flag-format", r"other\{.+\}")
    assert first.exit_code == 0 and second.exit_code == 0, second.output
    assert f"{dest}: 5 challenges, 1 new, 2 left unstarted" in second.stdout
    assert load_board(dest).flag_format == r"[0-9a-f]{8,64}"
    assert third.exit_code == 2 and "the board's flag format is" in third.stderr


def test_a_challenge_that_cannot_be_pulled_is_named_and_the_exit_status_is_1(tmp_path):
    with FakeGM(sample()) as fake:
        fake.challenges["metadata-day-01"].sha256 = {0: "f" * 64}
        result = pull(fake, tmp_path / "board")
    assert result.exit_code == 1, result.output
    assert 'not pulled: "metadata-day-01" ("Who Wrote It"): ' in result.stderr and "sha256" in result.stderr
    assert "3 challenges, 3 new" in result.stdout


def test_nothing_started_is_exit_2_and_says_how_to_start(tmp_path):
    with FakeGM([FakeAttempt("script-day-05", "Obfuscated")]) as fake:
        result = pull(fake, tmp_path / "board")
    assert result.exit_code == 2
    assert "flightdeck: none of the 1 challenge the Game Master" in result.stderr and "pull with --start" in result.stderr


def test_a_refused_token_is_exit_2_and_the_token_is_never_printed(tmp_path):
    with FakeGM(sample()) as fake:
        result = pull(fake, tmp_path / "board", env={TOKEN_VAR: "not-the-token-77"})
        assert all(r.method == "GET" for r in fake.requests)
    assert result.exit_code == 2 and "refused the token (HTTP 401)" in result.stderr
    assert "not-the-token-77" not in result.output and not any((tmp_path / "board").glob("*/challenge.json"))


def test_the_token_comes_only_from_the_variable_named(tmp_path):
    with FakeGM(sample()) as fake:
        unset = pull(fake, tmp_path / "board", env={TOKEN_VAR: ""})
        pasted = gm("pull", fake.url, str(tmp_path / "board"), "--token-env", "a-token pasted.here")
        long = gm("pull", fake.url, str(tmp_path / "board"), "--token-env", "A" * 40)
        assert fake.requests == []
    assert unset.exit_code == 2 and f"the environment variable {TOKEN_VAR} is not set or is empty" in unset.stderr
    assert pasted.exit_code == 2 and "must be the NAME of an environment variable" in pasted.stderr
    assert "a-token pasted.here" not in pasted.output
    assert long.exit_code == 2 and "A" * 40 not in long.output  # a long name may be a token pasted in its place


def test_a_bad_flag_format_or_url_is_exit_2_before_anything_is_asked(tmp_path):
    with FakeGM(sample()) as fake:
        bad_format = pull(fake, tmp_path / "board", "--flag-format", "(")
        bad_url = gm("pull", "gm.example.org", str(tmp_path / "board"), "--token-env", TOKEN_VAR)
        assert fake.requests == []
    assert bad_format.exit_code == 2 and "--flag-format does not compile" in bad_format.stderr
    assert bad_url.exit_code == 2 and "the Game Master's URL must start with http:// or https://" in bad_url.stderr


def test_list_shows_every_challenge_and_marks_the_clocked_ones_with_one_read():
    with FakeGM(sample()) as fake:
        result = gm("list", fake.url, "--token-env", TOKEN_VAR)
        assert [r.path for r in fake.requests] == ["/?op=list&all=true"]
    assert result.exit_code == 0, result.output
    lines = result.stdout.splitlines()
    assert lines[0] == "metadata-day-01  metadata  single_solve  open  Who Wrote It"
    assert "metadata-day-01/time_trial  metadata  time_trial (clocked)  open  Who Wrote It" in lines
    assert "binary-day-02  binary  single_solve  solved  Packed" in lines
    assert lines[-1] == "5 challenges, 1 solved" and TOKEN not in result.output


def test_list_shows_hostile_names_made_safe_and_a_failure_as_exit_2(monkeypatch):
    monkeypatch.setattr("ctf_flightdeck.platform.gamemaster.MAX_WAIT", 0.001)  # the retries' pauses, not the behaviour
    with FakeGM([FakeAttempt("evil-day-01", "Clear\x1b[2J the screen")]) as fake:
        shown = gm("list", fake.url, "--token-env", TOKEN_VAR)
        fake.script("GET", "list", *[Reply(503, {"error": "unavailable"}, {"Retry-After": "0"})] * 4)
        failed = gm("list", fake.url, "--token-env", TOKEN_VAR)
    assert shown.exit_code == 0 and "\x1b" not in shown.output
    assert failed.exit_code == 2 and "HTTP 503" in failed.stderr and "gave up after 4 tries" in failed.stderr


def test_the_board_folder_holds_no_token_and_no_download_capability(tmp_path):
    with FakeGM(sample()) as fake:
        assert pull(fake, tmp_path / "board").exit_code == 0
    for path in (tmp_path / "board").rglob("*.json"):
        text = path.read_text()
        assert TOKEN not in text and "capability" not in text
    assert json.loads((tmp_path / "board" / "board.json").read_text())["flag_format"] == DEFAULT_ANSWER_FORMAT
