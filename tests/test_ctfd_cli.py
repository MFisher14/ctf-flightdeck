"""`flightdeck ctfd pull`, against the fake CTFd (tests/fake_ctfd.py) on 127.0.0.1.

The command is run in-process with Typer's CliRunner; the token reaches it only through the
environment variable --token-env names. No real CTFd is contacted.
"""

from __future__ import annotations

from typer.testing import CliRunner

from ctf_flightdeck.platform import ctfd_cli
from ctf_flightdeck.platform.manual import load_board
from fake_ctfd import FLAG_FORMAT, TOKEN, FakeChallenge, FakeCTFd, Reply, sample

TOKEN_VAR = "FLIGHTDECK_TEST_CTFD_TOKEN"
runner = CliRunner()


def pull(*args: str, env: dict[str, str] | None = None):
    return runner.invoke(ctfd_cli.app, ["pull", *args], env=env)


def test_pull_writes_the_board_and_never_prints_the_token(tmp_path):
    dest = tmp_path / "board"
    with FakeCTFd(sample() + [FakeChallenge(5, "Locked", type="hidden")]) as fake:
        result = pull(fake.base_url, str(dest), "--token-env", TOKEN_VAR, "--event", "Fake CTF",
                      "--flag-format", FLAG_FORMAT, env={TOKEN_VAR: TOKEN})
    assert result.exit_code == 0, result.output
    assert 'added baby-rsa: "Baby RSA" (Crypto, 100 points, 1 file)' in result.stdout
    assert "4 challenges, 4 new, 1 locked until a prerequisite is solved" in result.stdout
    board = load_board(dest)
    assert TOKEN not in result.output and board.event == "Fake CTF" and board.flag_format == FLAG_FORMAT


def test_the_event_name_defaults_to_the_folders(tmp_path):
    with FakeCTFd(sample()) as fake:
        result = pull(fake.base_url, str(tmp_path / "spring-ctf"), "--token-env", TOKEN_VAR, env={TOKEN_VAR: TOKEN})
    assert result.exit_code == 0, result.output
    assert load_board(tmp_path / "spring-ctf").event == "spring-ctf"


def test_pull_without_the_token_variable_fails_naming_it(tmp_path):
    with FakeCTFd(sample()) as fake:
        unset = pull(fake.base_url, str(tmp_path / "b"), "--token-env", TOKEN_VAR, env={TOKEN_VAR: ""})
        token_as_name = pull(fake.base_url, str(tmp_path / "b"), "--token-env", TOKEN, env={TOKEN_VAR: TOKEN})
        assert fake.requests == []
    assert unset.exit_code == 2 and TOKEN_VAR in unset.stderr and "is not set or is empty" in unset.stderr
    assert token_as_name.exit_code == 2 and "NAME of an environment variable" in token_as_name.stderr
    assert TOKEN not in token_as_name.output  # a token given where its name belongs is not echoed


def test_pull_never_echoes_a_long_variable_name_that_may_be_a_pasted_token(tmp_path):
    pasted = "looks_like_a_pasted_token_" + "q" * 40  # a valid variable name, as a CTFd token is
    result = pull("https://ctf.example.org", str(tmp_path / "b"), "--token-env", pasted)
    assert result.exit_code == 2 and pasted not in result.output and "that --token-env names" in result.stderr
    assert not (tmp_path / "b").exists()


def test_pull_with_challenges_left_out_exits_1_and_names_them(tmp_path):
    with FakeCTFd(sample() + [FakeChallenge(5, "Far Away", file_urls=["https://cdn.example.org/far.zip"])]) as fake:
        partial = pull(fake.base_url, str(tmp_path / "board"), "--token-env", TOKEN_VAR, env={TOKEN_VAR: TOKEN})
        refused = pull(fake.base_url, str(tmp_path / "x"), "--token-env", TOKEN_VAR, env={TOKEN_VAR: "wrong-token"})
    assert partial.exit_code == 1 and 'not pulled: challenge 5 ("Far Away")' in partial.stderr
    assert "4 challenges, 4 new" in partial.stdout
    assert refused.exit_code == 2 and "refused the API token" in refused.stderr and "wrong-token" not in refused.output


def test_a_pull_that_stops_partway_exits_2_and_names_each_challenge_it_left_out(tmp_path):
    down = Reply(503, "down", {"Retry-After": "0"})  # retried at once, so the test stays fast
    with FakeCTFd(sample()) as fake:
        fake.challenges[2].file_urls = ["https://cdn.example.org/x/far.zip"]
        # the list comes through, then CTFd goes down for challenge 3 and for the list asked again
        fake.script("GET", "/api/v1/challenges", Reply(200, fake.listing()), *[down] * 4)
        fake.script("GET", "/api/v1/challenges/3", *[down] * 4)
        result = pull(fake.base_url, str(tmp_path / "board"), "--token-env", TOKEN_VAR, env={TOKEN_VAR: TOKEN})
    assert result.exit_code == 2 and "added warmup" in result.stdout
    lines = result.stderr.splitlines()
    assert lines[0].startswith('not pulled: challenge 2 ("Baby RSA"): ') and "another host" in lines[0]
    assert lines[1].startswith('not pulled: challenge 3 ("Login Portal"): ') and "HTTP 503" in lines[1]
    assert lines[2].startswith("flightdeck: ") and lines[2].endswith(
        "the pull stopped there, with 1 new challenge written: pull again to go on")
    assert len(lines) == 3
