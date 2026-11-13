"""`flightdeck start`: an event folder from a few answers, and `play FOLDER` opening it.

No test here reaches a platform: the launch is replaced where a test would play, and the
profile's own check runs against the test's environment only.
"""

from __future__ import annotations

import stat

import pytest
from typer.testing import CliRunner

from ctf_flightdeck import cli, keys, start
from ctf_flightdeck.keys import KeysError
from ctf_flightdeck.preflight import Policy, load_profile
from ctf_flightdeck.setup import AnswerError, providers_answer

SECRET = "ctfd_0123456789abcdef0123456789abcdef"  # synthetic: no site issued it


@pytest.fixture
def setup(tmp_path, monkeypatch):
    """A config and a keys file of the test's own, and a record of what `start` launched."""
    config = tmp_path / "config.toml"
    config.write_text('[models]\nladder = ["m"]\n[lanes]\nruntime = "host"\n')
    monkeypatch.setenv("FLIGHTDECK_CONFIG", str(config))
    monkeypatch.setenv("FLIGHTDECK_KEYS", str(tmp_path / "keys.env"))
    launched = []
    monkeypatch.setattr(cli, "play", lambda **kwargs: launched.append(kwargs))
    return launched


def run(*args, input=None):
    return CliRunner().invoke(cli.app, ["start", *args], input=input)


# ---------------------------------------------------------------------- the answers


def test_an_events_name_gives_its_folder_name_and_a_token_variable_of_its_own():
    assert start.slug("  PlatyPwn 2026! ") == "platypwn-2026"
    assert start.token_variable("PlatyPwn 2026") == "CTFD_TOKEN_PLATYPWN_2026"
    assert start.token_variable("Other CTF") != start.token_variable("PlatyPwn 2026")
    with pytest.raises(start.StartError):
        start.slug("!!!")


@pytest.mark.parametrize(("typed", "matches", "refuses"), [
    ("PP", "PP{a_flag}", "XX{a_flag}"),
    ("PP{", "PP{a_flag}", "PP[a_flag]"),
    ("flag{...}", "flag{x}", "flag{}"),
    (r"CTF\{[0-9a-f]{8}\}", "CTF{deadbeef}", "CTF{nothex!}"),
])
def test_a_flag_prefix_becomes_a_format_that_matches_that_events_flags_only(typed, matches, refuses):
    import re

    pattern = start.flag_format_answer(typed)
    assert re.fullmatch(pattern, matches) and not re.fullmatch(pattern, refuses)


def test_no_flag_format_is_none_and_a_broken_expression_is_refused():
    assert start.flag_format_answer("  ") is None
    with pytest.raises(start.StartError):
        start.flag_format_answer("CTF\\{[")


@pytest.mark.parametrize(("typed", "url"), [("ctf.example.org", "https://ctf.example.org"), ("http://127.0.0.1:8000/", "http://127.0.0.1:8000")])
def test_a_site_address_gets_its_scheme_and_loses_its_last_slash(typed, url):
    assert start.url_answer(typed) == url


@pytest.mark.parametrize("typed", ["", "ftp://ctf.example.org", "https://me:pw@ctf.example.org", "https://a b"])
def test_an_address_that_is_not_a_site_is_refused(typed):
    with pytest.raises(start.StartError):
        start.url_answer(typed)


def test_the_event_file_loads_as_the_profile_the_answers_describe(tmp_path):
    answers = start.EventAnswers(name='Quote "CTF" \\ 2026', platform="ctfd", url="https://ctf.example.org",
                                 token_env="CTFD_TOKEN_QUOTE", flag_format=r"PP\{[^}]+\}", submit="auto")
    written = start.write(tmp_path / "event", answers)
    profile, policies = load_profile(written)
    assert (profile.name, profile.platform, profile.url, profile.token_env) == ('Quote "CTF" \\ 2026', "ctfd", "https://ctf.example.org", "CTFD_TOKEN_QUOTE")
    assert profile.flag_format == r"PP\{[^}]+\}" and profile.ai_allowed
    assert policies.submit is Policy.AUTO and policies.pull is Policy.AUTO
    assert (tmp_path / "event" / "board").is_dir()


def test_a_by_hand_event_never_touches_the_platform_and_names_its_board(tmp_path):
    written = start.write(tmp_path / "event", start.EventAnswers(name="Hand CTF", platform="manual"))
    profile, policies = load_profile(written)
    assert profile.platform == "manual" and profile.board == tmp_path / "event" / "board"
    assert policies.submit is Policy.MANUAL and policies.pull is Policy.MANUAL


def test_an_event_file_that_is_there_is_never_written_over(tmp_path):
    first = start.write(tmp_path, start.EventAnswers(name="One", platform="manual"))
    before = first.read_text()
    with pytest.raises(start.StartError, match="exists"):
        start.write(tmp_path, start.EventAnswers(name="Two", platform="manual"))
    assert first.read_text() == before


def test_play_takes_an_event_folder_as_its_profile_and_its_board(tmp_path):
    start.write(tmp_path / "event", start.EventAnswers(name="One", platform="manual"))
    assert start.resolve(tmp_path / "event", None) == (tmp_path / "event" / "board", tmp_path / "event" / "event.toml")
    plain = tmp_path / "plain"
    plain.mkdir()
    assert start.resolve(plain, None) == (plain, None)  # a folder board: as before
    other = tmp_path / "other.toml"
    assert start.resolve(tmp_path / "event", other) == (tmp_path / "event", other)  # --event given: the player's word


# ---------------------------------------------------------------------- the keys file


def test_a_saved_key_is_read_back_and_the_file_is_the_owners_only(tmp_path):
    path = tmp_path / "sub" / "keys.env"
    keys.save("CTFD_TOKEN_X", SECRET, path=path)
    assert keys.load_keys(path) == {"CTFD_TOKEN_X": SECRET}
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_saving_a_key_replaces_its_old_value_and_keeps_the_other_lines(tmp_path):
    path = tmp_path / "keys.env"
    path.write_text("# mine\nOTHER=one\nexport CTFD_TOKEN_X=old\n")
    path.chmod(0o600)
    keys.save("CTFD_TOKEN_X", SECRET, path=path)
    assert keys.load_keys(path) == {"OTHER": "one", "CTFD_TOKEN_X": SECRET}
    assert "# mine" in path.read_text() and "old" not in path.read_text()


@pytest.mark.parametrize(("name", "value"), [("CTFD_TOKEN_X", "two\nlines"), ("CTFD_TOKEN_X", "  "), ("not a name", SECRET)])
def test_a_key_that_cannot_be_one_line_of_the_file_is_refused_without_showing_it(tmp_path, name, value):
    path = tmp_path / "keys.env"
    with pytest.raises(KeysError) as caught:
        keys.save(name, value, path=path)
    assert value.strip() not in str(caught.value) or not value.strip()
    assert not path.exists()


def test_a_keys_file_others_can_read_is_not_added_to(tmp_path):
    path = tmp_path / "keys.env"
    path.write_text("OTHER=one\n")
    path.chmod(0o644)
    with pytest.raises(KeysError, match="chmod 600"):
        keys.save("CTFD_TOKEN_X", SECRET, path=path)
    assert path.read_text() == "OTHER=one\n"


# ---------------------------------------------------------------------- the command


def test_at_a_terminal_start_asks_makes_the_folder_keeps_the_token_out_of_sight_and_launches(tmp_path, monkeypatch, setup):
    monkeypatch.setattr(cli, "_at_terminal", lambda: True)
    folder = tmp_path / "ctf" / "example"
    answers = f"Example CTF 2026\n{folder}\ny\n1\nctf.example.org\nEX\n2\n{SECRET}\nn\ny\n"
    result = run(input=answers)
    assert result.exit_code == 0, result.output
    profile, policies = load_profile(folder / "event.toml")
    assert (profile.name, profile.url, profile.token_env) == ("Example CTF 2026", "https://ctf.example.org", "CTFD_TOKEN_EXAMPLE_CTF_2026")
    assert policies.submit is Policy.AUTO
    assert keys.load_keys(tmp_path / "keys.env") == {"CTFD_TOKEN_EXAMPLE_CTF_2026": SECRET}
    assert SECRET not in result.output and SECRET not in (folder / "event.toml").read_text()
    assert "solvers (L1): none installed" in result.output and "flightdeck pack install" in result.output
    assert [call["board"] for call in setup] == [folder]


def test_start_does_not_set_up_an_event_whose_rules_forbid_ai(tmp_path, monkeypatch, setup):
    monkeypatch.setattr(cli, "_at_terminal", lambda: True)
    folder = tmp_path / "example"
    result = run(input=f"Example CTF\n{folder}\nn\n")
    assert result.exit_code == 1 and "do not allow" in result.output
    assert not folder.exists() and setup == []


def test_start_with_no_token_says_where_it_goes_and_does_not_launch(tmp_path, monkeypatch, setup):
    monkeypatch.setattr(cli, "_at_terminal", lambda: True)
    folder = tmp_path / "example"
    result = run(input=f"Example CTF\n{folder}\ny\nctfd\nhttps://ctf.example.org\n\n1\n\nn\n")
    assert result.exit_code == 0, result.output
    assert "token: not set yet. Put CTFD_TOKEN_EXAMPLE_CTF=<your CTFd access token> in" in result.output
    assert f"play: flightdeck play {folder}" in result.output and setup == []


def test_a_by_hand_event_starts_empty_says_how_to_add_a_challenge_and_launches(tmp_path, monkeypatch, setup):
    monkeypatch.setattr(cli, "_at_terminal", lambda: True)
    folder = tmp_path / "example"
    result = run(input=f"Example CTF\n{folder}\ny\n2\n\nn\ny\n")
    assert result.exit_code == 0, result.output
    assert "type /new" in result.output and "flightdeck add" in result.output
    assert load_profile(folder / "event.toml")[0].platform == "manual"
    assert [call["board"] for call in setup] == [folder]  # an empty board plays: challenges are added in the console


def test_start_offers_the_solver_pack_and_a_failed_install_does_not_undo_the_event(tmp_path, monkeypatch, setup):
    import typer

    from ctf_flightdeck import pack_cli

    monkeypatch.setattr(cli, "_at_terminal", lambda: True)
    asked = []

    def install(**kwargs):
        asked.append(kwargs)
        raise typer.Exit(2)

    monkeypatch.setattr(pack_cli, "install", install)
    folder = tmp_path / "example"
    result = run(input=f"Example CTF\n{folder}\ny\n2\n\ny\nn\n")
    assert result.exit_code == 0, result.output
    assert len(asked) == 1 and asked[0]["source"] is None and asked[0]["yes"] is False  # the pack's own questions still asked
    assert "solvers (L1): not installed (the reason is above)" in result.output
    assert (folder / "event.toml").is_file()


def test_a_folder_that_is_already_an_event_is_played_not_asked_about_again(tmp_path, monkeypatch, setup):
    monkeypatch.setattr(cli, "_at_terminal", lambda: True)
    written = start.write(tmp_path / "example", start.EventAnswers(name="One", platform="manual"))
    before = written.read_text()
    result = run(str(tmp_path / "example"), input="y\n")
    assert result.exit_code == 0, result.output
    assert "already set up" in result.output and written.read_text() == before
    assert [call["board"] for call in setup] == [tmp_path / "example"]


def test_away_from_a_terminal_start_names_every_answer_it_needs(tmp_path, monkeypatch, setup):
    monkeypatch.setattr(cli, "_at_terminal", lambda: False)
    result = run(str(tmp_path / "example"), "--platform", "ctfd")
    assert result.exit_code == 2
    for option in ("--name NAME", "--url URL", "--ai-allowed"):
        assert option in result.output
    assert not (tmp_path / "example").exists()


def test_away_from_a_terminal_start_takes_its_answers_as_options_and_never_launches(tmp_path, monkeypatch, setup):
    monkeypatch.setattr(cli, "_at_terminal", lambda: False)
    monkeypatch.setenv("CTFD_TOKEN_EXAMPLE_CTF", SECRET)
    folder = tmp_path / "example"
    result = run(str(folder), "--name", "Example CTF", "--platform", "ctfd", "--url", "https://ctf.example.org", "--flag", "EX", "--ai-allowed")
    assert result.exit_code == 0, result.output
    assert "token: CTFD_TOKEN_EXAMPLE_CTF is already set in your environment" in result.output
    assert load_profile(folder / "event.toml")[1].submit is Policy.CONFIRM
    assert f"play: flightdeck play {folder}" in result.output and setup == [] and SECRET not in result.output


def test_start_without_a_config_and_nobody_to_ask_says_to_run_init(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "_at_terminal", lambda: False)
    monkeypatch.setenv("FLIGHTDECK_CONFIG", str(tmp_path / "absent.toml"))
    result = run(str(tmp_path / "example"), "--name", "X", "--platform", "manual", "--ai-allowed")
    assert result.exit_code == 2 and "flightdeck init" in result.output
    assert not (tmp_path / "example").exists()


# ---------------------------------------------------------------------- play, and what points at start


def test_play_opens_an_event_folder_with_its_own_profile(tmp_path, monkeypatch):
    from ctf_flightdeck import run as runs

    seen = []

    def refuse(options):
        seen.append(options)
        raise runs.RunError("stopped by the test")

    monkeypatch.setattr(runs, "prepare_run", refuse)
    start.write(tmp_path / "example", start.EventAnswers(name="One", platform="manual"))
    result = CliRunner().invoke(cli.app, ["play", str(tmp_path / "example")])
    assert result.exit_code == 2 and "stopped by the test" in result.output
    assert (seen[0].board, seen[0].event) == (tmp_path / "example" / "board", tmp_path / "example" / "event.toml")
    assert "flightdeck start" not in result.output  # the folder is an event already


@pytest.mark.parametrize("make", [False, True])
def test_play_on_a_folder_with_nothing_in_it_points_at_start(tmp_path, monkeypatch, make):
    monkeypatch.setenv("FLIGHTDECK_CONFIG", str(tmp_path / "config.toml"))
    (tmp_path / "config.toml").write_text('[models]\nladder = ["m"]\n[lanes]\nruntime = "host"\n')
    board = tmp_path / "board"
    if make:
        board.mkdir()
    result = CliRunner().invoke(cli.app, ["play", str(board)])
    assert result.exit_code == 2
    assert "`flightdeck start`" in result.output


def test_flightdeck_alone_names_start_and_says_whether_solvers_are_installed(tmp_path, monkeypatch):
    monkeypatch.setenv("FLIGHTDECK_CONFIG", str(tmp_path / "config.toml"))
    (tmp_path / "config.toml").write_text('[models]\nladder = ["m"]\n')
    result = CliRunner().invoke(cli.app, [])
    assert result.exit_code == 0, result.output
    assert "flightdeck start" in result.output and "solvers (L1): none installed" in result.output


# ---------------------------------------------------------------------- init's provider menu


@pytest.mark.parametrize(("typed", "chosen"), [
    ("2", ("anthropic",)), ("ollama", ("local",)), ("anthropic, openrouter, codingagent", ("anthropic", "openrouter")),
    ("1 2", ("openrouter", "anthropic")), ("claude-code, 3", ("openai",)),
])
def test_the_provider_menu_takes_numbers_names_and_several_at_once(typed, chosen):
    assert providers_answer(typed) == chosen


@pytest.mark.parametrize("typed", ["", "7", "gemini", "codingagent"])
def test_the_provider_menu_refuses_what_names_no_api(typed):
    with pytest.raises(AnswerError, match="1 to 6"):
        providers_answer(typed)


def test_init_given_anthropic_and_openrouter_together_writes_openrouter_as_the_fallback(tmp_path, monkeypatch):
    from ctf_flightdeck.config import load_config

    monkeypatch.setattr(cli, "_at_terminal", lambda: True)
    target = tmp_path / "config.toml"
    result = CliRunner().invoke(cli.app, ["init", "--path", str(target)], input="anthropic, openrouter, codingagent\n\nhost\n")
    assert result.exit_code == 0, result.output
    config = load_config(target)
    assert config.api.provider == "anthropic" and config.fallback is not None and "openrouter" in config.fallback.base_url
    assert "Lanes use anthropic." in result.output and "Error" not in result.output
    assert "flightdeck start" in result.output
