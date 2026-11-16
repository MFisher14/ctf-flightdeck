"""`flightdeck start`: an event folder from a few answers, and `play FOLDER` opening it.

No test here reaches a platform: the launch is replaced where a test would play, and the
profile's own check runs against the test's environment only.
"""

from __future__ import annotations

import os
import stat

import pytest
from typer.testing import CliRunner

from ctf_flightdeck import cli, events, keys, start
from ctf_flightdeck.keys import KeysError
from ctf_flightdeck.preflight import Policy, load_profile
from ctf_flightdeck.setup import AnswerError, providers_answer

SECRET = "ctfd_0123456789abcdef0123456789abcdef"  # synthetic: no site issued it
OLD_SECRET = "ctfd_fedcba9876543210fedcba9876543210"  # synthetic: another site's token, in the tests of whose token goes where


@pytest.fixture
def setup(tmp_path, monkeypatch):
    """A config, a keys file and a home folder of the test's own (the events start knows of
    are the test's: the state folder is its own too, conftest), and a record of what `start`
    launched."""
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home" / "ctf").mkdir(parents=True)
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
    ("CTF{s0me_t3xt}", "CTF{abc123}", "XTF{abc123}"),  # the rules' example flag, pasted: its prefix, not that one text
    ("flag{}", "flag{anything at all}", "flag{}"),
    ("CTF{flag}", "CTF{deadbeef}", "CTF[flag]"),
    ("my-ctf{a b.c}", "my-ctf{real_one}", "my_ctf{real_one}"),
    ("CTF{cut_off", "CTF{abc123}", "CTF{}"),
])
def test_a_flag_prefix_becomes_a_format_that_matches_that_events_flags_only(typed, matches, refuses):
    import re

    pattern = start.flag_format_answer(typed)
    assert re.fullmatch(pattern, matches) and not re.fullmatch(pattern, refuses)


def test_what_was_made_of_a_flag_format_is_said_in_words():
    pattern, said = start.flag_format_read("CTF{s0me_t3xt}")
    assert pattern == r"CTF\{[^}]+\}"
    assert said == ("read CTF{s0me_t3xt} as an example flag: flags look like CTF{...}, with any text between the braces "
                    r"(the regular expression CTF\{[^}]+\})")
    assert start.flag_format_read("PP")[1].startswith("flags look like PP{...}, with any text between the braces")
    own = r"CTF\{[0-9a-f]{8}\}"
    assert start.flag_format_read(own) == (own, f"kept as your own regular expression, exactly as typed: {own} "
                                                "(for a prefix, give only what comes before the {)")
    assert start.flag_format_read("CTF{.+}")[0] == "CTF{.+}"  # a quantifier in it: an expression of the player's own, kept
    assert start.flag_format_read("")[0] is None and start.flag_format_read("")[1].startswith("no flag format")


def test_no_flag_format_is_none_and_a_broken_expression_is_refused():
    assert start.flag_format_answer("  ") is None
    with pytest.raises(start.StartError):
        start.flag_format_answer("CTF\\{[")


@pytest.mark.parametrize(("typed", "url"), [("ctf.example.net", "https://ctf.example.net"), ("http://127.0.0.1:8000/", "http://127.0.0.1:8000")])
def test_a_site_address_gets_its_scheme_and_loses_its_last_slash(typed, url):
    assert start.url_answer(typed) == url


@pytest.mark.parametrize("typed", ["", "ftp://ctf.example.net", "https://me:pw@ctf.example.net", "https://a b"])
def test_an_address_that_is_not_a_site_is_refused(typed):
    with pytest.raises(start.StartError):
        start.url_answer(typed)


def test_the_event_file_loads_as_the_profile_the_answers_describe(tmp_path):
    answers = start.EventAnswers(name='Quote "CTF" \\ 2026', platform="ctfd", url="https://ctf.example.net",
                                 token_env="CTFD_TOKEN_QUOTE", flag_format=r"PP\{[^}]+\}", submit="auto")
    written = start.write(tmp_path / "event", answers)
    profile, policies = load_profile(written)
    assert (profile.name, profile.platform, profile.url, profile.token_env) == ('Quote "CTF" \\ 2026', "ctfd", "https://ctf.example.net", "CTFD_TOKEN_QUOTE")
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
    answers = f"Example CTF 2026\n{folder}\ny\n\n1\nctf.example.net\nEX\n2\n{SECRET}\n\nn\ny\n"
    result = run(input=answers)
    assert result.exit_code == 0, result.output
    profile, policies = load_profile(folder / "event.toml")
    assert (profile.name, profile.url, profile.token_env) == ("Example CTF 2026", "https://ctf.example.net", "CTFD_TOKEN_EXAMPLE_CTF_2026")
    assert policies.submit is Policy.AUTO
    assert profile.declared_label is None and "label:" not in result.output  # Enter at the label question: the event asks for none
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


def test_the_rules_question_says_what_a_lane_does_so_a_chat_only_rule_is_not_answered_yes(tmp_path, monkeypatch, setup):
    """An event may allow asking a model about a concept and forbid giving it the challenge:
    the one question names both things a lane does, and a no to it sets nothing up."""
    monkeypatch.setattr(cli, "_at_terminal", lambda: True)
    folder = tmp_path / "example"
    result = run(input=f"Example CTF\n{folder}\nn\n")
    assert "AI agents to work on the challenges, with each challenge's text and files given to a model?" in result.output
    assert ("not set up: flightdeck's lanes are AI agents that are given each challenge's text and files, and this event's "
            "rules do not allow that") in " ".join(result.output.split())
    assert result.exit_code == 1 and not folder.exists()


def test_the_event_file_start_writes_says_both_rules_the_player_answered_for(tmp_path):
    written = start.write(tmp_path / "event", start.EventAnswers(name="Hand CTF", platform="manual"))
    text = written.read_text()
    assert "ai_allowed = true" in text and "material_to_models = true" in text
    assert '# declared_label = "Human-Led AI"' in text  # no label declared: the key is there to fill in
    profile, _ = load_profile(written)
    assert profile.ai_allowed and profile.material_to_models and profile.declared_label is None


def test_at_a_terminal_start_asks_for_the_declared_label_and_writes_it_in_the_event_file(tmp_path, monkeypatch, setup):
    monkeypatch.setattr(cli, "_at_terminal", lambda: True)
    folder = tmp_path / "example"
    result = run(input=f"Example CTF\n{folder}\ny\nan/address\n Human-Led AI \n2\n\n\nn\ny\n")
    assert result.exit_code == 0, result.output
    assert "Label your team declared to the event for its AI use" in result.output
    assert "give the label as a few words as the event writes them" in result.output  # the first answer was no label: asked again
    assert "label: Human-Led AI (what your team declared to the event; shown before each run and on its flight card)" in result.output
    profile, policies = load_profile(folder / "event.toml")
    assert profile.declared_label == "Human-Led AI" and policies.agents is Policy.AUTO


def test_away_from_a_terminal_the_label_is_an_option_checked_before_anything_is_written(tmp_path, monkeypatch, setup):
    monkeypatch.setattr(cli, "_at_terminal", lambda: False)
    by_hand = ("--name", "Hand CTF", "--platform", "manual", "--ai-allowed")
    refused = run(str(tmp_path / "bad"), *by_hand, "--label", "see https://example.org")
    assert refused.exit_code == 2 and "--label: give the label as a few words" in " ".join(refused.output.split())
    assert not (tmp_path / "bad").exists()
    result = run(str(tmp_path / "good"), *by_hand, "--label", "Low AI")
    assert result.exit_code == 0, result.output
    assert load_profile(tmp_path / "good" / "event.toml")[0].declared_label == "Low AI"
    plain = run(str(tmp_path / "plain"), *by_hand)  # no --label and nobody to ask: no label, and no question
    assert plain.exit_code == 0 and load_profile(tmp_path / "plain" / "event.toml")[0].declared_label is None


@pytest.mark.parametrize(("typed", "label"), [("", None), ("   ", None), ("Human-Led AI", "Human-Led AI"), (" No AI ", "No AI")])
def test_a_label_answer_is_the_events_words_or_nothing(typed, label):
    assert start.label_answer(typed) == label


@pytest.mark.parametrize("typed", ["a\tb", "https://example.org", "x" * 41, "<i>", "--"])
def test_a_label_answer_that_is_not_a_few_plain_words_is_refused(typed):
    with pytest.raises(start.StartError, match="give the label as a few words"):
        start.label_answer(typed)


def test_start_with_no_token_says_where_it_goes_and_does_not_launch(tmp_path, monkeypatch, setup):
    monkeypatch.setattr(cli, "_at_terminal", lambda: True)
    folder = tmp_path / "example"
    result = run(input=f"Example CTF\n{folder}\ny\n\nctfd\nhttps://ctf.example.net\n\n1\n\n\nn\n")
    assert result.exit_code == 0, result.output
    assert "token: not set yet. Put CTFD_TOKEN_EXAMPLE_CTF=<your CTFd access token> in" in result.output
    assert f"play: flightdeck play {folder}" in result.output and setup == []


def test_a_by_hand_event_starts_empty_says_how_to_add_a_challenge_and_launches(tmp_path, monkeypatch, setup):
    monkeypatch.setattr(cli, "_at_terminal", lambda: True)
    folder = tmp_path / "example"
    result = run(input=f"Example CTF\n{folder}\ny\n\n2\n\n\nn\ny\n")
    assert result.exit_code == 0, result.output
    assert "type /new" in result.output and "flightdeck add" in result.output
    assert load_profile(folder / "event.toml")[0].platform == "manual"
    assert [call["board"] for call in setup] == [folder]  # an empty board plays: challenges are added in the console


def test_the_platform_question_offers_the_json_api_platforms_so_by_hand_is_not_the_only_way_off_ctfd(tmp_path, monkeypatch, setup):
    """"by hand: any other site" left a player on rCTF, noCTF or GZCTF submitting every flag
    on the site. The menu offers them as a choice of its own, and the next question names each
    preset the http platform has, in the order its numbers answer it."""
    from ctf_flightdeck.platform.http import PRESETS

    monkeypatch.setattr(cli, "_at_terminal", lambda: True)
    result = run(input=f"Example CTF\n{tmp_path / 'example'}\ny\n\n3\n")
    menu = result.output.split("How does flightdeck get this event's challenges?", 1)[1].split("Choose 1, 2 or 3", 1)[0]
    assert "3  json api  the site runs rCTF, rCTF v2, noCTF or GZCTF" in menu
    presets = result.output.split("Which platform does the event's site run?", 1)[1].split("Choose 1 to 4", 1)[0]
    for number, name in enumerate(PRESETS, 1):
        assert f"  {number}  {start.PRESET_LABELS[name]} " in presets and start.preset_answer(str(number)) == name


# ---------------------------------------------------------------------- a JSON-API platform (P95)


LINK = "https://ctf.example.net/login?token=c3ludGhldGljK3Rva2VuPQ%3D%3D"  # synthetic: an rCTF login link no site issued


@pytest.mark.parametrize("preset", ["rctf", "rctf2", "noctf", "gzctf"])
def test_a_json_api_event_file_is_the_presets_example_filled_in_and_passes_preflight(tmp_path, monkeypatch, preset):
    """The event file start writes for rCTF, noCTF or GZCTF carries the [http] table
    `flightdeck http example --preset NAME` writes (with the event's game), names a token
    variable the http platform takes, and is refused by nothing in preflight."""
    from ctf_flightdeck import http_cli
    from ctf_flightdeck.config import load_config
    from ctf_flightdeck.preflight import check

    game = "3" if preset == "gzctf" else None
    token_env = start.token_variable("Example CTF", start.token_prefix("http", preset))
    monkeypatch.setenv(token_env, "synthetic-token")
    answers = start.EventAnswers(name="Example CTF", platform="http", url="https://ctf.example.net", token_env=token_env,
                                 submit="auto", preset=preset, game=game)
    written = start.write(tmp_path / "event", answers)
    text = written.read_text()
    assert http_cli.preset_table(preset, game, keys_file=True).strip() in text and "in quotes" not in text
    profile, policies = load_profile(written)
    assert (profile.platform, profile.url, profile.token_env, profile.http.preset, profile.http.game) == (
        "http", "https://ctf.example.net", token_env, preset, game)
    assert profile.board == tmp_path / "event" / "board" and profile.platform_automation
    assert policies.submit is Policy.AUTO and policies.pull is Policy.AUTO
    config = tmp_path / "config.toml"
    config.write_text('[models]\nladder = ["m"]\n[lanes]\nruntime = "host"\n')
    problems = check(profile, policies, max_lanes=1, model_config=load_config(config), runtime="host", environ={token_env: "x"})
    assert [problem.message for problem in problems if problem.refuse] == []


def test_a_json_api_platforms_token_variable_is_one_the_http_platform_takes_and_never_a_ctfd_one():
    from ctf_flightdeck.platform.http import PRESETS, parse_config

    for preset in PRESETS:
        name = start.token_variable("Example CTF", start.token_prefix("http", preset))
        assert parse_config({"preset": preset, **({"game": "1"} if preset == "gzctf" else {})}).names_token(name)
        assert not name.startswith("CTFD_")
    assert start.token_prefix("http", "rctf2") == "RCTF_TOKEN_" and start.token_prefix("http", "noctf") == "NOCTF_TOKEN_"
    assert start.token_prefix("ctfd") == "CTFD_TOKEN_"


@pytest.mark.parametrize(("preset", "typed", "url", "game"), [
    ("rctf", "ctf.example.net", "https://ctf.example.net", None),
    ("rctf", "https://ctf.example.net/challs", "https://ctf.example.net", None),  # the page pasted from the browser
    ("rctf2", "https://ctf.example.net:8443/scores?page=2", "https://ctf.example.net:8443", None),
    ("gzctf", "https://ctf.example.net/games/03/challenges", "https://ctf.example.net", "3"),  # the game's page: the game too
    ("gzctf", "https://ctf.example.net/games/0", "https://ctf.example.net", None),  # no game 0
    ("noctf", "https://api.example.org/v1", "https://api.example.org/v1", None),  # noCTF's is its API's address: as typed
])
def test_a_json_api_events_address_is_the_one_its_routes_are_under(preset, typed, url, game):
    got, from_url, said = start.http_url_read(preset, typed)
    assert (got, from_url) == (url, game)
    assert (said is None) == (url == typed or "://" not in typed)
    if game is not None:
        assert said.endswith(f"and the game is {game}, from its page's address")


@pytest.mark.parametrize(("typed", "game"), [("3", "3"), (" 012 ", "12")])
def test_a_games_number_is_its_pages_number(typed, game):
    assert start.game_answer(typed) == game


@pytest.mark.parametrize("typed", ["", "0", "three", "-1", "1 2", "1234567890", "3/challenges", "１"])
def test_a_game_that_is_not_a_pages_number_is_refused(typed):
    with pytest.raises(start.StartError, match="the game's number"):
        start.game_answer(typed)


def test_a_preset_table_has_its_game_exactly_when_its_routes_name_one():
    from ctf_flightdeck import http_cli

    with pytest.raises(ValueError, match="name the game"):
        http_cli.preset_table("gzctf")
    with pytest.raises(ValueError, match="name no game"):
        http_cli.preset_table("rctf", "3")
    with pytest.raises(ValueError, match="no preset"):
        http_cli.preset_table("ctfd")
    assert 'game = "7"' in http_cli.preset_table("gzctf", "7") and 'game = "1"' not in http_cli.preset_table("gzctf", "7")
    assert "in quotes" in http_cli.preset_table("rctf") and "in quotes" not in http_cli.preset_table("rctf", keys_file=True)


def http_answers(folder, *, preset_number, url, more="", token=""):
    """At a terminal: the name, the folder, the AI rules (y), no label, the JSON-API choice, the
    preset, the address, [more] (the game, a line each), no flag format, confirm, the token (hidden),
    no VPN file, no solver pack and no launch."""
    return f"Example CTF\n{folder}\ny\n\n3\n{preset_number}\n{url}\n{more}\n1\n{token}\n\nn\nn\n"


def test_at_a_terminal_start_sets_up_an_rctf_event_and_keeps_its_login_link_out_of_sight(tmp_path, monkeypatch, setup):
    monkeypatch.setattr(cli, "_at_terminal", lambda: True)
    folder = tmp_path / "example"
    result = run(input=http_answers(folder, preset_number=1, url="https://ctf.example.net/challs", token=LINK))
    assert result.exit_code == 0, result.output
    profile, policies = load_profile(folder / "event.toml")
    assert (profile.platform, profile.http.preset, profile.url, profile.token_env) == (
        "http", "rctf", "https://ctf.example.net", "RCTF_TOKEN_EXAMPLE_CTF")
    assert policies.submit is Policy.CONFIRM
    assert "address: rCTF's routes are under the site's root, so the address is https://ctf.example.net" in result.output
    assert "Paste your team's login link, whole" in result.output  # the question says where rCTF keeps it, not CTFd's Settings
    assert keys.load_keys(tmp_path / "keys.env") == {"RCTF_TOKEN_EXAMPLE_CTF": LINK}
    assert LINK not in result.output and "c3ludGhldGlj" not in (folder / "event.toml").read_text()
    assert "pulled from https://ctf.example.net when you play (rCTF's API, by the http platform)" in result.output
    assert "type /new" not in result.output  # the board is pulled, not filled by hand
    assert f"check: `flightdeck http check {folder / 'event.toml'}` signs in, lists the challenges" in result.output


def test_a_gzctf_events_game_comes_from_its_pages_address_or_is_asked_for(tmp_path, monkeypatch, setup):
    monkeypatch.setattr(cli, "_at_terminal", lambda: True)
    from_page = run(input=http_answers(tmp_path / "one", preset_number=4, url="https://ctf.example.net/games/3/challenges",
                                       more="", token="synthetic-cookie"))
    assert from_page.exit_code == 0, from_page.output
    assert "The game's number" not in from_page.output and "and the game is 3, from its page's address" in from_page.output
    one = load_profile(tmp_path / "one" / "event.toml")[0]
    assert (one.url, one.http.game, one.token_env) == ("https://ctf.example.net", "3", "GZCTF_TOKEN_EXAMPLE_CTF")
    asked = run(input=http_answers(tmp_path / "two", preset_number=4, url="other.example.org", more="0\n5\n", token=""))
    assert asked.exit_code == 0, asked.output
    assert "The game's number" in asked.output and "give the game's number" in asked.output  # 0 is no game: asked again
    assert load_profile(tmp_path / "two" / "event.toml")[0].http.game == "5"
    assert "token: not set yet. Put GZCTF_TOKEN_EXAMPLE_CTF_2=<your GZCTF token> in" in asked.output
    assert "the value of the GZCTF_Token cookie" in asked.output.split("token: not set yet", 1)[1]


HTTP = ("--name", "Example CTF", "--url", "https://ctf.example.net", "--ai-allowed")


def test_away_from_a_terminal_a_json_api_event_takes_its_preset_game_and_token_as_options(tmp_path, monkeypatch, setup):
    monkeypatch.setattr(cli, "_at_terminal", lambda: False)
    monkeypatch.setenv("MY_NOCTF", "synthetic-session-token")
    folder = tmp_path / "example"
    result = run(str(folder), *HTTP, "--preset", "noctf", "--token-env", "MY_NOCTF", "--submit", "auto")  # --preset alone: the http platform
    assert result.exit_code == 0, result.output
    profile, policies = load_profile(folder / "event.toml")
    assert (profile.platform, profile.http.preset, profile.token_env, policies.submit) == ("http", "noctf", "NOCTF_TOKEN_EXAMPLE_CTF", Policy.AUTO)
    assert keys.load_keys(tmp_path / "keys.env") == {"NOCTF_TOKEN_EXAMPLE_CTF": "synthetic-session-token"}
    assert "synthetic-session-token" not in result.output and setup == []
    gz = run(str(tmp_path / "gz"), *HTTP, "--platform", "http", "--preset", "GZCTF", "--game", "4")
    assert gz.exit_code == 0, gz.output
    assert load_profile(tmp_path / "gz" / "event.toml")[0].http.game == "4"


@pytest.mark.parametrize(("options", "said"), [
    (("--platform", "http"), "--preset rctf|rctf2|noctf|gzctf"),
    (("--preset", "gzctf"), "give --game NUMBER"),
    (("--preset", "rctf", "--game", "3"), "--game is for GZCTF (--preset gzctf): rCTF's routes name no game"),
    (("--platform", "manual", "--preset", "rctf"), "--preset is for --platform http"),
    (("--platform", "ctfd", "--game", "3"), "--game is for --platform http"),
    (("--preset", "fbctf"), "--preset: answer 1 (rCTF), 2 (rCTF v2), 3 (noCTF), 4 (GZCTF)"),
    (("--preset", "gzctf", "--url", "https://ctf.example.net/games/3", "--game", "4"), "--game 4 and the address's game (3) differ"),
])
def test_a_json_api_answer_that_does_not_fit_stops_start_before_anything_is_written(tmp_path, monkeypatch, setup, options, said):
    monkeypatch.setattr(cli, "_at_terminal", lambda: False)
    folder = tmp_path / "example"
    result = run(str(folder), "--name", "Example CTF", "--ai-allowed", *(() if "--url" in options else ("--url", "https://ctf.example.net")),
                 *options)
    assert result.exit_code == 2 and said in result.output, result.output
    assert not folder.exists() and not (tmp_path / "keys.env").exists()


def test_an_rctf_event_at_another_site_of_the_same_name_gets_a_token_variable_of_its_own(tmp_path, monkeypatch, setup):
    monkeypatch.setattr(cli, "_at_terminal", lambda: False)
    monkeypatch.setenv("ONE", "synthetic-one")
    monkeypatch.setenv("TWO", "synthetic-two")
    first = run(str(tmp_path / "ctf" / "one"), *HTTP, "--preset", "rctf", "--token-env", "ONE")
    assert first.exit_code == 0, first.output
    events.remember(tmp_path / "ctf" / "one")
    second = run(str(tmp_path / "ctf" / "two"), "--name", "Example CTF", "--url", "https://other.example.org", "--ai-allowed",
                 "--preset", "rctf", "--token-env", "TWO")
    assert second.exit_code == 0, second.output
    assert load_profile(tmp_path / "ctf" / "two" / "event.toml")[0].token_env == "RCTF_TOKEN_EXAMPLE_CTF_2"
    assert keys.load_keys(tmp_path / "keys.env") == {"RCTF_TOKEN_EXAMPLE_CTF": "synthetic-one", "RCTF_TOKEN_EXAMPLE_CTF_2": "synthetic-two"}


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
    result = run(input=f"Example CTF\n{folder}\ny\n\n2\n\n\ny\nn\n")
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


def test_a_folder_already_set_up_whose_token_is_not_set_says_so_before_it_launches(tmp_path, monkeypatch, setup):
    """Start left out the check's "token is not set" as said already, with where the token
    goes; for a folder set up before (an http profile from `flightdeck http example`, or a
    CTFd event whose token was skipped) nothing had said it, and play then refused."""
    from ctf_flightdeck import http_cli

    monkeypatch.delenv("RCTF_TOKEN", raising=False)
    folder = tmp_path / "quals"
    folder.mkdir()
    (folder / "event.toml").write_text(http_cli.example_profile(False, "rctf").replace("ctf.example.org", "ctf.example.net"))
    result = run(str(folder), "--no-launch")
    assert result.exit_code == 0, result.output
    assert "note: the token variable RCTF_TOKEN (event.token_env) is not set or is empty" in result.output
    monkeypatch.setenv("RCTF_TOKEN", "a-synthetic-team-token")
    assert "RCTF_TOKEN" not in run(str(folder), "--no-launch").output  # set: nothing to say


def test_a_folder_whose_profile_is_still_at_the_examples_address_is_refused_before_play_is_offered(tmp_path, monkeypatch, setup):
    """`flightdeck http example` into the folder, the token set, nothing edited: start once said
    nothing and offered to launch, and play then refused event.url. It now says the refusal."""
    from ctf_flightdeck import http_cli
    from ctf_flightdeck.preflight import placeholder_url

    monkeypatch.setenv("RCTF_TOKEN", "a-synthetic-team-token")
    folder = tmp_path / "quals"
    folder.mkdir()
    (folder / "event.toml").write_text(http_cli.example_profile(False, "rctf"))
    result = run(str(folder), "--no-launch")
    assert result.exit_code == 2, result.output
    assert f"refuse: {placeholder_url('https://ctf.example.org')}" in result.output


def test_away_from_a_terminal_start_names_every_answer_it_needs(tmp_path, monkeypatch, setup):
    monkeypatch.setattr(cli, "_at_terminal", lambda: False)
    result = run(str(tmp_path / "example"), "--platform", "ctfd")
    assert result.exit_code == 2
    for option in ("--name NAME", "--url URL", "--ai-allowed"):
        assert option in result.output
    assert not (tmp_path / "example").exists()


def test_away_from_a_terminal_start_takes_its_answers_as_options_and_never_launches(tmp_path, monkeypatch, setup):
    monkeypatch.setattr(cli, "_at_terminal", lambda: False)
    monkeypatch.setenv("EXAMPLE_TOKEN", SECRET)
    folder = tmp_path / "example"
    result = run(str(folder), "--name", "Example CTF", "--platform", "ctfd", "--url", "https://ctf.example.net", "--flag", "EX", "--ai-allowed",
                 "--token-env", "EXAMPLE_TOKEN")
    assert result.exit_code == 0, result.output
    assert f"token: saved in {tmp_path / 'keys.env'} as CTFD_TOKEN_EXAMPLE_CTF" in result.output
    assert keys.load_keys(tmp_path / "keys.env") == {"CTFD_TOKEN_EXAMPLE_CTF": SECRET}
    assert "flag format: flags look like EX{...}" in result.output
    assert load_profile(folder / "event.toml")[1].submit is Policy.CONFIRM
    assert f"play: flightdeck play {folder}" in result.output and setup == [] and SECRET not in result.output


# ---------------------------------------------------------------------- the token: handed over without a prompt


CTFD = ("--name", "Example CTF", "--platform", "ctfd", "--url", "https://ctf.example.net", "--ai-allowed")


def test_start_takes_the_token_from_a_pipe_and_has_no_option_for_the_token_itself(tmp_path, monkeypatch, setup):
    monkeypatch.setattr(cli, "_at_terminal", lambda: False)
    folder = tmp_path / "example"
    result = run(str(folder), *CTFD, "--token-stdin", input=f"{SECRET}\n")
    assert result.exit_code == 0, result.output
    assert keys.load_keys(tmp_path / "keys.env") == {"CTFD_TOKEN_EXAMPLE_CTF": SECRET}
    assert SECRET not in result.output and SECRET not in (folder / "event.toml").read_text()
    refused = run(str(tmp_path / "other"), *CTFD, "--token", SECRET)  # a command line is kept in history and shown by ps
    assert refused.exit_code == 2 and "No such option" in refused.output and not (tmp_path / "other").exists()


@pytest.mark.parametrize(("options", "given", "said"), [
    (("--token-env", "ABSENT_TOKEN"), None, "--token-env: ABSENT_TOKEN is not set in the environment"),
    (("--token-env", SECRET + "!"), None, "--token-env takes the name of an environment variable"),
    (("--token-env", SECRET), None, "--token-env takes the name of an environment variable"),  # the token, pasted where a name goes
    (("--token-env", "A_VARIABLE_NAME_TOO_LONG_TO_BE_SHOWN_BACK"), None, "--token-env: the variable --token-env names is not set in the environment"),
    (("--token-env", "EXAMPLE_TOKEN", "--token-stdin"), SECRET, "give --token-env NAME or --token-stdin, not both"),
    (("--token-stdin",), "", "--token-stdin: nothing came on standard input"),
    (("--token-stdin",), f"{SECRET}\nsecond-line\n", "--token-stdin: the token has a line break in it (U+000A)"),
    (("--token-env", "QUOTED_TOKEN"), None, "--token-env: the token is in quotes: give it without them"),
])
def test_a_token_that_cannot_be_taken_stops_start_before_anything_is_written_and_is_never_shown(tmp_path, monkeypatch, setup, options, given, said):
    monkeypatch.setattr(cli, "_at_terminal", lambda: False)
    monkeypatch.setenv("EXAMPLE_TOKEN", SECRET)
    monkeypatch.setenv("QUOTED_TOKEN", f'"{SECRET}"')
    folder = tmp_path / "example"
    result = run(str(folder), *CTFD, *options, input=given)
    assert result.exit_code == 2 and said in result.output
    assert SECRET not in result.output and "second-line" not in result.output and "A_VARIABLE_NAME_TOO_LONG_TO_BE_SHOWN_BACK" not in result.output
    assert not folder.exists() and not (tmp_path / "keys.env").exists()


def test_a_token_is_for_a_ctfd_event_and_a_pipe_is_not_a_terminal(tmp_path, monkeypatch, setup):
    monkeypatch.setattr(cli, "_at_terminal", lambda: False)
    monkeypatch.setenv("EXAMPLE_TOKEN", SECRET)
    by_hand = run(str(tmp_path / "hand"), "--name", "Hand CTF", "--platform", "manual", "--ai-allowed", "--token-env", "EXAMPLE_TOKEN")
    assert by_hand.exit_code == 2 and "--token-env is for --platform ctfd or http" in by_hand.output
    assert not (tmp_path / "hand").exists() and not (tmp_path / "keys.env").exists()
    monkeypatch.setattr(cli, "_at_terminal", lambda: True)
    at_a_terminal = run(str(tmp_path / "example"), *CTFD, "--token-stdin", input=f"{SECRET}\n")
    assert at_a_terminal.exit_code == 2 and "--token-stdin reads the token from a pipe" in at_a_terminal.output
    assert not (tmp_path / "example").exists()


# ---------------------------------------------------------------------- the token: one site's, never another's


def old_event(tmp_path, *, url="https://old.example.org", name="Example CTF", variable="CTFD_TOKEN_EXAMPLE_CTF", token=OLD_SECRET):
    """Last year's event of the same name, at another site, with its token in the keys file."""
    folder = tmp_path / "last-year"
    start.write(folder, start.EventAnswers(name=name, platform="ctfd", url=url, token_env=variable))
    events.remember(folder)
    if token:
        keys.save(variable, token, path=tmp_path / "keys.env")
    return folder


@pytest.mark.parametrize(("url", "site"), [
    ("https://ctf.example.net", "ctf.example.net:443"), ("https://CTF.Example.net:443/path", "ctf.example.net:443"),
    ("https://ctf.example.net.", "ctf.example.net:443"), ("http://ctf.example.net", "ctf.example.net:80"),
    ("https://ctf.example.net:8443", "ctf.example.net:8443"), ("https://ctf-example.org", "ctf-example.org:443"),
    ("ftp://ctf.example.net", None), ("ctf.example.net", None), ("", None), (None, None), ("https://a:notaport", None),
])
def test_a_site_is_an_addresses_host_and_port(url, site):
    assert start.site_of(url) == site


def test_the_token_variable_is_the_first_that_is_this_sites_or_nobodys(tmp_path):
    here, there = "https://ctf.example.net", "https://old.example.org"
    use = lambda url, folder="e": start.TokenUse(start.site_of(url), tmp_path / folder)  # noqa: E731
    choose = lambda uses, set_in: start.token_variable_for("Example CTF", here, uses=uses, source=lambda name: set_in.get(name))  # noqa: E731
    base = "CTFD_TOKEN_EXAMPLE_CTF"

    assert choose({}, {}) == start.TokenVariable(base, None)  # a first event: the name's own variable, to be asked for
    again = choose({base: [use(here)]}, {base: "keys file"})  # the same site, set up before: its token is used again
    assert (again.name, again.source, again.passed) == (base, "keys file", ())

    other = choose({base: [use(there, "last-year")]}, {base: "keys file"})  # another site's: never read for this one
    assert (other.name, other.source) == (f"{base}_2", None)
    assert other.passed == (f"{base} is the token for old.example.org (the event in {tmp_path / 'last-year'})",)
    unset = choose({base: [use(there)]}, {})  # another site's, not set yet: never written with this one's token either
    assert unset.name == f"{base}_2"
    both = choose({base: [use(here), use(there)]}, {base: "keys file"})  # one event of each site names it: not this site's alone
    assert both.name == f"{base}_2"

    stale = choose({}, {base: "environment"})  # set, and no event says whose it is (last year's folder is gone)
    assert (stale.name, stale.source) == (f"{base}_2", None)
    assert stale.passed == (f"{base} is set in your environment, and no event of yours says it is the token for ctf.example.net",)
    third = choose({base: [use(there)], f"{base}_2": [use("https://third.example.org")]}, {})
    assert third.name == f"{base}_3" and len(third.passed) == 2
    reuse_second = choose({base: [use(there)], f"{base}_2": [use(here)]}, {base: "keys file", f"{base}_2": "keys file"})
    assert (reuse_second.name, reuse_second.source) == (f"{base}_2", "keys file")

    lookalike = start.token_variable_for("Example CTF", "https://ctf-example.org", uses={base: [use(here)]},
                                         source=lambda name: "keys file" if name == base else None)
    assert (lookalike.name, lookalike.source) == (f"{base}_2", None)  # a host that reads alike is another site
    with pytest.raises(start.StartError, match="give this event another name"):  # never a variable that is not this site's, even then
        start.token_variable_for("Example CTF", here, uses={}, source=lambda name: "keys file")
    with pytest.raises(start.StartError, match="address"):
        start.token_variable_for("Example CTF", "not an address", uses={}, source=lambda name: None)


def test_the_events_start_knows_of_say_which_site_each_token_variable_is_for(tmp_path, setup):
    folder = old_event(tmp_path, token=None)
    start.write(tmp_path / "home" / "ctf" / "hand", start.EventAnswers(name="Hand", platform="manual"))  # names no token
    broken = tmp_path / "home" / "ctf" / "broken"
    broken.mkdir()
    (broken / "event.toml").write_text("[event\n")
    assert start.token_uses() == {"CTFD_TOKEN_EXAMPLE_CTF": [start.TokenUse("old.example.org:443", folder.resolve())]}


def test_an_event_of_the_same_name_at_another_site_gets_a_token_variable_of_its_own_and_is_asked_for_its_token(tmp_path, monkeypatch, setup):
    """Last year's token is in the keys file under the name's variable. This year's event has
    the same name and another address: its token is asked for and kept beside the old one,
    and its event file names the new variable, so the old token is never sent to the new site."""
    monkeypatch.setattr(cli, "_at_terminal", lambda: True)
    old_event(tmp_path)
    folder = tmp_path / "this-year"
    result = run(input=f"Example CTF!\n{folder}\ny\n\n1\nctf.example.net\nEX\n1\n{SECRET}\n\nn\nn\n")
    assert result.exit_code == 0, result.output
    assert load_profile(folder / "event.toml")[0].token_env == "CTFD_TOKEN_EXAMPLE_CTF_2"
    assert keys.load_keys(tmp_path / "keys.env") == {"CTFD_TOKEN_EXAMPLE_CTF": OLD_SECRET, "CTFD_TOKEN_EXAMPLE_CTF_2": SECRET}
    assert (f"token: CTFD_TOKEN_EXAMPLE_CTF is the token for old.example.org (the event in {(tmp_path / 'last-year').resolve()}), "
            "so it is not used for this event") in result.output
    assert f"token: saved in {tmp_path / 'keys.env'} as CTFD_TOKEN_EXAMPLE_CTF_2" in result.output
    assert SECRET not in result.output and OLD_SECRET not in result.output


def test_a_token_left_in_the_keys_file_by_an_event_that_is_gone_is_not_used_for_a_new_site(tmp_path, monkeypatch, setup):
    monkeypatch.setattr(cli, "_at_terminal", lambda: False)
    keys.save("CTFD_TOKEN_EXAMPLE_CTF", OLD_SECRET, path=tmp_path / "keys.env")  # last year's; its folder was deleted
    folder = tmp_path / "example"
    result = run(str(folder), *CTFD)
    assert result.exit_code == 0, result.output
    assert load_profile(folder / "event.toml")[0].token_env == "CTFD_TOKEN_EXAMPLE_CTF_2"
    assert ("token: CTFD_TOKEN_EXAMPLE_CTF is set in your keys file, and no event of yours says it is the token for ctf.example.net, "
            "so it is not used for this event") in result.output
    assert "token: not set yet. Put CTFD_TOKEN_EXAMPLE_CTF_2=<your CTFd access token> in" in result.output
    assert "--token-env NAME" in result.output and "--token-stdin" in result.output  # how to hand it over, away from a terminal
    assert keys.load_keys(tmp_path / "keys.env") == {"CTFD_TOKEN_EXAMPLE_CTF": OLD_SECRET} and OLD_SECRET not in result.output


def test_an_event_at_the_same_site_as_one_set_up_before_uses_that_sites_token_again(tmp_path, monkeypatch, setup):
    monkeypatch.setattr(cli, "_at_terminal", lambda: False)
    old_event(tmp_path, url="https://ctf.example.net/")
    folder = tmp_path / "again"
    result = run(str(folder), *CTFD)
    assert result.exit_code == 0, result.output
    assert load_profile(folder / "event.toml")[0].token_env == "CTFD_TOKEN_EXAMPLE_CTF"
    assert ("token: CTFD_TOKEN_EXAMPLE_CTF is already set in your keys file: it is the token for ctf.example.net, "
            "as an event of yours there says") in result.output
    assert keys.load_keys(tmp_path / "keys.env") == {"CTFD_TOKEN_EXAMPLE_CTF": OLD_SECRET} and OLD_SECRET not in result.output


def test_a_token_pasted_with_a_hidden_character_is_asked_for_again_with_the_reason(tmp_path, monkeypatch, setup):
    monkeypatch.setattr(cli, "_at_terminal", lambda: True)
    folder = tmp_path / "example"
    result = run(input=f"Example CTF\n{folder}\ny\n\n1\nctf.example.net\n\n1\n{SECRET}\u200bOPENROUTER_API_KEY=evil\n{SECRET}\n\nn\nn\n")
    assert result.exit_code == 0, result.output
    assert "That token has an invisible character in it (U+200B)" in result.output
    assert keys.load_keys(tmp_path / "keys.env") == {"CTFD_TOKEN_EXAMPLE_CTF": SECRET}
    assert SECRET not in result.output and "evil" not in result.output


# ---------------------------------------------------------------------- checked before anything is written


def test_a_vpn_file_that_is_not_there_stops_start_before_the_event_or_the_token_is_written(tmp_path, monkeypatch, setup):
    monkeypatch.setattr(cli, "_at_terminal", lambda: False)
    monkeypatch.setenv("EXAMPLE_TOKEN", SECRET)
    folder = tmp_path / "example"
    result = run(str(folder), *CTFD, "--token-env", "EXAMPLE_TOKEN", "--vpn", str(tmp_path / "typo.conf"))
    assert result.exit_code == 2 and f"--vpn: {tmp_path / 'typo.conf'}: no such file" in result.output
    assert not folder.exists() and not (tmp_path / "keys.env").exists() and events.known() == []
    vpn_file = tmp_path / "team.conf"
    vpn_file.write_text("[Interface]\n")
    monkeypatch.setattr("ctf_flightdeck.vpn_cli.ensure_tool", lambda kept, **kw: False)  # no package manager, no sudo in a test
    result = run(str(folder), *CTFD, "--token-env", "EXAMPLE_TOKEN", "--vpn", str(vpn_file))  # the corrected command sets it all up
    assert result.exit_code == 0, result.output
    assert (folder / "vpn.conf").read_text() == "[Interface]\n" and (folder / "event.toml").is_file()
    assert keys.load_keys(tmp_path / "keys.env") == {"CTFD_TOKEN_EXAMPLE_CTF": SECRET}


def test_a_vpn_file_of_no_kind_flightdeck_connects_is_refused_before_anything_is_written(tmp_path, monkeypatch, setup):
    monkeypatch.setattr(cli, "_at_terminal", lambda: False)
    notes = tmp_path / "notes.txt"
    notes.write_text("not a VPN file\n")
    result = run(str(tmp_path / "example"), "--name", "X", "--platform", "manual", "--ai-allowed", "--vpn", str(notes))
    assert result.exit_code == 2 and "--vpn: " in result.output and not (tmp_path / "example").exists()


def test_answers_given_for_an_event_that_is_already_set_up_are_said_to_be_unused(tmp_path, monkeypatch, setup):
    monkeypatch.setattr(cli, "_at_terminal", lambda: False)
    folder = tmp_path / "example"
    start.write(folder, start.EventAnswers(name="One", platform="manual"))
    before = (folder / "event.toml").read_text()
    vpn_file = tmp_path / "team.conf"
    vpn_file.write_text("[Interface]\n")
    result = run(str(folder), "--name", "X", "--platform", "manual", "--ai-allowed", "--vpn", str(vpn_file))
    assert result.exit_code == 0, result.output
    assert (f"note: --name, --platform, --vpn were not used: the event is set up already; `flightdeck vpn add {folder} FILE` "
            "keeps a VPN file for it") in result.output
    assert (folder / "event.toml").read_text() == before and not (folder / "vpn.conf").exists()
    plain = run(str(folder))
    assert plain.exit_code == 0 and "already set up" in plain.output and "not used" not in plain.output


def test_a_folder_that_cannot_be_made_stops_start_before_the_token_is_kept(tmp_path, monkeypatch, setup):
    monkeypatch.setattr(cli, "_at_terminal", lambda: False)
    monkeypatch.setenv("EXAMPLE_TOKEN", SECRET)
    (tmp_path / "plainfile").write_text("a file\n")
    result = run(str(tmp_path / "plainfile" / "sub"), *CTFD, "--token-env", "EXAMPLE_TOKEN")
    assert result.exit_code == 2
    assert f"{tmp_path / 'plainfile' / 'sub'} cannot be made: {tmp_path / 'plainfile'} is a file, not a folder" in result.output
    assert not (tmp_path / "keys.env").exists() and SECRET not in result.output


def test_what_stops_an_event_folder_being_made_is_found_without_making_anything(tmp_path):
    (tmp_path / "plainfile").write_text("a file\n")
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o500)
    (tmp_path / "nowhere").symlink_to(tmp_path / "gone")
    start.write(tmp_path / "event", start.EventAnswers(name="One", platform="manual"))
    try:
        assert start.folder_problem(tmp_path / "new" / "deep" / "er") is None and not (tmp_path / "new").exists()
        assert start.folder_problem(tmp_path) is None
        assert start.folder_problem(tmp_path / "plainfile") == f"{tmp_path / 'plainfile'} is a file, not a folder"
        assert "is a file, not a folder" in start.folder_problem(tmp_path / "plainfile" / "sub")
        assert start.folder_problem(tmp_path / "nowhere" / "sub") == f"{tmp_path / 'nowhere' / 'sub'} cannot be made: {tmp_path / 'nowhere'} is a link to nothing"
        assert "is already an event" in start.folder_problem(tmp_path / "event")
        if os.geteuid() != 0:  # root writes anywhere
            assert start.folder_problem(locked / "sub") == f"{locked / 'sub'} cannot be made: you cannot write in {locked}"
            assert start.folder_problem(locked) == f"you cannot write in {locked}"
    finally:
        locked.chmod(0o700)


def test_a_keys_file_that_cannot_be_used_stops_start_before_the_event_is_written(tmp_path, monkeypatch, setup):
    monkeypatch.setattr(cli, "_at_terminal", lambda: False)
    (tmp_path / "keys.env").write_text("OTHER=one\n")
    (tmp_path / "keys.env").chmod(0o644)
    result = run(str(tmp_path / "example"), *CTFD)
    assert result.exit_code == 2 and "chmod 600" in result.output and not (tmp_path / "example").exists()


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
    result = CliRunner().invoke(cli.app, ["init", "--path", str(target)], input="anthropic, openrouter, codingagent\n\nhost\n\n\n")  # no key pasted for either
    assert result.exit_code == 0, result.output
    config = load_config(target)
    assert config.api.provider == "anthropic" and config.fallback is not None and "openrouter" in config.fallback.base_url
    assert "Lanes use anthropic." in result.output and "Error" not in result.output
    assert "flightdeck start" in result.output
