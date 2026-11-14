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
    answers = f"Example CTF 2026\n{folder}\ny\n1\nctf.example.org\nEX\n2\n{SECRET}\n\nn\ny\n"
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
    result = run(input=f"Example CTF\n{folder}\ny\nctfd\nhttps://ctf.example.org\n\n1\n\n\nn\n")
    assert result.exit_code == 0, result.output
    assert "token: not set yet. Put CTFD_TOKEN_EXAMPLE_CTF=<your CTFd access token> in" in result.output
    assert f"play: flightdeck play {folder}" in result.output and setup == []


def test_a_by_hand_event_starts_empty_says_how_to_add_a_challenge_and_launches(tmp_path, monkeypatch, setup):
    monkeypatch.setattr(cli, "_at_terminal", lambda: True)
    folder = tmp_path / "example"
    result = run(input=f"Example CTF\n{folder}\ny\n2\n\n\nn\ny\n")
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
    result = run(input=f"Example CTF\n{folder}\ny\n2\n\n\ny\nn\n")
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
    monkeypatch.setenv("EXAMPLE_TOKEN", SECRET)
    folder = tmp_path / "example"
    result = run(str(folder), "--name", "Example CTF", "--platform", "ctfd", "--url", "https://ctf.example.org", "--flag", "EX", "--ai-allowed",
                 "--token-env", "EXAMPLE_TOKEN")
    assert result.exit_code == 0, result.output
    assert f"token: saved in {tmp_path / 'keys.env'} as CTFD_TOKEN_EXAMPLE_CTF" in result.output
    assert keys.load_keys(tmp_path / "keys.env") == {"CTFD_TOKEN_EXAMPLE_CTF": SECRET}
    assert "flag format: flags look like EX{...}" in result.output
    assert load_profile(folder / "event.toml")[1].submit is Policy.CONFIRM
    assert f"play: flightdeck play {folder}" in result.output and setup == [] and SECRET not in result.output


# ---------------------------------------------------------------------- the token: handed over without a prompt


CTFD = ("--name", "Example CTF", "--platform", "ctfd", "--url", "https://ctf.example.org", "--ai-allowed")


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
    assert by_hand.exit_code == 2 and "--token-env is for --platform ctfd" in by_hand.output
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
    ("https://ctf.example.org", "ctf.example.org:443"), ("https://CTF.Example.org:443/path", "ctf.example.org:443"),
    ("https://ctf.example.org.", "ctf.example.org:443"), ("http://ctf.example.org", "ctf.example.org:80"),
    ("https://ctf.example.org:8443", "ctf.example.org:8443"), ("https://ctf-example.org", "ctf-example.org:443"),
    ("ftp://ctf.example.org", None), ("ctf.example.org", None), ("", None), (None, None), ("https://a:notaport", None),
])
def test_a_site_is_an_addresses_host_and_port(url, site):
    assert start.site_of(url) == site


def test_the_token_variable_is_the_first_that_is_this_sites_or_nobodys(tmp_path):
    here, there = "https://ctf.example.org", "https://old.example.org"
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
    assert stale.passed == (f"{base} is set in your environment, and no event of yours says it is the token for ctf.example.org",)
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
    result = run(input=f"Example CTF!\n{folder}\ny\n1\nctf.example.org\nEX\n1\n{SECRET}\n\nn\nn\n")
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
    assert ("token: CTFD_TOKEN_EXAMPLE_CTF is set in your keys file, and no event of yours says it is the token for ctf.example.org, "
            "so it is not used for this event") in result.output
    assert "token: not set yet. Put CTFD_TOKEN_EXAMPLE_CTF_2=<your CTFd access token> in" in result.output
    assert "--token-env NAME" in result.output and "--token-stdin" in result.output  # how to hand it over, away from a terminal
    assert keys.load_keys(tmp_path / "keys.env") == {"CTFD_TOKEN_EXAMPLE_CTF": OLD_SECRET} and OLD_SECRET not in result.output


def test_an_event_at_the_same_site_as_one_set_up_before_uses_that_sites_token_again(tmp_path, monkeypatch, setup):
    monkeypatch.setattr(cli, "_at_terminal", lambda: False)
    old_event(tmp_path, url="https://ctf.example.org/")
    folder = tmp_path / "again"
    result = run(str(folder), *CTFD)
    assert result.exit_code == 0, result.output
    assert load_profile(folder / "event.toml")[0].token_env == "CTFD_TOKEN_EXAMPLE_CTF"
    assert ("token: CTFD_TOKEN_EXAMPLE_CTF is already set in your keys file: it is the token for ctf.example.org, "
            "as an event of yours there says") in result.output
    assert keys.load_keys(tmp_path / "keys.env") == {"CTFD_TOKEN_EXAMPLE_CTF": OLD_SECRET} and OLD_SECRET not in result.output


def test_a_token_pasted_with_a_hidden_character_is_asked_for_again_with_the_reason(tmp_path, monkeypatch, setup):
    monkeypatch.setattr(cli, "_at_terminal", lambda: True)
    folder = tmp_path / "example"
    result = run(input=f"Example CTF\n{folder}\ny\n1\nctf.example.org\n\n1\n{SECRET}\u200bOPENROUTER_API_KEY=evil\n{SECRET}\n\nn\nn\n")
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
    result = CliRunner().invoke(cli.app, ["init", "--path", str(target)], input="anthropic, openrouter, codingagent\n\nhost\n")
    assert result.exit_code == 0, result.output
    config = load_config(target)
    assert config.api.provider == "anthropic" and config.fallback is not None and "openrouter" in config.fallback.base_url
    assert "Lanes use anthropic." in result.output and "Error" not in result.output
    assert "flightdeck start" in result.output
