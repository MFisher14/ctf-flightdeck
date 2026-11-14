"""An event on the http platform: what pre-flight says of its profile, `flightdeck http`, and
whole runs through `prepare_run` against a stand-in in the shape of rCTF (tests/fake_http.py).

The engine's own rules are in test_http_platform.py. Here: the [http] table needs no leave
from the player's config, the token variable must be named for the platform, the plan is
printed before anything runs, and a run pulls, submits and reads the solved list through the
same link a plugin's platform uses. Nothing real is contacted.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import quote

import pytest
from typer.testing import CliRunner

from ctf_flightdeck import http_cli, plugin_cli, preflight_cli
from ctf_flightdeck.config import ConfigError, load_config
from ctf_flightdeck.core.model import ChallengeStatus, LaneState, PendingKind
from ctf_flightdeck.platform.manual import cannot_check, load_board
from ctf_flightdeck.platform.plugin_run import PluginLink
from ctf_flightdeck.preflight import HTTP_BOARD, ProfileError, check, describe, load_profile
from ctf_flightdeck.run import RunError, RunOptions, prepare_run

from fake_ctfd import Reply
from fake_http import AUTH_TOKEN, FLAG_FORMAT, TEAM_TOKEN, FakeRCTF, RTask, answer, login_link, sample
from fake_model import FakeModelServer
from test_event_run import Model, config, log, model_api, play, platform_solves, submit, wait_for  # noqa: F401

TOKEN_VAR = "RCTF_TOKEN"
URL = "https://ctf.example.test"
PRESET = 'preset = "rctf"'
runner = CliRunner()


def event_file(tmp_path: Path, url: str = URL, *, http: str | None = PRESET, platform: str = "http", token_env: str | None = TOKEN_VAR,
               board: str | None = "board", automation: bool = True, extra: str = "", **policies: str) -> Path:
    lines = ["[event]", 'name = "Fake Quals"', f'platform = "{platform}"', f'url = "{url}"', f"flag_format = '{FLAG_FORMAT}'"]
    lines += [f"{key} = '{value}'" for key, value in (("token_env", token_env), ("board", board)) if value is not None]
    lines += ["[rules]", "ai_allowed = true", f"platform_automation = {str(automation).lower()}", 'live_targets = "allowed"']
    if policies:
        lines += ["[policies]", *[f'{stage} = "{policy}"' for stage, policy in policies.items()]]
    if http is not None:
        lines += ["[http]", http]
    path = tmp_path / "event.toml"
    path.write_text("\n".join(lines) + "\n" + extra)
    return path


def checked(tmp_path: Path, *, environ=None, model_config=None, **fields) -> tuple[list[str], list[str]]:
    """(the refusals, the warnings) of check() for an http profile, with no config unless one is given."""
    loaded, chosen = load_profile(event_file(tmp_path, **fields))
    problems = check(loaded, chosen, max_lanes=4, environ={TOKEN_VAR: "set"} if environ is None else environ, model_config=model_config)
    return [p.message for p in problems if p.refuse], [p.message for p in problems if not p.refuse]


# ---------------------------------------------------------------------- pre-flight


@pytest.mark.parametrize("model_config", [None, ConfigError("no config here")])
def test_an_http_profile_needs_no_leave_from_the_players_config_and_its_plan_is_printed(tmp_path, model_config):
    """The table is data, so a profile may carry it (a plugin, which is code, needs the
    config's [plugins] table): what it makes flightdeck send is shown before anything runs."""
    refusals, _ = checked(tmp_path, model_config=model_config)
    assert refusals == []
    loaded, chosen = load_profile(event_file(tmp_path))
    lines = describe(loaded, chosen, environ={TOKEN_VAR: "set"})
    assert lines[0] == f"event     Fake Quals · http (rctf preset) at {URL} · solo"
    assert f"token     ${TOKEN_VAR} (set), sent only to {URL}" in lines
    assert [line for line in lines if line.startswith("http")] == [
        "http      the rctf preset's routes, with the [http] table's own keys on top",
        "http      link      the token variable may hold your login link (its ?token= is taken) or the token as the link writes it "
        "(%2B is read as +)",
        "http      sign in   POST /api/v1/auth/login: your token in the request's body; the answer's $.data.authToken is the session token",
        "http      list      GET /api/v1/challs, with the session token (Authorization: Bearer)",
        "http      files     each address at $.files[*].url: on the event's own address without your token; on another host over "
        "https only, and never with a token",
        "http      submit    POST /api/v1/challs/{ref}/submit, with the session token (Authorization: Bearer): the flag in the "
        "request's body, sent once",
        "http      solved    GET /api/v1/users/me, with the session token (Authorization: Bearer)",
    ]
    assert f"pull      auto     {HTTP_BOARD['auto']}" in lines
    boxed, chosen = load_profile(event_file(tmp_path, http='preset = "rctf2"', extra='\n[instances]\nplugin = "rctf"\n'))
    route = "/api/v2/integrations/challs/{id}/instance, with the session token (Authorization: Bearer): only for an on-demand challenge"
    assert [line for line in describe(boxed, chosen, environ={}) if line.startswith("http      instance")] == [
        f"http      instance  {action} {method} {route} of the board"
        for action, method in (("status", "GET"), ("start", "PUT"), ("renew", "PATCH"), ("stop", "DELETE"))]
    own = '\n[instances]\napi = true\nstart = ["POST", "/x/start"]\nstop = ["POST", "/x/stop"]\nrenew = ["POST", "/x/renew"]\n' \
          'status = ["GET", "/x?c={id}"]\nbody_key = "c"\n'
    routed, chosen = load_profile(event_file(tmp_path, extra=own))
    shown = [line for line in describe(routed, chosen, environ={}) if line.startswith("http      instance")]
    assert [line.split(",")[0] for line in shown] == [  # the paths InstanceClient asks under /api/v1, as it asks them
        "http      instance  status GET /api/v1/x?c={id}", "http      instance  start POST /api/v1/x/start",
        "http      instance  renew POST /api/v1/x/renew", "http      instance  stop POST /api/v1/x/stop"]
    manual, chosen = load_profile(event_file(tmp_path, pull="manual"))
    assert f"pull      manual   {HTTP_BOARD['manual']} (the rules allow auto)" in describe(manual, chosen, environ={})
    assert "it plays the board `flightdeck http pull` wrote" in HTTP_BOARD["manual"]


def test_a_table_written_out_is_named_as_such_and_a_key_under_a_preset_shows_in_the_plan(tmp_path):
    own = 'preset = "rctf"\nfiles_auth = true\n[http.list]\nrequest = ["GET", "/api/v2/challs"]'
    loaded, chosen = load_profile(event_file(tmp_path, http=own))
    lines = describe(loaded, chosen, environ={})
    assert "http      list      GET /api/v2/challs, with the session token (Authorization: Bearer)" in lines
    assert any("on the event's own address with the session token" in line for line in lines)
    written = http_cli.example_profile(routes=True)
    path = tmp_path / "own.toml"
    path.write_text(written)
    loaded, chosen = load_profile(path)
    assert describe(loaded, chosen, environ={})[0] == "event     Example Quals · http (the routes of its [http] table) at https://ctf.example.org · solo"


NOT_NAMED = ("a variable that is not named for this platform (its name is not HTTP_TOKEN and does not start with HTTP_TOKEN_ or "
             "RCTF_), so it may hold another service's or another event's secret")
PROXY = "a proxy setting, whose value is a proxy's address and often the password for it"


@pytest.mark.parametrize("variable, http, why", [
    ("RCTF_TOKEN", PRESET, None),
    ("RCTF_TOKEN_QUALS_2026", PRESET, None),
    ("HTTP_TOKEN", PRESET, None),
    ("HTTP_TOKEN_EXAMPLE", PRESET, None),
    ("CTFD_TOKEN", PRESET, NOT_NAMED),
    ("MY_RCTF_TOKEN", PRESET, NOT_NAMED),
    ("HTTP_EXAMPLE_TOKEN", PRESET, NOT_NAMED),  # HTTP_ alone names no platform: other programs' settings start with it
    ("HTTP_TOKENS", PRESET, NOT_NAMED),
    ("HTTP_PASSWORD", PRESET, NOT_NAMED),
    ("HTTP_AUTHORIZATION", PRESET, NOT_NAMED),  # what a CGI server calls a request's Authorization header
    ("HTTP_COOKIE", PRESET, NOT_NAMED),
    ("HTTP_PROXY", PRESET, PROXY),
    ("HTTP_PROXY_PASSWORD", PRESET, PROXY),
    ("HTTPS_PROXY", PRESET, PROXY),
    ("ALL_PROXY", PRESET, PROXY),
    ("OPENAI_API_KEY", PRESET, "a variable for another service's key"),
    ("GITHUB_TOKEN", PRESET, "a variable for another service's key"),
    ("STRIPE_SECRET_KEY", PRESET, "a name ending in _SECRET_KEY like other services' key variables (HTTP_TOKEN, or a name that starts "
                                  "with HTTP_TOKEN_ or RCTF_, is fine)"),
])
def test_the_token_variable_of_an_http_profile_is_one_named_for_the_platform(tmp_path, variable, http, why):
    """The profile names the variable and the address its value goes to, and it may be a
    teammate's: it cannot name a CTFd token, another service's key, a proxy's address or
    anything else. The value of a refused variable is in no message."""
    value = "http://someone:a-password-that-stays-home@proxy.example.test:8080"
    refusals, warnings = checked(tmp_path, token_env=variable, http=http, environ={variable: value})
    if why is None:
        assert refusals == [] and not any("token" in warning for warning in warnings)
    else:
        assert refusals == [f"event.token_env names {variable}, {why}, not a token for this platform: flightdeck would send its "
                            f"value to {URL}. Name the variable that holds your token for it, like RCTF_TOKEN"]


def test_without_a_preset_only_http_token_names_the_platform(tmp_path):
    routes = http_cli.example_profile(routes=True).split("[http.auth]", 1)[1]
    refusals, _ = checked(tmp_path, token_env="RCTF_TOKEN", http=None, extra="[http.auth]" + routes)
    assert len(refusals) == 1 and "(its name is not HTTP_TOKEN and does not start with HTTP_TOKEN_)" in refusals[0]
    assert refusals[0].endswith("like HTTP_TOKEN")
    refusals, _ = checked(tmp_path, token_env="HTTP_PROXY", http=None, extra="[http.auth]" + routes, environ={"HTTP_PROXY": "x"})
    assert len(refusals) == 1 and PROXY in refusals[0] and refusals[0].endswith("like HTTP_TOKEN")
    for variable in ("HTTP_TOKEN", "HTTP_TOKEN_QUALS"):
        assert checked(tmp_path, token_env=variable, http=None, extra="[http.auth]" + routes, environ={variable: "x"})[0] == []


def test_a_profile_that_names_the_proxy_variable_sends_its_value_nowhere(tmp_path, own_config, monkeypatch):
    """HTTP_PROXY starts with HTTP_ and is no token: its value is a proxy's address, often
    with the password in it, and the sign-in request's body would carry it whole."""
    secret = "http://someone:a-password-that-stays-home@proxy.example.test:8080"
    monkeypatch.setenv("HTTP_PROXY", secret)
    with FakeRCTF(sample()) as fake:
        for command in ("check", "pull"):
            result = invoke(command, event_file(tmp_path, fake.url, token_env="HTTP_PROXY"))
            assert result.exit_code == 2 and f"event.token_env names HTTP_PROXY, {PROXY}, not a token" in result.output
            assert "a-password-that-stays-home" not in result.output
        with FakeModelServer(responder=Model({})) as server, pytest.raises(RunError) as refused:
            options = run_options(tmp_path, fake.url, server, pull="auto", submit="auto")
            event_file(tmp_path, fake.url, token_env="HTTP_PROXY", board=str(tmp_path / "board"), pull="auto", submit="auto")
            prepare_run(options)
        assert PROXY in str(refused.value) and "a-password-that-stays-home" not in str(refused.value)
        assert fake.requests == []


def test_no_secret_the_players_config_names_is_an_http_events_token_whatever_its_name(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text('[api]\nbase_url = "http://127.0.0.1:11434/v1"\nkey_env = "HTTP_MODEL_KEY"\n[models]\nladder = ["local-model"]\n'
                    '[notify]\nwebhook_env = "RCTF_HOOK"\n')
    loaded = load_config(path)
    refusals, _ = checked(tmp_path, token_env="HTTP_MODEL_KEY", model_config=loaded)
    assert refusals == [f"event.token_env names HTTP_MODEL_KEY (api.key_env in your config), a variable for another service's key, not a "
                        f"token for this platform: flightdeck would send its value to {URL}. Name the variable that holds your token "
                        "for it, like RCTF_TOKEN"]
    refusals, _ = checked(tmp_path, token_env="RCTF_HOOK", model_config=loaded)
    assert len(refusals) == 1 and "(notify.webhook_env in your config), the variable that holds your notification webhook's URL" in refusals[0]


def test_what_an_http_profile_must_have_and_what_is_only_a_warning(tmp_path):
    with pytest.raises(ProfileError) as missing:
        load_profile(event_file(tmp_path, http=None))
    assert str(missing.value) == (f'{tmp_path / "event.toml"}: the [http] table is missing: platform = "http" asks the platform by the '
                                  'routes it writes (preset = "rctf", or the platform\'s own: `flightdeck http example` prints one to edit)')
    with pytest.raises(ProfileError) as bad:
        load_profile(event_file(tmp_path, http='preset = "rctf"\n[http.list]\nrequest = ["GET", "https://evil.example.test/x"]'))
    assert str(bad.value).startswith(f'{tmp_path / "event.toml"}: http.list.request: the path must start with / and name a route under event.url')
    assert "evil.example.test" not in str(bad.value)
    refusals, warnings = checked(tmp_path, token_env=None, environ={})
    assert refusals == ['event.token_env is required for platform "http": the name of the environment variable that holds your token '
                        "(the token itself never goes in the profile), like RCTF_TOKEN"]
    refusals, warnings = checked(tmp_path, environ={})
    assert refusals == [] and f"the token variable {TOKEN_VAR} (event.token_env) is not set or is empty: export your token in it" in warnings
    _, warnings = checked(tmp_path, url="http://ctf.example.test")
    assert "event.url is http, not https: your token would cross the network unencrypted" in warnings
    _, warnings = checked(tmp_path, url="http://127.0.0.1:8080")
    assert not any("unencrypted" in warning for warning in warnings)
    _, warnings = checked(tmp_path, pull="manual", submit="manual")
    assert "this run does not use the platform's API: pull and submit are both by hand" in warnings
    refusals, _ = checked(tmp_path, automation=False)
    assert refusals == []  # pull and submit are then by hand: the profile is still one flightdeck plays


def test_a_table_with_no_submit_route_is_refused_only_when_flags_would_go_to_the_platform(tmp_path):
    written = http_cli.example_profile(routes=True)
    head, rest = written.split("[http.submit]", 1)
    no_submit = "[http.auth]" + head.split("[http.auth]", 1)[1] + "[http.solved]" + rest.split("[http.solved]", 1)[1]
    refusals, _ = checked(tmp_path, http=None, token_env="HTTP_TOKEN", extra=no_submit, environ={"HTTP_TOKEN": "x"})
    assert refusals == ['the submit policy "confirm" sends flags to the platform, and the [http] table has no [http.submit] to send them '
                        'by: add it, or set submit = "manual" under [policies]']
    assert checked(tmp_path, http=None, token_env="HTTP_TOKEN", extra=no_submit, environ={"HTTP_TOKEN": "x"}, submit="manual")[0] == []


def test_an_http_table_under_another_platform_does_nothing_and_says_so(tmp_path):
    (tmp_path / "board").mkdir()
    refusals, warnings = checked(tmp_path, platform="manual", token_env=None)
    assert refusals == [] and 'the [http] table does nothing in this run: it is read only for platform = "http"' in warnings


def test_an_http_profile_cannot_send_a_pull_to_a_folder_outside_its_own(tmp_path):
    refusals, _ = checked(tmp_path, board=str(tmp_path.parent / "elsewhere"))
    assert len(refusals) == 1 and refusals[0].startswith("event.board: for the http platform the board is a folder inside the profile's own folder")
    assert refusals[0].endswith("`flightdeck play FOLDER --event EVENT.toml`, `flightdeck http pull EVENT.toml FOLDER`")
    (tmp_path / "board").write_text("a file")
    assert checked(tmp_path)[0] == [f"event.board: {tmp_path / 'board'}: is not a directory"]


def test_no_plugin_can_take_the_name_http(tmp_path):
    """The board's record says which adapter pulled it by name: a plugin called http would be
    taken for the built-in one."""
    path = tmp_path / "config.toml"
    path.write_text(f'[api]\nbase_url = "http://127.0.0.1:11434/v1"\nkey_env = ""\n[models]\nladder = ["m"]\n[plugins.http]\npath = "{tmp_path}"\n')
    with pytest.raises(ConfigError, match="plugins.http: http is a platform flightdeck has built in: a plugin cannot take its name"):
        load_config(path)


def test_flightdeck_preflight_prints_the_plan_of_an_http_profile(tmp_path, monkeypatch):
    monkeypatch.setenv("FLIGHTDECK_CONFIG", str(tmp_path / "no-config-here.toml"))
    monkeypatch.setenv(TOKEN_VAR, "set")
    result = runner.invoke(preflight_cli.app, [str(event_file(tmp_path)), "--config", str(config(tmp_path, "http://127.0.0.1:9/v1")), "--docker"])
    assert result.exit_code == 0, result.output
    out = result.stdout.splitlines()
    assert f"event     Fake Quals · http (rctf preset) at {URL} · solo" in out
    assert "http      submit    POST /api/v1/challs/{ref}/submit, with the session token (Authorization: Bearer): the flag in the request's body, sent once" in out


# ---------------------------------------------------------------------- flightdeck http


def invoke(*args):
    return runner.invoke(http_cli.app, [str(a) for a in args], prog_name="flightdeck http")


@pytest.fixture
def own_config(tmp_path, monkeypatch) -> Path:
    """The player's config for the commands: a file in tmp_path, never the real one."""
    path = tmp_path / "config.toml"
    path.write_text('[api]\nbase_url = "http://127.0.0.1:11434/v1"\nkey_env = ""\n[models]\nladder = ["local-model"]\n')
    monkeypatch.setenv("FLIGHTDECK_CONFIG", str(path))
    return path


@pytest.fixture
def token(monkeypatch):
    monkeypatch.setenv(TOKEN_VAR, TEAM_TOKEN)


@pytest.mark.parametrize("routes", [False, True])
def test_the_example_profile_loads_and_passes_the_check(tmp_path, routes):
    result = invoke("example", *(["--routes"] if routes else []))
    assert result.exit_code == 0 and result.output == http_cli.example_profile(routes)
    path = tmp_path / "event.toml"
    path.write_text(result.output)
    loaded, chosen = load_profile(path)
    variable = "HTTP_TOKEN" if routes else "RCTF_TOKEN"
    assert loaded.token_env == variable and (loaded.http.preset == "rctf") is not routes
    problems = check(loaded, chosen, max_lanes=4, environ={variable: "set"})
    assert [p.message for p in problems if p.refuse] == []
    other = tmp_path / "other"
    other.mkdir()
    preset, _ = load_profile(event_file(other))
    assert {**loaded.http.__dict__, "preset": None} == {**preset.http.__dict__, "preset": None}  # the routes written out are the preset's


def test_http_check_shows_what_each_path_matched_and_submits_nothing(tmp_path, own_config, token):
    with FakeRCTF(sample()) as fake:
        result = invoke("check", event_file(tmp_path, fake.url), "--show", "1")
        assert fake.kinds() == ["login", "challs", "me"]
    assert result.exit_code == 0, result.output
    out = result.stdout.splitlines()
    assert out[0] == f"Fake Quals at {fake.url}: nothing is submitted, no file is downloaded"
    assert "  submit    POST /api/v1/challs/{ref}/submit, with the session token (Authorization: Bearer): the flag in the request's body, sent once" in out
    assert "list     GET /api/v1/challs: HTTP 200, $.data[*] matched 3 challenges" in out
    assert '    name         $.name                     "Warm Up"' in out
    assert "solved   GET /api/v1/users/me: HTTP 200, $.data.solves[*].id matched 1 ref, 1 of them on the list" in out
    assert out[-1] == "every path a pull needs matched; nothing was submitted"
    assert TEAM_TOKEN not in result.output and AUTH_TOKEN not in result.output


def test_http_check_signs_in_with_the_login_link_in_the_token_variable(tmp_path, own_config, monkeypatch):
    """What the docs tell an rCTF player to export: the team's login link, where the token is percent-encoded."""
    with FakeRCTF(sample()) as fake:
        link = login_link(fake.url)
        assert TEAM_TOKEN not in link
        monkeypatch.setenv(TOKEN_VAR, link)
        result = invoke("check", event_file(tmp_path, fake.url))
        assert fake.kinds() == ["login", "challs", "me"] and fake.of("login")[0].json == {"teamToken": TEAM_TOKEN}
        assert result.exit_code == 0, result.output
        assert result.stdout.splitlines()[-1] == "every path a pull needs matched; nothing was submitted"
        assert TEAM_TOKEN not in result.output and link.split("=", 1)[1] not in result.output
        monkeypatch.setenv(TOKEN_VAR, login_link("https://other.example.test"))
        refused = invoke("check", event_file(tmp_path, fake.url))
        assert len(fake.requests) == 3
    assert refused.exit_code == 2 and refused.output == (
        f"flightdeck: the variable event.token_env names holds a link to another site (https://other.example.test, and event.url is "
        f"{fake.url}): flightdeck does not send one site's token to another. Put this event's login link in it, or the token alone "
        f"({TOKEN_VAR})\n")


def test_a_run_refuses_a_login_link_to_another_site_before_the_platform_is_asked(tmp_path, monkeypatch):
    monkeypatch.setenv(TOKEN_VAR, login_link("https://other.example.test"))
    with FakeRCTF(sample()) as fake, FakeModelServer(responder=Model({})) as server:
        with pytest.raises(RunError) as refused:
            rctf_run(tmp_path, fake, server)
        assert fake.requests == []
    assert str(refused.value).startswith("the variable event.token_env names holds a link to another site (https://other.example.test, ")
    assert str(refused.value).endswith(f"({TOKEN_VAR})") and "fake" not in str(refused.value)


def test_http_check_exits_1_for_a_path_that_matches_nothing_and_2_when_the_platform_does_not_answer(tmp_path, own_config, token):
    wrong = 'preset = "rctf"\n[http.list]\nname = "$.title"'
    with FakeRCTF(sample()) as fake:
        result = invoke("check", event_file(tmp_path, fake.url, http=wrong))
        assert result.exit_code == 1 and "    name         $.title                    matched nothing: REQUIRED" in result.output
        assert "flightdeck: 3 paths of the [http] table did not match what a pull needs: see above" in result.output
        fake.started = False
        early = invoke("check", event_file(tmp_path, fake.url))
        assert fake.of("submit") == [] and fake.of("file") == []
    assert early.exit_code == 2
    assert early.output.endswith("flightdeck: GET /api/v1/challs was answered with HTTP 401 (Unauthorized): The event has not started yet.\n")


def test_http_pull_writes_the_board_reads_the_solved_list_and_submits_nothing(tmp_path, own_config, monkeypatch):
    keys = tmp_path / "keys.env"  # the token comes from the keys file
    keys.write_text(f"{TOKEN_VAR}={TEAM_TOKEN}\n")
    keys.chmod(0o600)
    monkeypatch.setenv("FLIGHTDECK_KEYS", str(keys))
    board = tmp_path / "board"
    with FakeRCTF(sample()) as fake:
        event = event_file(tmp_path, fake.url)
        result = invoke("pull", event)
        assert result.exit_code == 0, result.output
        assert result.output == f"pulled into {board}: 3 challenges (misc 2, web 1), 1 listed as solved; nothing was submitted\n"
        assert fake.kinds() == ["login", "challs", "file", "me"]  # one sign-in serves the pull and the solved list
        assert json.loads((board / "plugin.json").read_text()) == {
            "format": 1, "plugin": "http", "url": fake.url, "refs": {"done-before": "done-a4d0", "warm-up": "warm-7f3a", "web-thing": "web-19c2"}}
        assert (board / "warm-up" / "note.txt").read_bytes() == b"a synthetic handout\n"
        assert [item.challenge.id for item in load_board(board).challenges] == ["done-before", "warm-up", "web-thing"]
        fake.add(RTask("new-55aa", "Newer", category="web", files={"more.txt": b"more\n"}))
        again = invoke("pull", event)
        assert again.output == f"pulled into {board}: 4 challenges (misc 2, web 2), 1 new, 1 listed as solved; nothing was submitted\n"
        assert len(fake.of("file")) == 2 and fake.of("submit") == []  # the first file was not fetched a second time
        other = tmp_path / "elsewhere"
        named = invoke("pull", event, other)  # FOLDER: another board folder than the profile's
        assert named.exit_code == 0 and named.output.startswith(f"pulled into {other}: 4 challenges")
    assert TEAM_TOKEN not in (board / "plugin.json").read_text()


def test_http_pull_names_what_was_left_out_and_exits_1(tmp_path, own_config, token):
    with FakeRCTF(sample()[:2]) as fake:
        fake.script("file", Reply(404, "gone"))
        result = invoke("pull", event_file(tmp_path, fake.url))
    assert result.exit_code == 1
    assert f'http: not added: Warm Up: its file "note.txt" could not be fetched: HTTP 404 (Not Found) from {fake.url}\n' in result.output
    assert f"pulled into {tmp_path / 'board'}: 1 challenge (web 1), 0 listed as solved; nothing was submitted\n" in result.output
    assert not (tmp_path / "board" / "warm-up").exists()


def test_http_pull_refuses_a_folder_that_holds_another_board(tmp_path, own_config, token):
    board = tmp_path / "board"
    board.mkdir()
    (board / "plugin.json").write_text(json.dumps({"format": 1, "plugin": "acme", "url": URL, "refs": {}}))
    with FakeRCTF(sample()) as fake:
        result = invoke("pull", event_file(tmp_path, fake.url))
        assert fake.requests == []
    assert result.exit_code == 2
    assert result.output == (f"flightdeck: {board} holds a board pulled by something other than the http adapter or from another address: "
                             "use a new folder\n")


@pytest.mark.parametrize("fields, set_token, message", [
    ({"platform": "manual", "token_env": None}, True,
     'flightdeck: `flightdeck http pull` is for an event profile with platform = "http" and an [http] table; `flightdeck http example` '
     "prints one\n"),
    ({"automation": False}, True, "the event's rules do not allow scripts on the platform, so flightdeck does not ask it\n"),
    ({"token_env": None}, True, 'flightdeck: event.token_env is required for platform "http": the name of the environment variable that '
                                "holds your token\n"),
    ({"token_env": "CTFD_TOKEN"}, True, "Name the variable that holds your token for it, like RCTF_TOKEN\n"),
    ({"token_env": "HTTP_PROXY_PASSWORD"}, True, "Name the variable that holds your token for it, like RCTF_TOKEN\n"),
    ({}, False, f"flightdeck: the token variable {TOKEN_VAR} (event.token_env) is not set or is empty: put {TOKEN_VAR}=<token> in your "
                "keys file or export it, then try again\n"),
    ({"board": None}, True, "flightdeck: name the board folder: `flightdeck http pull EVENT.toml FOLDER`, or set event.board in the profile\n"),
])
def test_http_pull_refuses_before_it_asks_the_platform(tmp_path, own_config, monkeypatch, fields, set_token, message):
    (tmp_path / "board").mkdir()
    monkeypatch.setenv("CTFD_TOKEN", "a-ctfd-token-that-must-stay-home")
    if set_token:
        monkeypatch.setenv(TOKEN_VAR, TEAM_TOKEN)
    with FakeRCTF(sample()) as fake:
        result = invoke("pull", event_file(tmp_path, fake.url, **fields))
        assert fake.requests == []
    assert result.exit_code == 2 and result.output.endswith(message)


def test_the_commands_say_so_when_the_config_was_not_read_and_still_check_the_variables_name(tmp_path, monkeypatch, token):
    monkeypatch.setenv("FLIGHTDECK_CONFIG", str(tmp_path / "no-config-here.toml"))
    with FakeRCTF(sample()) as fake:
        result = invoke("check", event_file(tmp_path, fake.url))
        assert result.exit_code == 0 and "flightdeck: note: your config was not read (" in result.output
        assert "so the token variable is checked by its name alone" in result.output
        refused = invoke("check", event_file(tmp_path, fake.url, token_env="OPENAI_API_KEY"))
    assert refused.exit_code == 2 and "a variable for another service's key" in refused.output


def test_plugin_pull_points_an_http_profile_at_its_own_command(tmp_path, own_config, token):
    result = runner.invoke(plugin_cli.app, ["pull", str(event_file(tmp_path))], prog_name="flightdeck plugin")
    assert result.exit_code == 2
    assert result.output == ('flightdeck: event.platform is "http", which flightdeck has built in: `flightdeck plugin pull` is for an '
                             "event on a plugin's platform; `flightdeck http pull` pulls this one\n")


# ---------------------------------------------------------------------- a whole run


def run_options(tmp_path: Path, url: str, server=None, *, max_lanes: int = 1, **options) -> RunOptions:
    """Options for a run of the rCTF event. The player's config has no [plugins] table: none is needed."""
    policies = {stage: options.pop(stage) for stage in ("pull", "submit") if stage in options}
    path = config(tmp_path, server.base_url if server is not None else None, max_lanes=max_lanes)
    return RunOptions(event=event_file(tmp_path, url, board=str(tmp_path / "board"), **policies), config=path, **options)


def rctf_run(tmp_path: Path, fake: FakeRCTF, server=None, **options):
    return prepare_run(run_options(tmp_path, fake.url, server, **{"pull": "auto", "submit": "auto", **options}))


def http_warnings(run) -> list[str]:
    return [e["text"] for e in log(run) if e["kind"] == "warning" and e["data"].get("source") == "http"]


def lane_for(run, challenge_id: str):
    return next(lane for lane in run.deck.lanes.values() if lane.challenge_id == challenge_id)


def test_a_run_plays_an_rctf_event_from_the_preset_and_a_wrong_flag_is_wrong_and_the_right_one_solves(tmp_path, token):
    with FakeRCTF(sample()) as fake, FakeModelServer(responder=Model({"Warm Up": [submit("t{nope}"), submit("t{warm}")]})) as server:
        run = rctf_run(tmp_path, fake, server)
        assert fake.kinds() == ["login", "challs", "file", "me"]  # one sign-in, the pull with its file, the solved list: before anything starts
        board = tmp_path / "board"
        assert (board / "warm-up" / "note.txt").read_bytes() == b"a synthetic handout\n"
        assert isinstance(run.plug, PluginLink) and run.plug.pulls and run.deck.submitter is run.plug and run.links == [run.plug]
        assert run.plug.refs == {"warm-up": "warm-7f3a", "web-thing": "web-19c2", "done-before": "done-a4d0"}
        assert run.watches_folder and not run.by_hand and run.app(refresh_seconds=None).adder is None  # the platform fills this board

        async def body(run):
            assert run.deck.challenges["done-before"].status is ChallengeStatus.TEAMMATE  # listed as solved: no lane
            assert [lane.challenge_id for lane in run.deck.lanes.values()] == ["warm-up"]
            await wait_for(lambda: run.deck.challenges["warm-up"].status is ChallengeStatus.SOLVED, "the solve")

        play(run, body)
        assert fake.submits() == [("warm-7f3a", "t{nope}"), ("warm-7f3a", "t{warm}")]  # each flag went out once: a 400 is an answer
        assert all(r.headers["authorization"] == f"Bearer {AUTH_TOKEN}" for r in fake.of("submit"))
    submitted = [(e["data"]["flag"], e["data"]["correct"], e["data"]["by"]) for e in log(run) if e["kind"] == "submit"]
    assert submitted == [("t{nope}", False, "platform"), ("t{warm}", True, "platform")]
    assert platform_solves(run) == [("done-before", "your account", True)]
    assert lane_for(run, "warm-up").state is LaneState.SOLVED and http_warnings(run) == [] and run.errors == []
    said = run.notes()
    assert f"flags go to {fake.url} through the http adapter" in said
    assert f"board: 3 challenges from {fake.url} through the http adapter in {board} (3 new); flightdeck pulls again every 300 s" in said
    everything = run.log.path.read_text() + "\n".join(said) + (run.dir / "status.json").read_text() + (board / "plugin.json").read_text()
    assert TEAM_TOKEN not in everything and AUTH_TOKEN not in everything


def test_a_flag_rctf_rate_limits_is_sent_again_after_the_wait_its_429_names(tmp_path, token):
    with FakeRCTF(sample()[:1]) as fake, FakeModelServer(responder=Model({"Warm Up": [submit("t{warm}")]})) as server:
        run = rctf_run(tmp_path, fake, server)
        fake.limited, fake.time_left = 2, 4000
        waits: list[float] = []

        async def nap(seconds: float) -> None:
            waits.append(seconds)

        run.plug.sleep = nap

        async def body(run):
            await wait_for(lambda: run.deck.challenges["warm-up"].status is ChallengeStatus.SOLVED, "the solve")

        play(run, body)
        assert fake.submits() == [("warm-7f3a", "t{warm}")] * 3 and waits == [5.0, 5.0]  # timeLeft in milliseconds, and a second
    assert http_warnings(run) == []


def test_a_run_on_rctf_v2_starts_a_challenges_instance_with_the_sign_ins_session_and_stops_it_on_the_solve(tmp_path, token):
    """The rctf2 preset marks the challenge with an instancer on-demand; [instances] plugin =
    "rctf" starts it before its lane works it, by its string id and with the same session as
    the pull's, hands the lane its address, and stops it once it is solved."""
    from fake_http import Instancer

    tasks = [RTask("box-7f3a", "Boxed", category="pwn", flag="t{boxed}", instancer=Instancer(slow=1)),
             RTask("plain-19c2", "Plain", flag="t{plain}")]
    model = Model({"Boxed": [submit("t{boxed}")], "Plain": [submit("t{plain}")]})
    with FakeRCTF(tasks, v2=True) as fake, FakeModelServer(responder=model) as server:
        event = event_file(tmp_path, fake.url, http='preset = "rctf2"', board=str(tmp_path / "board"), pull="auto", submit="auto",
                           extra='\n[instances]\nplugin = "rctf"\n')
        run = prepare_run(RunOptions(event=event, config=config(tmp_path, server.base_url, max_lanes=2)))
        run.instances.every = 0.05
        assert json.loads((tmp_path / "board" / "boxed" / "challenge.json").read_text())["instance"] == "on-demand"
        assert any(note.startswith("instances: flightdeck starts a challenge's instance on the platform before a lane works it (1 on")
                   for note in run.notes())

        async def body(run):
            await wait_for(lambda: run.deck.challenges["boxed"].status is ChallengeStatus.SOLVED, "the boxed challenge solved")
            # the run's own word that it is stopped (the stop's answer read), not only the fake's: the run ends after this
            await wait_for(lambda: fake.tasks["box-7f3a"].instancer.status == "stopped" and "boxed" not in run.instances.running,
                           "its instance stopped after the solve")

        play(run, body)
        asked = [(r.method, r.path) for r in fake.of("instance")]
        assert {path for _, path in asked} == {"/api/v2/integrations/challs/box-7f3a/instance"}  # only the on-demand one, by its own id
        assert [m for m, _ in asked if m != "GET"] == ["PUT", "DELETE"]  # one start, one stop
        # the first pull's caller signed in once; the run's own signs in once, and its instancer and its flags share that session
        assert fake.kinds().count("login") == 2 and fake.kinds().index("instance") > fake.kinds().index("login", 1)
        assert {r.headers["authorization"] for r in fake.of("instance") + fake.of("submit")} == {f"Bearer {AUTH_TOKEN}"}
    briefs = {r["json"]["messages"][1]["content"].split("Challenge: ", 1)[1].split(" (", 1)[0]: r["json"]["messages"][1]["content"]
              for r in server.chats()}
    assert "\nLive instance: tcp://pwn-1.chal.example.test:31337" in briefs["Boxed"]
    assert "\nLive instance: none\n" in briefs["Plain"]
    everything = run.log.path.read_text() + "\n".join(run.notes())
    assert TEAM_TOKEN not in everything and AUTH_TOKEN not in everything


def test_a_kind_the_table_has_no_rule_for_gives_the_flag_back_to_the_player_and_is_never_wrong(tmp_path, token):
    with FakeRCTF(sample()[:1]) as fake, FakeModelServer(responder=Model({"Warm Up": [submit("t{warm}")]})) as server:
        run = rctf_run(tmp_path, fake, server)
        fake.ended = True

        async def body(run):
            await wait_for(lambda: run.deck.lanes and lane_for(run, "warm-up").pending is not None, "the flag, back with the player")
            assert lane_for(run, "warm-up").pending.kind is PendingKind.CONFIRM

        play(run, body)
        assert fake.submits() == [("warm-7f3a", "t{warm}")]
    assert http_warnings(run) == ['the http adapter did not judge t{warm} for Warm Up: the platform gave no verdict on it '
                                  '(HTTP 401, $.kind is "badEnded": The event is over.)']
    assert not any(e["kind"] == "submit" and e["data"].get("correct") is False for e in log(run))
    assert run.deck.challenges["warm-up"].status is not ChallengeStatus.SOLVED


def test_a_pull_or_a_solved_list_that_fails_at_the_start_stops_the_run_and_names_the_adapter(tmp_path, token):
    with FakeRCTF(sample()) as fake, FakeModelServer(responder=Model({})) as server:
        fake.started = False
        with pytest.raises(RunError) as refused:
            rctf_run(tmp_path, fake, server)
        assert str(refused.value) == ("the http adapter could not pull the board: GET /api/v1/challs was answered with HTTP 401 "
                                      "(Unauthorized): The event has not started yet.; nothing was started")
        fake.started = True
        fake.script("me", answer(500, "badUnknown", "a server error"))
        with pytest.raises(RunError) as refused:
            rctf_run(tmp_path, fake, server)
        assert str(refused.value) == ("could not read the solved list from the http adapter: GET /api/v1/users/me was answered with "
                                      "HTTP 500 (Internal Server Error): a server error; nothing was started")
        assert server.chats() == [] and fake.submits() == []


def test_a_token_that_is_not_set_stops_the_run_before_the_platform_is_asked(tmp_path, monkeypatch):
    monkeypatch.delenv(TOKEN_VAR, raising=False)
    with FakeRCTF(sample()) as fake, FakeModelServer(responder=Model({})) as server:
        with pytest.raises(RunError) as refused:
            rctf_run(tmp_path, fake, server)
        assert fake.requests == []
    assert str(refused.value) == (f"the token variable {TOKEN_VAR} (event.token_env) is not set or is empty: put {TOKEN_VAR}=<token> in "
                                  "your keys file or export it, then start play again")


def test_under_pull_manual_the_run_plays_the_board_http_pull_wrote_and_refuses_one_it_did_not(tmp_path, own_config, token):
    with FakeRCTF(sample()) as fake, FakeModelServer(responder=Model({})) as server:
        board = tmp_path / "board"
        with pytest.raises(RunError) as refused:
            rctf_run(tmp_path, fake, server, pull="manual")
        assert str(refused.value) == (f"{board} was not pulled by the http adapter, so flightdeck has nowhere to send its flags: "
                                      "`flightdeck http pull EVENT.toml` first, or set policies.pull to auto or confirm")
        assert invoke("pull", event_file(tmp_path, fake.url, board=str(board))).exit_code == 0
        before = len(fake.of("challs"))
        run = rctf_run(tmp_path, fake, server, pull="manual")
        try:
            assert len(fake.of("challs")) == before and not run.plug.pulls
            assert sorted(item.challenge.id for item in run.board.challenges) == ["done-before", "warm-up", "web-thing"]
            assert any(note.startswith(f"board: 3 challenges in {board}, as `flightdeck http pull` wrote it") for note in run.notes())
        finally:
            run.close()


def test_a_profile_that_uses_the_platform_for_nothing_plays_as_a_by_hand_board_and_asks_it_nothing(tmp_path):
    """pull and submit both by hand: no token is read and no request is made."""
    (tmp_path / "board").mkdir()
    with FakeRCTF(sample()) as fake, FakeModelServer(responder=Model({})) as server:
        run = rctf_run(tmp_path, fake, server, pull="manual", submit="manual")
        try:
            assert run.plug is None and run.links == [] and run.by_hand and run.deck.verify is cannot_check
            assert "event profile: this run does not use the platform's API: pull and submit are both by hand" in run.notes()
        finally:
            run.close()
        assert fake.requests == []


def test_answers_cannot_be_checked_against_a_file_when_flags_go_through_the_http_adapter(tmp_path, token, model_api):
    answers = tmp_path / "answers.json"
    answers.write_text("{}")
    with FakeRCTF(sample()) as fake:
        with pytest.raises(RunError) as refused:
            prepare_run(RunOptions(**{**run_options(tmp_path, fake.url, pull="auto", submit="auto").__dict__, "answers": answers}))
        assert fake.requests == []
    assert str(refused.value) == ("--answers checks flags against a file, and this event checks them on its platform, through the http "
                                  "adapter: drop --answers")


def test_a_coding_agent_lane_on_an_http_event_shows_the_login_link_and_the_token_in_it_by_their_names(tmp_path, monkeypatch):
    """The event's variable holds the team's login link (auth.link_param), exported in the
    player's shell: a host lane can read it. The link, the token taken out of it and the token
    as a link writes it are secrets the run holds, each shown as [NAME] wherever the lane
    prints it (here the fake CLI echoes all three), in the run's events and transcripts too."""
    from test_external import Fake

    encoded = quote(TEAM_TOKEN, safe="")
    assert encoded != TEAM_TOKEN  # the token has + / =, so the two forms differ
    path = [d for d in os.environ.get("PATH", "").split(os.pathsep)
            if d and not any(os.access(os.path.join(d, cli), os.X_OK) for cli in ("claude", "codex"))]
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-anthropic-credential-for-tests")
    agent = None
    try:
        with FakeRCTF(sample()) as fake:
            link = login_link(fake.url)
            monkeypatch.setenv(TOKEN_VAR, link)
            agent = Fake(tmp_path, {"turns": [{"calls": [{"tools": [{"bash": f"echo token '{link}' '{TEAM_TOKEN}' '{encoded}'"}]}]}]})
            monkeypatch.setenv("PATH", os.pathsep.join([str(agent.bin), *path]))
            run = rctf_run(tmp_path, fake, agent="claude", runtime="host")

            async def body(run):
                (lane,) = run.deck.lanes.values()
                await wait_for(lambda: any(a.output.startswith("token ") for a in lane.actions), "the step")

            play(run, body)
    finally:
        if agent is not None:
            agent.kill_leftovers()
    (lane,) = run.deck.lanes.values()
    assert [a.output for a in lane.actions if a.output.startswith("token ")] == [
        f"token [{TOKEN_VAR}] [{TOKEN_VAR}_DECODED] [{TOKEN_VAR}_ENCODED]"]
    for kept in (run.log.path, *(run.dir / "lanes").iterdir()):
        text = kept.read_text()
        assert TEAM_TOKEN not in text and encoded not in text, kept.name
