"""Plugins: the manifest, one call to a plugin's program, the board a pull writes, and
`flightdeck plugin`. Every plugin here is synthetic (plugin_kit.py): it answers from a file
in tmp_path and uses no network."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import time
from pathlib import Path

import pytest

from ctf_flightdeck import __version__
from ctf_flightdeck.config import PluginRef
from ctf_flightdeck.plugins import call, manifest
from ctf_flightdeck.plugins.call import CallFailed, Caller, Verdict, child_env
from ctf_flightdeck.plugins.manifest import PluginError

from plugin_kit import TOKEN, calls, challenge, make_plugin, set_replies

URL = "https://ctf.example.test"
KNOWN = "name, api, command, version, description, token"


def run(coro):
    return asyncio.run(coro)


def caller(folder: Path, replies: dict, *, token: str | None = TOKEN, **kw) -> Caller:
    return Caller(manifest.read(make_plugin(folder, replies)), URL, "Quals", token, **kw)


# ---------------------------------------------------------------------- plugin.toml


def good(extra: str = "", *, name: str = "acme", api: str = "api = 1\n", command: str = 'command = ["{python}", "adapter.py"]\n') -> str:
    return f'name = "{name}"\n{api}{command}{extra}'


def test_a_manifest_gives_the_plugin_and_what_flightdeck_runs_for_it(tmp_path):
    root = make_plugin(tmp_path / "acme")
    plugin = manifest.load(PluginRef("acme", root))
    assert plugin == manifest.Plugin(name="acme", version="0.3.1", description="Acme events", api=1,
                                     argv=(sys.executable, "adapter.py"), token=True, root=root.resolve())
    (root / "plugin.toml").write_text(good("token = false\n", command='command = ["run.sh", "--quiet"]\n'))
    script = root / "run.sh"
    script.write_text("#!/bin/sh\n")
    script.chmod(0o755)
    plain = manifest.read(root)
    assert plain.argv == (str(script.resolve()), "--quiet") and plain.token is False and (plain.version, plain.description) == ("", "")
    (root / "plugin.toml").write_text(good(command='command = ["sh", "adapter.sh"]\n'))
    assert manifest.read(root).argv == (shutil.which("sh"), "adapter.sh")  # not in the folder: a program on PATH


def manifest_cases(tmp_path: Path) -> list[tuple[str, str, str]]:
    """(what, plugin.toml, the exact message) for a plugin the config calls acme."""
    path = (tmp_path / "acme").resolve() / "plugin.toml"
    return [
        ("an unknown key", good('comand = ["x"]\n'), f"plugin acme: {path}: unknown key comand (known: {KNOWN})"),
        ("a bad name", good(name="Acme CTF"),
         f"plugin acme: {path}: name must be the platform's name: lower-case letters, digits, - and _, starting with a letter, "
         "at most 32 characters"),
        ("a built-in platform's name", good(name="ctfd"),
         f"plugin acme: {path}: name is ctfd, a platform flightdeck has built in: a plugin cannot take its name"),
        ("no api", good(api=""),
         f"plugin acme: {path}: api is missing: the plugin API it speaks, a whole number (this flightdeck speaks 1)"),
        ("an api that is no number", good(api='api = "1"\n'),
         f"plugin acme: {path}: api must be a whole number: the plugin API it speaks (this flightdeck speaks 1)"),
        ("a later api", good(api="api = 2\n"),
         f"plugin acme speaks plugin API 2, and this flightdeck ({__version__}) speaks 1: update flightdeck, or use the plugin's "
         "release for API 1"),
        # a plugin for a later API may have keys this flightdeck does not know: the API is what is wrong with it
        ("a later api with a key of its own", good("sandbox = true\n", api="api = 2\n"),
         f"plugin acme speaks plugin API 2, and this flightdeck ({__version__}) speaks 1: update flightdeck, or use the plugin's "
         "release for API 1"),
        ("a command outside the folder", good(command='command = ["../run.sh"]\n'),
         "plugin acme: command names a file outside the plugin's folder"),
        ("an absolute command", good(command='command = ["/bin/sh", "adapter.sh"]\n'),
         "plugin acme: command names a file outside the plugin's folder"),
        ("a link out of the folder", good(command='command = ["link-out"]\n'),
         "plugin acme: command names a file outside the plugin's folder"),
        ("a program that is nowhere", good(command='command = ["no-such-program-7731"]\n'),
         "plugin acme: command's program is not in the plugin's folder and not on PATH"),
        ("a file that may not be run", good(command='command = ["adapter.py"]\n'),
         "plugin acme: command's program is a file flightdeck may not run: `chmod +x` it, or start the command with {python}"),
        ("a command that is no list", good(command='command = "python adapter.py"\n'),
         f'plugin acme: {path}: command must be a list of words, like ["{{python}}", "adapter.py"]: what flightdeck runs for each call'),
        ("another name than the config's", good(name="other"),
         f"plugin acme: {path} says another name than [plugins.acme] in your config: the two must match"),
        ("a description that is too long", good(f'description = "{"d" * 201}"\n'),
         f"plugin acme: {path}: description must be text of at most 200 characters"),
        ("a token that is no switch", good('token = "yes"\n'),
         f"plugin acme: {path}: token must be true or false: whether an event on this platform needs a token"),
        ("a file that is not TOML", "name = \n", f"plugin acme: {path}: Invalid value (at line 1, column 8)"),
        ("a file that is too large", good("# " + "x" * 70_000 + "\n"), f"plugin acme: {path}: larger than 64 KiB"),
    ]


@pytest.mark.parametrize("case", range(18))
def test_a_manifest_flightdeck_cannot_use_is_refused_with_its_reason(tmp_path, case):
    what, toml, message = manifest_cases(tmp_path)[case]
    root = make_plugin(tmp_path / "acme", toml=toml)
    outside = tmp_path / "elsewhere.sh"
    outside.write_text("#!/bin/sh\n")
    outside.chmod(0o755)
    (root / "link-out").symlink_to(outside)
    with pytest.raises(PluginError) as caught:
        manifest.load(PluginRef("acme", root))
    assert str(caught.value) == message, what


def test_the_table_of_manifest_cases_is_all_run(tmp_path):
    assert len(manifest_cases(tmp_path)) == 18


def test_a_plugin_folder_without_a_manifest_is_named(tmp_path):
    (tmp_path / "empty").mkdir()
    with pytest.raises(PluginError) as caught:
        manifest.load(PluginRef("acme", tmp_path / "empty"))
    assert str(caught.value) == f"plugin acme: {tmp_path.resolve() / 'empty' / 'plugin.toml'}: no such file"
    with pytest.raises(PluginError, match="^plugin gone: .*plugin.toml: no such file$"):
        manifest.read(tmp_path / "gone")  # no config name: the folder's


def test_no_manifest_error_shows_a_key_or_a_folder_name_as_it_was_written(tmp_path):
    root = make_plugin(tmp_path / "a\x1b[31mcme", toml=good('"\\u001b[2Jkey" = 1\n'))
    with pytest.raises(PluginError) as caught:
        manifest.read(root)
    assert "\x1b" not in str(caught.value) and "^[[2Jkey" in str(caught.value)


# ---------------------------------------------------------------------- the child's environment


def test_child_env_is_the_allow_list_the_api_and_the_token_and_nothing_else():
    parent = {"PATH": "/usr/bin", "HOME": "/home/p", "LANG": "en_US.UTF-8", "https_proxy": "http://127.0.0.1:3128",
              "OPENROUTER_API_KEY": "sk-or-fake", "ANTHROPIC_API_KEY": "sk-ant-fake", "ACME_TOKEN": TOKEN,
              "FLIGHTDECK_KEYS": "/home/p/keys.env", "FLIGHTDECK_PLUGIN_TOKEN": "a stale one", "AWS_SECRET_ACCESS_KEY": "fake"}
    assert child_env(TOKEN, parent) == {"PATH": "/usr/bin", "HOME": "/home/p", "LANG": "en_US.UTF-8",
                                        "https_proxy": "http://127.0.0.1:3128", "FLIGHTDECK_PLUGIN_API": "1",
                                        "FLIGHTDECK_PLUGIN_TOKEN": TOKEN}
    assert child_env(None, parent) == {"PATH": "/usr/bin", "HOME": "/home/p", "LANG": "en_US.UTF-8",
                                       "https_proxy": "http://127.0.0.1:3128", "FLIGHTDECK_PLUGIN_API": "1"}
    assert set(call.ENV_KEEP) == {"PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "SSL_CERT_FILE", "SSL_CERT_DIR",
                                  "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"}


def test_a_plugins_program_runs_without_the_players_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-fake-for-this-test")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake-for-this-test")
    monkeypatch.setenv("ACME_TOKEN", TOKEN)
    keys = tmp_path / "keys.env"  # the keys file is never merged into what a plugin gets
    keys.write_text("OPENAI_API_KEY=sk-fake-from-the-keys-file\n")
    keys.chmod(0o600)
    monkeypatch.setenv("FLIGHTDECK_KEYS", str(keys))
    acme = caller(tmp_path / "acme", {"solved": {"answer": {"solved": []}}})
    assert run(acme.solved()) == set()
    (seen,) = calls(tmp_path / "acme")
    env = seen["env"]
    assert env["FLIGHTDECK_PLUGIN_TOKEN"] == TOKEN and env["FLIGHTDECK_PLUGIN_API"] == "1"
    assert env["PATH"] == os.environ["PATH"]
    own = {"__CF_USER_TEXT_ENCODING"}  # what macOS puts in every process itself
    assert set(env) - own <= {*call.ENV_KEEP, "FLIGHTDECK_PLUGIN_API", "FLIGHTDECK_PLUGIN_TOKEN"}
    assert not any("sk-" in value for value in env.values())
    assert [name for name, value in env.items() if value == TOKEN] == ["FLIGHTDECK_PLUGIN_TOKEN"]
    # the token is in the environment only: not in the request, not on the command line
    assert TOKEN not in json.dumps(seen["request"]) and TOKEN not in " ".join(seen["argv"])
    assert seen["cwd"] == str((tmp_path / "acme").resolve())


def test_a_plugin_that_takes_no_token_gets_none(tmp_path, monkeypatch):
    monkeypatch.setenv("FLIGHTDECK_PLUGIN_TOKEN", "left over in the shell")
    run(caller(tmp_path / "acme", {"solved": {"answer": {"solved": []}}}, token=None).solved())
    assert "FLIGHTDECK_PLUGIN_TOKEN" not in calls(tmp_path / "acme")[0]["env"]


# ---------------------------------------------------------------------- one call


def test_each_call_sends_one_request_and_reads_one_answer(tmp_path):
    listed = [challenge("17", "Warm Up", description=f"the organisers' token is {TOKEN}")]
    acme = caller(tmp_path / "acme", {
        "pull": {"answer": {"challenges": listed, "notes": ["2 challenges are \x1b[31mlocked", f"token {TOKEN}", " "]}},
        "submit": {"answer": {"verdict": "incorrect", "detail": f"no\x1b[2J: {TOKEN}", "tries_left": 2, "retry_after": 30}},
        "solved": {"answer": {"solved": ["17", "23"]}},
    })
    pulled = run(acme.pull(tmp_path / "files", ["9"]))
    assert pulled.notes == ("2 challenges are ^[[31mlocked", "token <token>")
    assert pulled.challenges == ({**listed[0], "description": "the organisers' token is <token>"},)
    assert run(acme.submit("17", "flag{a \ud83d lone surrogate}")) == Verdict("incorrect", "no^[[2J: <token>", 2, 30.0)
    assert run(acme.solved()) == {"17", "23"}
    base = {"api": 1, "event": "Quals", "url": URL}
    assert [seen["request"] for seen in calls(tmp_path / "acme")] == [
        {**base, "op": "pull", "files": str(tmp_path / "files"), "known": ["9"]},
        {**base, "op": "submit", "ref": "17", "flag": "flag{a \ud83d lone surrogate}"},
        {**base, "op": "solved"},
    ]
    set_replies(tmp_path / "acme", {"submit": {"answer": {"verdict": "correct"}}})
    assert run(acme.submit("17", "flag{x}")) == Verdict("correct", "", None, None)


FAILED_CALLS = [
    ({"exit": 1, "stderr": "Traceback\n  first line\nboom {token} \x1b[31mred\n\n"}, "it exited with status 1: boom <token> ^[[31mred"),
    ({"exit": 3}, "it exited with status 3 and wrote nothing to stderr"),
    ({"exit": 2, "answer": {"verdict": "correct"}}, "it exited with status 2 and wrote nothing to stderr"),  # never a verdict
    ({"raw": "not json"}, "its answer is not one JSON object"),
    ({"raw": ""}, "its answer is not one JSON object"),
    ({"raw": '{"verdict": "correct"}{"verdict": "correct"}'}, "its answer is not one JSON object"),
    ({"raw": '["correct"]'}, "its answer is not one JSON object"),
    ({"raw": '{"verdict": "correct", "retry_after": NaN}'}, "its answer is not one JSON object"),
    ({"answer": {"verdict": "correct", "points": 50}}, "its answer has an unknown key points (known: verdict, detail, tries_left, retry_after)"),
    ({"answer": {"verdict": "accepted"}}, "verdict must be one of correct, incorrect, already_solved, rate_limited, unjudged"),
    ({"answer": {}}, "verdict must be one of correct, incorrect, already_solved, rate_limited, unjudged"),
    ({"answer": {"verdict": "incorrect", "tries_left": -1}}, "tries_left must be a whole number, 0 or more"),
    ({"answer": {"verdict": "rate_limited", "retry_after": "soon"}}, "retry_after must be a number of seconds, 0 or more"),
    ({"answer": {"verdict": "incorrect", "detail": 5}}, "detail must be a string"),
    ({"bytes": 1_000_001}, "its answer is larger than 1 MB"),
]


@pytest.mark.parametrize("directive, reason", FAILED_CALLS)
def test_a_call_without_a_well_formed_answer_fails_with_its_reason(tmp_path, directive, reason):
    acme = caller(tmp_path / "acme", {"submit": directive})
    with pytest.raises(CallFailed) as caught:
        run(acme.submit("17", "flag{x}"))
    assert str(caught.value) == reason and caught.value.timed_out is False
    assert TOKEN not in str(caught.value)


@pytest.mark.parametrize("op, directive, reason", [
    ("pull", {"answer": {"challenges": {"17": {}}}}, 'its answer must have "challenges": a list of objects, one for each challenge'),
    ("pull", {"answer": {"challenges": [], "notes": "none"}}, '"notes" must be a list of strings'),
    ("pull", {"answer": {"challenges": [], "locked": 2}}, "its answer has an unknown key locked (known: challenges, notes)"),
    ("solved", {"answer": {"solved": [17]}},
     'its answer must have "solved": a list of refs, each a string of 1 to 128 printable characters: the platform\'s own id for the challenge'),
    ("solved", {"answer": {}},
     'its answer must have "solved": a list of refs, each a string of 1 to 128 printable characters: the platform\'s own id for the challenge'),
])
def test_a_pull_or_a_solved_list_of_the_wrong_shape_fails_the_call(tmp_path, op, directive, reason):
    acme = caller(tmp_path / "acme", {op: directive})
    with pytest.raises(CallFailed) as caught:
        run(acme.pull(tmp_path / "files") if op == "pull" else acme.solved())
    assert str(caught.value) == reason


def gone(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    return False


def test_a_call_that_runs_out_of_time_is_killed_with_everything_it_started(tmp_path):
    acme = caller(tmp_path / "acme", {"submit": {"sleep": 60, "child": True, "answer": {"verdict": "correct"}}}, seconds={"submit": 3.0})
    started = time.monotonic()
    with pytest.raises(CallFailed) as caught:
        run(acme.submit("17", "flag{x}"))
    assert str(caught.value) == "it gave no answer within 3 s" and caught.value.timed_out is True
    assert time.monotonic() - started < 20
    (seen,) = calls(tmp_path / "acme")
    assert gone(seen["pid"])
    deadline = time.monotonic() + 10  # the child it started was in its group: killed, and reaped by init in a moment
    while not gone(seen["child"]) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert gone(seen["child"])


def test_the_time_a_call_may_take_is_per_op():
    assert call.SECONDS == {"pull": 300.0, "submit": 30.0, "solved": 30.0}
    assert call.MAX_STDOUT == {"pull": 8_000_000, "submit": 1_000_000, "solved": 1_000_000}


def test_a_program_that_cannot_be_started_fails_the_call(tmp_path):
    acme = caller(tmp_path / "acme", {})
    shutil.rmtree(tmp_path / "acme")  # the folder went away after the manifest was read
    with pytest.raises(CallFailed, match="^it could not be started "):
        run(acme.solved())
