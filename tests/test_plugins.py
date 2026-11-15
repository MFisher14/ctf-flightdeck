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
from typer.testing import CliRunner

from ctf_flightdeck import __version__, cli, plugin_cli
from ctf_flightdeck.config import PluginRef, load_config
from ctf_flightdeck.keys import keys_file_named
from ctf_flightdeck.platform.manual import load_board
from ctf_flightdeck.plugins import board as boards
from ctf_flightdeck.plugins import call, manifest
from ctf_flightdeck.plugins.call import CallFailed, Caller, Verdict, child_env
from ctf_flightdeck.plugins.manifest import PluginError

from plugin_kit import TOKEN, calls, challenge, make_plugin, set_replies
from serving import Serving

runner = CliRunner()
URL = "https://ctf.example.test"
CONFIG = '[api]\nbase_url = "http://127.0.0.1:11434/v1"\nkey_env = ""\n\n[models]\nladder = ["local-model"]\n\n[lanes]\nruntime = "host"\n'
KNOWN = "name, api, command, version, description, token"


def run(coro):
    return asyncio.run(coro)


def invoke(*args, **kw):
    return runner.invoke(plugin_cli.app, [str(a) for a in args], prog_name="flightdeck plugin", **kw)


def caller(folder: Path, replies: dict, *, token: str | None = TOKEN, **kw) -> Caller:
    return Caller(manifest.read(make_plugin(folder, replies)), URL, "Quals", token, **kw)


@pytest.fixture
def config(tmp_path: Path, monkeypatch) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(CONFIG)
    monkeypatch.setenv("FLIGHTDECK_CONFIG", str(path))
    return path


def enabled(config: Path, folder: Path, name: str = "acme") -> None:
    config.write_text(config.read_text() + f'\n[plugins.{name}]\npath = "{folder}"\n')


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


def test_a_caller_says_a_pull_is_running_while_a_submit_waits_behind_it(tmp_path):
    """Calls never overlap (docs/PLUGINS.md): a submit waits for the pull, and `running` says
    what it waits for, so a run can say so on the lane."""
    acme = caller(tmp_path / "acme", {"pull": {"sleep": 1, "answer": {"challenges": []}}, "submit": {"answer": {"verdict": "correct"}}})

    async def main():
        assert acme.running is None
        pulling = asyncio.create_task(acme.pull(tmp_path / "files"))
        while acme.running is None:
            await asyncio.sleep(0.01)
        assert acme.running == "pull"
        verdict = await acme.submit("17", "flag{x}")
        assert pulling.done() and acme.running is None
        return verdict

    assert run(main()) == Verdict("correct", "", None, None)
    assert [seen["request"]["op"] for seen in calls(tmp_path / "acme")] == ["pull", "submit"]
    set_replies(tmp_path / "acme", {"submit": {"exit": 1}})
    with pytest.raises(CallFailed):
        run(acme.submit("17", "flag{x}"))
    assert acme.running is None  # a call that fails holds nothing


def test_the_time_a_call_may_take_is_per_op():
    assert call.SECONDS == {"pull": 300.0, "submit": 30.0, "solved": 30.0}
    assert call.MAX_STDOUT == {"pull": 8_000_000, "submit": 1_000_000, "solved": 1_000_000}


def test_a_program_that_cannot_be_started_fails_the_call(tmp_path):
    acme = caller(tmp_path / "acme", {})
    shutil.rmtree(tmp_path / "acme")  # the folder went away after the manifest was read
    with pytest.raises(CallFailed, match="^it could not be started "):
        run(acme.solved())


# ---------------------------------------------------------------------- the board a pull writes


def pull(folder: Path, board: Path, replies: dict, *, name: str = "acme", url: str = URL) -> boards.Written:
    plugin = manifest.read(make_plugin(folder, replies, name=name))
    return run(boards.pull_into(Caller(plugin, url, "Quals", TOKEN), board, plugin=name, url=url))


def test_a_pull_writes_a_board_the_folder_board_loader_reads(tmp_path):
    board = tmp_path / "quals" / "board"
    written = pull(tmp_path / "acme", board, {"pull": {
        "write": {"17/chal.zip": "zip bytes", "23/notes/readme.txt": "read me"},
        "answer": {"notes": ["2 challenges are locked"], "challenges": [
            challenge("17", "Warm Up", files=["17/chal.zip"], solves=3, max_attempts=5),
            challenge("23", "Web Thing", category="Web Exploitation", points=250, files=["23/notes/readme.txt"],
                      urls=["https://chal.example.test:8443"]),
            {"ref": "31", "name": "Bare"},
        ]},
    }})
    assert (written.added, written.problems, written.notes) == (["warm-up", "web-thing", "bare"], [], ["2 challenges are locked"])
    loaded = load_board(board)
    by_id = {item.challenge.id: item for item in loaded.challenges}
    assert sorted(by_id) == ["bare", "warm-up", "web-thing"]
    warm = by_id["warm-up"].challenge
    assert (warm.name, warm.category, warm.points, warm.solves, warm.max_attempts, warm.files) == ("Warm Up", "misc", 100, 3, 5, ("chal.zip",))
    assert (board / "warm-up" / "chal.zip").read_text() == "zip bytes"
    web = by_id["web-thing"]
    assert (web.challenge.category, web.challenge.points, web.urls) == ("web", 250, ("https://chal.example.test:8443",))
    assert (board / "web-thing" / "readme.txt").read_text() == "read me"
    assert (by_id["bare"].challenge.category, by_id["bare"].challenge.points) == ("misc", 0)  # what the plugin left out
    assert json.loads((board / "plugin.json").read_text()) == {
        "format": 1, "plugin": "acme", "url": URL, "refs": {"bare": "31", "warm-up": "17", "web-thing": "23"}}
    assert boards.load_refs(board, plugin="acme", url=URL + "/") == {"bare": "31", "warm-up": "17", "web-thing": "23"}
    # the plugin was handed a staging folder beside the board, and nothing of it is left
    files = Path(calls(tmp_path / "acme")[0]["request"]["files"])
    assert files.parent.parent == board.parent.resolve() and not files.parent.exists()
    assert sorted(entry.name for entry in board.parent.iterdir()) == ["board"]


def test_a_challenge_that_does_not_pass_is_left_out_and_named_while_the_others_land(tmp_path):
    board = tmp_path / "board"
    (tmp_path / "secret.txt").write_text("the player's own file")
    written = pull(tmp_path / "acme", board, {"pull": {
        "write": {"ok.txt": "fine", "one/twin.txt": "1", "two/twin.txt": "2"},
        "answer": {"challenges": [
            challenge("1", "Climbs Out", files=["../secret.txt"]),
            challenge("2", "Absolute", files=[str(tmp_path / "secret.txt")]),
            challenge("3", "Not There", files=["missing.bin"]),
            challenge("4", "Extra Key", flag="flag{leaked}"),
            challenge("5", "Bad Points", points="many"),
            challenge("6", "Bad \x1b[31mUrl", urls=["https://chal.example.test/path"]),
            challenge("", "No Ref"),
            {"ref": "8"},
            challenge("9", "Twins", files=["one/twin.txt", "two/twin.txt"]),
            challenge("10", "Fine", files=["ok.txt"]),
            challenge("10", "Fine Again"),
        ]},
    }})
    assert written.added == ["fine"]
    assert written.problems == [
        'Climbs Out: "files"[0] must be a relative path inside the files folder the pull was given, with no ..',
        'Absolute: "files"[0] must be a relative path inside the files folder the pull was given, with no ..',
        'Not There: "files"[0] names a file the plugin did not put in the files folder',
        "Extra Key: unknown key flag (known: ref, name, category, points, description, files, urls, solves, max_attempts, instance)",
        'Bad Points: "points" must be a whole number, 0 or more',
        'Bad ^[[31mUrl: "urls"[0] must be an http:// or https:// origin, scheme://host[:port], or a TCP service, tcp://host:port '
        "(what `nc host port` reaches): in printable ASCII with no spaces, and with no path, query or user name; a host that ends "
        "in a number must be an IPv4 address, four numbers from 0 to 255",
        'No Ref: "ref" must be a string of 1 to 128 printable characters: the platform\'s own id for the challenge',
        '8: "name" must be a non-empty string',
        'Twins: "files"[1] has the name of another file of the challenge',
        "Fine Again: its ref is another challenge's in the same pull",
    ]
    assert [item.challenge.id for item in load_board(board).challenges] == ["fine"]
    assert sorted(entry.name for entry in board.iterdir()) == ["fine", "plugin.json"]
    assert (tmp_path / "secret.txt").read_text() == "the player's own file"
    assert boards.load_refs(board, plugin="acme", url=URL) == {"fine": "10"}  # the ones left out are asked for again


def test_a_link_the_plugin_left_in_the_files_folder_is_never_followed(tmp_path):
    board = tmp_path / "board"
    secret = tmp_path / "secret.txt"
    secret.write_text("the player's own file")
    folder = make_plugin(tmp_path / "acme")
    # a plugin that links to a file of the player's instead of downloading one
    (folder / "adapter.py").write_text(
        "import json, os, sys\n"
        "req = json.load(sys.stdin)\n"
        f"os.symlink({str(secret)!r}, os.path.join(req['files'], 'handout.txt'))\n"
        "json.dump({'challenges': [{'ref': '1', 'name': 'Linked', 'files': ['handout.txt']}]}, sys.stdout)\n")
    written = run(boards.pull_into(Caller(manifest.read(folder), URL, "Quals", TOKEN), board, plugin="acme", url=URL))
    assert written.added == [] and written.problems == ['Linked: "files"[0] is a link or inside one; flightdeck does not follow links']
    assert load_board(board, empty_ok=True).challenges == ()


def test_a_name_with_no_ascii_letters_gets_its_id_from_the_ref_and_a_taken_id_is_numbered(tmp_path):
    board = tmp_path / "board"
    written = pull(tmp_path / "acme", board, {"pull": {"answer": {"challenges": [
        challenge("17", "\u6311\u6218"), challenge("x/9", "\u2603"), challenge("40", "Same Name"), challenge("41", "Same Name"),
        challenge("42", "same-name"), challenge("\u2603", "\u2603\u2603"),
    ]}}})
    assert written.problems == []
    assert written.added == ["c-17", "c-x-9", "same-name", "same-name-2", "same-name-3", "c"]
    assert boards.load_refs(board, plugin="acme", url=URL) == {
        "c-17": "17", "c-x-9": "x/9", "same-name": "40", "same-name-2": "41", "same-name-3": "42", "c": "\u2603"}
    assert load_board(board).challenges[1].challenge.name == "\u6311\u6218"


def test_a_second_pull_adds_only_what_is_new(tmp_path):
    board = tmp_path / "board"
    first = [challenge("17", "Warm Up", files=["a.txt"]), challenge("23", "Web Thing")]
    assert pull(tmp_path / "acme", board, {"pull": {"write": {"a.txt": "one"}, "answer": {"challenges": first}}}).added == ["warm-up", "web-thing"]
    (board / "warm-up" / "notes.md").write_text("the player's notes")
    later = [*first, challenge("31", "Late One"), challenge("32", "Warm Up")]  # another challenge of a name that is taken
    again = pull(tmp_path / "acme", board, {"pull": {"write": {"a.txt": "changed"}, "answer": {"challenges": later}}})
    assert (again.added, again.problems) == (["late-one", "warm-up-2"], [])
    assert calls(tmp_path / "acme")[-1]["request"]["known"] == ["17", "23"]
    assert sorted(entry.name for entry in board.iterdir()) == ["late-one", "plugin.json", "warm-up", "warm-up-2", "web-thing"]
    assert (board / "warm-up" / "a.txt").read_text() == "one" and (board / "warm-up" / "notes.md").exists()
    assert pull(tmp_path / "acme", board, {"pull": {"answer": {"challenges": later}}}).added == []
    assert len(load_board(board).challenges) == 4


def test_a_pull_that_lands_while_another_was_pulling_keeps_its_refs_and_is_not_added_twice(tmp_path):
    """A run's pull and `flightdeck plugin pull` in another terminal may overlap: the one that
    lands second reads plugin.json again, so it neither adds the other's challenges a second
    time (warm-up-2) nor writes over the other's refs."""
    board = tmp_path / "board"
    listed = [challenge("17", "Warm Up"), challenge("23", "Web Thing")]
    other = Caller(manifest.read(make_plugin(tmp_path / "other", {"pull": {"answer": {"challenges": listed[:1]}}})), URL, "Quals", TOKEN)
    acme = Caller(manifest.read(make_plugin(tmp_path / "acme", {"pull": {"answer": {"challenges": listed}}})), URL, "Quals", TOKEN)
    real = acme.pull

    async def slow_pull(files_dir, known=()):
        landed = await boards.pull_into(other, board, plugin="acme", url=URL)  # lands while this pull is still going
        assert landed.added == ["warm-up"]
        return await real(files_dir, known)

    acme.pull = slow_pull
    written = run(boards.pull_into(acme, board, plugin="acme", url=URL))
    assert (written.added, written.problems) == (["web-thing"], [])
    assert boards.load_refs(board, plugin="acme", url=URL) == {"warm-up": "17", "web-thing": "23"}
    assert sorted(entry.name for entry in board.iterdir()) == ["plugin.json", "warm-up", "web-thing"]


def test_a_pull_lands_only_once_the_board_lock_is_free(tmp_path):
    """The lock is flock on the board folder: another process that holds it (a pull landing)
    keeps this one's challenges out of the board until it lets go."""
    import fcntl
    import threading

    board = tmp_path / "board"
    board.mkdir()
    plugin = manifest.read(make_plugin(tmp_path / "acme", {"pull": {"answer": {"challenges": [challenge("17", "Warm Up")]}}}))
    held = os.open(board, os.O_RDONLY | os.O_DIRECTORY)
    fcntl.flock(held, fcntl.LOCK_EX)
    result: list = []
    worker = threading.Thread(target=lambda: result.append(
        run(boards.pull_into(Caller(plugin, URL, "Quals", TOKEN), board, plugin="acme", url=URL))))
    try:
        worker.start()
        deadline = time.monotonic() + 20
        while not calls(tmp_path / "acme") and time.monotonic() < deadline:
            time.sleep(0.02)
        assert calls(tmp_path / "acme"), "the plugin was never asked"
        worker.join(0.5)
        assert worker.is_alive() and list(board.iterdir()) == []  # it waits for the lock: nothing landed
    finally:
        os.close(held)
    worker.join(20)
    assert result[0].added == ["warm-up"] and boards.load_refs(board, plugin="acme", url=URL) == {"warm-up": "17"}


def test_a_folder_that_is_another_board_is_refused_before_the_plugin_is_asked(tmp_path):
    board = tmp_path / "board"
    listed = {"pull": {"answer": {"challenges": [challenge("17", "Warm Up")]}}}
    pull(tmp_path / "acme", board, listed)
    other = f"{board.resolve()} holds a board pulled by another plugin or from another address: use a new folder"
    with pytest.raises(PluginError) as caught:
        pull(tmp_path / "rival", board, listed, name="rival")
    assert str(caught.value) == other and calls(tmp_path / "rival") == []
    with pytest.raises(PluginError) as caught:
        pull(tmp_path / "acme", board, listed, url="https://elsewhere.example.test")
    assert str(caught.value) == other and len(calls(tmp_path / "acme")) == 1
    with pytest.raises(PluginError) as caught:
        boards.load_refs(board, plugin="rival", url=URL)
    assert str(caught.value) == other
    by_hand = tmp_path / "by-hand"
    (by_hand / "mine").mkdir(parents=True)
    with pytest.raises(PluginError) as caught:
        pull(tmp_path / "acme", by_hand, listed)
    assert str(caught.value) == (f"{by_hand.resolve()} is not empty and holds no plugin.json, so it is not a board the acme plugin "
                                 "pulled: use a new folder")
    with pytest.raises(PluginError) as caught:
        boards.load_refs(by_hand, plugin="acme", url=URL)
    assert str(caught.value) == (f"{by_hand} was not pulled by the acme plugin, so flightdeck has nowhere to send its flags: "
                                 "`flightdeck plugin pull EVENT.toml` first, or set policies.pull to auto or confirm")
    (board / "plugin.json").write_text('{"format": 1, "plugin": "acme", "url": "' + URL + '", "refs": {"warm-up": 17}}')
    with pytest.raises(PluginError, match="is not a plugin.json flightdeck wrote"):
        boards.load_refs(board, plugin="acme", url=URL)


def test_a_pull_that_lists_more_challenges_than_a_board_holds_adds_none(tmp_path):
    """One answer may be 8 MB: without a limit it lists 200,000 challenges, each a folder and
    a rewrite of plugin.json. More than MAX_CHALLENGES is no answer flightdeck uses."""
    board = tmp_path / "board"
    assert call.MAX_CHALLENGES == 1000
    many = [challenge(str(n), f"Challenge {n}") for n in range(call.MAX_CHALLENGES + 1)]
    with pytest.raises(CallFailed) as caught:
        pull(tmp_path / "acme", board, {"pull": {"answer": {"challenges": many}}})
    assert str(caught.value) == ("its answer lists 1,001 challenges, more than the 1,000 flightdeck takes from one pull: nothing "
                                 "was added (a plugin for a larger platform lists the event's own challenges)")
    assert list(board.iterdir()) == [] and sorted(entry.name for entry in tmp_path.iterdir()) == ["acme", "board"]
    written = pull(tmp_path / "acme", board, {"pull": {"answer": {"challenges": many[:40]}}})  # as many as an event has: all land
    assert len(written.added) == 40 and written.problems == []


def test_a_pull_names_the_first_challenges_it_leaves_out_and_counts_the_rest(tmp_path):
    """Each problem is a warning in a run and a line of `plugin pull`: a platform that lists
    thousands of broken challenges gets MAX_PROBLEMS of them named, not thousands of alerts."""
    board = tmp_path / "board"
    assert boards.MAX_PROBLEMS == 20
    broken = [{**challenge(str(n), f"Broken {n}"), "flag": "no such key"} for n in range(75)]
    written = pull(tmp_path / "acme", board, {"pull": {"answer": {"challenges": [challenge("ok", "Fine"), *broken]}}})
    assert written.added == ["fine"] and len(written.problems) == 21
    assert written.problems[0].startswith("Broken 0: unknown key flag") and written.problems[19].startswith("Broken 19: unknown key flag")
    assert written.problems[20] == "55 more challenges were left out too: the first 20 are named, and they may share a cause"
    again = pull(tmp_path / "acme", board, {"pull": {"answer": {"challenges": broken[:21]}}})
    assert again.problems[20] == "1 more challenge was left out too: the first 20 are named, and they may share a cause"


def test_a_pulls_folders_are_written_off_the_loop_that_called_it(tmp_path, monkeypatch):
    """In a run the pull is awaited on the console's loop, which every lane shares: the
    folders are built, read back and moved in a thread, and the loop goes on meanwhile."""
    import threading

    ticked, seen = threading.Event(), []
    real = boards.load_challenge

    def checked(folder):
        ticked.clear()
        seen.append((ticked.wait(3), threading.current_thread() is threading.main_thread()))  # blocks the loop, if it runs on it
        return real(folder)

    monkeypatch.setattr(boards, "load_challenge", checked)
    plugin = manifest.read(make_plugin(tmp_path / "acme", {"pull": {"answer": {"challenges": [challenge("1", "One"), challenge("2", "Two")]}}}))

    async def main():
        async def tick():
            while True:
                await asyncio.sleep(0.01)
                ticked.set()

        beat = asyncio.create_task(tick())
        try:
            return await boards.pull_into(Caller(plugin, URL, "Quals", TOKEN), tmp_path / "board", plugin="acme", url=URL)
        finally:
            beat.cancel()

    written = run(main())
    assert written.added == ["one", "two"] and seen == [(True, False), (True, False)]  # the loop ticked while each folder was read back


def test_a_pull_that_fails_adds_nothing_and_leaves_no_staging_folder(tmp_path):
    board = tmp_path / "board"
    with pytest.raises(CallFailed, match="^it exited with status 1: the platform is down$"):
        pull(tmp_path / "acme", board, {"pull": {"exit": 1, "stderr": "the platform is down\n"}})
    assert sorted(entry.name for entry in tmp_path.iterdir()) == ["acme", "board"] and list(board.iterdir()) == []


# ---------------------------------------------------------------------- flightdeck plugin new


def test_plugin_new_writes_a_plugin_flightdeck_accepts_and_never_writes_over_one(tmp_path):
    result = invoke("new", "harbour-ctf", "--dir", tmp_path)
    assert result.exit_code == 0, result.output
    folder = tmp_path / "harbour-ctf"
    assert sorted(entry.name for entry in folder.iterdir()) == ["adapter.py", "event.example.toml", "plugin.toml"]
    plugin = manifest.read(folder)
    assert (plugin.name, plugin.api, plugin.argv, plugin.token) == ("harbour-ctf", 1, (sys.executable, "adapter.py"), True)
    compile((folder / "adapter.py").read_text(), "adapter.py", "exec")  # it is Python; it is not run
    for op in ('"pull"', '"submit"', '"solved"', "FLIGHTDECK_PLUGIN_TOKEN"):
        assert op in (folder / "adapter.py").read_text()
    from ctf_flightdeck.preflight import load_profile

    profile, _ = load_profile(folder / "event.example.toml")
    assert (profile.platform, profile.plugin, profile.token_env) == ("harbour-ctf", True, "HARBOUR_CTF_TOKEN")
    before = (folder / "adapter.py").read_text()
    (folder / "adapter.py").write_text(before + "# my own routes\n")
    again = invoke("new", "harbour-ctf", "--dir", tmp_path)
    assert again.exit_code == 2 and "is already there: flightdeck does not write over it" in again.output
    assert (folder / "adapter.py").read_text() == before + "# my own routes\n"


def test_the_skeleton_works_as_written_against_a_platform_with_its_placeholder_routes(tmp_path):
    """The adapter `plugin new` writes is run as it is, against a stand-in platform on 127.0.0.1
    that serves the skeleton's placeholder routes: what a player starts from must work."""
    import http.server

    tasks = [{"id": 17, "title": "Warm Up", "category": "misc", "points": 50, "text": "a synthetic task", "solved": True},
             {"id": 23, "title": "Web Thing", "category": "web", "points": 250, "text": "another", "urls": ["http://127.0.0.1:8080"]}]
    seen = []

    class Platform(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def answer(self, body):
            data = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            seen.append((self.path, self.headers.get("Authorization"), None))
            self.answer(tasks)

        def do_POST(self):
            flag = json.loads(self.rfile.read(int(self.headers["Content-Length"])))["flag"]
            seen.append((self.path, self.headers.get("Authorization"), flag))
            self.answer({"status": {"flag{right}": "ok", "flag{again}": "dup", "flag{odd}": "frozen"}.get(flag, "bad")})

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Platform)
    serving = Serving(server, "a-platform")
    try:
        assert invoke("new", "harbour", "--dir", tmp_path).exit_code == 0
        url = f"http://127.0.0.1:{server.server_address[1]}"
        environ = {"PATH": os.environ["PATH"], "NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1"}
        harbour = Caller(manifest.read(tmp_path / "harbour"), url, "Quals", TOKEN, environ=environ)
        written = run(boards.pull_into(harbour, tmp_path / "board", plugin="harbour", url=url))
        assert (written.added, written.problems) == (["warm-up", "web-thing"], [])
        assert boards.load_refs(tmp_path / "board", plugin="harbour", url=url) == {"warm-up": "17", "web-thing": "23"}
        assert load_board(tmp_path / "board").challenges[1].urls == ("http://127.0.0.1:8080",)
        assert run(harbour.submit("17", "flag{right}")) == Verdict("correct", "ok")
        assert run(harbour.submit("17", "flag{wrong}")) == Verdict("incorrect", "bad")
        assert run(harbour.submit("17", "flag{again}")) == Verdict("already_solved", "dup")
        assert run(harbour.submit("23", "flag{odd}")) == Verdict("unjudged", "frozen")  # a word it does not know is no verdict
        assert run(harbour.solved()) == {"17"}
    finally:
        serving.stop()
        server.server_close()
    assert [path for path, _, _ in seen] == ["/api/tasks", "/api/tasks/17/flag", "/api/tasks/17/flag", "/api/tasks/17/flag",
                                             "/api/tasks/23/flag", "/api/tasks"]
    assert {auth for _, auth, _ in seen} == {f"Bearer {TOKEN}"}


@pytest.mark.parametrize("name, why", [
    ("Harbour", "a plugin's name is the platform's name: lower-case letters, digits, - and _, starting with a letter, at most 32 characters"),
    ("ctfd", "ctfd is a platform flightdeck has built in: a plugin cannot take its name"),
])
def test_plugin_new_refuses_a_name_no_platform_can_have(tmp_path, name, why):
    result = invoke("new", name, "--dir", tmp_path)
    assert result.exit_code == 2 and f"flightdeck: {why}" in result.output and list(tmp_path.iterdir()) == []


# ---------------------------------------------------------------------- flightdeck plugin add


def test_plugin_add_shows_the_card_and_stops_with_no_terminal_and_no_yes(tmp_path, config):
    root = make_plugin(tmp_path / "acme")
    result = invoke("add", root)
    assert result.exit_code == 2 and "there is no terminal to ask at" in result.output
    assert config.read_text() == CONFIG
    for line in (
        "  plugin    acme 0.3.1 (plugin API 1): Acme events",
        f"  folder    {root.resolve()}",
        '  provides  platform "acme"   (event.toml: platform = "acme")',
        "  runs      <flightdeck's python> adapter.py   in that folder: for each pull, each flag, and each minute for the solved list",
        "  gets      the event's URL, its token (the variable event.token_env names), the flags it submits",
        "  not given your model API keys or the rest of your environment",
        "  flightdeck does not sandbox a plugin: it runs as you, and can read your files and use the network. Read its files first.",
    ):
        assert line + "\n" in result.output
    assert calls(root) == []  # nothing of the plugin is run to show it


def test_plugin_add_asks_and_no_leaves_the_config_as_it_was(tmp_path, config, monkeypatch):
    monkeypatch.setattr(plugin_cli, "_at_terminal", lambda: True)
    root = make_plugin(tmp_path / "acme")
    for answer in ("n\n", "\n"):
        result = invoke("add", root, input=answer)
        assert result.exit_code == 1 and "Enable it? [y/N]" in result.output and "the plugin was not enabled" in result.output
        assert config.read_text() == CONFIG
    result = invoke("add", root, input="y\n")
    assert result.exit_code == 0, result.output
    assert load_config(config).plugins == {"acme": PluginRef("acme", root.resolve())}
    assert config.read_text().startswith(CONFIG) and f"config: {config} now has [plugins.acme] path = {root.resolve()}" in result.output


def test_plugin_add_with_yes_writes_the_table_and_a_second_add_is_refused(tmp_path, config):
    root = make_plugin(tmp_path / "ac me")  # a folder name with a space in it
    assert invoke("add", root, "--yes").exit_code == 0
    assert load_config(config).plugins["acme"].path == root.resolve()
    assert manifest.load(load_config(config).plugins["acme"]).name == "acme"
    after = config.read_text()
    again = invoke("add", root, "--yes")
    assert again.exit_code == 2 and f"flightdeck: plugins.acme is already in {config}: change its path there" in again.output
    assert config.read_text() == after
    other = make_plugin(tmp_path / "token-free", name="token-free", toml='name = "token-free"\napi = 1\ncommand = ["{python}", "adapter.py"]\ntoken = false\n')
    result = invoke("add", other, "--yes")
    assert result.exit_code == 0 and "  gets      the event's URL, the flags it submits\n" in result.output
    assert sorted(load_config(config).plugins) == ["acme", "token-free"]


def test_plugin_add_needs_a_config_and_a_plugin_it_can_read(tmp_path, config, monkeypatch):
    broken = make_plugin(tmp_path / "broken", toml='name = "acme"\napi = 1\ncomand = ["x"]\n')
    result = invoke("add", broken, "--yes")
    assert result.exit_code == 2 and f"unknown key comand (known: {KNOWN})" in result.output and config.read_text() == CONFIG
    later = make_plugin(tmp_path / "later", toml='name = "acme"\napi = 2\ncommand = ["{python}", "adapter.py"]\n')
    assert invoke("add", later, "--yes").exit_code == 2 and config.read_text() == CONFIG
    monkeypatch.setenv("FLIGHTDECK_CONFIG", str(tmp_path / "none.toml"))
    missing = invoke("add", make_plugin(tmp_path / "acme"), "--yes")
    assert missing.exit_code == 2 and f"flightdeck: there is no config at {tmp_path / 'none.toml'}: run `flightdeck init` first" in missing.output
    assert not (tmp_path / "none.toml").exists()


def test_a_config_that_does_not_load_with_the_plugin_in_it_is_put_back(tmp_path):
    path = tmp_path / "config.toml"
    # [plugins] as an inline table: valid, and a [plugins.acme] table after it is not
    closed = "plugins = {}\n" + CONFIG
    path.write_text(closed)
    with pytest.raises(PluginError, match="^the config did not load with the plugin in it, so it was put back as it was: "):
        manifest.enable(path, "acme", tmp_path / "acme")
    assert path.read_text() == closed
    with pytest.raises(PluginError) as caught:
        manifest.enable(tmp_path / "none.toml", "acme", tmp_path / "acme")
    assert str(caught.value) == f"there is no config at {tmp_path / 'none.toml'}: run `flightdeck init` first"
    path.write_text(CONFIG)
    manifest.enable(path, "acme", tmp_path / 'a "quoted" folder')
    assert load_config(path).plugins["acme"].path == tmp_path / 'a "quoted" folder'
    with pytest.raises(PluginError) as caught:
        manifest.enable(path, "acme", tmp_path / "elsewhere")
    assert str(caught.value) == f"plugins.acme is already in {path}: change its path there"


def test_a_plugins_own_words_are_shown_made_safe(tmp_path, config):
    root = make_plugin(tmp_path / "acme", toml=(
        'name = "acme"\napi = 1\ncommand = ["{python}", "adapter.py", "--mode=\\u001b[2Jx"]\n'
        'version = "1\\u001b[31m"\ndescription = "nice \\u001b[31mred\\u001b[0m\\nplugin"\n'))
    result = invoke("add", root)
    assert "\x1b" not in result.output and "nice ^[[31mred^[[0m" in result.output and "--mode=^[[2Jx" in result.output
    assert "plugin    acme 1^[[31m (plugin API 1): nice" in result.output


# ---------------------------------------------------------------------- flightdeck plugin pull

EVENT = """[event]
name = "Quals"
platform = "acme"
url = "https://ctf.example.test"
token_env = "ACME_TOKEN"
board = "board"

[rules]
ai_allowed = true
platform_automation = {automation}
live_targets = "off"
"""
LISTED = {
    "pull": {"write": {"17/chal.zip": "zip"}, "answer": {"challenges": [
        challenge("17", "Warm Up", files=["17/chal.zip"]), challenge("23", "Web Thing", category="web"), challenge("31", "Late One")]}},
    "solved": {"answer": {"solved": ["23", "99"]}},
}


def event_file(tmp_path: Path, *, automation: bool = True, text: str = EVENT) -> Path:
    folder = tmp_path / "quals"
    folder.mkdir(exist_ok=True)
    path = folder / "event.toml"
    path.write_text(text.replace("{automation}", "true" if automation else "false"))
    return path


def test_plugin_pull_writes_the_board_reads_the_solved_list_and_submits_nothing(tmp_path, config, monkeypatch):
    root = make_plugin(tmp_path / "acme", LISTED)
    enabled(config, root)
    keys = tmp_path / "keys.env"  # the token comes from the keys file; the plugin gets it and no other key
    keys.write_text(f"ACME_TOKEN={TOKEN}\nOPENROUTER_API_KEY=sk-or-fake-for-this-test\n")
    keys.chmod(0o600)
    monkeypatch.setenv("FLIGHTDECK_KEYS", str(keys))
    event = event_file(tmp_path)
    board = tmp_path / "quals" / "board"
    result = invoke("pull", event)
    assert result.exit_code == 0, result.output
    assert result.output == f"pulled into {board}: 3 challenges (misc 2, web 1), 1 listed as solved; nothing was submitted\n"
    assert [seen["request"]["op"] for seen in calls(root)] == ["pull", "solved"]
    for seen in calls(root):
        assert seen["env"]["FLIGHTDECK_PLUGIN_TOKEN"] == TOKEN and seen["request"]["url"] == URL and seen["request"]["event"] == "Quals"
        assert "OPENROUTER_API_KEY" not in seen["env"] and "ACME_TOKEN" not in seen["env"]
    assert [item.challenge.id for item in load_board(board).challenges] == ["late-one", "warm-up", "web-thing"]
    more = [*LISTED["pull"]["answer"]["challenges"], challenge("40", "Newer", category="web")]
    set_replies(root, {**LISTED, "pull": {**LISTED["pull"], "answer": {"challenges": more}}})
    other = tmp_path / "elsewhere"
    again = invoke("pull", event)
    assert again.output == f"pulled into {board}: 4 challenges (misc 2, web 2), 1 new, 1 listed as solved; nothing was submitted\n"
    named = invoke("pull", event, other)  # FOLDER: another board folder than the profile's
    assert named.exit_code == 0 and named.output.startswith(f"pulled into {other}: 4 challenges")
    assert [seen["request"]["op"] for seen in calls(root)] == ["pull", "solved"] * 3


def test_plugin_pull_names_what_was_left_out_and_exits_1(tmp_path, config, monkeypatch):
    root = make_plugin(tmp_path / "acme", {
        "pull": {"answer": {"notes": ["2 challenges are locked"], "challenges": [challenge("17", "Warm Up"), challenge("18", "Odd", points=-1)]}},
        "solved": {"answer": {"solved": []}},
    })
    enabled(config, root)
    monkeypatch.setenv("ACME_TOKEN", TOKEN)
    result = invoke("pull", event_file(tmp_path))
    assert result.exit_code == 1
    assert 'acme: not added: Odd: "points" must be a whole number, 0 or more\n' in result.output
    assert "acme: 2 challenges are locked\n" in result.output
    assert "1 challenge (misc 1), 0 listed as solved; nothing was submitted\n" in result.output


def test_plugin_pull_runs_nothing_when_the_rules_forbid_scripts_on_the_platform(tmp_path, config, monkeypatch):
    root = make_plugin(tmp_path / "acme", LISTED)
    enabled(config, root)
    monkeypatch.setenv("ACME_TOKEN", TOKEN)
    event = event_file(tmp_path, automation=False)
    result = invoke("pull", event)
    assert result.exit_code == 2
    assert (f"flightdeck: rules.platform_automation = false in {event}: the event's rules do not allow scripts on the platform, "
            "so flightdeck does not run the acme plugin for it\n") == result.output
    assert calls(root) == [] and not (tmp_path / "quals" / "board").exists()


def test_plugin_pull_runs_only_a_plugin_the_players_config_allows(tmp_path, config, monkeypatch):
    root = make_plugin(tmp_path / "acme", LISTED)
    monkeypatch.setenv("ACME_TOKEN", TOKEN)
    event = event_file(tmp_path)
    result = invoke("pull", event)
    assert result.exit_code == 2 and calls(root) == []
    assert result.output == ('flightdeck: event.platform is not "ctfd", "manual", "gamemaster" or "http", and names no plugin in your config '
                             "(your config has no [plugins] table). `flightdeck plugin add FOLDER` adds one, after showing you what it runs\n")
    enabled(config, root, name="rival")  # the config allows another name: the profile's word is not shown
    result = invoke("pull", event)
    assert result.exit_code == 2 and "(your config has: rival)" in result.output and "acme" not in result.output and calls(root) == []
    config.write_text(CONFIG)
    enabled(config, root)
    builtin = event_file(tmp_path, text=EVENT.replace('platform = "acme"', 'platform = "manual"'))
    result = invoke("pull", builtin)
    assert result.exit_code == 2 and 'event.platform is "manual", which flightdeck has built in' in result.output and calls(root) == []
    config.write_text("[models\n")
    result = invoke("pull", event_file(tmp_path))
    assert result.exit_code == 2 and calls(root) == []
    assert "event.platform names a plugin's platform, and your config could not be read, so flightdeck cannot tell whether you added it" in result.output


@pytest.mark.parametrize("change, set_token, message", [
    (("token_env = \"ACME_TOKEN\"\n", ""), True,
     'flightdeck: event.token_env is required for platform "acme": the name of the environment variable that holds your token\n'),
    (("url = \"https://ctf.example.test\"\n", ""), True,
     "flightdeck: event.url is required for a plugin's platform: the address its adapter talks to\n"),
    (("board = \"board\"\n", ""), True,
     "flightdeck: name the board folder: `flightdeck plugin pull EVENT.toml FOLDER`, or set event.board in the profile\n"),
    (("", ""), False,
     "flightdeck: the token variable ACME_TOKEN (event.token_env) is not set or is empty: put ACME_TOKEN=<token> in {keys} "
     "or export it, then pull again\n"),
    (("ACME_TOKEN", "OPENAI_API_KEY"), True,
     "flightdeck: event.token_env names OPENAI_API_KEY, a variable for another service's key, not a token for this platform: "
     "flightdeck would hand its value to the acme plugin. Name the variable that holds your token for it, like ACME_TOKEN\n"),
    (("ACME_TOKEN", "MY_API_KEY"), True,
     "flightdeck: event.token_env names MY_API_KEY, a name ending in _API_KEY like other services' key variables (a name that starts "
     "with ACME_ is fine), not a token for this platform: flightdeck would hand its value to the acme plugin. Name the variable that "
     "holds your token for it, like ACME_TOKEN\n"),
])
def test_plugin_pull_refuses_before_it_runs_the_plugin(tmp_path, config, monkeypatch, change, set_token, message):
    root = make_plugin(tmp_path / "acme", LISTED)
    enabled(config, root)
    for name in ("ACME_TOKEN", "OPENAI_API_KEY", "MY_API_KEY"):
        monkeypatch.setenv(name, TOKEN) if set_token else monkeypatch.delenv(name, raising=False)
    result = invoke("pull", event_file(tmp_path, text=EVENT.replace(*change) if change[0] else EVENT))
    assert (result.exit_code, result.output) == (2, message.replace("{keys}", keys_file_named()))
    assert calls(root) == []


def test_plugin_pull_hands_no_variable_that_is_not_named_for_the_plugin(tmp_path, config, monkeypatch):
    root = make_plugin(tmp_path / "acme", LISTED)
    enabled(config, root)
    for name in ("NPM_TOKEN", "CTFD_TOKEN", "DISCORD_WEBHOOK_URL"):
        monkeypatch.setenv(name, "another-secret-for-this-test")
        result = invoke("pull", event_file(tmp_path, text=EVENT.replace("ACME_TOKEN", name)))
        assert result.exit_code == 2 and calls(root) == [], name
        assert f"event.token_env names {name}, a variable that is not named for this platform (its name does not start with ACME_)" in result.output
        assert "another-secret-for-this-test" not in result.output


def test_plugin_pull_warns_before_a_token_crosses_the_network_unencrypted(tmp_path, config, monkeypatch):
    """A run's pre-flight warns of an http address; a pull by hand hands the same token over, and says the same first."""
    root = make_plugin(tmp_path / "acme", LISTED)
    enabled(config, root)
    monkeypatch.setenv("ACME_TOKEN", TOKEN)
    warning = "flightdeck: warning: event.url is http, not https: the token the acme plugin is given would cross the network unencrypted\n"
    result = invoke("pull", event_file(tmp_path, text=EVENT.replace("https://ctf.example.test", "http://ctf.example.test")))
    assert result.exit_code == 0 and result.output.startswith(warning)
    for quiet in ("https://ctf.example.test", "http://127.0.0.1:8000"):  # encrypted, or this machine
        (tmp_path / "quals" / "board").exists() and __import__("shutil").rmtree(tmp_path / "quals" / "board")
        result = invoke("pull", event_file(tmp_path, text=EVENT.replace("https://ctf.example.test", quiet)))
        assert result.exit_code == 0 and "warning" not in result.output, result.output


def test_plugin_pull_writes_nowhere_a_profile_points_outside_its_own_folder(tmp_path, config, monkeypatch):
    """The profile's board is the profile's word. Outside the profile's folder it is refused
    before the plugin runs and before any folder is made; a folder the player names is the player's."""
    root = make_plugin(tmp_path / "acme", LISTED)
    enabled(config, root)
    monkeypatch.setenv("ACME_TOKEN", TOKEN)
    outside = tmp_path / "home" / ".config" / "editor" / "plugin"
    event = event_file(tmp_path, text=EVENT.replace('board = "board"', f'board = "{outside}"'))
    result = invoke("pull", event)
    assert result.exit_code == 2 and calls(root) == [] and not (tmp_path / "home").exists()
    assert result.output.startswith("flightdeck: event.board: for a plugin's platform the board is a folder inside the profile's own folder")
    result = invoke("pull", event, tmp_path / "mine")  # naming a folder does not make the profile's word fine: it is taken out
    assert result.exit_code == 2 and calls(root) == [] and not (tmp_path / "mine").exists()
    unset = event_file(tmp_path, text=EVENT.replace('board = "board"\n', ""))
    result = invoke("pull", unset, tmp_path / "mine")  # the player's own word, on the command line: anywhere
    assert result.exit_code == 0 and (tmp_path / "mine" / "plugin.json").is_file()


def test_plugin_pull_never_hands_the_model_key_of_the_config_to_a_plugin(tmp_path, config, monkeypatch):
    root = make_plugin(tmp_path / "acme", LISTED)
    config.write_text(CONFIG.replace('key_env = ""', 'key_env = "HOUSE_KEY"'))
    enabled(config, root)
    monkeypatch.setenv("HOUSE_KEY", "sk-fake-for-this-test")
    result = invoke("pull", event_file(tmp_path, text=EVENT.replace("ACME_TOKEN", "HOUSE_KEY")))
    assert result.exit_code == 2 and calls(root) == []
    assert "event.token_env names HOUSE_KEY (api.key_env in your config), a variable for another service's key" in result.output


def test_plugin_pull_says_why_the_plugin_failed_and_never_shows_the_token(tmp_path, config, monkeypatch):
    root = make_plugin(tmp_path / "acme", {"pull": {"exit": 1, "stderr": "401 for token {token}\n"}})
    enabled(config, root)
    monkeypatch.setenv("ACME_TOKEN", TOKEN)
    event = event_file(tmp_path)
    result = invoke("pull", event)
    assert (result.exit_code, result.output) == (
        2, "flightdeck: the acme plugin could not pull the board: it exited with status 1: 401 for token <token>\n")
    set_replies(root, {"pull": LISTED["pull"], "solved": {"raw": "<html>"}})
    result = invoke("pull", event)
    board = tmp_path / "quals" / "board"
    assert result.exit_code == 2 and TOKEN not in result.output
    assert result.output == (
        f"pulled into {board}: 3 challenges (misc 2, web 1); nothing was submitted\n"
        f"flightdeck: could not read the solved list from the acme plugin: its answer is not one JSON object; what was pulled "
        f"stays in {board}\n")
    broken = make_plugin(tmp_path / "broken", toml='name = "acme"\napi = 1\n')
    config.write_text(CONFIG)
    enabled(config, broken)
    result = invoke("pull", event)
    assert result.exit_code == 2 and result.output.startswith("flightdeck: plugin acme: ") and "command must be a list of words" in result.output


# ---------------------------------------------------------------------- the root command and doctor


def test_flightdeck_plugin_is_mounted_with_its_three_commands():
    shown = CliRunner().invoke(cli.app, ["plugin", "--help"], terminal_width=200).output
    for name in ("new", "add", "pull"):
        assert f" {name} " in shown
    assert "Plugins: play an event on a platform flightdeck does not know, through an adapter of your own." in " ".join(shown.split())


def test_doctor_reports_each_enabled_plugin_and_a_broken_one_never_fails_the_setup(tmp_path, config, monkeypatch):
    from ctf_flightdeck.setup import doctor

    good_one = make_plugin(tmp_path / "acme")
    broken = make_plugin(tmp_path / "harbour", toml='name = "harbour"\napi = 1\ncomand = ["x"]\n')
    enabled(config, good_one)
    enabled(config, broken, name="harbour")
    enabled(config, tmp_path / "gone", name="gone")
    checks = {check.name: check for check in doctor(config, environ={}) if check.name.startswith("plugin ")}
    assert list(checks) == ["plugin acme", "plugin harbour", "plugin gone"]
    assert (checks["plugin acme"].ok, checks["plugin acme"].essential) == (True, False)
    assert checks["plugin acme"].detail == "platform acme, runs <flightdeck's python> adapter.py"
    path = broken.resolve() / "plugin.toml"
    assert (checks["plugin harbour"].ok, checks["plugin harbour"].essential) == (False, False)
    assert checks["plugin harbour"].detail == f"plugin harbour: {path}: unknown key comand (known: {KNOWN})"
    assert checks["plugin harbour"].fix == f"fix the plugin's plugin.toml, or take [plugins.harbour] out of {config}"
    assert checks["plugin gone"].detail == f"plugin gone: {tmp_path.resolve() / 'gone' / 'plugin.toml'}: no such file"
    assert calls(good_one) == [] and calls(broken) == []  # doctor reads the manifests and runs nothing
    result = CliRunner().invoke(cli.app, ["doctor", "--config", str(config)])
    assert f"warn plugin harbour: plugin harbour: {path}: unknown key comand" in result.output
    assert f"     fix: fix the plugin's plugin.toml, or take [plugins.harbour] out of {config}" in result.output
    assert "ok   plugin acme: platform acme, runs <flightdeck's python> adapter.py" in result.output
    assert "FAIL plugin" not in result.output
