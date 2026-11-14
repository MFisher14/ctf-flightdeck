"""A plugin's plugin.toml, the card `flightdeck plugin add` shows, and the config's [plugins] table.

    name = "myctf"                          # the platform's name: what event.toml's `platform` selects
    api = 1                                 # the plugin API it speaks (SUPPORTED_API)
    command = ["{python}", "adapter.py"]    # what flightdeck runs, once per call, in the plugin's folder
    version = "0.1.0"                       # optional
    description = "MyCTF events"            # optional, at most 200 characters
    token = true                            # optional, default true: the event must name token_env

The first word of `command` is `{python}` (flightdeck's own interpreter: the standard library
is all it promises), a file inside the plugin's folder, or a program on PATH. It is resolved
here, when the manifest is read, so a plugin that cannot run fails at `plugin add`, in
`doctor` and before a run starts, with the reason named.

The file is strict: an unknown key is an error. Nothing in it is run and nothing of the
plugin is imported here. Every string of a plugin that an error or the card shows is made
safe first (text.untrusted): a plugin's folder may be someone else's work.
"""

from __future__ import annotations

import os
import shutil
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .. import __version__
from ..config import PLUGIN_NAME, RESERVED_PLATFORMS, ConfigError, PluginRef, load_config
from ..config_edit import EditError, rewrite
from ..text import untrusted

MANIFEST = "plugin.toml"
SUPPORTED_API = (1,)
KEYS = ("name", "api", "command", "version", "description", "token")
MAX_BYTES = 64 * 1024  # a plugin.toml bigger than this is refused
MAX_DESCRIPTION = 200
MAX_VERSION = 32
MAX_WORDS = 32  # words in `command`
PYTHON = "{python}"
NAME_RULE = "lower-case letters, digits, - and _, starting with a letter, at most 32 characters"


class PluginError(Exception):
    """A plugin cannot be used. The message names the plugin and what is wrong, made safe to show."""


@dataclass(frozen=True)
class Plugin:
    name: str  # the platform's name
    version: str  # "" when the manifest gives none
    description: str  # as written: made safe where it is shown
    api: int
    argv: tuple[str, ...]  # `command` with its program resolved: what flightdeck runs, with the folder as cwd
    token: bool  # whether the event must name token_env
    root: Path  # the plugin's folder, resolved


def read(root: Path, *, name: str | None = None) -> Plugin:
    """The plugin in the folder `root`, from its plugin.toml. `name`: what the player's config
    calls it, for the errors; without it they name the folder. PluginError when the manifest
    is absent, is not what this flightdeck reads, or names a program that cannot be run."""
    label = f"plugin {name if name is not None else _show(Path(root).name)}"
    try:
        root = Path(root).expanduser().resolve()
    except (OSError, RuntimeError):
        raise PluginError(f"{label}: its folder cannot be found") from None
    path = root / MANIFEST
    where = f"{label}: {_show(path)}"
    if not (path.is_symlink() or path.exists()):
        raise PluginError(f"{where}: no such file")
    if path.is_symlink() or not path.is_file():
        raise PluginError(f"{where}: is not a regular file")
    try:
        if path.stat().st_size > MAX_BYTES:
            raise PluginError(f"{where}: larger than 64 KiB")
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PluginError(f"{where}: cannot read it ({exc.strerror or exc})") from None
    except UnicodeDecodeError:
        raise PluginError(f"{where}: is not UTF-8 text") from None
    except tomllib.TOMLDecodeError as exc:
        raise PluginError(f"{where}: {_show(str(exc))}") from None
    # the API first: a plugin for a later API may have keys this flightdeck does not know
    api = data.get("api")
    if "api" not in data:
        raise PluginError(f"{where}: api is missing: the plugin API it speaks, a whole number (this flightdeck speaks {_apis()})")
    if isinstance(api, bool) or not isinstance(api, int):
        raise PluginError(f"{where}: api must be a whole number: the plugin API it speaks (this flightdeck speaks {_apis()})")
    if api not in SUPPORTED_API:
        raise PluginError(
            f"{label} speaks plugin API {api}, and this flightdeck ({__version__}) speaks {_apis()}: update flightdeck, or use "
            f"the plugin's release for API {SUPPORTED_API[-1]}"
        )
    unknown = [key for key in data if key not in KEYS]
    if unknown:
        raise PluginError(f"{where}: unknown key {', '.join(_show(key)[:64] for key in unknown)} (known: {', '.join(KEYS)})")
    own = data.get("name")
    if not isinstance(own, str) or PLUGIN_NAME.fullmatch(own) is None:  # never shown: it is not a name
        raise PluginError(f"{where}: name must be the platform's name: {NAME_RULE}")
    if own in RESERVED_PLATFORMS:
        raise PluginError(f"{where}: name is {own}, a platform flightdeck has built in: a plugin cannot take its name")
    version = data.get("version", "")
    if not isinstance(version, str) or len(version) > MAX_VERSION or "\n" in version:
        raise PluginError(f"{where}: version must be one line of at most {MAX_VERSION} characters")
    description = data.get("description", "")
    if not isinstance(description, str) or len(description) > MAX_DESCRIPTION:
        raise PluginError(f"{where}: description must be text of at most {MAX_DESCRIPTION} characters")
    token = data.get("token", True)
    if not isinstance(token, bool):
        raise PluginError(f"{where}: token must be true or false: whether an event on this platform needs a token")
    command = data.get("command")
    if (not isinstance(command, list) or not command or len(command) > MAX_WORDS
            or not all(isinstance(word, str) and word and "\x00" not in word for word in command)):
        raise PluginError(
            f'{where}: command must be a list of words, like ["{PYTHON}", "adapter.py"]: what flightdeck runs for each call'
        )
    program = _program(label, root, command[0])
    return Plugin(name=own, version=version, description=description, api=api, argv=(program, *command[1:]), token=token, root=root)


def load(ref: PluginRef) -> Plugin:
    """The plugin a [plugins.NAME] table of the player's config names: read(), and its
    plugin.toml must give the table's name, so the platform an event selects is the one
    the player added."""
    plugin = read(ref.path, name=ref.name)
    if plugin.name != ref.name:
        raise PluginError(
            f"plugin {ref.name}: {_show(plugin.root / MANIFEST)} says another name than [plugins.{ref.name}] in your config: "
            "the two must match"
        )
    return plugin


def _program(label: str, root: Path, word: str) -> str:
    """The program `command` starts with, as what is run: flightdeck's interpreter for
    {python}, a file inside the plugin's folder (through no link out of it), or a program
    on PATH."""
    if word == PYTHON:
        return sys.executable
    outside = PluginError(f"{label}: command names a file outside the plugin's folder")
    if os.path.isabs(word) or ".." in Path(word).parts:
        raise outside
    candidate = root / word
    if candidate.is_symlink() or candidate.exists():
        try:
            target = candidate.resolve()
        except (OSError, RuntimeError):  # a loop of links
            raise outside from None
        if root not in target.parents:
            raise outside
        if not target.is_file():
            raise PluginError(f"{label}: command's program is not a file")
        if not os.access(target, os.X_OK):
            raise PluginError(
                f"{label}: command's program is a file flightdeck may not run: `chmod +x` it, or start the command with {PYTHON}"
            )
        return str(target)
    found = None if os.sep in word else shutil.which(word)
    if found is None:
        raise PluginError(f"{label}: command's program is not in the plugin's folder and not on PATH")
    return found


def _apis() -> str:
    return " and ".join(str(api) for api in SUPPORTED_API)


# ---------------------------------------------------------------------- what the player is shown


def command_line(plugin: Plugin) -> str:
    """What flightdeck runs for the plugin, made safe to show."""
    first = "<flightdeck's python>" if plugin.argv[0] == sys.executable else _show(plugin.argv[0])
    return " ".join([first, *(_show(word) for word in plugin.argv[1:])])


def card(plugin: Plugin) -> list[str]:
    """What `flightdeck plugin add` shows before it asks: what the plugin is, what it runs,
    what it gets and what it does not. Every string of the plugin's is made safe."""
    title = plugin.name + (f" {_show(plugin.version)}" if plugin.version else "") + f" (plugin API {plugin.api})"
    if plugin.description.strip():
        title += f": {_show(plugin.description.strip())}"
    gets = ["the event's URL"]
    if plugin.token:
        gets.append("its token (the variable event.token_env names)")
    gets.append("the flags it submits")
    return [
        f"plugin    {title}",
        f"folder    {_show(plugin.root)}",
        f'provides  platform "{plugin.name}"   (event.toml: platform = "{plugin.name}")',
        f"runs      {command_line(plugin)}   in that folder: for each pull, each flag, and each minute for the solved list",
        f"gets      {', '.join(gets)}",
        "not given your model API keys or the rest of your environment",
        "flightdeck does not sandbox a plugin: it runs as you, and can read your files and use the network. Read its files first.",
    ]


def doctor_line(plugin: Plugin) -> str:
    """One line for `flightdeck doctor`: the platform a usable plugin provides and what runs for it."""
    return f"platform {plugin.name}, runs {command_line(plugin)}"


# ---------------------------------------------------------------------- flightdeck plugin new

_PLUGIN_TOML = '''# A flightdeck plugin: a platform flightdeck does not know. See docs/PLUGINS.md.
name = "{name}"              # the platform's name: event.toml says platform = "{name}"
api = 1                      # the plugin API this adapter speaks
command = ["{{python}}", "adapter.py"]   # {{python}} is flightdeck's own interpreter: the standard library only
version = "0.1.0"
description = "{name} events"
# token = false              # for a platform that needs no token: the event then names no token_env
'''

_ADAPTER = '''"""The {name} adapter: flightdeck runs this file once per call, in this folder.

One JSON object arrives on stdin, and exactly one JSON object must go to stdout. Exit 0 when
it worked; on a failure exit non-zero with the reason on stderr (flightdeck shows its last
line). The event's token is in FLIGHTDECK_PLUGIN_TOKEN, and nothing else of the player's
environment is here. Standard library only: `{{python}}` promises no other package.

The three calls (plugin API 1):

  pull    {{"op": "pull", "event": NAME, "url": URL, "files": DIR, "known": [REF, ...]}}
          -> {{"challenges": [{{"ref": "17", "name": "Warm Up", "category": "misc", "points": 50,
                              "description": "...", "files": ["17/chal.zip"], "urls": ["https://host:8443"],
                              "solves": 3, "max_attempts": 0}}], "notes": ["2 challenges are locked"]}}
          `ref` (the platform's own id, as a string) and `name` are required. Download each
          file into DIR and list its path relative to DIR. The refs in `known` are on the
          board already, so their files need no second download. flightdeck writes the
          board folders itself. A `urls` entry is an origin (https://host[:port]) or a
          service (tcp://host:port), with no path.
  submit  {{"op": "submit", "event": NAME, "url": URL, "ref": REF, "flag": FLAG}}
          -> {{"verdict": "correct" | "incorrect" | "already_solved" | "rate_limited" | "unjudged",
              "detail": "...", "tries_left": 2, "retry_after": 30}}     (the last three are optional)
          Answer "unjudged" whenever the platform's reply is not clearly one of the others:
          the flag then goes back to the player and is never recorded as wrong.
  solved  {{"op": "solved", "event": NAME, "url": URL}}
          -> {{"solved": ["17", "23"]}}

The routes and field names below are placeholders: change them to the platform's own.
Test against a fake of your own on 127.0.0.1, never against a real event.
"""

import json
import os
import sys
import urllib.request

req = json.load(sys.stdin)


def api(path, body=None):
    request = urllib.request.Request(
        req["url"] + path,
        data=None if body is None else json.dumps(body).encode(),
        headers={{"Authorization": "Bearer " + os.environ["FLIGHTDECK_PLUGIN_TOKEN"], "Content-Type": "application/json"}},
    )
    with urllib.request.urlopen(request, timeout=20) as reply:
        return json.load(reply)


if req["op"] == "pull":
    out = {{"challenges": [
        {{"ref": str(task["id"]), "name": task["title"], "category": task["category"], "points": task["points"],
          "description": task["text"], "files": [], "urls": task.get("urls", [])}}
        for task in api("/api/tasks")
    ]}}
elif req["op"] == "submit":
    word = api(f"/api/tasks/{{req['ref']}}/flag", {{"flag": req["flag"]}})["status"]
    out = {{"verdict": {{"ok": "correct", "bad": "incorrect", "dup": "already_solved"}}.get(word, "unjudged"), "detail": word}}
elif req["op"] == "solved":
    out = {{"solved": [str(task["id"]) for task in api("/api/tasks") if task.get("solved")]}}
else:
    sys.exit("unknown op")
json.dump(out, sys.stdout)
'''

_EVENT_EXAMPLE = '''# An event on the {name} platform. Copy this next to the event's files as event.toml and
# fill it in; `flightdeck preflight event.toml` then says what a run will do.
[event]
name = "My event"
platform = "{name}"                 # the plugin you added with `flightdeck plugin add`
url = "https://ctf.example.org"     # the address the adapter talks to
token_env = "{variable}"            # the NAME of the variable that holds your token, never the token
board = "board"                     # the folder the challenges are pulled into

[rules]
ai_allowed = true                   # do the event's rules allow AI help?
platform_automation = true          # do they allow scripts on the platform (pulling, submitting)?
live_targets = "confirm"            # "allowed", "confirm" or "off"
'''


def skeleton(name: str) -> dict[str, str]:
    """The files `flightdeck plugin new NAME` writes, by file name: a manifest read() accepts,
    an adapter with the three calls and placeholder routes, and an example event profile."""
    if PLUGIN_NAME.fullmatch(name) is None:
        raise PluginError(f"a plugin's name is the platform's name: {NAME_RULE}")
    if name in RESERVED_PLATFORMS:
        raise PluginError(f"{name} is a platform flightdeck has built in: a plugin cannot take its name")
    variable = name.upper().replace("-", "_") + "_TOKEN"
    return {
        MANIFEST: _PLUGIN_TOML.format(name=name),
        "adapter.py": _ADAPTER.format(name=name),
        "event.example.toml": _EVENT_EXAMPLE.format(name=name, variable=variable),
    }


# ---------------------------------------------------------------------- the config's [plugins] table


def enable(config_path: Path, name: str, root: Path) -> None:
    """Add `[plugins.NAME] path` to the config at `config_path`: what allows the plugin. The
    edited file must load with the plugin in it, or it is put back as it was
    (config_edit.rewrite, the one place a config is changed in)."""

    def change(before: str) -> str:
        try:
            there = tomllib.loads(before).get("plugins")
        except tomllib.TOMLDecodeError:
            there = None  # a config that is not TOML: the load after the write says why, and the file is put back
        if isinstance(there, dict) and name in there:
            raise PluginError(f"plugins.{name} is already in {config_path}: change its path there")
        gap = "" if not before or before.endswith("\n\n") else ("\n" if before.endswith("\n") else "\n\n")
        return f"{before}{gap}[plugins.{name}]\npath = {_toml(str(root))}\n"

    def check() -> None:
        ref = load_config(config_path).plugins.get(name)
        if ref is None or ref.path != root:
            raise ConfigError(f"{config_path}: [plugins.{name}] did not take the plugin's folder")

    try:
        rewrite(config_path, change, check, what="the plugin")
    except EditError as exc:
        raise PluginError(str(exc)) from None


def _toml(value: str) -> str:
    """`value` as a TOML basic string."""
    out = []
    for char in value:
        if char in ('"', "\\"):
            out.append("\\" + char)
        elif ord(char) < 0x20 or ord(char) == 0x7F:
            out.append(f"\\u{ord(char):04x}")
        else:
            out.append(char)
    return '"' + "".join(out) + '"'


def _show(value: object) -> str:
    return untrusted(str(value), one_line=True)
