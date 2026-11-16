"""`flightdeck http`: an event on a platform with a JSON API, played from a table of routes.

    flightdeck http example [--preset NAME] [--routes]  # print an event profile to edit: a preset (rctf, rctf2, noctf, gzctf), or its routes written out
    flightdeck http check EVENT.toml           # sign in, list, read the solved list (and an instance's status); show what each path matched; submit nothing
    flightdeck http pull EVENT.toml [FOLDER]   # pull the event's board and read the solved list; submit nothing

The profile's [http] table (docs/BOARDS.md, platform/http.py) says how the platform's API is
asked. It is data, not code: nothing of the player's or of a teammate's runs. `check` is how
a table is written in a few minutes: it makes the requests that change nothing and prints
what each path of the table matched in the platform's answers.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from .start import PRESET_LABELS
from .text import untrusted

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help="A platform with a JSON API (rCTF, noCTF, GZCTF and others): play it from the routes in the event profile's [http] table.",
)

EXAMPLE = """\
# ctf-flightdeck event profile for a platform with a JSON API (platform = "http"). Write it from
# the event's rules, then `flightdeck preflight event.toml` (what a run would send, and where your
# token goes) and `flightdeck http check event.toml` (what each path matches on the site; submits
# nothing). It holds no secret: the token stays in the variable token_env names.

[event]
name = "Example Quals"
platform = "http"
url = "https://ctf.example.org"     # the platform's address: every route is a path under it
token_env = "RCTF_TOKEN"            # the NAME of the variable that holds your token: RCTF_..., HTTP_TOKEN or HTTP_TOKEN_...
board = "board"                     # the folder the challenges are pulled into, beside this file
# flag_format = "example\\\\{[^}]+\\\\}"  # a regular expression for the event's flags

[rules]
ai_allowed = true                   # may model-driven lanes work challenges
platform_automation = true          # may flightdeck pull and submit through the platform's API
live_targets = "confirm"            # "allowed", "confirm" or "off": may lanes touch challenge instances

[policies]
submit = "confirm"                  # you approve each flag before it is sent ("auto": a claimed flag goes at once)

"""
PRESET = {
    "rctf": """\
[http]
preset = "rctf"                     # rCTF's routes, which ship with flightdeck; a key written under [http] wins
# rCTF: put your team's login link in the variable, whole and in quotes (its profile page's "Team Invite":
# https://.../login?token=...), or the token alone. flightdeck takes the token out of the link and decodes it.
""",
    "rctf2": """\
[http]
preset = "rctf2"                    # rCTF v2's routes, which ship with flightdeck; a key written under [http] wins
# rCTF v2: put your team's login link in the variable, whole and in quotes (its profile page's "Team Invite":
# https://.../login?token=...), or the token alone. flightdeck takes the token out of the link and decodes it.

# The challenges with an instance the site starts for your team are marked on the board. To have flightdeck
# start each one before a lane works it, set live_targets = "allowed" under [rules] and take the # off the
# two lines below; `flightdeck http check` then asks the status of the first one's instance (it starts nothing).
# [instances]
# plugin = "rctf"
""",
    "noctf": """\
[http]
preset = "noctf"                    # noCTF's routes, which ship with flightdeck; a key written under [http] wins
# noCTF: event.url is the address of its API, which may not be the web page's (the browser's network tab shows
# the host the requests to /challenges go to). The token is the session token the page keeps once you sign in
# (the browser's storage for the site, under noctf-session-token); a session lasts a week.
""",
    "gzctf": """\
[http]
preset = "gzctf"                    # GZCTF's routes, which ship with flightdeck; a key written under [http] wins
game = "1"                          # the game's number, as its address shows it: https://.../games/1
# GZCTF: put the value of the GZCTF_Token cookie in the variable, in quotes. Sign in on the site, then
# your browser's developer tools (Storage or Application, Cookies) show it. It lasts 7 days from your last visit.
""",
}
ROUTES_HEAD = """\
# The routes of the platform's API. These are {label}'s, written out: change them to the platform in
# front of you (its browser's network tab shows its routes). `flightdeck http check` tries them.
"""
LABELS = PRESET_LABELS  # each preset's name as the platform writes it: start's table, so the two cannot drift
_GAME_LINE = 'game = "1"                          '


_QUOTED = (", whole and in quotes", ", in quotes")  # how the example says to export a token: a keys file holds it bare


def preset_table(preset: str, game: str | None = None, *, keys_file: bool = False) -> str:
    """The [http] table of `flightdeck http example --preset NAME`, with the event's game
    (GZCTF's number, which only its routes name) in place of the example's. `flightdeck start`
    writes it under the event file it fills in (`keys_file`: the token is kept in the keys
    file, which takes it without the quotes an export needs, so the table does not ask for
    them). ValueError for a preset flightdeck has not, a GZCTF table without its game, or a
    game for a preset whose routes name none."""
    import json

    if preset not in PRESET:
        raise ValueError(f"no preset of that name (known: {', '.join(PRESET)})")
    text = PRESET[preset]
    if (_GAME_LINE in text) != (game is not None):
        raise ValueError(f"{LABELS[preset]}'s routes {'name the game: give its number' if game is None else 'name no game'}")
    if game is not None:
        text = text.replace(_GAME_LINE, f"game = {json.dumps(game, ensure_ascii=False)}".ljust(len(_GAME_LINE)))
    if keys_file:
        for words in _QUOTED:
            text = text.replace(words, "")
    return text


_TOKEN_LINE = 'token_env = "RCTF_TOKEN"            # the NAME of the variable that holds your token: RCTF_..., HTTP_TOKEN or HTTP_TOKEN_...'


def example_profile(routes: bool = False, preset: str = "rctf") -> str:
    """An event profile on the http platform that loads: with `preset`, or (`routes`) with
    that preset's table written out under [http], to edit for another platform."""
    from .platform.http import PRESETS, preset_text, variable_prefix

    if preset not in PRESETS:
        raise ValueError(f"no preset of that name (known: {', '.join(PRESETS)})")
    if not routes:
        prefix = variable_prefix(preset)  # rctf2's is RCTF_: a variable named RCTF2_ would be refused
        own = EXAMPLE.replace(_TOKEN_LINE, f'token_env = "{prefix}TOKEN"'.ljust(36) + f"# the NAME of the variable that holds your token: "
                              f"{prefix}..., HTTP_TOKEN or HTTP_TOKEN_...")
        assert prefix == "RCTF_" or own != EXAMPLE
        return own + PRESET[preset]
    table = re.sub(r"(?m)^\[([a-z.]+)\]$", r"[http.\1]", preset_text(preset))
    table = "\n".join(line for line in table.splitlines() if not line.startswith("#")).strip("\n")
    own = EXAMPLE.replace(_TOKEN_LINE, 'token_env = "HTTP_TOKEN"            # the NAME of the variable that holds your token: HTTP_TOKEN or HTTP_TOKEN_...')
    assert own != EXAMPLE
    if preset == "gzctf":  # its routes name {game}: a table with none does not load
        table = '[http]\ngame = "1"                          # the game\'s number, as its address shows it: https://.../games/1\n\n' + table
    own = EXAMPLE.replace(_TOKEN_LINE, 'token_env = "HTTP_TOKEN"            # the NAME of the variable that holds your token: HTTP_TOKEN or HTTP_TOKEN_...')
    assert own != EXAMPLE
    return own + ROUTES_HEAD.format(label=LABELS[preset]) + table + "\n"


@app.command("example")
def example(
    preset: Annotated[str, typer.Option("--preset", metavar="NAME", help="The platform: rctf (the default), rctf2 (rCTF v2), noctf or gzctf.")] = "rctf",
    routes: Annotated[bool, typer.Option("--routes", metavar="", help="Write every route of the preset out under [http], to edit for another platform.")] = False,
) -> None:
    """Print an event profile for the http platform, to edit: `flightdeck http example > event.toml`."""
    try:
        text = example_profile(routes, preset)
    except ValueError as exc:
        _fail(str(exc))
    typer.echo(text, nl=False)


@app.command("check")
def check(
    event: Annotated[Path, typer.Argument(metavar="EVENT.toml", dir_okay=False, help='The event profile: platform = "http", with an [http] table.')],
    show: Annotated[int, typer.Option("--show", min=1, max=20, help="How many challenges to show each path's match for.")] = 2,
) -> None:
    """Try the [http] table against the platform: sign in, list the challenges, read the solved list.

    Prints each request and what each path of the table matched for the first challenges.
    With an [instances] table it also asks the instancer's status for the first challenge
    marked on-demand (a GET; no instance is started, renewed or stopped). Nothing is submitted
    and no file is downloaded: only requests that change nothing are made (and the sign-in,
    when the table has one).

    Exit status 1 when a path matched nothing or the wrong thing, or the instancer's status
    gave nothing a run could use; 2 when a request failed.
    """
    import asyncio

    from .platform.http import plan
    from .plugins.call import CallFailed

    profile, caller = _ready(event, "check")
    instances = profile.instances
    typer.echo(f"{_show(profile.name)} at {_show(profile.url)}: nothing is submitted, no file is downloaded"
               + (", no instance is started" if instances is not None else ""))
    for line in plan(profile.http, instances):
        typer.echo(f"  {line}")
    typer.echo("")
    other = None  # a named shape for another platform: a run starts no instance with it (preflight.instances_off)
    if instances is not None and instances.platform not in (None, profile.platform):
        other = (f'instance not asked: instances.plugin {instances.plugin} is for platform "{instances.platform}", and this '
                 'event\'s is "http", so a run starts no instance with it (rCTF v2\'s instancer: plugin = "rctf")')
    try:
        found = asyncio.run(caller.check(show, instances if other is None else None))
    except CallFailed as exc:
        _fail(str(exc))
    for line in found.lines:
        typer.echo(line)
    if other is not None:
        typer.echo(other)
    if found.problems:
        typer.echo(f"flightdeck: {found.problems} path{'' if found.problems == 1 else 's'} of the [http] table did not match what a pull "
                   "needs: see above", err=True)
    if found.instance or other is not None:
        typer.echo("flightdeck: the [instances] table's status route did not give what a run needs: see the instance line above",
                   err=True)
    if found.problems or found.instance or other is not None:
        raise typer.Exit(1)
    typer.echo("every path a pull needs matched; nothing was submitted" + (" and no instance was started" if instances is not None else ""))


@app.command("pull")
def pull(
    event: Annotated[Path, typer.Argument(metavar="EVENT.toml", dir_okay=False, help='The event profile: platform = "http", with an [http] table.')],
    folder: Annotated[Path | None, typer.Argument(metavar="FOLDER", file_okay=False, show_default=False, help="The board folder (default: the profile's event.board).")] = None,
) -> None:
    """Pull an event's board by its [http] table and read the solved list back; nothing is submitted.

    flightdeck lists the challenges, downloads their files and writes the board folders, each
    checked as any folder board. A second pull adds what is new.

    Exit status 1 when some challenges were left out (each is named, with the reason), 2 when
    the pull could not start or a request failed.
    """
    from .platform.http import NAME
    from .plugin_cli import pull_and_report
    from .preflight import plugin_board_problem

    profile, caller = _ready(event, "pull")
    elsewhere = plugin_board_problem(profile)  # the profile's word for where a pull writes: inside its own folder, or none
    if elsewhere is not None:
        _fail(elsewhere)
    board = folder.expanduser() if folder is not None else profile.board
    if board is None:
        _fail("name the board folder: `flightdeck http pull EVENT.toml FOLDER`, or set event.board in the profile")
    pull_and_report(caller, board, name=NAME, url=profile.url)


def _ready(event: Path, command: str):
    """(the profile, a caller for it) for a command that asks the platform: the profile must
    be an http one whose rules allow the platform's API, and its token variable must be one
    a run would take (preflight) and be set. The token is never shown."""
    from .config import ConfigError, load_config
    from .keys import KeysError, environment, keys_file_named
    from .platform.http import HttpCaller
    from .preflight import ProfileError, http_token_env, load_profile, placeholder_url

    try:
        profile, _ = load_profile(event)  # it expands ~ itself, and says so when it cannot
    except ProfileError as exc:
        _fail(str(exc))
    if profile.platform != "http" or profile.http is None:
        _fail(f'`flightdeck http {command}` is for an event profile with platform = "http" and an [http] table; '
              "`flightdeck http example` prints one")
    if not profile.platform_automation:
        _fail(f"rules.platform_automation = false in {_show(event)}: the event's rules do not allow scripts on the platform, "
              "so flightdeck does not ask it")
    if profile.url is None:
        _fail('event.url is required for platform "http": the platform\'s address, which every route of the [http] table is under')
    if (unedited := placeholder_url(profile.url)) is not None:
        _fail(unedited)
    name = profile.token_env
    if name is None:
        _fail('event.token_env is required for platform "http": the name of the environment variable that holds your token')
    try:
        config = load_config()
    except ConfigError as exc:  # the table needs no leave from the config: only the names of its own secrets are read from it
        config = None
        typer.echo(f"flightdeck: note: your config was not read ({exc}), so the token variable is checked by its name alone", err=True)
    wrong = http_token_env(name, profile.http, config, profile.url)
    if wrong is not None:
        _fail(wrong)
    try:
        value = environment().get(name, "").strip()
    except KeysError as exc:
        _fail(str(exc))
    if not value:
        _fail(f"the token variable {name} (event.token_env) is not set or is empty: put {name}=<token> in {keys_file_named()} or "
              "export it, then try again")
    if profile.url.lower().startswith("http://") and not _loopback(profile.url):
        typer.echo("flightdeck: warning: event.url is http, not https: your token would cross the network unencrypted", err=True)
    try:
        return profile, HttpCaller(profile.http, profile.url, value)
    except ValueError as exc:  # a token no header can carry; the message never shows it
        _fail(f"{exc} ({name})")


def _loopback(url: str) -> bool:
    from urllib.parse import urlsplit

    from .preflight import _loopback as loopback

    try:
        return loopback(urlsplit(url).hostname or "")
    except ValueError:
        return False


def _show(value: object) -> str:
    return untrusted(str(value), one_line=True)


def _fail(message: str, *, status: int = 2) -> NoReturn:
    typer.echo(f"flightdeck: {message}", err=True)
    raise typer.Exit(status)
