"""`flightdeck start`: set up an event and play it, by answering a few questions.

    flightdeck start                 # asks for the event, makes its folder, launches
    flightdeck start ~/ctf/example   # the same, in that folder; a folder already set up is launched

It writes FOLDER/event.toml and FOLDER/board/ (start.py), puts a CTFd token you paste into
your keys file (never into the event file, never shown), says whether the solver pack is
installed, and then plays the event as `flightdeck play FOLDER` does. With no config yet it
asks init's questions first. Away from a terminal it asks nothing: give the answers as options.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, NoReturn

import typer

from .text import untrusted

PLATFORM_MENU = (
    "How does flightdeck get this event's challenges?\n"
    "  1  ctfd      the event's site runs CTFd (most do: the page footer often says \"Powered by CTFd\").\n"
    "               flightdeck pulls the board, adds new challenges as they appear and submits flags.\n"
    "  2  by hand   any other site: you put each challenge in the event's board folder and submit\n"
    "               flags on the site yourself.\n"
    "Choose 1 or 2"
)
SUBMIT_MENU = (
    "When a lane finds a flag:\n"
    "  1  confirm   it waits for you; one key sends it (the safe choice)\n"
    "  2  auto      it is sent to the site at once (auto approve)\n"
    "Choose 1 or 2"
)
TOKEN_QUESTION = ("Paste your CTFd access token (on the event's site: Settings, then Access Tokens, then Generate). "
                  "Nothing shows as you paste; Enter alone skips it for now")


def start(
    folder: Annotated[Path | None, typer.Argument(metavar="FOLDER", show_default=False, file_okay=False,
                                                  help="The event's folder (default: asked; ~/ctf/<the event's name>). One already set up is played.")] = None,
    name: Annotated[str | None, typer.Option("--name", help="The event's name.")] = None,
    platform: Annotated[str | None, typer.Option("--platform", metavar="ctfd|manual", help="ctfd: flightdeck pulls and submits through the site; manual: a board you fill by hand.")] = None,
    url: Annotated[str | None, typer.Option("--url", help="The event site's address (ctfd).")] = None,
    flag: Annotated[str | None, typer.Option("--flag", metavar="PREFIX", help="What comes before the { in a flag (PP for PP{...}), or a regular expression.")] = None,
    submit: Annotated[str | None, typer.Option("--submit", metavar="confirm|auto", help="confirm: you approve each flag; auto: a flag a lane claims is sent at once.")] = None,
    ai_allowed: Annotated[bool, typer.Option("--ai-allowed", metavar="", help="The event's rules allow AI tools (asked at a terminal).")] = False,
    launch: Annotated[bool | None, typer.Option("--launch/--no-launch", metavar="", show_default=False, help="Play the event once it is set up (default: asked at a terminal).")] = None,
    config: Annotated[Path | None, typer.Option("--config", dir_okay=False, help="Config file (default: your config).")] = None,
) -> None:
    """Set up an event and play it: asks for the event's name, site and token, makes its
    folder, says whether the solver pack is installed, and launches."""
    from . import cli, keys
    from . import start as events
    from .config import ConfigError, default_config_path, expand

    interactive = cli._at_terminal()

    def ask(question: str, check, default: str | None = None, **more):
        def proc(value: str):
            try:
                return check(value)
            except events.StartError as exc:
                raise typer.BadParameter(str(exc)) from None

        return typer.prompt(question, default=default, value_proc=proc, **more)

    def given(value: str, option: str, check):
        try:
            return check(value)
        except events.StartError as exc:
            _fail(f"{option}: {exc}")

    try:
        config_path = expand(config) if config else default_config_path()
        if folder is not None:
            folder = expand(folder)
    except ConfigError as exc:
        _fail(str(exc))

    # ---- the config first: nothing plays without one
    if not config_path.exists():
        if not interactive or config is not None:
            _fail(f"there is no config at {config_path}: run `flightdeck init` first")
        typer.echo("No config yet, so first the questions `flightdeck init` asks (your model API, where lanes run).\n")
        cli.init(provider=None, base_url=None, key_env=None, models=None, host=None, runtime=None, max_lanes=4,
                 fallback=None, path=None, force=False, light="rules", light_model=None)
        typer.echo("")

    # ---- a folder that is already an event: play it
    if folder is not None and events.is_event_folder(folder):
        typer.echo(f"{folder} is already set up ({events.EVENT_FILE}); edit that file to change the event.")
        _status(folder, config_path)
        _launch(folder, config, launch, interactive)
        return

    # ---- the questions
    if not interactive:
        missing = [text for text, absent in (
            ("--name NAME", name is None), ("--platform ctfd|manual", platform is None),
            ("--url URL", platform == "ctfd" and url is None),
            ("--ai-allowed (the event's rules allow AI tools)", not ai_allowed),
        ) if absent]
        if missing:
            _fail("start is not at a terminal, so it cannot ask: give " + ", ".join(missing) + " (see `flightdeck start --help`)")
    name = given(name, "--name", events.name_answer) if name is not None else ask("Event name (like \"Example CTF 2026\")", events.name_answer)
    if folder is None:
        suggested = Path.home() / "ctf" / events.slug(name)
        if interactive:
            typed = typer.prompt("Folder for this event (made if missing)", default=str(suggested))
            try:
                folder = expand(Path(typed.strip()))
            except ConfigError as exc:
                _fail(str(exc))
        else:
            folder = suggested
        if events.is_event_folder(folder):
            typer.echo(f"{folder} is already set up ({events.EVENT_FILE}); edit that file to change the event.")
            _status(folder, config_path)
            _launch(folder, config, launch, interactive)
            return
    if folder.exists() and not folder.is_dir():
        _fail(f"{folder} is not a folder")
    if not ai_allowed:
        ai_allowed = typer.confirm("Do this event's rules allow AI tools? (flightdeck does not play an event that forbids them)", default=None)
        if not ai_allowed:
            _fail("not set up: flightdeck's lanes are AI agents, and this event's rules do not allow them", status=1)
    platform = given(platform, "--platform", events.platform_answer) if platform is not None else ask(PLATFORM_MENU, events.platform_answer, "1")
    token_env = None
    if platform == "ctfd":
        url = given(url, "--url", events.url_answer) if url is not None else ask("The event site's address (like https://ctf.example.org)", events.url_answer)
        token_env = events.token_variable(name)
    elif url is not None:
        _fail("--url is for --platform ctfd")
    if flag is not None:
        flag_format = given(flag, "--flag", events.flag_format_answer)
    elif interactive:
        flag_format = ask("Flag format: what comes before the { in a flag (PP for PP{...}); Enter if you do not know yet",
                          events.flag_format_answer, "", show_default=False)
    else:
        flag_format = None
    if platform != "ctfd":
        if submit is not None:
            _fail("--submit is for --platform ctfd (by hand, you submit each flag on the site)")
        submit = "confirm"
    elif submit is not None:
        submit = given(submit, "--submit", events.submit_answer)
    else:
        submit = ask(SUBMIT_MENU, events.submit_answer, "1") if interactive else "confirm"

    # ---- the token: to the keys file, under this event's own variable
    token_note = ""
    if token_env is not None:
        try:
            where = keys.source(token_env)
            if where is not None:
                token_note = f"token: {token_env} is already set in {'your environment' if where == 'environment' else 'your keys file'}"
            elif interactive:
                token = typer.prompt(TOKEN_QUESTION, default="", hide_input=True, show_default=False).strip()
                if token:
                    saved = keys.save(token_env, token)
                    token_note = f"token: saved in {saved} as {token_env} (never shown, never in the event file)"
            if not token_note:
                token_note = (f"token: not set yet. Put {token_env}=<your CTFd access token> in {keys.keys_path()} (chmod 600) "
                              "before you play: the site's Settings, then Access Tokens")
        except keys.KeysError as exc:
            _fail(str(exc))

    # ---- the folder and the event file
    answers = events.EventAnswers(name=name, platform=platform, url=url, token_env=token_env, flag_format=flag_format, submit=submit)
    try:
        written = events.write(folder, answers)
    except events.StartError as exc:
        _fail(str(exc))
    typer.echo("")
    typer.echo(f"event: {_show(name)}")
    typer.echo(f"  {written}   the event's rules, from your answers (edit it any time)")
    board = folder / events.BOARD_DIR
    if platform == "ctfd":
        typer.echo(f"  {board}/   the challenges: pulled from {_show(url)} when you play")
    else:
        typer.echo(f"  {board}/   the challenges: one folder each, with its files and a challenge.json")
    if token_note:
        typer.echo(token_note)
    _status(folder, config_path, offer_pack=interactive, config=config)
    if platform != "ctfd":
        typer.echo("The board starts empty. In the console, type /new to hand over a challenge: its name, then its text, files and\n"
                   "screenshots (drag them in). A lane starts on it at once. From another terminal: flightdeck add --help")
    _launch(folder, config, launch, interactive, ready=" not set yet" not in token_note)


def _status(folder: Path, config_path: Path, *, offer_pack: bool = False, config: Path | None = None) -> None:
    """What stands between this event and playing it: the profile's own check, and the pack."""
    from . import start as events
    from .config import ConfigError, load_config
    from .preflight import ProfileError, check, load_profile
    from .run import RunError, _environment

    try:
        loaded = load_config(config_path)
    except ConfigError as exc:
        _fail(str(exc))
    try:
        profile, policies = load_profile(events.event_file(folder))
        problems = check(profile, policies, max_lanes=loaded.lanes.max_lanes, model_config=loaded,
                         runtime=loaded.lanes.runtime, environ=_environment())
    except (ProfileError, RunError) as exc:
        _fail(str(exc))
    for problem in problems:
        if not problem.refuse and "(event.token_env) is not set" in problem.message:
            continue  # said above, with where the token goes
        typer.echo(f"{'refuse' if problem.refuse else 'note'}: {problem.message}")
    typer.echo(pack_line(loaded))
    if offer_pack and loaded.l1.pack is None and typer.confirm(
            "Install the solver pack now? (a few minutes: it builds its own Python environment, and asks before each step)", default=False):
        from . import pack_cli

        try:
            pack_cli.install(source=None, ref=None, subdir=None, name=None, yes=False, no_setup=False, image=None,
                             lane_tools=None, config=config, no_config=False)
        except typer.Exit as stopped:
            if stopped.exit_code:
                typer.echo("solvers (L1): not installed (the reason is above); the event is set up all the same, and "
                           "`flightdeck pack install` tries again")
    if any(problem.refuse for problem in problems):
        _fail(f"the event file refuses a run as it stands: fix it, then `flightdeck play {folder}`")


def pack_line(config) -> str:
    """Whether no-model solvers (L1) run first, in one line."""
    pack = config.l1.pack
    if pack is None:
        return ("solvers (L1): none installed, so each lane starts on its model. Optional: `flightdeck pack install` "
                "adds flightdeck's solver pack (some 800 no-model solvers that run first; needs uv and git)")
    from .l1.manifest import ManifestError, discover

    try:
        count = len(discover(pack))
    except ManifestError as exc:
        return f"solvers (L1): the pack at {pack} does not load ({exc}): `flightdeck doctor` says how to fix it"
    return f"solvers (L1): installed, {count} engine(s) at {pack}; they run first on every challenge"


def _launch(folder: Path, config: Path | None, launch: bool | None, interactive: bool, *, ready: bool = True) -> None:
    command = f"flightdeck play {folder}"
    if launch is None:
        launch = interactive and ready and typer.confirm(f"Launch now? (the same as: {command}; it spends tokens on your model API)", default=True)
    if not launch:
        typer.echo(f"play: {command}")
        return
    from . import cli

    typer.echo(f"flightdeck: {command}", err=True)
    cli.play(board=folder, config=config)


def _show(value: object) -> str:
    return untrusted(str(value), one_line=True)


def _fail(message: str, *, status: int = 2) -> NoReturn:
    typer.echo(f"flightdeck: {message}", err=True)
    raise typer.Exit(status)


def add(
    folder: Annotated[Path, typer.Argument(metavar="FOLDER", show_default=False, file_okay=False,
                                           help="The event's folder (the one `flightdeck start` made), or a board folder.")],
    name: Annotated[str, typer.Option("--name", "-n", help="The challenge's name, as the site shows it.")],
    text: Annotated[str | None, typer.Option("--text", "-t", help="Its description; `-` reads it from standard input. A line that is "
                                             "only a web address or `nc host port` is also taken as its instance.")] = None,
    file: Annotated[list[Path] | None, typer.Option("--file", "-f", help="A file, screenshot or folder of its handout (repeat for more).")] = None,
    url: Annotated[list[str] | None, typer.Option("--url", "-u", help="Its instance: https://host[:port], or `nc host port` (repeat for more).")] = None,
    category: Annotated[str, typer.Option("--category", "-c", help="Its category: web, crypto, pwn...")] = "",
    points: Annotated[int, typer.Option("--points", "-p", min=0, help="Its points.")] = 0,
) -> None:
    """Add a challenge to a board you fill yourself: makes its folder from a name, its text
    and its files. A run that is playing the board starts a lane on it within seconds."""
    import sys

    from . import addchallenge
    from . import start as events
    from .config import ConfigError, expand

    try:
        folder = expand(folder)
        files = tuple(expand(item) for item in file or ())
    except ConfigError as exc:
        _fail(str(exc))
    board = folder / events.BOARD_DIR if events.is_event_folder(folder) else folder
    if not board.is_dir():
        _fail(f"{board} is not a folder: give the event's folder (`flightdeck start` makes one) or a board folder")
    if text == "-":
        text = sys.stdin.read()
    description, found, addresses = addchallenge.parse(text or "")
    for item in url or ():
        ((_, _, more)) = addchallenge.parse(item)
        if not more:
            _fail(f"--url: {_show(item)} is not a web address (https://host) or `nc host port`")
        addresses += tuple(a for a in more if a not in addresses)
    try:
        made = addchallenge.create(board, addchallenge.NewChallenge(
            name=name, category=category, points=points, description=description,
            files=tuple(dict.fromkeys(files + found)), urls=addresses))
    except addchallenge.AddError as exc:
        _fail(str(exc))
    typer.echo(f"added {made}")
    typer.echo(f"a run playing this board starts a lane on it within seconds; otherwise: flightdeck play {folder}")
