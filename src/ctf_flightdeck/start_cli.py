"""`flightdeck start`: set up an event and play it, by answering a few questions.

    flightdeck start                 # asks for the event, makes its folder, launches
    flightdeck start ~/ctf/example   # the same, in that folder; a folder already set up is launched

It writes FOLDER/event.toml and FOLDER/board/ (start.py), puts a CTFd token you paste into
your keys file (never into the event file, never shown), says whether the solver pack is
installed, and then plays the event as `flightdeck play FOLDER` does. With no config yet it
asks init's questions first. Away from a terminal it asks nothing: give the answers as options.

The token never comes as an option's value (a command line is kept in the shell's history and
shown in the process list): it is pasted at the hidden prompt, or handed over with --token-env
NAME (an environment variable's name) or --token-stdin (a pipe). It is kept under a variable
bound to the event's site (start.token_variable_for): a variable that is another site's, or
that no event says is this site's, is never used for this event.

Every answer is checked before anything is written: a --vpn file that is not there, a folder
that cannot be made or a token that cannot be kept stops start with nothing left behind.
"""

from __future__ import annotations

import re
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
_VARIABLE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_TOKEN_SHAPE = re.compile(r"ctfd_[0-9a-f]{16,}|[0-9a-f]{32,}", re.IGNORECASE)  # a token pasted where a variable's name goes
MAX_SHOWN_NAME = 32  # a variable name longer than this is not echoed: it may be a token pasted in its place (as `ctfd pull` does)
TOKEN_QUESTION = ("Paste your CTFd access token (on the event's site: Settings, then Access Tokens, then Generate). "
                  "Nothing shows as you paste; Enter alone skips it for now")


def start(
    folder: Annotated[Path | None, typer.Argument(metavar="FOLDER", show_default=False, file_okay=False,
                                                  help="The event's folder (default: asked; ~/ctf/<the event's name>). One already set up is played.")] = None,
    name: Annotated[str | None, typer.Option("--name", help="The event's name.")] = None,
    platform: Annotated[str | None, typer.Option("--platform", metavar="ctfd|manual", help="ctfd: flightdeck pulls and submits through the site; manual: a board you fill by hand.")] = None,
    url: Annotated[str | None, typer.Option("--url", help="The event site's address (ctfd).")] = None,
    flag: Annotated[str | None, typer.Option("--flag", metavar="PREFIX", help="What comes before the { in a flag (PP for PP{...}), an example flag, or a regular expression.")] = None,
    submit: Annotated[str | None, typer.Option("--submit", metavar="confirm|auto", help="confirm: you approve each flag; auto: a flag a lane claims is sent at once.")] = None,
    vpn_file: Annotated[Path | None, typer.Option("--vpn", metavar="FILE", dir_okay=False, help="The event's VPN file for its live targets (WireGuard .conf or OpenVPN .ovpn).")] = None,
    token_from: Annotated[str | None, typer.Option("--token-env", metavar="NAME", help="The environment variable that holds your CTFd access token (ctfd): start "
                                                   "keeps the token in your keys file. No option takes the token itself.")] = None,
    token_stdin: Annotated[bool, typer.Option("--token-stdin", metavar="", help="Read your CTFd access token from standard input (ctfd): one line, from a pipe.")] = False,
    ai_allowed: Annotated[bool, typer.Option("--ai-allowed", metavar="", help="The event's rules allow AI tools (asked at a terminal).")] = False,
    launch: Annotated[bool | None, typer.Option("--launch/--no-launch", metavar="", show_default=False, help="Play the event once it is set up (default: asked at a terminal).")] = None,
    config: Annotated[Path | None, typer.Option("--config", dir_okay=False, help="Config file (default: your config).")] = None,
) -> None:
    """Set up an event and play it: asks for the event's name, site and token, makes its
    folder, says whether the solver pack is installed, and launches."""
    from . import cli, keys, vpn
    from . import start as events
    from .config import ConfigError, default_config_path, expand

    interactive = cli._at_terminal()
    as_options = [option for option, was_given in (  # the answers that came as options, before any is asked for
        ("--name", name is not None), ("--platform", platform is not None), ("--url", url is not None), ("--flag", flag is not None),
        ("--submit", submit is not None), ("--vpn", vpn_file is not None), ("--token-env", token_from is not None),
        ("--token-stdin", token_stdin)) if was_given]

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

    def already(folder: Path) -> None:
        """A folder that is an event is played as it is; an answer given for it is said to be unused."""
        typer.echo(f"{folder} is already set up ({events.EVENT_FILE}); edit that file to change the event.")
        if as_options:
            more = [f"`flightdeck vpn add {folder} FILE` keeps a VPN file for it"] if vpn_file is not None else []
            if token_from is not None or token_stdin:
                more.append(f"its token goes in {_keys_file()}, under the variable its event file names (token_env)")
            typer.echo(f"note: {', '.join(as_options)} {'was' if len(as_options) == 1 else 'were'} not used: the event is set up already"
                       + "".join(f"; {text}" for text in more))
        _status(folder, config_path)
        _launch(folder, config, launch, interactive)

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
        already(folder)
        return

    # ---- what came as options is checked now, before a question is asked or anything is written
    vpn_source = None
    if vpn_file is not None:
        try:
            vpn_source = expand(vpn_file)
            _vpn_checked(vpn_source)
        except (vpn.VPNError, ConfigError) as exc:
            _fail(f"--vpn: {exc}")
    token = _token_given(token_from, token_stdin, interactive)  # None: none was handed over

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
            already(folder)
            return
    unusable = events.folder_problem(folder)
    if unusable is not None:
        _fail(unusable)
    if not ai_allowed:
        ai_allowed = typer.confirm("Do this event's rules allow AI tools? (flightdeck does not play an event that forbids them)", default=None)
        if not ai_allowed:
            _fail("not set up: flightdeck's lanes are AI agents, and this event's rules do not allow them", status=1)
    platform = given(platform, "--platform", events.platform_answer) if platform is not None else ask(PLATFORM_MENU, events.platform_answer, "1")
    chosen = None
    if platform == "ctfd":
        url = given(url, "--url", events.url_answer) if url is not None else ask("The event site's address (like https://ctf.example.org)", events.url_answer)
        try:
            chosen = events.token_variable_for(name, url)  # this site's variable: never one that is another site's
        except (keys.KeysError, events.StartError) as exc:
            _fail(str(exc))
    elif url is not None:
        _fail("--url is for --platform ctfd")
    elif token is not None:
        _fail(f"{'--token-env' if token_from is not None else '--token-stdin'} is for --platform ctfd (by hand, flightdeck never signs in to the site)")
    token_env = chosen.name if chosen is not None else None
    flag_format = None
    if flag is not None:
        flag_format, understood = given(flag, "--flag", events.flag_format_read)
    elif interactive:
        flag_format, understood = ask("Flag format: what comes before the { in a flag (PP for PP{...}); Enter if you do not know yet",
                                      events.flag_format_read, "", show_default=False)
    if flag_format is not None:
        typer.echo(f"flag format: {understood}")  # what was made of the answer: an example flag is read as its prefix
    if platform != "ctfd":
        if submit is not None:
            _fail("--submit is for --platform ctfd (by hand, you submit each flag on the site)")
        submit = "confirm"
    elif submit is not None:
        submit = given(submit, "--submit", events.submit_answer)
    else:
        submit = ask(SUBMIT_MENU, events.submit_answer, "1") if interactive else "confirm"

    # ---- the token: asked for here, kept (once the event is written) under this site's own variable
    if chosen is not None:
        for line in chosen.passed:
            typer.echo(f"token: {line}, so it is not used for this event")
        if token is None and chosen.source is None and interactive:
            def token_answer(typed: str) -> str | None:
                if not typed.strip():
                    return None
                problem = keys.value_problem(typed)
                if problem is not None:
                    typer.echo(f"That token {problem}.")  # said here: a hidden prompt's own error gives no reason
                    raise typer.BadParameter(f"the token {problem}")
                return typed.strip()

            token = typer.prompt(TOKEN_QUESTION, default="", hide_input=True, show_default=False, value_proc=token_answer)

    # ---- the event's VPN file, when its live targets are behind one
    if vpn_source is None and interactive:
        def vpn_answer(typed: str):
            typed = typed.strip().strip("'\"").replace("\\ ", " ")
            if not typed:
                return None
            path = Path(typed).expanduser()
            if not path.is_file():
                raise typer.BadParameter(f"{path}: no such file (drag the file onto this window, or press Enter for none)")
            try:
                _vpn_checked(path)
            except vpn.VPNError as exc:
                raise typer.BadParameter(str(exc)) from None
            return path

        vpn_source = typer.prompt("VPN file for the event's live targets (a WireGuard .conf or OpenVPN .ovpn: drag it in); "
                                  "Enter if the event has none", default="", show_default=False, value_proc=vpn_answer) or None

    # ---- the folder and the event file: the first thing written
    answers = events.EventAnswers(name=name, platform=platform, url=url, token_env=token_env, flag_format=flag_format, submit=submit)
    try:
        written = events.write(folder, answers)
    except events.StartError as exc:
        _fail(str(exc))
    from . import events as known_events

    known_events.remember(folder)

    # ---- the token, to the keys file: after the event, so no token is kept for an event that was not set up
    token_note = ""
    if chosen is not None:
        where_to_put = f"Put {token_env}=<your CTFd access token> in {_keys_file()} (chmod 600)"
        if token is not None:
            try:
                saved = keys.save(token_env, token)
            except keys.KeysError as exc:
                _fail(f"{exc}. The event is set up in {folder}, but its token is not kept. {where_to_put}, then: flightdeck play {folder}")
            token_note = f"token: saved in {saved} as {token_env} (never shown, never in the event file)"
            if chosen.source == "environment":
                token_note += f"\nnote: {token_env} is also set in your environment, and the environment's value is the one a run uses"
        elif chosen.source is not None:
            token_note = (f"token: {token_env} is already set in your {chosen.source}: it is the token for "
                          f"{events.site_name(events.site_of(url))}, as an event of yours there says")
        else:
            token_note = f"token: not set yet. {where_to_put} before you play: the site's Settings, then Access Tokens"
            if not interactive:
                token_note += ("\n       Or let start keep it: --token-env NAME (the environment variable that holds it) or "
                               "--token-stdin (from a pipe)")
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
    if vpn_source is not None:
        try:
            kept = vpn.keep(folder, vpn_source)
        except vpn.VPNError as exc:
            _fail(str(exc))
        typer.echo(f"vpn: kept as {kept.file} (yours only)")
        from . import vpn_cli

        if vpn_cli.ensure_tool(kept):  # installs wg-quick or openvpn when it is missing, on a yes
            typer.echo(f"vpn: ready; `flightdeck play` offers to connect it, and `flightdeck vpn up {folder}` does it now")
    _status(folder, config_path, offer_pack=interactive, config=config)
    if platform != "ctfd":
        typer.echo("The board starts empty. In the console, type /new to hand over a challenge: its name, then its text, files and\n"
                   "screenshots (drag them in). A lane starts on it at once. From another terminal: flightdeck add --help")
    _launch(folder, config, launch, interactive, ready=chosen is None or token is not None or chosen.source is not None)


def _token_given(variable: str | None, from_stdin: bool, interactive: bool) -> str | None:
    """The CTFd token handed over without a prompt: the value of the environment variable
    --token-env names, or what --token-stdin reads from a pipe. None when neither was given.
    Neither puts the token on the command line, where the shell's history and the process
    list would keep it. A token that is not there, or that the keys file cannot hold, stops
    start here, before anything is written; the reason never shows the token."""
    import os
    import sys

    from . import keys

    if variable is None and not from_stdin:
        return None
    if variable is not None and from_stdin:
        _fail("give --token-env NAME or --token-stdin, not both")
    if variable is not None:
        if not _VARIABLE.fullmatch(variable) or _TOKEN_SHAPE.fullmatch(variable):
            _fail("--token-env takes the name of an environment variable (letters, digits and _), never the token itself")
        option, value = "--token-env", os.environ.get(variable, "")
        if not value.strip():
            named = variable if len(variable) <= MAX_SHOWN_NAME else "the variable --token-env names"
            _fail(f"--token-env: {named} is not set in the environment (start reads the token from it; it does not look in your keys file)")
    else:
        if interactive:
            _fail("--token-stdin reads the token from a pipe; at a terminal, leave it out and start asks for the token (nothing shows as you paste)")
        option, value = "--token-stdin", sys.stdin.read()
        if not value.strip():
            _fail("--token-stdin: nothing came on standard input")
    problem = keys.value_problem(value)
    if problem is not None:
        _fail(f"{option}: the token {problem}")
    return value.strip()


def _vpn_checked(source: Path) -> None:
    """The event's VPN file, checked before the event is written: it is a file, of a kind
    flightdeck connects (by its name), small enough to be one, and readable. vpn.VPNError with
    the reason otherwise. vpn.keep copies it into the event's folder afterwards."""
    from . import vpn

    if not source.is_file():
        raise vpn.VPNError(f"{source}: no such file")
    vpn.kind_of(source)
    try:
        if source.stat().st_size > vpn.MAX_BYTES:
            raise vpn.VPNError(f"{source.name} is over {vpn.MAX_BYTES // 1024} KB: that is not a VPN file")
        with open(source, "rb"):
            pass
    except OSError as exc:
        raise vpn.VPNError(f"{source}: cannot read it ({exc.strerror or type(exc).__name__})") from None


def _keys_file() -> Path:
    from . import keys

    try:
        return keys.keys_path()
    except keys.KeysError as exc:
        _fail(str(exc))


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
    text: Annotated[str | None, typer.Option("--text", "-t", help="Its description, kept as you give it; `-` reads it from standard "
                                             "input. A line that is only a web address or `nc host port` is also taken as its "
                                             "instance. A path in it is only text: files come from --file.")] = None,
    file: Annotated[list[Path] | None, typer.Option("--file", "-f", help="A file, screenshot or folder of its handout (repeat for more). "
                                                    "Each one attached is printed with its size.")] = None,
    url: Annotated[list[str] | None, typer.Option("--url", "-u", help="Its instance: https://host[:port], or `nc host port` (repeat for more).")] = None,
    category: Annotated[str, typer.Option("--category", "-c", help="Its category: web, crypto, pwn...")] = "",
    points: Annotated[int, typer.Option("--points", "-p", min=0, help="Its points.")] = 0,
) -> None:
    """Add a challenge to a board you fill yourself: makes its folder from a name, its text
    and its files. A run that is playing the board starts a lane on it within seconds.

    The text is kept as it is given and is never searched for files: only --file attaches
    one, and each file attached is printed."""
    import sys

    from . import addchallenge
    from . import start as events
    from .config import ConfigError, expand

    try:
        folder = expand(folder)
        files = tuple(dict.fromkeys(expand(item) for item in file or ()))
    except ConfigError as exc:
        _fail(str(exc))
    board = folder / events.BOARD_DIR if events.is_event_folder(folder) else folder
    if not board.is_dir():
        _fail(f"{board} is not a folder: give the event's folder (`flightdeck start` makes one) or a board folder")
    if text == "-":
        text = sys.stdin.read()
    description, addresses = addchallenge.parse(text or "")
    for item in url or ():
        one = addchallenge.address(item)
        if one is None:
            _fail(f"--url: {_show(item)} is not a web address (https://host) or `nc host port`")
        if one not in addresses:
            addresses += (one,)
    try:
        made = addchallenge.create(board, addchallenge.NewChallenge(
            name=name, category=category, points=points, description=description, files=files, urls=addresses))
    except addchallenge.AddError as exc:
        _fail(str(exc))
    typer.echo(f"added {made}")
    for item in files:
        typer.echo(f"attached {_show(item.name)} ({addchallenge.size_text(item)})")
    if not files:
        typer.echo("no file attached (--file attaches one)")
    typer.echo(f"a run playing this board starts a lane on it within seconds; otherwise: flightdeck play {folder}")
