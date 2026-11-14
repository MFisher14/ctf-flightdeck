"""Command line: `flightdeck` (also installed as `ctfdeck`)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from enum import StrEnum
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from . import __version__
from .mock import scenarios

ScenarioName = StrEnum("ScenarioName", {name: name for name in scenarios.SCENARIOS})
SCENARIO_LIST = "Scenarios:\n\n" + "\n".join(
    f"- **{name}**: {build().summary}." for name, build in scenarios.SCENARIOS.items()
)

PLAY, SETUP, EVENT, AFTER, SOLVERS = "Play", "Set up", "Before and during an event", "After a run", "Solvers (L1)"
PANELS = (SETUP, PLAY, EVENT, AFTER, SOLVERS)  # the order `flightdeck --help` shows them in


class _ByPanel(typer.core.TyperGroup):
    """The root command: its commands listed panel by panel in PANELS' order (Typer would list
    them as they were registered, every command before every group), and within a panel as
    they were registered."""

    def list_commands(self, ctx) -> list[str]:
        def panel(name: str) -> int:
            title = getattr(self.commands[name], "rich_help_panel", None)
            return PANELS.index(title) if title in PANELS else len(PANELS)

        return sorted(self.commands, key=panel)  # a stable sort: registration order within a panel


app = typer.Typer(
    name="flightdeck",
    cls=_ByPanel,
    add_completion=False,
    rich_markup_mode="markdown",
    help="A terminal harness for playing CTFs with AI agents, where you run the loop.",
    epilog="New here? `flightdeck init`, then `flightdeck doctor`, then `flightdeck practice`. An event: `flightdeck start`. "
    "No setup at all: `flightdeck mock`.",
)


def _version(ctx: typer.Context, value: bool) -> None:
    if value:
        typer.echo(f"{ctx.find_root().info_name} {__version__}")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def root(
    ctx: typer.Context,
    version: Annotated[
        bool, typer.Option("--version", callback=_version, is_eager=True, metavar="", help="Show the version and exit.")
    ] = False,
) -> None:
    """A terminal harness for playing CTFs with AI agents, where you run the loop."""
    if ctx.invoked_subcommand is None:
        if _at_terminal() and _at_terminal_out():
            _home()
        else:  # nobody to ask (a script, a pipe): say what to run
            typer.echo(_next_steps(), nl=False)


MAX_RESUME = 6  # events offered on the opening menu, most recently played first


def _home() -> None:
    """`flightdeck` alone, at a terminal: the home screen (console/home.py), then what the
    player chose there."""
    from . import events, start_cli
    from .config import ConfigError, default_config_path, load_config
    from .console import home

    try:
        path = default_config_path()
        have = path.exists()
        loaded = load_config(path) if have else None
    except ConfigError as exc:
        typer.echo(f"flightdeck: {exc}", err=True)
        raise typer.Exit(2) from None
    status = start_cli.pack_line(loaded).split(". Optional")[0] if loaded is not None else ""
    menu = home.items(have_config=have, events=events.known()[:MAX_RESUME] if have else (),
                      pack_installed=loaded is not None and loaded.l1.pack is not None)
    choice = _home_choice(menu, status)
    if choice is None:
        return
    kind = choice[0]
    if kind == "resume":
        play(board=choice[1])
    elif kind == "new":
        _start_new(choice[1])
    elif kind == "practice":
        practice()
    elif kind == "mock":
        mock()
    elif kind == "pack":
        from . import pack_cli

        pack_cli.install()
    elif kind == "setup":
        start_cli.start()


def _home_choice(menu, status: str):
    from .console.home import HomeApp

    return HomeApp(menu, status).run()


def _start_new(new) -> None:
    """Set up the event the home screen's form described, and play it: the event folder, the
    token to the keys file, the VPN file (its tool installed on a yes), then the console. The
    folder comes first, so no token is kept for an event that could not be set up."""
    from . import events, keys, vpn, vpn_cli
    from . import start as starts

    def fail(text: str) -> NoReturn:
        typer.echo(f"flightdeck: {text}", err=True)
        raise typer.Exit(2)

    answers = new.answers
    try:
        starts.write(new.folder, answers)
    except starts.StartError as exc:
        fail(str(exc))
    events.remember(new.folder)
    typer.echo(f"flightdeck: set up {new.folder}", err=True)
    for note in new.notes:
        typer.echo(f"flightdeck: token: {note}", err=True)
    try:
        if new.token:
            keys.save(answers.token_env, new.token)
    except keys.KeysError as exc:
        fail(f"{exc}. The event is set up, but its token is not kept: put {answers.token_env}=<your CTFd access token> in "
             f"{keys.keys_path()} (chmod 600), then `flightdeck` resumes this event")
    try:
        if new.vpn is not None:
            vpn_cli.ensure_tool(vpn.keep(new.folder, new.vpn))
    except vpn.VPNError as exc:
        fail(f"{exc}. The event is set up without its VPN file: `flightdeck vpn add {new.folder} FILE` keeps one")
    if answers.platform == "ctfd" and not new.token:
        try:
            there = keys.source(answers.token_env) is not None
        except keys.KeysError as exc:
            fail(str(exc))
        if not there:
            fail(f"no token yet: put {answers.token_env}=<your CTFd access token> in {keys.keys_path()} (chmod 600), "
                 f"then `flightdeck` resumes this event")
    play(board=new.folder)


def _next_steps() -> str:
    """What `flightdeck` alone says: what it is, and the next step on this machine."""
    from .config import ConfigError, default_config_path

    head = f"flightdeck {__version__}: a terminal harness for playing CTFs with AI agents, where you run the loop.\n\n"
    try:
        path = default_config_path()
        have = path.exists()
    except ConfigError as exc:
        return head + f"{exc}\n"
    pack = ""
    if not have:
        steps = [
            ("flightdeck init", "a few questions; writes your config"),
            ("flightdeck doctor", "checks your setup and says how to fix what is missing"),
            ("flightdeck practice", "plays 14 small practice challenges (spends tokens on your model API)"),
            ("flightdeck start", "sets up an event and plays it: asks for its name, site and token, makes its folder"),
        ]
        text = head + "No config yet. Start here:\n"
    else:
        steps = [
            ("flightdeck start", "play an event: asks for its name, site and token, makes its folder, launches"),
            ("flightdeck play FOLDER", "play an event you set up before, or any folder of challenges"),
            ("flightdeck practice", "the practice set (14 small challenges)"),
            ("flightdeck doctor", "checks your setup"),
        ]
        text = head + f"Your config: {path}\n"
        from .config import load_config
        from .start_cli import pack_line

        try:
            pack = "\n" + pack_line(load_config(path)) + "\n"
        except ConfigError as exc:
            pack = f"\n{exc}\n"
    width = max(len(command) for command, _ in steps)
    text += "".join(f"  {command:<{width}}  {what}\n" for command, what in steps)
    return text + pack + "\nNo setup at all: flightdeck mock (fake data, nothing spent). Every command: flightdeck --help\n"


def _path(path: Path) -> Path:
    """`path` with ~ expanded, or a clean exit naming the problem (a ~user that does not exist)."""
    from .config import ConfigError, expand

    try:
        return expand(path)
    except ConfigError as exc:
        typer.echo(f"flightdeck: {exc}", err=True)
        raise typer.Exit(2) from None


@app.command(epilog=SCENARIO_LIST, rich_help_panel=PLAY)
def mock(
    scenario: Annotated[
        ScenarioName,
        typer.Option("--scenario", "-s", metavar="NAME", help="Scenario to play (listed below)."),
    ] = ScenarioName.default,
    max_lanes: Annotated[
        int | None, typer.Option("--max-lanes", min=1, help="Concurrent lanes (default: the scenario's, 16 for most).")
    ] = None,
    team: Annotated[
        bool | None, typer.Option("--team/--solo", metavar="", help="Team or solo mode (default: the scenario's; default is team).")
    ] = None,
    host: Annotated[
        bool | None, typer.Option("--host/--docker", metavar="", help="Show lanes running on the host instead of in Docker.")
    ] = None,
    screenshot: Annotated[
        Path | None,
        typer.Option(
            "--screenshot", metavar="DIR", file_okay=False, dir_okay=True,
            help="Run headless and save SVG screenshots of the key moments to DIR, then exit.",
        ),
    ] = None,
    speed: Annotated[
        float, typer.Option("--speed", min=0.25, max=20.0, help="Mock clock ticks per second (live console).")
    ] = 1.0,
) -> None:
    """Open the console on fake, scripted data: no models, no network, nothing spent."""
    containerized = None if host is None else not host
    if screenshot is not None:
        from .mock.screenshots import capture

        screenshot = _path(screenshot)  # the shell leaves ~ alone in --screenshot=~/x

        try:
            screenshot.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise typer.BadParameter(f"cannot create {screenshot}: {exc.strerror}", param_hint="--screenshot") from exc
        result = capture(scenario.value, screenshot, max_lanes=max_lanes, team=team, containerized=containerized)
        for path in result.saved:
            typer.echo(str(path))
        for note in result.skipped:
            typer.echo(f"skipped {note}", err=True)
        return

    from .console.app import FlightdeckApp
    from .mock.world import FakeWorld

    world = FakeWorld(scenarios.get(scenario.value), max_lanes=max_lanes, team=team, containerized=containerized)
    FlightdeckApp(world.deck, ticker=world.tick, tick_seconds=1.0 / speed, mock=f"MOCK · {scenario.value}", welcome=True).run()


class Submit(StrEnum):
    confirm = "confirm"
    auto = "auto"


class Agent(StrEnum):
    claude = "claude"
    codex = "codex"


AGENT_HELP = "Lanes are this coding-agent CLI (its own key or token and models: [agents] in your config) instead of flightdeck's own loop."
HEADLESS_HELP = (
    "No console: the run writes status.json in its run folder, approvals wait (nothing is approved), and SIGTERM or "
    "Ctrl-C stops it as quitting does."
)
AUTOPILOT_HELP = ("Engage autopilot: the run goes on by rule while you are away, never looser than the event's rules; "
                  "needs a run budget and Docker (default: the config's [autopilot] engage).")
BUDGET_DOLLARS_HELP = "The whole run's budget in dollars, for autopilot (default: the config's [autopilot] budget_dollars)."
BUDGET_TOKENS_HELP = "The whole run's budget in tokens, for autopilot (default: the config's [autopilot] budget_tokens)."
AGENT_AUTH_HELP = "The CLI's credential: claude api-key or oauth-token; codex api-key or login (default: the one the CLI would use)."


@app.command(rich_help_panel=PLAY)
def play(
    board: Annotated[
        Path | None,
        typer.Argument(
            metavar="BOARD", file_okay=False, dir_okay=True, show_default=False,
            help="A folder of challenge folders (each with a challenge.json); for a CTFd event, the folder its board is pulled into.",
        ),
    ] = None,
    event: Annotated[
        Path | None,
        typer.Option(
            "--event", dir_okay=False, metavar="EVENT.toml",
            help="The event profile: play by the event's rules and policies (`flightdeck preflight` checks it).",
        ),
    ] = None,
    answers: Annotated[
        Path | None,
        typer.Option("--answers", exists=True, dir_okay=False, help="sha256 answers file (default: answers.sha256.json in the board, if any)."),
    ] = None,
    config: Annotated[
        Path | None, typer.Option("--config", dir_okay=False, help="Config file (default: $FLIGHTDECK_CONFIG or ~/.config/ctf-flightdeck/config.toml).")
    ] = None,
    max_lanes: Annotated[int | None, typer.Option("--max-lanes", min=1, help="Concurrent lanes (default: the config's).")] = None,
    host: Annotated[
        bool | None, typer.Option("--host/--docker", metavar="", help="Run lanes on this machine, or in Docker (default: the config's runtime).")
    ] = None,
    team: Annotated[
        bool | None, typer.Option("--team/--solo", metavar="", help="Team or solo mode (default: the event profile's, else solo).")
    ] = None,
    team_dir: Annotated[
        Path | None,
        typer.Option(
            "--team-dir", file_okay=False, metavar="FOLDER",
            help="Team mode through the folder your teammates share (`flightdeck team init` makes it).",
        ),
    ] = None,
    handle: Annotated[
        str | None, typer.Option("--handle", metavar="NAME", help="Your name in the team folder (default: your login name).")
    ] = None,
    submit: Annotated[
        Submit | None, typer.Option("--submit", help="confirm: you approve each flag; auto: a flag a lane claims goes at once; the rest wait for you "
                                                   "(default: the config's).")
    ] = None,
    model: Annotated[str | None, typer.Option("--model", help="The model lanes start on (default: the weakest in the ladder).")] = None,
    run_dir: Annotated[Path | None, typer.Option("--run-dir", file_okay=False, help="Where run folders go (default: the config's).")] = None,
    pack: Annotated[
        Path | None, typer.Option("--pack", file_okay=False, help="Your L1 pack: no-model solvers a lane runs first (default: the config's [l1] pack).")
    ] = None,
    agent: Annotated[Agent | None, typer.Option("--agent", help=AGENT_HELP)] = None,
    agent_auth: Annotated[str | None, typer.Option("--agent-auth", metavar="HOW", help=AGENT_AUTH_HELP)] = None,
    headless: Annotated[bool, typer.Option("--headless", metavar="", help=HEADLESS_HELP)] = False,
    autopilot: Annotated[bool | None, typer.Option("--autopilot/--no-autopilot", metavar="", help=AUTOPILOT_HELP)] = None,
    budget_dollars: Annotated[float | None, typer.Option("--budget-dollars", min=0.0, metavar="DOLLARS", help=BUDGET_DOLLARS_HELP)] = None,
    budget_tokens: Annotated[int | None, typer.Option("--budget-tokens", min=1, metavar="TOKENS", help=BUDGET_TOKENS_HELP)] = None,
) -> None:
    """Play a board with agent lanes; with --event, by the event's rules: its CTFd board
    (pulled, new waves, flags submitted, solves followed) and the team folder. Spends tokens:
    on the API in your config, or with --agent on that CLI's own key or subscription."""
    from .run import RunError, RunOptions, host_warning, prepare_run
    from .start import is_event_folder, resolve

    asked = _path(board) if board else None
    board, event = resolve(asked, event)  # a folder `flightdeck start` made: its event.toml and its board/
    if asked is not None and is_event_folder(asked):
        from . import events

        events.remember(asked)  # `flightdeck` alone offers to resume it
    if asked is not None and not _vpn_ready(asked, ask=_at_terminal() and not headless):
        raise typer.Exit(1)
    options = RunOptions(
        board=board,
        answers=_path(answers) if answers else None,
        config=_path(config) if config else None,
        max_lanes=max_lanes,
        runtime=None if host is None else ("host" if host else "docker"),
        team=team,
        submit=submit.value if submit else None,
        model=model,
        run_dir=_path(run_dir) if run_dir else None,
        pack=_path(pack) if pack else None,
        event=event,  # load_profile expands ~ itself, and says so when it cannot
        team_dir=_path(team_dir) if team_dir else None,
        handle=handle,
        confirm=_ask if _at_terminal() and not headless else None,  # a headless run has nobody to ask
        agent=agent.value if agent else None,
        agent_auth=agent_auth,
        autopilot=autopilot, budget_dollars=budget_dollars, budget_tokens=budget_tokens,
        say=lambda line: typer.echo(f"flightdeck: {line}", err=True),
    )
    try:
        run = prepare_run(options)
    except RunError as exc:
        typer.echo(f"flightdeck: {exc}", err=True)
        if asked is not None and event is None and not _has_entries(asked):  # nothing to play there yet
            typer.echo("flightdeck: to set up an event (its folder, its rules, its board) and play it: `flightdeck start`", err=True)
        raise typer.Exit(2) from None
    except KeyboardInterrupt:  # Ctrl-C in autopilot's wait for the event's start (the one wait before a run)
        typer.echo("flightdeck: stopped before the run started: nothing was pulled and no lane started", err=True)
        raise typer.Exit(130) from None
    if run.runtime == "host":
        typer.echo(f"flightdeck: {host_warning()}", err=True)
    for note in run.notes():
        typer.echo(f"flightdeck: {note}", err=True)
    if headless:  # no console: the board is released, then the run waits for a signal or its own end (headless.py)
        from .headless import Headless

        console = Headless(run, say=lambda line: typer.echo(f"flightdeck: {line}", err=True))
        between = console.fly
    else:
        console = run.app(welcome=_first_console())
        between = console.run_async  # the console releases the board itself once it is up (on_start)
    _fly(run, between)
    if console.stopped_by is not None:  # SIGHUP or SIGTERM: the lanes were stopped as when you quit
        typer.echo(f"flightdeck: {console.stopped_by.name}: the run's lanes were stopped as when you quit", err=True)
        raise typer.Exit(128 + console.stopped_by)
    if console.return_code:  # the console failed (Textual has printed why): not a run that ended as asked
        typer.echo("flightdeck: the console failed: the run's lanes were stopped as when you quit", err=True)
        raise typer.Exit(1)


def _vpn_ready(folder: Path, *, ask: bool) -> bool:
    """Before a folder with a VPN file is played: say whether the VPN looks connected, and at
    a terminal offer to connect it when it does not. False only when the player chose to stop.
    Only a file the player added through flightdeck is offered (vpn.added): one that is merely
    in the folder (a board is untrusted data), or that changed since it was added, is said to
    be there and unverified, and nothing is run for it."""
    from . import vpn, vpn_cli

    found = vpn.find(folder)
    if found is None:
        return True
    try:
        if not vpn.added(found):
            typer.echo(f"flightdeck: {vpn.unverified(found)}", err=True)
            typer.echo("flightdeck: it was not connected: lanes reach this event's live targets only if its VPN is up", err=True)
            return True
        state = vpn.connected(found)
    except vpn.VPNError as exc:
        typer.echo(f"flightdeck: {exc}", err=True)
        return True
    if state is not False:
        typer.echo(f"flightdeck: {vpn.status_line(found, state)}", err=True)
        return True
    typer.echo(f"flightdeck: {vpn.status_line(found, state)}", err=True)
    if not ask:
        typer.echo("flightdeck: lanes cannot reach this event's live targets until it is connected", err=True)
        return True
    if vpn_cli.connect(found) == 0:
        return True
    return typer.confirm("The VPN is not connected, so lanes cannot reach live targets. Play anyway?", default=False)


def _has_entries(folder: Path) -> bool:
    """Whether `folder` is a folder with something in it."""
    try:
        return any(folder.iterdir())
    except OSError:
        return False


def _fly(run, between: Callable[[], Awaitable[object]]) -> None:
    """One run from its release to its exit lines, whatever plays it. `between` is awaited on
    an event loop of this function's own and is what runs from the board's release to the
    run's shutdown: the console (which releases the board itself once it is up), or anything
    that calls run.release() and waits. However it ends (it returns, it raises, it is
    cancelled), the run is shut down on that same loop, where its lanes and background tasks
    live (Run.shutdown: once, also when `between` already did it), then closed, and the exit
    lines are printed. What `between` raised is raised again after them."""
    import asyncio

    async def flight() -> None:
        try:
            await between()
        finally:
            await run.shutdown()

    try:
        asyncio.run(flight())
    finally:
        run.close()
        card = run.scorecard()
        if card:
            typer.echo(card, nl=False)
        else:  # no answers to score against (a real event): the scorecard's spend line alone
            typer.echo(_spent(run.deck))
        held = _held_at_the_end(run.deck)
        if held:
            typer.echo(f"flightdeck: {held}", err=True)
        typer.echo(f"run log: {run.log.path}")
        for line in _after_the_run(run.dir):
            typer.echo(line)
        waiting = _flags_left_waiting(run.deck)
        if waiting:
            typer.echo(f"flightdeck: not submitted, still waiting for your approval when the run ended: {'; '.join(waiting)}", err=True)
        for problem in run.errors:
            typer.echo(f"flightdeck: {problem}", err=True)


def _spent(deck) -> str:
    """What the run spent, in one line, for a run with no scorecard to say it: the deck's own
    totals (Deck.totals: every lane's turns and its spend outside a turn, a light model's
    among it), which the console's header showed and each lane's transcript records, so the
    post-flight report gives the same figures. Read it after Run.shutdown(), which counts
    what the lanes report as they stop. The dollars are "at least" when some spend had no
    price or a turn's cost never came."""
    from . import fmt

    tokens, dollars, unpriced = deck.totals()
    if unpriced:
        return f"Spent {fmt.tokens(tokens)} tokens · at least ${fmt.dollars(dollars)} (some of it has no known cost)"
    return f"Spent {fmt.tokens(tokens)} tokens · ${fmt.dollars(dollars)}"


def _held_at_the_end(deck) -> str:
    """Why the queue was held when the run ended, and what that left unstarted; "" when it was
    not held. Made safe to print: the reason quotes the model API's answer."""
    from .text import untrusted

    if not deck.held:
        return ""
    queued = len(deck.queue)
    left = f"{queued} challenge{'' if queued == 1 else 's'} queued, not started" if queued else "nothing was queued"
    return f"the queue was held when the run ended ({left}): {untrusted(deck.held, one_line=True)}"


def _after_the_run(run_dir: Path) -> list[str]:
    """The run folder and the commands that read it, ready to paste: report, writeups, gaps and
    share for every run; score only when it can score this one, that is when the run recorded
    a board (run.json) that is still there with answers to check flags against."""
    import shlex

    from .text import untrusted

    shown = untrusted(str(run_dir), one_line=True)
    folder = shlex.quote(shown)
    steps = [
        (f"flightdeck report {folder}", "the post-flight report: solves, interventions, spend"),
        (f"flightdeck writeups {folder}", "a writeup draft for each solve"),
        (f"flightdeck gaps {folder}", "what no L1 engine solved, and why"),
        (f"flightdeck share {folder}", "the flight card, to post: your setup and how it went, no flags"),
    ]
    if _scorable(run_dir):
        steps.append((f"flightdeck score {folder}", "the scorecard, against the board's answers"))
    width = max(len(command) for command, _ in steps)
    return [f"run folder: {shown}", "next:"] + [f"  {command:<{width}}  {what}" for command, what in steps]


def _scorable(run_dir: Path) -> bool:
    """Whether `flightdeck score RUN_DIR` can score the run: what it reads is there (the board
    run.json records, and answers: the file the run was given, or the board's own)."""
    from .platform.manual import BoardError, load_board
    from .runrecord import RunFolderError, read_run_info

    try:
        info = read_run_info(run_dir)
    except RunFolderError:
        return False
    if info is None or info.board is None:
        return False
    try:
        return load_board(info.board, answers=info.answers).answers is not None
    except (BoardError, OSError):
        return False


def _flags_left_waiting(deck) -> list[str]:
    """The flags lanes still waited for the player to approve when the run ended (so never
    submitted), as "L01 Name: flag", made safe to print (they come from a lane)."""
    from .core.model import PendingKind
    from .text import untrusted

    out = []
    for lane in sorted(deck.lanes.values(), key=lambda lane: lane.number):
        for pending in ([lane.pending] if lane.pending is not None else []) + list(lane.waiting):
            if pending.kind is PendingKind.SUBMIT and pending.flag:
                name = untrusted(deck.challenges[lane.challenge_id].name, one_line=True)
                out.append(f"{lane.id} {name}: {untrusted(pending.flag, one_line=True)}")
    return out


def _ask(question: str) -> bool:
    """A yes/no question to the player at the terminal; no is the default."""
    return typer.confirm(question, default=False)


@app.command(rich_help_panel=PLAY)
def practice(
    config: Annotated[
        Path | None, typer.Option("--config", dir_okay=False, help="Config file (default: $FLIGHTDECK_CONFIG or ~/.config/ctf-flightdeck/config.toml).")
    ] = None,
    max_lanes: Annotated[int | None, typer.Option("--max-lanes", min=1, help="Concurrent lanes (default: the config's).")] = None,
    host: Annotated[
        bool | None, typer.Option("--host/--docker", metavar="", help="Run lanes on this machine, or in Docker (default: the config's runtime).")
    ] = None,
    model: Annotated[str | None, typer.Option("--model", help="The model lanes start on (default: the weakest in the ladder).")] = None,
    run_dir: Annotated[Path | None, typer.Option("--run-dir", file_okay=False, help="Where run folders go (default: the config's).")] = None,
    pack: Annotated[
        Path | None, typer.Option("--pack", file_okay=False, help="Your L1 pack: no-model solvers a lane runs first (default: the config's [l1] pack).")
    ] = None,
    agent: Annotated[Agent | None, typer.Option("--agent", help=AGENT_HELP)] = None,
    agent_auth: Annotated[str | None, typer.Option("--agent-auth", metavar="HOW", help=AGENT_AUTH_HELP)] = None,
    headless: Annotated[bool, typer.Option("--headless", metavar="", help=HEADLESS_HELP)] = False,
    autopilot: Annotated[bool | None, typer.Option("--autopilot/--no-autopilot", metavar="", help=AUTOPILOT_HELP)] = None,
    budget_dollars: Annotated[float | None, typer.Option("--budget-dollars", min=0.0, metavar="DOLLARS", help=BUDGET_DOLLARS_HELP)] = None,
    budget_tokens: Annotated[int | None, typer.Option("--budget-tokens", min=1, metavar="TOKENS", help=BUDGET_TOKENS_HELP)] = None,
) -> None:
    """Play the practice set that ships with flightdeck (14 small synthetic challenges, answers
    checked by hash). Spends tokens like `play`."""
    from .practice_set import practice_dir

    try:
        board = practice_dir()
    except FileNotFoundError as exc:
        typer.echo(f"flightdeck: {exc}", err=True)
        raise typer.Exit(2) from None
    play(
        board=board, answers=None, config=config, max_lanes=max_lanes, host=host,
        team=False, submit=None, model=model, run_dir=run_dir, pack=pack, agent=agent, agent_auth=agent_auth,
        headless=headless,
        autopilot=autopilot, budget_dollars=budget_dollars, budget_tokens=budget_tokens,
    )


image_app = typer.Typer(no_args_is_help=True, help="The lane image: what a lane's shell has inside its container.")
app.add_typer(image_app, name="image", rich_help_panel=SETUP)


@image_app.command("build")
def image_build(
    tag: Annotated[str, typer.Option("--tag", show_default=False, help="Image name and tag (default: ctf-flightdeck-lane:1, the [lanes] image init writes; another tag needs [lanes] image set to it).")] = "",
) -> None:
    """Build the lane image with Docker (pulls the Debian base image and packages)."""
    import subprocess

    from .agent.workspace import docker_unavailable
    from .lane import IMAGE, build_command, context_dir

    reason = docker_unavailable()
    if reason:
        typer.echo(f"flightdeck: building the lane image needs Docker: {reason}", err=True)
        raise typer.Exit(2)
    argv = build_command(tag or IMAGE)
    typer.echo(f"flightdeck: {' '.join(argv)}", err=True)
    result = subprocess.run(argv, cwd=context_dir())
    if result.returncode != 0:
        typer.echo(f"flightdeck: docker build failed (exit {result.returncode})", err=True)
        raise typer.Exit(result.returncode)
    typer.echo(f"built {tag or IMAGE}")


@image_app.command("dockerfile")
def image_dockerfile() -> None:
    """Print the lane image's Dockerfile."""
    from .lane import dockerfile

    typer.echo(dockerfile(), nl=False)


@app.command(rich_help_panel=SETUP)
def init(
    provider: Annotated[str | None, typer.Option("--provider", help="openrouter, anthropic, openai, ollama (or local), mlx (an MLX server) or custom.")] = None,
    base_url: Annotated[str | None, typer.Option("--base-url", help="The API's base URL (custom provider).")] = None,
    key_env: Annotated[str | None, typer.Option("--key-env", help="The environment variable that will hold your key.")] = None,
    models: Annotated[str | None, typer.Option("--models", help="Model ids, weakest first, comma-separated.")] = None,
    host: Annotated[bool | None, typer.Option("--host/--docker", metavar="", help="Run lanes on this machine, or in Docker.")] = None,
    runtime: Annotated[str | None, typer.Option("--runtime", metavar="docker|host", help="The same as --docker or --host.")] = None,
    max_lanes: Annotated[int, typer.Option("--max-lanes", min=1, help="Lanes at a time.")] = 4,
    fallback: Annotated[bool | None, typer.Option(
        "--fallback/--no-fallback", metavar="",
        help="With --provider anthropic: OpenRouter (OPENROUTER_API_KEY) for a lane whose calls to Anthropic keep failing. "
             "At a terminal you are asked when that key is set.")] = None,
    path: Annotated[Path | None, typer.Option("--path", dir_okay=False, help="Where to write it (default: the usual config path).")] = None,
    force: Annotated[bool, typer.Option("--force", metavar="", help="Replace an existing config.")] = False,
    light: Annotated[str, typer.Option("--light", help="The light model for small jobs: rules (none, the default); ollama or "
                                       "mlx (an open-weight model on this machine: recommended, with --light-model); anthropic; cactus; "
                                       "decider (a Strands Decider server on this machine, port 8000).")] = "rules",
    light_model: Annotated[str | None, typer.Option("--light-model", help="The light model's id (anthropic: claude-haiku-5-5 by default; "
                                                    "decider: optional, the model its server must serve).")] = None,
) -> None:
    """Write a config by answering a few questions (or give them all as options)."""
    from .setup import SUGGESTED_LIGHT, light_answers, light_line

    light_choice = light.strip().lower()
    # at a terminal, a light model on this machine without --light-model is asked for, with a suggestion
    ask_light = light_choice in SUGGESTED_LIGHT and not light_model and _at_terminal()
    try:
        light_table = None if ask_light else light_answers(light_choice, light_model)
    except ValueError as exc:
        typer.echo(f"flightdeck: {exc}", err=True)
        raise typer.Exit(2) from None
    from .agent.workspace import docker_unavailable
    from .config import ConfigError, default_config_path
    from .keys import KeysError, keys_path, source
    from .setup import (
        ANTHROPIC,
        ANTHROPIC_LADDER,
        BENCHMARK,
        LOCAL_PROVIDERS,
        PROVIDERS,
        RUNTIME_QUESTION,
        SUGGESTED_LADDERS,
        AnswerError,
        Answers,
        anthropic_fallback,
        anthropic_prices,
        base_url_answer,
        image_present,
        key_env_answer,
        light_model_answer,
        mlx_server_command,
        models_answer,
        PROVIDER_MENU,
        provider_answer,
        providers_answer,
        runtime_answer,
        write_config,
    )

    from .lane import IMAGE as LANE_IMAGE

    interactive = _at_terminal()

    def fail(text: str) -> NoReturn:
        typer.echo(f"flightdeck: {text}", err=True)
        raise typer.Exit(2)

    def given(value: str, option: str, check):
        """An answer given as an option, checked; a bad one names the option."""
        try:
            return check(value)
        except AnswerError as exc:
            fail(f"{option}: {exc}")

    def ask(question: str, check, default: str | None = None):
        """An answer asked at the terminal, checked as it is typed: a bad one is asked again."""

        def proc(value: str):
            try:
                return check(value)
            except AnswerError as exc:
                raise typer.BadParameter(str(exc)) from None

        return typer.prompt(question, default=default, value_proc=proc)

    def known(variable: str) -> bool:
        """Whether the player has this key, in the environment or the keys file (never its value)."""
        try:
            return source(variable) is not None
        except KeysError:
            return False  # doctor reports the keys file

    target = _path(path or default_config_path())
    if target.exists() and not force:  # said before any question, so no answer is lost
        fail(f"{target} exists; `flightdeck init --force` replaces it, or `--path FILE` writes another")
    if runtime is not None:
        chosen = given(runtime, "--runtime", runtime_answer)
        if host is not None and host != (chosen == "host"):
            fail(f"--runtime {chosen} and --{'host' if host else 'docker'} disagree: give one of them")
        host = chosen == "host"
    if provider is not None:
        provider = given(provider, "--provider", provider_answer)
    if not interactive:
        missing = []
        if provider is None:
            missing.append("--provider (openrouter, anthropic, openai, ollama (or local), mlx or custom)")
        if provider == "custom" and base_url is None:
            missing.append("--base-url URL")
        if provider == "custom" and key_env is None:
            missing.append("--key-env VAR (--key-env '' for a server that needs no key)")
        if models is None and provider in SUGGESTED_LADDERS:
            suggested, why = SUGGESTED_LADDERS[provider]
            missing.append(f"--models ID,ID (weakest first; suggested: --models {suggested}, {why})")
        elif models is None and provider != "anthropic":
            missing.append("--models ID,ID (weakest first)")
        if host is None:
            missing.append("--host or --docker")
        if missing:
            fail(
                "init is not at a terminal, so it cannot ask: give " + ", ".join(missing[:-1])
                + (" and " if len(missing) > 1 else "") + missing[-1] + " (see `flightdeck init --help`)"
            )
    if provider is None:
        provider, *others = ask(PROVIDER_MENU, providers_answer, "1")
        if others and provider == "anthropic" and "openrouter" in others and fallback is None:
            fallback = True  # asked for together: OpenRouter stands in when Anthropic keeps failing
            others.remove("openrouter")
        typer.echo(f"Lanes use {provider}." + (
            f" One API runs the lanes; for {' and '.join(others)} as a fallback, write [fallback] in the config "
            "(`flightdeck config --example` shows it)." if others else ""))
    dialect = "anthropic" if provider == "anthropic" else "openai"
    if base_url is not None:
        base_url = given(base_url, "--base-url", lambda text: base_url_answer(text, anthropic=dialect == "anthropic"))
    if key_env is not None:
        key_env = given(key_env, "--key-env", lambda text: key_env_answer(text, empty=dialect != "anthropic"))
    if provider == "anthropic":
        base_url = base_url or ANTHROPIC[0]
        key_env = ANTHROPIC[1] if key_env is None else key_env
    elif provider in PROVIDERS:
        url, env = PROVIDERS[provider]
        base_url = base_url or url
        key_env = env if key_env is None else key_env
    else:  # custom
        if base_url is None:
            base_url = ask("API base URL (OpenAI-compatible, ending in /v1 usually)", base_url_answer)
        if key_env is None:
            key_env = ask("Environment variable for the key (empty if none)", key_env_answer, "")
    if fallback is not None and dialect != "anthropic":
        fail("--fallback is for --provider anthropic (write [fallback] in the config for others)")
    question = "Models, weakest first, comma-separated"
    if models is not None:
        ladder = given(models, "--models", models_answer)
    elif dialect == "anthropic":
        default_ladder = ",".join(ANTHROPIC_LADDER)
        ladder = ask(question, models_answer, default_ladder) if interactive else models_answer(default_ladder)
    else:
        if provider == "openrouter":
            typer.echo("Model ids look like vendor/model; see https://openrouter.ai/models")
        suggested, why = SUGGESTED_LADDERS.get(provider, (None, ""))
        if suggested is not None:
            typer.echo(f"Suggested: {suggested}, {why}. Press Enter to take it, or give your own.")
        ladder = ask(question, models_answer, suggested)
    prices = anthropic_prices(ladder) if dialect == "anthropic" else {}  # the refusal fallback's models too
    spare, offer = None, ""
    if dialect == "anthropic":
        candidate = anthropic_fallback(ladder)
        if candidate is None and fallback:
            fail("--fallback: OpenRouter's name is not known here for every model in the ladder; "
                 "write [fallback] in the config yourself (see `flightdeck config --example`)")
        if candidate is not None and fallback is None and known(candidate.key_env):
            if interactive:
                fallback = typer.confirm(
                    f"{candidate.key_env} is set: use OpenRouter for a lane whose calls to Anthropic keep failing?", default=True)
            else:
                offer = (f"note: {candidate.key_env} is set: `flightdeck init --provider anthropic --fallback` "
                         "also writes OpenRouter as the fallback when Anthropic keeps failing")
        if fallback and candidate is not None:
            spare = candidate
    if host is None:
        docker_reason = docker_unavailable()
        default = "docker" if docker_reason is None else "host"
        lanes_at = ask(RUNTIME_QUESTION + ("" if docker_reason is None else f" (docker: {docker_reason})"),
                       runtime_answer, default)
    else:
        lanes_at = "host" if host else "docker"
    if ask_light:
        suggested, why = SUGGESTED_LIGHT[light_choice]
        typer.echo(f"Suggested light model: {suggested}, {why}. Press Enter to take it, or give your own.")
        light_table = light_answers(light_choice, ask("Light model, as your server names it", light_model_answer, suggested))
    # A local model costs nothing and reports no cost: a dollar cap would only make every lane
    # stop once to ask whether to carry on without it.
    dollar_cap = None if provider in LOCAL_PROVIDERS else 2.0
    from .config import LOCAL_MAX_TOKENS, LOCAL_TIMEOUT
    from .light import on_this_machine

    here = dialect == "openai" and on_this_machine(base_url)  # a server on this machine: its replies can take minutes
    mlx_here = provider == "mlx" and on_this_machine(base_url)  # the lanes' MLX server, at whatever port it was given
    if light_table is not None and light_choice == "mlx" and mlx_here and light_table.model == ladder[0]:
        from dataclasses import replace

        light_table = replace(light_table, base_url=base_url)  # the one server the player starts serves both
    answers = Answers(base_url, key_env or "", ladder, lanes_at, max_lanes, dollar_cap=dollar_cap,
                      provider=dialect, prices=prices, fallback=spare, light=light_table,
                      timeout=LOCAL_TIMEOUT if here else None, max_tokens=LOCAL_MAX_TOKENS if here else None)
    try:
        written = write_config(answers, target, force=force)
    except (ConfigError, FileExistsError) as exc:
        fail(str(exc))
    except OSError as exc:
        fail(f"cannot write {target}: {exc.strerror or type(exc).__name__}")
    typer.echo(f"wrote {written}")
    if lanes_at == "host":  # said where the runtime is chosen, not only when play starts
        from .run import host_warning

        typer.echo(f"warning: {host_warning()}")
    if spare is not None:
        typer.echo(f"with OpenRouter as the fallback ({', '.join(spare.ladder)})")
    if here:
        typer.echo(f"lane calls: {LOCAL_TIMEOUT} s per try and replies of up to {LOCAL_MAX_TOKENS} tokens, for a server "
                   "on this machine: a local model can take minutes for one reply (the default 180 s gave up on Gemma 4 "
                   f"12B's replies {BENCHMARK}); change timeout and max_tokens under [api]")
    from .setup import OLLAMA_CONTEXT_NOTE, is_ollama

    if dialect == "openai" and is_ollama(base_url):
        typer.echo(f"context: {OLLAMA_CONTEXT_NOTE}")
    if provider == "mlx":
        typer.echo(f"next: start the MLX server: {mlx_server_command(ladder[0], base_url)}   (thinking off, and a reply cap of "
                   "8192 tokens instead of its 512: with these, Qwen3.5 9B solved 2 of 4 practice challenges on MLX "
                   f"{BENCHMARK})")
    if light_table is not None and light_choice == "mlx":
        import shlex
        from urllib.parse import urlsplit

        served = shlex.quote(light_table.model)
        port = urlsplit(light_table.base_url).port  # [light]'s: mlx_lm.server's default 8080, or the lanes' (above)
        if not (mlx_here and urlsplit(base_url).port == port):  # a server of its own, at the default port
            typer.echo(f"next: serve the light model: mlx_lm.server --model {served}   (flightdeck asks for thinking off "
                       "with each request, so it needs no flag for that)")
        elif light_table.model != ladder[0]:  # the lanes' server, which holds one model at a time
            typer.echo(f"note: lanes and the light model share the MLX server at {urlsplit(base_url).netloc}, which holds "
                       "one model at a time; to keep both loaded, serve the light model on another port (mlx_lm.server "
                       f"--model {served} --port {port + 1}) and set [light] base_url to http://127.0.0.1:{port + 1}/v1")
    try:
        keys_file = str(keys_path())
    except KeysError:
        keys_file = "the keys file"
    for variable in (key_env, spare.key_env if spare is not None else ""):
        if not variable:
            continue
        try:
            where = source(variable)
        except KeysError:
            where = None  # a keys file flightdeck refuses to read: doctor says why
        if where is not None:
            shown = keys_file if where == "keys file" else "your environment"
            typer.echo(f"key: {variable} is set in {shown} (its value is never shown or stored)")
        else:
            typer.echo(f"next: put {variable}=<your key> in {keys_file} (chmod 600), or export {variable}=<your key>  "
                       "(flightdeck never stores it)")
    if offer:
        typer.echo(offer)
    if lanes_at == "docker" and not image_present(LANE_IMAGE):  # the image init wrote; a built one needs no step
        typer.echo("next: flightdeck image build   (builds the lane image once)")
    typer.echo(light_line(light_table))
    typer.echo("then: flightdeck doctor, and flightdeck practice")
    typer.echo("for an event: flightdeck start   (asks for the event's name, site and token, makes its folder, launches)")
    typer.echo("optional: flightdeck pack install   (flightdeck's solver pack: some 800 no-model solvers that run first)")


@app.command(rich_help_panel=SETUP)
def doctor(
    config: Annotated[Path | None, typer.Option("--config", dir_okay=False, help="The config file to check.")] = None,
    agent: Annotated[Agent | None, typer.Option("--agent", help="Also check this coding-agent CLI and its credential (play --agent).")] = None,
    clean: Annotated[
        bool,
        typer.Option("--clean", metavar="", help="Remove what runs left running when flightdeck itself was killed (play and practice do this when they start)."),
    ] = False,
) -> None:
    """Check your setup (Python, the config and its keys, a local model server, the light model,
    Docker and the lane image, your terminal) and say how to fix each problem; and list what a
    killed flightdeck left running."""
    from .setup import doctor as run_checks
    from .setup import report

    kind = agent.value if agent else None
    text, status = report(run_checks(_path(config) if config else None, agent=kind, clean=clean), agent=kind)
    typer.echo(text, nl=False)
    raise typer.Exit(status)


@app.command("config", rich_help_panel=SETUP)
def config_command(
    example: Annotated[bool, typer.Option("--example", metavar="", help="Print a commented example config and exit.")] = False,
    path: Annotated[Path | None, typer.Option("--path", dir_okay=False, help="The config file to check.")] = None,
) -> None:
    """Check your config (or print an example). Never prints the API key."""
    from .config import ConfigError, default_config_path, example_config, load_config
    from .run import environment_has_key

    if example:
        typer.echo(example_config(), nl=False)
        return
    target = _path(path or default_config_path())
    try:
        loaded = load_config(target)
    except ConfigError as exc:
        typer.echo(f"flightdeck: {exc}", err=True)
        raise typer.Exit(2) from None
    lanes = loaded.lanes
    key = loaded.api.key_env
    typer.echo(f"config: {target}")
    typer.echo(f"api: {loaded.api.base_url} ({loaded.api.provider})")
    typer.echo(f"key: {key or '(none needed)'}" + (f" is {'set' if environment_has_key(loaded) else 'NOT set'}" if key else ""))
    typer.echo(f"models (weakest first): {', '.join(loaded.models)}")
    spare = loaded.fallback
    if spare is not None:
        typer.echo(f"fallback: {spare.base_url} ({spare.provider}), key {spare.key_env or '(none needed)'}"
                   + (f" is {'set' if environment_has_key(loaded, fallback=True) else 'NOT set'}" if spare.key_env else ""))
        typer.echo(f"fallback models: {', '.join(spare.ladder)}")
    named = dict.fromkeys([*loaded.models, *(m for ladder in loaded.agents.values() for m in ladder)])  # [agents] models too
    priced = [m for m in named if m in loaded.prices] + [m for m in loaded.prices if m not in named]  # the refusal fallback's
    typer.echo(f"prices from config: {', '.join(priced) or 'none (the API reports cost, or it shows as unknown)'}")
    typer.echo(f"lanes: {lanes.max_lanes} at a time, runtime {lanes.runtime}" + (f" ({lanes.image})" if lanes.runtime == "docker" else ""))
    tokens = f"{lanes.token_cap} tokens" if lanes.token_cap else "no token cap"
    dollars = f"${lanes.dollar_cap:g}" if lanes.dollar_cap else "no dollar cap"
    typer.echo(f"caps per lane: {tokens}, {dollars}; submit {lanes.submit}")
    typer.echo(f"runs go to: {loaded.run_dir}")


# ---------------------------------------------------------------------- the components' own commands
# Each lives in its component's module (heavy imports inside the command, so mounting costs
# little at startup) and is mounted here.


def _mount() -> None:
    from . import (
        build_cli, gaps_cli, localmodel_cli, pack_cli, postflight_cli, practice_cli, preflight_cli, share_cli, start_cli, team_cli, vpn_cli, writeup_cli,
    )
    from . import models_cli
    from .l1 import cli as l1_cli
    from .platform import ctfd_cli, gamemaster_cli

    app.add_typer(preflight_cli.app, name="preflight", rich_help_panel=EVENT,
                  help="Check an event profile (event.toml): what the rules allow, and what flightdeck will do.")
    app.add_typer(ctfd_cli.app, name="ctfd", rich_help_panel=EVENT)
    app.add_typer(gamemaster_cli.app, name="gm", rich_help_panel=EVENT)
    app.add_typer(team_cli.app, name="team", rich_help_panel=EVENT)
    app.add_typer(vpn_cli.app, name="vpn", rich_help_panel=EVENT)
    app.add_typer(l1_cli.app, name="l1", rich_help_panel=SOLVERS)
    app.add_typer(pack_cli.app, name="pack", rich_help_panel=SOLVERS)
    app.command("start", rich_help_panel=PLAY)(start_cli.start)
    app.command("add", rich_help_panel=EVENT)(start_cli.add)
    app.command("report", rich_help_panel=AFTER)(postflight_cli.report_command)
    app.command("writeups", rich_help_panel=AFTER)(writeup_cli.writeups)
    app.command("score", rich_help_panel=AFTER)(practice_cli.score_command)
    app.command("gaps", rich_help_panel=AFTER)(gaps_cli.gaps_command)
    app.command("share", rich_help_panel=AFTER)(share_cli.share_command)
    app.add_typer(build_cli.app, name="build", rich_help_panel=SOLVERS,
                  help="Build mode: turn a gap into a new L1 engine, with a test that proves a raw handout reaches it.")
    app.command("eval-local", rich_help_panel=SETUP)(localmodel_cli.eval_local)
    app.command("models", rich_help_panel=SETUP)(models_cli.models_command)


_mount()


def _first_console() -> bool:
    """Whether this is the player's first real console on this machine (it opens on the
    welcome screen); noted in the state folder so the next one opens on the dashboard."""
    from .leftovers import state_folder

    try:
        note = state_folder() / "welcomed"
        if note.exists():
            return False
        note.parent.mkdir(parents=True, exist_ok=True)
        note.write_text("the welcome screen was shown\n")
    except OSError:
        return False
    return True


def _at_terminal_out() -> bool:
    """Whether what flightdeck prints goes to a terminal (not a pipe or a file)."""
    import sys

    return sys.stdout.isatty()


def _at_terminal() -> bool:
    """Whether init may ask questions (stdin is a terminal)."""
    import sys

    return sys.stdin.isatty()


def main() -> None:
    app()
