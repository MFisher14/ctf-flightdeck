"""Command line: `flightdeck` (also installed as `ctfdeck`)."""

from __future__ import annotations

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

app = typer.Typer(
    name="flightdeck",
    add_completion=False,
    rich_markup_mode="markdown",
    help="A terminal harness for playing CTFs with AI agents, where you run the loop.",
    epilog="New here? `flightdeck init`, then `flightdeck doctor`, then `flightdeck practice`. "
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
        bool, typer.Option("--version", callback=_version, is_eager=True, help="Show the version and exit.")
    ] = False,
) -> None:
    """A terminal harness for playing CTFs with AI agents, where you run the loop."""
    if ctx.invoked_subcommand is None:
        typer.echo(_next_steps(), nl=False)


def _next_steps() -> str:
    """What `flightdeck` alone says: what it is, and the next step on this machine."""
    from .config import ConfigError, default_config_path

    head = f"flightdeck {__version__}: a terminal harness for playing CTFs with AI agents, where you run the loop.\n\n"
    try:
        path = default_config_path()
        have = path.exists()
    except ConfigError as exc:
        return head + f"{exc}\n"
    if not have:
        steps = [
            ("flightdeck init", "a few questions; writes your config"),
            ("flightdeck doctor", "checks your setup and says how to fix what is missing"),
            ("flightdeck practice", "plays 14 small practice challenges that ship with flightdeck"),
        ]
        text = head + "No config yet. Start here:\n"
    else:
        steps = [
            ("flightdeck doctor", "checks your setup"),
            ("flightdeck practice", "the practice set, or: flightdeck play BOARD"),
        ]
        text = head + f"Your config: {path}\n"
    width = max(len(command) for command, _ in steps)
    text += "".join(f"  {command:<{width}}  {what}\n" for command, what in steps)
    return text + "\nNo setup at all: flightdeck mock (fake data, nothing spent). Every command: flightdeck --help\n"


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
        bool | None, typer.Option("--team/--solo", help="Team or solo mode (default: the scenario's; default is team).")
    ] = None,
    host: Annotated[
        bool | None, typer.Option("--host/--docker", help="Show lanes running on the host instead of in Docker.")
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
    """Open the console on fake, scripted data (M0 mock). No models, no network."""
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
    FlightdeckApp(world.deck, ticker=world.tick, tick_seconds=1.0 / speed, mock=f"MOCK · {scenario.value}").run()


class Submit(StrEnum):
    confirm = "confirm"
    auto = "auto"


class Agent(StrEnum):
    claude = "claude"
    codex = "codex"


AGENT_HELP = "Lanes are this coding-agent CLI (its own login or key and models: [agents] in your config) instead of flightdeck's own loop."
AGENT_AUTH_HELP = "The CLI's credential: claude api-key or oauth-token; codex api-key or login (default: the one the CLI would use)."


@app.command(rich_help_panel=PLAY)
def play(
    board: Annotated[
        Path | None,
        typer.Argument(
            file_okay=False, dir_okay=True, show_default=False,
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
        bool | None, typer.Option("--host/--docker", help="Run lanes on this machine, or in Docker (default: the config's runtime).")
    ] = None,
    team: Annotated[
        bool | None, typer.Option("--team/--solo", help="Team or solo mode (default: the event profile's, else solo).")
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
        Submit | None, typer.Option("--submit", help="confirm: you approve each flag; auto: submit at once (default: the config's).")
    ] = None,
    model: Annotated[str | None, typer.Option("--model", help="The model lanes start on (default: the weakest in the ladder).")] = None,
    run_dir: Annotated[Path | None, typer.Option("--run-dir", file_okay=False, help="Where run folders go (default: the config's).")] = None,
    pack: Annotated[
        Path | None, typer.Option("--pack", file_okay=False, help="Your L1 pack: no-model solvers a lane runs first (default: the config's [l1] pack).")
    ] = None,
    agent: Annotated[Agent | None, typer.Option("--agent", help=AGENT_HELP)] = None,
    agent_auth: Annotated[str | None, typer.Option("--agent-auth", metavar="HOW", help=AGENT_AUTH_HELP)] = None,
) -> None:
    """Play a board with agent lanes; with --event, by the event's rules: its CTFd board
    (pulled, new waves, flags submitted, solves followed) and the team folder. Spends tokens
    on the API in your config."""
    from .run import RunError, RunOptions, host_warning, prepare_run

    options = RunOptions(
        board=_path(board) if board else None,
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
        confirm=_ask if _at_terminal() else None,
        agent=agent.value if agent else None,
        agent_auth=agent_auth,
    )
    try:
        run = prepare_run(options)
    except RunError as exc:
        typer.echo(f"flightdeck: {exc}", err=True)
        raise typer.Exit(2) from None
    if run.runtime == "host":
        typer.echo(f"flightdeck: {host_warning()}", err=True)
    for note in run.notes():
        typer.echo(f"flightdeck: {note}", err=True)
    console = run.app()
    try:
        console.run()
    finally:
        run.close()
        card = run.scorecard()
        if card:
            typer.echo(card, nl=False)
        typer.echo(f"run log: {run.log.path}")
        waiting = _flags_left_waiting(run.deck)
        if waiting:
            typer.echo(f"flightdeck: not submitted, still waiting for your approval when the run ended: {'; '.join(waiting)}", err=True)
        for problem in run.errors:
            typer.echo(f"flightdeck: {problem}", err=True)
    if console.stopped_by is not None:  # SIGHUP or SIGTERM: the lanes were stopped as when you quit
        typer.echo(f"flightdeck: {console.stopped_by.name}: the run's lanes were stopped as when you quit", err=True)
        raise typer.Exit(128 + console.stopped_by)


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
        bool | None, typer.Option("--host/--docker", help="Run lanes on this machine, or in Docker (default: the config's runtime).")
    ] = None,
    model: Annotated[str | None, typer.Option("--model", help="The model lanes start on (default: the weakest in the ladder).")] = None,
    run_dir: Annotated[Path | None, typer.Option("--run-dir", file_okay=False, help="Where run folders go (default: the config's).")] = None,
    pack: Annotated[
        Path | None, typer.Option("--pack", file_okay=False, help="Your L1 pack: no-model solvers a lane runs first (default: the config's [l1] pack).")
    ] = None,
    agent: Annotated[Agent | None, typer.Option("--agent", help=AGENT_HELP)] = None,
    agent_auth: Annotated[str | None, typer.Option("--agent-auth", metavar="HOW", help=AGENT_AUTH_HELP)] = None,
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
    )


image_app = typer.Typer(no_args_is_help=True, help="The lane image: what a lane's shell has inside its container.")
app.add_typer(image_app, name="image", rich_help_panel=SETUP)


@image_app.command("build")
def image_build(
    tag: Annotated[str, typer.Option("--tag", help="Image name and tag.")] = "",
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
    provider: Annotated[str | None, typer.Option("--provider", help="openrouter, anthropic, openai, local (Ollama), mlx (an MLX server) or custom.")] = None,
    base_url: Annotated[str | None, typer.Option("--base-url", help="The API's base URL (custom provider).")] = None,
    key_env: Annotated[str | None, typer.Option("--key-env", help="The environment variable that will hold your key.")] = None,
    models: Annotated[str | None, typer.Option("--models", help="Model ids, weakest first, comma-separated.")] = None,
    host: Annotated[bool | None, typer.Option("--host/--docker", help="Run lanes on this machine, or in Docker.")] = None,
    runtime: Annotated[str | None, typer.Option("--runtime", metavar="docker|host", help="The same as --docker or --host.")] = None,
    max_lanes: Annotated[int, typer.Option("--max-lanes", min=1, help="Lanes at a time.")] = 4,
    fallback: Annotated[bool | None, typer.Option(
        "--fallback/--no-fallback",
        help="With --provider anthropic: OpenRouter (OPENROUTER_API_KEY) for a lane whose calls to Anthropic keep failing. "
             "At a terminal you are asked when that key is set.")] = None,
    path: Annotated[Path | None, typer.Option("--path", dir_okay=False, help="Where to write it (default: the usual config path).")] = None,
    force: Annotated[bool, typer.Option("--force", help="Replace an existing config.")] = False,
    light: Annotated[str, typer.Option("--light", help="The light model for small jobs: rules (none, the default); ollama or "
                                       "mlx (an open-weight model on this machine: recommended, with --light-model); anthropic; cactus; "
                                       "decider (a Strands Decider server on this machine, port 8000).")] = "rules",
    light_model: Annotated[str | None, typer.Option("--light-model", help="The light model's id (anthropic: claude-haiku-5-5 by default; "
                                                    "decider: optional, the model its server must serve).")] = None,
) -> None:
    """Write a config by answering a few questions (or give them all as options)."""
    from .setup import light_answers, light_line

    try:
        light_table = light_answers(light.strip().lower(), light_model)
    except ValueError as exc:
        typer.echo(f"flightdeck: {exc}", err=True)
        raise typer.Exit(2) from None
    from .agent.workspace import docker_unavailable
    from .config import ConfigError, default_config_path
    from .keys import KeysError, keys_path, source
    from .setup import (
        ANTHROPIC,
        ANTHROPIC_LADDER,
        ANTHROPIC_PRICES,
        LOCAL_PROVIDERS,
        PROVIDERS,
        AnswerError,
        Answers,
        anthropic_fallback,
        base_url_answer,
        key_env_answer,
        models_answer,
        provider_answer,
        runtime_answer,
        write_config,
    )

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
            missing.append("--provider (openrouter, anthropic, openai, local, mlx or custom)")
        if provider == "custom" and base_url is None:
            missing.append("--base-url URL")
        if provider == "custom" and key_env is None:
            missing.append("--key-env VAR (--key-env '' for a server that needs no key)")
        if models is None and provider != "anthropic":
            missing.append("--models ID,ID (weakest first)")
        if host is None:
            missing.append("--host or --docker")
        if missing:
            fail(
                "init is not at a terminal, so it cannot ask: give " + ", ".join(missing[:-1])
                + (" and " if len(missing) > 1 else "") + missing[-1] + " (see `flightdeck init --help`)"
            )
    if provider is None:
        provider = ask("Provider: openrouter, anthropic, openai, local (Ollama), mlx or custom", provider_answer, "openrouter")
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
        ladder = ask(question, models_answer)
    prices = {m: ANTHROPIC_PRICES[m] for m in ladder if m in ANTHROPIC_PRICES} if dialect == "anthropic" else {}
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
        lanes_at = ask("Runtime: docker or host" + ("" if docker_reason is None else f" (docker: {docker_reason})"),
                       runtime_answer, default)
    else:
        lanes_at = "host" if host else "docker"
    # A local model costs nothing and reports no cost: a dollar cap would only make every lane
    # stop once to ask whether to carry on without it.
    dollar_cap = None if provider in LOCAL_PROVIDERS else 2.0
    answers = Answers(base_url, key_env or "", ladder, lanes_at, max_lanes, dollar_cap=dollar_cap,
                      provider=dialect, prices=prices, fallback=spare, light=light_table)
    try:
        written = write_config(answers, target, force=force)
    except (ConfigError, FileExistsError) as exc:
        fail(str(exc))
    except OSError as exc:
        fail(f"cannot write {target}: {exc.strerror or type(exc).__name__}")
    typer.echo(f"wrote {written}")
    if spare is not None:
        typer.echo(f"with OpenRouter as the fallback ({', '.join(spare.ladder)})")
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
    if lanes_at == "docker":
        typer.echo("next: flightdeck image build   (builds the lane image once)")
    typer.echo(light_line(light_table))
    typer.echo("then: flightdeck doctor, and flightdeck practice")


@app.command(rich_help_panel=SETUP)
def doctor(
    config: Annotated[Path | None, typer.Option("--config", dir_okay=False, help="The config file to check.")] = None,
    agent: Annotated[Agent | None, typer.Option("--agent", help="Also check this coding-agent CLI and its credential (play --agent).")] = None,
) -> None:
    """Check Python, the config, the API key variable, Docker and the lane image, with fixes."""
    from .setup import doctor as run_checks
    from .setup import report

    kind = agent.value if agent else None
    text, status = report(run_checks(_path(config) if config else None, agent=kind), agent=kind)
    typer.echo(text, nl=False)
    raise typer.Exit(status)


@app.command("config", rich_help_panel=SETUP)
def config_command(
    example: Annotated[bool, typer.Option("--example", help="Print a commented example config and exit.")] = False,
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
    priced = [m for m in loaded.models if m in loaded.prices]
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
    from . import build_cli, gaps_cli, localmodel_cli, postflight_cli, practice_cli, preflight_cli, team_cli, writeup_cli
    from .l1 import cli as l1_cli
    from .platform import ctfd_cli

    app.add_typer(preflight_cli.app, name="preflight", rich_help_panel=EVENT,
                  help="Check an event profile (event.toml): what the rules allow, and what flightdeck will do.")
    app.add_typer(ctfd_cli.app, name="ctfd", rich_help_panel=EVENT)
    app.add_typer(team_cli.app, name="team", rich_help_panel=EVENT)
    app.add_typer(l1_cli.app, name="l1", rich_help_panel=SOLVERS)
    app.command("report", rich_help_panel=AFTER)(postflight_cli.report_command)
    app.command("writeups", rich_help_panel=AFTER)(writeup_cli.writeups)
    app.command("score", rich_help_panel=AFTER)(practice_cli.score_command)
    app.command("gaps", rich_help_panel=SOLVERS)(gaps_cli.gaps_command)
    app.add_typer(build_cli.app, name="build", rich_help_panel=SOLVERS,
                  help="Build mode: turn a gap into a new L1 engine, with a test that proves a raw handout reaches it.")
    app.command("eval-local", rich_help_panel=SETUP)(localmodel_cli.eval_local)


_mount()


def _at_terminal() -> bool:
    """Whether init may ask questions (stdin is a terminal)."""
    import sys

    return sys.stdin.isatty()


def main() -> None:
    app()
