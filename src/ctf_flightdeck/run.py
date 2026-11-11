"""A real run (M1): a folder board, the player's config, agent lanes and the console,
wired together.

`prepare_run()` checks everything that would stop a run before anything starts, and says
which: the config, the board, the API key, Docker and its image (never pulled). Then the
console starts, and the board is released on the console's event loop, so lanes run
there (the deck's single-thread rule).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .agent.client import ModelClient
from .agent.driver import AgentDriver
from .agent.l1stage import L1Stage
from .agent.workspace import DockerWorkspace, HostWorkspace, Workspace, docker_unavailable
from .clock import RunClock
from .config import Config, ConfigError, api_key, load_config
from .core.deck import Deck, QueueEntry
from .core.model import Challenge, DeckConfig, Lane
from .eventlog import EventLog, new_run_dir
from .transcript import TranscriptLog
from .platform.manual import AnswerVerifier, Board, BoardError, cannot_check, load_board


class RunError(Exception):
    """A run cannot start; the message says why and what to do."""


@dataclass(frozen=True)
class RunOptions:
    board: Path
    answers: Path | None = None
    config: Path | None = None
    max_lanes: int | None = None
    runtime: str | None = None  # "docker" | "host"; default: the config's
    team: bool = False
    submit: str | None = None  # "confirm" | "auto"; default: the config's
    model: str | None = None  # the model lanes start on; default: the weakest in the ladder
    run_dir: Path | None = None  # where run folders go; default: the config's
    pack: Path | None = None  # the L1 pack; default: the config's [l1] pack, if any
    instance: str = "auto"  # may lanes reach a live instance: auto, confirm (each lane asks first), off


@dataclass
class Run:
    board: Board
    config: Config
    deck: Deck
    driver: AgentDriver
    client: ModelClient
    log: EventLog
    transcripts: TranscriptLog
    dir: Path
    runtime: str
    model: str
    watch: object = None  # detect.Watch: the course detectors, attached to the deck

    def notes(self) -> list[str]:
        """Things the player should know before lanes start."""
        out = []
        lanes = self.config.lanes
        l1 = self.driver.l1
        if l1 is not None:
            where = " (on this machine, as you, even though lanes run in Docker)" if self.runtime == "docker" else ""
            out.append(f"L1: {len(l1.manifests)} engine(s) from your pack run first on each challenge{where}")
        unpriced = [m for m in self.config.models if m not in self.config.prices]
        if lanes.dollar_cap and unpriced and "openrouter.ai" not in self.config.api.base_url:
            out.append(
                f"no price in your config for {', '.join(unpriced)}: if the API does not report a cost, a lane "
                f"on that model asks you once before it carries on without its ${lanes.dollar_cap:g} cap"
            )
        return out

    def entries(self) -> list[QueueEntry]:
        """The board in triage order: cheap first (fewest points, then most solves)."""
        lanes = self.config.lanes
        order = sorted(self.board.challenges, key=lambda b: (b.challenge.points, -b.challenge.solves, b.challenge.name))
        return [QueueEntry(b.challenge.id, self.model, token_cap=lanes.token_cap, dollar_cap=lanes.dollar_cap) for b in order]

    def release(self) -> None:
        """Put the board on the deck and start the first lanes (call on the console's loop)."""
        self.deck.release([b.challenge for b in self.board.challenges], self.entries(), "Board")

    async def shutdown(self) -> None:
        """Stop every lane, close its workspace, close the API client."""
        await self.driver.shutdown()
        await self.client.aclose()

    def close(self) -> None:
        self.transcripts.close()
        self.log.close()

    def scorecard(self) -> str | None:
        """After close(): the run scored against the board's answers (practice mode), or None
        when the board has no answers to check flags against."""
        if not self.board.answers:
            return None
        from .practice_mode import ScoreError, score, scorecard

        try:
            return scorecard(score(self.log.path, self.board))
        except ScoreError as exc:
            return f"no scorecard: {exc}\n"

    def app(self, refresh_seconds: float | None = 0.5):
        from .console.app import FlightdeckApp

        return FlightdeckApp(
            self.deck, refresh_seconds=refresh_seconds, on_start=self.release, on_exit=self.shutdown
        )


def prepare_run(options: RunOptions) -> Run:
    """Everything a run needs, checked up front. Raises RunError with the reason."""
    try:
        config = load_config(options.config)
    except ConfigError as exc:
        raise RunError(str(exc)) from None
    try:
        board = load_board(options.board, answers=options.answers)
    except BoardError as exc:
        raise RunError(str(exc)) from None
    try:
        key = api_key(config)
    except ConfigError as exc:
        raise RunError(str(exc)) from None
    runtime = options.runtime or config.lanes.runtime
    if runtime not in ("docker", "host"):
        raise RunError(f"runtime must be docker or host, not {runtime!r}")
    if runtime == "docker":
        _check_docker(config.lanes.image)
    model = options.model or config.models[0]
    if model not in config.models:
        raise RunError(f"model {model!r} is not in the ladder in {config.source}: {', '.join(config.models)}")
    submit = options.submit or config.lanes.submit
    run_dir = new_run_dir((options.run_dir or config.run_dir).expanduser())
    log = EventLog(run_dir / "events.jsonl")
    deck_config = DeckConfig(
        event=board.event,
        team=options.team,
        containerized=runtime == "docker",
        max_lanes=options.max_lanes or config.lanes.max_lanes,
        submit=submit,
        models=config.models,
        **({"flag_format": board.flag_format} if board.flag_format else {}),
    )
    verify = AnswerVerifier(board.answers) if board.answers else cannot_check
    handouts = {b.challenge.id: b.handout for b in board.challenges}
    l1 = _l1_stage(options.pack or config.l1.pack, handouts, run_dir, deck_config.flag_format, config.l1.concurrency)
    client = ModelClient(config.api.base_url, key)

    urls = {b.challenge.id: b.urls for b in board.challenges}

    def workspace(lane: Lane, challenge: Challenge) -> Workspace:
        root = run_dir / lane.id.lower() / "work"
        if runtime == "docker":
            return DockerWorkspace(
                root,
                handouts[challenge.id],
                image=config.lanes.image,
                name=f"flightdeck-{run_dir.name}-{lane.id.lower()}",
                network=lane_network(urls[challenge.id]) if options.instance == "auto" else "none",
            )
        return HostWorkspace(root, handouts[challenge.id])

    driver = AgentDriver(
        client,
        workspace,
        run_id=run_dir.name,
        files={b.challenge.id: b.challenge.files for b in board.challenges},
        urls=urls,
        prices=config.prices,
        l1=l1,
        instance=options.instance,
    )
    deck = Deck(deck_config, driver, RunClock(), verify)
    log.attach(deck)
    transcripts = TranscriptLog(run_dir / "lanes")
    transcripts.attach(deck)
    watch = _watch(deck)
    return Run(board, config, deck, driver, client, log, transcripts, run_dir, runtime, model, watch)


def _l1_stage(pack: Path | None, handouts: dict[str, Path], run_dir: Path, flag_format: str, concurrency: int) -> L1Stage | None:
    """The L1 stage for a pack, checked before anything starts; None without a pack."""
    if pack is None:
        return None
    from .l1.manifest import ManifestError, discover

    try:
        manifests = discover(pack.expanduser())
    except ManifestError as exc:
        raise RunError(f"the L1 pack cannot be used: {exc}") from None
    if not manifests:
        raise RunError(
            f"the L1 pack {pack} has no engines (no .manifest.toml files): `flightdeck l1 import` writes them "
            "for a folder of scripts"
        )
    return L1Stage(manifests, handouts, run_dir, flag_format, concurrency=concurrency)


def _watch(deck: Deck):
    """The course detectors (M3), raising and clearing alerts after every turn."""
    from .detect import Watch, default_detectors

    watch = Watch(deck, default_detectors())
    watch.attach()
    return watch


def _check_docker(image: str) -> None:
    reason = docker_unavailable()
    if reason:
        raise RunError(f"the docker runtime needs Docker: {reason}. Start Docker, or run lanes on this machine with --host")
    docker = shutil.which("docker") or "docker"
    found = subprocess.run([docker, "image", "inspect", image], capture_output=True, text=True)
    if found.returncode != 0:
        from .lane import IMAGE

        how = "`flightdeck image build`" if image == IMAGE else f"`docker pull {image}`"
        raise RunError(
            f"the lane image {image} is not on this machine, and flightdeck never fetches images by "
            f"itself: run {how}, or set [lanes] image in your config"
        )


def lane_network(urls: tuple[str, ...]) -> str:
    """A docker lane gets a network only when its challenge has a live instance to reach.
    Without one it gets none, so it cannot fetch solutions or talk to anything else."""
    return "bridge" if urls else "none"


def host_warning() -> str:
    return (
        "Lanes run on this machine (runtime host): their shell has your user account, so a lane "
        "can read your files and the environment of your processes, including flightdeck's, which "
        "holds your API key. Use the docker runtime, a disposable VM, or a separate low-limit key."
    )


def environment_has_key(config: Config, environ: Mapping[str, str] = os.environ) -> bool:
    """Whether the API key variable is set (never its value)."""
    return not config.api.key_env or bool(environ.get(config.api.key_env))
