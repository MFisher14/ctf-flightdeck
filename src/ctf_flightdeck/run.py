"""A real run: a board, the player's config, agent lanes and the console, wired together;
with an event profile (`play --event`), the event's rules and policies, a CTFd board and the
team channel too.

`prepare_run()` checks everything that would stop a run before anything starts, and says
which: the config, the event profile (any refusal from preflight.check() stops the run), the
board, the API key, Docker and its image (never pulled), the team folder, the CTFd token,
and then the model APIs themselves, asked once whether they take the key and serve the
ladder's models (apicheck.py). Only then does it pull a CTFd board (under the pull policy
"confirm", after the player says yes). Then the console starts, and the board is released
on the console's event loop, so lanes run there (the deck's single-thread rule); so do the
run's background tasks (CTFd waves and solves, the team watcher), which shutdown() stops.

An event profile's policies, stage by stage (preflight.py):
- agents: auto or confirm start lanes as usual (starting play is the player's yes); manual
  or off refuse the run, since play is agent lanes;
- l1: auto or confirm run the L1 pack in each lane first; manual or off do not;
- submit: auto or confirm hand flags to the board's verifier (CTFd, or an answers file), at
  once or after the player approves; manual or off never do (preflight.deck_submit): the
  player submits by hand and says how it went;
- instance: auto, confirm or off is RunOptions.instance; manual is off for lanes;
- pull (CTFd): auto pulls the board before the console starts and again every wave_seconds;
  confirm pulls it once, after the player says yes.
The profile's flag format overrides the board's, its max_lanes caps the lanes (check()
refuses more), and its team = true asks for the team folder.

A CTFd run also reads the platform's solves (at the start, then every solves_seconds): a
challenge CTFd lists as solved that this run did not solve is not queued, and is closed,
solo or team mode, as solved by whom CTFd says: "you" (this user's own solve: by hand, or
in an earlier run), "your team" (a teammate's, in CTFd's teams mode), or "you or your team"
when CTFd did not say. Its lanes stop, and the solve is a platform event the reports count
(Deck.platform_solved). The CTFd token is read from the variable event.token_env names and
lives only in the CTFd client and verifier: it is never printed, logged, or put in a note or
an error.

The team channel (team.py): mirror() writes our claims, solves and live-box holds to the
team folder as the deck makes them, and the team watcher applies the teammates' marks. A
challenge the team folder shows as solved, or claimed by a teammate, is not queued.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import getpass
import json
import math
import os
import shlex
import shutil
import subprocess
from collections.abc import Callable, Collection, Coroutine, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from .agent.client import ChatClient
from .agent.driver import AgentDriver
from .agent.fallback import api_name, build_client
from .agent.l1stage import L1Stage
from .agent.workspace import DockerWorkspace, HostWorkspace, Workspace, docker_unavailable
from .clock import RunClock
from .config import Config, ConfigError, api_key, fallback_key, load_config
from .core.deck import Deck, QueueEntry
from .core.model import Challenge, DeckConfig, Lane, PendingKind
from .eventlog import EventLog, new_run_dir
from .platform.ctfd import CTFdClient, CTFdError, CTFdVerifier, Pull, Solves, check_site, load_ids, pull
from .platform.manual import AnswerVerifier, Board, BoardChallenge, BoardError, cannot_check, load_board
from .preflight import (
    USES_PLATFORM,
    EventProfile,
    Policies,
    Policy,
    ProfileError,
    check,
    deck_submit,
    load_profile,
    looser,
    strictest,
)
from .team import HANDLE_RULE, POLL_SECONDS, TeamChannel, TeamError, TeamWatcher, mirror, printable, valid_handle
from .text import untrusted
from .transcript import TranscriptLog

WAVE_SECONDS = 120.0  # a CTFd board under the pull policy "auto" is pulled again this often (a new wave)
SOLVES_SECONDS = 60.0  # a CTFd run reads the platform's solves this often
# Who solved a challenge that CTFd lists as solved and this run did not solve, as CTFd says:
YOU = "you"  # this user (CTFd's users mode, or the user's own solve in teams mode)
YOUR_TEAM = "your team"  # a teammate, in CTFd's teams mode
YOU_OR_YOUR_TEAM = "you or your team"  # the account, when CTFd did not say whose solve it is
INSTANCE_POLICIES = ("auto", "confirm", "off")


class RunError(Exception):
    """A run cannot start; the message says why and what to do."""


@dataclass(frozen=True)
class RunOptions:
    board: Path | None = None  # the folder board; for a CTFd event, the folder its board is pulled into
    answers: Path | None = None
    config: Path | None = None
    max_lanes: int | None = None
    runtime: str | None = None  # "docker" | "host"; default: the config's
    team: bool | None = None  # team mode; None: the event profile's, else solo (team_dir turns it on)
    submit: str | None = None  # "confirm" | "auto"; default: the config's (an event's policy: never looser)
    model: str | None = None  # the model lanes start on; default: the weakest in the ladder
    run_dir: Path | None = None  # where run folders go; default: the config's
    pack: Path | None = None  # the L1 pack; default: the config's [l1] pack, if any
    instance: str = "auto"  # may lanes reach a live instance: auto, confirm (each lane asks first), off
    event: Path | None = None  # the event profile (event.toml): the event's rules and policies apply
    team_dir: Path | None = None  # the team folder teammates' flightdecks share (team.py)
    handle: str | None = None  # our handle in the team folder; default: the login name
    wave_seconds: float = WAVE_SECONDS
    solves_seconds: float = SOLVES_SECONDS
    team_seconds: float = POLL_SECONDS  # how often the team folder is read
    confirm: Callable[[str], bool] | None = None  # asks the player yes or no (the pull policy "confirm"); None: nobody to ask
    agent: str | None = None  # "claude" | "codex": lanes are that coding-agent CLI instead of flightdeck's own loop
    agent_auth: str | None = None  # the CLI's credential: claude "api-key" | "oauth-token", codex "api-key" | "login"


@dataclass(eq=False)
class CTFdLink:
    """A CTFd board during a run: the client its waves and solves use, and what the run knows."""

    client: CTFdClient  # used on the console's loop only
    folder: Path  # the board folder
    event: str
    flag_format: str | None
    ids: dict[str, int]  # board id -> CTFd id
    waves: bool  # pull "auto": the board is pulled again every wave_seconds
    solved: set[int]  # the CTFd ids CTFd last listed as solved for this account, and those it answered "already solved"
    wave: int = 1  # the board as first pulled is wave 1
    listed: frozenset[int] = frozenset()  # the CTFd ids in CTFd's last list of the account's solves
    mine: frozenset[int] | None = None  # of those, this user's own as CTFd last said; None: it did not say
    shared: bool = True  # the account is a team (CTFd's teams mode), as CTFd last said
    answered: set[str] = field(default_factory=set)  # CTFd answered a flag for it "already solved": solved, whatever a lane waits for
    reported: set[str] = field(default_factory=set)  # pull problems told to the player
    problems: dict[str, str] = field(default_factory=dict)  # what failed (a poll, or using its answer) -> the failure shown last

    def solved_board_ids(self) -> list[str]:
        """The board ids of the challenges CTFd lists as solved."""
        return [cid for cid, number in sorted(self.ids.items()) if number in self.solved]

    def read(self, solves: Solves) -> None:
        """CTFd's latest list of the account's solves."""
        self.solved = set(solves.ids)
        self.listed, self.mine, self.shared = solves.ids, solves.mine, solves.shared

    def who(self, cid: str) -> str:
        """Who solved a challenge CTFd lists as solved, as far as CTFd says."""
        number = self.ids.get(cid)
        if not self.shared:
            return YOU  # every solve of a user's account is the user's
        if self.mine is None or number not in self.listed:
            return YOU_OR_YOUR_TEAM  # CTFd did not say whose (or only answered a flag "already solved")
        return YOU if number in self.mine else YOUR_TEAM


@dataclass
class Run:
    board: Board
    config: Config
    deck: Deck
    driver: AgentDriver  # or agent.external.ExternalDriver, for a coding-agent CLI (--agent)
    client: ChatClient | None  # None when lanes are a coding-agent CLI
    log: EventLog
    transcripts: TranscriptLog
    dir: Path
    runtime: str
    model: str
    watch: object = None  # detect.Watch: the course detectors, attached to the deck
    options: RunOptions = field(default_factory=RunOptions)  # as the run uses them, the event profile applied
    profile: EventProfile | None = None
    policies: Policies | None = None
    ctfd: CTFdLink | None = None
    verifier: CTFdVerifier | None = None  # the deck's verify() for a CTFd board, when submit uses the platform
    team: TeamChannel | None = None
    _notes: list[str] = field(default_factory=list, repr=False)
    _handouts: dict[str, Path] = field(default_factory=dict, repr=False)  # shared with the workspaces and the L1 stage
    _urls: dict[str, tuple[str, ...]] = field(default_factory=dict, repr=False)
    _unmirror: Callable[[], None] | None = field(default=None, repr=False)
    _watcher: TeamWatcher | None = field(default=None, repr=False)
    _team_stop: asyncio.Event | None = field(default=None, repr=False)
    _tasks: list[asyncio.Task] = field(default_factory=list, repr=False)
    _errors: list[str] = field(default_factory=list, repr=False)

    def notes(self) -> list[str]:
        """Things the player should know before lanes start."""
        out = list(self._notes)
        lanes = self.config.lanes
        l1 = getattr(self.driver, "l1", None)
        if l1 is not None:
            where = " (on this machine, as you, even though lanes run in Docker)" if self.runtime == "docker" else ""
            out.append(f"L1: {len(l1.manifests)} engine(s) from your pack run first on each challenge{where}")
        unpriced = [m for m in self.config.models if m not in self.config.prices]
        if self.client is not None and lanes.dollar_cap and unpriced and "openrouter.ai" not in self.config.api.base_url:
            out.append(
                f"no price in your config for {', '.join(unpriced)}: if the API does not report a cost, a lane "
                f"on that model asks you once before it carries on without its ${lanes.dollar_cap:g} cap"
            )
        return out

    @property
    def errors(self) -> list[str]:
        """Problems to show when the run has ended: the lanes' cleanup, the team folder's."""
        return [*self.driver.errors, *self._errors]

    def entries(self, challenges: Sequence[BoardChallenge] | None = None, *, skip: Collection[str] = ()) -> list[QueueEntry]:
        """The challenges (default: the board's) in triage order: cheap first (fewest points,
        then most solves); the ids in `skip` are left out."""
        lanes = self.config.lanes
        items = self.board.challenges if challenges is None else challenges
        order = sorted(
            (b for b in items if b.challenge.id not in skip),
            key=lambda b: (b.challenge.points, -b.challenge.solves, b.challenge.name),
        )
        return [QueueEntry(b.challenge.id, self.model, token_cap=lanes.token_cap, dollar_cap=lanes.dollar_cap) for b in order]

    def release(self) -> None:
        """Put the board on the deck and start the first lanes, then the run's background
        tasks: CTFd waves and solves, the team watcher (call on the console's loop).

        A challenge solved on CTFd, or solved or claimed by a teammate in the team folder, is
        not queued. The team folder is read here first, on this thread, so no lane starts on
        a challenge a teammate holds."""
        state = None
        if self.team is not None:
            self._watcher = TeamWatcher(self.team, self.deck)
            state = self._watcher.poll()  # its marks wait until the board is on the deck
        self.deck.release([b.challenge for b in self.board.challenges], self.entries(skip=self._held()), "Board")
        if state is not None:
            self._watcher.apply(state)
        if self.ctfd is not None:
            self._apply_solves(before_run=True)  # what CTFd listed before the run started
            if self.ctfd.waves:
                self._tasks.append(asyncio.create_task(self._waves(), name="flightdeck CTFd waves"))
            self._tasks.append(asyncio.create_task(self._solves(), name="flightdeck CTFd solves"))
        if self._watcher is not None:
            self._team_stop = asyncio.Event()
            watching = self._watcher.run(interval=self.options.team_seconds, stop=self._team_stop)
            self._tasks.append(asyncio.create_task(watching, name="flightdeck team watcher"))

    async def shutdown(self) -> None:
        """Stop the background tasks and every lane, close the workspaces and the API clients,
        and free our live-box holds in the team folder."""
        if self._team_stop is not None:
            self._team_stop.set()
        tasks, self._tasks = self._tasks, []
        for task in tasks:
            task.cancel()
        outcomes = await asyncio.gather(*tasks, return_exceptions=True)
        for task, outcome in zip(tasks, outcomes):
            if isinstance(outcome, Exception):
                self._errors.append(f"{task.get_name()}: {type(outcome).__name__}: {outcome}")
        await self.driver.shutdown()
        if self.team is not None:
            try:
                self.team.free_boxes()  # the lanes stopped without a lane-end event, so mirror() did not see them go
            except TeamError as exc:
                self._errors.append(f"team: could not free your live-box holds in the team folder: {exc}")
        if self.client is not None:
            await self.client.aclose()
        if self.ctfd is not None:
            await self.ctfd.client.aclose()

    def close(self) -> None:
        if self._unmirror is not None:
            self._unmirror()
            self._unmirror = None
        if self.verifier is not None:
            self.verifier.close()
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

    # ------------------------------------------------------------------ the event's background work

    def _held(self) -> set[str]:
        """Board ids not to queue: solved on CTFd, or in the team folder solved (by anyone)
        or claimed by a teammate."""
        held = set(self.ctfd.solved_board_ids()) if self.ctfd is not None else set()
        state = self._watcher.latest if self._watcher is not None else None
        if state is not None and self.team is not None:
            held |= set(state.solves)
            held |= {cid for cid, mark in state.claims.items() if mark.who != self.team.me}
        return held

    def _apply_solves(self, *, before_run: bool = False) -> None:
        """Close what CTFd lists as solved and this run did not solve, solo or team mode, as
        solved by whom CTFd says (CTFdLink.who): its lanes stop, it leaves the queue, and a
        platform event records it for the reports. `before_run`: CTFd listed it before the
        run started. A challenge whose flag the player is submitting by hand waits for their
        answer (it is then the lane's solve)."""
        link = self.ctfd
        assert link is not None
        for cid in link.solved_board_ids():
            ch = self.deck.challenges.get(cid)
            if ch is None or ch.closed:
                continue
            if self._confirming(cid) and cid not in link.answered:
                continue
            self.deck.platform_solved(cid, link.who(cid), before_run=before_run)

    def _confirming(self, cid: str) -> bool:
        """Whether a lane on it waits for the player to say if a flag they submitted by hand
        was accepted (their answer closes it, as solved by that lane)."""
        for lane in self.deck.lanes_on(cid):
            queued = ([lane.pending] if lane.pending is not None else []) + lane.waiting
            if any(p.kind is PendingKind.CONFIRM for p in queued):
                return True
        return False

    async def _waves(self) -> None:
        """Pull the board again every wave_seconds and release what is new. A failure is a
        warning on the console (once while it lasts), never the end of the task."""
        link = self.ctfd
        assert link is not None
        every = self.options.wave_seconds
        while True:
            await asyncio.sleep(every)
            try:
                result = await pull(link.client, link.folder, event=link.event, flag_format=link.flag_format)
            except Exception as exc:  # CTFdError, BoardError, OSError, or a bug: say so, and try again later
                self._ctfd_problem(
                    "waves", f"could not pull new challenges from CTFd: {_reason(exc)}; flightdeck tries again in {every:g} s"
                )
                continue
            link.problems.pop("waves", None)
            try:
                self._wave(result)
            except Exception as exc:  # a bug: say so, and keep pulling
                self._ctfd_problem("release", f"could not release the new challenges from CTFd: {type(exc).__name__}: {exc}")
            else:
                link.problems.pop("release", None)

    def _wave(self, result: Pull) -> None:
        link = self.ctfd
        assert link is not None
        link.ids.update(result.ids)
        if self.verifier is not None:
            self.verifier.ids.update(result.ids)
        for line in result.problems:
            if line not in link.reported:
                link.reported.add(line)
                self.deck.warn(f"CTFd: not pulled: {line}; the next wave tries it again", data={"source": "ctfd"})
        new = [b for b in result.board.challenges if b.challenge.id not in self.deck.challenges]
        if not new:
            return
        self._add(new)
        link.wave += 1
        self.deck.release([b.challenge for b in new], self.entries(new, skip=self._held()), f"Wave {link.wave}")
        self._apply_solves()

    def _add(self, new: Sequence[BoardChallenge]) -> None:
        """New challenges on the board: their handouts and instances, for lanes and L1."""
        self.board = replace(self.board, challenges=self.board.challenges + tuple(new))
        for b in new:
            cid = b.challenge.id
            self._handouts[cid] = b.handout
            self._urls[cid] = tuple(b.urls)
            self.driver.files[cid] = b.challenge.files
            self.driver.urls[cid] = tuple(b.urls)

    async def _solves(self) -> None:
        """Read the platform's solves every solves_seconds (the board's were read before the
        run started). A failure is a warning on the console, once while it lasts."""
        link = self.ctfd
        assert link is not None
        every = self.options.solves_seconds
        while True:
            await asyncio.sleep(every)
            try:
                solves = await link.client.solves()
            except Exception as exc:  # CTFdError, or a bug: say so, and try again later
                self._ctfd_problem(
                    "solves", f"could not read the solves from CTFd: {_reason(exc)}; flightdeck tries again in {every:g} s"
                )
                continue
            link.problems.pop("solves", None)
            link.read(solves)
            try:
                self._apply_solves()
            except Exception as exc:  # a bug: say so, and keep reading
                self._ctfd_problem("apply", f"could not apply the solves from CTFd: {type(exc).__name__}: {exc}")
            else:
                link.problems.pop("apply", None)

    def _ctfd_problem(self, kind: str, text: str) -> None:
        """A failed CTFd poll, as a console warning: once while the same failure lasts."""
        link = self.ctfd
        assert link is not None
        if link.problems.get(kind) == text:
            return
        link.problems[kind] = text
        self.deck.warn(text, data={"source": "ctfd"})


# ---------------------------------------------------------------------- preparing a run


@dataclass
class _Plan:
    """The run's settings once the event profile (if any) is applied."""

    options: RunOptions  # board, max_lanes, team, submit, pack and instance as the run uses them
    profile: EventProfile | None
    policies: Policies | None
    platform: bool  # whether flags go to the board's verifier (preflight.DeckSubmit.platform)
    notes: list[str]

    @property
    def ctfd(self) -> bool:
        return self.profile is not None and self.profile.platform == "ctfd"


def prepare_run(options: RunOptions) -> Run:
    """Everything a run needs, checked up front. Raises RunError with the reason."""
    _check_options(options)
    try:
        config = load_config(options.config)
    except ConfigError as exc:
        raise RunError(str(exc)) from None
    runtime = options.runtime or config.lanes.runtime
    if runtime not in ("docker", "host"):
        raise RunError(f"runtime must be docker or host, not {runtime!r}")
    plan = _plan(options, config, runtime)
    options = plan.options
    board = None if plan.ctfd else _load_board(options)
    ladder, agent, key, spare_key = config.models, None, None, None
    if options.agent is not None:  # lanes are a coding-agent CLI: its own login, its own models
        ladder = _agent_ladder(options.agent, config, plan.notes)
        model = options.model or ladder[0]
        if model not in ladder:
            raise RunError(f"model {model!r} is not in the {options.agent} ladder: {', '.join(ladder)}")
        if options.instance != "auto":
            raise RunError(
                f'the instance policy is "{options.instance}", but a {options.agent} lane reaches whatever its CLI '
                "can reach (in Docker its container needs a network for the CLI's own API), so flightdeck "
                "cannot hold it to that: play this event with flightdeck's own lanes (no --agent)"
            )
        agent = _find_agent(options.agent, model, options.agent_auth)
        plan.notes.append(f"lanes are {options.agent} on {model} ({agent.auth})" if agent.auth else f"lanes are {options.agent} on {model}")
        plan.notes.extend(agent.warnings)
    else:
        try:
            key = api_key(config)
            spare_key = fallback_key(config)  # a [fallback] whose key is missing stops the run, as [api]'s does
        except ConfigError as exc:
            raise RunError(str(exc)) from None
        model = options.model or config.models[0]
        if model not in config.models:
            raise RunError(f"model {model!r} is not in the ladder in {config.source}: {', '.join(config.models)}")
        if config.fallback is not None:
            primary = api_name(config.api.provider, config.api.base_url)
            spare = api_name(config.fallback.provider, config.fallback.base_url)
            plan.notes.append(f"a lane whose calls to {primary} keep failing moves to {spare} for the rest of its context")
    if runtime == "docker":
        _check_docker(config.lanes.image)
        if agent is not None:
            _check_image_has(config.lanes.image, agent.kind)
    manifests = _l1_manifests(options.pack)
    team = _team_channel(options, plan)
    profile = plan.profile
    first = token = None
    if plan.ctfd:
        assert profile is not None
        token = _ctfd_token(profile)
    if agent is None:  # the model APIs, asked once (a coding-agent CLI uses its own)
        _check_apis(config, key, spare_key, plan.notes)
    if plan.ctfd:  # the last check, then the first thing done: the pull
        assert token is not None
        first = _pull_first(options, plan, token)
        board = first.board
    assert board is not None
    run_dir = new_run_dir((options.run_dir or config.run_dir).expanduser())
    log = EventLog(run_dir / "events.jsonl")
    flag_format = (profile.flag_format if profile is not None else None) or board.flag_format
    deck_config = DeckConfig(
        event=profile.name if profile is not None else board.event,
        team=bool(options.team),
        containerized=runtime == "docker",
        max_lanes=options.max_lanes,
        submit=options.submit,
        models=ladder,
        **({"flag_format": flag_format} if flag_format else {}),
    )
    handouts = {b.challenge.id: b.handout for b in board.challenges}
    urls = {b.challenge.id: tuple(b.urls) for b in board.challenges}
    l1 = None
    if manifests is not None:
        l1 = L1Stage(manifests, handouts, run_dir, deck_config.flag_format, concurrency=config.l1.concurrency)
    try:
        client = build_client(config, key, spare_key) if agent is None else None
    except ValueError as exc:  # a key no HTTP header can carry; never shown
        raise RunError(f"the model API cannot be used: {exc}") from None
    instance = options.instance
    link = verifier = None
    if first is not None:
        assert profile is not None and profile.url is not None and plan.policies is not None and token is not None
        link = CTFdLink(
            CTFdClient(profile.url, token),
            first.folder,
            profile.name,
            profile.flag_format,
            dict(first.ids),
            waves=plan.policies.pull is Policy.AUTO,
            solved=set(),
            reported=set(first.problems),
        )
        if first.solves is not None:
            link.read(first.solves)
        if plan.platform:
            verifier = CTFdVerifier(profile.url, token, first.ids)
    if verifier is not None:
        assert link is not None
        verify = _OnCTFd(verifier, link)
    elif plan.platform and board.answers:
        verify = AnswerVerifier(board.answers)
    else:
        verify = cannot_check

    def workspace(lane: Lane, challenge: Challenge) -> Workspace:
        root = run_dir / lane.id.lower() / "work"
        if runtime == "docker":
            return DockerWorkspace(
                root,
                handouts[challenge.id],
                image=config.lanes.image,
                name=f"flightdeck-{run_dir.name}-{lane.id.lower()}",
                network="bridge" if agent is not None else (lane_network(urls[challenge.id]) if instance == "auto" else "none"),
            )
        return HostWorkspace(root, handouts[challenge.id])

    files = {b.challenge.id: b.challenge.files for b in board.challenges}
    if agent is not None:
        from .agent.external import ExternalDriver

        if l1 is not None:
            plan.notes.append(f"your L1 pack is not used: L1 runs before flightdeck's own lanes, not {agent.kind} lanes (for now)")
        driver = ExternalDriver(agent, workspace, run_id=run_dir.name, files=files, urls=urls, prices=config.prices)
    else:
        assert client is not None
        driver = AgentDriver(
            client,
            workspace,
            run_id=run_dir.name,
            files=files,
            urls=urls,
            prices=config.prices,
            l1=l1,
            instance=instance,
        )
    deck = Deck(deck_config, driver, RunClock(), verify)
    if isinstance(verify, _OnCTFd):
        verify.deck = deck
    log.attach(deck)
    transcripts = TranscriptLog(run_dir / "lanes")
    transcripts.attach(deck)
    # after the logs (a warning raised inside an event is logged after it), before any lane
    # can get a live-box approval
    unmirror = mirror(team, deck) if team is not None else None
    watch = _watch(deck)
    run = Run(
        board, config, deck, driver, client, log, transcripts, run_dir, runtime, model, watch,
        options=options, profile=profile, policies=plan.policies, ctfd=link, verifier=verifier, team=team,
        _notes=plan.notes, _handouts=handouts, _urls=urls, _unmirror=unmirror,
    )
    if isinstance(verify, _OnCTFd):
        verify.solved = run._apply_solves
    return run


def _check_apis(config: Config, key: str | None, spare_key: str | None, notes: list[str]) -> None:
    """Ask the model APIs the lanes will call, before anything starts (apicheck.py): a key
    one refuses, a model it does not serve, or nothing answering stops the run here, instead
    of ending every lane at its first call. What could not be checked is a note."""
    from .apicheck import Api, CheckFailed, check

    apis = [Api("api", config.api.provider, config.api.base_url, key, config.api.key_env, config.models)]
    spare = config.fallback
    if spare is not None:
        apis.append(Api("fallback", spare.provider, spare.base_url, spare_key, spare.key_env, spare.ladder))
    for api in apis:
        try:
            notes += check(api, source=config.source)
        except CheckFailed as exc:
            raise RunError(str(exc)) from None


def _check_options(options: RunOptions) -> None:
    """Options a caller set in code that the run cannot use."""
    for name in ("wave_seconds", "solves_seconds", "team_seconds"):
        value = getattr(options, name)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not (math.isfinite(value) and value > 0):
            raise RunError(f"{name} must be a positive number of seconds, not {value!r}")
    if options.instance not in INSTANCE_POLICIES:
        raise RunError(f"instance must be auto, confirm or off, not {options.instance!r}")
    if options.submit not in (None, "confirm", "auto"):
        raise RunError(f"submit must be confirm or auto, not {options.submit!r}")


def _load_board(options: RunOptions) -> Board:
    if options.board is None:
        raise RunError(
            "name the board: `flightdeck play BOARD` (a folder of challenge folders), or give an event profile with "
            "--event EVENT.toml"
        )
    try:
        return load_board(options.board, answers=options.answers)
    except BoardError as exc:
        raise RunError(str(exc)) from None


# ---------------------------------------------------------------------- the event profile


def _plan(options: RunOptions, config: Config, runtime: str) -> _Plan:
    """The run's settings: the options and the config, with the event profile's rules and
    policies applied when there is one. RunError when the profile refuses the run."""
    pack = options.pack or config.l1.pack
    if options.event is None:
        team = _team_mode(options, None)
        effective = replace(
            options,
            max_lanes=options.max_lanes or config.lanes.max_lanes,
            team=team,
            submit=options.submit or config.lanes.submit,
            pack=pack,
        )
        return _Plan(effective, None, None, True, [])
    try:
        profile, policies = load_profile(options.event)  # it expands ~ itself, and says so when it cannot
    except ProfileError as exc:
        raise RunError(str(exc)) from None
    if policies.agents in (Policy.MANUAL, Policy.OFF):
        raise RunError(_no_agents(profile, policies))
    notes: list[str] = []
    lanes = options.max_lanes
    if lanes is None:
        lanes = config.lanes.max_lanes
        if profile.max_lanes is not None and lanes > profile.max_lanes:
            most = profile.max_lanes
            notes.append(
                f"{most} lane{'' if most == 1 else 's'} at a time, the most the event's rules allow (rules.max_lanes; "
                f"your config says {lanes})"
            )
            lanes = most
    problems = check(profile, policies, max_lanes=lanes, model_config=config, runtime=runtime, environ=_environment())
    refusals = [problem.message for problem in problems if problem.refuse]
    if refusals:
        count = len(refusals)
        how = f"`flightdeck preflight {_show(shlex.quote(str(profile.source)))}` shows the whole check"
        raise RunError(
            f"the event profile refuses this run ({count} refusal{'' if count == 1 else 's'}; {how}):\n"
            + "\n".join(f"refuse: {message}" for message in refusals)
        )
    notes += [f"event profile: {problem.message}" for problem in problems]  # the warnings
    board = options.board
    if profile.platform == "ctfd":
        if board is None:
            raise RunError(
                "a CTFd event needs the folder its board is pulled into: `flightdeck play FOLDER --event EVENT.toml` "
                "(a new folder, or one pulled from this CTFd before: the new challenges are added)"
            )
        if options.answers is not None:
            raise RunError("--answers checks flags against a file, and a CTFd event checks them on CTFd: drop --answers")
    elif board is None:
        board = profile.board  # check() refused a manual profile without one
    elif profile.board is not None and _same_dir(board, profile.board) is False:
        notes.append(f"board: {_show(board)}, as you asked (the event profile names {_show(profile.board)})")
    submit = _event_submit(options, policies)
    if not submit.platform:
        notes.append(
            f'submit is "{policies.submit}" in the event profile: flightdeck never submits a flag. It shows each one; '
            "you submit it on the platform, then answer a (accepted) or d (rejected)"
        )
    if policies.agents is Policy.CONFIRM:
        notes.append('agents is "confirm" in the event profile: starting play is your yes, so lanes start on their own up to the lane limit')
    if policies.l1 in (Policy.MANUAL, Policy.OFF):
        if pack is not None:
            how = "run your solvers yourself (`flightdeck l1 route` lists those that match a challenge)" if policies.l1 is Policy.MANUAL else "nothing runs it"
            notes.append(f'l1 is "{policies.l1}" in the event profile, so your L1 pack does not run in lanes: {how}')
        pack = None
    elif policies.l1 is Policy.CONFIRM and pack is not None:
        notes.append('l1 is "confirm" in the event profile: starting play is your yes, so your L1 solvers run first on each challenge')
    for_lanes = Policy.OFF if policies.instance is Policy.MANUAL else policies.instance  # manual: the player works the instance
    effective = replace(
        options,
        board=board,
        max_lanes=lanes,
        team=_team_mode(options, profile),
        submit=submit.policy,
        pack=pack,
        instance=strictest(options.instance, for_lanes).value,
    )
    return _Plan(effective, profile, policies, submit.platform, notes)


def _no_agents(profile: EventProfile, policies: Policies) -> str:
    if not profile.ai_allowed:
        why = "the event's rules do not allow AI help (rules.ai_allowed = false), so agents are off"
    else:
        why = f'the event profile sets agents = "{policies.agents}"'
    return (
        f"{why}: `flightdeck play` plays with agent lanes, so it does not start. Play by hand; `flightdeck l1 run` "
        "runs your no-model solvers"
    )


def _event_submit(options: RunOptions, policies: Policies):
    """The deck's submit policy, and whether flags go to the board's verifier: the profile's
    policy, or --submit when it is stricter (a looser one is refused)."""
    policy = policies.submit
    if options.submit is not None:
        asked = Policy(options.submit)
        if looser(asked, policy):
            raise RunError(
                f'--submit {asked} is looser than the event profile\'s submit policy "{policy}": drop --submit, or '
                "change submit in the profile's [policies] if the event's rules allow it"
            )
        policy = strictest(asked, policy)
    return deck_submit(policy)


def _same_dir(a: Path, b: Path) -> bool | None:
    """Whether two paths name the same folder; None when that cannot be told."""
    try:
        return Path(a).expanduser().resolve() == Path(b).expanduser().resolve()
    except (OSError, RuntimeError):
        return None


# ---------------------------------------------------------------------- the team channel


def _team_mode(options: RunOptions, profile: EventProfile | None) -> bool:
    if options.team_dir is not None:
        if options.team is False:
            raise RunError("--solo and --team-dir do not go together: the team folder is for team mode. Drop one of them")
        return True
    if options.handle is not None:
        raise RunError("--handle is your name in the team folder: give the folder with --team-dir FOLDER too")
    if options.team is not None:
        return options.team
    if profile is not None and profile.team:
        raise RunError(
            "the event profile sets team = true, so play needs the team folder your teammates share: give it with "
            "--team-dir FOLDER (one teammate makes it once with `flightdeck team init FOLDER`), or play alone with --solo"
        )
    return False


def _team_channel(options: RunOptions, plan: _Plan) -> TeamChannel | None:
    """Our side of the team folder (team mode with --team-dir), with a note saying who we are there."""
    if options.team_dir is None:
        if options.team:
            plan.notes.append(
                "team mode with no team folder: your claims stay on this deck"
                + (", and CTFd's solves still stop lanes" if plan.ctfd else "")
                + ". --team-dir FOLDER shares claims and solves with your teammates"
            )
        return None
    handle, source = options.handle, "from --handle"
    if handle is None:
        try:
            handle = getpass.getuser()
        except Exception:  # no LOGNAME, USER or password entry to name us
            raise RunError("flightdeck cannot find your login name for the team folder: give your handle with --handle NAME") from None
        source = "your login name; --handle NAME sets another"
    if not valid_handle(handle):
        what = "--handle" if options.handle is not None else "your login name"
        shown = json.dumps(printable(handle), ensure_ascii=False)
        raise RunError(f"{what} {shown} is not a usable team handle ({HANDLE_RULE}): give one with --handle NAME")
    try:
        channel = TeamChannel(options.team_dir, handle)
    except TeamError as exc:
        raise RunError(str(exc)) from None
    plan.notes.append(f"team: you are {handle} in the team folder {printable(channel.folder)} ({source})")
    return channel


# ---------------------------------------------------------------------- the CTFd board


class _OnCTFd:
    """The deck's verify() for a CTFd board: CTFdVerifier's answer and, when CTFd did not
    judge the flag (paused, rate-limited, out of tries, no answer, part of the answer), its
    reason as a warning on the deck, which then asks the player to submit the flag by hand.

    "already solved" (by the account, so by the team) is news, not a problem: the run takes
    CTFd's word for it, as for a solve its poll finds, without waiting for the player's
    answer about this flag. That happens once the deck's call is over, never from inside it."""

    def __init__(self, verifier: CTFdVerifier, link: CTFdLink) -> None:
        self.verifier = verifier
        self.link = link
        self.deck: Deck | None = None  # set once the deck exists
        self.solved: Callable[[], None] | None = None  # the run's: close what CTFd lists as solved

    def __call__(self, challenge_id: str, flag: str) -> bool | None:
        ok = self.verifier(challenge_id, flag)
        attempt = self.verifier.last_attempt
        number = self.verifier.ids.get(challenge_id)
        if ok is None and attempt is not None and attempt.status == "already_solved" and number is not None:
            self.link.answered.add(challenge_id)
            self.link.solved.add(number)
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:  # the deck is driven without a loop (no run): the next poll applies it
                loop = None
            if loop is not None and self.solved is not None:
                loop.call_soon(self.solved)
            return ok
        reason = self.verifier.last_error
        if ok is None and reason and self.deck is not None:
            ch = self.deck.challenges.get(challenge_id)
            name = untrusted(ch.name if ch is not None else challenge_id, one_line=True)
            self.deck.warn(
                f"CTFd did not judge {untrusted(flag, one_line=True)} for {name}: {reason}",
                challenge=challenge_id,
                data={"source": "ctfd"},
            )
        return ok


@dataclass(frozen=True)
class _FirstPull:
    board: Board
    folder: Path
    ids: Mapping[str, int]  # board id -> CTFd id
    solves: Solves | None  # what CTFd lists as solved for the account, and whose; None if it could not be read
    problems: tuple[str, ...]  # the challenges left out, and why


def _ctfd_token(profile: EventProfile) -> str:
    """The CTFd token, from the variable event.token_env names. Never shown."""
    name = profile.token_env
    assert name is not None  # check() refuses a CTFd profile without one
    from .keys import KeysError, environment

    try:
        value = environment().get(name, "").strip()
    except KeysError as exc:
        raise RunError(str(exc)) from None
    if not value:
        raise RunError(
            f"the CTFd token variable {name} (event.token_env) is not set or is empty: put {name}=<token> in your "
            "keys file or export it (CTFd: Settings, Access Tokens), then start play again"
        )
    assert profile.url is not None  # check() refuses a CTFd profile without one
    try:
        check_site(profile.url, value)
    except ValueError as exc:  # a token no header can carry; the message never shows it
        raise RunError(f"{exc} ({name}, the variable event.token_env names)") from None
    return value


def _pull_first(options: RunOptions, plan: _Plan, token: str) -> _FirstPull:
    """The CTFd board before the console starts: pulled (under the pull policy "confirm",
    once the player says yes), with the solves CTFd lists for the account."""
    profile, policies = plan.profile, plan.policies
    assert profile is not None and policies is not None and profile.url is not None and options.board is not None
    # check() refuses a CTFd profile whose pull policy is manual or off: nothing to play then
    assert policies.pull in USES_PLATFORM
    folder = options.board
    url, where = _show(profile.url), _show(folder)
    try:
        client = CTFdClient(profile.url, token)
    except ValueError as exc:  # the token holds what a header cannot carry; the message never shows it
        raise RunError(f"{exc} ({profile.token_env}, the variable event.token_env names)") from None
    if policies.pull is Policy.CONFIRM:
        if options.confirm is None:
            raise RunError(
                'the event\'s pull policy is "confirm", so flightdeck asks before it pulls the board, and it cannot ask '
                'here (not at a terminal): start play at a terminal, or set pull = "auto" in the profile\'s [policies]'
            )
        if not options.confirm(f"Pull the board from {url} into {where}?"):
            raise RunError("you said no to the pull, so nothing was pulled and the run did not start")
    try:
        result, solves, unread = _sync(_pull_and_solves(client, folder, profile.name, profile.flag_format))
    except (CTFdError, BoardError) as exc:
        raise RunError(f"could not pull the board from CTFd: {exc}") from None
    except OSError as exc:
        raise RunError(f"{where}: cannot write the board ({exc.strerror or type(exc).__name__})") from None
    try:
        ids = load_ids(folder)
    except CTFdError as exc:
        raise RunError(str(exc)) from None
    waves = policies.pull is Policy.AUTO
    total = len(result.board.challenges)
    plan.notes.append(
        f"board: {total} challenge{'' if total == 1 else 's'} from CTFd at {url} in {where} ({len(result.added)} new)"
    )
    later = "the next wave tries it again" if waves else "start play again to try it again"
    plan.notes += [f"not pulled: {line}; {later}" for line in result.problems]
    if result.hidden:
        plan.notes.append(
            f"{result.hidden} challenge{' is' if result.hidden == 1 else 's are'} locked on CTFd until a prerequisite is solved"
            + ("; a later wave pulls them once they unlock" if waves else "")
        )
    if unread is not None:
        plan.notes.append(f"could not read your solves from CTFd: {unread}; lanes may start on challenges already solved")
    if not waves:
        plan.notes.append(
            'pull is "confirm" in the event profile: flightdeck pulled the board once, after you said yes, and pulls no '
            "later waves; start play again to pull new challenges"
        )
    return _FirstPull(result.board, folder, ids, solves, tuple(result.problems))


async def _pull_and_solves(
    client: CTFdClient, folder: Path, event: str, flag_format: str | None
) -> tuple[Pull, Solves | None, str | None]:
    """Pull the board, then read the solves (None, and the reason they could not be read).
    The client is closed at the end: it is used on this loop only."""
    async with client:
        result = await pull(client, folder, event=event, flag_format=flag_format)
        try:
            return result, await client.solves(), None
        except CTFdError as exc:
            return result, None, str(exc)


def _sync(coro: Coroutine[Any, Any, Any]) -> Any:
    """Run a coroutine to the end from synchronous code: on a loop of its own, in a worker
    thread when this thread already runs one."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with concurrent.futures.ThreadPoolExecutor(1) as pool:
        return pool.submit(asyncio.run, coro).result()


def _reason(exc: BaseException) -> str:
    """Why a CTFd poll failed, for a warning. CTFd's errors never hold the token."""
    if isinstance(exc, (CTFdError, BoardError)):
        return str(exc)
    if isinstance(exc, OSError):
        return f"cannot write the board ({exc.strerror or type(exc).__name__})"
    return f"{type(exc).__name__}: {exc}"


def _show(value: object) -> str:
    return untrusted(str(value), one_line=True)


# ---------------------------------------------------------------------- lanes


def _l1_manifests(pack: Path | None) -> list | None:
    """The engines of the L1 pack, checked before anything starts; None without a pack."""
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
    return manifests


def _watch(deck: Deck):
    """The course detectors (M3), raising and clearing alerts after every turn."""
    from .detect import Watch, default_detectors

    watch = Watch(deck, default_detectors())
    watch.attach()
    return watch


DEFAULT_AGENT_LADDERS = {"claude": ("sonnet", "opus")}  # Claude Code's own model aliases


def _agent_ladder(kind: str, config: Config, notes: list[str]) -> tuple[str, ...]:
    """The models a `kind` lane may use, weakest first: [agents] in the config, else the default."""
    if kind not in ("claude", "codex"):
        raise RunError(f"--agent must be claude or codex, not {kind!r}")
    ladder = config.agents.get(kind)
    if ladder:
        return ladder
    ladder = DEFAULT_AGENT_LADDERS.get(kind)
    if not ladder:
        raise RunError(
            f'no model ladder for {kind} lanes: add [agents] {kind} = ["<model>", ...] to {config.source} '
            "(weakest first; escalating moves right)"
        )
    notes.append(f"{kind} lanes start on {ladder[0]} and escalate to {', '.join(ladder[1:])} ([agents] {kind} in your config changes this)")
    return ladder


def _find_agent(kind: str, model: str, auth: str | None):
    from .agent.external import AgentError, find_agent

    try:
        return find_agent(kind, model, auth=auth, environ=_environment())
    except AgentError as exc:
        raise RunError(str(exc)) from None


def _environment() -> dict[str, str]:
    """This process's environment plus the player's keys file (the environment wins)."""
    from .keys import KeysError, environment

    try:
        return environment()
    except KeysError as exc:
        raise RunError(str(exc)) from None


def _check_image_has(image: str, program: str) -> None:
    """A docker lane runs the agent's CLI inside its container, so the lane image must have it."""
    problem = image_lacks(image, program)
    if problem is not None:
        raise RunError(
            f"{problem}: run them on this machine with --host, or build an image that has {program} and set "
            "[lanes] image in your config"
        )


def image_lacks(image: str, program: str) -> str | None:
    """Why `program` cannot run in the lane image `image` (it is not on its PATH, or docker did
    not say), or None when it is there. play --agent and doctor --agent ask the same way: a
    throwaway container of the image, never pulled, with no network."""
    docker = shutil.which("docker") or "docker"
    try:
        probe = subprocess.run(
            [docker, "run", "--rm", "--pull", "never", "--network", "none", "--entrypoint", "sh", image, "-c", f"command -v {program}"],
            capture_output=True, text=True, timeout=120,
        )
    except subprocess.TimeoutExpired:
        return f"docker did not answer whether the lane image {image} has {program} (within 120 s), so {program} lanes cannot run in Docker"
    if probe.returncode != 0:
        return f"the lane image {image} has no {program} CLI, so {program} lanes cannot run in Docker"
    return None


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


def environment_has_key(config: Config, environ: Mapping[str, str] = os.environ, *, fallback: bool = False) -> bool:
    """Whether the API key variable ([fallback]'s with fallback=True) is set, in the
    environment or the keys file (never its value)."""
    if fallback:
        name = config.fallback.key_env if config.fallback is not None else ""
    else:
        name = config.api.key_env
    if not name:
        return True
    from .keys import KeysError, source

    try:
        return source(name, environ) is not None
    except KeysError:  # a keys file flightdeck refuses to read holds nothing it would use
        return bool(environ.get(name, "").strip())
