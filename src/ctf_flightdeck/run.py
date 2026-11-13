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
run's background tasks (CTFd waves, solves and submits, the team watcher), which shutdown()
stops.

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

A CTFd run's flags go to CTFd from one worker task (_Submits, the deck's submitter), one at a
time and off the console's loop: the lane carries on, and CTFd's answer reaches the deck when
it is in (Deck.platform_verdict). A challenge whose tries CTFd counts (its max_attempts, or a
wrong flag's "N tries remaining") gets no flag without the player, under auto too (unless
the player's config says `submit_limited = "auto"`: DeckConfig.holds). The tries
left are what CTFd last said: in its answer to a flag, or in the challenge's details at each
pull (the attempts used, by you or a teammate: Pull.tries, Deck.platform_tries), so a new run
starts with them. With none left the challenge is out of tries: no lane starts on it, those
on it stop, and no flag of it goes to CTFd or to the player to submit by hand, until a later
pull finds tries left again (CTFd's timeout behaviour gives them back after a wait). A
flag still on its way when the run ends is named on the way out, as not known to have been
submitted.

The team channel (team.py): mirror() writes our claims, solves and live-box holds to the
team folder as the deck makes them, and the team watcher applies the teammates' marks. A
challenge the team folder shows as solved, or claimed by a teammate, is not queued.

Autopilot (autopilot.py, D20): every run has one, attached to the deck after the Watch and
off until it is engaged: by `play --autopilot` or `[autopilot] engage = true` when the board
is released, or by `/autopilot on` in the console. Engaging it at the start needs a run
budget and the Docker runtime, checked here before anything starts, and the notes say what it
will and will not do under this run's policies, none of which it changes. With an event
profile's `start` still to come, prepare_run waits for it after every check and before the
first pull; at its `end` the run stops as quitting does (Run._until_end). The run tells
autopilot when the platform needs a human: a CTFd poll that keeps failing, a flag CTFd did
not judge, or a web page where CTFd's API should answer (platform/ctfd.py: HumanCheck).
While autopilot guards the run the model client sends no server-side refusal fallback.

What a run starts carries its marks (leftovers.py): its containers flightdeck's labels, and
its process groups on this machine a record in the run folder, which a note in flightdeck's
state folder names (so it is found wherever --run-dir put it). Before a run starts, what
earlier runs left running because flightdeck itself was killed (SIGKILL, a power loss) is
removed, and the notes say what.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import getpass
import json
import math
import os
import re
import shlex
import shutil
import subprocess
import time
from collections.abc import Awaitable, Callable, Collection, Coroutine, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .agent.client import ChatClient
from .agent.driver import COMPACT_AT, AgentDriver
from .agent.egress import CLI_API
from .agent.fallback import api_name, build_client
from .agent.l1stage import L1Stage
from .agent.workspace import DockerWorkspace, HostWorkspace, Workspace, docker_unavailable
from .autopilot import NEEDS_BUDGET, NEEDS_DOCKER, Autopilot, Budget, start_notes
from .clock import RunClock
from .config import Config, ConfigError, api_key, fallback_key, lane_refresh_at, load_config, webhook_url
from .core.deck import Deck, QueueEntry
from .core.model import Challenge, DeckConfig, Lane, PendingKind
from .eventlog import EventLog, new_run_dir
from .instancerun import InstanceRunner, on_demand
from .platform.instances import InstanceClient
from .leftovers import RECORD, ProcessRecord, labels, sweep
from .platform.ctfd import CTFdClient, CTFdError, CTFdVerifier, HumanCheck, Pull, Solves, Verdict, check_site, load_ids, pull
from .platform.manual import AnswerVerifier, Board, BoardChallenge, BoardError, cannot_check, load_board
from .preflight import (
    USES_PLATFORM,
    EventProfile,
    Policies,
    Policy,
    ProfileError,
    check,
    deck_submit,
    instances_off,
    load_profile,
    looser,
    no_agents,
    strictest,
)
from .notify import Notifier, NotifyError
from .runrecord import write_run_info, write_run_setup
from .status import NAME as STATUS_NAME
from .status import StatusFile
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
PLATFORM_FAILURES = 3  # the same CTFd poll failing this many times in a row is the platform failing: autopilot disengages
START_WAIT_STEP = 30.0  # seconds: how long the wait for an event's start sleeps before it looks at the time again


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
    autopilot: bool | None = None  # engage autopilot when the board is released; None: the config's [autopilot] engage
    budget_dollars: float | None = None  # the run budget autopilot needs, in dollars; None: the config's
    budget_tokens: int | None = None  # and in tokens; None: the config's
    say: Callable[[str], None] | None = None  # says a line to the player before the console is up (the wait for the start)
    now: Callable[[], datetime] | None = None  # the time of day, with its zone (the event's start and end); None: the system's
    sleep: Callable[[float], None] | None = None  # how the wait for the event's start passes time; None: time.sleep


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
    failing: dict[str, int] = field(default_factory=dict)  # a poll -> how many times in a row it has failed
    tries: dict[str, int] = field(default_factory=dict)  # board id -> the tries left at its flag, as CTFd's details last said (a pull's)

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
    verifier: CTFdVerifier | None = None  # what submits a CTFd board's flags, when submit uses the platform
    team: TeamChannel | None = None
    _notes: list[str] = field(default_factory=list, repr=False)
    _handouts: dict[str, Path] = field(default_factory=dict, repr=False)  # shared with the workspaces and the L1 stage
    _urls: dict[str, tuple[str, ...]] = field(default_factory=dict, repr=False)
    _unmirror: Callable[[], None] | None = field(default=None, repr=False)
    _watcher: TeamWatcher | None = field(default=None, repr=False)
    _team_stop: asyncio.Event | None = field(default=None, repr=False)
    _tasks: list[asyncio.Task] = field(default_factory=list, repr=False)
    _stopping: asyncio.Future | None = field(default=None, repr=False)  # the one shutdown, once begun
    _errors: list[str] = field(default_factory=list, repr=False)
    _submits: _Submits | None = field(default=None, repr=False)  # the deck's submitter, with the verifier
    processes: ProcessRecord | None = None  # what the run started on this machine, for the next start if flightdeck is killed
    lights: object = None  # light.Lights: the light engines its jobs share (closed after the watch)
    status: StatusFile | None = None  # status.json in the run folder, for whatever is not the console
    notifier: Notifier | None = None  # the notification webhook, when [notify] names one
    autopilot: Autopilot | None = None  # the run's autopilot (autopilot.py): off until engaged
    instances: InstanceRunner | None = None  # starts and stops the platform's on-demand instances (instancerun.py); None: it starts none
    engage: bool = False  # engage autopilot when the board is released (--autopilot, or [autopilot] engage)
    stopper: Callable[[str], None] | None = None  # ends the run as quitting does, saying why: whoever flies the run sets it (the console: app())

    def notes(self) -> list[str]:
        """Things the player should know before lanes start."""
        out = list(self._notes)
        lanes = self.config.lanes
        l1 = getattr(self.driver, "l1", None)
        if l1 is not None:
            if getattr(l1, "image", None) is not None:
                own = getattr(l1, "engine_image", None)
                where = (
                    f", each in a container of {f'the pack image {own}' if own else f'the lane image {l1.image}'} with your pack mounted read-only, and no network "
                    "unless lanes may reach the challenge's live instance at once (instance auto)"
                )
            else:
                where = ", on this machine, as you"
            out.append(f"L1: {len(l1.manifests)} engine(s) from your pack run first on each challenge{where}")
        unpriced = [m for m in self.config.models if m not in self.config.prices]
        if self.client is not None and lanes.dollar_cap and unpriced and "openrouter.ai" not in self.config.api.base_url:
            out.append(
                f"no price in your config for {', '.join(unpriced)}: if the API does not report a cost, a lane "
                f"on that model asks you once before it carries on without its ${lanes.dollar_cap:g} cap"
            )
        if self.client is not None and self.config.api.provider == "anthropic":
            out.extend(anthropic_price_notes(self.config, lanes.dollar_cap))
        return out

    @property
    def errors(self) -> list[str]:
        """Problems to show when the run has ended: the lanes' cleanup, the team folder's, the
        flags still on their way to CTFd, and the run's process record's."""
        submits = self._submits.errors if self._submits is not None else []
        record = [self.processes.problem] if self.processes is not None and self.processes.problem else []
        status = [self.status.problem] if self.status is not None and self.status.problem else []
        return [*self.driver.errors, *submits, *self._errors, *record, *status]

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
        if self.status is not None:  # its timer: the file moves on with no event too
            self._tasks.append(asyncio.create_task(self.status.run(), name="flightdeck status file"))
        if self.notifier is not None:  # before any lane starts: what was queued so far goes now
            self.notifier.start()
        if self.team is not None:
            self._watcher = TeamWatcher(self.team, self.deck)
            state = self._watcher.poll()  # its marks wait until the board is on the deck
        if self._submits is not None:  # before any lane starts: it sends their flags to CTFd
            self._tasks.append(asyncio.create_task(self._submits.work(), name="flightdeck CTFd submits"))
        if self.engage and self.autopilot is not None:  # before any lane starts: its guardrails hold from the first turn
            outcome = self.autopilot.engage()
            if not outcome.ok:  # prepare_run checked the budget and the runtime: something changed since
                self.deck.warn(outcome.message, data={"autopilot": "not engaged"})
        if self.autopilot is not None and self.profile is not None and self.profile.end is not None:
            self._tasks.append(asyncio.create_task(self._until_end(self.profile.end), name="flightdeck event end"))
        if self.instances is not None:  # before any lane starts: an on-demand challenge waits for its instance
            self.instances.hold([b.challenge for b in self.board.challenges])
            self._tasks.append(asyncio.create_task(self.instances.work(), name="flightdeck instances"))
        self.deck.release([b.challenge for b in self.board.challenges], self.entries(skip=self._held()), "Board")
        if state is not None:
            self._watcher.apply(state, before_run=True)  # what the team folder held before the run started
        if self.ctfd is not None:
            self._apply_solves(before_run=True)  # what CTFd listed before the run started
            self._apply_tries(self.ctfd.tries, before_run=True)  # and the tries its details said were left (none: out of tries)
            if self.ctfd.waves:
                self._tasks.append(asyncio.create_task(self._waves(), name="flightdeck CTFd waves"))
            self._tasks.append(asyncio.create_task(self._solves(), name="flightdeck CTFd solves"))
        if self._watcher is not None:
            self._team_stop = asyncio.Event()
            watching = self._watcher.run(interval=self.options.team_seconds, stop=self._team_stop)
            self._tasks.append(asyncio.create_task(watching, name="flightdeck team watcher"))

    async def shutdown(self) -> None:
        """Stop the run, once: the console's quit (on_exit) and whatever ran the console
        (cli._fly, on every way out) both call this, and the second call only waits for the
        first to end. Await it on the loop release() ran on: the lanes and the background
        tasks live there. Whoever awaits it may be cancelled (a console that fails while it
        quits) without the shutdown stopping half way."""
        if self._stopping is None:
            self._stopping = asyncio.ensure_future(self._shutdown())
        await asyncio.shield(self._stopping)

    async def _shutdown(self) -> None:
        """Close the deck first (Deck.close: each lane's work stops at once, before anything
        here awaits, and without ending the lane; nothing raises an alert, asks the player or
        starts a lane from then on, yet what the lanes report as they stop counts, a
        coding-agent CLI's cost of the turn quitting cut among it). Then stop the background
        tasks, wait for every lane's driver to finish stopping, close the workspaces and the
        API clients, and free our live-box holds in the team folder."""
        self.deck.close()
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
        if self._submits is not None:  # after the lanes, so a flag one handed over as it stopped is named too
            self._errors += self._submits.unsent()
        if self.instances is not None:  # after the lanes: nothing works an instance any more
            self._errors += [f"instances: {line}" for line in await self.instances.close()]
            self.instances.client.close()
        if self.team is not None:
            try:
                self.team.free_boxes()  # the lanes stopped without a lane-end event, so mirror() did not see them go
            except TeamError as exc:
                self._errors.append(f"team: could not free your live-box holds in the team folder: {exc}")
        if self.client is not None:
            await self.client.aclose()
        if self.watch is not None:
            await self.watch.aclose()  # the hint judge, if any
        if self.lights is not None:
            await self.lights.aclose()  # the light models, each once
        if self.ctfd is not None:
            await self.ctfd.client.aclose()
        if self.notifier is not None:  # last: what the shutdown itself had to say is sent too
            await self.notifier.aclose()

    def close(self) -> None:
        if self._unmirror is not None:
            self._unmirror()
            self._unmirror = None
        if self.verifier is not None:
            self.verifier.close()
        self.transcripts.close()
        if self.status is not None:  # before the log closes: a write that fails is a warning in it
            self.status.close()
        self.log.close()
        if self.processes is not None:
            self.processes.finish()

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

        app = FlightdeckApp(
            self.deck, refresh_seconds=refresh_seconds, on_start=self.release, on_exit=self.shutdown, run_dir=str(self.dir)
        )
        self.stopper = app.stop_run  # the event's end under autopilot: quit as the player would, without asking
        return app

    async def _until_end(self, end: datetime) -> None:
        """Wait for the event's end (event.end), then, unless the player has the controls
        (Autopilot.ended), stop the run as quitting does: through `stopper` (the console
        quits without asking), or with nobody flying it, by shutting the run down here."""
        now = self.options.now or _now
        while (left := (end - now()).total_seconds()) > 0:
            await asyncio.sleep(min(left, START_WAIT_STEP))
        assert self.autopilot is not None
        if not self.autopilot.ended(end.isoformat()):
            return
        why = f"the event ended ({end.isoformat()}): "
        if self.stopper is not None:
            self.stopper(why)
        else:
            asyncio.ensure_future(self.shutdown())  # not awaited: the shutdown cancels this task among the others

    # ------------------------------------------------------------------ the event's background work

    def _held(self) -> set[str]:
        """Board ids not to queue: solved on CTFd, out of tries on CTFd (as its details said at
        the last pull), or in the team folder solved (by anyone) or claimed by a teammate."""
        held = set(self.ctfd.solved_board_ids()) if self.ctfd is not None else set()
        if self.ctfd is not None:
            held |= {cid for cid, left in self.ctfd.tries.items() if left == 0}
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
        answer (it is then the lane's solve), and so does one whose flag is on its way to CTFd
        (its answer may be that very solve)."""
        link = self.ctfd
        assert link is not None
        for cid in link.solved_board_ids():
            ch = self.deck.challenges.get(cid)
            if ch is None or ch.closed:
                continue
            if (self._confirming(cid) and cid not in link.answered) or self.deck.submitting(cid):
                continue
            self.deck.platform_solved(cid, link.who(cid), before_run=before_run)

    def _apply_tries(self, tries: Mapping[str, int], *, before_run: bool = False, asked: float | None = None) -> None:
        """Give the deck the tries CTFd's details said were left at a pull (Pull.tries;
        Deck.platform_tries): from then on each approval of the challenge's flags says the
        count, at 0 it is out of tries, and a count above the deck's opens it again when it
        was `asked` (the deck's clock as the pull began) after CTFd's last answer to a flag of
        it. `before_run`: the first pull's."""
        for cid, left in sorted(tries.items()):
            if cid in self.deck.challenges:
                self.deck.platform_tries(cid, left, before_run=before_run, asked=asked)

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
            asked = self.deck.now  # the counts of tries this pull reads are no older than this
            try:
                result = await pull(link.client, link.folder, event=link.event, flag_format=link.flag_format)
            except Exception as exc:  # CTFdError, BoardError, OSError, or a bug: say so, and try again later
                self._ctfd_problem(
                    "waves", f"could not pull new challenges from CTFd: {_reason(exc)}; flightdeck tries again in {every:g} s"
                )
                self._platform_failed("waves", "pulling new challenges", exc)
                continue
            link.problems.pop("waves", None)
            link.failing.pop("waves", None)
            try:
                self._wave(result, asked)
            except Exception as exc:  # a bug: say so, and keep pulling
                self._ctfd_problem("release", f"could not release the new challenges from CTFd: {type(exc).__name__}: {exc}")
            else:
                link.problems.pop("release", None)

    def _wave(self, result: Pull, asked: float | None = None) -> None:
        """What a pull of the waves brought: the new challenges, released, and the tries CTFd's
        details say are left now (a teammate may have spent some, or CTFd given some back), new
        challenges or not. `asked`: the deck's clock as the pull began."""
        link = self.ctfd
        assert link is not None
        link.ids.update(result.ids)
        if self.verifier is not None:
            self.verifier.ids.update(result.ids)
        if self.instances is not None:
            self.instances.client.ids.update(result.ids)
        for line in result.problems:
            if line not in link.reported:
                link.reported.add(line)
                self.deck.warn(f"CTFd: not pulled: {line}; the next wave tries it again", data={"source": "ctfd"})
        for line in result.tries_unread:
            if line not in link.reported:
                link.reported.add(line)
                self.deck.warn(f"CTFd: {line}; the next wave asks again", data={"source": "ctfd"})
        link.tries.update(result.tries)
        new = [b for b in result.board.challenges if b.challenge.id not in self.deck.challenges]
        if new:
            self._add(new)
            if self.profile is not None and self.profile.instances is not None:
                on_demand([b.challenge for b in new], self.profile.instances.types)
            if self.instances is not None:
                self.instances.hold([b.challenge for b in new])
            link.wave += 1
            self.deck.release([b.challenge for b in new], self.entries(new, skip=self._held()), f"Wave {link.wave}")
            self._apply_solves()
        self._apply_tries(result.tries, asked=asked)

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
                self._platform_failed("solves", "reading the solves", exc)
                continue
            link.problems.pop("solves", None)
            link.failing.pop("solves", None)
            link.read(solves)
            try:
                self._apply_solves()
            except Exception as exc:  # a bug: say so, and keep reading
                self._ctfd_problem("apply", f"could not apply the solves from CTFd: {type(exc).__name__}: {exc}")
            else:
                link.problems.pop("apply", None)

    def _platform_failed(self, kind: str, what: str, exc: BaseException) -> None:
        """A CTFd poll failed: count it, and tell autopilot when the platform needs a human
        (Autopilot.platform: it disengages). At once for a web page where CTFd's API should
        answer (HumanCheck: a login page, a CAPTCHA); after PLATFORM_FAILURES failures in a row
        of the same poll for anything else (one failure passes: the next poll tries again)."""
        link = self.ctfd
        assert link is not None
        link.failing[kind] = count = link.failing.get(kind, 0) + 1
        if self.autopilot is None:
            return
        if isinstance(exc, HumanCheck):
            self.autopilot.platform(_reason(exc))
        elif count == PLATFORM_FAILURES:
            self.autopilot.platform(f"{what} from CTFd has failed {count} times in a row: {_reason(exc)}")

    def _flag_unjudged(self, verdict: Verdict) -> None:
        """CTFd did not judge a flag (paused, rate-limited, no answer, a page for a person):
        the flag goes to the player to submit by hand, so autopilot disengages."""
        if self.autopilot is not None:
            self.autopilot.platform(f"CTFd did not judge a flag: {verdict.error}")

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
    engage, budget = _autopilot_asked(options, config, runtime)
    board = None if plan.ctfd else _load_board(options)
    ladder, agent, key, spare_key = config.models, None, None, None
    if options.agent is not None:  # lanes are a coding-agent CLI: its own login, its own models
        ladder = _agent_ladder(options.agent, config, plan.notes)
        model = options.model or ladder[0]
        if model not in ladder:
            raise RunError(f"model {model!r} is not in the {options.agent} ladder: {', '.join(ladder)}")
        if options.instance != "auto":
            raise RunError(
                f'the instance policy is "{options.instance}", but a {options.agent} lane does not ask before it '
                "reaches its instance, and on the host it reaches whatever its CLI can reach, so flightdeck "
                "cannot hold it to that: play this event with flightdeck's own lanes (no --agent)"
            )
        agent = _find_agent(options.agent, model, options.agent_auth)
        plan.notes.append(f"lanes are {options.agent} on {model} ({agent.auth})" if agent.auth else f"lanes are {options.agent} on {model}")
        plan.notes.extend(agent.warnings)
        unpriced = [m for m in ladder if m not in config.prices]
        if options.agent == "codex" and unpriced:  # codex reports its tokens but no cost: a price makes them dollars
            on = "it" if len(unpriced) == 1 else "one of them"
            cap = config.lanes.dollar_cap
            asks = f" and asks you once before it carries on without its ${cap:g} cap" if cap else ""
            plan.notes.append(
                f"codex reports its tokens but no cost, and your config has no price for {', '.join(unpriced)}: a lane on "
                f"{on} shows its dollars as unknown{asks}; a table like [prices.{json.dumps(unpriced[0])}] in your config "
                "(input and output, in dollars per million tokens) prices one"
            )
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
        if config.api.fast:
            from .agent.fastmode import fast_note

            plan.notes.append(fast_note(config.api.fast))
        if config.api.effort:
            plan.notes.append("effort: " + ", ".join(f"{name} at {level}" for name, level in config.api.effort)
                              + " (any other ladder model runs at Anthropic's default for it)")
    try:
        webhook = webhook_url(config)  # [notify]: a variable named and not set stops the run here
    except ConfigError as exc:
        raise RunError(str(exc)) from None
    if runtime == "docker":
        _check_docker(config.lanes.image)
        if agent is not None:
            _check_image_has(config.lanes.image, agent.kind)
    manifests = _l1_manifests(options.pack)
    if runtime == "docker" and manifests is not None and config.l1.image:
        _check_l1_image(config.l1.image)
    team = _team_channel(options, plan)
    profile = plan.profile
    first = token = None
    if plan.ctfd:
        assert profile is not None
        token = _ctfd_token(profile)
    if agent is None:  # the model APIs, asked once (a coding-agent CLI uses its own)
        _check_apis(config, key, spare_key, plan.notes)
    if engage and profile is not None:  # every check is done: wait for the event's start before anything is pulled
        _wait_for_start(options, profile)
    if plan.ctfd:  # the last check, then the first thing done: the pull
        assert token is not None
        first = _pull_first(options, plan, token)
        board = first.board
    assert board is not None
    runs = (options.run_dir or config.run_dir).expanduser()
    plan.notes += sweep(runs, docker=True if runtime == "docker" else None, clean=True).lines  # what killed runs left
    run_dir = new_run_dir(runs)
    try:
        processes = ProcessRecord.start(run_dir, docker=runtime == "docker")
    except OSError as exc:  # the record, or the note that lets a later start find it
        what = f"cannot write {exc.filename}" if exc.filename else f"cannot keep {run_dir / RECORD}"
        raise RunError(f"{what}: {exc.strerror or exc}") from None
    marks = labels(run_dir.name)  # on every container the run starts
    write_run_info(run_dir, board=options.board, answers=options.answers)  # for the commands after the run
    log = EventLog(run_dir / "events.jsonl")
    flag_format = (profile.flag_format if profile is not None else None) or board.flag_format
    deck_config = DeckConfig(
        event=profile.name if profile is not None else board.event,
        team=bool(options.team),
        containerized=runtime == "docker",
        max_lanes=options.max_lanes,
        submit=options.submit,
        submit_limited=config.lanes.submit_limited,
        wrong_stop=config.lanes.wrong_stop,
        models=ladder,
        **({"flag_format": flag_format} if flag_format else {}),
    )
    plan.notes.append(_flag_format_note(deck_config.flag_format, profile, board, options.board))
    if deck_config.spends_tries:
        plan.notes.append(SPENDS_TRIES)
    elif config.lanes.submit_limited == "auto":
        plan.notes.append(f'submit_limited = "auto" in your config does nothing in this run: submit is "{deck_config.submit}", so every flag waits for you')
    handouts = {b.challenge.id: b.handout for b in board.challenges}
    urls = {b.challenge.id: tuple(b.urls) for b in board.challenges}
    l1 = None
    toolkit, lane_image, lane_mounts = "", config.lanes.image, ()
    if manifests is not None and config.l1.lane_tools:
        toolkit = _lane_toolkit(options.pack)
        if runtime == "docker":
            # the lane sees the pack where it is on this machine, read-only, and runs in the
            # pack's image: the pack's own Python and tools are there, not in the lane image
            lane_mounts = ((options.pack, str(options.pack)),)
            lane_image = config.l1.image or config.lanes.image
            if lane_image != config.lanes.image and agent is not None:
                _check_image_has(lane_image, agent.kind)  # the CLI must be in the image its lane runs in
        plan.notes.append("L1: the lanes' models may call your pack's engines (lane_tools)"
                          + (f"; lanes run in {lane_image} with the pack mounted read-only" if runtime == "docker" else ""))
    if manifests is not None:
        l1 = L1Stage(
            manifests, handouts, run_dir, deck_config.flag_format, concurrency=config.l1.concurrency,
            image=config.lanes.image if runtime == "docker" else None, pack=options.pack,  # D17: engines run where lanes do
            engine_image=config.l1.image if runtime == "docker" else None, toolkit=toolkit,
            labels=marks, record=processes, urls=urls,
        )
    write_run_setup(run_dir, _setup(  # for the flight card of `flightdeck share`
        config, options, deck_config, ladder, agent=options.agent, ctfd=bool(plan.ctfd),
        engines=len(manifests) if manifests is not None else 0,
    ))
    try:
        client = build_client(config, key, spare_key) if agent is None else None
    except ValueError as exc:  # a key no HTTP header can carry; never shown
        raise RunError(f"the model API cannot be used: {exc}") from None
    instance = options.instance
    link = verifier = submits = None
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
            reported=set(first.problems) | set(first.tries_unread),
            tries=dict(first.tries),
        )
        if first.solves is not None:
            link.read(first.solves)
        if plan.platform:
            verifier = CTFdVerifier(profile.url, token, first.ids)
    if verifier is not None:
        assert link is not None
        submits = _Submits(verifier, link)
        verify = _never_verify  # flags go to CTFd through the submitter, never through verify()
    elif plan.platform and board.answers:
        verify = AnswerVerifier(board.answers)
    else:
        verify = cannot_check

    def workspace(lane: Lane, challenge: Challenge) -> Workspace:
        root = run_dir / lane.id.lower() / "work"
        if runtime == "docker":
            reach, later = lane_reach(urls[challenge.id], instance, api=CLI_API[agent.kind] if agent is not None else ())
            return DockerWorkspace(
                root,
                handouts[challenge.id],
                image=lane_image,
                name=f"flightdeck-{run_dir.name}-{lane.id.lower()}",
                reach=reach,
                later=later,
                labels=marks,
                mounts=lane_mounts,
            )
        return HostWorkspace(root, handouts[challenge.id], record=processes)

    files = {b.challenge.id: b.challenge.files for b in board.challenges}
    # each shown as [NAME] wherever a lane's tool call or its CLI writes it (agent/held.py)
    held = _held_secrets(config, profile, token)
    if agent is not None:
        from .agent.external import ExternalDriver

        driver = ExternalDriver(agent, workspace, run_id=run_dir.name, files=files, urls=urls, prices=config.prices, secrets=held,
                                instance=instance, l1=l1)
    else:
        assert client is not None
        driver = AgentDriver(
            client,
            workspace,
            run_id=run_dir.name,
            files=files,
            urls=urls,
            prices=config.prices,
            compact_at=lane_refresh_at(config, COMPACT_AT),  # sooner where [api] or [fallback] states a smaller context
            l1=l1,
            instance=instance,
            secrets=held,
        )
    deck = Deck(deck_config, driver, RunClock(), verify, submitter=submits)
    if submits is not None:
        submits.deck = deck
    log.attach(deck)
    status = StatusFile(run_dir / STATUS_NAME, deck, run=run_dir.name, held=held)  # after the log: its warning is logged
    status.attach()
    notifier = None
    if webhook is not None:
        env = config.notify.webhook_env
        try:
            notifier = Notifier(webhook, deck, run=run_dir.name, env=env, on=config.notify.on, held=held)
        except NotifyError as exc:
            raise RunError(str(exc)) from None
        notifier.attach()
        plan.notes.append(
            f"notifications ({', '.join(config.notify.on)}) go to the webhook in the variable {env}: what is sent is in "
            "docs/GUIDE.md (never a flag)"
        )
    transcripts = TranscriptLog(run_dir / "lanes")
    transcripts.attach(deck)
    # after the logs (a warning raised inside an event is logged after it), before any lane
    # can get a live-box approval
    unmirror = mirror(team, deck) if team is not None else None
    idle = _flagcheck_idle(deck_config.submit, submits is not None or isinstance(verify, AnswerVerifier))
    lights = _lights(config, plan.notes, idle={"flagcheck": idle} if idle else None)
    driver.flaggate = _flaggate(config, lights, plan.notes)  # before any lane starts (release)
    driver.lights = lights  # route and recon at each lane's start (agent/facts.py); no lane has started yet
    watch = _watch(deck, config, plan.notes, lights)
    switch, has_fallback = _refusal_switch(client, ladder)
    autopilot = Autopilot(deck, budget, refusals=switch)
    autopilot.attach()  # after the watch: it sees the alerts the watch raised
    if engage:
        plan.notes += start_notes(
            plan.policies, submit=deck_config.submit, spends_tries=deck_config.spends_tries, instance=instance, budget=budget,
            waves=link is not None and link.waves, refusal_fallback=has_fallback, agent=options.agent,
            start=profile.start if profile is not None else None, end=profile.end if profile is not None else None,
        )
    instances = _instances(profile, plan.policies, board, link, token, deck, urls, driver, plan.notes)
    run = Run(
        board, config, deck, driver, client, log, transcripts, run_dir, runtime, model, watch,
        options=options, profile=profile, policies=plan.policies, ctfd=link, verifier=verifier, team=team,
        _notes=plan.notes, _handouts=handouts, _urls=urls, _unmirror=unmirror, _submits=submits,
        processes=processes, lights=lights, status=status, notifier=notifier, autopilot=autopilot, engage=engage,
        instances=instances,
    )
    if submits is not None:
        submits.solved = run._apply_solves
        submits.unjudged = run._flag_unjudged
    return run


def _instances(profile: EventProfile | None, policies: Policies, board: Board, link: CTFdLink | None, token: str | None,
               deck: Deck, urls: dict[str, tuple[str, ...]], driver: object, notes: list[str]) -> InstanceRunner | None:
    """The run's instance scheduler, when the event's [instances] table and its policies let
    flightdeck start instances on the platform; else None, with a note saying why when the
    board has challenges that need one. Marks the board's on-demand challenges either way."""
    challenges = [b.challenge for b in board.challenges]
    marked = on_demand(challenges, profile.instances.types if profile is not None and profile.instances is not None else ())
    why = instances_off(profile, policies) if profile is not None else "there is no event profile"
    if why or link is None or token is None:
        if marked:
            notes.append(
                f"instances: {len(marked)} challenge{'s' if len(marked) != 1 else ''} on this board need an instance the platform "
                f"starts when asked, and flightdeck starts none: {why or 'this run has no link to the platform'}. Start one on the "
                "site yourself; its lane works from the files"
            )
        return None
    assert profile is not None and profile.instances is not None and profile.url is not None
    client = InstanceClient(profile.url, token, link.ids, profile.instances)
    notes.append(
        f"instances: flightdeck starts a challenge's instance on the platform before a lane works it"
        f" ({len(marked)} on the board now), keeps at most {profile.instances.max_running} running, and stops one when its "
        "challenge is solved or nobody works it"
    )
    return InstanceRunner(deck, client, max_running=profile.instances.max_running, urls=[urls, driver.urls])


def _autopilot_asked(options: RunOptions, config: Config, runtime: str) -> tuple[bool, Budget]:
    """Whether this run engages autopilot at its start (--autopilot, else [autopilot] engage),
    and its run budget (the options', else the config's). Asked for without a budget, or off
    the Docker runtime, the run does not start: RunError, in one line, with the reason."""
    engage = config.autopilot.engage if options.autopilot is None else options.autopilot
    dollars = options.budget_dollars if options.budget_dollars is not None else config.autopilot.budget_dollars
    tokens = options.budget_tokens if options.budget_tokens is not None else config.autopilot.budget_tokens
    try:
        budget = Budget(dollars=dollars, tokens=tokens)
    except ValueError as exc:
        raise RunError(str(exc)) from None
    if engage and not budget.set:
        raise RunError(NEEDS_BUDGET)
    if engage and runtime != "docker":
        raise RunError(f"{NEEDS_DOCKER}: drop --host, or play without --autopilot")
    return engage, budget


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _wait_for_start(options: RunOptions, profile: EventProfile) -> None:
    """Under autopilot, wait until the event's start (event.start) before anything is pulled
    or released, saying so first. Ctrl-C stops the wait (KeyboardInterrupt: nothing has
    started). An event whose end has passed is refused: there is nothing to run."""
    now = options.now or _now
    if profile.end is not None and now() >= profile.end:
        raise RunError(f"the event ended at {profile.end.isoformat()} (event.end in the event profile): autopilot has "
                       "nothing to run. Play without --autopilot, or correct the profile")
    start = profile.start
    if start is None or (left := (start - now()).total_seconds()) <= 0:
        return
    if options.say is not None:
        from . import fmt

        options.say(f"autopilot: the event starts at {start.isoformat()} (event.start), in {fmt.duration(left)}: waiting "
                    "until then before anything is pulled or started. Ctrl-C stops the wait")
    sleep = options.sleep or time.sleep
    while (left := (start - now()).total_seconds()) > 0:
        sleep(min(left, START_WAIT_STEP))


def _refusal_switch(client: ChatClient | None, ladder: Sequence[str]) -> tuple[Callable[[bool], None] | None, bool]:
    """What switches the model client's rerouting of a refusal off and on, for autopilot (no
    refused request goes on to another model while it guards the run), and whether there is
    any to switch off for this ladder. The one thing that reroutes a refusal is Anthropic's
    server-side refusal fallback (agent/anthropic_client.py: `server_fallback`, read at every
    request); the [fallback] API never takes a call a model declined (agent/fallback.py).
    None for a coding-agent CLI's lanes, which have no client here."""
    from .agent.refusal import SERVER_FALLBACK_MODELS

    if client is None:
        return None, False
    parts = [part for part in (client, getattr(client, "primary", None), getattr(client, "fallback", None))
             if part is not None and hasattr(part, "server_fallback")]
    before = [(part, part.server_fallback) for part in parts]

    def switch(allowed: bool) -> None:
        for part, was in before:
            part.server_fallback = was and allowed

    return switch, any(was for _, was in before) and any(model in SERVER_FALLBACK_MODELS for model in ladder)


def _flag_format_note(effective: str, profile: EventProfile | None, board: Board, folder: Path | None) -> str:
    """The run note on the flag format the deck checks every candidate against, and where it
    came from: the event profile's wins over the board's, and flightdeck's own is the default.
    Every loader has checked it (flagformat.py), so it is one line with nothing hidden."""
    if profile is not None and profile.flag_format:
        where = f"the event profile {_show(profile.source)} (event.flag_format)"
    elif board.flag_format:
        where = "the board's board.json" + (f" in {_show(folder)}" if folder is not None else "")
    else:
        where = "flightdeck's default, since neither the board nor an event profile sets one"
    return f"flag format: {_show(effective)}, from {where}"


def _held_secrets(config: Config, profile: EventProfile | None, token: str | None) -> dict[str, str]:
    """Every secret this run holds, as name -> value, for a lane's redaction (agent/held.py:
    flightdeck's own lanes show each value as [NAME] wherever a tool call gives it, before the
    model or the deck has it; agent/external.py's wherever the CLI writes it, before anything
    is shown, logged or put in a transcript): each value in the keys file, the [api] and
    [fallback] keys (a coding-agent run uses neither, but a host lane can read them), the
    notification webhook's URL ([notify] webhook_env: it often holds a token), and the CTFd token. A variable set in the environment wins over the keys file, as it does
    everywhere in flightdeck; a keys-file value it overrides is a secret all the same, shown as
    [NAME_IN_KEYS_FILE]. A key that is not set is no secret to hide, and no error here."""
    from .keys import KeysError, load_keys

    try:
        filed = {name: value.strip() for name, value in load_keys().items()}
    except KeysError as exc:
        raise RunError(str(exc)) from None
    environ = _environment()
    spare = config.fallback.key_env if config.fallback is not None else ""
    held = {
        name: value
        for name in dict.fromkeys([*filed, config.api.key_env, spare, config.notify.webhook_env])
        if name and (value := environ.get(name, "").strip() or filed.get(name, ""))
    }
    if profile is not None and profile.token_env and token:
        held[profile.token_env] = token
    for name, value in filed.items():
        if value and value != held.get(name):
            held[f"{name}_IN_KEYS_FILE"] = value
    return held


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


def anthropic_price_notes(config: Config, cap: float | None) -> list[str]:
    """What the config of a run on the Anthropic API prices below Anthropic's bill or not at
    all, said before lanes start (a config written before init wrote these): a model the
    refusal fallback answers with for the ladder (agent/refusal.py) with no price, whose
    attempts are spend with no price (P7), and a price with no cache_write, at which a cache
    write counts as input although Anthropic charges 1.25 times input for one."""
    from .agent.refusal import answering

    out = []
    spare = [m for m in answering(config.models) if m not in config.prices]
    if spare:
        then = f"asks you once before it carries on without its ${cap:g} cap" if cap else "shows its dollars as not fully known"
        out.append(f"no price in your config for {', '.join(spare)}, which Anthropic's refusal fallback answers with for "
                   f"your ladder: a lane it answers for {then} ([prices.{json.dumps(spare[0])}] prices it; `flightdeck "
                   "init --provider anthropic` writes these)")
    flat = [m for m in (*config.models, *answering(config.models))
            if m in config.prices and config.prices[m].cache_write is None]
    if flat:
        out.append(f"no cache_write in your price for {', '.join(flat)}: what a lane writes to Anthropic's prompt cache "
                   "counts at the input rate, below the 1.25 times input Anthropic charges for it")
    return out


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
        raise RunError(no_agents(profile, policies))
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


SPENDS_TRIES = (
    'submit_limited = "auto" in your config: a flag for a challenge whose tries the platform counts goes out without you, '
    "the last try included; a wrong flag can use up the tries"
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
                "team mode with no team folder: your claims stay on your flightdeck"
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


class _Submits:
    """The deck's submitter for a CTFd board (Deck(submitter=...)): flags go to CTFd from one
    worker task on the console's loop, one at a time, so a slow CTFd never holds the console
    or a lane up.

    The deck hands a flag over by calling this, which only queues it. work() sends it with
    CTFdVerifier.submit() in a thread (asyncio.to_thread: the call returns its Verdict and
    sets nothing the loop reads), then, back on the loop, does the run's bookkeeping and gives
    the deck the answer (Deck.platform_verdict), with the tries CTFd says are left. When CTFd
    did not judge the flag (paused, rate-limited, no answer, part of the answer) its reason
    is a warning on the deck, which then asks the player to submit it by hand. Out of tries
    ("locked_out") is no such warning: the deck closes the challenge and says so,
    with CTFd's words, and asks nobody to submit the flag by hand (CTFd checks none).
    "already solved" (by the account, so by the team) is news, not a problem: the run takes
    CTFd's word for it, as for a solve its poll finds, without waiting for the player's
    answer about this flag. A flag still on its way when the run ends is named then
    (unsent()), as not known to have been submitted.

    A rate limit that passes is waited out and the flag sent again (P33), up to RESENDS times:
    CTFd said it did not check the flag ("ratelimited", after the verifier ruled out a
    challenge that is out of tries), so there is no answer to count twice. The wait is what
    CTFd asks ("Try again in N seconds", at most RESEND_MAX) or RESEND_WAIT, a little over
    the minute CTFd's limits count in. Flags queued behind it wait too: they are the same
    account's, and would be refused the same way. Never for a challenge whose tries are
    counted: CTFd records a refused try against the limit, so those stay the player's (D21).
    When the last send is refused too, the flag goes back to the player as before."""

    RESENDS = 3  # sends after the first, for one flag
    RESEND_WAIT = 65.0  # seconds, when CTFd names no wait: its limits count the last minute
    RESEND_MAX = 300.0  # the longest wait taken from CTFd's own words

    def __init__(self, verifier: CTFdVerifier, link: CTFdLink) -> None:
        self.verifier = verifier
        self.link = link
        self.deck: Deck | None = None  # set once the deck exists
        self.solved: Callable[[], None] | None = None  # the run's: close what CTFd lists as solved
        self.unjudged: Callable[[Verdict], None] | None = None  # the run's: CTFd did not judge a flag (autopilot disengages)
        self.queue: asyncio.Queue[tuple[str, str, str]] = asyncio.Queue()  # (lane, challenge, flag) to send, in order
        self.sending: tuple[str, str, str] | None = None  # the one sent now, until its answer is applied
        self.errors: list[str] = []  # bookkeeping that failed (a flightdeck bug), shown when the run ends
        self.sleep: Callable[[float], Awaitable[None]] = asyncio.sleep  # the wait before a flag is sent again

    def __call__(self, lane_id: str, challenge_id: str, flag: str) -> None:
        self.queue.put_nowait((lane_id, challenge_id, flag))

    async def work(self) -> None:
        """Send each flag in turn, and apply CTFd's answer on this loop. Cancelled at shutdown."""
        while True:
            item = await self.queue.get()
            self.sending = item
            lane_id, challenge_id, flag = item
            sends = 0
            while True:
                try:
                    verdict = await asyncio.to_thread(self.verifier.submit, challenge_id, flag)
                except Exception as exc:  # a bug in the verifier: the outcome is not known, and the worker goes on
                    verdict = Verdict(None, error=(
                        f"flightdeck could not submit it ({type(exc).__name__}: {exc}); it may have reached CTFd: check the "
                        "challenge there before submitting it again"
                    ))
                sends += 1
                wait = self.resend_after(challenge_id, verdict) if sends <= self.RESENDS else None
                if wait is None:
                    break
                with contextlib.suppress(Exception):  # the note is a courtesy: the resend does not hang on it
                    self.deck.note(lane_id, (
                        f"CTFd rate-limited the submission of {_show(flag)} and did not check it; flightdeck sends it "
                        f"again in {wait:g}s (send {sends + 1} of {self.RESENDS + 1})"
                    ))
                await self.sleep(wait)
            try:
                self.answer(lane_id, challenge_id, flag, verdict)
            except Exception as exc:  # a bug: said now and at the end, and the next flag still goes
                problem = f"CTFd: could not apply CTFd's answer to {_show(flag)}: {type(exc).__name__}: {exc}"
                self.errors.append(problem)
                with contextlib.suppress(Exception):
                    self.deck.warn(problem, challenge=challenge_id, data={"source": "ctfd"})
            self.sending = None

    def resend_after(self, challenge_id: str, verdict: Verdict) -> float | None:
        """How long to wait before sending the flag again, or None when it is not sent again:
        only a rate limit CTFd says passes, at a challenge whose tries nobody counts."""
        attempt = verdict.attempt
        if verdict.ok is not None or attempt is None or attempt.status != "ratelimited" or attempt.tries_left is not None:
            return None
        ch = self.deck.challenges.get(challenge_id) if self.deck is not None else None
        if ch is None or ch.limited:
            return None
        said = re.search(r"\bin (\d{1,5}) seconds?\b", attempt.message or "")
        if said is None:
            return self.RESEND_WAIT
        return min(float(said.group(1)) + 1.0, self.RESEND_MAX)

    def answer(self, lane_id: str, challenge_id: str, flag: str, verdict: Verdict) -> None:
        """CTFd's answer to a flag, on the deck's thread: the run's bookkeeping, then the deck's."""
        deck, link = self.deck, self.link
        assert deck is not None
        attempt = verdict.attempt
        tries = attempt.tries_left if attempt is not None else None
        detail = verdict.error or (attempt.message if attempt is not None else "")
        number = self.verifier.ids.get(challenge_id)
        if verdict.ok is None and attempt is not None and attempt.status == "already_solved" and number is not None:
            link.answered.add(challenge_id)
            link.solved.add(number)
            deck.platform_verdict(lane_id, flag, None, detail, tries_left=tries)
            if self.solved is not None:
                self.solved()
            return
        locked = attempt is not None and attempt.status == "locked_out"  # the deck says it: the challenge is out of tries
        if verdict.ok is None and verdict.error and not locked:
            ch = deck.challenges.get(challenge_id)
            name = untrusted(ch.name if ch is not None else challenge_id, one_line=True)
            deck.warn(
                f"CTFd did not judge {untrusted(flag, one_line=True)} for {name}: {verdict.error}",
                challenge=challenge_id,
                data={"source": "ctfd"},
            )
        deck.platform_verdict(lane_id, flag, verdict.ok, detail, tries_left=tries)
        if verdict.ok is None and verdict.error and not locked and self.unjudged is not None:
            self.unjudged(verdict)  # after the deck has the flag back with the player

    def unsent(self) -> list[str]:
        """After the worker has stopped: the flags on their way to CTFd when the run ended,
        said for the player, made safe to print. The one being sent may have reached CTFd;
        the others did not leave flightdeck."""
        deck = self.deck
        out: list[str] = []

        def named(lane_id: str, challenge_id: str, flag: str) -> str:
            ch = deck.challenges.get(challenge_id) if deck is not None else None
            return f"{_show(flag)} ({lane_id}, {_show(ch.name if ch is not None else challenge_id)})"

        if self.sending is not None:
            lane_id, challenge_id, flag = self.sending
            out.append(
                f"CTFd: {named(lane_id, challenge_id, flag)} was on its way to CTFd when the run ended, so it is not known "
                "to have been submitted: check the challenge on CTFd before you submit it again"
            )
        while not self.queue.empty():
            out.append(f"CTFd: {named(*self.queue.get_nowait())} was not submitted: it was waiting to go to CTFd when the run ended")
        if deck is not None:
            for challenge_id in deck.challenges:
                for lane_id, flag in deck.submitting(challenge_id)[1:]:
                    out.append(
                        f"CTFd: {named(lane_id, challenge_id, flag)} was not submitted: it was waiting for the answer to "
                        "another flag of that challenge when the run ended"
                    )
        return out


def _never_verify(challenge_id: str, flag: str) -> bool | None:
    """The deck's verify() when flags go to CTFd through its submitter: the deck never calls it."""
    raise RuntimeError("a CTFd run's flags go to CTFd through the run's submitter, never through verify()")


@dataclass(frozen=True)
class _FirstPull:
    board: Board
    folder: Path
    ids: Mapping[str, int]  # board id -> CTFd id
    solves: Solves | None  # what CTFd lists as solved for the account, and whose; None if it could not be read
    problems: tuple[str, ...]  # the challenges left out, and why
    tries: Mapping[str, int] = field(default_factory=dict)  # board id -> the tries left at its flag (Pull.tries)
    tries_unread: tuple[str, ...] = ()  # the challenges whose tries used could not be read, and why


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
                'here (not at a terminal, or a headless run): start play at a terminal without --headless, or set '
                'pull = "auto" in the profile\'s [policies]'
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
    plan.notes += _tries_notes(result)
    if not waves:
        plan.notes.append(
            'pull is "confirm" in the event profile: flightdeck pulled the board once, after you said yes, and pulls no '
            "later waves; start play again to pull new challenges"
        )
    return _FirstPull(result.board, folder, ids, solves, tuple(result.problems), dict(result.tries), tuple(result.tries_unread))


def _tries_notes(result: Pull) -> list[str]:
    """What the player should know of the tries CTFd counts, as the first pull read them: how
    many are left at each such flag, which challenges are out of tries (no lane works them
    while CTFd says so), and which counts could not be read (their flags wait for you all the
    same)."""
    notes: list[str] = []
    names = {b.challenge.id: b.challenge for b in result.board.challenges}
    for cid, left in sorted(result.tries.items()):
        ch = names.get(cid)
        if ch is None:
            continue
        name, most = _show(ch.name), ch.max_attempts
        if left == 0:
            notes.append(f"{name}: CTFd says no tries are left at its flag ({most} allowed), so it is out of tries: no lane "
                         "works it and flightdeck sends no flag for it while CTFd says so")
        else:
            notes.append(f"{name}: CTFd allows {most} tries at its flag and {left} {'is' if left == 1 else 'are'} left; "
                         "each of its flags waits for you")
    notes += [f"CTFd: {line}; its flags wait for you all the same" for line in result.tries_unread]
    return notes


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


# The [light] jobs a run of this build gives the light model: the hint judge (detect/judge.py),
# the flagcheck before an auto-submit (agent/flaggate.py), and route and recon at a lane's start
# (agent/facts.py).
RUN_LIGHT_JOBS = ("judge", "flagcheck", "route", "recon")


def _flagcheck_idle(submit: str, checks: bool) -> str:
    """Why no flag of this run goes out without the player, so flagcheck (agent/flaggate.py),
    which checks only such a flag, has nothing to do; "" when one may. `checks`: flags go to a
    platform, or to an answers file, rather than to the player to submit by hand."""
    if submit != "auto":
        return f'submit is "{submit}", so every flag waits for you already'
    if not checks:
        return ("flightdeck submits no flag in this run (no answers file and no platform to send it to): you submit "
                "each one yourself")
    return ""


def _lights(config: Config, notes: list[str], *, idle: dict[str, str] | None = None):
    """The run's light engines (light.build_all), one per distinct spec, for the [light] jobs a
    run wires in; a spec that cannot be made leaves its jobs off, said in `notes`, as is a job
    [light] jobs lists that this build does not run yet, and what route and recon do. `idle`:
    jobs this run gives nothing to do, with why (said in `notes` for a job [light] jobs lists):
    no engine is made for them."""
    from .agent.facts import first_look_notes
    from .light import build_all

    idle = {job: why for job, why in (idle or {}).items() if job in config.light_jobs}
    lights = build_all(config, jobs=[job for job in RUN_LIGHT_JOBS if job not in idle])
    notes.extend(lights.notes)
    for job, why in idle.items():
        notes.append(f"[light] jobs lists {job}, but this run gives it nothing to do: {why}")
    notes.extend(first_look_notes(lights))
    waiting = [job for job in config.light_jobs if job not in RUN_LIGHT_JOBS]
    if waiting:
        listed = waiting[0] if len(waiting) == 1 else ", ".join(waiting[:-1]) + " and " + waiting[-1]
        notes.append(f"[light] jobs lists {listed}, which this build of flightdeck does not run yet: no light model "
                     "is asked for them")
    return lights


def _flaggate(config: Config, lights, notes: list[str]):
    """The run's flagcheck (agent/flaggate.py), on the engine `lights` made for it, or None;
    its line for the player goes in `notes`."""
    from .agent.flaggate import from_lights

    gate, note = from_lights(config, lights)
    if note:
        notes.append(note)
    return gate


def _watch(deck: Deck, config: Config | None = None, notes: list[str] | None = None, lights=None):
    """The course detectors (M3), raising and clearing alerts after every turn; with a light
    model for the judge ([light] jobs), the hint judge too (its line for the player goes in
    `notes`). `lights`: the run's light engines (_lights), which the judge shares."""
    from .detect import Watch, default_detectors
    from .detect.judge import from_config

    judge, note = from_config(config, lights=lights) if config is not None else (None, "")
    if note and notes is not None:
        notes.append(note)
    watch = Watch(deck, default_detectors(), judge=judge)
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


def _lane_toolkit(pack: Path) -> str:
    """The pack's note for the lanes' briefs ([l1] lane_tools), or RunError: the pack must say
    how a lane calls it."""
    from . import pack as packs

    try:
        return packs.lane_note(packs.read(pack))
    except packs.PackError as exc:
        raise RunError(f"[l1] lane_tools is on, but {exc}; turn lane_tools off, or use a pack that brings a lane note") from None


def _check_l1_image(image: str) -> None:
    docker = shutil.which("docker") or "docker"
    if subprocess.run([docker, "image", "inspect", image], capture_output=True, text=True).returncode != 0:
        raise RunError(
            f"the L1 image {image} ([l1] image) is not on this machine, and flightdeck never fetches images by itself: "
            "`flightdeck pack image` builds your pack's image, or remove [l1] image to run engines in the lane image"
        )


KNOWN_APIS = {"api.anthropic.com": "the Anthropic API", "openrouter.ai": "OpenRouter", "api.openai.com": "the OpenAI API"}


def api_kind(base_url: str) -> str:
    """An API named for a flight card: a server on this machine, one of the public APIs, or
    "another API". Never the address itself, which can name a private host."""
    from urllib.parse import urlsplit

    from .light import on_this_machine

    if on_this_machine(base_url):
        return "a server on this machine"
    try:
        host = urlsplit(base_url).hostname or ""
    except ValueError:
        host = ""
    return KNOWN_APIS.get(host, "another API")


def _setup(
    config: Config, options: RunOptions, deck_config: DeckConfig, ladder: Sequence[str], *,
    agent: str | None, ctfd: bool, engines: int,
) -> dict[str, object]:
    """How this run is set up, for RUN_DIR/setup.json and the flight card. It names models
    and settings only: no path, no key or its variable, no address, no event and no
    challenge."""
    from .config import light_specs
    from .practice_set import practice_dir

    board = "ctfd" if ctfd else "folder"
    if options.board is not None and Path(options.board).resolve() == practice_dir().resolve():
        board = "practice"
    lights = [
        {"engine": spec.config.engine, "model": spec.config.model, "jobs": list(spec.jobs),
         "api": api_kind(spec.config.base_url) if spec.config.base_url else ""}
        for spec in light_specs(config) if spec.jobs and spec.config.engine != "rules"
    ]
    return {
        "runtime": "docker" if deck_config.containerized else "host",
        "max_lanes": deck_config.max_lanes,
        "submit": deck_config.submit,
        "lanes": agent or "flightdeck",
        "api": "" if agent else api_kind(config.api.base_url),
        "fallback": "" if agent or config.fallback is None else api_kind(config.fallback.base_url),
        "ladder": list(ladder),
        "fast": [] if agent else list(config.api.fast),
        "light": lights,
        "l1_engines": engines,
        "team": deck_config.team,
        "board": board,
        "token_cap": config.lanes.token_cap,
        "dollar_cap": config.lanes.dollar_cap,
    }  # autopilot is not here: the flight card reads it from the run log, which says whether it was engaged


def lane_reach(urls: Sequence[str], instance: str, api: Sequence[str] = ()) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """(what a docker lane's network reaches from its start, what it reaches once the player
    allows it its instance), as URLs (P9): its challenge's instance, `urls`, at once under
    the instance policy "auto", after the player's yes under "confirm", never under "off";
    and `api`, a coding-agent CLI's own API (agent.egress.CLI_API), from the start. A lane
    with neither gets no network at all, so it cannot fetch solutions or talk to anything;
    one with either reaches those hosts and ports and nothing else (agent/egress.py), never
    Docker's open bridge network."""
    if instance == "auto":
        return (*api, *urls), ()
    if instance == "confirm":
        return tuple(api), tuple(urls)
    return tuple(api), ()


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
