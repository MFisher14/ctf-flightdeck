"""The agent driver: every lane is an agent loop against a model API (M1, D5a).

One asyncio task per lane, on the console's event loop, so every Deck call happens on the
deck's thread (the LaneDriver contract in core/driver.py). A turn is one model call: the
reply's tool calls run in the lane's workspace, their results go back into the lane's
context, and the turn is reported to the deck (tokens, cost, the step, changed files, a
candidate flag). The step is one for the console and the detectors (_step: the turn's first
real call, with "(+N more)" for the rest); with it goes every tool call the turn ran, each
with a longer excerpt of its output, which the lane's transcript keeps (TurnReport.calls). The deck applies the rules (approvals, caps, the flag format); the loop
calls the model, and runs a tool call, only while the lane is RUNNING, and waits otherwise.

Each lane starts with a fresh context: the fixed system prompt, then the challenge brief (and,
once its L1 engines have run, what they found). Escalation starts a fresh context too, on the
stronger model, with the deck's summary; so does the refresh of a context grown too long.

A lane whose challenge other lanes worked or work, or whose challenge is one of a series on the
board, reads that after its brief (agent/sharing.py: what those lanes tried, the sibling
challenges and where a sibling's files are, fenced as data): made once, at its first model
call, and repeated as it was in every fresh context. A sibling's workspace is picked at the
lane's start, before its own is prepared (a Docker lane's container mounts it read-only).

With a light model for route or recon ([light] jobs), the challenge's first look (agent/facts.py)
starts once the workspace is ready, beside the handout search and the L1 stage. Nothing waits
for it: at the lane's first model call the brief takes what is back, in a fence of its own, and
every fresh context of the lane repeats that brief as it was; what comes later is never added.

A flag the model submits that the challenge's own text holds (its description, or a handout
file as it came: often a decoy) is not claimed: under submit auto too it waits for the
player, and the model hears why, as agent/external.py's lanes do. Such a flag that an L1
engine gives as its result (a stand-in flag.txt it read out) waits too, and the lane says why.
The search of that text at the lane's start (planted) is bounded, so under auto, before
such a flag would go out on its own, it is looked for in all of that text (agent/owntext.py),
and it waits when it is there or when that search could not cover it all.
With the light model's flagcheck (agent/flaggate.py), a flag the model submits that would go
out without the player
(submit auto, not planted, tries not counted) is checked first, in the background: it reaches
the deck once the light model has answered, claimed as before unless it called the flag a
stand-in, which then waits for the player. The lane goes on meanwhile; one that gives up
meanwhile ends once the check is in.

A TCP service the description names with a command (`nc host port`), on another machine, that
the board does not list as the challenge's instance is said to the player at the lane's start
(no model: the instance rule). Nothing is opened or added for it.

A lane gives up after MAX_IDLE_TURNS replies in a row without a tool call, and then calls the
model no more, also while the deck keeps it open for a flag that still waits (for the player,
or for the platform's answer). A model call that
fails in a way every lane would (no answer, a refused key, an unknown model) holds the deck's
queue before the lane ends, so the next challenges are not started only to fail the same way.

The secrets the run holds (`secrets`: run.py's _held_secrets, name -> value) never reach the
model or the deck by value: each is replaced by [NAME] (agent/held.py) in what a tool call
gave, where it arrives and before anything cuts it (the lane's Toolbox), in every report to
the deck (its step, its plan, its files' diffs; never its flag), in the driver's notes on the
lane, and in what else the driver writes into the lane's context (what the L1 engines found,
the first look, the player's and flightdeck's messages, a summary). A host lane can read the
keys file; this keeps the values out of the model's API and out of every record, as
agent/external.py does for its lanes. It is cleanup, not a fence.

Escalation and take-over are turn boundaries. Each bumps the lane's generation, and a reply
asked for in an older generation runs no further tool call. After an escalation none of
it goes into the new context (it belongs to the old one). After a take-over the calls it
had not run yet are answered "not run", and the next call tells the model what the player
did. A reply that arrives after either is dropped (its cost still counts). So is one the lane's
stop cuts short (a kill, a solve, quitting) while it waits for the paused lane or its tool calls
run: what its call cost is reported as spend, which the deck counts after a lane's end too.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path

from ..core.driver import TakeoverRefused, TurnReport, spend_only
from ..core.model import Call, Challenge, EscalationSummary, Lane, LaneState, Pending, PendingKind
from ..core.summary import lane_summary
from ..l1.runner import scan
from ..light import Lights
from ..pricing import Price, call_cost
from ..text import untrusted
from . import owntext, prompts, sharing
from .client import RETRY_STATUSES, ChatClient, ModelError, Reply, Usage
from .flaggate import SUBMITTED_ONLY, FlagGate, Outputs
from .held import Secrets
from .facts import FirstLooks, Look
from .l1stage import L1Stage, StageLane, run_stage
from .tools import TOOLS, Toolbox, ToolResult
from .workspace import (
    PRIVATE,
    DockerWorkspace,
    ShellSpec,
    Snapshot,
    Workspace,
    WorkspaceError,
    changed_files,
    open_inside,
    remove_shell_home,
    take_snapshot,
    write_inside,
)

WorkspaceFactory = Callable[[Lane, Challenge], Workspace]
"""Makes the workspace for a lane: HostWorkspace or DockerWorkspace, per `containerized`."""

MAX_SESSION = 256  # OpenRouter's limit for session_id
MAX_FILES_PER_TURN = 50  # an unpacked archive can change thousands; the console shows the first 50
COMPACT_AT = 50_000  # prompt tokens: past this, a lane continues in a fresh context with a summary
HISTORY = f"{PRIVATE}/takeover_history"  # the take-over shell's bash history (its HISTFILE)
MAX_HISTORY_BYTES = 64 * 1024  # read from the end of the history, at most
NOT_RUN = "not run: the player took over your shell before this call ran"
INSTANCE_POLICIES = ("auto", "confirm", "off")  # pre-flight's instance policy, as lanes see it (manual is off)
MAX_IDLE_TURNS = 3  # replies (a CLI lane's turns: agent/external.py) in a row that did nothing before the lane gives up
MAX_SAID_FLAGS = 3  # candidates taken from one reply's text, at most
SAID_SCAN = 20_000  # characters of a reply's text searched for flags
# The search of the challenge's own text for flags at a lane's start is bounded by these, and says nothing of what it
# misses: under auto a flag a lane gives is looked for in all of that text before it goes out (_vet).
PLANT_SECONDS = 5.0  # that search (off the loop) stops after this long
PLANT_FILE_BYTES = 1024 * 1024  # of each handout file searched
PLANT_BYTES = 16 * 1024 * 1024  # of all of them
EVERY_LANE = {  # HTTP statuses of a model API that every lane would get alike, and what the player should check
    401: "check the API key",
    402: "check the account's credits",
    403: "check that the key may use this model",
    404: "check the model id in the [models] ladder, and base_url",
    405: "check base_url",
}
# A model API failure that may pass (_may_pass) ends its own lane only. That many lanes ending on one in a row, each
# within that long of the one before and with no reply from the API in between, is an outage: the queue is held.
OUTAGE_LANES = 2
OUTAGE_SECONDS = 300.0


def _may_pass(status: int | None) -> bool:
    """Whether a model API's failure is one that may pass on its own: a status the client
    tries again (a timeout, a rate limit, a 5xx) or any other 5xx (Anthropic's 529 overloaded)."""
    return status is not None and (status in RETRY_STATUSES or status >= 500)


def web_origins(urls: Sequence[str]) -> tuple[str, ...]:
    """The http(s) origins among a challenge's instances: the http tool's. A TCP service
    (tcp://host:port, what `nc host port` reaches) is the shell's."""
    return tuple(url for url in urls if url.startswith(("http://", "https://")))


def unlisted_services(description: str, urls: Sequence[str]) -> tuple[str, ...]:
    """The TCP services (tcp://host:port) a challenge's description names with a command, as
    connection info does (`nc host port`, `ncat`, `telnet`, `socat - TCP:host:port`, `openssl
    s_client -connect host:port`: platform/ctfd.services_in), that are not among the instances
    the board lists for it: the instance rule, no model. A bare HOST:PORT is not one there
    (`vuln.c:57` is a line of source), nor is a loopback address (a copy of the service the
    player runs on their own machine)."""
    from ..platform.ctfd import services_in

    listed = set(urls)
    return tuple(service for service in services_in(description, bare=False)
                 if service not in listed and not _loopback(service))


def _loopback(service: str) -> bool:
    """tcp://host:port names this machine: localhost, or a loopback address."""
    host = service.removeprefix("tcp://").rpartition(":")[0].removeprefix("[").removesuffix("]")
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def instance_note(services: Sequence[str], workspace: Workspace) -> str:
    """The player's note on services the description names and the board does not list
    (unlisted_services): what the lane can reach, and how the player would add one."""
    named = ", ".join(_with_nc(service) for service in services)
    it, they = ("it", "it is") if len(services) == 1 else ("them", "they are")
    if isinstance(workspace, DockerWorkspace) and workspace.network == "none":
        reach = f"this lane's container has no network, so it cannot reach {it}"
    else:
        reach = f"flightdeck does not give {it} to this lane as its instance"
    return (f"the description names {named}, which the board does not list as this challenge's instance: {reach}. "
            f"If {they} the challenge's instance, add {it} to \"urls\" in its challenge.json; flightdeck opens nothing "
            "and adds no instance on its own")


def _with_nc(service: str) -> str:
    """tcp://host:port as the brief names a TCP instance: with the command that reaches it."""
    host, _, port = service.removeprefix("tcp://").rpartition(":")
    host = host.removeprefix("[").removesuffix("]")
    return f"{service} (nc {host} {port})" if host and port.isdigit() else service


def _set_event() -> asyncio.Event:
    event = asyncio.Event()
    event.set()
    return event


class _Overtaken(Exception):
    """Stops a failing call's retries: the lane ended, or the call no longer counts (the
    lane was escalated or taken over while it waited)."""


@dataclass
class _Run:
    """The driver's state for one lane."""

    lane_id: str
    challenge: Challenge
    workspace: Workspace
    toolbox: Toolbox
    model: str
    session: str
    messages: list[dict] = field(default_factory=list)
    l1_message: dict | None = None  # what the L1 engines found: after the brief in every fresh context of the lane
    notes: list[str] = field(default_factory=list)  # flightdeck's notes for the next turn
    wake: asyncio.Event = field(default_factory=asyncio.Event)
    idle: asyncio.Event = field(default_factory=_set_event)  # cleared while a turn runs its tool calls
    task: asyncio.Task[None] | None = None
    closing: asyncio.Future[None] | None = None  # closing the workspace: shielded, so a cancel cannot cut it short
    ready: bool = False  # the workspace is prepared
    stopped: bool = False
    closed: bool = False
    instance: str = ""  # the live instance under the confirm policy: asked, allowed, open, declined, failed
    escalations: int = 0
    generation: int = 0  # bumped at escalation and take-over: a reply asked for before must not run
    idle_turns: int = 0  # replies in a row with no tool call (and no new flag in their text) since the player last spoke
    said: set[str] = field(default_factory=set)  # flags the model wrote without calling a tool, already raised
    planted: frozenset[str] = frozenset()  # flag-format matches in the challenge's own text: never claimed when submitted
    own: dict[str, owntext.Found] = field(default_factory=dict)  # submit auto: each flag it gives, looked for in all of it
    outputs: Outputs = field(default_factory=Outputs)  # its newest tool outputs: where a flag it submits was found
    uncounted: tuple[str, Usage] | None = None  # a reply's call (its model, its usage) not reported yet: _count_cut
    look: Look | None = None  # the challenge's first look (agent/facts.py), until the lane's first model call takes it
    recon: str = ""  # what of the first look was back then: in the brief of every fresh context of the lane
    shares: tuple[sharing.Share, ...] = ()  # the sibling workspaces it may read (agent/sharing.py), picked at its start
    handover: dict | None = None  # what other lanes tried and its series, as of its first model call: after the brief in every fresh context
    opened: bool = False  # the lane's first model call is made (or about to be): nothing more goes into its brief


@dataclass
class Takeover:
    """The player's shell in a lane's workspace. begin() waits for the command the lane is
    running, then gives the shell; finish() says what changed, tells the lane, and puts the
    changed files on the lane."""

    run: _Run
    driver: AgentDriver
    before: Snapshot | None = None
    history: bool = False  # the history file was emptied at the start, so what it holds is this take-over's
    shell: ShellSpec | None = None  # what begin() gave; finish() removes the folder made for it (its HOME)

    @property
    def busy(self) -> bool:
        """The lane is running a command; begin() waits for it (it has its own timeout)."""
        return not self.run.idle.is_set()

    async def begin(self) -> ShellSpec:
        run = self.run
        await run.idle.wait()
        if run.closed or self.driver._over(run):
            raise TakeoverRefused(f"{run.lane_id} has ended")
        shell = self.shell = run.workspace.interactive_shell()  # first: on the host it repairs .flightdeck
        root = run.workspace.root
        try:
            await asyncio.to_thread(write_inside, root, HISTORY, b"")
            self.history = True
        except OSError:
            self.history = False  # then its lines could be the lane's: they are not read
        self.before = await asyncio.to_thread(take_snapshot, root)
        return shell

    def finish(self) -> str:
        run = self.run
        if self.shell is not None:  # the shell has exited: its HOME goes (the workspace's close tries again)
            problem = remove_shell_home(self.shell)
            if problem:
                self.driver.errors.append(f"{run.lane_id}: {problem}")
        root = run.workspace.root
        changes = changed_files(self.before, take_snapshot(root), root) if self.before is not None else []
        if changes:
            names = ", ".join(f"{prompts.one(c.path, 120)} ({c.status})" for c in changes[:8])
            note = f"changed {names}" + (f" and {len(changes) - 8} more" if len(changes) > 8 else "")
        else:
            note = "no files changed"
        told = f"The player took over your shell and handed it back ({note})."
        commands = self._commands(root) if self.history else []
        if commands:
            told += " Their last commands, as the workspace recorded them:\n" + prompts.fenced("\n".join(commands)) + "\n"
        run.notes.append(told + " Look at the workspace again before you go on.")
        if changes:  # the player's, not the lane's: a writeup keeps them apart
            self.driver._report(run, TurnReport(turn=False, files=tuple(replace(c, by="player") for c in changes)))
        return note

    @staticmethod
    def _commands(root) -> list[str]:
        """The take-over's last commands, each one line. Read without following a symlink: in
        its container the lane can put anything at that path, a link to a host file too."""
        try:
            fd = open_inside(root, HISTORY.split("/"))
        except OSError:
            return []
        with os.fdopen(fd, "rb") as file:
            size = os.fstat(file.fileno()).st_size
            file.seek(max(0, size - MAX_HISTORY_BYTES))
            raw = file.read(MAX_HISTORY_BYTES)
        lines = [line for line in raw.decode("utf-8", "replace").splitlines() if line.strip()]
        return [prompts.one(line, 200) for line in lines[-8:]]


class AgentDriver:
    """Runs lanes as agent loops. Implements core.driver.LaneDriver."""

    def __init__(
        self,
        client: ChatClient,
        workspaces: WorkspaceFactory,
        *,
        run_id: str,
        files: Mapping[str, Sequence[str]] | None = None,
        urls: Mapping[str, Sequence[str]] | None = None,
        prices: Mapping[str, Price] | None = None,
        max_tokens: int | None = None,
        compact_at: int | None = COMPACT_AT,
        l1: L1Stage | None = None,
        instance: str = "auto",
        flaggate: FlagGate | None = None,
        lights: Lights | None = None,
        secrets: Mapping[str, str] | None = None,
    ) -> None:
        """`secrets`: name -> value of what must never reach a lane's model or the deck (run.py's
        _held_secrets), each shown as [NAME] wherever a lane's tool calls give it."""
        self.client = client
        self.redact = Secrets(secrets)
        self.workspaces = workspaces
        self.run_id = run_id
        self.files = dict(files or {})  # challenge id -> handout file names, for the brief
        self.urls = {cid: tuple(u) for cid, u in (urls or {}).items()}  # challenge id -> live instance origins
        self.prices = dict(prices or {})
        self.max_tokens = max_tokens
        self.compact_at = compact_at  # None: never refresh a lane's context
        self.l1 = l1  # the player's no-model solvers, run before a lane's first model call; None: none
        if instance not in INSTANCE_POLICIES:
            raise ValueError(f"instance must be one of {', '.join(INSTANCE_POLICIES)}, got {instance!r}")
        self.instance = instance  # may lanes reach a challenge's live instance: auto, confirm (ask first), off
        # the light model's flagcheck (run.py sets the run's before any lane starts); None: no flag is checked
        self.flaggate = flaggate
        self.runs: dict[str, _Run] = {}
        self.errors: list[str] = []  # cleanup problems, shown when the console exits
        self.answered: set[str] = set()  # the models that have answered a lane in this run
        self.outage: list[tuple[str, float]] = []  # lanes that ended in a row on a failure that may pass, and when (_outage)
        self.deck = None
        self.lights = lights  # the run's light engines (light.Lights): route and recon at a lane's start; None: none
        self.looks = FirstLooks(self.errors)

    # ------------------------------------------------------------------ LaneDriver

    def attach(self, deck) -> None:
        self.deck = deck

    def start(self, lane: Lane, challenge: Challenge) -> None:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            raise RuntimeError("agent lanes start from the console's event loop, and none is running") from None
        workspace = self.workspaces(lane, challenge)
        urls = self.urls.get(challenge.id, ())
        if urls and self.instance == "confirm":
            toolbox = Toolbox(workspace, scrub=self.redact, http_off="the player has not allowed the live instance yet")
        elif urls and self.instance == "off":
            toolbox = Toolbox(workspace, scrub=self.redact, http_off="the event's rules keep lanes off the live instance")
        elif urls and not web_origins(urls):  # a TCP service (`nc host port`): the shell reaches it, not http
            toolbox = Toolbox(workspace, scrub=self.redact, http_off=f"this challenge's instance is not a web server ({', '.join(urls)}): "
                                                  "reach it from the shell, for example with nc")
        else:
            toolbox = Toolbox(workspace, scrub=self.redact, http_allow=web_origins(urls))
        run = _Run(
            lane_id=lane.id,
            challenge=challenge,
            workspace=workspace,
            toolbox=toolbox,
            model=lane.model,
            session=self._session(lane.id, 0),
            shares=sharing.attach(self.deck, challenge, workspace, self._root_of),
        )
        run.messages = self._fresh(run, lane.approach)
        self.runs[lane.id] = run
        run.task = loop.create_task(self._loop(run), name=f"flightdeck lane {lane.id}")

    def pause(self, lane: Lane) -> None:
        """A paused lane finishes the command it is running, then waits: the loop checks the
        lane's state before every model call and every tool call. A lane the player takes
        over does the same, and also drops a reply asked for before the take-over, so
        nothing the model chose before the player touched the workspace runs after."""
        run = self.runs.get(lane.id)
        if run is not None and lane.state is LaneState.TAKEOVER:
            run.generation += 1
            run.wake.set()

    def resume(self, lane: Lane) -> None:
        self._wake(lane)

    def hint(self, lane: Lane, text: str) -> None:
        self._wake(lane)  # the hint is in lane.hints; the next turn sends it and reports it taken

    def redirect(self, lane: Lane, text: str) -> None:
        self._note(lane, f"The player changed your plan to: {untrusted(text, one_line=True)}")

    def escalate(self, lane: Lane, model: str, summary: EscalationSummary) -> None:
        run = self.runs.get(lane.id)
        if run is None:
            return
        run.model = model
        run.escalations += 1
        run.generation += 1
        run.idle_turns = 0  # the stronger model gets its own chances
        run.session = self._session(lane.id, run.escalations)
        text = lane_summary(self.deck, lane, before=summary)
        run.messages = self._fresh(run, lane.approach) + [{"role": "user", "content": self.redact(prompts.escalation(text))}]
        run.wake.set()  # flightdeck's notes stay queued: the stronger model reads them with its first call

    def approved(self, lane: Lane, pending: Pending) -> None:
        if pending.kind is PendingKind.LIVE_BOX:
            run = self.runs.get(lane.id)
            if run is not None and run.instance == "asked":
                run.instance = "allowed"  # opened before the lane's next model call
            self._note(lane, "The player allowed you to use the live instance now.")
        elif pending.kind is PendingKind.BUDGET:
            self._note(lane, "The player approved more budget. Carry on, and keep it lean.")
        else:
            self._wake(lane)

    def rejected(self, lane: Lane, flag: str) -> None:
        self._note(lane, f"{prompts.one(flag, 200)} was submitted and it is not correct.")

    def declined(self, lane: Lane, pending: Pending) -> None:
        if pending.kind is PendingKind.SUBMIT:
            flag = prompts.one(pending.flag or "", 200)
            self._note(lane, f"The player did not submit {flag}: they think it is not the flag. Keep going.")
        elif pending.kind is PendingKind.LIVE_BOX:
            run = self.runs.get(lane.id)
            if run is not None and run.instance == "asked":
                run.instance = "declined"
                run.toolbox.http_off = "the player said no to the live instance"
            self._note(lane, "The player said no to the live instance: work from the handout only.")
        else:
            self._note(lane, f"The player declined: {prompts.one(pending.detail, 200)}.")

    def rotated(self, lane: Lane, flag: str, every: int) -> None:
        self._note(lane, prompts.rotated_out(flag, every))

    def stop(self, lane: Lane) -> None:
        if self.flaggate is not None:
            self.flaggate.stop(self.deck, lane.id)  # a flag still under check was never submitted: said so
        run = self.runs.get(lane.id)
        if run is None:
            return
        run.stopped = True
        run.wake.set()
        if run.task is not None and not run.task.done() and run.task is not asyncio.current_task():
            run.task.cancel()  # its finally closes the workspace

    def takeover(self, lane: Lane) -> Takeover:
        """The player's shell in the lane's workspace. TakeoverRefused when the lane has none
        now: its workspace is not ready yet, or it has ended."""
        run = self.runs.get(lane.id)
        if run is None or run.closed or run.stopped:
            raise TakeoverRefused(f"{lane.id} has no workspace any more")
        if not run.ready:
            raise TakeoverRefused(f"{lane.id}'s workspace is not ready yet; try again in a moment")
        return Takeover(run, self)

    # ------------------------------------------------------------------ the loop

    async def _loop(self, run: _Run) -> None:
        try:
            self._instance_note(run)
            await self._work(run)
        except asyncio.CancelledError:
            raise
        except WorkspaceError as exc:  # the workspace broke under the lane (container gone, root removed)
            self._report(run, TurnReport(turn=False, action="workspace", output=str(exc), gave_up=f"the workspace failed: {exc}"))
        except Exception as exc:  # a flightdeck bug: end the lane loudly, never let its task die quietly
            self.errors.append(f"{run.lane_id}: {type(exc).__name__}: {exc}")
            self._report(run, TurnReport(turn=False, action="flightdeck error", output=f"{type(exc).__name__}: {exc}",
                                         gave_up=f"flightdeck error: {type(exc).__name__}: {exc}"))
        finally:
            try:
                self._count_cut(run)
            except Exception as exc:  # a flightdeck bug: reported when the console exits; the workspace still closes
                self.errors.append(f"{run.lane_id}: counting what a cut reply cost failed: {type(exc).__name__}: {exc}")
            await self._close(run)

    async def _work(self, run: _Run) -> None:
        try:
            await run.workspace.prepare()
        except (WorkspaceError, OSError) as exc:
            self._report(run, TurnReport(turn=False, action="workspace", output=str(exc), gave_up=f"could not prepare the workspace: {exc}"))
            return
        run.ready = True
        cid = run.challenge.id
        reach = self.urls.get(cid, ()) if self.instance != "off" else ()  # under off, no first look points the lane at one
        run.look = self.looks.start(self.lights, self.deck, run.lane_id, run.challenge, run.workspace,
                                    self.files.get(cid, run.challenge.files), reach)  # never waited for
        await self._plant(run)
        if self.l1 is not None:
            await self._l1_stage(run)
        urls = self.urls.get(run.challenge.id, ())
        if urls and self.instance == "confirm" and not self._over(run):
            run.instance = "asked"
            self._report(run, TurnReport(turn=False, pending=Pending(
                PendingKind.LIVE_BOX, f"let {run.lane_id} reach the live instance: {', '.join(urls)}")))
        while await self._until_running(run):
            if not run.opened:
                self._open(run)
            if run.instance == "allowed":
                await self._open_instance(run, urls)
            lane = self._lane(run)
            assert lane is not None
            hints = list(lane.hints)
            notes, run.notes = run.notes, []
            if hints or notes:  # the player spoke (or flightdeck on their behalf): a reply to it starts the count again
                run.messages.append({"role": "user", "content": self.redact(prompts.player_message(hints, notes))})
                run.idle_turns = 0
            generation, model, messages = run.generation, run.model, run.messages
            try:
                reply = await self.client.chat(
                    model, messages, TOOLS, session_id=run.session, max_tokens=self.max_tokens,
                    before_retry=lambda: self._retry_gate(run, generation),
                )
            except _Overtaken:
                if self._over(run):
                    return
                self._overtaken(run, messages, hints, notes)
                continue
            except ModelError as exc:
                if run.generation != generation:
                    # a call of the old context (escalated) or from before a take-over: its failure
                    # does not end the lane, which goes on with the next call; what it cost counts
                    # (a refusal is paid for: every attempt the refusal fallback made)
                    self._overtaken(run, messages, hints, notes, exc.usage, model, declined=exc.declined)
                    continue
                self._failed(run, exc, model, len(hints))
                return
            run.uncounted = (model, reply.usage)  # until its turn (or its drop) reports what it cost
            self._answered(model)
            if reply.notice:
                self._say(run.lane_id, f"{run.lane_id} {reply.notice}")  # e.g. it moved to the fallback API
            if not await self._until_running(run, generation) and self._over(run):
                return  # killed or finished while the model was thinking
            if run.generation != generation:
                # escalated or taken over while this model was thinking, or while the lane was
                # paused with the reply held: the reply was decided before that. Drop it, but
                # count what it cost.
                self._overtaken(run, messages, hints, notes, reply.usage, model)
                continue
            if await self._turn(run, reply, len(hints), generation, model, messages):
                await self._until_over(run)  # it gave up: no more model calls, though a flag of it may still wait
                return
            if run.messages is messages:  # not escalated during the turn
                self._refresh_if_long(run, reply.usage.prompt_tokens)

    async def _plant(self, run: _Run) -> None:
        """Remember the flag-format matches in the challenge's own text, its description and
        the handout as it came (the workspace before anything ran in it): a decoy flag.txt, an
        example in a readme. A flag the model submits, or an L1 engine gives as its result, that
        is one of them is not claimed, so it waits for the player under auto too, as
        agent/external.py does for its agents. This search is bounded (_own_flags), so what it
        misses is not said: under auto such a flag is looked for in all of that text before it
        goes out (_vet)."""
        found = await asyncio.to_thread(
            _own_flags, run.workspace.root, run.challenge.description, self._flag_re(), time.monotonic() + PLANT_SECONDS
        )
        run.planted = frozenset(found)

    async def _vet(self, run: _Run, flags: Sequence[str]) -> None:
        """Under auto, before a flag the lane gives (the model's submit_flag, an L1 engine's
        result) goes out without the player: look for it in all of the challenge's own text,
        its description and every file of the handout as it came (agent/owntext.py). What was
        found is kept (run.own) for _own_text. Not for a flag that cannot go out anyway (not
        the whole flag format, known not to be the flag) or already known to be the
        challenge's (planted)."""
        if self.deck.config.submit != "auto":
            return
        for flag in dict.fromkeys(flags):
            if flag in run.own or flag in run.planted or not self._flag_re().fullmatch(flag):
                continue
            if self.deck.not_flag(run.challenge.id, flag) is not None:
                continue
            handout = getattr(run.workspace, "handout", None)
            run.own[flag] = await owntext.look_for(run.challenge.description, handout, flag)

    def _own_text(self, run: _Run, flag: str) -> str:
        """Why a flag the lane gives waits for the player, as the challenge's own text holds it
        or may (planted; _vet's search: owntext.Found.says); "" when nothing says so. Under auto
        a flag _vet never looked for waits too (a flightdeck bug, never a submit)."""
        if flag in run.planted:
            return owntext.OWN_TEXT
        if (self.deck.config.submit != "auto" or not self._flag_re().fullmatch(flag)
                or self.deck.not_flag(run.challenge.id, flag) is not None):
            return ""
        found = run.own.get(flag)
        return owntext.UNSEARCHED if found is None else found.says()

    async def _l1_stage(self, run: _Run) -> None:
        """Run the engines routed to the challenge (agent/l1stage.py). A flag one found is the
        lane's candidate (claimed, unless the runner found it in what a text engine printed, or
        the challenge's own text holds it or may: _own_text, as for the model's submit_flag, and
        the lane says why); what they all found goes in the lane's context. In Docker an engine is
        online only when the lane may reach the challenge's instance at once (instance auto): it
        runs before the confirm policy's question, so it must never need the answer."""
        assert self.l1 is not None
        # the stage itself is l1stage.run_stage, which a coding-agent lane runs too (agent/external.py)
        text = await run_stage(self.l1, self.deck, StageLane(
            lane_id=run.lane_id,
            challenge=run.challenge,
            online=bool(self.urls.get(run.challenge.id)) and self.instance == "auto",
            over=lambda: self._over(run),
            note=lambda said: self._say(run.lane_id, said),
            error=self.errors.append,
            vet=lambda flags: self._vet(run, flags),
            own_text=lambda flag: self._own_text(run, flag),
            report=lambda rep: self._report(run, rep),
            redact=self.redact,
        ))
        if text is not None:
            run.l1_message = {"role": "user", "content": text}
            run.messages.append(dict(run.l1_message))

    async def _open_instance(self, run: _Run, urls: Sequence[str]) -> None:
        """The player allowed the live instance: give a docker lane's container (it started with
        no network) a network that reaches the instance and nothing else
        (DockerWorkspace.open_instance), and let the http tool reach the instance."""
        connect = getattr(run.workspace, "open_instance", None)
        try:
            if connect is not None:
                await connect()
        except WorkspaceError as exc:
            run.instance = "failed"
            self._say(run.lane_id, f"could not open the network to the live instance: {exc}")
            run.notes.append(f"flightdeck could not open the network to the live instance ({exc}): work from the handout.")
            return
        if web_origins(urls):
            run.toolbox.allow(web_origins(urls))  # a TCP service is the shell's, through the network just opened
        else:
            run.toolbox.http_off = f"this challenge's instance is not a web server ({', '.join(urls)}): reach it from the shell"
        run.instance = "open"

    async def _until_running(self, run: _Run, generation: int | None = None) -> bool:
        """Wait while the lane is paused, taken over or waiting for the player. False once it
        has finished or was stopped, or, given a generation, once that generation is past."""
        while not run.stopped:
            if generation is not None and run.generation != generation:
                return False
            lane = self._lane(run)
            if lane is None or lane.finished:
                return False
            if lane.state is LaneState.RUNNING:
                return True
            run.wake.clear()
            await run.wake.wait()
        return False

    async def _retry_gate(self, run: _Run, generation: int) -> None:
        """Before the client tries a failed call again: hold it while the lane is paused,
        and stop it once the lane has ended or the call no longer counts."""
        if not await self._until_running(run, generation):
            raise _Overtaken()

    def _failed(self, run: _Run, error: ModelError, model: str, hints_taken: int) -> None:
        """The model call failed for good: the lane ends with the reason. A model that declined
        (a refusal) is not an API error, and its call was paid for: its tokens count.

        A failure every lane would get alike (a refused key, an unknown model, an API that does
        not answer: _every_lane) first holds the deck's queue, saying why and what to check,
        so the next challenges stay queued instead of each starting a lane that fails the same
        way. The lanes already running end as this one does when they hit it.

        A failure that may pass (a rate limit, a 5xx, an overload) ends only its own lane, until
        lanes keep ending on it with no reply from the API in between (_outage): then the
        queue is held too, and the challenges those lanes park go back on it when the player
        lifts the hold."""
        check = self._every_lane(error, model)
        if check:
            # a failure that may pass, before the model ever answered: its challenge is queued again with the outage's
            ended = [run.lane_id] if not error.declined and _may_pass(error.status) else []
            self.deck.hold_queue(f"{run.lane_id}'s call to {model} failed in a way every lane would ({check}): {error}", ended=ended)
        else:
            ended = self._outage(run, error)
            if ended:
                self.deck.hold_queue(
                    f"the model API keeps failing: {len(ended)} lanes in a row ended on it ({', '.join(ended)}) with no reply "
                    f"in between. Lift the hold once it answers again: the challenges they parked are queued again. "
                    f"{run.lane_id}'s call to {model}: {error}",
                    ended=ended,
                )
        usage = error.usage
        self._apart(run, model, usage)  # before the lane ends: then nothing more is reported
        tokens = usage.total if usage else 0
        cached = usage.cached_tokens if usage else 0
        dollars = self._priced(usage.model or model, usage) if usage is not None else 0.0
        if error.declined:
            action, gave_up = f"{model} declined", str(error)
        else:
            action, gave_up = f"model call to {model} failed", f"model API error: {error}"
        self._report(run, TurnReport(turn=False, action=action, output=str(error), tokens=tokens, cached_tokens=cached,
                                     dollars=dollars, hints_taken=hints_taken, gave_up=gave_up,
                                     declined=error.declined,
                                     model=(usage.model or None) if usage else None))

    def _every_lane(self, error: ModelError, model: str) -> str:
        """What the player should check when every lane would fail as this call did, else "".

        That is: no answer at all (nothing listens at base_url, or it never answers in time);
        a status that is about the key, the account, the model id or the URL (EVERY_LANE); or
        any failure before any lane has had an answer from this model in this run (an unknown
        model id is a 400 on some APIs). A model that declined answered, and a failure once
        the model has answered may be this lane's own (its context too long) or may pass (a
        rate limit, an overload): those end only this lane."""
        if error.declined:
            return ""
        if error.status is None:
            return "the model API does not answer: is it running, and is base_url right?"
        if error.status in EVERY_LANE:
            return EVERY_LANE[error.status]
        if model not in self.answered:
            return f"no lane has had an answer from {model} yet: check the model id and base_url"
        return ""

    def _outage(self, run: _Run, error: ModelError) -> list[str]:
        """Count a failure that ended this lane for good and may pass (_may_pass: a rate limit,
        a 5xx, Anthropic's 529), and return the lanes of the outage it belongs to once it
        looks like one, else []. An outage is OUTAGE_LANES lanes or more ending that way in
        a row: no reply from the model API in between (_answered clears the count), and each
        within OUTAGE_SECONDS of the one before. Only failures that reach _failed count: not a
        superseded call's (_overtaken), nor one a [fallback] API took over. Lanes share one
        model API (the driver's client), so the count is the run's.

        While the hold it led to stands, each further lane ending this way is of the same
        outage. Once the player has lifted that hold, the count starts again."""
        if error.declined or not _may_pass(error.status):
            return []
        now = self.deck.now
        lifted = len(self.outage) >= OUTAGE_LANES and not self.deck.held  # we held the queue, and the player lifted it
        if lifted or (self.outage and now - self.outage[-1][1] > OUTAGE_SECONDS):
            self.outage.clear()
        self.outage.append((run.lane_id, now))
        return [lane_id for lane_id, _ in self.outage] if len(self.outage) >= OUTAGE_LANES else []

    def _answered(self, model: str) -> None:
        """The model API answered a lane's call: `model` is known to answer in this run, and
        whatever failures came before were not an outage that still lasts."""
        self.answered.add(model)
        self.outage.clear()

    def _overtaken(self, run: _Run, messages: list[dict], hints: list[str], notes: list[str],
                   usage: Usage | None = None, model: str = "", *, declined: bool = False) -> None:
        """A call to `model` that no longer counts: its reply, or its refusal (`declined`),
        came after the lane was escalated or taken over. Its cost does (`usage`: what the
        call used, every attempt of it). After a take-over the context is the same, and it
        holds the call's hints and notes; after an escalation the new context has had
        neither, so they go again."""
        same = run.messages is messages
        if not same:
            run.notes[:0] = notes
        run.uncounted = None  # reported here
        dropped = "a refusal" if declined else "a reply"
        why = f"{dropped} dropped: the lane was escalated or taken over while the model answered"
        self._apart(run, model, usage, why)
        self._report(
            run,
            TurnReport(
                turn=False,
                tokens=usage.total if usage else 0,
                cached_tokens=usage.cached_tokens if usage else 0,
                dollars=self._priced(usage.model or model, usage) if usage is not None else 0.0,
                hints_taken=len(hints) if same else 0,
                why=why,
                model=(usage.model if usage else "") or model or None,
            ),
        )

    async def _turn(self, run: _Run, reply: Reply, hints_taken: int, generation: int, model: str,
                    messages: list[dict]) -> bool:
        """Run the reply's tool calls and report the turn. True when the lane gave up with it."""
        lane = self._lane(run)
        assert lane is not None
        turn = lane.turns + 1
        root = run.workspace.root
        results: list[ToolResult] = []
        run.idle.clear()
        try:
            before = await asyncio.to_thread(take_snapshot, root)
            for index, call in enumerate(reply.tool_calls):
                if not await self._until_running(run, generation):  # paused: wait; escalated or taken over: stop
                    if self._over(run):
                        return False
                    break
                results.append(await run.toolbox.call(call.name, call.arguments, turn=turn, index=index))
            after = await asyncio.to_thread(take_snapshot, root)
            changes = await asyncio.to_thread(changed_files, before, after, root)
        finally:
            run.idle.set()
        if self._over(run):
            return False
        await self._vet(run, [r.flag for r in results if r.flag])  # under auto: before a flag it submitted may go out
        if self._over(run):
            return False
        same = run.messages is messages  # else escalated during the turn: none of it goes into the new context
        notes: list[str] = []
        files = tuple(changes[:MAX_FILES_PER_TURN])
        if len(changes) > MAX_FILES_PER_TURN:
            notes.append(f"That turn changed {len(changes)} files; the console lists the first {MAX_FILES_PER_TURN}.")
        for result in results:  # what the lane saw: where a flag it submits later was found (agent/flaggate.py)
            if not (result.flag or result.plan):
                run.outputs.add(result.action, result.content)
        flags = [r.flag for r in results if r.flag]
        plans = [r.plan for r in results if r.plan]
        # the challenge hands these out (or may: _own_text): often decoys, so the player decides
        reasons = {flag: self._own_text(run, flag) for flag in dict.fromkeys(flags)}
        own = {flag: reason for flag, reason in reasons.items() if reason}
        # said to the model and the player, but not of one known not to be the flag already (declined, rejected): the
        # deck tells the model that instead
        told = {flag: why for flag, why in own.items() if self.deck.not_flag(run.challenge.id, flag) is None}
        for flag in flags:
            if not self._flag_re().fullmatch(flag):  # the format is the board's: it stays in the brief's fence, never here
                notes.append(f"{prompts.one(flag, 200)} does not match the flag format in the challenge brief; it was not submitted.")
            elif flag in told:
                notes.append(_waits(flag, told[flag]))
        skipped = len(reply.tool_calls) - len(results)
        said: list[str] = []  # flags the model wrote in a reply with no tool call: candidates it did not submit
        idle = False  # the last of MAX_IDLE_TURNS replies in a row that did nothing: the lane gives up
        if same and run.generation == generation:
            if reply.tool_calls:
                run.idle_turns = 0
            else:
                said = self._flags_said(run, reply.content)
                run.idle_turns = 0 if said else run.idle_turns + 1
                idle = run.idle_turns >= MAX_IDLE_TURNS
        if same:
            messages.append(reply.message)
            for call, result in zip(reply.tool_calls, results):
                messages.append({"role": "tool", "tool_call_id": call.id, "content": result.content})
            for call in reply.tool_calls[len(results):]:
                messages.append({"role": "tool", "tool_call_id": call.id, "content": NOT_RUN})
            if not reply.tool_calls and run.generation == generation and not idle:
                messages.append({"role": "user", "content": prompts.NUDGE})
            run.notes.extend(notes)
        action, output = _step(results, reply)
        if skipped:
            why = "taken over" if same else "escalated"
            action = (f"{action}  " if results else "") + f"({skipped} tool call{'s' if skipped > 1 else ''} not run: {why})"
        checked, again = self._checked_first(run, flags)
        raised = [flag for flag in flags if flag not in checked and flag not in again]  # the deck has these now
        usage = reply.usage
        run.uncounted = None  # reported here
        self._apart(run, model, usage)
        self._report(
            run,
            TurnReport(
                action=action,
                output=output,
                calls=tuple(Call(result.action, result.excerpt) for result in results),  # all of them, for the transcript
                tokens=usage.total,
                cached_tokens=usage.cached_tokens,
                dollars=self._dollars(model, reply),
                plan=plans[-1] if plans else None,
                files=files,
                flag=raised[0] if raised else None,
                claimed=not raised or raised[0] not in own,
                hints_taken=hints_taken if same else 0,
                model=usage.model or model,  # the refusal fallback's model, when it took the turn
            ),
        )
        for flag in raised[1:]:  # more candidates in one reply: each is its own approval
            self._report(run, TurnReport(turn=False, flag=flag, claimed=flag not in own))
        for flag, why in told.items():
            self._say(run.lane_id, f"{flag} {why}, so it waits for you, though the lane submitted it")
        for flag in again:
            self._say(run.lane_id, f"candidate {flag} again; not raised: the light model is still checking it")
        for flag in said:  # never submitted on its own: the model may be quoting a decoy it read
            if self.flaggate is None or not self.flaggate.under_check(run.lane_id, flag):  # else the check has it
                self._report(run, TurnReport(turn=False, flag=flag, claimed=False))
        for flag in checked:  # each reaches the deck once the light model has answered; the lane goes on
            assert self.flaggate is not None
            self.flaggate.start(self.deck, run.lane_id, run.challenge, flag, run.outputs.where(flag, SUBMITTED_ONLY),
                                lambda rep, run=run: self._report(run, rep))
        if idle:
            run.idle_turns = 0
            last = prompts.one(reply.content, 200) if reply.content.strip() else "(nothing)"
            self._report(run, TurnReport(
                turn=False, gave_up=f"the model answered {MAX_IDLE_TURNS} times in a row without calling a tool; it last said: {last}",
            ))
        return idle

    async def _until_over(self, run: _Run) -> None:
        """After the lane gave up: call the model no more, and wait until the deck ends the lane.
        It does at once, or once no flag of the lane waits any more, for the player or for the
        platform's answer; while its flag is with the platform the lane stays RUNNING, so the
        loop must not go on."""
        while not self._over(run):
            run.wake.clear()
            await run.wake.wait()

    def _checked_first(self, run: _Run, flags: Sequence[str]) -> tuple[list[str], list[str]]:
        """Of a turn's submitted flags, each once: those the light model checks before they go
        to the deck (agent/flaggate.py: not the challenge's own text, nor maybe so (_own_text),
        and going out without the player now), and those it is checking already (submitted
        again: raised once)."""
        gate = self.flaggate
        checked: list[str] = []
        again: list[str] = []
        if gate is None:
            return checked, again
        for flag in dict.fromkeys(flags):
            if gate.under_check(run.lane_id, flag):
                again.append(flag)
            elif not self._own_text(run, flag) and gate.covers(self.deck, run.lane_id, flag):
                checked.append(flag)
        return checked, again

    def _flags_said(self, run: _Run, text: str) -> list[str]:
        """Matches of the flag format in what the model wrote, new to this lane, at most
        MAX_SAID_FLAGS of them (a model that lists made-up flags asks the player a few times,
        not a hundred)."""
        found: list[str] = []
        for match in self._flag_re().finditer(text[:SAID_SCAN]):
            flag = match.group(0)
            if flag and flag not in run.said and flag not in found:
                found.append(flag)
                if len(found) == MAX_SAID_FLAGS:
                    break
        run.said.update(found)
        return found

    def _refresh_if_long(self, run: _Run, prompt_tokens: int) -> None:
        """Past compact_at prompt tokens, continue in a fresh context: the same prefix and
        brief (so the API's cache still hits) plus a summary, instead of the whole history."""
        lane = self._lane(run)
        if self.compact_at is None or prompt_tokens < self.compact_at or lane is None or lane.finished:
            return
        summary = lane_summary(self.deck, lane)
        run.messages = self._fresh(run, lane.approach) + [{"role": "user", "content": self.redact(prompts.refresh(summary, prompt_tokens))}]
        self._say(lane.id, f"context refreshed at {prompt_tokens:,} prompt tokens (a summary replaces the history)")

    # ------------------------------------------------------------------ helpers

    def _open(self, run: _Run) -> None:
        """Just before the lane's first model call: its brief takes the first look as far as it
        is back (agent/facts.py), and from now on nothing more goes into it. The context's
        brief (always its second message: the lane's first context, or an escalation's made
        before the call) is made again with it; a later one repeats it (_fresh). What other
        lanes on its challenge tried, and its series (agent/sharing.py), is made now too, as
        things stand, and goes after the brief in this context and every later one."""
        run.opened = True
        lane = self._lane(run)
        look, run.look = run.look, None
        if look is not None:
            run.recon = self.redact(self.looks.opening(look, self.deck, run.lane_id, self._flag_re()))
            if run.recon and len(run.messages) > 1:
                run.messages[1] = self._fresh(run, lane.approach if lane is not None else "")[1]
        handed = self.redact(sharing.opening(self.deck, lane, run.shares)) if lane is not None else ""
        if handed:  # what other lanes tried, and its series: right after the brief, as _fresh puts it
            run.handover = {"role": "user", "content": handed}
            if len(run.messages) > 1:
                run.messages.insert(2, dict(run.handover))

    def _fresh(self, run: _Run, approach: str) -> list[dict]:
        """A new context: the system prompt, the brief (with the first look the lane took at its
        first model call, if any: the same text every time, so the cached prefix holds), and
        what the L1 engines found (once they have run: an escalation or a refresh keeps it, so
        the model never pays to redo what they did or ruled out), after what the lane was
        handed of other lanes' work at its first model call (run.handover), if anything.
        `approach` is the player's own direction (lane.approach), never the model's plan."""
        challenge = run.challenge
        messages = [
            {"role": "system", "content": prompts.system_prompt()},
            {
                "role": "user",
                "content": prompts.brief(challenge, self.files.get(challenge.id, challenge.files), self.urls.get(challenge.id, ()),
                                         approach, flag_format=self.deck.config.flag_format, recon=run.recon,
                                         instance=self.instance, shell_hosts=getattr(run.workspace, "shell_hosts", None),
                                         toolkit=self.l1.toolkit if self.l1 is not None else ""),
            },
        ]
        if run.handover is not None:
            messages.append(dict(run.handover))
        if run.l1_message is not None:
            messages.append(dict(run.l1_message))
        return messages

    def _dollars(self, model: str, reply: Reply) -> float | None:
        """What the reply's own part of a call to `model` cost (its other parts: _apart)."""
        return self._priced(reply.usage.model or model, reply.usage)

    def _priced(self, model: str, usage: Usage) -> float | None:
        """What `usage` cost, `model` having run it: the API's figure (or a fast call's), else at
        the config's price for `model`, else None (not known)."""
        return call_cost(usage.cost, self.prices.get(model), usage.prompt_tokens, usage.completion_tokens,
                         usage.cached_tokens, usage.cache_write_tokens)

    def _apart(self, run: _Run, model: str, usage: Usage | None, why: str = "") -> None:
        """The parts of a call to `model` that ran on other models than its last attempt (Usage:
        Anthropic's refusal fallback reports each attempt), each reported as spend of the model
        that ran it, at that model's price, or not known when the config has none: every attempt
        counts on the lane, and the post-flight puts it in that model's row. Each is an attempt
        that declined, and the fallback ran the call on the next model."""
        if usage is None:
            return
        last = usage.model or model
        for part in usage.more:
            ran = part.model or model
            said = f"{ran} declined, so Anthropic's refusal fallback ran the call on {last}"
            self._report(run, TurnReport(turn=False, tokens=part.total, cached_tokens=part.cached_tokens,
                                         dollars=self._priced(ran, part), why=f"{said}; {why}" if why else said,
                                         model=ran))

    def _session(self, lane_id: str, escalations: int) -> str:
        session = f"flightdeck-{self.run_id}-{lane_id}" + (f"-e{escalations}" if escalations else "")
        return session[:MAX_SESSION]

    def _flag_re(self) -> re.Pattern[str]:
        return re.compile(self.deck.config.flag_format)

    def _root_of(self, lane_id: str) -> Path | None:
        """The folder of that lane's workspace on this machine, when this driver ran it."""
        run = self.runs.get(lane_id)
        return Path(run.workspace.root) if run is not None else None

    def _lane(self, run: _Run) -> Lane | None:
        return self.deck.lanes.get(run.lane_id)

    def _over(self, run: _Run) -> bool:
        lane = self._lane(run)
        return run.stopped or lane is None or lane.finished

    def _count_cut(self, run: _Run) -> None:
        """The cost of a reply the lane's stop cut short (a kill, a solve, quitting), the reply
        having come while the lane was paused or while its tool calls ran: its call was paid
        for, so what it cost is reported as spend, every attempt of it (_apart), which the deck
        counts on the lane and the run after the lane's end and once the run is closing. A
        call still under way when the lane stops is cancelled with the lane's task: no reply
        comes, and nothing says what it used."""
        if run.uncounted is None:
            return
        model, usage = run.uncounted
        run.uncounted = None
        why = "a reply cut short: the lane stopped before its turn was done"
        self._apart(run, model, usage, why)
        self._report(run, TurnReport(turn=False, tokens=usage.total, cached_tokens=usage.cached_tokens,
                                     dollars=self._priced(usage.model or model, usage), why=why,
                                     model=usage.model or model))

    def _report(self, run: _Run, report: TurnReport) -> None:
        lane = self._lane(run)
        if lane is None:
            return
        report = self.redact.scrub(report)  # the one way to the deck: no secret the run holds goes by value (never the flag)
        if lane.finished or run.stopped:
            if spend_only(report):  # what was spent counts after the lane's end too (Deck.report): _count_cut
                self.deck.report(run.lane_id, report)
            return
        if self.flaggate is not None:  # giving up while a flag is under check: it ends once the check is in
            report = self.flaggate.defer_gave_up(run.lane_id, report)
            if report is None:
                return
        self.deck.report(run.lane_id, report)

    def _say(self, lane_id: str, text: str) -> None:
        """A note of the driver's on a lane, the run's secrets out of it (it may quote what a
        lane's engine or its model's API wrote)."""
        self.deck.note(lane_id, self.redact(text))

    def _note(self, lane: Lane, text: str) -> None:
        run = self.runs.get(lane.id)
        if run is not None:
            run.notes.append(text)
            run.wake.set()

    def _wake(self, lane: Lane) -> None:
        run = self.runs.get(lane.id)
        if run is not None:
            run.wake.set()

    def _instance_note(self, run: _Run) -> None:
        """The instance rule, at the lane's start: a TCP service the description names that the
        board does not list for the challenge is said to the player (instance_note), unless the
        event keeps lanes off every instance (instance off). Nothing changes for the lane: its
        network, its http tool and the challenge's instances stay as the board has them."""
        if self.instance == "off":
            return
        services = unlisted_services(run.challenge.description, self.urls.get(run.challenge.id, ()))
        if services:
            self._say(run.lane_id, instance_note(services, run.workspace))

    async def _close(self, run: _Run) -> None:
        """Close the lane's workspace once. The close runs shielded: cancelling the lane's
        task again (shutdown does) cannot cut `docker rm` short."""
        if run.closing is None:
            run.closed = True
            run.closing = asyncio.ensure_future(self._close_workspace(run))
        await asyncio.shield(run.closing)

    async def _close_workspace(self, run: _Run) -> None:
        try:
            await run.workspace.close()
        except Exception as exc:  # reported when the console exits; a lane's end is not held up
            self.errors.append(f"{run.lane_id}: closing its workspace failed: {exc}")

    # ------------------------------------------------------------------ shutdown

    async def shutdown(self) -> None:
        """Stop every lane and close every workspace (the console calls this before it exits);
        a first look still under way first. The flag checks stop once every lane has (so no lane
        asks for one after), before the run closes the light model, which it does after this."""
        await self.looks.aclose()
        tasks = []
        for run in self.runs.values():
            run.stopped = True
            run.wake.set()
            if run.task is not None and not run.task.done():
                if run.closing is None:  # still working: cancel it (its finally closes the workspace)
                    run.task.cancel()
                tasks.append(run.task)
        if self.flaggate is not None:
            self.errors += await self.flaggate.aclose()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        for run in self.runs.values():
            await self._close(run)


def _own_flags(root: Path, description: str, pattern: re.Pattern[str], deadline: float) -> set[str]:
    """The flag-format matches in a challenge's own text: its description, and every file of
    the workspace (the handout, before anything ran in it), a text file as the snapshot keeps
    it and any other read from root, at most PLANT_FILE_BYTES of each and PLANT_BYTES in all,
    as Latin-1 (a flag in a binary's strings shows), as far as the search got by `deadline`.
    Bounded, so it may miss one (past those limits, past the snapshot's, a file it could not
    read): a flag a lane gives is looked for in all of that text before it goes out on its
    own (AgentDriver._vet). In a thread: it can take a while."""
    found: dict[str, None] = {}
    if not scan(description, pattern, deadline, found):
        return set(found)
    snapshot = take_snapshot(root)
    budget = PLANT_BYTES
    for path, (size, _, _) in snapshot.files.items():
        text = snapshot.texts.get(path)
        if text is None:
            if budget <= 0:
                continue
            try:
                fd = open_inside(root, path.split("/"))
                with os.fdopen(fd, "rb") as file:
                    data = file.read(min(size, PLANT_FILE_BYTES, budget))
            except OSError:  # gone or unreadable
                continue
            budget -= len(data)
            text = data.decode("latin-1")
        if not scan(text, pattern, deadline, found):
            break
    return set(found)


def _waits(flag: str, why: str) -> str:
    """What the model hears of a flag it submitted that the challenge's own text holds, or may
    (_own_text, `why`): that it waits, never the names of the handout's files the search met
    (they are the challenge's, and the player has them)."""
    shown = prompts.one(flag, 200)
    if why == owntext.OWN_TEXT:
        return (f"{shown} {owntext.OWN_TEXT}, so it is not submitted on its own: it waits for the player. A flag a "
                "challenge hands out is often a decoy; keep going until you hear it was correct.")
    return (f"flightdeck could not make sure that {shown} is not written in the challenge's own text, so it is not "
            "submitted on its own: it waits for the player. Keep going until you hear it was correct.")


def _step(results: list[ToolResult], reply: Reply) -> tuple[str, str]:
    """The turn as one step for the console: the first real action (not a plan or a
    submission), else the first result, else what the model said."""
    if results:
        shown = next((r for r in results if not (r.flag or r.plan)), results[0])
        action = shown.action + (f"  (+{len(results) - 1} more)" if len(results) > 1 else "")
        return action, shown.output
    if reply.tool_calls:
        return "", ""
    said = reply.content.strip().splitlines()[0] if reply.content.strip() else "(an empty reply)"
    return f"says: {said[:200]}", ""
