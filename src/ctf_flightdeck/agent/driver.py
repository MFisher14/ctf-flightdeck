"""The agent driver: every lane is an agent loop against a model API (M1, D5a).

One asyncio task per lane, on the console's event loop, so every Deck call happens on the
deck's thread (the LaneDriver contract in core/driver.py). A turn is one model call: the
reply's tool calls run in the lane's workspace, their results go back into the lane's
context, and the turn is reported to the deck (tokens, cost, the step, changed files, a
candidate flag). The deck applies the rules (approvals, caps, the flag format); the loop
calls the model, and runs a tool call, only while the lane is RUNNING, and waits otherwise.

Each lane starts with a fresh context: the fixed system prompt, then the challenge brief (and,
once its L1 engines have run, what they found). Escalation starts a fresh context too, on the
stronger model, with the deck's summary; so does the refresh of a context grown too long.

A lane gives up after MAX_IDLE_TURNS replies in a row without a tool call. A model call that
fails in a way every lane would (no answer, a refused key, an unknown model) holds the deck's
queue before the lane ends, so the next challenges are not started only to fail the same way.

Escalation and take-over are turn boundaries. Each bumps the lane's generation, and a reply
asked for in an older generation runs no further tool call. After an escalation none of
it goes into the new context (it belongs to the old one). After a take-over the calls it
had not run yet are answered "not run", and the next call tells the model what the player
did. A reply that arrives after either is dropped (its cost still counts).
"""

from __future__ import annotations

import asyncio
import os
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace

from ..core.driver import TakeoverRefused, TurnReport
from ..core.model import Challenge, EscalationSummary, Lane, LaneState, Pending, PendingKind
from ..core.summary import lane_summary
from ..pricing import Price, call_cost
from ..text import untrusted
from . import prompts
from .client import ChatClient, ModelError, Reply
from .l1stage import FLAG_STATUSES, L1Stage, result_line
from .tools import TOOLS, Toolbox, ToolResult
from .workspace import (
    PRIVATE,
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
MAX_IDLE_TURNS = 3  # replies in a row without a tool call before the lane gives up (as agent/external.py's lanes do)
MAX_SAID_FLAGS = 3  # candidates taken from one reply's text, at most
SAID_SCAN = 20_000  # characters of a reply's text searched for flags
EVERY_LANE = {  # HTTP statuses of a model API that every lane would get alike, and what the player should check
    401: "check the API key",
    402: "check the account's credits",
    403: "check that the key may use this model",
    404: "check the model id in the [models] ladder, and base_url",
    405: "check base_url",
}


def web_origins(urls: Sequence[str]) -> tuple[str, ...]:
    """The http(s) origins among a challenge's instances: the http tool's. A TCP service
    (tcp://host:port, what `nc host port` reaches) is the shell's."""
    return tuple(url for url in urls if url.startswith(("http://", "https://")))


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
    ) -> None:
        self.client = client
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
        self.runs: dict[str, _Run] = {}
        self.errors: list[str] = []  # cleanup problems, shown when the console exits
        self.answered: set[str] = set()  # the models that have answered a lane in this run
        self.deck = None

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
            toolbox = Toolbox(workspace, http_off="the player has not allowed the live instance yet")
        elif urls and self.instance == "off":
            toolbox = Toolbox(workspace, http_off="the event's rules keep lanes off the live instance")
        elif urls and not web_origins(urls):  # a TCP service (`nc host port`): the shell reaches it, not http
            toolbox = Toolbox(workspace, http_off=f"this challenge's instance is not a web server ({', '.join(urls)}): "
                                                  "reach it from the shell, for example with nc")
        else:
            toolbox = Toolbox(workspace, http_allow=web_origins(urls))
        run = _Run(
            lane_id=lane.id,
            challenge=challenge,
            workspace=workspace,
            toolbox=toolbox,
            model=lane.model,
            session=self._session(lane.id, 0),
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
        run.messages = self._fresh(run, lane.approach) + [{"role": "user", "content": prompts.escalation(text)}]
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

    def stop(self, lane: Lane) -> None:
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
            await self._close(run)

    async def _work(self, run: _Run) -> None:
        try:
            await run.workspace.prepare()
        except (WorkspaceError, OSError) as exc:
            self._report(run, TurnReport(turn=False, action="workspace", output=str(exc), gave_up=f"could not prepare the workspace: {exc}"))
            return
        run.ready = True
        if self.l1 is not None:
            await self._l1_stage(run)
        urls = self.urls.get(run.challenge.id, ())
        if urls and self.instance == "confirm" and not self._over(run):
            run.instance = "asked"
            self._report(run, TurnReport(turn=False, pending=Pending(
                PendingKind.LIVE_BOX, f"let {run.lane_id} reach the live instance: {', '.join(urls)}")))
        while await self._until_running(run):
            if run.instance == "allowed":
                await self._open_instance(run, urls)
            lane = self._lane(run)
            assert lane is not None
            hints = list(lane.hints)
            notes, run.notes = run.notes, []
            if hints or notes:  # the player spoke (or flightdeck on their behalf): a reply to it starts the count again
                run.messages.append({"role": "user", "content": prompts.player_message(hints, notes)})
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
                    # does not end the lane, which goes on with the next call
                    self._overtaken(run, messages, hints, notes)
                    continue
                self._failed(run, exc, model, len(hints))
                return
            self.answered.add(model)
            if reply.notice:
                self.deck.note(run.lane_id, f"{run.lane_id} {reply.notice}")  # e.g. it moved to the fallback API
            if not await self._until_running(run, generation) and self._over(run):
                return  # killed or finished while the model was thinking
            if run.generation != generation:
                # escalated or taken over while this model was thinking, or while the lane was
                # paused with the reply held: the reply was decided before that. Drop it, but
                # count what it cost.
                self._overtaken(run, messages, hints, notes, reply, model)
                continue
            await self._turn(run, reply, len(hints), generation, model, messages)
            if run.messages is messages:  # not escalated during the turn
                self._refresh_if_long(run, reply.usage.prompt_tokens)

    async def _l1_stage(self, run: _Run) -> None:
        """Run the engines routed to the challenge (agent/l1stage.py). A flag one found is the
        lane's candidate (claimed, unless the runner found it in what a text engine printed);
        what they all found goes in the lane's context. In Docker an engine is online only
        when the lane may reach the challenge's instance at once (instance auto): it runs
        before the confirm policy's question, so it must never need the answer."""
        assert self.l1 is not None
        online = bool(self.urls.get(run.challenge.id)) and self.instance == "auto"
        try:
            runs = await self.l1.run(run.lane_id, run.challenge, online=online)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # a broken pack or an L1 bug: the lane goes on without L1, loudly
            self.errors.append(f"{run.lane_id}: L1 did not run: {type(exc).__name__}: {exc}")
            self.deck.note(run.lane_id, f"L1 did not run: {type(exc).__name__}: {exc}")
            return
        if self._over(run):
            return
        if not runs:
            self.deck.note(run.lane_id, "L1: no engine in the pack routes to this challenge")
            return
        for engine in runs:
            res = engine.result
            self.deck.record_l1(run.challenge.id, engine.manifest.id, res.status, flags=res.flags,
                                seconds=engine.seconds, notes=res.notes, lane_id=run.lane_id)
        for engine in runs:
            if engine.result.status in FLAG_STATUSES:
                for flag in engine.result.flags:
                    # a match in what a text engine printed may be the challenge's decoy: it waits for the player
                    self._report(run, TurnReport(turn=False, flag=flag, claimed=not engine.scraped))
        if not self._over(run):
            run.l1_message = {"role": "user", "content": prompts.l1_results([result_line(e) for e in runs])}
            run.messages.append(dict(run.l1_message))

    async def _open_instance(self, run: _Run, urls: Sequence[str]) -> None:
        """The player allowed the live instance: connect a docker lane's container to the
        network (it started with none) and let the http tool reach the instance."""
        connect = getattr(run.workspace, "connect_network", None)
        try:
            if connect is not None:
                await connect("bridge")
        except WorkspaceError as exc:
            run.instance = "failed"
            self.deck.note(run.lane_id, f"could not open the network to the live instance: {exc}")
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
        way. The lanes already running end as this one does when they hit it."""
        check = self._every_lane(error, model)
        if check:
            self.deck.hold_queue(f"{run.lane_id}'s call to {model} failed in a way every lane would ({check}): {error}")
        usage = error.usage
        tokens = usage.total if usage else 0
        cached = usage.cached_tokens if usage else 0
        dollars = 0.0
        if usage is not None:
            dollars = call_cost(usage.cost, self.prices.get(model), usage.prompt_tokens, usage.completion_tokens,
                                usage.cached_tokens)
        if error.declined:
            action, gave_up = f"{model} declined", str(error)
        else:
            action, gave_up = f"model call to {model} failed", f"model API error: {error}"
        self._report(run, TurnReport(turn=False, action=action, output=str(error), tokens=tokens, cached_tokens=cached,
                                     dollars=dollars, hints_taken=hints_taken, gave_up=gave_up))

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

    def _overtaken(self, run: _Run, messages: list[dict], hints: list[str], notes: list[str],
                   reply: Reply | None = None, model: str = "") -> None:
        """A call that no longer counts. Its cost does. After a take-over the context is the
        same, and it holds the call's hints and notes; after an escalation the new context
        has had neither, so they go again."""
        same = run.messages is messages
        if not same:
            run.notes[:0] = notes
        usage = reply.usage if reply is not None else None
        self._report(
            run,
            TurnReport(
                turn=False,
                tokens=usage.total if usage else 0,
                cached_tokens=usage.cached_tokens if usage else 0,
                dollars=self._dollars(model, reply) if reply is not None else 0.0,
                hints_taken=len(hints) if same else 0,
                why="a reply dropped: the lane was escalated or taken over while the model answered",
                model=model or None,
            ),
        )

    async def _turn(self, run: _Run, reply: Reply, hints_taken: int, generation: int, model: str,
                    messages: list[dict]) -> None:
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
                        return
                    break
                results.append(await run.toolbox.call(call.name, call.arguments, turn=turn, index=index))
            after = await asyncio.to_thread(take_snapshot, root)
            changes = await asyncio.to_thread(changed_files, before, after, root)
        finally:
            run.idle.set()
        if self._over(run):
            return
        same = run.messages is messages  # else escalated during the turn: none of it goes into the new context
        notes: list[str] = []
        files = tuple(changes[:MAX_FILES_PER_TURN])
        if len(changes) > MAX_FILES_PER_TURN:
            notes.append(f"That turn changed {len(changes)} files; the console lists the first {MAX_FILES_PER_TURN}.")
        flags = [r.flag for r in results if r.flag]
        plans = [r.plan for r in results if r.plan]
        for flag in flags:
            if not self._flag_re().fullmatch(flag):  # the format is the board's: it stays in the brief's fence, never here
                notes.append(f"{prompts.one(flag, 200)} does not match the flag format in the challenge brief; it was not submitted.")
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
        usage = reply.usage
        self._report(
            run,
            TurnReport(
                action=action,
                output=output,
                tokens=usage.total,
                cached_tokens=usage.cached_tokens,
                dollars=self._dollars(model, reply),
                plan=plans[-1] if plans else None,
                files=files,
                flag=flags[0] if flags else None,
                hints_taken=hints_taken if same else 0,
                model=model,
            ),
        )
        for flag in flags[1:]:  # more candidates in one reply: each is its own approval
            self._report(run, TurnReport(turn=False, flag=flag))
        for flag in said:  # never submitted on its own: the model may be quoting a decoy it read
            self._report(run, TurnReport(turn=False, flag=flag, claimed=False))
        if idle:
            run.idle_turns = 0
            last = prompts.one(reply.content, 200) if reply.content.strip() else "(nothing)"
            self._report(run, TurnReport(
                turn=False, gave_up=f"the model answered {MAX_IDLE_TURNS} times in a row without calling a tool; it last said: {last}",
            ))

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
        run.messages = self._fresh(run, lane.approach) + [{"role": "user", "content": prompts.refresh(summary, prompt_tokens)}]
        self.deck.note(lane.id, f"context refreshed at {prompt_tokens:,} prompt tokens (a summary replaces the history)")

    # ------------------------------------------------------------------ helpers

    def _fresh(self, run: _Run, approach: str) -> list[dict]:
        """A new context: the system prompt, the brief, and what the L1 engines found (once
        they have run: an escalation or a refresh keeps it, so the model never pays to redo
        what they did or ruled out). `approach` is the player's own direction (lane.approach),
        never the model's plan."""
        challenge = run.challenge
        messages = [
            {"role": "system", "content": prompts.system_prompt()},
            {
                "role": "user",
                "content": prompts.brief(challenge, self.files.get(challenge.id, challenge.files), self.urls.get(challenge.id, ()),
                                         approach, flag_format=self.deck.config.flag_format),
            },
        ]
        if run.l1_message is not None:
            messages.append(dict(run.l1_message))
        return messages

    def _dollars(self, model: str, reply: Reply) -> float | None:
        usage = reply.usage
        return call_cost(usage.cost, self.prices.get(model), usage.prompt_tokens, usage.completion_tokens, usage.cached_tokens)

    def _session(self, lane_id: str, escalations: int) -> str:
        session = f"flightdeck-{self.run_id}-{lane_id}" + (f"-e{escalations}" if escalations else "")
        return session[:MAX_SESSION]

    def _flag_re(self) -> re.Pattern[str]:
        return re.compile(self.deck.config.flag_format)

    def _lane(self, run: _Run) -> Lane | None:
        return self.deck.lanes.get(run.lane_id)

    def _over(self, run: _Run) -> bool:
        lane = self._lane(run)
        return run.stopped or lane is None or lane.finished

    def _report(self, run: _Run, report: TurnReport) -> None:
        lane = self._lane(run)
        if lane is not None and not lane.finished and not run.stopped:
            self.deck.report(run.lane_id, report)

    def _note(self, lane: Lane, text: str) -> None:
        run = self.runs.get(lane.id)
        if run is not None:
            run.notes.append(text)
            run.wake.set()

    def _wake(self, lane: Lane) -> None:
        run = self.runs.get(lane.id)
        if run is not None:
            run.wake.set()

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
        """Stop every lane and close every workspace (the console calls this before it exits)."""
        tasks = []
        for run in self.runs.values():
            run.stopped = True
            run.wake.set()
            if run.task is not None and not run.task.done():
                if run.closing is None:  # still working: cancel it (its finally closes the workspace)
                    run.task.cancel()
                tasks.append(run.task)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        for run in self.runs.values():
            await self._close(run)


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
