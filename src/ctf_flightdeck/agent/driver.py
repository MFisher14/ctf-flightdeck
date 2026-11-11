"""The agent driver: every lane is an agent loop against a model API (M1, D5a).

One asyncio task per lane, on the console's event loop, so every Deck call happens on the
deck's thread (the LaneDriver contract in core/driver.py). A turn is one model call: the
reply's tool calls run in the lane's workspace, their results go back into the lane's
context, and the turn is reported to the deck (tokens, cost, the step, changed files, a
candidate flag). The deck applies the rules (approvals, caps, the flag format); the loop
only calls the model while the lane is RUNNING, and waits otherwise.

Each lane starts with a fresh context: the fixed system prompt, then the challenge brief.
Escalation starts a fresh context too, on the stronger model, with the deck's summary.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field

from ..core.driver import TurnReport
from ..core.model import Challenge, EscalationSummary, Lane, LaneState, Pending, PendingKind
from ..pricing import Price, call_cost
from . import prompts
from .client import ModelClient, ModelError, Reply
from .tools import TOOLS, Toolbox, ToolResult
from .workspace import ShellSpec, Snapshot, Workspace, WorkspaceError, changed_files, take_snapshot

WorkspaceFactory = Callable[[Lane, Challenge], Workspace]
"""Makes the workspace for a lane: HostWorkspace or DockerWorkspace, per `containerized`."""

MAX_SESSION = 256  # OpenRouter's limit for session_id
MAX_FILES_PER_TURN = 50  # an unpacked archive can change thousands; the console shows the first 50


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
    notes: list[str] = field(default_factory=list)  # flightdeck's notes for the next turn
    wake: asyncio.Event = field(default_factory=asyncio.Event)
    task: asyncio.Task[None] | None = None
    stopped: bool = False
    closed: bool = False
    escalations: int = 0
    generation: int = 0  # bumped when the context is replaced (escalation): older replies are stale


@dataclass
class Takeover:
    """The player's shell in a lane's workspace. finish() says what changed, tells the lane,
    and puts the changed files on the lane."""

    shell: ShellSpec
    run: _Run
    before: Snapshot
    driver: AgentDriver

    def finish(self) -> str:
        root = self.run.workspace.root
        changes = changed_files(self.before, take_snapshot(root), root)
        if changes:
            names = ", ".join(f"{c.path} ({c.status})" for c in changes[:8])
            note = f"changed {names}" + (f" and {len(changes) - 8} more" if len(changes) > 8 else "")
        else:
            note = "no files changed"
        history = root / ".flightdeck" / "takeover_history"
        commands = history.read_text(errors="replace").splitlines()[-8:] if history.is_file() else []
        told = f"The player took over your shell and handed it back ({note})."
        if commands:
            told += " Their last commands: " + "; ".join(commands) + "."
        self.run.notes.append(told + " Look at the workspace again before you go on.")
        if changes:
            self.driver._report(self.run, TurnReport(turn=False, files=tuple(changes)))
        return note


class AgentDriver:
    """Runs lanes as agent loops. Implements core.driver.LaneDriver."""

    def __init__(
        self,
        client: ModelClient,
        workspaces: WorkspaceFactory,
        *,
        run_id: str,
        files: Mapping[str, Sequence[str]] | None = None,
        urls: Mapping[str, Sequence[str]] | None = None,
        prices: Mapping[str, Price] | None = None,
        max_tokens: int | None = None,
    ) -> None:
        self.client = client
        self.workspaces = workspaces
        self.run_id = run_id
        self.files = dict(files or {})  # challenge id -> handout file names, for the brief
        self.urls = {cid: tuple(u) for cid, u in (urls or {}).items()}  # challenge id -> live instance origins
        self.prices = dict(prices or {})
        self.max_tokens = max_tokens
        self.runs: dict[str, _Run] = {}
        self.errors: list[str] = []  # cleanup problems, shown when the console exits
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
        run = _Run(
            lane_id=lane.id,
            challenge=challenge,
            workspace=workspace,
            toolbox=Toolbox(workspace, http_allow=urls),
            model=lane.model,
            session=self._session(lane.id, 0),
        )
        run.messages = self._fresh(run, lane.approach or lane.plan)
        self.runs[lane.id] = run
        run.task = loop.create_task(self._loop(run), name=f"flightdeck lane {lane.id}")

    def pause(self, lane: Lane) -> None:
        """Nothing to interrupt: the loop checks the lane's state before every model call
        and before running the tool calls of a reply that arrived meanwhile."""

    def resume(self, lane: Lane) -> None:
        self._wake(lane)

    def hint(self, lane: Lane, text: str) -> None:
        self._wake(lane)  # the hint is in lane.hints; the next turn sends it and reports it taken

    def redirect(self, lane: Lane, text: str) -> None:
        self._note(lane, f"The player changed your plan to: {text}")

    def escalate(self, lane: Lane, model: str, summary: EscalationSummary) -> None:
        run = self.runs.get(lane.id)
        if run is None:
            return
        run.model = model
        run.escalations += 1
        run.generation += 1
        run.session = self._session(lane.id, run.escalations)
        run.messages = self._fresh(run, lane.plan) + [{"role": "user", "content": prompts.escalation(summary)}]
        run.notes.clear()
        run.wake.set()

    def approved(self, lane: Lane, pending: Pending) -> None:
        if pending.kind is PendingKind.LIVE_BOX:
            self._note(lane, "The player allowed you to use the live instance now.")
        elif pending.kind is PendingKind.BUDGET:
            self._note(lane, "The player approved more budget. Carry on, and keep it lean.")
        else:
            self._wake(lane)

    def rejected(self, lane: Lane, flag: str) -> None:
        self._note(lane, f"{flag} was submitted and it is not correct.")

    def declined(self, lane: Lane, pending: Pending) -> None:
        if pending.kind is PendingKind.SUBMIT:
            self._note(lane, f"The player did not submit {pending.flag}: they think it is not the flag. Keep going.")
        elif pending.kind is PendingKind.LIVE_BOX:
            self._note(lane, "The player said no to the live instance: work from the handout only.")
        else:
            self._note(lane, f"The player declined: {pending.detail}.")

    def stop(self, lane: Lane) -> None:
        run = self.runs.get(lane.id)
        if run is None:
            return
        run.stopped = True
        run.wake.set()
        if run.task is not None and not run.task.done() and run.task is not asyncio.current_task():
            run.task.cancel()  # its finally closes the workspace

    def takeover(self, lane: Lane) -> Takeover | None:
        """A shell in the lane's workspace for the player, or None if the lane has none."""
        run = self.runs.get(lane.id)
        if run is None or run.closed:
            return None
        return Takeover(run.workspace.interactive_shell(), run, take_snapshot(run.workspace.root), self)

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
        while await self._until_running(run):
            lane = self._lane(run)
            assert lane is not None
            hints = list(lane.hints)
            notes, run.notes = run.notes, []
            if hints or notes:
                run.messages.append({"role": "user", "content": prompts.player_message(hints, notes)})
            generation, model = run.generation, run.model
            try:
                reply = await self.client.chat(
                    run.model, run.messages, TOOLS, session_id=run.session, max_tokens=self.max_tokens
                )
            except ModelError as exc:
                self._report(
                    run,
                    TurnReport(turn=False, action=f"model call to {run.model} failed", output=str(exc),
                               hints_taken=len(hints), gave_up=f"model API error: {exc}"),
                )
                return
            if run.generation != generation:
                # escalated while this model was thinking: its reply belongs to the old context.
                # Drop it, but count what it cost.
                self._report(run, TurnReport(turn=False, tokens=reply.usage.total, cached_tokens=reply.usage.cached_tokens,
                                             dollars=self._dollars(model, reply)))
                continue
            if not await self._until_running(run):
                return  # killed or finished while the model was thinking
            await self._turn(run, reply, len(hints))

    async def _until_running(self, run: _Run) -> bool:
        """Wait while the lane is paused, taken over or waiting for the player. False once
        it has finished or was stopped."""
        while not run.stopped:
            lane = self._lane(run)
            if lane is None or lane.finished:
                return False
            if lane.state is LaneState.RUNNING:
                return True
            run.wake.clear()
            await run.wake.wait()
        return False

    async def _turn(self, run: _Run, reply: Reply, hints_taken: int) -> None:
        lane = self._lane(run)
        assert lane is not None
        turn = lane.turns + 1
        run.messages.append(reply.message)
        root = run.workspace.root
        before = await asyncio.to_thread(take_snapshot, root)
        results: list[ToolResult] = []
        for index, call in enumerate(reply.tool_calls):
            result = await run.toolbox.call(call.name, call.arguments, turn=turn, index=index)
            results.append(result)
            run.messages.append({"role": "tool", "tool_call_id": call.id, "content": result.content})
        after = await asyncio.to_thread(take_snapshot, root)
        changes = await asyncio.to_thread(changed_files, before, after, root)
        files = tuple(changes[:MAX_FILES_PER_TURN])
        if len(changes) > MAX_FILES_PER_TURN:
            run.notes.append(f"That turn changed {len(changes)} files; the console lists the first {MAX_FILES_PER_TURN}.")
        if not reply.tool_calls:
            run.messages.append({"role": "user", "content": prompts.NUDGE})
        flags = [r.flag for r in results if r.flag]
        plans = [r.plan for r in results if r.plan]
        for flag in flags:
            if not self._flag_re().fullmatch(flag):
                run.notes.append(f"{flag} does not match the flag format {self.deck.config.flag_format}; it was not submitted.")
        usage = reply.usage
        action, output = _step(results, reply)
        self._report(
            run,
            TurnReport(
                action=action,
                output=output,
                tokens=usage.total,
                cached_tokens=usage.cached_tokens,
                dollars=self._dollars(run.model, reply),
                plan=plans[-1] if plans else None,
                files=files,
                flag=flags[0] if flags else None,
                hints_taken=hints_taken,
            ),
        )
        for flag in flags[1:]:  # more candidates in one reply: each is its own approval
            self._report(run, TurnReport(turn=False, flag=flag))

    # ------------------------------------------------------------------ helpers

    def _fresh(self, run: _Run, approach: str) -> list[dict]:
        challenge = run.challenge
        return [
            {"role": "system", "content": prompts.system_prompt(self.deck.config.flag_format)},
            {
                "role": "user",
                "content": prompts.brief(challenge, self.files.get(challenge.id, challenge.files), self.urls.get(challenge.id, ()), approach),
            },
        ]

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
        if run.closed:
            return
        run.closed = True
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
    said = reply.content.strip().splitlines()[0] if reply.content.strip() else "(an empty reply)"
    return f"says: {said[:200]}", ""
