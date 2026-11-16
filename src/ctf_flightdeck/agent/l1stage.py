"""The L1 stage of a lane (M2): the player's no-model solvers, run before the lane's model.

A lane routes its challenge through the pack (l1.router.route), runs every engine routed to
it (l1.runner.run_routed, each in its own copy of the handout), and logs each result on the
deck (Deck.record_l1). A flag an engine found becomes the lane's candidate, so it waits for
the player's approval like any other (or is submitted at once under the auto policy, when
the engine claimed it: a match found in what a text engine printed always waits, and so does
a flag the challenge's own text holds, such as a stand-in flag.txt an engine read out). If
no engine solved the challenge, the lane goes on to the model, whose context says what the
engines found, fenced as data: an engine's output comes from the challenge's files.

Both kinds of lane run the one stage (run_stage): flightdeck's own (agent/driver.py) before
their first model call, and a coding-agent lane (agent/external.py) before its CLI is first
started, so a flag an engine finds in seconds never costs a CLI session. Each gives the
stage its own parts (StageLane): how it looks a claimed flag up in the challenge's own text,
how it reports, and what it takes out of the text it shows (a coding-agent lane's secrets).

Where engines run follows the lanes (D17). On the host runtime they run on this machine, as
the player: they are the player's own code (l1/runner.py says how they are sandboxed, and
what that does not stop). When lanes run in Docker (`image` set), each engine runs in a
container of the lane image (l1/container.py), with the pack mounted read-only, and no
network unless the lane may reach the challenge's live instance at once (`online`: instance
policy auto, and the challenge has one). Then the lane's engines share a fenced network that
reaches that instance and nothing else (agent/egress.py), as the lane's own container will.
So under the confirm, manual and off policies no engine can reach the instance, before the
player is asked or ever. An engine never runs in the lane's own
workspace or container, so nothing it writes is among the lane's files.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..core.driver import TurnReport
from ..core.model import Challenge
from ..l1.container import EngineContainer, container_name, fence_name
from ..l1.manifest import Manifest
from ..l1.router import route
from ..l1.runner import EngineRun, WorkspaceFactory, run_routed
from . import prompts
from .egress import Egress
from .workspace import HostWorkspace

if TYPE_CHECKING:
    from ..leftovers import ProcessRecord

FLAG_STATUSES = ("solved", "candidate")  # results whose flags go to the player


@dataclass(frozen=True)
class L1Stage:
    manifests: Sequence[Manifest]
    handouts: Mapping[str, Path]  # challenge id -> its handout folder
    workdir: Path  # engine workspaces: workdir/<lane id>/l1/<engine id>
    flag_format: str
    concurrency: int = 4
    image: str | None = None  # lanes run in Docker: each engine runs in a container of this image; None: on this machine
    pack: Path | None = None  # the pack's folder, as its manifests were read from it: mounted read-only in each container
    engine_image: str | None = None  # the image of an engine's container when it is not the lane image ([l1] image); the fence's proxies stay on `image`
    labels: Mapping[str, str] = field(default_factory=dict)  # on each engine's container: the run's (leftovers.labels())
    record: ProcessRecord | None = None  # the run's record of process groups: an engine on this machine is in it while it runs
    urls: Mapping[str, Sequence[str]] = field(default_factory=dict)  # challenge id -> its live instance: what online engines in Docker reach
    toolkit: str = ""  # [l1] lane_tools: the pack's note for a lane's brief (pack.lane_note); "": lanes are not told of the pack
    model_after: float = 0.0  # [l1] model_after: seconds the engines get before the lane's model starts anyway; 0: it waits for all

    def __post_init__(self) -> None:
        if self.image is not None and self.pack is None:
            raise ValueError("L1 engines in Docker need the pack's folder, to mount it in their containers")

    def routed(self, challenge: Challenge) -> list:
        return route(self.manifests, challenge, self.handouts[challenge.id])

    async def run(self, lane_id: str, challenge: Challenge, *, online: bool = False) -> list[EngineRun]:
        """Run the engines routed to `challenge` for a lane. `online`: in Docker, the engines'
        containers are on a fenced network that reaches the challenge's instance and nothing
        else (the lane may reach it at once); else they have none. Engines on this machine
        have its network either way."""
        hits = self.routed(challenge)
        if not hits:
            return []
        lane = lane_id.lower()
        egress = None
        if self.image is not None and online:
            # one fence for the lane's engines (agent/egress.py), made before the first engine
            # starts and removed after the last has gone: WorkspaceError when it cannot be
            # made, and then no engine runs (never one on an open network instead)
            urls = self.urls.get(challenge.id, ())
            if not urls:
                raise ValueError(f"L1 engines were to be online for {challenge.id}, which has no instance to reach")
            egress = Egress(fence_name(self.workdir.name, lane), image=self.image, labels=self.labels)
        try:
            if egress is not None:
                await egress.allow(urls)
            return await run_routed(
                hits,
                self.handouts[challenge.id],
                workdir=self.workdir / lane / "l1",
                flag_format=self.flag_format,
                concurrency=self.concurrency,
                challenge_id=challenge.id,
                workspace_factory=(self.containers(lane, egress.network if egress is not None else "none")
                                   if self.image is not None else self.hosts()),
            )
        finally:
            if egress is not None:
                await egress.close()

    def containers(self, lane: str, network: str) -> WorkspaceFactory:
        """Makes each engine's container for a lane, on `network`."""
        image, pack = self.engine_image or self.image, self.pack
        assert image is not None and pack is not None

        def factory(engine_id: str, root: Path, handout: Path) -> EngineContainer:
            name = container_name(self.workdir.name, lane, engine_id)
            return EngineContainer(root, handout, image=image, name=name, network=network, pack=pack, labels=self.labels)

        return factory

    def hosts(self) -> WorkspaceFactory | None:
        """Makes each engine's workspace on this machine, in the run's record (None without
        one: l1.runner's own host workspace)."""
        record = self.record
        if record is None:
            return None
        return lambda engine_id, root, handout: HostWorkspace(root, handout, record=record, what=f"the L1 engine {engine_id}")


def result_line(run: EngineRun) -> str:
    """One engine's result, for the lane's context (made safe by the prompt's fence)."""
    res = run.result
    line = f"{run.manifest.id}: {res.status}"
    if res.flags:
        line += f", found {', '.join(res.flags)}"
    if res.notes:
        line += f" ({res.notes})"
    return line


@dataclass(frozen=True)
class StageLane:
    """What a lane gives the stage (run_stage): its own parts of it, so that flightdeck's own
    lanes and coding-agent lanes run one stage."""

    lane_id: str
    challenge: Challenge
    online: bool  # the lane may reach the challenge's live instance at once: it has one, and the instance policy is auto
    over: Callable[[], bool]  # the lane has ended: nothing more of it is reported
    note: Callable[[str], None]  # a note on the lane, for the player
    error: Callable[[str], None]  # a problem shown when the console exits
    vet: Callable[[Sequence[str]], Awaitable[None]]  # under auto: looks for each claimed flag in the challenge's own text
    own_text: Callable[[str], str]  # why a claimed flag waits, as the challenge's own text holds it or may; "" when nothing says so
    report: Callable[[TurnReport], None]
    redact: Callable[[str], str] = str  # takes what the lane never shows out of an engine's words (never out of a flag it gave)
    # model_after: what the engines found once the model has started (the lane keeps it for
    # every fresh context, and the model hears it as a note), and the lane's hold on the task
    # that finishes the stage (cancelled when the lane closes). Without both, the stage waits
    # for every engine, whatever model_after says
    later: Callable[[str], None] | None = None
    keep: Callable[[asyncio.Future[Any]], None] | None = None


async def run_stage(stage: L1Stage, deck: Any, lane: StageLane) -> str | None:
    """Run the engines routed to the lane's challenge, before the lane's model does anything,
    for at most stage.model_after seconds (0: as long as they take). What finish() says of
    them, when they are done in time. Else the model starts with a note that they still run
    (prompts.l1_running), and a task the lane keeps (lane.keep) finishes the stage: their
    flags go to the deck as below, and what they found goes to the lane (lane.later). An
    engine's own time limit is its manifest's: a pack whose engine runs out its limit no
    longer holds the model for it (2026-11-16: the solver pack's intake ran its 300 s on two
    practice challenges before any model started)."""
    work = asyncio.ensure_future(stage.run(lane.lane_id, lane.challenge, online=lane.online))
    if stage.model_after <= 0 or lane.later is None or lane.keep is None:
        return await finish(work, deck, lane)
    try:
        done, _ = await asyncio.wait({work}, timeout=stage.model_after)
    except asyncio.CancelledError:
        work.cancel()
        raise
    if done:
        return await finish(work, deck, lane)
    names = [hit.manifest.id for hit in stage.routed(lane.challenge)]
    lane.note(f"L1: {_engines(names)} still running after {stage.model_after:g} s: the lane's model starts now, "
              "and hears what they find")
    later, keep = lane.later, lane.keep

    async def rest() -> None:
        text = await finish(work, deck, lane, late=True)
        if text is not None and not lane.over():
            later(text)

    task = asyncio.ensure_future(rest())
    task.add_done_callback(lambda _: work.cancel())  # the lane closed first: the engines stop with it
    keep(task)
    return prompts.l1_running(names, stage.model_after)


def _engines(names: Sequence[str]) -> str:
    shown = ", ".join(names[:6]) + (f" and {len(names) - 6} more" if len(names) > 6 else "")
    return f"{'engine' if len(names) == 1 else 'engines'} {shown}"


async def finish(work: asyncio.Future[list[EngineRun]], deck: Any, lane: StageLane, *, late: bool = False) -> str | None:
    """What the engines routed to the lane's challenge found, once they are done (`work`;
    `late`: after the lane's model started, past model_after). A flag one found is the lane's candidate (claimed, unless the runner found it in what a
    text engine printed, or the challenge's own text holds it or may: lane.own_text, as for a
    flag the model gives, and the lane says why). Returns what they all found, for the lane's
    context (prompts.l1_results: fenced as data), or None when there is nothing to say there:
    no engine routes to the challenge, L1 did not run (said loudly: the lane goes on without
    it), or the lane ended meanwhile.

    In Docker an engine is online only when the lane may reach the challenge's instance at
    once (lane.online): it runs before the confirm policy's question, so it must never need
    the answer."""
    try:
        runs = await work
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # a broken pack or an L1 bug: the lane goes on without L1, loudly
        said = f"L1 did not run: {type(exc).__name__}: {exc}"
        lane.error(f"{lane.lane_id}: {said}")
        lane.note(said)
        return None
    if lane.over():
        return None
    if not runs:
        lane.note("L1: no engine in the pack routes to this challenge")
        return None
    cid = lane.challenge.id
    for engine in runs:
        res = engine.result
        deck.record_l1(cid, engine.manifest.id, res.status, flags=res.flags, seconds=engine.seconds,
                       notes=lane.redact(res.notes) if res.notes else res.notes, lane_id=lane.lane_id)
    # an engine's own result is claimed: under auto each is looked for in the challenge's own text first
    await lane.vet([flag for engine in runs if engine.result.status in FLAG_STATUSES and not engine.scraped
                    for flag in engine.result.flags])
    if lane.over():
        return None
    for engine in runs:
        if engine.result.status in FLAG_STATUSES:
            for flag in engine.result.flags:
                # a match in what a text engine printed may be the challenge's decoy, and so may a flag the
                # challenge's own text holds, or may (a stand-in flag.txt an engine read out as its result): either waits
                why = "" if engine.scraped else lane.own_text(flag)
                # not said of a flag known not to be the flag (the deck says why it is not asked)
                said = bool(why) and deck.not_flag(cid, flag) is None
                claimed = not engine.scraped and not why
                # one no engine vouched for may wait aside: unanswered for the deck's bench_after, it
                # waits on while the lane's model starts, so a decoy never holds the challenge while
                # the player is away (2026-11-16: under autopilot welcome-mat's decoy waited, and
                # no model ever tried the challenge)
                lane.report(TurnReport(turn=False, flag=flag, claimed=claimed, aside=not claimed))
                if said:
                    lane.note(f"{flag} {why}, so it waits for you, though your L1 engine "
                              f"{engine.manifest.id} gave it as its flag")
    if lane.over():
        return None
    return prompts.l1_results([lane.redact(result_line(engine)) for engine in runs], late=late)
