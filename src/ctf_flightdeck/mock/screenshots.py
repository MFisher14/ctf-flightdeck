"""`flightdeck mock --screenshot DIR`: play a scenario headless and save SVG screenshots
of its key moments.

Moments are found by watching the deck, so any scenario works; a moment the scenario
does not have (no teammates in solo mode, no wave) is reported as skipped, never faked.
The clock is advanced without redrawing between ticks, so a run takes seconds.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from ..console.app import FlightdeckApp
from ..console.focus import FocusScreen
from ..core.attention import SortMode, sort_lanes
from ..core.model import AlertKind, ChallengeStatus, Lane, LaneState, PendingKind
from . import scenarios
from .scenarios import ReleaseAt
from .world import FakeWorld

SIZE = (160, 46)
NARROW = (120, 36)

# The course alerts, in the order the runner looks for one to show and answer.
PREFERRED = (AlertKind.HINT, AlertKind.DIRECTION, AlertKind.EFFORT, AlertKind.LOOP, AlertKind.STALL)

# Every moment, in order. Each run saves a moment (as NN-<moment>[-detail].svg) or reports it
# in CaptureResult.skipped as "<moment>[, <moment>...]: why".
MOMENTS = (
    "open", "wave-drop", "alert", "command-menu", "focus-lane", "chat", "focus-after", "diff",
    "approve-pending", "approve-submit", "team-stop", "attention-sort", f"narrow-{NARROW[0]}x{NARROW[1]}", "fork-prompt",
    "kill-prompt", "take-over", "challenge-card", "help",
)


@dataclass
class CaptureResult:
    saved: list[Path] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


def capture(
    scenario: str,
    out_dir: Path,
    *,
    max_lanes: int | None = None,
    team: bool | None = None,
    containerized: bool | None = None,
    size: tuple[int, int] = SIZE,
) -> CaptureResult:
    world = FakeWorld(scenarios.get(scenario), max_lanes=max_lanes, team=team, containerized=containerized)
    return asyncio.run(_capture(world, Path(out_dir), size))


class _Run:
    def __init__(self, app: FlightdeckApp, world: FakeWorld, pilot, out_dir: Path, result: CaptureResult) -> None:
        self.app, self.world, self.pilot, self.out_dir, self.result = app, world, pilot, out_dir, result

    async def shot(self, name: str) -> None:
        self.app.refresh_view()
        await self.pilot.pause()
        filename = f"{len(self.result.saved) + 1:02d}-{name}.svg"
        self.result.saved.append(Path(self.app.save_screenshot(filename=filename, path=str(self.out_dir))))

    async def advance_until(self, done: Callable[[], bool], limit: int) -> bool:
        """Tick the world (no redraw per tick) until `done`, then redraw once."""
        reached = done()
        for _ in range(limit):
            if reached:
                break
            self.world.tick()
            reached = done()
        self.app.refresh_view()
        await self.pilot.pause()
        return reached

    async def press(self, *keys: str) -> None:
        await self.pilot.press(*keys)
        await self.pilot.pause()

    async def fleet(self, select: str | None = None) -> None:
        self.app.show_fleet(select=select)
        await self.pilot.pause()


async def _capture(world: FakeWorld, out_dir: Path, size: tuple[int, int]) -> CaptureResult:
    deck = world.deck
    result = CaptureResult()
    app = FlightdeckApp(deck, ticker=world.tick, mock=f"MOCK · {world.scenario.name}", refresh_seconds=None)
    async with app.run_test(size=size) as pilot:
        run = _Run(app, world, pilot, out_dir, result)

        def top_lane() -> Lane | None:
            ordered = sort_lanes(deck.lanes.values(), SortMode.ATTENTION, deck.now)
            return ordered[0] if ordered else None

        def course_lane() -> tuple[Lane, AlertKind] | None:
            for kind in PREFERRED:
                for lane in deck.active_lanes():
                    if lane.alert(kind) is not None and lane.pending is None:
                        return lane, kind
            return None

        await run.shot("open")

        # Wave drop: only if the scenario has one still to come.
        waves = [at for at, ev in world.scenario.timeline if isinstance(ev, ReleaseAt) and len(ev.ids) >= 10 and at > world.ticks]
        if waves:
            await run.advance_until(lambda: world.ticks >= waves[0], limit=waves[0] - world.ticks + 1)
            top = top_lane()
            if top is not None:
                app.fleet.select_lane(top.id)
            await run.shot("wave-drop")
        else:
            result.skipped.append("wave-drop: the scenario has no wave of 10+ challenges still to come")

        # An alert with its suggested answers, the command bar, then the lane in focus.
        if await run.advance_until(lambda: course_lane() is not None, limit=60):
            lane, kind = course_lane()  # type: ignore[misc]
            app.fleet.select_lane(lane.id)
            await run.shot(f"alert-{kind.tag}")
            await run.press("slash")
            await run.shot("command-menu")
            await run.press("escape", "escape")
            app.open_lane(lane.id)
            await pilot.pause()
            await run.shot("focus-lane")
            suggestion = next((s for s in lane.alert(kind).suggestions if s.key in ("r", "h", "e")), None)
            text = {"r": "/redirect ", "h": "", "e": "/escalate"}.get(suggestion.key, "") + suggestion.text if suggestion else ""
            chat = app.screen.query_one("#chat")
            chat.start(text or "try a simpler approach first")
            await pilot.pause()
            await run.shot("chat")
            await run.press("enter")
            await run.advance_until(lambda: lane.pending is not None or lane.finished, limit=12)
            await run.shot("focus-after")
            if lane.files:
                await run.press("slash", *"diff", "enter")
                await run.shot("diff")
            else:
                result.skipped.append(f"diff: {lane.id} changed no files")
        else:
            result.skipped.append(
                "alert, command-menu, focus-lane, chat, focus-after, diff: "
                "no lane raised a course alert (off-hint, wrong way, effort, loop, stall)"
            )

        # Approve a submit from the focus view; the board updates in the fleet.
        def waiting_flag() -> Lane | None:
            return next((x for x in deck.active_lanes() if x.pending and x.pending.kind is PendingKind.SUBMIT), None)

        if await run.advance_until(lambda: waiting_flag() is not None, limit=60):
            lane = waiting_flag()
            assert lane is not None
            app.open_lane(lane.id)
            await pilot.pause()
            await run.shot("approve-pending")
            await run.press("slash", *"approve", "enter")
            await run.fleet()
            app.fleet.select_challenge(lane.challenge_id)
            await run.shot("approve-submit")
        else:
            result.skipped.append("approve-pending, approve-submit: no lane found a flag")

        # Team stop: a teammate's solve stops a lane by itself.
        def stopped_lane() -> Lane | None:
            return next(
                (x for x in deck.lanes.values() if x.state is LaneState.STOPPED and x.alert(AlertKind.TEAMMATE)),
                None,
            )

        await run.fleet()
        if deck.config.team and await run.advance_until(lambda: stopped_lane() is not None, limit=80):
            stopped = stopped_lane()
            assert stopped is not None
            app.fleet.select_lane(stopped.id)
            await run.shot("team-stop")
        else:
            why = "solo mode" if not deck.config.team else "no teammate solved a challenge a lane was on"
            result.skipped.append(f"team-stop: {why}")

        # The fleet once more lanes have had their say, also at a narrower size.
        await run.advance_until(lambda: False, limit=12)
        top = top_lane()
        if top is not None:
            app.fleet.select_lane(top.id)
        await run.shot("attention-sort")
        await pilot.resize_terminal(*NARROW)
        await pilot.pause()
        await run.shot(f"narrow-{NARROW[0]}x{NARROW[1]}")
        await pilot.resize_terminal(*size)
        await pilot.pause()

        # Prompts and placeholders.
        target = (course_lane() or (next(iter(deck.active_lanes()), None), None))[0]
        if target is not None:
            app.fleet.select_lane(target.id)
            await run.press("f")
            await run.shot("fork-prompt")
            await run.press("escape")
            await run.press("k")
            await run.shot("kill-prompt")
            await run.press("escape")
        else:
            result.skipped.append("fork-prompt, kill-prompt: no active lane left")
        running = next((x for x in deck.active_lanes() if x.state is LaneState.RUNNING), None)
        if running is not None:
            app.fleet.select_lane(running.id)
            await run.press("t")
            await run.shot("take-over")
            await run.press("enter")
        else:
            result.skipped.append("take-over: no running lane left")
        idle = next((ch for ch in deck.challenges.values() if ch.status in (ChallengeStatus.PARKED, ChallengeStatus.QUEUED) and not deck.lanes_on(ch.id)), None)
        if idle is not None:
            app.fleet.select_challenge(idle.id)
            await run.press("enter")
            await run.shot("challenge-card")
            await run.press("escape")
        else:
            result.skipped.append("challenge-card: no parked or queued challenge without a lane")
        await run.press("question_mark")
        await run.shot("help")
        await run.press("escape")
        assert not isinstance(app.screen, FocusScreen)
    return result
