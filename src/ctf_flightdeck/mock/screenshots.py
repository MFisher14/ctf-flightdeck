"""`flightdeck mock --screenshot DIR`: play a scenario headless and save SVG screenshots
of its key moments (wave drop, an alert with its suggested action, an intervention,
the detail pane, team stop, approve submit, the prompts, take over and help).

Moments are found by watching the deck, so any scenario works; a moment the scenario
does not have (no teammates in solo mode, say) is reported as skipped, not faked.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from ..console.app import FlightdeckApp
from ..core.attention import SortMode, sort_lanes
from ..core.model import AlertKind, Lane, LaneState, PendingKind
from . import scenarios
from .world import FakeWorld

SIZE = (160, 48)

# Which key answers which alert, for the "intervention" moment.
ANSWER = {
    AlertKind.HINT: "r",
    AlertKind.DIRECTION: "r",
    AlertKind.EFFORT: "h",
    AlertKind.LOOP: "h",
    AlertKind.STALL: "e",
}
PREFERRED = (AlertKind.HINT, AlertKind.DIRECTION, AlertKind.EFFORT, AlertKind.LOOP, AlertKind.STALL)


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


class _Shots:
    def __init__(self, app: FlightdeckApp, pilot, out_dir: Path, result: CaptureResult) -> None:
        self.app, self.pilot, self.out_dir, self.result = app, pilot, out_dir, result

    async def take(self, name: str, *, keep_toasts: bool = False) -> None:
        if not keep_toasts:
            self.app.clear_notifications()
        await self.pilot.pause()
        filename = f"{len(self.result.saved) + 1:02d}-{name}.svg"
        self.result.saved.append(Path(self.app.save_screenshot(filename=filename, path=str(self.out_dir))))
        self.app.clear_notifications()  # the next shot shows only its own toasts

    async def advance_until(self, done: Callable[[], bool], limit: int) -> bool:
        for _ in range(limit):
            if done():
                return True
            self.app.step()
            await self.pilot.pause()
        return done()

    async def press(self, *keys: str) -> None:
        await self.pilot.press(*keys)
        await self.pilot.pause()


async def _capture(world: FakeWorld, out_dir: Path, size: tuple[int, int]) -> CaptureResult:
    deck = world.deck
    result = CaptureResult()
    app = FlightdeckApp(deck, ticker=world.tick, mock=f"MOCK · {world.scenario.name}")
    async with app.run_test(size=size, notifications=True) as pilot:
        shots = _Shots(app, pilot, out_dir, result)

        def top_lane() -> Lane | None:
            ordered = sort_lanes(deck.lanes.values(), SortMode.ATTENTION, deck.now)
            return ordered[0] if ordered else None

        await shots.take("open")

        # Wave drop: ten or more challenges released at once.
        sizes = [len(deck.challenges)]

        def wave_dropped() -> bool:
            sizes.append(len(deck.challenges))
            return sizes[-1] - sizes[-2] >= 10

        if await shots.advance_until(wave_dropped, limit=80):
            lane = top_lane()
            if lane is not None:
                app.select_lane(lane.id)
            await shots.take("wave-drop", keep_toasts=True)
        else:
            result.skipped.append("wave-drop: the scenario releases no wave of 10+ challenges")

        # An alert with its suggested action, then the player answering it.
        def course_lane() -> Lane | None:
            for kind in PREFERRED:
                for lane in deck.active_lanes():
                    if lane.alert(kind) is not None:
                        return lane
            return None

        if await shots.advance_until(lambda: course_lane() is not None, limit=60):
            lane = course_lane()
            assert lane is not None
            kind = next(k for k in PREFERRED if lane.alert(k) is not None)
            app.select_lane(lane.id)
            await shots.take(f"alert-{kind.tag}")
            key = ANSWER[kind]
            await shots.press(key)
            if key in ("r", "h"):
                await shots.take("redirect-prompt" if key == "r" else "hint-prompt")
                await shots.press("enter")
            await shots.take(f"intervened-{kind.tag}", keep_toasts=True)
            if await shots.advance_until(lambda: lane.pending is not None or lane.finished, limit=12):
                app.select_lane(lane.id)
                await shots.take("detail-pane")
        else:
            result.skipped.append("alert: no lane raised a course alert (hint, wrong way, effort, loop, stall)")
            lane = None

        # Approve submit: a lane waiting with a flag, then the board after approval.
        def flag_lane() -> Lane | None:
            if lane is not None and lane.pending and lane.pending.kind is PendingKind.SUBMIT:
                return lane
            return next(
                (x for x in deck.active_lanes() if x.pending and x.pending.kind is PendingKind.SUBMIT),
                None,
            )

        if await shots.advance_until(lambda: flag_lane() is not None, limit=60):
            waiting = flag_lane()
            assert waiting is not None
            app.select_lane(waiting.id)
            await shots.take("approve-pending")
            await shots.press("a")
            app.select_challenge(waiting.challenge_id)
            await shots.take("approve-submit", keep_toasts=True)
        else:
            result.skipped.append("approve-submit: no lane found a flag")

        # Team stop: a teammate's solve stops a lane by itself.
        def stopped_lane() -> Lane | None:
            return next(
                (x for x in deck.lanes.values() if x.state is LaneState.STOPPED and x.alert(AlertKind.TEAMMATE)),
                None,
            )

        if deck.config.team and await shots.advance_until(lambda: stopped_lane() is not None, limit=80):
            stopped = stopped_lane()
            assert stopped is not None
            app.select_lane(stopped.id)
            await shots.take("team-stop", keep_toasts=True)
        else:
            why = "solo mode" if not deck.config.team else "no teammate solved a challenge a lane was on"
            result.skipped.append(f"team-stop: {why}")

        # The lane list once every alert kind has had its chance to fire.
        await shots.advance_until(lambda: False, limit=20)
        top = top_lane()
        if top is not None:
            app.select_lane(top.id)
        await shots.take("attention-sort")

        # Fork and kill prompts, on a lane with a course alert if there is one.
        target = course_lane() or next(iter(deck.active_lanes()), None)
        if target is not None:
            app.select_lane(target.id)
            await shots.press("f")
            await shots.take("fork-prompt")
            await shots.press("escape")
            await shots.press("k")
            await shots.take("kill-prompt")
            await shots.press("escape")
        running = next((x for x in deck.active_lanes() if x.state is LaneState.RUNNING), None)
        if running is not None:
            app.select_lane(running.id)
            await shots.press("t")
            await shots.take("take-over")
            await shots.press("enter")
        else:
            result.skipped.append("take-over: no running lane left")
        await shots.press("question_mark")
        await shots.take("help")
        await shots.press("escape")
    return result


