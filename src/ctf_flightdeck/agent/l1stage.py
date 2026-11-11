"""The L1 stage of a lane (M2): the player's no-model solvers, run before the first model call.

A lane routes its challenge through the pack (l1.router.route), runs every engine routed to
it (l1.runner.run_routed, each in its own copy of the handout), and logs each result on the
deck (Deck.record_l1). A flag an engine found becomes the lane's candidate, so it waits for
the player's approval like any other (or is submitted at once under the auto policy). If no
engine solved the challenge, the lane goes on to the model, whose context says what the
engines found, fenced as data: an engine's output comes from the challenge's files.

Engines run on this machine whatever the lanes' runtime: they are the player's own code
(l1/runner.py says how they are sandboxed, and what that does not stop).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from ..core.model import Challenge
from ..l1.manifest import Manifest
from ..l1.router import route
from ..l1.runner import EngineRun, run_routed

FLAG_STATUSES = ("solved", "candidate")  # results whose flags go to the player


@dataclass(frozen=True)
class L1Stage:
    manifests: Sequence[Manifest]
    handouts: Mapping[str, Path]  # challenge id -> its handout folder
    workdir: Path  # engine workspaces: workdir/<lane id>/l1/<engine id>
    flag_format: str
    concurrency: int = 4

    def routed(self, challenge: Challenge) -> list:
        return route(self.manifests, challenge, self.handouts[challenge.id])

    async def run(self, lane_id: str, challenge: Challenge) -> list[EngineRun]:
        hits = self.routed(challenge)
        if not hits:
            return []
        return await run_routed(
            hits,
            self.handouts[challenge.id],
            workdir=self.workdir / lane_id.lower() / "l1",
            flag_format=self.flag_format,
            concurrency=self.concurrency,
            challenge_id=challenge.id,
        )


def result_line(run: EngineRun) -> str:
    """One engine's result, for the lane's context (made safe by the prompt's fence)."""
    res = run.result
    line = f"{run.manifest.id}: {res.status}"
    if res.flags:
        line += f", found {', '.join(res.flags)}"
    if res.notes:
        line += f" ({res.notes})"
    return line
