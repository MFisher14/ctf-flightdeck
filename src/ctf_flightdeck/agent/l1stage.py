"""The L1 stage of a lane (M2): the player's no-model solvers, run before the first model call.

A lane routes its challenge through the pack (l1.router.route), runs every engine routed to
it (l1.runner.run_routed, each in its own copy of the handout), and logs each result on the
deck (Deck.record_l1). A flag an engine found becomes the lane's candidate, so it waits for
the player's approval like any other (or is submitted at once under the auto policy, when
the engine claimed it: a match found in what a text engine printed always waits). If no
engine solved the challenge, the lane goes on to the model, whose context says what the
engines found, fenced as data: an engine's output comes from the challenge's files.

Where engines run follows the lanes (D17). On the host runtime they run on this machine, as
the player: they are the player's own code (l1/runner.py says how they are sandboxed, and
what that does not stop). When lanes run in Docker (`image` set), each engine runs in a
container of the lane image (l1/container.py), with the pack mounted read-only, and no
network unless the lane may reach the challenge's live instance at once (`online`: instance
policy auto, and the challenge has one). So under the confirm, manual and off policies no
engine can reach the instance, before the player is asked or ever.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from ..core.model import Challenge
from ..l1.container import EngineContainer, container_name
from ..l1.manifest import Manifest
from ..l1.router import route
from ..l1.runner import EngineRun, WorkspaceFactory, run_routed

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

    def __post_init__(self) -> None:
        if self.image is not None and self.pack is None:
            raise ValueError("L1 engines in Docker need the pack's folder, to mount it in their containers")

    def routed(self, challenge: Challenge) -> list:
        return route(self.manifests, challenge, self.handouts[challenge.id])

    async def run(self, lane_id: str, challenge: Challenge, *, online: bool = False) -> list[EngineRun]:
        """Run the engines routed to `challenge` for a lane. `online`: in Docker, an engine's
        container joins the bridge network (the lane may reach the challenge's instance at
        once); else it has none. Engines on this machine have its network either way."""
        hits = self.routed(challenge)
        if not hits:
            return []
        lane = lane_id.lower()
        return await run_routed(
            hits,
            self.handouts[challenge.id],
            workdir=self.workdir / lane / "l1",
            flag_format=self.flag_format,
            concurrency=self.concurrency,
            challenge_id=challenge.id,
            workspace_factory=self.containers(lane, "bridge" if online else "none") if self.image is not None else None,
        )

    def containers(self, lane: str, network: str) -> WorkspaceFactory:
        """Makes each engine's container for a lane, on `network`."""
        image, pack = self.image, self.pack
        assert image is not None and pack is not None

        def factory(engine_id: str, root: Path, handout: Path) -> EngineContainer:
            name = container_name(self.workdir.name, lane, engine_id)
            return EngineContainer(root, handout, image=image, name=name, network=network, pack=pack)

        return factory


def result_line(run: EngineRun) -> str:
    """One engine's result, for the lane's context (made safe by the prompt's fence)."""
    res = run.result
    line = f"{run.manifest.id}: {res.status}"
    if res.flags:
        line += f", found {', '.join(res.flags)}"
    if res.notes:
        line += f" ({res.notes})"
    return line
