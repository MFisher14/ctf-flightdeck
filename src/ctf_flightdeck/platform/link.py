"""What a run asks of a platform it submits to and reads the solved list from during play.

A link is the deck's submitter (called with a flag the deck lets through: it only queues it,
and answers later through Deck.platform_verdict) and the reader of the platform's solved list.
The run (run.py) holds its links in `Run.links` and treats them alike: it starts their tasks
when the board is released, leaves the challenges they hold out of the queue, closes what the
platform listed as solved before the run, and at the end names the flags that were still on
their way and closes them.

GameMasterLink (platform/gamemaster_run.py) and PluginLink (platform/plugin_run.py) are the
two. A CTFd board is older than this and is wired into the run by itself (run._Submits).
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Protocol, runtime_checkable

from ..core.deck import Deck


@runtime_checkable
class PlatformLink(Protocol):
    deck: Deck | None  # set once the deck exists
    needs_human: Callable[[str], None] | None  # the run's: the platform needs a human (autopilot disengages)

    def __call__(self, lane_id: str, challenge_id: str, flag: str) -> None:
        """Take a flag for the platform: queued, never sent from here."""

    def tasks(self) -> list[asyncio.Task]:
        """The link's background tasks, started on the running loop: the run cancels them at its end."""

    def held(self) -> set[str]:
        """The board ids the platform lists as solved: not to queue."""

    def apply_solved(self, *, before_run: bool = False) -> None:
        """Close each board challenge the platform lists as solved that this run did not solve."""

    def unsent(self) -> list[str]:
        """After the tasks have stopped: the flags that were on their way, said for the player."""

    async def aclose(self) -> None:
        """Close what the link holds open."""
