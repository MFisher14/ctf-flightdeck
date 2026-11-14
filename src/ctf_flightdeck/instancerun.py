"""Instances on demand in a run: which of the platform's containers to start, keep and stop.

A challenge marked on-demand (`Challenge.on_demand`: challenge.json's `"instance":
"on-demand"`, or its CTFd type listed in the event's [instances] types) has no address until
the platform starts its container, and the platform runs only a few per team. So no lane
starts on such a challenge until its instance is up (Deck.wait_for), and this module decides,
with no model, which ones are:

- `plan()` is the rule, pure: stop every instance of ours whose challenge nobody works any
  more (solved, closed, parked: not queued and with no open lane), so its slot is free at
  once; start instances for the challenges that are wanted (queued, or with an open lane) and
  have none, in the deck's own queue order, up to the slots left under `max_running`. A
  running instance of a wanted challenge is never stopped to make room: it is being worked.
- `InstanceRunner` applies it every few seconds from a task on the console's loop
  (`work()`), asking the platform in a worker thread (platform/instances.InstanceClient).

What a start does: the instance's address becomes the challenge's `urls` (in the run's map
and the driver's: http for a web challenge, tcp for any other, unless the plugin gave a URL),
`Challenge.live` is set, and Deck.ready() lets its queued lanes start. They then get it as
any live instance: named in the brief, and a Docker lane's network reaches it and nothing
else. A stop takes the address away and makes the challenge wait again.

Only what this run started is ever stopped. Before a start the plugin is asked for the
challenge's status: an instance that is already up (a teammate's, or one from an earlier
run) is adopted and used, and left running when this run is done with it. In a team the
slots are shared, and stopping a teammate's instance would cut their lane off.

When the platform says no:
- "full" (the team's cap is reached, by teammates' instances this run cannot see): nothing
  is recorded as running, one warning says so while it lasts, and the start is tried again
  after RETRY_FULL seconds.
- any other refusal or error: a warning with the platform's words (once per challenge and
  message), and the next try after a wait that doubles from RETRY_FIRST up to RETRY_MOST.
  The challenge keeps its place in the queue meanwhile; nothing else waits for it.

Expiry. When the plugin says how long an instance lives, it is renewed RENEW_BEFORE seconds
before its end while its challenge is wanted. An instance that ended anyway (the renew was
refused, or the platform stopped it) is started again, and if its address changed the
challenge's open lanes are told so on their transcripts and the player is warned: a Docker
lane's network was fenced to the old address when the lane started, so such a lane is the
player's to kill and queue again.

close() stops every instance this run started. A flightdeck that is killed leaves them to
the platform, which stops them at their expiry.

Nothing here reaches an instance, submits a flag or reads a challenge's files.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable, Mapping, MutableMapping, Sequence
from dataclasses import dataclass, replace

from .core.deck import Deck
from .core.model import Challenge, ChallengeStatus
from .platform.instances import Instance, InstanceError, InstanceRefused
from .text import untrusted

EVERY = 5.0  # seconds between looks at the deck
RENEW_BEFORE = 300.0  # seconds before an instance's end at which it is renewed
RETRY_FULL = 30.0  # seconds before a start is tried again when the team's cap was reached
RETRY_FIRST = 30.0  # seconds before a start that failed is tried again, the first time
RETRY_MOST = 300.0  # and at most
WAITS = "waits for its instance: the platform has not started it yet"
WEB = "web"  # the category code whose instances are web servers


@dataclass(frozen=True)
class Need:
    """One on-demand challenge as plan() sees it."""

    challenge: str
    wanted: bool  # queued, or a lane is open on it, and it is not closed
    running: bool  # its instance is up, as far as this run knows
    ours: bool = True  # this run started it (False: adopted, never stopped here)
    place: int = 0  # its place in line: open lanes first, then the deck's queue order


@dataclass(frozen=True)
class Plan:
    stop: tuple[str, ...]  # instances of ours nobody works any more: stopped first, freeing slots
    start: tuple[str, ...]  # wanted challenges to start now, in order
    waiting: tuple[str, ...]  # wanted challenges with no slot yet


def plan(needs: Sequence[Need], max_running: int) -> Plan:
    """What to stop and start. `max_running` counts every running instance this run knows
    of, adopted ones too: they take the team's slots all the same."""
    if max_running < 1:
        raise ValueError(f"max_running must be at least 1, got {max_running}")
    stop = tuple(n.challenge for n in needs if n.running and not n.wanted and n.ours)
    kept = sum(1 for n in needs if n.running and (n.wanted or not n.ours))
    want = sorted((n for n in needs if n.wanted and not n.running), key=lambda n: (n.place, n.challenge))
    free = max(0, max_running - kept)
    return Plan(stop, tuple(n.challenge for n in want[:free]), tuple(n.challenge for n in want[free:]))


class InstanceRunner:
    """Keeps a run's on-demand instances as plan() says. Everything that touches the deck
    runs on the console's loop; the platform is asked in worker threads."""

    def __init__(
        self,
        deck: Deck,
        client,  # platform.instances.InstanceClient, or anything with its start/status/renew/stop
        *,
        max_running: int,
        urls: Sequence[MutableMapping[str, tuple[str, ...]]],  # every map of challenge id -> urls that lanes and L1 read
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        every: float = EVERY,
    ) -> None:
        self.deck = deck
        self.client = client
        self.max_running = max_running
        self.urls = list(urls)
        self.clock = clock
        self.sleep = sleep
        self.every = every
        self.running: dict[str, Instance] = {}  # challenge id -> its instance, as last known
        self.adopted: set[str] = set()  # running, but not started by this run: never stopped here
        self.retry_at: dict[str, float] = {}  # challenge id -> not before this clock time
        self.failures: dict[str, int] = {}
        self._said: set[tuple[str, str]] = set()  # (challenge id, message) warned of already
        self._full_said = False
        self._renew_refused: set[str] = set()

    # ------------------------------------------------------------------ what the run calls

    def hold(self, challenges: Sequence[Challenge]) -> None:
        """Before these challenges are released: the on-demand ones wait for their instance."""
        for ch in challenges:
            if ch.on_demand and ch.id not in self.running:
                self.deck.wait_for(ch.id, WAITS)

    async def work(self) -> None:
        """Until cancelled: look at the deck, apply the plan, wait."""
        while True:
            try:
                await self.step()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # a bug here must not end the run's instances for good
                self._warn("", f"instances: flightdeck could not plan them this time ({type(exc).__name__}: {exc})")
            await self.sleep(self.every)

    async def step(self) -> Plan:
        """One look: stop what nobody works, start what is wanted, renew what ends soon."""
        todo = plan(self.needs(), self.max_running)
        for cid in todo.stop:
            await self._stop(cid)
        for cid in todo.start:
            if self.clock() >= self.retry_at.get(cid, 0.0):
                await self._start(cid)
        await self._renew()
        return todo

    async def close(self) -> list[str]:
        """Stop every instance this run started. What could not be stopped, said for the player."""
        left: list[str] = []
        for cid in [c for c in self.running if c not in self.adopted]:
            try:
                await asyncio.to_thread(self.client.stop, cid)
            except InstanceError as exc:
                left.append(f"the instance of {self._name(cid)} may still run on the platform: {exc}")
            self.running.pop(cid, None)
        return left

    # ------------------------------------------------------------------ the deck, read

    def needs(self) -> list[Need]:
        deck = self.deck
        order = {entry.challenge: i for i, entry in reversed(list(enumerate(deck.queue)))}
        out = []
        for ch in deck.challenges.values():
            if not ch.on_demand:
                continue
            lanes = any(not lane.finished for lane in deck.lanes_on(ch.id))
            wanted = not ch.closed and ch.status is not ChallengeStatus.BLOCKED and (lanes or ch.id in order)
            place = -1 if lanes else order.get(ch.id, len(order))
            out.append(Need(ch.id, wanted, ch.id in self.running, ch.id not in self.adopted, place))
        return out

    # ------------------------------------------------------------------ the platform, asked

    async def _start(self, cid: str) -> None:
        ch = self.deck.challenges[cid]
        mine = cid in self.running and cid not in self.adopted  # ours, and thought ended: asked about again
        try:
            there = await asyncio.to_thread(self.client.status, cid)
            got = there if there is not None else await asyncio.to_thread(self.client.start, cid)
        except InstanceRefused as exc:
            if exc.full:
                self.retry_at[cid] = self.clock() + RETRY_FULL
                if not self._full_said:
                    self._full_said = True
                    self.deck.warn(
                        f"instances: the platform's cap on running instances is reached ({exc}); {self._name(cid)} waits, "
                        f"and flightdeck asks again every {RETRY_FULL:g} s. A teammate's instances count too",
                        challenge=cid, data={"source": "instances", "full": True},
                    )
                return
            self._failed(cid, str(exc))
            return
        except InstanceError as exc:
            self._failed(cid, str(exc))
            return
        self._full_said = False
        self.failures.pop(cid, None)
        self.retry_at.pop(cid, None)
        adopted = there is not None and not mine
        if adopted:
            self.adopted.add(cid)
        before = self.running.get(cid)
        if mine and there is not None and got.expires_at is not None and got.expires_at <= self.clock():
            got = replace(got, expires_at=None)  # the platform still runs it past the end it named: its end is not known
        self.running[cid] = got
        url = got.url(web=ch.category == WEB)
        for target in self.urls:
            target[cid] = (url,)
        ch.live = True
        if before is None or (before.host, before.port) != (got.host, got.port):
            how = "was already running (a teammate's, or an earlier run's: flightdeck will not stop it)" if adopted else "started"
            self.deck.warn(f"instances: the instance of {self._name(cid)} {how}: {untrusted(url, one_line=True)}",
                           challenge=cid, data={"source": "instances", "url": url, "adopted": adopted})
        if before is not None and (before.host, before.port) != (got.host, got.port):
            self._moved(cid, url)
        self.deck.ready(cid)

    async def _stop(self, cid: str) -> None:
        try:
            await asyncio.to_thread(self.client.stop, cid)
        except InstanceError as exc:
            self._warn(cid, f"instances: could not stop the instance of {self._name(cid)}: {exc}; it holds one of the team's slots "
                            "until the platform ends it")
        self._gone(cid)

    def _gone(self, cid: str) -> None:
        self.running.pop(cid, None)
        self.adopted.discard(cid)
        self._renew_refused.discard(cid)
        for target in self.urls:
            target[cid] = ()
        ch = self.deck.challenges.get(cid)
        if ch is not None:
            ch.live = False
            if not ch.closed:
                self.deck.wait_for(cid, WAITS)

    async def _renew(self) -> None:
        now = self.clock()
        wanted = {n.challenge for n in self.needs() if n.wanted}
        for cid, instance in list(self.running.items()):
            if instance.expires_at is None or cid not in wanted:
                continue
            if now >= instance.expires_at:  # it ended: asked about, and started again when it is gone
                if now >= self.retry_at.get(cid, 0.0):
                    self._renew_refused.discard(cid)
                    await self._start(cid)
                continue
            if instance.expires_at - now > RENEW_BEFORE or cid in self._renew_refused:
                continue
            try:
                renewed = await asyncio.to_thread(self.client.renew, cid)
                if renewed is None:
                    renewed = await asyncio.to_thread(self.client.status, cid)
            except InstanceError as exc:
                self._renew_refused.add(cid)
                self._warn(cid, f"instances: could not renew the instance of {self._name(cid)}: {exc}; flightdeck starts it again "
                                "when it ends")
                continue
            if renewed is not None:
                self.running[cid] = renewed

    # ------------------------------------------------------------------ said to the player

    def _failed(self, cid: str, why: str) -> None:
        count = self.failures.get(cid, 0) + 1
        self.failures[cid] = count
        wait = min(RETRY_FIRST * (2 ** (count - 1)), RETRY_MOST)
        self.retry_at[cid] = self.clock() + wait
        self._warn(cid, f"instances: could not start the instance of {self._name(cid)}: {why}; its lanes wait, and flightdeck "
                        "tries again later (queued challenges behind it go on)")

    def _moved(self, cid: str, url: str) -> None:
        shown = untrusted(url, one_line=True)
        for lane in self.deck.lanes_on(cid):
            if not lane.finished:
                self.deck.note(lane.id, f"this challenge's instance was started again and is now at {shown}")
        self.deck.warn(
            f"instances: the instance of {self._name(cid)} was started again at another address ({shown}). A Docker lane's "
            "network still reaches only the old one: kill such a lane and queue the challenge again",
            challenge=cid, data={"source": "instances", "moved": True},
        )

    def _warn(self, cid: str, text: str) -> None:
        if (cid, text) in self._said:
            return
        self._said.add((cid, text))
        self.deck.warn(text, challenge=cid or None, data={"source": "instances"})

    def _name(self, cid: str) -> str:
        ch = self.deck.challenges.get(cid)
        return untrusted(ch.name if ch is not None else cid, one_line=True)


def on_demand(challenges: Sequence[Challenge], types: Sequence[str]) -> list[Challenge]:
    """Mark the challenges whose platform type is one of the event's [instances] types as
    on-demand (those the board marked already stay so); the ones that are."""
    kinds = set(types)
    for ch in challenges:
        if ch.platform_type and ch.platform_type in kinds:
            ch.on_demand = True
    return [ch for ch in challenges if ch.on_demand]
