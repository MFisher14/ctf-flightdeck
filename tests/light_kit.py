"""A light model for the route and recon tests: a fake OpenAI-compatible server (fake_model.py)
that answers each job as a test scripts it, and a deck with flightdeck's agent driver whose run
has that light model for route and recon. Real HTTP, real subprocesses in host workspaces under
tmp_path; nothing in flightdeck is mocked and no real model is called. Challenges are synthetic
(hosts under .test)."""

from __future__ import annotations

import asyncio
import threading
import time
from pathlib import Path

from ctf_flightdeck import light as L
from ctf_flightdeck.agent.client import ModelClient
from ctf_flightdeck.agent.driver import AgentDriver
from ctf_flightdeck.agent.workspace import HostWorkspace
from ctf_flightdeck.clock import RunClock
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.model import ActionKind, Challenge, DeckConfig, EventKind

from fake_model import FakeModelServer, FakeReply, text_reply

FLAG = r"t\{[a-z0-9_]+\}"
MODELS = ("small", "big")
STARTS = {  # how each light job's prompt starts (light.py), so the fake tells them apart
    "category": L.CATEGORY.ask,
    "family": L.FAMILY.ask,
    "instance": L.INSTANCE.ask,
    "recon": L.RECON_TASK.split("\n", 1)[0],
}


async def until(cond, what: str, timeout: float = 15.0) -> None:
    end = time.monotonic() + timeout
    while not cond():
        if time.monotonic() > end:
            raise AssertionError(f"timed out waiting for {what}")
        await asyncio.sleep(0.01)


def job_of(record: dict) -> str:
    """Which job a request to the light model is: category, family, instance, recon, or other."""
    messages = (record.get("json") or {}).get("messages") or []
    user = next((m.get("content") or "" for m in messages if m.get("role") == "user"), "")
    return next((job for job, start in STARTS.items() if user.startswith(start)), "other")


def user_text(record: dict) -> str:
    messages = (record.get("json") or {}).get("messages") or []
    return next((m.get("content") or "" for m in messages if m.get("role") == "user"), "")


class LightModel:
    """A fake light model on 127.0.0.1. Each job gets its scripted answer (text, or a FakeReply
    as it is: an HTTP error, say); with a `gate`, no answer goes out before the gate is set
    (leaving the context sets it)."""

    def __init__(self, answers: dict[str, str | FakeReply], *, gate: threading.Event | None = None,
                 cost: float | None = None, hold: set[str] | None = None) -> None:
        self.answers = dict(answers)
        self.gate = gate
        self.hold = hold  # the jobs the gate holds (None: every job)
        self.cost = cost
        self.server = FakeModelServer(responder=self._respond)

    def _respond(self, record: dict):
        job = job_of(record)
        if self.gate is not None and (self.hold is None or job in self.hold):
            self.gate.wait(60)
        said = self.answers.get(job, "no idea")
        if isinstance(said, FakeReply):
            return said
        return text_reply(said, prompt_tokens=40, completion_tokens=4, cost=self.cost)

    def asked(self) -> list[str]:
        return [job_of(r) for r in self.server.chats()]

    def requests(self, job: str) -> list[dict]:
        return [r for r in self.server.chats() if job_of(r) == job]

    def engine(self, *, timeout: float = 20.0, free: bool = True) -> L.ModelLight:
        """The light engine as build() makes it, but with the client's own time limit well past
        the job's, so a job that runs out of time is the job's TIMEOUT, never an HTTP error.
        `free`: as build() makes it for a server on this machine; False, as for a server on
        another host with no [light] price: a call the API reports no cost for has none known."""
        client = ModelClient(self.server.base_url, None, max_retries=0, timeout=max(4 * timeout, 10.0))
        return L.ModelLight("openai", client, "light/m", timeout=timeout, tokens=L.OPENAI_TOKENS, temperature=0.0,
                            free=free)

    def __enter__(self) -> LightModel:
        self.server.__enter__()
        return self

    def __exit__(self, *exc: object) -> None:
        if self.gate is not None:
            self.gate.set()
        self.server.__exit__(*exc)


def lights(engine: L.Light | None, jobs: tuple[str, ...] = ("route", "recon")) -> L.Lights:
    """The run's light engines, as build_all makes them: one engine shared by `jobs`."""
    return L.Lights(engines=dict.fromkeys(jobs, engine) if engine is not None else {})


def handout(tmp_path: Path, name: str, files: dict[str, str | bytes]) -> Path:
    folder = tmp_path / "board" / name
    folder.mkdir(parents=True)
    for rel, content in files.items():
        target = folder / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content)
    return folder


class Lab:
    """A deck with the agent driver against a fake lanes model and host workspaces in tmp; the
    run's light engines are `lights` (None: no light model)."""

    def __init__(self, tmp_path: Path, lanes: FakeModelServer, handouts: dict[str, Path], *, lights: L.Lights | None = None,
                 urls=None, instance: str = "auto", submit: str = "confirm", compact_at: int | None = 50_000, l1=None,
                 flag_format: str = FLAG, verify=None) -> None:
        self.tmp = tmp_path
        self.handouts = handouts
        self.client = ModelClient(lanes.base_url, "sk-test-not-a-real-key", max_retries=0)
        self.driver = AgentDriver(
            self.client,
            lambda lane, ch: HostWorkspace(tmp_path / "runs" / lane.id / "work", self.handouts[ch.id]),
            run_id="run1",
            files={cid: sorted(p.relative_to(path).as_posix() for p in path.rglob("*") if p.is_file())
                   for cid, path in handouts.items()},
            urls=urls,
            instance=instance,
            compact_at=compact_at,
            l1=l1,
            lights=lights,
        )
        config = DeckConfig(event="t", flag_format=flag_format, models=MODELS, max_lanes=2, submit=submit)
        self.deck = Deck(config, self.driver, RunClock(), verify or (lambda cid, flag: flag == "t{real_one}"))
        self.lights = lights

    def release(self, *challenges: Challenge, dollar_cap: float | None = None) -> None:
        self.deck.release(list(challenges), [QueueEntry(ch.id, "small", dollar_cap=dollar_cap) for ch in challenges])

    def lane(self, cid: str):
        (lane,) = [x for x in self.deck.lanes.values() if x.challenge_id == cid]
        return lane

    def looked(self, cid: str) -> bool:
        """The challenge's first look has started, and every job of it is back."""
        return self.driver.looks.done(cid)

    def warnings(self) -> list:
        return [e for e in self.deck.events if e.kind is EventKind.WARNING and e.data.get("source") == "light"]

    def routes(self) -> list:
        return [e for e in self.deck.events if e.kind is EventKind.ROUTE]

    def spends(self) -> list:
        return [e for e in self.deck.events if e.kind is EventKind.SPEND]

    async def finish(self) -> None:
        await self.driver.shutdown()
        await self.client.aclose()
        if self.lights is not None:
            await self.lights.aclose()


def notes(lane) -> list[str]:
    return [a.text for a in lane.actions if a.kind is ActionKind.NOTE]


def challenge(cid: str, category: str = "misc", description: str = "", **extra) -> Challenge:
    return Challenge(cid, cid.replace("-", " ").title(), category, 100, solves=5, description=description, **extra)
