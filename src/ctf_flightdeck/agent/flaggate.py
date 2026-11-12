"""flagcheck: the light model's hold before an auto-submit, never a submit (D15, P15; the
function eval of 2026-11-11).

Today a flag a lane claims goes out without the player only when all of this holds: submit is
"auto"; the lane claims it (the model's submit_flag call, a coding-agent CLI's FLAG line); the
challenge's own text does not hold it (its description, the handout as it came: planted); the
platform does not count the tries at the challenge's flag (Challenge.limited); and the deck
neither knows it is not the flag nor has it waiting or on its way already. For such a flag,
and only such (FlagGate.covers), a run whose [light] jobs list flagcheck first asks the light
model whether it is the challenge's real flag or a stand-in (a format example, a local-testing
value, a decoy, another challenge's flag, the lane's own text coming back). The flag leaves the
lane's report while it is checked, and the lane goes on meanwhile; once the answer is in, it
goes to the deck as it would have gone at once (a claim), unless the light model said
"stand-in": then it is not claimed, so it waits for the player, and a note on the lane names
the light model.

It can only hold. It submits nothing and releases nothing held today (a planted flag, a match
scraped from output, a flag the model wrote without submit_flag, a flag of a challenge whose
tries are counted): those never reach it. Under submit confirm it checks nothing. A failure, a
refusal, a timeout, an unsure answer or one outside the options holds nothing: the flag goes as
it would without the check, and the run says so once per kind of failure, naming the light
model. A lane that gives up while a flag of it is under check ends only once the answer is in
(its flag first), so the flag is never lost to the check; a lane that ends otherwise (killed, a
budget declined) loses the flag it was checking, and the player is told which.

The candidate and where the lane found it (`where`: the newest tool output of the lane that
holds the flag, WHERE_CHARS characters around it) are untrusted: light.render folds them into
the model's fence, or into a decision model's state alone; nothing they say can do more than
pick one of the two options, and either option can at most hold a flag.

What the check spent is the lane's (a SPEND event, why "the flag check (<engine> <model>)").
"""

from __future__ import annotations

import asyncio
import re
import time
from collections import deque
from collections.abc import Callable
from dataclasses import replace
from typing import TYPE_CHECKING

from .. import credentials
from ..core.driver import TurnReport
from ..core.model import Challenge
from ..light import (
    ERROR,
    FLAG_CHOICES,
    FLAG_QUESTION,
    FLAGCHECK,
    NO_ANSWER,
    OUTSIDE,
    REFUSED,
    STAND_IN,
    TIMEOUT,
    UNSURE,
    Answer,
    Light,
    shown,
)
from . import prompts

if TYPE_CHECKING:
    from ..config import Config
    from ..core.deck import Deck
    from ..light import Lights

WHERE_CHARS = 400  # of the lane's output around the flag, as the function eval's cases show it
ACTION_CHARS = 200  # of the step's command, on the line before its output
MAX_OUTPUTS = 64  # a lane's newest tool outputs kept for `where`
OUTPUT_CHARS = 1024 * 1024  # characters of them kept in all (the newest one whole up to this)
GRACE = 1.0  # seconds past the light model's own time limit before the check stops waiting for it
SUBMITTED_ONLY = "the model's own submit_flag call; no tool output of this lane contains it"
CLAIMED_ONLY = "the agent's own FLAG line; no tool output of this lane contains it"

WHAT = {  # a failed check, for the player's warning
    REFUSED: "declined to check",
    ERROR: "failed to check",
    TIMEOUT: "took too long to check",
    NO_ANSWER: "gave no answer about",
    OUTSIDE: "answered neither real nor stand-in about",
    UNSURE: "was unsure about",
}

Report = Callable[[TurnReport], None]
"""How a check hands the deck its outcome: the driver's own report path for the lane, which
drops what comes after the lane's end."""


class Outputs:
    """A lane's newest tool outputs with the step that printed each: where a flag it claims
    later was found (FlagGate.where). At most MAX_OUTPUTS of them and OUTPUT_CHARS characters in
    all; the oldest go first."""

    def __init__(self, *, most: int = MAX_OUTPUTS, chars: int = OUTPUT_CHARS) -> None:
        self.most = most
        self.chars = chars
        self._items: deque[tuple[str, str]] = deque()
        self._size = 0

    def add(self, action: str, text: str) -> None:
        if not text:
            return
        text = text[: self.chars]
        self._items.append((action, text))
        self._size += len(text)
        while len(self._items) > self.most or (self._size > self.chars and len(self._items) > 1):
            _, old = self._items.popleft()
            self._size -= len(old)

    def where(self, flag: str, nowhere: str) -> str:
        """The newest output that holds `flag`, as its step and WHERE_CHARS characters around
        the flag; `nowhere` when none does."""
        for action, text in reversed(self._items):
            at = text.rfind(flag)
            if at >= 0:
                return around(action, text, at, len(flag))
        return nowhere


def around(action: str, text: str, at: int, length: int, chars: int = WHERE_CHARS) -> str:
    """`action` (the step: "$ cat flag.txt") on a line of its own, then at most `chars`
    characters of its output `text` around the flag found at `at` (the whole flag, however
    long), "[...]" marking a cut."""
    room = max(chars, length)
    start = max(0, at - (room - length) // 2)
    end = min(len(text), start + room)
    start = max(0, end - room)
    window = ("[...]" if start > 0 else "") + text[start:end] + ("[...]" if end < len(text) else "")
    head = prompts.one(action, ACTION_CHARS) if action.strip() else ""
    return f"{head}\n{window}" if head else window


class FlagGate:
    """A run's flagcheck: its light engine (light.build_all's, closed by the run's Lights, never
    here) and the time a check may take ([light.flagcheck] timeout, else [light]'s). One per run,
    shared by the driver's lanes: it holds which flags each lane has under check, and which
    kinds of failure the player has been told about."""

    def __init__(self, light: Light, *, timeout: float) -> None:
        if not light.does(FLAGCHECK):
            raise ValueError(f"{light.label} does not check flags")
        if not timeout > 0:
            raise ValueError(f"timeout must be a positive number of seconds, got {timeout}")
        self.light = light
        self.timeout = timeout
        self.warned: set[str] = set()  # the kinds of failure said to the player
        self.problems: list[str] = []  # flightdeck bugs met handing a checked flag to the deck, for the run's end
        self._checks: dict[str, dict[str, asyncio.Task[None]]] = {}  # lane id -> flag -> its check
        self._gave_up: dict[str, str] = {}  # lane id -> why it gave up, held until its checks are in

    # ------------------------------------------------------------------ what it covers

    def covers(self, deck: Deck, lane_id: str, flag: str) -> bool:
        """Whether `flag`, claimed by the lane and not the challenge's own text (the caller
        knows both), would go out without the player now, as Deck._candidate would send it:
        submit auto, the whole flag format, a challenge open and whose tries the platform does
        not count, not known not to be the flag, and not waiting for the player on this lane
        or on its way to the platform already."""
        lane = deck.lanes.get(lane_id)
        if lane is None or lane.finished or deck.config.submit != "auto":
            return False
        ch = deck.challenges[lane.challenge_id]
        if ch.closed or ch.limited or not re.fullmatch(deck.config.flag_format, flag):
            return False
        if deck.not_flag(ch.id, flag) is not None:
            return False
        queued = ([lane.pending] if lane.pending is not None else []) + lane.waiting
        if any(p.flag == flag for p in queued):
            return False
        return all(sent != flag for _, sent in deck.submitting(ch.id))

    def under_check(self, lane_id: str, flag: str) -> bool:
        return flag in self._checks.get(lane_id, {})

    def checking(self, lane_id: str) -> bool:
        """Whether a flag of the lane is under check."""
        return bool(self._checks.get(lane_id))

    def giving_up(self, lane_id: str) -> bool:
        """The lane gave up while a flag of it was under check: it ends once the check is in."""
        return lane_id in self._gave_up

    # ------------------------------------------------------------------ checking a flag

    def start(self, deck: Deck, lane_id: str, challenge: Challenge, flag: str, where: str, report: Report) -> None:
        """Check `flag` in the background (the caller has made sure it is covered and not under
        check), and hand it to the deck through `report` once the answer is in: claimed, as it
        would have gone at once, or, for a stand-in, not claimed, so that it waits for the
        player. Nothing waits for it."""
        task = asyncio.get_running_loop().create_task(
            self._check(deck, lane_id, challenge, flag, where, report), name=f"flightdeck flagcheck {lane_id}"
        )
        self._checks.setdefault(lane_id, {})[flag] = task
        deck.note(lane_id, f"the light model ({self.light.label}) checks {flag} before it goes out without you")

    async def ask(self, challenge: Challenge, flag: str, where: str, flag_format: str) -> Answer:
        """The light model's answer on `flag`: one flagcheck question, within the time limit,
        the flag and where it was found as data (a credential-shaped value in that output taken
        out first: the light model may be another provider's than the lane's). Never raises:
        whatever goes wrong is a failed answer, so the flag goes as it would without the check."""
        data = {
            "name": challenge.name,
            "category": challenge.category,
            "flag_format": flag_format,
            "description": challenge.description,
            "candidate": flag,
            "where": credentials.redact(where, keep=(flag,)),
        }
        begun = time.perf_counter()
        try:
            async with asyncio.timeout(self.timeout + GRACE):
                return await self.light.ask_choice(FLAGCHECK, data, FLAG_QUESTION, FLAG_CHOICES)
        except TimeoutError:
            return Answer(None, failure=TIMEOUT, why=f"no answer within {self.timeout:g} s",
                          seconds=time.perf_counter() - begun)
        except Exception as exc:  # the engine broke: this check's failure, never the flag's loss
            return Answer(None, failure=ERROR, why=f"the check broke: {type(exc).__name__}: {exc}",
                          seconds=time.perf_counter() - begun)

    @staticmethod
    def holds(answer: Answer) -> bool:
        """Only a stand-in, answered: anything else (a real flag, a failure, a refusal, a
        timeout, an unsure answer, one outside the options) holds nothing."""
        return answer.ok and answer.choice == STAND_IN

    async def _check(self, deck: Deck, lane_id: str, challenge: Challenge, flag: str, where: str, report: Report) -> None:
        answer = await self.ask(challenge, flag, where, deck.config.flag_format)
        checks = self._checks.get(lane_id)
        if checks is None or checks.get(flag) is not asyncio.current_task():
            return  # the lane ended meanwhile (stop): it said what became of the flag
        del checks[flag]  # no longer under check: from here the deck has it
        try:
            self._settle(deck, lane_id, flag, answer, report)
        except Exception as exc:  # a flightdeck bug: the flag must not vanish quietly
            problem = f"{lane_id}: flightdeck could not hand {flag} to the deck after its check: {type(exc).__name__}: {exc}"
            self.problems.append(problem)
            deck.warn(f"{problem}; it was not submitted: submit it by hand if you think it is the flag",
                      challenge=challenge.id, data={"source": "light", "job": FLAGCHECK, "lane": lane_id, "error": problem})
        finally:
            if not checks and self._checks.get(lane_id) is checks:
                del self._checks[lane_id]
                why = self._gave_up.pop(lane_id, None)
                if why is not None:  # the lane gave up meanwhile: now that its flag is with the deck, it may end
                    report(TurnReport(turn=False, gave_up=why))

    def _settle(self, deck: Deck, lane_id: str, flag: str, answer: Answer, report: Report) -> None:
        """The check is in: what it spent, then the flag, to the deck through `report`."""
        lane = deck.lanes.get(lane_id)
        if lane is None or lane.finished:
            return
        if answer.spent:
            report(TurnReport(turn=False, tokens=answer.tokens, cached_tokens=answer.cached_tokens, dollars=answer.cost,
                              why=f"the flag check ({self.light.label})", model=self.light.model or None))
        held = self.holds(answer)
        if held:
            deck.note(lane_id, f"the light model ({self.light.label}) calls {flag} a stand-in, not this challenge's real "
                               "flag (a format example, a local-testing value, a decoy, another challenge's flag or the "
                               "lane's own text coming back), so it waits for you instead of going out on its own")
        elif not answer.ok:
            self._warn(deck, lane_id, lane.challenge_id, flag, answer)
        report(TurnReport(turn=False, flag=flag, claimed=not held))

    def _warn(self, deck: Deck, lane_id: str, challenge_id: str, flag: str, answer: Answer) -> None:
        if answer.failure in self.warned:
            return
        self.warned.add(answer.failure)
        what = WHAT.get(answer.failure, "failed to check")
        kind = "for an unsure answer" if answer.failure == UNSURE else "for this kind of failure"
        deck.warn(
            f"{lane_id}: the light model ({self.light.label}) {what} {flag}: {shown(answer.why) or 'no reason given'}. "
            f"The rules' answer stands: the flag goes as it would without the check. Said once {kind}; the light model "
            "checks the next flag all the same.",
            challenge=challenge_id,
            data={"source": "light", "job": FLAGCHECK, "engine": self.light.engine, "model": self.light.model,
                  "failure": answer.failure, "lane": lane_id},
        )

    # ------------------------------------------------------------------ a lane's end

    def defer_gave_up(self, lane_id: str, report: TurnReport) -> TurnReport | None:
        """A lane that gives up while a flag of it is under check ends only once the check is in,
        after its flag has reached the deck (which then holds the lane open for it, as for a
        flag on its way to the platform). What of `report` goes to the deck now; None: nothing."""
        if report.gave_up is None or not self.checking(lane_id):
            return report
        self._gave_up.setdefault(lane_id, report.gave_up)
        rest = replace(report, gave_up=None)
        return None if rest == TurnReport(turn=False) else rest

    def stop(self, deck: Deck, lane_id: str) -> None:
        """The lane has ended: its checks stop. A flag it still had under check was never
        submitted: the player hears which, unless its challenge is closed (nothing to submit)."""
        checks = self._checks.pop(lane_id, {})
        self._gave_up.pop(lane_id, None)
        for task in checks.values():
            if task is not asyncio.current_task():
                task.cancel()
        lane = deck.lanes.get(lane_id)
        if not checks or lane is None:
            return
        flags = list(checks)
        try:
            asyncio.get_running_loop().call_soon(self._lost, deck, lane_id, lane.challenge_id, flags)
        except RuntimeError:  # no loop: said at once
            self._lost(deck, lane_id, lane.challenge_id, flags)

    def _lost(self, deck: Deck, lane_id: str, challenge_id: str, flags: list[str]) -> None:
        """After the deck has finished ending the lane (stop runs inside it)."""
        ch = deck.challenges.get(challenge_id)
        if ch is None or ch.closed:
            return
        named = ", ".join(flags)
        deck.warn(
            f"{lane_id} ended while the light model ({self.light.label}) checked {named}, so "
            f"{'it was' if len(flags) == 1 else 'they were'} not submitted: submit it by hand if you think it is the flag",
            challenge=challenge_id,
            data={"source": "light", "job": FLAGCHECK, "lane": lane_id, "flags": flags},
        )

    async def aclose(self) -> list[str]:
        """The run ends: every check stops (before the run closes the light engine). Returns a
        line for each flag still under check, never submitted, and for each problem met, for the
        run's closing problems."""
        lost = [*self.problems]
        self.problems.clear()
        lost += [f"{lane_id}: {flag} was still under the light model's check when the run ended; it was not submitted"
                 for lane_id, checks in self._checks.items() for flag in checks]
        tasks = [task for checks in self._checks.values() for task in checks.values()]
        self._checks.clear()
        self._gave_up.clear()
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        return lost


# ---------------------------------------------------------------------- a run's flag check


def from_lights(config: Config, lights: Lights) -> tuple[FlagGate | None, str]:
    """The run's flag check, and a line for the player about it ("" for none): None when
    [light] jobs leaves flagcheck out, or its engine was not made for this run (could not be
    made: lights.notes says why; or the run gave it nothing to do: run._flagcheck_idle)."""
    from ..config import light_for
    from ..light import ANTHROPIC, OPENAI, on_this_machine

    if FLAGCHECK not in config.light_jobs:
        return None, ""
    engine = lights.get(FLAGCHECK)
    if engine is None:
        return None, ""
    spec = light_for(config, FLAGCHECK)
    note = (f"light model: {engine.label} checks each flag a lane claims before it goes out without you (submit auto): "
            "one it calls a stand-in waits for you, and it never submits a flag; when it fails, refuses or times out, "
            "the flag goes as it would without the check")
    unpriced = "; no price for it in your config, so its calls are unpriced"
    if spec.price is None and spec.engine == ANTHROPIC:
        note += unpriced + ": a dollar-capped lane asks you once before it carries on without its cap"
    elif spec.price is None and spec.engine == OPENAI and not on_this_machine(spec.base_url):
        note += unpriced + " unless the API reports their cost: a dollar-capped lane may ask you once"
    return FlagGate(engine, timeout=spec.timeout), note
