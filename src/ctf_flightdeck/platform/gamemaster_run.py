"""A Game Master board in a run: the deck's submitter for its answers, and its solved list read back.

`flightdeck play BOARD --event EVENT.toml`, with an event profile whose platform is
"gamemaster", plays a board that `flightdeck gm pull` wrote (run.py). A run pulls nothing and
starts no attempt: it submits answers under the profile's submit policy and reads what the
Game Master lists as solved. GameMasterLink is both, on the console's loop:

- the deck's submitter (Deck(submitter=link)): a flag the deck lets through (it matched the
  event's flag format, and under "confirm" the player approved it; the wrong-answer stop
  holds as for any platform) is queued, and one worker task (work()) sends each in turn to
  where its board challenge's answer goes (gm.json: the Game Master's challenge id and answer
  id), one POST each. What is sent is answer_of(the flag format, the flag): the format's
  group named "answer", else the whole flag. The Game Master's word reaches the deck through
  Deck.platform_verdict: CORRECT and accepted are right (accepted: that answer is banked, and
  the attempt's other answers are other board challenges), incorrect is wrong, and everything
  else is no verdict, never a wrong answer: the player then submits it by hand and says how
  it went, a warning says why, and autopilot is told the platform needs a human
  (`needs_human`). already_solved closes the challenge, and every board challenge of the same
  attempt, as the platform's solve. The flag the Game Master gives with CORRECT is kept out of
  everything flightdeck shows or logs: the solve is on the Game Master.
- a rate limit (HTTP 429) judged nothing, so the same answer is sent again, as for CTFd
  (docs/DECISIONS.md, P33): after the wait the Game Master asks (Retry-After, at most
  RESEND_MAX) or RESEND_WAIT, up to RESENDS more times, saying so on the lane; answers queued
  behind it wait. Never for a challenge whose tries the board counts. After the last refused
  send the answer goes back to the player.
- the solved list (watch()): every `solves_seconds` the Game Master's list is read, and each
  board challenge of an attempt it lists as solved, that this run did not solve, is closed
  (Deck.platform_solved), but one whose answer is on its way (the solve may be that answer's)
  or that waits for the player's word on a hand submit. A read that fails is a warning, once
  while the same failure lasts, and after PLATFORM_FAILURES in a row autopilot is told.

The token lives in the client only. Nothing here prints or logs it, and the client's errors
never hold it.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable, Collection, Mapping

from ..core.deck import Deck
from ..core.model import PendingKind
from ..text import untrusted
from .gamemaster import RATE_LIMITED, Address, GameMasterClient, GameMasterError, Submitted, answer_of, unjudged

WHO = "your account"  # who solved what the Game Master lists as solved: it does not say more
SOLVES_SECONDS = 60.0  # the Game Master's list is read this often
SUBMIT_SECONDS = 30.0  # an answer to a submission that is not all in by then is not known
PLATFORM_FAILURES = 3  # the list failing this many times in a row is the platform failing: autopilot is told
SOURCE = {"source": "gamemaster"}  # on every warning from here


async def listed_solved(url: str, token: str) -> set[str]:
    """The Game Master ids its list says are solved, read once with a client of its own (for
    the start of a run: it also shows the URL and the token work). GameMasterError when the
    list cannot be read; ValueError for a URL or token that cannot be used."""
    async with GameMasterClient(url, token) as client:
        return {row.id for row in await client.challenges() if row.solved}


class GameMasterLink:
    """A Game Master board during a run (see the module's words). Set `deck` once the deck
    exists; use it on the console's loop only."""

    RESENDS = 3  # more sends of an answer the Game Master rate-limited
    RESEND_WAIT = 65.0  # seconds, when the Game Master names no wait
    RESEND_MAX = 300.0  # the longest wait taken from the Game Master's Retry-After

    def __init__(
        self,
        client: GameMasterClient,
        ids: Mapping[str, Address],
        *,
        solved: Collection[str] = (),
        solves_seconds: float = SOLVES_SECONDS,
        submit_seconds: float = SUBMIT_SECONDS,
    ) -> None:
        if not solves_seconds > 0 or not submit_seconds > 0:
            raise ValueError("solves_seconds and submit_seconds must be positive numbers of seconds")
        self.client = client
        self.ids = dict(ids)  # board id -> where its answer goes
        self.solved = set(solved)  # the Game Master ids it last listed as solved, and those it answered already_solved
        self.answered: set[str] = set()  # board ids the Game Master answered already_solved for
        self.solves_seconds = solves_seconds
        self.submit_seconds = submit_seconds
        self.deck: Deck | None = None
        self.needs_human: Callable[[str], None] | None = None  # the run's: the platform needs a human (autopilot disengages)
        self.queue: asyncio.Queue[tuple[str, str, str]] = asyncio.Queue()  # (lane, board id, flag) to send, in order
        self.sending: tuple[str, str, str] | None = None  # the one sent now, until its answer is applied
        self.errors: list[str] = []  # bookkeeping that failed (a flightdeck bug), shown when the run ends
        self.sleep: Callable[[float], Awaitable[None]] = asyncio.sleep  # the wait before an answer is sent again
        self._said = ""  # the list's failure last warned of: said once while it lasts
        self._failures = 0  # reads of the list that failed in a row

    def __call__(self, lane_id: str, challenge_id: str, flag: str) -> None:
        self.queue.put_nowait((lane_id, challenge_id, flag))

    def tasks(self) -> list[asyncio.Task]:
        """The link's two background tasks, started on the running loop: the run cancels them at its end."""
        return [
            asyncio.create_task(self.work(), name="flightdeck Game Master submits"),
            asyncio.create_task(self.watch(), name="flightdeck Game Master solves"),
        ]

    def held(self) -> set[str]:
        """The board ids of the attempts the Game Master lists as solved: not to queue."""
        return {cid for cid, address in self.ids.items() if address.challenge in self.solved}

    async def aclose(self) -> None:
        await self.client.aclose()

    # ------------------------------------------------------------------ answers to the Game Master

    async def work(self) -> None:
        """Send each answer in turn, and apply the Game Master's word on this loop. Cancelled at shutdown."""
        while True:
            item = await self.queue.get()
            self.sending = item
            lane_id, challenge_id, flag = item
            outcome = await self._send(lane_id, challenge_id, flag)
            try:
                self.answer(lane_id, challenge_id, flag, outcome)
            except Exception as exc:  # a bug: said now and at the end, and the next answer still goes
                problem = f"Game Master: could not apply its answer to {_show(flag)}: {type(exc).__name__}: {exc}"
                self.errors.append(problem)
                with contextlib.suppress(Exception):
                    self.deck.warn(problem, challenge=challenge_id, data=SOURCE)
            self.sending = None

    async def _send(self, lane_id: str, challenge_id: str, flag: str) -> Submitted | str:
        """The Game Master's word on the flag, after the resends of a rate limit; or why there is none."""
        assert self.deck is not None
        address = self.ids.get(challenge_id)
        if address is None:
            return (f"{_show(challenge_id)} was not pulled from the Game Master, so flightdeck has nowhere to send its "
                    "answer: submit it by hand, then say whether it was accepted")
        value = answer_of(self.deck.config.flag_format, flag)
        if value is None:  # the deck lets through only what matches the format: a flightdeck bug, and nothing is sent
            return f"flightdeck found no answer to send in {_show(flag)} (it does not match the flag format); it was not sent"
        sends = 0
        while True:
            try:
                result = await asyncio.wait_for(self.client.submit(address.challenge, {address.answer: value}), self.submit_seconds)
            except GameMasterError as exc:
                return str(exc)
            except TimeoutError:
                return (f"no complete answer from the Game Master within {self.submit_seconds:g} s; the answer may have "
                        "reached it: check the challenge there before submitting it again")
            except Exception as exc:  # a bug in the client: the outcome is not known, and the worker goes on
                return (f"flightdeck could not submit it ({type(exc).__name__}: {exc}); it may have reached the Game "
                        "Master: check the challenge there before submitting it again")
            sends += 1
            wait = self.resend_after(challenge_id, result) if sends <= self.RESENDS else None
            if wait is None:
                return result
            with contextlib.suppress(Exception):  # the note is a courtesy: the resend does not hang on it
                self.deck.note(lane_id, (
                    f"the Game Master rate-limited the submission of {_show(flag)} and did not check it; flightdeck sends "
                    f"it again in {wait:g}s (send {sends + 1} of {self.RESENDS + 1})"
                ))
            await self.sleep(wait)

    def resend_after(self, challenge_id: str, result: Submitted) -> float | None:
        """How long to wait before sending the answer again, or None when it is not sent again:
        only a rate limit, at a challenge whose tries nobody counts."""
        if result.word != RATE_LIMITED:
            return None
        ch = self.deck.challenges.get(challenge_id) if self.deck is not None else None
        if ch is None or ch.limited:
            return None
        if result.retry_after is None:
            return self.RESEND_WAIT
        return min(result.retry_after + 1.0, self.RESEND_MAX)

    def answer(self, lane_id: str, challenge_id: str, flag: str, outcome: Submitted | str) -> None:
        """The Game Master's word on a flag (or why there is none), on the deck's thread: the
        link's bookkeeping, then the deck's."""
        deck = self.deck
        assert deck is not None
        address = self.ids.get(challenge_id)
        if isinstance(outcome, Submitted) and outcome.ok is not None:
            if outcome.word == "accepted":
                left = "" if outcome.remaining is None else f", {outcome.remaining} more of the attempt's answers wanted"
                detail = f"accepted{left}"
            else:
                detail = "CORRECT" if outcome.ok else "incorrect"
            deck.platform_verdict(lane_id, flag, outcome.ok, detail)
            if outcome.word == "CORRECT" and address is not None:
                self.solved.add(address.challenge)  # the whole attempt: its other answers' challenges close with it
                self.apply_solved()
            return
        if isinstance(outcome, Submitted) and outcome.word == "already_solved" and address is not None:
            self.answered.add(challenge_id)
            self.solved.add(address.challenge)
            deck.platform_verdict(lane_id, flag, None, unjudged(outcome))
            self.apply_solved()
            return
        why = unjudged(outcome) if isinstance(outcome, Submitted) else outcome
        ch = deck.challenges.get(challenge_id)
        name = _show(ch.name if ch is not None else challenge_id)
        deck.warn(f"the Game Master did not judge {_show(flag)} for {name}: {why}", challenge=challenge_id, data=SOURCE)
        deck.platform_verdict(lane_id, flag, None, why)
        if self.needs_human is not None:
            self.needs_human(f"the Game Master did not judge an answer: {why}")  # after the deck has it back with the player

    def unsent(self) -> list[str]:
        """After the worker has stopped: the answers on their way to the Game Master when the
        run ended, said for the player, made safe to print. The one being sent may have
        reached it; the others did not leave flightdeck."""
        deck = self.deck
        out: list[str] = list(self.errors)

        def named(lane_id: str, challenge_id: str, flag: str) -> str:
            ch = deck.challenges.get(challenge_id) if deck is not None else None
            return f"{_show(flag)} ({lane_id}, {_show(ch.name if ch is not None else challenge_id)})"

        if self.sending is not None:
            out.append(
                f"Game Master: {named(*self.sending)} was on its way to the Game Master when the run ended, so it is not "
                "known to have been submitted: check the challenge there before you submit it again"
            )
        while not self.queue.empty():
            out.append(f"Game Master: {named(*self.queue.get_nowait())} was not submitted: it was waiting to go to the "
                       "Game Master when the run ended")
        if deck is not None:
            for challenge_id in deck.challenges:
                for lane_id, flag in deck.submitting(challenge_id)[1:]:
                    out.append(
                        f"Game Master: {named(lane_id, challenge_id, flag)} was not submitted: it was waiting for the "
                        "answer to another flag of that challenge when the run ended"
                    )
        return out

    # ------------------------------------------------------------------ the solved list

    async def watch(self) -> None:
        """Read the Game Master's list every `solves_seconds` and close what it lists as solved.
        Cancelled at shutdown."""
        while True:
            await asyncio.sleep(self.solves_seconds)
            try:
                rows = await self.client.challenges()
            except Exception as exc:  # GameMasterError, or a bug: say so, and read again later
                self._failed(exc)
                continue
            self._said, self._failures = "", 0
            self.solved |= {row.id for row in rows if row.solved}
            try:
                self.apply_solved()
            except Exception as exc:  # a bug
                problem = f"Game Master: could not apply its solved list: {type(exc).__name__}: {exc}"
                if problem not in self.errors:
                    self.errors.append(problem)

    def _failed(self, exc: BaseException) -> None:
        why = str(exc) if isinstance(exc, GameMasterError) else f"{type(exc).__name__}: {exc}"
        self._failures += 1
        if self.deck is not None and why != self._said:
            self._said = why
            self.deck.warn(
                f"could not read the solved list from the Game Master: {why}; flightdeck reads it again in "
                f"{self.solves_seconds:g} s", data=SOURCE,
            )
        if self._failures == PLATFORM_FAILURES and self.needs_human is not None:
            self.needs_human(f"reading the solved list from the Game Master has failed {self._failures} times in a row: {why}")

    def apply_solved(self, *, before_run: bool = False) -> None:
        """Close each board challenge of an attempt the Game Master lists as solved (or answered
        already_solved for) that this run did not solve: its lanes stop, it leaves the queue,
        and a platform event records it. Left for now: one whose flag is on its way (its answer
        may be that very solve), and one where the player is saying how a hand submit went
        (their answer closes it), unless the Game Master itself answered already_solved for it."""
        deck = self.deck
        assert deck is not None
        for cid in sorted(self.held()):
            ch = deck.challenges.get(cid)
            if ch is None or ch.closed:
                continue
            if deck.submitting(cid) or (self._confirming(cid) and cid not in self.answered):
                continue
            deck.platform_solved(cid, WHO, before_run=before_run)

    def _confirming(self, cid: str) -> bool:
        assert self.deck is not None
        for lane in self.deck.lanes_on(cid):
            queued = ([lane.pending] if lane.pending is not None else []) + lane.waiting
            if any(p.kind is PendingKind.CONFIRM for p in queued):
                return True
        return False


def _show(value: object) -> str:
    return untrusted(str(value), one_line=True)
