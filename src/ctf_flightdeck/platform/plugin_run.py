"""A plugin's platform in a run: the deck's submitter for its flags, its solved list read back,
and its board pulled again.

`flightdeck play --event EVENT.toml`, with an event profile whose platform is a plugin the
player added (plugins/), plays the board flightdeck wrote from the plugin's pull (run.py).
PluginLink is the run's link to that platform, on the console's loop. Every call to the
plugin is one run of its program, out of process (plugins/call.py: Caller), one at a time.

- the deck's submitter (Deck(submitter=link), when the submit policy uses the platform): a
  flag the deck lets through is queued, and one worker task (work()) sends each in turn with
  the challenge's ref, the platform's own id for it (plugin.json in the board folder). The
  plugin's word reaches the deck through Deck.platform_verdict: `correct` is right,
  `incorrect` is wrong, and everything else is no verdict, never a wrong answer:
  `unjudged`, a rate limit that outlasted the resends, a call that failed, hung or answered
  what the plugin API does not know (plugins.call.CallFailed), and a challenge with no ref.
  The player then submits it by hand and says how it went, a warning says why, and autopilot
  is told the platform needs a human (`needs_human`). `already_solved` closes the challenge
  as the platform's solve. The tries the plugin says are left go to the deck with the verdict.
- `rate_limited` judged nothing, so the same flag is sent again, as for CTFd
  (docs/DECISIONS.md, P33): after the wait the plugin gives (retry_after, at most RESEND_MAX)
  or RESEND_WAIT, up to RESENDS more times, saying so on the lane; flags queued behind it
  wait. Never for a challenge whose tries are counted.
- the solved list (watch()): every `solves_seconds` the plugin's `solved` is read, and each
  board challenge it lists, that this run did not solve, is closed (Deck.platform_solved),
  but one whose flag is on its way or that waits for the player's word on a hand submit. A
  read that fails is a warning, once while the same failure lasts, and after
  PLATFORM_FAILURES in a row autopilot is told.
- the board again (repull(), only with `pulls`: the pull policy "auto"): every
  `pull_seconds` the plugin's `pull` is asked, flightdeck writes the new challenges' folders
  (plugins.board.pull_into), and the run releases them (`added`: Run.scan_board). A pull that
  fails is a warning, once while it lasts, and counts toward telling autopilot too.

Everything the plugin says is untrusted: the Caller cuts the token out of every string and
makes each reason safe; what is shown here of a flag or a name is made safe again.

The built-in http platform (platform/http.py) plays through this same link: its caller makes
the three calls itself, in process, from the event profile's table of routes. The link asks
only what plugins.call.PlatformCaller promises, and names the caller in its messages by the
caller's own label ("the acme plugin", "the http adapter").
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable, Collection, Mapping
from pathlib import Path

from ..core.deck import Deck
from ..core.model import PendingKind
from ..plugins.board import load_refs, pull_into
from ..plugins.call import SECONDS, CallFailed, PlatformCaller, Verdict, plugin_label
from ..plugins.manifest import PluginError
from ..text import untrusted

WHO = "your account"  # who solved what the plugin lists as solved: it does not say more
SOLVES_SECONDS = 60.0  # the plugin's solved list is read this often
PULL_SECONDS = 300.0  # under the pull policy "auto" the plugin's pull is asked again this often
PLATFORM_FAILURES = 3  # the same read failing this many times in a row is the platform failing: autopilot is told
SOURCE = {"source": "plugin"}  # on every warning of a plugin's link (the http platform's say "http")
MAYBE_SENT = "; it may have reached the platform: check the challenge there before you submit it again"


class PluginLink:
    """A plugin's platform during a run (see the module's words). Set `deck` once the deck
    exists; use it on the console's loop only."""

    RESENDS = 3  # more sends of a flag the platform rate-limited
    RESEND_WAIT = 65.0  # seconds, when the plugin names no wait
    RESEND_MAX = 300.0  # the longest wait taken from the plugin's retry_after

    def __init__(
        self,
        caller: PlatformCaller,
        name: str,
        board: Path,
        refs: Mapping[str, str],
        *,
        solved: Collection[str] = (),
        pulls: bool,
        solves_seconds: float = SOLVES_SECONDS,
        pull_seconds: float = PULL_SECONDS,
    ) -> None:
        if not solves_seconds > 0 or not pull_seconds > 0:
            raise ValueError("solves_seconds and pull_seconds must be positive numbers of seconds")
        self.caller = caller
        self.name = name  # the plugin's name: the player's own word for it ([plugins.NAME] in their config); "http" for the built-in
        self.label = getattr(caller, "label", None) or plugin_label(name)  # how messages name it: "the acme plugin", "the http adapter"
        self.mark = self.label.removeprefix("the ")  # at the start of a line: "acme plugin: ..."
        self.command = getattr(caller, "pull_command", None) or "flightdeck plugin pull"
        self.source = {"source": getattr(caller, "source", None) or "plugin"}  # on every warning from here
        self.board = Path(board)  # the board folder, with its plugin.json
        self.refs = dict(refs)  # board id -> the platform's own id for the challenge
        self.solved = set(solved)  # the refs the plugin last listed as solved, and those it answered already_solved for
        self.answered: set[str] = set()  # board ids the plugin answered already_solved for
        self.pulls = pulls  # the pull policy "auto": the board is pulled again every pull_seconds
        self.solves_seconds = solves_seconds
        self.pull_seconds = pull_seconds
        self.deck: Deck | None = None
        self.needs_human: Callable[[str], None] | None = None  # the run's: the platform needs a human (autopilot disengages)
        self.added: Callable[[], object] | None = None  # the run's: release the folders a pull added to the board (Run.scan_board)
        self.queue: asyncio.Queue[tuple[str, str, str]] = asyncio.Queue()  # (lane, board id, flag) to send, in order
        self.sending: tuple[str, str, str] | None = None  # the one sent now, until its answer is applied
        self.errors: list[str] = []  # bookkeeping that failed (a flightdeck bug), shown when the run ends
        self.sleep: Callable[[float], Awaitable[None]] = asyncio.sleep  # the wait before a flag is sent again
        self.reported: set[str] = set()  # what a pull left out or noted, told to the player already
        self._said: dict[str, str] = {}  # a read ("solved", "pull") -> its failure last warned of: said once while it lasts
        self._failures: dict[str, int] = {}  # a read -> how many times in a row it has failed

    def __call__(self, lane_id: str, challenge_id: str, flag: str) -> None:
        self.queue.put_nowait((lane_id, challenge_id, flag))

    def tasks(self) -> list[asyncio.Task]:
        """The link's background tasks, started on the running loop: the run cancels them at its end."""
        tasks = [
            asyncio.create_task(self.work(), name=f"flightdeck {self.mark} submits"),
            asyncio.create_task(self.watch(), name=f"flightdeck {self.mark} solves"),
        ]
        if self.pulls:
            tasks.append(asyncio.create_task(self.repull(), name=f"flightdeck {self.mark} pulls"))
        return tasks

    def held(self) -> set[str]:
        """The board ids of the challenges the plugin lists as solved: not to queue."""
        return {cid for cid, ref in self.refs.items() if ref in self.solved}

    async def aclose(self) -> None:
        """Nothing is held open: each call to the plugin is a process that has ended."""

    # ------------------------------------------------------------------ flags to the plugin

    async def work(self) -> None:
        """Send each flag in turn, and apply the plugin's word on this loop. Cancelled at shutdown."""
        while True:
            item = await self.queue.get()
            self.sending = item
            lane_id, challenge_id, flag = item
            outcome = await self._send(lane_id, challenge_id, flag)
            try:
                self.answer(lane_id, challenge_id, flag, outcome)
            except Exception as exc:  # a bug: said now and at the end, and the next flag still goes
                problem = f"{self.mark}: could not apply its answer to {_show(flag)}: {type(exc).__name__}: {exc}"
                self.errors.append(problem)
                with contextlib.suppress(Exception):
                    self.deck.warn(problem, challenge=challenge_id, data=self.source)
            self.sending = None

    def reload(self) -> None:
        """Read the board's plugin.json again for the refs of challenges a pull added since:
        this run's, or `flightdeck plugin pull` in another terminal. One that cannot be read
        is a warning, once while it lasts; a challenge with no ref gets no flag sent."""
        try:
            self.refs.update(load_refs(self.board, plugin=self.name, url=self.caller.url, label=self.label, command=self.command))
        except PluginError as exc:
            if self.deck is not None and self._said.get("refs") != str(exc):
                self._said["refs"] = str(exc)
                self.deck.warn(f"{exc}; flags of challenges added since the last read are not sent", data=self.source)
        else:
            self._said.pop("refs", None)

    def _ref(self, challenge_id: str) -> str | None:
        """The challenge's ref; one the link does not have is looked for in plugin.json again."""
        if challenge_id not in self.refs:
            self.reload()
        return self.refs.get(challenge_id)

    async def _send(self, lane_id: str, challenge_id: str, flag: str) -> Verdict | str:
        """The plugin's word on the flag, after the resends of a rate limit; or why there is none."""
        assert self.deck is not None
        ref = self._ref(challenge_id)
        if ref is None:
            through = "through the plugin" if self.source == SOURCE else "from the platform"
            return (f"{_show(challenge_id)} was not pulled {through}, so flightdeck has nowhere to send its flag: "
                    "submit it by hand, then say whether it was accepted")
        sends = 0
        while True:
            self._waits_behind_pull(lane_id, flag)
            try:
                verdict = await self.caller.submit(ref, flag)
            except CallFailed as exc:
                return str(exc) + (MAYBE_SENT if exc.timed_out else "")
            except Exception as exc:  # a bug in the caller: the outcome is not known, and the worker goes on
                return f"flightdeck could not submit it ({type(exc).__name__}: {exc})" + MAYBE_SENT
            sends += 1
            wait = self.resend_after(challenge_id, verdict) if sends <= self.RESENDS else None
            if wait is None:
                return verdict
            with contextlib.suppress(Exception):  # the note is a courtesy: the resend does not hang on it
                self.deck.note(lane_id, (
                    f"the platform rate-limited the submission of {_show(flag)} and did not check it; flightdeck sends it "
                    f"again in {wait:g}s (send {sends + 1} of {self.RESENDS + 1})"
                ))
            await self.sleep(wait)

    def _waits_behind_pull(self, lane_id: str, flag: str) -> None:
        """A note on the lane when the flag must wait for a pull to end: calls to a plugin never
        overlap (docs/PLUGINS.md), and a pull may take minutes."""
        if getattr(self.caller, "running", None) != "pull":
            return
        seconds = (getattr(self.caller, "seconds", None) or SECONDS)["pull"]
        with contextlib.suppress(Exception):  # the note is a courtesy: the submit does not hang on it
            self.deck.note(lane_id, (
                f"{self.label} is pulling the board; {_show(flag)} goes to the platform when the pull ends "
                f"(a pull may take up to {seconds:g} s, and calls to a plugin never overlap)"
            ))

    def resend_after(self, challenge_id: str, verdict: Verdict) -> float | None:
        """How long to wait before sending the flag again, or None when it is not sent again:
        only a rate limit, at a challenge whose tries nobody counts."""
        if verdict.word != "rate_limited" or verdict.tries_left is not None:
            return None
        ch = self.deck.challenges.get(challenge_id) if self.deck is not None else None
        if ch is None or ch.limited:
            return None
        if verdict.retry_after is None:
            return self.RESEND_WAIT
        return min(verdict.retry_after + 1.0, self.RESEND_MAX)

    def answer(self, lane_id: str, challenge_id: str, flag: str, outcome: Verdict | str) -> None:
        """The plugin's word on a flag (or why there is none), on the deck's thread: the link's
        bookkeeping, then the deck's."""
        deck = self.deck
        assert deck is not None
        ref = self.refs.get(challenge_id)
        if isinstance(outcome, Verdict):
            word, detail, tries = outcome.word, outcome.detail, outcome.tries_left
            if word in ("correct", "incorrect"):
                if word == "correct" and ref is not None:
                    self.solved.add(ref)
                deck.platform_verdict(lane_id, flag, word == "correct", detail or word, tries_left=tries)
                return
            if word == "already_solved" and ref is not None:
                self.answered.add(challenge_id)
                self.solved.add(ref)
                deck.platform_verdict(lane_id, flag, None, detail or "the platform says the challenge is already solved",
                                      tries_left=tries)
                self.apply_solved()
                return
            if word == "rate_limited":
                why = "the platform rate-limited it and did not check it"
            else:
                why = "the platform gave no verdict on it"
            why += f" ({detail})" if detail else ""
            if tries == 0:  # out of tries: the deck closes the challenge and says so, and nobody is asked to submit by hand
                deck.platform_verdict(lane_id, flag, None, why, tries_left=0)
                return
        else:
            why, tries = outcome, None
        ch = deck.challenges.get(challenge_id)
        name = _show(ch.name if ch is not None else challenge_id)
        deck.warn(f"{self.label} did not judge {_show(flag)} for {name}: {why}", challenge=challenge_id, data=self.source)
        deck.platform_verdict(lane_id, flag, None, why, tries_left=tries)
        if self.needs_human is not None:
            self.needs_human(f"{self.label} did not judge a flag: {why}")  # after the deck has it back with the player

    def unsent(self) -> list[str]:
        """After the worker has stopped: the flags on their way to the platform when the run
        ended, said for the player, made safe to print. The one being sent may have reached
        it; the others did not leave flightdeck."""
        deck = self.deck
        out: list[str] = list(self.errors)
        mark = self.mark

        def named(lane_id: str, challenge_id: str, flag: str) -> str:
            ch = deck.challenges.get(challenge_id) if deck is not None else None
            return f"{_show(flag)} ({lane_id}, {_show(ch.name if ch is not None else challenge_id)})"

        if self.sending is not None:
            out.append(
                f"{mark}: {named(*self.sending)} was on its way to the platform when the run ended, so it is not known to "
                "have been submitted: check the challenge there before you submit it again"
            )
        while not self.queue.empty():
            out.append(f"{mark}: {named(*self.queue.get_nowait())} was not submitted: it was waiting to go to the platform "
                       "when the run ended")
        if deck is not None:
            for challenge_id in deck.challenges:
                for lane_id, flag in deck.submitting(challenge_id)[1:]:
                    out.append(
                        f"{mark}: {named(lane_id, challenge_id, flag)} was not submitted: it was waiting for the answer to "
                        "another flag of that challenge when the run ended"
                    )
        return out

    # ------------------------------------------------------------------ the solved list

    async def watch(self) -> None:
        """Read the plugin's solved list every `solves_seconds` and close what it lists.
        Cancelled at shutdown."""
        while True:
            await asyncio.sleep(self.solves_seconds)
            try:
                refs = await self.caller.solved()
            except Exception as exc:  # CallFailed, or a bug: say so, and read again later
                self._failed("solved", exc, f"could not read the solved list from {self.label}",
                             f"flightdeck reads it again in {self.solves_seconds:g} s", "reading the solved list from")
                continue
            self._worked("solved")
            self.solved |= refs
            self._apply("its solved list")

    def _apply(self, what: str) -> None:
        try:
            self.apply_solved()
        except Exception as exc:  # a bug
            problem = f"{self.mark}: could not apply {what}: {type(exc).__name__}: {exc}"
            if problem not in self.errors:
                self.errors.append(problem)

    def _worked(self, kind: str) -> None:
        self._said.pop(kind, None)
        self._failures.pop(kind, None)

    def _failed(self, kind: str, exc: BaseException, what: str, then: str, doing: str) -> None:
        """A read of the platform failed: a warning, once while the same failure lasts, and
        after PLATFORM_FAILURES in a row of the same read autopilot is told."""
        why = str(exc) if isinstance(exc, (CallFailed, PluginError)) else f"{type(exc).__name__}: {exc}"
        self._failures[kind] = count = self._failures.get(kind, 0) + 1
        if self.deck is not None and why != self._said.get(kind):
            self._said[kind] = why
            self.deck.warn(f"{what}: {why}; {then}", data=self.source)
        if count == PLATFORM_FAILURES and self.needs_human is not None:
            self.needs_human(f"{doing} {self.label} has failed {count} times in a row: {why}")

    def apply_solved(self, *, before_run: bool = False) -> None:
        """Close each board challenge the plugin lists as solved (or answered already_solved
        for) that this run did not solve: its lanes stop, it leaves the queue, and a platform
        event records it. Left for now: one whose flag is on its way (its answer may be that
        very solve), and one where the player is saying how a hand submit went (their answer
        closes it), unless the plugin itself answered already_solved for it."""
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

    # ------------------------------------------------------------------ the board, pulled again

    async def repull(self) -> None:
        """Ask the plugin's pull again every `pull_seconds`, and have the run release the
        challenges flightdeck added to the board. Cancelled at shutdown."""
        while True:
            await asyncio.sleep(self.pull_seconds)
            try:
                written = await pull_into(self.caller, self.board, plugin=self.name, url=self.caller.url)
            except Exception as exc:  # CallFailed, PluginError, or a bug: say so, and pull again later
                self._failed("pull", exc, f"{self.label} could not pull new challenges",
                             f"flightdeck pulls again in {self.pull_seconds:g} s", "pulling new challenges through")
                continue
            self._worked("pull")
            try:
                self.pulled(written)
            except Exception as exc:  # a bug
                problem = f"{self.mark}: could not release what its pull added: {type(exc).__name__}: {exc}"
                if problem not in self.errors:
                    self.errors.append(problem)

    def pulled(self, written) -> None:
        """What a pull did (plugins.board.Written): each challenge it left out and each note of
        the plugin's is a warning, once; the folders it added are released by the run, and
        those the platform already lists as solved are closed."""
        deck = self.deck
        assert deck is not None
        for line in [f"{self.name}: not added: {problem}" for problem in written.problems] + [f"{self.name}: {note}" for note in written.notes]:
            if line not in self.reported:
                self.reported.add(line)
                deck.warn(line, data=self.source)
        if not written.added:
            return
        self.reload()
        if self.added is not None:
            self.added()
        self.apply_solved()


def _show(value: object) -> str:
    return untrusted(str(value), one_line=True)
