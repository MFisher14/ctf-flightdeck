"""The notification webhook: a small JSON message POSTed when the run has news for a player
who is not at the console. Opt-in: `[notify] webhook_env` in the config names the variable
that holds the URL (config.webhook_url reads it).

What is sent, and when (config.NOTIFY_KINDS; `[notify] on` chooses among them):

    flag        a flag was accepted: a submit event that is correct, answered by the platform
                or the board's answers file. Not the player's own word for a flag submitted by
                hand (the player was there), and not an answer for a challenge solved meanwhile.
    needs-you   a lane needs the player: a new approval (a pending event) or a new alert that
                wants an answer (not the flag alert, which comes with its approval, and not
                an informational one). At most one per lane and need in RATE_SECONDS, so a
                noisy lane cannot flood the receiver.
    disengaged  no more lanes start: a warning event whose data holds "autopilot":
                "disengaged" (with its "reason"), or one that holds the queue ("held": true).

The message is one JSON object, FORMAT 1, with exactly these fields (docs/GUIDE.md says the
same to players):

    flightdeck  the version that sent it
    format      1
    run         the run folder's name
    event       the event's name
    kind        "flag", "needs-you" or "disengaged"
    lane        the lane's id ("L01"), or null (disengaged)
    challenge   {"id", "name"}, or null (disengaged)
    need        needs-you: the approval's kind ("submit", "confirm", "budget", "live box") or
                the alert's ("budget", "loop", "stall", ...); null for the other kinds
    text        one line of at most MAX_TEXT characters, for a person to read

A flag's value is never sent. A webhook is someone else's server, often a chat channel others
read, and a flag there before it is submitted is a flag given away: the message says that a
flag waits or was accepted, and for which challenge; the flag is in the console, in
status.json and in events.jsonl, on the player's own machine. `text` is written here for the
flag kinds, and whatever it quotes (an approval's detail, an alert's reason, a hold's reason)
has every held secret as [NAME], the value of anything shaped like a credential taken out
(credentials.py), anything that matches the run's flag format as [flag], and control and
invisible characters made visible (text.untrusted). The names come from the board: untrusted
text, cut, sent as data.

The URL is a secret (it often holds a token). It is one of the run's held secrets (run.py:
[NAME] wherever a lane's text would show it), and nothing here logs it, puts it in an event
or shows it in an error: a failure is described by the HTTP status or the exception's type
alone, never by the exception's own words, which can quote the URL. Only http:// and
https:// URLs are used, redirects are not followed (a redirect is an answer, not a new place
to send the message), and the proxy settings of the environment are not used.

Sending never holds up the deck. The deck's listener only puts a message on a bounded queue
(QUEUE messages: one more is dropped, said once); one background task on the run's loop sends
them, one at a time, each given TIMEOUT seconds in all. A message that fails is not sent
again. A failure is a deck warning, said once while the same failure lasts, and the run goes
on. When the run shuts down the task is given DRAIN seconds to send what is queued.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import time
from collections.abc import Callable, Collection, Mapping
from typing import TYPE_CHECKING

import httpx

from . import __version__, credentials
from .agent.held import Secrets
from .config import NOTIFY_KINDS
from .core.model import FLAG_PENDING, INFORMATIONAL_ALERTS, AlertKind, Event, EventKind, PendingKind
from .text import untrusted

if TYPE_CHECKING:
    from .core.deck import Deck

FORMAT = 1
FLAG, NEEDS_YOU, DISENGAGED = NOTIFY_KINDS
TIMEOUT = 5.0  # seconds one message may take, all of it
QUEUE = 32  # messages that may wait to be sent
DRAIN = 6.0  # seconds a shutdown waits for the queued messages
RATE_SECONDS = 60.0  # a lane's same need is sent at most once in this long
MAX_TEXT = 200  # characters of `text`
MAX_NAME = 80  # characters of a name (the event, a challenge, its id)
CUT = "..."
NO_FLAG = "[flag]"


class NotifyError(Exception):
    """The webhook cannot be used; the message never shows its URL."""


class Notifier:
    """Sends the deck's news to one webhook. attach() follows the deck; start() starts the
    sending task (on the run's loop); aclose() stops it."""

    def __init__(
        self, url: str, deck: Deck, *, run: str, env: str = "", on: Collection[str] = NOTIFY_KINDS,
        held: Mapping[str, str] | None = None, timeout: float = TIMEOUT, queue: int = QUEUE,
        rate_seconds: float = RATE_SECONDS, drain: float = DRAIN, clock: Callable[[], float] = time.monotonic,
    ) -> None:
        unknown = [kind for kind in on if kind not in NOTIFY_KINDS]
        if unknown:
            raise NotifyError(f"unknown notification kind {', '.join(map(repr, unknown))}: one of {', '.join(NOTIFY_KINDS)}")
        try:
            parsed = httpx.URL(url)
        except (httpx.InvalidURL, TypeError, ValueError):
            parsed = None
        if parsed is None or parsed.scheme not in ("http", "https") or not parsed.host:
            raise NotifyError("the notification webhook is not an http:// or https:// URL (it is not shown: it is a secret)")
        self._url = parsed
        self.deck = deck
        self.run_name = run
        self.where = f"the variable {env}" if env else "its URL is not shown"
        self.on = frozenset(on)
        self.timeout = timeout
        self.rate_seconds = rate_seconds
        self.drain = drain
        self.sent = 0  # messages the webhook answered with a 2xx
        self.dropped = 0  # messages that found the queue full
        self._clock = clock
        self._held = Secrets({**(held or {}), env or "NOTIFY_WEBHOOK": url})
        self._flag_re = re.compile(deck.config.flag_format)
        self._queue: asyncio.Queue[dict[str, object]] = asyncio.Queue(maxsize=queue)
        self._last: dict[tuple[str, str], float] = {}  # (lane id, need) -> when it was last queued
        self._problem = ""  # the failure said last; "" after a message that went through
        self._said_dropped = False
        self._unsubscribe: Callable[[], None] | None = None
        self._task: asyncio.Task | None = None
        self._http: httpx.AsyncClient | None = None

    def __repr__(self) -> str:  # never the URL
        return f"Notifier({self.where}, on={sorted(self.on)})"

    # ------------------------------------------------------------------ the deck's side

    def attach(self) -> None:
        """Follow the deck from now on. Messages wait on the queue until start()."""
        if self._unsubscribe is not None:
            raise RuntimeError("the notifier is already attached")
        self._unsubscribe = self.deck.subscribe(self._event)

    def _event(self, event: Event) -> None:
        """A deck event (on the deck's thread): queue its message, if it has one. Never waits."""
        message = self.message(event)
        if message is None:
            return
        if message["kind"] == NEEDS_YOU:
            key, now = (str(message["lane"]), str(message["need"])), self._clock()
            last = self._last.get(key)
            if last is not None and now - last < self.rate_seconds:
                return
            self._last[key] = now
        try:
            self._queue.put_nowait(message)
        except asyncio.QueueFull:
            self.dropped += 1
            if not self._said_dropped:
                self._said_dropped = True
                self.deck.warn(
                    f"a notification was dropped: {self._queue.maxsize} already wait to be sent to the webhook "
                    f"({self.where}); flightdeck says this once",
                    data={"source": "notify"},
                )

    def message(self, event: Event) -> dict[str, object] | None:
        """The message for a deck event, or None when the event is no news (or its kind is
        not one `on` lists)."""
        data = event.data
        kind, need, text = None, None, ""
        if event.kind is EventKind.SUBMIT:
            if data.get("correct") is True and data.get("by") != "player" and not data.get("solved_meanwhile"):
                kind = FLAG
                text = f"{event.lane} solved {self._challenge_name(event)}: its flag was accepted"
        elif event.kind is EventKind.PENDING:
            kind, need = NEEDS_YOU, str(data.get("kind", ""))
            name = self._challenge_name(event)
            if need == PendingKind.SUBMIT.value:
                text = f"{event.lane} has a flag for {name}: it waits for your approval"
            elif need in (p.value for p in FLAG_PENDING):
                text = f"{event.lane} has a flag for {name}: submit it by hand, then say how it went"
            else:
                text = f"{event.lane} on {name} waits for your approval ({need}): {data.get('detail', '')}"
        elif event.kind is EventKind.ALERT:
            if event.alert is not None and event.alert is not AlertKind.FLAG and event.alert not in INFORMATIONAL_ALERTS:
                kind, need = NEEDS_YOU, event.alert.value
                text = f"{event.lane} on {self._challenge_name(event)}: {event.alert.label}: {data.get('reason', '')}"
        elif event.kind is EventKind.WARNING:
            if data.get("autopilot") == "disengaged":
                kind, text = DISENGAGED, f"autopilot disengaged: {data.get('reason') or event.text}"
            elif data.get("held") is True:
                kind, text = DISENGAGED, event.text  # "no more lanes start: <why>"
        if kind is None or kind not in self.on:
            return None
        challenge = self.deck.challenges.get(event.challenge) if event.challenge is not None else None
        return {
            "flightdeck": __version__,
            "format": FORMAT,
            "run": self.run_name,
            "event": _name(self.deck.config.event),
            "kind": kind,
            "lane": event.lane,
            "challenge": None if challenge is None else {"id": _name(challenge.id), "name": _name(challenge.name)},
            "need": need,
            "text": self._safe(text),
        }

    def _challenge_name(self, event: Event) -> str:
        challenge = self.deck.challenges.get(event.challenge) if event.challenge is not None else None
        return _name(challenge.name) if challenge is not None else "a challenge"

    def _safe(self, text: str) -> str:
        """`text` for someone else's server: no held secret, no credential, no flag, one
        line of visible characters, cut. The secrets go first: a cut one would keep its start."""
        text = credentials.redact(self._held(str(text)))
        text = self._flag_re.sub(NO_FLAG, text)
        return _cut(untrusted(text, one_line=True), MAX_TEXT)

    # ------------------------------------------------------------------ the sending side

    def start(self) -> None:
        """Start sending (on the run's loop). Once."""
        if self._task is None:
            self._http = httpx.AsyncClient(
                follow_redirects=False, trust_env=False, timeout=httpx.Timeout(self.timeout),
                headers={"User-Agent": f"ctf-flightdeck/{__version__}"},
            )
            self._task = asyncio.create_task(self._work(), name="flightdeck notifications")

    async def aclose(self) -> None:
        """Stop following the deck, give what is queued `drain` seconds to go, then stop."""
        if self._unsubscribe is not None:
            self._unsubscribe()
            self._unsubscribe = None
        task, self._task = self._task, None
        if task is not None:
            with contextlib.suppress(TimeoutError):
                async with asyncio.timeout(self.drain):
                    await self._queue.join()
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        http, self._http = self._http, None
        if http is not None:
            await http.aclose()

    async def _work(self) -> None:
        while True:
            message = await self._queue.get()
            try:
                problem = await self._send(message)
                if not problem:
                    self.sent += 1
                    self._problem = ""
                elif problem != self._problem:  # once while the same failure lasts
                    self._problem = problem
                    self.deck.warn(
                        f"a notification could not be sent to the webhook ({self.where}): {problem}; the run goes on, "
                        "and flightdeck does not send it again",
                        data={"source": "notify"},
                    )
            finally:
                self._queue.task_done()

    async def _send(self, message: dict[str, object]) -> str:
        """POST one message; "" when the webhook took it, else why not (never the URL, and
        never an exception's own words: they can quote it)."""
        assert self._http is not None
        try:
            async with asyncio.timeout(self.timeout):
                async with self._http.stream("POST", self._url, json=message) as response:  # the answer's body is not read
                    status = response.status_code
        except (TimeoutError, httpx.TimeoutException):
            return f"no answer within {self.timeout:g} s"
        except Exception as exc:  # httpx.HTTPError, an OSError under it, or a bug: the run goes on
            return f"the request failed ({type(exc).__name__})"
        if 200 <= status < 300:
            return ""
        if 300 <= status < 400:
            return f"it answered HTTP {status}, a redirect, which flightdeck does not follow"
        return f"it answered HTTP {status}"


def _cut(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - len(CUT)] + CUT


def _name(text: str) -> str:
    """A name from the board: visible characters on one line, cut."""
    return _cut(untrusted(str(text), one_line=True), MAX_NAME)
