"""The Game Master adapter: list a Game Master's challenges, read and start attempts, download
their artifacts, submit answers, and pull what is started into a folder board.

A Game Master is a CTF platform that is one URL. A challenge there is an attempt: it must be
started before its files and questions can be read, it takes one or more answers, each
addressed by an answer id, and an answer is often not a flag (a name, a hash, a number): the
Game Master gives the challenge's flag only in its answer to a right one.

The wire, as this module uses it (the contract of the solver pack's adapter,
packs/solvers/ctf/platform/gamemaster.py, re-implemented here; nothing is imported from it):
- every request goes to the one URL with `Authorization: Bearer <token>`;
- GET ?op=list&all=true: {"challenges": [{"id", "name", "day", "lane", "mode", "solved"}]};
- GET ?op=status&challenge=<id>: the attempt, a JSON object: "name", "prompt", "guidance",
  "questions" [{"id", "question", "answer_format"}], "answer_ids", its files as "artifacts"
  [{"filename", "sha256"}] or one "download" with "sha256", "targets" [{"url"}], "deadline".
  An id that is not started answers HTTP 409 {"error": "start_required"};
- GET ?op=artifact&challenge=<id>&delivery=<n>: the bytes of file n (from 0); its name is
  the status's "filename", else the Content-Disposition's;
- POST {"challenge": <id>}: start the attempt. An id that ends in /time_trial or /mastery
  (or whose listed mode is time_trial or mastery) is clocked: starting it starts a clock;
- POST {"challenge": <id>, "answers": {<answer id>: <value>}}: submit. The answer's word is
  its "result" or "error".

What the words mean here (WORDS):
- CORRECT (the attempt is solved; its "flag" comes with it) and accepted (that answer is
  banked, "remaining" more are wanted) are a right answer, with HTTP 200 only;
- incorrect is a wrong answer, with HTTP 200 only;
- already_solved, with HTTP 200 only, is news, not an error: the challenge is solved, and
  this answer was not checked;
- the refusals (REFUSALS: start_required, attempt_expired, invalid_answers, invalid_request,
  payload_too_large), with any HTTP status, judge nothing: the answer is not known to be
  wrong;
- HTTP 429 is rate_limited whatever its body: the answer was not checked;
- any other word, or a verdict word with another HTTP status, is a GameMasterError that
  names it. It is never read as a verdict.

flightdeck never starts a clocked attempt: start() refuses one before anything is sent, and
nothing in flightdeck goes round it. The player starts it on the Game Master, and the next
pull finds it started. A plain attempt is started only by a pull the player asked to start
them (pull(start=True): `flightdeck gm pull --start`); a run starts none.

Retries: a GET that gets 429 or 5xx, or no answer at all, is tried again with backoff (a
Retry-After is honoured, capped at max_wait). A POST is sent once: a start begins an attempt
and a submit is judged, so neither is repeated here (run code may send a rate-limited answer
again: platform/gamemaster_run.py).

Secrets: the token goes in the Authorization header and nowhere else: not in a repr, an
error or an exception chain (no httpx error is chained: its request holds the header). Text
from the server has the token cut out before it is shown. No redirect is followed. The
"download" values of a status are capability URLs: this module never requests, keeps or
shows them (a file is fetched by op=artifact only).

Untrusted data: everything from the Game Master is data, shown only made safe and cut short.
A file name must be a plain name (no path, no "..", no control characters) or the download
is refused; a file whose sha256 the status states is checked against it, and one that does
not match is not kept. Nothing pulled is run, and files are written without an execute bit.

The board folder: one folder per answer of each started attempt (an attempt with one answer
is one challenge on the board; one with several is one challenge per answer id, each with a
copy of the attempt's files), dest/board.json and dest/gm.json, which records the Game
Master's URL and where each board id's answer goes: {"url": ..., "ids": {board id:
{"challenge": <id>, "answer": <answer id>}}}. load_ids() reads it back. A folder appears only
when it is complete (built in a staging folder, checked with load_board(), then moved into
place). A pull into a folder that holds a board from the same Game Master keeps what is there
and adds what is new. Pull.unstarted lists every attempt left unstarted, and why.

Answers and the flag format: flightdeck checks every candidate against the event's flag
format before it goes anywhere, and that check is not loosened for a Game Master. Instead
the flag format of a Game Master board states what an answer looks like: a pull writes
DEFAULT_ANSWER_FORMAT, answer{...}, into board.json unless the player gives another, and
answer_of() says what part of a candidate is sent: the format's group named "answer" when it
has one, else the whole candidate.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import tempfile
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import httpx

from .. import __version__
from ..flagformat import check as check_flag_format
from ..text import untrusted
from .ctfd import (  # helpers that say nothing of CTFd: reading, waiting, safe text, writing a board folder
    CTFdError,
    _create,
    _describe,
    _Failure,
    _parse,
    _phrase,
    _quote,
    _read,
    _retry_after,
    _retryable,
    _show,
    _valid,
    _write_json,
    origins_in,
    services_in,
    slugify,
)
from .manual import BOARD_FILE, CHALLENGE_FILE, MAX_JSON_BYTES, Board, BoardError, load_board
from .manual import _settings as _board_json  # board.json's event and flag format, read as the board loader reads them

STATE_FILE = "gm.json"
"""In the board folder: the Game Master's URL and where each board id's answer goes."""

VERDICTS = ("CORRECT", "accepted", "incorrect", "already_solved")
REFUSALS = ("start_required", "attempt_expired", "invalid_answers", "invalid_request", "payload_too_large")
RATE_LIMITED = "rate_limited"
WORDS = (*VERDICTS, *REFUSALS, RATE_LIMITED)
"""Every word Submitted.word can be. CORRECT and accepted are right, incorrect is wrong, and
the rest judged nothing."""

CLOCKED_SUFFIXES = ("/time_trial", "/mastery")
CLOCKED_MODES = ("time_trial", "mastery")
DEFAULT_ANSWER_FORMAT = r"answer\{(?P<answer>[^{}\r\n]{1,200})\}"
"""The flag format a pull gives a new Game Master board when the player names none: a lane
submits answer{...}, and what is inside the braces goes to the Game Master (answer_of)."""
ANSWER_GROUP = "answer"

MAX_WAIT = 30.0  # seconds: the longest pause between tries, whatever Retry-After asks for
CONNECT_TIMEOUT = 10.0  # seconds: a connection that takes longer is not coming
MAX_API_BYTES = 20_000_000  # an API answer bigger than this is refused
MAX_FILE_BYTES = 1 << 30  # an artifact bigger than this is refused (1 GiB); fetch it by hand
MAX_STATE_BYTES = 1_000_000  # a gm.json bigger than this is refused
MAX_SHOWN = 200  # characters of the server's own words kept in a message
MAX_ID = 200  # characters of a challenge id or an answer id
MAX_ANSWERS = 64  # answers of one attempt; more is not an attempt flightdeck puts on a board
MAX_FILES = 64  # files of one attempt
MAX_TEXT = MAX_JSON_BYTES // 8  # characters of a prompt kept in a description; challenge.json stays loadable
SLUG_MAX = 40  # characters of a name kept in a board id; room for the answer id and "-<n>" within 64

_LOCK = ".gm-pull.lock"
_STAGING = ".gm-pull-"
_DOWNLOAD = ".gm-download-"
_IGNORED = frozenset({_LOCK, ".DS_Store"})  # what may sit in an empty board folder
_TOKEN_CHARS = re.compile(r"[\x21-\x7e]+")  # what a token may hold: printable ASCII, no spaces
_SLUG = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_DISPOSITION = re.compile(r'filename="([^"]*)"|filename=([^;"\s]+)', re.IGNORECASE)


class GameMasterError(Exception):
    """A Game Master request failed, an answer was not one this module knows, or a pull cannot
    go on. The message says what and why, naming the request and the HTTP status when there
    was one. It never holds the token.

    `retryable` is True when the failure was of a kind that passes (no answer, 429, 5xx).
    `sent` is False only when the request is known not to have left this machine.
    """

    def __init__(
        self, message: str, *, request: str | None = None, status: int | None = None, retryable: bool = False,
        sent: bool = True,
    ) -> None:
        super().__init__(message)
        self.request = request  # e.g. "GET op=status"
        self.status = status  # the HTTP status of the answer; None when there was no answer
        self.retryable = retryable
        self.sent = sent


class ClockedAttempt(GameMasterError):
    """A start was asked for an attempt whose start runs a clock. flightdeck never starts one:
    nothing was sent."""


@dataclass(frozen=True)
class Listed:
    """A row of the Game Master's list (untrusted)."""

    id: str
    name: str  # its id when the row names none
    lane: str  # the Game Master's category: "web", "binary", ...; "" when it says none
    mode: str  # "single_solve", "time_trial", "mastery", ...; "" when it says none
    solved: bool

    @property
    def clocked(self) -> bool:
        return is_clocked(self.id, self.mode)


@dataclass(frozen=True)
class Question:
    id: str
    text: str  # the question, "" when the attempt gives none
    format: str  # its answer_format as the Game Master wrote it (JSON, one line, cut short); "" when it gives none


@dataclass(frozen=True)
class Delivery:
    """One file of an attempt, fetched by its index (GameMasterClient.artifact)."""

    index: int  # from 0
    name: str | None  # as the status names it; None: the download's Content-Disposition says
    sha256: str | None  # as the status states it, lower case; None when it states none


@dataclass(frozen=True)
class Attempt:
    """A challenge's attempt as the Game Master describes it (untrusted). Not `started`: the
    Game Master answered start_required, and the rest is whatever it said all the same."""

    id: str
    started: bool
    name: str | None = None
    prompt: str = ""
    guidance: str = ""
    questions: tuple[Question, ...] = ()
    answer_ids: tuple[str, ...] = ()  # its "answer_ids", else its questions' ids
    deliveries: tuple[Delivery, ...] = ()
    targets: tuple[str, ...] = ()  # the URLs of its live targets, as sent
    deadline: str | None = None  # as sent, when the attempt ends
    solved: bool = False  # its status says CORRECT


@dataclass(frozen=True)
class Submitted:
    """The Game Master's answer to a submission. `word` is one of WORDS. `ok`: True for
    CORRECT and accepted, False for incorrect, None when nothing was judged (already_solved,
    a refusal, rate_limited). `message`: the Game Master's own words, made safe to show.
    `remaining`: the answers still wanted, when it said (accepted). `flag`: the challenge's
    flag, when it gave one (CORRECT): shown nowhere by this module. `retry_after`: seconds
    the Game Master asked to wait (rate_limited), when it said."""

    word: str
    ok: bool | None
    message: str = ""
    remaining: int | None = None
    flag: str | None = None
    retry_after: float | None = None


@dataclass(frozen=True)
class Address:
    """Where a board challenge's answer goes: the Game Master's challenge id and answer id."""

    challenge: str
    answer: str


@dataclass(frozen=True)
class Pull:
    """What a pull wrote, and what it left."""

    board: Board  # load_board(dest) after the pull
    ids: Mapping[str, Address]  # board id -> where its answer goes, for every challenge pulled from the Game Master
    added: tuple[str, ...]  # board ids new in this pull, in the list's order
    started: tuple[str, ...]  # the Game Master ids this pull started (none without start=True)
    unstarted: tuple[str, ...]  # one line per attempt left unstarted, and why; safe to print
    problems: tuple[str, ...]  # one line per challenge that could not be pulled, and why; safe to print


class PullStopped(GameMasterError):
    """pull() stopped partway because the Game Master refused the token. What was written
    stays; `added`, `started`, `unstarted` and `problems` are as far as it got."""

    def __init__(self, cause: GameMasterError, added: tuple[str, ...], started: tuple[str, ...],
                 unstarted: tuple[str, ...], problems: tuple[str, ...]) -> None:
        count = len(added)
        self.reason = f"{cause}; the pull stopped there, with {count} new challenge{'' if count == 1 else 's'} written"
        self.added, self.started, self.unstarted, self.problems = added, started, unstarted, problems
        super().__init__(self.reason, request=cause.request, status=cause.status, retryable=cause.retryable)


def is_clocked(challenge_id: str, mode: str = "") -> bool:
    """Whether starting this attempt starts a clock: its id ends in /time_trial or /mastery, or
    the list gives it one of those modes."""
    return challenge_id.strip().rstrip("/").lower().endswith(CLOCKED_SUFFIXES) or mode.strip().lower() in CLOCKED_MODES


def answer_of(flag_format: str, candidate: str) -> str | None:
    """What goes to the Game Master for a candidate the deck let through: the part the flag
    format's group named "answer" matched, or the whole candidate when the format has no such
    group (or the group took no part in the match). None when the candidate does not match the
    whole format, or the part to send is empty: nothing is sent then."""
    match = re.compile(flag_format).fullmatch(candidate)
    if match is None:
        return None
    value = match.group(ANSWER_GROUP) if ANSWER_GROUP in match.re.groupindex else None
    return (candidate if value is None else value) or None


def unjudged(result: Submitted) -> str:
    """Why the Game Master's answer is no verdict on the answer sent, for the player."""
    said = f" (the Game Master says: {result.message})" if result.message else ""
    word = result.word
    if word == "already_solved":
        return f"the Game Master says this challenge is already solved{said}; it did not check this answer"
    if word == "start_required":
        return ("the Game Master did not check the answer: the attempt is not started (start_required). Start it "
                f"(`flightdeck gm pull --start`, or on the Game Master), then submit the answer by hand{said}")
    if word == "attempt_expired":
        return ("the Game Master did not check the answer: the attempt has expired (attempt_expired), so a new one "
                f"must be started first{said}")
    if word == "invalid_answers":
        return ("the Game Master did not judge the answer: it refused its form (invalid_answers), so it is not known "
                f"to be wrong{said}")
    if word == RATE_LIMITED:
        wait = f" for {result.retry_after:g} s" if result.retry_after is not None else ""
        return f"the Game Master rate-limited the submission and did not check the answer. Wait{wait}, then submit it by hand"
    return f"the Game Master refused the request ({word}) and did not check the answer{said}"


# ---------------------------------------------------------------------- the client


@dataclass
class _Answer:
    request: str
    status: int
    headers: httpx.Headers
    body: bytes
    tries: int = 1


class GameMasterClient:
    """A Game Master for one account (the token's), on one event loop.

    httpx pools connections per event loop, so keep a client on the loop that first uses it
    and `aclose()` it when done (or use `async with`). `timeout` bounds each step of a try,
    in seconds (connecting gets at most CONNECT_TIMEOUT of it). A GET makes at most
    `max_retries + 1` tries; a POST (a start, a submit) makes one.
    """

    def __init__(
        self,
        url: str,
        token: str,
        *,
        timeout: float = 30.0,
        max_retries: int = 3,
        backoff: float = 1.0,
        transport: httpx.AsyncBaseTransport | None = None,
        max_wait: float = MAX_WAIT,
        max_file_bytes: int = MAX_FILE_BYTES,
    ) -> None:
        self._site = _Site(url, token)
        if not timeout > 0:
            raise ValueError(f"timeout must be a positive number of seconds, got {timeout}")
        if isinstance(max_retries, bool) or not isinstance(max_retries, int) or max_retries < 0:
            raise ValueError(f"max_retries must be a whole number, 0 or more, got {max_retries!r}")
        if not backoff >= 0:
            raise ValueError(f"backoff must not be negative, got {backoff}")
        if not max_wait >= 0:
            raise ValueError(f"max_wait must not be negative, got {max_wait}")
        if isinstance(max_file_bytes, bool) or not isinstance(max_file_bytes, int) or max_file_bytes < 1:
            raise ValueError(f"max_file_bytes must be a whole number of bytes, 1 or more, got {max_file_bytes!r}")
        self.max_retries = max_retries
        self.backoff = backoff
        self.max_wait = max_wait
        self.max_file_bytes = max_file_bytes
        self._http = httpx.AsyncClient(
            headers=self._site.headers(),
            timeout=httpx.Timeout(timeout, connect=min(timeout, CONNECT_TIMEOUT)),
            transport=transport,
            follow_redirects=False,  # a redirect is an answer, not a new place to send the token
        )
        self._closed = False

    @property
    def url(self) -> str:
        """The Game Master's address as used: every request goes to it."""
        return self._site.root

    def __repr__(self) -> str:
        return f"GameMasterClient({self._site.root!r}, token=set)"

    async def __aenter__(self) -> GameMasterClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        self._closed = True
        await self._http.aclose()

    # ------------------------------------------------------------------ reads

    async def challenges(self) -> list[Listed]:
        """Every challenge the Game Master lists for this account, in its order. A row that is
        not an object with a usable id is a GameMasterError: the list is not one to work from."""
        answer = await self._exchange("GET", "op=list", params={"op": "list", "all": "true"})
        body = self._object(answer)
        rows = body.get("challenges")
        if not isinstance(rows, list):
            raise self._site.error(f"{self._where(answer)} without a list of challenges", request=answer.request,
                                   status=answer.status)
        listed: list[Listed] = []
        seen: set[str] = set()
        for row in rows:
            cid = row.get("id") if isinstance(row, dict) else None
            if not _is_id(cid) or cid in seen:
                what = "twice" if cid in seen and _is_id(cid) else "without a usable id"
                raise self._site.error(f"{self._where(answer)} with a challenge listed {what}", request=answer.request,
                                       status=answer.status)
            seen.add(cid)
            listed.append(Listed(
                id=cid,
                name=_text(row.get("name")) or cid,
                lane=_text(row.get("lane")),
                mode=_text(row.get("mode")),
                solved=row.get("solved") is True,
            ))
        return listed

    async def status(self, challenge_id: str) -> Attempt:
        """The challenge's attempt. Never starts one: an id that is not started comes back with
        `started` False (the Game Master's start_required)."""
        _check_id(challenge_id, "challenge_id")
        answer = await self._exchange("GET", "op=status", params={"op": "status", "challenge": challenge_id})
        if answer.status == 409:
            body = _parse(answer.body)
            if isinstance(body, dict) and _word(body) == "start_required":
                return _attempt(self._site, challenge_id, body, started=False, answer=answer)
        return _attempt(self._site, challenge_id, self._object(answer), started=True, answer=answer)

    async def artifact(self, challenge_id: str, delivery: Delivery, dest: Path) -> Path:
        """Fetch one file of the challenge's attempt into the directory `dest`; the file written.

        It is named as the status names it (Delivery.name), else as the download's
        Content-Disposition does, else artifact-<n>.bin; a name that is not a plain file name
        is refused. A file already there is never overwritten: the new one is named
        name-2.ext, name-3.ext, ... (and challenge.json is never used). The download streams
        to disk, at most max_file_bytes; when the status states its sha256, a file that does
        not match is not kept. A failed download leaves no file.
        """
        _check_id(challenge_id, "challenge_id")
        folder = Path(dest)
        if folder.is_symlink() or not folder.is_dir():
            raise GameMasterError(f"{_show(folder)}: is not a directory to download into")
        request = f"GET op=artifact delivery={delivery.index}"
        params = {"op": "artifact", "challenge": challenge_id, "delivery": str(delivery.index)}
        tries = self.max_retries + 1
        for attempt in range(tries):
            outcome = await self._fetch(params, folder, delivery, request)
            if isinstance(outcome, Path):
                return outcome
            answer, failure = outcome
            last = attempt + 1 >= tries
            if failure is not None:
                if last or not failure.transient:
                    raise self._site.no_answer(request, failure, attempt + 1)
                wait = self._delay(attempt, None)
            else:
                assert answer is not None
                answer.tries = attempt + 1
                if last:
                    raise self._site.refused(answer)
                wait = self._delay(attempt, answer.headers.get("retry-after"))
            await asyncio.sleep(wait)
        raise AssertionError("unreachable")  # pragma: no cover

    # ------------------------------------------------------------------ writes: each sent once

    async def start(self, challenge_id: str, *, mode: str = "") -> None:
        """Start the challenge's attempt: one POST, never repeated. ClockedAttempt, before
        anything is sent, for an attempt whose start runs a clock (is_clocked; `mode` is the
        list's): flightdeck never starts one. GameMasterError when the Game Master did not
        answer HTTP 200 with a JSON object, or no answer came (the attempt may have started
        all the same: status() says). What the start answers is not read as the attempt:
        ask status() next."""
        _check_id(challenge_id, "challenge_id")
        if is_clocked(challenge_id, mode):
            raise ClockedAttempt(
                f"{_quote(challenge_id)} is a clocked attempt: starting it starts a clock, and flightdeck never starts "
                "one. Start it on the Game Master yourself; nothing was sent",
                sent=False,
            )
        answer = await self._exchange("POST", "start", payload={"challenge": challenge_id})
        if answer.status != 200:
            raise self._site.refused(answer, after="; the attempt was not started")
        self._object(answer)

    async def submit(self, challenge_id: str, answers: Mapping[str, str]) -> Submitted:
        """Submit answers for the challenge's attempt, {answer id: value}: one POST, never
        repeated. The Game Master's word as a Submitted; GameMasterError for a word that is
        not one of WORDS (it names the word), a verdict word that comes with another HTTP
        status than 200, an answer that is not the Game Master's JSON, or no answer."""
        _check_id(challenge_id, "challenge_id")
        if not isinstance(answers, Mapping) or not answers:
            raise ValueError("answers must map at least one answer id to its value")
        for key, value in answers.items():
            _check_id(key, "an answer id")
            if not isinstance(value, str) or not value:
                raise ValueError("an answer's value must be a non-empty string")
        answer = await self._exchange("POST", "submit", payload={"challenge": challenge_id, "answers": dict(answers)})
        return _submitted(self._site, answer)

    # ------------------------------------------------------------------ requests

    async def _exchange(
        self, method: str, request: str, *, params: Mapping[str, str] | None = None, payload: dict | None = None
    ) -> _Answer:
        """One call: the last answer, after retries for a GET. Raises GameMasterError when no
        answer came; an answer of any status is the caller's to judge."""
        if self._closed:
            raise RuntimeError("the Game Master client is closed")
        name = f"{method} {request}"
        content = None if payload is None else json.dumps(payload, ensure_ascii=True).encode("ascii")
        tries = self.max_retries + 1 if method == "GET" else 1
        for attempt in range(tries):
            failure = None
            try:
                answer = await self._once(method, name, params, content)
            except httpx.HTTPError as exc:
                failure = _describe(exc)  # the error itself is dropped: its request holds the token
            last = attempt + 1 >= tries
            if failure is None:
                answer.tries = attempt + 1
                if last or not _retryable(answer.status):
                    return answer
                wait = self._delay(attempt, answer.headers.get("retry-after"))
            else:
                if last or not failure.transient:
                    raise self._site.no_answer(name, failure, attempt + 1, write=request if method == "POST" else None)
                wait = self._delay(attempt, None)
            await asyncio.sleep(wait)
        raise AssertionError("unreachable")  # pragma: no cover

    async def _once(self, method: str, name: str, params: Mapping[str, str] | None, content: bytes | None) -> _Answer:
        headers = {"Content-Type": "application/json"} if content is not None else None
        async with self._http.stream(method, self._site.root, params=params, content=content, headers=headers) as response:
            body = await _read(response, MAX_API_BYTES)
            if body is None:
                raise self._site.error(
                    f"the Game Master at {self._site.root} answered {name} with more than {MAX_API_BYTES:,} bytes; "
                    "flightdeck refuses an answer that big",
                    request=name, status=response.status_code,
                )
            return _Answer(name, response.status_code, response.headers, body)

    def _where(self, answer: _Answer) -> str:
        return f"the Game Master at {self._site.root} answered {answer.request}"

    def _object(self, answer: _Answer) -> dict:
        """A successful answer's JSON object; GameMasterError for anything else."""
        if answer.status != 200:
            raise self._site.refused(answer)
        body = _parse(answer.body)
        if not isinstance(body, dict):
            raise self._site.error(
                f"{self._where(answer)} with something that is not a JSON object; is {self._site.root} the Game "
                "Master's address?",
                request=answer.request, status=answer.status,
            )
        return body

    def _delay(self, attempt: int, retry_after: str | None) -> float:
        asked = _retry_after(retry_after)
        seconds = asked if asked is not None else self.backoff * 2.0 ** min(attempt, 30)
        return min(self.max_wait, max(0.0, seconds))

    async def _fetch(
        self, params: Mapping[str, str], folder: Path, delivery: Delivery, request: str
    ) -> Path | tuple[_Answer | None, _Failure | None]:
        """One try at a download: the file, or the answer (429, 5xx) or failure worth another try."""
        try:
            async with self._http.stream("GET", self._site.root, params=params) as response:
                status = response.status_code
                if status != 200:
                    body = await _read(response, 64 * 1024) or b""
                    answer = _Answer(request, status, response.headers, body)
                    if _retryable(status):
                        return answer, None
                    raise self._site.refused(answer)
                return await self._save(response, folder, delivery, request)
        except httpx.HTTPError as exc:
            return None, _describe(exc)

    async def _save(self, response: httpx.Response, folder: Path, delivery: Delivery, request: str) -> Path:
        stated = delivery.name
        if stated is None:
            found = _DISPOSITION.search(response.headers.get("content-disposition", ""))
            stated = (found.group(1) or found.group(2)) if found is not None else None
        name = f"artifact-{delivery.index + 1}.bin" if stated is None else stated
        problem = _name_problem(name)
        if problem is not None:
            raise self._site.error(f"the file name {_quote(name)} of {request} {problem}; flightdeck refuses to write it",
                                   request=request)
        length = response.headers.get("content-length", "")
        if length.isdigit() and int(length) > self.max_file_bytes:
            raise self._too_big(request, name)
        fd, temp = tempfile.mkstemp(dir=folder, prefix=_DOWNLOAD)
        done = False
        try:
            digest = hashlib.sha256()
            with os.fdopen(fd, "wb") as out:
                size = 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > self.max_file_bytes:
                        raise self._too_big(request, name)
                    digest.update(chunk)
                    out.write(chunk)
            if delivery.sha256 is not None and digest.hexdigest() != delivery.sha256:
                raise self._site.error(
                    f"the file {_quote(name)} of {request} does not have the sha256 the Game Master states for it; "
                    "flightdeck does not keep it",
                    request=request,
                )
            os.chmod(temp, 0o644)
            try:
                path, placeholder = _create(folder, name)
            except CTFdError as exc:  # 99 files of that name there already
                raise GameMasterError(str(exc), request=request) from None
            os.close(placeholder)
            os.replace(temp, path)
            done = True
            return path
        finally:
            if not done:
                Path(temp).unlink(missing_ok=True)

    def _too_big(self, request: str, name: str) -> GameMasterError:
        return self._site.error(
            f"the file {_quote(name)} is over {self.max_file_bytes:,} bytes, more than flightdeck downloads by itself; "
            "fetch it by hand",
            request=request,
        )


def _submitted(site: _Site, answer: _Answer) -> Submitted:
    """The Game Master's answer to a submission as a Submitted; GameMasterError when it is not
    one this module knows (see the module's words)."""
    where = f"the Game Master at {site.root} answered {answer.request}"
    unknown = "nothing is known of the answer sent: check the challenge on the Game Master before submitting it again"
    if answer.status == 429:  # whatever its body: a proxy's rate limit says the same
        return Submitted(RATE_LIMITED, None, retry_after=_wait(answer.headers.get("retry-after")))
    body = _parse(answer.body)
    if not isinstance(body, dict):
        if answer.status == 401:
            raise site.refused(answer, after="; the answer was not checked")
        raise site.error(
            f"{where} with HTTP {answer.status}{_phrase(answer.status)} and something that is not the Game Master's "
            f"JSON; {unknown}",
            request=answer.request, status=answer.status, retryable=_retryable(answer.status),
        )
    word = _word(body)
    message = body.get("message")
    said = site.short(message) if isinstance(message, str) else ""
    if word in VERDICTS and answer.status == 200:
        if word == "CORRECT":
            flag = body.get("flag")
            return Submitted(word, True, said, flag=flag if isinstance(flag, str) and flag else None)
        if word == "accepted":
            remaining = body.get("remaining")
            counted = isinstance(remaining, int) and not isinstance(remaining, bool) and remaining >= 0
            return Submitted(word, True, said, remaining=remaining if counted else None)
        return Submitted(word, False if word == "incorrect" else None, said)
    if word in REFUSALS:
        return Submitted(word, None, said)
    if answer.status == 401:
        raise site.refused(answer, after="; the answer was not checked")
    if word is None:
        raise site.error(
            f"{where} with HTTP {answer.status}{_phrase(answer.status)} and no word (neither a result nor an error); "
            f"{unknown}",
            request=answer.request, status=answer.status, retryable=_retryable(answer.status),
        )
    raise site.error(
        f"{where} with the word {_quote(word)} and HTTP {answer.status}, which is not a Game Master verdict flightdeck "
        f"knows; {unknown}",
        request=answer.request, status=answer.status, retryable=_retryable(answer.status),
    )


def _attempt(site: _Site, challenge_id: str, body: dict, *, started: bool, answer: _Answer) -> Attempt:
    """An attempt from the status's JSON object. Fields of another type than the wire's are a
    GameMasterError, so a board is never made from half an attempt."""

    def bad(what: str) -> GameMasterError:
        return site.error(
            f"the Game Master at {site.root} answered {answer.request} for {_quote(challenge_id)} with {what}",
            request=answer.request, status=answer.status,
        )

    def listed(key: str, most: int) -> list:
        value = body.get(key)
        if value is None:
            return []
        if not isinstance(value, list) or len(value) > most:
            raise bad(f'"{key}" that is not a list of at most {most}')
        return value

    questions: list[Question] = []
    for item in listed("questions", MAX_ANSWERS):
        qid = item.get("id") if isinstance(item, dict) else None
        if not _is_id(qid):
            raise bad("a question without a usable id")
        form = item.get("answer_format")
        shown = json.dumps(form, ensure_ascii=False, sort_keys=True) if isinstance(form, (dict, str)) and form else ""
        questions.append(Question(qid, _text(item.get("question")), shown if len(shown) <= 1000 else shown[:997] + "..."))
    ids = listed("answer_ids", MAX_ANSWERS) or [question.id for question in questions]
    if not all(_is_id(aid) for aid in ids) or len(set(ids)) != len(ids):
        raise bad("answer ids that are not usable, or one twice")
    deliveries: list[Delivery] = []
    artifacts = listed("artifacts", MAX_FILES)
    if not artifacts and (body.get("download") or body.get("sha256")):
        artifacts = [{"filename": body.get("filename"), "sha256": body.get("sha256")}]
    for index, item in enumerate(artifacts):
        if not isinstance(item, dict):
            raise bad("an artifact that is not a JSON object")
        name, digest = item.get("filename"), item.get("sha256")
        if name is not None and not isinstance(name, str):
            raise bad("an artifact whose file name is not a string")
        if digest is not None and (not isinstance(digest, str) or not _SHA256.fullmatch(digest.lower())):
            raise bad("an artifact whose sha256 is not 64 hex digits")
        deliveries.append(Delivery(index, name or None, digest.lower() if digest else None))
    targets: list[str] = []
    for item in listed("targets", MAX_FILES):
        url = item.get("url") if isinstance(item, dict) else None
        if isinstance(url, str) and url:
            targets.append(url)
    deadline = body.get("deadline")
    return Attempt(
        id=challenge_id,
        started=started,
        name=_text(body.get("name")) or None,
        prompt=_text(body.get("prompt")),
        guidance=_text(body.get("guidance")),
        questions=tuple(questions),
        answer_ids=tuple(ids),
        deliveries=tuple(deliveries),
        targets=tuple(targets),
        deadline=deadline if isinstance(deadline, str) and deadline else None,
        solved=body.get("result") == "CORRECT",
    )


# ---------------------------------------------------------------------- pulling a board


async def pull(
    client: GameMasterClient,
    dest: Path,
    *,
    event: str | None = None,
    flag_format: str | None = None,
    start: bool = False,
    progress: Callable[[str], None] | None = None,
) -> Pull:
    """Pull every started attempt the Game Master lists into the folder `dest` (made if
    missing), as a folder board: one challenge per answer of each attempt.

    An attempt that is not started is left out and named in Pull.unstarted with the reason:
    without `start`, every one; with `start`, a clocked one (flightdeck never starts a clock)
    and one the list says is solved (nothing to gain). With `start`, each other one is
    started (one POST, then its status is asked) and its id is in Pull.started. An attempt
    that cannot be pulled (its status or a file keeps failing, values that make no board
    challenge) is a line in Pull.problems, and the next pull tries it again. `progress` gets
    one line per challenge added and per attempt started, safe to print.

    `dest` must be empty, or a board pulled from this same Game Master before: then what is
    there is kept and only what is new is added. board.json gets `event` (None: the board's
    own, or the folder's name for a new board) and `flag_format`: None keeps the board's, and
    gives a new board DEFAULT_ANSWER_FORMAT; another format than the board has is refused.

    Raises GameMasterError when the pull cannot start (`dest` not usable, the list failing,
    the token refused) or the board would be empty (it says why, the unstarted attempts
    included); PullStopped when the token is refused partway. BoardError if the board folder
    does not load, OSError if board.json or gm.json cannot be written, ValueError for an empty
    event or a flag format the board loader would refuse.
    """
    if event is not None and (not isinstance(event, str) or not event.strip()):
        raise ValueError("event must be a non-empty string (the board's name), or None to keep the board's own")
    if flag_format is not None:
        check_flag_format(flag_format, "flag_format")
    folder = Path(dest).expanduser()
    if folder.exists() and not folder.is_dir():
        raise GameMasterError(f"{_show(folder)}: is not a directory to pull a board into")
    made = None
    try:
        folder.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        made = exc.strerror
    if made is not None:
        raise GameMasterError(f"{_show(folder)}: cannot create it ({made})")
    root = folder.resolve()
    _read_state(root, client.url)  # refuse a folder that is not ours before touching it
    with _locked(root):
        for entry in root.iterdir():  # staging folders a pull that died left behind (ours, by name; we hold the lock)
            if entry.name.startswith(_STAGING) and entry.is_dir() and not entry.is_symlink():
                shutil.rmtree(entry, ignore_errors=True)
        ids = _read_state(root, client.url)
        event, flag_format = _settings(root, ids, event, flag_format)
        rows = await client.challenges()
        # The folder is this Game Master's board from here on, even if no challenge comes through.
        _write_state(root, client.url, ids)
        _write_json(root / BOARD_FILE, {"event": event, "flag_format": flag_format})
        taken = {entry.name.lower() for entry in root.iterdir()} | set(ids)
        added: list[str] = []
        started: list[str] = []
        unstarted: list[str] = []
        problems: list[str] = []
        fatal: GameMasterError | None = None
        stage_root = root / f"{_STAGING}{secrets.token_hex(6)}"
        try:
            for row in rows:
                mine = {address.answer: slug for slug, address in ids.items() if address.challenge == row.id}
                if mine and all(_is_challenge_folder(root / slug) for slug in mine.values()):
                    continue  # pulled before: kept as it is
                reason = None
                try:
                    attempt = await client.status(row.id)
                    if not attempt.started:
                        why = _why_unstarted(row, start)
                        if why is not None:
                            unstarted.append(f"{_label(row)}: {why}")
                            continue
                        await client.start(row.id, mode=row.mode)
                        started.append(row.id)
                        if progress is not None:
                            progress(f"started {_label(row)}")
                        attempt = await client.status(row.id)
                        if not attempt.started:
                            raise GameMasterError("the Game Master took the start, and still says start_required")
                    new = await _pull_one(client, root, stage_root, row, attempt, mine, taken, ids)
                except GameMasterError as exc:
                    reason = str(exc).replace(str(stage_root), str(root))
                    if exc.status == 401:
                        fatal = exc  # the token was refused: so it would be for every challenge left
                except (BoardError, _Unusable) as exc:
                    reason = str(exc).replace(str(stage_root), str(root))
                except OSError as exc:
                    reason = f"cannot write it ({exc.strerror or type(exc).__name__})"
                if reason is not None:
                    problems.append(f"{_label(row)}: {reason}")
                if fatal is not None:
                    break
                if reason is not None:
                    continue
                for slug, line in new:
                    added.append(slug)
                    if progress is not None:
                        progress(line)
        finally:
            shutil.rmtree(stage_root, ignore_errors=True)
        if fatal is not None:
            raise PullStopped(fatal, tuple(added), tuple(started), tuple(unstarted), tuple(problems))
        if not any(_is_challenge_folder(entry) for entry in root.iterdir()):
            raise GameMasterError(_empty_board(client.url, len(rows), unstarted, problems, start))
        board = load_board(root)
    mapped = {item.challenge.id: ids[item.challenge.id] for item in board.challenges if item.challenge.id in ids}
    return Pull(board, mapped, tuple(added), tuple(started), tuple(unstarted), tuple(problems))


def check_site(url: str, token: str) -> None:
    """ValueError, saying why, when the Game Master's URL or the token cannot be used (a token
    no HTTP header can carry); its message never shows the token. Nothing is sent."""
    _Site(url, token)


def load_ids(dest: Path, url: str | None = None) -> dict[str, Address]:
    """The board id -> Address mapping a pull wrote into the board folder `dest`. With `url`,
    GameMasterError unless the board was pulled from that Game Master."""
    root = Path(dest).expanduser().resolve()
    path = root / STATE_FILE
    if not (path.is_symlink() or path.exists()):
        raise GameMasterError(
            f"{_show(path)}: no such file, so this is not a board pulled from a Game Master: `flightdeck gm pull` writes it"
        )
    stored, ids = _parse_state(path)
    if url is not None and stored != _Site.address(url):
        raise GameMasterError(
            f"{_show(path)}: this board was pulled from {_show(stored)}, not from {_show(_Site.address(url))}"
        )
    return ids


def _why_unstarted(row: Listed, start: bool) -> str | None:
    """Why an attempt that is not started stays so in this pull; None when the pull starts it."""
    if row.clocked:
        return ("not started, and its start runs a clock: flightdeck never starts one. Start it on the Game Master "
                "yourself, then pull again")
    if row.solved:
        return "not started, and the Game Master lists it as solved, so there is nothing to start it for"
    if not start:
        return "not started: pull with --start to start it, or start it on the Game Master, then pull again"
    return None


def _empty_board(url: str, listed: int, unstarted: list[str], problems: list[str], start: bool) -> str:
    if not listed:
        return f"the Game Master at {url} lists no challenges for this account yet"
    text = f"none of the {listed} challenge{'' if listed == 1 else 's'} the Game Master at {url} lists could be pulled"
    if unstarted:
        count = len(unstarted)
        text += f": {count} {'is' if count == 1 else 'are'} not started"
        if not start:
            text += " (pull with --start to start every attempt that runs no clock)"
        text += ": " + "; ".join(unstarted)
    return text + (". Not pulled: " + "; ".join(problems) if problems else "")


class _Unusable(Exception):
    """An attempt whose details make no board challenge; the message says why."""


async def _pull_one(
    client: GameMasterClient,
    root: Path,
    stage_root: Path,
    row: Listed,
    attempt: Attempt,
    mine: Mapping[str, str],
    taken: set[str],
    ids: dict[str, Address],
) -> list[tuple[str, str]]:
    """Pull one attempt into root/<slug>, one folder per answer id: (slug, a progress line) of
    each folder written. Its files are downloaded once and copied into each folder. The
    folders are built in the staging folder and checked with load_board() first, and the
    mapping is written before they move into place: a crash in between leaves a mapped slug
    with no folder, which the next pull fills in (`mine`: answer id -> the slug it has)."""
    if not attempt.answer_ids:
        raise _Unusable("its attempt lists no answer ids, so flightdeck has nowhere to send an answer for it")
    name = attempt.name or row.name
    several = len(attempt.answer_ids) > 1
    urls = _targets(attempt.targets)
    wanted: list[tuple[str, str, str]] = []  # (answer id, slug, the challenge's name on the board)
    for aid in attempt.answer_ids:
        slug = mine.get(aid)
        if slug is not None and _is_challenge_folder(root / slug):
            continue
        if slug is not None and ((root / slug).is_symlink() or (root / slug).exists()):
            raise _Unusable(f"{_show(root / slug)} is in the way (not a challenge folder); move it to pull this again")
        if slug is None:
            slug = _new_slug(name, row.id, aid if several else "", taken | {s for _, s, _ in wanted})
        wanted.append((aid, slug, f"{name} ({aid})" if several else name))
    if not wanted:
        return []
    stage_root.mkdir(exist_ok=True)
    first = stage_root / wanted[0][1]
    built: list[Path] = []
    try:
        first.mkdir()
        built.append(first)
        names = [(await client.artifact(row.id, delivery, first)).name for delivery in attempt.deliveries]
        for _, slug, _ in wanted[1:]:
            stage = stage_root / slug
            stage.mkdir()
            built.append(stage)
            for file in names:
                shutil.copyfile(first / file, stage / file)
                os.chmod(stage / file, 0o644)
        for position, (aid, slug, title) in enumerate(wanted):
            _write_json(stage_root / slug / CHALLENGE_FILE, {
                "name": title,
                "category": row.lane,
                "points": 0,
                "solves": 0,
                "description": _description(attempt, aid, name, urls),
                "files": names,
                "urls": list(urls),
                "id": slug,
            })
        try:
            load_board(stage_root)
        except BoardError as exc:
            raise _Unusable(f"flightdeck could not make a valid {CHALLENGE_FILE} of it: {exc}") from None
        before = dict(ids)
        ids.update({slug: Address(row.id, aid) for aid, slug, _ in wanted})
        _write_state(root, client.url, ids)
        moved: list[Path] = []
        try:
            for _, slug, _ in wanted:
                os.rename(stage_root / slug, root / slug)
                moved.append(root / slug)
        except OSError:
            for path in moved:
                shutil.rmtree(path, ignore_errors=True)
            ids.clear()
            ids.update(before)
            _write_state(root, client.url, ids)
            raise
    except BaseException:
        for stage in built:
            shutil.rmtree(stage, ignore_errors=True)
        raise
    lines = []
    count = len(names)
    for _, slug, title in wanted:
        taken.add(slug)
        lines.append((slug, f"added {slug}: {_quote(title)} ({untrusted(row.lane, one_line=True) or 'no lane'}, "
                            f"{count} file{'' if count == 1 else 's'})"))
    return lines


def _targets(targets: tuple[str, ...]) -> tuple[str, ...]:
    """The origins and TCP services a board's challenge.json takes, from an attempt's targets."""
    found: list[str] = []
    for target in targets:
        for url in (*origins_in(target), *services_in(target)):
            if url not in found:
                found.append(url)
    return tuple(found)


def _description(attempt: Attempt, answer_id: str, name: str, urls: tuple[str, ...]) -> str:
    """A board challenge's description: the attempt's prompt and guidance and this answer's
    question as the Game Master wrote them (cut at MAX_TEXT characters each), then the
    paragraphs flightdeck adds: the targets, the deadline, the other answers, how to answer."""
    question = next((q for q in attempt.questions if q.id == answer_id), None)
    parts = [_cut(attempt.prompt), _cut(attempt.guidance)]
    asked = f"Question ({answer_id})" + (f": {_cut(question.text)}" if question is not None and question.text else "")
    if question is not None and question.format:
        asked += f"\nAnswer format: {question.format}"
    parts.append(asked)
    if attempt.targets:
        parts.append("Targets: " + " ".join(target[:500] for target in attempt.targets[:16]))
    if attempt.deadline is not None:
        parts.append(f"The attempt ends at {attempt.deadline[:64]} (as the Game Master said when the board was pulled).")
    count = len(attempt.answer_ids)
    if count > 1:
        parts.append(
            f"This is one of the {count} answers of one Game Master attempt, {name}: the others are challenges of "
            "their own on this board. Give this challenge the answer to the question above only."
        )
    parts.append(
        "The answer is not a flag in a form of its own. Submit it in the event's flag format: where that format has "
        'a group named "answer", the answer is the part the group matches, and only that part is sent on.'
    )
    return "\n\n".join(part for part in parts if part)


def _cut(text: str) -> str:
    return text if len(text) <= MAX_TEXT else text[: MAX_TEXT - 40].rstrip() + "\n[cut short by flightdeck]"


def _new_slug(name: str, challenge_id: str, answer_id: str, taken: set[str]) -> str:
    base = slugify(name) or slugify(challenge_id) or "challenge"
    part = slugify(answer_id)[:16].rstrip("-") if answer_id else ""
    if part:
        base = f"{base}-{part}"
    for candidate in [base] + [f"{base}-{n}" for n in range(2, 100)]:
        if candidate.lower() not in taken:
            return candidate
    raise _Unusable(f"every folder name tried for it ({base}, ...) is taken")


def _settings(root: Path, known: Mapping[str, Address], event: str | None, flag_format: str | None) -> tuple[str, str]:
    """board.json's event and flag format after this pull (see pull())."""
    if not known:  # a new board, or one whose first pull got no challenge through: nothing played yet
        return (root.name if event is None else event), (DEFAULT_ANSWER_FORMAT if flag_format is None else flag_format)
    stored_event, stored_format = _board_json(root)
    if flag_format is not None and stored_format is not None and flag_format != stored_format:
        raise GameMasterError(
            f"{_show(root / BOARD_FILE)}: the board's flag format is {_show(stored_format)}, not {_show(flag_format)}; "
            "leave the flag format out to keep the board's, or change it in board.json first"
        )
    kept = stored_format if flag_format is None else flag_format
    return (stored_event if event is None else event), (DEFAULT_ANSWER_FORMAT if kept is None else kept)


def _is_challenge_folder(entry: Path) -> bool:
    return not entry.is_symlink() and entry.is_dir() and (entry / CHALLENGE_FILE).is_file()


# ---------------------------------------------------------------------- the board folder


@contextmanager
def _locked(root: Path) -> Iterator[None]:
    """One pull at a time into a folder (an exclusive lock on its lock file)."""
    import fcntl  # POSIX only: macOS and Linux (Windows through WSL), as flightdeck supports

    fd, problem = -1, None
    try:
        fd = os.open(root / _LOCK, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), 0o644)
    except OSError as exc:
        problem = exc.strerror or type(exc).__name__
    if problem is not None:
        raise GameMasterError(f"{_show(root / _LOCK)}: cannot open the pull's lock file ({problem})")
    try:
        busy = False
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            busy = True
        if busy:
            raise GameMasterError(f"{_show(root)}: another pull into this folder is running; wait for it to finish")
        yield
    finally:
        os.close(fd)


def _read_state(root: Path, url: str) -> dict[str, Address]:
    """The mapping already in `root`, or {} for an empty folder; GameMasterError for a folder
    that holds something else, or a board pulled from another Game Master."""
    path = root / STATE_FILE
    if not (path.is_symlink() or path.exists()):
        others = [
            entry.name for entry in root.iterdir() if entry.name not in _IGNORED and not entry.name.startswith(_STAGING)
        ]
        if others:
            raise GameMasterError(
                f"{_show(root)}: is not empty and holds no {STATE_FILE}, so it is not a board flightdeck pulled from a "
                "Game Master; pull into a new or empty folder"
            )
        return {}
    stored, ids = _parse_state(path)
    if stored != url:
        if not ids:  # claimed by a pull that got no challenge through (a mistyped URL): free to claim again
            return {}
        raise GameMasterError(
            f"{_show(path)}: this board was pulled from {_show(stored)}, not {_show(url)}; pull into another folder"
        )
    return ids


def _parse_state(path: Path) -> tuple[str, dict[str, Address]]:
    where = _show(path)
    data: object = None
    problem = None
    try:
        info = path.lstat()
        if stat.S_ISREG(info.st_mode) and info.st_size <= MAX_STATE_BYTES:
            data = _parse(path.read_bytes())
        else:
            problem = f"must be a regular file of at most {MAX_STATE_BYTES:,} bytes, not a symlink"
    except OSError as exc:
        problem = f"cannot read it ({exc.strerror})"
    if problem is not None:
        raise GameMasterError(f"{where}: {problem}")
    if not isinstance(data, dict) or set(data) != {"url", "ids"}:
        raise GameMasterError(f'{where}: must be a JSON object with exactly the keys "url" and "ids"')
    url, ids = data["url"], data["ids"]
    if not isinstance(url, str) or not isinstance(ids, dict):
        raise GameMasterError(f'{where}: "url" must be a string and "ids" an object of board id to its challenge and answer')
    found: dict[str, Address] = {}
    for slug, entry in ids.items():
        challenge = entry.get("challenge") if isinstance(entry, dict) else None
        answer = entry.get("answer") if isinstance(entry, dict) else None
        if not _SLUG.fullmatch(slug) or set(entry if isinstance(entry, dict) else ()) != {"challenge", "answer"} \
                or not _is_id(challenge) or not _is_id(answer):
            raise GameMasterError(
                f'{where}: "ids" must map board ids to {{"challenge": the Game Master\'s challenge id, "answer": its '
                "answer id}"
            )
        address = Address(challenge, answer)
        if address in found.values():
            raise GameMasterError(f'{where}: "ids" gives one answer of one challenge to two board ids')
        found[slug] = address
    return url, found


def _write_state(root: Path, url: str, ids: Mapping[str, Address]) -> None:
    _write_json(root / STATE_FILE, {
        "url": url,
        "ids": {slug: {"challenge": address.challenge, "answer": address.answer} for slug, address in sorted(ids.items())},
    })


# ---------------------------------------------------------------------- checks and messages


class _Site:
    """A Game Master's address and token: the request headers, and messages that never show the token."""

    def __init__(self, url: str, token: str) -> None:
        self.root = self.address(url)
        if not isinstance(token, str) or not _TOKEN_CHARS.fullmatch(token):
            raise ValueError(
                "the Game Master token is empty or holds characters an HTTP header cannot carry (spaces, line breaks, "
                "non-ASCII); check the variable it came from"
            )
        self._token = token

    @staticmethod
    def address(url: object) -> str:
        """The one URL every request goes to: the address given, with a path that ends in "/"."""
        if not isinstance(url, str) or not url.lower().startswith(("http://", "https://")):
            raise ValueError("the Game Master's URL must start with http:// or https://")
        parsed = None
        try:
            parsed = httpx.URL(url)
        except httpx.InvalidURL:
            pass
        if parsed is None:
            raise ValueError("the Game Master's URL is not a valid URL")
        if not parsed.host:
            raise ValueError("the Game Master's URL has no host")
        if parsed.userinfo:
            raise ValueError(
                "the Game Master's URL holds a user name or password; give the token through its environment variable, "
                "never in the URL"
            )
        if parsed.query or parsed.fragment:
            raise ValueError("the Game Master's URL must not have a query or a fragment: give the address it answers at")
        return str(parsed.copy_with(path=parsed.path.rstrip("/") + "/"))

    def headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
            "User-Agent": f"ctf-flightdeck/{__version__}",
        }

    def short(self, text: str) -> str:
        """The server's words, safe to show: no token, one line, cut short."""
        text = untrusted(_valid(text).replace(self._token, "[token]")[: MAX_SHOWN * 4], one_line=True).strip()
        return text if len(text) <= MAX_SHOWN else text[: MAX_SHOWN - 3] + "..."

    def error(
        self, message: str, *, request: str | None = None, status: int | None = None, retryable: bool = False,
        sent: bool = True,
    ) -> GameMasterError:
        text = _valid(message).replace(self._token, "[token]")
        return GameMasterError(untrusted(text, one_line=True), request=request, status=status, retryable=retryable, sent=sent)

    def refused(self, answer: _Answer, *, after: str = "") -> GameMasterError:
        """The GameMasterError for an answer that is not a success."""
        status, request = answer.status, answer.request
        body = _parse(answer.body)
        word = _word(body) if isinstance(body, dict) else None
        message = body.get("message") if isinstance(body, dict) else None
        said = "; ".join(self.short(part) for part in (word, message) if isinstance(part, str) and part)
        says = f" (the Game Master says: {said})" if said else ""
        where = f"the Game Master at {self.root}"
        if 300 <= status < 400:
            text = (f"{where} answered {request} with a redirect (HTTP {status}{_phrase(status)}); flightdeck never "
                    "follows a redirect with the token. Check the Game Master's URL (https, and the exact address)")
        elif status == 401:
            text = (f"{where} refused the token (HTTP 401) at {request}{says}. Check the token in the variable it comes "
                    "from")
        else:
            text = f"{where} answered HTTP {status}{_phrase(status)} at {request}{says}"
        if answer.tries > 1:
            text += f"; gave up after {answer.tries} tries"
        return self.error(text + after, request=request, status=status, retryable=_retryable(status))

    def no_answer(self, request: str, failure: _Failure, tries: int, *, write: str | None = None) -> GameMasterError:
        text = f"no answer from the Game Master at {self.root} to {request}: {self.short(failure.what)}"
        if tries > 1:
            text += f"; gave up after {tries} tries"
        if write is not None:
            what = "the answer" if write == "submit" else "the start"
            text += (
                f"; {what} may have reached the Game Master: check the challenge there before sending it again"
                if failure.sent
                else f"; {what} was not sent"
            )
        return self.error(text, request=request, retryable=failure.transient, sent=failure.sent)


def _word(body: dict) -> str | None:
    """The word of a Game Master answer: its "error", else its "result"."""
    for key in ("error", "result"):
        word = body.get(key)
        if isinstance(word, str) and word:
            return word
    return None


def _wait(value: str | None) -> float | None:
    seconds = _retry_after(value)
    return None if seconds is None else max(0.0, seconds)


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""


def _is_id(value: object) -> bool:
    """A challenge id or answer id flightdeck can use: a string of 1 to MAX_ID characters, one
    line, with no control or invisible characters and no surrounding space."""
    return (isinstance(value, str) and 0 < len(value) <= MAX_ID and value.strip() == value
            and untrusted(_valid(value), one_line=True) == value)


def _check_id(value: object, what: str) -> None:
    if not _is_id(value):
        raise ValueError(f"{what} must be a Game Master id: 1 to {MAX_ID} characters on one line, with no control characters")


def _name_problem(name: str) -> str | None:
    """Why `name` is not a plain file name to write; None when it is one."""
    if not name or name in (".", ".."):
        return "is not a file name"
    if "/" in name or "\\" in name or "\x00" in name:
        return "is a path, not a plain file name"
    if untrusted(_valid(name), one_line=True) != name or name.strip() != name:
        return "holds control, invisible or surrounding space characters"
    if len(name.encode("utf-8", "surrogatepass")) > 255:
        return "is longer than a file name may be"
    if name.startswith((_DOWNLOAD, _STAGING)) or name == _LOCK:
        return "is a name flightdeck keeps for itself"
    return None


def _label(row: Listed) -> str:
    return f"{_quote(row.id)}" + (f" ({_quote(row.name)})" if row.name != row.id else "")
