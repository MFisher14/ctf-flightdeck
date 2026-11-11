"""The CTFd adapter: pull a CTFd board into a folder board, submit flags, read the solves.

flightdeck plays a CTFd event through the folder board of M1 (platform/manual.py): a pull
writes each challenge CTFd shows into a folder of its own, with its challenge.json and its
downloaded files, and the deck works that folder as it works any board. Flags go back
through CTFdVerifier, the deck's verify(), which the deck calls only for a flag the player
approved (or under the auto submit policy).

CTFd's API (v1), as this module uses it:
- Every request carries `Authorization: Token <token>` and `Content-Type: application/json`.
  CTFd reads the token only from a request that says it is JSON, GETs included; without
  that header a request counts as anonymous.
- Answers are {"success": bool, "data": ...}. A 401 means CTFd refused the token; a 403 that
  it was refused, or that this account may not do this now (no team yet, the CTF not
  running, banned).
- /api/v1/challenges lists the challenges. CTFd does not page it, but meta.pagination is
  followed when a server does. A challenge locked behind another is listed as type "hidden",
  name "???": it is left out until a later pull finds it unlocked.
- POST /api/v1/challenges/attempt puts a status in its data whatever the HTTP status: paused
  comes as 403, ratelimited as 429 or 403. A challenge out of tries comes as "incorrect" with
  403, sent before CTFd looks at the flag (the last real try is "incorrect" with 200): this
  module calls that "locked_out", since the flag was not checked and may be right.
- /api/v1/teams/me/solves holds the team's solves. In users mode CTFd answers 404 there (and
  403 to a user not on a team yet); then /api/v1/users/me/solves is asked instead.

Retries: a GET that gets 429 or 5xx, or no answer at all, is tried again with backoff (a
Retry-After in seconds or as an HTTP date is honoured, capped at max_wait). A flag attempt is
never retried: a second try could count twice (CTFd counts attempts and may cap them), so it
is reported as it went, and the player decides.

Secrets: the token goes in the Authorization header and nowhere else: not in a repr, an
error or an exception chain (no httpx error is chained: its request holds the header). Text
from the server has the token cut out before it is shown. A redirect is never followed with
the token off the CTFd's own origin: an API redirect is an error, and a download follows one
with the token only on that origin. A download redirected to another host (CTFd keeping its
files on S3 answers with a signed URL on the storage's host) is followed only over https,
by a second client that sends no token, no cookie and no JSON header. The per-file token
CTFd puts in each file URL (?token=...) and a signed URL's query are credentials too, so a
file is named by its path, and another host by its origin, never by a query.

Untrusted data: everything from CTFd (names, descriptions, connection info, file names,
messages) is data, shown only through text.untrusted() and cut short. A file URL must stay on
the CTFd's origin and a file name must be a plain name (no path, no "..", no control
characters), or the download is refused. Nothing pulled is ever run, and files are written
without an execute bit.

The board folder: dest/<slug>/ (challenge.json and its files) for each challenge,
dest/board.json, and dest/ctfd.json, which records the CTFd's URL and the CTFd id of every
board id (slug) pulled: {"url": ..., "ids": {slug: id}}. load_ids() reads it back for
CTFdVerifier. It sits outside every challenge folder, so no lane sees it. A challenge folder
appears only when it is complete: it is built in a staging folder, checked with load_board(),
then moved into place. A pull into a folder that already holds a board from the same CTFd
keeps every folder there as it is and adds the challenges that are new (a second wave); a
challenge that cannot be pulled is left out with the reason, and tried again by the next pull.
"""

from __future__ import annotations

import asyncio
import email.utils
import json
import os
import re
import secrets
import shutil
import stat
import tempfile
import threading
import time
import unicodedata
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from pathlib import Path
from urllib.parse import unquote

import httpx

from .. import __version__
from ..text import untrusted
from .manual import BOARD_FILE, CHALLENGE_FILE, MAX_JSON_BYTES, Board, BoardError, load_board
from .manual import _origin as _board_origin  # the board's own rule for an origin, so what a pull writes loads
from .manual import _settings as _board_json  # board.json's event and flag format, read as the board loader reads them

API = "/api/v1"
STATE_FILE = "ctfd.json"
"""In the board folder: the CTFd's URL and the CTFd id of each board id pulled."""

ATTEMPT_STATUSES = ("correct", "incorrect", "already_solved", "paused", "ratelimited", "partial", "locked_out")
"""CTFd's answers to a flag. "partial": part of a multi-part answer was right (CTFd 3.8+).
"locked_out": CTFd's "incorrect" sent with HTTP 403, which means this account has no tries
left on the challenge: CTFd did not check the flag."""

MAX_WAIT = 30.0  # seconds: the longest pause between tries, whatever Retry-After asks for
CONNECT_TIMEOUT = 10.0  # seconds: a connection that takes longer is not coming
MAX_API_BYTES = 20_000_000  # an API answer bigger than this is refused
MAX_ATTEMPT_BYTES = 64 * 1024  # the verifier's limit for an answer to a flag (CTFd's is a few hundred bytes)
MAX_FILE_BYTES = 1 << 30  # a handout file bigger than this is refused (1 GiB); fetch it by hand
MAX_STATE_BYTES = 1_000_000  # a ctfd.json bigger than this is refused
MAX_PAGES = 500  # pages of one listing; more means a server that never stops
MAX_REDIRECTS = 3  # same-origin redirects a download follows
MAX_SHOWN = 200  # characters of the server's own words kept in a message
MAX_ID = 2**53  # CTFd ids are database ids; anything bigger is not one
SLUG_MAX = 40  # characters of a name kept in its slug; room for "-<id>-<n>" within 64
DESCRIPTION_MAX_BYTES = MAX_JSON_BYTES // 5  # a description bigger as JSON is cut short; challenge.json stays loadable
DESCRIPTION_FILE = "description.md"  # where the whole of a description cut short goes, beside the handout
MAX_PARAGRAPH = 2_000  # characters of a paragraph flightdeck adds (the connection info) kept beside a cut description

_LOCK = ".ctfd-pull.lock"
_STAGING = ".ctfd-pull-"
_IGNORED = frozenset({_LOCK, ".DS_Store"})  # what may sit in an empty board folder
_TOKEN_CHARS = re.compile(r"[\x21-\x7e]+")  # what a token may hold: printable ASCII, no spaces
_SECONDS = re.compile(r"\s*(\d{1,10}(?:\.\d{1,6})?)\s*")
_URL = re.compile(r"https?://[^\s<>\"'`\\]+", re.IGNORECASE)
_HOST = re.compile(r"[a-z0-9_.-]+")
_FILE_TOKEN = re.compile(r"([?&]token=)[^&#\s]*", re.IGNORECASE)
_NOT_JSON = object()
_LATE = object()  # an answer that was not all in by the deadline
_TRANSIENT = (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError)
_UNSENT = (httpx.ConnectError, httpx.ConnectTimeout)  # the request never left this machine


class CTFdError(Exception):
    """A CTFd request failed, or a pull cannot go on. The message says what and why,
    naming the endpoint and the HTTP status when there was one. It never holds the token.

    `retryable` is True when the failure was of a kind that passes (no answer, 429, 5xx):
    trying again later may work. A pull stops at a refused token, and at such an error when
    CTFd's challenge list fails too, instead of meeting it again for every challenge left.
    """

    def __init__(
        self, message: str, *, endpoint: str | None = None, status: int | None = None, retryable: bool = False
    ) -> None:
        super().__init__(message)
        self.endpoint = endpoint  # e.g. "GET /api/v1/challenges"
        self.status = status  # the HTTP status of the answer; None when there was no answer
        self.retryable = retryable


@dataclass(frozen=True)
class Attempt:
    """CTFd's answer to a flag. `status` is one of ATTEMPT_STATUSES; `message` is CTFd's
    own words, made safe to show (one line, control characters visible, cut short)."""

    status: str  # correct | incorrect | already_solved | paused | ratelimited | partial | locked_out
    message: str


@dataclass(frozen=True)
class Pull:
    """What a pull wrote, and what it could not."""

    board: Board  # load_board(dest) after the pull
    ids: Mapping[str, int]  # board id -> CTFd id, for every challenge on the board pulled from CTFd
    added: tuple[str, ...]  # board ids new in this pull (a wave), in CTFd id order
    problems: tuple[str, ...]  # one line per challenge left out this time, and why; safe to print
    hidden: int  # challenges CTFd lists as locked ("???") until a prerequisite is solved


class PullIncomplete(CTFdError):
    """pull_board() wrote what it could but left challenges out. `pull` holds the board as
    written and a reason per challenge left out; the next pull tries those again."""

    def __init__(self, pull: Pull) -> None:
        count = len(pull.problems)
        super().__init__(f"{count} challenge{'' if count == 1 else 's'} not pulled: " + "; ".join(pull.problems))
        self.pull = pull


class PullStopped(CTFdError):
    """pull() stopped partway: CTFd refused the token, or stopped answering (a challenge failed
    in a way that passes, and the challenge list, asked again, failed too). What was written
    stays, and the next pull goes on from there. `reason` says why it stopped, `added` holds
    the board ids this pull wrote, and `problems` a line per challenge it left out so far;
    the message holds all three. endpoint, status and retryable are those of the cause."""

    def __init__(self, cause: CTFdError, added: tuple[str, ...], problems: tuple[str, ...]) -> None:
        count = len(added)
        self.reason = (
            f"{cause}; the pull stopped there, with {count} new challenge{'' if count == 1 else 's'} written: "
            "pull again to go on"
        )
        self.added = added
        self.problems = problems
        text = self.reason + (". Not pulled so far: " + "; ".join(problems) if problems else "")
        super().__init__(text, endpoint=cause.endpoint, status=cause.status, retryable=cause.retryable)


# ---------------------------------------------------------------------- the API client


@dataclass
class _Answer:
    endpoint: str
    status: int
    headers: httpx.Headers
    body: bytes
    tries: int = 1
    host: str | None = None  # the origin of the file host that answered, when it was not CTFd (a download)


@dataclass(frozen=True)
class _Failure:
    """A try that got no answer: what happened, whether a retry may help, whether the
    request may have reached the server."""

    what: str
    transient: bool
    sent: bool


class CTFdClient:
    """CTFd's API for one account (the token's), on one event loop.

    httpx pools connections per event loop, so keep a client on the loop that first uses it
    and `aclose()` it when done (or use `async with`). `timeout` bounds each try, in seconds
    (connecting gets at most CONNECT_TIMEOUT of it). A GET makes at most `max_retries + 1`
    tries; a flag attempt makes one. With `transport` given, httpx ignores proxy variables;
    it carries the requests to the CTFd only (a file on another host goes through httpx's
    own, see download()).
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        timeout: float = 30.0,
        max_retries: int = 3,
        backoff: float = 1.0,
        transport: httpx.AsyncBaseTransport | None = None,
        max_wait: float = MAX_WAIT,
        max_file_bytes: int = MAX_FILE_BYTES,
    ) -> None:
        self._site = _Site(base_url, token)
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
        self._elsewhere: httpx.AsyncClient | None = None  # for files on another host: made when first needed
        self._closed = False

    @property
    def base_url(self) -> str:
        """The CTFd's address as used: scheme://host[:port][/path], no trailing "/"."""
        return self._site.root

    def __repr__(self) -> str:
        return f"CTFdClient({self._site.root!r}, token=set)"

    async def __aenter__(self) -> CTFdClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        self._closed = True
        await self._http.aclose()
        if self._elsewhere is not None:
            await self._elsewhere.aclose()

    # ------------------------------------------------------------------ endpoints

    async def challenges(self) -> list[dict]:
        """Every challenge CTFd lists for this account, all pages, in CTFd's order. Each is
        CTFd's own dict (untrusted): id, type, name, value, solves, category, ..."""
        items = await self._all("/challenges")
        for item in items:
            if not isinstance(item, dict):
                raise self._site.error(
                    f"CTFd at {self._site.root} listed a challenge that is not a JSON object", endpoint=f"GET {API}/challenges"
                )
        return items

    async def challenge(self, challenge_id: int) -> dict:
        """One challenge's details (untrusted): name, value, description, connection_info,
        category, solves, files (URLs), ..."""
        _check_number(challenge_id, "challenge_id")
        answer = await self._exchange("GET", f"/challenges/{challenge_id}")
        data = self._ok(answer)["data"]
        if not isinstance(data, dict):
            raise self._site.error(
                f"CTFd at {self._site.root} answered {answer.endpoint} with data that is not a JSON object",
                endpoint=answer.endpoint,
                status=answer.status,
            )
        return data

    async def download(self, url: str, dest: Path) -> Path:
        """Fetch one URL from a challenge's "files" into the directory `dest`; the file written.

        The URL is resolved against base_url and must be on the CTFd's origin (scheme, host
        and port). A redirect on that origin is followed with the token. A redirect to another
        host is followed only over https, and from then on without the token, CTFd's cookies
        or the JSON header: CTFd keeping its files on S3 (or other object storage) answers a
        file with a redirect to a signed URL on the storage's host. At most MAX_REDIRECTS
        redirects in all. The file is named after the CTFd URL's last path segment, which must
        be a plain file name. A file already there is never overwritten: the new one is named
        name-2.ext, name-3.ext, ... (and challenge.json is never used, in any case). The
        download streams to disk, at most max_file_bytes; a failed one leaves no file.
        """
        target = self._file_url(url)
        name = _file_name(target, self._site)
        folder = Path(dest)
        if folder.is_symlink() or not folder.is_dir():
            raise CTFdError(f"{untrusted(str(folder), one_line=True)}: is not a directory to download into")
        endpoint = f"GET {_path_of(target)}"
        tries = self.max_retries + 1
        for attempt in range(tries):
            outcome = await self._fetch(target, folder, name, endpoint)
            if isinstance(outcome, Path):
                return outcome
            if attempt + 1 >= tries or (outcome.failure is not None and not outcome.failure.transient):
                raise self._gave_up(endpoint, outcome, attempt + 1)
            await asyncio.sleep(self._delay(attempt, outcome.retry_after))
        raise AssertionError("unreachable")  # pragma: no cover

    async def attempt(self, challenge_id: int, flag: str) -> Attempt:
        """Submit a flag, once (never retried: a second try could count twice). A 429 is a
        `ratelimited` attempt. An error that leaves the outcome unknown says so."""
        _check_number(challenge_id, "challenge_id")
        if not isinstance(flag, str):
            raise TypeError("flag must be a string")
        answer = await self._exchange(
            "POST", "/challenges/attempt", payload={"challenge_id": challenge_id, "submission": flag}, retry=False
        )
        return _attempt(self._site, answer)

    async def solved_ids(self) -> set[int]:
        """The CTFd ids of the challenges this account has solved: the team's solves in
        teams mode (a teammate's count), else the user's own."""
        path = "/teams/me/solves"
        team = await self._exchange("GET", path)
        if team.status in (403, 404):  # users mode answers 404; a user not on a team yet, 403
            path = "/users/me/solves"
            items = await self._all(path)
        else:
            items = await self._all(path, first=team)
        solved: set[int] = set()
        for item in items:
            number = item.get("challenge_id") if isinstance(item, dict) else None
            if not _is_number(number):
                raise self._site.error(
                    f"CTFd at {self._site.root} listed a solve without a challenge id at GET {API}{path}",
                    endpoint=f"GET {API}{path}",
                )
            solved.add(number)
        return solved

    # ------------------------------------------------------------------ requests

    async def _all(self, path: str, *, first: _Answer | None = None) -> list:
        """The data of every page of a listing, following meta.pagination.next."""
        items: list = []
        page = 1
        answer = first if first is not None else await self._exchange("GET", path)
        for _ in range(MAX_PAGES):
            doc = self._ok(answer)
            data = doc["data"]
            if not isinstance(data, list):
                raise self._site.error(
                    f"CTFd at {self._site.root} answered {answer.endpoint} with data that is not a list",
                    endpoint=answer.endpoint,
                    status=answer.status,
                )
            items.extend(data)
            following = self._next_page(doc, answer)
            if following is None:
                return items
            if following <= page:
                raise self._site.error(
                    f"CTFd at {self._site.root} answered {answer.endpoint} with a next page ({following}) that is "
                    f"not after page {page}",
                    endpoint=answer.endpoint,
                )
            page = following
            answer = await self._exchange("GET", f"{path}?page={page}")
        raise self._site.error(f"CTFd at {self._site.root} has more than {MAX_PAGES} pages at GET {API}{path}")

    def _next_page(self, doc: dict, answer: _Answer) -> int | None:
        meta = doc.get("meta")
        pagination = meta.get("pagination") if isinstance(meta, dict) else None
        following = pagination.get("next") if isinstance(pagination, dict) else None
        if following is None:
            return None
        if not _is_number(following):
            raise self._site.error(
                f"CTFd at {self._site.root} answered {answer.endpoint} with a next page that is not a page number",
                endpoint=answer.endpoint,
            )
        return following

    async def _exchange(self, method: str, path: str, *, payload: dict | None = None, retry: bool = True) -> _Answer:
        """One API call: the last answer, after retries if `retry`. Raises CTFdError when no
        answer came; an answer of any status is the caller's to judge."""
        if self._closed:
            raise RuntimeError("the CTFd client is closed")
        endpoint = f"{method} {API}{path}"
        url = self._site.root + API + path
        content = None if payload is None else json.dumps(payload, ensure_ascii=True).encode("ascii")
        tries = self.max_retries + 1 if retry else 1
        for attempt in range(tries):
            failure = None
            try:
                answer = await self._once(method, url, content, endpoint)
            except httpx.HTTPError as exc:
                failure = _describe(exc)
            last = attempt + 1 >= tries
            if failure is None:
                answer.tries = attempt + 1
                if last or not _retryable(answer.status):
                    return answer
                wait = self._delay(attempt, answer.headers.get("retry-after"))
            else:
                if last or not failure.transient:
                    raise self._site.no_answer(endpoint, failure, attempt + 1, submit=payload is not None)
                wait = self._delay(attempt, None)
            await asyncio.sleep(wait)
        raise AssertionError("unreachable")  # pragma: no cover

    async def _once(self, method: str, url: str, content: bytes | None, endpoint: str) -> _Answer:
        async with self._http.stream(method, url, content=content) as response:
            body = await _read(response, MAX_API_BYTES)
            if body is None:
                raise self._site.error(
                    f"CTFd at {self._site.root} answered {endpoint} with more than {MAX_API_BYTES:,} bytes; flightdeck "
                    "refuses an answer that big",
                    endpoint=endpoint,
                    status=response.status_code,
                )
            return _Answer(endpoint, response.status_code, response.headers, body)

    def _ok(self, answer: _Answer) -> dict:
        """A successful CTFd answer, {"success": true, "data": ...}; CTFdError for anything else."""
        if not 200 <= answer.status < 300:
            raise self._site.refused(answer)
        doc = _parse(answer.body)
        where = f"CTFd at {self._site.root} answered {answer.endpoint}"
        if not isinstance(doc, dict):
            what = "not JSON" if doc is _NOT_JSON else "not a JSON object"
            raise self._site.error(
                f"{where} with something that is not a CTFd API answer ({what}); is {self._site.root} the CTFd's address?",
                endpoint=answer.endpoint,
                status=answer.status,
            )
        if doc.get("success") is not True:
            said = self._site.short(_message(doc))
            raise self._site.error(
                f"{where} with success: false" + (f" (CTFd says: {said})" if said else ""),
                endpoint=answer.endpoint,
                status=answer.status,
            )
        if "data" not in doc:
            raise self._site.error(f"{where} without data", endpoint=answer.endpoint, status=answer.status)
        return doc

    def _delay(self, attempt: int, retry_after: str | None) -> float:
        """Seconds to wait after failed try number `attempt` (0 for the first): the server's
        Retry-After if it gave one, else backoff doubling; never more than max_wait."""
        asked = _retry_after(retry_after)
        seconds = asked if asked is not None else self.backoff * 2.0 ** min(attempt, 30)
        return min(self.max_wait, max(0.0, seconds))

    # ------------------------------------------------------------------ downloads

    def _file_url(self, url: object) -> httpx.URL:
        """A challenge's file URL, resolved against base_url; CTFdError unless it stays on the CTFd's origin."""
        if not isinstance(url, str) or not url.strip() or url != untrusted(url, one_line=True):
            raise self._site.error("a file entry is not a URL flightdeck can use")
        target, bad = None, False
        try:
            target = self._site.base.join(url.strip())
        except httpx.InvalidURL:
            bad = True
        if bad or target is None:
            raise self._site.error("a file entry is not a valid URL")
        if not _same_origin(target, self._site.base):
            raise self._site.error(
                f"the file {_quote(_last_segment(target))} is on another host ({_origin_text(target)}); flightdeck downloads "
                f"only from the CTFd at {self._site.root}"
            )
        if target.userinfo:
            raise self._site.error("a file URL holds a user name or password; flightdeck does not use it")
        return target

    async def _fetch(self, url: httpx.URL, folder: Path, name: str, endpoint: str) -> Path | _Again:
        """One try at a download, following redirects (see download())."""
        failure = None
        hops = 0
        host = None  # the other host's origin, once a redirect has left the CTFd's: the token stays behind
        try:
            while True:
                http = self._http if host is None else self._files_elsewhere()
                async with http.stream("GET", url) as response:
                    status = response.status_code
                    if 300 <= status < 400:
                        hops += 1
                        url = self._redirect(url, response.headers.get("location"), endpoint, status, hops, host)
                        if host is not None or not _same_origin(url, self._site.base):
                            host = _origin_text(url)
                        continue
                    if _retryable(status):
                        body = await _read(response, 64 * 1024) or b""
                        answer = _Answer(endpoint, status, response.headers, body, host=host)
                        return _Again(answer, None, response.headers.get("retry-after"), host)
                    if not 200 <= status < 300:
                        body = await _read(response, 64 * 1024) or b""
                        raise self._site.refused(_Answer(endpoint, status, response.headers, body, host=host))
                    return await self._save(response, folder, name, endpoint)
        except httpx.HTTPError as exc:
            failure = _describe(exc)
        return _Again(None, failure, None, host)

    def _redirect(
        self, current: httpx.URL, location: str | None, endpoint: str, status: int, hops: int, host: str | None
    ) -> httpx.URL:
        """Where a download's redirect leads, if flightdeck may follow it; CTFdError if not.
        `host` is the other host the download is on already (None: still on the CTFd's origin)."""
        who = f"CTFd at {self._site.root}" if host is None else f"the file host {host}"
        where = f"{who} answered {endpoint} with a redirect (HTTP {status})"
        if not location:
            raise self._site.error(f"{where} that names no place", endpoint=endpoint, status=status)
        target, bad = None, False
        try:
            target = current.join(location)
        except httpx.InvalidURL:
            bad = True
        if bad or target is None or not target.host:
            raise self._site.error(f"{where} to a URL that is not valid", endpoint=endpoint, status=status)
        if hops > MAX_REDIRECTS:
            raise self._site.error(f"{where}, more than {MAX_REDIRECTS} times", endpoint=endpoint, status=status)
        if target.userinfo:
            raise self._site.error(
                f"{where} to a URL with a user name or password in it, which flightdeck does not use; fetch this file "
                "by hand",
                endpoint=endpoint,
                status=status,
            )
        if host is None and _same_origin(target, self._site.base):
            return target  # still the CTFd's own origin: the token goes along
        if target.scheme != "https":
            raise self._site.error(
                f"{where} to another host ({_origin_text(target)}); flightdeck follows a download to another host only "
                "over https, so fetch this file by hand",
                endpoint=endpoint,
                status=status,
            )
        return target

    def _files_elsewhere(self) -> httpx.AsyncClient:
        """The client for a file on another host (object storage): no token, no cookie from
        CTFd, no JSON header; nothing but what a browser following the redirect would send."""
        if self._elsewhere is None:
            self._elsewhere = httpx.AsyncClient(
                headers={"User-Agent": f"ctf-flightdeck/{__version__}"},
                timeout=self._http.timeout,
                follow_redirects=False,
            )
        return self._elsewhere

    async def _save(self, response: httpx.Response, folder: Path, name: str, endpoint: str) -> Path:
        length = response.headers.get("content-length", "")
        if length.isdigit() and int(length) > self.max_file_bytes:
            raise self._too_big(endpoint, name)
        path, fd = _create(folder, name)
        done = False
        try:
            with os.fdopen(fd, "wb") as out:
                size = 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > self.max_file_bytes:
                        raise self._too_big(endpoint, name)
                    out.write(chunk)
            done = True
            return path
        finally:
            if not done:
                path.unlink(missing_ok=True)

    def _too_big(self, endpoint: str, name: str) -> CTFdError:
        return self._site.error(
            f"the file {_quote(name)} is over {self.max_file_bytes:,} bytes, more than flightdeck downloads by "
            "itself; fetch it by hand",
            endpoint=endpoint,
        )

    def _gave_up(self, endpoint: str, outcome: _Again, tries: int) -> CTFdError:
        if outcome.failure is not None:
            return self._site.no_answer(endpoint, outcome.failure, tries, host=outcome.host)
        assert outcome.answer is not None
        outcome.answer.tries = tries
        return self._site.refused(outcome.answer)


@dataclass(frozen=True)
class _Again:
    """A download try that may be worth repeating: an answer of 429 or 5xx, or no answer."""

    answer: _Answer | None
    failure: _Failure | None
    retry_after: str | None
    host: str | None = None  # the other host the download was on, when it was not CTFd's


# ---------------------------------------------------------------------- the deck's verifier


class CTFdVerifier:
    """The deck's verify() for a CTFd board: submits a flag and says whether it was right.

    True for correct, False for incorrect, None when CTFd did not judge the flag (already
    solved, paused, rate-limited, out of tries, a partial answer) or the outcome is unknown
    (no answer, an error): the deck then asks the player to submit by hand and confirm.
    `last_error` says why for the console; `last_attempt` holds CTFd's answer when there was
    one, and its status tells a caller what to do next: "already_solved" means the account
    (the team) solved the challenge already, without that flag being checked, and
    "locked_out" that no flag for it can be checked any more.

    The deck calls it synchronously on the console's event loop, so it never touches asyncio:
    one request with its own httpx.Client, which blocks the console for that round trip (a
    rare, player-approved action), and never longer than `timeout` seconds in all. httpx's
    timeouts bound each step of a request only (a server that sends a byte now and then
    never trips them), so the request runs in a worker thread the call waits for; one
    still going when the time is up is left to end on its own, and the answer is unknown.
    It never retries: a retried submit could count twice. `ids` maps board ids (slugs) to
    CTFd ids: Pull.ids, or load_ids(board folder); after a wave, add the new ones to
    `verifier.ids`.
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        ids: Mapping[str, int],
        *,
        timeout: float = 10.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._site = _Site(base_url, token)
        if not timeout > 0:
            raise ValueError(f"timeout must be a positive number of seconds, got {timeout}")
        self.ids: dict[str, int] = {}
        for key, value in ids.items():
            if not isinstance(key, str) or not _is_number(value):
                raise ValueError("ids must map board ids (strings) to CTFd challenge ids (whole numbers, 1 or more)")
            self.ids[key] = value
        self.timeout = timeout
        self.last_error: str | None = None
        self.last_attempt: Attempt | None = None
        self._http = httpx.Client(
            headers=self._site.headers(),
            timeout=httpx.Timeout(timeout, connect=min(timeout, CONNECT_TIMEOUT)),
            transport=transport,
            follow_redirects=False,
        )

    def __repr__(self) -> str:
        return f"CTFdVerifier({self._site.root!r}, token=set, {len(self.ids)} challenges)"

    def __enter__(self) -> CTFdVerifier:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._http.close()

    def __call__(self, challenge_id: str, flag: str) -> bool | None:
        self.last_error = None
        self.last_attempt = None
        number = self.ids.get(challenge_id)
        if number is None:
            self.last_error = (
                f"{untrusted(str(challenge_id), one_line=True)} was not pulled from CTFd, so flightdeck has no CTFd id to "
                "submit it to: submit it by hand, then say whether it was accepted"
            )
            return None
        endpoint = f"POST {API}/challenges/attempt"
        content = json.dumps({"challenge_id": number, "submission": flag}, ensure_ascii=True).encode("ascii")
        answer = self._submit(content, endpoint)
        if isinstance(answer, CTFdError):
            self.last_error = str(answer)
            return None
        if isinstance(answer, _Failure):
            self.last_error = str(self._site.no_answer(endpoint, answer, 1, submit=True))
            return None
        error = None
        try:
            attempt = _attempt(self._site, answer)
        except CTFdError as exc:
            error = str(exc)
        if error is not None:
            self.last_error = error
            return None
        self.last_attempt = attempt
        if attempt.status == "correct":
            return True
        if attempt.status == "incorrect":
            return False
        self.last_error = _unjudged(attempt)
        return None

    def _submit(self, content: bytes, endpoint: str) -> _Answer | _Failure | CTFdError:
        """The submission's one request, in a worker thread the call waits for, at most
        `timeout` seconds from now: CTFd's answer, the failure that left none, or the error
        that says none came in time (or one too big to be CTFd's)."""
        deadline = time.monotonic() + self.timeout
        unknown = "; the flag may have reached CTFd: check the challenge there before submitting it again"
        late = self._site.error(
            f"no complete answer from CTFd at {self._site.root} to {endpoint} within {self.timeout:g} s{unknown}",
            endpoint=endpoint,
            retryable=True,
        )
        box: list[_Answer | _Failure | CTFdError | BaseException] = []

        def exchange() -> None:
            try:
                with self._http.stream("POST", self._site.root + API + "/challenges/attempt", content=content) as response:
                    body = _read_sync(response, MAX_ATTEMPT_BYTES, deadline)
                    if isinstance(body, bytes):
                        box.append(_Answer(endpoint, response.status_code, response.headers, body))
                    elif body is None:
                        box.append(
                            self._site.error(
                                f"CTFd at {self._site.root} answered {endpoint} with more than {MAX_ATTEMPT_BYTES:,} "
                                f"bytes, which is not an answer to a flag{unknown}",
                                endpoint=endpoint,
                                status=response.status_code,
                            )
                        )
                    else:
                        box.append(late)
            except httpx.HTTPError as exc:
                box.append(_describe(exc))  # the error itself is dropped: its request holds the token
            except BaseException as exc:  # a bug: raised again in the caller's thread, never lost
                box.append(exc)

        worker = threading.Thread(target=exchange, name="ctfd-submit", daemon=True)
        worker.start()
        worker.join(max(0.0, deadline - time.monotonic()))
        if not box:
            return late  # the worker ends when the server answers, gives up or hangs up; its result is dropped
        outcome = box[0]
        if isinstance(outcome, BaseException) and not isinstance(outcome, CTFdError):
            raise outcome
        return outcome


def _unjudged(attempt: Attempt) -> str:
    said = f" (CTFd says: {attempt.message})" if attempt.message else ""
    if attempt.status == "already_solved":
        # CTFd answers so for any submission once the account has a solve: this flag may be wrong
        return f"CTFd says this challenge is already solved (by you or a teammate){said}; it did not check this flag"
    if attempt.status == "paused":
        return f"CTFd is paused, so it did not check the flag{said}. Submit it by hand when CTFd runs again"
    if attempt.status == "ratelimited":
        return f"CTFd rate-limited the submission and did not check the flag{said}. Wait, then submit it by hand"
    if attempt.status == "locked_out":
        return (
            f"CTFd did not check the flag: this account has no tries left on this challenge{said}, so CTFd checks "
            "no more flags for it. The flag is not known to be wrong"
        )
    return f"CTFd says the flag is only part of the answer{said}; the challenge is not solved yet"


def _attempt(site: _Site, answer: _Answer) -> Attempt:
    """CTFd's answer to a flag, whatever its HTTP status; CTFdError when it is not one."""
    doc = _parse(answer.body)
    data = doc.get("data") if isinstance(doc, dict) and doc.get("success") is True else None
    status = data.get("status") if isinstance(data, dict) else None
    where = f"CTFd at {site.root} answered {answer.endpoint}"
    if isinstance(status, str):
        message = data.get("message")
        said = site.short(message) if isinstance(message, str) else ""
        if status == "incorrect" and answer.status == 403:
            # CTFd's answer when the account has no tries left, sent before it checks the flag
            return Attempt("locked_out", said)
        if status in ATTEMPT_STATUSES:
            return Attempt(status, said)
        if status == "authentication_required":
            raise site.error(
                f"{where} with authentication_required: it did not take the token, and the flag was not submitted",
                endpoint=answer.endpoint,
                status=answer.status,
            )
        raise site.error(
            f"{where} with the status {_quote(status)}, which flightdeck does not know"
            + (f" (CTFd says: {said})" if said else "")
            + "; check the challenge on CTFd",
            endpoint=answer.endpoint,
            status=answer.status,
        )
    if answer.status == 429:  # a rate limit in front of CTFd (a proxy's): the flag was not checked
        wait = answer.headers.get("retry-after")
        return Attempt("ratelimited", "the server answered HTTP 429 (Too Many Requests)" + (f", retry after {site.short(wait)}" if wait else ""))
    if 200 <= answer.status < 300 or answer.status >= 500:
        error = site.refused(answer) if answer.status >= 500 else site.error(
            f"{where} with something that is not an answer to a flag", endpoint=answer.endpoint, status=answer.status
        )
        raise site.error(
            f"{error}; the flag may have reached CTFd: check the challenge there before submitting it again",
            endpoint=answer.endpoint,
            status=answer.status,
        )
    raise site.error(f"{site.refused(answer)}; the flag was not checked", endpoint=answer.endpoint, status=answer.status)


# ---------------------------------------------------------------------- pulling a board


async def pull(
    client: CTFdClient,
    dest: Path,
    *,
    event: str | None = None,
    flag_format: str | None,
    progress: Callable[[str], None] | None = None,
) -> Pull:
    """Pull the board from CTFd into the folder `dest` (made if missing), as a folder board.

    `dest` must be empty, or a board pulled from this same CTFd before: then the folders there
    are kept as they are and only challenges new on CTFd are added (a wave). A challenge that
    cannot be pulled (its details or a file keep failing, a value CTFd got wrong) is left out
    with the reason in Pull.problems, and tried again by the next pull. `progress` gets one
    line per challenge added, safe to print.

    board.json gets `event` (the board's name) and `flag_format`. None keeps what a board
    pulled before has in its board.json; on a new board, None names it after the folder and
    sets no flag format. A flag format other than the one a board has already is refused:
    a wave must not loosen the check that keeps decoy flags from being submitted (change it
    in board.json first if it is wrong).

    Raises CTFdError when the pull cannot start (`dest` not usable, a flag format the board
    does not have, the listing failing, the token refused) or the board would be empty (it
    says why: nothing listed, all locked, the reasons). PullStopped, a CTFdError, when it
    stops partway: the token refused, or CTFd no longer answering (a challenge failed with
    no answer, 429 or 5xx after the retries, and the challenge list, asked again, failed
    too); what was written by then stays, and the next pull goes on from there. BoardError
    if the board folder (board.json included) does not load, as after an edit by hand, and
    OSError if board.json or ctfd.json cannot be written.
    """
    if event is not None and (not isinstance(event, str) or not event.strip()):
        raise ValueError("event must be a non-empty string (the board's name), or None to keep the board's own")
    if flag_format is not None:
        bad = False
        try:
            re.compile(flag_format)
        except (re.error, TypeError):
            bad = True
        if bad or not flag_format:
            raise ValueError("flag_format must be a regular expression that compiles")
    folder = Path(dest).expanduser()
    if folder.exists() and not folder.is_dir():
        raise CTFdError(f"{_show(folder)}: is not a directory to pull a board into")
    made = None
    try:
        folder.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        made = exc.strerror
    if made is not None:
        raise CTFdError(f"{_show(folder)}: cannot create it ({made})")
    root = folder.resolve()
    _read_state(root, client.base_url)  # refuse a folder that is not ours before touching it
    with _locked(root):
        _clear_staging(root)
        known = _read_state(root, client.base_url)
        event, flag_format = _settings(root, known, event, flag_format)
        listing = await client.challenges()
        # The folder is this CTFd's board from here on, even if no challenge comes through.
        _write_state(root, client.base_url, known)
        _write_json(root / BOARD_FILE, {"event": event, **({"flag_format": flag_format} if flag_format is not None else {})})
        ids = dict(known)
        by_ctfd = {number: slug for slug, number in known.items()}
        taken = {entry.name.lower() for entry in root.iterdir()} | set(known)
        added: list[str] = []
        problems: list[str] = []
        hidden = 0
        fatal: CTFdError | None = None
        stage_root = root / f"{_STAGING}{secrets.token_hex(6)}"
        try:
            for number, item in _numbered(listing, problems):
                if item.get("type") == "hidden":
                    hidden += 1
                    continue
                slug = by_ctfd.get(number)
                if slug is not None:
                    there = root / slug
                    if there.is_symlink() or there.exists():
                        if not there.is_symlink() and there.is_dir() and (there / CHALLENGE_FILE).is_file():
                            continue  # pulled before: kept as it is
                        problems.append(
                            f"{_label(number, item.get('name'))}: {_show(there)} is in the way (not a challenge folder); "
                            "move it to pull this challenge again"
                        )
                        continue
                reason = None
                try:
                    slug, line = await _pull_one(client, root, stage_root, number, item, slug, taken, ids)
                except CTFdError as exc:
                    if exc.status == 401:
                        fatal = exc  # the token was refused: so it would be for every challenge left
                    else:
                        reason = str(exc).replace(str(stage_root), str(root))
                        if exc.retryable:
                            # no answer, 429 or 5xx after the retries: this challenge's own trouble (a plugin that
                            # fails, a file the proxy cannot serve) unless CTFd no longer answers its list either
                            fatal = await _not_answering(client)
                except (BoardError, _Unusable) as exc:
                    reason = str(exc).replace(str(stage_root), str(root))
                except OSError as exc:
                    reason = f"cannot write it ({exc.strerror or type(exc).__name__})"
                if reason is not None:
                    problems.append(f"{_label(number, item.get('name'))}: {reason}")
                if fatal is not None:
                    break
                if reason is not None:
                    continue
                by_ctfd[number] = slug
                added.append(slug)
                if progress is not None:
                    progress(line)
        finally:
            shutil.rmtree(stage_root, ignore_errors=True)
        if fatal is not None:
            raise PullStopped(fatal, tuple(added), tuple(problems))
        if not any(_is_challenge_folder(entry) for entry in root.iterdir()):
            raise CTFdError(_empty_board(client.base_url, len(listing), hidden, problems))
        board = load_board(root)
    mapped = {item.challenge.id: ids[item.challenge.id] for item in board.challenges if item.challenge.id in ids}
    return Pull(board=board, ids=mapped, added=tuple(added), problems=tuple(problems), hidden=hidden)


def _settings(root: Path, known: Mapping[str, int], event: str | None, flag_format: str | None) -> tuple[str, str | None]:
    """board.json's event and flag format after this pull (see pull())."""
    if not known:  # a new board, or one whose first pull got no challenge through: nothing played yet
        return (root.name if event is None else event), flag_format
    stored_event, stored_format = _board_json(root)
    if flag_format is not None and stored_format is not None and flag_format != stored_format:
        raise CTFdError(
            f"{_show(root / BOARD_FILE)}: the board's flag format is {_show(stored_format)}, not {_show(flag_format)}; "
            "leave the flag format out to keep the board's, or change it in board.json first"
        )
    return (stored_event if event is None else event), (stored_format if flag_format is None else flag_format)


async def _not_answering(client: CTFdClient) -> CTFdError | None:
    """After a challenge failed in a way that passes: None if CTFd still answers its challenge
    list (asked with the client's retries), so the failure was that challenge's own; else the
    error that says CTFd does not answer."""
    try:
        await client.challenges()
    except CTFdError as exc:
        return exc
    return None


def _is_challenge_folder(entry: Path) -> bool:
    return not entry.is_symlink() and entry.is_dir() and (entry / CHALLENGE_FILE).is_file()


def _empty_board(url: str, listed: int, hidden: int, problems: list[str]) -> str:
    if not listed:
        text = f"CTFd at {url} lists no challenges for this account yet"
    elif hidden == listed:
        text = f"all {listed} challenges CTFd at {url} lists are locked until a prerequisite is solved"
    else:
        text = f"none of the {listed} challenges CTFd at {url} lists could be pulled"
        if hidden:
            text += f" ({hidden} locked until a prerequisite is solved)"
    return text + (": " + "; ".join(problems) if problems else "")


async def pull_board(client: CTFdClient, dest: Path, *, event: str | None = None, flag_format: str | None) -> Board:
    """pull(), for a caller that wants the whole board or an error: the board, or
    PullIncomplete (whose .pull holds what was written and why the rest was left out).
    The CTFd ids of the board's challenges are in dest/ctfd.json: load_ids(dest)."""
    result = await pull(client, dest, event=event, flag_format=flag_format)
    if result.problems:
        raise PullIncomplete(result)
    return result.board


def load_ids(dest: Path) -> dict[str, int]:
    """The board id -> CTFd id mapping a pull wrote into the board folder `dest`."""
    root = Path(dest).expanduser().resolve()
    path = root / STATE_FILE
    if not (path.is_symlink() or path.exists()):
        raise CTFdError(f"{_show(path)}: no such file; it is written by a pull from CTFd")
    return _parse_state(path)[1]


def origins_in(text: str | None) -> tuple[str, ...]:
    """The http(s) origins (scheme://host[:port], lower case) of the URLs in `text`, in
    order, each once. Only origins a board's challenge.json takes are kept (the folder
    board's own rule: a host that ends in a number must be a plain IPv4 address, so 127.1
    or 2130706433 is left out); a URL with no usable host is left out, and so is anything
    else (`nc host port` has no URL in it)."""
    if not text:
        return ()
    found: list[str] = []
    for match in _URL.finditer(text):
        origin = _origin(_trim(match.group(0)))
        if origin is not None:
            origin = _board_origin(origin)
        if origin is not None and origin not in found:
            found.append(origin)
    return tuple(found)


def slugify(name: str) -> str:
    """A board id made from a challenge's name: lower-case ASCII letters and digits joined
    by "-", at most SLUG_MAX characters; "" when nothing is left."""
    text = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode("ascii").lower()
    text = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    return text[:SLUG_MAX].rstrip("-")


class _Unusable(Exception):
    """A challenge whose details make no sense for a board; the message says why."""


@dataclass(frozen=True)
class _Spec:
    name: str
    category: str
    points: int
    solves: int
    description: str  # CTFd's own
    extra: tuple[str, ...]  # paragraphs flightdeck adds after it: the connection info, notes
    urls: tuple[str, ...]
    files: tuple[str, ...]  # the file URLs, as CTFd sent them


async def _pull_one(
    client: CTFdClient,
    root: Path,
    stage_root: Path,
    number: int,
    item: dict,
    slug: str | None,
    taken: set[str],
    ids: dict[str, int],
) -> tuple[str, str]:
    """Pull one challenge into root/<slug>: (slug, a progress line). The folder is built in
    the staging folder and checked with load_board() first, so it appears complete or not
    at all. The mapping is written before the folder moves into place: a crash in between
    leaves a mapped slug with no folder, which the next pull fills in."""
    spec = _spec(number, item, await client.challenge(number), client._site.base)
    if slug is None:
        slug = _new_slug(spec.name, number, taken)
    stage_root.mkdir(exist_ok=True)
    stage = stage_root / slug
    stage.mkdir()
    try:
        names = [(await client.download(url, stage)).name for url in spec.files]
        description, whole = _description(spec, stage)
        if whole is not None:
            names.append(whole)
        _write_json(
            stage / CHALLENGE_FILE,
            {
                "name": spec.name,
                "category": spec.category,
                "points": spec.points,
                "solves": spec.solves,
                "description": description,
                "files": names,
                "urls": list(spec.urls),
                "id": slug,
            },
        )
        try:
            load_board(stage_root)
        except BoardError as exc:
            raise _Unusable(f"flightdeck could not make a valid {CHALLENGE_FILE} of it: {exc}") from None
        _write_state(root, client.base_url, {**ids, slug: number})
        ids[slug] = number
        try:
            os.rename(stage, root / slug)
        except OSError:
            del ids[slug]
            _write_state(root, client.base_url, ids)
            raise
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise
    taken.add(slug)
    count = len(names)
    cut = "" if whole is None else f"; its description is cut short, the whole of it is in {whole}"
    line = (
        f"added {slug}: {_quote(spec.name)} ({untrusted(spec.category, one_line=True) or 'no category'}, "
        f"{spec.points} points, {count} file{'' if count == 1 else 's'}{cut})"
    )
    return slug, line


def _numbered(listing: list[dict], problems: list[str]) -> Iterator[tuple[int, dict]]:
    """The listing's entries by CTFd id (ascending, each id once); a bad entry is a problem."""
    seen: dict[int, dict] = {}
    for item in listing:
        number = item.get("id")
        if not _is_number(number):
            problems.append(f"an entry in the challenge list has no valid id ({_quote(str(item.get('name', '')))})")
            continue
        seen.setdefault(number, item)
    for number in sorted(seen):
        yield number, seen[number]


def _spec(number: int, item: dict, detail: dict, ctfd: httpx.URL) -> _Spec:
    """challenge.json's fields from CTFd's details (the listing fills in what they lack)."""
    if detail.get("id") != number:
        raise _Unusable("CTFd answered with the details of another challenge")

    def field(key: str) -> object:
        return detail[key] if key in detail else item.get(key)

    name = field("name")
    if not isinstance(name, str) or not name.strip():
        raise _Unusable("it has no name")
    category = field("category")
    if category is None:
        category = ""
    if not isinstance(category, str):
        raise _Unusable("its category is not text")
    points = field("value")
    if not _is_count(points):
        raise _Unusable("its value (points) is not a whole number, 0 or more")
    solves = field("solves")
    if solves is None:  # CTFd hides solve counts when scores or accounts are hidden
        solves = 0
    if not _is_count(solves):
        raise _Unusable("its solve count is not a whole number, 0 or more")
    description = detail.get("description")
    if description is None:
        description = ""
    if not isinstance(description, str):
        raise _Unusable("its description is not text")
    connection = detail.get("connection_info")
    if connection is None:
        connection = ""
    if not isinstance(connection, str):
        raise _Unusable("its connection info is not text")
    files = detail.get("files")
    if files is None:
        files = []
    if not isinstance(files, list) or not all(isinstance(url, str) for url in files):
        raise _Unusable("its files are not a list of URLs")
    extra: list[str] = []  # what the folder board has no field for, after CTFd's description
    connection = connection.strip()
    if connection and connection not in description:
        extra.append(f"Connection info: {connection}")  # `nc host port` must still reach the lane
    urls = origins_in(connection)
    platform = [origin for origin in urls if _on_ctfd(origin, ctfd)]
    if platform:
        # an instancer page on CTFd, a link to the scoreboard: a lane's instance is the one place its
        # tools may send requests to, and CTF infrastructure is never a target
        urls = tuple(origin for origin in urls if origin not in platform)
        extra.append(
            f"Note from flightdeck: the connection info points at CTFd itself ({', '.join(platform)}), which lanes "
            "never get as an instance."
        )
    tries = detail.get("max_attempts")  # 0 (or absent) when CTFd allows any number
    if _is_number(tries):
        # the player and the lane should know that every wrong flag costs one
        extra.append(
            f"Note from flightdeck: CTFd allows {tries} attempt{'' if tries == 1 else 's'} at this challenge's flag, "
            "then checks no more."
        )
    return _Spec(name, category, points, solves, description, tuple(extra), urls, tuple(files))


def _description(spec: _Spec, stage: Path) -> tuple[str, str | None]:
    """challenge.json's description: CTFd's, then the paragraphs flightdeck adds. One too long
    for challenge.json (an image pasted into it) is written whole to a file in `stage`, and
    cut short where the board shows it. Returns it and that file's name, if one was written."""
    text = _paragraphs(spec.description, spec.extra)
    if len(json.dumps(text, ensure_ascii=True)) <= DESCRIPTION_MAX_BYTES:
        return text, None
    path, fd = _create(stage, DESCRIPTION_FILE)
    with os.fdopen(fd, "wb") as out:
        out.write(text.encode("utf-8", "replace"))
    note = (
        "Note from flightdeck: this description is too long for the board, so it is cut short; the whole of it is in "
        f"the file {path.name}."
    )
    # CTFd's own text gets half the room; flightdeck's paragraphs (the connection info) stay in view
    kept = [part if len(part) <= MAX_PARAGRAPH else part[: MAX_PARAGRAPH - 3] + "..." for part in spec.extra]
    return _paragraphs(_cut(spec.description, DESCRIPTION_MAX_BYTES // 2), (note, *kept)), path.name


def _paragraphs(text: str, paragraphs: tuple[str, ...]) -> str:
    """`paragraphs` after `text`, with a blank line before each."""
    for paragraph in paragraphs:
        text = (text.rstrip() + "\n\n" if text.strip() else "") + paragraph
    return text


def _cut(text: str, budget: int) -> str:
    """The longest start of `text` that takes at most `budget` bytes as JSON (ASCII, as
    challenge.json is written: a character takes 1 to 12 bytes there)."""
    low, high = 0, min(len(text), budget)
    while low < high:
        middle = (low + high + 1) // 2
        if len(json.dumps(text[:middle], ensure_ascii=True)) <= budget:
            low = middle
        else:
            high = middle - 1
    return text[:low]


_DEFAULT_PORTS = {"http": 80, "https": 443}


def _on_ctfd(origin: str, ctfd: httpx.URL) -> bool:
    """`origin` (scheme://host[:port]) is the CTFd's own: its host on its port, whatever the
    scheme, or on either default port when CTFd is on one (http:// to an https CTFd is the
    same site). Another port on that host is another service."""
    url = httpx.URL(origin)
    if url.raw_host.lower().rstrip(b".") != ctfd.raw_host.lower().rstrip(b"."):
        return False
    port = url.port or _DEFAULT_PORTS.get(url.scheme)
    own = ctfd.port or _DEFAULT_PORTS.get(ctfd.scheme)
    return port == own or (port in (80, 443) and own in (80, 443))


def _new_slug(name: str, number: int, taken: set[str]) -> str:
    base = slugify(name) or f"challenge-{number}"
    candidates = [base, f"{base}-{number}"] + [f"{base}-{number}-{n}" for n in range(2, 100)]
    for candidate in candidates:
        if candidate.lower() not in taken:
            return candidate
    raise _Unusable(f"every folder name tried for it ({base}, ...) is taken")


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
        raise CTFdError(f"{_show(root / _LOCK)}: cannot open the pull's lock file ({problem})")
    try:
        busy = False
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            busy = True
        if busy:
            raise CTFdError(f"{_show(root)}: another pull into this folder is running; wait for it to finish")
        yield
    finally:
        os.close(fd)


def _clear_staging(root: Path) -> None:
    """Remove staging folders a pull that died left behind (only ours, by name; we hold the lock)."""
    for entry in root.iterdir():
        if entry.name.startswith(_STAGING) and entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry, ignore_errors=True)


def _read_state(root: Path, url: str) -> dict[str, int]:
    """The mapping already in `root`, or {} for an empty folder; CTFdError for a folder that
    holds something else, or a board pulled from another CTFd."""
    path = root / STATE_FILE
    if not (path.is_symlink() or path.exists()):
        others = [
            entry.name for entry in root.iterdir() if entry.name not in _IGNORED and not entry.name.startswith(_STAGING)
        ]
        if others:
            raise CTFdError(
                f"{_show(root)}: is not empty and holds no {STATE_FILE}, so it is not a board flightdeck pulled from "
                "CTFd; pull into a new or empty folder"
            )
        return {}
    stored, ids = _parse_state(path)
    if stored != url:
        if not ids:  # claimed by a pull that got no challenge through (a mistyped URL): free to claim again
            return {}
        raise CTFdError(
            f"{_show(path)}: this board was pulled from {_show(stored)}, not {_show(url)}; pull into another folder"
        )
    return ids


def _parse_state(path: Path) -> tuple[str, dict[str, int]]:
    where = _show(path)
    data = _NOT_JSON
    try:
        info = path.lstat()
        if stat.S_ISREG(info.st_mode) and info.st_size <= MAX_STATE_BYTES:
            data = _parse(path.read_bytes())
        else:
            data = None
    except OSError as exc:
        problem = exc.strerror
    else:
        problem = None
    if problem is not None:
        raise CTFdError(f"{where}: cannot read it ({problem})")
    if data is None:
        raise CTFdError(f"{where}: must be a regular file of at most {MAX_STATE_BYTES:,} bytes, not a symlink")
    if not isinstance(data, dict) or set(data) != {"url", "ids"}:
        raise CTFdError(f'{where}: must be a JSON object with exactly the keys "url" and "ids"')
    url, ids = data["url"], data["ids"]
    if not isinstance(url, str) or not isinstance(ids, dict):
        raise CTFdError(f'{where}: "url" must be a string and "ids" an object of board id to CTFd id')
    numbers: set[int] = set()
    for slug, number in ids.items():
        if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,63}", slug) or not _is_number(number):
            raise CTFdError(f'{where}: "ids" must map board ids to CTFd ids (whole numbers, 1 or more)')
        if number in numbers:
            raise CTFdError(f'{where}: "ids" gives CTFd id {number} to two board ids')
        numbers.add(number)
    return url, dict(ids)


def _write_state(root: Path, url: str, ids: Mapping[str, int]) -> None:
    _write_json(root / STATE_FILE, {"url": url, "ids": dict(sorted(ids.items()))})


def _write_json(path: Path, data: object) -> None:
    """Write JSON atomically (a temporary file in the same folder, then os.replace)."""
    text = json.dumps(data, indent=2, ensure_ascii=True) + "\n"
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="ascii") as out:
            out.write(text)
        os.chmod(temp, 0o644)
        os.replace(temp, path)
    except BaseException:
        Path(temp).unlink(missing_ok=True)
        raise


def _create(folder: Path, name: str) -> tuple[Path, int]:
    """A new file in `folder` named `name`, or name-2.ext, name-3.ext, ... if taken; never
    challenge.json in any case or form (on a case-insensitive file system, as macOS's and
    WSL's drives are, Challenge.json is the file challenge.json is written over), never
    through a symlink. Returns its path and an open descriptor."""
    dot = name.find(".", 1)
    stem, ext = (name, "") if dot == -1 else (name[:dot], name[dot:])
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    for n in range(1, 100):
        candidate = name if n == 1 else f"{stem}-{n}{ext}"
        if unicodedata.normalize("NFKC", candidate).casefold() == CHALLENGE_FILE:
            continue
        path = folder / candidate
        try:
            return path, os.open(path, flags, 0o644)
        except FileExistsError:
            continue
    raise CTFdError(f"{_show(folder)}: already holds 99 files named like {_quote(name)}")


# ---------------------------------------------------------------------- checks and messages


class _Site:
    """A CTFd's address and token: the request headers, and messages that never show the token."""

    def __init__(self, base_url: str, token: str) -> None:
        self.base = _base_url(base_url)  # its path ends in "/", so a relative URL resolves under it
        self.root = str(self.base).rstrip("/")
        if not isinstance(token, str) or not _TOKEN_CHARS.fullmatch(token):
            raise ValueError(
                "the CTFd token is empty or holds characters an HTTP header cannot carry (spaces, line breaks, "
                "non-ASCII); check the variable it came from"
            )
        self._token = token

    def headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Token {self._token}",
            "Content-Type": "application/json",  # CTFd reads the token only from a JSON request, GETs too
            "User-Agent": f"ctf-flightdeck/{__version__}",
        }

    def short(self, text: str) -> str:
        """The server's words, safe to show: no token or file token, one line, cut short."""
        text = _FILE_TOKEN.sub(r"\1[file token]", text.replace(self._token, "[token]"))
        text = untrusted(text[: MAX_SHOWN * 4], one_line=True).strip()
        return text if len(text) <= MAX_SHOWN else text[: MAX_SHOWN - 3] + "..."

    def error(
        self, message: str, *, endpoint: str | None = None, status: int | None = None, retryable: bool = False
    ) -> CTFdError:
        text = _FILE_TOKEN.sub(r"\1[file token]", message.replace(self._token, "[token]"))
        return CTFdError(untrusted(text, one_line=True), endpoint=endpoint, status=status, retryable=retryable)

    def refused(self, answer: _Answer) -> CTFdError:
        """The CTFdError for an answer that is not a success."""
        status, endpoint = answer.status, answer.endpoint
        doc = _parse(answer.body)
        said = self.short(_message(doc)) if isinstance(doc, dict) else ""
        says = f" (CTFd says: {said})" if said else ""
        where = f"CTFd at {self.root}"
        if answer.host is not None:  # a file host CTFd sent a download to: the token never went there
            says = f" (it says: {said})" if said else ""
            text = (
                f"the file host {answer.host}, where CTFd at {self.root} sent {endpoint}, answered HTTP {status}"
                f"{_phrase(status)}{says}"
            )
        elif 300 <= status < 400:
            location = answer.headers.get("location")
            target = None
            if location:
                try:
                    target = self.base.join(location)
                except httpx.InvalidURL:
                    target = None
            to = f" to {_origin_text(target)}" if target is not None else ""
            text = (
                f"{where} answered {endpoint} with a redirect (HTTP {status}{_phrase(status)}){to}; flightdeck never "
                "follows a redirect with the token. Check the event URL (https, and the exact address)"
            )
        elif status == 401:
            text = (
                f"{where} refused the API token (HTTP 401) at {endpoint}{says}. Make a new token in CTFd (Settings, "
                "Access Tokens) and put it in the token's environment variable"
            )
        elif status == 403:
            text = (
                f"{where} answered HTTP 403 (Forbidden) at {endpoint}: the token was refused, or this account may not do "
                f"this now (not on a team yet, the CTF not running, or banned){says}"
            )
        else:
            text = f"{where} answered HTTP {status}{_phrase(status)} at {endpoint}{says}"
        if answer.tries > 1:
            text += f"; gave up after {answer.tries} tries"
        return self.error(text, endpoint=endpoint, status=status, retryable=_retryable(status))

    def no_answer(
        self, endpoint: str, failure: _Failure, tries: int, *, submit: bool = False, host: str | None = None
    ) -> CTFdError:
        if host is None:
            text = f"no answer from CTFd at {self.root} to {endpoint}: {self.short(failure.what)}"
        else:
            text = (
                f"no answer from the file host {host}, where CTFd at {self.root} sent {endpoint}: "
                f"{self.short(failure.what)}"
            )
        if tries > 1:
            text += f"; gave up after {tries} tries"
        if submit:
            text += (
                "; the flag may have reached CTFd: check the challenge there before submitting it again"
                if failure.sent
                else "; the flag was not submitted"
            )
        return self.error(text, endpoint=endpoint, retryable=failure.transient)


def _base_url(url: object) -> httpx.URL:
    if not isinstance(url, str) or not url.lower().startswith(("http://", "https://")):
        raise ValueError("the CTFd URL must start with http:// or https://")
    bad = False
    try:
        parsed = httpx.URL(url)
    except httpx.InvalidURL:
        bad = True
    if bad:
        raise ValueError("the CTFd URL is not a valid URL")
    if not parsed.host:
        raise ValueError("the CTFd URL has no host")
    if parsed.userinfo:
        raise ValueError(
            "the CTFd URL holds a user name or password; give the token through its environment variable, never in the URL"
        )
    if parsed.query or parsed.fragment:
        raise ValueError("the CTFd URL must not have a query or a fragment: give the address CTFd runs at")
    return parsed.copy_with(path=parsed.path.rstrip("/") + "/")


def _check_number(value: object, what: str) -> None:
    if not _is_number(value):
        raise ValueError(f"{what} must be a CTFd id: a whole number, 1 or more")


def _is_number(value: object) -> bool:
    """A CTFd id or page number: an int (not a bool), 1 to MAX_ID."""
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= MAX_ID


def _is_count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= MAX_ID


def _retryable(status: int) -> bool:
    return status == 429 or 500 <= status <= 599


def _retry_after(value: str | None) -> float | None:
    """Retry-After in seconds, from a number or an HTTP date; None when absent or unreadable."""
    if value is None:
        return None
    match = _SECONDS.fullmatch(value)
    if match:
        return float(match.group(1))
    when = None
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return (when - datetime.now(timezone.utc)).total_seconds()


def _describe(exc: httpx.HTTPError) -> _Failure:
    """An httpx error as plain data. The error itself is dropped, never chained: its request
    holds the Authorization header."""
    what = type(exc).__name__ + (f": {exc}" if str(exc) else "")
    return _Failure(what, isinstance(exc, _TRANSIENT), not isinstance(exc, _UNSENT))


async def _read(response: httpx.Response, limit: int) -> bytes | None:
    """The body, or None when it is longer than `limit` bytes."""
    chunks, size = [], 0
    async for chunk in response.aiter_bytes():
        size += len(chunk)
        if size > limit:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def _read_sync(response: httpx.Response, limit: int, deadline: float) -> bytes | None | object:
    """The body; None when it is longer than `limit` bytes; _LATE when it is not all in by
    `deadline` (a time.monotonic() value): then the reading stops, and the connection with it."""
    chunks, size = [], 0
    for chunk in response.iter_bytes():
        size += len(chunk)
        if size > limit:
            return None
        chunks.append(chunk)
        if time.monotonic() > deadline:
            return _LATE
    return b"".join(chunks)


def _parse(body: bytes) -> object:
    try:
        return json.loads(body)
    except (ValueError, RecursionError):  # also UnicodeDecodeError
        return _NOT_JSON


def _message(doc: object) -> str:
    """The server's own words in an error answer: CTFd's "message", its "errors", or data.message."""
    if not isinstance(doc, dict):
        return ""
    parts: list[str] = []
    message = doc.get("message")
    if isinstance(message, str):
        parts.append(message)
    errors = doc.get("errors")
    if isinstance(errors, str):
        parts.append(errors)
    elif isinstance(errors, list):
        parts.extend(item for item in errors if isinstance(item, str))
    elif isinstance(errors, dict):
        for key, value in errors.items():
            texts = value if isinstance(value, list) else [value]
            parts.extend(f"{key}: {text}" if key else text for text in texts if isinstance(text, str))
    data = doc.get("data")
    if not parts and isinstance(data, dict) and isinstance(data.get("message"), str):
        parts.append(data["message"])
    return "; ".join(parts)


def _same_origin(a: httpx.URL, b: httpx.URL) -> bool:
    return (a.scheme, a.host, a.port) == (b.scheme, b.host, b.port)


def _origin_text(url: httpx.URL) -> str:
    """scheme://host[:port] of a URL, safe to show (never its path or query)."""
    host = url.host or "(no host)"
    if ":" in host:
        host = f"[{host}]"
    shown = f"{url.scheme}://{host}" + (f":{url.port}" if url.port is not None else "")
    return untrusted(shown, one_line=True)


def _path_of(url: httpx.URL) -> str:
    """A URL's path, decoded and safe to show, never its query (a file URL's holds a credential)."""
    return untrusted(url.path, one_line=True)


def _last_segment(url: httpx.URL) -> str:
    return url.path.rsplit("/", 1)[-1] or url.path


def _file_name(url: httpx.URL, site: _Site) -> str:
    """The file name a download gets: the URL's last path segment, percent-decoded, if it is
    a plain name. CTFdError otherwise (a path, "..", control characters, too long)."""
    raw = url.raw_path.split(b"?", 1)[0].rsplit(b"/", 1)[-1]
    name = None
    try:
        name = unquote(raw.decode("ascii"), errors="strict")
    except UnicodeError:
        name = None
    problem = None
    if name is None:
        problem = "is not UTF-8"
    elif not name or name in (".", ".."):
        problem = "is not a file name"
    elif "/" in name or "\\" in name or "\x00" in name:
        problem = "is a path, not a plain file name"
    elif untrusted(name, one_line=True) != name or name.strip() != name:
        problem = "holds control, invisible or surrounding space characters"
    elif len(name.encode("utf-8", "surrogatepass")) > 255:
        problem = "is longer than a file name may be"
    if problem is not None:
        shown = _quote(name if name is not None else raw.decode("ascii", "replace"))
        raise site.error(f"the file name {shown} in a file URL {problem}; flightdeck refuses to write it")
    assert name is not None
    return name


def _trim(url: str) -> str:
    """A URL found in prose without the punctuation that ends a sentence or closes a bracket around it."""
    pairs = {")": "(", "]": "[", "}": "{", ">": "<"}
    while url:
        last = url[-1]
        if last in ".,;:!?'\"":
            url = url[:-1]
        elif last in pairs and url.count(last) > url.count(pairs[last]):
            url = url[:-1]
        else:
            break
    return url


def _origin(url: str) -> str | None:
    """scheme://host[:port] of an http(s) URL, lower case (IPv6 in brackets); None if it has no usable host."""
    try:
        parts = httpx.URL(url)
        port = parts.port
    except (httpx.InvalidURL, ValueError):
        return None
    scheme = parts.scheme.lower()
    host = parts.host.lower()
    if scheme not in ("http", "https") or not host or (port is not None and not 1 <= port <= 65535):
        return None  # httpx takes any port number; the board takes only real ones
    if ":" in host:
        host = f"[{host}]"
    elif not _HOST.fullmatch(host):
        return None
    return f"{scheme}://{host}" + ("" if port is None else f":{port}")


def _label(number: int, name: object) -> str:
    return f"challenge {number}" + (f" ({_quote(name)})" if isinstance(name, str) and name.strip() else "")


def _show(value: object) -> str:
    return untrusted(str(value), one_line=True)


def _quote(text: str) -> str:
    """Untrusted text quoted for a message: made safe, and cut short."""
    safe = untrusted(text, one_line=True)
    return json.dumps(safe if len(safe) <= 60 else safe[:57] + "...", ensure_ascii=False)


def _phrase(code: int) -> str:
    try:
        return f" ({HTTPStatus(code).phrase})"
    except ValueError:
        return ""
