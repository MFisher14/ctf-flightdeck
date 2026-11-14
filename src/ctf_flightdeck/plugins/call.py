"""One call to a plugin: its program is run once, out of process, and answers on stdout.

Plugin API 1. The program runs with the plugin's folder as its working directory, gets one
JSON object on stdin, and must write exactly one JSON object to stdout and exit 0. A failure
is a non-zero exit with the reason on stderr.

    pull    {"api": 1, "op": "pull", "event": NAME, "url": URL, "files": DIR, "known": [REF, ...]}
            -> {"challenges": [{"ref": "17", "name": "Warm Up", ...}], "notes": ["..."]}
    submit  {"api": 1, "op": "submit", "event": NAME, "url": URL, "ref": REF, "flag": FLAG}
            -> {"verdict": WORD, "detail": "...", "tries_left": 2, "retry_after": 30}
    solved  {"api": 1, "op": "solved", "event": NAME, "url": URL}
            -> {"solved": [REF, ...]}

The child's environment is child_env(): the few variables a program needs to run and reach
the network (ENV_KEEP), FLIGHTDECK_PLUGIN_API and the event's token in FLIGHTDECK_PLUGIN_TOKEN.
It is built from those names alone, so no model API key and nothing else of the player's
environment is in it. The token is never on the command line and never in the request.

A call that does not end in a well-formed answer is a CallFailed with the reason: no answer
within the time allowed (the whole process group is then killed), an answer that is too
large, a non-zero exit, or stdout that is not one JSON object of the keys this API knows.
What an answer means is the caller's business: a CallFailed is never a verdict.

Everything a plugin says is untrusted. scrub() cuts the token's value out of a string and
makes it safe to show; every string of an answer has the token cut out before anything else
sees it, and every reason in a CallFailed is scrubbed.

PlatformCaller is what the board writer (plugins/board.py) and a run's link
(platform/plugin_run.py) ask of whatever makes the three calls: Caller here, which runs a
plugin's program, and platform.http.HttpCaller, which makes them itself from an event
profile's table of routes.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import signal
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ..text import untrusted
from .manifest import Plugin

API_ENV = "FLIGHTDECK_PLUGIN_API"
TOKEN_ENV = "FLIGHTDECK_PLUGIN_TOKEN"
_PROXIES = ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY")
ENV_KEEP = ("PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "SSL_CERT_FILE", "SSL_CERT_DIR",
            *_PROXIES, *(name.lower() for name in _PROXIES))
"""The variables of flightdeck's own environment a plugin's program is given: what it needs to
run, to find a temporary folder and to reach the network the way the player's machine does."""

OPS = ("pull", "submit", "solved")
SECONDS = {"pull": 300.0, "submit": 30.0, "solved": 30.0}  # how long each call may take
MAX_STDOUT = {"pull": 8_000_000, "submit": 1_000_000, "solved": 1_000_000}  # bytes of an answer
MAX_STDERR = 16_384  # bytes of stderr kept: its end
MAX_SHOWN = 300  # characters of a plugin's string in a message
MAX_REF = 128
MAX_NOTES = 20
MAX_CHALLENGES = 1000  # challenges one pull may list: more is no answer (an 8 MB answer has room for 200,000 folders to make)
VERDICTS = ("correct", "incorrect", "already_solved", "rate_limited", "unjudged")
PULL_KEYS = ("challenges", "notes")
SUBMIT_KEYS = ("verdict", "detail", "tries_left", "retry_after")
SOLVED_KEYS = ("solved",)
TOKEN_MARK = "<token>"
REF_RULE = f"a string of 1 to {MAX_REF} printable characters: the platform's own id for the challenge"


class CallFailed(Exception):
    """A call gave no answer flightdeck can use. The message is the reason, made safe to show
    and with the token cut out. `timed_out`: the program was still running when its time was
    up, so what it was asked to do may have reached the platform."""

    def __init__(self, reason: str, *, timed_out: bool = False) -> None:
        super().__init__(reason)
        self.timed_out = timed_out


class _TooLarge(Exception):
    pass


@dataclass(frozen=True)
class Verdict:
    word: str  # one of VERDICTS
    detail: str = ""  # the platform's own words, made safe; "" when the plugin gives none
    tries_left: int | None = None  # tries the platform still allows at this flag's challenge, when it says
    retry_after: float | None = None  # seconds the platform asks to wait, with rate_limited


@dataclass(frozen=True)
class PullReply:
    challenges: tuple[dict, ...]  # as the plugin listed them, the token cut out: untrusted, checked by plugins.board
    notes: tuple[str, ...]  # what the plugin wants the player to know, made safe
    problems: tuple[str, ...] = ()  # "<name or ref>: <why it was left out>", made safe: challenges the caller itself left out


class PlatformCaller(Protocol):
    """What makes the three calls for one event: a plugin's program (Caller), or flightdeck
    itself from a table of routes (platform.http.HttpCaller). Every string it gives back is
    made safe and has the token cut out; a call it cannot answer is a CallFailed."""

    url: str  # the event's address
    token: str  # the event's token; "" when it takes none
    label: str  # how messages name it: "the acme plugin", "the http adapter"
    pull_command: str  # the command that pulls its board outside a run: "flightdeck plugin pull"
    source: str  # the "source" of its warnings in the event log: "plugin", "http"

    async def pull(self, files_dir: Path, known: Sequence[str] = ()) -> PullReply:
        """The platform's challenges, their files downloaded into `files_dir`; the refs in `known` are on the board already."""

    async def submit(self, ref: str, flag: str) -> Verdict:
        """Send one flag for the challenge the platform calls `ref`; what the platform said."""

    async def solved(self) -> set[str]:
        """The refs of the challenges the platform lists as solved for this account."""


PLUGIN_PULL = "flightdeck plugin pull"


def plugin_label(name: str) -> str:
    """How messages name the plugin `name`."""
    return f"the {name} plugin"


def child_env(token: str | None, environ: Mapping[str, str] = os.environ, *, api: int = 1) -> dict[str, str]:
    """The whole environment of a plugin's program: ENV_KEEP's variables as `environ` has
    them, the plugin API, and the event's token when there is one. Nothing else: `environ`
    must be the process's own environment, never one with the keys file merged in."""
    env = {name: environ[name] for name in ENV_KEEP if name in environ}
    env[API_ENV] = str(api)
    if token:
        env[TOKEN_ENV] = token
    return env


def scrub(text: object, token: str | None, *, limit: int = MAX_SHOWN) -> str:
    """A plugin's string for a message: the token's value replaced, made safe, one line, cut short."""
    shown = str(text)
    if token:
        shown = shown.replace(token, TOKEN_MARK)
    shown = untrusted(shown, one_line=True)
    return shown if len(shown) <= limit else shown[:limit - 3] + "..."


def valid_ref(value: object) -> bool:
    """Whether `value` is a challenge's ref as this API takes one (REF_RULE)."""
    return isinstance(value, str) and 0 < len(value) <= MAX_REF and value.isprintable()


class Caller:
    """Runs one plugin for one event: pull(), submit() and solved(), one process per call and
    one call at a time. `token` is the event's token ("" or None: the plugin takes none)."""

    pull_command = PLUGIN_PULL
    source = "plugin"

    def __init__(self, plugin: Plugin, url: str, event: str, token: str | None, *,
                 seconds: Mapping[str, float] | None = None, environ: Mapping[str, str] | None = None) -> None:
        self.plugin = plugin
        self.label = plugin_label(plugin.name)
        self.url = url
        self.event = event
        self.token = token or ""
        self.seconds = {**SECONDS, **(seconds or {})}
        self._environ = environ
        self._lock = asyncio.Lock()

    async def pull(self, files_dir: Path, known: Sequence[str] = ()) -> PullReply:
        """The platform's challenges. The plugin downloads their files into `files_dir`; the
        refs in `known` are on the board already. The challenges come back as the plugin
        listed them: plugins.board checks each one."""
        reply = await self._call("pull", {"files": str(files_dir), "known": list(known)}, PULL_KEYS)
        challenges = reply.get("challenges")
        if not isinstance(challenges, list) or not all(isinstance(item, dict) for item in challenges):
            raise CallFailed('its answer must have "challenges": a list of objects, one for each challenge')
        if len(challenges) > MAX_CHALLENGES:
            raise CallFailed(f"its answer lists {len(challenges):,} challenges, more than the {MAX_CHALLENGES:,} flightdeck takes "
                             "from one pull: nothing was added (a plugin for a larger platform lists the event's own challenges)")
        notes = reply.get("notes", [])
        if not isinstance(notes, list) or not all(isinstance(note, str) for note in notes):
            raise CallFailed('"notes" must be a list of strings')
        return PullReply(tuple(challenges), tuple(scrub(note, self.token) for note in notes[:MAX_NOTES] if note.strip()))

    async def submit(self, ref: str, flag: str) -> Verdict:
        """Send one flag for the challenge the plugin calls `ref`; what the platform said."""
        reply = await self._call("submit", {"ref": ref, "flag": flag}, SUBMIT_KEYS)
        word = reply.get("verdict")
        if not isinstance(word, str) or word not in VERDICTS:
            raise CallFailed(f"verdict must be one of {', '.join(VERDICTS)}")
        detail = reply.get("detail", "")
        if not isinstance(detail, str):
            raise CallFailed("detail must be a string")
        tries_left = reply.get("tries_left")
        if tries_left is not None and (isinstance(tries_left, bool) or not isinstance(tries_left, int) or tries_left < 0):
            raise CallFailed("tries_left must be a whole number, 0 or more")
        retry_after = reply.get("retry_after")
        if retry_after is not None and (isinstance(retry_after, bool) or not isinstance(retry_after, (int, float)) or retry_after < 0):
            raise CallFailed("retry_after must be a number of seconds, 0 or more")
        return Verdict(word, scrub(detail, self.token), tries_left, None if retry_after is None else float(retry_after))

    async def solved(self) -> set[str]:
        """The refs of the challenges the platform lists as solved for this account."""
        reply = await self._call("solved", {}, SOLVED_KEYS)
        refs = reply.get("solved")
        if not isinstance(refs, list) or not all(valid_ref(ref) for ref in refs):
            raise CallFailed(f'its answer must have "solved": a list of refs, each {REF_RULE}')
        return set(refs)

    async def _call(self, op: str, fields: dict, known: tuple[str, ...]) -> dict:
        request = {"api": self.plugin.api, "op": op, "event": self.event, "url": self.url, **fields}
        async with self._lock:
            out = await self._run(op, json.dumps(request).encode("ascii"))
        try:
            reply = _cut(json.loads(out.decode("utf-8"), parse_constant=_no_constant), self.token)
        except (UnicodeDecodeError, ValueError, RecursionError):
            reply = None
        if not isinstance(reply, dict):
            raise CallFailed("its answer is not one JSON object")
        unknown = [key for key in reply if key not in known]
        if unknown:
            raise CallFailed(f"its answer has an unknown key {', '.join(scrub(key, self.token, limit=64) for key in unknown[:5])} "
                             f"(known: {', '.join(known)})")
        return reply

    async def _run(self, op: str, payload: bytes) -> bytes:
        """Run the program for one call and give back its stdout. CallFailed when it could not
        be started, ran out of time, wrote too much or did not exit 0."""
        timeout, limit = self.seconds[op], MAX_STDOUT[op]
        environ = os.environ if self._environ is None else self._environ
        try:
            proc = await asyncio.create_subprocess_exec(
                *self.plugin.argv,
                cwd=self.plugin.root,
                env=child_env(self.token, environ, api=self.plugin.api),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,  # a group of its own, so the whole of it can be killed
            )
        except OSError as exc:
            raise CallFailed(f"it could not be started ({scrub(exc.strerror or exc, self.token)})") from None
        try:
            try:
                out, err = await asyncio.wait_for(_talk(proc, payload, limit), timeout)
            except TimeoutError:
                await _kill(proc)
                raise CallFailed(f"it gave no answer within {timeout:g} s", timed_out=True) from None
            except _TooLarge:
                await _kill(proc)
                raise CallFailed(f"its answer is larger than {limit // 1_000_000} MB") from None
        finally:
            if proc.returncode is None:  # cancelled, or an error of flightdeck's own: nothing of a call outlives it
                await _kill(proc)
        if proc.returncode != 0:
            lines = [line for line in err.decode("utf-8", "replace").splitlines() if line.strip()]
            how = f"it exited with status {proc.returncode}" if proc.returncode > 0 else f"it was stopped by signal {-proc.returncode}"
            raise CallFailed(how + (f": {scrub(lines[-1].strip(), self.token)}" if lines else " and wrote nothing to stderr"))
        return out


async def _talk(proc: asyncio.subprocess.Process, payload: bytes, limit: int) -> tuple[bytes, bytes]:
    """Give the program its request, and read its stdout (at most `limit` bytes: _TooLarge
    past that) and the end of its stderr, until both close and it has exited."""

    async def feed() -> None:
        try:
            proc.stdin.write(payload)
            await proc.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass  # it exited without reading its request: its exit status and stdout say the rest
        finally:
            proc.stdin.close()

    async def answer() -> bytes:
        chunks, size = [], 0
        while chunk := await proc.stdout.read(65536):
            size += len(chunk)
            if size > limit:
                raise _TooLarge
            chunks.append(chunk)
        return b"".join(chunks)

    async def errors() -> bytes:
        tail = b""
        while chunk := await proc.stderr.read(65536):
            tail = (tail + chunk)[-MAX_STDERR:]
        return tail

    tasks = [asyncio.ensure_future(part) for part in (answer(), errors(), feed())]
    try:
        out, err, _ = await asyncio.gather(*tasks)
        await proc.wait()
    finally:
        for task in tasks:
            task.cancel()
    return out, err


async def _kill(proc: asyncio.subprocess.Process) -> None:
    """Kill the program's whole process group and wait until the program itself is gone."""
    with contextlib.suppress(ProcessLookupError, PermissionError):  # already gone
        os.killpg(proc.pid, signal.SIGKILL)  # start_new_session: the group's id is its pid
    with contextlib.suppress(ProcessLookupError):
        await asyncio.shield(proc.wait())


def _cut(value: object, token: str) -> object:
    """`value` (parsed JSON) with the token's value cut out of every string, keys included."""
    if not token:
        return value
    if isinstance(value, str):
        return value.replace(token, TOKEN_MARK)
    if isinstance(value, list):
        return [_cut(item, token) for item in value]
    if isinstance(value, dict):
        return {_cut(key, token): _cut(item, token) for key, item in value.items()}
    return value


def _no_constant(name: str) -> float:
    raise ValueError(f"{name} is not JSON")
