"""The tools a lane's model can call, and the toolbox that runs them in the lane's workspace.

Everything the model sends is untrusted (AGENTS.md rule 5), steered as it is by challenge
text: arguments are checked, paths are fenced to the workspace, http goes only to the
challenge's own instance, and each mistake comes back as an error result the model can
correct, never an exception. Output is cut to what a context can afford, and the full text
goes to a file the model can read on purpose (context size drives cost: ARCHITECTURE.md).

One deliberate difference from the M1 contract: a plan over 500 characters is cut, and
set_plan then answers "Plan noted (cut to 500 characters)." rather than "Plan noted.", so
the model knows the player sees only the start of it.
"""

from __future__ import annotations

import asyncio
import errno
import json
import math
import os
import re
import shlex
import stat
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from ..text import untrusted
from .workspace import OUTPUT_CAP, PRIVATE, SNIFF, RunResult, Workspace, open_inside, write_inside

MIN_CHARS = 200  # the smallest max_chars that still leaves room for a cut marker or a footer
FOOTER_CHARS = 160  # room read_file keeps for its "[lines a-b of n; ...]" footer
CONSOLE_CHARS = 300  # ToolResult.output
ACTION_CHARS = 400  # ToolResult.action
PLAN_CHARS = 500
READ_LINES = 400
COMMAND_BYTES = 100_000  # the longest shell command: it is one argument (bash -c), and Linux takes at most 128 KiB in one
HTTP_TIMEOUT = 30.0
HTTP_HEADERS = 30  # response headers shown at most
SYMLINK_HOPS = 40
PATH_CHARS = 4096  # the longest path read_file looks up, in characters (Linux's PATH_MAX)
SUBMITTED = "Sent to the player for approval. Carry on until you hear it was correct."


def _tool(name: str, description: str, properties: dict[str, dict], required: list[str]) -> dict:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
                "additionalProperties": False,
            },
        },
    }


_TIMEOUT = {"type": "integer", "description": "Seconds before it is killed (default 60, max 300)."}

TOOLS: list[dict] = [
    _tool(
        "shell",
        "Run a bash command in the workspace (your working directory). Each call is a fresh shell. "
        "Long output is cut; the full output is saved to a file named in the result.",
        {"command": {"type": "string"}, "timeout_seconds": _TIMEOUT},
        ["command"],
    ),
    _tool(
        "read_file",
        "Read a text file in the workspace, 400 lines at a time by default.",
        {
            "path": {"type": "string", "description": "Relative to the workspace."},
            "start_line": {"type": "integer", "description": "First line to show, from 1."},
            "max_lines": {"type": "integer"},
        },
        ["path"],
    ),
    _tool(
        "python",
        "Run Python 3 code in the workspace; print what you want to see.",
        {"code": {"type": "string"}, "timeout_seconds": _TIMEOUT},
        ["code"],
    ),
    _tool(
        "http",
        "Send one HTTP request to the challenge's own instance (no other host; redirects are not followed).",
        {
            "method": {"type": "string", "description": "GET, POST, ..."},
            "url": {"type": "string"},
            "body": {"type": "string"},
            "headers": {"type": "object", "additionalProperties": {"type": "string"}},
        },
        ["method", "url"],
    ),
    _tool(
        "submit_flag",
        "Hand a candidate flag to the player, who decides whether to submit it.",
        {"flag": {"type": "string"}, "how": {"type": "string", "description": "One line on how you found it."}},
        ["flag"],
    ),
    _tool(
        "set_plan",
        "Tell the player watching what you are doing next, in one or two sentences.",
        {"plan": {"type": "string"}},
        ["plan"],
    ),
]

_PARAMETERS = {t["function"]["name"]: tuple(t["function"]["parameters"]["properties"]) for t in TOOLS}


@dataclass(frozen=True)
class ToolResult:
    """One tool call's result: what the model sees, and what the console shows."""

    content: str  # for the model: truncated, naming the overflow file
    action: str  # one line for the console: "$ ls", "read notes.txt", "GET http://...", ...
    output: str  # short output for the console, at most 300 characters
    flag: str | None = None  # submit_flag: the candidate, stripped
    plan: str | None = None  # set_plan: the new plan, stripped
    error: bool = False  # the call itself failed: bad arguments, a refused path or origin...


class _Mistake(Exception):
    """Something the model got wrong. It becomes an error result, never an exception."""

    def __init__(self, message: str, action: str = "") -> None:
        super().__init__(message)
        self.action = action


Origin = tuple[str, str, int]  # (scheme, host, port)


class Toolbox:
    """Runs a lane's tool calls in its workspace.

    http_allow lists the origins the http tool may reach (the challenge's own instance, like
    "http://127.0.0.1:8080"); with none, http is off.
    """

    def __init__(
        self,
        workspace: Workspace,
        *,
        max_chars: int = 8000,
        default_timeout: float = 60.0,
        max_timeout: float = 300.0,
        http_allow: tuple[str, ...] = (),
    ) -> None:
        if max_chars < MIN_CHARS:
            raise ValueError(f"max_chars must be at least {MIN_CHARS}, got {max_chars}")
        if not 0 < default_timeout <= max_timeout:
            raise ValueError(f"need 0 < default_timeout <= max_timeout, got {default_timeout} and {max_timeout}")
        self.workspace = workspace
        self.max_chars = max_chars
        self.default_timeout = default_timeout
        self.max_timeout = max_timeout
        self.http_allow: dict[Origin, str] = {_allowed_origin(o): o for o in http_allow}
        self._tools: dict[str, Callable[[dict[str, Any], int, int], Awaitable[ToolResult]]] = {
            "shell": self._shell,
            "read_file": self._read_file,
            "python": self._python,
            "http": self._http,
            "submit_flag": self._submit_flag,
            "set_plan": self._set_plan,
        }

    async def call(self, name: str, arguments: str, *, turn: int, index: int) -> ToolResult:
        """Run one tool call; `turn` and `index` name its overflow files.

        Never raises for the model's mistakes (bad JSON, an unknown tool, a missing argument, a
        path outside the workspace...): they come back as ToolResult(error=True,
        content="error: ..."). A broken workspace (WorkspaceError) does raise: no model can fix it.
        """
        tool = self._tools.get(name)
        if tool is None:
            shown = _clip(str(name), 60)
            return _failed(f"unknown tool {shown}", f"unknown tool {shown!r}; the tools are {', '.join(self._tools)}")
        try:
            return await tool(_arguments(arguments, name), turn, index)
        except _Mistake as mistake:
            return _failed(mistake.action or name, str(mistake))

    # ------------------------------------------------------------ shell and python

    async def _shell(self, args: dict[str, Any], turn: int, index: int) -> ToolResult:
        command = _required(args, "command", "shell")
        action = f"$ {command}"
        if not command.strip():
            raise _Mistake("command is empty", action)
        if "\0" in command:
            raise _Mistake("command contains a NUL character", action)
        _sendable(command, "command", action)
        size = len(command.encode("utf-8"))
        if size > COMMAND_BYTES:
            # Past the system's limit, starting bash fails (E2BIG) before the command runs.
            raise _Mistake(f"the command is {size} bytes, over the {COMMAND_BYTES}-byte limit for one command; write long data to a file in parts", action)
        timeout = self._timeout(args)
        return self._ran(action, await self.workspace.run(command, timeout=timeout), timeout, turn, index)

    async def _python(self, args: dict[str, Any], turn: int, index: int) -> ToolResult:
        code = _required(args, "code", "python")
        first = next((line.strip() for line in code.splitlines() if line.strip()), "")
        action = f"python: {first}"
        if not first:
            raise _Mistake("code is empty", action)
        timeout = self._timeout(args)
        name = f"{PRIVATE}/py/turn{turn}-{index}.py"
        try:
            write_inside(self.workspace.root, name, code.encode("utf-8", "replace"))
        except OSError as exc:
            raise _Mistake(f"could not save the code to {name}: {exc.strerror or exc}", action) from None
        result = await self.workspace.run(f"python3 {shlex.quote(name)}", timeout=timeout)
        return self._ran(action, result, timeout, turn, index)

    def _timeout(self, args: dict[str, Any]) -> float:
        asked = _number(args, "timeout_seconds")
        if asked is None:
            return self.default_timeout
        return float(min(max(asked, 1), self.max_timeout))

    def _ran(self, action: str, result: RunResult, timeout: float, turn: int, index: int) -> ToolResult:
        text = result.output.decode("utf-8", "replace")
        if result.timed_out:
            status = f"timed out after {timeout:g}s"
        elif result.exit_code is None:
            status = "killed"
        else:
            status = f"exit {result.exit_code}"
        body = self._fit(text, result.output, self.max_chars - len(status) - 1, turn, index)
        failed = result.exit_code != 0
        return ToolResult(
            content=f"{status}\n{body}",
            action=_one_line(action),
            output=_brief(text, status if failed else "", tail=failed),
        )

    def _fit(self, text: str, raw: bytes, room: int, turn: int, index: int) -> str:
        """text if it fits in `room` characters; else its head (~60%) and tail (~30%) around a
        line naming the file that holds all of it."""
        if len(text) <= room:
            return text
        name = f"{PRIVATE}/out/turn{turn}-{index}.txt"
        try:
            write_inside(self.workspace.root, name, raw)
            where = f"full output in {name}"
        except OSError as exc:
            where = f"the full output could not be saved ({exc.strerror or exc})"
        marker = len(f"\n[... {len(text)} characters cut; {where} ...]\n")
        head = max(0, min(int(self.max_chars * 0.6), (room - marker) * 2 // 3))
        tail = max(0, min(int(self.max_chars * 0.3), room - marker - head))
        cut = len(text) - head - tail
        return f"{text[:head]}\n[... {cut} characters cut; {where} ...]\n{text[len(text) - tail:]}"

    # ------------------------------------------------------------ read_file

    async def _read_file(self, args: dict[str, Any], turn: int, index: int) -> ToolResult:
        path = _required(args, "path", "read_file")
        action = f"read {path}"
        start = _number(args, "start_line")
        count = _number(args, "max_lines")
        start = 1 if start is None else int(start)
        count = READ_LINES if count is None else int(count)
        if start < 1:
            raise _Mistake("start_line counts from 1", action)
        if count < 1:
            raise _Mistake("max_lines must be at least 1", action)
        # The fence looks the path up on disk too, so it runs off the event loop with the read.
        return await asyncio.to_thread(self._fence_and_read, path, action, start, count)

    def _fence_and_read(self, path: str, action: str, start: int, count: int) -> ToolResult:
        return self._read(self._fence(path, action), path, action, start, count)

    def _fence(self, path: str, action: str) -> list[str]:
        """The file the model means, as components under root, following symlinks the way the
        lane's commands would see them (in docker, /work/... is root). Anything that leaves root
        is refused. The components found are opened later without following any symlink, so a
        swap after this check cannot lead outside either.

        Each component costs one lookup, and the work is bounded: a path over PATH_CHARS is
        refused before any lookup, and so is one that grows past that through its symlinks
        (no such path can be opened anyway)."""
        if len(path) > PATH_CHARS:
            raise _Mistake(f"the path is {len(path)} characters; a path can be at most {PATH_CHARS}", action)
        if not path.strip():
            raise _Mistake("path is empty", action)
        if "\0" in path:
            raise _Mistake("path contains a NUL character", action)
        _sendable(path, "path", action)
        base = str(Path(self.workspace.root))
        prefixes = _prefixes(self.workspace)
        if path.startswith("/"):
            below = _below(path, prefixes)
            if below is None:
                raise _Mistake(f"{path} is outside the workspace", action)
            pending = deque(below)
        else:
            pending = deque(path.split("/"))
        parts: list[str] = []
        here = base  # root/parts as one path, grown a component at a time
        ends: list[int] = []  # len(here) before each part was added, to step back on ".."
        hops = 0
        while pending:
            name = pending.popleft()
            if name in ("", "."):
                continue
            if name == "..":
                if not parts:
                    raise _Mistake(f"{path} is outside the workspace", action)
                parts.pop()
                here = here[: ends.pop()]
                continue
            step = f"{here}/{name}"
            if len(step) - len(base) > PATH_CHARS:
                raise _Mistake(f"{path} is too long once its symlinks are followed (over {PATH_CHARS} characters)", action)
            try:
                link = stat.S_ISLNK(os.lstat(step).st_mode)
            except OSError:
                link = False  # missing, or under a file: opening it says which
            if not link:
                parts.append(name)
                ends.append(len(here))
                here = step
                continue
            hops += 1
            if hops > SYMLINK_HOPS:
                raise _Mistake(f"{path}: too many levels of symlinks", action)
            try:
                target = os.readlink(step)
            except OSError:
                raise _Mistake(f"{path} changed while it was being looked up; try again", action) from None
            if target.startswith("/"):
                rest = _below(target, prefixes)
                if rest is None:
                    raise _Mistake(f"{path} leads outside the workspace (a symlink to {target})", action)
                parts, ends, here = [], [], base
                pending.extendleft(reversed(rest))
            else:
                pending.extendleft(reversed(target.split("/")))
        return parts

    def _read(self, parts: list[str], path: str, action: str, start: int, count: int) -> ToolResult:
        try:
            fd = open_inside(Path(self.workspace.root), parts)
        except OSError as exc:
            return _failed(action, _open_problem(path, exc))
        with open(fd, "rb") as f:
            size = os.fstat(f.fileno()).st_size
            if b"\0" in f.read(SNIFF):
                summary = f"binary file, {size} bytes"
                return ToolResult(f"{summary}; use shell (file, xxd, strings)", _one_line(action), summary)
            f.seek(0)
            return self._lines(f, path, action, start, count)

    def _lines(self, f: Any, path: str, action: str, start: int, count: int) -> ToolResult:
        budget = max(MIN_CHARS - FOOTER_CHARS, self.max_chars - FOOTER_CHARS)
        limit = budget * 4 + 4  # bytes enough for `budget` characters
        lines: list[str] = []
        used = number = 0
        more = cut = False
        while True:
            raw, whole = _read_line(f, limit)
            if raw is None:
                break
            number += 1
            if number < start:
                continue
            if number >= start + count:
                more = True
                break
            line = raw.decode("utf-8", "replace")
            if used + len(line) > budget:
                if lines:
                    more = True
                    break
                line, whole = line[:budget], False  # one line longer than the budget: show its start
            lines.append(line)
            used += len(line)
            if not whole:
                cut = True
                more = bool(f.read(1))
                break
        if not lines:
            if number == 0:
                return ToolResult("(empty file)", _one_line(action), "empty file")
            raise _Mistake(f"start_line {_clip(str(start), 30)} is past the end: {path} has {number} lines", action)
        last = start + len(lines) - 1
        text = "".join(lines)
        if not (more or cut):
            shown = f"{len(lines)} lines" if start == 1 else f"lines {start}-{last}"
            return ToolResult(text, _one_line(action), shown)
        total = _count_lines(f)
        notes = [f"lines {start}-{last} of {total}" if total is not None else f"lines {start}-{last} of a {os.fstat(f.fileno()).st_size}-byte file"]
        if cut:
            notes.append(f"line {last} is cut; use shell (cut, head -c) for the rest of it")
        if more:
            notes.append(f"read on with start_line={last + 1}")
        newline = "" if text.endswith("\n") else "\n"
        return ToolResult(f"{text}{newline}[{'; '.join(notes)}]", _one_line(action), notes[0])

    # ------------------------------------------------------------ http

    async def _http(self, args: dict[str, Any], turn: int, index: int) -> ToolResult:
        method = _required(args, "method", "http").strip().upper()
        url = _required(args, "url", "http").strip()
        body = _optional(args, "body")
        headers = args.get("headers")
        action = f"{method} {url}"
        if not re.fullmatch(r"[A-Z]{1,20}", method):
            raise _Mistake(f"method {_clip(method, 40)!r} is not an HTTP method like GET or POST", action)
        if headers is not None and not (
            isinstance(headers, dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in headers.items())
        ):
            raise _Mistake("headers must be an object of strings", action)
        if not self.http_allow:
            raise _Mistake("http is off: this challenge has no instance to reach", action)
        _sendable(url, "url", action)
        _sendable(body or "", "body", action)
        _sendable("".join(f"{k}{v}" for k, v in (headers or {}).items()), "headers", action)
        try:
            target = httpx.URL(url)
        except (httpx.InvalidURL, ValueError, TypeError) as exc:
            raise _Mistake(f"not a valid URL: {exc}", action) from None
        if target.scheme not in ("http", "https") or not target.host:
            raise _Mistake("the URL must start with http:// or https:// and name a host", action)
        if target.userinfo:
            raise _Mistake("no user:password@ in the URL; send an Authorization header instead", action)
        if _origin(target) not in self.http_allow:
            allowed = ", ".join(self.http_allow.values())
            raise _Mistake(f"{_show(_origin(target))} is not this challenge's instance; http goes only to {allowed}", action)
        try:
            async with asyncio.timeout(HTTP_TIMEOUT):
                response, raw, complete = await _fetch(method, target, body, headers)
        except (TimeoutError, httpx.TimeoutException):
            raise _Mistake(f"no complete answer within {HTTP_TIMEOUT:g} s", action) from None
        except httpx.HTTPError as exc:
            raise _Mistake(f"the request failed: {type(exc).__name__}: {_clip(str(exc), 200)}", action) from None
        except (ValueError, UnicodeError) as exc:
            raise _Mistake(f"the request was not sent: {_clip(str(exc), 200)}", action) from None
        except Exception as exc:
            # The HTTP stack refused what the model asked for in a way httpx does not wrap: h11
            # raises its own LocalProtocolError while writing a body that disagrees with a
            # Content-Length header the model set. Cancellation is not an Exception, so it
            # still goes through.
            raise _Mistake(f"the request could not be sent as given: {type(exc).__name__}: {_clip(str(exc), 200)}", action) from None
        return self._answer(action, response, raw, complete, turn, index)

    def _answer(self, action: str, response: httpx.Response, raw: bytes, complete: bool, turn: int, index: int) -> ToolResult:
        # The reason phrase is the instance's text, of any length: clipped like a header line,
        # so it cannot push the body out of max_chars.
        reason = untrusted(response.reason_phrase, one_line=True)
        status = _clip(f"{response.http_version} {response.status_code} {reason}".strip(), min(200, self.max_chars // 4))
        head = "\n".join([status, *_header_lines(response.headers, self.max_chars // 4)])
        if not complete:
            head += f"\n[body over {OUTPUT_CAP // (1024 * 1024)} MB: the rest was not read]"
        if b"\0" in raw[:SNIFF]:
            name = f"{PRIVATE}/out/turn{turn}-{index}.txt"
            try:
                write_inside(self.workspace.root, name, raw)
                body = f"[binary body, {len(raw)} bytes; saved to {name}]"
            except OSError as exc:
                body = f"[binary body, {len(raw)} bytes; it could not be saved ({exc.strerror or exc})]"
        elif raw:
            body = self._fit(raw.decode("utf-8", "replace"), raw, self.max_chars - len(head) - 2, turn, index)
        else:
            body = "(empty body)"
        summary = f"{response.status_code} {_clip(reason, 60)}".strip() + f", {len(raw)} bytes"
        return ToolResult(f"{head}\n\n{body}", _one_line(action), _clip(summary, CONSOLE_CHARS))

    # ------------------------------------------------------------ flags and plans

    async def _submit_flag(self, args: dict[str, Any], turn: int, index: int) -> ToolResult:
        flag = _required(args, "flag", "submit_flag").strip()
        how = (_optional(args, "how") or "").strip()
        if not flag:
            raise _Mistake("flag is empty", "submit")
        return ToolResult(SUBMITTED, _one_line(f"submit {flag}"), _clip(how, CONSOLE_CHARS), flag=flag)

    async def _set_plan(self, args: dict[str, Any], turn: int, index: int) -> ToolResult:
        plan = _required(args, "plan", "set_plan").strip()
        if not plan:
            raise _Mistake("plan is empty", "plan")
        noted = "Plan noted."
        if len(plan) > PLAN_CHARS:
            plan = _clip(plan, PLAN_CHARS)
            noted = f"Plan noted (cut to {PLAN_CHARS} characters)."
        return ToolResult(noted, _one_line(f"plan: {plan}"), "", plan=plan)


# ---------------------------------------------------------------- arguments


def _arguments(text: str, tool: str) -> dict[str, Any]:
    if not isinstance(text, str):
        raise _Mistake("the arguments must be JSON text")
    if not text.strip():
        value: Any = {}
    else:
        try:
            value = json.loads(text)
        except json.JSONDecodeError as exc:
            raise _Mistake(f"the arguments are not valid JSON ({exc.msg} at character {exc.pos}); send one JSON object") from None
        except (ValueError, RecursionError):
            raise _Mistake("the arguments are not valid JSON; send one JSON object") from None
    if not isinstance(value, dict):
        raise _Mistake("the arguments must be a JSON object")
    allowed = _PARAMETERS[tool]
    unknown = sorted(k for k in value if k not in allowed)
    if unknown:
        named = ", ".join(_clip(k, 40) for k in unknown[:5])
        raise _Mistake(f"{tool} takes {', '.join(allowed)}; unknown: {named}")
    return value


def _required(args: dict[str, Any], key: str, tool: str) -> str:
    value = _optional(args, key)
    if value is None:
        raise _Mistake(f"{tool} needs {key} (a string)")
    return value


def _optional(args: dict[str, Any], key: str) -> str | None:
    value = args.get(key)
    if value is not None and not isinstance(value, str):
        raise _Mistake(f"{key} must be a string")
    return value


def _number(args: dict[str, Any], key: str) -> float | None:
    """A JSON number, or None when absent. An integer can be far too big for a float (JSON
    allows 4000 digits), so it is never turned into one here: callers compare and clamp it."""
    value = args.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or (isinstance(value, float) and not math.isfinite(value)):
        raise _Mistake(f"{key} must be a number")
    return value


def _sendable(text: str, what: str, action: str) -> None:
    """Text that can go to a process or a socket: no lone surrogates (JSON allows them)."""
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        raise _Mistake(f"the {what} holds characters that are not valid Unicode", action) from None


# ---------------------------------------------------------------- paths


def _prefixes(workspace: Workspace) -> tuple[str, ...]:
    """Absolute paths, as the lane sees them, that mean the workspace root."""
    root = Path(workspace.root)
    names = [getattr(workspace, "workdir", None), str(root), str(root.resolve())]
    return tuple(dict.fromkeys(n.rstrip("/") for n in names if n and n.rstrip("/")))


def _below(path: str, prefixes: tuple[str, ...]) -> list[str] | None:
    """The components of an absolute path below the root, or None when it is outside."""
    for prefix in prefixes:
        if path == prefix or path.startswith(prefix + "/"):
            return path[len(prefix) :].split("/")
    return None


def _open_problem(path: str, exc: OSError) -> str:
    if isinstance(exc, FileNotFoundError):
        return f"no such file: {path}"
    if isinstance(exc, IsADirectoryError):
        return f"{path} is a directory; use shell (ls)"
    if isinstance(exc, NotADirectoryError):
        return f"no such file: {path} (part of the path is a file)"
    if isinstance(exc, PermissionError):
        return f"permission denied: {path}"
    if exc.errno == errno.ELOOP:
        return f"{path} changed while it was being opened; try again"
    if exc.errno == errno.EINVAL:
        return f"{path} is not a regular file"
    return f"cannot read {path}: {exc.strerror or exc}"


def _read_line(f: Any, limit: int) -> tuple[bytes | None, bool]:
    """(the next line, at most `limit` bytes of it; whether it is whole). The rest of a longer
    line is skipped, so line numbers stay right."""
    chunk = f.readline(limit)
    if not chunk:
        return None, True
    if chunk.endswith(b"\n") or len(chunk) < limit:
        return chunk, True
    while True:
        more = f.readline(1024 * 1024)
        if not more or more.endswith(b"\n"):
            return chunk, False


def _count_lines(f: Any) -> int | None:
    """How many lines the whole file has, or None when it is too big to count cheaply."""
    if os.fstat(f.fileno()).st_size > 64 * 1024 * 1024:
        return None
    f.seek(0)
    newlines, last = 0, b""
    while chunk := f.read(1024 * 1024):
        newlines += chunk.count(b"\n")
        last = chunk[-1:]
    return newlines + (1 if last and last != b"\n" else 0)


# ---------------------------------------------------------------- http


def _origin(url: httpx.URL) -> Origin:
    port = url.port or {"http": 80, "https": 443}.get(url.scheme, 0)
    return url.scheme, url.host.lower(), port


def _show(origin: Origin) -> str:
    scheme, host, port = origin
    return f"{scheme}://{f'[{host}]' if ':' in host else host}:{port}"


def _allowed_origin(text: str) -> Origin:
    """An http_allow entry: scheme://host[:port], nothing more. ValueError otherwise."""
    try:
        url = httpx.URL(text)
    except (httpx.InvalidURL, ValueError, TypeError):
        url = None
    if (
        url is None
        or url.scheme not in ("http", "https")
        or not url.host
        or url.userinfo
        or url.raw_path not in (b"", b"/")
        or url.fragment
    ):
        raise ValueError(f"http_allow entry {text!r} is not an origin like http://127.0.0.1:8080")
    return _origin(url)


async def _fetch(method: str, target: httpx.URL, body: str | None, headers: dict[str, str] | None) -> tuple[httpx.Response, bytes, bool]:
    """One request, straight to the instance: no redirects followed, and no proxy from the
    environment (trust_env off), so the request goes only where the allowlist said. Reads at
    most OUTPUT_CAP bytes of the body: (response, body, whether the body was read to its end)."""
    content = None if body is None else body.encode("utf-8")
    async with httpx.AsyncClient(trust_env=False, follow_redirects=False, timeout=HTTP_TIMEOUT) as client:
        async with client.stream(method, target, content=content, headers=headers) as response:
            raw = bytearray()
            complete = True
            async for chunk in response.aiter_bytes():
                raw += chunk
                if len(raw) > OUTPUT_CAP:
                    del raw[OUTPUT_CAP:]
                    complete = False
                    break
            return response, bytes(raw), complete


_NOISE_HEADERS = frozenset(
    {
        "date", "connection", "keep-alive", "transfer-encoding", "accept-ranges", "age", "alt-svc",
        "vary", "expires", "pragma", "etag", "last-modified", "cache-control",
    }
)


def _header_lines(headers: httpx.Headers, room: int) -> list[str]:
    """The response headers worth a model's tokens, one line each, in at most `room` characters."""
    items = [(k, v) for k, v in headers.multi_items() if k not in _NOISE_HEADERS]
    lines: list[str] = []
    for k, v in items[:HTTP_HEADERS]:
        line = _clip(untrusted(f"{k}: {v}", one_line=True), 200)
        if sum(len(x) + 1 for x in lines) + len(line) > room:
            break
        lines.append(line)
    if len(lines) < len(items):
        lines.append(f"[... {len(items) - len(lines)} more headers]")
    return lines


# ---------------------------------------------------------------- results


def _failed(action: str, message: str) -> ToolResult:
    return ToolResult(f"error: {message}", _one_line(action), _clip(f"error: {message}", CONSOLE_CHARS), error=True)


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _one_line(text: str) -> str:
    return _clip(untrusted(text, one_line=True), ACTION_CHARS)


def _brief(text: str, status: str, *, tail: bool) -> str:
    """Up to 300 characters for the console: the first lines of a success, the last lines of a
    failure (where errors are)."""
    window = text[-4096:] if tail else text[:4096]
    lines = [line.strip() for line in window.splitlines() if line.strip()]
    picked = lines[-3:] if tail else lines[:3]
    excerpt = "\n".join(picked) if picked else "(no output)"
    return _clip(f"{status} · {excerpt}" if status else excerpt, CONSOLE_CHARS)
