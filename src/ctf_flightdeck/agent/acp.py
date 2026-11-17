"""ACP agents as lanes (P100): an agent that speaks the Agent Client Protocol on its stdio.

The Agent Client Protocol (agentclientprotocol.com) is JSON-RPC 2.0, one message per line,
over the agent's stdin and stdout. flightdeck is the client and speaks protocol version 1
(PROTOCOL_VERSION: the schema at schema/v1/schema.json of the protocol's repository, read on
2026-11-16). The player names the agent by its command line ([agents.acp] in the config:
docs/GUIDE.md), so any agent with an ACP mode, or an adapter that gives one, can run lanes.

A lane is one process of the agent, like a claude lane (agent/external.py: every rule there
holds here too: the held configuration files, the agent's home outside the workspace, the
environment allowlist, secrets redacted before anything is kept, freezing, stops, take-overs,
escalation, the flag rules). What ACP adds:
- the start: `initialize` (flightdeck's version and capabilities), then `session/new` in the
  lane's workspace with no MCP servers. An agent that answers another protocol version, or
  says it must be logged in first (ACP's `authenticate`, which flightdeck never calls), ends
  the lane naming why. lane_rules() goes in as the session's system prompt when the agent
  takes one (sessionCapabilities.systemPrompt), else at the top of the first prompt.
- a turn: `session/prompt` with one text block; its answer (a stopReason) ends the turn. The
  agent's message chunks are its words (searched for flags; a FLAG line claims one), its
  tool calls and their updates are the lane's steps, its plan is the lane's plan.
- an interrupt (a hint, a verdict, a hand-back): `session/cancel`, as claude's interrupt
  request; the turn ends with stopReason cancelled and the message goes in as the next prompt.
- permission: the agent asks (`session/request_permission`) and flightdeck answers by its own
  policy (judge), never by anything the challenge says: a command is allowed, as claude's Bash
  is; a read, a search or an edit only when every path it names is in the lane's workspace
  (and an edit, a delete or a move not in flightdeck's own .flightdeck); a fetch, a switch of
  the agent's mode, or a call flightdeck cannot place is refused. It picks allow_once (never
  "always", which would let later calls past the policy), allow_always only for a command.
- files: flightdeck offers fs/read_text_file and fs/write_text_file, confined to the lane's
  workspace (open_inside and write_inside: no symlink is followed on the way, nothing is
  written in .flightdeck). A write waits while the lane is paused or taken over. No terminal:
  the agent runs its commands itself.
- cost: ACP reports none in general (P7): a turn ends with its cost unknown, as a codex turn
  with no price, so a dollar-capped lane asks once before it carries on without its cap. An
  agent that sends usage_update with a cost in USD (cumulative for the session) has the turn's
  share of it counted. ACP reports no tokens either: a token cap is never reached.
- an outage (P78): ACP gives no structured reason for a failed turn, so a lane whose prompt
  fails ends with the agent's message and counts toward no outage.

tests/fake_acp_agent.py plays an agent from the protocol's schema, and marks each of its
assumptions ASSUMED. One real agent was run (2026-11-16): Claude Code's ACP adapter,
@agentclientprotocol/claude-agent-acp 0.99.1, played the practice set on the host (12 of 14,
tool calls, permission requests, the cost it reported in USD). It also sends
_auth/status_update, an extension notification ("_"), skipped quietly as the spec says.
"""

from __future__ import annotations

import asyncio
import json
import os
import posixpath
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .. import __version__
from ..core.driver import TurnReport
from ..core.model import FileChange, LaneState
from .external import (
    ACP,
    CONTAINER_ROOT,
    CUT_TURN,
    MAX_PROBLEMS,
    NUDGE,
    TURN_END,
    AgentError,
    CliAgent,
    _check_model,
    _first_line,
    _one_line,
    _Proc,
    _Run,
    _str,
    lane_rules,
)
from .workspace import PRIVATE, absolute_path, open_inside, write_inside

PROTOCOL_VERSION = 1
MODEL = "{model}"  # in an argument of the agent's command line: the lane's model (config.ACP_MODEL)
FS_READ_BYTES = 2 * 1024 * 1024  # the most fs/read_text_file reads of one file
SESSION_ID_CHARS = 512
# JSON-RPC error codes (the schema's ErrorCode)
INVALID_PARAMS = -32602
METHOD_NOT_FOUND = -32601
INTERNAL = -32603
NOT_FOUND = -32002
AUTH_REQUIRED = -32000

ANYWHERE = ("execute", "think")  # a command runs in the lane's workspace (or its container), as claude's Bash
IN_WORKSPACE = ("read", "search", "edit", "delete", "move")
CHANGES = ("edit", "delete", "move")
KNOWN_UPDATES = frozenset({
    "user_message_chunk", "agent_thought_chunk", "available_commands_update", "current_mode_update",
    "config_option_update", "session_info_update", "compaction_update", "compaction_summary_chunk",
})  # nothing a lane shows: skipped without a note


# ---------------------------------------------------------------------- finding the agent


def find_acp_agent(command: Sequence[str], model: str, *, env: Sequence[str] = (), api: Sequence[str] = (),
                   hold: Sequence[str] = (), environ: Mapping[str, str] = os.environ, docker: bool = False) -> CliAgent:
    """The ACP agent the player's [agents.acp] names, ready to run lanes on `model`, or
    AgentError naming what is missing. Its program is found on PATH's absolute folders only
    (as find_agent finds a CLI), or taken as the absolute path given; each variable `env`
    names must be set, and its value goes to the agent, a secret (shown as [NAME]).

    `docker`: the lanes run in Docker, where the agent runs inside the lane's container, so
    its program is looked for in the lane image (run._check_image_has before the run,
    ExternalLane.container_cli at each lane's start), never on this machine: an agent
    installed only in the image is enough, and one installed only here is not."""
    if not command:
        raise AgentError("[agents.acp] command is empty: it needs the agent's program, then its arguments")
    _check_model(model)
    program, *args = command  # with no {model} in args, the ladder's one model is a name for the deck and [prices] only
    expanded = os.path.expanduser(program)
    if docker:
        if "/" in program and not program.startswith("/"):
            raise AgentError(f"[agents.acp] command names {program} by a relative path: give a name on the lane image's "
                             "PATH or an absolute path in it")
        expanded = found = program  # a path in the image: ~ there is not this machine's home
    elif os.path.isabs(expanded):
        if not (os.path.isfile(expanded) and os.access(expanded, os.X_OK)):
            raise AgentError(f"[agents.acp] command names {expanded}, which is not a program this user can run")
        found = expanded
    else:
        if "/" in program:
            raise AgentError(f"[agents.acp] command names {program} by a relative path: give a name on PATH or an "
                             "absolute path")
        path = absolute_path(environ.get("PATH", os.defpath))
        located = shutil.which(program, path=path) if path else None
        if located is None:
            raise AgentError(f"{program} ([agents.acp] command) not found on PATH: install it, or give its absolute path")
        found = str(Path(located).absolute())
    missing = [name for name in env if not environ.get(name, "").strip()]
    if missing:
        raise AgentError(
            f"[agents.acp] env names {', '.join(missing)}, and {'it is' if len(missing) == 1 else 'they are'} not set "
            "in the environment or the keys file"
        )
    extra = {name: environ[name].strip() for name in env}
    if env:
        how = f"{', '.join(env)}: the agent's own credential, passed by name"
        warnings = [
            f"The agent's credential ({', '.join(env)}) is in its process's environment, and the commands the agent "
            "runs can read it. In the host runtime those commands also run as you and can read your files. Prefer the "
            "docker runtime, and use a key you can revoke, with a low spending limit.",
        ]
    else:
        how = "no credential passed ([agents.acp] env names none)"
        warnings = [
            "[agents.acp] env names no variable, so the agent gets no credential from flightdeck; its HOME is a folder "
            "of the lane's (outside the workspace, empty at first), so a login saved in your own home is not seen.",
        ]
    warnings.append(
        "ACP agents report no cost in general: a lane's dollars show as unknown (a dollar cap asks once before it "
        "carries on without it) unless the agent reports its cost in USD."
    )
    return CliAgent(
        ACP, found, model, MappingProxyType(extra), how, tuple(warnings), api=tuple(api), program=expanded,
        args=tuple(args), hold=frozenset(name.lower() for name in hold),
    )


def acp_argv(executable: str, args: Sequence[str], model: str) -> list[str]:
    """The agent's command line on `model`: {model} in an argument is replaced by it. The
    model passed _check_model (letters, digits and . _ : / @ + [ ] -), and nothing goes
    through a shell."""
    return [executable, *(arg.replace(MODEL, model) for arg in args)]


# ---------------------------------------------------------------------- the policy


def judge(kind: str, places: Sequence[list[str] | None]) -> str:
    """Whether flightdeck allows a tool call the agent asks permission for: "" when it does,
    else why not. `kind` is the call's ToolKind; `places`, each path it names, as parts
    relative to the workspace (None: outside it, or through a symlink that leads out).
    The policy of a claude lane: commands run, work stays in the workspace, and what would
    need a human to judge is refused. Challenge text never reaches this."""
    if kind in ANYWHERE:
        return ""
    if kind in IN_WORKSPACE:
        if not places:
            return f"a {kind} that names no path (flightdeck allows one only in the lane's workspace)"
        if any(place is None for place in places):
            return f"a {kind} outside the lane's workspace"
        if kind in CHANGES and any(place and place[0] == PRIVATE for place in places):
            return f"a {kind} in flightdeck's own {PRIVATE}"
        return ""
    if kind == "fetch":
        return "a fetch (the agent reaches the challenge through commands in its workspace)"
    if kind == "switch_mode":
        return "a switch of the agent's mode, which could change what it does without asking"
    return f"a tool call of kind {_one_line(kind, 40) or 'other'}, which flightdeck cannot place"


def choose(options: Any, kind: str, allow: bool) -> dict:
    """The outcome of a permission request: one of the options the agent offered. Allowed:
    allow_once; allow_always only for a command (judge allows every one). Refused:
    reject_once, else reject_always. With no such option, the request is answered cancelled,
    which lets nothing run."""
    offered = [o for o in options if isinstance(o, dict) and isinstance(o.get("optionId"), str)] if isinstance(options, list) else []
    wanted = ("allow_once", "allow_always") if allow and kind in ANYWHERE else ("allow_once",) if allow else (
        "reject_once", "reject_always")
    for want in wanted:
        for option in offered:
            if option.get("kind") == want:
                return {"outcome": "selected", "optionId": option["optionId"]}
    return {"outcome": "cancelled"}


# ---------------------------------------------------------------------- one connection


@dataclass
class _Conn:
    """The protocol's state for one process of the agent."""

    proc: _Proc
    next_id: int = 0
    waiting: dict[int, asyncio.Future[dict]] = field(default_factory=dict)  # our requests -> their answers
    session: str | None = None
    system_prompt: bool = False  # the agent took lane_rules() as the session's system prompt
    prompt: int | None = None  # the id of the session/prompt in flight
    cost: float | None = None  # the session's cost so far in USD, as the agent last reported it
    billed: float = 0.0  # of it, what turns have counted
    currency: str = ""  # a cost in something else than USD: said once, never counted
    gone: bool = False  # its stdout ended


class AcpRun(_Run):
    """An ACP agent: one process for the lane; one session/prompt per turn."""

    kind = ACP

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.conns: dict[_Proc, _Conn] = {}
        self.busy = False  # a prompt is in flight: the next message waits until it is answered
        self.message: list[str] = []  # the agent's message so far (its chunks), until a tool call or the turn's end
        self.message_id: str | None = None
        self.tools: dict[str, dict] = {}  # tool call id -> what the agent said of it (kind, title, rawInput, locations)
        self.done: set[str] = set()  # tool calls whose step is on the lane
        self.plan = ""
        self.refusals = 0

    # ------------------------------------------------------------------ the lane's life

    def cap_note(self) -> None:
        lane = self.lane()
        if lane is None:
            return
        if lane.token_cap:
            self.note("an ACP agent reports no tokens, so this lane's token cap is never reached: its dollar cap and "
                      "your eyes are what hold it")
        if lane.dollar_cap:
            self.note("an ACP agent reports its cost only if it sends one, and then when a turn ends: this lane's "
                      "dollar cap is checked then, and asks once if the cost is unknown")

    def workdir(self) -> str:
        return CONTAINER_ROOT if self.docker else str(self.workspace.root)

    async def session(self) -> None:
        while await self.until_running():
            generation = self.generation
            await self.before_start()
            lane = self.lane()
            if self.over() or lane is None:
                return
            if generation != self.generation or lane.state is not LaneState.RUNNING:
                continue
            proc = await self.spawn(acp_argv(self.cli, self.driver.agent.args, self.model), generation)
            if proc is None:
                return
            if proc.ending is not None:  # escalated while it started: start over, messages kept
                await self.finished(proc)
                continue
            conn = _Conn(proc)
            self.conns[proc] = conn
            self.tools, self.done, self.message, self.message_id = {}, set(), [], None
            reader = asyncio.ensure_future(self.pump(proc))
            self.track(reader)
            why = await self.handshake(conn, reader)
            if why:
                self.report(TurnReport(turn=False, action="start the agent", output=why, gave_up=why))
                proc.end(self.driver.stop_grace, self.driver.errors)
            elif self.current(proc):
                lane = self.lane()
                hints = list(lane.hints) if lane is not None else []
                extra = self.compose(hints)
                opening = self.opening() if conn.system_prompt else f"{lane_rules()}\n\n{self.opening()}"
                self.prompt_turn(conn, opening + (f"\n\n{extra}" if extra else ""), extra)
                if hints:
                    self.report(TurnReport(turn=False, hints_taken=len(hints)))
            await asyncio.gather(reader, return_exceptions=False)
            conn.gone = True
            for future in conn.waiting.values():
                if not future.done():
                    future.cancel()
            await self.finished(proc)
            self.busy = False
            if self.over() or why:
                return
            if generation != self.generation:
                self.carry = proc.sent  # what it was told mid-turn goes to the stronger model too
                continue
            self.report(TurnReport(turn=False, gave_up=self.exit_reason(proc)))
            return

    async def handshake(self, conn: _Conn, reader: asyncio.Future[None]) -> str:
        """initialize, then session/new: "" once the session is open, else why the lane ends
        ("" too when the agent exited meanwhile: the session loop says how)."""
        answer = await self.call(conn, reader, "initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "clientCapabilities": {"fs": {"readTextFile": True, "writeTextFile": True}, "terminal": False},
            "clientInfo": {"name": "flightdeck", "title": "ctf-flightdeck", "version": __version__},
        })
        if answer is None:
            return ""
        if "error" in answer:
            return self.refused("initialize", answer["error"])
        result = answer.get("result")
        result = result if isinstance(result, dict) else {}
        version = result.get("protocolVersion")
        if not isinstance(version, int) or isinstance(version, bool):
            return "the agent answered initialize with no protocol version"
        if version != PROTOCOL_VERSION:
            return f"the agent speaks ACP version {version}, and flightdeck speaks version {PROTOCOL_VERSION}"
        info = result.get("agentInfo")
        caps = result.get("agentCapabilities") if isinstance(result.get("agentCapabilities"), dict) else {}
        session_caps = caps.get("sessionCapabilities") if isinstance(caps.get("sessionCapabilities"), dict) else {}
        conn.system_prompt = isinstance(session_caps.get("systemPrompt"), dict)
        if isinstance(info, dict):
            name = _one_line(_str(info.get("name")), 60) or "an unnamed agent"
            self.note(f"the ACP agent is {name} {_one_line(_str(info.get('version')), 40)}".rstrip()
                      + f", on {self.model}")
        params: dict[str, Any] = {"cwd": self.workdir(), "mcpServers": []}
        if conn.system_prompt:
            params["systemPrompt"] = {"mode": "append", "content": [{"type": "text", "text": lane_rules()}]}
        answer = await self.call(conn, reader, "session/new", params)
        if answer is None:
            return ""
        if "error" in answer:
            return self.refused("session/new", answer["error"])
        result = answer.get("result")
        session = result.get("sessionId") if isinstance(result, dict) else None
        if not isinstance(session, str) or not session or len(session) > SESSION_ID_CHARS:
            return "the agent answered session/new with no session id flightdeck can use"
        conn.session = session
        return ""

    def refused(self, method: str, error: Any) -> str:
        code, message = _error(error)
        if code == AUTH_REQUIRED:
            return (f"the agent needs to be logged in before {method} (ACP's authenticate, which flightdeck does not "
                    "do): give it its credential by name in [agents.acp] env" + (f"; it said: {message}" if message else ""))
        return f"the agent refused {method} (error {code})" + (f": {message}" if message else "")

    async def call(self, conn: _Conn, reader: asyncio.Future[None], method: str, params: dict) -> dict | None:
        """A request and its answer (the whole message: result or error); None when the agent
        went away first, or the lane was stopped."""
        future = self.request(conn, method, params)
        if future is None:
            return None
        await asyncio.wait({future, reader}, return_when=asyncio.FIRST_COMPLETED)
        if not future.done() or future.cancelled():
            return None
        return future.result()

    # ------------------------------------------------------------------ writing to the agent

    def write(self, conn: _Conn, message: dict) -> bool:
        proc = conn.proc
        stdin = proc.process.stdin
        if stdin is None or stdin.is_closing() or not proc.alive or proc.ending is not None or conn.gone:
            return False
        stdin.write(json.dumps({"jsonrpc": "2.0", **message}).encode("utf-8") + b"\n")
        return True

    def request(self, conn: _Conn, method: str, params: dict) -> asyncio.Future[dict] | None:
        conn.next_id += 1
        ident = conn.next_id
        if not self.write(conn, {"id": ident, "method": method, "params": params}):
            return None
        future: asyncio.Future[dict] = asyncio.get_running_loop().create_future()
        conn.waiting[ident] = future
        return future

    def answer(self, conn: _Conn, ident: Any, result: dict | None = None, *, error: tuple[int, str] | None = None) -> None:
        if error is not None:
            self.write(conn, {"id": ident, "error": {"code": error[0], "message": error[1]}})
        else:
            self.write(conn, {"id": ident, "result": result if result is not None else {}})

    def prompt_turn(self, conn: _Conn, text: str, sent: str) -> None:
        """One turn: session/prompt with the text; `sent` is the part of it that is the
        player's messages and flightdeck's notes."""
        if conn.session is None:
            return
        future = self.request(conn, "session/prompt", {"sessionId": conn.session, "prompt": [{"type": "text", "text": text}]})
        if future is None:
            return
        conn.prompt = conn.next_id
        conn.proc.sent = sent
        self.busy = True

    def interrupt(self, conn: _Conn) -> None:
        """End the agent's turn: session/cancel (a notification), as claude's interrupt
        request. Written before a frozen agent is woken (sync), so it is there when it runs."""
        if conn.session is None:
            return
        if self.write(conn, {"method": "session/cancel", "params": {"sessionId": conn.session}}):
            conn.proc.interrupted = True

    def deliver(self) -> None:
        lane = self.lane()
        proc = self.proc
        if lane is None or lane.state is not LaneState.RUNNING or proc is None or not self.current(proc) or not proc.alive:
            return
        conn = self.conns.get(proc)
        if conn is None or conn.session is None:
            return  # still starting: the first prompt carries everything
        if self.busy:
            if (lane.hints or self.notes) and not proc.interrupted:
                self.interrupt(conn)  # the turn ends cancelled; the message goes once it has
            return
        hints = list(lane.hints)
        extra = self.compose(hints)
        self.prompt_turn(conn, extra or NUDGE, extra)
        if hints:
            self.report(TurnReport(turn=False, hints_taken=len(hints)))

    # ------------------------------------------------------------------ reading the agent

    async def on_event(self, proc: _Proc, event: dict) -> None:
        conn = self.conns.get(proc)
        if conn is None:
            return
        method = event.get("method")
        if isinstance(method, str):
            if "id" in event:
                self.track(asyncio.ensure_future(self.on_request(conn, event.get("id"), method, event.get("params"))))
            elif method == "session/update":
                params = event.get("params")
                if isinstance(params, dict) and params.get("sessionId") == conn.session:
                    await self.on_update(proc, conn, params.get("update"))
            elif not method.startswith("_"):  # "_..." is an agent's own extension: the spec has clients ignore it
                self.unknown_event(proc, f"notification {method}")
            return
        ident = event.get("id")
        if "result" not in event and "error" not in event:
            self.problem(proc, "a message that is no request, notification or answer")
            return
        future = conn.waiting.pop(ident, None) if isinstance(ident, int) and not isinstance(ident, bool) else None
        if future is None:
            self.problem(proc, "an answer to no request of flightdeck's")
            return
        if not future.done():
            future.set_result(event)
        if ident == conn.prompt:
            conn.prompt = None
            await self.turn_ended(proc, conn, event)

    async def on_request(self, conn: _Conn, ident: Any, method: str, params: Any) -> None:
        """A request of the agent's: permission, or a file. Answered by flightdeck's policy."""
        params = params if isinstance(params, dict) else {}
        if params.get("sessionId") != conn.session or conn.session is None:
            self.answer(conn, ident, error=(INVALID_PARAMS, "no such session"))
            return
        try:
            if method == "session/request_permission":
                self.answer(conn, ident, {"outcome": self.permission(conn, params)})
            elif method == "fs/read_text_file":
                self.answer(conn, ident, await self.read_file(params))
            elif method == "fs/write_text_file":
                self.answer(conn, ident, await self.write_file(params))
            else:
                self.answer(conn, ident, error=(METHOD_NOT_FOUND, f"flightdeck does not offer {method}"))
        except _Refusal as refusal:
            self.answer(conn, ident, error=(refusal.code, refusal.message))

    async def on_update(self, proc: _Proc, conn: _Conn, update: Any) -> None:
        if not isinstance(update, dict):
            self.problem(proc, "a session/update with no update")
            return
        kind = _str(update.get("sessionUpdate"))
        if kind == "usage_update":
            self.usage(conn, update.get("cost"))  # an old model's too: what it cost counts
            return
        current = self.current(proc)
        if kind in ("agent_message_chunk", "tool_call", "tool_call_update", "plan"):
            self.api_answered()
        if not current:
            return
        if kind == "agent_message_chunk":
            content = update.get("content")
            mid = update.get("messageId") if isinstance(update.get("messageId"), str) else None
            if mid is not None and self.message_id is not None and mid != self.message_id:
                await self.flush()
            self.message_id = mid
            if isinstance(content, dict) and content.get("type") == "text":
                self.message.append(_str(content.get("text")))
        elif kind in ("tool_call", "tool_call_update"):
            await self.flush()
            await self.tool(update, new=kind == "tool_call")
        elif kind == "plan":
            await self.flush()
            self.on_plan(update.get("entries"))
        elif kind == "notice":
            self.note(f"the agent says: {_one_line(_str(update.get('title')), 300) or 'a notice with no title'}")
        elif kind not in KNOWN_UPDATES:
            self.unknown_event(proc, f"update {kind}")

    async def flush(self) -> None:
        """The agent's message so far, as its words: a flag in it is a candidate (a FLAG line
        claims it), and its first line goes on the lane."""
        text, self.message, self.message_id = "".join(self.message), [], None
        if text.strip():
            await self.text(text, show=True)

    async def tool(self, update: dict, *, new: bool) -> None:
        ident = _str(update.get("toolCallId"))
        if not ident:
            return
        known = self.tools.setdefault(ident, {})
        for key in ("kind", "title", "rawInput", "locations", "content", "rawOutput", "status"):
            if update.get(key) is not None:
                known[key] = update[key]
        status = _str(known.get("status")) or ("pending" if new else "")
        if ident in self.done:
            return
        if status in ("pending", "in_progress"):
            self.in_flight[ident] = self.action(known)
            return
        if status not in ("completed", "failed"):
            return
        self.done.add(ident)
        with self.record_step():  # from before a take-over's freeze: its shell waits for this step
            action = self.finished_tool(ident) or self.action(known)
            files = [FileChange(self.relative(path), "", "modified") for path in self.diffs(known.get("content"))]
            await self.step(action, self.output(known), prefix="failed: " if status == "failed" else "", files=files)

    def action(self, call: dict) -> str:
        kind = _str(call.get("kind")) or "other"
        title = _str(call.get("title"))
        raw = call.get("rawInput") if isinstance(call.get("rawInput"), dict) else {}
        if kind == "execute":
            command = raw.get("command")
            if isinstance(command, list):
                command = " ".join(str(part) for part in command)
            return f"$ {_str(command) or title}"
        paths = [self.relative(path) for path in self.paths(call)]
        if kind in ("read", "edit", "delete", "move", "search") and paths:
            return f"{kind.title()} {', '.join(paths[:3])}"
        return f"{kind} {title}".strip()

    def output(self, call: dict) -> str:
        texts: list[str] = []
        for item in call.get("content") if isinstance(call.get("content"), list) else []:
            if not isinstance(item, dict):
                continue
            if item.get("type") == "content" and isinstance(item.get("content"), dict) and item["content"].get("type") == "text":
                texts.append(_str(item["content"].get("text")))
            elif item.get("type") == "diff":
                texts.append(f"(changed {self.relative(_str(item.get('path')))})")
        if texts:
            return "\n".join(texts)
        raw = call.get("rawOutput")
        if isinstance(raw, str):
            return raw
        if isinstance(raw, dict):
            for key in ("output", "stdout", "result"):
                if isinstance(raw.get(key), str):
                    return raw[key]
            return json.dumps(raw, ensure_ascii=False)[:4000]
        return ""

    def paths(self, call: dict) -> list[str]:
        out = []
        for place in call.get("locations") if isinstance(call.get("locations"), list) else []:
            if isinstance(place, dict) and isinstance(place.get("path"), str):
                out.append(place["path"])
        return out

    def diffs(self, content: Any) -> list[str]:
        return [_str(item.get("path")) for item in content if isinstance(item, dict) and item.get("type") == "diff"
                and _str(item.get("path"))] if isinstance(content, list) else []

    def on_plan(self, entries: Any) -> None:
        if not isinstance(entries, list):
            return
        for entry in entries:
            if isinstance(entry, dict) and entry.get("status") != "completed" and _str(entry.get("content")).strip():
                plan = _one_line(_str(entry.get("content")), 500)
                if plan != self.plan:
                    self.plan = plan
                    self.report(TurnReport(turn=False, plan=plan))
                return

    def usage(self, conn: _Conn, cost: Any) -> None:
        if not isinstance(cost, dict):
            return
        amount, currency = cost.get("amount"), _str(cost.get("currency"))
        if isinstance(amount, bool) or not isinstance(amount, (int, float)) or not 0 <= amount < 1e9:
            return
        if currency.upper() != "USD":
            if not conn.currency:
                conn.currency = _one_line(currency, 20) or "no unit"
                self.note(f"the agent reports its cost in {conn.currency}, which flightdeck does not count as dollars")
            return
        conn.cost = float(amount)

    async def turn_ended(self, proc: _Proc, conn: _Conn, answer: dict) -> None:
        """session/prompt was answered: the turn's cost, and what the lane does next."""
        current = self.current(proc)
        if current:
            await self.flush()  # its last words, should they hold a flag
            current = self.current(proc)  # stopped or escalated while they were searched
        # from here on nothing waits: the turn is accounted for before anything goes to the agent
        dollars: float | None = None
        if conn.cost is not None:
            dollars = max(conn.cost - conn.billed, 0.0)
            conn.billed = max(conn.cost, conn.billed)
        self.turn_tokens = [0, 0, 0, 0]
        self.cost_due = False
        tokens, cached = self.take_tokens()
        if not current:
            self.report(TurnReport(turn=False, tokens=tokens, cached_tokens=cached, dollars=dollars,
                                   why=CUT_TURN.format(kind=self.kind), model=proc.model, turn_end=True))
            return
        result = answer.get("result") if isinstance(answer.get("result"), dict) else {}
        stop = _str(result.get("stopReason"))
        error = answer.get("error")
        interrupted = proc.interrupted and stop == "cancelled"
        proc.interrupted = False
        self.busy = False
        proc.sent = ""
        self._delivering = True  # nothing goes to the agent before this turn is accounted for
        try:
            self.release_held()  # the turn is over: what it never claimed goes to the player
            self.report(TurnReport(turn=False, tokens=tokens, cached_tokens=cached, dollars=dollars,
                                   why=TURN_END.format(kind=self.kind), model=proc.model, turn_end=True))
            if error is not None:
                code, message = _error(error)
                self.failed_turn(f"the agent's turn failed (error {code})" + (f": {message}" if message else ""), "")
                return
            if stop == "refusal":
                last = _one_line(_first_line(self.said), 200)
                self.report(TurnReport(turn=False, declined=True, gave_up="the agent refused to go on (stopReason refusal)"
                                       + (f"; it last said: {last}" if last else "")))
                return
            if stop not in ("end_turn", "max_tokens", "max_turn_requests", "cancelled"):
                self.note(f"the agent ended its turn with a stop reason flightdeck does not know: {_one_line(stop, 60) or 'none'}")
            if interrupted:
                self.steps = 0
            elif self.idle_turn():
                return
        finally:
            self._delivering = False
        self.sync()  # the next prompt: what waits for the agent, or a nudge

    # ------------------------------------------------------------------ the agent asks

    def place(self, path: Any) -> list[str] | None:
        """A path the agent named, as parts relative to the lane's workspace; None when it is
        not absolute (ACP's paths are), not in the workspace, or leads out of it through a
        symlink on this machine (a docker lane's /work is the same folder)."""
        if not isinstance(path, str) or not path.startswith("/") or "\x00" in path:
            return None
        norm = posixpath.normpath(path)
        rel = self.relative(norm)
        if rel == norm:
            return None
        parts = [] if rel == "." else rel.split("/")
        if any(part in ("", ".", "..") for part in parts):
            return None
        root = os.path.realpath(self.workspace.root)
        real = os.path.realpath(os.path.join(root, *parts))
        if real != root and not real.startswith(root.rstrip(os.sep) + os.sep):
            return None
        return parts

    def permission(self, conn: _Conn, params: dict) -> dict:
        call = params.get("toolCall") if isinstance(params.get("toolCall"), dict) else {}
        known = dict(self.tools.get(_str(call.get("toolCallId")), {}))
        known.update({key: value for key, value in call.items() if value is not None})
        kind = _str(known.get("kind")) or "other"
        if conn.proc.interrupted or not self.current(conn.proc):
            return {"outcome": "cancelled"}  # after session/cancel every pending request is answered so (the spec)
        places = [self.place(path) for path in self.paths(known)]
        why = judge(kind, places)
        outcome = choose(params.get("options"), kind, not why)
        if why or outcome["outcome"] != "selected":
            self.refusals += 1
            if self.refusals <= MAX_PROBLEMS:
                said = why or "none of the agent's options was one flightdeck picks (allow_once)"
                self.note(f"refused the agent's {_one_line(self.action(known), 200)}: {said}")
        return outcome

    async def read_file(self, params: dict) -> dict:
        parts = self.place(params.get("path"))
        if parts is None or not parts:
            raise _Refusal(INVALID_PARAMS, "flightdeck reads files in the lane's workspace only")
        try:
            fd = await asyncio.to_thread(open_inside, Path(self.workspace.root), parts)
        except FileNotFoundError:
            raise _Refusal(NOT_FOUND, "no such file") from None
        except OSError as exc:
            raise _Refusal(INVALID_PARAMS, f"cannot read it: {exc.strerror or exc} (a symlink is never followed)") from None
        with os.fdopen(fd, "rb") as file:
            data = await asyncio.to_thread(file.read, FS_READ_BYTES + 1)
        if len(data) > FS_READ_BYTES:
            raise _Refusal(INVALID_PARAMS, f"the file is over {FS_READ_BYTES // (1024 * 1024)} MB: read it with a command")
        lines = data.decode("utf-8", "replace").splitlines(keepends=True)
        line, limit = params.get("line"), params.get("limit")
        start = line - 1 if isinstance(line, int) and not isinstance(line, bool) and line >= 1 else 0
        end = start + limit if isinstance(limit, int) and not isinstance(limit, bool) and limit >= 0 else None
        return {"content": "".join(lines[start:end])}

    async def write_file(self, params: dict) -> dict:
        parts = self.place(params.get("path"))
        content = params.get("content")
        if parts is None or not parts:
            raise _Refusal(INVALID_PARAMS, "flightdeck writes files in the lane's workspace only")
        if parts[0] == PRIVATE:
            raise _Refusal(INVALID_PARAMS, f"{PRIVATE} is flightdeck's own: nothing is written there")
        if not isinstance(content, str):
            raise _Refusal(INVALID_PARAMS, "no content")
        if not await self.until_running():  # paused or taken over: the player's shell has the workspace now
            raise _Refusal(INTERNAL, "the lane has ended")
        try:
            await asyncio.to_thread(write_inside, Path(self.workspace.root), "/".join(parts), content.encode("utf-8"))
        except (OSError, ValueError) as exc:
            raise _Refusal(INVALID_PARAMS, f"cannot write it: {getattr(exc, 'strerror', None) or exc} "
                                           "(a symlink is never followed)") from None
        return {}


class _Refusal(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _error(error: Any) -> tuple[Any, str]:
    if not isinstance(error, dict):
        return "?", ""
    code = error.get("code")
    code = code if isinstance(code, int) and not isinstance(code, bool) else "?"
    return code, _one_line(_str(error.get("message")), 300)
