"""A fake `claude` and `codex` for the external-agent tests. Never the real tools: a real
run spends the player's money.

It plays each CLI from what its documentation says, so the driver meets the shapes (and the
refusals) it would meet in a real run. A test writes the agent's behaviour as a script: what
it says, which tools it calls, the usage and cost of each model call. The fake renders that
in the CLI's own event format, runs the tool calls for real in its working directory, and
records what it was given (argv, environment, working directory, every message).

How it runs: tests/test_external.py writes a wrapper per CLI (bin/claude, bin/codex): a small
Python script that sets FAKE_AGENT_SCRIPT (the behaviour, JSON), FAKE_AGENT_RECORD (a JSONL
file this appends to) and FAKE_AGENT_STATE (its state across processes), then execs
`python -I fake_agent_cli.py <claude|codex> <the CLI's own arguments>`.

What it models. From the docs (code.claude.com headless and cli-reference; the Codex
non-interactive docs and codex-rs/exec), with what is ASSUMED (not checked against a real
run) marked:

Claude Code: `claude -p --input-format stream-json --output-format stream-json --verbose ...`
- Options it does not know are refused (exit 1); stream-json output in print mode needs
  --verbose; stream-json input needs stream-json output.
- stdin: one JSON user message per line, {"type":"user","message":{"role":"user","content":
  ...},"parent_tool_use_id":null} (ASSUMED: the docs show the SDK's message type, not a raw
  line). A line that is not one: exit 1.
- stdout: system/init first (session_id, model, tools, cwd, permissionMode, apiKeySource);
  for each model call one `assistant` event per content block (text or tool_use), each with
  the message's id and usage (ASSUMED: the same usage on each); one `user` event per
  tool_result; at the end of the turn a `result` event: subtype, is_error, num_turns,
  result, session_id, total_cost_usd (ASSUMED: counted from the start of the process), usage.
- Tools: --tools lists what exists (others: "No such tool available"). With
  --permission-prompts none, what would ask for permission is refused (ASSUMED: its exact
  meaning), so a Bash command runs only when allowed (--allowedTools Bash, or
  bypassPermissions), and an edit needs acceptEdits or an allow rule. A command runs in the
  working directory with the CLI's own environment.
- SIGINT during a turn ends the turn: a result event (subtype error_during_execution), then it
  waits for the next message (ASSUMED). SIGINT while it waits does nothing (ASSUMED). stdin
  closed: it exits 0 (ASSUMED). SIGTERM: it exits (status 143).
- Its own configuration (user settings: hooks, env such as ANTHROPIC_BASE_URL) is
  settings.json in $CLAUDE_CONFIG_DIR, else in $HOME/.claude (ASSUMED: CLAUDE_CONFIG_DIR as
  the docs list it). The fake records the folder and that file's text at start.

Codex: `codex exec --json ...`
- Reads its prompt from stdin to the end: an open stdin hangs it. Options go before
  `resume`; the removed --full-auto and unknown options are refused (exit 2).
- stdout: thread.started {thread_id}, turn.started, item.started / item.completed per item
  ({id: "item_N", type, ...}: command_execution {command, the shell wrapper `bash -lc '...'`
  included; aggregated_output; exit_code, null while it runs; status}, agent_message {text},
  reasoning {text}, file_change {changes [{path, kind add|delete|update}], status},
  todo_list {items [{text, completed}]}, error {message}), then turn.completed {usage
  {input_tokens, cached_input_tokens, output_tokens}} (ASSUMED: counted over the whole
  thread, resumed turns included; cached tokens are part of input_tokens), or turn.failed
  {error {message}} and exit 1. A top-level error {message} does not end the turn.
- `resume <thread_id>` continues a thread; an unknown thread: exit 1.
- -c shell_environment_policy.inherit=core: commands get only the core variables.
- SIGINT: exit 1 at once, with no turn event.
- Its own configuration is config.toml in $CODEX_HOME, else in $HOME/.codex (codex's docs);
  a CODEX_HOME that is not an existing folder: exit 1 (ASSUMED: codex resolves the path it
  names). The fake records the folder and that file's text at start.

Script (JSON): {"turns": [TURN, ...]}, one TURN per claude user message or per codex
process, in order across processes. When the turns run out, the fake answers nothing more
(claude reads on; codex waits until it is signalled).
- claude TURN: {"calls": [CALL, ...], "cost": dollars for the turn (null: no total_cost_usd),
  "result": text, "subtype": "success", "is_error": false}. CALL: {"think": seconds,
  "raw": [lines], "stderr": line, "spawn": [{"cmd": [...], "session": bool}], "exit": status,
  "ignore": ["INT", "TERM"] (from then on those signals are ignored: a hung CLI),
  "text": text, "tools": [{"bash": cmd} | {"read": path} | {"write": [path, text]} |
  {"tool": name, "input": {...}}], "usage": [input, output, cache_read, cache_creation]}.
- codex TURN: {"items": [ITEM, ...], "usage": [input, cached, output] added to the thread,
  "fail": message}. ITEM: {"command": cmd} | {"message": text} | {"reasoning": text} |
  {"file": [path, text]} | {"todo": [[text, done], ...]} | {"warning": text} (an error item)
  | {"error": text} (a top-level error event) | {"raw": line} | {"stderr": line} |
  {"sleep": seconds} | {"spawn": [...]} | {"exit": status}.
"""

from __future__ import annotations

import fcntl
import json
import os
import shlex
import signal
import subprocess
import sys
import time
import uuid

CLAUDE_VALUES = {
    "--input-format", "--output-format", "--model", "--append-system-prompt", "--system-prompt", "--tools",
    "--allowedTools", "--allowed-tools", "--disallowedTools", "--disallowed-tools", "--permission-mode",
    "--permission-prompts", "--max-turns", "--resume", "-r", "--session-id", "--max-budget-usd", "--add-dir",
    "--mcp-config", "--settings", "--setting-sources", "--fallback-model",
}
CLAUDE_FLAGS = {
    "-p", "--print", "--verbose", "--bare", "--no-session-persistence", "--include-partial-messages",
    "--strict-mcp-config", "--replay-user-messages", "--continue", "--dangerously-skip-permissions",
}
PERMISSION_MODES = {"default", "acceptEdits", "plan", "auto", "dontAsk", "bypassPermissions"}
CODEX_VALUES = {"--sandbox", "-s", "--cd", "-C", "--model", "-m", "-c", "--config", "--color", "--output-last-message", "-o", "--profile", "-p", "--image", "-i"}
CODEX_FLAGS = {"--json", "--skip-git-repo-check", "--ephemeral", "--oss", "--dangerously-bypass-approvals-and-sandbox"}
SANDBOXES = {"read-only", "workspace-write", "danger-full-access"}
CORE_ENV = ("HOME", "LOGNAME", "PATH", "SHELL", "USER", "USERNAME", "TMPDIR", "TEMP", "TMP")


class Interrupt(Exception):
    """SIGINT during a claude turn."""


def record(kind: str, **data: object) -> None:
    path = os.environ.get("FAKE_AGENT_RECORD")
    if not path:
        return
    line = json.dumps({"rec": kind, "pid": os.getpid(), **data}) + "\n"
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
    try:
        os.write(fd, line.encode())
    finally:
        os.close(fd)


def emit(event: dict) -> None:
    sys.stdout.write(json.dumps(event) + "\n")
    sys.stdout.flush()


def fail(message: str, status: int) -> None:
    sys.stderr.write(message + "\n")
    sys.stderr.flush()
    record("exit", code=status, why=message)
    sys.exit(status)


def script() -> dict:
    with open(os.environ["FAKE_AGENT_SCRIPT"], encoding="utf-8") as f:
        return json.load(f)


def update_state(change):
    """Change the state shared by every process of a test, under a lock; returns what `change` returns."""
    with open(os.environ["FAKE_AGENT_STATE"], "a+", encoding="utf-8") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.seek(0)
        raw = f.read()
        state = json.loads(raw) if raw.strip() else {"turn": 0, "threads": {}}
        result = change(state)
        f.seek(0)
        f.truncate()
        f.write(json.dumps(state))
    return result


def next_turn() -> dict | None:
    def take(state: dict) -> int:
        state["turn"] += 1
        return state["turn"] - 1

    index = update_state(take)
    turns = script().get("turns", [])
    return turns[index] if index < len(turns) else None


def directives(step: dict) -> None:
    """What a call or an item does besides its events: think, write raw lines, die, start children,
    stop answering signals (a hung CLI)."""
    for name in step.get("ignore", []):
        signal.signal(getattr(signal, f"SIG{name}"), signal.SIG_IGN)
        record("ignoring", sig=f"SIG{name}")
    if step.get("think") or step.get("sleep"):
        time.sleep(float(step.get("think") or step.get("sleep")))
    for line in step.get("raw", []) if isinstance(step.get("raw"), list) else ([step["raw"]] if "raw" in step else []):
        sys.stdout.write(line + "\n")
        sys.stdout.flush()
    if "stderr" in step:
        sys.stderr.write(step["stderr"] + "\n")
        sys.stderr.flush()
    for child in step.get("spawn", []):
        proc = subprocess.Popen(
            child["cmd"], start_new_session=bool(child.get("session")),
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        record("spawned", child=proc.pid, session=bool(child.get("session")))
    if "exit" in step:
        record("exit", code=step["exit"])
        sys.stdout.flush()
        os._exit(int(step["exit"]))


def wait_forever() -> None:
    while True:
        time.sleep(3600)


def own_config(variable: str, default: str, name: str) -> tuple[str, str | None]:
    """(the folder a CLI reads its own configuration from: $variable, else $HOME/default;
    the text of the file `name` there, None if there is none)."""
    folder = os.environ.get(variable) or os.path.join(os.environ.get("HOME", ""), default)
    try:
        with open(os.path.join(folder, name), encoding="utf-8") as f:
            return folder, f.read()
    except OSError:
        return folder, None


# ---------------------------------------------------------------------- claude


class ClaudeOptions:
    def __init__(self, args: list[str]) -> None:
        self.values: dict[str, list[str]] = {}
        self.flags: set[str] = set()
        i = 0
        while i < len(args):
            arg = args[i]
            name, _, inline = arg.partition("=") if arg.startswith("--") else (arg, "", "")
            if name in CLAUDE_VALUES:
                if inline:
                    value = inline
                elif i + 1 < len(args):
                    i += 1
                    value = args[i]
                else:
                    fail(f"error: option '{name}' argument missing", 1)
                self.values.setdefault(name, []).append(value)
            elif arg in CLAUDE_FLAGS:
                self.flags.add(arg)
            else:
                fail(f"error: unknown option '{arg}'", 1)
            i += 1

    def one(self, name: str, default: str = "") -> str:
        return self.values.get(name, [default])[-1]

    def listed(self, *names: str) -> set[str]:
        out: set[str] = set()
        for name in names:
            for value in self.values.get(name, []):
                out |= {part.strip() for part in value.replace(" ", ",").split(",") if part.strip()}
        return out


def claude(args: list[str]) -> None:
    opts = ClaudeOptions(args)
    printing = "-p" in opts.flags or "--print" in opts.flags
    out_format = opts.one("--output-format", "text")
    in_format = opts.one("--input-format", "text")
    if out_format not in ("text", "json", "stream-json") or in_format not in ("text", "stream-json"):
        fail("error: unknown input or output format", 1)
    if printing and out_format == "stream-json" and "--verbose" not in opts.flags:
        fail("Error: When using --print, --output-format=stream-json requires --verbose", 1)
    if in_format == "stream-json" and out_format != "stream-json":
        fail("Error: --input-format=stream-json requires output-format=stream-json.", 1)
    mode = opts.one("--permission-mode", "default")
    if mode not in PERMISSION_MODES:
        fail(f"error: option '--permission-mode <mode>' argument '{mode}' is invalid", 1)
    if not printing or in_format != "stream-json":
        fail("fake claude: this fake only plays print mode with stream-json input", 1)
    tools = opts.listed("--tools") if "--tools" in opts.values else {"Bash", "Read", "Edit", "Write", "Glob", "Grep", "WebFetch", "WebSearch", "Task"}
    allowed = opts.listed("--allowedTools", "--allowed-tools")
    model = opts.one("--model", "claude-default")
    config_dir, settings = own_config("CLAUDE_CONFIG_DIR", ".claude", "settings.json")
    record("start", cli="claude", argv=args, cwd=os.getcwd(), env=dict(os.environ), pgid=os.getpgrp(),
           files=sorted(os.listdir(".")), config_dir=config_dir, settings=settings)
    session = str(uuid.uuid4())
    state = {"in_turn": False, "cost": 0.0, "init": False}

    def on_sigint(signum, frame):
        record("signal", sig="SIGINT", in_turn=state["in_turn"])
        if state["in_turn"]:
            raise Interrupt()

    signal.signal(signal.SIGINT, on_sigint)
    while True:
        line = sys.stdin.readline()
        if not line:
            record("exit", code=0, why="stdin closed")
            sys.exit(0)
        record("stdin", line=line.rstrip("\n"))
        try:
            message = json.loads(line)
        except ValueError:
            fail("Error: invalid stream-json input: not JSON", 1)
        body = message.get("message") if isinstance(message, dict) else None
        if not (
            message.get("type") == "user" and isinstance(body, dict) and body.get("role") == "user"
            and isinstance(body.get("content"), (str, list))
        ):
            fail("Error: invalid stream-json input: expected a user message", 1)
        if not state["init"]:
            state["init"] = True
            emit({
                "type": "system", "subtype": "init", "cwd": os.getcwd(), "session_id": session,
                "tools": sorted(tools), "mcp_servers": [], "model": model, "permissionMode": mode,
                "slash_commands": [], "apiKeySource": "ANTHROPIC_API_KEY" if os.environ.get("ANTHROPIC_API_KEY") else "none",
                "claude_code_version": "2.1.300", "output_style": "default", "uuid": str(uuid.uuid4()),
            })
        turn = next_turn()
        if turn is None:
            continue  # nothing scripted: no answer
        claude_turn(turn, state, session, model, tools, allowed, mode)


def claude_turn(turn: dict, state: dict, session: str, model: str, tools: set[str], allowed: set[str], mode: str) -> None:
    state["in_turn"] = True
    calls = 0
    said = ""
    total = {"input_tokens": 0, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0, "output_tokens": 0}
    try:
        try:
            for call in turn.get("calls", []):
                directives(call)
                fresh, out, read, created = (list(call.get("usage", [0, 0, 0, 0])) + [0, 0, 0, 0])[:4]
                usage = {"input_tokens": fresh, "cache_creation_input_tokens": created, "cache_read_input_tokens": read, "output_tokens": out}
                for key, value in usage.items():
                    total[key] += value
                mid = "msg_" + uuid.uuid4().hex[:24]
                blocks: list[dict] = []
                if call.get("text"):
                    said = call["text"]
                    blocks.append({"type": "text", "text": call["text"]})
                uses = [tool_use(spec) for spec in call.get("tools", [])]
                for block in blocks + uses:
                    emit({
                        "type": "assistant",
                        "message": {"id": mid, "type": "message", "role": "assistant", "model": model, "content": [block],
                                    "stop_reason": None, "stop_sequence": None, "usage": usage},
                        "parent_tool_use_id": None, "session_id": session, "uuid": str(uuid.uuid4()),
                    })
                calls += 1
                for use in uses:
                    text, error = run_claude_tool(use, tools, allowed, mode)
                    emit({
                        "type": "user",
                        "message": {"role": "user", "content": [{"tool_use_id": use["id"], "type": "tool_result", "content": text, "is_error": error}]},
                        "parent_tool_use_id": None, "session_id": session, "uuid": str(uuid.uuid4()),
                    })
            cost = turn.get("cost", 0.0)
            event = {
                "type": "result", "subtype": turn.get("subtype", "success"), "is_error": bool(turn.get("is_error", False)),
                "duration_ms": 1000, "duration_api_ms": 800, "num_turns": calls, "result": turn.get("result", said),
                "session_id": session, "usage": total, "permission_denials": [], "uuid": str(uuid.uuid4()),
            }
            if cost is not None:
                state["cost"] += cost
                event["total_cost_usd"] = round(state["cost"], 6)
            emit(event)
        except Interrupt:
            emit({
                "type": "result", "subtype": "error_during_execution", "is_error": True, "duration_ms": 1000,
                "duration_api_ms": 800, "num_turns": calls, "result": "[Request interrupted by user]",
                "session_id": session, "total_cost_usd": round(state["cost"], 6), "usage": total,
                "permission_denials": [], "uuid": str(uuid.uuid4()),
            })
    finally:
        state["in_turn"] = False


def tool_use(spec: dict) -> dict:
    use_id = "toolu_" + uuid.uuid4().hex[:24]
    if "bash" in spec:
        return {"type": "tool_use", "id": use_id, "name": "Bash", "input": {"command": spec["bash"], "description": "run a command"}}
    if "read" in spec:
        return {"type": "tool_use", "id": use_id, "name": "Read", "input": {"file_path": os.path.abspath(spec["read"])}}
    if "write" in spec:
        path, text = spec["write"]
        return {"type": "tool_use", "id": use_id, "name": "Write", "input": {"file_path": os.path.abspath(path), "content": text}}
    return {"type": "tool_use", "id": use_id, "name": spec["tool"], "input": spec.get("input", {})}


def run_claude_tool(use: dict, tools: set[str], allowed: set[str], mode: str) -> tuple[str, bool]:
    name, args = use["name"], use["input"]
    if name not in tools:
        return f"Error: No such tool available: {name}", True
    if name == "Bash":
        if name not in allowed and mode != "bypassPermissions":
            return "Permission to use Bash has been denied.", True
        done = subprocess.run(
            ["bash", "-c", args["command"]], cwd=os.getcwd(), env=os.environ, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120, check=False,
        )
        text = done.stdout.decode("utf-8", "replace")
        if done.returncode != 0:
            return f"Error: Exit code {done.returncode}\n{text}", True
        return text, False
    if name == "Read":
        try:
            with open(args["file_path"], encoding="utf-8", errors="replace") as f:
                lines = f.read().splitlines()
        except OSError as exc:
            return f"Error: {exc.strerror}: {args['file_path']}", True
        return "\n".join(f"{n:>6}\t{line}" for n, line in enumerate(lines, 1)), False
    if name in ("Write", "Edit"):
        if mode not in ("acceptEdits", "bypassPermissions") and name not in allowed:
            return f"Permission to use {name} has been denied.", True
        path = args["file_path"]
        if not os.path.abspath(path).startswith(os.getcwd() + os.sep) and mode != "bypassPermissions":
            return f"Permission to use {name} has been denied.", True
        with open(path, "w", encoding="utf-8") as f:
            f.write(args.get("content", ""))
        return f"File created successfully at: {path}", False
    return "ok", False


# ---------------------------------------------------------------------- codex


class CodexOptions:
    def __init__(self, args: list[str]) -> None:
        if not args or args[0] != "exec":
            fail("fake codex: this fake only plays `codex exec`", 2)
        self.values: dict[str, list[str]] = {}
        self.flags: set[str] = set()
        self.resume: str | None = None
        self.prompt: str | None = None
        rest = args[1:]
        i = 0
        resumed = False
        while i < len(rest):
            arg = rest[i]
            if arg == "--full-auto":
                fail("error: unexpected argument '--full-auto' found", 2)
            if arg == "resume" and not resumed and self.prompt is None:
                resumed = True
                if i + 1 >= len(rest) or rest[i + 1].startswith("-"):
                    fail("error: resume needs a session id here", 2)
                self.resume = rest[i + 1]
                i += 2
                continue
            if resumed and arg not in ("--json", "-m", "--model") and arg.startswith("-"):
                fail(f"error: unexpected argument '{arg}' found (options go before `resume`)", 2)
            if arg in CODEX_VALUES:
                if i + 1 >= len(rest):
                    fail(f"error: a value is required for '{arg}'", 2)
                self.values.setdefault(arg, []).append(rest[i + 1])
                i += 2
                continue
            if arg in CODEX_FLAGS:
                self.flags.add(arg)
            elif arg.startswith("-"):
                fail(f"error: unexpected argument '{arg}' found", 2)
            elif self.prompt is None:
                self.prompt = arg
            else:
                fail(f"error: unexpected argument '{arg}' found", 2)
            i += 1
        sandbox = self.one("--sandbox", "-s") or "read-only"
        if sandbox not in SANDBOXES:
            fail(f"error: invalid value '{sandbox}' for '--sandbox <SANDBOX_MODE>'", 2)
        self.sandbox = sandbox

    def one(self, *names: str) -> str | None:
        for name in names:
            if name in self.values:
                return self.values[name][-1]
        return None

    def configs(self) -> dict[str, str]:
        out = {}
        for item in self.values.get("-c", []) + self.values.get("--config", []):
            key, _, value = item.partition("=")
            out[key] = value
        return out


def codex(args: list[str]) -> None:
    opts = CodexOptions(args)
    named = os.environ.get("CODEX_HOME")
    if named and not os.path.isdir(named):
        fail(f"Error: CODEX_HOME points to {named!r}, but that path does not exist", 1)
    codex_home, config = own_config("CODEX_HOME", ".codex", "config.toml")
    record("start", cli="codex", argv=args, cwd=os.getcwd(), env=dict(os.environ), pgid=os.getpgrp(),
           codex_home=codex_home, config=config)

    def on_sigint(signum, frame):
        record("signal", sig="SIGINT")
        sys.stderr.write("interrupted\n")
        sys.stderr.flush()
        os._exit(1)

    signal.signal(signal.SIGINT, on_sigint)
    prompt = opts.prompt if opts.prompt not in (None, "-") else sys.stdin.read()
    record("prompt", text=prompt)
    workdir = opts.one("--cd", "-C")
    if workdir:
        os.chdir(workdir)
    record("files", files=sorted(os.listdir(".")))
    if "--json" not in opts.flags:
        print("codex (human output): this fake writes JSON events only with --json")
    if opts.resume is not None:
        thread = opts.resume
        if not update_state(lambda state: thread in state["threads"]):
            fail(f"Error: no rollout found for thread id {thread}", 1)
    else:
        thread = str(uuid.uuid4())
        update_state(lambda state: state["threads"].setdefault(thread, [0, 0, 0]))
    emit({"type": "thread.started", "thread_id": thread})
    turn = next_turn()
    if turn is None:
        wait_forever()
    emit({"type": "turn.started"})
    env = dict(os.environ)
    if opts.configs().get("shell_environment_policy.inherit") == "core":
        env = {name: value for name, value in env.items() if name in CORE_ENV}
    for number, item in enumerate(turn.get("items", [])):
        codex_item(item, f"item_{number}", env)
    if turn.get("fail"):
        emit({"type": "turn.failed", "error": {"message": turn["fail"]}})
        record("exit", code=1)
        sys.exit(1)
    grow = (list(turn.get("usage", [0, 0, 0])) + [0, 0, 0])[:3]

    def add(state: dict) -> list[int]:
        total = [a + b for a, b in zip(state["threads"][thread], grow)]
        state["threads"][thread] = total
        return total

    total = update_state(add)
    emit({"type": "turn.completed", "usage": {"input_tokens": total[0], "cached_input_tokens": total[1], "output_tokens": total[2]}})
    record("exit", code=0)
    sys.exit(0)


def codex_item(item: dict, item_id: str, env: dict[str, str]) -> None:
    directives(item)
    if "command" in item:
        shown = f"bash -lc {shlex.quote(item['command'])}"
        base = {"id": item_id, "type": "command_execution", "command": shown}
        emit({"type": "item.started", "item": {**base, "aggregated_output": "", "exit_code": None, "status": "in_progress"}})
        done = subprocess.run(
            ["bash", "-c", item["command"]], cwd=os.getcwd(), env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120, check=False,
        )
        status = "completed" if done.returncode == 0 else "failed"
        emit({"type": "item.completed", "item": {**base, "aggregated_output": done.stdout.decode("utf-8", "replace"),
                                                 "exit_code": done.returncode, "status": status}})
    elif "message" in item:
        emit({"type": "item.completed", "item": {"id": item_id, "type": "agent_message", "text": item["message"]}})
    elif "reasoning" in item:
        emit({"type": "item.completed", "item": {"id": item_id, "type": "reasoning", "text": item["reasoning"]}})
    elif "file" in item:
        path, text = item["file"]
        full = os.path.abspath(path)
        kind = "update" if os.path.exists(full) else "add"
        with open(full, "w", encoding="utf-8") as f:
            f.write(text)
        emit({"type": "item.completed", "item": {"id": item_id, "type": "file_change", "changes": [{"path": full, "kind": kind}], "status": "completed"}})
    elif "todo" in item:
        items = [{"text": text, "completed": bool(done)} for text, done in item["todo"]]
        emit({"type": "item.started", "item": {"id": item_id, "type": "todo_list", "items": items}})
    elif "warning" in item:
        emit({"type": "item.completed", "item": {"id": item_id, "type": "error", "message": item["warning"]}})
    elif "error" in item:
        emit({"type": "error", "message": item["error"]})


def main() -> None:
    cli, args = sys.argv[1], sys.argv[2:]
    if cli == "claude":
        claude(args)
    elif cli == "codex":
        codex(args)
    else:
        fail(f"fake agent: unknown CLI {cli!r}", 2)


if __name__ == "__main__":
    main()
