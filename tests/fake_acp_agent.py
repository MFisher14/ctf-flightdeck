"""A fake ACP agent for the ACP lane tests (agent/acp.py). Never a real agent: no real agent
or adapter has been run against flightdeck, and a real run spends the player's money.

It plays an agent that speaks the Agent Client Protocol, version 1, from the protocol's
schema (schema/v1/schema.json of agentclientprotocol/agent-client-protocol, read on
2026-11-16) and its docs (agentclientprotocol.com: overview, initialization, prompt turn,
tool calls, file system). Everything it does is ASSUMED from those: no real agent was
compared with it. In particular, ASSUMED:
- one JSON-RPC 2.0 message per line on stdin and stdout, no Content-Length framing;
- `initialize` comes first and is answered with the agent's protocol version (the client's
  if it speaks it), agentCapabilities and agentInfo; anything before it is refused;
- `session/new` takes cwd (absolute) and mcpServers (a list), and a systemPrompt only when
  the agent advertised sessionCapabilities.systemPrompt (else it is refused: the spec's
  "Clients MUST only send this when ..."); an agent that needs a login refuses it with code
  -32000 until `authenticate`;
- `session/prompt` with text blocks runs a turn: session/update notifications
  (agent_message_chunk, tool_call, tool_call_update, plan, usage_update), then the answer
  {stopReason}. A tool call that needs permission is announced pending, then
  session/request_permission is sent with allow_once / allow_always / reject_once options;
  a selected allow runs it (a command: for real, in its working directory), anything else
  fails it;
- `session/cancel` (a notification) ends the turn being run: the turn answers stopReason
  "cancelled", and a tool call not yet run is not run;
- fs/read_text_file and fs/write_text_file are asked of the client only when it advertised
  them, with absolute paths;
- stdin closed: it exits 0. SIGTERM: it exits.

A test writes the agent's behaviour as a script (JSON, FAKE_ACP_SCRIPT):
  {"version": 1, "system_prompt": true, "auth": false, "info": {...},
   "turns": [[step, ...], ...]}
A step is one of
  {"say": text, "chunks": n, "id": message id}  agent_message_chunk(s), the text cut in n pieces
  {"run": command, "ask": true}                 an execute tool call (rawInput.command)
  {"tool": {kind, title, paths, ask, write: {path: text}}}  another tool call; with write, the
                                                agent writes those files itself once allowed
  {"read": path} / {"write": [path, text]}      fs/read_text_file or fs/write_text_file of the client
  {"plan": [entry, ...]}                        a plan (the first is in_progress, the rest pending)
  {"cost": amount, "currency": "USD"}           a usage_update with the session's cost so far
  {"think": seconds} / {"until": path}          wait (a session/cancel ends the turn here)
  {"stop": reason}                              the turn's stopReason (default end_turn)
  {"fail": message}                             the prompt is answered with a JSON-RPC error
  {"exit": status}                              exit now
Turns past the script end at once with end_turn and say nothing.

It records (FAKE_ACP_RECORD, JSONL) its start (argv, env, cwd), every message it was sent,
and the answers to its own requests.
"""

from __future__ import annotations

import json
import os
import queue
import signal
import subprocess
import sys
import threading
import time

SCRIPT = json.loads(open(os.environ["FAKE_ACP_SCRIPT"]).read())
RECORD = os.environ["FAKE_ACP_RECORD"]
_lock = threading.Lock()
_out = threading.Lock()
inbox: queue.Queue = queue.Queue()
answers: dict[int, queue.Queue] = {}
state = {"cancelled": False, "session": None, "client": {}, "next": 1000, "turn": 0}


def record(kind: str, **data) -> None:
    with _lock, open(RECORD, "a") as f:
        f.write(json.dumps({"rec": kind, "pid": os.getpid(), **data}) + "\n")


def send(message: dict) -> None:
    with _out:
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", **message}) + "\n")
        sys.stdout.flush()


def update(body: dict) -> None:
    send({"method": "session/update", "params": {"sessionId": state["session"], "update": body}})


def ask(method: str, params: dict) -> dict:
    """A request of the client's, and its answer (result or error)."""
    state["next"] += 1
    ident = state["next"]
    box: queue.Queue = queue.Queue()
    answers[ident] = box
    send({"id": ident, "method": method, "params": params})
    answer = box.get()
    record("answer", method=method, answer=answer)
    return answer


def reader() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        message = json.loads(line)
        record("recv", message=message)
        if "method" not in message and message.get("id") in answers:
            answers.pop(message["id"]).put(message)
        elif message.get("method") == "session/cancel":
            state["cancelled"] = True
        else:
            inbox.put(message)
    inbox.put(None)


def wait(seconds: float | None = None, path: str | None = None) -> bool:
    """Wait; False when a session/cancel came first."""
    end = time.monotonic() + (seconds or 0)
    while not state["cancelled"]:
        if path is not None and os.path.exists(path):
            return True
        if path is None and time.monotonic() >= end:
            return True
        time.sleep(0.02)
    return False


def permitted(call: dict) -> bool:
    answer = ask("session/request_permission", {"sessionId": state["session"], "toolCall": call, "options": [
        {"optionId": "yes", "name": "Allow", "kind": "allow_once"},
        {"optionId": "always", "name": "Always allow", "kind": "allow_always"},
        {"optionId": "no", "name": "Reject", "kind": "reject_once"},
    ]})
    outcome = (answer.get("result") or {}).get("outcome") or {}
    return outcome.get("outcome") == "selected" and outcome.get("optionId") in ("yes", "always")


def tool_call(ident: str, kind: str, title: str, *, raw: dict | None = None, paths=(), ask_first=True, act=None) -> None:
    locations = [{"path": p if p.startswith("/") else os.path.join(os.getcwd(), p)} for p in paths]
    call = {"toolCallId": ident, "title": title, "kind": kind, "status": "pending", "locations": locations,
            "rawInput": raw or {}}
    update({"sessionUpdate": "tool_call", **call})
    if ask_first and not permitted({"toolCallId": ident, "title": title, "kind": kind, "locations": locations}):
        update({"sessionUpdate": "tool_call_update", "toolCallId": ident, "status": "failed",
                "content": [{"type": "content", "content": {"type": "text", "text": "refused by the client"}}]})
        return
    if state["cancelled"]:
        return
    update({"sessionUpdate": "tool_call_update", "toolCallId": ident, "status": "in_progress"})
    text = act() if act is not None else ""
    update({"sessionUpdate": "tool_call_update", "toolCallId": ident, "status": "completed",
            "content": [{"type": "content", "content": {"type": "text", "text": text}}]})


def run_command(command: str) -> str:
    done = subprocess.run(["bash", "-c", command], capture_output=True, text=True, timeout=30)
    return done.stdout + done.stderr


def play_turn(steps: list) -> dict:
    """One prompt turn: the result of session/prompt (or an error)."""
    stop = "end_turn"
    for n, step in enumerate(steps):
        if state["cancelled"]:
            return {"result": {"stopReason": "cancelled"}}
        ident = f"call-{state['turn']}-{n}"
        if "say" in step:
            text, pieces = step["say"], max(int(step.get("chunks", 1)), 1)
            size = -(-len(text) // pieces) or 1
            for i in range(0, len(text), size):
                body = {"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": text[i:i + size]}}
                if "id" in step:
                    body["messageId"] = step["id"]
                update(body)
        elif "run" in step:
            command = step["run"]
            tool_call(ident, "execute", f"Run {command}", raw={"command": command}, ask_first=step.get("ask", True),
                      act=lambda: run_command(command))
        elif "tool" in step:
            spec = step["tool"]

            def act(spec=spec):
                for path, text in (spec.get("write") or {}).items():
                    with open(path, "w") as f:
                        f.write(text)
                return "done"

            tool_call(ident, spec.get("kind", "other"), spec.get("title", "a tool"), paths=spec.get("paths", ()),
                      ask_first=spec.get("ask", True), act=act)
        elif "read" in step:
            ask("fs/read_text_file", {"sessionId": state["session"], "path": step["read"], **step.get("params", {})})
        elif "write" in step:
            path, text = step["write"]
            ask("fs/write_text_file", {"sessionId": state["session"], "path": path, "content": text})
        elif "plan" in step:
            update({"sessionUpdate": "plan", "entries": [
                {"content": entry, "priority": "medium", "status": "in_progress" if i == 0 else "pending"}
                for i, entry in enumerate(step["plan"])]})
        elif "cost" in step:
            update({"sessionUpdate": "usage_update", "used": 1000, "size": 200000,
                    "cost": {"amount": step["cost"], "currency": step.get("currency", "USD")}})
        elif "think" in step:
            if not wait(seconds=step["think"]):
                return {"result": {"stopReason": "cancelled"}}
        elif "until" in step:
            if not wait(path=step["until"]):
                return {"result": {"stopReason": "cancelled"}}
        elif "stop" in step:
            stop = step["stop"]
        elif "fail" in step:
            return {"error": {"code": -32603, "message": step["fail"]}}
        elif "exit" in step:
            sys.stdout.flush()
            os._exit(step["exit"])
    if state["cancelled"]:
        return {"result": {"stopReason": "cancelled"}}
    return {"result": {"stopReason": stop}}


def handle(message: dict) -> None:
    method, ident, params = message.get("method"), message.get("id"), message.get("params") or {}
    if method != "initialize" and not state["client"]:
        send({"id": ident, "error": {"code": -32600, "message": "initialize first"}})
        return
    if method == "initialize":
        assert isinstance(params.get("protocolVersion"), int)
        state["client"] = params.get("clientCapabilities") or {"none": True}
        caps = {"loadSession": False, "promptCapabilities": {"image": False, "audio": False, "embeddedContext": False},
                "sessionCapabilities": {"systemPrompt": {}} if SCRIPT.get("system_prompt", True) else {}}
        send({"id": ident, "result": {"protocolVersion": SCRIPT.get("version", 1), "agentCapabilities": caps,
                                      "authMethods": [{"id": "login", "name": "Log in"}] if SCRIPT.get("auth") else [],
                                      "agentInfo": SCRIPT.get("info", {"name": "fake-acp", "version": "0.0.1"})}})
    elif method == "session/new":
        if SCRIPT.get("auth"):
            send({"id": ident, "error": {"code": -32000, "message": "Authentication required"}})
            return
        if not (isinstance(params.get("cwd"), str) and params["cwd"].startswith("/") and isinstance(params.get("mcpServers"), list)):
            send({"id": ident, "error": {"code": -32602, "message": "cwd and mcpServers are required"}})
            return
        if "systemPrompt" in params and not SCRIPT.get("system_prompt", True):
            send({"id": ident, "error": {"code": -32602, "message": "systemPrompt is not supported"}})
            return
        state["session"] = "sess-1"
        send({"id": ident, "result": {"sessionId": "sess-1"}})
    elif method == "session/prompt":
        if params.get("sessionId") != state["session"]:
            send({"id": ident, "error": {"code": -32602, "message": "no such session"}})
            return
        state["cancelled"] = False
        turns = SCRIPT.get("turns", [])
        steps = turns[state["turn"]] if state["turn"] < len(turns) else []
        result = play_turn(steps)
        state["turn"] += 1
        send({"id": ident, **result})
    else:
        send({"id": ident, "error": {"code": -32601, "message": f"unknown method {method}"}})


def main() -> None:
    record("start", argv=sys.argv[1:], env=dict(os.environ), cwd=os.getcwd())
    signal.signal(signal.SIGTERM, lambda *_: os._exit(143))
    threading.Thread(target=reader, daemon=True).start()
    while (message := inbox.get()) is not None:
        if "id" in message and "method" in message:
            handle(message)
    os._exit(0)


if __name__ == "__main__":
    main()
