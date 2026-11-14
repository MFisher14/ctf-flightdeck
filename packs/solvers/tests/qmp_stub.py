"""A stub QEMU Machine Protocol endpoint for the B-131 boot-harness tests. No QEMU, no VM, no image.

It speaks QMP as QEMU does: a greeting, then newline-delimited JSON; every command before
`qmp_capabilities` is refused (CommandNotFound), as in QEMU's negotiation mode; a reply echoes the
command's id. `screendump` writes the next synthetic frame (a PPM the test built) to the file name
the command gives. Every message received is recorded.

    with StubQMP(frames=[ppm1, ppm2], transport="unix") as stub:     # or "tcp" (127.0.0.1)
        stub.spec            # "unix:/.../q.sock" | "tcp:127.0.0.1:<port>": what diskboot.QMP.connect takes
        stub.commands        # [{"execute": ..., "arguments": ...}, ...] in arrival order

As a command (`python -I tests/qmp_stub.py --stdio STATE.json`) it serves one session on stdin and
stdout, for the command transport (the plan's `docker exec -i ... socat`). STATE.json holds
{"frames": [paths of PPM files], "log": path of a JSON-lines file, "errors": {...}, "mute": [...]}.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import socketserver
import sys
import tempfile
import threading

GREETING = {"QMP": {"version": {"qemu": {"major": 9, "minor": 2, "micro": 0}, "package": "stub"},
                    "capabilities": ["oob"]}}


def ppm(width: int, height: int, pixel_at) -> bytes:
    """A binary PPM whose pixel (x, y) is pixel_at(x, y) -> (r, g, b)."""
    body = bytearray()
    for y in range(height):
        for x in range(width):
            body += bytes(pixel_at(x, y))
    return b"P6\n%d %d\n255\n" % (width, height) + bytes(body)


class Protocol:
    """One QMP session: feed it lines, it writes replies. Shared by the socket and stdio forms."""

    def __init__(self, write, record, frames, *, errors=None, mute=(), events=(), greeting=True):
        self.write, self.record = write, record
        self.frames = list(frames)
        self.errors = dict(errors or {})
        self.mute = set(mute)
        self.events = list(events)
        self.negotiated = False
        self.shots = 0
        if greeting:
            self.send(GREETING)

    def send(self, obj) -> None:
        self.write(json.dumps(obj).encode() + b"\n")

    def handle(self, line: bytes) -> bool:
        """Answer one message; False when the session is over."""
        msg = json.loads(line)
        self.record(msg)
        cmd, ident = msg.get("execute"), msg.get("id")

        def reply(body):
            if ident is not None:
                body = {**body, "id": ident}
            self.send(body)

        if cmd in self.mute:
            return True
        if not self.negotiated:
            if cmd == "qmp_capabilities":
                self.negotiated = True
                reply({"return": {}})
            else:
                reply({"error": {"class": "CommandNotFound",
                                 "desc": f"Expecting capabilities negotiation with 'qmp_capabilities', got {cmd}"}})
            return True
        if cmd in self.errors:
            reply({"error": self.errors[cmd]})
            return True
        if cmd == "screendump":
            for ev in self.events:
                self.send(ev)
            self.events = []
            if not self.frames:
                reply({"error": {"class": "GenericError", "desc": "no display"}})
                return True
            data = self.frames[min(self.shots, len(self.frames) - 1)]
            self.shots += 1
            name = msg["arguments"]["filename"]
            os.makedirs(os.path.dirname(name), exist_ok=True)
            with open(name, "wb") as fh:
                fh.write(data)
            reply({"return": {}})
            return True
        if cmd == "query-status":
            reply({"return": {"status": "running", "running": True}})
            return True
        if cmd == "quit":
            reply({"return": {}})
            return False
        reply({"return": {}})
        return True


class StubQMP:
    def __init__(self, frames=(), *, transport: str = "unix", errors=None, mute=(), events=(), greeting=True):
        self.frames, self.errors, self.mute, self.events, self.greeting = frames, errors, mute, events, greeting
        self.transport = transport
        self.commands: list[dict] = []
        self.connections = 0
        self._dir = None
        self._server = None

    def __enter__(self) -> "StubQMP":
        stub = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                stub.connections += 1
                proto = Protocol(self.wfile.write, stub.commands.append, stub.frames, errors=stub.errors,
                                 mute=stub.mute, events=stub.events, greeting=stub.greeting)
                for line in self.rfile:
                    if line.strip() and not proto.handle(line):
                        break
                    self.wfile.flush()

        if self.transport == "unix":
            self._dir = tempfile.mkdtemp(prefix="q-")       # short: AF_UNIX paths are limited to ~104 bytes
            path = os.path.join(self._dir, "q.sock")

            class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
                daemon_threads = True

            self._server = Server(path, Handler)
            self.spec = f"unix:{path}"
        elif self.transport == "tcp":
            class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
                daemon_threads = True
                allow_reuse_address = True

            self._server = Server(("127.0.0.1", 0), Handler)
            self.spec = f"tcp:127.0.0.1:{self._server.server_address[1]}"
        else:
            raise ValueError(self.transport)
        threading.Thread(target=self._server.serve_forever, name="qmp-stub", daemon=True).start()
        return self

    def __exit__(self, *exc) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._dir:
            shutil.rmtree(self._dir, ignore_errors=True)

    def executed(self) -> list[str]:
        return [c.get("execute") for c in self.commands]


def serve_stdio(state_path: str) -> int:
    with open(state_path, encoding="utf-8") as fh:
        state = json.load(fh)
    frames = []
    for p in state.get("frames", []):
        with open(p, "rb") as fh:
            frames.append(fh.read())
    out = sys.stdout.buffer

    def write(data: bytes) -> None:
        out.write(data)
        out.flush()

    def record(msg) -> None:
        with open(state["log"], "a", encoding="utf-8") as fh:
            fh.write(json.dumps(msg) + "\n")

    proto = Protocol(write, record, frames, errors=state.get("errors"), mute=state.get("mute", ()))
    for line in sys.stdin.buffer:
        if line.strip() and not proto.handle(line):
            break
    return 0


DOCKER_STUB = '''\
#!{python} -I
# {marker}
# A stub docker for the boot-harness tests: logs every call; `image inspect` answers from the state
# file; `run` prints a container id; `exec` becomes the stdio QMP stub (or exits at once).
import json, os, sys
state = json.load(open(os.environ["STUB_STATE"]))
args = sys.argv[1:]
with open(os.environ["STUB_LOG"], "a") as fh:
    fh.write(json.dumps({{"argv": args}}) + "\\n")
if args[:2] == ["image", "inspect"]:
    tag = args[-1]
    if tag in state.get("images", {{}}):
        print(json.dumps(state["images"][tag]))
        sys.exit(0)
    print("Error response from daemon: No such image: " + tag, file=sys.stderr)
    sys.exit(1)
if args[:1] == ["run"]:
    print("0123456789ab")
    sys.exit(state.get("run_rc", 0))
if args[:1] == ["exec"]:
    if not state.get("qmp_state"):
        sys.exit(1)
    os.execv({python!r}, [{python!r}, "-I", {stub!r}, "--stdio", state["qmp_state"]])
sys.exit(0)
'''


def docker_stub(tmp, state: dict, *, marker: bool = True) -> dict:
    """A bin folder holding a stub `docker`; returns the environ to run with (PATH, STUB_STATE,
    STUB_LOG, CTF_TESTING). Without `marker` the script is a "real" docker as far as the
    CTF_TESTING guard can tell, and the guard must refuse it."""
    from ctf.toolchain import images
    bindir = tmp / "stubbin"
    bindir.mkdir(parents=True, exist_ok=True)
    exe = bindir / "docker"
    exe.write_text(DOCKER_STUB.format(python=sys.executable, stub=os.path.abspath(__file__),
                                      marker=images.STUB_MARKER if marker else "an ordinary docker"))
    exe.chmod(0o755)
    st = tmp / "docker-state.json"
    st.write_text(json.dumps(state))
    return {"PATH": str(bindir), "STUB_STATE": str(st), "STUB_LOG": str(tmp / "docker-log.jsonl"),
            "CTF_TESTING": "1", "HOME": str(tmp)}


def docker_calls(environ: dict) -> list[list[str]]:
    try:
        with open(environ["STUB_LOG"], encoding="utf-8") as fh:
            return [json.loads(x)["argv"] for x in fh if x.strip()]
    except FileNotFoundError:
        return []


def stdio_state(tmp, frames, **extra) -> str:
    """Write the frames and the state file of a stdio QMP stub; returns the state file's path."""
    paths = []
    for i, data in enumerate(frames):
        p = tmp / f"frame-{i}.ppm"
        p.write_bytes(data)
        paths.append(str(p))
    st = tmp / "qmp-state.json"
    st.write_text(json.dumps({"frames": paths, "log": str(tmp / "qmp-log.jsonl"), **extra}))
    return str(st)


def stdio_log(tmp) -> list[dict]:
    try:
        return [json.loads(x) for x in (tmp / "qmp-log.jsonl").read_text().splitlines() if x.strip()]
    except FileNotFoundError:
        return []


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--stdio":
        raise SystemExit(serve_stdio(sys.argv[2]))
    raise SystemExit("usage: qmp_stub.py --stdio STATE.json")
