"""The toolbox, driven through Toolbox.call() against a real host workspace in tmp_path.

The http tool talks to a local http.server each test starts on 127.0.0.1. An origin it must
refuse is a socket that listens but never accepts: any connection attempt would be left
pending on it, so "no pending connection" proves the tool never connected.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import socket
import subprocess
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from ctf_flightdeck.agent import tools
from ctf_flightdeck.agent.tools import SUBMITTED, TOOLS, ToolResult, Toolbox
from ctf_flightdeck.agent.workspace import DockerWorkspace, HostWorkspace, docker_unavailable

IMAGE = "debian:bookworm-slim"
NOTES = "".join(f"line {i}\n" for i in range(1, 1001))


def run(coro):
    return asyncio.run(coro)


def call(box: Toolbox, name: str, args: dict | str, *, turn: int = 1, index: int = 0) -> ToolResult:
    text = args if isinstance(args, str) else json.dumps(args)
    return run(box.call(name, text, turn=turn, index=index))


def within(seconds: float, fn):
    """fn() in a daemon thread, so a hang fails the test instead of stalling the suite."""
    box: dict = {}
    worker = threading.Thread(target=lambda: box.setdefault("value", fn()), daemon=True)
    worker.start()
    worker.join(seconds)
    assert not worker.is_alive(), f"no answer within {seconds} s"
    return box["value"]


@pytest.fixture
def handout(tmp_path: Path) -> Path:
    h = tmp_path / "handout"
    h.mkdir()
    (h / "challenge.json").write_text('{"name": "Demo", "category": "misc", "points": 50}\n')
    (h / "notes.txt").write_text(NOTES)
    return h


@pytest.fixture
def lane(tmp_path: Path, handout: Path):
    ws = HostWorkspace(tmp_path / "lane", handout)
    run(ws.prepare())
    yield ws
    run(ws.close())


@pytest.fixture
def box(lane) -> Toolbox:
    return Toolbox(lane)


# ---------------------------------------------------------------- the schemas


def test_the_tools_are_six_short_openai_function_schemas():
    assert [t["function"]["name"] for t in TOOLS] == ["shell", "read_file", "python", "http", "submit_flag", "set_plan"]
    required = {}
    for tool in TOOLS:
        assert tool["type"] == "function" and tool["function"]["description"]
        params = tool["function"]["parameters"]
        assert params["type"] == "object" and set(params["required"]) <= set(params["properties"])
        required[tool["function"]["name"]] = params["required"]
    assert required == {
        "shell": ["command"],
        "read_file": ["path"],
        "python": ["code"],
        "http": ["method", "url"],
        "submit_flag": ["flag"],
        "set_plan": ["plan"],
    }
    assert len(json.dumps(TOOLS)) < 6000  # about 1500 tokens at 4 characters a token


# ---------------------------------------------------------------- shell and python


def test_shell_gives_the_exit_code_and_output_and_a_short_line_for_the_console(box):
    failed = call(box, "shell", {"command": "echo hello; echo oops >&2; exit 2"})
    assert failed == ToolResult("exit 2\nhello\noops\n", "$ echo hello; echo oops >&2; exit 2", "exit 2 · hello\noops")
    fine = call(box, "shell", {"command": "printf 'a\\nb\\nc\\nd\\n'"})
    assert (fine.content, fine.output) == ("exit 0\na\nb\nc\nd\n", "a\nb\nc")
    assert call(box, "shell", {"command": "true"}).output == "(no output)"
    assert call(box, "shell", {"command": "echo a\necho b"}).action == "$ echo a ⏎ echo b"


def test_the_console_line_is_at_most_300_characters(box):
    result = call(box, "shell", {"command": "printf 'x%.0s' $(seq 1 1000)"})
    assert len(result.output) == 300 and result.output.endswith("…")


def test_shell_timeouts_have_a_default_and_are_clamped(lane):
    box = Toolbox(lane, default_timeout=1, max_timeout=2)
    started = time.monotonic()
    result = call(box, "shell", {"command": "echo before; sleep 60", "timeout_seconds": 10_000})
    assert result.content == "timed out after 2s\nbefore\n"
    assert result.output == "timed out after 2s · before"
    assert call(box, "shell", {"command": "sleep 60"}).content == "timed out after 1s\n"
    assert call(box, "shell", {"command": "sleep 60", "timeout_seconds": 0}).content == "timed out after 1s\n"
    assert time.monotonic() - started < 20


def test_long_output_is_cut_to_its_head_and_tail_and_saved_in_full(lane):
    box = Toolbox(lane, max_chars=1000)
    full = "".join(f"{i}\n" for i in range(1, 5001))
    result = call(box, "shell", {"command": "seq 1 5000"}, turn=7, index=2)
    assert len(result.content) <= 1000
    shape = re.fullmatch(
        r"exit 0\n(?P<head>.*)\n\[\.\.\. (?P<cut>\d+) characters cut; full output in \.flightdeck/out/turn7-2\.txt \.\.\.\]\n(?P<tail>.*)",
        result.content,
        re.S,
    )
    assert shape, result.content
    head, cut, tail = shape["head"], int(shape["cut"]), shape["tail"]
    assert full.startswith(head) and full.endswith(tail)
    assert len(head) + cut + len(tail) == len(full)
    assert 500 <= len(head) <= 700 and 250 <= len(tail) <= 350
    assert (lane.root / ".flightdeck" / "out" / "turn7-2.txt").read_text() == full


def test_even_the_smallest_max_chars_keeps_results_within_it(lane):
    with pytest.raises(ValueError, match="max_chars must be at least 200"):
        Toolbox(lane, max_chars=199)
    box = Toolbox(lane, max_chars=200)
    shell = call(box, "shell", {"command": "seq 1 5000"})
    assert len(shell.content) <= 200 and "characters cut; full output in .flightdeck/out/turn1-0.txt" in shell.content
    read = call(box, "read_file", {"path": "notes.txt"})
    assert len(read.content) <= 200 and read.content.startswith("line 1\n") and "read on with start_line=" in read.content


def test_output_that_fits_is_not_cut_and_not_saved(lane):
    box = Toolbox(lane, max_chars=1000)
    assert call(box, "shell", {"command": "seq 1 100"}, turn=8, index=0).content == "exit 0\n" + "".join(f"{i}\n" for i in range(1, 101))
    assert not (lane.root / ".flightdeck" / "out" / "turn8-0.txt").exists()


def test_the_overflow_file_is_never_written_through_a_symlink_or_a_link_the_lane_planted(lane, tmp_path):
    box = Toolbox(lane, max_chars=1000)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    call(box, "shell", {"command": f"rm -rf .flightdeck/out && ln -s {elsewhere} .flightdeck/out"})
    result = call(box, "shell", {"command": "seq 1 5000"}, turn=2, index=0)
    assert list(elsewhere.iterdir()) == []
    assert "the full output could not be saved" in result.content
    victim = tmp_path / "victim.txt"
    victim.write_text("original\n")
    call(box, "shell", {"command": f"rm -f .flightdeck/out && mkdir .flightdeck/out && ln {victim} .flightdeck/out/turn3-0.txt"})
    call(box, "shell", {"command": "seq 1 5000"}, turn=3, index=0)
    assert victim.read_text() == "original\n"
    assert (lane.root / ".flightdeck" / "out" / "turn3-0.txt").read_text().startswith("1\n2\n")


@pytest.fixture
def python3():
    if shutil.which("python3") is None:
        pytest.skip("python3 is not on PATH")


def test_python_saves_the_code_in_the_workspace_and_runs_it_there(box, lane, python3):
    code = "import os\nprint(os.getcwd())\nprint(open('notes.txt').readline().strip())\n"
    result = call(box, "python", {"code": code}, turn=4, index=1)
    assert result.content == f"exit 0\n{lane.root.resolve()}\nline 1\n"
    assert (lane.root / ".flightdeck" / "py" / "turn4-1.py").read_text() == code
    assert result.action == "python: import os"


def test_python_failures_and_timeouts_read_like_shell_ones(box, python3):
    failed = call(box, "python", {"code": "\n\nraise SystemExit('boom')"})
    assert failed.content == "exit 1\nboom\n" and failed.action == "python: raise SystemExit('boom')"
    slow = call(box, "python", {"code": "import time\ntime.sleep(60)", "timeout_seconds": 1})
    assert slow.content == "timed out after 1s\n"


# ---------------------------------------------------------------- read_file


def test_read_file_reads_400_lines_at_a_time_and_says_where_to_go_on(box):
    result = call(box, "read_file", {"path": "notes.txt"})
    lines = result.content.splitlines()
    assert lines[:400] == [f"line {i}" for i in range(1, 401)]
    assert lines[400:] == ["[lines 1-400 of 1000; read on with start_line=401]"]
    assert (result.action, result.output, result.error) == ("read notes.txt", "lines 1-400 of 1000", False)


def test_read_file_takes_a_start_line_and_a_count(box):
    assert call(box, "read_file", {"path": "notes.txt", "start_line": 999, "max_lines": 5}).content == "line 999\nline 1000\n"
    middle = call(box, "read_file", {"path": "notes.txt", "start_line": 10, "max_lines": 2})
    assert middle.content == "line 10\nline 11\n[lines 10-11 of 1000; read on with start_line=12]"
    past = call(box, "read_file", {"path": "notes.txt", "start_line": 2000})
    assert (past.error, past.content) == (True, "error: start_line 2000 is past the end: notes.txt has 1000 lines")


def test_read_file_stays_within_max_chars(lane):
    box = Toolbox(lane, max_chars=1000)
    result = call(box, "read_file", {"path": "notes.txt"})
    assert len(result.content) <= 1000
    footer = result.content.splitlines()[-1]
    last = int(re.fullmatch(r"\[lines 1-(\d+) of 1000; read on with start_line=(\d+)\]", footer)[1])
    assert result.content.splitlines()[:-1] == [f"line {i}" for i in range(1, last + 1)]


def test_a_line_longer_than_max_chars_is_cut_and_the_next_line_still_counts(lane):
    (lane.root / "long.txt").write_text("x" * 50_000 + "\nsecond\n")
    box = Toolbox(lane, max_chars=1000)
    first = call(box, "read_file", {"path": "long.txt"})
    assert len(first.content) <= 1000 and first.content.startswith("x" * 500)
    assert first.content.endswith("[lines 1-1 of 2; line 1 is cut; use shell (cut, head -c) for the rest of it; read on with start_line=2]")
    assert call(box, "read_file", {"path": "long.txt", "start_line": 2}).content == "second\n"


def test_read_file_takes_an_absolute_path_inside_the_workspace(box, lane):
    for path in (lane.root / "notes.txt", lane.root.resolve() / "notes.txt"):
        assert call(box, "read_file", {"path": str(path), "max_lines": 1}).content.startswith("line 1\n[lines 1-1 of 1000")


def test_read_file_follows_a_symlink_that_stays_inside(box, lane):
    (lane.root / "sub").mkdir()
    os.symlink("notes.txt", lane.root / "alias")
    os.symlink("../notes.txt", lane.root / "sub" / "up")
    os.symlink(lane.root / "notes.txt", lane.root / "absolute-alias")
    os.symlink("sub", lane.root / "subdir")
    for path in ("alias", "sub/up", "absolute-alias", "subdir/up", "sub/../notes.txt"):
        assert call(box, "read_file", {"path": path, "max_lines": 1}).content.startswith("line 1\n"), path


@pytest.mark.parametrize("path", ["../outside.txt", "/etc/passwd", "sub/../../outside.txt", "leak", "rel-leak", "dir-leak/outside.txt", "loop"])
def test_read_file_refuses_anything_outside_the_workspace(lane, tmp_path, path):
    (tmp_path / "outside.txt").write_text("secret outside the lane\n")
    (lane.root / "sub").mkdir()
    os.symlink(tmp_path / "outside.txt", lane.root / "leak")
    os.symlink("../outside.txt", lane.root / "rel-leak")
    os.symlink(tmp_path, lane.root / "dir-leak")
    os.symlink("loop", lane.root / "loop")
    result = call(Toolbox(lane), "read_file", {"path": path})
    assert result.error
    assert "outside the workspace" in result.content or "too many levels of symlinks" in result.content
    assert "secret" not in result.content


def test_read_file_maps_work_paths_and_container_symlinks_to_the_workspace(tmp_path):
    root = tmp_path / "box"
    root.mkdir()
    (root / "data.txt").write_text("in the box\n")
    os.symlink("/work/data.txt", root / "inside")
    os.symlink("/etc/passwd", root / "host")
    # Never prepared: the toolbox only uses its paths, so no container is needed.
    ws = DockerWorkspace(root, tmp_path / "unused", image=IMAGE, name="flightdeck-test-paths")
    box = Toolbox(ws)
    assert call(box, "read_file", {"path": "/work/data.txt"}).content == "in the box\n"
    assert call(box, "read_file", {"path": "inside"}).content == "in the box\n"
    for path in ("host", "/workshop/data.txt", "/etc/passwd"):
        refused = call(box, "read_file", {"path": path})
        assert refused.error and "outside the workspace" in refused.content, path


def test_read_file_says_a_binary_file_is_binary(box, lane):
    (lane.root / "blob.bin").write_bytes(b"PK\x03\x04" + b"\x00" * 60)
    result = call(box, "read_file", {"path": "blob.bin"})
    assert result == ToolResult("binary file, 64 bytes; use shell (file, xxd, strings)", "read blob.bin", "binary file, 64 bytes")


def test_read_file_names_what_is_wrong_with_a_path(box, lane):
    (lane.root / "empty.txt").write_bytes(b"")
    assert call(box, "read_file", {"path": "empty.txt"}).content == "(empty file)"
    cases = {
        "missing.txt": "error: no such file: missing.txt",
        ".": "error: . is a directory; use shell (ls)",
        "notes.txt/x": "error: no such file: notes.txt/x (part of the path is a file)",
    }
    for path, message in cases.items():
        assert (call(box, "read_file", {"path": path}).content, path) == (message, path)


def test_read_file_never_hangs_on_a_fifo(box, lane):
    os.mkfifo(lane.root / "fifo")
    result = within(10, lambda: call(box, "read_file", {"path": "fifo"}))
    assert (result.error, result.content) == (True, "error: fifo is not a regular file")


# ---------------------------------------------------------------- the model's mistakes


@pytest.mark.parametrize(
    "name, arguments, message",
    [
        ("nope", "{}", "error: unknown tool 'nope'; the tools are shell, read_file, python, http, submit_flag, set_plan"),
        ("shell", "{not json", "error: the arguments are not valid JSON (Expecting property name"),
        ("shell", "[" * 100_000 + "]" * 100_000, "error: the arguments are not valid JSON; send one JSON object"),
        ("shell", "[1, 2]", "error: the arguments must be a JSON object"),
        ("shell", "{}", "error: shell needs command (a string)"),
        ("shell", "", "error: shell needs command (a string)"),
        ("shell", '{"command": 5}', "error: command must be a string"),
        ("shell", '{"command": "ls", "timeout_seconds": "ten"}', "error: timeout_seconds must be a number"),
        ("shell", '{"command": "ls", "timeout_seconds": true}', "error: timeout_seconds must be a number"),
        ("shell", '{"command": "ls", "timeout": 5}', "error: shell takes command, timeout_seconds; unknown: timeout"),
        ("shell", '{"command": "   "}', "error: command is empty"),
        ("shell", '{"command": "echo \\u0000"}', "error: command contains a NUL character"),
        ("shell", '{"command": "echo \\ud800"}', "error: the command holds characters that are not valid Unicode"),
        ("python", '{"code": "  \\n "}', "error: code is empty"),
        ("read_file", '{"path": "notes.txt", "start_line": 0}', "error: start_line counts from 1"),
        ("read_file", '{"path": "notes.txt", "max_lines": 0}', "error: max_lines must be at least 1"),
        ("read_file", '{"path": "a\\u0000b"}', "error: path contains a NUL character"),
        ("http", '{"method": "GET"}', "error: http needs url (a string)"),
        ("http", '{"method": "G E T", "url": "http://127.0.0.1/"}', "error: method 'G E T' is not an HTTP method"),
        ("http", '{"method": "GET", "url": "http://127.0.0.1/", "headers": {"a": 1}}', "error: headers must be an object of strings"),
        ("submit_flag", '{"flag": "  "}', "error: flag is empty"),
        ("set_plan", "{}", "error: set_plan needs plan (a string)"),
    ],
)
def test_the_models_mistakes_come_back_as_errors_it_can_read(box, name, arguments, message):
    result = run(box.call(name, arguments, turn=1, index=0))
    assert result.error and result.content.startswith(message), result.content
    assert len(result.output) <= 300


# ---------------------------------------------------------------- flags and plans


def test_submit_flag_hands_the_stripped_flag_to_the_player(box):
    result = call(box, "submit_flag", {"flag": "  practice{abc}\n", "how": "xor with the known prefix"})
    assert result == ToolResult(SUBMITTED, "submit practice{abc}", "xor with the known prefix", flag="practice{abc}")
    assert SUBMITTED == "Sent to the player for approval. Carry on until you hear it was correct."


def test_set_plan_notes_the_stripped_plan(box):
    result = call(box, "set_plan", {"plan": "  Decode the base64 layer, then try XOR.  "})
    plan = "Decode the base64 layer, then try XOR."
    assert result == ToolResult("Plan noted.", f"plan: {plan}", "", plan=plan)
    long = call(box, "set_plan", {"plan": "x" * 2000})
    assert len(long.plan) == 500 and long.content == "Plan noted (cut to 500 characters)."


# ---------------------------------------------------------------- http


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:
        pass

    def _send(self, status: int, body: bytes, headers: tuple = ()) -> None:
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _record(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        request = {
            "method": self.command,
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body": self.rfile.read(length) if length else b"",
        }
        self.server.requests.append(request)
        return request

    def do_GET(self) -> None:
        self._record()
        if self.path == "/":
            self._send(200, b"<h1>hello</h1>\n", (("Content-Type", "text/html"), ("X-Hint", "try /admin"), ("Set-Cookie", "session=abc")))
        elif self.path == "/moved":
            self._send(302, b"", (("Location", self.server.redirect_to),))
        elif self.path == "/big":
            self._send(200, b"".join(b"%05d\n" % i for i in range(5000)))
        elif self.path == "/binary":
            self._send(200, bytes(range(256)) * 4, (("Content-Type", "application/octet-stream"),))
        else:
            self._send(404, b"not found\n")

    def do_POST(self) -> None:
        request = self._record()
        self._send(201, b"got " + request["body"] + b" with " + request["headers"].get("x-token", "").encode())


@pytest.fixture
def web():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.requests = []
    server.redirect_to = ""
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


@pytest.fixture
def silent(monkeypatch):
    """A port that listens but never accepts: a connection to it would show up as pending.
    The http timeout is cut to 2 s so that a request wrongly sent there fails fast."""
    monkeypatch.setattr(tools, "HTTP_TIMEOUT", 2.0)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(8)
    yield sock
    sock.close()


def origin(server) -> str:
    return f"http://127.0.0.1:{server.server_address[1]}"


def port(sock: socket.socket) -> int:
    return sock.getsockname()[1]


def assert_never_connected(sock: socket.socket) -> None:
    sock.setblocking(False)
    with pytest.raises(BlockingIOError):
        sock.accept()


def test_http_reaches_the_instance_and_shows_the_status_headers_and_body(lane, web):
    box = Toolbox(lane, http_allow=(origin(web),))
    result = call(box, "http", {"method": "get", "url": origin(web) + "/"})
    head, body = result.content.split("\n\n", 1)
    lines = head.splitlines()
    assert lines[0] == "HTTP/1.0 200 OK"
    assert {"content-type: text/html", "x-hint: try /admin", "set-cookie: session=abc", "content-length: 15"} <= set(lines)
    assert not any(line.startswith("date:") for line in lines)
    assert body == "<h1>hello</h1>\n"
    assert (result.action, result.output, result.error) == (f"GET {origin(web)}/", "200 OK, 15 bytes", False)
    assert [r["path"] for r in web.requests] == ["/"]


def test_http_sends_the_method_body_and_headers_it_is_given(lane, web):
    box = Toolbox(lane, http_allow=(origin(web),))
    result = call(box, "http", {"method": "POST", "url": origin(web) + "/submit", "body": "a=1", "headers": {"X-Token": "t0k"}})
    assert result.content.endswith("\n\ngot a=1 with t0k")
    assert (web.requests[0]["method"], web.requests[0]["body"]) == ("POST", b"a=1")


def test_http_refuses_every_other_origin_without_connecting(lane, web, silent):
    box = Toolbox(lane, http_allow=(origin(web),))
    for url in (
        f"http://127.0.0.1:{port(silent)}/",
        f"https://127.0.0.1:{port(silent)}/",
        f"http://localhost:{port(silent)}/",
        f"http://127.0.0.1:{web.server_address[1]}@127.0.0.1:{port(silent)}/",
        "ftp://127.0.0.1/",
        "not a url",
    ):
        result = call(box, "http", {"method": "GET", "url": url})
        assert result.error, url
    assert "is not this challenge's instance; http goes only to " + origin(web) in call(box, "http", {"method": "GET", "url": f"http://127.0.0.1:{port(silent)}/"}).content
    assert_never_connected(silent)
    with_password = call(box, "http", {"method": "GET", "url": f"http://user:pw@127.0.0.1:{web.server_address[1]}/"})
    assert with_password.content == "error: no user:password@ in the URL; send an Authorization header instead"
    assert web.requests == []


def test_http_follows_no_redirect(lane, web, silent):
    web.redirect_to = f"http://127.0.0.1:{port(silent)}/"
    box = Toolbox(lane, http_allow=(origin(web), web.redirect_to.rstrip("/")))
    result = call(box, "http", {"method": "GET", "url": origin(web) + "/moved"})
    assert result.content.startswith("HTTP/1.0 302 Found\n")
    assert f"location: {web.redirect_to}" in result.content.splitlines()
    assert_never_connected(silent)


def test_http_ignores_proxies_set_in_the_environment(lane, web, silent, monkeypatch):
    proxy = f"http://127.0.0.1:{port(silent)}"
    for name in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(name, proxy)
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
    box = Toolbox(lane, http_allow=(origin(web),))
    assert not call(box, "http", {"method": "GET", "url": origin(web) + "/"}).error
    assert_never_connected(silent)


def test_http_treats_a_default_port_as_the_same_origin(lane, silent):
    box = Toolbox(lane, http_allow=("http://127.0.0.1:80",))
    result = call(box, "http", {"method": "GET", "url": "http://127.0.0.1/"})
    assert "not this challenge's instance" not in result.content  # allowed; nothing may listen there, which is fine


def test_http_is_off_without_an_instance(box):
    result = call(box, "http", {"method": "GET", "url": "http://127.0.0.1:9/"})
    assert (result.error, result.content) == (True, "error: http is off: this challenge has no instance to reach")


def test_a_long_http_body_is_cut_and_saved_in_full(lane, web):
    box = Toolbox(lane, max_chars=1000, http_allow=(origin(web),))
    result = call(box, "http", {"method": "GET", "url": origin(web) + "/big"}, turn=3, index=1)
    assert len(result.content) <= 1000
    assert "characters cut; full output in .flightdeck/out/turn3-1.txt ...]" in result.content
    assert result.content.startswith("HTTP/1.0 200 OK\n")
    assert (lane.root / ".flightdeck" / "out" / "turn3-1.txt").read_bytes() == b"".join(b"%05d\n" % i for i in range(5000))


def test_a_binary_http_body_is_saved_rather_than_shown(lane, web):
    box = Toolbox(lane, http_allow=(origin(web),))
    result = call(box, "http", {"method": "GET", "url": origin(web) + "/binary"}, turn=5, index=0)
    assert result.content.endswith("\n\n[binary body, 1024 bytes; saved to .flightdeck/out/turn5-0.txt]")
    assert (lane.root / ".flightdeck" / "out" / "turn5-0.txt").read_bytes() == bytes(range(256)) * 4


def test_an_unreachable_instance_is_an_error_the_model_can_read(lane, silent):
    closed = port(silent)
    silent.close()  # nothing listens there now
    box = Toolbox(lane, http_allow=(f"http://127.0.0.1:{closed}",))
    result = call(box, "http", {"method": "GET", "url": f"http://127.0.0.1:{closed}/"})
    assert result.error and result.content.startswith("error: the request failed: ConnectError")


@pytest.mark.parametrize("bad", ["127.0.0.1:8080", "ftp://127.0.0.1", "http://127.0.0.1:8080/path", "http://user:pw@127.0.0.1", ""])
def test_http_allow_takes_only_origins(lane, bad):
    with pytest.raises(ValueError, match="not an origin"):
        Toolbox(lane, http_allow=(bad,))


# ---------------------------------------------------------------- in a docker lane


@pytest.fixture
def docker_lane(tmp_path, handout):
    reason = docker_unavailable()
    if reason is None and subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True, timeout=60).returncode:
        reason = f"image {IMAGE} is not present locally (these tests never pull it)"
    if reason:
        pytest.skip(reason)
    name = f"flightdeck-test-{uuid.uuid4().hex[:12]}"
    ws = DockerWorkspace(tmp_path / "box", handout, image=IMAGE, name=name)
    try:
        run(ws.prepare())
        yield ws
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=60)


def test_tools_in_a_docker_lane_run_in_the_container_and_read_through_work(docker_lane):
    box = Toolbox(docker_lane)
    made = call(box, "shell", {"command": "pwd && ln -s /etc/passwd leak && ln -s /work/notes.txt alias"})
    assert made.content == "exit 0\n/work\n"
    assert call(box, "read_file", {"path": "/work/alias", "max_lines": 1}).content.startswith("line 1\n")
    leak = call(box, "read_file", {"path": "leak"})
    assert leak.error and "outside the workspace" in leak.content
    missing = call(box, "python", {"code": "print(1)"}, turn=2, index=0)
    assert missing.content.startswith("exit 127\n") and "python3" in missing.content  # the image has none, and says so
    assert (docker_lane.root / ".flightdeck" / "py" / "turn2-0.py").read_text() == "print(1)"
