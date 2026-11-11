"""A fake machine for the hardware probes, and small model-list servers on 127.0.0.1.

FakeHost answers the probes from what a test gives it: the programs on PATH, each command's
output (or the ProbeError it raises), each file's text and each URL's answer. It records every
command run and every URL fetched, so a test can say what was asked, and of whom. Nothing it
does touches this machine, except with real_http=True: then a URL it has no answer for is
fetched with hardware.http_get, for a ListServer the test started.

ListServer is real HTTP on 127.0.0.1 (a free port) in a background thread: each path answers
with a scripted status and body, after a delay if the test wants the client to time out. It
records the Host header of every request it gets.
"""

from __future__ import annotations

import socketserver
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ctf_flightdeck import hardware
from ctf_flightdeck.hardware import ProbeError, Refused

GIB = 1024**3


class FakeHost:
    def __init__(
        self,
        system: str,
        arch: str,
        *,
        programs: Mapping[str, str] | None = None,
        commands: Mapping[tuple[str, ...], str | Exception] | None = None,
        files: Mapping[str, str] | None = None,
        http: Mapping[str, tuple[int, bytes] | Exception] | None = None,
        importable: Sequence[str] = (),
        real_http: bool = False,
    ) -> None:
        self.system, self.arch = system, arch
        self.programs = dict(programs or {})  # name -> absolute path
        self.commands = dict(commands or {})  # argv -> stdout, or the exception it raises
        self.files = dict(files or {})  # path -> text
        self.http = dict(http or {})  # url -> (status, body), or the exception
        self._importable = set(importable)
        self.real_http = real_http
        self.ran: list[list[str]] = []
        self.timeouts: list[float] = []
        self.fetched: list[str] = []

    def which(self, program: str) -> str | None:
        return self.programs.get(program)

    def run(self, argv: Sequence[str], timeout: float) -> str:
        self.ran.append(list(argv))
        self.timeouts.append(timeout)
        answer = self.commands.get(tuple(argv))
        if answer is None:
            raise ProbeError(f"{argv[0]} is not scripted")
        if isinstance(answer, Exception):
            raise answer
        return answer

    def get(self, url: str, timeout: float) -> tuple[int, bytes]:
        self.fetched.append(url)
        if url not in self.http and self.real_http:
            return hardware.http_get(url, timeout)
        answer = self.http.get(url, Refused("nothing is listening there"))
        if isinstance(answer, Exception):
            raise answer
        return answer

    def read(self, path: str) -> str:
        if path not in self.files:
            raise FileNotFoundError(2, "No such file or directory", path)
        return self.files[path]

    def importable(self, module: str) -> bool:
        return module in self._importable


def apple_mac(memory: int = 36 * GIB, chip: str = "Apple M4 Max", **kwargs) -> FakeHost:
    """An Apple Silicon Mac: sysctl answers the chip and the memory; no nvidia-smi."""
    return FakeHost("Darwin", "arm64", programs={"sysctl": "/usr/sbin/sysctl", **kwargs.pop("programs", {})},
                    commands={("/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"): f"{chip}\n",
                              ("/usr/sbin/sysctl", "-n", "hw.memsize"): f"{memory}\n", **kwargs.pop("commands", {})},
                    **kwargs)


def linux_box(memtotal_kib: int, *, osrelease: str = "6.8.0-45-generic\n", nvidia: str | Exception | None = None,
              nvidia_path: str = "/usr/bin/nvidia-smi", **kwargs) -> FakeHost:
    """A Linux machine: /proc/meminfo and the kernel release; nvidia-smi on PATH when `nvidia` is given."""
    programs, commands = dict(kwargs.pop("programs", {})), dict(kwargs.pop("commands", {}))
    if nvidia is not None:
        programs["nvidia-smi"] = nvidia_path
        commands[(nvidia_path, "--query-gpu=name,memory.total", "--format=csv,noheader,nounits")] = nvidia
    meminfo = f"MemTotal:       {memtotal_kib} kB\nMemFree:         1234567 kB\nMemAvailable:   2345678 kB\n"
    files = {"/proc/meminfo": meminfo, "/proc/sys/kernel/osrelease": osrelease, **kwargs.pop("files", {})}
    return FakeHost("Linux", "x86_64", programs=programs, commands=commands, files=files, **kwargs)


# ---------------------------------------------------------------------- real HTTP on 127.0.0.1


@dataclass(frozen=True)
class Answer:
    status: int = 200
    body: bytes = b""
    delay: float = 0.0  # seconds before answering
    headers: tuple[tuple[str, str], ...] = ()


class ListServer:
    """GET path -> its scripted Answer (404 for any other path), on 127.0.0.1."""

    def __init__(self, routes: Mapping[str, Answer]) -> None:
        self.routes = dict(routes)
        self.hosts: list[str] = []  # the Host header of each request
        self.paths: list[str] = []  # the path of each request, as it was sent (a proxy is sent the whole URL)
        self._lock = threading.Lock()
        self._httpd = _Server(self)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def __enter__(self) -> ListServer:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._httpd.shutdown()
        self._thread.join()
        self._httpd.server_close()


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, owner: ListServer) -> None:
        self.owner = owner
        super().__init__(("127.0.0.1", 0), _Handler)

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)  # no reverse lookup of the host name
        self.server_name, self.server_port = self.server_address[:2]

    def handle_error(self, request, client_address) -> None:
        pass  # a client that timed out and hung up: expected


class _Handler(BaseHTTPRequestHandler):
    server: _Server

    def do_GET(self) -> None:
        owner = self.server.owner
        with owner._lock:
            owner.hosts.append(self.headers.get("Host", ""))
            owner.paths.append(self.path)
        answer = owner.routes.get(self.path, Answer(404, b'{"error": "not found"}'))
        if answer.delay:
            time.sleep(answer.delay)
        try:
            self.send_response(answer.status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(answer.body)))
            for name, value in answer.headers:
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(answer.body)
        except OSError:
            pass

    def log_message(self, format: str, *args: object) -> None:
        pass
