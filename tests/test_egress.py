"""The fence round a Docker lane's network (agent/egress.py, agent/egress_proxy.py; issue #14).

Three kinds of test:

- the arguments flightdeck builds, and what it does when docker refuses, against a stand-in
  docker (tests/l1_kit.py's): no container, no network;
- the proxy itself, run as a plain process the way its container runs it, against two servers
  on 127.0.0.1: the one its list names and one it does not;
- the real thing, when Docker runs here and the lane image is already on this machine (never
  pulled, never built): a lane's container reaches its instance and not a second server on
  this machine, nor a name outside. Otherwise those tests are skipped with the reason, so
  they report as not run. Every container and network a test starts is removed, even when
  the test fails.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import socketserver
import subprocess
import sys
import threading
import uuid
from pathlib import Path

import pytest

from ctf_flightdeck import leftovers
from ctf_flightdeck.agent import egress, egress_proxy, prompts
from ctf_flightdeck.agent.egress import CLI_API, Egress, FenceError, Host, hosts, proxy_config, shell_hosts
from ctf_flightdeck.agent.workspace import DockerWorkspace, HostWorkspace, WorkspaceError, docker_unavailable
from ctf_flightdeck.core.model import ActionKind, Challenge
from ctf_flightdeck.lane import IMAGE as LANE_IMAGE

from l1_kit import FAKE_IMAGE, install_fake_docker


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------- which hosts and ports


def test_urls_become_hosts_with_the_ports_each_names_and_the_scheme_gives_a_missing_port():
    found = hosts(("https://shop.chal.example.test", "tcp://shop.chal.example.test:1337", "http://Shop.Chal.Example.Test:8080/",
                   "http://other.example.test", "https://shop.chal.example.test:443"))
    assert found == (
        Host("shop.chal.example.test", "shop.chal.example.test", (443, 1337, 8080), "shop.chal.example.test"),
        Host("other.example.test", "other.example.test", (80,), "other.example.test"),
    )
    assert not any(host.renamed for host in found) and shell_hosts(("https://shop.chal.example.test",)) == {}


@pytest.mark.parametrize(
    "url, name, upstream, written",
    [
        ("tcp://10.0.0.5:1337", "instance-10-0-0-5", "10.0.0.5", "10.0.0.5"),  # an address is not a name
        ("http://127.0.0.1:8080", "instance-127-0-0-1", "host.docker.internal", "127.0.0.1"),  # this machine
        ("http://localhost:8080", "instance-localhost", "host.docker.internal", "localhost"),
        ("http://app.localhost:8080", "instance-app-localhost", "host.docker.internal", "app.localhost"),
        ("http://0.0.0.0:8080", "instance-0-0-0-0", "host.docker.internal", "0.0.0.0"),
        ("tcp://[::1]:9000", "instance-0000-0000-0000-0000-0000-0000-0000-0001", "host.docker.internal", "::1"),
        ("tcp://[2001:db8::7]:9000", "instance-2001-0db8-0000-0000-0000-0000-0000-0007", "2001:db8::7", "2001:db8::7"),
        ("http://host.docker.internal:8080", "host.docker.internal", "host.docker.internal", "host.docker.internal"),
    ],
)
def test_an_address_or_localhost_gets_a_name_on_the_lanes_network_and_this_machine_is_the_host_gateway(url, name, upstream, written):
    (host,) = hosts((url,))
    assert (host.name, host.upstream, host.written) == (name, upstream, written)
    assert shell_hosts((url,)) == ({written: name} if written != name else {})


@pytest.mark.parametrize("url", ["ftp://chal.example.test:21", "tcp://chal.example.test", "http://", "http://bad host/",
                                 "http://chal.example.test:99999", "http://-x-.example.test./", "http://exa$mple.test"])
def test_an_address_no_fence_can_be_built_for_is_refused_with_the_reason(url):
    with pytest.raises(FenceError, match="not an|is not a name"):
        hosts((url,))
    assert shell_hosts((url,)) == {}  # said when the lane's workspace starts, not here


def test_a_proxy_listens_on_exactly_its_hosts_ports_and_carries_each_to_the_same_port():
    (host,) = hosts(("https://chal.example.test", "tcp://chal.example.test:1337"))
    assert json.loads(proxy_config(host)) == {"routes": [{"listen": 443, "host": "chal.example.test", "port": 443},
                                                         {"listen": 1337, "host": "chal.example.test", "port": 1337}]}
    assert egress_proxy.read_config(proxy_config(host)) == ("0.0.0.0", [(443, "chal.example.test", 443), (1337, "chal.example.test", 1337)])
    (here,) = hosts(("http://127.0.0.1:8080",))
    assert json.loads(proxy_config(here))["routes"] == [{"listen": 8080, "host": "host.docker.internal", "port": 8080}]


def test_the_cli_api_hosts_are_one_list_and_each_is_one_https_host():
    assert CLI_API == {"claude": ("https://api.anthropic.com",), "codex": ("https://api.openai.com",)}
    assert [(h.name, h.ports) for h in hosts(CLI_API["claude"] + CLI_API["codex"])] == [("api.anthropic.com", (443,)),
                                                                                       ("api.openai.com", (443,))]


@pytest.mark.parametrize("text, why", [
    ("not json", "not JSON"), ("{}", "no routes"), ('{"routes": []}', "no routes"),
    ('{"routes": [{"listen": 0, "host": "a", "port": 1}]}', "a route is not"),
    ('{"routes": [{"listen": 1, "host": "", "port": 1}]}', "a route is not"),
    ('{"routes": [{"listen": true, "host": "a", "port": 1}]}', "a route is not"),
    ('{"routes": [{"listen": 5, "host": "a", "port": 1}, {"listen": 5, "host": "b", "port": 1}]}', "two routes listen on port 5"),
])
def test_the_proxy_refuses_a_configuration_it_cannot_follow(text, why):
    with pytest.raises(ValueError, match=why):
        egress_proxy.read_config(text)


def test_the_proxy_and_flightdeck_agree_on_the_ready_line_and_the_script_imports_nothing_of_flightdeck():
    assert egress.READY == egress_proxy.READY and egress.SAID == "flightdeck-egress: "
    source = egress.PROXY_SOURCE.read_text(encoding="utf-8")
    assert egress.PROXY_SOURCE == Path(egress_proxy.__file__)
    imports = [line.split()[1] for line in source.splitlines() if line.startswith(("import ", "from "))]
    assert sorted(imports) == ["asyncio", "json", "socket", "sys"]  # the standard library: it runs alone in the lane image


# ---------------------------------------------------------------- the brief


def test_the_brief_tells_a_fenced_lane_the_names_its_shell_must_use_and_only_then():
    challenge = Challenge("c", "Gate", "pwn", 100, description="nc 10.0.0.5 1337")
    urls = ("tcp://10.0.0.5:1337", "http://localhost:8080")
    plain = prompts.brief(challenge, [], urls)
    told = prompts.brief(challenge, [], urls, shell_hosts=shell_hosts(urls))
    assert told.startswith(plain) and "instance-" not in plain
    extra = told[len(plain):]
    assert "use these names instead, on the same ports: 10.0.0.5 is instance-10-0-0-5, localhost is instance-localhost." in extra
    assert prompts.FENCE_CLOSE not in extra  # flightdeck's own words, after the challenge's fence
    assert prompts.brief(challenge, [], urls, shell_hosts={}) == plain
    off = prompts.brief(challenge, [], urls, instance="off", shell_hosts=shell_hosts(urls))
    assert "instance-10-0-0-5" not in off and prompts.OFF_LIMITS in off  # kept off it: no way in is named


# ---------------------------------------------------------------- the proxy, as a process


class _Server(socketserver.ThreadingTCPServer):
    """A server on 127.0.0.1 that answers every connection with its word and notes what it was sent."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, word: str, host: str = "127.0.0.1") -> None:
        self.word = word
        self.seen: list[bytes] = []
        super().__init__((host, 0), _Answer)
        self.port = self.server_address[1]
        threading.Thread(target=self.serve_forever, daemon=True).start()

    def stop(self) -> None:
        self.shutdown()
        self.server_close()


class _Answer(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(5)
        got = b""
        try:
            while b"\r\n\r\n" not in got:
                more = self.request.recv(4096)
                if not more:
                    break
                got += more
        except OSError:
            pass
        self.server.seen.append(got)
        self.request.sendall(f"HTTP/1.0 200 OK\r\n\r\n{self.server.word}\n".encode())


@pytest.fixture
def two_servers():
    allowed, other = _Server("THE-INSTANCE"), _Server("A-SECOND-SERVER")
    yield allowed, other
    allowed.stop()
    other.stop()


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def start_proxy(config: dict) -> subprocess.Popen:
    """The proxy as its container runs it: python -I -c <the script's text> <config>."""
    source = egress.PROXY_SOURCE.read_text(encoding="utf-8")
    return subprocess.Popen([sys.executable, "-I", "-c", source, json.dumps(config)], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)


def ask(port: int, request: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=10) as conn:
        conn.sendall(request)
        conn.shutdown(socket.SHUT_WR)
        got = b""
        while True:
            more = conn.recv(4096)
            if not more:
                return got
            got += more


def test_the_proxy_carries_a_connection_to_the_one_server_its_list_names_whatever_the_lane_sends(two_servers):
    allowed, other = two_servers
    listen = free_port()
    proxy = start_proxy({"bind": "127.0.0.1", "routes": [{"listen": listen, "host": "127.0.0.1", "port": allowed.port}]})
    try:
        assert proxy.stdout.readline().strip() == egress.READY
        assert b"THE-INSTANCE" in ask(listen, b"GET / HTTP/1.0\r\n\r\n")
        # nothing a lane says picks another destination: not a Host header, not a proxy-style
        # request line, not CONNECT. Each is carried to the instance as bytes, which answers it.
        tries = [
            f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{other.port}\r\n\r\n".encode(),
            f"GET http://127.0.0.1:{other.port}/ HTTP/1.1\r\nHost: 127.0.0.1:{other.port}\r\n\r\n".encode(),
            f"CONNECT 127.0.0.1:{other.port} HTTP/1.1\r\nHost: 127.0.0.1:{other.port}\r\n\r\n".encode(),
        ]
        for request in tries:
            answer = ask(listen, request)
            assert b"THE-INSTANCE" in answer and b"A-SECOND-SERVER" not in answer
        assert allowed.seen == [b"GET / HTTP/1.0\r\n\r\n", *tries]  # byte for byte
        assert other.seen == []  # the second server never heard from the proxy
        # and the proxy listens on nothing else: the second server's port is not served by it
        assert proxy.poll() is None
        with pytest.raises(OSError):
            socket.create_connection(("127.0.0.1", free_port()), timeout=2).close()
    finally:
        proxy.kill()
        proxy.wait()


def test_the_proxy_carries_both_directions_until_each_side_is_done(two_servers):
    """A TCP service is not HTTP: what the server says first arrives, and so does a slow second line."""
    ready = threading.Event()
    received: list[bytes] = []

    def talk() -> None:
        conn, _ = listener.accept()
        with conn:
            conn.sendall(b"banner> ")
            received.append(conn.recv(100))
            conn.sendall(b"second line\n")
            ready.wait(5)
            conn.sendall(b"last\n")

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        threading.Thread(target=talk, daemon=True).start()
        listen = free_port()
        proxy = start_proxy({"bind": "127.0.0.1", "routes": [{"listen": listen, "host": "localhost", "port": listener.getsockname()[1]}]})
        try:
            assert proxy.stdout.readline().strip() == egress.READY
            with socket.create_connection(("127.0.0.1", listen), timeout=10) as conn:
                conn.settimeout(10)
                assert conn.recv(100) == b"banner> "  # the server spoke first
                conn.sendall(b"hello\n")
                assert conn.recv(100) == b"second line\n" and received == [b"hello\n"]
                ready.set()
                assert conn.recv(100) == b"last\n" and conn.recv(100) == b""  # the server closed: so does the proxy
        finally:
            proxy.kill()
            proxy.wait()


@pytest.mark.parametrize("config, said", [
    ({"routes": [{"listen": 1, "host": "no-such-host.invalid", "port": 80}], "bind": "127.0.0.1"},
     "flightdeck-egress: cannot find the address of no-such-host.invalid: "),
    ({"routes": []}, "flightdeck-egress: the configuration names no routes"),
])
def test_a_proxy_that_cannot_serve_its_list_says_why_and_exits_instead_of_serving_part_of_it(config, said):
    proxy = start_proxy(config)
    out, _ = proxy.communicate(timeout=60)
    assert proxy.returncode == 2 and out.startswith(said) and egress.READY not in out


def test_a_proxy_whose_port_is_taken_says_so_and_serves_nothing(two_servers):
    allowed, other = two_servers
    proxy = start_proxy({"bind": "127.0.0.1", "routes": [{"listen": free_port(), "host": "127.0.0.1", "port": allowed.port},
                                                         {"listen": other.port, "host": "127.0.0.1", "port": allowed.port}]})
    out, _ = proxy.communicate(timeout=60)
    assert proxy.returncode == 2 and out.startswith(f"flightdeck-egress: cannot listen on port {other.port}: ")
    assert egress.READY not in out and allowed.seen == []


# ---------------------------------------------------------------- what flightdeck asks of docker


@pytest.fixture
def fake_docker(tmp_path, monkeypatch) -> Path:
    """tests/l1_kit.py's stand-in docker first on PATH; the folder its logs are written to."""
    return install_fake_docker(tmp_path, monkeypatch).parent


def logged(folder: Path, name: str) -> list[str]:
    path = folder / name
    return path.read_text().splitlines() if path.exists() else []


LABELS = {"flightdeck.run": "r1", "flightdeck.pid": "7"}
MARKS = "--label flightdeck.pid=7 --label flightdeck.run=r1"
ISOLATED = "-o com.docker.network.bridge.gateway_mode_ipv4=isolated"


def test_a_fence_is_an_internal_network_without_a_gateway_and_a_proxy_per_host_all_with_the_runs_labels(fake_docker):
    fence = Egress("flightdeck-r1-l01", image=FAKE_IMAGE, labels=LABELS)
    assert fence.network == "flightdeck-r1-l01-net"
    run(fence.allow(("https://chal.example.test", "tcp://chal.example.test:1337", "tcp://10.0.0.5:9000")))
    assert logged(fake_docker, "network.log") == [
        f"network create --internal {ISOLATED} {MARKS} flightdeck-r1-l01-net",
        "network inspect --format {{json .IPAM.Config}} flightdeck-r1-l01-net",
        "network connect --alias chal.example.test flightdeck-r1-l01-net flightdeck-r1-l01-egress-1",
        "network connect --alias instance-10-0-0-5 flightdeck-r1-l01-net flightdeck-r1-l01-egress-2",
    ]
    first, second = logged(fake_docker, "proxies.log")
    assert first == (
        f"run -d --init --pull never --name flightdeck-r1-l01-egress-1 {MARKS} --network bridge "
        "--sysctl net.ipv4.ip_forward=0 --cap-drop ALL --cap-add NET_BIND_SERVICE --security-opt no-new-privileges "
        f"--read-only --memory 256m --cpus 1 --pids-limit 64 --entrypoint python3 {FAKE_IMAGE} "
        '{"routes": [{"listen": 443, "host": "chal.example.test", "port": 443}, {"listen": 1337, "host": "chal.example.test", "port": 1337}]}'
    )
    assert "--name flightdeck-r1-l01-egress-2 " in second and "--add-host" not in second
    assert second.endswith('{"routes": [{"listen": 9000, "host": "10.0.0.5", "port": 9000}]}')
    assert fence.allowed == {"chal.example.test": (443, 1337), "instance-10-0-0-5": (9000,)}
    # the script docker is handed is the proxy's own, whole, after -I -c
    args = fence.proxy_args("p", hosts(("tcp://10.0.0.5:9000",))[0])
    assert args[-4:-1] == ["-I", "-c", egress.PROXY_SOURCE.read_text(encoding="utf-8")] and args[args.index("--pull") + 1] == "never"
    run(fence.close())
    assert logged(fake_docker, "rm.log") == ["rm -f flightdeck-r1-l01-egress-1", "rm -f flightdeck-r1-l01-egress-2"]
    assert logged(fake_docker, "network.log")[-1] == "network rm flightdeck-r1-l01-net"
    with pytest.raises(WorkspaceError, match="closed"):
        run(fence.allow(("tcp://chal.example.test:1",)))


def test_a_fence_is_opened_further_without_a_second_network_and_a_host_it_already_reaches_is_not_started_twice(fake_docker):
    fence = Egress("flightdeck-r1-l01", image=FAKE_IMAGE)

    async def main():
        await fence.allow(CLI_API["claude"])
        await fence.allow((*CLI_API["claude"], "http://127.0.0.1:8080"))  # the instance, later
        with pytest.raises(WorkspaceError, match="already reaches 127.0.0.1 on other ports"):
            await fence.allow(("http://127.0.0.1:9090",))
        await fence.close()

    run(main())
    calls = logged(fake_docker, "network.log")
    assert [c.split()[1] for c in calls] == ["create", "inspect", "connect", "connect", "rm"]
    assert calls[3] == "network connect --alias instance-127-0-0-1 flightdeck-r1-l01-net flightdeck-r1-l01-egress-2"
    api, here = logged(fake_docker, "proxies.log")
    assert api.endswith('{"routes": [{"listen": 443, "host": "api.anthropic.com", "port": 443}]}')
    # this machine is reached through docker's host gateway, named on the proxy alone
    assert "--add-host host.docker.internal:host-gateway" in here
    assert here.endswith('{"routes": [{"listen": 8080, "host": "host.docker.internal", "port": 8080}]}')


@pytest.mark.parametrize("setup, urls, why", [
    ({"create.fail": "Error response from daemon: all predefined address pools have been fully subnetted\n"},
     ("tcp://chal.example.test:1337",), "docker network create flightdeck-r1-l01-net failed: .*address pools"),
    ({"create.fail": "Error response from daemon: network with name flightdeck-r1-l01-net already exists\n"},
     ("tcp://chal.example.test:1337",), "network name flightdeck-r1-l01-net is already in use"),
    # a Docker that gives the internal network a gateway (this machine's address) is not the fence
    ({"gateway.txt": '[{"Subnet":"172.30.0.0/16","Gateway":"172.30.0.1"}]\n'}, ("tcp://chal.example.test:1337",),
     r"gave the lane's internal network a gateway \(172.30.0.1\).*gateway_mode_ipv4=isolated"),
    ({"logs.txt": "flightdeck-egress: cannot find the address of chal.example.test: Name or service not known\n"},
     ("tcp://chal.example.test:1337",),
     "the egress proxy for chal.example.test did not start: cannot find the address of chal.example.test: Name or service not known"),
    ({"logs.txt": "Traceback (most recent call last):\nRuntimeError: boom\n"}, ("tcp://chal.example.test:1337",),
     "the egress proxy for chal.example.test did not start: RuntimeError: boom"),  # its container has stopped
    ({}, ("gopher://chal.example.test:70",), "this lane's network cannot be fenced: 'gopher://chal.example.test:70' is not"),
])
def test_when_the_fence_cannot_be_built_the_lane_hears_why_and_gets_no_network_at_all(tmp_path, fake_docker, setup, urls, why):
    for name, text in setup.items():
        (fake_docker / name).write_text(text)
    handout = tmp_path / "handout"
    handout.mkdir()
    box = DockerWorkspace(tmp_path / "lane", handout, image=FAKE_IMAGE, name="flightdeck-r1-l01", reach=urls)
    with pytest.raises(WorkspaceError, match=why):
        run(box.prepare())
    assert logged(fake_docker, "runs.log") == []  # no lane container: never one on bridge instead
    calls = logged(fake_docker, "network.log")
    assert not any(" bridge" in call for call in calls)
    if "already in use" in why or "cannot be fenced" in why:  # someone else's network, or none made: not removed
        assert "network rm flightdeck-r1-l01-net" not in calls
    else:  # what was made is gone again
        assert calls[-1] == "network rm flightdeck-r1-l01-net"
        assert len(logged(fake_docker, "rm.log")) == len(logged(fake_docker, "proxies.log"))


def test_an_image_without_python3_cannot_fence_a_lane_and_the_reason_names_the_fix(tmp_path, monkeypatch):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "docker").write_text(
        "#!/bin/bash\ncase \"$1\" in\n  run) echo 'docker: Error response from daemon: failed to create task: OCI runtime "
        "create failed: exec: \"python3\": executable file not found in $PATH: unknown' >&2; exit 127 ;;\n"
        "  network) [ \"$2\" = rm ] && echo \"$*\" >> \"$(dirname \"$0\")/gone.log\"; [ \"$2\" = inspect ] && echo '[]'; exit 0 ;;\n"
        "  rm) echo \"$*\" >> \"$(dirname \"$0\")/gone.log\"; exit 0 ;;\nesac\n")
    (fake_bin / "docker").chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}{os.environ['PATH']}")
    fence = Egress("flightdeck-r1-l01", image="debian:bookworm-slim")
    with pytest.raises(WorkspaceError, match="image debian:bookworm-slim has no python3, which the proxy that fences a lane's "
                                             "network runs on: build the lane image with `flightdeck image build`"):
        run(fence.allow(("tcp://chal.example.test:1337",)))
    run(fence.close())  # the container docker made and could not start, and the network, are removed
    assert (fake_bin / "gone.log").read_text().splitlines() == ["rm -f flightdeck-r1-l01-egress-1", "network rm flightdeck-r1-l01-net"]


def workspace(tmp_path: Path, **settings) -> DockerWorkspace:
    handout = tmp_path / "handout"
    handout.mkdir(exist_ok=True)
    return DockerWorkspace(tmp_path / "lane", handout, image=FAKE_IMAGE, name="flightdeck-r1-l01", labels=LABELS, **settings)


def test_a_lane_with_nothing_to_reach_has_no_network_and_no_fence(tmp_path, fake_docker):
    box = workspace(tmp_path)
    assert box.egress is None and box.network == "none" and box.shell_hosts == {}

    async def main():
        await box.prepare()
        await box.open_instance()  # nothing to open: nothing happens
        await box.close()

    run(main())
    (started,) = logged(fake_docker, "runs.log")
    assert " --network none " in started and logged(fake_docker, "network.log") == [] and logged(fake_docker, "proxies.log") == []


def test_a_lane_that_may_reach_its_instance_starts_on_its_fenced_network_and_the_fence_goes_with_it(tmp_path, fake_docker):
    box = workspace(tmp_path, reach=("tcp://chal.example.test:1337", "http://127.0.0.1:8080"))
    assert box.network == "flightdeck-r1-l01-net" and box.shell_hosts == {"127.0.0.1": "instance-127-0-0-1"}

    async def main():
        await box.prepare()
        await box.close()

    run(main())
    (started,) = logged(fake_docker, "runs.log")
    assert f" {MARKS} --network flightdeck-r1-l01-net " in started and "bridge" not in started
    calls = logged(fake_docker, "network.log")
    assert calls[0] == f"network create --internal {ISOLATED} {MARKS} flightdeck-r1-l01-net" and calls[-1] == "network rm flightdeck-r1-l01-net"
    assert len(logged(fake_docker, "proxies.log")) == 2
    # the lane's container goes first: docker removes no network a container is on
    assert logged(fake_docker, "rm.log") == ["rm -f flightdeck-r1-l01", "rm -f flightdeck-r1-l01-egress-1", "rm -f flightdeck-r1-l01-egress-2"]


def test_a_lane_that_must_ask_starts_with_no_network_and_joins_its_fence_only_when_it_is_opened(tmp_path, fake_docker):
    box = workspace(tmp_path, later=("tcp://chal.example.test:1337",))
    assert box.network == "none"

    async def main():
        with pytest.raises(WorkspaceError, match="not prepared"):
            await box.open_instance()
        await box.prepare()
        assert logged(fake_docker, "network.log") == [] and logged(fake_docker, "proxies.log") == []  # nothing before the yes
        (started,) = logged(fake_docker, "runs.log")
        assert " --network none " in started
        await box.open_instance()
        assert box.network == "flightdeck-r1-l01-net" and box.reach == ("tcp://chal.example.test:1337",) and box.later == ()
        calls = logged(fake_docker, "network.log")
        await box.open_instance()  # open already: nothing more
        assert logged(fake_docker, "network.log") == calls
        await box.close()
        return calls

    calls = run(main())
    assert calls == [
        f"network create --internal {ISOLATED} {MARKS} flightdeck-r1-l01-net",
        "network inspect --format {{json .IPAM.Config}} flightdeck-r1-l01-net",
        "network connect --alias chal.example.test flightdeck-r1-l01-net flightdeck-r1-l01-egress-1",
        "network disconnect none flightdeck-r1-l01",
        "network connect flightdeck-r1-l01-net flightdeck-r1-l01",
    ]
    assert logged(fake_docker, "network.log")[-1] == "network rm flightdeck-r1-l01-net"


def test_a_coding_agent_lane_under_confirm_keeps_its_api_and_gains_its_instance_on_the_same_network(tmp_path, fake_docker):
    box = workspace(tmp_path, reach=CLI_API["codex"], later=("http://shop.chal.example.test",))

    async def main():
        await box.prepare()
        assert len(logged(fake_docker, "proxies.log")) == 1
        await box.open_instance()
        await box.close()

    run(main())
    calls = logged(fake_docker, "network.log")
    assert not any("disconnect" in call or call.endswith("flightdeck-r1-l01-net flightdeck-r1-l01") for call in calls)  # it was on it already
    assert [p.rsplit(" {", 1)[1] for p in logged(fake_docker, "proxies.log")] == [
        '"routes": [{"listen": 443, "host": "api.openai.com", "port": 443}]}',
        '"routes": [{"listen": 80, "host": "shop.chal.example.test", "port": 80}]}',
    ]


def test_a_fenced_lane_names_no_network_of_its_own_and_a_failed_opening_leaves_it_where_it_was(tmp_path, fake_docker):
    with pytest.raises(ValueError, match="a fenced lane starts on a network of its own, not on 'bridge'"):
        workspace(tmp_path, network="bridge", reach=("tcp://chal.example.test:1337",))
    box = workspace(tmp_path, later=("tcp://chal.example.test:1337",))

    async def main():
        await box.prepare()
        (fake_docker / "create.fail").write_text("Error response from daemon: no address pool left\n")
        with pytest.raises(WorkspaceError, match="docker network create flightdeck-r1-l01-net failed"):
            await box.open_instance()
        assert box.network == "none" and box.later == ("tcp://chal.example.test:1337",)
        await box.close()

    run(main())
    assert not any("connect" in call for call in logged(fake_docker, "network.log"))


# ---------------------------------------------------------------- the driver, under confirm


class _Asked(HostWorkspace):
    """A workspace that notes each open_instance() the driver calls (a docker lane's), and
    fails it when `refuses` is set, as docker would."""

    opened: list[str] = []
    refuses = ""
    shell_hosts = {"10.0.0.5": "instance-10-0-0-5"}

    async def open_instance(self) -> None:
        if _Asked.refuses:
            raise WorkspaceError(_Asked.refuses)
        _Asked.opened.append(self.root.parent.name)


@pytest.mark.parametrize("answer, refuses", [("approve", ""), ("decline", ""),
                                             ("approve", "docker network create flightdeck-r1-l01-net failed: no pool left")])
def test_the_driver_opens_a_lanes_fence_on_the_players_yes_only_and_says_when_it_could_not(tmp_path, answer, refuses):
    from fake_model import FakeModelServer, text_reply
    from test_agent_driver import Lab, last_user, until

    from ctf_flightdeck.core import interventions as iv

    _Asked.opened, _Asked.refuses = [], refuses
    server = FakeModelServer([text_reply("done"), text_reply("done"), text_reply("done")])

    async def main():
        with server:
            lab = Lab(tmp_path, server, urls={"note": ("tcp://10.0.0.5:1337",)}, instance="confirm")
            lab.driver.workspaces = lambda lane, ch: _Asked(tmp_path / "runs" / lane.id / "work", lab.handouts[ch.id])
            lab.release()
            lane = lab.lane()
            await until(lambda: lane.pending is not None, "the lane asking for the instance")
            await asyncio.sleep(0.2)
            assert _Asked.opened == [] and server.requests == []  # nothing opened, nothing asked of the model, before the answer
            assert lab.deck.apply(iv.Approve(lane.id) if answer == "approve" else iv.Decline(lane.id)).ok
            await until(lambda: len(server.requests) >= 1, "the lane's first model call")
            state = lab.driver.runs[lane.id].instance
            notes = [a.text for a in lane.actions if a.kind is ActionKind.NOTE]
            first = server.requests[0]["json"]["messages"]
            await lab.finish()
            return lane, state, notes, first, last_user(server.requests[0])

    lane, state, notes, first, told = run(main())
    # the brief names what the shell must call a host given by address (the workspace's shell_hosts)
    assert "10.0.0.5 is instance-10-0-0-5" in first[1]["content"]
    if answer == "decline":
        assert _Asked.opened == [] and state == "declined"
    elif refuses:
        assert _Asked.opened == [] and state == "failed"
        assert f"could not open the network to the live instance: {refuses}" in notes
        assert f"flightdeck could not open the network to the live instance ({refuses}): work from the handout." in told
    else:
        assert _Asked.opened == [lane.id] and state == "open"  # once, before the lane's first model call
        assert "The player allowed you to use the live instance now." in told


# ---------------------------------------------------------------- what a killed flightdeck leaves


def test_a_killed_runs_fence_is_found_and_removed_with_its_containers_networks_last(tmp_path, monkeypatch):
    from test_leftovers import RUN, killed_flightdeck, ps_line

    fake_bin = install_fake_docker(tmp_path, monkeypatch).parent
    gone, me = killed_flightdeck(), leftovers.Owner.this()
    (fake_bin / "ps.txt").write_text(ps_line("a" * 64, f"flightdeck-{RUN}-l01", RUN, gone)
                                     + ps_line("b" * 64, f"flightdeck-{RUN}-l01-egress-1", RUN, gone))
    (fake_bin / "networks.txt").write_text(
        ps_line("c" * 64, f"flightdeck-{RUN}-l01-net", RUN, gone)
        + ps_line("d" * 64, "flightdeck-now-l01-net", "now", me)  # a run that still runs
        + f"{'e' * 64}\tnot-ours\t{RUN}\t\t\t\t\t\n"  # without the rest of flightdeck's labels
    )
    found = leftovers.sweep(None, docker=True, clean=False)
    assert found.found == (f"run {RUN} did not shut down (its flightdeck was killed, or the machine stopped) and left running: "
                           f"its container flightdeck-{RUN}-l01; its container flightdeck-{RUN}-l01-egress-1; "
                           f"its network flightdeck-{RUN}-l01-net",)
    assert not (fake_bin / "rm.log").exists()
    assert logged(fake_bin, "network.log") == [f"network ls --no-trunc --filter label=flightdeck.run --format {leftovers._NETWORK_FORMAT}"]
    swept = leftovers.sweep(None, docker=True, clean=True)
    assert swept.done == (f"run {RUN} did not shut down (its flightdeck was killed, or the machine stopped); removed what it "
                          f"left running: its container flightdeck-{RUN}-l01; its container flightdeck-{RUN}-l01-egress-1; "
                          f"its network flightdeck-{RUN}-l01-net",)
    assert logged(fake_bin, "rm.log") == [f"rm -f {'a' * 64}", f"rm -f {'b' * 64}"]
    assert logged(fake_bin, "network.log")[-1] == f"network rm {'c' * 64}"  # only the killed run's, by its id
    assert sum(" rm " in f" {call} " for call in logged(fake_bin, "network.log")) == 1


def test_when_the_networks_cannot_be_listed_nothing_of_dockers_is_removed_and_the_sweep_says_so(tmp_path, monkeypatch):
    from test_leftovers import RUN, killed_flightdeck, ps_line

    fake_bin = install_fake_docker(tmp_path, monkeypatch).parent
    (fake_bin / "ps.txt").write_text(ps_line("a" * 64, f"flightdeck-{RUN}-l01", RUN, killed_flightdeck()))
    (fake_bin / "networks.fail").write_text("Cannot connect to the Docker daemon\n")
    swept = leftovers.sweep(None, docker=True, clean=True)
    assert swept.done == () and not (fake_bin / "rm.log").exists()
    assert swept.alone == ("the containers of runs that did not shut down could not be looked for (Cannot connect to the "
                           "Docker daemon); once Docker runs, `flightdeck doctor --clean` removes them",)


# ---------------------------------------------------------------- the real thing


def _lane_image_skip_reason() -> str | None:
    reason = docker_unavailable()
    if reason:
        return reason
    probe = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", LANE_IMAGE], capture_output=True, timeout=60)
    if probe.returncode != 0:
        return (f"the lane image {LANE_IMAGE} is not present locally (`flightdeck image build` makes it; these tests never "
                "build or pull it)")
    return None


def _this_machine() -> str:
    """The address two test servers listen on so that a proxy on Docker's bridge network can
    reach them: 127.0.0.1 where Docker runs in a VM that forwards to this machine's loopback
    (Docker Desktop on macOS); elsewhere the bridge network's gateway, this machine's address
    on it."""
    if sys.platform == "darwin":
        return "127.0.0.1"
    out = subprocess.run(["docker", "network", "inspect", "bridge", "--format", "{{(index .IPAM.Config 0).Gateway}}"],
                         capture_output=True, text=True, timeout=60)
    return out.stdout.strip()


@pytest.fixture(scope="module")
def lane_image():
    reason = _lane_image_skip_reason()
    if reason:
        pytest.skip(f"not run: {reason}")


@pytest.fixture
def real_servers(lane_image):
    address = _this_machine()
    try:
        allowed, other = _Server("THE-INSTANCE", address), _Server("A-SECOND-SERVER", address)
    except OSError as exc:
        pytest.skip(f"not run: cannot listen on {address or 'the bridge gateway'}, where a container reaches this machine: {exc}")
    yield address, allowed, other
    allowed.stop()
    other.stop()


@pytest.fixture
def lane_name(lane_image):
    """A fresh lane name; its container, proxies and network are removed after the test whatever happened."""
    name = f"flightdeck-test-{uuid.uuid4().hex[:12]}"
    yield name
    for extra in ("", "-egress-1", "-egress-2"):
        subprocess.run(["docker", "rm", "-f", name + extra], capture_output=True, timeout=60)
    subprocess.run(["docker", "network", "rm", f"{name}-net"], capture_output=True, timeout=60)


def docker(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=60)


def fetch(box: DockerWorkspace, host: str, port: int) -> tuple[int | None, str]:
    """From the lane's shell: open host:port, send an HTTP request, print what comes back."""
    command = (f"exec 3<>/dev/tcp/{host}/{port} && printf 'GET / HTTP/1.0\\r\\n\\r\\n' >&3 && cat <&3")
    result = run(box.run(command, timeout=20))
    return result.exit_code, result.output.decode("utf-8", "replace")


def test_a_real_lane_reaches_its_instance_and_not_a_second_server_on_this_machine(tmp_path, real_servers, lane_name):
    address, allowed, other = real_servers
    handout = tmp_path / "handout"
    handout.mkdir()
    box = DockerWorkspace(tmp_path / "lane", handout, image=LANE_IMAGE, name=lane_name, reach=(f"http://{address}:{allowed.port}",),
                          labels={"flightdeck.run": "fence-test"})
    (name,) = box.shell_hosts.values()
    run(box.prepare())
    try:
        # its only network is the fence's: an internal one, with the run's label, and not bridge
        networks = json.loads(docker("inspect", "--format", "{{json .NetworkSettings.Networks}}", lane_name).stdout)
        assert list(networks) == [f"{lane_name}-net"]
        made = json.loads(docker("network", "inspect", f"{lane_name}-net").stdout)[0]
        assert made["Internal"] is True and made["Labels"] == {"flightdeck.run": "fence-test"}
        assert not any(config.get("Gateway") for config in made["IPAM"]["Config"])
        proxy = json.loads(docker("inspect", f"{lane_name}-egress-1").stdout)[0]
        assert proxy["Config"]["Labels"]["flightdeck.run"] == "fence-test" and proxy["Config"]["Image"] == LANE_IMAGE
        assert sorted(proxy["NetworkSettings"]["Networks"]) == sorted(["bridge", f"{lane_name}-net"])

        code, said = fetch(box, name, allowed.port)
        assert code == 0 and "THE-INSTANCE" in said  # the instance, by the name the brief gives the lane
        assert len(allowed.seen) == 1

        # the second server: not through the proxy (it listens on the instance's port only), not
        # by this machine's address, not by docker's name for this machine
        for host in (name, address, "host.docker.internal", proxy["NetworkSettings"]["Networks"]["bridge"]["IPAddress"]):
            code, said = fetch(box, host, other.port)
            assert code != 0 and "A-SECOND-SERVER" not in said, (host, said)
        # and the instance's own port is reached only through the proxy, never directly
        code, said = fetch(box, address, allowed.port)
        if address != "127.0.0.1":  # (the lane's own loopback is the lane's: nothing listens there)
            assert code != 0 and "THE-INSTANCE" not in said
        assert other.seen == [] and len(allowed.seen) == 1

        # no name outside resolves (the internal network's DNS forwards nothing), and no address routes
        looked = run(box.run("getent hosts example.com; echo status=$?", timeout=30))
        assert looked.output.decode().strip() == "status=2"
        code, said = fetch(box, "192.0.2.1", 80)  # TEST-NET-1: an address no one has
        assert code != 0
        inside = run(box.run(f"getent hosts {name}", timeout=30)).output.decode()
        assert inside.split()[1:] == [name]  # the one name it knows: the proxy
    finally:
        run(box.close())
    assert docker("container", "inspect", lane_name).returncode != 0
    assert docker("container", "inspect", f"{lane_name}-egress-1").returncode != 0
    assert docker("network", "inspect", f"{lane_name}-net").returncode != 0


def test_a_real_lane_that_must_ask_reaches_nothing_until_it_is_opened_and_then_only_its_instance(tmp_path, real_servers, lane_name):
    address, allowed, other = real_servers
    handout = tmp_path / "handout"
    handout.mkdir()
    box = DockerWorkspace(tmp_path / "lane", handout, image=LANE_IMAGE, name=lane_name, later=(f"tcp://{address}:{allowed.port}",))
    (name,) = box.shell_hosts.values()
    run(box.prepare())
    try:
        assert docker("network", "inspect", f"{lane_name}-net").returncode != 0  # nothing made before the yes
        code, _ = fetch(box, name, allowed.port)
        assert code != 0 and allowed.seen == []
        run(box.open_instance())
        networks = json.loads(docker("inspect", "--format", "{{json .NetworkSettings.Networks}}", lane_name).stdout)
        assert list(networks) == [f"{lane_name}-net"]
        code, said = fetch(box, name, allowed.port)
        assert code == 0 and "THE-INSTANCE" in said
        code, said = fetch(box, name, other.port)
        assert code != 0 and "A-SECOND-SERVER" not in said and other.seen == []
    finally:
        run(box.close())
    assert docker("network", "inspect", f"{lane_name}-net").returncode != 0


def test_a_real_fence_left_by_a_killed_flightdeck_is_listed_and_removed_by_the_sweep(lane_image, lane_name):
    from test_leftovers import killed_flightdeck

    marks = leftovers.labels("fence-left", killed_flightdeck())
    fence = Egress(lane_name, image=LANE_IMAGE, labels=marks)
    run(fence.allow(("tcp://localhost:9",)))  # never closed: its flightdeck "was killed"
    assert docker("network", "inspect", f"{lane_name}-net").returncode == 0
    found = leftovers.sweep(None, docker=True, clean=False)
    assert found.found == ("run fence-left did not shut down (its flightdeck was killed, or the machine stopped) and left "
                           f"running: its container {lane_name}-egress-1; its network {lane_name}-net",)
    swept = leftovers.sweep(None, docker=True, clean=True)
    assert swept.done == ("run fence-left did not shut down (its flightdeck was killed, or the machine stopped); removed what "
                          f"it left running: its container {lane_name}-egress-1; its network {lane_name}-net",)
    assert docker("container", "inspect", f"{lane_name}-egress-1").returncode != 0
    assert docker("network", "inspect", f"{lane_name}-net").returncode != 0
    assert leftovers.sweep(None, docker=True, clean=False) == leftovers.Swept()
