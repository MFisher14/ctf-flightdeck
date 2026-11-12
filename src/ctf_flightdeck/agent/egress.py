"""The fence round a Docker lane's network (P9): it reaches its challenge's own instance and,
for a coding-agent lane, its CLI's API. Nothing else: not Docker's open bridge network.

How it is built, per lane (Egress):

- an internal Docker network (`docker network create --internal`, with no gateway address:
  gateway_mode_ipv4=isolated), which routes nowhere: not to the internet, not to this
  machine, not to other containers' networks. Its embedded DNS answers only for the names
  on it and forwards nothing, so a name lookup is not a way out either;
- for each host the lane may reach, a small proxy container (egress_proxy.py: standard
  library Python, run from the lane image, so no image of its own is pulled or built) on
  Docker's bridge network and on the lane's network. It listens on exactly the ports the
  challenge's `urls` name for that host and carries each connection, byte for byte, to that
  host and port. It is on the lane's network under the host's own name (a network alias),
  so `nc chal.example.org 1337` or `curl https://chal.example.org/` in the lane works as
  the challenge wrote it, TLS and all: the lane's name lookup finds the proxy.

An address is not a name, so an instance the challenge gives by IP address, or as localhost,
cannot be reached as written: the lane's network has no route to it. Such a host gets a name
on the lane's network instead (instance-10-0-0-5 for 10.0.0.5, instance-localhost), on the
same ports, and the lane's brief says so (shell_hosts()). localhost and loopback addresses
mean this machine: the proxy reaches it through Docker's host gateway (host.docker.internal).

What it does not do (the player's guide says the same): no UDP, no ping, no port of the
instance's host that `urls` does not list; a redirect or a link to another host goes nowhere;
a proxy finds its host's addresses once, when it starts.

Everything started here carries the run's labels (leftovers.labels()), so what a killed
flightdeck leaves is found and removed by the next play or `doctor --clean`. Nothing here
falls back to the bridge network: when Docker cannot build the fence, the lane gets a
WorkspaceError that says why.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .workspace import WorkspaceError, _docker, _docker_label, _first_line

# What a coding-agent CLI must reach to work at all: its model API, as flightdeck runs it in a
# container (claude with ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN, codex with
# CODEX_API_KEY: agent/external.py). The one list of hosts a fenced lane reaches besides its
# challenge's instance.
CLI_API: dict[str, tuple[str, ...]] = {
    "claude": ("https://api.anthropic.com",),
    "codex": ("https://api.openai.com",),
}

HOST_GATEWAY = "host.docker.internal"  # this machine, from a container on the bridge network
ISOLATED = "com.docker.network.bridge.gateway_mode_ipv4=isolated"
PROXY_SOURCE = Path(__file__).with_name("egress_proxy.py")
READY = "flightdeck-egress ready"  # egress_proxy.READY: the line a proxy prints once it listens
SAID = "flightdeck-egress: "  # what starts the line a proxy prints before it gives up
READY_TIMEOUT = 20.0  # seconds a proxy has to say READY
_POLL = 0.2
_NAME = re.compile(r"[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*")
_DEFAULT_PORT = {"http": 80, "https": 443}


class FenceError(ValueError):
    """An instance address no fence can be built for; the message says which and why."""


@dataclass(frozen=True)
class Host:
    """One host a fenced lane may reach."""

    name: str  # what it is called on the lane's network (the proxy's alias there)
    upstream: str  # where its proxy connects: the host itself, or HOST_GATEWAY for this machine
    ports: tuple[int, ...]
    written: str  # the host as the challenge writes it: `name`, unless that is an address or localhost

    @property
    def renamed(self) -> bool:
        return self.written != self.name


def hosts(urls: Sequence[str]) -> tuple[Host, ...]:
    """The hosts, and the ports of each, that `urls` name (http://, https:// and tcp://, as the
    board loader writes them), in the order first named. FenceError for a URL that is not one
    of those, or a host that no name on a Docker network can stand for."""
    found: dict[str, tuple[str, str, list[int]]] = {}
    for url in urls:
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError:
            raise FenceError(f"{url!r} is not an instance address") from None
        port = port if port is not None else _DEFAULT_PORT.get(parts.scheme)
        if parts.scheme not in ("http", "https", "tcp") or not parts.hostname or not port:
            raise FenceError(f"{url!r} is not an http, https or tcp instance address with a host and a port")
        name, upstream, written = _named(parts.hostname)
        ports = found.setdefault(name, (upstream, written, []))[2]
        if port not in ports:
            ports.append(port)
    return tuple(Host(name, upstream, tuple(sorted(ports)), written) for name, (upstream, written, ports) in found.items())


def _named(host: str) -> tuple[str, str, str]:
    """(its name on the lane's network, where its proxy connects, the host as written)."""
    host = host.lower().removesuffix(".")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        here = address.is_loopback or address.is_unspecified
        digits = address.exploded.replace(".", "-").replace(":", "-")
        return f"instance-{digits}", HOST_GATEWAY if here else str(address), str(address)
    if not _NAME.fullmatch(host) or len(host) > 253:
        raise FenceError(f"the instance host {host[:80]!r} is not a name a Docker network can carry")
    if host == "localhost" or host.endswith(".localhost"):
        return "instance-" + host.replace(".", "-"), HOST_GATEWAY, host
    return host, host, host


def shell_hosts(urls: Sequence[str]) -> dict[str, str]:
    """{the host as the challenge writes it: its name in a fenced lane's container} for each
    host of `urls` that is not reached as written (an IP address, localhost). {} when `urls`
    cannot be fenced: the lane's workspace says so when it starts."""
    try:
        return {host.written: host.name for host in hosts(urls) if host.renamed}
    except FenceError:
        return {}


def proxy_config(host: Host) -> str:
    """The configuration of `host`'s proxy (egress_proxy.read_config): each of its ports, to the
    same port of the host."""
    return json.dumps({"routes": [{"listen": port, "host": host.upstream, "port": port} for port in host.ports]})


def _no_python(said: str) -> bool:
    """Whether docker, or the container's init, said the image has no python3 to start: the
    OCI runtime's `exec: "python3": executable file not found in $PATH`, or tini's `exec
    python3 failed: No such file or directory`."""
    return "python3" in said and ("executable file not found" in said or "No such file or directory" in said)


class Egress:
    """A lane's fenced network: `network`, an internal Docker network, and a proxy container
    for each host the lane may reach (see the module docstring).

    allow(urls) lets the network reach the hosts and ports `urls` name, making the network at
    its first call; it can be called again for more (a lane the player allows onto its
    instance later). close() removes the proxies and the network, after whatever allow() was
    still starting has ended. `name` is the lane's container name: the network is
    <name>-net and the proxies <name>-egress-1, -2, ..."""

    def __init__(self, name: str, *, image: str, labels: Mapping[str, str] | None = None) -> None:
        self.name = name
        self.network = f"{name}-net"
        self.image = image
        self.labels = dict(sorted(_docker_label(key, value) for key, value in (labels or {}).items()))
        self.allowed: dict[str, tuple[int, ...]] = {}  # a host's name on the network -> its ports
        self._made = False  # the network is ours, or may be: close() removes it
        self._proxies: list[str] = []  # the proxy containers started, or that may have been
        self._pending: list[asyncio.Future[None]] = []
        self._closed = False

    async def allow(self, urls: Sequence[str]) -> None:
        """Let the lane's network reach what `urls` name. WorkspaceError, with the reason, when
        it cannot be done: the lane then reaches no more than before."""
        if self._closed:
            raise WorkspaceError("workspace is closed")
        try:
            wanted = hosts(urls)
        except FenceError as exc:
            raise WorkspaceError(f"this lane's network cannot be fenced: {exc}") from None
        # docker carries on with a command even if this lane is cancelled, so the work is a
        # task of its own, which close() waits for before it removes what the task made
        task = asyncio.ensure_future(self._allow(wanted))
        self._pending.append(task)
        await asyncio.shield(task)

    async def _allow(self, wanted: Sequence[Host]) -> None:
        if not self._made:
            await self._make_network()
        for host in wanted:
            have = self.allowed.get(host.name)
            if have is not None:
                if set(host.ports) <= set(have):
                    continue
                raise WorkspaceError(f"this lane's network already reaches {host.written} on other ports: "
                                     "a host's ports are opened together")
            await self._start_proxy(host)
            self.allowed[host.name] = host.ports

    def network_args(self) -> list[str]:
        """The `docker network create` arguments of the lane's network."""
        labels = [arg for key, value in self.labels.items() for arg in ("--label", f"{key}={value}")]
        return ["network", "create", "--internal", "-o", ISOLATED, *labels, self.network]

    def proxy_args(self, proxy: str, host: Host) -> list[str]:
        """The `docker run` arguments of `host`'s proxy container: on the bridge network (it
        joins the lane's once it has found its host), from the lane image, never pulled; it
        does not forward packets (only the connections its script carries), has no
        capability but binding a low port, and can write nowhere."""
        labels = [arg for key, value in self.labels.items() for arg in ("--label", f"{key}={value}")]
        gateway = ["--add-host", f"{HOST_GATEWAY}:host-gateway"] if host.upstream == HOST_GATEWAY else []
        return [
            "run", "-d", "--init", "--pull", "never",
            "--name", proxy,
            *labels,
            "--network", "bridge",
            *gateway,
            "--sysctl", "net.ipv4.ip_forward=0",
            "--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE",
            "--security-opt", "no-new-privileges",
            "--read-only",
            "--memory", "256m", "--cpus", "1", "--pids-limit", "64",
            "--entrypoint", "python3",
            self.image, "-I", "-c", PROXY_SOURCE.read_text(encoding="utf-8"), proxy_config(host),
        ]

    async def _make_network(self) -> None:
        self._made = True
        code, out = await _docker(*self.network_args())
        if code != 0:
            if "already exists" in out:
                self._made = False  # someone else's network: never remove it
                raise WorkspaceError(f"network name {self.network} is already in use (docker network rm {self.network} "
                                     "if it is a leftover)")
            raise WorkspaceError(f"docker network create {self.network} failed: {_first_line(out)}")
        # A Docker that does not know the isolated gateway mode takes the option and gives the
        # network a gateway all the same: an address of this machine, which the lane could
        # reach. That is not the fence, so it is refused rather than used.
        code, out = await _docker("network", "inspect", "--format", "{{json .IPAM.Config}}", self.network)
        if code != 0:
            raise WorkspaceError(f"docker network inspect {self.network} failed: {_first_line(out)}")
        try:
            ranges = json.loads(out)
            gateways = [str(item["Gateway"]) for item in ranges or [] if item.get("Gateway")]
        except (ValueError, TypeError, AttributeError):
            raise WorkspaceError(f"docker network inspect {self.network} did not say whether the network has a gateway: "
                                 f"{_first_line(out)}") from None
        if gateways:
            raise WorkspaceError(
                f"Docker gave the lane's internal network a gateway ({_first_line(' '.join(gateways))}), through which the lane could "
                "reach this machine: fencing a lane's network needs a Docker Engine that knows internal networks "
                "without one (the bridge option gateway_mode_ipv4=isolated): update Docker"
            )

    async def _start_proxy(self, host: Host) -> None:
        proxy = f"{self.name}-egress-{len(self._proxies) + 1}"
        try:
            args = self.proxy_args(proxy, host)
        except OSError as exc:
            raise WorkspaceError(f"flightdeck's egress proxy script cannot be read: {exc.strerror or exc}") from None
        self._proxies.append(proxy)
        code, out = await _docker(*args)
        if code != 0:
            if "already in use" in out:
                self._proxies.remove(proxy)  # someone else's container: never remove it
                raise WorkspaceError(f"container name {proxy} is already in use (docker rm -f {proxy} if it is a leftover)")
            if _no_python(out):
                raise WorkspaceError(self._python_missing())
            raise WorkspaceError(f"the egress proxy for {host.written} could not start: {_first_line(out)}")
        loop = asyncio.get_running_loop()
        deadline = loop.time() + READY_TIMEOUT
        stopped = False
        while True:
            code, out = await _docker("logs", proxy)
            lines = [line.strip() for line in out.splitlines() if line.strip()]
            if code == 0 and READY in lines:
                break
            said = next((line.removeprefix(SAID) for line in lines if line.startswith(SAID)), "")
            if code == 0 and not said and not stopped:
                state, running = await _docker("container", "inspect", "--format", "{{.State.Running}}", proxy)
                if state != 0 or running.strip() != "true":
                    stopped = True  # it ended: what it printed last is read once more, now that it is all there
                    continue
            if _no_python(out):
                raise WorkspaceError(self._python_missing())
            if code != 0 or said or stopped or loop.time() >= deadline:
                why = (_first_line(out) if code != 0 else said if said
                       else (lines[-1] if lines else "its container stopped") if stopped
                       else f"it was not ready within {READY_TIMEOUT:.0f} s")
                raise WorkspaceError(f"the egress proxy for {host.written} did not start: {_first_line(why)}")
            await asyncio.sleep(_POLL)
        # only now: on the lane's network the proxy answers to the host's own name, and it has
        # already found the host's real addresses
        code, out = await _docker("network", "connect", "--alias", host.name, self.network, proxy)
        if code != 0:
            raise WorkspaceError(f"docker network connect {self.network} {proxy} failed: {_first_line(out)}")

    def _python_missing(self) -> str:
        return (f"image {self.image} has no python3, which the proxy that fences a lane's network runs on: "
                "build the lane image with `flightdeck image build`, or set [lanes] image to one that has it")

    async def close(self) -> None:
        """Remove the proxies and the network. The lane's own container must be gone already
        (docker removes no network a container is on)."""
        self._closed = True
        for task in self._pending:
            try:
                await asyncio.shield(task)  # still starting something: let it end first
            except Exception:  # it failed: whatever it left is removed below
                pass
        self._pending = []
        problems = []
        for proxy in list(self._proxies):
            code, out = await _docker("rm", "-f", proxy)
            if code != 0 and "No such container" not in out:
                problems.append(f"docker rm -f {proxy} failed: {_first_line(out)}")
            else:
                self._proxies.remove(proxy)
        if self._made and not problems:
            code, out = await _docker("network", "rm", self.network)
            if code != 0 and "not found" not in out and "No such network" not in out:
                problems.append(f"docker network rm {self.network} failed: {_first_line(out)}")
            else:
                self._made = False
        if problems:
            raise WorkspaceError("; ".join(problems))
