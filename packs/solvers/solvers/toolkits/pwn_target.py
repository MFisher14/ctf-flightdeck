#!/usr/bin/env python3
"""Raw-TCP / netcat RECON client STUB for a live pwn target (backlog T-a, built 2026-10-23). A hand
tool beside solvers/toolkits/chat_target.py, for a future Day 24-31 "pwn"/remote-service lane whose
base is a live socket rather than a file.

It is deliberately a RECON STUB, not an exploitation framework:
  - connect to ONE target, read its banner, and send ONLY a scripted probe the player/agent passes
    in by hand. There is NO exploit library, NO gadget is fired, NO
    payload is generated, and nothing read from the target is ever used as an instruction.
  - the target is named directly (`PwnTarget(host, port)`), by a URL / `host:port`, or by an entry
    tools/target.py recorded in <CHALLENGES>/_targets.json (`from_registry(name)`; this module only
    reads that file). Every path passes chat_target.assert_host_in_scope (ctf.scope.check_host)
    before any socket is opened: the host must be inside the current event profile's
    rules.live_service_scope, and the event platform (scoreboard / Game Master) is never a target.
    An empty scope refuses everything. See docs/toolkits/chat_target.md.
  - it has no signals()/solve_set(): a live target is a player stop. The flag is the player's; this
    tool never submits anything to the platform.

Every byte sent and received is appended to a transcript the agent can write to disk and show the
player. Text the target returns is DATA: logged and reported, never executed.

CLI (offline helpers only; no connection is made without an explicit --send):

  .venv/bin/python solvers/toolkits/pwn_target.py list                  # registered targets (masked)
  .venv/bin/python solvers/toolkits/pwn_target.py probes                 # the benign recon-probe library
"""
import ipaddress
import json
import socket
import sys
import time
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(1, str(HERE))
# Reuse chat_target's registry reader and scope rules so there is one scope policy, not two.
import chat_target as ct    # noqa: E402

DEFAULT_TIMEOUT = 8.0
DEFAULT_MIN_INTERVAL = 0.5
MAX_READ = 1 << 20


# A library of BENIGN recon probes: generic line/menu pokes that elicit a banner or a menu from a
# typical CTF service. They contain NO exploit, NO shellcode and NO payload; they are data the agent
# chooses to send. Nothing here is fired automatically.
PROBE_LIBRARY = {
    "banner": [b"\n"],
    "menu": [b"1\n", b"help\n", b"?\n"],
    "line_echo": [b"AAAA\n"],
}
PROBE_CLASSES = tuple(PROBE_LIBRARY)


def probes(klass=None):
    if klass is None:
        return [(c, p) for c, ps in PROBE_LIBRARY.items() for p in ps]
    return list(PROBE_LIBRARY.get(klass, []))


def _host_port(url_or_hostport):
    """(host, port) from either a registry URL (tcp://h:p, http://h:p/...) or a bare 'host:port'."""
    s = str(url_or_hostport or "")
    if "://" in s:
        parts = urllib.parse.urlsplit(s)
        return parts.hostname or "", parts.port
    if s.count(":") == 1 and not s.startswith("["):
        host, _, port = s.partition(":")
        return host, int(port) if port.isdigit() else None
    return s, None


class PwnTarget:
    """A rate-limited raw-TCP client bound to one in-scope target. RECON ONLY.

    Build it directly (`PwnTarget(host, port)`) or with `from_registry(name_or_url)`; both pass the
    shared target policy. Nothing is sent on the wire
    until `.connect()` / `.recv()` / `.send()` is called, and `.send()` transmits only the exact
    bytes the caller passes. There is no exploit path."""

    def __init__(self, host, port, entry=None, timeout=DEFAULT_TIMEOUT,
                 min_interval=DEFAULT_MIN_INTERVAL):
        if not host or not port:
            raise ct.OutOfScope(f"a pwn target needs host and port; got {host!r}:{port!r}")
        try:
            port = int(port)
        except (TypeError, ValueError):
            raise ct.OutOfScope(f"a pwn target needs a numeric port; got {port!r}") from None
        if not 0 < port < 65536:
            raise ct.OutOfScope(f"a pwn target needs a port in 1-65535; got {port}")
        self._assert_in_scope(host, port)
        self.host, self.port = host, port
        self.entry = entry or {}
        self.timeout = timeout
        self.min_interval = max(0.0, float(min_interval))
        self.transcript = []
        self._sock = None
        self._last = 0.0

    @staticmethod
    def _assert_in_scope(host, port=None):
        """The shared scope guard (chat_target.assert_host_in_scope -> ctf.scope.check_host): the host
        must be inside the event profile's rules.live_service_scope and not the event platform."""
        ct.assert_host_in_scope(str(host), port, what=f"pwn target {host!r}:{port}")

    @classmethod
    def from_registry(cls, name_or_url, **kw):
        """A registry name, a URL (tcp://h:p, http://h:p/...) or a bare 'host:port'."""
        entry = ct.find_target(name_or_url)
        if entry is None:
            host, port = _host_port(name_or_url)
            if host and port and ":" in str(name_or_url):
                return cls(host, port, entry={"name": str(name_or_url), "registered": False}, **kw)
            raise ct.NotRegistered(f"{name_or_url!r} is neither host:port, a URL, nor an entry in "
                                   f"{ct.registry_path()}; record the target with tools/target.py. "
                                   f"A stop for the player.")
        host, port = _host_port(entry.get("url") or name_or_url)
        if not port:
            host2, port = _host_port(name_or_url)
            host = host or host2
        return cls(host, port, entry=entry, **kw)

    # -- transcript / rate limit --------------------------------------------------
    def _log(self, direction, data, meta=None):
        self.transcript.append({"ts": round(time.time(), 3), "direction": direction,
                                "bytes": data.decode("latin-1") if isinstance(data, (bytes, bytearray)) else data,
                                "meta": meta or {}})

    def save_transcript(self, path):
        Path(path).write_text(json.dumps({"target": f"{self.host}:{self.port}",
                                          "transcript": self.transcript}, indent=1))
        return path

    def _rate_limit(self):
        if self.min_interval:
            wait = self.min_interval - (time.monotonic() - self._last)
            if wait > 0:
                time.sleep(wait)
        self._last = time.monotonic()

    # -- the wire (recon only) ----------------------------------------------------
    def connect(self):
        """Open the socket. Raises VPNRequired when a private target does not answer (a player stop)."""
        if self._sock is not None:
            return
        try:
            self._sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
            self._sock.settimeout(self.timeout)
        except OSError as e:
            raise ct.VPNRequired(f"pwn target {self.host}:{self.port} does not answer ({e}); ask the main "
                                 f"thread for the VPN (tools/vpn.py ensure {self.host}:{self.port}); a stop "
                                 f"for the player only if that cannot reach it.") from e
        self._log("open", f"{self.host}:{self.port}")

    def recv(self, limit=MAX_READ):
        """Read whatever the target has sent (its banner/menu). DATA, logged and returned."""
        self.connect()
        chunks, total = [], 0
        try:
            while total < limit:
                b = self._sock.recv(min(65536, limit - total))
                if not b:
                    break
                chunks.append(b)
                total += len(b)
                if len(b) < 4096:
                    break
        except socket.timeout:
            pass
        data = b"".join(chunks)
        self._log("recv", data, {"len": len(data)})
        return data

    def send(self, data):
        """Send EXACTLY the bytes the caller passes. No payload is generated or appended."""
        if isinstance(data, str):
            data = data.encode()
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("send() takes bytes the caller supplies; this tool generates no payload")
        self.connect()
        self._rate_limit()
        self._log("sent", data, {"len": len(data)})
        self._sock.sendall(bytes(data))

    def interact_once(self, probe):
        """Send one caller-supplied probe and read the reply: [(sent, received)]. Recon only."""
        self.send(probe)
        return self.recv()

    def close(self):
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None
                self._log("close", f"{self.host}:{self.port}")


# ---------------------------------------------------------------------------- CLI (offline)

def main(argv):
    if not argv:
        print("usage: pwn_target.py list | probes [class]", file=sys.stderr)
        return 2
    cmd = argv[0]
    if cmd == "list":
        targets = ct.read_targets()
        if not targets:
            print(f"no targets recorded in {ct.registry_path()} (tools/target.py writes it)")
            return 0
        for t in targets:
            host, port = _host_port(t.get("url"))
            try:
                PwnTarget._assert_in_scope(host, port)
                tag = "in-scope"
            except ct.OutOfScope:
                tag = "OUT-OF-SCOPE"
            print(f"- {t.get('name') or '?'}  {ct._mask(t['url'])}  port={port}  {tag}")
        return 0
    if cmd == "probes":
        klass = argv[1] if len(argv) > 1 else None
        if klass and klass not in PROBE_LIBRARY:
            print(f"unknown class {klass!r}; known: {', '.join(PROBE_CLASSES)}", file=sys.stderr)
            return 2
        for c, p in ([(klass, x) for x in probes(klass)] if klass else probes()):
            print(f"[{c}] {p!r}")
        return 0
    print(f"unknown command {cmd!r}; use: list | probes [class]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
