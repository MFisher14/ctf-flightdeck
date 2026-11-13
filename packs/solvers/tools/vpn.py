#!/usr/bin/env python3
"""Drive a Tunnelblick VPN profile, for when the assigned target is only reachable through one.
No sudo, no password, one line out.

  python3 tools/vpn.py status
  python3 tools/vpn.py up [--wait S] [--probe ADDRESS[:PORT]]
  python3 tools/vpn.py down [--wait S]
  python3 tools/vpn.py ensure ADDRESS[:PORT] [--wait S]

Tunnelblick holds the event's VPN profile (its name is $CTF_VPN_PROFILE, else `vpn_profile` in the
event config; with neither, every command that needs it refuses and says so); AppleScript
connects and disconnects it in a few seconds. Connecting changes this Mac's routes, so the VPN is
brought up only when a solver needs a target behind it and taken down again when that is done.

status  `VPN <state>`: Tunnelblick's own word for the profile (CONNECTED, EXITING when it is
        off, CONNECTING, AUTH, GET_CONFIG, ASSIGN_IP, RECONNECTING ...), or NOT_RUNNING when
        Tunnelblick is not open (status never opens it). Exit 0 connected, 1 anything else.
up      connect and wait until the state is CONNECTED (default 30 s); with --probe, wait on
        until that address answers too. Already connected: says so and connects nothing.
down    disconnect and wait until Tunnelblick says so.
ensure  the idempotent one a solver uses: when the address already answers, nothing is touched;
        otherwise `up`, then wait for the address. When the event config declares `vpn_ranges`
        (tools/target.py), an address outside them is only probed: the VPN would not route it.
        Exit 0 the address answers, 1 it does not, 2 refused or wrong usage.

"Answers": with a port, a TCP connection opens (a refused connection means the host is there and
the port is closed: that is said, and counts after 5 s of nothing better, because the route is
then proven). Without a port, one ping, else any answer on 80, 443 or 22.

connect changes this Mac's routes: `up` and `ensure` can wait (--clock-wait S, default 20 s) for
an optional caller-supplied `clock_busy` predicate to clear before they connect; by default
nothing holds them.

Scope (R-13): every address is checked with ctf.scope.check_host before it is probed or waited
for (ensure, up --probe, probe, tcp): a host outside the event profile's rules.live_service_scope,
or the event platform, is refused (exit 2) before any ping or socket, and before the VPN is touched.

Every action is one line in <CHALLENGES>/_logs/vpn.log. Nothing here reads the token. Stand-ins
for tests: the functions take `runner` and `probe`; the command line takes $CTF_VPN_OSASCRIPT (a
program in place of /usr/bin/osascript) and $CTF_VPN_PROFILE. No test connects anything.

(The Huntress clock path's cheap ifconfig check, tunnel_interfaces()/is_up_fast(), belongs to the
Huntress platform adapter with its only caller, open_day.py; it is not part of master.)
"""
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import target  # noqa: E402  (the address reader and the event's VPN ranges; no request, no gm import)

try:
    from ctf import scope
except ModuleNotFoundError:
    sys.path.append(str(HERE.parent))
    from ctf import scope

APP = "Tunnelblick"
UP_WAIT = 30.0            # seconds `up` waits for CONNECTED, and `ensure` for the address
DOWN_WAIT = 15.0
CLOCK_WAIT = 20.0         # seconds to wait for a free clock lock before the routes change
REFUSED_GRACE = 5.0       # a host that refuses the port this long counts as answering
POLL = 0.5
PROBE_TIMEOUT = 2.0
SCRIPT_TIMEOUT = 20
CONNECTED = "CONNECTED"
OFF = ("EXITING", "NOT_RUNNING")
USAGE = "usage: vpn.py status | up [--wait S] [--probe ADDRESS[:PORT]] | down [--wait S] | ensure ADDRESS[:PORT] [--wait S]"


def profile() -> str:
    """The Tunnelblick profile name: $CTF_VPN_PROFILE, else the event config's `vpn_profile`.
    ValueError (refused, with the reason) when neither names one or the name is not plain."""
    name = os.environ.get("CTF_VPN_PROFILE")
    where = "$CTF_VPN_PROFILE"
    if not name:
        _, cfg = target._event_config()
        name, where = cfg.get("vpn_profile"), "the event config's vpn_profile"
    if not name:
        raise ValueError("no VPN profile named: set $CTF_VPN_PROFILE or `vpn_profile` in the event config")
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}", name):
        raise ValueError(f"{where} is not a plain profile name")   # it goes into AppleScript source
    return name


def osascript(lines, timeout=SCRIPT_TIMEOUT):
    """Run AppleScript lines; (exit status, output on one line). Never raises."""
    program = os.environ.get("CTF_VPN_OSASCRIPT") or "/usr/bin/osascript"
    command = [program]
    for text in lines:
        command += ["-e", text]
    try:
        done = subprocess.run(command, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
        return done.returncode, " ".join((done.stdout or done.stderr or "").split())
    except subprocess.TimeoutExpired:
        return 124, f"no answer from {APP} in {timeout} s"
    except OSError as e:
        return 127, f"{type(e).__name__}: {e}"


def state(runner=osascript) -> str:
    """Tunnelblick's word for the profile, upper case; NOT_RUNNING; or `UNKNOWN: <why>`."""
    name = profile()
    rc, out = runner([f'if application "{APP}" is running then',
                      f'tell application "{APP}" to get state of first configuration where name = "{name}"',
                      "else", '"NOT_RUNNING"', "end if"])
    if rc != 0 or not out:
        return f"UNKNOWN: {out or 'exit ' + str(rc)}"[:160]
    return out.strip().strip('"').upper()


def tcp(host, port, timeout=PROBE_TIMEOUT) -> str:
    """open, refused or silent. ctf.scope.OutOfScope (before any socket) for an out-of-scope host."""
    scope.check_host(host, port, what=f"vpn probe {host}:{port}")
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "open"
    except ConnectionRefusedError:
        return "refused"
    except OSError:
        return "silent"


def probe(host, port=None) -> str:
    """Whether the address answers: open, refused (the host is there, the port is closed) or silent.
    ctf.scope.OutOfScope (before the ping or any socket) for an out-of-scope host."""
    scope.check_host(host, port, what=f"vpn probe {host}" + (f":{port}" if port else ""))
    if port:
        return tcp(host, port)
    try:
        done = subprocess.run(["/sbin/ping", "-c", "1", "-t", "2", "-q", host], capture_output=True, timeout=4,
                              stdin=subprocess.DEVNULL)
        if done.returncode == 0:
            return "open"
    except (OSError, subprocess.TimeoutExpired):
        pass
    seen = [tcp(host, p, 1.0) for p in (80, 443, 22)]
    return "open" if "open" in seen else ("refused" if "refused" in seen else "silent")


def _clock_busy() -> bool:
    """No clock binds master play, so nothing holds `up`/`ensure` back by default; a caller that must
    serialize this Mac's route changes (the Huntress adapter's judge clock) passes its own
    clock_busy predicate instead."""
    return False


def _log(text):
    try:
        folder = target.folder() / "_logs"
        folder.mkdir(parents=True, exist_ok=True)
        with open(folder / "vpn.log", "a", encoding="utf-8") as f:
            f.write(f"{datetime.now().astimezone().isoformat(timespec='seconds')} {text}\n")
    except (Exception, SystemExit):
        pass


def _wait_address(host, port, wait, probe_fn, sleep, now):
    """(answers, word): poll until open, or refused for REFUSED_GRACE, or `wait` is over."""
    start, refused_at, seen = now(), None, "silent"
    while True:
        seen = probe_fn(host, port)
        if seen == "open":
            return True, "answers"
        if seen == "refused":
            refused_at = now() if refused_at is None else refused_at
            if now() - refused_at >= REFUSED_GRACE or now() - start >= wait:
                return True, f"the host answers, port {port or '80/443/22'} is closed"
        else:
            refused_at = None
        if now() - start >= wait:
            return False, f"does not answer after {wait:.0f} s"
        sleep(POLL)


def up(wait=UP_WAIT, address=None, runner=osascript, probe_fn=probe, clock_busy=_clock_busy,
       clock_wait=CLOCK_WAIT, sleep=time.sleep, now=time.monotonic):
    """(ok, line). Connect the profile and wait for CONNECTED, then for `address` if one is given."""
    host, port = (address["host"], address["port"]) if address else (None, None)
    where = address["address"] if address else ""
    if host:
        scope.check_host(host, port, what=f"vpn address {where}")   # before the routes change
    st = state(runner)
    notes = []
    if st != CONNECTED:
        waited = now()
        while clock_busy() and now() - waited < clock_wait:
            sleep(POLL)
        if clock_busy():
            notes.append(f"a clock was still running after {clock_wait:.0f} s; connected anyway")
        t0 = now()
        rc, out = runner([f'tell application "{APP}" to connect "{profile()}"'])
        if rc != 0:
            return False, f"VPN NOT up: {APP} did not take the connect ({out or 'exit ' + str(rc)})"[:240]
        while True:
            st = state(runner)
            if st == CONNECTED:
                break
            if now() - t0 >= wait:
                return False, f"VPN NOT up: state {st} after {wait:.0f} s (open {APP} and look at the profile's log)"
            sleep(POLL)
        head = f"VPN up: connected in {now() - t0:.1f} s"
    else:
        head = "VPN up: already connected"
    ok = True
    if host:
        ok, word = _wait_address(host, port, wait, probe_fn, sleep, now)
        head += f"; {where} {word}"
    if notes:
        head += "; NOTE " + "; ".join(notes)
    return ok, head


def down(wait=DOWN_WAIT, runner=osascript, sleep=time.sleep, now=time.monotonic):
    st = state(runner)
    if st in OFF:
        return True, f"VPN down: already off ({st})"
    rc, out = runner([f'tell application "{APP}" to disconnect "{profile()}"'])
    if rc != 0:
        return False, f"VPN NOT down: {APP} did not take the disconnect ({out or 'exit ' + str(rc)})"[:240]
    t0 = now()
    while True:
        st = state(runner)
        if st in OFF:
            return True, f"VPN down: disconnected in {now() - t0:.1f} s"
        if now() - t0 >= wait:
            return False, f"VPN NOT down: state {st} after {wait:.0f} s"
        sleep(POLL)


def ensure(address, wait=UP_WAIT, runner=osascript, probe_fn=probe, **kw):
    """(ok, line). Nothing is touched when the address already answers; otherwise bring the VPN up
    and wait for the address. When the event config declares vpn_ranges and the address lies
    outside them (address["vpn"] is False), the VPN is not touched: it would not route it."""
    host, port, where = address["host"], address["port"], address["address"]
    scope.check_host(host, port, what=f"vpn address {where}")       # before any probe or VPN change
    if probe_fn(host, port) == "open":
        try:
            st = state(runner)
        except ValueError as e:          # no profile named: nothing needed it, so it is only said
            st = f"UNKNOWN: {e}"
        return True, f"VPN ok: {where} answers; nothing changed (state {st})"
    if address.get("vpn") is False:
        ranges = ", ".join(target.event_ranges()) or "none declared"
        return False, (f"VPN not used: {where} is outside the event VPN's ranges ({ranges}) "
                       f"and does not answer; the VPN would not route it")
    return up(wait=wait, address=address, runner=runner, probe_fn=probe_fn, **kw)


def _number(args, flag, default):
    if flag not in args:
        return default
    i = args.index(flag)
    value = float(args[i + 1])          # ValueError and IndexError are wrong usage
    del args[i:i + 2]
    if not 0 <= value <= 600:
        raise ValueError(flag)
    return value


def main(argv) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if argv else 2
    cmd, args = argv[0], list(argv[1:])
    try:
        wait = _number(args, "--wait", None)
        clock_wait = _number(args, "--clock-wait", CLOCK_WAIT)
        address = None
        if "--probe" in args:
            i = args.index("--probe")
            address = target.parse(args[i + 1])
            del args[i:i + 2]
        if cmd == "status" and not args and address is None:
            st = state()
            print(f"VPN {st}")
            return 0 if st == CONNECTED else 1
        if cmd == "up" and not args:
            ok, line = up(wait=UP_WAIT if wait is None else wait, address=address, clock_wait=clock_wait)
        elif cmd == "down" and not args and address is None:
            ok, line = down(wait=DOWN_WAIT if wait is None else wait)
        elif cmd == "ensure" and len(args) == 1 and address is None:
            ok, line = ensure(target.parse(args[0]), wait=UP_WAIT if wait is None else wait, clock_wait=clock_wait)
        else:
            print(USAGE, file=sys.stderr)
            return 2
    except (ValueError, IndexError) as e:
        print(f"vpn.py: refused: {e}" if isinstance(e, ValueError) and str(e) and not str(e).startswith("--")
              else USAGE, file=sys.stderr)
        return 2
    print(line)
    _log(f"{cmd} -> {line}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
