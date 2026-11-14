#!/usr/bin/env python3
"""Connectivity and auth watchdog (B-177): notice when unattended agents stall or die on lost network,
Mac sleep, an API or platform (Game Master) outage, or an auth failure; tell the player; relaunch the
agent once it can work again.

    tools/watchdog.py watch [--probe NAME=URL ...] [--platform] [--interval S] [--sleep-gap S] [--dry-run]
    tools/watchdog.py run --name NAME [--probe NAME=URL ...] [--platform] [--max-relaunches N]
                          [--auth-retries N] [--resume-arg ARG ...] -- COMMAND ...
    tools/watchdog.py ack NAME

watch   Probes reachability every --interval seconds and alerts (tools/alert.py) when a probe goes down
        and when it comes back; one alert when every probe is down at once ("network looks down").
        A Mac sleep (or any suspension) is seen as wall time that ran while the machine's uptime clock
        did not, and is alerted with its length.
run     Runs one headless agent command (normally `tools/claude_launch ... -- -p ...` or
        `tools/codex_launch ... exec ...`), passes its output through unchanged, and keeps watching
        while it runs. When it ends on an error the tail of its output names (see PATTERNS), it is
        relaunched in the same slot:
          network / api   after the probes are reachable again (with no probes: after --retry-wait);
          auth            relaunched automatically --auth-retries times (default 1); after that the
                          player is pinged (critical) to fix it (/login) and run `watchdog.py ack NAME`;
          limit           (usage / rate / credit limit) the player is pinged at once and acks.
        At most --max-relaunches relaunches (default 3); then a critical alert and the agent's own exit
        code. Exit 3 (the R-09 budget gate refused or stopped it), 130 (interrupted) and a death by
        signal are final: never relaunched. A clean exit (0) is relaunched only when the agent's own
        JSON error record (a `result` line with is_error, or an `error` / `turn.failed` event) says so.
        --resume-arg is appended to the command on relaunch (e.g. --continue).
ack     The player's "fixed it" (after /login, network repair, an account fix) for an agent the
        watchdog is holding. Refused when no watchdog is waiting on NAME.

Probes: NAME=URL, URL is http(s)://host[:port][/path] (a GET; down on no answer, a timeout or HTTP 5xx,
up on any other status) or tcp://host:port (a connect). --platform adds the current event's
platform.base_url as the probe "platform". $CTF_WATCHDOG_PROBES adds "NAME=URL,NAME=URL". Probes go
direct (no proxy) and carry no credentials. The watchdog never reads an auth file: an auth failure is
read from the agent's own output, and the fix is confirmed by the player's ack.

Output is data: only the last TAIL_LINES lines are read, JSON lines only through their error fields
(an assistant message quoting "Not logged in" is not an auth failure), plain lines through the CLIs'
own wording, or through generic wording ("401 Unauthorized", "Connection refused") only on a line that
starts with a CLI error prefix (API Error / Error: / ERROR), and no output text is copied
into an alert or the ledger: they carry the matched pattern's label only.

Ledger events (<workdir>/ledger.jsonl): watchdog.down {probe, detail}, watchdog.up {probe, down_s},
watchdog.sleep {gap_s}, watchdog.agent_start {agent, attempt, pid}, watchdog.agent_end {agent, attempt,
rc, failure?, signal?}, watchdog.wait_human {agent, kind}, watchdog.ack {agent}, watchdog.relaunch
{agent, attempt, after}, watchdog.gave_up {agent, reason}. Exit codes: the agent's own, 2 for a usage or
setup error.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

try:
    from ctf import env as ctf_env, ledger as ctf_ledger, paths as ctf_paths
except ModuleNotFoundError:     # run as a script: the checkout root on sys.path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from ctf import env as ctf_env, ledger as ctf_ledger, paths as ctf_paths

from tools import alert as _alert  # noqa: E402
from tools import process_group as _pg  # noqa: E402

TAIL_LINES = 40
FINAL_RC = frozenset({3, 130})          # 3: the R-09 gate refused/stopped it; 130: interrupted
HUMAN_KINDS = frozenset({"auth", "limit"})
DEFAULT_INTERVAL = 30.0
DEFAULT_SLEEP_GAP = 60.0
DEFAULT_PROBE_TIMEOUT = 5.0
DEFAULT_MAX_RELAUNCHES = 3
DEFAULT_AUTH_RETRIES = 1
DEFAULT_RETRY_WAIT = 60.0
DEFAULT_RENOTIFY = 900.0
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
STATE_DIR = "_watchdog"

# (kind, label, pattern, bare): checked in this order, first match wins. The label (never the output
# text) is what an alert and the ledger carry. A JSON error record is already known to be the CLI's own
# error, so every pattern is read from it. A plain line may be challenge or tool output the agent echoed
# (codex exec streams command output; a web challenge answers "401 Unauthorized", nc says "Connection
# refused"), so a pattern that is not `bare` counts on a plain line only when the line starts with a CLI
# error prefix (CLI_ERROR). `bare` patterns are the CLIs' own wording or error codes.
PATTERNS: tuple[tuple[str, str, re.Pattern, bool], ...] = tuple(
    (kind, label, re.compile(rx, re.I), bare) for kind, label, rx, bare in (
        ("auth", "not logged in", r"please run /login", True),
        ("auth", "not logged in", r"\bnot logged in\b", False),
        ("auth", "invalid api key", r"invalid x-api-key", True),
        ("auth", "invalid api key", r"invalid api key|incorrect api key", False),
        # anchored to the CLI's own error forms: a bare "token has expired" is what a JWT challenge says
        ("auth", "token expired", r"oauth token (?:has )?expired|"
                                  r"api error[^\n]{0,80}\btoken (?:has )?expired", True),
        ("auth", "token refresh failed", r"(?:access|refresh) token could not be refreshed", True),
        ("auth", "token refresh failed", r"failed to refresh (?:the )?token", False),
        ("auth", "authentication error", r"authentication_error", True),
        ("auth", "authentication error", r"authentication failed|please (?:log|sign) in again", False),
        ("auth", "http 401", r"api error:? *401\b", True),
        ("auth", "http 401", r"\b401\b[^\n]{0,40}unauthori[sz]ed|unauthori[sz]ed[^\n]{0,40}\b401\b", False),
        ("auth", "permission denied by api", r"permission_error|api error:? *403\b", True),
        # never a bare "limit reached" or "billing": challenge output says those too
        ("limit", "usage limit", r"usage limit|(?:\d+-hour|session|weekly|opus|sonnet) limit reached|"
                                 r"hit your limit|insufficient_quota", True),
        ("limit", "usage limit", r"quota exceeded", False),
        ("limit", "credit balance", r"credit balance is too low|billing_error", True),
        ("limit", "rate limited", r"rate_limit_error|api error:? *429\b", True),
        ("limit", "rate limited", r"rate limit(?:ed)?|\b429\b|too many requests", False),
        # Node / reqwest error codes are the CLIs' own; the OS's wording is every tool's (nc, curl, python)
        ("network", "connection error", r"econnrefused|econnreset|socket hang up", True),
        ("network", "connection error", r"connection error|connection refused|connection reset|"
                                        r"failed to connect", False),
        ("network", "dns failure", r"enotfound|eai_again", True),
        ("network", "dns failure", r"getaddrinfo|could not resolve host|nodename nor servname|"
                                   r"name or service not known|temporary failure in name resolution", False),
        ("network", "network unreachable", r"enetunreach|ehostunreach|etimedout|error sending request", True),
        ("network", "network unreachable", r"network is unreachable|no route to host", False),
        ("api", "api overloaded", r"overloaded_error|api error:? *529\b", True),
        ("api", "api overloaded", r"overloaded", False),
        ("api", "api server error", r"api error:? *5\d\d\b|\bapi_error\b", True),
        # a web challenge answers "500 Internal Server Error" and "502 Bad Gateway" all day
        ("api", "api server error", r"internal server error|service unavailable|bad gateway|"
                                    r"gateway time-?out|\b50[0234]\b[^\n]{0,40}(?:error|unavailable|gateway)",
         False),
        ("api", "stream disconnected", r"stream disconnected", True),
        ("api", "stream disconnected", r"stream error|stream closed", False),
        ("api", "request timed out", r"request timed out|timed out waiting", False),
    )
)
# How the CLIs start their own error lines: claude -p "API Error: ...", "Error: ...", codex
# "[timestamp] ERROR: ..." or "ERROR codex_...". Case-sensitive: "error:" from any tool does not count.
CLI_ERROR = re.compile(r"^(?:\x1b\[[0-9;]*m|\[[^\]\n]{1,40}\]\s*)*(?:API Error\b|Error:|ERROR\b)")


class WatchdogError(ValueError):
    """A usage or setup error, named."""


# ------------------------------------------------------------------ failure classification

@dataclass(frozen=True)
class Failure:
    kind: str       # auth | limit | network | api
    signal: str     # the matched pattern's label

    @property
    def human(self) -> bool:
        return self.kind in HUMAN_KINDS


def _texts_of(obj: dict) -> list[str]:
    """The error text of one JSON record, or [] when the record is not an error record."""
    out: list[str] = []
    t = obj.get("type")
    if t == "result":
        if obj.get("is_error") is True:
            for k in ("result", "error", "subtype"):
                v = obj.get(k)
                if isinstance(v, str):
                    out.append(v)
                elif isinstance(v, dict) and isinstance(v.get("message"), str):
                    out.append(v["message"])
    elif t in ("error", "turn.failed", "stream_error"):
        for k in ("message", "error"):
            v = obj.get(k)
            if isinstance(v, str):
                out.append(v)
            elif isinstance(v, dict):
                for kk in ("message", "type"):
                    if isinstance(v.get(kk), str):
                        out.append(v[kk])
    return out


def _error_parts(lines: Sequence[str], *, plain: bool) -> tuple[list[str], list[str]]:
    """(texts from JSON error records, plain non-JSON lines) of an output tail. Other JSON records are
    never read, and plain lines only when `plain` (the agent exited non-zero)."""
    records: list[str] = []
    plains: list[str] = []
    for line in list(lines)[-TAIL_LINES:]:
        s = line.strip()
        if not s:
            continue
        if s.startswith("{"):
            try:
                obj = json.loads(s)
            except ValueError:
                obj = None
            if isinstance(obj, dict):
                records.extend(_texts_of(obj))
                continue
        if plain:
            plains.append(s)
    return records, plains


def classify(rc: int | None, lines: Sequence[str]) -> Failure | None:
    """Why an agent ended, when it ended on an error a relaunch can fix. None: leave it ended."""
    if rc is None or rc < 0 or rc in FINAL_RC:
        return None
    records, plains = _error_parts(lines, plain=rc != 0)
    prefixed = [t for t in plains if CLI_ERROR.match(t)]
    for kind, label, rx, bare in PATTERNS:
        if any(rx.search(t) for t in records + (plains if bare else prefixed)):
            return Failure(kind, label)
    return None


# ------------------------------------------------------------------ probes

@dataclass(frozen=True)
class Probe:
    name: str
    url: str

    @property
    def scheme(self) -> str:
        return urllib.parse.urlsplit(self.url).scheme

    def check(self, timeout: float = DEFAULT_PROBE_TIMEOUT) -> tuple[bool, str]:
        """(reachable, detail). Never raises for an unreachable target."""
        parts = urllib.parse.urlsplit(self.url)
        if parts.scheme == "tcp":
            try:
                with socket.create_connection((parts.hostname, parts.port), timeout=timeout):
                    return True, "connected"
            except OSError as e:
                return False, _os_reason(e)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        req = urllib.request.Request(self.url, method="GET", headers={"User-Agent": "ctf-watchdog"})
        try:
            with opener.open(req, timeout=timeout) as resp:
                code = resp.status
        except urllib.error.HTTPError as e:
            code = e.code
            e.close()
        except urllib.error.URLError as e:
            reason = e.reason
            return False, _os_reason(reason) if isinstance(reason, OSError) else f"unreachable ({reason})"
        except (OSError, ValueError) as e:     # timeouts, resets, a malformed response
            return False, _os_reason(e) if isinstance(e, OSError) else f"bad response ({type(e).__name__})"
        if code >= 500:
            return False, f"HTTP {code}"
        return True, f"HTTP {code}"


def _os_reason(e: OSError) -> str:
    if isinstance(e, (socket.timeout, TimeoutError)):
        return "timed out"
    if isinstance(e, socket.gaierror):
        return "name not resolved"
    if isinstance(e, ConnectionRefusedError):
        return "connection refused"
    return f"{type(e).__name__}" + (f" errno={e.errno}" if e.errno else "")


def parse_probe(spec: str) -> Probe:
    if "=" not in spec:
        raise WatchdogError(f"probe {spec!r}: expected NAME=URL")
    name, url = (x.strip() for x in spec.split("=", 1))
    if not NAME_RE.match(name):
        raise WatchdogError(f"probe name {name!r}: letters, digits, '_', '.', '-' only")
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError as e:
        raise WatchdogError(f"probe {name}: bad URL {url!r} ({e})") from None
    if parts.scheme not in ("http", "https", "tcp"):
        raise WatchdogError(f"probe {name}: URL must start with http://, https:// or tcp://, got {url!r}")
    if not parts.hostname:
        raise WatchdogError(f"probe {name}: URL {url!r} has no host")
    if parts.scheme == "tcp" and port is None:
        raise WatchdogError(f"probe {name}: a tcp:// probe needs a port, got {url!r}")
    if parts.username or parts.password:
        raise WatchdogError(f"probe {name}: a probe URL carries no credentials")
    return Probe(name, url)


def platform_probe(event_slug: str | None = None) -> Probe:
    """The current event's platform (the Game Master, the CTFd) as the probe "platform"."""
    from ctf import event as ctf_event
    try:
        prof = ctf_event.load(event_slug) if event_slug else ctf_event.current()
    except Exception as e:      # EventError, EnvError: named, never a traceback
        raise WatchdogError(f"--platform: no event profile ({type(e).__name__}: {e})") from None
    if prof.platform.kind == "manual" or not prof.platform.base_url:
        raise WatchdogError(f"event {prof.slug}: platform kind {prof.platform.kind!r} has no base_url to probe")
    return parse_probe(f"platform={prof.platform.base_url}")


def probes_from(specs: Sequence[str], *, platform: bool, event_slug: str | None = None,
                use_env: bool = True) -> list[Probe]:
    raw = list(specs)
    if use_env:
        extra = ctf_env.get("CTF_WATCHDOG_PROBES") or ""
        raw += [s.strip() for s in extra.split(",") if s.strip()]
    probes = [parse_probe(s) for s in raw]
    if platform:
        probes.append(platform_probe(event_slug))
    names = [p.name for p in probes]
    dup = sorted({n for n in names if names.count(n) > 1})
    if dup:
        raise WatchdogError(f"probe name used twice: {', '.join(dup)}")
    return probes


# ------------------------------------------------------------------ clocks, alerts, records

def uptime_clock() -> float:
    """A clock that stops while the Mac sleeps (CLOCK_UPTIME_RAW; time.monotonic elsewhere)."""
    if hasattr(time, "CLOCK_UPTIME_RAW"):
        return time.clock_gettime(time.CLOCK_UPTIME_RAW)
    return time.monotonic()


def _mins(seconds: float) -> str:
    return f"{seconds / 60:.0f} min" if seconds >= 90 else f"{seconds:.0f} s"


class Monitor:
    """Reachability and sleep, one tick at a time. Alerts on a change only, never on every tick."""

    def __init__(self, probes: Sequence[Probe], *, record: Callable[..., None], lane: str | None = None,
                 sleep_gap: float = DEFAULT_SLEEP_GAP, probe_timeout: float = DEFAULT_PROBE_TIMEOUT,
                 wall: Callable[[], float] = time.time, uptime: Callable[[], float] = uptime_clock):
        self.probes = list(probes)
        self.record = record
        self.lane = lane
        self.sleep_gap = sleep_gap
        self.probe_timeout = probe_timeout
        self.wall, self.uptime = wall, uptime
        self.down: dict[str, tuple[float, str]] = {}     # probe -> (since, detail)
        self._last: tuple[float, float] | None = None

    def check_sleep(self) -> float | None:
        """Seconds of wall time that passed while the uptime clock stood still since the last call,
        when that is at least sleep_gap (the machine slept or was suspended)."""
        now = (self.wall(), self.uptime())
        gap = None
        if self._last is not None:
            lost = (now[0] - self._last[0]) - (now[1] - self._last[1])
            if lost >= self.sleep_gap:
                gap = lost
        self._last = now
        if gap is not None:
            self.record("watchdog.sleep", gap_s=round(gap, 1))
            _alert.alert("warn", f"this Mac was asleep or suspended for about {_mins(gap)}; unattended "
                                 f"agents stalled meanwhile", lane=self.lane)
        return gap

    def tick(self) -> bool:
        """Sleep check and one round of probes. True when every probe is reachable (or none exist)."""
        self.check_sleep()
        if not self.probes:
            return True
        results = {p.name: p.check(self.probe_timeout) for p in self.probes}
        now = self.wall()
        went_down, came_up = [], []
        for name, (ok, detail) in results.items():
            if not ok and name not in self.down:
                self.down[name] = (now, detail)
                went_down.append((name, detail))
                self.record("watchdog.down", probe=name, detail=detail)
            elif ok and name in self.down:
                since, _ = self.down.pop(name)
                came_up.append((name, now - since))
                self.record("watchdog.up", probe=name, down_s=round(now - since, 1))
        if went_down:
            listed = ", ".join(f"{n} ({d})" for n, d in went_down)
            if len(self.down) == len(self.probes) and len(self.probes) > 1:
                msg = f"network looks down: no probe reachable: {listed}"
            else:
                msg = f"unreachable: {listed}"
            _alert.alert("warn", msg + "; unattended agents will stall until it returns", lane=self.lane)
        if came_up:
            listed = ", ".join(f"{n} (down {_mins(s)})" for n, s in came_up)
            _alert.alert("info", f"reachable again: {listed}", lane=self.lane)
        return not self.down

    def watch(self, *, interval: float, cycles: int | None = None,
              sleep: Callable[[float], None] = time.sleep) -> None:
        n = 0
        while cycles is None or n < cycles:
            self.tick()
            n += 1
            if cycles is None or n < cycles:
                sleep(interval)


def ledger_recorder(workdir: Path, **base) -> Callable[..., None]:
    def record(event: str, **fields) -> None:
        ctf_ledger.append(event, workdir=workdir, **base, **fields)
    return record


# ------------------------------------------------------------------ the agent supervisor

@dataclass
class Policy:
    max_relaunches: int = DEFAULT_MAX_RELAUNCHES
    auth_retries: int = DEFAULT_AUTH_RETRIES     # automatic relaunches after an auth failure
    poll: float = DEFAULT_INTERVAL                # probe interval while the agent runs or we wait
    retry_wait: float = DEFAULT_RETRY_WAIT        # no probes: wait this long before a relaunch
    renotify: float = DEFAULT_RENOTIFY            # repeat a pending "needs you" ping
    give_up_after: float | None = None            # stop waiting (reachability or ack) after this long
    resume_args: tuple[str, ...] = ()

    def validate(self) -> None:
        if self.max_relaunches < 0 or self.auth_retries < 0:
            raise WatchdogError("--max-relaunches and --auth-retries must be 0 or more")
        for k in ("poll", "retry_wait", "renotify"):
            if getattr(self, k) <= 0:
                raise WatchdogError(f"{k.replace('_', '-')} must be positive")
        if self.give_up_after is not None and self.give_up_after <= 0:
            raise WatchdogError("give-up-after must be positive")


def state_dir(workdir: Path) -> Path:
    return Path(workdir) / STATE_DIR


def check_name(name: str) -> str:
    if not NAME_RE.match(name or ""):
        raise WatchdogError(f"agent name {name!r}: 1-64 letters, digits, '_', '.', '-'")
    return name


def _write_out(stream, raw: bytes) -> None:
    buf = getattr(stream, "buffer", None)
    if buf is not None:
        buf.write(raw)
        buf.flush()
    else:
        stream.write(raw.decode("utf-8", errors="replace"))
        stream.flush()


class Supervisor:
    """Run one agent command; relaunch it after a fixable failure (see the top of this file)."""

    def __init__(self, name: str, argv: Sequence[str], *, workdir: Path, probes: Sequence[Probe] = (),
                 policy: Policy | None = None, cwd: str | Path | None = None, stdout=None, stderr=None,
                 stdin=None, sleep_gap: float = DEFAULT_SLEEP_GAP, probe_timeout: float = DEFAULT_PROBE_TIMEOUT,
                 wall: Callable[[], float] = time.time, uptime: Callable[[], float] = uptime_clock,
                 sleep: Callable[[float], None] = time.sleep):
        if not argv:
            raise WatchdogError("no agent command given (put it after --)")
        self.name = check_name(name)
        self.argv = list(argv)
        self.workdir = Path(workdir)
        self.policy = policy or Policy()
        self.policy.validate()
        self.cwd = cwd
        self.out = stdout if stdout is not None else sys.stdout
        self.err = stderr if stderr is not None else sys.stderr
        self.stdin = stdin
        self.wall, self.sleep = wall, sleep
        self.record = ledger_recorder(self.workdir, agent=self.name)
        self.monitor = Monitor(probes, record=self.record, lane=self.name, sleep_gap=sleep_gap,
                               probe_timeout=probe_timeout, wall=wall, uptime=uptime)
        self.attempt = 0

    # one run of the agent
    def run_once(self, argv: Sequence[str]) -> tuple[int, list[str]]:
        tail: collections.deque[str] = collections.deque(maxlen=TAIL_LINES)
        lock = threading.Lock()
        owned = _pg.spawn(list(argv), cwd=None if self.cwd is None else str(self.cwd), stdin=self.stdin,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc = owned.popen
        self.record("watchdog.agent_start", attempt=self.attempt, pid=proc.pid)

        def pump(pipe, out) -> None:
            for raw in iter(pipe.readline, b""):
                try:
                    _write_out(out, raw)
                except Exception:   # a closed terminal must not hide the failure we are reading for
                    pass
                with lock:
                    tail.append(raw.decode("utf-8", errors="replace"))

        threads = [threading.Thread(target=pump, args=(proc.stdout, self.out), daemon=True),
                   threading.Thread(target=pump, args=(proc.stderr, self.err), daemon=True)]
        for t in threads:
            t.start()
        try:
            while True:
                try:
                    proc.wait(timeout=self.policy.poll)
                    break
                except subprocess.TimeoutExpired:
                    self.monitor.tick()      # keep watching while it works: a stall gets an alert
        except KeyboardInterrupt:
            owned.stop(grace=1.0)
            owned.wait_after_stop(timeout=5.0)
            for t in threads:
                t.join(timeout=2.0)
            raise
        for t in threads:
            t.join(timeout=5.0)
        with lock:
            return proc.returncode, list(tail)

    def _note(self, msg: str) -> None:
        print(f"watchdog[{self.name}]: {msg}", file=self.err, flush=True)

    def _gave_up_waiting(self, started: float) -> bool:
        lim = self.policy.give_up_after
        return lim is not None and self.wall() - started >= lim

    def wait_reachable(self) -> bool:
        """Block until every probe answers. False when give_up_after ran out."""
        if not self.monitor.probes:
            self._note(f"no probes configured: relaunching after a {self.policy.retry_wait:g} s wait")
            self.sleep(self.policy.retry_wait)
            self.monitor.check_sleep()
            return True
        started = self.wall()
        while not self.monitor.tick():
            if self._gave_up_waiting(started):
                return False
            self.sleep(self.policy.poll)
        return True

    def wait_human(self, failure: Failure) -> bool:
        """Ping the player and block until `watchdog.py ack NAME`. False when give_up_after ran out."""
        d = state_dir(self.workdir)
        d.mkdir(parents=True, exist_ok=True)
        ack, waiting = d / f"{self.name}.ack", d / f"{self.name}.waiting"
        ack.unlink(missing_ok=True)                 # only an ack given from now on counts
        fix = "run /login in that harness" if failure.kind == "auth" else "check the account's usage or limits"
        cmd = f"python3 tools/watchdog.py ack {self.name}"
        # the try opens before the marker exists: a Ctrl-C at any point after it leaves no stale wait
        try:
            waiting.write_text(json.dumps({"kind": failure.kind, "signal": failure.signal,
                                           "since": self.wall()}))
            self.record("watchdog.wait_human", kind=failure.kind, signal=failure.signal)
            started = last_ping = self.wall()
            _alert.alert("critical", f"agent {self.name} needs you: {failure.kind} failure ({failure.signal}) "
                                     f"again; {fix}, then: {cmd}", lane=self.name)
            while not ack.exists():
                if self._gave_up_waiting(started):
                    return False
                if self.wall() - last_ping >= self.policy.renotify:
                    last_ping = self.wall()
                    _alert.alert("critical", f"still waiting on you for agent {self.name} "
                                             f"({failure.signal}): {fix}, then: {cmd}", lane=self.name)
                self.sleep(self.policy.poll)
            self.record("watchdog.ack")
            return True
        finally:
            waiting.unlink(missing_ok=True)
            ack.unlink(missing_ok=True)

    def run(self) -> int:
        """Run until the agent ends for good. A Ctrl-C while waiting (for reachability or the ack) is
        exit 130 with watchdog.gave_up reason=interrupted, not a traceback."""
        try:
            return self._run()
        except KeyboardInterrupt:
            self.record("watchdog.gave_up", reason="interrupted")
            self._note("interrupted; not relaunching")
            return 130

    def _run(self) -> int:
        relaunches = 0
        human_streak = 0
        argv = self.argv
        self.monitor.check_sleep()          # the baseline a sleep is measured from
        while True:
            self.attempt += 1
            try:
                rc, tail = self.run_once(argv)
            except KeyboardInterrupt:
                self.record("watchdog.agent_end", attempt=self.attempt, rc=130)
                return 130
            failure = classify(rc, tail)
            self.record("watchdog.agent_end", attempt=self.attempt, rc=rc,
                        **({"failure": failure.kind, "signal": failure.signal} if failure else {}))
            if failure is None:
                return rc
            if relaunches >= self.policy.max_relaunches:
                self.record("watchdog.gave_up", reason="max_relaunches", failure=failure.kind)
                _alert.alert("critical", f"agent {self.name} ended on a {failure.kind} failure "
                                         f"({failure.signal}) after {relaunches} relaunch(es); not relaunching "
                                         f"again", lane=self.name)
                return rc
            human_streak = human_streak + 1 if failure.human else 0
            needs_you = failure.human and (failure.kind == "limit" or human_streak > self.policy.auth_retries)
            if not needs_you:
                _alert.alert("warn", f"agent {self.name} ended on a {failure.kind} failure ({failure.signal}); "
                                     f"relaunching when it can work again", lane=self.name)
            if not self.wait_reachable():
                self.record("watchdog.gave_up", reason="unreachable", failure=failure.kind)
                _alert.alert("critical", f"agent {self.name}: still unreachable after "
                                         f"{_mins(self.policy.give_up_after or 0)}; not relaunching", lane=self.name)
                return rc
            if needs_you:
                if not self.wait_human(failure):
                    self.record("watchdog.gave_up", reason="no_ack", failure=failure.kind)
                    _alert.alert("critical", f"agent {self.name}: no ack after "
                                             f"{_mins(self.policy.give_up_after or 0)}; not relaunching",
                                 lane=self.name)
                    return rc
                human_streak = 0
            relaunches += 1
            argv = self.argv + list(self.policy.resume_args)
            self.record("watchdog.relaunch", attempt=self.attempt + 1, after=failure.kind)
            _alert.alert("info", f"relaunching agent {self.name} (relaunch {relaunches} of "
                                 f"{self.policy.max_relaunches}) after a {failure.kind} failure", lane=self.name)


def ack(name: str, workdir: Path) -> None:
    """Tell a waiting watchdog the player has fixed what it was waiting on."""
    check_name(name)
    d = state_dir(workdir)
    if not (d / f"{name}.waiting").exists():
        raise WatchdogError(f"no watchdog is waiting on agent {name!r} (in {d})")
    (d / f"{name}.ack").write_text(json.dumps({"ts": time.time()}))


# ------------------------------------------------------------------ command line

def _add_probe_options(p: argparse.ArgumentParser) -> None:
    p.add_argument("--probe", action="append", default=[], metavar="NAME=URL",
                   help="a reachability probe: http(s)://... (GET; 5xx = down) or tcp://host:port; repeatable")
    p.add_argument("--platform", action="store_true", help="probe the current event's platform.base_url")
    p.add_argument("--event", help="event slug for --platform (default: the current event)")
    p.add_argument("--probe-timeout", type=float, default=DEFAULT_PROBE_TIMEOUT, metavar="S")
    p.add_argument("--sleep-gap", type=float, default=DEFAULT_SLEEP_GAP, metavar="S",
                   help=f"report a sleep or suspension this long or longer (default {DEFAULT_SLEEP_GAP:g})")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="watchdog.py", description=__doc__.split("\n\n")[0])
    sp = p.add_subparsers(dest="action", required=True)
    w = sp.add_parser("watch", help="alert on lost reachability and Mac sleep, and on recovery")
    _add_probe_options(w)
    w.add_argument("--interval", type=float, default=DEFAULT_INTERVAL, metavar="S")
    w.add_argument("--cycles", type=int, help="stop after this many rounds (default: run until stopped)")
    w.add_argument("--dry-run", action="store_true", help="list the probes and exit")
    r = sp.add_parser("run", help="run an agent command; relaunch it after a network, API or auth failure")
    _add_probe_options(r)
    r.add_argument("--name", required=True, help="the agent's name (alerts, ledger, `ack NAME`)")
    r.add_argument("--max-relaunches", type=int, default=DEFAULT_MAX_RELAUNCHES)
    r.add_argument("--auth-retries", type=int, default=DEFAULT_AUTH_RETRIES,
                   help="automatic relaunches after an auth failure before the player is pinged")
    r.add_argument("--poll", type=float, default=DEFAULT_INTERVAL, metavar="S")
    r.add_argument("--retry-wait", type=float, default=DEFAULT_RETRY_WAIT, metavar="S")
    r.add_argument("--renotify", type=float, default=DEFAULT_RENOTIFY, metavar="S")
    r.add_argument("--give-up-after", type=float, metavar="S")
    r.add_argument("--resume-arg", action="append", default=[], metavar="ARG",
                   help="appended to the command on a relaunch (e.g. --resume-arg=--continue); repeatable")
    a = sp.add_parser("ack", help="the player has fixed what a waiting agent needs (after /login, ...)")
    a.add_argument("name")
    return p


def _workdir() -> Path:
    try:
        return ctf_paths.workdir()
    except Exception as e:     # no CTF_WORKDIR and no current event: say which
        raise WatchdogError(f"no workdir: set CTF_WORKDIR or CTF_EVENT ({type(e).__name__}: {e})") from None


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    command: list[str] = []
    if "--" in argv:
        i = argv.index("--")
        argv, command = argv[:i], argv[i + 1:]
    args = build_parser().parse_args(argv)
    try:
        if args.action == "ack":
            if command:
                raise WatchdogError("ack takes no command")
            ack(args.name, _workdir())
            print(f"watchdog: ack recorded for {args.name}; it relaunches on its next poll")
            return 0
        probes = probes_from(args.probe, platform=args.platform, event_slug=args.event)
        if args.action == "watch":
            if command:
                raise WatchdogError("watch takes no command (did you mean run?)")
            if not probes:
                raise WatchdogError("no probes: give --probe NAME=URL, --platform or $CTF_WATCHDOG_PROBES")
            if args.interval <= 0:
                raise WatchdogError("--interval must be positive")
            if args.dry_run:
                for pr in probes:
                    print(f"{pr.name}\t{pr.url}")
                return 0
            mon = Monitor(probes, record=ledger_recorder(_workdir()), sleep_gap=args.sleep_gap,
                          probe_timeout=args.probe_timeout)
            try:
                mon.watch(interval=args.interval, cycles=args.cycles)
            except KeyboardInterrupt:
                return 130
            return 0
        policy = Policy(max_relaunches=args.max_relaunches, auth_retries=args.auth_retries, poll=args.poll,
                        retry_wait=args.retry_wait, renotify=args.renotify, give_up_after=args.give_up_after,
                        resume_args=tuple(args.resume_arg))
        sup = Supervisor(args.name, command, workdir=_workdir(), probes=probes, policy=policy,
                         sleep_gap=args.sleep_gap, probe_timeout=args.probe_timeout)
        return sup.run()
    except WatchdogError as e:
        print(f"watchdog: {e}", file=sys.stderr)
        return 2
    except FileNotFoundError as e:       # the agent command itself
        print(f"watchdog: cannot start the agent: {e.strerror}: {e.filename}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
