"""B-177: the connectivity and auth watchdog (tools/watchdog.py).

Every agent is a stub Python script written by the test, every service a fake on 127.0.0.1 started by
the test; no real Claude or Codex session starts and no auth file is read. Notifications are real
tools/alert.py alerts with CTF_QUIET=1: the print and the ALERTS.log line, no macOS notification.
"""
from __future__ import annotations

import io
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from ctf import ledger, paths
from tools import watchdog as wd

REPO = paths.repo_root()
PY = sys.executable
SCRIPT = REPO / "tools" / "watchdog.py"

STUB = '''import json, os, signal, sys, time
spec = json.load(open(sys.argv[1]))
count = spec["count"]
n = int(open(count).read()) if os.path.exists(count) else 0
open(count, "w").write(str(n + 1))
with open(spec["mark"], "a") as fh:
    fh.write(json.dumps(sys.argv[2:]) + "\\n")
step = spec["steps"][min(n, len(spec["steps"]) - 1)]
for line in step.get("out", []):
    print(line, flush=True)
for line in step.get("err", []):
    print(line, file=sys.stderr, flush=True)
time.sleep(step.get("sleep", 0))
if step.get("kill"):
    os.kill(os.getpid(), signal.SIGKILL)
sys.exit(step.get("rc", 0))
'''

NOT_LOGGED_IN = "Not logged in · Please run /login"


# ------------------------------------------------------------------ fixtures

class Agent:
    """A stub agent whose n-th start follows steps[n] (the last step repeats)."""

    def __init__(self, tmp: Path):
        self.dir = tmp / "agent"
        self.dir.mkdir()
        self.script = self.dir / "stub.py"
        self.script.write_text(STUB)
        self.spec = self.dir / "spec.json"
        self.mark = self.dir / "mark.txt"
        self.count = self.dir / "count.txt"

    def steps(self, *steps):
        self.spec.write_text(json.dumps({"count": str(self.count), "mark": str(self.mark), "steps": list(steps)}))
        return self

    def argv(self, *extra):
        return [PY, str(self.script), str(self.spec), *extra]

    def starts(self) -> list[list[str]]:
        if not self.mark.exists():
            return []
        return [json.loads(x) for x in self.mark.read_text().splitlines()]


class FakeService:
    """An HTTP service on 127.0.0.1 whose status code the test sets."""

    def __init__(self, status=200):
        self.status = status
        svc = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(svc.status)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}/"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def svc():
    s = FakeService()
    yield s
    s.close()


@pytest.fixture
def work(tmp_path, monkeypatch):
    w = tmp_path / "work"
    w.mkdir()
    monkeypatch.setenv("CTF_WORKDIR", str(w))
    monkeypatch.setenv("CTF_QUIET", "1")
    monkeypatch.delenv("CTF_SOUND", raising=False)
    monkeypatch.delenv("CTF_WATCHDOG_PROBES", raising=False)
    return w


@pytest.fixture
def agent(tmp_path):
    return Agent(tmp_path)


def closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def alerts(work: Path) -> list[str]:
    p = work / "_logs" / "ALERTS.log"
    return p.read_text().splitlines() if p.exists() else []


def events(work: Path, kind: str | None = None) -> list[dict]:
    return [r for r in ledger.read(work) if kind is None or r["event"] == kind]


def sup(agent, work, *, probes=(), out=None, err=None, **policy):
    # give_up_after bounds every wait, so a wrong wait fails the test instead of hanging it
    pol = dict(poll=0.05, retry_wait=0.01, renotify=60.0, give_up_after=8.0)
    pol.update(policy)
    return wd.Supervisor("lane1", agent.argv("-p", "go"), workdir=work, probes=probes,
                         policy=wd.Policy(**pol), stdout=out or io.StringIO(), stderr=err or io.StringIO(),
                         stdin=subprocess.DEVNULL)


def run(s, timeout=30.0):
    """s.run() in a thread, bounded: a supervisor that never returns fails the test."""
    box = {}
    t = threading.Thread(target=lambda: box.setdefault("rc", s.run()), daemon=True)
    t.start()
    t.join(timeout)
    assert not t.is_alive(), "the supervisor did not return"
    return box["rc"]


def wait_for(cond, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.02)
    return False


# ------------------------------------------------------------------ classification

@pytest.mark.parametrize("rc,lines,kind,signal", [
    (1, [NOT_LOGGED_IN], "auth", "not logged in"),
    (1, ['{"type":"result","subtype":"success","is_error":true,"result":"Invalid API key · Please run /login"}'],
     "auth", "not logged in"),
    (1, ["Error: OAuth token has expired."], "auth", "token expired"),
    (1, ["Your access token could not be refreshed because your refresh token was already used"],
     "auth", "token refresh failed"),
    (1, ['API Error: 401 {"type":"error","error":{"type":"authentication_error"}}'], "auth", "authentication error"),
    (1, ["API Error: 401 OAuth token has expired"], "auth", "token expired"),
    (1, ["API Error: 403 the access token has expired"], "auth", "token expired"),
    (1, ["Claude AI usage limit reached|1762000000"], "limit", "usage limit"),
    (1, ["5-hour limit reached ∙ resets 3pm"], "limit", "usage limit"),
    (1, ["Weekly limit reached · resets Mon"], "limit", "usage limit"),
    (1, ["Credit balance is too low"], "limit", "credit balance"),
    (1, ['API Error: 402 {"type":"error","error":{"type":"billing_error"}}'], "limit", "credit balance"),
    (1, ["API Error: 429 rate_limit_error"], "limit", "rate limited"),
    (1, ["API Error: Connection error."], "network", "connection error"),
    (1, ["getaddrinfo ENOTFOUND api.anthropic.com"], "network", "dns failure"),
    (1, ["error sending request for url"], "network", "network unreachable"),
    (1, ['API Error: 529 {"type":"error","error":{"type":"overloaded_error"}}'], "api", "api overloaded"),
    (1, ["API Error: 500 Internal server error"], "api", "api server error"),
    (1, ['{"type":"error","message":"stream disconnected before completion"}'], "api", "stream disconnected"),
    (1, ['{"type":"turn.failed","error":{"message":"stream disconnected before completion"}}'],
     "api", "stream disconnected"),
    # a clean exit is read only through the agent's own JSON error records
    (0, ['{"type":"result","is_error":true,"result":"API Error: 503 service unavailable"}'], "api",
     "api server error"),
])
def test_classify_names_the_failure_kind(rc, lines, kind, signal):
    f = wd.classify(rc, ["some ordinary output", *lines])
    assert f is not None and (f.kind, f.signal) == (kind, signal)
    assert f.human is (kind in ("auth", "limit"))


@pytest.mark.parametrize("rc,lines", [
    (0, [NOT_LOGGED_IN]),                    # plain text on a clean exit is the agent's work, not its death
    (3, [NOT_LOGGED_IN]),                    # the R-09 budget gate refused or stopped it: final
    (130, ["API Error: Connection error."]),  # interrupted by the player
    (-9, [NOT_LOGGED_IN]),                   # killed by a signal
    (1, ["Traceback: ValueError: bad padding"]),   # an ordinary failure: nothing a relaunch fixes
    # assistant / tool content quoting an error is data, even when the agent then fails
    (1, ['{"type":"assistant","message":{"content":[{"type":"text","text":"' + NOT_LOGGED_IN + '"}]}}']),
    (1, ['{"type":"result","is_error":false,"result":"' + NOT_LOGGED_IN + '"}']),
    (None, [NOT_LOGGED_IN]),
    # challenge text an agent's plain-text answer may quote: not the CLI's own errors
    (1, ["jwt.exceptions.ExpiredSignatureError: token has expired"]),
    (1, ["the session token expired; forging a new one with the leaked key"]),
    (1, ["see /billing for the admin panel"]),
    (1, ["login attempt limit reached, waiting before the next guess"]),
])
def test_classify_leaves_final_and_ordinary_endings_alone(rc, lines):
    assert wd.classify(rc, lines) is None


# Challenge and tool output an agent's tail carries (codex exec streams command output, stdout and
# stderr alike): the generic wording, with no CLI error prefix, is data. Each was a false relaunch (and
# for 429 / rate limited a critical ping and a block on the ack) before round 2.
CHALLENGE_LINES = [
    "HTTP/1.1 401 Unauthorized",
    "Authentication failed.",
    "HTTP/1.1 429 Too Many Requests",
    "rate limited",
    "nc: connectx to chal.local port 1337 (tcp) failed: Connection refused",
    "curl: (7) Failed to connect to chal port 80 after 2 ms: Couldn't connect to server",
    "curl: (6) Could not resolve host: chal.local",
    "HTTP/1.1 500 Internal Server Error",
    "<center>502 Bad Gateway</center>",
    "You are not logged in",
    '{"error": "Invalid API key"}',
    "requests.exceptions.HTTPError: 503 Server Error: Service Unavailable for url: http://chal/",
    "overloaded operator<< found in the binary",
    "Quota exceeded for this account",
]


@pytest.mark.parametrize("line", CHALLENGE_LINES)
def test_generic_wording_in_challenge_output_is_not_a_cli_failure(line):
    assert wd.classify(1, ["ran the exploit", line]) is None


@pytest.mark.parametrize("line,kind,signal", [
    ("Error: 401 Unauthorized", "auth", "http 401"),
    ("Error: Authentication failed", "auth", "authentication error"),
    ("API Error: Too Many Requests", "limit", "rate limited"),
    ("[2026-11-11T10:00:00] ERROR: rate limited, retry later", "limit", "rate limited"),
    ("ERROR: unexpected status 429 Too Many Requests", "limit", "rate limited"),
    ("Error: connect: Connection refused", "network", "connection error"),
    ("\x1b[31mERROR\x1b[0m: Could not resolve host", "network", "dns failure"),
    ("Error: Not logged in", "auth", "not logged in"),
    ("ERROR: Incorrect API key provided", "auth", "invalid api key"),
    ("API Error: Internal server error", "api", "api server error"),
])
def test_the_same_wording_counts_behind_a_cli_error_prefix(line, kind, signal):
    f = wd.classify(1, ["ran the exploit", line])
    assert f is not None and (f.kind, f.signal) == (kind, signal)


@pytest.mark.parametrize("line", ["error: 401 Unauthorized", "  some tool: Error: rate limited",
                                  "Errors: 429 too many requests"])
def test_the_cli_error_prefix_is_case_sensitive_and_at_line_start(line):
    assert wd.classify(1, [line]) is None


def test_generic_wording_counts_inside_a_json_error_record():
    rec = json.dumps({"type": "result", "is_error": True, "result": "429 Too Many Requests"})
    f = wd.classify(1, [rec])
    assert f is not None and (f.kind, f.signal) == ("limit", "rate limited")


def test_a_challenge_429_in_the_tail_does_not_block_on_the_player(agent, work):
    """The end-to-end harm: a limit classification pings critical and holds for an ack."""
    agent.steps({"out": ["HTTP/1.1 429 Too Many Requests"], "rc": 1})
    s = sup(agent, work)
    assert run(s) == 1
    assert len(agent.starts()) == 1
    assert not (work / "_watchdog" / "lane1.waiting").exists()
    assert events(work, "watchdog.wait_human") == []
    assert not any(" CRITICAL " in x for x in alerts(work))


def test_classify_reads_only_the_tail():
    lines = [NOT_LOGGED_IN] + [f"line {i}" for i in range(wd.TAIL_LINES)]
    assert wd.classify(1, lines) is None
    assert wd.classify(1, lines[1:] + [NOT_LOGGED_IN]).kind == "auth"


def test_auth_wins_over_a_network_word_in_the_same_tail():
    f = wd.classify(1, ["API Error: Connection error.", NOT_LOGGED_IN])
    assert f.kind == "auth"


# ------------------------------------------------------------------ probes

def test_http_probe_up_on_any_non_5xx_and_down_on_5xx(svc):
    p = wd.parse_probe(f"gm={svc.url}")
    for code in (200, 401, 404):
        svc.status = code
        assert p.check(2) == (True, f"HTTP {code}")
    for code in (500, 503):
        svc.status = code
        assert p.check(2) == (False, f"HTTP {code}")


def test_probe_down_when_nothing_answers():
    port = closed_port()
    assert wd.parse_probe(f"x=http://127.0.0.1:{port}/").check(2) == (False, "connection refused")
    assert wd.parse_probe(f"x=tcp://127.0.0.1:{port}").check(2) == (False, "connection refused")


def test_tcp_probe_up_when_it_connects(svc):
    assert wd.parse_probe(f"x=tcp://127.0.0.1:{svc.port}").check(2) == (True, "connected")


def test_http_probe_times_out_on_a_silent_server():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    try:
        t0 = time.monotonic()
        ok, detail = wd.parse_probe(f"x=http://127.0.0.1:{srv.getsockname()[1]}/").check(0.3)
        assert (ok, detail) == (False, "timed out")
        assert time.monotonic() - t0 < 3
    finally:
        srv.close()


@pytest.mark.parametrize("spec,why", [
    ("nourl", "NAME=URL"),
    ("x=ftp://h/", "must start with"),
    ("x=tcp://h", "needs a port"),
    ("x=http:///path", "no host"),
    ("x=https://user:pw@h/", "no credentials"),
    ("bad name=http://h/", "probe name"),
])
def test_bad_probe_specs_are_refused_by_name(spec, why):
    with pytest.raises(wd.WatchdogError, match=why):
        wd.parse_probe(spec)


def test_probes_from_env_flag_and_platform(monkeypatch, work):
    monkeypatch.setenv("CTF_WATCHDOG_PROBES", "api=tcp://127.0.0.1:1, net=http://127.0.0.1:2/")
    ps = wd.probes_from(["gm=http://127.0.0.1:3/"], platform=True, event_slug="pink")
    assert [(p.name, p.url) for p in ps] == [("gm", "http://127.0.0.1:3/"), ("api", "tcp://127.0.0.1:1"),
                                             ("net", "http://127.0.0.1:2/"), ("platform", "https://pink.ctf.example")]
    with pytest.raises(wd.WatchdogError, match="used twice: api"):
        wd.probes_from(["api=http://127.0.0.1:3/"], platform=False)
    with pytest.raises(wd.WatchdogError, match="has no base_url"):
        wd.probes_from([], platform=True, event_slug="spooky", use_env=False)


# ------------------------------------------------------------------ the monitor

def test_monitor_alerts_once_per_change_and_records_it(svc, work):
    rec = wd.ledger_recorder(work)
    mon = wd.Monitor([wd.parse_probe(f"gm={svc.url}")], record=rec, probe_timeout=2)
    assert mon.tick() is True and alerts(work) == []
    svc.status = 503
    assert mon.tick() is False
    assert mon.tick() is False                              # still down: no second alert
    svc.status = 200
    assert mon.tick() is True
    lines = alerts(work)
    assert len(lines) == 2, lines
    assert " WARN " in lines[0] and "unreachable: gm (HTTP 503)" in lines[0]
    assert " INFO " in lines[1] and "reachable again: gm" in lines[1]
    assert [(e["event"], e["probe"]) for e in events(work) if e["event"].startswith("watchdog.")] == \
        [("watchdog.down", "gm"), ("watchdog.up", "gm")]
    assert events(work, "watchdog.down")[0]["detail"] == "HTTP 503"


def test_monitor_says_network_down_when_every_probe_fails(svc, work, monkeypatch):
    port = closed_port()
    probes = [wd.parse_probe(f"a=http://127.0.0.1:{port}/"), wd.parse_probe(f"b=tcp://127.0.0.1:{port}")]
    wd.Monitor(probes, record=wd.ledger_recorder(work), probe_timeout=2).tick()
    assert "network looks down" in alerts(work)[0]
    # one of two down is not "the network"
    w2 = work / "two"
    probes = [wd.parse_probe(f"a=http://127.0.0.1:{port}/"), wd.parse_probe(f"b={svc.url}")]
    monkeypatch.setenv("CTF_WORKDIR", str(w2))
    wd.Monitor(probes, record=wd.ledger_recorder(w2), probe_timeout=2).tick()
    line = alerts(w2)[0]
    assert "network looks down" not in line and "unreachable: a (connection refused)" in line


def test_sleep_is_wall_time_the_uptime_clock_did_not_see(work):
    clock = {"wall": 1000.0, "up": 50.0}
    mon = wd.Monitor([], record=wd.ledger_recorder(work), sleep_gap=60,
                     wall=lambda: clock["wall"], uptime=lambda: clock["up"])
    assert mon.check_sleep() is None                        # the baseline
    clock["wall"] += 30; clock["up"] += 30                  # awake: both clocks moved
    assert mon.check_sleep() is None
    clock["wall"] += 59 + 5; clock["up"] += 5               # 59 s lost: under the gap
    assert mon.check_sleep() is None
    clock["wall"] += 600 + 5; clock["up"] += 5              # asleep for ten minutes
    assert mon.check_sleep() == 600
    clock["wall"] += 60; clock["up"] += 0                   # exactly the gap counts
    assert mon.tick() is True
    lines = alerts(work)
    assert len(lines) == 2 and "asleep or suspended for about 10 min" in lines[0]
    assert [e["gap_s"] for e in events(work, "watchdog.sleep")] == [600, 60]


def test_watch_command_alerts_on_down_once_over_several_rounds(tmp_path, svc):
    w = tmp_path / "w"
    svc.status = 503
    env = dict(os.environ, CTF_WORKDIR=str(w), CTF_QUIET="1")
    env.pop("CTF_WATCHDOG_PROBES", None)
    r = subprocess.run([PY, str(SCRIPT), "watch", "--probe", f"gm={svc.url}", "--interval", "0.05",
                        "--cycles", "3"], capture_output=True, text=True, env=env, timeout=60)
    assert r.returncode == 0, r.stderr
    assert r.stderr.count("ALERT WARN") == 1 and "gm (HTTP 503)" in r.stderr
    assert len(events(w, "watchdog.down")) == 1


@pytest.mark.parametrize("args,why", [
    (["watch"], "no probes"),
    (["watch", "--probe", "x=ftp://h/"], "must start with"),
    (["watch", "--platform", "--event", "spooky"], "has no base_url"),
    (["run", "--name", "lane1"], "no agent command"),
    (["run", "--name", "../x", "--", "true"], "agent name"),
    (["run", "--name", "lane1", "--poll", "0", "--", "true"], "poll must be positive"),
    (["ack", "lane1"], "no watchdog is waiting on agent 'lane1'"),
])
def test_cli_setup_errors_exit_2_with_a_named_reason(tmp_path, args, why):
    env = dict(os.environ, CTF_WORKDIR=str(tmp_path), CTF_QUIET="1")
    env.pop("CTF_WATCHDOG_PROBES", None)
    r = subprocess.run([PY, str(SCRIPT), *args], capture_output=True, text=True, env=env, timeout=60)
    assert r.returncode == 2 and why in r.stderr, (r.returncode, r.stderr)


def test_watch_dry_run_lists_the_platform_probe(tmp_path):
    env = dict(os.environ, CTF_WORKDIR=str(tmp_path), CTF_EVENT="pink")
    env.pop("CTF_WATCHDOG_PROBES", None)
    r = subprocess.run([PY, str(SCRIPT), "watch", "--platform", "--dry-run"], capture_output=True, text=True,
                       env=env, timeout=60)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "platform\thttps://pink.ctf.example"
    assert not (tmp_path / "ledger.jsonl").exists()


# ------------------------------------------------------------------ the supervisor

def test_a_clean_run_is_launched_once_and_its_output_passed_through(agent, work):
    agent.steps({"out": ["working", NOT_LOGGED_IN], "err": ["progress"], "rc": 0})
    out, err = io.StringIO(), io.StringIO()
    assert run(sup(agent, work, out=out, err=err)) == 0
    assert len(agent.starts()) == 1
    assert out.getvalue() == f"working\n{NOT_LOGGED_IN}\n" and err.getvalue() == "progress\n"
    assert alerts(work) == []


def test_an_ordinary_failure_is_not_relaunched(agent, work):
    agent.steps({"err": ["Traceback (most recent call last):", "KeyError: 'x'"], "rc": 1})
    assert run(sup(agent, work)) == 1
    assert len(agent.starts()) == 1 and alerts(work) == []
    end, = events(work, "watchdog.agent_end")
    assert end["rc"] == 1 and "failure" not in end and not events(work, "watchdog.relaunch")


def test_auth_failure_is_relaunched_once_automatically_with_resume_args(agent, work):
    agent.steps({"out": ['{"type":"result","is_error":true,"result":"' + NOT_LOGGED_IN + '"}'], "rc": 1},
                {"out": ["solved"], "rc": 0})
    s = sup(agent, work, resume_args=("--continue",))
    assert run(s) == 0
    assert agent.starts() == [["-p", "go"], ["-p", "go", "--continue"]]
    lines = alerts(work)
    assert len(lines) == 2
    assert " WARN [lane1] " in lines[0] and "auth failure (not logged in)" in lines[0]
    assert " INFO [lane1] " in lines[1] and "relaunching agent lane1 (relaunch 1 of 3)" in lines[1]
    ends = events(work, "watchdog.agent_end")
    assert [(e["attempt"], e["rc"], e.get("failure")) for e in ends] == [(1, 1, "auth"), (2, 0, None)]
    assert all(e["agent"] == "lane1" for e in events(work))
    assert [e["attempt"] for e in events(work, "watchdog.relaunch")] == [2]


def test_second_auth_failure_pings_the_player_and_waits_for_ack(agent, work):
    agent.steps({"err": [NOT_LOGGED_IN], "rc": 1}, {"err": [NOT_LOGGED_IN], "rc": 1}, {"out": ["ok"], "rc": 0})
    s = sup(agent, work)
    result = {}
    t = threading.Thread(target=lambda: result.setdefault("rc", s.run()), daemon=True)
    t.start()
    waiting = work / "_watchdog" / "lane1.waiting"
    assert wait_for(waiting.exists)
    time.sleep(0.4)                                          # it holds: no relaunch without the ack
    assert len(agent.starts()) == 2 and t.is_alive()
    crit = [x for x in alerts(work) if " CRITICAL " in x]
    assert len(crit) == 1 and "needs you" in crit[0] and "/login" in crit[0]
    assert "tools/watchdog.py ack lane1" in crit[0]
    env = dict(os.environ)
    r = subprocess.run([PY, str(SCRIPT), "ack", "lane1"], capture_output=True, text=True, env=env, timeout=60)
    assert r.returncode == 0, r.stderr
    t.join(timeout=20)
    assert result.get("rc") == 0 and len(agent.starts()) == 3
    assert not waiting.exists() and not (work / "_watchdog" / "lane1.ack").exists()
    kinds = [e["event"] for e in events(work)]
    last_relaunch = max(i for i, k in enumerate(kinds) if k == "watchdog.relaunch")
    assert kinds.index("watchdog.wait_human") < kinds.index("watchdog.ack") < last_relaunch


def test_an_old_ack_does_not_release_a_new_wait(agent, work):
    d = work / "_watchdog"
    d.mkdir()
    (d / "lane1.ack").write_text("{}")                       # left over from earlier
    agent.steps({"err": ["Claude AI usage limit reached"], "rc": 1}, {"rc": 0})
    s = sup(agent, work)
    t = threading.Thread(target=s.run, daemon=True)
    t.start()
    assert wait_for((d / "lane1.waiting").exists)
    time.sleep(0.3)
    assert len(agent.starts()) == 1 and t.is_alive()
    wd.ack("lane1", work)
    t.join(timeout=20)
    assert not t.is_alive() and len(agent.starts()) == 2


def test_a_usage_limit_needs_the_player_at_once_and_is_pinged_again(agent, work):
    agent.steps({"err": ["Claude AI usage limit reached|1762000000"], "rc": 1}, {"rc": 0})
    s = sup(agent, work, renotify=0.15)
    t = threading.Thread(target=s.run, daemon=True)
    t.start()
    assert wait_for(lambda: sum("still waiting on you" in x for x in alerts(work)) >= 2)
    assert len(agent.starts()) == 1
    assert not any(" WARN " in x for x in alerts(work))      # no "relaunching when it can" promise
    wd.ack("lane1", work)
    t.join(timeout=20)
    assert len(agent.starts()) == 2


class FakeClock:
    """Wall time that moves only when the code under test sleeps; `on_sleep` runs after each sleep."""

    def __init__(self, start=1000.0, on_sleep=None):
        self.now = start
        self.start = start
        self.slept: list[float] = []
        self.on_sleep = on_sleep

    def wall(self):
        return self.now

    def sleep(self, s):
        self.slept.append(s)
        self.now += s
        if self.on_sleep:
            self.on_sleep(self)


def test_the_re_ping_goes_out_every_renotify_seconds_not_every_poll(agent, work, monkeypatch):
    """renotify=10, poll=1, ack at 35 s: re-pings at exactly 10, 20 and 30 s, three and no more."""
    ack = work / "_watchdog" / "lane1.ack"

    def ack_at_35(c):
        if c.now - c.start >= 35:
            ack.write_text("{}")

    clock = FakeClock(on_sleep=ack_at_35)
    sent = []                     # (seconds into the wait, message) of each alert, on the fake clock
    real_alert = wd._alert.alert

    def timed_alert(level, message, **kw):
        sent.append((clock.now - clock.start, message))
        return real_alert(level, message, **kw)

    monkeypatch.setattr(wd._alert, "alert", timed_alert)
    agent.steps({"rc": 0})
    s = wd.Supervisor("lane1", agent.argv(), workdir=work, policy=wd.Policy(poll=1.0, renotify=10.0),
                      stdout=io.StringIO(), stderr=io.StringIO(), wall=clock.wall, sleep=clock.sleep)
    assert s.wait_human(wd.Failure("limit", "usage limit")) is True
    assert len(clock.slept) == 35
    assert [t for t, m in sent if "needs you" in m] == [0]
    assert [t for t, m in sent if "still waiting on you" in m] == [10, 20, 30], sent
    lines = alerts(work)
    assert sum("needs you" in x for x in lines) == 1
    assert sum("still waiting on you" in x for x in lines) == 3, lines


@pytest.mark.parametrize("where", ["record", "alert"])
def test_ctrl_c_while_the_wait_is_being_announced_leaves_no_stale_wait(agent, work, monkeypatch, where):
    """A Ctrl-C between writing the .waiting marker and the wait loop (during the ledger record or the
    first critical ping) still clears the marker, so a later `ack` is refused: nobody is waiting."""
    waiting = work / "_watchdog" / "lane1.waiting"
    seen = {}
    agent.steps({"err": ["Claude AI usage limit reached"], "rc": 1}, {"rc": 0})
    s = sup(agent, work)
    if where == "record":
        real_record = s.record

        def record(event, **kw):
            if event == "watchdog.wait_human":
                seen["marker"] = waiting.exists()
                raise KeyboardInterrupt
            return real_record(event, **kw)
        s.record = record
    else:
        real_alert = wd._alert.alert

        def alert(level, message, **kw):
            if "needs you" in message:
                seen["marker"] = waiting.exists()
                raise KeyboardInterrupt
            return real_alert(level, message, **kw)
        monkeypatch.setattr(wd._alert, "alert", alert)
    assert run(s) == 130
    assert seen == {"marker": True}          # the interrupt landed while the marker was there
    assert not waiting.exists()
    assert len(agent.starts()) == 1
    with pytest.raises(wd.WatchdogError):
        wd.ack("lane1", work)


def test_interrupt_while_waiting_for_the_ack_exits_130_and_clears_the_wait(agent, work):
    agent.steps({"err": ["Claude AI usage limit reached"], "rc": 1}, {"rc": 0})

    waiting = work / "_watchdog" / "lane1.waiting"

    def ctrl_c(c):          # the player's Ctrl-C lands once the watchdog holds for the ack
        if waiting.exists():
            raise KeyboardInterrupt

    clock = FakeClock(on_sleep=ctrl_c)
    s = sup(agent, work)
    s.wall, s.sleep = clock.wall, clock.sleep
    assert run(s) == 130
    assert len(agent.starts()) == 1
    assert len(events(work, "watchdog.wait_human")) == 1
    assert [e["reason"] for e in events(work, "watchdog.gave_up")] == ["interrupted"]
    assert not waiting.exists()


def test_ctrl_c_on_the_run_command_while_it_waits_is_exit_130_not_a_traceback(tmp_path, agent):
    w = tmp_path / "w"
    agent.steps({"err": ["Claude AI usage limit reached"], "rc": 1}, {"rc": 0})
    env = dict(os.environ, CTF_WORKDIR=str(w), CTF_QUIET="1")
    env.pop("CTF_WATCHDOG_PROBES", None)
    # SIGINT raises KeyboardInterrupt even when the test runner left it ignored for its children
    boot = ("import runpy, signal, sys; signal.signal(signal.SIGINT, signal.default_int_handler); "
            "sys.argv = sys.argv[1:]; runpy.run_path(sys.argv[0], run_name='__main__')")
    p = subprocess.Popen([PY, "-c", boot, str(SCRIPT), "run", "--name", "lane1", "--poll", "0.05",
                          "--retry-wait", "0.01", "--", *agent.argv("-p", "go")],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
                         stdin=subprocess.DEVNULL)
    try:
        assert wait_for((w / "_watchdog" / "lane1.waiting").exists, timeout=20)
        p.send_signal(signal.SIGINT)
        _, err = p.communicate(timeout=30)
    finally:
        if p.poll() is None:
            p.kill()
            p.wait()
    assert p.returncode == 130, err
    assert "Traceback" not in err and "interrupted; not relaunching" in err
    assert [e["reason"] for e in events(w, "watchdog.gave_up")] == ["interrupted"]
    assert not (w / "_watchdog" / "lane1.waiting").exists() and len(agent.starts()) == 1


def test_a_network_failure_between_two_auth_failures_resets_the_auth_count(agent, work):
    """auth, network, auth: the auth failures are not consecutive, so each gets its automatic relaunch."""
    agent.steps({"err": [NOT_LOGGED_IN], "rc": 1}, {"err": ["API Error: Connection error."], "rc": 1},
                {"err": [NOT_LOGGED_IN], "rc": 1}, {"rc": 0})
    assert run(sup(agent, work, give_up_after=2.0)) == 0
    assert len(agent.starts()) == 4
    assert events(work, "watchdog.wait_human") == [] and events(work, "watchdog.gave_up") == []
    assert not any(" CRITICAL " in x for x in alerts(work))


def test_api_failure_waits_until_the_probe_is_reachable(agent, work, svc):
    agent.steps({"err": ["API Error: 529 overloaded_error"], "rc": 1}, {"rc": 0})
    svc.status = 503
    sleeps = []

    def fake_sleep(s):
        sleeps.append(s)
        if len(sleeps) == 3:
            svc.status = 200

    s = sup(agent, work, probes=[wd.parse_probe(f"api={svc.url}")])
    s.sleep = fake_sleep
    assert run(s) == 0
    assert len(sleeps) == 3 and len(agent.starts()) == 2
    kinds = [e["event"] for e in events(work)]
    starts = [i for i, k in enumerate(kinds) if k == "watchdog.agent_start"]
    assert kinds.index("watchdog.down") < kinds.index("watchdog.up") < starts[1]
    assert any("reachable again: api" in x for x in alerts(work))


def test_network_failure_without_probes_waits_retry_wait_and_says_so(agent, work):
    agent.steps({"err": ["API Error: Connection error."], "rc": 1}, {"rc": 0})
    err = io.StringIO()
    slept = []
    s = sup(agent, work, err=err, retry_wait=7)
    s.sleep = slept.append
    assert run(s) == 0
    assert slept == [7] and len(agent.starts()) == 2
    assert "no probes configured: relaunching after a 7 s wait" in err.getvalue()


def test_gives_up_after_max_relaunches_with_a_critical_alert(agent, work):
    agent.steps({"err": ["getaddrinfo ENOTFOUND api.example"], "rc": 7})
    assert run(sup(agent, work, max_relaunches=2, resume_args=("--continue",))) == 7
    # the resume args are added once to the original command, never stacked relaunch after relaunch
    assert agent.starts() == [["-p", "go"], ["-p", "go", "--continue"], ["-p", "go", "--continue"]]
    last = alerts(work)[-1]
    assert " CRITICAL " in last and "after 2 relaunch(es); not relaunching again" in last
    assert events(work, "watchdog.gave_up")[0]["reason"] == "max_relaunches"


def test_gives_up_waiting_for_reachability_after_give_up_after(agent, work):
    agent.steps({"err": ["API Error: 503 service unavailable"], "rc": 1}, {"rc": 0})
    port = closed_port()
    t0 = time.monotonic()
    rc = run(sup(agent, work, probes=[wd.parse_probe(f"api=tcp://127.0.0.1:{port}")], give_up_after=0.3))
    assert rc == 1 and len(agent.starts()) == 1
    assert time.monotonic() - t0 < 10
    assert events(work, "watchdog.gave_up")[0]["reason"] == "unreachable"


@pytest.mark.parametrize("step", [
    {"err": [NOT_LOGGED_IN], "rc": 3},                       # the budget gate's exit code
    {"err": [NOT_LOGGED_IN], "kill": True},                  # died by a signal
])
def test_final_endings_are_never_relaunched(agent, work, step):
    agent.steps(step, {"rc": 0})
    rc = run(sup(agent, work))
    assert rc == (3 if step.get("rc") == 3 else -9)
    assert len(agent.starts()) == 1 and alerts(work) == []


def test_output_text_never_reaches_alerts_or_the_ledger(agent, work):
    agent.steps({"err": [f"{NOT_LOGGED_IN} sk-ant-api03-SECRETVALUE"], "rc": 1}, {"rc": 0})
    assert run(sup(agent, work)) == 0
    assert "SECRETVALUE" not in (work / "_logs" / "ALERTS.log").read_text()
    assert "SECRETVALUE" not in (work / "ledger.jsonl").read_text()


def test_probes_keep_running_while_the_agent_works(agent, work):
    port = closed_port()
    agent.steps({"out": ["thinking"], "sleep": 0.6, "rc": 0})
    assert run(sup(agent, work, probes=[wd.parse_probe(f"api=tcp://127.0.0.1:{port}")])) == 0
    kinds = [e["event"] for e in events(work)]
    assert kinds.index("watchdog.agent_start") < kinds.index("watchdog.down") < kinds.index("watchdog.agent_end")
    assert len([k for k in kinds if k == "watchdog.down"]) == 1
    assert any("unreachable: api" in x for x in alerts(work))


def test_run_command_end_to_end(tmp_path, agent):
    w = tmp_path / "w"
    agent.steps({"out": ["first"], "err": [NOT_LOGGED_IN], "rc": 1}, {"out": ["second"], "rc": 0})
    env = dict(os.environ, CTF_WORKDIR=str(w), CTF_QUIET="1")
    env.pop("CTF_WATCHDOG_PROBES", None)
    r = subprocess.run([PY, str(SCRIPT), "run", "--name", "lane1", "--poll", "0.05", "--retry-wait", "0.01",
                        "--resume-arg=--continue", "--", *agent.argv("-p", "go")],
                       capture_output=True, text=True, env=env, timeout=60, stdin=subprocess.DEVNULL)
    assert r.returncode == 0, r.stderr
    assert r.stdout == "first\nsecond\n"
    assert agent.starts() == [["-p", "go"], ["-p", "go", "--continue"]]
    assert "ALERT WARN [lane1]" in r.stderr and "ALERT INFO [lane1]" in r.stderr


def test_run_command_with_a_missing_agent_binary_exits_2(tmp_path):
    env = dict(os.environ, CTF_WORKDIR=str(tmp_path), CTF_QUIET="1")
    r = subprocess.run([PY, str(SCRIPT), "run", "--name", "lane1", "--", str(tmp_path / "no-such-agent")],
                       capture_output=True, text=True, env=env, timeout=60)
    assert r.returncode == 2 and "cannot start the agent" in r.stderr


def test_probes_go_direct_not_through_a_proxy(svc, monkeypatch):
    dead = f"http://127.0.0.1:{closed_port()}"
    for var in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY"):
        monkeypatch.setenv(var, dead)
    for var in ("no_proxy", "NO_PROXY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr("urllib.request.proxy_bypass", lambda host: False)
    assert wd.parse_probe(f"gm={svc.url}").check(2) == (True, "HTTP 200")


def test_platform_probe_on_an_unknown_event_is_a_named_error(work):
    with pytest.raises(wd.WatchdogError, match="--platform: no event profile"):
        wd.platform_probe("no-such-event")


def test_an_ack_resets_the_auth_count(agent, work):
    """After the player's fix, the next auth failure gets its automatic relaunch again."""
    agent.steps({"err": [NOT_LOGGED_IN], "rc": 1}, {"err": [NOT_LOGGED_IN], "rc": 1},
                {"err": [NOT_LOGGED_IN], "rc": 1}, {"rc": 0})
    s = sup(agent, work, give_up_after=2.0)
    box = {}
    t = threading.Thread(target=lambda: box.setdefault("rc", s.run()), daemon=True)
    t.start()
    assert wait_for((work / "_watchdog" / "lane1.waiting").exists)
    wd.ack("lane1", work)
    t.join(timeout=20)
    assert box.get("rc") == 0 and len(agent.starts()) == 4
    assert len(events(work, "watchdog.wait_human")) == 1
