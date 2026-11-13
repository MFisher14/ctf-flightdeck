"""B-185: the release latency path -- pre-warmed connections, parallel list and start, phase timing,
status-only start recovery with a persisted pending attempt and a provisioning alert, the sole-lane
exemption from the minute hold, and the wire-floor table per mode.

The live-path tests run against a fake Game Master this file starts on 127.0.0.1 (a real HTTP/1.1
keep-alive server that counts the TCP connections it accepts); the guard's timing rules run on a
scripted platform double and a virtual clock. Nothing here leaves the machine.
"""
from __future__ import annotations

import dataclasses
import hashlib
import io
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from ctf import cli, env, event, paths
from ctf.event import WirePace
from ctf.platform import NotAllowed, NotSupported, PlatformError, get_adapter, latency, wire
from ctf.platform.base import InstanceInfo
from ctf.platform.wire import POLL, PRIORITY, READ

T0 = 1_760_000_400.0
CID = "web-day-28"
ART = b"synthetic delivery bytes\n" * 40


# ------------------------------------------------------------------------------------------ fakes

class FakeGM:
    """A fake Game Master on 127.0.0.1. Start behaviour per test:
    prep_s        after the attempt is created, status says preparing this long, then running
    hang_first_s  the first start POST answers only after this long (the client times out first)
    lose_first    the first start POST creates no attempt (a POST that never landed)
    list_delay_s  the list answers this late (so a serial list-then-start shows)
    stop_after_start  the start POST is accepted (preparing), but status then reports the attempt
                  expired, so the mode is stopped after the start with the clock never running
    """

    def __init__(self, prep_s=0.0, hang_first_s=0.0, lose_first=False, listed=(CID,), list_delay_s=0.0,
                 stop_after_start=False):
        self.prep_s, self.hang_first_s, self.lose_first = prep_s, hang_first_s, lose_first
        self.stop_after_start = stop_after_start
        self.list_delay_s = list_delay_s
        self.listed = list(listed)
        self.created: float | None = None
        self.connections = 0
        self.requests: list[tuple[str, str, str | None, float]] = []   # (method, op, challenge, when)
        self.lock = threading.Lock()
        fake = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _reply(self, code, body, ctype="application/json", extra=None):
                data = body if isinstance(body, bytes) else json.dumps(body).encode()
                try:
                    self.send_response(code)
                    self.send_header("Content-Type", ctype)
                    self.send_header("Content-Length", str(len(data)))
                    for k, v in (extra or {}).items():
                        self.send_header(k, v)
                    self.end_headers()
                    self.wfile.write(data)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def do_GET(self):
                q = {k: v[0] for k, v in parse_qs(urlsplit(self.path).query).items()}
                op, cid = q.get("op"), q.get("challenge")
                with fake.lock:
                    fake.requests.append(("GET", op, cid, time.time()))
                if op == "list":
                    time.sleep(fake.list_delay_s)
                    return self._reply(200, {"challenges": [{"id": c, "name": c, "lane": "web", "day": 28,
                                                             "mode": "single_solve"} for c in fake.listed]})
                if op == "status":
                    st = fake.state()
                    if st == "absent":
                        return self._reply(409, {"error": "start_required"})
                    if st == "preparing":
                        return self._reply(200, {"result": "preparing", "challenge": cid})
                    if st == "stopped":
                        return self._reply(200, {"result": "expired", "challenge": cid})
                    return self._reply(200, fake.attempt(cid))
                if op == "artifact":
                    return self._reply(200, ART, "application/octet-stream",
                                       {"Content-Disposition": 'attachment; filename="site.tar"'})
                return self._reply(400, {"error": "invalid_request"})

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}")
                cid = body.get("challenge")
                with fake.lock:
                    fake.requests.append(("POST", "submit" if "answers" in body else "start", cid, time.time()))
                    first = sum(1 for r in fake.requests if r[1] == "start") == 1
                if "answers" in body:
                    return self._reply(200, {"result": "CORRECT"})
                if not (first and fake.lose_first):
                    with fake.lock:
                        if fake.created is None:
                            fake.created = time.time()
                if first and fake.hang_first_s:
                    time.sleep(fake.hang_first_s)
                st = fake.state()
                if st == "stopped":
                    # the start was accepted and is provisioning; the expiry shows on the next status read
                    return self._reply(200, {"result": "preparing", "challenge": cid})
                if st == "preparing":
                    return self._reply(200, {"result": "preparing", "challenge": cid})
                if st == "absent":
                    return self._reply(503, {"error": "mode_configuration_invalid"})
                return self._reply(200, fake.attempt(cid))

        class S(ThreadingHTTPServer):
            daemon_threads = True

            def process_request(self, request, client_address):
                with fake.lock:
                    fake.connections += 1
                super().process_request(request, client_address)

        self.server = S(("127.0.0.1", 0), H)
        self.port = self.server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def state(self) -> str:
        if self.created is None:
            return "absent"
        if self.stop_after_start:
            return "stopped"
        return "preparing" if time.time() - self.created < self.prep_s else "running"

    def attempt(self, cid):
        return {"attempt_id": "att-1", "challenge": cid, "questions": [{"id": "q1"}],
                "targets": [{"url": "http://127.0.0.1:9/target"}],
                "artifacts": [{"filename": "site.tar", "sha256": hashlib.sha256(ART).hexdigest()}]}

    def ops(self, op=None):
        return [r for r in self.requests if op is None or r[1] == op]

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def gm():
    servers = []

    def make(**kw):
        s = FakeGM(**kw)
        servers.append(s)
        return s
    yield make
    for s in servers:
        s.close()


@pytest.fixture
def loopback(tmp_path, monkeypatch):
    """(profile root, workdir) with a huntress profile pointed at a fake Game Master URL."""
    for name in ("CTF_PLATFORM_URL", "CTF_WIRE_LANE", "CTF_EVENT", *env.legacy_names("CTF_PLATFORM_URL")):
        monkeypatch.delenv(name, raising=False)
    wd = tmp_path / "work"
    monkeypatch.setenv("CTF_WORKDIR", str(wd))

    def profile(url):
        root = tmp_path / "events"
        (root / "huntress").mkdir(parents=True, exist_ok=True)
        src = event.load("huntress").path.read_text().replace(
            'base_url = "https://gamemaster.huntress.example"', f'base_url = "{url}"')
        (root / "huntress" / "event.toml").write_text(src)
        monkeypatch.setattr(paths, "events_root", lambda: root)
        return event.load("huntress")
    return profile, wd


class Clock:
    def __init__(self, t=T0):
        self.t = t
        self.slept: list[float] = []

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.slept.append(s)
        self.t += s


class Platform:
    """A scripted platform for the guard: start_instance answers from `posts` (an InstanceInfo state
    or an exception), instance_status from `status(t)` on the virtual clock."""

    kind = "gamemaster"

    def __init__(self, clock, posts, status):
        self.clock, self._posts, self._status = clock, list(posts), status
        self.post_calls: list[float] = []
        self.status_calls: list[float] = []

    def start_instance(self, cid):
        self.post_calls.append(self.clock())
        a = self._posts.pop(0)
        if isinstance(a, BaseException):
            raise a
        return InstanceInfo(cid, a)

    def instance_status(self, cid):
        self.status_calls.append(self.clock())
        return InstanceInfo(cid, self._status(self.clock()))


def settle(cond, timeout=3.0):
    end = time.monotonic() + timeout
    while not cond() and time.monotonic() < end:
        time.sleep(0.01)


def guard(plat, clock, wd, **kw):
    err = io.StringIO()
    g = latency.StartGuard(plat, workdir=wd, clock=clock, sleep=clock.sleep, err=err, **kw)
    return g, err


# ------------------------------------------------------------------------------------------ sole lane

def pace(**kw):
    return dataclasses.replace(WirePace(), **kw)


def test_sole_lane_rule():
    p = pace(release_window_s=60.0)
    rows = [[T0 + 1, "web", READ], [T0 + 2, "bin", READ], [T0 + 3, "watch", READ], [T0 + 4, "meta", POLL]]
    now = T0 + 10
    assert wire.sole_lane(rows, "bin", [T0], now, p, {"web": T0 + 5})
    # web marked done before this window's anchor: it is still working in this one
    assert not wire.sole_lane(rows, "bin", [T0], now, p, {"web": T0 - 1})
    assert not wire.sole_lane(rows, "bin", [T0], now, p, {})
    # an unnamed request that is not a poll blocks it; an unnamed poll does not
    assert not wire.sole_lane(rows + [[T0 + 6, None, PRIORITY]], "bin", [T0], now, p, {"web": T0 + 5})
    assert wire.sole_lane(rows + [[T0 + 6, None, POLL]], "bin", [T0], now, p, {"web": T0 + 5})
    # a lane named in release_lanes counts even before it sends anything
    p2 = pace(release_window_s=60.0, release_lanes=(("mobile", 4),))
    assert not wire.sole_lane(rows, "bin", [T0], now, p2, {"web": T0 + 5})
    assert wire.sole_lane(rows, "bin", [T0], now, p2, {"web": T0 + 5, "mobile": T0 + 7})
    # outside a window, and for an unnamed lane: never
    assert not wire.sole_lane(rows, "bin", [T0], T0 + 61, p, {"web": T0 + 5})
    assert not wire.sole_lane(rows, None, [T0], now, p, {"web": T0 + 5})
    # alone in the window with no other lane known: not "the last one working"
    assert not wire.sole_lane([[T0 + 2, "bin", READ]], "bin", [T0], now, p, {})
    assert not wire.sole_lane([[T0 + 2, "bin", READ]], "bin", [T0], now, p, {"web": T0 - 1})
    # a lane marked done in this window counts as known (and done) even with no request
    assert wire.sole_lane([[T0 + 2, "bin", READ]], "bin", [T0], now, p, {"web": T0 + 1})
    # a request from before the window does not make a competitor
    assert wire.sole_lane([[T0 - 5, "mob", READ], [T0 + 2, "bin", READ]], "bin", [T0], now, p,
                          {"web": T0 + 1})


def _wire(tmp_path, clock, lane, **kw):
    prof = dataclasses.replace(event.load("huntress"), wire=pace(**kw))
    return wire.Wire(prof, workdir=tmp_path, lane=lane, clock=clock, sleep=clock.sleep, err=io.StringIO())


def test_sole_lane_is_exempt_from_the_lane_hold_and_journaled(tmp_path):
    clock = Clock(T0 + 1)
    wire.mark_releases(tmp_path, [T0], now=T0)
    kw = dict(release_lane_budget=1, release_window_s=60.0, max_wait_s=30.0)
    web, bin_ = _wire(tmp_path, clock, "web", **kw), _wire(tmp_path, clock, "bin", **kw)
    assert web.admit("web", READ)["held_s"] == 0
    clock.t = T0 + 2
    assert bin_.admit("bin", READ)["exempt"] is None
    # bin's second read: held by its lane budget while web is still working
    steps = bin_.admission("bin", READ)
    assert next(steps) > 0
    steps.close()
    wire.mark_lane_done(tmp_path, "web", now=T0 + 3)
    clock.t = T0 + 4
    adm = bin_.admit("bin", READ)
    assert adm["held_s"] == 0 and adm["exempt"] == "sole_lane" and adm["forced"] is False
    assert clock.slept == []
    # undo: web works again, so bin is held again
    wire.mark_lane_done(tmp_path, "web", done=False, now=T0 + 5)
    steps = bin_.admission("bin", READ)
    assert next(steps) > 0
    steps.close()


def test_sole_lane_is_exempt_from_the_release_budget_too(tmp_path):
    clock = Clock(T0 + 1)
    wire.mark_releases(tmp_path, [T0], now=T0)
    kw = dict(release_budget=2, release_window_s=60.0)
    web, bin_ = _wire(tmp_path, clock, "web", **kw), _wire(tmp_path, clock, "bin", **kw)
    web.admit("web", READ)
    bin_.admit("bin", READ)
    clock.t = T0 + 2
    steps = bin_.admission("bin", READ)
    assert next(steps) == pytest.approx(30.0)      # held by the release budget (re-asked at max_wait_s)
    steps.close()
    wire.mark_lane_done(tmp_path, "web", now=T0 + 2)
    adm = bin_.admit("bin", READ)
    assert adm["exempt"] == "sole_lane" and adm["held_s"] == 0


def test_sole_lane_never_lifts_the_team_cap(tmp_path):
    clock = Clock(T0 + 1)
    wire.mark_releases(tmp_path, [T0], now=T0)
    kw = dict(per_minute=2, release_lane_budget=1, release_window_s=60.0)
    w = _wire(tmp_path, clock, "bin", **kw)
    w.admit("bin", READ)
    clock.t = T0 + 2
    steps = w.admission("bin", READ)       # the lane budget: no other lane known, so not sole
    wait = next(steps)
    steps.close()
    assert wait > 0
    wire.mark_lane_done(tmp_path, "web", now=T0 + 2)   # the only other lane is done: bin is sole
    clock.t = T0 + 3
    assert w.admit("bin", READ)["exempt"] == "sole_lane"
    clock.t = T0 + 4
    steps = w.admission("bin", READ)       # 2 in the last 60 s = per_minute: the team cap holds
    wait = next(steps)
    steps.close()
    assert wait == pytest.approx(T0 + 1 + 60 - (T0 + 4))


def test_mark_lane_done_validates_and_records(tmp_path):
    with pytest.raises(wire.WireError, match="must match"):
        wire.mark_lane_done(tmp_path, "bad lane")
    assert wire.mark_lane_done(tmp_path, "web", now=T0) == {"web": T0}
    assert wire.mark_lane_done(tmp_path, "bin", now=T0 + 1) == {"web": T0, "bin": T0 + 1}
    assert wire.mark_lane_done(tmp_path, "web", done=False, now=T0 + 2) == {"bin": T0 + 1}


@pytest.mark.parametrize("headers,want", [({"Content-Length": "123"}, 123), ({"content-length": "7"}, 7),
                                          ({}, None), ({"Content-Length": "x"}, None),
                                          ({"Content-Length": "-1"}, None)])
def test_content_length(headers, want):
    class R:
        pass
    r = R()
    r.headers = headers
    assert wire.content_length(r) == want


# ------------------------------------------------------------------------------------------ warm

def test_warm_opens_connections_without_a_request_and_they_are_reused(gm, loopback):
    srv = gm()
    profile, wd = loopback
    gate = get_adapter(profile(srv.url))
    assert latency.warm(gate, 2) == 2
    settle(lambda: srv.connections >= 2)           # the server accepts after the client's connect returns
    assert srv.connections == 2 and srv.requests == []
    assert wire.read_journal(wd)[0] == []                 # nothing sent, nothing counted
    got = latency.parallel({"list": gate.list_challenges, "status": lambda: gate.instance_status(CID)})
    assert all(o.ok for o in got.values()), got
    assert len(srv.requests) == 2 and srv.connections == 2   # both rode the warm connections


def test_without_warm_parallel_requests_open_their_own_connections(gm, loopback):
    """The control for the test above: the connection count is what warm changes."""
    srv = gm()
    profile, _ = loopback
    gate = get_adapter(profile(srv.url))
    assert srv.connections == 0
    latency.parallel({"list": gate.list_challenges, "status": lambda: gate.instance_status(CID)})
    assert srv.connections >= 1 and len(srv.requests) == 2


def test_warm_refuses_what_it_cannot_warm(gm, loopback):
    srv = gm()
    profile, _ = loopback
    gate = get_adapter(profile(srv.url))
    with pytest.raises(ValueError):
        latency.warm(gate, 0)
    with pytest.raises(latency.LatencyError, match="pool keeps 10"):
        latency.warm(gate, 11)

    class NoSession:
        kind = "manual"
    with pytest.raises(NotSupported, match="no requests session"):
        latency.warm(NoSession())


def test_warm_names_missing_urllib3_pool_internals(gm, loopback, monkeypatch):
    """warm() rides urllib3 pool internals; a urllib3 without them is named before any connect."""
    import requests.adapters
    srv = gm()
    profile, _ = loopback
    gate = get_adapter(profile(srv.url))
    real = requests.adapters.HTTPAdapter.get_connection_with_tls_context

    class Stripped:
        """The real pool's public face without _get_conn (as a urllib3 that renamed it would be)."""
        def __init__(self, pool):
            self.pool, self._put_conn = pool.pool, pool._put_conn

    monkeypatch.setattr(requests.adapters.HTTPAdapter, "get_connection_with_tls_context",
                        lambda self, *a, **k: Stripped(real(self, *a, **k)))
    with pytest.raises(latency.LatencyError, match=r"urllib3 .* has no _get_conn; warm\(\) needs urllib3 2\.x"):
        latency.warm(gate, 1)
    assert srv.connections == 0


def test_warm_names_a_pool_queue_without_maxsize(gm, loopback, monkeypatch):
    """The pool's queue must say how many idle connections it keeps (pool.maxsize); one that does not
    is named before any connect, not guessed at."""
    import requests.adapters
    srv = gm()
    profile, _ = loopback
    gate = get_adapter(profile(srv.url))
    real = requests.adapters.HTTPAdapter.get_connection_with_tls_context

    class NoMaxsize:
        """A pool queue with no maxsize attribute."""

    class Stripped:
        """The real pool's _get_conn and _put_conn, over a queue that does not report its size."""
        def __init__(self, pool):
            self._get_conn, self._put_conn, self.pool = pool._get_conn, pool._put_conn, NoMaxsize()

    monkeypatch.setattr(requests.adapters.HTTPAdapter, "get_connection_with_tls_context",
                        lambda self, *a, **k: Stripped(real(self, *a, **k)))
    with pytest.raises(latency.LatencyError, match=r"urllib3 .* has no pool\.maxsize; warm\(\) needs"):
        latency.warm(gate, 1)
    assert srv.connections == 0


def test_warm_connect_failure_is_named(loopback):
    profile, _ = loopback
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()                                   # nothing listens there
    gate = get_adapter(profile(f"http://127.0.0.1:{port}"))
    with pytest.raises(latency.LatencyError, match="connect to .* failed"):
        latency.warm(gate, 1)


# ------------------------------------------------------------------------------------------ parallel, phases

def test_parallel_runs_at_once_and_keeps_errors(tmp_path):
    log = latency.PhaseLog(tmp_path, challenge="c1", anchor=time.time())

    def slow():
        time.sleep(0.3)
        return 1

    def boom():
        time.sleep(0.3)
        raise PlatformError("nope")
    t = time.monotonic()
    got = latency.parallel({"a": slow, "b": boom, "c": slow}, phases=log)
    assert time.monotonic() - t < 0.6               # serially it is 0.9 s
    assert got["a"].value == 1 and got["a"].ok and not got["b"].ok
    assert isinstance(got["b"].error, PlatformError)
    rows, bad = latency.read_phases(tmp_path)
    assert bad == 0 and sorted(r["phase"] for r in rows) == ["a", "b", "c"]
    b = next(r for r in rows if r["phase"] == "b")
    assert b["ok"] is False and b["error"] == "PlatformError" and b["dur_s"] >= 0.29
    assert latency.parallel({}) == {}


def test_phase_log_rows(tmp_path):
    clock = Clock(T0 + 3)
    log = latency.PhaseLog(tmp_path, challenge="mobile-day-04/mastery", kind="gamemaster", anchor=T0,
                           run="r1", clock=clock)
    with log.span("download") as ex:
        clock.t += 0.25
        ex["bytes"] = 99
    with pytest.raises(KeyError):
        with log.span("start"):
            clock.t += 1
            raise KeyError("x")
    log.mark("ready")
    (latency.phases_path(tmp_path)).open("a").write("not json\n{\"t0\": 1}\n")
    rows, bad = latency.read_phases(tmp_path)
    assert bad == 2
    d, s, r = rows
    assert (d["phase"], d["rel_s"], d["dur_s"], d["bytes"], d["ok"], d["mode"]) == \
        ("download", 3.0, 0.25, 99, True, "mobile/mastery")
    assert (s["ok"], s["error"], s["dur_s"]) == (False, "KeyError", 1.0)
    assert r["dur_s"] == 0 and r["rel_s"] == pytest.approx(4.25)
    assert latency.read_phases(tmp_path, since=T0 + 3.25)[0] == [s, r]


@pytest.mark.parametrize("kind,cid,want", [
    ("gamemaster", "mobile-day-04/mastery", "mobile/mastery"),
    ("gamemaster", "web-day-28", "web/base"),
    ("gamemaster", "web-day-28/time_trial#q1", "web/time_trial"),
    ("gamemaster", "oddname", "oddname/base"),
    ("ctfd", "12", "ctfd"),
    ("gamemaster", None, "*"),
])
def test_mode_of(kind, cid, want):
    assert latency.mode_of(kind, cid) == want


# ------------------------------------------------------------------------------------------ the start guard

def test_poll_interval():
    assert [latency.poll_interval(t) for t in (0, 9.9, 10, 29.9, 30, 500)] == [1, 1, 2, 2, 5, 5]


def test_one_post_then_status_until_ready(tmp_path):
    clock = Clock()
    plat = Platform(clock, ["starting"], lambda t: "running" if t >= T0 + 12 else "starting")
    g, err = guard(plat, clock, tmp_path)
    out = g.ensure_ready(CID)
    assert out.state == "ready" and len(plat.post_calls) == 1
    assert plat.status_calls == [T0 + x for x in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12)]
    rec = g.record(CID)
    assert rec["state"] == "ready" and rec["open_posts"] == 0 and rec["posts"] == 1
    assert not out.alerted and "ALERT" not in err.getvalue()


def test_a_second_process_never_posts_while_a_start_is_pending(tmp_path):
    clock = Clock()
    plat = Platform(clock, ["starting"], lambda t: "starting")
    g1, _ = guard(plat, clock, tmp_path)
    assert g1.start(CID).state == "preparing"
    g2, _ = guard(plat, clock, tmp_path)           # another lane, same workdir
    out = g2.start(CID)
    assert out.posted is False and out.state == "preparing" and "no POST" in out.note
    assert len(plat.post_calls) == 1 and len(plat.status_calls) == 1


def test_a_second_process_never_posts_while_a_raised_post_is_unknown(tmp_path):
    """Day 28 across processes: lane A's POST timed out (outcome unknown, status shows no attempt
    yet); lane B's start inside the grace window must not send a second POST."""
    clock = Clock()
    plat = Platform(clock, [PlatformError("start_instance: POST failed (ReadTimeout)"), "starting"],
                    lambda t: "stopped")
    g1, _ = guard(plat, clock, tmp_path)
    out1 = g1.start(CID)
    assert out1.posted is True and out1.state == "unknown"
    assert g1.record(CID)["state"] == "unknown"           # the record the second process finds
    assert len(plat.post_calls) == 1 and len(plat.status_calls) == 1
    clock.t = T0 + 5                                        # inside post_grace_s (40 s)
    g2, _ = guard(plat, clock, tmp_path)
    out2 = g2.start(CID)
    assert out2.posted is False and "no POST" in out2.note
    assert len(plat.post_calls) == 1                        # no second POST
    assert len(plat.status_calls) == 2                      # exactly one status read by g2
    assert out2.state == "unknown" and g2.record(CID)["open_posts"] == 1


def test_a_post_that_raised_is_recovered_by_status_only(tmp_path):
    """Day 28: the first POST timed out; the old client POSTed 16 more times. Here: one."""
    clock = Clock()
    plat = Platform(clock, [PlatformError("start_instance: POST failed (ReadTimeout)")],
                    lambda t: "running" if t >= T0 + 20 else "starting")
    g, err = guard(plat, clock, tmp_path)
    out = g.ensure_ready(CID)
    assert out.state == "ready" and len(plat.post_calls) == 1
    assert "outcome is unknown" in err.getvalue()


def test_absent_after_the_grace_is_the_one_case_for_a_repost(tmp_path):
    clock = Clock()
    # the POST never landed: status shows no attempt until the second POST (made at >= T0 + 40)
    plat = Platform(clock, [PlatformError("POST failed (ReadTimeout)"), "starting"],
                    lambda t: "starting" if len(plat.post_calls) == 2 and t < T0 + 50 else
                    ("running" if len(plat.post_calls) == 2 else "stopped"))
    g, _ = guard(plat, clock, tmp_path, post_grace_s=40.0)
    out = g.ensure_ready(CID)
    assert out.state == "ready" and len(plat.post_calls) == 2
    assert plat.post_calls[1] >= T0 + 40           # not before the first POST's grace ran out
    rec = g.record(CID)
    assert rec["posts"] == 2 and rec["open_posts"] == 0


def test_max_posts_refuses_loudly_and_clear_allows_another(tmp_path):
    clock = Clock()
    plat = Platform(clock, ["stopped", "stopped", "running"], lambda t: "stopped")
    g, _ = guard(plat, clock, tmp_path, max_posts=2)
    with pytest.raises(latency.StartRefused, match="max_posts 2 reached, no POST sent"):
        g.ensure_ready(CID)
    assert len(plat.post_calls) == 2
    assert latency.pending_starts(tmp_path)[CID]["open_posts"] == 2
    assert latency.clear_start(tmp_path, CID) is True
    assert latency.clear_start(tmp_path, CID) is False
    assert g.start(CID).state == "ready" and len(plat.post_calls) == 3


def test_provisioning_alert_once_at_alert_after(tmp_path):
    clock = Clock()
    plat = Platform(clock, ["starting"], lambda t: "running" if t >= T0 + 70 else "starting")
    seen = []
    log = latency.PhaseLog(tmp_path, challenge=CID, anchor=T0, clock=clock)
    g, err = guard(plat, clock, tmp_path, alert_after_s=45.0, alert=seen.append, phases=log)
    out = g.ensure_ready(CID)
    assert out.state == "ready"
    assert err.getvalue().count("PROVISIONING ALERT") == 1 and len(seen) == 1
    assert g.record(CID)["alerted"] == T0 + 45      # the status read at +45 (reads at +35, +40, +45)
    rows = [r for r in log.rows if r["phase"] == "provision_alert"]
    assert len(rows) == 1 and rows[0]["waited_s"] >= 45
    # a second process waiting on the same attempt does not alert again
    clock2 = Clock(T0 + 60)
    plat2 = Platform(clock2, [], lambda t: "starting")
    g2, err2 = guard(plat2, clock2, tmp_path, alert_after_s=45.0)
    g2.await_ready(CID, timeout_s=3)
    assert "ALERT" not in err2.getvalue()


def test_alert_is_timed_from_the_first_post_not_from_await_ready(tmp_path):
    """The POST at T0, the wait begins at T0+35 (another lane, or a caller that did other work
    first): the alert fires at the read at T0+45 (45 s after the POST), not 45 s into the wait."""
    clock = Clock()
    plat = Platform(clock, ["starting"], lambda t: "starting")
    seen = []
    g, err = guard(plat, clock, tmp_path, alert_after_s=45.0, alert=seen.append)
    assert g.start(CID).state == "preparing" and plat.post_calls == [T0]
    clock.t = T0 + 35
    out = g.await_ready(CID, timeout_s=60)
    assert out.state == "preparing" and len(plat.post_calls) == 1
    assert g.record(CID)["alerted"] == T0 + 45            # reads at +35 .. +45, one second apart
    assert len(seen) == 1 and err.getvalue().count("PROVISIONING ALERT") == 1
    assert "45 s after its first start POST" in err.getvalue()


def test_no_alert_before_alert_after(tmp_path):
    clock = Clock()
    # status reads at +0..+10 (1 s) then +12: still starting at +11, running by +12
    plat = Platform(clock, ["starting"], lambda t: "running" if t >= T0 + 11 else "starting")
    g, err = guard(plat, clock, tmp_path, alert_after_s=12.0)
    assert g.ensure_ready(CID).state == "ready"
    assert "ALERT" not in err.getvalue() and not g.record(CID).get("alerted")


def test_timeout_returns_preparing_without_a_repost(tmp_path):
    clock = Clock()
    plat = Platform(clock, ["starting"], lambda t: "starting")
    g, _ = guard(plat, clock, tmp_path)
    out = g.ensure_ready(CID, timeout_s=30)
    assert out.state == "preparing" and "no start was re-POSTed" in out.note
    assert len(plat.post_calls) == 1 and clock.t - T0 <= 31


def test_timed_id_is_refused_before_any_request(tmp_path):
    clock = Clock()
    plat = Platform(clock, ["running"], lambda t: "running")
    g, _ = guard(plat, clock, tmp_path)
    with pytest.raises(NotAllowed, match="only the opener"):
        g.start("mobile-day-04/mastery")
    assert plat.post_calls == [] and g.record("mobile-day-04/mastery") is None


def test_a_refused_start_leaves_no_pending_record(tmp_path):
    clock = Clock()
    plat = Platform(clock, [NotAllowed("no instances here")], lambda t: "running")
    g, _ = guard(plat, clock, tmp_path)
    with pytest.raises(NotAllowed):
        g.start(CID)
    assert g.record(CID) is None


def test_corrupt_start_records_fail_loudly_with_no_post(tmp_path):
    clock = Clock()
    plat = Platform(clock, ["running"], lambda t: "running")
    g, _ = guard(plat, clock, tmp_path)
    (wire.wire_dir(tmp_path)).mkdir(parents=True)
    (wire.wire_dir(tmp_path) / latency.STARTS_NAME).write_text("{torn")
    with pytest.raises(latency.LatencyError, match="do not parse"):
        g.start(CID)
    assert plat.post_calls == []


def test_guard_arguments_are_validated(tmp_path):
    with pytest.raises(ValueError):
        latency.StartGuard(object(), workdir=tmp_path, alert_after_s=0)
    with pytest.raises(ValueError):
        latency.StartGuard(object(), workdir=tmp_path, max_posts=0)


# ------------------------------------------------------------------------------------------ the live path

def test_open_release_day28_shape_one_post_and_complete_phases(gm, loopback, tmp_path):
    """The first POST hangs past the client timeout while the attempt prepares: one POST, then status
    reads, the download and a complete phase record from the first request."""
    srv = gm(prep_s=1.0, hang_first_s=1.5, list_delay_s=0.3)
    profile, wd = loopback
    gate = get_adapter(profile(srv.url))
    gate._adapter.timeout_s = 0.6
    anchor = time.time() + 0.4
    res = latency.open_release(gate, CID, anchor=anchor, lead_s=0.3, dest=tmp_path / "dl", err=io.StringIO())
    assert res.ok, res.errors
    assert len(srv.ops("start")) == 1                     # never re-POSTed
    assert res.listed is True and res.start.state == "ready"
    assert [p.read_bytes() for p in res.files] == [ART]
    names = [r["phase"] for r in res.phases]
    assert names[:2] == ["warm", "anchor"] and {"list", "start", "provision", "download"} <= set(names)
    assert names[-1] == "ready"
    lst = next(r for r in res.phases if r["phase"] == "list")
    st = next(r for r in res.phases if r["phase"] == "start")
    assert 0 <= lst["rel_s"] < 0.2 and 0 <= st["rel_s"] < 0.2        # list and start at the release
    assert abs(lst["t0"] - st["t0"]) < 0.1                         # in parallel
    assert len(srv.ops("list")) == 1
    t_list, t_start = srv.ops("list")[0][3], srv.ops("start")[0][3]
    assert abs(t_start - t_list) < 0.2              # the start did not wait for the 0.3 s list
    warm_row = res.phases[0]
    assert warm_row["t0"] >= anchor - 0.3 - 0.05 and warm_row["t0"] < anchor
    assert srv.connections <= 3                                    # the hung POST's socket is the extra
    rep = latency.run_report(*_rows(wd), challenge=CID)
    assert len(rep) == 1 and rep[0]["missing"] == [] and rep[0]["open_s"] > 0
    assert rep[0]["first_request_rel_s"] < 0.2
    jr, _ = wire.read_journal(wd)
    start_rows = [r for r in jr if r["op"] == "start"]
    assert len(start_rows) == 1 and start_rows[0]["error"] == "ReadTimeout"
    art = [r for r in jr if r["op"] == "artifact"]
    assert art and art[0]["bytes"] == len(ART)
    assert rep[0]["bytes"] >= len(ART)


def _rows(wd):
    return latency.read_phases(wd)[0], wire.read_journal(wd)[0]


def test_open_release_without_start_reads_only(gm, loopback):
    srv = gm()
    profile, wd = loopback
    gate = get_adapter(profile(srv.url))
    srv.created = time.time() - 5                # an attempt already running
    res = latency.open_release(gate, CID, start=False)
    assert res.ok and res.start is None and srv.ops("start") == []
    assert {"list", "detail"} <= {r["phase"] for r in res.phases}


def test_open_release_refuses_a_timed_id_before_any_request(gm, loopback):
    srv = gm()
    profile, wd = loopback
    gate = get_adapter(profile(srv.url))
    with pytest.raises(NotAllowed, match="only the opener"):
        latency.open_release(gate, "web-day-28/time_trial")
    assert srv.requests == [] and srv.connections == 0


def test_open_release_reports_an_unlisted_challenge(gm, loopback):
    srv = gm(listed=["other-day-01"])
    profile, _ = loopback
    gate = get_adapter(profile(srv.url))
    res = latency.open_release(gate, CID)
    assert res.listed is False and not res.ok


# ------------------------------------------------------------------------------------------ reports

def _phase(run, phase, t0, dur, mode="web/base", cid=CID, anchor=T0, ok=True, **kw):
    return {"run": run, "challenge": cid, "mode": mode, "phase": phase, "t0": t0, "t1": t0 + dur,
            "dur_s": dur, "rel_s": t0 - anchor, "ok": ok, "error": None if ok else "X", **kw}


def _j(op, ts, dur, cid=CID, status=200, held=0.0, nbytes=None):
    return {"ts": ts, "op": op, "challenge": cid, "status": status, "dur_s": dur, "held_s": held,
            "bytes": nbytes, "kind": "gamemaster"}


def test_run_report_joins_phases_and_journal():
    ph = [_phase("r1", "warm", T0 - 2, 0.01), _phase("r1", "anchor", T0, 0),
          _phase("r1", "list", T0 + 0.1, 0.2), _phase("r1", "start", T0 + 0.1, 0.4),
          _phase("r1", "download", T0 + 0.6, 0.3), _phase("r1", "ready", T0 + 0.9, 0),
          _phase("r2", "list", T0 + 100, 0.2, anchor=T0 + 99.5)]
    jr = [_j("list", T0 + 0.1, 0.2, cid=None, held=0.5), _j("start", T0 + 0.1, 0.4),
          _j("artifact", T0 + 0.6, 0.05, nbytes=1000), _j("status", T0 + 0.5, 0.01, cid="other"),
          _j("status", T0 + 50, 0.01)]
    rep = {r["run"]: r for r in latency.run_report(ph, jr)}
    r1 = rep["r1"]
    assert r1["anchor"] == T0 and r1["first_request_rel_s"] == pytest.approx(0.1)
    assert r1["open_s"] == pytest.approx(0.8) and r1["missing"] == []
    assert r1["requests"] == 3 and r1["held_s"] == pytest.approx(0.5) and r1["bytes"] == 1000
    assert r1["phases"]["start"] == {"rel_s": pytest.approx(0.1), "dur_s": 0.4, "ok": True}
    r2 = rep["r2"]
    assert r2["open_s"] is None and r2["missing"] == ["warm", "start", "download", "ready"]
    assert latency.run_report(ph, jr, challenge="nope") == []


def test_floor_table_per_mode_and_records():
    ph = [_phase("r1", "list", T0 + 0.1, 0.2), _phase("r1", "start", T0 + 0.1, 0.5),
          _phase("r1", "ready", T0 + 1.6, 0),
          _phase("r2", "list", T0 + 200.1, 0.3), _phase("r2", "ready", T0 + 200.9, 0),
          _phase("r3", "start", T0 + 400, 0.9, ok=False),
          _phase("m1", "start", T0 + 10, 0.1, mode="mobile/mastery", cid="mobile-day-04/mastery")]
    jr = [_j("submit", T0 + 2, 0.3), _j("submit", T0 + 202, 0.2), _j("submit", T0 + 300, 0.05, status=429),
          _j("status", T0 + 1, 0.1), _j("status", T0 + 3, 0.3), _j("list", T0, 0.2, cid=None),
          _j("submit", T0 + 20, 0.4, cid="mobile-day-04/mastery")]
    t = {r["mode"]: r for r in latency.floor_table(
        ph, jr, kind="gamemaster", records={"web/base": 1.0, "mobile/mastery": 2.0, "binary/base": 3.0})}
    web = t["web/base"]
    assert web["ops"]["submit"] == {"n": 2, "min": 0.2, "p50": 0.25}       # the 429 is not a round trip
    assert web["ops"]["status"] == {"n": 2, "min": 0.1, "p50": 0.2}
    assert web["phases"]["start"] == {"n": 1, "min": 0.5, "p50": 0.5}      # the failed start left out
    assert web["phases"]["list"]["min"] == 0.2
    assert web["runs"] == 2 and web["open_floor_s"] == pytest.approx(0.8)
    assert web["submit_floor_s"] == 0.2 and web["floor_s"] == pytest.approx(1.0)
    assert web["margin_s"] == pytest.approx(0.0) and web["verdict"].startswith("beatable")
    mob = t["mobile/mastery"]
    assert mob["floor_s"] is None and mob["verdict"].startswith("unmeasured")
    assert t["binary/base"]["runs"] == 0 and t["binary/base"]["verdict"].startswith("unmeasured")
    assert t["*"]["ops"]["list"]["n"] == 1
    t2 = {r["mode"]: r for r in latency.floor_table(ph, jr, kind="gamemaster", records={"web/base": 0.9})}
    assert t2["web/base"]["verdict"].startswith("below the wire floor") and t2["web/base"]["margin_s"] < 0


def test_floor_table_timed_modes():
    """open_release refuses timed starts, so a timed mode's floor needs an opener's PhaseLog rows: the
    unmeasured verdict says so; rows written by an opener (the B-252 hook) give it a floor."""
    mcid = "mobile-day-30/mastery"
    jr = [_j("submit", T0 + 2, 0.25, cid=mcid)]
    t = {r["mode"]: r for r in latency.floor_table([], jr, kind="gamemaster",
                                                   records={"mobile/mastery": 2.351, "web/base": 1.0})}
    assert t["mobile/mastery"]["floor_s"] is None
    assert "Game Master opener" in t["mobile/mastery"]["verdict"]
    assert "opener" not in t["web/base"]["verdict"]          # an untimed mode has no such excuse
    ph = [_phase("o1", "start", T0 + 0.05, 0.3, mode="mobile/mastery", cid=mcid),
          _phase("o1", "download", T0 + 0.35, 0.2, mode="mobile/mastery", cid=mcid),
          _phase("o1", "ready", T0 + 0.6, 0, mode="mobile/mastery", cid=mcid)]
    m = {r["mode"]: r for r in latency.floor_table(ph, jr, kind="gamemaster",
                                                   records={"mobile/mastery": 2.351})}["mobile/mastery"]
    assert m["open_floor_s"] == pytest.approx(0.55) and m["floor_s"] == pytest.approx(0.8)
    assert m["verdict"].startswith("beatable")


def test_floor_table_timed_mode_with_an_opening_but_no_submit():
    """A timed mode whose opener wrote PhaseLog rows has an opening floor; with no answered submit it
    is unmeasured for want of a submit, and the verdict must not claim no opening floor exists."""
    mcid = "mobile-day-30/time_trial"
    ph = [_phase("o1", "start", T0 + 0.05, 0.3, mode="mobile/time_trial", cid=mcid),
          _phase("o1", "download", T0 + 0.35, 0.2, mode="mobile/time_trial", cid=mcid),
          _phase("o1", "ready", T0 + 0.6, 0, mode="mobile/time_trial", cid=mcid)]
    jr = [_j("status", T0 + 0.1, 0.05, cid=mcid), _j("submit", T0 + 2, 0.2, cid=mcid, status=429)]
    m = {r["mode"]: r for r in latency.floor_table(ph, jr, kind="gamemaster",
                                                   records={"mobile/time_trial": 2.351})}["mobile/time_trial"]
    assert m["open_floor_s"] == pytest.approx(0.55) and m["submit_floor_s"] is None
    assert m["floor_s"] is None and m["margin_s"] is None
    assert m["verdict"].startswith("unmeasured")
    assert "Game Master opener" not in m["verdict"] and "no opening floor" not in m["verdict"]


def test_parse_records():
    assert latency.parse_records(["mobile/time_trial=2.351", "web/base=4"]) == \
        {"mobile/time_trial": 2.351, "web/base": 4.0}
    for bad in ("mobile", "mobile=x", "=3", "m=-1"):
        with pytest.raises(ValueError, match="MODE=SECONDS"):
            latency.parse_records([bad])


def test_write_floors(tmp_path):
    p = latency.write_floors(tmp_path, [{"mode": "web/base", "floor_s": 1.0}], now=T0)
    assert json.loads(p.read_text()) == {"written": T0, "modes": [{"mode": "web/base", "floor_s": 1.0}]}
    assert p.stat().st_mode & 0o777 == 0o600


# ------------------------------------------------------------------------------------------ CLI

def _write_rows(wd, phases, journal):
    d = wire.wire_dir(wd)
    d.mkdir(parents=True, exist_ok=True)
    (d / latency.PHASES_NAME).write_text("".join(json.dumps(r) + "\n" for r in phases))
    (d / wire.JOURNAL_NAME).write_text("".join(json.dumps(r) + "\n" for r in journal))


def test_cli_floors_phases_pending_lane_done(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("CTF_WORKDIR", raising=False)
    wd = tmp_path / "w"
    _write_rows(wd, [_phase("r1", "warm", T0 - 2, 0.01), _phase("r1", "list", T0 + 0.1, 0.2),
                     _phase("r1", "start", T0 + 0.1, 0.4), _phase("r1", "ready", T0 + 0.9, 0)],
                [_j("submit", T0 + 2, 0.3)])
    assert cli.main(["latency", "--event", "huntress", "floors", "--workdir", str(wd), "--json",
                     "--record", "web/base=1.5", "--write"]) == 0
    out = capsys.readouterr()
    t = {r["mode"]: r for r in json.loads(out.out)}
    assert t["web/base"]["floor_s"] == pytest.approx(1.1) and t["web/base"]["margin_s"] == pytest.approx(0.4)
    assert (wire.wire_dir(wd) / latency.FLOORS_NAME).is_file() and "floors written" in out.err
    assert cli.main(["latency", "--event", "huntress", "floors", "--workdir", str(wd),
                     "--record", "web/base=0.5"]) == 0
    assert "below the wire floor" in capsys.readouterr().out
    assert cli.main(["latency", "--event", "huntress", "floors", "--workdir", str(wd), "--record", "x"]) == 2
    assert "MODE=SECONDS" in capsys.readouterr().err
    assert cli.main(["latency", "--event", "huntress", "phases", "--workdir", str(wd)]) == 0
    out = capsys.readouterr().out
    assert "web-day-28 [web/base] run r1" in out and "not measured: download" in out
    assert cli.main(["latency", "--event", "huntress", "lane-done", "web", "--workdir", str(wd)]) == 0
    assert "web" in json.loads((wire.wire_dir(wd) / wire.STATE_NAME).read_text())["lanes_done"]
    capsys.readouterr()
    assert cli.main(["latency", "--event", "huntress", "lane-done", "web", "--undo", "--workdir", str(wd)]) == 0
    assert json.loads((wire.wire_dir(wd) / wire.STATE_NAME).read_text())["lanes_done"] == {}
    assert cli.main(["latency", "--event", "huntress", "pending", "--workdir", str(wd)]) == 0
    assert "no start records" in capsys.readouterr().out


def test_cli_start_and_open_against_the_fake(gm, loopback, capsys, tmp_path):
    srv = gm(prep_s=0.5)
    profile, wd = loopback
    profile(srv.url)
    assert cli.main(["latency", "--event", "huntress", "start", CID, "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["state"] == "ready" and out["posts"] == 1 and len(srv.ops("start")) == 1
    assert out["info"]["connection_info"] == "http://127.0.0.1:9/target"
    # the record says ready: a second start POSTs a new attempt only through the guard's count
    assert cli.main(["latency", "--event", "huntress", "pending", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)[CID]["state"] == "ready"
    before = len(srv.requests)
    assert cli.main(["latency", "--event", "huntress", "open", "web-day-28/mastery"]) == 4
    assert "refused" in capsys.readouterr().err and len(srv.requests) == before
    assert cli.main(["latency", "--event", "huntress", "open", CID, "--no-start",
                     "--dest", str(tmp_path / "dl")]) == 0
    out = capsys.readouterr().out
    assert "warm" in out and "download" in out and (tmp_path / "dl" / "site.tar").read_bytes() == ART


def test_cli_open_exits_1_when_the_opening_fails(gm, loopback, capsys):
    srv = gm(listed=["other-day-01"])
    profile, _ = loopback
    profile(srv.url)
    # the start works, but the challenge is not on the list: a failed step
    assert cli.main(["latency", "--event", "huntress", "open", CID]) == 1
    assert f"{CID} is not on the list" in capsys.readouterr().out
    assert len(srv.ops("start")) == 1


def test_cli_open_exits_1_when_the_attempt_is_not_ready(gm, loopback, capsys):
    srv = gm(prep_s=30)
    profile, _ = loopback
    profile(srv.url)
    assert cli.main(["latency", "--event", "huntress", "open", CID, "--timeout", "1.5", "--json"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is False and out["listed"] is True and out["errors"] == {}
    assert out["start"]["state"] == "preparing" and len(srv.ops("start")) == 1


def test_cli_start_reports_not_ready_with_exit_1(gm, loopback, capsys):
    srv = gm(prep_s=30)
    profile, _ = loopback
    profile(srv.url)
    assert cli.main(["latency", "--event", "huntress", "start", CID, "--timeout", "1.5"]) == 1
    out = capsys.readouterr().out
    assert "preparing" in out and "no start was re-POSTed" in out and len(srv.ops("start")) == 1


# ---------------------------------------------------------------------- B-252: poll-to-detect

def _state(wd):
    return json.loads((wire.wire_dir(wd) / "state.json").read_text())


def test_live_inflight_reaps_stale_and_malformed_slots():
    now = 1000.0
    fresh, stale = [1, "a", now - 5], [2, "b", now - 40]
    assert wire.live_inflight([fresh, stale, "junk", [3, "c"]], now) == [fresh]
    assert wire.live_inflight([stale], now, ttl=60.0) == [stale]


def test_poll_inflight_holds_a_third_list_poll_but_not_a_read(tmp_path):
    # two list polls already in flight (fresh slots): a third list poll is held, a read is not
    prof = dataclasses.replace(event.load("huntress"), wire=WirePace())
    clk = Clock(T0)
    d = wire.wire_dir(tmp_path)
    d.mkdir(parents=True, exist_ok=True)
    (d / "state.json").write_text(json.dumps({"poll_inflight": [[11, "a", T0], [12, "b", T0]]}))
    w = wire.Wire(prof, workdir=tmp_path, clock=clk, sleep=clk.sleep, lane="web")
    held = w.admission("web", POLL)
    assert next(held) == pytest.approx(wire.POLL_INFLIGHT_RECHECK_S)      # held, not admitted
    read = w.admission("web", READ)
    with pytest.raises(StopIteration) as si:                              # a read is not poll-capped
        next(read)
    assert si.value.value["held_by"] is None
    # with the cap off, the poll is admitted despite the two slots
    off = wire.Wire(prof, workdir=tmp_path, clock=clk, sleep=clk.sleep, lane="web", poll_inflight=0)
    with pytest.raises(StopIteration):
        next(off.admission("web", POLL))


def test_a_poll_held_by_the_inflight_cap_is_admitted_when_a_slot_frees_and_journaled(tmp_path):
    prof = dataclasses.replace(event.load("huntress"), wire=WirePace())
    d = wire.wire_dir(tmp_path)
    d.mkdir(parents=True, exist_ok=True)
    now = time.time()                                                    # fresh slots for the real clock
    (d / "state.json").write_text(json.dumps({"poll_inflight": [[11, "a", now], [12, "b", now]]}))

    class Resp:
        status_code, headers = 200, {}

    def free_one():
        time.sleep(0.15)                                                 # a lower bound (rule 16): a slot frees
        with wire._locked(tmp_path):
            st = wire._read_state(tmp_path, time.time(), io.StringIO())
            st["poll_inflight"] = [[11, "a", time.time()]]
            wire._write_state(tmp_path, st)

    threading.Thread(target=free_one, daemon=True).start()
    w = wire.Wire(prof, workdir=tmp_path, lane="web")
    w.send(lambda *a, **k: Resp(), "GET", "http://127.0.0.1:1/", params={"op": "list"})   # held, then admitted
    rows, _ = wire.read_journal(tmp_path)
    assert rows[-1]["op"] == "list" and rows[-1]["held_by"] == "poll_inflight"
    assert rows[-1]["held_s"] >= 0.1                                     # it was genuinely held


def test_a_poll_slot_is_freed_on_success_and_on_error(tmp_path):
    prof = dataclasses.replace(event.load("huntress"), wire=WirePace())
    w = wire.Wire(prof, workdir=tmp_path, lane="web")

    class Resp:
        status_code, headers = 200, {}

    w.send(lambda *a, **k: Resp(), "GET", "http://127.0.0.1:1/", params={"op": "list"})
    assert _state(tmp_path)["poll_inflight"] == []

    def boom(*a, **k):
        raise RuntimeError("down")

    with pytest.raises(RuntimeError):
        w.send(boom, "GET", "http://127.0.0.1:1/", params={"op": "list"})
    assert _state(tmp_path)["poll_inflight"] == []


def test_two_list_polls_in_flight_hold_a_third_until_one_returns(tmp_path):
    # a real concurrency ordering check (robust to load: waits on conditions, asserts order only)
    prof = dataclasses.replace(event.load("huntress"), wire=WirePace())
    w = wire.Wire(prof, workdir=tmp_path, lane="web")
    gates = [threading.Event() for _ in range(3)]
    begun = [threading.Event() for _ in range(3)]

    class Resp:
        status_code, headers = 200, {}

    def make(i):
        def req(method, url, **kw):
            begun[i].set()
            gates[i].wait(5)
            return Resp()
        return req

    def run(i):
        w.send(make(i), "GET", "http://127.0.0.1:1/", params={"op": "list"})

    threads = [threading.Thread(target=run, args=(i,), daemon=True) for i in range(3)]
    threads[0].start()
    threads[1].start()
    settle(lambda: begun[0].is_set() and begun[1].is_set())              # two slots taken
    assert begun[0].is_set() and begun[1].is_set()
    threads[2].start()
    settle(lambda: False, timeout=0.3)                                   # give the third time to try
    assert not begun[2].is_set()                                         # the cap holds it
    gates[0].set()                                                       # free one slot
    settle(lambda: begun[2].is_set())
    assert begun[2].is_set()                                             # now it runs
    for g in gates:
        g.set()
    for t in threads:
        t.join(5)


# ---------------------------------------------------------------------- B-252: warm timed opener

def _timed_starter(gate):
    """A stand-in for B-231's run_for_time start path: one POST that starts the clock, through the
    adapter's wired session (journaled as op=start), returning the InstanceInfo it parses."""
    ad = latency._adapter(gate)

    def start(cid):
        r = ad._send("POST", "start_timed", json={"challenge": cid})
        body = r.json()
        return ad._instance(cid, r.status_code, body if isinstance(body, dict) else {})
    return start


TT = "web-day-28/time_trial"


def test_open_timed_warms_posts_the_clock_once_and_times_the_opening(gm, loopback):
    srv = gm(listed=[TT])
    profile, wd = loopback
    gate = get_adapter(profile(srv.url))
    res = latency.open_timed(gate, TT, starter=_timed_starter(gate), dest=wd / "dl")
    assert res.ok and res.started and res.info.state == "running"
    assert res.listed is True and res.mode == "web/time_trial"
    assert len(srv.ops("start")) == 1 and len(srv.ops("submit")) == 0   # one clock start, no submit
    names = [p["phase"] for p in res.phases]
    assert names[0] == "warm" and names[1] in ("anchor", "go") and "start" in names
    assert "list" in names and names[-1] == "ready"
    assert (wd / "dl" / "site.tar").read_bytes() == ART
    # the phases log now gives the timed mode an opening floor in the wire-floor table
    rows, _ = latency.read_phases(wd)
    jrows, _ = wire.read_journal(wd)
    row = next(r for r in latency.floor_table(rows, jrows, kind="gamemaster") if r["mode"] == "web/time_trial")
    assert row["open_floor_s"] is not None


def test_open_timed_waits_out_provisioning_by_status_only(gm, loopback):
    srv = gm(prep_s=0.4, listed=[TT])
    profile, wd = loopback
    gate = get_adapter(profile(srv.url))
    res = latency.open_timed(gate, TT, starter=_timed_starter(gate))
    assert res.ok and res.info.state == "running"
    assert any(p["phase"] == "provision" for p in res.phases)
    assert len(srv.ops("start")) == 1                                   # never re-POSTed while preparing


def test_open_timed_flags_a_stop_after_the_start_as_a_clock_that_did_not_run(gm, loopback):
    # the start POST is accepted (provisioning), but the attempt is expired on the next status read:
    # a clock that never ran. open_timed must flag it, not report a running mode.
    srv = gm(listed=[TT], stop_after_start=True)
    profile, wd = loopback
    gate = get_adapter(profile(srv.url))
    res = latency.open_timed(gate, TT, starter=_timed_starter(gate), dest=wd / "dl")
    assert len(srv.ops("start")) == 1                                   # the start was POSTed once
    assert res.started and res.info is not None and res.info.state == "stopped"
    assert "start" in res.errors and "stopped after the start" in res.errors["start"]
    assert res.ok is False
    assert [p["phase"] for p in res.phases][-1] != "ready"              # never marked ready, never downloaded
    assert not (wd / "dl" / "site.tar").exists()


def test_open_timed_without_a_starter_uses_the_b231_route(gm, loopback):
    # B-231 landed: no starter means the no-model timed-start route (ctf/platform/timedstart.py),
    # which POSTs through StartGuard's start record and writes the halloffame hof.start record.
    from ctf import ledger
    srv = gm(listed=[TT])
    profile, wd = loopback
    gate = get_adapter(profile(srv.url))
    res = latency.open_timed(gate, TT, starter=None)
    assert res.ok and len(srv.ops("start")) == 1
    assert [r["challenge_id"] for r in ledger.read(wd) if r.get("event") == "hof.start"] == [TT]
    assert latency.pending_starts(wd)[TT]["state"] == "ready"


def test_open_timed_refuses_an_untimed_id(gm, loopback):
    srv = gm(listed=[CID])
    profile, _ = loopback
    gate = get_adapter(profile(srv.url))
    with pytest.raises(NotAllowed):
        latency.open_timed(gate, CID, starter=_timed_starter(gate))
    assert len(srv.ops("start")) == 0


# ---------------------------------------------------------------------- B-252: gate-green-to-ladder

def test_latest_gate_and_gate_green(tmp_path):
    from ctf import ledger
    assert latency.latest_gate(tmp_path, "web") is None and latency.gate_green(tmp_path, "web") is False
    ledger.append("adapt.gate", workdir=tmp_path, lane="web", verdict="no", lane_key="k1")
    ledger.append("adapt.gate", workdir=tmp_path, lane="binary", verdict="yes", lane_key="k2")
    ledger.append("adapt.gate", workdir=tmp_path, lane="web", verdict="yes", lane_key="k3")
    assert latency.gate_green(tmp_path, "web") is True                   # newest web record wins
    assert latency.latest_gate(tmp_path, "web")["lane_key"] == "k3"
    assert latency.gate_green(tmp_path, "binary") is True


def _plan(action, cid, reason="r"):
    from ctf.adapt import chain

    def planner(base, lane, *, workdir, root):
        return chain.ChainStep(base=base, challenge_id=cid, mode="time_trial", action=action, reason=reason)
    return planner


def test_ladder_on_green_starts_the_mode_when_the_gate_is_green_and_the_chain_says_start(gm, loopback):
    srv = gm(listed=[TT])
    profile, wd = loopback
    gate = get_adapter(profile(srv.url))
    from ctf import ledger
    ledger.append("adapt.gate", workdir=wd, lane="web", verdict="yes", lane_key="k")
    res = latency.ladder_on_green(gate, "web-day-28", "web", starter=_timed_starter(gate),
                                  workdir=wd, planner=_plan("start", TT))
    assert res.started and res.ok and res.action == "start" and len(srv.ops("start")) == 1


def test_ladder_on_green_starts_the_mode_when_the_chain_says_retry(gm, loopback):
    # a retry (a failed timed mode re-run behind the gate) opens the clock exactly like a start
    srv = gm(listed=[TT])
    profile, wd = loopback
    gate = get_adapter(profile(srv.url))
    from ctf import ledger
    ledger.append("adapt.gate", workdir=wd, lane="web", verdict="yes", lane_key="k")
    res = latency.ladder_on_green(gate, "web-day-28", "web", starter=_timed_starter(gate),
                                  workdir=wd, planner=_plan("retry", TT))
    assert res.started and res.ok and res.action == "retry" and len(srv.ops("start")) == 1


def test_ladder_on_green_holds_when_no_green_record_and_never_starts(gm, loopback):
    srv = gm(listed=[TT])
    profile, wd = loopback
    gate = get_adapter(profile(srv.url))
    from ctf import ledger
    ledger.append("adapt.gate", workdir=wd, lane="web", verdict="no", lane_key="k")

    def planner(*a, **k):
        raise AssertionError("planner must not run without a green gate")

    res = latency.ladder_on_green(gate, "web-day-28", "web", starter=_timed_starter(gate),
                                  workdir=wd, planner=planner)
    assert not res.started and res.action == "hold" and len(srv.ops("start")) == 0


def test_ladder_on_green_does_not_start_when_the_chain_says_wait(gm, loopback):
    srv = gm(listed=[TT])
    profile, wd = loopback
    gate = get_adapter(profile(srv.url))
    from ctf import ledger
    ledger.append("adapt.gate", workdir=wd, lane="web", verdict="yes", lane_key="k")
    res = latency.ladder_on_green(gate, "web-day-28", "web", starter=_timed_starter(gate),
                                  workdir=wd, planner=_plan("wait", "web-day-28", reason="base not closed"))
    assert not res.started and res.action == "wait" and "base not closed" in res.reason
    assert len(srv.ops("start")) == 0


# ---------------------------------------------------------------------- B-252: bank-submit RTT

def _jrow(op, dur, status=200, challenge=None, kind="gamemaster"):
    return {"op": op, "dur_s": dur, "status": status, "challenge": challenge, "kind": kind}


def test_submit_rtt_and_bank_submit_floor():
    rows = [_jrow("submit", 0.2, challenge="web-day-01"), _jrow("submit", 0.4, challenge="web-day-02"),
            _jrow("submit", 9.9, challenge="web-day-03", status=429),   # a 429 is not a round trip
            _jrow("submit", 0.3, challenge="mobile-day-01"), _jrow("list", 0.1)]
    web = latency.submit_rtt(rows, kind="gamemaster", lane="web")
    assert web["n"] == 2 and web["min"] == 0.2 and web["p50"] == pytest.approx(0.3)
    bank = latency.bank_submit_floor(rows, count=1300, kind="gamemaster", lane="web")
    assert bank["count"] == 1300 and bank["bank_floor_min_s"] == pytest.approx(260.0)
    assert bank["bank_floor_p50_s"] == pytest.approx(390.0)
    # a lane with no measured submit has no bank floor (no invented number)
    empty = latency.bank_submit_floor(rows, count=1300, kind="gamemaster", lane="binary")
    assert empty["bank_floor_min_s"] is None


def test_floor_table_adds_a_bank_floor_only_for_named_modes_and_keeps_floor_s():
    jrows = [_jrow("submit", 0.2, challenge="web-day-01/time_trial"),
             _jrow("submit", 0.2, challenge="web-day-02")]
    plain = latency.floor_table([], jrows, kind="gamemaster")
    banked = latency.floor_table([], jrows, kind="gamemaster", bank_counts={"web/time_trial": 1000})
    tt_plain = next(r for r in plain if r["mode"] == "web/time_trial")
    tt_bank = next(r for r in banked if r["mode"] == "web/time_trial")
    assert "bank" not in tt_plain                                        # opt-in: default adds nothing
    assert tt_bank["bank"]["bank_floor_min_s"] == pytest.approx(200.0)   # 1000 x 0.2
    assert tt_bank["floor_s"] == tt_plain["floor_s"]                     # the bank is never folded in
    assert all("bank" not in r for r in banked if r["mode"] != "web/time_trial")


def test_gmtiming_supplies_the_benchmark_bank_only_for_timed_modes():
    from ctf.platform import gmtiming
    counts = gmtiming.bank_counts("huntress", ["web/time_trial", "web/base", "mobile/mastery"])
    assert counts == {"web/time_trial": gmtiming.HUNTRESS_BANK_LOW, "mobile/mastery": gmtiming.HUNTRESS_BANK_LOW}
    assert gmtiming.bank_counts("unknown-event", ["web/time_trial"]) == {}   # no profile, no guess
