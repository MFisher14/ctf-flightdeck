#!/usr/bin/env python3
"""B-048: race / TOCTOU burst engine (solvers/web/double_spend race API + ctf.fastlane.try_race).

Every fixture is SYNTHETIC and every target is a loopback / in-process fake: the separate-connection
burst drives in-memory fake clients, the single-packet last-byte-sync path drives a 127.0.0.1 TCP
server the test starts itself, and no real CTF platform, instance or credential is ever contacted.

Design notes tied to the build rules:
  * Concurrency is proven structurally -- a fake client parks every request on a shared Barrier, so a
    non-overlapping (serialized) burst would dead-lock the barrier and fail the test -- never with a
    wall-clock bound (rule 16).
  * The two-person TOCTOU win is deterministic: the model server's "pending window" is opened by the
    engine's injected ``sleep`` callback, so the 409/retry_after_ms re-burst loop is exercised without
    depending on thread timing.
  * The single-packet discipline (every connection primed before any final byte is flushed) is
    asserted from the engine's own ``on_event`` hook, which the release barrier makes deterministic.
"""
from __future__ import annotations

import importlib
import json
import socket
import socketserver
import sys
import threading
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO), str(REPO / "solvers" / "web"), str(REPO / "solvers" / "toolkits")]

D = importlib.import_module("double_spend")

FLAG = "CSCTF{tw0_k3y_turn_r4ced}"


# ---------------------------------------------------------------------------------------------------
# in-memory two-person-rule model + fake clients (separate-connection burst)
# ---------------------------------------------------------------------------------------------------
class TwoPersonModel:
    """A deterministic TOCTOU model: ARMs only when >=2 approvals land while a window is open.

    The window starts CLOSED (the first burst loses with 409 + retry_after_ms). The engine's injected
    ``sleep`` opens the next window, so the second burst's concurrent approvals drive it to ARMED."""

    def __init__(self, *, approve="/orders/ord-7/approve", state="/orders/ord-7"):
        self.approve_route = approve
        self.state_route = state
        self.lock = threading.Lock()
        self.window_open = False
        self.window_approvals = 0
        self.state = "PENDING_AUTH"
        self.approve_calls = 0
        self.flag = FLAG

    def open_window(self):
        with self.lock:
            self.window_open = True
            self.window_approvals = 0

    def _approve(self):
        with self.lock:
            self.approve_calls += 1
            if self.state == "ARMED":
                return 200, {"ok": True, "effect": "already_armed", "state": "ARMED"}
            self.window_approvals += 1
            if self.window_open and self.window_approvals >= 2:
                self.state = "ARMED"
                return 200, {"ok": True, "effect": "armed", "state": "ARMED"}
            return 409, {"error": "two_person_rule", "state": self.state, "retry_after_ms": 250}

    def _readback(self):
        with self.lock:
            doc = {"state": self.state, "order": "ord-7"}
            if self.state == "ARMED":
                doc["arming_authorization"] = self.flag
            return 200, doc

    def handle(self, method, path):
        path = path.split("?", 1)[0]
        if method == "POST" and path == self.approve_route:
            return self._approve()
        if method == "GET" and path == self.state_route:
            return self._readback()
        return 404, {"error": "not_found"}


class FakeClient:
    """A scope-locked-looking fake that routes to a shared model; records nothing secret."""

    def __init__(self, base, model, *, arrive=None):
        self.base = base
        self.origin = base
        self._scope = ("http", "race.test", 80)
        self.timeout = 5.0
        self.model = model
        self._arrive = arrive

    def request(self, method, path, data=None, headers=None, allow_redirects=True):
        if self._arrive is not None and method.upper() == "POST":
            # Prove the burst overlaps: every POST must be in flight together or this blocks.
            self._arrive.wait(timeout=10.0)
        status, doc = self.model.handle(method.upper(), path)
        return {"status": status, "body": json.dumps(doc).encode(),
                "response_headers": {"Content-Type": "application/json"}}


def _factory(model, *, arrive=None):
    def make(url, timeout=None):
        return FakeClient(url or "http://race.test/", model, arrive=arrive)
    return make


# ---------------------------------------------------------------------------------------------------
# unit: width clamp, retry-after parsing, state labelling
# ---------------------------------------------------------------------------------------------------
def test_race_width_clamps_and_rejects():
    assert D.race_width(None) == D.RACE_DEFAULT_WIDTH
    assert D.race_width(8) == 8
    assert D.race_width(D.RACE_MAX_WIDTH) == D.RACE_MAX_WIDTH
    for bad in (0, -1, D.RACE_MAX_WIDTH + 1, "x"):
        with pytest.raises(ValueError):
            D.race_width(bad)
    assert D.race_width(2.9) == 2  # a float is truncated toward an integer width, not rejected


def test_retry_after_ms_parses_body_and_header_and_caps():
    assert D.race_retry_after_ms({"status": 409, "body": b'{"retry_after_ms": 250}'}) == 250.0
    assert D.race_retry_after_ms({"status": 409, "body": b'{"retry_after": 2}'}) == 2000.0
    assert D.race_retry_after_ms({"status": 429, "headers": {"retry-after": "1"}, "body": b""}) == 1000.0
    # Over-long hints are capped, not trusted blindly.
    assert D.race_retry_after_ms({"status": 409, "body": b'{"retry_after_ms": 999999}'}) == D.RACE_RETRY_CAP_MS
    assert D.race_retry_after_ms({"status": 200, "body": b"{}"}) is None
    assert D.race_retry_after_ms({"status": 409, "body": b"not json"}) is None


def test_race_state_prefers_state_field_then_status():
    assert D.race_state({"status": 200, "body": b'{"state": "ARMED"}'}) == "ARMED (HTTP 200)"
    assert D.race_state({"status": 403, "body": b"{}"}) == "HTTP 403"
    assert D.race_state({"status": None, "body": b"", "error": "timeout"}) == "error:timeout"


# ---------------------------------------------------------------------------------------------------
# separate-connection burst overlaps on the wire
# ---------------------------------------------------------------------------------------------------
def test_burst_separate_releases_all_connections_together():
    width = 6
    model = TwoPersonModel()
    arrive = threading.Barrier(width)  # every POST worker must be in flight at once, or this times out
    clients = [FakeClient("http://race.test/", model, arrive=arrive) for _ in range(width)]
    results = D.burst_separate(clients, "POST", model.approve_route, body="{}")
    assert len(results) == width
    assert all(r.get("status") in (200, 409) for r in results), results
    # The model saw every concurrent approval (the barrier would have broken otherwise).
    assert model.approve_calls == width
    # No barrier-broken sentinels.
    assert not any(r.get("error") == "barrier" for r in results), results


class ProbeBarrier:
    """A real, functioning release gate that records the peak number of threads blocked in it.

    It wraps a genuine ``threading.Barrier(parties)``, so it only releases once ``parties`` callers
    have arrived -- which guarantees a moment where exactly ``parties`` threads are simultaneously
    inside ``wait``. ``peak_waiting`` captures that moment. A gate built for too few parties (e.g.
    the ``Barrier(1)`` mutation, which never makes the engine wait for anyone) can never reach a peak
    of ``width + 1``, so the assertion below fails without relying on any wall-clock bound.
    """

    def __init__(self, parties):
        self.parties = parties
        self._real = threading.Barrier(parties)
        self._lock = threading.Lock()
        self._waiting = 0
        self.peak_waiting = 0

    def wait(self, timeout=None):
        with self._lock:
            self._waiting += 1
            if self._waiting > self.peak_waiting:
                self.peak_waiting = self._waiting
        try:
            return self._real.wait(timeout=timeout)
        finally:
            with self._lock:
                self._waiting -= 1


def test_burst_separate_gate_is_the_engines_own_all_together_release():
    """Kill the ``threading.Barrier(width + 1) -> Barrier(1)`` survivor.

    The fakes here carry NO internal ``arrive`` barrier, so the only synchronization in play is the
    engine's own release gate. We inject an instrumented gate and assert the engine built it for
    ``width + 1`` parties and genuinely held every worker plus the coordinator in it together. With
    the release neutered to a 1-party gate the engine never blocks anyone, peak_waiting stays 1, and
    this fails -- whereas the model still sees every call, so a liveness-only check would not notice.
    """
    width = 6
    model = TwoPersonModel()
    gates = []

    def release_factory(parties):
        gate = ProbeBarrier(parties)
        gates.append(gate)
        return gate

    clients = [FakeClient("http://race.test/", model) for _ in range(width)]
    results = D.burst_separate(clients, "POST", model.approve_route, body="{}",
                               release_factory=release_factory)
    assert len(results) == width and model.approve_calls == width
    assert not any(r.get("error") == "barrier" for r in results), results
    assert len(gates) == 1, gates
    gate = gates[0]
    # The engine sized its gate to hold every worker (width) plus the coordinating party.
    assert gate.parties == width + 1
    # ...and it actually held them all at once: a real Barrier(width + 1) cannot release until all
    # width + 1 parties are simultaneously inside wait(). Barrier(1) would peak at 1.
    assert gate.peak_waiting == width + 1


# ---------------------------------------------------------------------------------------------------
# full plan: lose-then-win with a 409 retry_after_ms re-burst, reporting state transitions
# ---------------------------------------------------------------------------------------------------
def _recording_sleep(model):
    waits = []

    def sleep(seconds):
        waits.append(seconds)
        model.open_window()  # the next pending window opens after the server-advised wait

    return sleep, waits


def test_run_race_plan_wins_on_second_burst_and_reports_transitions():
    model = TwoPersonModel()
    sleep, waits = _recording_sleep(model)
    plan = {
        "url": "http://race.test/", "route": model.approve_route,
        "readback_route": model.state_route, "success_state": "ARMED",
        "flag_field": "arming_authorization", "width": 8, "retries": 3, "mode": "separate",
        "headers": {"Authorization": "Bearer opk_vega7_SECRET"},
    }
    out = D.run_race_plan(_factory(model), plan, sleep=sleep)
    assert out["won"] is True, out
    assert out["state"] == "ARMED (HTTP 200)", out
    assert out["payoff_text"] == FLAG
    report = out["report"]
    assert report["attempts"] == 2 and report["retries_used"] == 1, report
    assert waits == [0.25], waits  # the 250 ms retry_after_ms, honoured once
    tr = report["transitions"]
    assert [t["to"] for t in tr] == ["PENDING_AUTH (HTTP 200)", "ARMED (HTTP 200)"], tr
    assert tr[1]["from"] == "PENDING_AUTH (HTTP 200)"
    # The report must never echo the bearer credential.
    assert "SECRET" not in json.dumps(report) and "Bearer" not in json.dumps(report)


def test_race_transition_ok_count_tallies_the_two_hundreds_in_each_burst():
    """Kill the ok_count survivor: ``s == 200`` -> ``s == 201``.

    Each transition row carries ``ok_count`` -- the number of HTTP 200s in that burst -- which the
    operator sees as 'ok X/width' via ctf.fastlane._race_transition_summary. A wrong tally would
    mislead the operator, so a burst with a known 200/409 mix must report the exact 200 count.
    """
    bursts = [
        # attempt 1: two 200s, two 409s (one carrying a retry hint so the loop re-bursts)
        [{"status": 200, "body": b"{}", "headers": {}},
         {"status": 409, "body": b"{}", "headers": {}},
         {"status": 200, "body": b"{}", "headers": {}},
         {"status": 409, "body": b'{"retry_after_ms": 1}', "headers": {}}],
        # attempt 2: three 200s, one 409
        [{"status": 200, "body": b"{}", "headers": {}},
         {"status": 200, "body": b"{}", "headers": {}},
         {"status": 200, "body": b"{}", "headers": {}},
         {"status": 409, "body": b"{}", "headers": {}}],
    ]

    def transport(attempt):
        return bursts[min(attempt, len(bursts) - 1)]

    # success() never fires, so both bursts run and both transition rows are recorded.
    report, winner = D.race(transport=transport, width=4, success=lambda *a: False,
                            readback=None, retries=1, sleep=lambda _s: None)
    assert winner is None
    assert [t["ok_count"] for t in report["transitions"]] == [2, 3], report["transitions"]
    # The tally counts 200s specifically, not the burst width or the 409s.
    assert [t["statuses"].count(200) for t in report["transitions"]] == [2, 3]


def test_run_race_plan_width_one_never_arms_and_stops_loudly():
    model = TwoPersonModel()
    sleep, _ = _recording_sleep(model)
    plan = {"url": "http://race.test/", "route": model.approve_route,
            "readback_route": model.state_route, "success_state": "ARMED",
            "flag_field": "arming_authorization", "width": 1, "retries": 2, "mode": "separate"}
    out = D.run_race_plan(_factory(model), plan, sleep=sleep)
    assert out["won"] is False
    assert out["report"]["stopped"], out  # a named stop reason, never silently green
    assert out["payoff_text"] == ""


def test_run_race_plan_rejects_incomplete_plan():
    out = D.run_race_plan(_factory(TwoPersonModel()), {"route": "/x"})
    assert out["won"] is False and "readback_route" in out["stopped"] and "success_state" in out["stopped"]


# ---------------------------------------------------------------------------------------------------
# race() bounds: max_requests, deadline, external stop
# ---------------------------------------------------------------------------------------------------
def test_race_respects_max_requests_bound():
    calls = {"n": 0}

    def transport(_a):
        calls["n"] += 1
        return [{"status": 409, "body": b'{"retry_after_ms": 1}', "headers": {}} for _ in range(4)]

    report, winner = race_no_win(transport, width=4, readback=None, max_requests=4,
                                 retries=9, sleep=lambda _s: None)
    assert winner is None
    assert report["stopped"] == "max_requests"
    assert calls["n"] == 1  # 4 requests used by the first burst; a second (4 more) would exceed 4


def test_race_stops_on_external_event():
    stop = threading.Event()
    stop.set()

    def transport(_a):  # pragma: no cover - must never run once stop is set
        raise AssertionError("transport ran after stop was set")

    report, winner = D.race(transport=transport, width=3,
                            success=lambda *a: False, readback=None, stop=stop)
    assert winner is None and report["stopped"] == "stopped" and report["attempts"] == 0


def race_no_win(transport, **kw):
    return D.race(transport=transport, success=lambda *a: False, **kw)


# ---------------------------------------------------------------------------------------------------
# retry ceiling: the re-burst is bounded by `retries` and the last permitted retry is honoured
# ---------------------------------------------------------------------------------------------------
def _losing_burst(_attempt):
    return [{"status": 409, "body": b'{"retry_after_ms": 5}', "headers": {}} for _ in range(3)]


def test_race_wins_on_the_last_permitted_retry_not_before():
    """Kill the ``attempt > retries -> attempt >= retries`` survivor.

    The window opens only on the ``retries``-th wait, so the win lands on the final permitted
    re-burst (attempt ``retries + 1``). ``>=`` would stop one burst early and never reach it, so the
    win -- and ``retries_used == retries`` -- fail under the mutation.
    """
    retries = 3
    waits = {"n": 0}

    def sleep(_seconds):
        waits["n"] += 1

    def readback():
        if waits["n"] >= retries:  # armed only after the server-advised window has opened `retries` times
            return {"status": 200, "body": b'{"state": "ARMED"}', "headers": {}}
        return {"status": 409, "body": b'{"state": "PENDING", "retry_after_ms": 5}', "headers": {}}

    def success(state, _burst, _auth):
        return "ARMED" in (state or "")

    report, winner = D.race(transport=_losing_burst, width=3, success=success,
                            readback=readback, retries=retries, sleep=sleep)
    assert winner is not None, report
    assert report["won"] is True
    assert report["retries_used"] == retries          # won exactly at the configured ceiling
    assert report["attempts"] == retries + 1


def test_race_retry_ceiling_is_bounded_by_retries():
    """The re-burst never exceeds ``retries`` extra attempts even when every burst loses.

    Pins the upper bound: with ``>=`` this would stop at ``retries - 1`` waits, so asserting the
    exact ``retries`` waits (and ``retries + 1`` total attempts) also kills the mutation from the
    losing side.
    """
    retries = 3
    waits = {"n": 0}

    def sleep(_seconds):
        waits["n"] += 1

    report, winner = race_no_win(_losing_burst, width=3, readback=None,
                                 retries=retries, sleep=sleep)
    assert winner is None
    assert report["retries_used"] == retries
    assert report["attempts"] == retries + 1
    assert waits["n"] == retries
    assert report["stopped"] == "no win within retries"


# ---------------------------------------------------------------------------------------------------
# single-packet / last-byte synchronization
# ---------------------------------------------------------------------------------------------------
class _ArmResponder(socketserver.StreamRequestHandler):
    def handle(self):
        data = b""
        # Read request line + headers.
        while b"\r\n\r\n" not in data:
            chunk = self.connection.recv(4096)
            if not chunk:
                return
            data += chunk
        head, _, rest = data.partition(b"\r\n\r\n")
        req_line = head.split(b"\r\n", 1)[0]
        length = 0
        for line in head.split(b"\r\n")[1:]:
            name, _, value = line.partition(b":")
            if name.strip().lower() == b"content-length":
                try:
                    length = int(value.strip())
                except ValueError:
                    length = 0
        # Signal that this connection's request is INCOMPLETE: the body is short, so the server
        # must block here until the withheld final byte(s) arrive. The single-packet transport
        # must not let that happen until every connection is primed and the barrier releases.
        if len(rest) < length:
            with self.server.events_lock:
                self.server.awaiting.append(req_line)
        while len(rest) < length:
            chunk = self.connection.recv(4096)
            if not chunk:
                break
            rest += chunk
        # A COMPLETE request (headers + full declared body) has now arrived.
        with self.server.events_lock:
            self.server.received.append(req_line)
            self.server.completed.append(req_line)
        body = json.dumps({"state": "ARMED", "arming_authorization": FLAG}).encode()
        self.connection.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr):
        super().__init__(addr, _ArmResponder)
        self.received = []
        self.events_lock = threading.Lock()
        # Connections that reached the withheld-body wait (request still incomplete) and
        # connections that delivered a COMPLETE request (headers + full body).
        self.awaiting = []
        self.completed = []


@pytest.fixture
def loopback_server():
    server = _Server(("127.0.0.1", 0))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


def _loopback_client(port):
    # A real scope-locked WebClient to the loopback server (conftest pins 127.0.0.0/8 in scope).
    return D._web.WebClient(f"http://127.0.0.1:{port}/", timeout=5.0)


def test_single_packet_primes_every_connection_before_any_final_byte(loopback_server):
    port = loopback_server.server_address[1]
    client = _loopback_client(port)
    width = 5
    events = []
    lock = threading.Lock()

    def on_event(index, name):
        with lock:
            events.append(name)

    results = D.burst_single_packet(client, "POST", "/orders/ord-7/approve", width=width,
                                    body="{}", headers={"Authorization": "Bearer opk_SECRET"},
                                    on_event=on_event)
    # Last-byte sync discipline: all connections primed before any final byte is flushed.
    assert events.count("primed") == width and events.count("final") == width
    assert events.index("final") > max(i for i, n in enumerate(events) if n == "primed")
    # Functional: every connection got a complete 200 back, and the server saw N full requests.
    assert all(r.get("status") == 200 for r in results), results
    assert len(loopback_server.received) == width
    assert all(line.startswith(b"POST /orders/ord-7/approve") for line in loopback_server.received)


def test_single_packet_withholds_the_final_byte_until_the_barrier_releases(loopback_server):
    """Kill the withhold survivor: ``head, tail = raw[:-hold], raw[-hold:]`` -> ``raw, b""``.

    The defining behaviour of the single-packet transport is that each connection sends ALL BUT the
    final byte(s) of its request at prime time and parks; the withheld tail is flushed only once
    every connection is primed (the release barrier). We verify the request is INCOMPLETE at prime
    time: while every worker is held inside its ``"primed"`` callback -- which runs BEFORE the worker
    reaches the release barrier, so the barrier can never gather its ``width + 1`` parties and no tail
    can have been flushed -- the loopback server must have completed ZERO requests. If priming
    instead sent the whole request (the mutation), the server completes every request here and the
    assertion fails.
    """
    port = loopback_server.server_address[1]
    client = _loopback_client(port)
    width = 4
    primed = threading.Event()
    let_go = threading.Event()
    seen = {"n": 0}
    lock = threading.Lock()

    def on_event(index, name):
        if name == "primed":
            with lock:
                seen["n"] += 1
                if seen["n"] == width:
                    primed.set()
            # Hold every worker in its primed callback, before it reaches the release barrier, so the
            # barrier provably cannot release and no withheld tail can be flushed yet.
            let_go.wait(timeout=60.0)

    out = {}

    def run():
        out["results"] = D.burst_single_packet(
            client, "POST", "/orders/ord-7/approve", width=width, body='{"n":1}',
            headers={"Authorization": "Bearer opk_SECRET"}, on_event=on_event,
            barrier_timeout=120.0)

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    try:
        assert primed.wait(timeout=60.0), "connections never primed"
        # Each connection is now either parked awaiting its withheld body (correct code) or -- under
        # the mutation -- has already delivered a complete request. This loop terminates under BOTH
        # code paths, so it is not a wall-clock upper bound on the behaviour under test; it only waits
        # until every connection has reached one of those two states.
        deadline = time.monotonic() + 60.0
        while time.monotonic() < deadline:
            with loopback_server.events_lock:
                settled = len(loopback_server.awaiting) + len(loopback_server.completed)
            if settled >= width:
                break
            time.sleep(0.01)
        with loopback_server.events_lock:
            completed_before_release = list(loopback_server.completed)
        # The discriminator: priming must not complete any request. The mutation (prime sends the
        # whole request, release sends nothing) completes all `width` here and fails this assertion.
        assert completed_before_release == [], (
            "a primed connection delivered a complete request before the barrier released")
    finally:
        let_go.set()
    worker.join(timeout=60.0)
    assert not worker.is_alive(), "burst did not finish after the barrier released"
    results = out["results"]
    # After release, the withheld tails flush together and every request completes with a full 200.
    assert all(r.get("status") == 200 for r in results), results
    with loopback_server.events_lock:
        assert len(loopback_server.completed) == width


def test_single_packet_wins_a_plan_over_raw_sockets(loopback_server):
    port = loopback_server.server_address[1]

    def factory(url, timeout=None):
        return _loopback_client(port)

    plan = {"url": f"http://127.0.0.1:{port}/", "route": "/orders/ord-7/approve",
            "readback_route": "/orders/ord-7", "success_state": "ARMED",
            "flag_field": "arming_authorization", "width": 4, "retries": 0, "mode": "single-packet",
            "headers": {"Authorization": "Bearer opk_SECRET"}}
    out = D.run_race_plan(factory, plan)
    assert out["won"] is True and out["payoff_text"] == FLAG, out
    assert out["report"]["mode"] == "single-packet"


class _StubClient:
    def __init__(self, scheme, base):
        self._scope = (scheme, "127.0.0.1", 443 if scheme == "https" else 80)
        self.base = base
        self.origin = base


def test_single_packet_refuses_tls_loudly():
    client = _StubClient("https", "https://127.0.0.1/")
    with pytest.raises(D.RaceUnsupported) as exc:
        D.burst_single_packet(client, "POST", "/approve", width=2)
    assert "TLS" in str(exc.value)


def test_single_packet_refuses_off_origin_route():
    client = _StubClient("http", "http://127.0.0.1/")
    with pytest.raises(D.RaceUnsupported) as exc:
        D.burst_single_packet(client, "POST", "http://evil.test/approve", width=2)
    assert "origin" in str(exc.value)
