#!/usr/bin/env python3
"""B-237: the bounded WebSocket proof-reader class in the no-model web first pass.

Huntress Day 22 "Socket to Me" (coverage rows base / time_trial / mastery): the target's clue document names
an exact ``feature_route`` and a ``stream_reference``; a plain GET of the route answers ``426
websocket_upgrade_required``; an upgrade of the route with ``?stream=<reference>`` answers 101 and the proof
arrives in the first server frame.  Layer 1 had no WebSocket class that day, so all three rows went to an
agent.

These tests drive the real web first pass end to end: the B-007 lane (``ctf.web_lane.run_row``, GET-only
mode) over the B-005 Game Master adapter against a recorded fake Game Master, and the real
``proof_hunt`` -> ``realtime_read`` -> ``WebClient.websocket_receive`` chain against a synthetic loopback
WebSocket target this file starts on 127.0.0.1.  No live service is contacted.
"""
from __future__ import annotations

import base64
import hashlib
import json
import socket
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tests"))

import event_pin  # noqa: E402  (tests/event_pin.py)
event_pin.pin(globals(), "huntress")  # web answers are proof_<32 hex> (events/huntress [proof])

import web_fakes  # noqa: E402  -- loopback GET-class sites + proof_hunt loader
from platform_fixture_session import FakeSession  # noqa: E402
from ctf import event, web_lane  # noqa: E402
from ctf.platform import gamemaster  # noqa: E402
from ctf.platform.base import Challenge  # noqa: E402
from ctf.platform.policy import SubmitGate  # noqa: E402

GM = "http://127.0.0.1:8765/"
BASE_ID = "web-exploitation-day-22-socket-to-me"
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


# --------------------------------------------------------------------------------------------------
#  A synthetic Socket-to-Me target
# --------------------------------------------------------------------------------------------------
class WsShape:
    """What the target serves and what it saw.

    ``accept`` is the one query parameter name the upgrade honors (``stream`` on Day 22).  ``clues`` is the
    clue document.  After a 101 the server sends one text frame, half-closes, and counts every byte the
    client sends afterwards (a server-first read must send none)."""

    def __init__(self, proof, *, route="/dispatch-53decf", reference=13777, accept="stream", clues=None,
                 effect="unauthorized_event_stream", control_status=426, refusal_extra=None, frames=None):
        self.proof = proof
        self.frames = frames             # explicit server-first frame payloads (dicts); None = the one proof frame
        self.route = route
        self.reference = reference
        self.accept = accept
        self.effect = effect
        self.control_status = control_status
        self.refusal_extra = dict(refusal_extra or {})   # extra fields in the 403 refusal body
        self.clues = clues if clues is not None else {
            "framework": "Koa", "feature_route": route, "stream_reference": reference}
        self.lock = threading.Lock()
        self.hits = []                     # (method, raw path, lower-cased headers)
        self.client_bytes_after_upgrade = []

    def record(self, method, path, headers):
        with self.lock:
            self.hits.append((method, path, {k.lower(): v for k, v in headers.items()}))

    def after_upgrade(self, count, timeout=5.0):
        """The client byte counts of the first ``count`` upgraded connections, once their handlers finish."""
        import time
        end = time.time() + timeout
        while time.time() < end:
            with self.lock:
                if len(self.client_bytes_after_upgrade) >= count:
                    return list(self.client_bytes_after_upgrade)
            time.sleep(0.02)
        with self.lock:
            return list(self.client_bytes_after_upgrade)

    def upgrades(self):
        return [h for h in self.hits if h[2].get("upgrade", "").lower() == "websocket"]

    def bare_controls(self):
        return [h for h in self.hits
                if h[1] == self.route and h[2].get("upgrade", "").lower() != "websocket"]


def _frame(text):
    data = text.encode("utf-8")
    assert len(data) < 65536
    if len(data) < 126:
        return bytes((0x81, len(data))) + data
    return bytes((0x81, 126)) + len(data).to_bytes(2, "big") + data


class _WsHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_a):
        pass

    def _reply(self, status, value, headers=None):
        body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_POST(self):  # noqa: N802 -- the GET-only lane must never get here
        self.server.shape.record("POST", self.path, self.headers)
        self._reply(405, {"error": "method_not_allowed"})

    def do_GET(self):  # noqa: N802
        shape = self.server.shape
        shape.record("GET", self.path, self.headers)
        parts = urllib.parse.urlsplit(self.path)
        if parts.path == "/":
            self._reply(200, {"service": "socket-to-me"})
            return
        if parts.path == "/api/clues":
            self._reply(200, shape.clues)
            return
        if parts.path != shape.route:
            self._reply(404, {"error": "not_found"})
            return
        if self.headers.get("Upgrade", "").lower() != "websocket":
            if shape.control_status != 426:
                self._reply(shape.control_status, {"service": "dispatch"})
                return
            self._reply(426, {"error": "websocket_upgrade_required"}, {"Upgrade": "websocket"})
            return
        query = urllib.parse.parse_qs(parts.query)
        if query != {shape.accept: [str(shape.reference)]}:
            self._reply(403, dict({"error": "stream_reference_invalid"}, **shape.refusal_extra))
            return
        key = self.headers.get("Sec-WebSocket-Key", "")
        accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode("ascii")).digest()).decode("ascii")
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        payloads = shape.frames if shape.frames is not None else [
            {"ok": True, "effect": shape.effect, "evidence": shape.proof}]
        self.wfile.write(b"".join(_frame(json.dumps(p, separators=(",", ":"))) for p in payloads))
        self.wfile.flush()
        # Half-close so the reader sees the end of the stream, then count anything the client sends.
        got = 0
        try:
            self.connection.shutdown(socket.SHUT_WR)
            self.connection.settimeout(2.0)
            while True:
                chunk = self.connection.recv(4096)
                if not chunk:
                    break
                got += len(chunk)
        except OSError:
            pass
        with shape.lock:
            shape.client_bytes_after_upgrade.append(got)
        self.close_connection = True


def serve_ws(shape):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _WsHandler)
    server.daemon_threads = True
    server.shape = shape
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address
    return server, f"http://{host}:{port}"


@pytest.fixture
def servers():
    started = []
    yield started
    for srv in started:
        srv.shutdown()
        srv.server_close()


# --------------------------------------------------------------------------------------------------
#  The fake Game Master
# --------------------------------------------------------------------------------------------------
def attempt_body(urls, answer_ids):
    return {"attempt_id": "a1", "name": "Socket to Me", "prompt": "Recover the proof from the event stream.",
            "questions": [{"id": a, "question": "Recover the proof."} for a in answer_ids],
            "answer_ids": list(answer_ids), "targets": [{"url": u} for u in urls],
            "deadline": "2099-01-01T00:00:00Z"}


def make_gate(cid, att, *, start=True):
    mode = cid.rsplit("/", 1)[1] if "/" in cid else "base"
    listing = {"challenges": [{"id": cid, "name": cid, "lane": "web", "mode": mode, "day": 22,
                               "solved": False}]}
    routes = [{"method": "GET", "url": GM, "params": {"op": "list", "all": "true"}, "body": listing},
              {"method": "GET", "url": GM, "params": {"op": "status", "challenge": cid}, "body": att}]
    if start:
        routes.append({"method": "POST", "url": GM, "json": {"challenge": cid}, "body": att})
    routes.append({"method": "POST", "url": GM, "body": {"result": "CORRECT"}})
    s = FakeSession(routes)
    return SubmitGate(gamemaster.GameMasterAdapter(GM, session=s), event.load("huntress")), s


def submit_posts(s):
    return [c for c in s.sent("POST") if isinstance(c.get("json"), dict) and "answers" in c["json"]]


def start_posts(s):
    return [c for c in s.sent("POST") if isinstance(c.get("json"), dict) and "answers" not in c["json"]]


def run(gate, cid, **kw):
    kw.setdefault("sleep", lambda _s: None)
    kw.setdefault("deadline_s", 20.0)
    return web_lane.run_row(gate, Challenge(id=cid, name="Socket to Me", category="web"), **kw)


# --------------------------------------------------------------------------------------------------
#  Day 22 rows
# --------------------------------------------------------------------------------------------------
def test_base_row_reads_the_server_first_frame_and_banks_it(servers):
    proof = web_fakes.uuid_proof("b237-base")
    shape = WsShape(proof)
    srv, url = serve_ws(shape)
    servers.append(srv)
    gate, s = make_gate(BASE_ID, attempt_body([url], ["proof-1"]))
    res = run(gate, BASE_ID)
    assert res.state == web_lane.BANKED, res
    assert res.proofs == {"proof-1": proof}
    sent = submit_posts(s)
    assert len(sent) == 1 and sent[0]["json"]["answers"] == {"proof-1": proof}
    # The class: a bare 426 control, then one upgrade with ?stream=<reference>, and no client frame.
    assert shape.upgrades() and shape.upgrades()[0][1] == "/dispatch-53decf?stream=13777"
    assert len(shape.upgrades()) == 1
    assert shape.after_upgrade(1) == [0]
    assert not [h for h in shape.hits if h[0] != "GET"]


def test_reference_is_tried_as_stream_then_as_the_full_key(servers):
    """A target that honors only the full clue key: the class tries ``?stream=`` first, then
    ``?stream_reference=``, and banks the second."""
    proof = web_fakes.uuid_proof("b237-fullkey")
    shape = WsShape(proof, accept="stream_reference")
    srv, url = serve_ws(shape)
    servers.append(srv)
    gate, s = make_gate(BASE_ID, attempt_body([url], ["proof-1"]))
    res = run(gate, BASE_ID)
    assert res.state == web_lane.BANKED, res
    assert res.proofs == {"proof-1": proof}
    assert [h[1] for h in shape.upgrades()] == ["/dispatch-53decf?stream=13777",
                                                "/dispatch-53decf?stream_reference=13777"]
    assert shape.after_upgrade(1) == [0]


def test_time_trial_reads_a_running_attempt_on_its_new_route_without_a_start(servers):
    """Time Trial: same class, new route and reference; the opener owns the clock so the lane only reads."""
    tid = BASE_ID + "/time_trial"
    proof = web_fakes.uuid_proof("b237-tt")
    shape = WsShape(proof, route="/process-1dc541", reference=14733)
    srv, url = serve_ws(shape)
    servers.append(srv)
    gate, s = make_gate(tid, attempt_body([url], ["proof-1"]), start=False)
    res = run(gate, tid)
    assert res.state == web_lane.BANKED, res
    assert res.proofs == {"proof-1": proof}
    assert start_posts(s) == []
    assert [h[1] for h in shape.upgrades()] == ["/process-1dc541?stream=14733"]


def test_mastery_bundle_closes_with_the_websocket_target_last(servers):
    """Mastery recycles the day's classes: backup, idor, sqli, lfi, then the WebSocket target as proof-5.
    One submit carries all five."""
    tid = BASE_ID + "/mastery"
    proofs = {f"proof-{i}": web_fakes.uuid_proof(f"b237-m{i}") for i in range(1, 6)}
    urls = []
    for i, kind in enumerate(("backup", "idor", "sqli", "lfi"), 1):
        srv, url = web_fakes.serve(web_fakes.Site(web_fakes.SHAPES[kind](proofs[f"proof-{i}"])))
        servers.append(srv)
        urls.append(url)
    shape = WsShape(proofs["proof-5"], route="/inspect-f8a2c6", reference=14862)
    srv, url = serve_ws(shape)
    servers.append(srv)
    urls.append(url)
    gate, s = make_gate(tid, attempt_body(urls, list(proofs)), start=False)
    res = run(gate, tid, deadline_s=40.0)
    assert res.state == web_lane.BANKED, res
    assert dict(res.proofs) == proofs
    sent = submit_posts(s)
    assert len(sent) == 1 and sent[0]["json"]["answers"] == proofs
    assert [h[1] for h in shape.upgrades()] == ["/inspect-f8a2c6?stream=14862"]
    assert shape.after_upgrade(1) == [0]


# --------------------------------------------------------------------------------------------------
#  A refused upgrade is a complete control (the stream-then-full-key fix), never a source of a proof
# --------------------------------------------------------------------------------------------------
def test_a_decoy_proof_in_the_refusal_body_is_never_banked(servers):
    """The ``?stream=`` refusal echoes the very proof the later 101 frame carries: that value is a control,
    not an effect, so nothing is banked."""
    proof = web_fakes.uuid_proof("b237-decoy")
    shape = WsShape(proof, accept="stream_reference", refusal_extra={"last_event": proof})
    srv, url = serve_ws(shape)
    servers.append(srv)
    gate, s = make_gate(BASE_ID, attempt_body([url], ["proof-1"]))
    res = run(gate, BASE_ID)
    assert res.state == web_lane.NO_PROOF, res
    assert submit_posts(s) == []
    assert len(shape.upgrades()) == 2          # both query forms were tried; the second answered 101


class _FakeSock:
    def __init__(self, data):
        self.data = bytearray(data)

    def settimeout(self, _t):
        pass

    def recv(self, n):
        out = bytes(self.data[:n])
        del self.data[:n]
        return out

    def sendall(self, _b):
        pass

    def close(self):
        pass


def _refusal(pairs, rest, more, *, max_bytes=4096, status=403):
    """Drive ``WebClient.websocket_receive`` over a scripted refusal (no socket is opened)."""
    W = web_lane.load_proof_hunt()._web
    client = W.WebClient("http://127.0.0.1:9/")
    client._stream_socket = lambda *_a: _FakeSock(more)
    head = (status, "Forbidden", dict(pairs), list(pairs), rest)
    client._stream_send_and_head = lambda *_a: head
    return client.websocket_receive("/ws?stream=1", max_bytes=max_bytes, deadline=__import__("time").time() + 2)


def test_a_complete_content_length_refusal_keeps_its_body_and_no_protocol_error():
    body = b'{"error":"stream_reference_invalid"}'
    got = _refusal([("Content-Type", "application/json"), ("Content-Length", str(len(body)))],
                   body[:7], body[7:])
    assert got["status"] == 403 and got["upgraded"] is False
    assert got["body"] == body
    assert got["upgrade_refused"] == "status_403_not_101"
    assert not got.get("protocol_error") and got["truncated"] is False
    assert got["websocket_messages"] == []


@pytest.mark.parametrize("label,pairs,rest,more,max_bytes", [
    ("chunked", [("Transfer-Encoding", "chunked")], b"5\r\nhello\r\n0\r\n\r\n", b"", 4096),
    ("no-length", [("Content-Type", "application/json")], b"{}", b"", 4096),
    ("over-limit", [("Content-Length", "100")], b"x" * 10, b"x" * 90, 64),
    ("short", [("Content-Length", "50")], b"x" * 10, b"", 4096),
    ("trailing-bytes", [("Content-Length", "2")], b"{}HTTP/1.1 200 OK\r\n", b"", 4096),
    ("conflicting-length", [("Content-Length", "2"), ("Content-Length", "3")], b"{}", b"", 4096),
])
def test_a_refusal_that_is_not_provably_complete_stays_fail_closed(label, pairs, rest, more, max_bytes):
    got = _refusal(pairs, rest, more, max_bytes=max_bytes)
    assert got["upgraded"] is False, label
    assert got["body"] == b"", label
    assert "status_403_not_101" in got["protocol_error"], label
    assert "upgrade_refused" not in got, label


@pytest.mark.parametrize("size,kept", [(63, True), (64, True), (65, False)])
def test_the_refusal_body_bound_is_max_bytes_inclusive(size, kept):
    """A refusal body of exactly ``max_bytes`` is a complete control; one byte more stays fail-closed."""
    body = b"y" * size
    got = _refusal([("Content-Length", str(size))], body[:5], body[5:], max_bytes=64)
    assert got["upgraded"] is False
    if kept:
        assert got["body"] == body and not got.get("protocol_error")
        assert got["upgrade_refused"] == "status_403_not_101"
    else:
        assert got["body"] == b"" and "status_403_not_101" in got["protocol_error"]
        assert "upgrade_refused" not in got


def test_an_informational_non_101_answer_stays_fail_closed():
    got = _refusal([("Content-Length", "0")], b"", b"", status=100)
    assert got["body"] == b"" and got.get("protocol_error")
    assert "upgrade_refused" not in got


# --------------------------------------------------------------------------------------------------
#  Named reasons: the first pass says why the WebSocket class did not read (Day 22 lost ~40 s to that)
# --------------------------------------------------------------------------------------------------
def _no_proof(servers, shape):
    srv, url = serve_ws(shape)
    servers.append(srv)
    gate, s = make_gate(BASE_ID, attempt_body([url], ["proof-1"]))
    res = run(gate, BASE_ID)
    assert res.state == web_lane.NO_PROOF, res
    assert submit_posts(s) == []
    return res


def test_every_refused_upgrade_is_named_with_each_query_form(servers):
    shape = WsShape(web_fakes.uuid_proof("b237-refused"), accept="token")
    res = _no_proof(servers, shape)
    ws = [n for n in res.notes if "WebSocket class" in n]
    assert ws == ["proof-1: WebSocket class declined on /dispatch-53decf: no upgrade yielded an "
                  "effect-bearing proof (?stream -> 403, ?stream_reference -> 403)"], res.notes
    assert ws[0] in res.reason                       # the row's reason leads with the named cause
    assert any(n.startswith("proof-1: class hint: ") and "426 websocket_upgrade_required" in n
               for n in res.notes), res.notes


def test_ambiguous_references_are_named_and_never_upgraded(servers):
    clues = {"feature_route": "/dispatch-53decf", "stream_reference": 13777, "event_reference": 9}
    shape = WsShape(web_fakes.uuid_proof("b237-ambig"), clues=clues)
    res = _no_proof(servers, shape)
    assert ("proof-1: WebSocket class declined on /dispatch-53decf: ambiguous: 2 stream/event/channel "
            "references; the class reads only one exact reference") in res.notes, res.notes
    assert shape.upgrades() == []


def test_a_route_that_is_not_a_426_control_is_named(servers):
    shape = WsShape(web_fakes.uuid_proof("b237-200"), control_status=200)
    res = _no_proof(servers, shape)
    assert ("proof-1: WebSocket class declined on /dispatch-53decf: the feature route answered 200, "
            "not a 426 WebSocket upgrade control") in res.notes, res.notes
    assert shape.upgrades() == []


def test_a_client_message_contract_is_refused_by_get_only_and_named(servers):
    """A ``websocket_read`` contract needs a client application frame: the GET-only lane refuses it before
    any connection (Open O-2) and says so."""
    contract = {"route": "/dispatch-53decf",
                "request": {"id_field": "id", "id": 1, "operation_field": "op", "operation": "read",
                            "reference_field": "stream", "reference": 13777},
                "response": {"id_field": "id", "effect_field": "effect",
                             "effect": "unauthorized_event_stream"}}
    shape = WsShape(web_fakes.uuid_proof("b237-conv"), clues={"websocket_read": contract})
    res = _no_proof(servers, shape)
    assert ("proof-1: WebSocket class declined on /dispatch-53decf: the clue's websocket_read contract "
            "needs client application frames, which this GET-only client refuses (Open O-2)") in res.notes, \
        res.notes
    assert shape.upgrades() == []
    assert not [h for h in shape.hits if h[0] != "GET"]


@pytest.mark.parametrize("label,frames", [
    ("two effect-bearing proofs", [
        {"ok": True, "effect": "unauthorized_event_stream", "evidence": web_fakes.uuid_proof("b237-two-a")},
        {"ok": True, "effect": "unauthorized_event_stream", "evidence": web_fakes.uuid_proof("b237-two-b")}]),
    ("a proof with no effect field", [{"ok": True, "evidence": web_fakes.uuid_proof("b237-no-effect")}]),
])
def test_a_101_without_one_effect_bearing_proof_is_named_ambiguous_and_not_banked(servers, label, frames):
    """The upgrade succeeds, but its frames do not hold exactly one effect-bearing proof: nothing is banked
    and the row names the ambiguous outcome (not a decline) on the route."""
    shape = WsShape(web_fakes.uuid_proof("b237-ambig-101"), frames=frames)
    res = _no_proof(servers, shape)
    ws = [n for n in res.notes if "WebSocket class" in n]
    assert ws == ["proof-1: WebSocket class ambiguous on /dispatch-53decf: ?stream answered 101 but its "
                  "frames held no single effect-bearing proof (candidate surfaced, not banked)"], (label, res.notes)
    assert [h[1] for h in shape.upgrades()] == ["/dispatch-53decf?stream=13777"], label
    assert shape.after_upgrade(1) == [0], label


def _direct_read(shape, servers, **ctx):
    """Run ``realtime_read.solve`` directly on the synthetic target with its clue and control preloaded, so
    every request the reader sends is a WebSocket upgrade."""
    rt = web_lane.load_proof_hunt()._realtime_read
    srv, url = serve_ws(shape)
    servers.append(srv)
    control = {"status": 426, "body": b'{"error":"websocket_upgrade_required"}',
               "response_headers": {"Upgrade": "websocket"}}
    sink = {}
    proof = rt.solve({"url": url, "answer_id": "proof-1"},
                     dict(ctx, result_sink=sink,
                          preloaded={"/api/clues": {"status": 200, "body": json.dumps(shape.clues).encode()},
                                     shape.route: control}))
    return proof, sink["proof-1"]


def test_a_budget_stop_between_query_forms_is_named(servers, monkeypatch):
    monkeypatch.setenv("CTF_WEB_REALTIME", "on")
    shape = WsShape(web_fakes.uuid_proof("b237-budget"), accept="stream_reference")
    proof, summary = _direct_read(shape, servers, max_requests=1)
    assert proof is None
    assert [h[1] for h in shape.upgrades()] == ["/dispatch-53decf?stream=13777"]   # the 2nd form never sent
    ws = summary["websocket"]
    assert ws["outcome"] == "declined"
    assert ws["reason"] == "stopped before every query form was tried (max_requests)"
    assert ws["tries"] == [{"query": "stream", "status": 403}]
    # with budget for both forms the same target reads (the stop above is the budget, nothing else)
    proof2, summary2 = _direct_read(WsShape(shape.proof, accept="stream_reference"), servers, max_requests=2)
    assert proof2 == shape.proof and summary2["websocket"]["outcome"] == "read"


def test_an_unreadable_off_switch_is_off_with_a_named_reason(monkeypatch, tmp_path):
    rt = web_lane.load_proof_hunt()._realtime_read
    monkeypatch.delenv("CTF_WEB_REALTIME", raising=False)
    monkeypatch.setattr(rt.ctf_paths, "workdir", lambda *_a, **_k: tmp_path)
    assert rt.disabled_reason() is None                 # the workdir resolves and holds no switch
    real_exists = Path.exists

    def exists(self, *a, **k):
        if self.name == rt.OFF_FILE:
            raise PermissionError("denied")
        return real_exists(self, *a, **k)
    monkeypatch.setattr(Path, "exists", exists)
    assert rt.disabled_reason() == f"the {rt.OFF_FILE} switch could not be checked (PermissionError)"
    assert rt.enabled() is False


def test_env_switch_turns_the_class_off_by_name(servers, monkeypatch):
    monkeypatch.setenv("CTF_WEB_REALTIME", "off")
    shape = WsShape(web_fakes.uuid_proof("b237-env-off"))
    res = _no_proof(servers, shape)
    assert res.notes[0] == "WebSocket class off: CTF_WEB_REALTIME=off turns the real-time class off"
    assert res.notes[0] in res.reason
    assert shape.upgrades() == []


def test_off_file_in_the_workdir_turns_the_class_off_by_name(servers, monkeypatch, tmp_path):
    monkeypatch.delenv("CTF_WEB_REALTIME", raising=False)
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    (tmp_path / "_web_realtime.off").write_text("")
    shape = WsShape(web_fakes.uuid_proof("b237-file-off"))
    res = _no_proof(servers, shape)
    assert res.notes[0] == "WebSocket class off: _web_realtime.off in the event workdir turns the real-time class off"
    assert shape.upgrades() == []


def test_an_unresolvable_workdir_is_off_with_a_named_reason(monkeypatch):
    rt = web_lane.load_proof_hunt()._realtime_read
    monkeypatch.delenv("CTF_WEB_REALTIME", raising=False)

    def boom(*_a, **_k):
        raise LookupError("no current event")
    monkeypatch.setattr(rt.ctf_paths, "workdir", boom)
    reason = rt.disabled_reason()
    assert reason.startswith("the event workdir could not be resolved (LookupError)")
    assert rt.enabled() is False
    monkeypatch.setenv("CTF_WEB_REALTIME", "on")     # the explicit switch overrides the unresolved workdir
    assert rt.disabled_reason() is None and rt.enabled() is True


def test_partial_mastery_banks_what_it_read_and_names_the_websocket_target(servers):
    tid = BASE_ID + "/mastery"
    proofs = {f"proof-{i}": web_fakes.uuid_proof(f"b237-p{i}") for i in range(1, 3)}
    srv, url1 = web_fakes.serve(web_fakes.Site(web_fakes.site_backup(proofs["proof-1"])))
    servers.append(srv)
    shape = WsShape(proofs["proof-2"], route="/inspect-f8a2c6", reference=14862, accept="token")
    srv, url2 = serve_ws(shape)
    servers.append(srv)
    gate, s = make_gate(tid, attempt_body([url1, url2], list(proofs)), start=False)
    res = run(gate, tid)
    assert res.state == web_lane.BANKED and dict(res.proofs) == {"proof-1": proofs["proof-1"]}, res
    assert any(n.startswith("proof-2: WebSocket class declined on /inspect-f8a2c6: no upgrade yielded")
               for n in res.notes), res.notes
    assert not any(n.startswith("proof-1:") for n in res.notes), res.notes


# --------------------------------------------------------------------------------------------------
#  ctf.web_ws and the CLI output
# --------------------------------------------------------------------------------------------------
def _entry(stopped=None, websocket=None, hint=None):
    return {"classes": {"realtime-read": {"stopped": stopped, "websocket": websocket}},
            "class_hint": {"line": hint} if hint else None, "stopped": None, "where": None}


def test_class_notes_skip_read_targets_sort_and_name_off_once():
    from ctf import web_ws
    declined = {"route": "/r", "outcome": "declined", "reason": "why"}
    sink = {"proof-2": _entry("off: switch", declined, "h2"),
            "proof-1": _entry("off: switch", declined, "h1"),
            "proof-3": _entry(None, {"route": "/r", "outcome": "read", "reason": "ok"}, None)}
    notes = web_ws.class_notes(sink, {"proof-3": "proof_" + "a" * 32})
    assert notes == ["WebSocket class off: switch",
                     "proof-1: WebSocket class declined on /r: why", "proof-1: class hint: h1",
                     "proof-2: WebSocket class declined on /r: why", "proof-2: class hint: h2"]
    # a read target contributes nothing, even with a hint
    assert web_ws.class_notes({"proof-1": _entry(None, declined, "h")}, {"proof-1": "x"}) == []
    # bounded
    many = {f"p{i:02d}": _entry(None, declined, "h") for i in range(20)}
    assert len(web_ws.class_notes(many, {})) == web_ws.MAX_NOTES
    assert len(web_ws.class_notes({"p": _entry(None, dict(declined, reason="x" * 2000))}, {})[0]) \
        == web_ws.MAX_NOTE_CHARS


def test_cli_row_line_prints_each_note_indented():
    from ctf.cli import web_lane as cli
    r = web_lane.RowResult("c1", web_lane.NO_PROOF, "no proof", notes=("a: one", "b: two"))
    assert cli._row_line(r).splitlines() == [f"{web_lane.NO_PROOF:<14} c1  (no proof)",
                                             "    - a: one", "    - b: two"]
