#!/usr/bin/env python3
"""B-049: stateful WebSocket client core + client-trust recon.

Two halves, both offline except the loopback section:
  * unit tests for the sequence/nonce counter, the sequenced-message renderer, the app.js
    frame-schema miner (reusing ``api_protocols``/``js_recon``), and the client-trust recon rule;
  * an end-to-end stateful read driven through the real ``realtime_read`` -> ``WebClient
    .websocket_conversation`` chain against a synthetic loopback WebSocket server this file starts
    on 127.0.0.1 that *enforces* sequence ordering.  No live service is contacted; no challenge
    binary is executed; every fixture is built here.
"""
from __future__ import annotations

import base64
import hashlib
import json
import socket
import struct
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
WEB = REPO / "solvers" / "web"
sys.path.insert(0, str(WEB))
sys.path.insert(0, str(REPO / "tests"))

import ws_client_trust as wct  # noqa: E402
import event_pin  # noqa: E402  (tests/event_pin.py)

# The loopback section drives the real web pipeline; its answers are proof_<32 hex> (events/huntress).
# The pin must be at module scope so the autouse CTF_EVENT fixture applies to every test here.
event_pin.pin(globals(), "huntress")

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


# ==================================================================================================
#  1. The sequence / nonce counter
# ==================================================================================================
def test_sequence_counter_follows_start_and_step_and_tracks_state():
    state = wct.SequenceState(start=5, step=3)
    assert state.current_sequence is None and state.issued == 0
    assert [state.next_sequence() for _ in range(4)] == [5, 8, 11, 14]
    assert state.current_sequence == 14 and state.issued == 4
    assert state.snapshot() == {"start": 5, "step": 3, "issued": 4, "nonces": 0,
                                "current_sequence": 14}


def test_injected_nonce_factory_is_used_and_decoupled_from_the_sequence():
    issued = []
    state = wct.SequenceState(start=1, step=1, nonce_factory=lambda index: (issued.append(index) or f"n{index}"))
    state.next_sequence()
    state.next_sequence()
    # The nonce index counts nonces, not sequences: both nonces so far are the 1st and 2nd nonce.
    assert state.next_nonce() == "n1"
    assert state.next_nonce() == "n2"
    assert issued == [1, 2]
    assert state.snapshot()["nonces"] == 2


def test_default_nonce_is_fresh_and_field_safe():
    state = wct.SequenceState(start=1, step=1, nonce_bytes=8)
    nonces = {state.next_nonce() for _ in range(32)}
    assert len(nonces) == 32                       # genuinely fresh, not a repeated constant
    assert all(wct.FIELD.fullmatch(value) for value in nonces)


@pytest.mark.parametrize("kwargs", [
    {"start": True}, {"step": 0}, {"step": 1.5}, {"nonce_bytes": 0}, {"nonce_bytes": 65},
    {"nonce_factory": 7},
])
def test_sequence_state_rejects_bad_configuration(kwargs):
    with pytest.raises(wct.WSClientTrustError):
        wct.SequenceState(**{"start": 1, "step": 1, **kwargs})


def test_nonce_factory_must_return_a_field_safe_token():
    state = wct.SequenceState(start=1, step=1, nonce_factory=lambda _i: "not a token!")
    with pytest.raises(wct.WSClientTrustError):
        state.next_nonce()


# ==================================================================================================
#  2. The sequenced-message renderer
# ==================================================================================================
def test_build_sequenced_messages_fills_sequence_and_nonce_per_frame():
    state = wct.SequenceState(start=1, step=1, nonce_factory=lambda index: f"nonce{index}")
    messages = wct.build_sequenced_messages(
        {"id": 7, "op": "read", "unit": "rtu-3"}, "seq", 3, state, nonce_field="nonce")
    assert [json.loads(message) for message in messages] == [
        {"id": 7, "op": "read", "unit": "rtu-3", "seq": 1, "nonce": "nonce1"},
        {"id": 7, "op": "read", "unit": "rtu-3", "seq": 2, "nonce": "nonce2"},
        {"id": 7, "op": "read", "unit": "rtu-3", "seq": 3, "nonce": "nonce3"},
    ]
    assert state.issued == 3


def test_build_sequenced_messages_without_a_nonce_field():
    state = wct.SequenceState(start=10, step=10)
    messages = wct.build_sequenced_messages({"id": 1}, "seq", 2, state)
    assert [json.loads(m)["seq"] for m in messages] == [10, 20]
    assert all("nonce" not in json.loads(m) for m in messages)


@pytest.mark.parametrize("call", [
    lambda s: wct.build_sequenced_messages({"seq": 1}, "seq", 1, s),                 # name collision
    lambda s: wct.build_sequenced_messages({"id": 1}, "seq", 0, s),                  # count too small
    lambda s: wct.build_sequenced_messages({"id": 1}, "seq", 5, s),                  # count too large
    lambda s: wct.build_sequenced_messages({"id": [1]}, "seq", 1, s),               # non-scalar field
    lambda s: wct.build_sequenced_messages({"id": 1}, "bad field", 1, s),           # bad field name
    lambda s: wct.build_sequenced_messages({"id": 1}, "seq", 1, s, nonce_field="id"),  # nonce clashes
])
def test_build_sequenced_messages_rejects_bad_contracts(call):
    with pytest.raises(wct.WSClientTrustError):
        call(wct.SequenceState(start=1, step=1))


# ==================================================================================================
#  3. Frame-schema mining from app.js
# ==================================================================================================
APP_STATEFUL = """
const WS = 'wss://rtu.example.invalid/control';
function makeNonce() { return crypto.randomUUID(); }
let counter = 0;
function pollTelemetry() {
  ws.send(JSON.stringify({id: 1, op: 'read', unit: 'rtu-7', seq: counter++, nonce: makeNonce()}));
}
socket.send(JSON.stringify({type: 'ping'}));
"""


def test_mine_frame_schemas_labels_a_stateful_frame_and_its_endpoint():
    report = wct.mine_frame_schemas(APP_STATEFUL)
    stateful = [s for s in report["schemas"] if s["stateful"]]
    assert len(stateful) == 1
    schema = stateful[0]
    assert set(schema["fields"]) == {"id", "op", "unit", "seq", "nonce"}
    assert schema["sequence_fields"] == ["seq"] and schema["nonce_fields"] == ["nonce"]
    # A plain ping frame is mined too but carries no sequence/nonce, so it is not stateful.
    assert any(s["fields"] == ["type"] and not s["stateful"] for s in report["schemas"])
    assert report["ws_endpoints"] == ["wss://rtu.example.invalid/control"]


def test_mine_frame_schemas_is_empty_without_a_send_payload():
    assert wct.mine_frame_schemas("const x = {seq: 1};\nconsole.log(x);")["schemas"] == []


def test_mine_frame_schemas_names_a_js_recon_failure_instead_of_swallowing_it(monkeypatch):
    # Rule 6: a best-effort recon fault must not vanish.  When js_recon's endpoint scan blows up, the
    # schemas (the miner's real product) still come back, but the endpoint miss is reported by name,
    # not hidden behind a bare empty list.
    def boom(_name, _data):
        raise RuntimeError("js_recon exploded")

    monkeypatch.setattr(wct._jsr, "scan_text", boom)
    report = wct.mine_frame_schemas(APP_STATEFUL)
    # The schemas are unaffected by the js_recon fault.
    assert any(s["stateful"] for s in report["schemas"])
    assert report["ws_endpoints"] == []
    assert report["ws_scan_error"] is not None
    assert "js_recon exploded" in report["ws_scan_error"]
    assert "RuntimeError" in report["ws_scan_error"]


def test_mine_frame_schemas_reports_no_scan_error_on_a_clean_run():
    assert wct.mine_frame_schemas(APP_STATEFUL)["ws_scan_error"] is None


# ==================================================================================================
#  4. The client-trust recon rule
# ==================================================================================================
def _names(findings):
    return [f["name"] for f in findings]


def test_flags_an_in_browser_geofence_gate_on_a_privileged_action():
    app = """
    if (Intl.DateTimeFormat().resolvedOptions().timeZone === 'America/New_York') {
      fetch('/api/unlock', {method: 'POST'});
    }
    """
    findings = wct.flag_client_trust(app)
    gate = next(f for f in findings if f["name"] == "client_side_trust_gate")
    assert gate["severity"] == "high"
    assert gate["signal"] == "resolved_timezone"
    assert "fetch(" in gate["gated"]
    assert "server must" in gate["note"].lower()


def test_a_region_string_comparison_needs_a_geo_named_variable_to_flag():
    # A geofence: the compared variable is geo-named, so the browser decides access by region.
    geofenced = "if (countryCode === 'US') { fetch('/api/pay'); }"
    assert "client_side_trust_gate" in _names(wct.flag_client_trust(geofenced))
    # A normal server-derived role check compares against a string but names no geo signal: not flagged.
    role_check = "if (profile.role === 'admin') { fetch('/api/pay'); }"
    assert wct.flag_client_trust(role_check) == []


def test_flags_an_eligibility_variable_decided_in_browser():
    app = """
    let isEligible = navigator.language.startsWith('en-US');
    if (isEligible) { startSession(); } else { location.href = '/blocked'; }
    """
    findings = wct.flag_client_trust(app)
    assert "client_side_eligibility_decision" in _names(findings)
    decision = next(f for f in findings if f["name"] == "client_side_eligibility_decision")
    assert decision["signal"] == "navigator_language" and "isEligible" in decision["gated"]


def test_flags_a_client_storage_eligibility_block():
    app = """
    if (!localStorage.getItem('premium_entitlement')) {
      throw new Error('not allowed');
    }
    """
    findings = wct.flag_client_trust(app)
    assert "client_side_eligibility_block" in _names(findings)


def test_a_server_checked_flow_without_a_client_signal_is_not_flagged():
    # The decision uses a server-provided value and no browser-only signal: nothing to flag.
    app = """
    const profile = await (await fetch('/api/me')).json();
    if (profile.role === 'admin') { renderAdminPanel(); }
    const total = cart.items.reduce((a, b) => a + b.price, 0);
    """
    assert wct.flag_client_trust(app) == []


def test_findings_never_carry_a_derived_answer():
    app = "if (navigator.geolocation) { fetch('/x'); } // flag{not_an_answer}"
    findings = wct.flag_client_trust(app)
    assert findings and all("flag" not in f and "answer" not in f for f in findings)
    # The combined report derives nothing submittable at the top level either.
    report = wct.analyze_app_js(app)
    assert "flag" not in report and report["browser_started"] is False


def test_analyze_app_js_reuses_api_protocols_for_a_saved_frame_capture():
    import api_protocols as api
    capture = api.build_websocket_frame('{"role":"admin","action":"deleteUser"}', masked=False)
    report = wct.analyze_app_js("const x = 1;", saved_frames=capture)
    ids = {row["id"] for row in report["saved_frame_findings"]}
    assert "ws-client-authority-fields" in ids


# ==================================================================================================
#  5. End-to-end stateful read against a loopback WebSocket server that enforces ordering
# ==================================================================================================
def _server_frame(text):
    data = text.encode("utf-8")
    if len(data) < 126:
        return bytes((0x81, len(data))) + data
    return bytes((0x81, 126)) + struct.pack(">H", len(data)) + data


def _recv_exact(rfile, count):
    chunks = []
    while count > 0:
        piece = rfile.read(count)
        if not piece:
            raise EOFError
        chunks.append(piece)
        count -= len(piece)
    return b"".join(chunks)


def _read_client_message(rfile):
    """Read one complete (reassembled) masked client text message; None on close."""
    payload = bytearray()
    opcode = None
    while True:
        header = _recv_exact(rfile, 2)
        fin = bool(header[0] & 0x80)
        this_opcode = header[0] & 0x0F
        masked = bool(header[1] & 0x80)
        length = header[1] & 0x7F
        if length == 126:
            length = struct.unpack(">H", _recv_exact(rfile, 2))[0]
        elif length == 127:
            length = struct.unpack(">Q", _recv_exact(rfile, 8))[0]
        if not masked:
            raise AssertionError("client frame was not masked")
        mask = _recv_exact(rfile, 4)
        raw = _recv_exact(rfile, length)
        chunk = bytes(byte ^ mask[i % 4] for i, byte in enumerate(raw))
        if this_opcode == 0x8:                       # close
            return None
        if this_opcode in (0x1, 0x0):
            if this_opcode == 0x1:
                opcode = 0x1
            payload.extend(chunk)
            if fin:
                return payload.decode("utf-8")
        # ping/pong/other control frames are ignored for this synthetic server


class RtuShape:
    """A stateful RTU-style target: it serves a 426 control, upgrades, then accepts exactly the
    frames whose sequence numbers increment as expected before it discloses the telemetry proof."""

    def __init__(self, proof, *, route="/control", start=1, step=1, effect="telemetry_disclosed",
                 enforce=True):
        self.proof = proof
        self.route = route
        self.start = start
        self.step = step
        self.effect = effect
        self.enforce = enforce
        self.lock = threading.Lock()
        self.received = []            # (seq, nonce)
        self.replied = None           # "proof" | "refused"

    def clue(self, request):
        return {"framework": "Koa",
                "websocket_stateful_read": {
                    "route": self.route,
                    "request": request,
                    "response": {"id_field": "id", "effect_field": "effect", "effect": self.effect},
                    "steps": 3, "sequence_start": self.start, "sequence_step": self.step}}

    def proof_reply(self):
        """The frame a satisfied server returns: the contract id, the agreed effect, and the proof."""
        return {"id": 1, "effect": self.effect, "evidence": self.proof}


class _RtuHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_a):
        pass

    def _reply(self, status, value, headers=None):
        body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_GET(self):  # noqa: N802
        shape = self.server.shape
        parts = urllib.parse.urlsplit(self.path)
        if parts.path == "/api/clues":
            self._reply(200, self.server.clue_doc)
            return
        if parts.path != shape.route:
            self._reply(404, {"error": "not_found"})
            return
        if self.headers.get("Upgrade", "").lower() != "websocket":
            self._reply(426, {"error": "websocket_upgrade_required"}, {"Upgrade": "websocket"})
            return
        key = self.headers.get("Sec-WebSocket-Key", "")
        accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        self.connection.settimeout(5.0)
        expected = shape.start
        ok = True
        try:
            for _ in range(3):
                message = _read_client_message(self.rfile)
                if message is None:
                    break
                doc = json.loads(message)
                with shape.lock:
                    shape.received.append((doc.get("seq"), doc.get("nonce")))
                if shape.enforce and doc.get("seq") != expected:
                    ok = False
                expected += shape.step
        except (EOFError, OSError, ValueError):
            ok = False
        nonces = [n for _s, n in shape.received]
        if ok and len(set(nonces)) == len(nonces) and len(shape.received) == 3:
            reply = shape.proof_reply()
            with shape.lock:
                shape.replied = "proof"
        else:
            reply = {"id": 1, "error": "sequence_rejected"}
            with shape.lock:
                shape.replied = "refused"
        try:
            self.wfile.write(_server_frame(json.dumps(reply, separators=(",", ":"))))
            self.wfile.flush()
            self.connection.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        self.close_connection = True


def _serve_rtu(shape, request):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RtuHandler)
    server.daemon_threads = True
    server.shape = shape
    host, port = server.server_address
    url = f"http://{host}:{port}"
    server.clue_doc = shape.clue(request)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, url


@pytest.fixture
def servers():
    started = []
    yield started
    for srv in started:
        srv.shutdown()
        srv.server_close()


def _load_realtime():
    import realtime_read
    return realtime_read


REQUEST = {"id_field": "id", "id": 1, "operation_field": "op", "operation": "read",
           "reference_field": "unit", "reference": "rtu-7", "sequence_field": "seq",
           "nonce_field": "nonce"}


def _direct_stateful(shape, servers, monkeypatch, request=REQUEST, **ctx):
    monkeypatch.setenv("CTF_WEB_REALTIME", "on")
    rt = _load_realtime()
    srv, url = _serve_rtu(shape, request)
    servers.append(srv)
    control = {"status": 426, "body": b'{"error":"websocket_upgrade_required"}',
               "response_headers": {"Upgrade": "websocket"}}
    sink = {}
    proof = rt.solve(
        {"url": url, "answer_id": "proof-1"},
        dict(ctx, result_sink=sink,
             preloaded={"/api/clues": {"status": 200, "body": json.dumps(srv.clue_doc).encode()},
                        shape.route: control}))
    return proof, sink["proof-1"]


def test_stateful_read_sends_incrementing_sequence_and_banks_the_proof(servers, monkeypatch):
    import web_fakes  # tests/web_fakes.py
    proof = web_fakes.uuid_proof("b049-ok")
    shape = RtuShape(proof)
    got, summary = _direct_stateful(shape, servers, monkeypatch)
    assert got == proof, summary
    assert summary["protocol"] == "websocket-stateful" and summary["success"] is True
    # The server saw three frames whose sequence numbers incremented 1, 2, 3, each with a fresh nonce.
    assert [seq for seq, _nonce in shape.received] == [1, 2, 3]
    assert len({nonce for _seq, nonce in shape.received}) == 3
    assert shape.replied == "proof"


def test_a_custom_sequence_start_and_step_are_honored(servers, monkeypatch):
    import web_fakes
    proof = web_fakes.uuid_proof("b049-step")
    # The clue the shape serves declares start=2 step=2, so the reader must send 2, 4, 6.
    shape = RtuShape(proof, start=2, step=2)
    got, _summary = _direct_stateful(shape, servers, monkeypatch)
    assert [seq for seq, _nonce in shape.received] == [2, 4, 6]
    assert got == proof


class _Mismatch(RtuShape):
    """The clue advertises start=1 (the client sends 1, 2, 3) but the server expects 5, 6, 7."""

    def clue(self, request):
        doc = super().clue(request)
        doc["websocket_stateful_read"]["sequence_start"] = 1
        return doc


def test_wrong_ordering_is_rejected_by_a_strict_server_and_no_proof_is_banked(servers, monkeypatch):
    import web_fakes
    proof = web_fakes.uuid_proof("b049-reject")
    mism = _Mismatch(proof, start=5, step=1, enforce=True)         # server expects 5, 6, 7
    got, summary = _direct_stateful(mism, servers, monkeypatch)
    assert got is None
    assert summary["success"] is False
    assert mism.replied == "refused"
    assert [seq for seq, _nonce in mism.received] == [1, 2, 3]     # the client's monotonic frames


class _WrongEffectDecoy(RtuShape):
    """A satisfied server that echoes the contract id and a proof-shaped ``evidence`` field but names
    the WRONG ``effect``: the reader must refuse to bank it, because id correlation alone is not
    consent -- the effect the request asked for never happened."""

    def proof_reply(self):
        return {"id": 1, "effect": "some_other_effect", "evidence": self.proof}


class _AbsentEffectDecoy(RtuShape):
    """Same, but the reply omits the effect field entirely while still carrying the proof shape."""

    def proof_reply(self):
        return {"id": 1, "evidence": self.proof}


@pytest.mark.parametrize("decoy_cls", [_WrongEffectDecoy, _AbsentEffectDecoy])
def test_a_reply_with_the_right_id_but_the_wrong_effect_is_not_banked(servers, monkeypatch, decoy_cls):
    # Kills the mutation that drops the effect_field/effect term from the stateful reader's
    # correlation (realtime_read.py _client_websocket_stateful): without that term the id-only match
    # would correlate this decoy and _outcome would bank its proof-shaped evidence.  The ordering is
    # correct, so the server *does* disclose a frame -- the gate that must stop it is the effect guard.
    import web_fakes
    proof = web_fakes.uuid_proof("b049-wrongeffect")
    decoy = decoy_cls(proof)
    got, summary = _direct_stateful(decoy, servers, monkeypatch)
    assert got is None, summary
    assert summary["success"] is False
    assert decoy.replied == "proof"                       # the server was satisfied and sent its frame
    assert [seq for seq, _nonce in decoy.received] == [1, 2, 3]   # ordering was correct; effect gated it


def test_a_get_only_client_declines_the_stateful_conversation(servers, monkeypatch):
    import web_fakes
    proof = web_fakes.uuid_proof("b049-getonly")
    shape = RtuShape(proof)

    def get_only_factory(url, timeout):
        W = __import__("web")
        return W.WebClient(url, timeout=timeout, get_only=True)

    got, summary = _direct_stateful(shape, servers, monkeypatch, client_factory=get_only_factory)
    assert got is None
    ws = summary["websocket"]
    assert ws["outcome"] == "declined" and "GET-only" in ws["reason"]
    assert shape.replied is None                                   # never upgraded/sent a frame


@pytest.mark.parametrize("bad_request", [
    {"id_field": "id", "id": 1, "operation_field": "op", "operation": "delete",   # not a read op
     "reference_field": "unit", "reference": "r", "sequence_field": "seq"},
    {"id_field": "id", "id": 1, "operation_field": "op", "operation": "read",
     "reference_field": "unit", "reference": "r", "sequence_field": "id"},         # seq clashes with id
])
def test_a_malformed_stateful_contract_is_a_named_terminal_decline(servers, monkeypatch, bad_request):
    import web_fakes
    shape = RtuShape(web_fakes.uuid_proof("b049-bad"))
    got, summary = _direct_stateful(shape, servers, monkeypatch, request=bad_request)
    assert got is None
    assert summary["terminal"] is True
    assert summary["stopped"] == "invalid client stateful WebSocket read contract"
    assert shape.replied is None
