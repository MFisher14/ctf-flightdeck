#!/usr/bin/env python3
"""B-123: the descriptor-driven API invocation engine (AsyncAPI / OpenRPC / SOAP / gRPC-web).

The descriptor recon engines (``descriptor_inventory`` for AsyncAPI/OpenRPC, ``service_descriptors``
for WSDL/protobuf/gRPC-web) parse descriptors recon-only; every operation is ``requestable=False``.
``solvers/web/api_invoke.py`` is the gated reader that takes one already-inventoried, exact-linked
descriptor record and drives exactly one bounded read-only operation against the descriptor's own
same-origin server, surfacing the proof.

These tests drive the real engine -> real ``WebClient`` chain against a synthetic loopback service
this file starts on 127.0.0.1 (no live service), plus unit coverage of the gate, the read-only
classifier (the safety heart), operation selection, same-origin endpoint resolution, and the
one-bounded-request builder.  Every test produces the descriptor record by running the real recon
parsers, so the recon->invoke seam is exercised, not mocked.
"""
from __future__ import annotations

import base64
import hashlib
import json
import socket
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tests"))

import event_pin  # noqa: E402  (tests/event_pin.py)
event_pin.pin(globals(), "huntress")  # web answers are proof_<32 hex> (events/huntress [proof])

import web_fakes  # noqa: E402  -- uuid_proof

for _p in (REPO / "solvers" / "web", REPO / "solvers" / "toolkits", REPO):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import api_invoke as ai  # noqa: E402
import descriptor_inventory as di  # noqa: E402
import service_descriptors as sd  # noqa: E402
import web as W  # noqa: E402


RPCPROOF = web_fakes.uuid_proof("B123-rpc")
SOAPPROOF = web_fakes.uuid_proof("B123-soap")
GRPCPROOF = web_fakes.uuid_proof("B123-grpc")
CHANPROOF = web_fakes.uuid_proof("B123-channel")   # the selected AsyncAPI channel's payoff
DECOYPROOF = web_fakes.uuid_proof("B123-decoy")    # a different channel's payoff: must never be read
WSPROOF = web_fakes.uuid_proof("B123-ws")
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _pb_string(field, text):
    data = text.encode()
    return bytes(((field << 3) | 2, len(data))) + data


def _grpc_frame(flags, payload):
    return bytes((flags,)) + len(payload).to_bytes(4, "big") + payload


def _ws_text(text):
    data = text.encode()
    return bytes((0x81, len(data))) + data


# ==================================================================================================
#  A synthetic loopback service: a JSON-RPC endpoint, a SOAP endpoint, and a gRPC-web method path.
# ==================================================================================================
class Shape:
    def __init__(self):
        self.lock = threading.Lock()
        self.rpc_calls = []     # (method, params) seen on /rpc
        self.soap_calls = []    # (soapaction, body) seen on /soap
        self.grpc_calls = []    # (path, content_type, body_b64) seen on a method path
        self.writes = []        # any request to a write-only endpoint (must stay empty)
        self.realtime = []      # (path, "websocket"|"sse") seen on a channel GET
        self.ws_client_bytes = []  # bytes a WebSocket client sent after the upgrade (must be 0)


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_a):
        pass

    def _reply(self, status, obj, *, content_type="application/json", raw=None, headers=()):
        body = raw if raw is not None else json.dumps(obj, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _read_body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except (TypeError, ValueError):
            length = 0
        return self.rfile.read(length) if length > 0 else b""

    def do_POST(self):  # noqa: N802
        shape = self.server.shape
        parts = urllib.parse.urlsplit(self.path)
        body = self._read_body()
        if parts.path == "/app/rpc":
            try:
                doc = json.loads(body.decode("utf-8"))
            except ValueError:
                self._reply(400, {"error": "bad_json"})
                return
            with shape.lock:
                shape.rpc_calls.append((doc.get("method"), doc.get("params")))
            # A read method returns the proof; the JSON-RPC envelope carries it in result.
            self._reply(200, {"jsonrpc": "2.0", "id": doc.get("id"),
                              "result": {"ok": True, "flag": RPCPROOF}})
            return
        if parts.path == "/app/soap":
            with shape.lock:
                shape.soap_calls.append((self.headers.get("SOAPAction"), body.decode("utf-8", "replace")))
            env = ('<?xml version="1.0"?><soap:Envelope '
                   'xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>'
                   f'<GetInfoResponse><flag>{SOAPPROOF}</flag></GetInfoResponse>'
                   '</soap:Body></soap:Envelope>')
            self._reply(200, None, content_type="text/xml; charset=utf-8", raw=env.encode())
            return
        if parts.path == "/pkg.Svc/GetItem":
            with shape.lock:
                shape.grpc_calls.append((parts.path, self.headers.get("Content-Type"),
                                         base64.b64encode(body).decode("ascii")))
            frame = base64.b64encode(b"\x00\x00\x00\x00\x00")  # one empty inert data frame
            self._reply(200, None, content_type="application/grpc-web-text", raw=frame)
            return
        if parts.path in ("/pkg.Svc/GetSecret", "/pkg.Svc/GetDenied", "/pkg.Svc/GetTwo"):
            with shape.lock:
                shape.grpc_calls.append((parts.path, self.headers.get("Content-Type"),
                                         base64.b64encode(body).decode("ascii")))
            status = b"7" if parts.path.endswith("GetDenied") else b"0"
            first = DECOYPROOF if parts.path.endswith("GetTwo") else "ok"
            message = _pb_string(1, first) + _pb_string(2, GRPCPROOF)
            raw = (_grpc_frame(0, message)
                   + _grpc_frame(0x80, b"grpc-status: " + status + b"\r\n"))
            self._reply(200, None, content_type="application/grpc-web-text",
                        raw=base64.b64encode(raw))
            return
        if parts.path == "/pkg.Svc/GetTrailersOnly":
            # A trailers-only error reply: the status rides as an HTTP response header and no
            # trailer frame follows the data frame that carries the payoff.
            with shape.lock:
                shape.grpc_calls.append((parts.path, self.headers.get("Content-Type"),
                                         base64.b64encode(body).decode("ascii")))
            raw = _grpc_frame(0, _pb_string(1, GRPCPROOF))
            self._reply(200, None, content_type="application/grpc-web-text",
                        raw=base64.b64encode(raw), headers=(("grpc-status", "13"),))
            return
        if parts.path == "/app/soapfault":
            with shape.lock:
                shape.soap_calls.append((self.headers.get("SOAPAction"), body.decode("utf-8", "replace")))
            env = ('<?xml version="1.0"?><soap:Envelope '
                   'xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><soap:Fault>'
                   f'<faultcode>soap:Server</faultcode><faultstring>{SOAPPROOF}</faultstring>'
                   '</soap:Fault></soap:Body></soap:Envelope>')
            self._reply(200, None, content_type="text/xml; charset=utf-8", raw=env.encode())
            return
        if parts.path == "/app/admin":
            with shape.lock:
                shape.writes.append((parts.path, body))
            self._reply(200, {"ok": True, "flag": RPCPROOF})  # a trap: must never be hit
            return
        self._reply(404, {"error": "not_found"})

    def do_GET(self):  # noqa: N802 -- AsyncAPI channel reads (SSE and server-first WebSocket)
        shape = self.server.shape
        path = urllib.parse.urlsplit(self.path).path
        if self.headers.get("Upgrade", "").lower() == "websocket":
            with shape.lock:
                shape.realtime.append((path, "websocket"))
            if path != "/app/ws/feed":
                self._reply(404, {"error": "not_found"})
                return
            key = self.headers.get("Sec-WebSocket-Key", "")
            accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode("ascii")).digest()).decode()
            self.send_response(101, "Switching Protocols")
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.end_headers()
            self.wfile.write(_ws_text(json.dumps({"feed": "ticker", "flag": WSPROOF}))
                             + b"\x88\x02\x03\xe8")
            self.wfile.flush()
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
                shape.ws_client_bytes.append(got)
            self.close_connection = True
            return
        with shape.lock:
            shape.realtime.append((path, "sse"))
        events = {"/app/stream/alerts": CHANPROOF, "/app/stream/noise": DECOYPROOF}
        if path not in events:
            self._reply(404, {"error": "not_found"})
            return
        data = json.dumps({"channel": path.rsplit("/", 1)[-1], "flag": events[path]})
        self._reply(200, None, content_type="text/event-stream",
                    raw=("event: alert\r\ndata: " + data + "\r\n\r\n").encode())


def _serve(shape):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.daemon_threads = True
    server.shape = shape
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address
    return server, f"http://{host}:{port}/app"


@pytest.fixture
def service():
    started = []

    def start():
        shape = Shape()
        server, url = _serve(shape)
        started.append(server)
        return shape, url

    yield start
    for srv in started:
        srv.shutdown()
        srv.server_close()


@pytest.fixture
def on(monkeypatch):
    """Turn the default-off invocation gate on for the invoking tests."""
    monkeypatch.setenv("CTF_WEB_APICALL", "on")
    assert ai.enabled()


def _enc(obj):
    return {"status": 200, "body": json.dumps(obj).encode(),
            "response_headers": {"Content-Type": "application/json"}}


def _invoke(url, descriptor, operation, *, client=None, max_requests=3, spec=None, **extra):
    sink = {}
    client = client if client is not None else W.WebClient(url, timeout=5.0)
    clue = spec if spec is not None else {"descriptor": descriptor, "operation": operation}
    preloaded = {"/api/clues": _enc({"api_invoke": clue})}
    ctx = {"client": client, "preloaded": preloaded, "baseline_texts": [],
           "deadline": time.time() + 30, "max_requests": max_requests, "result_sink": sink}
    ctx.update(extra)
    proof = ai.solve({"url": url, "answer_id": "target"}, ctx)
    return proof, sink["target"]


def _openrpc(url):
    doc = {"openrpc": "1.2.6", "methods": [
        {"name": "getAccountBalance", "params": [],
         "result": {"name": "r", "schema": {"type": "object"}}},
        {"name": "createTransfer", "params": [{"name": "amount", "required": True}]},
    ], "servers": [{"name": "rpc", "url": url + "/rpc"}]}
    return di.parse_document(doc, base_url=url, path="/openrpc.json")


# ==================================================================================================
#  End-to-end: a read-only OpenRPC method is invoked and its payoff returned
# ==================================================================================================
def test_openrpc_read_method_is_invoked_and_payoff_returned(service, on):
    shape, url = service()
    rec = _openrpc(url)
    proof, summary = _invoke(url, rec, "getAccountBalance")
    assert proof == RPCPROOF
    # Exactly one JSON-RPC POST carrying the read method name, no arguments fabricated.
    assert shape.rpc_calls == [("getAccountBalance", {})]
    assert summary["verdict"] == "read" and summary["kind"] == "openrpc"
    assert summary["transport"] == "http" and summary["requests"] == 1
    assert summary["success"] is True
    # The write method was never selected, so the trap endpoint saw nothing.
    assert shape.writes == []


def test_a_write_method_is_surfaced_and_never_invoked(service, on):
    shape, url = service()
    rec = _openrpc(url)
    proof, summary = _invoke(url, rec, "createTransfer")
    assert proof is None
    assert summary["verdict"] == "write"
    assert summary["requests"] == 0            # nothing was sent
    assert shape.rpc_calls == [] and shape.writes == []
    assert "not provably read-only" in summary["surfaced"]["reason"]


def test_off_host_descriptor_server_is_refused_without_a_request(service, on):
    shape, url = service()
    # The descriptor's server points off-host: the engine must refuse and send nothing.
    doc = {"openrpc": "1.2.6",
           "methods": [{"name": "getStatus", "params": []}],
           "servers": [{"name": "ext", "url": "http://evil.example.com/rpc"}]}
    rec = di.parse_document(doc, base_url=url, path="/openrpc.json")
    proof, summary = _invoke(url, rec, "getStatus")
    assert proof is None
    assert summary["requests"] == 0
    assert summary["surfaced"]["reason"] == "no same-origin endpoint: " + ai.OFF_HOST_SERVER
    assert shape.rpc_calls == []


def test_soap_read_operation_is_invoked_with_envelope_and_action(service, on):
    shape, url = service()
    wsdl = (
        '<?xml version="1.0"?>'
        '<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" '
        'xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/" targetNamespace="urn:demo">'
        '<message name="GetInfoIn"/><message name="GetInfoOut"/>'
        '<portType name="P"><operation name="GetInfo">'
        '<input message="GetInfoIn"/><output message="GetInfoOut"/></operation></portType>'
        '<binding name="B" type="P">'
        '<soap:binding transport="http://schemas.xmlsoap.org/soap/http"/>'
        '<operation name="GetInfo"><soap:operation soapAction="urn:demo:GetInfo"/></operation></binding>'
        '<service name="S"><port name="P" binding="B">'
        f'<soap:address location="{url}/soap"/></port></service></definitions>'
    ).encode()
    rec = sd.parse(wsdl, base_url=url, path="/svc.wsdl")
    proof, summary = _invoke(url, rec, "GetInfo")
    # The SOAP read was driven correctly: one POST, the operation element namespaced, the action set.
    assert len(shape.soap_calls) == 1
    action, sent = shape.soap_calls[0]
    assert action == '"urn:demo:GetInfo"'
    assert "<GetInfo" in sent and 'xmlns="urn:demo"' in sent and "soap:Envelope" in sent
    assert summary["kind"] == "wsdl" and summary["verdict"] == "read" and summary["requests"] == 1
    # The SOAP Body is turned into a JSON view the shared extractor reads, so the XML payoff is
    # auto-returned (not merely listed as a candidate).
    assert proof == SOAPPROOF
    assert summary["candidates"] == []


def test_grpc_web_read_method_sends_one_inert_empty_frame(service, on):
    shape, url = service()
    grpc = (b"var d = new grpc.web.MethodDescriptor('/pkg.Svc/GetItem', "
            b"grpc.web.MethodType.UNARY, proto.pkg.Empty, proto.pkg.Item);")
    rec = sd.parse(grpc, base_url=url, path="/svc_grpc_web_pb.js")
    _proof, summary = _invoke(url, rec, "GetItem")
    assert len(shape.grpc_calls) == 1
    path, ctype, body_b64 = shape.grpc_calls[0]
    assert path == "/pkg.Svc/GetItem"
    assert "grpc-web-text" in ctype
    # The engine sent exactly one inert, empty gRPC-web data frame (flags=0, length=0).
    frame = base64.b64decode(base64.b64decode(body_b64))
    assert frame == b"\x00\x00\x00\x00\x00"
    assert summary["kind"] == "grpc-web" and summary["verdict"] == "read" and summary["requests"] == 1


def test_grpc_method_with_nonempty_input_is_not_fabricated(service, on):
    shape, url = service()
    grpc = (b"var d = new grpc.web.MethodDescriptor('/pkg.Svc/GetThing', "
            b"grpc.web.MethodType.UNARY, proto.pkg.ThingRequest, proto.pkg.Thing);")
    rec = sd.parse(grpc, base_url=url, path="/svc_grpc_web_pb.js")
    proof, summary = _invoke(url, rec, "GetThing")
    assert proof is None
    assert shape.grpc_calls == []
    assert "fabricate protobuf fields" in summary["surfaced"]["reason"]


def test_a_get_only_client_blocks_the_rpc_post(service, on):
    shape, url = service()
    rec = _openrpc(url)
    client = W.WebClient(url, timeout=5.0, get_only=True)
    proof, summary = _invoke(url, rec, "getAccountBalance", client=client)
    assert proof is None
    assert shape.rpc_calls == []            # the POST never left the client
    assert "GET-only" in summary["surfaced"]["reason"]


def test_required_param_without_a_safe_value_is_refused(service, on):
    shape, url = service()
    # A read-named method, but a required parameter with no single enumerated value: never guessed.
    doc = {"openrpc": "1.2.6", "methods": [
        {"name": "getRecord", "params": [{"name": "id", "required": True}]},
    ], "servers": [{"name": "rpc", "url": url + "/rpc"}]}
    rec = di.parse_document(doc, base_url=url, path="/openrpc.json")
    proof, summary = _invoke(url, rec, "getRecord")
    assert proof is None
    assert shape.rpc_calls == []
    assert "fabricate an argument" in summary["surfaced"]["reason"]


def test_a_read_method_with_an_enumerated_required_param_is_invoked(service, on):
    shape, url = service()
    doc = {"openrpc": "1.2.6", "methods": [
        {"name": "getMode", "params": [
            {"name": "mode", "required": True, "schema": {"enum": ["status"]}}]},
    ], "servers": [{"name": "rpc", "url": url + "/rpc"}]}
    rec = di.parse_document(doc, base_url=url, path="/openrpc.json")
    proof, _summary = _invoke(url, rec, "getMode")
    assert proof == RPCPROOF
    assert shape.rpc_calls == [("getMode", {"mode": "status"})]


# ==================================================================================================
#  Gate (default off; recon-first, invocation opt-in)
# ==================================================================================================
def test_invocation_is_gated_off_by_default(monkeypatch, service):
    monkeypatch.delenv("CTF_WEB_APICALL", raising=False)
    # With no workdir marker, the engine must be off and name why; no request is attempted.
    shape, url = service()
    rec = _openrpc(url)
    proof, summary = _invoke(url, rec, "getAccountBalance")
    assert proof is None
    assert shape.rpc_calls == []
    assert "gated off by default" in (summary["stopped"] or "")


def test_env_switch_off_value_is_a_named_reason(monkeypatch):
    monkeypatch.setenv("CTF_WEB_APICALL", "no")
    assert ai.enabled() is False
    assert "does not enable" in ai.disabled_reason()


def test_env_switch_on_enables(monkeypatch):
    monkeypatch.setenv("CTF_WEB_APICALL", "on")
    assert ai.enabled() is True
    assert ai.disabled_reason() is None


# ==================================================================================================
#  Read-only classifier (the safety heart)
# ==================================================================================================
@pytest.mark.parametrize("name,expected", [
    ("getUser", "read"), ("listOrders", "read"), ("searchItems", "read"),
    ("fetchStatus", "read"), ("whoami", "read"), ("user.describe", "read"),
    ("getOrder", "read"), ("getIssue", "read"), ("getVoteCount", "read"),
    ("createUser", "write"), ("deleteOrder", "write"), ("updateProfile", "write"),
    ("transferFunds", "write"), ("resetPassword", "write"), ("getAndDelete", "write"),
    ("doThing", "unknown"), ("process", "unknown"), ("", "unknown"),
    # A read verb later in the name proves nothing: only a leading fetch verb is read.
    ("userGet", "unknown"),
    # Ambiguous fetch-or-act verbs are not read verbs.
    ("resolveTicket", "unknown"), ("reportAbuse", "unknown"), ("loadFixtures", "unknown"),
    ("pollQueue", "unknown"), ("watchChanges", "unknown"),
    # Side-effect verbs that are not CRUD words, leading or anywhere in the name.
    ("refundStatus", "write"), ("claimInfo", "write"), ("redeemReport", "write"),
    ("useCouponCount", "write"), ("withdrawSummary", "write"), ("buyItem", "write"),
    ("mintToken", "write"), ("voteCount", "write"), ("toggleFeature", "write"),
    ("markRead", "write"), ("openSession", "write"),
    # A chained name does two things: a write after the conjunction is a write, else unknown.
    ("getAndIncrement", "write"), ("getOrIncrementCounter", "write"), ("fetchAndBurn", "write"),
    ("pollAndAck", "write"), ("readAndMark", "write"), ("getAndLog", "write"),
    ("getAndAudit", "unknown"), ("fetchThenSummarize", "unknown"),
])
def test_rpc_name_classification(name, expected):
    verdict, _reason = ai.classify_operation("openrpc", {"name": name})
    assert verdict == expected


def test_asyncapi_is_classified_by_action_not_name():
    # AsyncAPI v2: subscribe (the app receives) is a read; publish (the app sends) is a write.
    doc = {"asyncapi": "2.6.0", "channels": {
        "user/events": {"subscribe": {"operationId": "onUserEvent",
                                       "message": {"name": "UserEvent"}}},
        "user/commands": {"publish": {"operationId": "sendCommand",
                                      "message": {"name": "Command"}}},
    }}
    rec = di.parse_document(doc, base_url="http://127.0.0.1:1/app", path="/asyncapi.json")
    by_action = {op["action"]: ai.classify_operation("asyncapi", op)[0] for op in rec["operations"]}
    assert by_action.get("subscribe") == "read"
    assert by_action.get("publish") == "write"


def test_client_streaming_rpc_is_a_write_regardless_of_name():
    verdict, reason = ai.classify_operation("grpc-web",
                                            {"name": "GetStream", "client_streaming": True})
    assert verdict == "write" and "streams from the client" in reason


# ==================================================================================================
#  Selection and same-origin resolution (unit)
# ==================================================================================================
def test_select_operation_requires_an_unambiguous_match():
    rec = {"kind": "openrpc", "operations": [
        {"operation_id": "getA", "name": "getA"}, {"operation_id": "getB", "name": "getB"}]}
    op, _ = ai.select_operation(rec, "getA")
    assert op["name"] == "getA"
    assert ai.select_operation(rec, "missing")[0] is None
    # A duplicate identity is ambiguous and refused, never silently first-wins.
    dup = {"kind": "openrpc", "operations": [
        {"operation_id": "dup", "name": "dup"}, {"name": "dup"}]}
    op2, reason = ai.select_operation(dup, "dup")
    assert op2 is None and "ambiguous" in reason


def test_same_origin_endpoint_prefers_same_origin_and_refuses_off_host():
    base = "http://127.0.0.1:8080/app"
    same = {"kind": "openrpc", "servers": [
        {"same_origin": True, "endpoint": "/app/rpc"}]}
    route, _ = ai.same_origin_endpoint(same, base)
    assert route == "/app/rpc"
    off = {"kind": "openrpc", "servers": [{"same_origin": False}]}
    route2, reason = ai.same_origin_endpoint(off, base)
    assert route2 is None and "off-host" in reason


def test_destructive_endpoint_is_refused(service, on):
    shape, url = service()
    # A read-named method, but the descriptor's same-origin server points at a destructive route.
    doc = {"openrpc": "1.2.6", "methods": [{"name": "getData", "params": []}],
           "servers": [{"name": "s", "url": url + "/delete"}]}
    rec = di.parse_document(doc, base_url=url, path="/openrpc.json")
    proof, summary = _invoke(url, rec, "getData")
    assert proof is None and shape.rpc_calls == []
    assert "destructive" in summary["surfaced"]["reason"]


def test_build_invocation_json_rpc_shapes_a_jsonrpc_2_request():
    plan, reason = ai.build_invocation("openrpc", {"name": "getX", "params": []}, "/rpc")
    assert reason is None
    doc = json.loads(plan["body"].decode("ascii"))
    assert doc == {"jsonrpc": "2.0", "id": 1, "method": "getX", "params": {}}
    assert plan["method"] == "POST" and plan["headers"]["Content-Type"] == "application/json"


# ==================================================================================================
#  Round-1 fixes: budget / stop / deadline / route guard (each blocks the one request)
# ==================================================================================================
def test_a_zero_request_budget_sends_nothing(service, on):
    shape, url = service()
    proof, summary = _invoke(url, _openrpc(url), "getAccountBalance", max_requests=0)
    assert proof is None
    assert shape.rpc_calls == [] and summary["requests"] == 0
    assert summary["stopped"] == "max_requests"


def test_a_one_request_budget_sends_exactly_the_one_call(service, on):
    shape, url = service()
    proof, summary = _invoke(url, _openrpc(url), "getAccountBalance", max_requests=1)
    assert proof == RPCPROOF
    assert len(shape.rpc_calls) == 1 and summary["requests"] == 1


def test_a_set_stop_event_sends_nothing(service, on):
    shape, url = service()
    stop = threading.Event()
    stop.set()
    proof, summary = _invoke(url, _openrpc(url), "getAccountBalance", stop=stop)
    assert proof is None and shape.rpc_calls == []
    assert summary["stopped"] == "stopped"


def test_an_elapsed_deadline_sends_nothing(service, on):
    shape, url = service()
    # A deadline already in the past (a lower-bound fact, not a wall-clock race).
    proof, summary = _invoke(url, _openrpc(url), "getAccountBalance", deadline=time.time() - 60)
    assert proof is None and shape.rpc_calls == []
    assert summary["stopped"] == "deadline"


def test_the_route_guard_can_refuse_the_endpoint(service, on):
    shape, url = service()
    seen = []

    def guard(route):
        seen.append(route)
        return False

    proof, summary = _invoke(url, _openrpc(url), "getAccountBalance", route_allowed=guard)
    assert proof is None and shape.rpc_calls == []
    assert seen == ["/app/rpc"]                 # the guard was asked about the resolved endpoint
    assert summary["surfaced"]["reason"] == "route guard refused the invocation endpoint"


def test_a_failing_route_guard_is_a_named_refusal(service, on):
    shape, url = service()

    def guard(_route):
        raise RuntimeError("guard broke")

    proof, summary = _invoke(url, _openrpc(url), "getAccountBalance", route_allowed=guard)
    assert proof is None and shape.rpc_calls == []
    assert "route guard failed" in summary["surfaced"]["reason"]
    assert "RuntimeError" in summary["surfaced"]["reason"]


def test_an_allowing_route_guard_lets_the_call_through(service, on):
    shape, url = service()
    proof, _summary = _invoke(url, _openrpc(url), "getAccountBalance", route_allowed=lambda r: True)
    assert proof == RPCPROOF and len(shape.rpc_calls) == 1


# ==================================================================================================
#  No guessing: an ambiguous enumerated value is refused
# ==================================================================================================
def test_a_required_param_with_two_enum_values_is_refused(service, on):
    shape, url = service()
    doc = {"openrpc": "1.2.6", "methods": [
        {"name": "getMode", "params": [
            {"name": "mode", "required": True, "schema": {"enum": ["status", "debug"]}}]},
    ], "servers": [{"name": "rpc", "url": url + "/rpc"}]}
    rec = di.parse_document(doc, base_url=url, path="/openrpc.json")
    proof, summary = _invoke(url, rec, "getMode")
    assert proof is None and shape.rpc_calls == []
    assert "no single enumerated-safe value" in summary["surfaced"]["reason"]


# ==================================================================================================
#  Off-host: SOAP addresses and forged records
# ==================================================================================================
def _wsdl(location, op="GetInfo"):
    return (
        '<?xml version="1.0"?>'
        '<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" '
        'xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/" targetNamespace="urn:demo">'
        f'<message name="{op}In"/><message name="{op}Out"/>'
        f'<portType name="P"><operation name="{op}">'
        f'<input message="{op}In"/><output message="{op}Out"/></operation></portType>'
        '<binding name="B" type="P">'
        '<soap:binding transport="http://schemas.xmlsoap.org/soap/http"/>'
        f'<operation name="{op}"><soap:operation soapAction="urn:demo:{op}"/></operation></binding>'
        '<service name="S"><port name="P" binding="B">'
        f'<soap:address location="{location}"/></port></service></definitions>'
    )


def test_an_off_host_wsdl_soap_address_is_refused_with_the_off_host_reason(service, on):
    shape, url = service()
    rec = sd.parse(_wsdl("http://evil.example.com/soap").encode(), base_url=url, path="/svc.wsdl")
    assert rec["addresses"][0]["off_origin"] is True        # the recon parser flagged it
    proof, summary = _invoke(url, rec, "GetInfo")
    assert proof is None and shape.soap_calls == []
    assert summary["surfaced"]["reason"] == "no same-origin endpoint: " + ai.OFF_HOST_SOAP


def test_a_soap_address_flagged_off_origin_is_never_used_even_if_its_path_looks_local():
    base = "http://127.0.0.1:8080/app"
    rec = {"kind": "wsdl", "addresses": [
        {"location": "/app/soap", "resolved": base + "/soap", "off_origin": True}]}
    route, reason = ai.same_origin_endpoint(rec, base)
    assert route is None and reason == ai.OFF_HOST_SOAP


def test_an_off_host_server_row_carrying_an_endpoint_is_never_used():
    # A forged/contradictory row: the descriptor says off-host, but an endpoint path is present.
    base = "http://127.0.0.1:8080/app"
    rec = {"kind": "openrpc", "servers": [{"same_origin": False, "endpoint": "/app/rpc"}]}
    route, reason = ai.same_origin_endpoint(rec, base)
    assert route is None and reason == ai.OFF_HOST_SERVER


def test_a_contradictory_pre_parsed_record_is_refused_before_any_request(service, on):
    shape, url = service()
    rec = _openrpc(url)
    rec["servers"] = [{"same_origin": False, "endpoint": "/app/rpc"}]
    proof, summary = _invoke(url, rec, "getAccountBalance")
    assert proof is None and shape.rpc_calls == []
    assert "contradictory record" in summary["surfaced"]["reason"]


@pytest.mark.parametrize("mutate,needle", [
    (lambda r: r["servers"][0].update(same_origin="yes"), "same_origin flag is not a boolean"),
    (lambda r: r["operations"][0].update(client_streaming="no"), "client_streaming flag"),
    (lambda r: r["operations"][0].update(action=["call"]), "action is not a string"),
    (lambda r: r.update(servers="x"), "servers is not a list"),
    (lambda r: r["operations"][0].update(address_known="yes"), "address_known flag"),
])
def test_record_problem_names_mistyped_fields(mutate, needle):
    rec = _openrpc("http://127.0.0.1:8080/app")
    assert ai.record_problem(rec) is None
    mutate(rec)
    assert needle in ai.record_problem(rec)


# ==================================================================================================
#  Re-parse: a raw document / source is parsed by the recon engine against the engine's own target
# ==================================================================================================
def test_a_raw_openrpc_document_is_reparsed_and_invoked(service, on):
    shape, url = service()
    doc = {"openrpc": "1.2.6", "methods": [{"name": "getAccountBalance", "params": []}],
           "servers": [{"name": "rpc", "url": url + "/rpc"}]}
    proof, summary = _invoke(url, None, None, spec={
        "document": doc, "path": "/openrpc.json", "operation": "getAccountBalance"})
    assert proof == RPCPROOF
    assert shape.rpc_calls == [("getAccountBalance", {})] and summary["kind"] == "openrpc"


def test_a_raw_document_cannot_smuggle_an_off_host_server_as_same_origin(service, on):
    shape, url = service()
    # The same_origin flag is computed by the recon engine against the target, so an off-host
    # server in a raw document is refused even though no record flag was supplied.
    doc = {"openrpc": "1.2.6", "methods": [{"name": "getAccountBalance", "params": []}],
           "servers": [{"name": "rpc", "url": "http://evil.example.com/rpc"}]}
    proof, summary = _invoke(url, None, None, spec={
        "document": doc, "path": "/openrpc.json", "operation": "getAccountBalance"})
    assert proof is None and shape.rpc_calls == []
    assert summary["surfaced"]["reason"] == "no same-origin endpoint: " + ai.OFF_HOST_SERVER


def test_a_raw_wsdl_source_is_reparsed_and_invoked(service, on):
    shape, url = service()
    proof, summary = _invoke(url, None, None, spec={
        "source": _wsdl(f"{url}/soap"), "path": "/svc.wsdl", "operation": "GetInfo"})
    assert proof == SOAPPROOF and len(shape.soap_calls) == 1 and summary["kind"] == "wsdl"


def test_two_descriptor_forms_at_once_are_refused(service, on):
    shape, url = service()
    proof, summary = _invoke(url, None, None, spec={
        "descriptor": _openrpc(url), "document": {"openrpc": "1.2.6", "methods": []},
        "operation": "getAccountBalance"})
    assert proof is None and shape.rpc_calls == []
    assert "exactly one of descriptor / document / source" in summary["surfaced"]["reason"]


# ==================================================================================================
#  SOAP and gRPC-web payoffs are judged (auto-returned or demoted), not merely listed
# ==================================================================================================
def test_a_soap_fault_payoff_is_a_candidate_never_auto_returned(service, on):
    shape, url = service()
    rec = sd.parse(_wsdl(f"{url}/soapfault").encode(), base_url=url, path="/svc.wsdl")
    proof, summary = _invoke(url, rec, "GetInfo")
    assert len(shape.soap_calls) == 1
    assert proof is None
    assert SOAPPROOF in summary["candidates"]
    assert summary["stopped"] == "SOAP Fault returned"


def test_soap_view_refuses_a_dtd_and_maps_the_body():
    doc, fault, reason = ai.soap_view(
        b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><x>&a;</x>')
    assert doc is None and "DTD" in reason
    doc, fault, reason = ai.soap_view(
        b'<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>'
        b'<R><v>1</v><v>2</v><w>x</w></R></s:Body></s:Envelope>')
    assert reason is None and fault is False
    assert doc == {"R": {"v": ["1", "2"], "w": "x"}}


def test_a_grpc_web_payoff_is_decoded_from_the_protobuf_frame(service, on):
    shape, url = service()
    grpc = (b"var d = new grpc.web.MethodDescriptor('/pkg.Svc/GetSecret', "
            b"grpc.web.MethodType.UNARY, proto.pkg.Empty, proto.pkg.Secret);")
    rec = sd.parse(grpc, base_url=url, path="/svc_grpc_web_pb.js")
    proof, summary = _invoke(url, rec, "GetSecret")
    assert len(shape.grpc_calls) == 1
    assert proof == GRPCPROOF
    assert summary["success"] is True


def test_a_grpc_error_status_demotes_the_payoff_to_a_candidate(service, on):
    shape, url = service()
    grpc = (b"var d = new grpc.web.MethodDescriptor('/pkg.Svc/GetDenied', "
            b"grpc.web.MethodType.UNARY, proto.pkg.Empty, proto.pkg.Secret);")
    rec = sd.parse(grpc, base_url=url, path="/svc_grpc_web_pb.js")
    proof, summary = _invoke(url, rec, "GetDenied")
    assert len(shape.grpc_calls) == 1
    assert proof is None
    assert GRPCPROOF in summary["candidates"]
    assert summary["stopped"] == "grpc-status 7"


def test_a_grpc_status_response_header_demotes_the_payoff_to_a_candidate(service, on):
    # Trailers-only error: grpc-status 13 arrives as an HTTP header, with no trailer frame.
    shape, url = service()
    grpc = (b"var d = new grpc.web.MethodDescriptor('/pkg.Svc/GetTrailersOnly', "
            b"grpc.web.MethodType.UNARY, proto.pkg.Empty, proto.pkg.Secret);")
    rec = sd.parse(grpc, base_url=url, path="/svc_grpc_web_pb.js")
    proof, summary = _invoke(url, rec, "GetTrailersOnly")
    assert len(shape.grpc_calls) == 1
    assert proof is None   # not auto-returned: the non-zero header status keeps it a candidate
    assert GRPCPROOF in summary["candidates"]
    assert summary["stopped"] == "grpc-status 13"


def test_two_distinct_grpc_payoffs_are_ambiguous_and_not_auto_returned(service, on):
    shape, url = service()
    grpc = (b"var d = new grpc.web.MethodDescriptor('/pkg.Svc/GetTwo', "
            b"grpc.web.MethodType.UNARY, proto.pkg.Empty, proto.pkg.Secret);")
    rec = sd.parse(grpc, base_url=url, path="/svc_grpc_web_pb.js")
    proof, summary = _invoke(url, rec, "GetTwo")
    assert len(shape.grpc_calls) == 1
    assert proof is None
    assert set(summary["candidates"]) == {GRPCPROOF, DECOYPROOF}


def test_grpc_view_rejects_a_truncated_frame_and_proto_strings_walks_nested_messages():
    doc, error, reason = ai.grpc_view(b"\x00\x00\x00\x00\x09abc", "application/grpc-web")
    assert doc is None and "truncated frame" in reason
    inner = _pb_string(1, "hi")                   # b"\x0a\x02hi": not printable, so a nested message
    message = _pb_string(1, "hello") + bytes(((2 << 3) | 2, len(inner))) + inner
    strings, ok = ai.proto_strings(message)
    assert ok and strings == ["hello", "hi"]
    _strings, ok2 = ai.proto_strings(b"\x0a\x09short")   # declared length past the end
    assert ok2 is False


# ==================================================================================================
#  Silent fallbacks are named
# ==================================================================================================
def test_a_missing_proof_extractor_is_named_and_nothing_is_sent(service, on, monkeypatch):
    shape, url = service()
    monkeypatch.setattr(ai, "_proofs", None)
    monkeypatch.setattr(ai, "_PROOFS_IMPORT_ERROR", "ImportError")
    proof, summary = _invoke(url, _openrpc(url), "getAccountBalance")
    assert proof is None and shape.rpc_calls == []
    assert "forge_event failed to import (ImportError)" in summary["stopped"]


def test_a_raising_proof_extractor_is_a_named_stop(service, on, monkeypatch):
    shape, url = service()

    class _Broken:
        @staticmethod
        def extract_success(*_a, **_k):
            raise RuntimeError("extractor broke")

    monkeypatch.setattr(ai, "_proofs", _Broken)
    proof, summary = _invoke(url, _openrpc(url), "getAccountBalance")
    assert len(shape.rpc_calls) == 1
    assert proof is None
    assert "extract_success raised RuntimeError" in summary["stopped"]


def test_an_extractor_fault_on_one_view_stops_the_whole_judgement(service, on, monkeypatch):
    # A gRPC reply is judged one decoded string at a time.  If the shared extractor faults on one
    # string, no other string may be banked: the response as a whole was not judged.
    shape, url = service()
    calls = []

    class _FlakyExtractor:
        @staticmethod
        def extract_success(response, *_a, **_k):
            calls.append(response["body"])
            if len(calls) == 1:
                raise ValueError("first view broke")
            return {"auto": GRPCPROOF, "candidates": []}

    monkeypatch.setattr(ai, "_proofs", _FlakyExtractor)
    grpc = (b"var d = new grpc.web.MethodDescriptor('/pkg.Svc/GetSecret', "
            b"grpc.web.MethodType.UNARY, proto.pkg.Empty, proto.pkg.Secret);")
    rec = sd.parse(grpc, base_url=url, path="/svc_grpc_web_pb.js")
    proof, summary = _invoke(url, rec, "GetSecret")
    assert len(shape.grpc_calls) == 1
    assert proof is None and calls == [b"ok"]
    assert "extract_success raised ValueError" in summary["stopped"]


# ==================================================================================================
#  AsyncAPI: v3 actions, and the SELECTED channel is the one read
# ==================================================================================================
def _async_v3(url):
    host = urllib.parse.urlsplit(url).netloc
    doc = {"asyncapi": "3.0.0",
           "servers": {"ws": {"host": host, "pathname": "/app/ws", "protocol": "ws"}},
           "channels": {"feed": {"address": "feed"}, "cmd": {"address": "cmd"}},
           "operations": {
               "readFeed": {"action": "send", "channel": {"$ref": "#/channels/feed"}},
               "pushCommand": {"action": "receive", "channel": {"$ref": "#/channels/cmd"}}}}
    return di.parse_document(doc, base_url=url, path="/asyncapi.json")


def test_asyncapi_v3_actions_are_classified_from_the_applications_side():
    rec = _async_v3("http://127.0.0.1:1/app")
    verdicts = {op["operation_id"]: ai.classify_operation("asyncapi", op)[0]
                for op in rec["operations"]}
    # v3 'send' = the application sends, the client only receives -> read; 'receive' -> write.
    assert verdicts == {"readFeed": "read", "pushCommand": "write"}


@pytest.mark.parametrize("op,expected", [
    ({"action": "send", "spec_version": "asyncapi-2.6.0"}, "unknown"),
    ({"action": "subscribe", "spec_version": "asyncapi-3.0.0"}, "unknown"),
    ({"action": "receive"}, "unknown"),
    ({"action": "subscribe", "spec_version": "asyncapi-2.0.0"}, "read"),
    ({"action": "publish", "spec_version": "asyncapi-2.0.0"}, "write"),
])
def test_asyncapi_action_words_from_the_wrong_version_are_unknown(op, expected):
    assert ai.classify_operation("asyncapi", op)[0] == expected


@pytest.fixture
def realtime_on(monkeypatch):
    monkeypatch.setenv("CTF_WEB_REALTIME", "on")


def _async_v2_sse(url):
    doc = {"asyncapi": "2.6.0",
           "servers": {"main": {"url": url + "/stream", "protocol": "http"}},
           "channels": {
               "noise": {"subscribe": {"operationId": "onNoise", "message": {"name": "N"}}},
               "alerts": {"subscribe": {"operationId": "onAlerts", "message": {"name": "A"}}},
               "commands": {"publish": {"operationId": "sendCommand", "message": {"name": "C"}}}}}
    return di.parse_document(doc, base_url=url, path="/asyncapi.json")


def test_asyncapi_reads_exactly_the_selected_sse_channel(service, on, realtime_on):
    shape, url = service()
    proof, summary = _invoke(url, _async_v2_sse(url), "onAlerts")
    assert shape.realtime == [("/app/stream/alerts", "sse")]   # the selected channel, nothing else
    assert proof == CHANPROOF and proof != DECOYPROOF
    assert summary["route"] == "/app/stream/alerts" and summary["requests"] == 1
    assert summary["transport"] == "realtime"


def test_asyncapi_reads_the_other_channel_when_it_is_the_one_selected(service, on, realtime_on):
    shape, url = service()
    proof, _summary = _invoke(url, _async_v2_sse(url), "onNoise")
    assert shape.realtime == [("/app/stream/noise", "sse")]
    assert proof == DECOYPROOF


def test_asyncapi_v3_send_reads_the_websocket_channel_without_sending_a_frame(service, on, realtime_on):
    shape, url = service()
    proof, summary = _invoke(url, _async_v3(url), "readFeed")
    assert shape.realtime == [("/app/ws/feed", "websocket")]
    assert proof == WSPROOF
    # The fake records the client's post-upgrade bytes once the client hangs up; wait for that
    # record (a generous bound for a loaded machine, not a timing assertion).
    give_up = time.time() + 60
    while not shape.ws_client_bytes and time.time() < give_up:
        time.sleep(0.05)
    assert shape.ws_client_bytes == [0]          # server-first read: the client sent no frame
    assert summary["requests"] == 1


def test_asyncapi_v3_receive_is_a_write_and_never_connects(service, on, realtime_on):
    shape, url = service()
    proof, summary = _invoke(url, _async_v3(url), "pushCommand")
    assert proof is None and shape.realtime == []
    assert summary["verdict"] == "write" and summary["requests"] == 0


def test_asyncapi_channel_read_honours_the_realtime_off_switch(service, on, monkeypatch):
    monkeypatch.setenv("CTF_WEB_REALTIME", "off")
    shape, url = service()
    proof, summary = _invoke(url, _async_v2_sse(url), "onAlerts")
    assert proof is None and shape.realtime == []
    assert "real-time class is off" in summary["surfaced"]["reason"]
    assert summary["surfaced"]["channel"] == "/app/stream/alerts"


def test_asyncapi_without_realtime_read_is_a_named_lead(service, on, realtime_on, monkeypatch):
    monkeypatch.setattr(ai, "_realtime_read", None)
    monkeypatch.setattr(ai, "_REALTIME_IMPORT_ERROR", "SyntaxError")
    shape, url = service()
    proof, summary = _invoke(url, _async_v2_sse(url), "onAlerts")
    assert proof is None and shape.realtime == []
    assert "realtime_read failed to import (SyntaxError)" in summary["surfaced"]["reason"]


def test_asyncapi_channel_budget_zero_sends_nothing(service, on, realtime_on):
    shape, url = service()
    proof, summary = _invoke(url, _async_v2_sse(url), "onAlerts", max_requests=0)
    assert proof is None and shape.realtime == [] and summary["stopped"] == "max_requests"


def _async_v3_unknown_address(url, channel):
    host = urllib.parse.urlsplit(url).netloc
    doc = {"asyncapi": "3.0.0",
           "servers": {"ws": {"host": host, "pathname": "/app/ws", "protocol": "ws"}},
           "channels": {"secretFeed": channel},
           "operations": {"readSecret": {"action": "send",
                                         "channel": {"$ref": "#/channels/secretFeed"}}}}
    return di.parse_document(doc, base_url=url, path="/asyncapi.json")


@pytest.mark.parametrize("channel", [{"address": None}, {}], ids=["null-address", "no-address"])
def test_asyncapi_v3_channel_with_unknown_address_is_surfaced_never_read(service, on, realtime_on,
                                                                         channel):
    # A v3 channel whose address is null/absent is dynamic or unknown.  The channel id
    # ('secretFeed') is a name, not a route: /app/ws/secretFeed must never be invented and read.
    shape, url = service()
    rec = _async_v3_unknown_address(url, channel)
    (op,) = rec["operations"]
    assert op["channel"] == "secretFeed" and op["address_known"] is False
    proof, summary = _invoke(url, rec, "readSecret")
    assert proof is None and shape.realtime == [] and summary["requests"] == 0
    assert "no known address" in summary["surfaced"]["reason"]


def test_asyncapi_v3_known_address_records_the_flag_and_resolves():
    rec = _async_v3("http://127.0.0.1:8080/app")
    assert {op["operation_id"]: op["address_known"] for op in rec["operations"]} == {
        "readFeed": True, "pushCommand": True}
    assert all(op["address_known"] is True for op in _async_v2_sse("http://127.0.0.1:8080/app")["operations"])


def test_asyncapi_channel_requires_a_known_address_for_v3_records():
    base = "http://127.0.0.1:8080/app"
    same = {"kind": "asyncapi", "servers": [
        {"same_origin": True, "endpoint": "/app/ws", "protocol": "ws"}]}
    v3 = {"channel": "feed", "spec_version": "asyncapi-3.0.0"}
    # A v3 record without the flag cannot show the address was real: refused, not guessed.
    route, _stream, reason = ai.asyncapi_channel(same, base, v3)
    assert route is None and "no known address" in reason
    route, _stream, reason = ai.asyncapi_channel(same, base, dict(v3, address_known=False))
    assert route is None and "no known address" in reason
    route, stream, _ = ai.asyncapi_channel(same, base, dict(v3, address_known=True))
    assert (route, stream) == ("/app/ws/feed", "websocket")
    # An explicit False is refused whatever the version says.
    route, _stream, reason = ai.asyncapi_channel(same, base, {"channel": "feed", "address_known": False})
    assert route is None and "no known address" in reason


def test_asyncapi_templated_or_off_host_channels_are_refused():
    base = "http://127.0.0.1:8080/app"
    same = {"kind": "asyncapi", "servers": [
        {"same_origin": True, "endpoint": "/app/stream", "protocol": "http"}]}
    route, stream, reason = ai.asyncapi_channel(same, base, {"channel": "user/{id}"})
    assert route is None and "templated" in reason
    route, stream, _ = ai.asyncapi_channel(same, base, {"channel": "alerts"})
    assert (route, stream) == ("/app/stream/alerts", "sse")
    off = {"kind": "asyncapi", "servers": [{"same_origin": False, "protocol": "ws"}]}
    route, _stream, reason = ai.asyncapi_channel(off, base, {"channel": "alerts"})
    assert route is None and reason == ai.OFF_HOST_SERVER
    mqtt = {"kind": "asyncapi", "servers": [
        {"same_origin": True, "endpoint": "/app/mq", "protocol": "mqtt"}]}
    route, _stream, reason = ai.asyncapi_channel(mqtt, base, {"channel": "alerts"})
    assert route is None and "no bounded read transport" in reason
    two = {"kind": "asyncapi", "servers": [
        {"same_origin": True, "endpoint": "/app/a", "protocol": "ws"},
        {"same_origin": True, "endpoint": "/app/b", "protocol": "http"}]}
    route, _stream, reason = ai.asyncapi_channel(two, base, {"channel": "alerts"})
    assert route is None and "refusing to guess" in reason


# ==================================================================================================
#  proof_chain dispatches an api_invoke layer to this engine
# ==================================================================================================
def test_proof_chain_dispatches_an_api_invoke_layer(service, on):
    import proof_chain as pc
    assert pc.engine_for("api_invoke") is ai
    shape, url = service()
    protocol = {"layers": [{"index": 1, "class": "api_invoke", "clue": {"/api/clues": {
        "api_invoke": {"descriptor": _openrpc(url), "operation": "getAccountBalance"}}}}]}
    sink = {}
    proof = pc.solve(
        {"url": url, "answer_id": "target"},
        {"client": W.WebClient(url, timeout=5.0),
         "preloaded": {"/api/clues": _enc({"proof_chain": protocol})}, "baseline_texts": [],
         "route_allowed": lambda path, **kw: True, "deadline": time.time() + 30,
         "max_requests": 6, "result_sink": sink})
    assert proof == RPCPROOF
    assert shape.rpc_calls == [("getAccountBalance", {})]
    assert sink["target"]["per_layer"][0]["engine"] == "api_invoke"


def test_proof_chain_names_an_unimportable_api_invoke_engine(monkeypatch):
    import proof_chain as pc
    monkeypatch.setattr(pc, "_api_invoke", None)
    assert pc.engine_for("api_invoke") is None
    assert pc._unavailable_engine("api_invoke") == "api_invoke"
