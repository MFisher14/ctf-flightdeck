#!/usr/bin/env python3
"""Saved-shape regressions for the three web classes first solved by hand on Day 27.

The proof values and rotated route contracts are the exact recorded base/Mastery evidence. Targets are local
fakes; the public ``proof_hunt.solve_targets`` entry point and production ``WebClient`` own every request.
"""

from __future__ import annotations

import event_pin  # noqa: E402  (tests/event_pin.py)
event_pin.pin(globals(), "huntress")  # Huntress web tests: proof_<32 hex> payoffs (events/huntress [proof])

import base64
import hashlib
import json
import sys
import threading
import time
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO / "solvers" / "web"), str(REPO / "solvers" / "toolkits")]
sys.dont_write_bytecode = True

import proof_hunt  # noqa: E402


DOUBLE_PROOF = "proof_8e67ba1640834690b85ba1f5dc910197"
SOCKET_PROOF = "proof_e442d8f2fb1143709309016c38d8efad"
FORWARDED_PROOF = "proof_8e3c33e76509438bb0236d125262491b"
SSE_PROOF = "proof_404142434445464748494a4b4c4d4e4f"
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _wire_frame(payload):
    data = payload.encode("utf-8")
    if len(data) < 126:
        return bytes((0x81, len(data))) + data
    return bytes((0x81, 126)) + len(data).to_bytes(2, "big") + data


class Shape:
    def __init__(self, kind, proof=None):
        self.kind = kind
        if proof is None:
            if kind == "double":
                proof = DOUBLE_PROOF
            elif kind.startswith("socket"):
                proof = SOCKET_PROOF
            elif kind.startswith("forwarded"):
                proof = FORWARDED_PROOF
        self.proof = proof
        self.lock = threading.Lock()
        self.condition = threading.Condition(self.lock)
        self.hits = []
        self.race_arrivals = 0
        self.race_successes = 0

    def record(self, method, path, headers, body=b""):
        with self.lock:
            self.hits.append((method, path, {str(k).lower(): str(v) for k, v in headers.items()}, bytes(body)))


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    @property
    def shape(self):
        return self.server.shape

    def _reply(self, status, value, headers=None):
        body = value if isinstance(value, bytes) else json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        for key, val in (headers or {}).items():
            self.send_header(key, val)
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _common(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/":
            self._reply(200, {"service": self.shape.kind})
            return True
        if path in ("/robots.txt", "/openapi.json"):
            self._reply(404, {"error": "not_found"})
            return True
        return False

    def do_GET(self):  # noqa: N802
        self.shape.record("GET", self.path, self.headers)
        if self._common():
            return
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        if self.shape.kind == "double":
            if path == "/api/clues":
                self._reply(200, {"framework": "Rails", "feature_route": "/execute-bdb3f6",
                                  "secondary_route": "/audit-ad790f", "current_role": "analyst"})
            elif path == "/execute-bdb3f6":
                self._reply(405, {"error": "post_required"})
            elif path == "/audit-ad790f":
                with self.shape.lock:
                    successes = self.shape.race_successes
                if successes >= 2:
                    self._reply(200, {"ok": True, "effect": "single_credit_spent_twice",
                                      "evidence": self.shape.proof})
                else:
                    self._reply(403, {"error": "credit_not_overspent", "credits": 1})
            else:
                self._reply(404, {"error": "not_found"})
            return
        if self.shape.kind == "double-fallthrough-decoy":
            if path == "/api/clues":
                self._reply(200, {"feature_route": "/read-result", "secondary_route": "/audit-result"})
            elif path == "/read-result":
                self._reply(200, {"ok": True, "effect": "privileged_read", "evidence": DOUBLE_PROOF})
            elif path == "/audit-result":
                self._reply(403, {"error": "not_available"})
            else:
                self._reply(404, {"error": "not_found"})
            return
        if self.shape.kind in ("socket", "socket-header-decoy", "socket-header-ambiguous"):
            if path == "/api/clues":
                self._reply(200, {"framework": "Koa", "feature_route": "/dispatch-53decf",
                                  "stream_reference": 13777})
                return
            if path != "/dispatch-53decf":
                self._reply(404, {"error": "not_found"})
                return
            if self.headers.get("Upgrade", "").lower() != "websocket":
                headers = {"Upgrade": "websocket"}
                if self.shape.kind == "socket-header-decoy":
                    headers["X-Proof-Decoy"] = SOCKET_PROOF
                self._reply(426, {"error": "websocket_upgrade_required"}, headers)
                return
            query = urllib.parse.parse_qs(parsed.query)
            if query.get("stream") != ["13777"]:
                self._reply(403, {"error": "stream_reference_invalid"})
                return
            key = self.headers.get("Sec-WebSocket-Key", "")
            accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode("ascii")).digest()).decode("ascii")
            self.send_response(101, "Switching Protocols")
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            if self.shape.kind == "socket-header-ambiguous":
                self.send_header("X-Other-Proof", SSE_PROOF)
            self.end_headers()
            payload = json.dumps({"ok": True, "effect": "unauthorized_event_stream",
                                  "evidence": self.shape.proof}, separators=(",", ":"))
            self.wfile.write(_wire_frame(payload))
            self.wfile.flush()
            self.close_connection = True
            return
        if self.shape.kind == "forwarded":
            if path == "/api/clues":
                self._reply(200, {"framework": "Micronaut", "feature_route": "/submit-f092e3",
                                  "deployment": "trusted_reverse_proxy", "current_role": "analyst"})
            elif path == "/submit-f092e3" and self.headers.get("X-Forwarded-For") == "127.0.0.1":
                self._reply(200, {"ok": True, "effect": "proxy_trust_admin_bypass",
                                  "evaluated_client": "127.0.0.1", "evidence": self.shape.proof})
            elif path == "/submit-f092e3":
                self._reply(403, {"error": "loopback_only", "evaluated_client": "10.1.0.0"})
            else:
                self._reply(404, {"error": "not_found"})
            return
        if self.shape.kind == "forwarded-secondary":
            if path == "/api/clues":
                self._reply(200, {"feature_route": "/about", "secondary_route": "/submit-secondary",
                                  "deployment": "trusted_reverse_proxy"})
            elif path == "/about":
                self._reply(200, {"service": "proxy-demo"})
            elif path == "/submit-secondary" and self.headers.get("X-Forwarded-For") == "127.0.0.1":
                self._reply(200, {"ok": True, "effect": "proxy_trust_admin_bypass",
                                  "evaluated_client": "127.0.0.1", "evidence": self.shape.proof})
            elif path == "/submit-secondary":
                self._reply(403, {"error": "loopback_only", "evaluated_client": "10.1.0.0"})
            else:
                self._reply(404, {"error": "not_found"})
            return
        if self.shape.kind == "sse":
            if path == "/api/clues":
                self._reply(200, {"framework": "next", "sse_route": "/events-a19d7e",
                                  "transport": "server_sent_events"})
            elif path == "/events-a19d7e":
                data = json.dumps({"ok": True, "effect": "event_stream_read",
                                   "evidence": SSE_PROOF}, separators=(",", ":"))
                body = ("event: proof\ndata: " + data + "\n\n").encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
                self.close_connection = True
            else:
                self._reply(404, {"error": "not_found"})
            return
        if self.shape.kind == "fatal":
            if path == "/api/clues":
                self._reply(200, {"feature_route": "/delete-everything",
                                  "deployment": "trusted_reverse_proxy"})
            else:
                self._reply(404, {"error": "not_found"})
            return
        if self.shape.kind == "fatal-ws":
            if path == "/api/clues":
                self._reply(200, {"feature_route": "/update-account", "stream_reference": 7})
            else:
                self._reply(404, {"error": "not_found"})
            return
        if self.shape.kind == "fatal-ws-query":
            if path == "/api/clues":
                self._reply(200, {"feature_route": "/dispatch-safe", "stream_reset_reference": 7})
            else:
                self._reply(426, {"error": "websocket_upgrade_required"}, {"Upgrade": "websocket"})
            return
        if self.shape.kind == "fatal-sse":
            if path == "/api/clues":
                self._reply(200, {"sse_route": "/approve-request",
                                  "transport": "server_sent_events"})
            else:
                self._reply(404, {"error": "not_found"})

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(min(length, 4096))
        self.shape.record("POST", self.path, self.headers, body)
        path = urllib.parse.urlsplit(self.path).path
        if self.shape.kind != "double" or path != "/execute-bdb3f6" \
                or body.strip() != b"{}" or "application/json" not in self.headers.get("Content-Type", ""):
            self._reply(404, {"error": "not_found"})
            return
        # The first operation waits for a true overlap. A serial caller times out and loses; once two or more
        # requests reach the check-before-decrement point together, exactly two redeem the one synthetic credit.
        with self.shape.condition:
            self.shape.race_arrivals += 1
            if self.shape.race_arrivals < 2:
                self.shape.condition.wait(timeout=0.75)
            else:
                self.shape.condition.notify_all()
            overlapped = self.shape.race_arrivals >= 2
            if overlapped and self.shape.race_successes < 2:
                self.shape.race_successes += 1
                won = True
            else:
                won = False
        time.sleep(0.02)
        self._reply(200 if won else 409,
                    {"ok": True, "effect": "credit_redeemed"} if won else {"error": "credit_unavailable"})


def serve(kind, proof=None):
    shape = Shape(kind, proof=proof)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.shape = shape
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    return server, shape, f"http://{host}:{port}"


def hunt(items, seconds=15, max_requests=80):
    return proof_hunt.solve_targets(items, {"deadline": time.time() + seconds,
                                            "max_requests": max_requests,
                                            "prompt": ("One credit, two purchases. The ledger cannot count "
                                                       "what it cannot see coming — race it and spend the same "
                                                       "credit twice."),
                                            "challenge": "day27-recorded-shapes"})


class Day27Coverage(unittest.TestCase):
    def tearDown(self):
        for server in getattr(self, "servers", []):
            server.shutdown()
            server.server_close()

    def test_all_three_recorded_proofs_in_one_fresh_layer1_run(self):
        self.servers = []
        targets = []
        shapes = {}
        for index, (kind, aid, question) in enumerate((
                ("double", "proof-double", "Exploit the double-spend race and recover the proof."),
                ("socket", "proof-socket", "Recover the proof from the advertised event stream."),
                ("forwarded", "proof-forwarded", "Recover the proof from the trusted reverse-proxy target."),
        ), 1):
            server, shape, url = serve(kind)
            self.servers.append(server)
            shapes[kind] = shape
            targets.append({"answer_id": aid, "url": url, "index": index, "question": question})
        result = hunt(targets)
        self.assertEqual(result, {"proof-double": DOUBLE_PROOF,
                                  "proof-socket": SOCKET_PROOF,
                                  "proof-forwarded": FORWARDED_PROOF})
        self.assertGreaterEqual(len([hit for hit in shapes["double"].hits if hit[0] == "POST"]), 2)
        self.assertTrue(any(hit[0] == "GET" and hit[1].startswith("/dispatch-53decf?stream=13777")
                            and hit[2].get("upgrade", "").lower() == "websocket"
                            for hit in shapes["socket"].hits))
        self.assertTrue(any(hit[1] == "/submit-f092e3"
                            and hit[2].get("x-forwarded-for") == "127.0.0.1"
                            for hit in shapes["forwarded"].hits))

    def test_fatal_advertised_action_is_still_never_requested(self):
        server, shape, url = serve("fatal")
        self.servers = [server]
        result = hunt([{"answer_id": "proof-1", "url": url,
                        "question": "Recover the proof from this reverse proxy."}], max_requests=16)
        self.assertIsNone(result["proof-1"])
        self.assertFalse(any("delete-everything" in hit[1] for hit in shape.hits), shape.hits)

        # The exception is provenance-scoped, not a global removal of the destructive-word guard.
        hunter = proof_hunt._Hunter(url, max_requests=0)
        self.assertFalse(hunter.allowed("/submit-unadvertised", offered=True))
        self.assertTrue(hunter.allowed("/submit-f092e3", offered=False, trusted=True))
        self.assertFalse(hunter.allowed("/delete-everything", offered=False, trusted=True))

    def test_exact_sse_route_reads_only_the_first_event(self):
        server, shape, url = serve("sse")
        self.servers = [server]
        result = hunt([{"answer_id": "proof-sse", "url": url,
                        "question": "Recover the proof from the advertised server-sent event stream."}])
        self.assertEqual(result["proof-sse"], SSE_PROOF)
        events = [hit for hit in shape.hits if hit[1] == "/events-a19d7e"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0][2].get("accept"), "text/event-stream")

    def test_full_destructive_guard_precedes_both_realtime_transports(self):
        self.servers = []
        for kind, forbidden in (("fatal-ws", "/update-account"),
                                ("fatal-sse", "/approve-request")):
            server, shape, url = serve(kind)
            self.servers.append(server)
            result = hunt([{"answer_id": kind, "url": url,
                            "question": "Recover the advertised event proof."}], max_requests=16)
            self.assertIsNone(result[kind])
            self.assertFalse(any(hit[1].split("?", 1)[0] == forbidden for hit in shape.hits), shape.hits)

        server, shape, url = serve("fatal-ws-query")
        self.servers.append(server)
        result = hunt([{"answer_id": "fatal-ws-query", "url": url,
                        "question": "Recover the advertised event proof."}], max_requests=16)
        self.assertIsNone(result["fatal-ws-query"])
        self.assertFalse(any("stream_reset" in hit[1] for hit in shape.hits), shape.hits)
        self.assertFalse(any(hit[2].get("upgrade", "").lower() == "websocket"
                             for hit in shape.hits), shape.hits)

        class NoWireClient:
            def __init__(self, base):
                self.base, self.timeout, self.calls = base, 2, []

            def request(self, *args, **kwargs):
                self.calls.append((args, kwargs))
                raise AssertionError("unsafe real-time contract reached the wire")

            websocket_receive = sse_first_event = request

        direct_client = NoWireClient(url)
        sink = {}
        direct_hunter = proof_hunt._Hunter(url, max_requests=0)
        direct = proof_hunt._realtime_read.solve(
            {"answer_id": "direct", "url": url},
            {"client": direct_client, "deadline": time.time() + 2, "max_requests": 5,
             "preloaded": {"/api/clues": {"status": 200, "body": json.dumps({
                 "feature_route": "/dispatch-safe", "stream_reset_reference": 7,
             }).encode()}},
             "route_allowed": lambda route: direct_hunter.allowed(route, False, trusted=True),
             "result_sink": sink},
        )
        self.assertIsNone(direct)
        self.assertEqual(direct_client.calls, [])
        self.assertEqual(sink["direct"]["requests"], 0)

    def test_guarded_proxy_route_may_be_the_exact_secondary_clue(self):
        server, shape, url = serve("forwarded-secondary")
        self.servers = [server]
        result = hunt([{"answer_id": "secondary", "url": url,
                        "question": "Recover the proof from the trusted reverse proxy."}])
        self.assertEqual(result["secondary"], FORWARDED_PROOF)
        self.assertTrue(any(hit[1] == "/submit-secondary"
                            and hit[2].get("x-forwarded-for") == "127.0.0.1"
                            for hit in shape.hits))

    def test_websocket_headers_obey_baseline_and_ambiguity_rules(self):
        self.servers = []
        for kind in ("socket-header-decoy", "socket-header-ambiguous"):
            server, shape, url = serve(kind)
            self.servers.append(server)
            result = hunt([{"answer_id": kind, "url": url,
                            "question": "Recover the advertised event proof."}])
            self.assertIsNone(result[kind])
            self.assertTrue(any(hit[2].get("upgrade", "").lower() == "websocket"
                                for hit in shape.hits))

    def test_websocket_messages_are_never_concatenated_for_effect_or_proof(self):
        clues = {"feature_route": "/dispatch-safe", "stream_reference": 7}
        control = {"status": 426, "body": b'{"error":"websocket_upgrade_required"}',
                   "response_headers": {"Upgrade": "websocket"}}

        class MessageClient:
            base = "http://target.test/"
            timeout = 2

            def __init__(self, messages):
                self.messages = messages
                self.calls = []

            def websocket_receive(self, path, **_kwargs):
                self.calls.append(path)
                return {"status": 101, "body": "\n".join(self.messages).encode(),
                        "websocket_messages": list(self.messages),
                        "response_headers": {"Upgrade": "websocket"}}

        def solve(messages):
            client, sink = MessageClient(messages), {}
            answer = proof_hunt._realtime_read.solve(
                {"answer_id": "direct", "url": "http://target.test/"},
                {"client": client, "deadline": time.time() + 2, "max_requests": 2,
                 "preloaded": {"/api/clues": {"status": 200,
                                                "body": json.dumps(clues).encode()},
                               "/dispatch-safe": control},
                 "route_allowed": lambda _route: True, "result_sink": sink},
            )
            return answer, sink["direct"], client.calls

        split = ["event_stream_read\nproof:", SOCKET_PROOF]
        answer, summary, calls = solve(split)
        self.assertIsNone(answer, (summary, calls))
        same = [json.dumps({"ok": True, "effect": "event_stream_read",
                            "evidence": SOCKET_PROOF}, separators=(",", ":"))]
        answer, summary, calls = solve(same)
        self.assertEqual(answer, SOCKET_PROOF, (summary, calls))

        mixed = [json.dumps({"ok": True, "effect": "event_stream_read",
                             "proof": SOCKET_PROOF}, separators=(",", ":")),
                 json.dumps({"proof": SSE_PROOF}, separators=(",", ":"))]
        answer, summary, calls = solve(mixed)
        self.assertIsNone(answer, (summary, calls))
        self.assertIn(SSE_PROOF, summary["candidates"])

    def test_realtime_camelcase_destructive_routes_are_zero_wire(self):
        class NoWireClient:
            base = "http://target.test/"
            timeout = 2

            def __init__(self):
                self.calls = []

            def request(self, *args, **kwargs):
                self.calls.append((args, kwargs))
                raise AssertionError("destructive route reached transport")

            websocket_receive = sse_first_event = request

        for clue in ({"feature_route": "/deleteUser", "stream_reference": 7},
                     {"sse_route": "/transferFunds", "feature": "SSE event stream"}):
            client, sink = NoWireClient(), {}
            answer = proof_hunt._realtime_read.solve(
                {"answer_id": "direct", "url": client.base},
                {"client": client, "deadline": time.time() + 2, "max_requests": 5,
                 "preloaded": {"/api/clues": {"status": 200,
                                                "body": json.dumps(clue).encode()}},
                 "route_allowed": lambda _route: True, "result_sink": sink},
            )
            self.assertIsNone(answer, (clue, sink))
            self.assertEqual(client.calls, [], clue)

    def test_realtime_alias_conflicts_are_zero_wire(self):
        class NoWireClient:
            base = "http://target.test/"
            timeout = 2

            def __init__(self):
                self.calls = []

            def request(self, *args, **kwargs):
                self.calls.append((args, kwargs))
                raise AssertionError("ambiguous realtime contract reached transport")

            websocket_receive = sse_first_event = request

        clues = (
            {"sse_route": "/events-a", "event_stream_route": "/events-b",
             "transport": "server_sent_events"},
            {"sse_route": "/events-a", "feature_route": "/events-b",
             "transport": "server_sent_events"},
            {"feature_route": "/dispatch-safe", "stream_reference": 7,
             "event_reference": 8},
        )
        for clue in clues:
            client, sink = NoWireClient(), {}
            answer = proof_hunt._realtime_read.solve(
                {"answer_id": "direct", "url": client.base},
                {"client": client, "deadline": time.time() + 2, "max_requests": 5,
                 "preloaded": {"/api/clues": {"status": 200,
                                                "body": json.dumps(clue).encode()}},
                 "route_allowed": lambda _route: True, "result_sink": sink},
            )
            self.assertIsNone(answer, (clue, sink))
            self.assertEqual(client.calls, [], clue)

    def test_failed_peer_control_remains_a_plain_decoy_after_fallthrough(self):
        server, shape, url = serve("double-fallthrough-decoy")
        self.servers = [server]
        result = hunt([{"answer_id": "fallthrough", "url": url,
                        "question": "Race the one credit twice, then recover the proof."}])
        self.assertIsNone(result["fallthrough"])
        reads = [hit for hit in shape.hits if hit[1] == "/read-result"]
        self.assertGreaterEqual(len(reads), 2, shape.hits)


if __name__ == "__main__":
    unittest.main(verbosity=2)
