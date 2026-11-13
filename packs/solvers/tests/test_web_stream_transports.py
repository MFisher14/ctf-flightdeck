#!/usr/bin/env python3
"""Offline socket regressions for WebClient's bounded server-first transports.

Every connection stays on a loopback fake.  The fake records the exact upgrade/SSE request and
any bytes sent after the HTTP upgrade, so these tests prove both the scope lock and the promise
that ``websocket_receive`` sends no WebSocket client frame.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import ipaddress
import json
import os
import socket
import socketserver
import ssl
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
os.environ.pop("CTF_PLATFORM_URL", None)
os.environ.pop("CTF_TOKEN", None)
import web  # noqa: E402


PROOF = "proof_0123456789ab4def8abc0123456789ab"
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
# SH-10: the wss test's client timeout is its whole stream deadline (connect, TLS handshake, upgrade, frames).
# The fake server does the handshake on its accept thread, in this process: under the suite's load 1 s ran
# out inside the handshake ("_ssl.c: The handshake operation timed out", raised as VPNRequired). This is a
# real wall-clock wait, so the bound is one that holds at that load; no check reads the time it took, and a
# client that skipped TLS or changed the origin still fails at once (the server refuses plain bytes).
TLS_CLIENT_TIMEOUT = 10.0


def _frame(payload, opcode=1, masked=False):
    payload = payload.encode() if isinstance(payload, str) else bytes(payload)
    first = 0x80 | opcode
    mask = os.urandom(4) if masked else b""
    flag = 0x80 if masked else 0
    if len(payload) < 126:
        head = bytes((first, flag | len(payload)))
    elif len(payload) < (1 << 16):
        head = bytes((first, flag | 126)) + len(payload).to_bytes(2, "big")
    else:
        head = bytes((first, flag | 127)) + len(payload).to_bytes(8, "big")
    if masked:
        payload = bytes(value ^ mask[i % 4] for i, value in enumerate(payload))
    return head + mask + payload


def _chunk(payload):
    return f"{len(payload):x}\r\n".encode() + payload + b"\r\n"


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        raw = bytearray()
        self.request.settimeout(2)
        while b"\r\n\r\n" not in raw and len(raw) <= 65536:
            part = self.request.recv(4096)
            if not part:
                return
            raw.extend(part)
        head, _, extra = bytes(raw).partition(b"\r\n\r\n")
        lines = head.decode("iso-8859-1").split("\r\n")
        request_line = lines[0]
        headers = {}
        for line in lines[1:]:
            name, value = line.split(":", 1)
            headers[name.lower()] = value.strip()
        path = request_line.split(" ", 2)[1]
        record = {"line": request_line, "headers": headers, "extra": extra,
                  "after_upgrade": None}
        with self.server.records_lock:
            self.server.records.append(record)

        if path.startswith("/ws") or path in ("/bad-accept", "/masked", "/large"):
            key = headers.get("sec-websocket-key", "")
            accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
            if path == "/bad-accept":
                accept = "not-the-right-accept"
            response = ("HTTP/1.1 101 Switching Protocols\r\n"
                        "Upgrade: websocket\r\n"
                        "Connection: keep-alive, Upgrade\r\n"
                        f"Sec-WebSocket-Accept: {accept}\r\n\r\n").encode()
            if path == "/masked":
                response += _frame(PROOF, masked=True)
            elif path == "/large":
                # Announce a payload beyond the caller's cap. The reader must stop before trying
                # to consume it; the connection close is enough to finish the handler.
                response += bytes((0x81, 126)) + (4096).to_bytes(2, "big")
            else:
                response += _frame(json.dumps({"proof": PROOF, "stream": "alpha"}))
            self.request.sendall(response)
            self.request.settimeout(0.8)
            try:
                record["after_upgrade"] = self.request.recv(4096)
            except TimeoutError:
                record["after_upgrade"] = b"<timeout>"
            return

        if path == "/slow-ws":
            time.sleep(1)
            return

        if path == "/events":
            self.request.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\n"
                b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
            )
            pieces = (
                b": heartbeat\r\n\r\n",
                b"event: proof\r\n",
                ("data: " + PROOF[:18]).encode(),
                (PROOF[18:] + "\r\n").encode(),
                b"id: seven\r\nretry: 250\r\n\r\n",
                b"data: second-event-must-not-be-returned\r\n\r\n",
            )
            try:
                for piece in pieces:
                    self.request.sendall(_chunk(piece))
                self.request.sendall(b"0\r\n\r\n")
            except OSError:
                pass
            return

        if path == "/invalid-utf8-sse":
            body = b"data: " + PROOF.encode() + b"\xff\r\n\r\n"
            self.request.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: "
                + str(len(body)).encode() + b"\r\n\r\n" + body
            )
            return

        if path == "/wrong-type":
            body = ("decoy " + PROOF).encode()
            self.request.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
                + str(len(body)).encode() + b"\r\n\r\n" + body
            )
            return

        if path == "/endless":
            body = b"data: " + b"x" * 4096
            self.request.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: "
                + str(len(body)).encode() + b"\r\n\r\n" + body
            )
            return

        self.request.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, tls_context=None):
        self.tls_context = tls_context
        self.records = []
        self.records_lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), _Handler)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self):
        return self.server_address[1]

    def get_request(self):
        conn, address = super().get_request()
        if self.tls_context is not None:
            conn = self.tls_context.wrap_socket(conn, server_side=True)
        return conn, address

    def stop(self):
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=2)


def _tls_context(folder):
    """Make a short-lived loopback certificate using the dependency already used by TLS tests."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = Path(folder) / "cert.pem", Path(folder) / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                         serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    return ctx


class StreamTransportTests(unittest.TestCase):
    def setUp(self):
        self.server = _Server()

    def tearDown(self):
        self.server.stop()

    def client(self, timeout=1.0):
        return web.WebClient(f"http://127.0.0.1:{self.server.port}", timeout=timeout)

    def test_websocket_validates_upgrade_logs_exact_request_and_sends_no_frames(self):
        client = self.client()
        got = client.websocket_receive("/ws?stream=alpha", max_frames=4, max_bytes=4096)
        self.assertEqual(got["status"], 101)
        self.assertTrue(got["upgraded"])
        self.assertTrue(any(PROOF in message for message in got["websocket_messages"]))
        self.assertEqual(got["client_frames"], 0)
        self.assertEqual(got["websocket_frames"][0]["opcode"], 1)
        self.assertIs(client.log[-1], got)
        record = self.server.records[-1]
        self.assertEqual(record["line"], "GET /ws?stream=alpha HTTP/1.1")
        self.assertEqual(record["headers"]["upgrade"].lower(), "websocket")
        self.assertEqual(record["headers"]["sec-websocket-version"], "13")
        until = time.time() + 1
        while record["after_upgrade"] is None and time.time() < until:
            time.sleep(0.01)
        self.assertEqual(record["after_upgrade"], b"")
        # Nested transport metadata remains serializable by the existing evidence logger.
        with tempfile.TemporaryDirectory() as folder:
            saved = client.save_log(Path(folder) / "requests.json")
            self.assertEqual(json.loads(Path(saved).read_text())[0]["transport"], "websocket")

    def test_websocket_rejects_bad_accept_and_masked_server_frame(self):
        client = self.client()
        bad = client.websocket_receive("/bad-accept", max_bytes=4096)
        self.assertFalse(bad["upgraded"])
        self.assertIn("invalid_sec_websocket_accept", bad["protocol_error"])
        self.assertNotIn(PROOF.encode(), bad["body"])
        masked = client.websocket_receive("/masked", max_bytes=4096)
        self.assertTrue(masked["upgraded"])
        self.assertIn("masked", masked["protocol_error"])
        self.assertNotIn(PROOF.encode(), masked["body"])

    def test_websocket_bounds_and_expired_deadline(self):
        client = self.client()
        large = client.websocket_receive("/large", max_bytes=64)
        self.assertTrue(large["truncated"])
        self.assertEqual(large["body"], b"")
        before = len(self.server.records)
        expired = client.websocket_receive("/ws", deadline=time.time() - 0.01)
        self.assertTrue(expired["timed_out"])
        time.sleep(0.05)
        self.assertEqual(len(self.server.records), before, "an expired deadline must not open a socket")

    def test_websocket_scope_refuses_other_port_before_connect(self):
        other = _Server()
        try:
            client = self.client()
            with self.assertRaises(web.OutOfScope):
                client.websocket_receive(f"ws://127.0.0.1:{other.port}/ws")
            time.sleep(0.05)
            self.assertEqual(other.records, [])
            with self.assertRaises(web.OutOfScope):
                client.websocket_receive("ws://127.0.0.1:80@evil.example/ws")
        finally:
            other.stop()

    def test_sse_chunked_first_event_and_protocol_guards(self):
        client = self.client()
        got = client.sse_first_event("/events", max_bytes=4096)
        self.assertEqual(got["status"], 200)
        self.assertTrue(got["event_received"])
        self.assertEqual(got["sse_event"]["event"], "proof")
        self.assertEqual(got["sse_event"]["data"], PROOF)
        self.assertEqual(got["sse_event"]["id"], "seven")
        self.assertEqual(got["sse_event"]["retry"], 250)
        self.assertNotIn(b"second-event", got["body"])
        self.assertEqual(self.server.records[-1]["headers"]["accept"], "text/event-stream")

        wrong = client.sse_first_event("/wrong-type", max_bytes=4096)
        self.assertFalse(wrong["event_received"])
        self.assertIn("content_type_not_event_stream", wrong["protocol_error"])
        self.assertNotIn(PROOF.encode(), wrong["body"])

        limited = client.sse_first_event("/endless", max_bytes=64)
        self.assertFalse(limited["event_received"])
        self.assertTrue(limited["truncated"])
        self.assertEqual(limited["body"], b"")
        self.assertEqual(limited["discarded_bytes"], 64)

        malformed = client.sse_first_event("/invalid-utf8-sse", max_bytes=4096)
        self.assertFalse(malformed["event_received"])
        self.assertTrue(malformed.get("protocol_error"))
        self.assertEqual(malformed["body"], b"")
        self.assertNotIn(PROOF.encode(), malformed["body"])

    def test_wss_alias_uses_tls_and_keeps_exact_origin(self):
        with tempfile.TemporaryDirectory() as folder:
            tls_server = _Server(_tls_context(folder))
            try:
                client = web.WebClient(f"https://127.0.0.1:{tls_server.port}", timeout=TLS_CLIENT_TIMEOUT)
                got = client.websocket_receive(f"wss://127.0.0.1:{tls_server.port}/ws?stream=tls")
                self.assertTrue(got["upgraded"])
                self.assertTrue(any(PROOF in message for message in got["websocket_messages"]))
                self.assertTrue(got["websocket_url"].startswith("wss://"))
                self.assertTrue(got["url"].startswith("https://"))
            finally:
                tls_server.stop()


if __name__ == "__main__":
    unittest.main(verbosity=2)
