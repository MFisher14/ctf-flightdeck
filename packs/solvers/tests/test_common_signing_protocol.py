"""B-027: length-prefixed binary-protocol client with ECDSA challenge-response signing.

The transport and auth are exercised against a fake SP00KY-style server bound to 127.0.0.1 (never a
real service). The server verifies the client's signature with the public key for a known scalar, so a
passing auth proves the client signed the exact canonical challenge message.
"""
from __future__ import annotations

import os
import socket
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "solvers" / "common"))

import ecc_faults as ef                       # noqa: E402
import ecdsa_recovery as er                   # noqa: E402
import signing_protocol as sp                 # noqa: E402

R1 = ef.SECP256R1


def test_frame_codec_roundtrip():
    codec = sp.FrameCodec()
    frame = codec.encode(0x06, b"hello")
    opcode, length = codec.decode_header(frame[: codec.header_len])
    assert opcode == 0x06 and length == 5
    assert frame[codec.header_len:] == b"hello"


def test_frame_codec_rejects_oversize_and_bad_version():
    codec = sp.FrameCodec(max_payload=4)
    with pytest.raises(sp.ProtocolError):
        codec.encode(0x01, b"toolong")
    with pytest.raises(sp.ProtocolError):
        codec.decode_header(bytes([0x02, 0x01, 0x00, 0x01]))     # version 2 != 1


class _FakeServer:
    """A one-shot SP00KY auth server: challenge, verify the proof against `pubkey`, reply pass/fail."""

    def __init__(self, pubkey, challenge=b"C" * 32, scheme=sp.SP00KY_AUTH):
        self.pubkey = pubkey
        self.challenge = challenge
        self.scheme = scheme
        self.codec = sp.FrameCodec()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.verified = None
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self.thread.start()
        return self

    def _recv_frame(self, conn):
        header = b""
        while len(header) < self.codec.header_len:
            header += conn.recv(self.codec.header_len - len(header))
        opcode, length = self.codec.decode_header(header)
        payload = b""
        while len(payload) < length:
            payload += conn.recv(length - len(payload))
        return opcode, payload

    def _serve(self):
        conn, _ = self.sock.accept()
        with conn:
            opcode, payload = self._recv_frame(conn)     # AUTH_START
            assert opcode == self.scheme.start_opcode
            ulen = payload[0]
            username = payload[1 : 1 + ulen].decode()
            conn.sendall(self.codec.encode(self.scheme.challenge_opcode, self.challenge))
            opcode, proof = self._recv_frame(conn)        # AUTH_PROVE
            assert opcode == self.scheme.prove_opcode
            r = int.from_bytes(proof[:32], "big")
            s = int.from_bytes(proof[32:64], "big")
            message = er.build_canonical_message(
                {"username": username, "challenge": self.challenge}, self.scheme.sign_layout)
            z = er.hash_z(message, R1)
            self.verified = ef.ecdsa_verify((r, s, z), self.pubkey, R1)
            conn.sendall(self.codec.encode(self.scheme.result_opcode,
                                           bytes([0x01 if self.verified else 0x00])))

    def close(self):
        self.sock.close()


def test_authenticate_signs_the_challenge_and_server_accepts():
    d = 0xB4ADE2A2E9404047
    pubkey = ef.ec_mul(d, None, R1)
    server = _FakeServer(pubkey).start()
    try:
        with sp.FramedConnection("127.0.0.1", server.port, timeout=5) as conn:
            ok = sp.authenticate(conn, sp.SP00KY_AUTH, "admin", d)
        assert ok is True
        assert server.verified is True
    finally:
        server.close()


def test_authenticate_fails_with_the_wrong_scalar():
    d = 0x1234
    pubkey = ef.ec_mul(d, None, R1)         # server knows admin's real pubkey
    server = _FakeServer(pubkey).start()
    try:
        with sp.FramedConnection("127.0.0.1", server.port, timeout=5) as conn:
            ok = sp.authenticate(conn, sp.SP00KY_AUTH, "admin", d + 1)   # attacker's wrong scalar
        assert ok is False
        assert server.verified is False
    finally:
        server.close()


def test_connection_closed_midframe_raises():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def _hang():
        conn, _ = srv.accept()
        conn.sendall(bytes([0x01, 0x03, 0x00, 0x20]))    # header promises 32 bytes
        conn.close()                                      # ...then closes

    threading.Thread(target=_hang, daemon=True).start()
    try:
        with sp.FramedConnection("127.0.0.1", port, timeout=5) as conn:
            conn.send(0x02, b"\x05admin")
            with pytest.raises(sp.ProtocolError):
                conn.recv()
    finally:
        srv.close()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
