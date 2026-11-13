#!/usr/bin/env python3
"""Reusable length-prefixed binary-protocol client with ECDSA challenge-response signing (B-027).

Several signing-service challenges (spooky *No-Nonsense-on-this-Server*, the CSCTF receipt/authorize
services) speak a small framed TCP protocol: a fixed header carrying a version, an opcode and a
big-endian payload length, then the payload.  Authentication is challenge-response: the client asks to
authenticate as a user, the server returns a random challenge, and the client proves control of a
private scalar by signing a canonical message that embeds the challenge, then sends ``r || s``.

This module is the transport-and-auth scaffold, kept out of the recovery math so the two compose.  It
never contacts a service by itself; a driver passes a host/port, and tests drive it against a fake
server bound to ``127.0.0.1``.  The ECDSA signing is delegated to ``ecdsa_recovery.ecdsa_sign`` and the
canonical message is built by ``ecdsa_recovery.build_canonical_message`` from a declared layout, so the
exact framing and message serialization are operator-supplied data, not baked in here.
"""
from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Optional, Sequence

from ecdsa_recovery import build_canonical_message, ecdsa_sign  # flat import on the engine sys.path


class ProtocolError(RuntimeError):
    """A frame was malformed, oversized, or the peer closed mid-message (named, never swallowed)."""


@dataclass(frozen=True)
class FrameCodec:
    """How a frame is laid out: ``version`` byte, 1-byte opcode, big-endian length of ``length_bytes``.

    The default matches the SP00KY framing (version|opcode|uint16 length|payload).
    """

    version: int = 0x01
    length_bytes: int = 2
    max_payload: int = 1024

    @property
    def header_len(self) -> int:
        return 2 + self.length_bytes

    def encode(self, opcode: int, payload: bytes) -> bytes:
        if not 0 <= opcode <= 0xFF:
            raise ProtocolError(f"opcode {opcode} out of range")
        if len(payload) > self.max_payload:
            raise ProtocolError(f"payload {len(payload)} exceeds max {self.max_payload}")
        return (bytes([self.version & 0xFF, opcode & 0xFF])
                + len(payload).to_bytes(self.length_bytes, "big") + payload)

    def decode_header(self, header: bytes) -> tuple[int, int]:
        if len(header) != self.header_len:
            raise ProtocolError("short header")
        version = header[0]
        if version != self.version:
            raise ProtocolError(f"unexpected protocol version {version:#x} (want {self.version:#x})")
        opcode = header[1]
        length = int.from_bytes(header[2:2 + self.length_bytes], "big")
        if length > self.max_payload:
            raise ProtocolError(f"declared length {length} exceeds max {self.max_payload}")
        return opcode, length


@dataclass
class FramedConnection:
    """A framed TCP connection.  Use as a context manager; it never resolves DNS lazily on send."""

    host: str
    port: int
    codec: FrameCodec = field(default_factory=FrameCodec)
    timeout: float = 10.0
    _sock: Optional[socket.socket] = field(default=None, init=False, repr=False)

    def __enter__(self) -> "FramedConnection":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def connect(self) -> None:
        self._sock = socket.create_connection((self.host, self.port), timeout=self.timeout)

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def _recv_exact(self, count: int) -> bytes:
        assert self._sock is not None
        chunks = bytearray()
        while len(chunks) < count:
            try:
                block = self._sock.recv(count - len(chunks))
            except OSError as exc:      # reset/closed peer: a named failure, not a silent partial read
                raise ProtocolError(f"recv failed mid-frame: {exc}") from None
            if not block:
                raise ProtocolError("connection closed mid-frame")
            chunks += block
        return bytes(chunks)

    def send(self, opcode: int, payload: bytes = b"") -> None:
        if self._sock is None:
            raise ProtocolError("not connected")
        self._sock.sendall(self.codec.encode(opcode, payload))

    def recv(self) -> tuple[int, bytes]:
        opcode, length = self.codec.decode_header(self._recv_exact(self.codec.header_len))
        return opcode, self._recv_exact(length)


@dataclass(frozen=True)
class AuthScheme:
    """Opcodes and the canonical signed-message layout for a challenge-response auth exchange.

    ``sign_layout`` is an ``ecdsa_recovery`` layout; the username and challenge are injected into the
    record it is built from under the names ``username`` and ``challenge``.
    """

    start_opcode: int
    challenge_opcode: int
    prove_opcode: int
    result_opcode: int
    sign_layout: Sequence[tuple]
    curve: str = "secp256r1"
    hash_name: str = "sha256"
    challenge_len: Optional[int] = None     # expected challenge length, when the spec fixes it
    success_byte: int = 0x01


def authenticate(conn: FramedConnection, scheme: AuthScheme, username: str, scalar: int, *,
                 sign_k: Optional[int] = None) -> bool:
    """Run AUTH_START -> AUTH_CHALLENGE -> AUTH_PROVE -> AUTH_RESULT and return whether it succeeded.

    The AUTH_START payload is ``uint8(len(username)) || username``; AUTH_PROVE is ``r||s`` as two
    32-byte big-endian halves.  The signed message is the scheme's canonical layout with the live
    challenge embedded.
    """
    name = username.encode("utf-8")
    if len(name) > 0xFF:
        raise ProtocolError("username too long for a 1-byte length prefix")
    conn.send(scheme.start_opcode, bytes([len(name)]) + name)
    opcode, challenge = conn.recv()
    if opcode != scheme.challenge_opcode:
        raise ProtocolError(f"expected challenge opcode {scheme.challenge_opcode:#x}, got {opcode:#x}")
    if scheme.challenge_len is not None and len(challenge) != scheme.challenge_len:
        raise ProtocolError(f"challenge length {len(challenge)} != expected {scheme.challenge_len}")
    record = {"username": username, "challenge": challenge}
    message = build_canonical_message(record, scheme.sign_layout)
    r, s = ecdsa_sign(scalar, message, curve=scheme.curve, hash_name=scheme.hash_name, k=sign_k,
                      low_s=True)
    proof = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    conn.send(scheme.prove_opcode, proof)
    opcode, result = conn.recv()
    if opcode != scheme.result_opcode:
        raise ProtocolError(f"expected result opcode {scheme.result_opcode:#x}, got {opcode:#x}")
    return bool(result) and result[0] == scheme.success_byte


# A ready-made SP00KY-style scheme (the spooky No-Nonsense service).  The layout is still data: an
# operator confirms it against the protocol spec before use.
SP00KY_AUTH = AuthScheme(
    start_opcode=0x02,
    challenge_opcode=0x03,
    prove_opcode=0x04,
    result_opcode=0x05,
    sign_layout=(
        ("const", b"SP00KY-AUTH-v1"),
        ("lenpstr", "username", 1),
        ("bytes", "challenge"),
    ),
    curve="secp256r1",
    challenge_len=32,
)
