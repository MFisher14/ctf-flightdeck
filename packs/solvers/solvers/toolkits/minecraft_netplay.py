#!/usr/bin/env python3
"""Minecraft Java protocol framing and the Server List Ping: a server's status with no account.

This is **protocol framing only** (B-120): the VarInt, String and packet codecs, the Handshaking
packet and the Status request/response of the Java edition "Server List Ping".  It performs no login,
no authentication and no Microsoft or Mojang contact, joins no world and sends no chat: the one
exchange it drives is handshake (next state: status) then status request, which every server answers
to any client.  What comes back is recon a challenge can hide a flag in: the MOTD, the version name,
the online players' sample, the mod list and the favicon.

The codec functions are pure and offline; ``split_frames`` and ``parse_handshake`` also read a
captured client or server stream (a TCP stream cut from a pcap).  The one function that opens a
socket, :func:`status_ping`, is scope-guarded and fails closed: every host, loopback included, goes
through ``ctf.scope.check_host``, so it must be inside the event profile's ``rules.live_service_scope``
and must not be the event platform; with no event that resolves, every host is refused.  The
exchange runs under one absolute deadline: the host is resolved once, each of its addresses is tried
with only the time that is left, and so are both sends and every read, so a server that drips its
reply a byte at a time cannot hold the engine past it.  The one step outside the deadline is the name
lookup itself, which the standard library cannot time out (a numeric address needs none).  Tests
drive it against a fake server on 127.0.0.1 under the suite's scope profile; it is never aimed at
event infrastructure from build work.

VarInts are little-endian groups of 7 bits with the high bit as a continuation flag, at most 5 bytes
for a 32-bit value.  A packet on the wire is ``VarInt(length) || VarInt(packet id) || data``; the
Status state never enables compression or encryption, so neither is implemented here.

Entry ``solve(challenge_dir, profile, host=..., port=...) -> SolverResult`` runs the ping through
``python -m ctf run toolkits.minecraft_netplay <challenge_dir> --opt host=H [--opt port=N]``; it is
never run by intake (it needs the network and a named target).
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import math
import socket
import sys
import time
from typing import Any, Callable

import minecraft_world as _world

# ctf package import (script runs need the checkout root on sys.path), mirroring the sibling toolkits.
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt
from ctf import event as _event
from ctf import scope as _scope


ENGINE_ID = "toolkits.minecraft_netplay"

# -- bounds: a status response is small, and a hostile server must not make us allocate without limit
MAX_VARINT_BYTES = 5
MAX_PACKET_BYTES = 1 << 20          # a status JSON with a base64 favicon is at most a few hundred KiB
MAX_STRING_BYTES = MAX_PACKET_BYTES
MAX_ADDRESS_CHARS = 255             # the protocol's limit on the handshake's server address
MAX_FLAGS = 64
MAX_FAVICON_BYTES = 1 << 20
DEFAULT_PORT = 25565
DEFAULT_TIMEOUT_S = 10.0
PROTOCOL_UNKNOWN = -1               # the handshake value a ping uses so as not to claim a version

# The Handshaking packet's "next state" values.  This module only ever sends STATUS.
NEXT_STATE_STATUS = 1
NEXT_STATE_LOGIN = 2
NEXT_STATE_TRANSFER = 3
_NEXT_STATES = (NEXT_STATE_STATUS, NEXT_STATE_LOGIN, NEXT_STATE_TRANSFER)

REFUSED_EXIT = 4


class MinecraftNetplayError(ValueError):
    """Malformed, over-limit, or unsupported protocol input."""


def _fail(message: str) -> MinecraftNetplayError:
    return MinecraftNetplayError(message)


# --------------------------------------------------------------------------- VarInt and String
def encode_varint(value: int) -> bytes:
    """Encode a signed 32-bit integer as a VarInt (two's complement for negatives)."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise _fail("VarInt value must be an int")
    if not -(1 << 31) <= value < (1 << 31):
        raise _fail("VarInt value is out of signed 32-bit range")
    unsigned = value & 0xFFFFFFFF
    out = bytearray()
    while True:
        byte = unsigned & 0x7F
        unsigned >>= 7
        if unsigned:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def decode_varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode a VarInt at ``offset``: ``(signed 32-bit value, next offset)``.  At most 5 bytes."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise _fail("VarInt input must be bytes-like")
    view = bytes(data)
    result = 0
    for index in range(MAX_VARINT_BYTES):
        pos = offset + index
        if pos >= len(view):
            raise _fail("truncated VarInt")
        byte = view[pos]
        result |= (byte & 0x7F) << (7 * index)
        if not byte & 0x80:
            if result >= (1 << 32):
                raise _fail("VarInt does not fit in 32 bits")
            if result >= (1 << 31):
                result -= 1 << 32
            return result, pos + 1
    raise _fail("VarInt exceeds 5 bytes")


def encode_string(text: str) -> bytes:
    """Encode a protocol String: VarInt(byte length) then the UTF-8 bytes."""
    if not isinstance(text, str):
        raise _fail("protocol String must be str")
    raw = text.encode("utf-8")
    if len(raw) > MAX_STRING_BYTES:
        raise _fail("protocol String exceeds the length cap")
    return encode_varint(len(raw)) + raw


def decode_string(data: bytes, offset: int = 0) -> tuple[str, int]:
    """Decode a protocol String at ``offset``: ``(text, next offset)``."""
    length, pos = decode_varint(data, offset)
    if length < 0:
        raise _fail("protocol String length is negative")
    if length > MAX_STRING_BYTES:
        raise _fail("protocol String length exceeds the cap")
    view = bytes(data)
    if pos + length > len(view):
        raise _fail("truncated protocol String")
    try:
        text = view[pos:pos + length].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _fail("protocol String is not valid UTF-8") from exc
    return text, pos + length


# --------------------------------------------------------------------------- packets
def frame_packet(packet_id: int, data: bytes = b"") -> bytes:
    """Build an uncompressed packet: VarInt(length) || VarInt(packet id) || data."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise _fail("packet data must be bytes-like")
    body = encode_varint(packet_id) + bytes(data)
    if len(body) > MAX_PACKET_BYTES:
        raise _fail("packet body exceeds the length cap")
    return encode_varint(len(body)) + body


def parse_packet(body: bytes) -> tuple[int, bytes]:
    """Split a packet body (no length prefix) into ``(packet id, data)``."""
    packet_id, pos = decode_varint(body, 0)
    return packet_id, bytes(body)[pos:]


def split_frames(stream: bytes) -> tuple[list[bytes], bytes]:
    """Cut a byte stream into complete packet bodies: ``(bodies, the incomplete rest)``.

    For a captured client or server stream.  A length that is negative or over the cap is an error;
    a frame that has not fully arrived stays in the rest.
    """
    view = bytes(stream)
    bodies: list[bytes] = []
    pos = 0
    while pos < len(view):
        prefix = view[pos:pos + MAX_VARINT_BYTES]
        if len(prefix) < MAX_VARINT_BYTES and all(byte & 0x80 for byte in prefix):
            break                           # the length prefix itself has not fully arrived
        length, start = decode_varint(view, pos)
        if length < 0 or length > MAX_PACKET_BYTES:
            raise _fail("packet length is negative or exceeds the cap")
        if start + length > len(view):
            break
        bodies.append(view[start:start + length])
        pos = start + length
    return bodies, view[pos:]


def build_handshake(server_address: str, server_port: int, *,
                    protocol_version: int = PROTOCOL_UNKNOWN,
                    next_state: int = NEXT_STATE_STATUS) -> bytes:
    """Build the Handshaking packet (id 0x00): protocol version, address, port, next state."""
    if not isinstance(server_port, int) or isinstance(server_port, bool) or not 0 <= server_port <= 0xFFFF:
        raise _fail("server port must be an int in 0-65535")
    if not isinstance(server_address, str) or len(server_address) > MAX_ADDRESS_CHARS:
        raise _fail(f"server address must be a string of at most {MAX_ADDRESS_CHARS} characters")
    if next_state not in _NEXT_STATES:
        raise _fail("next_state must be 1 (status), 2 (login) or 3 (transfer)")
    payload = (encode_varint(protocol_version) + encode_string(server_address)
               + server_port.to_bytes(2, "big") + encode_varint(next_state))
    return frame_packet(0x00, payload)


def parse_handshake(body: bytes) -> dict[str, Any]:
    """Parse a Handshaking packet body: what a client told a server it wants."""
    packet_id, data = parse_packet(body)
    if packet_id != 0x00:
        raise _fail(f"expected handshake packet id 0x00, got {packet_id:#x}")
    protocol_version, pos = decode_varint(data, 0)
    address, pos = decode_string(data, pos)
    if pos + 2 > len(data):
        raise _fail("truncated handshake port")
    port = int.from_bytes(data[pos:pos + 2], "big")
    next_state, pos = decode_varint(data, pos + 2)
    if pos != len(data):
        raise _fail("trailing bytes after the handshake")
    return {"protocol_version": protocol_version, "server_address": address, "server_port": port,
            "next_state": next_state}


def build_status_request() -> bytes:
    """Build the Status Request packet (id 0x00, empty)."""
    return frame_packet(0x00)


def parse_status_response(body: bytes) -> dict[str, Any]:
    """Parse a Status Response packet body (id 0x00, one String of JSON) into a dict."""
    packet_id, rest = parse_packet(body)
    if packet_id != 0x00:
        raise _fail(f"expected status response packet id 0x00, got {packet_id:#x}")
    text, pos = decode_string(rest, 0)
    if pos != len(rest):
        raise _fail("trailing bytes after the status response String")
    try:
        parsed = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise _fail("status response is not valid JSON") from exc
    if not isinstance(parsed, dict):
        raise _fail("status response JSON is not an object")
    return parsed


# --------------------------------------------------------------------------- what a status carries
def status_surfaces(status: dict[str, Any]) -> list[tuple[str, str]]:
    """``[(surface, text)]`` for every place a status shows text: the MOTD as the client renders it
    (a chat component flattened, formatting codes removed), the version name, each sampled player
    name, each mod id, and every other string value in the JSON (``field``), one value at a time so
    nothing is read across the JSON's own syntax.  The icon field is left out when it is an icon; when
    it is not one (no ``data:`` URI, or base64 that does not decode) it is text like the rest
    (``favicon-text``)."""
    surfaces: list[tuple[str, str]] = []
    description = status.get("description")
    if description is not None:
        surfaces.append(("motd", _world.strip_formatting(_world.json_component_text(description))))
    version = status.get("version")
    if isinstance(version, dict) and isinstance(version.get("name"), str):
        surfaces.append(("version", _world.strip_formatting(version["name"])))
    players = status.get("players")
    sample = players.get("sample") if isinstance(players, dict) else None
    if isinstance(sample, list):
        names = [entry["name"] for entry in sample[:256]
                 if isinstance(entry, dict) and isinstance(entry.get("name"), str)]
        for name in names:
            surfaces.append(("player", _world.strip_formatting(name)))
        if len(names) > 1:                 # a server can spell a line of text down the player list
            surfaces.append(("players-joined", _world.strip_formatting("".join(names))))
    for key in ("forgeData", "modinfo"):
        mods = status.get(key)
        mod_list = (mods.get("mods") or mods.get("modList")) if isinstance(mods, dict) else None
        if isinstance(mod_list, list):
            for mod in mod_list[:512]:
                if isinstance(mod, dict):
                    surfaces.append(("mod", " ".join(str(v) for v in mod.values() if isinstance(v, str))))
    shown = {text for _surface, text in surfaces}
    for leaf in _world.json_strings({key: value for key, value in status.items() if key != "favicon"}):
        if leaf not in shown:
            surfaces.append(("field", leaf))
    favicon = status.get("favicon")
    if isinstance(favicon, str) and favicon and read_favicon(status)[0] is None:
        # not an icon (no data: URI, or one that does not decode): text a server chose to put there
        surfaces.append(("favicon-text", favicon))
    return surfaces


def _harvest(status: dict[str, Any], profile=None) -> tuple[list[dict[str, str]], int]:
    """``([{flag, surface}], dropped)``: ``dropped`` is how many distinct flags past MAX_FLAGS were
    left out."""
    ff = flagfmt.for_profile(profile) if profile is not None else flagfmt.current()
    found: dict[str, str] = {}
    dropped: set[str] = set()
    for surface, text in status_surfaces(status):
        for flag in ff.find_flags(text):
            if flag in found:
                continue
            if len(found) < MAX_FLAGS:
                found[flag] = surface
            else:
                dropped.add(flag)
    return [{"flag": flag, "surface": surface} for flag, surface in found.items()], len(dropped)


def harvest_status_flags(status: dict[str, Any], profile=None) -> list[dict[str, str]]:
    """Flags of the event format on the status surfaces: ``[{flag, surface}]``, first surface wins.
    At most MAX_FLAGS; :func:`status_ping` reports how many more there were (``flags_dropped``)."""
    return _harvest(status, profile)[0]


_BASE64_BREAKS = str.maketrans("", "", "\r\n\t ")      # line breaks and blanks are never base64 data


def favicon_bytes(status: dict[str, Any]) -> bytes | None:
    """The server icon a status carries (``data:image/png;base64,...``), decoded, or None when the
    status has none.  Line breaks (LF or CRLF) and blanks in the base64 are dropped first; an icon
    that still does not decode, or is over the size cap, is a :class:`MinecraftNetplayError`.
    :func:`read_favicon` is the form that never raises."""
    favicon = status.get("favicon")
    if not isinstance(favicon, str) or "," not in favicon or not favicon.startswith("data:"):
        return None
    encoded = favicon.split(",", 1)[1].translate(_BASE64_BREAKS)
    if len(encoded) > MAX_FAVICON_BYTES * 2:
        raise _fail("favicon exceeds the size cap")
    try:
        return base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise _fail("favicon is not valid base64") from exc


def read_favicon(status: dict[str, Any]) -> tuple[bytes | None, str | None]:
    """``(icon, error)``: the decoded icon, or None with the reason it could not be decoded (None when
    the status simply has no icon).  A broken icon is one field of the status, never a reason to
    lose the rest of it."""
    try:
        return favicon_bytes(status), None
    except MinecraftNetplayError as exc:
        return None, str(exc)


# --------------------------------------------------------------------------- scope guard and client
def guard_target(host: str, port: int, profile=None) -> str:
    """Scope-check a live target before any connection; return the host to connect to.

    Every host, loopback included, must pass ``ctf.scope.check_host`` for ``profile`` (or the pinned
    or current event when none is given): the event must resolve, its ``rules.live_service_scope``
    must list the host, and the host must not be the event platform.  There is no loopback
    exemption: a platform or another service can sit on a loopback port.  The returned host is the
    normalised one the scope check passed, and it is the one :func:`status_ping` connects to.
    """
    if not isinstance(host, str) or not host.strip():
        raise _fail("host must be a non-empty string")
    if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 0xFFFF:
        raise _fail("port must be an int in 0-65535")
    return _scope.check_host(host, port, what=f"minecraft status ping {host}:{port}", profile=profile)


class Deadline:
    """One absolute time limit for a whole exchange, on an injectable clock (``time.monotonic``)."""

    def __init__(self, seconds: float, clock: Callable[[], float] | None = None) -> None:
        if (isinstance(seconds, bool) or not isinstance(seconds, (int, float))
                or not math.isfinite(seconds) or seconds <= 0):
            raise _fail("timeout must be a positive number of seconds")
        self.seconds = float(seconds)
        self.clock = clock or time.monotonic
        self.end = self.clock() + self.seconds

    def expired(self) -> MinecraftNetplayError:
        return _fail(f"no complete status reply within the {self.seconds:g} s deadline")

    def remaining(self) -> float:
        """Seconds left; raises once none are."""
        left = self.end - self.clock()
        if left <= 0:
            raise self.expired()
        return left


def _recv_exact(sock: socket.socket, count: int, deadline: Deadline | None = None) -> bytes:
    buf = bytearray()
    while len(buf) < count:
        if deadline is not None:               # the time left for the whole exchange, not per read
            sock.settimeout(deadline.remaining())
        try:
            chunk = sock.recv(min(65536, count - len(buf)))
        except socket.timeout:
            if deadline is None:
                raise
            raise deadline.expired() from None
        if not chunk:
            raise _fail("connection closed before the full frame arrived")
        buf.extend(chunk)
    return bytes(buf)


def read_frame(sock: socket.socket, deadline: Deadline | None = None) -> bytes:
    """Read one length-prefixed packet body (no compression) from a connected socket.

    With a ``deadline`` the socket timeout is set to the time remaining before every read, so the
    frame as a whole is bounded however slowly it arrives; without one the socket's own timeout is
    the caller's business."""
    prefix = bytearray()
    while True:
        prefix.extend(_recv_exact(sock, 1, deadline))
        if not prefix[-1] & 0x80:
            break
        if len(prefix) >= MAX_VARINT_BYTES:
            raise _fail("VarInt exceeds 5 bytes")
    length, _next = decode_varint(bytes(prefix))
    if length < 0 or length > MAX_PACKET_BYTES:
        raise _fail("incoming packet length is negative or exceeds the cap")
    return _recv_exact(sock, length, deadline)


def _connect(host: str, port: int, deadline: Deadline) -> socket.socket:
    """Open a TCP connection to ``host:port`` inside ``deadline``.

    The host is resolved once and each address is tried with only the time the deadline has left
    (``socket.create_connection`` would give every address the full timeout again, so a host with
    several dead addresses could take a multiple of it).  When the time runs out, or every address
    fails, the last connection error is raised.  The name lookup itself has no timeout in the
    standard library: it is the one step the deadline does not bound."""
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    last: OSError | None = None
    for family, kind, proto, _canonical, address in addresses:
        try:
            left = deadline.remaining()
        except MinecraftNetplayError:
            if last is not None:               # the time went on addresses that did not answer
                raise last from None
            raise
        sock: socket.socket | None = None
        try:
            sock = socket.socket(family, kind, proto)
            sock.settimeout(left)
            sock.connect(address)
            return sock
        except OSError as exc:
            last = exc
            if sock is not None:
                sock.close()
    if last is None:
        raise OSError(f"no address for {host}")
    raise last


def status_ping(host: str, port: int = DEFAULT_PORT, *, profile=None,
                protocol_version: int = PROTOCOL_UNKNOWN,
                timeout: float = DEFAULT_TIMEOUT_S,
                clock: Callable[[], float] | None = None) -> dict[str, Any]:
    """Run one Server List Ping against ``host:port`` and return the parsed status with its flags.

    No login: the handshake always asks for the status state, and nothing but the status request
    follows it.  Scope-guarded (:func:`guard_target`) before the connection is opened.  ``timeout``
    is one deadline (on ``clock``) for the connection attempts to every address the host resolves
    to, both sends and every read together: a reply that is not complete by then is a
    :class:`MinecraftNetplayError`.  Only the name lookup is outside it (:func:`_connect`).  The
    report's ``favicon_png`` is the decoded icon (bytes, or None); everything else in it is
    JSON-safe.  An icon that does not decode is ``favicon_error`` (the reason) and its text is
    searched as the ``favicon-text`` surface: the status, its surfaces and its flags are returned
    all the same.
    """
    target = guard_target(host, port, profile)
    deadline = Deadline(timeout, clock)
    sock = _connect(target, port, deadline)
    try:
        try:
            sock.settimeout(deadline.remaining())
            sock.sendall(build_handshake(target, port, protocol_version=protocol_version,
                                         next_state=NEXT_STATE_STATUS))
            sock.settimeout(deadline.remaining())
            sock.sendall(build_status_request())
        except socket.timeout:
            raise deadline.expired() from None
        body = read_frame(sock, deadline)
    finally:
        sock.close()
    status = parse_status_response(body)
    icon, icon_error = read_favicon(status)
    shown = {key: value for key, value in status.items() if key != "favicon"}
    flags, dropped = _harvest(status, profile)
    cut: list[bool] = []                        # the surfaces read a bounded number of JSON values
    _world.json_strings(shown, cut)
    return {
        "kind": "minecraft-status", "host": target, "port": port, "logged_in": False,
        "status": shown,
        "surfaces": [{"surface": surface, "text": text[:2000]}
                     for surface, text in status_surfaces(status) if surface != "field"],
        "favicon": None if icon is None else {"bytes": len(icon), "sha256": hashlib.sha256(icon).hexdigest()},
        "favicon_png": icon,
        "favicon_error": icon_error,
        "flags": flags,
        "flags_dropped": dropped,
        "status_truncated": bool(cut),
    }


# --------------------------------------------------------------------------- engine entry and CLI
_SOLVE_OPTS = frozenset({"host", "port", "protocol", "timeout", "favicon_out"})


def solve(challenge_dir, profile=None, **opts):
    """Engine entry: one status ping of ``--opt host=H [--opt port=N]``.

    Options: ``host`` (required), ``port`` (default 25565), ``protocol`` (handshake version, default
    -1), ``timeout`` (seconds for the whole exchange, default 10, at most 120), ``favicon_out`` (a
    path to write the server icon to).  A
    missing host, an out-of-scope host and an unreachable server are ``blocked`` with the reason; one
    distinct flag on the status is ``solved``, several ``candidate``; a status with no flag is
    ``unsure`` with the MOTD, version and player sample as evidence.  A server icon that does not
    decode is a note, never a reason to drop the status.
    """
    from ctf.result import Evidence, SolverResult

    unknown = sorted(set(opts) - _SOLVE_OPTS)
    if unknown:
        raise _fail(f"unknown option(s) {', '.join(unknown)}; known: {', '.join(sorted(_SOLVE_OPTS))}")
    host = opts.get("host")
    if not isinstance(host, str) or not host.strip():
        return SolverResult(status="blocked", engine=ENGINE_ID,
                            notes="no target: pass --opt host=<server> [--opt port=25565]; this engine "
                                  "never picks a host itself")
    port = opts.get("port", DEFAULT_PORT)
    protocol = opts.get("protocol", PROTOCOL_UNKNOWN)
    timeout = opts.get("timeout", DEFAULT_TIMEOUT_S)
    if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 0xFFFF:
        raise _fail("port must be an int in 0-65535")
    if isinstance(protocol, bool) or not isinstance(protocol, int) or not -(1 << 31) <= protocol < (1 << 31):
        raise _fail("protocol must be a 32-bit int")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 120:
        raise _fail("timeout must be a number of seconds in (0, 120]")
    try:
        report = status_ping(host, port, profile=profile, protocol_version=protocol, timeout=float(timeout))
    except _scope.OutOfScope as exc:
        return SolverResult(status="blocked", engine=ENGINE_ID, notes=f"refused by the event scope: {exc}")
    except OSError as exc:
        return SolverResult(status="blocked", engine=ENGINE_ID,
                            notes=f"could not reach {host}:{port} ({exc.strerror or type(exc).__name__})")
    except MinecraftNetplayError as exc:
        return SolverResult(status="blocked", engine=ENGINE_ID,
                            notes=f"{host}:{port} did not answer a status ping the protocol allows ({exc})")
    notes = [f"status ping of {host}:{port}, no login"]
    if report["flags_dropped"]:
        notes.append(f"{report['flags_dropped']} more distinct flag(s) past the cap of {MAX_FLAGS} "
                     "were not kept: read the status itself")
    if report["status_truncated"]:
        notes.append(f"the status JSON holds more than {_world.MAX_COMPONENT_NODES} values: the ones past "
                     "that were not searched (run the script for the whole status)")
    if report["favicon_error"]:
        notes.append(f"the server icon was not decoded ({report['favicon_error']}): its text was "
                     "searched for the flag format like any other field; the status itself was read")
    icon = report["favicon_png"]
    if icon is not None:
        notes.append(f"favicon: {len(icon)} bytes, sha256 {report['favicon']['sha256']}")
        if opts.get("favicon_out"):
            with open(str(opts["favicon_out"]), "wb") as handle:
                handle.write(icon)
            notes.append(f"favicon written to {opts['favicon_out']}")
    flags = [row["flag"] for row in report["flags"]]
    evidence = [Evidence(kind="wire", detail=f"flag format on the status {row['surface']}")
                for row in report["flags"]]
    evidence += [Evidence(kind="wire", detail=f"{row['surface']}: {row['text'][:240]}")
                 for row in report["surfaces"][:12]]
    status = "solved" if len(flags) == 1 else "candidate" if flags else "unsure"
    return SolverResult(status=status, flags=tuple(flags), evidence=tuple(evidence), engine=ENGINE_ID,
                        notes="; ".join(notes))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Minecraft Java status ping (framing only; no login)")
    parser.add_argument("host", help="server host: one in the event's live_service_scope")
    parser.add_argument("port", nargs="?", type=int, default=DEFAULT_PORT)
    parser.add_argument("--protocol", type=int, default=PROTOCOL_UNKNOWN,
                        help="handshake protocol version (default -1, 'unknown')")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S,
                        help=f"seconds for the whole exchange (default {DEFAULT_TIMEOUT_S:g})")
    parser.add_argument("--event", help="event slug for the scope guard and flag format "
                                        "(default: the current event)")
    parser.add_argument("--favicon-out", metavar="FILE", help="write the server icon (PNG) to FILE")
    parser.add_argument("--compact", action="store_true")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        profile = _event.load(args.event) if args.event else None
        report = status_ping(args.host, args.port, profile=profile, protocol_version=args.protocol,
                             timeout=args.timeout)
    except _scope.OutOfScope as exc:
        print(f"minecraft_netplay: refused: {exc}", file=sys.stderr)
        return REFUSED_EXIT
    except _event.EventError as exc:
        print(f"minecraft_netplay: no event ({exc}); set CTF_EVENT or pass --event", file=sys.stderr)
        return 2
    except MinecraftNetplayError as exc:
        print(f"minecraft_netplay: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"minecraft_netplay: could not reach {args.host}:{args.port} "
              f"({exc.strerror or type(exc).__name__})", file=sys.stderr)
        return 2
    icon = report.pop("favicon_png")
    if icon is not None and args.favicon_out:
        with open(args.favicon_out, "wb") as handle:
            handle.write(icon)
    json.dump(report, sys.stdout, indent=None if args.compact else 2, sort_keys=True)
    sys.stdout.write("\n")
    return 0 if report["flags"] else 1


__all__ = [
    "MinecraftNetplayError", "ENGINE_ID", "encode_varint", "decode_varint", "encode_string",
    "decode_string", "frame_packet", "parse_packet", "split_frames", "build_handshake", "parse_handshake",
    "build_status_request", "parse_status_response", "status_surfaces", "harvest_status_flags",
    "favicon_bytes", "read_favicon", "guard_target", "Deadline", "read_frame", "status_ping", "solve", "main",
    "NEXT_STATE_STATUS", "NEXT_STATE_LOGIN", "NEXT_STATE_TRANSFER", "PROTOCOL_UNKNOWN", "DEFAULT_PORT",
]


if __name__ == "__main__":
    raise SystemExit(main())
