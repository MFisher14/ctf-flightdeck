"""B-056: the GDB-RSP live-bench client (solvers/toolkits/rsp.py).

Every networked test runs against a fake GDB stub the test itself starts on 127.0.0.1 (loopback, no
external network), under the suite's loopback scope pin (tests/conftest.py allows 127.0.0.0/8). No
challenge binary is executed; the stub is a synthetic Python handler built here. The stub speaks real
RSP framing, checksums, acks, no-ack mode, qSupported, qXfer:memory-map:read and m/M, so the client is
exercised end to end over a socket through PwnTarget (which runs the scope guard).

Each behaviour has a test that fails when the behaviour is wrong:
  - wire helpers: checksum, escape/unescape, run-length decode, frame/parse_frame, a bad checksum.
  - memory-map XML parsing, including the DTD/entity refusal on untrusted markup.
  - Session/scope: an out-of-scope host is refused before any socket opens.
  - handshake: qSupported parsing + the switch to no-ack mode; commands still work with acks off.
  - reads: batched m, the ~40-packet batch cap, and the paced MMIO page walker (one m per page, paced
    between pages via an injected sleeper -- no wall-clock dependence).
  - writes: M only for an allow-listed address; a non-listed or empty-allow write is refused before any
    byte goes on the wire.
"""
import socket
import socketserver
import threading

import pytest

import rsp
from ctf import scope


# --------------------------------------------------------------------------- fake GDB RSP stub

def _rsp_checksum(body: bytes) -> int:
    return sum(body) & 0xff


class _StubServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, *, packet_size=0x1000, image=b"", image_base=0, rle_runs=False):
        self.packet_size = packet_size
        self.image_base = image_base
        self.mem = {image_base + i: b for i, b in enumerate(image)}
        self.rle_runs = rle_runs
        self.writes = []                      # (addr, bytes) of every M the client sent
        self.memmap = (
            b'<memory-map>'
            b'<memory type="ram" start="0x0" length="0x1000"/>'
            b'<memory type="io" start="0x40000000" length="0x400"/>'
            b'<memory type="flash" start="0x8000000" length="0x10000"/>'
            b'</memory-map>')
        super().__init__(("127.0.0.1", 0), _StubHandler)
        self.port = self.server_address[1]
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def read_mem(self, addr, n):
        raw = bytes(self.mem.get(addr + i, 0) for i in range(n))
        if self.rle_runs:
            return _rle_encode(raw.hex().encode())
        return raw.hex().encode()

    def stop(self):
        self.shutdown()
        self.server_close()


def _rle_encode(data: bytes) -> bytes:
    """Encode runs of >=4 identical bytes GDB-style (byte, '*', count where count = repeats + 29).

    Only used to prove the client's run-length DECODER on the wire; count bytes are kept printable and
    clear of the $/#/} specials by capping each run.
    """
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        j = i
        while j < n and data[j] == data[i] and (j - i) < 90:
            j += 1
        runlen = j - i
        out.append(data[i])
        extra = runlen - 1
        if extra >= 4:
            count_byte = extra + 29
            if count_byte in (ord("#"), ord("$"), ord("}")):
                count_byte -= 1
                extra = count_byte - 29
            out.append(ord("*"))
            out.append(count_byte)
            i += 1 + extra
        else:
            i += 1
    return bytes(out)


class _StubHandler(socketserver.BaseRequestHandler):
    def handle(self):
        buf = b""
        no_ack = False
        pending_no_ack = False
        s = self.request
        while True:
            try:
                data = s.recv(4096)
            except OSError:
                return
            if not data:
                return
            buf += data
            while True:
                start = buf.find(b"$")
                if start < 0:
                    buf = b""                 # only acks/noise buffered; drop it
                    break
                buf = buf[start:]
                hash_at = buf.find(b"#")
                if hash_at < 0 or hash_at + 2 >= len(buf):
                    break                     # incomplete frame
                body = buf[1:hash_at]
                cs = buf[hash_at + 1:hash_at + 3]
                buf = buf[hash_at + 3:]
                if int(cs, 16) != _rsp_checksum(body):
                    if not no_ack:
                        s.sendall(b"-")
                    continue
                if not no_ack:
                    s.sendall(b"+")
                reply, pending_no_ack = self._respond(rsp.unescape(body))
                s.sendall(b"$" + reply + b"#" + f"{_rsp_checksum(reply):02x}".encode())
                if pending_no_ack:
                    no_ack = True

    def _respond(self, cmd):
        srv = self.server
        if cmd.startswith(b"qSupported"):
            return (b"PacketSize=%x;qXfer:memory-map:read+;QStartNoAckMode+;multiprocess+"
                    % srv.packet_size), False
        if cmd == b"QStartNoAckMode":
            return b"OK", True
        if cmd.startswith(b"qXfer:memory-map:read:"):
            tail = cmd[len(b"qXfer:memory-map:read:"):]
            _annex, _, rng = tail.partition(b":")
            off_s, _, len_s = rng.partition(b",")
            off, ln = int(off_s, 16), int(len_s, 16)
            data = srv.memmap[off:off + ln]
            more = (off + ln) < len(srv.memmap)
            return (b"m" if more else b"l") + data, False
        if cmd[:1] == b"m":
            a_s, _, n_s = cmd[1:].partition(b",")
            return srv.read_mem(int(a_s, 16), int(n_s, 16)), False
        if cmd[:1] == b"M":
            head, _, hexdata = cmd[1:].partition(b":")
            a_s, _, _n_s = head.partition(b",")
            addr = int(a_s, 16)
            raw = bytes.fromhex(hexdata.decode())
            for i, b in enumerate(raw):
                srv.mem[addr + i] = b
            srv.writes.append((addr, raw))
            return b"OK", False
        return b"", False


def _client(srv, **kw):
    return rsp.RSPClient("127.0.0.1", srv.port, min_interval=0, **kw)


# --------------------------------------------------------------------------- wire helpers (pure)

def test_checksum_is_mod_256_sum():
    assert rsp.checksum(b"OK") == (ord("O") + ord("K")) & 0xff
    assert rsp.checksum(b"") == 0
    # 'vCont?' checksum is a known RSP value.
    assert f"{rsp.checksum(b'vCont?'):02x}" == f"{sum(b'vCont?') & 0xff:02x}"


def test_frame_round_trips_through_parse():
    frame = rsp.frame_packet(b"qSupported")
    assert frame.startswith(b"$qSupported#")
    body, rest = rsp.parse_frame(frame + b"trailing")
    assert body == b"qSupported" and rest == b"trailing"


def test_parse_frame_incomplete_returns_none():
    assert rsp.parse_frame(b"$qSup") == (None, b"$qSup")
    assert rsp.parse_frame(b"$qSupported#a") == (None, b"$qSupported#a")  # checksum digits not all here


def test_parse_frame_bad_checksum_is_loud():
    with pytest.raises(rsp.RSPProtocolError):
        rsp.parse_frame(b"$OK#00")            # real checksum is not 00


def test_escape_unescape_round_trip_specials():
    raw = bytes([0x24, 0x23, 0x7d, 0x2a, 0x41, 0x00])   # $ # } * A NUL
    esc = rsp.escape(raw)
    assert 0x24 not in esc and 0x23 not in esc          # no bare $/# survive in packet data
    assert rsp.unescape(esc) == raw


def test_unescape_expands_run_length():
    # 'A' then '*' then count byte 0x20 (space): (0x20 - 29) = 3 ADDITIONAL 'A's => 4 total.
    assert rsp.unescape(b"A*\x20") == b"AAAA"
    assert rsp.unescape(b"abc") == b"abc"
    with pytest.raises(rsp.RSPProtocolError):
        rsp.unescape(b"*\x20")                # run marker with nothing to repeat


# --------------------------------------------------------------------------- memory-map parsing

def test_parse_memory_map_regions():
    xml = (b'<memory-map><memory type="ram" start="0x0" length="0x100"/>'
           b'<memory type="io" start="0x40000000" length="0x400"/></memory-map>')
    regions = rsp.parse_memory_map(xml)
    assert [(r.start, r.length, r.type) for r in regions] == [
        (0x0, 0x100, "ram"), (0x40000000, 0x400, "io")]
    assert regions[1].end == 0x40000400
    assert regions[0].contains(0x50, 4) and not regions[0].contains(0x50, 0x1000)


def test_parse_memory_map_refuses_dtd_entities():
    evil = b'<!DOCTYPE m [<!ENTITY x "y">]><memory-map><memory start="0x0" length="0x1"/></memory-map>'
    with pytest.raises(rsp.RSPProtocolError):
        rsp.parse_memory_map(evil)


def test_feature_parse_shapes():
    feats = rsp._parse_features(b"PacketSize=1000;qXfer:memory-map:read+;Qfoo-;bar?")
    assert feats["PacketSize"] == "1000"
    assert feats["qXfer:memory-map:read"] is True
    assert feats["Qfoo"] is False
    assert feats["bar"] == "?"


# --------------------------------------------------------------------------- scope

def test_client_refuses_out_of_scope_before_any_socket(monkeypatch):
    opened = []
    real = socket.create_connection
    monkeypatch.setattr(socket, "create_connection",
                        lambda *a, **k: (opened.append(a), real(*a, **k))[1])
    with pytest.raises(scope.OutOfScope):
        rsp.RSPClient("8.8.8.8", 1234)
    assert opened == []


# --------------------------------------------------------------------------- handshake / acks

def test_handshake_parses_features_and_switches_to_no_ack():
    srv = _StubServer(packet_size=0x200)
    try:
        with _client(srv) as c:
            assert c.ack_mode is True
            feats = c.handshake()
            assert feats["qXfer:memory-map:read"] is True
            assert c.packet_size == 0x200
            assert c.ack_mode is False                 # QStartNoAckMode negotiated
            # A command still works with acks off (would hang/raise if either side still acked).
            assert c.read_memory(0, 0) == b""
            regions = c.memory_map()
            assert any(r.type == "io" for r in regions)
    finally:
        srv.stop()


def test_commands_work_in_ack_mode():
    srv = _StubServer()
    try:
        with _client(srv) as c:
            # No handshake: stays in ack mode. A command still round-trips (acks exchanged both ways).
            assert c.ack_mode is True
            assert c.command(b"QStartNoAckMode") == b"OK"
    finally:
        srv.stop()


# --------------------------------------------------------------------------- reads

def test_read_memory_batches_and_matches_image():
    image = bytes(range(256)) * 2            # 512 deterministic bytes at base 0x1000
    srv = _StubServer(image=image, image_base=0x1000)
    try:
        with _client(srv) as c:
            c.handshake()
            got = c.read_memory(0x1000, 512, chunk=64)     # 8 m packets
            assert got == image
            assert c.read_memory(0x1000 + 10, 4, chunk=64) == image[10:14]
    finally:
        srv.stop()


def test_read_memory_decodes_run_length_from_wire():
    image = b"\x41" * 32 + b"\x42\x43"       # a long run to force the stub's RLE encoder
    srv = _StubServer(image=image, image_base=0x2000, rle_runs=True)
    try:
        with _client(srv) as c:
            c.handshake()
            assert c.read_memory(0x2000, len(image), chunk=len(image)) == image
    finally:
        srv.stop()


def test_read_memory_enforces_batch_cap():
    srv = _StubServer()
    try:
        with _client(srv) as c:
            c.handshake()
            # 100 bytes at chunk=1 would need 100 m packets, over the 40-packet cap -> loud refusal.
            with pytest.raises(rsp.RSPError):
                c.read_memory(0, 100, chunk=1, max_packets=40)
    finally:
        srv.stop()


# --------------------------------------------------------------------------- paced MMIO walker

def test_walk_pages_is_paced_one_packet_per_page():
    image = bytes((i * 7) & 0xff for i in range(0x400))      # 1 KiB MMIO window
    srv = _StubServer(image=image, image_base=0x40000000)
    try:
        with _client(srv) as c:
            c.handshake()
            sleeps = []
            pacer = rsp.Pacer(interval=0.001, sleeper=lambda s: sleeps.append(s))
            before = c.packets_sent
            pages = list(c.walk_pages(0x40000000, 0x400, page_size=0x100, pacer=pacer))
            # 4 pages, each one m packet; reconstruct the full window from what the walker yielded.
            assert [addr for addr, _ in pages] == [0x40000000, 0x40000100, 0x40000200, 0x40000300]
            assert b"".join(data for _, data in pages) == image
            assert c.packets_sent - before == 4            # exactly one m packet per page
            # Paced BETWEEN pages: 3 gaps for 4 pages, each a real sleeper call (logical, not wall-clock).
            assert pacer.waits == 3 and sleeps == [0.001, 0.001, 0.001]
    finally:
        srv.stop()


# --------------------------------------------------------------------------- writes (allow-listed)

def test_write_memory_only_for_allowed_address():
    srv = _StubServer(image=b"\x00" * 8, image_base=0x90)
    try:
        with _client(srv) as c:
            c.handshake()
            assert c.write_memory(0x9c, b"\x01", allow=[0x9c]) is True
            assert srv.writes == [(0x9c, b"\x01")]
            assert srv.mem[0x9c] == 1
    finally:
        srv.stop()


def test_write_memory_refuses_unlisted_address_before_wire():
    srv = _StubServer(image=b"\x00" * 8, image_base=0x90)
    try:
        with _client(srv) as c:
            c.handshake()
            sent = c.packets_sent
            with pytest.raises(rsp.RSPError):
                c.write_memory(0x90, b"\xff", allow=[0x9c])    # not the confirmed address
            assert c.packets_sent == sent                      # nothing went on the wire
            assert srv.writes == []
    finally:
        srv.stop()


def test_write_memory_refuses_empty_allow():
    srv = _StubServer()
    try:
        with _client(srv) as c:
            c.handshake()
            # The empty-`allow` refusal is its OWN guard, distinct from the not-in-list refusal: match
            # its specific reason so deleting the dedicated guard (and falling through to `addr not in
            # allowed`) would change the message and fail this test, not pass silently.
            with pytest.raises(rsp.RSPError, match=r"`allow` is empty"):
                c.write_memory(0x9c, b"\x01", allow=[])        # no guessing / sweeping
            assert srv.writes == []
            # Contrast: a non-empty list that lacks the address refuses with a DIFFERENT reason, so the
            # two guards are provably separate paths.
            with pytest.raises(rsp.RSPError, match=r"not in the caller's allow list"):
                c.write_memory(0x9c, b"\x01", allow=[0xab])
            assert srv.writes == []
    finally:
        srv.stop()


# --------------------------------------------------------------------------- factories (B-003 slots)

class _FakeInstances:
    """Stands in for ctf.instances: status(cid) returns the slot's connect mapping (B-003 surface)."""

    def __init__(self, mapping):
        self._mapping = mapping
        self.asked = []

    def status(self, cid):
        self.asked.append(cid)
        return self._mapping


def test_from_endpoint_builds_scoped_client_and_connects():
    srv = _StubServer()
    try:
        c = rsp.RSPClient.from_endpoint({"host": "127.0.0.1", "port": srv.port}, min_interval=0)
        assert (c.host, c.port) == ("127.0.0.1", srv.port)
        with c:
            feats = c.handshake()
            assert feats["qXfer:memory-map:read"] is True
    finally:
        srv.stop()


def test_from_endpoint_missing_host_or_port_is_refused():
    # A slot mapping without a host (or port) must fail loud, before any socket -- not default or guess.
    with pytest.raises(scope.OutOfScope, match="host and port"):
        rsp.RSPClient.from_endpoint({"port": 1234})
    with pytest.raises(scope.OutOfScope, match="host and port"):
        rsp.RSPClient.from_endpoint({"host": "127.0.0.1"})


def test_from_endpoint_out_of_scope_host_refused_before_socket(monkeypatch):
    opened = []
    real = socket.create_connection
    monkeypatch.setattr(socket, "create_connection",
                        lambda *a, **k: (opened.append(a), real(*a, **k))[1])
    with pytest.raises(scope.OutOfScope):
        rsp.RSPClient.from_endpoint({"host": "8.8.8.8", "port": 1234})
    assert opened == []


def test_from_instances_reads_assigned_slot():
    srv = _StubServer()
    try:
        inst = _FakeInstances({"host": "127.0.0.1", "port": srv.port})
        c = rsp.RSPClient.from_instances(inst, 7, min_interval=0)
        assert inst.asked == [7]                        # the assigned challenge's slot was read
        assert (c.host, c.port) == ("127.0.0.1", srv.port)
        with c:
            assert c.handshake()["qXfer:memory-map:read"] is True
    finally:
        srv.stop()


def test_from_instances_bad_slot_is_refused():
    inst = _FakeInstances({"port": 1234})               # status() returned no host
    with pytest.raises(scope.OutOfScope, match="host and port"):
        rsp.RSPClient.from_instances(inst, 7)


def test_from_session_reuses_session_target():
    srv = _StubServer()
    try:
        inner = _client(srv)                            # a scope-checked PwnTarget-backed client
        session = type("S", (), {"target": inner.target})()
        c = rsp.RSPClient.from_session(session)
        assert c.target is inner.target                 # same scope-checked transport, no new socket spec
        with c:
            assert c.handshake()["qXfer:memory-map:read"] is True
    finally:
        srv.stop()


# --------------------------------------------------------------------------- qXfer chunking

def test_memory_map_reassembles_across_chunks():
    # A small packet size forces qXfer to span several m-chunks before the final l.
    srv = _StubServer(packet_size=0x20)
    try:
        with _client(srv, packet_size=0x20) as c:
            regions = c.memory_map()
            types = [r.type for r in regions]
            assert types == ["ram", "io", "flash"]            # full map despite the chunking
    finally:
        srv.stop()
