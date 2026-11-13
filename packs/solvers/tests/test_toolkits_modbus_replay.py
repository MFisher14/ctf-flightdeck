"""B-082: Modbus/TCP replay and the spec-driven witness/report engine (solvers/toolkits/modbus_replay.py).

Every capture is built here: our own Ethernet/IPv4/TCP frames in our own PCAP/PCAPNG writer. Expected
digests are computed in the test from PDUs the test wrote, never by the engine. Nothing from a
challenge is read.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import struct
import sys
import tomllib
import zipfile
from pathlib import Path

import pytest

import ics_capture as capture
import modbus_replay as mr
from ctf import event
from ctf.result import SolverResult

REPO = Path(__file__).resolve().parents[1]
TEMPLATES = REPO / "solvers" / "toolkits" / "modbus_replay_templates"


def _profile(prefixes=("CSCTF",), slug="b082-test"):
    return event.parse({
        "slug": slug, "name": "modbus replay test",
        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 1, 2)},
        "platform": {"kind": "manual"},
        "flag": {"prefixes": list(prefixes)},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed"},
    }, src="<test>")


PROFILE = _profile()


# ---- fixture builders ------------------------------------------------------------------------------

def _ip(text: str) -> bytes:
    return bytes(int(part) for part in text.split("."))


def tcp_frame(payload: bytes, src: str, dst: str, sport: int, dport: int, seq: int, flags: int = 0x18) -> bytes:
    tcp = (struct.pack(">HHII", sport, dport, seq, 0) + bytes([0x50, flags])
           + struct.pack(">HHH", 8192, 0, 0) + payload)
    ip = (b"\x45\x00" + struct.pack(">H", 20 + len(tcp)) + b"\x00\x01\x40\x00\x40\x06\x00\x00"
          + _ip(src) + _ip(dst) + tcp)
    return b"\x02" * 6 + b"\x04" * 6 + b"\x08\x00" + ip


def _block(kind: int, body: bytes) -> bytes:
    body += b"\x00" * ((-len(body)) & 3)
    length = 12 + len(body)
    return struct.pack("<II", kind, length) + body + struct.pack("<I", length)


def pcapng(frames: list[bytes]) -> bytes:
    out = struct.pack("<II", 0x0A0D0D0A, 28) + struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + struct.pack("<I", 28)
    out += _block(1, struct.pack("<HxxI", 1, 65535))
    for index, frame in enumerate(frames):
        out += _block(6, struct.pack("<IIIII", 0, 0, 1_000_000 + index * 1000, len(frame), len(frame)) + frame)
    return out


def pcap(frames: list[bytes]) -> bytes:
    out = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiiii", 2, 4, 0, 0, 65535, 1)
    for index, frame in enumerate(frames):
        out += struct.pack("<IIII", 1_700_000_000 + index, 0, len(frame), len(frame)) + frame
    return out


def mbap(tid: int, pdu: bytes, unit: int = 1, pid: int = 0) -> bytes:
    return struct.pack(">HHHB", tid, pid, len(pdu) + 1, unit) + pdu


def fc16(start: int, values: list[int]) -> bytes:
    return (b"\x10" + struct.pack(">HHB", start, len(values), 2 * len(values))
            + b"".join(struct.pack(">H", value) for value in values))


def fc16_ok(start: int, quantity: int) -> bytes:
    return b"\x10" + struct.pack(">HH", start, quantity)


def fc03(start: int, quantity: int) -> bytes:
    return b"\x03" + struct.pack(">HH", start, quantity)


def fc03_ok(values: list[int]) -> bytes:
    return bytes([3, 2 * len(values)]) + b"".join(struct.pack(">H", value) for value in values)


def fc06(address: int, value: int) -> bytes:
    return b"\x06" + struct.pack(">HH", address, value)


def exc(function: int, code: int = 2) -> bytes:
    return bytes([function | 0x80, code])


class Wire:
    """One Modbus/TCP connection as frames, with running TCP sequence numbers per direction."""

    def __init__(self, client="10.0.0.5", server="10.0.0.9", cport=40001, sport=502, unit=1):
        self.client, self.server, self.cport, self.sport, self.unit = client, server, cport, sport, unit
        self.frames: list[bytes] = []
        self.seq = {True: 1000, False: 7000}

    def raw(self, to_server: bool, payload: bytes, *, seq: int | None = None, flags: int = 0x18) -> int:
        """Append one TCP segment (seq=None: the next in-order bytes). Returns its packet index."""
        if seq is None:
            seq = self.seq[to_server]
            self.seq[to_server] += len(payload)
        if to_server:
            frame = tcp_frame(payload, self.client, self.server, self.cport, self.sport, seq, flags)
        else:
            frame = tcp_frame(payload, self.server, self.client, self.sport, self.cport, seq, flags)
        self.frames.append(frame)
        return len(self.frames) - 1

    def req(self, tid: int, pdu: bytes, unit: int | None = None, pid: int = 0) -> int:
        return self.raw(True, mbap(tid, pdu, self.unit if unit is None else unit, pid))

    def rsp(self, tid: int, pdu: bytes, unit: int | None = None, pid: int = 0) -> int:
        return self.raw(False, mbap(tid, pdu, self.unit if unit is None else unit, pid))

    def write(self, tid: int, start: int, values: list[int]) -> None:
        self.req(tid, fc16(start, values))
        self.rsp(tid, fc16_ok(start, len(values)))

    def read(self, tid: int, start: int, values: list[int]) -> None:
        self.req(tid, fc03(start, len(values)))
        self.rsp(tid, fc03_ok(values))

    def pcapng(self) -> bytes:
        return pcapng(self.frames)


def adus_of(wire: Wire, **kw):
    adus, findings = mr.capture_adus(wire.pcapng(), **kw)
    return adus, findings


def paired(wire: Wire, mode: str = "pending"):
    adus, _ = adus_of(wire)
    return mr.pair(adus, mode)


def by_tid(txns):
    return {txn.request.tid: txn for txn in txns}


def spec_of(**tables) -> mr.Spec:
    """A minimal valid witness spec, with whole tables replaced by keyword."""
    raw = {
        "schema": 1,
        "output": {"kind": "witness", "prefix_hex": "aa55", "parts": ["request_pdu", "response_pdu"], "wrap": "none"},
    }
    raw.update(tables)
    return mr.parse_spec(raw)


# ---- ics_capture: where each packet's bytes start in a reassembled chunk ---------------------------

def test_reassembly_records_where_each_packet_starts_in_a_chunk():
    def packet(index, sequence, payload):
        return {"transport": "tcp", "source": "a", "source_port": 1, "destination": "b", "destination_port": 502,
                "sequence": sequence, "packet_index": index, "payload": payload}
    stream = capture.reassemble_tcp([packet(0, 10, b"abcdef"), packet(1, 13, b"dXfghi"), packet(2, 30, b"tail"),
                                     packet(3, 34, b"more")])[0]
    first, second = stream["chunks"]
    assert first["data"] == b"abcdefghi"
    assert first["packet_indices"] == [0, 1] and first["segment_offsets"] == [0, 6]   # the overlap adds 3 bytes at 6
    assert second["data"] == b"tailmore"
    assert second["packet_indices"] == [2, 3] and second["segment_offsets"] == [0, 4]  # offsets restart after a gap


# ---- 1. ADUs in capture order ----------------------------------------------------------------------

def test_adus_come_out_in_capture_order_with_their_fields():
    wire = Wire(unit=7)
    wire.req(0x0102, fc03(0x10, 2))
    wire.rsp(0x0102, fc03_ok([5, 6]))
    wire.req(0x0103, fc16(0x20, [9]))
    wire.rsp(0x0103, exc(0x10, 3))
    adus, findings = adus_of(wire)
    assert findings == []
    assert [(a.ordinal, a.packet, a.direction, a.tid) for a in adus] == [
        (0, 0, "request", 0x0102), (1, 1, "response", 0x0102), (2, 2, "request", 0x0103), (3, 3, "response", 0x0103)]
    first, last = adus[0], adus[3]
    assert (first.client, first.client_port, first.server, first.server_port) == ("10.0.0.5", 40001, "10.0.0.9", 502)
    assert (last.client, last.client_port, last.server, last.server_port) == ("10.0.0.5", 40001, "10.0.0.9", 502)
    assert (first.unit, first.pid, first.length, first.pdu) == (7, 0, 6, bytes.fromhex("0300100002"))
    assert first.function == 3 and not first.is_exception
    assert last.function == 16 and last.is_exception and last.pdu == b"\x90\x03"
    assert first.raw == bytes.fromhex("010200000006070300100002")
    assert adus[1].timestamp == pytest.approx(1.001)        # the pcapng packet time of packet 1


def test_classic_pcap_is_read_too():
    wire = Wire()
    wire.read(1, 0, [42])
    adus, _ = mr.capture_adus(pcap(wire.frames))
    assert [(a.direction, a.tid, a.pdu) for a in adus] == [("request", 1, fc03(0, 1)), ("response", 1, fc03_ok([42]))]


def test_an_adu_split_over_segments_sits_at_the_packet_that_completed_it():
    wire = Wire()
    request = mbap(1, fc16(0x30, [7]))
    wire.raw(True, request[:5])                      # packet 0: the first half of request 1
    wire.rsp(9, fc03_ok([1]))                        # packet 1: a whole response from the server
    wire.raw(True, request[5:])                      # packet 2: request 1 is complete only now
    adus, findings = adus_of(wire)
    assert findings == []
    assert [(a.direction, a.tid, a.packet) for a in adus] == [("response", 9, 1), ("request", 1, 2)]
    assert adus[1].pdu == fc16(0x30, [7])


def test_two_adus_in_one_segment_keep_their_stream_order():
    wire = Wire()
    wire.raw(True, mbap(1, fc03(0, 1)) + mbap(2, fc03(4, 1)))
    adus, _ = adus_of(wire)
    assert [(a.tid, a.packet, a.ordinal) for a in adus] == [(1, 0, 0), (2, 0, 1)]


def test_out_of_order_segments_deliver_in_stream_order():
    wire = Wire()
    one, two = mbap(1, fc03(0, 1)), mbap(2, fc03(4, 1))
    wire.raw(True, two, seq=1000 + len(one))         # packet 0: the later bytes arrive first
    wire.rsp(8, fc03_ok([3]))                        # packet 1
    wire.raw(True, one, seq=1000)                    # packet 2: now both requests can be delivered
    adus, findings = adus_of(wire)
    assert [f["kind"] for f in findings] == []
    assert [(a.direction, a.tid, a.packet) for a in adus] == [("response", 8, 1), ("request", 1, 2), ("request", 2, 2)]


def test_a_retransmitted_segment_adds_no_adu():
    wire = Wire()
    wire.req(1, fc03(0, 1))
    wire.raw(True, mbap(1, fc03(0, 1)), seq=1000)    # the same bytes again
    wire.rsp(1, fc03_ok([4]))
    adus, findings = adus_of(wire)
    assert [(a.direction, a.tid, a.packet) for a in adus] == [("request", 1, 0), ("response", 1, 2)]
    assert findings == []


def test_rejected_and_damaged_framing_is_reported():
    wire = Wire()
    wire.req(1, fc03(0, 1), pid=5)                   # nonzero protocol identifier: kept in sequence, rejected
    wire.req(2, fc03(0, 1))
    wire.raw(True, mbap(3, fc03(0, 1))[:9])          # a truncated tail
    adus, findings = adus_of(wire)
    assert [(a.tid, a.malformed) for a in adus] == [(1, "nonzero protocol identifier 0x0005"), (2, "")]
    assert [f["kind"] for f in findings] == ["truncated-adu"]

    gap = Wire()
    gap.req(1, fc03(0, 1))
    gap.raw(True, mbap(2, fc03(0, 1)), seq=5000)     # bytes are missing before this segment
    adus, findings = adus_of(gap)
    assert [a.tid for a in adus] == [1, 2]
    assert [f["kind"] for f in findings] == ["tcp-gap"]
    assert findings[0]["conversation"] == ("10.0.0.5", 40001, "10.0.0.9", 502, 0)

    lost = Wire()
    lost.raw(True, struct.pack(">HHHB", 1, 0, 1, 1) + b"\x03" + mbap(2, fc03(0, 1)))   # MBAP Length 1
    adus, findings = adus_of(lost)
    assert adus == [] and [f["kind"] for f in findings] == ["framing-lost"]

    long = Wire()
    long.req(4, b"\x10" + bytes(300))
    adus, _ = adus_of(long)
    assert adus[0].malformed == "MBAP Length 302 over 254"


def test_only_the_named_server_port_is_modbus():
    wire = Wire(sport=1502)
    wire.read(1, 0, [1])
    assert adus_of(wire)[0] == []
    adus, _ = adus_of(wire, server_port=1502)
    assert [a.direction for a in adus] == ["request", "response"]
    both = Wire(cport=502, sport=502)                # which side is the server? never guessed
    both.read(1, 0, [1])
    adus, findings = adus_of(both)
    assert adus == [] and [f["kind"] for f in findings] == ["ambiguous-direction", "ambiguous-direction"]


def test_scope_needs_exactly_one_conversation_and_filters_the_unit():
    one, two = Wire(cport=40001), Wire(cport=40002, client="10.0.0.6")
    one.read(1, 0, [1])
    one.req(2, fc03(0, 1), unit=9)
    two.read(1, 0, [2])
    adus, _ = mr.capture_adus(pcapng(one.frames + two.frames))
    with pytest.raises(mr.ReplayError) as err:
        mr.scope_adus(adus, mr.Scope())
    assert err.value.reason == "ambiguous-conversation"
    assert "10.0.0.5:40001" in err.value.detail and "10.0.0.6:40002" in err.value.detail
    scoped, conv = mr.scope_adus(adus, mr.Scope(client="10.0.0.5"))
    assert conv == ("10.0.0.5", 40001, "10.0.0.9", 502, 0) and [a.tid for a in scoped] == [1, 1, 2]
    scoped, conv = mr.scope_adus(adus, mr.Scope(client_port=40002))
    assert conv[0] == "10.0.0.6" and len(scoped) == 2
    scoped, _ = mr.scope_adus(adus, mr.Scope(client="10.0.0.5", unit=9))
    assert [(a.tid, a.unit) for a in scoped] == [(2, 9)]
    broadcast = Wire(unit=0)
    broadcast.req(1, fc03(0, 1))
    broadcast.req(2, fc03(0, 1), unit=1)
    scoped, _ = mr.scope_adus(adus_of(broadcast)[0], mr.Scope(unit=0))       # unit 0 is a unit, not "any"
    assert [(a.tid, a.unit) for a in scoped] == [(1, 0)]
    for scope, reason in ((mr.Scope(server="10.9.9.9"), "no-modbus"), (mr.Scope(client="10.0.0.5", unit=3), "no-modbus")):
        with pytest.raises(mr.ReplayError) as err:
            mr.scope_adus(adus, scope)
        assert err.value.reason == reason


# ---- 2. pairing ------------------------------------------------------------------------------------

def test_pending_pairs_by_transaction_id_and_immediate_needs_adjacency():
    wire = Wire()
    wire.req(0xA, fc16(0x30, [1]))
    wire.req(0xB, fc16(0x31, [2]))
    wire.rsp(0xB, fc16_ok(0x31, 1))
    wire.rsp(0xA, fc16_ok(0x30, 1))
    txns, findings = paired(wire, "pending")
    assert [(t.request.tid, t.kind, t.accepted, t.response.packet) for t in txns] == [
        (0xA, "normal", True, 3), (0xB, "normal", True, 2)]
    assert findings == []
    assert [(t.start, t.quantity, t.words) for t in txns] == [(0x30, 1, (1,)), (0x31, 1, (2,))]

    txns, findings = paired(wire, "immediate")
    assert [(t.request.tid, t.kind, t.accepted) for t in txns] == [(0xA, "unanswered", False), (0xB, "normal", True)]
    assert [f["kind"] for f in findings] == ["orphan-response"] and "0x000A" in findings[0]["detail"]


def test_a_response_must_match_unit_and_function():
    wire = Wire()
    wire.req(1, fc03(0, 1), unit=1)
    wire.rsp(1, fc03_ok([5]), unit=2)                # another unit: not its response
    wire.req(2, fc03(0, 1))
    wire.rsp(2, fc16_ok(0, 1))                       # another function code
    wire.req(3, fc03(0, 1))
    wire.rsp(4, fc03_ok([5]))                        # another transaction id
    for mode in ("pending", "immediate"):
        txns, findings = paired(wire, mode)
        assert [t.accepted for t in txns] == [False, False, False], mode
        assert [f["kind"] for f in findings] == ["orphan-response"] * 3, mode
        assert all(t.words == () for t in txns), mode
    txns, _ = paired(wire, "pending")
    assert [t.kind for t in txns] == ["unanswered", "rejected", "unanswered"]
    txns, _ = paired(wire, "immediate")
    assert [t.kind for t in txns] == ["unanswered", "unanswered", "unanswered"]


def acceptance_wire() -> Wire:
    wire = Wire()
    wire.write(1, 0x30, [7, 8])                                      # accepted FC16
    wire.req(2, fc16(0x30, [7]))
    wire.rsp(2, exc(0x10, 4))                                        # exception
    wire.req(3, fc16(0x30, [7]))
    wire.rsp(3, fc16_ok(0x30, 2))                                    # echo: wrong quantity
    wire.req(4, fc16(0x30, [7]))
    wire.rsp(4, fc16_ok(0x31, 1))                                    # echo: wrong start
    wire.req(5, fc16(0x30, [7]))
    wire.rsp(5, fc16_ok(0x30, 1) + b"\x00")                          # echo with a trailing byte
    wire.req(6, b"\x10" + struct.pack(">HHB", 0x30, 2, 2) + b"\x00\x07")   # FC16 byte count is not 2 x quantity
    wire.rsp(6, fc16_ok(0x30, 2))
    wire.req(7, fc03(0x10, 2))
    wire.rsp(7, fc03_ok([1]))                                        # FC03 byte count is not 2 x quantity
    wire.req(8, fc03(0x10, 2))
    wire.rsp(8, fc03_ok([1, 2]))                                     # accepted FC03
    wire.req(9, fc06(0x40, 5))
    wire.rsp(9, fc06(0x40, 5))                                       # accepted FC06
    wire.req(10, fc06(0x40, 5))
    wire.rsp(10, fc06(0x40, 6))                                      # FC06 echo differs
    wire.req(11, fc03(0x10, 1))                                      # never answered
    wire.req(12, b"\x2b\x0e\x01\x00")
    wire.rsp(12, b"\x2b\x0e\x01\x01\x00\x00\x00")                    # another function: paired, no state
    wire.req(13, fc16(0x30, [7]))
    wire.rsp(13, exc(0x10, 4) + b"\x00")                             # malformed exception
    return wire


def test_what_makes_a_transaction_accepted():
    wire = acceptance_wire()
    for mode in ("pending", "immediate"):
        txns = by_tid(paired(wire, mode)[0])
        got = {tid: (t.kind, t.accepted) for tid, t in txns.items()}
        assert got == {
            1: ("normal", True), 2: ("exception", False), 3: ("normal", False), 4: ("normal", False),
            5: ("normal", False), 6: ("rejected", False), 7: ("normal", False), 8: ("normal", True),
            9: ("normal", True), 10: ("normal", False), 11: ("unanswered", False), 12: ("normal", True),
            13: ("exception", False)}, mode
        assert txns[1].words == (7, 8) and txns[8].words == (1, 2) and txns[9].words == (5,)
        assert (txns[9].start, txns[9].quantity) == (0x40, 1)
        assert "echo" in txns[3].reason and "echo" in txns[4].reason and "echo" in txns[5].reason
        assert "byte count" in txns[7].reason and txns[6].reason == "malformed FC16 request"
        assert txns[13].reason == "malformed exception response" and txns[2].reason == ""


def test_malformed_requests_are_rejected_at_the_request():
    wire = Wire()
    requests = {
        1: fc03(0x10, 0), 2: fc03(0x10, 126), 3: fc03(0x10, 125), 4: fc03(0x10, 1) + b"\x00",
        5: fc16(0x10, []), 6: fc16(0x10, [0] * 124), 7: fc16(0x10, [0] * 123), 8: fc16(0x10, [1]) + b"\x00",
        9: fc06(0x10, 1)[:4], 10: fc06(0x10, 1) + b"\x00", 11: exc(0x10, 1), 12: b"\x10\x00\x10",
    }
    for tid, pdu in requests.items():
        wire.req(tid, pdu)
    txns = by_tid(paired(wire, "pending")[0])
    assert {tid: txn.kind for tid, txn in txns.items()} == {
        1: "rejected", 2: "rejected", 3: "unanswered", 4: "rejected", 5: "rejected", 6: "rejected",
        7: "unanswered", 8: "rejected", 9: "rejected", 10: "rejected", 11: "rejected", 12: "rejected"}
    assert txns[1].reason == "malformed FC03 request" and txns[9].reason == "malformed FC06 request"
    assert txns[11].reason == "request carries an exception function code"
    assert (txns[3].start, txns[3].quantity) == (0x10, 125) and len(txns[7].words) == 123


def test_counts_label_every_transaction_once():
    vector = [{"rows": [{"request_pdu": "00", "response_pdu": "00"}],
               "expect_digest": hashlib.sha256(b"\xaa\x55\x00\x00").hexdigest()}]
    out = mr.run_spec(spec_of(vector=vector), acceptance_wire().pcapng(), PROFILE)
    assert out.counts == {"adus": 25, "transactions": 13, "accepted": 4, "exceptions": 2, "unanswered": 1,
                          "rejected": 6, "writes": 1, "targets": 1, "ineligible": 0, "discarded": 0,
                          "unselected": 0, "rows": 1}
    assert out.counts["accepted"] + out.counts["exceptions"] + out.counts["unanswered"] + out.counts["rejected"] == 13


def test_pending_rejects_a_transaction_id_pending_twice_and_a_duplicate_response():
    wire = Wire()
    wire.req(5, fc16(0x30, [1]))
    wire.req(5, fc16(0x30, [2]))
    wire.rsp(5, fc16_ok(0x30, 1))                    # which request? neither is confirmed
    wire.write(6, 0x31, [3])
    wire.rsp(6, fc16_ok(0x31, 1))                    # a second response to an answered request
    wire.write(7, 0x32, [4])
    wire.write(7, 0x32, [5])                         # a transaction id used again later is fine
    txns, findings = paired(wire, "pending")
    assert [(t.request.tid, t.kind, t.accepted) for t in txns] == [
        (5, "rejected", False), (5, "rejected", False), (6, "normal", False), (7, "normal", True), (7, "normal", True)]
    assert txns[2].reason == "a duplicate response followed"
    assert [f["kind"] for f in findings] == ["orphan-response", "orphan-response"]


def test_a_rejected_adu_never_pairs():
    wire = Wire()
    wire.req(1, fc16(0x30, [1]), pid=7)              # rejected request
    wire.rsp(1, fc16_ok(0x30, 1))
    wire.req(2, fc16(0x30, [2]))
    wire.rsp(2, fc16_ok(0x30, 1), pid=7)             # rejected response
    wire.rsp(2, fc16_ok(0x30, 1))                    # the real one, still pending in `pending` mode
    txns, _ = paired(wire, "pending")
    assert [(t.kind, t.accepted) for t in txns] == [("rejected", False), ("normal", True)]
    txns, _ = paired(wire, "immediate")              # ... but no longer directly after its request
    assert [(t.kind, t.accepted) for t in txns] == [("rejected", False), ("unanswered", False)]
    with pytest.raises(mr.ReplayError):
        mr.pair([], "fifo")


# ---- 3. register-state replay ----------------------------------------------------------------------

def test_a_write_takes_effect_on_its_normal_response_not_its_request():
    wire = Wire()
    wire.req(1, fc16(0x10, [7]))                     # the write is on the wire ...
    wire.read(2, 0x10, [3])                          # ... the controller still reports 3 ...
    wire.rsp(1, fc16_ok(0x10, 1))                    # ... and only now is the write accepted
    wire.read(3, 0x10, [7])
    txns, _ = paired(wire, "pending")
    timeline = mr.replay(txns)
    t = by_tid(txns)
    assert (dict(t[2].before), dict(t[2].after)) == ({}, {0x10: 3})
    assert (dict(t[1].before), dict(t[1].after)) == ({0x10: 3}, {0x10: 7})
    assert (dict(t[3].before), dict(t[3].after)) == ({0x10: 7}, {0x10: 7})
    assert [(row["tid"], row["source"], row["address"], row["old"], row["new"], row["packet"]) for row in timeline] == [
        (2, "read", 0x10, None, 3, 2), (1, "write", 0x10, 3, 7, 3)]


def test_only_accepted_writes_and_fc03_reads_change_state():
    wire = Wire()
    wire.read(1, 0x10, [1, 2, 3])                    # FC03 refreshes every word it covers
    wire.req(2, fc16(0x10, [9]))
    wire.rsp(2, exc(0x10))                           # exception: nothing
    wire.req(3, fc16(0x11, [9]))
    wire.rsp(3, fc16_ok(0x11, 2))                    # bad echo: nothing
    wire.req(4, fc06(0x12, 9))
    wire.rsp(4, fc06(0x12, 9))                       # FC06 applies
    wire.write(5, 0x11, [20, 30])                    # FC16 applies to both words
    wire.req(6, b"\x04" + struct.pack(">HH", 0x10, 1))
    wire.rsp(6, bytes([4, 2, 0, 99]))                # FC04 is the input-register table: not holding state
    wire.req(7, fc16(0x10, [55]))                    # unanswered: nothing
    txns, _ = paired(wire, "immediate")
    timeline = mr.replay(txns, initial={0x10: 0, 0x50: 8})
    t = by_tid(txns)
    assert dict(t[1].before) == {0x10: 0, 0x50: 8}
    assert dict(t[1].after) == {0x10: 1, 0x11: 2, 0x12: 3, 0x50: 8}
    assert t[2].after == t[2].before and t[3].after == t[3].before
    assert dict(t[4].after) == {0x10: 1, 0x11: 2, 0x12: 9, 0x50: 8}
    assert dict(t[5].after) == {0x10: 1, 0x11: 20, 0x12: 30, 0x50: 8}
    assert t[6].after == t[6].before and t[7].after == t[7].before
    assert [(row["tid"], row["address"], row["old"], row["new"]) for row in timeline] == [
        (1, 0x10, 0, 1), (1, 0x11, None, 2), (1, 0x12, None, 3), (4, 0x12, 3, 9), (5, 0x11, 2, 20), (5, 0x12, 9, 30)]

    txns, _ = paired(wire, "immediate")
    mr.replay(txns, fc03_refresh=False)
    assert dict(by_tid(txns)[5].after) == {0x12: 30, 0x11: 20}       # reads ignored on request


# ---- expressions, templates, encodings -------------------------------------------------------------

@pytest.mark.parametrize("text, names, value", [
    ("p * g // 1000", {"p": 80, "g": 500}, 40),
    ("7 // 2 + 7 % 4 - -1", {}, 7),
    ("998 * 1065 * abs(v - prev_v)", {"v": 565, "prev_v": 2263}, 1804753260),
    ("a == 1 and r < 37558 and q > 9000 * 100000", {"a": 1, "r": 5000, "q": 900000001}, 1),
    ("a == 1 and r < 37558 and q > 9000 * 100000", {"a": 1, "r": 5000, "q": 900000000}, 0),
    ("not (x == 1 and y == 1)", {"x": 1, "y": 0}, 1),
    ("not (x == 1 and y == 1)", {"x": 1, "y": 1}, 0),
    ("x == 0 or y == 0", {"x": 1, "y": 1}, 0),
    ("0 <= x < 10", {"x": 10}, 0),
    ("0 <= x < 10", {"x": 9}, 1),
    ("x != y", {"x": 3, "y": 3}, 0),
    ("x >= y", {"x": 3, "y": 3}, 1),
    ("x > y", {"x": 3, "y": 3}, 0),
    ("x <= 2", {"x": 3}, 0),
    ("(x << 4 | 3) ^ 1", {"x": 2}, 34),
    ("x >> 1 & 6", {"x": 13}, 6),
    ("min(x, 4) + max(x, 4)", {"x": 9}, 13),
    ("5 if x else 6", {"x": 0}, 6),
    ("True + (x == 2)", {"x": 2}, 2),
    ("+x - 1", {"x": 3}, 2),
])
def test_expressions_evaluate_as_integers(text, names, value):
    assert mr.Expr(text, "t").eval(names) == value


@pytest.mark.parametrize("text, hint", [
    ("p / 2", "use '//'"), ("__import__('os')", "abs(), min() and max()"), ("x.real", "Attribute"),
    ("x[0]", "Subscript"), ("'a'", "Constant"), ("1.5 * x", "Constant"), ("lambda: 1", "Lambda"),
    ("x ** 99", "Pow"), ("x in (1, 2)", "comparisons"), ("abs(x=1)", "abs(), min() and max()"),
    ("(", "not an expression"), ("", "non-empty"), ("[x for x in y]", "ListComp"), ("x := 1", "not an expression"),
])
def test_expressions_refuse_everything_else(text, hint):
    with pytest.raises(mr.ReplayError) as err:
        mr.Expr(text, "select.when")
    assert err.value.reason == "spec" and hint in err.value.detail and "select.when" in err.value.detail


def test_expression_runtime_errors_are_named():
    for text, names, reason in (("x + y", {"x": 1}, "undefined-name"), ("x // y", {"x": 1, "y": 0}, "expression"),
                                ("x % y", {"x": 1, "y": 0}, "expression"), ("1 << x", {"x": 99999}, "expression"),
                                ("x * x", {"x": 1 << 3000}, "expression")):
        with pytest.raises(mr.ReplayError) as err:
            mr.Expr(text, "t").eval(names)
        assert err.value.reason == reason, text
    assert mr.Expr("a + prev_b", "t").names == {"a", "prev_b"}


def test_templates_render_fields_and_refuse_stray_braces():
    line = mr.Template("i={i};tid={tid:04X};low={tid:x};w={v:6d};z={v:03d};{{lit}}", "output.row")
    assert line.render({"i": 0, "tid": 0x0A1F, "v": 42}) == "i=0;tid=0A1F;low=a1f;w=    42;z=042;{lit}"
    assert line.names == {"i", "tid", "v"}
    for bad in ("x={", "x=}", "{a.b}", "{a!r}", "{a:>4}", "{0}"):
        with pytest.raises(mr.ReplayError) as err:
            mr.Template(bad, "output.row")
        assert err.value.reason == "spec"
    for bad, hint in (("{a:s}", "field format 's'"), ("{a:4}", "field format '4'"), ("{a:0x}", None),
                      ("{a:065d}", "field width 65"), ("{a:0999999999d}", "field width 999999999"),
                      ("{a:dz}", "field format 'dz'"), ("{a:04Xfoo}", "field format '04Xfoo'")):  # whole format
        if hint is None:                                             # zero fill with no width is still a format
            assert mr.Template(bad, "output.row").render({"a": 10}) == "a"
            continue
        with pytest.raises(mr.ReplayError) as err:
            mr.Template(bad, "output.row")
        assert err.value.reason == "spec" and hint in err.value.detail, bad
    assert mr.Template("{a:064X}", "output.row").render({"a": 255}) == "0" * 62 + "FF"
    with pytest.raises(mr.ReplayError) as err:
        mr.Template("{missing}", "output.footer[0]").render({})
    assert err.value.reason == "undefined-name" and "output.footer[0]" in err.value.detail


@pytest.mark.parametrize("encoding, blob, text", [
    ("hex", b"\x00\xff\x1a", "00ff1a"), ("hex-upper", b"\x00\xff\x1a", "00FF1A"),
    ("base32", b"hello!", "NBSWY3DPEE======"), ("base32-nopad", b"hello!", "NBSWY3DPEE"),
    ("base64", b"\xfb\xff", "+/8="), ("base64-nopad", b"\xfb\xff", "+/8"),
    ("base64url", b"\xfb\xff", "-_8="), ("base64url-nopad", b"\xfb\xff", "-_8"),
])
def test_encodings(encoding, blob, text):
    assert mr.encode(blob, encoding) == text
    assert encoding in mr.ENCODINGS


# ---- 4. spec validation ----------------------------------------------------------------------------

def _raw_report():
    return {
        "schema": 1,
        "select": {"readback": {"start": 0x2000, "quantity": 2, "fields": ["p", "g"]}},
        "rows": {"initial": {"p": 1, "g": 2}, "derive": [{"name": "e", "expr": "p * g"}]},
        "output": {"kind": "report", "row": "{i};{p};{g};{e}", "footer": ["m={mask:02X}"],
                   "aggregate": [{"name": "mask", "kind": "bitmask", "expr": "e > 2", "width": 8}]},
        "vector": [{"rows": [{"p": 2, "g": 3}], "expect": "x"}],
    }


def test_a_full_spec_parses_with_its_defaults():
    spec = mr.parse_spec(_raw_report(), "mem")
    assert spec.pairing == "pending" and spec.scope == mr.Scope() and spec.select.function == 16
    assert spec.select.state == "before" and spec.select.order == "response" and spec.fc03_refresh is True
    assert spec.select.readback == mr.Readback(function=3, start=0x2000, quantity=2, fields=("p", "g"))
    assert spec.output.hash == "sha256" and spec.output.encoding == "hex" and spec.output.wrap == "event"
    assert spec.output.digest_bytes == 0 and spec.output.newline == "\n" and spec.output.final_newline is False
    assert spec.unknown is None and spec.allow_damaged is False and spec.capture_file is None
    assert spec.vectors[0].name == "vector 1" and spec.source == "mem"


def _broken(change):
    raw = _raw_report()
    change(raw)
    return raw


@pytest.mark.parametrize("change, hint", [
    (lambda r: r.update(schema=2), "schema must be 1"),
    (lambda r: r.update(extra=1), "unknown key(s) extra"),
    (lambda r: r.pop("output"), "[output] is missing"),
    (lambda r: r["output"].update(kind="pdf"), "output.kind"),
    (lambda r: r["output"].update(hash="crc32"), "output.hash"),
    (lambda r: r["output"].update(encoding="base58"), "output.encoding"),
    (lambda r: r["output"].update(wrap="FLAG"), "output.wrap"),
    (lambda r: r["output"].update(digest_bytes=-1), "output.digest_bytes"),
    (lambda r: r["output"].update(newline="cr"), "output.newline"),
    (lambda r: r["output"].update(final_newline="no"), "output.final_newline"),
    (lambda r: r["output"].update(parts=["request_pdu"]), "unknown key(s) parts"),
    (lambda r: r["output"].update(row="{i"), "stray brace"),
    (lambda r: r["output"]["aggregate"][0].update(kind="median"), "aggregate[0].kind"),
    (lambda r: r["output"]["aggregate"][0].update(name="p"), "used twice"),
    (lambda r: r["output"]["aggregate"][0].update(first="middle"), "aggregate[0].first"),
    (lambda r: r["output"]["aggregate"][0].pop("expr"), "aggregate[0].expr"),
    (lambda r: r.update(pairing={"mode": "fifo"}), "pairing.mode"),
    (lambda r: r.update(scope={"unit": 300}), "scope.unit"),
    (lambda r: r.update(scope={"unit": True}), "scope.unit"),
    (lambda r: r.update(scope={"server_port": 0}), "scope.server_port"),
    (lambda r: r["output"].update(digest_bytes=65), "output.digest_bytes"),
    (lambda r: r["output"]["aggregate"][0].update(width=0), "aggregate[0].width"),
    (lambda r: r["select"]["readback"].update(quantity=126), "select.readback.quantity"),
    (lambda r: r.update(scope={"port": 502}), "unknown key(s) port"),
    (lambda r: r.update(scope={"client": 5}), "scope.client"),
    (lambda r: r.update(registers={"tid": 1}), "reserved name"),
    (lambda r: r.update(registers={"prev_x": 1}), "reserved name"),
    (lambda r: r.update(registers={"w0": 1}), "reserved name"),
    (lambda r: r.update(registers={"a-b": 1}), "not a name"),
    (lambda r: r.update(registers={"p": 1}), "used twice"),
    (lambda r: r.update(registers={"x": 70000}), "registers.x"),
    (lambda r: r.update(replay={"initial": {"nope": 1}}), "not a name in [registers]"),
    (lambda r: r.update(replay={"unknown": "zero"}), "replay.unknown"),
    (lambda r: r.update(replay={"fc03_refresh": 1}), "replay.fc03_refresh"),
    (lambda r: r["select"].update(function=3), "select.function must be 6 or 16"),
    (lambda r: r["select"].update(state="during"), "select.state"),
    (lambda r: r["select"].update(order="random"), "select.order"),
    (lambda r: r["select"].update(window=[5, 1]), "select.window"),
    (lambda r: r["select"].update(start=[]), "select.start"),
    (lambda r: r["select"].update(when="p / g"), "select.when"),
    (lambda r: r["select"]["readback"].update(fields=["p"]), "select.readback.fields"),
    (lambda r: r["select"]["readback"].update(function=16), "select.readback.function"),
    (lambda r: r["rows"]["derive"].append({"name": "e", "expr": "1"}), "used twice"),
    (lambda r: r["rows"].update(check=[{"expr": "import os"}]), "rows.check[0].expr"),
    (lambda r: r["rows"].update(initial={"p": -1}), "rows.initial.p"),
    (lambda r: r.update(expect={"flags": 1}), "unknown key(s) flags"),
    (lambda r: r.update(expect={"rows": "many"}), "expect.rows"),
    (lambda r: r.update(capture={"allow_damaged": "yes"}), "capture.allow_damaged"),
    (lambda r: r.update(vector={"rows": []}), "[[vector]] must be an array"),
    (lambda r: r["vector"][0].update(rows=[]), "vector[0].rows"),
    (lambda r: r["vector"][0].pop("expect"), "does not test the hash or encoding"),
    (lambda r: r["vector"][0].update(expect=5), "vector[0].expect"),
    (lambda r: r["vector"][0].update(expect_rows=[]), "vector[0].expect_rows"),
    (lambda r: r["vector"][0].update(rows=[{"p": "2"}]), "vector[0].rows[0].p"),
])
def test_spec_problems_are_named(change, hint):
    with pytest.raises(mr.ReplayError) as err:
        mr.parse_spec(_broken(change))
    assert err.value.reason == "spec" and hint in err.value.detail


def test_witness_spec_rules():
    base = {"kind": "witness", "parts": ["request_pdu"]}
    for output, hint in (
        ({**base, "parts": []}, "output.parts"), ({**base, "parts": ["frame"]}, "output.parts"),
        ({**base, "prefix_hex": "zz"}, "output.prefix_hex"), ({**base, "prefix_hex": "00", "prefix_text": "A"}, "not both"),
        ({**base, "row": "x"}, "unknown key(s) row"),
    ):
        with pytest.raises(mr.ReplayError) as err:
            mr.parse_spec({"schema": 1, "output": output})
        assert hint in err.value.detail
    spec = mr.parse_spec({"schema": 1, "output": {**base, "prefix_text": "AB\u0000"},
                          "vector": [{"name": "v", "rows": [{"request_pdu": "10 00:13,00 01"}], "expect_digest": "AB CD"}]})
    assert spec.output.prefix == b"AB\x00"
    assert spec.vectors[0].rows[0]["_parts"] == {"request_pdu": bytes.fromhex("1000130001")}
    assert spec.vectors[0].expect_digest == "abcd"
    for vector, hint in (({"rows": [{"response_pdu": "00"}], "expect": "x"}, "unknown key(s) response_pdu"),
                         ({"rows": [{}], "expect": "x"}, "lacks request_pdu"),
                         ({"rows": [{"request_pdu": "0g"}], "expect": "x"}, "is not hex"),
                         ({"rows": [{"request_pdu": "00"}], "expect": "x", "expect_text": "t"}, "expect_text is for a report")):
        with pytest.raises(mr.ReplayError) as err:
            mr.parse_spec({"schema": 1, "output": base, "vector": [vector]})
        assert hint in err.value.detail


def test_load_spec_names_an_unreadable_or_invalid_file(tmp_path):
    with pytest.raises(mr.ReplayError) as err:
        mr.load_spec(tmp_path / "missing.toml")
    assert err.value.reason == "spec" and "cannot read" in err.value.detail
    bad = tmp_path / "bad.toml"
    bad.write_text("schema = \n")
    with pytest.raises(mr.ReplayError) as err:
        mr.load_spec(bad)
    assert "not valid TOML" in err.value.detail


# ---- the witness family ----------------------------------------------------------------------------

PREFIX = b"SYNTH-WITNESS/2\x00"
WITNESS_SPEC = """
schema = 1
[scope]
unit = 1
[pairing]
mode = "MODE"
[registers]
permit = 0x0020
isolated = 0x0021
[select]
function = 16
start = [0x0030, 0x0031]
quantity = [1]
when = "not (permit == 1 and isolated == 1)"
order = "ORDER"
[expect]
ineligible = 3
[output]
kind = "witness"
prefix_text = "SYNTH-WITNESS/2\\u0000"
parts = ["request_pdu", "response_pdu"]
hash = "sha256"
encoding = "hex"
wrap = "event"
[[vector]]
name = "handout"
rows = [{ request_pdu = "10 00 30 00 01 02 00 2a", response_pdu = "10 00 30 00 01" }]
expect = "VECTOR"
"""
VECTOR_T = bytes.fromhex("100030000102002a") + bytes.fromhex("1000300001")
VECTOR_W = hashlib.sha256(PREFIX + VECTOR_T).hexdigest()


def witness_spec(mode="immediate", order="response", vector=VECTOR_W, text=WITNESS_SPEC) -> str:
    return text.replace("MODE", mode).replace("ORDER", order).replace("VECTOR", vector)


def witness_wire() -> tuple[Wire, bytes]:
    """A sequential interlock capture and the T the policy selects from it (built from the test's PDUs)."""
    wire = Wire()
    wire.read(1, 0x20, [1, 0])                       # permit 1, isolated 0
    wire.write(2, 0x30, [7])                         # target, unsafe: isolated is 0
    wire.write(3, 0x21, [1])                         # prerequisite write (ineligible); isolated becomes 1
    wire.write(4, 0x31, [9])                         # target, safe
    wire.write(5, 0x20, [0])                         # prerequisite write (ineligible); permit becomes 0
    wire.write(6, 0x30, [8])                         # target, unsafe: permit is 0
    wire.req(7, fc16(0x31, [5]))
    wire.rsp(7, exc(0x10, 2))                        # a refused target: not accepted
    wire.write(8, 0x30, [1, 2])                      # accepted, quantity 2: ineligible
    wire.read(9, 0x20, [1, 1])                       # an observation restores permit
    wire.write(10, 0x30, [3])                        # target, safe
    wire.req(11, fc16(0x31, [4]))                    # never answered
    t = fc16(0x30, [7]) + fc16_ok(0x30, 1) + fc16(0x30, [8]) + fc16_ok(0x30, 1)
    return wire, t


def test_witness_selects_unsafe_targets_and_hashes_prefix_and_pdus(tmp_path):
    wire, t = witness_wire()
    assert t == bytes.fromhex("10003000010200071000300001" "10003000010200081000300001")
    spec_file = tmp_path / "spec.toml"
    spec_file.write_text(witness_spec())
    out = mr.run_spec(mr.load_spec(spec_file), wire.pcapng(), PROFILE)
    assert out.refusals == [] and out.emitted
    assert out.counts == {"adus": 21, "transactions": 11, "accepted": 9, "exceptions": 1, "unanswered": 1,
                          "rejected": 0, "writes": 7, "targets": 4, "ineligible": 3, "discarded": 0,
                          "unselected": 2, "rows": 2}
    assert [(row["tid"], row["i"], row["permit"], row["isolated"], row["w0"]) for row in out.rows] == [
        (2, 0, 1, 0, 7), (6, 1, 0, 1, 8)]
    assert out.built.material == PREFIX + t
    want = hashlib.sha256(PREFIX + t).hexdigest()
    assert out.built.value == want and out.built.digest == want and out.flag == f"CSCTF{{{want}}}"
    assert out.vectors == [{"name": "handout", "passed": True, "problems": [],
                            "covers": ["encoding", "hash", "serialisation"]}]
    assert out.selection_checked is True


def test_the_state_just_before_the_response_decides_and_rows_follow_response_order():
    """Interleaved traffic (pending rule): a prerequisite write still on the wire has not taken effect
    when the target's response arrives; one already acknowledged has."""
    wire = Wire()
    wire.read(1, 0x20, [1, 1])
    wire.req(2, fc16(0x20, [0]))                     # permit := 0 requested ...
    wire.req(3, fc16(0x30, [5]))                     # target A requested
    wire.rsp(3, fc16_ok(0x30, 1))                    # A acknowledged while permit is still 1: safe
    wire.rsp(2, fc16_ok(0x20, 1))                    # ... permit is 0 from here
    wire.req(4, fc16(0x30, [6]))                     # target B requested first
    wire.req(5, fc16(0x31, [7]))                     # target C requested second
    wire.rsp(5, fc16_ok(0x31, 1))                    # C acknowledged first
    wire.rsp(4, fc16_ok(0x30, 1))                    # B acknowledged second
    b = fc16(0x30, [6]) + fc16_ok(0x30, 1)
    c = fc16(0x31, [7]) + fc16_ok(0x31, 1)
    spec = mr.parse_spec(tomllib.loads(witness_spec("pending").replace("ineligible = 3", "ineligible = 1")))
    out = mr.run_spec(spec, wire.pcapng(), PROFILE)
    assert [row["tid"] for row in out.rows] == [5, 4] and out.counts["unselected"] == 1
    assert out.built.material == PREFIX + c + b      # normal-response order
    by_request = mr.parse_spec(tomllib.loads(
        witness_spec("pending", order="request").replace("ineligible = 3", "ineligible = 1")))
    out = mr.run_spec(by_request, wire.pcapng(), PROFILE)
    assert [row["tid"] for row in out.rows] == [4, 5] and out.built.material == PREFIX + b + c
    after = tomllib.loads(witness_spec("pending").replace("ineligible = 3", "ineligible = 1"))
    after["select"]["state"] = "after"               # a target write never changes a prerequisite word
    after["select"]["start"] = [0x20]                # ... so judge the permit write itself, after it lands
    after["expect"] = {"targets": 1}
    out = mr.run_spec(mr.parse_spec(after), wire.pcapng(), PROFILE)
    assert [(row["tid"], row["permit"]) for row in out.rows] == [(2, 0)]
    after["select"]["state"] = "before"
    out = mr.run_spec(mr.parse_spec(after), wire.pcapng(), PROFILE)
    assert out.rows == [] and out.counts["unselected"] == 1          # before its own response permit was 1


@pytest.mark.parametrize("parts, hash_name, digest_bytes, encoding", [
    (["request_pdu", "response_pdu"], "sha256", 0, "hex"),
    (["response_pdu", "request_pdu"], "sha1", 0, "hex-upper"),
    (["request_adu"], "sha512", 24, "base32-nopad"),
    (["response_adu", "request_data"], "md5", 0, "base64"),
    (["response_data"], "none", 0, "hex"),
    (["request_pdu"], "sha3_256", 5, "base64url-nopad"),
])
def test_witness_parts_hash_truncation_and_encoding(parts, hash_name, digest_bytes, encoding):
    wire = Wire(unit=3)
    wire.write(0x0102, 0x30, [7])
    wire.write(0x0103, 0x31, [8, 9])
    pieces = {
        0x0102: {"request_pdu": fc16(0x30, [7]), "response_pdu": fc16_ok(0x30, 1),
                 "request_adu": mbap(0x0102, fc16(0x30, [7]), 3), "response_adu": mbap(0x0102, fc16_ok(0x30, 1), 3),
                 "request_data": fc16(0x30, [7])[1:], "response_data": fc16_ok(0x30, 1)[1:]},
        0x0103: {"request_pdu": fc16(0x31, [8, 9]), "response_pdu": fc16_ok(0x31, 2),
                 "request_adu": mbap(0x0103, fc16(0x31, [8, 9]), 3), "response_adu": mbap(0x0103, fc16_ok(0x31, 2), 3),
                 "request_data": fc16(0x31, [8, 9])[1:], "response_data": fc16_ok(0x31, 2)[1:]},
    }
    material = b"\xaa\x55" + b"".join(pieces[tid][part] for tid in (0x0102, 0x0103) for part in parts)
    digest = material if hash_name == "none" else hashlib.new(hash_name, material).digest()
    cut = digest[:digest_bytes] if digest_bytes else digest
    want = {"hex": cut.hex(), "hex-upper": cut.hex().upper(),
            "base32-nopad": base64.b32encode(cut).decode().rstrip("="), "base64": base64.b64encode(cut).decode(),
            "base64url-nopad": base64.urlsafe_b64encode(cut).decode().rstrip("=")}[encoding]
    vector_row = {part: pieces[0x0102][part].hex() for part in parts}
    vector_material = b"\xaa\x55" + b"".join(pieces[0x0102][part] for part in parts)
    vector_digest = vector_material if hash_name == "none" else hashlib.new(hash_name, vector_material).digest()
    spec = spec_of(output={"kind": "witness", "prefix_hex": "aa 55", "parts": parts, "hash": hash_name,
                           "digest_bytes": digest_bytes, "encoding": encoding, "wrap": "W<{}>"},
                   vector=[{"rows": [vector_row], "expect_digest": vector_digest.hex()}])
    out = mr.run_spec(spec, wire.pcapng(), PROFILE)
    assert out.refusals == []
    assert out.built.material == material and out.built.value == want and out.flag == f"W<{want}>"
    assert out.built.digest == digest.hex()


def test_the_window_bounds_both_ends_of_a_write():
    wire = Wire()
    for tid, start, values in ((1, 0x1FFF, [1]), (2, 0x2000, [1]), (3, 0x2002, [1]), (4, 0x2003, [1]),
                               (5, 0x1FFF, [1, 1]), (6, 0x2001, [1, 1]), (7, 0x2001, [1, 1, 1])):
        wire.write(tid, start, values)
    vector = [{"rows": [{"request_pdu": "00", "response_pdu": "00"}],
               "expect_digest": hashlib.sha256(b"\xaa\x55\x00\x00").hexdigest()}]
    out = mr.run_spec(spec_of(select={"window": [0x2000, 0x2002]}, vector=vector), wire.pcapng(), PROFILE)
    assert [row["tid"] for row in out.rows] == [2, 3, 6] and out.counts["ineligible"] == 4
    out = mr.run_spec(spec_of(select={"start": [0x2001], "quantity": [2, 3]}, vector=vector), wire.pcapng(), PROFILE)
    assert [row["tid"] for row in out.rows] == [6, 7]
    out = mr.run_spec(spec_of(vector=vector), wire.pcapng(), PROFILE)        # no filter: every accepted write
    assert [row["tid"] for row in out.rows] == [1, 2, 3, 4, 5, 6, 7] and out.emitted


def test_fc06_writes_can_be_the_targets():
    wire = Wire()
    wire.req(1, fc06(0x30, 7))
    wire.rsp(1, fc06(0x30, 7))
    wire.write(2, 0x30, [8])                         # FC16: not this spec's function
    wire.req(3, fc06(0x31, 9))
    wire.rsp(3, fc06(0x31, 9))
    material = b"\xaa\x55" + fc06(0x30, 7) * 2 + fc06(0x31, 9) * 2
    vector = [{"rows": [{"request_pdu": "00", "response_pdu": "00"}],
               "expect_digest": hashlib.sha256(b"\xaa\x55\x00\x00").hexdigest()}]
    out = mr.run_spec(spec_of(select={"function": 6}, vector=vector), wire.pcapng(), PROFILE)
    assert [(row["tid"], row["w0"]) for row in out.rows] == [(1, 7), (3, 9)]
    assert out.built.material == material and out.built.value == hashlib.sha256(material).hexdigest()


def test_digest_bytes_longer_than_the_digest_is_refused():
    wire = Wire()
    wire.write(1, 0x30, [7])
    spec = spec_of(output={"kind": "witness", "parts": ["request_pdu"], "hash": "md5", "digest_bytes": 20},
                   vector=[{"rows": [{"request_pdu": "00"}], "expect": "x"}])
    out = mr.run_spec(spec, wire.pcapng(), PROFILE)
    assert not out.emitted and "digest_bytes 20 is more than the 16-byte digest" in out.refusals[0]


# ---- the known-answer gate -------------------------------------------------------------------------

def test_nothing_is_emitted_without_a_vector_or_when_one_does_not_reproduce():
    wire, _ = witness_wire()
    raw = tomllib.loads(witness_spec())
    no_vector = dict(raw)
    del no_vector["vector"]
    out = mr.run_spec(mr.parse_spec(no_vector), wire.pcapng(), PROFILE)
    assert out.built is None and out.flag is None and not out.emitted
    assert len(out.refusals) == 1 and out.refusals[0].startswith("no-test-vector")

    wrong_expect = tomllib.loads(witness_spec(vector="00" * 32))
    out = mr.run_spec(mr.parse_spec(wrong_expect), wire.pcapng(), PROFILE)
    assert out.built is None and out.flag is None
    assert out.refusals[0].startswith("vector-mismatch: handout: value differs: expected " + "00" * 32)
    assert VECTOR_W in out.refusals[0]               # what the recipe gave for the vector, never the capture's value
    assert out.vectors[0]["passed"] is False

    # The vector is right and the recipe in the spec is wrong (prefix, part order, hash, encoding): refused.
    for change in (lambda o: o.update(prefix_text="SYNTH-WITNESS/3\u0000"),
                   lambda o: o.update(parts=["response_pdu", "request_pdu"]),
                   lambda o: o.update(hash="sha1"),
                   lambda o: o.update(encoding="hex-upper"),
                   lambda o: o.update(digest_bytes=16)):
        broken = tomllib.loads(witness_spec())
        change(broken["output"])
        out = mr.run_spec(mr.parse_spec(broken), wire.pcapng(), PROFILE)
        assert out.built is None and out.refusals[0].startswith("vector-mismatch"), broken["output"]

    two = tomllib.loads(witness_spec())
    two["vector"].append({"name": "second", "rows": two["vector"][0]["rows"], "expect_digest": "ff" * 32})
    out = mr.run_spec(mr.parse_spec(two), wire.pcapng(), PROFILE)      # every vector must pass
    assert out.built is None and "second: digest differs" in out.refusals[0] and "handout:" not in out.refusals[0]
    assert [row["passed"] for row in out.vectors] == [True, False]


def test_a_failed_count_expectation_refuses_even_with_a_good_vector():
    wire, _ = witness_wire()
    raw = tomllib.loads(witness_spec())
    raw["expect"] = {"ineligible": 8, "rows": 2, "exceptions": 1}
    out = mr.run_spec(mr.parse_spec(raw), wire.pcapng(), PROFILE)
    assert out.built is None and out.refusals == ["expect.ineligible = 8, the capture gives 3"]
    raw["expect"] = {"ineligible": 3, "rows": 2, "exceptions": 1, "unanswered": 1, "targets": 4}
    assert mr.run_spec(mr.parse_spec(raw), wire.pcapng(), PROFILE).emitted


def test_an_unobserved_policy_register_is_an_error_unless_the_spec_says_what_to_assume():
    wire = Wire()
    wire.write(1, 0x30, [7])                         # the first target comes before any observation
    wire.read(2, 0x20, [1, 1])
    wire.write(3, 0x30, [8])
    raw = tomllib.loads(witness_spec())
    raw["expect"] = {"targets": 2}
    with pytest.raises(mr.ReplayError) as err:
        mr.run_spec(mr.parse_spec(raw), wire.pcapng(), PROFILE)
    assert err.value.reason == "register-unknown" and "isolated, permit" in err.value.detail
    raw["replay"] = {"unknown": 0}
    out = mr.run_spec(mr.parse_spec(raw), wire.pcapng(), PROFILE)
    assert [row["tid"] for row in out.rows] == [1]
    raw["replay"] = {"initial": {"permit": 1, "isolated": 1}}
    out = mr.run_spec(mr.parse_spec(raw), wire.pcapng(), PROFILE)
    assert out.rows == [] and out.counts["unselected"] == 2


def test_a_damaged_conversation_is_refused_by_name_unless_allowed():
    wire, _ = witness_wire()
    wire.raw(True, mbap(12, fc16(0x30, [1])), seq=90000)             # a hole in the request stream
    raw = tomllib.loads(witness_spec())
    with pytest.raises(mr.ReplayError) as err:
        mr.run_spec(mr.parse_spec(raw), wire.pcapng(), PROFILE)
    assert err.value.reason == "capture-damaged" and "tcp-gap" in err.value.detail
    raw["capture"] = {"allow_damaged": True}
    out = mr.run_spec(mr.parse_spec(raw), wire.pcapng(), PROFILE)
    assert out.emitted and [f["kind"] for f in out.findings] == ["tcp-gap"]


# ---- the report family -----------------------------------------------------------------------------

REPORT_SPEC = """
schema = 1
[scope]
unit = 9
[pairing]
mode = "pending"
[select]
function = 16
quantity = [1, 2, 3]
window = [0x2000, 0x2002]
[select.readback]
function = 3
start = 0x2000
quantity = 3
fields = ["rate", "valve", "armed"]
[rows]
initial = { rate = 10, valve = 100, armed = 0 }
[[rows.derive]]
name = "flow"
expr = "rate * valve // 100"
[[rows.derive]]
name = "jump"
expr = "abs(flow - prev_flow)"
[[rows.derive]]
name = "unsafe"
expr = "armed == 1 and jump > 50"
[[rows.check]]
name = "armed"
expr = "armed == 1"
[expect]
rows = 3
exceptions = 2
[output]
kind = "report"
header = ["synth-reconciliation-v3", "initial;rate={init_rate};valve={init_valve};armed={init_armed};flow={init_flow}", "n={n}"]
row = "i={i};tid={tid:04X};rate={rate};valve={valve};armed={armed}"
footer = ["unsafe-mask={mask:04X};unsafe={count};sum={total}"]
hash = "sha256"
digest_bytes = 20
encoding = "base32-nopad"
wrap = "event"
[[output.aggregate]]
name = "mask"
kind = "bitmask"
expr = "unsafe"
width = 16
[[output.aggregate]]
name = "count"
kind = "count"
expr = "unsafe"
[[output.aggregate]]
name = "total"
kind = "sum"
expr = "jump"
[[vector]]
name = "public"
rows = [ { tid = 0x0101, rate = 80, valve = 100, armed = 1 }, { tid = 0x0102, rate = 80, valve = 100, armed = 0 } ]
expect_initial = { flow = 10 }
expect_rows = [ { flow = 80, jump = 70, unsafe = 1 }, { flow = 80, jump = 0, unsafe = 0 } ]
expect_text = "VTEXT"
expect_digest = "VDIGEST"
expect = "VVALUE"
"""
VECTOR_TEXT = "\n".join([
    "synth-reconciliation-v3", "initial;rate=10;valve=100;armed=0;flow=10", "n=2",
    "i=0;tid=0101;rate=80;valve=100;armed=1", "i=1;tid=0102;rate=80;valve=100;armed=0",
    "unsafe-mask=8000;unsafe=1;sum=70"])
VECTOR_DIGEST = hashlib.sha256(VECTOR_TEXT.encode()).digest()


def report_raw() -> dict:
    text = (REPORT_SPEC.replace("VTEXT", VECTOR_TEXT.replace("\n", "\\n")).replace("VDIGEST", VECTOR_DIGEST.hex())
            .replace("VVALUE", base64.b32encode(VECTOR_DIGEST[:20]).decode().rstrip("=")))
    return tomllib.loads(text)


def report_wire() -> Wire:
    wire = Wire(unit=9)
    wire.read(0x0001, 0x2000, [10, 100, 0])          # a harmless read before the interval
    wire.write(0x0A01, 0x2000, [80, 100, 1])
    wire.read(0x0B01, 0x2000, [80, 100, 1])          # confirmed: row 0
    wire.write(0x0A02, 0x2001, [50])
    wire.read(0x0B02, 0x2000, [80, 50, 1])           # confirmed: row 1
    wire.req(0x0A03, fc16(0x2000, [1, 1, 1]))
    wire.rsp(0x0A03, exc(0x10, 4))                   # exception: never a write
    wire.read(0x0B03, 0x2000, [80, 50, 1])
    wire.write(0x0A04, 0x2000, [20, 50, 1])
    wire.read(0x0C04, 0x2000, [20])                  # an intervening client ADU (another read) ...
    wire.read(0x0B04, 0x2000, [20, 50, 1])           # ... so this readback confirms nothing
    wire.write(0x0A05, 0x2002, [0])
    wire.req(0x0B05, fc03(0x2000, 3))
    wire.rsp(0x0B05, exc(0x03, 2))                   # the readback itself is refused: discarded
    wire.write(0x0A06, 0x2000, [100, 100, 1])
    wire.read(0x0B06, 0x2000, [100, 100, 1])         # confirmed: row 2
    wire.write(0x0A07, 0x2002, [1, 1])               # reaches 0x2003: outside the window, ineligible
    wire.read(0x0B07, 0x2000, [100, 100, 1])
    wire.req(0x0A08, fc16(0x2000, [5]))              # a final unanswered write
    return wire


REPORT_TEXT = "\n".join([
    "synth-reconciliation-v3", "initial;rate=10;valve=100;armed=0;flow=10", "n=3",
    "i=0;tid=0A01;rate=80;valve=100;armed=1",        # flow 80, jump 70: unsafe
    "i=1;tid=0A02;rate=80;valve=50;armed=1",         # flow 40, jump 40
    "i=2;tid=0A06;rate=100;valve=100;armed=1",       # flow 100, jump 60: unsafe
    "unsafe-mask=A000;unsafe=2;sum=170"])


def test_report_confirms_by_readback_derives_and_renders_the_canonical_text():
    out = mr.run_spec(mr.parse_spec(report_raw()), report_wire().pcapng(), PROFILE)
    assert out.refusals == []
    assert out.counts == {"adus": 33, "transactions": 17, "accepted": 14, "exceptions": 2, "unanswered": 1,
                          "rejected": 0, "writes": 6, "targets": 5, "ineligible": 1, "discarded": 2,
                          "unselected": 0, "rows": 3}
    assert [(d["tid"], d["reason"]) for d in out.discards] == [
        (0x0A04, "the next client ADU (tid 0x0C04) is not the readback FC03 start 0x2000 quantity 3"),
        (0x0A05, "the readback tid 0x0B05 was not confirmed (exception)")]
    assert [(r["tid"], r["rb_tid"], r["flow"], r["jump"], r["unsafe"], r["prev_flow"]) for r in out.rows] == [
        (0x0A01, 0x0B01, 80, 70, 1, 10), (0x0A02, 0x0B02, 40, 40, 0, 80), (0x0A06, 0x0B06, 100, 60, 1, 40)]
    assert out.built.text == REPORT_TEXT and out.built.material == REPORT_TEXT.encode()
    digest = hashlib.sha256(REPORT_TEXT.encode()).digest()
    want = base64.b32encode(digest[:20]).decode().rstrip("=")
    assert out.built.digest == digest.hex() and out.built.value == want and out.flag == f"CSCTF{{{want}}}"
    assert out.vectors == [{"name": "public", "passed": True, "problems": [],
                            "covers": ["derived columns", "encoding", "hash", "serialisation"]}]


def test_report_line_endings_bit_order_and_final_newline():
    raw = report_raw()
    raw["output"].update(newline="crlf", final_newline=True)
    raw["output"]["aggregate"][0]["first"] = "lsb"
    for key in ("expect_text", "expect_digest", "expect"):
        del raw["vector"][0][key]
    vector_text = VECTOR_TEXT.replace("unsafe-mask=8000", "unsafe-mask=0001").replace("\n", "\r\n") + "\r\n"
    raw["vector"][0]["expect_text"] = vector_text
    raw["vector"][0]["expect_digest"] = hashlib.sha256(vector_text.encode()).hexdigest()
    out = mr.run_spec(mr.parse_spec(raw), report_wire().pcapng(), PROFILE)
    assert out.refusals == []
    assert out.built.text == REPORT_TEXT.replace("unsafe-mask=A000", "unsafe-mask=0005").replace("\n", "\r\n") + "\r\n"


def test_a_false_row_check_or_a_wrong_vector_column_refuses_the_report():
    raw = report_raw()
    raw["rows"]["check"] = [{"name": "slow", "expr": "jump < 65"}]
    out = mr.run_spec(mr.parse_spec(raw), report_wire().pcapng(), PROFILE)
    assert out.built is None
    assert out.refusals == ["row 0 (tid 0x0A01): check 'slow' is false: jump < 65"]

    raw = report_raw()
    raw["rows"]["derive"][0]["expr"] = "rate * valve // 10"          # a wrong screen formula
    out = mr.run_spec(mr.parse_spec(raw), report_wire().pcapng(), PROFILE)
    assert out.built is None and out.refusals[0].startswith("vector-mismatch: public: initial flow: expected 10, got 100")
    assert "row 0 flow: expected 80, got 800" in out.refusals[0]

    raw = report_raw()
    raw["vector"][0]["rows"][1]["armed"] = 1                         # checks never run on a vector's rows ...
    raw["vector"][0]["expect_text"] = VECTOR_TEXT                    # ... but its text must still match
    out = mr.run_spec(mr.parse_spec(raw), report_wire().pcapng(), PROFILE)
    assert out.built is None and "public: text differs" in out.refusals[0]

    raw = report_raw()
    raw["rows"]["initial"] = {}                                      # no previous row for row 0
    del raw["vector"][0]["expect_initial"]
    raw["output"]["header"] = ["n={n}"]
    with pytest.raises(mr.ReplayError) as err:
        mr.run_spec(mr.parse_spec(raw), report_wire().pcapng(), PROFILE)
    assert err.value.reason == "undefined-name" and "prev_flow" in err.value.detail


def test_count_without_an_expression_counts_every_row():
    raw = report_raw()
    raw["output"]["aggregate"].append({"name": "everything", "kind": "count"})
    raw["output"]["footer"] = ["rows={everything};unsafe={count};jump={total}"]
    text = VECTOR_TEXT.replace("unsafe-mask=8000;unsafe=1;sum=70", "rows=2;unsafe=1;jump=70")
    raw["vector"][0].update(expect_text=text, expect_digest=hashlib.sha256(text.encode()).hexdigest())
    del raw["vector"][0]["expect"]
    out = mr.run_spec(mr.parse_spec(raw), report_wire().pcapng(), PROFILE)
    assert out.refusals == [] and out.built.text.splitlines()[-1] == "rows=3;unsafe=2;jump=170"


def test_row_lines_see_the_report_wide_names_and_an_initial_row_error_is_not_swallowed():
    raw = report_raw()
    raw["output"].update(header=[], footer=[], row="{i}/{n};init={init_flow};mask={mask:04X};flow={flow}")
    text = "0/2;init=10;mask=8000;flow=80\n1/2;init=10;mask=8000;flow=80"
    raw["vector"][0].update(expect_text=text, expect_digest=hashlib.sha256(text.encode()).hexdigest())
    del raw["vector"][0]["expect"]
    assert mr.run_vectors(mr.parse_spec(raw))[0]["problems"] == []

    raw["rows"]["derive"][0]["expr"] = "rate * valve // 100 + 0 // rate"     # fine on every row ...
    raw["rows"]["initial"]["rate"] = 0                                       # ... and a division by zero on the initial one
    results = mr.run_vectors(mr.parse_spec(raw))
    assert results[0]["passed"] is False and results[0]["problems"][0].startswith("expression: rows.derive[0].expr")
    with pytest.raises(mr.ReplayError) as err:
        mr.run_spec(mr.parse_spec(raw), report_wire().pcapng(), PROFILE)
    assert err.value.reason == "expression" and "division by zero" in err.value.detail


def test_a_vector_may_carry_its_own_initial_row():
    raw = report_raw()
    vector = raw["vector"][0]
    vector["initial"] = {"rate": 20, "valve": 100, "armed": 0}       # flow 20, so row 0 jumps 60
    vector["expect_initial"] = {"flow": 20}
    vector["expect_rows"] = [{"jump": 60, "unsafe": 1}, {"jump": 0}]
    text = VECTOR_TEXT.replace("initial;rate=10;valve=100;armed=0;flow=10", "initial;rate=20;valve=100;armed=0;flow=20") \
        .replace("sum=70", "sum=60")
    vector.update(expect_text=text, expect_digest=hashlib.sha256(text.encode()).hexdigest())
    del vector["expect"]
    out = mr.run_spec(mr.parse_spec(raw), report_wire().pcapng(), PROFILE)
    assert out.refusals == [] and out.built.text == REPORT_TEXT      # the capture rows keep [rows] initial


def test_one_readback_confirms_only_the_first_write_that_reaches_it():
    wire = Wire(unit=9)
    wire.req(1, fc16(0x2000, [1, 1, 1]))
    wire.req(2, fc16(0x2000, [2, 2, 1]))
    wire.rsp(1, fc16_ok(0x2000, 3))
    wire.rsp(2, fc16_ok(0x2000, 3))
    wire.read(3, 0x2000, [2, 2, 1])
    raw = report_raw()
    raw["expect"] = {"rows": 1}
    raw["rows"]["check"] = []
    out = mr.run_spec(mr.parse_spec(raw), wire.pcapng(), PROFILE)
    assert [row["tid"] for row in out.rows] == [1]
    assert out.discards == [{"tid": 2, "packet": 3, "reason": "the readback tid 0x0003 already confirms an earlier write"}]

    last = Wire(unit=9)
    last.write(1, 0x2000, [1, 1, 1])                                 # no client ADU follows
    out = mr.run_spec(mr.parse_spec({**raw, "expect": {"rows": 0}}), last.pcapng(), PROFILE)
    assert out.rows == [] and "no client ADU follows" in out.discards[0]["reason"]


def test_a_bitmask_narrower_than_the_rows_is_refused_by_name():
    raw = report_raw()
    raw["output"]["aggregate"][0]["width"] = 2                       # the two vector rows fit: bits 10 -> "0002"
    text = VECTOR_TEXT.replace("unsafe-mask=8000", "unsafe-mask=0002")
    raw["vector"][0].update(expect_text=text, expect_digest=hashlib.sha256(text.encode()).hexdigest())
    del raw["vector"][0]["expect"]
    assert [row["passed"] for row in mr.run_vectors(mr.parse_spec(raw))] == [True]
    with pytest.raises(mr.ReplayError) as err:                       # ... the capture's three rows do not
        mr.run_spec(mr.parse_spec(raw), report_wire().pcapng(), PROFILE)
    assert err.value.reason == "aggregate" and "bitmask 'mask' is 2 bits wide but there are 3 rows" in err.value.detail
    raw["vector"][0]["rows"] = raw["vector"][0]["rows"] + [{"tid": 3, "rate": 1, "valve": 1, "armed": 0}]
    raw["vector"][0]["expect_rows"] = raw["vector"][0]["expect_rows"] + [{}]
    out = mr.run_spec(mr.parse_spec(raw), report_wire().pcapng(), PROFILE)   # in a vector it shuts the gate
    assert out.built is None and "aggregate: bitmask 'mask' is 2 bits wide but there are 3 rows" in out.refusals[0]


# ---- 8. the engine contract ------------------------------------------------------------------------

def challenge(tmp_path, wire: Wire | None, spec: str | None = None, name="cap.pcapng") -> Path:
    folder = tmp_path / "9001-synthetic"
    (folder / "files").mkdir(parents=True)
    if wire is not None:
        (folder / "files" / name).write_bytes(wire.pcapng())
    if spec is not None:
        (folder / "modbus-replay.toml").write_text(spec)
    return folder


def test_solve_with_a_spec_is_solved_and_writes_the_hashed_material(tmp_path):
    wire, t = witness_wire()
    folder = challenge(tmp_path, wire, witness_spec())
    res = mr.solve(folder, PROFILE)
    want = hashlib.sha256(PREFIX + t).hexdigest()
    assert res.status == "solved" and res.flags == (f"CSCTF{{{want}}}",) and res.engine == "toolkits.modbus_replay"
    assert (folder / "recon" / "modbus_replay" / "witness.bin").read_bytes() == PREFIX + t
    assert [e.kind for e in res.evidence] == ["wire", "oracle", "decode"]
    assert res.evidence[0].path == "files/cap.pcapng" and "4 targets, 3 ineligible" in res.evidence[0].detail
    assert "handout (encoding/hash/serialisation)" in res.evidence[1].detail
    assert res.evidence[2].path == "recon/modbus_replay/witness.bin"
    report = json.loads((folder / "recon" / "modbus_replay" / "replay.json").read_text())
    assert report["emitted"] is True and report["flag"] == res.flags[0] and report["value"] == want
    assert report["counts"]["rows"] == 2 and [row["tid"] for row in report["rows"]] == [2, 6]
    assert not any(key.startswith(("prev_", "_")) for key in report["rows"][0])
    assert report["transactions"][1] == {
        "index": 1, "tid": 2, "unit": 1, "function": 16, "kind": "normal", "accepted": True, "reason": "",
        "start": 0x30, "quantity": 1, "words": [7], "request_packet": 2, "response_packet": 3,
        "request_pdu": "1000300001020007", "response_pdu": "1000300001"}
    assert report["timeline"][0] == {"ordinal": 1, "packet": 1, "tid": 1, "function": 3, "source": "read",
                                     "address": 0x20, "old": None, "new": 1}
    assert SolverResult.from_json(res.to_json()) == res


def test_solve_writes_the_report_text_for_a_report_spec(tmp_path):
    folder = tmp_path / "9002-recon"
    (folder / "files").mkdir(parents=True)
    (folder / "files" / "station.pcap").write_bytes(pcap(report_wire().frames))      # a classic pcap this time
    spec_text = (REPORT_SPEC.replace("VTEXT", VECTOR_TEXT.replace("\n", "\\n")).replace("VDIGEST", VECTOR_DIGEST.hex())
                 .replace("VVALUE", base64.b32encode(VECTOR_DIGEST[:20]).decode().rstrip("=")))
    (folder / "modbus-replay.toml").write_text(spec_text)
    res = mr.solve(folder, PROFILE)
    want = base64.b32encode(hashlib.sha256(REPORT_TEXT.encode()).digest()[:20]).decode().rstrip("=")
    assert res.status == "solved" and res.flags == (f"CSCTF{{{want}}}",)
    out = folder / "recon" / "modbus_replay"
    assert (out / "report.txt").read_bytes() == REPORT_TEXT.encode() and not (out / "witness.bin").exists()
    assert res.evidence[0].path == "files/station.pcap" and res.evidence[2].path == "recon/modbus_replay/report.txt"
    assert "base32-nopad of the first 20 bytes" in res.evidence[2].detail
    report = json.loads((out / "replay.json").read_text())
    assert [(d["tid"]) for d in report["discarded"]] == [0x0A04, 0x0A05] and report["counts"]["rows"] == 3


def test_solve_finds_the_spec_under_recon_and_follows_its_server_port(tmp_path):
    wire = Wire(sport=1502)                          # a controller on another port
    wire.read(1, 0x20, [1, 0])
    wire.write(2, 0x30, [7])                         # the one unsafe target
    wire.write(3, 0x21, [1])
    wire.write(4, 0x40, [1])
    wire.write(5, 0x41, [1])                         # three ineligible writes
    folder = challenge(tmp_path, wire)
    assert mr.solve(folder, PROFILE).status == "none"                # nothing on 502, and no spec says otherwise
    (folder / "recon").mkdir()
    (folder / "recon" / "modbus-replay.toml").write_text(
        witness_spec().replace("[scope]\nunit = 1", "[scope]\nunit = 1\nserver_port = 1502"))
    res = mr.solve(folder, PROFILE)
    material = PREFIX + fc16(0x30, [7]) + fc16_ok(0x30, 1)
    assert res.status == "solved" and res.flags == (f"CSCTF{{{hashlib.sha256(material).hexdigest()}}}",)
    (folder / "modbus-replay.toml").write_text("schema = 1\n")       # the challenge-root spec wins over recon/
    assert mr.solve(folder, PROFILE).status == "blocked"


def test_damage_in_another_conversation_does_not_refuse_the_scoped_one(tmp_path):
    wire, t = witness_wire()
    other = Wire(client="10.0.0.77", cport=41000)
    other.write(1, 0x30, [1])
    other.raw(True, mbap(2, fc16(0x30, [2])), seq=99000)             # a hole, but not in the scoped conversation
    raw = tomllib.loads(witness_spec())
    raw["scope"]["client"] = "10.0.0.5"
    out = mr.run_spec(mr.parse_spec(raw), pcapng(wire.frames + other.frames), PROFILE)
    assert out.emitted and out.findings == [] and out.built.material == PREFIX + t
    raw["scope"]["client"] = "10.0.0.77"
    with pytest.raises(mr.ReplayError) as err:
        mr.run_spec(mr.parse_spec(raw), pcapng(wire.frames + other.frames), PROFILE)
    assert err.value.reason == "capture-damaged"


def test_solve_uses_the_event_prefix_and_reports_a_foreign_wrapper_as_candidate(tmp_path):
    wire, t = witness_wire()
    want = hashlib.sha256(PREFIX + t).hexdigest()
    folder = challenge(tmp_path, wire, witness_spec())
    res = mr.solve(folder, _profile(prefixes=("ZZTOP",)))
    assert res.status == "solved" and res.flags == (f"ZZTOP{{{want}}}",)
    (folder / "modbus-replay.toml").write_text(witness_spec().replace('wrap = "event"', 'wrap = "OTHER{{}}"'))
    res = mr.solve(folder, PROFILE)
    assert res.status == "candidate" and res.flags == (f"OTHER{{{want}}}",)
    assert "not in the event's flag format" in res.notes
    (folder / "modbus-replay.toml").write_text(witness_spec().replace('wrap = "event"', 'wrap = "none"'))
    res = mr.solve(folder, PROFILE)
    assert res.status == "candidate" and res.flags == (want,)


def test_solve_without_a_stated_selection_check_is_only_a_candidate(tmp_path):
    wire, t = witness_wire()
    folder = challenge(tmp_path, wire, witness_spec().replace("[expect]\nineligible = 3\n", ""))
    res = mr.solve(folder, PROFILE)
    assert res.status == "candidate" and res.flags == (f"CSCTF{{{hashlib.sha256(PREFIX + t).hexdigest()}}}",)
    assert "no [expect] count" in res.notes


def test_a_row_check_alone_states_the_selection_and_solves(tmp_path):
    wire, t = witness_wire()
    check = '[[rows.check]]\nname = "unsafe"\nexpr = "not (permit == 1 and isolated == 1)"\n'
    folder = challenge(tmp_path, wire, witness_spec().replace("[expect]\nineligible = 3\n", check))
    res = mr.solve(folder, PROFILE)
    assert res.status == "solved" and res.flags == (f"CSCTF{{{hashlib.sha256(PREFIX + t).hexdigest()}}}",)
    assert "no [expect] count" not in res.notes


# The counts witness_wire() gives (test_witness_selects_unsafe_targets_and_hashes_prefix_and_pdus).
WITNESS_COUNTS = {"adus": 21, "transactions": 11, "accepted": 9, "exceptions": 1, "unanswered": 1, "rejected": 0,
                  "writes": 7, "targets": 4, "ineligible": 3, "discarded": 0, "unselected": 2, "rows": 2}


@pytest.mark.parametrize("key", sorted(WITNESS_COUNTS))
def test_only_a_count_of_the_selection_makes_it_checked(key):
    raw = tomllib.loads(witness_spec())
    raw["expect"] = {key: WITNESS_COUNTS[key]}                       # true, so nothing is refused either way
    out = mr.run_spec(mr.parse_spec(raw), witness_wire()[0].pcapng(), PROFILE)
    assert out.refusals == [] and out.emitted
    selection = key in ("targets", "ineligible", "discarded", "unselected", "rows")
    assert out.selection_checked is selection, key


def test_solve_with_only_a_capture_wide_count_is_still_a_candidate(tmp_path):
    wire, _ = witness_wire()
    folder = challenge(tmp_path, wire, witness_spec().replace("ineligible = 3", "adus = 21\ntransactions = 11"))
    res = mr.solve(folder, PROFILE)
    assert res.status == "candidate" and "no [expect] count of the selection" in res.notes


def test_wrap_event_needs_a_lead_that_opens_a_brace(monkeypatch):
    assert mr.wrap_value("v", "event", PROFILE) == "CSCTF{v}"
    assert mr.wrap_value("v", "pre[{}]", PROFILE) == "pre[v]" and mr.wrap_value("v", "none", PROFILE) == "v"

    class Lead:                                                      # a format whose lead is not PREFIX{
        def cribs(self):
            return ("flag-",)
    monkeypatch.setattr(mr, "_flag_format", lambda profile=None: Lead())
    with pytest.raises(mr.ReplayError) as err:
        mr.wrap_value("v", "event", PROFILE)
    assert err.value.reason == "wrap" and "'flag-'" in err.value.detail


def test_solve_refusal_emits_no_flag_and_removes_a_stale_output(tmp_path):
    wire, _ = witness_wire()
    folder = challenge(tmp_path, wire, witness_spec())
    assert mr.solve(folder, PROFILE).status == "solved"
    material = folder / "recon" / "modbus_replay" / "witness.bin"
    assert material.is_file()
    (folder / "modbus-replay.toml").write_text(witness_spec(vector="11" * 32))
    res = mr.solve(folder, PROFILE)
    assert res.status == "unsure" and res.flags == ()
    assert "nothing emitted: vector-mismatch: handout: value differs" in res.notes
    assert not material.exists()
    report = json.loads((folder / "recon" / "modbus_replay" / "replay.json").read_text())
    assert report["emitted"] is False and "flag" not in report and "value" not in report
    assert report["refusals"][0].startswith("vector-mismatch")
    capture_value = hashlib.sha256(PREFIX + witness_wire()[1]).hexdigest()
    assert capture_value not in res.to_json() and capture_value not in json.dumps(report)


def test_solve_without_a_spec_reports_the_mechanical_pass(tmp_path):
    wire, _ = witness_wire()
    folder = challenge(tmp_path, wire)
    res = mr.solve(folder, PROFILE)
    assert res.status == "unsure" and res.flags == ()
    assert len(res.evidence) == 1 and res.evidence[0].path == "files/cap.pcapng"
    assert ("11 transactions, 9 accepted {'fc03': 2, 'fc16': 7}, 1 exception(s), 1 unanswered, 0 rejected"
            in res.evidence[0].detail)
    assert "modbus_replay_templates" in res.notes and "modbus-replay.toml" in res.notes
    report = json.loads((folder / "recon" / "modbus_replay" / "replay.json").read_text())
    conv = report["captures"]["files/cap.pcapng"]["conversations"][0]
    assert conv["conversation"] == "10.0.0.5:40001 -> 10.0.0.9:502 (connection 0)" and conv["units"] == [1]
    assert conv["registers_seen"] == 4 and len(conv["transactions_list"]) == 11     # 0x20 0x21 0x30 0x31
    assert [(row["address"], row["new"]) for row in conv["timeline"]][:4] == [(0x20, 1), (0x21, 0), (0x30, 7), (0x21, 1)]


def test_solve_finds_nothing_without_modbus(tmp_path):
    folder = tmp_path / "empty"
    (folder / "files").mkdir(parents=True)
    (folder / "files" / "readme.txt").write_text("no capture here")
    res = mr.solve(folder, PROFILE)
    assert res.status == "none" and "no Modbus/TCP ADU on server port 502" in res.notes
    web = Wire(sport=80)
    web.raw(True, b"GET / HTTP/1.1\r\n\r\n")
    (folder / "files" / "web.pcapng").write_bytes(web.pcapng())
    res = mr.solve(folder, PROFILE)                                  # a readable capture with no Modbus: none
    assert res.status == "none" and "no Modbus/TCP ADU on server port 502" in res.notes
    assert mr.solve(tmp_path / "absent", PROFILE).status == "blocked"


@pytest.mark.parametrize("torn", [b"\x0a\x0d\x0d\x0a" + b"\x00" * 9, b"\x0a\x0d\x0d\x0a" + b"\xff" * 60],
                         ids=["truncated", "bad-byte-order-magic"])
def test_a_capture_that_will_not_parse_blocks_instead_of_none(tmp_path, torn):
    folder = tmp_path / "torn"
    (folder / "files").mkdir(parents=True)
    web = Wire(sport=80)
    web.raw(True, b"GET / HTTP/1.1\r\n\r\n")
    (folder / "files" / "web.pcapng").write_bytes(web.pcapng())
    (folder / "files" / "torn.pcapng").write_bytes(torn)
    res = mr.solve(folder, PROFILE)                                  # the torn file may hold the Modbus
    assert res.status == "blocked" and res.notes.startswith("unreadable-input"), res.notes
    assert "files/torn.pcapng (" in res.notes and "files/web.pcapng" not in res.notes


def test_a_decoy_capture_beside_an_encrypted_zip_still_blocks(tmp_path):
    wire, _ = witness_wire()
    folder = tmp_path / "decoy"
    (folder / "files").mkdir(parents=True)
    web = Wire(sport=80)
    web.raw(True, b"GET / HTTP/1.1\r\n\r\n")
    (folder / "files" / "decoy.pcapng").write_bytes(web.pcapng())    # read, parsed, but no Modbus
    (folder / "files" / "locked.zip").write_bytes(_encrypt_flag(_zip({"trace.pcapng": wire.pcapng()})))
    found, skipped = mr.find_captures(folder)
    assert [name for name, _ in found] == ["files/decoy.pcapng"] and len(skipped) == 1
    res = mr.solve(folder, PROFILE)
    assert res.status == "blocked" and res.notes.startswith("unreadable-input"), res.notes
    assert "files/locked.zip!trace.pcapng (an encrypted member" in res.notes


def test_a_capture_of_exactly_the_cap_is_read(tmp_path, monkeypatch):
    wire, _ = witness_wire()
    capture_bytes = wire.pcapng()
    folder = tmp_path / "cap"
    (folder / "files").mkdir(parents=True)
    (folder / "files" / "exact.pcapng").write_bytes(capture_bytes)
    (folder / "files" / "exact.zip").write_bytes(_zip({"inner.pcapng": capture_bytes + b"\x00"}))
    monkeypatch.setattr(mr._cap, "MAX_CAPTURE", len(capture_bytes))
    found, skipped = mr.find_captures(folder)
    assert [name for name, _ in found] == ["files/exact.pcapng"]     # len == cap: read
    assert [row.split(" (")[0] for row in skipped] == ["files/exact.zip!inner.pcapng"]   # cap + 1: not read
    monkeypatch.setattr(mr._cap, "MAX_CAPTURE", len(capture_bytes) + 1)
    found, skipped = mr.find_captures(folder)
    assert [name for name, _ in found] == ["files/exact.pcapng", "files/exact.zip!inner.pcapng"] and skipped == []


def test_solve_blocks_by_name_on_a_bad_spec_a_missing_spec_and_an_unclear_capture(tmp_path):
    wire, _ = witness_wire()
    folder = challenge(tmp_path, wire, "schema = 1\n")
    res = mr.solve(folder, PROFILE)
    assert res.status == "blocked" and res.notes.startswith("spec: [output] is missing")
    res = mr.solve(folder, PROFILE, spec="nowhere.toml")
    assert res.status == "blocked" and "cannot read" in res.notes and "nowhere.toml" in res.notes

    other = Wire(client="10.0.0.77")
    other.write(1, 0x30, [1])
    (folder / "files" / "other.pcapng").write_bytes(other.pcapng())
    (folder / "modbus-replay.toml").write_text(witness_spec())
    res = mr.solve(folder, PROFILE)
    assert res.status == "blocked" and res.notes.startswith("ambiguous-capture")
    assert "files/cap.pcapng" in res.notes and "files/other.pcapng" in res.notes
    for named in ("cap.pcapng", "files/cap.pcapng"):                 # by file name, or by its listed path
        (folder / "modbus-replay.toml").write_text(
            witness_spec().replace("schema = 1", f'schema = 1\n[capture]\nfile = "{named}"'))
        assert mr.solve(folder, PROFILE).status == "solved", named
    (folder / "modbus-replay.toml").write_text(witness_spec().replace("schema = 1", 'schema = 1\n[capture]\nfile = "pcapng"'))
    assert mr.solve(folder, PROFILE).notes.startswith("capture-missing")     # never a substring match
    (folder / "modbus-replay.toml").write_text(witness_spec().replace("schema = 1", 'schema = 1\n[capture]\nfile = "gone.pcapng"'))
    res = mr.solve(folder, PROFILE)
    assert res.status == "blocked" and res.notes.startswith("capture-missing")

    (folder / "modbus-replay.toml").write_text(witness_spec().replace("unit = 1", "unit = 44"))
    res = mr.solve(folder, PROFILE, spec="modbus-replay.toml")
    assert res.status == "blocked" and res.notes.startswith("ambiguous-capture")
    (folder / "files" / "other.pcapng").unlink()
    res = mr.solve(folder, PROFILE)
    assert res.status == "blocked" and res.notes.startswith("no-modbus: no ADU with unit 44")


def test_find_captures_reads_the_sweep_copy_zip_members_and_never_dot_ctf(tmp_path):
    wire, t = witness_wire()
    folder = tmp_path / "c"
    (folder / "files").mkdir(parents=True)
    with zipfile.ZipFile(folder / "files" / "handout.zip", "w") as archive:
        archive.writestr(zipfile.ZipInfo("deep/trace.pcapng", date_time=(2026, 1, 1, 0, 0, 0)), wire.pcapng())
        archive.writestr(zipfile.ZipInfo("policy.md", date_time=(2026, 1, 1, 0, 0, 0)), "prose")
    (folder / "files" / ".ctf").mkdir()
    (folder / "files" / ".ctf" / "secret.pcapng").write_bytes(Wire(client="10.1.1.1").pcapng() + b"x")
    (folder / "files" / "recon").mkdir()
    (folder / "files" / "recon" / "old.pcapng").write_bytes(pcapng([]))
    found, skipped = mr.find_captures(folder)
    assert [name for name, _ in found] == ["files/handout.zip!deep/trace.pcapng"] and skipped == []
    (folder / "modbus-replay.toml").write_text(witness_spec().replace(
        "schema = 1", 'schema = 1\n[capture]\nfile = "trace.pcapng"'))
    res = mr.solve(folder, PROFILE)
    assert res.status == "solved" and res.evidence[0].path == "files/handout.zip!deep/trace.pcapng"
    assert res.flags == (f"CSCTF{{{hashlib.sha256(PREFIX + t).hexdigest()}}}",)

    (folder / "unpacked" / "handout.zip.unpacked").mkdir(parents=True)   # after a sweep: its copy, no zip reading
    with zipfile.ZipFile(folder / "unpacked" / "handout.zip", "w") as archive:
        archive.writestr(zipfile.ZipInfo("inner.pcapng", date_time=(2026, 1, 1, 0, 0, 0)), Wire(client="10.2.2.2").pcapng())
    (folder / "unpacked" / "handout.zip.unpacked" / "trace.pcapng").write_bytes(wire.pcapng())
    (folder / "unpacked" / "copy.pcapng").write_bytes(wire.pcapng())                 # identical bytes: listed once
    found, skipped = mr.find_captures(folder)
    assert [name for name, _ in found] == ["unpacked/copy.pcapng"] and skipped == []
    with pytest.raises(FileNotFoundError):
        mr.find_captures(tmp_path / "nope")


def _encrypt_flag(blob: bytes) -> bytes:
    """Set the 'encrypted' bit (general purpose flag bit 0) on every local and central header of a zip
    the test wrote: what an encrypted handout looks like to a reader without the password."""
    out = bytearray(blob)
    for magic, flag_at in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        at = out.find(magic)
        while at != -1:
            out[at + flag_at] |= 0x1
            at = out.find(magic, at + 4)
    return bytes(out)


def _zip(members: dict[str, bytes]) -> bytes:
    import io
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:           # stored: member bytes sit verbatim in the zip
        for name, data in members.items():
            archive.writestr(zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0)), data)
    return buffer.getvalue()


def test_find_captures_names_what_it_could_not_read(tmp_path, monkeypatch):
    wire, t = witness_wire()
    capture_bytes = wire.pcapng()
    folder = tmp_path / "c"
    (folder / "files").mkdir(parents=True)
    files = folder / "files"
    (files / "a-locked.zip").write_bytes(_encrypt_flag(_zip({"trace.pcapng": capture_bytes})))
    (files / "b-broken.zip").write_bytes(b"PK\x03\x04" + b"\x00" * 40)
    torn = bytearray(_zip({"torn.pcapng": capture_bytes}))
    torn[torn.find(capture_bytes) + 40] ^= 0xFF                      # past the magic: the CRC check fails on read
    (files / "c-torn.zip").write_bytes(bytes(torn))
    outside = tmp_path / "elsewhere.pcapng"
    outside.write_bytes(capture_bytes)
    (files / "d-link.pcapng").symlink_to(outside)
    (files / "e-link.txt").symlink_to(outside)                       # not named like a capture: not listed
    found, skipped = mr.find_captures(folder)
    assert found == []
    assert [row.split(" (")[0] for row in skipped] == [
        "files/a-locked.zip!trace.pcapng", "files/b-broken.zip", "files/c-torn.zip!torn.pcapng", "files/d-link.pcapng"]
    assert "encrypted member" in skipped[0] and "will not open" in skipped[1] and "BadZipFile" in skipped[1]
    assert "unreadable" in skipped[2] and "symlink, not followed" in skipped[3]

    res = mr.solve(folder, PROFILE)                                  # the capture may be in there: never "none"
    assert res.status == "blocked" and res.notes.startswith("unreadable-input")
    assert "files/a-locked.zip!trace.pcapng (an encrypted member" in res.notes and "files/c-torn.zip" in res.notes

    monkeypatch.setattr(mr._cap, "MAX_CAPTURE", len(capture_bytes) - 1)
    (files / "f-big.pcapng").write_bytes(capture_bytes)
    (files / "g-big.zip").write_bytes(_zip({"big.pcapng": capture_bytes}))
    _, skipped = mr.find_captures(folder)
    assert f"files/f-big.pcapng (a capture of {len(capture_bytes)} bytes, over the {len(capture_bytes) - 1}-byte cap)" \
        in skipped
    assert any(row.startswith("files/g-big.zip!big.pcapng (a capture of") for row in skipped)
    monkeypatch.undo()

    (files / "h-ok.zip").write_bytes(_zip({"ok.pcapng": capture_bytes}))   # a readable copy beside them
    (folder / "modbus-replay.toml").write_text(witness_spec())
    res = mr.solve(folder, PROFILE)
    assert res.status == "solved" and res.flags == (f"CSCTF{{{hashlib.sha256(PREFIX + t).hexdigest()}}}",)
    assert "unreadable capture(s): files/a-locked.zip!trace.pcapng (an encrypted member" in res.notes


def test_the_shipped_templates_are_valid_and_run_on_a_matching_capture():
    witness = mr.load_spec(TEMPLATES / "witness.toml")
    assert [row["passed"] for row in mr.run_vectors(witness)] == [True]
    wire = Wire(unit=1)
    wire.read(1, 0x20, [1, 0])
    wire.write(2, 0x30, [7])                         # unsafe: isolated 0
    wire.write(3, 0x21, [1])                         # ineligible
    wire.write(4, 0x31, [9])                         # safe
    wire.write(5, 0x40, [0])                         # ineligible
    out = mr.run_spec(witness, wire.pcapng(), PROFILE)
    material = b"EXAMPLE-WITNESS/1\x00" + fc16(0x30, [7]) + fc16_ok(0x30, 1)
    assert out.refusals == [] and out.built.material == material
    assert out.flag == f"CSCTF{{{hashlib.sha256(material).hexdigest()}}}"

    report = mr.load_spec(TEMPLATES / "report.toml")
    assert [row["passed"] for row in mr.run_vectors(report)] == [True]
    wire = Wire(unit=9)
    for k, values in enumerate(([80, 100, 1], [80, 100, 0], [20, 10, 1])):
        wire.write(0x0100 + k, 0x2000, values)
        wire.read(0x0200 + k, 0x2000, values)
    out = mr.run_spec(report, wire.pcapng(), PROFILE)
    text = "\n".join(["example-reconciliation-v1", "initial;rate=10;valve=100;armed=0", "n=3",
                      "i=0;tid=0100;rate=80;valve=100;armed=1", "i=1;tid=0101;rate=80;valve=100;armed=0",
                      "i=2;tid=0102;rate=20;valve=10;armed=1", "unsafe-mask=A000"])
    assert out.refusals == [] and out.built.text == text
    assert out.built.value == base64.b32encode(hashlib.sha256(text.encode()).digest()[:20]).decode().rstrip("=")


# ---- routing, intake, the runner -------------------------------------------------------------------

def test_a_modbus_brief_routes_here_first_and_other_briefs_do_not(tmp_path):
    from ctf.engines import router
    ids = [h.manifest.id for h in router.route("forensics", "The controller took valid Modbus/TCP writes.", tmp_path)]
    assert ids[0] == "toolkits.modbus_replay" and "toolkits.ics_scada" in ids
    ids = [h.manifest.id for h in router.route("networking", "Read the holding registers of the pump", tmp_path)]
    assert ids[0] == "toolkits.modbus_replay"
    ids = [h.manifest.id for h in router.route("forensics", "a memory image of a workstation", tmp_path)]
    assert "toolkits.modbus_replay" not in ids


def test_intake_runs_the_engine_with_no_model_and_again_once_the_spec_exists(tmp_path):
    from ctf.engines import manifest
    from ctf.intake import engines as E
    from ctf.intake import guard as G
    wire, t = witness_wire()
    folder = tmp_path / "9001-interlock"
    (folder / "unpacked").mkdir(parents=True)
    (folder / "unpacked" / "trace.pcapng").write_bytes(wire.pcapng())
    guard = G.Guard("hook", (), "test")
    plan = E.plan(manifest.discover(), "forensics", "accepted Modbus/TCP maintenance writes", folder / "unpacked", guard=guard)
    job = next(j for j in plan.jobs if j.engine == "toolkits.modbus_replay")
    assert job.manifest.intake.run == "challenge" and job.manifest.intake.select == "route"
    quiet = E.plan(manifest.discover(), "forensics", "a disk image", folder / "unpacked", guard=guard)
    assert "toolkits.modbus_replay" not in {j.engine for j in quiet.jobs}

    ctx = E.Context(challenge_dir=folder, folder=folder / "unpacked", out_root=folder / "recon" / "engines",
                    profile=event.load("csctf"), guard=guard, root=REPO, python=sys.executable,
                    challenge_id="9001", record=False)
    run = E.run_job(job, ctx)
    assert run.status == "ok", (folder / run.errors).read_text()
    assert run.result_status == "unsure" and run.flags == ()
    assert (folder / "recon" / "modbus_replay" / "replay.json").is_file()

    (folder / "modbus-replay.toml").write_text(witness_spec())
    run = E.run_job(job, ctx)
    assert run.status == "ok", (folder / run.errors).read_text()
    assert run.result_status == "solved"
    assert run.flags == (f"CSCTF{{{hashlib.sha256(PREFIX + t).hexdigest()}}}",)


def test_cli_prints_the_result_json_last(tmp_path, capsys):
    wire, t = witness_wire()
    folder = challenge(tmp_path, wire)
    spec_file = tmp_path / "elsewhere.toml"
    spec_file.write_text(witness_spec())
    out_dir = tmp_path / "out"
    assert mr.main([str(folder), "--spec", str(spec_file), "--out", str(out_dir), "--event", "csctf"]) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    res = SolverResult.from_json(lines[-1])
    assert res.status == "solved" and res.flags == (f"CSCTF{{{hashlib.sha256(PREFIX + t).hexdigest()}}}",)
    assert (out_dir / "witness.bin").read_bytes() == PREFIX + t and not (folder / "recon").exists()
    assert lines[0].startswith("[wire] ")
    assert mr.main([str(tmp_path / "missing")]) == 2
    assert "no such folder" in capsys.readouterr().err


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
