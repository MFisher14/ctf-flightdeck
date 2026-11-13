"""B-077: CFDP PDU parsing, File Data coverage, the mission filter and NAK reconstruction.

Every capture is built here, byte by byte, with this file's own encoders (`_sp`, `_pdu`, `_metadata`,
`_filedata`, `_eof`): the module's builder is never used to make its own input, and the expected NAKs
are hex written out by hand from the CFDP layout. All values are made up.
"""
from __future__ import annotations

import base64
import datetime as dt
import json
import re
import struct
import subprocess
import sys
import tomllib
import types
from pathlib import Path

import pytest

import sec_space_ccsds as ccsds
import sec_space_cfdp as cfdp
from ctf import event
from ctf.engines import manifest as _manifest
from ctf.engines import router, runner
from ctf.intake import engines as _intake_engines
from ctf.result import SolverResult

REPO = Path(__file__).resolve().parents[1]
APID = 0x2A5
SRC, SEQ, DST = 0x11, 0x2C, 0x05


# ----------------------------------------------------------------------- this file's own encoders
def _sp(data: bytes, *, apid=APID, pvn=0, tc=0, sec=0, flags=3, count=0) -> bytes:
    word = (pvn << 13) | (tc << 12) | (sec << 11) | apid
    return struct.pack(">HHH", word, (flags << 14) | count, len(data) - 1) + data


def _pdu(body: bytes, *, data=0, version=1, to_sender=0, unack=0, crc=0, large=0, segctl=0, segmeta=0,
         idlen=1, seqlen=1, src=SRC, seq=SEQ, dst=DST, declared=None) -> bytes:
    length = len(body) + (2 if crc else 0) if declared is None else declared
    first = (version << 5) | (data << 4) | (to_sender << 3) | (unack << 2) | (crc << 1) | large
    third = (segctl << 7) | ((idlen - 1) << 4) | (segmeta << 3) | (seqlen - 1)
    out = (bytes([first]) + struct.pack(">H", length) + bytes([third]) + src.to_bytes(idlen, "big")
           + seq.to_bytes(seqlen, "big") + dst.to_bytes(idlen, "big") + body)
    if crc:
        out += struct.pack(">H", ccsds.crc16_fecf(out))     # the sibling decoder's bitwise CRC
    return out


def _fss(kw) -> int:
    return 8 if kw.get("large") else 4


def _metadata(size: int, *, checksum_type=15, closure=0, src_name=b"", dst_name=b"", options=b"", **kw):
    body = (bytes([0x07, (closure << 6) | checksum_type]) + size.to_bytes(_fss(kw), "big")
            + bytes([len(src_name)]) + src_name + bytes([len(dst_name)]) + dst_name + options)
    return _pdu(body, **kw)


def _filedata(offset: int, length: int, *, prefix=b"", **kw) -> bytes:
    return _pdu(prefix + offset.to_bytes(_fss(kw), "big") + bytes(length), data=1, **kw)


def _eof(size: int, *, cc=0, spare=0, checksum=0, fault=b"", **kw) -> bytes:
    body = bytes([0x04, (cc << 4) | spare]) + checksum.to_bytes(4, "big") + size.to_bytes(_fss(kw), "big")
    return _pdu(body + fault, **kw)


def _stream(*pdus: bytes) -> bytes:
    return b"".join(_sp(p, count=i) for i, p in enumerate(pdus))


def _flt(**sections) -> cfdp.Filter:
    return cfdp.parse_filter({"stream": {"framing": "space-packet"}, **sections})


def _without(table: dict, key: str) -> dict:
    return {k: v for k, v in table.items() if k != key}


TRANSACTION = {"version": 1, "direction": "toward-receiver", "mode": "acknowledged", "crc": False,
               "large_file": False, "entity_id_length": 1, "sequence_number_length": 1,
               "source": SRC, "sequence": SEQ, "destination": DST}
PACKET = {"pvn": 0, "type": "tm", "secondary_header": False, "apid": APID, "sequence_flags": 3}


def _profile(prefixes=("TESTCTF",), body=None):
    flag = {"prefixes": list(prefixes)}
    if body:
        flag["body"] = body
    return event.parse({
        "slug": "cfdp-test", "name": "cfdp", "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 1, 2)},
        "platform": {"kind": "manual"}, "flag": flag,
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed"},
    }, src="<test>")


# ------------------------------------------------------------------------------------- PDU parsing
def test_fixed_header_fields_from_a_hand_written_pdu():
    # 0x3d = version 1, file data, toward sender, unacknowledged, no CRC, large file.
    # 0xa9 = segmentation control, 3-octet entity IDs, segment metadata present, 2-octet sequence number.
    raw = bytes.fromhex("3d 000d a9 0a0b0c 0102 0d0e0f" "41 ee" "0000000000000100" "aabbcc".replace(" ", ""))
    p = cfdp.parse_pdu(raw)
    assert (p.version, p.kind, p.file_directive) == (1, "file-data", False)
    assert (p.direction, p.mode, p.crc, p.large_file) == ("toward-sender", "unacknowledged", False, True)
    assert (p.segmentation_control, p.segment_metadata) == (True, True)
    assert (p.entity_id_length, p.sequence_number_length) == (3, 2)
    assert (p.source, p.sequence, p.destination) == (0x0A0B0C, 0x0102, 0x0D0E0F)
    assert p.header_length == 12 and p.data_field_length == 13
    assert p.fields["record_continuation_state"] == 1 and p.fields["segment_metadata_hex"] == "ee"
    assert (p.fields["offset"], p.fields["length"], p.fields["end"]) == (0x100, 3, 0x103)
    assert p.payload == bytes.fromhex("aabbcc")


def test_the_other_value_of_every_header_flag():
    # 20 = version 1, directive, toward receiver, acknowledged, no CRC, small file; 0005 data octets.
    p = cfdp.parse_pdu(bytes.fromhex("200005" "00" "112c05" "0c" "00000007"))
    assert (p.version, p.kind, p.file_directive) == (1, "keep-alive", True)
    assert (p.direction, p.mode, p.crc, p.large_file) == ("toward-receiver", "acknowledged", False, False)
    assert (p.segmentation_control, p.segment_metadata) == (False, False)
    assert p.fields["progress"] == 7


def test_metadata_fields_names_and_options():
    raw = _metadata(0x01020304, checksum_type=3, closure=1, src_name=b"a.bin", dst_name=b"/x/b",
                    options=bytes([0x02, 0x03]) + b"abc" + bytes([0x05, 0x00]))
    p = cfdp.parse_pdu(raw)
    assert p.kind == "metadata" and p.fields["directive_code"] == 7
    assert p.fields["file_size"] == 0x01020304
    assert p.fields["checksum_type"] == 3 and p.fields["closure_requested"] is True
    assert (p.fields["source_file_name"], p.fields["destination_file_name"]) == ("a.bin", "/x/b")
    assert p.fields["options"] == [{"type": 2, "value_hex": "616263"}, {"type": 5, "value_hex": ""}]
    plain = cfdp.parse_pdu(_metadata(9)).fields
    assert plain["closure_requested"] is False and plain["checksum_type"] == 15 and plain["options"] == []


def test_metadata_with_large_file_flag_has_a_64_bit_size():
    p = cfdp.parse_pdu(_metadata(0x1_0000_0002, large=1))
    assert p.large_file and p.fields["file_size"] == 0x1_0000_0002


@pytest.mark.parametrize("raw, why", [
    (_metadata(5)[:-1], "declares"),                                   # the unit is one octet short
    (_pdu(bytes([0x07, 0x0F, 0, 0, 0, 5, 3]) + b"ab"), "source file name"),   # an LV running past the end
    (_pdu(bytes([0x07, 0x0F, 0, 0, 0, 5, 0, 0, 0x02, 0x09, 0x41])), "TLV"),   # a TLV running past the end
    (_pdu(bytes([0x07, 0x0F, 0, 0])), "Metadata"),
])
def test_malformed_metadata_is_an_error(raw, why):
    with pytest.raises(cfdp.CfdpError, match=why):
        cfdp.parse_pdu(raw)


def test_eof_fields_and_fault_location():
    p = cfdp.parse_pdu(_eof(0x60, cc=4, spare=2, checksum=0xDEADBEEF, fault=bytes([0x06, 0x01, 0x11])))
    assert p.kind == "eof"
    assert (p.fields["condition_code"], p.fields["spare"]) == (4, 2)
    assert p.fields["checksum"] == 0xDEADBEEF and p.fields["file_size"] == 0x60
    assert p.fields["fault_location"] == {"type": 6, "value_hex": "11"}
    assert cfdp.parse_pdu(_eof(1)).fields["fault_location"] is None
    with pytest.raises(cfdp.CfdpError, match="at most one"):
        cfdp.parse_pdu(_eof(1, fault=bytes([6, 1, 1, 6, 1, 2])))
    with pytest.raises(cfdp.CfdpError, match="EOF"):
        cfdp.parse_pdu(_pdu(bytes([0x04, 0, 0, 0, 0, 0, 0, 0])))


def test_file_data_offsets_small_and_large():
    small = cfdp.parse_pdu(_filedata(0xFFFFFFF0, 8))
    assert (small.fields["offset"], small.fields["end"]) == (0xFFFFFFF0, 0xFFFFFFF8)
    large = cfdp.parse_pdu(_filedata(0x2_0000_0000, 5, large=1))
    assert (large.fields["offset"], large.fields["length"]) == (0x2_0000_0000, 5)
    assert cfdp.parse_pdu(_filedata(7, 0)).fields["length"] == 0
    with pytest.raises(cfdp.CfdpError, match="offset"):
        cfdp.parse_pdu(_pdu(b"\x00\x00\x00", data=1))


def test_segment_metadata_must_fit():
    with pytest.raises(cfdp.CfdpError, match="segment metadata"):
        cfdp.parse_pdu(_pdu(bytes([0x05, 1, 2]), data=1, segmeta=1))


@pytest.mark.parametrize("length, rcs", [(32, 0), (63, 2)])
def test_segment_metadata_length_uses_all_six_bits(length, rcs):
    # The length is the low six bits of the first octet: 32 and 63 need bit 5, which a 5-bit read drops.
    meta = bytes(range(0x80, 0x80 + length))
    payload = bytes.fromhex("c0ffee")
    raw = _pdu(bytes([(rcs << 6) | length]) + meta + (0x1234).to_bytes(4, "big") + payload,
               data=1, segmeta=1)
    p = cfdp.parse_pdu(raw)
    assert p.fields["record_continuation_state"] == rcs
    assert p.fields["segment_metadata_hex"] == meta.hex()
    assert (p.fields["offset"], p.fields["length"], p.fields["end"]) == (0x1234, 3, 0x1237)
    assert p.payload == payload


def test_nak_pdu_parses_scope_and_requests():
    raw = bytes.fromhex("28001900112c0508000000000000006000000005000000060000001300000020")
    p = cfdp.parse_pdu(raw)
    assert p.kind == "nak" and p.direction == "toward-sender"
    assert (p.fields["scope_start"], p.fields["scope_end"]) == (0, 0x60)
    assert p.fields["segment_requests"] == [(5, 6), (0x13, 0x20)]
    with pytest.raises(cfdp.CfdpError, match="whole segment-request pairs"):
        cfdp.parse_pdu(_pdu(bytes([0x08]) + bytes(12)))


def test_other_directives_are_named_not_rejected():
    assert cfdp.parse_pdu(_pdu(bytes([0x06, 0x41, 0x02]))).fields["acked_directive_code"] == 4
    fin = cfdp.parse_pdu(_pdu(bytes([0x05, 0x26]))).fields
    assert (fin["condition_code"], fin["delivery_code"], fin["file_status"]) == (2, 1, 2)
    assert cfdp.parse_pdu(_pdu(bytes([0x09, 0x80]))).fields["response_required"] == "keep-alive"
    unknown = cfdp.parse_pdu(_pdu(bytes([0x3F, 0xAA])))
    assert unknown.kind == "directive-0x3f" and unknown.fields["body_hex"] == "aa"


@pytest.mark.parametrize("raw, why", [
    (b"\x20\x00", "fixed header"),
    (_pdu(b"", data=0), "no directive code"),
    (_pdu(bytes([0x04]) + bytes(9), declared=11), "declares"),          # one more than is there
    (_pdu(bytes([0x04]) + bytes(9), declared=9), "declares"),           # one fewer
    (_pdu(bytes([0x04]) + bytes(9), version=2), "version 2"),
    (bytes.fromhex("20000070112c"), "truncated CFDP header"),
])
def test_a_pdu_must_be_whole_and_consume_its_unit_exactly(raw, why):
    with pytest.raises(cfdp.CfdpError, match=why):
        cfdp.parse_pdu(raw)


def test_crc_flagged_pdu_must_verify():
    good = _filedata(4, 6, crc=1)
    p = cfdp.parse_pdu(good)
    assert p.crc and p.fields["length"] == 6 and p.fields["end"] == 10     # the CRC is not file data
    assert p.fields["crc_value"] == int.from_bytes(good[-2:], "big")
    bad = good[:-1] + bytes([good[-1] ^ 1])
    with pytest.raises(cfdp.CfdpError, match="CRC mismatch"):
        cfdp.parse_pdu(bad)
    with pytest.raises(cfdp.CfdpError, match="no room for a CRC"):
        # 32 = version 1, file data, CRC flag; a one-octet data field cannot hold the two CRC octets.
        cfdp.parse_pdu(bytes.fromhex("320001" "00" "112c05" "00"))


def test_crc16_is_the_ccsds_crc():
    for sample in (b"", b"123456789", bytes(range(256)) * 3):
        assert cfdp.crc16(sample) == ccsds.crc16_fecf(sample)
    assert cfdp.crc16(b"123456789") == 0x29B1          # CRC-16/IBM-3740 check value


# --------------------------------------------------------------------------------------- framing
def test_space_packet_walk_reports_offsets_and_header_fields():
    a, b = _pdu(bytes([0x09, 0x00])), bytes(3)
    raw = _sp(a, count=7) + _sp(b, apid=0x7FF, pvn=3, tc=1, sec=1, flags=1, count=0x3FFF)
    units = cfdp.walk_space_packets(raw)
    assert [(u.index, u.offset, u.data_offset, u.data) for u in units] == [
        (0, 0, 6, a), (1, 6 + len(a), 12 + len(a), b)]
    assert units[0].packet == {"pvn": 0, "type": "tm", "secondary_header": False, "apid": APID,
                               "sequence_flags": 3, "sequence_count": 7}
    assert units[1].packet == {"pvn": 3, "type": "tc", "secondary_header": True, "apid": 0x7FF,
                               "sequence_flags": 1, "sequence_count": 0x3FFF}


def test_space_packet_walk_agrees_with_the_sibling_decoder():
    raw = _stream(_metadata(40), _filedata(0, 9), _eof(40))
    theirs = ccsds.parse_space_packet_stream(raw)
    ours = cfdp.walk_space_packets(raw)
    assert [(u.offset, u.packet["apid"], u.packet["sequence_count"], u.data.hex()) for u in ours] == [
        (p["stream_offset"], p["apid"], p["sequence_count"], p["data_hex"]) for p in theirs]


@pytest.mark.parametrize("cut, why", [(1, "truncated Space Packet at offset"), (-3, "primary header")])
def test_a_truncated_recording_is_rejected_not_resynchronised(cut, why):
    raw = _stream(_metadata(40), _filedata(0, 9))
    damaged = raw[:-cut] if cut > 0 else raw + b"\x0a\xa5\xc0"
    with pytest.raises(cfdp.CfdpError, match=why):
        cfdp.walk_space_packets(damaged)
    with pytest.raises(cfdp.CfdpError, match=why):
        cfdp.reconstruct(damaged, _flt())


def test_empty_and_non_bytes_streams_are_errors():
    with pytest.raises(cfdp.CfdpError, match="empty"):
        cfdp.walk_space_packets(b"")
    with pytest.raises(cfdp.CfdpError, match="empty"):
        cfdp.walk_pdus(b"")
    with pytest.raises(cfdp.CfdpError, match="must be bytes"):
        cfdp.walk_space_packets("not bytes")
    with pytest.raises(cfdp.CfdpError, match="unknown framing"):
        cfdp.walk(b"x", "tm-frame")


def test_stream_size_and_unit_count_limits_are_named(monkeypatch, tmp_path, capsys):
    raw = _stream(_metadata(30), _filedata(0, 10), _eof(30))
    monkeypatch.setattr(cfdp, "MAX_STREAM", len(raw) - 1)
    with pytest.raises(cfdp.CfdpError, match="over the"):
        cfdp.walk_space_packets(raw)
    cap = tmp_path / "big.bin"
    cap.write_bytes(raw)
    assert cfdp.main(["survey", str(cap)]) == 2
    assert "over the" in capsys.readouterr().err
    monkeypatch.setattr(cfdp, "MAX_STREAM", len(raw))
    assert len(cfdp.walk_space_packets(raw)) == 3                  # exactly at the limit is read
    monkeypatch.setattr(cfdp, "MAX_UNITS", 2)
    with pytest.raises(cfdp.CfdpError, match="more than 2 Space Packets"):
        cfdp.walk_space_packets(raw)
    with pytest.raises(cfdp.CfdpError, match="more than 2 PDUs"):
        cfdp.walk_pdus(b"".join([_metadata(30), _filedata(0, 10), _eof(30)]))
    monkeypatch.setattr(cfdp, "MAX_UNITS", 3)
    assert len(cfdp.walk_pdus(b"".join([_metadata(30), _filedata(0, 10), _eof(30)]))) == 3


def test_bare_pdu_walk_slices_by_declared_length():
    a, b = _metadata(40), _filedata(0, 9, idlen=2, seqlen=3)
    units = cfdp.walk_pdus(a + b)
    assert [(u.offset, u.data, u.packet) for u in units] == [(0, a, None), (len(a), b, None)]
    with pytest.raises(cfdp.CfdpError, match="truncated CFDP PDU at offset"):
        cfdp.walk_pdus(a + b[:-1])
    with pytest.raises(cfdp.CfdpError, match="fixed header"):
        cfdp.walk_pdus(a + b"\x20\x00")


# --------------------------------------------------------------------------------------- coverage
def test_merge_ranges_joins_overlaps_touching_and_duplicates():
    assert cfdp.merge_ranges([(30, 40), (4, 20), (10, 30), (4, 20), (50, 70), (60, 65), (9, 9), (8, 3)]) \
        == [(4, 40), (50, 70)]
    assert cfdp.merge_ranges([]) == []
    assert cfdp.merge_ranges([(0, 1), (2, 3)]) == [(0, 1), (2, 3)]        # a one-byte hole stays a hole


def test_complement_is_ascending_maximal_and_clipped_to_the_scope():
    cov = [(4, 40), (50, 70)]
    assert cfdp.complement(cov, 0, 96) == [(0, 4), (40, 50), (70, 96)]
    assert cfdp.complement(cov, 4, 70) == [(40, 50)]
    assert cfdp.complement(cov, 10, 60) == [(40, 50)]
    assert cfdp.complement(cov, 45, 48) == [(45, 48)]
    assert cfdp.complement([(0, 200)], 0, 96) == []
    assert cfdp.complement([(90, 200)], 0, 96) == [(0, 90)]
    assert cfdp.complement([], 3, 9) == [(3, 9)]
    assert cfdp.complement([(100, 120)], 0, 50) == [(0, 50)]
    assert cfdp.complement([(0, 5), (5, 6)], 0, 6) == []


def test_complement_keeps_one_byte_gaps_leading_interior_and_trailing():
    assert cfdp.complement([(0, 5), (6, 10)], 0, 10) == [(5, 6)]
    assert cfdp.complement([(1, 10)], 0, 10) == [(0, 1)]
    assert cfdp.complement([(0, 9)], 0, 10) == [(9, 10)]
    assert cfdp.complement([(1, 3), (4, 6), (7, 9)], 0, 10) == [(0, 1), (3, 4), (6, 7), (9, 10)]


# -------------------------------------------------------------------------------------- build_nak
def test_build_nak_known_answer():
    nak = cfdp.build_nak(source=SRC, sequence=SEQ, destination=DST, scope_start=0, scope_end=0x60,
                         segment_requests=[(5, 6), (0x13, 0x20)])
    # 28: version 1, directive, toward sender, acknowledged, no CRC, small file. 0019: 25 octets.
    assert nak.hex() == "28001900112c0508000000000000006000000005000000060000001300000020"


def test_build_nak_header_variants():
    nak = cfdp.build_nak(source=0x0A0B, sequence=0x010203, destination=0x0C0D, scope_start=1,
                         scope_end=0x1_0000_0000, segment_requests=[(1, 2)], entity_id_length=2,
                         sequence_number_length=3, version=0, direction="toward-receiver",
                         mode="unacknowledged", large_file=True)
    # 05: version 0, directive, toward receiver, unacknowledged, no CRC, large. 12: ID length 2, seq length 3.
    assert nak.hex() == ("05" "0021" "12" "0a0b" "010203" "0c0d" "08" "0000000000000001" "0000000100000000"
                         "0000000000000001" "0000000000000002")


def test_build_nak_with_crc_appends_a_crc_the_parser_accepts():
    nak = cfdp.build_nak(source=SRC, sequence=SEQ, destination=DST, scope_start=0, scope_end=9,
                         segment_requests=[(2, 3)], crc=True)
    assert nak[0] == 0x2A and int.from_bytes(nak[1:3], "big") == 19        # 17 body octets + 2 CRC
    assert int.from_bytes(nak[-2:], "big") == ccsds.crc16_fecf(nak[:-2])
    assert cfdp.parse_pdu(nak).fields["segment_requests"] == [(2, 3)]


@pytest.mark.parametrize("kw, why", [
    ({"scope_end": 2 ** 32}, "end of scope"),
    ({"segment_requests": [(0, 2 ** 32)]}, "segment request end"),
    ({"segment_requests": [(9, 3)]}, "reversed"),
    ({"scope_start": 9, "scope_end": 3}, "reversed"),
    ({"source": 256}, "source entity ID"),
    ({"sequence": 256}, "transaction sequence number"),
    ({"destination": -1}, "destination entity ID"),
    ({"entity_id_length": 9}, "entity_id_length"),
    ({"sequence_number_length": 0}, "sequence_number_length"),
    ({"version": 2}, "version"),
    ({"direction": "up"}, "direction"),
    ({"mode": "best-effort"}, "mode"),
    ({"segment_requests": [(i, i + 1) for i in range(0, 20000, 2)]}, "split it"),
])
def test_build_nak_refuses_what_does_not_fit(kw, why):
    base = dict(source=SRC, sequence=SEQ, destination=DST, scope_start=0, scope_end=0x60,
                segment_requests=[(5, 6)])
    with pytest.raises(cfdp.CfdpError, match=why):
        cfdp.build_nak(**{**base, **kw})


def test_build_nak_takes_the_largest_request_list_that_fits():
    requests = [(i, i + 1) for i in range(0, 2 * 8190, 2)]        # 9 + 8190 * 8 = 65529 octets
    nak = cfdp.build_nak(source=SRC, sequence=SEQ, destination=DST, scope_start=0, scope_end=2 ** 20,
                         segment_requests=requests)
    assert int.from_bytes(nak[1:3], "big") == 65529 and len(nak) == 7 + 65529


# ------------------------------------------------------------------------------- the mission case
# One recording that exercises every rule of a strict mission filter. Unit numbers are the comments.
def _mission() -> bytes:
    return b"".join([
        _sp(_metadata(64), apid=0x012),                          # 0  target tuple, but another APID
        _sp(_filedata(0, 96, src=0x33, seq=0x09)),               # 1  another transaction, same APID
        _sp(_filedata(0, 4)),                                    # 2  File Data before any Metadata
        _sp(_metadata(200, checksum_type=0)),                    # 3  Metadata with the wrong checksum type
        _sp(_metadata(96)),                                      # 4  the Metadata
        _sp(_metadata(80)),                                      # 5  a later Metadata
        _sp(_filedata(4, 16)),                                   # 6  [4, 20)
        _sp(_filedata(10, 20)),                                  # 7  [10, 30) overlaps
        _sp(_filedata(30, 10)),                                  # 8  [30, 40) touches
        _sp(_filedata(4, 16)),                                   # 9  duplicate
        _sp(_filedata(50, 20)),                                  # 10 [50, 70)
        _sp(_filedata(90, 10)),                                  # 11 [90, 100) runs past the file size
        _sp(_filedata(40, 10, segctl=1)),                        # 12 [40, 50) with segmentation control
        _sp(_pdu(bytes(6), data=1, declared=5)),                 # 13 length does not consume the packet
        _sp(_filedata(70, 20), tc=1),                            # 14 [70, 90) in a telecommand packet
        _sp(_filedata(70, 10), flags=1),                         # 15 [70, 80) in a segmented packet
        _sp(_eof(80)),                                           # 16 EOF whose size is not the Metadata's
        _sp(_eof(96, cc=4)),                                     # 17 EOF with a condition code
        _sp(_filedata(70, 2)),                                   # 18 [70, 72)
        _sp(_eof(96)),                                           # 19 the EOF
        _sp(_filedata(72, 18)),                                  # 20 [72, 90) after the EOF
        _sp(_eof(96)),                                           # 21 a later EOF
        _sp(_pdu(bytes([0x06, 0x41, 0x00]), to_sender=1)),       # 22 an ACK from the receiver
    ])


def _strict(**override) -> dict:
    cfg = {
        "stream": {"framing": "space-packet"},
        "packet": dict(PACKET),
        "transaction": _without(TRANSACTION, "direction"),
        "file_data": {"segmentation_control": False, "segment_metadata": False},
        "metadata": {"checksum_type": 15, "closure_requested": False, "options": False},
        "eof": {"condition_code": 0, "spare": 0, "checksum": 0, "fault_location": False,
                "file_size": "metadata"},
        "policy": {"metadata_first": True, "beyond_file_size": "discard", "eof_snapshot": True},
        "nak": {"request_metadata": False},
    }
    for section, table in override.items():
        cfg[section] = table
    return cfg


def _edit(section: str, **keys) -> dict:
    """The strict config with keys of one section changed (a value of None removes the key)."""
    table = dict(_strict()[section])
    for key, value in keys.items():
        if value is None:
            table.pop(key, None)
        else:
            table[key] = value
    return _strict(**{section: table})


def test_strict_mission_filter_reconstructs_the_nak():
    rec = cfdp.reconstruct(_mission(), cfdp.parse_filter(_strict()))
    assert rec.units == 23
    assert rec.coverage == ((4, 40), (50, 72))
    assert rec.scope == (0, 96)
    assert rec.missing == ((0, 4), (40, 50), (72, 96))
    assert rec.requests == rec.missing
    # 0x21 = 1 + 8 + 3 * 8 octets of data field.
    assert [n.hex() for n in rec.naks] == [
        "28002100112c0508" "00000000" "00000060" "0000000000000004" "0000002800000032" "0000004800000060"]
    assert rec.reason == ""
    assert rec.metadata == {"unit": 4, "offset": rec.trace[4][1], "file_size": 96, "checksum_type": 15,
                            "closure_requested": False}
    assert rec.eof["unit"] == 19 and rec.eof["file_size"] == 96
    assert rec.segments == 6 and rec.covered_bytes == 58 and rec.missing_bytes == 38
    assert rec.transaction["source"] == SRC and rec.transaction["sequence"] == SEQ
    assert rec.discards == {
        "packet.apid": 1, "transaction.source": 1, "file_data.before_metadata": 1,
        "metadata.checksum_type": 1, "metadata.later": 1, "file_data.beyond_file_size": 1,
        "file_data.segmentation_control": 1, "malformed": 1, "packet.type": 1,
        "packet.sequence_flags": 1, "eof.file_size": 1, "eof.condition_code": 1,
        "file_data.after_eof": 1, "eof.later": 1}
    assert rec.ignored == {"ack": 1}
    assert "unit 13" in rec.malformed[0] and "declares" in rec.malformed[0]
    assert [(t[0], t[2], t[3]) for t in rec.trace][:5] == [
        (0, "-", "packet.apid"), (1, "file-data", "transaction.source"),
        (2, "file-data", "file_data.before_metadata"), (3, "metadata", "metadata.checksum_type"),
        (4, "metadata", "accept")]
    assert rec.trace[22][2:] == ("ack", "ignored") and len(rec.trace) == 23


def test_strict_mission_filter_requests_every_one_byte_hole():
    # A target capture can leave holes of a single octet; each one is its own segment request. The
    # decoys would fill two of the holes if their packet or transaction were counted.
    raw = b"".join([
        _sp(_metadata(24)),
        _sp(_filedata(1, 4)),                                    # [1, 5): leading hole [0, 1)
        _sp(_filedata(5, 1), apid=0x012),                        # decoy over [5, 6): another APID
        _sp(_filedata(6, 4)),                                    # [6, 10): hole [5, 6)
        _sp(_filedata(10, 1, src=0x33)),                         # decoy over [10, 11): another tuple
        _sp(_filedata(11, 12)),                                  # [11, 23): hole [10, 11)
        _sp(_eof(24)),                                           # trailing hole [23, 24)
    ])
    rec = cfdp.reconstruct(raw, cfdp.parse_filter(_strict()))
    assert rec.coverage == ((1, 5), (6, 10), (11, 23))
    assert rec.missing == ((0, 1), (5, 6), (10, 11), (23, 24)) and rec.missing_bytes == 4
    assert rec.discards == {"packet.apid": 1, "transaction.source": 1}
    # 0x29 = 1 + 8 + 4 * 8 octets of data field.
    assert [n.hex() for n in rec.naks] == [
        "28002900112c0508" "00000000" "00000018"
        "0000000000000001" "0000000500000006" "0000000a0000000b" "0000001700000018"]


@pytest.mark.parametrize("cfg, missing", [
    # each line relaxes ONE rule of the strict filter; the NAK changes the way that rule says
    (_edit("policy", metadata_first=False), [(40, 50), (72, 96)]),                 # unit 2 counts
    (_edit("policy", beyond_file_size="keep"), [(0, 4), (40, 50), (72, 90)]),      # unit 11 counts
    (_edit("policy", eof_snapshot=False), [(0, 4), (40, 50), (90, 96)]),           # unit 20 counts
    (_edit("file_data", segmentation_control=None), [(0, 4), (72, 96)]),           # unit 12 counts
    (_edit("packet", type=None), [(0, 4), (40, 50), (90, 96)]),                    # unit 14 counts
    (_edit("packet", sequence_flags=None), [(0, 4), (40, 50), (80, 96)]),          # unit 15 counts
    (_edit("eof", condition_code=None), [(0, 4), (40, 50), (70, 96)]),             # unit 17 is the EOF
])
def test_relaxing_one_rule_changes_the_nak(cfg, missing):
    rec = cfdp.reconstruct(_mission(), cfdp.parse_filter(cfg))
    assert list(rec.missing) == missing
    assert len(rec.naks) == 1
    assert cfdp.parse_pdu(rec.naks[0]).fields["segment_requests"] == missing


def test_without_the_eof_size_rule_the_first_eof_scopes_the_nak():
    rec = cfdp.reconstruct(_mission(), cfdp.parse_filter(_edit("eof", file_size=None)))
    assert rec.eof["unit"] == 16 and rec.scope == (0, 80)
    assert rec.missing == ((0, 4), (40, 50), (70, 80))


def test_without_the_metadata_rule_the_wrong_metadata_is_accepted_and_no_eof_matches():
    rec = cfdp.reconstruct(_mission(), cfdp.parse_filter(_edit("metadata", checksum_type=None)))
    assert rec.metadata["unit"] == 3 and rec.metadata["file_size"] == 200
    assert rec.eof is None and rec.naks == ()
    assert "no EOF was accepted" in rec.reason
    # every EOF, 96 or 80, is not 200; unit 17 fails its condition code first (checked before the size)
    assert rec.discards["eof.file_size"] == 3 and rec.discards["eof.condition_code"] == 1


def test_without_the_apid_rule_the_decoy_metadata_wins():
    rec = cfdp.reconstruct(_mission(), cfdp.parse_filter(_edit("packet", apid=None)))
    assert rec.metadata["unit"] == 0 and rec.metadata["file_size"] == 64
    assert rec.naks == () and rec.eof is None


def test_apid_may_be_a_list():
    rec = cfdp.reconstruct(_mission(), cfdp.parse_filter(_edit("packet", apid=[0x012, APID])))
    assert rec.metadata["unit"] == 0
    assert "packet.apid" not in rec.discards


def test_without_the_tuple_the_filter_is_ambiguous_and_says_which_transactions():
    cfg = _strict(transaction=_without(_without(TRANSACTION, "source"), "sequence"))
    with pytest.raises(cfdp.AmbiguousTransaction) as e:
        cfdp.reconstruct(_mission(), cfdp.parse_filter(cfg))
    text = str(e.value)
    assert "2 transactions" in text and "0x11/0x2c/0x05" in text and "0x33/0x09/0x05 (1 PDU)" in text
    assert "transaction.source" in text


def test_standard_policy_is_not_the_mission_policy():
    # No policy stated and nothing but the tuple selected: the CFDP standard receiver. Data before
    # Metadata counts, nothing is dropped for the file size, the first EOF of any kind is the EOF.
    cfg = {"stream": {"framing": "space-packet"}, "packet": {"apid": APID},
           "transaction": {"source": SRC, "sequence": SEQ, "destination": DST}}
    rec = cfdp.reconstruct(_mission(), cfdp.parse_filter(cfg))
    assert rec.metadata["unit"] == 3 and rec.eof["unit"] == 16
    assert rec.coverage == ((0, 100),)
    assert rec.naks == () and "complete" in rec.reason


# ------------------------------------------------------------- one selection key at a time
def _variant_stream(variant: bytes, packet_kw=None) -> bytes:
    return b"".join([_sp(_metadata(30)), _sp(_filedata(0, 10)), _sp(variant, **(packet_kw or {})),
                     _sp(_eof(30))])


FLAG_VARIANTS = {
    "version": dict(version=0), "direction": dict(to_sender=1), "mode": dict(unack=1),
    "crc": dict(crc=1), "large_file": dict(large=1),
}
IDENTITY_VARIANTS = {
    "entity_id_length": dict(idlen=2), "sequence_number_length": dict(seqlen=2),
    "source": dict(src=0x12), "sequence": dict(seq=0x2D), "destination": dict(dst=0x06),
}


@pytest.mark.parametrize("key", sorted(FLAG_VARIANTS))
def test_each_header_flag_is_selected_on_only_when_stated(key):
    raw = _variant_stream(_filedata(10, 10, **FLAG_VARIANTS[key]))
    stated = cfdp.reconstruct(raw, _flt(transaction=dict(TRANSACTION)))
    assert stated.missing == ((10, 30),) and stated.discards == {f"transaction.{key}": 1}
    unstated = cfdp.reconstruct(raw, _flt(transaction=_without(TRANSACTION, key)))
    assert unstated.missing == ((20, 30),) and unstated.discards == {}


@pytest.mark.parametrize("key", sorted(IDENTITY_VARIANTS))
def test_each_identity_field_is_selected_on_and_ambiguous_when_not_stated(key):
    raw = _variant_stream(_filedata(10, 10, **IDENTITY_VARIANTS[key]))
    stated = cfdp.reconstruct(raw, _flt(transaction=dict(TRANSACTION)))
    assert stated.missing == ((10, 30),) and stated.discards == {f"transaction.{key}": 1}
    with pytest.raises(cfdp.AmbiguousTransaction, match="2 transactions"):
        cfdp.reconstruct(raw, _flt(transaction=_without(TRANSACTION, key)))


@pytest.mark.parametrize("key, packet_kw", [
    ("pvn", dict(pvn=1)), ("type", dict(tc=1)), ("secondary_header", dict(sec=1)),
    ("apid", dict(apid=0x2A6)), ("sequence_flags", dict(flags=0)),
])
def test_each_packet_field_is_selected_on_only_when_stated(key, packet_kw):
    raw = _variant_stream(_filedata(10, 10), packet_kw)
    stated = cfdp.reconstruct(raw, _flt(packet=dict(PACKET)))
    assert stated.missing == ((10, 30),) and stated.discards == {f"packet.{key}": 1}
    unstated = cfdp.reconstruct(raw, _flt(packet=_without(PACKET, key)))
    assert unstated.missing == ((20, 30),) and unstated.discards == {}


def test_segment_metadata_flag_is_a_file_data_rule():
    raw = _variant_stream(_filedata(10, 10, segmeta=1, prefix=bytes([0x02, 0xAA, 0xBB])))
    stated = cfdp.reconstruct(raw, _flt(file_data={"segment_metadata": False}))
    assert stated.missing == ((10, 30),) and stated.discards == {"file_data.segment_metadata": 1}
    assert cfdp.reconstruct(raw, _flt()).missing == ((20, 30),)       # offset read after the metadata
    only = cfdp.reconstruct(raw, _flt(file_data={"segment_metadata": True}))
    assert only.missing == ((0, 10), (20, 30))


@pytest.mark.parametrize("key, want, bad", [
    ("checksum_type", 15, dict(checksum_type=2)),
    ("closure_requested", False, dict(closure=1)),
    ("options", False, dict(options=bytes([0x02, 0x01, 0x41]))),
])
def test_each_metadata_rule_decides_which_metadata_is_accepted(key, want, bad):
    raw = b"".join([_sp(_metadata(50, **bad)), _sp(_metadata(30)), _sp(_filedata(0, 10)), _sp(_eof(30))])
    stated = cfdp.reconstruct(raw, _flt(metadata={key: want}, nak={"scope_end": "metadata"}))
    assert stated.metadata["file_size"] == 30 and stated.discards == {f"metadata.{key}": 1}
    assert stated.missing == ((10, 30),)
    unstated = cfdp.reconstruct(raw, _flt(nak={"scope_end": "metadata"}))
    assert unstated.metadata["file_size"] == 50 and unstated.discards == {"metadata.later": 1}
    assert unstated.missing == ((10, 50),)


def test_a_stated_true_requires_the_option_or_fault_location_to_be_there():
    raw = b"".join([_sp(_metadata(50)), _sp(_metadata(30, options=bytes([0x02, 0x00]))),
                    _sp(_filedata(0, 10)), _sp(_eof(30)),
                    _sp(_eof(30, cc=4, fault=bytes([6, 1, SRC])))])
    rec = cfdp.reconstruct(raw, _flt(metadata={"options": True}, eof={"fault_location": True}))
    assert rec.metadata["unit"] == 1 and rec.eof["unit"] == 4
    assert rec.discards == {"metadata.options": 1, "eof.fault_location": 1}


@pytest.mark.parametrize("key, want, bad, missing_unstated", [
    ("condition_code", 0, dict(cc=2), [(10, 30)]),
    ("spare", 0, dict(spare=1), [(10, 30)]),
    ("checksum", 0, dict(checksum=1), [(10, 30)]),
    ("fault_location", False, dict(fault=bytes([6, 1, SRC])), [(10, 30)]),
    ("file_size", 30, dict(size=25), [(10, 25)]),
    ("file_size", "metadata", dict(size=25), [(10, 25)]),
])
def test_each_eof_rule_decides_which_eof_is_accepted(key, want, bad, missing_unstated):
    bad = dict(bad)
    raw = b"".join([_sp(_metadata(30)), _sp(_filedata(0, 10)), _sp(_eof(bad.pop("size", 30), **bad)),
                    _sp(_filedata(10, 10)), _sp(_eof(30))])
    stated = cfdp.reconstruct(raw, _flt(eof={key: want}))
    assert stated.eof["unit"] == 4 and stated.missing == ((20, 30),)
    assert stated.discards == {f"eof.{key}": 1}
    unstated = cfdp.reconstruct(raw, _flt())
    assert unstated.eof["unit"] == 2 and list(unstated.missing) == missing_unstated
    assert unstated.discards == {"file_data.after_eof": 1, "eof.later": 1}


def test_eof_size_equal_to_metadata_needs_an_accepted_metadata():
    raw = b"".join([_sp(_filedata(0, 10)), _sp(_eof(30))])
    rec = cfdp.reconstruct(raw, _flt(eof={"file_size": "metadata"}))
    assert rec.eof is None and rec.discards == {"eof.file_size": 1} and "no EOF was accepted" in rec.reason


def test_metadata_first_drops_the_eof_too():
    raw = b"".join([_sp(_filedata(0, 10)), _sp(_eof(30)), _sp(_metadata(30)), _sp(_filedata(10, 5)),
                    _sp(_eof(30))])
    rec = cfdp.reconstruct(raw, _flt(policy={"metadata_first": True}))
    assert rec.eof["unit"] == 4 and rec.missing == ((0, 10), (15, 30))
    assert rec.discards == {"file_data.before_metadata": 1, "eof.before_metadata": 1}
    std = cfdp.reconstruct(raw, _flt())
    assert std.eof["unit"] == 1 and std.missing == ((10, 30),)


def test_beyond_file_size_needs_the_whole_segment_inside():
    raw = b"".join([_sp(_metadata(30)), _sp(_filedata(20, 10)), _sp(_filedata(0, 31)), _sp(_eof(30))])
    rec = cfdp.reconstruct(raw, _flt(policy={"beyond_file_size": "discard"}))
    assert rec.coverage == ((20, 30),)                    # end == size is inside, end == size + 1 is not
    assert rec.discards == {"file_data.beyond_file_size": 1}


# ------------------------------------------------------------------------------------ NAK options
def test_no_eof_means_no_nak_unless_the_scope_is_stated_otherwise():
    raw = b"".join([_sp(_metadata(30)), _sp(_filedata(0, 10))])
    rec = cfdp.reconstruct(raw, _flt())
    assert rec.naks == () and rec.scope is None and "no EOF was accepted" in rec.reason
    assert rec.coverage == ((0, 10),)                     # the coverage is still reported
    by_metadata = cfdp.reconstruct(raw, _flt(nak={"scope_end": "metadata"}))
    assert by_metadata.missing == ((10, 30),) and len(by_metadata.naks) == 1
    by_count = cfdp.reconstruct(raw, _flt(nak={"scope_end": 12, "scope_start": 4}))
    assert by_count.scope == (4, 12) and by_count.missing == ((10, 12),)
    assert by_count.naks[0].hex() == "28001100112c0508" "00000004" "0000000c" "0000000a0000000c"
    no_md = cfdp.reconstruct(_stream(_filedata(0, 10)), _flt(nak={"scope_end": "metadata"}))
    assert no_md.naks == () and "no Metadata was accepted" in no_md.reason


def test_scope_start_past_the_file_size_is_a_named_reason():
    raw = b"".join([_sp(_metadata(30)), _sp(_filedata(0, 10)), _sp(_eof(30))])
    rec = cfdp.reconstruct(raw, _flt(nak={"scope_start": 31}))
    assert rec.naks == () and "scope_start 31 is past" in rec.reason


def test_complete_coverage_sends_no_nak():
    raw = b"".join([_sp(_metadata(30)), _sp(_filedata(0, 20)), _sp(_filedata(20, 10)), _sp(_eof(30))])
    rec = cfdp.reconstruct(raw, _flt())
    assert rec.naks == () and rec.missing == () and "complete" in rec.reason
    assert rec.scope == (0, 30)


def test_missing_metadata_is_requested_by_default_and_not_when_told():
    raw = b"".join([_sp(_filedata(0, 10)), _sp(_eof(30))])
    std = cfdp.reconstruct(raw, _flt())
    assert std.requests == ((0, 0), (10, 30)) and std.missing == ((10, 30),)
    assert std.naks[0].hex() == ("28001900112c0508" "00000000" "0000001e" "0000000000000000"
                                 "0000000a0000001e")
    told = cfdp.reconstruct(raw, _flt(nak={"request_metadata": False}))
    assert told.requests == ((10, 30),)
    whole = b"".join([_sp(_filedata(0, 30)), _sp(_eof(30))])
    assert cfdp.reconstruct(whole, _flt()).requests == ((0, 0),)           # only the Metadata is missing
    assert cfdp.reconstruct(whole, _flt(nak={"request_metadata": False})).naks == ()


def test_nak_header_copies_the_transaction_and_takes_stated_overrides():
    kw = dict(idlen=2, seqlen=3, src=0x0A0B, seq=0x010203, dst=0x0C0D, unack=1, large=1)
    raw = b"".join([_sp(_metadata(30, **kw)), _sp(_filedata(0, 10, **kw)), _sp(_eof(30, **kw))])
    rec = cfdp.reconstruct(raw, _flt())
    # 2d: version 1, directive, toward sender, unacknowledged, large file (copied from the EOF).
    assert rec.naks[0].hex() == ("2d" "0021" "12" "0a0b" "010203" "0c0d" "08" "0000000000000000"
                                 "000000000000001e" "000000000000000a" "000000000000001e")
    over = cfdp.reconstruct(raw, _flt(nak={"direction": "toward-receiver", "mode": "acknowledged",
                                           "large_file": False, "crc": True}))
    nak = over.naks[0]
    assert nak[0] == 0x22 and int.from_bytes(nak[1:3], "big") == 19
    assert nak[-2:] == struct.pack(">H", ccsds.crc16_fecf(nak[:-2]))


def test_a_nak_that_cannot_be_serialised_is_a_named_reason():
    kw = dict(large=1)
    raw = b"".join([_sp(_metadata(2 ** 33, **kw)), _sp(_filedata(0, 10, **kw)), _sp(_eof(2 ** 33, **kw))])
    rec = cfdp.reconstruct(raw, _flt(nak={"large_file": False}))
    assert rec.naks == () and "cannot be serialised" in rec.reason and "4 octet" in rec.reason
    assert rec.missing == ((10, 2 ** 33),)


def test_max_segment_requests_splits_into_a_chained_nak_sequence():
    pieces = [_sp(_metadata(100))] + [_sp(_filedata(o, 5)) for o in (10, 30, 50, 70, 90)] + [_sp(_eof(100))]
    raw = b"".join(pieces)
    missing = [(0, 10), (15, 30), (35, 50), (55, 70), (75, 90), (95, 100)]
    rec = cfdp.reconstruct(raw, _flt(nak={"max_segment_requests": 4}))
    assert list(rec.missing) == missing and len(rec.naks) == 2
    first, second = (cfdp.parse_pdu(n).fields for n in rec.naks)
    assert (first["scope_start"], first["scope_end"]) == (0, 70) and first["segment_requests"] == missing[:4]
    assert (second["scope_start"], second["scope_end"]) == (70, 100)
    assert second["segment_requests"] == missing[4:]
    whole = cfdp.reconstruct(raw, _flt(nak={"max_segment_requests": 6}))
    assert len(whole.naks) == 1 and cfdp.parse_pdu(whole.naks[0]).fields["scope_end"] == 100


def test_the_last_nak_scope_ends_at_the_file_size_even_when_the_last_gap_is_interior():
    # Coverage reaches the EOF size, so the last missing range ends before the scope does: the
    # (last) NAK's scope still ends at the EOF file size, not at its last request.
    raw = b"".join([_sp(_metadata(30)), _sp(_filedata(0, 10)), _sp(_filedata(20, 10)), _sp(_eof(30))])
    rec = cfdp.reconstruct(raw, _flt())
    assert rec.missing == ((10, 20),) and rec.scope == (0, 30) and len(rec.naks) == 1
    f = cfdp.parse_pdu(rec.naks[0]).fields
    assert (f["scope_start"], f["scope_end"]) == (0, 30) and f["segment_requests"] == [(10, 20)]
    assert rec.naks[0].hex() == "28001100112c0508" "00000000" "0000001e" "0000000a00000014"
    # Split into a sequence: the first NAK ends at its last request, the last at the file size.
    raw2 = b"".join([_sp(_metadata(40)), _sp(_filedata(0, 5)), _sp(_filedata(10, 5)),
                     _sp(_filedata(20, 20)), _sp(_eof(40))])
    seq = cfdp.reconstruct(raw2, _flt(nak={"max_segment_requests": 1}))
    assert seq.missing == ((5, 10), (15, 20)) and len(seq.naks) == 2
    scopes = [(p["scope_start"], p["scope_end"]) for p in (cfdp.parse_pdu(n).fields for n in seq.naks)]
    assert scopes == [(0, 10), (10, 40)]


def test_a_metadata_only_request_nak_scopes_the_whole_file():
    # Every byte arrived and only the Metadata is missing: the sole request is (0, 0), and the NAK's
    # scope is the whole file [0, EOF size), not (0, 0).
    raw = b"".join([_sp(_filedata(0, 30)), _sp(_eof(30))])
    rec = cfdp.reconstruct(raw, _flt())
    assert rec.requests == ((0, 0),) and rec.missing == () and len(rec.naks) == 1
    f = cfdp.parse_pdu(rec.naks[0]).fields
    assert (f["scope_start"], f["scope_end"]) == (0, 30) and f["segment_requests"] == [(0, 0)]


def test_bare_pdu_framing_reconstructs_the_same_nak():
    pdus = [_metadata(30), _filedata(0, 10), _eof(30)]
    bare = cfdp.reconstruct(b"".join(pdus), cfdp.parse_filter({"stream": {"framing": "cfdp-pdu"}}))
    packed = cfdp.reconstruct(_stream(*pdus), _flt())
    assert bare.naks == packed.naks and len(bare.naks) == 1 and bare.missing == ((10, 30),)


def test_no_pdu_passing_the_filter_is_a_named_reason():
    rec = cfdp.reconstruct(_stream(_metadata(30), _eof(30)), _flt(transaction={"source": 0x77}))
    assert rec.naks == () and rec.reason == "no PDU passed the filter" and rec.selected == 0
    assert rec.transaction is None


def test_to_dict_is_json_and_caps_the_range_lists():
    rec = cfdp.reconstruct(_mission(), cfdp.parse_filter(_strict()))
    d = json.loads(json.dumps(rec.to_dict(ranges=2)))
    assert d["missing_ranges"] == 3 and d["missing"] == [[0, 4], [40, 50]]
    assert d["naks_hex"] == [n.hex() for n in rec.naks] and d["scope"] == [0, 96]


# ------------------------------------------------------------------------------------ filter config
@pytest.mark.parametrize("cfg, why", [
    ({}, "stream.framing is required"),
    ({"stream": {"framing": "tm-frame"}}, "stream.framing: expected one of"),
    ({"stream": {"framing": "space-packet"}, "relay": {}}, r"unknown section \[relay\]"),
    ({"stream": {"framing": "space-packet", "resync": True}}, "unknown key stream.resync"),
    ({"stream": {"framing": "space-packet"}, "packet": {"apid": 0x800}}, "packet.apid"),
    ({"stream": {"framing": "space-packet"}, "packet": {"apid": []}}, "packet.apid"),
    ({"stream": {"framing": "space-packet"}, "packet": {"apid": "0x2A5"}}, "packet.apid"),
    ({"stream": {"framing": "space-packet"}, "packet": {"secondary_header": 0}}, "packet.secondary_header"),
    ({"stream": {"framing": "space-packet"}, "packet": {"pvn": True}}, "packet.pvn"),
    ({"stream": {"framing": "space-packet"}, "packet": {"type": "telemetry"}}, "packet.type"),
    ({"stream": {"framing": "cfdp-pdu"}, "packet": {"apid": 1}}, r"\[packet\] selects Space Packets"),
    ({"stream": {"framing": "space-packet"}, "transaction": {"version": 2}}, "transaction.version"),
    ({"stream": {"framing": "space-packet"}, "transaction": {"entity_id_length": 9}}, "entity_id_length"),
    ({"stream": {"framing": "space-packet"}, "transaction": {"mode": "ack"}}, "transaction.mode"),
    ({"stream": {"framing": "space-packet"}, "metadata": {"checksum_type": 16}}, "metadata.checksum_type"),
    ({"stream": {"framing": "space-packet"}, "eof": {"file_size": "eof"}}, "eof.file_size"),
    ({"stream": {"framing": "space-packet"}, "eof": {"file_size": True}}, "eof.file_size"),
    ({"stream": {"framing": "space-packet"}, "policy": {"beyond_file_size": "clip"}}, "policy.beyond_file_size"),
    ({"stream": {"framing": "space-packet"}, "policy": {"metadata_first": "yes"}}, "policy.metadata_first"),
    ({"stream": {"framing": "space-packet"}, "nak": {"scope_end": "file"}}, "nak.scope_end"),
    ({"stream": {"framing": "space-packet"}, "nak": {"scope_end": -1}}, "nak.scope_end"),
    ({"stream": {"framing": "space-packet"}, "nak": {"scope_start": 5, "scope_end": 4}}, "scope_start is past"),
    ({"stream": {"framing": "space-packet"}, "nak": {"max_segment_requests": 0}}, "nak.max_segment_requests"),
    ({"stream": {"framing": "space-packet"}, "output": {"encoding": "hex-upper"}}, "output.wrap is required"),
    ({"stream": {"framing": "space-packet"}, "output": {"wrap": "flag"}}, "output.encoding is required"),
    ({"stream": {"framing": "space-packet"}, "output": {"encoding": "hex", "wrap": "flag"}}, "output.encoding"),
    ({"stream": {"framing": "space-packet"}, "output": {"encoding": "base64", "wrap": "flag",
                                                        "prefix": "A{"}}, "output.prefix"),
    ({"stream": {"framing": "space-packet"}, "output": {"encoding": "base64", "wrap": "none",
                                                        "prefix": "A"}}, "no meaning"),
    ({"stream": {"framing": "space-packet", "file": ""}}, "stream.file"),
    ({"stream": "space-packet"}, r"\[stream\] must be a table"),
    ([], "a filter is a table"),
])
def test_a_bad_filter_names_the_key(cfg, why):
    with pytest.raises(cfdp.FilterError, match=why):
        cfdp.parse_filter(cfg, source="f.toml")


def test_filter_defaults_are_the_cfdp_standard_and_only_stated_keys_select():
    flt = _flt(packet={"apid": 7})
    assert flt.policy == {"metadata_first": False, "beyond_file_size": "keep", "eof_snapshot": True}
    assert flt.nak == {"scope_start": 0, "scope_end": "eof", "direction": "toward-sender",
                       "request_metadata": True}
    assert flt.packet == {"apid": (7,)} and flt.transaction == {} and flt.output is None
    assert flt.stated()["packet"] == {"apid": [7]} and "output" not in flt.stated()


def test_load_filter_reads_toml_and_names_a_bad_file(tmp_path):
    good = tmp_path / "f.toml"
    good.write_text('[stream]\nframing = "cfdp-pdu"\n[transaction]\nsource = 0x11\n[nak]\nscope_end = 40\n')
    flt = cfdp.load_filter(good)
    assert flt.framing == "cfdp-pdu" and flt.transaction == {"source": 0x11} and flt.nak["scope_end"] == 40
    assert flt.source == str(good)
    bad = tmp_path / "bad.toml"
    bad.write_text("[stream\n")
    with pytest.raises(cfdp.FilterError, match="not valid TOML"):
        cfdp.load_filter(bad)
    with pytest.raises(cfdp.FilterError, match="cannot read"):
        cfdp.load_filter(tmp_path / "absent.toml")
    wrong = tmp_path / "wrong.toml"
    wrong.write_text('[stream]\nframing = "space-packet"\n[policy]\nmetadata_first = 1\n')
    with pytest.raises(cfdp.FilterError, match=r"wrong\.toml: policy\.metadata_first"):
        cfdp.load_filter(wrong)


def test_the_documented_example_filter_loads_and_states_every_section():
    text = (REPO / "docs" / "toolkits" / "sec_space_cfdp.md").read_text(encoding="utf-8")
    block = re.search(r"```toml\n(.*?)```", text, re.S).group(1)
    data = tomllib.loads(block)
    flt = cfdp.parse_filter(data)
    assert set(data) == set(cfdp.SCHEMA)                  # the page shows every section
    for section, keys in cfdp.SCHEMA.items():             # and every key, live or commented out
        for key in keys:
            assert re.search(rf"^#? ?{key}\b|# .*\b{key}\b", block, re.M), f"{section}.{key} is not on the page"
    assert flt.policy["metadata_first"] is True and flt.output == {"encoding": "hex-upper", "wrap": "flag"}


# ------------------------------------------------------------------------------- survey / skeleton
def test_survey_lists_each_selection_with_its_coverage_and_standard_nak():
    got = cfdp.survey(_mission())
    assert got["framing"] == "space-packet" and got["units"] == 23
    assert got["cfdp_units"] == 22 and got["other_units"] == 1
    rows = got["rows"]
    idents = [(r["packet"]["apid"], r["packet"]["type"], r["packet"]["sequence_flags"],
               r["transaction"]["source"], r["transaction"]["direction"]) for r in rows]
    assert idents == [
        (0x012, "tm", 3, SRC, "toward-receiver"), (APID, "tm", 3, 0x33, "toward-receiver"),
        (APID, "tm", 3, SRC, "toward-receiver"), (APID, "tc", 3, SRC, "toward-receiver"),
        (APID, "tm", 1, SRC, "toward-receiver"), (APID, "tm", 3, SRC, "toward-sender")]
    decoy, other, target, tc, segmented, ack = rows
    assert decoy["pdus"] == {"metadata": 1} and decoy["file_size"] == 64 and decoy["file_size_from"] == "metadata"
    assert decoy["missing"] == [(0, 64)] and decoy["standard_nak_hex"] is None     # no EOF, no deferred NAK
    assert other["pdus"] == {"file-data": 1} and other["file_size"] is None and other["missing"] == []
    assert other["covered_bytes"] == 96 and other["first_unit"] == 1
    # File Data units 2, 6-12, 18 and 20 (12 has segmentation control: not a survey key; 13 is malformed)
    assert target["pdus"] == {"eof": 4, "file-data": 10, "metadata": 3}
    assert target["file_size"] == 80 and target["file_size_from"] == "eof"         # the first EOF, standard policy
    assert target["coverage"] == [(0, 70), (90, 100)]          # units 18 and 20 come after the first EOF
    assert target["missing"] == [(70, 80)] and target["missing_bytes"] == 10
    assert target["standard_nak_hex"] == "28001100112c0508" "00000000" "00000050" "0000004600000050"
    assert tc["covered_bytes"] == 20 and segmented["covered_bytes"] == 10
    assert ack["pdus"] == {"ack": 1}


def test_survey_detects_bare_pdu_streams_and_rejects_everything_else():
    bare = b"".join([_metadata(30), _filedata(0, 10), _eof(30)])
    got = cfdp.survey(bare)
    assert got["framing"] == "cfdp-pdu" and len(got["rows"]) == 1
    assert got["rows"][0]["packet"] is None and got["rows"][0]["missing"] == [(10, 30)]
    assert cfdp.detect_framing(_stream(_metadata(30))) == "space-packet"
    for junk in (b"just some text in a readme\n", bytes(range(256)), _sp(bytes(40)) + _sp(bytes(9)),
                 b"PK\x03\x04" + bytes(60)):
        with pytest.raises(cfdp.CfdpError, match="no CFDP found"):
            cfdp.survey(junk)
    with pytest.raises(cfdp.CfdpError, match="truncated"):
        cfdp.survey(bare[:-1], framing="cfdp-pdu")          # a stated framing is not second-guessed


def test_skeleton_selects_exactly_its_row_under_the_standard_policy():
    got = cfdp.survey(_mission())
    target = got["rows"][2]
    text = cfdp.skeleton(target, got["framing"])
    data = tomllib.loads(text)
    assert data["packet"] == {"pvn": 0, "type": "tm", "secondary_header": False, "apid": APID,
                              "sequence_flags": 3}
    assert data["transaction"] == TRANSACTION
    assert data["policy"] == cfdp.STANDARD_POLICY and data["nak"] == cfdp.STANDARD_NAK
    assert "output" not in data and "# [output]" in text           # the format is the reader's to state
    rec = cfdp.reconstruct(_mission(), cfdp.parse_filter(data))
    assert [n.hex() for n in rec.naks] == [target["standard_nak_hex"]]
    bare = cfdp.survey(_metadata(30, idlen=2, src=0x0A0B, dst=0x0C0D) + _eof(30, idlen=2, src=0x0A0B, dst=0x0C0D))
    data = tomllib.loads(cfdp.skeleton(bare["rows"][0], bare["framing"]))
    assert "packet" not in data and data["stream"] == {"framing": "cfdp-pdu"}
    assert data["transaction"]["source"] == 0x0A0B and data["transaction"]["entity_id_length"] == 2


# ----------------------------------------------------------------------------------------- output
NAK = bytes.fromhex("28001900112c0508000000000000006000000005000000060000001300000020")


def test_output_takes_the_flag_lead_from_the_event_profile():
    value, ok, note = cfdp.render_output(NAK, {"encoding": "hex-upper", "wrap": "flag"}, _profile())
    assert value == "TESTCTF{" + NAK.hex().upper() + "}" and ok is True and "in the event" in note
    other = cfdp.render_output(NAK, {"encoding": "hex-upper", "wrap": "flag"}, _profile(("zeta", "TESTCTF")))
    assert other[0].startswith("zeta{")                    # the profile's first prefix, not a constant


@pytest.mark.parametrize("encoding, body", [
    ("hex-upper", NAK.hex().upper()), ("hex-lower", NAK.hex()),
    ("base64", base64.b64encode(NAK).decode()),
])
def test_output_encodings_and_bare_wrap(encoding, body):
    assert cfdp.render_output(NAK, {"encoding": encoding, "wrap": "flag"}, _profile())[0] == f"TESTCTF{{{body}}}"
    bare, ok, _ = cfdp.render_output(NAK, {"encoding": encoding, "wrap": "none"}, _profile())
    assert bare == body and ok is False
    assert NAK.hex().upper() != NAK.hex()                  # the two hex cases really differ here


def test_output_says_when_the_stated_format_is_not_the_events():
    out = {"encoding": "hex-upper", "wrap": "flag"}
    long_nak = NAK + bytes(200)                            # 464 hex digits: over the default 256 body
    value, ok, note = cfdp.render_output(long_nak, out, _profile())
    assert value.startswith("TESTCTF{") and ok is False and "NOT in the event" in note
    stated, ok, _ = cfdp.render_output(NAK, {**out, "prefix": "handout"}, _profile())
    assert stated == "handout{" + NAK.hex().upper() + "}" and ok is False
    narrow = _profile(body="[0-9a-f]{1,256}")              # an event whose body is lower-case hex only
    assert cfdp.render_output(NAK, out, narrow)[1] is False
    assert cfdp.render_output(NAK, {"encoding": "hex-lower", "wrap": "flag"}, narrow)[1] is True


def test_output_without_a_profile_or_a_known_prefix_fails_by_name():
    out = {"encoding": "hex-upper", "wrap": "flag"}
    with pytest.raises(cfdp.OutputError, match="event profile"):
        cfdp.render_output(NAK, out, None)
    with pytest.raises(cfdp.OutputError, match="no known flag prefix"):
        cfdp.render_output(NAK, out, _profile(()))
    value, ok, note = cfdp.render_output(NAK, {**out, "prefix": "X"}, None)
    assert value.startswith("X{") and ok is None and "not checked" in note
    assert cfdp.render_output(NAK, {**out, "prefix": "X"}, _profile(()))[0].startswith("X{")


# ---------------------------------------------------------------------------------------- solve()
MISSION_NAK = "28002100112c0508" "00000000" "00000060" "0000000000000004" "0000002800000032" "0000004800000060"


def _toml(cfg: dict) -> str:
    def value(v):
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, list):
            return "[" + ", ".join(value(x) for x in v) + "]"
        return json.dumps(v)
    return "\n".join(f"[{name}]\n" + "\n".join(f"{k} = {value(v)}" for k, v in table.items()) + "\n"
                     for name, table in cfg.items())


def _challenge(tmp_path: Path, *, cfg: dict | None = None) -> Path:
    root = tmp_path / "77-relay"
    (root / "files").mkdir(parents=True)
    (root / "unpacked" / "handout.zip.unpacked").mkdir(parents=True)
    (root / "recon").mkdir()
    (root / "files" / "handout.zip").write_bytes(b"PK\x03\x04" + bytes(40))
    (root / "unpacked" / "handout.zip.unpacked" / "downlink.bin").write_bytes(_mission())
    (root / "unpacked" / "handout.zip.unpacked" / "README.txt").write_text("read the profile\n")
    (root / "recon" / "copy.bin").write_bytes(_mission())          # intake output: never a handout
    (root / "notes.md").write_text("# relay\n")
    if cfg is not None:
        (root / cfdp.FILTER_NAME).write_text(_toml(cfg))
    return root


def test_solve_without_a_filter_surveys_and_is_unsure(tmp_path):
    root = _challenge(tmp_path)
    res = cfdp.solve(root, _profile())
    assert isinstance(res, SolverResult) and res.status == "unsure" and res.flags == ()
    assert res.engine == "toolkits.sec_space_cfdp"
    paths = {e.path for e in res.evidence}
    assert paths == {"unpacked/handout.zip.unpacked/downlink.bin"}            # not recon/, not the zip
    details = [e.detail for e in res.evidence]
    assert "23 unit(s), 22 carry a whole CFDP PDU, 6 distinct" in details[0]
    target = next(d for d in details if "0x11/0x2c/0x05 on APID 0x2a5" in d and "4 eof" in d)
    assert "file size 80 (from eof)" in target and "missing 10 byte(s) in 1 range(s): [70,80)" in target
    assert "standard-policy NAK 28001100112c0508" in target
    assert any("0x33/0x09/0x05" in d and "no Metadata or EOF" in d for d in details)
    assert cfdp.FILTER_NAME in res.notes and "not an answer" in res.notes
    assert MISSION_NAK.upper() not in res.to_json().upper()                   # no mission answer was guessed


def test_solve_with_a_filter_and_output_returns_the_candidate(tmp_path):
    root = _challenge(tmp_path, cfg=_strict(output={"encoding": "hex-upper", "wrap": "flag"}))
    res = cfdp.solve(root, _profile())
    assert res.status == "candidate"
    assert res.flags == ("TESTCTF{" + MISSION_NAK.upper() + "}",)
    details = [e.detail for e in res.evidence]
    assert any(d == f"NAK PDU: {MISSION_NAK}" for d in details)
    assert any("missing 38 byte(s) in 3 range(s): [0,4) [40,50) [72,96)" in d for d in details)
    assert any("Metadata at unit 4 (file size 96)" in d and "EOF at unit 19" in d
               and "1 file_data.before_metadata" in d for d in details)
    assert '"metadata_first": true' in res.notes and "in the event's flag format" in res.notes
    lower = _challenge(tmp_path / "b", cfg=_strict(output={"encoding": "hex-lower", "wrap": "none"}))
    assert cfdp.solve(lower, _profile()).flags == (MISSION_NAK,)


def test_solve_with_a_filter_but_no_output_reports_hex_and_is_unsure(tmp_path):
    root = _challenge(tmp_path, cfg=_strict())
    res = cfdp.solve(root, _profile())
    assert res.status == "unsure" and res.flags == ()
    assert any(e.detail == f"NAK PDU: {MISSION_NAK}" for e in res.evidence)
    assert "states no [output] format" in res.notes


def test_solve_names_what_stops_the_rendering(tmp_path):
    root = _challenge(tmp_path, cfg=_strict(output={"encoding": "hex-upper", "wrap": "flag"}))
    res = cfdp.solve(root, _profile(()))                    # an event whose prefix is not known yet
    assert res.status == "unsure" and res.flags == ()
    assert "built but not rendered" in res.notes and "state output.prefix" in res.notes


def test_solve_takes_filter_and_file_options(tmp_path):
    root = _challenge(tmp_path)
    elsewhere = tmp_path / "mine.toml"
    elsewhere.write_text(_toml(_strict(output={"encoding": "hex-lower", "wrap": "flag", "prefix": "relay"})))
    res = cfdp.solve(root, _profile(), filter=str(elsewhere))
    assert res.status == "candidate" and res.flags == (f"relay{{{MISSION_NAK}}}",)
    assert "NOT in the event" in res.notes
    other = dict(src=0x77)                                     # another transaction: the filter drops it
    (root / "second.bin").write_bytes(_stream(_metadata(30, **other), _filedata(0, 10, **other),
                                              _eof(30, **other)))
    both = cfdp.solve(root, _profile(), filter=str(elsewhere))
    assert both.flags == (f"relay{{{MISSION_NAK}}}",)
    assert "second.bin: no NAK: no PDU passed the filter" in both.notes
    (root / "third.bin").write_bytes(_stream(_metadata(30), _filedata(0, 10), _eof(30)))
    three = cfdp.solve(root, _profile(), filter=str(elsewhere))
    # each capture that yields a NAK is its own candidate, in sorted path order (third.bin < unpacked/)
    assert three.flags == ("relay{28001100112c0508" "00000000" "0000001e" "0000000a0000001e}",
                           f"relay{{{MISSION_NAK}}}")
    (root / "third.bin").unlink()
    one = cfdp.solve(root, _profile(), filter=str(elsewhere), file="second.bin")
    assert one.status == "none" and "no PDU passed the filter" in one.notes
    recon = cfdp.solve(root, _profile(), filter=str(elsewhere), file="recon/copy.bin")
    assert recon.flags == (f"relay{{{MISSION_NAK}}}",)                        # a named file is always read


def test_solve_honours_stream_file_in_the_filter(tmp_path):
    cfg = _strict(output={"encoding": "hex-upper", "wrap": "flag"})
    cfg["stream"] = {"framing": "space-packet", "file": "down*.bin"}
    root = _challenge(tmp_path, cfg=cfg)
    (root / "other.bin").write_bytes(_stream(_metadata(30), _filedata(0, 10), _eof(30)))
    res = cfdp.solve(root, _profile())
    assert res.status == "candidate" and "other.bin" not in res.notes
    cfg["stream"]["file"] = "nothing*"
    (root / cfdp.FILTER_NAME).write_text(_toml(cfg))
    blocked = cfdp.solve(root, _profile())
    assert blocked.status == "blocked" and "stream.file = 'nothing*'" in blocked.notes


def test_solve_blocked_on_a_bad_filter_missing_paths_and_unknown_options(tmp_path):
    root = _challenge(tmp_path)
    (root / cfdp.FILTER_NAME).write_text('[stream]\nframing = "space-packet"\n[relay]\nx = 1\n')
    bad = cfdp.solve(root, _profile())
    assert bad.status == "blocked" and "unknown section [relay]" in bad.notes
    assert cfdp.solve(root, _profile(), filter="absent.toml").status == "blocked"
    assert "absent.toml does not exist" in cfdp.solve(root, _profile(), filter="absent.toml").notes
    (root / cfdp.FILTER_NAME).unlink()
    gone = cfdp.solve(root, _profile(), file="nope.bin")
    assert gone.status == "blocked" and "nope.bin does not exist" in gone.notes
    odd = cfdp.solve(root, _profile(), fliter="x")
    assert odd.status == "blocked" and "fliter" in odd.notes
    assert cfdp.solve(tmp_path / "absent", _profile()).status == "blocked"


def test_solve_file_option_must_stay_inside_the_challenge_folder(tmp_path):
    cfg = _strict(output={"encoding": "hex-lower", "wrap": "none"})
    root = _challenge(tmp_path, cfg=cfg)
    outside = tmp_path / "outside.bin"                         # a real capture, one level up
    outside.write_bytes(_mission())
    (root / "link.bin").symlink_to(outside)
    for name in ("../outside.bin", str(outside), "link.bin", "files/../../outside.bin"):
        res = cfdp.solve(root, _profile(), file=name)
        assert res.status == "blocked", name
        assert "outside the challenge folder" in res.notes and res.flags == ()
    inside = cfdp.solve(root, _profile(), file="files/../unpacked/handout.zip.unpacked/downlink.bin")
    assert inside.status == "candidate" and inside.flags == (MISSION_NAK,)


def test_cli_run_without_the_ctf_package_names_the_missing_package(tmp_path):
    # `python3 -I script.py` puts only the script's folder on sys.path, so `ctf` is not importable.
    cap = tmp_path / "downlink.bin"
    cap.write_bytes(_mission())
    script = REPO / "solvers" / "toolkits" / "sec_space_cfdp.py"
    env = {"PATH": "/usr/bin:/bin"}

    def run(cfg):
        flt = tmp_path / "f.toml"
        flt.write_text(_toml(cfg))
        return subprocess.run([sys.executable, "-I", str(script), "nak", str(cap), "--filter", str(flt)],
                              capture_output=True, text=True, cwd=tmp_path, env=env)

    flag = run(_strict(output={"encoding": "hex-upper", "wrap": "flag"}))
    assert flag.returncode == 2 and "Traceback" not in flag.stderr
    assert "no event profile for the [output] flag wrapper" in flag.stderr
    assert "ctf package is not importable" in flag.stderr and "tools/ctfpy" in flag.stderr
    assert f"NAK {MISSION_NAK}" not in flag.stdout
    stated = run(_strict(output={"encoding": "hex-lower", "wrap": "flag", "prefix": "relay"}))
    assert stated.returncode == 0 and "Traceback" not in stated.stderr
    assert f"answer relay{{{MISSION_NAK}}}" in stated.stdout and "no event profile" in stated.stdout


def test_solve_ambiguous_filter_is_unsure_and_lists_the_transactions(tmp_path):
    cfg = _strict(transaction={"version": 1})
    root = _challenge(tmp_path, cfg=cfg)
    res = cfdp.solve(root, _profile())
    assert res.status == "unsure" and res.flags == ()
    assert "the filter selects 2 transactions" in res.notes and "0x33/0x09/0x05" in res.notes


def test_solve_none_when_nothing_is_cfdp_or_coverage_is_complete(tmp_path):
    root = tmp_path / "1-empty"
    (root / "files").mkdir(parents=True)
    (root / "files" / "readme.txt").write_text("nothing to see\n")
    (root / "files" / "blob.bin").write_bytes(bytes(range(256)))
    res = cfdp.solve(root, _profile())
    assert res.status == "none" and "no CFDP PDUs in 2 file(s)" in res.notes
    (root / cfdp.FILTER_NAME).write_text('[stream]\nframing = "space-packet"\n')
    filtered = cfdp.solve(root, _profile())
    assert filtered.status == "none" and "no file walks as a space-packet stream" in filtered.notes
    assert "blob.bin: not a space-packet stream" in filtered.notes
    (root / "files" / "whole.bin").write_bytes(_stream(_metadata(30), _filedata(0, 30), _eof(30)))
    complete = cfdp.solve(root, _profile())
    assert complete.status == "none" and "coverage of [0, 30) is complete" in complete.notes


def test_stream_files_skips_duplicates_recon_dotfolders_and_oversize(tmp_path, monkeypatch):
    root = _challenge(tmp_path)
    (root / "files" / "downlink.bin").write_bytes(_mission())                 # the same bytes again
    (root / ".cache").mkdir()
    (root / ".cache" / "x.bin").write_bytes(b"abc")
    (root / "files" / "empty.bin").write_bytes(b"")
    (root / "files" / "big.bin").write_bytes(bytes(64))
    (root / cfdp.FILTER_NAME).write_text('[stream]\nframing = "space-packet"\n')
    monkeypatch.setattr(cfdp, "MAX_STREAM", 60)
    (root / "unpacked" / "handout.zip.unpacked" / "downlink.bin").write_bytes(bytes(50))
    (root / "files" / "downlink.bin").write_bytes(bytes(50))
    files, notes = cfdp.stream_files(root)
    names = [p.relative_to(root).as_posix() for p in files]
    assert names == ["files/downlink.bin", "files/handout.zip", "notes.md",
                     "unpacked/handout.zip.unpacked/README.txt"]
    assert notes == ["files/big.bin not read: 64 bytes is over the 60-byte limit"]


# ------------------------------------------------------------------- manifest, routing and runner
ENGINE = "toolkits.sec_space_cfdp"


def test_manifest_is_a_contract_engine_wired_for_intake():
    m = _manifest.load(REPO / "solvers" / "toolkits" / "sec_space_cfdp.manifest.toml")
    assert m.id == ENGINE == cfdp.ENGINE_ID
    assert m.entry.kind == "function" and m.entry.function == "solve"
    assert m.cost_class == "cheap" and m.status == "active" and m.needs_tools == ()
    assert m.intake is not None and m.intake.select == "route" and m.intake.run == "challenge"
    assert m.intake.spawns is False


def test_routes_cfdp_briefs_first_and_ccsds_briefs_after_the_general_decoder(tmp_path):
    ids = [h.manifest.id for h in router.route("networking", "Reconstruct the CFDP NAK the relay withheld")]
    assert ids[0] == ENGINE
    ccsds_ids = [h.manifest.id for h in router.route("networking", "a modified CCSDS telemetry parser")]
    assert ENGINE in ccsds_ids and "toolkits.sec_space_ccsds" in ccsds_ids
    assert ccsds_ids.index("toolkits.sec_space_ccsds") < ccsds_ids.index(ENGINE)
    assert ENGINE not in [h.manifest.id for h in router.route("networking", "a pcap of an ftp session")]
    (tmp_path / "relay-cfdp.zip").write_bytes(b"PK\x03\x04")
    by_file = [h.manifest.id for h in router.route("misc", "an unlabelled archive", tmp_path)]
    assert ENGINE in by_file


def test_intake_plans_it_for_a_ccsds_brief_and_not_for_an_unrelated_one(tmp_path):
    (tmp_path / "downlink.bin").write_bytes(_mission())
    mans = [m for m in _manifest.discover() if m.id == ENGINE]
    assert mans, "engine not discovered"
    guard = types.SimpleNamespace(allows_spawn=False, reason="hook guard")
    plan = _intake_engines.plan(mans, "networking", "the demodulated ccsds frame stream", tmp_path,
                                guard=guard, max_cost="cheap")
    assert [j.engine for j in plan.jobs] == [ENGINE] and plan.jobs[0].files == ()
    quiet = _intake_engines.plan(mans, "networking", "a wifi handshake", tmp_path, guard=guard)
    assert not quiet.jobs and not quiet.skipped


def test_ctf_run_prints_the_solver_result_for_a_challenge_folder(tmp_path):
    root = _challenge(tmp_path, cfg=_strict(output={"encoding": "hex-upper", "wrap": "flag"}))
    cmd = runner.command(ENGINE, [str(root), "--event", "csctf"], record=False)
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO)
    assert proc.returncode == 0, proc.stderr
    res = SolverResult.from_json(proc.stdout.strip().splitlines()[-1])
    lead = event.load("csctf").flag.prefixes[0]
    assert res.status == "candidate" and res.flags == (f"{lead}{{{MISSION_NAK.upper()}}}",)
    survey = subprocess.run(runner.command(ENGINE, [str(_challenge(tmp_path / "s")), "--event", "csctf"],
                                           record=False), capture_output=True, text=True, cwd=REPO)
    assert SolverResult.from_json(survey.stdout.strip().splitlines()[-1]).status == "unsure"


# -------------------------------------------------------------------------------------------- CLI
def test_cli_survey_text_and_json(tmp_path, capsys):
    cap = tmp_path / "downlink.bin"
    cap.write_bytes(_mission())
    assert cfdp.main(["survey", str(cap)]) == 0
    out = capsys.readouterr().out
    assert "space-packet stream: 23 unit(s), 22 carry a whole CFDP PDU" in out
    assert "row 2: transaction 0x11/0x2c/0x05 on APID 0x2a5" in out
    assert cfdp.main(["survey", str(cap), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["rows"][2]["missing"] == [[70, 80]] and data["rows"][2]["missing_ranges"] == 1
    assert cfdp.main(["survey", str(cap), "--framing", "cfdp-pdu"]) == 2
    assert "sec_space_cfdp:" in capsys.readouterr().err


def test_cli_skeleton_needs_a_row_when_there_are_several(tmp_path, capsys):
    cap = tmp_path / "downlink.bin"
    cap.write_bytes(_mission())
    assert cfdp.main(["skeleton", str(cap)]) == 2
    err = capsys.readouterr().err
    assert "holds 6 selections" in err and "row 5:" in err
    assert cfdp.main(["skeleton", str(cap), "--row", "6"]) == 2
    assert "outside 0..5" in capsys.readouterr().err
    assert cfdp.main(["skeleton", str(cap), "--row", "2"]) == 0
    data = tomllib.loads(capsys.readouterr().out)
    assert data["transaction"]["source"] == SRC and data["packet"]["apid"] == APID
    single = tmp_path / "one.bin"
    single.write_bytes(_stream(_metadata(30), _filedata(0, 10), _eof(30)))
    assert cfdp.main(["skeleton", str(single)]) == 0
    assert tomllib.loads(capsys.readouterr().out)["stream"]["framing"] == "space-packet"


def test_cli_nak_prints_the_pdu_the_trace_and_the_answer(tmp_path, capsys, monkeypatch):
    cap = tmp_path / "downlink.bin"
    cap.write_bytes(_mission())
    flt = tmp_path / "f.toml"
    flt.write_text(_toml(_strict(output={"encoding": "hex-upper", "wrap": "flag"})))
    assert cfdp.main(["nak", str(cap), "--filter", str(flt), "--event", "csctf", "--trace"]) == 0
    out = capsys.readouterr().out
    lead = event.load("csctf").flag.prefixes[0]
    assert f"NAK {MISSION_NAK}" in out and f"answer {lead}{{{MISSION_NAK.upper()}}}" in out
    assert "unit 2 @" in out and "file-data: file_data.before_metadata" in out
    assert "not counted: 1 packet.apid" in out and "missing 38 byte(s) in 3 range(s)" in out
    assert cfdp.main(["nak", str(cap), "--filter", str(flt), "--event", "csctf", "--json", "--trace"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["naks_hex"] == [MISSION_NAK] and data["rendered"][0]["in_event_format"] is True
    assert data["trace"][4] == [4, data["metadata"]["offset"], "metadata", "accept"]
    monkeypatch.delenv("CTF_EVENT", raising=False)
    assert cfdp.main(["nak", str(cap), "--filter", str(flt), "--event", "no-such-event"]) == 2
    assert "no event profile" in capsys.readouterr().err


def test_cli_nak_exit_codes(tmp_path, capsys):
    whole = tmp_path / "whole.bin"
    whole.write_bytes(_stream(_metadata(30), _filedata(0, 30), _eof(30)))
    flt = tmp_path / "f.toml"
    flt.write_text('[stream]\nframing = "space-packet"\n')
    assert cfdp.main(["nak", str(whole), "--filter", str(flt)]) == 1            # ran, no NAK to send
    assert "no NAK: coverage of [0, 30) is complete" in capsys.readouterr().out
    assert cfdp.main(["nak", str(whole), "--filter", str(tmp_path / "absent.toml")]) == 2
    assert cfdp.main(["nak", str(tmp_path / "absent.bin"), "--filter", str(flt)]) == 2
    assert cfdp.main(["nak", str(whole)]) == 2                                   # --filter is required
    capsys.readouterr()


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
