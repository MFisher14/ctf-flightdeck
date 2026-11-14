#!/usr/bin/env python3
"""Tests for solvers/toolkits/ics_scada.py -- the S7comm / DNP3 / IEC 60870-5-104 offline decoder.

  CTF_WORKDIR=/tmp/ctfws .venv/bin/python tests/test_ics_scada.py

Every frame here is built by hand from the protocol spec with KNOWN field values, then decoded and
asserted field-by-field. No real captures, no real flags, no network. scapy ships no dissector for
any of these three protocols (that is why this engine exists), so the cross-check is spec-derived:
the DNP3 CRC is pinned to the published CRC-16/DNP catalogue vector (check(b"123456789")==0xEA82),
and the pcap path is exercised by writing frames with scapy and reading the values back.
"""
import json
import struct
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import ics_scada as M   # noqa: E402


# ============================================================ S7comm builders + tests

def _tpkt_cotp(s7: bytes) -> bytes:
    cotp = bytes([0x02, 0xF0, 0x80])                 # LI=2, DT data, TPDU-nr 0x80 (EOT)
    tpkt = bytes([0x03, 0x00]) + struct.pack(">H", 4 + len(cotp) + len(s7))
    return tpkt + cotp + s7


def _s7(rosctr, pduref, param, data, errclass=None, errcode=None) -> bytes:
    h = bytes([0x32, rosctr, 0x00, 0x00]) + struct.pack(">HHH", pduref, len(param), len(data))
    if rosctr in (0x02, 0x03):
        h += bytes([errclass or 0, errcode or 0])
    return h + param + data


def _s7_item(tsize, count, db, area, byte_addr, bit=0):
    addr = byte_addr * 8 + bit
    return bytes([0x12, 0x0A, 0x10, tsize]) + struct.pack(">HH", count, db) + bytes([area]) \
        + addr.to_bytes(3, "big")


def t_s7_setup_communication():
    param = bytes([0xF0, 0x00]) + struct.pack(">HHH", 1, 1, 0x01E0)
    frame = _tpkt_cotp(_s7(0x01, 0x0400, param, b""))
    name, recs = M.dissect_payload(frame)
    assert name == "s7comm", name
    s7 = recs[0]["s7"]
    assert s7["rosctr_name"].startswith("Job"), s7["rosctr_name"]
    assert s7["function_name"] == "Setup communication", s7
    assert s7["setup"]["pdu_length"] == 0x01E0, s7["setup"]
    assert s7["setup"]["max_amq_calling"] == 1


def t_s7_write_var_word():
    # write WORD 0x1234 to DB1, byte address 4 (area DB=0x84, type WORD=0x04)
    item = _s7_item(0x04, 1, 1, 0x84, 4)
    param = bytes([0x05, 0x01]) + item
    data = bytes([0x00, 0x04]) + struct.pack(">H", 16) + struct.pack(">H", 0x1234)
    frame = _tpkt_cotp(_s7(0x01, 0x0401, param, data))
    s7 = M.dissect_payload(frame)[1][0]["s7"]
    assert s7["function_name"] == "Write Var", s7
    it = s7["items"][0]
    assert it["area_name"] == "Data blocks (DB)" and it["db_number"] == 1, it
    assert it["byte_address"] == 4 and it["bit_offset"] == 0, it
    assert it["transport_size_name"] == "WORD" and it["count"] == 1, it
    dv = s7["data_items"][0]
    assert dv["return_code_name"] == "Reserved", dv              # 0x00 in a request
    assert dv["length_bytes"] == 2 and dv["value"]["uint16"] == 0x1234, dv


def t_s7_read_var_response_value():
    param = bytes([0x04, 0x01])                                   # Read Var, 1 item (response param)
    data = bytes([0xFF, 0x04]) + struct.pack(">H", 16) + struct.pack(">H", 0x00FF)
    frame = _tpkt_cotp(_s7(0x03, 0x0401, param, data, 0, 0))
    s7 = M.dissect_payload(frame)[1][0]["s7"]
    assert s7["rosctr_name"].startswith("Ack_Data"), s7["rosctr_name"]
    assert s7["error_class"] == 0 and s7["error_code"] == 0
    assert s7["function_name"] == "Read Var"
    dv = s7["data_items"][0]
    assert dv["return_code_name"] == "Success", dv
    assert dv["value"]["uint16"] == 0x00FF == 255, dv


def t_s7_octet_string_flag_highlight():
    flag = b"csctf{s7_setpoint_override}"
    item = _s7_item(0x03, len(flag), 2, 0x84, 0)                  # CHAR type, DB2
    param = bytes([0x05, 0x01]) + item
    data = bytes([0x00, 0x09]) + struct.pack(">H", len(flag)) + flag   # data transport 0x09 = octet string
    frame = _tpkt_cotp(_s7(0x01, 0x0402, param, data))
    rep = M.analyze_bytes(frame, "s7.bin")
    assert "csctf{s7_setpoint_override}" in rep["flags"], rep["flags"]
    dv = rep["frames"][0]["s7"]["data_items"][0]
    assert dv["value"]["ascii"] == flag.decode(), dv["value"]
    # the human report must render the flag prominently (ANSI off for the assertion)
    text = M.format_report(rep, color=False)
    assert "FLAG FORMAT MATCH" in text and flag.decode() in text, text[:400]


def t_s7_multiple_frames_back_to_back():
    f1 = _tpkt_cotp(_s7(0x01, 1, bytes([0xF0, 0x00]) + struct.pack(">HHH", 1, 1, 480), b""))
    item = _s7_item(0x04, 1, 1, 0x84, 0)
    f2 = _tpkt_cotp(_s7(0x01, 2, bytes([0x05, 0x01]) + item,
                        bytes([0x00, 0x04]) + struct.pack(">H", 16) + struct.pack(">H", 0xBEEF)))
    name, recs = M.dissect_payload(f1 + f2)
    assert name == "s7comm" and len(recs) == 2, (name, len(recs))
    assert recs[0]["s7"]["function_name"] == "Setup communication"
    assert recs[1]["s7"]["data_items"][0]["value"]["uint16"] == 0xBEEF


# ============================================================ DNP3 builders + tests

def _dnp3_blocks(user: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(user), 16):
        chunk = user[i:i + 16]
        out += chunk + struct.pack("<H", M.dnp3_crc(chunk))
    return bytes(out)


def _dnp3_frame(ctrl, dest, src, user: bytes) -> bytes:
    hdr = bytes([0x05, 0x64, 5 + len(user), ctrl]) + struct.pack("<HH", dest, src)
    hdr += struct.pack("<H", M.dnp3_crc(hdr))
    return hdr + _dnp3_blocks(user)


def t_dnp3_crc_known_answer():
    # published CRC-16/DNP catalogue check value -- pins the CRC implementation
    assert M.dnp3_crc(b"123456789") == 0xEA82, hex(M.dnp3_crc(b"123456789"))


def t_dnp3_read_class_poll():
    user = bytes([0xC0]) + bytes([0xC0, 0x01]) + bytes([60, 1, 0x06, 60, 2, 0x06, 60, 3, 0x06, 60, 4, 0x06])
    frame = _dnp3_frame(0xC4, 10, 1, user)       # DIR=1 PRM=1 func=4 UNCONFIRMED_USER_DATA
    name, recs = M.dissect_payload(frame)
    assert name == "dnp3", name
    r = recs[0]
    assert r["header_crc_ok"] and r["block_crc_ok"], r
    assert r["prm"] == 1 and r["link_function_name"] == "UNCONFIRMED_USER_DATA", r
    assert r["destination"] == 10 and r["source"] == 1
    assert r["transport"]["fir"] == 1 and r["transport"]["fin"] == 1
    app = r["application"]
    assert app["function_name"] == "READ", app
    groups = [(o["group"], o["variation"]) for o in app["objects"]]
    assert groups == [(60, 1), (60, 2), (60, 3), (60, 4)], groups
    assert all(o["range_name"] == "no range (all objects)" for o in app["objects"])


def t_dnp3_response_analog_input_multiblock():
    # object g30 v1 (analog input 32-bit + flag), qualifier 0x00 (1-octet start/stop), start=0 stop=1
    obj = bytes([30, 1, 0x00, 0, 1])
    obj += bytes([0x01]) + struct.pack("<i", 12345)
    obj += bytes([0x01]) + struct.pack("<i", -42)
    user = bytes([0xC0]) + bytes([0xC0, 0x81]) + struct.pack("<H", 0x0000) + obj   # RESPONSE + IIN=0
    assert len(user) == 20, len(user)                             # 20 bytes -> 2 link blocks (16 + 4)
    frame = _dnp3_frame(0x44, 1, 10, user)                        # PRM=1 func=4, outstation->master
    r = M.dissect_payload(frame)[1][0]
    assert r["data_blocks"] == 2 and r["block_crc_ok"], r
    app = r["application"]
    assert app["function_name"] == "RESPONSE" and app["iin"] == 0, app
    o = app["objects"][0]
    assert (o["group"], o["variation"]) == (30, 1) and o["count"] == 2, o
    pts = o["points"]
    assert pts[0]["index"] == 0 and pts[0]["value"] == 12345, pts[0]
    assert pts[1]["index"] == 1 and pts[1]["value"] == -42, pts[1]


def t_dnp3_crob_operate():
    # group 12 var 1 CROB, qualifier 0x28 (prefix=2 2-octet index, range=... ) -- use 0x17: prefix 1, count 1
    crob = bytes([0x41, 0x01]) + struct.pack("<I", 100) + struct.pack("<I", 0) + bytes([0x00])  # LATCH? code 0x41
    obj = bytes([12, 1, 0x17, 1]) + bytes([3]) + crob            # qual 0x17 -> 1-octet index + 1-octet count; index=3
    user = bytes([0xC0]) + bytes([0xC0, 0x05]) + obj             # DIRECT_OPERATE
    frame = _dnp3_frame(0xC4, 5, 2, user)
    r = M.dissect_payload(frame)[1][0]
    app = r["application"]
    assert app["function_name"] == "DIRECT_OPERATE", app
    o = app["objects"][0]
    assert (o["group"], o["variation"]) == (12, 1), o
    pt = o["points"][0]
    assert pt["index"] == 3 and pt["count"] == 1 and pt["on_time_ms"] == 100, pt
    assert pt["control_code"] == 0x41


def t_dnp3_octet_string_flag():
    flag = b"flag{dnp3_rtu_firmware}"
    var = len(flag)
    obj = bytes([110, var, 0x17, 1]) + bytes([5]) + flag        # g110 v<len>, prefix 1-octet index=5, count 1
    user = bytes([0xC0]) + bytes([0xC0, 0x02]) + obj            # WRITE
    frame = _dnp3_frame(0xC4, 7, 3, user)
    rep = M.analyze_bytes(frame, "dnp3.bin")
    assert flag.decode() in rep["flags"], rep["flags"]
    o = rep["frames"][0]["application"]["objects"][0]
    assert o["group"] == 110 and o["points"][0]["ascii"] == flag.decode(), o


# ============================================================ IEC 60870-5-104 builders + tests

def _iec_apdu(control4: bytes, asdu: bytes = b"") -> bytes:
    return bytes([0x68, len(control4) + len(asdu)]) + control4 + asdu


def _iec_i_control(ns, nr) -> bytes:
    return bytes([(ns << 1) & 0xFF, (ns >> 7) & 0xFF, (nr << 1) & 0xFF, (nr >> 7) & 0xFF])


def t_iec104_u_startdt():
    r = M.dissect_payload(_iec_apdu(bytes([0x07, 0x00, 0x00, 0x00])))[1][0]
    assert r["format"] == "U" and r["u_command"] == "STARTDT act", r


def t_iec104_s_frame():
    r = M.dissect_payload(_iec_apdu(bytes([0x01, 0x00, 0x0A, 0x00])))[1][0]
    assert r["format"] == "S" and r["rx_sequence"] == 5, r


def t_iec104_i_shortfloat_measured():
    asdu = bytes([13, 0x01, 0x03, 0x00]) + struct.pack("<H", 1)       # type 13, SQ0 n1, cause 3 spont, CA=1
    asdu += (100).to_bytes(3, "little") + struct.pack("<f", 3.14) + bytes([0x00])
    r = M.dissect_payload(_iec_apdu(_iec_i_control(0, 0), asdu))[1][0]
    assert r["format"] == "I" and r["tx_sequence"] == 0 and r["rx_sequence"] == 0, r
    a = r["asdu"]
    assert a["type_id"] == 13 and a["type_name"].startswith("M_ME_NC_1"), a
    assert a["cause_name"] == "spontaneous" and a["common_address"] == 1, a
    io = a["information_objects"][0]
    assert io["ioa"] == 100, io
    assert abs(io["float"] - 3.14) < 1e-5, io


def t_iec104_i_interrogation_command():
    asdu = bytes([100, 0x01, 0x06, 0x00]) + struct.pack("<H", 1)      # C_IC_NA_1, cause 6 activation, CA=1
    asdu += (0).to_bytes(3, "little") + bytes([20])                   # IOA 0, QOI 20 (station interrogation)
    r = M.dissect_payload(_iec_apdu(_iec_i_control(1, 0), asdu))[1][0]
    a = r["asdu"]
    assert a["type_id"] == 100 and a["cause_name"] == "activation", a
    io = a["information_objects"][0]
    assert io["ioa"] == 0 and io["qoi"] == 20, io
    assert "station" in io["qoi_name"], io


def t_iec104_sq1_sequence_of_points():
    # SQ=1: one base IOA then 3 consecutive scaled measured values (type 11, SVA(2)+QDS(1))
    vals = [111, 222, 333]
    asdu = bytes([11, 0x80 | 3, 0x01, 0x00]) + struct.pack("<H", 7)   # SQ=1 n=3, cause 1 periodic, CA=7
    asdu += (200).to_bytes(3, "little")
    for v in vals:
        asdu += struct.pack("<h", v) + bytes([0x00])
    r = M.dissect_payload(_iec_apdu(_iec_i_control(2, 3), asdu))[1][0]
    a = r["asdu"]
    assert a["sq"] == 1 and a["num_objects"] == 3, a
    ios = a["information_objects"]
    assert [io["ioa"] for io in ios] == [200, 201, 202], ios
    assert [io["scaled"] for io in ios] == vals, ios


def t_iec104_flag_in_unknown_asdu():
    flag = b"CTF{iec104_substation_rtu}"
    asdu = bytes([120, 0x01, 0x0D, 0x00]) + struct.pack("<H", 1)      # type 120 (file ready, not auto-decoded)
    asdu += (1).to_bytes(3, "little") + flag
    rep = M.analyze_bytes(_iec_apdu(_iec_i_control(0, 0), asdu), "iec.bin")
    assert flag.decode() in rep["flags"], rep["flags"]


# ============================================================ pcap round-trip (scapy write, we read)

def t_pcap_all_three_with_tcp_reassembly():
    try:
        from scapy.all import IP, TCP, Raw, wrpcap
    except Exception as e:
        print(f"pass  pcap_all_three_with_tcp_reassembly (SKIPPED: scapy unavailable: {e})")
        return
    s7 = _tpkt_cotp(_s7(0x01, 0x0401, bytes([0x05, 0x01]) + _s7_item(0x04, 1, 1, 0x84, 4),
                        bytes([0x00, 0x04]) + struct.pack(">H", 16) + struct.pack(">H", 0x1234)))
    dnp = _dnp3_frame(0xC4, 10, 1, bytes([0xC0, 0xC0, 0x01, 60, 1, 0x06]))
    iec = _iec_apdu(bytes([0x07, 0x00, 0x00, 0x00]))                  # STARTDT act

    pkts = []
    # S7 split across two TCP segments -> exercises sequence-based reassembly
    pkts.append(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=102, seq=1000, flags="PA") / Raw(s7[:6]))
    pkts.append(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=102, seq=1006, flags="PA") / Raw(s7[6:]))
    pkts.append(IP(src="10.0.0.3", dst="10.0.0.4") / TCP(sport=50001, dport=20000, seq=1, flags="PA") / Raw(dnp))
    pkts.append(IP(src="10.0.0.5", dst="10.0.0.6") / TCP(sport=50002, dport=2404, seq=1, flags="PA") / Raw(iec))

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as fh:
        path = fh.name
    wrpcap(path, pkts)
    rep = M.analyze_file(path)
    assert rep["input"] == "pcap", rep
    by_proto = {fl["protocol"]: fl for fl in rep["flows"]}
    assert set(by_proto) == {"s7comm", "dnp3", "iec104"}, list(by_proto)
    # S7 reassembled from the two segments and fully decoded
    s7rec = by_proto["s7comm"]["frames"][0]["s7"]
    assert s7rec["function_name"] == "Write Var"
    assert s7rec["data_items"][0]["value"]["uint16"] == 0x1234, s7rec
    assert by_proto["dnp3"]["frames"][0]["application"]["function_name"] == "READ"
    assert by_proto["iec104"]["frames"][0]["u_command"] == "STARTDT act"
    Path(path).unlink(missing_ok=True)


def t_pcap_dnp3_over_udp():
    try:
        from scapy.all import IP, UDP, Raw, wrpcap
    except Exception as e:
        print(f"pass  pcap_dnp3_over_udp (SKIPPED: scapy unavailable: {e})")
        return
    dnp = _dnp3_frame(0xC4, 10, 1, bytes([0xC0, 0xC0, 0x01, 60, 1, 0x06]))
    pkt = IP(src="10.1.1.1", dst="10.1.1.2") / UDP(sport=40000, dport=20000) / Raw(dnp)
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as fh:
        path = fh.name
    wrpcap(path, [pkt])
    rep = M.analyze_file(path)
    fl = rep["flows"][0]
    assert fl["proto"] == "udp" and fl["protocol"] == "dnp3", fl
    assert fl["frames"][0]["application"]["function_name"] == "READ", fl
    Path(path).unlink(missing_ok=True)


def t_pcap_flag_surfaced_from_capture():
    try:
        from scapy.all import IP, TCP, Raw, wrpcap
    except Exception as e:
        print(f"pass  pcap_flag_surfaced_from_capture (SKIPPED: scapy unavailable: {e})")
        return
    flag = b"chronos{ics_pcap_loot}"
    item = _s7_item(0x03, len(flag), 2, 0x84, 0)
    s7 = _tpkt_cotp(_s7(0x01, 1, bytes([0x05, 0x01]) + item,
                        bytes([0x00, 0x09]) + struct.pack(">H", len(flag)) + flag))
    pkt = IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=4000, dport=102, seq=1, flags="PA") / Raw(s7)
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as fh:
        path = fh.name
    wrpcap(path, [pkt])
    rep = M.analyze_file(path)
    assert flag.decode() in rep["flags"], rep
    assert flag.decode() in M.format_report(rep, color=False)
    Path(path).unlink(missing_ok=True)


# ============================================================ cross-cutting

def t_scapy_really_lacks_these_dissectors():
    # Documents WHY this engine exists: scapy.contrib covers modbus/enip/opc_da/knx but not these.
    try:
        import scapy, glob, os
        d = os.path.dirname(scapy.__file__)
        names = {os.path.basename(x)[:-3].lower() for x in glob.glob(os.path.join(d, "contrib", "*.py"))}
    except Exception:
        print("pass  scapy_really_lacks_these_dissectors (SKIPPED: scapy unavailable)")
        return
    for absent in ("s7comm", "s7", "dnp3", "iec104", "iec60870", "iec104_apci"):
        assert absent not in names, f"scapy unexpectedly ships {absent}; revisit coverage"


def t_json_output_is_valid():
    frame = _dnp3_frame(0xC4, 10, 1, bytes([0xC0, 0xC0, 0x01, 60, 1, 0x06]))
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as fh:
        fh.write(frame)
        path = fh.name
    out = M.report([path], as_json=True)
    data = json.loads(out)                                        # must be valid JSON
    assert data[0]["protocol"] == "dnp3", data[0]
    Path(path).unlink(missing_ok=True)


def t_non_ics_input_is_graceful():
    rep = M.analyze_bytes(b"this is not an ICS frame at all\x00\x01\x02", "junk.bin")
    assert rep["protocol"] is None and rep["frame_count"] == 0, rep
    assert "no S7comm" in M.format_report(rep, color=False)


def t_s7_real_value():
    # Read response carrying a REAL (data transport 0x07, length in BYTES = 4)
    data = bytes([0xFF, 0x07]) + struct.pack(">H", 4) + struct.pack(">f", 42.5)
    frame = _tpkt_cotp(_s7(0x03, 1, bytes([0x04, 0x01]), data, 0, 0))
    dv = M.dissect_payload(frame)[1][0]["s7"]["data_items"][0]
    assert dv["transport_size_name"] == "REAL" and dv["length_unit"] == "bytes", dv
    assert dv["length_bytes"] == 4 and abs(dv["value"]["real"] - 42.5) < 1e-6, dv


def t_s7_dword_length_is_in_bits():
    # transport size 0x04 (BYTE/WORD/DWORD) counts length in BITS: 32 bits -> 4 bytes, DWORD value
    data = bytes([0xFF, 0x04]) + struct.pack(">H", 32) + struct.pack(">I", 0xDEADBEEF)
    frame = _tpkt_cotp(_s7(0x03, 1, bytes([0x04, 0x01]), data, 0, 0))
    dv = M.dissect_payload(frame)[1][0]["s7"]["data_items"][0]
    assert dv["length_unit"] == "bits" and dv["length_bytes"] == 4, dv
    assert dv["value"]["uint32"] == 0xDEADBEEF, dv["value"]


def t_s7_two_items_fill_byte():
    # odd-length first item (3-byte octet string) must be followed by a pad byte before item[1]
    d0 = bytes([0xFF, 0x09]) + struct.pack(">H", 3) + b"ABC"           # octet string, bytes
    d1 = bytes([0xFF, 0x04]) + struct.pack(">H", 16) + struct.pack(">H", 0x1234)
    data = d0 + b"\x00" + d1
    frame = _tpkt_cotp(_s7(0x03, 1, bytes([0x04, 0x02]), data, 0, 0))
    items = M.dissect_payload(frame)[1][0]["s7"]["data_items"]
    assert len(items) == 2, items
    assert items[0]["value"]["ascii"] == "ABC", items[0]
    assert items[1]["value"]["uint16"] == 0x1234, items[1]            # correct only if pad skipped


def t_dnp3_analog_16bit_two_octet_range():
    # g30 v4 (analog input 16-bit, no flag) with qualifier 0x01 = 2-octet start/stop (start=100 stop=101)
    obj = bytes([30, 4, 0x01]) + struct.pack("<HH", 100, 101)
    obj += struct.pack("<h", -12345) + struct.pack("<h", 6000)
    user = bytes([0xC0, 0xC0, 0x81]) + struct.pack("<H", 0) + obj
    r = M.dissect_payload(_dnp3_frame(0x44, 1, 10, user))[1][0]
    o = r["application"]["objects"][0]
    assert o["start"] == 100 and o["stop"] == 101 and o["count"] == 2, o
    assert [p["index"] for p in o["points"]] == [100, 101], o["points"]
    assert [p["value"] for p in o["points"]] == [-12345, 6000], o["points"]


def t_iec104_vti_step_position_is_signed_i7():
    # Type 5 M_ST_NA_1: VTI value is a 7-bit two's-complement signed integer (-64..63), bit7=transient.
    # byte 0xC0 -> transient=1, value = -64 (NOT +64). Regression guard for the I7 sign fix.
    asdu = bytes([5, 0x01, 0x03, 0x00]) + struct.pack("<H", 1)
    asdu += (10).to_bytes(3, "little") + bytes([0xC0, 0x00])
    io = M.dissect_payload(_iec_apdu(_iec_i_control(0, 0), asdu))[1][0]["asdu"]["information_objects"][0]
    assert io["ioa"] == 10 and io["transient"] == 1 and io["value"] == -64, io
    # 0xFF -> transient=1, value -1
    asdu = bytes([5, 0x01, 0x03, 0x00]) + struct.pack("<H", 1) + (11).to_bytes(3, "little") + bytes([0xFF, 0x00])
    io = M.dissect_payload(_iec_apdu(_iec_i_control(0, 0), asdu))[1][0]["asdu"]["information_objects"][0]
    assert io["value"] == -1, io


def t_iec104_cp56time2a_fields():
    # Clock-sync (type 103) carries a CP56Time2a; decode a known instant 2023-03-09 07:08:09.250, dow=4.
    ms = 9 * 1000 + 250
    cp56 = struct.pack("<H", ms) + bytes([8 & 0x3F, 7 & 0x1F, (4 << 5) | 9, 3, 23])
    asdu = bytes([103, 0x01, 0x06, 0x00]) + struct.pack("<H", 1) + (0).to_bytes(3, "little") + cp56
    io = M.dissect_payload(_iec_apdu(_iec_i_control(0, 0), asdu))[1][0]["asdu"]["information_objects"][0]
    assert (io["year"], io["month"], io["day"]) == (2023, 3, 9), io
    assert (io["hour"], io["minute"], io["second"], io["millisecond"]) == (7, 8, 9, 250), io
    assert io["day_of_week"] == 4 and io["invalid"] is False, io


def t_iec104_large_sequence_numbers():
    # N(S)/N(R) are 15-bit; verify values that cross the octet boundary round-trip correctly.
    for ns, nr in [(127, 128), (5000, 9000), (16383, 16383)]:
        asdu = bytes([100, 0x01, 0x06, 0x00]) + struct.pack("<H", 1) + (0).to_bytes(3, "little") + bytes([20])
        r = M.dissect_payload(_iec_apdu(_iec_i_control(ns, nr), asdu))[1][0]
        assert r["tx_sequence"] == ns and r["rx_sequence"] == nr, (ns, nr, r)


def t_dnp3_crc_matches_independent_reflected_algo():
    # Cross-check the CRC against a fully independent MSB-first + reflect-I/O implementation of
    # CRC-16/DNP (poly 0x3D65) on random blobs -- catches any bug in the engine's LSB-first loop.
    import random

    def _reflect(x, n):
        r = 0
        for i in range(n):
            if x & (1 << i):
                r |= 1 << (n - 1 - i)
        return r

    def _crc_msb(data):
        crc = 0
        for b in bytes(data):
            crc ^= _reflect(b, 8) << 8
            for _ in range(8):
                crc = ((crc << 1) ^ 0x3D65) & 0xFFFF if (crc & 0x8000) else (crc << 1) & 0xFFFF
        return _reflect(crc, 16) ^ 0xFFFF
    rng = random.Random(1815)
    for _ in range(500):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 40)))
        assert M.dnp3_crc(blob) == _crc_msb(blob), blob.hex()


TESTS = [
    t_s7_setup_communication,
    t_s7_real_value,
    t_s7_dword_length_is_in_bits,
    t_s7_two_items_fill_byte,
    t_dnp3_analog_16bit_two_octet_range,
    t_iec104_vti_step_position_is_signed_i7,
    t_iec104_cp56time2a_fields,
    t_iec104_large_sequence_numbers,
    t_dnp3_crc_matches_independent_reflected_algo,
    t_s7_write_var_word,
    t_s7_read_var_response_value,
    t_s7_octet_string_flag_highlight,
    t_s7_multiple_frames_back_to_back,
    t_dnp3_crc_known_answer,
    t_dnp3_read_class_poll,
    t_dnp3_response_analog_input_multiblock,
    t_dnp3_crob_operate,
    t_dnp3_octet_string_flag,
    t_iec104_u_startdt,
    t_iec104_s_frame,
    t_iec104_i_shortfloat_measured,
    t_iec104_i_interrogation_command,
    t_iec104_sq1_sequence_of_points,
    t_iec104_flag_in_unknown_asdu,
    t_pcap_all_three_with_tcp_reassembly,
    t_pcap_dnp3_over_udp,
    t_pcap_flag_surfaced_from_capture,
    t_scapy_really_lacks_these_dissectors,
    t_json_output_is_valid,
    t_non_ics_input_is_graceful,
]


def main():
    failed = 0
    for test in TESTS:
        try:
            test()
        except AssertionError as e:
            failed += 1
            import traceback
            where = traceback.extract_tb(e.__traceback__)[-1]
            print(f"FAIL  {test.__name__[2:]}: line {where.lineno}: {str(e)[:900]}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            import traceback
            where = traceback.extract_tb(e.__traceback__)[-1]
            print(f"FAIL  {test.__name__[2:]}: raised {type(e).__name__}: {e} "
                  f"({Path(where.filename).name}:{where.lineno})")
        else:
            print(f"pass  {test.__name__[2:]}")
    print("ok" if not failed else f"{failed} check(s) failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
