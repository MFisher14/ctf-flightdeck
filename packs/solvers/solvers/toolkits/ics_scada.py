#!/usr/bin/env python3
"""Toolkit ics_scada: offline, never-execute decoders for the three ICS/SCADA protocols that scapy
does NOT ship a dissector for -- S7comm (Siemens, TPKT/COTP/S7 over TCP 102), DNP3 (TCP/UDP 20000)
and IEC 60870-5-104 (TCP 2404). scapy.contrib already covers modbus, enipTCP (EtherNet/IP), opc_da,
knx and ethercat; use those elsewhere. This module fills the remaining gap for the "Total Warfare"
critical-infrastructure theme (power / ICS / SCADA, substation RTUs, PLC traffic).

Discipline (AGENTS.md "Detonation only in Docker", solvers rules "never execute"):
  - OFFLINE and STATIC. The bytes are walked as a documented grammar; nothing is instantiated, run,
    or sent on the network. A frame that does not parse cleanly is reported as such, never guessed.
  - Inputs: a RAW protocol-payload file (one or more back-to-back frames) OR a .pcap/.pcapng. For a
    capture, scapy reads the packets, the relevant TCP streams (ports 102 / 20000 / 2404) and UDP
    datagrams (port 20000, DNP3) are reassembled, and THIS module dissects the payloads itself.
  - In jeopardy the decoded content is where a flag hides, so every string/octet value and every raw
    payload is scanned for the CSCTF flag format and any hit is highlighted prominently.

What is decoded (CTF-relevant subset, spec-derived):
  S7comm   TPKT (RFC 1006) + COTP (ISO 8073 class 0) framing; S7 header (ROSCTR, PDU ref, param/data
           lengths, error class/code on responses); Setup Communication (negotiated PDU size, AmQ);
           Read Var / Write Var items (area + DB + bit/byte address + data type + element count) and
           the written/returned values (BYTE/WORD/DWORD/INT/REAL/BIT/octet-string).
  DNP3     data-link header (start 0x0564, length, DIR/PRM/FCB/FCV + link function, 16-bit dest/src)
           with every block CRC (CRC-16/DNP, poly 0x3D65) verified; CRC-stripped user data; transport
           function (FIR/FIN/SEQ); application control + function code; object headers (group /
           variation / qualifier), range or count, and point values for common objects (binary in/out,
           analog in/out, counters, CROB control).
  IEC-104  APCI (start 0x68, length, 4 control octets) classified I / S / U; U-format commands
           (STARTDT/STOPDT/TESTFR act/con); S/I sequence numbers; for I-frames the ASDU: Type ID,
           SQ + element count, Cause of Transmission (+ originator), Common Address, and per information
           object the IOA and its value (single/double point, normalized/scaled/short-float measured
           values, commands, interrogation, CP56Time2a time tags).

CLI:  .venv/bin/python solvers/toolkits/ics_scada.py <file|pcap>... [--json]
      <file>  a raw S7/DNP3/IEC-104 payload (auto-detected by signature) OR a .pcap/.pcapng capture.
      --json  emit the structured decode as JSON instead of the human-readable report.
"""
import argparse
import json
import struct
import sys
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

HERE = Path(__file__).resolve().parent

# CSCTF flag format (shared across the toolkit): decoded content is where a flag hides.
FLAG_RE = flagfmt.TEXT

MAX_FILE = 64 * 1024 * 1024
# Default well-known ports (pulled from a pcap). Overridable on the CLI.
S7_PORTS = {102}
DNP3_PORTS = {20000}
IEC104_PORTS = {2404}


# ------------------------------------------------------------------ small helpers

def _flags_in(*blobs) -> list:
    """Every distinct event-format flag string found in the given bytes/str blobs (order-preserving).
    Bytes (register blocks, payloads) are scanned without a word boundary before the flag
    (flagfmt.PACKED_TEXT, R-16); text keeps the boundary."""
    out, seen = [], set()
    for b in blobs:
        if b is None:
            continue
        if isinstance(b, (bytes, bytearray)):
            s, rx = bytes(b).decode("latin-1"), flagfmt.PACKED_TEXT
        else:
            s, rx = str(b), FLAG_RE
        for m in rx.findall(s):
            if m not in seen:
                seen.add(m)
                out.append(m)
    return out


def _printable_str(b):
    """The decoded string if the bytes are wholly printable text (tab/newline allowed), else None."""
    try:
        s = bytes(b).decode("utf-8")
    except Exception:
        try:
            s = bytes(b).decode("latin-1")
        except Exception:
            return None
    if not s:
        return None
    if any((ord(c) < 32 and c not in "\t\r\n") or ord(c) == 127 for c in s):
        return None
    return s


def _hexpreview(b, limit=48) -> str:
    b = bytes(b)
    h = b[:limit].hex()
    if len(b) > limit:
        h += f"...(+{len(b) - limit}B)"
    return h


def _u16be(d, o):
    return (d[o] << 8) | d[o + 1]


def _u16le(d, o):
    return d[o] | (d[o + 1] << 8)


def _u24le(d, o):
    return d[o] | (d[o + 1] << 8) | (d[o + 2] << 16)


class ParseError(Exception):
    pass


# ================================================================== S7comm (TPKT/COTP/S7)

S7_ROSCTR = {
    0x01: "Job (request)",
    0x02: "Ack",
    0x03: "Ack_Data (response)",
    0x07: "Userdata",
}

S7_FUNCTION = {
    0x00: "CPU services",
    0x04: "Read Var",
    0x05: "Write Var",
    0x1A: "Request download",
    0x1B: "Download block",
    0x1C: "Download ended",
    0x1D: "Start upload",
    0x1E: "Upload",
    0x1F: "End upload",
    0x28: "PI-Service (PLC control)",
    0x29: "PLC Stop",
    0xF0: "Setup communication",
}

# Transport size inside a Read/Write address item (the requested data TYPE).
S7_ADDR_TSIZE = {
    0x00: "NULL", 0x01: "BIT", 0x02: "BYTE", 0x03: "CHAR", 0x04: "WORD",
    0x05: "INT", 0x06: "DWORD", 0x07: "DINT", 0x08: "REAL", 0x09: "DATE",
    0x0A: "TOD", 0x0B: "TIME", 0x0C: "S5TIME", 0x0F: "DATE_AND_TIME",
    0x1C: "COUNTER", 0x1D: "TIMER", 0x1E: "IEC_COUNTER", 0x1F: "IEC_TIMER",
}

# Memory area codes.
S7_AREA = {
    0x03: "S7-200 system info", 0x05: "S7-200 system flags",
    0x06: "S7-200 analog inputs", 0x07: "S7-200 analog outputs",
    0x1C: "S7 counters (C)", 0x1D: "S7 timers (T)",
    0x80: "Direct peripheral access (P)", 0x81: "Inputs (I/E)",
    0x82: "Outputs (Q/A)", 0x83: "Flags/Merkers (M)", 0x84: "Data blocks (DB)",
    0x85: "Instance data blocks (DI)", 0x86: "Local data (L)",
    0x87: "Previous local data (V)",
}

# Transport size inside a DATA item (how the value bytes are counted).
S7_DATA_TSIZE = {
    0x00: "NULL", 0x03: "BIT", 0x04: "BYTE/WORD/DWORD", 0x05: "INT",
    0x06: "DINT", 0x07: "REAL", 0x09: "OCTET STRING",
}
# For these transport sizes the length field is in BITS; otherwise it is in bytes.
_S7_LEN_IN_BITS = {0x03, 0x04, 0x05}

S7_RETCODE = {
    0x00: "Reserved", 0x01: "Hardware fault", 0x03: "Accessing object not allowed",
    0x05: "Invalid address", 0x06: "Data type not supported",
    0x07: "Data type inconsistent", 0x0A: "Object does not exist", 0xFF: "Success",
}

COTP_PDU = {0xE0: "CR Connect Request", 0xD0: "CC Connect Confirm",
            0x80: "DR Disconnect Request", 0xC0: "DC Disconnect Confirm",
            0xF0: "DT Data", 0x70: "ER Error"}


def _s7_decode_value(tsize, nbytes, raw):
    """Best-effort typed rendering of an S7 data item's value bytes (plus the raw hex)."""
    val = {"raw_hex": raw.hex()}
    txt = _printable_str(raw)
    if txt is not None and any(ch.isprintable() and ch not in "\r\n\t" for ch in txt):
        val["ascii"] = txt
    try:
        if tsize == 0x03 and nbytes >= 1:                       # BIT
            val["bit"] = raw[0] & 1
        elif tsize == 0x04:                                     # BYTE / WORD / DWORD
            if nbytes == 1:
                val["uint8"] = raw[0]
            elif nbytes == 2:
                val["uint16"] = _u16be(raw, 0)
            elif nbytes == 4:
                val["uint32"] = int.from_bytes(raw[:4], "big")
        elif tsize == 0x05:                                     # INT (signed)
            if nbytes == 2:
                val["int16"] = int.from_bytes(raw[:2], "big", signed=True)
        elif tsize == 0x06 and nbytes == 4:                     # DINT
            val["int32"] = int.from_bytes(raw[:4], "big", signed=True)
        elif tsize == 0x07 and nbytes == 4:                     # REAL
            val["real"] = struct.unpack(">f", raw[:4])[0]
    except Exception:
        pass
    return val


def _s7_parse_data_items(data, n_items):
    """Parse the S7 DATA section into per-item values (Write request / Read response)."""
    items, o = [], 0
    for idx in range(n_items):
        if o + 4 > len(data):
            break
        ret = data[o]
        tsize = data[o + 1]
        blen = _u16be(data, o + 2)
        o += 4
        nbytes = (blen + 7) // 8 if tsize in _S7_LEN_IN_BITS else blen
        raw = data[o:o + nbytes]
        o += nbytes
        rec = {
            "return_code": ret,
            "return_code_name": S7_RETCODE.get(ret, f"0x{ret:02x}"),
            "transport_size": tsize,
            "transport_size_name": S7_DATA_TSIZE.get(tsize, f"0x{tsize:02x}"),
            "length_raw": blen,
            "length_unit": "bits" if tsize in _S7_LEN_IN_BITS else "bytes",
            "length_bytes": nbytes,
            "value": _s7_decode_value(tsize, nbytes, raw),
        }
        items.append(rec)
        # fill byte between items when the item length is odd (not after the last item)
        if idx != n_items - 1 and nbytes % 2 == 1:
            o += 1
    return items


def _s7_parse_rw_items(param, n_items):
    """Parse Read/Write Var address items (the 12-byte S7ANY form, syntax id 0x10)."""
    items, o = [], 0
    for _ in range(n_items):
        if o + 2 > len(param) or param[o] != 0x12:
            break
        spec_len = param[o + 1]
        body = param[o + 2:o + 2 + spec_len]
        o += 2 + spec_len
        if len(body) < 10 or body[0] != 0x10:                  # syntax id 0x10 = S7ANY
            items.append({"syntax_id": body[0] if body else None, "raw_hex": body.hex()})
            continue
        tsize = body[1]
        count = _u16be(body, 2)
        db = _u16be(body, 4)
        area = body[6]
        addr = (body[7] << 16) | (body[8] << 8) | body[9]
        items.append({
            "syntax_id": 0x10, "syntax": "S7ANY",
            "transport_size": tsize,
            "transport_size_name": S7_ADDR_TSIZE.get(tsize, f"0x{tsize:02x}"),
            "count": count,
            "db_number": db,
            "area": area,
            "area_name": S7_AREA.get(area, f"0x{area:02x}"),
            "bit_address": addr,
            "byte_address": addr >> 3,
            "bit_offset": addr & 7,
        })
    return items


def parse_s7_pdu(s7):
    """Parse one S7 telegram (starting at protocol id 0x32). Returns a decode dict or raises."""
    if len(s7) < 10 or s7[0] != 0x32:
        raise ParseError("not an S7 telegram (protocol id != 0x32)")
    rosctr = s7[1]
    pduref = _u16be(s7, 4)
    param_len = _u16be(s7, 6)
    data_len = _u16be(s7, 8)
    hdr = 12 if rosctr in (0x02, 0x03) else 10
    rec = {
        "protocol": "S7comm",
        "rosctr": rosctr,
        "rosctr_name": S7_ROSCTR.get(rosctr, f"0x{rosctr:02x}"),
        "pdu_reference": pduref,
        "param_length": param_len,
        "data_length": data_len,
    }
    if hdr == 12 and len(s7) >= 12:
        rec["error_class"] = s7[10]
        rec["error_code"] = s7[11]
    param = s7[hdr:hdr + param_len]
    data = s7[hdr + param_len:hdr + param_len + data_len]
    if param:
        func = param[0]
        rec["function"] = func
        rec["function_name"] = S7_FUNCTION.get(func, f"0x{func:02x}")
        if func == 0xF0 and len(param) >= 8:                   # Setup communication
            rec["setup"] = {
                "max_amq_calling": _u16be(param, 2),
                "max_amq_called": _u16be(param, 4),
                "pdu_length": _u16be(param, 6),
            }
        elif func in (0x04, 0x05) and len(param) >= 2:         # Read / Write Var
            n_items = param[1]
            rec["item_count"] = n_items
            rec["items"] = _s7_parse_rw_items(param[2:], n_items)
            if data:
                rec["data_items"] = _s7_parse_data_items(data, n_items)
    rec["flags"] = _flags_in(s7, param, data)
    return rec


def parse_tpkt_cotp(buf, off=0):
    """Parse one TPKT+COTP+S7 unit at buf[off:]. Returns (record, next_off) or raises ParseError."""
    d = buf
    if off + 4 > len(d) or d[off] != 0x03 or d[off + 1] != 0x00:
        raise ParseError("not a TPKT header (expected 03 00)")
    tpkt_len = _u16be(d, off + 2)
    if tpkt_len < 7 or off + tpkt_len > len(d):
        raise ParseError("TPKT length out of range")
    end = off + tpkt_len
    cotp_li = d[off + 4]
    pdu_type = d[off + 5] if off + 5 < end else 0
    rec = {
        "protocol": "S7comm/TPKT",
        "tpkt_length": tpkt_len,
        "cotp_pdu_type": pdu_type,
        "cotp_pdu_name": COTP_PDU.get(pdu_type & 0xF0, COTP_PDU.get(pdu_type, f"0x{pdu_type:02x}")),
    }
    cotp_end = off + 5 + cotp_li                               # COTP header: LI byte + LI more octets
    if cotp_end > end:
        raise ParseError("truncated COTP header")
    if (pdu_type & 0xF0) == 0xF0:                              # DT Data -> S7 payload follows
        if cotp_end < end:
            rec["eot"] = bool(d[off + 6] & 0x80) if off + 6 < end else None
            s7 = d[cotp_end:end]
            try:
                rec["s7"] = parse_s7_pdu(s7)
            except ParseError as e:
                rec["s7_error"] = str(e)
                rec["s7_raw_hex"] = _hexpreview(s7)
                rec["flags"] = _flags_in(s7)
    else:
        # CR/CC/DR etc: report refs if present (dst-ref, src-ref)
        if (pdu_type & 0xF0) in (0xE0, 0xD0):
            if off + 10 > cotp_end:
                raise ParseError("truncated COTP connection references")
            rec["dst_ref"] = _u16be(d, off + 6)
            rec["src_ref"] = _u16be(d, off + 8)
    return rec, end


def iter_s7(buf):
    """Yield every TPKT/COTP/S7 unit in a raw buffer (back-to-back frames)."""
    off, out = 0, []
    while off + 4 <= len(buf):
        try:
            rec, off = parse_tpkt_cotp(buf, off)
        except ParseError:
            break
        out.append(rec)
    return out


# ================================================================== DNP3 (TCP/UDP 20000)

def dnp3_crc(data) -> int:
    """CRC-16/DNP (poly 0x3D65, reflected, init 0, xorout 0xFFFF). Check value of b'123456789' is
    0xEA82 -- the published catalogue vector. Stored on the wire little-endian."""
    crc = 0
    for b in bytes(data):
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return (~crc) & 0xFFFF


DNP3_PRIMARY_FC = {
    0: "RESET_LINK_STATES", 1: "RESET_USER_PROCESS", 2: "TEST_LINK_STATES",
    3: "CONFIRMED_USER_DATA", 4: "UNCONFIRMED_USER_DATA", 9: "REQUEST_LINK_STATUS",
}
DNP3_SECONDARY_FC = {
    0: "ACK", 1: "NACK", 11: "LINK_STATUS", 15: "NOT_SUPPORTED",
}

DNP3_APP_FC = {
    0x00: "CONFIRM", 0x01: "READ", 0x02: "WRITE", 0x03: "SELECT", 0x04: "OPERATE",
    0x05: "DIRECT_OPERATE", 0x06: "DIRECT_OPERATE_NR", 0x07: "IMMED_FREEZE",
    0x08: "IMMED_FREEZE_NR", 0x09: "FREEZE_CLEAR", 0x0A: "FREEZE_CLEAR_NR",
    0x0B: "FREEZE_AT_TIME", 0x0C: "FREEZE_AT_TIME_NR", 0x0D: "COLD_RESTART",
    0x0E: "WARM_RESTART", 0x0F: "INITIALIZE_DATA", 0x10: "INITIALIZE_APPL",
    0x11: "START_APPL", 0x12: "STOP_APPL", 0x13: "SAVE_CONFIG",
    0x14: "ENABLE_UNSOLICITED", 0x15: "DISABLE_UNSOLICITED", 0x16: "ASSIGN_CLASS",
    0x17: "DELAY_MEASURE", 0x18: "RECORD_CURRENT_TIME", 0x19: "OPEN_FILE",
    0x1A: "CLOSE_FILE", 0x1B: "DELETE_FILE", 0x1C: "GET_FILE_INFO",
    0x1D: "AUTHENTICATE_FILE", 0x1E: "ABORT_FILE", 0x1F: "ACTIVATE_CONFIG",
    0x20: "AUTHENTICATE_REQ", 0x21: "AUTH_REQUEST_NO_ACK",
    0x81: "RESPONSE", 0x82: "UNSOLICITED_RESPONSE", 0x83: "AUTHENTICATE_RESP",
}

# Common object (group, variation) -> (name, value byte-size per point, decoder key). size None = not auto-decoded.
DNP3_OBJECTS = {
    (1, 0): ("Binary Input - any var", None, None),
    (1, 1): ("Binary Input - packed", None, "packed_bit"),
    (1, 2): ("Binary Input - with flags", 1, "flags_bit"),
    (2, 1): ("Binary Input Event - no time", 1, "flags_bit"),
    (10, 1): ("Binary Output - packed", None, "packed_bit"),
    (10, 2): ("Binary Output - with flags", 1, "flags_bit"),
    (12, 1): ("Binary Output Command - CROB", 11, "crob"),
    (20, 1): ("Counter - 32-bit with flag", 5, "flag_u32"),
    (20, 2): ("Counter - 16-bit with flag", 3, "flag_u16"),
    (20, 5): ("Counter - 32-bit no flag", 4, "u32"),
    (20, 6): ("Counter - 16-bit no flag", 2, "u16"),
    (30, 1): ("Analog Input - 32-bit with flag", 5, "flag_i32"),
    (30, 2): ("Analog Input - 16-bit with flag", 3, "flag_i16"),
    (30, 3): ("Analog Input - 32-bit no flag", 4, "i32"),
    (30, 4): ("Analog Input - 16-bit no flag", 2, "i16"),
    (30, 5): ("Analog Input - short float with flag", 5, "flag_f32"),
    (40, 1): ("Analog Output Status - 32-bit with flag", 5, "flag_i32"),
    (40, 2): ("Analog Output Status - 16-bit with flag", 3, "flag_i16"),
    (41, 1): ("Analog Output Block - 32-bit", 5, "i32_status"),
    (41, 2): ("Analog Output Block - 16-bit", 3, "i16_status"),
    (41, 3): ("Analog Output Block - short float", 5, "f32_status"),
    (50, 1): ("Time and Date", 6, "u48_time"),
    (60, 1): ("Class 0 data", None, None),
    (60, 2): ("Class 1 data", None, None),
    (60, 3): ("Class 2 data", None, None),
    (60, 4): ("Class 3 data", None, None),
    (80, 1): ("Internal Indications", None, None),
    (110, 0): ("Octet String", None, "octet"),
    (111, 0): ("Octet String Event", None, "octet"),
}

DNP3_CONTROL_CODE = {
    0x01: "PULSE_ON", 0x03: "LATCH_ON", 0x04: "LATCH_OFF", 0x41: "PULSE_ON|close",
    0x81: "PULSE_ON|trip", 0x00: "NUL",
}


def _dnp3_point_value(dec, raw):
    """Decode one DNP3 point's value bytes by decoder key `dec`."""
    v = {"raw_hex": raw.hex()}
    try:
        if dec == "flags_bit":
            v["flags"] = raw[0]
            v["state"] = (raw[0] >> 7) & 1
            v["online"] = raw[0] & 1
        elif dec == "flag_u32":
            v["flags"] = raw[0]
            v["value"] = int.from_bytes(raw[1:5], "little")
        elif dec == "flag_u16":
            v["flags"] = raw[0]
            v["value"] = int.from_bytes(raw[1:3], "little")
        elif dec == "u32":
            v["value"] = int.from_bytes(raw[:4], "little")
        elif dec == "u16":
            v["value"] = int.from_bytes(raw[:2], "little")
        elif dec == "flag_i32":
            v["flags"] = raw[0]
            v["value"] = int.from_bytes(raw[1:5], "little", signed=True)
        elif dec == "flag_i16":
            v["flags"] = raw[0]
            v["value"] = int.from_bytes(raw[1:3], "little", signed=True)
        elif dec == "i32":
            v["value"] = int.from_bytes(raw[:4], "little", signed=True)
        elif dec == "i16":
            v["value"] = int.from_bytes(raw[:2], "little", signed=True)
        elif dec == "flag_f32":
            v["flags"] = raw[0]
            v["value"] = struct.unpack("<f", raw[1:5])[0]
        elif dec == "i32_status":
            v["value"] = int.from_bytes(raw[:4], "little", signed=True)
            v["status"] = raw[4]
        elif dec == "i16_status":
            v["value"] = int.from_bytes(raw[:2], "little", signed=True)
            v["status"] = raw[2]
        elif dec == "f32_status":
            v["value"] = struct.unpack("<f", raw[:4])[0]
            v["status"] = raw[4]
        elif dec == "crob":
            v["control_code"] = raw[0]
            v["control_code_name"] = DNP3_CONTROL_CODE.get(raw[0], f"0x{raw[0]:02x}")
            v["count"] = raw[1]
            v["on_time_ms"] = int.from_bytes(raw[2:6], "little")
            v["off_time_ms"] = int.from_bytes(raw[6:10], "little")
            v["status"] = raw[10]
        elif dec == "u48_time":
            v["ms_since_epoch"] = int.from_bytes(raw[:6], "little")
        elif dec == "octet":
            s = _printable_str(raw)
            if s is not None:
                v["ascii"] = s
    except Exception:
        pass
    return v


def _dnp3_qualifier(q):
    prefix = (q >> 4) & 0x07
    rng = q & 0x0F
    pre_names = {0: "no prefix", 1: "1-octet index", 2: "2-octet index", 3: "4-octet index",
                 4: "1-octet size", 5: "2-octet size", 6: "4-octet size"}
    rng_names = {0: "1-octet start/stop", 1: "2-octet start/stop", 2: "4-octet start/stop",
                 3: "1-octet start/stop vaddr", 4: "2-octet start/stop vaddr",
                 5: "4-octet start/stop vaddr", 6: "no range (all objects)",
                 7: "1-octet count", 8: "2-octet count", 9: "4-octet count",
                 0x0B: "1-octet count, variable format"}
    return prefix, rng, pre_names.get(prefix, f"prefix {prefix}"), rng_names.get(rng, f"range {rng}")


def _dnp3_parse_objects(body):
    """Parse the application object headers + point values from the app data `body`."""
    objs, o = [], 0
    guard = 0
    while o + 3 <= len(body) and guard < 256:
        guard += 1
        group, var, qual = body[o], body[o + 1], body[o + 2]
        o += 3
        prefix, rng, pre_name, rng_name = _dnp3_qualifier(qual)
        name, size, dec = DNP3_OBJECTS.get((group, var),
                                           DNP3_OBJECTS.get((group, 0), (f"group {group} var {var}", None, None)))
        if group in (110, 111) and var > 0:                    # octet string: variation IS the length
            size, dec = var, "octet"
            name = f"Octet String ({var}-octet)" + (" Event" if group == 111 else "")
        obj = {
            "group": group, "variation": var, "qualifier": qual,
            "object_name": name, "prefix_code": prefix, "prefix_name": pre_name,
            "range_code": rng, "range_name": rng_name,
        }
        # range field
        start = stop = count = None
        if rng in (0, 3):                                      # 1-octet start/stop
            if o + 2 > len(body):
                break
            start, stop = body[o], body[o + 1]
            count = stop - start + 1
            o += 2
        elif rng in (1, 4):                                   # 2-octet start/stop
            if o + 4 > len(body):
                break
            start, stop = _u16le(body, o), _u16le(body, o + 2)
            count = stop - start + 1
            o += 4
        elif rng == 7:                                        # 1-octet count
            if o >= len(body):
                raise ParseError("truncated DNP3 object count")
            count = body[o]; o += 1
        elif rng == 8:                                        # 2-octet count
            if o + 2 > len(body):
                break
            count = _u16le(body, o); o += 2
        elif rng == 6:                                        # all objects, no range
            count = 0
        else:
            obj["note"] = "range/qualifier not auto-parsed; remaining bytes shown raw"
            obj["raw_hex"] = _hexpreview(body[o:])
            objs.append(obj)
            break
        obj["start"] = start
        obj["stop"] = stop
        obj["count"] = count
        pre_sz = {0: 0, 1: 1, 2: 2, 3: 4}.get(prefix, 0)
        points = []
        if count and size is not None and rng != 6:
            ok = True
            for i in range(count):
                index = None
                if pre_sz:
                    if o + pre_sz > len(body):
                        ok = False
                        break
                    index = int.from_bytes(body[o:o + pre_sz], "little")
                    o += pre_sz
                if o + size > len(body):
                    ok = False
                    break
                raw = body[o:o + size]
                o += size
                pt = {"index": index if index is not None else (start + i if start is not None else i)}
                pt.update(_dnp3_point_value(dec, raw))
                points.append(pt)
            if not ok and o >= len(body):
                pass
        elif dec == "octet" and count:
            # octet-string objects: with 1-octet size prefix each object carries its length
            for i in range(count):
                if prefix in (4, 5, 6):
                    szf = {4: 1, 5: 2, 6: 4}[prefix]
                    if o + szf > len(body):
                        break
                    ln = int.from_bytes(body[o:o + szf], "little")
                    o += szf
                else:
                    ln = len(body) - o
                raw = body[o:o + ln]
                o += ln
                pt = {"index": (start + i if start is not None else i), "raw_hex": raw.hex()}
                s = _printable_str(raw)
                if s is not None:
                    pt["ascii"] = s
                points.append(pt)
        if points:
            obj["points"] = points
        objs.append(obj)
    return objs


def parse_dnp3_frame(buf, off=0):
    """Parse one DNP3 link frame at buf[off:]. Returns (record, next_off) or raises ParseError."""
    d = buf
    if off + 10 > len(d) or d[off] != 0x05 or d[off + 1] != 0x64:
        raise ParseError("not a DNP3 start (expected 05 64)")
    length = d[off + 2]
    if length < 5:
        raise ParseError("DNP3 length < 5")
    ctrl = d[off + 3]
    dest = _u16le(d, off + 4)
    src = _u16le(d, off + 6)
    hdr_crc = _u16le(d, off + 8)
    hdr_ok = (dnp3_crc(d[off:off + 8]) == hdr_crc)
    dir_bit = (ctrl >> 7) & 1
    prm = (ctrl >> 6) & 1
    fc = ctrl & 0x0F
    rec = {
        "protocol": "DNP3",
        "length": length,
        "control": ctrl,
        "dir": dir_bit,
        "prm": prm,
        "fcb": (ctrl >> 5) & 1,
        "fcv": (ctrl >> 4) & 1,
        "link_function": fc,
        "link_function_name": (DNP3_PRIMARY_FC if prm else DNP3_SECONDARY_FC).get(fc, f"0x{fc:x}"),
        "destination": dest,
        "source": src,
        "header_crc": hdr_crc,
        "header_crc_ok": hdr_ok,
    }
    # user data: (length - 5) octets, transmitted in <=16-byte blocks each with a trailing 2-byte CRC
    user_len = length - 5
    o = off + 10
    user = bytearray()
    crc_all_ok = True
    blocks = 0
    while len(user) < user_len:
        take = min(16, user_len - len(user))
        if o + take + 2 > len(d):
            crc_all_ok = False
            break
        chunk = d[o:o + take]
        bcrc = _u16le(d, o + take)
        if dnp3_crc(chunk) != bcrc:
            crc_all_ok = False
        user.extend(chunk)
        o += take + 2
        blocks += 1
    rec["user_data_len"] = user_len
    rec["data_blocks"] = blocks
    rec["block_crc_ok"] = crc_all_ok
    next_off = o
    # transport + application layers
    if user:
        tr = user[0]
        rec["transport"] = {
            "byte": tr, "fin": (tr >> 7) & 1, "fir": (tr >> 6) & 1, "sequence": tr & 0x3F,
        }
        app = bytes(user[1:])
        if app:
            ac = app[0]
            arec = {
                "app_control": ac, "fir": (ac >> 7) & 1, "fin": (ac >> 6) & 1,
                "con": (ac >> 5) & 1, "uns": (ac >> 4) & 1, "sequence": ac & 0x0F,
            }
            ao = 1
            if len(app) >= 2:
                afc = app[1]
                arec["function_code"] = afc
                arec["function_name"] = DNP3_APP_FC.get(afc, f"0x{afc:02x}")
                ao = 2
                if afc in (0x81, 0x82, 0x83) and len(app) >= 4:   # responses carry 2 IIN octets
                    arec["iin"] = _u16le(app, 2)
                    ao = 4
                arec["objects"] = _dnp3_parse_objects(app[ao:])
            rec["application"] = arec
    rec["flags"] = _flags_in(bytes(user), d[off:next_off])
    return rec, next_off


def iter_dnp3(buf):
    off, out = 0, []
    while off + 10 <= len(buf):
        try:
            rec, off = parse_dnp3_frame(buf, off)
        except ParseError:
            break
        out.append(rec)
    return out


# ================================================================== IEC 60870-5-104 (TCP 2404)

IEC104_TYPEID = {
    1: "M_SP_NA_1 Single-point", 2: "M_SP_TA_1 Single-point w/time",
    3: "M_DP_NA_1 Double-point", 4: "M_DP_TA_1 Double-point w/time",
    5: "M_ST_NA_1 Step position", 7: "M_BO_NA_1 Bitstring 32", 9: "M_ME_NA_1 Normalized",
    11: "M_ME_NB_1 Scaled", 13: "M_ME_NC_1 Short float", 15: "M_IT_NA_1 Integrated totals",
    20: "M_PS_NA_1 Packed single-point w/change", 21: "M_ME_ND_1 Normalized no quality",
    30: "M_SP_TB_1 Single-point CP56Time2a", 31: "M_DP_TB_1 Double-point CP56Time2a",
    34: "M_ME_TD_1 Normalized CP56Time2a", 35: "M_ME_TE_1 Scaled CP56Time2a",
    36: "M_ME_TF_1 Short float CP56Time2a", 37: "M_IT_TB_1 Integrated totals CP56Time2a",
    45: "C_SC_NA_1 Single command", 46: "C_DC_NA_1 Double command",
    47: "C_RC_NA_1 Regulating step command", 48: "C_SE_NA_1 Set-point normalized",
    49: "C_SE_NB_1 Set-point scaled", 50: "C_SE_NC_1 Set-point short float",
    51: "C_BO_NA_1 Bitstring 32 command", 58: "C_SC_TA_1 Single command w/time",
    59: "C_DC_TA_1 Double command w/time", 60: "C_RC_TA_1 Reg step w/time",
    61: "C_SE_TA_1 Set-point normalized w/time", 62: "C_SE_TB_1 Set-point scaled w/time",
    63: "C_SE_TC_1 Set-point short float w/time", 64: "C_BO_TA_1 Bitstring command w/time",
    70: "M_EI_NA_1 End of initialization", 100: "C_IC_NA_1 Interrogation command",
    101: "C_CI_NA_1 Counter interrogation", 102: "C_RD_NA_1 Read command",
    103: "C_CS_NA_1 Clock synchronization", 104: "C_TS_NA_1 Test command",
    105: "C_RP_NA_1 Reset process", 106: "C_CD_NA_1 Delay acquisition",
    107: "C_TS_TA_1 Test command w/time", 110: "P_ME_NA_1 Param normalized",
    111: "P_ME_NB_1 Param scaled", 112: "P_ME_NC_1 Param short float",
    113: "P_AC_NA_1 Parameter activation", 120: "F_FR_NA_1 File ready",
    121: "F_SR_NA_1 Section ready", 122: "F_SC_NA_1 Call dir/file/section",
    123: "F_LS_NA_1 Last section", 124: "F_AF_NA_1 Ack file/section",
    125: "F_SG_NA_1 Segment", 126: "F_DR_TA_1 Directory",
}

IEC104_COT = {
    1: "periodic/cyclic", 2: "background scan", 3: "spontaneous", 4: "initialized",
    5: "request/requested", 6: "activation", 7: "activation confirmation",
    8: "deactivation", 9: "deactivation confirmation", 10: "activation termination",
    11: "return info (remote cmd)", 12: "return info (local cmd)", 13: "file transfer",
    20: "interrogated by station", 21: "interrogated by group 1", 37: "interrogated by counter",
    44: "unknown type ID", 45: "unknown cause", 46: "unknown common address",
    47: "unknown IOA",
}

# TypeID -> (element value size in bytes excluding IOA, decoder key).
IEC104_ELEM = {
    1: (1, "siq"), 3: (1, "diq"), 5: (2, "vti_qds"), 7: (5, "bsi_qds"),
    9: (3, "nva_qds"), 11: (3, "sva_qds"), 13: (5, "r32_qds"), 15: (5, "bcr"),
    21: (2, "nva"), 30: (8, "siq_time"), 31: (8, "diq_time"), 36: (12, "r32_qds_time"),
    45: (1, "sco"), 46: (1, "dco"), 47: (1, "rco"), 48: (3, "nva_qos"),
    49: (3, "sva_qos"), 50: (5, "r32_qos"), 70: (1, "coi"),
    100: (1, "qoi"), 101: (1, "qcc"), 102: (0, "none"), 103: (7, "cp56"),
}


def _cp56(raw):
    if len(raw) < 7:
        return {"raw_hex": raw.hex()}
    ms = _u16le(raw, 0)
    minute = raw[2] & 0x3F
    hour = raw[3] & 0x1F
    day = raw[4] & 0x1F
    dow = (raw[4] >> 5) & 0x07
    month = raw[5] & 0x0F
    year = 2000 + (raw[6] & 0x7F)
    return {
        "year": year, "month": month, "day": day, "hour": hour, "minute": minute,
        "second": ms // 1000, "millisecond": ms % 1000, "day_of_week": dow,
        "iso": f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{ms/1000:06.3f}",
        "invalid": bool(raw[2] & 0x80),
    }


def _iec_elem_value(dec, raw):
    v = {"raw_hex": raw.hex()}
    try:
        if dec == "siq":
            v["spi"] = raw[0] & 1
            v["quality"] = raw[0] & 0xF0
        elif dec == "diq":
            v["dpi"] = raw[0] & 0x03
            v["dpi_name"] = {0: "indeterminate", 1: "OFF", 2: "ON", 3: "indeterminate"}[raw[0] & 3]
            v["quality"] = raw[0] & 0xF0
        elif dec == "nva" or dec == "nva_qds" or dec == "nva_qos":
            iv = int.from_bytes(raw[:2], "little", signed=True)
            v["normalized_raw"] = iv
            v["normalized"] = iv / 32768.0
            if dec != "nva":
                v["quality"] = raw[2]
        elif dec == "sva_qds" or dec == "sva_qos":
            v["scaled"] = int.from_bytes(raw[:2], "little", signed=True)
            v["quality"] = raw[2]
        elif dec == "r32_qds" or dec == "r32_qos":
            v["float"] = struct.unpack("<f", raw[:4])[0]
            v["quality"] = raw[4]
        elif dec == "r32_qds_time":
            v["float"] = struct.unpack("<f", raw[:4])[0]
            v["quality"] = raw[4]
            v["time"] = _cp56(raw[5:12])
        elif dec == "siq_time":
            v["spi"] = raw[0] & 1
            v["quality"] = raw[0] & 0xF0
            v["time"] = _cp56(raw[1:8])
        elif dec == "diq_time":
            v["dpi"] = raw[0] & 0x03
            v["time"] = _cp56(raw[1:8])
        elif dec == "bcr":
            v["counter"] = int.from_bytes(raw[:4], "little", signed=True)
            v["sequence_notation"] = raw[4]
        elif dec == "bsi_qds":
            v["bitstring"] = int.from_bytes(raw[:4], "little")
            v["quality"] = raw[4]
        elif dec == "vti_qds":
            _v7 = raw[0] & 0x7F                             # VTI value is I7 (7-bit two's complement)
            v["value"] = _v7 - 128 if (_v7 & 0x40) else _v7
            v["transient"] = (raw[0] >> 7) & 1
            v["quality"] = raw[1]
        elif dec == "sco":
            v["scs"] = raw[0] & 1
            v["scs_name"] = "ON" if raw[0] & 1 else "OFF"
            v["qu"] = (raw[0] >> 2) & 0x1F
            v["select"] = (raw[0] >> 7) & 1
        elif dec == "dco":
            v["dcs"] = raw[0] & 0x03
            v["select"] = (raw[0] >> 7) & 1
        elif dec == "rco":
            v["rcs"] = raw[0] & 0x03
            v["select"] = (raw[0] >> 7) & 1
        elif dec == "qoi":
            v["qoi"] = raw[0]
            v["qoi_name"] = {20: "station (general) interrogation", 0: "not specified"}.get(
                raw[0], "group/other")
        elif dec == "qcc":
            v["qcc"] = raw[0]
        elif dec == "coi":
            v["coi"] = raw[0]
        elif dec == "cp56":
            v.update(_cp56(raw[:7]))
    except Exception:
        pass
    return v


def _iec104_parse_asdu(asdu):
    if len(asdu) < 6:
        return {"error": "ASDU too short", "raw_hex": asdu.hex()}
    typeid = asdu[0]
    vsq = asdu[1]
    sq = (vsq >> 7) & 1
    n = vsq & 0x7F
    cot = asdu[2]
    cause = cot & 0x3F
    rec = {
        "type_id": typeid,
        "type_name": IEC104_TYPEID.get(typeid, f"TypeID {typeid}"),
        "sq": sq,
        "num_objects": n,
        "cause": cause,
        "cause_name": IEC104_COT.get(cause, f"cause {cause}"),
        "test": bool(cot & 0x80),
        "negative": bool(cot & 0x40),
        "originator_address": asdu[3],
        "common_address": _u16le(asdu, 4),
    }
    size_dec = IEC104_ELEM.get(typeid)
    o = 6
    objs = []
    if size_dec is not None and n > 0:
        size, dec = size_dec
        if sq == 0:                                            # each element has its own IOA
            for _ in range(n):
                if o + 3 + size > len(asdu):
                    break
                ioa = _u24le(asdu, o)
                o += 3
                raw = asdu[o:o + size]
                o += size
                pt = {"ioa": ioa}
                pt.update(_iec_elem_value(dec, raw))
                objs.append(pt)
        else:                                                  # SQ=1: one base IOA, consecutive elements
            if o + 3 <= len(asdu):
                base = _u24le(asdu, o)
                o += 3
                for i in range(n):
                    if o + size > len(asdu):
                        break
                    raw = asdu[o:o + size]
                    o += size
                    pt = {"ioa": base + i}
                    pt.update(_iec_elem_value(dec, raw))
                    objs.append(pt)
    else:
        rec["note"] = "element format for this Type ID not auto-decoded; information objects shown raw"
        rec["information_raw_hex"] = _hexpreview(asdu[6:])
    if objs:
        rec["information_objects"] = objs
    rec["flags"] = _flags_in(asdu)
    return rec


IEC104_U_CMD = {
    0x07: "STARTDT act", 0x0B: "STARTDT con", 0x13: "STOPDT act", 0x23: "STOPDT con",
    0x43: "TESTFR act", 0x83: "TESTFR con",
}


def parse_iec104_apdu(buf, off=0):
    """Parse one IEC-104 APDU at buf[off:]. Returns (record, next_off) or raises ParseError."""
    d = buf
    if off + 2 > len(d) or d[off] != 0x68:
        raise ParseError("not an IEC-104 APCI (expected start 0x68)")
    length = d[off + 1]
    if length < 4 or off + 2 + length > len(d):
        raise ParseError("IEC-104 length out of range")
    end = off + 2 + length
    c = d[off + 2:off + 6]
    rec = {"protocol": "IEC-104", "apdu_length": length}
    if (c[0] & 0x01) == 0:                                     # I-format
        ns = (c[0] >> 1) | (c[1] << 7)
        nr = (c[2] >> 1) | (c[3] << 7)
        rec.update({"format": "I", "tx_sequence": ns, "rx_sequence": nr})
        asdu = d[off + 6:end]
        rec["asdu"] = _iec104_parse_asdu(asdu)
        rec["flags"] = rec["asdu"].get("flags", [])
    elif (c[0] & 0x03) == 0x01:                                # S-format
        nr = (c[2] >> 1) | (c[3] << 7)
        rec.update({"format": "S", "rx_sequence": nr})
    else:                                                      # U-format
        rec.update({"format": "U",
                    "u_command": IEC104_U_CMD.get(c[0], f"0x{c[0]:02x}"),
                    "u_control": c[0]})
    return rec, end


def iter_iec104(buf):
    off, out = 0, []
    while off + 2 <= len(buf):
        try:
            rec, off = parse_iec104_apdu(buf, off)
        except ParseError:
            break
        out.append(rec)
    return out


# ================================================================== dispatch + pcap

PROTOCOLS = [
    ("s7comm", lambda b: len(b) >= 4 and b[0] == 0x03 and b[1] == 0x00, iter_s7),
    ("dnp3", lambda b: len(b) >= 2 and b[0] == 0x05 and b[1] == 0x64, iter_dnp3),
    ("iec104", lambda b: len(b) >= 2 and b[0] == 0x68, iter_iec104),
]


def dissect_payload(buf, hint=None):
    """Dissect a raw payload. Returns (protocol_name, [records]) for the first protocol that matches
    the leading signature (or `hint` if given and it parses), else (None, [])."""
    order = PROTOCOLS
    if hint:
        order = [p for p in PROTOCOLS if p[0] == hint] + [p for p in PROTOCOLS if p[0] != hint]
    for name, sig, parser in order:
        if sig(buf):
            recs = parser(buf)
            if recs:
                return name, recs
    # bare S7 (no TPKT) fallback
    if len(buf) >= 10 and buf[0] == 0x32:
        try:
            return "s7comm", [{"protocol": "S7comm", "s7": parse_s7_pdu(buf)}]
        except ParseError:
            pass
    return None, []


def _is_pcap(data) -> bool:
    if len(data) < 4:
        return False
    magic = data[:4]
    return magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",      # pcap (us / ns swapped)
                     b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") or data[:4] == b"\x0a\x0d\x0d\x0a"  # pcapng


def _reassemble(segments):
    """Order TCP segments [(seq, bytes)] into a byte stream by sequence number (handles reordering /
    retransmission; genuine gaps are zero-filled). Seq wrap within a session is assumed not to occur."""
    segs = [(s, bytes(b)) for s, b in segments if b]
    if not segs:
        return b""
    base = min(s for s, _ in segs)
    buf = bytearray()
    for seq, data in sorted(segs, key=lambda x: x[0]):
        off = seq - base
        if off < 0:
            continue
        if off + len(data) > len(buf):
            buf.extend(b"\x00" * (off + len(data) - len(buf)))
        buf[off:off + len(data)] = data
    return bytes(buf)


def read_pcap(path, ports=None):
    """Read a capture with scapy and return a list of flow dicts:
       {proto,'tcp'/'udp', src, sport, dst, dport, protocol_hint, payload}.
    TCP streams on the ICS ports are reassembled per direction; UDP (DNP3) datagrams are concatenated.
    Raises RuntimeError if scapy is unavailable."""
    try:
        from scapy.all import rdpcap, TCP, UDP, IP, IPv6, Raw
    except Exception as e:                                     # pragma: no cover - env without scapy
        raise RuntimeError(f"scapy required to read a pcap ({e}); pass a raw payload file instead")
    port_map = ports or {"s7comm": S7_PORTS, "dnp3": DNP3_PORTS, "iec104": IEC104_PORTS}
    all_ports = set().union(*port_map.values())

    def hint_for(sp, dp):
        for name, ps in port_map.items():
            if sp in ps or dp in ps:
                return name
        return None

    try:
        pkts = rdpcap(path)
    except Exception as e:                                     # malformed / truncated capture
        raise RuntimeError(f"scapy could not read the capture: {e}")
    tcp_flows, udp_flows = {}, {}
    for p in pkts:
        ipsrc = ipdst = None
        if IP in p:
            ipsrc, ipdst = p[IP].src, p[IP].dst
        elif IPv6 in p:
            ipsrc, ipdst = p[IPv6].src, p[IPv6].dst
        if TCP in p:
            t = p[TCP]
            if t.sport not in all_ports and t.dport not in all_ports:
                continue
            payload = bytes(t[Raw].load) if Raw in t else bytes(t.payload)
            if not payload:
                continue
            key = (ipsrc, t.sport, ipdst, t.dport)
            tcp_flows.setdefault(key, []).append((int(t.seq), payload))
        elif UDP in p:
            u = p[UDP]
            if u.sport not in all_ports and u.dport not in all_ports:
                continue
            payload = bytes(u[Raw].load) if Raw in u else bytes(u.payload)
            if not payload:
                continue
            key = (ipsrc, u.sport, ipdst, u.dport)
            udp_flows.setdefault(key, []).append(payload)

    flows = []
    for (src, sport, dst, dport), segs in tcp_flows.items():
        flows.append({"proto": "tcp", "src": src, "sport": sport, "dst": dst, "dport": dport,
                      "protocol_hint": hint_for(sport, dport), "payload": _reassemble(segs)})
    for (src, sport, dst, dport), parts in udp_flows.items():
        flows.append({"proto": "udp", "src": src, "sport": sport, "dst": dst, "dport": dport,
                      "protocol_hint": hint_for(sport, dport), "payload": b"".join(parts)})
    return flows


# ================================================================== report assembly

def analyze_bytes(data, source="<bytes>"):
    """Decode a raw payload buffer. Returns a report dict."""
    proto, recs = dissect_payload(data)
    flags = []
    for r in recs:
        flags += r.get("flags", [])
        if "s7" in r and isinstance(r["s7"], dict):
            flags += r["s7"].get("flags", [])
        if "asdu" in r and isinstance(r["asdu"], dict):
            flags += r["asdu"].get("flags", [])
    flags += _flags_in(data)
    return {
        "source": source, "input": "raw",
        "protocol": proto, "frame_count": len(recs), "frames": recs,
        "flags": sorted(set(flags)),
    }


def analyze_file(path):
    """Decode a file: a .pcap/.pcapng (scapy reassembly) or a raw protocol payload. Returns a report."""
    data = Path(path).read_bytes()
    if len(data) > MAX_FILE:
        return {"source": str(path), "error": f"file too large ({len(data)} bytes)"}
    if _is_pcap(data):
        rep = {"source": str(path), "input": "pcap", "flows": []}
        try:
            flows = read_pcap(str(path))
        except RuntimeError as e:
            rep["error"] = str(e)
            return rep
        all_flags = []
        for fl in flows:
            proto, recs = dissect_payload(fl["payload"], hint=fl.get("protocol_hint"))
            fr = {k: fl[k] for k in ("proto", "src", "sport", "dst", "dport", "protocol_hint")}
            fr["payload_len"] = len(fl["payload"])
            fr["protocol"] = proto
            fr["frame_count"] = len(recs)
            fr["frames"] = recs
            ff = list(_flags_in(fl["payload"]))
            for r in recs:
                ff += r.get("flags", [])
                if isinstance(r.get("s7"), dict):
                    ff += r["s7"].get("flags", [])
                if isinstance(r.get("asdu"), dict):
                    ff += r["asdu"].get("flags", [])
            fr["flags"] = sorted(set(ff))
            all_flags += ff
            rep["flows"].append(fr)
        rep["flags"] = sorted(set(all_flags))
        return rep
    return analyze_bytes(data, source=str(path))


# ---------------------------------------------------------------- human formatting

def _c(s, code, on):
    return f"\x1b[{code}m{s}\x1b[0m" if on else s


def _mark_flags(text, color):
    return FLAG_RE.sub(lambda m: _c(m.group(0), "1;97;41", color), text)


def _fmt_s7(s7, ind, color, lines):
    p = "  " * ind
    lines.append(f"{p}S7comm {s7['rosctr_name']}  pdu_ref={s7['pdu_reference']} "
                 f"param_len={s7['param_length']} data_len={s7['data_length']}")
    if "error_class" in s7:
        lines.append(f"{p}  error: class=0x{s7['error_class']:02x} code=0x{s7['error_code']:02x}")
    if "function_name" in s7:
        lines.append(f"{p}  function: {s7['function_name']} (0x{s7.get('function', 0):02x})")
    if "setup" in s7:
        st = s7["setup"]
        lines.append(f"{p}  setup: max_amq_calling={st['max_amq_calling']} "
                     f"max_amq_called={st['max_amq_called']} negotiated_pdu_len={st['pdu_length']}")
    for i, it in enumerate(s7.get("items", [])):
        if "area_name" in it:
            lines.append(f"{p}  item[{i}]: {it['area_name']} DB{it['db_number']} "
                         f"byte {it['byte_address']}.{it['bit_offset']} "
                         f"type={it['transport_size_name']} count={it['count']}")
        else:
            lines.append(f"{p}  item[{i}]: (non-S7ANY) {it.get('raw_hex', '')}")
    for i, it in enumerate(s7.get("data_items", [])):
        val = it["value"]
        shown = {k: v for k, v in val.items() if k != "raw_hex"}
        vs = ", ".join(f"{k}={v}" for k, v in shown.items()) or f"raw={val['raw_hex']}"
        lines.append(f"{p}  value[{i}]: {it['return_code_name']} {it['transport_size_name']} "
                     f"len={it['length_bytes']}B  {_mark_flags(vs, color)}")


def _fmt_dnp3(r, ind, color, lines):
    p = "  " * ind
    crc = "CRC ok" if r.get("header_crc_ok") and r.get("block_crc_ok") else _c("CRC BAD", "1;91", color)
    lines.append(f"{p}DNP3 link: {r['link_function_name']} "
                 f"{'PRM' if r['prm'] else 'sec'} dst={r['destination']} src={r['source']} "
                 f"len={r['length']} blocks={r.get('data_blocks', 0)} [{crc}]")
    tr = r.get("transport")
    if tr:
        lines.append(f"{p}  transport: FIR={tr['fir']} FIN={tr['fin']} seq={tr['sequence']}")
    app = r.get("application")
    if app:
        iin = f" iin=0x{app['iin']:04x}" if "iin" in app else ""
        lines.append(f"{p}  app: {app.get('function_name', '?')} "
                     f"(0x{app.get('function_code', 0):02x}) seq={app['sequence']} "
                     f"FIR={app['fir']} FIN={app['fin']} CON={app['con']} UNS={app['uns']}{iin}")
        for ob in app.get("objects", []):
            head = (f"{p}    obj g{ob['group']}v{ob['variation']} \"{ob['object_name']}\" "
                    f"qual=0x{ob['qualifier']:02x} [{ob['prefix_name']}; {ob['range_name']}]")
            if ob.get("count") is not None:
                head += f" count={ob['count']}"
            lines.append(head)
            for pt in ob.get("points", []):
                shown = {k: v for k, v in pt.items() if k not in ("raw_hex",)}
                vs = ", ".join(f"{k}={v}" for k, v in shown.items())
                lines.append(f"{p}      point {_mark_flags(vs, color)}")


def _fmt_iec104(r, ind, color, lines):
    p = "  " * ind
    if r["format"] == "I":
        a = r["asdu"]
        lines.append(f"{p}IEC-104 I-frame  N(S)={r['tx_sequence']} N(R)={r['rx_sequence']}")
        neg = " NEG" if a.get("negative") else ""
        test = " TEST" if a.get("test") else ""
        lines.append(f"{p}  ASDU: {a['type_name']}  cause={a['cause_name']}{neg}{test}  "
                     f"CA={a['common_address']} orig={a['originator_address']} "
                     f"objects={a['num_objects']} SQ={a['sq']}")
        for o in a.get("information_objects", []):
            shown = {k: v for k, v in o.items() if k not in ("raw_hex",)}
            vs = ", ".join(f"{k}={v}" for k, v in shown.items())
            lines.append(f"{p}    IOA {_mark_flags(vs, color)}")
        if "note" in a:
            lines.append(f"{p}    ({a['note']}: {a.get('information_raw_hex', '')})")
    elif r["format"] == "S":
        lines.append(f"{p}IEC-104 S-frame  N(R)={r['rx_sequence']} (acknowledge)")
    else:
        lines.append(f"{p}IEC-104 U-frame  {r['u_command']} (control=0x{r['u_control']:02x})")


def _fmt_frame(r, ind, color, lines):
    proto = r.get("protocol", "")
    if proto == "DNP3":
        _fmt_dnp3(r, ind, color, lines)
    elif proto == "IEC-104":
        _fmt_iec104(r, ind, color, lines)
    elif proto.startswith("S7comm"):
        p = "  " * ind
        if "s7" in r and isinstance(r["s7"], dict):
            lines.append(f"{p}TPKT/COTP {r.get('cotp_pdu_name', '')} (tpkt_len={r.get('tpkt_length', '?')})")
            _fmt_s7(r["s7"], ind + 1, color, lines)
        elif "s7_error" in r:
            lines.append(f"{p}TPKT/COTP {r.get('cotp_pdu_name', '')}: S7 undecoded ({r['s7_error']})")
        else:
            lines.append(f"{p}TPKT/COTP {r.get('cotp_pdu_name', '')}")
    else:
        lines.append(f"{'  ' * ind}{json.dumps(r, default=str)[:200]}")


def format_report(rep, color=True):
    lines = []
    src = rep.get("source", "<input>")
    lines.append(f"# {src}")
    if rep.get("error"):
        lines.append(f"  error: {rep['error']}")
        return "\n".join(lines)
    flags = rep.get("flags") or []
    if flags:
        lines.append("")
        lines.append(_c("  *** FLAG FORMAT MATCH ***", "1;97;41", color))
        for f in flags:
            lines.append("    " + _c(f, "1;93", color))
        lines.append("")
    if rep.get("input") == "pcap":
        flows = rep.get("flows", [])
        lines.append(f"  pcap: {len(flows)} relevant ICS flow(s)")
        for fl in flows:
            lines.append(f"  --- {fl['proto']} {fl['src']}:{fl['sport']} -> {fl['dst']}:{fl['dport']} "
                         f"  hint={fl.get('protocol_hint')} decoded={fl.get('protocol')} "
                         f"frames={fl.get('frame_count', 0)} ({fl.get('payload_len', 0)}B)")
            for r in fl.get("frames", []):
                _fmt_frame(r, 2, color, lines)
    else:
        lines.append(f"  raw payload: protocol={rep.get('protocol')} frames={rep.get('frame_count', 0)}")
        for r in rep.get("frames", []):
            _fmt_frame(r, 1, color, lines)
    if not flags and not (rep.get("frames") or rep.get("flows")):
        lines.append("  no S7comm / DNP3 / IEC-104 frames recognised")
    return "\n".join(lines)


# ---------------------------------------------------------------- CLI

def report(paths, as_json=False, color=None):
    """Analyze each path and return the rendered report string (human or JSON)."""
    reps = []
    for p in paths:
        try:
            reps.append(analyze_file(p))
        except OSError as e:
            reps.append({"source": str(p), "error": str(e)})
    if as_json:
        return json.dumps(reps, indent=1, default=lambda o: o.hex() if isinstance(o, (bytes, bytearray)) else str(o))
    if color is None:
        color = sys.stdout.isatty()
    return "\n".join(format_report(r, color=color) for r in reps)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="ics_scada.py",
        description="Offline decoder for S7comm (TCP 102), DNP3 (TCP/UDP 20000) and "
                    "IEC 60870-5-104 (TCP 2404). Input: a raw protocol payload OR a .pcap/.pcapng.")
    ap.add_argument("files", nargs="+", help="raw S7/DNP3/IEC-104 payload file(s) and/or .pcap/.pcapng capture(s)")
    ap.add_argument("--json", action="store_true", help="emit the structured decode as JSON")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI highlighting")
    args = ap.parse_args(argv)
    out = report(args.files, as_json=args.json, color=False if args.no_color else None)
    print(out)
    # exit 0 always (a decode that finds nothing is not an error); a flag hit is surfaced in the text
    return 0


if __name__ == "__main__":
    sys.exit(main())
