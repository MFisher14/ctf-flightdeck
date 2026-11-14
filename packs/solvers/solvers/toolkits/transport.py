#!/usr/bin/env python3
"""Toolkit transport: an OFFLINE, STATIC reader for transport / automotive telemetry artifacts --
the gap beyond the IP/ICS network engines (network.py / net_* ) for the physical-layer buses and
surveillance links a "Total Warfare" transport challenge drops: a captured CAN bus, an aircraft
Mode S / ADS-B downlink, a maritime AIS feed, or a plain GPS NMEA log.

NOTHING here is ever executed or instantiated (the never-execute discipline): the bytes of a frame
are walked as a grammar and only field values and decoded text are read out. The module never
touches the network -- it parses a provided file.

What it decodes:
  CAN      candump text logs ( "(ts) iface ID#DATA", "iface ID [len] D D ..", bare "ID#DATA",
           CAN-FD "ID##fDATA", remote "ID#R" ), raw SocketCAN struct can_frame records, and CAN
           frames pulled from a .pcap/.pcapng (scapy, LINKTYPE_CAN_SOCKETCAN). For each frame:
           arbitration id, 11- vs 29-bit, DLC, data bytes. For a 29-bit id the J1939 breakdown
           (priority, EDP/DP, PDU format/specific, PGN, source & destination address). For an
           OBD-II id (0x7DF / 0x7E0-0x7EF) the ISO-TP single-frame service + PID decode of the
           common mode-01 PIDs (RPM, speed, coolant temp, throttle, MAF, fuel level, ...).
  ADS-B    Mode S DF17/DF18 extended squitter (112-bit): downlink format, capability, 24-bit ICAO
           address, type code; for TC 1-4 the aircraft identification (callsign, 6-bit decode) and
           wake/category; TC 5-8 / 9-18 / 20-22 are noted as surface / airborne position (with the
           raw CPR fields) and TC 19 as velocity. The 24-bit Mode S CRC is checked.
  AIS      NMEA !AIVDM / !AIVDO: multi-fragment reassembly, 6-bit ASCII armor decode, and the
           ITU-R M.1371 field layout for message types 1/2/3 (position: MMSI, lat/lon, SOG/COG,
           nav status) and 5 (static & voyage: MMSI, IMO, call sign, vessel name, destination).
  NMEA     GPS NMEA-0183 GGA (fix quality, sats, lat/lon, altitude, time) and RMC (status, lat/lon,
           SOG, track, date/time) for any talker id (GP/GN/GL/GA/GB...). Checksums validated.

Every decoded text field (callsign, vessel name, destination, GPS sentence, CAN payload as ASCII)
and the raw input are scanned for the CSCTF flag format -- in jeopardy the decoded content IS where
the flag hides, so a hit is HIGHLIGHTED prominently.

CLI:
    .venv/bin/python solvers/toolkits/transport.py <file>... [--json] [--format auto|can|adsb|ais|nmea]
Inputs may be a raw protocol-payload/text file OR a .pcap/.pcapng (CAN frames and NMEA/AIS sentences
are pulled out of packet payloads). Offline parser only; it never connects or scans.
"""
import argparse
import json
import re
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

# Keep stdlib imports clean whether run as a script (toolkit dir first on sys.path) or imported.
HERE = Path(__file__).resolve().parent
if __name__ == "__main__" and sys.path and Path(sys.path[0] or ".").resolve() == HERE:
    sys.path.pop(0)

# construct is a hard dependency of the repo (requirements.txt); use it for the fixed binary
# struct grammar, but degrade to the struct module if it is somehow absent.
try:
    import construct as _cs
    HAVE_CONSTRUCT = True
except Exception:  # noqa: BLE001
    _cs = None
    HAVE_CONSTRUCT = False

# scapy is optional at read time: used for .pcap/.pcapng and as a cross-check, never required.
try:
    import scapy.all as _scapy  # noqa: F401
    HAVE_SCAPY = True
except Exception:  # noqa: BLE001
    _scapy = None
    HAVE_SCAPY = False

KEY = "transport"
MAX_FILE = 64 * 1024 * 1024

# --------------------------------------------------------------------------- event flag detection
# The active event's flag format (ctf.flagfmt). A hit is printed for the player to submit through
# ctf.submit.guarded_submit -- nothing here auto-submits.
FLAG_RE = flagfmt.TEXT


def find_flags(data) -> set:
    """Every event-format flag string in a body (bytes or str), deduplicated. Bytes are raw CAN frames
    and binary captures, where a flag can follow a byte of the previous field, so they are scanned
    without a word boundary before the flag (flagfmt.PACKED_TEXT, R-16); text keeps the boundary."""
    if isinstance(data, (bytes, bytearray)):
        text, rx = bytes(data).decode("utf-8", "replace"), flagfmt.PACKED_TEXT
    else:
        text, rx = str(data or ""), FLAG_RE
    return set(rx.findall(text))


def is_flag(value) -> bool:
    """True when value is exactly one CSCTF-format flag (the returnable form)."""
    return isinstance(value, str) and FLAG_RE.fullmatch(value) is not None


# =========================================================================== bit helpers
def _bits(data: bytes) -> str:
    """A big-endian '0'/'1' string for the bytes (MSB first) -- the natural order for the
    bit-packed Mode S and AIS field layouts."""
    return "".join(f"{b:08b}" for b in data)


def _ub(bits: str, start: int, length: int) -> int:
    """Unsigned integer from bits[start:start+length]."""
    return int(bits[start:start + length], 2) if length else 0


def _sb(bits: str, start: int, length: int) -> int:
    """Two's-complement signed integer from bits[start:start+length]."""
    v = int(bits[start:start + length], 2)
    if v & (1 << (length - 1)):
        v -= 1 << length
    return v


def _ascii_preview(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


# =========================================================================== CAN bus
CAN_EFF_FLAG = 0x80000000   # extended (29-bit) frame
CAN_RTR_FLAG = 0x40000000   # remote transmission request
CAN_ERR_FLAG = 0x20000000   # error frame
CAN_EFF_MASK = 0x1FFFFFFF
CAN_SFF_MASK = 0x000007FF

# A small, well-known subset of J1939 PGNs for a friendlier report (purely cosmetic labels).
J1939_PGN_NAMES = {
    0x00000: "Torque/Speed Control 1 (TSC1)",
    0x0F004: "Electronic Engine Controller 1 (EEC1)",
    0x0F003: "Electronic Engine Controller 2 (EEC2)",
    0x0FEF1: "Cruise Control / Vehicle Speed (CCVS1)",
    0x0FEEE: "Engine Temperature 1 (ET1)",
    0x0FEEF: "Engine Fluid Level/Pressure 1 (EFL/P1)",
    0x0FEF2: "Fuel Economy (LFE)",
    0x0FEF5: "Ambient Conditions (AMB)",
    0x0FEF6: "Inlet/Exhaust Conditions 1 (IC1)",
    0x0FEE5: "Engine Hours/Revolutions (HOURS)",
    0x0FEE9: "Fuel Consumption (LFC)",
    0x0FEEC: "Vehicle Identification (VI)",
    0x0FECA: "Diagnostic Message 1 - active DTCs (DM1)",
    0x0FECB: "Diagnostic Message 2 (DM2)",
    0x0EA00: "Request (PGN request)",
    0x0EE00: "Address Claimed / Cannot Claim",
    0x0EB00: "Transport Protocol - Data Transfer (TP.DT)",
    0x0EC00: "Transport Protocol - Connection Mgmt (TP.CM)",
    0x0FE6C: "Tachograph (TCO1)",
}

# J1939 source/destination address 0xFF is the global/broadcast address.
J1939_GLOBAL_ADDR = 0xFF


def decode_can_id(canid: int, extended=None) -> dict:
    """Break a raw CAN arbitration id into its 11-/29-bit interpretation, and -- for a 29-bit id --
    its SAE J1939 fields (priority, EDP, DP, PDU format/specific, PGN, source & dest address).

    `extended` forces the frame kind; when None, an id that does not fit 11 bits is treated as 29-bit.
    """
    if extended is None:
        extended = canid > CAN_SFF_MASK
    out = {"id": canid, "id_hex": f"{canid:X}", "extended": bool(extended)}
    if not extended:
        out["id"] &= CAN_SFF_MASK
        out["id_hex"] = f"{out['id']:03X}"
        return out
    cid = canid & CAN_EFF_MASK
    out["id"] = cid
    out["id_hex"] = f"{cid:08X}"
    priority = (cid >> 26) & 0x7
    edp = (cid >> 25) & 0x1          # extended data page (reserved)
    dp = (cid >> 24) & 0x1           # data page
    pf = (cid >> 16) & 0xFF          # PDU format
    ps = (cid >> 8) & 0xFF           # PDU specific (destination addr in PDU1, group ext in PDU2)
    sa = cid & 0xFF                  # source address
    if pf < 240:                     # PDU1: destination-specific; PS is the destination address
        pgn = (edp << 17) | (dp << 16) | (pf << 8)
        dest = ps
    else:                            # PDU2: broadcast; PS is a group extension, part of the PGN
        pgn = (edp << 17) | (dp << 16) | (pf << 8) | ps
        dest = J1939_GLOBAL_ADDR
    out["j1939"] = {
        "priority": priority, "edp": edp, "dp": dp,
        "pdu_format": pf, "pdu_specific": ps, "source_address": sa,
        "dest_address": dest, "pgn": pgn, "pgn_hex": f"{pgn:05X}",
        "pgn_name": J1939_PGN_NAMES.get(pgn),
    }
    return out


# ---- OBD-II (mode 01 current data) -----------------------------------------------------------
# Each: pid -> (name, n_data_bytes, decoder(data)->float|int|None, unit). Formulas per SAE J1979.
def _obd_ab(data, i=0):
    return data[i], data[i + 1]


OBD_PIDS = {
    0x04: ("Calculated engine load", 1, lambda d: d[0] * 100.0 / 255, "%"),
    0x05: ("Engine coolant temperature", 1, lambda d: d[0] - 40, "degC"),
    0x06: ("Short term fuel trim bank 1", 1, lambda d: (d[0] - 128) * 100.0 / 128, "%"),
    0x07: ("Long term fuel trim bank 1", 1, lambda d: (d[0] - 128) * 100.0 / 128, "%"),
    0x0A: ("Fuel pressure", 1, lambda d: d[0] * 3, "kPa"),
    0x0B: ("Intake manifold abs pressure", 1, lambda d: d[0], "kPa"),
    0x0C: ("Engine RPM", 2, lambda d: ((d[0] << 8) | d[1]) / 4.0, "rpm"),
    0x0D: ("Vehicle speed", 1, lambda d: d[0], "km/h"),
    0x0E: ("Timing advance", 1, lambda d: d[0] / 2.0 - 64, "deg"),
    0x0F: ("Intake air temperature", 1, lambda d: d[0] - 40, "degC"),
    0x10: ("MAF air flow rate", 2, lambda d: ((d[0] << 8) | d[1]) / 100.0, "g/s"),
    0x11: ("Throttle position", 1, lambda d: d[0] * 100.0 / 255, "%"),
    0x1F: ("Run time since engine start", 2, lambda d: (d[0] << 8) | d[1], "s"),
    0x21: ("Distance with MIL on", 2, lambda d: (d[0] << 8) | d[1], "km"),
    0x2F: ("Fuel tank level input", 1, lambda d: d[0] * 100.0 / 255, "%"),
    0x31: ("Distance since codes cleared", 2, lambda d: (d[0] << 8) | d[1], "km"),
    0x33: ("Absolute barometric pressure", 1, lambda d: d[0], "kPa"),
    0x42: ("Control module voltage", 2, lambda d: ((d[0] << 8) | d[1]) / 1000.0, "V"),
    0x46: ("Ambient air temperature", 1, lambda d: d[0] - 40, "degC"),
    0x5E: ("Engine fuel rate", 2, lambda d: ((d[0] << 8) | d[1]) / 20.0, "L/h"),
}

OBD_MODE_NAMES = {
    0x01: "show current data", 0x02: "show freeze frame data", 0x03: "show stored DTCs",
    0x04: "clear DTCs", 0x09: "vehicle information",
}
OBD_REQUEST_IDS = {0x7DF} | set(range(0x7E0, 0x7E8))
OBD_RESPONSE_IDS = set(range(0x7E8, 0x7F0))


def decode_obd(canid: int, data: bytes) -> dict | None:
    """Decode an OBD-II ISO-TP single frame on a diagnostic CAN id. Returns None when the id is not
    an OBD id or the frame is not a readable single-frame request/response."""
    if canid not in OBD_REQUEST_IDS and canid not in OBD_RESPONSE_IDS:
        return None
    if len(data) < 2:
        return None
    pci = data[0]
    pci_type = pci >> 4
    if pci_type != 0:           # only single frames (SF) are decoded structurally here
        return None
    length = pci & 0x0F
    if length < 1 or length > 7 or 1 + length > len(data):
        return None
    payload = data[1:1 + length]
    service = payload[0]
    is_response = service & 0x40
    mode = service & 0xBF
    out = {
        "is_response": bool(is_response),
        "service": service,
        "mode": mode,
        "mode_name": OBD_MODE_NAMES.get(mode),
        "pid": payload[1] if len(payload) >= 2 else None,
    }
    pid = out["pid"]
    if mode == 0x01 and pid is not None and pid in OBD_PIDS:
        name, nbytes, fn, unit = OBD_PIDS[pid]
        d = payload[2:2 + nbytes]
        out["pid_name"] = name
        out["pid_hex"] = f"{pid:02X}"
        if is_response and len(d) >= nbytes:
            try:
                out["value"] = round(fn(d), 4) if isinstance(fn(d), float) else fn(d)
                out["unit"] = unit
            except Exception:  # noqa: BLE001
                out["value"] = None
    elif pid is not None:
        out["pid_hex"] = f"{pid:02X}"
    return out


# ---- candump / SocketCAN parsing -------------------------------------------------------------
# candump log format: "(1529487759.000000) can0 18FEF100#0102030405060708"
_CANDUMP_LOG = re.compile(
    r"^\((?P<ts>\d+\.\d+)\)\s+(?P<iface>\S+)\s+(?P<id>[0-9A-Fa-f]+)(?P<sep>#{1,2})(?P<data>.*)$")
# candump default/space format: "can0  18FEF100   [8]  01 02 03 04 05 06 07 08"
_CANDUMP_SPACE = re.compile(
    r"^(?P<iface>\S+)\s+(?P<id>[0-9A-Fa-f]+)\s+\[(?P<dlc>\d+)\]\s+(?P<data>[0-9A-Fa-f ]*)$")
# bare format: "18FEF100#0102030405060708"
_CANDUMP_BARE = re.compile(r"^(?P<id>[0-9A-Fa-f]+)(?P<sep>#{1,2})(?P<data>.*)$")


def _can_frame_from_fields(canid_text, sep, data_text, dlc=None, ts=None, iface=None):
    canid = int(canid_text, 16)
    # Extended id is signalled either by >3 hex digits or by an explicit > 11-bit value.
    extended = len(canid_text.strip()) > 3 or canid > CAN_SFF_MASK
    fd = sep == "##"
    remote = False
    data_text = (data_text or "").strip()
    if fd and data_text:
        # CAN-FD: first hex nib/byte after ## is the FD flags byte.
        data_text = data_text[2:] if len(data_text) >= 2 else ""
    if data_text.upper().startswith("R") and sep == "#":
        remote = True
        data = b""
    else:
        hexstr = re.sub(r"\s+", "", data_text)
        if len(hexstr) % 2:
            hexstr = hexstr[:-1]
        try:
            data = bytes.fromhex(hexstr)
        except ValueError:
            data = b""
    frame = {
        "id_raw": canid, "extended": extended, "fd": fd, "remote": remote,
        "dlc": dlc if dlc is not None else len(data), "data": data,
        "data_hex": data.hex(), "ts": float(ts) if ts else None, "iface": iface,
    }
    frame.update(_enrich_can(canid, extended, data))
    return frame


def _enrich_can(canid, extended, data):
    info = {"decode": decode_can_id(canid, extended)}
    obd = decode_obd(canid & (CAN_EFF_MASK if extended else CAN_SFF_MASK), data)
    if obd:
        info["obd"] = obd
    ascii_data = _ascii_preview(data)
    info["ascii"] = ascii_data
    return info


def parse_candump_line(line: str):
    """Parse one candump line into a CAN frame dict, or None if the line is not a candump frame."""
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("//"):
        return None
    m = _CANDUMP_LOG.match(line)
    if m:
        return _can_frame_from_fields(m["id"], m["sep"], m["data"], ts=m["ts"], iface=m["iface"])
    m = _CANDUMP_SPACE.match(line)
    if m:
        return _can_frame_from_fields(m["id"], "#", m["data"], dlc=int(m["dlc"]), iface=m["iface"])
    m = _CANDUMP_BARE.match(line)
    if m and len(m["id"]) in (3, 8) or (m and 1 <= len(m["id"]) <= 8 and m["sep"]):
        return _can_frame_from_fields(m["id"], m["sep"], m["data"])
    return None


def parse_candump_text(text: str) -> list:
    frames = []
    for line in text.splitlines():
        try:
            fr = parse_candump_line(line)
        except Exception:  # noqa: BLE001
            fr = None
        if fr is not None:
            frames.append(fr)
    return frames


# raw SocketCAN struct can_frame: __u32 can_id (host/LE), __u8 can_dlc, 3 pad, __u8 data[8] = 16 B.
if HAVE_CONSTRUCT:
    _CAN_FRAME_STRUCT = _cs.Struct(
        "can_id" / _cs.Int32ul,
        "can_dlc" / _cs.Int8ul,
        "_pad" / _cs.Bytes(3),
        "data" / _cs.Bytes(8),
    )
else:
    _CAN_FRAME_STRUCT = None


def parse_socketcan_struct(data: bytes) -> list:
    """Parse a buffer of raw 16-byte SocketCAN `struct can_frame` records (little-endian can_id with
    the EFF/RTR/ERR flag bits in the top 3 bits). Returns [] if the buffer is not a clean multiple
    of 16 or the records do not look like can_frames."""
    if not data or len(data) % 16 != 0:
        return []
    frames = []
    for off in range(0, len(data), 16):
        rec = data[off:off + 16]
        if _CAN_FRAME_STRUCT is not None:
            p = _CAN_FRAME_STRUCT.parse(rec)
            raw_id, dlc, payload = p.can_id, p.can_dlc, p.data
        else:
            raw_id, dlc = struct.unpack_from("<IB", rec, 0)
            payload = rec[8:16]
        extended = bool(raw_id & CAN_EFF_FLAG)
        remote = bool(raw_id & CAN_RTR_FLAG)
        err = bool(raw_id & CAN_ERR_FLAG)
        canid = raw_id & (CAN_EFF_MASK if extended else CAN_SFF_MASK)
        if dlc > 8:                                 # not a classic can_frame -> bail on the whole buffer
            return []
        payload = payload[:dlc]
        frame = {
            "id_raw": canid, "extended": extended, "fd": False, "remote": remote, "error": err,
            "dlc": dlc, "data": payload, "data_hex": payload.hex(), "ts": None, "iface": None,
        }
        frame.update(_enrich_can(canid, extended, payload))
        frames.append(frame)
    return frames


# =========================================================================== ADS-B / Mode S
# Mode S 24-bit CRC generator polynomial (x^24 + x^23 + ... ); for DF17/18 a correct frame divides
# to a zero remainder (parity is the plain CRC, not address-overlaid).
_MODES_GEN = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1]
# TC 1-4 aircraft-id 6-bit charset (ICAO Annex 10 / Doc 9871).
_ADSB_CS = "#ABCDEFGHIJKLMNOPQRSTUVWXYZ##### ###############0123456789######"

_ADSB_CATEGORY = {
    (1, 0): "No ADS-B emitter category information",
    (2, 1): "Surface emergency vehicle", (2, 3): "Surface service vehicle",
    (3, 1): "Glider/sailplane", (3, 2): "Lighter-than-air", (3, 3): "Parachutist/skydiver",
    (3, 4): "Ultralight/hang-glider", (3, 6): "UAV", (3, 7): "Space/transatmospheric",
    (4, 1): "Light (<15500 lbs)", (4, 2): "Medium 1 (15500-75000 lbs)",
    (4, 3): "Medium 2 (75000-300000 lbs)", (4, 4): "High vortex aircraft",
    (4, 5): "Heavy (>300000 lbs)", (4, 6): "High performance", (4, 7): "Rotorcraft",
}


def modes_crc_remainder(frame: bytes) -> int:
    """The Mode S CRC remainder over a 56- or 112-bit frame. 0 means a valid DF17/18 parity."""
    msgbin = [((b >> i) & 1) for b in frame for i in range(7, -1, -1)]
    if len(msgbin) < 24:
        return -1
    for i in range(len(msgbin) - 24):
        if msgbin[i]:
            for j in range(25):
                msgbin[i + j] ^= _MODES_GEN[j]
    rem = 0
    for i in range(24):
        rem = (rem << 1) | msgbin[-24 + i]
    return rem


def decode_adsb_callsign(me: bytes) -> str:
    """Decode the 8-character callsign from a TC 1-4 aircraft-identification ME field."""
    bits = _bits(me)
    chars = []
    for i in range(8):
        v = _ub(bits, 8 + i * 6, 6)
        chars.append(_ADSB_CS[v])
    return "".join(chars).replace("#", "").rstrip()


def decode_modes(frame: bytes) -> dict | None:
    """Decode a Mode S frame. Full ME decode for DF17/18 extended squitter; a short summary for
    other downlink formats. Returns None if the frame is too short to be Mode S."""
    if len(frame) not in (7, 14):
        return None
    df = frame[0] >> 3
    out = {
        "df": df, "bytes": len(frame), "raw_hex": frame.hex().upper(),
        "crc_remainder": modes_crc_remainder(frame),
    }
    out["crc_ok"] = out["crc_remainder"] == 0
    if df in (17, 18) and len(frame) == 14:
        out["capability"] = frame[0] & 0x07
        out["icao"] = frame[1:4].hex().upper()
        me = frame[4:11]
        out["me_hex"] = me.hex().upper()
        tc = me[0] >> 3
        out["type_code"] = tc
        if 1 <= tc <= 4:                            # aircraft identification
            out["msg"] = "aircraft_identification"
            cat = me[0] & 0x07
            out["category_raw"] = cat
            out["category"] = _ADSB_CATEGORY.get((tc, cat))
            out["callsign"] = decode_adsb_callsign(me)
        elif 5 <= tc <= 8:                          # surface position
            out["msg"] = "surface_position"
            out.update(_adsb_position_raw(me))
        elif 9 <= tc <= 18 or 20 <= tc <= 22:       # airborne position (baro / GNSS)
            out["msg"] = "airborne_position"
            out["altitude_ft"] = _adsb_alt(me)
            out.update(_adsb_position_raw(me))
        elif tc == 19:                              # airborne velocity
            out["msg"] = "airborne_velocity"
        else:
            out["msg"] = f"type_code_{tc}"
    else:
        out["icao"] = frame[1:4].hex().upper() if len(frame) >= 4 else None
        out["msg"] = f"downlink_format_{df}"
    return out


def _adsb_position_raw(me: bytes) -> dict:
    """The CPR fields of a position ME. Full lat/lon needs an even+odd CPR pair or a reference
    position (local decode); we report the raw CPR so the player can pair/solve them."""
    bits = _bits(me)
    return {
        "cpr_odd": _ub(bits, 21, 1),
        "cpr_lat": _ub(bits, 22, 17),
        "cpr_lon": _ub(bits, 39, 17),
        "note": "position needs an even+odd CPR pair (or a reference) to resolve lat/lon",
    }


def _adsb_alt(me: bytes) -> float | None:
    """Barometric altitude from an airborne-position ME (the Q-bit 25-ft encoding)."""
    bits = _bits(me)
    alt = _ub(bits, 8, 12)              # 12-bit altitude field (bits 8-19 of ME)
    if alt == 0:
        return None
    q = (alt >> 4) & 1
    if q:
        n = ((alt & 0xFE0) >> 1) | (alt & 0x0F)
        return n * 25 - 1000
    return None                         # Gillham (gray) coding not resolved here


def _hex_frames(text: str):
    """Pull Mode S frames out of a text log: dump1090 AVR "*8D..;" lines or bare 14/28-hex lines."""
    frames = []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        m = re.match(r"^[*@]?([0-9A-Fa-f]{14}|[0-9A-Fa-f]{28})[;]?\s*$", s)
        if m:
            try:
                frames.append(bytes.fromhex(m.group(1)))
            except ValueError:
                pass
    return frames


# =========================================================================== AIS (AIVDM/AIVDO)
_NAV_STATUS = {
    0: "under way using engine", 1: "at anchor", 2: "not under command",
    3: "restricted manoeuvrability", 4: "constrained by draught", 5: "moored",
    6: "aground", 7: "engaged in fishing", 8: "under way sailing",
    14: "AIS-SART/MOB/EPIRB", 15: "undefined",
}
_SHIP_TYPE = {
    30: "Fishing", 31: "Towing", 35: "Military ops", 36: "Sailing", 37: "Pleasure craft",
    52: "Tug", 60: "Passenger", 70: "Cargo", 80: "Tanker", 90: "Other",
}


def ais_unarmor(payload: str, fill: int = 0) -> str:
    """ASCII-armored AIS payload -> bitstring (each char is 6 bits), minus the trailing `fill` bits."""
    bits = []
    for ch in payload:
        v = ord(ch) - 48
        if v > 40:
            v -= 8
        if v < 0 or v > 63:
            raise ValueError(f"bad AIS payload char {ch!r}")
        bits.append(f"{v:06b}")
    s = "".join(bits)
    if fill:
        s = s[:len(s) - fill]
    return s


def ais_text(bits: str) -> str:
    """Decode a run of 6-bit AIS characters (ITU-R M.1371 table) into text, trimming the '@' pad
    and trailing spaces."""
    out = []
    for i in range(0, len(bits) - 5, 6):
        v = int(bits[i:i + 6], 2)
        out.append(chr(v + 64) if v < 32 else chr(v))
    return "".join(out).replace("@", " ").rstrip()


def _ais_latlon(bits, lon_at, lon_len, lat_at, lat_len):
    lon = _sb(bits, lon_at, lon_len) / 600000.0
    lat = _sb(bits, lat_at, lat_len) / 600000.0
    return lon, lat


def decode_ais_payload(bits: str) -> dict:
    """Decode the ITU-R M.1371 fields of a reassembled AIS message. Types 1/2/3 (position) and 5
    (static & voyage) are fully broken out; other types get type + MMSI."""
    if len(bits) < 38:
        return {"error": "payload too short"}
    mtype = _ub(bits, 0, 6)
    out = {"type": mtype, "repeat": _ub(bits, 6, 2), "mmsi": _ub(bits, 8, 38 - 8)}
    if mtype in (1, 2, 3):
        out["msg"] = "position_report_class_a"
        status = _ub(bits, 38, 4)
        out["nav_status"] = status
        out["nav_status_name"] = _NAV_STATUS.get(status)
        rot = _sb(bits, 42, 8)
        out["rate_of_turn_raw"] = rot
        sog = _ub(bits, 50, 10)
        out["sog_knots"] = None if sog == 1023 else sog / 10.0
        out["position_accuracy"] = _ub(bits, 60, 1)
        lon, lat = _ais_latlon(bits, 61, 28, 89, 27)
        out["lon"] = None if abs(lon) > 180 else round(lon, 6)
        out["lat"] = None if abs(lat) > 90 else round(lat, 6)
        cog = _ub(bits, 116, 12)
        out["cog"] = None if cog == 3600 else cog / 10.0
        hdg = _ub(bits, 128, 9)
        out["heading"] = None if hdg == 511 else hdg
        out["timestamp"] = _ub(bits, 137, 6)
    elif mtype == 5 and len(bits) >= 424:
        out["msg"] = "static_and_voyage_data"
        out["ais_version"] = _ub(bits, 38, 2)
        out["imo"] = _ub(bits, 40, 30)
        out["callsign"] = ais_text(bits[70:112])
        out["shipname"] = ais_text(bits[112:232])
        stype = _ub(bits, 232, 8)
        out["ship_type"] = stype
        out["ship_type_name"] = _SHIP_TYPE.get(stype)
        out["draught"] = _ub(bits, 294, 8) / 10.0
        out["destination"] = ais_text(bits[302:422])
    elif mtype == 4:
        out["msg"] = "base_station_report"
        lon, lat = _ais_latlon(bits, 79, 28, 107, 27)
        out["lon"] = None if abs(lon) > 180 else round(lon, 6)
        out["lat"] = None if abs(lat) > 90 else round(lat, 6)
    elif mtype == 18:
        out["msg"] = "position_report_class_b"
        sog = _ub(bits, 46, 10)
        out["sog_knots"] = None if sog == 1023 else sog / 10.0
        lon, lat = _ais_latlon(bits, 57, 28, 85, 27)
        out["lon"] = None if abs(lon) > 180 else round(lon, 6)
        out["lat"] = None if abs(lat) > 90 else round(lat, 6)
    elif mtype in (24,):
        out["msg"] = "static_data_report"
        part = _ub(bits, 38, 2)
        out["part"] = part
        if part == 0 and len(bits) >= 160:
            out["shipname"] = ais_text(bits[40:160])
    else:
        out["msg"] = f"type_{mtype}"
    return out


def parse_aivdm(text: str) -> list:
    """Reassemble and decode !AIVDM / !AIVDO sentences in a text body. Multi-fragment messages are
    joined by (channel, message-id); the fill-bit count of the last fragment is applied."""
    sentences = []
    for line in text.splitlines():
        s = line.strip()
        if "AIVDM" not in s and "AIVDO" not in s:
            continue
        i = s.find("!AIVD")
        if i < 0:
            continue
        s = s[i:]
        body = s[1:].split("*")[0]              # strip leading '!' and the *checksum
        parts = body.split(",")
        if len(parts) < 6 or parts[0] not in ("AIVDM", "AIVDO"):
            continue
        try:
            total = int(parts[1]); frag = int(parts[2])
        except ValueError:
            continue
        msgid = parts[3]
        channel = parts[4]
        payload = parts[5]
        fill = 0
        if len(parts) >= 7:
            try:
                fill = int(parts[6])
            except ValueError:
                fill = 0
        sentences.append({"total": total, "frag": frag, "msgid": msgid,
                          "channel": channel, "payload": payload, "fill": fill, "raw": s})
    # group multi-fragment
    out = []
    pending = {}
    for sen in sentences:
        if sen["total"] == 1:
            out.append(_finish_ais([sen]))
            continue
        key = (sen["channel"], sen["msgid"])
        pending.setdefault(key, []).append(sen)
        group = pending[key]
        if len(group) == sen["total"]:
            group.sort(key=lambda x: x["frag"])
            out.append(_finish_ais(group))
            del pending[key]
    for group in pending.values():              # emit incomplete groups best-effort
        group.sort(key=lambda x: x["frag"])
        out.append(_finish_ais(group, complete=False))
    return out


def _finish_ais(group, complete=True):
    payload = "".join(g["payload"] for g in group)
    fill = group[-1]["fill"]
    rec = {
        "fragments": len(group), "complete": complete,
        "channel": group[0]["channel"], "msgid": group[0]["msgid"],
        "raw": [g["raw"] for g in group],
    }
    try:
        bits = ais_unarmor(payload, fill)
        rec["decoded"] = decode_ais_payload(bits)
    except Exception as e:  # noqa: BLE001
        rec["error"] = str(e)
    return rec


# =========================================================================== NMEA-0183 / GPS
def nmea_checksum(sentence: str) -> str:
    """The NMEA XOR checksum (hex, 2 chars) of the body between '$'/'!' and '*'."""
    body = sentence
    if body and body[0] in "$!":
        body = body[1:]
    body = body.split("*")[0]
    c = 0
    for ch in body:
        c ^= ord(ch)
    return f"{c:02X}"


def _nmea_latlon(val, hemi):
    """ddmm.mmmm + hemisphere -> signed decimal degrees."""
    if not val:
        return None
    try:
        f = float(val)
    except ValueError:
        return None
    deg = int(f // 100)
    minutes = f - deg * 100
    dec = deg + minutes / 60.0
    if hemi in ("S", "W"):
        dec = -dec
    return round(dec, 6)


def parse_nmea_line(line: str):
    """Parse a GGA or RMC sentence (any talker id) into a dict, or None otherwise."""
    s = line.strip()
    i = s.find("$")
    if i < 0:
        i = s.find("!")
    if i < 0:
        return None
    s = s[i:]
    star = s.find("*")
    chk = None
    if star >= 0:
        chk = s[star + 1:star + 3]
    body = s[1:star] if star >= 0 else s[1:]
    f = body.split(",")
    if not f:
        return None
    tag = f[0]
    if len(tag) != 5:
        return None
    talker, kind = tag[:2], tag[2:]
    out = {"talker": talker, "sentence": kind, "raw": s}
    if chk is not None:
        out["checksum"] = chk.upper()
        out["checksum_ok"] = nmea_checksum(s) == chk.upper()
    if kind == "GGA" and len(f) >= 10:
        out["type"] = "GGA"
        out["time_utc"] = f[1]
        out["lat"] = _nmea_latlon(f[2], f[3])
        out["lon"] = _nmea_latlon(f[4], f[5])
        out["fix_quality"] = _int(f[6])
        out["fix_text"] = {0: "invalid", 1: "GPS fix", 2: "DGPS fix", 4: "RTK fixed",
                           5: "RTK float"}.get(_int(f[6]))
        out["num_sats"] = _int(f[7])
        out["hdop"] = _float(f[8])
        out["altitude_m"] = _float(f[9])
        return out
    if kind == "RMC" and len(f) >= 10:
        out["type"] = "RMC"
        out["time_utc"] = f[1]
        out["status"] = f[2]
        out["status_text"] = {"A": "valid/active", "V": "void/invalid"}.get(f[2])
        out["lat"] = _nmea_latlon(f[3], f[4])
        out["lon"] = _nmea_latlon(f[5], f[6])
        out["sog_knots"] = _float(f[7])
        out["track_deg"] = _float(f[8])
        out["date"] = f[9]
        return out
    return None


def _int(x):
    try:
        return int(x)
    except (ValueError, TypeError):
        return None


def _float(x):
    try:
        return float(x)
    except (ValueError, TypeError):
        return None


def parse_nmea_text(text: str) -> list:
    out = []
    for line in text.splitlines():
        if "GGA" not in line and "RMC" not in line:
            continue
        try:
            rec = parse_nmea_line(line)
        except Exception:  # noqa: BLE001
            rec = None
        if rec:
            out.append(rec)
    return out


# =========================================================================== pcap input
def _is_pcap(data: bytes) -> bool:
    return data[:4] in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1",
                        b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1") or data[:4] == b"\x0a\x0d\x0d\x0a"


def read_pcap(path: str) -> dict:
    """Pull CAN frames and NMEA/AIS text out of a .pcap/.pcapng using scapy. Returns {} when scapy
    is absent (the caller then falls back to raw/text parsing)."""
    if not HAVE_SCAPY:
        return {}
    result = {"can": [], "nmea_text": []}
    try:
        packets = _scapy.rdpcap(path)
    except Exception:  # noqa: BLE001
        return {}
    try:
        from scapy.layers.can import CAN as _CAN
    except Exception:  # noqa: BLE001
        _CAN = None
    text_chunks = []
    for pkt in packets:
        if _CAN is not None and pkt.haslayer(_CAN):
            c = pkt.getlayer(_CAN)
            canid = int(c.identifier)
            extended = canid > CAN_SFF_MASK
            payload = bytes(c.data)[:int(c.length)] if hasattr(c, "length") else bytes(c.data)
            frame = {
                "id_raw": canid, "extended": extended, "fd": False, "remote": False,
                "dlc": int(getattr(c, "length", len(payload))), "data": payload,
                "data_hex": payload.hex(), "ts": float(getattr(pkt, "time", 0)) or None,
                "iface": None,
            }
            frame.update(_enrich_can(canid, extended, payload))
            result["can"].append(frame)
            continue
        # Otherwise look for ASCII NMEA/AIS in the transport payload (AIS is often UDP NMEA).
        raw = bytes(pkt.payload) if hasattr(pkt, "payload") else bytes(pkt)
        if b"AIVD" in raw or b"GGA" in raw or b"RMC" in raw:
            text_chunks.append(raw.decode("ascii", "replace"))
    result["nmea_text"] = text_chunks
    return result


# =========================================================================== orchestration
def analyze_bytes(data: bytes, name: str = "<data>", only: str = None) -> dict:
    """Run every relevant decoder over one artifact and return a structured report. `only` (one of
    'can'/'adsb'/'ais'/'nmea') restricts analysis to a single decoder when auto-detection would be
    ambiguous; None (the default) runs them all."""
    rep = {"file": name, "bytes": len(data),
           "can": [], "adsb": [], "ais": [], "nmea": [], "flags": set(), "kinds": []}

    def want(kind):
        return only in (None, kind)

    pcap_text = ""
    if _is_pcap(data) and HAVE_SCAPY:
        pc = read_pcap(name)
        if want("can"):
            rep["can"].extend(pc.get("can", []))
            if pc.get("can"):
                rep["kinds"].append("pcap:can")
        pcap_text = "\n".join(pc.get("nmea_text", []))

    # Text interpretation (candump / AIVDM / NMEA / hex Mode S). latin-1 keeps all byte values.
    text = data.decode("latin-1", "replace")
    if pcap_text:
        text = text + "\n" + pcap_text

    if want("can"):
        if not rep["can"]:
            rep["can"] = parse_candump_text(text)
            if rep["can"]:
                rep["kinds"].append("candump")
        if not rep["can"]:                               # try raw SocketCAN struct records
            sc = parse_socketcan_struct(data)
            if sc:
                rep["can"] = sc
                rep["kinds"].append("socketcan-raw")

    if want("adsb"):
        for fr in _hex_frames(text):                     # ADS-B from hex/AVR text
            dec = decode_modes(fr)
            if dec:
                rep["adsb"].append(dec)
        if not rep["adsb"]:                              # ADS-B from raw binary frames
            for sz in (14, 7):
                if len(data) and len(data) % sz == 0 and (data[0] >> 3) in (17, 18, 11, 4, 5, 20, 21):
                    ok = []
                    for off in range(0, len(data), sz):
                        dec = decode_modes(data[off:off + sz])
                        if dec:
                            ok.append(dec)
                    if ok and any(d.get("df") in (17, 18) for d in ok):
                        rep["adsb"] = ok
                        break
        if rep["adsb"]:
            rep["kinds"].append("adsb")

    if want("ais"):
        ais = parse_aivdm(text)
        if ais:
            rep["ais"] = ais
            rep["kinds"].append("ais")

    if want("nmea"):
        nmea = parse_nmea_text(text)
        if nmea:
            rep["nmea"] = nmea
            rep["kinds"].append("nmea")

    rep["flags"] = _collect_flags(rep, data)
    return rep


def _collect_flags(rep, data) -> set:
    flags = set(find_flags(data))
    # also scan decoded text fields explicitly (they come from 6-bit/text decodes, not raw bytes)
    for fr in rep["can"]:
        flags |= find_flags(fr.get("ascii", ""))
    for a in rep["adsb"]:
        flags |= find_flags(a.get("callsign", ""))
    for m in rep["ais"]:
        d = m.get("decoded") or {}
        for k in ("shipname", "callsign", "destination"):
            flags |= find_flags(d.get(k, ""))
    for n in rep["nmea"]:
        flags |= find_flags(n.get("raw", ""))
    return flags


def reports(paths, only=None) -> list:
    out = []
    for p in paths:
        try:
            data = Path(p).read_bytes()[:MAX_FILE]
        except OSError as e:
            out.append({"file": p, "error": str(e)})
            continue
        out.append(analyze_bytes(data, p, only=only))
    return out


# =========================================================================== CLI rendering
def _flag_line(flags) -> str:
    return "  ".join(f">>> FLAG: {f} <<<" for f in sorted(flags))


def _fmt_can(fr) -> str:
    kind = "EFF" if fr["extended"] else "SFF"
    if fr.get("fd"):
        kind += "/FD"
    if fr.get("remote"):
        kind += "/RTR"
    head = f"  id={fr['decode']['id_hex']} [{kind}] dlc={fr['dlc']} data={fr['data_hex']}"
    j = fr["decode"].get("j1939")
    extra = []
    if j:
        pgn = f"PGN {j['pgn']} (0x{j['pgn_hex']})"
        if j["pgn_name"]:
            pgn += f" {j['pgn_name']}"
        da = "GLOBAL" if j["dest_address"] == J1939_GLOBAL_ADDR else j["dest_address"]
        extra.append(f"J1939 prio={j['priority']} {pgn} SA={j['source_address']} DA={da}")
    obd = fr.get("obd")
    if obd:
        if obd.get("pid_name"):
            val = obd.get("value")
            vs = f" = {val} {obd.get('unit','')}" if val is not None else ""
            extra.append(f"OBD mode {obd['mode']:#04x} PID 0x{obd.get('pid_hex','')} "
                         f"{obd['pid_name']}{vs}".rstrip())
        else:
            extra.append(f"OBD service {obd['service']:#04x} ({obd.get('mode_name') or '?'})")
    ascii_data = fr.get("ascii", "")
    if ascii_data.strip(". "):
        extra.append(f"ascii={ascii_data!r}")
    lines = [head]
    for e in extra:
        lines.append(f"      {e}")
    return "\n".join(lines)


def render(rep) -> str:
    if "error" in rep:
        return f"# {rep['file']}: {rep['error']}"
    L = [f"# {rep['file']}  ({rep['bytes']} bytes)  kinds: {', '.join(rep['kinds']) or 'none'}"]
    if rep["flags"]:
        L.append("  " + _flag_line(rep["flags"]))
    if rep["can"]:
        L.append(f"  CAN frames: {len(rep['can'])}")
        for fr in rep["can"][:200]:
            L.append(_fmt_can(fr))
    if rep["adsb"]:
        L.append(f"  ADS-B / Mode S frames: {len(rep['adsb'])}")
        for a in rep["adsb"][:200]:
            crc = "CRC ok" if a.get("crc_ok") else f"CRC rem={a.get('crc_remainder')}"
            line = f"  DF{a['df']} {a.get('msg','')} icao={a.get('icao')} [{crc}]"
            if a.get("type_code") is not None:
                line += f" TC={a['type_code']}"
            if a.get("callsign"):
                line += f" callsign={a['callsign']!r}"
            if a.get("category"):
                line += f" cat={a['category']}"
            if a.get("altitude_ft") is not None:
                line += f" alt={a['altitude_ft']}ft"
            if a.get("cpr_lat") is not None:
                line += f" CPR(odd={a['cpr_odd']} lat={a['cpr_lat']} lon={a['cpr_lon']})"
            L.append(line)
    if rep["ais"]:
        L.append(f"  AIS messages: {len(rep['ais'])}")
        for m in rep["ais"]:
            d = m.get("decoded") or {}
            if m.get("error"):
                L.append(f"  [frag x{m['fragments']}] decode error: {m['error']}")
                continue
            line = f"  type {d.get('type')} {d.get('msg','')} MMSI={d.get('mmsi')}"
            if d.get("lat") is not None or d.get("lon") is not None:
                line += f" lat={d.get('lat')} lon={d.get('lon')}"
            if d.get("sog_knots") is not None:
                line += f" sog={d['sog_knots']}kn"
            if d.get("nav_status_name"):
                line += f" status={d['nav_status_name']!r}"
            if d.get("shipname"):
                line += f" name={d['shipname']!r}"
            if d.get("callsign"):
                line += f" callsign={d['callsign']!r}"
            if d.get("destination"):
                line += f" dest={d['destination']!r}"
            if d.get("imo"):
                line += f" IMO={d['imo']}"
            if not m.get("complete"):
                line += " [INCOMPLETE fragments]"
            L.append(line)
    if rep["nmea"]:
        L.append(f"  NMEA GPS sentences: {len(rep['nmea'])}")
        for n in rep["nmea"]:
            chk = "" if n.get("checksum_ok") is None else (
                " chk=ok" if n["checksum_ok"] else " chk=BAD")
            if n["type"] == "GGA":
                L.append(f"  GGA {n['talker']} t={n.get('time_utc')} lat={n.get('lat')} "
                         f"lon={n.get('lon')} fix={n.get('fix_text')} sats={n.get('num_sats')} "
                         f"alt={n.get('altitude_m')}m{chk}")
            else:
                L.append(f"  RMC {n['talker']} t={n.get('time_utc')} date={n.get('date')} "
                         f"status={n.get('status_text')} lat={n.get('lat')} lon={n.get('lon')} "
                         f"sog={n.get('sog_knots')}kn track={n.get('track_deg')}{chk}")
    if not any(rep[k] for k in ("can", "adsb", "ais", "nmea")):
        L.append("  no CAN / ADS-B / AIS / NMEA content recognised")
    return "\n".join(L)


def _json_default(o):
    if isinstance(o, (bytes, bytearray)):
        return o.hex()
    if isinstance(o, set):
        return sorted(o)
    return str(o)


def main(argv) -> int:
    ap = argparse.ArgumentParser(
        prog="transport.py",
        description="Offline decoder for transport/automotive telemetry: CAN bus (candump / "
                    "SocketCAN / pcap), ADS-B Mode S DF17, AIS AIVDM, and GPS NMEA-0183. "
                    "Input may be a raw protocol/text file or a .pcap/.pcapng.")
    ap.add_argument("files", nargs="*", help="artifact file(s): candump log, AIVDM/NMEA text, "
                                             "Mode S hex, raw SocketCAN, or a pcap/pcapng")
    ap.add_argument("--json", action="store_true", help="emit the structured decode as JSON")
    ap.add_argument("--format", choices=["auto", "can", "adsb", "ais", "nmea"], default="auto",
                    help="restrict to one decoder when auto-detection is ambiguous (default: auto)")
    args = ap.parse_args(argv)
    if not args.files:
        ap.print_help(sys.stderr)
        return 2
    reps = reports(args.files, only=None if args.format == "auto" else args.format)
    if args.json:
        print(json.dumps(reps, indent=1, default=_json_default))
        return 0
    all_flags = set()
    for rep in reps:
        print(render(rep))
        all_flags |= set(rep.get("flags", ()))
    if all_flags:
        print("\n=== CSCTF flag candidates (submit via ctf.submit.guarded_submit) ===")
        print(_flag_line(all_flags))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
