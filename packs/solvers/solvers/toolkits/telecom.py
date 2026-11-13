#!/usr/bin/env python3
"""Toolkit telecom: an OFFLINE, STATIC reader for carrier / mobile-core signalling. Built for CSCTF
2026 "Total Warfare" (the telecom critical-infrastructure lane). It parses bytes as a grammar and
reads out structure and values; it never connects, scans, or runs anything (AGENTS.md: engines are
offline and static).

What it decodes
  GTP-C / GTP-U   GPRS Tunnelling Protocol, control and user plane. Version 1 (Gn/Gp) and version 2
                  (S5/S8/S11, EPC). Surfaces TEID, message type, the sequence number, and the
                  Information Elements (IMSI, MSISDN, IMEI/MEI, APN, F-TEID, End-User/PDN address,
                  Cause, RAT, serving network, ...). GTP-U (G-PDU, type 255) tunnels a user IP packet
                  -- the inner packet and its payload are surfaced and swept for a flag.
  Diameter        The AAA / EPC signalling bus (S6a/S6d, Gx, Rx, Cx, ...). Command code + name,
                  Request vs Answer, Application-Id + name, hop-by-hop / end-to-end ids, and every
                  AVP: code, vendor, name, flags, and decoded value (OctetString AVPs decoded to
                  text, grouped AVPs walked).
  SS7 over SIGTRAN  M3UA (RFC 4666) over SCTP, and the SCCP (ITU-T Q.713) it transports. A DATA
                  message's Protocol-Data is read for OPC / DPC / SI, and the SCCP Called / Calling
                  Party addresses (address indicator, point code, SSN, Global Title digits) are
                  decoded. MAP / TCAP presence is recognised (TCAP dialogue / component portion,
                  MAP operation code, MAP application-context OID). This path is a self-contained
                  parser -- it needs no scapy and still works when scapy is absent.

Where the flag hides (jeopardy): the decoded content IS the puzzle. A flag in CSCTF format
(regex (?:csctf|CSCTF|flag|chronos|CHRONOS|CTF)\\{...\\}) is often tucked into an IMSI/MSISDN-adjacent
string, an APN, a Diameter Origin-Host / User-Name / other OctetString AVP, an SCCP Global Title, or
the GTP-U inner payload. Every decoded string and every record's raw bytes are swept, and any hit is
highlighted prominently.

Inputs (both)
  * a .pcap / .pcapng capture -- scapy reads it; GTP on UDP 2123/2152, Diameter on SCTP/TCP 3868
    (SCTP PPID 46/47), M3UA on SCTP (PPID 3 / port 2905) are pulled and dissected.
  * a raw protocol-payload file -- a single GTP-C/GTP-U, Diameter, M3UA, SCCP, or TCAP message; the
    type is auto-detected from its structure.

CLI
  .venv/bin/python solvers/toolkits/telecom.py <file>... [--json]
  .venv/bin/python solvers/toolkits/telecom.py --raw <kind> <file>   force a raw parse
      (<kind> = gtp | diameter | m3ua | sccp | tcap)

Scope: this is a passive parser of a provided artifact. It does not touch the network, and nothing
here flips a bit on a live system (CSCTF fair play: only assigned targets, no scanning/flooding).
"""
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

FLAG_RE = flagfmt.TEXT
MAX_FILE = 64 * 1024 * 1024

# scapy is used for GTP, Diameter, and reading pcaps; the SS7/SIGTRAN custom path runs without it.
try:
    from scapy.all import rdpcap, IP, IPv6, UDP, TCP, SCTP  # noqa: F401
    from scapy.layers.sctp import SCTPChunkData
    HAVE_SCAPY = True
except Exception:  # noqa: BLE001 - degrade gracefully (the custom SS7 path still works)
    HAVE_SCAPY = False


# ===========================================================================  flag highlighting

def _is_tty() -> bool:
    try:
        return sys.stdout.isatty()
    except Exception:  # noqa: BLE001
        return False


def _flags_in(value) -> list:
    """Every event-format flag string inside bytes or text, in order, de-duplicated. Bytes (packed
    signalling fields) are scanned without a word boundary before the flag (flagfmt.PACKED_TEXT,
    R-16); text keeps the boundary."""
    if value is None:
        return []
    if isinstance(value, (bytes, bytearray)):
        text, rx = bytes(value).decode("latin-1", "replace"), flagfmt.PACKED_TEXT
    else:
        text, rx = str(value), FLAG_RE
    out, seen = [], set()
    for m in rx.findall(text):
        if m not in seen:
            seen.add(m)
            out.append(m)
    return out


def _hl(s: str) -> str:
    """A flag string rendered to stand out (reverse-video bold on a TTY, bracketed otherwise)."""
    if _is_tty():
        return "\033[1;7;31m " + s + " \033[0m"
    return ">>> " + s + " <<<"


# ===========================================================================  small byte helpers

def _u8(d, i):
    return d[i]


def _u16(d, i):
    return struct.unpack_from(">H", d, i)[0]


def _u32(d, i):
    return struct.unpack_from(">I", d, i)[0]


def _printable(b: bytes) -> str:
    """A bytes value as text when it is cleanly printable ASCII/UTF-8, else a hex string."""
    if not isinstance(b, (bytes, bytearray)):
        return str(b)
    try:
        s = bytes(b).decode("utf-8")
        if s and all(32 <= ord(c) < 127 or c in "\t" for c in s):
            return s
    except Exception:  # noqa: BLE001
        pass
    return bytes(b).hex()


def _tbcd(b: bytes) -> str:
    """Telephony BCD (TBCD / packed BCD) digits: low nibble then high nibble per byte, 0xF is a
    filler and ends the number. Used for IMSI / MSISDN / Global-Title digit strings."""
    digits = []
    mapping = "0123456789*#abc"
    for byte in bytes(b):
        for nib in (byte & 0x0F, byte >> 4):
            if nib == 0x0F:
                return "".join(digits)
            digits.append(mapping[nib] if nib < len(mapping) else "?")
    return "".join(digits)


# ===========================================================================  GTP (scapy-backed)

GTP_IE_VALUE_FIELDS = {
    # IE class name -> list of field names whose value is worth surfacing (scanned for a flag too).
    # Both the GTPv1 (scapy.contrib.gtp) and GTPv2 (gtp_v2) spellings are listed; absent ones skip.
    "IE_IMSI": ["imsi", "IMSI"],
    "IE_IMEI": ["IMEI"],
    "IE_MEI": ["MEI"],
    "IE_MSInternationalNumber": ["digits"],
    "IE_MSISDN": ["digits"],
    "IE_AccessPointName": ["APN"],
    "IE_APN": ["APN"],
    "IE_EndUserAddress": ["PDPAddress", "IPv6_PDPAddress"],
    "IE_PAA": ["ipv4", "ipv6"],
    "IE_FTEID": ["GRE_Key", "ipv4", "ipv6", "InterfaceType"],
    "IE_GSNAddress": ["address"],
    "IE_Cause": ["CauseValue", "Cause"],
    "IE_RAT": ["RAT_type", "RAT_Type"],
    "IE_RATType": ["RAT_type", "RAT_Type"],
    "IE_ServingNetwork": ["MCC", "MNC"],
    "IE_ULI": ["MCC", "MNC", "LAC", "CI", "SAC", "RAC", "TAC", "ECI"],
    "IE_ChargingID": ["ChargingID"],
    "IE_ChargingId": ["id"],
    "IE_ProtocolConfigurationOptions": ["Protocols"],
    "IE_PCO": ["Protocols"],
}

# structural fields present on IEs that are never the "value"
_GTP_STRUCT_FIELDS = {"ietype", "length", "CR_flag", "instance", "ie_type", "npdu", "next_ex",
                      "SPARE", "SPARE1", "SPARE2", "flags"}


def _gtp_ie_record(ie) -> dict:
    """One IE as {name, type, fields:{...}, flags:[...]} with its value fields decoded and swept."""
    cls = ie.__class__.__name__
    name = cls[3:] if cls.startswith("IE_") else cls
    wanted = GTP_IE_VALUE_FIELDS.get(cls)
    fields = {}
    flag_hits = []
    try:
        field_names = [f.name for f in ie.fields_desc]
    except Exception:  # noqa: BLE001
        field_names = []
    if wanted is None:
        wanted = [fn for fn in field_names if fn not in _GTP_STRUCT_FIELDS]
    for fn in wanted:
        if fn not in field_names:
            continue
        try:
            val = getattr(ie, fn, None)
        except Exception:  # noqa: BLE001
            continue
        if val is None or val == b"":
            continue
        if isinstance(val, (bytes, bytearray)):
            shown = _printable(val)
        else:
            shown = val
        fields[fn] = shown
        flag_hits += _flags_in(val)
    # sweep the whole IE's bytes as a backstop (a flag could sit in a field we did not name)
    try:
        flag_hits += [f for f in _flags_in(bytes(ie)) if f not in flag_hits]
    except Exception:  # noqa: BLE001
        pass
    rec = {"name": name, "type": getattr(ie, "ietype", None), "fields": fields}
    if flag_hits:
        rec["flags"] = flag_hits
    return rec


def _gtp_ie_list(layer) -> list:
    out = []
    seen = set()
    cur = layer
    # IE_list is the usual container; also follow the payload chain for robustness
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        ie_list = getattr(cur, "IE_list", None)
        if ie_list:
            for ie in ie_list:
                out.append(_gtp_ie_record(ie))
            break
        cur = getattr(cur, "payload", None)
        if cur is None or cur.__class__.__name__ in ("NoPayload", "Raw"):
            break
    return out


def parse_gtp(payload: bytes) -> dict:
    """Decode one GTP-C or GTP-U message from raw bytes, or return None. Needs scapy."""
    if not HAVE_SCAPY or not payload:
        return None
    try:
        from scapy.contrib import gtp, gtp_v2
    except Exception:  # noqa: BLE001
        return None
    b = bytes(payload)
    if len(b) < 8:
        return None
    version = b[0] >> 5
    rec = {"protocol": "GTP", "version": version}
    try:
        if version == 2:
            pkt = gtp_v2.GTPHeader(b)
            mt = getattr(gtp_v2, "GTPmessageType", {})
            rec["kind"] = "control"
            rec["gtp_type"] = int(pkt.gtp_type)
            rec["type_name"] = mt.get(int(pkt.gtp_type), "?")
            rec["teid"] = getattr(pkt, "teid", None)
            rec["seq"] = getattr(pkt, "seq", None)
            rec["length"] = int(getattr(pkt, "length", 0) or 0)
            rec["ies"] = _gtp_ie_list(pkt.payload)
        elif version == 1:
            gtp_type = b[1]
            mt = getattr(gtp, "GTPmessageType", {})
            if gtp_type == 255:  # G-PDU: user plane, tunnels an inner IP packet
                pkt = gtp.GTP_U_Header(b)
                rec["kind"] = "user"
                rec["gtp_type"] = int(pkt.gtp_type)
                rec["type_name"] = mt.get(int(pkt.gtp_type), "g_pdu")
                rec["teid"] = int(getattr(pkt, "teid", 0) or 0)
                rec["seq"] = getattr(pkt, "seq", None)
                rec["length"] = int(getattr(pkt, "length", 0) or 0)
                rec["inner"] = _gtpu_inner(pkt.payload)
            else:
                pkt = gtp.GTPHeader(b)
                rec["kind"] = "control"
                rec["gtp_type"] = int(pkt.gtp_type)
                rec["type_name"] = mt.get(int(pkt.gtp_type), "?")
                rec["teid"] = int(getattr(pkt, "teid", 0) or 0)
                rec["seq"] = getattr(pkt, "seq", None)
                rec["length"] = int(getattr(pkt, "length", 0) or 0)
                rec["ies"] = _gtp_ie_list(pkt.payload)
        else:
            return None
    except Exception:  # noqa: BLE001 - a malformed message is no record
        return None
    rec["flags"] = _collect_gtp_flags(rec)
    return rec


def _gtpu_inner(inner) -> dict:
    """The user IP packet a GTP-U G-PDU carries: 5-tuple summary + the inner payload, swept."""
    out = {"summary": None, "src": None, "dst": None, "proto": None, "payload_hex": None,
           "payload_text": None, "flags": []}
    try:
        out["summary"] = inner.summary()
    except Exception:  # noqa: BLE001
        pass
    for attr in ("src", "dst"):
        out[attr] = getattr(inner, attr, None)
    try:
        raw_inner = bytes(inner)
    except Exception:  # noqa: BLE001
        raw_inner = b""
    # the innermost application payload (past IP/UDP/TCP), if any
    app = inner
    for _ in range(6):
        nxt = getattr(app, "payload", None)
        if nxt is None or nxt.__class__.__name__ == "NoPayload":
            break
        app = nxt
    try:
        app_bytes = bytes(app) if app is not inner else raw_inner
    except Exception:  # noqa: BLE001
        app_bytes = raw_inner
    if app_bytes:
        out["payload_hex"] = app_bytes[:512].hex()
        out["payload_text"] = _printable(app_bytes[:512]) if len(app_bytes) <= 512 else None
    out["flags"] = _flags_in(raw_inner)
    return out


def _collect_gtp_flags(rec: dict) -> list:
    hits = []
    for ie in rec.get("ies", []):
        for f in ie.get("flags", []):
            if f not in hits:
                hits.append(f)
    inner = rec.get("inner")
    if inner:
        for f in inner.get("flags", []):
            if f not in hits:
                hits.append(f)
    return hits


# ===========================================================================  Diameter (scapy-backed)

# 3GPP application ids that scapy's base AppIDsEnum does not name
_DIAM_APP_3GPP = {
    16777216: "3GPP-Cx", 16777217: "3GPP-Sh", 16777238: "3GPP-Gx", 16777236: "3GPP-Rx",
    16777251: "3GPP-S6a/S6d", 16777252: "3GPP-S13", 16777272: "3GPP-S6b", 16777255: "3GPP-SLg",
    16777291: "3GPP-SLh", 16777265: "3GPP-S7a", 16777250: "3GPP-STa", 16777264: "3GPP-SWm",
    16777267: "3GPP-SWx", 4294967295: "Relay",
}
# short Request/Answer abbreviations for the common EPC command codes
_DIAM_CMD_ABBR = {
    316: ("ULR", "ULA"), 317: ("CLR", "CLA"), 318: ("AIR", "AIA"), 319: ("IDR", "IDA"),
    321: ("PUR", "PUA"), 322: ("RSR", "RSA"), 323: ("DSR", "DSA"), 324: ("NOR", "NOA"),
    272: ("CCR", "CCA"), 265: ("AAR", "AAA"), 258: ("RAR", "RAA"), 274: ("ASR", "ASA"),
    275: ("STR", "STA"), 257: ("CER", "CEA"), 280: ("DWR", "DWA"), 282: ("DPR", "DPA"),
}
_DIAM_VALUE_FIELDS = ("val",)  # scapy OctetString/Integer AVP subclasses carry the value in `val`


def _diam_app_name(app_id: int) -> str:
    try:
        from scapy.contrib import diameter
        base = getattr(diameter, "AppIDsEnum", {})
    except Exception:  # noqa: BLE001
        base = {}
    return _DIAM_APP_3GPP.get(app_id) or base.get(app_id) or str(app_id)


def _diam_cmd_name(code: int, is_request: bool) -> str:
    try:
        from scapy.contrib import diameter
        f = [x for x in diameter.DiamG.fields_desc if x.name == "drCode"][0]
        base = getattr(f, "i2s", {}) or {}
    except Exception:  # noqa: BLE001
        base = {}
    name = base.get(code)
    suffix = "Request" if is_request else "Answer"
    if name:
        full = "%s-%s" % (name, suffix)
    else:
        full = "cmd-%d-%s" % (code, suffix)
    abbr = _DIAM_CMD_ABBR.get(code)
    if abbr:
        full += " (%s)" % (abbr[0] if is_request else abbr[1])
    return full


def _diam_avp_name(code: int, vendor: int) -> str:
    try:
        from scapy.contrib import diameter
        table = getattr(diameter, "AvpDefDict", {})
    except Exception:  # noqa: BLE001
        table = {}
    ent = table.get(vendor, {}).get(code) or table.get(0, {}).get(code)
    return ent[0] if ent else "AVP-%d" % code


def _diam_avp_record(avp) -> dict:
    code = int(getattr(avp, "avpCode", 0) or 0)
    flags = int(getattr(avp, "avpFlags", 0) or 0)
    vendor = int(getattr(avp, "avpVnd", 0) or 0) if (flags & 0x80) else 0
    rec = {"code": code, "vendor": vendor, "name": _diam_avp_name(code, vendor),
           "flags": {"V": bool(flags & 0x80), "M": bool(flags & 0x40), "P": bool(flags & 0x20)},
           "value": None, "grouped": None}
    flag_hits = []
    # grouped AVP: recurse into its nested AVP list. scapy carries the children in the `val`
    # field (a list of AVP packets) for its *_Grouped classes; some builds also expose `avpList`.
    nested = getattr(avp, "avpList", None)
    if not nested:
        maybe = getattr(avp, "val", None)
        if isinstance(maybe, list):          # a *_Grouped AVP -- val is the nested AVP list
            nested = maybe
    if nested:
        rec["grouped"] = [_diam_avp_record(x) for x in nested]
        for g in rec["grouped"]:
            flag_hits += g.get("_flaghits", [])
    else:
        for fn in _DIAM_VALUE_FIELDS:
            if hasattr(avp, fn):
                try:
                    val = getattr(avp, fn)
                except Exception:  # noqa: BLE001
                    val = None
                if val is None:
                    continue
                rec["value"] = _printable(val) if isinstance(val, (bytes, bytearray)) else val
                flag_hits += _flags_in(val)
                break
    try:
        flag_hits += [f for f in _flags_in(bytes(avp)) if f not in flag_hits]
    except Exception:  # noqa: BLE001
        pass
    if flag_hits:
        rec["_flaghits"] = flag_hits
    return rec


def parse_diameter(payload: bytes) -> dict:
    """Decode one Diameter message from raw bytes, or return None. Needs scapy."""
    if not HAVE_SCAPY or not payload:
        return None
    b = bytes(payload)
    if len(b) < 20 or b[0] != 0x01:
        return None
    # sanity: the 24-bit message length must match (one message per blob)
    msg_len = (b[1] << 16) | (b[2] << 8) | b[3]
    if msg_len < 20 or msg_len > len(b):
        return None
    try:
        from scapy.contrib import diameter
        pkt = diameter.DiamG(b[:msg_len])
    except Exception:  # noqa: BLE001
        return None
    try:
        drflags = int(pkt.drFlags)
    except Exception:  # noqa: BLE001
        drflags = 0
    is_request = bool(drflags & 0x80)
    code = int(getattr(pkt, "drCode", 0) or 0)
    app_id = int(getattr(pkt, "drAppId", 0) or 0)
    rec = {"protocol": "Diameter", "command_code": code,
           "command_name": _diam_cmd_name(code, is_request),
           "is_request": is_request, "application_id": app_id,
           "application_name": _diam_app_name(app_id),
           "flags": {"R": bool(drflags & 0x80), "P": bool(drflags & 0x40),
                     "E": bool(drflags & 0x20), "T": bool(drflags & 0x10)},
           "hop_by_hop": int(getattr(pkt, "drHbHId", 0) or 0),
           "end_to_end": int(getattr(pkt, "drEtEId", 0) or 0),
           "avps": []}
    flag_hits = []
    for avp in getattr(pkt, "avpList", []) or []:
        a = _diam_avp_record(avp)
        flag_hits += a.pop("_flaghits", [])
        rec["avps"].append(a)
    rec["flag_hits"] = []
    for f in flag_hits:
        if f not in rec["flag_hits"]:
            rec["flag_hits"].append(f)
    return rec


# ===========================================================================  M3UA (custom, no scapy)

M3UA_CLASS = {0: "MGMT", 1: "Transfer", 2: "SSNM", 3: "ASPSM", 4: "ASPTM", 5: "RKM",
              6: "IIM", 9: "RKM", 10: "IIM"}
M3UA_TYPE = {
    (0, 0): "ERR", (0, 1): "NTFY",
    (1, 1): "DATA",
    (2, 1): "DUNA", (2, 2): "DAVA", (2, 3): "DAUD", (2, 4): "SCON", (2, 5): "DUPU", (2, 6): "DRST",
    (3, 1): "ASPUP", (3, 2): "ASPDN", (3, 3): "BEAT", (3, 4): "ASPUP_ACK", (3, 5): "ASPDN_ACK",
    (3, 6): "BEAT_ACK",
    (4, 1): "ASPAC", (4, 2): "ASPIA", (4, 3): "ASPAC_ACK", (4, 4): "ASPIA_ACK",
}
# RFC 4666 section 3.2 parameter tags. Common parameters (0x00xx) and M3UA-specific (0x02xx).
M3UA_PARAM = {
    # common parameters
    0x0004: "INFO String", 0x0006: "Routing Context", 0x0007: "Diagnostic Information",
    0x0009: "Heartbeat Data", 0x000B: "Traffic Mode Type", 0x000C: "Error Code",
    0x000D: "Status", 0x0011: "ASP Identifier", 0x0012: "Affected Point Code",
    0x0013: "Correlation ID",
    # M3UA-specific parameters
    0x0200: "Network Appearance", 0x0204: "User/Cause", 0x0205: "Congestion Indications",
    0x0206: "Concerned Destination", 0x0207: "Routing Key", 0x0208: "Registration Result",
    0x0209: "Deregistration Result", 0x020A: "Local Routing Key Identifier",
    0x020B: "Destination Point Code", 0x020C: "Service Indicators",
    0x020E: "Originating Point Code List", 0x0210: "Protocol Data",
    0x0212: "Registration Status", 0x0213: "Deregistration Status",
}
M3UA_SI = {0: "SNM", 1: "MTN", 3: "SCCP", 4: "TUP", 5: "ISUP", 6: "DUP", 9: "B-ISUP", 10: "SAT-ISUP"}


def _m3ua_params(data: bytes) -> list:
    """Walk the TLV parameter list of an M3UA message body (4-byte-aligned)."""
    out = []
    i, n = 0, len(data)
    while i + 4 <= n:
        tag = _u16(data, i)
        length = _u16(data, i + 2)
        if length < 4 or i + length > n:
            break
        value = data[i + 4:i + length]
        out.append((tag, value))
        i += length + ((4 - (length % 4)) % 4)  # pad to the next 4-byte boundary
    return out


def parse_m3ua(data: bytes) -> dict:
    """Decode an M3UA (RFC 4666) message; for a DATA message, read the Protocol-Data and hand the
    MTP3-user payload (SCCP) on. Pure-stdlib: works with or without scapy. None if not M3UA."""
    b = bytes(data)
    if len(b) < 8 or b[0] != 0x01 or b[1] != 0x00:
        return None
    mclass = b[2]
    mtype = b[3]
    mlen = _u32(b, 4)
    if mlen < 8 or mlen > len(b) + 3:  # allow a little slack for trailing SCTP padding
        return None
    body = b[8:mlen] if mlen <= len(b) else b[8:]
    rec = {"protocol": "M3UA", "msg_class": mclass, "class_name": M3UA_CLASS.get(mclass, "?"),
           "msg_type": mtype, "type_name": M3UA_TYPE.get((mclass, mtype), "?"),
           "length": mlen, "params": [], "protocol_data": None, "sccp": None}
    for tag, value in _m3ua_params(body):
        p = {"tag": "0x%04x" % tag, "name": M3UA_PARAM.get(tag, "?"), "len": len(value)}
        if tag == 0x0210 and len(value) >= 12:   # Protocol Data (RFC 4666 3.3.1 / 3.4.1)
            pd = _m3ua_protocol_data(value)
            rec["protocol_data"] = pd
            if pd.get("service_indicator") == 3 and pd.get("user_data_hex"):  # SI=3 -> SCCP
                rec["sccp"] = parse_sccp(bytes.fromhex(pd["user_data_hex"]))
        else:
            p["value_hex"] = value[:64].hex()
        rec["params"].append(p)
    return rec


def _m3ua_protocol_data(value: bytes) -> dict:
    """The Protocol Data parameter (RFC 4666 3.4.1): OPC, DPC, SI, NI, MP, SLS, then MTP3-user data."""
    opc = _u32(value, 0)
    dpc = _u32(value, 4)
    si = value[8]
    ni = value[9]
    mp = value[10]
    sls = value[11]
    user = value[12:]
    return {"opc": opc, "opc_itu": _pc_itu(opc), "dpc": dpc, "dpc_itu": _pc_itu(dpc),
            "service_indicator": si, "si_name": M3UA_SI.get(si, "?"),
            "network_indicator": ni, "message_priority": mp, "signalling_link_selection": sls,
            "user_data_hex": user.hex()}


def _pc_itu(pc: int) -> str:
    """An ITU 14-bit point code split zone-region-sp (3-8-3), when it fits 14 bits."""
    if pc > 0x3FFF:
        return ""
    return "%d-%d-%d" % ((pc >> 11) & 0x07, (pc >> 3) & 0xFF, pc & 0x07)


# ===========================================================================  SCCP (custom, no scapy)

SCCP_TYPE = {0x01: "CR", 0x02: "CC", 0x03: "CREF", 0x04: "RLSD", 0x05: "RLC", 0x06: "DT1",
             0x07: "DT2", 0x08: "AK", 0x09: "UDT", 0x0A: "UDTS", 0x0B: "ED", 0x0C: "EA",
             0x0D: "RSR", 0x0E: "RSC", 0x0F: "ERR", 0x10: "IT", 0x11: "XUDT", 0x12: "XUDTS",
             0x13: "LUDT", 0x14: "LUDTS"}
SCCP_SSN = {0: "unknown", 1: "SCCP mgmt", 2: "reserved(ITU)", 3: "ISUP", 4: "OMAP", 5: "MAP",
            6: "HLR", 7: "VLR", 8: "MSC", 9: "EIR", 10: "AUC", 11: "ISDN-SS", 13: "BISDN",
            14: "PCAP", 142: "RANAP", 143: "RNSAP", 145: "GMLC", 146: "CAP", 147: "gsmSCF",
            148: "SIWFS", 149: "SGSN", 150: "GGSN"}
SCCP_NAI = {0: "unknown", 1: "subscriber", 2: "reserved-national", 3: "national-significant",
            4: "international"}
SCCP_NP = {0: "unknown", 1: "ISDN/telephony(E.164)", 3: "data(X.121)", 4: "telex(F.69)",
           5: "maritime-mobile", 6: "land-mobile(E.212)", 7: "ISDN/mobile(E.214)"}

# connectionless message layouts: offsets of the mandatory-variable pointers after the fixed part
# UDT  : type(1) class(1) ptrCdPA ptrCgPA ptrData        -> pointers start at offset 2
# XUDT : type(1) class(1) hopcount(1) ptrCdPA ptrCgPA ptrData -> pointers start at offset 3
# LUDT : type(1) class(1) hopcount(1) ptrCdPA(2) ptrCgPA(2) ptrData(2) -> 16-bit pointers at off 3


def _u16le(d, i):
    return struct.unpack_from("<H", d, i)[0]


def _sccp_var(data: bytes, ptr_off: int, wide: bool = False):
    """A mandatory-variable parameter located by a pointer at ptr_off: (length-prefixed) value or
    None. `wide` selects the 2-octet pointer + 2-octet length indicator used by LUDT/LUDTS. SCCP
    encodes these multi-octet numeric fields least-significant-octet first -- the same little-endian
    convention as the signalling point code (Q.713), and how Wireshark reads them."""
    try:
        if wide:
            ptr = _u16le(data, ptr_off)
            if ptr == 0:
                return None
            start = ptr_off + ptr
            ln = _u16le(data, start)
            return data[start + 2:start + 2 + ln]
        ptr = data[ptr_off]
        if ptr == 0:
            return None
        start = ptr_off + ptr
        ln = data[start]
        return data[start + 1:start + 1 + ln]
    except Exception:  # noqa: BLE001
        return None


def parse_sccp_address(addr: bytes) -> dict:
    """An SCCP Called/Calling Party Address (ITU-T Q.713 3.4): address indicator, optional point
    code, optional SSN, optional Global Title (digits decoded)."""
    out = {"raw_hex": bytes(addr).hex(), "point_code": None, "ssn": None, "ssn_name": None,
           "global_title": None, "gt_digits": None, "routing": None}
    if not addr:
        return out
    ai = addr[0]
    pc_present = bool(ai & 0x01)
    ssn_present = bool(ai & 0x02)
    gti = (ai >> 2) & 0x0F
    routing_on_ssn = bool(ai & 0x40)
    out["address_indicator"] = "0x%02x" % ai
    out["gti"] = gti
    out["routing"] = "SSN/PC" if routing_on_ssn else "GT"
    i = 1
    if pc_present and i + 2 <= len(addr):
        pc = addr[i] | (addr[i + 1] << 8)  # ITU 14-bit point code, little-endian
        out["point_code"] = pc & 0x3FFF
        out["point_code_itu"] = _pc_itu(pc & 0x3FFF)
        i += 2
    if ssn_present and i < len(addr):
        ssn = addr[i]
        out["ssn"] = ssn
        out["ssn_name"] = SCCP_SSN.get(ssn, "?")
        i += 1
    if gti != 0 and i < len(addr):
        out["global_title"] = _sccp_global_title(gti, addr[i:])
        if out["global_title"]:
            out["gt_digits"] = out["global_title"].get("digits")
    return out


def _sccp_global_title(gti: int, gt: bytes) -> dict:
    """Decode a Global Title by its indicator. GTI 2 (TT only) and GTI 4 (TT + NP/ES + NAI + digits,
    the common international form) are handled; others return the raw digit nibbles."""
    res = {"gti": gti}
    j = 0
    try:
        if gti == 0x04:
            res["translation_type"] = gt[j]; j += 1
            np_es = gt[j]; j += 1
            res["numbering_plan"] = SCCP_NP.get(np_es >> 4, np_es >> 4)
            res["encoding_scheme"] = np_es & 0x0F
            nai = gt[j]; j += 1
            res["nature_of_address"] = SCCP_NAI.get(nai & 0x7F, nai & 0x7F)
            res["digits"] = _tbcd(gt[j:])
        elif gti == 0x02:
            res["translation_type"] = gt[j]; j += 1
            res["digits"] = _tbcd(gt[j:])
        elif gti == 0x01:
            nai = gt[j]; j += 1
            res["nature_of_address"] = SCCP_NAI.get(nai & 0x7F, nai & 0x7F)
            res["digits"] = _tbcd(gt[j:])
        else:
            res["digits"] = _tbcd(gt)
    except Exception:  # noqa: BLE001
        res["digits"] = _tbcd(gt) if gt else None
    return res


def parse_sccp(data: bytes) -> dict:
    """Decode an SCCP message (ITU-T Q.713). Full address decode for the connectionless types
    (UDT/XUDT/LUDT and their service variants); the data part is checked for TCAP/MAP. None if the
    first octet is not a known SCCP message type."""
    b = bytes(data)
    if not b:
        return None
    mtype = b[0]
    name = SCCP_TYPE.get(mtype)
    if name is None:
        return None
    rec = {"protocol": "SCCP", "msg_type": mtype, "type_name": name,
           "called_party": None, "calling_party": None, "data": None, "tcap": None}
    flag_hits = []
    try:
        if mtype in (0x09, 0x0A):            # UDT / UDTS: class(1) then 3 one-octet pointers at off 2
            rec["protocol_class"] = b[1]
            cdpa = _sccp_var(b, 2)
            cgpa = _sccp_var(b, 3)
            payload = _sccp_var(b, 4)
        elif mtype in (0x11, 0x12):          # XUDT / XUDTS: + hop counter, pointers at off 3
            rec["protocol_class"] = b[1]
            rec["hop_counter"] = b[2]
            cdpa = _sccp_var(b, 3)
            cgpa = _sccp_var(b, 4)
            payload = _sccp_var(b, 5)
        elif mtype in (0x13, 0x14):          # LUDT / LUDTS: + hop counter, 2-octet pointers at off 3
            rec["protocol_class"] = b[1]
            rec["hop_counter"] = b[2]
            cdpa = _sccp_var(b, 3, wide=True)
            cgpa = _sccp_var(b, 5, wide=True)
            payload = _sccp_var(b, 7, wide=True)
        else:
            return rec  # connection-oriented type recognised by name; no address decode here
    except Exception:  # noqa: BLE001
        return rec
    if cdpa is not None:
        rec["called_party"] = parse_sccp_address(cdpa)
        flag_hits += _flags_in(rec["called_party"].get("gt_digits"))
    if cgpa is not None:
        rec["calling_party"] = parse_sccp_address(cgpa)
        flag_hits += _flags_in(rec["calling_party"].get("gt_digits"))
    if payload:
        rec["data"] = {"len": len(payload), "hex": payload[:64].hex()}
        rec["tcap"] = detect_tcap(payload)
        flag_hits += _flags_in(payload)
    if flag_hits:
        rec["flag_hits"] = []
        for f in flag_hits:
            if f not in rec["flag_hits"]:
                rec["flag_hits"].append(f)
    return rec


# ===========================================================================  TCAP / MAP (custom)

TCAP_MSG = {0x61: "Unidirectional", 0x62: "Begin", 0x64: "End", 0x65: "Continue", 0x67: "Abort"}
TCAP_COMPONENT = {0xA1: "Invoke", 0xA2: "ReturnResultLast", 0xA3: "ReturnError", 0xA4: "Reject",
                  0xA7: "ReturnResultNotLast"}
# a handful of well-known MAP operation codes (3GPP TS 29.002); common mobility/SMS/auth operations
MAP_OPCODE = {2: "updateLocation", 3: "cancelLocation", 4: "provideRoamingNumber",
              6: "resumeCallHandling", 7: "insertSubscriberData", 8: "deleteSubscriberData",
              9: "sendParameters", 10: "registerSS", 11: "eraseSS", 22: "sendRoutingInfo",
              23: "sendRoutingInfoForGprs", 29: "sendRoutingInfoForLCS", 37: "reset",
              43: "reportSM-DeliveryStatus", 44: "mt-ForwardSM", 45: "sendRoutingInfoForSM",
              46: "mo-ForwardSM", 47: "beginSubscriberActivity", 55: "processUnstructuredSS-Request",
              56: "sendAuthenticationInfo", 57: "restoreData", 59: "sendIMSI",
              70: "anyTimeInterrogation", 71: "anyTimeSubscriptionInterrogation"}


def _ber_tlv(data: bytes, i: int):
    """Read one BER TLV at offset i: (tag, length, value_start, value_end, next) or None."""
    n = len(data)
    if i >= n:
        return None
    tag = data[i]
    j = i + 1
    if (tag & 0x1F) == 0x1F:                 # multi-byte tag
        while j < n and (data[j] & 0x80):
            j += 1
        j += 1
    if j >= n:
        return None
    ln = data[j]
    j += 1
    if ln & 0x80:                            # long form length
        num = ln & 0x7F
        if num == 0 or j + num > n:
            return None
        ln = int.from_bytes(data[j:j + num], "big")
        j += num
    vstart = j
    vend = j + ln
    if vend > n:
        vend = n
    return tag, ln, vstart, vend, vend


def detect_tcap(data: bytes) -> dict:
    """Recognise TCAP (ITU-T Q.773) and, within it, MAP (3GPP TS 29.002). Reports the TCAP message
    type, the component(s) and their MAP operation codes, and any MAP application-context OID."""
    b = bytes(data)
    if not b:
        return None
    msg = TCAP_MSG.get(b[0])
    if msg is None:
        return None
    rec = {"present": True, "message_type": msg, "map": False, "components": [],
           "application_context": None, "dialogue": None}
    top = _ber_tlv(b, 0)
    if not top:
        return rec
    _, _, vs, ve, _ = top
    i = vs
    # walk the top-level fields of the TCAP message (transaction ids, dialogue portion, components)
    while i < ve:
        t = _ber_tlv(b, i)
        if not t:
            break
        tag, _, cs, ce, nxt = t
        if tag == 0x6B:                      # Dialogue Portion (EXTERNAL) -> look for an AC OID
            ac = _find_ac_oid(b[cs:ce])
            if ac:
                rec["application_context"] = ac["oid"]
                rec["dialogue"] = ac.get("dialogue")
                if ac.get("is_map"):
                    rec["map"] = True
        elif tag == 0x6C:                    # Component Portion -> walk the components
            k = cs
            while k < ce:
                c = _ber_tlv(b, k)
                if not c:
                    break
                ctag, _, kcs, kce, knx = c
                comp = {"type": TCAP_COMPONENT.get(ctag, "0x%02x" % ctag), "opcode": None,
                        "operation": None}
                op = _tcap_opcode(b[kcs:kce])
                if op is not None:
                    comp["opcode"] = op
                    comp["operation"] = MAP_OPCODE.get(op)
                    if op in MAP_OPCODE:
                        rec["map"] = True
                rec["components"].append(comp)
                k = knx if knx > k else ce
        i = nxt if nxt > i else ve
    return rec


def _tcap_opcode(comp_body: bytes):
    """The MAP operation code inside an Invoke/ReturnResult component: the (local) INTEGER that
    follows the invokeID, or the opcode carried in a ReturnResult's sequence. Best-effort."""
    i, n = 0, len(comp_body)
    ints = []
    while i < n:
        t = _ber_tlv(comp_body, i)
        if not t:
            break
        tag, ln, vs, ve, nxt = t
        if tag == 0x02 and 0 < (ve - vs) <= 4:          # INTEGER (invokeID, then opcode)
            ints.append(int.from_bytes(comp_body[vs:ve], "big", signed=True))
        elif tag == 0x30:                                # ReturnResult: opcode nested in the SEQUENCE
            inner = _tcap_opcode(comp_body[vs:ve])
            if inner is not None:
                return inner
        i = nxt if nxt > i else n
    # Invoke carries invokeID then operationCode (both local INTEGERs); the opcode is the 2nd int
    if len(ints) >= 2:
        return ints[1]
    if len(ints) == 1:
        return ints[0]
    return None


def _find_ac_oid(dialogue: bytes) -> dict:
    """Scan a TCAP dialogue portion for an OBJECT IDENTIFIER (tag 0x06). A value beginning
    06 07 04 00 00 01 00 ... (the MAP arc 0.4.0.0.1) marks a MAP application context."""
    i, n = 0, len(dialogue)
    while i < n:
        t = _ber_tlv(dialogue, i)
        if not t:
            break
        tag, ln, vs, ve, nxt = t
        if tag == 0x06:                      # OBJECT IDENTIFIER
            oid_bytes = dialogue[vs:ve]
            is_map = oid_bytes[:5] == b"\x04\x00\x00\x01\x00"
            return {"oid": _decode_oid(oid_bytes), "is_map": is_map,
                    "dialogue": "MAP application context" if is_map else None}
        if tag in (0x60, 0x61, 0x28, 0xA0, 0xA1, 0x30, 0x6B, 0x62, 0xBE, 0xA2, 0x02, 0x04):
            # descend into constructed wrappers (EXTERNAL / dialoguePDU / AARQ etc.)
            if tag & 0x20:
                inner = _find_ac_oid(dialogue[vs:ve])
                if inner:
                    return inner
        i = nxt if nxt > i else n
    return {}


def _decode_oid(b: bytes) -> str:
    """A BER OBJECT IDENTIFIER value's dotted form."""
    if not b:
        return ""
    first = b[0]
    out = [str(first // 40), str(first % 40)]
    val = 0
    for byte in b[1:]:
        val = (val << 7) | (byte & 0x7F)
        if not (byte & 0x80):
            out.append(str(val))
            val = 0
    return ".".join(out)


# ===========================================================================  raw auto-detect

def sniff_raw(data: bytes) -> dict:
    """Best-effort structural classification of a raw protocol payload, returning a decoded record.
    Order: GTP, Diameter, M3UA (then SCCP/TCAP under it), bare SCCP, bare TCAP."""
    b = bytes(data)
    if not b:
        return None
    # GTP: version in the top 3 bits is 1 or 2, PT/flags plausible, header length fits
    ver = b[0] >> 5
    if ver in (1, 2) and len(b) >= 8:
        g = parse_gtp(b)
        if g:
            return g
    # Diameter and M3UA both start 0x01; disambiguate by structure
    if b[0] == 0x01:
        if b[1] == 0x00 and b[2] in M3UA_CLASS:   # M3UA: reserved byte 0, known class
            m = parse_m3ua(b)
            if m:
                return m
        d = parse_diameter(b)
        if d:
            return d
        m = parse_m3ua(b)
        if m:
            return m
    # bare SCCP
    if b[0] in SCCP_TYPE:
        s = parse_sccp(b)
        if s and (s.get("called_party") or s.get("calling_party") or s.get("data")):
            return s
    # bare TCAP
    if b[0] in TCAP_MSG:
        t = detect_tcap(b)
        if t:
            return {"protocol": "TCAP", **t}
    return None


# ===========================================================================  pcap reading (scapy)

def _sctp_chunks(pkt):
    """Yield (proto_id, data) for each SCTP DATA chunk in a packet."""
    try:
        layer = pkt[SCTP].payload
    except Exception:  # noqa: BLE001
        return
    seen = 0
    while layer is not None and layer.__class__.__name__ != "NoPayload" and seen < 64:
        seen += 1
        if isinstance(layer, SCTPChunkData):
            try:
                yield int(getattr(layer, "proto_id", 0) or 0), bytes(layer.data)
            except Exception:  # noqa: BLE001
                pass
        layer = getattr(layer, "payload", None)


def scan_pcap(path: str) -> list:
    """Every GTP / Diameter / M3UA(+SCCP+TCAP) message in a capture, each tagged with its 5-tuple."""
    out = []
    try:
        packets = rdpcap(path)
    except Exception as e:  # noqa: BLE001
        raise ValueError("cannot read pcap: %s" % e)
    for idx, pkt in enumerate(packets):
        src = dst = None
        if pkt.haslayer(IP):
            src, dst = pkt[IP].src, pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src, dst = pkt[IPv6].src, pkt[IPv6].dst
        tag = {"pkt": idx + 1, "src": src, "dst": dst}

        if pkt.haslayer(UDP):
            u = pkt[UDP]
            payload = bytes(u.payload) if u.payload else b""
            if not payload:
                continue
            if u.sport in (2123, 2152) or u.dport in (2123, 2152):
                rec = parse_gtp(payload)
                if rec:
                    out.append({**tag, "sport": u.sport, "dport": u.dport, "record": rec})
                    continue
            # GTP can appear on other ports too; try structurally
            if (payload[0] >> 5) in (1, 2):
                rec = parse_gtp(payload)
                if rec:
                    out.append({**tag, "sport": u.sport, "dport": u.dport, "record": rec})

        elif pkt.haslayer(SCTP):
            s = pkt[SCTP]
            for ppid, cdata in _sctp_chunks(pkt):
                if not cdata:
                    continue
                rec = None
                if ppid == 3 or s.sport in (2905, 2906) or s.dport in (2905, 2906):
                    rec = parse_m3ua(cdata)
                elif ppid in (46, 47) or s.sport == 3868 or s.dport == 3868:
                    rec = parse_diameter(cdata)
                if rec is None:                 # fall back to structural detection
                    rec = parse_m3ua(cdata) or parse_diameter(cdata) or sniff_raw(cdata)
                if rec:
                    out.append({**tag, "sport": s.sport, "dport": s.dport, "ppid": ppid,
                                "record": rec})

        elif pkt.haslayer(TCP):
            t = pkt[TCP]
            payload = bytes(t.payload) if t.payload else b""
            if payload and (t.sport == 3868 or t.dport == 3868 or payload[0] == 0x01):
                rec = parse_diameter(payload)
                if rec:
                    out.append({**tag, "sport": t.sport, "dport": t.dport, "record": rec})
    return out


# ===========================================================================  rendering

def _record_flags(rec: dict) -> list:
    """All flag hits reachable inside one decoded record."""
    hits = []

    def add(fs):
        for f in fs or []:
            if f not in hits:
                hits.append(f)
    if not isinstance(rec, dict):
        return hits
    add(rec.get("flags") if isinstance(rec.get("flags"), list) else None)
    add(rec.get("flag_hits"))
    sccp = rec.get("sccp")
    if isinstance(sccp, dict):
        add(sccp.get("flag_hits"))
    for a in rec.get("avps", []) or []:
        add(a.get("_flaghits"))
    return hits


def _print_record(rec: dict, indent: str = "") -> list:
    """Render one decoded record to stdout; return its flag hits."""
    flags = []
    proto = rec.get("protocol", "?")
    if proto == "GTP":
        v = rec.get("version")
        line = "%sGTP v%s %s  type=%s(%s)  TEID=%s" % (
            indent, v, rec.get("kind"), rec.get("gtp_type"), rec.get("type_name"),
            _teid(rec.get("teid")))
        if rec.get("seq") is not None:
            line += "  seq=%s" % rec.get("seq")
        print(line)
        for ie in rec.get("ies", []):
            fld = ", ".join("%s=%s" % (k, v2) for k, v2 in (ie.get("fields") or {}).items())
            print("%s  IE %s%s" % (indent, ie.get("name"), ("  " + fld) if fld else ""))
        inner = rec.get("inner")
        if inner:
            print("%s  inner: %s" % (indent, inner.get("summary")))
            if inner.get("payload_text"):
                print("%s  inner payload: %s" % (indent, inner.get("payload_text")[:200]))
        flags = rec.get("flags") or []
    elif proto == "Diameter":
        print("%sDiameter  %s  app=%s(%s)  hbh=0x%08x ete=0x%08x" % (
            indent, rec.get("command_name"), rec.get("application_id"),
            rec.get("application_name"), rec.get("hop_by_hop"), rec.get("end_to_end")))
        for a in rec.get("avps", []):
            _print_avp(a, indent + "  ")
        flags = rec.get("flag_hits") or []
    elif proto == "M3UA":
        print("%sM3UA  class=%s(%s) type=%s(%s)  len=%s" % (
            indent, rec.get("msg_class"), rec.get("class_name"), rec.get("msg_type"),
            rec.get("type_name"), rec.get("length")))
        pd = rec.get("protocol_data")
        if pd:
            print("%s  ProtocolData: OPC=%s(%s) DPC=%s(%s) SI=%s(%s) NI=%s SLS=%s" % (
                indent, pd.get("opc"), pd.get("opc_itu"), pd.get("dpc"), pd.get("dpc_itu"),
                pd.get("service_indicator"), pd.get("si_name"), pd.get("network_indicator"),
                pd.get("signalling_link_selection")))
        for p in rec.get("params", []):
            if p.get("name") not in ("Protocol Data",):
                print("%s  param %s %s (len=%s)" % (indent, p.get("tag"), p.get("name"), p.get("len")))
        if rec.get("sccp"):
            flags += _print_record(rec["sccp"], indent + "  ")
    elif proto == "SCCP":
        print("%sSCCP  %s (type 0x%02x)%s" % (
            indent, rec.get("type_name"), rec.get("msg_type"),
            "  class=%s" % rec.get("protocol_class") if rec.get("protocol_class") is not None else ""))
        for role in ("called_party", "calling_party"):
            a = rec.get(role)
            if a:
                print("%s  %s: %s" % (indent, role.replace("_party", "").title(), _addr_str(a)))
        if rec.get("tcap"):
            _print_tcap(rec["tcap"], indent + "  ")
        flags = rec.get("flag_hits") or []
    elif proto == "TCAP":
        _print_tcap(rec, indent)
    else:
        print("%s%s" % (indent, json.dumps(rec, default=str)[:200]))
    return flags


def _print_avp(a: dict, indent: str):
    fl = a.get("flags", {})
    bits = "".join(k for k in ("V", "M", "P") if fl.get(k))
    head = "%sAVP %s (code %s%s)" % (indent, a.get("name"), a.get("code"),
                                     ", vnd %s" % a["vendor"] if a.get("vendor") else "")
    if bits:
        head += " [%s]" % bits
    if a.get("grouped"):
        print(head + ":")
        for g in a["grouped"]:
            _print_avp(g, indent + "  ")
    else:
        val = a.get("value")
        print("%s = %s" % (head, _clip(val)))


def _print_tcap(t: dict, indent: str):
    line = "%sTCAP %s" % (indent, t.get("message_type"))
    if t.get("map"):
        line += "  [MAP]"
    if t.get("application_context"):
        line += "  AC=%s" % t.get("application_context")
    print(line)
    for c in t.get("components", []):
        op = c.get("operation")
        print("%s  component %s%s" % (
            indent, c.get("type"),
            "  op=%s(%s)" % (c.get("opcode"), op) if c.get("opcode") is not None else ""))


def _teid(teid):
    if teid is None:
        return "-"
    try:
        return "0x%08x" % int(teid)
    except Exception:  # noqa: BLE001
        return str(teid)


def _addr_str(a: dict) -> str:
    parts = ["AI=%s" % a.get("address_indicator"), "route=%s" % a.get("routing")]
    if a.get("point_code") is not None:
        parts.append("PC=%s(%s)" % (a.get("point_code"), a.get("point_code_itu")))
    if a.get("ssn") is not None:
        parts.append("SSN=%s(%s)" % (a.get("ssn"), a.get("ssn_name")))
    if a.get("gt_digits"):
        parts.append("GT=%s" % a.get("gt_digits"))
    return "  ".join(parts)


def _clip(v, n: int = 120) -> str:
    s = v if isinstance(v, str) else json.dumps(v, default=str) if isinstance(v, (dict, list)) else str(v)
    return s if len(s) <= n else s[:n] + "..."


# ===========================================================================  CLI

def _read_file(path: str) -> bytes:
    data = Path(path).read_bytes()
    if len(data) > MAX_FILE:
        raise ValueError("file too large (%d bytes)" % len(data))
    return data


def _looks_like_pcap(data: bytes) -> bool:
    return data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1",
                        b"\xa1\xb2\x3c\x4d") or data[:4] == b"\x0a\x0d\x0d\x0a"  # pcap / pcapng


def report(path: str, forced_kind: str = None) -> dict:
    """Decode one file (pcap or raw payload) into a structured report dict."""
    data = _read_file(path)
    result = {"file": path, "bytes": len(data), "kind": None, "records": [], "flags": [],
              "scapy": HAVE_SCAPY}
    if forced_kind:
        parsers = {"gtp": parse_gtp, "diameter": parse_diameter, "m3ua": parse_m3ua,
                   "sccp": parse_sccp, "tcap": lambda b: ({"protocol": "TCAP", **detect_tcap(b)}
                                                          if detect_tcap(b) else None)}
        fn = parsers.get(forced_kind)
        if fn is None:
            raise ValueError("unknown --raw kind %r (gtp|diameter|m3ua|sccp|tcap)" % forced_kind)
        rec = fn(data)
        if rec:
            result["kind"] = "raw:%s" % forced_kind
            result["records"].append({"record": rec})
    elif _looks_like_pcap(data):
        result["kind"] = "pcap"
        if not HAVE_SCAPY:
            result["error"] = "scapy not available: cannot read pcap (install scapy or pass a raw payload)"
            return result
        result["records"] = [{k: v for k, v in r.items()} for r in scan_pcap(path)]
    else:
        rec = sniff_raw(data)
        if rec:
            result["kind"] = "raw:%s" % rec.get("protocol", "?").lower()
            result["records"].append({"record": rec})
        else:
            result["kind"] = "unrecognised"
    # gather flags from every decoded record
    for r in result["records"]:
        for f in _record_flags(r.get("record", {})):
            if f not in result["flags"]:
                result["flags"].append(f)
    # backstop: an ASCII flag can sit in a payload we did not route or fully decode, so sweep the
    # whole file's bytes too (the decoded content is where the flag hides -- never miss a hit)
    for f in _flags_in(data):
        if f not in result["flags"]:
            result["flags"].append(f)
    return result


def _print_human(result: dict):
    print("# %s  (%d bytes, %s)" % (result["file"], result["bytes"], result.get("kind")))
    if result.get("error"):
        print("  ! %s" % result["error"])
    if not result["records"]:
        if result.get("kind") != "pcap":
            print("  no carrier-signalling structure recognised")
        if result["flags"]:
            print("  (but a flag-format string is present in the raw bytes)")
            print("  " + "=" * 60)
            for f in result["flags"]:
                print("  FLAG FORMAT MATCH: " + _hl(f))
            print("  " + "=" * 60)
        return
    flags = []
    for r in result["records"]:
        loc = ""
        if "pkt" in r:
            loc = "pkt %s  %s:%s -> %s:%s" % (r.get("pkt"), r.get("src"), r.get("sport"),
                                              r.get("dst"), r.get("dport"))
            if r.get("ppid") is not None:
                loc += "  ppid=%s" % r.get("ppid")
            print("- %s" % loc)
        flags += _print_record(r.get("record", {}), "  " if loc else "")
    # prominent flag banner
    allflags = []
    for f in result["flags"] + flags:
        if f not in allflags:
            allflags.append(f)
    if allflags:
        print()
        print("  " + "=" * 60)
        for f in allflags:
            print("  FLAG FORMAT MATCH: " + _hl(f))
        print("  " + "=" * 60)


def main(argv) -> int:
    args = list(argv)
    if any(arg in ("-h", "--help") for arg in args):
        print(__doc__)
        return 0
    as_json = "--json" in args
    args = [a for a in args if a != "--json"]
    forced_kind = None
    if "--raw" in args:
        k = args.index("--raw")
        if k + 1 >= len(args):
            print("telecom.py: --raw needs a kind (gtp|diameter|m3ua|sccp|tcap)", file=sys.stderr)
            return 2
        forced_kind = args[k + 1]
        del args[k:k + 2]
    paths = [a for a in args if not a.startswith("--")]
    if not paths:
        print(__doc__.split("\n\n")[0], file=sys.stderr)
        print("\nusage: telecom.py <file>... [--json] [--raw <gtp|diameter|m3ua|sccp|tcap> <file>]",
              file=sys.stderr)
        if not HAVE_SCAPY:
            print("note: scapy is not importable here; GTP/Diameter/pcap need it, "
                  "the SS7/M3UA/SCCP/TCAP raw path still works.", file=sys.stderr)
        return 2
    results = []
    for p in paths:
        try:
            results.append(report(p, forced_kind))
        except (OSError, ValueError) as e:
            print("telecom.py: %s: %s" % (p, e), file=sys.stderr)
    if as_json:
        print(json.dumps(results, indent=1, default=lambda o: o.hex()
                         if isinstance(o, (bytes, bytearray)) else str(o)))
        return 0
    for r in results:
        _print_human(r)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
