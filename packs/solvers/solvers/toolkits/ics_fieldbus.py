#!/usr/bin/env python3
"""Toolkit ics_fieldbus: an OFFLINE, STATIC reader for the industrial fieldbus / building-automation
protocols that show up in the CSCTF "Total Warfare" ICS lane. It never connects, never scans and
never instantiates an artifact to read it (the never-execute discipline): bytes are walked as a
grammar and the structure / service / addresses / values are read out. In a jeopardy ICS challenge
the decoded payload IS where the flag hides, so every readable field and the whole payload are
scanned for the CSCTF flag format and matches are printed prominently.

Protocols
  BACnet/IP   CUSTOM parser (stdlib only, so it ALWAYS works): BVLC -> NPDU -> APDU with the full
              BACnet application/context tag grammar. Decodes ReadProperty / ReadPropertyMultiple /
              WriteProperty / Who-Is / I-Am (and renders any service's tag stream): object
              identifiers, property identifiers, character strings, enumerated/unsigned/real values.
              UDP 47808 (0xBAC0).
  EtherNet/IP CUSTOM framing parser of the ENIP encapsulation + CPF items (true wire byte order),
  + CIP       plus a focused CIP reader (service, EPATH class/instance/attribute + Logix ANSI symbol
              segments, request/response status and data). scapy.contrib.enipTCP is used for enum
              labels + a cross-check when present, but NOTE: its ItemData.data is a little-endian
              string field that byte-reverses CIP, so CIP is always read from the raw buffer here.
              TCP 44818.
  Profinet    READABLE WRAPPER over scapy.contrib.pnio / pnio_dcp / pnio_rpc: frameID, DCP service
              and blocks (name-of-station, IP/MAC/gateway, vendor/role), and DCE/RPC (DceRpc4).
              Ethernet 0x8892 (RT/DCP) and UDP 34964 (RPC).
  OPC-DA      READABLE WRAPPER over scapy.contrib.opc_da: the DCE/RPC PDU type (bind/request/
              response/...), call id, opnum, and a string/flag scan of the stub data. TCP (DCOM).

Input: a RAW protocol-payload file (the UDP/TCP payload bytes, or an Ethernet frame for Profinet),
OR a .pcap/.pcapng (scapy is used to read it and pull the relevant packets by port/layer, then each
payload is dissected). Protocol is auto-detected; override with --proto.

Degrades gracefully: BACnet and EtherNet/IP work with stdlib alone; Profinet and OPC-DA report that
scapy is required if it is missing. Nothing here touches the network (CSCTF fair-play: offline only).

CLI:  .venv/bin/python solvers/toolkits/ics_fieldbus.py <file>... [--json] [--proto NAME]
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

KEY = "ics_fieldbus"

# The CSCTF flag format (task-specified). Searched over decoded text AND raw bytes.
FLAG_RE = flagfmt.TEXT

MAX_FILE = 64 * 1024 * 1024
MAX_TAGS = 20000
MAX_ITEMS = 256


# ======================================================================================
#  shared helpers
# ======================================================================================

def _scan_flags(data) -> list:
    """Every event-format flag in `data` (bytes or str), order-preserving and de-duplicated. Bytes
    (register blocks, frame payloads) are scanned without a word boundary before the flag
    (flagfmt.PACKED_TEXT, R-16); text keeps the boundary."""
    if isinstance(data, (bytes, bytearray)):
        text, rx = bytes(data).decode("latin-1", "replace"), flagfmt.PACKED_TEXT
    else:
        text, rx = str(data), FLAG_RE
    out, seen = [], set()
    for m in rx.finditer(text):
        v = m.group(0)
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def _printable_strings(data: bytes, minlen: int = 4) -> list:
    """ASCII runs of length >= minlen (for a readable summary of binary payloads)."""
    out, cur = [], []
    for byte in bytes(data):
        if 32 <= byte < 127:
            cur.append(chr(byte))
        else:
            if len(cur) >= minlen:
                out.append("".join(cur))
            cur = []
    if len(cur) >= minlen:
        out.append("".join(cur))
    return out


# ======================================================================================
#  BACnet/IP  (custom: BVLC / NPDU / APDU + the BACnet tag grammar)
# ======================================================================================

BVLC_FUNCTIONS = {
    0x00: "BVLC-Result",
    0x01: "Write-Broadcast-Distribution-Table",
    0x02: "Read-Broadcast-Distribution-Table",
    0x03: "Read-Broadcast-Distribution-Table-Ack",
    0x04: "Forwarded-NPDU",
    0x05: "Register-Foreign-Device",
    0x06: "Read-Foreign-Device-Table",
    0x07: "Read-Foreign-Device-Table-Ack",
    0x08: "Delete-Foreign-Device-Table-Entry",
    0x09: "Distribute-Broadcast-To-Network",
    0x0A: "Original-Unicast-NPDU",
    0x0B: "Original-Broadcast-NPDU",
    0x0C: "Secure-BVLL",
}

APDU_TYPES = {
    0x0: "Confirmed-REQ",
    0x1: "Unconfirmed-REQ",
    0x2: "SimpleACK",
    0x3: "ComplexACK",
    0x4: "SegmentACK",
    0x5: "Error-PDU",
    0x6: "Reject-PDU",
    0x7: "Abort-PDU",
}

CONFIRMED_SERVICES = {
    0: "acknowledgeAlarm", 1: "confirmedCOVNotification", 2: "confirmedEventNotification",
    3: "getAlarmSummary", 4: "getEnrollmentSummary", 5: "subscribeCOV", 6: "atomicReadFile",
    7: "atomicWriteFile", 8: "addListElement", 9: "removeListElement", 10: "createObject",
    11: "deleteObject", 12: "readProperty", 13: "readPropertyConditional",
    14: "readPropertyMultiple", 15: "writeProperty", 16: "writePropertyMultiple",
    17: "deviceCommunicationControl", 18: "confirmedPrivateTransfer", 19: "confirmedTextMessage",
    20: "reinitializeDevice", 21: "vtOpen", 22: "vtClose", 23: "vtData", 24: "authenticate",
    25: "requestKey", 26: "readRange", 27: "lifeSafetyOperation", 28: "subscribeCOVProperty",
    29: "getEventInformation",
}

UNCONFIRMED_SERVICES = {
    0: "i-Am", 1: "i-Have", 2: "unconfirmedCOVNotification", 3: "unconfirmedEventNotification",
    4: "unconfirmedPrivateTransfer", 5: "unconfirmedTextMessage", 6: "timeSynchronization",
    7: "who-Has", 8: "who-Is", 9: "utcTimeSynchronization", 10: "writeGroup",
}

BACNET_OBJECT_TYPES = {
    0: "analog-input", 1: "analog-output", 2: "analog-value", 3: "binary-input",
    4: "binary-output", 5: "binary-value", 6: "calendar", 7: "command", 8: "device",
    9: "event-enrollment", 10: "file", 11: "group", 12: "loop", 13: "multi-state-input",
    14: "multi-state-output", 15: "notification-class", 16: "program", 17: "schedule",
    18: "averaging", 19: "multi-state-value", 20: "trend-log", 21: "life-safety-point",
    22: "life-safety-zone", 23: "accumulator", 24: "pulse-converter", 25: "event-log",
    28: "load-control", 36: "access-door", 56: "network-port",
}

BACNET_PROPERTIES = {
    12: "application-software-version", 28: "description", 36: "event-state",
    44: "firmware-revision", 70: "model-name", 73: "number-of-states", 75: "object-identifier",
    76: "object-list", 77: "object-name", 79: "object-type", 81: "out-of-service",
    85: "present-value", 87: "priority-array", 103: "reliability", 111: "status-flags",
    117: "units", 121: "vendor-name", 120: "vendor-identifier", 112: "system-status",
    155: "database-revision", 371: "property-list", 846: "serial-number",
}

APP_TAG_NAMES = {
    0: "Null", 1: "Boolean", 2: "Unsigned", 3: "Signed", 4: "Real", 5: "Double",
    6: "OctetString", 7: "CharacterString", 8: "BitString", 9: "Enumerated", 10: "Date",
    11: "Time", 12: "BACnetObjectIdentifier",
}

CHAR_ENCODINGS = {0: "utf-8", 3: "utf-32-be", 4: "utf-16-be", 5: "iso-8859-1"}


class _BError(ValueError):
    pass


def _object_id(value: int) -> dict:
    otype = value >> 22
    inst = value & 0x3FFFFF
    return {"object_type": BACNET_OBJECT_TYPES.get(otype, otype), "object_type_num": otype,
            "instance": inst, "text": f"{BACNET_OBJECT_TYPES.get(otype, otype)}:{inst}"}


def _decode_charstring(content: bytes) -> dict:
    if not content:
        return {"encoding": None, "string": ""}
    enc = content[0]
    body = content[1:]
    codec = CHAR_ENCODINGS.get(enc, "latin-1")
    try:
        s = body.decode(codec)
    except Exception:
        s = body.decode("latin-1", "replace")
    return {"encoding": CHAR_ENCODINGS.get(enc, enc), "string": s}


def _decode_app_value(tagnum: int, content: bytes) -> dict:
    name = APP_TAG_NAMES.get(tagnum, f"app-tag-{tagnum}")
    tok = {"tag_class": "application", "tag_number": tagnum, "app_type": name,
           "length": len(content), "raw": content.hex()}
    if tagnum == 0:                                    # Null
        tok["value"] = None
    elif tagnum == 2:                                  # Unsigned
        tok["value"] = int.from_bytes(content, "big") if content else 0
    elif tagnum == 3:                                  # Signed
        tok["value"] = int.from_bytes(content, "big", signed=True) if content else 0
    elif tagnum == 4 and len(content) == 4:            # Real (float32)
        tok["value"] = struct.unpack(">f", content)[0]
    elif tagnum == 5 and len(content) == 8:            # Double
        tok["value"] = struct.unpack(">d", content)[0]
    elif tagnum == 7:                                  # CharacterString
        cs = _decode_charstring(content)
        tok["value"] = cs["string"]
        tok["encoding"] = cs["encoding"]
        tok["flags"] = _scan_flags(cs["string"])
    elif tagnum == 9:                                  # Enumerated
        tok["value"] = int.from_bytes(content, "big") if content else 0
    elif tagnum == 12 and len(content) == 4:           # Object Identifier
        tok["value"] = _object_id(int.from_bytes(content, "big"))
    elif tagnum == 6:                                  # OctetString
        tok["value"] = content.hex()
        tok["flags"] = _scan_flags(content)
    else:
        tok["value"] = content.hex()
    return tok


def _decode_context_value(tagnum: int, content: bytes) -> dict:
    tok = {"tag_class": "context", "tag_number": tagnum, "length": len(content),
           "raw": content.hex()}
    # Context tags carry no application type; offer useful renderings.
    if 1 <= len(content) <= 4:
        tok["as_unsigned"] = int.from_bytes(content, "big")
    if len(content) == 4:
        tok["as_object_id"] = _object_id(int.from_bytes(content, "big"))
    flags = _scan_flags(content)
    if flags:
        tok["flags"] = flags
    strings = _printable_strings(content, 3)
    if strings:
        tok["as_text"] = strings
    return tok


def decode_bacnet_tags(data: bytes, start: int = 0) -> list:
    """Flat token list for the BACnet tag stream from `start`. Opening/closing context tags are
    emitted as markers with a `depth` so the renderer can indent; primitives carry their value."""
    tokens, i, depth, n = [], start, 0, len(data)
    budget = MAX_TAGS
    while i < n:
        budget -= 1
        if budget <= 0:
            tokens.append({"error": "tag budget exceeded"})
            break
        tagbyte = data[i]
        i += 1
        tagnum = tagbyte >> 4
        is_context = bool((tagbyte >> 3) & 1)
        lvt = tagbyte & 0x07
        if tagnum == 0x0F:                             # extended tag number
            if i >= n:
                tokens.append({"error": "truncated extended tag number"})
                break
            tagnum = data[i]
            i += 1
        if is_context and lvt == 6:                     # opening tag
            tokens.append({"tag_class": "context", "tag_number": tagnum, "kind": "opening",
                           "depth": depth})
            depth += 1
            continue
        if is_context and lvt == 7:                     # closing tag
            depth = max(0, depth - 1)
            tokens.append({"tag_class": "context", "tag_number": tagnum, "kind": "closing",
                           "depth": depth})
            continue
        if (not is_context) and tagnum == 1:            # application Boolean: value is in LVT
            tokens.append({"tag_class": "application", "tag_number": 1, "app_type": "Boolean",
                           "value": bool(lvt), "depth": depth})
            continue
        if lvt == 5:                                    # extended length
            if i >= n:
                tokens.append({"error": "truncated extended length"})
                break
            length = data[i]
            i += 1
            if length == 254:
                length = int.from_bytes(data[i:i + 2], "big")
                i += 2
            elif length == 255:
                length = int.from_bytes(data[i:i + 4], "big")
                i += 4
        else:
            length = lvt
        content = data[i:i + length]
        i += length
        if len(content) < length:
            tokens.append({"error": "truncated value", "tag_number": tagnum,
                           "wanted": length, "got": len(content), "raw": content.hex()})
            break
        tok = (_decode_context_value(tagnum, content) if is_context
               else _decode_app_value(tagnum, content))
        tok["kind"] = "primitive"
        tok["depth"] = depth
        tokens.append(tok)
    return tokens


def parse_bvlc(data: bytes) -> dict:
    """Parse the BVLC header. Returns the function + where the NPDU starts, or raises _BError."""
    if len(data) < 4 or data[0] != 0x81:
        raise _BError("not BACnet/IP (BVLC type != 0x81)")
    func = data[1]
    length = int.from_bytes(data[2:4], "big")
    out = {"bvlc_type": 0x81, "function": BVLC_FUNCTIONS.get(func, func), "function_num": func,
           "length": length}
    off = 4
    if func == 0x04:                                   # Forwarded-NPDU: 6-byte B/IP source
        if len(data) < 10:
            raise _BError("truncated Forwarded-NPDU address")
        ip = ".".join(str(b) for b in data[4:8])
        port = int.from_bytes(data[8:10], "big")
        out["forwarded_from"] = f"{ip}:{port}"
        off = 10
    elif func == 0x00:                                 # BVLC-Result
        out["result_code"] = int.from_bytes(data[4:6], "big") if len(data) >= 6 else None
        out["npdu_offset"] = None
        return out
    out["npdu_offset"] = off
    return out


def parse_npdu(data: bytes, off: int) -> dict:
    """Parse the NPDU starting at `off`. Returns control info + where the APDU (or network
    message) starts."""
    if off < 0 or off + 2 > len(data):
        raise _BError("truncated NPDU")
    version = data[off]
    control = data[off + 1]
    i = off + 2
    out = {"version": version, "control": control,
           "is_network_message": bool(control & 0x80),
           "dest_present": bool(control & 0x20),
           "src_present": bool(control & 0x08),
           "expecting_reply": bool(control & 0x04),
           "priority": control & 0x03}
    if control & 0x20:                                 # destination specifier
        if i + 3 > len(data):
            raise _BError("truncated NPDU dest")
        out["dnet"] = int.from_bytes(data[i:i + 2], "big")
        dlen = data[i + 2]
        i += 3
        out["dadr"] = data[i:i + dlen].hex() if dlen else "broadcast"
        i += dlen
    if control & 0x08:                                 # source specifier
        if i + 3 > len(data):
            raise _BError("truncated NPDU src")
        out["snet"] = int.from_bytes(data[i:i + 2], "big")
        slen = data[i + 2]
        i += 3
        out["sadr"] = data[i:i + slen].hex()
        i += slen
    if control & 0x20:                                 # hop count follows a destination
        if i >= len(data):
            raise _BError("truncated NPDU hop count")
        out["hop_count"] = data[i]
        i += 1
    if control & 0x80:                                 # network layer message
        if i >= len(data):
            raise _BError("truncated NPDU network message type")
        out["network_message_type"] = data[i]
        i += 1
        if out["network_message_type"] >= 0x80:
            if i + 2 > len(data):
                raise _BError("truncated NPDU vendor ID")
            out["vendor_id"] = int.from_bytes(data[i:i + 2], "big")
            i += 2
    out["apdu_offset"] = i
    return out


def parse_bacnet_apdu(data: bytes, off: int) -> dict:
    """Parse the APDU starting at `off`: PDU type, invoke id, service choice, and the decoded tag
    stream (with a service-level interpretation for the common property services)."""
    if off < 0 or off >= len(data):
        raise _BError("no APDU")
    b0 = data[off]
    ptype = b0 >> 4
    out = {"pdu_type": APDU_TYPES.get(ptype, ptype), "pdu_type_num": ptype,
           "pdu_flags": b0 & 0x0F}
    i = off + 1
    segmented = bool(b0 & 0x08)
    out["segmented"] = segmented
    header_length = {0: 6 if segmented else 4, 1: 2, 2: 3,
                     3: 5 if segmented else 3, 5: 3, 6: 3, 7: 3}.get(ptype, 1)
    if off + header_length > len(data):
        raise _BError("truncated BACnet APDU header")
    if ptype == 0x0:                                   # Confirmed-REQ
        if i + 2 > len(data):
            raise _BError("truncated Confirmed-REQ")
        out["max_segments_apdu"] = data[i]
        out["invoke_id"] = data[i + 1]
        i += 2
        if segmented:
            out["sequence_number"] = data[i]
            out["proposed_window"] = data[i + 1]
            i += 2
        out["service_choice"] = CONFIRMED_SERVICES.get(data[i], data[i])
        out["service_choice_num"] = data[i]
        i += 1
    elif ptype == 0x1:                                 # Unconfirmed-REQ
        out["service_choice"] = UNCONFIRMED_SERVICES.get(data[i], data[i])
        out["service_choice_num"] = data[i]
        i += 1
    elif ptype == 0x2:                                 # SimpleACK
        out["invoke_id"] = data[i]
        out["service_choice"] = CONFIRMED_SERVICES.get(data[i + 1], data[i + 1])
        out["service_choice_num"] = data[i + 1]
        i += 2
    elif ptype == 0x3:                                 # ComplexACK
        out["invoke_id"] = data[i]
        i += 1
        if segmented:
            out["sequence_number"] = data[i]
            out["proposed_window"] = data[i + 1]
            i += 2
        out["service_choice"] = CONFIRMED_SERVICES.get(data[i], data[i])
        out["service_choice_num"] = data[i]
        i += 1
    elif ptype == 0x5:                                 # Error-PDU
        out["invoke_id"] = data[i]
        out["service_choice"] = CONFIRMED_SERVICES.get(data[i + 1], data[i + 1])
        out["service_choice_num"] = data[i + 1]
        i += 2
    elif ptype in (0x6, 0x7):                          # Reject / Abort
        out["invoke_id"] = data[i]
        out["reason"] = data[i + 1]
        i += 2
    out["tags"] = decode_bacnet_tags(data, i)
    _interpret_bacnet_service(out)
    return out


def _interpret_bacnet_service(apdu: dict) -> None:
    """Attach a service-level reading (object / property / value) for the property services, using
    the position of context tags in the stream."""
    svc = apdu.get("service_choice")
    tags = apdu.get("tags") or []
    reading = {}
    if svc in ("readProperty", "writeProperty"):
        for tok in tags:
            if tok.get("kind") != "primitive":
                continue
            if tok.get("tag_class") == "context" and tok.get("tag_number") == 0 and "as_object_id" in tok:
                reading["object"] = tok["as_object_id"]["text"]
            elif tok.get("tag_class") == "context" and tok.get("tag_number") == 1 and "as_unsigned" in tok:
                pid = tok["as_unsigned"]
                reading["property"] = BACNET_PROPERTIES.get(pid, pid)
            elif tok.get("tag_class") == "context" and tok.get("tag_number") == 2 and "as_unsigned" in tok:
                reading["array_index"] = tok["as_unsigned"]
        # the value lives inside opening/closing context 3 (writeProperty req / readProperty ack)
        vals = [t for t in tags if t.get("kind") == "primitive" and t.get("tag_class") == "application"]
        if vals:
            v = vals[-1]
            reading["value"] = v.get("value")
            if v.get("flags"):
                reading["value_flags"] = v["flags"]
    elif svc == "i-Am":
        apps = [t for t in tags if t.get("tag_class") == "application" and t.get("kind") == "primitive"]
        if apps and apps[0].get("app_type") == "BACnetObjectIdentifier":
            reading["device"] = apps[0]["value"]["text"]
        nums = [t["value"] for t in apps if t.get("app_type") in ("Unsigned", "Enumerated")]
        if len(nums) >= 1:
            reading["max_apdu"] = nums[0]
        if len(nums) >= 2:
            reading["vendor_id"] = nums[-1]
    elif svc == "who-Is":
        nums = [t.get("as_unsigned") for t in tags
                if t.get("tag_class") == "context" and "as_unsigned" in t]
        if len(nums) == 2:
            reading["device_instance_range"] = [nums[0], nums[1]]
    if reading:
        apdu["service_reading"] = reading


def bacnet_report(payload: bytes) -> dict:
    """Decode one BACnet/IP payload (starting at the BVLC header). Returns a report dict."""
    rep = {"protocol": "bacnet-ip", "bytes": len(payload)}
    try:
        bvlc = parse_bvlc(payload)
        rep["bvlc"] = bvlc
        if bvlc.get("npdu_offset") is None:
            rep["flags"] = _scan_flags(payload)
            return rep
        npdu = parse_npdu(payload, bvlc["npdu_offset"])
        rep["npdu"] = npdu
        if not npdu["is_network_message"]:
            rep["apdu"] = parse_bacnet_apdu(payload, npdu["apdu_offset"])
    except _BError as e:
        rep["error"] = str(e)
    except Exception as e:                             # noqa: BLE001 - never crash a triage run
        rep["error"] = f"{type(e).__name__}: {e}"
    rep["flags"] = _scan_flags(payload)
    return rep


# ======================================================================================
#  EtherNet/IP + CIP  (custom framing, true wire order; scapy for labels/cross-check)
# ======================================================================================

ENIP_COMMANDS = {
    0x0004: "ListServices", 0x0063: "ListIdentity", 0x0064: "ListInterfaces",
    0x0065: "RegisterSession", 0x0066: "UnRegisterSession", 0x006F: "SendRRData",
    0x0070: "SendUnitData", 0x0072: "IndicateStatus", 0x0073: "Cancel",
}

ENIP_STATUS = {
    0x0000: "success", 0x0001: "invalid or unsupported command", 0x0002: "insufficient memory",
    0x0003: "incorrect data", 0x0064: "invalid session handle", 0x0065: "invalid length",
    0x0069: "unsupported protocol version",
}

CPF_ITEM_TYPES = {
    0x0000: "Null Address", 0x000C: "ListIdentity Response", 0x00A1: "Connected Address",
    0x00B1: "Connected Data", 0x00B2: "Unconnected Data", 0x0100: "ListServices Response",
    0x8000: "Sockaddr Info O->T", 0x8001: "Sockaddr Info T->O",
}

CIP_SERVICES = {
    0x01: "Get_Attributes_All", 0x02: "Set_Attributes_All", 0x03: "Get_Attribute_List",
    0x04: "Set_Attribute_List", 0x05: "Reset", 0x06: "Start", 0x07: "Stop",
    0x08: "Create", 0x09: "Delete", 0x0A: "Multiple_Service_Packet",
    0x0D: "Apply_Attributes", 0x0E: "Get_Attribute_Single", 0x10: "Set_Attribute_Single",
    0x11: "Find_Next_Object_Instance", 0x14: "Error_Response", 0x15: "Restore", 0x16: "Save",
    0x18: "Get_Member", 0x19: "Set_Member", 0x4B: "Execute_PCCC", 0x4C: "Read_Tag",
    0x4D: "Write_Tag", 0x4E: "Read_Modify_Write_Tag", 0x52: "Unconnected_Send",
    0x53: "Write_Tag_Fragmented", 0x54: "Forward_Open", 0x55: "Get_Instance_Attribute_List",
    0x5A: "Read_Tag_Fragmented", 0x5B: "Forward_Open_Ex",
}

CIP_CLASSES = {
    0x01: "Identity", 0x02: "Message_Router", 0x03: "DeviceNet", 0x04: "Assembly",
    0x05: "Connection", 0x06: "Connection_Manager", 0x07: "Register", 0x08: "Discrete_Input_Point",
    0x0F: "Parameter", 0x37: "File", 0x47: "Device_Level_Ring", 0x48: "QoS",
    0x6B: "Symbol", 0x6C: "Template", 0x72: "Base_Energy", 0xAC: "Logix_Controller",
    0xF5: "TCP/IP_Interface", 0xF6: "Ethernet_Link",
}

CIP_STATUS = {
    0x00: "Success", 0x01: "Connection failure", 0x02: "Resource unavailable",
    0x04: "Path segment error", 0x05: "Path destination unknown", 0x08: "Service not supported",
    0x09: "Invalid attribute value", 0x0C: "Object state conflict", 0x0E: "Attribute not settable",
    0x10: "Device state conflict", 0x13: "Not enough data", 0x14: "Attribute not supported",
    0x15: "Too much data", 0x16: "Object does not exist", 0x1E: "Embedded service error",
    0x26: "Path size invalid",
}


def _parse_epath(path: bytes) -> list:
    """Decode a CIP EPATH: class/instance/attribute/member logical segments and ANSI symbol
    (0x91) segments (Logix tag names)."""
    segs, i, n = [], 0, len(path)
    while i < n:
        seg = path[i]
        seg_type = seg & 0xE0
        if seg == 0x91:                                # ANSI extended symbol segment
            if i + 1 >= n:
                break
            ln = path[i + 1]
            name = path[i + 2:i + 2 + ln]
            segs.append({"segment": "symbol", "name": name.decode("latin-1", "replace")})
            i += 2 + ln + (ln & 1)                      # pad to even
            continue
        if seg_type == 0x20:                           # logical segment
            fmt = seg & 0x03
            logical = (seg >> 2) & 0x07
            kind = {0: "class", 1: "instance", 2: "member", 3: "connection_point",
                    4: "attribute"}.get(logical, f"logical-{logical}")
            if fmt == 0:                               # 8-bit
                val = path[i + 1]
                i += 2
            elif fmt == 1:                             # 16-bit (padded)
                val = int.from_bytes(path[i + 2:i + 4], "little")
                i += 4
            elif fmt == 2:                             # 32-bit
                val = int.from_bytes(path[i + 2:i + 6], "little")
                i += 6
            else:
                break
            entry = {"segment": kind, "value": val}
            if kind == "class":
                entry["name"] = CIP_CLASSES.get(val, val)
            segs.append(entry)
            continue
        # Unknown / port / data segment: record and stop (don't guess).
        segs.append({"segment": "raw", "raw": path[i:].hex()})
        break
    return segs


def parse_cip(data: bytes) -> dict:
    """Parse one CIP message (request or response). Request/response is distinguished by the top
    bit of the service byte."""
    if not data:
        return {"error": "empty CIP"}
    service = data[0]
    is_response = bool(service & 0x80)
    svc = service & 0x7F
    out = {"service": CIP_SERVICES.get(svc, svc), "service_num": svc,
           "direction": "response" if is_response else "request"}
    try:
        if not is_response:
            path_words = data[1]
            path = data[2:2 + path_words * 2]
            out["path"] = _parse_epath(path)
            req_data = data[2 + path_words * 2:]
            out["request_data"] = req_data.hex()
            flags = _scan_flags(req_data)
            strings = _printable_strings(req_data, 4)
            if svc == 0x0A:                            # Multiple_Service_Packet
                out["embedded"] = _parse_multiple_service(req_data)
        else:
            gen_status = data[2]
            addl_words = data[3]
            addl = data[4:4 + addl_words * 2]
            resp_data = data[4 + addl_words * 2:]
            out["general_status"] = CIP_STATUS.get(gen_status, gen_status)
            out["general_status_num"] = gen_status
            if addl:
                out["additional_status"] = addl.hex()
            out["response_data"] = resp_data.hex()
            flags = _scan_flags(resp_data)
            strings = _printable_strings(resp_data, 4)
        if flags:
            out["flags"] = flags
        if strings:
            out["strings"] = strings
    except Exception as e:                             # noqa: BLE001
        out["error"] = f"{type(e).__name__}: {e}"
    return out


def _parse_multiple_service(data: bytes) -> list:
    """Multiple Service Packet: count, offset table, then embedded CIP messages."""
    out = []
    try:
        count = int.from_bytes(data[0:2], "little")
        offsets = [int.from_bytes(data[2 + 2 * k:4 + 2 * k], "little") for k in range(count)]
        for k, start in enumerate(offsets):
            stop = offsets[k + 1] if k + 1 < len(offsets) else len(data)
            out.append(parse_cip(data[start:stop]))
    except Exception as e:                             # noqa: BLE001
        out.append({"error": f"{type(e).__name__}: {e}"})
    return out


def _parse_identity_item(data: bytes) -> dict:
    """CPF ListIdentity response item (type 0x0C): device vendor/type/serial/product-name."""
    out = {}
    try:
        out["encap_protocol_version"] = int.from_bytes(data[0:2], "little")
        # 16-byte sockaddr (big-endian inside): family, port, addr
        out["socket_port"] = int.from_bytes(data[4:6], "big")
        out["socket_addr"] = ".".join(str(b) for b in data[6:10])
        off = 18
        out["vendor_id"] = int.from_bytes(data[off:off + 2], "little")
        out["device_type"] = int.from_bytes(data[off + 2:off + 4], "little")
        out["product_code"] = int.from_bytes(data[off + 4:off + 6], "little")
        out["revision"] = f"{data[off + 6]}.{data[off + 7]}"
        out["status"] = int.from_bytes(data[off + 8:off + 10], "little")
        out["serial"] = hex(int.from_bytes(data[off + 10:off + 14], "little"))
        name_len = data[off + 14]
        name = data[off + 15:off + 15 + name_len]
        out["product_name"] = name.decode("latin-1", "replace")
        out["flags"] = _scan_flags(name)
    except Exception as e:                             # noqa: BLE001
        out["error"] = f"{type(e).__name__}: {e}"
    return out


def parse_enip(payload: bytes) -> dict:
    """Parse the ENIP encapsulation + CPF items from the raw payload (true wire byte order) and
    the CIP inside each data item. Works with stdlib alone."""
    if len(payload) < 24:
        return {"protocol": "ethernet-ip", "error": "too short for an ENIP header", "bytes": len(payload)}
    cmd = int.from_bytes(payload[0:2], "little")
    length = int.from_bytes(payload[2:4], "little")
    session = int.from_bytes(payload[4:8], "little")
    status = int.from_bytes(payload[8:12], "little")
    options = int.from_bytes(payload[20:24], "little")
    rep = {"protocol": "ethernet-ip",
           "command": ENIP_COMMANDS.get(cmd, hex(cmd)), "command_num": cmd,
           "length": length, "session": hex(session),
           "status": ENIP_STATUS.get(status, hex(status)), "status_num": status,
           "options": options, "bytes": len(payload)}
    body = payload[24:24 + length] if length else payload[24:]
    if cmd == 0x65 and len(body) >= 4:                 # RegisterSession
        rep["protocol_version"] = int.from_bytes(body[0:2], "little")
        rep["session_options"] = int.from_bytes(body[2:4], "little")
    elif cmd in (0x6F, 0x70) and len(body) >= 8:       # SendRRData / SendUnitData
        rep["interface_handle"] = int.from_bytes(body[0:4], "little")
        rep["timeout"] = int.from_bytes(body[4:6], "little")
        item_count = int.from_bytes(body[6:8], "little")
        rep["item_count"] = item_count
        items, off = [], 8
        for _ in range(min(item_count, MAX_ITEMS)):
            if off + 4 > len(body):
                break
            tid = int.from_bytes(body[off:off + 2], "little")
            ilen = int.from_bytes(body[off + 2:off + 4], "little")
            idata = body[off + 4:off + 4 + ilen]
            off += 4 + ilen
            item = {"type_id": CPF_ITEM_TYPES.get(tid, hex(tid)), "type_id_num": tid,
                    "length": ilen}
            cipbytes = idata
            if tid == 0x00B1 and len(idata) >= 2:      # Connected Data: 2-byte sequence first
                item["sequence_count"] = int.from_bytes(idata[0:2], "little")
                cipbytes = idata[2:]
            if tid in (0x00B1, 0x00B2) and cipbytes:
                item["cip"] = parse_cip(cipbytes)
            elif tid == 0x000C and idata:              # ListIdentity response item
                item["identity"] = _parse_identity_item(idata)
            else:
                f = _scan_flags(idata)
                if f:
                    item["flags"] = f
            items.append(item)
        rep["items"] = items
    elif cmd == 0x63 and len(body) >= 2:               # ListIdentity response
        item_count = int.from_bytes(body[0:2], "little")
        rep["item_count"] = item_count
        off, items = 2, []
        for _ in range(min(item_count, MAX_ITEMS)):
            if off + 4 > len(body):
                break
            tid = int.from_bytes(body[off:off + 2], "little")
            ilen = int.from_bytes(body[off + 2:off + 4], "little")
            idata = body[off + 4:off + 4 + ilen]
            off += 4 + ilen
            items.append({"type_id": CPF_ITEM_TYPES.get(tid, hex(tid)), "type_id_num": tid,
                          "identity": _parse_identity_item(idata) if tid == 0x000C else None,
                          "raw": idata.hex()})
        rep["items"] = items
    rep["flags"] = _scan_flags(payload)
    # Optional scapy cross-check (enum names), recorded for transparency; CIP bytes are NOT taken
    # from scapy because its ItemData.data field byte-reverses the payload.
    sc = _load_scapy()
    if sc and sc.get("ENIPTCP"):
        try:
            d = sc["ENIPTCP"](payload)
            rep["scapy_command"] = str(d.commandId)
        except Exception:                              # noqa: BLE001
            pass
    return rep


# ======================================================================================
#  scapy loader (lazy, cached, graceful)
# ======================================================================================

_SCAPY = None


def _load_scapy():
    """Import scapy + the contrib dissectors once. Returns a dict of classes, or None if scapy is
    not available. Never raises."""
    global _SCAPY
    if _SCAPY is not None:
        return _SCAPY if _SCAPY else None
    mods = {}
    try:
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from scapy.all import rdpcap, Ether, IP, IPv6, UDP, TCP, Raw  # noqa: F401
            from scapy.contrib.enipTCP import ENIPTCP
            from scapy.contrib.pnio import ProfinetIO
            from scapy.contrib import pnio_dcp as pnio_dcp
            from scapy.contrib import pnio_rpc as pnio_rpc
            from scapy.contrib import opc_da as opc_da
        mods = {"rdpcap": rdpcap, "Ether": Ether, "IP": IP, "IPv6": IPv6, "UDP": UDP, "TCP": TCP,
                "Raw": Raw, "ENIPTCP": ENIPTCP, "ProfinetIO": ProfinetIO,
                "pnio_dcp": pnio_dcp, "pnio_rpc": pnio_rpc, "opc_da": opc_da}
        _SCAPY = mods
        return mods
    except Exception:                                  # noqa: BLE001
        _SCAPY = {}
        return None


# ======================================================================================
#  Profinet  (scapy wrapper over pnio / pnio_dcp / pnio_rpc)
# ======================================================================================

def _packet_fields(pkt) -> dict:
    """Readable field dump of one scapy packet layer. Only PRESENT fields are shown (a scapy
    ConditionalField whose condition is false is skipped, so default placeholder values are not
    mistaken for real data). Enum values are rendered to their names (i2repr); byte fields are
    flag-scanned; packet-list fields are left to the caller."""
    out, flags = {}, []
    for f in pkt.fields_desc:
        cond = getattr(f, "cond", None)                # ConditionalField: honor its condition
        if cond is not None:
            try:
                if not cond(pkt):
                    continue
            except Exception:                          # noqa: BLE001
                continue
        name = f.name
        if name in ("padding", "reserved", "res"):
            continue
        try:
            val = pkt.getfieldval(name)
        except Exception:                              # noqa: BLE001
            continue
        if isinstance(val, (list, tuple)):             # packet lists handled by the caller
            continue
        if isinstance(val, (bytes, bytearray)):
            flags += _scan_flags(val)
        else:
            flags += _scan_flags(str(val))
        try:
            out[name] = f.i2repr(pkt, val)
        except Exception:                              # noqa: BLE001
            out[name] = str(val)
    if flags:
        out["flags"] = sorted(set(flags))
    return out


def profinet_report(payload: bytes = None, pkt=None, prefer: str = None) -> dict:
    """Readable Profinet report. `pkt` may be a scapy packet already dissected from a pcap;
    otherwise `payload` is dissected as a raw Profinet frame (ProfinetIO RT/DCP, Ethertype
    0x8892) or a DCE/RPC datagram (acyclic PN-CM, UDP 34964). `prefer="rpc"` forces the
    DCE/RPC reading (the caller passes it for UDP 34964); otherwise a datagram whose first byte
    is 0x04 (DCE/RPC v4 rpc_vers, connection-less) is read as DCE/RPC and everything else as a
    ProfinetIO frame. (The old frameID==0 sniff never fired: a DCE/RPC datagram's first two
    bytes are 0x04xx, so ProfinetIO read a bogus frameID and the RPC was never decoded.)"""
    sc = _load_scapy()
    if not sc:
        return {"protocol": "profinet", "error": "scapy is required for Profinet (not installed)",
                "flags": _scan_flags(payload or b"")}
    ProfinetIO = sc["ProfinetIO"]
    pnio_dcp = sc["pnio_dcp"]
    pnio_rpc = sc["pnio_rpc"]
    rep = {"protocol": "profinet"}
    try:
        if pkt is None:
            payload = payload or b""
            want_rpc = (prefer == "rpc") or (prefer is None and payload[:1] == b"\x04")
            if want_rpc:
                try:
                    pkt = pnio_rpc.DceRpc4(payload)
                except Exception:                      # noqa: BLE001
                    pkt = ProfinetIO(payload)
            else:
                pkt = ProfinetIO(payload)
        raw_bytes = bytes(pkt.original) if getattr(pkt, "original", None) else bytes(pkt)
        if pkt.haslayer(ProfinetIO):
            pio = pkt.getlayer(ProfinetIO)
            try:
                rep["frame_id"] = pio.get_field("frameID").i2repr(pio, pio.frameID)
            except Exception:                          # noqa: BLE001
                rep["frame_id"] = str(pio.frameID)
            rep["frame_id_num"] = int(pio.frameID)
        dcp_cls = pnio_dcp.ProfinetDCP
        if pkt.haslayer(dcp_cls):
            dcp = pkt.getlayer(dcp_cls)
            # Present header fields (service, xid, and for Set/Get requests the name/ip/mac/...).
            rep["dcp"] = {k: v for k, v in _packet_fields(dcp).items() if k != "flags"}
            blocks = []
            for blk in (dcp.dcp_blocks or []):
                blocks.append({"block": blk.__class__.__name__, **_packet_fields(blk)})
            if blocks:
                rep["dcp"]["blocks"] = blocks
        if pkt.haslayer(pnio_rpc.DceRpc4):
            rpc = pkt.getlayer(pnio_rpc.DceRpc4)
            rep["rpc"] = _packet_fields(rpc)
        rep["flags"] = sorted(set(_scan_flags(raw_bytes)))
    except Exception as e:                             # noqa: BLE001
        rep["error"] = f"{type(e).__name__}: {e}"
        rep["flags"] = _scan_flags(payload or b"")
    return rep


# ======================================================================================
#  OPC-DA  (scapy wrapper over opc_da: DCE/RPC DCOM)
# ======================================================================================

def opcda_report(payload: bytes = None, pkt=None) -> dict:
    """Readable OPC-DA / DCOM report: the DCE/RPC PDU type, call id, opnum, and a string + flag
    scan of the stub data (OPC item ids / values)."""
    sc = _load_scapy()
    if not sc:
        return {"protocol": "opc-da", "error": "scapy is required for OPC-DA (not installed)",
                "flags": _scan_flags(payload or b"")}
    opc_da = sc["opc_da"]
    rep = {"protocol": "opc-da"}
    try:
        msg = pkt if pkt is not None else opc_da.OpcDaMessage(payload)
        raw_bytes = bytes(payload) if payload is not None else bytes(msg)
        hdr = msg.getlayer(opc_da.OpcDaHeaderMessage)
        if hdr is not None:
            pt = int(hdr.pduType)
            rep["pdu_type"] = dict(opc_da._pduType).get(pt, pt)
            rep["pdu_type_num"] = pt
            rep["version"] = f"{int(hdr.versionMajor)}.{int(hdr.versionMinor)}"
            rep["byte_order"] = ("little-endian" if int(hdr.integerRepresentation) == 1
                                 else "big-endian")
        for cls_name in ("OpcDaHeaderNLE", "OpcDaHeaderN"):
            hn = msg.getlayer(getattr(opc_da, cls_name))
            if hn is not None:
                rep["call_id"] = hex(int(hn.callID))
                rep["frag_length"] = int(hn.fragLength)
                break
        for cls_name in ("OpcDaRequestLE", "OpcDaRequest", "OpcDaResponseLE", "OpcDaResponse"):
            cls = getattr(opc_da, cls_name, None)
            if cls is not None and msg.haslayer(cls):
                lyr = msg.getlayer(cls)
                if hasattr(lyr, "opNum"):
                    rep["op_num"] = int(lyr.opNum)
                if hasattr(lyr, "contextId"):
                    rep["context_id"] = int(lyr.contextId)
                if hasattr(lyr, "allocHint"):
                    rep["alloc_hint"] = int(lyr.allocHint)
                break
        if (hdr is not None and rep.get("pdu_type_num") == 0
                and any(key not in rep for key in ("op_num", "context_id", "alloc_hint"))):
            # Some Scapy versions leave a standard request body as Raw. Its
            # fixed fields follow the 16-byte connection-oriented RPC header.
            request = bytes(hdr)
            if len(request) < 16:
                raise _BError("truncated RPC common header")
            byte_order = "little" if int(hdr.integerRepresentation) == 1 else "big"
            header_length = 40 if request[3] & 0x80 else 24  # optional object UUID
            fragment_length = int.from_bytes(request[8:10], byte_order)
            if fragment_length < header_length or fragment_length > len(request):
                raise _BError("truncated RPC request fragment")
            auth_length = int.from_bytes(request[10:12], byte_order)
            if auth_length and fragment_length - auth_length - 8 < header_length:
                raise _BError("RPC authentication trailer overlaps request header")
            rep.setdefault("alloc_hint", int.from_bytes(request[16:20], byte_order))
            rep.setdefault("context_id", int.from_bytes(request[20:22], byte_order))
            rep.setdefault("op_num", int.from_bytes(request[22:24], byte_order))
        # NTLM auth details, if any, often ride OPC-DA/DCOM.
        ntlm = getattr(opc_da, "NTLM_Header", None)
        if ntlm is not None and msg.haslayer(ntlm):
            rep["ntlm"] = _packet_fields(msg.getlayer(ntlm))
        strings = _printable_strings(raw_bytes, 4)
        if strings:
            rep["strings"] = strings
        rep["flags"] = sorted(set(_scan_flags(raw_bytes)))
    except Exception as e:                             # noqa: BLE001
        rep["error"] = f"{type(e).__name__}: {e}"
        rep["flags"] = _scan_flags(payload or b"")
    return rep


# ======================================================================================
#  protocol auto-detection
# ======================================================================================

def detect_protocol(payload: bytes) -> str:
    """Best-effort protocol guess for a raw payload. None if nothing fits."""
    if not payload:
        return None
    if payload[0] == 0x81 and len(payload) >= 4:       # BVLC type
        func = payload[1]
        if func in BVLC_FUNCTIONS and int.from_bytes(payload[2:4], "big") <= len(payload) + 4:
            return "bacnet"
    # DCE/RPC v4 (Profinet acyclic PN-CM, connection-less; also what rides UDP 34964). The
    # datagram begins with rpc_vers=0x04 and a small ptype, and its connection-less header is
    # long (three 16-byte UUIDs). The only ENIP command that also starts with 0x04 is
    # ListServices, whose request is exactly 24 bytes -- so a longer 0x04 datagram is DCE/RPC,
    # not ENIP. Checked before ENIP so it is not swallowed as ListServices.
    if len(payload) >= 40 and payload[0] == 0x04 and payload[1] <= 0x13:
        return "profinet"
    if len(payload) >= 24:                              # ENIP header: command in known set
        cmd = int.from_bytes(payload[0:2], "little")
        length = int.from_bytes(payload[2:4], "little")
        if cmd in ENIP_COMMANDS and 24 + length <= len(payload) + 8:
            return "enip"
    if len(payload) >= 8 and payload[0] == 0x05 and payload[2] < 14:  # DCE/RPC v5 header
        return "opcda"
    # Profinet raw frame: ProfinetIO frameID is the first 2 bytes (big-endian). Prefer scapy's
    # known-frame-id table when available, else a range heuristic (DCP/alarm/RT-cyclic/PTCP).
    if len(payload) >= 2:
        fid = int.from_bytes(payload[0:2], "big")
        sc = _load_scapy()
        if sc:
            try:
                from scapy.contrib.pnio import PNIO_FRAME_IDS
                if fid in PNIO_FRAME_IDS:
                    return "profinet"
            except Exception:                          # noqa: BLE001
                pass
        if 0xFE00 <= fid <= 0xFFFF or 0x8000 <= fid <= 0xBFFF or fid in (0x0080, 0x0020):
            return "profinet"
    return None


# ======================================================================================
#  pcap handling
# ======================================================================================

def _is_pcap(data: bytes) -> bool:
    return data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1",
                        b"\xa1\xb2\x3c\x4d") or data[:4] == b"\x0a\x0d\x0d\x0a"  # pcapng


def reports_from_pcap(path: str) -> list:
    """Dissect a pcap/pcapng and return per-packet reports for every fieldbus payload found."""
    sc = _load_scapy()
    if not sc:
        return [{"error": "scapy is required to read a pcap (not installed)"}]
    rdpcap = sc["rdpcap"]
    UDP, TCP, Raw = sc["UDP"], sc["TCP"], sc["Raw"]
    ProfinetIO = sc["ProfinetIO"]
    pnio_dcp, opc_da = sc["pnio_dcp"], sc["opc_da"]
    out = []
    try:
        packets = rdpcap(path)
    except Exception as e:                             # noqa: BLE001
        return [{"error": f"could not read pcap: {type(e).__name__}: {e}"}]
    for idx, pkt in enumerate(packets):
        try:
            # Profinet RT/DCP rides raw Ethernet (0x8892) -> scapy already dissected it.
            if pkt.haslayer(ProfinetIO) or pkt.haslayer(pnio_dcp.ProfinetDCP):
                r = profinet_report(pkt=pkt)
                r["packet"] = idx
                out.append(r)
                continue
            if pkt.haslayer(UDP):
                udp = pkt.getlayer(UDP)
                pl = bytes(udp.payload) if udp.payload else b""
                if not pl:
                    continue
                if 47808 in (udp.sport, udp.dport) or (pl[:1] == b"\x81"):
                    r = bacnet_report(pl)
                    r["packet"] = idx
                    out.append(r)
                elif 34964 in (udp.sport, udp.dport):          # Profinet DCE/RPC (acyclic PN-CM)
                    r = profinet_report(payload=pl, prefer="rpc")
                    r["packet"] = idx
                    out.append(r)
            elif pkt.haslayer(TCP):
                tcp = pkt.getlayer(TCP)
                pl = bytes(tcp.payload) if tcp.payload else b""
                if not pl:
                    continue
                if 44818 in (tcp.sport, tcp.dport):
                    for r in _split_enip(pl):
                        r["packet"] = idx
                        out.append(r)
                elif 135 in (tcp.sport, tcp.dport) or (len(pl) >= 8 and pl[0] == 0x05 and pl[2] < 14):
                    r = opcda_report(payload=pl)
                    r["packet"] = idx
                    out.append(r)
        except Exception as e:                         # noqa: BLE001
            out.append({"packet": idx, "error": f"{type(e).__name__}: {e}"})
    return out


def _split_enip(payload: bytes) -> list:
    """A TCP segment can carry several ENIP frames back to back; split on the length field."""
    out, off = [], 0
    while off + 24 <= len(payload):
        length = int.from_bytes(payload[off + 2:off + 4], "little")
        frame = payload[off:off + 24 + length]
        if len(frame) < 24:
            break
        out.append(parse_enip(frame))
        off += 24 + length
        if length == 0 and len(out) > 0:
            break
    if not out:
        out.append(parse_enip(payload))
    return out


# ======================================================================================
#  one-file dispatch
# ======================================================================================

def analyze_file(path: str, proto: str = None) -> dict:
    """Analyze one input file (raw payload or pcap). Returns {file, kind, reports:[...]}."""
    data = Path(path).read_bytes()
    if len(data) > MAX_FILE:
        return {"file": path, "error": f"file too large ({len(data)} bytes)"}
    if _is_pcap(data):
        return {"file": path, "kind": "pcap", "reports": reports_from_pcap(path)}
    chosen = proto or detect_protocol(data)
    if chosen == "bacnet":
        rep = bacnet_report(data)
    elif chosen == "enip":
        rep = parse_enip(data)
    elif chosen == "profinet":
        rep = profinet_report(payload=data)
    elif chosen == "opcda":
        rep = opcda_report(payload=data)
    else:
        return {"file": path, "kind": "raw", "reports": [],
                "error": "could not auto-detect protocol; pass --proto bacnet|enip|profinet|opcda",
                "flags": _scan_flags(data)}
    return {"file": path, "kind": "raw", "reports": [rep]}


# ======================================================================================
#  rendering
# ======================================================================================

def _all_flags(obj) -> list:
    """Collect every flag string found anywhere in a report tree."""
    found = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "flags" and isinstance(v, list):
                found += v
            else:
                found += _all_flags(v)
    elif isinstance(obj, list):
        for v in obj:
            found += _all_flags(v)
    elif isinstance(obj, str):
        found += _scan_flags(obj)
    seen, out = set(), []
    for f in found:
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out


def _render_tags(tags, lines):
    for tok in tags:
        if "error" in tok:
            lines.append(f"      ! {tok['error']}")
            continue
        indent = "    " + "  " * tok.get("depth", 0)
        kind = tok.get("kind")
        if kind == "opening":
            lines.append(f"{indent}[{tok['tag_number']}  {{")
            continue
        if kind == "closing":
            lines.append(f"{indent}}} {tok['tag_number']}]")
            continue
        cls = "ctx" if tok.get("tag_class") == "context" else "app"
        if tok.get("tag_class") == "application":
            label = tok.get("app_type", "?")
            val = tok.get("value")
            extra = ""
            if tok.get("flags"):
                extra = "   <<< FLAG >>>"
            if isinstance(val, dict) and "text" in val:
                val = val["text"]
            lines.append(f"{indent}{cls} {label} = {val!r}{extra}")
        else:
            desc = []
            if "as_unsigned" in tok:
                desc.append(f"uint={tok['as_unsigned']}")
            if "as_object_id" in tok:
                desc.append(f"object={tok['as_object_id']['text']}")
            if "as_text" in tok:
                desc.append(f"text={tok['as_text']}")
            if not desc:
                desc.append(f"raw=0x{tok.get('raw', '')}")
            extra = "   <<< FLAG >>>" if tok.get("flags") else ""
            lines.append(f"{indent}{cls}[{tok['tag_number']}] {', '.join(desc)}{extra}")


def render_report(rep: dict, lines: list):
    proto = rep.get("protocol", "?")
    pk = f" (packet #{rep['packet']})" if "packet" in rep else ""
    lines.append(f"  -- {proto}{pk} --")
    if rep.get("error"):
        lines.append(f"     error: {rep['error']}")
    if proto == "bacnet-ip":
        bv = rep.get("bvlc", {})
        lines.append(f"     BVLC: {bv.get('function')}  len={bv.get('length')}"
                     + (f"  from {bv['forwarded_from']}" if bv.get("forwarded_from") else ""))
        np = rep.get("npdu")
        if np:
            d = []
            if np.get("src_present"):
                d.append(f"SNET={np.get('snet')} SADR={np.get('sadr')}")
            if np.get("dest_present"):
                d.append(f"DNET={np.get('dnet')} DADR={np.get('dadr')}")
            if np.get("expecting_reply"):
                d.append("expecting-reply")
            lines.append(f"     NPDU: v{np.get('version')} priority={np.get('priority')}"
                         + ("  " + ", ".join(d) if d else ""))
        ap = rep.get("apdu")
        if ap:
            svc = ap.get("service_choice")
            lines.append(f"     APDU: {ap.get('pdu_type')}"
                         + (f"  invoke={ap.get('invoke_id')}" if "invoke_id" in ap else "")
                         + (f"  service={svc}" if svc is not None else ""))
            sr = ap.get("service_reading")
            if sr:
                parts = [f"{k}={v}" for k, v in sr.items()]
                lines.append(f"       -> {', '.join(parts)}")
            if ap.get("tags"):
                _render_tags(ap["tags"], lines)
    elif proto == "ethernet-ip":
        lines.append(f"     ENIP: {rep.get('command')}  session={rep.get('session')}"
                     f"  status={rep.get('status')}")
        if "protocol_version" in rep:
            lines.append(f"       RegisterSession: protocol v{rep['protocol_version']}")
        for it in rep.get("items", []):
            head = f"       item {it.get('type_id')} (len {it.get('length')})"
            if "sequence_count" in it:
                head += f"  seq={it['sequence_count']}"
            lines.append(head)
            cip = it.get("cip")
            if cip:
                _render_cip(cip, lines)
            ident = it.get("identity")
            if ident:
                lines.append(f"         identity: {ident.get('product_name')!r}"
                             f"  vendor={ident.get('vendor_id')} serial={ident.get('serial')}"
                             + ("   <<< FLAG >>>" if ident.get("flags") else ""))
    elif proto == "profinet":
        if "frame_id" in rep:
            lines.append(f"     frameID: {rep['frame_id']}")
        dcp = rep.get("dcp")
        if dcp:
            lines.append(f"     DCP: {dcp.get('service_id')} / {dcp.get('service_type')}"
                         f"  xid={dcp.get('xid')}")
            for blk in dcp.get("blocks", []):
                fields = {k: v for k, v in blk.items() if k not in ("block",)}
                flag = "   <<< FLAG >>>" if fields.pop("flags", None) else ""
                lines.append(f"       {blk['block']}: {fields}{flag}")
            for fld in ("name_of_station", "ip", "mac", "gateway", "netmask", "alias_name"):
                if fld in dcp:
                    lines.append(f"       {fld} = {dcp[fld]}")
        if rep.get("rpc"):
            lines.append(f"     RPC: {rep['rpc']}")
    elif proto == "opc-da":
        lines.append(f"     OPC-DA/DCOM: {rep.get('pdu_type')}  call={rep.get('call_id')}"
                     + (f"  opnum={rep['op_num']}" if "op_num" in rep else "")
                     + (f"  byte_order={rep.get('byte_order')}" if rep.get("byte_order") else ""))
        if rep.get("ntlm"):
            lines.append(f"       NTLM: {rep['ntlm']}")
        if rep.get("strings"):
            lines.append(f"       strings: {rep['strings'][:8]}")


def _render_cip(cip: dict, lines: list):
    if cip.get("error"):
        lines.append(f"         CIP: error {cip['error']}")
        return
    if cip.get("direction") == "request":
        path = cip.get("path", [])
        path_str = " / ".join(
            (f"{p['segment']}={p.get('name', p.get('value', p.get('raw')))}") for p in path)
        lines.append(f"         CIP request: {cip.get('service')}   path: {path_str}")
    else:
        lines.append(f"         CIP response: {cip.get('service')}  status={cip.get('general_status')}")
    if cip.get("flags"):
        lines.append(f"         CIP data <<< FLAG >>>: {cip['flags']}")
    elif cip.get("strings"):
        lines.append(f"         CIP data strings: {cip['strings'][:6]}")
    for sub in cip.get("embedded", []):
        _render_cip(sub, lines)


def render(result: dict) -> str:
    lines = [f"# {result['file']}  [{result.get('kind', '?')}]"]
    if result.get("error"):
        lines.append(f"  error: {result['error']}")
    flags = _all_flags(result)
    if flags:
        lines.append("  " + "=" * 56)
        for f in flags:
            lines.append(f"  *** CSCTF FLAG FORMAT MATCH:  {f}")
        lines.append("  " + "=" * 56)
    reports = result.get("reports", [])
    if not reports and not result.get("error"):
        lines.append("  (no fieldbus payloads recognized)")
    for rep in reports:
        render_report(rep, lines)
    return "\n".join(lines)


# ======================================================================================
#  CLI
# ======================================================================================

def _json_default(o):
    if isinstance(o, (bytes, bytearray)):
        return o.hex()
    return str(o)


def main(argv) -> int:
    ap = argparse.ArgumentParser(
        prog="ics_fieldbus.py",
        description="Offline decoder for BACnet/IP, EtherNet/IP+CIP, Profinet and OPC-DA. "
                    "Input: a raw protocol-payload file (UDP/TCP payload, or an Ethernet frame "
                    "for Profinet) OR a .pcap/.pcapng. Flag-format hits are highlighted.")
    ap.add_argument("files", nargs="*", help="raw payload file(s) and/or pcap/pcapng file(s)")
    ap.add_argument("--json", action="store_true", help="emit the full decode as JSON")
    ap.add_argument("--proto", choices=["bacnet", "enip", "profinet", "opcda"],
                    help="force the protocol for a RAW payload file (ignored for pcaps)")
    args = ap.parse_args(argv)
    if not args.files:
        ap.print_help(sys.stderr)
        return 2
    results = []
    for p in args.files:
        try:
            results.append(analyze_file(p, args.proto))
        except OSError as e:
            results.append({"file": p, "error": str(e)})
        except Exception as e:                         # noqa: BLE001
            results.append({"file": p, "error": f"{type(e).__name__}: {e}"})
    if args.json:
        print(json.dumps(results, indent=1, default=_json_default))
        return 0
    for r in results:
        print(render(r))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
