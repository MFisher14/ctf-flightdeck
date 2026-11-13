#!/usr/bin/env python3
"""solvers/toolkits/ics_fieldbus.py: the ICS fieldbus / building-automation offline decoder.

Offline, no network, no token. Every input below is SYNTHETIC and SPEC-DERIVED: BACnet/IP frames are
hand-built from the BVLC/NPDU/APDU + tag grammar with known field values; the EtherNet/IP + CIP frames
are hand-built in TRUE wire byte order; the Profinet and OPC-DA frames are built with scapy (the
dissectors the wrapper wraps) and the wrapper is asserted to read them back. No real device data and
no real flags (the flag strings here are obviously synthetic markers in the CSCTF format).

  CTF_WORKDIR=/tmp/ctfws .venv/bin/python tests/test_ics_fieldbus.py   # prints 'ok', exits 0/1

  bacnet      BVLC/NPDU/APDU; ReadProperty req+ack, WriteProperty, Who-Is/I-Am, Forwarded-NPDU, the
              application-tag primitives (unsigned/real/enumerated/object-id/char-string), extended
              tag numbers and extended lengths; a flag in a character-string property value is found
  enip/cip    ENIP encapsulation + CPF items in TRUE wire order; CIP Get_Attribute_Single request and
              response, Logix Read_Tag symbolic path, Connected Data sequence, ListIdentity product
              name, RegisterSession; CROSS-CHECKED against scapy.contrib.enipTCP (and the test pins
              the enipTCP ItemData.data byte-reversal that makes raw-buffer CIP parsing necessary)
  profinet    scapy-built ProfinetIO/ProfinetDCP Identify response + Set-name request; the wrapper
              reads frameID, service and the name-of-station block (where a flag hides)
  opc-da      scapy-built OpcDaMessage REQUEST and BIND; the wrapper reads the PDU type, call id and
              opnum and flag-scans the stub data
  pcap        a mixed BACnet(UDP)/ENIP(TCP)/Profinet(Ether) capture read back through analyze_file
  cli         the command prints a readable decode, highlights the flag, and emits valid --json
  degrade     with scapy forced absent, Profinet/OPC-DA report an error (no crash) and BACnet/ENIP
              still work
"""
import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
os.environ.setdefault("CTF_WORKDIR", tempfile.mkdtemp(prefix="csctf-icsfb-"))
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
sys.dont_write_bytecode = True

import ics_fieldbus as F                                    # noqa: E402

PY = sys.executable
MOD = str(REPO / "solvers" / "toolkits" / "ics_fieldbus.py")


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:400]}]"))
    if not ok:
        raise AssertionError(f"{label}" + (f": {detail}" if detail else ""))


# ====================================================================================== BACnet builders

def _bvlc(body, func=0x0A):
    return bytes([0x81, func]) + (len(body) + 4).to_bytes(2, "big") + body


def _objid_bytes(otype, inst):
    return ((otype << 22) | inst).to_bytes(4, "big")


def _ctx(num, content):                                     # context primitive tag, len <= 4
    assert len(content) <= 4
    return bytes([(num << 4) | 0x08 | len(content)]) + content


def _ctx_open(num):
    return bytes([(num << 4) | 0x08 | 0x06])


def _ctx_close(num):
    return bytes([(num << 4) | 0x08 | 0x07])


def _app_u(val):
    n = max(1, (val.bit_length() + 7) // 8)
    return bytes([0x20 | n]) + val.to_bytes(n, "big")       # application tag 2, Unsigned


def _app_enum(val):
    n = max(1, (val.bit_length() + 7) // 8)
    return bytes([0x90 | n]) + val.to_bytes(n, "big")       # application tag 9, Enumerated


def _app_real(f):
    return bytes([0x44]) + struct.pack(">f", f)             # application tag 4, Real (len 4)


def _app_objid(otype, inst):
    return bytes([0xC4]) + _objid_bytes(otype, inst)        # application tag 12, len 4


def _app_charstring(s, enc=0):
    body = bytes([enc]) + s.encode()
    if len(body) <= 4:
        return bytes([0x70 | len(body)]) + body
    return bytes([0x70 | 0x05, len(body)]) + body           # extended length (one byte, < 254)


# ====================================================================================== BACnet tests

RP_FLAG = "csctf{bacnet_rp_object_name}"
WP_FLAG = "chronos{bacnet_writeprop}"


def test_bacnet_readproperty_ack():
    apdu = (bytes([0x30, 0x01, 0x0C])                       # ComplexACK, invoke 1, svc 12 readProperty
            + _ctx(0, _objid_bytes(8, 12345))               # object device:12345
            + _ctx(1, bytes([77]))                          # property object-name (77)
            + _ctx_open(3) + _app_charstring(RP_FLAG) + _ctx_close(3))
    rep = F.bacnet_report(_bvlc(bytes([0x01, 0x00]) + apdu))   # NPDU v1 ctrl 0, then APDU
    check("bacnet ack: protocol", rep.get("protocol") == "bacnet-ip", rep)
    check("bacnet ack: BVLC Original-Unicast",
          rep["bvlc"]["function"] == "Original-Unicast-NPDU", rep["bvlc"])
    ap = rep["apdu"]
    check("bacnet ack: ComplexACK readProperty",
          ap["pdu_type"] == "ComplexACK" and ap["service_choice"] == "readProperty", ap)
    sr = ap["service_reading"]
    check("bacnet ack: object device:12345", sr.get("object") == "device:12345", sr)
    check("bacnet ack: property object-name", sr.get("property") == "object-name", sr)
    check("bacnet ack: value is the flag", sr.get("value") == RP_FLAG, sr)
    check("bacnet ack: flag highlighted", RP_FLAG in F._all_flags(rep), F._all_flags(rep))


def test_bacnet_readproperty_request():
    apdu = (bytes([0x00, 0x05, 0x2A, 0x0C])                 # Confirmed-REQ, maxseg, invoke 42, svc 12
            + _ctx(0, _objid_bytes(2, 7))                   # analog-value:7
            + _ctx(1, bytes([85])))                         # property present-value (85)
    body = bytes([0x01, 0x04]) + apdu                       # NPDU control 0x04 = expecting reply
    rep = F.bacnet_report(_bvlc(body))
    ap = rep["apdu"]
    check("bacnet req: Confirmed-REQ readProperty",
          ap["pdu_type"] == "Confirmed-REQ" and ap["service_choice"] == "readProperty", ap)
    check("bacnet req: invoke id 42", ap["invoke_id"] == 42, ap)
    check("bacnet req: npdu expecting-reply", rep["npdu"]["expecting_reply"] is True, rep["npdu"])
    sr = ap["service_reading"]
    check("bacnet req: object analog-value:7", sr.get("object") == "analog-value:7", sr)
    check("bacnet req: property present-value", sr.get("property") == "present-value", sr)


def test_bacnet_writeproperty_flag():
    apdu = (bytes([0x00, 0x05, 0x03, 0x0F])                 # Confirmed-REQ svc 15 writeProperty
            + _ctx(0, _objid_bytes(5, 2))                   # binary-value:2
            + _ctx(1, bytes([85]))                          # present-value
            + _ctx_open(3) + _app_charstring(WP_FLAG) + _ctx_close(3))
    rep = F.bacnet_report(_bvlc(bytes([0x01, 0x00]) + apdu))   # NPDU v1 ctrl 0, then APDU
    check("bacnet wp: service writeProperty", rep["apdu"]["service_choice"] == "writeProperty", rep["apdu"])
    check("bacnet wp: flag found", WP_FLAG in F._all_flags(rep), F._all_flags(rep))


def test_bacnet_whois_iam():
    whois = _bvlc(bytes([0x01, 0x00]) + bytes([0x10, 0x08]) + _ctx(0, bytes([5])) + _ctx(1, bytes([40])),
                  func=0x0B)
    r = F.bacnet_report(whois)
    check("bacnet who-is: service", r["apdu"]["service_choice"] == "who-Is", r["apdu"])
    check("bacnet who-is: range [5,40]",
          r["apdu"]["service_reading"].get("device_instance_range") == [5, 40], r["apdu"])

    iam = _bvlc(bytes([0x01, 0x00]) + bytes([0x10, 0x00]) + _app_objid(8, 260)
                + _app_u(1476) + _app_enum(0) + _app_u(99), func=0x0B)
    r2 = F.bacnet_report(iam)
    sr = r2["apdu"]["service_reading"]
    check("bacnet i-am: device", sr.get("device") == "device:260", sr)
    check("bacnet i-am: vendor id 99", sr.get("vendor_id") == 99, sr)


def test_bacnet_forwarded_npdu():
    apdu = bytes([0x10, 0x00]) + _app_objid(8, 1)           # I-Am
    inner = bytes([0x01, 0x00]) + apdu
    body = bytes([192, 168, 1, 50]) + (47808).to_bytes(2, "big") + inner  # 6-byte B/IP + NPDU
    frame = _bvlc(body, func=0x04)                          # Forwarded-NPDU
    rep = F.bacnet_report(frame)
    check("bacnet fwd: function", rep["bvlc"]["function"] == "Forwarded-NPDU", rep["bvlc"])
    check("bacnet fwd: source addr", rep["bvlc"]["forwarded_from"] == "192.168.1.50:47808", rep["bvlc"])
    check("bacnet fwd: inner APDU decoded", rep["apdu"]["service_choice"] == "i-Am", rep.get("apdu"))


def test_bacnet_npdu_routing():
    # Routed frame: control 0x2C = dest + src + expecting-reply. DNET/DLEN/DADR, SNET/SLEN/SADR,
    # then the hop count (which follows a destination), then the APDU.
    npdu = (bytes([0x01, 0x2C])
            + bytes([0x00, 0x05, 0x01, 0x42])           # DNET=5 DLEN=1 DADR=0x42
            + bytes([0x00, 0x0A, 0x01, 0x17])           # SNET=10 SLEN=1 SADR=0x17
            + bytes([0xFE]))                            # hop count 254
    apdu = bytes([0x10, 0x08])                          # unconfirmed who-is
    rep = F.bacnet_report(_bvlc(npdu + apdu))
    np = rep["npdu"]
    check("bacnet route: dnet/dadr", np.get("dnet") == 5 and np.get("dadr") == "42", np)
    check("bacnet route: snet/sadr", np.get("snet") == 10 and np.get("sadr") == "17", np)
    check("bacnet route: hop count 254", np.get("hop_count") == 254, np)
    check("bacnet route: expecting-reply + src/dest flags",
          np.get("expecting_reply") and np.get("src_present") and np.get("dest_present"), np)
    check("bacnet route: APDU after routing decoded",
          rep["apdu"]["service_choice"] == "who-Is", rep.get("apdu"))
    # Global-broadcast destination: DLEN=0 means a broadcast DADR, but the hop count still follows.
    npdu2 = bytes([0x01, 0x20]) + bytes([0xFF, 0xFF, 0x00]) + bytes([0xFF]) + apdu
    r2 = F.bacnet_report(_bvlc(npdu2))
    check("bacnet route: global-broadcast dadr + hop",
          r2["npdu"]["dnet"] == 0xFFFF and r2["npdu"]["dadr"] == "broadcast"
          and r2["npdu"]["hop_count"] == 255 and r2["apdu"]["service_choice"] == "who-Is", r2["npdu"])


def test_bacnet_signed_and_double():
    stream = (bytes([0x31, 0xFF])                       # Signed, len 1 = -1
              + bytes([0x32, 0xFF, 0x80])               # Signed, len 2 = -128
              + bytes([0x55, 0x08]) + struct.pack(">d", -12.5))   # Double (tag 5, extended length)
    toks = [t for t in F.decode_bacnet_tags(stream) if t.get("kind") == "primitive"]
    check("bacnet signed: -1", toks[0]["app_type"] == "Signed" and toks[0]["value"] == -1, toks[0])
    check("bacnet signed: -128", toks[1]["value"] == -128, toks[1])
    check("bacnet double: -12.5",
          toks[2]["app_type"] == "Double" and abs(toks[2]["value"] + 12.5) < 1e-9, toks[2])


def test_bacnet_tag_primitives():
    stream = _app_u(1000) + _app_real(3.5) + _app_enum(5) + _app_objid(8, 77)
    toks = [t for t in F.decode_bacnet_tags(stream) if t.get("kind") == "primitive"]
    kinds = [(t.get("app_type"), t.get("value")) for t in toks]
    check("bacnet tags: unsigned 1000", kinds[0] == ("Unsigned", 1000), kinds)
    check("bacnet tags: real 3.5", kinds[1][0] == "Real" and abs(kinds[1][1] - 3.5) < 1e-6, kinds)
    check("bacnet tags: enumerated 5", kinds[2] == ("Enumerated", 5), kinds)
    check("bacnet tags: object-id device:77",
          kinds[3][0] == "BACnetObjectIdentifier" and kinds[3][1]["text"] == "device:77", kinds)


def test_bacnet_extended_tag_and_length():
    # Context tag number 20 (extended-number form 0xF9 + 0x14), 1-byte value 9.
    ext = bytes([0xF9, 20, 9])
    toks = F.decode_bacnet_tags(ext)
    check("bacnet ext tag: number 20",
          toks[0]["tag_number"] == 20 and toks[0]["as_unsigned"] == 9, toks)
    # Extended-length character string (> 4 bytes) already exercised by the ACK flag; assert the
    # decoder reads a 200-byte string length exactly.
    big = "A" * 200
    cs = F.decode_bacnet_tags(_app_charstring(big))
    check("bacnet ext len: 200-char string", cs[0].get("value") == big, cs[0].get("length"))


def test_bacnet_adversarial():
    for name, blob in [("random", bytes(range(60))), ("not-bvlc", b"\x00" * 32),
                       ("truncated", b"\x81\x0a\x00\xff\x01")]:
        rep = F.bacnet_report(blob)
        check(f"bacnet adversarial {name}: no crash, no bogus flag",
              isinstance(rep, dict) and not rep.get("flags"), rep)


# ====================================================================================== ENIP/CIP builders

def _enip(cip_bytes=None, cmd=0x6F, session=0x11223344, item_type=0x00B2, body_override=None):
    """ENIP SendRRData with a null item + one data item carrying `cip_bytes` in TRUE wire order."""
    if body_override is not None:
        body = body_override
    else:
        cpf = (0).to_bytes(2, "little") + (0).to_bytes(2, "little")             # null address item
        cpf += item_type.to_bytes(2, "little") + len(cip_bytes).to_bytes(2, "little") + cip_bytes
        body = (0).to_bytes(4, "little") + (0).to_bytes(2, "little") + (2).to_bytes(2, "little") + cpf
    return (cmd.to_bytes(2, "little") + len(body).to_bytes(2, "little") + session.to_bytes(4, "little")
            + (0).to_bytes(4, "little") + b"\x00" * 8 + (0).to_bytes(4, "little") + body)


ENIP_FLAG = "csctf{enip_cip_product_name}"


def test_enip_cip_request():
    cip = bytes([0x0E, 0x03, 0x20, 0x01, 0x24, 0x01, 0x30, 0x07])   # Get_Attribute_Single Id/1/attr7
    rep = F.parse_enip(_enip(cip))
    check("enip req: command SendRRData", rep["command"] == "SendRRData", rep)
    check("enip req: session hex", rep["session"] == hex(0x11223344), rep)
    cipr = rep["items"][1]["cip"]
    check("enip req: CIP Get_Attribute_Single",
          cipr["service"] == "Get_Attribute_Single" and cipr["direction"] == "request", cipr)
    segs = {s["segment"]: s.get("name", s.get("value")) for s in cipr["path"]}
    check("enip req: path class Identity", segs.get("class") == "Identity", segs)
    check("enip req: path instance 1", segs.get("instance") == 1, segs)
    check("enip req: path attribute 7", segs.get("attribute") == 7, segs)


def test_enip_cip_response_flag():
    cip = bytes([0x8E, 0x00, 0x00, 0x00]) + ENIP_FLAG.encode()      # svc 0x0E | response, status 0
    rep = F.parse_enip(_enip(cip))
    cipr = rep["items"][1]["cip"]
    check("enip resp: direction", cipr["direction"] == "response", cipr)
    check("enip resp: status Success", cipr["general_status"] == "Success", cipr)
    check("enip resp: flag highlighted", ENIP_FLAG in F._all_flags(rep), F._all_flags(rep))


def test_enip_logix_symbolic():
    name = b"MyTag"
    sym = bytes([0x91, len(name)]) + name + (b"\x00" if len(name) % 2 else b"")
    cip = bytes([0x4C, len(sym) // 2]) + sym + (1).to_bytes(2, "little")   # Read_Tag, 1 element
    rep = F.parse_enip(_enip(cip))
    cipr = rep["items"][1]["cip"]
    check("enip logix: service Read_Tag", cipr["service"] == "Read_Tag", cipr)
    syms = [s["name"] for s in cipr["path"] if s["segment"] == "symbol"]
    check("enip logix: symbol MyTag", syms == ["MyTag"], cipr["path"])


def test_cip_16_and_32_bit_segments():
    # class 0x00AC (16-bit, padded), instance 0x1234 (16-bit), attribute 0x05 (8-bit).
    path = (bytes([0x21, 0x00]) + struct.pack("<H", 0x00AC)
            + bytes([0x25, 0x00]) + struct.pack("<H", 0x1234)
            + bytes([0x30, 0x05]))
    cip = F.parse_cip(bytes([0x0E, len(path) // 2]) + path)
    segs = {s["segment"]: s.get("name", s.get("value")) for s in cip["path"]}
    check("cip 16-bit: class Logix_Controller (0xAC)", segs.get("class") == "Logix_Controller", segs)
    check("cip 16-bit: instance 0x1234", segs.get("instance") == 0x1234, segs)
    check("cip 8-bit: attribute 5", segs.get("attribute") == 5, segs)
    # 32-bit instance (padded).
    path32 = bytes([0x20, 0x01]) + bytes([0x26, 0x00]) + struct.pack("<I", 0xDEADBEEF)
    cip32 = F.parse_cip(bytes([0x0E, len(path32) // 2]) + path32)
    s32 = {s["segment"]: s.get("value") for s in cip32["path"]}
    check("cip 32-bit: instance 0xDEADBEEF", s32.get("instance") == 0xDEADBEEF, s32)


def test_cip_multiple_service_packet():
    emb0 = bytes([0x0E, 0x02, 0x20, 0x01, 0x24, 0x01])          # Get_Attribute_Single Identity/1
    emb1 = bytes([0x4C, 0x02, 0x20, 0x6B, 0x24, 0x01])          # Read_Tag Symbol/1
    count = 2
    off0 = 2 + count * 2
    off1 = off0 + len(emb0)
    data = struct.pack("<HHH", count, off0, off1) + emb0 + emb1
    cip = F.parse_cip(bytes([0x0A, 0x02, 0x20, 0x02, 0x24, 0x01]) + data)   # svc 0x0A to Msg Router
    check("cip msp: service Multiple_Service_Packet",
          cip["service"] == "Multiple_Service_Packet", cip["service"])
    emb = cip.get("embedded", [])
    check("cip msp: two embedded services expanded", len(emb) == 2, emb)
    check("cip msp: embedded[0] Get_Attribute_Single",
          emb and emb[0]["service"] == "Get_Attribute_Single", emb)
    check("cip msp: embedded[1] Read_Tag", len(emb) > 1 and emb[1]["service"] == "Read_Tag", emb)


def test_enip_connected_item_sequence():
    cip = bytes([0x8C, 0x00, 0x00, 0x00]) + b"OK"           # a Read_Tag response payload
    seq = (0x0007).to_bytes(2, "little")
    rep = F.parse_enip(_enip(seq + cip, item_type=0x00B1))
    it = rep["items"][1]
    check("enip conn: type Connected Data", it["type_id"] == "Connected Data", it)
    check("enip conn: sequence count 7", it.get("sequence_count") == 7, it)
    check("enip conn: CIP after sequence", it["cip"]["direction"] == "response", it["cip"])


def test_enip_listidentity_and_register():
    # ListIdentity response item (type 0x000C) with a product name holding a flag.
    pname = b"ControlLogix flag{enip_identity}"
    item = (struct.pack("<H", 1) + b"\x00" * 2 + struct.pack(">H", 44818) + bytes([10, 0, 0, 5])
            + b"\x00" * 8 + struct.pack("<H", 1) + struct.pack("<H", 14) + struct.pack("<H", 54)
            + bytes([21, 1]) + struct.pack("<H", 0x30) + struct.pack("<I", 0x12345678)
            + bytes([len(pname)]) + pname + bytes([3]))
    body = struct.pack("<H", 1) + struct.pack("<H", 0x000C) + struct.pack("<H", len(item)) + item
    rep = F.parse_enip(_enip(cmd=0x63, body_override=body))
    check("enip identity: command ListIdentity", rep["command"] == "ListIdentity", rep["command"])
    check("enip identity: flag in product name", "flag{enip_identity}" in F._all_flags(rep),
          F._all_flags(rep))

    reg = F.parse_enip(_enip(cmd=0x65, body_override=struct.pack("<HH", 1, 0)))
    check("enip register: command RegisterSession", reg["command"] == "RegisterSession", reg["command"])
    check("enip register: protocol version 1", reg.get("protocol_version") == 1, reg)


def test_enip_detect():
    cip = bytes([0x0E, 0x02, 0x20, 0x01, 0x24, 0x01])
    wire = _enip(cip)
    check("enip detect: auto-detected", F.detect_protocol(wire) == "enip", wire[:4].hex())


def test_enip_scapy_crosscheck():
    """Cross-check the ENIP envelope against scapy.contrib.enipTCP, and PIN the ItemData.data
    byte-reversal that is the reason CIP is parsed from the raw buffer here, not from scapy."""
    sc = F._load_scapy()
    if not sc:
        check("enip scapy: skipped (scapy absent)", True)
        return
    from scapy.contrib.enipTCP import ENIPTCP, ENIPSendRRData, ItemData
    cip = bytes([0x0E, 0x03, 0x20, 0x01, 0x24, 0x01, 0x30, 0x07])
    wire = _enip(cip)                                       # TRUE wire order (what a device emits)
    mine = F.parse_enip(wire)
    d = ENIPTCP(wire)
    check("enip x-check: command agrees", int(d.commandId) == mine["command_num"] == 0x6F, mine["command_num"])
    check("enip x-check: session agrees", hex(int(d.session)) == mine["session"], mine["session"])
    items = d.payload.items
    check("enip x-check: item count agrees", len(items) == len(mine["items"]) == 2, len(items))
    check("enip x-check: data item type id agrees",
          int(items[1].typeId) == mine["items"][1]["type_id_num"] == 0x00B2, items[1].typeId)
    # The pin: scapy's XLEStrLenField reverses the item data, so scapy's it.data == our CIP reversed.
    check("enip x-check: scapy ItemData.data is byte-reversed (justifies raw-buffer CIP)",
          bytes(items[1].data) == cip[::-1], bytes(items[1].data).hex())
    check("enip x-check: our CIP is correct (true order)",
          mine["items"][1]["cip"]["service"] == "Get_Attribute_Single", mine["items"][1]["cip"])


# ====================================================================================== Profinet tests

PN_FLAG = "chronos{profinet_station_name}"


def test_profinet_dcp_identify():
    sc = F._load_scapy()
    if not sc:
        r = F.profinet_report(payload=b"\xfe\xff")
        check("profinet: graceful without scapy", "scapy" in str(r.get("error", "")).lower(), r)
        return
    from scapy.all import raw
    from scapy.contrib.pnio import ProfinetIO
    from scapy.contrib import pnio_dcp as dcpmod
    from scapy.contrib.pnio_dcp import ProfinetDCP, DCPNameOfStationBlock
    blk = DCPNameOfStationBlock(name_of_station=PN_FLAG.encode())
    dcp = ProfinetDCP(service_id=5, service_type=1, xid=0x0101,
                      dcp_data_length=len(raw(blk)), dcp_blocks=[blk])
    pio = ProfinetIO(frameID=dcpmod.DCP_IDENTIFY_RESPONSE_FRAME_ID) / dcp
    rep = F.profinet_report(payload=raw(pio))
    check("profinet: frameID identify response", rep.get("frame_id") == "DCP-Identify-ResPDU", rep)
    check("profinet: DCP service Identify", rep["dcp"]["service_id"] == "Identify", rep["dcp"])
    check("profinet: name-of-station block present",
          any(b["block"] == "DCPNameOfStationBlock" for b in rep["dcp"].get("blocks", [])), rep["dcp"])
    check("profinet: station-name flag found", PN_FLAG in rep.get("flags", []), rep.get("flags"))


def test_profinet_dcp_set_request():
    sc = F._load_scapy()
    if not sc:
        check("profinet set: skipped (scapy absent)", True)
        return
    from scapy.all import raw
    from scapy.contrib.pnio import ProfinetIO
    from scapy.contrib import pnio_dcp as dcpmod
    from scapy.contrib.pnio_dcp import ProfinetDCP
    # Set name-of-station request rides ProfinetIO with the DCP Get/Set frame id (0xFEFD).
    req = ProfinetDCP(service_id=4, service_type=0, option=2, sub_option=2,
                      name_of_station=b"plc", dcp_block_length=5)
    pio = ProfinetIO(frameID=dcpmod.DCP_GET_SET_FRAME_ID) / req
    rep = F.profinet_report(payload=raw(pio))
    check("profinet set: service id Set", rep["dcp"]["service_id"] == "Set", rep["dcp"])
    check("profinet set: name_of_station present as a header field",
          "name_of_station" in rep["dcp"], rep["dcp"])


def test_profinet_dce_rpc():
    """Profinet acyclic PN-CM rides DCE/RPC v4 over UDP 34964. Regression guard: a DCE/RPC
    datagram begins with rpc_vers=0x04, which the old code mis-read as a ProfinetIO frameID
    (so the RPC was never decoded). Both the explicit prefer='rpc' path (what the pcap UDP
    dispatch uses) and the raw first-byte autodetect must now yield an 'rpc' field, not a
    bogus frame_id."""
    sc = F._load_scapy()
    if not sc:
        check("profinet rpc: skipped (scapy absent)", True)
        return
    from scapy.all import raw
    from scapy.contrib import pnio_rpc
    payload = raw(pnio_rpc.DceRpc4(ptype=0, seqnum=7, opnum=3))
    check("profinet rpc: datagram starts 0x04 (rpc_vers 4)", payload[:1] == b"\x04", payload[:4].hex())
    r_pref = F.profinet_report(payload=payload, prefer="rpc")
    check("profinet rpc: prefer='rpc' decodes DceRpc4",
          "rpc" in r_pref and "frame_id" not in r_pref, r_pref)
    check("profinet rpc: opnum/seqnum read", str(r_pref["rpc"].get("opnum")) == "3"
          and str(r_pref["rpc"].get("seqnum")) == "7", r_pref.get("rpc"))
    r_auto = F.profinet_report(payload=payload)
    check("profinet rpc: raw autodetect (0x04) also decodes RPC",
          "rpc" in r_auto and "frame_id" not in r_auto, r_auto)
    check("profinet rpc: detect_protocol routes raw DCE/RPC to profinet",
          F.detect_protocol(payload) == "profinet", F.detect_protocol(payload))


# ====================================================================================== OPC-DA tests

OPC_FLAG = "csctf{opc_da_item_id}"


def test_opcda_request():
    sc = F._load_scapy()
    if not sc:
        r = F.opcda_report(payload=b"\x05\x00\x00\x03")
        check("opc-da: graceful without scapy", "scapy" in str(r.get("error", "")).lower(), r)
        return
    from scapy.all import raw
    from scapy.contrib import opc_da as o
    stub = ("itemID=" + OPC_FLAG + "\x00").encode()
    chain = (o.OpcDaHeaderMessage(versionMajor=5, versionMinor=0, pduType=0, integerRepresentation=1)
             / o.OpcDaHeaderNLE(callID=0x2A)
             / o.OpcDaRequestLE(allocHint=len(stub), contextId=1, opNum=3, stubData=stub))
    rep = F.opcda_report(payload=raw(chain))
    check("opc-da req: PDU type REQUEST", rep.get("pdu_type") == "REQUEST", rep)
    check("opc-da req: call id 0x2a", rep.get("call_id") == hex(0x2A), rep)
    check("opc-da req: opnum 3", rep.get("op_num") == 3, rep)
    check("opc-da req: flag in stub", OPC_FLAG in rep.get("flags", []), rep.get("flags"))


def test_opcda_bind():
    sc = F._load_scapy()
    if not sc:
        check("opc-da bind: skipped (scapy absent)", True)
        return
    from scapy.all import raw
    from scapy.contrib import opc_da as o
    chain = (o.OpcDaHeaderMessage(versionMajor=5, pduType=11, integerRepresentation=1)
             / o.OpcDaHeaderNLE(callID=1)
             / o.OpcDaBindLE(maxXmitFrag=5840, maxRecvtFrag=5840, assocGroupId=0))
    rep = F.opcda_report(payload=raw(chain))
    check("opc-da bind: PDU type BIND", rep.get("pdu_type") == "BIND", rep)


# ====================================================================================== pcap + CLI

def test_pcap_mixed():
    sc = F._load_scapy()
    if not sc:
        check("pcap: skipped (scapy absent)", True)
        return
    from scapy.all import raw, Ether, IP, UDP, TCP, wrpcap
    from scapy.contrib.pnio import ProfinetIO
    from scapy.contrib import pnio_dcp as dcpmod
    from scapy.contrib.pnio_dcp import ProfinetDCP, DCPNameOfStationBlock
    tmp = Path(tempfile.mkdtemp(prefix="icsfb-pcap-"))
    pcap = tmp / "mixed.pcap"
    blk = DCPNameOfStationBlock(name_of_station=PN_FLAG.encode())
    dcp = ProfinetDCP(service_id=5, service_type=1, xid=0x0101,
                      dcp_data_length=len(raw(blk)), dcp_blocks=[blk])
    eth_pn = Ether(src="00:11:22:33:44:55", dst="01:0e:cf:00:00:00", type=0x8892) \
        / ProfinetIO(frameID=dcpmod.DCP_IDENTIFY_RESPONSE_FRAME_ID) / dcp
    whois = _bvlc(bytes([0x01, 0x00]) + bytes([0x10, 0x08]), func=0x0B)
    eth_bac = Ether() / IP(src="10.0.0.9", dst="10.0.0.255") / UDP(sport=47808, dport=47808) / whois
    cip = bytes([0x8E, 0x00, 0x00, 0x00]) + b"flag{enip_in_pcap}"
    eth_enip = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5000, dport=44818) / _enip(cip)
    wrpcap(str(pcap), [eth_pn, eth_bac, eth_enip])
    res = F.analyze_file(str(pcap))
    protos = {r.get("protocol") for r in res["reports"]}
    check("pcap: all three protocols decoded",
          {"profinet", "bacnet-ip", "ethernet-ip"} <= protos, protos)
    allflags = F._all_flags(res)
    check("pcap: profinet flag found", PN_FLAG in allflags, allflags)
    check("pcap: enip flag found", "flag{enip_in_pcap}" in allflags, allflags)


def test_cli():
    tmp = Path(tempfile.mkdtemp(prefix="icsfb-cli-"))
    raw_bacnet = tmp / "rp_ack.bin"
    apdu = (bytes([0x30, 0x01, 0x0C]) + _ctx(0, _objid_bytes(8, 1)) + _ctx(1, bytes([77]))
            + _ctx_open(3) + _app_charstring(RP_FLAG) + _ctx_close(3))
    raw_bacnet.write_bytes(_bvlc(bytes([0x01, 0x00]) + apdu))   # NPDU v1 ctrl 0, then APDU
    r = subprocess.run([PY, MOD, str(raw_bacnet)], capture_output=True, text=True, timeout=120)
    check("cli: exit 0", r.returncode == 0, r.stderr[-300:])
    check("cli: flag highlighted", "CSCTF FLAG FORMAT MATCH" in r.stdout and RP_FLAG in r.stdout,
          r.stdout[-400:])
    check("cli: readable service line", "readProperty" in r.stdout, r.stdout[-400:])

    rj = subprocess.run([PY, MOD, str(raw_bacnet), "--json"], capture_output=True, text=True, timeout=120)
    check("cli json: exit 0", rj.returncode == 0, rj.stderr[-300:])
    try:
        parsed = json.loads(rj.stdout)
        ok = isinstance(parsed, list) and RP_FLAG in json.dumps(parsed)
    except Exception as e:                                  # noqa: BLE001
        ok = False
        parsed = str(e)
    check("cli json: valid JSON containing the flag", ok, str(parsed)[:300])

    # --proto override on a raw payload.
    rp = subprocess.run([PY, MOD, str(raw_bacnet), "--proto", "bacnet"],
                        capture_output=True, text=True, timeout=120)
    check("cli proto: override works", rp.returncode == 0 and "bacnet-ip" in rp.stdout, rp.stdout[-200:])


def test_degrade_without_scapy():
    """Force scapy absent: Profinet/OPC-DA report an error (no crash); BACnet/ENIP still work."""
    orig = F._SCAPY
    try:
        F._SCAPY = {}                                       # _load_scapy() now returns None
        rp = F.profinet_report(payload=b"\xfe\xff\x05\x01")
        check("degrade: profinet error mentions scapy", "scapy" in str(rp.get("error", "")).lower(), rp)
        ro = F.opcda_report(payload=b"\x05\x00\x00\x00")
        check("degrade: opc-da error mentions scapy", "scapy" in str(ro.get("error", "")).lower(), ro)
        # BACnet is custom -> still fully works.
        apdu = bytes([0x10, 0x00]) + _app_objid(8, 5)
        rb = F.bacnet_report(_bvlc(bytes([0x01, 0x00]) + apdu, func=0x0B))
        check("degrade: bacnet still works", rb["apdu"]["service_choice"] == "i-Am", rb.get("apdu"))
        # ENIP framing is stdlib -> still works (scapy cross-check is simply skipped).
        cip = bytes([0x0E, 0x02, 0x20, 0x01, 0x24, 0x01])
        re = F.parse_enip(_enip(cip))
        check("degrade: enip still works",
              re["items"][1]["cip"]["service"] == "Get_Attribute_Single", re.get("items"))
    finally:
        F._SCAPY = orig


# ====================================================================================== runner

def main():
    tests = [
        test_bacnet_readproperty_ack, test_bacnet_readproperty_request, test_bacnet_writeproperty_flag,
        test_bacnet_whois_iam, test_bacnet_forwarded_npdu, test_bacnet_npdu_routing,
        test_bacnet_signed_and_double, test_bacnet_tag_primitives,
        test_bacnet_extended_tag_and_length, test_bacnet_adversarial,
        test_enip_cip_request, test_enip_cip_response_flag, test_enip_logix_symbolic,
        test_cip_16_and_32_bit_segments, test_cip_multiple_service_packet,
        test_enip_connected_item_sequence, test_enip_listidentity_and_register, test_enip_detect,
        test_enip_scapy_crosscheck,
        test_profinet_dcp_identify, test_profinet_dcp_set_request, test_profinet_dce_rpc,
        test_opcda_request, test_opcda_bind,
        test_pcap_mixed, test_cli, test_degrade_without_scapy,
    ]
    failures = []
    for t in tests:
        try:
            t()
        except AssertionError as e:
            failures.append(f"{t.__name__}: {e}")
        except Exception as e:                              # noqa: BLE001
            failures.append(f"{t.__name__}: UNEXPECTED {type(e).__name__}: {e}")
    if failures:
        print("\n" + f"{len(failures)} FAILED:")
        for f in failures:
            print("  - " + f)
        return 1
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
