#!/usr/bin/env python3
"""Synthetic, spec-derived tests for the telecom signalling engine (solvers/toolkits/telecom.py).

  CTF_WORKDIR=/tmp/ctfws .venv/bin/python tests/test_telecom.py

Everything here is built from the specs with known field values and read back:
  * GTP-C / GTP-U and Diameter packets are built with scapy and cross-checked against scapy's own
    dissector, then asserted field-by-field through telecom.parse_gtp / parse_diameter.
  * M3UA (RFC 4666) + SCCP (Q.713) + TCAP/MAP bytes are hand-assembled from the spec (independent
    TBCD and TLV encoders) and read back by the pure-stdlib custom path -- which must work with scapy
    monkeypatched OFF, proving it degrades gracefully.
  * A synthetic pcap carrying all three is read end to end by scan_pcap.

No real IMSIs/MSISDNs, no real flags: the flag strings are obvious synthetic markers.
"""
import os
import struct
import sys
import tempfile
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt, paths
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[1]))
    from ctf import flagfmt, paths

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import telecom as T  # noqa: E402

try:
    from scapy.contrib import gtp, gtp_v2, diameter  # noqa: E402
    from scapy.all import IP, UDP, TCP, SCTP, Raw, wrpcap  # noqa: E402
    from scapy.layers.sctp import SCTPChunkData  # noqa: E402
    HAVE_SCAPY = True
except Exception:  # noqa: BLE001
    HAVE_SCAPY = False


# ---- independent spec encoders (so the test does not depend on the code under test) --------------

def enc_tbcd(digits: str) -> bytes:
    """Pack decimal digits as TBCD: low nibble first, 0xF filler for an odd count."""
    out = bytearray()
    ds = [int(c) for c in digits]
    for i in range(0, len(ds), 2):
        lo = ds[i]
        hi = ds[i + 1] if i + 1 < len(ds) else 0x0F
        out.append((hi << 4) | lo)
    return bytes(out)


def tlv(tag: int, value: bytes) -> bytes:
    """A short-form BER TLV (lengths here are all < 128)."""
    assert len(value) < 128
    return bytes([tag, len(value)]) + value


# ---- GTP (scapy-built, cross-checked) ------------------------------------------------------------

def t_gtp_v1_control_ies():
    pkt = gtp.GTPHeader(gtp_type=16, teid=0x11223344) / gtp.GTPCreatePDPContextRequest(IE_list=[
        gtp.IE_IMSI(imsi="208930000000001"),
        gtp.IE_MSInternationalNumber(length=7, digits="33600000001"),
        gtp.IE_AccessPointName(APN="internet.apn"),
    ])
    raw = bytes(pkt)
    # cross-check against scapy's own dissector
    rp = gtp.GTPHeader(raw)
    assert int(rp.gtp_type) == 16 and int(rp.teid) == 0x11223344
    rec = T.parse_gtp(raw)
    assert rec and rec["version"] == 1 and rec["kind"] == "control"
    assert rec["gtp_type"] == 16 and rec["type_name"] == "create_pdp_context_req", rec["type_name"]
    assert rec["teid"] == 0x11223344
    names = {ie["name"]: ie["fields"] for ie in rec["ies"]}
    assert "IMSI" in names and names["IMSI"]["imsi"] == "208930000000001", names
    assert names["MSInternationalNumber"]["digits"] == "33600000001", names
    assert names["AccessPointName"]["APN"] == "internet.apn", names


def t_gtp_u_inner_payload_and_flag():
    flag = "csctf{gtpu_inner_payload}"
    pkt = gtp.GTP_U_Header(gtp_type=255, teid=0xDEADBEEF) / IP(src="10.0.0.1", dst="10.0.0.2") / \
        UDP(sport=4000, dport=5000) / Raw(load=flag.encode())
    raw = bytes(pkt)
    rec = T.parse_gtp(raw)
    assert rec and rec["kind"] == "user" and rec["gtp_type"] == 255, rec
    assert rec["teid"] == 0xDEADBEEF
    assert rec["inner"] and rec["inner"]["src"] == "10.0.0.1" and rec["inner"]["dst"] == "10.0.0.2"
    assert flag in rec["inner"]["flags"], rec["inner"]
    assert flag in rec["flags"], rec["flags"]


def t_gtp_v2_create_session_imsi():
    pkt = gtp_v2.GTPHeader(gtp_type=32, teid=0x01020304) / gtp_v2.GTPV2CreateSessionRequest(
        IE_list=[gtp_v2.IE_IMSI(IMSI="208930000000001"),
                 gtp_v2.IE_MSISDN(length=6, digits="33600000001")])
    raw = bytes(pkt)
    rp = gtp_v2.GTPHeader(raw)
    assert int(rp.gtp_type) == 32 and int(rp.teid) == 0x01020304
    rec = T.parse_gtp(raw)
    assert rec and rec["version"] == 2 and rec["gtp_type"] == 32, rec
    assert rec["type_name"] == "create_session_req", rec["type_name"]
    assert rec["teid"] == 0x01020304
    names = {ie["name"]: ie["fields"] for ie in rec["ies"]}
    assert names.get("IMSI", {}).get("IMSI") == "208930000000001", names


# ---- Diameter (scapy-built, cross-checked) -------------------------------------------------------

def t_diameter_s6a_ulr_avps_and_flag():
    flag = "csctf{diameter_origin_host}"
    msg = diameter.DiamG(drCode=316, drAppId=16777251, drFlags=0xC0,
                         drHbHId=0x11111111, drEtEId=0x22222222, avpList=[
                             diameter.AVP(264, val=("mme." + flag).encode()),
                             diameter.AVP(296, val=b"epc.mnc093.mcc208.3gppnetwork.org"),
                             diameter.AVP(1, val=b"208930000000001"),
                             diameter.AVP(258, val=16777251),
                         ])
    raw = bytes(msg)
    rp = diameter.DiamG(raw)
    assert int(rp.drCode) == 316 and int(rp.drAppId) == 16777251
    rec = T.parse_diameter(raw)
    assert rec and rec["command_code"] == 316, rec
    assert rec["is_request"] is True and rec["flags"]["R"] is True
    assert "Update-Location-Request" in rec["command_name"] and "(ULR)" in rec["command_name"], \
        rec["command_name"]
    assert rec["application_id"] == 16777251 and rec["application_name"] == "3GPP-S6a/S6d", rec
    assert rec["hop_by_hop"] == 0x11111111 and rec["end_to_end"] == 0x22222222
    byname = {a["name"]: a for a in rec["avps"]}
    assert "Origin-Host" in byname and byname["Origin-Host"]["value"] == "mme." + flag, byname
    assert "User-Name" in byname and byname["User-Name"]["value"] == "208930000000001", byname
    assert byname["Auth-Application-Id"]["value"] == 16777251, byname
    assert flag in rec["flag_hits"], rec["flag_hits"]


def t_diameter_answer_vs_request():
    msg = diameter.DiamG(drCode=316, drAppId=16777251, drFlags=0x00,
                         avpList=[diameter.AVP(268, val=2001)])  # Result-Code, no R bit = Answer
    rec = T.parse_diameter(bytes(msg))
    assert rec["is_request"] is False
    assert "Update-Location-Answer" in rec["command_name"] and "(ULA)" in rec["command_name"], rec
    byname = {a["name"]: a for a in rec["avps"]}
    assert byname.get("Result-Code", {}).get("value") == 2001, byname


def t_diameter_grouped_and_vendor_avps():
    """A grouped AVP must be WALKED into its children (not stringified), and a vendor-specific AVP
    (V flag set + Vendor-Id present, padded to 4 bytes) must be decoded with its vendor + flag."""
    flag = "csctf{grouped_nested_avp}"
    grp = diameter.AVP(260, val=[diameter.AVP(266, val=10415),         # Vendor-Specific-Application-Id
                                 diameter.AVP(258, val=16777251)])     #  { Vendor-Id, Auth-App-Id }
    vend = diameter.AVP(1407, avpFlags=0xC0, avpVnd=10415,             # Visited-PLMN-Id, V+M flags
                        val=("plmn." + flag).encode())
    msg = diameter.DiamG(drCode=318, drAppId=16777251, drFlags=0x80,
                         avpList=[grp, vend, diameter.AVP(264, val=b"hss.example.org")])
    raw = bytes(msg)
    # byte-level cross-check: the vendor AVP carries flags byte 0xC0 and vendor-id 10415 (0x000028af)
    assert b"\x00\x00\x05\x7f\xc0" in raw and b"\x00\x00\x28\xaf" in raw, raw.hex()
    rp = diameter.DiamG(raw)                                           # scapy re-dissect cross-check
    assert int(rp.drCode) == 318 and len(rp.avpList) == 3, rp.avpList
    rec = T.parse_diameter(raw)
    byname = {a["name"]: a for a in rec["avps"]}
    g = byname["Vendor-Specific-Application-Id"]
    assert g["grouped"], g                                             # walked, not None
    assert g["value"] is None, g                                       # not the list-of-packets blob
    nested = {x["name"]: x["value"] for x in g["grouped"]}
    assert nested.get("Vendor-Id") == 10415, nested
    assert nested.get("Auth-Application-Id") == 16777251, nested
    v = byname["Visited-PLMN-Id"]
    assert v["flags"]["V"] is True and v["flags"]["M"] is True, v
    assert v["vendor"] == 10415, v
    assert v["value"] == "plmn." + flag, v
    assert flag in rec["flag_hits"], rec["flag_hits"]


# ---- M3UA + SCCP + TCAP/MAP (hand-built from the spec; pure-stdlib path) --------------------------

def build_sccp_gt4(digits: str) -> bytes:
    # Global Title indicator 4: TT, NP/ES, NAI, then TBCD digits
    tt = 0x00
    np_es = (0x01 << 4) | 0x01            # NP=1 (E.164), ES=1 (BCD, odd)
    nai = 0x04                            # international number
    return bytes([tt, np_es, nai]) + enc_tbcd(digits)


def build_sccp_address(pc: int, ssn: int, gt4_digits: str, route_on_ssn: bool) -> bytes:
    ai = 0x01 | 0x02 | (0x04 << 2)        # PC present + SSN present + GTI=4
    if route_on_ssn:
        ai |= 0x40
    body = bytearray([ai])
    body += struct.pack("<H", pc & 0x3FFF)  # ITU 14-bit PC, little-endian
    body.append(ssn)
    body += build_sccp_gt4(gt4_digits)
    return bytes(body)


def build_tcap_begin_map(flag: str) -> bytes:
    otid = tlv(0x48, b"\x11\x22\x33\x44")
    ac_oid = tlv(0x06, b"\x04\x00\x00\x01\x00\x01\x03")        # MAP networkLocUp AC (0.4.0.0.1.0.1.3)
    dialogue = tlv(0x6B, tlv(0x28, ac_oid))                     # dialoguePortion -> EXTERNAL -> OID
    invoke = tlv(0xA1, tlv(0x02, b"\x01")                       # invokeID = 1
                 + tlv(0x02, b"\x02")                           # operationCode = 2 (updateLocation)
                 + tlv(0x04, flag.encode()))                    # parameter carrying a flag marker
    components = tlv(0x6C, invoke)
    return tlv(0x62, otid + dialogue + components)              # Begin


def build_sccp_udt(cdpa: bytes, cgpa: bytes, data: bytes) -> bytes:
    # UDT: type(09) class(00) ptrCdPA ptrCgPA ptrData, then the three length-prefixed variable parts
    fixed = bytes([0x09, 0x00])
    # three one-octet pointers follow; variable parts start right after them
    var_cdpa = bytes([len(cdpa)]) + cdpa
    var_cgpa = bytes([len(cgpa)]) + cgpa
    var_data = bytes([len(data)]) + data
    p1 = 3                                  # from the CdPA pointer (offset 2) to var part (offset 5)
    p2 = 2 + len(var_cdpa)                  # from the CgPA pointer (offset 3)
    p3 = 1 + len(var_cdpa) + len(var_cgpa)  # from the Data pointer (offset 4)
    return fixed + bytes([p1, p2, p3]) + var_cdpa + var_cgpa + var_data


def build_m3ua_data(opc: int, dpc: int, si: int, user: bytes) -> bytes:
    pd = struct.pack(">II", opc, dpc) + bytes([si, 0x02, 0x00, 0x00]) + user  # OPC,DPC,SI,NI,MP,SLS
    pad = (-len(pd)) % 4
    param = struct.pack(">HH", 0x0210, 4 + len(pd)) + pd + b"\x00" * pad
    body = param
    total = 8 + len(body)
    return bytes([0x01, 0x00, 0x01, 0x01]) + struct.pack(">I", total) + body


FLAG_SS7 = "csctf{ss7_map_sms}"


def _build_full_m3ua():
    cdpa = build_sccp_address(pc=1234, ssn=6, gt4_digits="12345", route_on_ssn=True)   # HLR
    cgpa = build_sccp_address(pc=5678, ssn=8, gt4_digits="67890", route_on_ssn=False)  # MSC
    tcap = build_tcap_begin_map(FLAG_SS7)
    sccp = build_sccp_udt(cdpa, cgpa, tcap)
    return build_m3ua_data(opc=1234, dpc=5678, si=3, user=sccp), cdpa, cgpa


def t_tbcd_roundtrip():
    for digits in ("12345", "67890", "0", "1234567890", "208930000000001"):
        assert T._tbcd(enc_tbcd(digits)) == digits, digits


def t_sccp_address_decode():
    addr = build_sccp_address(pc=1234, ssn=6, gt4_digits="12345", route_on_ssn=True)
    a = T.parse_sccp_address(addr)
    assert a["point_code"] == 1234, a
    assert a["ssn"] == 6 and a["ssn_name"] == "HLR", a
    assert a["routing"] == "SSN/PC", a
    assert a["gt_digits"] == "12345", a
    assert a["global_title"]["numbering_plan"] == "ISDN/telephony(E.164)", a["global_title"]
    assert a["global_title"]["nature_of_address"] == "international", a["global_title"]


def build_sccp_ludt(cdpa: bytes, cgpa: bytes, data: bytes) -> bytes:
    """LUDT (Q.713 4.18): type(0x13) class hop, then four 2-octet LITTLE-endian pointers
    (CdPA, CgPA, Long data, Optional), then the length-prefixed variable parts (2-octet LE lengths).
    A pointer counts octets from its own first octet to the parameter's length indicator."""
    fixed = bytes([0x13, 0x01, 0x0F])            # LUDT, protocol class 1, hop counter 15
    vc = struct.pack("<H", len(cdpa)) + cdpa
    vg = struct.pack("<H", len(cgpa)) + cgpa
    vd = struct.pack("<H", len(data)) + data
    var_start = 3 + 8                            # fixed(3) + four 2-octet pointers(8)
    p_cdpa = var_start - 3
    p_cgpa = (var_start + len(vc)) - 5
    p_data = (var_start + len(vc) + len(vg)) - 7
    return fixed + struct.pack("<HHHH", p_cdpa, p_cgpa, p_data, 0) + vc + vg + vd


def t_sccp_ludt_decode():
    """LUDT/LUDTS use 2-octet little-endian pointers and length indicators (not big-endian). A long
    (>255 byte) data part forces LUDT; the addresses and the oversized data must still decode."""
    cdpa = build_sccp_address(pc=1234, ssn=6, gt4_digits="12345", route_on_ssn=True)
    cgpa = build_sccp_address(pc=5678, ssn=8, gt4_digits="67890", route_on_ssn=False)
    data = b"LONGDATA-" + b"Z" * 300             # 309 bytes -> cannot be a plain UDT
    assert len(data) > 255
    msg = build_sccp_ludt(cdpa, cgpa, data)
    rec = T.parse_sccp(msg)
    assert rec and rec["type_name"] == "LUDT", rec
    assert rec["hop_counter"] == 0x0F, rec
    assert rec["called_party"]["gt_digits"] == "12345", rec["called_party"]
    assert rec["called_party"]["ssn_name"] == "HLR", rec["called_party"]
    assert rec["calling_party"]["gt_digits"] == "67890", rec["calling_party"]
    assert rec["data"] and rec["data"]["len"] == len(data), rec["data"]


def t_m3ua_sccp_tcap_map_chain():
    m3ua, _, _ = _build_full_m3ua()
    rec = T.parse_m3ua(m3ua)
    assert rec and rec["protocol"] == "M3UA", rec
    assert rec["class_name"] == "Transfer" and rec["type_name"] == "DATA", rec
    pd = rec["protocol_data"]
    assert pd and pd["opc"] == 1234 and pd["dpc"] == 5678, pd
    assert pd["service_indicator"] == 3 and pd["si_name"] == "SCCP", pd
    assert pd["opc_itu"] == T._pc_itu(1234), pd
    sccp = rec["sccp"]
    assert sccp and sccp["type_name"] == "UDT", sccp
    assert sccp["called_party"]["ssn_name"] == "HLR", sccp["called_party"]
    assert sccp["calling_party"]["ssn_name"] == "MSC", sccp["calling_party"]
    assert sccp["called_party"]["gt_digits"] == "12345", sccp["called_party"]
    tcap = sccp["tcap"]
    assert tcap and tcap["present"] and tcap["message_type"] == "Begin", tcap
    assert tcap["map"] is True, tcap
    assert tcap["application_context"] == "0.4.0.0.1.0.1.3", tcap["application_context"]
    comps = tcap["components"]
    assert comps and comps[0]["type"] == "Invoke", comps
    assert comps[0]["opcode"] == 2 and comps[0]["operation"] == "updateLocation", comps
    assert FLAG_SS7 in (sccp.get("flag_hits") or []), sccp.get("flag_hits")


def t_m3ua_param_names():
    """M3UA management-message parameter tags are named per RFC 4666 (the whole table, not just the
    DATA/Protocol-Data path). Guards the parameter-id map against the earlier mislabelling."""
    def param(tag, val):
        pad = (-len(val)) % 4
        return struct.pack(">HH", tag, 4 + len(val)) + val + b"\x00" * pad
    body = (param(0x0011, struct.pack(">I", 0x12345678))      # ASP Identifier
            + param(0x000B, struct.pack(">I", 2))             # Traffic Mode Type (loadshare)
            + param(0x0004, b"node-A!!")                      # INFO String
            + param(0x0006, struct.pack(">I", 7)))            # Routing Context
    msg = bytes([0x01, 0x00, 0x03, 0x01]) + struct.pack(">I", 8 + len(body)) + body  # ASPSM / ASPUP
    rec = T.parse_m3ua(msg)
    assert rec and rec["class_name"] == "ASPSM" and rec["type_name"] == "ASPUP", rec
    names = {p["tag"]: p["name"] for p in rec["params"]}
    assert names["0x0011"] == "ASP Identifier", names
    assert names["0x000b"] == "Traffic Mode Type", names
    assert names["0x0004"] == "INFO String", names
    assert names["0x0006"] == "Routing Context", names


def t_ss7_path_without_scapy():
    """The SS7/M3UA/SCCP/TCAP path must not depend on scapy (graceful degradation)."""
    saved = T.HAVE_SCAPY
    try:
        T.HAVE_SCAPY = False
        m3ua, _, _ = _build_full_m3ua()
        rec = T.parse_m3ua(m3ua)
        assert rec and rec["sccp"]["tcap"]["map"] is True, rec
        # and the scapy-only paths fail closed rather than raising
        assert T.parse_gtp(b"\x30\x10\x00\x08\x00\x00\x00\x00") is None
        assert T.parse_diameter(b"\x01\x00\x00\x14" + b"\x00" * 16) is None
    finally:
        T.HAVE_SCAPY = saved


def t_tcap_standalone_detect():
    tcap = build_tcap_begin_map(FLAG_SS7)
    d = T.detect_tcap(tcap)
    assert d and d["message_type"] == "Begin" and d["map"] is True, d
    # a non-TCAP first byte is rejected
    assert T.detect_tcap(b"\x09\x00\x00") is None


def t_sniff_raw_dispatch():
    m3ua, _, _ = _build_full_m3ua()
    assert T.sniff_raw(m3ua)["protocol"] == "M3UA"
    if HAVE_SCAPY:
        g = bytes(gtp.GTPHeader(gtp_type=1, teid=1) / gtp.GTPEchoRequest())
        assert T.sniff_raw(g)["protocol"] == "GTP"
        dm = bytes(diameter.DiamG(drCode=280, drAppId=0, drFlags=0x80))
        assert T.sniff_raw(dm)["protocol"] == "Diameter"


# ---- pcap end to end -----------------------------------------------------------------------------

def t_pcap_scan_all_three():
    if not HAVE_SCAPY:
        return
    flag_u = "csctf{pcap_gtpu}"
    gtpc = IP(src="1.1.1.1", dst="1.1.1.2") / UDP(sport=2123, dport=2123) / \
        gtp.GTPHeader(gtp_type=16, teid=0x55) / gtp.GTPCreatePDPContextRequest(
            IE_list=[gtp.IE_IMSI(imsi="208930000000001")])
    gtpu = IP(src="2.2.2.1", dst="2.2.2.2") / UDP(sport=2152, dport=2152) / \
        gtp.GTP_U_Header(gtp_type=255, teid=0x66) / IP(src="10.0.0.1", dst="10.0.0.2") / \
        UDP() / Raw(load=flag_u.encode())
    m3ua, _, _ = _build_full_m3ua()
    sctp = IP(src="3.3.3.1", dst="3.3.3.2") / SCTP(sport=2905, dport=2905) / \
        SCTPChunkData(proto_id=3, data=m3ua)
    diam = diameter.DiamG(drCode=318, drAppId=16777251, drFlags=0x80,
                          avpList=[diameter.AVP(264, val=b"hss.example.org")])
    tcp = IP(src="4.4.4.1", dst="4.4.4.2") / TCP(sport=3868, dport=3868) / Raw(load=bytes(diam))

    workdir = paths.ensure_workdir()
    pcap_path = str(Path(workdir) / "telecom_test_synth.pcap")
    wrpcap(pcap_path, [gtpc, gtpu, sctp, tcp])

    res = T.report(pcap_path)
    assert res["kind"] == "pcap", res
    protos = [r["record"]["protocol"] for r in res["records"]]
    assert "GTP" in protos, protos
    assert "M3UA" in protos, protos
    assert "Diameter" in protos, protos
    # GTP-U inner flag and SS7 MAP flag both surface in the capture-wide flag list
    assert flag_u in res["flags"], res["flags"]
    assert FLAG_SS7 in res["flags"], res["flags"]
    # the Diameter AIR command is named
    diam_recs = [r["record"] for r in res["records"] if r["record"]["protocol"] == "Diameter"]
    assert any("Authentication-Information-Request" in d["command_name"] for d in diam_recs), diam_recs


def t_raw_flag_backstop():
    """A flag sitting in bytes that do not parse as any protocol is still surfaced."""
    workdir = paths.ensure_workdir()
    p = str(Path(workdir) / "telecom_test_clear.bin")
    Path(p).write_bytes(b"\xff\x00 noise csctf{unparsed_but_present} noise \x00")
    res = T.report(p)
    assert "csctf{unparsed_but_present}" in res["flags"], res["flags"]


def t_flag_regex_matches_spec():
    assert T.FLAG_RE.pattern == flagfmt.current().pattern      # the event's format, not a local regex
    assert T._flags_in(b"noise csctf{abc} trail") == ["csctf{abc}"]
    assert T._flags_in(b"chronos{x} CHRONOS{y}") == ["chronos{x}", "CHRONOS{y}"]


# ---- scapy-gated vs. always-on registry ----------------------------------------------------------

SCAPY_TESTS = [
    t_gtp_v1_control_ies, t_gtp_u_inner_payload_and_flag, t_gtp_v2_create_session_imsi,
    t_diameter_s6a_ulr_avps_and_flag, t_diameter_answer_vs_request,
    t_diameter_grouped_and_vendor_avps, t_pcap_scan_all_three,
]
ALWAYS_TESTS = [
    t_tbcd_roundtrip, t_sccp_address_decode, t_sccp_ludt_decode, t_m3ua_sccp_tcap_map_chain,
    t_m3ua_param_names, t_ss7_path_without_scapy, t_tcap_standalone_detect, t_sniff_raw_dispatch,
    t_raw_flag_backstop, t_flag_regex_matches_spec,
]


def main():
    tests = list(ALWAYS_TESTS)
    if HAVE_SCAPY:
        tests = SCAPY_TESTS + tests
    else:
        print("note: scapy not importable; running the SS7/M3UA/SCCP/TCAP custom path only")
    failed = 0
    for test in tests:
        try:
            test()
        except AssertionError as e:
            failed += 1
            import traceback
            where = traceback.extract_tb(e.__traceback__)[-1]
            print("FAIL  %s: line %s: %s" % (test.__name__[2:], where.lineno, str(e)[:900]))
        except Exception as e:  # noqa: BLE001
            failed += 1
            import traceback
            where = traceback.extract_tb(e.__traceback__)[-1]
            print("FAIL  %s: raised %s: %s (%s:%s)" % (
                test.__name__[2:], type(e).__name__, e, Path(where.filename).name, where.lineno))
        else:
            print("pass  %s" % test.__name__[2:])
    print("ok" if not failed else "%d check(s) failed" % failed)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
