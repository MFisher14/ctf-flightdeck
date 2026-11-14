#!/usr/bin/env python3
"""Synthetic, spec-derived regression test for solvers/toolkits/financial.py.

  CTF_WORKDIR=/tmp/ctfws .venv/bin/python tests/test_financial.py

Every input here is built from the published grammar with KNOWN field values and an INDEPENDENT
encoder (the bitmap math and the BER TLV encoder below are written separately from the parser), so
a pass proves the parser reads back exactly what the spec says. No scapy dissector exists for
ISO 8583 / EMV / SWIFT, so the cross-check against scapy is on the pcap TRANSPORT: the pcap is
written by scapy's own writer and read back by the engine's loader. Nothing here is a real card,
account, or flag — PAN 4111111111111111 is the universal Visa test number; the flags are obvious
placeholders.
"""
import contextlib
import io
import os
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import financial as F   # noqa: E402


# ---------------------------------------------------------------- independent (spec) encoders

def ref_bitmap(fields):
    """The ISO 8583 bitmap bytes for a set of present data elements, by the spec bit convention
    (field N -> bit N, field 1 = secondary-bitmap indicator). Written independently of the parser."""
    fields = set(fields)
    secondary = any(f > 64 for f in fields)
    bits = set(fields)
    if secondary:
        bits.add(1)
    ba = bytearray(16 if secondary else 8)
    for f in bits:
        if 1 <= f <= 128:
            ba[(f - 1) // 8] |= 0x80 >> ((f - 1) % 8)
    return bytes(ba)


def enc_n(digits):
    """BCD-pack a numeric string (left-pad a leading nibble when odd-length)."""
    if len(digits) % 2:
        digits = "0" + digits
    return bytes.fromhex(digits)


def ber_tlv(tag_hex, value):
    """A BER-TLV element (EMV): tag bytes + BER length + value. Independent of the parser."""
    t = bytes.fromhex(tag_hex)
    n = len(value)
    if n < 0x80:
        length = bytes([n])
    else:
        lb = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(lb)]) + lb
    return t + length + value


# ---------------------------------------------------------------- ISO 8583

def t_iso_ascii_basic():
    flag = "CTF{iso_ascii_test}"
    de48 = "%03d%s" % (len(flag), flag)
    msg = ("0200" + ref_bitmap([3, 4, 11, 41, 48]).hex().upper()
           + "123456" + "000000150000" + "000042" + "TERM0001" + de48).encode()
    r = F.parse_iso8583(msg, encoding="ascii")
    assert r is not None
    assert r["mti"]["raw"] == "0200"
    assert r["mti"]["version"] == "ISO 8583:1987"
    assert r["mti"]["class"] == "Financial"
    assert r["mti"]["function"] == "Request"
    assert r["mti"]["origin"] == "Acquirer"
    assert r["present_fields"] == [3, 4, 11, 41, 48], r["present_fields"]
    vals = {f["de"]: f["value"] for f in r["fields"]}
    assert vals[3] == "123456"
    assert vals[4] == "000000150000"
    assert vals[11] == "000042"
    assert vals[41] == "TERM0001"
    assert vals[48] == flag
    assert r["flags"] == [flag], r["flags"]
    assert r["trailing_hex"] == ""


def t_iso_bitmap_render_matches_spec():
    want = ref_bitmap([3, 4, 11, 41, 48]).hex().upper()
    msg = ("0200" + want + "123456" + "000000150000" + "000042" + "TERM0001" + "003ABC").encode()
    r = F.parse_iso8583(msg, encoding="ascii")
    assert r["bitmaps"][0] == want, (r["bitmaps"], want)
    assert r["has_secondary_bitmap"] is False


def t_iso_packed_secondary_bitmap():
    # fully packed (BCD) network-management message, present DE 7,11,39,70 (70 forces a secondary bitmap)
    body = (enc_n("1103120000")            # DE7  n10 transmission date/time
            + enc_n("000099")              # DE11 n6  STAN
            + b"00"                        # DE39 an2 response code
            + enc_n("301"))                # DE70 n3  network mgmt info code
    msg = bytes.fromhex("0810") + ref_bitmap([7, 11, 39, 70]) + body
    r = F.parse_iso8583(msg, encoding="packed")
    assert r is not None
    assert r["mti"]["raw"] == "0810"
    assert r["mti"]["class"] == "Network management"
    assert r["has_secondary_bitmap"] is True
    assert r["present_fields"] == [7, 11, 39, 70], r["present_fields"]
    vals = {f["de"]: f["value"] for f in r["fields"]}
    assert vals[7] == "1103120000", vals[7]
    assert vals[11] == "000099", vals[11]
    assert vals[39] == "00", vals[39]
    assert vals[70] == "301", vals[70]
    assert r["trailing_hex"] == ""


def t_iso_llvar_lllvar_and_luhn():
    # DE2 PAN (LLVAR, ASCII) + DE48 (LLLVAR). PAN 4111111111111111 is the Visa test number.
    pan = "4111111111111111"
    de2 = "%02d%s" % (len(pan), pan)
    de48 = "003XYZ"
    msg = ("0200" + ref_bitmap([2, 48]).hex().upper() + de2 + de48).encode()
    r = F.parse_iso8583(msg, encoding="ascii")
    f2 = next(f for f in r["fields"] if f["de"] == 2)
    assert f2["value"] == pan
    assert f2["declared_len"] == 16
    assert f2["lentype"] == "LLVAR"
    assert "Luhn valid" in (f2.get("note") or ""), f2.get("note")
    f48 = next(f for f in r["fields"] if f["de"] == 48)
    assert f48["value"] == "XYZ"
    assert f48["declared_len"] == 3
    assert f48["lentype"] == "LLLVAR"


def t_iso_track2_field_parsed():
    track = "4111111111111111=25122010000000000"
    de35 = "%02d%s" % (len(track), track)
    msg = ("0200" + ref_bitmap([35]).hex().upper() + de35).encode()
    r = F.parse_iso8583(msg, encoding="ascii")
    f35 = next(f for f in r["fields"] if f["de"] == 35)
    assert f35["value"] == track
    note = f35.get("note") or ""
    assert "PAN=4111111111111111" in note and "expiry(YYMM)=2512" in note, note


def t_iso_auto_detects_encoding():
    ascii_msg = ("0200" + ref_bitmap([3, 11]).hex().upper() + "123456" + "000001").encode()
    r1 = F.parse_iso8583(ascii_msg)
    assert r1["encoding"]["bitmap"] == "hex" and r1["encoding"]["field"] == "ascii"
    assert r1["present_fields"] == [3, 11]

    packed = bytes.fromhex("0810") + ref_bitmap([7, 11, 39, 70]) \
        + enc_n("1103120000") + enc_n("000099") + b"00" + enc_n("301")
    r2 = F.parse_iso8583(packed)
    assert r2["encoding"]["mti"] == "bcd" and r2["encoding"]["field"] == "bcd", r2["encoding"]
    assert r2["present_fields"] == [7, 11, 39, 70]


def t_iso_binary_bitmap_ascii_fields():
    # ASCII MTI + raw binary bitmap + ASCII field values (a very common on-wire mix)
    msg = b"0200" + ref_bitmap([3, 11]) + b"123456" + b"000001"
    r = F.parse_iso8583(msg, encoding="bin-bitmap")
    assert r is not None
    assert r["encoding"]["bitmap"] == "binary"
    assert r["present_fields"] == [3, 11]
    assert {f["de"]: f["value"] for f in r["fields"]} == {3: "123456", 11: "000001"}


def t_iso_mli_strip():
    core = ("0200" + ref_bitmap([3]).hex().upper() + "123456").encode()
    framed = len(core).to_bytes(2, "big") + core
    r = F.parse_iso8583(framed, encoding="ascii", strip_mli=True)
    assert r is not None and r["present_fields"] == [3]
    # auto mode also recovers it (it tries the stripped buffer)
    r2 = F.parse_iso8583(framed)
    assert r2 is not None and r2["present_fields"] == [3], r2 and r2["present_fields"]


def t_iso_spec_1987_vs_1993_de72():
    # DE72 is a fixed n4 in 1987 but an LLLVAR 'Data record' in 1993.
    msg = ("0200" + ref_bitmap([3, 72]).hex().upper() + "123456" + "005HELLO").encode()
    r93 = F.parse_iso8583(msg, encoding="ascii", spec="1993")
    f72 = next(f for f in r93["fields"] if f["de"] == 72)
    assert f72["lentype"] == "LLLVAR" and f72["value"] == "HELLO", f72
    assert f72["name"] == "Data record"
    r87 = F.parse_iso8583(msg, encoding="ascii", spec="1987")
    g72 = next(f for f in r87["fields"] if f["de"] == 72)
    assert g72["lentype"] == "FIXED" and g72["value"] == "005H", g72   # reads 4 fixed chars
    assert r87["trailing_hex"] == b"ELLO".hex()


def t_iso_rejects_garbage():
    assert F.parse_iso8583(b"\x00\x01\x02\x03this is not a payment message at all!!") is None
    assert F.parse_iso8583(b"hello world") is None


# ---------------------------------------------------------------- EMV BER-TLV

def _emv_sample():
    flag = b"CTF{emv_tlv_test}"
    a5 = ber_tlv("50", b"VISA CREDIT") + ber_tlv("9F26", bytes.fromhex("1122334455667788"))
    fci = ber_tlv("84", bytes.fromhex("A0000000031010")) + ber_tlv("A5", a5)
    blob = (ber_tlv("6F", fci)
            + ber_tlv("5A", bytes.fromhex("4111111111111111"))
            + ber_tlv("57", bytes.fromhex("4111111111111111D25122010000000000000F"))
            + ber_tlv("9A", bytes.fromhex("251103"))
            + ber_tlv("9F02", bytes.fromhex("000000150000"))
            + ber_tlv("9F12", flag))
    return blob, flag.decode()


def t_emv_tree_and_values():
    blob, flag = _emv_sample()
    r = F.parse_emv(blob)
    assert r is not None
    assert r["consumed"] == r["total"] == len(blob)
    # top-level tags in order
    top = [n["tag"] for n in r["tlvs"]]
    assert top == ["6F", "5A", "57", "9A", "9F02", "9F12"], top
    # the 6F template is constructed and holds 84 + A5(50,9F26)
    fci = r["tlvs"][0]
    assert fci["constructed"] and fci["name"].startswith("File Control Information")
    child_tags = [c["tag"] for c in fci["children"]]
    assert child_tags == ["84", "A5"], child_tags
    a5 = fci["children"][1]
    assert [c["tag"] for c in a5["children"]] == ["50", "9F26"]
    label = a5["children"][0]
    assert label["decoded"]["ascii"] == "VISA CREDIT"
    # 5A PAN decoded + Luhn
    pan = r["tlvs"][1]
    assert pan["decoded"]["pan"] == "4111111111111111"
    assert pan["decoded"]["luhn"] is True
    # 57 track-2 nibble decode (D -> '=', F -> end)
    tr = r["tlvs"][2]
    assert tr["decoded"]["track2"] == "4111111111111111=25122010000000000000", tr["decoded"]["track2"]
    assert tr["decoded"]["track2_parsed"]["expiry"] == "2512"
    # 9A date, 9F02 amount
    assert r["tlvs"][3]["decoded"]["date"] == "2025-11-03"
    assert r["tlvs"][4]["decoded"]["numeric"] == "150000"
    # flag surfaces from the 9F12 value
    assert flag in r["flags"], r["flags"]


def t_emv_multibyte_tag_parse():
    tag, constructed, cls, i = F._parse_tag(b"\x9f\x26\xff", 0)
    assert tag == "9F26" and constructed is False and cls == 2 and i == 2
    tag2, _, _, i2 = F._parse_tag(b"\x6f\x10", 0)
    assert tag2 == "6F" and i2 == 1


def t_emv_ber_long_form_length():
    value = bytes(range(130))                       # 130 bytes forces 0x81 0x82 long-form length
    elem = ber_tlv("9F46", value)
    length, j = F._parse_len(elem, len(bytes.fromhex("9F46")))
    assert length == 130, length
    nodes, consumed = F._tlv_walk(elem, 0, len(elem), 0, [1000])
    assert consumed == len(elem)
    assert nodes[0]["tag"] == "9F46" and nodes[0]["length"] == 130
    assert nodes[0]["value"] == value


def t_emv_skips_padding():
    # EMV allows 0x00 / 0xFF padding between TLVs
    blob = b"\x00" + ber_tlv("50", b"LBL") + b"\xff" + ber_tlv("87", b"\x01")
    nodes, _ = F._tlv_walk(blob, 0, len(blob), 0, [100])
    assert [n["tag"] for n in nodes] == ["50", "87"], [n["tag"] for n in nodes]


def t_emv_rejects_non_emv():
    assert F.parse_emv(b"just some ascii text, not tlv") is None
    assert F.parse_emv(b"\x01\x02\x03\x04") is None


# ---------------------------------------------------------------- SWIFT MT

def _mt103():
    flag = "CTF{swift_mt103_test}"
    return (
        "{1:F01BANKBEBBAXXX0000000000}"
        "{2:I103DEUTDEFFXXXXN}"
        "{3:{108:MYREF12345}{121:180f1e65-90e0-44d5-a49a-92b55eb3025f}}"
        "{4:\r\n"
        ":20:REFERENCE123\r\n"
        ":23B:CRED\r\n"
        ":32A:251103EUR1234,56\r\n"
        ":50K:/12345678\r\nORDERING CUSTOMER NAME\r\nADDR LINE\r\n"
        ":59:/98765432\r\nBENEFICIARY " + flag + "\r\n"
        ":70:INVOICE 42\r\n"
        ":71A:SHA\r\n"
        "-}"
        "{5:{MAC:00000000}{CHK:123456789ABC}}"
    ).encode(), flag


def t_swift_block_structure():
    data, _ = _mt103()
    r = F.parse_swift(data)
    assert r is not None
    assert r["message_type"] == "103"
    b1 = r["blocks"]["1"]
    assert b1["app_id"] == "F" and b1["service_id"] == "01"
    assert b1["lt_address"] == "BANKBEBBAXXX" and b1["bic"] == "BANKBEBB"
    b2 = r["blocks"]["2"]
    assert b2["direction"] == "input" and b2["message_type"] == "103"
    assert b2["receiver_bic"] == "DEUTDEFF"
    # block 3 nested subfields
    subs = dict(r["blocks"]["3"]["subfields"])
    assert subs["108"] == "MYREF12345"


def t_swift_mt103_fields():
    data, flag = _mt103()
    r = F.parse_swift(data)
    fields = {f["tag"]: f for f in r["blocks"]["4"]["fields"]}
    assert set(["20", "23B", "32A", "50K", "59", "70", "71A"]).issubset(fields), list(fields)
    assert fields["20"]["value"] == "REFERENCE123"
    assert fields["20"]["name"] == "Sender's Reference"
    # :32A: value date / currency / amount decode
    dec = fields["32A"]["decoded"]
    assert dec["value_date"] == "2025-11-03" and dec["currency"] == "EUR" and dec["amount"] == "1234.56"
    # :71A: charge bearer
    assert fields["71A"]["decoded"]["charge_bearer"] == "SHA"
    # multiline :50K: preserved
    assert "ORDERING CUSTOMER NAME" in fields["50K"]["value"]
    # flag surfaces from :59:
    assert flag in r["flags"], r["flags"]


def t_swift_rejects_non_swift():
    iso = ("0200" + ref_bitmap([3]).hex().upper() + "123456").encode()
    assert F.parse_swift(iso) is None
    assert F.parse_swift(b"\x00\x01\x02\x03") is None


def t_swift_block2_output_direction():
    # Output application header (a RECEIVED FIN message):
    #   O | MT(3) | input time(4) | MIR(28) | output date(6) | output time(4) | prio(1)
    # MIR = input date(6) + input LT address(12) + session(4) + input sequence(6) = 28 chars.
    mir = "970103" + "DEUTDEFFXXXX" + "2222" + "123456"
    assert len(mir) == 28
    b2 = "O" + "103" + "1200" + mir + "251103" + "1215" + "N"
    msg = ("{1:F01BANKBEBBAXXX0000000000}{2:" + b2 + "}{4:\r\n:20:REF\r\n-}").encode()
    r = F.parse_swift(msg)
    assert r is not None and r["message_type"] == "103"
    d = r["blocks"]["2"]
    assert d["direction"] == "output"
    assert d["input_time"] == "1200"
    assert d["message_input_reference"] == mir, d["message_input_reference"]
    assert d["sender_bic"] == "DEUTDEFF", d.get("sender_bic")
    assert d["output_date"] == "251103", d.get("output_date")   # NOT read from inside the MIR
    assert d["output_time"] == "1215", d.get("output_time")
    assert d["priority"] == "N"


# ---------------------------------------------------------------- ISO 8583 bitmap-math edge paths

def t_iso_ascii_secondary_bitmap():
    # A field >64 (DE70) forces a secondary bitmap in the fully-ASCII (hex-bitmap) encoding too.
    msg = ("0200" + ref_bitmap([3, 70]).hex().upper() + "123456" + "301").encode()
    r = F.parse_iso8583(msg, encoding="ascii")
    assert r is not None
    assert r["present_fields"] == [3, 70], r["present_fields"]
    assert r["has_secondary_bitmap"] is True
    assert len(r["bitmaps"]) == 2                       # primary + secondary both rendered
    assert {f["de"]: f["value"] for f in r["fields"]} == {3: "123456", 70: "301"}
    assert r["trailing_hex"] == ""


def t_iso_tertiary_indicator_not_a_field():
    # Bit 65 (first bit of the secondary bitmap) is the TERTIARY-bitmap indicator, not DE65.
    # Build the bitmaps independently: primary bit1 (secondary present) + bit3; secondary bit65.
    ba = bytearray(16)
    ba[0] |= 0x80                                        # bit 1 -> secondary bitmap present
    ba[0] |= 0x20                                        # bit 3
    ba[8] |= 0x80                                        # bit 65 -> tertiary indicator
    msg = ("0200" + bytes(ba).hex().upper() + "123456").encode()
    r = F.parse_iso8583(msg, encoding="ascii")
    assert r["present_fields"] == [3], r["present_fields"]
    assert 65 not in r["present_fields"]
    assert r["has_tertiary_bitmap"] is True
    assert r["trailing_hex"] == ""


# ---------------------------------------------------------------- EMV binary vs BCD amounts

def t_emv_binary_amount_tags():
    # EMV format "b" amounts/counters are BIG-ENDIAN BINARY integers, not BCD:
    #   81 = 0x00000100 is 256 (not 100); ATC 9F36 = 0x0012 is 18 (not 12).
    # EMV format "n" amount 9F02 is packed BCD: 0x000000000256 is 256.
    inner = (ber_tlv("81", bytes.fromhex("00000100"))
             + ber_tlv("9F04", bytes.fromhex("00000200"))
             + ber_tlv("9F36", bytes.fromhex("0012"))
             + ber_tlv("9F02", bytes.fromhex("000000000256")))
    blob = ber_tlv("77", inner)                          # 77 is a real root template
    r = F.parse_emv(blob)
    assert r is not None
    kids = {c["tag"]: c for c in r["tlvs"][0]["children"]}
    assert kids["81"]["decoded"]["numeric"] == "256", kids["81"]["decoded"]
    assert kids["9F04"]["decoded"]["numeric"] == "512", kids["9F04"]["decoded"]
    assert kids["9F36"]["decoded"]["numeric"] == "18", kids["9F36"]["decoded"]
    assert kids["9F02"]["decoded"]["numeric"] == "256", kids["9F02"]["decoded"]


# ---------------------------------------------------------------- flag highlighting

def t_flag_find_and_highlight():
    assert F.find_flags("x CTF{a} y chronos{b} z") == ["CTF{a}", "chronos{b}"]
    assert F.find_flags(b"\x00csctf{bytes}\x00") == ["csctf{bytes}"]
    # non-tty marker wraps the hit; a tty uses ANSI
    assert F._hilite("v=CTF{z}", tty=False) == "v=>>>CTF{z}<<<"
    assert "\x1b[1;31m" in F._hilite("CTF{z}", tty=True)
    assert F.find_flags("no flag here") == []


# ---------------------------------------------------------------- dispatch / CLI / pcap

def t_analyze_no_cross_contamination():
    iso = ("0200" + ref_bitmap([3, 11]).hex().upper() + "123456" + "000001").encode()
    emv, _ = _emv_sample()
    swift, _ = _mt103()
    assert [x["type"] for x in F.analyze_bytes(iso)] == ["iso8583"]
    assert [x["type"] for x in F.analyze_bytes(emv)] == ["emv"]
    assert [x["type"] for x in F.analyze_bytes(swift)] == ["swift"]
    # hex-encoded EMV is detected through the auto hex path
    assert [x["type"] for x in F.analyze_bytes(emv.hex().upper().encode())] == ["emv"]


def t_cli_json_and_text(tmpdir):
    iso = ("0200" + ref_bitmap([3, 48]).hex().upper() + "123456" + "013CTF{cli_json}").encode()
    p = Path(tmpdir) / "iso.bin"
    p.write_bytes(iso)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = F.main([str(p)])
    assert rc == 0
    text = out.getvalue()
    assert "CTF{cli_json}" in text and "FLAGS FOUND" in text and "iso8583" in text
    out2 = io.StringIO()
    with contextlib.redirect_stdout(out2):
        rc2 = F.main(["--json", str(p)])
    assert rc2 == 0 and '"type": "iso8583"' in out2.getvalue()


def t_pcap_roundtrip_with_scapy(tmpdir):
    try:
        import logging
        logging.getLogger("scapy").setLevel(logging.ERROR)
        from scapy.all import Ether, IP, TCP, Raw, wrpcap
    except Exception as e:                            # scapy optional: engine degrades gracefully
        print(f"    (scapy unavailable: {e} - pcap cross-check skipped)")
        return
    pflag = "CTF{pcap_iso}"
    iso = ("0200" + ref_bitmap([3, 48]).hex().upper() + "123456"
           + "%03d%s" % (len(pflag), pflag)).encode()
    swift, _ = _mt103()
    pkts = [Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5001, dport=8583) / Raw(load=iso),
            Ether() / IP(src="10.0.0.3", dst="10.0.0.4") / TCP(sport=6001, dport=1234) / Raw(load=swift)]
    path = Path(tmpdir) / "capture.pcap"
    wrpcap(str(path), pkts)
    assert F._looks_pcap(path.read_bytes()[:8])
    payloads = F.pcap_payloads(str(path))
    assert len(payloads) >= 2, payloads
    entries = F.analyze_file(str(path))
    types = {r["type"] for _lbl, r in entries if r}
    flags = set()
    for _lbl, r in entries:
        if r:
            flags |= set(r.get("flags", []))
    assert "iso8583" in types and "swift" in types, types
    assert "CTF{pcap_iso}" in flags and "CTF{swift_mt103_test}" in flags, flags


# ---------------------------------------------------------------- runner

TESTS = [
    t_iso_ascii_basic,
    t_iso_bitmap_render_matches_spec,
    t_iso_packed_secondary_bitmap,
    t_iso_llvar_lllvar_and_luhn,
    t_iso_track2_field_parsed,
    t_iso_auto_detects_encoding,
    t_iso_binary_bitmap_ascii_fields,
    t_iso_mli_strip,
    t_iso_spec_1987_vs_1993_de72,
    t_iso_rejects_garbage,
    t_emv_tree_and_values,
    t_emv_multibyte_tag_parse,
    t_emv_ber_long_form_length,
    t_emv_skips_padding,
    t_emv_rejects_non_emv,
    t_swift_block_structure,
    t_swift_mt103_fields,
    t_swift_rejects_non_swift,
    t_swift_block2_output_direction,
    t_iso_ascii_secondary_bitmap,
    t_iso_tertiary_indicator_not_a_field,
    t_emv_binary_amount_tags,
    t_flag_find_and_highlight,
    t_analyze_no_cross_contamination,
    t_cli_json_and_text,
    t_pcap_roundtrip_with_scapy,
]
# tests that need a scratch directory
_NEED_TMP = {t_cli_json_and_text, t_pcap_roundtrip_with_scapy}


def main():
    failed = 0
    tmp = tempfile.mkdtemp(prefix="csctf-financial-")
    for test in TESTS:
        try:
            if test in _NEED_TMP:
                test(tmp)
            else:
                test()
        except AssertionError as e:
            failed += 1
            import traceback
            where = traceback.extract_tb(e.__traceback__)[-1]
            print(f"FAIL  {test.__name__[2:]}: line {where.lineno}: {str(e)[:900]}")
        except Exception as e:                       # noqa: BLE001
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
