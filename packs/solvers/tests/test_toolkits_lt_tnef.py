"""B-251: the TNEF (winmail.dat) reader (solvers/toolkits/lt_tnef.py).

Streams are written by the corpus writer (ctf/formats/corpus_longtail.py) from the attribute ids and
property encodings of [MS-OXTNEF]; it shares no code with the reader. The published FILETIME of the
Unix epoch (116444736000000000) pins the time conversion, and the compressed RTF body is produced by
the pinned compressed_rtf package, not by the reader.
"""
import hashlib
import struct
import sys

import pytest

import lt_tnef
from _lt_common import FormatError
from lt_mutations import bit_flips, mutations, only_declared_errors
from ctf import flagfmt
from ctf.formats.corpus_longtail import TNEF_IID_IMESSAGE, tnef_attr, tnef_date, tnef_props, tnef_stream

PS_PUBLIC_STRINGS = bytes.fromhex("2903020000000000c000000000000046")
NOTES = b"quarterly notes\r\n" + bytes(range(256))
SHEET = b"PK\x03\x04 not really a sheet"
RTF = b"{\\rtf1\\ansi the formatted body}"


def u16(text):
    return (text + "\x00").encode("utf-16-le")


def inner_message(subject=b"inner subject\x00"):
    return tnef_stream([
        tnef_attr(1, 0x00089006, struct.pack("<I", 0x00010000)),
        tnef_attr(1, 0x00018004, subject),
        tnef_attr(2, 0x00069002, bytes(14)),
        tnef_attr(2, 0x00018010, b"deep.bin\x00"),
        tnef_attr(2, 0x0006800F, b"deep attachment bytes"),
    ], key=7)


def message(subject=b"Weekly figures\x00", notes=NOTES, rtf=RTF, checksum_delta=0, inner=None, codepage=1252):
    import compressed_rtf
    props = tnef_props([
        (0x001F, 0x0037, u16("Weekly figures (unicode)")),
        (0x001E, 0x0C1A, b"Ada Example\x00"),
        (0x0102, 0x1013, b"<html><body>the html body</body></html>"),
        (0x0102, 0x1009, compressed_rtf.compress(rtf)),
        (0x0040, 0x0039, 116444736000000000),
        (0x000B, 0x0E1F, 1),
        (0x0003, 0x0E07, 33),
        (0x1003, 0x8001, [10, -20, 30], (PS_PUBLIC_STRINGS, 0x8510)),
        (0x001F, 0x8002, u16("urgent"), (PS_PUBLIC_STRINGS, "Keywords")),
    ])
    return tnef_stream([
        tnef_attr(1, 0x00089006, struct.pack("<I", 0x00010000)),
        tnef_attr(1, 0x00069007, struct.pack("<II", codepage, 0)),
        tnef_attr(1, 0x00078008, b"IPM.Microsoft Mail.Note\x00"),
        tnef_attr(1, 0x00018004, subject, checksum_delta),
        tnef_attr(1, 0x00038005, tnef_date(2025, 3, 4, 5, 6, 7)),
        tnef_attr(1, 0x0002800C, b"the plain body\r\n\x00"),
        tnef_attr(1, 0x0004800D, struct.pack("<H", 2)),
        tnef_attr(1, 0x00069003, props),
        # attachment 1: the classic attributes, and a long name in its properties
        tnef_attr(2, 0x00069002, bytes(14)),
        tnef_attr(2, 0x00018010, b"NOTES~1.TXT\x00"),
        tnef_attr(2, 0x0006800F, notes),
        tnef_attr(2, 0x00038012, tnef_date(2025, 1, 2, 3, 4, 5)),
        tnef_attr(2, 0x00038013, tnef_date(2025, 1, 3, 4, 5, 6)),
        tnef_attr(2, 0x00069005, tnef_props([(0x001F, 0x3707, u16("notes for the quarter.txt")),
                                              (0x001E, 0x370E, b"text/plain\x00")])),
        # attachment 2: its bytes only in PR_ATTACH_DATA_BIN
        tnef_attr(2, 0x00069002, bytes(14)),
        tnef_attr(2, 0x00069005, tnef_props([(0x001E, 0x3704, b"sheet.xlsx\x00"), (0x0102, 0x3701, SHEET)])),
        # attachment 3: an embedded message (PR_ATTACH_DATA_OBJ: IID_IMessage, then a TNEF stream)
        tnef_attr(2, 0x00069002, bytes(14)),
        tnef_attr(2, 0x00069005, tnef_props([(0x001E, 0x3001, b"forwarded\x00"),
                                              (0x000D, 0x3701, TNEF_IID_IMESSAGE + (inner or inner_message()))])),
    ])


def test_message_fields_properties_and_attachments():
    blobs = []
    got = lt_tnef.read_tnef(message(), blobs)
    assert (got["key"], got["oem_codepage"], got["tnef_version"]) == (0x1234, 1252, "0x00010000")
    assert (got["message_class"], got["subject"], got["date_sent"]) == ("IPM.Microsoft Mail.Note", "Weekly figures",
                                                                         "2025-03-04T05:06:07")
    assert got["body"] == "the plain body\r\n" and got["priority"] == 2 and got["checksum_mismatches"] == []
    p = got["properties"]
    assert p["subject"] == "Weekly figures (unicode)" and p["sender_name"] == "Ada Example"
    assert p["body_html"] == "<html><body>the html body</body></html>"
    assert p["rtf_compressed"] == RTF.decode()
    assert p["client_submit_time"] == "1970-01-01T00:00:00Z"      # the published FILETIME of the Unix epoch
    assert p["0x0e1f"] is True and p["0x0e07"] == 33
    assert p["00020329-0000-0000-c000-000000000046:0x8510"] == [10, -20, 30]
    assert p["Keywords"] == "urgent"

    one, two, three = got["attachments"]
    assert one["name"] == "notes for the quarter.txt" and one["title"] == "NOTES~1.TXT"
    assert (one["size"], one["sha256"]) == (len(NOTES), hashlib.sha256(NOTES).hexdigest())
    assert (one["created"], one["modified"]) == ("2025-01-02T03:04:05", "2025-01-03T04:05:06")
    assert one["properties"]["attach_mime_tag"] == "text/plain"
    assert (two["name"], two["size"], two["sha256"]) == ("sheet.xlsx", len(SHEET), hashlib.sha256(SHEET).hexdigest())
    assert three["name"] == "attachment-3" and three["properties"]["display_name"] == "forwarded"
    inner = three["embedded_message"]
    assert inner["subject"] == "inner subject" and inner["key"] == 7
    assert inner["attachments"] == [{"name": "deep.bin", "title": "deep.bin", "size": 21,
                                     "sha256": hashlib.sha256(b"deep attachment bytes").hexdigest()}]
    labels = dict(blobs)
    assert labels["notes for the quarter.txt"] == NOTES and labels["sheet.xlsx"] == SHEET
    assert labels["deep.bin"] == b"deep attachment bytes" and labels["message rtf"] == RTF


def test_a_checksum_mismatch_is_reported_and_the_stream_still_read():
    got = lt_tnef.read_tnef(message(checksum_delta=1))
    assert got["checksum_mismatches"] == [f"subject at offset {6 + 15 + 19 + 35}"] and got["subject"] == "Weekly figures"


def test_oem_codepage_decodes_message_text():
    got = lt_tnef.read_tnef(message(subject="Отчёт".encode("cp1251") + b"\x00", codepage=1251))
    assert got["subject"] == "Отчёт"
    unknown = lt_tnef.read_tnef(message(codepage=99999))
    assert unknown["subject"] == "Weekly figures" and "read as cp1252" in unknown["codepage_note"]
    assert "codepage_note" not in got


def test_refusals():
    good = message()
    with pytest.raises(FormatError, match="no TNEF signature"):
        lt_tnef.read_tnef(b"\x00" + good[1:])
    with pytest.raises(FormatError, match="runs past the end"):
        lt_tnef.read_tnef(good[:-5])
    with pytest.raises(FormatError, match="has the level 9"):
        lt_tnef.read_tnef(tnef_stream([b"\x09" + tnef_attr(1, 0x00018004, b"x")[1:]]))
    with pytest.raises(FormatError, match="type 0x00ff, which this reader cannot size"):
        lt_tnef.read_tnef(tnef_stream([tnef_attr(1, 0x00069003, struct.pack("<IHH", 1, 0x00FF, 0x1234))]))
    with pytest.raises(FormatError, match="states 4294967295 properties"):
        lt_tnef.read_tnef(tnef_stream([tnef_attr(1, 0x00069003, struct.pack("<I", 0xFFFFFFFF))]))
    nested = inner_message()
    for _ in range(10):
        nested = tnef_stream([tnef_attr(2, 0x00069002, bytes(14)),
                              tnef_attr(2, 0x00069005, tnef_props([(0x000D, 0x3701, TNEF_IID_IMESSAGE + nested)]))])
    with pytest.raises(FormatError, match="nest deeper"):
        lt_tnef.read_tnef(nested)


def test_corrupt_compressed_rtf_is_listed_not_dropped():
    data = tnef_stream([tnef_attr(1, 0x00069003, tnef_props([(0x0102, 0x1009, b"\x00" * 24)]))])
    blobs = []
    got = lt_tnef.read_tnef(data, blobs)
    assert "does not decompress" in got["properties"]["rtf_compressed"]["undecoded"]
    assert got["properties"]["rtf_compressed"]["compressed_bytes"] == 24 and blobs == [("message rtf_compressed", b"\x00" * 24)]


def test_solve_finds_flags_in_attachment_bytes_rtf_and_embedded_messages(tmp_path):
    lead = flagfmt.cribs()[0]
    a, b, c = lead + "tnef_attachment_bytes}", lead + "tnef_compressed_rtf}", lead + "tnef_embedded_subject}"
    (tmp_path / "winmail.dat").write_bytes(message(notes=b"\x00\xff" + a.encode() + b"\xfe"))
    r = lt_tnef.solve(tmp_path)
    assert (r.status, r.flags) == ("solved", (a,)) and r.evidence[0].path == "winmail.dat"

    (tmp_path / "winmail.dat").write_bytes(message(rtf=b"{\\rtf1 " + b.encode() + b"}"))
    assert lt_tnef.solve(tmp_path).flags == (b,)

    (tmp_path / "winmail.dat").write_bytes(message(inner=inner_message(c.encode() + b"\x00")))
    assert lt_tnef.solve(tmp_path).flags == (c,)

    (tmp_path / "winmail.dat").write_bytes(message())
    r = lt_tnef.solve(tmp_path)
    assert r.status == "unsure" and "attachments[3]" in r.evidence[0].detail
    (tmp_path / "winmail.dat").unlink()
    assert lt_tnef.solve(tmp_path).status == "none"


# ------------------------------------------------------------------ round 1

def props_stream(raw: bytes) -> bytes:
    return tnef_stream([tnef_attr(1, 0x00069003, raw)])


@pytest.mark.parametrize("ptype", [0x1000, 0x1001])
def test_a_multi_valued_property_of_a_type_with_no_size_is_refused(ptype):
    # 2,000 properties of 20,000 values each, none of which takes a byte: 16 KiB that used to build 40 million values
    raw = struct.pack("<I", 2000) + b"".join(struct.pack("<HHI", ptype, 0x7000 + i, 20000) for i in range(2000))
    assert len(raw) < 17_000
    with pytest.raises(FormatError, match=f"the property 0x7000 is a multi-valued list of a type with no size \\(0x{ptype:04x}\\)"):
        lt_tnef.read_tnef(props_stream(raw))
    # one value of such a type is a property with no value (PT_NULL): read, and it takes no bytes
    single = struct.pack("<IHHHHi", 2, 0x0001, 0x7000, 0x0003, 0x7001, 9)
    assert lt_tnef.read_tnef(props_stream(single))["properties"] == {"0x7000": None, "0x7001": 9}


def test_property_and_value_counts_are_held_to_their_limits_and_to_the_bytes():
    assert lt_tnef.MAX_PROPS == 20_000
    with pytest.raises(FormatError, match="a property list states 20001 properties"):
        lt_tnef.read_tnef(props_stream(struct.pack("<I", 20_001) + bytes(8)))
    with pytest.raises(FormatError, match="a property states 20001 values"):
        lt_tnef.read_tnef(props_stream(struct.pack("<IHHI", 1, 0x1003, 0x7000, 20_001) + bytes(8)))
    # under the limit, the values must still be in the bytes: a count the data cannot hold ends at the data
    with pytest.raises(FormatError, match="runs past the end"):
        lt_tnef.read_tnef(props_stream(struct.pack("<IHHI", 1, 0x1003, 0x7000, 20_000) + bytes(8)))
    with pytest.raises(FormatError, match="runs past the end"):
        lt_tnef.read_tnef(props_stream(struct.pack("<I", 20_000) + bytes(8)))
    many = struct.pack("<IHHI", 1, 0x1003, 0x7000, 20_000) + struct.pack("<20000i", *range(20_000))
    assert lt_tnef.read_tnef(props_stream(many))["properties"]["0x7000"] == list(range(20_000))


def test_compressed_rtf_without_its_decoder_is_named_in_the_facts_and_in_the_result(monkeypatch, tmp_path):
    lead = flagfmt.cribs()[0]
    in_rtf, in_subject = lead + "only_in_the_rtf_body}", lead + "in_the_subject_beside_it}"
    rtf = b"{\\rtf1 " + in_rtf.encode() + b" and a body long enough to be compressed, compressed, compressed}"
    plain, inner = message(rtf=rtf), message(rtf=rtf, inner=message(rtf=rtf, subject=b"inner\x00"))
    both = message(rtf=rtf, subject=in_subject.encode() + b"\x00")
    monkeypatch.setitem(sys.modules, "compressed_rtf", None)     # the import fails as on a host without it
    blobs = []
    got = lt_tnef.read_tnef(plain, blobs)
    assert got["needs_tool"] == ["py:compressed_rtf: the message body is compressed RTF"]
    assert got["properties"]["rtf_compressed"]["undecoded"] == "needs_tool py:compressed_rtf: the body is compressed RTF"
    assert not [label for label, _ in blobs if "rtf" in label]                  # undecoded bytes are not scanned
    assert got["subject"] == "Weekly figures" and len(got["attachments"]) == 3          # the rest is still read
    # an embedded message's body is named by the outermost message, once each
    nested = lt_tnef.read_tnef(inner)
    assert nested["needs_tool"] == ["py:compressed_rtf: the message body is compressed RTF"] * 2
    assert "needs_tool" not in nested["attachments"][2]["embedded_message"]

    (tmp_path / "winmail.dat").write_bytes(plain)
    r = lt_tnef.solve(tmp_path)                                   # no flag in what was read: blocked, not "no flag"
    assert (r.status, r.flags) == ("blocked", ())
    assert r.notes == "winmail.dat: TNEF stream: needs_tool py:compressed_rtf: the message body is compressed RTF"
    (tmp_path / "winmail.dat").write_bytes(both)
    r = lt_tnef.solve(tmp_path)                                   # what can be read is read, and the tool is still named
    assert (r.status, r.flags) == ("solved", (in_subject,)) and "needs_tool py:compressed_rtf" in r.notes
    monkeypatch.undo()
    r = lt_tnef.solve(tmp_path)
    assert r.status == "candidate" and set(r.flags) == {in_subject, in_rtf} and r.notes == ""


def test_mutated_streams_raise_only_the_declared_errors():
    from ctf.formats import corpus
    base = corpus.build("tnef_winmail").data
    read, refused = only_declared_errors(lt_tnef.inspect, bit_flips(base))
    assert read + refused == 8 * len(base) and refused > 200 and read > 200      # a changed data byte is still read
    read, refused = only_declared_errors(lt_tnef.inspect, mutations(message(), 2500, seed=251))
    assert read + refused == 2500 and refused > 300 and read > 300
