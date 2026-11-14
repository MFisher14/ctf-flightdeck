"""NITF tests use NGA Sarpy's independent writer and hand-built framing.

Install the test oracle with ./.venv/bin/pip install sarpy.
No fixture is encoded by the engine under test.
"""

import random

import numpy as np
import pytest
from sarpy.io.general.nitf_elements.base import TREList, UnknownTRE, UserHeaderType
from sarpy.io.general.nitf_elements.nitf_head import NITFHeader, TextSegmentsType
from sarpy.io.general.nitf_elements.security import NITFSecurityTags
from sarpy.io.general.nitf_elements.text import TextSegmentHeader

import defense_nitf as nitf


def oracle_file(payload=b"CSCTF{NITF_text}", text_format="STA", tre=True):
    security = NITFSecurityTags(CLAS="S", CLSY="US", REL="USA, GBR", CODE="SI")
    text = TextSegmentHeader(TEXTID="0000001", TXTDT="20261105120000",
                             TXTITL="Published-layout fixture", TXTFMT=text_format,
                             Security=security)
    ext = UserHeaderType(data=TREList(tres=[UnknownTRE("CTF001", b"CSCTF{NITF_tre}")])) if tre else None
    header = NITFHeader(OSTAID="TEST", FDT="20261105120000", FTITLE="NITF fixture",
                        Security=security, ExtendedHeader=ext)
    header.TextSegments = TextSegmentsType(
        subhead_sizes=np.array([text.get_bytes_length()]),
        item_sizes=np.array([len(payload)]))
    header.FL = header.get_bytes_length() + text.get_bytes_length() + len(payload)
    return header.to_bytes() + text.to_bytes() + payload, header


def test_sarpy_oracle_fields_offsets_tres_and_text():
    raw, header = oracle_file()
    result = nitf.parse_nitf(raw)
    assert result["fields"]["FL"] == len(raw) == header.FL
    assert result["fields"]["HL"] == header.HL
    assert result["fields"]["FSCLAS"] == "S"
    assert result["fields"]["FSCODE"] == "SI"
    assert result["fields"]["FSREL"] == "USA, GBR"
    segment = result["segments"][0]
    assert segment["subheader_offset"] == header.HL
    assert segment["data_offset"] == header.HL + 282
    assert segment["decoded"]["fields"]["TSCLAS"] == "S"
    assert segment["decoded"]["text"] == "CSCTF{NITF_text}"
    assert result["flags"] == ["CSCTF{NITF_tre}", "CSCTF{NITF_text}"]
    record = result["extended_header"]["tres"][0]
    assert record["tag"] == "CTF001"
    assert raw[record["offset"]:record["offset"]+6] == b"CTF001"
    assert bytes.fromhex(record["data_hex"]) == b"CSCTF{NITF_tre}"


@pytest.mark.parametrize("fmt,payload,expected", [
    ("MTF", b"MSGID/GENADMIN/TEST//", "MSGID/GENADMIN/TEST//"),
    ("UT1", b"A\xe9", "A\xe9"),
    ("U8S", "\u0394 radar".encode(), "\u0394 radar"),
])
def test_text_encodings(fmt, payload, expected):
    raw, _ = oracle_file(payload, fmt)
    assert nitf.parse_nitf(raw)["segments"][0]["decoded"]["text"] == expected


def test_explicit_header_only_mode():
    raw, header = oracle_file()
    result = nitf.parse_nitf(raw[:header.HL], header_only=True)
    assert result["warnings"] == ["Payloads unverified: header-only mode"]
    assert "decoded" not in result["segments"][0]
    with pytest.raises(nitf.DefenseNITFError):
        nitf.parse_nitf(raw[:header.HL])
    with pytest.raises(nitf.DefenseNITFError):
        nitf.parse_nitf(raw, header_only=True)


def test_hand_built_all_segment_tables():
    # Fixed standard widths, independently stated here rather than obtained
    # from engine constants. Opaque subheaders need only their proper marker.
    fixed = (b"NITF02.10" + b"03BF01" + b"TEST".ljust(10) + b"20261105120000"
             + b"hand-built".ljust(80) + b"U" + b" " * 166
             + b"00000000000" + b"\x01\x02\x03" + b"".ljust(24) + b"".ljust(18))
    # IMAGE, GRAPHICS, reserved, TEXT=0, DES, RES, two empty extension areas.
    table = (b"0010000020000000003" + b"0010002000004" + b"000" + b"000"
             + b"0010002000000005" + b"00100020000006" + b"0000000000")
    payload = b"IMabcSYdefgDEhijklREmnopqr"
    hl = len(fixed) + 18 + len(table)
    raw = fixed + f"{hl+len(payload):012d}{hl:06d}".encode() + table + payload
    result = nitf.parse_nitf(raw)
    assert result["fields"]["FBKGC"] == [1, 2, 3]
    assert [s["kind"] for s in result["segments"]] == ["image", "graphic", "des", "res"]
    assert [s["data_length"] for s in result["segments"]] == [3, 4, 5, 6]
    assert [raw[s["data_offset"]:s["data_offset"] + s["data_length"]]
            for s in result["segments"]] == [b"abc", b"defg", b"hijkl", b"mnopqr"]


def test_empty_header_oracle_and_tre_binary_value():
    header = NITFHeader(OSTAID="TEST", FDT="20261105120000")
    header.FL = header.HL
    result = nitf.parse_nitf(header.to_bytes())
    assert result["segments"] == []
    assert result["fields"]["HL"] == 388
    assert nitf.parse_tres(b"TEST  00003\x00\xffA")[0]["data_hex"] == "00ff41"


@pytest.mark.parametrize("bad", [None, 3, "NITF02.10", [], {}, True])
def test_bad_api_types_fail_closed(bad):
    with pytest.raises(nitf.DefenseNITFError):
        nitf.parse_nitf(bad)
    with pytest.raises(nitf.DefenseNITFError):
        nitf.parse_tres(bad)


def test_all_truncations_and_trailing_bytes_reject():
    raw, _ = oracle_file()
    for size in range(len(raw)):
        with pytest.raises(nitf.DefenseNITFError):
            nitf.parse_nitf(raw[:size])
    with pytest.raises(nitf.DefenseNITFError):
        nitf.parse_nitf(raw + b"x")


@pytest.mark.parametrize("offset,replacement", [
    (4, b"02.00"), (9, b"-1"), (11, b"XXXX"), (119, b"X"),
    (296, b"1"), (342, b"999999999999"), (342, b"            "),
    (354, b"000100"), (360, b"999"), (366, b"001"),
])
def test_invalid_headers(offset, replacement):
    raw, _ = oracle_file()
    changed = raw[:offset] + replacement + raw[offset+len(replacement):]
    with pytest.raises(nitf.DefenseNITFError):
        nitf.parse_nitf(changed)


@pytest.mark.parametrize("bad", [b"X", b"ABCDEF00000", b"ABCDEF00004xyz",
                                  b"ABCDEF99999", b"AB!DEF00001x", b"ABCDEF 0001x",
                                  b"ABCDEF00001xJUNK"])
def test_bad_tres_reject(bad):
    with pytest.raises(nitf.DefenseNITFError):
        nitf.parse_tres(bad)


def test_bad_text_content_and_subheader_reject():
    raw, _ = oracle_file(b"\xff", "STA")
    with pytest.raises(nitf.DefenseNITFError):
        nitf.parse_nitf(raw)
    raw, header = oracle_file()
    changed = raw[:header.HL] + b"XX" + raw[header.HL + 2:]
    with pytest.raises(nitf.DefenseNITFError):
        nitf.parse_nitf(changed)
    with pytest.raises(nitf.DefenseNITFError):
        nitf.parse_nitf(raw, header_only=1)


def test_bounded_random_malformed_data_never_leaks_builtin_exception():
    rng = random.Random(1553)
    raw, _ = oracle_file()
    for _ in range(500):
        changed = bytearray(raw)
        for _ in range(rng.randrange(1, 5)):
            changed[rng.randrange(len(changed))] = rng.randrange(256)
        try:
            nitf.parse_nitf(changed)
        except nitf.DefenseNITFError:
            pass


def test_cli(tmp_path, capsys):
    path = tmp_path / "fixture.ntf"
    raw, _ = oracle_file()
    path.write_bytes(raw)
    assert nitf.main([str(path)]) == 0
    assert "NITF_text" in capsys.readouterr().out
    assert nitf.main(["--help"]) == 0
    assert nitf.main([]) == 2
    assert nitf.main(["bad\x00path"]) == 2
    assert nitf.main([str(path.parent / "absent.ntf")]) == 2
    path.write_bytes(b"bad")
    assert nitf.main([str(path)]) == 2
