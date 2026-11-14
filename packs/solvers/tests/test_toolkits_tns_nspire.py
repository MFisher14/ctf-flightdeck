"""B-132: toolkits.tns_nspire, the TI-Nspire document reader (solvers/toolkits/tns_nspire.py).

It walks the *TIMLP zip variant, decrypts TI's method-13 members, decodes their TIXC token streams,
renders Graphs & Geometry pages, decodes an index list through a sibling document's string, and
reports flag-shaped text typed into a page as a possible decoy. Every document here is built by
tests/tns_build.py from the format (struct, zlib, Cryptodome's own 3DES, a separate TIXC encoder),
never through the reader, and every TIXC vector is spelled out in bytes.
"""
import hashlib
import io
import json
import struct
import sys
import zipfile
import zlib
from pathlib import Path

import pytest

import archive_expand as ae
import ctf.intake as I
from ctf import event, flagcheck, sweep
from ctf.engines import manifest as _manifest
from ctf.engines import router
from ctf.formats import fingerprint
from ctf.intake import autosubmit
from ctf.intake import engines as E
from ctf.intake import guard as G
from ctf.result import SolverResult

import tns_build as B
import tns_nspire as T

REPO = Path(__file__).resolve().parents[1]
PINK = event.load("pink")
FF = __import__("ctf.flagfmt", fromlist=["x"]).for_profile(PINK)
crypto = pytest.mark.needs_tool("py:Cryptodome")
pil = pytest.mark.needs_tool("py:PIL")


@pytest.fixture(autouse=True)
def _workdir(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    monkeypatch.setattr(ae.pw, "candidates", lambda: [b"infected"])


def _challenge(tmp_path, files, sub="files"):
    ch = tmp_path / "challenge"
    for name, body in files.items():
        p = ch / sub / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(body)
    return ch


def _details(r):
    return [e.detail for e in r.evidence]


def _noise(n: int) -> bytes:
    """n bytes that do not compress, the same every run."""
    out = b""
    i = 0
    while len(out) < n:
        out += hashlib.sha256(b"tns-noise-%d" % i).digest()
        i += 1
    return out[:n]


SCRIPT = b'import lib_demo as lib\ne = lib.get("alphabet")\nprint(e)\n'


# ------------------------------------------------------------------ the container

def test_the_walk_reads_stored_and_deflated_members_in_file_order():
    data = B.container([B.stored("readme.txt", b"stored as it is"), B.member("main.py", SCRIPT),
                        B.member("empty.py", b"")], version="0900")
    box = T.read_container(data)
    assert box.version == "0900" and box.notes == []
    assert [(m.name, m.method, m.encoding, m.data, m.crc_ok, m.problem) for m in box.members] == [
        ("readme.txt", 0, "stored", b"stored as it is", True, None),
        ("main.py", 8, "deflate", SCRIPT, True, None),
        ("empty.py", 8, "deflate", b"", True, None)]
    assert box.members[1].usize == len(SCRIPT) and box.members[1].csize == len(B.deflate(SCRIPT))
    assert data[box.members[1].offset:box.members[1].offset + box.members[1].csize] == B.deflate(SCRIPT)


def test_a_document_without_the_directory_and_one_with_no_member_are_walked():
    assert [m.name for m in T.read_container(B.container([B.member("a.py", b"x = 1")], directory=False)).members] == ["a.py"]
    empty = T.read_container(B.container([]))
    assert empty.members == [] and empty.notes == []
    assert T.read_container(b"*TIMLP0500").members == []


def test_a_local_headers_extra_field_is_stepped_over():
    first, second = B.member("a.py", b"x = 1"), B.member("b.py", b"y = 2")
    first.extra, second.extra = b"\x01\x02\x03\x04\x05", b"\xaa" * 9
    box = T.read_container(B.container([first, second]))
    assert [(m.name, m.data, m.crc_ok) for m in box.members] == [("a.py", b"x = 1", True), ("b.py", b"y = 2", True)]
    assert box.notes == []


def test_what_is_not_a_document_is_refused_by_name():
    with pytest.raises(T.TnsError, match="TIMLP"):
        T.read_container(b"PK\x03\x04" + bytes(40))
    with pytest.raises(T.TnsError, match="cut short"):
        T.read_container(b"*TIMLP05")
    with pytest.raises(T.TnsError, match="cut short"):
        T.read_container(b"*TIMLP050")                            # nine bytes: one short of the header
    assert T.is_tns(b"*TIMLP0500") and not T.is_tns(b"*TIMLQ0500") and not T.is_tns(b"")


def test_the_walk_stops_with_a_note_where_a_header_is_not_one():
    good = B.container([B.member("a.py", b"x = 1"), B.member("b.py", b"y = 2")], directory=False)
    cut = good.index(b"PK\x03\x04")
    bad = good[:cut] + b"XY\x03\x04" + good[cut + 4:]
    box = T.read_container(bad)
    assert [m.name for m in box.members] == ["a.py"] and box.members[0].data == b"x = 1"
    assert len(box.notes) == 1 and f"offset {cut}" in box.notes[0] and "XY" in box.notes[0]


def test_a_member_that_runs_past_the_end_is_named_and_the_ones_before_it_are_read():
    data = B.container([B.member("a.py", b"x = 1"), B.member("b.py", _noise(400))], directory=False)
    box = T.read_container(data[:-50])
    assert box.members[0].data == b"x = 1"
    assert box.members[1].data is None and "past the end" in box.members[1].problem
    assert any("b.py" in n and "past the end" in n for n in box.notes)
    short = T.read_container(data[:len(data) - 400 - 20])        # cut inside the second header
    assert [m.name for m in short.members] == ["a.py"] and any("header is cut short" in n for n in short.notes)


def test_a_size_or_crc_that_differs_from_the_header_is_said():
    e = B.member("a.py", b"x = 1")
    e.crc ^= 1
    m = T.read_container(B.container([e])).members[0]
    assert m.data == b"x = 1" and m.crc_ok is False and "CRC-32 differs" in m.note
    e = B.member("a.py", b"x = 1")
    e.usize += 1
    m = T.read_container(B.container([e])).members[0]
    assert m.data == b"x = 1" and m.crc_ok is False and m.note


def test_an_unknown_method_a_data_descriptor_and_a_bad_stream_are_problems_not_guesses():
    odd = B.Entry("a.bin", 14, b"lzma?", 5, 0)
    box = T.read_container(B.container([odd, B.member("b.py", b"y = 2")]))
    assert box.members[0].data is None and "method 14" in box.members[0].problem
    assert box.members[1].data == b"y = 2"                        # the walk goes on past a member it cannot read
    lazy = B.Entry("late.py", 8, b"", 0, 0, flags=8)
    box = T.read_container(B.container([lazy]))
    assert box.members[0].data is None and "data descriptor" in box.members[0].problem and box.notes
    broken = B.Entry("c.py", 8, b"\xff\xff\xff\xff", 4, 0)
    assert "does not inflate" in T.read_container(B.container([broken])).members[0].problem
    cut = B.member("d.py", _noise(300))
    cut.payload = cut.payload[:100]
    assert "ends early" in T.read_container(B.container([cut])).members[0].problem


def test_the_member_limit_holds_for_the_stated_size_and_for_what_really_inflates():
    big = B.member("big.py", bytes(5000))
    box = T.read_container(B.container([big]), max_member=4999)
    assert box.members[0].data is None and "5000 bytes stated, over the member limit of 4999" in box.members[0].problem
    assert T.read_container(B.container([big]), max_member=5000).members[0].data == bytes(5000)
    liar = B.member("liar.py", bytes(5000))
    liar.usize = 10                                               # the header understates what the stream holds
    box = T.read_container(B.container([liar]), max_member=4999)
    assert box.members[0].data is None and "inflates past the member limit of 4999" in box.members[0].problem


def test_more_members_than_the_cap_are_not_read_and_that_is_said(monkeypatch):
    monkeypatch.setattr(T, "MAX_MEMBERS", 2)
    box = T.read_container(B.container([B.member(f"m{i}.py", b"x") for i in range(4)]))
    assert [m.name for m in box.members] == ["m0.py", "m1.py"] and any("more than 2 members" in n for n in box.notes)


# ------------------------------------------------------------------ method 13 (vectors made with Cryptodome's DES3)

@crypto
def test_method13_decrypts_a_vector_built_with_cryptodome():
    plain = _noise(333)                                           # not a multiple of 8: the last block is short
    stream = B.stored_deflate(plain)
    raw = B.method13_bytes(stream, seed=0x6FE21307)
    assert T.method13_decrypt(raw) == stream
    assert T.method13_decrypt(B.method13_bytes(b"", seed=5)) == b""
    box = T.read_container(B.container([B.encrypted("secret.bin", plain)]))
    assert (box.members[0].encoding, box.members[0].data, box.members[0].crc_ok) == ("method13", plain, True)


@crypto
def test_method13_uses_the_seed_and_the_key_of_the_header():
    stream = B.stored_deflate(_noise(200))
    for seed, packed in ((0, B.PACKED), (0xDEADBEEF, B.PACKED), (7, bytes(range(0x80, 0x80 + 21)))):
        assert T.method13_decrypt(B.method13_bytes(stream, seed=seed, packed=packed)) == stream
    other = B.method13_bytes(stream, seed=7, packed=B.PACKED, key24=B.expand(bytes(range(0x80, 0x80 + 21))))
    assert T.method13_decrypt(other) != stream                    # encrypted under another key than the header's


@crypto
def test_the_keystream_counter_wraps_at_0x400_blocks_and_at_32_bits():
    plain = _noise(8 * 0x400 + 8 * 40)                            # 1064 blocks: 40 of them past the wrap
    stream = B.stored_deflate(plain)
    assert T.method13_decrypt(B.method13_bytes(stream, seed=0x1000)) == stream
    unwrapped = B.method13_bytes(stream, seed=0x1000, wrap=None)  # a counter that never wraps: not the format
    got = T.method13_decrypt(unwrapped)
    assert got[:8 * 0x400] == stream[:8 * 0x400] and got != stream
    high = B.method13_bytes(stream, seed=0xFFFFFF00)              # seed + i passes 2**32 inside the first 0x400 blocks
    assert T.method13_decrypt(high) == stream


@crypto
def test_a_key_whose_parts_repeat_still_decrypts():
    from Cryptodome.Cipher import DES
    zero = bytes(21)                                              # three equal DES keys: EDE is single DES
    stream = B.stored_deflate(b"same key three times")

    def single(blocks):
        counters = b"".join(b"\x00" * 4 + struct.pack("<I", 9 + i) for i in range(blocks))
        return DES.new(bytes(8), DES.MODE_ECB).encrypt(counters)
    assert T.method13_decrypt(B.method13_bytes(stream, seed=9, packed=zero, stream_of=single)) == stream


@crypto
def test_a_method13_member_that_is_not_one_is_a_problem():
    raw = B.method13_bytes(B.deflate(b"x"), magic=b"TIEN0200")
    with pytest.raises(T.TnsError, match="TIEN0100"):
        T.method13_decrypt(raw)
    with pytest.raises(T.TnsError, match="40-byte header"):
        T.method13_decrypt(bytes(39))
    box = T.read_container(B.container([B.Entry("p.xml", 13, bytes(64), 10, 0), B.member("a.py", b"x = 1")]))
    assert box.members[0].data is None and "TIEN0100" in box.members[0].problem and box.members[0].missing is None
    assert box.members[1].data == b"x = 1"


def test_expand_key_spreads_seven_bits_to_a_byte():
    assert T.expand_key(b"\xff" * 21) == b"\xfe" * 24
    assert T.expand_key(bytes(21)) == bytes(24)
    assert T.expand_key(b"\x80" + bytes(20)) == b"\x80" + bytes(23)
    assert T.expand_key(bytes(6) + b"\x01" + bytes(14)) == bytes(7) + b"\x02" + bytes(16)
    assert T.expand_key(bytes(7) + b"\x01" + bytes(13)) == bytes(8) + b"\x00\x80" + bytes(14)
    for packed in (B.PACKED, bytes(range(200, 221)), _noise(21)):
        assert T.expand_key(packed) == B.expand(packed)
    with pytest.raises(T.TnsError, match="21 bytes"):
        T.expand_key(bytes(20))


def test_without_pycryptodomex_an_encrypted_member_names_it(monkeypatch, tmp_path):
    monkeypatch.setitem(sys.modules, "Cryptodome.Cipher", None)   # the import now fails
    entry = B.Entry("Problem1.xml", 13, bytes(80), 10, 0)
    box = T.read_container(B.container([entry, B.member("a.py", b"x = 1")]))
    assert box.members[0].data is None and "pycryptodomex (py:Cryptodome)" in box.members[0].problem
    assert box.members[0].missing == "py:Cryptodome" and box.members[1].data == b"x = 1"
    r = T.solve(_challenge(tmp_path, {"doc.tns": B.container([entry])}), PINK)
    assert r.status == "blocked" and "py:Cryptodome" in r.notes and "Problem1.xml was not read" in r.notes
    assert "0 of 1 member(s) read" in r.notes
    flagged = B.container([entry, B.member("a.py", b'print("PINK{script_still_read}")')])
    r = T.solve(_challenge(tmp_path / "b", {"doc.tns": flagged}), PINK)
    assert r.status == "solved" and r.flags == ("PINK{script_still_read}",) and "missing: py:Cryptodome" in r.notes
    assert "1 of 2 member(s) read: a.py (deflate)" in r.notes
    two = B.container([entry, B.member("a.py", b'print("PINK{one}", "PINK{two}")')])
    r = T.solve(_challenge(tmp_path / "c", {"doc.tns": two}), PINK)
    assert r.status == "candidate" and r.flags == ("PINK{one}", "PINK{two}")      # what was found is not hidden


# ------------------------------------------------------------------ TIXC (every vector spelled out in bytes)

HEAD = b"TIXC0100-1.0?>"
DECL = b'<?xml version="1.0" encoding="UTF-8" ?>'


def _in_t(token: bytes) -> bytes:
    """A document <t>TOKEN</t>: the tag spelled once, closed by index 0."""
    return HEAD + b"<t>" + token + b"\x0e\x00"


TEXT_VECTORS = [
    ("literal", b"Hi, there!", "Hi, there!"),
    ("tab-newline-return", b"a\tb\nc\rd", "a\tb\nc\rd"),
    ("letters-none", bytes.fromhex("a6561a"), "none"),                    # n | o n | e END
    ("letters-false", bytes.fromhex("af13b71a"), "false"),                # SHIFT | f a | l s | e END
    ("letters-end-high-nibble", bytes.fromhex("a2a0") + b"!", "t!"),      # t | END(low nibble unused), then a literal
    ("letters-second-half-run", bytes.fromhex("a1f0f3a0"), "emg"),        # e | SHIFT m | SHIFT g | END
    ("letters-shift-twice", bytes.fromhex("af0f3a"), "mg"),               # SHIFT | m SHIFT | g END
    ("letters-empty", bytes.fromhex("aa") + b"x", "x"),                   # END at once
    ("letters-space-and-quote", bytes.fromhex("a90f" "fa"), "h '"),       # h | space SHIFT | ' END
    ("digits-10", bytes.fromhex("f10f"), "10"),                           # 1 | 0 END
    ("digits-minus", bytes.fromhex("fb10f0"), "\u221210"),                # MINUS | 1 0 | END
    ("digits-6.67", bytes.fromhex("f6d67f"), "6.67"),                     # 6 | . 6 | 7 END
    ("digits-second-half", bytes.fromhex("fa31a4f0"), "(1)"),             # SHIFT | ( 1 | SHIFT ) | END
    ("digits-shift-twice", bytes.fromhex("fa3a4f"), "()"),                # SHIFT | ( SHIFT | ) END
    ("digits-pairs", bytes.fromhex("faef"), "))"),                        # SHIFT | P END
    ("digits-brackets", bytes.fromhex("faff"), "]["),                     # SHIFT | B END
    ("digits-exponent", bytes.fromhex("fef0"), "\uf000"),                 # E | END
    ("digits-empty", bytes.fromhex("ff") + b"x", "x"),                    # END at once
    ("two-byte", bytes.fromhex("00e9"), "\u00e9"),
    ("two-byte-high", bytes.fromhex("07ff"), "\u07ff"),
    ("unit-run-one", bytes.fromhex("802212"), "\u2212"),
    ("unit-run-two", bytes.fromhex("81221220ac") + b"!", "\u2212\u20ac!"),
    ("four-byte", bytes.fromhex("0801f600"), "\U0001f600"),
]


@pytest.mark.parametrize("token,text", [v[1:] for v in TEXT_VECTORS], ids=[v[0] for v in TEXT_VECTORS])
def test_tixc_text_tokens(token, text):
    assert T.tixc_decode(_in_t(token)).decode("utf-8") == DECL.decode() + f"<t>{text}</t>"


def test_tixc_markup_names_tags_and_attributes_by_index():
    stream = (HEAD
              + b'<doc ver="1.0">'                 # tag 0, attribute 0, a literal value
              + b"<a>hi\x0e\x01"                   # tag 1; closed by index
              + b"<b/>"                            # tag 2, empty
              + b"\x0c\x01" + bytes.fromhex("a6561a") + b"\x0e\x01"   # <a> by index: closes itself, then text
              + b'<c x="' + bytes.fromhex("f1f0") + b'">\x0e\x03'     # tag 3, attribute 1 with a packed value
              + b"\x0c\x01\x0f\x00v2\"\x0f\x01" + bytes.fromhex("a1a0") + b'">z\x0e\x01'   # <a ver="v2" x="e">z</a>
              + b"\x0c\x02/>"                      # <b/> by index
              + b"<d\x0e\x04"                      # <d></d>: spelled, closed at once by its own new index
              + b"\x0c\x03 y=\"q\"/>"              # <c y="q"/>: an indexed tag with a spelled attribute (2)
              + b"<e\x0f\x02w\">\x0e\x05"          # <e y="w"></e>: a spelled tag with an indexed attribute
              + b"\x0e\x00")
    want = (DECL + b'<doc ver="1.0"><a>hi</a><b/><a>none</a><c x="1"></c><a ver="v2" x="e">z</a><b/><d></d>'
                   b'<c y="q"/><e y="w"></e></doc>')
    assert T.tixc_decode(stream) == want


def test_tixc_markup_bytes_inside_packed_text_are_text_not_markup():
    # In letter mode 0x0e is the pair (space, 'u') and 0x3c is ('a', 'c'): not a closing tag, not '<'.
    stream = HEAD + b"<t>" + bytes.fromhex("a1" "0e" "3c" "a0") + b"\x0e\x00"
    assert T.tixc_decode(stream) == DECL + b"<t>e uac</t>"
    # In an attribute value a quote byte inside a 16-bit unit (U+2222) does not end the value.
    stream = HEAD + b'<t k="' + bytes.fromhex("802222") + b'">\x0e\x00'
    assert T.tixc_decode(stream) == DECL + '<t k="\u2222"></t>'.encode()


def test_tixc_keeps_a_cdata_section_as_it_is():
    stream = HEAD + b"<t><![CDATA[x < y ]] \x0e\x00 > z]]>after\x0e\x00"
    assert T.tixc_decode(stream) == DECL + b"<t><![CDATA[x < y ]] \x0e\x00 > z]]>after</t>"
    # the section ends at its first ]]>: what follows is markup again, even with another ]]> later
    stream = HEAD + b"<t><![CDATA[a]]>\x0e\x00\x0c\x00]]>\x0e\x00"
    assert T.tixc_decode(stream) == DECL + b"<t><![CDATA[a]]></t><t>]]></t>"


def test_a_closing_tag_spelled_out_passes_through_and_takes_no_index():
    stream = HEAD + b"<t><a></a><b>\x0e\x02\x0e\x00"
    assert T.tixc_decode(stream) == DECL + b"<t><a></a><b></b></t>"


def test_the_version_of_the_header_is_the_xml_version():
    assert T.tixc_decode(b"TIXC0100-1.1?><t>\x0e\x00").startswith(b'<?xml version="1.1" encoding="UTF-8" ?><t>')


@pytest.mark.parametrize("stream,message", [
    (b"TIXD0100-1.0?><t>\x0e\x00", "no TIXC header"),
    (b"TIXC0100-1.0?", "no TIXC header"),
    (HEAD + b"text", "does not open with a tag"),
    (HEAD + b"<t>\x0e\x01", "tag index 1 was never spelled"),
    (HEAD + b"<t>\x0c\x05", "tag index 5 was never spelled"),
    (HEAD + b"<t\x0f\x00", "attribute index 0 was never spelled"),
    (HEAD + b"<t>" + bytes.fromhex("a6"), "ends inside"),
    (HEAD + b"<t>" + bytes.fromhex("8022"), "ends inside"),
    (HEAD + b'<t k="v', "ends inside"),
    (HEAD + b"<t", "ends inside"),
    (HEAD + b"<t>\x0b\x00\x00", "0x0b is no text token"),
    (HEAD + b"<t>\xb0", "0xb0 is no text token"),
    (HEAD + b"<t>\x9f", "0x9f is no text token"),
    (HEAD + b"<t>\x7f", "0x7f is no text token"),
    (HEAD + b"<t>\x08\x11\x00\x00\x0e\x00", r"U\+110000"),
    (HEAD + b"<t><!-- note -->\x0e\x00", "other than a CDATA section"),
    (HEAD + b"<t><![CDATA[open", "CDATA section is not closed"),
    (HEAD + b'<t k="v"x', "0x78 after an attribute"),
    (HEAD + b"<t k=v>\x0e\x00", "does not open with a quote"),
])
def test_tixc_streams_that_are_not_tixc_are_refused_by_name(stream, message):
    with pytest.raises(T.TnsError, match=message):
        T.tixc_decode(stream)


def test_a_stream_may_end_right_after_an_indexed_tag_or_in_plain_text():
    assert T.tixc_decode(HEAD + b"<t>\x0e\x00\x0c\x00") == DECL + b"<t></t><t>"
    assert T.tixc_decode(HEAD + b"<t>ab") == DECL + b"<t>ab"


def test_tixc_decoding_is_capped():
    stream = HEAD + b"<t>" + b"x" * 5000 + b"\x0e\x00"
    assert len(T.tixc_decode(stream, cap=6000)) == len(DECL) + 5007
    with pytest.raises(T.TnsError, match="past the member limit of 4000"):
        T.tixc_decode(stream, cap=4000)
    exact = len(DECL) + 5007
    assert len(T.tixc_decode(stream, cap=exact)) == exact
    with pytest.raises(T.TnsError, match="past the member limit"):
        T.tixc_decode(stream, cap=exact - 1)


PAGE = B.geometry(points=[(22, 10.0, 50.0), (23, 10.0, 40.0), (24, 30.0, 40.0), (25, 30.0, 50.0, False)],
                  segments=[(55, 22, 23), (56, 23, 24), (57, 24, 25, False), (58, 22, 99)],
                  texts=[(8, "\u221210", 24.0, 47.0, 1.0, 1.0, 7), (87, "g_", 14.0, 48.0, 6.0, 4.0)],
                  extra=[("gg:segment", {}, [("gg:id", {}, ["59"]), ("gg:par", {}, ["22 "])]),
                         ("gg:segment", {}, [("gg:id", {}, ["60"]), ("gg:par", {}, ["22 23 24 "])])])


def test_a_whole_page_encoded_by_the_test_encoder_decodes_to_its_xml():
    assert T.tixc_decode(B.tixc(PAGE)) == B.xml(PAGE)
    assert T.tixc_decode(B.tixc(B.settings())) == B.xml(B.settings())
    assert "\u2212" in B.xml(PAGE).decode() and b"\x80\x22\x12" in B.tixc(PAGE)   # the encoder really packs


@crypto
def test_an_encrypted_page_is_read_as_its_xml_and_checked_against_the_headers_crc():
    box = T.read_container(B.container([B.xml_page("Document.xml", B.settings()), B.xml_page("Problem1.xml", PAGE)]))
    assert [(m.name, m.encoding, m.crc_ok, m.note) for m in box.members] == [
        ("Document.xml", "method13+tixc", True, None), ("Problem1.xml", "method13+tixc", True, None)]
    assert box.members[1].data == B.xml(PAGE)


def test_a_tixc_stream_that_does_not_decode_is_kept_as_stored_and_said():
    stream = b"TIXC0100-1.0?><t>\x0e\x07"
    box = T.read_container(B.container([B.member("Problem1.xml", stream)]))
    m = box.members[0]
    assert m.data == stream and m.encoding == "deflate" and "TIXC stream did not decode" in m.note
    assert "tag index 7" in m.note and "kept as stored" in m.note


# ------------------------------------------------------------------ pages

def test_objects_without_an_id_a_text_or_a_place_are_still_read():
    tree = B.geometry(points=[(1, 0.0, 0.0)], extra=[
        ("gg:point", {}, [("gg:x", {}, ["2.0"]), ("gg:y", {}, ["3.0"])]),                           # no id
        ("gg:label", {}, [("gg:id", {}, ["30"]), ("gg:chrs", {}, ["1 1 3 0 0 0 x\n"]), ("gg:x", {}, ["1.0"]),
                          ("gg:y", {}, ["1.0"])]),                                                   # an axis label
        ("gg:text", {}, [("gg:id", {}, ["31"]), ("gg:chrs", {}, ["1 1 2 0 0 0   \n"]), ("gg:x", {}, ["1.0"]),
                         ("gg:y", {}, ["1.0"])]),                                                   # blank
        ("gg:text", {}, [("gg:id", {}, ["32"]), ("gg:chrs", {}, ["1 1 2 0 0 0 nowhere\n"])]),      # no place
        ("gg:text", {}, [("gg:id", {}, ["33"]), ("gg:chrs", {}, ["plain words\n"]), ("gg:x", {}, ["1.0"]),
                         ("gg:y", {}, ["2.0"])])])                                                  # no format fields
    page = T.parse_page(B.xml(tree))
    assert list(page.points) == ["1", "#3"] and (page.points["#3"].x, page.points["#3"].y) == (2.0, 3.0)
    assert [(t.id, t.text, t.attached) for t in page.texts] == [
        ("30", "x", True), ("31", "  ", False), ("32", "nowhere", False), ("33", "plain words", False)]
    assert [t.id for t in page.free_texts()] == ["33"] and page.other == {"axes_system": 1}
    page.layout()                                                 # a text object with no place is not laid out


def test_a_page_gives_its_points_segments_and_text_objects():
    page = T.parse_page(B.xml(PAGE), "Problem1.xml")
    assert page.name == "Problem1.xml"
    assert {k: (p.x, p.y, p.hidden) for k, p in page.points.items()} == {
        "22": (10.0, 50.0, False), "23": (10.0, 40.0, False), "24": (30.0, 40.0, False), "25": (30.0, 50.0, True)}
    assert [(s.id, s.a, s.b, s.hidden) for s in page.segments] == [
        ("55", "22", "23", False), ("56", "23", "24", False), ("57", "24", "25", True), ("58", "22", "99", False)]
    assert [s.id for s in page.drawn_segments()] == ["55", "56", "57"]
    assert any("1 segment(s) name an end that is no point" in n for n in page.notes)
    assert [(t.id, t.text, t.attached, t.x, t.y, t.w, t.h) for t in page.texts] == [
        ("8", "\u221210", True, 24.0, 47.0, 1.0, 1.0), ("87", "g_", False, 14.0, 48.0, 6.0, 4.0)]
    assert [t.id for t in page.free_texts()] == ["87"]
    assert page.other == {"axes_system": 1, "segment": 2} and page.drawn     # a segment has exactly two ends


def test_a_minus_sign_is_a_minus_and_a_bad_number_is_no_point():
    tree = B.geometry(points=[(1, -3.5, -2.0)],
                      extra=[("gg:point", {}, [("gg:id", {}, ["2"]), ("gg:x", {}, ["nan"]), ("gg:y", {}, ["1"])]),
                             ("gg:point", {}, [("gg:id", {}, ["3"]), ("gg:x", {}, ["1e999"]), ("gg:y", {}, ["1"])]),
                             ("gg:point", {}, [("gg:id", {}, ["4"]), ("gg:x", {}, ["abc"]), ("gg:y", {}, ["1"])])])
    page = T.parse_page(B.xml(tree))
    assert list(page.points) == ["1"] and (page.points["1"].x, page.points["1"].y) == (-3.5, -2.0)
    assert page.other == {"axes_system": 1, "point": 3}           # counted as not drawn, not dropped


def test_what_is_no_page_is_none_and_hostile_xml_is_refused():
    assert T.parse_page(B.xml(B.settings())) is None
    with pytest.raises(T.TnsError, match="does not parse"):
        T.parse_page(b"<doc><open></doc>")
    bomb = b'<?xml version="1.0"?><!DOCTYPE d [<!ENTITY a "aaaa">]><d>&a;</d>'
    with pytest.raises(T.TnsError, match="DOCTYPE"):
        T.parse_page(bomb)
    only_text = T.parse_page(B.xml(B.geometry(texts=[(5, "note", 1.0, 2.0, 3.0, 1.0)])))
    assert not only_text.drawn and [t.text for t in only_text.free_texts()] == ["note"]


def test_more_objects_than_the_cap_stop_the_reading_with_a_note(monkeypatch):
    monkeypatch.setattr(T, "MAX_OBJECTS", 3)
    page = T.parse_page(B.xml(B.geometry(points=[(i, float(i), 1.0) for i in range(1, 9)])))
    assert len(page.points) == 2 and any("more than 3 objects" in n for n in page.notes)   # the axes object counts


def test_layout_fits_the_longer_side_and_flips_y():
    page = T.parse_page(B.xml(B.geometry(points=[(1, 10.0, 50.0), (2, 30.0, 40.0)])))
    page.layout(width=280, margin=40)
    assert page.scale == 10.0 and page.origin == (10.0, 50.0) and page.size == (280, 180)
    assert page.to_pixel(10.0, 50.0) == (40.0, 40.0)              # the highest, leftmost point: top left
    assert page.to_pixel(30.0, 40.0) == (240.0, 140.0)            # lower on the page: further down the picture
    tall = T.parse_page(B.xml(B.geometry(points=[(1, 0.0, 0.0), (2, 5.0, 20.0)])))
    tall.layout(width=280, margin=40)
    assert tall.scale == 10.0 and tall.size == (130, 280)
    one = T.parse_page(B.xml(B.geometry(points=[(1, 3.0, 3.0)])))
    one.layout(width=280, margin=40)
    assert one.scale == 1.0 and one.size == (80, 80) and one.to_pixel(3.0, 3.0) == (40.0, 40.0)
    boxed = T.parse_page(B.xml(B.geometry(points=[(1, 0.0, 0.0)], texts=[(9, "t", 2.0, 10.0, 8.0, 4.0)])))
    boxed.layout(width=280, margin=40)                            # the text box (2..10, 10..6) widens the picture
    assert boxed.origin == (0.0, 10.0) and boxed.scale == 20.0 and boxed.size == (280, 280)


def _picture(png: bytes):
    from PIL import Image
    im = Image.open(io.BytesIO(png)).convert("RGB")
    return im, im.load()


@pil
def test_the_rendering_draws_segments_points_hidden_objects_and_text_where_they_sit():
    page = T.parse_page(B.xml(PAGE))
    im, px = _picture(T.render_page(page, width=1040))
    assert im.size == page.size == (1040, 560) and page.scale == 48.0
    black, red, white = (0, 0, 0), (220, 0, 0), (255, 255, 255)

    def at(x, y):
        cx, cy = page.to_pixel(x, y)
        return px[int(round(cx)), int(round(cy))]
    assert at(10.0, 45.0) == black                               # the middle of segment 55 (shown)
    assert at(20.0, 40.0) == black                               # the middle of segment 56
    assert at(30.0, 45.0) == red                                 # the middle of segment 57 (hidden)
    assert at(30.0, 50.0) == red and at(10.0, 50.0) == black     # a hidden point, a shown one
    assert at(20.0, 50.0) == white                               # no segment joins 22 and 25
    assert at(25.0, 45.0) == white                               # nothing in the middle
    # y is flipped: the points at y = 50 are above the ones at y = 40
    assert page.to_pixel(10.0, 50.0)[1] < page.to_pixel(10.0, 40.0)[1]
    # the free text "g_" is drawn in blue inside its box (x 14..20, y 48..44), and nowhere else: the
    # attached text at (24, 47), an axis number, is not drawn
    x0, y0 = page.to_pixel(14.0, 48.0)
    x1, y1 = page.to_pixel(20.0, 44.0)
    blue = [(x, y) for x in range(im.width) for y in range(im.height) if px[x, y][2] > 150 and px[x, y][0] < 80]
    assert len(blue) > 200
    assert all(x0 - 2 <= x <= x1 + 2 and y0 - 2 <= y <= y1 + 2 for x, y in blue)


@pil
def test_a_page_of_one_point_still_renders():
    page = T.parse_page(B.xml(B.geometry(points=[(1, 3.0, 3.0)])))
    im, px = _picture(T.render_page(page))
    assert im.size == (80, 80) and px[40, 40] == (0, 0, 0) and px[5, 5] == (255, 255, 255)


def test_without_pillow_a_rendering_names_it(monkeypatch, tmp_path):
    monkeypatch.setitem(sys.modules, "PIL", None)
    with pytest.raises(T.ToolMissing, match=r"Pillow \(py:PIL\)"):
        T.render_page(T.parse_page(B.xml(PAGE)))
    ch = _challenge(tmp_path, {"p.tns": B.container([B.member("Problem1.xml", B.xml(PAGE))])})
    r = T.solve(ch, PINK)
    assert r.status == "blocked" and "missing: py:PIL" in r.notes
    assert "files/p.tns -> Problem1.xml: a page rendering needs Pillow (py:PIL)" in r.notes
    assert not [e for e in r.evidence if e.kind == "render"] and not list((ch / "recon").rglob("*.png"))


def test_a_page_of_text_objects_only_is_not_a_drawing(tmp_path):
    tree = B.geometry(texts=[(5, "just a note", 1.0, 2.0, 3.0, 1.0)])
    ch = _challenge(tmp_path, {"p.tns": B.container([B.member("Problem1.xml", B.xml(tree))])})
    r = T.solve(ch, PINK)
    assert r.status == "none" and not [e for e in r.evidence if e.kind == "render"]
    report = json.loads((ch / "recon" / "tns_nspire" / "report.json").read_text())
    assert report["pages"][0]["texts"] == ["just a note"] and report["pages"][0]["rendered"] is False
    assert report["ocr"] == "not needed"


# ------------------------------------------------------------------ flags: the index list (Pink 11)

_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_"
ALPHABET = "".join(_CHARS[(i * 23 + 7) % 65] for i in range(65))       # a fixed shuffle: 23 and 65 are coprime


def _indexes(text: str, base: int = 0) -> list:
    return [ALPHABET.index(c) + base for c in text]


def _two_documents(flag: str, base: int = 0, sep: str = " "):
    run = sep.join(str(i) for i in _indexes(flag, base))
    main = f'import lib_demo as lib\ne = lib.get("alphabet")\nc = "{run}"\nf = ""\nfor n in c.split():\n    f += e[int(n)]\n'
    lib = f'alphabet = "{ALPHABET}"\ndef get(name):\n  if name == "alphabet": return alphabet\n#hi\n'
    return (B.container([B.member("main.py", main.encode())], version="0900"),
            B.container([B.member("lib_demo.py", lib.encode())], version="0900"))


def test_an_index_list_in_one_document_is_decoded_through_the_string_of_another(tmp_path):
    flag = "PINK{synth3tic_ind3x_list}"
    main, lib = _two_documents(flag)
    assert flag.encode() not in main and flag.encode() not in lib          # in neither file as it stands
    r = T.solve(_challenge(tmp_path, {"main.tns": main, "lib_demo.tns": lib}), PINK)
    assert r.status == "solved" and r.flags == (flag,), r
    decode = [e for e in r.evidence if e.kind == "decode"]
    assert len(decode) == 1 and f"{len(flag)} indexes in files/main.tns -> main.py" in decode[0].detail
    assert "65-character string in files/lib_demo.tns -> lib_demo.py" in decode[0].detail
    assert "counted from 1" not in decode[0].detail
    SolverResult.from_json(r.to_json())


@pytest.mark.parametrize("sep", [", ", ",", ";", "\n", " ,\t"], ids=["comma-space", "comma", "semicolon", "newline", "mixed"])
def test_the_list_may_be_separated_by_commas_semicolons_or_lines(sep):
    flag = "PINK{any_s3parator}"
    texts = {"a": "c = [" + sep.join(str(i) for i in _indexes(flag)) + "]", "b": f"alphabet = '{ALPHABET}'"}
    assert [(f, s) for f, _, s in T.index_decodes(texts, FF)] == [(flag, "a")]


def test_a_list_counted_from_one_is_decoded_and_said():
    flag = "PINK{count3d_from_on3}"
    texts = {"a": " ".join(str(i) for i in _indexes(flag, 1)), "b": f'"{ALPHABET}"'}
    got = T.index_decodes(texts, FF)
    assert [g[0] for g in got] == [flag] and "counted from 1" in got[0][1]


def test_a_list_that_spells_no_flag_or_indexes_past_the_string_says_nothing(tmp_path):
    flag = "PINK{synth3tic_ind3x_list}"
    plain = {"a": " ".join(str(i) for i in _indexes("just_s0me_w0rds_n0_flag")), "b": f'"{ALPHABET}"'}
    assert T.index_decodes(plain, FF) == []
    past = {"a": " ".join(str(i + 30) for i in _indexes(flag)), "b": f'"{ALPHABET}"'}    # the decoy of Pink 11
    assert T.index_decodes(past, FF) == []
    short = {"a": " ".join(str(i) for i in _indexes("PINK{a}")), "b": f'"{ALPHABET}"'}    # 7 integers: no list
    assert T.index_decodes(short, FF) == []
    eight = {"a": " ".join(str(i) for i in _indexes("PINK{ab}")), "b": f'"{ALPHABET}"'}    # 8 are one
    assert [g[0] for g in T.index_decodes(eight, FF)] == ["PINK{ab}"]
    edge = {"a": " ".join(str(i) for i in _indexes(flag)[:-1] + [len(ALPHABET)]), "b": f'"{ALPHABET}"'}
    assert T.index_decodes(edge, FF) == []                        # one index just past the end: from 0 it fits nothing
    no_string = {"a": " ".join(str(i) for i in _indexes(flag)), "b": "alphabet = 5"}
    assert T.index_decodes(no_string, FF) == []
    main, _ = _two_documents(flag)
    r = T.solve(_challenge(tmp_path, {"main.tns": main}), PINK)                  # the list without its alphabet
    assert r.status == "none" and not r.flags and "1 of 1 member(s) read: main.py (deflate)" in r.notes


def test_one_flag_found_through_several_lists_and_strings_is_reported_once():
    flag = "PINK{0nce}"
    run = " ".join(str(i) for i in _indexes(flag))
    texts = {"a": f'c = "{run}"\nd = "{run}"', "b": f'x = "{ALPHABET}"\ny = "{ALPHABET}"'}
    assert [g[0] for g in T.index_decodes(texts, FF)] == [flag]


# ------------------------------------------------------------------ flags: script text, document text, OCR

def test_a_flag_as_it_stands_in_a_script_member_is_solved(tmp_path):
    doc = B.container([B.member("main.py", b'print("PINK{lit3ral_in_a_script}")')])
    ch = _challenge(tmp_path, {"main.tns": doc})
    r = T.solve(ch, PINK)
    assert r.status == "solved" and r.flags == ("PINK{lit3ral_in_a_script}",)
    match = [e for e in r.evidence if e.kind == "match"]
    assert len(match) == 1 and "as it stands in the member files/main.tns -> main.py" in match[0].detail
    assert (ch / match[0].path).read_bytes() == b'print("PINK{lit3ral_in_a_script}")'


def _drawn_page(text="PINK{typ3d_on_the_page}"):
    return B.geometry(points=[(22, 10.0, 50.0), (23, 10.0, 40.0), (24, 30.0, 40.0)], segments=[(55, 22, 23), (56, 23, 24)],
                      texts=[(132, text, 12.0, 58.0, 19.0, 2.2)])


@crypto
@pil
def test_flag_shaped_text_on_a_drawn_page_is_a_possible_decoy_never_solved(tmp_path):
    doc = B.container([B.xml_page("Document.xml", B.settings()), B.xml_page("Problem1.xml", _drawn_page())])
    ch = _challenge(tmp_path, {"paint.tns": doc})
    r = T.solve(ch, PINK, ocr="off")
    assert r.status == "candidate" and r.flags == ("PINK{typ3d_on_the_page}",), r
    decoy = [e for e in r.evidence if e.kind == "decoy"]
    assert len(decoy) == 1 and decoy[0].detail.startswith("possible decoy: PINK{typ3d_on_the_page}: ")
    assert "text object 132 of the page files/paint.tns -> Problem1.xml" in decoy[0].detail
    assert "also draws 3 point(s) and 2 segment(s)" in decoy[0].detail
    assert (ch / decoy[0].path).read_bytes() == B.xml(_drawn_page())           # the page, written as XML
    assert "a possible decoy, not a proven flag" in r.notes and "OCR off" in r.notes
    render = [e for e in r.evidence if e.kind == "render"]
    assert len(render) == 1 and "3 point(s), 2 segment(s)" in render[0].detail and "hidden" not in render[0].detail
    im, _ = _picture((ch / render[0].path).read_bytes())
    assert im.width == T.RENDER_WIDTH
    report = json.loads((ch / "recon" / "tns_nspire" / "report.json").read_text())
    assert report["schema"] == 1 and report["engine"] == T.ENGINE and report["ocr"] == "off"
    assert [m["name"] for m in report["documents"]["files/paint.tns"]["members"]] == ["Document.xml", "Problem1.xml"]
    assert report["documents"]["files/paint.tns"]["members"][1]["crc_ok"] is True
    assert report["findings"][0]["kind"] == "document-text" and report["pages"][0]["points"] == 3
    assert [(e.detail, e.path) for e in r.evidence if e.kind == "carve"] == [("report written", "recon/tns_nspire/report.json")]
    SolverResult.from_json(r.to_json())


def test_flag_shaped_text_in_a_document_page_with_nothing_drawn_is_still_only_a_candidate(tmp_path):
    notes = ("doc", {"ver": "1.0"}, [("note", {}, ["the flag is PINK{in_a_n0tes_page}"])])
    doc = B.container([B.member("Problem1.xml", B.xml(notes))])                # plain XML, not TIXC
    r = T.solve(_challenge(tmp_path, {"notes.tns": doc}), PINK)
    assert r.status == "candidate" and r.flags == ("PINK{in_a_n0tes_page}",)
    assert [e.kind for e in r.evidence if e.kind in ("decoy", "match", "decode")] == ["decoy"]
    assert "flag-shaped text in the document page files/notes.tns -> Problem1.xml" in _details(r)[0]
    assert "draws" not in _details(r)[0]


def test_a_decoded_flag_comes_before_document_text_and_two_values_are_candidates(tmp_path):
    flag = "PINK{the_r3al_one}"
    main, lib = _two_documents(flag)
    notes = ("doc", {"ver": "1.0"}, [("note", {}, ["PINK{typ3d_decoy}"])])
    files = {"main.tns": main, "lib_demo.tns": lib, "page.tns": B.container([B.member("Problem1.xml", B.xml(notes))])}
    r = T.solve(_challenge(tmp_path, files), PINK)
    assert r.status == "candidate" and r.flags == (flag, "PINK{typ3d_decoy}")
    assert "PINK{typ3d_decoy} is text typed into a document page" in r.notes and f"{flag} is text" not in r.notes


@crypto
@pil
def test_a_flag_read_by_ocr_is_a_candidate_ranked_before_document_text(tmp_path):
    doc = B.container([B.xml_page("Problem1.xml", _drawn_page())])
    seen = []

    def read(png, deadline=None):
        seen.append(png[:8])
        return "PINK(drawn_fl4g)\nsome other line\n"                      # the brace read as a bracket
    r = T.solve(_challenge(tmp_path, {"paint.tns": doc}), PINK, read=read)
    assert seen == [b"\x89PNG\r\n\x1a\n"]                                        # the rendering is what OCR is given
    assert r.status == "candidate" and r.flags == ("PINK{drawn_fl4g}", "PINK{typ3d_on_the_page}"), r
    ocr = [e for e in r.evidence if e.kind == "ocr"]
    assert len(ocr) == 1 and "read by OCR from the rendering of files/paint.tns -> Problem1.xml" in ocr[0].detail
    assert ocr[0].path.endswith("Problem1.xml.png")
    assert "OCR of files/paint.tns -> Problem1.xml: PINK(drawn_fl4g) / some other line" in r.notes
    report = json.loads((tmp_path / "challenge" / "recon" / "tns_nspire" / "report.json").read_text())
    assert report["ocr"] == "run" and report["pages"][0]["ocr"].startswith("PINK(drawn_fl4g)")


@crypto
@pil
def test_a_drawn_page_with_no_flag_is_unsure_and_says_whether_ocr_ran(tmp_path, monkeypatch):
    doc = B.container([B.xml_page("Problem1.xml", _drawn_page(text="g_"))])
    ch = _challenge(tmp_path, {"paint.tns": doc})
    r = T.solve(ch, PINK, read=lambda png, deadline=None: "A g_ tn")
    assert r.status == "unsure" and not r.flags and "OCR of files/paint.tns -> Problem1.xml: A g_ tn" in r.notes
    assert "text objects ['g_']" in [e for e in r.evidence if e.kind == "render"][0].detail
    import shutil
    monkeypatch.setattr(shutil, "which", lambda name: None)
    r = T.solve(ch, PINK)
    assert r.status == "unsure" and "OCR not run: tesseract is not on PATH" in r.notes
    r = T.solve(ch, PINK, ocr="on")
    assert r.status == "blocked" and "ocr=on" in r.notes and "tesseract is not on PATH" in r.notes
    r = T.solve(ch, PINK, ocr="off")
    assert r.status == "unsure" and "OCR off" in r.notes


@crypto
@pil
def test_an_ocr_call_that_fails_or_runs_out_of_time_is_a_note_not_a_crash(tmp_path):
    ch = _challenge(tmp_path, {"paint.tns": B.container([B.xml_page("Problem1.xml", _drawn_page(text="g_"))])})

    def refused(png, deadline=None):
        raise PermissionError("intake network guard: subprocess.Popen refused")
    r = T.solve(ch, PINK, read=refused)
    assert r.status == "unsure" and "not read by OCR: PermissionError: intake network guard" in r.notes
    calls = []
    r = T.solve(ch, PINK, read=lambda png, deadline=None: calls.append(1) or "x", seconds=-1)
    assert calls == [] and "not read by OCR: out of time" in r.notes


@crypto
@pil
def test_hidden_objects_and_objects_not_drawn_are_counted_in_the_result(tmp_path):
    tree = B.geometry(points=[(1, 0.0, 0.0), (2, 4.0, 0.0, False)], segments=[(3, 1, 2, False)],
                      extra=[("gg:circle", {}, [("gg:id", {}, ["9"]), ("gg:par", {}, ["1 2 "])])])
    r = T.solve(_challenge(tmp_path, {"p.tns": B.container([B.xml_page("Problem1.xml", tree)])}), PINK, ocr="off")
    assert r.status == "unsure"
    assert "2 point(s), 1 segment(s), 2 hidden (red)" in [e for e in r.evidence if e.kind == "render"][0].detail
    assert "not drawn: axes_system x1, circle x1" in r.notes


@pytest.mark.needs_tool("tesseract", "py:PIL", "py:Cryptodome")
def test_tesseract_reads_the_text_of_a_rendering(tmp_path):
    tree = B.geometry(points=[(1, 0.0, 0.0), (2, 60.0, 0.0)], segments=[(3, 1, 2)],
                      texts=[(9, "CALCULATOR", 5.0, 14.0, 50.0, 8.0)])
    r = T.solve(_challenge(tmp_path, {"p.tns": B.container([B.xml_page("Problem1.xml", tree)])}), PINK, ocr="on", seconds=240)
    assert r.status == "unsure" and "CALCULATOR" in r.notes.split("OCR of files/p.tns -> Problem1.xml: ", 1)[1]


# ------------------------------------------------------------------ the engine around them

def test_a_challenge_with_no_document_is_none_and_writes_nothing(tmp_path):
    ch = _challenge(tmp_path, {"notes.txt": b"hello", "fake.tns": b"PK\x03\x04 not a TI document"})
    r = T.solve(ch, PINK)
    assert r.status == "none" and r.notes == "no file of the challenge is a TI-Nspire document (*TIMLP)"
    assert not (ch / "recon").exists()
    with pytest.raises(FileNotFoundError):
        T.solve(tmp_path / "absent", PINK)


def test_examine_reads_only_the_documents_among_the_files_it_is_given():
    doc = B.container([B.member("a.py", b'print("PINK{giv3n_as_bytes}")')])
    rep = T.examine({"notes.txt": b"hello", "b.tns": doc, "c.bin": b"\x00\x01"}, FF)
    assert list(rep.docs) == ["b.tns"] and rep.notes == [] and rep.written == []
    assert [(f.flag, f.kind, f.file, f.member, f.path) for f in rep.findings] == [
        ("PINK{giv3n_as_bytes}", "literal", "b.tns", "a.py", None)]
    main, lib = _two_documents("PINK{wh3re_it_was}")
    rep = T.examine({"main.tns": main, "lib_demo.tns": lib}, FF)
    assert [(f.flag, f.kind, f.file, f.member) for f in rep.findings] == [
        ("PINK{wh3re_it_was}", "decoded", "main.tns", "main.py")]


def test_a_flag_in_a_member_that_is_not_text_is_still_found(tmp_path):
    blob = bytes(range(256)) + b"PINK{in_a_binary_m3mber}" + bytes(64)
    r = T.solve(_challenge(tmp_path, {"a.tns": B.container([B.stored("res.bin", blob)])}), PINK)
    assert r.status == "solved" and r.flags == ("PINK{in_a_binary_m3mber}",)


def test_what_the_reader_could_not_settle_is_in_the_result_notes(tmp_path):
    wrong = B.member("a.py", b"x = 1")
    wrong.crc ^= 1
    cut = B.container([B.member("b.py", b"y = 2"), B.member("c.py", _noise(400))], directory=False)[:-50]
    files = {"crc.tns": B.container([wrong]), "cut.tns": cut,
             "xml.tns": B.container([B.member("Problem1.xml", b"<doc><open></doc>")])}
    r = T.solve(_challenge(tmp_path, files), PINK)
    assert r.status == "none"
    assert "files/crc.tns -> a.py: size or CRC-32 differs from the header" in r.notes
    assert "files/cut.tns -> c.py was not read: it runs past the end of the file" in r.notes
    assert "files/cut.tns: the walk stopped at 'c.py'" in r.notes and "files/cut.tns: TI-Nspire document (container 0500), 1 of 2" in r.notes
    assert "files/xml.tns: Problem1.xml: the XML does not parse" in r.notes


def test_bad_options_are_blocked_by_name(tmp_path):
    ch = _challenge(tmp_path, {"a.tns": B.container([B.member("a.py", b"x = 1")])})
    assert "seconds must be a number" in T.solve(ch, PINK, seconds="soon").notes
    r = T.solve(ch, PINK, ocr="maybe")
    assert r.status == "blocked" and "ocr must be auto, on or off" in r.notes
    with pytest.raises(ValueError, match="ocr must be"):
        T.examine({}, FF, ocr="maybe")


def test_members_are_written_under_the_out_folder_whatever_they_are_called(tmp_path):
    doc = B.container([B.member("../../escape.py", b"x = 1"), B.member("/abs/olute.py", b"y = 2"), B.member("...", b"z")])
    ch = _challenge(tmp_path, {"sub/odd name.tns": doc})
    out = tmp_path / "out"
    r = T.solve(ch, PINK, out=str(out))
    assert r.status == "none"
    written = sorted(p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file())
    assert written == ["files_sub_odd_name.tns/00-escape.py", "files_sub_odd_name.tns/01-abs_olute.py",
                       "files_sub_odd_name.tns/02-member", "report.json"]
    assert not (tmp_path / "escape.py").exists() and not (ch / "recon").exists()
    assert (out / "files_sub_odd_name.tns" / "00-escape.py").read_bytes() == b"x = 1"


def test_an_existing_link_at_an_output_path_is_replaced_not_followed(tmp_path):
    ch = _challenge(tmp_path, {"a.tns": B.container([B.member("a.py", b"x = 1")])})
    victim = tmp_path / "victim.txt"
    victim.write_bytes(b"keep me")
    out = ch / "recon" / "tns_nspire" / "files_a.tns"
    out.mkdir(parents=True)
    (out / "00-a.py").symlink_to(victim)
    T.solve(ch, PINK)
    assert victim.read_bytes() == b"keep me" and not (out / "00-a.py").is_symlink()
    assert (out / "00-a.py").read_bytes() == b"x = 1"


def test_the_documents_of_a_challenge_come_from_the_sweeps_copy_first(tmp_path, monkeypatch):
    doc = B.container([B.member("a.py", b"x = 1")])
    ch = _challenge(tmp_path, {"a.tns": doc, "b.txt": b"*TIMLQ no"})
    notes = []
    assert list(T.challenge_documents(ch, notes)) == ["files/a.tns"] and notes == []
    (ch / "unpacked" / "zip.unpacked").mkdir(parents=True)
    (ch / "unpacked" / "zip.unpacked" / "inner.tns").write_bytes(doc)
    (ch / "unpacked" / "recon").mkdir()
    (ch / "unpacked" / "recon" / "old.tns").write_bytes(doc)
    (ch / "unpacked" / "link.tns").symlink_to(ch / "files" / "a.tns")
    assert list(T.challenge_documents(ch, notes)) == ["unpacked/zip.unpacked/inner.tns"]
    bare = tmp_path / "bare"
    bare.mkdir()
    (bare / "x.tns").write_bytes(doc)
    assert list(T.challenge_documents(bare, notes)) == ["x.tns"]
    monkeypatch.setattr(T, "MAX_FILE", len(doc) - 1)
    assert T.challenge_documents(bare, notes) == {} and notes == [f"x.tns is a TI-Nspire document over {len(doc) - 1} bytes: not read"]
    r = T.solve(bare, PINK)
    assert r.status == "none" and "x.tns is a TI-Nspire document over" in r.notes


def test_a_document_cut_inside_its_magic_header_is_a_note(tmp_path):
    r = T.solve(_challenge(tmp_path, {"cut.tns": b"*TIMLP05", "ok.tns": B.container([B.member("a.py", b"x = 1")])}), PINK)
    assert r.status == "none" and "files/cut.tns: cut short inside the *TIMLP header" in r.notes
    assert "files/ok.tns: TI-Nspire document (container 0500), 1 of 1 member(s) read" in r.notes


def test_more_documents_than_the_cap_are_named_not_dropped(tmp_path, monkeypatch):
    monkeypatch.setattr(T, "MAX_DOCS", 1)
    doc = B.container([B.member("a.py", b"x = 1")])
    r = T.solve(_challenge(tmp_path, {"a.tns": doc, "b.tns": doc}), PINK)
    assert "more than 1 TI-Nspire documents: files/b.tns and what follows are not read" in r.notes


def test_the_challenge_id_comes_from_the_option_or_challenge_json(tmp_path):
    ch = _challenge(tmp_path, {"a.tns": B.container([B.member("a.py", b"x = 1")])})
    assert T.solve(ch, PINK).challenge_id is None
    (ch / "challenge.json").write_text(json.dumps({"id": 14, "name": "TNS 2"}))
    assert T.solve(ch, PINK).challenge_id == "14"
    assert T.solve(ch, PINK, challenge_id="x9").challenge_id == "x9"
    for doc in ({"id": ""}, {"id": None}, {"name": "no id"}, ["not", "an", "object"]):
        (ch / "challenge.json").write_text(json.dumps(doc))
        assert T.solve(ch, PINK).challenge_id is None
    assert T.solve(ch, PINK).engine == "toolkits.tns_nspire"


# ------------------------------------------------------------------ manifest, routing, intake

def _mine():
    return [m for m in _manifest.discover() if m.id == T.ENGINE]


def test_the_manifest_is_a_cheap_contract_engine_that_intake_runs_on_the_magic():
    m = _manifest.load(REPO / "solvers" / "toolkits" / "tns_nspire.manifest.toml")
    assert m.id == T.ENGINE and m.entry.kind == "function" and m.entry.function == "solve"
    assert m.cost_class == "cheap" and m.status == "active"
    assert set(m.needs_tools) == {"py:Cryptodome"}                    # Pillow and tesseract are optional: not needs
    assert m.intake.select == "files" and m.intake.run == "challenge" and m.intake.match == ("magic:*TIMLP",)
    assert not m.intake.spawns and m.intake.timeout > T.DEFAULT_SECONDS


def test_the_router_puts_a_tns_handout_here_first_whatever_the_category(tmp_path):
    ch = _challenge(tmp_path, {"calc.bin": B.container([B.member("a.py", b"x = 1")])})    # by magic, not by name
    for category in ("rev", "misc", "forensics"):
        hits = router.route(category, "I really like my calculator", ch / "files")
        assert hits[0].manifest.id == T.ENGINE, (category, [h.manifest.id for h in hits[:3]])
    named = _challenge(tmp_path / "n", {"empty.tns": b"not one"})
    assert T.ENGINE in [h.manifest.id for h in router.route("rev", "", named / "files")]           # by extension
    assert T.ENGINE in [h.manifest.id for h in router.route("misc", "a TI-Nspire document")]
    plain = _challenge(tmp_path / "p", {"notes.txt": b"hello"})
    assert T.ENGINE not in [h.manifest.id for h in router.route("rev", "reverse this binary", plain / "files")]


def test_intake_plans_it_for_a_document_and_not_for_other_files(tmp_path):
    hook = G.Guard("hook", (), "test: audit hook only")
    ch = _challenge(tmp_path, {"calc.tns": B.container([B.member("a.py", b"x = 1")])})
    plan = E.plan(_mine(), "rev", "", ch / "files", guard=hook)
    assert [j.engine for j in plan.jobs] == [T.ENGINE]                           # it runs under the hook guard too
    other = _challenge(tmp_path / "o", {"calc.tns": b"PK\x03\x04 a zip named .tns"})
    assert not E.plan(_mine(), "rev", "", other / "files", guard=hook).jobs


@crypto
@pil
def test_intake_runs_it_under_the_audit_hook_guard(tmp_path):
    """The real intake run: a child process under the Python audit hook (no network, no program started),
    on an encrypted document. Decryption, TIXC and the rendering need no other program; the OCR call is
    refused by the guard or finds no tesseract, and the result says which."""
    hook = G.Guard("hook", (), "test: audit hook only")
    flag = "PINK{intak3_reads_it}"
    main, lib = _two_documents(flag)
    paint = B.container([B.xml_page("Document.xml", B.settings()), B.xml_page("Problem1.xml", _drawn_page(text="g_"))])
    ch = _challenge(tmp_path, {"main.tns": main, "lib_demo.tns": lib, "paint.tns": paint})
    plan = E.plan(_mine(), "rev", "", ch / "files", guard=hook)
    ctx = E.Context(challenge_dir=ch, folder=ch / "files", out_root=ch / "recon" / "engines", profile=PINK,
                    guard=hook, root=REPO, python=sys.executable, challenge_id="b132", record=False,
                    workdir=tmp_path / "work")
    run = E.run_job(plan.jobs[0], ctx, timeout=120)
    out = (ch / run.output).read_text()
    assert run.status == "ok" and run.result_status == "solved", (run, (ch / run.errors).read_text()[-800:])
    assert run.flags == (flag,) and run.disputed == ()               # a decoded flag is not disputed
    result = json.loads([ln for ln in out.splitlines() if ln.strip()][-1])
    assert "paint.tns: TI-Nspire document (container 0500), 2 of 2 member(s) read" in result["notes"]
    assert "OCR not run" in result["notes"] or "not read by OCR" in result["notes"]
    assert (ch / "recon" / "tns_nspire" / "files_paint.tns" / "01-Problem1.xml.png").is_file()


# ------------------------------------------------------------------ intake does not call a possible decoy solved

def _merged(runs, sweep_flags=()):
    rep = I.Report("14", None, SolverResult("none", engine="intake", challenge_id="14"))
    for f in sweep_flags:
        rep.flags[f] = ["sweep plain in paint.tns -> Problem1.xml"]
    rep.runs = list(runs)
    I._merge(rep, PINK, "")
    return rep, I._result(rep, "14")


def _run(flags=(), disputed=()):
    return E.EngineRun(T.ENGINE, (), "ok", 0, 0.1, "recon/engines/out.txt", "recon/engines/err.txt", "candidate",
                       tuple(flags), "", tuple(disputed))


def test_a_flag_an_engine_disputes_is_a_candidate_even_when_the_sweep_found_it_too():
    decoy = "PINK{typ3d_on_the_page}"
    rep, res = _merged([_run([decoy], [decoy])], sweep_flags=[decoy])
    assert res.status == "candidate" and res.flags == (decoy,)
    assert "reports it as a possible decoy" in res.notes and T.ENGINE in res.notes
    assert rep.disputed == {decoy: f"engine {T.ENGINE} reports it as a possible decoy (recon/engines/out.txt)"}
    assert rep.to_dict()["disputed"] == rep.disputed
    assert autosubmit.eligible(res.status, res.flags, PINK)[0] is None        # nothing is sent on its own
    rep, res = _merged([_run([decoy], [decoy])])                              # found by the engine alone
    assert res.status == "candidate" and res.flags == (decoy,)


def test_without_a_dispute_or_with_another_flag_disputed_the_merge_is_as_before():
    flag = "PINK{the_r3al_one}"
    rep, res = _merged([_run([flag])], sweep_flags=[flag])
    assert res.status == "solved" and rep.disputed == {}
    rep, res = _merged([_run([flag], ["PINK{s0me_other}"])], sweep_flags=[flag])
    assert res.status == "solved" and res.flags == (flag,)                    # the dispute names a value nobody found
    rep, res = _merged([_run([flag], ["not a flag at all"])], sweep_flags=[flag])
    assert res.status == "solved" and rep.disputed == {}
    rep, res = _merged([_run([flag, "PINK{typ3d}"], ["PINK{typ3d}"])])        # two values: a candidate as ever
    assert res.status == "candidate" and res.flags == (flag, "PINK{typ3d}")


@crypto
@pil
def test_the_sweep_and_the_engine_together_keep_intake_from_solving_on_page_text(tmp_path):
    """Pink 14 rebuilt: the sweep's walk reads the flag-shaped text out of the decrypted page and, since the
    walk marks that member as where decoys sit, disputes it itself; the engine's run on the same challenge
    marks it a possible decoy too; the merged intake result is a candidate, so the capped auto-submit
    stands down. The decoy here has no decoy word in it, so the plausibility check alone would not have
    stopped it."""
    hook = G.Guard("hook", (), "test: audit hook only")
    decoy = "PINK{typ3d_on_the_page}"
    ch = tmp_path / "work" / "14-tns-2"
    (ch / "files").mkdir(parents=True)
    (ch / "challenge.json").write_text(json.dumps({"id": 14, "name": "TNS 2", "category": "Reversing", "description": ""}))
    (ch / "files" / "paint.tns").write_bytes(B.container([B.xml_page("Document.xml", B.settings()),
                                                          B.xml_page("Problem1.xml", _drawn_page(decoy))]))
    swept = sweep.sweep(ch, PINK)
    assert swept.result.status == "candidate" and swept.result.flags == (decoy,)   # the sweep alone stands down
    assert swept.disputed == {decoy: {"why": f"only in {T.DOCUMENT_DOUBT}: paint.tns -> Problem1.xml",
                                      "engine": T.ENGINE}}
    assert "possible decoy" in swept.result.notes and T.ENGINE in swept.result.notes
    assert json.loads((ch / "unpacked" / sweep.REPORT).read_text())["disputed"] == swept.disputed
    assert "decoy_marker" not in flagcheck.check(decoy, PINK, source="intake").codes()
    plan = E.plan(_mine(), "Reversing", "", ch / "unpacked", guard=hook)
    ctx = E.Context(challenge_dir=ch, folder=ch / "unpacked", out_root=ch / "recon" / "engines", profile=PINK,
                    guard=hook, root=REPO, python=sys.executable, challenge_id="14", record=False,
                    workdir=tmp_path / "work")
    run = E.run_job(plan.jobs[0], ctx, timeout=120)
    assert run.status == "ok" and run.result_status == "candidate", (run, (ch / run.errors).read_text()[-800:])
    assert run.flags == (decoy,) and run.disputed == (decoy,) and run.to_dict()["disputed"] == [decoy]
    rep = I.Report("14", ch, SolverResult("none", engine="intake", challenge_id="14"))
    rep.sweep, rep.runs = swept, [run]
    I._merge(rep, PINK, "")
    res = I._result(rep, "14")
    assert res.status == "candidate" and res.flags == (decoy,) and "possible decoy" in res.notes
    flag, why = autosubmit.eligible(res.status, res.flags, PINK)
    assert flag is None and "ambiguous" in why


# ------------------------------------------------------------------ the sweep's walk (tools/archive_expand.py)

def _walk(name, data, **kw):
    w = ae.Walk(**kw)
    out = {}
    ae.expand(name, data, out, opts=w)
    return out, w


@crypto
def test_the_wide_walk_opens_a_document_and_gives_each_member_as_its_content():
    doc = B.container([B.xml_page("Problem1.xml", PAGE), B.member("main.py", SCRIPT)])
    out, w = _walk("calc.tns", doc)
    assert [k for k in out if "->" in k or k == "calc.tns"] == ["calc.tns", "calc.tns -> Problem1.xml", "calc.tns -> main.py"]
    assert out["calc.tns -> Problem1.xml"] == B.xml(PAGE) and out["calc.tns -> main.py"] == SCRIPT
    assert w.notes == [] and w.count == 2 and w.total == len(B.xml(PAGE)) + len(SCRIPT)
    assert [chain for chain, _, _ in w.rows] == [("calc.tns",), ("calc.tns", "Problem1.xml"), ("calc.tns", "main.py")]


def test_the_walk_follows_a_document_inside_a_zip_and_a_zip_inside_a_document():
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as z:
        z.writestr("deep.txt", b"deep")
    doc = B.container([B.member("main.py", SCRIPT), B.stored("bundle.zip", inner.getvalue())])
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w") as z:
        z.writestr("handout/calc.tns", doc)
    out, w = _walk("handout.zip", outer.getvalue())
    assert out["handout/calc.tns -> main.py"] == SCRIPT
    assert out["bundle.zip -> deep.txt"] == b"deep" and w.notes == []
    assert ("handout.zip", "handout/calc.tns", "bundle.zip", "deep.txt") in [c for c, _, _ in w.rows]


def test_the_walk_loads_the_reader_once_by_path_and_says_when_it_is_not_there(monkeypatch):
    assert ae._load_tns() is T                                    # the module the engine runs as: one copy
    monkeypatch.delitem(sys.modules, "tns_nspire")
    fresh = ae._load_tns()
    assert fresh is not T and sys.modules["tns_nspire"] is fresh and ae._load_tns() is fresh
    assert Path(fresh.__file__) == REPO / "solvers" / "toolkits" / "tns_nspire.py"
    monkeypatch.setattr(ae, "_load_tns", lambda: None)            # a copy of tools/ with no solvers/ beside it
    doc = B.container([B.member("main.py", SCRIPT)])
    out, w = _walk("calc.tns", doc)
    assert out == {"calc.tns": doc}
    assert w.notes == ["'calc.tns' is a TI-Nspire document but solvers/toolkits/tns_nspire.py is not beside this tools/: not opened"]


def test_the_legacy_walk_leaves_a_document_opaque():
    doc = B.container([B.member("main.py", SCRIPT)])
    out = {}
    ae.expand("calc.tns", doc, out)
    assert out == {"calc.tns": doc}


def test_the_walk_notes_every_member_it_does_not_read(monkeypatch):
    doc = B.container([B.member("big.py", bytes(5000)), B.Entry("odd.bin", 14, b"?", 1, 0), B.member("ok.py", b"x = 1")])
    out, w = _walk("calc.tns", doc, max_member=4999)
    assert [k for k in out if "->" in k] == ["calc.tns -> ok.py"]
    assert any("skipped 'calc.tns -> big.py': 5000 bytes stated, over the member limit of 4999" in n for n in w.notes)
    assert any("skipped 'calc.tns -> odd.bin'" in n and "method 14" in n for n in w.notes)
    cut = B.container([B.member("a.py", b"x = 1"), B.member("b.py", _noise(400))], directory=False)[:-50]
    out, w = _walk("cut.tns", cut)
    assert [k for k in out if "->" in k] == ["cut.tns -> a.py"]
    assert any(n.startswith("'cut.tns': the walk stopped at 'b.py'") for n in w.notes)
    out, w = _walk("short.tns", b"*TIMLP05")
    assert list(out) == ["short.tns"] and any("starts like a TI-Nspire document but did not open" in n for n in w.notes)
    monkeypatch.setitem(sys.modules, "Cryptodome.Cipher", None)
    out, w = _walk("enc.tns", B.container([B.Entry("Problem1.xml", 13, bytes(80), 10, 0)]))
    assert list(out) == ["enc.tns"] and any("pycryptodomex (py:Cryptodome)" in n for n in w.notes)


def test_the_walk_counts_members_against_its_budgets_and_its_depth():
    doc = B.container([B.member(f"m{i}.py", b"x" * 10) for i in range(5)])
    out, w = _walk("calc.tns", doc, max_members=2)
    assert [k for k in out if "->" in k] == ["calc.tns -> m0.py", "calc.tns -> m1.py"] and w.full
    assert any("stopped at 'calc.tns -> m2.py'" in n for n in w.notes)
    nested = B.container([B.stored("in.tns", B.container([B.member("deep.py", b"x")]))])
    out, w = _walk("out.tns", nested, max_depth=0)
    assert "in.tns -> deep.py" not in out and "out.tns -> in.tns" in out
    assert any("'in.tns' was not opened: it lies 1 archives deep" in n for n in w.notes)
    out, w = _walk("out.tns", nested, max_depth=1)
    assert out["in.tns -> deep.py"] == b"x"


def test_a_broken_tixc_page_reaches_the_walk_as_stored_with_a_note():
    stream = b"TIXC0100-1.0?><t>\x0e\x07"
    out, w = _walk("calc.tns", B.container([B.member("Problem1.xml", stream)]))
    assert out["calc.tns -> Problem1.xml"] == stream
    assert any(n.startswith("'calc.tns -> Problem1.xml': its TIXC stream did not decode") for n in w.notes)


@crypto
def test_the_sweep_finds_a_flag_inside_a_document_member(tmp_path):
    flag = "PINK{sw3pt_from_a_tns_member}"
    doc = B.container([B.xml_page("Document.xml", B.settings()), B.member("main.py", f'print("{flag}")'.encode())])
    ch = tmp_path / "work" / "11-tns"
    (ch / "files").mkdir(parents=True)
    (ch / "challenge.json").write_text(json.dumps({"id": 11, "name": "TNS", "category": "Reversing", "description": ""}))
    (ch / "files" / "calc.tns").write_bytes(doc)
    assert flag.encode() not in doc
    rep = sweep.sweep(ch, PINK)
    assert rep.result.status == "solved" and rep.result.flags == (flag,)
    chains = [" -> ".join(e.chain) for e in rep.manifest]
    assert "calc.tns -> main.py" in chains and "calc.tns -> Document.xml" in chains
    assert (ch / "unpacked" / "calc.tns.unpacked" / "Document.xml").read_bytes() == B.xml(B.settings())
    # and the engine, run on the swept challenge, reads the document from the sweep's copy
    r = T.solve(ch, PINK)
    assert r.status == "solved" and r.flags == (flag,) and "unpacked/calc.tns" in r.notes


def test_the_fingerprint_step_names_the_format_and_this_engine():
    res = fingerprint.analyze("mystery.bin", b"*TIMLP0500" + bytes(300))
    assert res.candidates and res.candidates[0].source == "magic"
    assert res.candidates[0].label == "TI-Nspire document (.tns)" and "toolkits.tns_nspire" in res.candidates[0].why


# ------------------------------------------------------------------ verification round 1 (B-132 fixer)

def test_a_member_with_bit_3_set_that_still_states_its_sizes_is_read_and_the_walk_goes_on():
    flagged = B.member("a.py", b"x = 1")
    flagged.flags = 8                                             # a data descriptor follows, but the sizes are here too
    box = T.read_container(B.container([flagged, B.member("b.py", b"y = 2")]))
    assert [(m.name, m.data, m.problem) for m in box.members] == [("a.py", b"x = 1", None), ("b.py", b"y = 2", None)]
    assert box.notes == []


def test_only_an_explicit_asho_of_0_hides_an_object():
    tree = B.geometry(extra=[
        ("gg:point", {}, [("gg:id", {}, ["1"]), ("gg:x", {}, ["1.0"]), ("gg:y", {}, ["1.0"]), ("gg:asho", {}, [])]),
        ("gg:point", {}, [("gg:id", {}, ["2"]), ("gg:x", {}, ["2.0"]), ("gg:y", {}, ["1.0"]), ("gg:asho", {}, [" 0 "])]),
        ("gg:point", {}, [("gg:id", {}, ["3"]), ("gg:x", {}, ["3.0"]), ("gg:y", {}, ["1.0"]), ("gg:asho", {}, ["2"])])])
    page = T.parse_page(B.xml(tree))
    assert {k: p.hidden for k, p in page.points.items()} == {"1": False, "2": True, "3": False}


def test_a_free_text_of_seven_or_more_words_without_the_format_numbers_comes_back_whole():
    words = "the flag is not PINK{h3re} at all today"                # nine words, no six numbers in front
    tree = B.geometry(extra=[("gg:text", {}, [("gg:id", {}, ["40"]), ("gg:chrs", {}, [words + "\n"]),
                                              ("gg:x", {}, ["1.0"]), ("gg:y", {}, ["2.0"])]),
                             ("gg:text", {}, [("gg:id", {}, ["41"]), ("gg:chrs", {}, ["1 2 3 4 5 six seven eight\n"]),
                                              ("gg:x", {}, ["1.0"]), ("gg:y", {}, ["4.0"])]),
                             ("gg:text", {}, [("gg:id", {}, ["42"]), ("gg:chrs", {}, ["1 −1 2 0 0 0 a b c\n"]),
                                              ("gg:x", {}, ["1.0"]), ("gg:y", {}, ["6.0"])])])
    page = T.parse_page(B.xml(tree))
    assert [(t.id, t.text) for t in page.texts] == [
        ("40", words), ("41", "1 2 3 4 5 six seven eight"), ("42", "1 −1 2 0 0 0 a b c")]
    assert T._chars("1 1 2 0 -3 0 typed words here") == "typed words here"   # six numbers (one negative): dropped


def test_the_index_list_caps_hold_exactly(monkeypatch):
    flag = "PINK{past_the_cap}"
    noise = " ".join(["1"] * 8)
    runs = "\n".join(f"r{i} = [{noise}]" for i in range(2)) + "\nc = [" + " ".join(str(i) for i in _indexes(flag)) + "]"
    texts = {"a": runs, "b": f'"{ALPHABET}"'}
    monkeypatch.setattr(T, "MAX_LISTS", 2)                        # the flag's run is the third: not tried
    assert T.index_decodes(texts, FF) == []
    monkeypatch.setattr(T, "MAX_LISTS", 3)                        # now it is the last one tried
    assert [g[0] for g in T.index_decodes(texts, FF)] == [flag]
    strings = {"a": "c = [" + " ".join(str(i) for i in _indexes(flag)) + "]",
               "b": "\n".join(f's{i} = "{"z" * 20}"' for i in range(2)) + f'\nalphabet = "{ALPHABET}"'}
    monkeypatch.setattr(T, "MAX_STRINGS", 2)
    assert T.index_decodes(strings, FF) == []
    monkeypatch.setattr(T, "MAX_STRINGS", 3)
    assert [g[0] for g in T.index_decodes(strings, FF)] == [flag]


def test_the_walk_decodes_no_more_than_its_budget_and_one_member():
    """60 members of 1 MiB of zeros (a few KiB stored) under a walk of 2 MiB in all: the walk keeps two,
    stops, and never holds the other members' decoded bytes (an eager read held all 60 MiB at once)."""
    import tracemalloc
    body = bytes(1 << 20)
    payload, crc = B.deflate(body), zlib.crc32(body)
    doc = B.container([B.Entry(f"m{i:02d}.bin", 8, payload, len(body), crc) for i in range(60)])
    assert len(doc) < 150_000
    tracemalloc.start()
    try:
        out, w = _walk("bomb.tns", doc, max_total=2 << 20)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert [k for k in out if "->" in k] == ["bomb.tns -> m00.bin", "bomb.tns -> m01.bin"] and w.full
    assert any("stopped at 'bomb.tns -> m02.bin'" in n for n in w.notes)
    assert peak < 12 << 20, peak                                  # 2 MiB kept, one more in hand, the walk's own copies


def test_once_a_nested_archive_spends_the_walk_no_later_member_is_even_decoded():
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as z:
        for i in range(3):
            z.writestr(f"f{i}.txt", b"z" * 10)
    doc = B.container([B.stored("bundle.zip", inner.getvalue()), B.Entry("odd.bin", 14, b"?", 1, 0),
                       B.member("late.py", b"x = 1")])
    out, w = _walk("calc.tns", doc, max_members=3)               # bundle.zip and two of its members fill it
    assert w.full and "calc.tns -> late.py" not in out
    assert not any("odd.bin" in n for n in w.notes), w.notes     # the member after the spent walk is never looked at


def test_a_member_that_inflates_past_the_walks_room_is_cut_not_held(monkeypatch):
    big = B.member("liar.bin", bytes(5000))
    big.usize = 10                                                # states 10 bytes, inflates to 5000
    out, w = _walk("calc.tns", B.container([B.member("a.py", b"x" * 100), big]), max_total=1000)
    assert out["calc.tns -> a.py"] == b"x" * 100 and "calc.tns -> liar.bin" not in out
    assert any("skipped 'calc.tns -> liar.bin'" in n and "inflates past the member limit of 900" in n for n in w.notes)


def test_examine_stops_reading_at_its_total_limit_and_says_so(monkeypatch):
    monkeypatch.setattr(T, "MAX_TOTAL", 150)
    doc = B.container([B.member("a.py", b"a" * 100), B.member("b.py", b'"PINK{n0t_r3ad}"' + b"b" * 84),
                       B.member("c.py", b"c" * 10)])
    rep = T.examine({"d.tns": doc}, FF)
    rows = rep.docs["d.tns"]["members"]
    assert rows[0]["problem"] is None and rows[2]["problem"] is None             # 100 + 10 fit; 100 more do not
    assert "would pass the total limit of 150" in rows[1]["problem"] and rep.findings == []
    assert rep.notes == ["the total limit of 150 decoded bytes was reached at d.tns -> b.py: it and any later "
                         "member that does not fit are not read"]
    liar = B.member("l.py", b"l" * 100)
    liar.usize = 1
    rep = T.examine({"d.tns": B.container([B.member("a.py", b"a" * 100), liar])}, FF)
    assert "inflates past the member limit of 50" in rep.docs["d.tns"]["members"][1]["problem"]


def test_examine_reads_up_to_its_total_limit_exactly_and_not_one_byte_past(monkeypatch):
    monkeypatch.setattr(T, "MAX_TOTAL", 150)
    # 100 + 50 is exactly the limit: both are read; then a member of 0 bytes finds no room left
    doc = B.container([B.member("a.py", b"a" * 100), B.member("b.py", b"b" * 50), B.member("c.py", b"")])
    rep = T.examine({"d.tns": doc}, FF)
    rows = rep.docs["d.tns"]["members"]
    assert [r["problem"] for r in rows[:2]] == [None, None] and [r["bytes"] for r in rows[:2]] == [100, 50]
    assert "already decoded to 150 bytes, and 0 more would pass the total limit of 150" in rows[2]["problem"]
    assert rep.notes == ["the total limit of 150 decoded bytes was reached at d.tns -> c.py: it and any later "
                         "member that does not fit are not read"]
    # one byte more than the room left is refused by the total limit, before it is inflated
    doc = B.container([B.member("a.py", b"a" * 100), B.member("b.py", b"b" * 51), B.member("c.py", b"c" * 49)])
    rows = T.examine({"d.tns": doc}, FF).docs["d.tns"]["members"]
    assert rows[1]["problem"] == ("not read: the handout's documents already decoded to 100 bytes, and 51 more "
                                  "would pass the total limit of 150")
    assert rows[0]["problem"] is None and rows[2]["problem"] is None              # 100 + 49 still fit


def test_two_handout_paths_that_make_one_folder_name_keep_their_own_folders(tmp_path):
    a = B.container([B.member("m.py", b"from a")])
    b = B.container([B.member("m.py", b"from b")])
    c = B.container([B.member("m.py", b"from c")])
    ch = _challenge(tmp_path, {"a b.tns": a, "a_b.tns": b, "sub/a_b.tns": c})
    out = tmp_path / "out"
    T.solve(ch, PINK, out=str(out))
    got = {p.parent.name: p.read_bytes() for p in out.rglob("00-m.py")}
    assert got == {"files_a_b.tns": b"from a", "files_a_b.tns-2": b"from b", "files_sub_a_b.tns": b"from c"}
    used = set()                                                  # a folder name differing only in case is taken too
    assert [T._folder(f, used) for f in ("files/A.tns", "files/a.tns", "files/a.tns-2")] == [
        "files_A.tns", "files_a.tns-2", "files_a.tns-2-2"]
    used = set()
    assert [T._folder(f, used) for f in ("files/b.tns", "files/B.tns")] == ["files_b.tns", "files_B.tns-2"]


def test_the_ocr_reader_is_loaded_by_path_and_sys_path_is_left_alone(monkeypatch):
    monkeypatch.delitem(sys.modules, T.OCR_MODULE, raising=False)
    monkeypatch.delitem(sys.modules, "image_carve", raising=False)
    monkeypatch.setattr(sys, "path", [p for p in sys.path if Path(p).resolve() != REPO / "solvers" / "toolkits"])
    snapshot = list(sys.path)
    ic = T._ocr_module()
    assert Path(ic.__file__) == REPO / "solvers" / "toolkits" / "image_carve.py" and T._ocr_module() is ic
    added = [p for p in sys.path if p not in snapshot]
    # image_carve itself puts its own folder on the path for its siblings; this module adds nothing else
    assert all(Path(p).resolve() == REPO / "solvers" / "toolkits" for p in added), added
    assert str(T.HERE.parent / "common") not in added
    monkeypatch.setattr(T, "HERE", REPO / "absent")
    monkeypatch.delitem(sys.modules, T.OCR_MODULE)
    with pytest.raises(T.ToolMissing, match="image_carve.py is not beside this module"):
        T._ocr_module()
    assert T.OCR_MODULE not in sys.modules


def test_the_ocr_reader_takes_a_private_name_and_leaves_image_carve_to_a_normal_import(monkeypatch):
    assert T.OCR_MODULE != "image_carve" and "." not in T.OCR_MODULE
    monkeypatch.delitem(sys.modules, T.OCR_MODULE, raising=False)
    monkeypatch.delitem(sys.modules, "image_carve", raising=False)
    ic = T._ocr_module()
    assert sys.modules[T.OCR_MODULE] is ic and ic.__name__ == T.OCR_MODULE
    assert "image_carve" not in sys.modules                       # a later `import image_carve` is a normal import
    other = object()                                              # and one already there is neither used nor replaced
    monkeypatch.setitem(sys.modules, "image_carve", other)
    monkeypatch.delitem(sys.modules, T.OCR_MODULE)
    again = T._ocr_module()
    assert again is not other and sys.modules["image_carve"] is other and hasattr(again, "ocr_text")


def test_a_flag_proven_by_a_script_and_also_typed_on_a_page_is_solved_with_no_decoy_evidence(tmp_path):
    flag = "PINK{in_b0th_places}"
    notes = ("doc", {"ver": "1.0"}, [("note", {}, [flag])])
    doc = B.container([B.member("Problem1.xml", B.xml(notes)), B.member("main.py", f'print("{flag}")'.encode())])
    r = T.solve(_challenge(tmp_path, {"d.tns": doc}), PINK)
    assert r.status == "solved" and r.flags == (flag,)
    assert not [e for e in r.evidence if e.kind == "decoy"] and "possible decoy" not in r.notes
    also = [e for e in r.evidence if e.kind == "match" and "also flag-shaped text in the document page" in e.detail]
    assert len(also) == 1 and also[0].detail.startswith(f"{flag}: also ")
    run = _run([flag])
    run.result_status = "solved"
    rep, res = _merged([run], sweep_flags=[flag])
    assert res.status == "solved" and rep.disputed == {}


def test_a_flag_both_read_by_ocr_and_typed_on_the_page_is_still_a_possible_decoy():
    rep = T.Report(findings=[T.Finding("PINK{typ3d}", "ocr", "p.tns", "Problem1.xml", "read by OCR"),
                             T.Finding("PINK{typ3d}", "document-text", "p.tns", "Problem1.xml", "typed into text object 9")],
                   docs={"p.tns": {"version": "0500", "members": [], "notes": []}})
    r = T.result_of(rep)
    assert r.status == "candidate" and [e.kind for e in r.evidence] == ["ocr", "decoy"]
    assert "PINK{typ3d} is text typed into a document page" in r.notes


def _swept(tmp_path, doc, name="paint.tns"):
    ch = tmp_path / "work" / "14-tns"
    (ch / "files").mkdir(parents=True)
    (ch / "challenge.json").write_text(json.dumps({"id": 14, "name": "TNS", "category": "Reversing", "description": ""}))
    (ch / "files" / name).write_bytes(doc)
    return ch, sweep.sweep(ch, PINK)


def test_the_walk_marks_document_pages_and_not_scripts():
    doc = B.container([B.member("Problem1.xml", b"<doc/>"), B.member("main.py", SCRIPT), B.stored("res.bin", b"\x00")])
    _, w = _walk("calc.tns", doc)
    assert w.doubt == {("calc.tns", "Problem1.xml"): (T.DOCUMENT_DOUBT, T.ENGINE)}
    assert ae.Walk().doubt == {}


def test_without_any_engine_the_sweep_alone_keeps_intake_from_solving_on_page_text(tmp_path):
    """--no-engines, an engine that timed out or crashed, a missing module: intake has only the sweep."""
    decoy = "PINK{n0_engine_ran}"
    notes = ("doc", {"ver": "1.0"}, [("note", {}, [decoy])])
    ch, swept = _swept(tmp_path, B.container([B.stored("Problem1.xml", B.xml(notes))]))   # stored: in the .tns too
    assert decoy.encode() in (ch / "files" / "paint.tns").read_bytes()
    assert swept.result.status == "candidate" and list(swept.disputed) == [decoy]
    rep = I.Report("14", ch, SolverResult("none", engine="intake", challenge_id="14"))
    rep.sweep, rep.runs = swept, []
    I._merge(rep, PINK, "")
    res = I._result(rep, "14")
    assert res.status == "candidate" and res.flags == (decoy,) and "the sweep found it only in" in res.notes
    assert rep.disputed == {decoy: f"the sweep found it only in {T.DOCUMENT_DOUBT}: paint.tns -> Problem1.xml"}
    assert autosubmit.eligible(res.status, res.flags, PINK)[0] is None
    # an engine other than the reader, or the reader without a proof, does not lift it
    for run in (E.EngineRun("toolkits.other", (), "ok", 0, 0.1, "o", "e", "solved", (decoy,), ""), _run([decoy])):
        rep.runs, rep.disputed, rep.flags = [run], {}, {}
        I._merge(rep, PINK, "")
        assert I._result(rep, "14").status == "candidate", run
    proved = _run([decoy])
    proved.result_status = "solved"                               # the reader proved it from a script or a list
    rep.runs, rep.disputed, rep.flags = [proved], {}, {}
    I._merge(rep, PINK, "")
    assert I._result(rep, "14").status == "solved" and rep.disputed == {}
    still = _run([decoy], [decoy])
    still.result_status = "solved"                                # solved but disputing it: the dispute stands
    rep.runs, rep.disputed, rep.flags = [still], {}, {}
    I._merge(rep, PINK, "")
    assert I._result(rep, "14").status == "candidate"


def test_a_flag_the_sweep_also_finds_outside_the_page_is_not_disputed(tmp_path):
    flag = "PINK{in_a_scr1pt_too}"
    notes = ("doc", {"ver": "1.0"}, [("note", {}, [flag])])
    _, swept = _swept(tmp_path, B.container([B.member("Problem1.xml", B.xml(notes)),
                                             B.member("main.py", f'print("{flag}")'.encode())]))
    assert swept.result.status == "solved" and swept.disputed == {}
    other = tmp_path / "o"
    other.mkdir()
    _, swept = _swept(other, B.container([B.member("Problem1.xml", B.xml(notes)), B.member("Problem2.xml", B.xml(notes))]))
    assert swept.result.status == "candidate" and list(swept.disputed) == [flag]   # two pages: still only pages
    assert sweep._disputes({flag: []}, [], {("x",): ("w", "e")}) == {}              # no hit, no dispute


# ------------------------------------------------------------------ the Pink 2026 handouts (never committed)

PINK11 = "e6a13fc86cf03770e5351ebeb9b2c628fe7035d37e0e09abf363e4ad2001657a"     # sha256 of the accepted flag
PINK14_DECOY = "d0337b431eec4942f688f1259d892be59aee6e7b719eb7dc577a8b7a37143866"  # sha256 of the decoy text


@pytest.mark.needs_realdata("pink-tns")
@pytest.mark.needs_tool("py:Cryptodome", "py:PIL")
def test_the_pink_handouts_are_read_end_to_end(tmp_path):
    """<realdata>/pink-tns/ holds pink.tns, lib_pink.tns (Pink 11) and tns2_pink.tns (Pink 14)."""
    from ctf import paths
    src = paths.require_realdata() / "pink-tns"
    for name in ("pink.tns", "lib_pink.tns", "tns2_pink.tns"):
        box = T.read_container((src / name).read_bytes())
        assert box.notes == [] and all(m.crc_ok for m in box.members), name     # TI's CRC of every decoded page
        assert all(m.encoding == "method13+tixc" for m in box.members if m.name.endswith(".xml")), name
    c11 = _challenge(tmp_path / "11", {n: (src / n).read_bytes() for n in ("pink.tns", "lib_pink.tns")})
    r = T.solve(c11, PINK, ocr="off")
    assert r.status == "solved" and [hashlib.sha256(f.encode()).hexdigest() for f in r.flags] == [PINK11]
    c14 = _challenge(tmp_path / "14", {"tns2_pink.tns": (src / "tns2_pink.tns").read_bytes()})
    r = T.solve(c14, PINK, ocr="off")
    assert r.status == "candidate" and [hashlib.sha256(f.encode()).hexdigest() for f in r.flags] == [PINK14_DECOY]
    assert [e.kind for e in r.evidence if e.kind in ("decoy", "render")] == ["decoy", "render"]
    assert "63 point(s), 45 segment(s)" in [e for e in r.evidence if e.kind == "render"][0].detail


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
