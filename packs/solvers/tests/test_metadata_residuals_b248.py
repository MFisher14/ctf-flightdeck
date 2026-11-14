"""B-248: metadata lane residuals.

  1. png.text_chunk_keywords (the Day 13 drill): the tEXt keyword list, no longer the tEXt chunk called `keywords`;
     two readings in one file are no answer; the FAMILY stderr line names a keyword-family capture.
  2. USN V4 and mixed V2/V3/V4 journals (coverage matrix F7), through solvers/toolkits/foridepth_usn.py.
  3. bigobj COFF objects (readers_objects), coff.* and pe.* +object; bigobj fields and the stamp as a date.
  4. scalar ar.member_<field> of a one-member archive.
  5. the embedded ICC profile of a TIFF (tag 34675) and of a HEIF primary item (colr prof).
  6. the regf base-block decoy (Day 25): the root key name and the embedded file name never cross-match.
  7. stated_spec: a place inside a named structure and inside an archive member.
  8. readers_synthesis: descending digest order and size order, offered unsure.

Every fixture is built in the test or by ctf/formats/corpus.py; nothing is downloaded or executed. The judge ledger is
off unless a test says otherwise, so every answer here is the lane's own reading.
"""
import io
import json
import struct
import sys
import tarfile
import zipfile
import zlib
from contextlib import redirect_stderr
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
MD = REPO / "solvers" / "metadata-forensics"
for _p in (str(REPO), str(REPO / "solvers" / "common"), str(MD)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import labels  # noqa: E402
import properties_strict as ps  # noqa: E402
from ctf.formats import corpus as C  # noqa: E402

RF = ps.MORE_MODULES["readers_forensic.py"]
RO = ps.MORE_MODULES["readers_objects.py"]
RS = ps.MORE_MODULES["readers_residuals.py"]
ST = ps._stated_mod()
SY = ps._synthesis_mod()


@pytest.fixture(autouse=True)
def no_judge(monkeypatch):
    monkeypatch.setenv("CTF_JUDGE_LEDGER", "off")


def ask(prop, name, data, kind=None, syntax=None, question=None, aid=None, files=None):
    q = {"answer_id": aid or "t-" + prop.replace(".", "-"), "question": question or f"Determine {prop} for {name}."}
    if kind is not None or syntax is not None:
        q["answer_format"] = {"kind": kind or "text", "syntax": syntax or ""}
    err = io.StringIO()
    with redirect_stderr(err):
        got = ps.answer_question(q, files if files is not None else {name: data}, {})
    return got, err.getvalue()


def values(answer):
    """The values an answer offers: the options of an unsure answer (the literal-none `absent` option left out),
    or [the plain answer]."""
    if answer is None:
        return []
    p = labels.parse(answer)
    if p is None:
        return [answer]
    return [v for n, v in p.options if n != "absent"]


def unsure(answer):
    return answer is not None and labels.is_unsure(answer)


# ------------------------------------------------------------------ 1. PNG keyword list under the family's names

IHDR = struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)


def png(*texts, extra=()):
    return C.png_write([(b"IHDR", IHDR)] + [(b"tEXt", t) for t in texts] + list(extra)
                       + [(b"IDAT", zlib.compress(b"\x00\x00")), (b"IEND", b"")])


@pytest.mark.parametrize("prop", sorted(RS.PNG_KEYWORD_LISTS))
def test_png_keyword_list_names_read_the_text_keywords_in_file_order(prop):
    got, _ = ask(prop, "x.png", png(b"Software\x00Cam", b"Author\x00Ada"), kind="json")
    assert unsure(got)
    assert values(got)[0] == '["Software","Author"]'


def test_png_text_chunk_keywords_was_a_family_capture_and_now_is_registered():
    # lookup() takes REG before FAMILIES: the exact name is the keyword-list reader, not png_text_<keyword>
    assert ps.canon("png.text_chunk_keywords") in ps.REG
    assert ps.REG[ps.canon("png.text_chunk_keywords")].fn is not None
    # the family still answers a real keyword under its chunk_ spelling
    got, _ = ask("png.text_chunk_software", "x.png", png(b"Software\x00Cam 1.2"))
    assert values(got) == ['"Cam 1.2"'] or values(got) == ["Cam 1.2"]


def test_png_keyword_list_is_no_answer_when_the_family_reading_is_also_in_the_file():
    # a tEXt chunk whose keyword is `Keywords`: png.text_chunk_keywords could ask for its text. Two readings: None.
    got, err = ask("png.text_chunk_keywords", "x.png", png(b"Keywords\x00alpha, beta", b"Title\x00t"), kind="json")
    assert got is None, got
    # the same file under a list name whose family reading is not in it still answers
    got, _ = ask("png.text_keyword_list", "x.png", png(b"Keywords\x00alpha, beta", b"Title\x00t"), kind="json")
    assert values(got)[0] == '["Keywords","Title"]'


def test_png_keyword_list_is_no_answer_beside_itxt_and_on_a_non_png():
    itxt = (b"iTXt", b"Author\x00\x00\x00\x00\x00y")
    got, _ = ask("png.text_chunk_keywords", "x.png", png(b"Title\x00x", extra=[itxt]), kind="json")
    assert got is None
    got, _ = ask("png.text_chunk_keywords", "x.png", b"GIF89a" + bytes(40), kind="json")
    assert got is None


def test_family_capture_prints_one_family_line_and_a_registered_name_prints_none():
    _, err = ask("png.text_software", "x.png", png(b"Software\x00Cam"))
    lines = [ln for ln in err.splitlines() if ln.startswith("FAMILY ")]
    assert len(lines) == 1
    assert "png_text_" in lines[0] and "'software'" in lines[0] and "png.text_software" in lines[0]
    _, err = ask("png.text_keywords", "x.png", png(b"Software\x00Cam"))
    assert not [ln for ln in err.splitlines() if ln.startswith("FAMILY ")]


# ------------------------------------------------------------------ 2. USN V4 and mixed journals

def test_mixed_journal_counts_every_record_and_lists_versions():
    s = C.build("usn_mixed")
    assert values(ask("usn.record_count", s.name, s.data)[0])[0] == "3"
    assert values(ask("usn.record_major_versions", s.name, s.data, kind="json")[0])[0] == "[3,4,2]"
    assert values(ask("usn.v4_record_count", s.name, s.data)[0])[0] == "1"
    assert values(ask("usn.v2_record_count", s.name, s.data)[0])[0] == "1"
    assert values(ask("usn.v3_record_count", s.name, s.data)[0])[0] == "1"


def test_a_v4_first_record_reads_its_extents_and_has_no_name_or_time():
    s = C.build("usn_v4_first")
    rec = RF._usn_first(s.data)
    assert rec["major"] == 4 and rec["extent_count"] == 2
    assert rec["extent_offsets"] == [0x1000, 0x3000] and rec["extent_lengths"] == [0x200, 0x80]
    assert rec["usn"] == 0x9000 and rec["frn"] == 0x123 and rec["parent"] == 5
    for prop in ("usn.first_record_file_name", "usn.first_record_timestamp", "usn.first_record_security_id"):
        got, _ = ask(prop, s.name, s.data)
        assert unsure(got) and values(got) == [], (prop, got)    # only the literal none: the field is absent
        assert [n for n, _ in labels.parse(got).options] == ["absent"]


def _v4(count=2, ext_size=16, rec_len=None):
    body = struct.pack("<IHH", 0, 4, 0) + (7).to_bytes(16, "little") + (5).to_bytes(16, "little")
    body += struct.pack("<QIIIHH", 0x40, 0, 0, 0, count, ext_size)
    body += b"".join(struct.pack("<qq", 0x100 * (i + 1), 0x10) for i in range(count)) + bytes(count * (ext_size - 16))
    rec_len = len(body) if rec_len is None else rec_len
    return struct.pack("<I", rec_len) + body[4:] + bytes(max(0, rec_len - len(body)))


@pytest.mark.parametrize("bad", [dict(count=0), dict(ext_size=24), dict(rec_len=64 + 32 + 8)])
def test_a_v4_record_outside_v4_0_is_no_journal(bad):
    good = bytes(4096) + _v4()
    assert RF._usn_first(good) is not None
    assert RF._usn_first(bytes(4096) + _v4(**bad)) is None


def test_a_damaged_record_after_the_first_gives_no_count():
    s = C.build("usn_mixed")
    v3 = len(C._usn_v3("report.docx", 0x5000, 0x100))
    broken = bytearray(s.data)
    broken[4096 + v3 + 4] = 9          # the V4 record's major version: 9
    assert ask("usn.record_count", s.name, bytes(broken))[0] is None


def _usn_v2_sized(size, name="big.txt"):
    """A V2 record of an exact RecordLength (padding after the name): 256 begins with the byte 00."""
    n = name.encode("utf-16-le")
    rec = struct.pack("<IHHQQQqIIIIHH", size, 2, 0, 0x123, 5, 0x7000, 0, 0x100, 0, 0, 0x20, len(n), 60) + n
    return rec + bytes(size - len(rec))


@pytest.mark.parametrize("size", [256, 512, 768])
def test_a_first_record_whose_length_begins_with_a_zero_byte_is_read(size):
    """The leading zeros run into the record's RecordLength (256 is 00 01 00 00): the start rounds down to the grid
    the record sits on, never up past it."""
    rec = _usn_v2_sized(size)
    assert rec[0] == 0
    data = bytes(4096) + rec + C._usn_v2("after.txt", 0x7100, 0x2)
    first = RF._usn_first(data)
    assert first is not None and first["name"] == "big.txt" and first["record_length"] == size
    assert values(ask("usn.record_count", "$J", data)[0])[0] == "2"
    from ctf import formats as F
    assert F.DETECTORS["usn"](data) is True
    assert F.DETECTORS["usn"](bytes(4096) + _usn_v2_sized(256)[:200]) is False     # the record runs past the file


def test_the_v4_parser_missing_fails_loud(monkeypatch, tmp_path):
    monkeypatch.setattr(RF, "_USN_TOOLKIT", None)
    monkeypatch.setattr(RF, "__file__", str(tmp_path / "metadata-forensics" / "readers_forensic.py"))
    with pytest.raises(ps.PackMissing):
        RF._usn_rec(bytes(_v4()), 0)


# ------------------------------------------------------------------ 3. bigobj COFF

def test_bigobj_object_is_read_by_the_coff_readers_with_20_byte_symbols():
    s = C.build("coff_bigobj")
    h = RO.bigobj_object(s.data)
    assert h["nsec"] == 3 and h["symsize"] == 20 and h["table"] == 56
    assert RO.section_names(s.data, h) == list(C.BIGOBJ_SECTIONS)
    assert values(ask("coff.section_names", s.name, s.data, kind="json")[0])[0] == json.dumps(
        list(C.BIGOBJ_SECTIONS), separators=(",", ":"))
    assert "IMAGE_FILE_MACHINE_AMD64" in values(ask("coff.machine", s.name, s.data)[0])
    assert str(C.BIGOBJ_STAMP) in values(ask("coff.time_date_stamp", s.name, s.data)[0])


def test_bigobj_has_no_characteristics_and_its_own_fields_are_read():
    s = C.build("coff_bigobj")
    assert ask("coff.characteristics", s.name, s.data)[0] is None
    assert values(ask("coff.is_bigobj", s.name, s.data)[0]) == ["true"]
    assert values(ask("coff.bigobj_version", s.name, s.data)[0])[0] == "2"
    assert values(ask("coff.bigobj_class_id", s.name, s.data)[0])[0] == "d1baa1c7-baee-4ba9-af20-faf66aa4dcb8"
    import datetime
    when = datetime.datetime.fromtimestamp(C.BIGOBJ_STAMP, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert when in values(ask("coff.time_date_stamp_utc", s.name, s.data)[0])
    zero = bytearray(s.data)
    zero[8:12] = bytes(4)                     # a zero stamp (a reproducible build) is no date: absent
    assert values(ask("coff.time_date_stamp_utc", s.name, bytes(zero))[0]) == []


def test_a_classic_object_is_not_bigobj_and_a_pe_question_on_bigobj_reads_the_object():
    classic = struct.pack("<HHIIIHH", 0x8664, 1, 1, 0, 0, 0, 0) + struct.pack("<8sIIIIIIHHI", b".text", 0, 0, 0, 0, 0, 0, 0, 0, 0)
    classic += bytes(64)
    assert values(ask("coff.is_bigobj", "a.obj", classic)[0]) == ["false"]
    s = C.build("coff_bigobj")
    got, _ = ask("pe.coff_machine_u16_hex", s.name, s.data)
    assert "0x8664" in values(got) and unsure(got)


def test_a_bigobj_whose_section_table_runs_past_the_file_is_no_object():
    s = C.build("coff_bigobj")
    cut = bytearray(s.data[:56 + 40])           # header and one section header of the three it states
    assert RO.bigobj_object(bytes(cut)) is None
    assert ask("coff.number_of_sections", "m.obj", bytes(cut))[0] is None


def _bigobj_third_section_raw(size, ptr):
    s = C.build("coff_bigobj")
    d = bytearray(s.data)
    struct.pack_into("<II", d, 56 + 40 * 2 + 16, size, ptr)     # SizeOfRawData, PointerToRawData of section 3
    return bytes(d)


def test_a_bigobj_section_whose_raw_data_runs_past_the_file_is_no_object():
    n = len(C.build("coff_bigobj").data)
    assert RO.bigobj_object(_bigobj_third_section_raw(8, n - 8)) is not None      # ends at the file's last byte
    past = _bigobj_third_section_raw(8, n - 4)                                    # four bytes past the end
    assert RO.bigobj_object(past) is None
    assert ask("coff.number_of_sections", "m.obj", past)[0] is None
    assert RO.bigobj_object(_bigobj_third_section_raw(8, 0)) is not None          # no raw data: nothing to bound


def test_a_bigobj_member_of_an_archive_is_an_object_member():
    s = C.build("coff_bigobj")
    lib = C.ar_write([("a.obj", 0, 0, 0, 0o644, s.data), ("b.obj", 0, 0, 0, 0o644, s.data)])
    assert RO.objects(lib, "coff") == [s.data, s.data]
    assert "IMAGE_FILE_MACHINE_AMD64" in values(ask("coff.machine", "x.lib", lib)[0])


# ------------------------------------------------------------------ 4. ar scalar member fields

def test_scalar_member_fields_of_a_one_member_archive():
    s = C.build("ar_single")
    assert values(ask("ar.member_name", s.name, s.data)[0])[0] == "notes.txt"
    assert values(ask("ar.member_uid", s.name, s.data)[0])[0] == "1000"
    assert values(ask("ar.member_gid", s.name, s.data)[0])[0] == "100"
    assert "100644" in values(ask("ar.member_mode", s.name, s.data)[0])
    assert values(ask("ar.member_size_bytes", s.name, s.data)[0])[0] == str(len(C.AR_MEMBER))


def test_a_scalar_member_field_of_a_two_member_archive_is_no_answer():
    two = C.ar_write([("a.txt", 1, 1, 1, 0o644, b"aa"), ("b.txt", 2, 2, 2, 0o600, b"bbb")])
    for prop in ("ar.member_name", "ar.member_uid", "ar.member_size_bytes"):
        assert ask(prop, "two.a", two)[0] is None, prop
    assert ask("ar.member_uid", "x.bin", b"not an archive at all")[0] is None


# ------------------------------------------------------------------ 5. embedded ICC: TIFF and HEIF

def test_tiff_and_heif_embedded_profiles_are_read():
    for sid, prop in (("tiff_icc", "tiff.icc_profile_description"), ("heif_icc", "heic.icc_profile_description")):
        s = C.build(sid)
        assert values(ask(prop, s.name, s.data)[0])[0] == C.ICC_DESCRIPTION, sid
        assert values(ask("icc.profile_description", s.name, s.data)[0])[0] == C.ICC_DESCRIPTION, sid


def heif(colrs):
    """A HEIF still whose primary item carries ispe and the given colr bodies (all associated with item 1)."""
    box = C._box
    props = [box(b"ispe", bytes(4) + struct.pack(">II", 64, 48))] + [box(b"colr", c) for c in colrs]
    ipma = box(b"ipma", bytes(4) + struct.pack(">I", 1) + struct.pack(">HB", 1, len(props))
               + bytes(0x80 | (i + 1) for i in range(len(props))))
    meta = box(b"meta", bytes(4) + box(b"hdlr", bytes(8) + b"pict" + bytes(13)) + box(b"pitm", bytes(4) + b"\x00\x01")
               + box(b"iinf", bytes(4) + b"\x00\x01" + box(b"infe", b"\x02\x00\x00\x00\x00\x01\x00\x00hvc1\x00"))
               + box(b"iprp", box(b"ipco", b"".join(props)) + ipma))
    return box(b"ftyp", b"heic" + bytes(4) + b"mif1heic") + meta


def test_a_heif_colour_with_no_profile_is_absent_and_two_profiles_are_no_answer():
    nclx = b"nclx" + struct.pack(">HHHB", 1, 13, 6, 0x80)
    one = heif([nclx, b"prof" + C.icc_profile("Only one")])
    assert values(ask("heic.icc_profile_description", "a.heic", one)[0]) == ["Only one"]
    got, _ = ask("heic.icc_profile_description", "a.heic", heif([nclx]))
    assert unsure(got) and values(got) == []          # the field is absent: the literal none only
    two = heif([b"prof" + C.icc_profile("First"), b"rICC" + C.icc_profile("Second")])
    assert ask("heic.icc_profile_description", "a.heic", two)[0] is None


def heif_two_items(primary_colrs, other_colrs):
    """A HEIF with items 1 (primary) and 2, each associated with its own properties: ispe and primary_colrs for item
    1, ispe and other_colrs for item 2 (a thumbnail or auxiliary image with its own colour)."""
    box = C._box
    ispe = box(b"ispe", bytes(4) + struct.pack(">II", 64, 48))
    props = [ispe] + [box(b"colr", c) for c in primary_colrs] + [ispe] + [box(b"colr", c) for c in other_colrs]
    first = list(range(1, 2 + len(primary_colrs)))
    second = list(range(2 + len(primary_colrs), len(props) + 1))
    entries = b"".join(struct.pack(">HB", item, len(idx)) + bytes(0x80 | i for i in idx)
                       for item, idx in ((1, first), (2, second)))
    ipma = box(b"ipma", bytes(4) + struct.pack(">I", 2) + entries)
    infe = b"".join(box(b"infe", b"\x02\x00\x00\x00" + struct.pack(">H", i) + b"\x00\x00hvc1\x00") for i in (1, 2))
    meta = box(b"meta", bytes(4) + box(b"hdlr", bytes(8) + b"pict" + bytes(13)) + box(b"pitm", bytes(4) + b"\x00\x01")
               + box(b"iinf", bytes(4) + b"\x00\x02" + infe) + box(b"iprp", box(b"ipco", b"".join(props)) + ipma))
    return box(b"ftyp", b"heic" + bytes(4) + b"mif1heic") + meta


def test_a_heif_profile_is_the_primary_items_never_another_items():
    both = heif_two_items([b"prof" + C.icc_profile("Primary")], [b"prof" + C.icc_profile("Thumbnail")])
    assert values(ask("heic.icc_profile_description", "a.heic", both)[0]) == ["Primary"]
    other_only = heif_two_items([], [b"prof" + C.icc_profile("Thumbnail")])
    got, _ = ask("heic.icc_profile_description", "a.heic", other_only)
    assert unsure(got) and values(got) == []          # the primary item has no profile: absent, not the other's


def test_a_tiff_without_tag_34675_has_no_profile():
    s = C.build("tiff_icc")
    no_tag = s.data.replace(struct.pack("<HH", 34675, 7), struct.pack("<HH", 34674, 7), 1)
    got, _ = ask("tiff.icc_profile_description", s.name, no_tag)
    assert values(got) == []


# ------------------------------------------------------------------ 6. the regf base-block decoy (Day 25)

ROOT_NAMES = ("registry.hive_root_name", "registry.hive_root_key_name", "regf.root_key_name", "hive.root_key_name")
FILE_NAMES = ("registry.hive_file_name", "registry.embedded_file_name", "regf.file_name", "regf.embedded_file_name")


@pytest.mark.parametrize("ledger", ["off", "on"])
def test_root_key_name_and_base_block_file_name_never_cross_match(monkeypatch, ledger):
    if ledger == "on":
        monkeypatch.delenv("CTF_JUDGE_LEDGER", raising=False)
    s = C.build("regf_decoy")
    for prop in ROOT_NAMES:
        got = values(ask(prop, s.name, s.data)[0])
        assert got and got[0] == C.REGF_ROOT and C.REGF_DECOY not in got, (prop, got)
    for prop in FILE_NAMES:
        got = values(ask(prop, s.name, s.data)[0])
        assert got and got[0] == C.REGF_DECOY and C.REGF_ROOT not in got, (prop, got)


# ------------------------------------------------------------------ 7. stated places inside a structure or a member

def pe_image():
    mz = bytearray(0x40)
    mz[:2] = b"MZ"
    mz[0x10:0x14] = b"\xAA\xBB\xCC\xDD"
    struct.pack_into("<I", mz, 0x3C, 0x40)
    coff = struct.pack("<HHIIIHH", 0x8664, 2, 0x5F000000, 0, 0, 0xF0, 0x22)
    opt = bytearray(0xF0)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<I", opt, 0x10, 0x1234)
    sec = b"".join(struct.pack("<8sIIIIIIHHI", n, 0x200, 0x1000, 0x200, p, 0, 0, 0, 0, 0x60000020)
                   for n, p in ((b".text", 0x200), (b".data", 0x400)))
    head = bytes(mz) + b"PE\x00\x00" + coff + bytes(opt) + sec
    text = bytearray(0x200)
    struct.pack_into("<H", text, 2, 0xBEEF)
    data = bytearray(0x200)
    struct.pack_into("<I", data, 8, 0xC0FFEE)
    return head + bytes(0x200 - len(head)) + bytes(text) + bytes(data)


def elf_image():
    """A 64-bit little-endian ELF with sections null, .text, .shstrtab; .text holds 0x1122 at offset 6."""
    shstr = b"\x00.text\x00.shstrtab\x00"
    text = bytes(6) + struct.pack("<H", 0x1122) + bytes(8)
    text_at, str_at = 64, 64 + len(text)
    sh_at = (str_at + len(shstr) + 7) & ~7
    head = bytearray(64)
    head[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<HHIQQQIHHHHHH", head, 16, 1, 62, 1, 0, 0, sh_at, 0, 64, 0, 0, 64, 3, 2)
    shdr = bytes(64)
    shdr += struct.pack("<IIQQQQIIQQ", 1, 1, 6, 0, text_at, len(text), 0, 0, 16, 0)
    shdr += struct.pack("<IIQQQQIIQQ", 7, 3, 0, 0, str_at, len(shstr), 0, 0, 1, 0)
    body = bytes(head) + text + shstr
    return body + bytes(sh_at - len(body)) + shdr


def stated(prop, name, files, syntax, kind="integer"):
    got, err = ask(prop, name, None, kind=kind, syntax=syntax, files=files)
    return got, [ln for ln in err.splitlines() if ln.startswith("STATED")]


@pytest.mark.parametrize("syntax, value, tag", [
    ("the u32le at offset 0x10 of the optional header, base-10", 0x1234, "+u32le+in_optional_header"),
    ("the u16le at offset 2 of the .text section, base-10", 0xBEEF, "+u16le+in_section_.text"),
    ("the u32le at offset 8 into the section `.data`, base-10", 0xC0FFEE, "+u32le+in_section_.data"),
    ("the u16le at offset 0 relative to the start of the COFF header, base-10", 0x8664, "+u16le+in_coff_header"),
    ("the u32le at offset 0 of the PE header, base-10", 0x4550, "+u32le+in_pe_header"),
])
def test_a_place_in_a_named_structure_is_read_from_the_structure(syntax, value, tag):
    got, lines = stated("pe.zz_probe", "a.exe", {"a.exe": pe_image()}, syntax)
    p = labels.parse(got)
    assert p is not None and p.key.endswith(tag), (got, lines)
    assert values(got) == [str(value)]


def test_an_untied_structure_word_leaves_the_file_offset():
    got, _ = stated("pe.zz_probe", "a.exe", {"a.exe": pe_image()},
                    "inspect the optional header; give the u32le at offset 0x10, base-10")
    assert values(got) == [str(0xDDCCBBAA)] and labels.parse(got).key.endswith("+u32le")


@pytest.mark.parametrize("syntax", [
    "the u16le at offset 0x1ff of the .text section, base-10",          # past the section's raw size
    "the u16le at offset 2 of the .bss section, base-10",               # no such section
    "the u16le at offset 2 of the .text section or offset 2 of the optional header, base-10",   # two structures
    "the u16le at offset 0 of the program header table, base-10",       # an ELF structure of a PE
])
def test_a_structure_that_does_not_hold_the_place_reads_nothing(syntax):
    got, lines = stated("pe.zz_probe", "a.exe", {"a.exe": pe_image()}, syntax)
    assert got is None and lines and "nothing read" in lines[-1], (got, lines)


def test_an_elf_section_by_name():
    got, _ = stated("elf.zz_probe", "a.so", {"a.so": elf_image()}, "the u16le at offset 6 of the .text section, base-10")
    assert values(got) == [str(0x1122)]


def elf_with_bss():
    """elf_image's shape plus a .bss section (SHT_NOBITS) whose sh_offset and sh_size point at .text's file bytes:
    a NOBITS section has no bytes in the file, whatever its size says."""
    shstr = b"\x00.text\x00.bss\x00.shstrtab\x00"
    text = bytes(6) + struct.pack("<H", 0x1122) + bytes(8)
    text_at, str_at = 64, 64 + len(text)
    sh_at = (str_at + len(shstr) + 7) & ~7
    head = bytearray(64)
    head[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<HHIQQQIHHHHHH", head, 16, 1, 62, 1, 0, 0, sh_at, 0, 64, 0, 0, 64, 4, 3)
    shdr = bytes(64)
    shdr += struct.pack("<IIQQQQIIQQ", 1, 1, 6, 0, text_at, len(text), 0, 0, 16, 0)
    shdr += struct.pack("<IIQQQQIIQQ", 7, 8, 3, 0, text_at, len(text), 0, 0, 16, 0)
    shdr += struct.pack("<IIQQQQIIQQ", 12, 3, 0, 0, str_at, len(shstr), 0, 0, 1, 0)
    body = bytes(head) + text + shstr
    return body + bytes(sh_at - len(body)) + shdr


def test_a_place_in_an_elf_nobits_section_reads_nothing():
    elf = elf_with_bss()
    got, _ = stated("elf.zz_probe", "a.so", {"a.so": elf}, "the u16le at offset 6 of the .text section, base-10")
    assert values(got) == [str(0x1122)]                   # the same bytes, through a PROGBITS section, do read
    got, lines = stated("elf.zz_probe", "a.so", {"a.so": elf}, "the u16le at offset 6 of the .bss section, base-10")
    assert got is None and lines and "nothing read" in lines[-1], (got, lines)


@pytest.mark.parametrize("words", ["PE file header", "NT file header", "pe file headers"])
def test_pe_file_header_is_ambiguous_and_reads_nothing(words):
    """`PE file header` names the PE signature's header to some authors and the COFF file header to others: the
    offset is counted from neither."""
    got, lines = stated("pe.zz_probe", "a.exe", {"a.exe": pe_image()}, f"the u16le at offset 0 of the {words}, base-10")
    assert got is None and lines and "two structures" in lines[-1], (got, lines)


@pytest.mark.parametrize("words, value", [("PE header", 0x4550), ("NT headers", 0x4550), ("COFF file header", 0x8664),
                                          ("file header", 0x8664)])
def test_unambiguous_header_words_keep_their_base(words, value):
    got, _ = stated("pe.zz_probe", "a.exe", {"a.exe": pe_image()}, f"the u16le at offset 0 of the {words}, base-10")
    assert values(got) == [str(value)], (words, got)


def _zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n, b in entries:
            z.writestr(n, b)
    return buf.getvalue()


PAYLOAD = b"\x00\x00\x00\x00\x78\x56\x34\x12"


@pytest.mark.parametrize("syntax", ["the u32le at offset 4 of the member `payload.bin`, base-10",
                                    "the u32le at offset 4 of the zip member cfg/payload.bin, base-10",
                                    "the u32le at offset 4 of archive entry 'payload.bin', base-10",
                                    "the u32le at offset 4 in the payload.bin member, base-10"])
def test_a_place_in_a_zip_member(syntax):
    z = _zip([("cfg/payload.bin", PAYLOAD), ("readme.txt", b"\x01" * 16)])
    got, _ = stated("zip.zz_probe", "bundle.zip", {"bundle.zip": z}, syntax)
    assert values(got) == [str(0x12345678)] and labels.parse(got).key.endswith("+u32le+member")


def test_a_place_in_a_member_of_a_member_and_in_tar_and_ar_members():
    inner = _zip([("deep/payload.bin", PAYLOAD)])
    outer = _zip([("inner.zip", inner)])
    syn = "the u32le at offset 4 of the member `inner.zip/deep/payload.bin`, base-10"
    assert values(stated("zip.zz_probe", "outer.zip", {"outer.zip": outer}, syn)[0]) == [str(0x12345678)]
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        info = tarfile.TarInfo("data/payload.bin")
        info.size = len(PAYLOAD)
        t.addfile(info, io.BytesIO(PAYLOAD))
    syn = "the u32le at offset 4 of the member `payload.bin`, base-10"
    assert values(stated("tar.zz_probe", "b.tar.gz", {"b.tar.gz": buf.getvalue()}, syn)[0]) == [str(0x12345678)]
    ar = C.ar_write([("other.txt", 0, 0, 0, 0o644, b"\xff" * 8), ("payload.bin", 0, 0, 0, 0o644, PAYLOAD)])
    assert values(stated("ar.zz_probe", "lib.a", {"lib.a": ar}, syn)[0]) == [str(0x12345678)]


@pytest.mark.parametrize("syntax", ["the u32le at offset 4 of the member `missing.bin`, base-10",
                                    "the u32le at offset 4 of the member `a.bin` or the member `b.bin`, base-10",
                                    "the u32le at offset 4 of the member `dup.bin`, base-10"])
def test_a_member_that_is_not_one_member_reads_nothing(syntax):
    z = _zip([("x/dup.bin", PAYLOAD), ("y/dup.bin", PAYLOAD), ("a.bin", PAYLOAD), ("b.bin", PAYLOAD)])
    got, lines = stated("zip.zz_probe", "bundle.zip", {"bundle.zip": z}, syntax)
    assert got is None and lines, (got, lines)


def test_a_target_that_already_is_the_member_is_read_as_it_is():
    got, _ = stated("bin.zz_probe", "payload.bin", {"payload.bin": PAYLOAD},
                    "the u32le at offset 4 of the member `payload.bin`, base-10")
    assert values(got) == [str(0x12345678)]


def test_spec_parses_the_member_with_its_case_and_ties_the_base_to_the_offset():
    q = {"question": "Determine x.y for a.zip.", "answer_format": {"kind": "integer",
                                                                    "syntax": "the u16le at offset 2 of member `Cfg/Data.BIN`"}}
    s = ST.spec_of(q)
    assert s["member"] == "Cfg/Data.BIN" and "base" not in s
    q["answer_format"]["syntax"] = "the u16le at offset 2 of the optional header"
    assert ST.spec_of(q)["base"] == ("optional_header",)
    q["answer_format"]["syntax"] = "the u16le at offset 2; offset 4 of the optional header"
    assert ST.spec_of(q).get("base_conflict") is True


# ------------------------------------------------------------------ 8. synthesis: descending digest and size orders

FILES = {"a.txt": b"aaaa", "b.bin": b"b", "c.dat": b"cccccccc"}
LIST = ' Files: ["a.txt","b.bin","c.dat"]'


def _digest_order(algo, reverse):
    import hashlib
    return [n for _, n in sorted(((hashlib.new(algo, FILES[n]).hexdigest(), n) for n in FILES), reverse=reverse)]


def test_ascending_digest_order_is_still_plain():
    text = ("Compute the full-file SHA-256 digest of each named file, then submit a compact JSON array of their "
            "filenames in ascending digest order." + LIST)
    got, _ = ask("x", None, None, kind="json", question=text, aid="t-synthesis-sha256-order", files=FILES)
    assert got == json.dumps(_digest_order("sha256", False), separators=(",", ":"))


def test_descending_digest_order_is_read_and_unsure():
    text = ("Compute the full-file SHA-256 digest of each named file, then submit a compact JSON array of their "
            "filenames in descending digest order." + LIST)
    q = {"answer_id": "t-synthesis-sha256-order", "question": text, "answer_format": {"kind": "json"}}
    got, _ = ask("x", None, None, kind="json", question=text, aid="t-synthesis-sha256-order", files=FILES)
    assert unsure(got) and values(got) == [json.dumps(_digest_order("sha256", True), separators=(",", ":"))]
    assert labels.parse(got).key == "metadata.synthesis/sha256+descending"
    assert SY.covered(q["answer_id"], text, q["answer_format"]) is not None      # never counted as plain


@pytest.mark.parametrize("words, order", [("in ascending size order", ["b.bin", "a.txt", "c.dat"]),
                                          ("sorted smallest first", ["b.bin", "a.txt", "c.dat"]),
                                          ("in descending size order", ["c.dat", "a.txt", "b.bin"]),
                                          ("largest first", ["c.dat", "a.txt", "b.bin"])])
def test_size_order_is_read_and_unsure(words, order):
    text = f"Submit a compact JSON array of their filenames {words}." + LIST
    got, _ = ask("x", None, None, kind="json", question=text, aid="t-synthesis-size-order", files=FILES)
    assert unsure(got) and values(got) == [json.dumps(order, separators=(",", ":"))]


@pytest.mark.parametrize("text, files", [
    ("Submit a compact JSON array of their filenames in ascending size order.", {**FILES, "c.dat": b"zzzz"}),  # a tie
    ("Submit a compact JSON array of their filenames in ascending size order of their SHA-256 digests.", FILES),
    ("Submit a compact JSON array of their filenames in ascending size order, largest first.", FILES),
    ("Submit a compact JSON array of their uppercase filenames in ascending size order.", FILES),
])
def test_size_order_is_none_when_not_settled(text, files):
    got, _ = ask("x", None, None, kind="json", question=text + LIST, aid="t-synthesis-size-order", files=files)
    assert got is None


# ------------------------------------------------------------------ 9. the catalog detectors of the B-248 formats

def _corrupt(sid, at, value):
    d = bytearray(C.build(sid).data)
    d[at:at + len(value)] = value
    return bytes(d)


def test_each_b248_detector_needs_its_own_structure():
    from ctf import formats as F
    for sid, fmt in (("png_text", "png"), ("tiff_icc", "tiff"), ("heif_icc", "heif"), ("regf_decoy", "regf"),
                     ("usn_mixed", "usn"), ("usn_v4_first", "usn"), ("coff_bigobj", "coff"), ("ar_single", "ar")):
        assert F.DETECTORS[fmt](C.build(sid).data), sid
    assert not F.DETECTORS["png"](_corrupt("png_text", 12, b"IDAT"))           # the first chunk is not IHDR
    assert not F.DETECTORS["heif"](_corrupt("heif_icc", 8, b"mp42").replace(b"mif1heic", b"isomavc1", 1))   # no HEIF brand
    assert not F.DETECTORS["regf"](_corrupt("regf_decoy", 4096, b"xbin"))      # no hive bin after the base block
    s = C.build("usn_mixed")
    assert not F.DETECTORS["usn"](_corrupt("usn_mixed", 4096 + 4, struct.pack("<H", 5)))   # version 5
    assert not F.DETECTORS["usn"](_corrupt("usn_mixed", 4096 + 6, struct.pack("<H", 1)))   # minor 1
    assert not F.DETECTORS["usn"](s.data[:4096 + 40])                          # the record runs past the file
    assert not F.DETECTORS["usn"](bytes(8192))                                 # sparse zeros only
    assert not F.DETECTORS["coff"](_corrupt("coff_bigobj", 4, struct.pack("<H", 1)))       # bigobj version 1
    assert not F.DETECTORS["ar"](_corrupt("ar_single", 66, b"x\n"))            # no member header terminator
    assert F.DETECTORS["ar"](b"!<arch>\n")                                     # an empty archive is an archive


def test_a_classic_coff_object_is_identified_and_a_pe_is_not():
    from ctf import formats as F
    classic = struct.pack("<HHIIIHH", 0x8664, 1, 1, 0, 0, 0, 0) + struct.pack(
        "<8sIIIIIIHHI", b".text", 0, 0, 0, 0, 0, 0, 0, 0, 0)
    assert F.DETECTORS["coff"](classic)
    assert not F.DETECTORS["coff"](struct.pack("<HHIIIHH", 0x8664, 3, 1, 0, 0, 0, 0) + bytes(40))   # 3 sections, 1 fits
    assert not F.DETECTORS["coff"](struct.pack("<HHIIIHH", 0x1234, 1, 1, 0, 0, 0, 0) + bytes(40))   # unknown machine
    assert not F.DETECTORS["coff"](pe_image())
