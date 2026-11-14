"""B-162: the ranked format catalog, the synthetic corpus and its per-format fixture checks.

Every sample is built from invented values (ctf/formats/corpus.py); its checks are what the builder wrote.
Each check is asked through the metadata lane exactly as a question ('Determine <property> for <file>.')
and must come back as the plain answer or as one of the unsure options. The structural pieces of the
corpus (compound file, MSI stream names, property set) are first held to readers that are not the lane's.
"""
import io
import random
import shutil
import struct
import zipfile
from pathlib import Path

import olefile          # pinned in requirements.in: a missing one is an error, never a skip
import pytest

from ctf import formats
from ctf.formats import corpus as C
from ctf.formats import matrix as X

LANE = X.lane_module()
import labels  # noqa: E402  (solvers/common, on sys.path once the lane is loaded)

CATALOG = formats.load()
SPEC_FORMATS = {"ole", "msi", "cab", "msix", "lnk", "ooxml", "riff", "eml"}
IDENTITY = {"file.size_bytes", "size_bytes", "sha256", "md5", "sha1"}


@pytest.fixture
def no_judge(monkeypatch):
    monkeypatch.setenv("CTF_JUDGE_LEDGER", "off")


def _tool_mark(spec):
    alts = spec.split("|")
    return pytest.mark.needs_tool(next((t for t in alts if shutil.which(t)), alts[0]))


def _check_params():
    out = []
    for sid in sorted(C.BUILDERS):
        s = C.build(sid)
        for i, c in enumerate(s.checks):
            marks = [_tool_mark(t) for t in c.needs_tools]
            out.append(pytest.param(sid, i, id=f"{sid}-{c.prop}{'-member' if c.artifact else ''}-{i}", marks=marks))
    return out


def _matched(answer, expected):
    status, ok, _first = X.matches(answer, expected, labels)
    return status, ok


# ------------------------------------------------------------------ the catalog

def test_catalog_is_ranked_and_covers_every_format_the_spec_names():
    assert [f.rank for f in CATALOG] == list(range(1, len(CATALOG) + 1))
    assert {f.id for f in CATALOG} >= SPEC_FORMATS
    for f in CATALOG:
        assert f.samples and all(s in C.BUILDERS for s in f.samples)
    assert next(f for f in CATALOG if f.id == "msi").refines == "ole"


GOOD = '''
[[format]]
id = "lnk"
rank = 1
label = "shell link"
basis = "test"
extensions = [".lnk"]
namespaces = ["lnk"]
samples = ["lnk_shortcut"]
'''


@pytest.mark.parametrize("edit, message", [
    (lambda t: t.replace('rank = 1', 'rank = 2'), "ranks must be 1..1"),
    (lambda t: t + 'colour = "red"\n', "unknown keys"),
    (lambda t: t.replace('basis = "test"\n', ''), "missing 'basis'"),
    (lambda t: t.replace('"lnk_shortcut"', '"no_such_builder"'), "has no builder"),
    (lambda t: t.replace('id = "lnk"', 'id = "pdf"'), "id must be one of the detected formats"),
    (lambda t: t.replace('".lnk"', '".LNK"'), "extensions are lower case"),
    (lambda t: t + GOOD.replace('rank = 1', 'rank = 2'), "listed twice"),
    (lambda t: t + 'refines = "ole"\n', "refines 'ole'"),
    (lambda t: t + 'nearest = [{ asked = "a.b", reader = "c.d", sample = "riff_wav" }]\n', "not one of this format's samples"),
    (lambda t: t + 'nearest = [{ asked = "lnk.x", reader = "lnk.x", sample = "lnk_shortcut" }]\n', "names its own reader"),
    (lambda t: t + 'gaps = [{ asked = "lnk.x", sample = "lnk_shortcut" }]\n', "a gap entry is"),
    (lambda t: t.replace('samples = ["lnk_shortcut"]', 'samples = []'), "samples must be a non-empty list"),
])
def test_a_bad_catalog_fails_loudly_naming_the_key(tmp_path, edit, message):
    path = tmp_path / "catalog.toml"
    path.write_text(GOOD, encoding="utf-8")
    assert [f.id for f in formats.load(path)] == ["lnk"]          # the base is good
    path.write_text(edit(GOOD), encoding="utf-8")
    with pytest.raises(formats.CatalogError, match=message.replace("(", r"\(").replace(".", r"\.")):
        formats.load(path)


def test_a_missing_catalog_is_an_error_not_an_empty_catalog(tmp_path):
    with pytest.raises(formats.CatalogError, match="not there"):
        formats.load(tmp_path / "absent.toml")


def test_an_unknown_sample_id_is_named():
    with pytest.raises(C.CorpusError, match="no corpus builder 'nope'.*lnk_shortcut"):
        C.build("nope")


# ------------------------------------------------------------------ identification

@pytest.mark.parametrize("fmt", CATALOG, ids=lambda f: f.id)
def test_every_sample_is_identified_as_its_own_format_first_and_sure(fmt):
    for sid in fmt.samples:
        s = C.build(sid)
        got = formats.identify(s.name, s.data, CATALOG)
        assert got and got[0].format == fmt.id and got[0].sure, (sid, got)


def test_a_finer_format_drops_the_one_it_refines():
    s = C.build("msi_package")
    got = [m.format for m in formats.identify(s.name, s.data, CATALOG)]
    assert got[0] == "msi" and "ole" not in got
    doc = C.build("ole_document")
    assert [m.format for m in formats.identify(doc.name, doc.data, CATALOG) if m.sure] == ["ole"]


def test_an_extension_alone_is_never_sure():
    wav = C.build("riff_wav").data
    got = formats.identify("evidence.lnk", wav, CATALOG)
    assert [(m.format, m.sure) for m in got] == [("riff", True), ("lnk", False)]
    assert "extension .lnk only" in got[1].why
    assert formats.identify("notes.txt", b"plain words, nothing more\n", CATALOG) == []
    lnk = C.build("lnk_shortcut")
    assert [(m.format, m.sure) for m in formats.identify("updater.lnk", lnk.data, CATALOG)] == [("lnk", True)]


@pytest.mark.parametrize("data", [b"", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\xff" * 40, b"PK\x03\x04garbage",
                                  b"MSCF\x00\x00", b"RIFF", b"From: a\n\nbody"])
def test_truncated_or_hostile_bytes_match_nothing_structurally(data):
    assert [m for m in formats.identify("x.bin", data, CATALOG) if m.sure] == []


def _cfb_with_entry(name: str, length: int) -> bytes:
    """A two-stream compound file whose first unused directory entry carries `name` with the name length
    field set to `length` (bytes, terminator included)."""
    d = bytearray(C.cfb_write({"A": b"x"}))
    first_dir, = struct.unpack_from("<I", d, 0x30)
    at = 512 + first_dir * 512 + 3 * 128                 # entries 0 and 1 are Root Entry and A; 2 and 3 unused
    assert d[at:at + 64] == b"\x00" * 64                 # an unused entry
    raw = name.encode("utf-16-le")
    d[at:at + len(raw)] = raw
    struct.pack_into("<H", d, at + 64, length)
    return bytes(d)


def test_a_directory_name_counts_only_within_its_stated_length():
    """MSI stream names start with U+4840; an entry's name is the first (length - 2) bytes, 2..64. An entry
    whose length field is outside that range has no name, whatever bytes sit in its name area."""
    name = "\u4840Property"
    good = _cfb_with_entry(name, len(name.encode("utf-16-le")) + 2)
    assert [m.format for m in formats.identify("x.bin", good, CATALOG) if m.sure] == ["msi"]   # the site is read
    for length in (0, 1, 65, 66, 0xFFFF):
        data = _cfb_with_entry(name, length)
        assert [m.format for m in formats.identify("x.bin", data, CATALOG) if m.sure] == ["ole"], length


def test_a_detector_bug_is_named_not_a_quiet_no_match(monkeypatch):
    lnk = C.build("lnk_shortcut")

    def buggy(d):
        return d.no_such_attribute
    monkeypatch.setitem(formats.DETECTORS, "riff", buggy)
    with pytest.raises(formats.DetectorError, match="the riff detector raised AttributeError"):
        formats.identify(lnk.name, lnk.data, CATALOG)


@pytest.mark.parametrize("error", [struct.error("short"), ValueError("v"), EOFError(),
                                   zipfile.BadZipFile("z"), UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad")])
def test_a_detector_parse_error_is_no_match(monkeypatch, error):
    lnk = C.build("lnk_shortcut")

    def parse_fails(d):
        raise error
    monkeypatch.setitem(formats.DETECTORS, "lnk", parse_fails)
    assert [(m.format, m.sure) for m in formats.identify(lnk.name, lnk.data, CATALOG)] == [("lnk", False)]


def test_an_index_error_is_a_detector_bug_not_a_parse_error(monkeypatch):
    """The detectors slice and use struct.unpack_from: hostile bytes cannot raise IndexError, so one is a
    bug, named (the seeded fuzz below and a 45 000-input run found none)."""
    assert IndexError not in formats.PARSE_ERRORS
    lnk = C.build("lnk_shortcut")

    def off_the_end(d):
        return d[len(d)]
    monkeypatch.setitem(formats.DETECTORS, "lnk", off_the_end)
    with pytest.raises(formats.DetectorError, match="the lnk detector raised IndexError"):
        formats.identify(lnk.name, lnk.data, CATALOG)


def _with_comment(d: bytes, comment: bytes) -> bytes:
    """The zip `d` with its end record's comment set (zipfile writes it, so the file stays a valid zip)."""
    out = io.BytesIO(d)
    with zipfile.ZipFile(out, "a") as z:
        z.comment = comment
    return out.getvalue()


@pytest.mark.parametrize("length", [60_000, 0xFFFF])
@pytest.mark.parametrize("sid,fmt", [("ooxml_docx", "ooxml"), ("msix_package", "msix")])
def test_a_zip_with_a_long_comment_is_still_identified(sid, fmt, length):
    """The end record is searched for in the last 22 + 0xFFFF bytes: the largest comment a zip can carry
    (0xFFFF) puts it at exactly the start of that window."""
    d = _with_comment(C.build(sid).data, b"c" * length)
    assert len(d) - d.rindex(b"PK\x05\x06") == 22 + length
    assert zipfile.ZipFile(io.BytesIO(d)).comment == b"c" * length
    got = formats.identify("x.bin", d, CATALOG)
    assert (got[0].format, got[0].sure) == (fmt, True)


def test_the_zip_view_clamps_a_seek_before_the_start():
    view = formats._View(b"0123456789")
    assert view.seek(3) == 3
    assert view.seek(-5, 1) == 0 and view.tell() == 0          # relative, past the start
    assert view.read(2) == b"01"
    assert view.seek(-20, 2) == 0 and view.read(3) == b"012"   # from the end, past the start
    assert view.seek(-4, 2) == 6 and view.read() == b"6789"
    assert view.seek(2) == 2 and view.seek(-1, 1) == 1 and view.read(1) == b"1"


def test_the_stated_directory_size_is_held_to_the_file_size_then_to_the_limit(monkeypatch):
    """A size of exactly the file's length passes the file-size test (and so meets the limit); one byte
    more is no match before the limit is looked at. A size of exactly the limit is read."""
    docx = C.build("ooxml_docx").data
    monkeypatch.setattr(formats, "MAX_ZIP_DIRECTORY_BYTES", 64)
    assert [m for m in formats.identify("x.bin", _set_directory_size(docx, len(docx) + 1), CATALOG) if m.sure] == []
    with pytest.raises(formats.FormatLimit, match=f"central directory of {len(docx)} bytes, over the 64-byte limit"):
        formats.identify("x.bin", _set_directory_size(docx, len(docx)), CATALOG)
    eocd = docx.rindex(b"PK\x05\x06")
    size, = struct.unpack_from("<I", docx, eocd + 12)
    monkeypatch.setattr(formats, "MAX_ZIP_DIRECTORY_BYTES", size)
    assert formats.identify("x.bin", docx, CATALOG)[0].format == "ooxml"
    monkeypatch.setattr(formats, "MAX_ZIP_DIRECTORY_BYTES", size - 1)
    with pytest.raises(formats.FormatLimit):
        formats.identify("x.bin", docx, CATALOG)


def test_a_zip_that_states_an_unsupported_version_is_no_match():
    d = bytearray(C.build("ooxml_docx").data)
    cd = d.index(b"PK\x01\x02")
    d[cd + 5] = 0                                          # version made by: host 0 (MS-DOS) ...
    d[cd + 6] = 108                                        # ... version needed to extract 10.8: zipfile refuses it
    with pytest.raises(NotImplementedError):
        zipfile.ZipFile(io.BytesIO(bytes(d))).infolist()
    assert [m for m in formats.identify("x.docx", bytes(d), CATALOG) if m.sure] == []


def test_hostile_mutations_of_every_sample_never_raise():
    """Truncations and random byte flips of every sample: identify answers (any answer), never raises."""
    rnd = random.Random(162)
    ids, asked = {f.id for f in CATALOG}, 0
    for sid in sorted(C.BUILDERS):
        d = C.build(sid).data
        inputs = [d[:max(0, cut)] for cut in sorted({0, 1, 4, 8, 12, 22, 511, 512, 513, len(d) // 2, len(d) - 22, len(d) - 1}
                                                    | {rnd.randrange(len(d)) for _ in range(10)})]
        for _ in range(60):
            b = bytearray(d)
            for _ in range(rnd.randint(1, 8)):
                b[rnd.randrange(len(b))] = rnd.randrange(256)
            inputs.append(bytes(b))
        for data in inputs:
            got = formats.identify("x", data, CATALOG)        # no extension: every match is structural
            assert all(m.sure and m.format in ids for m in got), (sid, got)
            asked += 1
        assert formats.identify("x", d, CATALOG)[0].sure      # the unmutated sample still is its format
    assert asked >= 70 * len(C.BUILDERS)


def _set_directory_size(d: bytes, size: int) -> bytes:
    b = bytearray(d)
    eocd = b.rindex(b"PK\x05\x06")
    struct.pack_into("<I", b, eocd + 12, size)
    return bytes(b)


def test_a_zip_central_directory_over_the_limit_is_refused_by_name(monkeypatch):
    docx = C.build("ooxml_docx").data
    monkeypatch.setattr(formats, "MAX_ZIP_DIRECTORY_BYTES", 64)
    with pytest.raises(formats.FormatLimit, match=r"central directory of \d+ bytes, over the 64-byte limit"):
        formats.identify("x.docx", docx, CATALOG)
    monkeypatch.setattr(formats, "MAX_ZIP_DIRECTORY_BYTES", 1 << 20)
    assert formats.identify("x.docx", docx, CATALOG)[0].format == "ooxml"


def test_a_zip_end_record_stating_more_than_the_file_holds_is_no_match():
    docx = C.build("ooxml_docx").data
    assert [m for m in formats.identify("x.bin", _set_directory_size(docx, len(docx) + 1), CATALOG) if m.sure] == []


def test_a_zip64_end_record_states_the_directory_size(tmp_path, monkeypatch):
    path = tmp_path / "z.zip"
    with zipfile.ZipFile(path, "w", allowZip64=True) as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w/>")
    plain = path.read_bytes()
    eocd = plain.rindex(b"PK\x05\x06")
    count, size, offset = struct.unpack_from("<HII", plain, eocd + 10)
    zip64 = struct.pack("<4sQHHIIQQQQ", b"PK\x06\x06", 44, 45, 45, 0, 0, count, count, size, offset)
    locator = struct.pack("<4sIQI", b"PK\x06\x07", 0, eocd, 1)
    end = bytearray(plain[eocd:])
    struct.pack_into("<HHII", end, 8, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF)
    data = plain[:eocd] + zip64 + locator + bytes(end)
    assert zipfile.ZipFile(io.BytesIO(data)).namelist() == ["[Content_Types].xml", "word/document.xml"]
    assert formats.identify("z.zip", data, CATALOG)[0].format == "ooxml"
    monkeypatch.setattr(formats, "MAX_ZIP_DIRECTORY_BYTES", size - 1)      # the zip64 record's size is the one read
    with pytest.raises(formats.FormatLimit, match=f"central directory of {size} bytes"):
        formats.identify("z.zip", data, CATALOG)


@pytest.mark.parametrize("sid", sorted(C.BUILDERS))
def test_identify_path_maps_the_file_and_agrees_with_identify(tmp_path, monkeypatch, sid):
    s = C.build(sid)
    path = tmp_path / s.name
    path.write_bytes(s.data)

    def whole(*a, **k):
        raise AssertionError("the file was read whole")
    monkeypatch.setattr(Path, "read_bytes", whole)
    assert formats.identify_path(path, CATALOG) == formats.identify(s.name, s.data, CATALOG)


def test_identify_path_of_an_empty_file(tmp_path):
    path = tmp_path / "empty.lnk"
    path.write_bytes(b"")
    assert [(m.format, m.sure) for m in formats.identify_path(path, CATALOG)] == [("lnk", False)]


def test_mail_detection_wants_a_header_block_not_a_mention():
    assert formats.DETECTORS["eml"](C.build("eml_attachments").data)
    assert not formats.DETECTORS["eml"](b"Dear team,\nFrom: the note below\nSubject: none\n\nthanks")
    assert not formats.DETECTORS["eml"](b"Subject: s\nDate: Tue, 04 Mar 2025\nTo: b@x.test\n\nno sender")
    assert formats.DETECTORS["eml"](b"From someone Tue Mar  4 05:06:07 2025\nFrom: a@b.test\nSubject: s\n\nbody")


# ------------------------------------------------------------------ the builders against readers that are not the lane's

def test_compound_file_streams_read_back_through_olefile():
    big = bytes(range(256)) * 40                    # over the mini-stream cutoff
    data = C.cfb_write({"Small": b"abc" * 10, "Big": big, "Store/Inner": b"nested"}, clsid=b"\x11" * 16)
    with olefile.OleFileIO(io.BytesIO(data)) as ole:
        assert ole.openstream("Small").read() == b"abc" * 10
        assert ole.openstream("Big").read() == big
        assert ole.openstream("Store/Inner").read() == b"nested"
        assert ole.root.clsid == "11111111-1111-1111-1111-111111111111"


def test_summary_information_reads_back_through_olefile():
    data = C.cfb_write({"\x05SummaryInformation": C.property_set({"title": "T one", "author": "A two", "page_count": 9,
                                                                   "create_time": C.WHEN})})
    with olefile.OleFileIO(io.BytesIO(data)) as ole:
        meta = ole.get_metadata()
    assert (meta.title, meta.author, meta.num_pages) == (b"T one", b"A two", 9)
    assert meta.create_time.replace(tzinfo=None) == C.WHEN.replace(tzinfo=None)


@pytest.mark.parametrize("name, table", [("_StringPool", True), ("Property", True), ("payload.cab", False),
                                          ("a", False), ("Binary.Icon_01", True), ("x-y z", False)])
def test_msi_stream_names_decode_through_the_lanes_own_decoder(name, table):
    rf = LANE.MORE_MODULES["readers_formats.py"]
    assert rf.msi_name(C.msi_stream_name(name, table)) == (name, table)


def test_lzx_uncompressed_block_layout():
    body = C.lzx_uncompressed(b"abc")
    word0, word1 = struct.unpack_from("<HH", body)
    bits = ((word0 << 16) | word1) >> 4
    assert bits >> 27 == 0 and (bits >> 24) & 7 == 3 and bits & 0xFFFFFF == 3
    assert body[4:16] == struct.pack("<III", 1, 1, 1) and body[16:] == b"abc\x00"     # odd size: one pad byte
    with pytest.raises(C.CorpusError):
        C.lzx_uncompressed(b"x" * 32769)


@pytest.mark.needs_tool("bsdtar")
def test_lzx_cabinet_unpacks_with_bsdtar(tmp_path):
    import subprocess
    cab = tmp_path / "lzx.cab"
    cab.write_bytes(C.cab_write(C.CAB_MEMBERS, "lzx"))
    out = tmp_path / "out"
    out.mkdir()
    subprocess.run([shutil.which("bsdtar"), "-x", "-f", str(cab), "-C", str(out)], check=True, timeout=30)
    for name, body in C.CAB_MEMBERS:
        assert (out / name).read_bytes() == body


def test_samples_are_byte_stable():
    for sid, fn in C.BUILDERS.items():
        assert fn().data == fn().data, sid


# ------------------------------------------------------------------ one fixture test per format: every check

@pytest.mark.parametrize("sid, index", _check_params())
def test_every_check_is_read_by_the_lane(no_judge, sid, index):
    s = C.build(sid)
    c = s.checks[index]
    answer, err = X.ask(LANE, c.prop, s, c.artifact)
    status, ok = _matched(answer, c.expected)
    assert ok, f"{sid} {c.prop}: expected {c.expected!r}, got {status} {answer!r}\n{err[-800:]}"
    if c.prop not in IDENTITY:
        assert status == "unsure", f"{c.prop} must not be plain before the judge has spoken: {answer!r}"


def _other_format_sample(sid):
    own = next(f for f in CATALOG if sid in f.samples)
    other = next(f for f in CATALOG if f.id != own.id and f.id != own.refines and own.id != f.refines)
    return C.build(other.samples[0])


@pytest.mark.parametrize("sid", sorted(C.BUILDERS))
def test_no_check_holds_on_a_file_of_another_format(no_judge, sid):
    s, other = C.build(sid), _other_format_sample(sid)
    for c in s.checks:
        if c.prop in IDENTITY or c.artifact:
            continue
        answer, _ = X.ask(LANE, c.prop, other)
        status, ok = _matched(answer, c.expected)
        assert not ok, f"{c.prop} of {sid} also 'holds' on {other.id}: {status} {answer!r}"


def test_a_wrong_expectation_is_not_matched(no_judge):
    s = C.build("lnk_shortcut")
    answer, _ = X.ask(LANE, "lnk.target_path", s)
    assert _matched(answer, C.LNK_TARGET)[1]
    assert not _matched(answer, C.LNK_TARGET + "x")[1]
    answer, _ = X.ask(LANE, "lnk.target_file_size", s)
    assert _matched(answer, 48128)[1] and not _matched(answer, 48129)[1]


def test_quantum_cabinet_in_an_msi_is_unpacked_by_the_lanes_decoder(no_judge):
    import msi_fixtures                       # tests/: the Quantum encoder held to libmspack and 7zz
    data = b"".join(b for _, b in C.CAB_MEMBERS)
    cab = C.cab_write(C.CAB_MEMBERS, "quantum", window_bits=18, blocks=msi_fixtures.quantum_encode(data, 18))
    s = C._msi("msi_quantum", cab, "quantum")
    for c in s.checks:
        if c.prop in ("msi.cabinet_compression", "msi.cabinet_file_sha256_list", "msi.cabinet_member_names"):
            answer, err = X.ask(LANE, c.prop, s)
            assert _matched(answer, c.expected)[1], (c.prop, answer, err[-600:])


def test_an_unread_quantum_folder_gives_no_digest(no_judge):
    """A Quantum folder whose blocks are not Quantum: no member digest, never a digest of the packed bytes."""
    junk = [(b"\x55" * 40, sum(len(b) for _, b in C.CAB_MEMBERS))]
    s = C._msi("msi_bad_quantum", C.cab_write(C.CAB_MEMBERS, "quantum", window_bits=18, blocks=junk), "quantum")
    answer, _ = X.ask(LANE, "msi.cabinet_file_sha256_list", s)
    status, values, _ = X.classify(answer, labels)
    assert not any(v in X.renderings([__import__("hashlib").sha256(b).hexdigest() for _, b in C.CAB_MEMBERS]) for v in values)


# ------------------------------------------------------------------ nearest reader: always unsure

NEAREST = [(f.id, n) for f in CATALOG for n in f.nearest]


@pytest.mark.parametrize("fid, n", NEAREST, ids=[n.asked for _, n in NEAREST])
@pytest.mark.parametrize("ledger", ["off", "on"])
def test_a_nearest_reader_answer_is_always_unsure(monkeypatch, fid, n, ledger):
    if ledger == "off":
        monkeypatch.setenv("CTF_JUDGE_LEDGER", "off")
    else:
        monkeypatch.delenv("CTF_JUDGE_LEDGER", raising=False)
    answer, err = X.ask(LANE, n.asked, C.build(n.sample))
    status, values, names = X.classify(answer, labels)
    assert status == "unsure", f"{n.asked}: {status} {answer!r}\n{err[-600:]}"
    registered = LANE.lookup(LANE.canon(n.asked)) is not None
    assert registered or any(name.endswith("~" + n.reader) for name in names), (n.asked, names)


def test_the_judged_name_is_plain_and_its_nearest_spelling_is_not(monkeypatch):
    """msi.product_code_guid is judged (braces_upper, the tracked seed): plain. The same reader reached under
    a spelling the judge never saw stays unsure, with the stored form first."""
    monkeypatch.delenv("CTF_JUDGE_LEDGER", raising=False)
    s = C.build("msi_package")
    direct, _ = X.ask(LANE, "msi.product_code_guid", s)
    assert X.classify(direct, labels)[0] == "plain" and direct == C.PRODUCT_CODE
    for asked in ("installer.product_code_guid", "msi.property_table_product_code_guid"):
        near, _ = X.ask(LANE, asked, s)
        status, values, _ = X.classify(near, labels)
        assert status == "unsure" and values[0] == C.PRODUCT_CODE, (asked, near)
