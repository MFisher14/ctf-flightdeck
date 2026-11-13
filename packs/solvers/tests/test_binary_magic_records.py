"""B-225: the magic-agnostic XOR+CRC record reader (solvers/binary/magic_records.py).

Fixtures are built synthetically in the test. `binary_lookahead.record("hdr16crc", tag, obj, key, endian)`
is the HCFG/HGAU/HGRF shape (magic | version u8 | key u8 | length u16 | crc32 u32 | payload XOR key).
"""
import base64
import json
import struct
import zlib

import pytest

import binary_lookahead as L
import magic_records as mr


CFG = {"campaign": "BR31-gauntlet", "url": "https://example.invalid/c2", "sleep": 30}


def hdr16(tag, obj, key=0x5A, endian="<"):
    return L.record("hdr16crc", tag, obj, key=key, endian=endian)


# ---------------------------------------------------------------------------- magic-agnostic record reading

def test_reads_a_record_under_any_printable_magic():
    for tag in (b"HCFG", b"HGAU", b"HGRF", b"QX41", b"abc0"):
        data = b"\x00" * 16 + hdr16(tag, CFG) + b"\x00" * 8
        rec = mr.unique_record(data, tag)
        assert rec is not None and rec.magic == tag
        assert rec.json == CFG and rec.key == 0x5A


def test_discovers_the_magic_when_none_is_pinned():
    data = b"filler....." + hdr16(b"HGAU", CFG)
    rec = mr.unique_record(data)                 # magic not given: discovered from the bytes
    assert rec is not None and rec.magic == b"HGAU" and rec.json == CFG


def test_a_corrupt_crc_is_no_record():
    # the stored CRC does not match the de-XORed payload: never read, never a guess
    bad = bytearray(hdr16(b"HGAU", CFG))
    bad[8] ^= 1                                   # flip a CRC byte
    assert mr.records(bytes(bad), b"HGAU") == []
    assert mr.unique_record(bytes(bad), b"HGAU") is None


def test_a_wrong_magic_does_not_match():
    data = hdr16(b"HGAU", CFG)
    assert mr.records(data, b"HCFG") == []        # the bytes are an HGAU record, not an HCFG one


def test_backward_scan_takes_the_last_record_first():
    # two valid records of one magic: forward yields the first offset first, backward the last
    data = hdr16(b"HGAU", {"n": 1}) + hdr16(b"HGAU", {"n": 2})
    fwd = mr.records(data, b"HGAU")
    bwd = mr.records(data, b"HGAU", backward=True)
    assert [r.offset for r in fwd] == sorted(r.offset for r in fwd)
    assert [r.offset for r in bwd] == sorted((r.offset for r in bwd), reverse=True)
    assert {r.json["n"] for r in fwd} == {1, 2}


def test_big_endian_length_and_crc():
    data = hdr16(b"HGAU", CFG, endian=">")
    assert mr.records(data, b"HGAU", endian="<") == []
    rec = mr.unique_record(data, b"HGAU", endian=">")
    assert rec is not None and rec.endian == ">" and rec.json == CFG


def test_both_endians_tried_by_default():
    data = hdr16(b"HGAU", CFG, endian=">")
    rec = mr.unique_record(data, b"HGAU")         # endian not pinned
    assert rec is not None and rec.endian == ">"


def test_unique_record_is_none_when_two_payloads_differ():
    data = hdr16(b"HGAU", {"n": 1}) + hdr16(b"HGAU", {"n": 2})
    assert mr.unique_record(data, b"HGAU") is None   # two distinct records: never a guess


def test_two_identical_records_are_one():
    data = hdr16(b"HGAU", CFG) + hdr16(b"HGAU", CFG)
    rec = mr.unique_record(data, b"HGAU")
    assert rec is not None and rec.json == CFG


def test_a_length_past_the_blob_is_no_record():
    rec = bytearray(hdr16(b"HGAU", CFG))
    struct.pack_into("<H", rec, 6, 0xFFFF)        # a length field far past the bytes
    assert mr.records(bytes(rec), b"HGAU") == []


def test_zero_length_is_no_record():
    rec = bytearray(hdr16(b"HGAU", CFG))
    struct.pack_into("<H", rec, 6, 0)
    assert mr.records(bytes(rec), b"HGAU") == []


def test_a_record_whose_payload_is_not_json_is_crc_valid_but_has_no_json():
    plain = b"not json at all!!"
    key = 0x33
    payload = bytes(b ^ key for b in plain)
    data = b"RAWR" + struct.pack("<BBHI", 1, key, len(payload), zlib.crc32(plain) & 0xFFFFFFFF) + payload
    recs = mr.records(data, b"RAWR")
    assert len(recs) == 1 and recs[0].json is None    # CRC proves the bytes; they are simply not JSON


def test_bad_magic_length_raises():
    with pytest.raises(ValueError):
        mr.records(b"\x00" * 64, b"TOOLONG")


# ---------------------------------------------------------------------------- post-XOR transforms (others)

def _b64_record(tag, obj, key=0x5A):
    # stored payload = XOR(base64(JSON), key); CRC is over the DECODED JSON (hcfg.py's 'base64' reading)
    json_bytes = json.dumps(obj, separators=(",", ":")).encode()
    text = base64.b64encode(json_bytes)
    enc = bytes(b ^ key for b in text)
    return tag + struct.pack("<BBHI", 1, key, len(enc), zlib.crc32(json_bytes) & 0xFFFFFFFF) + enc


def test_others_reads_a_base64_payload_crc_gated():
    data = _b64_record(b"HGAU", CFG)
    assert mr.records(data, b"HGAU") == []             # plain XOR is base64 text, CRC is over the JSON
    rec = mr.unique_record(data, b"HGAU", others=True)
    assert rec is not None and rec.decoding == "base64" and rec.json == CFG


def test_others_off_does_not_invent_a_transform():
    data = _b64_record(b"HGAU", CFG)
    assert mr.unique_record(data, b"HGAU") is None      # without others=True, no transform is tried


# ---------------------------------------------------------------------------- field-word -> record-root

def test_resolve_drops_a_leading_root_word_absent_from_the_json():
    # fields_d31: the question says gauntlet.config.sleep, the JSON has only config, no gauntlet key
    rec_json = {"config": {"sleep": 30, "url": "x"}, "trace": {"branch": "success"}}
    ok, v = mr.resolve(rec_json, "gauntlet.config.sleep")
    assert (ok, v) == (True, 30)


def test_resolve_expands_an_underscored_token_into_a_path():
    # gauntlet.trace_branch -> trace.branch (fields_d31._branch's fallback, generalized)
    rec_json = {"config": {}, "trace": {"branch": "decoy"}}
    ok, v = mr.resolve(rec_json, "gauntlet.trace_branch")
    assert (ok, v) == (True, "decoy")


def test_resolve_keeps_a_leading_token_that_is_a_real_key():
    rec_json = {"config": {"url": "u"}}
    ok, v = mr.resolve(rec_json, "config.url")
    assert (ok, v) == (True, "u")


def test_resolve_root_word_is_dropped_even_when_it_is_a_key():
    rec_json = {"gauntlet": "decoy-value", "config": {"sleep": 7}}
    ok, v = mr.resolve(rec_json, "gauntlet.config.sleep", root_word="gauntlet")
    assert (ok, v) == (True, 7)       # root_word forces the drop, not the shadowing 'gauntlet' member


def test_resolve_missing_member_is_not_found():
    rec_json = {"config": {"url": "u"}}
    ok, v = mr.resolve(rec_json, "config.absent")
    assert (ok, v) == (False, None)


def test_resolve_a_path_that_is_only_the_root_word_is_not_found():
    rec_json = {"config": {}}
    ok, v = mr.resolve(rec_json, "gauntlet")
    assert ok is False


# ---------------------------------------------------------------------------- container offset, any magic

def test_container_offset_raw_only_when_crc_valid():
    pre = b"\x00" * 20
    data = pre + hdr16(b"HGAU", CFG)
    off = mr.container_offset(data, b"HGAU")
    assert off["raw"] == len(pre)


def test_container_offset_no_raw_when_the_magic_frames_no_record():
    data = b"....HGAU not a header...."       # the magic stands but frames no CRC-valid record
    off = mr.container_offset(data, b"HGAU")
    assert "raw" not in off


def test_container_offset_finds_a_base64_stored_magic():
    rec = hdr16(b"HGAU", CFG)
    text = base64.b64encode(rec)
    data = b"prefix==" + text
    off = mr.container_offset(data, b"HGAU")
    assert "base64" in off and off["base64"] >= len(b"prefix==")


def test_container_offset_finds_a_hex_stored_magic():
    data = b"xx" + b"HGAU".hex().encode() + b"yy"
    off = mr.container_offset(data, b"HGAU")
    assert off["hex"] == 2


def test_container_offset_finds_a_utf16le_stored_magic():
    wide = b"HGAU".decode("latin-1").encode("utf-16-le")
    data = b"zzz" + wide
    off = mr.container_offset(data, b"HGAU")
    assert off["utf16le"] == 3


@pytest.mark.parametrize("pad", [0, 1, 2])
def test_container_offset_finds_base64_at_each_byte_alignment(pad):
    # the magic can sit at any of the three byte alignments inside a base64 stream; container_offset
    # searches each alignment's seed (no length guard -- every seed of a 4-byte magic is 5-6 chars), so
    # the record is located however it is aligned. This pins the per-alignment behaviour the removed
    # `len(seed) >= 3` dead threshold left untested at its edge.
    rec = hdr16(b"HGAU", CFG)
    text = base64.b64encode(b"\x00" * pad + rec)     # the magic at byte offset `pad` -> b64 alignment `pad`
    data = b"LEADBYTES" + text
    off = mr.container_offset(data, b"HGAU")
    assert "base64" in off and off["base64"] >= len(b"LEADBYTES")
    seeds = mr._b64_seeds(b"HGAU")
    # the reported offset is the start of one of the magic's three base64 seed runs
    assert any(data.startswith(bytes(seed), off["base64"]) for seed in seeds.values())
    # this alignment's own seed is present in the text and is 5-6 chars (never short enough to guard on)
    assert bytes(seeds[pad]) in text and 5 <= len(seeds[pad]) <= 6


# ---------------------------------------------------------------------------- stated magic / path

def test_stated_magic_reads_a_four_char_token():
    assert mr.stated_magic("the decoded HGAU JSON object at the tail") == b"HGAU"
    assert mr.stated_magic("at config.n decoded HGRF JSON property graph") == b"HGRF"


def test_stated_magic_none_when_no_magic_word():
    assert mr.stated_magic("how many members are in the delivery?") is None


def test_stated_magic_skips_a_stopword_and_takes_the_real_magic():
    # JSON, UTF8, BYTE are stopwords, not magics: the real record magic that stands with them is taken
    assert mr.stated_magic("the JSON field in HGAU") == b"HGAU"
    assert mr.stated_magic("decode the UTF8 BYTE run then read HGRF") == b"HGRF"


def test_stated_magic_first_non_stopword_magic_wins():
    # two real magics in one question: the one stated first wins (the question names its own record first)
    assert mr.stated_magic("read HGAU, which resembles the HGRF capsule") == b"HGAU"
    assert mr.stated_magic("compare HGRF against the earlier HGAU record") == b"HGRF"


def test_stated_magic_falls_back_to_a_table_word_when_only_stopwords_are_upper():
    # no upper-case 4-char token survives the stopwords, but a lower-case MAGIC_TABLE word still resolves
    assert mr.stated_magic("the JSON object of the hcfg record") == b"HCFG"


def test_stated_path_reads_a_dotted_path():
    assert mr.stated_path("the decoded HGRF JSON property graph.config.sleep value") == "graph.config.sleep"


def test_stated_path_none_without_a_dot():
    assert mr.stated_path("the xor key as hex") is None


# ---------------------------------------------------------------------------- nested search (CRC gate)

def test_nested_records_through_a_zip_member():
    # an ELF whose overlay is a zip; a zip entry is an HGAU record (generic surfaces every zip entry,
    # magic-agnostically), and the CRC gate reads the record inside -- a container the sample wraps.
    import io
    import zipfile
    rec = hdr16(b"HGAU", CFG)
    image = L.elf64([(".text", b"\xc3" * 16, 6, 0x401000)])
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("cfg.bin", rec)
    data = image + buf.getvalue()
    hits = mr.nested_records(data, b"HGAU")
    assert any(rec_.json == CFG for how, rec_ in hits)
    assert any("zip" in how for how, _ in hits)


def test_nested_records_through_a_base64_layer():
    # an HCFG record base64'd over an ELF: generic's HCFG-anchored base64 reading surfaces the layer,
    # and the CRC gate reads the record (generic._children is HCFG-anchored for text runs).
    rec = hdr16(b"HCFG", CFG)
    image = L.elf64([(".text", b"\xc3" * 16, 6, 0x401000)])
    data = image + base64.b64encode(rec)
    hits = mr.nested_records(data, b"HCFG")
    assert any(rec_.json == CFG for _, rec_ in hits)


def test_nested_records_includes_the_member_itself():
    data = b"\x00" * 8 + hdr16(b"HGAU", CFG)
    hits = mr.nested_records(data, b"HGAU")
    hows = {how for how, _ in hits}
    assert "raw" in hows and any(r.json == CFG for _, r in hits)


# ---------------------------------------------------------------------------- the conservative reader

def _q(qid, text=""):
    return {"qid": qid, "question": text}


def test_solve_set_answers_crc_and_xor_key_plain():
    rec = hdr16(b"HGAU", CFG, key=0x5A)
    crc = struct.unpack_from("<I", rec, 8)[0]
    files = {"d31--sample.elf": b"\x00" * 8 + rec}
    qs = [_q("d31_analysis_gauntlet_crc32_hex", "decoded HGAU JSON crc32"),
          _q("d31_analysis_xor_key_hex", "the HGAU xor key")]
    out = mr.solve_set(qs, files, {})
    assert out["d31_analysis_gauntlet_crc32_hex"] == f"0x{crc:08x}"
    assert out["d31_analysis_xor_key_hex"] == "0x5a"


def test_solve_set_config_member_is_unsure_not_a_wrong_plain():
    rec = hdr16(b"HGAU", CFG)
    files = {"d31--sample.elf": rec}
    out = mr.solve_set([_q("d31_analysis_config_url", "HGAU config.url")], files, {})
    got = out.get("d31_analysis_config_url")
    assert got is not None and str(got).startswith("??")   # an unsure pick, never a plain wrong answer
    # the proposed value is the real member, carried in the unsure string
    assert "https://example.invalid/c2" in str(got)


def test_solve_set_ignores_a_member_with_no_record():
    files = {"d31--sample.elf": b"no record here at all"}
    out = mr.solve_set([_q("d31_analysis_gauntlet_crc32_hex", "HGAU crc32")], files, {})
    assert out == {}


def test_solve_set_a_reader_that_raises_costs_only_its_own_id(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("boom")
    monkeypatch.setattr(mr, "unique_record", boom)
    files = {"d31--sample.elf": hdr16(b"HGAU", CFG)}
    out = mr.solve_set([_q("d31_analysis_gauntlet_crc32_hex", "HGAU crc32")], files, {})
    assert out == {}                      # swallowed with a note, no crash


def test_answer_field_fails_loud_when_labels_is_unavailable(monkeypatch):
    # labels is a Phase-0 contract module, not an optional pack: when it cannot load, a config member is
    # NOT degraded to a possibly-wrong plain answer -- answer_field raises with a named reason (rule 6).
    def no_labels():
        raise RuntimeError("solvers/common/labels.py is unavailable")
    monkeypatch.setattr(mr, "_labels", no_labels)
    rec = mr.unique_record(hdr16(b"HGAU", CFG), b"HGAU")
    assert rec is not None
    # the plain renderings still work without labels
    assert mr.answer_field("xor_key_hex", rec) == "0x5a"
    # but a config member is never a plain fallback -- it raises
    with pytest.raises(RuntimeError):
        mr.answer_field("config_url", rec, "HGAU config.url")


def test_solve_set_skips_a_config_id_when_labels_is_unavailable(monkeypatch):
    # the loud failure costs only the config id; solve_set swallows it, never emitting a wrong plain
    def no_labels():
        raise RuntimeError("solvers/common/labels.py is unavailable")
    monkeypatch.setattr(mr, "_labels", no_labels)
    files = {"d31--sample.elf": hdr16(b"HGAU", CFG)}
    out = mr.solve_set([_q("d31_analysis_config_url", "HGAU config.url")], files, {})
    assert out == {}                      # not answered -- never the plain "https://example.invalid/c2"


def test_labels_loader_raises_a_named_error_when_the_module_cannot_import(monkeypatch):
    # Drives the REAL _labels() body (the two tests above replace it). A None entry in sys.modules makes
    # `import labels` raise ImportError, which is the branch that once returned None silently.
    import sys
    monkeypatch.setitem(sys.modules, "labels", None)
    with pytest.raises(RuntimeError) as err:
        mr._labels()
    assert "solvers/common/labels.py" in str(err.value)      # the named reason, not a bare failure
    assert isinstance(err.value.__cause__, ImportError)


def test_a_config_member_is_never_plain_when_labels_cannot_import(monkeypatch):
    # The same real import failure, end to end: answer_field raises and solve_set drops only that id.
    import sys
    monkeypatch.setitem(sys.modules, "labels", None)
    data = hdr16(b"HGAU", CFG, key=0x5A)
    rec = mr.unique_record(data, b"HGAU")
    assert rec is not None
    with pytest.raises(RuntimeError):
        mr.answer_field("config_url", rec, "HGAU config.url")
    qs = [_q("d31_analysis_config_url", "HGAU config.url"), _q("d31_analysis_xor_key_hex", "the HGAU xor key")]
    out = mr.solve_set(qs, {"d31--sample.elf": data}, {})
    assert out == {"d31_analysis_xor_key_hex": "0x5a"}       # the plain rendering survives; no wrong plain


def test_labels_loader_returns_the_real_contract_module():
    labels = mr._labels()
    assert callable(labels.pick)
    assert str(labels.pick("binary.magic_config/config.url", [("record_member", "v")])).startswith("??")


def test_solve_set_composes_with_computed_wrap():
    from ctf.lookahead import computed
    rec = hdr16(b"HGAU", CFG, key=0x5A)
    files = {"d31--sample.elf": rec}
    wrapped = computed.wrap(mr.solve_set)
    count_q = {"qid": "d31_analysis_member_count", "question": "How many members are in the delivery",
               "answer_format": {"kind": "integer"}}
    qs = [_q("d31_analysis_xor_key_hex", "HGAU xor key"), count_q]
    out = wrapped(qs, files, {})
    assert out["d31_analysis_xor_key_hex"] == "0x5a"      # my reader's answer is kept
    assert out["d31_analysis_member_count"] == 1          # the computed tier fills the empty id
