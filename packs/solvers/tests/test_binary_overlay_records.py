"""B-216: the magic-agnostic overlay and record reader (solvers/binary/overlay_records.py)."""
import base64
import gzip
import json
import random
import struct
import zlib

import pytest

import binary_lookahead as L
import overlay_records as orr

TEXT = [(".text", b"\xc3" * 32, 6, 0x401000)]
CFG = {"campaign": "BR21-look-ahead", "url": "https://example.invalid/c2", "sleep": 30}
FRAMINGS = ["hdr16crc", "hdr32crc", "len32crc", "len32sha", "tlv32", "footer"]


def test_elf_overlay_starts_after_the_section_header_table():
    image = L.elf64(TEXT)
    ov = orr.overlay(image + b"TAILDATA")
    assert (ov.container, ov.start, ov.blob) == ("elf", len(image), b"TAILDATA")
    assert orr.overlay(image).blob == b""


def test_elf_section_past_the_tables_extends_the_image():
    # a section placed after the section header table is part of the image, not an overlay
    image = L.elf64(TEXT)
    data = bytearray(image + b"S" * 40)
    import struct
    shoff = struct.unpack_from("<Q", data, 0x28)[0]
    struct.pack_into("<QQ", data, shoff + 64 + 24, len(image), 40)          # .text's offset and size
    assert orr.overlay(bytes(data)).blob == b""


def test_pe_overlay_excludes_coff_tables_and_the_certificate():
    tail = b"OVERLAY!"
    data = L.pe64([(".text", b"\xc3" * 64, 0x60000020)], coff_symbols=[("main", 1, 0x20, 2)], overlay=tail,
                  cert=b"\x30" * 48)
    ov = orr.overlay(data)
    assert ov.container == "pe" and ov.blob == tail and ov.end == len(data) - 48


def test_macho_overlay_after_the_last_segment():
    image = L.macho64([("_main", 0x0F, 1)])
    ov = orr.overlay(image + b"MACHTAIL")
    assert (ov.container, ov.start, ov.blob) == ("macho", len(image), b"MACHTAIL")


@pytest.mark.parametrize("data", [b"", b"PK\x03\x04zip", b"#!/bin/sh\n", None])
def test_no_image_no_overlay(data):
    assert orr.overlay(data) is None


@pytest.mark.parametrize("framing", FRAMINGS)
@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("tag", [b"HCFG", b"PK19", b"RS20", b"zz_9"])
def test_every_framing_verifies_under_any_tag(framing, endian, tag):
    recs = orr.records(L.record(framing, tag, CFG, endian=endian))
    hits = [r for r in recs if r.framing == framing and r.endian == endian]
    assert len(hits) == 1
    assert hits[0].tag == tag.decode() and hits[0].json == CFG and hits[0].verified


@pytest.mark.parametrize("framing", ["hdr16crc", "hdr32crc", "len32crc", "len32sha"])
def test_a_wrong_check_value_is_no_record(framing):
    assert orr.records(L.record(framing, b"PK19", CFG, corrupt=True)) == []


def test_a_checked_record_inside_other_bytes_is_found():
    rec = L.record("hdr16crc", b"RS20", CFG)
    blob = bytes(range(200, 256)) * 3 + rec + b"\xff" * 33
    recs = [r for r in orr.records(blob) if r.json == CFG]
    assert len(recs) == 1 and recs[0].offset == 168


def test_a_tlv_chain_must_cover_the_blob():
    chain = L.record("tlv32", b"AAAA", {"a": 1}) + L.record("tlv32", b"BBBB", {"b": 2})
    recs = orr.records(chain + b"\0" * 7)
    assert [(r.tag, r.verified) for r in recs] == [("AAAA", "chain"), ("BBBB", "chain")]
    assert orr.records(chain + b"junk-after-the-chain") == []                  # bytes the lengths do not describe


def test_a_footer_must_account_for_every_byte():
    rec = L.record("footer", b"FTR1", CFG)
    assert [r.framing for r in orr.records(rec)] == ["footer"]
    assert [r for r in orr.records(b"x" + rec) if r.framing == "footer"] == []


def test_random_bytes_hold_no_record():
    rng = random.Random(216)
    for _ in range(20):
        assert orr.records(bytes(rng.randrange(256) for _ in range(4096))) == []


def test_text_blob_is_cheap_and_empty():
    blob = (b"lorem ipsum dolor sit amet " * 4000)[:100000]
    assert orr.records(blob) == []


def test_config_is_the_one_distinct_record_across_blobs():
    a = L.record("hdr16crc", b"PK19", CFG)
    b = L.record("len32sha", b"QQ20", CFG)
    assert orr.config([a, b, b"nothing here"]) == CFG
    other = L.record("hdr16crc", b"PK19", dict(CFG, campaign="decoy"))
    assert orr.config([a, other]) is None
    assert orr.config([b"nothing"]) is None


def test_zero_padding_before_a_record_is_skipped():
    rec = L.record("tlv32", b"PAD0", CFG)
    recs = orr.records(b"\0" * 12 + rec)
    assert len(recs) == 1 and recs[0].offset == 12 and recs[0].json == CFG


def test_cli(tmp_path, capsys):
    p = tmp_path / "s.bin"
    p.write_bytes(L.elf64(TEXT, overlay=L.record("hdr16crc", b"PK19", CFG)))
    assert orr._main([str(p)]) == 0
    out = capsys.readouterr().out
    assert "overlay" in out and "tag=PK19" in out and "verified=crc32" in out


# ---------------------------------------------------------------------------- fix round 1 (verification of B-216)

def test_a_bss_section_does_not_extend_the_elf_image():
    # gcc's .bss is SHT_NOBITS: its offset + size runs past the file, and none of it is file bytes
    image = L.elf64(TEXT, nobits=[(".bss", 0x10000, 0x403000)])
    ov = orr.overlay(image + b"TAILDATA")
    assert (ov.start, ov.blob) == (len(image), b"TAILDATA")


def _security_dir(data: bytes, at: int, size: int) -> bytes:
    data = bytearray(data)
    opt = struct.unpack_from("<I", data, 0x3C)[0] + 24
    struct.pack_into("<II", data, opt + 112 + 8 * 4, at, size)     # data directory 4: the certificate table
    return bytes(data)


def test_a_certificate_table_inside_the_image_does_not_cut_it():
    tail = b"OVERLAY!"
    plain = L.pe64([(".text", b"\xc3" * 64, 0x60000020)], overlay=tail)
    image_end = len(plain) - len(tail)
    assert image_end == 0x400                                       # headers 0x200, .text raw 0x200-0x400
    data = _security_dir(plain, 0x300, 48)                          # inside .text, before the image end
    ov = orr.overlay(data)
    assert (ov.start, ov.end, ov.blob) == (image_end, len(data), tail)


@pytest.mark.parametrize("framing", ["hdr16crc", "hdr32crc"])
def test_a_version_byte_above_version_max_is_no_record(framing):
    assert orr.VERSION_MAX == 15
    ok = orr.records(L.record(framing, b"VX15", CFG, version=15))
    assert [(r.tag, r.version) for r in ok if r.framing == framing] == [("VX15", 15)]
    assert orr.records(L.record(framing, b"VX16", CFG, version=16)) == []


def test_tlv_chain_padding_is_at_most_pad_max():
    chain = L.record("tlv32", b"AAAA", {"a": 1}) + L.record("tlv32", b"BBBB", {"b": 2})
    assert orr.PAD_MAX == 15
    assert [r.tag for r in orr.records(chain + b"\0" * 15)] == ["AAAA", "BBBB"]
    assert orr.records(chain + b"\0" * 16) == []


def _crc_record(tag: bytes, packed: bytes, plain: bytes) -> bytes:
    return tag + struct.pack("<II", len(packed), zlib.crc32(plain)) + packed


@pytest.mark.parametrize("how", ["zlib", "gzip"])
def test_an_unpacked_reading_is_capped(monkeypatch, how):
    plain = json.dumps(dict(CFG, pad="P" * 3000)).encode()
    packed = zlib.compress(plain) if how == "zlib" else gzip.compress(plain)
    rec = _crc_record(b"BOMB", packed, plain)
    monkeypatch.setattr(orr, "DECODED_MAX", len(plain))
    assert [(r.tag, r.decoding) for r in orr.records(rec)] == [("BOMB", how)]
    monkeypatch.setattr(orr, "DECODED_MAX", len(plain) - 1)         # it would unpack to one byte more: not read
    assert orr.records(rec) == []


def test_inflate_keeps_the_stdlib_rules():
    z, g = zlib.compress(b"abc"), gzip.compress(b"abc")
    assert orr._inflate(z + b"trailing") == b"abc"                  # as zlib.decompress
    assert orr._inflate(z[:-1]) is None                              # truncated
    assert orr._inflate(g, gz=True) == b"abc"
    assert orr._inflate(g + g, gz=True) == b"abcabc"                 # every member, as gzip.decompress
    assert orr._inflate(g + b"\0\0\0", gz=True) == b"abc"
    assert orr._inflate(g + b"xx", gz=True) is None                  # BadGzipFile there
    assert orr._inflate(b"not a stream") is None


@pytest.mark.parametrize("encode", ["b64encode", "b32encode", "b32hexencode"])
def test_config_reads_a_record_written_whole_as_text(encode):
    real = L.record("hdr16crc", b"QX41", CFG)
    text = getattr(base64, encode)(real)
    assert orr.records(text) == []                                   # the framed reader alone does not see it
    assert orr.config([text]) == CFG
    if encode != "b64encode":
        assert orr.config([text.lower()]) == CFG                    # base32 forms in either case
    decoy = L.record("hdr16crc", b"QX41", dict(CFG, campaign="decoy"))
    assert orr.config([decoy, text]) is None                         # two distinct records: never a guess


def test_text_layers_reads_only_whole_text():
    assert orr.text_layers(b"\x7fELF" + base64.b64encode(b"x" * 30)) == []
    assert orr.text_layers(b"QUJD") == []                              # shorter than TEXT_MIN
    assert ("base64", b"y" * 30) in orr.text_layers(base64.b64encode(b"y" * 30) + b"\n")
