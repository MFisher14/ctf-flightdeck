"""Independent wire fixtures from ZPAQ 2.06 §§2/4/7 and libzpaq framing.

Fixtures below are assembled directly from the published grammar; the engine
has no encoder. Modeled payloads test framing only, not arithmetic validity.
Unmodeled lengths follow unzpaq206.cpp's big-endian reader (the §2 prose has an
endian typo; §4's CURR := CURR*256 + next_byte and the reference code agree).
"""
import hashlib
import json
import random
import struct

import pytest

import ff_zpaq_inventory as zpaq


TAG = bytes.fromhex("37 6b 53 74 a0 31 83 d3 8c b2 28 b0 d3")


def _block(segments=b"", *, components=(), program=b"", level=2, memory=b"\0" * 4):
    model = memory + bytes([len(components)]) + b"".join(components) + b"\0" + program + b"\0"
    return b"zPQ" + bytes([level, 1]) + struct.pack("<H", len(model)) + model + segments + b"\xff"


def _segment(name=b"", comment=b"", *, chunks=(b"\0hello",), coded=None, sha1=None):
    data = (b"".join(struct.pack(">I", len(chunk)) + chunk for chunk in chunks) + b"\0" * 4
            if coded is None else coded)
    trailer = b"\xfe" if sha1 is None else b"\xfd" + sha1
    return b"\x01" + name + b"\0" + comment + b"\0\0" + data + trailer


def test_literal_minimal_header_offsets_and_hashes():
    # 7 fixed prefix bytes; 7 model bytes; one EOB. No helper needed.
    raw = bytes.fromhex("7a5051 02 01 0700 00000000 00 00 00 ff")
    result = zpaq.inspect_zpaq(raw)
    assert result["block_count"] == 1
    assert result["segment_count"] == 0
    assert result["unparsed_ranges"] == []
    assert result["payload_verified"] is False
    assert result["input_sha256"] == hashlib.sha256(raw).hexdigest()
    block = result["blocks"][0]
    assert (block["offset"], block["end_offset"], block["header_offset"], block["header_size"]) == (0, 15, 7, 7)
    assert (block["hcomp_offset"], block["hcomp_size"]) == (13, 0)
    assert block["stored_sha256"] == hashlib.sha256(raw).hexdigest()


def test_unmodeled_segment_literal_layout_and_declared_hash():
    # SHA-1('hello') from the standard hash, not an engine-derived expected value.
    digest = bytes.fromhex("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
    seg = _segment(b"a.txt", b"5", sha1=digest)
    raw = _block(seg)
    result = zpaq.inspect_zpaq(raw)
    item = result["blocks"][0]["segments"][0]
    assert item["offset"] == 14
    assert item["filename"] == "a.txt"
    assert item["comment"] == "5"
    assert item["declared_size"] == 5
    assert item["encoded_offset"] == 24
    assert item["encoded_size"] == 14  # BE32 length + PASS/hello + BE32 zero
    assert item["terminator_offset"] == 34
    assert item["trailer_offset"] == 38
    assert item["end_offset"] == 59
    assert item["chunk_count"] == 1
    assert item["framed_payload_size"] == 6
    assert item["declared_sha1"] == digest.hex()
    assert item["sha1_verified"] is False
    assert item["size_verified"] is False
    assert item["encoded_sha256"] == hashlib.sha256(raw[24:38]).hexdigest()


def test_unmodeled_data_is_skipped_by_big_endian_lengths():
    # Fake stream, segment markers, and zero terminators inside a chunk are inert.
    payload = b"\0" + TAG + _block() + b"\0" * 9 + b"\xfd\xfe\xff\x01"
    raw = _block(_segment(b"f", b"999", chunks=(payload, b"more")))
    result = zpaq.inspect_zpaq(raw)
    item = result["blocks"][0]["segments"][0]
    assert result["block_count"] == result["segment_count"] == 1
    assert item["chunk_count"] == 2
    assert item["framed_payload_size"] == len(payload) + 4
    assert item["declared_size"] == 999  # never inferred from framed payload
    assert item["encoded_size"] == len(payload) + 4 + 12


@pytest.mark.parametrize("zeros", [4, 5, 6, 7])
@pytest.mark.parametrize("level", [1, 2])
def test_modeled_terminators_segments_and_continuation(zeros, level):
    first = _segment(b"file", b"3", coded=b"\x12\0\0\0\x34" + b"\0" * zeros)
    second = _segment(b"", b"2", coded=b"\x56\0\0\0\0")
    raw = _block(first + second, components=(b"\x01\x80",), program=b"\x38", level=level)
    result = zpaq.inspect_zpaq(raw)
    block = result["blocks"][0]
    assert block["level"] == level
    assert block["hcomp_size"] == 1
    assert block["hcomp_sha256"] == hashlib.sha256(b"\x38").hexdigest()
    a, b = block["segments"]
    assert a["terminator_size"] == zeros
    assert a["encoded_size"] == 5 + zeros
    assert a["continuation_of"] is None
    assert b["continuation_of"] == 0
    assert b["declared_sha1"] is None
    assert b["offset"] == a["end_offset"]


def test_all_component_layouts_and_extreme_memory_do_not_allocate_vm():
    comps = (b"\x01\x80", b"\x02\x20\xff", b"\x03\x1a", b"\x04\x20\x20",
             b"\x05\x00\x03\xff", b"\x06\x20\x00\x04\xff\xff",
             b"\x07\x20\x00\x06\xff\xff", b"\x08\x1a\x06",
             b"\x09\x20\x07\x00\xff")
    # Looping/invalid bytecode is inventoried, not evaluated or rejected as code.
    program = b"\x3f\xfe\0\xff\0\0"
    raw = _block(components=comps, program=program, memory=b"\xff" * 4)
    block = zpaq.inspect_zpaq(raw)["blocks"][0]
    assert (block["hh"], block["hm"], block["ph"], block["pm"]) == (255,) * 4
    assert [c["name"] for c in block["components"]] == ["CONST", "CM", "ICM", "MATCH", "AVG", "MIX2", "MIX", "ISSE", "SSE"]
    assert [c["parameters"] for c in block["components"]] == [list(c[1:]) for c in comps]
    assert block["hcomp_size"] == len(program)


def test_embedded_locator_adjacent_blocks_and_unparsed_ranges():
    a = _block(_segment(b"first"))
    b = _block(_segment())
    raw = b"junkzPQ" + TAG + a + b + b"gap" + TAG + b + b"tail"
    result = zpaq.inspect_zpaq(raw)
    x, y, z = result["blocks"]
    assert x["offset"] == 20
    assert x["locator_offset"] == 7
    assert y["offset"] == 20 + len(a)
    assert y["locator_offset"] is None
    assert y["segments"][0]["continuation_of"] == 0
    assert z["segments"][0]["continuation_of"] is None  # unrelated next sequence
    assert result["unparsed_ranges"] == [
        {"offset": 0, "end_offset": 7},
        {"offset": y["end_offset"], "end_offset": y["end_offset"] + 3},
        {"offset": z["end_offset"], "end_offset": len(raw)},
    ]


def test_binary_names_comments_and_journal_metadata_stay_lossless():
    name = b"../\xffCSCTF{visible}"
    raw = _block(_segment(name, b"4294967295 jDC\x01"))
    item = zpaq.inspect_zpaq(raw)["blocks"][0]["segments"][0]
    assert item["filename_hex"] == name.hex()
    assert item["filename"] == "../\ufffdCSCTF{visible}"
    assert item["comment_hex"] == b"4294967295 jDC\x01".hex()
    assert item["journaling_marker"] is True
    assert item["declared_size"] == 4294967295


@pytest.mark.parametrize("comment,expected", [
    (b"", None), (b"abc", None), (b"12x", None), (b"-1", None), (b"0", 0),
    (b"123 bytes", 123), (b"18446744073709551615", 2**64 - 1),
    (b"18446744073709551616", None), (b"1" * 5000, None),
])
def test_comment_size_is_bounded_advisory_metadata(comment, expected):
    item = zpaq.inspect_zpaq(_block(_segment(comment=comment)))["blocks"][0]["segments"][0]
    assert item["declared_size"] == expected


@pytest.mark.parametrize("raw", [
    b"", b"\xff" * 100, b"zPQ", b"junk" + _block(),
    _block(level=0), _block(level=3), _block(level=1),
    _block(components=(b"\x0a",)), _block(components=(b"\x02\x21\0",)),
    _block(components=(b"\x03\x1b",)), _block(components=(b"\x04\0\x21",)),
    _block(components=(b"\x05\0\0\0",)),
    _block(components=(b"\x01\x80", b"\x07\0\0\x02\0\0")),
    _block(_segment(coded=b"\xff" * 10)),
    _block(_segment(coded=b"\x01\0\0\0x\0\0\0\0")),  # LE32 would be 1
    _block(_segment(coded=b"\x12" + b"\0" * 8), components=(b"\x01\x80",)),
    b"zPQ\x02\x01\x01\x00\x00\xff",  # impossibly short hsize
])
def test_invalid_structures_raise_declared_error(raw):
    with pytest.raises(zpaq.ZpaqError):
        zpaq.inspect_zpaq(raw)


@pytest.mark.parametrize("bad", [None, "zPQ", 123, [], bytearray(b"zPQ"), memoryview(b"zPQ")])
def test_invalid_api_types_raise_declared_error(bad):
    with pytest.raises(zpaq.ZpaqError):
        zpaq.inspect_zpaq(bad)


def test_every_truncation_of_single_block_is_rejected():
    raws = [
        _block(_segment(b"a", b"5", sha1=b"\x11" * 20)),
        TAG + _block(_segment(b"a", b"5", coded=b"\x12" + b"\0" * 4), components=(b"\x01\x80",)),
    ]
    for raw in raws:
        for end in range(len(raw)):
            with pytest.raises(zpaq.ZpaqError):
                zpaq.inspect_zpaq(raw[:end])


def test_deterministic_bitflips_and_random_bytes_never_leak_exceptions():
    raw = _block(_segment(b"a", b"5", sha1=b"\x11" * 20))
    rng = random.Random(20261105)
    inputs = [rng.randbytes(rng.randrange(400)) for _ in range(200)]
    inputs += [raw[:i] + bytes([value ^ (1 << bit)]) + raw[i + 1:]
               for i, value in enumerate(raw) for bit in range(8)]
    inputs += [b"zPQ" + rng.randbytes(200) for _ in range(100)]
    for data in inputs:
        try:
            result = zpaq.inspect_zpaq(data)
        except zpaq.ZpaqError:
            continue
        assert result["payload_verified"] is False
        json.dumps(result)


@pytest.mark.parametrize("limit,raw", [
    ("MAX_INPUT", _block()), ("MAX_BLOCKS", _block() * 2),
    ("MAX_SEGMENTS", _block(_segment() * 2)),
    ("MAX_COMPONENTS", _block(components=(b"\x01\x80",)) * 2),
    ("MAX_CHUNKS", _block(_segment(chunks=(b"a", b"b")))),
    ("MAX_STRING", _block(_segment(b"aa"))),
    ("MAX_METADATA", _block(_segment(b"a", b"b"))),
])
def test_budget_caps_fail_closed(monkeypatch, limit, raw):
    monkeypatch.setattr(zpaq, limit, 1)
    with pytest.raises(zpaq.ZpaqError):
        zpaq.inspect_zpaq(raw)


def test_cli_guards_and_json(tmp_path, capsys, monkeypatch):
    path = tmp_path / "example.zpaq"
    path.write_bytes(_block())
    assert zpaq.main([str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["block_count"] == 1
    assert zpaq.main(["--help"]) == 0
    assert zpaq.main([]) == 2
    assert zpaq.main([str(tmp_path / "missing")]) == 2
    path.write_bytes(b"bad")
    assert zpaq.main([str(path)]) == 2
    def noninteger_exit(*args, **kwargs):
        raise SystemExit("error")
    monkeypatch.setattr(zpaq.argparse.ArgumentParser, "parse_args", noninteger_exit)
    assert zpaq.main([]) == 2
