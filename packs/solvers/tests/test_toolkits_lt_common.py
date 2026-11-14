"""B-251: the plumbing the long-tail readers share (solvers/toolkits/_lt_common.py).

What every reader inherits is held here once: the file-size limit and the symlink rule of the folder
walk, the decompression that stops at a stated output size (packed here by each codec's own library,
never by the helper), and the rule that a part a missing decoder left undecoded is named in the result
instead of ending in a quiet "no flag".
"""
import bz2
import json
import lzma
import sys
import zlib

import brotli
import cramjam
import pytest
import zstandard

import _lt_common as common
import lt_avro
from _lt_common import FormatError, NeedsTool, bounded_decompress
from ctf import flagfmt
from ctf.formats import corpus_longtail as L

LEAD = flagfmt.cribs()[0]
SCHEMA = b'{"type": "record", "name": "R", "fields": [{"name": "note", "type": "bytes"}]}'


def avro_with(note: bytes) -> bytes:
    return L.avro_container(SCHEMA, [(1, L.avro_string(note))])


# ------------------------------------------------------------------ the folder walk

def test_a_file_over_the_size_limit_is_named_and_not_read(tmp_path, monkeypatch):
    flag = LEAD + "over_the_size_limit}"
    data = avro_with(flag.encode())
    (tmp_path / "big.avro").write_bytes(data)
    assert lt_avro.solve(tmp_path).flags == (flag,)                      # read while it fits
    monkeypatch.setattr(common, "MAX_FILE_BYTES", len(data) - 1)
    r = lt_avro.solve(tmp_path)
    assert (r.status, r.flags) == ("blocked", ())
    assert f"big.avro: Avro container, {len(data)} bytes is over the {len(data) - 1}-byte limit: not read" in r.notes
    monkeypatch.setattr(common, "MAX_FILE_BYTES", len(data))             # a file of exactly the limit is read
    assert lt_avro.solve(tmp_path).status == "solved"


def test_symlinks_in_a_handout_are_never_followed(tmp_path):
    flag = LEAD + "behind_a_symlink}"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.avro").write_bytes(avro_with(flag.encode()))
    handout = tmp_path / "handout"
    handout.mkdir()
    (handout / "link.avro").symlink_to(outside / "secret.avro")           # a file link
    (handout / "linked").symlink_to(outside, target_is_directory=True)    # and a folder link
    assert common.walk(handout) == ([], False)
    r = lt_avro.solve(handout)
    assert (r.status, r.flags) == ("none", ())
    (handout / "real.avro").write_bytes(avro_with(flag.encode()))
    r = lt_avro.solve(handout)
    assert (r.status, r.flags) == ("solved", (flag,)) and [e.path for e in r.evidence] == ["real.avro"]


def test_more_files_than_the_walk_takes_is_said(tmp_path, monkeypatch):
    for name in ("a.avro", "b.avro", "c.avro"):
        (tmp_path / name).write_bytes(avro_with(b"nothing here"))
    monkeypatch.setattr(common, "MAX_FILES", 2)
    files, over = common.walk(tmp_path)
    assert [f.name for f in files] == ["a.avro", "b.avro"] and over is True
    r = lt_avro.solve(tmp_path)
    assert r.status == "unsure" and "more than 2 files: only the first 2 (sorted) were looked at" in r.notes
    assert [e.path for e in r.evidence] == ["a.avro", "b.avro"]


# ------------------------------------------------------------------ decompression with a stated limit

def _deflate(raw, wbits):
    c = zlib.compressobj(9, zlib.DEFLATED, wbits)
    return c.compress(raw) + c.flush()


def _zstd_stream(raw):
    c = zstandard.ZstdCompressor().compressobj()       # a streamed frame states no content size
    return c.compress(raw) + c.flush()


PACKERS = {
    "deflate": lambda raw: _deflate(raw, -15), "zlib": lambda raw: _deflate(raw, 15), "gzip": lambda raw: _deflate(raw, 31),
    "bzip2": bz2.compress, "xz": lzma.compress, "brotli": brotli.compress,
    "zstd": lambda raw: zstandard.ZstdCompressor().compress(raw), "zstd-stream": _zstd_stream,
    "snappy": lambda raw: bytes(cramjam.snappy.compress_raw(raw)),
}
RAW = bytes(range(256)) * 40 + b"the tail of the part"


@pytest.mark.parametrize("name", sorted(PACKERS))
def test_bounded_decompress_gives_the_bytes_up_to_its_limit_and_refuses_more(name):
    codec, packed = name.split("-")[0], PACKERS[name](RAW)
    assert bounded_decompress(codec, packed, len(RAW), "part 3") == RAW          # exactly the limit: read
    assert bounded_decompress(codec, packed, len(RAW) + 500, "part 3") == RAW
    for limit in (len(RAW) - 1, 100, 0):
        with pytest.raises(FormatError, match=f"part 3 decompresses to more than {limit} bytes: not inflated further"):
            bounded_decompress(codec, packed, limit, "part 3")


@pytest.mark.parametrize("name", sorted(PACKERS))
def test_bounded_decompress_never_inflates_a_bomb_past_the_limit(name):
    # 48 MiB of zeros packs to kilobytes (snappy: about 2 MiB). With a 4096-byte limit the helper must
    # refuse it having produced about that much: traced allocation is the measure, not the clock.
    import tracemalloc
    codec, packed = name.split("-")[0], PACKERS[name](bytes(48 << 20))
    assert len(packed) < 4 << 20
    tracemalloc.start()
    try:
        with pytest.raises(FormatError, match="decompresses to more than 4096 bytes"):
            bounded_decompress(codec, packed, 4096, "the bomb")
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 16 << 20, f"{name}: {peak} bytes were allocated refusing a part limited to 4096"


def test_a_zstd_frame_that_states_its_size_is_refused_before_anything_is_inflated():
    import tracemalloc
    packed = zstandard.ZstdCompressor().compress(bytes(48 << 20))          # the frame header says 48 MiB
    assert zstandard.frame_content_size(packed) == 48 << 20
    tracemalloc.start()
    try:
        with pytest.raises(FormatError, match="the block decompresses to more than 33554432 bytes"):
            bounded_decompress("zstd", packed, 32 << 20, "the block")
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 4 << 20, f"{peak} bytes were inflated of a frame that states more than its limit"


@pytest.mark.parametrize("name", sorted(PACKERS))
def test_bounded_decompress_names_corrupt_and_cut_data(name):
    codec, packed = name.split("-")[0], PACKERS[name](RAW)
    with pytest.raises(FormatError, match=f"part 3: the {codec} data does not decompress"):
        bounded_decompress(codec, packed[:len(packed) // 2], len(RAW), "part 3")          # cut short
    with pytest.raises(FormatError, match=f"part 3: the {codec} data does not decompress"):
        bounded_decompress(codec, b"\x00\xff\x13\x37" * 8, len(RAW), "part 3")


def test_bounded_decompress_lz4_block_and_unknown_codec():
    packed = bytes(cramjam.lz4.compress_block(RAW, store_size=False))
    assert bounded_decompress("lz4", packed, len(RAW), "a page") == RAW
    with pytest.raises(FormatError, match="a page: the lz4 data does not decompress"):
        bounded_decompress("lz4", packed, len(RAW) - 1, "a page")           # the block holds more than was stated
    with pytest.raises(FormatError, match="the codec 'lzo' is not one this reader decodes"):
        bounded_decompress("lzo", packed, len(RAW), "a page")


@pytest.mark.parametrize("codec,module", [("brotli", "brotli"), ("zstd", "zstandard"), ("snappy", "cramjam"),
                                          ("lz4", "cramjam")])
def test_bounded_decompress_names_a_decoder_that_is_not_installed(codec, module, monkeypatch):
    packed = PACKERS.get(codec, lambda raw: bytes(cramjam.lz4.compress_block(raw, store_size=False)))(RAW)
    monkeypatch.setitem(sys.modules, module, None)             # the import fails as on a host without it
    with pytest.raises(NeedsTool, match=f"needs_tool py:{module}: the column is compressed") as e:
        bounded_decompress(codec, packed, len(RAW), "a page", "the column is compressed")
    assert (e.value.tool, e.value.why) == (f"py:{module}", "the column is compressed")


# ------------------------------------------------------------------ a part a missing decoder left undecoded

def _reader(parts):
    """A stand-in reader: every file `*.part` is read, and its facts are parts[name]."""
    return (lambda head, name: name.endswith(".part")), (lambda data, name, opts: (dict(parts[name]), []))


def test_an_undecoded_part_is_named_in_the_notes_whatever_the_status(tmp_path):
    flag = LEAD + "beside_an_undecoded_part}"
    missing = {"format": "x", "needs_tool": ["py:brotli: the box at offset 12 is brotli-compressed"]}
    (tmp_path / "a.part").write_bytes(b"x")
    detect, inspect = _reader({"a.part": missing, "b.part": {"format": "x", "note": "plain"},
                               "c.part": {"format": "x", "note": flag, "needs_tool": ["djxl: pixels"]}})
    note = "a.part: thing: needs_tool py:brotli: the box at offset 12 is brotli-compressed"

    r = common.solve_files("toolkits.t", "thing", tmp_path, None, detect, inspect)
    assert (r.status, r.notes) == ("blocked", note)             # nothing was read whole: not "unsure, no flag"
    assert [e.path for e in r.evidence] == ["a.part"]           # what was read of it is still shown

    (tmp_path / "b.part").write_bytes(b"x")                     # another file read whole, with no flag
    r = common.solve_files("toolkits.t", "thing", tmp_path, None, detect, inspect)
    assert (r.status, r.notes) == ("unsure", note)

    (tmp_path / "c.part").write_bytes(b"x")                     # a flag in what could be read: still named
    r = common.solve_files("toolkits.t", "thing", tmp_path, None, detect, inspect)
    assert (r.status, r.flags) == ("solved", (flag,))
    assert r.notes == note + "; c.part: thing: needs_tool djxl: pixels"


def test_cli_exits_1_and_names_the_tool_when_a_part_was_left_undecoded(tmp_path, capsys):
    (tmp_path / "a.part").write_bytes(b"x")
    (tmp_path / "b.part").write_bytes(b"x")
    detect, inspect = _reader({"a.part": {"format": "x", "needs_tool": ["py:brotli: a box"]}, "b.part": {"format": "x"}})
    assert common.cli([str(tmp_path / "b.part")], "doc", detect, inspect) == 0
    capsys.readouterr()
    assert common.cli([str(tmp_path / "a.part"), str(tmp_path / "b.part")], "doc", detect, inspect) == 1
    first, second = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert first["error"] == "NeedsTool: needs_tool py:brotli: a box" and first["format"] == "x"
    assert "error" not in second
