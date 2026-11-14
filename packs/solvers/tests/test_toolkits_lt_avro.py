"""B-251: the Avro object container reader (solvers/toolkits/lt_avro.py).

The datum decoder is held to the byte examples the Avro specification prints. The container fixtures
are written here by a small encoder that is independent of the reader (its own zigzag and block
writer), under every codec the reader names.
"""
import bz2
import json
import lzma
import struct
import sys
import zlib

import pytest

import lt_avro
from _lt_common import FormatError, NeedsTool
from lt_mutations import bit_flips, mutations, only_declared_errors
from ctf import flagfmt

SYNC = bytes(range(0xA0, 0xB0))


def zz(n):
    """The specification's zigzag varint, written independently of the reader."""
    u = (n << 1) ^ (n >> 63)
    out = bytearray()
    while True:
        b = u & 0x7F
        u >>= 7
        if u:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def s(text):
    b = text.encode() if isinstance(text, str) else text
    return zz(len(b)) + b


def container(schema, blocks, codec="null", sync=SYNC, extra_meta=None, crc_delta=0):
    """blocks: [(record count, encoded records)]."""
    meta = {"avro.schema": json.dumps(schema).encode(), "avro.codec": codec.encode()}
    meta.update(extra_meta or {})
    out = bytearray(b"Obj\x01" + zz(len(meta)))
    for k, v in meta.items():
        out += s(k) + s(v)
    out += zz(0) + sync
    for count, raw in blocks:
        if codec == "deflate":
            c = zlib.compressobj(9, zlib.DEFLATED, -15)
            body = c.compress(raw) + c.flush()
        elif codec == "snappy":
            import cramjam
            body = bytes(cramjam.snappy.compress_raw(raw)) + struct.pack(">I", (zlib.crc32(raw) + crc_delta) & 0xFFFFFFFF)
        elif codec == "bzip2":
            body = bz2.compress(raw)
        elif codec == "xz":
            body = lzma.compress(raw)
        elif codec == "zstandard":
            import zstandard
            body = zstandard.ZstdCompressor().compress(raw)
        else:
            body = raw
        out += zz(count) + zz(len(body)) + body + sync
    return bytes(out)


SCHEMA = {"type": "record", "name": "Row", "namespace": "corp.audit", "fields": [
    {"name": "id", "type": "long"},
    {"name": "user", "type": "string"},
    {"name": "note", "type": ["null", "string"]},
    {"name": "blob", "type": "bytes"},
    {"name": "level", "type": {"type": "enum", "name": "Level", "symbols": ["LOW", "HIGH"]}},
    {"name": "again", "type": "Level"},
    {"name": "tag", "type": {"type": "fixed", "name": "Tag", "size": 4}},
    {"name": "scores", "type": {"type": "array", "items": "int"}},
    {"name": "attrs", "type": {"type": "map", "values": "double"}},
    {"name": "ok", "type": "boolean"},
    {"name": "ratio", "type": "float"},
]}


def row(i, user, note, blob, level, tag, scores, attrs, ok, ratio, negative_blocks=False):
    out = zz(i) + s(user) + (zz(0) if note is None else zz(1) + s(note)) + s(blob) + zz(level) + zz(1 - level) + tag
    items = b"".join(zz(x) for x in scores)
    if negative_blocks and scores:
        out += zz(-len(scores)) + zz(len(items)) + items + zz(0)
    else:
        out += (zz(len(scores)) + items if scores else b"") + zz(0)
    pairs = b"".join(s(k) + struct.pack("<d", v) for k, v in attrs.items())
    out += (zz(len(attrs)) + pairs if attrs else b"") + zz(0)
    return out + bytes([ok]) + struct.pack("<f", ratio)


ROWS = [(7, "ada", None, b"\x00\xff\x10", 0, b"TAG1", [1, -2, 300], {"x": 1.5}, True, 0.5),
        (-9, "bob", "second", b"plain bytes", 1, b"TAG2", [], {}, False, 2.0)]
WANT = [{"id": 7, "user": "ada", "note": None, "blob": "hex:00ff10", "level": "LOW", "again": "HIGH", "tag": "TAG1",
         "scores": [1, -2, 300], "attrs": {"x": 1.5}, "ok": True, "ratio": 0.5},
        {"id": -9, "user": "bob", "note": "second", "blob": "plain bytes", "level": "HIGH", "again": "LOW", "tag": "TAG2",
         "scores": [], "attrs": {}, "ok": False, "ratio": 2.0}]


@pytest.mark.parametrize("n,hexed", [(0, "00"), (-1, "01"), (1, "02"), (-2, "03"), (2, "04"), (-64, "7f"), (64, "8001")])
def test_zigzag_long_matches_the_specification_table(n, hexed):
    assert lt_avro.read_long(bytes.fromhex(hexed), 0) == (n, len(hexed) // 2)
    assert zz(n).hex() == hexed          # the test's own writer agrees with the published bytes


def test_datum_decoder_matches_the_specification_examples():
    rec = {"type": "record", "name": "test", "fields": [{"name": "a", "type": "long"}, {"name": "b", "type": "string"}]}
    assert lt_avro.decode_datum(rec, bytes.fromhex("3606666f6f")) == ({"a": 27, "b": "foo"}, 5)
    assert lt_avro.decode_datum({"type": "array", "items": "long"}, bytes.fromhex("04063600")) == ([3, 27], 4)
    assert lt_avro.decode_datum(["null", "string"], bytes.fromhex("00")) == (None, 1)
    assert lt_avro.decode_datum(["null", "string"], bytes.fromhex("020261")) == ("a", 3)
    assert lt_avro.decode_datum("string", bytes.fromhex("06666f6f")) == ("foo", 4)


@pytest.mark.parametrize("codec", ["null", "deflate", "snappy", "bzip2", "xz", "zstandard"])
def test_container_records_under_every_codec(codec):
    data = container(SCHEMA, [(1, row(*ROWS[0])), (1, row(*ROWS[1]))], codec, extra_meta={"owner": b"forensics"})
    got = lt_avro.read_container(data)
    assert got["records"] == WANT
    assert (got["codec"], got["block_count"], got["record_count"]) == (codec, 2, 2)
    assert got["sync_hex"] == SYNC.hex()
    assert got["metadata"] == {"avro.codec": codec, "owner": "forensics"}
    assert got["schema"] == SCHEMA           # the embedded schema, without the reader's bookkeeping


def test_negative_block_counts_carry_a_byte_size():
    data = container(SCHEMA, [(1, row(*ROWS[0], negative_blocks=True))])
    assert lt_avro.read_container(data)["records"] == WANT[:1]


def test_record_cap_keeps_the_true_count():
    data = container(SCHEMA, [(2, row(*ROWS[0]) + row(*ROWS[1]))])
    got = lt_avro.read_container(data, max_records=1)
    assert (got["record_count"], got["records_kept"], got["records"]) == (2, 1, WANT[:1])


def test_corruption_is_named_never_a_shorter_result():
    good = container(SCHEMA, [(1, row(*ROWS[0])), (1, row(*ROWS[1]))])
    bad_sync = good[:-1] + bytes([good[-1] ^ 1])
    with pytest.raises(FormatError, match="block 1: the sync marker"):
        lt_avro.read_container(bad_sync)
    with pytest.raises(FormatError, match="runs past the end"):
        lt_avro.read_container(good[:-20])
    with pytest.raises(FormatError, match="snappy CRC32"):
        lt_avro.read_container(container(SCHEMA, [(1, row(*ROWS[0]))], "snappy", crc_delta=1))
    with pytest.raises(FormatError, match="block 0: the deflate data does not decompress"):
        lt_avro.read_container(container(SCHEMA, [(1, b"\xff\xff\xff\xff")], "null").replace(b"\x08null", b"\x0edeflate"))
    with pytest.raises(FormatError, match="codec 'lzo'"):
        lt_avro.read_container(container(SCHEMA, [(1, row(*ROWS[0]))], "lzo"))
    with pytest.raises(FormatError, match="3 bytes are left after its 1 records"):
        lt_avro.read_container(container(SCHEMA, [(1, row(*ROWS[0]) + b"\x00\x00\x00")]))
    with pytest.raises(FormatError, match="union index 5"):
        lt_avro.decode_datum(["null", "string"], zz(5))
    with pytest.raises(FormatError, match="never defines"):
        lt_avro.decode_datum({"type": "record", "name": "r", "fields": [{"name": "a", "type": "Missing"}]}, b"\x00")


def test_namespaces_resolve_short_names_inside_the_enclosing_record():
    schema = {"type": "record", "name": "Outer", "namespace": "a.b", "fields": [
        {"name": "first", "type": {"type": "record", "name": "Inner", "fields": [{"name": "v", "type": "int"}]}},
        {"name": "second", "type": "Inner"},
        {"name": "third", "type": "a.b.Inner"}]}
    assert lt_avro.decode_datum(schema, zz(1) + zz(2) + zz(3))[0] == {"first": {"v": 1}, "second": {"v": 2}, "third": {"v": 3}}


def test_solve_finds_a_flag_in_a_bytes_field_and_reports_statuses(tmp_path):
    flag = flagfmt.cribs()[0] + "avro_bytes_field}"
    blob = b"\x00\x01\xfe" + flag.encode() + b"\xff"
    rows = (7, "ada", None, blob, 0, b"TAG1", [], {}, True, 0.5)
    (tmp_path / "export.avro").write_bytes(container(SCHEMA, [(1, row(*rows))], "deflate"))
    (tmp_path / "notes.txt").write_bytes(b"Obj is not the magic here")
    r = lt_avro.solve(tmp_path)
    assert (r.status, r.flags) == ("solved", (flag,))
    assert r.evidence[0].path == "export.avro"

    # the same flag met again (a second file, and as text and bytes of one record) is still one flag
    twice = (7, "ada", flag, flag.encode(), 0, b"TAG1", [], {}, True, 0.5)
    (tmp_path / "copy.avro").write_bytes(container(SCHEMA, [(1, row(*twice))]))
    r = lt_avro.solve(tmp_path)
    assert (r.status, r.flags) == ("solved", (flag,))
    assert [e.path for e in r.evidence] == ["copy.avro", "export.avro"]
    (tmp_path / "copy.avro").unlink()

    other = flagfmt.cribs()[0] + "second_one}"
    (tmp_path / "more.avro").write_bytes(container(SCHEMA, [(1, row(*ROWS[1][:2], other, *ROWS[1][3:]))]))
    r = lt_avro.solve(tmp_path)
    assert r.status == "candidate" and set(r.flags) == {flag, other}


def test_solve_without_a_flag_is_unsure_or_none(tmp_path):
    assert lt_avro.solve(tmp_path).status == "none"
    (tmp_path / "a.avro").write_bytes(container(SCHEMA, [(1, row(*ROWS[0]))]))
    r = lt_avro.solve(tmp_path)
    assert r.status == "unsure" and "record_count=1" in r.evidence[0].detail
    (tmp_path / "a.avro").write_bytes(container(SCHEMA, [(1, row(*ROWS[0]))])[:-3])
    r = lt_avro.solve(tmp_path)
    assert r.status == "unsure" and "malformed Avro container" in r.notes


def test_cli_prints_one_json_object_per_file(tmp_path, capsys):
    p = tmp_path / "x.avro"
    p.write_bytes(container(SCHEMA, [(1, row(*ROWS[1]))]))
    q = tmp_path / "not.avro"
    q.write_bytes(b"plain")
    from _lt_common import cli
    assert cli([str(p), str(q), "--out", str(tmp_path / "out")], lt_avro.__doc__, lt_avro.detect, lt_avro.inspect) == 1
    first, second = [json.loads(x) for x in capsys.readouterr().out.splitlines()]
    assert first["records"] == WANT[1:] and "error" not in first
    assert "FormatError" in second["error"]
    written = sorted((tmp_path / "out").iterdir())
    assert [w.read_bytes() for w in written] == [b"plain bytes", b"TAG2"]


# ------------------------------------------------------------------ round 1: hostile files and stated bounds

@pytest.mark.parametrize("schema,message", [
    ({"type": "record", "name": "r", "fields": 5}, "the fields of r are not a list"),
    ({"type": "record", "name": "r", "fields": [7]}, "a field of r has no type"),
    ({"type": "enum", "name": "e", "symbols": 7}, "the symbols of e are not a list of strings"),
    ({"type": "enum", "name": "e", "symbols": ["A", 2]}, "the symbols of e are not a list of strings"),
    ({"type": "record", "name": "r", "namespace": 5, "fields": []}, "the namespace of r is not a string"),
    ({"type": "fixed", "name": "f", "size": "four"}, "a fixed schema has no size"),
    ({"type": "fixed", "name": 9, "size": 4}, "a fixed schema has no name"),
    (17, "is not an Avro schema"),
    ({"type": 5}, "is not an Avro type"),
])
def test_a_schema_of_the_wrong_json_types_is_a_format_error(schema, message):
    with pytest.raises(FormatError, match=message):
        lt_avro.read_container(container(schema, [(1, b"\x00")]))


def test_a_schema_nested_past_the_json_reader_is_a_format_error():
    deep = b"[" * 100_000 + b"]" * 100_000
    with pytest.raises(FormatError, match="nests deeper"):
        lt_avro.Schema(deep)
    with pytest.raises(FormatError, match="nests deeper"):
        lt_avro.decode_datum(deep, b"\x00")
    with pytest.raises(FormatError, match="nests deeper"):           # the reader's own depth limit, well inside JSON's
        lt_avro.decode_datum(b"[" * 200 + b'"null"' + b"]" * 200, b"\x00")


def test_min_size_is_the_fewest_bytes_a_datum_takes():
    sc = lt_avro.Schema(json.dumps(SCHEMA))
    # id 1, user 1, note 1 (the union index), blob 1, level 1, again 1, tag 4, scores 1, attrs 1, ok 1, ratio 4
    assert sc.min_size(sc.root) == 17
    for schema, least in (("null", 0), ("boolean", 1), ("long", 1), ("float", 4), ("double", 8), ("string", 1),
                          (["null", "double"], 1), ({"type": "array", "items": "double"}, 1),
                          ({"type": "map", "values": "null"}, 1), ({"type": "fixed", "name": "z", "size": 0}, 0),
                          ({"type": "fixed", "name": "f", "size": 6}, 6), ({"type": "record", "name": "e", "fields": []}, 0),
                          ({"type": "record", "name": "n", "fields": [{"name": "a", "type": "null"}]}, 0),
                          ({"type": "record", "name": "p", "fields": [{"name": "a", "type": "double"},
                                                                       {"name": "b", "type": "float"}]}, 12)):
        sc = lt_avro.Schema(json.dumps(schema))
        assert sc.min_size(sc.root) == least, schema
    # a type that holds itself (through a union, as a list node does) is summed once, not without end
    node = {"type": "record", "name": "Node", "fields": [{"name": "v", "type": "long"}, {"name": "next", "type": ["null", "Node"]}]}
    sc = lt_avro.Schema(json.dumps(node))
    assert sc.min_size(sc.root) == 2
    assert lt_avro.decode_datum(node, zz(1) + zz(1) + zz(2) + zz(0))[0] == {"v": 1, "next": {"v": 2, "next": None}}


def test_a_block_cannot_state_more_records_than_its_bytes_hold():
    one = row(*ROWS[0])
    with pytest.raises(FormatError, match=f"block 0 states {1 << 40} records in {len(one)} bytes"):
        lt_avro.read_container(container(SCHEMA, [(1 << 40, one)]))
    # exactly what the bytes can hold is not refused by the bound (it is then decoded and found short)
    longs = container("long", [(3, zz(1) + zz(2) + zz(3))])
    assert lt_avro.read_container(longs)["records"] == [1, 2, 3]
    with pytest.raises(FormatError, match="block 0 states 4 records in 3 bytes"):
        lt_avro.read_container(container("long", [(4, zz(1) + zz(2) + zz(3))]))


@pytest.mark.parametrize("schema,empty", [("null", None), ({"type": "record", "name": "E", "fields": []}, {}),
                                          ({"type": "fixed", "name": "Z", "size": 0}, "")])
def test_records_of_no_size_are_walked_to_a_cap_not_to_the_stated_count(schema, empty):
    # a file of under 150 bytes that states 5,000,000 records, then a second block: the count is all that
    # bounds a datum that takes no bytes, so the walk stops at its cap and says so
    data = container(schema, [(5_000_000, b""), (3, b"")])
    assert len(data) < 150
    got = lt_avro.read_container(data, max_records=4, max_walk=1000)
    assert (got["record_count"], got["records_walked"], got["records_kept"], got["block_count"]) == (5_000_003, 1000, 4, 2)
    assert got["records"] == [empty] * 4
    assert got["walk_stopped"] == "1000 records were decoded: the records after them are counted, not decoded"
    # under the cap every record is decoded and nothing is said
    small = lt_avro.read_container(container(schema, [(7, b""), (3, b"")]), max_walk=1000)
    assert small["record_count"] == 10 and "walk_stopped" not in small and "records_walked" not in small
    if empty is None:      # the default cap is the module's: a count of 2**60 costs MAX_WALK decodes, not 2**60
        assert lt_avro.MAX_WALK == 1_000_000
        huge = lt_avro.read_container(container(schema, [(1 << 60, b"")]), max_records=2)
        assert (huge["record_count"], huge["records_walked"]) == (1 << 60, lt_avro.MAX_WALK)


def test_blocks_after_the_walk_stopped_are_still_checked_for_their_sync_marker():
    good = container("null", [(5000, b""), (3, b"")])
    assert lt_avro.read_container(good, max_walk=10)["block_count"] == 2
    with pytest.raises(FormatError, match="block 1: the sync marker"):
        lt_avro.read_container(good[:-1] + bytes([good[-1] ^ 1]), max_walk=10)


def test_array_and_map_counts_are_held_to_the_bytes_or_to_the_empty_item_cap(monkeypatch):
    nulls = {"type": "array", "items": "null"}
    assert lt_avro.decode_datum(nulls, bytes.fromhex("0a00")) == ([None] * 5, 2)        # valid Avro: five nulls
    assert lt_avro.decode_datum({"type": "array", "items": {"type": "record", "name": "E", "fields": []}},
                                zz(3) + zz(0)) == ([{}, {}, {}], 2)
    # items that take bytes: the count is refused before anything is decoded
    with pytest.raises(FormatError, match="an array block states 3 items in 2 bytes"):
        lt_avro.decode_datum({"type": "array", "items": "long"}, zz(3) + zz(1) + zz(0))
    with pytest.raises(FormatError, match="an array block states 2 items in 15 bytes"):
        lt_avro.decode_datum({"type": "array", "items": "double"}, zz(2) + bytes(15))
    assert lt_avro.decode_datum({"type": "array", "items": "double"}, zz(2) + bytes(16) + zz(0))[0] == [0.0, 0.0]
    # a map entry is its key's length byte and its value: nine bytes at least for a double
    with pytest.raises(FormatError, match="an map block states 2 items in 17 bytes"):
        lt_avro.decode_datum({"type": "map", "values": "double"}, zz(2) + bytes(17))
    with pytest.raises(FormatError, match=f"an array block states {1 << 40} items in 1 bytes"):
        lt_avro.decode_datum({"type": "array", "items": "long"}, zz(1 << 40) + zz(0))
    # items of no size: charged to the file's cap, in every block of every array
    assert lt_avro.MAX_EMPTY_ITEMS == 1_000_000
    with pytest.raises(FormatError, match="an array block states 1000001 items of no size: more than 1000000 in the file"):
        lt_avro.decode_datum(nulls, zz(1_000_001) + zz(0))
    with pytest.raises(FormatError, match=f"an array block states {1 << 40} items of no size: more than 1000000 in the file"):
        lt_avro.decode_datum(nulls, zz(1 << 40) + zz(0))
    monkeypatch.setattr(lt_avro, "MAX_EMPTY_ITEMS", 10)
    assert lt_avro.decode_datum(nulls, zz(6) + zz(4) + zz(0))[0] == [None] * 10
    with pytest.raises(FormatError, match="an array block states 5 items of no size: more than 10 in the file"):
        lt_avro.decode_datum(nulls, zz(6) + zz(5) + zz(0))
    two = {"type": "record", "name": "T", "fields": [{"name": "a", "type": nulls}, {"name": "b", "type": nulls}]}
    with pytest.raises(FormatError, match="more than 10 in the file"):                  # two arrays share the cap
        lt_avro.decode_datum(two, zz(6) + zz(0) + zz(6) + zz(0))


@pytest.mark.parametrize("codec", ["deflate", "snappy", "bzip2", "xz", "zstandard"])
def test_a_block_is_never_inflated_past_the_block_limit(codec, monkeypatch):
    raw = b"".join(zz(i) for i in range(4000))
    data = container("long", [(4000, raw)], codec)
    assert lt_avro.read_container(data)["record_count"] == 4000
    monkeypatch.setattr(lt_avro, "MAX_BLOCK_BYTES", len(raw))
    assert lt_avro.read_container(data)["records_kept"] == 4000                           # exactly the limit
    monkeypatch.setattr(lt_avro, "MAX_BLOCK_BYTES", len(raw) - 1)
    with pytest.raises(FormatError, match=f"block 0 decompresses to more than {len(raw) - 1} bytes"):
        lt_avro.read_container(data)


def test_blocks_past_the_files_decompression_budget_are_counted_not_decoded():
    block = b"".join(zz(i) for i in range(200))
    data = container("long", [(200, block)] * 4, "deflate")
    got = lt_avro.read_container(data, max_unpacked=2 * len(block))
    assert (got["record_count"], got["records_walked"], got["records_kept"], got["block_count"]) == (800, 400, 400, 4)
    assert got["walk_stopped"] == f"the blocks before it decompressed to {2 * len(block)} bytes: block 2 on is not decoded"
    whole = lt_avro.read_container(data, max_unpacked=4 * len(block))
    assert whole["records_kept"] == 800 and "walk_stopped" not in whole


@pytest.mark.parametrize("codec,module", [("snappy", "cramjam"), ("zstandard", "zstandard")])
def test_a_codec_whose_decoder_is_not_installed_is_named_never_passed_through(codec, module, monkeypatch, tmp_path):
    data = container(SCHEMA, [(1, row(*ROWS[0]))], codec)
    (tmp_path / "a.avro").write_bytes(data)
    monkeypatch.setitem(sys.modules, module, None)             # the import fails as on a host without it
    with pytest.raises(NeedsTool, match=f"needs_tool py:{module}: the container's codec is {codec}") as e:
        lt_avro.read_container(data)
    assert e.value.tool == f"py:{module}"
    r = lt_avro.solve(tmp_path)
    assert r.status == "blocked" and f"a.avro: Avro container: needs_tool py:{module}" in r.notes


@pytest.mark.parametrize("codec", ["null", "deflate", "snappy"])
def test_mutated_containers_raise_only_the_declared_errors(codec):
    base = container(SCHEMA, [(1, row(*ROWS[0])), (1, row(*ROWS[1]))], codec, extra_meta={"owner": b"forensics"})
    # anything but a declared error (TypeError, KeyError, RecursionError, struct.error ...) fails the test
    read, refused = only_declared_errors(lt_avro.inspect, mutations(base, 1500, seed=251))
    assert read + refused == 1500 and refused > 300 and read > 0        # the mutations do reach the parser


def test_every_bit_flip_of_the_schema_raises_only_the_declared_errors():
    base = container(SCHEMA, [(1, row(*ROWS[0]))])
    start, stop = base.index(b'{"type"'), base.index(SYNC)
    read, refused = only_declared_errors(lt_avro.inspect, bit_flips(base, start, stop))
    assert read + refused == 8 * (stop - start) and refused > 500 and read > 0


# ------------------------------------------------------------------ round 2: values of no size cost their number

def nulls_record(fields):
    return {"type": "record", "name": "Wide", "fields": [{"name": f"f{i}", "type": "null"} for i in range(fields)]}


def test_a_record_of_many_fields_of_no_size_costs_its_fields_not_the_stated_count_times_them():
    # 2000 null fields and a block stating 1,000,000 records in no bytes: 2,001,000,000 values were it
    # walked to MAX_WALK; the file's value budget ends the walk instead, and the facts say where
    # every value is charged: a record of 2000 fields is 2001 values, so 4 fit in 8004 and not in 8003
    # (asserted first: on a small count, so a reader that does not charge fails here and does not run on)
    assert lt_avro.read_container(container(nulls_record(2000), [(4, b"")]), max_values=8003)["records_walked"] == 3
    assert lt_avro.read_container(container(nulls_record(2000), [(4, b"")]), max_values=8004)["records_kept"] == 4
    data = container(nulls_record(2000), [(1_000_000, b""), (5, b"")])
    assert len(data) < 80_000
    got = lt_avro.read_container(data, max_records=2, max_values=10_000)
    assert (got["record_count"], got["records_walked"], got["records_kept"], got["block_count"]) == (1_000_005, 4, 2, 2)
    assert got["walk_stopped"] == "10000 values were decoded: record 4 and the records after it are counted, not decoded"
    assert got["records"][0] == {f"f{i}": None for i in range(2000)}
    # the default budget is the module's, and decode_datum is held to it too (a FormatError there)
    assert lt_avro.MAX_DECODED_VALUES == 4_000_000 and lt_avro.MAX_KEPT_VALUES == 1_000_000
    assert lt_avro.Schema('"null"').values_left == lt_avro.MAX_DECODED_VALUES


def test_decode_datum_refuses_a_datum_past_the_value_budget(monkeypatch):
    monkeypatch.setattr(lt_avro, "MAX_DECODED_VALUES", 2001)
    assert lt_avro.decode_datum(nulls_record(2000), b"") == ({f"f{i}": None for i in range(2000)}, 0)
    monkeypatch.setattr(lt_avro, "MAX_DECODED_VALUES", 2000)
    with pytest.raises(FormatError, match="more than 2000 values decoded in the file"):
        lt_avro.decode_datum(nulls_record(2000), b"")
    with pytest.raises(lt_avro.WorkLimit):
        lt_avro.decode_datum({"type": "array", "items": "null"}, zz(5000) + zz(0))


def test_the_kept_records_are_held_to_a_number_of_values():
    rec = {"type": "record", "name": "R", "fields": [{"name": "a", "type": "long"}, {"name": "b", "type": "string"},
                                                    {"name": "c", "type": "bytes"}]}
    rows = [zz(i) + s(f"u{i}") + s(b"\xff" + bytes([i])) for i in range(6)]
    data = container(rec, [(6, b"".join(rows))])
    blobs = []
    got = lt_avro.read_container(data, blobs=blobs, max_kept_values=9)           # four values a record
    assert got["records_kept"] == 2 and [r["a"] for r in got["records"]] == [0, 1]
    assert got["keep_stopped"] == ("the 2 records kept hold 8 values: the records after them are decoded, not kept "
                                   "(a limit of 9 values)")
    assert got["record_count"] == 6 and "walk_stopped" not in got           # every record is still decoded
    whole = lt_avro.read_container(data, max_kept_values=24)
    assert whole["records_kept"] == 6 and "keep_stopped" not in whole
    assert lt_avro.read_container(data, max_kept_values=23)["records_kept"] == 5
    # once keeping stopped it does not resume, even for a record that would still fit
    xs = {"type": "record", "name": "X", "fields": [{"name": "a", "type": "long"},
                                                   {"name": "xs", "type": {"type": "array", "items": "long"}}]}
    rows = [zz(0) + zz(0), zz(1) + zz(10) + zz(7) * 10 + zz(0), zz(2) + zz(0)]     # 3, 13 and 3 values
    got = lt_avro.read_container(container(xs, [(3, b"".join(rows))]), max_kept_values=7)
    assert [r["a"] for r in got["records"]] == [0] and "the 1 records kept hold 3 values" in got["keep_stopped"]
