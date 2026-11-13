"""B-251: the Thrift decoder and Parquet reader (solvers/toolkits/lt_thrift_parquet.py).

Thrift structs are checked against literal bytes assembled by hand from the protocol specifications
(the compact protocol's `dddd tttt` field headers and zigzag varints, the binary protocol's typed,
big-endian fields). The RLE / bit-packed hybrid is held to the example the Parquet format document
prints (the values 0..7 at three bits are the bytes 88 C6 FA). Parquet files are written here by a
small writer that shares no code with the reader.
"""
import struct
import sys
import zlib

import pytest

import lt_thrift_parquet as tp
from _lt_common import FormatError, NeedsKey, NeedsTool
from ctf import flagfmt
from lt_mutations import bit_flips, mutations, only_declared_errors

H = bytes.fromhex


# ------------------------------------------------------------------ Thrift

def test_compact_struct_from_hand_assembled_bytes():
    #   15 02            field 1 (delta 1), i32, zigzag(1)
    #   19 2c            field 2, list: 2 elements of type 12 (struct)
    #   48 01 61 00      struct {4: "a"};  48 01 62 00  struct {4: "b"}
    #   18 03 66 6f 6f   field 3, binary "foo"
    #   17 <1.5 LE>      field 4, double
    #   11 / 12          field 5 true, field 6 false (the value is in the header)
    #   05 c8 01 05      long form: i32, field id zigzag(100), value zigzag(-3)
    st, end = tp.compact_struct(H("1502" "192c" "48016100" "48016200" "1803666f6f" "17") + struct.pack("<d", 1.5)
                                + H("11" "12" "05c80105" "00"))
    assert dict(st) == {1: 1, 2: [{4: b"a"}, {4: b"b"}], 3: b"foo", 4: 1.5, 5: True, 6: False, 100: -3}
    assert st.types == {1: "i32", 2: "list", 3: "binary", 4: "double", 5: "bool", 6: "bool", 100: "i32"}
    assert end == 33


def test_compact_containers_long_list_map_and_bool_elements():
    # 1b 02 85: field 1 map, 2 entries, key binary / value i32;  29 f5 10: field 2 (delta 2) list, long form, 16 x i32
    # 19 21 01 02: field 3 list of 2 bools as bytes (1 true, 2 false);  13 fe: field 4 i8 -2
    st, _ = tp.compact_struct(H("1b0285" "016104" "016206" "29f510") + bytes(range(0, 32, 2)) + H("1921" "0102" "13fe" "00"))
    assert dict(st) == {1: [[b"a", 2], [b"b", 3]], 3: list(range(16)), 4: [True, False], 5: -2}


def test_binary_struct_and_both_message_envelopes():
    body = (H("08 0001 00000007") + H("0b 0002 00000002 6869") + H("0f 0003 0a 00000002") + struct.pack(">qq", -1, 5)
            + H("0d 0004 0b 08 00000001 00000001 6b 0000002a") + H("02 0005 01") + H("04 0006") + struct.pack(">d", 2.5)
            + H("00"))
    want = {1: 7, 2: b"hi", 3: [-1, 5], 4: [[b"k", 42]], 5: True, 6: 2.5}
    st, end = tp.binary_struct(body)
    assert dict(st) == want and end == len(body)

    msg = H("80010001 00000004") + b"ping" + H("00000009") + body
    (reading,) = tp.decode_thrift(msg)
    assert reading["protocol"] == "binary" and reading["envelope"] == {"name": "ping", "type": "call", "seqid": 9}
    assert reading["struct"] == {"1:i32": 7, "2:binary": "hi", "3:list": [-1, 5], "4:map": [["k", 42]], "5:bool": True,
                                 "6:double": 2.5}

    compact = H("82 41 09 04") + b"ping" + H("1502 00")           # type reply (2 << 5 | version 1), seqid 9
    (reading,) = tp.decode_thrift(compact)
    assert reading == {"protocol": "compact", "envelope": {"name": "ping", "type": "reply", "seqid": 9},
                       "struct": {"1:i32": 1}}


def test_bare_structs_are_read_only_on_request_and_every_reading_is_returned():
    with pytest.raises(FormatError, match="no message envelope"):
        tp.decode_thrift(H("150200"))
    assert tp.decode_thrift(H("150200"), bare=True) == [{"protocol": "compact", "envelope": None, "struct": {"1:i32": 1}}]
    with pytest.raises(FormatError):           # a struct field cut short parses in neither protocol
        tp.decode_thrift(H("0c 00"), bare=True)
    with pytest.raises(FormatError, match="1 bytes are left"):
        tp.decode_thrift(H("150200ff"), bare=True)
    with pytest.raises(FormatError, match="an empty struct"):
        tp.decode_thrift(H("00"), bare=True)


def test_hostile_thrift_is_refused_quickly():
    with pytest.raises(FormatError, match="nests deeper"):
        tp.compact_struct(H("1c") * 5000)
    with pytest.raises(FormatError, match="nests deeper"):
        tp.binary_struct(H("0c0001") * 5000)
    with pytest.raises(FormatError, match="states 4294967295 elements"):
        tp.compact_struct(H("19f5ffffffff0f"))
    with pytest.raises(FormatError, match="list states 2147483647"):
        tp.binary_struct(H("0f0001087fffffff"))
    with pytest.raises(FormatError, match="runs past the end"):
        tp.compact_struct(H("1805616263"))
    with pytest.raises(FormatError, match="not a compact-protocol type"):
        tp.compact_struct(H("1e00"))


# ------------------------------------------------------------------ the hybrid encoding

def test_hybrid_matches_the_format_documents_example_and_runs():
    assert tp.hybrid(H("03" "88c6fa"), 3, 8) == [0, 1, 2, 3, 4, 5, 6, 7]
    assert tp.hybrid(H("10" "04"), 3, 8) == [4] * 8                       # an RLE run: 8 << 1, the value 4
    assert tp.hybrid(H("06" "0201" "03" "88c6fa"), 9, 5)[:3] == [258] * 3   # a two-byte run value, then a packed group
    assert tp.hybrid(H("03" "88c6fa" "04" "07"), 3, 10) == [0, 1, 2, 3, 4, 5, 6, 7, 7, 7]
    assert tp.hybrid(b"", 0, 4) == [0, 0, 0, 0]
    with pytest.raises(FormatError, match="ends before its values"):
        tp.hybrid(H("03" "88c6"), 3, 8)
    with pytest.raises(FormatError, match="empty RLE run"):
        tp.hybrid(H("00" "04"), 3, 8)
    with pytest.raises(FormatError):
        tp.hybrid(H("10"), 3, 8)


# ------------------------------------------------------------------ a Parquet writer of the test's own

def uv(n):
    out = bytearray()
    while True:
        b, n = n & 0x7F, n >> 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def zz(n):
    return uv((n << 1) ^ (n >> 63))


class W:
    """A Thrift compact struct writer."""

    def __init__(self):
        self.out, self.last = bytearray(), 0

    def _f(self, fid, t, payload=b""):
        d = fid - self.last
        self.out += (bytes([d << 4 | t]) if 0 < d <= 15 else bytes([t]) + zz(fid)) + payload
        self.last = fid
        return self

    def i32(self, fid, v):
        return self._f(fid, 5, zz(v))

    def i64(self, fid, v):
        return self._f(fid, 6, zz(v))

    def bin(self, fid, b):
        return self._f(fid, 8, uv(len(b)) + b)

    def bool(self, fid, v):
        return self._f(fid, 1 if v else 2)

    def struct(self, fid, s):
        return self._f(fid, 12, s)

    def list(self, fid, et, items):
        n = len(items)
        head = bytes([n << 4 | et]) if n < 15 else bytes([0xF0 | et]) + uv(n)
        return self._f(fid, 9, head + b"".join(items))

    def done(self):
        return bytes(self.out) + b"\x00"


def squeeze(codec, raw):
    if codec == 1:
        import cramjam
        return bytes(cramjam.snappy.compress_raw(raw))
    if codec == 2:
        c = zlib.compressobj(6, zlib.DEFLATED, 31)
        return c.compress(raw) + c.flush()
    if codec == 6:
        import zstandard
        return zstandard.ZstdCompressor().compress(raw)
    if codec == 4:
        import brotli
        return brotli.compress(raw)
    if codec == 7:
        import cramjam
        return bytes(cramjam.lz4.compress_block(raw, store_size=False))
    return raw


def rle_levels(levels, bit_width=1):
    """Definition levels as one bit-packed run per eight values (padded with zeros)."""
    out = bytearray()
    for i in range(0, len(levels), 8):
        chunk = levels[i:i + 8] + [0] * (8 - len(levels[i:i + 8]))
        acc = sum(v << (k * bit_width) for k, v in enumerate(chunk))
        out += b"\x03" + acc.to_bytes(bit_width, "little")
    return bytes(out)


def page_v1(n, enc, payload, codec, levels=None):
    raw = (struct.pack("<I", len(levels)) + levels if levels is not None else b"") + payload
    body = squeeze(codec, raw)
    head = W().i32(1, 0).i32(2, len(raw)).i32(3, len(body)).struct(5, W().i32(1, n).i32(2, enc).i32(3, 3).i32(4, 3).done())
    return head.done() + body


def page_v2(n, nulls, enc, payload, codec, levels=b""):
    body = squeeze(codec, payload)
    h2 = W().i32(1, n).i32(2, nulls).i32(3, n).i32(4, enc).i32(5, len(levels)).i32(6, 0).done()
    head = W().i32(1, 3).i32(2, len(levels) + len(payload)).i32(3, len(levels) + len(body)).struct(8, h2)
    return head.done() + levels + body


def dict_page(values, codec):
    raw = b"".join(struct.pack("<I", len(v)) + v for v in values)
    body = squeeze(codec, raw)
    head = W().i32(1, 2).i32(2, len(raw)).i32(3, len(body)).struct(7, W().i32(1, len(values)).i32(2, 0).done())
    return head.done() + body


def element(name, ptype=None, rep=None, children=None, converted=None, length=None):
    w = W()
    if ptype is not None:
        w.i32(1, ptype)
    if length is not None:
        w.i32(2, length)
    if rep is not None:
        w.i32(3, rep)
    w.bin(4, name.encode())
    if children is not None:
        w.i32(5, children)
    if converted is not None:
        w.i32(6, converted)
    return w.done()


def parquet(columns, num_rows, kv=None, created_by=b"corpus-writer 1.0", tail=b"PAR1"):
    """columns: [(schema element, path, ptype, codec, encodings, num_values, [page bytes], dict?, stats)]."""
    out = bytearray(b"PAR1")
    chunks = []
    for elem, path, ptype, codec, encs, nvals, pages, has_dict, stats in columns:
        start = len(out)
        for pg in pages:
            out += pg
        md = W().i32(1, ptype).list(2, 5, [zz(e) for e in encs]).list(3, 8, [uv(len(p)) + p for p in [x.encode() for x in path]])
        md.i32(4, codec).i64(5, nvals).i64(6, len(out) - start).i64(7, len(out) - start)
        md.i64(9, start + (len(pages[0]) if has_dict else 0))
        if has_dict:
            md.i64(11, start)
        if stats:                                        # {"raw": a Statistics struct written by the caller}, or min/max
            md.struct(12, stats["raw"] if "raw" in stats else
                      W().i64(3, stats.get("nulls", 0)).bin(5, stats["max"]).bin(6, stats["min"]).done())
        chunks.append(W().i64(2, start).struct(3, md.done()).done())
    fm = W().i32(1, 1).list(2, 12, [element("schema", children=len(columns))] + [c[0] for c in columns]).i64(3, num_rows)
    fm.list(4, 12, [W().list(1, 12, chunks).i64(2, len(out) - 4).i64(3, num_rows).done()])
    if kv:
        fm.list(5, 12, [W().bin(1, k).bin(2, v).done() for k, v in kv.items()])
    fm.bin(6, created_by)
    footer = fm.done()
    return bytes(out) + footer + struct.pack("<I", len(footer)) + tail


NAMES = [b"ada", None, b"grace", b"ada", None]
DICT = [b"ada", b"grace"]


def sample(flag=b"", name_codec=1, score_codec=6, kv=None):
    ids = [10, 20, 30, 40, 50]
    scores = [1.5, -2.0, 3.25, 0.0, 9.0]
    id_col = (element("id", 2, 0), ["id"], 2, 0, [0], 5, [page_v1(5, 0, struct.pack("<5q", *ids), 0)], False,
              {"min": struct.pack("<q", 10), "max": struct.pack("<q", 50)})
    idx = [DICT.index(n) for n in NAMES if n is not None]              # 0, 1, 0: one bit each, one packed group
    packed = bytes([1]) + b"\x03" + bytes([sum(v << k for k, v in enumerate(idx))])
    levels = rle_levels([0 if n is None else 1 for n in NAMES])
    name_col = (element("name", 6, 1, converted=0), ["name"], 6, name_codec, [8, 0, 3], 5,
                [dict_page([DICT[0] + flag, DICT[1]], name_codec), page_v1(5, 8, packed, name_codec, levels)], True,
                {"min": b"ada", "max": b"grace", "nulls": 2})
    score_col = (element("score", 5, 0), ["score"], 5, score_codec, [0], 5,
                 [page_v2(3, 0, 0, struct.pack("<3d", *scores[:3]), score_codec),
                  page_v2(2, 0, 0, struct.pack("<2d", *scores[3:]), score_codec)], False, None)
    flags_col = (element("ok", 0, 0), ["ok"], 0, 2, [0], 5, [page_v1(5, 0, bytes([0b10101]), 2)], False, None)
    delta_col = (element("delta", 1, 0), ["delta"], 1, 0, [5], 5, [page_v1(5, 5, b"\x00" * 8, 0)], False, None)
    fixed_col = (element("tag", 7, 0, length=3), ["tag"], 7, 7, [0], 5, [page_v1(5, 0, b"aaabbbcccdddeee", 7)], False, None)
    return parquet([id_col, name_col, score_col, flags_col, delta_col, fixed_col], 5,
                   kv if kv is not None else {b"owner": b"forensics team"})


@pytest.mark.parametrize("name_codec,score_codec", [(1, 6), (0, 0), (2, 4), (6, 7), (4, 2)])
def test_parquet_columns_metadata_and_statistics(name_codec, score_codec):
    got = tp.read_parquet(sample(name_codec=name_codec, score_codec=score_codec))
    assert (got["version"], got["num_rows"], got["created_by"]) == (1, 5, "corpus-writer 1.0")
    assert got["key_value_metadata"] == {"owner": "forensics team"}
    assert [(c["path"], c["type"], c["repetition"], c["max_def"]) for c in got["columns"]] == [
        ("id", "INT64", "required", 0), ("name", "BYTE_ARRAY", "optional", 1), ("score", "DOUBLE", "required", 0),
        ("ok", "BOOLEAN", "required", 0), ("delta", "INT32", "required", 0), ("tag", "FIXED_LEN_BYTE_ARRAY", "required", 0)]
    assert got["columns"][1]["converted_type"] == "UTF8"
    (group,) = got["row_groups"]
    cols = {c["path"]: c for c in group["columns"]}
    assert cols["id"]["values"] == [10, 20, 30, 40, 50] and cols["id"]["statistics"] == {"min": 10, "max": 50, "null_count": 0}
    assert cols["name"]["values"] == ["ada", "grace", "ada"] and cols["name"]["null_count"] == 2
    assert cols["name"]["statistics"] == {"min": "ada", "max": "grace", "null_count": 2}
    assert cols["name"]["codec"] == tp.CODECS[name_codec] and cols["name"]["pages"] == 2
    assert cols["score"]["values"] == [1.5, -2.0, 3.25, 0.0, 9.0] and cols["score"]["pages"] == 2
    assert cols["ok"]["values"] == [True, False, True, False, True]
    assert cols["tag"]["values"] == ["aaa", "bbb", "ccc", "ddd", "eee"]
    assert cols["delta"]["undecoded"] == "the encoding DELTA_BINARY_PACKED is not decoded" and "values" not in cols["delta"]


def test_parquet_value_cap_and_plain_optional_strings():
    levels = rle_levels([1, 0, 1])
    payload = b"".join(struct.pack("<I", len(v)) + v for v in (b"one", b"three"))
    col = (element("s", 6, 1), ["s"], 6, 0, [0], 3, [page_v1(3, 0, payload, 0, levels)], False, None)
    got = tp.read_parquet(parquet([col], 3), max_values=1)
    c = got["row_groups"][0]["columns"][0]
    assert (c["values"], c["values_kept"], c["null_count"], c["num_values"]) == (["one"], 1, 1, 3)


def test_parquet_refusals_are_named():
    good = sample()
    with pytest.raises(FormatError, match="no Parquet magic \\(PAR1\\) at the end"):
        tp.read_parquet(good[:-1] + b"X")
    with pytest.raises(NeedsKey, match="encrypted \\(PARE\\)"):
        tp.read_parquet(good[:-4] + b"PARE")
    with pytest.raises(FormatError, match="footer states"):
        tp.read_parquet(good[:-8] + struct.pack("<I", len(good)) + b"PAR1")
    # a page whose stated uncompressed size is wrong
    col = (element("id", 2, 0), ["id"], 2, 2, [0], 1, [page_v1(1, 0, struct.pack("<q", 1), 2).replace(b"\x15\x10", b"\x15\x12", 1)],
           False, None)
    with pytest.raises(FormatError, match="decompresses to 8 bytes, its header says 9"):
        tp.read_parquet(parquet([col], 1))
    # a dictionary index past the dictionary
    bad = (element("name", 6, 0), ["name"], 6, 0, [8], 1, [dict_page([b"only"], 0), page_v1(1, 8, bytes([2]) + b"\x02\x03", 0)],
           True, None)
    with pytest.raises(FormatError, match="dictionary index 3 is outside its 1 entries"):
        tp.read_parquet(parquet([bad], 1))
    # a dictionary-encoded page with no dictionary page before it
    orphan = (element("name", 6, 0), ["name"], 6, 0, [8], 1, [page_v1(1, 8, bytes([1]) + b"\x02\x00", 0)], False, None)
    with pytest.raises(FormatError, match="before any dictionary page"):
        tp.read_parquet(parquet([orphan], 1))


def test_solve_reads_flags_from_dictionary_values_metadata_and_messages(tmp_path):
    flag = flagfmt.cribs()[0] + "parquet_dictionary}"
    (tmp_path / "rows.parquet").write_bytes(sample(flag=b" " + flag.encode()))
    r = tp.solve(tmp_path)
    assert (r.status, r.flags) == ("solved", (flag,)) and r.evidence[0].path == "rows.parquet"

    meta = flagfmt.cribs()[0] + "parquet_footer_metadata}"
    (tmp_path / "rows.parquet").write_bytes(sample(kv={b"note": b"\xff\xfe" + meta.encode()}))
    assert tp.solve(tmp_path).flags == (meta,)

    wire = flagfmt.cribs()[0] + "thrift_call_argument}"
    (tmp_path / "rows.parquet").unlink()
    (tmp_path / "call.bin").write_bytes(H("80010001 00000005") + b"login" + H("00000001")
                                        + H("0b0001") + struct.pack(">i", len(wire)) + wire.encode() + H("00"))
    r = tp.solve(tmp_path)
    assert (r.status, r.flags) == ("solved", (wire,))


def test_solve_statuses_without_a_flag(tmp_path):
    assert tp.solve(tmp_path).status == "none"
    (tmp_path / "enc.parquet").write_bytes(sample()[:-4] + b"PARE")
    r = tp.solve(tmp_path)
    assert r.status == "blocked" and "footer key is needed" in r.notes
    (tmp_path / "ok.parquet").write_bytes(sample())
    r = tp.solve(tmp_path)
    assert r.status == "unsure" and "num_rows=5" in r.evidence[0].detail


def test_bare_cli_reads_a_struct_with_no_magic(tmp_path, capsys):
    p = tmp_path / "blob"
    p.write_bytes(H("1502" "1803666f6f" "00"))
    assert tp.main(["--bare", str(p)]) == 0
    assert '"2:binary": "foo"' in capsys.readouterr().out
    assert tp.main([str(p)]) == 1          # without --bare it has no structure to detect
    assert "FormatError" in capsys.readouterr().out


# ------------------------------------------------------------------ round 1: hostile files and stated bounds

def col(name, ptype, pages, codec=0, encs=(0,), n=1, rep=0, has_dict=False, stats=None, length=None):
    return (element(name, ptype, rep, length=length), [name], ptype, codec, list(encs), n, pages, has_dict, stats)


def strings(*values):
    return b"".join(struct.pack("<I", len(v)) + v for v in values)


def data_page(header, body, usize=None, ptype=0, field=5):
    """A page whose header struct is written by the caller (to put anything in it)."""
    usize = len(body) if usize is None else usize
    return W().i32(1, ptype).i32(2, usize).i32(3, len(body)).struct(field, header).done() + body


def v1_header(n, enc=0):
    return W().i32(1, n).i32(2, enc).i32(3, 3).i32(4, 3).done()


def only(data, **kw):
    """The one column chunk of a one-column file."""
    (group,) = tp.read_parquet(data, **kw)["row_groups"]
    (c,) = group["columns"]
    return c


def with_footer(footer):
    raw = footer.done()
    return b"PAR1" + raw + struct.pack("<I", len(raw)) + b"PAR1"


SCHEMA_OK = [element("schema", children=1), element("id", 2, 0)]


@pytest.mark.parametrize("footer,message", [
    (W().i32(1, 1).i32(2, 5), "the footer's schema is a Thrift int, not list"),
    (W().i32(1, 1).list(2, 5, [zz(1)]), "the footer has no schema"),
    (W().i32(1, 1).list(2, 12, [element("schema", children=1), W().i32(1, 2).i32(4, 9).done()]),
     "a schema element's name is a Thrift int, not bytes"),
    (W().i32(1, 1).list(2, 12, [element("schema", children=1), W().bin(1, b"x").bin(4, b"id").done()]),
     "a schema element's type is a Thrift bytes, not int"),
    (W().i32(1, 1).list(2, 12, [W().bin(4, b"schema").bin(5, b"one").done(), element("id", 2, 0)]),
     "the schema root's num_children is a Thrift bytes, not int"),
    (W().i32(1, 1).list(2, 12, SCHEMA_OK).list(4, 5, [zz(1)]), "the footer's row groups holds a value that is not a struct"),
    (W().i32(1, 1).list(2, 12, SCHEMA_OK).i32(4, 3), "the footer's row groups is a Thrift int, not list"),
    (W().i32(1, 1).list(2, 12, SCHEMA_OK).list(4, 12, [W().i32(1, 4).done()]), "a row group's columns is a Thrift int, not list"),
    (W().i32(1, 1).list(2, 12, SCHEMA_OK).list(5, 12, [W().bin(1, b"k").i32(2, 3).done()]),
     "a metadata value is a Thrift int, not bytes"),
    (W().i32(1, 1).list(2, 12, SCHEMA_OK).i32(6, 5), "the footer's created_by is a Thrift int, not bytes"),
    (W().bin(1, b"one").list(2, 12, SCHEMA_OK), "the footer's version is a Thrift bytes, not int"),
    (W().i32(1, 1).list(2, 12, SCHEMA_OK).struct(3, W().done()), "the footer's num_rows is a Thrift struct, not int"),
])
def test_footer_fields_of_the_wrong_thrift_type_are_format_errors(footer, message):
    with pytest.raises(FormatError, match=message):
        tp.read_parquet(with_footer(footer))


def chunk_file(md, pages=(b"",)):
    """A file of one INT64 column whose column metadata struct is written by the caller."""
    body = b"".join(pages)
    footer = W().i32(1, 1).list(2, 12, SCHEMA_OK).i64(3, 1)
    return b"PAR1" + body + with_footer(footer.list(4, 12, [W().list(1, 12, [W().struct(3, md.done()).done()]).done()]))[4:]


def chunk_md(over=None):
    """Column metadata of the INT64 column `id`: one data page at offset 4, with the fields of `over`
    ({field id: (W method, arguments...)}) put in place of the good ones."""
    fields = {1: ("i32", 2), 2: ("list", 5, [zz(0)]), 3: ("list", 8, [uv(2) + b"id"]), 4: ("i32", 0), 5: ("i64", 1),
              9: ("i64", 4)}
    fields.update(over or {})
    md = W()
    for fid in sorted(fields):
        kind, *args = fields[fid]
        getattr(md, kind)(fid, *args)
    return md


GOOD_PAGE = data_page(v1_header(1), struct.pack("<q", 77))


@pytest.mark.parametrize("md,pages,message", [
    (chunk_md({4: ("bin", b"gzip")}), [GOOD_PAGE], "a column chunk's codec is a Thrift bytes, not int"),
    (chunk_md({5: ("bin", b"one")}), [GOOD_PAGE], "a column chunk's num_values is a Thrift bytes, not int"),
    (chunk_md({5: ("i64", -4)}), [GOOD_PAGE], "a column chunk states -4 values"),
    (chunk_md({9: ("bin", b"four")}), [GOOD_PAGE], "a column chunk's data page offset is a Thrift bytes, not int"),
    (chunk_md({9: ("i64", 1 << 40)}), [GOOD_PAGE], "a column chunk's page offset is outside the file"),
    (chunk_md({3: ("list", 5, [zz(7)])}), [GOOD_PAGE], "a column's path holds a value that is not a bytes"),
    (chunk_md({2: ("i32", 0)}), [GOOD_PAGE], "a column's encodings is a Thrift int, not list"),
    (chunk_md(), [W().i32(1, 0).i32(2, 8).i32(3, 8).done() + bytes(8)], "a data page has no data page header"),
    (chunk_md(), [W().i32(1, 0).bin(2, b"8").i32(3, 8).done() + bytes(8)], "a page header's uncompressed size is a Thrift bytes"),
    (chunk_md(), [W().i32(1, 0).i32(3, 8).done() + bytes(8)], "a page header has no sizes"),
    (chunk_md(), [data_page(W().bin(1, b"x").i32(2, 0).done(), bytes(8))], "a data page's num_values is a Thrift bytes, not int"),
    (chunk_md(), [data_page(W().i32(1, 1).bin(2, b"plain").done(), bytes(8))], "a data page's encoding is a Thrift bytes, not int"),
    (chunk_md(), [data_page(W().i64(1, 1 << 31).i32(2, 0).done(), bytes(8))], "a data page's num_values is 2147483648"),
    (chunk_md(), [data_page(W().i32(1, -1).i32(2, 0).done(), bytes(8))], "a data page's num_values is -1"),
    (chunk_md(), [data_page(v1_header(0), bytes(8))], "a data page states no values"),
    (chunk_md(), [data_page(W().i32(1, 1).done(), bytes(8), ptype=3, field=5)], "a version 2 data page has no header"),
    (chunk_md(), [data_page(W().i32(1, 1).done(), bytes(8), ptype=2, field=5)], "a dictionary page has no dictionary page header"),
    (chunk_md(), [data_page(W().i32(1, -1).i32(2, 0).done(), b"", ptype=2, field=7)], "a dictionary page's num_values is -1"),
])
def test_column_and_page_header_fields_of_the_wrong_type_or_sign_are_format_errors(md, pages, message):
    with pytest.raises(FormatError, match=message):
        tp.read_parquet(chunk_file(md, pages))


def test_the_hand_written_column_file_reads_when_nothing_is_wrong_with_it():
    c = only(chunk_file(chunk_md(), [GOOD_PAGE]))
    assert (c["path"], c["values"], c["pages"], c["codec"], c["encodings"]) == ("id", [77], 1, "UNCOMPRESSED", ["PLAIN"])


def test_a_malformed_file_does_not_hide_a_good_one_in_the_same_folder(tmp_path):
    flag = flagfmt.cribs()[0] + "beside_a_malformed_parquet}"
    (tmp_path / "bad.parquet").write_bytes(with_footer(W().i32(1, 1).list(2, 12, SCHEMA_OK).i32(6, 5)))
    (tmp_path / "good.parquet").write_bytes(sample(flag=b" " + flag.encode()))
    r = tp.solve(tmp_path)
    assert (r.status, r.flags) == ("solved", (flag,))
    assert "bad.parquet: malformed Parquet/Thrift: the footer's created_by is a Thrift int, not bytes" in r.notes


def test_hybrid_runs_are_counted_never_expanded():
    assert list(tp.hybrid_runs(uv((5 << 1) | 1), 0, 100)) == [(0, 40), (0, 60)]                    # five groups of no bits
    assert list(tp.hybrid_runs(uv((1 << 40) << 1) + b"\x05", 3, 1 << 39)) == [(5, 1 << 39)]        # one RLE run
    assert list(tp.hybrid_runs(uv(((1 << 50) << 1) | 1), 0, 10 ** 12)) == [(0, 10 ** 12)]         # groups of no bits
    assert list(tp.hybrid_runs(b"", 0, 10 ** 12)) == [(0, 10 ** 12)]
    # a group of no bits is eight values and no more: what follows it is still read, and still checked
    assert list(tp.hybrid_runs(H("03" "04"), 0, 12)) == [(0, 8), (0, 2), (0, 2)]
    with pytest.raises(FormatError, match="an empty RLE run"):
        list(tp.hybrid_runs(H("03" "00"), 0, 12))
    assert list(tp.hybrid_runs(H("03" "88c6fa" "04" "07"), 3, 10)) == [(v, 1) for v in range(8)] + [(7, 2)]
    assert list(tp.hybrid_runs(H("06" "0201"), 9, 2)) == [(258, 2)]                               # a run cut to the count
    assert list(tp.hybrid_runs(H("03" "88c6fa"), 3, 0)) == []
    with pytest.raises(FormatError, match="a bit width of 33"):
        list(tp.hybrid_runs(b"\x02\x00", 33, 1))
    with pytest.raises(FormatError, match="ends before its values"):                               # a huge group count
        list(tp.hybrid_runs(uv(((1 << 50) << 1) | 1) + H("88c6fa"), 3, 10 ** 12))
    # hybrid() builds a list, so it has a cap of its own; the reader never calls it with a header's count
    assert tp.hybrid(uv(5000 << 1) + b"\x01", 1, 5000) == [1] * 5000
    with pytest.raises(FormatError, match="more than hybrid\\(\\) expands"):
        tp.hybrid(uv((1 << 40) << 1) + b"\x01", 1, tp.MAX_EXPANDED + 1)


def traced(fn):
    """(result, peak bytes allocated while fn ran): what a count taken from the file may not drive."""
    import tracemalloc
    tracemalloc.start()
    try:
        return fn(), tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("stated", [20_000_000, (1 << 31) - 1])
def test_a_page_header_num_values_never_sizes_an_allocation(stated):
    # a dictionary of one entry, then a data page that is one RLE run stating `stated` indices: under 200 bytes
    payload = bytes([1]) + uv(stated << 1) + b"\x00"
    pages = [dict_page([b"v"], 0), data_page(v1_header(stated, 8), payload)]
    data = parquet([col("c", 6, pages, encs=(8,), n=stated, has_dict=True)], stated)
    assert len(data) < 200
    c, peak = traced(lambda: only(data, max_values=5))
    assert (c["values"], c["values_kept"], c["null_count"], c["num_values"], c["pages"]) == (["v"] * 5, 5, 0, stated, 2)
    assert peak < 1 << 20, f"{peak} bytes were allocated for a {len(data)}-byte file"
    # definition levels the same way: one run that says every value is null
    levels = uv(stated << 1) + b"\x00"
    nulls = parquet([col("s", 6, [data_page(v1_header(stated), struct.pack("<I", len(levels)) + levels)], n=stated, rep=1)], stated)
    c, peak = traced(lambda: only(nulls))
    assert (c["values"], c["null_count"], c["num_values"]) == ([], stated, stated) and peak < 1 << 20
    # an out-of-range index is still found in a run that is not expanded
    bad = [dict_page([b"v"], 0), data_page(v1_header(stated, 8), bytes([1]) + uv(4 << 1) + b"\x00" + uv(stated << 1) + b"\x01")]
    with pytest.raises(FormatError, match="a dictionary index 1 is outside its 1 entries"):
        tp.read_parquet(parquet([col("c", 6, bad, encs=(8,), n=stated, has_dict=True)], stated), max_values=2)


def test_a_plain_page_must_hold_the_values_it_states_and_only_the_kept_ones_are_decoded():
    with pytest.raises(FormatError, match="a INT64 page ends before its 20000000 values"):
        tp.read_parquet(parquet([col("id", 2, [data_page(v1_header(20_000_000), bytes(16))], n=20_000_000)], 20_000_000))
    leaf = {"_type": 2, "_length": None}
    assert tp._plain(struct.pack("<4q", 5, 6, 7, 8), 0, leaf, 4, 2) == [5, 6]
    with pytest.raises(FormatError, match="ends before its 3 values"):          # checked even when one is kept
        tp._plain(bytes(16), 0, leaf, 3, 1)
    assert tp._plain(bytes([0b101]), 0, {"_type": 0, "_length": None}, 3, 2) == [True, False]
    assert tp._plain(b"aabbcc", 0, {"_type": 7, "_length": 2}, 3, 2) == [b"aa", b"bb"]
    with pytest.raises(FormatError, match="no type_length"):
        tp._plain(b"aabbcc", 0, {"_type": 7, "_length": None}, 3, 2)
    # a BYTE_ARRAY page is walked only as far as the kept values (stated in the module's bounds)
    assert tp._plain(strings(b"a", b"b") + b"\xff" * 8, 0, {"_type": 6, "_length": None}, 5, 2) == [b"a", b"b"]
    with pytest.raises(FormatError):
        tp._plain(strings(b"a", b"b") + b"\xff" * 8, 0, {"_type": 6, "_length": None}, 5, 3)


def test_pages_after_the_value_cap_are_not_read():
    pages = [page_v1(2, 0, struct.pack("<2q", 10 * i, 10 * i + 1), 0) for i in range(3)]
    data = parquet([col("id", 2, pages, n=6)], 6)
    c = only(data, max_values=2)
    assert (c["values"], c["pages"], c["cut"]) == ([0, 1], 1, "2 values are kept: the pages after the first 1 were not read")
    c = only(data, max_values=3)
    assert (c["values"], c["pages"], c["cut"]) == ([0, 1, 10], 2, "3 values are kept: the pages after the first 2 were not read")
    c = only(data, max_values=6)
    assert (c["values"], c["pages"], c["values_kept"]) == ([0, 1, 10, 11, 20, 21], 3, 6) and "cut" not in c
    assert c["num_values"] == 6
    # the unread pages are not parsed at all: bytes that are no page are only met when the cap lets the reader reach them
    broken = data.replace(pages[2], b"\xff" * len(pages[2]))
    assert only(broken, max_values=3)["values"] == [0, 1, 10]
    with pytest.raises(FormatError):
        tp.read_parquet(broken)


def test_dictionary_page_and_decompression_limits(monkeypatch):
    pages = [dict_page([b"one", b"two"], 0), page_v1(2, 8, bytes([1]) + b"\x03\x02", 0)]
    data = parquet([col("s", 6, pages, encs=(8,), n=2, has_dict=True)], 2)
    assert only(data)["values"] == ["one", "two"]
    monkeypatch.setattr(tp, "MAX_DICTIONARY", 1)
    assert only(data)["undecoded"] == "a dictionary of 2 entries is over the 1-entry limit"
    monkeypatch.undo()

    # a page larger than MAX_PAGE_BYTES (by its header) leaves the column undecoded, with the reason
    ints = parquet([col("id", 2, [page_v1(2, 0, struct.pack("<2q", 1, 2), 2)], codec=2, n=2)], 2)
    assert only(ints)["values"] == [1, 2]
    monkeypatch.setattr(tp, "MAX_PAGE_BYTES", 15)
    c = only(ints)
    assert c["undecoded"] == "a page of 16 bytes is over the 15-byte limit" and "values" not in c
    monkeypatch.setattr(tp, "MAX_PAGE_BYTES", 16)
    assert only(ints)["values"] == [1, 2]
    monkeypatch.undo()

    # a page whose data inflates past the size its header states is refused at that size
    stream = squeeze(2, bytes(1 << 20))
    bomb = parquet([col("id", 2, [data_page(v1_header(2), stream, usize=16)], codec=2, n=2)], 2)
    with pytest.raises(FormatError, match="a GZIP page decompresses to more than 16 bytes: not inflated further"):
        tp.read_parquet(bomb)


def test_the_files_pages_share_one_read_budget():
    # every page read is charged its stored bytes (header and body) and, when compressed, what it inflates to
    pages = [page_v1(2, 0, struct.pack("<2q", 10 * i, 10 * i + 1), 2) for i in range(3)]          # 16 bytes each, GZIP
    cost = [len(p) + 16 for p in pages]
    data = parquet([col("id", 2, pages, codec=2, n=6)], 6)
    c = only(data, max_read=cost[0] + cost[1] + cost[2] - 1)
    assert (c["values"], c["pages"]) == ([0, 1, 10, 11], 2)
    assert c["cut"] == "the file's pages reached its read limit before page 3: it and the pages after it were not read"
    assert "cut" not in only(data, max_read=sum(cost)) and "cut" not in only(data)
    # stored pages are charged too: a page that is the file's own bytes is still read, copied and walked
    stored_pages = [page_v1(2, 0, struct.pack("<2q", 10 * i, 10 * i + 1), 0) for i in range(3)]
    stored = parquet([col("id", 2, stored_pages, n=6)], 6)
    c = only(stored, max_read=len(stored_pages[0]))
    assert (c["values"], c["pages"]) == ([0, 1], 1) and "read limit before page 2" in c["cut"]
    assert only(stored, max_read=sum(map(len, stored_pages)))["values"] == [0, 1, 10, 11, 20, 21]
    # two columns draw on the same budget, and once it is spent no later chunk reads a page
    two = parquet([col("a", 2, pages[:2], codec=2, n=4), col("b", 2, pages[:2], codec=2, n=4),
                   col("c", 2, pages[:1], codec=2, n=2)], 4)
    a, b, c = tp.read_parquet(two, max_read=cost[0] + cost[1] + cost[0])["row_groups"][0]["columns"]
    assert "cut" not in a and b["values"] == [0, 1] and "before page 2" in b["cut"]
    assert c["values"] == [] and c["pages"] == 0 and "read limit before page 1" in c["cut"]


def chunks_on_one_page(page, count, ptype=2, codec=0, n=1, has_dict=False, offset=None):
    """A file of `count` column chunks (one leaf each) whose metadata all point at the same `page` bytes."""
    out = bytearray(b"PAR1") + page
    chunks = []
    for i in range(count):
        md = W().i32(1, ptype).list(2, 5, [zz(8 if has_dict else 0)]).list(3, 8, [uv(len(b"c%d" % i)) + b"c%d" % i])
        md.i32(4, codec).i64(5, n).i64(6, len(page)).i64(7, len(page)).i64(9, 4 if offset is None else offset)
        if has_dict:
            md.i64(11, 4)
        chunks.append(W().i64(2, 4).struct(3, md.done()).done())
    schema = [element("schema", children=count)] + [element("c%d" % i, ptype, 0) for i in range(count)]
    fm = W().i32(1, 1).list(2, 12, schema).i64(3, n).list(4, 12, [W().list(1, 12, chunks).i64(2, len(page)).i64(3, n).done()])
    footer = fm.done()
    return bytes(out) + footer + struct.pack("<I", len(footer)) + b"PAR1"


def test_chunks_that_share_one_stored_page_are_charged_for_every_read():
    # a 64 KiB stored page and 400 chunks that all point at it: each read copies it, so the file's read
    # budget, not the file's size, bounds the copies (400 reads would be 25 MiB)
    page = data_page(v1_header(8192), struct.pack("<8192q", *range(8192)))
    data = chunks_on_one_page(page, 400, n=8192)
    assert len(data) < 90_000
    got, peak = traced(lambda: tp.read_parquet(data, max_values=1, max_read=10 * len(page)))
    cols = got["row_groups"][0]["columns"]
    assert [c["pages"] for c in cols[:11]] == [1] * 10 + [0]
    assert all(c["values"] == [0] for c in cols[:10]) and all(c["values"] == [] for c in cols[10:])
    assert cols[10]["cut"] == "the file's pages reached its read limit before page 1: it and the pages after it were not read"
    assert peak < 8 << 20, f"{peak} bytes were allocated"
    # the default budget is the module's, of stored and decompressed bytes alike
    assert tp.MAX_FILE_READ == 512 << 20 and tp.MAX_FILE_PAGES == 200_000 and tp.MAX_KEPT_BYTES == 32 << 20


def test_index_pages_count_against_the_files_page_limit():
    # an index page (type 1) has no values, so only the page limit ends a chunk that keeps reading them
    index = W().i32(1, 1).i32(2, 0).i32(3, 0).done()
    data = chunks_on_one_page(index * 50 + data_page(v1_header(1), struct.pack("<q", 5)), 3, n=1)
    a, b, c = tp.read_parquet(data, max_pages=60)["row_groups"][0]["columns"]
    assert (a["values"], a["pages"], "cut" not in a) == ([5], 51, True)
    assert (b["values"], b["pages"]) == ([], 9) and b["cut"] == (
        "the file's 60-page limit was reached before page 10: it and the pages after it were not read")
    assert (c["values"], c["pages"]) == ([], 0)
    assert all(x["values"] == [5] for x in tp.read_parquet(data)["row_groups"][0]["columns"])


def test_kept_values_are_charged_their_bytes_not_their_number():
    # numbers are charged eight bytes each (the small cases first: a reader that does not charge fails
    # here, before the shared-dictionary file below makes it join what it should not)
    ints = parquet([col("id", 2, [page_v1(4, 0, struct.pack("<4q", 1, 2, 3, 4), 0)], n=4)], 4)
    c = only(ints, max_kept_bytes=24)
    assert c["values"] == [1, 2, 3] and "after the first 3 were not kept" in c["cut"]
    assert only(ints, max_kept_bytes=32)["values"] == [1, 2, 3, 4]
    # the cut is said where it happened, and the chunk's later pages are not read
    two = parquet([col("id", 2, [page_v1(2, 0, struct.pack("<2q", 1, 2), 0), page_v1(2, 0, struct.pack("<2q", 3, 4), 0)], n=4)], 4)
    c = only(two, max_kept_bytes=8)
    assert (c["values"], c["pages"]) == ([1], 1) and c["cut"] == (
        "the values kept from the file reached its limit of bytes in page 1: the chunk's values after the first 1 "
        "were not kept and the pages after it were not read")
    # a byte string is charged its length, each time a dictionary entry is kept
    entry = b"A" * 4096
    pages = dict_page([entry], 0) + data_page(v1_header(20_000, 8), bytes([1]) + uv(20_000 << 1) + b"\x00")
    data = chunks_on_one_page(pages, 100, ptype=6, n=20_000, has_dict=True, offset=4 + len(dict_page([entry], 0)))
    assert len(data) < 20_000
    c = only(chunks_on_one_page(pages, 1, ptype=6, n=20_000, has_dict=True, offset=4 + len(dict_page([entry], 0))),
             max_values=4, max_kept_bytes=3 * (len(entry) + 8))
    assert c["values_kept"] == 3 and "after the first 3 were not kept" in c["cut"]
    # 100 chunks share the two pages: the count cap alone would keep 100 x 50 references to the 4 KiB
    # entry and join them into blobs of 20 MiB; the byte budget keeps 10
    blobs = []
    got, peak = traced(lambda: tp.read_parquet(data, max_values=50, blobs=blobs, max_kept_bytes=10 * (len(entry) + 8)))
    cols = got["row_groups"][0]["columns"]
    assert cols[0]["values_kept"] == 10 and cols[0]["values"][0] == "A" * 512 + f"...(+{len(entry) - 512} bytes)"
    assert cols[0]["cut"] == ("the values kept from the file reached its limit of bytes in page 2: the chunk's values "
                              "after the first 10 were not kept and the pages after it were not read")
    assert all(c["values"] == [] and "before page 1" in c["cut"] for c in cols[1:])
    assert sum(len(b) for label, b in blobs if label.startswith("row group")) < 11 * len(entry)
    assert peak < 4 << 20, f"{peak} bytes were allocated"


def test_a_repeated_column_skips_its_repetition_levels():
    # two rows, ["x", "y"] and ["z"]: repetition levels 0 1 0 and definition levels 1 1 1, one bit each
    rep, dfn = b"\x03" + bytes([0b010]), b"\x03" + bytes([0b111])
    raw = struct.pack("<I", len(rep)) + rep + struct.pack("<I", len(dfn)) + dfn + strings(b"x", b"y", b"z")
    data = parquet([col("tags", 6, [data_page(v1_header(3), raw)], n=3, rep=2)], 2)
    got = tp.read_parquet(data)
    assert [(c["repetition"], c["max_def"], c["max_rep"]) for c in got["columns"]] == [("repeated", 1, 1)]
    c = got["row_groups"][0]["columns"][0]
    assert (c["values"], c["null_count"]) == (["x", "y", "z"], 0)
    # an empty list in the middle: its definition level is 0 and it has no value
    dfn = b"\x03" + bytes([0b101])
    raw = struct.pack("<I", len(rep)) + rep + struct.pack("<I", len(dfn)) + dfn + strings(b"x", b"z")
    c = only(parquet([col("tags", 6, [data_page(v1_header(3), raw)], n=3, rep=2)], 3))
    assert (c["values"], c["null_count"]) == (["x", "z"], 1)
    long = struct.pack("<I", 4096) + rep + struct.pack("<I", len(dfn)) + dfn + strings(b"x", b"z")
    with pytest.raises(FormatError, match="repetition levels run past it"):
        tp.read_parquet(parquet([col("tags", 6, [data_page(v1_header(3), long)], n=3, rep=2)], 3))
    packed = data_page(W().i32(1, 3).i32(2, 0).i32(3, 3).i32(4, 4).done(), raw)                  # BIT_PACKED repetition levels
    assert only(parquet([col("tags", 6, [packed], n=3, rep=2)], 3))["undecoded"] == "repetition levels in the encoding BIT_PACKED"


def v2_page(values, n, compressed):
    h2 = W().i32(1, n).i32(2, 0).i32(3, n).i32(4, 0).i32(5, 0).i32(6, 0)
    if compressed is not None:
        h2 = h2.bool(7, compressed) if isinstance(compressed, bool) else h2.i32(7, compressed)
    return data_page(h2.done(), values, ptype=3, field=8)


def test_a_version_2_page_that_says_it_is_not_compressed_is_read_as_stored():
    values = struct.pack("<3q", 7, 8, 9)
    stored = parquet([col("id", 2, [v2_page(values, 3, False)], codec=2, n=3)], 3)       # the chunk's codec is GZIP
    assert only(stored)["values"] == [7, 8, 9]
    for flag in (True, None):               # marked compressed, or not marked (the default): the bytes are no GZIP stream
        with pytest.raises(FormatError, match="a GZIP page: the gzip data does not decompress"):
            tp.read_parquet(parquet([col("id", 2, [v2_page(values, 3, flag)], codec=2, n=3)], 3))
    with pytest.raises(FormatError, match="a version 2 page's is_compressed is a Thrift int, not bool"):
        tp.read_parquet(parquet([col("id", 2, [v2_page(values, 3, 0)], codec=2, n=3)], 3))


def test_deprecated_statistics_are_read_and_scanned(tmp_path):
    old = {"raw": W().bin(1, b"zeta").bin(2, b"alpha").done()}                 # max (1) and min (2), the pre-2.4 fields
    page = page_v1(2, 0, strings(b"alpha", b"zeta"), 0)
    c = only(parquet([col("s", 6, [page], n=2, stats=old)], 2))
    assert c["statistics"] == {"min_deprecated": "alpha", "max_deprecated": "zeta"}
    flag = flagfmt.cribs()[0] + "deprecated_min_statistic}"
    hidden = {"raw": W().bin(1, b"zeta").bin(2, b"\xff" + flag.encode()).done()}
    (tmp_path / "s.parquet").write_bytes(parquet([col("s", 6, [page], n=2, stats=hidden)], 2))
    r = tp.solve(tmp_path)
    assert (r.status, r.flags) == ("solved", (flag,)) and "s statistics" in r.evidence[0].detail


@pytest.mark.parametrize("codec,module", [(4, "brotli"), (1, "cramjam"), (7, "cramjam"), (6, "zstandard")])
def test_a_page_codec_whose_decoder_is_not_installed_is_named_never_passed_through(codec, module, monkeypatch, tmp_path):
    data = sample(name_codec=codec, score_codec=0)
    (tmp_path / "rows.parquet").write_bytes(data)
    monkeypatch.setitem(sys.modules, module, None)             # the import fails as on a host without it
    with pytest.raises(NeedsTool, match=f"needs_tool py:{module}: a column is compressed with {tp.CODECS[codec]}") as e:
        tp.read_parquet(data)
    assert e.value.tool == f"py:{module}"
    r = tp.solve(tmp_path)
    assert r.status == "blocked" and f"rows.parquet: Parquet/Thrift: needs_tool py:{module}" in r.notes


def test_detect_takes_the_strict_envelope_and_not_its_near_misses():
    call = H("80010001 00000004") + b"ping" + H("00000009")
    assert tp.detect(call + H("00")) and tp.detect(call + H("0b0001 00000002 6869 00")) and tp.detect(b"PAR1" + bytes(20))
    assert not tp.detect(call + H("01"))                       # 1 is no binary-protocol field type
    assert not tp.detect(call)                                 # no struct after the envelope
    assert not tp.detect(H("80010001 00000004") + b"pi g" + H("00000009 00"))
    assert not tp.detect(H("80010005 00000004") + b"ping" + H("00000009 00"))          # no message type 5
    assert not tp.detect(H("80010001 00000000 00000009 00") + bytes(8))                # an empty name
    assert not tp.detect(H("80020001 00000004") + b"ping" + H("00000009 00"))          # another version


def test_mutated_parquet_files_raise_only_the_declared_errors():
    from ctf.formats import corpus
    base = corpus.build("parquet_rows").data
    read, refused = only_declared_errors(tp.inspect, bit_flips(base))                    # every bit of the corpus sample
    assert read + refused == 8 * len(base) and refused > 500 and read > 0
    for seed, data in enumerate((sample(), sample(name_codec=2, score_codec=0), sample(name_codec=0, score_codec=7))):
        read, refused = only_declared_errors(tp.inspect, mutations(data, 1500, seed=251 + seed))
        assert read + refused == 1500 and refused > 300 and read > 0


def test_mutated_thrift_messages_raise_only_the_declared_errors():
    body = (H("08 0001 00000007") + H("0b 0002 00000002 6869") + H("0f 0003 0a 00000002") + struct.pack(">qq", -1, 5)
            + H("0d 0004 0b 08 00000001 00000001 6b 0000002a") + H("0c 0005 02 0001 01 00") + H("00"))
    message = H("80010001 00000004") + b"ping" + H("00000009") + body
    assert tp.inspect(message)[0]["readings"][0]["struct"]["5:struct"] == {"1:bool": True}
    read, refused = only_declared_errors(tp.inspect, bit_flips(message))
    assert read + refused == 8 * len(message) and refused > 100 and read > 0
    read, refused = only_declared_errors(lambda d: tp.inspect(d, "x", {"bare": "1"}), mutations(body, 1500, seed=7))
    assert read + refused == 1500
