#!/usr/bin/env python3
"""Thrift (binary and compact protocol) decoder and Parquet reader (B-251 long tail), with no schema.

Thrift wire data carries each field's id and type, so a struct is walked without its IDL:

    decode_thrift(data, bare=False) -> [reading]   every way the bytes parse to their last byte: a
                                                   strict binary or a compact message envelope
                                                   (name, type, sequence id), and with bare=True a
                                                   bare struct in either protocol. Several readings
                                                   are all returned: the reader never picks one.
    compact_struct / binary_struct(data, offset)   (Struct, end): {field id: value} with .types

Parquet is read through that decoder: the footer (FileMetaData), the schema tree, the key/value
metadata, each column chunk's statistics, and the values of its pages: PLAIN and dictionary encoded
(PLAIN_DICTIONARY, RLE_DICTIONARY) data pages, version 1 and 2, with RLE definition levels, under
no compression, snappy, gzip, zstd, brotli or lz4_raw. What is not decoded is said per column
(`undecoded`: a delta or byte-stream-split encoding, LZO or framed LZ4, an encrypted column), never
dropped quietly. An encrypted footer (PARE) is a NeedsKey.

    read_parquet(data, max_values=...) -> dict
    read_thrift(data, bare=False) -> dict          {"format": "thrift", "readings": decode_thrift(...)}
    detect / inspect / solve                       the engine entry points (_lt_common)

Bounds. Every footer and page-header field is checked for its Thrift type before it is used: a file
that puts another type there is a FormatError, as is a count below zero. MAX_DEPTH nested values.
A page decompresses to the size its header states and no further (more is a FormatError), to
MAX_PAGE_BYTES at most. Column chunks may all point at the same pages, so what a file makes the reader
do is charged to budgets of the file, not of a chunk: every page read is charged its stored bytes
(header and body) and, when compressed, the bytes it decompresses to, against MAX_FILE_READ; at most
MAX_FILE_PAGES pages are read; and every value kept is charged its bytes (8 for a number, its length
plus 8 for a byte string, a dictionary entry each time it is kept) against MAX_KEPT_BYTES. MAX_VALUES
values are kept per column chunk: a page's stated num_values never sizes an allocation (level and
index runs are counted, not expanded; a PLAIN page is checked against its bytes and only the kept
values are decoded; a BYTE_ARRAY page is walked only as far as the kept values). Where a cap or a
budget ends a chunk's reading, its remaining pages are not read (`cut` says why; the stated count is
still reported), and once a file budget is spent no later chunk reads a page. A dictionary holds
MAX_DICTIONARY entries at most. No length is trusted past the end of the data.
"""
from __future__ import annotations

import json
import struct
import sys

from _lt_common import FormatError, NeedsKey, bounded_decompress, cli, need, solve_files, text_or_hex
from ctf.formats import detect_longtail as structure      # _lt_common put the repo root on sys.path

ENGINE = "toolkits.lt_thrift_parquet"
MAX_DEPTH = 64
MAX_PAGE_BYTES = 64 << 20
MAX_VALUES = 20_000
MAX_PAGE_VALUES = (1 << 31) - 1      # num_values is an i32 in the format
MAX_EXPANDED = 1 << 20               # values hybrid() builds a list of (the reader counts runs instead)
MAX_DICTIONARY = 1 << 20             # entries of one dictionary page
MAX_FILE_READ = 512 << 20            # bytes all the pages of a file may take, stored and decompressed
MAX_FILE_PAGES = 200_000             # pages read per file, whatever chunk points at them
MAX_KEPT_BYTES = 32 << 20            # bytes the values kept from a file may hold

COMPACT = {1: "bool", 2: "bool", 3: "i8", 4: "i16", 5: "i32", 6: "i64", 7: "double", 8: "binary", 9: "list",
           10: "set", 11: "map", 12: "struct", 13: "uuid"}
BINARY = {2: "bool", 3: "i8", 4: "double", 6: "i16", 8: "i32", 10: "i64", 11: "binary", 12: "struct", 13: "map",
          14: "set", 15: "list", 16: "uuid"}
MESSAGE_TYPES = {1: "call", 2: "reply", 3: "exception", 4: "oneway"}


class Struct(dict):
    """{field id: value}; .types is {field id: thrift type name}."""

    def __init__(self):
        super().__init__()
        self.types = {}


def _take(d, o, n):
    need(0 <= n <= len(d) - o, f"a {n}-byte value at offset {o} runs past the end of the data")
    return bytes(d[o:o + n]), o + n


def varint(d, o):
    shift = n = 0
    while True:
        need(o < len(d), "a varint runs past the end of the data")
        b = d[o]
        o += 1
        n |= (b & 0x7F) << shift
        if not b & 0x80:
            return n, o
        shift += 7
        need(shift <= 63, "a varint is longer than ten bytes")


def _zz(n):
    return (n >> 1) ^ -(n & 1)


# ------------------------------------------------------------------ compact protocol

def _compact_value(d, o, t, depth, element=False):
    need(depth <= MAX_DEPTH, "a value nests deeper than this reader follows")
    if t in (1, 2):                    # a field's bool is in its header; a container's is one byte
        if not element:
            return t == 1, o
        b, o = _take(d, o, 1)
        return b[0] == 1, o
    if t == 3:
        b, o = _take(d, o, 1)
        return struct.unpack("b", b)[0], o
    if t in (4, 5, 6):
        n, o = varint(d, o)
        return _zz(n), o
    if t == 7:
        b, o = _take(d, o, 8)
        return struct.unpack("<d", b)[0], o
    if t == 8:
        n, o = varint(d, o)
        return _take(d, o, n)
    if t in (9, 10):
        h, o = _take(d, o, 1)
        size, et = h[0] >> 4, h[0] & 15
        if size == 15:
            size, o = varint(d, o)
        need(et in COMPACT, f"a list's element type {et} is not a compact-protocol type")
        need(size <= len(d) - o, f"a list states {size} elements in {len(d) - o} bytes")
        out = []
        for _ in range(size):
            v, o = _compact_value(d, o, et, depth + 1, True)
            out.append(v)
        return out, o
    if t == 11:
        size, o = varint(d, o)
        if size == 0:
            return [], o
        h, o = _take(d, o, 1)
        kt, vt = h[0] >> 4, h[0] & 15
        need(kt in COMPACT and vt in COMPACT, f"a map's types {kt}/{vt} are not compact-protocol types")
        need(size <= len(d) - o, f"a map states {size} entries in {len(d) - o} bytes")
        out = []
        for _ in range(size):
            k, o = _compact_value(d, o, kt, depth + 1, True)
            v, o = _compact_value(d, o, vt, depth + 1, True)
            out.append([k, v])
        return out, o
    if t == 12:
        return compact_struct(d, o, depth + 1)
    if t == 13:
        return _take(d, o, 16)
    raise FormatError(f"the compact-protocol type {t} is not one")


def compact_struct(d, o=0, depth=0):
    need(depth <= MAX_DEPTH, "a struct nests deeper than this reader follows")
    out, last = Struct(), 0
    while True:
        h, o = _take(d, o, 1)
        if h[0] == 0:
            return out, o
        t, delta = h[0] & 15, h[0] >> 4
        need(t in COMPACT, f"a field header names the type {t}, which is not a compact-protocol type")
        if delta:
            fid = last + delta
        else:
            n, o = varint(d, o)
            fid = _zz(n)
        out[fid], o = _compact_value(d, o, t, depth)
        out.types[fid] = COMPACT[t]
        last = fid


# ------------------------------------------------------------------ binary protocol

def _binary_value(d, o, t, depth):
    need(depth <= MAX_DEPTH, "a value nests deeper than this reader follows")
    if t == 2:
        b, o = _take(d, o, 1)
        return b[0] != 0, o
    if t in (3, 4, 6, 8, 10):
        fmt = {3: ">b", 4: ">d", 6: ">h", 8: ">i", 10: ">q"}[t]
        b, o = _take(d, o, struct.calcsize(fmt))
        return struct.unpack(fmt, b)[0], o
    if t == 11:
        b, o = _take(d, o, 4)
        n = struct.unpack(">i", b)[0]
        need(n >= 0, "a string has a negative length")
        return _take(d, o, n)
    if t == 12:
        return binary_struct(d, o, depth + 1)
    if t == 13:
        b, o = _take(d, o, 6)
        kt, vt, size = b[0], b[1], struct.unpack(">i", b[2:])[0]
        need(size == 0 or (kt in BINARY and vt in BINARY), f"a map's types {kt}/{vt} are not binary-protocol types")
        need(0 <= size <= len(d) - o, f"a map states {size} entries in {len(d) - o} bytes")
        out = []
        for _ in range(size):
            k, o = _binary_value(d, o, kt, depth + 1)
            v, o = _binary_value(d, o, vt, depth + 1)
            out.append([k, v])
        return out, o
    if t in (14, 15):
        b, o = _take(d, o, 5)
        et, size = b[0], struct.unpack(">i", b[1:])[0]
        need(size == 0 or et in BINARY, f"a list's element type {et} is not a binary-protocol type")
        need(0 <= size <= len(d) - o, f"a list states {size} elements in {len(d) - o} bytes")
        out = []
        for _ in range(size):
            v, o = _binary_value(d, o, et, depth + 1)
            out.append(v)
        return out, o
    if t == 16:
        return _take(d, o, 16)
    raise FormatError(f"the binary-protocol type {t} is not one")


def binary_struct(d, o=0, depth=0):
    need(depth <= MAX_DEPTH, "a struct nests deeper than this reader follows")
    out = Struct()
    while True:
        h, o = _take(d, o, 1)
        if h[0] == 0:
            return out, o
        need(h[0] in BINARY, f"a field header names the type {h[0]}, which is not a binary-protocol type")
        b, o = _take(d, o, 2)
        fid = struct.unpack(">h", b)[0]
        out[fid], o = _binary_value(d, o, h[0], depth)
        out.types[fid] = BINARY[h[0]]


def render(v, blobs=None):
    """A decoded value as JSON-able facts: a struct's keys are `<id>:<type>`, bytes are text or hex."""
    if isinstance(v, Struct):
        return {f"{k}:{v.types[k]}": render(x, blobs) for k, x in v.items()}
    if isinstance(v, bytes):
        if blobs is not None:
            blobs.append(v)
        return text_or_hex(v)
    if isinstance(v, list):
        return [render(x, blobs) for x in v]
    return v


def decode_thrift(data: bytes, bare: bool = False, blobs=None) -> list:
    """Every reading of the bytes that ends exactly at their end. FormatError when there is none."""
    readings, errors = [], []

    def attempt(protocol, envelope, fn, at):
        try:
            st, end = fn(data, at)
        except FormatError as e:
            errors.append(f"{protocol}: {e}")
            return
        if end != len(data):
            errors.append(f"{protocol}: {len(data) - end} bytes are left after the struct")
            return
        if not st and envelope is None:
            errors.append(f"{protocol}: an empty struct")
            return
        readings.append({"protocol": protocol, "envelope": envelope, "struct": render(st, blobs)})

    if len(data) >= 12 and data[:3] == b"\x80\x01\x00" and data[3] in MESSAGE_TYPES:
        n = struct.unpack(">i", data[4:8])[0]
        if 0 <= n <= len(data) - 12:
            name = data[8:8 + n].decode("utf-8", "replace")
            seq = struct.unpack(">i", data[8 + n:12 + n])[0]
            attempt("binary", {"name": name, "type": MESSAGE_TYPES[data[3]], "seqid": seq}, binary_struct, 12 + n)
    if len(data) >= 4 and data[0] == 0x82 and data[1] & 0x1F == 1 and data[1] >> 5 in MESSAGE_TYPES:
        try:
            seq, o = varint(data, 2)
            n, o = varint(data, o)
            raw, o = _take(data, o, n)
            attempt("compact", {"name": raw.decode("utf-8", "replace"), "type": MESSAGE_TYPES[data[1] >> 5],
                                "seqid": seq}, compact_struct, o)
        except FormatError as e:
            errors.append(f"compact message: {e}")
    if bare:
        attempt("compact", None, compact_struct, 0)
        attempt("binary", None, binary_struct, 0)
    if not readings:
        raise FormatError("no Thrift reading consumes the bytes exactly (" + "; ".join(errors[:4] or ["no message envelope"]) + ")")
    return readings


# ------------------------------------------------------------------ Parquet

PHYSICAL = {0: "BOOLEAN", 1: "INT32", 2: "INT64", 3: "INT96", 4: "FLOAT", 5: "DOUBLE", 6: "BYTE_ARRAY",
            7: "FIXED_LEN_BYTE_ARRAY"}
REPETITION = {0: "required", 1: "optional", 2: "repeated"}
CODECS = {0: "UNCOMPRESSED", 1: "SNAPPY", 2: "GZIP", 3: "LZO", 4: "BROTLI", 5: "LZ4", 6: "ZSTD", 7: "LZ4_RAW"}
ENCODINGS = {0: "PLAIN", 2: "PLAIN_DICTIONARY", 3: "RLE", 4: "BIT_PACKED", 5: "DELTA_BINARY_PACKED",
             6: "DELTA_LENGTH_BYTE_ARRAY", 7: "DELTA_BYTE_ARRAY", 8: "RLE_DICTIONARY", 9: "BYTE_STREAM_SPLIT"}
CONVERTED = {0: "UTF8", 1: "MAP", 2: "MAP_KEY_VALUE", 3: "LIST", 4: "ENUM", 5: "DECIMAL", 6: "DATE", 7: "TIME_MILLIS",
             8: "TIME_MICROS", 9: "TIMESTAMP_MILLIS", 10: "TIMESTAMP_MICROS", 11: "UINT_8", 12: "UINT_16",
             13: "UINT_32", 14: "UINT_64", 15: "INT_8", 16: "INT_16", 17: "INT_32", 18: "INT_64", 19: "JSON",
             20: "BSON", 21: "INTERVAL"}
FIXED = {1: ("<i", 4), 2: ("<q", 8), 4: ("<f", 4), 5: ("<d", 8)}


LIBRARY = {1: "snappy", 2: "gzip", 4: "brotli", 6: "zstd", 7: "lz4"}      # codec -> bounded_decompress name


class _Undecoded(Exception):
    """This column's values are not decoded, for the stated reason (the rest of the file still is)."""


def _get(st, fid, kind, what, default=None):
    """Field `fid` of a decoded struct when it is absent (`default`) or has the Thrift type the format
    gives it (int, bytes, list, Struct, bool); a FormatError when the file put another type there."""
    v = st.get(fid)
    if v is None:
        return default
    ok = isinstance(v, kind) and (kind is not int or not isinstance(v, bool))
    need(ok, f"{what} is a Thrift {type(v).__name__.lower()}, not {'struct' if kind is Struct else kind.__name__}")
    return v


def _items(st, fid, kind, what) -> list:
    """Field `fid` as a list whose every element is a `kind` ([] when it is absent)."""
    out = _get(st, fid, list, what, [])
    need(all(isinstance(x, kind) and (kind is not int or not isinstance(x, bool)) for x in out),
         f"{what} holds a value that is not a {'struct' if kind is Struct else kind.__name__}")
    return out


def _count(st, fid, what) -> int:
    n = _get(st, fid, int, what, 0)
    need(0 <= n <= MAX_PAGE_VALUES, f"{what} is {n}")
    return n


def _name(table, v):
    return table.get(v, str(v)) if isinstance(v, int) and not isinstance(v, bool) else f"a {type(v).__name__} value"


def hybrid_runs(buf: bytes, bit_width: int, count: int):
    """(value, repeat) for exactly `count` values of Parquet's RLE / bit-packed hybrid encoding at
    `bit_width` bits each. A run is yielded as one pair, never expanded, so the work is bounded by the
    bytes of `buf`, whatever `count` says."""
    need(0 <= bit_width <= 32, f"a bit width of {bit_width}")
    o, width, left = 0, (bit_width + 7) // 8, count
    mask = (1 << bit_width) - 1
    while left > 0:
        if bit_width == 0 and o >= len(buf):
            yield 0, left
            return
        h, o = varint(buf, o)
        if h & 1:                                              # bit-packed: groups of eight values
            groups = h >> 1
            need(groups > 0, "an empty bit-packed run")
            if bit_width == 0:                                 # groups of no bits: one run of zeros
                n = min(left, 8 * groups)
                yield 0, n
                left -= n
                continue
            for _ in range(groups):
                if left <= 0:
                    break
                chunk, take = buf[o:o + bit_width], min(8, left)
                need(len(chunk) * 8 >= take * bit_width, "a bit-packed run ends before its values")
                acc = int.from_bytes(chunk, "little")
                for i in range(take):
                    yield (acc >> (i * bit_width)) & mask, 1
                left -= take
                o += bit_width
        else:                                                  # a run of one value
            run = h >> 1
            need(run > 0, "an empty RLE run")
            raw, o = _take(buf, o, width)
            n = min(run, left)
            yield int.from_bytes(raw, "little"), n
            left -= n


def hybrid(buf: bytes, bit_width: int, count: int) -> list:
    """`count` values of the hybrid encoding as a list (MAX_EXPANDED at most: the reader itself counts
    hybrid_runs and never builds a list a page header sized)."""
    need(0 <= count <= MAX_EXPANDED, f"{count} values are more than hybrid() expands ({MAX_EXPANDED})")
    out = []
    for v, n in hybrid_runs(buf, bit_width, count):
        out += [v] * n
    return out


def _present(levels: bytes, max_def: int, n: int) -> int:
    """How many of a page's n definition levels say the value is there."""
    return sum(rep for v, rep in hybrid_runs(levels, max_def.bit_length(), n) if v == max_def)


def _decompress(codec: int, body: bytes, size: int) -> bytes:
    """The page's bytes: exactly `size` of them, never more inflated than that."""
    name = _name(CODECS, codec)
    if size > MAX_PAGE_BYTES:
        raise _Undecoded(f"a page of {size} bytes is over the {MAX_PAGE_BYTES}-byte limit")
    if codec == 0:
        raw = body
    elif codec in LIBRARY:
        raw = bounded_decompress(LIBRARY[codec], body, size, f"a {name} page", f"a column is compressed with {name}")
    else:
        raise _Undecoded(f"the codec {name} is not decoded")
    need(len(raw) == size, f"a {name} page decompresses to {len(raw)} bytes, its header says {size}")
    return raw


def _plain(raw, at, leaf, n, keep):
    """The first min(n, keep) of a PLAIN page's n values. The page must hold all n (checked against its
    bytes for the fixed-size types; a BYTE_ARRAY page is walked only as far as the kept values)."""
    t, k = leaf["_type"], min(n, keep)
    if t == 0:
        need((n + 7) // 8 <= len(raw) - at, "a boolean page ends before its values")
        return [bool(raw[at + i // 8] >> (i % 8) & 1) for i in range(k)]
    if t in FIXED:
        fmt, w = FIXED[t]
        need(n * w <= len(raw) - at, f"a {PHYSICAL[t]} page ends before its {n} values")
        return list(struct.unpack_from(f"<{k}{fmt[1]}", raw, at))
    if t in (3, 7):
        w = 12 if t == 3 else leaf["_length"]
        need(isinstance(w, int) and w > 0, "a fixed-length column has no type_length")
        need(n * w <= len(raw) - at, f"a {PHYSICAL[t]} page ends before its {n} values")
        return [bytes(raw[at + i * w:at + (i + 1) * w]) for i in range(k)]
    if t == 6:
        out = []
        for _ in range(k):
            need(at + 4 <= len(raw), "a BYTE_ARRAY page ends before its values")
            ln = struct.unpack_from("<I", raw, at)[0]
            v, at = _take(raw, at + 4, ln)
            out.append(v)
        return out
    raise _Undecoded(f"the physical type {_name(PHYSICAL, t)} is not one")


def _values(raw, at, enc, leaf, present, dictionary, keep):
    """The first min(present, keep) values of a data page (every dictionary index is still checked)."""
    if enc == 0:
        return _plain(raw, at, leaf, present, keep)
    if enc in (2, 8):
        if dictionary is None:
            raise FormatError("a dictionary-encoded page comes before any dictionary page")
        if present == 0:
            return []
        need(at < len(raw), "a dictionary-encoded page has no bit width")
        out = []
        for i, rep in hybrid_runs(raw[at + 1:], raw[at], present):
            need(i < len(dictionary), f"a dictionary index {i} is outside its {len(dictionary)} entries")
            if len(out) < keep:
                out += [dictionary[i]] * min(rep, keep - len(out))
        return out
    raise _Undecoded(f"the encoding {_name(ENCODINGS, enc)} is not decoded")


def _leaves(elements):
    out, at = [], [1]

    def walk(count, path, d, r, depth):
        need(depth <= MAX_DEPTH, "the schema nests deeper than this reader follows")
        for _ in range(count):
            need(at[0] < len(elements), "the schema states more children than it has elements")
            e = elements[at[0]]
            at[0] += 1
            need(isinstance(e, Struct), "a schema element is not a struct")
            name = _get(e, 4, bytes, "a schema element's name", b"").decode("utf-8", "replace")
            rep = _get(e, 3, int, "a schema element's repetition", 0)
            kids = _get(e, 5, int, "a schema element's num_children", 0)
            ptype = _get(e, 1, int, "a schema element's type")
            dd, rr = d + (rep != 0), r + (rep == 2)
            if kids:
                walk(kids, path + [name], dd, rr, depth + 1)
            else:
                out.append({"path": ".".join(path + [name]), "type": PHYSICAL.get(ptype, str(ptype)),
                            "repetition": REPETITION.get(rep, str(rep)), "max_def": dd, "max_rep": rr,
                            "converted_type": CONVERTED.get(_get(e, 6, int, "a schema element's converted_type")),
                            "_type": ptype, "_length": _get(e, 2, int, "a schema element's type_length")})
    need(elements and isinstance(elements[0], Struct), "the footer has no schema")
    walk(_get(elements[0], 5, int, "the schema root's num_children", 0), [], 0, 0, 0)
    return out


def _show(v):
    return text_or_hex(v, 512) if isinstance(v, bytes) else v


def _statistic(raw, leaf):
    t = leaf["_type"]
    if t in FIXED and len(raw) == FIXED[t][1]:
        return struct.unpack(FIXED[t][0], raw)[0]
    if t == 0 and len(raw) == 1:
        return bool(raw[0])
    return text_or_hex(raw, 512)


class _Budget:
    """What the rest of a file may still cost: bytes of pages read (stored and decompressed), pages,
    and bytes of kept values. `spent` names the budget that ran out; from then on no page is read."""

    def __init__(self, read: int, pages: int, kept: int):
        self.read, self.pages, self.kept, self.spent = read, pages, kept, None
        self.page_limit = pages

    def value_cost(self, v) -> int:
        return 8 + len(v) if isinstance(v, bytes) else 8


def _column(data, md, leaf, max_values, budget):
    """(values kept, null count, pages read, why the reading stopped early or None) of one column
    chunk; _Undecoded with the reason when its values are not decoded at all. `budget` is the file's
    _Budget, shared by every chunk."""
    codec = _get(md, 4, int, "a column chunk's codec", 0)
    total = _get(md, 5, int, "a column chunk's num_values", 0)
    need(total >= 0, f"a column chunk states {total} values")
    first = _get(md, 9, int, "a column chunk's data page offset")
    lookup = _get(md, 11, int, "a column chunk's dictionary page offset")
    o = lookup if lookup and first is not None and lookup < first else first
    need(o is not None and 4 <= o < len(data), "a column chunk's page offset is outside the file")
    dictionary, values, nulls, seen, pages, cut = None, [], 0, 0, 0, None
    while seen < total:
        if len(values) >= max_values:
            cut = f"{max_values} values are kept: the pages after the first {pages} were not read"
            break
        if not budget.spent and budget.pages <= 0:
            budget.spent = f"the file's {budget.page_limit}-page limit was reached"
        if budget.spent:
            cut = f"{budget.spent} before page {pages + 1}: it and the pages after it were not read"
            break
        start = o
        ph, body_at = compact_struct(data, o)
        ptype = ph.get(1)
        usize = _get(ph, 2, int, "a page header's uncompressed size", -1)
        csize = _get(ph, 3, int, "a page header's compressed size", -1)
        need(usize >= 0 and csize >= 0, "a page header has no sizes")
        cost = body_at - start + csize + (usize if codec and ptype in (0, 2, 3) else 0)
        if cost > budget.read:
            budget.spent = "the file's pages reached its read limit"
            cut = f"{budget.spent} before page {pages + 1}: it and the pages after it were not read"
            break
        budget.read -= cost
        budget.pages -= 1
        body, o = _take(data, body_at, csize)
        pages += 1
        if ptype not in (0, 2, 3):
            continue                                         # an index page: no values
        if ptype == 2:
            h = _get(ph, 7, Struct, "a dictionary page's header")
            need(h is not None, "a dictionary page has no dictionary page header")
            n = _count(h, 1, "a dictionary page's num_values")
            if n > MAX_DICTIONARY:
                raise _Undecoded(f"a dictionary of {n} entries is over the {MAX_DICTIONARY}-entry limit")
            dictionary = _plain(_decompress(codec, body, usize), 0, leaf, n, n)
            continue
        if ptype == 0:
            h = _get(ph, 5, Struct, "a data page's header")
            need(h is not None, "a data page has no data page header")
            n, enc = _count(h, 1, "a data page's num_values"), _get(h, 2, int, "a data page's encoding", 0)
            raw, at, present = _decompress(codec, body, usize), 0, n
            if leaf["max_rep"]:
                if h.get(4) != 3:
                    raise _Undecoded(f"repetition levels in the encoding {_name(ENCODINGS, h.get(4))}")
                need(at + 4 <= len(raw), "a data page ends before its repetition levels")
                at += 4 + struct.unpack_from("<I", raw, at)[0]
                need(at <= len(raw), "a data page's repetition levels run past it")
            if leaf["max_def"]:
                if h.get(3) != 3:
                    raise _Undecoded(f"definition levels in the encoding {_name(ENCODINGS, h.get(3))}")
                need(at + 4 <= len(raw), "a data page ends before its definition levels")
                ln = struct.unpack_from("<I", raw, at)[0]
                lv, at = _take(raw, at + 4, ln)
                present = _present(lv, leaf["max_def"], n)
        else:
            h = _get(ph, 8, Struct, "a version 2 data page's header")
            need(h is not None, "a version 2 data page has no header")
            n, enc = _count(h, 1, "a version 2 page's num_values"), _get(h, 4, int, "a version 2 page's encoding", 0)
            dl = _get(h, 5, int, "a version 2 page's definition levels length", 0)
            rl = _get(h, 6, int, "a version 2 page's repetition levels length", 0)
            need(dl >= 0 and rl >= 0 and dl + rl <= len(body) and dl + rl <= usize, "a version 2 page's level sizes run past it")
            lv = body[rl:rl + dl]
            rest = body[rl + dl:]
            packed = _get(h, 7, bool, "a version 2 page's is_compressed", True)
            raw, at = (_decompress(codec, rest, usize - rl - dl) if packed else rest), 0
            present = n
            if leaf["max_def"]:
                present = _present(lv, leaf["max_def"], n)
        need(n > 0, "a data page states no values")
        for v in _values(raw, at, enc, leaf, present, dictionary, max_values - len(values)):
            if budget.value_cost(v) > budget.kept:
                budget.spent = "the values kept from the file reached its limit of bytes"
                break
            budget.kept -= budget.value_cost(v)
            values.append(v)
        nulls += n - present
        seen += n
        if budget.spent:
            cut = (f"{budget.spent} in page {pages}: the chunk's values after the first {len(values)} were not kept "
                   "and the pages after it were not read")
            break
    return values, nulls, pages, cut


def read_parquet(data: bytes, max_values: int = MAX_VALUES, blobs=None, max_read: int | None = None,
                 max_pages: int | None = None, max_kept_bytes: int | None = None) -> dict:
    blobs = [] if blobs is None else blobs
    budget = _Budget(MAX_FILE_READ if max_read is None else max_read,
                     MAX_FILE_PAGES if max_pages is None else max_pages,
                     MAX_KEPT_BYTES if max_kept_bytes is None else max_kept_bytes)
    need(len(data) >= 12 and data[:4] == b"PAR1", "no Parquet magic (PAR1) at the start")
    if data[-4:] == b"PARE":
        raise NeedsKey("the Parquet footer is encrypted (PARE): the footer key is needed")
    need(data[-4:] == b"PAR1", "no Parquet magic (PAR1) at the end: the file is cut or is not Parquet")
    flen = struct.unpack("<I", data[-8:-4])[0]
    need(flen <= len(data) - 12, f"the footer states {flen} bytes in a {len(data)}-byte file")
    fm, end = compact_struct(data[len(data) - 8 - flen:len(data) - 8])
    need(end == flen, f"{flen - end} bytes of the footer are left after its metadata")
    leaves = _leaves(_get(fm, 2, list, "the footer's schema", []))
    by_path = {leaf["path"]: leaf for leaf in leaves}
    kv = {}
    for item in _items(fm, 5, Struct, "the footer's key/value metadata"):
        key, value = _get(item, 1, bytes, "a metadata key", b""), _get(item, 2, bytes, "a metadata value", b"")
        kv[key.decode("utf-8", "replace")] = text_or_hex(value, 1 << 16)
        blobs.append(("metadata", value))
    groups = []
    for gi, rg in enumerate(_items(fm, 4, Struct, "the footer's row groups")):
        cols = []
        for cc in _items(rg, 1, Struct, "a row group's columns"):
            md = cc.get(3)
            if not isinstance(md, Struct):
                why = "an encrypted column (its metadata is not in the footer)" if 8 in cc or 9 in cc else \
                    "its metadata is in another file" if cc.get(1) else "it has no metadata"
                cols.append({"path": None, "undecoded": why})
                continue
            path = ".".join(p.decode("utf-8", "replace") for p in _items(md, 3, bytes, "a column's path"))
            leaf = by_path.get(path)
            col = {"path": path, "codec": _name(CODECS, md.get(4, 0)),
                   "encodings": [_name(ENCODINGS, e) for e in _get(md, 2, list, "a column's encodings", [])],
                   "num_values": _get(md, 5, int, "a column chunk's num_values")}
            need(leaf is not None, f"the column {path!r} is not a leaf of the schema")
            st = md.get(12)
            if isinstance(st, Struct):
                stats = {}
                for fid, key in ((6, "min"), (5, "max"), (2, "min_deprecated"), (1, "max_deprecated")):
                    if isinstance(st.get(fid), bytes):
                        stats[key] = _statistic(st[fid], leaf)
                        blobs.append((f"{path} statistics", st[fid]))
                if 3 in st:
                    stats["null_count"] = _get(st, 3, int, "a column's null_count statistic")
                col["statistics"] = stats
            try:
                values, nulls, pages, cut = _column(data, md, leaf, max_values, budget)
                col.update(values=[_show(v) for v in values], values_kept=len(values), null_count=nulls, pages=pages)
                if cut:
                    col["cut"] = cut
                raw = [v for v in values if isinstance(v, bytes)]
                if raw:
                    blobs.append((f"row group {gi} column {path}", b"\n".join(raw)))
            except _Undecoded as e:
                col["undecoded"] = str(e)
            cols.append(col)
        groups.append({"num_rows": _get(rg, 3, int, "a row group's num_rows"), "columns": cols})
    created = _get(fm, 6, bytes, "the footer's created_by")
    return {"format": "parquet", "version": _get(fm, 1, int, "the footer's version"),
            "num_rows": _get(fm, 3, int, "the footer's num_rows"),
            "created_by": None if created is None else created.decode("utf-8", "replace"),
            "columns": [{k: v for k, v in leaf.items() if not k.startswith("_")} for leaf in leaves],
            "key_value_metadata": kv, "row_groups": groups}


def read_thrift(data: bytes, bare: bool = False, blobs=None) -> dict:
    """The facts of a Thrift message: every reading (decode_thrift), never one picked among several."""
    return {"format": "thrift", "readings": decode_thrift(data, bare=bare, blobs=blobs)}


def detect(head: bytes, name: str = "") -> bool:
    """A Parquet file, or the strict binary protocol's message envelope (the catalog's own test)."""
    return head[:4] == b"PAR1" or structure.DETECTORS["thrift"](head)


def inspect(data: bytes, name: str = "", opts=None):
    opts = opts or {}
    blobs = []
    if data[:4] == b"PAR1":
        return read_parquet(data, int(opts.get("max_values", MAX_VALUES)), blobs), blobs
    raw = []
    facts = read_thrift(data, bare=str(opts.get("bare", "")) in ("1", "true", "yes"), blobs=raw)
    return facts, [("binary values", b"\n".join(raw))] if raw else []


def solve(challenge_dir, profile=None, **opts):
    """Read every Parquet file and enveloped Thrift message in the handout and scan the values for a flag."""
    return solve_files(ENGINE, "Parquet/Thrift", challenge_dir, profile, detect, inspect, opts)


def main(argv):
    if "--bare" in argv:                       # a bare struct has no magic: the caller says it is Thrift
        rc = 0
        for f in [a for a in argv if a != "--bare"]:
            try:
                with open(f, "rb") as fh:
                    rec = {"file": f, "format": "thrift", "readings": decode_thrift(fh.read(), bare=True)}
            except (OSError, FormatError) as e:
                rec, rc = {"file": f, "error": f"{type(e).__name__}: {e}"}, 1
            sys.stdout.write(json.dumps(rec) + "\n")
        return rc
    return cli(argv, __doc__, detect, inspect, ("max_values", "bare"))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
