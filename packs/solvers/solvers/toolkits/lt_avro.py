#!/usr/bin/env python3
"""Avro object container reader (B-251 long tail): the embedded schema, metadata and every record.

An Avro object container file (magic `Obj\\x01`) carries its own writer schema as JSON, so it is read
with no outside schema: the file metadata map, the 16-byte sync marker, then blocks of records under
the codec the metadata names (null, deflate, snappy with its CRC32, bzip2, xz, zstandard). Every
block's trailing sync marker and every snappy CRC is checked; a mismatch is a FormatError naming the
block, never a shorter result.

    decode_datum(schema, data, offset=0) -> (value, end)   one datum of a schema (the Avro binary encoding)
    read_container(data, max_records=...) -> dict          the facts of a container file
    detect / inspect / solve                               the engine entry points (_lt_common)

Bounds. No count the file states is trusted past what its bytes can hold: a block of records, an
array or a map whose items have a least encoded size (`Schema.min_size`) is refused when it states
more items than its bytes hold, and items of no size at all (null, an empty record, a zero-size fixed)
are charged to MAX_EMPTY_ITEMS per file. Every value decoded (a record and each of its fields, each
item, each union branch) is charged to MAX_DECODED_VALUES per file, so a record of many fields that
take no bytes costs its fields, never a count the file states times them. MAX_RECORDS records are
kept, and no more records once the kept ones hold MAX_KEPT_VALUES values (`keep_stopped` then says
so); MAX_WALK records are decoded and a block decompresses to MAX_BLOCK_BYTES at most (more is a
FormatError). Once MAX_WALK records or MAX_DECODED_VALUES values are decoded, or the blocks decoded
so far hold MAX_UNPACKED_BYTES, the remaining records and blocks are not decoded: `record_count` is
then the sum the block headers state, `records_walked` says how many were decoded and `walk_stopped`
why (the sync markers are still checked). MAX_DEPTH nested values. Bytes and fixed
values are shown as text when they are clean UTF-8, else as `hex:`; they are also handed to the flag
scan as raw bytes. Logical types are not applied: a decimal is its bytes, a timestamp its long.
"""
from __future__ import annotations

import json
import struct
import sys
import zlib

from _lt_common import FormatError, bounded_decompress, cli, need, solve_files, text_or_hex

ENGINE = "toolkits.lt_avro"
MAGIC = b"Obj\x01"
MAX_RECORDS = 50_000
MAX_WALK = 1_000_000               # records decoded (kept or not) before the walk stops
MAX_EMPTY_ITEMS = 1_000_000        # items of no encoded size (their count is all the file gives)
MAX_DECODED_VALUES = 4_000_000     # values decoded per file (a record and each of its fields count)
MAX_KEPT_VALUES = 1_000_000        # values the kept records may hold in all
MAX_BLOCK_BYTES = 64 << 20         # bytes one block may decompress to
MAX_UNPACKED_BYTES = 512 << 20     # bytes all the blocks of a file may decompress to
MAX_DEPTH = 64
CODECS = {"deflate": "deflate", "bzip2": "bzip2", "xz": "xz", "zstandard": "zstd"}
PRIMITIVES = ("null", "boolean", "int", "long", "float", "double", "bytes", "string")


def read_long(d, o):
    """A zigzag varint (Avro int and long): (value, end)."""
    shift = n = 0
    while True:
        need(o < len(d), "a varint runs past the end of the data")
        b = d[o]
        o += 1
        n |= (b & 0x7F) << shift
        if not b & 0x80:
            break
        shift += 7
        need(shift <= 63, "a varint is longer than ten bytes")
    return (n >> 1) ^ -(n & 1), o


class WorkLimit(FormatError):
    """The file's budget of decoded values is spent (read_container stops the walk on it)."""


def _take(d, o, n):
    need(0 <= n <= len(d) - o, f"a {n}-byte value at offset {o} runs past the end of the data")
    return d[o:o + n], o + n


class Schema:
    """A parsed writer schema: named types resolved by full name, as the specification resolves them."""

    def __init__(self, text):
        try:
            self.root = json.loads(text)
        except (ValueError, UnicodeDecodeError) as e:
            raise FormatError(f"avro.schema is not JSON ({e})") from None
        except RecursionError:
            raise FormatError("avro.schema nests deeper than a JSON reader follows") from None
        self.named, self.empty_left, self._sizes = {}, MAX_EMPTY_ITEMS, {}
        self.values_left = MAX_DECODED_VALUES
        self._collect(self.root, None)

    def spend_value(self):
        """Charge one decoded value to the file's budget."""
        self.values_left -= 1
        if self.values_left < 0:
            raise WorkLimit(f"more than {MAX_DECODED_VALUES} values decoded in the file")

    def spend_empty(self, n: int, what: str):
        """Charge n items that take no bytes: only their stated count bounds them."""
        self.empty_left -= n
        need(self.empty_left >= 0, f"{what} states {n} items of no size: more than {MAX_EMPTY_ITEMS} in the file")

    def min_size(self, s, ns=None, depth=0) -> int:
        """The fewest bytes one datum of the schema takes (0: null, an empty record, a zero-size fixed).
        A type met again inside itself counts 0 there: a lower bound is all a caller needs."""
        if depth > MAX_DEPTH:
            return 0
        try:
            s, ns = self.resolve(s, ns)
        except FormatError:                             # an undefined name: refused where a datum meets it
            return 0
        if isinstance(s, list):
            return 1 + min((self.min_size(b, ns, depth + 1) for b in s), default=0)
        if isinstance(s, str):
            return {"null": 0, "float": 4, "double": 8}.get(s, 1)
        if not isinstance(s, dict):
            return 0
        t = s.get("type")
        if t in ("array", "map", "enum"):
            return 1
        if t == "fixed":
            return s["size"] if isinstance(s.get("size"), int) and s["size"] > 0 else 0
        if t in ("record", "error"):
            key = id(s)
            if key not in self._sizes:
                self._sizes[key] = 0                    # while it is being summed (a recursive type)
                self._sizes[key] = sum(self.min_size(f["type"], ns, depth + 1) for f in s.get("fields", []))
            return self._sizes[key]
        return 0

    def _full(self, name, namespace):
        return name if "." in name or not namespace else f"{namespace}.{name}"

    def _collect(self, s, ns, depth=0):
        need(depth <= MAX_DEPTH, "the schema nests deeper than this reader follows")
        if isinstance(s, list):
            for b in s:
                self._collect(b, ns, depth + 1)
        elif isinstance(s, dict):
            t = s.get("type")
            if t in ("record", "error", "enum", "fixed"):
                need(isinstance(s.get("name"), str), f"a {t} schema has no name")
                space = s.get("namespace", ns)
                need(space is None or isinstance(space, str), f"the namespace of {s['name']} is not a string")
                full = self._full(s["name"], space)
                inner = full.rpartition(".")[0] or None
                self.named[full] = s
                s["__ns"] = inner
                if t in ("record", "error"):
                    need(isinstance(s.get("fields", []), list), f"the fields of {full} are not a list")
                    for f in s.get("fields", []):
                        need(isinstance(f, dict) and "type" in f, f"a field of {full} has no type")
                        self._collect(f["type"], inner, depth + 1)
                elif t == "enum":
                    symbols = s.get("symbols", [])
                    need(isinstance(symbols, list) and all(isinstance(x, str) for x in symbols),
                         f"the symbols of {full} are not a list of strings")
            elif t == "array":
                self._collect(s.get("items"), ns, depth + 1)
            elif t == "map":
                self._collect(s.get("values"), ns, depth + 1)
            elif isinstance(t, (dict, list)):
                self._collect(t, ns, depth + 1)

    def resolve(self, s, ns):
        """(schema dict or primitive name, namespace in force) for a schema as it is written at a use."""
        if isinstance(s, str):
            if s in PRIMITIVES:
                return s, ns
            got = self.named.get(self._full(s, ns)) or self.named.get(s)
            need(got is not None, f"the schema names the type {s!r} and never defines it")
            return got, got.get("__ns")
        if isinstance(s, dict) and isinstance(s.get("type"), (dict, list)):
            return self.resolve(s["type"], ns)
        if isinstance(s, dict) and s.get("type") in PRIMITIVES:
            return s["type"], ns
        if isinstance(s, dict) and isinstance(s.get("type"), str) and s["type"] not in (
                "record", "error", "enum", "fixed", "array", "map"):
            return self.resolve(s["type"], ns)
        return s, (s.get("__ns", ns) if isinstance(s, dict) else ns)


def _decode(sc: Schema, s, ns, d, o, blobs, depth):
    need(depth <= MAX_DEPTH, "a value nests deeper than this reader follows")
    sc.spend_value()
    s, ns = sc.resolve(s, ns)
    if isinstance(s, list):                                   # union: the branch index, then the value
        i, o = read_long(d, o)
        need(0 <= i < len(s), f"a union index {i} is outside its {len(s)} branches")
        return _decode(sc, s[i], ns, d, o, blobs, depth + 1)
    if s == "null":
        return None, o
    if s == "boolean":
        b, o = _take(d, o, 1)
        need(b[0] in (0, 1), f"a boolean is the byte {b[0]}")
        return bool(b[0]), o
    if s in ("int", "long"):
        return read_long(d, o)
    if s == "float":
        b, o = _take(d, o, 4)
        return struct.unpack("<f", b)[0], o
    if s == "double":
        b, o = _take(d, o, 8)
        return struct.unpack("<d", b)[0], o
    if s in ("bytes", "string"):
        n, o = read_long(d, o)
        b, o = _take(d, o, n)
        if s == "string":
            try:
                return b.decode("utf-8"), o
            except UnicodeDecodeError:
                raise FormatError("a string is not UTF-8") from None
        blobs.append(bytes(b))
        return text_or_hex(b), o
    need(isinstance(s, dict), f"a schema of type {type(s).__name__} is not an Avro schema")
    t = s.get("type")
    if t in ("record", "error"):
        out = {}
        for f in s.get("fields", []):
            out[str(f.get("name"))], o = _decode(sc, f["type"], ns, d, o, blobs, depth + 1)
        return out, o
    if t == "enum":
        i, o = read_long(d, o)
        symbols = s.get("symbols") or []
        need(0 <= i < len(symbols), f"an enum index {i} is outside its {len(symbols)} symbols")
        return symbols[i], o
    if t == "fixed":
        need(isinstance(s.get("size"), int) and s["size"] >= 0, "a fixed schema has no size")
        b, o = _take(d, o, s["size"])
        blobs.append(bytes(b))
        return text_or_hex(b), o
    if t in ("array", "map"):
        out = [] if t == "array" else {}
        while True:
            n, o = read_long(d, o)
            if n == 0:
                return out, o
            if n < 0:                                        # a negative count is followed by the block's size
                n = -n
                _, o = read_long(d, o)
            least = sc.min_size(s.get("items"), ns) if t == "array" else 1 + sc.min_size(s.get("values"), ns)
            if least:                                        # every item takes bytes: the bytes bound the count
                need(n * least <= len(d) - o, f"an {t} block states {n} items in {len(d) - o} bytes")
            else:                                            # null, empty records: only the count bounds them
                sc.spend_empty(n, f"an {t} block")
            for _ in range(n):
                if t == "array":
                    v, o = _decode(sc, s.get("items"), ns, d, o, blobs, depth + 1)
                    out.append(v)
                else:
                    k, o = _decode(sc, "string", ns, d, o, blobs, depth + 1)
                    out[k], o = _decode(sc, s.get("values"), ns, d, o, blobs, depth + 1)
    raise FormatError(f"the schema type {t!r} is not an Avro type")


def decode_datum(schema, data: bytes, offset: int = 0, blobs=None):
    """(value, end) of one datum. `schema` is a parsed schema (a dict, a union list, a primitive's name)
    or the schema's JSON text as bytes."""
    sc = Schema(schema if isinstance(schema, bytes) else json.dumps(schema))
    return _decode(sc, sc.root, None, data, offset, [] if blobs is None else blobs, 0)


def _unblock(codec: str, body: bytes, index: int) -> bytes:
    """The block's bytes, never more than MAX_BLOCK_BYTES of them (a block that holds more is a
    FormatError: nothing past the limit is inflated)."""
    what, why, limit = f"block {index}", f"the container's codec is {codec}", MAX_BLOCK_BYTES
    if codec == "null":
        return body
    if codec in CODECS:
        return bounded_decompress(CODECS[codec], body, limit, what, why)
    if codec == "snappy":
        need(len(body) >= 4, f"block {index}: a snappy block is shorter than its CRC")
        raw = bounded_decompress("snappy", body[:-4], limit, what, why)
        need(zlib.crc32(raw) == struct.unpack(">I", body[-4:])[0],
             f"block {index}: the snappy CRC32 does not match the decompressed bytes")
        return raw
    raise FormatError(f"the codec {codec!r} is not one this reader decodes "
                      "(null, deflate, snappy, bzip2, xz, zstandard)")


def read_container(data: bytes, max_records: int = MAX_RECORDS, blobs=None, max_walk: int | None = None,
                   max_unpacked: int | None = None, max_values: int | None = None,
                   max_kept_values: int | None = None) -> dict:
    blobs = [] if blobs is None else blobs
    max_walk = MAX_WALK if max_walk is None else max_walk
    max_unpacked = MAX_UNPACKED_BYTES if max_unpacked is None else max_unpacked
    max_kept_values = MAX_KEPT_VALUES if max_kept_values is None else max_kept_values
    need(data[:4] == MAGIC, "no Avro object container magic (Obj\\x01)")
    meta, o = {}, 4
    while True:                                              # the metadata: a map of bytes
        n, o = read_long(data, o)
        if n == 0:
            break
        if n < 0:
            n = -n
            _, o = read_long(data, o)
        need(n <= len(data) - o, "the metadata map states more entries than the file holds")
        for _ in range(n):
            ln, o = read_long(data, o)
            k, o = _take(data, o, ln)
            ln, o = read_long(data, o)
            v, o = _take(data, o, ln)
            meta[k.decode("utf-8", "replace")] = bytes(v)
    sync, o = _take(data, o, 16)
    need("avro.schema" in meta, "the metadata has no avro.schema")
    sc = Schema(meta["avro.schema"])
    if max_values is not None:
        sc.values_left = max_values
    budget = sc.values_left
    codec = meta.get("avro.codec", b"null").decode("ascii", "replace") or "null"
    least = sc.min_size(sc.root)
    records, total, walked, unpacked, blocks, stopped = [], 0, 0, 0, 0, None
    kept_values, keep_stopped = 0, None
    while o < len(data):
        count, o = read_long(data, o)
        size, o = read_long(data, o)
        need(count >= 0 and size >= 0, f"block {blocks}: a negative count or size")
        body, o = _take(data, o, size)
        mark, o = _take(data, o, 16)
        need(mark == sync, f"block {blocks}: the sync marker after it is not the file's")
        total += count
        blocks += 1
        if stopped:                                     # past a limit a block is counted, not decoded
            continue
        if unpacked >= max_unpacked:
            stopped = f"the blocks before it decompressed to {unpacked} bytes: block {blocks - 1} on is not decoded"
            continue
        raw = _unblock(codec, bytes(body), blocks - 1)
        unpacked += len(raw)
        if least:                                       # every record takes bytes: the bytes bound the count
            need(count * least <= len(raw), f"block {blocks - 1} states {count} records in {len(raw)} bytes")
        at = 0
        for _ in range(count):
            if walked >= max_walk:
                stopped = f"{max_walk} records were decoded: the records after them are counted, not decoded"
                break
            kept = len(records) < max_records and not keep_stopped    # past the cap a record is walked, not kept
            before = sc.values_left
            try:
                v, at = _decode(sc, sc.root, None, raw, at, blobs if kept else [], 0)
            except WorkLimit:
                stopped = (f"{budget} values were decoded: record {walked} and the records after it are counted, "
                           "not decoded")
                break
            if kept and kept_values + before - sc.values_left > max_kept_values:
                keep_stopped = (f"the {len(records)} records kept hold {kept_values} values: the records after "
                                f"them are decoded, not kept (a limit of {max_kept_values} values)")
            elif kept:
                kept_values += before - sc.values_left
                records.append(v)
            walked += 1
        else:
            need(at == len(raw), f"block {blocks - 1}: {len(raw) - at} bytes are left after its {count} records")
    for k, v in meta.items():
        if not k.startswith("avro."):
            blobs.append(v)
    out = {"format": "avro", "codec": codec, "sync_hex": bytes(sync).hex(), "block_count": blocks,
           "record_count": total, "records_kept": len(records),
           "schema": json.loads(meta["avro.schema"]),
           "metadata": {k: text_or_hex(v) for k, v in meta.items() if k != "avro.schema"},
           "records": records}
    if stopped:
        out.update(records_walked=walked, walk_stopped=stopped)
    if keep_stopped:
        out["keep_stopped"] = keep_stopped
    return out


def detect(head: bytes, name: str = "") -> bool:
    return head[:4] == MAGIC


def inspect(data: bytes, name: str = "", opts=None):
    blobs = []
    facts = read_container(data, int((opts or {}).get("max_records", MAX_RECORDS)), blobs)
    return facts, [(f"bytes[{i}]", b) for i, b in enumerate(blobs)]


def solve(challenge_dir, profile=None, **opts):
    """Read every Avro object container in the handout and scan its records and metadata for a flag."""
    return solve_files(ENGINE, "Avro container", challenge_dir, profile, detect, inspect, opts)


if __name__ == "__main__":
    sys.exit(cli(sys.argv[1:], __doc__, detect, inspect, ("max_records",)))
