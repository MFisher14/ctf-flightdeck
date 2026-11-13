"""Synthetic writers and corpus samples of the long-tail formats (B-251).

The writers here build each format from invented values and share no code with the readers under
`solvers/` (their own varints, their own table layout, their own key derivation), so a sample checks a
reader instead of mirroring it. The engine tests use the writers; `SAMPLES` are the catalog's corpus
samples (`ctf/formats/corpus.py` adds them to its BUILDERS).

    flat_buffer(fields, ident=None, size_prefixed=False)   a FlatBuffers buffer from a field list
    capnp_frame(segments)                                  a Cap'n Proto stream frame of word lists
    pb(...) / pb_msg(fields)                               protobuf wire fields
"""
from __future__ import annotations

import struct

# ------------------------------------------------------------------ FlatBuffers (forward layout)

_SCALARS = {"u8": "<B", "i8": "<b", "bool": "<?", "u16": "<H", "i16": "<h", "u32": "<I", "i32": "<i", "u64": "<Q",
            "i64": "<q", "f32": "<f", "f64": "<d"}


def _pad(out: bytearray, to: int = 4):
    out += bytes(-len(out) % to)


def _flat_emit(out: bytearray, f) -> int:
    kind = f[0]
    if kind == "table":
        return _flat_table(out, f[1])
    pos = len(out)
    if kind == "str":
        out += struct.pack("<I", len(f[1])) + f[1] + b"\x00"
    elif kind == "bytes":
        out += struct.pack("<I", len(f[1])) + f[1]
    elif kind == "vec":
        out += struct.pack("<I", len(f[2])) + b"".join(struct.pack(_SCALARS[f[1]], v) for v in f[2])
    elif kind in ("tables", "strs"):
        out += struct.pack("<I", len(f[1])) + bytes(4 * len(f[1]))
        for k, item in enumerate(f[1]):
            _pad(out)
            at = pos + 4 + 4 * k
            target = _flat_table(out, item) if kind == "tables" else _flat_emit(out, ("str", item))
            struct.pack_into("<I", out, at, target - at)
    else:
        raise ValueError(f"unknown FlatBuffers field kind {kind!r}")
    _pad(out)
    return pos


def _flat_table(out: bytearray, fields: list) -> int:
    """Append a table (vtable first, then the table, then what it references). Returns the table's
    position. fields[i] is None (absent), (scalar kind, value), ("str", bytes), ("bytes", bytes),
    ("vec", scalar kind, values), ("table", fields), ("tables", [fields]) or ("strs", [bytes])."""
    _pad(out)
    inline, slots, patches = bytearray(4), [], []
    for f in fields:
        if f is None:
            slots.append(0)
            continue
        if f[0] in _SCALARS:
            raw = struct.pack(_SCALARS[f[0]], f[1])
            inline += bytes(-len(inline) % min(len(raw), 4))
            slots.append(len(inline))
            inline += raw
        else:
            inline += bytes(-len(inline) % 4)
            slots.append(len(inline))
            patches.append((len(inline), f))
            inline += bytes(4)
    inline += bytes(-len(inline) % 4)
    vt = len(out)
    out += struct.pack("<HH", 4 + 2 * len(slots), len(inline)) + b"".join(struct.pack("<H", s) for s in slots)
    _pad(out)
    pos = len(out)
    struct.pack_into("<i", inline, 0, pos - vt)
    out += inline
    for off, f in patches:
        _pad(out)
        target = _flat_emit(out, f)
        struct.pack_into("<I", out, pos + off, target - (pos + off))
    return pos


def flat_buffer(fields: list, ident: bytes | None = None, size_prefixed: bool = False) -> bytes:
    out = bytearray(8 if ident else 4)
    if ident:
        out[4:8] = ident
    root = _flat_table(out, fields)
    struct.pack_into("<I", out, 0, root)
    return (struct.pack("<I", len(out)) if size_prefixed else b"") + bytes(out)


# ------------------------------------------------------------------ Cap'n Proto

def capnp_frame(segments: list) -> bytes:
    """One stream frame: the segment table, then each segment (a list of 64-bit words)."""
    head = struct.pack("<I", len(segments) - 1) + b"".join(struct.pack("<I", len(s)) for s in segments)
    head += bytes(-len(head) % 8)
    return head + b"".join(struct.pack(f"<{len(s)}Q", *s) for s in segments)


def capnp_struct_ptr(offset: int, data_words: int, pointer_words: int) -> int:
    return (offset & 0x3FFFFFFF) << 2 | data_words << 32 | pointer_words << 48


def capnp_list_ptr(offset: int, size: int, count: int) -> int:
    return (offset & 0x3FFFFFFF) << 2 | 1 | size << 32 | count << 35


def capnp_text(text: bytes) -> list:
    """The words of a Text value (the bytes and their NUL)."""
    raw = text + b"\x00"
    raw += bytes(-len(raw) % 8)
    return list(struct.unpack(f"<{len(raw) // 8}Q", raw))


# ------------------------------------------------------------------ protobuf wire format

def pb_varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b, n = n & 0x7F, n >> 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def pb(field: int, value) -> bytes:
    """One field: an int is a varint, bytes or str a length-delimited value, a float a 64-bit double."""
    if isinstance(value, bool) or isinstance(value, int):
        return pb_varint(field << 3) + pb_varint(int(value))
    if isinstance(value, float):
        return pb_varint(field << 3 | 1) + struct.pack("<d", value)
    raw = value.encode() if isinstance(value, str) else bytes(value)
    return pb_varint(field << 3 | 2) + pb_varint(len(raw)) + raw


def pb_msg(fields: list) -> bytes:
    return b"".join(pb(f, v) for f, v in fields)


# ------------------------------------------------------------------ TFLite and Core ML models

def tflite_model(description: bytes = b"", tensors=(), metadata=(), operators=(), opcodes=(), signature=None,
                 subgraph_name: bytes = b"main", signature_subgraph: int = 0, extra_subgraphs=()) -> bytes:
    """A TFLite model (FlatBuffers, identifier TFL3) laid out by the slots of the published schema.
    tensors: [(name, shape, tensor type number, constant bytes or b"")]; metadata: [(name, bytes)];
    opcodes: [(builtin code, custom name or None)]; operators: [(opcode index, inputs, outputs, custom
    options or None)]; signature: (key, [(input name, tensor)], [(output name, tensor)]), of the
    subgraph numbered `signature_subgraph`; extra_subgraphs: the names of further, empty subgraphs."""
    buffers = [b""]                       # buffer 0 is the empty one every tensor without data names

    def buf(raw):
        if not raw:
            return 0
        buffers.append(raw)
        return len(buffers) - 1

    tensor_tables = [[("vec", "i32", list(shape)), ("i8", kind), ("u32", buf(raw)), ("str", name)]
                     for name, shape, kind, raw in tensors]
    meta_tables = [[("str", name), ("u32", buf(raw))] for name, raw in metadata]
    op_tables = [[("u32", i), ("vec", "i32", list(ins)), ("vec", "i32", list(outs)), None, None,
                  ("bytes", custom) if custom else None] for i, ins, outs, custom in operators]
    code_tables = [[("i8", min(code, 127)), ("str", custom) if custom else None, ("i32", 1), ("i32", code)]
                   for code, custom in opcodes]
    subgraph = [("tables", tensor_tables), ("vec", "i32", [0]), ("vec", "i32", [max(0, len(tensor_tables) - 1)]),
                ("tables", op_tables), ("str", subgraph_name)]
    sigs = None
    if signature:
        key, ins, outs = signature
        sigs = ("tables", [[("tables", [[("str", n), ("u32", t)] for n, t in ins]),
                            ("tables", [[("str", n), ("u32", t)] for n, t in outs]), ("str", key), None,
                            ("u32", signature_subgraph)]])
    more = [[("tables", []), ("vec", "i32", []), ("vec", "i32", []), ("tables", []), ("str", name)] for name in extra_subgraphs]
    fields = [("u32", 3), ("tables", code_tables), ("tables", [subgraph] + more), ("str", description),
              None, None, ("tables", meta_tables) if meta_tables else None, sigs]
    fields[4] = ("tables", [[("bytes", raw)] if raw else [] for raw in buffers])
    return flat_buffer(fields, b"TFL3")


def coreml_model(spec_version: int = 5, inputs=(), outputs=(), metadata=None, user_defined=None,
                 predicted: str | None = None, model_field: int = 500, body: bytes = b"\x0a\x00") -> bytes:
    """A Core ML Model message. inputs/outputs: [(name, short description, FeatureType field number)];
    metadata: {short_description, version, author, license}."""
    def feature(name, text, kind):
        return pb_msg([(1, name), (2, text), (3, pb(kind, b""))])
    metadata = metadata or {}
    meta = pb_msg([(n, metadata[k]) for n, k in ((1, "short_description"), (2, "version"), (3, "author"), (4, "license"))
                   if k in metadata] + [(100, pb_msg([(1, k), (2, v)])) for k, v in (user_defined or {}).items()])
    desc = pb_msg([(1, feature(*f)) for f in inputs] + [(10, feature(*f)) for f in outputs]
                  + ([(11, predicted)] if predicted else []) + ([(100, meta)] if meta else []))
    return pb(1, spec_version) + pb(2, desc) + pb(model_field, body)


# ------------------------------------------------------------------ TNEF (winmail.dat)

TNEF_SIGNATURE = b"\x78\x9f\x3e\x22"
TNEF_IID_IMESSAGE = bytes.fromhex("0703020000000000c000000000000046")     # {00020307-0000-0000-C000-000000000046}
_TNEF_FIXED = {0x0002: "<hxx", 0x0003: "<i", 0x0005: "<d", 0x000B: "<Hxx", 0x0014: "<q", 0x0040: "<Q"}
_TNEF_VARIABLE = (0x001E, 0x001F, 0x0102, 0x000D)


def tnef_attr(level: int, ident: int, data: bytes, checksum_delta: int = 0) -> bytes:
    """One attribute: level, id (type in the high word), length, data, the 16-bit sum of the data bytes."""
    return struct.pack("<BII", level, ident, len(data)) + data + struct.pack("<H", (sum(data) + checksum_delta) & 0xFFFF)


def tnef_props(props: list) -> bytes:
    """A MAPI property list. props: [(type, id, value)] or [(type, id, value, (guid bytes, name))] for a
    named property (id >= 0x8000; name an int or a str). A variable-size value is bytes as stored (text
    with its NUL); a multi-valued one (type | 0x1000) is a list."""
    out = bytearray(struct.pack("<I", len(props)))
    for p in props:
        ptype, pid, value = p[:3]
        out += struct.pack("<HH", ptype, pid)
        if pid >= 0x8000:
            guid, name = p[3]
            out += guid
            if isinstance(name, int):
                out += struct.pack("<II", 0, name)
            else:
                raw = (name + "\x00").encode("utf-16-le")
                out += struct.pack("<II", 1, len(raw)) + raw + bytes(-len(raw) % 4)
        base, multi = ptype & 0x0FFF, bool(ptype & 0x1000)
        values = value if multi else [value]
        if base in _TNEF_VARIABLE or multi:
            out += struct.pack("<I", len(values))
        for v in values:
            if base in _TNEF_VARIABLE:
                out += struct.pack("<I", len(v)) + v + bytes(-len(v) % 4)
            else:
                out += struct.pack(_TNEF_FIXED[base], v)
    return bytes(out)


def tnef_date(y, mo, d, h, mi, s) -> bytes:
    return struct.pack("<7H", y, mo, d, h, mi, s, 0)


def tnef_stream(attributes: list, key: int = 0x1234) -> bytes:
    return TNEF_SIGNATURE + struct.pack("<H", key) + b"".join(attributes)


# ------------------------------------------------------------------ Avro and Parquet

def zigzag(n: int) -> bytes:
    """A zigzag varint (Avro int/long, Thrift compact integers)."""
    return pb_varint((n << 1) ^ (n >> 63))


def avro_string(text) -> bytes:
    raw = text.encode() if isinstance(text, str) else bytes(text)
    return zigzag(len(raw)) + raw


def avro_container(schema_json: bytes, blocks: list, codec: str = "null", sync: bytes = bytes(range(0x50, 0x60))) -> bytes:
    """An Avro object container. blocks: [(record count, the records' encoded bytes)]; codec null or deflate."""
    import zlib
    meta = {b"avro.schema": schema_json, b"avro.codec": codec.encode()}
    out = bytearray(b"Obj\x01" + zigzag(len(meta)))
    for k, v in meta.items():
        out += avro_string(k) + avro_string(v)
    out += zigzag(0) + sync
    for count, raw in blocks:
        if codec == "deflate":
            c = zlib.compressobj(9, zlib.DEFLATED, -15)
            raw = c.compress(raw) + c.flush()
        out += zigzag(count) + zigzag(len(raw)) + raw + sync
    return bytes(out)


class ThriftCompact:
    """A Thrift compact-protocol struct writer (field deltas, zigzag integers)."""

    def __init__(self):
        self.out, self.last = bytearray(), 0

    def _field(self, fid, kind, payload=b""):
        delta = fid - self.last
        self.out += (bytes([delta << 4 | kind]) if 0 < delta <= 15 else bytes([kind]) + zigzag(fid)) + payload
        self.last = fid
        return self

    def i32(self, fid, v):
        return self._field(fid, 5, zigzag(v))

    def i64(self, fid, v):
        return self._field(fid, 6, zigzag(v))

    def binary(self, fid, raw):
        return self._field(fid, 8, pb_varint(len(raw)) + raw)

    def struct(self, fid, body):
        return self._field(fid, 12, body)

    def list(self, fid, kind, items):
        head = bytes([len(items) << 4 | kind]) if len(items) < 15 else bytes([0xF0 | kind]) + pb_varint(len(items))
        return self._field(fid, 9, head + b"".join(items))

    def done(self) -> bytes:
        return bytes(self.out) + b"\x00"


def parquet_plain(columns: list, num_rows: int, key_values: dict, created_by: bytes) -> bytes:
    """A Parquet file of required columns in one row group, PLAIN, uncompressed, one version 1 data
    page each. columns: [(name, physical type number, the values' PLAIN bytes)]."""
    out, chunks, schema = bytearray(b"PAR1"), [], [ThriftCompact().binary(4, b"schema").i32(5, len(columns)).done()]
    for name, kind, payload in columns:
        start = len(out)
        header = ThriftCompact().i32(1, 0).i32(2, len(payload)).i32(3, len(payload)).struct(
            5, ThriftCompact().i32(1, num_rows).i32(2, 0).i32(3, 3).i32(4, 3).done()).done()
        out += header + payload
        meta = ThriftCompact().i32(1, kind).list(2, 5, [zigzag(0)]).list(3, 8, [pb_varint(len(name)) + name])
        meta.i32(4, 0).i64(5, num_rows).i64(6, len(out) - start).i64(7, len(out) - start).i64(9, start)
        chunks.append(ThriftCompact().i64(2, start).struct(3, meta.done()).done())
        schema.append(ThriftCompact().i32(1, kind).i32(3, 0).binary(4, name).done())
    footer = ThriftCompact().i32(1, 1).list(2, 12, schema).i64(3, num_rows)
    footer.list(4, 12, [ThriftCompact().list(1, 12, chunks).i64(2, len(out) - 4).i64(3, num_rows).done()])
    footer.list(5, 12, [ThriftCompact().binary(1, k).binary(2, v).done() for k, v in key_values.items()])
    raw = footer.binary(6, created_by).done()
    return bytes(out) + raw + struct.pack("<I", len(raw)) + b"PAR1"


def thrift_message(name: bytes, kind: int, seqid: int, fields: list) -> bytes:
    """A strict binary-protocol message: version 80 01, the message type (1 call .. 4 oneway), the
    method name, the sequence id, the argument struct and its stop byte. fields: [(id, value)]: an int
    is an i32, bytes a string, a bool a bool."""
    out = bytearray(b"\x80\x01\x00" + bytes([kind]) + struct.pack(">i", len(name)) + name + struct.pack(">i", seqid))
    for fid, value in fields:
        if isinstance(value, bool):
            out += struct.pack(">bhb", 2, fid, value)
        elif isinstance(value, int):
            out += struct.pack(">bhi", 8, fid, value)
        else:
            out += struct.pack(">bhi", 11, fid, len(value)) + value
    return bytes(out) + b"\x00"


# ------------------------------------------------------------------ JPEG XL container

JXL_SIGNATURE = bytes.fromhex("0000000c4a584c200d0a870a")
# The first bytes of two codestreams the libjxl encoder (cjxl 0.11.1) wrote for random images: 100x50
# 8-bit lossy, and 40x30 8-bit lossless. Only the header is read; what follows is filler.
JXL_HEAD_100X50 = bytes.fromhex("ff0a88f1010013080100556a671328010050a132")
JXL_HEAD_40X30 = bytes.fromhex("ff0ae830100908020100a5464b189b9c71840338")


def jxl_box(kind: bytes, body: bytes) -> bytes:
    return struct.pack(">I4s", 8 + len(body), kind) + body


# ------------------------------------------------------------------ the catalog's corpus samples

def _sample(sample_id, name, data, checks):
    from .corpus import Check, Sample, _fill_identity
    rows = tuple(Check(p, v) for p, v in checks) + (Check("file.size_bytes", None), Check("sha256", None))
    return Sample(sample_id, name, data, _fill_identity(rows, name, data))


def avro_events():
    import json
    schema = {"type": "record", "name": "Event", "namespace": "corp.audit", "fields": [
        {"name": "id", "type": "long"}, {"name": "user", "type": "string"}, {"name": "action", "type": "string"}]}
    rows = [zigzag(i) + avro_string(u) + avro_string(a) for i, u, a in
            ((1, "ada", "login"), (2, "bob", "export"), (3, "ada", "logout"))]
    sync = bytes(range(0x50, 0x60))
    data = avro_container(json.dumps(schema).encode(), [(2, rows[0] + rows[1]), (1, rows[2])], "deflate", sync)
    return _sample("avro_events", "events.avro", data, (
        ("avro.codec", "deflate"), ("avro.record_count", 3), ("avro.block_count", 2), ("avro.schema_name", "Event"),
        ("avro.schema_namespace", "corp.audit"), ("avro.field_names", ["id", "user", "action"]),
        ("avro.field_count", 3), ("avro.sync_marker_hex", sync.hex())))


def parquet_rows():
    names = [b"ada", b"bob", b"grace"]
    data = parquet_plain([(b"id", 2, struct.pack("<3q", 10, 20, 30)),
                          (b"name", 6, b"".join(struct.pack("<I", len(n)) + n for n in names))],
                         3, {b"owner": b"forensics team"}, b"corpus-writer version 1.0")
    return _sample("parquet_rows", "rows.parquet", data, (
        ("parquet.num_rows", 3), ("parquet.created_by", "corpus-writer version 1.0"), ("parquet.version", 1),
        ("parquet.column_names", ["id", "name"]), ("parquet.column_count", 2), ("parquet.row_group_count", 1),
        ("parquet.codec", "UNCOMPRESSED"), ("parquet.metadata_keys", ["owner"])))


def tnef_winmail():
    data = tnef_stream([
        tnef_attr(1, 0x00089006, struct.pack("<I", 0x00010000)),
        tnef_attr(1, 0x00069007, struct.pack("<II", 1252, 0)),
        tnef_attr(1, 0x00078008, b"IPM.Microsoft Mail.Note\x00"),
        tnef_attr(1, 0x00018004, b"Corpus quarterly figures\x00"),
        tnef_attr(1, 0x00038005, tnef_date(2025, 3, 4, 5, 6, 7)),
        tnef_attr(2, 0x00069002, bytes(14)), tnef_attr(2, 0x00018010, b"figures.csv\x00"),
        tnef_attr(2, 0x0006800F, b"quarter,total\r\nQ1,100\r\n"),
        tnef_attr(2, 0x00069002, bytes(14)), tnef_attr(2, 0x00018010, b"notes.txt\x00"),
        tnef_attr(2, 0x0006800F, b"synthetic corpus attachment\r\n"),
    ], key=0x1234)
    return _sample("tnef_winmail", "winmail.dat", data, (
        ("tnef.subject", "Corpus quarterly figures"), ("tnef.message_class", "IPM.Microsoft Mail.Note"),
        ("tnef.date_sent", "2025-03-04T05:06:07"), ("tnef.key", 0x1234), ("tnef.oem_codepage", 1252),
        ("tnef.attachment_count", 2), ("tnef.attachment_names", ["figures.csv", "notes.txt"])))


def jxl_container():
    stream = JXL_HEAD_100X50 + bytes(44)
    data = (JXL_SIGNATURE + jxl_box(b"ftyp", b"jxl \x00\x00\x00\x00jxl ") + jxl_box(b"jxll", b"\x0a")
            + jxl_box(b"Exif", b"\x00\x00\x00\x00II*\x00synthetic") + jxl_box(b"jxlc", stream))
    return _sample("jxl_container", "picture.jxl", data, (
        ("jxl.width", 100), ("jxl.height", 50), ("jxl.is_container", True), ("jxl.level", 10),
        ("jxl.box_types", ["JXL ", "ftyp", "jxll", "Exif", "jxlc"]), ("jxl.codestream_size_bytes", len(stream))))


def jxl_codestream():
    data = JXL_HEAD_40X30 + bytes(60)
    return _sample("jxl_codestream", "bare.jxl", data, (
        ("jxl.width", 40), ("jxl.height", 30), ("jxl.is_container", False), ("jxl.bits_per_sample", 8),
        ("jxl.codestream_size_bytes", len(data))))


def tflite_keywords():
    data = tflite_model(
        description=b"corpus keyword spotter", metadata=[(b"min_runtime_version", b"1.14.0")],
        tensors=[(b"input", [1, 4], 0, b""), (b"dense/kernel", [4], 0, struct.pack("<4f", 0.5, -1.25, 3.0, 8.0)),
                 (b"output", [1, 4], 0, b"")],
        opcodes=[(9, None), (32, b"CorpusOp")], operators=[(0, [0, 1], [2], None), (1, [2], [2], None)])
    return _sample("tflite_keywords", "keywords.tflite", data, (
        ("tflite.version", 3), ("tflite.description", "corpus keyword spotter"), ("tflite.subgraph_count", 1),
        ("tflite.tensor_count", 3), ("tflite.tensor_names", ["input", "dense/kernel", "output"]),
        ("tflite.operator_codes", ["FULLY_CONNECTED", "CorpusOp"]), ("tflite.metadata_names", ["min_runtime_version"]),
        ("tflite.buffer_count", 3)))


def coreml_classifier():
    data = coreml_model(
        spec_version=5, inputs=[("image", "a picture", 4)], outputs=[("label", "the class", 3), ("scores", "", 6)],
        predicted="label", metadata={"short_description": "Corpus leaf classifier", "version": "2.1",
                                     "author": "Ada Example", "license": "MIT"},
        user_defined={"note": "trained offline"}, model_field=500)
    return _sample("coreml_classifier", "Classifier.mlmodel", data, (
        ("coreml.specification_version", 5), ("coreml.model_type", "neuralNetwork"), ("coreml.author", "Ada Example"),
        ("coreml.license", "MIT"), ("coreml.short_description", "Corpus leaf classifier"),
        ("coreml.version_string", "2.1"), ("coreml.input_names", ["image"]),
        ("coreml.output_names", ["label", "scores"]), ("coreml.user_defined_keys", ["note"])))


def thrift_call():
    data = thrift_message(b"getUser", 1, 7, [(1, 42), (2, b"ada"), (3, True)])
    return _sample("thrift_call", "getUser.thriftbin", data, (
        ("thrift.method_name", "getUser"), ("thrift.message_type", "call"), ("thrift.sequence_id", 7),
        ("thrift.protocol", "binary"), ("thrift.field_count", 3), ("thrift.field_types", ["i32", "binary", "bool"])))


SAMPLES = {f.__name__: f for f in (avro_events, parquet_rows, tnef_winmail, jxl_container, jxl_codestream, thrift_call,
                                   tflite_keywords, coreml_classifier)}
