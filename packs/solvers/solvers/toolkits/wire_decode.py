#!/usr/bin/env python3
"""Toolkit wire_decode: a schema-less protobuf / CBOR / MessagePack / BSON wire decoder
(gap-analysis ticket C3, docs/retro/ctf-solver-gap-analysis.md; built 2026-10-23). Offline,
stdlib only (no cbor2/msgpack/bson needed): every format here is self-describing on the wire.

It reads the STRUCTURE of a serialized blob with no schema:
  protobuf   field numbers, wire types and their values (varint, 64-bit, length-delimited, 32-bit);
             a length-delimited field is reported as a nested message, a UTF-8 string, or raw bytes
  cbor       the RFC 8949 value tree (maps, arrays, ints, strings, bytes, bool/null/float)
  msgpack    the MessagePack value tree
  bson       a BSON document (the int32 length prefix and 0x00 terminator make it the least
             ambiguous of the four)

HARD RULES (AGENTS.md "New categories", "Uncertain answers"):
  - NEVER-GUESS. Field numbers, wire types, lengths and a scalar value read at a named field/key
    are DETERMINISTIC, so a structural value the question asks for is plain-ELIGIBLE: offered as
    labels.pick(key, options) of its renderings, which tools/verify.py probes on the untimed base
    and the ledger answers plain once judged. A SEMANTIC field NAME has no schema here and is
    unsure/None. A buffer that does not decode cleanly (not fully consumed, an invalid tag) is None
    for every question - never a partial guess.
  - A protobuf length-delimited field is ambiguous (string vs bytes vs sub-message): its string
    reading is offered unsure, never plain by itself.
  - Bounded: MAX_DEPTH deep, MAX_ITEMS nodes, MAX_FILE bytes; a decode that raises yields no fact.

Keys: `wire_decode.<field>/<shape>` (solvers/common/labels.py TOOLKIT_PREFIXES knows the prefix).
"""
import base64
import json
import math
import re
import struct
import sys
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
if __name__ == "__main__" and sys.path and Path(sys.path[0] or ".").resolve() == HERE:
    sys.path.pop(0)
if str(COMMON) not in sys.path:
    sys.path.insert(1, str(COMMON))
import labels    # noqa: E402
import triage    # noqa: E402

KEY = "wire_decode"
ARROW = triage.ARROW
MAX_FILE = 16 * 1024 * 1024
MAX_DEPTH = 32
MAX_ITEMS = 200000
MAX_GRPC_FRAMES = 100000


class _WireError(ValueError):
    pass


# ---------------------------------------------------------------------------- protobuf (schema-less)

_WT_NAME = {0: "varint", 1: "fixed64", 2: "length_delimited", 5: "fixed32"}


def _read_varint(data, i, end):
    shift, val, start = 0, 0, i
    while i < end:
        b = data[i]
        val |= (b & 0x7F) << shift
        i += 1
        if not b & 0x80:
            if val >> 64:                      # a varint may not exceed the unsigned 64-bit range
                raise _WireError("varint exceeds 64-bit range")
            return val, i
        shift += 7
        if shift > 70:
            raise _WireError("varint too long")
    raise _WireError("truncated varint")


def decode_protobuf(data: bytes, depth: int = 0, _budget=None) -> list:
    """[{field, wire_type, wire_name, value}] of a protobuf message that consumes data exactly.
    Raises _WireError on any malformed or not-fully-consumed input (never a partial read)."""
    if depth > MAX_DEPTH:
        raise _WireError("too deep")
    if _budget is None:
        _budget = [MAX_ITEMS]
    out, i, end = [], 0, len(data)
    while i < end:
        if _budget[0] <= 0:
            raise _WireError("too many fields")
        _budget[0] -= 1
        key, i = _read_varint(data, i, end)
        field, wt = key >> 3, key & 0x07
        if field == 0 or wt in (3, 4) or wt in (6, 7):      # field 0 invalid; groups deprecated; 6/7 reserved
            raise _WireError(f"bad tag field={field} wire={wt}")
        if wt == 0:
            v, i = _read_varint(data, i, end)
            entry = {"field": field, "wire_type": 0, "wire_name": "varint", "value": v}
        elif wt == 1:
            if i + 8 > end:
                raise _WireError("truncated fixed64")
            entry = {"field": field, "wire_type": 1, "wire_name": "fixed64",
                     "value": struct.unpack_from("<Q", data, i)[0]}
            i += 8
        elif wt == 5:
            if i + 4 > end:
                raise _WireError("truncated fixed32")
            entry = {"field": field, "wire_type": 5, "wire_name": "fixed32",
                     "value": struct.unpack_from("<I", data, i)[0]}
            i += 4
        else:                                               # wt == 2
            ln, i = _read_varint(data, i, end)
            if ln > end - i:
                raise _WireError("length past end")
            raw = data[i:i + ln]
            i += ln
            entry = {"field": field, "wire_type": 2, "wire_name": "length_delimited",
                     "value": _ld_value(raw, depth, _budget)}
        out.append(entry)
    return out


def _ld_value(raw: bytes, depth: int, budget):
    """A length-delimited protobuf value: a sub-message if it cleanly re-parses, else a UTF-8
    string if valid, else raw bytes. The three readings are kept so a question can be answered
    from whichever it asks for (string vs bytes vs message)."""
    v = {"len": len(raw)}
    try:
        v["string"] = raw.decode("utf-8")
        if not v["string"].isprintable() and not all(c in "\r\n\t" or c.isprintable() for c in v["string"]):
            v.pop("string", None)
    except UnicodeDecodeError:
        pass
    if raw:
        try:
            v["message"] = decode_protobuf(raw, depth + 1, budget)
        except _WireError:
            pass
    v["hex"] = raw.hex()
    return v


def _protobuf_fields_ok(fields) -> bool:
    """A sanity gate so random bytes are not read as a protobuf: at least one field, every field
    number small-ish and every length-delimited value either a printable string or a sub-message."""
    if not fields:
        return False
    for f in fields:
        if f["field"] > 536870911:
            return False
        if f["wire_type"] == 2 and isinstance(f["value"], dict):
            v = f["value"]
            if v["len"] and "string" not in v and "message" not in v and v["len"] > 2:
                # a non-empty length-delimited field that is neither text nor a sub-message: suspicious
                return False
    return True


# ---------------------------------------------------------------------------- gRPC / gRPC-Web framing

def _bounded_inflate(data: bytes, compression: str) -> bytes:
    if compression not in ("gzip", "deflate"):
        raise _WireError("unsupported gRPC compression")
    try:
        obj = zlib.decompressobj(31 if compression == "gzip" else zlib.MAX_WBITS)
        out = obj.decompress(data, MAX_FILE + 1)
        remaining = MAX_FILE + 1 - len(out)
        if remaining <= 0:
            raise _WireError("decompressed gRPC message exceeds cap")
        out += obj.flush(remaining)
    except zlib.error as exc:
        raise _WireError("invalid compressed gRPC message") from exc
    if not obj.eof or obj.unused_data or len(out) > MAX_FILE:
        raise _WireError("invalid or over-limit compressed gRPC message")
    return out


def _grpc_trailers(data: bytes) -> dict[str, list[str]]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise _WireError("gRPC-Web trailers are not ASCII") from exc
    headers: dict[str, list[str]] = {}
    for line in text.replace("\r\n", "\n").split("\n"):
        if not line:
            continue
        if ":" not in line:
            raise _WireError("malformed gRPC-Web trailer line")
        name, value = line.split(":", 1)
        name = name.strip().lower()
        if not re.fullmatch(r"[a-z0-9!#$%&'*+.^_`|~-]{1,128}", name):
            raise _WireError("invalid gRPC-Web trailer name")
        headers.setdefault(name, []).append(value.strip()[:8192])
    return headers


def decode_grpc_frames(data: bytes, *, grpc_web: bool = False, base64_encoded: bool = False,
                       compression: str | None = None) -> list[dict]:
    """Decode a complete gRPC or gRPC-Web framed byte stream.

    Each uncompressed message is also passed through the schema-less protobuf
    reader.  Compressed messages are inflated only when the caller supplies the
    captured ``grpc-encoding`` value.  A malformed/trailing frame rejects the
    whole stream rather than returning a misleading prefix.
    """
    if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_FILE:
        raise _WireError("gRPC stream exceeds cap")
    raw = bytes(data)
    if base64_encoded:
        compact = re.sub(rb"\s+", b"", raw)
        if not compact or not re.fullmatch(rb"[A-Za-z0-9+/]*={0,2}", compact):
            raise _WireError("invalid gRPC-Web base64")
        try:
            raw = base64.b64decode(compact, validate=True)
        except Exception as exc:
            raise _WireError("invalid gRPC-Web base64") from exc
        if len(raw) > MAX_FILE:
            raise _WireError("decoded gRPC-Web stream exceeds cap")
    rows, offset = [], 0
    while offset < len(raw):
        if len(rows) >= MAX_GRPC_FRAMES or offset + 5 > len(raw):
            raise _WireError("truncated or over-count gRPC stream")
        flag, length = raw[offset], int.from_bytes(raw[offset + 1:offset + 5], "big")
        offset += 5
        allowed = (0, 1, 0x80, 0x81) if grpc_web else (0, 1)
        if flag not in allowed or length > MAX_FILE or offset + length > len(raw):
            raise _WireError("invalid gRPC frame flag/length")
        body, offset = raw[offset:offset + length], offset + length
        trailers = bool(flag & 0x80)
        compressed = bool(flag & 1)
        row = {"index": len(rows), "length": length, "compressed": compressed,
               "trailers": trailers, "raw": body}
        if trailers:
            row["headers"] = _grpc_trailers(body)
        else:
            message = _bounded_inflate(body, compression) if compressed and compression else body
            row["message"] = message
            if compressed and compression is None:
                row["protobuf"] = None
                row["note"] = "compressed body retained; supply grpc-encoding to inflate"
            else:
                try:
                    fields = decode_protobuf(message)
                    row["protobuf"] = fields if _protobuf_fields_ok(fields) else None
                except (_WireError, struct.error, ValueError, IndexError):
                    row["protobuf"] = None
        rows.append(row)
    if not rows:
        raise _WireError("empty gRPC stream")
    return rows


# ---------------------------------------------------------------------------- CBOR (RFC 8949)

def decode_cbor(data: bytes):
    """The CBOR value of data, which must be consumed exactly. Raises _WireError otherwise."""
    val, i = _cbor_item(data, 0, 0, [MAX_ITEMS])
    if i != len(data):
        raise _WireError("trailing bytes after CBOR value")
    return val


def _cbor_item(data, i, depth, budget):
    if depth > MAX_DEPTH:
        raise _WireError("too deep")
    if budget[0] <= 0:
        raise _WireError("too many items")
    budget[0] -= 1
    if i >= len(data):
        raise _WireError("truncated")
    ib = data[i]
    mt, ai = ib >> 5, ib & 0x1F
    i += 1
    if ai < 24:
        arg = ai
    elif ai == 24:
        if i + 1 > len(data):
            raise _WireError("truncated head")
        arg, i = data[i], i + 1
    elif ai == 25:
        if i + 2 > len(data):
            raise _WireError("truncated head")
        arg, i = struct.unpack_from(">H", data, i)[0], i + 2
    elif ai == 26:
        if i + 4 > len(data):
            raise _WireError("truncated head")
        arg, i = struct.unpack_from(">I", data, i)[0], i + 4
    elif ai == 27:
        if i + 8 > len(data):
            raise _WireError("truncated head")
        arg, i = struct.unpack_from(">Q", data, i)[0], i + 8
    elif ai == 31:
        arg = None                                          # indefinite length
    else:
        raise _WireError("reserved additional-info")
    if ai == 31 and mt not in (2, 3, 4, 5):                 # indefinite only for strings/arrays/maps
        raise _WireError("indefinite length not allowed for this major type")
    if i > len(data):
        raise _WireError("truncated head")
    if mt == 0:
        return arg, i
    if mt == 1:
        return -1 - arg, i
    if mt == 2 or mt == 3:                                  # byte / text string
        if arg is None:
            chunks, i = _cbor_indefinite(data, i, depth, budget, mt)
            raw = b"".join(chunks)
        else:
            if arg > len(data) - i:
                raise _WireError("string past end")
            raw, i = data[i:i + arg], i + arg
        if mt == 3:
            try:
                return raw.decode("utf-8"), i
            except UnicodeDecodeError as exc:
                raise _WireError("invalid UTF-8 text string") from exc
        return raw, i
    if mt == 4:                                             # array
        out = []
        if arg is None:
            while i < len(data) and data[i] != 0xFF:
                v, i = _cbor_item(data, i, depth + 1, budget)
                out.append(v)
            i += 1
        else:
            for _ in range(arg):
                v, i = _cbor_item(data, i, depth + 1, budget)
                out.append(v)
        return out, i
    if mt == 5:                                             # map
        out = {}
        if arg is None:
            while i < len(data) and data[i] != 0xFF:
                k, i = _cbor_item(data, i, depth + 1, budget)
                v, i = _cbor_item(data, i, depth + 1, budget)
                out[_hashable(k)] = v
            i += 1
        else:
            for _ in range(arg):
                k, i = _cbor_item(data, i, depth + 1, budget)
                v, i = _cbor_item(data, i, depth + 1, budget)
                out[_hashable(k)] = v
        return out, i
    if mt == 6:                                             # tagged value
        v, i = _cbor_item(data, i, depth + 1, budget)
        return v, i
    if mt == 7:                                             # simple / float
        if ai == 20:
            return False, i
        if ai == 21:
            return True, i
        if ai == 22:
            return None, i
        if ai == 23:
            return None, i
        if ai == 25:
            return _half_float(arg), i
        if ai == 26:
            return struct.unpack(">f", struct.pack(">I", arg))[0], i
        if ai == 27:
            return struct.unpack(">d", struct.pack(">Q", arg))[0], i
        return arg, i
    raise _WireError("unknown major type")


def _cbor_indefinite(data, i, depth, budget, mt):
    chunks = []
    while i < len(data) and data[i] != 0xFF:
        # Each chunk must be a definite-length string of the SAME major type (RFC 8949 S3.2.3).
        if (data[i] >> 5) != mt or (data[i] & 0x1F) == 31:
            raise _WireError("indefinite string chunk has the wrong major type")
        v, i = _cbor_item(data, i, depth + 1, budget)
        chunks.append(v if isinstance(v, bytes) else v.encode("utf-8"))
    if i >= len(data):
        raise _WireError("unterminated indefinite string")
    return chunks, i + 1


def _half_float(x):
    exp, mant = (x >> 10) & 0x1F, x & 0x3FF
    sign = -1 if x & 0x8000 else 1
    if exp == 0:
        return sign * mant * 2 ** -24
    if exp == 31:
        return math.inf * sign if mant == 0 else math.nan
    return sign * (1 + mant / 1024) * 2 ** (exp - 15)


def _hashable(k):
    return k if isinstance(k, (str, int, bytes, bool)) else json.dumps(k, default=str, sort_keys=True)


# ---------------------------------------------------------------------------- MessagePack

def decode_msgpack(data: bytes):
    val, i = _mp_item(data, 0, 0, [MAX_ITEMS])
    if i != len(data):
        raise _WireError("trailing bytes after MessagePack value")
    return val


def _mp_item(data, i, depth, budget):
    if depth > MAX_DEPTH:
        raise _WireError("too deep")
    if budget[0] <= 0:
        raise _WireError("too many items")
    budget[0] -= 1
    if i >= len(data):
        raise _WireError("truncated")
    b = data[i]
    i += 1
    if b <= 0x7F:
        return b, i
    if b >= 0xE0:
        return b - 0x100, i
    if 0x80 <= b <= 0x8F:
        return _mp_map(data, i, b & 0x0F, depth, budget)
    if 0x90 <= b <= 0x9F:
        return _mp_array(data, i, b & 0x0F, depth, budget)
    if 0xA0 <= b <= 0xBF:
        return _mp_str(data, i, b & 0x1F)
    if b == 0xC0:
        return None, i
    if b == 0xC2:
        return False, i
    if b == 0xC3:
        return True, i
    if b in (0xC4, 0xC5, 0xC6):                             # bin 8/16/32
        n, i = _mp_len(data, i, {0xC4: 1, 0xC5: 2, 0xC6: 4}[b])
        return _mp_bytes(data, i, n)
    if b in (0xCA, 0xCB):                                   # float 32/64
        size = 4 if b == 0xCA else 8
        if i + size > len(data):
            raise _WireError("truncated float")
        if b == 0xCA:
            return struct.unpack_from(">f", data, i)[0], i + 4
        return struct.unpack_from(">d", data, i)[0], i + 8
    if b in (0xCC, 0xCD, 0xCE, 0xCF):                       # uint 8/16/32/64
        size = {0xCC: 1, 0xCD: 2, 0xCE: 4, 0xCF: 8}[b]
        if i + size > len(data):
            raise _WireError("truncated uint")
        return int.from_bytes(data[i:i + size], "big"), i + size
    if b in (0xD0, 0xD1, 0xD2, 0xD3):                       # int 8/16/32/64
        size = {0xD0: 1, 0xD1: 2, 0xD2: 4, 0xD3: 8}[b]
        if i + size > len(data):
            raise _WireError("truncated int")
        return int.from_bytes(data[i:i + size], "big", signed=True), i + size
    if b in (0xD9, 0xDA, 0xDB):                             # str 8/16/32
        n, i = _mp_len(data, i, {0xD9: 1, 0xDA: 2, 0xDB: 4}[b])
        return _mp_str(data, i, n)
    if b in (0xDC, 0xDD):                                   # array 16/32
        n, i = _mp_len(data, i, 2 if b == 0xDC else 4)
        return _mp_array(data, i, n, depth, budget)
    if b in (0xDE, 0xDF):                                   # map 16/32
        n, i = _mp_len(data, i, 2 if b == 0xDE else 4)
        return _mp_map(data, i, n, depth, budget)
    if b in (0xD4, 0xD5, 0xD6, 0xD7, 0xD8):                 # fixext
        size = {0xD4: 1, 0xD5: 2, 0xD6: 4, 0xD7: 8, 0xD8: 16}[b]
        if i + 1 + size > len(data):
            raise _WireError("truncated fixext")
        return {"ext": data[i], "data": data[i + 1:i + 1 + size].hex()}, i + 1 + size
    raise _WireError(f"unknown msgpack byte 0x{b:02x}")


def _mp_len(data, i, size):
    if i + size > len(data):
        raise _WireError("truncated length")
    return int.from_bytes(data[i:i + size], "big"), i + size


def _mp_str(data, i, n):
    if i + n > len(data):
        raise _WireError("str past end")
    try:
        return data[i:i + n].decode("utf-8"), i + n
    except UnicodeDecodeError as exc:
        raise _WireError("invalid UTF-8 msgpack str") from exc


def _mp_bytes(data, i, n):
    if i + n > len(data):
        raise _WireError("bin past end")
    return data[i:i + n], i + n


def _mp_array(data, i, n, depth, budget):
    out = []
    for _ in range(n):
        v, i = _mp_item(data, i, depth + 1, budget)
        out.append(v)
    return out, i


def _mp_map(data, i, n, depth, budget):
    out = {}
    for _ in range(n):
        k, i = _mp_item(data, i, depth + 1, budget)
        v, i = _mp_item(data, i, depth + 1, budget)
        out[_hashable(k)] = v
    return out, i


# ---------------------------------------------------------------------------- BSON

_BSON_TYPE = {0x01: "double", 0x02: "string", 0x03: "document", 0x04: "array", 0x05: "binary",
              0x07: "objectid", 0x08: "bool", 0x09: "datetime", 0x0A: "null", 0x10: "int32",
              0x11: "timestamp", 0x12: "int64", 0x13: "decimal128"}


def decode_bson(data: bytes):
    if len(data) < 5:
        raise _WireError("too short for BSON")
    total = struct.unpack_from("<i", data, 0)[0]
    if total != len(data):
        raise _WireError("BSON length does not match the buffer")
    doc, end = _bson_doc(data, 0, 0, [MAX_ITEMS])
    return doc


def _bson_doc(data, start, depth, budget):
    if depth > MAX_DEPTH:
        raise _WireError("too deep")
    total = struct.unpack_from("<i", data, start)[0]
    if total < 5 or start + total > len(data):
        raise _WireError("bad document length")
    i, end = start + 4, start + total
    out = {}
    while i < end - 1:
        if budget[0] <= 0:
            raise _WireError("too many items")
        budget[0] -= 1
        etype = data[i]
        i += 1
        key_end = data.index(0, i)
        name = data[i:key_end].decode("utf-8", "replace")
        i = key_end + 1
        val, i = _bson_value(data, i, etype, depth, budget)
        out[name] = val
    if data[end - 1] != 0:
        raise _WireError("document not 0-terminated")
    return out, end


def _bson_value(data, i, etype, depth, budget):
    if etype == 0x01:
        return struct.unpack_from("<d", data, i)[0], i + 8
    if etype in (0x02, 0x0D, 0x0E):                         # string / code / symbol
        n = struct.unpack_from("<i", data, i)[0]
        if n < 1 or i + 4 + n > len(data):                 # the declared length must stay inside the buffer
            raise _WireError("string length past buffer")
        s = data[i + 4:i + 4 + n - 1].decode("utf-8", "replace")
        return s, i + 4 + n
    if etype in (0x03, 0x04):                               # embedded document / array
        sub, end = _bson_doc(data, i, depth + 1, budget)
        if etype == 0x04:
            sub = [sub[k] for k in sorted(sub, key=lambda x: int(x) if str(x).isdigit() else x)]
        return sub, end
    if etype == 0x05:                                       # binary
        n = struct.unpack_from("<i", data, i)[0]
        return {"binary_subtype": data[i + 4], "hex": data[i + 5:i + 5 + n].hex()}, i + 5 + n
    if etype == 0x07:                                       # ObjectId
        return {"objectid": data[i:i + 12].hex()}, i + 12
    if etype == 0x08:
        return bool(data[i]), i + 1
    if etype == 0x09:                                       # UTC datetime (ms)
        return {"datetime_ms": struct.unpack_from("<q", data, i)[0]}, i + 8
    if etype == 0x0A:
        return None, i
    if etype == 0x10:
        return struct.unpack_from("<i", data, i)[0], i + 4
    if etype == 0x11:                                       # timestamp
        return {"timestamp": struct.unpack_from("<Q", data, i)[0]}, i + 8
    if etype == 0x12:
        return struct.unpack_from("<q", data, i)[0], i + 8
    raise _WireError(f"unsupported BSON element type 0x{etype:02x}")


# ---------------------------------------------------------------------------- what a blob is

def classify(data: bytes) -> dict:
    """{format, value|fields} for a blob that decodes cleanly (consumes every byte), else None.
    BSON first (least ambiguous), then CBOR, MessagePack, protobuf - the first clean, non-trivial
    decode wins; a blob several formats could claim is only reported when exactly one is clean."""
    if not isinstance(data, (bytes, bytearray)) or not data or len(data) > MAX_FILE:
        return None
    data = bytes(data)
    out = {}
    if len(data) >= 5 and struct.unpack_from("<i", data, 0)[0] == len(data):
        try:
            doc = decode_bson(data)
            if isinstance(doc, dict) and doc:
                out["bson"] = {"format": "bson", "value": doc}
        except (_WireError, struct.error, ValueError):
            pass
    for name, fn in (("cbor", decode_cbor), ("msgpack", decode_msgpack)):
        try:
            v = fn(data)
            if isinstance(v, (dict, list)) and v:          # require a container, so a lone int is not "a format"
                out[name] = {"format": name, "value": v}
        except (_WireError, struct.error, ValueError, UnicodeDecodeError, IndexError, OverflowError):
            pass
    try:
        fields = decode_protobuf(data)
        if _protobuf_fields_ok(fields):
            out["protobuf"] = {"format": "protobuf", "fields": fields}
    except (_WireError, struct.error, ValueError, IndexError):
        pass
    if not out:
        return None
    if "bson" in out:
        return out["bson"]
    if len(out) == 1:
        return next(iter(out.values()))
    # Several formats decode cleanly: prefer a self-describing container (cbor/msgpack) over the
    # schema-less protobuf guess, but mark it ambiguous so nothing structural is claimed blindly.
    pick = out.get("cbor") or out.get("msgpack") or out.get("protobuf")
    pick = dict(pick)
    pick["ambiguous"] = sorted(out)
    return pick


# ---------------------------------------------------------------------------- signals

_WORDS = re.compile(
    r"protobuf|proto\b|protocol buffer|\bgrpc(?:-web)?\b|\bcbor\b|messagepack|message ?pack|msgpack|\bbson\b|"
    r"wire ?type|field number|field ?\d+|varint|serial(?:ized|ization|ised)|length[- ]delimited|"
    r"deserialize|decode the (?:blob|message|payload)|submessage|sub-message", re.I)


def signals(questions, files) -> float:
    """0..1: a wire blob decodes cleanly in the bytes AND the questions speak of serialization. The
    decode is byte-primary, but because CBOR/MessagePack/protobuf have no magic, a meaningful score
    needs the vocabulary too - so it never steals a pcap or a mail from the specialist toolkits and
    is 0.0 on a 64-byte blob with a generic question. BSON (self-validating) scores higher alone."""
    fmt = None
    try:
        for _n, data in triage.unique_files(files or {}):
            rep = classify(data)
            if rep:
                fmt = rep["format"]
                if fmt == "bson":
                    break
    except Exception:  # noqa: BLE001
        fmt = None
    if not fmt:
        return 0.0
    hits = set()
    for q in questions or []:
        f = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
        text = " ".join(str(x or "") for x in (q.get("question"), q.get("answer_id") or q.get("id"), f.get("syntax")))
        hits |= {m.group().lower() for m in _WORDS.finditer(text)}
    base = 0.5 if fmt == "bson" else 0.3
    score = base + min(0.45, 0.12 * len(hits))
    return round(min(1.0, score), 2)


# ---------------------------------------------------------------------------- answers (never-guess)

def _scalar(v):
    """A protobuf/cbor/msgpack/bson value that can be answered as a single structural value, else None.
    A length-delimited protobuf value yields its string reading (unsure); bytes/messages do not."""
    if isinstance(v, bool):
        return ("bool", v)
    if isinstance(v, int):
        return ("int", v)
    if isinstance(v, float):
        return ("float", v)
    if isinstance(v, str):
        return ("str", v)
    if isinstance(v, dict) and set(v) <= {"len", "string", "message", "hex"}:   # a protobuf LD value
        if "string" in v and "message" not in v:
            return ("str", v["string"])
    return None


def _int_options(n):
    hx = format(n if n >= 0 else n & 0xFFFFFFFFFFFFFFFF, "x")
    return [("decimal", str(n)), ("hex", hx), ("hex_0x", "0x" + hx)]


def _value_options(kind, v):
    if kind == "int":
        return _int_options(v)
    if kind == "bool":
        return [("true_false", "true" if v else "false"), ("yes_no", "yes" if v else "no"),
                ("title", "True" if v else "False"), ("1_0", "1" if v else "0")]
    if kind == "float":
        return [("raw", repr(v)), ("plain", ("%g" % v))]
    return [("raw", str(v))]


def _pick(field, shape, options):
    opts, seen = [], set()
    for name, value in options:
        value = str(value)
        if (name, value) not in seen:
            seen.add((name, value))
            opts.append((name, value))
    if not opts:
        return None
    try:
        return labels.pick(f"{KEY}.{field}/{shape}", opts)
    except ValueError:
        return None


def _file_for(q, reps):
    member = q.get("member") or (str(q.get("artifact") or "").split(ARROW)[-1] if q.get("artifact") else "")
    base = Path(str(member)).name if member else ""
    if base:
        hit = [r for r in reps if Path(r[0]).name == base or r[0].split(ARROW)[-1] == member or r[0] == member]
        if len(hit) == 1:
            return hit[0][1]
        if hit:
            return None
    return reps[0][1] if len(reps) == 1 else None


def _map_of(rep):
    """The top-level map of a cbor/msgpack/bson decode, else None."""
    v = rep.get("value")
    return v if isinstance(v, dict) else None


def _answer_one(q, rep):
    text = str(q.get("question") or "")
    aid = str(q.get("answer_id") or q.get("id") or q.get("qid") or "")
    t = (text + " " + aid).lower()
    fmt = rep["format"]
    shape = fmt + ("+ambiguous" if rep.get("ambiguous") else "")

    def has(*words):
        return any(w in t for w in words)

    if has("flag"):
        return None
    # How many fields / keys (a deterministic structural count).
    if has("how many field", "number of field", "field count", "count of field", "how many key",
           "number of key", "number of entries", "how many entries", "number of element", "how many element"):
        if fmt == "protobuf":
            n = len(rep["fields"])
        else:
            m = _map_of(rep)
            if m is None:
                v = rep.get("value")
                n = len(v) if isinstance(v, list) else None
            else:
                n = len(m)
        return _pick("count", shape, [("decimal", n)]) if n is not None else None
    # Protobuf: the value at a named field number.
    if fmt == "protobuf":
        m = re.search(r"field\s*(?:number\s*|#\s*|no\.?\s*)?(\d+)", t) or re.search(r"\bfield[_\s]?(\d+)\b", aid)
        if m:
            num = int(m.group(1))
            matches = [f for f in rep["fields"] if f["field"] == num]
            if len(matches) == 1:
                sc = _scalar(matches[0]["value"])
                if sc is not None:
                    if has("string", "text", "utf") and sc[0] != "str":
                        return None
                    return _pick(f"field{num}", shape, _value_options(sc[0], sc[1]))
                if has("wire type", "type of field", "wiretype"):
                    return _pick(f"field{num}_wiretype", shape,
                                 [("name", matches[0]["wire_name"]), ("number", matches[0]["wire_type"])])
            return None
        return None
    # CBOR / MessagePack / BSON: the value at a named key.
    m = _map_of(rep)
    if m is not None:
        key_names = re.findall(r"['\"]([A-Za-z0-9_.\-]{1,64})['\"]", text)
        key_names += re.findall(r"(?:key|field|value of|the)\s+([A-Za-z_][A-Za-z0-9_]{0,63})\b", text)
        for kn in key_names:
            if kn in m:
                sc = _scalar(m[kn])
                if sc is not None:
                    return _pick(f"key_{_slug(kn)}", shape, _value_options(sc[0], sc[1]))
                return None
    return None


def _slug(s):
    return re.sub(r"[^a-z0-9]+", "_", str(s).lower()).strip("_")[:40]


def solve_set(questions, files, ctx) -> dict:
    reps = reports(files)
    out = {}
    for q in questions or []:
        qid = q.get("qid") or q.get("id") or q.get("answer_id")
        if qid is None:
            continue
        rep = _file_for(q, reps)
        try:
            out[qid] = None if rep is None else _answer_one(q, rep)
        except Exception:  # noqa: BLE001 - a value that cannot be read is no answer
            out[qid] = None
    if isinstance(ctx, dict) and isinstance(ctx.get("partial"), dict):
        ctx["partial"].update({k: v for k, v in out.items() if v is not None})
    return out


def reports(files) -> list:
    out = []
    try:
        for name, data in triage.unique_files(files or {}):
            try:
                rep = classify(data)
            except Exception:  # noqa: BLE001
                rep = None
            if rep is not None:
                out.append((name, rep))
    except Exception:  # noqa: BLE001
        return []
    return out


# ---------------------------------------------------------------------------- CLI (offline triage)

def _summary(rep: dict) -> str:
    if rep["format"] in ("grpc", "grpc-web"):
        return f"{rep['format']}: {len(rep.get('frames', []))} frame(s)"
    if rep["format"] == "protobuf":
        return "protobuf: " + ", ".join(f"#{f['field']}={f['wire_name']}" for f in rep["fields"][:20])
    v = rep.get("value")
    if isinstance(v, dict):
        return rep["format"] + " map: keys " + ", ".join(str(k) for k in list(v)[:20])
    if isinstance(v, list):
        return rep["format"] + f" array of {len(v)}"
    return rep["format"] + ": " + str(v)[:80]


def main(argv) -> int:
    as_json = "--json" in argv
    as_grpc = "--grpc" in argv or "--grpc-web" in argv
    grpc_web = "--grpc-web" in argv
    grpc_b64 = "--base64" in argv
    compression = next((a.split("=", 1)[1] for a in argv if a.startswith("--compression=")), None)
    usage = ("usage: wire_decode.py <file>... [--json] [--grpc|--grpc-web] [--base64] "
             "[--compression=gzip|deflate]   (offline; structural facts only)")
    if "--help" in argv or "-h" in argv:
        print(usage)
        return 0
    paths = [a for a in argv if not a.startswith("--")]
    if not paths:
        print(usage, file=sys.stderr)
        return 2
    out = []
    for p in paths:
        try:
            data = Path(p).read_bytes()
        except OSError as e:
            print(f"wire_decode.py: {p}: {e}", file=sys.stderr)
            continue
        if as_grpc:
            try:
                frames = decode_grpc_frames(data, grpc_web=grpc_web, base64_encoded=grpc_b64,
                                            compression=compression)
                rep = {"format": "grpc-web" if grpc_web else "grpc", "frames": frames}
            except (_WireError, ValueError, struct.error):
                rep = None
        else:
            rep = classify(data)
        out.append({"file": p, "format": rep["format"] if rep else None,
                    "report": rep, "bytes": len(data)})
    if as_json:
        print(json.dumps(out, indent=1, default=lambda o: o.hex() if isinstance(o, (bytes, bytearray)) else str(o)))
        return 0
    for row in out:
        if not row["format"]:
            print(f"- {row['file']}: no requested wire structure recognised ({row['bytes']} bytes)")
            continue
        print(f"# {row['file']}  [{row['format']}]  {_summary(row['report'])}")
        if row["report"].get("ambiguous"):
            print("  ambiguous: also decodes as " + ", ".join(row["report"]["ambiguous"]))
        print("  schema-less: structural values are plain-eligible via labels.pick; "
              "semantic field names and the flag are unsure/None.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
