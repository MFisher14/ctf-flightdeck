#!/usr/bin/env python3
"""Toolkit serial_decode: a structural reader for LANGUAGE-NATIVE serialization blobs delivered as a
forensics artifact (not a live web body) -- the gap beyond deser_detect (which only flags) and
wire_decode (protobuf / CBOR / MessagePack / BSON). Offline, stdlib only; NOTHING is ever
instantiated or executed (the deser_detect never-execute discipline): the bytes are walked as a
grammar and only names, structure and primitive values are read out.

It reads the STRUCTURE of a serialized blob with no schema:
  java    Java serialization stream (magic AC ED 00 05): the TC_OBJECT / TC_CLASSDESC / TC_STRING /
          TC_ARRAY grammar with its handle table -> class names, field names, primitive and string
          field values. Streams with Externalizable-without-block-data or anything the walk cannot
          account for byte-for-byte are declined whole (None).
  php     PHP serialize() string (N; b: i: d: s: a: O: C: r: R:): the grammar -> arrays, objects
          (class name + property names/values), scalars. Private/protected property names keep their
          NUL mangling and are matched with and without it.
  ruby    Ruby Marshal 4.8 (magic 04 08): nil/true/false, Fixnum/Bignum, Float, String, Symbol,
          Array, Hash, and plain objects (`o`: class symbol + instance variables), with the symbol
          and object link tables -> class names, ivar names/values, hash and array contents.

HARD RULES (AGENTS.md "New categories", "Uncertain answers"):
  - NEVER-GUESS, NEVER-EXECUTE. A class name, a field/ivar/property name, a count and a primitive
    value read at a named member ARE deterministic byte facts, so a structural value a question asks
    for is plain-ELIGIBLE: it is offered as labels.pick(key, options) of its renderings, which
    tools/verify.py probes on the untimed base and the ledger answers plain once the judge accepts a
    name. A SEMANTIC meaning (what a field is FOR) has no schema here and is unsure/None.
  - A blob is only read when it decodes cleanly AND consumes every byte exactly (a Java stream may
    hold several top-level objects back to back; the whole buffer must be accounted for). A buffer
    that does not fully parse yields no fact for any question - never a partial guess.
  - A container value (an array, a map, a nested object) is never squeezed into a scalar answer; a
    question that names it is None here.
  - The flag is never answered. Text inside a blob that addresses the solver is data, not an order.
  - Bounded: MAX_DEPTH deep, MAX_ITEMS nodes, MAX_FILE bytes; a decode that raises yields no fact.

Keys: `serial_decode.<field>/<format>` (solvers/common/labels.py TOOLKIT_PREFIXES knows the prefix).
"""
import json
import re
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
if __name__ == "__main__" and sys.path and Path(sys.path[0] or ".").resolve() == HERE:
    sys.path.pop(0)
if str(COMMON) not in sys.path:
    sys.path.insert(1, str(COMMON))
import labels    # noqa: E402
import triage    # noqa: E402

KEY = "serial_decode"
ARROW = triage.ARROW
MAX_FILE = 16 * 1024 * 1024
MAX_DEPTH = 64
MAX_ITEMS = 200000


class _SerialError(ValueError):
    """A blob that is not this format, or not well-formed, or not fully consumed."""


# ============================================================================ node model
# Every decoded value is one of these small tagged dicts, so the answer code is one shape across the
# three formats. Leaves carry "v"; containers carry their children; nothing is a live object.
#   {"k": "null"} {"k": "bool","v":bool} {"k": "int","v":int} {"k": "float","v":float}
#   {"k": "str","v":str}  {"k": "bytes","hex":str}  {"k": "sym","v":str}  (ruby symbol)
#   {"k": "array","items":[node,...]}
#   {"k": "map","pairs":[(keynode,node),...]}
#   {"k": "object","class":str,"fields":[(name:str, node),...]}
#   {"k": "ref","handle":int}  {"k": "class","name":str}  {"k": "enum","class":str,"value":node}

def _leaf_str(raw: bytes):
    try:
        return {"k": "str", "v": raw.decode("utf-8")}
    except UnicodeDecodeError:
        return {"k": "bytes", "hex": raw.hex()}


def _leaf_jstr(raw: bytes):
    """Java TC_STRING content is modified UTF-8 (NUL as C0 80, >U+FFFF as CESU-8 surrogate pairs)."""
    try:
        return {"k": "str", "v": _decode_mutf8(raw)}
    except _SerialError:
        return {"k": "bytes", "hex": raw.hex()}


# ============================================================================ PHP serialize()

_PHP_TOKENS = set(b"NbidsaOCrR")


def decode_php(data: bytes):
    """The node of a PHP serialize() blob that is consumed EXACTLY, else _SerialError."""
    if not data or data[0] not in _PHP_TOKENS:
        raise _SerialError("not a PHP serialize() token")
    node, i = _php_value(data, 0, 0, [MAX_ITEMS])
    if i != len(data):
        raise _SerialError("trailing bytes after PHP value")
    return node


def _php_int_token(data, i, stop):
    """Read ASCII characters up to (not past) a byte in `stop`; return (text, index after stop byte)."""
    j = i
    while j < len(data) and data[j] not in stop:
        j += 1
    if j >= len(data):
        raise _SerialError("truncated PHP number")
    try:
        return data[i:j].decode("ascii", "strict"), j + 1
    except UnicodeDecodeError as exc:
        raise _SerialError("non-ASCII in PHP number") from exc


def _safe_int(txt):
    """int() of a PHP numeric token, as _SerialError on a non-numeric or over-long string."""
    try:
        return int(txt)
    except ValueError as exc:
        raise _SerialError(f"invalid PHP integer token {txt!r}") from exc


def _php_value(data, i, depth, budget):
    if depth > MAX_DEPTH:
        raise _SerialError("too deep")
    if budget[0] <= 0:
        raise _SerialError("too many items")
    budget[0] -= 1
    if i >= len(data):
        raise _SerialError("truncated")
    t = data[i]
    if t == 0x4E:                                           # N;  null
        if data[i + 1:i + 2] != b";":
            raise _SerialError("bad null")
        return {"k": "null"}, i + 2
    if data[i + 1:i + 2] != b":":
        raise _SerialError("expected ':' after type")
    if t == 0x62:                                           # b:0; / b:1;
        v = data[i + 2:i + 3]
        if v not in (b"0", b"1") or data[i + 3:i + 4] != b";":
            raise _SerialError("bad bool")
        return {"k": "bool", "v": v == b"1"}, i + 4
    if t == 0x69:                                           # i:NUM;
        txt, j = _php_int_token(data, i + 2, b";")
        if not re.fullmatch(r"[+-]?\d+", txt):
            raise _SerialError("bad int")
        return {"k": "int", "v": _safe_int(txt)}, j
    if t == 0x64:                                           # d:NUM;
        txt, j = _php_int_token(data, i + 2, b";")
        return {"k": "float", "v": _php_float(txt)}, j
    if t == 0x73:                                           # s:LEN:"....";
        ln_txt, j = _php_int_token(data, i + 2, b":")
        ln = _safe_int(ln_txt)
        if ln < 0 or data[j:j + 1] != b'"':
            raise _SerialError("bad string head")
        start = j + 1
        end = start + ln
        if end + 1 > len(data) or data[end:end + 2] != b'";':
            raise _SerialError("string length past end or unterminated")
        return _leaf_str(data[start:end]), end + 2
    if t == 0x61:                                           # a:N:{ (key;value;)* }
        n_txt, j = _php_int_token(data, i + 2, b":")
        n = _safe_int(n_txt)
        if n < 0 or data[j:j + 1] != b"{":
            raise _SerialError("bad array head")
        j += 1
        pairs = []
        for _ in range(n):
            k, j = _php_value(data, j, depth + 1, budget)
            v, j = _php_value(data, j, depth + 1, budget)
            pairs.append((k, v))
        if data[j:j + 1] != b"}":
            raise _SerialError("array not closed")
        return {"k": "map", "pairs": pairs}, j + 1
    if t == 0x4F:                                           # O:LEN:"CLASS":N:{ (name;value;)* }
        cl_len_txt, j = _php_int_token(data, i + 2, b":")
        cl_len = _safe_int(cl_len_txt)
        if data[j:j + 1] != b'"':
            raise _SerialError("bad object class head")
        cname = data[j + 1:j + 1 + cl_len]
        j = j + 1 + cl_len
        if data[j:j + 2] != b'":':
            raise _SerialError("object class not terminated")
        j += 2
        n_txt, j = _php_int_token(data, j, b":")
        n = _safe_int(n_txt)
        if n < 0 or data[j:j + 1] != b"{":
            raise _SerialError("bad object body head")
        j += 1
        fields = []
        for _ in range(n):
            kn, j = _php_value(data, j, depth + 1, budget)
            v, j = _php_value(data, j, depth + 1, budget)
            name = kn.get("v") if kn.get("k") == "str" else None
            fields.append((name if name is not None else _node_key_text(kn), v))
        if data[j:j + 1] != b"}":
            raise _SerialError("object not closed")
        return {"k": "object", "class": _bytes_name(cname), "fields": fields}, j + 1
    if t == 0x43:                                           # C:LEN:"CLASS":DATALEN:{ raw }  (Serializable)
        cl_len_txt, j = _php_int_token(data, i + 2, b":")
        cl_len = _safe_int(cl_len_txt)
        if data[j:j + 1] != b'"':
            raise _SerialError("bad custom class head")
        cname = data[j + 1:j + 1 + cl_len]
        j = j + 1 + cl_len
        if data[j:j + 2] != b'":':
            raise _SerialError("custom class not terminated")
        j += 2
        dl_txt, j = _php_int_token(data, j, b":")
        dl = _safe_int(dl_txt)
        if dl < 0 or data[j:j + 1] != b"{":
            raise _SerialError("bad custom body")
        start = j + 1
        end = start + dl
        if end + 1 > len(data) or data[end:end + 1] != b"}":
            raise _SerialError("custom data past end")
        return {"k": "object", "class": _bytes_name(cname),
                "fields": [("__serialized_data__", {"k": "bytes", "hex": data[start:end].hex()})]}, end + 1
    if t in (0x72, 0x52):                                   # r:N; / R:N;  reference
        txt, j = _php_int_token(data, i + 2, b";")
        if not re.fullmatch(r"\d+", txt):
            raise _SerialError("bad reference")
        return {"k": "ref", "handle": _safe_int(txt)}, j
    raise _SerialError(f"unknown PHP token 0x{t:02x}")


def _php_float(txt):
    low = txt.strip().lower()
    if low in ("inf", "+inf"):
        return float("inf")
    if low == "-inf":
        return float("-inf")
    if low == "nan":
        return float("nan")
    try:
        return float(txt)
    except ValueError as exc:
        raise _SerialError(f"invalid PHP float token {txt!r}") from exc


def _bytes_name(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _node_key_text(node):
    if node.get("k") == "int":
        return str(node["v"])
    if node.get("k") == "str":
        return node["v"]
    return None


# ============================================================================ Ruby Marshal 4.8

class _RubyReader:
    def __init__(self, data):
        self.d = data
        self.i = 0
        self.symbols = []
        self.objects = []
        self.budget = MAX_ITEMS

    def _u1(self):
        if self.i >= len(self.d):
            raise _SerialError("truncated")
        b = self.d[self.i]
        self.i += 1
        return b

    def _long(self):
        c = self._u1()
        if c >= 128:
            c -= 256
        if c == 0:
            return 0
        if c > 0:
            if c > 4:
                return c - 5
            n = 0
            for k in range(c):
                n |= self._u1() << (8 * k)
            return n
        if c < -4:
            return c + 5
        n = -1
        for k in range(-c):
            n &= ~(0xFF << (8 * k))
            n |= self._u1() << (8 * k)
        return n

    def _bytes(self):
        n = self._long()
        if n < 0 or self.i + n > len(self.d):
            raise _SerialError("ruby string past end")
        raw = self.d[self.i:self.i + n]
        self.i += n
        return raw

    def value(self, depth):
        if depth > MAX_DEPTH:
            raise _SerialError("too deep")
        self.budget -= 1
        if self.budget <= 0:
            raise _SerialError("too many items")
        t = self._u1()
        if t == 0x30:                                       # '0' nil
            return {"k": "null"}
        if t == 0x54:                                       # 'T' true
            return {"k": "bool", "v": True}
        if t == 0x46:                                       # 'F' false
            return {"k": "bool", "v": False}
        if t == 0x69:                                       # 'i' Fixnum
            return {"k": "int", "v": self._long()}
        if t == 0x6C:                                       # 'l' Bignum
            sign = self._u1()
            words = self._long()
            n = 0
            for k in range(words):
                lo = self._u1()
                hi = self._u1()
                n |= (lo | (hi << 8)) << (16 * k)
            if sign == 0x2D:                                # '-'
                n = -n
            return {"k": "int", "v": n}
        if t == 0x66:                                       # 'f' Float (decimal string)
            raw = self._bytes()
            return {"k": "float", "v": _ruby_float(raw)}
        if t == 0x22:                                       # '"' String
            node = _leaf_str(self._bytes())
            self.objects.append(node)
            return node
        if t == 0x3A:                                       # ':' Symbol (defines)
            sym = _bytes_name(self._bytes())
            self.symbols.append(sym)
            return {"k": "sym", "v": sym}
        if t == 0x3B:                                       # ';' symlink
            idx = self._long()
            if 0 <= idx < len(self.symbols):
                return {"k": "sym", "v": self.symbols[idx]}
            raise _SerialError("bad symbol link")
        if t == 0x40:                                       # '@' object link
            idx = self._long()
            if 0 <= idx < len(self.objects):
                return self.objects[idx]
            return {"k": "ref", "handle": idx}
        if t == 0x5B:                                       # '[' Array
            node = {"k": "array", "items": []}
            self.objects.append(node)
            n = self._long()
            if n < 0:
                raise _SerialError("negative array length")
            for _ in range(n):
                node["items"].append(self.value(depth + 1))
            return node
        if t in (0x7B, 0x7D):                               # '{' Hash, '}' Hash with default
            node = {"k": "map", "pairs": []}
            self.objects.append(node)
            n = self._long()
            if n < 0:
                raise _SerialError("negative hash length")
            for _ in range(n):
                k = self.value(depth + 1)
                v = self.value(depth + 1)
                node["pairs"].append((k, v))
            if t == 0x7D:
                self.value(depth + 1)                       # default value, read and discarded
            return node
        if t == 0x49:                                       # 'I' object with instance variables
            inner = self.value(depth + 1)
            n = self._long()
            if n < 0:
                raise _SerialError("negative ivar count")
            for _ in range(n):
                self.value(depth + 1)                       # ivar symbol
                self.value(depth + 1)                       # ivar value (e.g. :E encoding flag)
            return inner
        if t == 0x6F:                                       # 'o' plain object
            node = {"k": "object", "class": None, "fields": []}
            self.objects.append(node)
            cls = self.value(depth + 1)
            node["class"] = cls.get("v") if cls.get("k") == "sym" else None
            n = self._long()
            if n < 0:
                raise _SerialError("negative ivar count")
            for _ in range(n):
                sym = self.value(depth + 1)
                val = self.value(depth + 1)
                name = sym.get("v") if sym.get("k") == "sym" else None
                node["fields"].append((_ruby_ivar_name(name), val))
            return node
        if t in (0x53,):                                    # 'S' Struct (class symbol + members)
            node = {"k": "object", "class": None, "fields": []}
            self.objects.append(node)
            cls = self.value(depth + 1)
            node["class"] = cls.get("v") if cls.get("k") == "sym" else None
            n = self._long()
            if n < 0:
                raise _SerialError("negative struct length")
            for _ in range(n):
                sym = self.value(depth + 1)
                val = self.value(depth + 1)
                name = sym.get("v") if sym.get("k") == "sym" else None
                node["fields"].append((_ruby_ivar_name(name), val))
            return node
        if t in (0x63, 0x6D, 0x4D):                         # 'c' Class, 'm'/'M' Module
            return {"k": "class", "name": _bytes_name(self._bytes())}
        raise _SerialError(f"unsupported Ruby Marshal type 0x{t:02x}")


def _ruby_ivar_name(name):
    if name is None:
        return None
    return name[1:] if name.startswith("@") else name


def _ruby_float(raw: bytes):
    low = raw.decode("latin-1").strip().lower()
    if low in ("inf", "+inf"):
        return float("inf")
    if low == "-inf":
        return float("-inf")
    if low in ("nan", "-nan"):
        return float("nan")
    try:
        return float(raw.decode("ascii", "strict"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise _SerialError("invalid Ruby float token") from exc


def decode_ruby(data: bytes):
    """The node of a Ruby Marshal 4.8 blob consumed EXACTLY, else _SerialError."""
    if not isinstance(data, (bytes, bytearray)) or len(data) < 3 or data[0] != 0x04 or data[1] != 0x08:
        raise _SerialError("not a Ruby Marshal 4.8 stream")
    r = _RubyReader(data)
    r.i = 2
    node = r.value(0)
    if r.i != len(data):
        raise _SerialError("trailing bytes after Ruby value")
    return node


# ============================================================================ Java serialization

_J_MAGIC = 0xACED
_BASE_HANDLE = 0x7E0000
# classDescFlags
_SC_WRITE_METHOD = 0x01
_SC_SERIALIZABLE = 0x02
_SC_EXTERNALIZABLE = 0x04
_SC_BLOCK_DATA = 0x08


class _JavaClassDesc:
    __slots__ = ("name", "flags", "fields", "super")

    def __init__(self, name):
        self.name = name
        self.flags = 0
        self.fields = []               # [(typecode:str, fieldname:str)]
        self.super = None


class _JavaReader:
    def __init__(self, data):
        self.d = data
        self.i = 0
        self.handles = []
        self.budget = MAX_ITEMS

    def _need(self, n):
        if self.i + n > len(self.d):
            raise _SerialError("truncated java stream")

    def _u1(self):
        self._need(1)
        b = self.d[self.i]
        self.i += 1
        return b

    def _u2(self):
        self._need(2)
        v = struct.unpack_from(">H", self.d, self.i)[0]
        self.i += 2
        return v

    def _u4(self):
        self._need(4)
        v = struct.unpack_from(">I", self.d, self.i)[0]
        self.i += 4
        return v

    def _i4(self):
        self._need(4)
        v = struct.unpack_from(">i", self.d, self.i)[0]
        self.i += 4
        return v

    def _i8(self):
        self._need(8)
        v = struct.unpack_from(">q", self.d, self.i)[0]
        self.i += 8
        return v

    def _utf(self, n):
        self._need(n)
        raw = self.d[self.i:self.i + n]
        self.i += n
        try:
            return _decode_mutf8(raw)
        except Exception:                                   # noqa: BLE001
            return raw.decode("latin-1")

    def _new_handle(self, node):
        self.handles.append(node)
        return node

    def _skip(self, n):
        self._need(n)
        self.i += n

    # -- the content grammar ------------------------------------------------
    def content(self, depth):
        if depth > MAX_DEPTH:
            raise _SerialError("too deep")
        while True:                                         # TC_RESET loops here, never recurses
            self.budget -= 1
            if self.budget <= 0:
                raise _SerialError("too many items")
            tc = self._u1()
            if tc == 0x79:                                  # TC_RESET: clear the handle table, read on
                self.handles = []
                continue
            return self._content_body(tc, depth)

    def _content_body(self, tc, depth):
        if tc == 0x70:                                      # TC_NULL
            return {"k": "null"}
        if tc == 0x71:                                      # TC_REFERENCE
            h = self._u4()
            idx = h - _BASE_HANDLE
            if 0 <= idx < len(self.handles):
                return self.handles[idx]
            return {"k": "ref", "handle": h}
        if tc == 0x74:                                      # TC_STRING
            node = _leaf_jstr(self._read_bytes(self._u2()))
            return self._new_handle(node)
        if tc == 0x7C:                                      # TC_LONGSTRING
            ln = self._read_u8_len()
            node = _leaf_jstr(self._read_bytes(ln))
            return self._new_handle(node)
        if tc == 0x73:                                      # TC_OBJECT
            cd = self._class_desc(depth)
            node = {"k": "object", "class": cd.name if cd else None, "fields": []}
            self._new_handle(node)
            self._class_data(cd, node, depth)
            return node
        if tc == 0x75:                                      # TC_ARRAY
            cd = self._class_desc(depth)
            node = {"k": "array", "items": []}
            self._new_handle(node)
            n = self._u4()
            comp = (cd.name[1:2] if cd and cd.name and len(cd.name) >= 2 else "L")
            for _ in range(n):
                node["items"].append(self._field_value(comp, depth))
            return node
        if tc == 0x76:                                      # TC_CLASS
            cd = self._class_desc(depth)
            node = {"k": "class", "name": cd.name if cd else None}
            return self._new_handle(node)
        if tc == 0x7E:                                      # TC_ENUM
            cd = self._class_desc(depth)
            node = {"k": "enum", "class": cd.name if cd else None, "value": None}
            self._new_handle(node)
            node["value"] = self.content(depth + 1)
            return node
        if tc in (0x77, 0x7A):                              # TC_BLOCKDATA / TC_BLOCKDATALONG
            ln = self._u1() if tc == 0x77 else self._u4()
            self._skip(ln)
            return {"k": "blockdata", "len": ln}
        raise _SerialError(f"unexpected java content tag 0x{tc:02x}")

    def _read_bytes(self, n):
        self._need(n)
        raw = self.d[self.i:self.i + n]
        self.i += n
        return raw

    def _read_u8_len(self):
        self._need(8)
        ln = struct.unpack_from(">Q", self.d, self.i)[0]
        self.i += 8
        if ln > MAX_FILE:
            raise _SerialError("long string too large")
        return ln

    def _class_desc(self, depth):
        if depth > MAX_DEPTH:
            raise _SerialError("too deep")
        tc = self._u1()
        if tc == 0x70:                                      # TC_NULL
            return None
        if tc == 0x71:                                      # TC_REFERENCE to a prior classDesc
            h = self._u4()
            idx = h - _BASE_HANDLE
            if 0 <= idx < len(self.handles) and isinstance(self.handles[idx], _JavaClassDesc):
                return self.handles[idx]
            raise _SerialError("class-desc reference does not resolve")
        if tc == 0x72:                                      # TC_CLASSDESC
            name = self._utf(self._u2())
            self._i8()                                      # serialVersionUID (not surfaced)
            cd = _JavaClassDesc(name)
            self._new_handle(cd)
            cd.flags = self._u1()
            nfields = self._u2()
            for _ in range(nfields):
                tcode = chr(self._u1())
                fname = self._utf(self._u2())
                if tcode in ("L", "["):
                    self._read_type_string(depth)          # field type string (TC_STRING / ref)
                elif tcode not in ("B", "C", "D", "F", "I", "J", "S", "Z"):
                    raise _SerialError(f"unknown field typecode {tcode!r}")
                cd.fields.append((tcode, fname))
            self._annotation(depth)                         # classAnnotation .. TC_ENDBLOCKDATA
            cd.super = self._class_desc(depth + 1)
            return cd
        if tc == 0x7D:                                      # TC_PROXYCLASSDESC
            cd = _JavaClassDesc(None)
            self._new_handle(cd)
            n = self._u4()
            for _ in range(n):
                self._utf(self._u2())                       # interface names
            self._annotation(depth)
            cd.super = self._class_desc(depth + 1)
            cd.flags = 0                                    # a proxy carries no serializable fields
            return cd
        raise _SerialError(f"unexpected class-desc tag 0x{tc:02x}")

    def _read_type_string(self, depth):
        tc = self._u1()
        if tc == 0x74:
            self._new_handle(_leaf_str(self._read_bytes(self._u2())))
        elif tc == 0x7C:
            self._new_handle(_leaf_str(self._read_bytes(self._read_u8_len())))
        elif tc == 0x71:
            self._u4()                                      # reference to an earlier type string
        else:
            raise _SerialError(f"bad field type string tag 0x{tc:02x}")

    def _annotation(self, depth):
        # contents* TC_ENDBLOCKDATA (0x78)
        while True:
            if self.i >= len(self.d):
                raise _SerialError("annotation not terminated")
            tc = self.d[self.i]
            if tc == 0x78:                                  # TC_ENDBLOCKDATA
                self.i += 1
                return
            self.content(depth + 1)

    def _class_data(self, cd, node, depth):
        chain = []
        c = cd
        while isinstance(c, _JavaClassDesc):
            chain.append(c)
            c = c.super
        chain.reverse()                                     # super first, as Java writes them
        for c in chain:
            flags = c.flags
            if flags & _SC_EXTERNALIZABLE:
                if flags & _SC_BLOCK_DATA:
                    self._annotation(depth)                 # external block data .. TC_ENDBLOCKDATA
                    continue
                raise _SerialError("pre-1.2 externalizable without block data cannot be read")
            if flags & _SC_SERIALIZABLE:
                for tcode, fname in c.fields:
                    val = self._field_value(tcode, depth)
                    node["fields"].append((fname, val))
                if flags & _SC_WRITE_METHOD:
                    self._annotation(depth)                 # objectAnnotation .. TC_ENDBLOCKDATA
            elif flags:
                raise _SerialError(f"unreadable class flags 0x{flags:02x}")

    def _field_value(self, tcode, depth):
        # The Java field/element typecode byte-PROVES the primitive's width, so an int node records
        # its "bits" (byte 8, char/short 16, int 32, long 64). That width is what _int_options masks a
        # negative two's-complement hex to; nothing is ever assumed to be 64-bit. PHP and Ruby ints are
        # arbitrary-precision and carry no width (no "bits"), so their hex rendering is never masked.
        if tcode == "B":
            v = self._u1()
            return {"k": "int", "v": v - 256 if v >= 128 else v, "bits": 8}
        if tcode == "C":
            return {"k": "int", "v": self._u2(), "bits": 16}       # char is unsigned 16-bit (never < 0)
        if tcode == "D":
            self._need(8)
            v = struct.unpack_from(">d", self.d, self.i)[0]
            self.i += 8
            return {"k": "float", "v": v}
        if tcode == "F":
            self._need(4)
            v = struct.unpack_from(">f", self.d, self.i)[0]
            self.i += 4
            return {"k": "float", "v": v}
        if tcode == "I":
            return {"k": "int", "v": self._i4(), "bits": 32}
        if tcode == "J":
            return {"k": "int", "v": self._i8(), "bits": 64}
        if tcode == "S":
            self._need(2)
            v = struct.unpack_from(">h", self.d, self.i)[0]
            self.i += 2
            return {"k": "int", "v": v, "bits": 16}
        if tcode == "Z":
            return {"k": "bool", "v": self._u1() != 0}
        if tcode in ("L", "["):
            return self.content(depth + 1)
        raise _SerialError(f"unknown field typecode {tcode!r}")


def _decode_mutf8(raw: bytes) -> str:
    """Java modified UTF-8: NUL as C0 80 and >U+FFFF as CESU-8 surrogate pairs. Plain ASCII and BMP
    text decode as ordinary UTF-8, which covers every class and field name."""
    out = []
    i, n = 0, len(raw)
    while i < n:
        b = raw[i]
        if b == 0:
            raise _SerialError("raw NUL in modified UTF-8")
        if b < 0x80:
            out.append(b)
            i += 1
        elif b & 0xE0 == 0xC0:
            if i + 1 >= n:
                raise _SerialError("truncated mutf8")
            out.append(((b & 0x1F) << 6) | (raw[i + 1] & 0x3F))
            i += 2
        elif b & 0xF0 == 0xE0:
            if i + 2 >= n:
                raise _SerialError("truncated mutf8")
            out.append(((b & 0x0F) << 12) | ((raw[i + 1] & 0x3F) << 6) | (raw[i + 2] & 0x3F))
            i += 3
        else:
            raise _SerialError("bad modified UTF-8 lead byte")
    # CESU-8: a code point above U+FFFF is two 3-byte sequences encoding a UTF-16 surrogate pair.
    chars, k = [], 0
    while k < len(out):
        u = out[k]
        if 0xD800 <= u <= 0xDBFF and k + 1 < len(out) and 0xDC00 <= out[k + 1] <= 0xDFFF:
            chars.append(0x10000 + ((u - 0xD800) << 10) + (out[k + 1] - 0xDC00))
            k += 2
        else:
            chars.append(u)
            k += 1
    return "".join(chr(c) for c in chars)


def decode_java(data: bytes):
    """The node (or list of nodes) of a Java serialization stream consumed EXACTLY, else _SerialError.
    A stream may hold several top-level objects back to back; all are read and the whole buffer must
    be accounted for."""
    if not isinstance(data, (bytes, bytearray)) or len(data) < 4 or struct.unpack_from(">H", data, 0)[0] != _J_MAGIC:
        raise _SerialError("not a Java serialization stream")
    if struct.unpack_from(">H", data, 2)[0] != 0x0005:
        raise _SerialError("unsupported Java stream version")
    r = _JavaReader(data)
    r.i = 4
    nodes = []
    while r.i < len(data):
        nodes.append(r.content(0))
    if r.i != len(data):
        raise _SerialError("trailing bytes after Java stream")
    if not nodes:
        raise _SerialError("empty Java stream")
    return nodes[0] if len(nodes) == 1 else {"k": "array", "items": nodes}


# ============================================================================ classify

def classify(data: bytes):
    """{format, root} for a blob that decodes cleanly and consumes every byte, else None. The three
    formats have disjoint, specific starts (AC ED / 04 08 / a PHP type token), so at most one is
    tried; a format is reported only when the WHOLE buffer parses."""
    if not isinstance(data, (bytes, bytearray)) or not data or len(data) > MAX_FILE:
        return None
    data = bytes(data)
    if len(data) >= 4 and struct.unpack_from(">H", data, 0)[0] == _J_MAGIC:
        try:
            return {"format": "java", "root": decode_java(data)}
        except (_SerialError, struct.error, ValueError, IndexError, OverflowError):
            return None
    if len(data) >= 3 and data[0] == 0x04 and data[1] == 0x08:
        try:
            return {"format": "ruby", "root": decode_ruby(data)}
        except (_SerialError, struct.error, ValueError, IndexError, OverflowError):
            return None
    if data[0] in _PHP_TOKENS:
        try:
            return {"format": "php", "root": decode_php(data)}
        except (_SerialError, struct.error, ValueError, IndexError, OverflowError):
            return None
    return None


# ============================================================================ accessors

def _count(node):
    if not isinstance(node, dict):
        return None
    k = node.get("k")
    if k == "array":
        return len(node["items"])
    if k == "map":
        return len(node["pairs"])
    if k == "object":
        return len(node["fields"])
    return None


def _classname(node):
    if isinstance(node, dict) and node.get("k") in ("object", "class", "enum"):
        name = node.get("class") if node.get("k") != "class" else node.get("name")
        return name if isinstance(name, str) and name else None
    return None


def _scalar(node):
    """('int'|'str'|'bool'|'float'|'null'|'sym', value) for a leaf, else None (a container)."""
    if not isinstance(node, dict):
        return None
    k = node.get("k")
    if k == "bool":
        return ("bool", node["v"])
    if k == "int":
        return ("int", node["v"])
    if k == "float":
        return ("float", node["v"])
    if k == "str":
        return ("str", node["v"])
    if k == "sym":
        return ("sym", node["v"])
    if k == "null":
        return ("null", "null")
    return None


def _field_node(root, name):
    """The value node of a named field/property/ivar/key, else None. For PHP a mangled private name
    ("\\0Class\\0prop") or protected ("\\0*\\0prop") also matches its bare tail."""
    if not isinstance(root, dict):
        return None
    hits = []
    if root.get("k") == "object":
        for fn, val in root["fields"]:
            if fn == name or _demangle(fn) == name:
                hits.append(val)
    elif root.get("k") == "map":
        for kn, val in root["pairs"]:
            kt = _node_key_text(kn) if kn.get("k") in ("int", "str") else (kn.get("v") if kn.get("k") == "sym" else None)
            if kt == name:
                hits.append(val)
    return hits[0] if len(hits) == 1 else None


def _demangle(name):
    if isinstance(name, str) and name.startswith("\x00"):
        return name.split("\x00")[-1]
    return name


def _index_node(root, idx):
    if isinstance(root, dict) and root.get("k") == "array" and 0 <= idx < len(root["items"]):
        return root["items"][idx]
    return None


# ============================================================================ never-guess answers

def _int_options(n, bits=None):
    """Renderings of ONE integer fact, as (options, is_candidate).

    A NON-NEGATIVE integer has one unambiguous hex form (`format(n, "x")`, width-independent: no
    leading zeros, no sign), so its renderings are plain-eligible spellings of one fact -> labels.pick
    (is_candidate False), unchanged.

    A NEGATIVE integer does NOT have one hex form: it can be written signed (sign-magnitude, `-1f`) or
    as two's-complement at the field's width (`ffff` for a 16-bit field, `ffffffff` for 32-bit, ...),
    and nothing in the bytes proves which the author chose. The old code rendered it as a FIXED 64-bit
    mask (`n & 0xFFFFFFFFFFFFFFFF`), which is wrong for a narrower field and silently drops the signed
    spelling. So the renderings are now DIFFERENT candidate HYPOTHESES (is_candidate True): they are
    never plain until the judge accepts a name, and the two's-complement form is offered ONLY when the
    field width is byte-proven (the Java typecode gave "bits"); it is never a 64-bit guess, and for an
    arbitrary-precision int with no proven width (PHP, Ruby) no two's-complement hypothesis is offered
    at all. The signed sign-magnitude form is width-independent, so it is always safe to offer."""
    if n >= 0:
        hx = format(n, "x")
        return [("decimal", str(n)), ("hex", hx), ("hex_0x", "0x" + hx)], False
    mag = format(-n, "x")                                   # magnitude, sign kept separate
    opts = [("decimal", str(n))]                            # signed decimal: always the exact fact
    if isinstance(bits, int) and bits > 0:                  # width byte-proven from the record/field def
        u = format(n & ((1 << bits) - 1), "x")              # two's-complement at the TRUE field width
        opts += [(f"hex_u{bits}", u), (f"hex_0x_u{bits}", "0x" + u)]
    opts += [("hex_signed", "-" + mag), ("hex_0x_signed", "-0x" + mag)]
    return opts, True


def _value_options(kind, v, bits=None):
    """(options, is_candidate) for a scalar leaf. is_candidate is True only for a negative integer,
    whose renderings are ambiguous (see _int_options); everything else is a plain-eligible pick."""
    if kind == "int":
        return _int_options(v, bits)
    if kind == "bool":
        return [("true_false", "true" if v else "false"), ("yes_no", "yes" if v else "no"),
                ("title", "True" if v else "False"), ("1_0", "1" if v else "0")], False
    if kind == "float":
        return [("raw", repr(v)), ("plain", ("%g" % v))], False
    if kind == "null":
        return [("none", "none"), ("null", "null"), ("nil", "nil")], False
    return [("raw", str(v))], False


def _class_options(name, fmt):
    opts = [("raw", name)]
    simple = re.split(r"[.$/]", name)[-1]
    if simple and simple != name:
        opts.append(("simple", simple))
    if fmt == "java" and "$" in name:
        opts.append(("dotted", name.replace("$", ".")))
    return opts


def _pick(field, fmt, options, candidate=False):
    """labels.pick for plain-eligible spellings of one fact; labels.candidates when `candidate` (a
    negative integer's ambiguous renderings, row 346): different hypotheses, never plain until judged,
    and then only for a variant that offers the accepted hypothesis."""
    opts, seen = [], set()
    for name, value in options:
        value = str(value)
        if (name, value) not in seen:
            seen.add((name, value))
            opts.append((name, value))
    if not opts:
        return None
    key = f"{KEY}.{field}/{fmt}"
    try:
        return labels.candidates(key, opts) if candidate else labels.pick(key, opts)
    except ValueError:
        return None


def _slug(s):
    return re.sub(r"[^a-z0-9]+", "_", str(s).lower()).strip("_")[:40]


_FORMAT_SPELL = {
    "java": [("java_serialization", "java_serialization"), ("java", "java"),
             ("java_object_stream", "java_object_stream")],
    "php": [("php_serialize", "php_serialize"), ("php", "php"), ("php_serialized", "php_serialized")],
    "ruby": [("ruby_marshal", "ruby_marshal"), ("ruby", "ruby"), ("marshal", "marshal")],
}

# Words that are NOT a specific member name: the structural words for the top-level blob itself
# ("the object", "the array", "the blob") and the counted/indexed nouns of the question grammar
# ("element", "entry", "value of ..."). When one of these does not resolve to a container member it
# means the root; a word OUTSIDE this set that names a member which does not resolve to a container
# means None, never the root count ("default to None rather than guessing root"). A member that is
# genuinely named one of these words is still used when it resolves to a container node.
_GENERIC_CONTAINER_WORDS = frozenset((
    # the blob itself
    "object", "array", "blob", "root", "structure", "stream", "payload", "map", "hash", "hashmap",
    "list", "arraylist", "dictionary", "dict", "collection", "graph", "document", "instance",
    "top", "top-level", "toplevel", "whole", "it", "this", "serialized", "serialised", "marshal",
    # the thing being counted or indexed (part of the question, not a member)
    "field", "fields", "property", "properties", "propery", "properies", "key", "keys", "ivar",
    "ivars", "element", "elements", "item", "items", "index", "indices", "indexes", "entry",
    "entries", "member", "members", "value", "values", "length", "size", "count", "number",
    "position", "slot", "variable", "variables", "attribute", "attributes",
))


def _referenced_names(text):
    """Member names a question names: every quoted string, and the word after a container/field
    keyword or 'the'. Case is preserved (member names are case-sensitive)."""
    names = re.findall(r"['\"]([^'\"]{1,120})['\"]", text)
    names += re.findall(r"(?:field|property|propery|ivar|key|variable|attribute|member|value of|the)\s+"
                        r"([A-Za-z_@$][A-Za-z0-9_.$]{0,63})\b", text)
    return names


def _resolve_path(root, dotted):
    """Walk a dotted member path from root (a.b.c), one segment per _field_node, or None."""
    node = root
    for part in str(dotted).split("."):
        if not part:
            return None
        node = _field_node(node, part)
        if node is None:
            return None
    return node


def _container_and_path(root, text):
    """The container a count/index question targets, as (node, path_label), or None.

    The key MUST encode WHICH container, so a rendering (e.g. 'decimal') the judge accepted for the
    root count can never plain-answer a differently-named container's count. So:
      - a specific member name that resolves to exactly one container node -> that node, scoped by it;
      - two different named containers -> None (ambiguous);
      - a specific member named that does NOT resolve to a container here (scalar / absent) -> None,
        never the root count ("default to None rather than guessing root");
      - no specific member named (only generic words like 'the object', or none) -> the root.
    The root label is '@root' and a member label is '@'+slug, both impossible to confuse with each
    other (a member literally named 'root' slugs to 'root', never '@root')."""
    found = {}                 # id(node) -> (name, node): distinct container nodes a name resolves to
    specific_unresolved = False
    for nm in _referenced_names(text):
        node = _resolve_path(root, nm)
        if node is not None and _count(node) is not None:
            found.setdefault(id(node), (nm, node))
        elif nm.lower() not in _GENERIC_CONTAINER_WORDS:
            specific_unresolved = True
    if len(found) == 1:
        nm, node = next(iter(found.values()))
        return node, "@" + (_slug(nm) or "x")
    if len(found) >= 2:
        return None            # two different named containers: which one is asked is not provable
    if specific_unresolved:
        return None            # a specific member was named but is not a container here
    return root, "@root"


def _answer_one(q, rep):
    text = str(q.get("question") or "")
    aid = str(q.get("answer_id") or q.get("id") or q.get("qid") or "")
    t = (text + " " + aid).lower()
    fmt = rep["format"]
    root = rep["root"]

    def has(*words):
        return any(w in t for w in words)

    if has("flag"):
        return None
    if has("what format", "which format", "serialization format", "serialisation format",
           "what kind of serial", "format of the blob", "format is used", "format is this"):
        return _pick("format", fmt, _FORMAT_SPELL[fmt])
    if has("class name", "classname", "class of the", "what class", "name of the class",
           "object class", "serialized class", "class is serial"):
        name = _classname(root)
        return _pick("classname", fmt, _class_options(name, fmt)) if name else None
    if has("how many field", "number of field", "field count", "how many propert", "number of propert",
           "how many key", "number of key", "number of entries", "how many entries", "how many ivar",
           "number of ivar", "number of element", "how many element", "how many item", "number of item",
           "how many member", "number of member"):
        # Scope the count by WHICH container is asked. The root count and a nested container's count
        # are separate keys, so a rendering accepted for one can never plain-answer the other.
        target = _container_and_path(root, text)
        if target is None:
            return None
        node, path = target
        n = _count(node)
        return _pick(f"count/{path}", fmt, [("decimal", n)]) if n is not None else None
    m = re.search(r"(?:element|item|index|entry)\s*(?:number\s*|#\s*|no\.?\s*)?(\d+)", t)
    if m:
        target = _container_and_path(root, text)
        if target is None:
            return None
        node, path = target
        idx = int(m.group(1))
        el = _index_node(node, idx)
        sc = _scalar(el)
        if not sc:
            return None
        opts, candidate = _value_options(sc[0], sc[1], el.get("bits"))
        return _pick(f"index{idx}/{path}", fmt, opts, candidate)
    names = _referenced_names(text)
    for nm in names:
        node = _field_node(root, nm)
        if node is not None:
            sc = _scalar(node)
            if not sc:
                return None
            opts, candidate = _value_options(sc[0], sc[1], node.get("bits"))
            return _pick(f"field_{_slug(nm)}", fmt, opts, candidate)
    return None


# ============================================================================ runner contract

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


# ============================================================================ signals

_WORDS = re.compile(
    r"serial(?:ized|ization|ised|isation)|deserial|unserial|marshal|java (?:object|stream)|"
    r"php|ruby|instance variable|\bivar\b|class ?name|\bgadget\b|object stream|serialize\(\)|"
    r"\bfield\b|propert|magic method", re.I)


def signals(questions, files) -> float:
    """0..1: a native serialization blob decodes cleanly in the bytes AND the questions speak of
    serialization. Java and Ruby have specific magic; PHP needs a container (an object or array), so
    a lone 'i:5;'-looking scalar never scores. The decode is byte-primary, but the vocabulary keeps
    it from stealing a neighbouring lane's artifact."""
    fmt = None
    try:
        for _n, data in triage.unique_files(files or {}):
            rep = classify(data)
            if rep:
                root = rep["root"]
                if rep["format"] == "php" and _count(root) is None:
                    continue                                # a lone PHP scalar is too weak to claim
                fmt = rep["format"]
                if fmt in ("java", "ruby"):
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
    base = 0.45 if fmt in ("java", "ruby") else 0.3
    score = base + min(0.45, 0.12 * len(hits))
    return round(min(1.0, score), 2)


# ============================================================================ CLI (offline triage)

def _summary(rep) -> str:
    fmt = rep["format"]
    root = rep["root"]
    cn = _classname(root)
    n = _count(root)
    head = fmt + (f" {root.get('k')}" if isinstance(root, dict) else "")
    if cn:
        head += f" class={cn}"
    if n is not None:
        head += f" ({n} member{'s' if n != 1 else ''})"
    if isinstance(root, dict) and root.get("k") == "object":
        head += ": " + ", ".join(fn for fn, _ in root["fields"][:16])
    elif isinstance(root, dict) and root.get("k") == "map":
        head += ": keys " + ", ".join(str(_node_key_text(k)) for k, _ in root["pairs"][:16])
    return head


def main(argv) -> int:
    as_json = "--json" in argv
    paths = [a for a in argv if not a.startswith("--")]
    if not paths:
        print("usage: serial_decode.py <file>... [--json]   (java/php/ruby structural facts only, flag None)",
              file=sys.stderr)
        return 2
    out = []
    for p in paths:
        try:
            data = Path(p).read_bytes()
        except OSError as e:
            print(f"serial_decode.py: {p}: {e}", file=sys.stderr)
            continue
        rep = classify(data)
        out.append({"file": p, "format": rep["format"] if rep else None, "report": rep, "bytes": len(data)})
    if as_json:
        print(json.dumps(out, indent=1, default=lambda o: o.hex() if isinstance(o, (bytes, bytearray)) else str(o)))
        return 0
    for row in out:
        if not row["format"]:
            print(f"- {row['file']}: no Java/PHP/Ruby native serialization recognised ({row['bytes']} bytes)")
            continue
        print(f"# {row['file']}  [{row['format']}]  {_summary(row['report'])}")
        print("  no instantiation: structural values are plain-eligible via labels.pick; "
              "semantic meaning and the flag are unsure/None.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
