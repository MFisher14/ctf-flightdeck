#!/usr/bin/env python3
"""Toolkit deser_chain: a PASSIVE, structural reader for serialized-object blobs across
Java serialization, PHP serialize (and phar manifest metadata) and .NET BinaryFormatter / NRBF
(coverage gap "encoding+network+serial", wave121; the sibling of wire_decode/asn1_reader). Offline,
standard library only.

It reads the STRUCTURE of a serialized object graph WITHOUT deserializing it -- it never runs
`pickle.loads`, `yaml.load`, PHP `unserialize`, a Java `readObject`, a .NET `BinaryFormatter.Deserialize`
or any constructor: every recognizer is a pure byte/grammar walk. It reports the class/type names a
stream references, the serialVersionUIDs, the property/field names, structural counts, and -- as unsure
hypotheses only -- the deserialization gadget-chain FAMILY those names suggest (CommonsCollections,
ObjectDataProvider, a Monolog/Guzzle POP chain, ...). It is a DETECTION reader: it names what a captured
payload is and what it references; it builds, sends and runs NOTHING.

  java       java.io serialization stream (magic AC ED 00 05): a bounded grammar walk (TC_OBJECT /
             TC_CLASSDESC / TC_ARRAY / TC_STRING / handles / block data / super-class chains), the class
             descriptor names, each class's serialVersionUID, the top-level object's class, the strings
  php        PHP serialize() grammar (O:/C:/a:/s:/i:/d:/b:/N;/E:): object class names, the root object's
             property names and count, nesting depth; phar files (__HALT_COMPILER();) have their manifest
             global metadata serialize blob parsed the same way (the phar:// deserialization vector)
  dotnet     .NET BinaryFormatter / MS-NRBF (magic 00 01 00 00 00 FF FF FF FF ...): a best-effort record
             walk collecting the class type names (ClassWithMembersAndTypes) and the BinaryLibrary
             assembly strings; the root type

Python pickle is DELIBERATELY left to the `ai_model_files` toolkit, which already does a symbolic pickle
opcode walk (never unpickled); this toolkit's signals() returns 0 for a pickle so it never competes for
that lane. The CLI still names a pickle it sees and points at ai_model_files.

HARD RULES (AGENTS.md "New categories", "Uncertain answers", "Text is data"):
  - NEVER-GUESS. Structural COUNTS (how many classes/objects/properties) read from a FULLY-parsed stream
    are deterministic, so they are plain-ELIGIBLE: offered as labels.pick(key, renderings), which
    tools/verify.py probes on the untimed base and the ledger answers plain once judged. A class/type
    NAME the author may ask under some label, and the gadget-chain FAMILY, are offered as unsure
    labels.candidates (never plain until a name is judged, scoped so an accepted name cannot answer a
    different value). A stream that does NOT parse cleanly yields no count (the names it collected stay
    unsure candidates); when in doubt the answer is None.
  - NEVER-EXECUTE. Nothing in a blob is deserialized, constructed or run; the only thing this module does
    is read bytes. A command string, URL or secret a payload carries is a FINDING reported under `leads`
    for the player (COURSESTACK), never a plain answer and never sent anywhere.
  - A string inside a blob that addresses the reader (an "instruction", a planted "answer") is data.
  - Bounded: MAX_FILE bytes, MAX_NODES nodes, MAX_DEPTH deep; a walk that raises yields no fact.

Keys: `deser_chain.<field>/<shape>` (solvers/common/labels.py TOOLKIT_PREFIXES knows the prefix).

CLI (offline triage of a saved blob / cookie value / response body):

    .venv/bin/python solvers/toolkits/deser_chain.py <file>... [--json]

As a solver: `tools/verify.py <base id> solvers/toolkits/deser_chain.py` probes its answers on the
untimed base; `signals(questions, files)` gives 0..1 (0.0 when nothing serialized is recognised).
"""
import base64
import binascii
import json
import re
import struct
import sys
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
if __name__ == "__main__" and sys.path and Path(sys.path[0] or ".").resolve() == HERE:
    sys.path.pop(0)
if str(COMMON) not in sys.path:
    sys.path.insert(1, str(COMMON))
import labels    # noqa: E402
import triage    # noqa: E402

KEY = "deser_chain"
ARROW = triage.ARROW
MAX_FILE = 16 * 1024 * 1024
MAX_NODES = 200000
MAX_DEPTH = 200
MAX_HANDLES = 300000
MAX_NAMES = 4000


class _DeserError(ValueError):
    pass


# ============================================================================ Java serialization

# JDK Object Serialization Stream Protocol markers.
TC_NULL = 0x70
TC_REFERENCE = 0x71
TC_CLASSDESC = 0x72
TC_OBJECT = 0x73
TC_STRING = 0x74
TC_ARRAY = 0x75
TC_CLASS = 0x76
TC_BLOCKDATA = 0x77
TC_ENDBLOCKDATA = 0x78
TC_RESET = 0x79
TC_BLOCKDATALONG = 0x7A
TC_EXCEPTION = 0x7B
TC_LONGSTRING = 0x7C
TC_PROXYCLASSDESC = 0x7D
TC_ENUM = 0x7E
JAVA_BASE_HANDLE = 0x7E0000

SC_WRITE_METHOD = 0x01
SC_SERIALIZABLE = 0x02
SC_EXTERNALIZABLE = 0x04
SC_BLOCK_DATA = 0x08
SC_ENUM = 0x10

_PRIM_SIZE = {ord("B"): 1, ord("C"): 2, ord("D"): 8, ord("F"): 4,
              ord("I"): 4, ord("J"): 8, ord("S"): 2, ord("Z"): 1}


def _decode_mutf8(raw: bytes) -> str:
    """Decode JVMS "modified UTF-8" (JVMS 4.4.7): a raw NUL is C0 80, and a supplementary code
    point is a CESU-8 surrogate pair of two 3-byte sequences. Standard-library only; raises
    _DeserError on bytes that are not valid modified UTF-8."""
    units, i, n = [], 0, len(raw)
    while i < n:
        b = raw[i]
        if b == 0 or b >= 0xF0:                       # a real NUL / 4-byte form never appears in mutf8
            raise _DeserError("invalid modified UTF-8")
        if b < 0x80:
            units.append(b)
            i += 1
        elif (b & 0xE0) == 0xC0:
            if i + 1 >= n or (raw[i + 1] & 0xC0) != 0x80:
                raise _DeserError("invalid modified UTF-8")
            units.append(((b & 0x1F) << 6) | (raw[i + 1] & 0x3F))
            i += 2
        elif (b & 0xF0) == 0xE0:
            if i + 2 >= n or (raw[i + 1] & 0xC0) != 0x80 or (raw[i + 2] & 0xC0) != 0x80:
                raise _DeserError("invalid modified UTF-8")
            units.append(((b & 0x0F) << 12) | ((raw[i + 1] & 0x3F) << 6) | (raw[i + 2] & 0x3F))
            i += 3
        else:
            raise _DeserError("invalid modified UTF-8")
    out, j, m = [], 0, len(units)
    while j < m:
        u = units[j]
        if 0xD800 <= u <= 0xDBFF and j + 1 < m and 0xDC00 <= units[j + 1] <= 0xDFFF:
            out.append(0x10000 + ((u - 0xD800) << 10) + (units[j + 1] - 0xDC00))
            j += 2
        else:
            out.append(u)
            j += 1
    return "".join(chr(c) for c in out)


class _JavaReader:
    """A bounded, fail-closed walk of a java.io serialization stream. It collects facts; it never
    constructs or runs anything. On any byte it does not understand it raises _DeserError, and the
    caller keeps whatever names were collected before that (as unsure candidates only)."""

    def __init__(self, data: bytes):
        self.d = data
        self.n = len(data)
        self.i = 0
        self.handles = {}          # handle -> ("classdesc"|"string"|..., value)
        self.next_handle = JAVA_BASE_HANDLE
        self.nodes = 0
        self.classes = []          # class descriptor names, in order first seen
        self.class_uids = {}       # class name -> serialVersionUID (first seen)
        self.strings = []          # TC_STRING / TC_LONGSTRING values
        self.object_count = 0
        self.root_class = None

    # -- primitive reads (bounds-checked) --
    def _need(self, k):
        if self.i + k > self.n or k < 0:
            raise _DeserError("short read")

    def u1(self):
        self._need(1)
        v = self.d[self.i]
        self.i += 1
        return v

    def u2(self):
        self._need(2)
        v = struct.unpack_from(">H", self.d, self.i)[0]
        self.i += 2
        return v

    def i4(self):
        self._need(4)
        v = struct.unpack_from(">i", self.d, self.i)[0]
        self.i += 4
        return v

    def i8(self):
        self._need(8)
        v = struct.unpack_from(">q", self.d, self.i)[0]
        self.i += 8
        return v

    def utf(self, long=False):
        ln = self.i8() if long else self.u2()
        if ln < 0:
            raise _DeserError("bad utf length")
        self._need(ln)
        s = _decode_mutf8(self.d[self.i:self.i + ln])    # Java strings are modified UTF-8 (JVMS 4.4.7)
        self.i += ln
        return s

    def _new_handle(self, kind, value):
        h = self.next_handle
        self.next_handle += 1
        if len(self.handles) > MAX_HANDLES:
            raise _DeserError("too many handles")
        self.handles[h] = (kind, value)
        return h

    def _bump(self):
        self.nodes += 1
        if self.nodes > MAX_NODES:
            raise _DeserError("too many nodes")

    # -- grammar --
    def parse(self):
        if self.n < 5 or self.d[0] != 0xAC or self.d[1] != 0xED:
            raise _DeserError("no java stream magic")
        self.i = 2
        version = self.u2()
        if version != 5:
            raise _DeserError(f"unsupported stream version {version}")
        while self.i < self.n:
            self._content(0)
        return self.report()

    def _record_class(self, name, uid):
        if name and name not in self.class_uids:
            if len(self.classes) < MAX_NAMES:
                self.classes.append(name)
            self.class_uids[name] = uid

    def _content(self, depth):
        if depth > MAX_DEPTH:
            raise _DeserError("too deep")
        self._bump()
        b = self.u1()
        if b == TC_NULL:
            return None
        if b == TC_REFERENCE:
            h = self.i4()
            if h not in self.handles:          # a reference is valid only to a previously assigned handle
                raise _DeserError("reference to unassigned handle")
            return None
        if b == TC_STRING:
            s = self.utf(False)
            self._new_handle("string", s)
            if len(self.strings) < MAX_NAMES:
                self.strings.append(s)
            return s
        if b == TC_LONGSTRING:
            s = self.utf(True)
            self._new_handle("string", s)
            if len(self.strings) < MAX_NAMES:
                self.strings.append(s)
            return s
        if b == TC_CLASSDESC or b == TC_PROXYCLASSDESC:
            self.i -= 1
            return self._class_desc(depth)
        if b == TC_OBJECT:
            return self._object(depth)
        if b == TC_ARRAY:
            return self._array(depth)
        if b == TC_ENUM:
            return self._enum(depth)
        if b == TC_CLASS:
            self._class_desc(depth)
            self._new_handle("class", None)
            return None
        if b == TC_BLOCKDATA:
            ln = self.u1()
            self._need(ln)
            self.i += ln
            return None
        if b == TC_BLOCKDATALONG:
            ln = self.i4()
            if ln < 0:
                raise _DeserError("bad blockdatalong length")
            self._need(ln)
            self.i += ln
            return None
        if b == TC_RESET:
            self.handles.clear()
            self.next_handle = JAVA_BASE_HANDLE
            return None
        if b == TC_EXCEPTION:
            self.handles.clear()
            self.next_handle = JAVA_BASE_HANDLE
            self._content(depth + 1)
            return None
        if b == TC_ENDBLOCKDATA:
            raise _DeserError("stray endblockdata")
        raise _DeserError(f"unknown marker 0x{b:02x} at {self.i - 1}")

    def _class_desc(self, depth):
        """Return a descriptor chain: a list of (flags, [field typecodes], name) from sub to super,
        used to read object field data. Resolves TC_REFERENCE / TC_NULL."""
        if depth > MAX_DEPTH:
            raise _DeserError("too deep")
        b = self.u1()
        if b == TC_NULL:
            return []
        if b == TC_REFERENCE:
            h = self.i4()
            kind, value = self.handles.get(h, (None, None))
            if kind == "classdesc":
                return value
            raise _DeserError("classdesc reference to non-classdesc")
        if b == TC_PROXYCLASSDESC:
            desc_ref = []
            self._new_handle("classdesc", desc_ref)
            cnt = self.i4()
            if cnt < 0 or cnt > MAX_NODES:
                raise _DeserError("bad proxy interface count")
            for _ in range(cnt):
                self.utf(False)
            self._annotation(depth)          # classAnnotation
            super_chain = self._class_desc(depth + 1)
            desc_ref.append((0, [], None))   # proxy carries no field data of its own
            desc_ref.extend(super_chain)
            return desc_ref
        if b != TC_CLASSDESC:
            raise _DeserError(f"expected classdesc, got 0x{b:02x}")
        name = self.utf(False)
        uid = self.i8()
        desc_ref = []
        self._new_handle("classdesc", desc_ref)
        self._record_class(name, uid)
        flags = self.u1()
        field_count = self.u2()
        fields = []
        for _ in range(field_count):
            tc = self.u1()
            self.utf(False)                  # field name
            if tc in (ord("["), ord("L")):
                # className1: a TC_STRING or a reference to one
                self._content(depth + 1)
                fields.append(ord("L"))
            elif tc in _PRIM_SIZE:
                fields.append(tc)
            else:
                raise _DeserError(f"bad field typecode 0x{tc:02x}")
        self._annotation(depth)              # classAnnotation
        super_chain = self._class_desc(depth + 1)
        desc_ref.append((flags, fields, name))
        desc_ref.extend(super_chain)
        return desc_ref

    def _annotation(self, depth):
        """classAnnotation / objectAnnotation: content* TC_ENDBLOCKDATA."""
        while True:
            self._bump()
            b = self.u1()
            if b == TC_ENDBLOCKDATA:
                return
            self.i -= 1
            self._content(depth + 1)

    def _object(self, depth):
        chain = self._class_desc(depth)
        self._new_handle("object", None)
        self.object_count += 1
        # chain[0] is the most-derived class, chain[-1] the topmost super. The root is the FIRST
        # (outermost) object started, so set it here, before its field objects are read.
        most_derived = chain[0][2] if chain else None
        if self.root_class is None and most_derived:
            self.root_class = most_derived
        # field data is written super-first (chain reversed).
        for flags, fields, _nm in reversed(chain):
            if flags & SC_EXTERNALIZABLE:
                if flags & SC_BLOCK_DATA:
                    self._annotation(depth)
                    continue
                raise _DeserError("externalizable without block data (protocol 1)")
            self._class_data(fields, depth)
            if flags & SC_WRITE_METHOD:
                self._annotation(depth)
        return most_derived

    def _class_data(self, fields, depth):
        for tc in fields:
            if tc == ord("L"):
                self._content(depth + 1)
            else:
                size = _PRIM_SIZE[tc]
                self._need(size)
                self.i += size

    def _array(self, depth):
        chain = self._class_desc(depth)
        self._new_handle("array", None)
        name = chain[-1][2] if chain else ""
        size = self.i4()
        if size < 0 or size > MAX_NODES:
            raise _DeserError("bad array size")
        elem = name[1] if name and len(name) >= 2 and name[0] == "[" else "L"
        ec = ord(elem) if elem in "BCDFIJSZ" else ord("L")
        if ec == ord("L"):
            for _ in range(size):
                self._content(depth + 1)
        else:
            step = _PRIM_SIZE[ec]
            self._need(size * step)
            self.i += size * step
        return None

    def _enum(self, depth):
        self._class_desc(depth)
        self._new_handle("enum", None)
        self._content(depth + 1)             # enum constant name (a String)
        return None

    def report(self):
        return {
            "format": "java",
            "complete": self.i == self.n,
            "classes": list(self.classes),
            "serial_uids": dict(self.class_uids),
            "object_count": self.object_count,
            "string_count": len(self.strings),
            "strings": list(self.strings),
            "root_class": self.root_class,
            "class_count": len(self.classes),
        }


def parse_java(data: bytes) -> dict:
    """A report for a java serialization stream, or None if it has no magic. `complete` says whether
    every byte was consumed; names collected before a failure are kept (unsure only)."""
    if not data or len(data) < 5 or data[0] != 0xAC or data[1] != 0xED:
        return None
    r = _JavaReader(data)
    try:
        return r.parse()
    except (_DeserError, struct.error, IndexError, UnicodeError):
        rep = r.report()
        rep["complete"] = False
        return rep if rep["classes"] or rep["object_count"] else rep


# ============================================================================ PHP serialize

class _PhpReader:
    def __init__(self, data: bytes):
        self.d = data
        self.n = len(data)
        self.i = 0
        self.nodes = 0
        self.objects = []          # (classname, [prop names], prop_count)
        self.classes = []
        self.max_depth = 0
        self.root = None
        self.has_phar = False

    def _expect(self, ch):
        if self.i >= self.n or self.d[self.i] != ord(ch):
            raise _DeserError(f"expected {ch!r} at {self.i}")
        self.i += 1

    def _read_int_until(self, term):
        start = self.i
        while self.i < self.n and self.d[self.i] != ord(term):
            self.i += 1
        if self.i >= self.n:
            raise _DeserError("unterminated integer")
        raw = self.d[start:self.i]
        self.i += 1
        return raw

    def _digits(self, term):
        raw = self._read_int_until(term)
        if not re.fullmatch(rb"-?\d+", raw):
            raise _DeserError(f"not an integer: {raw!r}")
        return int(raw)

    def value(self, depth):
        if depth > MAX_DEPTH:
            raise _DeserError("too deep")
        self.max_depth = max(self.max_depth, depth)
        self.nodes += 1
        if self.nodes > MAX_NODES:
            raise _DeserError("too many nodes")
        if self.i >= self.n:
            raise _DeserError("unexpected end")
        t = chr(self.d[self.i])
        if t == "N":                                    # N;
            self.i += 1
            self._expect(";")
            return ("null", None)
        self.i += 1
        self._expect(":")
        if t == "b":
            v = self._read_int_until(";")
            if v not in (b"0", b"1"):
                raise _DeserError("bad bool")
            return ("bool", v == b"1")
        if t == "i":
            return ("int", self._digits(";"))
        if t == "d":
            raw = self._read_int_until(";")
            try:
                return ("float", float(raw))
            except ValueError:
                low = raw.lower()
                if low in (b"inf", b"-inf", b"nan"):
                    return ("float", {b"inf": float("inf"), b"-inf": float("-inf"),
                                      b"nan": float("nan")}[low])
                raise _DeserError("bad double")
        if t == "s":
            return ("str", self._pstring())
        if t == "E":                                    # enum: E:len:"Name:case";
            raw = self._pstring_raw()
            return ("enum", raw.decode("utf-8", "replace"))
        if t in ("R", "r"):                             # reference by value/object index
            self._digits(";")
            return ("ref", None)
        if t == "a":
            return ("array", self._collection(depth, is_object=False))
        if t == "O":
            return ("object", self._object(depth, custom=False))
        if t == "C":
            return ("object", self._object(depth, custom=True))
        raise _DeserError(f"unknown php type {t!r}")

    def _pstring(self):
        return self._pstring_raw().decode("utf-8", "replace")

    def _pstring_raw(self):
        ln = self._digits(":")
        if ln < 0 or ln > self.n:
            raise _DeserError("bad string length")
        self._expect('"')
        if self.i + ln > self.n:
            raise _DeserError("string overruns buffer")
        raw = self.d[self.i:self.i + ln]
        self.i += ln
        self._expect('"')
        self._expect(";")
        return raw

    def _classname(self):
        ln = self._digits(":")
        if ln < 0 or ln > self.n:
            raise _DeserError("bad class name length")
        self._expect('"')
        if self.i + ln > self.n:
            raise _DeserError("class name overruns buffer")
        name = self.d[self.i:self.i + ln].decode("utf-8", "replace")
        self.i += ln
        self._expect('"')
        return name

    def _collection(self, depth, is_object):
        count = self._digits(":")
        if count < 0 or count > MAX_NODES:
            raise _DeserError("bad element count")
        self._expect("{")
        keys = []
        for _ in range(count):
            k = self.value(depth + 1)
            v = self.value(depth + 1)
            keys.append(k)
        self._expect("}")
        return count, keys

    def _object(self, depth, custom):
        name = self._classname()
        self._expect(":")
        if name and name not in self.classes and len(self.classes) < MAX_NAMES:
            self.classes.append(name)
        # Claim root BEFORE descending into properties, so a nested inner object cannot be
        # mistaken for the root; the provisional value is replaced with full info below.
        claim_root = self.root is None
        if claim_root:
            self.root = (name, [], 0)
        if custom:                                      # C:len:"Name":datalen:{data}
            ln = self._digits(":")
            if ln < 0 or self.i + 1 + ln > self.n:
                raise _DeserError("bad custom data length")
            self._expect("{")
            self._need_php(ln)
            self.i += ln
            self._expect("}")
            prop_names, pcount = [], 0
        else:
            pcount, keys = self._collection(depth, is_object=True)
            prop_names = [k[1] for k in keys if k[0] == "str"]
        info = (name, prop_names, pcount)
        self.objects.append(info)
        if claim_root:
            self.root = info
        return info

    def _need_php(self, k):
        if self.i + k > self.n:
            raise _DeserError("short read")

    def parse(self):
        self.root = None
        v = self.value(0)
        # allow trailing whitespace only
        rest = self.d[self.i:]
        if rest.strip(b" \t\r\n"):
            raise _DeserError("trailing bytes after value")
        return self.report(v)

    def report(self, root_value=None):
        root_kind = root_value[0] if root_value else None
        return {
            "format": "php",
            "complete": True,
            "objects": list(self.objects),
            "object_count": len(self.objects),
            "classes": list(self.classes),
            "class_count": len(self.classes),
            "max_depth": self.max_depth,
            "root": self.root,
            "root_kind": root_kind,
            "has_phar": self.has_phar,
        }


def parse_php(data: bytes) -> dict:
    """A report for a buffer that is exactly one PHP serialize() value (object-bearing or not), else
    None. Strict: the whole buffer must parse, lengths are byte-exact."""
    if not data or len(data) < 2:
        return None
    if data[0:1] not in (b"O", b"C", b"a", b"s", b"i", b"d", b"b", b"N", b"E"):
        return None
    r = _PhpReader(data)
    try:
        return r.parse()
    except (_DeserError, ValueError, IndexError):
        return None


def parse_phar(data: bytes) -> dict:
    """A phar file (stub ...__HALT_COMPILER();) with its manifest global-metadata serialize blob parsed
    as PHP, else None. The classic phar:// deserialization vector: unserialize happens on file access."""
    if not isinstance(data, (bytes, bytearray)):
        return None
    data = bytes(data)
    marker = data.find(b"__HALT_COMPILER();")
    if marker < 0 or len(data) > MAX_FILE:
        return None
    # The manifest begins after the stub (optional "?>\r\n" / "?>\n" / " ?>").
    p = marker + len(b"__HALT_COMPILER();")
    tail = data[p:p + 8]
    for skip in (b" ?>\r\n", b"?>\r\n", b" ?>\n", b"?>\n", b"?>", b""):
        if tail.startswith(skip):
            p += len(skip)
            break
    if p + 4 > len(data):
        return None
    try:
        manifest_len = struct.unpack_from("<I", data, p)[0]
        q = p + 4
        if q + manifest_len > len(data) or manifest_len < 14:
            return None
        num_files, api_ver, flags, alias_len = struct.unpack_from("<IHII", data, q)
        q += 14
        if alias_len > manifest_len:
            return None
        q += alias_len
        if q + 4 > len(data):
            return None
        meta_len = struct.unpack_from("<I", data, q)[0]
        q += 4
        if q + meta_len > p + 4 + manifest_len:         # metadata cannot escape the declared manifest extent
            return None
        meta = data[q:q + meta_len]
    except struct.error:
        return None
    rep = parse_php(meta) if meta else None
    if rep is None:
        rep = {"format": "php", "complete": bool(meta == b""), "objects": [], "object_count": 0,
               "classes": [], "class_count": 0, "max_depth": 0, "root": None, "root_kind": None}
    rep = dict(rep)
    rep["has_phar"] = True
    rep["phar_files"] = int(num_files)
    return rep


# ============================================================================ .NET BinaryFormatter (MS-NRBF)

# RecordTypeEnumeration values this walker understands; anything else ends the walk (names kept).
_NRBF_PRIM_SIZE = {1: 1, 2: 1, 3: None, 5: None, 6: 8, 7: 2, 8: 4, 9: 8, 10: 1,
                   11: 4, 12: 8, 13: 8, 14: 2, 15: 4, 16: 8, 18: None}


class _NetReader:
    def __init__(self, data: bytes):
        self.d = data
        self.n = len(data)
        self.i = 0
        self.nodes = 0
        self.types = []            # class type names (first seen)
        self.libraries = []        # BinaryLibrary assembly strings
        self.strings = []
        self.record_count = 0
        self.root_type = None
        self.saw_message_end = False
        self.classes_by_id = {}    # objectId -> (member BinaryTypeEnums, additional infos)

    def _need(self, k):
        if self.i + k > self.n or k < 0:
            raise _DeserError("short read")

    def u1(self):
        self._need(1)
        v = self.d[self.i]
        self.i += 1
        return v

    def i4(self):
        self._need(4)
        v = struct.unpack_from("<i", self.d, self.i)[0]
        self.i += 4
        return v

    def _bump(self):
        self.nodes += 1
        if self.nodes > MAX_NODES:
            raise _DeserError("too many nodes")

    def lpstring(self):
        """A LengthPrefixedString: a 7-bit-encoded length then that many UTF-8 bytes."""
        ln = 0
        shift = 0
        for _ in range(5):
            b = self.u1()
            ln |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
        else:
            raise _DeserError("bad 7-bit length")
        if ln < 0 or ln > self.n:
            raise _DeserError("bad lpstring length")
        self._need(ln)
        s = self.d[self.i:self.i + ln].decode("utf-8", "replace")
        self.i += ln
        return s

    def parse(self):
        if self.n < 17 or self.d[0] != 0x00:
            raise _DeserError("no nrbf header")
        # SerializationHeaderRecord: type 0, rootId, headerId, major=1, minor=0
        self.i = 1
        self.i4()                                  # rootId
        self.i4()                                  # headerId
        major = self.i4()
        minor = self.i4()
        if major != 1 or minor != 0:
            raise _DeserError(f"unsupported nrbf version {major}.{minor}")
        self.record_count = 1
        while self.i < self.n:
            t = self.u1()
            if t == 11:                            # MessageEnd
                self.record_count += 1
                self.saw_message_end = True
                break
            self.i -= 1
            self._record(0)
        return self.report()

    def _record(self, depth):
        if depth > MAX_DEPTH:
            raise _DeserError("too deep")
        self._bump()
        self.record_count += 1
        t = self.u1()
        if t == 12:                                # BinaryLibrary
            self.i4()                              # libraryId
            name = self.lpstring()
            if name and name not in self.libraries and len(self.libraries) < MAX_NAMES:
                self.libraries.append(name)
            return
        if t == 5:                                 # ClassWithMembersAndTypes
            self._class_with_members(depth, system=False)
            return
        if t == 4:                                 # SystemClassWithMembersAndTypes
            self._class_with_members(depth, system=True)
            return
        if t == 1:                                 # ClassWithId
            self.i4()                              # objectId
            meta_id = self.i4()
            info = self.classes_by_id.get(meta_id)
            if info is None:
                raise _DeserError("classwithid references unknown metadata")
            self._member_values(info, depth)
            return
        if t == 6:                                 # BinaryObjectString
            self.i4()
            s = self.lpstring()
            if len(self.strings) < MAX_NAMES:
                self.strings.append(s)
            return
        if t == 10:                                # ObjectNull
            return
        if t == 13:                                # ObjectNullMultiple256
            self.u1()
            return
        if t == 14:                                # ObjectNullMultiple
            self.i4()
            return
        if t == 9:                                 # MemberReference
            self.i4()
            return
        if t == 8:                                 # MemberPrimitiveTyped
            pt = self.u1()
            self._primitive(pt)
            return
        if t in (16, 17):                          # ArraySingleObject / ArraySingleString
            self.i4()                              # objectId
            length = self.i4()
            if length < 0 or length > MAX_NODES:
                raise _DeserError("bad array length")
            for _ in range(length):
                self._member_object(depth + 1)
            return
        if t == 15:                                # ArraySinglePrimitive
            self.i4()
            length = self.i4()
            pt = self.u1()
            if length < 0 or length > MAX_NODES:
                raise _DeserError("bad primitive array length")
            for _ in range(length):
                self._primitive(pt)
            return
        raise _DeserError(f"unsupported nrbf record 0x{t:02x}")

    def _class_with_members(self, depth, system):
        object_id = self.i4()                      # objectId
        name = self.lpstring()                     # the TYPE NAME
        if name and name not in self.types and len(self.types) < MAX_NAMES:
            self.types.append(name)
        if self.root_type is None:
            self.root_type = name
        member_count = self.i4()
        if member_count < 0 or member_count > MAX_NODES:
            raise _DeserError("bad member count")
        for _ in range(member_count):
            self.lpstring()                        # member names
        binary_types = [self.u1() for _ in range(member_count)]
        additional = []
        for bt in binary_types:
            additional.append(self._additional_info(bt))
        if not system:
            self.i4()                              # LibraryId
        info = (binary_types, additional)
        # metadata is addressable by its ObjectId (what a later ClassWithId references).
        self.classes_by_id[object_id] = info
        self._member_values(info, depth)

    def _additional_info(self, bt):
        if bt == 0:                                # Primitive
            return ("prim", self.u1())
        if bt == 7:                                # PrimitiveArray
            return ("primarray", self.u1())
        if bt == 3:                                # SystemClass
            return ("sysclass", self.lpstring())
        if bt == 4:                                # Class (name + libraryId)
            nm = self.lpstring()
            self.i4()
            return ("class", nm)
        if bt in (1, 2, 5, 6):                      # String / Object / ObjectArray / StringArray
            return (bt, None)
        raise _DeserError(f"unsupported binary type {bt}")

    def _member_values(self, info, depth):
        binary_types, additional = info
        for bt, add in zip(binary_types, additional):
            if bt == 0:                            # Primitive inline
                self._primitive(add[1])
            else:                                  # String/Object/.../arrays -> a record follows
                self._member_object(depth + 1)

    def _member_object(self, depth):
        self._bump()
        t = self.d[self.i] if self.i < self.n else None
        if t is None:
            raise _DeserError("short read in member")
        self._record(depth)

    def _primitive(self, pt):
        if pt in (3, 18):                          # Char / String -> lpstring-ish
            if pt == 18:
                self.lpstring()
            else:                                  # a single UTF-8 char (1..4 bytes)
                b0 = self.u1()
                extra = 0
                if b0 >= 0xF0:
                    extra = 3
                elif b0 >= 0xE0:
                    extra = 2
                elif b0 >= 0xC0:
                    extra = 1
                self._need(extra)
                self.i += extra
            return
        if pt == 5:                                # Decimal -> lpstring
            self.lpstring()
            return
        size = _NRBF_PRIM_SIZE.get(pt)
        if size is None:
            raise _DeserError(f"unsupported primitive {pt}")
        self._need(size)
        self.i += size

    def report(self):
        return {
            "format": "dotnet",
            "complete": self.i >= self.n or True,  # set precisely by caller via _consumed
            "_consumed": self.i,
            "types": list(self.types),
            "libraries": list(self.libraries),
            "strings": list(self.strings),
            "record_count": self.record_count,
            "type_count": len(self.types),
            "root_type": self.root_type,
            "class_count": len(self.types),
        }


def parse_dotnet(data: bytes) -> dict:
    """A report for a .NET BinaryFormatter / MS-NRBF stream, or None if it has no header. `complete`
    is True only when a MessageEnd record was reached and every byte consumed; the type/library names
    collected before a failure are kept (unsure only)."""
    if not data or len(data) < 17 or data[0] != 0x00:
        return None
    # header: 00 rootId(4) headerId(4) 01 00 00 00 00 00 00 00
    if struct.unpack_from("<i", data, 9)[0] != 1 or struct.unpack_from("<i", data, 13)[0] != 0:
        return None
    r = _NetReader(data)
    try:
        rep = r.parse()
        rep["complete"] = (r.i == r.n and r.saw_message_end)   # MS-NRBF mandates a MessageEnd record
        return rep
    except (_DeserError, struct.error, IndexError, UnicodeError):
        rep = r.report()
        rep["complete"] = False
        return rep


# ============================================================================ pickle (detect only; ai_model_files owns it)

def looks_like_pickle(data: bytes) -> bool:
    """A cheap, fail-closed pickle sniff for the CLI only -- this toolkit does NOT answer pickle
    (ai_model_files does the symbolic opcode walk). Protocol 2+ (\\x80) or a plausible opcode run
    ending in STOP (.) with no serialization magic of ours."""
    if not data or len(data) < 2:
        return False
    if data[:2] in (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05"):
        return True
    return False


# ============================================================================ gadget-chain families (unsure hypotheses)

# Each entry: a family hypothesis NAME and the class/type substrings whose presence suggests it.
# These are HINTS, offered only as unsure labels.candidates, never plain. A match means "classes
# consistent with this gadget family are referenced", which is a lead, not a judged fact.
_JAVA_FAMILIES = [
    ("commons_collections", ("org.apache.commons.collections.functors.InvokerTransformer",
                             "org.apache.commons.collections.functors.ChainedTransformer",
                             "org.apache.commons.collections.functors.InstantiateTransformer",
                             "org.apache.commons.collections4.functors.InvokerTransformer",
                             "org.apache.commons.collections.keyvalue.TiedMapEntry",
                             "org.apache.commons.collections.map.LazyMap")),
    ("commons_beanutils", ("org.apache.commons.beanutils.BeanComparator",)),
    ("templates_impl", ("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",)),
    ("groovy", ("org.codehaus.groovy.runtime.ConvertedClosure",
                "org.codehaus.groovy.runtime.MethodClosure")),
    ("spring", ("org.springframework.beans.factory.ObjectFactory",
                "org.springframework.core.SerializableTypeWrapper")),
    ("rome", ("com.sun.syndication.feed.impl.ObjectBean", "com.rometools.rome.feed.impl.ObjectBean")),
    ("c3p0", ("com.mchange.v2.c3p0.PoolBackedDataSource",
              "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource")),
    ("jdbc_rowset", ("com.sun.rowset.JdbcRowSetImpl",)),
    ("hibernate", ("org.hibernate.engine.spi.TypedValue", "org.hibernate.tuple.component.AbstractComponentTuplizer")),
    ("bean_shell", ("bsh.XThis", "bsh.Interpreter")),
    ("clojure", ("clojure.lang.PersistentArrayMap", "clojure.inspector.proxy")),
    ("urldns", ("java.net.URL",)),
    ("annotation_invocation", ("sun.reflect.annotation.AnnotationInvocationHandler",)),
    ("bad_attribute_value", ("javax.management.BadAttributeValueExpException",)),
]
_PHP_FAMILIES = [
    ("monolog_rce", ("Monolog\\Handler\\SyslogUdpHandler", "Monolog\\Handler\\BufferHandler",
                     "Monolog\\Handler\\AbstractProcessingHandler")),
    ("guzzle_rce", ("GuzzleHttp\\Psr7\\FnStream", "GuzzleHttp\\HandlerStack", "GuzzleHttp\\Cookie\\FileCookieJar")),
    ("laravel", ("Illuminate\\Broadcasting\\PendingBroadcast", "Illuminate\\Bus\\Dispatcher",
                 "Illuminate\\Foundation\\Testing\\PendingCommand")),
    ("symfony", ("Symfony\\Component\\Process\\Process",
                 "Symfony\\Component\\Cache\\Adapter\\TagAwareAdapter")),
    ("doctrine", ("Doctrine\\Common\\Cache\\FilesystemCache",)),
    ("phpggc_faker", ("Faker\\Generator", "Faker\\DefaultGenerator")),
    ("thinkphp", ("think\\process\\pipes\\Windows", "think\\model\\Pivot")),
    ("slim", ("Slim\\Http\\",)),
]
_NET_FAMILIES = [
    ("object_data_provider", ("System.Windows.Data.ObjectDataProvider",)),
    ("type_confuse_delegate", ("System.DelegateSerializationHolder", "System.Collections.Generic.SortedSet")),
    ("dataset", ("System.Data.DataSet",)),
    ("windows_identity", ("System.Security.Principal.WindowsIdentity",)),
    ("claims_identity", ("System.Security.Claims.ClaimsIdentity",)),
    ("psobject", ("System.Management.Automation.PSObject",)),
    ("text_formatting", ("Microsoft.VisualStudio.Text.Formatting.TextFormattingRunProperties",)),
    ("activity_surrogate", ("System.Workflow.ComponentModel.Serialization.ActivitySurrogateSelector",)),
    ("resource_set", ("System.Resources.ResourceSet",)),
    ("session_security_token", ("System.IdentityModel.Tokens.SessionSecurityToken",)),
]


def gadget_families(rep: dict):
    """[(hypothesis_name, label value)] for the gadget families a report's class/type names suggest,
    best (most specific) first. UNSURE only. Empty when nothing matches."""
    fmt = rep.get("format")
    names = []
    if fmt == "java":
        names = list(rep.get("classes") or [])
        table = _JAVA_FAMILIES
    elif fmt == "php":
        names = list(rep.get("classes") or [])
        table = _PHP_FAMILIES
    elif fmt == "dotnet":
        names = list(rep.get("types") or []) + list(rep.get("libraries") or [])
        table = _NET_FAMILIES
    else:
        return []
    blob = "\n".join(names)
    out = []
    for fam, needles in table:
        hits = sum(1 for nd in needles if nd in blob)
        if hits:
            out.append((hits, fam))
    out.sort(key=lambda x: (-x[0], x[1]))
    # java urldns only if URL is basically the only suspicious class (avoid false "urldns" on big chains)
    if fmt == "java" and len(out) > 1:
        out = [(h, f) for h, f in out if f != "urldns"] or out
    return [(fam, fam) for _h, fam in out]


# ============================================================================ classify

def _peel_b64(data: bytes):
    """If the whole file is one base64 blob that decodes to a recognised magic, return the decoded
    bytes; else None. Conservative: the entire (trimmed) content must be a base64 alphabet."""
    t = data.strip()
    if len(t) < 16 or len(t) > MAX_FILE:
        return None
    if not re.fullmatch(rb"[A-Za-z0-9+/_\-]+={0,2}", t):
        return None
    for alt in (t, t.replace(b"-", b"+").replace(b"_", b"/")):
        pad = alt + b"=" * (-len(alt) % 4)
        try:
            dec = base64.b64decode(pad, validate=True)
        except (binascii.Error, ValueError):
            continue
        if dec[:2] == b"\xac\xed" or (len(dec) >= 17 and dec[0] == 0x00
                                      and dec[1:5] == b"\x01\x00\x00\x00"):
            return dec
    return None


def classify(data: bytes) -> dict:
    """{format, ...} for a blob recognised as a serialized object graph, else None. java / dotnet by
    magic first (specific), then phar, then a clean whole-buffer PHP serialize. A single base64 layer
    is peeled for java/dotnet. The report carries `outer_encoding` when peeled and `gadget_families`."""
    if not isinstance(data, (bytes, bytearray)) or not data or len(data) > MAX_FILE:
        return None
    data = bytes(data)
    outer = []
    peeled = _peel_b64(data)
    core = data
    if peeled is not None:
        core = peeled
        outer = ["base64"]
    rep = None
    if core[:2] == b"\xac\xed":
        rep = parse_java(core)
    elif (len(core) >= 17 and core[0] == 0x00 and core[9:13] == b"\x01\x00\x00\x00"
          and core[13:17] == b"\x00\x00\x00\x00"):           # NRBF header: major=1, minor=0 (any rootId)
        rep = parse_dotnet(core)
    if rep is None:
        rep = parse_phar(data)
        if rep is not None:
            outer = []
    if rep is None:
        rep = parse_php(data)
    if rep is None:
        return None
    rep = dict(rep)
    rep["outer_encoding"] = outer
    rep["gadget_families"] = gadget_families(rep)
    return rep


# ============================================================================ signals

_WORDS = re.compile(
    r"deserial|unserialize|serial(?:ized|ization|ised)|gadget|ysoserial|phpggc|binaryformatter|"
    r"objectinputstream|readobject|invoker ?transformer|commons[- ]?collections|object ?data ?provider|"
    r"\bphar\b|pop ?chain|insecure deserial|class ?name|\bgadget chain\b|magic method|__wakeup|__destruct|"
    r"serialversionuid|typeconfuse|objectdataprovider", re.I)


def signals(questions, files) -> float:
    """0..1: a serialized-object blob is recognised in the bytes. java/dotnet/phar carry a specific
    magic, so they score on the bytes alone; a bare PHP serialize (text grammar) needs it to hold an
    OBJECT (so a plain serialized scalar never steals a lane) and leans a little on the vocabulary.
    Pickle is NOT this toolkit's (returns 0 for it)."""
    fmt = None
    has_object = False
    try:
        for _n, data in triage.unique_files(files or {}):
            rep = classify(data)
            if rep:
                fmt = rep["format"]
                if fmt in ("java", "dotnet") or rep.get("has_phar"):
                    has_object = True
                    break
                # php: require it to actually hold a serialized object
                if rep.get("object_count"):
                    has_object = True
    except Exception:  # noqa: BLE001
        fmt = None
    if not fmt:
        return 0.0
    hits = set()
    for q in questions or []:
        f = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
        text = " ".join(str(x or "") for x in (q.get("question"), q.get("answer_id") or q.get("id"), f.get("syntax")))
        hits |= {m.group().lower() for m in _WORDS.finditer(text)}
    if fmt in ("java", "dotnet"):
        base = 0.6                       # a specific, unambiguous magic
    elif has_object:
        base = 0.55                      # a PHP serialized object (strict whole-buffer parse; a whiff of vocab matches)
    else:
        base = 0.25                      # a PHP serialized scalar: do not match on bytes alone
    score = base + min(0.35, 0.1 * len(hits))
    return round(min(1.0, score), 2)


# ============================================================================ answers (never-guess)

def _pick(field, shape, options):
    opts, seen = [], set()
    for name, value in options:
        value = str(value)
        if (name, value) not in seen and value != "":
            seen.add((name, value))
            opts.append((name, value))
    if not opts:
        return None
    try:
        return labels.pick(f"{KEY}.{field}/{shape}", opts)
    except ValueError:
        return None


def _candidates(field, shape, options):
    opts, seen = [], set()
    for name, value in options:
        value = str(value)
        if name == value:                # a bare label is no hypothesis (never-wrong): drop it
            continue
        if (name, value) not in seen and value != "":
            seen.add((name, value))
            opts.append((name, value))
    if not opts:
        return None
    try:
        return labels.candidates(f"{KEY}.{field}/{shape}", opts)
    except ValueError:
        return None


def _name_renderings(name):
    """Renderings of ONE class/type name under distinct hypothesis names (never name==value)."""
    out = [("fqn", name)]
    if "/" in name:
        out.append(("dotted", name.replace("/", ".")))
    if "." in name:
        out.append(("simple", name.rsplit(".", 1)[-1]))
        out.append(("slashed", name.replace(".", "/")))
    # strip a leading array marker for the element type
    if name.startswith("[L") and name.endswith(";"):
        out.append(("element", name[2:-1]))
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


def _answer_one(q, rep):
    text = str(q.get("question") or "")
    aid = str(q.get("answer_id") or q.get("id") or q.get("qid") or "")
    t = (text + " " + aid).lower()
    fmt = rep["format"]
    shape = fmt + ("+incomplete" if not rep.get("complete") else "")

    def has(*words):
        return any(w in t for w in words)

    if has("flag"):
        return None

    # --- the serialization format / language (byte-proven; author's label unknown -> unsure pick) ---
    if has("what format", "which format", "what serialization", "which serialization", "what kind of serial",
           "serialization format", "what language", "which language", "format of the"):
        spellings = {
            "java": [("lang", "java"), ("lang_full", "java_serialization"), ("stream", "java_serialized_object")],
            "php": [("lang", "php"), ("lang_full", "php_serialize"), ("fn", "unserialize")],
            "dotnet": [("lang", "dotnet"), ("lang_full", "binaryformatter"), ("alt", "net"), ("nrbf", "nrbf")],
        }.get(fmt, [])
        return _pick("format", fmt, spellings)

    # --- gadget chain / library / vulnerable class (interpretive -> candidates, never plain) ---
    if has("gadget", "which chain", "what chain", "vulnerable library", "which library", "what library",
           "exploit", "payload type", "which gadget", "attack"):
        fams = rep.get("gadget_families") or []
        if fams:
            return _candidates("gadget_family", shape, [(f"fam_{n}", v) for n, v in fams])
        return None

    # --- an embedded command / url the payload carries: a FINDING, not a plain answer ---
    if has("command", "what does the payload run", "executed", "runs what", "which url", "callback url",
           "dns", "exfil"):
        return None     # reported as a lead by scan(); never submitted

    # --- how many classes / objects / records / properties (deterministic count -> plain-eligible) ---
    # (before the root/class blocks: "how many properties does the ROOT object have" is a count, not a name)
    if has("how many", "number of", "count of", "count the"):
        if not rep.get("complete"):          # only a cleanly-parsed stream gives a trustworthy count
            return None
        if fmt == "php" and has("propert", "field", "member"):
            rootinfo = rep.get("root")
            if rootinfo and rootinfo[2] is not None:
                return _pick("property_count", fmt, [("decimal", str(rootinfo[2]))])
            return None
        if has("class", "type"):
            n = rep.get("class_count")
            return _pick("class_count", fmt, [("decimal", str(n))]) if n is not None else None
        if has("object"):
            n = rep.get("object_count")
            return _pick("object_count", fmt, [("decimal", str(n))]) if n is not None else None
        if fmt == "dotnet" and has("record"):
            n = rep.get("record_count")
            return _pick("record_count", fmt, [("decimal", str(n))]) if n is not None else None
        if fmt == "java" and has("string"):
            n = rep.get("string_count")
            return _pick("string_count", fmt, [("decimal", str(n))]) if n is not None else None
        return None

    # --- serialVersionUID of a (Java) class ---
    if fmt == "java" and has("serialversionuid", "serial version uid", "serialuid"):
        uids = rep.get("serial_uids") or {}
        wanted = None
        for cn in uids:
            simple = cn.rsplit(".", 1)[-1].lower()
            if simple and simple in t:
                wanted = cn
                break
        if wanted is None and len(uids) == 1:
            wanted = next(iter(uids))
        if wanted is not None:
            u = uids[wanted]
            return _pick("serialversionuid", "java", [("decimal", str(u)),
                                                       ("hex", format(u & 0xFFFFFFFFFFFFFFFF, "x")),
                                                       ("hex_0x", "0x" + format(u & 0xFFFFFFFFFFFFFFFF, "x"))])
        return None

    # --- the root / top-level / outer class or type name (ONE fact -> renderings pick) ---
    root = rep.get("root_class") if fmt in ("java", "php") else rep.get("root_type")
    if fmt == "php" and rep.get("root"):
        root = rep["root"][0] if rep["root"] else None
    if has("root class", "top-level class", "top level class", "outer class", "first object", "root object",
           "outermost", "root type", "entry class"):
        if root:
            return _pick("root_class", fmt, _name_renderings(root))
        return None

    # --- which class is referenced / used (several facts -> candidates, never plain) ---
    if has("which class", "what class", "class name", "name of the class", "class referenced",
           "which type", "what type", "type name", "assembly", "which assembly"):
        if fmt == "dotnet" and has("assembly", "library"):
            libs = rep.get("libraries") or []
            if libs:
                return _candidates("library", shape, [(f"lib{i}", v) for i, v in enumerate(libs)])
            return None
        names = (rep.get("classes") if fmt in ("java", "php") else rep.get("types")) or []
        if root and (has("root") or has("top") or has("outer")):
            return _pick("root_class", fmt, _name_renderings(root))
        if names:
            opts = []
            for i, nm in enumerate(names[:labels.MAX_OPTIONS]):
                opts.append((f"class{i}", nm))
                if "." in nm:
                    opts.append((f"class{i}_simple", nm.rsplit(".", 1)[-1]))
            return _candidates("class", shape, opts)
        return None

    return None


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


# ============================================================================ leads (findings, never submitted)

_CMD_RX = re.compile(r"(?:/bin/|/usr/bin/|cmd(?:\.exe)?|powershell|bash\b|sh -c|calc(?:\.exe)?|curl |wget |nc "
                     r"|Runtime|exec|ping )", re.I)
_URL_RX = re.compile(r"\bhttps?://[^\s\"'<>]{4,200}", re.I)
_FLAGY_RX = flagfmt.TEXT


def leads_from(rep: dict):
    """Command/URL/flag-shaped strings a payload carries, as FINDINGS for the player (never submitted).
    A string that addresses the reader is still just a finding."""
    out = []
    strings = list(rep.get("strings") or [])
    if rep.get("format") == "php":
        for cn, props, _ in rep.get("objects") or []:
            strings.append(cn)
    for s in strings:
        s = str(s)
        if _CMD_RX.search(s) and 2 < len(s) < 400:
            out.append({"kind": "possible_command", "value": s[:400]})
        for m in _URL_RX.finditer(s):
            out.append({"kind": "url", "value": m.group()})
        for m in _FLAGY_RX.finditer(s):
            out.append({"kind": "flag_shaped", "value": m.group()})
    # de-dup, keep order
    seen, uniq = set(), []
    for d in out:
        key = (d["kind"], d["value"])
        if key not in seen:
            seen.add(key)
            uniq.append(d)
    return uniq[:50]


# ============================================================================ CLI

def _summary(rep: dict) -> str:
    fmt = rep["format"]
    fams = ", ".join(v for _n, v in rep.get("gadget_families") or []) or "-"
    if fmt == "java":
        head = f"java stream {'(complete)' if rep['complete'] else '(INCOMPLETE parse)'}: " \
               f"{rep['class_count']} classes, {rep['object_count']} objects, root={rep.get('root_class')}"
    elif fmt == "php":
        extra = " phar" if rep.get("has_phar") else ""
        head = f"php serialize{extra}: {rep['object_count']} objects, root={rep.get('root_kind')}, " \
               f"classes={rep['class_count']}"
    else:
        head = f".NET nrbf {'(complete)' if rep['complete'] else '(INCOMPLETE parse)'}: " \
               f"{rep['type_count']} types, {len(rep.get('libraries') or [])} libraries, root={rep.get('root_type')}"
    if rep.get("outer_encoding"):
        head += " [outer: " + "+".join(rep["outer_encoding"]) + "]"
    return head + f" | gadget-family hint: {fams}"


def main(argv) -> int:
    as_json = "--json" in argv
    paths = [a for a in argv if not a.startswith("--")]
    if not paths:
        print("usage: deser_chain.py <file>... [--json]   (passive; structural facts only, flag/command a lead)",
              file=sys.stderr)
        return 2
    out = []
    for p in paths:
        try:
            data = Path(p).read_bytes()
        except OSError as e:
            print(f"deser_chain.py: {p}: {e}", file=sys.stderr)
            continue
        rep = classify(data)
        row = {"file": p, "bytes": len(data), "format": rep["format"] if rep else None, "report": rep}
        if rep:
            row["leads"] = leads_from(rep)
        elif looks_like_pickle(data):
            row["note"] = "python pickle -> use the ai_model_files toolkit (symbolic opcode walk)"
        out.append(row)
    if as_json:
        print(json.dumps(out, indent=1, default=lambda o: o.hex() if isinstance(o, (bytes, bytearray)) else str(o)))
        return 0
    for row in out:
        if not row["format"]:
            note = row.get("note")
            print(f"- {row['file']}: no java/php/.NET serialized structure recognised ({row['bytes']} bytes)"
                  + (f" -- {note}" if note else ""))
            continue
        print(f"# {row['file']}  [{row['format']}]  {_summary(row['report'])}")
        if row.get("leads"):
            print("  leads (findings for the player, never submitted):")
            for ld in row["leads"][:20]:
                print(f"    {ld['kind']}: {ld['value']}")
        print("  passive: structural counts are plain-eligible via labels.pick; class/type names and the "
              "gadget family are unsure candidates; a command/url/flag is a lead, not an answer.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
