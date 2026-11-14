#!/usr/bin/env python3
"""App code containers a mobile fixture can keep its puzzle in, beside assets/huntress_puzzle.json.

codec_search.py loads this module and asks it three things about one archive member. Nothing here
decides an answer: the readers only say what the member holds, and codec_search.py solves a
document found here as it solves any moved document (marked `doc-<format>` in the route, so the
answer is unsure until the judge accepts that route). Everything is plain Python over the bytes
in hand, bounded, and fails closed: a reader that does not recognise the bytes, or whose own
checks do not add up, gives nothing.

  docs(name, body, deadline)    -> [(object, format)]   puzzle-shaped objects the code holds
  strings(name, body, deadline) -> [(kind, bytes)]      the strings its author wrote, with their ends
  expand(name, body)            -> [(inner name, bytes)] assemblies packed inside the member
  pieces(name, body)            -> [(route, text)]      strings one method or one array puts together
  xor_codes(body, deadline)     -> {code: (route, key)} an answer code under a one-byte XOR or add
  dart_codes(body)              -> [code]               twenty-character Dart string objects that are a code

What is read (formats by their bytes, never by the member's name):

  hermes   Hermes bytecode (index.android.bundle, main.jsbundle of React Native). The string table
           gives every string with its true length (the storage packs them back to back and lets
           them overlap, so a scan for printable runs cuts them wrong). Object literals are put
           back together from the key and value buffers when the file's own counts line up; a
           string that is a JSON object is read as one. Versions 59 to 120 (checked on 84 and 98); the size of a function
           header is proved from the file (the string kind table must count exactly the strings).
  js       a JavaScript bundle as text: object literals that have a `codec` key, and string
           literals that are a JSON object (JSON.parse('...')).
  dex      beyond the string pool: each class's static fields with their initial values (the
           encoded array of static_values_off, and what a straight-line <clinit> stores: string,
           byte, int and char arrays), as one object per class with the field names as keys; the
           strings each method loads, in order.
  dotnet   .NET assemblies of a Xamarin or MAUI app: the user strings (#US heap) of every metadata
           root in the member, and the assemblies of a store (assemblies.blob, XABA) or of a
           member compressed one by one (XALZ, an LZ4 block) taken out for the other readers.
  native   printable runs (ASCII and UTF-16) of an ELF, Mach-O or Dart AOT snapshot (libapp.so)
           over the whole member, not its first megabyte; and a Dart string object of exactly
           twenty characters that is a code, read by its length field (the next object's header
           may follow it with no byte between).
  xor      an answer code that sits in a native library, a dex or an assembly under ONE byte of
           XOR or of addition. It is proved by the result and by nothing else: the full form
           ANS-[0-9A-F]{16} with a non-alphanumeric byte on both sides under exactly that key. The
           routine itself is not read.

An IPA needs nothing of its own here: it is a zip whose puzzle sits at another path or in a
plist (asset_docs.py), and its Mach-O is read by `native` and `xor`.
"""
import json
import re
import struct
import time

MAX_STRINGS = 60000        # strings taken from one string table
MAX_TEXT = 4096            # bytes of one string that is kept
MAX_DOCS = 64              # objects one member may give
MAX_CLASSES = 4000         # classes of one dex that are read
MAX_INSNS = 200000         # code units of one dex that are walked
MAX_ARRAY = 4096           # elements of one array
MAX_ASSEMBLY = 8 << 20     # bytes one compressed assembly may inflate to
MAX_INNER = 256            # assemblies taken out of one store
MAX_EXPAND = 16 << 20      # bytes all the assemblies taken out of one store may inflate to
MAX_XALZ_TRIES = 2048      # XALZ marks of one member that are tried
MAX_KEY_HITS = 4096        # places of one member that are tried under one key byte
MAX_OBJECT = 8192          # bytes of one JavaScript object literal
HERMES_MAGIC = bytes.fromhex("c61fbc03c103191f")
SCHEMA_KEYS = ("codec", "data", "steps", "encoding")
_ANS = re.compile(rb"(?<![0-9A-Za-z])ANS-[0-9A-F]{16}(?![0-9A-Za-z])")


def _late(deadline) -> bool:
    return deadline is not None and time.perf_counter() >= deadline


def _puzzle_like(obj) -> bool:
    return isinstance(obj, dict) and any(k in obj or k.upper() in obj for k in SCHEMA_KEYS)


def _json_object(text):
    """The object a text is, when it is a JSON object from its first to its last character."""
    if not isinstance(text, str) or len(text) > 1 << 16 or text[:1] != "{" or text.rstrip()[-1:] != "}":
        return None
    try:
        obj = json.loads(text)
    except ValueError:
        return None
    return obj if isinstance(obj, dict) and obj else None


# ---------------------------------------------------------------------------- Hermes bytecode

def is_hermes(body) -> bool:
    return body[:8] == HERMES_MAGIC


def _align4(n: int) -> int:
    return (n + 3) & ~3


def hermes_layout(d):
    """The sections of a Hermes bytecode file that hold its strings and literals, or None.

    {version, kinds: [(count, is identifier)], small: offset, overflow: offset, storage: (offset,
    size), after: offset of the first section behind the storage, counts: the header's numbers}.
    The header is 128 bytes in every version read here and its first fields never moved. What
    did change is the size of one function header (16 bytes to version 96, 12 in the versions
    after), so it is not assumed: of the sizes tried, exactly one must leave a string kind table
    that counts exactly `stringCount` strings and a string table whose every entry lies inside the
    storage."""
    if not is_hermes(d) or len(d) < 128:
        return None
    version = struct.unpack_from("<I", d, 8)[0]
    if not 59 <= version <= 120:
        return None
    (file_length, _global, functions, kind_count, identifiers, string_count, overflow_count,
     storage_size) = struct.unpack_from("<8I", d, 32)
    if file_length > len(d) or string_count > MAX_STRINGS or kind_count > 64 or not string_count:
        return None
    fits = []
    for width in (16, 12, 8, 20, 24):
        at = _align4(128 + functions * width)
        if at + 4 * kind_count > len(d):
            continue
        kinds = [(v & 0x7FFFFFFF, bool(v >> 31)) for v in struct.unpack_from("<%dI" % kind_count, d, at)]
        if sum(c for c, _ in kinds) != string_count or sum(c for c, i in kinds if i) != identifiers:
            continue
        small = _align4(_align4(at + 4 * kind_count) + 4 * identifiers)
        over = _align4(small + 4 * string_count)
        storage = _align4(over + 8 * overflow_count)
        if storage + storage_size > len(d):
            continue
        fits.append((width, kinds, small, over, storage))
    if len(fits) != 1:
        return None
    width, kinds, small, over, storage = fits[0]
    return {"version": version, "kinds": kinds, "small": small, "overflow": over, "storage": (storage, storage_size),
            "after": _align4(storage + storage_size), "function_header": width,
            "counts": struct.unpack_from("<19I", d, 32), "overflow_count": overflow_count, "strings": string_count}


def hermes_strings(d):
    """[(text, is identifier)] of a Hermes file by string id, or None when the table does not add up.

    An entry is 1 bit UTF-16, 23 bits offset, 8 bits length; a length of 255 sends the reader to
    the overflow table, where the offset field is the index. A UTF-16 string's length counts code
    units. One entry outside the storage refuses the whole table."""
    lay = hermes_layout(d)
    if lay is None:
        return None
    base, size = lay["storage"]
    flags = [ident for count, ident in lay["kinds"] for _ in range(count)]
    out = []
    for i, entry in enumerate(struct.unpack_from("<%dI" % lay["strings"], d, lay["small"])):
        wide, off, ln = entry & 1, (entry >> 1) & 0x7FFFFF, entry >> 24
        if ln == 255:
            if off >= lay["overflow_count"]:
                return None
            off, ln = struct.unpack_from("<II", d, lay["overflow"] + 8 * off)
        nbytes = ln * 2 if wide else ln
        if off + nbytes > size:
            return None
        raw = d[base + off:base + off + nbytes]
        try:
            text = raw.decode("utf-16le") if wide else raw.decode("latin-1")
        except UnicodeDecodeError:
            text = raw.decode("utf-16le", "replace")
        out.append((text, flags[i]))
    return out


_SLP_WIDTH = {3: 8, 4: 4, 5: 2, 6: 1, 7: 4}   # number, long string, short string, byte string, integer


def _literals(buf, strings, runs=None):
    """The values of a serialized literal buffer in order, or None when it does not read to its end.

    A run is one tag byte (bit 7: a second byte extends the count to 12 bits; bits 4 to 6: the
    type; the rest: the count) and then `count` values of that type. Trailing zero bytes are
    padding (a zero tag would be a run of no nulls). `runs`, when given, receives (byte offset of
    the run, index of its first value, count) for each run."""
    out, i = [], 0
    while i < len(buf):
        tag = buf[i]
        if tag == 0 and not any(buf[i:]):
            break
        at = i
        kind = (tag >> 4) & 7
        if tag & 0x80:
            if i + 1 >= len(buf):
                return None
            count, i = ((tag & 0x0F) << 8) | buf[i + 1], i + 2
        else:
            count, i = tag & 0x0F, i + 1
        if not count:
            return None
        width = _SLP_WIDTH.get(kind, 0)
        if i + width * count > len(buf) or len(out) + count > MAX_STRINGS:
            return None
        if runs is not None:
            runs.append((at, len(out), count))
        for _ in range(count):
            raw = buf[i:i + width]
            i += width
            if kind == 0:
                out.append(None)
            elif kind in (1, 2):
                out.append(kind == 1)
            elif kind == 3:
                v = struct.unpack("<d", raw)[0]
                out.append(int(v) if v == int(v) and abs(v) < 1 << 53 else v)
            elif kind == 7:
                out.append(struct.unpack("<i", raw)[0])
            else:
                sid = int.from_bytes(raw, "little")
                if sid >= len(strings):
                    return None
                out.append(strings[sid][0])
    return out


def _take(buf, at, n, strings):
    """Exactly n values read from byte `at` of a literal buffer (whole runs), or None."""
    got = _literals_from(buf, at, n, strings)
    return got if got is not None and len(got) == n else None


def _literals_from(buf, at, n, strings):
    out, i = [], at
    while len(out) < n:
        if i >= len(buf):
            return None
        tag = buf[i]
        kind = (tag >> 4) & 7
        if tag & 0x80:
            if i + 1 >= len(buf):
                return None
            count, i = ((tag & 0x0F) << 8) | buf[i + 1], i + 2
        else:
            count, i = tag & 0x0F, i + 1
        width = _SLP_WIDTH.get(kind, 0)
        if not count or len(out) + count > n or i + width * count > len(buf):
            return None
        part = _literals(buf[i - (2 if tag & 0x80 else 1):i + width * count], strings)
        if part is None:
            return None
        out += part
        i += width * count
    return out


MAX_WINDOW = 1 << 16       # bytes of a value buffer that are searched for one object's values


def hermes_objects(d, strings=None, known=None, deadline=None):
    """([object literals of a Hermes file as dicts], how they were cut) or ([], '').

    To version 96 the header gives an array buffer, a key buffer and a value buffer; later
    versions give one literal value buffer, a key buffer and a shape table of (key offset, key
    count). Which values belong to which keys is said only by the instruction that builds the
    object, and instructions are not read here; the compiler also stores one key list for all
    objects that share it and packs both buffers so that one literal's bytes may overlap the
    next. So objects are given only where the buffers say it themselves:

      exact    both buffers read from their first byte to their last, and the key buffer holds
               exactly as many keys as the value buffer holds values (every object once, in order,
               no array literal among them). The cut between two objects is the shape table's, or
               without one the key buffer's own runs.
      window   otherwise, for a key list that has `codec` (a shape of the table; without a table
               any run of string keys in the key buffer): the ONE place in the value buffer where
               that many values read as whole runs, the value under `codec` is a codec name
               `known` recognises and the value under `data` (when there is one) is a text. Two
               such places are nothing."""
    lay = hermes_layout(d)
    strings = strings if strings is not None else hermes_strings(d)
    if lay is None or strings is None:
        return [], ""
    c = lay["counts"]
    # counts[8..]: bigIntCount, bigIntStorageSize (from version 87), regExpCount, regExpStorageSize,
    # then the three buffer sizes. Before 87 the two bigint fields are not there.
    at = 10 if lay["version"] >= 87 else 8
    array_size, key_size, third = c[at + 2], c[at + 3], c[at + 4]
    a0 = lay["after"]
    k0 = _align4(a0 + array_size)
    v0 = _align4(k0 + key_size)
    if v0 > len(d) or max(array_size, key_size) > 1 << 22:
        return [], ""
    keybuf = d[k0:k0 + key_size]
    shaped = lay["function_header"] != 16       # the layout with a shape table
    if shaped:
        if v0 + 8 * third > len(d) or third > MAX_STRINGS:
            return [], ""
        valbuf = d[a0:a0 + array_size]
        shapes = [struct.unpack_from("<II", d, v0 + 8 * k) for k in range(third)]
    else:
        if v0 + third > len(d) or third > 1 << 22:
            return [], ""
        valbuf, shapes = d[v0:v0 + third], None
    # exact: both buffers read whole and count the same
    key_runs = []
    keys = _literals(keybuf, strings, key_runs)
    values = _literals(valbuf, strings)
    if keys and values is not None and len(keys) == len(values) and all(isinstance(k, str) for k in keys):
        starts = {off: i for off, i, _ in key_runs}
        cuts = ([(starts.get(off, -1), n) for off, n in shapes] if shapes is not None else [(i, n) for _, i, n in key_runs])
        out, i = [], 0
        for first, n in cuts:
            if first != i:
                out = None
                break
            out.append(dict(zip(keys[i:i + n], values[i:i + n])))
            i += n
        if out and i == len(keys):
            return out[:MAX_STRINGS], "exact"
    if known is None or len(valbuf) > MAX_WINDOW:
        return [], ""
    # window: the key lists that have `codec`, each looked for at every byte of the value buffer
    lists = []
    if shapes is not None:
        for off, n in shapes:
            names = _take(keybuf, off, n, strings) if 0 < n <= 64 else None
            if names:
                lists.append(names)
    else:
        for off in range(len(keybuf)):
            if not off & 1023 and _late(deadline):
                return [], ""
            if len(lists) > MAX_STRINGS:
                break
            tag = keybuf[off]
            if (tag >> 4) & 7 in (4, 5, 6) and not tag & 0x80 and tag & 0x0F:
                names = _take(keybuf, off, tag & 0x0F, strings)
                if names:
                    lists.append(names)
    out, seen = [], set()
    for names in lists:
        if "codec" not in names or len(set(names)) != len(names) or not all(isinstance(k, str) for k in names) \
                or tuple(names) in seen:
            continue
        seen.add(tuple(names))
        n, ci = len(names), names.index("codec")
        di = names.index("data") if "data" in names else None
        fits = []
        for o in range(len(valbuf)):
            if _late(deadline):
                return [], ""
            vals = _take(valbuf, o, n, strings)
            if vals and isinstance(vals[ci], str) and known(vals[ci].strip().lower()) \
                    and (di is None or isinstance(vals[di], str)) and vals not in fits:
                fits.append(vals)
        if len(fits) == 1:
            out.append(dict(zip(names, fits[0])))
    return out, "window" if out else ""


# ---------------------------------------------------------------------------- JavaScript text

_JS_KEY = re.compile(r"""(?<![\w$.])(?:["']codec["']|codec)\s*:""")
_JS_IDENT = re.compile(r"[A-Za-z_$][\w$]*")
_JS_NUMBER = re.compile(r"-?(?:0[xX][0-9a-fA-F]+|(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)")
_JS_ESC = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}


class _NotLiteral(ValueError):
    pass


def _js_value(s, i, depth=0):
    """(value, next index) for the JavaScript literal at s[i:], or _NotLiteral for anything computed."""
    if depth > 8:
        raise _NotLiteral
    i = _js_space(s, i)
    c = s[i:i + 1]
    if c == "{":
        out, i = {}, _js_space(s, i + 1)
        while s[i:i + 1] != "}":
            if s[i:i + 1] in "\"'":
                key, i = _js_string(s, i)
            else:
                m = _JS_IDENT.match(s, i) or _JS_NUMBER.match(s, i)
                if not m:
                    raise _NotLiteral
                key, i = m.group(0), m.end()
            i = _js_space(s, i)
            if s[i:i + 1] != ":":
                raise _NotLiteral
            out[key], i = _js_value(s, i + 1, depth + 1)
            i = _js_space(s, i)
            if s[i:i + 1] == ",":
                i = _js_space(s, i + 1)
            elif s[i:i + 1] != "}":
                raise _NotLiteral
            if len(out) > 400:
                raise _NotLiteral
        return out, i + 1
    if c == "[":
        out, i = [], _js_space(s, i + 1)
        while s[i:i + 1] != "]":
            v, i = _js_value(s, i, depth + 1)
            out.append(v)
            i = _js_space(s, i)
            if s[i:i + 1] == ",":
                i = _js_space(s, i + 1)
            elif s[i:i + 1] != "]":
                raise _NotLiteral
            if len(out) > MAX_ARRAY:
                raise _NotLiteral
        return out, i + 1
    if c and c in "\"'`":
        v, i = _js_string(s, i)
        while True:                               # "a" + "b": minifiers and authors both write it
            j = _js_space(s, i)
            if s[j:j + 1] != "+":
                return v, i
            j = _js_space(s, j + 1)
            if s[j:j + 1] not in ("\"", "'", "`") or not s[j:j + 1]:
                raise _NotLiteral
            more, i = _js_string(s, j)
            v += more
    if s.startswith("!0", i):
        return True, i + 2
    if s.startswith("!1", i):
        return False, i + 2
    if s.startswith("void 0", i):
        return None, i + 6
    m = _JS_NUMBER.match(s, i)
    if m:
        t = m.group(0)
        try:
            v = int(t, 16) if t.lstrip("-")[:2].lower() == "0x" else (int(t) if re.fullmatch(r"-?\d+", t) else float(t))
        except ValueError:
            raise _NotLiteral from None
        return v, m.end()
    m = _JS_IDENT.match(s, i)
    if m and m.group(0) in ("true", "false", "null", "undefined"):
        return {"true": True, "false": False}.get(m.group(0)), m.end()
    raise _NotLiteral


def _js_space(s, i):
    while True:
        while s[i:i + 1].isspace():
            i += 1
        if s.startswith("//", i):
            j = s.find("\n", i)
            i = len(s) if j < 0 else j + 1
        elif s.startswith("/*", i):
            j = s.find("*/", i)
            if j < 0:
                raise _NotLiteral
            i = j + 2
        else:
            return i


def _js_string(s, i):
    quote, out, i = s[i], [], i + 1
    while True:
        if i >= len(s) or len(out) > 1 << 16:
            raise _NotLiteral
        c = s[i]
        if c == quote:
            return "".join(out), i + 1
        if c == "\n" and quote != "`":
            raise _NotLiteral
        if c == "$" and quote == "`" and s[i + 1:i + 2] == "{":
            raise _NotLiteral                     # a template with a computed part
        if c != "\\":
            out.append(c)
            i += 1
            continue
        e = s[i + 1:i + 2]
        try:
            if e == "x":
                out.append(chr(int(s[i + 2:i + 4], 16)))
                i += 4
            elif e == "u" and s[i + 2:i + 3] == "{":
                j = s.index("}", i)
                out.append(chr(int(s[i + 3:j], 16)))
                i = j + 1
            elif e == "u":
                out.append(chr(int(s[i + 2:i + 6], 16)))
                i += 6
            elif e == "\n":
                i += 2
            else:
                out.append(_JS_ESC.get(e, e))
                i += 2
        except (ValueError, IndexError):
            raise _NotLiteral from None
        if not e:
            raise _NotLiteral


_JS_STR = re.compile(r"""(["'])(\{(?:\\.|(?!\1)[^\\\n])*\})\1""")


def js_objects(text, deadline=None):
    """Puzzle-shaped objects written in a JavaScript text: an object literal that has a `codec` key
    (the innermost literal around each such key that reads as a literal from brace to brace), and
    a string literal that is itself a JSON object with a puzzle field."""
    out, seen = [], set()
    for m in _JS_KEY.finditer(text):
        if len(out) >= MAX_DOCS or _late(deadline):
            break
        j = m.start()
        low = max(0, j - MAX_OBJECT)
        while True:
            j = text.rfind("{", low, j)
            if j < 0:
                break
            try:
                obj, end = _js_value(text, j)
            except (_NotLiteral, IndexError, RecursionError):
                continue
            if end > m.start() and isinstance(obj, dict) and "codec" in obj:
                if (j, end) not in seen:
                    seen.add((j, end))
                    if obj not in out:
                        out.append(obj)
                break
    for m in _JS_STR.finditer(text):
        if len(out) >= MAX_DOCS or _late(deadline):
            break
        try:
            inner, _ = _js_string(text, m.start())
        except (_NotLiteral, IndexError):
            continue
        obj = _json_object(inner)
        if _puzzle_like(obj) and obj not in out:
            out.append(obj)
    return out


def is_js(body) -> bool:
    """A member that is JavaScript text worth reading: no NUL, a word of the language near its head."""
    head = body[:4096]
    return (b"\0" not in head and bool(re.search(rb"\b(function|var |const |let |=>|__d\(|module\.exports|require\()", head))
            and head.lstrip()[:1] not in (b"<",))


# ---------------------------------------------------------------------------- DEX

# code units of one instruction, by opcode (Dalvik bytecode, "Summary of bytecode set")
_DEX_WIDTH = [1] * 256
for _lo, _hi, _w in ((0x02, 0x02, 2), (0x03, 0x03, 3), (0x05, 0x05, 2), (0x06, 0x06, 3), (0x08, 0x08, 2), (0x09, 0x09, 3),
                     (0x13, 0x13, 2), (0x14, 0x14, 3), (0x15, 0x16, 2), (0x17, 0x17, 3), (0x18, 0x18, 5), (0x19, 0x1A, 2),
                     (0x1B, 0x1B, 3), (0x1C, 0x1C, 2), (0x1F, 0x20, 2), (0x22, 0x23, 2), (0x24, 0x26, 3), (0x29, 0x29, 2),
                     (0x2A, 0x2C, 3), (0x2D, 0x3D, 2), (0x44, 0x6D, 2), (0x6E, 0x72, 3), (0x74, 0x78, 3), (0x90, 0xAF, 2),
                     (0xD0, 0xE2, 2), (0xFA, 0xFB, 4), (0xFC, 0xFD, 3), (0xFE, 0xFF, 2)):
    for _op in range(_lo, _hi + 1):
        _DEX_WIDTH[_op] = _w
_DEX_BRANCH = set(range(0x27, 0x3E)) - set(range(0x2D, 0x32))   # throw, goto, switches, if-*: a <clinit> is read up to one


class DexError(ValueError):
    """Malformed or unsupported DEX data."""


def is_dex(body) -> bool:
    return isinstance(body, (bytes, bytearray)) and body[:4] == b"dex\n" and len(body) >= 0x70


def _uleb(d, i):
    if not isinstance(i, int) or i < 0:
        raise DexError("uleb128 offset")
    v = shift = 0
    for _ in range(5):
        if i >= len(d):
            raise DexError("cut uleb128")
        b = d[i]
        i += 1
        if shift == 28 and b > 0x0F:
            raise DexError("uleb128 overflow")
        v |= (b & 0x7F) << shift
        if not b & 0x80:
            return v, i
        shift += 7
    raise DexError("uleb128 overflow")


class Dex:
    """The id tables of one dex file. Every index is checked by the slice it reads."""

    def __init__(self, d):
        if not is_dex(d):
            raise DexError("not a dex file")
        self.d = bytes(d)
        (self.n_str, self.o_str, self.n_type, self.o_type, _np, _op, self.n_field, self.o_field,
         self.n_method, self.o_method, self.n_class, self.o_class) = struct.unpack_from("<12I", d, 0x38)
        for count, offset, width in ((self.n_str, self.o_str, 4), (self.n_type, self.o_type, 4),
                                     (_np, _op, 12), (self.n_field, self.o_field, 8),
                                     (self.n_method, self.o_method, 8), (self.n_class, self.o_class, 32)):
            if count > 1 << 20 or offset > len(d) or count * width > len(d) - offset:
                raise DexError("an id table that is cut or too large")
        self._s = {}

    def _read(self, fmt, offset):
        if not isinstance(offset, int) or offset < 0 or offset + struct.calcsize(fmt) > len(self.d):
            raise DexError("cut DEX item")
        return struct.unpack_from(fmt, self.d, offset)

    @staticmethod
    def _index(i, count):
        if not isinstance(i, int) or not 0 <= i < count:
            raise DexError("DEX index")

    def string(self, i) -> str:
        self._index(i, self.n_str)
        if i not in self._s:
            o = self._read("<I", self.o_str + 4 * i)[0]
            _, o = _uleb(self.d, o)
            end = self.d.find(b"\0", o)
            if end < 0:
                raise DexError("unterminated DEX string")
            try:
                # DEX MUTF-8 uses C0 80 for NUL and UTF-16 surrogate pairs.
                value = self.d[o:end].replace(b"\xc0\x80", b"\0").decode("utf-8", "surrogatepass")
                self._s[i] = value.encode("utf-16le", "surrogatepass").decode("utf-16le", "surrogatepass")
            except UnicodeError as exc:
                raise DexError("invalid DEX string") from exc
        return self._s[i]

    def type(self, i) -> str:
        self._index(i, self.n_type)
        return self.string(self._read("<I", self.o_type + 4 * i)[0])

    def field(self, i):
        self._index(i, self.n_field)
        cls, typ, name = self._read("<HHI", self.o_field + 8 * i)
        return self.type(cls), self.type(typ), self.string(name)

    def method(self, i):
        self._index(i, self.n_method)
        cls, _proto, name = self._read("<HHI", self.o_method + 8 * i)
        return self.type(cls), self.string(name)

    def value(self, i):
        """(value, next index) of the encoded_value at i."""
        return self._value(i, 0)

    def _value(self, i, depth):
        d = self.d
        self._index(i, len(d))
        if depth > 64:
            raise DexError("encoded value nesting exceeds cap")
        arg, kind = d[i] >> 5, d[i] & 0x1F
        i += 1
        max_arg = {0x00: 0, 0x02: 1, 0x03: 1, 0x04: 3, 0x06: 7, 0x10: 3,
                   0x11: 7, 0x15: 3, 0x16: 3, 0x17: 3, 0x18: 3, 0x19: 3,
                   0x1A: 3, 0x1B: 3, 0x1C: 0, 0x1D: 0, 0x1E: 0, 0x1F: 1}
        if arg > max_arg.get(kind, 7):
            raise DexError("invalid encoded value width")
        if kind == 0x1F:
            return bool(arg), i
        if kind == 0x1E:
            return None, i
        if kind == 0x1C:
            n, i = _uleb(d, i)
            if n > MAX_ARRAY:
                raise DexError("an encoded array that is too long")
            out = []
            for _ in range(n):
                v, i = self._value(i, depth + 1)
                out.append(v)
            return out, i
        if kind == 0x1D:
            raise DexError("an annotation as a value")
        raw = d[i:i + arg + 1]
        if len(raw) != arg + 1:
            raise DexError("cut value")
        i += arg + 1
        if kind in (0x00, 0x02, 0x04, 0x06):
            return int.from_bytes(raw, "little", signed=True), i
        if kind == 0x03:
            return chr(int.from_bytes(raw, "little")), i
        if kind == 0x17:
            return self.string(int.from_bytes(raw, "little")), i
        if kind == 0x10:
            return struct.unpack("<f", raw.rjust(4, b"\0"))[0], i      # float: zero-extended to the right
        if kind == 0x11:
            return struct.unpack("<d", raw.rjust(8, b"\0"))[0], i
        return None, i                                                    # a type, field, method or enum reference

    def classes(self):
        """(class descriptor, [static field ids in order], static_values_off, [(method id, code offset)])."""
        d = self.d
        for c in range(min(self.n_class, MAX_CLASSES)):
            cls, _acc, _sup, _if, _src, _ann, data_off, static_off = self._read("<8I", self.o_class + 32 * c)
            fields, methods = [], []
            if data_off:
                ns, i = _uleb(d, data_off)
                ni, i = _uleb(d, i)
                nd, i = _uleb(d, i)
                nv, i = _uleb(d, i)
                if max(ns, ni, nd, nv) > 1 << 16:
                    raise DexError("class data that is too large")
                idx = 0
                for k in range(ns + ni):
                    if k == ns:
                        idx = 0
                    diff, i = _uleb(d, i)
                    _, i = _uleb(d, i)
                    idx += diff
                    if k < ns:
                        fields.append(idx)
                idx = 0
                for k in range(nd + nv):
                    if k == nd:
                        idx = 0
                    diff, i = _uleb(d, i)
                    _, i = _uleb(d, i)
                    code, i = _uleb(d, i)
                    idx += diff
                    methods.append((idx, code))
            yield self.type(cls), fields, static_off, methods

    def code(self, off):
        """The instructions of a code item as a list of 16-bit code units."""
        self._index(off, len(self.d))
        n = self._read("<I", off + 12)[0]
        if n > MAX_INSNS or off + 16 + 2 * n > len(self.d):
            raise DexError("a code item that is cut or too long")
        return self._read("<%dH" % n, off + 16)


def _dex_walk(insns):
    """(index, opcode) for each instruction, skipping the data tables that sit among them."""
    i, n = 0, len(insns)
    while i < n:
        unit = insns[i]
        op = unit & 0xFF
        if op == 0 and unit in (0x0100, 0x0200, 0x0300):
            if unit == 0x0100:
                size = 4 + 2 * insns[i + 1]
            elif unit == 0x0200:
                size = 2 + 4 * insns[i + 1]
            else:
                width, count = insns[i + 1], insns[i + 2] | (insns[i + 3] << 16)
                size = 4 + (width * count + 1) // 2
            i += size
            continue
        yield i, op
        i += _DEX_WIDTH[op]


def _fill_payload(insns, at):
    """The elements of the fill-array-data table at code unit `at`: (element width, [unsigned values])."""
    if insns[at] != 0x0300:
        raise ValueError("no array data where the instruction points")
    width, count = insns[at + 1], insns[at + 2] | (insns[at + 3] << 16)
    if width not in (1, 2, 4, 8) or count > MAX_ARRAY:
        raise ValueError("array data that is not read")
    units = insns[at + 4:at + 4 + (width * count + 1) // 2]
    raw = struct.pack("<%dH" % len(units), *units)[:width * count]
    if len(raw) != width * count:
        raise ValueError("array data that is cut")
    return width, [int.from_bytes(raw[k:k + width], "little") for k in range(0, len(raw), width)]


def _signed(v, bits):
    return v - (1 << bits) if v >> (bits - 1) else v


def _clinit(dex, insns, owner):
    """{field name: value} a class initializer stores into its own static fields, read up to its
    first branch. Registers hold what straight-line code put there: constants, strings, new arrays
    and what was stored into them; anything a call or an arithmetic step made is unknown."""
    reg, out = {}, {}
    unknown = object()
    result = unknown                                       # what the last filled-new-array made
    for i, op in _dex_walk(insns):
        u = insns[i]
        a = u >> 8
        if op in _DEX_BRANCH or op == 0x0E:
            break
        if op == 0x0C:                                     # move-result-object vAA
            reg[a], result = result, unknown
            continue
        if op == 0x24:                                     # filled-new-array {vC..vG}, type
            count, rest = u >> 12, insns[i + 2]
            regs = [(rest >> (4 * k)) & 0xF for k in range(4)] + [(u >> 8) & 0xF]
            vals = [reg.get(r, unknown) for r in regs[:count]]
            kind = dex.type(insns[i + 1])
            result = (vals, kind) if count <= 5 and all(isinstance(v, (int, str)) for v in vals) else unknown
            continue
        result = unknown
        if op == 0x12:                                     # const/4 vA, #+B
            reg[a & 0xF] = _signed(a >> 4, 4)
        elif op == 0x13:                                   # const/16
            reg[a] = _signed(insns[i + 1], 16)
        elif op == 0x14:                                   # const
            reg[a] = _signed(insns[i + 1] | (insns[i + 2] << 16), 32)
        elif op == 0x15:                                   # const/high16
            reg[a] = _signed(insns[i + 1] << 16, 32)
        elif op == 0x1A:                                   # const-string
            reg[a] = dex.string(insns[i + 1])
        elif op == 0x1B:
            reg[a] = dex.string(insns[i + 1] | (insns[i + 2] << 16))
        elif op in (0x01, 0x07):                           # move, move-object vA, vB
            reg[a & 0xF] = reg.get(a >> 4, unknown)
        elif op in (0x02, 0x08):
            reg[a] = reg.get(insns[i + 1], unknown)
        elif op == 0x23:                                   # new-array vA, vB(size), type
            size = reg.get(a >> 4, unknown)
            kind = dex.type(insns[i + 1])
            reg[a & 0xF] = ([None] * size, kind) if isinstance(size, int) and 0 <= size <= MAX_ARRAY else unknown
        elif op == 0x26:                                   # fill-array-data vAA, +BBBBBBBB
            arr = reg.get(a, unknown)
            off = _signed(insns[i + 1] | (insns[i + 2] << 16), 32)
            if isinstance(arr, tuple):
                width, values = _fill_payload(insns, i + off)
                if len(values) == len(arr[0]):
                    signed = [_signed(v, 8 * width) for v in values]
                    arr[0][:] = [chr(v) for v in values] if arr[1] == "[C" else signed
        elif 0x4B <= op <= 0x51:                           # aput*: vAA value, vBB array, vCC index
            arr, idx = reg.get(insns[i + 1] & 0xFF, unknown), reg.get(insns[i + 1] >> 8, unknown)
            val = reg.get(a, unknown)
            if isinstance(arr, tuple) and isinstance(idx, int) and 0 <= idx < len(arr[0]):
                arr[0][idx] = None if val is unknown else (chr(val) if arr[1] == "[C" and isinstance(val, int) else val)
        elif 0x67 <= op <= 0x6D:                           # sput*: vAA, field
            cls, _typ, name = dex.field(insns[i + 1])
            val = reg.get(a, unknown)
            if cls == owner and val is not unknown:
                if isinstance(val, tuple):
                    if any(x is None for x in val[0]):
                        continue                           # an element the walk did not see: not a value
                    val = bytes(x & 0xFF for x in val[0]) if val[1] == "[B" else (
                        "".join(val[0]) if val[1] == "[C" else list(val[0]))
                out[name] = val
        else:
            # anything else that writes a register makes it unknown: the destination is vA (4 bits)
            # for the 12x forms and vAA otherwise; clearing both is the safe reading
            if op in (0x0A, 0x0B, 0x0D, 0x16, 0x17, 0x18, 0x19, 0x1C, 0x1F, 0x20, 0x21, 0x22, 0x24, 0x25) \
                    or 0x44 <= op <= 0x4A or 0x52 <= op <= 0x58 or 0x60 <= op <= 0x66 or 0x7B <= op <= 0xE2:
                reg[a] = unknown
                reg[a & 0xF] = unknown
            if 0x6E <= op <= 0x78 or op == 0x25:           # a call may write into any array it was given
                for k, v in list(reg.items()):
                    if isinstance(v, tuple):
                        reg[k] = unknown
    return out


_FRAMEWORK_CLASS = re.compile(r"L(android|androidx|kotlin|kotlinx|java|javax|dalvik|com/google|okhttp3|okio|org/intellij|"
                              r"org/jetbrains)/")


_DEX_MEMO = [None, None]   # the last dex read to its end, and what it gave (the same bytes object, never a copy)


def dex_classes(d, deadline=None):
    """[{class, fields: {name: value}, methods: [(name, [strings loaded, in order])], arrays: [...]}]
    for the classes of a dex file that the app's author wrote, or [] when the file does not read."""
    if _DEX_MEMO[0] is d:
        return _DEX_MEMO[1]
    try:
        dex = Dex(d)
        out = []
        for cls, field_ids, static_off, methods in dex.classes():
            if _late(deadline):
                return out
            if _FRAMEWORK_CLASS.match(cls):
                continue
            fields = {}
            try:
                if static_off:
                    values, _ = _encoded_array(dex, static_off)
                    for fid, v in zip(field_ids, values):
                        if v is not None:
                            fields[dex.field(fid)[2]] = v
            except (ValueError, IndexError, struct.error):
                fields = {}
            loaded, cut = [], False
            for mid, code in methods:
                if not code:
                    continue
                if _late(deadline):                        # one class may name 65536 methods of 200000 units each
                    cut = True
                    break
                try:
                    insns = dex.code(code)
                    name = dex.method(mid)[1]
                    strs = []
                    for i, op in _dex_walk(insns):
                        if op == 0x1A:
                            strs.append(dex.string(insns[i + 1]))
                        elif op == 0x1B:
                            strs.append(dex.string(insns[i + 1] | (insns[i + 2] << 16)))
                    if name == "<clinit>":
                        for k, v in _clinit(dex, insns, cls).items():
                            fields.setdefault(k, v)
                    if strs:
                        loaded.append((name, strs))
                except (ValueError, IndexError, struct.error):
                    continue
            if cut:                                        # a class read in part is not given at all
                return out
            if fields or loaded:
                out.append({"class": cls, "fields": fields, "methods": loaded})
        else:
            _DEX_MEMO[:] = [d, out]                        # read to its end: docs() and pieces() ask for the same file
        return out
    except (ValueError, IndexError, struct.error):
        return []


def _encoded_array(dex, off):
    n, i = _uleb(dex.d, off)
    if n > MAX_ARRAY:
        raise ValueError("static values that are too many")
    out = []
    for _ in range(n):
        v, i = dex.value(i)
        out.append(v)
    return out, i


def _field_doc(fields):
    """A class's static fields as a document: bytes as text when they are printable, else as hex."""
    doc = {}
    for k, v in fields.items():
        if isinstance(v, bytes):
            v = v.decode("ascii") if v and all(32 <= c < 127 for c in v) else v.hex()
        if isinstance(v, float) and v != v:
            continue
        doc[k] = v
    return doc


# ---------------------------------------------------------------------------- .NET (Xamarin, MAUI)

def lz4_block(src, size, deadline=None, head=b""):
    """An LZ4 block inflated to exactly `size` bytes, or None. Stops when the output is full, so
    bytes after the block (the next assembly of a store) do no harm. `head`, when given, is what
    the output must begin with: a block that begins otherwise is given up at its first bytes, not
    after it has been inflated whole. Past `deadline` the block is given up (None)."""
    if size > MAX_ASSEMBLY:
        return None
    out, i, n, turns, checked = bytearray(), 0, len(src), 0, not head
    try:
        while len(out) < size:
            turns += 1
            if not turns & 255 and _late(deadline):
                return None
            if not checked and len(out) >= len(head):
                checked = True
                if not out.startswith(head):
                    return None
            token = src[i]
            i += 1
            lit = token >> 4
            if lit == 15:
                while True:
                    b = src[i]
                    i += 1
                    lit += b
                    if b != 255:
                        break
            if i + lit > n:
                return None
            out += src[i:i + lit]
            i += lit
            if len(out) >= size:
                break
            off = src[i] | (src[i + 1] << 8)
            i += 2
            if not off or off > len(out):
                return None
            mlen = (token & 15) + 4
            if (token & 15) == 15:
                while True:
                    b = src[i]
                    i += 1
                    mlen += b
                    if b != 255:
                        break
            if len(out) + mlen > size:
                return None                                # a match that runs past the stated size
            start = len(out) - off
            if off >= mlen:
                out += out[start:start + mlen]
            else:                                          # an overlapping match repeats its last `off` bytes
                unit = bytes(out[start:])
                out += (unit * (mlen // off + 1))[:mlen]
    except IndexError:
        return None
    return bytes(out) if len(out) == size and out.startswith(head) else None


def xalz(body, at=0, deadline=None, room=MAX_ASSEMBLY):
    """The assembly of an XALZ header at `at` (magic, descriptor index, inflated size, LZ4 block), or
    None: also when it states more than `room` bytes or is not inflated by `deadline`."""
    if body[at:at + 4] != b"XALZ" or len(body) < at + 12:
        return None
    size = struct.unpack_from("<I", body, at + 8)[0]
    if not 2 <= size <= room:
        return None
    out = lz4_block(body[at + 12:at + 12 + size + size // 255 + 64], size, deadline, b"MZ")
    return out if out and out[:2] == b"MZ" else None


def has_assemblies(body) -> bool:
    return body[:4] in (b"XABA", b"XALZ") or (body[:4] == b"\x7fELF" and b"XABA" in body[:1 << 16])


def dotnet_strings(body, deadline=None):
    """The user strings (#US heap) of every .NET metadata root in the bytes, in heap order.

    A root is `BSJB`, two version words, a reserved word, a version text, flags and the stream
    headers (offset, size, name). An entry of #US is a compressed length, UTF-16 text and one flag
    byte. A root or a heap that does not read gives nothing for that root."""
    out, at = [], 0
    while len(out) < MAX_STRINGS and not _late(deadline):
        at = body.find(b"BSJB", at)
        if at < 0:
            break
        root, at = at, at + 4
        try:
            vlen = struct.unpack_from("<I", body, root + 12)[0]
            if vlen > 255:
                continue
            p = root + 16 + vlen
            streams = struct.unpack_from("<H", body, p + 2)[0]
            p += 4
            for _ in range(min(streams, 16)):
                off, size = struct.unpack_from("<II", body, p)
                end = body.index(b"\0", p + 8, p + 8 + 33)
                name = body[p + 8:end]
                p = p + 8 + _align4(end - (p + 8) + 1)
                if name != b"#US":
                    continue
                i, stop = root + off, min(root + off + size, len(body))
                while i < stop and len(out) < MAX_STRINGS:
                    b = body[i]
                    if b < 0x80:
                        ln, i = b, i + 1
                    elif b < 0xC0:
                        ln, i = ((b & 0x3F) << 8) | body[i + 1], i + 2
                    else:
                        ln, i = ((b & 0x1F) << 24) | (body[i + 1] << 16) | (body[i + 2] << 8) | body[i + 3], i + 4
                    if i + ln > stop:
                        break
                    if ln > 1:
                        out.append(body[i:i + ln - 1].decode("utf-16le", "replace"))
                    i += ln
        except (struct.error, ValueError, IndexError):
            continue
    return out


def expand(name, body, deadline=None, room=MAX_EXPAND):
    """[(inner name, bytes)]: the assemblies a member packs under XALZ (one compressed assembly, or
    a store of them: assemblies.blob, libassemblies.<abi>.blob.so). Assemblies a store keeps as
    they are need no taking out: dotnet_strings reads every metadata root of the member.

    Bounded three ways, because a store is read on a clock and inflating is Python: at most
    MAX_INNER assemblies, at most `room` bytes inflated in all (an assembly that would pass it is
    left out), and nothing after `deadline`. A block whose first bytes are not `MZ` is dropped
    there. Review of 2026-10-08: a hundred headers that each stated 8 MiB took 27 s."""
    out, at, tries = [], 0, 0
    if not (has_assemblies(body) or b"XALZ" in body[:1 << 16]):
        return out
    while len(out) < MAX_INNER and tries < MAX_XALZ_TRIES and room >= 2 and not _late(deadline):
        at = body.find(b"XALZ", at)
        if at < 0:
            break
        tries += 1
        dll = xalz(body, at, deadline, room)
        if dll:
            out.append(("%s!xalz-%d.dll" % (name, len(out)), dll))
            room -= len(dll)
        at += 4
    return out


# ---------------------------------------------------------------------------- native code

_MACHO = (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe")
_RUN = re.compile(rb"[\x20-\x7e]{4,512}")
_WIDE = re.compile(rb"(?:[\x20-\x7e]\x00){4,512}")


def is_native(body) -> bool:
    return body[:4] == b"\x7fELF" or body[:4] in _MACHO or (body[:2] == b"MZ" and b"PE\0\0" in body[:1024])


def native_strings(body, limit=20000, deadline=None):
    """Printable runs of the whole member (ASCII of 4 to 512 characters, then UTF-16), each once,
    in file order. A Dart AOT snapshot keeps its one-byte strings as raw bytes between object
    headers, so its strings are runs like any other."""
    out = {}
    for rx, wide in ((_RUN, False), (_WIDE, True)):
        for m in rx.finditer(body):
            if len(out) >= limit or _late(deadline):
                return list(out)
            s = m.group(0)
            out.setdefault(s[::2] if wide else s, None)
    return list(out)


_DART = re.compile(rb"(?:\x28\x00\x00\x00|\x28\x00{7})(ANS-[0-9A-F]{16})")
_DART_WIDE = re.compile(rb"(?:\x28\x00\x00\x00|\x28\x00{7})((?:A\x00N\x00S\x00-\x00)(?:[0-9A-F]\x00){16})")


def dart_codes(body):
    """[answer code] a Dart AOT snapshot holds as a string object of exactly twenty characters.

    A Dart string in the snapshot's data is its length as a Smi (the length doubled: 0x28 for twenty,
    in four bytes with compressed pointers, else eight) and then the characters, padded to the
    object alignment. Twelve header bytes and twenty characters are thirty-two, so nothing may
    separate the code from the next object's header, and a scan that wants a non-alphanumeric byte
    after the code can miss it. Here the length field is the proof of where the string ends. The
    layout is the VM's as documented, not checked against a snapshot a real Flutter build wrote."""
    if body[:4] != b"\x7fELF":
        return []
    out = [m.group(1).decode() for m in _DART.finditer(body)]
    out += [m.group(1).decode("utf-16-le") for m in _DART_WIDE.finditer(body)]
    return list(dict.fromkeys(out))


_KEY_NEEDLE = {"xor": bytes(a ^ b for a, b in zip(b"ANS", b"NS-")),
               "add": bytes((b - a) & 0xFF for a, b in zip(b"ANS", b"NS-"))}


def _neighbour_differences(body, kind):
    """bytes d with d[i] = body[i] ^ body[i+1] (`xor`) or (body[i+1] - body[i]) mod 256 (`add`).

    Under one key byte these differences are the same as in the clear text, so one search for the
    three differences of `ANS-` finds the form under every key at once. The whole member is
    worked as one integer (each byte beside its neighbour), which is a few milliseconds a megabyte;
    a search per key was half a millisecond a megabyte for each of 510 keys, and a library of one
    megabyte was never searched to its end inside an APK's budget (review, 2026-10-08)."""
    n = len(body)
    x = int.from_bytes(body, "little")
    y = x >> 8
    if kind == "xor":
        return (x ^ y).to_bytes(n, "little")
    high = int.from_bytes(b"\x80" * n, "little")
    ones = (1 << (8 * n)) - 1
    # y - x in every byte, with no borrow from one byte into the next
    return (((y | high) - (x & (ones ^ high))) ^ ((y ^ x ^ ones) & high)).to_bytes(n, "little")


def xor_codes(body, deadline=None):
    """{answer code: (route, key byte)} for the codes a member holds under one byte of XOR
    (`xor-byte`) or of addition mod 256 (`add-byte`; the key is the byte that was added). The route
    never names the key: the next variant has another. A place counts only as the whole form with a
    byte on each side that is not a letter or digit under the same key (the end of the member is a
    side too). The places are found by the differences of neighbouring bytes, which no key changes."""
    found = {}
    if len(body) < 20:
        return found
    for kind in ("xor", "add"):
        if _late(deadline):
            return found
        diffs = _neighbour_differences(body, kind)
        needle = _KEY_NEEDLE[kind]
        at, hits = diffs.find(needle), 0
        while at >= 0:
            hits += 1
            if hits > MAX_KEY_HITS or (not hits & 255 and _late(deadline)):
                break                                      # a member that is `ANS-` under keys over and over
            key = (body[at] ^ 0x41) if kind == "xor" else (body[at] - 0x41) & 0xFF
            if key:
                dec = (lambda c: c ^ key) if kind == "xor" else (lambda c: (c - key) & 0xFF)
                window = bytes(dec(c) for c in body[max(0, at - 1):at + 21])
                lead = 1 if at else 0
                m = _ANS.match(window, lead) if (not lead or not window[:1].isalnum()) else None
                if m and m.end() - lead == 20:
                    found.setdefault(m.group(0).decode(), (kind + "-byte", key))
            at = diffs.find(needle, at + 1)
    return found


# ---------------------------------------------------------------------------- what codec_search asks

def kind_of(name, body) -> str:
    """The format of a member this module reads, or ''."""
    if is_hermes(body):
        return "hermes"
    if is_dex(body):
        return "dex"
    if body[:4] in (b"XABA", b"XALZ") or (body[:2] == b"MZ" and b"BSJB" in body):
        return "dotnet"
    if body[:4] == b"\x7fELF" and b"XABA" in body[:1 << 16]:
        return "dotnet"
    if is_native(body):
        return "native"
    if name.lower().endswith((".js", ".bundle", ".jsbundle", ".mjs", ".cjs")) and is_js(body):
        return "js"
    return ""


def docs(name, body, deadline=None, known=None):
    """[(object, format)]: puzzle-shaped objects in a member's code. Objects with no puzzle field
    (codec, data, steps, encoding, in any letter case) are left out. `known` says whether a text
    is a codec name; without it a Hermes object is given only where the buffers line up exactly."""
    kind = kind_of(name, body)
    out = []
    try:
        if kind == "hermes":
            table = hermes_strings(body)
            if table is None:
                return []
            objs, how = hermes_objects(body, table, known, deadline)
            out += [(o, "hermes" if how == "exact" else "hermes-window") for o in objs if _puzzle_like(o)]
            for text, _ in table:
                obj = _json_object(text) if text[:1] == "{" else None
                if _puzzle_like(obj):
                    out.append((obj, "hermes-json"))
        elif kind == "js":
            out += [(o, "js") for o in js_objects(body.decode("utf-8", "replace"), deadline)]
        elif kind == "dex":
            for c in dex_classes(body, deadline):
                doc = _field_doc(c["fields"])
                if _puzzle_like(doc):
                    out.append((doc, "dex-fields"))
                for _, strs in c["methods"]:
                    for s in strs:
                        obj = _json_object(s) if s[:1] == "{" else None
                        if _puzzle_like(obj):
                            out.append((obj, "dex-json"))
        elif kind == "dotnet":
            for s in dotnet_strings(body, deadline):
                obj = _json_object(s) if s[:1] == "{" else None
                if _puzzle_like(obj):
                    out.append((obj, "dotnet-json"))
    except (ValueError, IndexError, struct.error, RecursionError, MemoryError):
        return []
    return out[:MAX_DOCS]


def strings(name, body, deadline=None):
    """[(kind, bytes)]: the strings of a member's code with their true ends. The dex string pool is
    codec_search's own; a dex gives nothing here."""
    kind = kind_of(name, body)
    try:
        if kind == "hermes":
            table = hermes_strings(body) or []
            return [("hermes", t.encode("utf-8", "replace")) for t, ident in table if not ident and len(t) <= MAX_TEXT]
        if kind == "dotnet":
            return [("dotnet", s.encode("utf-8", "replace")) for s in dotnet_strings(body, deadline) if len(s) <= MAX_TEXT]
        if kind == "native":
            return [("native", s) for s in native_strings(body, deadline=deadline)]
    except (ValueError, IndexError, struct.error):
        return []
    return []


_HEAD = re.compile(r"ANS-[0-9A-F]{0,15}")
_TAIL = re.compile(r"[0-9A-F]{1,16}")


def pieces(name, body, deadline=None):
    """[(route, text)]: an answer code that one place of the code puts together from pieces.

    dex-method   the strings one method loads, in order, when they are a head (ANS- and hex digits)
                 followed by hex pieces that make exactly the form, with every other string of the
                 method left aside only if it is not hex
    dex-array    a static array of strings (or of characters or bytes) whose elements, joined as
                 listed, are exactly the form. An array beside an order list is a document
                 (`dex-fields`), not a piece list: codec_search reads both orders."""
    if not is_dex(body):
        return []
    out = []
    for c in dex_classes(body, deadline):
        ints = [v for v in c["fields"].values() if isinstance(v, list) and v and all(isinstance(x, int) for x in v)]
        for fname, v in c["fields"].items():
            if isinstance(v, bytes):
                v = v.decode("latin-1")
            if isinstance(v, list) and v and all(isinstance(x, str) for x in v):
                if any(len(o) == len(v) for o in ints):
                    continue
                v = "".join(v)
            if isinstance(v, str) and len(v) == 20 and _ANS.fullmatch(v.encode("latin-1", "replace")) \
                    and not isinstance(c["fields"][fname], str):
                out.append(("dex-array", v))
        for mname, strs in c["methods"]:
            if mname == "<clinit>":                        # what an initializer loads is its arrays' elements
                continue
            hexish = [s for s in strs if _HEAD.fullmatch(s) or _TAIL.fullmatch(s)]
            if len(hexish) >= 2 and _HEAD.fullmatch(hexish[0]) and not any(_HEAD.fullmatch(s) for s in hexish[1:]):
                joined = "".join(hexish)
                if len(joined) == 20 and _ANS.fullmatch(joined.encode()):
                    out.append(("dex-method", joined))
    return out


def main(argv) -> int:
    import sys
    if argv and argv[0] in ("-h", "--help"):
        print("usage: app_bundles.py <member-file>")
        return 0
    if len(argv) != 1:
        print("app_bundles.py: expected exactly one member file", file=sys.stderr)
        return 2
    try:
        with open(argv[0], "rb") as fh:
            body = fh.read()
        print("kind:", kind_of(argv[0], body) or "(none of the formats read here)")
        for obj, fmt in docs(argv[0], body):
            print("doc %s: %s" % (fmt, json.dumps(obj, default=str)[:400]))
        for route, text in pieces(argv[0], body):
            print("pieces %s: %s" % (route, text))
        got = strings(argv[0], body)
        print("strings: %d" % len(got))
        for kind, s in got[:40]:
            print("  %s %r" % (kind, s[:120]))
        if is_dex(body):
            for c in dex_classes(body):
                print("class %s fields=%s" % (c["class"], json.dumps(_field_doc(c["fields"]), default=str)[:300]))
                for mname, strs in c["methods"]:
                    print("  %s: %s" % (mname, strs[:12]))
        for code, (route, key) in xor_codes(body).items():
            print("%s key 0x%02x: %s" % (route, key, code))
        return 0
    except Exception as exc:
        print(f"app_bundles.py: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    import sys
    sys.exit(main(sys.argv[1:]))
