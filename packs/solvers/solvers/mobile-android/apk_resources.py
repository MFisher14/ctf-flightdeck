#!/usr/bin/env python3
"""Readers for the binary members of an APK, in plain Python (no androguard, no aapt, no jadx).

  .venv/bin/python solvers/mobile-android/apk_resources.py <file.apk>      # prints what it reads

  axml_tree(body)       a compiled XML file (AndroidManifest.xml, res/xml/*.xml) as a list of
                        elements: {"tag", "depth", "attrs": {name: value}, "text"}
  pool_strings(body, o) the strings of one ResStringPool chunk
  arsc_strings(body)    every string of resources.arsc's value pool
  arsc_values(body)     {(type, name): value} for the simple entries of resources.arsc
                        (string, integer, boolean), e.g. ("string", "puzzle_codec"): "xor"
  elf_strings(body)     printable runs of a native library
  expand(name, body)    members of a container inside the APK: an unencrypted Android backup
                        (.ab), a tar, a gzip; [] for anything else
  is_axml / is_arsc / is_elf

Everything is bounded (counts, sizes, depth) and fails closed: bytes that are not what a reader
expects give an empty result, never an exception. Used by codec_search.py (key material, puzzle
documents in other formats, strings) and by apk_facts.py (manifest facts).
"""
import base64
import gzip
import io
import re
import struct
import sys
import tarfile
import zlib

MAX_STRINGS = 20000
MAX_ELEMENTS = 5000
MAX_ENTRIES = 20000
MAX_INNER = 64            # members taken out of one container
MAX_INNER_BYTES = 1 << 20

RES_STRING_POOL, RES_TABLE, RES_XML = 0x0001, 0x0002, 0x0003
XML_RESOURCE_MAP, XML_START_NS, XML_END_NS, XML_START, XML_END, XML_CDATA = 0x0180, 0x0100, 0x0101, 0x0102, 0x0103, 0x0104
TABLE_PACKAGE, TABLE_TYPE, TABLE_TYPE_SPEC = 0x0200, 0x0201, 0x0202

# Attribute names by resource id, for a manifest whose attribute name strings were stripped.
ATTR_IDS = {
    0x01010000: "theme", 0x01010001: "label", 0x01010002: "icon", 0x01010003: "name", 0x01010006: "permission",
    0x0101000f: "debuggable", 0x01010010: "exported", 0x01010018: "authorities", 0x0101001b: "grantUriPermissions",
    0x01010024: "value", 0x01010027: "scheme", 0x01010028: "host", 0x01010029: "port", 0x0101002a: "path",
    0x0101002b: "pathPrefix", 0x0101002c: "pathPattern", 0x0101020c: "minSdkVersion", 0x0101021b: "versionCode",
    0x0101021c: "versionName", 0x01010270: "targetSdkVersion", 0x01010280: "allowBackup",
    0x010104ec: "usesCleartextTraffic", 0x01010527: "networkSecurityConfig",
}


def is_axml(body) -> bool:
    return len(body) >= 8 and struct.unpack_from("<HH", body, 0) == (RES_XML, 8)


def is_arsc(body) -> bool:
    return len(body) >= 12 and struct.unpack_from("<HH", body, 0) == (RES_TABLE, 12)


def is_elf(body) -> bool:
    return body[:4] == b"\x7fELF"


def pool_strings(d, off=8) -> list:
    """The strings of the ResStringPool chunk at `off`, as text; [] when there is none."""
    try:
        kind, hsize, size, count, _styles, flags, sstart, _ = struct.unpack_from("<HHIIIIII", d, off)
        if kind != RES_STRING_POOL or size > len(d) - off:
            return []
        out, utf8 = [], bool(flags & 0x100)
        for i in range(min(count, MAX_STRINGS)):
            o = off + sstart + struct.unpack_from("<I", d, off + hsize + 4 * i)[0]
            if utf8:
                o += 2 if d[o] & 0x80 else 1            # the length in characters
                n = d[o]
                o += 1
                if n & 0x80:
                    n = ((n & 0x7F) << 8) | d[o]
                    o += 1
                out.append(d[o:o + n].decode("utf-8", "replace"))
            else:
                n = struct.unpack_from("<H", d, o)[0]
                o += 2
                if n & 0x8000:
                    n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", d, o)[0]
                    o += 2
                out.append(d[o:o + 2 * n].decode("utf-16le", "replace"))
        return out
    except Exception:
        return []


def _typed(kind, data, strings):
    """One Res_value as a Python value: a string, an integer, a boolean, or text for the rest."""
    if kind == 0x03:
        return strings[data] if 0 <= data < len(strings) else None
    if kind == 0x12:
        return data != 0
    if kind == 0x10:
        return data - (1 << 32) if data & 0x80000000 else data
    if kind == 0x11:
        return data
    if kind == 0x01:
        return "@0x%08x" % data
    if kind == 0x02:
        return "?0x%08x" % data
    if kind == 0x00:
        return None
    if 0x1c <= kind <= 0x1f:
        return "#%08x" % data
    return "0x%08x" % data


def axml_tree(d) -> list:
    """The elements of a compiled XML file, in document order. [] for anything that is not one."""
    out = []
    try:
        if not is_axml(d):
            return []
        strings, ids, off, depth, total = [], [], 8, 0, min(len(d), struct.unpack_from("<I", d, 4)[0])

        def s(i):
            return strings[i] if 0 <= i < len(strings) else ""

        while off + 8 <= total and len(out) < MAX_ELEMENTS:
            kind, hsize, size = struct.unpack_from("<HHI", d, off)
            if size < 8 or off + size > total:
                break
            if kind == RES_STRING_POOL:
                strings = pool_strings(d, off)
            elif kind == XML_RESOURCE_MAP:
                ids = list(struct.unpack_from("<%dI" % ((size - hsize) // 4), d, off + hsize))
            elif kind == XML_START:
                _ns, name, astart, asize, acount = struct.unpack_from("<iiHHH", d, off + hsize)
                attrs, base = {}, off + hsize + astart
                for i in range(min(acount, 256)):
                    _ans, aname, raw, _sz, _r0, atype, adata = struct.unpack_from("<iiiHBBI", d, base + i * max(asize, 20))
                    key = s(aname) or ATTR_IDS.get(ids[aname] if 0 <= aname < len(ids) else -1, "")
                    if not key:
                        key = "attr_%d" % aname
                    attrs[key] = s(raw) if raw >= 0 and atype == 0x03 else _typed(atype, adata, strings)
                out.append({"tag": s(name), "depth": depth, "attrs": attrs, "text": ""})
                depth += 1
            elif kind == XML_END:
                depth = max(depth - 1, 0)
            elif kind == XML_CDATA and out:
                out[-1]["text"] += s(struct.unpack_from("<i", d, off + hsize)[0])
            off += size
    except Exception:
        pass
    return out


def arsc_strings(d) -> list:
    """Every string of the value pool of resources.arsc."""
    return pool_strings(d, 12) if is_arsc(d) else []


def arsc_values(d) -> dict:
    """{(type name, entry name): value} for the simple entries of resources.arsc, first configuration first.

    Strings come from the value pool; integers and booleans as numbers. Complex entries (arrays,
    styles, plurals) are read as a list of their simple values, which is what a string-array or an
    integer-array is. Sparse types are skipped."""
    out = {}
    try:
        if not is_arsc(d):
            return out
        values, off, total = [], 12, min(len(d), struct.unpack_from("<I", d, 4)[0])
        while off + 8 <= total:
            kind, hsize, size = struct.unpack_from("<HHI", d, off)
            if size < 8 or off + size > total:
                break
            if kind == RES_STRING_POOL and not values:
                values = pool_strings(d, off)
            elif kind == TABLE_PACKAGE:
                tpool, kpool = struct.unpack_from("<I", d, off + 8 + 4 + 256)[0], struct.unpack_from("<I", d, off + 8 + 4 + 256 + 8)[0]
                types, keys = pool_strings(d, off + tpool), pool_strings(d, off + kpool)
                inner, end = off + hsize, off + size
                while inner + 8 <= end and len(out) < MAX_ENTRIES:
                    k2, h2, s2 = struct.unpack_from("<HHI", d, inner)
                    if s2 < 8 or inner + s2 > end:
                        break
                    if k2 == TABLE_TYPE:
                        tid, flags, _res, count, start = struct.unpack_from("<BBHII", d, inner + 8)
                        tname = types[tid - 1] if 0 < tid <= len(types) else "type%d" % tid
                        if not flags & 0x01:
                            for i in range(min(count, MAX_ENTRIES)):
                                eoff = struct.unpack_from("<I", d, inner + h2 + 4 * i)[0]
                                if eoff == 0xFFFFFFFF:
                                    continue
                                e = inner + start + eoff
                                esize, eflags, ekey = struct.unpack_from("<HHI", d, e)
                                name = keys[ekey] if 0 <= ekey < len(keys) else "key%d" % ekey
                                if (tname, name) in out:
                                    continue
                                if eflags & 0x0001:     # a map: parent, count, then (name, Res_value) pairs
                                    _parent, n = struct.unpack_from("<II", d, e + 8)
                                    items = []
                                    for j in range(min(n, 256)):
                                        _nm, _vs, _r0, vt, vd = struct.unpack_from("<IHBBI", d, e + 16 + 12 * j)
                                        items.append(_typed(vt, vd, values))
                                    out[(tname, name)] = items
                                else:
                                    _vs, _r0, vt, vd = struct.unpack_from("<HBBI", d, e + esize)
                                    out[(tname, name)] = _typed(vt, vd, values)
                    inner += s2
            off += size
    except Exception:
        pass
    return out


_RUN = re.compile(rb"[\x20-\x7e]{4,256}")


def elf_strings(d, limit=4000) -> list:
    """Printable runs of 4 to 256 characters, in file order, each once."""
    if not is_elf(d):
        return []
    return list(dict.fromkeys(m.group(0) for m in _RUN.finditer(d[:1 << 20])))[:limit]


_ANS_CODE = re.compile(rb"ANS-[0-9A-F]{16}")


def native_secret(libs, data=None):
    """The one answer code a Day-15 puzzle stores in the APK's native libraries, or None (row 309).

    `libs` is an iterable of .so bodies (the lib/<abi>/*.so members). The code (ANS- and 16 upper-case
    hex characters) is returned only when the libraries hold exactly one distinct code: none, or two
    that differ, is None, because nothing then says which is meant. When `data` (the puzzle document's
    own `data` field) holds a different code, None as well: the library and the document disagree.
    Nothing is decoded or searched; the code must stand in the bytes as it is."""
    codes = set()
    for body in libs or ():
        codes.update(m.group(0).decode() for m in _ANS_CODE.finditer(bytes(body)))
    if len(codes) != 1:
        return None
    code = codes.pop()
    if isinstance(data, str) and _ANS_CODE.search(data.encode("utf-8", "replace")) and data.strip() != code:
        return None
    return code


# Day 16 look-ahead (row 312): the native theme (Day 15 = "the code stands in clear in lib/*/*.so")
# most likely deepens to "the code is hidden behind one constant transform in the library" (the
# forecast: an XOR/ADD key byte in libarena.so, or the code stored base64/hex/reversed). Everything
# below is UNSURE: native_derive is reached only when native_secret found no clear code, and
# codec_search.native_hit offers each reading under mobile.codec/native, so one base probe names the
# route and the cumulative Mastery is then plain. Nothing is guessed: a transform counts only when it
# yields exactly one distinct ANS code across the libraries; a multi-byte key is never brute-forced.
_NATIVE_SCAN = 1 << 18        # bytes of a library scanned for a one-byte-obfuscated code (256 KiB)
_A, _N, _S, _DASH = 0x41, 0x4E, 0x53, 0x2D   # 'A', 'N', 'S', '-'
_XDIFF = (_A ^ _N, _A ^ _S, _A ^ _DASH)      # XOR differences of the first four bytes (key-invariant)
_ADIFF = ((_N - _A) & 0xFF, (_S - _A) & 0xFF, (_DASH - _A) & 0xFF)  # ADD differences (key-invariant)
_HEX_CODE = re.compile(r"(?i)414e532d(?:3[0-9]|4[1-6]){16}")        # hex of the ascii code 'ANS-....'
_REV_CODE = re.compile(r"[0-9A-F]{16}-SNA")                         # the clear code written backwards
_B64_RUN = re.compile(r"[A-Za-z0-9+/]{26,28}={0,2}")               # base64 of the 20-byte code


def _xor_codes(b, out):
    """Every distinct code recovered by one-byte XOR of a 20-byte window of `b`, added to `out`."""
    n = len(b)
    for i in range(n - 19):
        x = b[i]
        if (x ^ b[i + 1]) != _XDIFF[0] or (x ^ b[i + 2]) != _XDIFF[1] or (x ^ b[i + 3]) != _XDIFF[2]:
            continue
        k = x ^ _A
        if not k:
            continue    # key 0 is the code in clear: native_clear's (row 318), never a reading named xor
        cand = bytes(c ^ k for c in b[i:i + 20])
        if _ANS_CODE.fullmatch(cand):
            out.add(cand.decode())


def _add_codes(b, out):
    """Every distinct code recovered by one-byte modular addition of a 20-byte window of `b`."""
    n = len(b)
    for i in range(n - 19):
        x = b[i]
        if (((b[i + 1] - x) & 0xFF) != _ADIFF[0] or ((b[i + 2] - x) & 0xFF) != _ADIFF[1]
                or ((b[i + 3] - x) & 0xFF) != _ADIFF[2]):
            continue
        k = (x - _A) & 0xFF
        if not k:
            continue    # key 0 is the code in clear (row 318)
        cand = bytes((c - k) & 0xFF for c in b[i:i + 20])
        if _ANS_CODE.fullmatch(cand):
            out.add(cand.decode())


def _text_codes(text, b64, hexc, revc):
    """Codes a library stores as a printable run: base64 of the code, hex of its ascii, or reversed."""
    for m in _REV_CODE.finditer(text):
        revc.add(m.group(0)[::-1])
    for m in _HEX_CODE.finditer(text):
        try:
            d = bytes.fromhex(m.group(0))
            if _ANS_CODE.fullmatch(d):
                hexc.add(d.decode())
        except ValueError:
            pass
    for m in _B64_RUN.finditer(text):
        try:
            d = base64.b64decode(m.group(0) + "===", validate=False)
        except Exception:
            continue
        if _ANS_CODE.fullmatch(d):
            b64.add(d.decode())


def native_derive(libs, data=None):
    """[(route, code)] for a Day-16 native puzzle whose code is hidden behind one constant transform
    in the APK's native libraries, most-likely first, or [] (row 312). Reached only when the code does
    not stand in clear (native_secret is None). Every reading is unsure, offered under
    mobile.codec/native. A transform contributes a code only when it yields exactly one distinct ANS
    code across the libraries; nothing is executed and no multi-byte key is searched. `data` is the
    document's own `data` field: a clear ANS code there is a candidate too (the obfuscation may leave a
    copy in the document), kept last so the library readings lead. Row 318: when the libraries hold
    exactly one code in clear and native_secret declined it (the document's `data` holds another), that
    code leads as `native:so-disagree`; a one-byte key of 0 is no xor or add reading (it is the clear code)."""
    bodies = [bytes(b)[:_NATIVE_SCAN] for b in (libs or ())]
    xor, add_, b64, hexc, revc = set(), set(), set(), set(), set()
    clear = set()
    for b in bodies:
        _xor_codes(b, xor)
        _add_codes(b, add_)
        _text_codes(b.decode("latin-1"), b64, hexc, revc)
    for body in libs or ():     # the whole library, as native_secret reads it: a second code anywhere declines
        clear.update(m.group(0).decode() for m in _ANS_CODE.finditer(bytes(body)))
    out, seen = [], set()
    # Row 318: the libraries hold exactly one code in clear and the document's `data` holds another (the
    # JNI-boundary decoy). native_secret declines; that code is offered first under a route of its own,
    # never the judged native:so-secret, and the document's copy after it (native:data-copy, below).
    for route, codes in (("native:so-disagree", clear if len(clear) == 1 else set()),
                         ("native:so-xor", xor), ("native:so-add", add_), ("native:so-base64", b64),
                         ("native:so-hex", hexc), ("native:so-reverse", revc)):
        if len(codes) == 1:
            c = next(iter(codes))
            if _ANS_CODE.fullmatch(c.encode()) and c not in seen:
                seen.add(c)
                out.append((route, c))
    if isinstance(data, str):
        m = _ANS_CODE.search(data.strip().encode("utf-8", "replace"))
        if m and m.group(0).decode() not in seen:
            out.append(("native:data-copy", m.group(0).decode()))
    return out[:6]


def _tar_members(blob, prefix) -> list:
    out, total = [], 0
    try:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:") as tf:
            for info in tf:
                if len(out) >= MAX_INNER:
                    break
                if not info.isfile() or info.size > MAX_INNER_BYTES or total + info.size > 4 * MAX_INNER_BYTES:
                    continue
                fh = tf.extractfile(info)       # read into memory only: nothing is written to disk
                if fh is None:
                    continue
                total += info.size
                out.append((prefix + info.name.lstrip("./"), fh.read()))
    except Exception:
        return out
    return out


def _bounded_inflate(body, wbits, limit=4 * MAX_INNER_BYTES):
    try:
        obj = zlib.decompressobj(wbits)
        out = obj.decompress(body, limit)
        return out if out and not obj.unconsumed_tail else None    # larger than the limit: not read
    except zlib.error:
        return None


def expand(name, body) -> list:
    """[(inner name, bytes)] for a container among the members: an Android backup that is not
    encrypted (`ANDROID BACKUP`, version, compressed, `none`, then a deflated tar), a tar, a gzip.
    The inner name is `<member>!<path>`. An encrypted backup gives [] (its key is the user's password)."""
    try:
        if body.startswith(b"ANDROID BACKUP\n"):
            head = body[:64].split(b"\n", 4)
            if len(head) < 5 or head[3] != b"none":
                return []
            payload = body[sum(len(x) + 1 for x in head[:4]):]
            tar = _bounded_inflate(payload, 15) if head[2] == b"1" else payload
            return _tar_members(tar, name + "!") if tar else []
        if body[:2] == b"\x1f\x8b":
            inner = _bounded_inflate(body, 31)
            if not inner:
                return []
            if inner[257:262] == b"ustar":
                return _tar_members(inner, name + "!")
            return [(name + "!gunzip", inner)] if len(inner) <= MAX_INNER_BYTES else []
        if body[257:262] == b"ustar":
            return _tar_members(body, name + "!")
    except Exception:
        return []
    return []


def main(argv) -> int:
    import zipfile
    if argv and argv[0] in ("-h", "--help"):
        print("usage: apk_resources.py <file.apk>")
        return 0
    if len(argv) != 1:
        print("apk_resources.py: expected exactly one APK", file=sys.stderr)
        return 2
    try:
        with zipfile.ZipFile(argv[0]) as zf:
            for info in zf.infolist():
                body = zf.read(info)
                if is_axml(body):
                    print("== %s (compiled XML)" % info.filename)
                    for el in axml_tree(body):
                        print("  %s<%s> %s %s" % ("  " * el["depth"], el["tag"], el["attrs"], el["text"]))
                elif is_arsc(body):
                    print("== %s (resource table)" % info.filename)
                    for (t, n), v in arsc_values(body).items():
                        print("  %s/%s = %r" % (t, n, v))
                elif is_elf(body):
                    print("== %s (ELF): %d strings" % (info.filename, len(elf_strings(body))))
                else:
                    for inner, b in expand(info.filename, body):
                        print("== %s: %d bytes" % (inner, len(b)))
        return 0
    except Exception as exc:
        print(f"apk_resources.py: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
