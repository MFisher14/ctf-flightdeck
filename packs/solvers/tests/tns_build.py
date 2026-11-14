"""Synthetic TI-Nspire documents for the B-132 tests, written from the format, not through the reader.

Nothing here imports solvers/toolkits/tns_nspire.py: the container is laid out with struct, a deflated
member with zlib, a method-13 member with Cryptodome's own 3DES (DES3, ECB), and a TIXC stream with the
small encoder below. Every value is invented; no real challenge file is involved.

    container(members, version="0500")      a .tns: *TIMLP, the local headers, the directory, TIPD
    member(name, data)                      a method-8 (deflate) member
    stored(name, data)                      a method-0 member
    encrypted(name, data, seed, packed)     a method-13 member around `data` (deflated first)
    xml_page(name, tree, seed=...)          a method-13 member holding the TIXC stream of `tree`,
                                            stating the size and CRC of the XML, as TI does
    tixc(tree) / xml(tree)                  one document as a TIXC stream and as the XML it stands for
    geometry(points, segments, texts)       the tree of a Graphs & Geometry page
    expand(packed21)                        three packed 56-bit DES keys as 24 bytes (bit strings)
"""
import struct
import zlib

HEADER_KEY = bytes.fromhex("79c4e0f45eef7a5b70137a57c2fd3d2cc2707cc1ad2f1575")
PACKED = bytes(range(0x11, 0x11 + 21))          # three distinct 56-bit keys
WRAP = 0x400


def deflate(data: bytes) -> bytes:
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def stored_deflate(data: bytes) -> bytes:
    """A raw deflate stream of stored blocks only: as long as the data, so a long member is long."""
    c = zlib.compressobj(0, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


class Entry:
    def __init__(self, name, method, payload, usize, crc, flags=0, extra=b""):
        self.name, self.method, self.payload, self.usize, self.crc, self.flags = name, method, payload, usize, crc, flags
        self.extra = extra                       # the local header's extra field


def member(name: str, data: bytes) -> Entry:
    return Entry(name, 8, deflate(data), len(data), zlib.crc32(data))


def stored(name: str, data: bytes) -> Entry:
    return Entry(name, 0, data, len(data), zlib.crc32(data))


def _local(e: Entry) -> bytes:
    name = e.name.encode("utf-8")
    return struct.pack("<HHHHHIIIHH", 20, e.flags, e.method, 0, 0x21, e.crc, len(e.payload), e.usize, len(name),
                       len(e.extra)) + name + e.extra


def container(members, version: str = "0500", directory: bool = True) -> bytes:
    """*TIMLP + version, the first local header without a signature, the others after PK\\x03\\x04, then
    (unless directory=False) the central directory and the TIPD end record TI writes."""
    out = bytearray(b"*TIMLP" + version.encode("ascii"))
    offsets = []
    for i, e in enumerate(members):
        if i:
            out += b"PK\x03\x04"
        offsets.append(len(out))
        out += _local(e) + e.payload
    if not directory:
        return bytes(out)
    start = len(out)
    for e, off in zip(members, offsets):
        name = e.name.encode("utf-8")
        out += b"PK\x01\x02" + struct.pack("<HHHHHHIIIHHHHHII", 20, 20, e.flags, e.method, 0, 0x21, e.crc, len(e.payload),
                                           e.usize, len(name), 0, 0, 0, 0, 0, off) + name
    size = len(out) - start
    out += b"TIPD" + struct.pack("<HHHHIIH", 0, 0, len(members), len(members), size, start, 0)
    return bytes(out)


# ---- method 13, with Cryptodome's 3DES --------------------------------------------------------------

def expand(packed: bytes) -> bytes:
    """21 bytes as 24: each run of 7 bits becomes a byte with a clear low bit (written with bit strings)."""
    bits = "".join(f"{b:08b}" for b in packed)
    return bytes(int(bits[i:i + 7] + "0", 2) for i in range(0, 168, 7))


def _ecb(key: bytes):
    from Cryptodome.Cipher import DES3
    return DES3.new(DES3.adjust_key_parity(key), DES3.MODE_ECB)


def keystream(key24: bytes, seed: int, blocks: int, wrap: int | None = WRAP) -> bytes:
    """3DES(key, 00000000 || LE32(seed + i mod wrap)) for i = 0 .. blocks-1 (wrap=None: never wraps)."""
    counters = b"".join(b"\x00" * 4 + struct.pack("<I", (seed + (i % wrap if wrap else i)) & 0xFFFFFFFF)
                        for i in range(blocks))
    return _ecb(key24).encrypt(counters)


def method13_bytes(stream: bytes, seed: int = 0x6FE21307, packed: bytes = PACKED, magic: bytes = b"TIEN0100",
                   wrap: int | None = WRAP, key24: bytes | None = None, stream_of=None) -> bytes:
    """A method-13 member's stored bytes around the (already deflated) `stream`."""
    head = magic + struct.pack("<II", WRAP, seed) + packed + b"\x00\x00\x00"
    assert len(head) == 40
    blocks = (len(stream) + 7) // 8
    ks = stream_of(blocks) if stream_of else keystream(key24 or expand(packed), seed, blocks, wrap)
    return _ecb(HEADER_KEY).encrypt(head) + bytes(a ^ b for a, b in zip(stream, ks))


def encrypted(name: str, data: bytes, seed: int = 0x6FE21307, packed: bytes = PACKED, **kw) -> Entry:
    return Entry(name, 13, method13_bytes(deflate(data), seed, packed, **kw), len(data), zlib.crc32(data))


# ---- TIXC and XML from one tree ---------------------------------------------------------------------
# A tree node is (tag, {attribute: value}, [child node or text, ...]).

def _text(s: str) -> bytes:
    out = bytearray()
    for ch in s:
        cp = ord(ch)
        if 0x20 <= cp < 0x7F or ch in "\t\n\r":
            out.append(cp)
        elif cp < 0x800:
            out += bytes([cp >> 8, cp & 0xFF])                  # 0x00-0x07: a code point under U+0800
        elif cp < 0x10000:
            out += bytes([0x80, cp >> 8, cp & 0xFF])            # 0x80: one 16-bit unit
        else:
            out += bytes([0x08, cp >> 16, (cp >> 8) & 0xFF, cp & 0xFF])
    return bytes(out)


def _node(node, tags, attrs, out):
    tag, at, kids = node
    t = tag.encode()
    indexed = t in tags
    if indexed:
        out += bytes([0x0C, tags.index(t)])
    else:
        out += b"<" + t
        tags.append(t)
    for k, v in at.items():
        kb = k.encode()
        if kb in attrs:
            out += bytes([0x0F, attrs.index(kb)])
        else:
            out += b" " + kb + b'="'
            attrs.append(kb)
        out += _text(v) + b'"'
    if at or not indexed:
        out += b">"                                           # a tag opened by index closes itself
    for i, kid in enumerate(kids):
        if isinstance(kid, str):
            assert not (indexed and not at and i == 0 and kid[:1] in (" ", "/")), "ambiguous after an indexed tag"
            out += _text(kid)
        else:
            _node(kid, tags, attrs, out)
    out += bytes([0x0E, tags.index(t)])


def tixc(tree, version: str = "1.0") -> bytes:
    out = bytearray(b"TIXC0100-" + version.encode() + b"?>")
    _node(tree, [], [], out)
    return bytes(out)


def xml(tree, version: str = "1.0") -> bytes:
    def ser(node):
        tag, at, kids = node
        head = "<" + tag + "".join(f' {k}="{v}"' for k, v in at.items()) + ">"
        return head + "".join(k if isinstance(k, str) else ser(k) for k in kids) + f"</{tag}>"
    return (f'<?xml version="{version}" encoding="UTF-8" ?>' + ser(tree)).encode("utf-8")


def xml_page(name: str, tree, seed: int = 0x01020304, packed: bytes = PACKED) -> Entry:
    """A method-13 member holding the TIXC stream of `tree`; size and CRC are the XML's, as TI states them."""
    doc = xml(tree)
    return Entry(name, 13, method13_bytes(deflate(tixc(tree)), seed, packed), len(doc), zlib.crc32(doc))


def _num(v: float) -> str:
    return repr(float(v)).replace("-", "\u2212")              # TI writes a minus sign, not a hyphen


def _leaf(tag, text=""):
    return (tag, {}, [text] if text else [])


def geometry(points=(), segments=(), texts=(), extra=()):
    """The tree of a Graphs & Geometry page. points: (id, x, y) or (id, x, y, shown); segments:
    (id, a, b) or (id, a, b, shown); texts: (id, text, x, y, w, h) or (..., parent id): a parent makes
    it an axis number, not a free text object. `extra` nodes are added to the object list as they are."""
    objs = [("gg:axes_system", {}, [_leaf("gg:id", "1"), _leaf("gg:umin", _num(-10)), _leaf("gg:umax", _num(10))])]
    for p in points:
        pid, x, y, shown = (*p, True)[:4]
        objs.append(("gg:point", {}, [_leaf("gg:id", str(pid)), _leaf("gg:point_"), _leaf("gg:x", _num(x)),
                                      _leaf("gg:y", _num(y)), _leaf("gg:asho", "1" if shown else "0"), _leaf("gg:lbl")]))
    for s in segments:
        sid, a, b, shown = (*s, True)[:4]
        objs.append(("gg:segment", {}, [_leaf("gg:id", str(sid)), _leaf("gg:par", f"{a} {b} "), _leaf("gg:seg_pp"),
                                        _leaf("gg:asho", "1" if shown else "0")]))
    for t in texts:
        tid, text, x, y, w, h = t[:6]
        kids = [_leaf("gg:id", str(tid))]
        if len(t) > 6:
            kids.append(_leaf("gg:par", f"{t[6]} "))
        kids += [("gg:text_", {}, [_leaf("gg:dx", "0"), _leaf("gg:dy", "0")]), _leaf("gg:chrs", f"1 1 2 0 0 0 {text}\n"),
                 _leaf("gg:x", _num(x)), _leaf("gg:y", _num(y)), _leaf("gg:w", _num(w)), _leaf("gg:h", _num(h)),
                 _leaf("gg:asho", "1")]
        objs.append(("gg:text", {}, kids))
    objs += list(extra)
    fig = ("gg:fig", {}, [_leaf("gg:ver", "10"), ("gg:objs", {}, objs), _leaf("gg:w", "100"), _leaf("gg:h", "100")])
    wdgt = ("wdgt", {"xmlns:gg": "urn:TI.GeoGrapher", "type": "TI.GeoGrapher", "ver": "1.0"},
            [_leaf("gg:mFlags", "3072"), fig, ("gg:wdgt", {"type": "Container"}, [])])
    return ("prob", {"xmlns": "urn:TI.Problem", "ver": "1.0", "pbname": ""},
            [_leaf("sym"), ("card", {"clay": "0", "h1": "10000"}, [_leaf("isDummyCard", "0"), wdgt])])


def settings():
    """The tree of a Document.xml: settings only, nothing drawn."""
    return ("doc", {"ver": "1.0"}, [("properties", {}, [_leaf("product", "28"), _leaf("swver", "6.2.0.333 CAS ")]),
                                    ("settings", {}, [_leaf("lang", "de"), _leaf("ddig", "7")]), _leaf("nps", "1")])
