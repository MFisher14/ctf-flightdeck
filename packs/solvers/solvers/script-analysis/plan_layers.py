#!/usr/bin/env python3
"""Generic layered plan tags: `HUNTRESS_ANALYSIS_V<n>:<TAG>-<labels>-<payload>` (Day 24 build night, ticket T2).

Day 23's `LYR-<l1>_<l2>-<payload>` named its layers in ENCODING order (l1 first, the payload is the outermost
result), so decoding undoes the LAST label first. That reader knew five labels (hex, b64, b32, rev, frag). This
module is the general form: a label table, a depth of up to 8, and an inverse search for a label it does not
know. The ONLY acceptance is the plan grammar (descriptor.plan_text: `v=<n>|key=value|...`, printable ASCII,
whole text). A decode that is not a plan answers nothing, so a wrong chain, a wrong label guess or a garbage
payload can never become an answer; two different valid plans from one tag withdraw (None).

Labels (case-insensitive; `_`, `+` or `>` between them):
  hex(h,b16)  b64(base64,b64u,b64url)  b32(base32)  b85(base85)  a85(ascii85)  z85  b36(base36)  b58(base58)
  b91  rev(reverse)  frag (pieces joined by one separator)  rot13(r13)  rot18  rot47  qp(quopri)
  url(pct,percent,urlenc)  zlib(deflate,inflate)  gz(gzip)  bz2  xz(lzma)  uu(uuencode)  oct  bin  dec
  b45(base45)  b62(base62)  yenc  brotli(br)   (Day 26: yenc and brotli are never searched for, only named)
  zstd(zst)  lz4  snappy(sz)                         (complete framed streams, bounded to MAX_OUT)
  xor<hexkey>  (a fixed repeating key, 1 to 8 bytes) and a bare `xor` (a single byte key, searched, accepted
  only when exactly one key gives a plan).
An unknown label is resolved by INVERSE SEARCH at its own position: every known decoder is tried there (a
bare xor only as the last step) and the chains are accepted by the grammar alone.

Bounds (ReDoS and time safe): payload <= MAX_PAYLOAD characters, every layer output <= MAX_OUT bytes, at most
MAX_STATES alternatives alive per level, at most MAX_OPS decode calls per tag, no regex with nested
quantifiers; the tag regex is anchored at the literal marker and each class is a single character class.

CLI (offline):  plan_layers.py <labels> <payload>      prints the plan or `no plan`
"""
import base64
import binascii
import bz2
import codecs
import lzma
import re
import sys
import urllib.parse
import zlib
from pathlib import Path

_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

MAX_LAYERS = 8
MAX_PAYLOAD = 400_000
MAX_OUT = 1 << 20
MAX_STATES = 24
MAX_STATES_INV = 8       # alive alternatives per level once an unknown label is being searched
INVERSE_MAX = 6000       # characters: a payload longer than this is decoded by known labels only
MAX_OPS = 6000
SEPS = ".-:,|;_ \t\n"

# `HUNTRESS_ANALYSIS_V1:<PREFIX>-<labels>-<payload>`; every class is one character class, the lazy label group
# stops at the first `-`, so matching is linear in the line.
TAG_RE = re.compile(r"(HUNTRESS_ANALYSIS_V\d+:)([A-Z][A-Z0-9]{1,7})-([A-Za-z0-9_+>]{1,80}?)-([^\s\"'*<>\\]+)")
TAG_JOINED = re.compile(r"^([A-Z][A-Z0-9]{1,7})-([A-Za-z0-9_+>]{1,80}?)-(.+)$", re.S)


def _t(b):
    return b.decode("latin-1") if isinstance(b, (bytes, bytearray)) else b


def _b(s):
    return s if isinstance(s, (bytes, bytearray)) else s.encode("latin-1", "replace")


# ------------------------------------------------------------------------------------------ the decoders
# Each takes bytes and returns a list of bytes alternatives ([] when this is not the layer's input).

def _d_hex(x):
    s = re.sub(rb"\s+", b"", x)
    if s[:2].lower() == b"0x":
        s = s[2:]
    if not s or len(s) % 2 or not re.fullmatch(rb"[0-9A-Fa-f]+", s):
        return []
    return [binascii.unhexlify(s)]


def _d_b64(x):
    t = re.sub(rb"\s+", b"", x)
    if not t:
        return []
    t += b"=" * (-len(t) % 4)
    out = []
    for fn in (lambda v: base64.b64decode(v, validate=True), base64.urlsafe_b64decode):
        try:
            r = fn(t)
        except Exception:  # noqa: BLE001
            continue
        if r and r not in out:
            out.append(r)
    return out


def _d_b32(x):
    t = re.sub(rb"\s+", b"", x).upper()
    if not t or not re.fullmatch(rb"[A-Z2-7]+=*", t):
        return []
    t += b"=" * (-len(t) % 8)
    try:
        r = base64.b32decode(t)
    except Exception:  # noqa: BLE001
        return []
    return [r] if r else []


def _d_b85(x):
    t = x.strip()
    if len(t) < 5:
        return []
    try:
        return [base64.b85decode(t)]
    except Exception:  # noqa: BLE001
        return []


def _d_a85(x):
    t = x.strip()
    if len(t) < 5:
        return []
    try:
        return [base64.a85decode(t, adobe=t.startswith(b"<~") and t.endswith(b"~>"))]
    except Exception:  # noqa: BLE001
        return []


_Z85 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"
_B85 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"
_Z85_TO_B85 = {ord(a): ord(b) for a, b in zip(_Z85, _B85)}


def _d_z85(x):
    t = _t(x).strip()
    if len(t) < 5 or len(t) % 5 or any(c not in _Z85 for c in t):
        return []
    try:
        return [base64.b85decode(t.translate(_Z85_TO_B85))]
    except Exception:  # noqa: BLE001
        return []


def _d_b36(x):
    t = _t(x).strip()
    if not (4 <= len(t) <= 8000) or not (re.fullmatch(r"[0-9a-z]+", t) or re.fullmatch(r"[0-9A-Z]+", t)):
        return []
    try:
        n = int(t, 36)
    except ValueError:
        return []
    return [n.to_bytes((n.bit_length() + 7) // 8, "big")] if n else []


_B58A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _d_b58(x):
    t = _t(x).strip()
    if not (2 <= len(t) <= 6000) or any(c not in _B58A for c in t):
        return []
    n = 0
    for c in t:
        n = n * 58 + _B58A.index(c)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return [b"\0" * (len(t) - len(t.lstrip("1"))) + body]


def _d_b91(x):
    try:
        import descriptor
        fn = descriptor.LAYERS.get("b91")
        r = fn(x) if fn is not None else None
    except Exception:  # noqa: BLE001
        r = None
    return [bytes(r)] if r else []


def _d_rev(x):
    return [x[::-1]] if len(x) > 1 else []


def _d_frag(x):
    s = _t(x)
    outs = []
    for c in SEPS:
        if c in s:
            outs.append(s.replace(c, "").encode("latin-1", "replace"))
    return outs or [x]


def _d_rot13(x):
    return [codecs.encode(_t(x), "rot13").encode("latin-1", "replace")] if re.search(rb"[A-Za-z]", x) else []


def _d_rot18(x):
    t = _t(x)
    r = "".join(chr(48 + (ord(c) - 43) % 10) if "0" <= c <= "9" else codecs.encode(c, "rot13")
                if c.isascii() and c.isalpha() else c for c in t)
    return [r.encode("latin-1", "replace")]


def _d_rot47(x):
    t = _t(x)
    return ["".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in t).encode("latin-1", "replace")]


def _d_qp(x):
    import quopri
    if b"=" not in x or re.search(rb"=(?![0-9A-Fa-f]{2}|\r?\n)", x):
        return []
    try:
        return [quopri.decodestring(bytes(x))]
    except Exception:  # noqa: BLE001
        return []


def _d_url(x):
    if b"%" not in x or re.search(rb"%(?![0-9A-Fa-f]{2})", x):
        return []
    return [urllib.parse.unquote_to_bytes(_t(x))]


def _inflate(x, wbits):
    d = zlib.decompressobj(wbits)
    try:
        out = d.decompress(bytes(x), MAX_OUT)
    except Exception:  # noqa: BLE001
        return None
    return out if out and d.eof else None


def _d_zlib(x):
    outs = []
    for wb in (15, 47, -15):
        r = _inflate(x, wb)
        if r is not None and r not in outs:
            outs.append(r)
    return outs


def _d_gz(x):
    return [r for r in (_inflate(x, 31),) if r is not None] or _d_zlib(x)


def _whole(make, x):
    d = make()
    try:
        out = d.decompress(bytes(x), MAX_OUT)
    except Exception:  # noqa: BLE001
        return []
    return [out] if d.eof and not d.unused_data and out else []


def _d_bz2(x):
    return _whole(bz2.BZ2Decompressor, x) if x[:3] == b"BZh" else []


def _d_xz(x):
    return _whole(lambda: lzma.LZMADecompressor(lzma.FORMAT_AUTO), x) if x[:6] == b"\xfd7zXZ\x00" or x[:3] == b"\x5d\x00\x00" else []


def _d_uu(x):
    lines = [ln for ln in _t(x).replace("\r", "").split("\n") if ln.strip()]
    if lines and lines[0].startswith("begin "):
        lines = lines[1:]
    if lines and lines[-1].strip() == "end":
        lines = lines[:-1]
    if lines and lines[-1].strip() in ("`", ""):
        lines = lines[:-1]
    if not lines:
        return []
    out = b""
    try:
        for ln in lines:
            out += binascii.a2b_uu(ln.encode("latin-1", "replace"))
    except Exception:  # noqa: BLE001
        return []
    return [out] if out else []


def _via_descriptor(name):
    """A Day 26 layer (base45, base62, yEnc, brotli) as this module's decoder: descriptor.py holds the readers (one
    copy of each algorithm); a reader that is not there, or fails on this input, gives no alternative."""
    def decode(x):
        try:
            import descriptor
            fn = getattr(descriptor, name)
            r = fn(_t(x) if name in ("_b45", "_b62", "_b62l", "_b62a") else x)
        except Exception:  # noqa: BLE001 - not this layer's input
            return []
        return [bytes(r)] if r else []
    return decode


def _d_b62(x):
    out = []
    for nm in ("_b62", "_b62l", "_b62a"):
        for r in _via_descriptor(nm)(x):
            if r not in out:
                out.append(r)
    return out


def _digit_groups(x, base, width):
    t = _t(x).strip()
    digits = "[0-7]" if base == 8 else "[01]"
    parts = [p for p in re.split(r"[^0-9A-Za-z]+", t) if p]
    if len(parts) == 1 and len(parts[0]) % width == 0:
        parts = [parts[0][i:i + width] for i in range(0, len(parts[0]), width)]
    if len(parts) < 2 or not all(re.fullmatch(f"{digits}{{1,{width}}}", p) for p in parts):
        return []
    vals = [int(p, base) for p in parts]
    return [bytes(vals)] if max(vals) < 256 else []


def _d_dec(x):
    parts = re.split(r"[ \t]*[,;:. \t][ \t]*", _t(x).strip())
    if len(parts) < 2 or not all(re.fullmatch(r"\d{1,3}", p) for p in parts):
        return []
    vals = [int(p) for p in parts]
    return [bytes(vals)] if max(vals) < 256 else []


def _xor(x, key):
    k = len(key)
    return bytes(c ^ key[i % k] for i, c in enumerate(x))


DECODERS = {
    "hex": _d_hex, "b64": _d_b64, "b32": _d_b32, "b85": _d_b85, "a85": _d_a85, "z85": _d_z85, "b36": _d_b36,
    "b58": _d_b58, "b91": _d_b91, "rev": _d_rev, "frag": _d_frag, "rot13": _d_rot13, "rot18": _d_rot18,
    "rot47": _d_rot47, "qp": _d_qp, "url": _d_url, "zlib": _d_zlib, "gz": _d_gz, "bz2": _d_bz2, "xz": _d_xz,
    "uu": _d_uu, "oct": lambda x: _digit_groups(x, 8, 3), "bin": lambda x: _digit_groups(x, 2, 8), "dec": _d_dec,
    # Day 26: base45 (RFC 9285), base62 (three alphabets), yEnc and brotli (label-only: no magic to search by)
    "b45": _via_descriptor("_b45"), "b62": _d_b62, "yenc": _via_descriptor("_yenc"),
    "brotli": _via_descriptor("_brotli"), "zstd": _via_descriptor("_zstd"),
    "lz4": _via_descriptor("_lz4"), "snappy": _via_descriptor("_snappy"),
}
ALIASES = {
    "h": "hex", "b16": "hex", "base16": "hex", "base64": "b64", "b64u": "b64", "b64url": "b64", "base32": "b32",
    "base85": "b85", "ascii85": "a85", "base36": "b36", "base58": "b58", "base91": "b91", "reverse": "rev",
    "r13": "rot13", "quopri": "qp", "pct": "url", "percent": "url", "urlenc": "url", "deflate": "zlib",
    "inflate": "zlib", "gzip": "gz", "lzma": "xz", "bzip2": "bz2", "uuencode": "uu", "octal": "oct",
    "binary": "bin", "decimal": "dec", "frags": "frag", "fragment": "frag",
    "base45": "b45", "base62": "b62", "br": "brotli", "zst": "zstd", "zstandard": "zstd",
    "lz4frame": "lz4", "sz": "snappy", "snappyframed": "snappy",
}
# the order the inverse search tries (cheapest and most selective first)
SEARCH_ORDER = ("b64", "hex", "b32", "b85", "a85", "z85", "b58", "b36", "b45", "b62", "zlib", "gz", "bz2", "xz",
                "zstd", "lz4", "snappy", "uu", "url", "qp",
                "oct", "bin", "dec", "frag", "rev", "rot47", "rot13", "rot18", "b91")


def canon(label):
    """The canonical layer name of one label, or None when the table does not hold it (an `xor<key>` is kept)."""
    w = label.lower()
    w = ALIASES.get(w, w)
    if w in DECODERS or w == "xor" or re.fullmatch(r"xor(?:[0-9a-f]{2}){1,8}", w):
        return w
    return None


def labels_of(text):
    names = [p for p in re.split(r"[_+>]", text or "") if p]
    return names if 1 <= len(names) <= MAX_LAYERS else None


# ------------------------------------------------------------------------------------------ the search

class _Budget:
    def __init__(self):
        self.ops = 0

    def spend(self):
        self.ops += 1
        return self.ops <= MAX_OPS


def _printable(b):
    return len(b) >= 8 and all(32 <= c < 127 or c in (9, 10, 13) for c in b)


def _plans_of(x):
    import descriptor
    out = []
    if len(x) <= 32768 and _printable(x):
        for t, _tr in descriptor.plan_text(x):
            if t not in out:
                out.append(t)
    return out


def _apply_one(name, x, bud, last):
    """alternatives (bytes, resolved name) for one layer applied to x."""
    if name == "xor":
        outs = []
        if last and len(x) <= 4096:
            for k in range(1, 256):
                if not bud.spend():
                    break
                y = _xor(x, bytes([k]))
                if y[:2] == b"v=" and _printable(y):
                    outs.append((y, "xor%02x" % k))
        return outs
    m = re.fullmatch(r"xor((?:[0-9a-f]{2}){1,8})", name)
    if m:
        return [(_xor(x, bytes.fromhex(m.group(1))), name)]
    fn = DECODERS.get(name)
    if fn is None or not bud.spend():
        return []
    try:
        res = fn(x)
    except Exception:  # noqa: BLE001 - not this layer's input
        return []
    return [(r, name) for r in res if r and len(r) <= MAX_OUT]


def searching_big(states):
    return any(len(x) > INVERSE_MAX for x, _c in states)


def decode_plans(labels, payload):
    """[(plan text, chain)] distinct valid plans a tag's payload decodes to; [] when none.

    `labels` is the label text (`hex_b64`) or a list of names. A known label is applied as named; an unknown
    one is searched over every decoder at its position. Acceptance is descriptor.plan_text alone."""
    names = labels_of(labels) if isinstance(labels, str) else list(labels or [])
    if not names or len(names) > MAX_LAYERS or not isinstance(payload, str) or not payload or len(payload) > MAX_PAYLOAD:
        return []
    bud = _Budget()
    states = [(payload.encode("latin-1", "replace"), ())]
    order = list(reversed(names))
    inv_used = False
    for i, raw in enumerate(order):
        name = canon(raw)
        last = i == len(order) - 1
        nxt, seen = [], set()
        if not name and (len(states[0][0]) > INVERSE_MAX or searching_big(states)):
            return []
        for x, chain in states:
            tries = [name] if name else list(SEARCH_ORDER) + ["xor"]
            for nm in tries:
                if nm == "xor" and not (last and not name) and name != "xor":
                    continue
                for y, used in _apply_one(nm, x, bud, last):
                    if not name and y == x:
                        continue
                    if y not in seen:
                        seen.add(y)
                        nxt.append((y, chain + (used,)))
        states = nxt[:(MAX_STATES if name and not inv_used else MAX_STATES_INV)]
        inv_used = inv_used or not name
        if not states or bud.ops > MAX_OPS:
            return []
    found = {}
    for x, chain in states:
        for t in _plans_of(x):
            if (not canon(order[-1])) and chain and chain[-1] in ("rot13", "rot18") and any(c.isdigit() for c in t):
                continue            # an inverse-resolved rot13/rot18 cannot be told apart: its digits are unproven
            found.setdefault(t, chain)
    return list(found.items())


def decode_plan(labels, payload):
    """The one plan text the tag decodes to, or None (no plan, or two different plans: withdraw)."""
    got = decode_plans(labels, payload)
    return got[0][0] if len(got) == 1 else None


# ------------------------------------------------------------------------------------------ tags in text

def tag_prefix_ok(prefix):
    """A prefix word the shipped descriptor reader already owns (B64, HEX, GZ, PLAIN, ...) is not ours."""
    if prefix in ("PLAIN", "RAW", "TEXT", "NONE", "SPLIT"):
        return False
    try:
        import descriptor
        return descriptor.tag_chain(prefix) is None
    except Exception:  # noqa: BLE001
        return True


def payload_candidates(text, start, token):
    """The payload of a tag found at text[start:]: the token the regex took, then (when that decodes to
    nothing) the rest of its line trimmed of closers, and that rest cut at its first quote."""
    yield token
    eol = text.find("\n", start)
    tail = text[start:eol if eol >= 0 else len(text)]
    if len(tail) > MAX_PAYLOAD:
        return
    outs = []
    t2 = re.sub(r"[\s\"';,)\]]*(?:\*/|-->|\?>|%>)?[\s\"';,)\]]*$", "", tail)
    for c in (t2, re.split(r"[\"']", tail, 1)[0]):
        if c and c != token and c not in outs:
            outs.append(c)
            yield c


def plan_for_tag(prefix, labels, text, start, token):
    """(plan, payload used) for one tag occurrence, or (None, None)."""
    if not tag_prefix_ok(prefix):
        return None, None
    names = labels_of(labels)
    if names is None:
        return None, None
    for cand in payload_candidates(text, start, token):
        plan = decode_plan(names, cand)
        if plan is not None:
            return plan, cand
    return None, None


def main(argv):
    if len(argv) != 3:
        print(__doc__)
        return 2
    plan = decode_plan(argv[1], argv[2])
    print(plan if plan else "no plan")
    return 0 if plan else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
