"""A bounded, MAGIC-GATED reversible-envelope peeler (the "same challenge, base64-wrapped" class).

A whole delivery or a single member is sometimes wrapped in a thin, reversible envelope -- the real
artifact re-encoded as base64 / base32 / base85 / hex / url-percent / PEM / data-URI, compressed
(gzip / zlib / raw-deflate / bz2 / xz), or byte-twisted (reversed / byte-swapped), possibly in a
two-level nest. Peeling that envelope reveals a container or format the lanes already solve. Before
this module `tools/run.py`'s `run.expand` peeled only zip and 7z, so such a wrapper was a SILENT MISS:
the lane saw undecodable bytes and returned None.

THE BRIGHT LINE -- never-wrong. A layer is peeled ONLY when the decode is RECOGNIZED: the decoded
bytes start with a known container/format magic (the default), or they satisfy a caller-supplied
predicate (a clean schema parse, a checksum, a crib). A speculative decode of garbage is DISCARDED
and never fed onward. Because a peel only ADDS a recognized inner stream (it never rewrites or drops
the original bytes), it can only turn a prior None/miss into a recognized inner solve; it moves zero
saved answers (no saved delivery carries such an envelope, so on a regression this module peels
nothing).

Two uses:

  * `tools/run.py run.expand` passes the default magic recognizer (no XOR): a base64/gzip/... wrapped
    APK / ELF / zip / 7z / dex / ... is peeled, then the normal expand recurses into the revealed
    container.
  * Warmups re-entry passes `crib=` (and `try_xor=True`): an XOR layer (single-byte, or a repeating
    key recovered from the crib by known-plaintext) is peeled and the result re-fed through the codec
    battery; a reading is kept ONLY when the FULL crib survives, so a wrong XOR key cannot manufacture
    a false crib match.

Everything is bounded by byte size and node counts, never by a clock; no decode is ever executed as
code, and nothing here makes a network request.

THE BOMB GUARD (Day 27 build). A few KiB can inflate to gigabytes, and `peel` runs on every delivery member
`tools/run.py` expands (Warmups, Mobile, Metadata). The decompressors used to be the stdlib's ONE-SHOT calls,
which allocate the whole output before `_cap` looks at its length (bz2 of 64 MiB of zeros peaked at 141 MiB,
a 256 MiB zstd bomb at 256 MiB, and a 10 GiB one would have taken 10 GiB). Now every decompressor is driven
incrementally (`_decode`): its output reaches a `_Sink` piece by piece, and a stream that passes MAX_OUT is
dropped the moment it is known to (at most MAX_OUT + 1 bytes of it were ever produced; zstd, snappy and
brotli can give one piece more, their libraries take no exact limit: a piece is one STEP_OUT for zstd, up to
about twice the room asked for by brotli, and what a run of at most STEP_IN_SNAPPY bytes of chunks holds, 21
times that at most, for snappy). A bomb of any size is therefore refused with MAX_OUT plus a piece or two in
hand: 512 MiB of zeros adds 67 to 99 MiB of resident memory in every format (132 when the stream also
declares a 128 MiB xz dictionary or zstd window, which the decoder fills as it writes), where the one-shot
calls added about 1 GiB. A stream that fits is decoded ONCE, as it always was (KEEP_DIV 1, one pass; a legal
stream just under MAX_OUT costs the same two copies of its output, the pieces and their join, as it did).
The first build held only MAX_OUT / 8 of a stream whose length was still open and decoded every longer one a
second time (KEEP_DIV 8): that doubled the time of an xz or bz2 envelope of 8 to 64 MiB (34 MiB of bz2:
1.1 s to 2.2 s) and only made a bomb's hold smaller (11 to 81 MiB), so KEEP_DIV is now its dial, not its
setting. The bytes returned for every stream that fits are exactly what the one-shot calls returned,
member by member: concatenated gzip / bz2 / xz streams, what follows the last bz2 / xz stream, trailing data
(zlib and raw deflate ignore it, gzip refuses non-NUL garbage), truncation and checksum errors
(tests/test_day27_unwrap_bounded_warmups.py runs them against the stdlib one-shot functions). The one
difference: a LATER bz2 / xz stream that the one-shot call would ignore for being corrupt, but that expands
past MAX_OUT before it fails, now ends the decode (None), since it would take its whole output to find out.
"""

import base64
import binascii
import bz2
import csv
import io
import json
import lzma
import re
import struct
import time
import zlib

# --------------------------------------------------------------------------- recognition magics

# Known container / executable / format ENDPOINT magics. A peeled stream is "recognized" when it
# starts with one of these: the gate that keeps a speculative decode of garbage from being fed onward.
# Kept to strong, multi-byte, low-false-positive magics on purpose; a 1-byte or entropy-free "magic"
# (a bare zlib 0x78 header) is NOT a recognition magic. Compression magics (gzip, bz2, xz, zlib) are
# deliberately absent: those are peeled THROUGH by the battery -- `_continuable` follows them one more
# level -- so `base64(gzip(apk))` reaches the APK rather than stopping at the gzip stream.
MAGICS = (
    b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08",          # zip / jar / apk / docx / ...
    b"7z\xbc\xaf\x27\x1c",                                  # 7z
    b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01",              # rar v4 / v5
    b"\x7fELF",                                             # ELF
    b"MZ",                                                  # PE / DOS
    b"\xca\xfe\xba\xbe",                                    # java class / mach-o fat
    b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",              # mach-o 32 / 64 (BE)
    b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",              # mach-o 32 / 64 (LE)
    b"dex\n",                                              # Android dex
    b"\x89PNG\r\n\x1a\n",                                  # png
    b"%PDF-",                                               # pdf
    b"HCFG",                                               # the Binary lane's config container
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",                   # OLE / MSI / legacy office
    b"SQLite format 3\x00",                                 # sqlite
)


# The subset of magics that are at least 4 bytes long: used to gate the decoders that have NO input
# magic of their own (raw-deflate) or are pure byte transforms (reverse, byteswap). A 2-byte magic
# (MZ) would false-positive far too often on the coincidental head of a transformed binary; a >=4-byte
# match on random bytes is ~1 in 4 billion.
STRONG_MAGICS = tuple(m for m in MAGICS if len(m) >= 4)


TEXT_ENDPOINT_MAX = 8 * 1024 * 1024


def _riff_endpoint(d: bytes) -> bool:
    """A complete WAVE or WebP RIFF, not merely bytes beginning with ``RIFF``."""
    if len(d) < 20 or d[:4] != b"RIFF" or struct.unpack_from("<I", d, 4)[0] + 8 != len(d):
        return False
    form = d[8:12]
    if form not in (b"WAVE", b"WEBP"):
        return False
    pos, kinds = 12, set()
    while pos < len(d):
        if pos + 8 > len(d):
            return False
        kind, size = d[pos:pos + 4], struct.unpack_from("<I", d, pos + 4)[0]
        pos += 8
        end = pos + size
        if end > len(d):
            return False
        kinds.add(kind)
        pos = end + (size & 1)
    if pos != len(d):
        return False
    return (b"fmt " in kinds and b"data" in kinds) if form == b"WAVE" else bool(
        kinds & {b"VP8 ", b"VP8L", b"VP8X"})


def _jpeg_endpoint(d: bytes) -> bool:
    """A complete JPEG with a parsed header, a frame, a scan, and a terminal EOI."""
    if len(d) < 16 or d[:2] != b"\xff\xd8" or d[-2:] != b"\xff\xd9":
        return False
    i, frame = 2, False
    while i < len(d) - 2:
        if d[i] != 0xff:
            return False
        while i < len(d) - 2 and d[i] == 0xff:
            i += 1
        marker = d[i]
        i += 1
        if marker in (0x01, *range(0xD0, 0xD8)):
            continue
        if marker == 0xD9:
            return False
        if i + 2 > len(d) - 2:
            return False
        n = struct.unpack_from(">H", d, i)[0]
        if n < 2 or i + n > len(d) - 2:
            return False
        if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7,
                      0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
            frame = n >= 8
        if marker == 0xDA:
            # Entropy-coded bytes are byte-stuffed and may contain restart markers.  The terminal EOI
            # is the structural boundary we need here; a parsed SOS plus SOF keeps a magic-only prefix out.
            return frame and i + n <= len(d) - 2
        i += n
    return False


def _gif_endpoint(d: bytes) -> bool:
    """Walk a complete GIF block stream through its trailer."""
    if len(d) < 14 or d[:6] not in (b"GIF87a", b"GIF89a") or d[-1:] != b";":
        return False
    packed = d[10]
    pos = 13 + (3 * (1 << ((packed & 7) + 1)) if packed & 0x80 else 0)
    saw_image = False

    def subblocks(p):
        while p < len(d):
            n = d[p]
            p += 1
            if n == 0:
                return p
            if p + n > len(d):
                return None
            p += n
        return None

    while pos < len(d):
        tag = d[pos]
        pos += 1
        if tag == 0x3B:
            return saw_image and pos == len(d)
        if tag == 0x21:
            if pos >= len(d):
                return False
            pos += 1                         # extension label
            got = subblocks(pos)
            if got is None:
                return False
            pos = got
            continue
        if tag != 0x2C or pos + 9 > len(d):
            return False
        flags = d[pos + 8]
        pos += 9
        if flags & 0x80:
            pos += 3 * (1 << ((flags & 7) + 1))
        if pos >= len(d):
            return False
        pos += 1                             # LZW minimum code size
        got = subblocks(pos)
        if got is None:
            return False
        pos, saw_image = got, True
    return False


def _pcap_endpoint(d: bytes) -> bool:
    """Walk every record of a classic pcap to an exact end."""
    if len(d) < 24:
        return False
    magics = {
        b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
        b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">",
    }
    endian = magics.get(d[:4])
    if endian is None:
        return False
    major, minor, snap = struct.unpack_from(endian + "HHxxxxxxxxI", d, 4)
    if major != 2 or minor > 4 or not (1 <= snap <= (1 << 30)):
        return False
    pos, packets = 24, 0
    while pos < len(d):
        if pos + 16 > len(d):
            return False
        caplen, wirelen = struct.unpack_from(endian + "II", d, pos + 8)
        pos += 16
        if caplen > snap or caplen > wirelen or pos + caplen > len(d):
            return False
        pos += caplen
        packets += 1
    return pos == len(d) and packets > 0


def _pcapng_endpoint(d: bytes) -> bool:
    """Walk complete pcapng blocks, honoring section byte order and mirrored lengths."""
    if len(d) < 28 or d[:4] != b"\x0a\x0d\x0d\x0a":
        return False
    pos, endian, blocks = 0, None, 0
    while pos < len(d):
        if pos + 12 > len(d):
            return False
        if d[pos:pos + 4] == b"\x0a\x0d\x0d\x0a":
            bom = d[pos + 8:pos + 12]
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">" if bom == b"\x1a\x2b\x3c\x4d" else None
            if endian is None:
                return False
        if endian is None:
            return False
        size = struct.unpack_from(endian + "I", d, pos + 4)[0]
        if size < 12 or size & 3 or pos + size > len(d) \
                or struct.unpack_from(endian + "I", d, pos + size - 4)[0] != size:
            return False
        pos += size
        blocks += 1
    return pos == len(d) and blocks > 0


def _registry_endpoint(d: bytes) -> bool:
    """A complete-enough registry hive header plus its first hbin, with a valid header checksum."""
    if len(d) < 4096 + 32 or d[:4] != b"regf" or d[4096:4100] != b"hbin":
        return False
    hbins = struct.unpack_from("<I", d, 0x28)[0]
    if not hbins or hbins & 0xfff or 4096 + hbins > len(d):
        return False
    checksum = 0
    for off in range(0, 0x1fc, 4):
        checksum ^= struct.unpack_from("<I", d, off)[0]
    return checksum == struct.unpack_from("<I", d, 0x1fc)[0]


_LOG_LINE = re.compile(r"(?:<\d{1,3}>|\d{4}-\d\d-\d\d[T ])")


def _text_endpoint(d: bytes) -> bool:
    """Exact structured JSON/JSONL, tabular CSV, or timestamped log; never arbitrary printable text."""
    if not (MIN_LEN <= len(d) <= TEXT_ENDPOINT_MAX) or b"\x00" in d:
        return False
    try:
        text = d.decode("utf-8-sig")
    except UnicodeDecodeError:
        return False
    stripped = text.strip()
    if not stripped:
        return False
    if stripped[:1] in "[{":
        try:
            value = json.loads(stripped)
        except (ValueError, RecursionError):
            pass
        else:
            if isinstance(value, (dict, list)):
                return True
    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) >= 2:
        try:
            if all(isinstance(json.loads(line), (dict, list)) for line in lines):
                return True
        except (ValueError, RecursionError):
            pass
        if all(_LOG_LINE.match(line) for line in lines):
            return True
    if len(lines) < 2 or not any(c in lines[0] for c in ",;\t"):
        return False
    for delim in (",", "\t", ";"):
        if delim not in lines[0]:
            continue
        try:
            rows = list(csv.reader(io.StringIO(text), delimiter=delim, strict=True))
        except (csv.Error, UnicodeError):
            continue
        if 2 <= len(rows) <= 100_000 and len(rows[0]) >= 2 and len(set(rows[0])) == len(rows[0]) \
                and all(len(row) == len(rows[0]) for row in rows) and all(cell.strip() for cell in rows[0]):
            return True
    return False


def _looks_structured(data: bytes) -> bool:
    return (_riff_endpoint(data) or _jpeg_endpoint(data) or _gif_endpoint(data)
            or _pcap_endpoint(data) or _pcapng_endpoint(data) or _registry_endpoint(data)
            or _text_endpoint(data))


def looks_like_container(data) -> bool:
    """Known magic, or a downstream format that passes its bounded structural recognizer."""
    if not isinstance(data, (bytes, bytearray)):
        return False
    data = bytes(data)
    head = data[:16]
    return any(head.startswith(m) for m in MAGICS) or _looks_structured(data)


def looks_like_container_strong(data) -> bool:
    """Like `looks_like_container` but only the >=4-byte magics (for header-less / transform decoders)."""
    if not isinstance(data, (bytes, bytearray)):
        return False
    data = bytes(data)
    head = data[:16]
    return any(head.startswith(m) for m in STRONG_MAGICS) or _looks_structured(data)


# --------------------------------------------------------------------------- bounds

MIN_LEN = 8                 # nothing shorter is a wrapped artifact
MAX_IN = 48 * 1024 * 1024   # bytes: inputs larger than this are not peeled (a 33 MB delivery is fine)
MAX_OUT = 64 * 1024 * 1024  # a decode that expands past this is dropped (a decompression bomb guard)
MAX_NODES = 256             # total decode attempts across all levels of one peel() call
MAX_RESULTS = 32            # recognized streams returned
DEFAULT_DEPTH = 3           # bounded three-layer nests (mixed or repeated codecs)
# KEEP_DIV 1 is ONE pass: a stream is held as it decodes, so a bomb is held up to MAX_OUT (and a piece or two) before
# it is refused, and a stream that fits is decoded once. Above 1 it is the first build's two passes: only
# MAX_OUT // KEEP_DIV of a stream whose length is still open is held, and a longer one that turns out to fit is decoded
# a second time (a stream of 8 to 64 MiB took twice as long, and the bomb was held in 8 MiB instead of 64).
KEEP_DIV = 1
STEP_OUT = 1 << 20          # the most one decompress call is asked for (less near MAX_OUT, and under a lowered one)
STEP_IN = 1 << 18           # input handed to a decompressor at a time (zlib, bz2, lzma)
STEP_IN_SNAPPY = 1 << 16    # snappy's framing has no output limit to ask for, so the input of one call is the limit

_B64_ALPHA = re.compile(rb"\A[A-Za-z0-9+/\s]*={0,2}\s*\Z")
_B64URL_ALPHA = re.compile(rb"\A[A-Za-z0-9\-_\s]*={0,2}\s*\Z")
_B32_ALPHA = re.compile(rb"\A[A-Z2-7\s]*={0,6}\s*\Z")
_B16_ALPHA = re.compile(rb"\A[0-9A-Fa-f\s]*\Z")
_A85_ALPHA = re.compile(rb"\A[\x21-\x75z\s]*\Z")      # Ascii85 printable range plus 'z'
_HAS_PERCENT = re.compile(rb"%[0-9A-Fa-f]{2}")
_PEM = re.compile(rb"-----BEGIN [A-Z0-9 ]+-----\r?\n(.*?)\r?\n-----END [A-Z0-9 ]+-----", re.S)
_DATA_URI = re.compile(rb"\Adata:[^,]*;base64,([A-Za-z0-9+/=\s]+)\Z", re.S)
_B58_ALPHA = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_SET = frozenset(_B58_ALPHA)
_WS = b" \t\r\n"
_NOT_NUL = re.compile(rb"[^\x00]")


def _clean(data: bytes) -> bytes:
    return bytes(data).strip()


# --------------------------------------------------------------------------- individual decoders
# Each returns decoded bytes, or None on ANY doubt (wrong alphabet, bad padding, a decode error, an
# empty or over-large result). None means "not this envelope"; it is never a guess.

def _cap(out):
    if out is None:
        return None
    if not out or len(out) > MAX_OUT:
        return None
    return out


def _d_base64(data: bytes):
    s = _clean(data)
    if len(s) < 4 or not _B64_ALPHA.fullmatch(s):
        return None
    body = bytes(c for c in s if c not in _WS)
    try:
        return _cap(base64.b64decode(body + b"=" * (-len(body) % 4), validate=True))
    except (binascii.Error, ValueError):
        return None


def _d_base64url(data: bytes):
    s = _clean(data)
    if len(s) < 4 or (b"-" not in s and b"_" not in s) or not _B64URL_ALPHA.fullmatch(s):
        return None
    body = bytes(c for c in s if c not in _WS)
    try:
        return _cap(base64.urlsafe_b64decode(body + b"=" * (-len(body) % 4)))
    except (binascii.Error, ValueError):
        return None


def _d_base32(data: bytes):
    s = _clean(data)
    if len(s) < 8 or not _B32_ALPHA.fullmatch(s):
        return None
    body = bytes(c for c in s if c not in _WS)
    body += b"=" * (-len(body) % 8)
    try:
        return _cap(base64.b32decode(body))
    except (binascii.Error, ValueError):
        return None


def _d_base16(data: bytes):
    s = bytes(c for c in _clean(data) if c not in _WS)
    if len(s) < 8 or len(s) % 2 or not _B16_ALPHA.fullmatch(s):
        return None
    try:
        return _cap(bytes.fromhex(s.decode("ascii")))
    except ValueError:
        return None


_B85_ALPHA = re.compile(rb"\A[\x21-\x7e\s]*\Z")      # base85 (RFC1924/b85) is printable ASCII


def _d_base85(data: bytes):
    s = _clean(data)
    if len(s) < 5 or not _B85_ALPHA.fullmatch(s):
        return None
    try:
        return _cap(base64.b85decode(bytes(c for c in s if c not in _WS)))
    except ValueError:
        return None


def _d_ascii85(data: bytes):
    s = _clean(data)
    if len(s) < 5 or not _A85_ALPHA.fullmatch(s):
        return None
    try:
        return _cap(base64.a85decode(s, adobe=s.startswith(b"<~")))
    except ValueError:
        return None


def _d_base58(data: bytes):
    s = bytes(c for c in _clean(data) if c not in _WS)
    if len(s) < 8 or any(c not in _B58_SET for c in s):
        return None
    n = 0
    for c in s:
        n = n * 58 + _B58_ALPHA.index(c)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip(b"1"))
    return _cap(b"\x00" * pad + body)


_URL_ALPHA = re.compile(rb"\A[\x20-\x7e\s]*\Z")      # a url-encoded blob is printable ASCII, not binary


def _d_url(data: bytes):
    s = _clean(data)
    if not _HAS_PERCENT.search(s) or not _URL_ALPHA.fullmatch(s):
        return None
    out = bytearray()
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == 0x25 and i + 2 < n:          # '%'
            try:
                out.append(int(s[i + 1:i + 3], 16))
            except ValueError:
                return None
            i += 3
        else:
            out.append(c)
            i += 1
    return _cap(bytes(out))


def _d_pem(data: bytes):
    m = _PEM.search(bytes(data))
    if not m:
        return None
    body = bytes(c for c in m.group(1) if c not in _WS)
    try:
        return _cap(base64.b64decode(body + b"=" * (-len(body) % 4), validate=True))
    except (binascii.Error, ValueError):
        return None


def _d_data_uri(data: bytes):
    m = _DATA_URI.match(_clean(data))
    if not m:
        return None
    body = bytes(c for c in m.group(1) if c not in _WS)
    try:
        return _cap(base64.b64decode(body + b"=" * (-len(body) % 4), validate=True))
    except (binascii.Error, ValueError):
        return None


# --- the bomb guard: bounded, incremental decompression (Day 27 build; see the module docstring) -------
# A decoder below gates on its input magic as before, then hands `_decode` a `run(data, sink)` function that
# drives the format's INCREMENTAL decompressor and gives every piece it yields to a `_Sink`. `run` follows the
# member / trailing-data / error rules of the stdlib one-shot function it replaces (gzip.decompress,
# bz2.decompress, lzma.decompress, zlib.decompress), so what it returns for a stream that fits is what that
# function returned; it raises on a stream the one-shot call refused, and `_decode` turns every raise into None.

class _Over(Exception):
    """The stream expands past MAX_OUT."""


class _Sink:
    """The output of one decode, bounded while it is produced.

    A decompress call is asked for `room()` bytes, never more than reaches MAX_OUT + 1 in all, so a stream
    past the cap is stopped (`add` raises `_Over`) with at most cap + 1 bytes of it ever produced. Output is
    held in pieces, up to `keep`. At the shipped KEEP_DIV of 1 `keep` is the cap, which `add` never lets a
    stream pass, so nothing is ever let go: ONE pass, and a bomb is refused with up to the cap in hand. With a
    smaller `keep` (KEEP_DIV above 1) the held pieces are let go past it and the rest is only counted
    (`counting`), so a bomb is rejected with `keep` plus one piece in hand, and a stream that turns out to
    fit gets a second pass that keeps everything. Members that end cleanly are folded in by `end_member`; one
    the stdlib's one-shot call ignores (what follows the last bz2 / xz stream) is dropped by `drop_member`."""

    __slots__ = ("cap", "keep", "step", "total", "cur", "kept", "done", "mem", "counting")

    def __init__(self, cap: int, keep: int, step: int):
        self.cap = cap          # MAX_OUT as of this decode
        self.keep = keep        # the most output held while the stream's length is open
        self.step = step        # the most one decompress call yields
        self.total = 0          # bytes of the members that ended cleanly
        self.cur = 0            # bytes of the member in flight
        self.kept = 0           # bytes held in done + mem
        self.done = []          # pieces of the members that ended cleanly
        self.mem = []           # pieces of the member in flight
        self.counting = False   # pieces are only counted: what was held has been let go

    def room(self) -> int:
        return max(1, min(self.step, self.cap + 1 - self.total - self.cur))

    def add(self, piece) -> None:
        n = len(piece)
        if not n:
            return
        self.cur += n
        if self.total + self.cur > self.cap:
            raise _Over
        if not self.counting:
            self.mem.append(piece)
            self.kept += n
            if self.kept > self.keep:
                self.done, self.mem, self.kept, self.counting = [], [], 0, True

    def end_member(self) -> None:
        self.total += self.cur
        self.cur = 0
        if self.mem:
            self.done += self.mem
            self.mem = []

    def drop_member(self) -> None:
        self.kept -= sum(map(len, self.mem))
        self.cur = 0
        self.mem = []

    def result(self) -> bytes:
        return self.done[0] if len(self.done) == 1 else b"".join(self.done)


def _decode(run, data: bytes):
    """What `run(data, sink)` decodes `data` to, or None: a bad or cut stream, one that expands past MAX_OUT
    (stopped as soon as it is known to), or one that decodes to nothing. One pass at the shipped KEEP_DIV of 1;
    above 1 a stream longer than MAX_OUT / KEEP_DIV is decoded a second time, to keep it."""
    cap = MAX_OUT
    keep = max(cap // max(KEEP_DIV, 1), 1)      # KEEP_DIV 1 keeps all of it: one pass, a bomb held up to the cap
    for hold in ((keep, cap) if keep < cap else (cap,)):
        sink = _Sink(cap, hold, max(min(STEP_OUT, hold // 2), 1))
        try:
            run(data, sink)
        except Exception:                       # _Over, a decode error, a truncated stream: not this envelope
            return None
        if sink.cur:                            # a member left in flight: the run did not finish
            return None
        if not sink.counting:
            return _cap(sink.result())
    return None                                 # (unreachable: a pass that holds the whole cap never counts)


def _inflate(mv, start: int, wbits: int, sink: _Sink, want_crc: bool = False):
    """Feed mv[start:] to a zlib decompressor (`wbits` as zlib.decompressobj takes it) up to the end of its
    stream, giving every piece to `sink`. Returns (offset just past the stream, crc32 and length of what it
    produced when `want_crc`, else 0 and 0). Whatever follows the stream is left alone, as zlib.decompress
    leaves it; a stream that ends before its end marker raises."""
    d = zlib.decompressobj(wbits)
    n, pos, crc, size, full = len(mv), start, 0, 0, False
    while not d.eof:
        tail = d.unconsumed_tail
        if tail:                                # the call before stopped at its output limit
            chunk = tail
        elif full:                              # ... and took all its input, but may hold output it had no room for
            chunk = b""
        elif pos < n:
            chunk = mv[pos:pos + STEP_IN]
            pos += len(chunk)
        else:
            raise EOFError("the deflate stream ends before its end marker")
        room = sink.room()
        piece = d.decompress(chunk, room)
        full = len(piece) >= room
        if piece:
            sink.add(piece)
            if want_crc:
                crc = zlib.crc32(piece, crc)
                size += len(piece)
        elif chunk and not d.eof and len(d.unconsumed_tail) >= len(chunk):
            raise ValueError("the decompressor neither took input nor gave output")
    return pos - len(d.unused_data), crc, size


def _stream(d, mv, start: int, sink: _Sink):
    """Feed mv[start:] to a bz2 or lzma decompressor object up to the end of its stream, giving every piece
    to `sink`. Returns the offset just past the stream, or None when the input ran out first."""
    n, pos, idle = len(mv), start, 0
    while not d.eof:
        if d.needs_input:
            if pos >= n:
                return None
            chunk = mv[pos:pos + STEP_IN]
            pos += len(chunk)
        else:
            chunk = b""                         # its last call stopped at the output limit: ask for the rest
        piece = d.decompress(chunk, sink.room())
        if piece:
            sink.add(piece)
            idle = 0
        elif not chunk and not d.eof:
            idle += 1
            if idle > 64:
                raise ValueError("the decompressor neither took input nor gave output")
    return pos - len(d.unused_data)


def _gzip_after_nul(b: bytes, p: int) -> int:
    i = b.find(b"\x00", p)
    return len(b) if i < 0 else i + 1


def _gzip_header(b: bytes, pos: int):
    """The offset just past the gzip member header at b[pos:]; None when b ends there. Raises when what is
    there is no gzip header (what gzip.decompress refuses). Mirrors gzip._read_gzip_header."""
    n = len(b)
    if pos >= n:
        return None
    if b[pos:pos + 2] != b"\x1f\x8b":
        raise ValueError("not a gzip member")
    if n - pos < 10:
        raise EOFError("the gzip header is cut short")
    if b[pos + 2] != 8:
        raise ValueError("unknown gzip compression method")
    flag, p = b[pos + 3], pos + 10
    if flag & 4:                                # FEXTRA
        if n - p < 2:
            raise EOFError("the gzip header is cut short")
        p += 2 + (b[p] | b[p + 1] << 8)
        if p > n:
            raise EOFError("the gzip header is cut short")
    if flag & 8:                                # FNAME
        p = _gzip_after_nul(b, p)
    if flag & 16:                               # FCOMMENT
        p = _gzip_after_nul(b, p)
    if flag & 2:                                # FHCRC
        p += 2
        if p > n:
            raise EOFError("the gzip header is cut short")
    return p


def _run_gzip(data: bytes, sink: _Sink):
    """gzip.decompress, bounded: members one after another (NUL bytes between them skipped), each checked
    against its CRC-32 and length; non-NUL bytes where a member should begin refuse the whole stream."""
    mv, n, pos = memoryview(data), len(data), 0
    while True:
        body = _gzip_header(data, pos)
        if body is None:
            return
        end, crc, size = _inflate(mv, body, -zlib.MAX_WBITS, sink, True)
        if n - end < 8:
            raise EOFError("the gzip member ends before its trailer")
        if (int.from_bytes(data[end:end + 4], "little") != crc
                or int.from_bytes(data[end + 4:end + 8], "little") != size & 0xFFFFFFFF):
            raise ValueError("gzip CRC or length check failed")
        sink.end_member()
        m = _NOT_NUL.search(data, end + 8)
        pos = m.start() if m else n


def _run_zlib(data: bytes, sink: _Sink):
    """zlib.decompress, bounded: one stream; whatever follows it is ignored."""
    _inflate(memoryview(data), 0, zlib.MAX_WBITS, sink)
    sink.end_member()


def _run_raw_deflate(data: bytes, sink: _Sink):
    """zlib.decompress(data, -15), bounded: one header-less deflate stream; whatever follows it is ignored."""
    _inflate(memoryview(data), 0, -zlib.MAX_WBITS, sink)
    sink.end_member()


def _run_bz2(data: bytes, sink: _Sink):
    """bz2.decompress, bounded: streams one after another; bytes after the last good one that are no bz2
    stream are ignored (one that is cut short is an error)."""
    mv, n, pos, members = memoryview(data), len(data), 0, 0
    while pos < n:
        d = bz2.BZ2Decompressor()
        try:
            end = _stream(d, mv, pos, sink)
        except OSError:
            if not members:
                raise
            sink.drop_member()                  # leftover data is not a valid bzip2 stream: ignored
            return
        if end is None:
            raise ValueError("the bz2 stream ends before its end marker")
        if end <= pos:
            raise ValueError("a bz2 stream that took no input")
        sink.end_member()
        members += 1
        pos = end


def _run_xz(data: bytes, sink: _Sink):
    """lzma.decompress, bounded: streams one after another (the format is read off each one's first byte);
    bytes after the last good one that are no stream are ignored (one that is cut short is an error)."""
    mv, n, pos, members = memoryview(data), len(data), 0, 0
    while True:
        d = lzma.LZMADecompressor()
        try:
            end = _stream(d, mv, pos, sink)
        except lzma.LZMAError:
            if not members:
                raise
            sink.drop_member()                  # leftover data is not a valid LZMA/XZ stream: ignored
            return
        if end is None:
            raise lzma.LZMAError("the stream ends before its end marker")
        if end <= pos:
            raise ValueError("a stream that took no input")
        sink.end_member()
        members += 1
        if end >= n:
            return
        pos = end


def _d_gzip(data: bytes):
    if not bytes(data[:2]) == b"\x1f\x8b":
        return None
    return _decode(_run_gzip, bytes(data))


def _d_zlib(data: bytes):
    if len(data) < 2 or data[0] != 0x78:     # zlib header byte; CMF=0x78 covers 1/9c/da/5e
        return None
    return _decode(_run_zlib, bytes(data))


def _d_raw_deflate(data: bytes):
    # No header/magic. GATED entirely by the recognizer on the OUTPUT (see _peel_one): a raw-deflate
    # stream whose inflation does not start with a known magic is discarded.
    if len(data) < 2:
        return None
    return _decode(_run_raw_deflate, bytes(data))


def _d_bz2(data: bytes):
    if not bytes(data[:3]) == b"BZh":
        return None
    return _decode(_run_bz2, bytes(data))


def _d_xz(data: bytes):
    if not bytes(data[:6]) == b"\xfd7zXZ\x00":
        return None
    return _decode(_run_xz, bytes(data))


# --- Day-26 additions: zstd / lz4 frame / snappy framed (strong input magic, safe in the blind battery)
# and brotli / raw snappy (NO magic: reachable ONLY through an explicit hint, see HINT_BATTERY).
# A missing library declines the format (returns None); nothing is half-implemented. Output is bounded
# by MAX_OUT while it is produced (the bomb guard above: each of these asks its library for a bounded
# piece at a time, the Day 27 build) and every result is still gated by the output recognizer.

ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
LZ4_MAGIC = b"\x04\x22\x4d\x18"
SNAPPY_FRAMED_MAGIC = b"\xff\x06\x00\x00sNaPpY"
ZSTD_BLOCK = 1 << 16        # input a zstd decode read at a time before Day 27 (its `decompressobj` loop), kept


class _Reader:
    """A file object over bytes that remembers how far it has been read (zstd's `read_to_iter`)."""

    __slots__ = ("b", "pos")

    def __init__(self, b: bytes):
        self.b, self.pos = b, 0

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            n = len(self.b) - self.pos
        piece = self.b[self.pos:self.pos + n]
        self.pos += len(piece)
        return piece


def _run_zstd(data: bytes, sink: _Sink):
    """The zstd frame, bounded. `read_to_iter` yields at most a piece's worth at a time and stops at the end
    of the first frame, as the decompressobj loop it replaces did (a truncated frame gives what its whole
    blocks hold, trailing data in the block that ends the frame is ignored). That loop fed 64 KiB at a time
    and failed on any block it fed after the frame was over, so a frame followed by a further 64 KiB block of
    anything is refused here too."""
    import zstandard
    rd = _Reader(data)
    for piece in zstandard.ZstdDecompressor().read_to_iter(rd, read_size=ZSTD_BLOCK, write_size=sink.step):
        sink.add(piece)
    if rd.pos < len(data):
        raise ValueError("more input after the end of the zstd frame")
    sink.end_member()


def _run_lz4(data: bytes, sink: _Sink):
    """The lz4 frame, bounded: the first frame, trailing data ignored, a truncated frame refused."""
    import lz4.frame
    d = lz4.frame.LZ4FrameDecompressor()
    piece = data
    while True:
        sink.add(d.decompress(piece, max_length=sink.room()))
        if d.eof:
            break
        if d.needs_input:
            raise EOFError("truncated lz4 frame")
        piece = b""
    sink.end_member()


_CHUNK_HEAD = struct.Struct("<I").unpack_from      # a chunk's header: its type byte, then its length in 3 bytes, low first


def _run_snappy_framed(data: bytes, sink: _Sink):
    """The snappy framing, bounded. The decoder takes no output limit, so what bounds a call is its input: the
    chunks are walked ONCE here, by python-snappy's own rule (a type byte and a 3-byte little-endian length,
    4 bytes more in all), and runs of WHOLE chunks, at most STEP_IN_SNAPPY bytes of them (a longer chunk goes
    alone), are handed to the engine python-snappy's `StreamDecompressor` wraps, cramjam's, each behind a stream
    header of its own (chunks do not depend on one another). A chunk holds at most 64 KiB of output (the engine
    refuses more), so a call cannot give much more than 21 times its input. A stream cut inside a chunk gives the
    chunks before it, as the one-shot `StreamDecompressor.decompress` did.

    Feeding `StreamDecompressor` itself in slices was quadratic: it keeps a half-fed chunk in `remains` and copies
    it again on every call, so a header that declares a 16 MiB chunk cost 0.25 to 0.5 s of copying (0.001 s one-shot).
    Whole chunks only, so there is no `remains`, and cramjam directly, so no second per-chunk loop runs."""
    import snappy  # noqa: F401  (the library that names the format: without it the format is declined, as before)
    import cramjam
    d, hdr, n = cramjam.snappy.Decompressor(), SNAPPY_FRAMED_MAGIC, len(data)

    def feed(a: int, b: int) -> None:
        d.decompress(hdr + data[a:b])
        sink.add(bytes(d.flush()))

    pos = start = len(hdr)
    limit = start + STEP_IN_SNAPPY                  # the run in hand ends by here, or it is one chunk
    while pos + 4 <= n:
        end = pos + (_CHUNK_HEAD(data, pos)[0] >> 8) + 4
        if end > n:
            break                                   # a chunk cut short: never fed, as StreamDecompressor never fed it
        if end > limit and pos > start:
            feed(start, pos)
            start, limit = pos, pos + STEP_IN_SNAPPY
        pos = end
    if pos > start:
        feed(start, pos)
    sink.end_member()


def _run_brotli(data: bytes, sink: _Sink):
    """The brotli stream, bounded by the decompressor's own output buffer limit. A soft one (brotli 1.2.0): the
    output buffer grows in doubling blocks (32752, 65520, ... bytes) and stops once it holds what was asked
    for, so a call can give up to about twice the room it was asked for (2,064,288 bytes at the 1 MiB room of
    STEP_OUT) and 32752 bytes when asked for 1. That cannot make a refusal wrong, since every byte a call gives
    is real output, only the overshoot past MAX_OUT is wider than a block. A stream that is not finished is
    refused."""
    import brotli
    d = brotli.Decompressor()
    sink.add(d.process(data, output_buffer_limit=sink.room()))
    while not d.is_finished():
        piece = d.process(b"", output_buffer_limit=sink.room())   # output the last call had no room for
        if not piece:
            raise EOFError("truncated brotli stream")
        sink.add(piece)
    sink.end_member()


def _d_zstd(data: bytes):
    if bytes(data[:4]) != ZSTD_MAGIC:
        return None
    return _decode(_run_zstd, bytes(data))


def _d_lz4(data: bytes):
    if bytes(data[:4]) != LZ4_MAGIC:
        return None
    return _decode(_run_lz4, bytes(data))


def _d_snappy_framed(data: bytes):
    if bytes(data[:10]) != SNAPPY_FRAMED_MAGIC:
        return None
    return _decode(_run_snappy_framed, bytes(data))


def _d_brotli(data: bytes):
    # No magic: only ever called under an explicit hint, and only accepted on a >=4-byte output magic.
    return _decode(_run_brotli, bytes(data))


def _d_snappy_raw(data: bytes):
    # A raw snappy block begins with the length it decodes to (a base-128 varint) and the decoder insists on
    # it, so a block that declares more than MAX_OUT is refused before the library allocates its output.
    try:
        import snappy
        b = bytes(data)
        n = shift = 0
        for c in b[:5]:
            n |= (c & 0x7F) << shift
            if not c & 0x80:
                break
            shift += 7
        else:
            return None                          # no end to the varint: not a raw snappy block
        if n > MAX_OUT:
            return None
        return _cap(snappy.uncompress(b))
    except Exception:
        return None


def _d_reverse(data: bytes):
    # A pure transform; only ever accepted when its OUTPUT is recognized (a reversed zip/elf/...).
    return _cap(bytes(data)[::-1])


def _d_byteswap16(data: bytes):
    b = bytes(data)
    if len(b) < 2 or len(b) % 2:
        return None
    out = bytearray(len(b))
    out[0::2], out[1::2] = b[1::2], b[0::2]
    return _cap(bytes(out))


# The battery, as (name, fn, strong). `strong` True means the decode has no input magic of its own
# (raw-deflate) or is a pure byte transform (reverse, byteswap), so it is recognized ONLY by a >=4-byte
# magic on its output -- a 2-byte MZ on the coincidental head of a transformed binary is not enough.
# The rest have a strong input gate (a whole-input alphabet, a literal marker, or a decompressor magic
# with a checksum), so a weak output magic is acceptable. Order is cheap-and-specific first.
_BATTERY = (
    ("gzip", _d_gzip, False),
    ("zlib", _d_zlib, False),
    ("bz2", _d_bz2, False),
    ("xz", _d_xz, False),
    ("zstd", _d_zstd, False),
    ("lz4", _d_lz4, False),
    ("snappy-framed", _d_snappy_framed, False),
    ("pem", _d_pem, False),
    ("data-uri", _d_data_uri, False),
    ("base64", _d_base64, False),
    ("base64url", _d_base64url, False),
    ("base32", _d_base32, False),
    ("base85", _d_base85, False),
    ("ascii85", _d_ascii85, False),
    ("base58", _d_base58, False),
    ("base16", _d_base16, False),
    ("url", _d_url, False),
    ("raw-deflate", _d_raw_deflate, True),
    ("byteswap16", _d_byteswap16, True),
    ("reverse", _d_reverse, True),
)


# No-magic codecs: NEVER in the blind battery. Used only when the caller passes `hints=` naming them
# (an explicit upstream signal such as a `.br` / `.sz` member name). Output must carry a >=4-byte magic.
HINT_BATTERY = {
    "brotli": ("brotli", _d_brotli, True),
    "snappy": ("snappy-raw", _d_snappy_raw, True),
}

HINT_SUFFIXES = {".br": "brotli", ".brotli": "brotli", ".sz": "snappy", ".snappy": "snappy"}


def hints_for_name(name) -> tuple:
    """Raw-codec hints carried by any explicit suffix in an envelope name.

    The suffix order is the layer order: ``x.zip.br.b64`` says the Base64 text contains a Brotli
    stream.  The raw decoder remains output-structure-gated, so retaining ``br`` while peeling the
    outer suffix cannot turn an unrelated file into an artifact.
    """
    n = str(name or "").lower().split(" [unwrap:")[0].replace("\\", "/").rsplit("/", 1)[-1]
    found = []
    for part in n.split(".")[1:]:
        hint = HINT_SUFFIXES.get("." + part)
        if hint is not None and hint not in found:
            found.append(hint)
    return tuple(found)


# --------------------------------------------------------------------------- XOR layers (warmups)

XOR_MAX = 4 * 1024 * 1024   # XOR is byte-for-byte; bounded to keep the battery cheap on big inputs


def _xor_single(data: bytes, k: int) -> bytes:
    return bytes(b ^ k for b in data)


def _xor_key(data: bytes, key: bytes) -> bytes:
    n = len(key)
    return bytes(b ^ key[i % n] for i, b in enumerate(data))


def _recover_xor_key(data: bytes, crib: bytes, max_key: int = 16):
    """A repeating XOR key recovered from a known-plaintext crib at offset 0 (the warmups sentence
    begins the plaintext). Returns the shortest key of length 1..max_key whose repetition against the
    crib bytes is self-consistent, else None. This only PROPOSES a key; the result is still gated by
    the caller's recognizer (the full crib must survive), so a spurious short key is discarded."""
    if len(data) < len(crib) or not crib:
        return None
    raw = bytes(data[:len(crib)])
    stream = bytes(a ^ b for a, b in zip(raw, crib))   # key repeated over len(crib)
    for klen in range(1, min(max_key, len(stream)) + 1):
        cand = stream[:klen]
        if cand * (len(stream) // klen) + cand[:len(stream) % klen] == stream:
            return cand
    return None


def xor_layers(data: bytes, cribs=(), single: bool = True):
    """Yield (xored_bytes, step_name) for candidate XOR peels of `data`:
      * every single-byte key 1..255 (when `single`), and
      * a repeating key recovered from each crib by known-plaintext at offset 0.
    These are CANDIDATES only; the caller gates them with a recognizer (magic / crib / checksum). A
    wrong key yields bytes the recognizer rejects, so nothing speculative is ever kept."""
    b = bytes(data)
    if not (MIN_LEN <= len(b) <= XOR_MAX):
        return
    if single:
        for k in range(1, 256):
            yield _xor_single(b, k), "xor:%02x" % k
    seen = set()
    for crib in cribs:
        if not crib:
            continue
        key = _recover_xor_key(b, bytes(crib))
        if key and key not in seen and any(key):
            seen.add(key)
            yield _xor_key(b, key), "xorkey:" + key.hex()


# --------------------------------------------------------------------------- the peeler

_XOR_CONTINUE_MAX = 64 * 1024   # bytes: in try_xor mode, codec-decoded binary this small may hide an XOR layer


def _is_printable(out: bytes) -> bool:
    sample = bytes(out[:256])
    return sum(1 for c in sample if 9 <= c <= 13 or 32 <= c <= 126) >= 0.90 * len(sample)


def _continuable(out: bytes, crib, try_xor: bool, from_xor: bool, hinted: bool = False) -> bool:
    """Whether a NON-recognized decode is worth one more level (a 2-level nest). Kept tight to avoid a
    frontier blow-up:
      * a compressor magic, or printable-ish text (another codec layer), is always worth one more level;
      * in try_xor mode, small BINARY from a CODEC step is followed so `base64(xor(text))` reaches the
        plaintext (the XOR then runs next level, still crib-gated);
      * binary produced BY an XOR step is a dead end -- a second XOR is just another single key, no new
        reach -- so it is dropped, which keeps the 255-key fan-out from starving the real path.
    Everything else is a dead end."""
    if not out or len(out) < MIN_LEN:
        return False
    head = bytes(out[:16])
    if head[:2] == b"\x1f\x8b" or head[:3] == b"BZh" or head[:6] == b"\xfd7zXZ\x00" or head[:1] == b"x" \
            or head[:4] in (ZSTD_MAGIC, LZ4_MAGIC) or head[:10] == SNAPPY_FRAMED_MAGIC:
        return True
    if _is_printable(out):                   # another layer of text (base64/hex/url/...), via XOR or codec
        return True
    if hinted and not from_xor:
        # Raw Brotli/Snappy have no magic.  A filename such as .br.b64 is an explicit claim that a
        # binary intermediate is worth carrying to the next bounded level; the hinted decoder's output
        # still has to pass the normal endpoint recognizer before anything is returned.
        return True
    if try_xor and not from_xor and len(out) <= _XOR_CONTINUE_MAX:
        return True                          # codec-decoded binary: an XOR layer may be under it
    return False


def peel(data, recognize=None, crib=None, try_xor=False, max_depth=DEFAULT_DEPTH,
         deadline=None, max_nodes=MAX_NODES, _state=None, hints=()):
    """Peel reversible envelopes off `data` and return a list of (decoded_bytes, chain) for every
    RECOGNIZED inner stream, best (shortest chain) first.

    recognize : predicate bytes -> bool deciding an inner stream is worth revealing. Default is
                `looks_like_container` (starts with a known magic). Pass your own for a clean-parse or
                checksum gate.
    crib      : bytes; a convenience recognizer "the full crib survives in the decoded bytes" (used by
                warmups). Combined with the default/`recognize` by OR. When set, `_continuable` also
                follows printable text one more level.
    try_xor   : also try single-byte and crib-recovered repeating-XOR layers (warmups). Off for the
                container use (a whole APK is not XOR-wrapped, and 255 keys x battery is wasted there).
    max_depth : levels of nesting to follow (default 2 -> one 2-level nest).
    deadline  : optional time.perf_counter() budget; peeling stops early and returns what it has.

    Guarantees: never returns a speculative decode (every result passed `recognize`); the original
    bytes are never altered; bounded by MAX_NODES / MAX_RESULTS / byte sizes."""
    if not isinstance(data, (bytes, bytearray)):
        return []
    data = bytes(data)
    if not (MIN_LEN <= len(data) <= MAX_IN):
        return []

    cribs = ()
    base_recog = recognize or looks_like_container
    # A caller-supplied `recognize` is trusted to gate itself (it decides for strong and weak alike); only
    # the DEFAULT magic recognizer gets the >=4-byte-magic tightening for strong (header-less/transform)
    # decoders.
    strong_recog = looks_like_container_strong if recognize is None else base_recog
    if crib:
        crib = bytes(crib)
        cribs = (crib,)

        def _recog(out, strong, _crib=crib):
            return (_crib in out) or (strong_recog(out) if strong else base_recog(out))
    else:
        def _recog(out, strong):
            return strong_recog(out) if strong else base_recog(out)

    st = _state if _state is not None else {"nodes": 0, "seen": set(), "results": [], "order": {}}
    frontier = [(data, ())]
    seen = st["seen"]
    seen.add(data)
    stop = [False]

    def _over() -> bool:
        if st["nodes"] >= max_nodes or len(st["results"]) >= MAX_RESULTS:
            return True
        if deadline is not None and time.perf_counter() > deadline:
            return True
        return False

    def _offer(out, step, chain, nxt, depth, from_xor, strong):
        if not out or out in seen:
            return
        seen.add(out)
        new_chain = chain + (step,)
        if _recog(out, strong):
            if out not in st["order"]:
                st["order"][out] = new_chain
                st["results"].append((out, new_chain))
        elif depth < max_depth and _continuable(out, crib, try_xor, from_xor, hinted=bool(hints)):
            nxt.append((out, new_chain))

    depth = 0
    while frontier and depth < max_depth and not stop[0]:
        depth += 1
        nxt = []
        for cur, chain in frontier:
            if _over():
                stop[0] = True
                break
            # A name such as ``artifact.zip.br.b64`` describes an INNER raw stream.  Carry its explicit
            # hint through every bounded depth; trying the raw decoder too early simply returns None and
            # every eventual output is still accepted only by the structural recognizer.
            extra = tuple(HINT_BATTERY[h] for h in hints if h in HINT_BATTERY)
            for name, fn, strong in _BATTERY + extra:
                if _over():
                    stop[0] = True
                    break
                st["nodes"] += 1
                _offer(fn(cur), name, chain, nxt, depth, from_xor=False, strong=strong)
            if stop[0]:
                break
            # XOR is never applied to a node already produced by XOR (two XORs are just one key, no new
            # reach) -- this also keeps the 255-key fan-out from starving the real path.
            if try_xor and not _over() and not (chain and chain[-1].startswith("xor")):
                for out, step in xor_layers(cur, cribs=cribs, single=True):
                    if _over():
                        stop[0] = True
                        break
                    st["nodes"] += 1
                    _offer(out, step, chain, nxt, depth, from_xor=True, strong=True)
            if stop[0]:
                break
        frontier = nxt
    # shortest chain first, then by discovery order
    return sorted(st["results"], key=lambda r: (len(r[1]), r[1]))
