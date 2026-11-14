"""A config packed with no digest to check (the Day 20 coverage-gap build, binary group).

Row 366 (`generic._overlay_record`) and the Day 19 live fix `fields_d19.py` read a trailing packed overlay
only behind its stored SHA-256. This module reads the same kind of thing when nothing stores a digest: the
HCFG container carries its own CRC-32, so a decoding that yields a whole container whose CRC-32 checks is the
proof, as for every other reading of the lane (`hcfg.containers`).

`generic._choose_config` asks it ONLY when the ordinary walk (layers, needles, the SHA overlay) found no
CRC-valid container in any of the prefix's files, so a day whose config the walk reads pays nothing. It
returns layers `(how, bytes)` for `hcfg.containers` to read; the caller accepts the result only when exactly
one distinct CRC-valid container of the day comes out of all of them (two that differ: None).

Where it looks (`regions`; TAIL_MAX is 4 MiB since row 387, 1 MiB before): an ELF's or PE's tail, from the end of its last mapped or listed byte (PT_LOAD,
section, header tables) to EOF, when that tail is TAIL_MAX or less, and the bytes before the tail when they are
TAIL_MAX or less; any other member whole when it is TAIL_MAX or less. Nothing else is read. Raw deflate and the
zlib header under a key are tried only at a tail's head or at the start of a member that is no executable. A raw
deflate stream inside an ELF is also tried immediately after a short ASCII identifier tag and NUL in a validated,
file-backed PT_LOAD range. The tag places, range bytes, compressed input and inflated output are all capped; the
stream must reach EOF, and the caller still accepts only a whole CRC-valid HCFG record.

What it reads, every family found by the mark the magic leaves under it, never by trying keys blindly:

  bytewise    plain = ror(b, n) ^ K        n 0..7, K 0..255 (xor, rotate, nibble swap = ror 4, and the two-key
                                           xor-then-rotate of PK19, which collapses to one rotation and one key)
              plain = ror(b + k, n)        add/sub, alone or before a rotation
              plain = ror(b, n) + k        a rotation before add/sub
              each over the region and over the region byte-reversed. The xor family is one search of the
              region's xor-difference stream for the rotated magic's differences (a key cancels in it); the add
              family the same over the subtraction-difference stream.
  streams     zlib, gzip, bz2, xz and LZMA-alone by their headers, in the region (the walk already reads them in
              a member under 4 MB; this reads the tail of a larger one); the same headers under a one-byte XOR
              (gzip, bz2, xz and LZMA-alone found by their xor-differences anywhere, zlib's two-byte header only
              at the head); raw deflate (no header) at the head only, plain and under each key byte of the head.
  head        the first HEAD_TRIES bytes of the region after its zero fill: the overlay's start, where a small
              header (a tag, k1, k2, a length) sits before the packed bytes.
  row 387     (the Day 20 speed build; `search_layers`, its own section below) two-key compositions that do not
              collapse, (b + k) ^ K and (b ^ K) + k, by an index of their difference signatures; and a byte map
              (any one-key family above, or a two-key one with a key from the head) before a zlib, gzip, bzip2, xz
              or LZMA-alone stream, at the starts a length field at the head pins and at the head itself.

Bounds, all by counts and bytes (never a clock, so the base, a gate's replay and a clock agree): TAIL_MAX bytes
read, SIG_HITS places of one signature, WINDOW bytes decoded at each place, HEAD_TRIES offsets and HEAD_KEYS
keys for raw deflate, OUT_MAX bytes out of one stream, MAX_LAYERS layers in all.
"""
import bz2
import hashlib
import lzma
import re
import struct
import zlib

MAGIC = b"HCFG"
TAIL_MAX = 4 << 20          # bytes of a region read (1 MiB until row 387)
WINDOW = 1 << 16            # bytes decoded at one place (a container is at most 12 + 65535)
SIG_HITS = 16               # places of one signature in one stream
HEAD_TRIES = 64             # offsets after the head's zero fill tried for raw deflate and zlib under xor
HEAD_KEYS = 16              # distinct key bytes of the head tried under raw deflate
PROBE = 512                 # bytes of a stream tried before the whole of it
OUT_MAX = 1 << 20           # bytes out of one stream
MAX_LAYERS = 256
ELF_LOAD_HEADERS = 256     # more program headers: the tagged-stream carrier is unsupported, never partly read
ELF_LOADS = 16             # file-backed PT_LOAD ranges considered
ELF_TAG_SCAN_MAX = 4 << 20 # more mapped bytes: unsupported, so an unread second record cannot be missed
ELF_TAG_HITS = 32          # more candidate starts: unsupported, never a partial choice
RAW_INPUT_MAX = 1 << 20    # compressed bytes supplied to one raw-deflate decoder
RAW_PROBE = 4096           # cheap first pass: a direct HCFG stream exposes its magic here

_CACHE = {}
_CACHE_MAX = 8


def _ror(v, n):
    n &= 7
    return ((v >> n) | (v << (8 - n))) & 0xFF if n else v


def _rol(v, n):
    return _ror(v, 8 - (n & 7))


_ROR = [bytes(_ror(b, n) for b in range(256)) for n in range(8)]
_XOR = {}


def _x(data: bytes, k: int) -> bytes:
    """`data` under a one-byte XOR key (one translate)."""
    t = _XOR.get(k)
    if t is None:
        t = _XOR[k] = bytes(b ^ k for b in range(256))
    return data.translate(t)


def _xd(seq: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(seq, seq[1:]))


def _sd(seq: bytes) -> bytes:
    return bytes((b - a) & 0xFF for a, b in zip(seq, seq[1:]))


def _rot_magic(n):
    return bytes(_rol(b, n) for b in MAGIC)


XOR_SIGS = [_xd(_rot_magic(n)) for n in range(8)]     # plain = ror(b, n) ^ K
ADD_ROT_SIGS = [_sd(_rot_magic(n)) for n in range(8)]  # plain = ror(b + k, n)
ADD_SIG = _sd(MAGIC)                                  # plain = ror(b, n) + k, over ror_n(region)


def _diffs(region: bytes):
    """(xor-difference, subtraction-difference) streams: d[i] is about region[i] and region[i + 1]."""
    try:
        import numpy as np
        a = np.frombuffer(region, np.uint8)
        return (a[:-1] ^ a[1:]).tobytes(), (a[1:] - a[:-1]).tobytes()
    except ImportError:
        return _xd(region), _sd(region)


def _finds(stream: bytes, sig: bytes):
    at, n = stream.find(sig), 0
    while at >= 0 and n < SIG_HITS:
        n += 1
        yield at
        at = stream.find(sig, at + 1)


def _bytewise(region: bytes, tag: str):
    """(how, decoded window) of every place where the magic stands under a transform of the family."""
    if len(region) < 16:
        return
    xd, sd = _diffs(region)
    for n in range(8):
        for i in _finds(xd, XOR_SIGS[n]):
            k = _ror(region[i], n) ^ MAGIC[0]
            if n == 0 and k == 0:
                continue                       # the magic in clear: the walk's own
            table = bytes(_ror(b, n) ^ k for b in range(256))
            win = region[i:i + WINDOW].translate(table)
            if win[:4] == MAGIC:
                yield f"{tag}ror{n}^{k:02x}@0x{i:x}", win
        for i in _finds(sd, ADD_ROT_SIGS[n]):
            k = (_rol(MAGIC[0], n) - region[i]) & 0xFF
            if k == 0:
                continue                       # no add: the xor family's (K 0)
            table = bytes(_ror((b + k) & 0xFF, n) for b in range(256))
            win = region[i:i + WINDOW].translate(table)
            if win[:4] == MAGIC:
                yield f"{tag}add{k:02x}>ror{n}@0x{i:x}", win
    for n in range(1, 8):
        rn = region.translate(_ROR[n])
        _, sdn = _diffs(rn)
        for i in _finds(sdn, ADD_SIG):
            k = (MAGIC[0] - rn[i]) & 0xFF
            if k == 0:
                continue
            table = bytes((_ror(b, n) + k) & 0xFF for b in range(256))
            win = region[i:i + WINDOW].translate(table)
            if win[:4] == MAGIC:
                yield f"{tag}ror{n}>add{k:02x}@0x{i:x}", win


def _inflate(make, region: bytes, at: int, k: int = 0):
    """The bytes a stream starting at `at` (under the one-byte XOR `k`) inflates to when they hold the magic,
    else b"". Its first PROBE bytes are tried alone first, so a place that is no stream costs no copy of the
    rest."""
    head = region[at:at + PROBE]
    try:
        make().decompress(_x(head, k) if k else head, OUT_MAX)
        whole = region[at:at + OUT_MAX + 1]
        got = make().decompress(_x(whole, k) if k else whole, OUT_MAX)
    except (zlib.error, lzma.LZMAError, OSError, EOFError, ValueError):
        return b""
    return got if len(got) >= 12 and MAGIC in got else b""


_STREAMS = (
    ("gzip", b"\x1f\x8b\x08", lambda: zlib.decompressobj(31)),
    ("bz2", b"BZh", bz2.BZ2Decompressor),
    ("xz", b"\xfd7zXZ\x00", lambda: lzma.LZMADecompressor(lzma.FORMAT_XZ)),
    ("lzma", b"\x5d\x00\x00", lambda: lzma.LZMADecompressor(lzma.FORMAT_ALONE)),
)
_ZLIB_FLG = (0x01, 0x5E, 0x9C, 0xDA)


def _head(region: bytes) -> int:
    """Where the region's bytes begin after its zero fill (the overlay's own first byte)."""
    n = len(region) - len(region.lstrip(b"\x00"))
    return n if n < len(region) else 0


def _streams(region: bytes, tag: str, head_ok: bool = True):
    """(how, inflated bytes) of the compressed streams of the family (module docstring)."""
    xd, _ = _diffs(region)
    for name, magic, make in _STREAMS:
        for i in _finds(xd, _xd(magic)):
            k = region[i] ^ magic[0]
            got = _inflate(make, region, i, k)
            if got:
                yield f"{tag}{'' if not k else f'xor{k:02x}>'}{name}@0x{i:x}", got
    if not head_ok:
        return
    h = _head(region)
    keys = []
    for b in region[h:h + 32]:
        if b and b not in keys and len(keys) < HEAD_KEYS:
            keys.append(b)
    zlib_make, raw_make = (lambda: zlib.decompressobj(15)), (lambda: zlib.decompressobj(-15))
    for j in range(h, min(len(region) - 2, h + HEAD_TRIES)):
        # zlib under a one-byte xor (the plain header is the walk's)
        k = region[j] ^ 0x78
        if k and region[j + 1] ^ k in _ZLIB_FLG:
            got = _inflate(zlib_make, region, j, k)
            if got:
                yield f"{tag}xor{k:02x}>zlib@0x{j:x}", got
        # raw deflate, plain and under each key byte of the head
        for k in [0] + keys:
            got = _inflate(raw_make, region, j, k)
            if got:
                yield f"{tag}{'' if not k else f'xor{k:02x}>'}deflate@0x{j:x}", got


def _elf_end(d: bytes):
    if d[:4] != b"\x7fELF" or len(d) < 52:
        return None
    bits, endian = d[4], d[5]
    if bits not in (1, 2) or endian not in (1, 2):
        return None
    e = "<" if endian == 1 else ">"
    try:
        if bits == 2:
            phoff, shoff = struct.unpack_from(e + "QQ", d, 0x20)
            ehsize, phentsize, phnum, shentsize, shnum = struct.unpack_from(e + "HHHHH", d, 0x34)
        else:
            phoff, shoff = struct.unpack_from(e + "II", d, 0x1C)
            ehsize, phentsize, phnum, shentsize, shnum = struct.unpack_from(e + "HHHHH", d, 0x28)
        end = max(ehsize, phoff + phentsize * phnum, shoff + shentsize * shnum)
        for k in range(min(phnum, 256)):
            o = phoff + k * phentsize
            if bits == 2:
                p_offset, = struct.unpack_from(e + "Q", d, o + 8)
                p_filesz, = struct.unpack_from(e + "Q", d, o + 32)
            else:
                p_offset, p_filesz = struct.unpack_from(e + "I", d, o + 4)[0], struct.unpack_from(e + "I", d, o + 16)[0]
            end = max(end, p_offset + p_filesz)
        for k in range(min(shnum, 4096)):
            o = shoff + k * shentsize
            sh_type, = struct.unpack_from(e + "I", d, o + 4)
            if sh_type == 8:                     # SHT_NOBITS holds no file bytes
                continue
            if bits == 2:
                off, size = struct.unpack_from(e + "QQ", d, o + 24)
            else:
                off, size = struct.unpack_from(e + "II", d, o + 16)
            end = max(end, off + size)
    except struct.error:
        return None
    return end


_ELF_TAG = re.compile(rb"(?<![A-Za-z0-9_.+\-])[A-Za-z][A-Za-z0-9_.+\-]{1,15}\x00")


def _elf_load_ranges(d: bytes):
    """Validated file ranges of an ELF's PT_LOAD entries, or [] for an unsupported/malformed table.

    This is deliberately all-or-nothing: a truncated table or any file-backed PT_LOAD outside the artifact makes
    the tag-anchored raw-deflate carrier unreadable instead of letting a convenient surviving entry win.
    """
    if d[:4] != b"\x7fELF" or len(d) < 52:
        return []
    bits, endian = d[4], d[5]
    if bits not in (1, 2) or endian not in (1, 2):
        return []
    e = "<" if endian == 1 else ">"
    try:
        if bits == 2:
            if len(d) < 64:
                return []
            phoff, = struct.unpack_from(e + "Q", d, 0x20)
            ehsize, phentsize, phnum = struct.unpack_from(e + "HHH", d, 0x34)
            need, off_at, size_at = 56, 8, 32
        else:
            phoff, = struct.unpack_from(e + "I", d, 0x1C)
            ehsize, phentsize, phnum = struct.unpack_from(e + "HHH", d, 0x28)
            need, off_at, size_at = 32, 4, 16
        if ehsize < (64 if bits == 2 else 52) or not phnum or phnum > ELF_LOAD_HEADERS or phentsize < need:
            return []
        if phoff > len(d) or phnum * phentsize > len(d) - phoff:
            return []
        out = []
        for k in range(phnum):
            row = phoff + k * phentsize
            p_type, = struct.unpack_from(e + "I", d, row)
            if p_type != 1:                         # PT_LOAD only: a byte-proven file-backed carrier
                continue
            p_offset = struct.unpack_from(e + ("Q" if bits == 2 else "I"), d, row + off_at)[0]
            p_filesz = struct.unpack_from(e + ("Q" if bits == 2 else "I"), d, row + size_at)[0]
            if p_offset > len(d) or p_filesz > len(d) - p_offset:
                return []
            if p_filesz and (p_offset, p_offset + p_filesz) not in out:
                out.append((p_offset, p_offset + p_filesz))
                if len(out) > ELF_LOADS:
                    return []                       # unsupported layout, not a partial choice
        return out
    except (struct.error, OverflowError):
        return []


def _raw_deflate_bounded(d: bytes, at: int, end: int):
    """A complete capped raw-deflate stream at `at` whose early output and whole output hold HCFG, else b"".

    Requiring `eof` is material: a truncated stream that happens to expose a valid-looking record prefix and a
    stream whose output continues past OUT_MAX are not carriers. Bytes after the stream are allowed because an ELF
    segment naturally continues after a constant.
    """
    if at >= end:
        return b""
    view = memoryview(d)[at:min(end, at + RAW_INPUT_MAX)]
    try:
        probe = zlib.decompressobj(-15).decompress(view[:RAW_PROBE], OUT_MAX + 1)
        if len(probe) > OUT_MAX or MAGIC not in probe:
            return b""
        dec = zlib.decompressobj(-15)
        got = dec.decompress(view, OUT_MAX + 1)
    except (zlib.error, ValueError):
        return b""
    if len(got) > OUT_MAX or dec.unconsumed_tail or not dec.eof or MAGIC not in got:
        return b""
    return got


def _elf_tagged_deflate(d: bytes):
    """Raw-deflate layers immediately after bounded ASCII identifier tags in validated ELF PT_LOAD bytes.

    The tag and stream start must be mapped. The capped stream may finish in the file overlay: compilers and linkers
    can put a constant at the end of a load range whose alignment/padding bytes follow outside that range.
    """
    ranges = _elf_load_ranges(d)
    if sum(hi - lo for lo, hi in ranges) > ELF_TAG_SCAN_MAX:
        return                                  # not exhaustive: choosing an early record would be unsafe
    marks, seen = [], set()
    for lo, hi in ranges:
        for m in _ELF_TAG.finditer(d, lo, hi):
            if m.end() >= hi:                    # at least the stream's first byte must be file-backed
                continue
            place = (m.start(), m.end())
            if place in seen:                   # overlapping PT_LOAD entries can name the same file bytes
                continue
            seen.add(place)
            marks.append((m.end(), m.group()[:-1]))
            if len(marks) > ELF_TAG_HITS:
                return                          # not exhaustive: keep the whole carrier unsupported
    for at, raw_tag in marks:
        got = _raw_deflate_bounded(d, at, len(d))
        if got:
            tag = raw_tag.decode("ascii", "replace")
            yield f"elf-tag:{tag}>deflate@0x{at:x}", got


def _pe_end(d: bytes):
    if d[:2] != b"MZ" or len(d) < 0x40:
        return None
    try:
        pe, = struct.unpack_from("<I", d, 0x3C)
        if d[pe:pe + 4] != b"PE\0\0":
            return None
        nsec, = struct.unpack_from("<H", d, pe + 6)
        optsize, = struct.unpack_from("<H", d, pe + 20)
        opt = pe + 24
        end = struct.unpack_from("<I", d, opt + 60)[0] if optsize >= 64 else 0   # SizeOfHeaders
        sec = opt + optsize
        for k in range(min(nsec, 96)):
            raw_size, raw_ptr = struct.unpack_from("<II", d, sec + 40 * k + 16)
            if raw_size:
                end = max(end, raw_ptr + raw_size)
    except struct.error:
        return None
    return end


def tail_start(member: bytes):
    """The file offset where an ELF's or PE's bytes past everything it maps or lists begin, or None."""
    end = _elf_end(member)
    if end is None:
        end = _pe_end(member)
    if end is None or end >= len(member):
        return None
    return end


def regions(member: bytes) -> list:
    """[(offset in the member, bytes, tag, whether its head is an overlay's start)] this module reads of a
    member (module docstring): an ELF's or PE's trailing tail of TAIL_MAX bytes or less first, then the rest of
    the member when that is TAIL_MAX or less; a member that is no ELF or PE whole when it is TAIL_MAX or less."""
    ts = tail_start(member)
    if ts is not None:
        out = []
        if len(member) - ts <= TAIL_MAX:
            out.append((ts, member[ts:], f"tail@0x{ts:x}:", True))
        if ts <= TAIL_MAX:
            out.append((0, member[:ts], "packed:", False))
        return out
    if len(member) <= TAIL_MAX:
        exe = member[:4] == b"\x7fELF" or member[:2] == b"MZ" or member[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe")
        return [(0, member, "packed:", not exe)]
    return []


def tail_layers(member: bytes) -> list:
    """[(how, bytes)] of every decoding of the family in the member's regions (module docstring), at most
    MAX_LAYERS; the caller counts only what hcfg.containers reads as a CRC-valid container."""
    # CRC-32 is only an integrity check for HCFG records, not an artifact identity.  Equal-length
    # chosen-prefix collisions are cheap and used to let one member reuse another member's decoded
    # layers here.  Scope this process-global cache to the exact bytes with a collision-resistant
    # digest; hashing replaces the old whole-member CRC pass, so this adds no second linear scan.
    key = (len(member), hashlib.sha256(member).digest())
    if key in _CACHE:
        return _CACHE[key]
    out = []
    for _, r, tag, head_ok in regions(member):
        for t, reg in ((tag, r), (tag + "reversed>", r[::-1])):
            out.extend(_bytewise(reg, t))
        out.extend(_streams(r, tag, head_ok))
        if len(out) >= MAX_LAYERS:
            break
    if len(out) < MAX_LAYERS:
        out.extend(_elf_tagged_deflate(member))
    if len(out) < MAX_LAYERS:
        out.extend(search_layers(member))     # row 387: two-key compositions, a byte map before a stream
    out = out[:MAX_LAYERS]
    if len(_CACHE) >= _CACHE_MAX:
        _CACHE.pop(next(iter(_CACHE)))
    _CACHE[key] = out
    return out


def overlay_tag(member: bytes):
    """The offset of an ELF's or PE's trailing overlay when it opens, after its zero fill, with a printable
    four-byte tag (an RS20/PK19-style magic), else None. Only a hint for an unsure overlay_offset pick: with no
    digest nothing pins where the overlay's own header begins."""
    at = tail_start(member)
    if at is None or len(member) - at > TAIL_MAX:
        return None
    t = member[at:]
    h = _head(t)
    tag = t[h:h + 4]
    if len(tag) == 4 and all(0x21 <= b <= 0x7E for b in tag):
        return at + h
    return None


# ---- the Day 20 speed build (row 387): two-key compositions and a byte map before a decompression
#
# The families above take one key (a rotation and an xor collapse to one, as an add and a rotation do). Two steps
# whose keys do not collapse are read here, each found by the mark the magic leaves under it, never by trying the
# 65,536 key pairs blindly:
#
#   add>xor   plain = (b + k) ^ K    the subtraction-difference stream holds sd(magic ^ K) where the magic stands
#                                    (k cancels), so one index pass over it finds every K at once; k follows.
#   xor>add   plain = (b ^ K) + k    the xor-difference stream holds xd(magic - k) (K cancels); K follows.
#
# over the region and over it byte-reversed for the HCFG magic, and (forward) for the bzip2 block magic (`1AY&SY`,
# its stream begins four bytes before it with `BZh1`..`BZh9`) and the xz magic, whose stream is then decompressed.
# Each signature is three differences (24 bits): a 16-bit table picks the candidates in one numpy pass and the
# third difference keeps the exact ones; a place counts only when the whole magic decodes there.
#
# A byte map before a decompression whose header is too short for that (zlib's two bytes, gzip's three,
# LZMA-alone's): only at the places a packed overlay begins (`starts`): every place a u32le length at the head
# pins (read at p, the packed bytes from p + 4 .. p + 4 + PIN_GAP to the region's end: PK19's tag, k1, k2, length,
# digest layout and its kin), then the region's head after its zero fill and the HEAD_TRIES offsets after it.
# There every one-key family (ror(b, n) ^ K, ror(b + k, n), ror(b, n) + k; the key follows from the header's first
# byte) and the two-key families with one key from the head's first 48 bytes (HEAD_KEYS of them; the other key
# follows) are tried on the first eight bytes against the five stream headers (zlib with its check, gzip, bzip2
# with its block magic, xz, LZMA-alone with a power-of-two dictionary), and only a header that matches is
# decompressed.
#
# Nothing here is proof by itself: the caller takes a layer only when hcfg.containers reads a whole container whose
# CRC-32 checks out of it, and the config only when exactly one distinct such container comes out of all the
# prefix's files (generic._packed_choice; two that differ: None). An HCFG window here is yielded only when its own
# lane-layout CRC-32 already checks (`_crc_window`), so a random hit costs no layer.
#
# Bounds, by counts and bytes (never a clock): the regions of `regions` (TAIL_MAX, 4 MiB since this build, for every
# family of the module; a random 4 MiB tail costs about 0.2 s in all), TWO_KEY_HITS verified places of one magic and family, PIN_STARTS pinned starts, START_HEADERS matching
# headers decompressed in one region, OUT_MAX bytes out of one stream.
TWO_KEY_HITS = 16           # verified places of one magic under one two-key family
PIN_STARTS = 16             # length-pinned packed starts at a region's head
PIN_GAP = 64                # bytes between a length field's end and the packed start it pins
START_HEADERS = 32          # stream headers decompressed at the starts of one region
START_KEY_BYTES = 48        # bytes of the head whose distinct values are the two-key families' head keys

BZ_BLOCK = b"1AY&SY"
XZ_MAGIC = b"\xfd7zXZ\x00"
_TWO_KEY_MAGICS = (("hcfg", MAGIC, 0), ("bz2", BZ_BLOCK, 4), ("xz", XZ_MAGIC, 0))
_INDEX = []


def _index():
    """{"sd"|"xd": (16-bit table, {24-bit code: [(magic name, family, key)]}, sorted codes)}: every two-key
    signature (section comment), built once."""
    if not _INDEX:
        import numpy as np
        built = {}
        keys = np.arange(1, 256, dtype=np.uint8)
        for stream, fam in (("sd", "add>xor"), ("xd", "xor>add")):
            codes = {}
            for name, magic, _ in _TWO_KEY_MAGICS:
                m = np.frombuffer(magic[:4], np.uint8)
                if stream == "sd":           # plain = (b + k) ^ K, key = K: the bytes are (m ^ K) - k
                    pats = m[None, :] ^ keys[:, None]
                    d = (pats[:, 1:] - pats[:, :-1]).astype(np.uint32)
                else:                        # plain = (b ^ K) + k, key = k: the bytes are (m - k) ^ K
                    pats = m[None, :] - keys[:, None]
                    d = (pats[:, 1:] ^ pats[:, :-1]).astype(np.uint32)
                for key, code in zip(keys.tolist(), (d[:, 0] | d[:, 1] << 8 | d[:, 2] << 16).tolist()):
                    codes.setdefault(code, []).append((name, fam, key))
            lut = np.zeros(1 << 16, dtype=bool)
            for code in codes:
                lut[code & 0xFFFF] = True
            built[stream] = (lut, codes, np.array(sorted(codes), dtype=np.uint32))
        _INDEX.append(built)
    return _INDEX[0]


def _crc_window(win: bytes) -> bool:
    """Whether `win` opens with a whole lane-layout HCFG record whose CRC-32 checks."""
    if len(win) < 13 or win[:4] != MAGIC:
        return False
    key = win[5]
    ln, crc = struct.unpack_from("<HI", win, 6)
    body = win[12:12 + ln]
    return ln > 0 and len(body) == ln and zlib.crc32(_x(body, key) if key else body) & 0xFFFFFFFF == crc


_XT = [bytes(b ^ k for b in range(256)) for k in range(256)]            # b ^ k
_AT = [bytes((b + k) & 0xFF for b in range(256)) for k in range(256)]   # b + k


def _table(fam: str, k: int, K: int) -> bytes:
    """The byte map of a two-key family (A.translate(B) is A, then B)."""
    if fam == "add>xor":
        return _AT[k].translate(_XT[K])
    return _XT[K].translate(_AT[k])


def _inflate_table(make, region: bytes, at: int, table: bytes):
    """The bytes a stream at `at` decodes to under the byte map `table` when they hold the magic, else b""."""
    try:
        make().decompress(region[at:at + PROBE].translate(table), OUT_MAX)
        got = make().decompress(region[at:at + OUT_MAX + 1].translate(table), OUT_MAX)
    except (zlib.error, lzma.LZMAError, OSError, EOFError, ValueError):
        return b""
    return got if len(got) >= 12 and MAGIC in got else b""


_MAKERS = {
    "zlib": lambda: zlib.decompressobj(15),
    "gzip": lambda: zlib.decompressobj(31),
    "bz2": bz2.BZ2Decompressor,
    "xz": lambda: lzma.LZMADecompressor(lzma.FORMAT_XZ),
    "lzma": lambda: lzma.LZMADecompressor(lzma.FORMAT_ALONE),
}


def _two_key(region: bytes, tag: str, streams: bool = True):
    """(how, bytes) of every place where a magic stands under add>xor or xor>add (section comment)."""
    if len(region) < 16:
        return
    try:
        import numpy as np
    except ImportError:
        return
    idx = _index()
    a = np.frombuffer(region, np.uint8)
    seen = {}
    for stream, d in (("sd", a[1:] - a[:-1]), ("xd", a[:-1] ^ a[1:])):
        lut, codes, targets = idx[stream]
        d16 = d[:-1].astype(np.uint16) | (d[1:].astype(np.uint16) << 8)
        cand = np.flatnonzero(lut[d16[:-1]])
        if not len(cand):
            continue
        c24 = d16[cand].astype(np.uint32) | (d[cand + 2].astype(np.uint32) << 16)
        keep = np.isin(c24, targets)
        for i, code in zip(cand[keep].tolist(), c24[keep].tolist()):
            for name, fam, key in codes[code]:
                if name != "hcfg" and not streams:
                    continue
                magic, back = next((m, b) for n, m, b in _TWO_KEY_MAGICS if n == name)
                if fam == "add>xor":
                    K, k = key, ((magic[0] ^ key) - region[i]) & 0xFF
                else:
                    k, K = key, ((magic[0] - key) & 0xFF) ^ region[i]
                if k in (0, 0x80) or K in (0, 0x80) or seen.get((name, fam), 0) >= TWO_KEY_HITS:
                    continue                 # one key alone is the families above (adding 0x80 is xor 0x80)
                t = _table(fam, k, K)
                if region[i:i + len(magic)].translate(t) != magic:
                    continue
                seen[(name, fam)] = seen.get((name, fam), 0) + 1
                how = f"{tag}add{k:02x}>xor{K:02x}" if fam == "add>xor" else f"{tag}xor{K:02x}>add{k:02x}"
                if name == "hcfg":
                    win = region[i:i + WINDOW].translate(t)
                    if _crc_window(win):
                        yield f"{how}@0x{i:x}", win
                    continue
                at = i - back
                if at < 0:
                    continue
                if name == "bz2":
                    h = region[at:i].translate(t)
                    if h[:3] != b"BZh" or not 0x31 <= h[3] <= 0x39:
                        continue
                got = _inflate_table(_MAKERS[name], region, at, t)
                if got:
                    yield f"{how}>{name}@0x{at:x}", got


def _header_ok(name: str, h: bytes) -> bool:
    """Whether the eight decoded bytes `h` open a stream of `name` (a check strong enough to decompress)."""
    if name == "zlib":
        return h[0] == 0x78 and (h[0] << 8 | h[1]) % 31 == 0 and not h[1] & 0x20
    if name == "gzip":
        return h[:3] == b"\x1f\x8b\x08" and h[3] < 0x20
    if name == "bz2":
        return h[:3] == b"BZh" and 0x31 <= h[3] <= 0x39 and h[4:8] == BZ_BLOCK[:4]
    if name == "xz":
        return h[:6] == XZ_MAGIC
    if name == "lzma":
        dic = struct.unpack_from("<I", h, 1)[0]
        return h[0] == 0x5D and dic >= 4096 and dic & (dic - 1) == 0
    return False


_FIRST = {"zlib": 0x78, "gzip": 0x1F, "bz2": 0x42, "xz": 0xFD, "lzma": 0x5D}


def starts(region: bytes) -> list:
    """Where a packed overlay's bytes may begin (section comment): every start a u32le length at the head pins
    first, then the head after its zero fill and the HEAD_TRIES offsets after it."""
    h = _head(region)
    pinned = []
    for p in range(h, min(len(region) - 4, h + HEAD_TRIES)):
        ln = struct.unpack_from("<I", region, p)[0]
        j = len(region) - ln
        if 0 < ln and p + 4 <= j <= p + 4 + PIN_GAP and j not in pinned:
            pinned.append(j)
            if len(pinned) >= PIN_STARTS:
                break
    return pinned + [j for j in range(h, min(len(region) - 8, h + HEAD_TRIES)) if j not in pinned]


def _start_maps(first: int, b0: int, keys):
    """(how, 256-byte table) of every one-key and head-keyed two-key map that turns the byte b0 into `first`."""
    for n in range(8):
        K = _ror(b0, n) ^ first
        if n or K:
            yield f"ror{n}^{K:02x}", _ROR[n].translate(_XT[K])
        k = (_rol(first, n) - b0) & 0xFF
        if k:
            yield f"add{k:02x}>ror{n}", _AT[k].translate(_ROR[n])
        k = (first - _ror(b0, n)) & 0xFF
        if n and k:
            yield f"ror{n}>add{k:02x}", _ROR[n].translate(_AT[k])
    for key in keys:
        if key == 0x80:
            continue                             # adding 0x80 is xor 0x80: a one-key map above
        k = ((first ^ key) - b0) & 0xFF          # add>xor, K from the head
        if k not in (0, 0x80):
            yield f"add{k:02x}>xor{key:02x}", _table("add>xor", k, key)
        K = ((first - key) & 0xFF) ^ b0          # xor>add, k from the head
        if K not in (0, 0x80):
            yield f"xor{K:02x}>add{key:02x}", _table("xor>add", key, K)


def _start_streams(region: bytes, tag: str):
    """(how, inflated bytes) of a stream under a byte map at the places a packed overlay begins."""
    h = _head(region)
    keys = []
    for b in region[h:h + START_KEY_BYTES]:
        if b and b not in keys and len(keys) < HEAD_KEYS:
            keys.append(b)
    tried = 0
    for j in starts(region):
        w = region[j:j + 8]
        if len(w) < 8:
            continue
        for name, first in _FIRST.items():
            for how, t in _start_maps(first, w[0], keys):
                if not _header_ok(name, w.translate(t)):
                    continue
                tried += 1
                got = _inflate_table(_MAKERS[name], region, j, t)
                if got:
                    yield f"{tag}{how}>{name}@0x{j:x}", got
                if tried >= START_HEADERS:
                    return


def search_layers(member: bytes) -> list:
    """[(how, bytes)] of the row-387 families (section comment), at most MAX_LAYERS."""
    out = []
    for _, r, tag, head_ok in regions(member):
        out.extend(_two_key(r, tag))
        out.extend(_two_key(r[::-1], tag + "reversed>", streams=False))
        if head_ok:
            out.extend(_start_streams(r, tag))
        if len(out) >= MAX_LAYERS:
            break
    return out[:MAX_LAYERS]
