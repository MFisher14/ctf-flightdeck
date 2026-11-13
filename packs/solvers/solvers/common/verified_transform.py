#!/usr/bin/env python3
"""Lane-agnostic "a decode/transform is PLAIN only when it self-validates" primitive.

The single most dangerous class of wrong answer is a DECODE we are proud of that is simply not
the intended one: a rotation that produced printable text, a "decompression" that yielded a
byte string, a carver that pulled a blob out of a file. Each of those is a GUESS until the
bytes prove themselves. The binary lane already lives by this rule -- `solvers/binary/`
(`packed_tail.py`, `hcfg.py`, `generic._choose_config`) takes a decoded container only when its
stored CRC-32 checks, and the carver `solvers/toolkits/carve_stego.py` (`judge_blob`, the
magic+sizer table) takes a carved blob only when a file structure reads out of it to a complete
end. This module lifts that rule into `solvers/common/` so warmups, script-analysis, binary,
mobile, metadata and every toolkit can import one primitive:

    import verified_transform as VT        # solvers/common is on sys.path for every lane

    body = VT.apply_and_verify(blob, strip4_and_inflate, crc=stored_crc)   # None unless CRC ok
    if VT.verify(decoded, structure=True):      # a whole PNG/JPEG/zip/gzip/... read out of it
        answer = decoded                         # plain-eligible: it proved itself
    member = VT.read_pseudo_encrypted_member(zip_bytes, "secret.txt")      # CRC-gated flag-flip

NEVER-WRONG CONTRACT (the whole point):
  * A transform's output is accepted (plain-eligible) ONLY when it self-validates, by one of the
    STRONG stored proofs: a stored CRC-32 matches, a stated digest (md5/sha1/sha256/...) matches,
    or a magic+sizer reads a complete file structure out of it whose sizer genuinely validates
    content (carve_stego.judge_blob-style; `_COMPLETE_STRUCTURE_KINDS`). With NO validator, nothing
    is verified.
  * Printable-but-unverified output is an UNSURE candidate (probed, never plain); garbage, or no
    validator at all, is None. `decide()` / `plain_or_candidate()` draw that line.
  * Pure: reads no files on its core path, makes no network call, executes nothing it is given.
    Bounded: it never looks at more than `MAX_BYTES` of a value, and every sizer bounds its own
    loops. Offline. A validator never raises into a solver -- a raise is False / None / {}.
  * A stored length (audit H10) and a structure match on a kind whose sizer does NOT validate
    content (pdf/gif/pe/riff/bmp -- a self-declared length or trailing marker; audit H9) are NOT
    proofs: many wrong decodes land on the right length or merely begin with a magic. Neither ever
    returns PLAIN on its own; each only keeps a printable value as an unsure candidate alongside a
    strong proof. CRC, a digest, or a complete-structure match are the strong proofs.

This is a library primitive: it exposes no `signals()` / `solve_set()`, is not registered, and
is on no solve, opener or clock path. `render_candidates.py` is its sibling: this one decides
whether a DECODE is trustworthy at all; that one spells/orders a value already read.
"""
from __future__ import annotations

import hashlib
import io
import struct
import zipfile
import zlib

__all__ = [
    "verify",
    "apply_and_verify",
    "decide",
    "plain_or_candidate",
    "clear_zip_encryption",
    "pseudo_encrypted_members",
    "read_pseudo_encrypted_member",
]

# ----------------------------------------------------------------------------- bounds
MAX_BYTES = 64 << 20          # a value larger than this is never validated (bounded; returns False)
MAX_INFLATE = 64 << 20        # bytes a compressed-stream sizer will inflate before it gives up
_PRINTABLE_SAMPLE = 1 << 16   # bytes of a value inspected for the printable/unsure decision


# ----------------------------------------------------------------------------- byte coercion

def _as_bytes(value):
    """`value` as bytes for the byte validators, or None when it cannot be one. A str is encoded
    UTF-8 (a decoded text value); bytes/bytearray/memoryview pass through; anything else is None."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        try:
            return value.encode("utf-8")
        except (UnicodeEncodeError, UnicodeError):
            return None
    return None


# ----------------------------------------------------------------------------- the four proofs

def _crc_ok(b: bytes, crc) -> bool:
    """`b`'s CRC-32 equals the stored value (an int, or a hex/decimal str)."""
    expected = _coerce_u32(crc)
    if expected is None:
        return False
    return (zlib.crc32(b) & 0xFFFFFFFF) == expected


def _coerce_u32(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value & 0xFFFFFFFF if value >= 0 else None
    if isinstance(value, str):
        s = value.strip()
        try:
            n = int(s, 16) if s[:2].lower() == "0x" else int(s)
        except ValueError:
            try:
                n = int(s, 16)
            except ValueError:
                return None
        return n & 0xFFFFFFFF if n >= 0 else None
    return None


def _length_ok(b: bytes, length) -> bool:
    """`b` is exactly `length` bytes long (the weakest proof)."""
    if isinstance(length, bool) or not isinstance(length, int) or length < 0:
        return False
    return len(b) == length


# raw-digest length (bytes) -> hashlib name; all distinct
_RAW_DIGEST = {16: "md5", 20: "sha1", 28: "sha224", 32: "sha256", 48: "sha384", 64: "sha512"}
# hex-digest length (chars) -> hashlib name; all distinct
_HEX_DIGEST = {32: "md5", 40: "sha1", 56: "sha224", 64: "sha256", 96: "sha384", 128: "sha512"}


def _digest_ok(b: bytes, digest) -> bool:
    """A stated digest of `b` matches. `digest` is a hex str or raw bytes (the algorithm is read
    from its length) or an (algorithm_name, value) pair (value hex str or bytes)."""
    algo = None
    value = digest
    if isinstance(digest, (tuple, list)) and len(digest) == 2 and isinstance(digest[0], str):
        algo, value = digest[0].strip().lower(), digest[1]
    want = _digest_raw(value, algo)
    if want is None:
        return False
    if algo is None:
        algo = _RAW_DIGEST.get(len(want))
        if algo is None:
            return False
    try:
        got = hashlib.new(algo, b).digest()
    except (ValueError, TypeError):
        return False
    return len(got) == len(want) and _const_eq(got, want)


def _digest_raw(value, algo):
    """A raw-bytes digest from a hex str or bytes, or None. With no algo, the length must name a
    known algorithm; with an algo given, any even-length hex or bytes is accepted."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        if algo is None and len(raw) not in _RAW_DIGEST:
            return None
        return raw
    if isinstance(value, str):
        s = value.strip().lower()
        if s[:2] == "0x":
            s = s[2:]
        if not s or len(s) % 2 or any(c not in "0123456789abcdef" for c in s):
            return None
        if algo is None and len(s) not in _HEX_DIGEST:
            return None
        try:
            return bytes.fromhex(s)
        except ValueError:
            return None
    return None


def _const_eq(a: bytes, b: bytes) -> bool:
    try:
        import hmac
        return hmac.compare_digest(a, b)
    except Exception:  # noqa: BLE001 - never raise out of a validator
        return a == b


# ----------------------------------------------------------------------------- magic + sizer (judge_blob-style)
#
# Ported, stdlib-only, from solvers/toolkits/carve_stego.py so this primitive carries no heavy
# dependency: each sizer reads a structure that starts at offset 0 and returns the offset where it
# ends, or None when the bytes are not that structure. They never raise; they are all bounded.

_PNG_SIG = b"\x89PNG\r\n\x1a\n"


def _png_end(d: bytes, off: int = 0):
    i, n = off + 8, 0
    while i + 12 <= len(d) and n < 100000:
        try:
            ln = struct.unpack_from(">I", d, i)[0]
        except struct.error:
            return None
        typ = d[i + 4:i + 8]
        if ln > 0x7FFFFFFF or not all(65 <= c <= 90 or 97 <= c <= 122 for c in typ):
            return None
        if n == 0 and typ not in (b"IHDR", b"CgBI"):
            return None
        i += 12 + ln
        n += 1
        if typ == b"IEND":
            return i if i <= len(d) else None
    return None


def _jpeg_end(d: bytes, off: int = 0):
    i, n, sof, sos = off + 2, len(d), False, False
    while i + 2 <= n:
        if d[i] != 0xFF:
            return None
        m = d[i + 1]
        if m == 0xFF:
            i += 1
            continue
        if m == 0xD9:
            return i + 2 if sof and sos else None
        if m in (0x01,) or 0xD0 <= m <= 0xD7:
            i += 2
            continue
        if i + 4 > n:
            return None
        ln = struct.unpack_from(">H", d, i + 2)[0]
        if ln < 2:
            return None
        if 0xC0 <= m <= 0xCF and m not in (0xC4, 0xC8, 0xCC):
            sof = True
        i += 2 + ln
        if m == 0xDA:
            sos = True
            while True:
                j = d.find(b"\xff", i)
                if j < 0 or j + 1 >= n:
                    return None
                nxt = d[j + 1]
                if nxt == 0 or 0xD0 <= nxt <= 0xD7 or nxt == 0xFF:
                    i = j + 1 if nxt == 0xFF else j + 2
                    continue
                i = j
                break
    return None


def _gif_end(d: bytes, off: int = 0):
    try:
        if len(d) < off + 13:
            return None
        flags = d[off + 10]
        i = off + 13 + (3 * (2 << (flags & 7)) if flags & 0x80 else 0)
        frames = 0
        while i < len(d):
            b = d[i]
            if b == 0x3B:
                return i + 1 if frames else None
            if b == 0x21:
                i += 2
            elif b == 0x2C:
                lf = d[i + 9]
                i += 10 + (3 * (2 << (lf & 7)) if lf & 0x80 else 0) + 1
                frames += 1
            else:
                return None
            while True:
                ln = d[i]
                i += 1 + ln
                if ln == 0:
                    break
    except IndexError:
        return None
    return None


def _pdf_end(d: bytes, off: int = 0):
    j = d.rfind(b"%%EOF")
    if j < off:
        return None
    j += 5
    while j < len(d) and d[j:j + 1] in (b"\r", b"\n"):
        j += 1
    return j


def _inflate_at(d: bytes, off: int, wbits: int):
    dec = zlib.decompressobj(wbits)
    out, total, pos, size = [], 0, off, 4096
    try:
        while True:
            piece = d[pos:pos + size]
            if not piece:
                return None
            got = dec.decompress(piece, MAX_INFLATE - total + 1)
            total += len(got)
            out.append(got)
            if total > MAX_INFLATE or dec.unconsumed_tail:
                return None
            if dec.eof:
                return pos + len(piece) - len(dec.unused_data), b"".join(out)
            pos += len(piece)
            size = min(size * 4, 1 << 20)
    except zlib.error:
        return None


def _gzip_end(d: bytes, off: int = 0):
    got = _inflate_at(d, off, 31)
    return got[0] if got else None


def _7z_end(d: bytes, off: int = 0):
    if len(d) < off + 32:
        return None
    try:
        crc, nxt, size = struct.unpack_from("<IQQ", d, off + 8)
    except struct.error:
        return None
    if zlib.crc32(d[off + 12:off + 32]) & 0xFFFFFFFF != crc:
        return None
    end = off + 32 + nxt + size
    return end if end <= len(d) else None


def _elf_end(d: bytes, off: int = 0):
    try:
        if d[off + 4] not in (1, 2) or d[off + 5] not in (1, 2) or d[off + 6] != 1:
            return None
        e = "<" if d[off + 5] == 1 else ">"
        if d[off + 4] == 2:
            phoff, shoff = struct.unpack_from(e + "QQ", d, off + 32)
            phentsize, phnum, shentsize, shnum = struct.unpack_from(e + "HHHH", d, off + 54)
        else:
            phoff, shoff = struct.unpack_from(e + "II", d, off + 28)
            phentsize, phnum, shentsize, shnum = struct.unpack_from(e + "HHHH", d, off + 42)
        etype = struct.unpack_from(e + "H", d, off + 16)[0]
        if 4 < etype < 0xFE00:
            return None
        end = shoff + shentsize * shnum if shoff else 0
        for k in range(min(phnum, 128)):
            p = off + phoff + k * phentsize
            if d[off + 4] == 2:
                poff, _, _, filesz = struct.unpack_from(e + "QQQQ", d, p + 8)
            else:
                poff, _, _, filesz = struct.unpack_from(e + "IIII", d, p + 4)
            end = max(end, poff + filesz)
        return off + end if 52 <= end <= len(d) - off else None
    except (struct.error, IndexError):
        return None


def _pe_end(d: bytes, off: int = 0):
    try:
        lfa = struct.unpack_from("<I", d, off + 0x3C)[0]
        p = off + lfa
        if lfa > 0x1000 or d[p:p + 4] != b"PE\x00\x00":
            return None
        nsec = struct.unpack_from("<H", d, p + 6)[0]
        opt = struct.unpack_from("<H", d, p + 20)[0]
        end = lfa + 24 + opt + nsec * 40
        for k in range(min(nsec, 96)):
            rsize, rptr = struct.unpack_from("<II", d, p + 24 + opt + k * 40 + 16)
            if rptr:
                end = max(end, rptr + rsize)
        return off + end if end <= len(d) - off else None
    except (struct.error, IndexError):
        return None


def _riff_end(d: bytes, off: int = 0):
    if len(d) < off + 12 or d[off + 8:off + 12] not in (b"WAVE", b"WEBP", b"AVI "):
        return None
    try:
        end = off + 8 + struct.unpack_from("<I", d, off + 4)[0]
    except struct.error:
        return None
    end += end & 1 and end < len(d)
    return end if off + 12 < end <= len(d) else None


def _bmp_end(d: bytes, off: int = 0):
    if len(d) < off + 26:
        return None
    try:
        size, r, pix, hdr = struct.unpack_from("<IIII", d, off + 2)
    except struct.error:
        return None
    if r or hdr not in (12, 40, 52, 56, 108, 124) or not 14 + hdr <= pix <= size or size > len(d) - off:
        return None
    return off + size


# (magic prefix, kind, sizer). A compressed-stream sizer (gzip) validates by inflating; the
# structural ones validate by parsing to a complete end. Order: strongest / least ambiguous first.
_SIZERS = (
    (_PNG_SIG, "png", _png_end),
    (b"\xff\xd8\xff", "jpeg", _jpeg_end),
    (b"GIF89a", "gif", _gif_end),
    (b"GIF87a", "gif", _gif_end),
    (b"%PDF-", "pdf", _pdf_end),
    (b"\x1f\x8b\x08", "gzip", _gzip_end),
    (b"7z\xbc\xaf\x27\x1c", "7z", _7z_end),
    (b"\x7fELF", "elf", _elf_end),
    (b"MZ", "pe", _pe_end),
    (b"RIFF", "riff", _riff_end),
    (b"BM", "bmp", _bmp_end),
)

# Kinds whose sizer is a genuinely COMPLETE validator of content -- a structure match on them is a
# STRONG proof, so it is plain-eligible. png/jpeg parse to a real end marker (IEND / EOI after a
# SOF+SOS); gzip inflates to a stream end; 7z checks a header CRC-32; elf parses its program/section
# headers; zip runs testzip() (every member's stored CRC).
#
# The other magics (pdf/gif/pe/riff/bmp) do NOT validate content: _pdf_end is just rfind(%%EOF),
# _riff_end/_bmp_end trust a SELF-declared length, _pe_end stops at the header and ignores trailing
# junk, _gif_end accepts junk LZW. A match on them is magic + a self-declared length/marker with no
# content checksum, so it is NOT a proof (audit H9): a structure hit on such a kind is demoted to the
# unsure branch and is never returned PLAIN unless a real proof (crc/digest) is also supplied.
_COMPLETE_STRUCTURE_KINDS = frozenset({"png", "jpeg", "gzip", "7z", "elf", "zip"})


def _zip_structure_end(b: bytes):
    """The end offset of a complete, CRC-valid zip at offset 0, or None. A real (password-)
    encrypted member makes `testzip()` raise, so such a zip is NOT a verified structure (the
    pseudo-encryption flag-flip is a separate, explicit path below)."""
    if b[:4] not in (b"PK\x03\x04", b"PK\x05\x06"):
        return None
    try:
        zf = zipfile.ZipFile(io.BytesIO(b))
    except Exception:  # noqa: BLE001
        return None
    try:
        try:
            bad = zf.testzip()
        except Exception:  # noqa: BLE001 - encrypted / broken
            return None
    finally:
        try:
            zf.close()
        except Exception:  # noqa: BLE001
            pass
    if bad is not None:
        return None
    e = b.rfind(b"PK\x05\x06")
    if e < 0 or e + 22 > len(b):
        return None
    try:
        clen = struct.unpack_from("<H", b, e + 20)[0]
    except struct.error:
        return None
    end = e + 22 + clen
    return end if end <= len(b) else None


def _structure_end(b: bytes, magic=None):
    """(kind, end) of a complete file structure that starts at offset 0, or None. When `magic` is
    given the bytes must start with it (a sanity prefix); the sizer does the real validation."""
    if len(b) < 4:
        return None
    if magic is not None:
        try:
            if not b.startswith(bytes(magic)):
                return None
        except (TypeError, ValueError):
            return None
    for mg, kind, sizer in _SIZERS:
        if b.startswith(mg):
            try:
                end = sizer(b, 0)
            except Exception:  # noqa: BLE001 - a sizer must never raise out of here
                end = None
            if end and end > len(mg):
                return (kind, end)
    z = _zip_structure_end(b)
    if z is not None:
        return ("zip", z)
    return None


def _structure_ok(b: bytes, magic, structure) -> bool:
    exact = isinstance(structure, str) and structure.strip().lower() == "exact"
    res = _structure_end(b, magic)
    if res is None:
        return False
    kind, end = res
    if kind not in _COMPLETE_STRUCTURE_KINDS:
        # H9: a loose sizer (magic + a self-declared length/marker, no content checksum) is not a
        # strong proof. Not plain-eligible -- fall to the unsure/None branch of decide().
        return False
    if exact:
        return end == len(b)
    return bool(end) and end > 0


# ----------------------------------------------------------------------------- public API

def _provided(crc, magic, length, digest, structure) -> bool:
    return (crc is not None or digest is not None or length is not None
            or magic is not None or bool(structure))


def verify(data, *, crc=None, magic=None, length=None, digest=None, structure=None) -> bool:
    """True when `data` SELF-VALIDATES under at least one supplied proof, False otherwise.

    crc        a stored CRC-32 (int or hex/decimal str): zlib.crc32(data) must equal it.
    magic      a magic prefix (bytes): data must start with it AND a content-validating sizer must
               read a complete file structure out of it. A prefix with no sizer behind it, or a
               loose sizer (pdf/gif/pe/riff/bmp), is not a proof.
    structure  truthy: a magic+sizer must read a complete file structure at offset 0 (magic
               auto-detected) whose kind is in `_COMPLETE_STRUCTURE_KINDS`. "exact": the structure
               must also end exactly at len(data).
    length     a stored byte length (int): accepted by the signature for callers, but a bare length
               match is NOT a proof (audit H10) and never returns True on its own.
    digest     a stated digest: a hex str / raw bytes (algorithm from its length) or an
               (algorithm, value) pair. The digest of data must equal it.

    With NO proof supplied, returns False ("no validator -> not verified"). Pure, bounded
    (nothing beyond MAX_BYTES is validated), offline, and never raises."""
    b = _as_bytes(data)
    if b is None or len(b) > MAX_BYTES:
        return False
    try:
        if crc is not None and _crc_ok(b, crc):
            return True
        if digest is not None and _digest_ok(b, digest):
            return True
        # H10: a bare length match is NOT a proof -- "many wrong decodes land on the right length."
        # length alone never returns True here; it only keeps a printable value as an unsure
        # candidate in decide() (probed, never plain) alongside a strong proof.
        if (magic is not None or structure) and _structure_ok(b, magic, structure):
            return True
    except Exception:  # noqa: BLE001 - a validator must never raise into a solver
        return False
    return False


def apply_and_verify(blob, transform, **validators):
    """Run `transform(blob)` and return its output ONLY when `verify(output, **validators)` passes;
    otherwise None. The transform may raise or return None -- either is None here. This is the
    never-wrong decode: a rotation/decompression/carve is returned only once it proves itself.

    `validators` are verify()'s keywords (crc, magic, length, digest, structure)."""
    try:
        out = transform(blob)
    except Exception:  # noqa: BLE001 - a transform's failure is just "not this one"
        return None
    if out is None:
        return None
    return out if verify(out, **validators) else None


def decide(data, *, crc=None, magic=None, length=None, digest=None, structure=None, ratio=0.9):
    """Classify a transform output for the plain-vs-unsure decision, under the never-wrong rule:

      "plain"   a supplied proof passed -> the value self-validated and is plain-eligible.
      "unsure"  a proof was supplied but none passed, yet the output reads as printable text
                -> a candidate worth probing, NEVER plain.
      None       garbage (unverified and not printable), or no proof was supplied at all.

    Pure, offline, bounded, never raises. The caller turns "unsure" into a labels.candidates pick
    (see `plain_or_candidate`)."""
    if not _provided(crc, magic, length, digest, structure):
        return None
    if verify(data, crc=crc, magic=magic, length=length, digest=digest, structure=structure):
        return "plain"
    b = _as_bytes(data)
    if b is not None and _is_printable(b, ratio):
        return "unsure"
    return None


def _is_printable(b: bytes, ratio: float = 0.9) -> bool:
    if not b:
        return False
    sample = b[:_PRINTABLE_SAMPLE]
    text = None
    if sample[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            text = sample.decode("utf-16")
        except (UnicodeDecodeError, ValueError):
            text = None
    if text is None:
        try:
            text = sample.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = sample[:-3].decode("utf-8")   # a trailing multibyte sequence cut by the sample
            except UnicodeDecodeError:
                return False
    if not text:
        return False
    good = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
    return good >= ratio * len(text)


def plain_or_candidate(key, value, data=None, *, option_name="verified_decode",
                       crc=None, magic=None, length=None, digest=None, structure=None):
    """The actionable form of `decide`, for a reader that read `value` from a transform output and
    must return it under the never-wrong contract:

      verified (a proof passed on `data`, default the bytes of `value`) -> `value` PLAIN.
      printable-but-unverified -> a labels.candidates unsure pick under `key` (one hypothesis,
                                  `option_name`), so it is probed and never sent plain.
      otherwise -> None.

    `key` is a labels key `<lane>.<field>/<shape>`. labels is imported lazily (it reads the ledger,
    as render_candidates.pick does); if it cannot be imported, the unsure branch degrades to None,
    so the plain and None branches stay pure. Never raises into a solver."""
    probe = value if data is None else data
    verdict = decide(probe, crc=crc, magic=magic, length=length, digest=digest, structure=structure)
    if verdict == "plain":
        return value
    if verdict != "unsure":
        return None
    try:
        import sys
        from pathlib import Path
        here = str(Path(__file__).resolve().parent)
        if here not in sys.path:
            sys.path.insert(0, here)
        import labels  # noqa: PLC0415
        opt = value if isinstance(value, str) else (_as_bytes(value) or b"").decode("latin-1")
        return labels.candidates(key, [(option_name, opt)])
    except Exception:  # noqa: BLE001 - labels unavailable or refused: stay never-wrong (no plain)
        return None


# ----------------------------------------------------------------------------- zip pseudo-encryption (gap-analysis C4)
#
# A zip "pseudo-encryption" is the author setting the general-purpose encryption bit (0x0001) on
# members that are NOT actually encrypted. A normal unzip refuses them. The fix is a verified
# transform: clear the bit, then read each member only when its STORED CRC-32 validates its
# decompressed bytes -- plain only on self-validation, exactly like every other decode here.

_ZIP_LFH = b"PK\x03\x04"
_ZIP_CEN = b"PK\x01\x02"
_ZIP_EOCD = b"PK\x05\x06"
_ZIP_FLAG_ENCRYPTED = 0x0001


def clear_zip_encryption(data):
    """A copy of the zip bytes with the general-purpose encryption bit (0x0001) cleared in every
    central-directory record and its local file header. The central directory is walked from the
    EOCD record (the local-header offsets come from there), so a stray PK signature inside
    compressed data is never touched. None when the bytes are not a parseable zip. Pure; bounded;
    never raises."""
    try:
        b = bytes(data)
    except (TypeError, ValueError):
        return None
    if len(b) > MAX_BYTES:
        return None
    e = b.rfind(_ZIP_EOCD)
    if e < 0 or e + 22 > len(b):
        return None
    try:
        total = struct.unpack_from("<H", b, e + 10)[0]
        cd_size = struct.unpack_from("<I", b, e + 12)[0]
        cd_off = struct.unpack_from("<I", b, e + 16)[0]
    except struct.error:
        return None
    cd_start = e - cd_size
    base = cd_start - cd_off          # the archive's own start (0 unless the zip is prefixed)
    if cd_start < 0 or base < 0 or cd_start + cd_size > len(b):
        return None
    out = bytearray(b)
    i, n = cd_start, 0
    while n < total and i + 46 <= cd_start + cd_size and out[i:i + 4] == _ZIP_CEN:
        try:
            name_len = struct.unpack_from("<H", out, i + 28)[0]
            extra_len = struct.unpack_from("<H", out, i + 30)[0]
            comment_len = struct.unpack_from("<H", out, i + 32)[0]
            lho = struct.unpack_from("<I", out, i + 42)[0]
            flag = struct.unpack_from("<H", out, i + 8)[0]
        except struct.error:
            return None
        struct.pack_into("<H", out, i + 8, flag & ~_ZIP_FLAG_ENCRYPTED)
        lpos = base + lho
        if 0 <= lpos and lpos + 8 <= len(out) and out[lpos:lpos + 4] == _ZIP_LFH:
            try:
                lflag = struct.unpack_from("<H", out, lpos + 6)[0]
                struct.pack_into("<H", out, lpos + 6, lflag & ~_ZIP_FLAG_ENCRYPTED)
            except struct.error:
                pass
        i += 46 + name_len + extra_len + comment_len
        n += 1
    return bytes(out)


def pseudo_encrypted_members(data) -> dict:
    """{name: decompressed bytes} of every member of a pseudo-encrypted zip whose STORED CRC-32
    validates after the encryption bit is cleared. A member needing a real password, or whose
    CRC-32 fails, is left out (never-wrong). {} when the bytes are not a zip or nothing validated.
    Pure; offline; never raises. (zipfile itself re-checks the CRC on read and raises on a
    mismatch; the explicit check here is the belt-and-suspenders guard.)"""
    cleared = clear_zip_encryption(data)
    if cleared is None:
        return {}
    try:
        zf = zipfile.ZipFile(io.BytesIO(cleared))
    except Exception:  # noqa: BLE001
        return {}
    out = {}
    try:
        for info in zf.infolist():
            if getattr(info, "is_dir", lambda: info.filename.endswith("/"))():
                continue
            try:
                raw = zf.read(info)
            except Exception:  # noqa: BLE001 - real encryption, bad CRC, broken member
                continue
            if (zlib.crc32(raw) & 0xFFFFFFFF) == (info.CRC & 0xFFFFFFFF):
                out[info.filename] = raw
    finally:
        try:
            zf.close()
        except Exception:  # noqa: BLE001
            pass
    return out


def read_pseudo_encrypted_member(data, name=None):
    """The decompressed bytes of a CRC-validated member of a pseudo-encrypted zip, or None. With
    `name`, that member (None when it is absent or its CRC-32 does not validate); without a name,
    the first member (in zip order) that validates. Pure; offline; never raises."""
    members = pseudo_encrypted_members(data)
    if not members:
        return None
    if name is None:
        return next(iter(members.values()))
    return members.get(name)


if __name__ == "__main__":   # a quick manual look, no network, nothing executed
    import gzip as _gzip

    body = b"the quick brown fox" * 4
    payload = struct.pack("<I", zlib.crc32(body) & 0xFFFFFFFF) + body
    print("crc header  ->", apply_and_verify(payload, lambda p: p[4:],
                                              crc=zlib.crc32(body) & 0xFFFFFFFF) == body)
    blob = _gzip.compress(body)
    print("gzip struct ->", verify(blob, structure=True), verify(blob, magic=b"\x1f\x8b\x08"))
    print("decide good ->", decide(body, crc=zlib.crc32(body) & 0xFFFFFFFF))
    print("decide text ->", decide(b"plain readable text", crc=0))
    print("decide junk ->", decide(bytes(range(32)), crc=0))
    print("digest      ->", verify(body, digest=hashlib.sha256(body).hexdigest()))
