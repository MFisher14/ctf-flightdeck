"""Ranked format catalog, structural identification and the synthetic corpus (B-162).

    load(path=None)              the catalog (ctf/formats/catalog.toml), ranked; CatalogError names any
                                 bad key, rank, builder or reference
    identify(name, data, cat)    the catalog formats a member could be, best first: every structural
                                 match in rank order (`sure`), then extension-only matches (never sure).
                                 `data` is any buffer (bytes, or an mmap of a file: no detector reads more
                                 than a bounded part of it). DetectorError when a detector fails other
                                 than on its parse; FormatLimit when a zip's stated central directory is
                                 over MAX_ZIP_DIRECTORY_BYTES
    identify_path(path, cat)     identify() on a file, mapped rather than read whole
    corpus                       the builders (ctf/formats/corpus.py)
    matrix                       the property coverage matrix over the metadata lane's readers
                                 (ctf/formats/matrix.py; it loads the lane, so it is imported on use)

The structural tests here are this module's own, small and bounded: a member is identified before any
reader is asked, so a format the readers do not know is still named (and the matrix shows it unread).
"""
from __future__ import annotations

import io
import mmap
import os
import struct
import tomllib
import zipfile
from dataclasses import dataclass
from pathlib import Path

from . import corpus

__all__ = ["CatalogError", "DetectorError", "FormatLimit", "Format", "Nearest", "Gap", "Match", "load", "identify",
           "identify_path", "DETECTORS", "CATALOG", "corpus"]

CATALOG = Path(__file__).with_name("catalog.toml")
FORMAT_KEYS = {"id", "rank", "label", "basis", "extensions", "namespaces", "samples", "nearest", "gaps", "refines"}
REQUIRED = ("id", "rank", "label", "basis", "extensions", "namespaces", "samples")


class CatalogError(ValueError):
    """The catalog cannot be used: the message names the file, the format and the key."""


class DetectorError(RuntimeError):
    """A detector failed with something its parse of hostile bytes cannot raise: a bug, named, never a
    quiet 'no match'."""


class FormatLimit(Exception):
    """The bytes state a structure larger than identify() reads (the message names the size and limit)."""


@dataclass(frozen=True)
class Nearest:
    asked: str
    reader: str
    sample: str


@dataclass(frozen=True)
class Gap:
    asked: str
    sample: str
    note: str


@dataclass(frozen=True)
class Format:
    id: str
    rank: int
    label: str
    basis: str
    extensions: tuple
    namespaces: tuple
    samples: tuple
    nearest: tuple = ()
    gaps: tuple = ()
    refines: str | None = None


@dataclass(frozen=True)
class Match:
    format: str
    rank: int
    sure: bool      # True: the bytes have the structure; False: only the name's extension says so
    why: str


# ------------------------------------------------------------------ structural tests (bounded)

MAX_ZIP_NAMES = 4096
MAX_ZIP_DIRECTORY_BYTES = 16 << 20     # a zip's central directory is parsed whole: refuse a larger one
# What a detector may raise on truncated or hostile bytes: no structural match. Anything else is a bug.
# IndexError is not one: the detectors slice and use struct.unpack_from, so an IndexError is a detector bug.
PARSE_ERRORS = (struct.error, ValueError, EOFError, OSError, zipfile.BadZipFile, zipfile.LargeZipFile)
MSI_CLSIDS = {bytes.fromhex("8410" "0c00" "0000" "0000" "c000000000000046"),     # {000C1084-...} msi
              bytes.fromhex("8610" "0c00" "0000" "0000" "c000000000000046"),     # msp
              bytes.fromhex("8210" "0c00" "0000" "0000" "c000000000000046")}     # mst


class _View(io.RawIOBase):
    """A seekable read-only file over a buffer, without a copy: zipfile reads only what it seeks to."""

    def __init__(self, buf):
        super().__init__()
        self._b, self._at = memoryview(buf), 0

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self._at

    def seek(self, off, whence=0):
        self._at = max(0, (0, self._at, len(self._b))[whence] + off)
        return self._at

    def readinto(self, out):
        n = max(0, min(len(out), len(self._b) - self._at))
        out[:n] = self._b[self._at:self._at + n]
        self._at += n
        return n

    def close(self):
        if not self.closed:
            self._b.release()
        super().close()


EOCD, EOCD64_LOCATOR, EOCD64 = b"PK\x05\x06", b"PK\x06\x07", b"PK\x06\x06"


def _zip_directory_size(d) -> int | None:
    """The central directory size the end record states (the zip64 record's when there is one), or None
    when there is no end record. Read from the last 64 KiB + 22 bytes only."""
    base = max(0, len(d) - (22 + 0xFFFF))
    tail = d[base:]
    i = tail.rfind(EOCD)
    if i < 0 or len(tail) - i < 22:
        return None
    size, = struct.unpack_from("<I", tail, i + 12)
    loc = i - 20
    if loc >= 0 and tail[loc:loc + 4] == EOCD64_LOCATOR:
        at, = struct.unpack_from("<Q", tail, loc + 8)
        if at + 56 <= len(d) and d[at:at + 4] == EOCD64:
            size, = struct.unpack_from("<Q", d[at + 40:at + 48])
    return size


def _zip_names(d):
    if d[:4] != b"PK\x03\x04":
        return None
    size = _zip_directory_size(d)
    if size is None or size > len(d):          # no end record, or one that states more than the file holds
        return None
    if size > MAX_ZIP_DIRECTORY_BYTES:
        raise FormatLimit(f"the zip end record states a central directory of {size} bytes, over the "
                          f"{MAX_ZIP_DIRECTORY_BYTES}-byte limit identify reads")
    try:
        with _View(d) as view, zipfile.ZipFile(view) as z:
            infos = z.infolist()
    except (zipfile.BadZipFile, ValueError, OSError, EOFError, NotImplementedError):
        return None                            # NotImplementedError: zipfile's refusal of a stated version
    return {i.filename for i in infos[:MAX_ZIP_NAMES]}


def _cfb_root(d: bytes):
    """(root CLSID, the names of the first directory sector's entries) of a compound file, or None."""
    if d[:8] != corpus.CFB_MAGIC or len(d) < 512:
        return None
    shift, = struct.unpack_from("<H", d, 0x1E)
    if shift not in (9, 12):
        return None
    sector = 1 << shift
    first_dir, = struct.unpack_from("<I", d, 0x30)
    at = sector + first_dir * sector
    if first_dir >= 0xFFFFFFFA or at + 128 > len(d):
        return None
    names = []
    for k in range(sector // 128):
        e = d[at + 128 * k: at + 128 * (k + 1)]
        if len(e) < 128:
            break
        n, = struct.unpack_from("<H", e, 64)
        if 2 <= n <= 64:
            names.append(e[:n - 2].decode("utf-16-le", "replace"))
    return d[at + 80:at + 96], names


def _is_ole(d: bytes) -> bool:
    return _cfb_root(d) is not None


def _is_msi(d: bytes) -> bool:
    root = _cfb_root(d)
    if root is None:
        return False
    clsid, names = root
    return clsid in MSI_CLSIDS or any(n.startswith("䡀") for n in names)


def _is_cab(d: bytes) -> bool:
    return d[:4] == b"MSCF" and len(d) >= 36 and d[24:26] == b"\x03\x01"


def _is_lnk(d: bytes) -> bool:
    return d[:4] == b"\x4c\x00\x00\x00" and d[4:20] == corpus.LNK_CLSID


def _is_riff(d: bytes) -> bool:
    return d[:4] == b"RIFF" and len(d) >= 12 and d[8:12].isascii()


def _is_ooxml(d: bytes) -> bool:
    names = _zip_names(d)
    return bool(names) and "[Content_Types].xml" in names and any(
        n.startswith(("word/", "xl/", "ppt/")) for n in names)


def _is_msix(d: bytes) -> bool:
    names = _zip_names(d)
    return bool(names) and ("AppxManifest.xml" in names or "AppxMetadata/AppxBundleManifest.xml" in names)


MAIL_HEADS = (b"from:", b"to:", b"subject:", b"date:", b"message-id:", b"mime-version:", b"received:", b"return-path:")


def _is_eml(d: bytes) -> bool:
    """A header block of RFC 5322 fields (name: value, continuations indented) ending in a blank line,
    with From and at least one more of the usual fields; a leading mbox 'From ' line is allowed."""
    head = d[:64 << 10]
    if head.startswith(b"From "):
        head = head.split(b"\n", 1)[1] if b"\n" in head else b""
    end = head.find(b"\r\n\r\n")
    end = head.find(b"\n\n") if end < 0 else end
    if end <= 0:
        return False
    seen = set()
    for line in head[:end].replace(b"\r\n", b"\n").split(b"\n"):
        if line[:1] in (b" ", b"\t"):
            continue
        name, colon, _ = line.partition(b":")
        if not colon or not name or not all(33 <= c <= 126 and c != 58 for c in name):
            return False
        seen.add(name.lower() + b":")
    return b"from:" in seen and len(seen & set(MAIL_HEADS)) >= 2


FS_BOOT_OEM = (b"NTFS    ", b"EXFAT   ")


def _is_disk(d) -> bool:
    """A partitioned disk image (B-221): a GPT header signature at LBA 1 (512- or 4096-byte sectors), or an
    MBR (boot signature, every status byte 0x00 or 0x80, at least one used entry with a non-zero start and
    length) that is not a filesystem's own boot sector (FAT, NTFS, exFAT carry the same boot signature)."""
    if d[512:520] == b"EFI PART" or d[4096:4104] == b"EFI PART":
        return True
    if len(d) < 512 or d[510:512] != b"\x55\xaa":
        return False
    if d[3:11] in FS_BOOT_OEM or d[54:59] in (b"FAT12", b"FAT16") or d[82:87] == b"FAT32":
        return False
    entries = [struct.unpack_from("<B3xB3xII", d, 446 + 16 * i) for i in range(4)]
    if any(status not in (0, 0x80) for status, _, _, _ in entries):
        return False
    return any(ptype and first and count for _, ptype, first, count in entries)


# ISO base media brands of still images (HEIF, AVIF, JPEG / AVC in HEIF, MIAF, Canon CR3 raw): an ftyp box
# is not a movie by itself
IMAGE_BRANDS = {b"heic", b"heix", b"heim", b"heis", b"hevc", b"hevx", b"mif1", b"mif2", b"msf1", b"miaf",
                b"avif", b"avis", b"avci", b"avcs", b"jpeg", b"jpgs", b"crx "}
# Brands only a timed (movie or audio) ISO base media file carries. The generic isom / iso2..iso9 are not
# here: still images list them too (a CR3 lists 'crx isom').
MOVIE_BRANDS = {b"mp41", b"mp42", b"mp71", b"avc1", b"M4A ", b"M4B ", b"M4P ", b"M4V ", b"M4VH", b"M4VP",
                b"qt  ", b"3gp4", b"3gp5", b"3gp6", b"3gp7", b"3gp8", b"3gp9", b"3g2a", b"3g2b", b"3g2c",
                b"mmp4", b"dash", b"f4v ", b"f4a ", b"mj2s", b"mjp2", b"msnv", b"cmfc", b"MSNV"}
EBML_MAGIC = b"\x1a\x45\xdf\xa3"


def _ftyp_brands(d: bytes) -> list:
    """The compatible brands of the leading ftyp box, read within its own size (and the file)."""
    size = int.from_bytes(d[:4], "big")
    end = min(size if size >= 16 else 16, len(d))
    return [bytes(d[i:i + 4]) for i in range(16, end - 3, 4)]


def _is_media(d: bytes) -> bool:
    """A media container the RIFF family does not cover (B-223): an ISO base media file (ftyp box first,
    and no still image: neither an image major brand nor an image compatible brand without a movie
    brand beside it), Matroska / WebM (EBML header), FLAC, Ogg, or AIFF / AIFF-C."""
    if len(d) >= 12 and d[4:8] == b"ftyp":
        major = bytes(d[8:12])
        if major in IMAGE_BRANDS:
            return False
        compat = set(_ftyp_brands(d))
        return not (compat & IMAGE_BRANDS) or bool((compat | {major}) & MOVIE_BRANDS)
    head = bytes(d[:4])
    if head in (EBML_MAGIC, b"fLaC", b"OggS"):
        return True
    return head == b"FORM" and bytes(d[8:12]) in (b"AIFF", b"AIFC")

def _is_dotnet(d) -> bool:
    """A managed PE (B-222): the optional header's CLR directory (entry 14) is set and points, through the
    section table, at a CLR header whose MetaData directory points at the BSJB metadata root. Reads the
    headers and two small places only; a cut file raises struct.error (no match)."""
    if d[:2] != b"MZ" or len(d) < 0x40:
        return False
    pe, = struct.unpack_from("<I", d, 0x3C)
    if d[pe:pe + 4] != b"PE\x00\x00":
        return False
    nsec, = struct.unpack_from("<H", d, pe + 6)
    optsize, = struct.unpack_from("<H", d, pe + 20)
    opt = pe + 24
    magic, = struct.unpack_from("<H", d, opt)
    first = {0x10B: 96, 0x20B: 112}.get(magic)
    if first is None or optsize < first + 15 * 8:
        return False
    ndirs, = struct.unpack_from("<I", d, opt + first - 4)
    if ndirs < 15:
        return False
    clr_rva, clr_size = struct.unpack_from("<II", d, opt + first + 14 * 8)
    if not clr_rva or clr_size < 72:
        return False
    sections = [struct.unpack_from("<IIII", d, opt + optsize + 40 * i + 8) for i in range(min(nsec, 96))]

    def offset(rva):
        for vsize, vaddr, rsize, rptr in sections:
            if vaddr <= rva < vaddr + max(vsize, rsize) and rva - vaddr < rsize:
                return rptr + rva - vaddr
        return None
    at = offset(clr_rva)
    if at is None:
        return False
    md_rva, = struct.unpack_from("<I", d, at + 8)
    md = offset(md_rva)
    return md is not None and d[md:md + 4] == b"BSJB"


# B-248: the formats of the metadata lane's residual readers. Each is identified by its own structure, read with
# its own size fields, independently of the lane's readers.

def _is_png(d: bytes) -> bool:
    return d[:8] == corpus.PNG_SIG and d[12:16] == b"IHDR"


def _is_tiff(d: bytes) -> bool:
    return d[:4] in (b"II*\x00", b"MM\x00*", b"II+\x00", b"MM\x00+")


HEIF_BRANDS = {b"heic", b"heix", b"hevc", b"hevx", b"heim", b"heis", b"hevm", b"hevs", b"mif1", b"msf1", b"avif", b"avis"}


def _is_heif(d: bytes) -> bool:
    if d[4:8] != b"ftyp" or len(d) < 16:
        return False
    size = struct.unpack_from(">I", d, 0)[0]
    if not 16 <= size <= min(len(d), 4096) or size % 4:
        return False
    return any(d[i:i + 4] in HEIF_BRANDS for i in [8] + list(range(16, size, 4)))


def _is_regf(d: bytes) -> bool:
    return d[:4] == b"regf" and len(d) >= 0x1000 + 0x20 and d[0x1000:0x1004] == b"hbin"


USN_HEADERS = {2: 60, 3: 76, 4: 64}


def _is_usn(d: bytes) -> bool:
    """A $J stream: optional sparse zeros, then a USN record of version 2, 3 or 4.0 whose length fits its header."""
    start = len(d) - len(bytes(d[:1 << 20]).lstrip(b"\x00")) if len(d) <= 1 << 20 else None
    if start is None or start >= len(d):
        return False
    start &= ~7          # down: a record's RecordLength may begin with zero bytes (256 is 00 01 00 00)
    if start + 8 > len(d):
        return False
    size, major, minor = struct.unpack_from("<IHH", d, start)
    head = USN_HEADERS.get(major)
    return head is not None and minor == 0 and size % 8 == 0 and head <= size <= 1 << 16 and start + size <= len(d)


COFF_MACHINES = {0x14C, 0x8664, 0xAA64, 0x1C4, 0x1C0, 0xA641}


def _is_coff(d: bytes) -> bool:
    """A bare COFF object: classic (a known machine at 0, 1..96 sections whose table fits) or bigobj (Sig1 0,
    Sig2 0xFFFF, version >= 2, the bigobj class id)."""
    if len(d) >= 56 and d[:4] == b"\x00\x00\xff\xff" and d[12:28] == corpus.BIGOBJ_CLSID:
        return struct.unpack_from("<H", d, 4)[0] >= 2
    if len(d) < 20 or d[:2] == b"MZ":
        return False
    machine, nsec = struct.unpack_from("<HH", d, 0)
    optsize = struct.unpack_from("<H", d, 16)[0]
    return machine in COFF_MACHINES and 1 <= nsec <= 96 and 20 + optsize + 40 * nsec <= len(d)


def _is_ar(d: bytes) -> bool:
    return d[:8] == b"!<arch>\n" and (len(d) == 8 or d[66:68] == b"`\n")


DETECTORS = {"ooxml": _is_ooxml, "eml": _is_eml, "lnk": _is_lnk, "riff": _is_riff, "ole": _is_ole,
             "msi": _is_msi, "cab": _is_cab, "msix": _is_msix, "media": _is_media,
             "dotnet": _is_dotnet, "png": _is_png, "tiff": _is_tiff, "heif": _is_heif,
             "regf": _is_regf, "usn": _is_usn, "coff": _is_coff, "ar": _is_ar,
             "disk": _is_disk}
from . import detect_longtail as _longtail   # noqa: E402  (B-251: avro, parquet, tnef, jxl, tflite, coreml)
DETECTORS.update(_longtail.DETECTORS)


# ------------------------------------------------------------------ the catalog

def _need(cond, where, what):
    if not cond:
        raise CatalogError(f"{where}: {what}")


def _strs(v):
    return isinstance(v, list) and all(isinstance(x, str) and x for x in v)


def load(path: Path | str | None = None) -> tuple:
    """The catalog's formats, by rank. Every key is checked; a builder, a detector or a reference that
    does not exist is a CatalogError, never a format quietly left out."""
    path = Path(path) if path is not None else CATALOG
    if not path.is_file():
        raise CatalogError(f"{path}: the format catalog is not there")
    try:
        doc = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as e:
        raise CatalogError(f"{path}: not TOML ({e})") from None
    _need(set(doc) == {"format"} and isinstance(doc["format"], list) and doc["format"], path,
          "the catalog is a non-empty list of [[format]] tables and nothing else")
    out, ids = [], set()
    for i, f in enumerate(doc["format"]):
        where = f"{path}: format {f.get('id', i + 1)!r}"
        _need(isinstance(f, dict), where, "not a table")
        _need(not set(f) - FORMAT_KEYS, where, f"unknown keys {sorted(set(f) - FORMAT_KEYS)}")
        for k in REQUIRED:
            _need(k in f, where, f"missing {k!r}")
        _need(isinstance(f["id"], str) and f["id"] in DETECTORS, where,
              f"id must be one of the detected formats {sorted(DETECTORS)}")
        _need(f["id"] not in ids, where, "listed twice")
        ids.add(f["id"])
        _need(isinstance(f["rank"], int) and not isinstance(f["rank"], bool) and f["rank"] >= 1, where, "rank must be an integer >= 1")
        for k in ("label", "basis"):
            _need(isinstance(f[k], str) and f[k].strip(), where, f"{k} must be a non-empty string")
        for k in ("extensions", "namespaces", "samples"):
            _need(_strs(f[k]) and f[k], where, f"{k} must be a non-empty list of strings")
        _need(all(e.startswith(".") and e == e.lower() for e in f["extensions"]), where, "extensions are lower case and start with '.'")
        for s in f["samples"]:
            _need(s in corpus.BUILDERS, where, f"sample {s!r} has no builder in ctf/formats/corpus.py")
        nearest, gaps = [], []
        for n in f.get("nearest", []):
            _need(isinstance(n, dict) and set(n) == {"asked", "reader", "sample"} and all(isinstance(v, str) and v for v in n.values()),
                  where, "a nearest entry is {asked, reader, sample}")
            _need(n["sample"] in f["samples"], where, f"nearest sample {n['sample']!r} is not one of this format's samples")
            _need(n["asked"] != n["reader"], where, f"nearest {n['asked']!r} names its own reader")
            nearest.append(Nearest(n["asked"], n["reader"], n["sample"]))
        for g in f.get("gaps", []):
            _need(isinstance(g, dict) and set(g) == {"asked", "sample", "note"} and all(isinstance(v, str) and v for v in g.values()),
                  where, "a gap entry is {asked, sample, note}")
            _need(g["sample"] in f["samples"], where, f"gap sample {g['sample']!r} is not one of this format's samples")
            gaps.append(Gap(g["asked"], g["sample"], g["note"]))
        refines = f.get("refines")
        _need(refines is None or isinstance(refines, str), where, "refines must be a format id")
        out.append(Format(f["id"], f["rank"], f["label"].strip(), f["basis"].strip(), tuple(f["extensions"]),
                          tuple(f["namespaces"]), tuple(f["samples"]), tuple(nearest), tuple(gaps), refines))
    ranks = sorted(x.rank for x in out)
    _need(ranks == list(range(1, len(out) + 1)), path, f"ranks must be 1..{len(out)} without gaps or repeats (have {ranks})")
    for x in out:
        _need(x.refines is None or (x.refines in ids and x.refines != x.id), path,
              f"format {x.id!r} refines {x.refines!r}, which is not another format of the catalog")
    return tuple(sorted(out, key=lambda x: x.rank))


def identify(name: str, data: bytes, catalog: tuple | None = None) -> list:
    """[Match] for one member, best first. Structural matches come first, in rank order, with a broader
    format dropped where a finer one that refines it matched (an MSI is not also reported as a plain
    compound file). Then the formats whose extension the name carries and whose structure did not match:
    never sure, a hint for the nearest reader only. A detector that raises a parse error (PARSE_ERRORS)
    on hostile bytes is no match; any other exception is a DetectorError naming the detector, and a
    FormatLimit passes through."""
    catalog = load() if catalog is None else catalog
    hits = []
    for f in catalog:
        try:
            ok = bool(DETECTORS[f.id](data))
        except FormatLimit:
            raise
        except PARSE_ERRORS:
            ok = False
        except Exception as e:
            raise DetectorError(f"the {f.id} detector raised {type(e).__name__}: {e}") from e
        if ok:
            hits.append(f)
    finer = {f.refines for f in hits if f.refines}
    out = [Match(f.id, f.rank, True, "structure") for f in hits if f.id not in finer]
    lowered = (name or "").lower()
    matched = {m.format for m in out}
    for f in catalog:
        ext = next((e for e in f.extensions if lowered.endswith(e)), None)
        if ext and f.id not in matched and f.id not in finer:
            out.append(Match(f.id, f.rank, False, f"extension {ext} only: the bytes do not have the structure"))
    return out


def identify_path(path, catalog: tuple | None = None) -> list:
    """identify() on a file by its name and bytes, mapped read-only rather than read whole."""
    path = Path(path)
    with open(path, "rb") as fh:
        if os.fstat(fh.fileno()).st_size == 0:
            return identify(path.name, b"", catalog)
        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
            return identify(path.name, mapped, catalog)
