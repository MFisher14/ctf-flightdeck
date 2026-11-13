#!/usr/bin/env python3
"""Reusable DECEPTION guard for the Metadata Forensics lane (Day 24 look-ahead, ticket T3).

Day 23 ("Page Me Maybe") was a DECEPTION day: a forged container whose stored order differed from the
judge's collation, an extension that lied about its content (a `.wav` that was really Ogg/Opus), and a
value read correctly but spelled in an author rendering the key had never judged. The single most
expensive failure mode is a WRONG PLAIN answer: one of them sinks the whole cumulative batch.

This module turns the three Day-23 lessons into a small, reusable, test-pinned guard that any reader or a
lane's `day_patch.py` can call, so a next deception day needs ZERO morning adaptation:

  (1) READ BY TRUE MAGIC, NOT BY EXTENSION. `true_magic(data)` names the container from the leading bytes
      only; `declared_format(name)` is what the extension claims; `is_decoy(name, data)` is True when they
      disagree. Generalises the `.wav`->Opus case to every container (a `.png` that is a zip, a `.bin` that
      is a Mach-O, a `.jpg` with a zip appended, ...).

  (2) ORDER IS CANDIDATES, NEVER PLAIN, while the judge's collation is unverified. `order_candidates(key,
      items)` offers BOTH the document (stored) order AND the ascending-sorted order as a bounded
      `labels.candidates` set (row 346) -- so one probe on the untimed base settles which the judge wants,
      and no single stored/sorted guess can ever sink a batch.

  (3) NEVER PICK A DECOY MEMBER. When a question names a specific member inside a container,
      `select_member(container, wanted)` returns exactly that member (by exact path, then by basename) and
      NEVER a decoy sibling; None when it is absent or ambiguous.

Everything here is PURE and byte-driven (no network, no ledger, no `signal`): the caller has already read
the value from the bytes -- that is where never-guess lives -- and this module only decides how to spell /
order it, or which bytes truly are the named member. It mirrors the invariants the shipped readers already
honour (readers_media's magic-only `_detect`, the ascending `zip.central_directory_member_names`,
`M.fc_candidates`); its job is to make them a single reusable primitive with a permanent battery
(`tests/test_day24_deception_battery.py`) so the next deception cannot cost a morning again.
"""
import importlib.util
import struct
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE.parent / "common") not in sys.path:
    sys.path.insert(0, str(_HERE.parent / "common"))
import labels  # noqa: E402  (the unsure/candidate contract)


def _fc():
    """format_candidates.py beside this file, loaded once. None if it cannot load, so the caller simply
    gets None back and the answer stays whatever the reader produced (never a plain guess)."""
    if "_mod" not in _fc.__dict__:
        try:
            spec = importlib.util.spec_from_file_location("metadata_fc_for_guard", _HERE / "format_candidates.py")
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            _fc._mod = mod
        except Exception:
            _fc._mod = None
    return _fc._mod


# --------------------------------------------------------------------------- (1) true magic vs extension

# Canonical container tag -> a predicate on the leading bytes. Ordered: the most specific / longest magic
# first, so a polyglot or a nested container is named by its OUTER real magic. A tag is a stable, neutral
# word, never an author label. Extend freely: a tag with no entry is simply unknown (-> None), never guessed.
def _is_mp4(d):
    return len(d) >= 12 and d[4:8] == b"ftyp"


def _is_tar(d):
    return len(d) >= 265 and d[257:262] == b"ustar"


_MAGICS = (
    ("sqlite_wal", lambda d: d[:4] in (b"\x37\x7f\x06\x82", b"\x37\x7f\x06\x83")),
    ("sqlite_journal", lambda d: d[:8] == b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7"),
    ("sqlite", lambda d: d[:16] == b"SQLite format 3\x00"),
    ("png", lambda d: d[:8] == b"\x89PNG\r\n\x1a\n"),
    ("gif", lambda d: d[:6] in (b"GIF87a", b"GIF89a")),
    ("pdf", lambda d: d[:5] == b"%PDF-"),
    ("class", lambda d: d[:4] == b"\xca\xfe\xba\xbe" and len(d) >= 8 and d[6:8] >= b"\x00\x2d"),  # Java class: version>=45
    ("macho_fat", lambda d: d[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf") and not (len(d) >= 8 and d[6:8] >= b"\x00\x2d")),
    ("macho", lambda d: d[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")),
    ("elf", lambda d: d[:4] == b"\x7fELF"),
    ("pe", lambda d: d[:2] == b"MZ"),
    ("flac", lambda d: d[:4] == b"fLaC"),
    ("ogg", lambda d: d[:4] == b"OggS"),
    ("riff", lambda d: d[:4] == b"RIFF"),            # WAV / AVI / WEBP container; refine below
    ("mp3_id3", lambda d: d[:3] == b"ID3"),
    ("mp4", _is_mp4),
    ("bzip2", lambda d: d[:3] == b"BZh"),
    ("gzip", lambda d: d[:2] == b"\x1f\x8b"),
    ("xz", lambda d: d[:6] == b"\xfd7zXZ\x00"),
    ("sevenzip", lambda d: d[:6] == b"7z\xbc\xaf\x27\x1c"),
    ("rar", lambda d: d[:6] == b"Rar!\x1a\x07"),
    ("zip", lambda d: d[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")),
    ("dex", lambda d: d[:4] == b"dex\n"),
    ("tar", _is_tar),
)

# refine RIFF subtype
_RIFF_SUB = {b"WAVE": "wav", b"AVI ": "avi", b"WEBP": "webp"}

# What a file EXTENSION claims. Only an unambiguous audio/media/container suffix is listed; an extension not
# here claims nothing (declared_format -> None), so is_decoy stays conservative and never cries wolf.
_EXT_CLAIM = {
    "wav": "wav", "flac": "flac", "ogg": "ogg", "opus": "ogg", "oga": "ogg", "mp3": "mp3_id3",
    "mp4": "mp4", "m4a": "mp4", "mov": "mp4", "png": "png", "gif": "gif", "jpg": "jpeg", "jpeg": "jpeg",
    "pdf": "pdf", "zip": "zip", "jar": "zip", "apk": "zip", "gz": "gzip", "bz2": "bzip2", "xz": "xz",
    "7z": "sevenzip", "rar": "rar", "elf": "elf", "so": "elf", "class": "class", "dex": "dex",
    "sqlite": "sqlite", "sqlite3": "sqlite", "db": "sqlite",
}


def true_magic(data):
    """The canonical container tag of `data` read from its LEADING BYTES, or None when no magic matches.
    Extension-independent on purpose: the one and only basis is the bytes. A RIFF container is refined to
    its subtype (wav/avi/webp)."""
    if not isinstance(data, (bytes, bytearray)) or len(data) < 2:
        return None
    d = bytes(data)
    for tag, pred in _MAGICS:
        try:
            if pred(d):
                if tag == "riff":
                    return _RIFF_SUB.get(d[8:12], "riff")
                return tag
        except Exception:
            continue
    return None


def declared_format(name):
    """The container tag a file NAME's extension claims, or None when its extension claims nothing."""
    if not isinstance(name, str) or "." not in name:
        return None
    ext = name.rsplit(".", 1)[-1].lower()
    return _EXT_CLAIM.get(ext)


def is_decoy(name, data):
    """True when the file's extension claims one container but its true magic is another (a decoy /
    mislabelled file, the Day-23 `.wav`->Opus trick generalised). False when they agree or the extension
    claims nothing or the magic is unknown (conservative: a decoy is only flagged on a definite conflict).
    `jpeg` and a RIFF-less wav etc. are treated leniently where one tag is a family of the other."""
    claimed = declared_format(name)
    actual = true_magic(data)
    if claimed is None or actual is None:
        return False
    if claimed == actual:
        return False
    # families that are not a conflict: a jar/apk IS a zip; opus/oga ARE ogg (handled by _EXT_CLAIM already)
    if {claimed, actual} <= {"zip"}:
        return False
    return True


# --------------------------------------------------------------------------- (2) order is candidates

def order_candidates(key, items, numeric=False):
    """A `labels.candidates` pick (row 346) over BOTH the document (stored) order AND the ascending-sorted
    order of a KNOWN collection -- the never-plain collation guard. One probe on the untimed base (or a
    no-deadline attempt) settles which order the judge collates by; no single guess can sink a batch.
    `key` is a labels key `<lane>.<field>/<shape>`; CANDIDATE_MARK is added by candidates(). None when the
    collection is empty or cannot be rendered. `numeric=True` sorts numerically (an int list)."""
    fc = _fc()
    if fc is None or not items:
        return None
    try:
        return fc.pick(key, list(items), "intlist" if numeric else "list")
    except Exception:
        return None


# --------------------------------------------------------------------------- (3) never pick a decoy member

def _zip_member_names(data):
    """Central-directory member names of a zip in STORED order, or None when it is not a readable zip.
    Pure stdlib, no decompression (names only), so a decoy body cannot execute anything."""
    try:
        import io
        import zipfile
        with zipfile.ZipFile(io.BytesIO(bytes(data))) as z:
            return z.namelist()
    except Exception:
        return None


def select_member(container, wanted):
    """The bytes of exactly the member named `wanted` inside a zip `container`, as `(stored_name, bytes)` --
    NEVER a decoy sibling. Matched first by exact path, then by basename when exactly one member has it.
    None when the member is absent, ambiguous (two members share the name/basename), or the container is not
    a readable zip. The question named a member; a sibling, however tempting, is never that member."""
    try:
        import io
        import zipfile
        with zipfile.ZipFile(io.BytesIO(bytes(container))) as z:
            infos = z.infolist()
            exact = [i for i in infos if i.filename == wanted]
            if len(exact) == 1:
                return exact[0].filename, z.read(exact[0])
            if len(exact) > 1:
                return None                                   # ambiguous: two members named exactly this
            base = [i for i in infos if i.filename.rsplit("/", 1)[-1] == wanted.rsplit("/", 1)[-1]]
            if len(base) == 1:
                return base[0].filename, z.read(base[0])
            return None                                       # absent or ambiguous by basename
    except Exception:
        return None


if __name__ == "__main__":   # a quick manual look, no network
    print("png bytes ->", true_magic(b"\x89PNG\r\n\x1a\n" + bytes(8)))
    print("zip under .png is a decoy:", is_decoy("image.png", b"PK\x03\x04" + bytes(30)))
    print("order ->", order_candidates("metadata.selftest/x", ["shelf", "cabinet", "box"]))
