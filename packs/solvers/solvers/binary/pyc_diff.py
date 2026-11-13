#!/usr/bin/env python3
"""Pyc-vs-source differential: which compiled .pyc no longer matches the .py beside it (B-058).

CSCTF Shadow-Dispatch shipped dozens of Lambda layer zips, each a clean-looking `_authlog.py` with its
`__pycache__/_authlog.cpython-312.pyc`; four of the pycs were trojaned and built unchecked-hash
(PEP 552 flags 0b01), so CPython loaded them without looking at the source ("no unauthorized
changes"). Finding the four took an agent recompiling and comparing code objects by hand. Here the
comparison is mechanical and needs no matching interpreter:

  hash-based pyc   the header's 8-byte source hash against SipHash of the sibling .py's raw bytes,
                   keyed by that pyc's own 4-byte magic (CPython's `_imp.source_hash`): SipHash-1-3
                   from 3.11, SipHash-2-4 for 3.7-3.10. Computed here in pure Python, so a 3.9 or 3.14
                   pyc is checked from any interpreter (importlib.util.source_hash only knows the
                   host's magic; the tests use it, and other installed interpreters, as the oracle).
  timestamp pyc    the header's source-size field against the sibling's size (mod 2**32). A weaker
                   check: an edit that keeps the length passes; it says so.
  both             a `__pycache__` name tag (`cpython-312`) that disagrees with the header's magic.

Pairs: `<dir>/__pycache__/<stem>.<tag>[.opt-N].pyc` with `<dir>/<stem>.py`, and a legacy `<stem>.pyc`
or `.pyo` with the `<stem>.py` beside it. Inputs: every file under the challenge folder (no symlink
is followed; `recon/`, `.git/` and `.ctf/` are never entered) and the members of zip, wheel, egg and
pyz archives in it, nested up to MAX_DEPTH levels, read in memory. A pair seen twice (an archive and
the sweep's unpacked copy of it) is checked once.

Only the header and the source bytes are read: no pyc is unmarshalled, imported or run, and no source
is compiled. What the tampered bytecode does (Shadow-Dispatch's beacon decode) stays an agent's job:
run `binary.redepth_pyc` on a reported pyc for a static disassembly.

Result: `unsure` with one evidence line per mismatching pyc (the lead: decompile those); `candidate`
when flag-format text sits in a mismatching pyc's bytes; `unsure` when no pair mismatches but some
could not be checked (a Python 2 header keeps no size, an unknown magic), were not read (a cap, an
encrypted or unreadable member), sit in an archive a cap (MAX_DEPTH, MAX_MEMBER) or encryption kept
shut, or the scan was cut short (MAX_TOTAL, MAX_FILES), naming them; `none` when every pair seen
matches or there is no pyc with a sibling source (a file that only looked like an archive and would
not open is named in the notes).

    python -m ctf run binary.pyc_diff <challenge_dir>
    tools/ctfpy solvers/binary/pyc_diff.py <file-or-folder> [...] [--all] [--json]   # by hand
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import sys
import zipfile
import zlib
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath

from bytecode_lifters import LiftError, inspect_pyc_header
from readers_more import PYC_MAGIC

ENGINE = "binary.pyc_diff"
MAX_FILES = 50_000              # files under the challenge folder that are looked at
MAX_DEPTH = 4                   # archive nesting levels opened
MAX_MEMBER = 256 << 20          # bytes of one nested archive read into memory
MAX_PAIR_BYTES = 32 << 20       # bytes of one .pyc or .py read
MAX_TOTAL = 1 << 30             # decompressed bytes read in all
MAX_PAIRS = 20_000              # pairs checked
SKIP_DIRS = {".git", ".ctf"}      # never entered, at any depth
SKIP_TOP = {"recon"}              # engine output beside the handout: skipped at the top only
# what reading an untrusted archive or file can raise; anything else is a bug here and propagates
_READ_ERRORS = (OSError, zipfile.BadZipFile, zipfile.LargeZipFile, ValueError, EOFError, zlib.error,
                NotImplementedError, RuntimeError)
ARCHIVE_EXTS = (".zip", ".whl", ".egg", ".pyz")
PYC_EXTS = (".pyc", ".pyo")
ZIP_MAGIC = b"PK\x03\x04"

_U64 = (1 << 64) - 1
_CACHE_NAME = re.compile(r"^(?P<stem>[^.]+)(?:\.(?P<tag>[a-z]+-?\d+))?(?:\.opt-\d+)?\.py[co]$", re.I)
_TAG_VERSION = re.compile(r"^(?:cpython|python)-?(?P<major>\d)(?P<minor>\d+)$", re.I)

# Magic numbers CPython used per minor version (Lib/importlib/_bootstrap_external.py): the released
# magic of each is PYC_MAGIC's (the Metadata lane's table); the ranges label alpha/beta magics.
_MAGIC_RANGES = ((3390, 3399, "3.7"), (3400, 3419, "3.8"), (3420, 3429, "3.9"), (3430, 3449, "3.10"),
                 (3450, 3499, "3.11"), (3500, 3549, "3.12"), (3550, 3599, "3.13"), (3600, 3649, "3.14"))
SIPHASH13_FROM = 3450           # 3.11 (bpo-29410) moved _Py_KeyedHash from SipHash-2-4 to SipHash-1-3


class PycDiffError(ValueError):
    """A header this module cannot read, or a magic it cannot key a source hash with."""


# ------------------------------------------------------------------ SipHash and the source hash

def _rotl(x: int, b: int) -> int:
    return ((x << b) | (x >> (64 - b))) & _U64


def siphash(k0: int, k1: int, data: bytes, c_rounds: int = 1, d_rounds: int = 3) -> int:
    """SipHash-c-d of `data` under the 128-bit key (k0, k1), as a 64-bit integer."""
    v0, v1 = k0 ^ 0x736F6D6570736575, k1 ^ 0x646F72616E646F6D
    v2, v3 = k0 ^ 0x6C7967656E657261, k1 ^ 0x7465646279746573

    def rounds(n, v0, v1, v2, v3):
        for _ in range(n):
            v0 = (v0 + v1) & _U64; v1 = _rotl(v1, 13) ^ v0; v0 = _rotl(v0, 32)
            v2 = (v2 + v3) & _U64; v3 = _rotl(v3, 16) ^ v2
            v0 = (v0 + v3) & _U64; v3 = _rotl(v3, 21) ^ v0
            v2 = (v2 + v1) & _U64; v1 = _rotl(v1, 17) ^ v2; v2 = _rotl(v2, 32)
        return v0, v1, v2, v3

    n = len(data)
    end = n - n % 8
    for i in range(0, end, 8):
        m = int.from_bytes(data[i:i + 8], "little")
        v3 ^= m
        v0, v1, v2, v3 = rounds(c_rounds, v0, v1, v2, v3)
        v0 ^= m
    last = ((n & 0xFF) << 56) | int.from_bytes(data[end:], "little")
    v3 ^= last
    v0, v1, v2, v3 = rounds(c_rounds, v0, v1, v2, v3)
    v0 ^= last
    v2 ^= 0xFF
    v0, v1, v2, v3 = rounds(d_rounds, v0, v1, v2, v3)
    return (v0 ^ v1 ^ v2 ^ v3) & _U64


def magic_number(magic: bytes) -> int:
    if len(magic) < 4 or magic[2:4] != b"\r\n":
        raise PycDiffError(f"not a pyc magic: {magic[:4].hex() or 'empty'}")
    return int.from_bytes(magic[:2], "little")


def hash_algorithm(magic: bytes) -> str:
    """'siphash13' or 'siphash24': what CPython's `_imp.source_hash` used for this magic."""
    m = magic_number(magic)
    if not 3392 <= m < 20000:
        raise PycDiffError(f"magic {m} predates hash-based pycs (PEP 552, Python 3.7)")
    return "siphash13" if m >= SIPHASH13_FROM else "siphash24"


def source_hash(source: bytes, magic: bytes) -> bytes:
    """The 8 bytes a hash-based pyc with this 4-byte magic stores for `source` (raw file bytes)."""
    rounds = (1, 3) if hash_algorithm(magic) == "siphash13" else (2, 4)
    key = int.from_bytes(magic[:4], "little")
    return siphash(key, 0, bytes(source), *rounds).to_bytes(8, "little")


def magic_version(magic: bytes) -> str | None:
    """'3.12' for a released magic (PYC_MAGIC), '3.12 (pre-release magic 3519)' inside a known range,
    None for a magic no CPython release line used."""
    m = magic_number(magic)
    if m in PYC_MAGIC:
        return PYC_MAGIC[m]
    for low, high, version in _MAGIC_RANGES:
        if low <= m <= high:
            return f"{version} (pre-release magic {m})"
    return None


def header_size(magic: bytes) -> int:
    """16 (PEP 552, 3.7+), 12 (3.3-3.6: mtime and size) or 8 (Python 2 and 3.0-3.2: mtime only)."""
    m = magic_number(magic)
    if 3392 <= m < 20000:
        return 16
    if 3190 <= m < 3392:
        return 12
    return 8


def tag_version(tag: str | None) -> str | None:
    """'3.12' for the cache tag 'cpython-312'; None for no tag or another implementation's tag."""
    hit = _TAG_VERSION.match(tag or "")
    return f"{hit['major']}.{hit['minor']}" if hit else None


# ------------------------------------------------------------------ one pair

@dataclass
class Check:
    pyc: str                     # label: "files/a.zip!python/__pycache__/x.cpython-312.pyc"
    source: str                  # label of the sibling .py
    path: str                    # the on-disk file that holds the pyc, relative to the challenge
    verdict: str                 # match | mismatch | unverifiable
    method: str                  # hash | size | tag | header | none
    version: str | None
    magic_hex: str
    flags: int | None
    detail: str
    pyc_sha256: str = ""
    source_sha256: str = ""
    also: list[str] = field(default_factory=list)   # the same pair at other places

    def to_dict(self) -> dict:
        return asdict(self)


def check_pair(pyc_name: str, pyc: bytes, source: bytes) -> tuple[str, str, str | None, str, int | None, str]:
    """(verdict, method, version, magic hex, flags, detail) of one pyc against its sibling source.
    Only the header is read; the marshalled code is never touched."""
    magic_hex = pyc[:4].hex()
    try:
        m = magic_number(pyc)
    except PycDiffError as e:
        return "mismatch", "header", None, magic_hex, None, f"{e}: CPython would refuse this file"
    version = magic_version(pyc)
    size = header_size(pyc)
    tag = _CACHE_NAME.match(PurePosixPath(pyc_name).name)
    named = tag_version(tag["tag"]) if tag else None
    if named and version and version.split(" ")[0] != named:
        return ("mismatch", "tag", version, magic_hex, None,
                f"named for Python {named} ({tag['tag']}) but its magic {m} is Python {version}")
    if size == 8:
        if len(pyc) < 8:
            return "mismatch", "header", version, magic_hex, None, "truncated pyc header (under 8 bytes)"
        return ("unverifiable", "none", version, magic_hex, None,
                f"a {version or f'magic {m}'} pyc header keeps only the source mtime, not its size or hash")
    try:
        head = inspect_pyc_header(pyc, header_size=size)
    except LiftError as e:
        flags = int.from_bytes(pyc[4:8], "little") if len(pyc) >= 8 and size == 16 else None
        if version is None:     # the layout was only assumed from the magic's range: no claim
            return ("unverifiable", "header", version, magic_hex, flags,
                    f"magic {m} is no known CPython magic and its header does not read as the "
                    f"{size}-byte layout assumed for it ({e})")
        return "mismatch", "header", version, magic_hex, flags, f"malformed header: {e}"
    flags = int.from_bytes(pyc[4:8], "little") if size == 16 else None
    if head.hash_based:
        stored = bytes.fromhex(head.source_hash_hex)
        want = source_hash(source, pyc)
        algo = hash_algorithm(pyc)
        kind = "checked" if head.checked_hash else "unchecked: CPython loads it without reading the source"
        if stored == want:
            return "match", "hash", version, magic_hex, flags, f"hash-based ({kind}); {algo} {want.hex()}"
        if version is None:
            return ("unverifiable", "hash", version, magic_hex, flags,
                    f"hash-based; magic {m} is no known CPython magic, so its hash ({algo} assumed: "
                    f"{want.hex()}) cannot confirm a mismatch with the stored {stored.hex()}")
        return ("mismatch", "hash", version, magic_hex, flags,
                f"hash-based ({kind}); header source hash {stored.hex()}, sibling hashes to {want.hex()} "
                f"({algo}, keyed by magic {magic_hex})")
    # CPython stores the size mod 2**32 (a 4-byte field); MAX_PAIR_BYTES keeps a scan far below that,
    # but check_pair is public and takes any sized buffer
    n = len(source)
    want = n & 0xFFFFFFFF
    of = f"{n} bytes" + (f", {want} mod 2**32" if want != n else "")
    if head.source_size == want:
        return ("match", "size", version, magic_hex, flags,
                f"timestamp-based; source size {of} matches (size only: an edit of the same length passes)")
    if version is None:
        return ("unverifiable", "size", version, magic_hex, flags,
                f"timestamp-based by an assumed {size}-byte layout; magic {m} is no known CPython magic, so "
                f"its size field {head.source_size} against the sibling's {of} cannot confirm a mismatch")
    return ("mismatch", "size", version, magic_hex, flags,
            f"timestamp-based; header source size {head.source_size}, sibling is {of}")


def source_for(pyc_rel: str) -> str | None:
    """The sibling source a pyc at this posix path compiles: `a/__pycache__/m.cpython-312.pyc` ->
    `a/m.py`, `a/m.pyc` -> `a/m.py`; None for a name that is not a pyc."""
    p = PurePosixPath(pyc_rel)
    if p.suffix.lower() not in PYC_EXTS:
        return None
    if p.parent.name == "__pycache__":
        hit = _CACHE_NAME.match(p.name)
        if not hit:
            return None
        return str(p.parent.parent / f"{hit['stem']}.py")
    return str(p.with_suffix(".py"))


# ------------------------------------------------------------------ walking a handout

class _Budget(Exception):
    pass


@dataclass
class Scan:
    checks: list[Check] = field(default_factory=list)
    orphans: list[str] = field(default_factory=list)     # pycs with no sibling source
    notes: list[str] = field(default_factory=list)
    total: int = 0
    mismatched_bytes: dict = field(default_factory=dict)  # label -> the bytes of a mismatching pyc
    repeats: int = 0                                      # pairs skipped as the same bytes seen elsewhere
    skipped: list[str] = field(default_factory=list)      # pyc labels paired with a source but not checked
    unopened: list[str] = field(default_factory=list)     # archives not opened (broken, encrypted, caps)
    capped: list[str] = field(default_factory=list)       # of those, the ones a cap or encryption kept shut
    stopped: str | None = None                            # why the scan ended before seeing everything
    _seen: dict = field(default_factory=dict)

    def take(self, n: int) -> None:
        self.total += n
        if self.total > MAX_TOTAL:
            raise _Budget(f"read budget MAX_TOTAL={MAX_TOTAL} bytes spent")

    def skip(self, label: str, why: str) -> None:
        self.skipped.append(label)
        self.notes.append(f"{label}: {why}")

    def unopen(self, label: str, why: str, *, capped: bool = False) -> None:
        """capped: a real archive kept shut by a cap (MAX_DEPTH, MAX_MEMBER) or by encryption, whose pairs
        were never seen; False for a file that only looked like an archive and would not open."""
        self.unopened.append(label)
        if capped:
            self.capped.append(label)
        self.notes.append(f"{label}: {why}")

    def stop(self, why: str) -> None:
        self.stopped = why
        self.notes.append(why)

    @property
    def complete(self) -> bool:
        """Every pyc seen with a sibling source was checked, no archive was kept shut by a cap or
        encryption, and the walk was not cut short."""
        return not self.skipped and not self.capped and self.stopped is None


def _is_pair_name(name: str) -> bool:
    return name.lower().endswith(PYC_EXTS + (".py",))


def _check_pairs(scan: Scan, sizes: dict, read, *, prefix: str, where: str | None,
                 locked: frozenset = frozenset()) -> None:
    """Pair and check the pycs of one tree (a folder, or one archive's members).
    sizes: {posix path: size} of its .py/.pyc/.pyo files; read(name) -> bytes; where: the on-disk file
    that holds this tree (an archive), relative to the scanned folder, or None for the folder itself;
    locked: names in sizes that cannot be read (encrypted members). A pair that is not checked, for any
    reason, is recorded in scan.skipped."""
    # an exact-case sibling wins; else one that differs only in case (a handout zipped on a
    # case-insensitive system: __pycache__/foo.cpython-312.pyc beside Foo.py)
    folded = {}
    for n in sorted(sizes):
        folded.setdefault(n.lower(), n)
    for name in sorted(sizes):
        want = source_for(name)
        if want is None:
            continue
        label = prefix + name
        src = want if want in sizes else folded.get(want.lower())
        if src is None:
            scan.orphans.append(label)
            continue
        if len(scan.checks) >= MAX_PAIRS:
            scan.skip(label, f"not checked (over MAX_PAIRS={MAX_PAIRS})")
            continue
        shut = next((n for n in (name, src) if n in locked), None)
        if shut is not None:
            scan.skip(label, "encrypted member, not read" if shut == name
                      else f"not checked ({prefix}{shut}: encrypted member, not read)")
            continue
        big = next((n for n in (name, src) if sizes[n] > MAX_PAIR_BYTES), None)
        if big is not None:
            scan.skip(label, f"not checked ({prefix}{big}: {sizes[big]} bytes, over "
                             f"MAX_PAIR_BYTES={MAX_PAIR_BYTES}, not read)")
            continue
        try:
            pyc, source = read(name), read(src)
        except _Budget:
            raise
        except _READ_ERRORS as e:   # untrusted container: name the failure, never drop it
            scan.skip(label, f"not read ({type(e).__name__}: {e})")
            continue
        key = (hashlib.sha256(pyc).hexdigest(), hashlib.sha256(source).hexdigest(), PurePosixPath(name).name)
        first = scan._seen.get(key)
        if first is not None:
            scan.repeats += 1
            if label < first.pyc:
                # the label that sorts first names the pair, whichever was read first: an archive's
                # member ("x.zip!m.pyc") before the sweep's unpacked copy of it ("x.zip.unpacked/m.pyc")
                label, first.pyc, first.source, first.path = first.pyc, label, prefix + src, where or name
                if label in scan.mismatched_bytes:
                    scan.mismatched_bytes[first.pyc] = scan.mismatched_bytes.pop(label)
            if len(first.also) < 5:
                first.also.append(label)
            continue
        verdict, method, version, magic_hex, flags, detail = check_pair(name, pyc, source)
        chk = Check(label, prefix + src, where or name, verdict, method, version, magic_hex, flags, detail,
                    key[0], key[1])
        scan._seen[key] = chk
        scan.checks.append(chk)
        if verdict == "mismatch":
            scan.mismatched_bytes[label] = pyc


def _walk_zip(scan: Scan, zf: zipfile.ZipFile, label: str, where: str, depth: int) -> None:
    """The pairs among one archive's members, then the archives inside it (in memory, to MAX_DEPTH)."""
    infos, locked = {}, set()
    for info in zf.infolist():
        if info.is_dir():
            continue
        member = info.filename.replace("\\", "/").lstrip("/")
        if not (_is_pair_name(member) or member.lower().endswith(ARCHIVE_EXTS)):
            continue
        if member in infos:
            scan.notes.append(f"{label}!{member}: stored twice; the first copy is read")
            continue
        if info.flag_bits & 1:
            locked.add(member)      # a pair it belongs to is named as not checked; an archive as unopened
        infos[member] = info

    def read(member: str) -> bytes:
        info = infos[member]
        scan.take(info.file_size)
        with zf.open(info) as fh:
            data = fh.read(MAX_MEMBER + 1)
        if len(data) > max(info.file_size, 0) or len(data) > MAX_MEMBER:
            raise ValueError("member is larger than its header says")
        return data

    _check_pairs(scan, {m: i.file_size for m, i in infos.items() if _is_pair_name(m)}, read,
                 prefix=label + "!", where=where, locked=frozenset(locked))
    for member in sorted(m for m in infos if m.lower().endswith(ARCHIVE_EXTS)):
        inner = f"{label}!{member}"
        if member in locked:
            scan.unopen(inner, "encrypted member, not read", capped=True)
            continue
        if depth >= MAX_DEPTH:
            scan.unopen(inner, f"archive not opened (nesting over MAX_DEPTH={MAX_DEPTH})", capped=True)
            continue
        if infos[member].file_size > MAX_MEMBER:
            scan.unopen(inner, f"{infos[member].file_size} bytes, over MAX_MEMBER={MAX_MEMBER}, not opened",
                        capped=True)
            continue
        try:
            sub = zipfile.ZipFile(io.BytesIO(read(member)))
        except _Budget:
            raise
        except _READ_ERRORS as e:
            scan.unopen(inner, f"archive not read ({type(e).__name__}: {e})")
            continue
        with sub:
            _walk_zip(scan, sub, inner, where, depth + 1)


def _files_under(target: Path, scan: Scan) -> list[Path]:
    files = []
    for dirpath, dirnames, filenames in os.walk(target):          # followlinks=False: no symlinked folder
        here = Path(dirpath)
        dirnames[:] = sorted(d for d in dirnames
                             if d not in SKIP_DIRS and not (here == target and d in SKIP_TOP))
        for n in sorted(filenames):
            f = here / n
            if not f.is_symlink() and f.is_file():
                files.append(f)
        if len(files) > MAX_FILES:
            scan.stop(f"more than MAX_FILES={MAX_FILES} files: the rest were not looked at")
            return files[:MAX_FILES]
    return files


def _looks_zip(f: Path) -> bool:
    if f.name.lower().endswith(ARCHIVE_EXTS):
        return True
    try:
        with f.open("rb") as fh:
            return fh.read(4) == ZIP_MAGIC
    except OSError:
        return False


def scan_path(target: Path) -> Scan:
    """Every pyc/source pair under `target`, checked. A folder: its files and archives; a pyc: it and its
    sibling source; an archive: its members. Labels are relative to the folder (or the file's folder)."""
    target = Path(target)
    scan = Scan()
    if target.is_dir():
        root, files = target, _files_under(target, scan)
    elif target.suffix.lower() in PYC_EXTS:
        cache = target.parent.name == "__pycache__"
        root = target.parent.parent if cache else target.parent
        rel = target.relative_to(root).as_posix()
        files = [target] + [root / s for s in [source_for(rel)] if s and (root / s).is_file()]
    else:
        root, files = target.parent, [target]
    pairs, archives = {}, []
    for f in files:
        rel = f.relative_to(root).as_posix()
        if _is_pair_name(rel):
            pairs[rel] = f.stat().st_size
        elif _looks_zip(f):
            archives.append(rel)

    def read(name: str) -> bytes:
        scan.take(pairs[name])
        with (root / name).open("rb") as fh:
            data = fh.read(MAX_PAIR_BYTES + 1)
        if len(data) > MAX_PAIR_BYTES:
            raise ValueError(f"over MAX_PAIR_BYTES={MAX_PAIR_BYTES}")
        return data

    try:
        _check_pairs(scan, pairs, read, prefix="", where=None)
        for rel in archives:
            try:
                zf = zipfile.ZipFile(root / rel)            # opened in place, never read whole
            except _READ_ERRORS as e:
                scan.unopen(rel, f"archive not read ({type(e).__name__}: {e})")
                continue
            with zf:
                _walk_zip(scan, zf, rel, rel, 1)
    except _Budget as e:
        scan.stop(f"stopped early: {e}")
    return scan


# ------------------------------------------------------------------ the contract entry

def summary(scan: Scan) -> str:
    """One line: how many pairs were checked and how they came out."""
    by: dict[str, list[Check]] = {}
    for c in scan.checks:
        by.setdefault(c.verdict, []).append(c)
    matched = by.get("match", [])
    size_only = sum(1 for c in matched if c.method == "size")
    out = (f"checked {len(scan.checks)} pyc/source pair(s): {len(matched)} match"
           + (f" ({size_only} by source size only)" if size_only else "")
           + f", {len(by.get('mismatch', []))} mismatch, {len(by.get('unverifiable', []))} unverifiable")
    if scan.repeats:
        out += f" ({scan.repeats} more pair(s) were the same bytes at another place)"
    if scan.skipped:
        out += f"; {len(scan.skipped)} pair(s) not checked"
    if scan.orphans:
        shown = ", ".join(scan.orphans[:5]) + (", ..." if len(scan.orphans) > 5 else "")
        out += f"; {len(scan.orphans)} pyc(s) with no sibling source ({shown})"
    return out


def solve(challenge_dir, profile, **_opts):
    """Report every pyc whose header disagrees with its sibling .py (source hash, size or name tag)."""
    from ctf import flagfmt
    from ctf.result import Evidence, SolverResult

    challenge_dir = Path(challenge_dir)
    if not challenge_dir.is_dir():
        return SolverResult(status="blocked", engine=ENGINE, notes=f"{challenge_dir}: not a folder")
    scan = scan_path(challenge_dir)
    ff = flagfmt.for_profile(profile)
    bad = [c for c in scan.checks if c.verdict == "mismatch"]
    unverified = [c for c in scan.checks if c.verdict == "unverifiable"]
    evidence, flags = [], []
    for c in bad:
        more = f" (the same pair also at {', '.join(c.also)})" if c.also else ""
        evidence.append(Evidence(kind="pyc-mismatch", detail=f"{c.pyc} vs {c.source}: {c.detail}{more}", path=c.path))
    for c in bad:
        for fl in ff.find_flags(scan.mismatched_bytes.get(c.pyc, b"")):
            if fl not in flags:
                flags.append(fl)
                evidence.append(Evidence(kind="match", detail=f"{c.pyc}: flag-format text in a mismatching pyc",
                                         path=c.path))
    note = "; ".join([summary(scan)] + scan.notes)
    if flags:
        return SolverResult(status="candidate", flags=tuple(flags), evidence=tuple(evidence), engine=ENGINE,
                            notes="flag-format text inside a pyc that disagrees with its source (static, "
                                  "unverified). " + note)
    if bad:
        return SolverResult(status="unsure", evidence=tuple(evidence), engine=ENGINE,
                            notes=(f"{len(bad)} pyc(s) disagree with their sibling source: decompile those "
                                   "(binary.redepth_pyc for 3.12/3.13) to see what changed. " + note))
    if unverified or not scan.complete:
        why = []
        if unverified:
            named = "; ".join(f"{c.pyc} ({c.detail})" for c in unverified[:5])
            why.append(f"{len(unverified)} pair(s) could not be checked: {named}")
        if scan.skipped:
            named = ", ".join(scan.skipped[:5]) + (", ..." if len(scan.skipped) > 5 else "")
            why.append(f"{len(scan.skipped)} pair(s) were not read: {named}")
        if scan.capped:
            named = ", ".join(scan.capped[:5]) + (", ..." if len(scan.capped) > 5 else "")
            why.append(f"{len(scan.capped)} archive(s) were kept shut by a cap or encryption, so their "
                       f"pairs were never seen: {named}")
        if scan.stopped:
            why.append(f"the scan was cut short ({scan.stopped}), so pairs past that point were never seen")
        return SolverResult(status="unsure", engine=ENGINE,
                            notes="no pyc mismatches, but " + "; and ".join(why) + ". " + note)
    if not scan.checks and not scan.orphans:
        where = (f"in what could be read ({len(scan.unopened)} archive(s) not opened)" if scan.unopened
                 else "in the handout")
        note = f"no pyc with a sibling .py {where}" + ("; " + "; ".join(scan.notes) if scan.notes else "")
    return SolverResult(status="none", engine=ENGINE, notes=note)


# ------------------------------------------------------------------ by hand

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="pyc_diff.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("paths", nargs="+", help="folders, archives or pyc files")
    ap.add_argument("--all", action="store_true", help="also list pairs that match")
    ap.add_argument("--json", action="store_true", help="one JSON object per pair")
    args = ap.parse_args(argv)
    mismatched = 0
    for p in args.paths:
        path = Path(p)
        if not path.exists():
            print(f"pyc_diff: {p}: no such file or folder", file=sys.stderr)
            return 2
        scan = scan_path(path)
        for c in scan.checks:
            mismatched += c.verdict == "mismatch"
            if c.verdict == "match" and not args.all:
                continue
            if args.json:
                print(json.dumps(c.to_dict(), sort_keys=True))
            else:
                print(f"{c.verdict.upper():12} {c.pyc}: {c.detail}")
        print(f"# {p}: {summary(scan)}" + ("; " + "; ".join(scan.notes) if scan.notes else ""), file=sys.stderr)
    return 1 if mismatched else 0


__all__ = ["ENGINE", "Check", "PycDiffError", "Scan", "check_pair", "hash_algorithm", "header_size",
           "magic_version", "main", "scan_path", "siphash", "solve", "source_for", "source_hash", "summary",
           "tag_version"]

if __name__ == "__main__":
    raise SystemExit(main())
