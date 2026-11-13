"""NTFS volume walk with deleted-file export (B-029): what `fls` + `icat` gave by hand, offline.

    vols = find_volumes(image)                  # [(byte offset, "bare" | "mbr p1" | "gpt p2")]
    vol = read_volume(image, offset, how)       # every FILE record of the $MFT, deleted ones too
    vol.files                                   # [NtfsFile]: path, deleted, size, data (or why not)
    listing(vol)                                # an fls-like table, one line per file and stream

The record and attribute checks are solvers/toolkits/filesystem_depth.py's (signature, update-sequence
fixup, attribute bounds, runlist), loaded as a pack: a record that fails them is counted and named, never
guessed at. On top of them this module adds what recovery needs:

- the $MFT is read through its own runlist (record 0), so a fragmented $MFT is walked whole; when record 0
  does not parse, the records are read contiguously from the boot sector's MFT start and a note says so;
- extension records (base reference set) give their attributes to the base record, and a $DATA split
  over several extents is joined by VCN;
- paths are rebuilt from $FILE_NAME parent references (Win32/POSIX name before the DOS 8.3 one); a parent
  that is not in the $MFT puts the file under `$Orphan/`;
- a deleted file whose clusters now lie in an allocated file's runs is marked `overwritten`: its bytes
  are still exported, but they may be someone else's;
- compressed (LZNT1) and EFS-encrypted streams, and runs outside the image, give no data and a reason.

Metafiles (records 0-15) and `$Extend/` are listed but not exported. Nothing is mounted or executed.
"""
from __future__ import annotations

import bisect
import struct
from dataclasses import dataclass, field

from .. import paths as _paths
from ..packs import load_module as _load_module

MAX_MFT = 64 << 20          # bytes of $MFT read (65536 records of 1 KiB)
MAX_FILES = 8192            # files and streams listed per volume
MAX_PATH_DEPTH = 64
FIRST_USER_RECORD = 16      # 0-15 are the metafiles ($MFT ... $Extend)
ROOT = 5
ATTR_FILE_NAME, ATTR_DATA = 0x30, 0x80
FLAG_COMPRESSED, FLAG_ENCRYPTED = 0x0001, 0x4000
USA_STRIDE = 512            # NTFS protects every 512 bytes of a record, whatever the sector size
NAMESPACE_DOS = 2
GAP_STOP = 256              # without record 0: empty slots in a row that end a contiguous read


class NtfsError(ValueError):
    """The bytes at that offset are not an NTFS volume this walk can read; the message says why."""


def _fsd():
    rel = "solvers/toolkits/filesystem_depth.py"
    return _load_module("ctf_recover_filesystem_depth", _paths.repo_root() / rel, pack=rel)


@dataclass
class NtfsFile:
    record: int
    path: str                        # relative to the volume root, '/'-separated; ':stream' for an ADS
    deleted: bool
    directory: bool
    size: int
    stream: str | None = None
    data: bytes | None = None
    why: str = ""                    # why data is None
    overwritten: bool = False        # deleted, and a cluster of it is in an allocated file's runs
    resident: bool = False
    orphan: bool = False             # its parent directory is not in the $MFT
    system: bool = False             # a metafile or under $Extend/: listed, not exported


@dataclass
class Volume:
    offset: int
    how: str
    cluster_size: int
    record_size: int
    records: int                     # FILE records read
    files: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    bad_records: list = field(default_factory=list)

    @property
    def deleted(self) -> list:
        return [f for f in self.files if f.deleted and not f.directory]


def is_ntfs_boot(sector: bytes) -> bool:
    return len(sector) >= 512 and sector[3:11] == b"NTFS    " and sector[510:512] == b"\x55\xaa"


def find_volumes(data: bytes) -> list[tuple[int, str]]:
    """[(offset, how)] of every NTFS boot sector at the start of the bytes or of an MBR / GPT partition."""
    if is_ntfs_boot(data[:512]):
        return [(0, "bare")]
    out = []
    if len(data) >= 1024 and data[512:520] == b"EFI PART":
        table, count, size = struct.unpack_from("<QII", data, 512 + 72)
        if 128 <= size <= 4096 and count <= 1024:
            for n in range(count):
                at = table * 512 + n * size
                if at + 48 > len(data):
                    break
                if not any(data[at:at + 16]):
                    continue
                first = struct.unpack_from("<Q", data, at + 32)[0]
                if is_ntfs_boot(data[first * 512:first * 512 + 512]):
                    out.append((first * 512, f"gpt p{n + 1}"))
        return out
    if len(data) >= 512 and data[510:512] == b"\x55\xaa":
        for n in range(4):
            e = 446 + 16 * n
            ptype = data[e + 4]
            lba = struct.unpack_from("<I", data, e + 8)[0]
            if ptype and lba and is_ntfs_boot(data[lba * 512:lba * 512 + 512]):
                out.append((lba * 512, f"mbr p{n + 1}"))
    return out


class _Intervals:
    """Allocated cluster ranges, for the overwritten test."""

    def __init__(self, ranges):
        merged = []
        for a, b in sorted(ranges):
            if merged and a <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], b)
            else:
                merged.append([a, b])
        self.starts = [a for a, _ in merged]
        self.ends = [b for _, b in merged]

    def overlaps(self, a: int, b: int) -> bool:
        i = bisect.bisect_right(self.starts, b - 1) - 1
        return i >= 0 and self.ends[i] > a


def _runs_ranges(attr) -> list[tuple[int, int]]:
    return [(r.lcn, r.lcn + r.length) for r in attr.runs if r.lcn is not None]


def _file_names(rec) -> list[tuple[int, int, str]]:
    """[(parent record, namespace, name)] of a record's $FILE_NAME attributes."""
    out = []
    for a in rec.attributes:
        if a.type_code != ATTR_FILE_NAME or a.value is None or len(a.value) < 66:
            continue
        parent = struct.unpack_from("<Q", a.value, 0)[0] & ((1 << 48) - 1)
        count, ns = a.value[64], a.value[65]
        try:
            name = a.value[66:66 + 2 * count].decode("utf-16-le")
        except UnicodeDecodeError:
            continue
        out.append((parent, ns, name))
    return out


def _best_name(names):
    for parent, ns, name in names:
        if ns != NAMESPACE_DOS:
            return parent, name
    return (names[0][0], names[0][2]) if names else None


def _mft_bytes(vol: memoryview, boot, fsd, notes: list) -> bytes:
    """The $MFT through record 0's own runlist, or contiguous from the MFT start (with a note)."""
    cs, rs = boot.cluster_size, boot.record_size
    start = boot.mft_lcn * cs
    rec0 = fsd.parse_ntfs_record(bytes(vol[start:start + rs]), sector_size=USA_STRIDE)
    data = None
    if rec0 is not None:
        pieces = [a for a in rec0.attributes if a.type_code == ATTR_DATA and not a.name and not a.resident]
        if pieces:
            data = pieces[0]
    if data is not None:
        size = min(data.data_size, MAX_MFT)
        if data.data_size > MAX_MFT:
            notes.append(f"the $MFT is {data.data_size} bytes: only the first {MAX_MFT} are read")
        out = bytearray()
        for r in data.runs:
            if r.lcn is None:
                out += bytes(r.length * cs)
            else:
                if (r.lcn + r.length) * cs > len(vol):
                    notes.append("a run of the $MFT lies past the end of the image: the records after it are "
                                 "not read")
                    break
                out += vol[r.lcn * cs:(r.lcn + r.length) * cs]
            if len(out) >= size:
                break
        return bytes(out[:size])
    notes.append(f"the $MFT's own record (0) does not parse: records are read contiguously from the boot "
                 f"sector's MFT start until {GAP_STOP} slots in a row hold no FILE record")
    out = bytearray()
    at, gap = start, 0
    while at + rs <= len(vol) and len(out) < MAX_MFT and gap < GAP_STOP:
        slot = bytes(vol[at:at + rs])
        gap = 0 if slot[:4] in (b"FILE", b"BAAD") else gap + 1
        out += slot
        at += rs
    return bytes(out)                # the empty slots at the end hold no FILE record: read as none


def read_volume(data: bytes, offset: int = 0, how: str = "bare") -> Volume:
    """Walk the NTFS volume that starts at `offset`. Raises NtfsError when its boot sector does not pass."""
    fsd = _fsd()
    vol = memoryview(data)[offset:]
    boot = fsd.parse_ntfs_boot(bytes(vol[:512]))
    if boot is None:
        raise NtfsError(f"no valid NTFS boot sector at offset {offset} (filesystem_depth.parse_ntfs_boot)")
    cs, rs = boot.cluster_size, boot.record_size
    v = Volume(offset, how, cs, rs, 0)
    mft = _mft_bytes(vol, boot, fsd, v.notes)
    recs = {}
    for n in range(len(mft) // rs):
        raw = mft[n * rs:(n + 1) * rs]
        if raw[:4] != b"FILE":
            if raw[:4] == b"BAAD":
                v.bad_records.append(n)
            continue
        rec = fsd.parse_ntfs_record(raw, sector_size=USA_STRIDE)
        if rec is None:
            v.bad_records.append(n)
            continue
        recs[n] = rec
    v.records = len(recs)
    if v.bad_records:
        shown = ", ".join(map(str, v.bad_records[:10])) + (" ..." if len(v.bad_records) > 10 else "")
        v.notes.append(f"{len(v.bad_records)} record(s) carry a FILE/BAAD signature but fail the record checks "
                       f"(not read): {shown}")
    # Extension records give their attributes to their base record.
    attrs, base_of = {}, {}
    for n, rec in recs.items():
        base = rec.base_record if rec.base_record and rec.base_record in recs else n
        base_of[n] = base
        attrs.setdefault(base, []).extend(rec.attributes)
    found = {}
    for n, rec in recs.items():
        found.setdefault(base_of[n], []).extend(_file_names(rec))
    names = {n: best for n, fns in found.items() if (best := _best_name(fns)) is not None}
    allocated = _Intervals([rg for n, rec in recs.items() if recs[base_of[n]].in_use
                            for a in rec.attributes if not a.resident for rg in _runs_ranges(a)])

    def path_of(n: int) -> tuple[str, bool]:
        parts, seen, cur = [], set(), n
        while cur != ROOT and len(parts) < MAX_PATH_DEPTH:
            if cur in seen or cur not in names:
                return "/".join(["$Orphan"] + parts[::-1]), True
            seen.add(cur)
            parent, name = names[cur]
            parts.append(name)
            cur = parent
        return "/".join(parts[::-1]), False

    for n in sorted(names):
        if n == ROOT:
            continue
        rec = recs[n]
        path, orphan = path_of(n)
        system = n < FIRST_USER_RECORD or path.startswith("$Extend/") or path == "$Extend"
        streams = {}
        for a in attrs[n]:
            if a.type_code == ATTR_DATA:
                streams.setdefault(a.name, []).append(a)
        if rec.directory and not streams:
            v.files.append(NtfsFile(n, path, not rec.in_use, True, 0, orphan=orphan, system=system))
            continue
        if not streams:
            v.files.append(NtfsFile(n, path, not rec.in_use, rec.directory, 0, why="no $DATA attribute",
                                    orphan=orphan, system=system))
        for sname in sorted(streams, key=lambda s: (s != "", s)):
            f = _stream(vol, fsd, n, rec, path, sname or None, streams[sname], cs, allocated)
            f.orphan, f.system = orphan, system
            v.files.append(f)
        if len(v.files) >= MAX_FILES:
            v.notes.append(f"stopped listing at {MAX_FILES} files and streams")
            break
    return v


def _stream(vol, fsd, n, rec, path, sname, pieces, cs, allocated) -> NtfsFile:
    full = path + (":" + sname if sname else "")
    deleted = not rec.in_use
    resident = [p for p in pieces if p.resident]
    if resident:
        a = resident[0]
        return NtfsFile(n, full, deleted, rec.directory, a.data_size, sname, fsd.recover_ntfs_attribute(
            vol, a, cs), resident=True)
    pieces = sorted(pieces, key=lambda p: p.runs[0].vcn if p.runs else 0)
    head = pieces[0]
    runs = tuple(r for p in pieces for r in p.runs)
    attr = fsd.NtfsAttribute(head.type_code, head.attribute_id, head.name, False, head.flags, None, runs,
                             head.data_size, head.allocated_size, head.initialized_size)
    f = NtfsFile(n, full, deleted, rec.directory, head.data_size, sname)
    if head.flags & FLAG_COMPRESSED:
        f.why = "compressed (LZNT1): not decoded here"
    elif head.flags & FLAG_ENCRYPTED:
        f.why = "EFS-encrypted: not decoded here"
    else:
        f.data = fsd.recover_ntfs_attribute(vol, attr, cs)
        if f.data is None:
            f.why = "its runs lie outside the image or do not cover its size"
    if deleted:
        f.overwritten = any(allocated.overlaps(a, b) for a, b in _runs_ranges(attr))
    return f


def listing(vol: Volume) -> str:
    """An fls-like table: record, state, size, path, and the reason when no bytes came out."""
    lines = [f"# NTFS volume at offset {vol.offset} ({vol.how}): cluster {vol.cluster_size}, record "
             f"{vol.record_size}, {vol.records} FILE records read",
             "# record  state      size  path"]
    for f in vol.files:
        state = ("deleted" if f.deleted else "in-use") + ("/dir" if f.directory else "")
        extra = []
        if f.overwritten:
            extra.append("clusters reused by an allocated file")
        if f.orphan:
            extra.append("parent not in the $MFT")
        if f.system:
            extra.append("metafile, not exported")
        if f.why:
            extra.append(f.why)
        lines.append(f"{f.record:8d}  {state:<11}{f.size:>10}  {f.path}" + (f"  [{'; '.join(extra)}]" if extra else ""))
    for note in vol.notes:
        lines.append(f"# note: {note}")
    return "\n".join(lines) + "\n"
