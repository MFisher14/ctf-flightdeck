"""ext2/3/4 volumes for the sweep (B-135): the file tree with mtimes, the orphan inodes, and validated
ELF programs carved from the blocks the block bitmap marks free. Read only, never mounted.

    for offset, how in find_volumes(data):          # bare, or an MBR / GPT partition
        vol = read_volume(data, offset, how)        # ExtError when it does not read
        vol.files        # [ExtFile] every regular file reached from the root, with path, mtime and bytes
        vol.orphans      # [ExtFile] inodes in use or deleted that no directory names (a deleted tool)
        vol.carves       # [Carve] validated objects (ELF by default) in the unallocated blocks
        listing(vol)     # the JSON the sweep writes as ext-listing.json (paths, inodes, mtimes, carves)

How the free blocks are found: the group descriptor table (block first_data_block + 1) gives each
group's block bitmap; bit i of group g is block first_data_block + g * blocks_per_group + i, set =
in use. A group flagged BLOCK_UNINIT (under a checksum feature) has no bitmap written yet: it is all
free. Blocks before first_data_block and past the end of the bytes are never carved. The free blocks
are joined in block order, as sleuthkit's blkls writes them, and solvers/toolkits/carving.py's checked
carver (`carve_all`, structure-validated: an ELF's size comes from its program and section headers)
runs over that stream, so an object split around an allocated block is still found. Each carve names
the blocks it came from.

Limits, each a note, never silent: meta_bg layouts are declined; inline-data files and directories are
listed without bytes; a file over the walk's budget is listed and not exported.
"""
from __future__ import annotations

import datetime as _dt
import json
import struct
from dataclasses import dataclass, field

from .. import paths as _paths
from ..packs import load_module as _load_module

__all__ = ["ExtError", "ExtFile", "Carve", "ExtVolume", "find_volumes", "read_volume", "listing",
           "allocation_bitmap", "CARVE_KINDS", "LISTING", "CARVE_DIR"]

CARVE_KINDS = ("elf",)               # what is carved from free blocks (the B-135 row: a deleted encryptor)
LISTING = "ext-listing.json"
CARVE_DIR = "ext-unallocated"        # carves land in <image>.unpacked/ext-unallocated/ (B-011 reads them)
MAX_DIR_ENTRIES = 200_000
MAX_DEPTH = 64
MAX_INODES = 2_000_000
WINDOW = 48 << 20                    # carve_all scans at most 64 MiB at once; windows overlap by STEP
STEP = 32 << 20

INCOMPAT_FILETYPE, INCOMPAT_META_BG, INCOMPAT_64BIT = 0x2, 0x10, 0x80
RO_COMPAT_GDT_CSUM, RO_COMPAT_METADATA_CSUM = 0x10, 0x400
BG_BLOCK_UNINIT = 0x2
FLAG_INLINE_DATA = 0x10000000
S_IFMT, S_IFDIR, S_IFREG = 0xF000, 0x4000, 0x8000


class ExtError(ValueError):
    """The bytes at that offset are not an ext volume this reader can walk; the message says why."""


def _fsd():
    rel = "solvers/toolkits/filesystem_depth.py"
    return _load_module("ctf_recover_filesystem_depth", _paths.repo_root() / rel, pack=rel)


def _di():
    rel = "solvers/toolkits/disk_images.py"
    return _load_module("ctf_recover_disk_images", _paths.repo_root() / rel, pack=rel)


def _carving():
    rel = "solvers/toolkits/carving.py"
    return _load_module("ctf_recover_carving", _paths.repo_root() / rel, pack=rel)


@dataclass
class ExtFile:
    inode: int
    path: str                        # '/'-separated from the volume root; 'inode-<n>' for an orphan
    mode: int
    size: int
    mtime: int                       # seconds since the epoch, UTC (i_mtime)
    deleted: bool = False
    data: bytes | None = None
    why: str = ""                    # why data is None


@dataclass
class Carve:
    kind: str
    stream_offset: int               # offset in the joined free-block stream
    size: int
    blocks: list                     # [(first block, count)] the object's bytes came from, in order
    data: bytes = b""

    @property
    def first_block(self) -> int:
        return self.blocks[0][0]


@dataclass
class ExtVolume:
    offset: int
    how: str
    block_size: int
    blocks_count: int
    first_data_block: int
    volume_name: str
    groups: int
    free_blocks: int = 0
    files: list = field(default_factory=list)
    orphans: list = field(default_factory=list)
    carves: list = field(default_factory=list)
    notes: list = field(default_factory=list)


def _is_ext(data: bytes, at: int) -> bool:
    return len(data) >= at + 2048 and data[at + 1024 + 56:at + 1024 + 58] == b"\x53\xef"


def find_volumes(data: bytes) -> list[tuple[int, str]]:
    """[(offset, how)] of every ext superblock at the start of the bytes or of an MBR / GPT partition."""
    if _is_ext(data, 0):
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
                if _is_ext(data, first * 512):
                    out.append((first * 512, f"gpt p{n + 1}"))
        return out
    if len(data) >= 512 and data[510:512] == b"\x55\xaa":
        for n in range(4):
            e = 446 + 16 * n
            lba = struct.unpack_from("<I", data, e + 8)[0]
            if data[e + 4] and lba and _is_ext(data, lba * 512):
                out.append((lba * 512, f"mbr p{n + 1}"))
    return out


@dataclass
class _Group:
    block_bitmap: int
    inode_table: int
    flags: int


def _groups(vol: bytes, sb, first_data_block: int) -> list[_Group]:
    bs = sb.block_size
    count = -(-(sb.blocks_count - first_data_block) // sb.blocks_per_group)
    wide = sb.features_incompat & INCOMPAT_64BIT and sb.descriptor_size >= 64
    at = (first_data_block + 1) * bs
    if at + count * sb.descriptor_size > len(vol):
        raise ExtError(f"the group descriptor table ({count} groups at byte {at}) is past the end of the bytes")
    out = []
    for g in range(count):
        d = at + g * sb.descriptor_size
        bitmap, table = struct.unpack_from("<I", vol, d)[0], struct.unpack_from("<I", vol, d + 8)[0]
        flags = struct.unpack_from("<H", vol, d + 0x12)[0]
        if wide:
            bitmap |= struct.unpack_from("<I", vol, d + 0x20)[0] << 32
            table |= struct.unpack_from("<I", vol, d + 0x28)[0] << 32
        out.append(_Group(bitmap, table, flags))
    return out


def allocation_bitmap(vol: bytes, sb, first_data_block: int, groups: list, notes: list) -> list[bool]:
    """One bool per block present in the bytes, True = in use (or not readable, so never carved). The list
    stops at the last whole block of the bytes: blocks the superblock declares past it (a truncated
    image, or a crafted blocks_count) count as in use and are never materialised, so the cost follows
    the bytes handed in, not the count the handout claims."""
    bs, bpg = sb.block_size, sb.blocks_per_group
    present = min(sb.blocks_count, len(vol) // bs)
    if present < sb.blocks_count:
        notes.append(f"the bytes end at block {present} of {sb.blocks_count}: the rest is not carved")
    used = [True] * present
    csum = sb.features_ro_compat & (RO_COMPAT_GDT_CSUM | RO_COMPAT_METADATA_CSUM)
    for g, grp in enumerate(groups):
        base = first_data_block + g * bpg
        n = min(bpg, present - base)
        if n <= 0:
            break
        if csum and grp.flags & BG_BLOCK_UNINIT:
            for i in range(n):
                used[base + i] = False
            continue
        at = grp.block_bitmap * bs
        if not grp.block_bitmap or at + (n + 7) // 8 > len(vol):
            notes.append(f"group {g}: its block bitmap (block {grp.block_bitmap}) is outside the bytes; "
                         f"its blocks are not carved")
            continue
        bits = vol[at:at + (n + 7) // 8]
        for i in range(n):
            used[base + i] = bool(bits[i >> 3] & (1 << (i & 7)))
    return used


def _inode_bytes(vol: bytes, sb, groups: list, ino: int) -> bytes | None:
    g, i = divmod(ino - 1, sb.inodes_per_group)
    if not 1 <= ino <= sb.inodes_count or g >= len(groups):
        return None
    at = groups[g].inode_table * sb.block_size + i * sb.inode_size
    raw = vol[at:at + sb.inode_size]
    return raw if len(raw) == sb.inode_size else None


def _content(vol: bytes, sb, raw: bytes, budget) -> tuple[bytes | None, str]:
    """(bytes, '') of an inode, or (None, why)."""
    if struct.unpack_from("<I", raw, 32)[0] & FLAG_INLINE_DATA:
        return None, "inline data is not read here"
    size = struct.unpack_from("<I", raw, 4)[0] | (struct.unpack_from("<I", raw, 108)[0] << 32
                                                  if len(raw) >= 112 else 0)
    if budget is not None and not budget(size):
        return None, f"{size} bytes: over the walk's budget"
    di = _di()
    try:
        got = di.recover_ext_inode(bytes(raw), vol, block_size=sb.block_size)
    except (di.DiskImageError, ValueError, struct.error, MemoryError) as e:
        return None, f"its blocks do not read: {e}"
    return got["data"], ""


def _dir_entries(data: bytes, block_size: int, filetype: bool):
    for base in range(0, len(data), block_size):
        pos, end = base, min(base + block_size, len(data))
        while pos + 8 <= end:
            ino, rec_len = struct.unpack_from("<IH", data, pos)
            name_len = data[pos + 6] if filetype else struct.unpack_from("<H", data, pos + 6)[0]
            if rec_len < 8 or pos + rec_len > end or 8 + name_len > rec_len:
                break
            if ino and name_len:
                yield ino, data[pos + 8:pos + 8 + name_len].decode("utf-8", "replace")
            pos += rec_len


def _mtime(raw: bytes) -> int:
    return struct.unpack_from("<I", raw, 16)[0]


def read_volume(data: bytes, offset: int = 0, how: str = "bare", *, budget=None,
                kinds=CARVE_KINDS) -> ExtVolume:
    """Walk the ext volume at `offset`. `budget(size) -> bool` is asked before a file's bytes are kept
    (the sweep passes the walk's take); None keeps everything."""
    fsd = _fsd()
    sb = fsd.parse_ext_superblock(data[offset:offset + 2048])
    if sb is None:
        raise ExtError(f"no valid ext superblock at byte {offset + 1024}")
    if sb.features_incompat & INCOMPAT_META_BG:
        raise ExtError("meta_bg group descriptor layout is not read here (debugfs/sleuthkit can)")
    first_data_block = struct.unpack_from("<I", data, offset + 1024 + 20)[0]
    if first_data_block not in (0, 1) or (first_data_block == 1) != (sb.block_size == 1024):
        raise ExtError(f"first data block {first_data_block} does not fit block size {sb.block_size}")
    vol = memoryview(data)[offset:offset + sb.blocks_count * sb.block_size]
    groups = _groups(vol, sb, first_data_block)
    v = ExtVolume(offset, how, sb.block_size, sb.blocks_count, first_data_block, sb.volume_name, len(groups))
    filetype = bool(sb.features_incompat & INCOMPAT_FILETYPE)

    # the tree, from the root (inode 2)
    seen, queue, entries = {2}, [(2, "", 0)], 0
    while queue:
        ino, prefix, depth = queue.pop(0)
        raw = _inode_bytes(vol, sb, groups, ino)
        if raw is None:
            v.notes.append(f"directory inode {ino} ({prefix or '/'}) is outside the inode tables")
            continue
        body, why = _content(vol, sb, raw, None)
        if body is None:
            v.notes.append(f"directory {prefix or '/'} (inode {ino}) not read: {why}")
            continue
        for child, name in _dir_entries(body, sb.block_size, filetype):
            if name in (".", "..") or child in seen:
                continue
            entries += 1
            if entries > MAX_DIR_ENTRIES:
                v.notes.append(f"stopped after {MAX_DIR_ENTRIES} directory entries")
                queue.clear()
                break
            seen.add(child)
            craw = _inode_bytes(vol, sb, groups, child)
            path = f"{prefix}/{name}" if prefix else name
            if craw is None:
                v.notes.append(f"{path}: inode {child} is outside the inode tables")
                continue
            mode = struct.unpack_from("<H", craw, 0)[0]
            if mode & S_IFMT == S_IFDIR:
                if depth + 1 < MAX_DEPTH:
                    queue.append((child, path, depth + 1))
                else:
                    v.notes.append(f"{path}: deeper than {MAX_DEPTH} directories, not walked")
            elif mode & S_IFMT == S_IFREG:
                f = _file(vol, sb, craw, child, path, budget)
                v.files.append(f)

    # orphans: inodes with a mode that no walked directory names (deleted files keep mode and mtime)
    scanned = 0
    for g, grp in enumerate(groups):
        if scanned >= MAX_INODES:
            v.notes.append(f"orphan scan stopped after {MAX_INODES} inodes")
            break
        if sb.features_ro_compat & (RO_COMPAT_GDT_CSUM | RO_COMPAT_METADATA_CSUM) and grp.flags & 0x1:
            continue                  # INODE_UNINIT: this group's inode table was never written
        for i in range(sb.inodes_per_group):
            ino = g * sb.inodes_per_group + i + 1
            scanned += 1
            if ino > sb.inodes_count or scanned > MAX_INODES:
                break
            if ino in seen or ino < 11:
                continue
            raw = _inode_bytes(vol, sb, groups, ino)
            if raw is None:
                break
            mode = struct.unpack_from("<H", raw, 0)[0]
            if mode & S_IFMT != S_IFREG:
                continue
            v.orphans.append(_file(vol, sb, raw, ino, f"inode-{ino}", budget))

    # the free blocks, joined in block order, carved
    used = allocation_bitmap(vol, sb, first_data_block, groups, v.notes)
    v.free_blocks = used.count(False)
    v.carves = _carve_free(vol, sb.block_size, used, kinds, v.notes)
    return v


def _file(vol, sb, raw: bytes, ino: int, path: str, budget) -> ExtFile:
    mode = struct.unpack_from("<H", raw, 0)[0]
    size = struct.unpack_from("<I", raw, 4)[0] | (struct.unpack_from("<I", raw, 108)[0] << 32
                                                  if len(raw) >= 112 else 0)
    dtime, links = struct.unpack_from("<I", raw, 20)[0], struct.unpack_from("<H", raw, 26)[0]
    f = ExtFile(ino, path, mode, size, _mtime(raw), deleted=bool(dtime or links == 0))
    f.data, f.why = _content(vol, sb, raw, budget)
    if f.data is not None and f.deleted and size and not any(f.data):
        f.data, f.why = None, "deleted: its blocks read as zeros (extents cleared)"
    return f


def _carve_free(vol, block_size: int, used: list, kinds, notes: list) -> list[Carve]:
    runs, stream, at = [], bytearray(), 0           # runs: (stream offset, first block, count)
    b = 0
    while b < len(used):
        if used[b]:
            b += 1
            continue
        first = b
        while b < len(used) and not used[b]:
            b += 1
        runs.append((len(stream), first, b - first))
        stream += vol[first * block_size:b * block_size]
    if not stream:
        return []
    cv = _carving()
    out, seen = [], set()
    starts = range(0, max(1, len(stream) - WINDOW + STEP), STEP) if len(stream) > WINDOW else (0,)
    for start in starts:
        window = bytes(stream[start:start + WINDOW])
        if tuple(kinds) == ("elf",) and b"\x7fELF" not in window:
            continue
        for obj in cv.carve_all(window, kinds=kinds):
            off = start + obj.offset
            if off in seen:
                continue
            seen.add(off)
            out.append(Carve(obj.kind, off, len(obj.data), _blocks_of(runs, off, len(obj.data), block_size),
                             obj.data))
    if len(stream) > WINDOW:
        notes.append(f"free blocks hold {len(stream)} bytes: carved in {WINDOW >> 20} MiB windows; an object "
                     f"over {(WINDOW - STEP) >> 20} MiB that crosses a window edge is missed")
    return sorted(out, key=lambda c: c.stream_offset)


def _blocks_of(runs, off: int, size: int, block_size: int) -> list:
    out, end = [], off + size
    for s, first, count in runs:
        e = s + count * block_size
        if e <= off or s >= end:
            continue
        lo, hi = max(s, off), min(e, end)
        out.append((first + (lo - s) // block_size, -(-(hi - s) // block_size) - (lo - s) // block_size))
    return out


def _iso(t: int) -> str:
    return _dt.datetime.fromtimestamp(t, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def carve_name(c: Carve) -> str:
    return f"{CARVE_DIR}/blk{c.first_block:08d}.{c.kind}"


def listing(vol: ExtVolume) -> str:
    """The volume as JSON: what the ransomware keystream engine reads mtimes from."""
    def row(f: ExtFile) -> dict:
        return {"path": f.path, "inode": f.inode, "mode": oct(f.mode), "size": f.size, "mtime": f.mtime,
                "mtime_utc": _iso(f.mtime), "deleted": f.deleted, "exported": f.data is not None,
                **({"why": f.why} if f.why else {})}
    doc = {"schema": 1, "filesystem": "ext", "offset": vol.offset, "how": vol.how, "block_size": vol.block_size,
           "blocks": vol.blocks_count, "free_blocks": vol.free_blocks, "volume_name": vol.volume_name,
           "files": [row(f) for f in vol.files], "orphans": [row(f) for f in vol.orphans],
           "unallocated_carves": [{"name": carve_name(c), "kind": c.kind, "size": c.size,
                                   "blocks": [list(r) for r in c.blocks]} for c in vol.carves],
           "notes": vol.notes}
    return json.dumps(doc, indent=1) + "\n"
