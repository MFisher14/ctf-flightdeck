"""Recovery the archive walk does not do (B-029): files of a disk image, deleted ones included, and both
sides of a tracked-change Word document. The sweep (ctf/sweep.py) adds what this gives as members, so the
flag search, the manifest and triage cover them, and the archive walk opens them in turn.

    members = cascade(rows, walk, notes, archive_expand)   # [(chain, bytes)] beyond the archive walk
    derive(chain, data, walk, notes)                        # [(sub-chain, bytes, open it?)] of one content

What one content gives:

- A disk container (QCOW2, VHD, VHDX, sparse VMDK, EWF1/E01) -> `<name>.raw`, the raw disk, through
  solvers/toolkits/disk_images.py (checked tables; a decline is a note).
- An NTFS volume, bare or in an MBR/GPT partition (ctf/recover/ntfs.py) -> `ntfs-listing.txt` (every
  file and stream, deleted ones and reasons included) and every exportable file as `deleted/<path>` or
  `allocated/<path>` (an ADS as `<path>:<stream>`), each opened by the archive walk in turn. A partition
  prefixes them with `mbr-p1/` or `gpt-p2/`. A file whose clusters were reused is still exported; the
  listing says so.
- An ext2/3/4 volume, bare or in an MBR/GPT partition (ctf/recover/extfs.py, B-135) -> `ext-listing.json`
  (every file with inode and mtime, orphan inodes, the free-block carves), every file as `ext/<path>`, an
  orphan inode whose blocks still read as `ext/orphan/inode-<n>`, and every validated ELF carved from the
  blocks the block bitmap marks free as `ext-unallocated/blk<N>.elf` (B-011 decompiles those).
- A .docx (ctf/recover/ooxml.py) -> `tracked-changes/accepted.txt`, `original.txt`, `deletions.txt`,
  `insertions.txt` (or `text.txt` with no tracked change): text joined across runs.
- A `socat -v -x` serial log (B-076, solvers/toolkits/serial_capture.py) -> each XMODEM transfer it
  carried as `socat/xmodem-<n>.<ext>` (ACKed blocks, 0x1A padding trimmed), or, with no transfer, each
  direction's bytes as `socat/stream-gt.bin` / `socat/stream-lt.bin`; each opened by the archive walk.

Every member counts against the walk's budgets (`Walk.take`); derivations nest at most DEPTH deep (a member
made at that depth is kept and searched, and noted as not derived further). A content that looks like an
image or a document and does not read is a note, never silent; so is any decoder failure on hostile bytes
(`cascade` names it and goes on with the next content).
"""
from __future__ import annotations

from .. import paths as _paths
from ..packs import load_module as _load_module
from . import extfs, ntfs, ooxml, xorcrib

__all__ = ["cascade", "derive", "extfs", "ntfs", "ooxml", "xorcrib", "DEPTH"]

DEPTH = 4                            # image -> file -> archive member -> document views
_CONTAINER_MAGIC = (b"QFI\xfb", b"vhdxfile", b"EVF\t\r\n\xff\x00", b"LVF\t\r\n\xff\x00", b"KDMV")
_EWF2_MAGIC = (b"EVF2\r\n\x81\x00", b"LEF2\r\n\x81\x00")


def _disk_images():
    rel = "solvers/toolkits/disk_images.py"
    return _load_module("ctf_recover_disk_images", _paths.repo_root() / rel, pack=rel)


def _serial_capture():
    rel = "solvers/toolkits/serial_capture.py"
    return _load_module("ctf_recover_serial_capture", _paths.repo_root() / rel, pack=rel)


def _socat_head(data: bytes) -> bool:
    """A cheap first look (no pack loaded): the content opens with a socat record direction mark."""
    return bytes(data[:64]).lstrip()[:2] in (b"> ", b"< ")


def _label(chain: tuple) -> str:
    return " -> ".join(chain)


def _container(data: bytes) -> bool:
    return data.startswith(_CONTAINER_MAGIC) or (len(data) >= 512 and data[-512:-504] == b"conectix")


def _take(walk, key: str, size: int) -> bool:
    return walk is None or walk.take(key, size)


def derive(chain: tuple, data: bytes, walk, notes: list) -> list[tuple[tuple, bytes, bool]]:
    """[(sub-chain, bytes, open_it)] that one content gives up: open_it is True for a file out of an image
    (the archive walk should open it), False for derived text."""
    out = []
    where = _label(chain)
    if data.startswith(_EWF2_MAGIC):
        notes.append(f"{where}: an EWF2 (Ex01) image is not decoded here: export it to raw with ewfexport")
    elif _container(data):
        di = _disk_images()
        try:
            res = di.unwrap(data)
        except (di.DiskImageError, ValueError, MemoryError) as e:
            notes.append(f"{where}: a disk container that does not unwrap: {e}")
        else:
            if res.raw is None:
                notes.append(f"{where}: {res.format} not unwrapped: {'; '.join(res.diagnostics)}")
            elif _take(walk, f"{where} -> {chain[-1]}.raw", len(res.raw)):
                out.append(((f"{chain[-1]}.raw",), res.raw, True))
        return out
    if _socat_head(data):
        sc = _serial_capture()
        if sc.looks_like_socat(data):
            got, more = sc.members(data)
            notes.extend(f"{where}: {n}" for n in more)
            for name, body, opens in got:
                if _take(walk, f"{where} -> {name}", len(body)):
                    out.append(((name,), body, opens))
            return out
    if ooxml.is_docx(data):
        try:
            v = ooxml.views(data)
        except ooxml.OoxmlError as e:
            notes.append(f"{where}: a Word document whose text does not read: {e}")
        else:
            notes.extend(f"{where}: {n}" for n in v.notes)
            for name, body in v.files():
                if _take(walk, f"{where} -> {name}", len(body)):
                    out.append(((name,), body, False))
        return out
    for offset, how in ntfs.find_volumes(data):
        try:
            vol = ntfs.read_volume(data, offset, how)
        except ntfs.NtfsError as e:
            notes.append(f"{where}: {e}")
            continue
        prefix = "" if how == "bare" else how.replace(" ", "-") + "/"
        listing = ntfs.listing(vol).encode()
        if _take(walk, f"{where} -> {prefix}ntfs-listing.txt", len(listing)):
            out.append(((f"{prefix}ntfs-listing.txt",), listing, False))
        exported = 0
        for f in vol.files:
            if f.directory or f.system or not f.data:
                continue
            name = f"{prefix}{'deleted' if f.deleted else 'allocated'}/{f.path}"
            if not _take(walk, f"{where} -> {name}", len(f.data)):
                continue                     # over the member limit, or the budget is spent (noted once)
            out.append(((name,), f.data, True))
            exported += 1
        dele = vol.deleted
        notes.append(f"{where}: NTFS volume at offset {offset} ({how}): {len(vol.files)} entries, "
                     f"{len(dele)} deleted file(s) ({sum(f.overwritten for f in dele)} with reused clusters), "
                     f"{exported} exported")
        notes.extend(f"{where}: {n}" for n in vol.notes)
    try:
        out.extend(_ext_members(data, where, walk, notes))
    except Exception as e:           # hostile bytes: a broken ext read keeps what NTFS already gave up
        notes.append(f"{where}: ext volume read failed, its members are not read ({type(e).__name__}: {e})")
    return out


def _ext_members(data: bytes, where: str, walk, notes: list) -> list[tuple[tuple, bytes, bool]]:
    """B-135: an ext2/3/4 volume -> `ext-listing.json` (paths, inodes, mtimes, orphans, carves), every
    file as `ext/<path>`, a deleted inode no directory names as `ext/orphan/inode-<n>` when its blocks
    still read, and each validated ELF in the free blocks as `ext-unallocated/blk<N>.elf`, which
    B-011's decompile intake picks up from the sweep's scratch copy."""
    out = []
    for offset, how in extfs.find_volumes(data):
        prefix = "" if how == "bare" else how.replace(" ", "-") + "/"
        try:
            vol = extfs.read_volume(data, offset, how,
                                    budget=lambda size: walk is None or size <= walk.max_member)
        except extfs.ExtError as e:
            notes.append(f"{where}: ext volume at offset {offset} ({how}): {e}")
            continue
        listing = extfs.listing(vol).encode()
        if _take(walk, f"{where} -> {prefix}{extfs.LISTING}", len(listing)):
            out.append(((f"{prefix}{extfs.LISTING}",), listing, False))
        exported = 0
        for f in vol.files + vol.orphans:
            if f.data is None:
                continue
            name = f"{prefix}ext/{'orphan/' if f.path.startswith('inode-') else ''}{f.path}"
            if _take(walk, f"{where} -> {name}", len(f.data)):
                out.append(((name,), f.data, True))
                exported += 1
        carved = 0
        for c in vol.carves:
            name = prefix + extfs.carve_name(c)
            if _take(walk, f"{where} -> {name}", len(c.data)):
                out.append(((name,), c.data, False))
                carved += 1
        notes.append(f"{where}: ext volume at offset {offset} ({how}): {len(vol.files)} file(s), "
                     f"{len(vol.orphans)} orphan inode(s), {exported} exported, {vol.free_blocks} free "
                     f"block(s), {carved} object(s) carved from them ({', '.join(extfs.CARVE_KINDS)})")
        notes.extend(f"{where}: {n}" for n in vol.notes)
    return out


def cascade(rows, walk, notes: list, archive_expand) -> list[tuple[tuple, bytes]]:
    """[(chain, bytes)] that `rows` ([(chain, bytes)], the archive walk's output for one original) give up
    beyond the walk: derived members, and the archive walk over each file out of an image, recursively."""
    out = []
    queue = [(tuple(c), bytes(b), 0) for c, b in rows]      # nothing is queued at level DEPTH or deeper
    while queue:
        chain, body, level = queue.pop(0)
        try:
            got = derive(chain, body, walk, notes)
        except Exception as e:       # hostile bytes: one content that breaks a decoder never stops the sweep
            notes.append(f"{_label(chain)}: recovery failed on this content, its derived members are not "
                         f"read ({type(e).__name__}: {e})")
            continue
        for sub, data, opens in got:
            full = chain + sub
            out.append((full, data))
            nested = [(full, data)]
            if opens:
                archive_expand.expand(sub[-1], data, {}, opts=walk)
                for c, _key, b in (walk.rows or [])[1:]:
                    member = (full + tuple(c)[1:], bytes(b))
                    out.append(member)
                    nested.append(member)
                walk.rows = None
            if level + 1 >= DEPTH:
                notes.append(f"{_label(full)}: not searched for further images or documents (derivation "
                             f"depth limit {DEPTH})")
                continue
            queue.extend((c, b, level + 1) for c, b in nested)
    return out
