#!/usr/bin/env python3
"""Toolkit fs_walk: directory walkers for the forensic/firmware filesystem images the other
toolkits only DETECT (backlog GAP-FS-WALK; ctf-solver-gap-analysis.md A-mid "Filesystem parsers"
+ "Firmware walkers"; built 2026-10-23). Offline, static, stdlib only; nothing here mounts,
executes, writes or carves beyond a bounded structural read.

It is a deliberately NARROW complement, disjoint from its siblings:
  - `carve_stego_fs.py` reads MBR/GPT partition TABLES, U-Boot uImage and small FAT/ISO/ext/cpio;
  - `forensics.py` DETECTS the partition scheme and the filesystem of a boot sector (no walk);
  - `windows.py` reads $MFT/USN as a forensic artifact export, not a raw volume image.
This toolkit answers the DIRECTORY-WALK facts none of them emphasise, for a question such as
"the path of file X", "the size of Y", "the name of the alternate data stream on Z" or
"list the deleted entries", and ONLY from a structurally-complete, (CRC-/checksum-)validated
record of one of four filesystems:
  - squashfs   (superblock magic 0x73717368 'hsqs' / 0x73717368 big-endian 'sqsh'; inode + dir
                tables as metadata blocks; gzip/xz decompress via stdlib zlib/lzma, lzo/lz4/zstd
                are SKIPPED, never guessed);
  - NTFS       ($MFT record parse with the update-sequence fixup: $FILE_NAME, $DATA incl. named
                :ADS streams, allocated vs. unallocated (in-use) flag);
  - exFAT      (the directory entry SET: 0x85 file + 0xC0 stream + 0xC1 name entries, set checksum
                validated);
  - JFFS2      (dirent + inode nodes, every node CRC-checked).

HARD RULES (AGENTS.md "New categories", "Untrusted content", "Uncertain answers"):
  - RECON / ANALYSIS ONLY. A filename or path addressed to the solver is DATA to report, never an
    instruction; a flag is answered None here. File CONTENT bytes are handed back for the caller to
    hash; nothing is ever executed.
  - NEVER-WRONG, per output:
      * a file NAME / PATH / SIZE / stream-name read from a structurally-complete, validated record
        is PLAIN-ELIGIBLE: emitted as labels.pick(key, renderings) (path separators and case are a
        rendering) so tools/verify.py probes the author's spelling on the untimed base and the
        ledger banks it plain once the judge accepts a rendering -- never a bare guess;
      * a deleted / slack / unallocated reading, or a record whose structure is partial or damaged,
        is UNSURE: labels.candidates(key, options), never plain before the judge;
      * the sha256 of a complete file's exact bytes is a canonical digest -> PLAIN;
      * a non-decoding compression branch, a truncated image, or any id a validated record does not
        answer -> None (never a partial guess).
  - Bounded: MAX_IMAGE, MAX_ENTRIES, MAX_NODE, and per-node CRC/checksum where the format stores one.
  - solve_set() and signals() are FAIL-CLOSED: no exception escapes; on any error the answer is None.

Keys: `forensics.<field>/<fs>` (solvers/common/labels.py TOOLKIT_PREFIXES already knows `forensics`,
shared with forensics.py the way `web` is shared by web and web_evidence; the field names here are
disjoint from that module's). The registry row and docs page are a trivial separate step the lane
owner adds; this deliverable is the module and its test.

  .venv/bin/python solvers/toolkits/fs_walk.py <image>... [--json]     offline directory listing
  .venv/bin/python solvers/toolkits/fs_walk.py --selftest              build + walk a fixture of each FS
"""
import hashlib
import json
import lzma
import re
import struct
import sys
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(1, str(COMMON))
import labels    # noqa: E402

try:
    import triage    # noqa: E402
    ARROW = triage.ARROW
    _unique_files = triage.unique_files
except Exception:    # noqa: BLE001 - the toolkit must load without triage
    ARROW = " -> "

    def _unique_files(files):
        seen, out = set(), []
        for k in sorted(files or {}):
            v = files[k]
            if isinstance(v, (bytes, bytearray)) and id(v) not in seen:
                seen.add(id(v))
                out.append((k, bytes(v)))
        return out

KEY = "forensics"
MAX_IMAGE = 256 * 1024 * 1024    # an image larger than this is not walked (bounded time)
MAX_ENTRIES = 4096               # entries emitted per image
MAX_NODE = 16 * 1024 * 1024      # a single file/node's bytes read
META_MAX = 1 << 20               # cap on a decompressed metadata region
SECTOR_HINT = 512


class _Unsupported(Exception):
    """A compression branch stdlib cannot decode: the affected bytes are None, never guessed."""


class _Truncated(Exception):
    """The image ended inside a structure: the affected record is partial."""


def _entry(name, path, size, kind="file", deleted=False, slack=False, stream=None,
           content=None, complete=True, crc_ok=None, fs=None) -> dict:
    """One walked entry. `complete` is True only for a structurally whole, validated record; a
    PLAIN-eligible fact is emitted only from such a record. `deleted`/`slack` force UNSURE."""
    return {"name": name, "path": path, "size": size, "kind": kind, "deleted": bool(deleted),
            "slack": bool(slack), "stream": stream, "content": content,
            "complete": bool(complete) and not deleted and not slack, "crc_ok": crc_ok, "fs": fs}


# ============================================================================ CRC (JFFS2)

def _jffs2_crc(data: bytes, val: int = 0) -> int:
    """JFFS2's node CRC: the raw reflected CRC-32 (poly 0xEDB88320) with register init `val` and NO
    pre/post inversion, as the kernel's crc32(val, buf, len) computes it. Expressed through zlib:
    raw_crc(init, d) == zlib.crc32(d, init ^ 0xffffffff) ^ 0xffffffff."""
    return zlib.crc32(data, (val ^ 0xFFFFFFFF) & 0xFFFFFFFF) ^ 0xFFFFFFFF & 0xFFFFFFFF


# ============================================================================ squashfs

SQUASHFS_MAGIC_LE = b"hsqs"       # 0x73717368 little-endian
SQUASHFS_MAGIC_BE = b"sqsh"       # big-endian image
_SQFS_COMP = {1: "gzip", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd"}


def is_squashfs(data: bytes) -> bool:
    return len(data) >= 96 and data[:4] in (SQUASHFS_MAGIC_LE, SQUASHFS_MAGIC_BE)


def _sqfs_decompress(payload: bytes, comp: int) -> bytes:
    if comp == 1:                                   # gzip (zlib stream)
        try:
            return zlib.decompress(payload)
        except zlib.error as e:
            raise _Truncated(f"invalid squashfs zlib data: {e}") from e
    if comp in (2, 4):                              # lzma / xz
        try:
            return lzma.decompress(payload)
        except lzma.LZMAError:
            # raw-lzma-alone streams need an explicit filter; try the common squashfs form
            try:
                return lzma.decompress(payload, format=lzma.FORMAT_ALONE)
            except lzma.LZMAError as e:
                raise _Unsupported(f"lzma: {e}") from e
    raise _Unsupported(f"squashfs compressor {_SQFS_COMP.get(comp, comp)} is not in stdlib")


def _sqfs_meta_block(data: bytes, off: int, comp: int, endian: str):
    """Return (payload bytes, next offset) for one metadata block. Top bit of the 2-byte header
    means stored uncompressed; otherwise decompress with the superblock's compressor."""
    if off + 2 > len(data):
        raise _Truncated("metadata header")
    hdr = struct.unpack_from(endian + "H", data, off)[0]
    size = hdr & 0x7FFF
    uncompressed = bool(hdr & 0x8000)
    start = off + 2
    if size == 0 or start + size > len(data):
        raise _Truncated("metadata body")
    chunk = data[start:start + size]
    payload = chunk if uncompressed else _sqfs_decompress(chunk, comp)
    return payload, start + size


def _sqfs_read_region(data: bytes, start: int, end: int, comp: int, endian: str):
    """Concatenate the metadata blocks of a table region, recording each on-disk block's relative
    start -> its position in the decompressed buffer (inode refs index by that)."""
    buf = bytearray()
    offsets = {}
    off = start
    while off < end and len(buf) < META_MAX:
        offsets[off - start] = len(buf)
        payload, off = _sqfs_meta_block(data, off, comp, endian)
        buf += payload
    return bytes(buf), offsets


def squashfs(data: bytes):
    """Walk a squashfs 4.0 image. Returns (ok_complete, [entry]); ok_complete is False when a
    branch did not decode (unsupported compression / truncation): its entries are omitted and the
    caller answers None for them. Returns None when the bytes are not squashfs."""
    if not is_squashfs(data) or len(data) > MAX_IMAGE:
        return None
    endian = "<" if data[:4] == SQUASHFS_MAGIC_LE else ">"
    try:
        (inode_count, _mtime, block_size, _frag_count, comp, block_log, _flags, _id_count,
         ver_major, _ver_minor) = struct.unpack_from(endian + "IIIIHHHHHH", data, 4)
        root_ref, bytes_used, id_tbl, _xattr_tbl, inode_tbl, dir_tbl, frag_tbl, _exp_tbl = \
            struct.unpack_from(endian + "QQQQQQQQ", data, 32)
    except struct.error:
        return None
    if ver_major != 4 or block_size != (1 << block_log):
        return None
    complete = True
    entries = []
    try:
        inode_end = min(dir_tbl or bytes_used, bytes_used, len(data))
        dir_end_candidates = [t for t in (frag_tbl, id_tbl, bytes_used) if t and t > dir_tbl]
        dir_end = min([*dir_end_candidates, len(data)]) if dir_tbl else len(data)
        inode_buf, inode_off = _sqfs_read_region(data, inode_tbl, inode_end, comp, endian)
        dir_buf, dir_off = _sqfs_read_region(data, dir_tbl, dir_end, comp, endian)
    except (_Unsupported, _Truncated, struct.error):
        return False, []     # the inode/dir table itself did not decode: nothing is proven
    seen_refs = set()

    def inode_pos(ref):
        blk = (ref >> 16) & 0xFFFFFFFFFFFF
        ofs = ref & 0xFFFF
        if blk not in inode_off:
            raise _Truncated("inode ref")
        return inode_off[blk] + ofs

    def parse_inode(pos):
        if pos + 16 > len(inode_buf):
            raise _Truncated("inode header")
        itype, _perm, _uid, _gid, _mt, inum = struct.unpack_from(endian + "HHHHII", inode_buf, pos)
        body = pos + 16
        return itype, inum, body

    def read_file_content(blocks_start, file_size, bs_list):
        out = bytearray()
        pos = blocks_start
        for raw in bs_list:
            bsize = raw & 0xFFFFFF
            uncompressed = bool(raw & 0x1000000)
            if bsize == 0:
                # Zero block sizes encode sparse logical blocks and consume no
                # physical bytes. The last block may be shorter than block_size.
                out += bytes(max(0, min(block_size, file_size - len(out), MAX_NODE - len(out))))
                if len(out) >= MAX_NODE:
                    break
                continue
            if pos + bsize > len(data):
                raise _Truncated("file block")
            blk = data[pos:pos + bsize]
            out += blk if uncompressed else _sqfs_decompress(blk, comp)
            pos += bsize
            if len(out) >= MAX_NODE:
                break
        return bytes(out[:file_size])

    def walk(ref, prefix, depth):
        nonlocal complete
        if depth > 32 or len(entries) >= MAX_ENTRIES or ref in seen_refs:
            return
        seen_refs.add(ref)
        itype, _inum, body = parse_inode(inode_pos(ref))
        if itype != 1:              # a non-directory root is unusual; nothing to list
            return
        # basic directory inode: block_index, link_count, file_size(u16), block_offset(u16), parent
        dblk, _links, dsize, dofs, _parent = struct.unpack_from(endian + "IIHHI", inode_buf, body)
        if dblk not in dir_off:
            raise _Truncated("dir block")
        base = dir_off[dblk] + dofs
        listing = dir_buf[base:base + max(0, dsize - 3)]
        i = 0
        while i + 12 <= len(listing):
            count, hstart, hinode = struct.unpack_from(endian + "III", listing, i)
            i += 12
            for _ in range(count + 1):
                if i + 8 > len(listing):
                    raise _Truncated("dir entry")
                eofs, idelta, etype, nsize = struct.unpack_from(endian + "HhHH", listing, i)
                i += 8
                name = listing[i:i + nsize + 1]
                i += nsize + 1
                if len(name) < nsize + 1:
                    raise _Truncated("dir name")
                name = name.decode("utf-8", "replace")
                child_ref = (hstart << 16) | eofs
                path = prefix + "/" + name
                if etype == 1:                        # subdirectory
                    entries.append(_entry(name, path, None, kind="dir", fs="squashfs"))
                    try:
                        walk(child_ref, path, depth + 1)
                    except (_Unsupported, _Truncated):
                        complete = False
                elif etype == 2:                      # basic file
                    try:
                        _ft, _fin, fbody = parse_inode(inode_pos(child_ref))
                        bstart, frag_idx, _boff, fsize = struct.unpack_from(
                            endian + "IIII", inode_buf, fbody)
                        nblocks = (fsize + block_size - 1) // block_size if frag_idx in (
                            0xFFFFFFFF,) else max(0, fsize // block_size)
                        bs_list = list(struct.unpack_from(
                            endian + "%dI" % nblocks, inode_buf, fbody + 16)) if nblocks else []
                        content = None
                        if frag_idx in (0xFFFFFFFF,) and nblocks:
                            try:
                                content = read_file_content(bstart, fsize, bs_list)
                            except (_Unsupported, _Truncated):
                                content = None
                                complete = False
                        entries.append(_entry(name, path, fsize, kind="file",
                                              content=content, fs="squashfs"))
                    except (_Unsupported, _Truncated, struct.error):
                        complete = False
                else:
                    entries.append(_entry(name, path, None, kind="other", fs="squashfs"))

    try:
        walk(root_ref, "", 0)
    except (_Unsupported, _Truncated, struct.error):
        complete = False
    return complete, entries


# ============================================================================ NTFS ($MFT)

def _ntfs_fixup(record: bytes) -> bytes:
    """Apply the update-sequence fixup. Returns the corrected record, or raises _Truncated when the
    sector-end signatures do not all equal the USN (a damaged / partial record)."""
    if len(record) < 48 or record[:4] != b"FILE":
        raise _Truncated("not a FILE record")
    usa_off, usa_size = struct.unpack_from("<HH", record, 4)
    if usa_size == 0 or usa_off + usa_size * 2 > len(record):
        raise _Truncated("bad usa")
    usn = record[usa_off:usa_off + 2]
    out = bytearray(record)
    for j in range(1, usa_size):
        sector_end = j * 512 - 2
        orig = record[usa_off + j * 2:usa_off + j * 2 + 2]
        if sector_end + 2 > len(record):
            raise _Truncated("missing usa sector trailer")
        if bytes(record[sector_end:sector_end + 2]) != usn:
            raise _Truncated("usa mismatch")      # corrupted record
        out[sector_end:sector_end + 2] = orig
    return bytes(out)


def _ntfs_records(data: bytes):
    """Yield (record_number, raw 1024-or-sized record) from a buffer of $MFT records, or from a full
    NTFS volume (boot sector 'NTFS    ' at offset 3, $MFT located via the BPB)."""
    rec_size = 1024
    start = 0
    if data[3:11] == b"NTFS    " and len(data) >= 512:
        bps = struct.unpack_from("<H", data, 0x0B)[0] or 512
        spc = data[0x0D] or 1
        mft_cluster = struct.unpack_from("<Q", data, 0x30)[0]
        raw_rs = struct.unpack_from("<b", data, 0x40)[0]
        rec_size = (1 << (-raw_rs)) if raw_rs < 0 else raw_rs * bps * spc
        start = mft_cluster * spc * bps
    if rec_size <= 0 or rec_size > 1 << 20:
        rec_size = 1024
    n = 0
    pos = start
    while pos + 4 <= len(data) and n < MAX_ENTRIES:
        if data[pos:pos + 4] != b"FILE":
            # not a record here; if this is a raw $MFT it is the end, else step a record
            if pos == start and start != 0:
                break
            break
        yield n, data[pos:pos + rec_size]
        pos += rec_size
        n += 1


def _ntfs_parse_record(record: bytes):
    """{num_flags, names:[(parent, name, namespace)], datas:[(stream_name_or_None, size, content)]}
    for one fixed-up record, else None. Raises _Truncated for a damaged record."""
    rec = _ntfs_fixup(record)
    seq_flags = struct.unpack_from("<H", rec, 22)[0]
    first_attr = struct.unpack_from("<H", rec, 20)[0]
    used = struct.unpack_from("<I", rec, 24)[0]
    in_use = bool(seq_flags & 0x0001)
    is_dir = bool(seq_flags & 0x0002)
    names, datas = [], []
    off = first_attr
    limit = min(used if used and used <= len(rec) else len(rec), len(rec))
    while off + 4 <= limit:
        atype = struct.unpack_from("<I", rec, off)[0]
        if atype == 0xFFFFFFFF:
            break
        if off + 16 > limit:
            raise _Truncated("attr header")
        alen = struct.unpack_from("<I", rec, off + 4)[0]
        if alen < 16 or off + alen > len(rec):
            raise _Truncated("attr length")
        non_res = rec[off + 8]
        name_len = rec[off + 9]
        name_off = struct.unpack_from("<H", rec, off + 10)[0]
        aname = ""
        if name_len:
            aname = rec[off + name_off:off + name_off + name_len * 2].decode("utf-16-le", "replace")
        if atype == 0x30 and non_res == 0:                     # $FILE_NAME (always resident)
            coff = struct.unpack_from("<H", rec, off + 20)[0]
            fn = off + coff
            if fn + 66 <= off + alen:
                parent = struct.unpack_from("<Q", rec, fn)[0] & 0xFFFFFFFFFFFF
                nlen = rec[fn + 64]
                ns = rec[fn + 65]
                nm = rec[fn + 66:fn + 66 + nlen * 2].decode("utf-16-le", "replace")
                names.append((parent, nm, ns))
        elif atype == 0x80:                                    # $DATA (unnamed = file, named = ADS)
            stream = aname or None
            if non_res == 0:
                clen = struct.unpack_from("<I", rec, off + 16)[0]
                coff = struct.unpack_from("<H", rec, off + 20)[0]
                content = bytes(rec[off + coff:off + coff + clen])
                datas.append((stream, len(content), content))
            else:
                real = struct.unpack_from("<Q", rec, off + 48)[0]
                datas.append((stream, real, None))             # non-resident: size only
        off += alen
    return {"in_use": in_use, "is_dir": is_dir, "names": names, "datas": datas}


def _ntfs_best_name(names):
    """Prefer a Win32 / POSIX name (namespace 1 or 3 or 0) over the 8.3 DOS name (namespace 2)."""
    if not names:
        return None
    for parent, nm, ns in names:
        if ns in (0, 1, 3):
            return parent, nm
    return names[0][0], names[0][1]


def ntfs(data: bytes):
    """Walk $MFT records (raw $MFT, or a volume's $MFT via the boot sector). Returns
    (complete, [entry]); a file entry per unnamed $DATA, an ADS entry per named $DATA, and a
    deleted entry per record whose in-use bit is clear. Returns None when the bytes are not NTFS."""
    if len(data) < 4 or len(data) > MAX_IMAGE:
        return None
    if data[:4] != b"FILE" and data[3:11] != b"NTFS    ":
        return None
    recs = {}
    raw = {}
    for num, rec in _ntfs_records(data):
        raw[num] = rec
        try:
            recs[num] = _ntfs_parse_record(rec)
        except (_Truncated, struct.error):
            recs[num] = None            # damaged record: surfaced as partial below
    if not raw:
        return None
    complete = True

    def path_of(num, seen=None):
        seen = seen or set()
        info = recs.get(num)
        if not info or not info["names"] or num in seen:
            return None
        seen.add(num)
        parent, nm = _ntfs_best_name(info["names"])
        if num == 5 or nm == ".":                 # root
            return ""
        up = path_of(parent, seen)
        return ((up if up is not None else "") + "\\" + nm)

    entries = []
    for num in sorted(raw):
        info = recs.get(num)
        if info is None:                          # damaged -> one partial, unsure entry
            complete = False
            entries.append(_entry(f"<record {num}>", None, None, kind="file",
                                  deleted=False, slack=False, complete=False, crc_ok=False,
                                  fs="ntfs"))
            continue
        if not info["names"]:
            continue
        parent, nm = _ntfs_best_name(info["names"])
        if num == 5 or nm == ".":                 # skip the root itself
            continue
        path = path_of(num) or ("\\" + nm)
        kind = "dir" if info["is_dir"] else "file"
        deleted = not info["in_use"]
        main = [d for d in info["datas"] if d[0] is None]
        size = main[0][1] if main else None
        content = main[0][2] if main else None
        entries.append(_entry(nm, path, size, kind=kind, deleted=deleted,
                              content=content, crc_ok=True, fs="ntfs"))
        for stream, ssize, scontent in info["datas"]:
            if stream:                            # named :ADS stream
                entries.append(_entry(nm, path + ":" + stream, ssize, kind="file",
                                      stream=stream, deleted=deleted, content=scontent,
                                      crc_ok=True, fs="ntfs"))
    return complete, entries


# ============================================================================ exFAT

def _exfat_set_checksum(entries: bytes) -> int:
    """The EntrySetChecksum over the primary entry's 32 bytes (skipping its own checksum field at
    bytes 2-3) and every secondary entry, 16-bit rotate-add."""
    csum = 0
    for i, b in enumerate(entries):
        if i in (2, 3):
            continue
        csum = ((csum << 15) | (csum >> 1)) & 0xFFFF
        csum = (csum + b) & 0xFFFF
    return csum


def is_exfat(data: bytes) -> bool:
    return len(data) >= 512 and data[3:11] == b"EXFAT   "


def exfat(data: bytes):
    """Walk the exFAT root directory's entry sets. Returns (complete, [entry]); a file per 0x85 set,
    its name from the 0xC1 name entries and its size from the 0xC0 stream entry's DataLength, the
    in-use bit giving allocated vs. deleted, and the set checksum validated. Returns None when the
    bytes are not exFAT."""
    if not is_exfat(data) or len(data) > MAX_IMAGE:
        return None
    try:
        bps_shift = data[108]
        spc_shift = data[109]
        heap_off_sectors = struct.unpack_from("<I", data, 88)[0]
        root_cluster = struct.unpack_from("<I", data, 96)[0]
    except (struct.error, IndexError):
        return None
    if not (0 <= bps_shift <= 12) or spc_shift > 25:
        return None
    sector = 1 << bps_shift
    cluster = sector << spc_shift
    heap_off = heap_off_sectors * sector

    def cluster_off(n):
        return heap_off + (n - 2) * cluster

    root = cluster_off(root_cluster)
    if root < 0 or root >= len(data):
        return None
    complete = True
    entries = []
    pos = root
    end = min(len(data), root + cluster)          # one cluster of root; bounded
    while pos + 32 <= end and len(entries) < MAX_ENTRIES:
        etype = data[pos]
        if etype == 0x00:                         # end of directory
            break
        base = etype & 0x7F
        in_use = bool(etype & 0x80)
        if base == 0x05:                          # File Directory Entry (primary)
            sec_count = data[pos + 1]
            set_len = (sec_count + 1) * 32
            if pos + set_len > end:
                complete = False
                entries.append(_entry("<partial set>", None, None, deleted=not in_use,
                                      complete=False, crc_ok=False, fs="exfat"))
                break
            entset = data[pos:pos + set_len]
            stored = struct.unpack_from("<H", entset, 2)[0]
            valid = _exfat_set_checksum(entset) == stored
            is_dir = bool(struct.unpack_from("<H", entset, 4)[0] & 0x10)
            name_raw = bytearray()
            size = None
            valid_length = None
            first_cluster = None
            no_fat_chain = False
            name_len = 0
            so = 32
            while so + 32 <= set_len:
                sb = entset[so]
                sbase = sb & 0x7F
                if sbase == 0x40:                 # Stream Extension
                    flags = entset[so + 1]
                    no_fat_chain = bool(flags & 0x02)
                    name_len = entset[so + 3]
                    valid_length = struct.unpack_from("<Q", entset, so + 8)[0]
                    first_cluster = struct.unpack_from("<I", entset, so + 20)[0]
                    size = struct.unpack_from("<Q", entset, so + 24)[0]
                elif sbase == 0x41:               # File Name
                    name_raw += entset[so + 2:so + 32]
                so += 32
            name = bytes(name_raw[:name_len * 2] if name_len else name_raw).decode("utf-16-le", "replace")
            if not name_len:
                name = name.rstrip("\x00")
            if size is not None and (valid_length is None or valid_length > size):
                valid = False
            content = None
            if valid and in_use and first_cluster and no_fat_chain and size is not None:
                c_off = cluster_off(first_cluster)
                if 0 <= c_off and c_off + min(size, MAX_NODE) <= len(data):
                    take = min(size, MAX_NODE)
                    initialized = min(valid_length, take)
                    content = bytes(data[c_off:c_off + initialized]) + bytes(take - initialized)
            entries.append(_entry(name, "/" + name, size, kind="dir" if is_dir else "file",
                                  deleted=not in_use, content=content,
                                  complete=valid and in_use, crc_ok=valid, fs="exfat"))
            if not valid:
                complete = False
            pos += set_len
        else:
            pos += 32
    return complete, entries


# ============================================================================ JFFS2

JFFS2_MAGIC = 0x1985
JFFS2_DIRENT = 0xE001
JFFS2_INODE = 0xE002


def is_jffs2(data: bytes) -> bool:
    if len(data) < 4:
        return False
    for endian in ("<", ">"):
        if struct.unpack_from(endian + "H", data, 0)[0] == JFFS2_MAGIC:
            return True
    return False


def jffs2(data: bytes):
    """Walk JFFS2 dirent and inode nodes, every node's header CRC and node CRC checked. Returns
    (complete, [entry]); a node whose CRC fails is skipped and the walk continues (the affected
    entry is omitted, so the caller answers None). Returns None when the bytes are not JFFS2."""
    if not is_jffs2(data) or len(data) > MAX_IMAGE:
        return None
    endian = "<" if struct.unpack_from("<H", data, 0)[0] == JFFS2_MAGIC else ">"
    complete = True
    dirents = {}         # ino -> (pino, name, type, version)
    inode_size = {}      # ino -> (version, isize)
    inode_data = {}      # ino -> {offset: bytes}
    off = 0
    n = 0
    while off + 12 <= len(data) and n < MAX_ENTRIES * 4:
        try:
            magic, ntype, totlen, hdr_crc = struct.unpack_from(endian + "HHII", data, off)
        except struct.error:
            break
        if magic != JFFS2_MAGIC:
            # padding / erased region: step forward by 4 to the next node boundary
            off += 4
            continue
        if totlen < 12 or off + totlen > len(data):
            complete = False
            break
        node = data[off:off + totlen]
        if _jffs2_crc(node[:8]) != hdr_crc:
            complete = False
            off += ((totlen + 3) & ~3) or 4
            n += 1
            continue
        if ntype == JFFS2_DIRENT and totlen >= 40:
            pino, version, ino, _mctime, nsize, dtype = struct.unpack_from(endian + "IIIIBB", node, 12)
            node_crc = struct.unpack_from(endian + "I", node, 32)[0]
            name_crc = struct.unpack_from(endian + "I", node, 36)[0]
            name = node[40:40 + nsize]
            if _jffs2_crc(node[:32]) != node_crc or _jffs2_crc(name) != name_crc or len(name) < nsize:
                complete = False
            else:
                prev = dirents.get(ino)
                if prev is None or version >= prev[3]:
                    dirents[ino] = (pino, name.decode("utf-8", "replace"),
                                    dtype, version) if nsize else (pino, "", dtype, version)
        elif ntype == JFFS2_INODE and totlen >= 68:
            (ino, version, _mode, _uid, _gid, isize, _at, _mt, _ct, doff, csize, dsize,
             compr) = struct.unpack_from(endian + "IIIHHIIIIIIIB", node, 12)
            data_crc = struct.unpack_from(endian + "I", node, 60)[0]
            node_crc = struct.unpack_from(endian + "I", node, 64)[0]
            payload = node[68:68 + csize]
            if _jffs2_crc(node[:60]) != node_crc or (csize and _jffs2_crc(payload) != data_crc):
                complete = False
            else:
                prev = inode_size.get(ino)
                if prev is None or version >= prev[0]:
                    inode_size[ino] = (version, isize)
                if compr == 0 and csize == dsize:        # JFFS2_COMPR_NONE: raw data
                    inode_data.setdefault(ino, {})[doff] = payload[:dsize]
                elif compr == 6 and csize:               # JFFS2_COMPR_ZLIB
                    try:
                        inode_data.setdefault(ino, {})[doff] = zlib.decompress(payload)[:dsize]
                    except zlib.error:
                        complete = False                 # a data node that did not inflate: content None
                # other compressors (rtime/rubin/lzo) are not decoded -> content stays None
        off += (totlen + 3) & ~3                          # nodes are 4-byte aligned
        n += 1

    def path_of(ino, seen=None):
        seen = seen or set()
        d = dirents.get(ino)
        if not d or ino in seen:
            return None
        seen.add(ino)
        pino, name, _dt, _v = d
        if pino == 1 or pino == ino:                      # root's inode number is 1
            return "/" + name
        up = path_of(pino, seen)
        return (up if up is not None else "") + "/" + name

    entries = []
    for ino in sorted(dirents):
        pino, name, dtype, _v = dirents[ino]
        if not name:
            continue
        path = path_of(ino) or ("/" + name)
        kind = "dir" if dtype == 4 else "file"            # DT_DIR == 4
        size = inode_size.get(ino, (None, None))[1]
        content = None
        parts = inode_data.get(ino)
        if parts is not None and size is not None:
            buf = bytearray(size)
            ok = True
            for d_off, chunk in parts.items():
                if d_off + len(chunk) <= size:
                    buf[d_off:d_off + len(chunk)] = chunk
                else:
                    ok = False
            content = bytes(buf) if ok else None
        entries.append(_entry(name, path, size, kind=kind, content=content, crc_ok=True, fs="jffs2"))
    return complete, entries


# ============================================================================ dispatch

_WALKERS = (("squashfs", is_squashfs, squashfs), ("ntfs", lambda d: d[:4] == b"FILE" or d[3:11] == b"NTFS    ", ntfs),
            ("exfat", is_exfat, exfat), ("jffs2", is_jffs2, jffs2))


def walk(data: bytes):
    """(fs_name, complete, [entry]) for the first of the four filesystems the bytes are, else
    (None, None, []). Never raises."""
    if not isinstance(data, (bytes, bytearray)):
        return None, None, []
    data = bytes(data)
    for name, detect, fn in _WALKERS:
        try:
            if detect(data):
                res = fn(data)
                if res is not None:
                    complete, entries = res
                    return name, complete, entries
        except Exception:    # noqa: BLE001 - one format's failure never costs the dispatch
            continue
    return None, None, []


def listing(files) -> list:
    """[(display name, fs, complete, [entry])] for every delivery member that is one of the four
    filesystems. Bounded and fail-closed."""
    out = []
    try:
        for name, data in _unique_files(files or {}):
            try:
                fs, complete, entries = walk(data)
            except Exception:    # noqa: BLE001
                fs, complete, entries = None, None, []
            if fs:
                out.append((name, fs, complete, entries))
    except Exception:    # noqa: BLE001
        return []
    return out


# ============================================================================ signals

_WORDS = re.compile(
    r"squashfs|jffs2|\bntfs\b|\bexfat\b|firmware|\$mft|\bmft\b|alternate data stream|\bads\b|"
    r"file ?system|\bfs\b|directory|\bpath\b|deleted (?:file|entry|entries)|unallocated|\bslack\b|"
    r"inode|dirent|superblock|data stream|carved|image|partition", re.I)


def signals(questions, files) -> float:
    """0..1: one of the four walkable filesystems validates in the bytes, plus walk vocabulary in the
    questions. 0.0 when nothing walks, so it never competes on a blob, an e-mail or a pcap."""
    try:
        found = {fs for _n, fs, _c, _e in listing(files or {})}
    except Exception:    # noqa: BLE001
        found = set()
    if not found:
        return 0.0
    score = 0.5
    hits = set()
    for q in (questions or []):
        fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
        text = " ".join(str(x or "") for x in (q.get("question"), q.get("answer_id") or q.get("id"),
                                               fmt.get("syntax")))
        hits |= {m.group().lower() for m in _WORDS.finditer(text)}
    score += min(0.4, 0.1 * len(hits))
    return round(min(1.0, score), 2)


# ============================================================================ answers (never-guess)

def _path_renderings(path: str) -> list:
    """METHOD-NAMED renderings of a path a judge might expect (separators and case are a
    rendering). The name is the method (`posix`, `windows`, ...), the value is THIS variant's
    path under it -- never a bare label, so the method the judge accepts answers the next
    variant with that variant's own value and never a stale one (GAP Pattern-A fix)."""
    if not path:
        return []
    posix = "/" + path.strip("/\\").replace("\\", "/")
    bare = posix.lstrip("/")
    win = "\\" + bare.replace("/", "\\")
    base = posix.rsplit("/", 1)[-1]
    out, seen = [], set()
    for name, v in (("posix", posix), ("bare", bare), ("windows", win),
                    ("windows_bare", win.lstrip("\\")), ("basename", base)):
        if v and v not in seen:                # dedupe by value, keeping the first method
            seen.add(v)
            out.append((name, v))
    return out[:labels.MAX_OPTIONS]


def _name_renderings(name: str) -> list:
    """METHOD-NAMED renderings of a file/stream name (the method != the value, so labels never
    returns a stale accepted value plain on a later variant; GAP Pattern-A fix)."""
    if not name:
        return []
    out = [("as_is", name)]
    low = name.lower()
    if low != name:
        out.append(("lower", low))
    stem = name.rsplit(".", 1)[0]
    if stem and stem != name:
        out.append(("stem", stem))
    return out[:labels.MAX_OPTIONS]


def _size_renderings(size) -> list:
    """METHOD-NAMED renderings of a size (decimal/hex), the value varying per variant."""
    if size is None:
        return []
    try:
        n = int(size)
    except (TypeError, ValueError):
        return []
    out = [("decimal", str(n))]
    if n:
        out.append(("hex", hex(n)))
    return out


def _pick(field, fs, renderings):
    """A PLAIN-ELIGIBLE fact: labels.pick over its METHOD-NAMED renderings `[(method, value)]`
    (name=method, value varies per variant, mirroring pcap_creds.renderings /
    repo_supply_chain._path_forms / asn1_reader._hex_options). Because the name is never the
    value, labels' `labels_only` branch is False: once the judge accepts a method the pick
    returns THIS variant's value under that method, and a later variant whose value differs
    stays unsure rather than banking a stale accepted value plain (GAP Pattern-A fix). Unsure
    until the judge accepts a method, then plain. None when there is nothing to offer."""
    opts, seen = [], set()
    for name, value in renderings:
        value = "" if value is None else str(value)
        if value and (name, value) not in seen:
            seen.add((name, value))
            opts.append((name, value))
    if not opts:
        return None
    try:
        return labels.pick(f"{KEY}.{field}/{fs}", opts[:labels.MAX_OPTIONS])
    except ValueError:
        return None


def _candidates(field, fs, values):
    """A deleted / partial reading: labels.candidates over DIFFERENT evidence-ranked values. Never
    plain before the judge accepts a hypothesis name."""
    opts, seen = [], set()
    for i, v in enumerate(values):
        v = str(v)
        if v and v not in seen:
            seen.add(v)
            opts.append((f"cand{i}", v))
    if not opts:
        return None
    try:
        return labels.candidates(f"{KEY}.{field}/{fs}", opts[:labels.MAX_OPTIONS])
    except ValueError:
        return None


def _member_of(q) -> str:
    member = q.get("member") or (str(q.get("artifact") or "").split(ARROW)[-1] if q.get("artifact") else "")
    return Path(str(member)).name if member else ""


def _file_report(q, reps):
    """The one filesystem report a question names, or (when the delivery has exactly one) that one."""
    base = _member_of(q)
    if base:
        hit = [r for r in reps if Path(r[0]).name == base or r[0].split(ARROW)[-1].endswith(base)]
        if len(hit) == 1:
            return hit[0]
        if hit:
            return None
    return reps[0] if len(reps) == 1 else None


def _named_entry(text: str, entries: list):
    """The one entry a question names by its filename (quoted, or a token with an extension). None
    when zero or more than one match -> never a guess."""
    tokens = set(re.findall(r"[\"'`]([^\"'`]+)[\"'`]", text))
    tokens |= set(re.findall(r"[A-Za-z0-9_.$\-]+\.[A-Za-z0-9]{1,8}", text))
    live = [e for e in entries if not e["deleted"] and not e["slack"]]
    for tok in sorted(tokens, key=len, reverse=True):
        tl = tok.lower()
        hit = [e for e in live if e["name"].lower() == tl or (e["path"] or "").lower().endswith(
            "/" + tl) or (e["path"] or "").lower().endswith("\\" + tl)]
        hit = [e for e in hit if e["stream"] is None]
        if len(hit) == 1:
            return hit[0]
    return None


# Hash / checksum questions. A digest is PLAIN only when the question NAMES the algorithm that is
# computed: a sha256 value is never the answer to an md5/sha1/crc question (never-guess, GAP audit).
# A standard cryptographic hash has one canonical rendering (lowercase hex) -> PLAIN; CRC-32 has
# several (decimal, hex, byte order) -> an unsure pick; a bare 'hash'/'checksum'/'digest' with no
# named algorithm pins nothing -> None.
_DIGEST_ALGOS = (
    ("sha-512", "sha512"), ("sha512", "sha512"),
    ("sha-384", "sha384"), ("sha384", "sha384"),
    ("sha-256", "sha256"), ("sha256", "sha256"),
    ("sha-224", "sha224"), ("sha224", "sha224"),
    ("sha-1", "sha1"), ("sha1", "sha1"),
    ("md5", "md5"),
)
_HASH_INTENT = re.compile(r"\b(hash|digest|checksum|fingerprint)\b", re.I)


def _named_digest(text: str):
    """The hash/checksum ALGORITHM a question names, by its own word (most specific first), or
    'crc32', or None when it names none we can satisfy -> never a guess at which algorithm."""
    t = (text or "").lower()
    for token, algo in _DIGEST_ALGOS:
        if token in t:
            return algo
    if "crc32" in t or "crc-32" in t or re.search(r"\bcrc\b", t):
        return "crc32"
    return None


def _digest_answer(algo, content: bytes, fs):
    """A digest of a complete file's exact bytes. PLAIN only for the NAMED standard hash (its one
    canonical lowercase-hex rendering); CRC-32 is an unsure pick over its renderings; no named
    algorithm -> None. Never answers one algorithm's value to a question that named another."""
    if algo is None:
        return None                               # bare 'hash'/'checksum'/'digest' pins no algorithm
    if algo == "crc32":
        crc = zlib.crc32(content) & 0xFFFFFFFF
        return _pick("crc32", fs, [("decimal", str(crc)), ("hex", "%08x" % crc),
                                   ("0x_hex", "0x%08x" % crc)])   # method-named; ambiguous rendering -> unsure
    try:
        return hashlib.new(algo, content).hexdigest()    # named standard hash -> canonical hex, PLAIN
    except (ValueError, TypeError):
        return None


def _answer_one(q, report):
    fs = report[1]
    entries = report[3]
    text = (str(q.get("question") or "") + " " + str(q.get("answer_id") or q.get("id") or "")).lower()

    def has(*words):
        return any(w in text for w in words)

    if has("flag"):
        return None

    deleted = [e for e in entries if e["deleted"] or e["slack"]]
    if has("deleted", "unallocated", "slack"):
        if not deleted:
            return None
        names = sorted({e["name"] for e in deleted if e["name"] and not e["name"].startswith("<")})
        if not names:
            return None
        values = [", ".join(names), "\n".join(names), str(len(names))]
        values += names[:labels.MAX_OPTIONS - 3]
        return _candidates("deleted_entries", fs, values)

    if has("alternate data stream", "data stream", ":ads", " ads", "ads ", "stream name", "named stream"):
        ads = [e for e in entries if e["stream"] and not e["deleted"]]
        named = _named_entry(text, entries)
        if named is not None:
            ads = [e for e in ads if (e["path"] or "").startswith((named["path"] or "") + ":")] or ads
        if len(ads) == 1 and ads[0]["complete"]:
            return _pick("ads_name", fs, _name_renderings(ads[0]["stream"]))
        return None

    entry = _named_entry(text, entries)
    if entry is None:
        return None
    if not entry["complete"]:
        return None                       # partial / damaged record -> the caller gets None

    algo = _named_digest(text)
    if algo is not None or _HASH_INTENT.search(text):
        if entry["content"] is None:
            return None                   # no exact bytes (non-resident / undecoded) -> never guess
        # PLAIN only when the NAMED algorithm matches what we compute; a different named algorithm is
        # computed and answered as itself; CRC-32 is unsure; a bare 'hash'/'checksum' is None.
        return _digest_answer(algo, entry["content"], fs)
    if has("size", "bytes", "length", "how large", "how big"):
        return _pick("file_size", fs, _size_renderings(entry["size"]))
    if has("full path", "path", "located", "location", "where"):
        return _pick("file_path", fs, _path_renderings(entry["path"]))
    if has("name", "called", "filename", "file name"):
        return _pick("file_name", fs, _name_renderings(entry["name"]))
    return None


def solve_set(questions, files, ctx=None) -> dict:
    """Runner contract. Fail-closed: any error on a question yields None for it, never a guess."""
    out = {}
    try:
        reps = listing(files)
    except Exception:    # noqa: BLE001
        reps = []
    for q in (questions or []):
        qid = q.get("qid") or q.get("id") or q.get("answer_id")
        if qid is None:
            continue
        try:
            report = _file_report(q, reps)
            out[qid] = None if report is None else _answer_one(q, report)
        except Exception:    # noqa: BLE001
            out[qid] = None
    return out


# ============================================================================ fixtures (in-file selftest)
#
# Minimal, spec-compliant images built in memory so the walkers can be exercised with no external
# tool or sample. These are pure byte builders (nothing is executed); tests/test_GAP_FS_WALK.py
# imports them, and `fs_walk.py --selftest` runs the same checks.

def _align(n, a=8):
    return (n + a - 1) & ~(a - 1)


def build_squashfs(files=None, *, break_compression=False, truncate=False) -> bytes:
    """A squashfs 4.0 image: one root directory of regular files, metadata stored UNCOMPRESSED
    (header top bit set) so no external compressor is needed. break_compression marks the inode
    table COMPRESSED with an lzo id (stdlib cannot decode it); truncate cuts the dir table off."""
    files = files or {"readme.txt": b"hello squashfs\n", "data.bin": bytes(range(32))}
    block_size, block_log = 4096, 12
    sb = bytearray(96)
    data_region = bytearray()
    file_meta = {}      # name -> (blocks_start, file_size, block_size_entry)
    for name, content in files.items():
        start = 96 + len(data_region)
        data_region += content
        file_meta[name] = (start, len(content), (len(content) & 0xFFFFFF) | 0x1000000)
    # inode table: inode1 (root dir), then one basic-file inode per file, in one metadata block.
    inode_payload = bytearray()
    inode_pos = {}
    inode_payload += struct.pack("<HHHHII", 1, 0o755, 0, 0, 0, 1)     # root dir common header
    # dir inode body filled in after the directory listing size is known; reserve 16 bytes
    dir_body_at = len(inode_payload)
    inode_payload += bytes(16)
    inode_num = 2
    for name in files:
        inode_pos[name] = len(inode_payload)
        bstart, fsize, bse = file_meta[name]
        inode_payload += struct.pack("<HHHHII", 2, 0o644, 0, 0, 0, inode_num)   # basic file common
        inode_payload += struct.pack("<IIII", bstart, 0xFFFFFFFF, 0, fsize)     # file body
        inode_payload += struct.pack("<I", bse)                                 # one block size
        inode_num += 1
    # directory table: one header + one entry per file, sorted by name.
    listing = bytearray()
    ordered = sorted(files)
    base_inode = 2
    listing += struct.pack("<III", len(ordered) - 1, 0, base_inode)             # dir header
    for idx, name in enumerate(ordered):
        nb = name.encode()
        listing += struct.pack("<HhHH", inode_pos[name], (2 + idx) - base_inode, 2, len(nb) - 1) + nb
    struct.pack_into("<IIHHI", inode_payload, dir_body_at, 0, 2, len(listing) + 3, 0, 1)

    inode_comp_flag = 0x0000 if break_compression else 0x8000
    inode_block = struct.pack("<H", (len(inode_payload) & 0x7FFF) | inode_comp_flag) + bytes(inode_payload)
    dir_block = struct.pack("<H", (len(listing) & 0x7FFF) | 0x8000) + bytes(listing)

    inode_tbl = 96 + len(data_region)
    dir_tbl = inode_tbl + len(inode_block)
    bytes_used = dir_tbl + len(dir_block)
    comp_id = 3 if break_compression else 1          # lzo (unsupported) when breaking, else gzip
    struct.pack_into("<4sIIIIHHHHHH", sb, 0, b"hsqs", len(files) + 1, 0, block_size, 0,
                     comp_id, block_log, 0, 0, 4, 0)
    struct.pack_into("<QQQQQQQQ", sb, 32, 0, bytes_used, bytes_used, 0xFFFFFFFFFFFFFFFF,
                     inode_tbl, dir_tbl, bytes_used, 0xFFFFFFFFFFFFFFFF)
    image = bytes(sb) + bytes(data_region) + inode_block + dir_block
    if truncate:
        image = image[:dir_tbl + 1]                  # cut inside the directory table
    return image


def _ntfs_res_attr(atype, content, name="") -> bytes:
    nb = name.encode("utf-16-le")
    name_off = 24 if nb else 0
    content_off = _align(24 + len(nb))
    total = _align(content_off + len(content))
    a = bytearray(total)
    struct.pack_into("<IIBBHHH", a, 0, atype, total, 0, len(name), name_off, 0, 0)
    struct.pack_into("<IHBB", a, 16, len(content), content_off, 0, 0)
    if nb:
        a[name_off:name_off + len(nb)] = nb
    a[content_off:content_off + len(content)] = content
    return bytes(a)


def _ntfs_file_name(parent_num, name, namespace=1) -> bytes:
    nb = name.encode("utf-16-le")
    c = bytearray(66 + len(nb))
    struct.pack_into("<Q", c, 0, (parent_num & 0xFFFFFFFFFFFF) | (1 << 48))
    c[64] = len(name)
    c[65] = namespace
    c[66:] = nb
    return bytes(c)


def _ntfs_record(name, parent, *, is_dir=False, in_use=True, data=b"", ads=None,
                 namespace=1, rec_size=1024) -> bytes:
    attrs = bytearray()
    attrs += _ntfs_res_attr(0x30, _ntfs_file_name(parent, name, namespace))   # $FILE_NAME attribute
    if not is_dir:
        attrs += _ntfs_res_attr(0x80, data)                 # unnamed $DATA
        if ads:
            attrs += _ntfs_res_attr(0x80, ads[1], name=ads[0])   # named :ADS stream
    rec = bytearray(rec_size)
    rec[0:4] = b"FILE"
    usa_off, usa_size = 48, (rec_size // 512) + 1
    struct.pack_into("<HH", rec, 4, usa_off, usa_size)
    struct.pack_into("<H", rec, 16, 1)                      # sequence number
    struct.pack_into("<H", rec, 18, 1)                      # hard link count
    first_attr = 56
    struct.pack_into("<H", rec, 20, first_attr)
    struct.pack_into("<H", rec, 22, (1 if in_use else 0) | (2 if is_dir else 0))
    rec[first_attr:first_attr + len(attrs)] = attrs
    end = first_attr + len(attrs)
    struct.pack_into("<I", rec, end, 0xFFFFFFFF)            # end-of-attributes marker
    struct.pack_into("<I", rec, 24, end + 4)               # used size
    struct.pack_into("<I", rec, 28, rec_size)              # allocated size
    usn = b"\x2a\x00"
    for j in range(1, usa_size):
        se = j * 512 - 2
        if se + 2 > rec_size:
            break
        rec[usa_off + j * 2:usa_off + j * 2 + 2] = rec[se:se + 2]   # save original
        rec[se:se + 2] = usn                                        # stamp the USN
    rec[usa_off:usa_off + 2] = usn
    return bytes(rec)


def build_ntfs() -> bytes:
    """A tiny NTFS volume: a boot sector pointing at an 8-record $MFT. Root at record 5, a live
    file with a named :ADS stream at 6, a deleted file at 7."""
    rec_size, bps, spc, mft_cluster = 1024, 512, 1, 4
    boot = bytearray(512)
    boot[3:11] = b"NTFS    "
    struct.pack_into("<H", boot, 0x0B, bps)
    boot[0x0D] = spc
    struct.pack_into("<Q", boot, 0x30, mft_cluster)
    struct.pack_into("<b", boot, 0x40, -10)                # 2^10 = 1024-byte records
    boot[510:512] = b"\x55\xaa"
    recs = []
    for sysname in ("$MFT", "$MFTMirr", "$LogFile", "$Volume", "$AttrDef"):   # records 0-4
        recs.append(_ntfs_record(sysname, 5, data=b"", rec_size=rec_size))
    recs.append(_ntfs_record(".", 5, is_dir=True, rec_size=rec_size))          # record 5 = root
    recs.append(_ntfs_record("secret.txt", 5, data=b"top secret bytes\n",
                             ads=("hidden.txt", b"payload from the stream\n"), rec_size=rec_size))  # 6
    recs.append(_ntfs_record("old.log", 5, in_use=False, data=b"deleted content\n",
                             rec_size=rec_size))            # record 7 = deleted
    mft = b"".join(recs)
    image = bytearray(mft_cluster * spc * bps + len(mft))
    image[0:512] = boot
    image[mft_cluster * spc * bps:] = mft
    return bytes(image)


def _exfat_set(name, size, first_cluster, *, in_use=True, is_dir=False) -> bytes:
    nb = name.encode("utf-16-le")
    name_entries = (len(name) + 14) // 15
    sec_count = 1 + name_entries
    s = bytearray((1 + sec_count) * 32)
    s[0] = 0x85 if in_use else 0x05                        # File directory entry (primary)
    s[1] = sec_count
    struct.pack_into("<H", s, 4, 0x10 if is_dir else 0x20)  # attributes
    s[32] = 0xC0 if in_use else 0x40                        # Stream extension
    s[33] = 0x03                                            # AllocationPossible | NoFatChain
    s[35] = len(name)                                       # NameLength
    struct.pack_into("<Q", s, 32 + 8, size)                # ValidDataLength
    struct.pack_into("<I", s, 32 + 20, first_cluster)
    struct.pack_into("<Q", s, 32 + 24, size)               # DataLength
    for k in range(name_entries):
        eo = 64 + k * 32
        s[eo] = 0xC1 if in_use else 0x41                   # File name entry
        chunk = nb[k * 30:(k + 1) * 30]
        s[eo + 2:eo + 2 + len(chunk)] = chunk
    struct.pack_into("<H", s, 2, _exfat_set_checksum(bytes(s)))
    return bytes(s)


def build_exfat() -> bytes:
    """A tiny exFAT image: 512-byte sectors/clusters, root at cluster 2, one live file in cluster 3
    and one deleted entry set."""
    sector = 512
    heap_sectors = 8
    boot = bytearray(sector)
    boot[3:11] = b"EXFAT   "
    struct.pack_into("<I", boot, 88, heap_sectors)         # ClusterHeapOffset (sectors)
    struct.pack_into("<I", boot, 92, 8)                    # ClusterCount
    struct.pack_into("<I", boot, 96, 2)                    # FirstClusterOfRootDirectory
    boot[108] = 9                                          # BytesPerSectorShift (512)
    boot[109] = 0                                          # SectorsPerClusterShift (1)
    boot[110] = 1                                          # NumberOfFats
    boot[510:512] = b"\x55\xaa"
    content = b"exfat report body\n"
    root = bytearray(sector)
    live = _exfat_set("report.pdf", len(content), 3)
    dead = _exfat_set("trash.tmp", 11, 4, in_use=False)
    root[0:len(live)] = live
    root[len(live):len(live) + len(dead)] = dead
    image = bytearray(heap_sectors * sector + 2 * sector)  # boot region + clusters 2 and 3
    image[0:sector] = boot
    image[heap_sectors * sector:heap_sectors * sector + sector] = root       # cluster 2 (root)
    image[heap_sectors * sector + sector:heap_sectors * sector + sector + len(content)] = content  # cluster 3
    return bytes(image)


def _jffs2_node(ntype, body) -> bytes:
    totlen = 12 + len(body)
    head = struct.pack("<HHI", JFFS2_MAGIC, ntype, totlen)
    node = head + struct.pack("<I", _jffs2_crc(head)) + body
    pad = (_align(totlen, 4) - totlen)
    return node + bytes(pad)


def _jffs2_dirent_finish(pino, ino, name, dtype, version, nb) -> bytes:
    totlen = 12 + 28 + len(nb)
    head = struct.pack("<HHI", JFFS2_MAGIC, JFFS2_DIRENT, totlen)
    hdr_crc = _jffs2_crc(head)
    body = bytearray(28 + len(nb))
    struct.pack_into("<IIII", body, 0, pino, version, ino, 0)
    body[16] = len(nb)
    body[17] = dtype
    node_wo_crcs = head + struct.pack("<I", hdr_crc) + bytes(body[:20])   # node[:32]
    struct.pack_into("<I", body, 20, _jffs2_crc(node_wo_crcs))
    struct.pack_into("<I", body, 24, _jffs2_crc(nb))
    body[28:] = nb
    node = head + struct.pack("<I", hdr_crc) + bytes(body)
    pad = _align(totlen, 4) - totlen
    return node + bytes(pad)


def _jffs2_inode(ino, content, version=1) -> bytes:
    totlen = 12 + 56 + len(content)
    head = struct.pack("<HHI", JFFS2_MAGIC, JFFS2_INODE, totlen)
    hdr_crc = _jffs2_crc(head)
    body = bytearray(56)                                   # node offsets 12..68
    struct.pack_into("<III", body, 0, ino, version, 0o100644)    # ino, version, mode
    struct.pack_into("<I", body, 16, len(content))               # isize (node offset 28)
    struct.pack_into("<I", body, 32, 0)                          # offset (node 44)
    struct.pack_into("<I", body, 36, len(content))               # csize  (node 48)
    struct.pack_into("<I", body, 40, len(content))               # dsize  (node 52)
    body[44] = 0                                                 # compr = NONE (node 56)
    struct.pack_into("<I", body, 48, _jffs2_crc(content))        # data_crc (node 60)
    node_prefix = head + struct.pack("<I", hdr_crc) + bytes(body[:48])   # node[:60]
    struct.pack_into("<I", body, 52, _jffs2_crc(node_prefix))    # node_crc (node 64)
    node = head + struct.pack("<I", hdr_crc) + bytes(body) + content
    pad = _align(totlen, 4) - totlen
    return node + bytes(pad)


def build_jffs2(corrupt_name=None) -> bytes:
    """A JFFS2 image: three regular files in the root (inode 1). When corrupt_name is given, one
    byte of that file's dirent name is flipped so its name CRC fails -> the walker drops that one
    entry and carries on."""
    DT_REG = 8
    plan = [(2, "firmware.bin", b"\x7fELF firmware image\n"),
            (3, "config.txt", b"mode=secure\n"),
            (4, "notes.md", b"# notes\n")]
    out = bytearray()
    for ino, name, content in plan:
        dirent = bytearray(_jffs2_dirent_finish(1, ino, name, DT_REG, 1, name.encode()))
        if corrupt_name and name == corrupt_name:
            dirent[40] ^= 0xFF                             # flip the first stored name byte (node offset 40)
        out += dirent
        out += _jffs2_inode(ino, content)
    return bytes(out)


def _run_selftest() -> int:
    ok = True

    def expect(label, cond):
        nonlocal ok
        print(f"{'ok  ' if cond else 'FAIL'} {label}")
        ok = ok and cond

    fs, complete, entries = walk(build_squashfs())
    names = {e["name"]: e for e in entries}
    expect("squashfs recognised + complete", fs == "squashfs" and complete)
    expect("squashfs file sizes", names.get("readme.txt", {}).get("size") == 15)
    _, comp_bad, _ = walk(build_squashfs(break_compression=True))
    expect("squashfs unsupported compression -> partial", comp_bad is False)
    _, comp_tr, _ = walk(build_squashfs(truncate=True))
    expect("squashfs truncated -> partial", comp_tr is False)

    fs, complete, entries = walk(build_ntfs())
    byname = {e["path"]: e for e in entries}
    expect("ntfs recognised", fs == "ntfs")
    expect("ntfs ADS surfaced", any(e["stream"] == "hidden.txt" for e in entries))
    expect("ntfs deleted surfaced", any(e["deleted"] and e["name"] == "old.log" for e in entries))

    fs, complete, entries = walk(build_exfat())
    expect("exfat recognised", fs == "exfat")
    expect("exfat live file", any(e["name"] == "report.pdf" and not e["deleted"] for e in entries))
    expect("exfat deleted set", any(e["name"] == "trash.tmp" and e["deleted"] for e in entries))

    fs, complete, entries = walk(build_jffs2())
    expect("jffs2 recognised + complete", fs == "jffs2" and complete)
    expect("jffs2 paths", {e["name"] for e in entries} >= {"firmware.bin", "config.txt", "notes.md"})
    fs, bad_complete, bad_entries = walk(build_jffs2(corrupt_name="config.txt"))
    seen = {e["name"] for e in bad_entries}
    expect("jffs2 corrupt node dropped, walk continues",
           bad_complete is False and "config.txt" not in seen and {"firmware.bin", "notes.md"} <= seen)
    print("ok" if ok else "FAILED")
    return 0 if ok else 1


# ============================================================================ CLI

def main(argv) -> int:
    as_json = "--json" in argv
    if "--selftest" in argv:
        return _run_selftest()
    paths = [a for a in argv if not a.startswith("--")]
    if not paths:
        print("usage: fs_walk.py <image>... [--json] | --selftest   "
              "(RECON ONLY; directory walk, flag answered None)", file=sys.stderr)
        return 2
    report = []
    for p in paths:
        try:
            data = Path(p).read_bytes()
        except OSError as e:
            print(f"fs_walk.py: {p}: {e}", file=sys.stderr)
            continue
        fs, complete, entries = walk(data)
        report.append({"file": p, "fs": fs, "complete": complete, "bytes": len(data),
                       "entries": [{k: (v if k != "content" else (None if v is None else len(v)))
                                    for k, v in e.items()} for e in entries]})
    if as_json:
        print(json.dumps(report, indent=1))
        return 0
    for row in report:
        if not row["fs"]:
            print(f"- {row['file']}: no squashfs/NTFS/exFAT/JFFS2 filesystem recognised "
                  f"({row['bytes']} bytes)")
            continue
        flag = "complete" if row["complete"] else "PARTIAL (some branch did not decode)"
        print(f"# {row['file']}  [{row['fs']}]  {len(row['entries'])} entries  ({flag})")
        for e in row["entries"]:
            tag = []
            if e["deleted"]:
                tag.append("deleted")
            if e["stream"]:
                tag.append("ADS:" + e["stream"])
            if not e["complete"]:
                tag.append("partial")
            sz = "" if e["size"] is None else f"  {e['size']} B"
            print(f"    {e['kind']:5} {e['path']}{sz}" + ("  [" + ",".join(tag) + "]" if tag else ""))
        print("  directory facts only; a name/path/size/stream is an unsure pick until the judge "
              "accepts a spelling; deleted/partial is unsure; a flag is None.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
