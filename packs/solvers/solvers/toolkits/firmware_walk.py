#!/usr/bin/env python3
"""Firmware / flash image content walker (built 2026-10-24, backlog key firmware-image-walker).

Reads the firmware CONTAINERS that solvers/toolkits/carve_stego_fs.py (ISO/FAT/ext/cpio/uImage)
and the binary / generic lanes (magic-DETECT only) do NOT walk, and is distinct from the generic
fs_walk track. All plain Python, read-only, bytes in and structure out; nothing here mounts,
executes, writes or inflates anything a non-stdlib codec is needed for.

  SquashFS 4.0   superblock + inode table + directory table + regular-file extraction.
                 gzip (zlib) and xz / lzma inflate through the stdlib; lzo, lz4 and zstd entries
                 are LISTED (name, size) but their file CONTENT is None (no stdlib codec).
  JFFS2          dirent + inode node walk, every node's header/node/data CRC checked, the newest
                 version of an inode winning; content only when compr is none/zero/zlib.
  UBI + UBIFS    the UBI PEB->LEB volume map is stripped, then the UBIFS nodes are read (common
                 header CRC checked): dentry names and inode sizes. Best-effort, bounded,
                 fail-closed; file content is left None (LEB data reassembly is not attempted).
  DTB / FDT      the flattened device tree: node paths and property values.
  U-Boot env     the leading CRC32 over the key=value area is validated FIRST; only then are the
                 variables read. A CRC mismatch yields no values. A region holding the two copies of
                 a REDUNDANT env (or an env that does not start the file) is split by env_copies():
                 each copy stands behind its own CRC, and pick_live_env() takes the live one by
                 U-Boot's flags-counter rule among the CRC-valid copies (B-069).

  walk(files) -> {"images": [ {name, kind, ...} ]}         every container found in the delivery
  solve_set(questions, files, ctx) -> {qid: answer}        the runner contract (never-guess)
  signals(questions, files) -> float                       0..1, how firmware-like the delivery is

NEVER-WRONG boundary (AGENTS.md, "Uncertain answers"):
  - A file/dir NAME and SIZE, and a device-tree PROPERTY value, read from a structurally-complete,
    CRC/length-consistent parse is a deterministic read of exact bytes -> PLAIN-eligible. The
    spelling or separator of a PATH is the author's choice -> labels.candidates (UNSURE).
  - A U-Boot env variable VALUE is PLAIN only when the leading CRC32 validates the whole env area;
    a CRC mismatch -> None.
  - A payload that needs a non-stdlib decompressor, a damaged / incomplete node, or an ambiguous
    version chain -> None for the affected entry, never a partial guess.
  - A "flag" (or any instruction) inside an extracted file is text-is-data -> None, never submitted.

  .venv/bin/python solvers/toolkits/firmware_walk.py <members>...   the walk, as text
"""
import json
import re
import struct
import sys
import time
import zlib
from pathlib import Path

try:
    import lzma
except Exception:                       # pragma: no cover - lzma is always present in .venv
    lzma = None

KEY = "firmware"
SENTINEL = "??"

MAX_IMAGES = 64
MAX_ENTRIES = 20000
MAX_FILE = 64 * 1024 * 1024
MAX_DEPTH = 32
MAX_NODES = 500000
MAX_META = 64 * 1024 * 1024
ARROW = " -> "
BUDGET = 1.0
BUDGET_UNTIMED = 20.0


# ---- CRC flavours ----------------------------------------------------------------------------------

def crc32_std(data: bytes) -> int:
    """The standard IEEE CRC-32 (zlib / U-Boot crc32(0, ...)): init 0xffffffff, reflected, final xor."""
    return zlib.crc32(data) & 0xFFFFFFFF


def jffs2_crc(data: bytes) -> int:
    """JFFS2 / mtd-utils crc32: the reflected IEEE table seeded with 0 and NO final inversion.

    zlib.crc32(d, v) = raw(v ^ 0xffffffff, d) ^ 0xffffffff, so raw(0, d) = zlib.crc32(d, 0xffffffff) ^ 0xffffffff."""
    return (zlib.crc32(data, 0xFFFFFFFF) ^ 0xFFFFFFFF) & 0xFFFFFFFF


def ubifs_crc(data: bytes) -> int:
    """UBIFS crc32: the reflected IEEE table seeded with 0xffffffff and no final inversion
    (UBIFS_CRC32_INIT). raw(0xffffffff, d) = zlib.crc32(d) ^ 0xffffffff."""
    return (zlib.crc32(data) ^ 0xFFFFFFFF) & 0xFFFFFFFF


# ---- unsure answers (labels.pick / labels.candidates with a graceful fallback) ---------------------

def _opts(options):
    out, seen = [], set()
    for item in options or []:
        name, value = item if isinstance(item, (tuple, list)) and len(item) == 2 else (str(item), item)
        if name and value is not None and name not in seen:
            seen.add(name)
            out.append((str(name), value))
    return out


def _unsure(field, shape, options, candidates=False):
    """An unsure answer for one established fact under '<KEY>.<field>/<shape>'. Uses
    solvers/common/labels.py when it knows the prefix, else writes the same wire form inline so the
    answer still carries "??" and can never reach the judge as a plain value."""
    opts = _opts(options)
    if not opts:
        return None
    key = f"{KEY}.{field}/{shape}".lower()
    try:
        import labels
        return labels.candidates(key, opts) if candidates else labels.pick(key, opts)
    except Exception:
        pass
    if candidates:
        key = key + "#candidates"
    return SENTINEL + json.dumps({"k": key, "o": [[n, v] for n, v in opts[:12]]}, separators=(",", ":"))


def _path_options(path: str):
    """Spellings of ONE path whose separator / leading slash the author chose: candidates, best first."""
    p = path.strip("/")
    out = [("slash_rooted", "/" + p), ("relative", p)]
    if p:
        out.append(("backslash", "\\" + p.replace("/", "\\")))
    return out


# ---- stdlib decompression ---------------------------------------------------------------------------

_SQUASH_COMP = {1: "gzip", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd"}
_STDLIB_COMP = {1, 2, 4}                 # gzip(zlib), legacy lzma, xz


def _inflate(comp_id: int, blob: bytes) -> bytes:
    """Inflate one SquashFS block with the stdlib only. Raises for a codec the stdlib lacks."""
    if comp_id == 1:
        return zlib.decompress(blob)
    if comp_id == 4:
        if lzma is None:
            raise ValueError("no lzma")
        return lzma.decompress(blob, format=lzma.FORMAT_XZ)
    if comp_id == 2:
        if lzma is None:
            raise ValueError("no lzma")
        return lzma.decompress(blob, format=lzma.FORMAT_ALONE)
    raise ValueError(f"unsupported squashfs compression {comp_id}")


# ---- SquashFS 4.0 -----------------------------------------------------------------------------------

SQUASHFS_MAGIC_LE = 0x73717368           # b"hsqs"
_INODE_BASIC_DIR = 1
_INODE_BASIC_FILE = 2
_INODE_EXT_DIR = 8
_INODE_EXT_FILE = 9


def is_squashfs(data: bytes) -> bool:
    return len(data) >= 96 and data[:4] == b"hsqs"


def _read_meta_table(data: bytes, start: int, end: int, comp_id: int):
    """Inflate a whole SquashFS metadata table into one buffer. Returns (buf, index) where index
    maps each compressed block's start offset (relative to `start`) to its offset in `buf`. Raises
    on a codec the stdlib lacks or a structurally-broken block, so the caller fails closed."""
    buf = bytearray()
    index = {}
    pos = start
    while pos + 2 <= end and len(buf) < MAX_META:
        rel = pos - start
        header = struct.unpack_from("<H", data, pos)[0]
        size = header & 0x7FFF
        uncompressed = bool(header & 0x8000)
        chunk = data[pos + 2:pos + 2 + size]
        if len(chunk) != size:
            raise ValueError("short metadata block")
        index[rel] = len(buf)
        buf += chunk if uncompressed else _inflate(comp_id, chunk)
        pos += 2 + size
        if size == 0:
            break
    return bytes(buf), index


def _squashfs(data: bytes):
    if not is_squashfs(data):
        return None
    (magic, inodes, mkfs, block_size, fragments, compression, block_log, flags, no_ids, s_major, s_minor,
     root_ref, bytes_used, id_table, xattr_table, inode_table, dir_table, frag_table, export_table) = struct.unpack_from(
        "<IIIIIHHHHHHQQQQQQQQ", data, 0)
    if magic != SQUASHFS_MAGIC_LE or s_major != 4:
        return None
    comp_name = _SQUASH_COMP.get(compression, f"id{compression}")
    out = {"name": None, "kind": "squashfs", "compression": comp_name, "complete": False, "entries": []}
    limit = min(len(data), bytes_used if bytes_used and bytes_used <= len(data) else len(data))

    # the end of each table is the next larger table start (ignoring the "none" sentinel), else bytes_used.
    def table_end(start):
        nxt = [t for t in (id_table, inode_table, dir_table, frag_table, export_table, xattr_table)
               if t != 0xFFFFFFFFFFFFFFFF and t > start]
        return min([limit] + nxt)

    try:
        inode_buf, inode_idx = _read_meta_table(data, inode_table, table_end(inode_table), compression)
        dir_buf, dir_idx = _read_meta_table(data, dir_table, table_end(dir_table), compression)
    except Exception:
        return out                       # metadata unreadable (e.g. a zstd image): fail closed, no entries

    def inode_at(block_rel, offset):
        base = inode_idx.get(block_rel)
        if base is None:
            return None
        return base + offset

    def parse_inode(pos):
        if pos is None or pos + 16 > len(inode_buf):
            return None
        itype, mode, uid, gid, mtime, inum = struct.unpack_from("<HHHHII", inode_buf, pos)
        node = {"type": itype, "inum": inum, "pos": pos}
        p = pos + 16
        if itype in (_INODE_BASIC_DIR, _INODE_EXT_DIR):
            if itype == _INODE_BASIC_DIR:
                if p + 16 > len(inode_buf):
                    return None
                start_block, nlink, fsize, offset, parent = struct.unpack_from("<IIHHI", inode_buf, p)
            else:
                if p + 24 > len(inode_buf):
                    return None
                nlink, fsize, start_block, parent, icount, offset = struct.unpack_from("<IIIIHH", inode_buf, p)
            node.update({"kind": "dir", "start_block": start_block, "offset": offset, "file_size": fsize})
            return node
        if itype in (_INODE_BASIC_FILE, _INODE_EXT_FILE):
            if itype == _INODE_BASIC_FILE:
                if p + 16 > len(inode_buf):
                    return None
                start_block, fragment, foffset, fsize = struct.unpack_from("<IIII", inode_buf, p)
                p += 16
                sparse = 0
            else:
                if p + 40 > len(inode_buf):
                    return None
                start_block, fsize, sparse, nlink, fragment, foffset, xattr = struct.unpack_from("<QQQIIII", inode_buf, p)
                p += 40
            nblocks = 0
            if fragment == 0xFFFFFFFF:
                nblocks = (fsize + block_size - 1) // block_size if block_size else 0
            else:
                nblocks = fsize // block_size if block_size else 0
            block_sizes = []
            for _ in range(nblocks):
                if p + 4 > len(inode_buf):
                    return None
                block_sizes.append(struct.unpack_from("<I", inode_buf, p)[0])
                p += 4
            node.update({"kind": "file", "start_block": start_block, "fragment": fragment,
                         "file_size": fsize, "block_sizes": block_sizes, "has_fragment": fragment != 0xFFFFFFFF})
            return node
        return None

    def extract(node):
        """The file's exact bytes, or (None, reason). Fails closed on a non-stdlib codec, a
        fragment we cannot reassemble, or any length mismatch."""
        if node.get("has_fragment"):
            return None, "tail stored in a fragment (not reassembled)"
        off = node["start_block"]
        parts = bytearray()
        for bs in node["block_sizes"]:
            size = bs & 0xFFFFFF
            uncompressed = bool(bs & 0x1000000)
            if off + size > len(data):
                return None, "data block past end of image"
            blk = data[off:off + size]
            off += size
            if size == 0:
                parts += b"\x00" * block_size          # a sparse block
                continue
            if uncompressed:
                parts += blk
            else:
                try:
                    parts += _inflate(compression, blk)
                except Exception:
                    return None, f"{comp_name}: no stdlib decompressor"
            if len(parts) > MAX_FILE:
                return None, "file exceeds MAX_FILE"
        if len(parts) != node["file_size"]:
            return None, "assembled size != inode file_size"
        return bytes(parts), None

    seen = set()
    entries = out["entries"]

    def walk_dir(dir_node, prefix, depth):
        if depth > MAX_DEPTH or len(entries) >= MAX_ENTRIES:
            return
        base = dir_idx.get(dir_node["start_block"])
        if base is None:
            return
        start = base + dir_node["offset"]
        listing_len = dir_node["file_size"] - 3
        if listing_len < 0 or start + listing_len > len(dir_buf):
            return
        region = dir_buf[start:start + listing_len]
        i = 0
        while i + 12 <= len(region) and len(entries) < MAX_ENTRIES:
            count, hdr_block, hdr_inum = struct.unpack_from("<III", region, i)
            i += 12
            for _ in range(count + 1):
                if i + 8 > len(region):
                    return
                e_off, e_inode_delta, e_type, e_size = struct.unpack_from("<HhHH", region, i)
                i += 8
                nlen = e_size + 1
                name = region[i:i + nlen]
                i += nlen
                if len(name) != nlen:
                    return
                try:
                    cname = name.decode("utf-8")
                except UnicodeDecodeError:
                    cname = name.decode("latin-1")
                child = parse_inode(inode_at(hdr_block, e_off))
                if child is None:
                    continue
                path = prefix + "/" + cname
                if child.get("kind") == "dir":
                    entries.append({"path": path, "name": cname, "type": "dir", "size": None,
                                    "content": None, "reason": None})
                    key = (child["inum"], child["start_block"], child["offset"])
                    if key not in seen:
                        seen.add(key)
                        walk_dir(child, path, depth + 1)
                elif child.get("kind") == "file":
                    content, reason = extract(child)
                    entries.append({"path": path, "name": cname, "type": "file",
                                    "size": child["file_size"], "content": content, "reason": reason})

    root = parse_inode(inode_at((root_ref >> 16) & 0xFFFFFFFFFFFF, root_ref & 0xFFFF))
    if root is not None and root.get("kind") == "dir":
        walk_dir(root, "", 0)
        out["complete"] = True
    return out


# ---- JFFS2 ------------------------------------------------------------------------------------------

JFFS2_MAGIC = 0x1985
_JFFS2_DIRENT = 0xE001
_JFFS2_INODE = 0xE002
_JFFS2_CLEANMARKER = 0x2003
_JFFS2_PADDING = 0x2004


def is_jffs2(data: bytes) -> bool:
    for sig in (b"\x85\x19", b"\x19\x85"):
        j = data.find(sig)
        if 0 <= j <= 4096 and len(data) >= j + 12:
            return True
    return False


def _jffs2(data: bytes):
    le = True
    first = min((data.find(b"\x85\x19"), data.find(b"\x19\x85")), key=lambda x: x if x >= 0 else 1 << 62)
    if first < 0:
        j_le, j_be = data.find(b"\x85\x19"), data.find(b"\x19\x85")
        if j_le < 0 and j_be < 0:
            return None
        le = j_be < 0 or (0 <= j_le <= j_be)
    else:
        le = data[first:first + 2] == b"\x85\x19"
    e = "<" if le else ">"
    out = {"name": None, "kind": "jffs2", "endian": "little" if le else "big", "entries": []}

    dirents = {}            # (pino, name) -> best dirent dict (newest version)
    inodes = {}             # ino -> list of data-node dicts
    isize = {}              # ino -> (version, file_size)
    pos = 0
    nodes = 0
    n = len(data)
    while pos + 12 <= n and nodes < MAX_NODES:
        if data[pos] == 0xFF:
            pos += 1
            continue
        magic = struct.unpack_from(e + "H", data, pos)[0]
        if magic != JFFS2_MAGIC:
            pos += 4
            continue
        nodetype = struct.unpack_from(e + "H", data, pos + 2)[0]
        totlen = struct.unpack_from(e + "I", data, pos + 4)[0]
        hdr_crc = struct.unpack_from(e + "I", data, pos + 8)[0]
        if jffs2_crc(data[pos:pos + 8]) != hdr_crc:
            pos += 4
            continue                                        # a damaged header: skip it, fail closed
        if totlen < 12 or pos + totlen > n:
            break
        node = data[pos:pos + totlen]
        nodes += 1
        if nodetype == _JFFS2_DIRENT and totlen >= 40:
            node_crc = struct.unpack_from(e + "I", node, 32)[0]
            name_crc = struct.unpack_from(e + "I", node, 36)[0]
            pino, version, ino, _m = struct.unpack_from(e + "IIII", node, 12)
            nsize = node[28]
            dtype = node[29]
            name = node[40:40 + nsize]
            if (jffs2_crc(node[0:32]) == node_crc and jffs2_crc(name) == name_crc and len(name) == nsize):
                try:
                    cname = name.decode("utf-8")
                except UnicodeDecodeError:
                    cname = name.decode("latin-1")
                k = (pino, cname)
                if k not in dirents or version > dirents[k]["version"]:
                    dirents[k] = {"pino": pino, "ino": ino, "name": cname, "version": version, "dtype": dtype}
        elif nodetype == _JFFS2_INODE and totlen >= 68:
            data_crc = struct.unpack_from(e + "I", node, 60)[0]
            node_crc = struct.unpack_from(e + "I", node, 64)[0]
            ino, version, mode = struct.unpack_from(e + "III", node, 12)
            fsize = struct.unpack_from(e + "I", node, 28)[0]
            offset = struct.unpack_from(e + "I", node, 44)[0]
            csize = struct.unpack_from(e + "I", node, 48)[0]
            dsize = struct.unpack_from(e + "I", node, 52)[0]
            compr = node[56]
            payload = node[68:68 + csize]
            if (jffs2_crc(node[0:64]) == node_crc and len(payload) == csize and jffs2_crc(payload) == data_crc):
                inodes.setdefault(ino, []).append(
                    {"version": version, "offset": offset, "csize": csize, "dsize": dsize, "compr": compr,
                     "payload": payload})
                if ino not in isize or version > isize[ino][0]:
                    isize[ino] = (version, fsize)
        pos += (totlen + 3) & ~3

    def file_content(ino):
        frags = sorted(inodes.get(ino, []), key=lambda d: d["version"])
        size = isize.get(ino, (0, 0))[1]
        if size <= 0:
            return b"" if size == 0 else None, None if size == 0 else "unknown size"
        if size > MAX_FILE:
            return None, "file exceeds MAX_FILE"
        buf = bytearray(size)
        covered = bytearray(size)
        for fr in frags:
            if fr["compr"] == 0:                            # JFFS2_COMPR_NONE
                chunk = fr["payload"]
            elif fr["compr"] == 1:                          # JFFS2_COMPR_ZERO
                chunk = b"\x00" * fr["dsize"]
            elif fr["compr"] == 6:                          # JFFS2_COMPR_ZLIB
                try:
                    chunk = zlib.decompress(fr["payload"])
                except Exception:
                    return None, "zlib fragment failed"
            else:
                return None, "non-stdlib JFFS2 compression"
            o = fr["offset"]
            if o + len(chunk) > size or len(chunk) != fr["dsize"]:
                return None, "fragment outside declared size"
            buf[o:o + len(chunk)] = chunk
            for b in range(o, o + len(chunk)):
                covered[b] = 1
        if not all(covered):
            return None, "incomplete data (holes in the inode chain)"
        return bytes(buf), None

    # paths: walk from the implicit root inode 1 down through surviving dirents (ino != 0 == live).
    children = {}
    for (pino, name), d in dirents.items():
        if d["ino"] != 0:
            children.setdefault(pino, []).append(d)

    def resolve(ino_no, prefix, depth, visited):
        if depth > MAX_DEPTH or ino_no in visited or len(out["entries"]) >= MAX_ENTRIES:
            return
        visited = visited | {ino_no}
        for d in sorted(children.get(ino_no, []), key=lambda x: x["name"]):
            path = prefix + "/" + d["name"]
            if d["dtype"] == 4:                             # DT_DIR
                out["entries"].append({"path": path, "name": d["name"], "type": "dir", "size": None,
                                       "content": None, "reason": None})
                resolve(d["ino"], path, depth + 1, visited)
            elif d["ino"] not in isize:
                # the NAME is proven by the dirent's CRCs, but no valid inode node survived for it:
                # the SIZE and CONTENT cannot be proven, so both are None (never a 0-byte guess).
                out["entries"].append({"path": path, "name": d["name"], "type": "file", "size": None,
                                       "content": None, "reason": "no valid inode node (dropped: CRC or absent)"})
            else:
                content, reason = file_content(d["ino"])
                out["entries"].append({"path": path, "name": d["name"], "type": "file",
                                       "size": isize[d["ino"]][1], "content": content, "reason": reason})

    resolve(1, "", 0, frozenset())
    return out


# ---- UBI + UBIFS (best-effort, CRC-gated, content left None) ---------------------------------------

_UBI_EC_MAGIC = b"UBI#"
_UBI_VID_MAGIC = b"UBI!"
_UBIFS_NODE_MAGIC = 0x06101831
_UBIFS_INO_NODE = 0
_UBIFS_DENT_NODE = 2


def is_ubi(data: bytes) -> bool:
    return data[:4] in (_UBI_EC_MAGIC, _UBI_VID_MAGIC)


def is_ubifs(data: bytes) -> bool:
    return len(data) >= 4 and struct.unpack_from("<I", data, 0)[0] == _UBIFS_NODE_MAGIC


def _ubi_lebs(data: bytes):
    """Strip UBI erase-block headers to the raw LEB data. Reads the EC header's data_offset to find
    the volume data; a block whose headers do not parse is skipped. Returns the concatenated LEB
    bytes (best-effort), bounded."""
    peb = None
    # the EC header carries vid_hdr_offset and data_offset; the erase-block size we infer from the
    # distance between successive EC magics.
    offs = []
    i = 0
    while True:
        j = data.find(_UBI_EC_MAGIC, i)
        if j < 0 or len(offs) > 4096:
            break
        offs.append(j)
        i = j + 4
    if len(offs) >= 2:
        peb = offs[1] - offs[0]
    out = bytearray()
    for k, base in enumerate(offs):
        if base + 64 > len(data):
            break
        try:
            version = data[base + 4]
            data_offset = struct.unpack_from(">I", data, base + 20)[0]
        except Exception:
            continue
        end = offs[k + 1] if k + 1 < len(offs) else (base + peb if peb else len(data))
        end = min(end, len(data))
        if 0 < data_offset < (end - base):
            out += data[base + data_offset:end]
        if len(out) > MAX_META:
            break
    return bytes(out)


def _ubifs_nodes(blob: bytes, out):
    """Scan UBIFS nodes, CRC-checking each common header, and collect dentry names and inode sizes.
    Content is left None (LEB data reassembly is not attempted). Bounded, fail-closed."""
    dents = {}          # (parent_inum, name) -> target inum, file type
    sizes = {}          # inum -> size
    pos = 0
    n = len(blob)
    nodes = 0
    while pos + 24 <= n and nodes < MAX_NODES:
        if struct.unpack_from("<I", blob, pos)[0] != _UBIFS_NODE_MAGIC:
            pos += 8                                     # UBIFS aligns nodes to 8 bytes
            continue
        crc = struct.unpack_from("<I", blob, pos + 4)[0]
        nlen = struct.unpack_from("<I", blob, pos + 16)[0]
        ntype = blob[pos + 20]
        if nlen < 24 or pos + nlen > n:
            pos += 8
            continue
        node = blob[pos:pos + nlen]
        if ubifs_crc(node[8:nlen]) != crc:               # the CRC covers everything after magic+crc
            pos += 8
            continue
        nodes += 1
        if ntype == _UBIFS_INO_NODE and nlen >= 56:
            inum = struct.unpack_from("<I", node, 24)[0]     # first word of the key
            size = struct.unpack_from("<Q", node, 48)[0]
            sizes[inum] = size
        elif ntype == _UBIFS_DENT_NODE and nlen >= 52:
            parent = struct.unpack_from("<I", node, 24)[0]   # first word of the key
            inum = struct.unpack_from("<Q", node, 40)[0]
            nm_len = struct.unpack_from("<H", node, 50)[0]
            ftype = node[49]
            name = None
            for name_off in (52, 56):                        # classic, then double-hash (cookie) layout
                cand = node[name_off:name_off + nm_len]
                if len(cand) == nm_len and nm_len and _printable(cand):
                    # length consistency: the node end should align the name+NUL to 8 bytes.
                    if ((name_off + nm_len + 1 + 7) & ~7) == nlen:
                        name = cand
                        break
            if name is not None:
                try:
                    cname = name.decode("utf-8")
                except UnicodeDecodeError:
                    cname = name.decode("latin-1")
                dents[(parent, cname)] = (inum, ftype)

    children = {}
    for (parent, name), (inum, ftype) in dents.items():
        children.setdefault(parent, []).append((name, inum, ftype))

    UBIFS_ROOT = 1
    entries = out["entries"]

    def resolve(inum, prefix, depth, visited):
        if depth > MAX_DEPTH or inum in visited or len(entries) >= MAX_ENTRIES:
            return
        visited = visited | {inum}
        for name, child, ftype in sorted(children.get(inum, []), key=lambda x: x[0]):
            path = prefix + "/" + name
            if ftype == 2:                                   # UBIFS_ITYPE_DIR
                entries.append({"path": path, "name": name, "type": "dir", "size": None,
                                "content": None, "reason": None})
                resolve(child, path, depth + 1, visited)
            else:
                entries.append({"path": path, "name": name, "type": "file", "size": sizes.get(child),
                                "content": None, "reason": "UBIFS data not reassembled"})

    resolve(UBIFS_ROOT, "", 0, frozenset())
    return out


def _printable(b: bytes) -> bool:
    return all(0x20 <= c < 0x7F for c in b)


def _ubi(data: bytes):
    if is_ubi(data):
        out = {"name": None, "kind": "ubi", "entries": [], "note": "best-effort UBI/UBIFS; content not reassembled"}
        blob = _ubi_lebs(data)
        j = blob.find(struct.pack("<I", _UBIFS_NODE_MAGIC))
        if j >= 0:
            _ubifs_nodes(blob[j:], out)
        return out
    if is_ubifs(data):
        out = {"name": None, "kind": "ubifs", "entries": [], "note": "best-effort UBIFS; content not reassembled"}
        _ubifs_nodes(data, out)
        return out
    return None


# ---- Flattened device tree (DTB / FDT) --------------------------------------------------------------

_FDT_MAGIC = 0xD00DFEED
_FDT_BEGIN_NODE = 1
_FDT_END_NODE = 2
_FDT_PROP = 3
_FDT_NOP = 4
_FDT_END = 9


def is_dtb(data: bytes) -> bool:
    return len(data) >= 40 and struct.unpack_from(">I", data, 0)[0] == _FDT_MAGIC


def _cstr(buf: bytes, off: int) -> bytes:
    end = buf.find(b"\x00", off)
    return buf[off:end] if end >= 0 else buf[off:]


def _prop_render(val: bytes):
    """A deterministic read of a property value, plus hints for rendering. `text` is set only for a
    clean NUL-terminated printable string (or string list); `cells` for a u32 array."""
    text = None
    cells = None
    if val and val[-1] == 0 and _printable(val[:-1].replace(b"\x00", b"")):
        parts = [p.decode("latin-1") for p in val.split(b"\x00") if p]
        text = ",".join(parts) if parts else ""
    if len(val) and len(val) % 4 == 0:
        cells = list(struct.unpack(">" + "I" * (len(val) // 4), val))
    return {"raw": val, "text": text, "cells": cells}


def _dtb(data: bytes):
    if not is_dtb(data):
        return None
    (magic, totalsize, off_struct, off_strings, off_memrsv, version, last_comp,
     boot_cpu, size_strings, size_struct) = struct.unpack_from(">IIIIIIIIII", data, 0)
    if magic != _FDT_MAGIC or version < 16:
        return None
    if off_struct + size_struct > len(data) or off_strings + size_strings > len(data):
        return None
    # The structure and strings blocks must lie within the header's declared totalsize; a section
    # beyond it is not a structurally-complete tree, so the parse must not report it as complete.
    if off_struct + size_struct > totalsize or off_strings + size_strings > totalsize:
        return None
    sb = data[off_struct:off_struct + size_struct]
    strings = data[off_strings:off_strings + size_strings]
    out = {"name": None, "kind": "dtb", "complete": False, "version": version, "nodes": [], "properties": {}}
    stack = []
    i = 0
    depth = 0
    while i + 4 <= len(sb):
        tok = struct.unpack_from(">I", sb, i)[0]
        i += 4
        if tok == _FDT_BEGIN_NODE:
            name = _cstr(sb, i)
            i += (len(name) + 1 + 3) & ~3
            depth += 1
            if depth > MAX_DEPTH:
                break
            if not stack:
                path = "/"
            else:
                nm = name.decode("latin-1")
                path = (stack[-1].rstrip("/") + "/" + nm) if stack[-1] != "/" else "/" + nm
            stack.append(path)
            out["nodes"].append(path)
        elif tok == _FDT_END_NODE:
            if stack:
                stack.pop()
            depth -= 1
        elif tok == _FDT_PROP:
            if i + 8 > len(sb):
                break
            plen, nameoff = struct.unpack_from(">II", sb, i)
            i += 8
            val = sb[i:i + plen]
            i += (plen + 3) & ~3
            if len(val) != plen or nameoff >= len(strings):
                break
            pname = _cstr(strings, nameoff).decode("latin-1")
            path = stack[-1] if stack else "/"
            out["properties"].setdefault(path, {})[pname] = _prop_render(val)
        elif tok == _FDT_NOP:
            continue
        elif tok == _FDT_END:
            out["complete"] = not stack
            break
        else:
            break
    return out


# ---- U-Boot environment -----------------------------------------------------------------------------

def _looks_like_env(body: bytes) -> bool:
    head = body[:4096]
    if b"=" not in head:
        return False
    first = head.split(b"\x00", 1)[0]
    return b"=" in first and _printable(first.replace(b"=", b""))


def _uboot_env(data: bytes):
    """Validate the leading CRC32 over the key=value area, then read the variables. A CRC mismatch
    leaves the values unread (crc_valid False, no vars). Handles the non-redundant (crc+data) and
    redundant (crc+flags+data) layouts; the CRC always covers everything after the header."""
    if len(data) < 6:
        return None
    stored = struct.unpack_from("<I", data, 0)[0]
    candidates = [(4, False, data[4:]), (5, True, data[5:])]
    chosen = None
    for hdr, redundant, body in candidates:
        if not _looks_like_env(body):
            continue
        valid = crc32_std(body) == stored
        if chosen is None or (valid and not chosen[0]):
            chosen = (valid, redundant, body)
        if valid:
            break
    if chosen is None:
        return None
    valid, redundant, body = chosen
    names, values = _env_pairs(body, valid)
    return {"name": None, "kind": "uboot_env", "crc_valid": bool(valid), "redundant": redundant,
            "vars": values, "names": names}


def _env_pairs(body: bytes, valid: bool):
    """(names, {name: value}) of one env data area. A value is read ONLY behind a good CRC."""
    names, values = [], {}
    for pair in body.split(b"\x00"):
        if pair == b"":
            break                                           # double NUL terminates the env
        if b"=" not in pair:
            continue
        k, _, v = pair.partition(b"=")
        try:
            kn = k.decode("ascii")
        except UnicodeDecodeError:
            continue
        names.append(kn)
        if valid:
            values[kn] = v.decode("latin-1")
    return names, values


# ---- redundant U-Boot environment: split the copies, pick the live one (B-069) ----------------------

MAX_ENV_SCAN = 64 * 1024 * 1024         # bytes of one region searched for env copies
MAX_ENV_SPAN = 1024 * 1024              # the longest env data area a CRC is tried over
MAX_ENV_HEADS = 128                     # variable chains tried as the start of a copy
MAX_ENV_COPIES = 16                     # CRC-valid copies listed
MAX_ENV_INVALID = 8                     # chains no CRC confirms that are listed (the rest are counted)
MAX_ENV_NEXT = 64                       # following chains whose start can end the copy in front

# One `name=value NUL` record. The name starts at a word boundary, so the search stays linear on
# text. Header bytes (the CRC, the flags) that are themselves name characters are taken into the
# first name: env_copies tries the data area at each of the first six bytes of that name.
_ENV_VAR = re.compile(rb"(?<![A-Za-z0-9_.\-])[A-Za-z0-9_.\-]{1,64}=[\x20-\x7e]*\x00")
_ENV_HEADER = 5                         # crc32 + flags: the most header a first name can have swallowed


def _env_chains(data: bytes):
    """(start, end, count) of every run of back-to-back `name=value NUL` records."""
    chains, cur = [], None
    for m in _ENV_VAR.finditer(data, 0, min(len(data), MAX_ENV_SCAN)):
        if cur is not None and m.start() == cur[1]:
            cur[1], cur[2] = m.end(), cur[2] + 1
            continue
        if cur is not None:
            chains.append(tuple(cur))
        cur = [m.start(), m.end(), 1]
    if cur is not None:
        chains.append(tuple(cur))
    return chains


def env_copies(data: bytes, base: int = 0, notes: list = None) -> list:
    """Every U-Boot environment copy in a region, wherever it starts: the split of a redundant env.

    A copy is `crc32 | [flags] | name=value NUL ... NUL | padding`. Its length is not stored, so each
    chain of variables is tried against the CRC word in front of it over every end a copy can have
    (the terminator, the end of the padding, the start of the next chain, the middle and end of the
    region, a power-of-two size); the shortest end the CRC confirms is the copy. Returns, in offset
    order, {offset, data_offset, end, size, crc_valid, crc_endian, redundant, flags, names, vars}.
    A chain of two or more variables no CRC confirms is listed with crc_valid False, its names and
    NO values (offset/end/size/flags None): a value is never read behind a bad CRC. `base` is added
    to every offset. A cap that cut the search or the listing short is named in `notes`."""
    if not isinstance(data, (bytes, bytearray)):
        return []
    data = bytes(data)
    n = len(data)
    if n > MAX_ENV_SCAN and notes is not None:
        notes.append(f"env search covered the first {MAX_ENV_SCAN} of {n} bytes")
    chains = _env_chains(data)
    starts = [c[0] for c in chains]
    copies, covered, tried, good, unlisted = [], 0, 0, 0, 0
    for index, (first, last, count) in enumerate(chains):
        if first < covered:
            continue                                        # inside a copy already confirmed
        if tried >= MAX_ENV_HEADS or good >= MAX_ENV_COPIES:
            if notes is not None:
                notes.append(f"env search stopped at offset {base + first:#x}: "
                             f"{tried} variable chains tried, {good} valid copies found")
            break
        tried += 1
        following = starts[index + 1:index + 1 + MAX_ENV_NEXT]
        term = last + 1 if data[last:last + 1] == b"\x00" else last
        pad = term
        if pad < n and data[pad] in (0x00, 0xFF):
            fill = data[pad]
            while pad < n and data[pad] == fill:
                pad += 1
        found = None
        # The data area starts at the chain, or up to five bytes into its first name when header
        # bytes read as name characters. One CRC pass per start serves both header layouts.
        for body in range(first, min(first + _ENV_HEADER + 1, data.index(b"=", first))):
            limit = min(n, body + MAX_ENV_SPAN)
            ends = {term, pad, n, n // 2}
            # the header of the next copy: 4 or 5 bytes in front of its data, which starts at the next
            # chain or up to five bytes into it
            ends.update(s + k for s in following for k in range(-_ENV_HEADER, 2))
            ends.update(body - hdr + (1 << k) for k in range(6, 24) for hdr in (4, 5))
            crc, at = 0, body
            for end in sorted(e for e in ends if term <= e <= limit):
                crc = zlib.crc32(data[at:end], crc) & 0xFFFFFFFF
                at = end
                for hdr in (5, 4):                          # crc+flags+data, then crc+data
                    head = body - hdr
                    if head < covered:
                        continue
                    stored = data[head:head + 4]
                    endian = ("little" if crc == int.from_bytes(stored, "little") else
                              "big" if crc == int.from_bytes(stored, "big") else None)
                    if endian:
                        found = (head, body, end, hdr == 5, data[body - 1] if hdr == 5 else None, endian)
                        break
                if found:
                    break
            if found:
                break
        if found:
            head, body, end, redundant, flags, endian = found
            names, values = _env_pairs(data[body:end], True)
            copies.append({"offset": base + head, "data_offset": base + body, "end": base + end,
                           "size": end - head, "crc_valid": True, "crc_endian": endian,
                           "redundant": redundant, "flags": flags, "names": names, "vars": values})
            covered = end
            good += 1
        elif count >= 2 and len(copies) - good >= MAX_ENV_INVALID:
            unlisted += 1
        elif count >= 2:
            names, _ = _env_pairs(data[first:term], False)
            copies.append({"offset": None, "data_offset": base + first, "end": None, "size": None,
                           "crc_valid": False, "crc_endian": None, "redundant": None, "flags": None,
                           "names": names, "vars": {}})
    if unlisted and notes is not None:
        notes.append(f"{unlisted} further variable chains with no valid CRC are not listed")
    return copies


def pick_live_env(copies):
    """(index, reason) of the live copy, or (None, reason). Only a CRC-valid copy can be live. With
    two valid redundant copies U-Boot's own rule decides (env_check_redund): flags 0 beats 255 (the
    counter wrapped), else the higher flags counter, and equal flags keep the first copy."""
    valid = [i for i, c in enumerate(copies or []) if c.get("crc_valid")]
    if not valid:
        return None, "no copy has a valid CRC"
    if len(valid) == 1:
        return valid[0], "the only copy with a valid CRC"
    counted = [i for i in valid if copies[i].get("redundant") and copies[i].get("flags") is not None]
    if len(counted) < 2:
        return valid[0], "several valid copies but fewer than two carry a flags byte: the first is taken"
    a, b = counted[0], counted[1]
    fa, fb = copies[a]["flags"], copies[b]["flags"]
    extra = "" if len(counted) == 2 else f" ({len(counted) - 2} further valid copies not compared)"
    if fa == 255 and fb == 0:
        return b, "flags counter wrapped (255 -> 0): the copy with flags 0 is newer" + extra
    if fb == 255 and fa == 0:
        return a, "flags counter wrapped (255 -> 0): the copy with flags 0 is newer" + extra
    if fa == fb:
        return a, f"both copies carry flags {fa}: U-Boot keeps the first" + extra
    live = a if fa > fb else b
    return live, f"higher flags counter ({max(fa, fb)} over {min(fa, fb)})" + extra


def _split_env(data: bytes):
    """The env image of a region the single-env read did not validate: its copies and the live one."""
    notes = []
    copies = env_copies(data, notes=notes)
    live, why = pick_live_env(copies)
    if live is None:
        return None
    c = copies[live]
    return {"name": None, "kind": "uboot_env", "crc_valid": True, "redundant": bool(c["redundant"]),
            "vars": dict(c["vars"]), "names": list(c["names"]), "copies": copies, "live": live,
            "live_reason": why, "notes": notes}


# ---- the top-level walk -----------------------------------------------------------------------------

def _detect_and_walk(name, data):
    for parser in (_squashfs, _jffs2, _ubi, _dtb):
        try:
            img = parser(data)
        except Exception:
            img = None
        if img is not None:
            img["name"] = name
            return img
    try:
        env = _uboot_env(data)
    except Exception:
        env = None
    if env is None or not env.get("crc_valid"):
        try:
            split = _split_env(data)
        except Exception:
            split = None
        if split is not None:
            env = split
    if env is not None:
        env["name"] = name
    return env


def walk(files) -> dict:
    """Every firmware container found across the delivery's members. `files` is {name: bytes}."""
    if not isinstance(files, dict):
        return {"images": []}
    images = []
    for name in list(files or {}):
        if len(images) >= MAX_IMAGES:
            break
        data = files.get(name)
        if not isinstance(data, (bytes, bytearray)) or len(data) < 6:
            continue
        img = _detect_and_walk(name, bytes(data))
        if img is not None:
            images.append(img)
    return {"images": images}


# ---- signals ----------------------------------------------------------------------------------------

_FW_WORDS = ("squashfs", "jffs2", "ubifs", "ubi ", "device tree", "devicetree", "dtb", "fdt", "u-boot",
             "uboot", "firmware", "flash", "rootfs", "bootargs", "bootcmd", "environment variable", "fit image")


def signals(questions, files) -> float:
    score = 0.0
    for name, data in (files or {}).items():
        if not isinstance(data, (bytes, bytearray)):
            continue
        b = bytes(data)
        if is_squashfs(b) or is_jffs2(b) or is_ubi(b) or is_ubifs(b) or is_dtb(b):
            score = max(score, 0.85)
        elif len(b) >= 6:
            try:
                if _uboot_env(b) is not None:
                    score = max(score, 0.6)
            except Exception:
                pass
    asked = 0
    for q in questions or []:
        t = (q.get("question") or q.get("text") or "").lower()
        if any(w in t for w in _FW_WORDS):
            asked += 1
    if asked:
        score = max(score, 0.4 + 0.3 * min(1.0, asked / max(1, len(questions or []))))
    return round(max(0.0, min(1.0, score)), 3)


# ---- solve_set (the runner contract, never-guess) --------------------------------------------------

_SIZE_WORDS = ("size", "bytes", "length", "how big", "how large")
_NAME_WORDS = ("name", "called", "filename", "file name")
_PATH_WORDS = ("path", "full path", "located", "location", "where")


def _index(images):
    by_name = {}        # bare name -> list of (size, path, content_present)
    by_path = {}
    env = None
    dtb_props = {}      # (path, prop) -> render ; also prop-only index
    for img in images:
        if img["kind"] in ("squashfs", "jffs2", "ubi", "ubifs"):
            for e in img.get("entries", []):
                by_name.setdefault(e["name"].lower(), []).append(e)
                by_path[e["path"].lower()] = e
        elif img["kind"] == "dtb":
            for path, props in img.get("properties", {}).items():
                for pname, render in props.items():
                    dtb_props[(path.lower(), pname.lower())] = render
                    dtb_props.setdefault(("*", pname.lower()), []).append(render) if False else None
        elif img["kind"] == "uboot_env":
            env = img
    return by_name, by_path, env, dtb_props


def _answer(q, images):
    t = (q.get("question") or q.get("text") or "").lower()
    member = (q.get("member") or "").lower()
    if not t:
        return None
    if "flag" in t or "proof" in t or "secret" in t or "password" in t:
        return None                                         # text-is-data: never submitted

    by_name, by_path, env, dtb_props = _index(images)

    # U-Boot environment variable value (plain only behind a validated CRC).
    if env is not None and ("environment" in t or "u-boot" in t or "uboot" in t
                            or "env var" in t or "variable" in t or "bootargs" in t or "bootcmd" in t):
        hit = [n for n in env.get("names", []) if n and n.lower() in t]
        if len(hit) == 1:
            name = hit[0]
            if env.get("crc_valid") and name in env.get("vars", {}):
                return env["vars"][name]                     # PLAIN: a validated env value is exact bytes
            return None                                      # CRC mismatch, or value absent

    # Device-tree property value. A property NAME can occur in many nodes (compatible, reg,
    # status, #address-cells, ...); the question matches by name alone, so a plain answer is
    # given ONLY when every node that carries the named property agrees on one value. Any
    # disagreement across nodes (or a mix of string/cell/empty renders) is ambiguous -> None,
    # never the first node's value as a guess.
    if dtb_props:
        hits = [render for (path, pname), render in dtb_props.items()
                if path != "*" and isinstance(render, dict) and pname and pname in t]
        if hits:
            texts = {r["text"] for r in hits if r.get("text") is not None}
            non_text = [r for r in hits if r.get("text") is None]
            if texts and not non_text and len(texts) == 1:
                return next(iter(texts))                      # PLAIN: one unambiguous string value
            if len(hits) == 1 and hits[0].get("cells"):
                cells = hits[0]["cells"]
                opts = [("decimal", " ".join(str(c) for c in cells)),
                        ("hex", " ".join("0x%08x" % c for c in cells))]
                return _unsure("dtb_property", "cells", opts, candidates=True)
            return None                                       # ambiguous across nodes / mixed: never guess

    # A file by name.
    matches = []
    for low, entries in by_name.items():
        if low and (low in t or (member and low in member)):
            matches.extend(entries)
    if len(matches) == 1:
        e = matches[0]
        if any(w in t for w in _SIZE_WORDS) and e.get("size") is not None:
            return e["size"]                                 # PLAIN: a size from a consistent parse
        if any(w in t for w in _PATH_WORDS):
            return _unsure("file_path", "fs", _path_options(e["path"]), candidates=True)
        if any(w in t for w in _NAME_WORDS):
            return e["name"]                                 # PLAIN: the exact name
    return None


def solve_set(questions, files, ctx) -> dict:
    attempt = (ctx or {}).get("attempt") if isinstance(ctx, dict) else None
    _ = isinstance(attempt, dict) and bool(attempt) and not attempt.get("deadline")
    partial = ctx.get("partial") if isinstance(ctx, dict) and isinstance(ctx.get("partial"), dict) else None
    deadline = time.monotonic() + (BUDGET_UNTIMED if _ else BUDGET)
    try:
        result = walk(files or {})
    except Exception:
        result = {"images": []}
    images = result.get("images", [])
    out = {}
    for q in questions or []:
        qid = q.get("qid") or q.get("id") or q.get("answer_id")
        try:
            out[qid] = _answer(q, images) if time.monotonic() < deadline else None
        except Exception:
            out[qid] = None
        if partial is not None and out.get(qid) is not None:
            partial[qid] = out[qid]
    return out


# ---- the command ------------------------------------------------------------------------------------

def _read_paths(paths):
    files = {}
    for p in paths:
        p = Path(p)
        if p.is_dir():
            for c in sorted(p.rglob("*")):
                if c.is_file():
                    files[str(c.relative_to(p))] = c.read_bytes()
        elif p.is_file():
            files[p.name] = p.read_bytes()
    return files


def main(argv):
    if not argv:
        print(__doc__)
        return 0
    files = _read_paths(argv)
    result = walk(files)
    for img in result["images"]:
        print(f"== {img['name']}  [{img['kind']}]" + (f"  comp={img.get('compression')}" if img.get("compression") else ""))
        if img["kind"] == "dtb":
            for path, props in img.get("properties", {}).items():
                for pname, r in props.items():
                    v = r["text"] if r["text"] is not None else (r["cells"] if r["cells"] is not None else r["raw"].hex())
                    print(f"   {path} :: {pname} = {v}")
        elif img["kind"] == "uboot_env":
            print(f"   crc_valid={img['crc_valid']} redundant={img['redundant']}")
            for i, c in enumerate(img.get("copies", [])):
                where = "?" if c["offset"] is None else f"{c['offset']:#x}"
                print(f"   copy {i} @{where} crc_valid={c['crc_valid']} flags={c['flags']}"
                      + (f"  LIVE: {img['live_reason']}" if i == img.get("live") else ""))
            for k in img.get("names", []):
                print(f"   {k} = {img['vars'].get(k) if img['crc_valid'] else '<crc invalid: None>'}")
        else:
            for e in img.get("entries", []):
                size = "" if e.get("size") is None else f"  {e['size']}B"
                body = "" if e.get("content") is not None or e["type"] == "dir" else f"  (content None: {e.get('reason')})"
                print(f"   {e['type']:4} {e['path']}{size}{body}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
