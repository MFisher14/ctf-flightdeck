#!/usr/bin/env python3
"""Small disk and dump containers for solvers/toolkits/carve_stego.py. Plain Python, read-only,
bytes in and lists out; nothing here mounts, executes or writes anything.

  iso9660(data)      [entry]  ISO9660 (Joliet names when the image has them)
  fat(data)          [entry]  FAT12/16/32 with long names, deleted entries (0xE5) and their bytes
                              when the clusters are still there (contiguous from the first one)
  ext2(data)         [entry]  ext2/3 (block maps) and simple ext4 extents; names left in the slack
                              of a directory block are listed as deleted
  cpio(data)         [entry]  newc/crc ("070701"/"070702"), odc ("070707"), old binary
  uimage(data)       dict     the 64-byte U-Boot legacy header, both CRCs checked, the payload
  recycle_i(data)    dict     a Recycle Bin $I record (version 1 and 2)
  minidump(data)     dict     MDMP stream table, modules, threads, memory ranges, system info
  elf_core(data)     dict     ELF core notes through pyelftools (process name, arguments, files)
  walk(data)         (kind, [entry]) the first of the above file systems the bytes are

An entry is {"path", "size", "dir", "deleted", "data" (bytes or None), "mtime" (text or None)}.
Every reader returns None (or raises ValueError, caught by walk) on bytes that are not its
format, and stops at fixed limits (MAX_ENTRIES, MAX_FILE): a hostile image costs a bounded time.
"""
import struct
import zlib
from datetime import datetime, timedelta, timezone

MAX_ENTRIES = 5000
MAX_FILE = 32 * 1024 * 1024
MAX_DEPTH = 16


def _entry(path, size, is_dir=False, deleted=False, data=None, mtime=None, **more) -> dict:
    return {"path": path, "size": size, "dir": is_dir, "deleted": deleted, "data": data, "mtime": mtime, **more}


# ---- ISO9660 ----------------------------------------------------------------------------------------

def is_iso9660(data: bytes) -> bool:
    return len(data) >= 0x8800 + 6 and data[0x8001:0x8006] == b"CD001"


def iso9660(data: bytes):
    if not is_iso9660(data):
        return None
    root, joliet, block = None, False, 2048
    for sector in range(16, 48):
        vd = data[sector * 2048:(sector + 1) * 2048]
        if len(vd) < 2048 or vd[1:6] != b"CD001" or vd[0] == 255:
            break
        if vd[0] == 1 and root is None:
            block = struct.unpack_from("<H", vd, 128)[0] or 2048
            root = vd[156:190]
        elif vd[0] == 2 and vd[88:91] in (b"%/@", b"%/C", b"%/E"):
            root, joliet = vd[156:190], True
    if root is None:
        return None
    out, seen = [], set()

    def walk(lba, length, prefix, depth):
        if depth > MAX_DEPTH or lba in seen or len(out) >= MAX_ENTRIES:
            return
        seen.add(lba)
        raw = data[lba * block:lba * block + min(length, 8 * 1024 * 1024)]
        i = 0
        while i < len(raw):
            n = raw[i]
            if n == 0:                      # records do not cross a sector: skip to the next one
                i = (i // block + 1) * block
                continue
            rec = raw[i:i + n]
            i += n
            if len(rec) < 34:
                break
            ext, size = struct.unpack_from("<I", rec, 2)[0], struct.unpack_from("<I", rec, 10)[0]
            flags, nlen = rec[25], rec[32]
            name_raw = rec[33:33 + nlen]
            if name_raw in (b"\x00", b"\x01"):
                continue
            name = name_raw.decode("utf-16-be", "replace") if joliet else name_raw.decode("latin-1")
            if not joliet:                  # a Rock Ridge NM entry carries the real name
                su = rec[33 + nlen + (1 - nlen % 2):]
                j = 0
                while j + 4 <= len(su):
                    sig, ln = su[j:j + 2], su[j + 2]
                    if ln < 4:
                        break
                    if sig == b"NM" and ln > 5:
                        name = su[j + 5:j + ln].decode("utf-8", "replace")
                    j += ln
            name = name.split(";")[0].rstrip(".") if not (flags & 2) else name
            y, mo, d, h, mi, s = rec[18:24]
            mtime = f"{1900 + y:04d}-{mo:02d}-{d:02d}T{h:02d}:{mi:02d}:{s:02d}" if mo else None
            path = prefix + name
            if flags & 2:
                out.append(_entry(path, 0, True, mtime=mtime))
                walk(ext, size, path + "/", depth + 1)
            else:
                body = data[ext * block:ext * block + size] if size <= MAX_FILE else None
                out.append(_entry(path, size, data=body, mtime=mtime, offset=ext * block))
            if len(out) >= MAX_ENTRIES:
                return

    walk(struct.unpack_from("<I", root, 2)[0], struct.unpack_from("<I", root, 10)[0], "", 0)
    return out


# ---- FAT12/16/32 ------------------------------------------------------------------------------------

def _fat_bpb(data: bytes):
    if len(data) < 512 or data[510:512] != b"\x55\xaa" and data[0] not in (0xEB, 0xE9):
        return None
    if data[21] != 0xF0 and data[21] < 0xF8:        # the media descriptor
        return None
    bps, spc, reserved, nfats, root_entries, total16, _media, fatsz16 = struct.unpack_from("<HBHBHHBH", data, 11)
    total32 = struct.unpack_from("<I", data, 32)[0]
    fatsz32, root_cluster = struct.unpack_from("<I", data, 36)[0], struct.unpack_from("<I", data, 44)[0]
    if bps not in (512, 1024, 2048, 4096) or spc not in (1, 2, 4, 8, 16, 32, 64, 128) or nfats not in (1, 2) or not reserved:
        return None
    fatsz = fatsz16 or fatsz32
    total = total16 or total32
    if not fatsz or not total:
        return None
    root_sectors = (root_entries * 32 + bps - 1) // bps
    first_data = reserved + nfats * fatsz + root_sectors
    if first_data >= total:
        return None
    clusters = (total - first_data) // spc
    kind = "fat12" if clusters < 4085 else "fat16" if clusters < 65525 else "fat32"
    if kind == "fat32" and fatsz16:
        return None
    return {"kind": kind, "bps": bps, "spc": spc, "reserved": reserved, "nfats": nfats, "root_entries": root_entries,
            "fatsz": fatsz, "total": total, "first_data": first_data, "clusters": clusters, "root_cluster": root_cluster,
            "label": data[43:54].decode("latin-1").strip() if kind != "fat32" else data[71:82].decode("latin-1").strip()}


def is_fat(data: bytes) -> bool:
    return _fat_bpb(data) is not None


def _dos_time(date, time):
    if not date:
        return None
    try:
        return datetime((date >> 9) + 1980, (date >> 5) & 15, date & 31, time >> 11, (time >> 5) & 63,
                        min(59, (time & 31) * 2)).strftime("%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None


def fat(data: bytes, info: dict = None):
    """Entries of a FAT image. `info`, when given, is filled with the BPB facts (kind, label, ...)."""
    b = _fat_bpb(data)
    if b is None:
        return None
    if info is not None:
        info.update(b)
    bps, spc = b["bps"], b["spc"]
    fat_off = b["reserved"] * bps
    table = data[fat_off:fat_off + b["fatsz"] * bps]
    csize = bps * spc

    def nxt(c):
        try:
            if b["kind"] == "fat12":
                v = struct.unpack_from("<H", table, c + c // 2)[0]
                v = v >> 4 if c & 1 else v & 0xFFF
                return v if v < 0xFF8 else None
            if b["kind"] == "fat16":
                v = struct.unpack_from("<H", table, c * 2)[0]
                return v if v < 0xFFF8 else None
            v = struct.unpack_from("<I", table, c * 4)[0] & 0x0FFFFFFF
            return v if v < 0x0FFFFFF8 else None
        except struct.error:
            return None

    def cluster(c):
        off = (b["first_data"] + (c - 2) * spc) * bps
        return data[off:off + csize]

    def chain(c, limit):
        out, seen = [], set()
        while c is not None and 2 <= c < b["clusters"] + 2 and c not in seen and len(out) * csize < limit:
            seen.add(c)
            out.append(cluster(c))
            c = nxt(c)
        return b"".join(out)

    out = []

    def read_dir(raw, prefix, depth, parent_deleted=False):
        lfn = []
        for i in range(0, len(raw) - 31, 32):
            e = raw[i:i + 32]
            first, attr = e[0], e[11]
            if first == 0:
                break
            deleted = first == 0xE5
            if attr & 0x3F == 0x0F:                     # a long-name piece (kept for a deleted entry too)
                chars = e[1:11] + e[14:26] + e[28:32]
                lfn.insert(0, chars)
                continue
            long_name = None
            if lfn:
                text = b"".join(lfn).decode("utf-16-le", "replace").split("\x00")[0].rstrip("￿")
                long_name = text or None
                lfn = []
            if attr & 0x08:                             # the volume label
                if depth == 0 and not deleted and info is not None and "dir_label" not in info:
                    info["dir_label"] = e[0:11].decode("cp437", "replace").strip()
                continue
            base, ext = e[0:8], e[8:11]
            if deleted:
                base = b"_" + base[1:]
            elif first == 0x05:
                base = b"\xe5" + base[1:]
            short = base.decode("cp437", "replace").rstrip()
            if e[12] & 0x08:
                short = short.lower()
            sext = ext.decode("cp437", "replace").rstrip()
            if e[12] & 0x10:
                sext = sext.lower()
            short = short + ("." + sext if sext else "")
            if short in (".", ".."):
                continue
            name = long_name or short
            hi, time, date, lo, size = struct.unpack_from("<H", e, 20)[0], *struct.unpack_from("<HHHI", e, 22)
            start = lo | (hi << 16 if b["kind"] == "fat32" else 0)
            path = prefix + name
            is_dir = bool(attr & 0x10)
            gone = deleted or parent_deleted
            body = None
            if not is_dir and size <= MAX_FILE:
                if size == 0:
                    body = b""
                elif not gone:
                    body = chain(start, size)[:size]
                elif 2 <= start < b["clusters"] + 2:    # a deleted file: its chain is gone, the clusters may not be
                    off = (b["first_data"] + (start - 2) * spc) * bps
                    body = data[off:off + size]
                    span = range(start, start + (size + csize - 1) // csize)
                    # a cluster given to another file since (its FAT entry is not 0) holds that file's bytes
                    body = body if len(body) == size and span[-1] < b["clusters"] + 2 and all(nxt(c) == 0 for c in span) else None
            out.append(_entry(path, size, is_dir, gone, body, _dos_time(date, time), short=short, cluster=start,
                              attr=attr))
            if len(out) >= MAX_ENTRIES:
                return
            if is_dir and depth < MAX_DEPTH and 2 <= start < b["clusters"] + 2:
                sub = cluster(start) if gone else chain(start, 4 * 1024 * 1024)
                read_dir(sub, path + "/", depth + 1, gone)

    if b["kind"] == "fat32":
        root = chain(b["root_cluster"], 8 * 1024 * 1024)
    else:
        off = (b["reserved"] + b["nfats"] * b["fatsz"]) * bps
        root = data[off:off + b["root_entries"] * 32]
    read_dir(root, "", 0)
    return out


# ---- ext2/3/4 ---------------------------------------------------------------------------------------

def is_ext(data: bytes) -> bool:
    return len(data) >= 2048 and data[1024 + 56:1024 + 58] == b"\x53\xef"


def ext2(data: bytes, info: dict = None):
    if not is_ext(data):
        return None
    sb = data[1024:2048]
    inodes_count, blocks_count = struct.unpack_from("<II", sb, 0)
    first_data_block, log_bs = struct.unpack_from("<II", sb, 20)
    blocks_per_group, _, inodes_per_group = struct.unpack_from("<III", sb, 32)
    rev = struct.unpack_from("<I", sb, 76)[0]
    inode_size = struct.unpack_from("<H", sb, 88)[0] if rev >= 1 else 128
    incompat = struct.unpack_from("<I", sb, 96)[0] if rev >= 1 else 0
    if log_bs > 6 or not inodes_per_group or not blocks_per_group or inode_size < 128:
        return None
    bs = 1024 << log_bs
    desc_size = struct.unpack_from("<H", sb, 254)[0] if incompat & 0x80 else 32
    desc_size = desc_size if desc_size >= 32 else 32
    gdt = (first_data_block + 1) * bs
    compat = struct.unpack_from("<I", sb, 92)[0] if rev >= 1 else 0
    version = "ext4" if incompat & 0x2C0 else "ext3" if compat & 0x4 else "ext2"   # extents, 64bit, flex_bg; journal
    if info is not None:
        info.update({"kind": "ext", "version": version, "block_size": bs, "inodes": inodes_count, "blocks": blocks_count,
                     "label": sb[120:136].split(b"\x00")[0].decode("latin-1"), "uuid": sb[104:120].hex()})

    def block(n):
        return data[n * bs:(n + 1) * bs] if n else b"\x00" * bs

    def inode(n):
        if not 1 <= n <= inodes_count:
            return None
        g, idx = divmod(n - 1, inodes_per_group)
        d = data[gdt + g * desc_size:gdt + (g + 1) * desc_size]
        if len(d) < 32:
            return None
        table = struct.unpack_from("<I", d, 8)[0]
        if desc_size >= 64 and len(d) >= 44:
            table |= struct.unpack_from("<I", d, 40)[0] << 32
        raw = data[table * bs + idx * inode_size:table * bs + (idx + 1) * inode_size]
        return raw if len(raw) >= 128 else None

    def content(raw, limit=MAX_FILE):
        mode, size = struct.unpack_from("<H", raw, 0)[0], struct.unpack_from("<I", raw, 4)[0]
        size |= struct.unpack_from("<I", raw, 108)[0] << 32 if mode & 0xF000 == 0x8000 else 0
        if size > limit:
            return None
        flags = struct.unpack_from("<I", raw, 32)[0]
        ib = raw[40:100]
        if mode & 0xF000 == 0xA000 and size < 60:      # a fast symlink: the target is in the inode
            return ib[:size]
        if flags & 0x10000000:                          # inline data
            return ib[:size]
        want = (size + bs - 1) // bs
        chunks = {}
        if flags & 0x80000:                             # extents

            def ext_node(node, depth):
                if depth > 5 or len(node) < 12:
                    return
                magic, entries, _, d = struct.unpack_from("<HHHH", node, 0)
                if magic != 0xF30A:
                    return
                for i in range(min(entries, (len(node) - 12) // 12)):
                    e = node[12 + i * 12:24 + i * 12]
                    if d == 0:
                        lblk, ln, hi, lo = struct.unpack_from("<IHHI", e, 0)
                        ln = ln - 32768 if ln > 32768 else ln
                        for k in range(min(ln, want)):
                            if lblk + k < want:
                                chunks[lblk + k] = (hi << 32 | lo) + k
                    else:
                        _, lo, hi = struct.unpack_from("<IIH", e, 0)
                        ext_node(block(hi << 32 | lo), depth + 1)
            ext_node(ib, 0)
        else:
            ptrs = list(struct.unpack_from("<15I", ib, 0))
            blocks = ptrs[:12]

            def indirect(n, level):
                if not n or len(blocks) >= want:
                    return
                for p in struct.unpack_from(f"<{bs // 4}I", block(n).ljust(bs, b"\x00"), 0):
                    if len(blocks) >= want:
                        return
                    if level == 1:
                        blocks.append(p)
                    else:
                        indirect(p, level - 1) if p else blocks.extend([0] * min((bs // 4) ** (level - 1), want - len(blocks)))
            for level, p in enumerate(ptrs[12:15], 1):
                indirect(p, level)
            chunks = dict(enumerate(blocks[:want]))
        return b"".join(block(chunks.get(i, 0)).ljust(bs, b"\x00") for i in range(want))[:size]

    out, seen, live = [], set(), set()

    def dirents(raw):
        """(inode, name, type, deleted) of a directory's bytes, with the names left in the slack."""
        for base in range(0, len(raw), bs):
            blk = raw[base:base + bs]
            i = 0
            while i + 8 <= len(blk):
                ino, rec, nlen, ftype = struct.unpack_from("<IHBB", blk, i)
                if rec < 8 or i + rec > len(blk):
                    break
                if ino and nlen:
                    yield ino, blk[i + 8:i + 8 + nlen].decode("utf-8", "replace"), ftype, False
                used = (8 + nlen + 3) & ~3 if ino else 8
                j = i + used
                while j + 8 <= i + rec:                 # the slack: what a removed entry leaves behind
                    ino2, rec2, nlen2, ftype2 = struct.unpack_from("<IHBB", blk, j)
                    need = (8 + nlen2 + 3) & ~3
                    name2 = blk[j + 8:j + 8 + nlen2]
                    if (0 < ino2 <= inodes_count and nlen2 and need <= rec2 <= i + rec - j and ftype2 <= 7
                            and all(32 <= c < 127 or c >= 128 for c in name2) and name2 not in (b".", b"..")):
                        yield ino2, name2.decode("utf-8", "replace"), ftype2, True
                        j += need
                    else:
                        j += 4
                i += rec

    def walk(ino, prefix, depth):
        if ino in seen or depth > MAX_DEPTH:
            return
        seen.add(ino)
        raw = inode(ino)
        body = content(raw, 8 * 1024 * 1024) if raw else None
        ents = list(dirents(body or b""))
        live.update(c for c, n, _t, gone in ents if not gone and n not in (".", ".."))
        for child, name, _ftype, deleted in ents:
            if name in (".", "..") or len(out) >= MAX_ENTRIES:
                continue
            craw = inode(child)
            if craw is None:
                continue
            mode, size = struct.unpack_from("<H", craw, 0)[0], struct.unpack_from("<I", craw, 4)[0]
            mtime, dtime = struct.unpack_from("<I", craw, 16)[0], struct.unpack_from("<I", craw, 20)[0]
            is_dir = mode & 0xF000 == 0x4000
            path = prefix + name
            stamp = datetime.fromtimestamp(mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if mtime else None
            data_ = None
            links = struct.unpack_from("<H", craw, 26)[0]
            # a slack name whose inode is in use (never freed: a rename; or freed and given to another file)
            stale = bool(deleted and (child in live or (links and not dtime)))
            if not is_dir and mode & 0xF000 in (0x8000, 0xA000) and not stale and (not deleted or (size and any(craw[40:100]))):
                data_ = content(craw)       # a removed ext2 inode often keeps its block pointers
            out.append(_entry(path, size, is_dir, deleted, data_, stamp, inode=child, mode=mode, dtime=dtime, stale=stale))
            if is_dir and not deleted:
                walk(child, path + "/", depth + 1)

    walk(2, "", 0)
    return out


# ---- cpio -------------------------------------------------------------------------------------------

def is_cpio(data: bytes) -> bool:
    return data[:6] in (b"070701", b"070702", b"070707") or data[:2] in (b"\xc7\x71", b"\x71\xc7")


def cpio(data: bytes):
    if not is_cpio(data):
        return None
    out, i = [], 0
    try:
        while i < len(data) and len(out) < MAX_ENTRIES:
            head = data[i:i + 6]
            if head in (b"070701", b"070702"):
                f = [int(data[i + 6 + 8 * k:i + 14 + 8 * k], 16) for k in range(13)]
                mode, mtime, size, nlen = f[1], f[5], f[6], f[11]
                name_at = i + 110
                body_at = (name_at + nlen + 3) & ~3
                nxt = (body_at + size + 3) & ~3
            elif head == b"070707":
                f = data[i + 6:i + 76]
                mode, mtime, nlen, size = int(f[12:18], 8), int(f[42:53], 8), int(f[53:59], 8), int(f[59:70], 8)
                name_at = i + 76
                body_at = name_at + nlen
                nxt = body_at + size
            elif data[i:i + 2] in (b"\xc7\x71", b"\x71\xc7"):
                e = "<" if data[i:i + 2] == b"\xc7\x71" else ">"
                h = struct.unpack_from(e + "13H", data, i)
                mode, mtime, nlen, size = h[3], h[8] << 16 | h[9], h[10], h[11] << 16 | h[12]
                name_at = i + 26
                body_at = name_at + nlen + (nlen & 1)
                nxt = body_at + size + (size & 1)
            else:
                break
            name = data[name_at:name_at + nlen].split(b"\x00")[0].decode("utf-8", "replace")
            if name == "TRAILER!!!":
                break
            is_dir = mode & 0o170000 == 0o040000
            stamp = datetime.fromtimestamp(mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if mtime else None
            out.append(_entry(name, size, is_dir, False, None if is_dir or size > MAX_FILE else data[body_at:body_at + size],
                              stamp, mode=mode))
            if nxt <= i:
                break
            i = nxt
    except (ValueError, struct.error):
        pass
    return out


# ---- U-Boot legacy image ----------------------------------------------------------------------------

_UI_OS = {0: "invalid", 1: "openbsd", 2: "netbsd", 3: "freebsd", 4: "4_4bsd", 5: "linux", 6: "svr4", 7: "esix",
          8: "solaris", 9: "irix", 10: "sco", 11: "dell", 12: "ncr", 13: "lynxos", 14: "vxworks", 15: "psos", 16: "qnx",
          17: "u-boot", 18: "rtems", 19: "artos", 20: "unity", 21: "integrity"}
_UI_ARCH = {0: "invalid", 1: "alpha", 2: "arm", 3: "x86", 4: "ia64", 5: "mips", 6: "mips64", 7: "powerpc", 8: "s390",
            9: "sh", 10: "sparc", 11: "sparc64", 12: "m68k", 13: "nios", 14: "microblaze", 15: "nios2", 16: "blackfin",
            17: "avr32", 18: "st200", 19: "sandbox", 20: "nds32", 21: "openrisc", 22: "arm64", 23: "arc", 24: "x86_64",
            25: "xtensa", 26: "riscv"}
_UI_TYPE = {0: "invalid", 1: "standalone", 2: "kernel", 3: "ramdisk", 4: "multi", 5: "firmware", 6: "script",
            7: "filesystem", 8: "flat_dt"}
_UI_COMP = {0: "none", 1: "gzip", 2: "bzip2", 3: "lzma", 4: "lzo", 5: "lz4", 6: "zstd"}


def uimage(data: bytes):
    if data[:4] != b"\x27\x05\x19\x56" or len(data) < 64:
        return None
    _, hcrc, when, size, load, entry, dcrc, os_, arch, typ, comp = struct.unpack_from(">7I4B", data, 0)
    payload = data[64:64 + size]
    return {"name": data[32:64].split(b"\x00")[0].decode("latin-1"), "size": size, "load": load, "entry": entry,
            "time": datetime.fromtimestamp(when, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "os": _UI_OS.get(os_, str(os_)), "arch": _UI_ARCH.get(arch, str(arch)), "type": _UI_TYPE.get(typ, str(typ)),
            "compression": _UI_COMP.get(comp, str(comp)),
            "header_crc_ok": zlib.crc32(data[:4] + b"\x00\x00\x00\x00" + data[8:64]) & 0xFFFFFFFF == hcrc,
            "data_crc_ok": len(payload) == size and zlib.crc32(payload) & 0xFFFFFFFF == dcrc, "data": payload}


# ---- Recycle Bin $I ---------------------------------------------------------------------------------

def _filetime(v):
    if not v:
        return None
    try:
        return (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=v // 10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except OverflowError:
        return None


def recycle_i(data: bytes):
    """A $I record: {"version", "size" (of the deleted file), "deleted" (UTC), "path"}; None if it is not one."""
    if len(data) < 28:
        return None
    version, size, when = struct.unpack_from("<QQQ", data, 0)
    if version == 1 and len(data) >= 24 + 4:
        path = data[24:24 + 520].decode("utf-16-le", "replace").split("\x00")[0]
    elif version == 2:
        n = struct.unpack_from("<I", data, 24)[0]
        if n > 32768 or 28 + n * 2 > len(data) + 2:
            return None
        path = data[28:28 + n * 2].decode("utf-16-le", "replace").split("\x00")[0]
    else:
        return None
    stamp = _filetime(when)
    if not path or stamp is None or not (path[1:3] == ":\\" or path.startswith("\\\\")):
        return None
    return {"version": version, "size": size, "deleted": stamp, "path": path}


# ---- minidump ---------------------------------------------------------------------------------------

_MD_STREAMS = {3: "ThreadList", 4: "ModuleList", 5: "MemoryList", 6: "Exception", 7: "SystemInfo", 8: "ThreadExList",
               9: "Memory64List", 10: "CommentA", 11: "CommentW", 12: "HandleData", 13: "FunctionTable",
               14: "UnloadedModuleList", 15: "MiscInfo", 16: "MemoryInfoList", 17: "ThreadInfoList",
               18: "HandleOperationList", 19: "Token", 21: "SystemMemoryInfo", 22: "ProcessVmCounters", 24: "ThreadNames"}
_MD_ARCH = {0: "x86", 5: "arm", 6: "ia64", 9: "amd64", 12: "arm64"}


def minidump(data: bytes):
    if data[:4] != b"MDMP" or len(data) < 32:
        return None
    _, _version, nstreams, rva, _chk, when, flags = struct.unpack_from("<IIIIIIQ", data, 0)
    out = {"time": datetime.fromtimestamp(when, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if when else None,
           "flags": flags, "streams": [], "modules": [], "threads": [], "memory": [], "system": None, "comments": []}

    def mdstring(at):
        try:
            n = struct.unpack_from("<I", data, at)[0]
            return data[at + 4:at + 4 + min(n, 4096)].decode("utf-16-le", "replace")
        except struct.error:
            return None

    for i in range(min(nstreams, 256)):
        try:
            typ, size, at = struct.unpack_from("<III", data, rva + i * 12)
        except struct.error:
            break
        out["streams"].append({"type": typ, "name": _MD_STREAMS.get(typ, f"stream_{typ}"), "size": size, "rva": at})
        try:
            if typ == 4:
                n = struct.unpack_from("<I", data, at)[0]
                for k in range(min(n, 2048)):
                    base, msize, _chk2, stamp, name_rva = struct.unpack_from("<QIIII", data, at + 4 + k * 108)
                    out["modules"].append({"base": base, "size": msize, "timestamp": stamp, "name": mdstring(name_rva)})
            elif typ == 3:
                n = struct.unpack_from("<I", data, at)[0]
                for k in range(min(n, 4096)):
                    tid, suspend, _pc, _prio, teb = struct.unpack_from("<IIIIQ", data, at + 4 + k * 48)
                    out["threads"].append({"id": tid, "suspend_count": suspend, "teb": teb})
            elif typ == 5:
                n = struct.unpack_from("<I", data, at)[0]
                for k in range(min(n, 8192)):
                    start, msize, mrva = struct.unpack_from("<QII", data, at + 4 + k * 16)
                    out["memory"].append({"start": start, "size": msize, "rva": mrva})
            elif typ == 9:
                n, base_rva = struct.unpack_from("<QQ", data, at)
                for k in range(min(n, 8192)):
                    start, msize = struct.unpack_from("<QQ", data, at + 16 + k * 16)
                    out["memory"].append({"start": start, "size": msize, "rva": base_rva})
                    base_rva += msize
            elif typ == 7:
                arch, _level, _rev, ncpu, _ptype, major, minor, build, _plat, csd = struct.unpack_from("<HHHBBIIIII", data, at)
                out["system"] = {"arch": _MD_ARCH.get(arch, str(arch)), "cpus": ncpu, "os": f"{major}.{minor}.{build}",
                                 "csd": mdstring(csd) if csd else None}
            elif typ == 10:
                out["comments"].append(data[at:at + size].split(b"\x00")[0].decode("latin-1"))
            elif typ == 11:
                out["comments"].append(data[at:at + size].decode("utf-16-le", "replace").split("\x00")[0])
        except struct.error:
            continue
    return out


# ---- ELF core ---------------------------------------------------------------------------------------

def elf_core(data: bytes):
    """Notes of an ELF core file: {"notes": [{type, name}], "process", "args", "pid", "files", "signal"}."""
    if data[:4] != b"\x7fELF" or len(data) < 20:
        return None
    endian = "<" if data[5] == 1 else ">"
    if struct.unpack_from(endian + "H", data, 16)[0] != 4:      # ET_CORE
        return None
    import io
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.segments import NoteSegment
    except ImportError:
        return None
    out = {"notes": [], "process": None, "args": None, "pid": None, "files": [], "signal": None, "segments": 0}
    try:
        elf = ELFFile(io.BytesIO(data))
        for seg in elf.iter_segments():
            if seg["p_type"] == "PT_LOAD":
                out["segments"] += 1
            if not isinstance(seg, NoteSegment):
                continue
            for note in seg.iter_notes():
                typ, desc = note["n_type"], note["n_desc"]
                out["notes"].append({"type": typ if isinstance(typ, str) else int(typ), "name": str(note["n_name"])})
                if typ == "NT_PRPSINFO":
                    def text(v):
                        return (v if isinstance(v, bytes) else bytes(v)).split(b"\x00")[0].decode("utf-8", "replace")
                    out["process"], out["args"], out["pid"] = text(desc["pr_fname"]), text(desc["pr_psargs"]), int(desc["pr_pid"])
                elif typ == "NT_FILE":
                    names = desc["filename"] if "filename" in desc else []
                    for m, name in zip(desc["Elf_Nt_File_Entry"], names):
                        out["files"].append({"start": int(m["vm_start"]), "end": int(m["vm_end"]),
                                             "name": (name if isinstance(name, bytes) else bytes(name)).decode("utf-8", "replace")})
                elif typ == "NT_PRSTATUS" and out["signal"] is None:
                    try:
                        out["signal"] = int(desc["pr_cursig"])
                    except (KeyError, TypeError):
                        pass
    except Exception:           # a note this reader cannot parse leaves what was read
        pass
    return out


# ---- partition tables ------------------------------------------------------------------------------

MBR_TYPES = {0x01: "fat12", 0x04: "fat16", 0x06: "fat16", 0x0B: "fat32", 0x0C: "fat32", 0x0E: "fat16", 0x07: "ntfs_or_exfat",
             0x82: "linux_swap", 0x83: "linux", 0x8E: "linux_lvm", 0xA5: "freebsd", 0xAF: "hfs", 0xEE: "gpt_protective",
             0xEF: "efi_system", 0x05: "extended", 0x0F: "extended", 0xFD: "linux_raid"}


def partitions(data: bytes, sector: int = 512):
    """The partition table of a whole-disk image: {scheme 'mbr'|'gpt', parts: [{index (from 1), type
    (the MBR type byte, or the GPT type GUID as text), type_name, start, size (bytes), name}]},
    only partitions that lie inside the image. None when sector 0 has no 0x55AA signature, when it
    is a file system's own boot sector (a FAT or NTFS BPB), or when no entry is usable. Extended
    (logical) partitions are listed as one entry and not walked."""
    if len(data) < 1024 or data[510:512] != b"\x55\xaa" or data[3:11] in (b"NTFS    ", b"EXFAT   ") or _fat_bpb(data):
        return None
    parts = []
    for i in range(4):
        e = data[446 + 16 * i:462 + 16 * i]
        boot, ptype, lba, count = e[0], e[4], struct.unpack_from("<I", e, 8)[0], struct.unpack_from("<I", e, 12)[0]
        if boot not in (0, 0x80):
            return None                             # code or text where a table would be
        if ptype and count and lba and lba * sector < len(data):
            parts.append({"index": i + 1, "type": ptype, "type_name": MBR_TYPES.get(ptype, f"0x{ptype:02x}"), "start": lba * sector,
                          "size": min(count * sector, len(data) - lba * sector), "name": None})
    for ext in [p for p in parts if p["type"] in (0x05, 0x0F)][:1]:
        ebr, n = ext["start"], 5                    # the chain of extended boot records: logical partitions from 5
        for _ in range(32):
            if ebr + 512 > len(data) or data[ebr + 510:ebr + 512] != b"\x55\xaa":
                break
            e0, e1 = data[ebr + 446:ebr + 462], data[ebr + 462:ebr + 478]
            lba, count = struct.unpack_from("<II", e0, 8)
            if e0[4] and count and ebr + lba * sector < len(data):
                parts.append({"index": n, "type": e0[4], "type_name": MBR_TYPES.get(e0[4], f"0x{e0[4]:02x}"),
                              "start": ebr + lba * sector, "size": min(count * sector, len(data) - ebr - lba * sector), "name": None})
                n += 1
            nxt = struct.unpack_from("<I", e1, 8)[0]
            if e1[4] not in (0x05, 0x0F) or not nxt:
                break
            ebr = ext["start"] + nxt * sector
    if any(p["type"] == 0xEE for p in parts) and data[sector:sector + 8] == b"EFI PART":
        first, n, esize = struct.unpack_from("<QII", data, sector + 72)
        gpt = []
        for i in range(min(n, 128)):
            off = first * sector + i * esize
            e = data[off:off + esize]
            if len(e) < 56 or e[:16] == b"\x00" * 16:
                continue
            a, b = struct.unpack_from("<QQ", e, 32)
            if a * sector >= len(data) or b < a:
                continue
            d1, d2, d3 = struct.unpack_from("<IHH", e, 0)
            guid = f"{d1:08x}-{d2:04x}-{d3:04x}-{e[8:10].hex()}-{e[10:16].hex()}"
            gpt.append({"index": i + 1, "type": guid, "type_name": guid, "start": a * sector,
                        "size": min((b - a + 1) * sector, len(data) - a * sector),
                        "name": e[56:128].decode("utf-16-le", "replace").split("\x00")[0] or None})
        return {"scheme": "gpt", "parts": gpt} if gpt else None
    return {"scheme": "mbr", "parts": parts} if parts else None


# ---- one way in -------------------------------------------------------------------------------------

def kind_of(data: bytes):
    """'iso9660', 'ext', 'fat12'/'fat16'/'fat32', 'cpio' or None, by the bytes."""
    if is_iso9660(data):
        return "iso9660"
    if is_ext(data):
        return "ext"
    if is_cpio(data):
        return "cpio"
    b = _fat_bpb(data) if len(data) >= 512 and data[:4] not in (b"MDMP", b"\x7fELF") else None
    return b["kind"] if b else None


def walk(data: bytes, info: dict = None):
    """(kind, entries) of the first file system the bytes are, or (None, None)."""
    kind = kind_of(data)
    try:
        if kind == "iso9660":
            return kind, iso9660(data)
        if kind == "ext":
            return kind, ext2(data, info)
        if kind == "cpio":
            return kind, cpio(data)
        if kind:
            return kind, fat(data, info)
    except (struct.error, IndexError, ValueError, RecursionError):
        return kind, None
    return None, None
