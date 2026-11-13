"""B-065: synthetic RAID material for tests/test_toolkits_raid_rebuild.py (not a test module).

Everything is built here in plain Python, from the on-disk formats and md(4)'s layout tables, and
shares no code with solvers/toolkits/raid_rebuild.py: a volume is cut into members stripe by stripe
with byte loops (no numpy, no slot formula), the md superblocks and the ext4 metadata checksums are
packed and summed by their own small routines (a bitwise CRC-32C, not the engine's table). No mdadm,
no mkfs, nothing from a challenge.
"""
from __future__ import annotations

import struct
from typing import NamedTuple

MD_MAGIC = 0xA92B4EFC
LAYOUT_NUMBER = {"left-asymmetric": 0, "right-asymmetric": 1, "left-symmetric": 2, "right-symmetric": 3}


# ---------------------------------------------------------------- cutting a volume into members

def _xor(a: bytes, b: bytes) -> bytes:
    return (int.from_bytes(a, "little") ^ int.from_bytes(b, "little")).to_bytes(len(a), "little")


def parity_slot(layout: str, n: int, stripe: int) -> int:
    """md(4): the left layouts start with parity on the last member and move it down one member per
    stripe; the right layouts start on the first and move it up."""
    return n - 1 - stripe % n if layout.startswith("left") else stripe % n


def data_slots(layout: str, n: int, stripe: int) -> list[int]:
    """The members holding the stripe's data chunks, in order: asymmetric = every member but the
    parity one, lowest first; symmetric = starting on the member after the parity one, wrapping."""
    p = parity_slot(layout, n, stripe)
    if layout.endswith("-asymmetric"):
        return [s for s in range(n) if s != p]
    return [(p + 1 + i) % n for i in range(n - 1)]


def pad_to(volume: bytes, unit: int) -> bytes:
    return volume + bytes(-len(volume) % unit)


def split_raid5(volume: bytes, n: int, layout: str, chunk: int) -> list[bytes]:
    """The n members of a RAID-5 array holding `volume` (padded to whole stripes)."""
    volume = pad_to(volume, (n - 1) * chunk)
    members = [bytearray() for _ in range(n)]
    for stripe in range(len(volume) // ((n - 1) * chunk)):
        base = stripe * (n - 1) * chunk
        chunks = [volume[base + i * chunk:base + (i + 1) * chunk] for i in range(n - 1)]
        parity = bytes(chunk)
        for c in chunks:
            parity = _xor(parity, c)
        for c, slot in zip(chunks, data_slots(layout, n, stripe)):
            members[slot] += c
        members[parity_slot(layout, n, stripe)] += parity
    return [bytes(m) for m in members]


def split_raid4(volume: bytes, n: int, chunk: int) -> list[bytes]:
    """RAID-4: the data members in order, parity always on the last."""
    volume = pad_to(volume, (n - 1) * chunk)
    members = [bytearray() for _ in range(n)]
    for base in range(0, len(volume), (n - 1) * chunk):
        parity = bytes(chunk)
        for i in range(n - 1):
            c = volume[base + i * chunk:base + (i + 1) * chunk]
            members[i] += c
            parity = _xor(parity, c)
        members[n - 1] += parity
    return [bytes(m) for m in members]


def split_raid0(volume: bytes, n: int, chunk: int) -> list[bytes]:
    volume = pad_to(volume, n * chunk)
    members = [bytearray() for _ in range(n)]
    for i in range(len(volume) // chunk):
        members[i % n] += volume[i * chunk:(i + 1) * chunk]
    return [bytes(m) for m in members]


# ---------------------------------------------------------------- md superblocks

def md_v1_superblock(*, level=5, layout=2, chunk_sectors=64, raid_disks=4, size_sectors=0, data_offset_sectors=128,
                     data_size_sectors=0, super_offset_sectors=8, dev_number=0, roles=(0, 1, 2, 3), events=7,
                     feature_map=0, uuid=bytes(range(0x10, 0x20)), name="lab:0", bad_csum=False) -> bytes:
    """A 4096-byte md v1.x superblock (struct mdp_superblock_1), checksum included."""
    sb = bytearray(4096)
    struct.pack_into("<IIII", sb, 0, MD_MAGIC, 1, feature_map, 0)
    sb[16:32] = uuid
    sb[32:32 + len(name)] = name.encode()
    struct.pack_into("<QiIQII", sb, 64, 1_790_000_000, level, layout, size_sectors, chunk_sectors, raid_disks)
    struct.pack_into("<QQQ", sb, 128, data_offset_sectors, data_size_sectors or size_sectors, super_offset_sectors)
    struct.pack_into("<I", sb, 160, dev_number)
    sb[168:184] = bytes([0xD0 + dev_number]) * 16
    struct.pack_into("<QQ", sb, 192, 1_790_000_100, events)
    struct.pack_into("<I", sb, 220, len(roles))
    for i, r in enumerate(roles):
        struct.pack_into("<H", sb, 256 + 2 * i, r)
    size = 256 + 2 * len(roles)
    total = 0
    for at in range(0, size - size % 4, 4):
        total += struct.unpack_from("<I", sb, at)[0]
    if size % 4:
        total += struct.unpack_from("<H", sb, size - 2)[0]
    csum = ((total & 0xFFFFFFFF) + (total >> 32)) & 0xFFFFFFFF
    struct.pack_into("<I", sb, 216, csum ^ 0x5A5A if bad_csum else csum)
    return bytes(sb)


def member_v12(data: bytes, **sb) -> bytes:
    """v1.2: the superblock 4 KiB into the member, the data after `data_offset_sectors`."""
    off = sb.setdefault("data_offset_sectors", 128) * 512
    block = md_v1_superblock(super_offset_sectors=8, size_sectors=sb.pop("size_sectors", len(data) // 512), **sb)
    return bytes(4096) + block + bytes(off - 8192) + data


def member_v11(data: bytes, **sb) -> bytes:
    """v1.1: the superblock at the very start."""
    off = sb.setdefault("data_offset_sectors", 16) * 512
    block = md_v1_superblock(super_offset_sectors=0, size_sectors=sb.pop("size_sectors", len(data) // 512), **sb)
    return block + bytes(off - 4096) + data


def member_v10(data: bytes, **sb) -> bytes:
    """v1.0: the data at the start, the superblock 8 KiB before the end (4 KiB aligned)."""
    sectors = -(-(len(data) // 512) // 8) * 8 + 24
    at = (sectors - 16) & ~7
    block = md_v1_superblock(super_offset_sectors=at, data_offset_sectors=0,
                             size_sectors=sb.pop("size_sectors", len(data) // 512), **sb)
    out = bytearray(sectors * 512)
    out[:len(data)] = data
    out[at * 512:at * 512 + 4096] = block
    return bytes(out)


def md_v090_superblock(*, level=5, layout=2, chunk_bytes=32768, raid_disks=4, size_kib=0, number=0, raid_disk=0,
                       state=0b0110, events=7, endian="<", minor=90, uuid_words=(0x11111111, 2, 3, 4)) -> bytes:
    """A 4096-byte md v0.90 superblock (mdp_super_t: 1024 words in the writer's byte order)."""
    w = [0] * 1024
    w[0], w[1], w[2] = MD_MAGIC, 0, minor
    w[5], w[13], w[14], w[15] = uuid_words
    w[6], w[7], w[8], w[9], w[10] = 1_790_000_000, level & 0xFFFFFFFF, size_kib, raid_disks, raid_disks
    w[32], w[33], w[34], w[35] = 1_790_000_100, 1, raid_disks, raid_disks
    if endian == "<":
        w[39], w[40] = events & 0xFFFFFFFF, events >> 32
    else:
        w[39], w[40] = events >> 32, events & 0xFFFFFFFF
    w[64], w[65] = layout, chunk_bytes
    for d in range(raid_disks):
        w[128 + 32 * d:128 + 32 * d + 5] = [d, 8, 16 * d, d, 0b0110]
    w[992:997] = [number, 8, 16 * number, raid_disk, state]
    total = sum(w)
    w[38] = ((total & 0xFFFFFFFF) + (total >> 32)) & 0xFFFFFFFF
    return struct.pack(f"{endian}1024I", *w)


def member_v090(data: bytes, **sb) -> bytes:
    """v0.90: the data at the start, the superblock in the last whole 64 KiB block."""
    sectors = -(-(len(data) // 512) // 128) * 128 + 128
    at = (sectors & ~127) - 128
    out = bytearray(sectors * 512)
    out[:len(data)] = data
    out[at * 512:at * 512 + 4096] = md_v090_superblock(size_kib=sb.pop("size_kib", len(data) // 1024), **sb)
    return bytes(out)


# ---------------------------------------------------------------- FAT16

def _name83(name: str) -> bytes:
    base, _, ext = name.partition(".")
    return base.upper().ljust(8).encode() + ext.upper().ljust(3).encode()


def fat16_image(files: dict, deleted: dict | None = None, *, sectors: int = 8192, label: str = "RAIDLAB") -> bytes:
    """A FAT16 volume (512-byte sectors, one sector per cluster, two FATs, a 512-entry root). `files`
    and then `deleted` get consecutive clusters in the order given; a deleted file keeps its bytes
    and loses its chain and the first letter of its name (0xE5)."""
    fat_sectors, root_sectors = 32, 32
    first_data = 1 + 2 * fat_sectors + root_sectors
    clusters = sectors - first_data
    assert 4085 <= clusters < 65525 and (clusters + 2) * 2 <= fat_sectors * 512
    boot = bytearray(512)
    boot[0:3] = b"\xeb\x3c\x90"
    boot[3:11] = b"MSDOS5.0"
    struct.pack_into("<HBHBHHBH", boot, 11, 512, 1, 1, 2, 512, sectors, 0xF8, fat_sectors)
    struct.pack_into("<HHII", boot, 24, 32, 2, 0, 0)
    boot[36:39] = b"\x80\x00\x29"
    boot[39:43] = b"\x65\xb0\x0b\x1e"
    boot[43:54] = label.ljust(11).encode()
    boot[54:62] = b"FAT16   "
    boot[510:512] = b"\x55\xaa"
    fat = [0] * (clusters + 2)
    fat[0], fat[1] = 0xFFF8, 0xFFFF
    root, area, nxt = bytearray(), bytearray(clusters * 512), 2
    for group, gone in ((files, False), (deleted or {}, True)):
        for name, body in group.items():
            n = -(-len(body) // 512)
            assert nxt + n <= clusters + 2, "the image is too small for these files"
            area[(nxt - 2) * 512:(nxt - 2) * 512 + len(body)] = body
            if not gone:
                for c in range(nxt, nxt + n):
                    fat[c] = c + 1 if c + 1 < nxt + n else 0xFFFF
            short = _name83(name)
            if gone:
                short = b"\xe5" + short[1:]
            root += struct.pack("<8s3sBBBHHHHHHHI", short[:8], short[8:], 0x20, 0, 0, 0x6000, 0x5B66, 0x5B66, 0,
                                0x6000, 0x5B66, nxt if body else 0, len(body))
            nxt += n
    table = struct.pack(f"<{len(fat)}H", *fat).ljust(fat_sectors * 512, b"\x00")
    return bytes(boot) + table + table + bytes(root).ljust(root_sectors * 512, b"\x00") + bytes(area)


# ---------------------------------------------------------------- ext4

def crc32c(crc: int, data: bytes) -> int:
    """CRC-32C the way the kernel's crc32c() runs it (seed in, no final inversion), bit by bit."""
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc


class Sparse(NamedTuple):
    """A file of `size` bytes whose first blocks hold `data` and whose rest was never written."""
    size: int
    data: bytes


def _backup_groups(groups: int) -> set:
    out = {0, 1}
    for base in (3, 5, 7):
        g = base
        while g < groups:
            out.add(g)
            g *= base
    return {g for g in out if g < groups}


def ext4_image(files: dict, *, blocks: int = 4096, block_size: int = 1024, blocks_per_group: int = 1024,
               inodes_per_group: int = 64, csum: bool = True, label: str = "raidlab",
               uuid: bytes = bytes(range(0xA0, 0xB0)), unlinked: dict | None = None, nameless: dict | None = None) -> bytes:
    """An ext4 volume without a journal: extents, sparse_super backups, 256-byte inodes and, with
    `csum`, metadata_csum (superblock, group descriptor, bitmap, inode and directory-block
    checksums). `files` maps 'dir/name' to bytes (or a Sparse); directories are made as needed.
    `unlinked` files get an inode and blocks, a deletion time and no name anywhere; `nameless` ones
    are live inodes (one link, no deletion time) that no directory names. Returns the image; the
    inode numbers follow insertion order from 12 (`ext4_inodes` gives the map)."""
    image, _ = _ext4(files, blocks, block_size, blocks_per_group, inodes_per_group, csum, label, uuid, unlinked or {},
                     nameless or {})
    return image


def ext4_inodes(files: dict, **kw) -> dict:
    """{path: inode number} of the image ext4_image(files, **kw) builds ('' is the root, 2)."""
    kw = {"blocks": 4096, "block_size": 1024, "blocks_per_group": 1024, "inodes_per_group": 64, "csum": True,
          "label": "raidlab", "uuid": bytes(range(0xA0, 0xB0)), "unlinked": None, "nameless": None, **kw}
    return _ext4(files, kw["blocks"], kw["block_size"], kw["blocks_per_group"], kw["inodes_per_group"], kw["csum"],
                 kw["label"], kw["uuid"], kw["unlinked"] or {}, kw["nameless"] or {})[1]


def _ext4(files, blocks, bs, bpg, ipg, csum, label, uuid, unlinked, nameless):
    isize = 256
    first = 1 if bs == 1024 else 0
    groups = -(-(blocks - first) // bpg)
    assert groups * 32 <= bs and ipg % 8 == 0 and bpg % 8 == 0
    itb = ipg * isize // bs
    backups = _backup_groups(groups)
    image = bytearray(blocks * bs)
    seed = crc32c(0xFFFFFFFF, uuid)
    meta, free = [], []
    for g in range(groups):
        start = first + g * bpg
        end = min(start + bpg, blocks)
        m = start + (2 if g in backups else 0)
        meta.append({"start": start, "end": end, "bbitmap": m, "ibitmap": m + 1, "itable": m + 2, "used": set(range(start, m + 2 + itb))})
        free += range(m + 2 + itb, end)
    used_inodes = set(range(1, 11))
    inode_raw, dirs, next_ino = {}, {"": {"ino": 2, "parent": 2, "entries": []}}, [12]
    owner = {}

    def take(n):
        got = free[:n]
        assert len(got) == n, "the image is too small for these files"
        del free[:n]
        for b in got:
            meta[(b - first) // bpg]["used"].add(b)
        return got

    def new_inode():
        ino = next_ino[0]
        next_ino[0] += 1
        return ino

    def extents(blks):
        runs = []
        for i, b in enumerate(blks):
            if runs and runs[-1][1] + runs[-1][2] == b:
                runs[-1][2] += 1
            else:
                runs.append([i, b, 1])
        assert len(runs) <= 4, "a fixture file may have four extents at most"
        raw = struct.pack("<HHHHI", 0xF30A, len(runs), 4, 0, 0)
        for logical, phys, n in runs:
            raw += struct.pack("<IHHI", logical, n, 0, phys)
        return raw.ljust(60, b"\x00")

    def make_inode(ino, mode, size, blks, links, dtime=0):
        raw = bytearray(isize)
        struct.pack_into("<HHIIIIIHHII", raw, 0, mode, 0, size & 0xFFFFFFFF, 1_790_000_000, 1_790_000_000, 1_790_000_000,
                         dtime, 0, links, len(blks) * bs // 512, 0x80000)
        raw[40:100] = extents(blks)
        struct.pack_into("<I", raw, 100, 0x1000 + ino)
        struct.pack_into("<I", raw, 108, size >> 32)
        struct.pack_into("<H", raw, 128, 32)
        if csum:
            c = crc32c(crc32c(crc32c(seed, struct.pack("<I", ino)), raw[100:104]), bytes(raw))
            struct.pack_into("<H", raw, 124, c & 0xFFFF)
            struct.pack_into("<H", raw, 130, c >> 16)
        inode_raw[ino] = bytes(raw)

    def put_file(path, body, links=1, dtime=0):
        size, data = (body.size, body.data) if isinstance(body, Sparse) else (len(body), body)
        blks = take(-(-len(data) // bs))
        for i, b in enumerate(blks):
            image[b * bs:b * bs + bs] = data[i * bs:(i + 1) * bs].ljust(bs, b"\x00")
        ino = new_inode()
        make_inode(ino, 0x81A4, size, blks, links, dtime)
        owner[path] = ino
        return ino

    def directory(path):
        if path not in dirs:
            parent, _, name = path.rpartition("/")
            up = directory(parent)
            ino = new_inode()
            dirs[path] = {"ino": ino, "parent": up["ino"], "entries": []}
            up["entries"].append((ino, name, 2))
            owner[path] = ino
        return dirs[path]

    for path, body in files.items():
        parent, _, name = path.rpartition("/")
        directory(parent)["entries"].append((put_file(path, body), name, 1))
    for name, body in unlinked.items():
        put_file("<unlinked>/" + name, body, links=0, dtime=1_790_000_500)
    for name, body in nameless.items():
        put_file("<nameless>/" + name, body)
    owner[""] = 2
    for path, d in dirs.items():
        rows = [(d["ino"], ".", 2), (d["parent"], "..", 2)] + d["entries"]
        room = bs - (12 if csum else 0)
        block, at = bytearray(bs), 0
        for i, (ino, name, ftype) in enumerate(rows):
            need = (8 + len(name) + 3) & ~3
            rec = room - at if i == len(rows) - 1 else need
            assert at + need <= room, "a fixture directory must fit one block"
            struct.pack_into("<IHBB", block, at, ino, rec, len(name), ftype)
            block[at + 8:at + 8 + len(name)] = name.encode()
            at += rec
        if csum:
            dseed = crc32c(crc32c(seed, struct.pack("<I", d["ino"])), struct.pack("<I", 0x1000 + d["ino"]))
            struct.pack_into("<IHBBI", block, bs - 12, 0, 12, 0, 0xDE, crc32c(dseed, bytes(block[:bs - 12])))
        blk = take(1)
        image[blk[0] * bs:blk[0] * bs + bs] = block
        make_inode(d["ino"], 0x41ED, bs, blk, 2 + sum(1 for e in d["entries"] if e[2] == 2))
    used_inodes |= {i for i in inode_raw if inode_raw[i][26:28] != b"\x00\x00"}
    gdt = bytearray()
    for g, m in enumerate(meta):
        for ino, raw in inode_raw.items():
            if (ino - 1) // ipg == g:
                at = m["itable"] * bs + ((ino - 1) % ipg) * isize
                image[at:at + isize] = raw
        bbits = bytearray(bs)
        for b in m["used"]:
            i = b - m["start"]
            bbits[i // 8] |= 1 << (i % 8)
        for i in range(m["end"] - m["start"], bs * 8):
            bbits[i // 8] |= 1 << (i % 8)
        ibits = bytearray(bs)
        for ino in used_inodes:
            if (ino - 1) // ipg == g:
                i = (ino - 1) % ipg
                ibits[i // 8] |= 1 << (i % 8)
        for i in range(ipg, bs * 8):
            ibits[i // 8] |= 1 << (i % 8)
        image[m["bbitmap"] * bs:m["bbitmap"] * bs + bs] = bbits
        image[m["ibitmap"] * bs:m["ibitmap"] * bs + bs] = ibits
        ndirs = sum(1 for d in dirs.values() if (d["ino"] - 1) // ipg == g)
        desc = bytearray(struct.pack("<IIIHHHHIHHHH", m["bbitmap"], m["ibitmap"], m["itable"],
                                     m["end"] - m["start"] - len(m["used"]),
                                     ipg - sum(1 for i in used_inodes if (i - 1) // ipg == g), ndirs, 0, 0,
                                     crc32c(seed, bytes(bbits[:bpg // 8])) & 0xFFFF if csum else 0,
                                     crc32c(seed, bytes(ibits[:ipg // 8])) & 0xFFFF if csum else 0, 0, 0))
        if csum:
            struct.pack_into("<H", desc, 30, crc32c(crc32c(seed, struct.pack("<I", g)), bytes(desc)) & 0xFFFF)
        gdt += desc

    def superblock(group):
        sb = bytearray(1024)
        struct.pack_into("<IIIIIIIIIIIII", sb, 0, groups * ipg, blocks, 0, len(free), groups * ipg - len(used_inodes),
                         first, {1024: 0, 2048: 1, 4096: 2}[bs], {1024: 0, 2048: 1, 4096: 2}[bs], bpg, bpg, ipg,
                         1_790_000_000, 1_790_000_000)
        struct.pack_into("<HHHHHHIIIIHH", sb, 52, 1, 0xFFFF, 0xEF53, 1, 1, 0, 1_790_000_000, 0, 0, 1, 0, 0)
        struct.pack_into("<IHHIII", sb, 84, 11, isize, group, 0, 0x2 | 0x40, 0x1 | (0x400 if csum else 0))
        sb[104:120] = uuid
        sb[120:120 + len(label)] = label.encode()
        struct.pack_into("<HH", sb, 348, 32, 32)
        if csum:
            sb[373] = 1
            struct.pack_into("<I", sb, 1020, crc32c(0xFFFFFFFF, bytes(sb[:1020])))
        return bytes(sb)

    for g in sorted(backups):
        start = meta[g]["start"]
        at = 1024 if g == 0 else start * bs
        image[at:at + 1024] = superblock(g)
        image[(start + 1) * bs:(start + 1) * bs + len(gdt)] = gdt
    return bytes(image), owner


# ---------------------------------------------------------------- a partition table

def mbr_disk(partition: bytes, *, start_sector: int = 2048, ptype: int = 0x83) -> bytes:
    """A whole-disk image: an MBR whose first entry is `partition`, starting at `start_sector`."""
    mbr = bytearray(512)
    struct.pack_into("<B3sB3sII", mbr, 446, 0, b"\x00\x02\x00", ptype, b"\x00\x00\x00", start_sector, len(partition) // 512)
    mbr[510:512] = b"\x55\xaa"
    return bytes(mbr) + bytes(start_sector * 512 - 512) + partition
