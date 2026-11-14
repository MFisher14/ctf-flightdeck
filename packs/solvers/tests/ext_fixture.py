"""Synthetic ext2/ext4 volumes and ELF programs for the B-135 tests. Everything is built here, byte by
byte; nothing comes from a challenge.

    img = Ext(blocks=512)                          # 1 KiB blocks, one group; block_size=4096, bpg=...
    d = img.mkdir("var")
    img.add("note.txt", b"...", parent=d, mtime=1_700_000_000)
    img.orphan(mode=0o100755, mtime=..., data=None)   # a deleted inode with its extents cleared
    img.free_write(b"\\x7fELF...")                  # bytes in blocks the bitmap leaves free
    raw = img.build()

    elf(code=b"...")                               # a minimal valid x86-64 ELF (program + section headers)
"""
from __future__ import annotations

import struct


class Ext:
    def __init__(self, blocks: int = 512, block_size: int = 1024, inodes: int = 64, *, extents: bool = False,
                 wide: bool = False, bpg: int | None = None, csum: bool = False, name: str = "HISTORIAN01"):
        self.bs, self.blocks, self.extents, self.wide, self.csum, self.name = (block_size, blocks, extents,
                                                                               wide, csum, name)
        self.fdb = 1 if block_size == 1024 else 0
        self.bpg = bpg or block_size * 8
        self.groups = -(-(blocks - self.fdb) // self.bpg)
        self.ipg = inodes
        self.isz = 128
        self.img = bytearray(blocks * block_size)
        self.used: set[int] = set(range(self.fdb))
        self.uninit: set[int] = set()
        self.inodes: dict[int, bytes] = {}
        self.dirs: dict[int, list] = {}
        self.dir_block: dict[int, int] = {}
        self.parent: dict[int, int] = {}
        self.next_ino = 11
        nxt = self.fdb
        self.sb_block, nxt = nxt, nxt + (1 if block_size == 1024 else 1)
        self.gdt, nxt = nxt, nxt + 1
        self.bitmaps = list(range(nxt, nxt + self.groups))
        nxt += self.groups
        self.ibitmaps = list(range(nxt, nxt + self.groups))
        nxt += self.groups
        per = -(-(self.ipg * self.isz) // block_size)
        self.itables = [nxt + g * per for g in range(self.groups)]
        nxt += per * self.groups
        self.used.update(range(self.fdb, nxt))
        self.next_block = nxt
        self.dirs[2] = []
        self.parent[2] = 2
        self.dir_block[2] = self._alloc(1)[0]

    # -- allocation
    def _alloc(self, n: int) -> list[int]:
        out = []
        while len(out) < n:
            b = self.next_block
            self.next_block += 1
            if b in self.used or b in self.reserved_free:
                continue
            self.used.add(b)
            out.append(b)
        return out

    reserved_free: set = set()

    def _inode(self, mode: int, size: int, blocks: list[int], mtime: int, links: int = 1, dtime: int = 0,
               clear_map: bool = False) -> bytes:
        raw = bytearray(self.isz)
        struct.pack_into("<HHIIIII", raw, 0, mode, 0, size & 0xFFFFFFFF, mtime, mtime, mtime, dtime)
        struct.pack_into("<HH", raw, 24, 0, links)
        flags = 0
        if self.extents:
            flags |= 0x80000
            if not clear_map:
                runs = _runs(blocks)
                struct.pack_into("<HHHHI", raw, 40, 0xF30A, len(runs), 4, 0, 0)
                logical = 0
                for i, (start, count) in enumerate(runs):
                    struct.pack_into("<IHHI", raw, 40 + 12 + 12 * i, logical, count, 0, start)
                    logical += count
        elif not clear_map:
            if len(blocks) > 12:
                raise ValueError("legacy fixture files hold at most 12 blocks")
            struct.pack_into(f"<{len(blocks)}I", raw, 40, *blocks)
        struct.pack_into("<I", raw, 32, flags)
        struct.pack_into("<I", raw, 108, size >> 32)
        return bytes(raw)

    def _new_ino(self) -> int:
        ino = self.next_ino
        self.next_ino += 1
        if ino > self.ipg * self.groups:
            raise ValueError("out of inodes")
        return ino

    def _store(self, data: bytes) -> list[int]:
        n = -(-len(data) // self.bs)
        blocks = self._alloc(n)
        for i, b in enumerate(blocks):
            chunk = data[i * self.bs:(i + 1) * self.bs]
            self.img[b * self.bs:b * self.bs + len(chunk)] = chunk
        return blocks

    # -- the tree
    def mkdir(self, name: str, parent: int = 2, mtime: int = 1_700_000_000) -> int:
        ino = self._new_ino()
        self.dirs[ino] = []
        self.parent[ino] = parent
        self.dir_block[ino] = self._alloc(1)[0]
        self.inodes[ino] = (mtime,)
        self.dirs[parent].append((ino, name, 2))
        return ino

    def add(self, name: str, data: bytes, parent: int = 2, mtime: int = 1_700_000_000,
            mode: int = 0o100644) -> int:
        ino = self._new_ino()
        blocks = self._store(data)
        self.inodes[ino] = self._inode(mode, len(data), blocks, mtime)
        self.dirs[parent].append((ino, name, 1))
        return ino

    def orphan(self, mode: int = 0o100755, mtime: int = 1_700_000_000, data: bytes | None = None,
               dtime: int = 1_700_000_100, links: int = 0) -> int:
        """An inode no directory names (deleted by default: links 0 and a dtime). With data, its block map
        still points at the bytes (an ext2-style delete; the blocks stay marked used here); without, the
        map is cleared (ext4)."""
        ino = self._new_ino()
        blocks = self._store(data) if data else []
        self.inodes[ino] = self._inode(mode, len(data or b"\0" * 9000), blocks, mtime, links=links, dtime=dtime,
                                       clear_map=data is None)
        return ino

    def reserved(self, ino: int, data: bytes, mode: int = 0o100600) -> int:
        """A reserved inode (1..10) with bytes, e.g. the ext3/4 journal at inode 8: a regular file that
        no directory names and that is not deleted."""
        if not 1 <= ino < 11 or ino == 2:
            raise ValueError("a reserved inode is 1, or 3..10")
        self.inodes[ino] = self._inode(mode, len(data), self._store(data), 1_700_000_000)
        return ino

    def free_write(self, data: bytes, block: int | None = None) -> list[int]:
        """Write `data` into consecutive blocks that stay free in the bitmap; the first block number."""
        n = -(-len(data) // self.bs)
        start = block if block is not None else self.blocks - n - 8
        blocks = list(range(start, start + n))
        if any(b in self.used for b in blocks):
            raise ValueError("those blocks are in use")
        self.reserved_free = set(self.reserved_free) | set(blocks)
        for i, b in enumerate(blocks):
            chunk = data[i * self.bs:(i + 1) * self.bs]
            self.img[b * self.bs:b * self.bs + len(chunk)] = chunk
        return blocks

    def write_raw(self, block: int, data: bytes, *, mark_used: bool) -> None:
        self.img[block * self.bs:block * self.bs + len(data)] = data
        if mark_used:
            self.used.update(range(block, block + -(-len(data) // self.bs)))

    # -- output
    def _dir_bytes(self, ino: int) -> bytes:
        entries = [(ino, ".", 2), (self.parent[ino], "..", 2)] + self.dirs[ino]
        out = bytearray(self.bs)
        pos = 0
        for i, (child, name, ftype) in enumerate(entries):
            nb = name.encode()
            need = (8 + len(nb) + 3) & ~3
            rec = self.bs - pos if i == len(entries) - 1 else need
            struct.pack_into("<IHBB", out, pos, child, rec, len(nb), ftype)
            out[pos + 8:pos + 8 + len(nb)] = nb
            pos += rec
        if pos != self.bs:
            raise ValueError("directory overflows one block")
        return bytes(out)

    def build(self) -> bytes:
        bs = self.bs
        for ino in self.dirs:
            blk = self.dir_block[ino]
            body = self._dir_bytes(ino)
            self.img[blk * bs:(blk + 1) * bs] = body
            mtime = 1_700_000_000 if ino == 2 else self.inodes[ino][0]
            self.inodes[ino] = self._inode(0o40755, bs, [blk], mtime, links=2)
        for ino, raw in self.inodes.items():
            g, i = divmod(ino - 1, self.ipg)
            at = self.itables[g] * bs + i * self.isz
            self.img[at:at + self.isz] = raw
        # superblock
        sb = bytearray(1024)
        struct.pack_into("<IIIIIIIIIII", sb, 0, self.ipg * self.groups, self.blocks, 0,
                         self.blocks - len(self.used), 0, self.fdb, {1024: 0, 2048: 1, 4096: 2}[bs], 0,
                         self.bpg, self.bpg, self.ipg)
        struct.pack_into("<H", sb, 56, 0xEF53)
        struct.pack_into("<I", sb, 76, 1)
        struct.pack_into("<IH", sb, 84, 11, self.isz)
        incompat = 0x2 | (0x40 if self.extents else 0) | (0x80 if self.wide else 0)
        ro = 0x400 if self.csum else 0
        struct.pack_into("<III", sb, 92, 0, incompat, ro)
        sb[104:120] = bytes(range(0x10, 0x20))
        sb[120:136] = self.name.encode().ljust(16, b"\0")
        if self.wide:
            struct.pack_into("<H", sb, 254, 64)
        self.img[1024:2048] = sb
        # group descriptors and bitmaps
        dsz = 64 if self.wide else 32
        for g in range(self.groups):
            d = self.gdt * bs + g * dsz
            flags = 0x2 if g in self.uninit else 0
            struct.pack_into("<III", self.img, d, self.bitmaps[g], self.ibitmaps[g], self.itables[g])
            struct.pack_into("<H", self.img, d + 0x12, flags)
            base = self.fdb + g * self.bpg
            bits = bytearray(bs)
            for i in range(self.bpg):
                b = base + i
                if b >= self.blocks or b in self.used:
                    bits[i >> 3] |= 1 << (i & 7)
            if g not in self.uninit:
                self.img[self.bitmaps[g] * bs:(self.bitmaps[g] + 1) * bs] = bits
        return bytes(self.img)


def _runs(blocks: list[int]) -> list[tuple[int, int]]:
    runs = []
    for b in blocks:
        if runs and runs[-1][0] + runs[-1][1] == b:
            runs[-1] = (runs[-1][0], runs[-1][1] + 1)
        else:
            runs.append((b, 1))
    return runs


def elf(code: bytes, *, extra: bytes = b"", pad_to: int = 0) -> bytes:
    """A minimal x86-64 ELF executable: header, one PT_LOAD, a .text section holding `code` (then `extra`),
    and a section header table with null, .text and .shstrtab. carving's _elf_end sizes it from the
    section headers, which end the file."""
    text_off = 0x40 + 0x38
    text = code + extra
    shstr = b"\0.text\0.shstrtab\0"
    shstr_off = text_off + len(text)
    shoff = (shstr_off + len(shstr) + 7) & ~7
    if pad_to and shoff < pad_to:
        shoff = pad_to
    out = bytearray(shoff + 3 * 64)
    out[0:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into("<HHIQQQIHHHHHH", out, 16, 2, 0x3E, 1, 0x400000 + text_off, 0x40, shoff, 0, 64, 0x38, 1,
                     64, 3, 2)
    struct.pack_into("<IIQQQQQQ", out, 0x40, 1, 5, 0, 0x400000, 0x400000, shoff + 3 * 64, shoff + 3 * 64, 0x1000)
    out[text_off:text_off + len(text)] = text
    out[shstr_off:shstr_off + len(shstr)] = shstr
    # section headers: [0] null, [1] .text, [2] .shstrtab
    struct.pack_into("<IIQQQQIIQQ", out, shoff + 64, 1, 1, 6, 0x400000 + text_off, text_off, len(text), 0, 0, 16, 0)
    struct.pack_into("<IIQQQQIIQQ", out, shoff + 128, 7, 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0)
    return bytes(out)
