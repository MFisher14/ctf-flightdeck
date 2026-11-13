"""Synthetic NTFS volumes and Word documents for the B-029 tests. Everything is built here, byte by byte;
nothing comes from a challenge.

    img = Ntfs(clusters=256)
    d = img.add("Staff", directory=True)
    img.add("note.txt", b"...", parent=d, deleted=True)
    raw = img.build()

    docx(body_xml)                      # a minimal .docx around one <w:body> worth of paragraphs
"""
from __future__ import annotations

import io
import struct
import zipfile
from dataclasses import dataclass, field

CS = 4096          # cluster size (8 sectors of 512)
RS = 1024          # MFT record size
ROOT = 5


def _align8(n: int) -> int:
    return (n + 7) & ~7


def _signed_len(v: int) -> int:
    n = 1
    while not -(1 << (8 * n - 1)) <= v < (1 << (8 * n - 1)):
        n += 1
    return n


def runlist(runs) -> bytes:
    """Encode [(lcn | None, count)] as an NTFS runlist (None = sparse), terminated."""
    out, prev = bytearray(), 0
    for lcn, count in runs:
        lb = count.to_bytes(max(1, (count.bit_length() + 7) // 8), "little")
        if lcn is None:
            out += bytes([len(lb)]) + lb
            continue
        delta = lcn - prev
        n = _signed_len(delta)
        out += bytes([(n << 4) | len(lb)]) + lb + delta.to_bytes(n, "little", signed=True)
        prev = lcn
    return bytes(out) + b"\x00"


def resident(type_code: int, value: bytes, name: str = "", attr_id: int = 0) -> bytes:
    nb = name.encode("utf-16-le")
    voff = _align8(24 + len(nb))
    length = _align8(voff + len(value))
    buf = bytearray(length)
    struct.pack_into("<IIBBHHH", buf, 0, type_code, length, 0, len(name), 24, 0, attr_id)
    struct.pack_into("<IHBB", buf, 16, len(value), voff, 0, 0)
    buf[24:24 + len(nb)] = nb
    buf[voff:voff + len(value)] = value
    return bytes(buf)


def nonresident(type_code: int, runs, data_size: int, name: str = "", flags: int = 0, attr_id: int = 0,
                start_vcn: int = 0, comp_unit: int = 0, alloc: int | None = None) -> bytes:
    nb = name.encode("utf-16-le")
    roff = _align8(64 + len(nb))
    rl = runlist(runs)
    length = _align8(roff + len(rl))
    total = sum(c for _l, c in runs)
    buf = bytearray(length)
    struct.pack_into("<IIBBHHH", buf, 0, type_code, length, 1, len(name), 64, flags, attr_id)
    struct.pack_into("<QQHH", buf, 16, start_vcn, start_vcn + total - 1, roff, comp_unit)
    phys = sum(c for l, c in runs if l is not None) * CS
    struct.pack_into("<QQQ", buf, 40, phys if alloc is None else alloc, data_size, data_size)
    buf[64:64 + len(nb)] = nb
    buf[roff:roff + len(rl)] = rl
    return bytes(buf)


def file_name(name: str, parent: int, namespace: int = 1, size: int = 0) -> bytes:
    nb = name.encode("utf-16-le")
    v = struct.pack("<QQQQQQQII", parent | (1 << 48), 0, 0, 0, 0, size, size, 0, 0)
    return resident(0x30, v + bytes([len(name), namespace]) + nb)


def record(num: int, attrs: list, in_use: bool = True, directory: bool = False, base: int = 0,
           break_usa: bool = False) -> bytes:
    buf = bytearray(RS)
    buf[0:4] = b"FILE"
    struct.pack_into("<HH", buf, 4, 48, RS // 512 + 1)
    struct.pack_into("<HHH", buf, 16, 1, 1, 56)
    struct.pack_into("<H", buf, 22, (1 if in_use else 0) | (2 if directory else 0))
    pos = 56
    for a in attrs:
        buf[pos:pos + len(a)] = a
        pos += len(a)
    buf[pos:pos + 4] = b"\xff\xff\xff\xff"
    pos += 8
    assert pos <= RS, "record overflow"
    struct.pack_into("<II", buf, 24, pos, RS)
    struct.pack_into("<Q", buf, 32, base | (1 << 48) if base else 0)
    struct.pack_into("<HHI", buf, 40, len(attrs), 0, num)
    usn = b"\x07\x00"
    buf[48:50] = usn
    for j in range(1, RS // 512 + 1):
        end = j * 512 - 2
        buf[48 + 2 * j:50 + 2 * j] = buf[end:end + 2]
        buf[end:end + 2] = usn if not (break_usa and j == 2) else b"\x99\x99"
    return bytes(buf)


@dataclass
class Entry:
    num: int
    name: str
    parent: int
    data: bytes | None
    deleted: bool
    directory: bool
    resident: bool
    runs: list | None
    ads: dict
    flags: int
    names: list = field(default_factory=list)       # extra (name, namespace) pairs
    split: bool = False                               # $DATA in two extents, the second in an extension record


class Ntfs:
    def __init__(self, clusters: int = 256, mft_lcn: int = 4, mft_records: int = 48, mft_runs=None):
        self.clusters = clusters
        self.mft_lcn = mft_lcn
        per = CS // RS
        self.mft_runs = mft_runs or [(mft_lcn, (mft_records + per - 1) // per)]
        self.records = sum(c for _l, c in self.mft_runs) * per
        self.entries: list[Entry] = []
        self.raw_records: dict[int, bytes] = {}
        self.next = 16
        self.cursor = max(l + c for l, c in self.mft_runs) + 1
        self.writes: list[tuple[int, bytes]] = []
        self.break_record0 = False

    def alloc(self, nbytes: int) -> list:
        n = max(1, (nbytes + CS - 1) // CS)
        runs = [(self.cursor, n)]
        self.cursor += n
        return runs

    def add(self, name: str, data: bytes | None = None, *, parent: int = ROOT, deleted: bool = False,
            directory: bool = False, resident: bool | None = None, runs=None, ads=None, flags: int = 0,
            num: int | None = None, names=None, split: bool = False) -> int:
        num = self.next if num is None else num
        self.next = max(self.next, num) + 1
        if data is not None and resident is None:
            resident = len(data) <= 400
        if data is not None and not resident and runs is None:
            runs = self.alloc(len(data))
        self.entries.append(Entry(num, name, parent, data, deleted, directory, bool(resident), runs,
                                  dict(ads or {}), flags, list(names or []), split))
        return num

    def raw_record(self, num: int, raw: bytes):
        self.raw_records[num] = raw

    def _place(self, runs, data: bytes):
        off = 0
        for lcn, count in runs:
            if lcn is None:
                off += count * CS
                continue
            self.writes.append((lcn * CS, data[off:off + count * CS]))
            off += count * CS

    def build(self) -> bytes:
        img = bytearray(self.clusters * CS)
        boot = bytearray(512)
        boot[0:3] = b"\xeb\x52\x90"
        boot[3:11] = b"NTFS    "
        struct.pack_into("<HB", boot, 11, 512, CS // 512)
        struct.pack_into("<QQQ", boot, 40, self.clusters * CS // 512, self.mft_lcn, 2)
        boot[64] = 0xF6                      # 2^10 = 1024-byte records
        boot[68] = 1
        struct.pack_into("<Q", boot, 72, 0x1234ABCD)
        boot[510:512] = b"\x55\xaa"
        img[0:512] = boot
        recs = {}
        mft_size = self.records * RS
        rec0 = record(0, [file_name("$MFT", ROOT, 3), nonresident(0x80, self.mft_runs, mft_size)])
        if self.break_record0:
            rec0 = record(0, [file_name("$MFT", ROOT, 3)], break_usa=True)
        recs[0] = rec0
        recs[ROOT] = record(ROOT, [file_name(".", ROOT, 3)], directory=True)
        for e in self.entries:
            attrs = [file_name(e.name, e.parent, 1)] + [file_name(n, e.parent, ns) for n, ns in e.names]
            ext = []
            if e.data is not None:
                if e.resident:
                    attrs.append(resident(0x80, e.data))
                elif e.split:
                    first, second = e.runs[:1], e.runs[1:]
                    attrs.append(nonresident(0x80, first, len(e.data),
                                             alloc=sum(c for _l, c in e.runs) * CS))
                    ext.append(nonresident(0x80, second, len(e.data), start_vcn=first[0][1],
                                           alloc=sum(c for _l, c in e.runs) * CS))
                    self._place(e.runs, e.data)
                else:
                    attrs.append(nonresident(0x80, e.runs, len(e.data), flags=e.flags,
                                             comp_unit=4 if e.flags & 1 else 0))
                    self._place(e.runs, e.data)
            for sname, sdata in e.ads.items():
                attrs.append(resident(0x80, sdata, sname))
            recs[e.num] = record(e.num, attrs, in_use=not e.deleted, directory=e.directory)
            if ext:
                xnum = self.next
                self.next += 1
                recs[xnum] = record(xnum, ext, in_use=not e.deleted, base=e.num)
        recs.update(self.raw_records)
        # the $MFT's own bytes, laid out through its runs
        mft = bytearray(mft_size)
        for n, r in recs.items():
            assert n < self.records, f"record {n} past the $MFT's {self.records} records"
            mft[n * RS:(n + 1) * RS] = r
        self._place(self.mft_runs, bytes(mft))
        for at, chunk in self.writes:
            img[at:at + len(chunk)] = chunk
        return bytes(img)


def mbr(volume: bytes, lba: int = 2048, ptype: int = 0x07) -> bytes:
    sector = bytearray(512)
    struct.pack_into("<BBBBBBBBII", sector, 446, 0, 0, 0, 0, ptype, 0, 0, 0, lba, len(volume) // 512)
    sector[510:512] = b"\x55\xaa"
    return bytes(sector) + bytes(lba * 512 - 512) + volume


def gpt(volume: bytes, first: int = 2048, slot: int = 0) -> bytes:
    """A GPT disk whose partition entry `slot` (0-based) holds the volume; the entries before it are empty."""
    disk = bytearray(first * 512)
    disk[0:512] = mbr(b"", 1, 0xEE)[:512]
    hdr = bytearray(92)
    hdr[0:8] = b"EFI PART"
    struct.pack_into("<QII", hdr, 72, 2, 128, 128)
    disk[512:512 + 92] = hdr
    entry = bytearray(128)
    entry[0:16] = bytes(range(1, 17))                   # a non-zero type GUID
    struct.pack_into("<QQ", entry, 32, first, first + len(volume) // 512 - 1)
    disk[1024 + 128 * slot:1024 + 128 * (slot + 1)] = entry
    return bytes(disk) + volume


def fixed_vhd(raw: bytes) -> bytes:
    footer = bytearray(512)
    footer[0:8] = b"conectix"
    struct.pack_into(">Q", footer, 16, 0xFFFFFFFFFFFFFFFF)
    struct.pack_into(">QQ", footer, 40, len(raw), len(raw))
    struct.pack_into(">I", footer, 60, 2)
    struct.pack_into(">I", footer, 64, (~sum(footer)) & 0xFFFFFFFF)
    return raw + bytes(footer)


# ---------------------------------------------------------------- Word documents

W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


def docx(body: str, parts: dict | None = None, raw_document: bytes | None = None,
         compression: int = zipfile.ZIP_DEFLATED) -> bytes:
    """A .docx whose word/document.xml holds `body` (paragraph XML with the w: prefix) inside <w:body>."""
    doc = raw_document or (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                           f'<w:document xmlns:w="{W_NS}"><w:body>{body}</w:body></w:document>').encode()
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", compression) as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types/>')
        z.writestr("word/document.xml", doc)
        for name, xml in (parts or {}).items():
            z.writestr(name, xml)
    return bio.getvalue()


def part(root: str, inner: str) -> str:
    return f'<?xml version="1.0"?><w:{root} xmlns:w="{W_NS}">{inner}</w:{root}>'


def run(text: str) -> str:
    return f'<w:r><w:t xml:space="preserve">{text}</w:t></w:r>'


def ins(text: str, cid: int = 1, author: str = "clerk") -> str:
    return f'<w:ins w:id="{cid}" w:author="{author}" w:date="2026-02-14T03:00:00Z">{run(text)}</w:ins>'


def dele(text: str, cid: int = 2, author: str = "editor") -> str:
    return (f'<w:del w:id="{cid}" w:author="{author}" w:date="2026-02-14T04:00:00Z"><w:r>'
            f'<w:delText xml:space="preserve">{text}</w:delText></w:r></w:del>')


def para(*pieces: str) -> str:
    return "<w:p>" + "".join(pieces) + "</w:p>"
