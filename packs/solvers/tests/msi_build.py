"""Synthetic Windows Installer files for the MSI reader tests (B-220, tests/test_msi_reader.py).

Carried from the archived Huntress test tests/test_day13_metadata_msi.py (its builders only; its
saved-day checks are tests/test_msi_reader.py's `saved` tests, which read through ctf.paths). Every
file is built here byte by byte, and every expected value in the tests is the one a file was built with
or hashlib's:

  cfb(streams)         a version 3 compound file (512-byte sectors, small streams in the mini stream)
  msi_stream(name)     a stream name as an MSI database stores it (inverse of readers_formats.msi_name)
  Db                   an MSI database in the making: string pool (2- or 3-byte ids, long strings in
                       either published layout), _Tables, _Columns, column-major tables
  cabinet(members)     a one-folder cabinet: stored, MSZIP, LZX (one verbatim block of literals) or
                       Quantum (msi_fixtures.quantum_encode, the mirror of the pack's decoder)
  installer()          a scratch installer with the tables Day 13's had, optionally damaged
  package(), bundle_of()  an MSIX package and bundle around AppxManifest.xml
  with_summary(rev)    an installer whose SummaryInformation holds a Revision Number
"""
import contextlib
import hashlib
import io
import struct
import warnings
import zipfile
import zlib

from msi_fixtures import quantum_encode   # the mirror Quantum encoder (needs the pack's model update)

END, FREE, FATSECT, NOSTREAM = 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF
MSI_CLSID = bytes.fromhex("84100c00 0000 0000 c000 000000000046".replace(" ", ""))
B64 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._"


def msi_stream(name: str, table: bool) -> str:
    """A stream name as an MSI database stores it (the inverse of readers_formats.msi_name)."""
    out, i = ("䡀" if table else ""), 0
    while i < len(name):
        a = B64.find(name[i])
        b = B64.find(name[i + 1]) if i + 1 < len(name) else -1
        if a >= 0 and b >= 0:
            out += chr(0x3800 + a + (b << 6))
            i += 2
        elif a >= 0:
            out += chr(0x4800 + a)
            i += 1
        else:
            out += name[i]
            i += 1
    return out


def cfb(streams, clsid=MSI_CLSID) -> bytes:
    """A version 3 compound file of the streams [(stored name, bytes)]: a stream under 4096 bytes in
    the mini stream (64-byte sectors, its own FAT), a larger one in the FAT, the directory a chain of
    right siblings under the root. Sector order: directory, mini FAT, mini stream, large streams, FAT."""
    ss, ms, cutoff = 512, 64, 4096

    def sectors(n, size):
        return -(-n // size)
    mini_fat, mini, where = [], b"", []
    for _, body in streams:
        if len(body) < cutoff:
            n = sectors(len(body), ms)
            where.append(len(mini_fat) if n else END)
            mini_fat += list(range(len(mini_fat) + 1, len(mini_fat) + n)) + [END] if n else []
            mini += body.ljust(n * ms, b"\x00")
        else:
            where.append(None)
    dir_sectors = sectors(len(streams) + 1, 4)
    mini_fat_sectors = sectors(len(mini_fat) * 4, ss)
    mini_sectors = sectors(len(mini), ss)
    fat = list(range(1, dir_sectors)) + [END]
    at = dir_sectors
    first_mini_fat = at if mini_fat_sectors else END
    fat += list(range(at + 1, at + mini_fat_sectors)) + [END] if mini_fat_sectors else []
    at += mini_fat_sectors
    first_mini = at if mini_sectors else END
    fat += list(range(at + 1, at + mini_sectors)) + [END] if mini_sectors else []
    at += mini_sectors
    large = b""
    for i, (_, body) in enumerate(streams):
        if where[i] is None:
            n = sectors(len(body), ss)
            where[i] = at
            fat += list(range(at + 1, at + n)) + [END]
            at += n
            large += body.ljust(n * ss, b"\x00")
    fat_sectors = 1
    while fat_sectors * (ss // 4) < at + fat_sectors:
        fat_sectors += 1
    fat += [FATSECT] * fat_sectors
    fat += [FREE] * (fat_sectors * (ss // 4) - len(fat))

    def entry(name, kind, right, child, start, size, cls=b"\x00" * 16):
        raw = (name + "\x00").encode("utf-16-le")
        return (raw.ljust(64, b"\x00") + struct.pack("<HBBIII", len(raw), kind, 1, NOSTREAM, right, child) + cls
                + struct.pack("<I8s8sIII", 0, b"", b"", start, size, 0))
    directory = entry("Root Entry", 5, NOSTREAM, 1 if streams else NOSTREAM, first_mini, len(mini), clsid)
    for i, (name, body) in enumerate(streams):
        directory += entry(name, 2, i + 2 if i + 1 < len(streams) else NOSTREAM, NOSTREAM, where[i], len(body))
    directory = directory.ljust(dir_sectors * ss, b"\x00")
    header = (bytes.fromhex("d0cf11e0a1b11ae1") + b"\x00" * 16 + struct.pack("<HHHHH", 0x3E, 3, 0xFFFE, 9, 6) + b"\x00" * 6
              + struct.pack("<IIIIIIIII", 0, fat_sectors, 0, 0, cutoff, first_mini_fat, mini_fat_sectors, END, 0)
              + struct.pack("<109I", *([at + i for i in range(fat_sectors)] + [FREE] * (109 - fat_sectors))))
    mini_fat_bytes = struct.pack(f"<{len(mini_fat)}I", *mini_fat).ljust(mini_fat_sectors * ss, b"\xff")
    return (header + directory + mini_fat_bytes + mini.ljust(mini_sectors * ss, b"\x00") + large
            + struct.pack(f"<{len(fat)}I", *fat))


STR, KEY, NUL, I2, I4 = 0x0D48, 0x2D48, 0x1000, 0x0502, 0x0104   # a string column, a key string, nullable, i2, i4
LONG_MARK = object()   # in Db.strings: the id an empty first entry of a long string takes


class Db:
    """An MSI database in the making: tables as (columns [(name, type)], rows)."""

    def __init__(self, codepage=0, wide=False, long="refs_first", long_own_id=False):
        """`long`: how a string of 64 KiB or more is written, `refs_first` ((0, refcount) then (low
        word, high word)) or `high_first` ((0, high word) then (low word, refcount)); `long_own_id`:
        whether its empty first entry takes a string id."""
        self.codepage, self.wide, self.strings, self.tables = codepage, wide, [], {}
        self.long, self.long_own_id = long, long_own_id

    def sid(self, text):
        if text is None or text == "":
            return 0
        raw = text if isinstance(text, bytes) else text.encode("ascii" if self.codepage == 0 else f"cp{self.codepage}")
        if raw not in self.strings:
            if len(raw) >= 0x10000 and self.long_own_id:
                self.strings.append(LONG_MARK)
            self.strings.append(raw)
        return self.strings.index(raw) + 1

    def pool(self):
        out = struct.pack("<HH", self.codepage, 0x8000 if self.wide else 0)
        for raw in self.strings:
            if raw is LONG_MARK:
                continue
            if len(raw) < 0x10000:
                out += struct.pack("<HH", len(raw), 1)
            elif self.long == "refs_first":
                out += struct.pack("<HHHH", 0, 2, len(raw) & 0xFFFF, len(raw) >> 16)
            else:
                out += struct.pack("<HHHH", 0, len(raw) >> 16, len(raw) & 0xFFFF, 2)
        return out

    def table(self, name, columns, rows):
        self.tables[name] = (columns, rows)

    def _ids(self, values):
        return b"".join(v.to_bytes(3 if self.wide else 2, "little") for v in values)

    def streams(self, extra=(), declare=()):
        """[(stored name, bytes)]: the tables, _Tables, _Columns, then the pool (built last, so it
        holds every string), then the plain streams of `extra`."""
        out, cols = [], []
        for name, (columns, rows) in self.tables.items():
            body = b""
            for i, (column, kind) in enumerate(columns):
                cols.append((name, i + 1, column, kind))
                cells = [row[i] for row in rows]
                if kind & 0x0800:
                    body += self._ids([self.sid(c) for c in cells])
                elif kind & 0xFF == 4:
                    body += b"".join(struct.pack("<I", 0 if c is None else (c + 0x80000000) & 0xFFFFFFFF) for c in cells)
                else:
                    body += b"".join(struct.pack("<H", 0 if c is None else (c + 0x8000) & 0xFFFF) for c in cells)
            if rows:
                out.append((msi_stream(name, True), body))
        names = list(self.tables) + list(declare)
        out.append((msi_stream("_Tables", True), self._ids([self.sid(n) for n in names])))
        out.append((msi_stream("_Columns", True),
                    self._ids([self.sid(t) for t, _, _, _ in cols]) + b"".join(struct.pack("<H", n ^ 0x8000) for _, n, _, _ in cols)
                    + self._ids([self.sid(c) for _, _, c, _ in cols]) + b"".join(struct.pack("<H", k ^ 0x8000) for _, _, _, k in cols)))
        out.append((msi_stream("_StringPool", True), self.pool()))
        out.append((msi_stream("_StringData", True), b"".join(x for x in self.strings if x is not LONG_MARK)))
        return out + [(msi_stream(n, False), b) for n, b in extra]


class Bits:
    """An LZX bit stream: bits most significant first, in 16-bit little-endian words."""

    def __init__(self):
        self.bits = []

    def put(self, value, n):
        self.bits += [(value >> (n - 1 - i)) & 1 for i in range(n)]

    def bytes(self):
        bits = self.bits + [0] * (-len(self.bits) % 16)
        out = b""
        for i in range(0, len(bits), 16):
            out += struct.pack("<H", int("".join(map(str, bits[i:i + 16])), 2))
        return out


def lzx(data: bytes) -> bytes:
    """`data` (under 32 KiB) as one LZX frame: no E8 translation, one verbatim block, every byte a
    literal. The main tree gives the 256 literals 8 bits each (so a literal's code is its value) and
    no match symbol a code; the length tree gives two symbols 1 bit each. Path lengths are written as
    (previous - new) mod 17 through a pretree of three codes: 0 -> `0`, 9 -> `10`, 16 -> `11`."""
    assert 0 < len(data) < 32768
    b = Bits()
    b.put(0, 1)                         # no Intel E8 preprocessing
    b.put(1, 3)                         # block type: verbatim
    b.put(len(data) >> 8, 16)           # the block's 24-bit size: the high 16 bits, then the low 8
    b.put(len(data) & 0xFF, 8)

    def pretree():
        for sym in range(20):
            b.put({0: 1, 9: 2, 16: 2}.get(sym, 0), 4)
    pretree()
    for _ in range(256):                # main tree, literals: length 8 = symbol 9
        b.put(0b10, 2)
    pretree()
    for _ in range(30 * 8):             # main tree, match symbols (30 position slots for a 32 KiB window): 0
        b.put(0, 1)
    pretree()
    for i in range(249):                # length tree: two symbols of length 1 = symbol 16, the rest 0
        if i < 2:
            b.put(0b11, 2)
        else:
            b.put(0, 1)
    for byte in data:
        b.put(byte, 8)
    return b.bytes()


def cab_checksum(data: bytes, seed: int) -> int:
    """The checksum of a cabinet's data block ([MS-CAB] 3.1): 32-bit little-endian words XORed
    together, then the one to three bytes left over."""
    for i in range(0, len(data) - len(data) % 4, 4):
        seed ^= data[i] | data[i + 1] << 8 | data[i + 2] << 16 | data[i + 3] << 24
    tail = data[len(data) - len(data) % 4:]
    if len(tail) == 3:
        seed ^= tail[0] << 16 | tail[1] << 8 | tail[2]
    elif len(tail) == 2:
        seed ^= tail[0] << 8 | tail[1]
    elif len(tail) == 1:
        seed ^= tail[0]
    return seed


def cabinet(members, method=1, continues=None, extra_block=None) -> bytes:
    """A one-folder cabinet of [(name, bytes)]: MSZIP (1), stored (0), LZX with a 32 KiB window (3),
    Quantum by quantum_encode (2, as many blocks as it has frames) or, for `bad-quantum`, bytes that
    are no Quantum stream. `continues` gives a member an iFolder of its own ({index: 0xFFFE});
    `extra_block` adds a last data block (packed bytes, stated unpacked size). A name given as bytes is
    written as it is."""
    whole = b"".join(b for _, b in members)
    kind, frames = method, None
    if method == 1:
        z = zlib.compressobj(9, zlib.DEFLATED, -15)
        packed = b"CK" + z.compress(whole) + z.flush()
    elif method == 3:
        packed, kind = lzx(whole), 3 | (15 << 8)
    elif method == 2:
        frames, kind = quantum_encode(whole, 18), 2 | (7 << 4) | (18 << 8)
    elif method == "bad-quantum":
        packed, kind = b"\x00" * 16, 2 | (4 << 4) | (10 << 8)
    else:
        packed = whole
    frames = frames or [(packed, len(whole))]
    files, at = b"", 0
    for i, (name, body) in enumerate(members):
        files += (struct.pack("<IIHHHH", len(body), at, (continues or {}).get(i, 0), 0x5A21, 0, 0x20)
                  + (name if isinstance(name, bytes) else name.encode("ascii")) + b"\x00")
        at += len(body)

    def block(body, unpacked):
        head = struct.pack("<HH", len(body), unpacked)
        return struct.pack("<I", cab_checksum(head, cab_checksum(body, 0))) + head + body
    blocks = b"".join(block(*frame) for frame in frames)
    if extra_block:
        blocks += block(*extra_block)
    files_at = 36 + 8
    data_at = files_at + len(files)
    size = data_at + len(blocks)
    return (b"MSCF" + struct.pack("<IIIIIBBHHHHH", 0, size, 0, files_at, 0, 3, 1, 1, len(members), 0, 0x1234, 0)
            + struct.pack("<IHH", data_at, len(frames) + (1 if extra_block else 0), kind) + files + blocks)


PRODUCT, UPGRADE, COMPONENT = ("{DD1A80D5-0250-4F4D-B289-13096D633C61}", "{5F63B105-6C37-46FB-B671-2AF6C4F4CD67}",
                               "{0DF92558-CBF2-48AC-A8C1-8DC80B710C29}")
PAYLOAD = b"scratch payload, 24 b.\r\n"
PROPERTIES = [("UpgradeCode", UPGRADE), ("ALLUSERS", "1"), ("Manufacturer", "Scratch Labs"), ("ProductLanguage", "1033"),
              ("ProductCode", PRODUCT), ("ProductName", "Scratch Product"), ("ProductVersion", "2.7.1"),
              ("ARPCONTACT", "desk@example.invalid")]


def installer(product=PRODUCT, properties=None, wide=False, codepage=0, method=1, damage=None, files=1, twice=None,
              cab=None, **db_options) -> bytes:
    """A scratch installer with the tables Day 13's had. `damage` breaks one thing: pool-sum,
    table-rows, string-id, two-rows, long-string; `twice` stores a table's stream twice."""
    db = Db(codepage, wide, **db_options)
    rows = [(n, product if n == "ProductCode" else v) for n, v in (properties or PROPERTIES)]
    if product is None:
        rows = [r for r in rows if r[0] != "ProductCode"]
    if damage == "two-rows":
        rows.append(("ProductCode", UPGRADE))
    db.table("Property", [("Property", KEY), ("Value", 0x0F00)], rows)
    db.table("Component", [("Component", KEY), ("ComponentId", 0x1D26), ("Directory_", STR), ("Attributes", I2),
                           ("Condition", 0x1DFF), ("KeyPath", 0x1D48)],
             [("MarkerComponent", COMPONENT, "INSTALLFOLDER", 256, None, "MarkerFile")])
    names = ["evidence.txt", "second.bin"][:files]
    db.table("File", [("File", KEY), ("Component_", STR), ("FileName", 0x0FFF), ("FileSize", I4), ("Version", 0x1D48),
                      ("Language", 0x1D14), ("Attributes", 0x1502), ("Sequence", I4)],
             [(f"File{i}", "MarkerComponent", n, len(PAYLOAD), None, None, 512, i + 1) for i, n in enumerate(names)])
    db.table("Media", [("DiskId", 0x2502), ("LastSequence", I4), ("DiskPrompt", 0x1F40), ("Cabinet", 0x1DFF),
                       ("VolumeLabel", 0x1D20), ("Source", 0x1D48)], [(1, 1, None, "#artifact.cab", None, None)])
    db.table("Feature", [("Feature", 0x2D26), ("Feature_Parent", 0x1D26), ("Title", 0x1F40), ("Description", 0x1FFF),
                         ("Display", 0x1502), ("Level", I2), ("Directory_", 0x1D48), ("Attributes", I2)],
             [("Complete", None, "Scratch Product", None, 2, 1, None, 0)])
    db.table("Directory", [("Directory", KEY), ("Directory_Parent", 0x1D48), ("DefaultDir", 0x0FFF)],
             [("INSTALLFOLDER", "ProgramFiles64Folder", "Scratch Product"), ("ProgramFiles64Folder", "TARGETDIR", "."),
              ("TARGETDIR", None, "SourceDir")])
    parts = struct.unpack("<4i", hashlib.md5(PAYLOAD).digest())
    db.table("MsiFileHash", [("File_", KEY), ("Options", I2), ("HashPart1", I4), ("HashPart2", I4), ("HashPart3", I4),
                             ("HashPart4", I4)], [("File0", 0) + parts])
    db.table("Binary", [("Name", KEY), ("Data", 0x0900)], [])
    cab = cab or cabinet([(f"File{i}", PAYLOAD) for i in range(files)], method)
    streams = db.streams(extra=[("artifact.cab", cab)], declare=("Error",))
    named = {n: i for i, (n, _) in enumerate(streams)}

    def change(table, fn):
        i = named[msi_stream(table, True)]
        streams[i] = (streams[i][0], fn(streams[i][1]))
    if damage == "pool-sum":
        change("_StringData", lambda b: b + b"x")
    elif damage == "table-rows":
        change("Property", lambda b: b + b"\x01")
    elif damage == "string-id":
        change("Property", lambda b: b[:-2] + b"\xff\x7f")
    elif damage == "long-string":
        change("_StringPool", lambda b: b[:4] + struct.pack("<HH", 0, 2) + b[8:])
    if twice:
        streams.append(streams[named[msi_stream(twice, True)]])
    return cfb(streams)


def with_raw_string(rows):
    """The streams of an installer whose pool says codepage 0 while its strings are cp1252 bytes."""
    db = Db(1252)
    db.table("Property", [("Property", KEY), ("Value", 0x0F00)], rows)
    streams = db.streams()
    i = next(i for i, (n, _) in enumerate(streams) if n == msi_stream("_StringPool", True))
    streams[i] = (streams[i][0], struct.pack("<HH", 0, 0) + streams[i][1][4:])
    return streams


MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10">
  <Identity Name="Scratch.Notes" Publisher="CN=Scratch Labs, O=Scratch, C=US" Version="3.2.1.0" ProcessorArchitecture="x64" />
  <Properties><DisplayName>Scratch Notes</DisplayName><PublisherDisplayName>Scratch Labs</PublisherDisplayName>
    <Logo>Assets\\StoreLogo.png</Logo></Properties>
  <Dependencies><TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.22621.0" /></Dependencies>
  <Applications><Application Id="App" Executable="Notes.exe" EntryPoint="Windows.FullTrustApplication" /></Applications>
  <Capabilities><Capability Name="internetClient" /><uap:Capability Name="documentsLibrary" /></Capabilities>
</Package>
"""

BUNDLE = """<?xml version="1.0" encoding="utf-8"?>
<Bundle xmlns="http://schemas.microsoft.com/appx/2013/bundle" SchemaVersion="5.0.0.0">
  <Identity Name="Scratch.Notes" Publisher="CN=Scratch Labs, O=Scratch, C=US" Version="2026.1013.1.0" />
  <Packages>
    <Package Type="application" Version="3.2.1.0" Architecture="x64" FileName="Notes_x64.msix" Offset="61" Size="1000" />
    <Package Type="application" Version="3.2.1.0" Architecture="arm64" FileName="Notes_arm64.msix" Offset="1200" Size="1000" />
    <Package Type="resource" Version="3.2.1.0" ResourceId="scale-140" FileName="Notes_scale-140.msix" Offset="2400" Size="1000" />
  </Packages>
</Bundle>
"""
MS_STORE = "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
MS_WINDOWS = "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"


def package(manifests=(MANIFEST,), signed=True):
    """An MSIX package (a zip) holding the given AppxManifest.xml texts (two: a duplicate name)."""
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("Notes.exe", b"MZ" + b"\x00" * 64)
        for m in manifests:
            with contextlib.suppress(UserWarning), warnings.catch_warnings():
                warnings.simplefilter("ignore")
                z.writestr("AppxManifest.xml", m)
        z.writestr("AppxBlockMap.xml", "<BlockMap/>")
        if signed:
            z.writestr("AppxSignature.p7x", b"PKCX")
    return out.getvalue()


def bundle_of(inner, manifest=BUNDLE):
    """An MSIX bundle (stored zip) of {file name: package bytes} and a bundle manifest."""
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as z:
        for name, body in inner.items():
            z.writestr(name, body)
        z.writestr("AppxMetadata/AppxBundleManifest.xml", manifest)
        z.writestr("AppxBlockMap.xml", "<BlockMap/>")
    return out.getvalue()


def summary_stream(revision: str) -> bytes:
    """A SummaryInformation property set with a title (PID 2) and a revision number (PID 9), both VT_LPSTR."""
    def lpstr(text):
        raw = text.encode("ascii") + b"\x00"
        return struct.pack("<II", 30, len(raw)) + raw.ljust(-(-len(raw) // 4) * 4, b"\x00")
    values = [(1, struct.pack("<IHH", 2, 1252, 0)), (2, lpstr("Installation Database")), (9, lpstr(revision))]
    at, index, body = 8 + 8 * len(values), b"", b""
    for pid, value in values:
        index += struct.pack("<II", pid, at + len(body))
        body += value
    section = struct.pack("<II", at + len(body), len(values)) + index + body
    fmtid = bytes.fromhex("e0859ff2f94f6810ab9108002b27b3d9")
    return struct.pack("<HHI", 0xFFFE, 0, 0x00020006) + b"\x00" * 16 + struct.pack("<I", 1) + fmtid + struct.pack("<I", 48) + section


def with_summary(revision: str) -> bytes:
    """An installer with a Property table and a SummaryInformation stream holding `revision`."""
    db = Db()
    db.table("Property", [("Property", KEY), ("Value", 0x0F00)], PROPERTIES)
    return cfb(db.streams() + [("\x05SummaryInformation", summary_stream(revision))])
