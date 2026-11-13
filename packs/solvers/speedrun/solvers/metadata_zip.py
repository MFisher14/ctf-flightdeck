"""A lean in-memory zip reader for the Metadata speed solver's small inner zips (an APK, a JAR, a DOCX, a
cluster/case zip): the central directory parsed with struct, members read as raw slices and inflated with
zlib, no CRC pass. It answers only the plain shape (no zip64, no prefix, no encryption, stored or deflated
members); anything else is handed to zipfile, so the result is never different from zipfile's, only faster.

Not a day module (the dispatcher loads only metadata_dNN), imported by them.
"""
from __future__ import annotations

import io
import struct
import zipfile
import zlib


class _Info:
    __slots__ = ("filename", "compress_type", "flag_bits", "compress_size", "file_size", "header_offset")

    def __init__(self, filename, compress_type, flag_bits, compress_size, file_size, header_offset):
        self.filename = filename
        self.compress_type = compress_type
        self.flag_bits = flag_bits
        self.compress_size = compress_size
        self.file_size = file_size
        self.header_offset = header_offset

    def is_dir(self):
        return self.filename.endswith("/")


class Lite:
    def __init__(self, data: bytes, infos: list):
        self.data = data
        self._infos = infos
        self._by = {}
        for i in infos:
            self._by[i.filename] = i   # zipfile: the last entry of a name wins in getinfo/read

    def infolist(self):
        return list(self._infos)

    def namelist(self):
        return [i.filename for i in self._infos]

    def getinfo(self, name):
        try:
            return self._by[name]
        except KeyError:
            raise KeyError(f"There is no item named {name!r} in the archive")

    def read(self, member):
        inf = member if isinstance(member, _Info) else self.getinfo(member)
        d = self.data
        o = inf.header_offset
        if d[o:o + 4] != b"PK\x03\x04":
            raise zipfile.BadZipFile("bad local header")
        nl, xl = struct.unpack_from("<HH", d, o + 26)
        s = o + 30 + nl + xl
        raw = d[s:s + inf.compress_size]
        if inf.compress_type == 0:
            return raw
        return zlib.decompress(raw, -15)


def open_zip(d: bytes):
    """A Lite view of a plain zip, else zipfile.ZipFile (which raises for a non-zip)."""
    try:
        lite = _lite(d)
    except Exception:
        lite = None
    return lite if lite is not None else zipfile.ZipFile(io.BytesIO(d))


def _lite(d: bytes):
    n = len(d)
    if n < 22 or d[:4] != b"PK\x03\x04":
        return None
    pos = n - 22
    if d[pos:pos + 4] != b"PK\x05\x06":
        return None   # a comment or trailing bytes: zipfile
    disk, cdisk, cnt_disk, cnt, cd_size, cd_off, clen = struct.unpack_from("<HHHHIIH", d, pos + 4)
    if disk or cdisk or cnt != cnt_disk or cnt == 0xFFFF or cd_off + cd_size != pos or clen:
        return None
    infos = []
    p = cd_off
    for _ in range(cnt):
        if d[p:p + 4] != b"PK\x01\x02":
            return None
        (flags, method, _t, _dt, _crc, csize, size, nlen, xlen, cmlen, _dsk, _ia, _ea,
         off) = struct.unpack_from("<HHHHIIIHHHHHII", d, p + 8)
        if flags & 1 or method not in (0, 8) or 0xFFFFFFFF in (csize, size, off):
            return None
        raw = d[p + 46:p + 46 + nlen]
        if flags & 0x800:
            name = raw.decode("utf-8")
        else:
            name = raw.decode("cp437")
        if "\x00" in name or "\\" in name:
            return None   # zipfile rewrites these: leave the shape to it
        infos.append(_Info(name, method, flags, csize, size, off))
        p += 46 + nlen + xlen + cmlen
    if p != pos:
        return None
    return Lite(d, infos)
