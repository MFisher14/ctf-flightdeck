"""Day 21 apk.package_name for the Metadata speed solver: the `package` attribute of the <manifest> element
of the APK's compiled AndroidManifest.xml (binary XML), verbatim. Fails closed (None) on anything odd.

Merged (B-001 hm-11) against the shipped reader (readers_apk._package over apk_resources.axml_tree): the
element's attribute block is found from the chunk's own header size (not a fixed 16), the attribute stride is
at least 20 bytes, the walk stops at the document's stated size and at a chunk that runs past it, the file must
open with a RES_XML header of size 8, and an empty package is no answer. Kept from Huntress: the lean zip
reader, one AndroidManifest.xml only, and a package that is neither a raw string nor a string value is None."""
from __future__ import annotations

import struct
import zipfile
import zlib

try:
    from .metadata_zip import open_zip
except ImportError:  # loaded without the package
    from metadata_zip import open_zip


def _strings(d: bytes, at: int):
    _t, hs, size, count, _sc, flags, sstart, _ss = struct.unpack_from("<HHIIIIII", d, at)
    utf8 = flags & 0x100
    offs = struct.unpack_from(f"<{count}I", d, at + hs)
    base = at + sstart
    out = []
    for o in offs:
        p = base + o
        if utf8:
            n = d[p]; p += 1
            if n & 0x80:
                p += 1
            n = d[p]; p += 1
            if n & 0x80:
                n = ((n & 0x7F) << 8) | d[p]; p += 1
            out.append(d[p:p + n].decode("utf-8", "replace"))
        else:
            n = struct.unpack_from("<H", d, p)[0]; p += 2
            if n & 0x8000:
                n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", d, p)[0]; p += 2
            out.append(d[p:p + 2 * n].decode("utf-16-le", "replace"))
    return out, at + size


def axml_manifest_package(x: bytes):
    try:
        return _axml_manifest_package(x)
    except (struct.error, IndexError):
        return None


def _axml_manifest_package(x: bytes):
    if len(x) < 8 or struct.unpack_from("<HH", x, 0) != (0x0003, 8):
        return None
    at, n = 8, min(len(x), struct.unpack_from("<I", x, 4)[0])
    strings = None
    found = []
    while at + 8 <= n:
        typ, hs, size = struct.unpack_from("<HHI", x, at)
        if size < 8 or at + size > n:
            break
        if typ == 0x0001:
            strings, _ = _strings(x, at)
        elif typ == 0x0102 and strings is not None:
            name_i = struct.unpack_from("<I", x, at + hs + 4)[0]
            astart, asize, acount = struct.unpack_from("<HHH", x, at + hs + 8)
            if 0 <= name_i < len(strings) and strings[name_i] == "manifest":
                base = at + hs + astart
                for k in range(acount):
                    a = base + k * max(asize, 20)
                    _ns, an, raw, _vs, _r0, vt, vd = struct.unpack_from("<IIIHBBI", x, a)
                    if an < len(strings) and strings[an] == "package":
                        if raw != 0xFFFFFFFF and raw < len(strings):
                            found.append(strings[raw])
                        elif vt == 0x03 and vd < len(strings):
                            found.append(strings[vd])
                        else:
                            return None
        at += size
    if len(set(found)) != 1 or not found[0]:
        return None
    return found[0]


def apk_package(name, d):
    if d[:4] != b"PK\x03\x04":
        return None
    try:
        z = open_zip(d)
        hits = [i for i in z.infolist() if i.filename == "AndroidManifest.xml"]
        if len(hits) != 1:
            return None
        body = z.read(hits[0])
    except (zipfile.BadZipFile, zlib.error, struct.error, OSError, NotImplementedError, RuntimeError):
        return None
    return axml_manifest_package(body)


PROPS = {"apk-package-name": apk_package}
