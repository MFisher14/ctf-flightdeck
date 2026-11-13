"""Day 14 lnk.target_path_windows for the Metadata speed solver: LinkInfo's LocalBasePath (the Unicode one when
the LinkInfo header carries it) + CommonPathSuffix, as the shipped reader composes it. None without LinkInfo.

Merged (B-001 hm-11) against CSCTF properties_strict._lnk_strings/_lnk_target: an empty string counts as
absent, so an empty Unicode LocalBasePath/CommonPathSuffix falls back to the ANSI one (the Huntress copy took
the empty Unicode text and dropped the ANSI path), and an undecodable string fails closed (None). Kept from
Huntress: a string with no NUL terminator is None, not the rest of the structure."""
from __future__ import annotations

import struct

_CLSID = bytes.fromhex("0114020000000000c000000000000046")


def _utf16z(b: bytes):
    for k in range(0, len(b) - 1, 2):
        if b[k] == 0 and b[k + 1] == 0:
            return b[:k].decode("utf-16-le") or None   # UnicodeDecodeError: lnk_target -> None
    return None


def _cstr(b: bytes):
    k = b.find(b"\x00")
    if k < 0:
        return None
    return b[:k].decode("latin-1") or None


def lnk_target(name, d):
    try:
        return _lnk_target(d)
    except (struct.error, UnicodeDecodeError):
        return None


def _lnk_target(d):
    if len(d) < 76 or d[:4] != b"\x4c\x00\x00\x00" or d[4:20] != _CLSID:
        return None
    flags = struct.unpack_from("<I", d, 20)[0]
    i = 76
    if flags & 0x1:
        i += 2 + struct.unpack_from("<H", d, i)[0]
    if not flags & 0x2 or i + 28 > len(d):
        return None
    size, head, iflags, _v, base_at, _n, suffix_at = struct.unpack_from("<IIIIIII", d, i)
    if i + size > len(d) or head < 0x1C:
        return None
    info = d[i:i + size]
    base = suffix = None
    if head >= 0x24:
        ubase, usuffix = struct.unpack_from("<II", info, 0x1C)
        if iflags & 1 and ubase:
            base = _utf16z(info[ubase:])
        if usuffix:
            suffix = _utf16z(info[usuffix:])
    if iflags & 1 and base is None:
        base = _cstr(info[base_at:])
    if suffix is None and suffix_at:
        suffix = _cstr(info[suffix_at:])
    if base is None:
        return None
    return base + (suffix or "")


PROPS = {"lnk-target-path-windows": lnk_target}
