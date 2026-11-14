#!/usr/bin/env python3
"""A PE image's resource directory, walked (the Day 21 build, round 2; the Binary look-ahead's L3,
`docs/retro/day-21-predictions-binary.md`, p .10 for a PE d21).

    walk(data, pe=None) -> {"types": [...], "leaves": [...]} or None

`pe` is binfmt.pe(data) when the caller has it. The directory is the three levels of the format (type, name or
id, language), each an IMAGE_RESOURCE_DIRECTORY of 16 bytes followed by its named entries and then its id
entries (8 bytes each: the name or id, with the high bit for a name string; the offset, with the high bit for a
subdirectory), names as a u16 length and UTF-16LE text, leaves as IMAGE_RESOURCE_DATA_ENTRY (rva, size,
codepage). A leaf is {"type", "type_id", "name", "id", "lang", "rva", "offset", "size", "hcfg"} with `type` the
RT_ name for a standard id or the type's own name string, `name` the entry's name string (None for an id entry),
`hcfg` whether a CRC-valid HCFG record stands in the leaf's bytes.

Bounds: 4096 entries in all, 3 levels, every offset inside the resource section; a loop or a cut table reads
nothing (None). The catalog asks it only for a field that names a resource (field_catalog's L3 rules), so no
other solve pays for it. What it reads is never plain: every answer is a labels.pick under
binary.pe_resource/<field> until the judge accepts a name."""
import struct

RT = {1: "RT_CURSOR", 2: "RT_BITMAP", 3: "RT_ICON", 4: "RT_MENU", 5: "RT_DIALOG", 6: "RT_STRING", 7: "RT_FONTDIR",
      8: "RT_FONT", 9: "RT_ACCELERATOR", 10: "RT_RCDATA", 11: "RT_MESSAGETABLE", 12: "RT_GROUP_CURSOR",
      14: "RT_GROUP_ICON", 16: "RT_VERSION", 17: "RT_DLGINCLUDE", 19: "RT_PLUGPLAY", 20: "RT_VXD",
      21: "RT_ANICURSOR", 22: "RT_ANIICON", 23: "RT_HTML", 24: "RT_MANIFEST"}
ENTRIES_MAX = 4096


def _offset(pe: dict, rva: int, length: int = 1):
    for s in pe["sections"]:
        size = max(s["vsize"], s["rsize"])
        if (s["va"] <= rva < s["va"] + size and rva - s["va"] < s["rsize"]
                and length <= s["rsize"] - (rva - s["va"])):
            return s["raw"] + rva - s["va"]
    return None


def walk(data: bytes, pe=None):
    if pe is None:
        import binfmt
        pe = binfmt.pe(data)
    if not pe:
        return None
    rva, size = pe["dirs"].get("resource", (0, 0))
    if not rva or not size:
        return None
    base = _offset(pe, rva)
    if base is None or base >= len(data):
        return None
    end = min(len(data), base + size)
    seen, count = set(), [0]

    def name_at(off):
        at = base + off
        if at + 2 > end:
            raise ValueError("a name past the directory")
        n = struct.unpack_from("<H", data, at)[0]
        if at + 2 + 2 * n > end:
            raise ValueError("a name past the directory")
        return data[at + 2:at + 2 + 2 * n].decode("utf-16-le", "replace")

    def entries(off):
        at = base + off
        if off in seen or at + 16 > end:
            raise ValueError("a loop or a cut directory")
        seen.add(off)
        named, ids = struct.unpack_from("<HH", data, at + 12)
        out = []
        for i in range(named + ids):
            e = at + 16 + 8 * i
            count[0] += 1
            if e + 8 > end or count[0] > ENTRIES_MAX:
                raise ValueError("a cut table")
            ident, target = struct.unpack_from("<II", data, e)
            label = name_at(ident & 0x7FFFFFFF) if ident & 0x80000000 else None
            out.append((label, None if label is not None else ident & 0xFFFF, target))
        return out

    try:
        types, leaves = [], []
        for tname, tid, tdir in entries(0):
            if not tdir & 0x80000000:
                raise ValueError("a type that is no directory")
            tlabel = tname if tname is not None else RT.get(tid, str(tid))
            types.append({"type": tlabel, "type_id": tid})
            for name, nid, ndir in entries(tdir & 0x7FFFFFFF):
                langs = entries(ndir & 0x7FFFFFFF) if ndir & 0x80000000 else [(None, None, ndir)]
                for _, lang, leaf in langs:
                    if leaf & 0x80000000 or base + leaf + 16 > end:
                        raise ValueError("a leaf that is no data entry")
                    drva, dsize = struct.unpack_from("<II", data, base + leaf)
                    off = _offset(pe, drva, dsize)
                    if off is None or off > len(data) or dsize > len(data) - off:
                        raise ValueError("a resource payload outside its section or file")
                    blob = data[off:off + dsize]
                    leaves.append({"type": tlabel, "type_id": tid, "name": name, "id": nid, "lang": lang,
                                   "rva": drva, "offset": off, "size": dsize, "hcfg": _has_record(blob)})
    except (ValueError, struct.error):
        return None
    return {"types": types, "leaves": leaves}


def _has_record(blob: bytes) -> bool:
    if b"HCFG" not in blob:
        return False
    import hcfg
    return any(c["crc_ok"] for c in hcfg.containers(blob))
