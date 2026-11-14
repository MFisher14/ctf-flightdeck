#!/usr/bin/env python3
"""Metadata Forensics reader pack (B-221): the rest of the partitioned-disk family under `disk.*`.

properties_strict.py loads this file by name after readers_more.py and calls register(M). readers_more.py
already ships the `disk` namespace (disk_image and raw_disk are read as it) and its one judged reader,
disk.partition_start_lba_sequence (Huntress Day 28, json_numbers_table_order under
metadata.format/disk.partition_start_lba_sequence+gpt). This pack adds the facts a question about the same
image can ask next, all read from the same table:

  the table      disk.partition_table_type (gpt / mbr; `dos` too, fdisk's word for an MBR label),
                 disk.partition_count (occupied entries), disk.has_protective_mbr
  GPT header     disk.disk_guid, disk.sector_size_bytes, disk.first_usable_lba, disk.last_usable_lba,
                 disk.backup_header_lba, disk.partition_entry_lba, disk.partition_entry_count (the header's
                 slots, used or not), disk.partition_entry_size_bytes, disk.total_sectors
  per partition  sequences in table order: disk.partition_type_guid_sequence, disk.partition_guid_sequence,
                 disk.partition_name_sequence (GPT), disk.partition_type_code_sequence (MBR),
                 disk.partition_end_lba_sequence, disk.partition_sector_count_sequence,
                 disk.partition_size_bytes_sequence (GPT: the header states the sector size)
  MBR            disk.mbr_disk_signature

Every reader is registered unconfirmed: every answer is unsure until the judge accepts a name for it, and none
of them joins the judged start-LBA key. The table is the start-LBA reader's own (readers_more._gpt_table_at:
both CRCs, every LBA inside the image and the usable range), so these readers never trust an entry that
reader would refuse. The extractor contract is properties_strict's: the value; None when the image is not of
the scheme the fact belongs to (a GPT name on an MBR disk); M.Unknown when it is and the bytes do not settle
the fact, with the reason: a damaged GPT, valid GPT headers at 512 and 4096 bytes that disagree, a protective
MBR with no valid GPT behind it, an MBR entry with a zero start or length, an MBR extended partition (its
logical partitions are not walked, so no count or sequence is whole), a sector size an MBR never states, and
valid identical GPTs at both 512 and 4096 bytes (the LBAs agree; the sector size, and so every byte size, is
open).
"""
import functools
import json
import struct
import uuid as uuidlib

M = None          # properties_strict, set by register()
NS = "disk"
SECTORS = (512, 4096)
MBR_EXTENDED = frozenset({0x05, 0x0F, 0x85})
MBR_PROTECTIVE = 0xEE


def U(msg):
    raise M.Unknown(msg)


def _more():
    """readers_more.py, loaded before this pack: its GPT table and MBR parse are the ones read here."""
    mod = M.MORE_MODULES.get("readers_more.py")
    if mod is None:
        raise RuntimeError("readers_disk.py needs readers_more.py loaded first (MORE_FILES order)")
    return mod


def _gpt_tables(d: bytes):
    """The valid primary GPTs of the image (one per sector size that holds one) and the reasons the others
    were refused. A header-shaped sector that fails a check is a reason, never silently no table."""
    found, refused = [], []
    for sector in SECTORS:
        if d[sector:sector + 8] != b"EFI PART":
            continue
        try:
            table = _more()._gpt_table_at(d, sector)
        except M.Unknown as e:
            refused.append(str(e))
            continue
        if table is not None:
            found.append(table)
    return found, refused


def _comparable(t: dict):
    """Everything of a table but its sector size: two sector sizes that give this same tuple are one reading."""
    return (t["disk_guid"], t["first"], t["last"], t["count"], t["esize"],
            tuple((e["index"], e["type"], e["unique"], e["first"], e["last"], e["name"]) for e in t["entries"]))


@functools.lru_cache(maxsize=8)
def disk_table(d: bytes):
    """("gpt", table) or ("mbr", [(index, status, type, first LBA, sectors)] of the occupied entries) or None
    when the bytes are no partitioned disk. Unknown where the image is one and the table cannot be trusted."""
    found, refused = _gpt_tables(d)
    if found:
        if len({_comparable(t) for t in found}) != 1:
            U("different valid GPT headers for the candidate sector sizes")
        return "gpt", dict(found[0], candidates=tuple(t["sector"] for t in found))
    if refused:
        U(refused[0])
    mbr = _more()._mbr(d)
    if mbr is None:
        return None
    used = [(i, p[0], p[1], p[2], p[3]) for i, p in enumerate(mbr[0]) if p[1]]
    if any(p[2] == MBR_PROTECTIVE for p in used):
        U("a protective MBR without a valid primary GPT header")
    if any(p[3] == 0 or p[4] == 0 for p in used):
        U("an MBR partition entry with a zero start or sector count")
    return "mbr", used


def _whole(entries):
    """The MBR's occupied primary entries when they are every partition of the disk: Unknown with an
    extended partition, whose logical partitions (the EBR chain) are not walked."""
    if any(p[2] in MBR_EXTENDED for p in entries):
        U("an MBR extended partition: its logical partitions are not walked")
    return entries


def _sector(table):
    """The sector size a GPT was read at: Unknown when headers at 512 and 4096 bytes are both valid and
    give the same table (then the LBAs agree and only the sector size is open)."""
    if len(table["candidates"]) > 1:
        U("valid GPT headers at both 512 and 4096 bytes: the sector size is not settled")
    return table["sector"]


def _gpt(d: bytes):
    t = disk_table(d)
    return t[1] if t is not None and t[0] == "gpt" else None


def _guid(raw: bytes) -> str:
    """A GPT GUID (mixed-endian on disk) as its 32 lowercase hex digits in written order."""
    return uuidlib.UUID(bytes_le=raw).hex


def _hyphen(h: str) -> str:
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


def _name(raw: bytes) -> str:
    """A GPT partition name: UTF-16LE up to the first NUL code unit; '' for an unnamed entry."""
    end = next((i for i in range(0, len(raw) - 1, 2) if raw[i:i + 2] == b"\x00\x00"), len(raw) & ~1)
    try:
        return raw[:end].decode("utf-16-le")
    except UnicodeDecodeError:
        U("a GPT partition name that is not UTF-16")


def _numbers(values):
    """A sequence of numbers in table order: compact JSON first (the form Day 28 judged for the start LBAs)."""
    out = [("json_numbers_table_order", json.dumps(list(values), separators=(",", ":")))]
    if values:
        out += [("comma", ",".join(map(str, values))), ("comma_space", ", ".join(map(str, values)))]
    return out


def _guids(hexes):
    out = [("hyphen_lower", json.dumps([_hyphen(h) for h in hexes], separators=(",", ":"))),
           ("hyphen_upper", json.dumps([_hyphen(h).upper() for h in hexes], separators=(",", ":")))]
    if hexes:
        out.append(("comma", ",".join(_hyphen(h) for h in hexes)))
    return out


def _texts(names):
    out = [("json_compact", json.dumps(list(names), ensure_ascii=False, separators=(",", ":")))]
    if names and all(n and "," not in n for n in names):
        out.append(("comma", ",".join(names)))
    return out


def _seq(per_gpt, per_mbr, forms):
    """A sequence extractor: per_gpt(table) or per_mbr(entries) gives the list (None: not this scheme's fact),
    forms(list) its options."""
    def fn(n, d):
        t = disk_table(d)
        if t is None:
            return None
        values = per_gpt(t[1]) if t[0] == "gpt" else per_mbr(_whole(t[1]))
        return None if values is None else forms(values)
    return fn


def _gpt_only(get):
    def fn(n, d):
        g = _gpt(d)
        return None if g is None else get(g)
    return fn


def _scheme(n, d):
    t = disk_table(d)
    if t is None:
        return None
    return [("lower", "gpt"), ("upper", "GPT")] if t[0] == "gpt" else [("lower", "mbr"), ("upper", "MBR"), ("name", "dos")]


def _count(n, d):
    t = disk_table(d)
    return None if t is None else len(t[1]["entries"] if t[0] == "gpt" else _whole(t[1]))


def _protective(n, d):
    t = disk_table(d)
    if t is None:
        return None
    if t[0] == "mbr":
        return False
    if len(d) < 512 or d[510:512] != b"\x55\xaa":
        return False
    return any(d[446 + 16 * i + 4] == MBR_PROTECTIVE for i in range(4))


def _mbr_unstated(what):
    def fn(t):
        U(f"an MBR does not state its sector size, so {what} is not in the bytes")
    return fn


def _sector_size(n, d):
    t = disk_table(d)
    if t is None:
        return None
    if t[0] == "mbr":
        _mbr_unstated("the sector size")(t)
    return _sector(t[1])


def _total_sectors(n, d):
    t = disk_table(d)
    if t is None:
        return None
    if t[0] == "mbr":
        _mbr_unstated("the sector count")(t)
    return len(d) // _sector(t[1])


def _mbr_signature(n, d):
    t = disk_table(d)
    if t is None or t[0] != "mbr":
        return None
    return struct.unpack_from("<I", d, 440)[0]


def _register():
    reg = lambda names, fmt, fn: M.prop(*[f"{NS}.{x}" for x in names], fmt=fmt)(fn)
    reg(("partition_table_type", "partition_scheme", "partition_table_scheme", "partitioning_scheme",
         "partition_style", "partition_table_format"), "forms", _scheme)
    reg(("partition_count", "used_partition_count", "number_of_partitions", "occupied_partition_count"),
        "integer", _count)
    reg(("has_protective_mbr", "protective_mbr", "protective_mbr_present"), "bool", _protective)
    reg(("disk_guid", "disk_uuid", "gpt_disk_guid"), "uuid", _gpt_only(lambda g: _guid(g["disk_guid"])))
    reg(("sector_size_bytes", "logical_sector_size_bytes", "sector_size", "lba_size_bytes"), "integer", _sector_size)
    reg(("total_sectors", "total_lba_count", "disk_size_sectors"), "integer", _total_sectors)
    reg(("first_usable_lba", "gpt_first_usable_lba"), "integer", _gpt_only(lambda g: g["first"]))
    reg(("last_usable_lba", "gpt_last_usable_lba"), "integer", _gpt_only(lambda g: g["last"]))
    reg(("backup_header_lba", "alternate_header_lba", "backup_gpt_lba", "alternate_lba"), "integer",
        _gpt_only(lambda g: g["backup"]))
    reg(("partition_entry_lba", "partition_entry_array_lba", "partition_array_lba"), "integer",
        _gpt_only(lambda g: g["table_lba"]))
    reg(("partition_entry_count", "number_of_partition_entries", "partition_entry_slots"), "integer",
        _gpt_only(lambda g: g["count"]))
    reg(("partition_entry_size_bytes", "partition_entry_size"), "integer", _gpt_only(lambda g: g["esize"]))
    reg(("mbr_disk_signature", "disk_signature", "mbr_signature", "nt_disk_signature"), "u32hex", _mbr_signature)

    reg(("partition_type_guid_sequence", "partition_type_guids", "partition_type_guid_list"), "forms",
        _seq(lambda g: [_guid(e["type"]) for e in g["entries"]], lambda m: None, _guids))
    reg(("partition_guid_sequence", "partition_unique_guid_sequence", "partition_guids", "partition_unique_guids",
         "partition_uuid_sequence"), "forms",
        _seq(lambda g: [_guid(e["unique"]) for e in g["entries"]], lambda m: None, _guids))
    reg(("partition_name_sequence", "partition_names", "partition_name_list", "partition_label_sequence"), "forms",
        _seq(lambda g: [_name(e["name"]) for e in g["entries"]], lambda m: None, _texts))
    reg(("partition_type_code_sequence", "partition_type_codes", "mbr_partition_type_sequence",
         "partition_system_id_sequence"), "forms",
        _seq(lambda g: None, lambda m: [p[2] for p in m],
             lambda codes: [("hex_lower", json.dumps([f"{c:02x}" for c in codes], separators=(",", ":"))),
                            ("0x_hex_lower", json.dumps([f"0x{c:02x}" for c in codes], separators=(",", ":"))),
                            ("json_numbers_table_order", json.dumps(codes, separators=(",", ":")))]))
    reg(("partition_end_lba_sequence", "partition_last_lba_sequence", "partition_end_lbas"), "forms",
        _seq(lambda g: [e["last"] for e in g["entries"]], lambda m: [p[3] + p[4] - 1 for p in m], _numbers))
    reg(("partition_sector_count_sequence", "partition_size_sectors_sequence", "partition_sizes_sectors",
         "partition_length_sectors_sequence"), "forms",
        _seq(lambda g: [e["last"] - e["first"] + 1 for e in g["entries"]], lambda m: [p[4] for p in m], _numbers))
    reg(("partition_size_bytes_sequence", "partition_sizes_bytes"), "forms",
        _seq(lambda g: [(e["last"] - e["first"] + 1) * _sector(g) for e in g["entries"]],
             _mbr_unstated("a partition's size in bytes"), _numbers))


def register(module):
    """properties_strict calls this with its own module object. Returns (names, families) added."""
    global M
    M = module
    _more()
    if NS not in M.NAMESPACES:
        raise RuntimeError("readers_disk.py extends the disk namespace readers_more.py registers; it is not there")
    before, families = dict(M.REG), len(M.FAMILIES)
    _register()
    for k, old in before.items():   # a name registered before keeps its reader: nothing judged is replaced
        if M.REG[k] is not old:
            M.MORE_CLASHES.append(M.REG[k].name)
            M.REG[k] = old
    M.TIE_FREE.update(M.REG[k].fn for k in M.REG if k not in before)
    return len(M.REG) - len(before), len(M.FAMILIES) - families
