#!/usr/bin/env python3
"""Metadata Forensics wave4 pack (ticket T7, docs/retro/day24plus-buildplan-metadata.md): deeper
forensic-container readers for the structural facts the lane did not already read.

properties_strict.py loads this file by name LAST in MORE_FILES and calls register(M) with itself.
Nothing here answers plain: every name is registered unconfirmed (free()/reg() below only register a
<ns>.<name> that NOTHING already reads), so the strict wrapper offers each through labels.pick until the
judge accepts a format for its key. Because the pack registers only free names and adds nothing to
conventions.json, it can never change a reading an earlier reader or a judged seed already gives, and every
saved attempt replays byte for byte as before.

Scope, after reading the whole lane (readers_day14*, readers_structures, readers_formats, properties_strict):
the lane ALREADY reads pcap/pcapng headers and timestamps, the regf base block and root subkeys, the evtx
file header and record count, the prefetch header (version, size, executable, hash, run count, last run),
the NTFS $MFT record (readers_formats) and SQLite header/schema counts in full. This pack fills the three
genuine gaps only:

  usn       the $UsnJrnl $J change journal, which had NO reader and NO magic of its own. Dispatch is by
            the first record's STRUCTURE (version 2 or 3, the fixed header size, a filename that decodes;
            or, since B-248, a strict V4.0 range-tracking record with its extent table), never by extension,
            so an arbitrary file is not misread as a journal. First-record fields, a record count over
            mixed V2/V3/V4 records, per-version counts and a V4 record's extents, all read from the bytes.
  regf      the root key's VALUE list (count, names), its class name and its own last-written time: the
            base-block fields and the subkey list are read elsewhere; the value list was not.
  prefetch  the VOLUME INFORMATION block (count, first volume's device path, serial and creation time):
            the volume-info offset/count/size live at a fixed place (0x6C/0x70/0x74) for every uncompressed
            SCCA version 17 to 30, and the leading entry fields (device path, creation time, serial) share
            one layout.
  ewf       the Expert Witness (EnCase .E01/.Ex01) image file: the file header had NO reader and NO magic of
            its own. The classic EVF/LVF segment file begins with an 8-byte signature, a 1-byte fields_start,
            a 16-bit segment number and a 16-bit fields_end, then a run of section descriptors (a 16-byte
            type string, then offsets). Dispatch is by the exact signature and a plausible fields_start, so
            an arbitrary file is never read as an image. Segment number, format and the first section's type,
            all read straight from the header. (Day 25 look-ahead #3: a classic-forensic container with no
            reader -> STOP; this closes EWF/E01 unsure.)
  evtx+N    an event log record BEYOND the first (``evtx.record_<N>_<field>``, ``evtx.second_record_<field>``,
            ...). readers_day14 reads the FIRST record only; the lane is cumulative and just introduced EVTX,
            so a follow-up that asks the second/Nth record's fields is in range. The Nth record of the first
            chunk is read with python-evtx, its event id / channel / provider / computer / time / level / task
            / user id / record id extracted exactly as the first-record reader does. (Day 25 look-ahead #3:
            "EVTX beyond the first record".)

Deliberately NOT built, to avoid duplication and stay never-wrong (each is already read, or belongs to the
network/sqlite toolkit, or cannot be keyed without a stated path): pcap/pcapng header and packet-timestamp
facts (done in properties_strict), evtx record count and first-record fields (done, readers_day14 +
readers_evtx_fields), the $MFT record (done, readers_formats), SQLite table/index/view counts and names
(done, properties_strict), packet PAYLOAD extraction and per-named-table SQLite row counts (the network and
sqlite_artifacts toolkits), a hive value "by its path", a jump list / shellbag and an EWF "header2" metadata
string (no property name states the path, the hive/key, or which compressed metadata field; the reader
contract is fn(name, data) and never sees the question text, so a by-path fact cannot be keyed never-wrong).

The extractor contract is the wrapper's: fn(name, data) returns the value read from the bytes, None when the
file is not of the type or lacks the structure, or raises M.Unknown when it is of the type and the bytes do
not settle the fact (damaged, cut or ambiguous). Everything is bounded by WALK caps and never calls out.
"""
import struct

M = None          # properties_strict, set by register()
SECTIONS = []
NEW_FNS = []      # the extractors this pack adds (for TIE_FREE and the test's confirmed check)


def section(fn):
    SECTIONS.append(fn)
    return fn


def U(msg):
    raise M.Unknown(msg)


def free(ns: str, names) -> list:
    """The names of a namespace nothing reads yet: not registered, and matched by no family."""
    return [x for x in names if M.canon(f"{ns}.{x}") not in M.REG and M.lookup(f"{ns}.{x}") is None]


def reg(ns: str, names, fmt, fn, bits=None, unit=None):
    """Register one new extractor under every <ns>.<name> that nothing reads yet."""
    names = free(ns, names)
    if names:
        M.prop(*[f"{ns}.{x}" for x in names], fmt=fmt, bits=bits, unit=unit)(fn)
        NEW_FNS.append(fn)


def register(module):
    global M
    M = module
    before = dict(M.REG)
    families = len(M.FAMILIES)
    NEW_FNS.clear()
    for s in SECTIONS:
        s()
    # every extractor this pack added is a forecast, so guess()/the nearest-reader tie-break treats it as free
    M.TIE_FREE.update(f for f in NEW_FNS)
    return len(M.REG) - len(before), len(M.FAMILIES) - families


# ============================================================ USN journal ($UsnJrnl:$J)
# A $J stream is a run of sparse zeros followed by USN_RECORD_V2/V3 structures, 8-byte aligned, with no
# file magic. Dispatch leans entirely on a strict read of the first record, so a file that is not a journal
# is returned None, never guessed at.

USN_WALK = 1 << 20              # records walked before the count is given up
USN_NAME_MAX = 512              # 255 UTF-16 code units, the NTFS name limit, in bytes
USN_REC_MAX = 1 << 16           # a record longer than this is not read
# version -> (header size = FileNameOffset, file-reference width in bytes)
USN_LAYOUT = {2: (60, 8), 3: (76, 16)}
# B-248: USN_RECORD_V4 (range tracking). A 64-byte fixed part (two FILE_ID_128 references, the USN, reason,
# source info, RemainingExtents, NumberOfExtents, ExtentSize) and then NumberOfExtents USN_RECORD_EXTENTs. It
# has NO timestamp, NO file name, NO security id and NO attributes: those fields of a V4 record are absent (the
# unsure `none`), never borrowed from a neighbour. The parse is solvers/toolkits/foridepth_usn.py's (reused, not
# forked); dispatch here is stricter than the toolkit's: V4.0's 16-byte extent, at least one extent, and the
# extent table exactly filling the record (rounded to the 8-byte grid), so an arbitrary file is not a journal.
USN_V4_HEADER = 64
USN_V4_EXTENT = 16
_USN_TOOLKIT = None


def _usn_toolkit():
    """solvers/toolkits/foridepth_usn.py, loaded by path once (the lane's own loader: a missing file raises
    PackMissing with its path, never a silent fallback)."""
    global _USN_TOOLKIT
    if _USN_TOOLKIT is None:
        from pathlib import Path
        from ctf.packs import load_module
        path = Path(__file__).resolve().parent.parent / "toolkits" / "foridepth_usn.py"
        _USN_TOOLKIT = load_module("metadata_foridepth_usn", path, pack="USN V4 parser (solvers/toolkits)", cache=False)
    return _USN_TOOLKIT


def _usn_v4(d: bytes, at: int):
    """A V4 record at `at` as the same dict a V2/V3 record gives (the absent fields None), or None when the
    bytes are not a strict V4.0 record."""
    if at + USN_V4_HEADER > len(d):
        return None
    rec_len, _, minor, = struct.unpack_from("<IHH", d, at)
    count, ext_size = struct.unpack_from("<HH", d, at + 60)
    if (minor != 0 or ext_size != USN_V4_EXTENT or count == 0 or rec_len > USN_REC_MAX or rec_len % 8
            or rec_len != (USN_V4_HEADER + count * ext_size + 7) & ~7 or at + rec_len > len(d)):
        return None
    tk = _usn_toolkit()
    try:
        r = tk.parse_record(d[at:at + rec_len], 0)
    except tk.ForidepthUsnError:
        return None
    return {"record_length": rec_len, "major": 4, "minor": 0, "frn": r["file_reference"]["value"],
            "parent": r["parent_reference"]["value"], "usn": r["usn"], "timestamp": None, "reason": r["reason"],
            "source_info": r["source_info"], "security_id": None, "file_attributes": None, "name_length": None,
            "name": None, "remaining_extents": r["remaining_extents"], "extent_count": count,
            "extent_offsets": [e["offset"] for e in r["extents"]], "extent_lengths": [e["length"] for e in r["extents"]]}


def _usn_rec(d: bytes, at: int):
    """Parse the USN record at `at` into a dict, or None when it is not a plausible V2/V3/V4 record. The checks
    (version, the exact header size, an even in-range name that decodes; for V4 the extent table) are strict
    enough that an arbitrary file is not read as a journal."""
    if at + 60 > len(d):
        return None
    rec_len, major, minor = struct.unpack_from("<IHH", d, at)
    if major == 4:
        return _usn_v4(d, at)
    if minor != 0 or major not in USN_LAYOUT:
        return None
    hdr, refw = USN_LAYOUT[major]
    if rec_len % 8 or rec_len < hdr or rec_len > USN_REC_MAX or at + rec_len > len(d):
        return None
    name_len, name_off = struct.unpack_from("<HH", d, at + hdr - 4)
    if name_off != hdr or name_len == 0 or name_len % 2 or name_len > USN_NAME_MAX:
        return None
    if name_off + name_len > rec_len:
        return None
    try:
        name = d[at + name_off:at + name_off + name_len].decode("utf-16-le")
    except UnicodeDecodeError:
        return None
    if "\x00" in name:
        return None
    frn = int.from_bytes(d[at + 8:at + 8 + refw], "little")
    parent = int.from_bytes(d[at + 8 + refw:at + 8 + 2 * refw], "little")
    p = at + 8 + 2 * refw
    usn, ts, reason, source, sec_id, attrs = struct.unpack_from("<QqIIII", d, p)
    return {"record_length": rec_len, "major": major, "minor": minor, "frn": frn, "parent": parent,
            "usn": usn, "timestamp": ts, "reason": reason, "source_info": source, "security_id": sec_id,
            "file_attributes": attrs, "name_length": name_len, "name": name, "remaining_extents": None,
            "extent_count": None, "extent_offsets": None, "extent_lengths": None}


def _usn_start(d: bytes):
    """The offset of the first record: the leading sparse zeros skipped, rounded DOWN to the 8-byte grid. A record
    starts on the grid, and its RecordLength's low bytes may be zero (a 256-byte record begins 00 01 00 00), so the
    first non-zero byte can lie a few bytes into the record: rounding up would skip its start. None when the stream
    is all zeros (so, not a journal we can read)."""
    start = len(d) - len(d.lstrip(b"\x00"))
    if start >= len(d):
        return None
    return start & ~7


def _usn_first(d: bytes):
    """The first USN record's fields, or None when the file is not a readable USN journal."""
    if len(d) < 60:
        return None
    start = _usn_start(d)
    if start is None:
        return None
    return _usn_rec(d, start)


def _usn_first_field(key):
    def fn(n, d):
        rec = _usn_first(d)
        if rec is None:
            return None
        v = rec[key]
        if v is None:
            return None   # a V4 record has no timestamp, name, security id or attributes: absent, not guessed
        return M._filetime(v) if key == "timestamp" else v
    return fn


def _usn_records(d: bytes):
    """Every record of the journal in stream order (V2, V3 and V4 mixed, as a range-tracking volume writes them),
    each walked by its own RecordLength; None when the first record does not read. A later record that does not
    read is Unknown: nothing after it is counted or listed."""
    if _usn_first(d) is None:
        return None
    at, out = _usn_start(d), []
    while at + 4 <= len(d):
        if len(out) > USN_WALK:
            U("more USN records than are walked")
        rec_len = struct.unpack_from("<I", d, at)[0]
        if rec_len == 0:
            break   # the rest of the stream is sparse padding
        rec = _usn_rec(d, at)
        if rec is None:
            U("a USN record after the first is not a readable V2/V3/V4 record; the count is not established")
        out.append(rec)
        at += rec_len
    return out


def _usn_count(n, d):
    recs = _usn_records(d)
    return None if recs is None else len(recs)


def _usn_versions(n, d):
    recs = _usn_records(d)
    return None if recs is None else [r["major"] for r in recs]


def _usn_version_count(major):
    def fn(n, d):
        recs = _usn_records(d)
        return None if recs is None else sum(1 for r in recs if r["major"] == major)
    return fn


@section
def _reg_usn():
    ns = "usn"
    if ns not in M.NAMESPACES:
        M.NAMESPACES.add(ns)
        M.PACK_NAMESPACES.add(ns)
        M.CONTENT_TOKENS.update({ns, "usnjrnl", "usnjournal"})
        M.RELATED.setdefault(ns, (ns,))
        M.MORE_TYPES.append((ns, _is_usn))
    M.NS_ALIAS.update({a: ns for a in ("usnjrnl", "usn_journal", "usn_j", "usnj", "usn_jrnl")
                       if a not in M.NS_ALIAS and a not in M.NAMESPACES})
    reg(ns, ["record_count", "total_records", "records", "entry_count", "number_of_records", "journal_record_count"],
        "integer", _usn_count)
    reg(ns, ["first_record_length", "record_length", "first_record_record_length", "first_entry_record_length"],
        "integer", _usn_first_field("record_length"))
    reg(ns, ["first_record_major_version", "major_version", "version_major", "first_record_version_major"],
        "integer", _usn_first_field("major"))
    reg(ns, ["first_record_minor_version", "minor_version", "version_minor", "first_record_version_minor"],
        "integer", _usn_first_field("minor"))
    reg(ns, ["first_record_usn", "first_usn", "usn", "first_record_update_sequence_number"],
        "integer", _usn_first_field("usn"))
    reg(ns, ["first_record_file_reference_number", "first_record_frn", "file_reference_number", "first_record_mft_reference"],
        "integer", _usn_first_field("frn"))
    reg(ns, ["first_record_parent_file_reference_number", "first_record_parent_frn", "parent_file_reference_number",
             "first_record_parent_reference"], "integer", _usn_first_field("parent"))
    reg(ns, ["first_record_timestamp", "first_record_time", "timestamp", "first_record_date_time", "first_timestamp"],
        "filetime", _usn_first_field("timestamp"))
    reg(ns, ["first_record_reason", "reason", "first_record_reason_flags", "reason_flags"],
        "number", _usn_first_field("reason"))
    reg(ns, ["first_record_source_info", "source_info", "first_record_source_information"],
        "number", _usn_first_field("source_info"))
    reg(ns, ["first_record_security_id", "security_id", "first_record_securityid"],
        "integer", _usn_first_field("security_id"))
    reg(ns, ["first_record_file_attributes", "file_attributes", "first_record_attributes"],
        "number", _usn_first_field("file_attributes"))
    reg(ns, ["first_record_file_name", "first_record_filename", "file_name", "filename", "first_record_name"],
        "text", _usn_first_field("name"))
    reg(ns, ["first_record_file_name_length", "first_record_filename_length", "file_name_length", "filename_length"],
        "integer", _usn_first_field("name_length"))
    # B-248: V4 (range-tracking) records and journals that mix V2/V3 with V4.
    reg(ns, ["record_major_versions", "record_versions", "major_versions", "record_version_list"], "intlist", _usn_versions)
    reg(ns, ["v4_record_count", "range_tracking_record_count", "version_4_record_count"], "integer", _usn_version_count(4))
    reg(ns, ["v3_record_count", "version_3_record_count"], "integer", _usn_version_count(3))
    reg(ns, ["v2_record_count", "version_2_record_count"], "integer", _usn_version_count(2))
    reg(ns, ["first_record_extent_count", "first_record_number_of_extents", "extent_count", "number_of_extents"],
        "integer", _usn_first_field("extent_count"))
    reg(ns, ["first_record_remaining_extents", "remaining_extents"], "integer", _usn_first_field("remaining_extents"))
    reg(ns, ["first_record_extent_offsets", "extent_offsets"], "intlist", _usn_first_field("extent_offsets"))
    reg(ns, ["first_record_extent_lengths", "extent_lengths"], "intlist", _usn_first_field("extent_lengths"))


def _is_usn(d):
    """The MORE_TYPES test for the facts page: True only for a file whose first record reads as USN. It must
    never raise; _usn_first does not, but the guard keeps that promise if the parser ever changes."""
    try:
        return _usn_first(d) is not None
    except Exception:
        return False


# ============================================================ regf: the root key's value list
# The base block and the root key's SUBKEY list are read elsewhere (readers_day14, properties_strict). The
# root key's VALUE list, its class name and its own last-written time were not.

REGF_VALUES = 1 << 16   # value cells walked for the root key


def _regf_root_cell(d: bytes):
    """The absolute offset of the root key's nk cell body (past the 4-byte cell size), or None when the file
    is not a hive. Validated exactly as readers_day14_impl.regf_root does."""
    if d[:4] != b"regf" or len(d) < 0x1000 + 0x60:
        return None
    root = struct.unpack_from("<I", d, 36)[0]
    at = 0x1000 + root + 4
    if at + 0x50 > len(d) or d[at:at + 2] != b"nk":
        U("a root cell that is not a key node")
    return at


def _regf_root_value_offsets(d: bytes):
    """[absolute offset of each vk cell body] for the root key's values, [] when it has none, or None when the
    file is not a hive."""
    at = _regf_root_cell(d)
    if at is None:
        return None
    nvals = struct.unpack_from("<I", d, at + 0x24)[0]
    if nvals in (0, 0xFFFFFFFF):
        return []
    if nvals > REGF_VALUES:
        U("more values than are walked")
    list_off = struct.unpack_from("<I", d, at + 0x28)[0]
    list_at = 0x1000 + list_off + 4
    if list_at + 4 * nvals > len(d):
        U("the root key's value list is cut")
    out = []
    for i in range(nvals):
        voff = struct.unpack_from("<I", d, list_at + 4 * i)[0]
        vk = 0x1000 + voff + 4
        if vk + 0x14 > len(d) or d[vk:vk + 2] != b"vk":
            U("a value cell that is not a value key")
        out.append(vk)
    return out


def _regf_value_name(d: bytes, vk: int):
    nlen, = struct.unpack_from("<H", d, vk + 2)
    flags, = struct.unpack_from("<H", d, vk + 0x10)
    if nlen == 0:
        return ""   # the default (unnamed) value
    raw = d[vk + 0x14:vk + 0x14 + nlen]
    if len(raw) != nlen:
        U("a value name that is cut")
    try:
        return raw.decode("latin-1" if flags & 1 else "utf-16-le")
    except UnicodeDecodeError:
        U("a value name that does not decode")


def _regf_root_value_count(n, d):
    at = _regf_root_cell(d)
    if at is None:
        return None
    nvals = struct.unpack_from("<I", d, at + 0x24)[0]
    return 0 if nvals == 0xFFFFFFFF else nvals


def _regf_root_value_names(n, d):
    offs = _regf_root_value_offsets(d)
    if offs is None or not offs:
        return None
    names = [_regf_value_name(d, vk) for vk in offs]
    if any(x == "" for x in names):
        U("the root key has an unnamed (default) value, which a plain name list does not represent")
    return names


def _regf_root_last_written(n, d):
    at = _regf_root_cell(d)
    if at is None:
        return None
    return M._filetime(struct.unpack_from("<Q", d, at + 4)[0])


def _regf_root_class_name(n, d):
    at = _regf_root_cell(d)
    if at is None:
        return None
    class_off = struct.unpack_from("<I", d, at + 0x30)[0]
    class_len = struct.unpack_from("<H", d, at + 0x4A)[0]
    if class_off == 0xFFFFFFFF or class_len == 0:
        return None
    cl = 0x1000 + class_off + 4
    raw = d[cl:cl + class_len]
    if len(raw) != class_len:
        U("a root key class name that is cut")
    try:
        return raw.decode("utf-16-le") or None
    except UnicodeDecodeError:
        U("a root key class name that does not decode")


@section
def _reg_regf():
    reg("regf", ["root_key_value_count", "root_value_count", "root_key_number_of_values", "root_number_of_values",
                 "root_values_count"], "integer", _regf_root_value_count)
    reg("regf", ["root_key_value_names", "root_value_names", "root_values", "root_key_values"],
        "list", _regf_root_value_names)
    reg("regf", ["root_key_last_written", "root_key_last_written_time", "root_last_written", "root_cell_last_written",
                 "root_key_timestamp", "root_node_last_written"], "filetime", _regf_root_last_written)
    reg("regf", ["root_key_class_name", "root_class_name", "root_key_class"], "text", _regf_root_class_name)


# ============================================================ prefetch: the volume information block
# The volume-info offset/count/size are at 0x6C/0x70/0x74 for every uncompressed SCCA version 17 to 30; the
# first volume entry's device path, creation time and serial share one leading layout across those versions.

PREFETCH_VERSIONS = (17, 23, 26, 30)


def _pf_volume(d: bytes):
    """{count, dev_path, serial, created} of a prefetch file's first volume, or None when the file is not an
    uncompressed SCCA prefetch. A compressed one (MAM) or a version whose layout is not read raises."""
    if d[:3] == b"MAM" and len(d) >= 8:
        U("the prefetch file is compressed (MAM, Xpress Huffman), which is not read")
    if len(d) < 0x78 or d[4:8] != b"SCCA":
        return None
    version = struct.unpack_from("<I", d, 0)[0]
    if version not in PREFETCH_VERSIONS:
        U(f"prefetch version {version} is not one whose volume layout is read")
    vol_off, vol_count, vol_size = struct.unpack_from("<III", d, 0x6C)
    out = {"count": vol_count, "dev_path": None, "serial": None, "created": None}
    if vol_count == 0:
        return out
    if vol_off + 0x14 > len(d):
        U("the volume information block lies past the end of the file")
    dev_off, dev_len = struct.unpack_from("<II", d, vol_off)
    created, = struct.unpack_from("<Q", d, vol_off + 8)
    serial, = struct.unpack_from("<I", d, vol_off + 0x10)
    out["serial"], out["created"] = serial, created
    if dev_len:
        if dev_len > 1 << 15:
            U("a volume device path longer than is read")
        p = vol_off + dev_off
        raw = d[p:p + dev_len * 2]
        if len(raw) != dev_len * 2:
            U("a volume device path that is cut")
        try:
            out["dev_path"] = raw.decode("utf-16-le").split("\x00")[0] or None
        except UnicodeDecodeError:
            U("a volume device path that does not decode")
    return out


def _pf_field(key, filetime=False):
    def fn(n, d):
        v = _pf_volume(d)
        if v is None:
            return None
        val = v[key]
        if val is None:
            return None
        return M._filetime(val) if filetime else val
    return fn


@section
def _reg_prefetch():
    reg("prefetch", ["volume_count", "volume_information_count", "number_of_volumes", "volumes_count",
                     "volume_entry_count"], "integer", _pf_field("count"))
    reg("prefetch", ["volume_device_path", "volume_name", "volume_device_name", "first_volume_device_path",
                     "volume_path", "first_volume_name"], "text", _pf_field("dev_path"))
    reg("prefetch", ["volume_serial_number", "volume_serial", "first_volume_serial_number", "volume_serial_number_value",
                     "first_volume_serial"], "number", _pf_field("serial"))
    reg("prefetch", ["volume_creation_time", "volume_created", "first_volume_creation_time", "volume_create_time",
                     "first_volume_created"], "filetime", _pf_field("created", filetime=True))


# ============================================================ EWF / EnCase image (.E01 / .Ex01)
# The classic Expert Witness (EVF/LVF) segment file: an 8-byte signature, a 1-byte fields_start that is
# always 0x01, a 16-bit little-endian segment number, a 16-bit fields_end (0x0000), then the first section
# descriptor (a 16-byte null-padded type string). Dispatch leans on the exact signature AND fields_start, so
# an arbitrary file is never read as an image. EWF2/Ex01 ("EVF2") carries a different header and is refused.

_EVF_SIGS = {
    b"EVF\x09\x0d\x0a\xff\x00": "ewf",   # EnCase physical image (.E01)
    b"LVF\x09\x0d\x0a\xff\x00": "lef",   # EnCase logical evidence (.L01)
}


def _evf(d: bytes):
    """{segment, format, signature, first_section} of a classic EWF/LVF file header, or None when the file is
    not one. EWF2/Ex01 and a header that is not plausible raise (so the answer is None, never a guess)."""
    if len(d) < 29:
        return None
    sig = d[:8]
    fmt = _EVF_SIGS.get(sig)
    if fmt is None:
        if d[:4] in (b"EVF2", b"LVF2"):
            U("an EWF2/Ex01 image, whose header layout is not read")
        return None
    if d[8] != 0x01:
        U("an EWF signature without the expected fields_start byte")
    segment = struct.unpack_from("<H", d, 9)[0]
    first = d[13:29].split(b"\x00", 1)[0]
    try:
        text = first.decode("ascii")
    except UnicodeDecodeError:
        U("a first section type that does not decode")
    section = text or None
    if section is not None and not section.replace("_", "").isalnum():
        U("a first section type that is not a plain identifier")
    return {"segment": segment, "format": fmt, "signature": sig.hex(), "first_section": section}


def _evf_field(key):
    def fn(n, d):
        r = _evf(d)
        if r is None:
            return None
        return r[key]
    return fn


def _is_evf(d):
    try:
        return _evf(d) is not None
    except Exception:
        return False


@section
def _reg_ewf():
    ns = "ewf"
    if ns not in M.NAMESPACES:
        M.NAMESPACES.add(ns)
        M.PACK_NAMESPACES.add(ns)
        M.CONTENT_TOKENS.update({ns, "e01", "ex01", "evf", "encase", "expert_witness", "l01"})
        M.RELATED.setdefault(ns, (ns,))
        M.MORE_TYPES.append((ns, _is_evf))
    M.NS_ALIAS.update({a: ns for a in ("e01", "ex01", "evf", "encase", "expert_witness", "ewf_image", "l01", "lef")
                       if a not in M.NS_ALIAS and a not in M.NAMESPACES})
    reg(ns, ["segment_number", "segment", "file_segment_number", "segment_no", "evf_segment_number"],
        "integer", _evf_field("segment"))
    reg(ns, ["format", "file_format", "image_format", "evf_format"], "label", _evf_field("format"))
    # The EWF/EVF signature bytes, as hex. Named WITHOUT a trailing `_hex`/width/form word (row 178's
    # guard in test_metadata_readers forbids one, since typed() would strip it and could shadow another
    # reader); the fmt is already "hex", so the value is hex either way. `signature` is read by
    # readers_dfir_more as the format family (free() leaves that reading in place), so the hex bytes are
    # reachable under `file_signature`/`magic`, and a question spelled with a trailing `_hex`
    # (`ewf.file_signature_hex`, `ewf.magic_hex`) still resolves here through guess()'s typed-name routing.
    reg(ns, ["signature", "file_signature", "magic"], "hex", _evf_field("signature"))
    reg(ns, ["first_section_type", "first_section", "first_section_name", "initial_section_type"],
        "text", _evf_field("first_section"))


# ============================================================ EVTX: a record BEYOND the first
# readers_day14 reads the first record only. These read the Nth record of the first chunk with python-evtx
# and pull the same fields, so a Day-25 follow-up asking the second/Nth record's event id, channel, provider,
# computer, time, level, task, user id or record id is answered (unsure), None when that record is absent,
# and Unknown (-> None) when the chunk is cut. All bounded by the 64 KiB first chunk.

EVTX_REC_WALK = 4096   # records of the first chunk walked before the Nth is given up

_EVTX_RX = {
    "event_id": r"<EventID[^>]*>(\d+)</EventID>",
    "computer": r"<Computer>([^<]*)</Computer>",
    "channel": r"<Channel>([^<]*)</Channel>",
    "provider": r"<Provider Name=\"([^\"]*)\"",
    "time_created": r"<TimeCreated SystemTime=\"([^\"]*)\"",
    "level": r"<Level>(\d+)</Level>",
    "task": r"<Task>(\d+)</Task>",
    "user_id": r"<Security UserID=\"([^\"]*)\"",
}
# a name without case or separators -> the canonical field key (record_id is the record number)
_EVTX_SAME = {
    "eventid": "event_id", "computername": "computer", "providername": "provider",
    "timecreated": "time_created", "systemtime": "time_created", "eventrecordid": "record_id",
    "recordnumber": "record_id", "recordid": "record_id", "userid": "user_id",
    "securityuserid": "user_id", "channelname": "channel", "computer": "computer", "channel": "channel",
    "provider": "provider", "level": "level", "task": "task",
}
_EVTX_NUMWORD = {"second": 2, "third": 3, "fourth": 4, "fifth": 5, "sixth": 6, "seventh": 7,
                 "eighth": 8, "ninth": 9, "tenth": 10}


def _evtx_nth(d: bytes, n: int):
    """(xml, record_number str) of the n-th (1-based) record of the first chunk, None when the file is not an
    event log or the record is absent, or raises Unknown when the chunk/record is cut."""
    if d[:8] != b"ElfFile\x00":
        return None
    if len(d) < 0x1000 + 0x200 or d[0x1000:0x1008] != b"ElfChnk\x00":
        U("an event log without a first chunk")
    try:
        import Evtx.Evtx as E
    except ImportError:
        U("the python-evtx library is not installed")
    chunk = E.ChunkHeader(d[:0x1000 + 0x10000], 0x1000)
    i = 0
    for rec in chunk.records():
        i += 1
        if i > EVTX_REC_WALK:
            U("more records than are walked")
        if rec.magic() != 0x2A2A or rec.length() > 0x10000:
            U("a record that is not whole")
        if i == n:
            return rec.xml(), str(rec.record_num())
    return None   # fewer than n records in the first chunk: the record is absent


def _evtx_record_field(name, data, n, field):
    """Read one field of the Nth record. n is an int (record_<N>) or a number word (second_record_...)."""
    import re
    try:
        idx = n if isinstance(n, int) else _EVTX_NUMWORD.get(n)
        if idx is None or idx < 1:
            return None
        got = _evtx_nth(data, idx)
    except (M.Unknown, M.Ambiguous):
        raise
    except Exception as e:
        raise M.Unknown(f"the bytes do not read as an event-log record ({type(e).__name__})")
    if got is None:
        return None
    xml, rid = got
    key = _EVTX_SAME.get(re.sub(r"[^a-z0-9]", "", field.lower()))
    if key is None:
        U("a record field this reader does not know by that name")
    if key == "record_id":
        return rid
    m = re.search(_EVTX_RX[key], xml)
    return m.group(1) if m else None


@section
def _reg_evtx_record_n():
    # evtx.record_<N>_<field>: the Nth record (N a decimal >= 1)
    def fn_num(name, data, n, field):
        return _evtx_record_field(name, data, int(n), field)
    M.family(r"evtx_record_(\d+)_([a-z_]+)", "text")(fn_num)
    NEW_FNS.append(fn_num)
    # evtx.<word>_record_<field>: second_record_, third_record_, ... tenth_record_
    words = "|".join(_EVTX_NUMWORD)

    def fn_word(name, data, word, field):
        return _evtx_record_field(name, data, word, field)
    M.family(rf"evtx_({words})_record_([a-z_]+)", "text")(fn_word)
    NEW_FNS.append(fn_word)
