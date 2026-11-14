#!/usr/bin/env python3
"""Metadata Forensics wave15 coverage pack (docs/retro/ctf-solver-gap-analysis.md, the forensics / DFIR /
binary-packaging / container / file-type gaps): magic-dispatched readers for four classic acquisition and
DFIR container formats the lane had NO reader and NO magic for.

properties_strict.py loads this file by name in MORE_FILES (before readers_forensic.py, so that file stays
last) and calls register(M) with itself. Nothing here answers plain: every name is registered unconfirmed
(free()/reg() below only register a <ns>.<name> that NOTHING already reads), so the strict wrapper offers
each through labels.pick until the judge accepts a format for its key. Because the pack registers only free
names and adds nothing to conventions.json, it can never change a reading an earlier reader or a judged seed
already gives, and every saved attempt replays byte for byte as before.

What it reads, dispatched STRICTLY by the leading magic / fixed-header structure (never by extension), so an
arbitrary file is returned None, never guessed at:

  wim    Windows Imaging Format (`MSWIM\\0\\0\\0`): the _WIMHEADER_V1_PACKED fixed header — header size,
         version, flags, chunk size, the image GUID, part/total parts, image count, boot index.
  vhdx   Hyper-V disk image v2 (`vhdxfile`): the File Type Identifier's creator string and, from whichever
         of the two 'head' header regions has the greater sequence number, the sequence number, the format
         version, the file/data/log write GUIDs, and the log version/length/offset.
  ewf    EnCase / Expert Witness evidence file (`EVF\\t\\r\\n\\xff\\0`, logical `LVF...`, and the EWF2
         `EVF2`/`LEF2` families): the signature family, the segment number, and the section linked-list walk
         (first section type, section count, section types). EWF2 layout differs, so only its family is read.
  evt    Classic (pre-Vista) Windows Event Log (`LfLe` at offset 4, header size 0x30): the ELF_LOGFILE_HEADER
         — header size, major/minor version, start/end offsets, current/oldest record numbers, max size,
         flags, retention.

Deliberately NOT built here, to avoid duplication and stay never-wrong (each is already read, lives in
another toolkit, or cannot be keyed/fixtured cleanly without a stated path):
  - VHD (`conectix` footer), ISO9660, MBR/GPT, FAT/NTFS/ext, QCOW2 — all read already (readers_more.py);
  - $MFT, pcap/pcapng, evtx (modern), prefetch, regf base block, SQLite, minidump — read already
    (properties_strict / readers_day14 / readers_structures / readers_forensic);
  - jump lists (`.automaticDestinations-ms`): the DestList stream lives inside a CFB mini-stream; reading it
    needs full OLE stream reconstruction and the entry layout is version-fragile, so it is left for a reader
    with a CFB fixture rather than risk a never-wrong misread;
  - the full WIM resource table / XML, the EWF per-section bodies, the EVT record bodies — those need a
    stated path or a sandbox and carry no clean lane property name.

The extractor contract is the wrapper's: fn(name, data) returns the value read from the bytes, None when the
file is not of the type or lacks the structure, or raises M.Unknown when it is of the type and the bytes do
not settle the fact (damaged, cut or ambiguous). Everything is bounded and never calls out.
"""
import struct
import uuid

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


def reg(ns: str, names, fmt, fn):
    """Register one new extractor under every <ns>.<name> that nothing reads yet."""
    names = free(ns, list(names))
    if names:
        M.prop(*[f"{ns}.{x}" for x in names], fmt=fmt)(fn)
        NEW_FNS.append(fn)


def namespace(ns: str, tokens=(), test=None, alias=()):
    """Add a brand-new namespace exactly as readers_forensic.py adds `usn`: a content token so a <ns>.* key
    is never read as a cross-file identity mismatch, a RELATED self-entry, the facts-page type test, and the
    spelling aliases (only those nothing else claims)."""
    if ns not in M.NAMESPACES:
        M.NAMESPACES.add(ns)
        M.PACK_NAMESPACES.add(ns)
        M.CONTENT_TOKENS.update({ns, *tokens})
        M.RELATED.setdefault(ns, (ns,))
        if test is not None:
            M.MORE_TYPES.append((ns, test))
    M.NS_ALIAS.update({a: ns for a in alias if a not in M.NS_ALIAS and a not in M.NAMESPACES})


def _field(parse, key):
    def fn(n, d):
        v = parse(d)
        if v is None:
            return None
        return v.get(key)
    return fn


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


def _guid(raw: bytes):
    """A 16-byte Windows/mixed-endian GUID as its 32 lowercase hex digits in 8-4-4-4-12 order (the form the
    uuid format class takes); None when it is not 16 bytes."""
    return uuid.UUID(bytes_le=bytes(raw)).hex if len(raw) == 16 else None


# ============================================================ WIM: Windows Imaging Format header
# `MSWIM\0\0\0` then the fixed _WIMHEADER_V1_PACKED (208 bytes). Every field read here lives at a constant
# offset, so a file of this magic is read with no walk.
WIM_MAGIC = b"MSWIM\x00\x00\x00"
WIM_HDR = 0xD0          # the packed header is 208 bytes


def _wim(d: bytes):
    if d[:8] != WIM_MAGIC:
        return None
    if len(d) < WIM_HDR:
        U("a WIM header that is cut")
    cb_size, version, flags, chunk = struct.unpack_from("<IIII", d, 8)
    part, total = struct.unpack_from("<HH", d, 0x28)
    image_count, = struct.unpack_from("<I", d, 0x2C)
    boot_index, = struct.unpack_from("<I", d, 0x78)
    return {"header_size": cb_size, "version": version, "flags": flags, "chunk_size": chunk,
            "guid": _guid(d[0x18:0x28]), "part_number": part, "total_parts": total,
            "image_count": image_count, "boot_index": boot_index}


def _is_wim(d):
    return d[:8] == WIM_MAGIC


@section
def _reg_wim():
    namespace("wim", tokens=("mswim", "windows_image"), test=_is_wim,
              alias=("windows_imaging_format", "swm"))
    reg("wim", ("image_count", "number_of_images", "images", "image_count_value"), "integer",
        _field(_wim, "image_count"))
    reg("wim", ("header_size", "header_size_bytes", "cb_size"), "integer", _field(_wim, "header_size"))
    reg("wim", ("version", "version_number", "header_version"), "number", _field(_wim, "version"))
    reg("wim", ("flags", "header_flags", "wim_flags"), "number", _field(_wim, "flags"))
    reg("wim", ("chunk_size", "compression_size", "chunk_size_bytes", "compressed_chunk_size"), "integer",
        _field(_wim, "chunk_size"))
    reg("wim", ("guid", "wim_guid", "image_guid"), "uuid", _field(_wim, "guid"))
    reg("wim", ("boot_index", "boot_image_index", "bootable_index"), "integer", _field(_wim, "boot_index"))
    # part_number (usPartNumber) and total_parts (usTotalParts) are intentionally NOT registered: the lane's
    # synonym reducer maps both "number" and "total" to "count", so "part_number" and "total_parts" collapse
    # to the same word-set within one namespace (the per-namespace word-uniqueness guard, row 48). They are
    # low-value spanned-WIM (.swm) fields; _wim() still reads them should a future name want them.


# ============================================================ VHDX: Hyper-V disk image v2
# `vhdxfile`, then a 512-byte UTF-16 creator; the two 'head' header regions sit at 64 KiB and 128 KiB and the
# current one is whichever has the greater sequence number.
VHDX_MAGIC = b"vhdxfile"
VHDX_HEADS = (0x10000, 0x20000)
VHDX_HEAD_LEN = 0x50    # read through log_offset (0x48 + 8)


def _vhdx(d: bytes):
    if d[:8] != VHDX_MAGIC:
        return None
    out = {"creator": None, "sequence_number": None, "format_version": None, "log_version": None,
           "log_length": None, "log_offset": None, "file_write_guid": None, "data_write_guid": None,
           "log_guid": None}
    if len(d) >= 8 + 512:
        try:
            out["creator"] = d[8:8 + 512].decode("utf-16-le").split("\x00")[0] or None
        except UnicodeDecodeError:
            U("a VHDX creator field that does not decode")
    best_seq = None
    for base in VHDX_HEADS:
        if base + VHDX_HEAD_LEN > len(d) or d[base:base + 4] != b"head":
            continue
        seq, = struct.unpack_from("<Q", d, base + 8)
        if best_seq is None or seq > best_seq:
            best_seq = seq
            log_ver, ver = struct.unpack_from("<HH", d, base + 0x40)
            log_len, = struct.unpack_from("<I", d, base + 0x44)
            log_off, = struct.unpack_from("<Q", d, base + 0x48)
            out.update(sequence_number=seq, format_version=ver, log_version=log_ver, log_length=log_len,
                       log_offset=log_off, file_write_guid=_guid(d[base + 0x10:base + 0x20]),
                       data_write_guid=_guid(d[base + 0x20:base + 0x30]),
                       log_guid=_guid(d[base + 0x30:base + 0x40]))
    return out


def _is_vhdx(d):
    return d[:8] == VHDX_MAGIC


@section
def _reg_vhdx():
    namespace("vhdx", tokens=("hyperv", "hyper_v"), test=_is_vhdx, alias=("vhdx_disk",))
    reg("vhdx", ("creator", "creator_application", "creator_string", "tool"), "text", _field(_vhdx, "creator"))
    reg("vhdx", ("sequence_number", "header_sequence_number", "current_sequence_number"), "integer",
        _field(_vhdx, "sequence_number"))
    reg("vhdx", ("format_version", "version", "header_version"), "number", _field(_vhdx, "format_version"))
    reg("vhdx", ("log_version", "header_log_version"), "number", _field(_vhdx, "log_version"))
    reg("vhdx", ("log_length", "log_length_bytes", "log_size_bytes"), "integer", _field(_vhdx, "log_length"))
    reg("vhdx", ("log_offset", "log_offset_bytes"), "integer", _field(_vhdx, "log_offset"))
    reg("vhdx", ("file_write_guid", "file_write_identifier"), "uuid", _field(_vhdx, "file_write_guid"))
    reg("vhdx", ("data_write_guid", "data_write_identifier"), "uuid", _field(_vhdx, "data_write_guid"))
    reg("vhdx", ("log_guid", "log_identifier"), "uuid", _field(_vhdx, "log_guid"))


# ============================================================ EWF / E01: EnCase evidence file
# The EWF1 families start `EVF \t \r \n \xff \0` (image) or `LVF ...` (logical); EWF2 is `EVF2`/`LEF2`. After
# the 8-byte magic an EWF1 segment file has a 1-byte fields-start (0x01), a 2-byte segment number, 2 zero
# bytes, then 76-byte section descriptors chained by their `next` offset to a terminal `done`/`next` section.
EWF1 = {b"EVF\x09\x0d\x0a\xff\x00": "EVF", b"LVF\x09\x0d\x0a\xff\x00": "LVF"}
EWF2 = {b"EVF2\x0d\x0a\x81\x00": "EVF2", b"LEF2\x0d\x0a\x81\x00": "LEF2"}
# The signature family -> the EWF format name: an EVF segment is a physical EWF image, an LVF/LEF segment the
# logical evidence format (LEF). The judge has accepted neither spelling for ewf.format, so the reader stays
# unsure; it offers the literal signature family (EVF/LVF/...) first and the format name (ewf/lef/...) as a
# second spelling, so both are reachable and neither is ever answered plain.
EWF_FORMAT_NAME = {"EVF": "ewf", "LVF": "lef", "EVF2": "ewf2", "LEF2": "lef2"}
EWF_SECTION = 76
EWF_SECTION_CAP = 1 << 12


def _ewf(d: bytes):
    """{family, v2} for an EWF segment file, or None when the magic is neither EWF1 nor EWF2."""
    fam = EWF1.get(d[:8])
    if fam:
        return {"family": fam, "v2": False}
    fam2 = EWF2.get(d[:8])
    if fam2:
        return {"family": fam2, "v2": True}
    return None


def _ewf1(d: bytes):
    """The dict for an EWF1 file whose fields-start byte is 0x01, else raise (so a damaged EWF1 is Unknown,
    never guessed); None when the file is not EWF1 at all (EWF2 or not EWF)."""
    base = _ewf(d)
    if base is None or base["v2"]:
        return None
    if len(d) < 13 or d[8] != 1:
        U("an EWF1 segment file whose fields-start byte is not 0x01")
    return base


def _ewf_segment(n, d):
    if _ewf1(d) is None:
        return None
    return struct.unpack_from("<H", d, 9)[0]


def _ewf_sections(d: bytes):
    """[section type] along the descriptor linked list, or raise Unknown when the chain is inconsistent."""
    types, at = [], 13
    for _ in range(EWF_SECTION_CAP):
        if at + EWF_SECTION > len(d):
            U("an EWF section descriptor that runs past the end of the file")
        raw = d[at:at + 16].split(b"\x00", 1)[0]
        if not raw or any(c < 0x20 or c > 0x7E for c in raw):
            U("an EWF section type that is not printable text")
        t = raw.decode("ascii")
        nxt, _size = struct.unpack_from("<QQ", d, at + 16)
        types.append(t)
        if t in ("done", "next") or nxt == at:
            return types
        if nxt <= at or nxt + EWF_SECTION > len(d):
            U("an EWF section 'next' offset that does not move forward inside the file")
        at = nxt
    U("more EWF sections than are walked")


def _ewf_section_types(n, d):
    return None if _ewf1(d) is None else _ewf_sections(d)


def _ewf_first_section(n, d):
    """The type string of the first section descriptor, read directly from offset 13: the 16-byte
    null-padded type field is defined there in every EWF1 segment file, independent of where the
    section's `next` offset points, so a header whose chain is not walkable (a terminal `next` of 0)
    still yields its first section type. None when the file is not EWF1; Unknown (-> None) when the
    descriptor is cut or its type is not printable text."""
    if _ewf1(d) is None:
        return None
    if 13 + 16 > len(d):
        U("an EWF1 file too short to hold the first section descriptor")
    raw = d[13:29].split(b"\x00", 1)[0]
    if not raw or any(c < 0x20 or c > 0x7E for c in raw):
        U("an EWF first section type that is not printable text")
    return raw.decode("ascii")


def _ewf_section_count(n, d):
    if _ewf1(d) is None:
        return None
    return len(_ewf_sections(d))


def _ewf_family(n, d):
    base = _ewf(d)
    if base is None:
        return None
    fam = base["family"]
    opts = [("raw", fam)]
    name = EWF_FORMAT_NAME.get(fam)
    if name and name != fam:
        opts.append(("lower", name))
    return opts


def _is_ewf(d):
    return d[:8] in EWF1 or d[:8] in EWF2


@section
def _reg_ewf():
    namespace("ewf", tokens=("encase", "e01", "expert_witness", "ewf2"), test=_is_ewf,
              alias=("e01", "encase", "ex01", "lx01", "l01", "s01"))
    # NB: NOT the bare "signature" -- readers_forensic.py reads the raw EWF signature BYTES (as hex) and
    # its test asks ewf.signature_hex. Row 178 forbids a registered "_hex" name, so that spelling resolves
    # by stripping "_hex" to "ewf.signature"; that base must therefore be the hex-bytes reader, not this
    # format-family one. The family stays reachable here as format / format_family / family / signature_family.
    # Class "forms" (wave41 lvf fix): _ewf_family offers the signature family (EVF/LVF) first and the format
    # name (ewf/lef) second via EWF_FORMAT_NAME, so ewf.format stays unsure and is reachable both ways.
    reg("ewf", ("format", "format_family", "family", "signature_family"), "forms", _ewf_family)
    # NB: NOT "segment_file_number" -- readers_forensic.py registers "file_segment_number", and the
    # per-namespace word-uniqueness guard (row 48) reduces both to the word-set {file, segment, count}
    # ("number" -> "count" in WORD_SAME). "segment_file_index" stays distinct ({file, segment, index}).
    reg("ewf", ("segment_number", "segment", "segment_file_index"), "integer", _ewf_segment)
    reg("ewf", ("first_section_type", "first_section", "initial_section_type"), "text", _ewf_first_section)
    reg("ewf", ("section_count", "number_of_sections", "sections_count", "section_descriptor_count"),
        "integer", _ewf_section_count)
    reg("ewf", ("section_types", "sections", "section_type_list", "section_names"), "list", _ewf_section_types)


# ============================================================ EVT: classic Windows Event Log
# The ELF_LOGFILE_HEADER is 48 bytes: a size field (0x30), the signature `LfLe` at offset 4, and ten more
# 32-bit fields. Dispatch is on the signature AND the size field, so a file that merely contains `LfLe` is
# not read as a header.
EVT_SIG = b"LfLe"
EVT_HDR = 0x30


def _evt(d: bytes):
    if len(d) < EVT_HDR or d[4:8] != EVT_SIG:
        return None
    (hsize, _sig, major, minor, start, end, cur, old, maxsize, flags, ret, ehsize) = struct.unpack_from(
        "<I4sIIIIIIIIII", d, 0)
    if hsize != EVT_HDR:
        U("a classic event-log header whose size field is not 0x30")
    return {"header_size": hsize, "major_version": major, "minor_version": minor, "start_offset": start,
            "end_offset": end, "current_record_number": cur, "oldest_record_number": old,
            "max_size": maxsize, "flags": flags, "retention": ret, "end_header_size": ehsize}


def _is_evt(d):
    try:
        return _evt(d) is not None
    except Exception:
        return False


@section
def _reg_evt():
    namespace("evt", tokens=("eventlog", "evtlog"), test=_is_evt,
              alias=("classic_event_log", "windows_event_log_classic"))
    reg("evt", ("header_size", "header_size_bytes"), "integer", _field(_evt, "header_size"))
    reg("evt", ("major_version", "version_major"), "integer", _field(_evt, "major_version"))
    reg("evt", ("minor_version", "version_minor"), "integer", _field(_evt, "minor_version"))
    reg("evt", ("start_offset", "first_record_offset"), "integer", _field(_evt, "start_offset"))
    reg("evt", ("end_offset", "last_record_offset", "eof_offset"), "integer", _field(_evt, "end_offset"))
    reg("evt", ("current_record_number", "current_record", "newest_record_number"), "integer",
        _field(_evt, "current_record_number"))
    reg("evt", ("oldest_record_number", "oldest_record", "first_record_number"), "integer",
        _field(_evt, "oldest_record_number"))
    reg("evt", ("max_size", "max_size_bytes", "maximum_size_bytes"), "integer", _field(_evt, "max_size"))
    reg("evt", ("flags", "header_flags", "log_flags"), "number", _field(_evt, "flags"))
    reg("evt", ("retention", "retention_seconds"), "number", _field(_evt, "retention"))
    reg("evt", ("end_header_size", "end_header_size_bytes"), "integer", _field(_evt, "end_header_size"))
