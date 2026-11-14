#!/usr/bin/env python3
"""Metadata Forensics reader pack of the Day 13 look-ahead (backlog row 270): names the registry
did not hold for structures it already reads, and one new file type.

properties_strict.py loads this file by name after readers_dotnet.py and calls register(M) with
itself. Nothing here answers plain: every name is registered unconfirmed, so the strict wrapper
offers it through labels.pick until the judge has accepted a format for its key. A name an earlier
file reads keeps that reading (reg() and also() leave out a name that is registered or that a
family reads), with one exception that is said below (the ELF build id, whose three names keep
their class and get a reader that also walks PT_NOTE).

The contract of an extractor is the wrapper's: fn(name, data) returns the value read from the
bytes, None when the file is not of the type or does not hold the structure (the wrapper then
offers the unsure `none`), or raises M.Unknown when it does and the bytes do not settle the fact.

One fact, one extractor. Where an earlier file reads the fact under another spelling, the new
spelling is that reader under one more name (also()): the nearest-reader search of the wrapper
gives a name to no reader once two extractors have its words, so a second extractor of a fact an
earlier name reads would take answers away. New extractors are only the facts nothing read.

What is here:
  elf     the GNU build id from the PT_NOTE segments, for a file with no section header table
          (build_id, gnu_build_id, note_gnu_build_id and their _hex spellings). With a section
          table the section is read as before, and a PT_NOTE that states another id is Unknown;
          two notes with different ids are Unknown. The interpreter under pt_interp_path and
          three more spellings.
  pe      the CodeView (RSDS) record of the debug directory under the debug_* names
          (debug_codeview_guid, debug_age, debug_codeview_pdb_path, ...): readers_more.py's one
          reader, _pe_codeview. That GUID is the PDB's, never the module's Mvid: no name here has
          the word mvid or module, and readers_dotnet.py's Mvid names have no word of these.
          tls_callback_count (the null-terminated array AddressOfCallBacks points at; a file
          whose header names no TLS directory has 0) and the manifest's requestedExecutionLevel
          (manifest_requested_execution_level; the one RT_MANIFEST resource, read as text).
  zip     the last central-directory entry's crc32, sizes, method, time, name and version made
          by, and the first entry's under the spellings a question may give the structure
          (central_directory_first_*, first_member_*): the first entry's are the earlier readers
          under one more name. <which>_..._crc32_hex offers the 0x form first.
          encrypted_member_count.
  tar     the first header's fields under first_header_* and first_member_* (the earlier
          readers of header_*, ustar_* and first_entry_*).
  gzip    trailer_crc32_hex (and crc32_hex, trailer_crc32_u32_hex): 0x and eight digits first,
          then the bare digits in both cases. gzip.trailer_crc32 keeps its two bare forms.
  aiff    a new namespace (aif, aifc): the FORM type, the COMM chunk's channels, sample frames,
          sample size and sample rate, the chunk ids, the AIFF-C compression type.
  iso     the namespace iso9660 under its short name, so iso.volume_id is a registered name
          with a key of its own spelling, and the descriptor's standard identifier and version.

Left out: the Authenticode signer (a certificate chain is not read here), a zip entry by its
member name (no reader names an entry that way, and a member's name is not a registry word).
"""
import fractions
import re
import struct

M = None          # properties_strict, set by register()
RM = None         # readers_more.py as loaded by properties_strict: _elfx, _pex, _pe_rva, _pe_codeview, _pvd
PT = None         # readers_pe_tables.py: _resources
SECTIONS = []
OLD = set()       # the extractors the earlier files registered: a name that reuses one is no forecast of this file


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


def also(ns: str, target: str, names):
    """More names of the registered <ns>.<target>, each under its own key: the same extractor,
    class, width and unit, never confirmed. Nothing where the target is not registered."""
    p = M.REG.get(M.canon(f"{ns}.{target}"))
    if p is None:
        return
    for x in free(ns, names):
        M.REG[M.canon(f"{ns}.{x}")] = M.Prop(f"{ns}.{x}", p.fn, p.fmt, False, p.bits, p.unit)


def register(module):
    global M, RM, PT
    M = module
    more = getattr(M, "MORE_MODULES", {})
    RM, PT = more.get("readers_more.py"), more.get("readers_pe_tables.py")
    if RM is None:
        raise RuntimeError("readers_more.py is not loaded, and its ELF and PE parsers are this file's")
    before = dict(M.REG)
    families = len(M.FAMILIES)
    OLD.clear()
    OLD.update(p.fn for p in before.values())
    for s in SECTIONS:
        s()
    M.TIE_FREE.update(M.REG[k].fn for k in M.REG if M.REG[k].fn not in OLD)
    return len(M.REG) - len(before), len(M.FAMILIES) - families


# ------------------------------------------------------------------ ELF: the build id without a section table

PT_NOTE = 4
NT_GNU_BUILD_ID = 3
NOTE_WALK = 4096   # notes of one segment, and PT_NOTE segments of one file


def _note_segments(d: bytes, x: dict) -> list:
    """[(offset, file size, alignment)] of the PT_NOTE segments, from the program header table."""
    if x["phentsize"] != (32 if x["bits"] == 32 else 56) or x["phnum"] >= NOTE_WALK:
        U("a program header table that is not walked: too many entries, or entries of another size")
    out = []
    for i in range(x["phnum"]):
        at = x["phoff"] + i * x["phentsize"]
        if x["bits"] == 32:
            typ, off, _, _, filesz, _, _, align = M._at(x["e"] + "8I", d, at)
        else:
            typ, _, off, _, _, filesz, _, align = M._at(x["e"] + "IIQQQQQQ", d, at)
        if typ == PT_NOTE:
            if off + filesz > len(d):
                U("a PT_NOTE segment that runs past the file")
            out.append((off, filesz, align))
    return out


def _gnu_build_ids(d: bytes, x: dict) -> list:
    """The descriptors (hex) of every GNU build-id note of the PT_NOTE segments, in file order,
    one per place: a note two segments both cover is one note."""
    found = {}
    for off, size, align in _note_segments(d, x):
        pad = 8 if align == 8 else 4
        p, end, steps = off, off + size, 0
        while p + 12 <= end:
            steps += 1
            if steps > NOTE_WALK:
                U("more notes in one segment than are walked")
            namesz, descsz, typ = struct.unpack(x["e"] + "III", d[p:p + 12])
            if not namesz and not descsz and not typ:
                break   # the segment's fill
            # the 12-byte header and the name are padded together (in an 8-aligned PT_NOTE the name alone
            # would be padded to 8 and the walk would overshoot by 4)
            desc = p + (12 + namesz + pad - 1) // pad * pad
            if desc + descsz > end:
                U("a note that runs past its PT_NOTE segment")
            if typ == NT_GNU_BUILD_ID and d[p + 12:p + 12 + namesz] == b"GNU\x00":
                if not descsz:
                    U("a GNU build-id note with no id")
                found.setdefault(p, d[desc:desc + descsz].hex())
            p = desc + (descsz + pad - 1) // pad * pad
    return [found[k] for k in sorted(found)]


def _build_id_reader(by_section):
    """The build id: the .note.gnu.build-id section where the file has a section table (the earlier
    reader, as it read it), and the PT_NOTE segments, which must not say anything else."""
    def fn(n, d):
        x = RM._elfx(d)
        if x is None:
            return None
        sections = bool(x["shoff"] and x["shnum"])
        segments = bool(x["phoff"] and x["phnum"])
        if not sections and not segments:
            U("the file has no section header table and no program header table")
        stated = by_section(n, d) if sections else None
        ids = sorted(set(_gnu_build_ids(d, x))) if segments else []
        if len(ids) > 1:
            U(f"{len(ids)} GNU build-id notes with different ids, and the name does not say which")
        if stated is not None and ids and ids[0] != stated:
            U("the .note.gnu.build-id section and the PT_NOTE segments state different build ids")
        return stated if stated is not None else (ids[0] if ids else None)
    return fn


@section
def _reg_elf():
    old = M.REG.get("elf_build_id")
    if old is not None:
        fn = _build_id_reader(old.fn)
        for k, p in list(M.REG.items()):   # every spelling of the earlier reader keeps its name, class and key
            if p.fn is old.fn:
                M.REG[k] = M.Prop(p.name, fn, p.fmt, False, p.bits, p.unit)
        # elf.note_gnu_build_id_hex and the like are not registered: no registered elf.* name ends in
        # hex (row 178), and the wrapper reads such a name by its stem (`hex_lower~elf.note_gnu_build_id`).
        for x in free("elf", ["build_id_note", "gnu_build_id_note", "note_build_id", "pt_note_gnu_build_id", "pt_note_build_id",
                              "build_id_bytes", "note_gnu_build_id_bytes"]):
            M.REG[M.canon(f"elf.{x}")] = M.Prop(f"elf.{x}", fn, old.fmt, False, old.bits, old.unit)
    also("elf", "interpreter", ["pt_interp_path", "interp_path", "interpreter_path", "program_interpreter_path", "pt_interp_string",
                                "dynamic_linker_path", "requested_interpreter"])


# ------------------------------------------------------------------ PE: the debug directory's names, TLS, the manifest

TLS_DIRECTORY = 9
RT_MANIFEST = 24
TLS_WALK = 4096
LEVEL = re.compile(r"<(?:[A-Za-z0-9_.\-]+:)?requestedExecutionLevel\b([^>]*)>")
ATTRIBUTE = r"""\b%s\s*=\s*(?:"([^"]*)"|'([^']*)')"""


def _tls_callbacks(n, d):
    x = RM._pex(d)
    if x is None:
        return None
    entry = x["dirs"][TLS_DIRECTORY] if len(x["dirs"]) > TLS_DIRECTORY else (0, 0)
    if not entry[0] and not entry[1]:
        return 0   # the header names no TLS directory: no callback is registered
    if not entry[0] or entry[1] < (40 if x["plus"] else 24):
        U("a TLS directory entry with no address, or shorter than the structure")
    at = RM._pe_rva(x, entry[0])
    step, fmt = (8, "<Q") if x["plus"] else (4, "<I")
    table = M._at(fmt, d, at + 3 * step)[0]   # AddressOfCallBacks, a virtual address
    if not table:
        return 0
    if table < x["base"]:
        U("AddressOfCallBacks lies below the image base")
    p, count = RM._pe_rva(x, table - x["base"]), 0
    while M._at(fmt, d, p + count * step)[0]:
        count += 1
        if count > TLS_WALK:
            U("more TLS callbacks than are walked")
    return count


def _manifests(d: bytes):
    """The texts of the RT_MANIFEST resources: None when the file is not a PE, [] when it has none."""
    if PT is None:
        U("readers_pe_tables.py is not loaded, and its resource tree is this reader's")
    root = PT._resources(d)
    if root is None:
        return None
    pe, out = RM._pefile(d), []
    walk = [e for e in (root.entries if root else []) if e.id == RT_MANIFEST]
    steps = 0
    while walk:
        steps += 1
        if steps > 4096:
            U("a resource tree that is not walked")
        entry = walk.pop()
        if hasattr(entry, "directory"):
            walk.extend(entry.directory.entries)
            continue
        size = entry.data.struct.Size
        if size > 1 << 20:
            U("a manifest larger than is read")
        raw = pe.get_data(entry.data.struct.OffsetToData, size)
        if len(raw) != size:
            U("a manifest resource that runs past the file")
        if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
            out.append(RM.text(raw, "utf-16"))
        else:
            out.append(RM.text(raw[3:] if raw[:3] == b"\xef\xbb\xbf" else raw))
    return out


def _manifest_attribute(attribute: str):
    def fn(n, d):
        texts = _manifests(d)
        if not texts:
            return None
        values = set()
        for t in texts:
            t = re.sub(r"<!--.*?-->", "", t, flags=re.S)
            for m in LEVEL.finditer(t):
                a = re.search(ATTRIBUTE % attribute, m.group(1))
                if a is None:
                    U(f"a requestedExecutionLevel element without {attribute}")
                values.add(a.group(1) if a.group(1) is not None else a.group(2))
        if len(values) > 1:
            U(f"several requestedExecutionLevel elements that state different values of {attribute}")
        return next(iter(values)) or None if values else None
    return fn


@section
def _reg_pe():
    also("pe", "pdb_guid", ["debug_codeview_guid", "debug_directory_codeview_guid", "debug_directory_guid", "debug_guid", "rsds_guid",
                            "debug_rsds_guid", "codeview_pdb_guid", "debug_codeview_pdb_guid", "codeview_signature",
                            "debug_codeview_signature", "debug_directory_pdb_guid", "codeview_rsds_guid"])
    also("pe", "pdb_age", ["debug_age", "debug_codeview_age", "debug_directory_codeview_age", "debug_directory_age", "rsds_age",
                           "debug_rsds_age", "codeview_pdb_age", "debug_directory_pdb_age"])
    also("pe", "pdb_path", ["debug_codeview_pdb_path", "debug_directory_pdb_path", "debug_directory_codeview_pdb_path", "rsds_pdb_path",
                            "debug_rsds_pdb_path", "debug_codeview_path", "codeview_path", "pdb_file_path", "debug_pdb_file_name",
                            "codeview_pdb_file_name", "debug_codeview_pdb_file_name", "rsds_path"])
    reg("pe", ["tls_callback_count", "tls_callbacks_count", "tls_directory_callback_count", "tls_callback_function_count",
               "tls_directory_callbacks_count"], "integer", _tls_callbacks)
    reg("pe", ["tls_callbacks_present", "has_tls_callbacks", "tls_callback_present"], "bool",
        lambda n, d: (lambda c: None if c is None else c > 0)(_tls_callbacks(n, d)))
    reg("pe", ["manifest_requested_execution_level", "manifest_execution_level", "requested_execution_level",
               "manifest_requested_execution_level_level", "manifest_requestedexecutionlevel", "manifest_requestedexecutionlevel_level",
               "manifest_trustinfo_requested_execution_level", "manifest_level", "execution_level"], "text", _manifest_attribute("level"))
    reg("pe", ["manifest_ui_access", "manifest_uiaccess", "manifest_requested_execution_level_ui_access",
               "manifest_requested_execution_level_uiaccess", "requested_execution_level_ui_access"], "text",
        _manifest_attribute("uiAccess"))


# ------------------------------------------------------------------ zip: one central-directory entry

SPELLINGS = ("{w}_entry_{f}", "{w}_member_{f}", "central_directory_{w}_{f}", "central_directory_{w}_entry_{f}",
             "central_directory_{w}_member_{f}", "cd_{w}_{f}", "cd_{w}_entry_{f}", "{w}_central_directory_entry_{f}",
             "{w}_central_header_{f}", "{w}_central_directory_header_{f}")
# the field as the earlier first_entry_* reader names it, its other names, the class, the value of one central header
ZIP_FIELDS = (
    ("crc32", ("crc32", "crc_32", "crc"), "hex", lambda e: f"{e['crc']:08x}"),
    ("compressed_size_bytes", ("compressed_size_bytes", "compressed_size"), "integer", lambda e: e["csize"]),
    ("uncompressed_size_bytes", ("uncompressed_size_bytes", "uncompressed_size", "size_bytes", "size"), "integer", lambda e: e["usize"]),
    ("compression_method", ("compression_method", "method"), "integer", lambda e: e["method"]),
    ("modified", ("modified", "mtime", "modified_time", "modification_time", "dos_modified", "dos_time", "last_modified"), "timestamp",
     lambda e: M._dos_stamp(e["time"], e["date"]) + (False,)),
    ("name", ("name", "filename", "file_name", "path"), "text", lambda e: e["name"]),
    ("version_made_by", ("version_made_by",), "number", lambda e: e["made"]),
)


def _spelled(which: str, fields) -> list:
    return [s.format(w=which, f=f) for f in fields for s in SPELLINGS]


def _crc_forms(value: int) -> list:
    """A CRC-32 under a name that ends in hex: 0x and its eight digits first (the form the judge
    took for the u16 and u32 fields of Days 9 and 10), then the bare digits in both cases."""
    return [("0x_hex_lower", f"0x{value:08x}"), ("hex_lower", f"{value:08x}"), ("hex_upper", f"{value:08X}")]


@section
def _reg_zip():
    for field, names, fmt, get in ZIP_FIELDS:
        # the first entry: the earlier reader of zip.first_entry_<field> under more names
        if M.canon(f"zip.first_entry_{field}") in M.REG:
            also("zip", f"first_entry_{field}", _spelled("first", names))
        else:
            reg("zip", _spelled("first", names), fmt, M._cd_list(lambda cd, get=get: get(cd[0])))
        reg("zip", _spelled("last", names), fmt, M._cd_list(lambda cd, get=get: get(cd[-1])))
    # <which>_..._crc32_hex is a family, not a registered name: no registered name ends in a width or
    # form word (row 178), so that typed() never strips one off a name a reader holds whole.
    where = "|".join(sorted({s.format(w="{w}", f="").rstrip("_") for s in SPELLINGS}, key=len, reverse=True))
    for which, index in (("first", 0), ("last", -1)):
        M.family(rf"zip_(?:{where.replace('{w}', which)})_crc_?32(?:_u32)?_hex", "forms")(
            lambda n, d, index=index: M._cd_list(lambda cd: _crc_forms(cd[index]["crc"]))(n, d))
    reg("zip", ["encrypted_member_count", "encrypted_entry_count", "encrypted_file_count", "encrypted_members_count",
                "central_directory_encrypted_entry_count"], "integer", M._cd_list(lambda cd: sum(1 for e in cd if e["flags"] & 1)))


# ------------------------------------------------------------------ tar: the first header under more names

@section
def _reg_tar():
    for field, more in (("mode", ()), ("uid", ()), ("gid", ()), ("size_bytes", ("size",)), ("mtime", ("modified", "modification_time")),
                        ("name", ("filename", "file_name", "path")), ("uname", ("owner_name", "user_name")),
                        ("gname", ("group_name",)), ("typeflag", ("type_flag", "type")), ("checksum", ("chksum",))):
        names = (field,) + more
        also("tar", f"first_entry_{field}", [f"{w}_{x}" for x in names for w in ("first_header", "first_member", "first_entry",
                                                                                 "first_ustar_header")])
    also("tar", "ustar_magic", ["first_header_magic", "first_header_ustar_magic", "first_entry_magic", "first_member_magic",
                                "header_ustar_magic"])
    also("tar", "ustar_version", ["first_header_version", "first_header_ustar_version", "first_entry_version", "first_member_version"])


# ------------------------------------------------------------------ gzip: the trailer's CRC-32 as hex

@section
def _reg_gzip():
    def crc(n, d):
        t = M._gzip_trailer(d)
        return None if t is None else _crc_forms(t[0])
    M.family(r"gzip_(?:trailer_|member_|stored_)?crc_?32(?:_u32)?_hex", "forms")(crc)


# ------------------------------------------------------------------ AIFF and AIFF-C

AIFF_WALK = 4096


def _aiff(d: bytes):
    """(form type, [(chunk id, body)]) of an AIFF or AIFF-C file, or None when the file is neither."""
    if d[:4] != b"FORM" or d[8:12] not in (b"AIFF", b"AIFC") or len(d) < 12:
        return None
    size = struct.unpack(">I", d[4:8])[0]
    if 8 + size > len(d):
        U("the file is shorter than its FORM chunk states")
    end = 8 + size
    chunks, p = [], 12
    while p + 8 <= end:
        if len(chunks) >= AIFF_WALK:
            U("more chunks than are walked")
        cid, n = d[p:p + 4], struct.unpack(">I", d[p + 4:p + 8])[0]
        if p + 8 + n > end:
            U("a chunk that runs past the FORM")
        if not all(32 <= c < 127 for c in cid):
            U("a chunk id that is not four printable characters")
        chunks.append((cid.decode("ascii"), d[p + 8:p + 8 + n]))
        p += 8 + n + (n & 1)
    return d[8:12].decode("ascii"), chunks, size


def _comm(d: bytes):
    """(channels, sample frames, sample size, sample rate as a Fraction, compression type or None)."""
    a = _aiff(d)
    if a is None:
        return None
    hits = [body for cid, body in a[1] if cid == "COMM"]
    if len(hits) != 1:
        U("not exactly one COMM chunk")
    body = hits[0]
    if len(body) < 18:
        U("a COMM chunk that is cut")
    channels, frames, bits = struct.unpack(">hIh", body[:8])
    sign_exp, mantissa = struct.unpack(">HQ", body[8:18])
    if sign_exp & 0x8000 or (sign_exp & 0x7FFF) == 0x7FFF:
        U("a sample rate that is negative or not a number")
    rate = fractions.Fraction(mantissa) * fractions.Fraction(2) ** ((sign_exp & 0x7FFF) - 16383 - 63)
    kind = None
    if a[0] == "AIFC":
        if len(body) < 22:
            U("an AIFF-C COMM chunk without its compression type")
        kind = RM.text(body[18:22], "ascii")
    return channels, frames, bits, rate, kind


def _comm_field(i: int):
    def fn(n, d):
        c = _comm(d)
        if c is None:
            return None
        if i == 3:
            if c[3].denominator != 1:
                U("a sample rate that is not a whole number of hertz")
            return int(c[3])
        return c[i]
    return fn


@section
def _reg_aiff():
    ns = "aiff"
    if ns not in M.NAMESPACES:
        M.NAMESPACES.add(ns)
        M.PACK_NAMESPACES.add(ns)
        M.CONTENT_TOKENS.update({ns, "aif", "aifc"})
        M.RELATED.setdefault(ns, (ns,))
        M.MORE_TYPES.append((ns, lambda d: d[:4] == b"FORM" and d[8:12] in (b"AIFF", b"AIFC")))
    M.NS_ALIAS.update({a: ns for a in ("aif", "aifc", "aiff_c") if a not in M.NS_ALIAS and a not in M.NAMESPACES})
    reg(ns, ["form_type", "form_format", "form_id", "format"], "text", lambda n, d: (lambda a: None if a is None else a[0])(_aiff(d)))
    reg(ns, ["form_size_bytes", "form_chunk_size_bytes", "form_size", "form_chunk_size"], "integer",
        lambda n, d: (lambda a: None if a is None else a[2])(_aiff(d)))
    reg(ns, ["chunk_ids", "chunk_types", "chunk_names"], "list",
        lambda n, d: (lambda a: None if a is None else [cid for cid, _ in a[1]] or None)(_aiff(d)))
    reg(ns, ["chunk_count"], "integer", lambda n, d: (lambda a: None if a is None else len(a[1]))(_aiff(d)))
    reg(ns, ["comm_channels", "channels", "channel_count", "comm_num_channels", "num_channels", "comm_channel_count",
             "comm_number_of_channels"], "integer", _comm_field(0))
    reg(ns, ["comm_num_sample_frames", "comm_sample_frames", "sample_frames", "sample_frame_count", "num_sample_frames",
             "comm_sample_frame_count"], "integer", _comm_field(1))
    reg(ns, ["comm_sample_size_bits", "comm_sample_size", "sample_size_bits", "sample_size", "bits_per_sample", "bit_depth",
             "comm_bits_per_sample"], "integer", _comm_field(2))
    reg(ns, ["comm_sample_rate_hz", "comm_sample_rate", "sample_rate_hz", "sample_rate"], "integer", _comm_field(3))
    reg(ns, ["comm_compression_type", "compression_type", "comm_compression", "compression"], "text", _comm_field(4))


# ------------------------------------------------------------------ ISO 9660 under its short name

@section
def _reg_iso():
    long, short = "iso9660", "iso"
    if long not in M.NAMESPACES or not hasattr(RM, "_pvd"):
        return
    reg(long, ["standard_identifier", "standard_id", "pvd_standard_identifier", "pvd_standard_id"], "text",
        RM.of(RM._pvd, lambda s: RM.text(s[1:6], "ascii")))
    reg(long, ["volume_descriptor_version", "pvd_version", "pvd_volume_descriptor_version"], "integer", RM.of(RM._pvd, lambda s: s[6]))
    if short in M.NAMESPACES:
        return
    M.NAMESPACES.add(short)
    M.PACK_NAMESPACES.add(short)
    M.RELATED.setdefault(short, (short, long))
    for k, p in list(M.REG.items()):   # every iso9660.<name> is iso.<name> too: the same extractor, a key of its own spelling
        head, _, rest = k.partition("_")
        if head == long and rest and f"{short}_{rest}" not in M.REG:
            M.REG[f"{short}_{rest}"] = M.Prop(f"{short}.{rest}", p.fn, p.fmt, False, p.bits, p.unit)
