#!/usr/bin/env python3
"""Metadata Forensics reader pack after Day 12: the CLR (.NET) metadata of a PE file.

properties_strict.py loads this file by name after the other packs and calls register(M) with
itself. Day 12 asked dotnet.mvid_guid (the Module table's Mvid) and the judge took the canonical
lowercase GUID text; the lane's agent read it in a day_patch.py, and that reader lives here now.
Everything else here is a forecast of the same family and answers unsure: every property is
registered unconfirmed, so the strict wrapper offers it through labels.pick until the judge has
accepted a format for its key.

The one judged name. dotnet.mvid_guid is registered under the name the day patch gave it,
`dotnet_mvid_guid` (dotnet was no namespace then, so the asked name was written without its dot),
because the ledger and, after `labels.py promote metadata`, the seed hold the judge's verdict under
exactly that key: metadata.format/dotnet_mvid_guid, name `raw`. It is not confirmed in code: it is
plain through the ledger or the seed, like every name judged since Day 7, and unsure on a checkout
that has neither. Its other spellings (dotnet.mvid, dotnet.module_version_id, ...) are GUID-class
readers under keys of their own.

The contract of an extractor is the wrapper's: fn(name, data) returns the value read from the
bytes, None when the file is not a PE, has no CLR header or does not hold the structure, or raises
M.Unknown when it does and the bytes do not settle the fact. The PE header and the section table
are readers_more.py's own reading (_pex); the CLR header, the metadata root, the #~ stream and its
tables are read here by ECMA-335 II.24 and II.22, plain Python over the bytes in hand (no dnfile on
the path of an answer: tests/test_metadata_dotnet.py holds every value against dnfile). Rows are
read only for the table a question asks, so a large assembly costs what its question costs.

What is here (namespace dotnet; clr, cli, net, managed and dot_net are read as it; the same names
are found under pe.dotnet_*, pe.clr_*, pe.net_* and pe.managed_*, and a name that says the runtime
itself under pe.* alone: pe.clr_header_flags, pe.cor20_flags, pe.mvid):
  CLR header     cb, the runtime version halves (2.5: the header's, not the framework's), Flags and
                 each of its bits (ILONLY, 32BITREQUIRED, STRONGNAMESIGNED, ...), the entry point
                 token and the method it names, the MetaData, Resources and StrongNameSignature
                 directories.
  metadata root  the version string (v4.0.30319), the root's own version, the stream names, their
                 count, each stream's size and offset.
  heaps          the #GUID heap's entry count and GUIDs, the #US heap's strings and their count.
  tables         the row count of every table by its name (dotnet.typedef_count,
                 dotnet.member_ref_row_count; a table the file does not have is 0), the tables
                 present, the Module's name and Mvid, the Assembly's name, version, culture, public
                 key, public key token, hash algorithm and flags, the AssemblyRef names, versions and
                 tokens, the TypeDef, TypeRef, MethodDef, MemberRef, ModuleRef and ManifestResource
                 names.
  attributes     the assembly's custom attributes whose constructor takes one string, read from
                 the #Blob: TargetFramework (and its FrameworkDisplayName), AssemblyTitle, Company,
                 Product, Copyright, Trademark, Description, Configuration, FileVersion,
                 InformationalVersion, the Guid attribute; the attribute type names and their count.
                 Two attributes of one type establish nothing.
  debug          the CodeView record of the debug directory: PDB path, GUID and age (readers_more's
                 _pe_codeview). That GUID is not the Mvid: the Mvid is the module's own identity,
                 a 16-byte entry of the #GUID heap that the Module table's row points at, while the
                 CodeView GUID sits in the RSDS record of the PE debug directory and names the PDB
                 that matches the build. A compiler may derive both from one hash; they are stored
                 in two places and are in general two values, and a file may have one and not the
                 other (the Day 12 samples have an Mvid and no CodeView record).
                 B-222: the other entries of the debug directory by their type: the type names
                 and count, the Repro entry (type 16) a deterministic build writes and its hash,
                 the PdbChecksum entry (type 19), an embedded portable PDB (type 17).
  namespaces     (B-222) the distinct namespaces of the TypeDef and TypeRef rows, in table order.
  bundle         (B-222) a .NET single-file bundle (an apphost, PE, ELF or Mach-O, with the app's
                 files appended) is read through its application assembly: every dotnet.* name of
                 an executable that has no CLR header of its own and carries a bundle is answered
                 from the assembly the bundle's deps.json / runtimeconfig.json names (or its one
                 application assembly when it has neither). B-054's decompile_intake reads the
                 manifest and takes the assembly out (bundle_members inflates a deflated one); this
                 file only picks which one. The bundle's own facts (is it one, its version and id,
                 its files, the assembly picked) are read under dotnet.bundle_* and
                 dotnet.is_single_file_bundle, from the bundle itself.

Not read, on purpose: a file with two streams of one name or both #~ and #-, a table past the
schema of ECMA-335 (the portable PDB tables) when a row behind it is asked, an attribute whose
constructor is not exactly (string), an entry point that is a native RVA, a bundle whose
application assembly is not settled by its manifest. Each is M.Unknown.

read_mvid(data) is the Mvid read for a caller outside the lane's question path
(speedrun/solvers/metadata_d12.py): the text, or None where the bytes do not settle it.
"""
import functools
import hashlib
import re
import struct
import uuid as uuidlib
import zlib
from pathlib import Path

M = None          # properties_strict, set by register()
RM = None         # readers_more.py as loaded by properties_strict: _pex, _pe_codeview, text
SECTIONS = []
MINE = {}         # canonical name (without the namespace) -> (extractor, class), for the pe.* spellings
LIMIT = 1 << 16   # rows of one table that are read into a list
NS = "dotnet"
NS_OTHER = ("clr", "cli", "net", "managed", "dot_net")        # M.NS_ALIAS: clr.header_flags is dotnet.header_flags
PE_PREFIXES = ("dotnet", "clr", "net", "managed")             # pe.dotnet_assembly_name, pe.clr_metadata_version
PE_OWN = ("clr_", "cor20_", "corflags", "comimage_", "mvid", "managed_")   # names that say the runtime themselves
JUDGED = "dotnet_mvid_guid"   # Day 12's name as the ledger keys it (see the docstring)
# B-054's engine, whose bundle_members takes the files out of a .NET single-file bundle (binary lane).
INTAKE = Path(__file__).resolve().parent.parent / "binary" / "decompile_intake.py"
# The heads of the executables an apphost is: PE, ELF, Mach-O (both byte orders, 32 and 64 bit).
EXEC_HEADS = (b"MZ", b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce")
# What a cut or hostile bundle raises while it is parsed and inflated: no answer. Anything else
# (B-054's file missing, a bug) is raised as it is: never a quiet Unknown.
BUNDLE_PARSE_ERRORS = (struct.error, ValueError, IndexError, KeyError, zlib.error, UnicodeDecodeError, OverflowError)


def section(fn):
    SECTIONS.append(fn)
    return fn


def U(msg):
    raise M.Unknown(msg)


def held(fn, subject=True):
    """fn, with whatever a cut or damaged structure raises turned into Unknown: nothing is established.
    With `subject` (every dotnet.* reader but the bundle's own), a single-file bundle is read through
    its application assembly (_subject)."""
    @functools.wraps(fn)
    def safe(*args):
        if subject and len(args) >= 2:
            args = (args[0], _subject(args[1])) + args[2:]
        try:
            return fn(*args)
        except (M.Unknown, M.Ambiguous, ImportError):   # ImportError: B-054's file is missing, named, never an Unknown
            raise
        except Exception as e:
            U(f"the bytes do not read as this structure ({type(e).__name__})")
    return safe


def reg(names, fmt, fn, bits=None, unit=None, subject=True):
    """Register one extractor under every dotnet.<name> that no earlier reader holds."""
    names = [names] if isinstance(names, str) else list(names)
    fn = held(fn, subject)
    free = [x for x in names if f"{NS}_{x}" not in M.REG]
    if free:
        M.prop(*[f"{NS}.{x}" for x in free], fmt=fmt, bits=bits, unit=unit)(fn)
        for x in free:
            MINE[x] = (fn, fmt)
    return fn


# ------------------------------------------------------------------ the CLR header and the metadata root

FLAGS = (("ILONLY", 0x1), ("32BITREQUIRED", 0x2), ("IL_LIBRARY", 0x4), ("STRONGNAMESIGNED", 0x8),
         ("NATIVE_ENTRYPOINT", 0x10), ("TRACKDEBUGDATA", 0x10000), ("32BITPREFERRED", 0x20000))   # COMIMAGE_FLAGS_<name>


def _off(x: dict, d: bytes, rva: int, size: int) -> int:
    """The file offset of `size` bytes at an RVA: in exactly one section and inside its raw data."""
    hits = [rptr + rva - vaddr for _, vsize, vaddr, rsize, rptr, _ in x["sections"]
            if vaddr <= rva < vaddr + max(vsize, rsize) and rva - vaddr < rsize]
    if len(hits) != 1 or hits[0] < 0 or hits[0] + size > len(d):
        U("an address that is not in one section's raw data")
    return hits[0]


@functools.lru_cache(maxsize=8)
def _clr(d: bytes):
    """The CLR header and the metadata root: None when the file is not a PE, () when its header names
    no CLR directory, else a dict. Streams are (name, file offset, size, offset in the metadata)."""
    x = RM._pex(d)
    if x is None:
        return None
    if len(x["dirs"]) <= 14:
        return ()
    rva, size = x["dirs"][14]
    if bool(rva) != bool(size):
        U("a CLR directory entry with an address and no size, or a size and no address")
    if not rva:
        return ()
    at = _off(x, d, rva, 72)
    cb, major, minor, md_rva, md_size, flags, entry, res_rva, res_size, sn_rva, sn_size = struct.unpack_from("<IHHIIIIIIII", d, at)
    if cb < 72:
        U("a CLR header shorter than its 72 bytes")
    md = _off(x, d, md_rva, 20)
    if d[md:md + 4] != b"BSJB":
        U("no metadata root where the CLR header points")
    root_major, root_minor, _reserved, vlen = struct.unpack_from("<HHII", d, md + 4)
    if vlen > 255 or md + 16 + vlen + 4 > len(d):
        U("a metadata version string that is cut")
    raw = d[md + 16:md + 16 + vlen].rstrip(b"\x00")
    if b"\x00" in raw:
        U("a metadata version string with bytes behind its end")
    p = md + 16 + vlen
    root_flags, count = struct.unpack_from("<HH", d, p)
    p += 4
    if count > 64:
        U("more metadata streams than any file has")
    streams = []
    for _ in range(count):
        offset, length = struct.unpack_from("<II", d, p)
        end = d.find(b"\x00", p + 8, p + 8 + 33)
        if end < 0:
            U("a stream name that does not end")
        name = d[p + 8:end]
        if not name or not name.isascii() or not name.decode("ascii").isprintable():
            U("a stream name that is not text")
        if md + offset + length > len(d):
            U("a metadata stream that runs past the file")
        streams.append((name.decode("ascii"), md + offset, length, offset))
        p += 8 + ((end - (p + 8) + 4) & ~3)
    return {"at": at, "cb": cb, "runtime": (major, minor), "md_rva": md_rva, "md_size": md_size, "md": md, "flags": flags,
            "entry": entry, "resources": (res_rva, res_size), "strong_name": (sn_rva, sn_size),
            "root_version": (root_major, root_minor), "version": RM.text(raw), "root_flags": root_flags, "streams": streams}


def of_clr(get, unmanaged=None):
    """An extractor over the CLR header: `unmanaged` for a PE that has none."""
    def fn(n, d):
        c = _clr(d)
        return c if c is None else (unmanaged if c == () else get(c))
    return fn


def _stream(c: dict, name: str):
    """(file offset, size) of the one stream of this name, None when the file has none."""
    hits = [(at, size) for s, at, size, _ in c["streams"] if s == name]
    if len(hits) > 1:
        U(f"two {name} streams")
    return hits[0] if hits else None


@section
def _reg_header():
    reg(["is_managed", "is_dotnet_assembly", "clr_header_present", "has_clr_header", "cor20_header_present", "is_clr_image"], "bool",
        of_clr(lambda c: True, False))
    reg(["clr_header_size", "clr_header_cb", "cor20_header_size", "cor20_cb", "clr_header_size_bytes"], "integer", of_clr(lambda c: c["cb"]))
    reg(["clr_header_major_runtime_version", "cor20_major_runtime_version", "major_runtime_version", "clr_major_runtime_version"],
        "integer", of_clr(lambda c: c["runtime"][0]))
    reg(["clr_header_minor_runtime_version", "cor20_minor_runtime_version", "minor_runtime_version", "clr_minor_runtime_version"],
        "integer", of_clr(lambda c: c["runtime"][1]))
    reg(["clr_header_runtime_version", "cor20_runtime_version", "clr_header_version", "cor20_version"], "dotted",
        of_clr(lambda c: c["runtime"]))
    reg(["clr_header_flags", "cor20_flags", "clr_flags", "corflags", "comimage_flags", "runtime_flags", "cor20_header_flags",
         "header_flags"], "number",
        of_clr(lambda c: c["flags"]), bits=32)

    def flag_names(c):
        if c["flags"] & ~sum(bit for _, bit in FLAGS):
            U("a flag bit the specification does not name")
        return [f"COMIMAGE_FLAGS_{name}" for name, bit in FLAGS if c["flags"] & bit] or None
    reg(["clr_header_flag_names", "cor20_flag_names", "corflags_names", "comimage_flag_names", "clr_flag_names"], "list", of_clr(flag_names))
    spell = {"ILONLY": ("il_only", "ilonly"), "32BITREQUIRED": ("32bit_required", "32bitrequired", "requires_32bit", "32_bit_required"),
             "IL_LIBRARY": ("il_library",), "STRONGNAMESIGNED": ("strong_name_signed", "strongnamesigned", "strong_named"),
             "NATIVE_ENTRYPOINT": ("native_entrypoint", "native_entry_point"), "TRACKDEBUGDATA": ("track_debug_data", "trackdebugdata"),
             "32BITPREFERRED": ("32bit_preferred", "32bitpreferred", "prefers_32bit", "prefer_32bit")}
    for name, bit in FLAGS:
        names = []
        for s in spell[name]:
            names += [s, f"is_{s}", f"clr_header_{s}", f"cor20_{s}", f"flag_{s}", f"comimage_flags_{s}", f"clr_flag_{s}"]
        reg(names, "bool", of_clr(lambda c, bit=bit: bool(c["flags"] & bit)))

    def token(c):
        if c["flags"] & 0x10:
            U("the entry point is a native RVA, not a metadata token")
        return c["entry"]
    # A token is written with every digit (0x06000001: the table's byte, then the row), under a hex name or not.
    reg(["entry_point_token", "clr_header_entry_point_token", "cor20_entry_point_token", "entrypoint_token", "managed_entry_point_token",
         "entry_point_metadata_token", "entry_point_token_hex", "clr_header_entry_point_token_hex", "entrypoint_token_hex"],
        "u32hex", of_clr(token), bits=32)
    # ... and with its width said (a family: no registered name ends in a width, row 178).
    M.family(rf"{NS}_(?:clr_header_|cor20_|managed_)?entry_?point_(?:metadata_)?token_u32(?:_hex)?", "u32hex")(held(of_clr(token)))
    reg(["entry_point_table", "entry_point_token_table"], "integer", of_clr(lambda c: token(c) >> 24))
    reg(["entry_point_rid", "entry_point_row", "entry_point_token_rid", "entry_point_token_row"], "integer",
        of_clr(lambda c: token(c) & 0xFFFFFF))
    reg(["metadata_rva", "clr_header_metadata_rva", "cor20_metadata_rva", "metadata_directory_rva", "metadata_virtual_address"],
        "number", of_clr(lambda c: c["md_rva"]), bits=32, unit="rva")
    reg(["metadata_size", "clr_header_metadata_size", "cor20_metadata_size", "metadata_directory_size", "metadata_size_bytes"], "integer",
        of_clr(lambda c: c["md_size"]), bits=32)
    reg(["metadata_file_offset", "metadata_root_file_offset", "metadata_root_offset", "bsjb_offset", "metadata_offset"], "number",
        of_clr(lambda c: c["md"]), bits=32, unit="offset")
    reg(["clr_header_file_offset", "cor20_header_file_offset", "clr_header_offset", "cor20_header_offset"], "number",
        of_clr(lambda c: c["at"]), bits=32, unit="offset")
    for what, key in (("resources", "resources"), ("strong_name_signature", "strong_name")):
        reg([f"{what}_rva", f"clr_header_{what}_rva", f"cor20_{what}_rva", f"{what}_directory_rva"], "number",
            of_clr(lambda c, key=key: c[key][0]), bits=32, unit="rva")
        reg([f"{what}_size", f"clr_header_{what}_size", f"cor20_{what}_size", f"{what}_directory_size", f"{what}_size_bytes"], "integer",
            of_clr(lambda c, key=key: c[key][1]), bits=32)

    def present(key):
        def get(c):
            rva, size = c[key]
            if bool(rva) != bool(size):
                U("a directory with an address and no size, or a size and no address")
            return bool(rva)
        return of_clr(get)
    reg(["strong_name_signature_present", "has_strong_name_signature", "strong_name_present"], "bool", present("strong_name"))
    reg(["resources_present", "has_managed_resources", "managed_resources_present", "resources_directory_present"], "bool",
        present("resources"))


@section
def _reg_root():
    # v4.0.30319 as the root writes it, then without its v: the version of the runtime the file was built for.
    reg(["metadata_version", "metadata_version_string", "metadata_root_version_string", "runtime_version", "clr_version",
         "metadata_runtime_version", "target_runtime_version", "runtime_version_string", "clr_runtime_version",
         "image_runtime_version", "metadata_header_version_string", "bsjb_version_string", "target_runtime"], "forms",
        of_clr(lambda c: ([("raw", c["version"])] + ([("bare", c["version"][1:])] if re.fullmatch(r"v\d[\d.]*", c["version"]) else []))
               if c["version"] else None))
    reg(["metadata_version_length", "metadata_version_string_length"], "integer", of_clr(lambda c: len(c["version"].encode())))
    reg(["metadata_root_version", "metadata_format_version", "metadata_signature_version", "bsjb_version"], "dotted",
        of_clr(lambda c: c["root_version"]))
    reg(["metadata_root_major_version", "metadata_major_version", "bsjb_major_version"], "integer", of_clr(lambda c: c["root_version"][0]))
    reg(["metadata_root_minor_version", "metadata_minor_version", "bsjb_minor_version"], "integer", of_clr(lambda c: c["root_version"][1]))
    reg(["stream_names", "metadata_stream_names", "metadata_streams", "streams", "stream_name_list", "metadata_stream_list"], "list",
        of_clr(lambda c: [s[0] for s in c["streams"]] or None))
    reg(["stream_count", "metadata_stream_count", "number_of_streams", "metadata_number_of_streams", "streams_count",
         "metadata_root_stream_count"], "integer", of_clr(lambda c: len(c["streams"])))

    heaps = {"strings": "#Strings", "strings_heap": "#Strings", "string_heap": "#Strings", "us": "#US", "us_heap": "#US",
             "user_strings": "#US", "user_strings_heap": "#US", "user_string_heap": "#US", "guid": "#GUID", "guid_heap": "#GUID",
             "blob": "#Blob", "blob_heap": "#Blob", "tables": "#~", "tables_stream": "#~", "metadata_tables": "#~"}
    words = "|".join(sorted(heaps, key=len, reverse=True))

    def one(c, word, at):
        hit = _stream(c, heaps[word]) or (_stream(c, "#-") if heaps[word] == "#~" else None)
        if hit is None:
            return None
        return hit[1] if at == "size" else hit[0] - (c["md"] if at == "offset" else 0)

    @M.family(rf"{NS}_({words})(?:_stream)?_size(?:_bytes)?", "integer")
    @held
    def _size(n, d, word):
        c = _clr(d)
        return None if not c else one(c, word, "size")

    @M.family(rf"{NS}_({words})(?:_stream)?_(offset|file_offset)", "number")
    @held
    def _offset(n, d, word, where):
        c = _clr(d)
        return None if not c else one(c, word, where)
    for word in heaps:
        MINE[f"{word}_size"] = (lambda n, d, word=word: _size(n, d, word), "integer")
        MINE[f"{word}_size_bytes"] = MINE[f"{word}_size"]
        MINE[f"{word}_offset"] = (lambda n, d, word=word: _offset(n, d, word, "offset"), "number")

    def guids(c, d):
        hit = _stream(c, "#GUID")
        if hit is None:
            return []
        if hit[1] % 16:
            U("a #GUID heap that is not a whole number of GUIDs")
        return [str(uuidlib.UUID(bytes_le=d[hit[0] + i:hit[0] + i + 16])) for i in range(0, min(hit[1], 16 * LIMIT), 16)]

    def over(get):
        def fn(n, d):
            c = _clr(d)
            return None if not c else get(c, d)
        return fn
    reg(["guid_heap_count", "guid_count", "guid_heap_guid_count", "guid_heap_entry_count", "guid_heap_entries", "guid_stream_count",
         "guid_heap_size_guids", "number_of_guids"], "integer", over(lambda c, d: len(guids(c, d))))
    reg(["guid_heap_guids", "guids", "guid_heap_values", "guid_list"], "list", over(lambda c, d: guids(c, d) or None))

    def user_strings(c, d):
        """The strings of the #US heap in heap order. An entry of length 0 is the heap's first
        byte or its padding, never a string: an empty string is stored as its one final byte."""
        hit = _stream(c, "#US")
        if hit is None:
            return []
        p, end, out = hit[0], hit[0] + hit[1], []
        while p < end:
            length, p = _compressed(d, p, end)
            if p + length > end:
                U("a user string that runs past its heap")
            if length:
                if length % 2 == 0:
                    U("a user string without its final byte")
                try:
                    out.append(d[p:p + length - 1].decode("utf-16-le"))
                except UnicodeDecodeError:
                    U("a user string that is not UTF-16")
                if len(out) > LIMIT:
                    U("more user strings than are read")
            p += length
        return out
    reg(["user_string_count", "user_strings_count", "us_heap_string_count", "us_string_count", "us_heap_count", "us_heap_entry_count",
         "number_of_user_strings", "us_count"], "integer", over(lambda c, d: len(user_strings(c, d))))

    def listed(c, d):
        out = user_strings(c, d)
        if any(not s for s in out):   # a list answer has no way to write an empty name
            U("an empty user string")
        return out or None
    reg(["user_strings", "us_heap_strings", "user_string_list", "us_strings", "user_string_values"], "list", over(listed))


def _compressed(d: bytes, p: int, end: int):
    """(value, the place after it) of a compressed unsigned integer (ECMA-335 II.23.2)."""
    if p >= end:
        U("a length that is cut")
    b = d[p]
    if b < 0x80:
        return b, p + 1
    if b & 0xC0 == 0x80 and p + 2 <= end:
        return (b & 0x3F) << 8 | d[p + 1], p + 2
    if b & 0xE0 == 0xC0 and p + 4 <= end:
        return (b & 0x1F) << 24 | d[p + 1] << 16 | d[p + 2] << 8 | d[p + 3], p + 4
    U("a length that is not a compressed integer")


# ------------------------------------------------------------------ the tables of the #~ stream

# Column kinds: H u16, I u32, S #Strings index, G #GUID index, B #Blob index, a table number for a
# simple index, a name of CODED for a coded index. ECMA-335 II.22, in table order.
SCHEMA = {
    0x00: ("Module", (("Generation", "H"), ("Name", "S"), ("Mvid", "G"), ("EncId", "G"), ("EncBaseId", "G"))),
    0x01: ("TypeRef", (("ResolutionScope", "ResolutionScope"), ("TypeName", "S"), ("TypeNamespace", "S"))),
    0x02: ("TypeDef", (("Flags", "I"), ("TypeName", "S"), ("TypeNamespace", "S"), ("Extends", "TypeDefOrRef"), ("FieldList", 0x04),
                       ("MethodList", 0x06))),
    0x03: ("FieldPtr", (("Field", 0x04),)),
    0x04: ("Field", (("Flags", "H"), ("Name", "S"), ("Signature", "B"))),
    0x05: ("MethodPtr", (("Method", 0x06),)),
    0x06: ("MethodDef", (("RVA", "I"), ("ImplFlags", "H"), ("Flags", "H"), ("Name", "S"), ("Signature", "B"), ("ParamList", 0x08))),
    0x07: ("ParamPtr", (("Param", 0x08),)),
    0x08: ("Param", (("Flags", "H"), ("Sequence", "H"), ("Name", "S"))),
    0x09: ("InterfaceImpl", (("Class", 0x02), ("Interface", "TypeDefOrRef"))),
    0x0A: ("MemberRef", (("Class", "MemberRefParent"), ("Name", "S"), ("Signature", "B"))),
    0x0B: ("Constant", (("Type", "H"), ("Parent", "HasConstant"), ("Value", "B"))),
    0x0C: ("CustomAttribute", (("Parent", "HasCustomAttribute"), ("Type", "CustomAttributeType"), ("Value", "B"))),
    0x0D: ("FieldMarshal", (("Parent", "HasFieldMarshal"), ("NativeType", "B"))),
    0x0E: ("DeclSecurity", (("Action", "H"), ("Parent", "HasDeclSecurity"), ("PermissionSet", "B"))),
    0x0F: ("ClassLayout", (("PackingSize", "H"), ("ClassSize", "I"), ("Parent", 0x02))),
    0x10: ("FieldLayout", (("Offset", "I"), ("Field", 0x04))),
    0x11: ("StandAloneSig", (("Signature", "B"),)),
    0x12: ("EventMap", (("Parent", 0x02), ("EventList", 0x14))),
    0x13: ("EventPtr", (("Event", 0x14),)),
    0x14: ("Event", (("EventFlags", "H"), ("Name", "S"), ("EventType", "TypeDefOrRef"))),
    0x15: ("PropertyMap", (("Parent", 0x02), ("PropertyList", 0x17))),
    0x16: ("PropertyPtr", (("Property", 0x17),)),
    0x17: ("Property", (("Flags", "H"), ("Name", "S"), ("Type", "B"))),
    0x18: ("MethodSemantics", (("Semantics", "H"), ("Method", 0x06), ("Association", "HasSemantics"))),
    0x19: ("MethodImpl", (("Class", 0x02), ("MethodBody", "MethodDefOrRef"), ("MethodDeclaration", "MethodDefOrRef"))),
    0x1A: ("ModuleRef", (("Name", "S"),)),
    0x1B: ("TypeSpec", (("Signature", "B"),)),
    0x1C: ("ImplMap", (("MappingFlags", "H"), ("MemberForwarded", "MemberForwarded"), ("ImportName", "S"), ("ImportScope", 0x1A))),
    0x1D: ("FieldRVA", (("RVA", "I"), ("Field", 0x04))),
    0x1E: ("EncLog", (("Token", "I"), ("FuncCode", "I"))),
    0x1F: ("EncMap", (("Token", "I"),)),
    0x20: ("Assembly", (("HashAlgId", "I"), ("MajorVersion", "H"), ("MinorVersion", "H"), ("BuildNumber", "H"), ("RevisionNumber", "H"),
                        ("Flags", "I"), ("PublicKey", "B"), ("Name", "S"), ("Culture", "S"))),
    0x21: ("AssemblyProcessor", (("Processor", "I"),)),
    0x22: ("AssemblyOS", (("OSPlatformID", "I"), ("OSMajorVersion", "I"), ("OSMinorVersion", "I"))),
    0x23: ("AssemblyRef", (("MajorVersion", "H"), ("MinorVersion", "H"), ("BuildNumber", "H"), ("RevisionNumber", "H"), ("Flags", "I"),
                           ("PublicKeyOrToken", "B"), ("Name", "S"), ("Culture", "S"), ("HashValue", "B"))),
    0x24: ("AssemblyRefProcessor", (("Processor", "I"), ("AssemblyRef", 0x23))),
    0x25: ("AssemblyRefOS", (("OSPlatformID", "I"), ("OSMajorVersion", "I"), ("OSMinorVersion", "I"), ("AssemblyRef", 0x23))),
    0x26: ("File", (("Flags", "I"), ("Name", "S"), ("HashValue", "B"))),
    0x27: ("ExportedType", (("Flags", "I"), ("TypeDefId", "I"), ("TypeName", "S"), ("TypeNamespace", "S"), ("Implementation", "Implementation"))),
    0x28: ("ManifestResource", (("Offset", "I"), ("Flags", "I"), ("Name", "S"), ("Implementation", "Implementation"))),
    0x29: ("NestedClass", (("NestedClass", 0x02), ("EnclosingClass", 0x02))),
    0x2A: ("GenericParam", (("Number", "H"), ("Flags", "H"), ("Owner", "TypeOrMethodDef"), ("Name", "S"))),
    0x2B: ("MethodSpec", (("Method", "MethodDefOrRef"), ("Instantiation", "B"))),
    0x2C: ("GenericParamConstraint", (("Owner", 0x2A), ("Constraint", "TypeDefOrRef"))),
}
TABLE = {name: number for number, (name, _) in SCHEMA.items()}
# name -> (tag bits, the table of each tag; None for a tag the specification leaves unused). II.24.2.6.
CODED = {
    "TypeDefOrRef": (2, (0x02, 0x01, 0x1B)),
    "HasConstant": (2, (0x04, 0x08, 0x17)),
    "HasCustomAttribute": (5, (0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E, 0x17, 0x14, 0x11, 0x1A, 0x1B, 0x20, 0x23, 0x26,
                               0x27, 0x28, 0x2A, 0x2C, 0x2B)),
    "HasFieldMarshal": (1, (0x04, 0x08)),
    "HasDeclSecurity": (2, (0x02, 0x06, 0x20)),
    "MemberRefParent": (3, (0x02, 0x01, 0x1A, 0x06, 0x1B)),
    "HasSemantics": (1, (0x14, 0x17)),
    "MethodDefOrRef": (1, (0x06, 0x0A)),
    "MemberForwarded": (1, (0x04, 0x06)),
    "Implementation": (2, (0x26, 0x23, 0x27)),
    "CustomAttributeType": (3, (None, None, 0x06, 0x0A, None)),
    "ResolutionScope": (2, (0x00, 0x1A, 0x23, 0x01)),
    "TypeOrMethodDef": (1, (0x02, 0x06)),
}


@functools.lru_cache(maxsize=8)
def _tables(d: bytes):
    """The #~ stream's header and the place of every table the schema knows: None and () as _clr,
    else a dict. `layout` holds a table only when every table before it is in the schema, so a
    table of a later specification costs the rows behind it and nothing else."""
    c = _clr(d)
    if not c:
        return c
    hits = [(at, size) for name, at, size, _ in c["streams"] if name in ("#~", "#-")]
    if len(hits) != 1:
        U("no tables stream, or more than one")
    t, size = hits[0]
    if size < 24:
        U("a tables stream shorter than its header")
    _reserved, major, minor, heap, _rid = struct.unpack_from("<IBBBB", d, t)
    valid, sorted_ = struct.unpack_from("<QQ", d, t + 8)
    present = [i for i in range(64) if valid >> i & 1]
    p = t + 24
    if p + 4 * len(present) > t + size:
        U("a tables stream that ends inside its row counts")
    rows = {i: struct.unpack_from("<I", d, p + 4 * k)[0] for k, i in enumerate(present)}
    p += 4 * len(present) + (4 if heap & 0x40 else 0)

    def width(kind):
        if kind in ("H", "I"):
            return 2 if kind == "H" else 4
        if kind in ("S", "G", "B"):
            return 4 if heap & {"S": 1, "G": 2, "B": 4}[kind] else 2
        if isinstance(kind, int):
            return 4 if rows.get(kind, 0) > 0xFFFF else 2
        bits, tabs = CODED[kind]
        return 4 if max(rows.get(tab, 0) for tab in tabs if tab is not None) >= 1 << (16 - bits) else 2
    layout = {}
    for i in present:
        if i not in SCHEMA:
            break
        cols, o = [], 0
        for name, kind in SCHEMA[i][1]:
            cols.append((name, o, width(kind)))
            o += cols[-1][2]
        if p + o * rows[i] > t + size:
            U("a table that runs past the tables stream")
        layout[i] = (p, o, cols)
        p += o * rows[i]
    return {"clr": c, "version": (major, minor), "heap": heap, "valid": valid, "sorted": sorted_, "present": present, "rows": rows,
            "layout": layout, "strings": _stream(c, "#Strings"), "guid": _stream(c, "#GUID"), "blob": _stream(c, "#Blob")}


def _row(d: bytes, t: dict, table: int, n: int) -> dict:
    """Row n (from 1) of a table as {column: number}."""
    if not 1 <= n <= t["rows"].get(table, 0):
        U(f"no row {n} in the {SCHEMA[table][0]} table")
    if table not in t["layout"]:
        U(f"the {SCHEMA[table][0]} table lies behind a table this reader has no schema for")
    p, size, cols = t["layout"][table]
    at = p + (n - 1) * size
    return {name: int.from_bytes(d[at + o:at + o + w], "little") for name, o, w in cols}


def _rows(d: bytes, t: dict, table: int) -> list:
    count = t["rows"].get(table, 0)
    if count > LIMIT:
        U(f"more {SCHEMA[table][0]} rows than are read into a list")
    return [_row(d, t, table, n) for n in range(1, count + 1)]


def _only(d: bytes, t: dict, table: int):
    """The one row of a table that has one row by its definition (Module, Assembly); None for none."""
    count = t["rows"].get(table, 0)
    if count > 1:
        U(f"{count} rows in the {SCHEMA[table][0]} table")
    return _row(d, t, table, 1) if count else None


def _string(d: bytes, t: dict, index: int) -> str:
    heap = t["strings"]
    if not index:
        return ""
    if heap is None or index >= heap[1]:
        U("a name outside the #Strings heap")
    end = d.find(b"\x00", heap[0] + index, heap[0] + heap[1])
    if end < 0:
        U("a name that does not end in its heap")
    return RM.text(d[heap[0] + index:end])


def _blob(d: bytes, t: dict, index: int) -> bytes:
    heap = t["blob"]
    if not index:
        return b""
    if heap is None or index >= heap[1]:
        U("a value outside the #Blob heap")
    length, p = _compressed(d, heap[0] + index, heap[0] + heap[1])
    if p + length > heap[0] + heap[1]:
        U("a value that runs past the #Blob heap")
    return bytes(d[p:p + length])


def _guid(d: bytes, t: dict, index: int):
    """The 16 bytes of a #GUID heap entry (indexes count from 1); None for the index 0."""
    heap = t["guid"]
    if not index:
        return None
    if heap is None or index * 16 > heap[1]:
        U("a GUID index outside the #GUID heap")
    return bytes(d[heap[0] + (index - 1) * 16:heap[0] + index * 16])


def _coded(kind: str, value: int):
    """(table number, row) of a coded index; (None, 0) for the null reference."""
    bits, tabs = CODED[kind]
    tag, row = value & ((1 << bits) - 1), value >> bits
    if not row:
        return None, 0
    if tag >= len(tabs) or tabs[tag] is None:
        U("a coded index with a tag the specification does not use")
    return tabs[tag], row


def of_tables(get, unmanaged=None):
    """An extractor over the tables: get(data, tables)."""
    def fn(n, d):
        t = _tables(d)
        return t if t is None else (unmanaged if t == () else get(d, t))
    return fn


def snake(name: str) -> str:
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()


def _mvid_bytes(d: bytes, t: dict):
    row = _only(d, t, TABLE["Module"])
    if row is None:
        U("no Module row")
    g = _guid(d, t, row["Mvid"])
    if g is None:
        U("a Module row with no Mvid")
    return g


def mvid(n, d):
    """Day 12's dotnet.mvid_guid: the Module table's Mvid as canonical lowercase GUID text
    (8-4-4-4-12), read from the #GUID heap entry the one Module row points at."""
    return of_tables(lambda d, t: str(uuidlib.UUID(bytes_le=_mvid_bytes(d, t))))(n, d)


@section
def _reg_module():
    # The judged name, under the ledger's own key (see the docstring): class text, form `raw`.
    if JUDGED not in M.REG:
        M.prop(JUDGED, fmt="text")(held(mvid))
    MINE["mvid_guid"] = (lambda n, d: (lambda v: None if v is None else v.replace("-", ""))(held(mvid)(n, d)), "uuid")
    reg(["mvid", "module_mvid", "module_version_id", "module_mvid_guid", "module_version_id_guid", "mvid_uuid", "module_guid",
         "module_table_mvid", "module_version_guid"], "uuid",
        of_tables(lambda d, t: uuidlib.UUID(bytes_le=_mvid_bytes(d, t)).hex))
    # The 16 bytes as the heap stores them (the first three fields little-endian), then the digits as written.
    # (`bytes` is a unit word to synonym(), so no name here is another reader's name plus `bytes`.)
    reg(["mvid_hex", "mvid_bytes_hex", "mvid_raw", "mvid_raw_bytes", "mvid_raw_hex"], "forms",
        of_tables(lambda d, t: [("bytes", _mvid_bytes(d, t).hex()), ("compact_lower", uuidlib.UUID(bytes_le=_mvid_bytes(d, t)).hex)]))
    reg(["mvid_guid_upper", "mvid_upper", "mvid_guid_uppercase", "mvid_uppercase", "module_version_id_upper"], "forms",
        of_tables(lambda d, t: (lambda g: [("hyphen_upper", str(g).upper()), ("compact_upper", g.hex.upper())])(
            uuidlib.UUID(bytes_le=_mvid_bytes(d, t)))))
    reg(["mvid_guid_index", "module_mvid_index", "mvid_index"], "integer",
        of_tables(lambda d, t: (lambda r: None if r is None else r["Mvid"])(_only(d, t, TABLE["Module"]))))

    def module(col):
        return of_tables(lambda d, t: (lambda r: None if r is None else _string(d, t, r[col]) or None)(_only(d, t, TABLE["Module"])))
    reg(["module_name", "module", "module_table_name", "module_file_name", "manifest_module_name"], "text", module("Name"))
    reg(["module_generation"], "integer",
        of_tables(lambda d, t: (lambda r: None if r is None else r["Generation"])(_only(d, t, TABLE["Module"]))))
    reg(["tables_stream_version", "metadata_tables_version", "table_schema_version", "tables_header_version", "metadata_table_version"],
        "dotted", of_tables(lambda d, t: t["version"]))
    reg(["heap_sizes", "tables_heap_sizes", "tables_stream_heap_sizes", "heap_size_flags"], "number", of_tables(lambda d, t: t["heap"]),
        bits=8)
    reg(["table_count", "metadata_table_count", "present_table_count", "tables_present_count", "number_of_tables"], "integer",
        of_tables(lambda d, t: len(t["present"])))
    reg(["table_names", "metadata_table_names", "present_table_names", "present_tables", "metadata_tables_present"], "list",
        of_tables(lambda d, t: [SCHEMA[i][0] if i in SCHEMA else U("a table the specification does not name") for i in t["present"]] or None))
    reg(["tables_valid_mask", "valid_mask", "metadata_tables_valid", "tables_valid", "valid_tables_mask"], "number",
        of_tables(lambda d, t: t["valid"]), bits=64)
    reg(["tables_sorted_mask", "sorted_mask", "metadata_tables_sorted", "tables_sorted"], "number", of_tables(lambda d, t: t["sorted"]),
        bits=64)

    # The row count of each table: dotnet.<table>_count, _row_count, _rows, _table_row_count, ... A
    # table the file does not have has no rows: 0, never none.
    spell = {}
    for number, (name, _) in SCHEMA.items():
        for s in {snake(name), name.lower()}:
            spell[s] = number
    more = {"type_definition": 0x02, "type_reference": 0x01, "method_definition": 0x06, "method": 0x06, "member_reference": 0x0A,
            "assembly_reference": 0x23, "referenced_assembly": 0x23, "module_reference": 0x1A, "managed_resource": 0x28,
            "embedded_resource": 0x28, "resource": 0x28, "parameter": 0x08, "exported_type": 0x27, "generic_parameter": 0x2A}
    spell.update({k: v for k, v in more.items() if k not in spell})
    words = "|".join(sorted(spell, key=len, reverse=True))

    @M.family(rf"{NS}_(?:metadata_)?({words})(?:_table)?_(?:row_count|rows_count|count|rows|num_rows|number_of_rows|entry_count)", "integer")
    @held
    def _count(n, d, word):
        t = _tables(d)
        return None if not t else t["rows"].get(spell[word], 0)

    @M.family(rf"{NS}_(?:number_of|num)_({words})(?:s|es|_rows|_entries)", "integer")
    @held
    def _number_of(n, d, word):
        return _count(n, d, word)
    for word in spell:
        MINE[f"{word}_count"] = MINE[f"{word}_row_count"] = (lambda n, d, word=word: _count(n, d, word), "integer")

    def names(table, *cols, full=False):
        def get(d, t):
            out = []
            for r in _rows(d, t, table):
                parts = [_string(d, t, r[c]) for c in cols]
                if full:
                    parts = [".".join(p for p in parts if p)]
                if not parts[-1]:
                    U("a row without a name")
                out.append(parts[-1])
            return out or None
        return of_tables(get)
    reg(["typedef_names", "type_def_names", "type_definition_names", "typedef_table_names"], "list", names(0x02, "TypeName"))
    reg(["typedef_full_names", "type_def_full_names", "type_definition_full_names", "typedef_qualified_names"], "list",
        names(0x02, "TypeNamespace", "TypeName", full=True))
    reg(["typeref_names", "type_ref_names", "type_reference_names", "typeref_table_names"], "list", names(0x01, "TypeName"))
    reg(["typeref_full_names", "type_ref_full_names", "type_reference_full_names", "typeref_qualified_names", "referenced_type_names"],
        "list", names(0x01, "TypeNamespace", "TypeName", full=True))
    reg(["methoddef_names", "method_def_names", "method_names", "method_definition_names", "methoddef_table_names"], "list",
        names(0x06, "Name"))
    reg(["memberref_names", "member_ref_names", "member_reference_names", "memberref_table_names"], "list", names(0x0A, "Name"))
    reg(["moduleref_names", "module_ref_names", "module_reference_names", "referenced_module_names", "pinvoke_module_names"], "list",
        names(0x1A, "Name"))
    reg(["field_names", "field_table_names"], "list", names(0x04, "Name"))
    reg(["manifest_resource_names", "managed_resource_names", "resource_names", "embedded_resource_names", "manifestresource_names",
         "managed_resources", "manifest_resources"], "list", names(0x28, "Name"))
    reg(["exported_type_names", "exportedtype_names"], "list", names(0x27, "TypeName"))
    reg(["file_names", "file_table_names", "assembly_file_names"], "list", names(0x26, "Name"))

    def entry_method(d, t):
        c = t["clr"]
        if c["flags"] & 0x10:
            U("the entry point is a native RVA, not a metadata token")
        if not c["entry"]:
            return None
        if c["entry"] >> 24 != 0x06:
            U("an entry point token that names no method of this module")
        return _string(d, t, _row(d, t, 0x06, c["entry"] & 0xFFFFFF)["Name"]) or None
    reg(["entry_point_method", "entry_point_method_name", "entry_point_name", "managed_entry_point", "entry_method_name",
         "managed_entry_point_method"], "text", of_tables(entry_method))


# ------------------------------------------------------------------ the Assembly and AssemblyRef tables

HASH_ALGORITHMS = {0x0000: "None", 0x8003: "MD5", 0x8004: "SHA1", 0x800C: "SHA256", 0x800D: "SHA384", 0x800E: "SHA512"}


def _version(r: dict) -> tuple:
    return r["MajorVersion"], r["MinorVersion"], r["BuildNumber"], r["RevisionNumber"]


def _quad(parts) -> list:
    return [("dotted", ".".join(map(str, parts))), ("comma", ",".join(map(str, parts)))]


def _token(key: bytes) -> str:
    """The public key token of a public key: the last eight bytes of its SHA-1, reversed (II.6.3)."""
    return hashlib.sha1(key).digest()[-8:][::-1].hex()


def of_assembly(get):
    """An extractor over the Assembly row: None for a module with no assembly manifest."""
    return of_tables(lambda d, t: (lambda r: None if r is None else get(d, t, r))(_only(d, t, TABLE["Assembly"])))


@section
def _reg_assembly():
    reg(["assembly_name", "assembly", "assembly_table_name", "assembly_simple_name", "assembly_definition_name", "assembly_short_name"],
        "text", of_assembly(lambda d, t, r: _string(d, t, r["Name"]) or None))
    reg(["assembly_version", "assembly_table_version", "assembly_definition_version", "assembly_version_number", "assembly_identity_version",
         "assembly_version_string", "assembly_version_dotted"],
        "forms", of_assembly(lambda d, t, r: _quad(_version(r))))
    for col, spellings in (("MajorVersion", ("major_version", "version_major")), ("MinorVersion", ("minor_version", "version_minor")),
                           ("BuildNumber", ("build_number", "version_build", "build_version")),
                           ("RevisionNumber", ("revision_number", "version_revision", "revision_version"))):
        reg([f"assembly_{s}" for s in spellings], "integer", of_assembly(lambda d, t, r, col=col: r[col]))

    def culture(d, t, r):
        value = _string(d, t, r["Culture"])
        if not value:   # the invariant culture: written as nothing, called neutral
            raise M.Ambiguous([("neutral", "neutral"), (M.ABSENT, M.NONE)])
        return value
    reg(["assembly_culture", "assembly_locale", "assembly_table_culture", "culture", "assembly_culture_name"], "text", of_assembly(culture))
    reg(["assembly_public_key", "public_key", "assembly_table_public_key", "assembly_public_key_hex", "assembly_public_key_blob"], "hex",
        of_assembly(lambda d, t, r: _blob(d, t, r["PublicKey"]).hex() or None))
    reg(["assembly_public_key_length", "assembly_public_key_size", "public_key_length", "public_key_size", "assembly_public_key_size_bytes",
         "assembly_public_key_length_bytes"], "integer", of_assembly(lambda d, t, r: len(_blob(d, t, r["PublicKey"]))))
    reg(["assembly_public_key_token", "public_key_token", "assembly_token", "assembly_public_key_token_hex", "strong_name_token",
         "assembly_strong_name_token"], "hex", of_assembly(lambda d, t, r: (lambda k: _token(k) if k else None)(_blob(d, t, r["PublicKey"]))))
    reg(["assembly_has_public_key", "has_public_key", "assembly_public_key_present", "assembly_flag_public_key", "assembly_is_strong_named"],
        "bool", of_assembly(lambda d, t, r: bool(_blob(d, t, r["PublicKey"]))))
    reg(["assembly_hash_algorithm", "assembly_hash_alg_id", "hash_algorithm", "assembly_hash_algorithm_id", "hash_alg_id",
         "assembly_table_hash_alg_id", "assembly_hash_alg"], "code",
        of_assembly(lambda d, t, r: (HASH_ALGORITHMS.get(r["HashAlgId"]), r["HashAlgId"])))
    reg(["assembly_flags", "assembly_table_flags", "assembly_definition_flags"], "number", of_assembly(lambda d, t, r: r["Flags"]), bits=32)

    def refs(get):
        def read(d, t):
            return [get(d, t, r) for r in _rows(d, t, TABLE["AssemblyRef"])] or None
        return of_tables(read)

    def ref_name(d, t, r):
        return _string(d, t, r["Name"]) or U("an assembly reference without a name")
    reg(["assembly_ref_names", "assemblyref_names", "referenced_assemblies", "referenced_assembly_names", "assembly_reference_names",
         "assembly_references", "assembly_refs", "assemblyref_table_names", "assemblyrefs"], "list", refs(ref_name))
    reg(["assembly_ref_versions", "assemblyref_versions", "referenced_assembly_versions", "assembly_reference_versions"], "list",
        refs(lambda d, t, r: ".".join(map(str, _version(r)))))
    # Each reference as the runtime's display name begins: `System.Runtime, Version=8.0.0.0`.
    reg(["assembly_ref_names_and_versions", "assemblyref_names_and_versions", "assembly_ref_display_names",
         "referenced_assemblies_with_versions", "assembly_reference_names_and_versions"], "list",
        refs(lambda d, t, r: f"{ref_name(d, t, r)}, Version={'.'.join(map(str, _version(r)))}"))

    def ref_token(d, t, r):
        blob = _blob(d, t, r["PublicKeyOrToken"])
        if not blob:
            U("an assembly reference with no public key token")
        if r["Flags"] & 1:   # the reference holds the whole public key
            return _token(blob)
        if len(blob) != 8:
            U("a public key token that is not eight bytes")
        return blob.hex()
    reg(["assembly_ref_public_key_tokens", "assemblyref_public_key_tokens", "referenced_assembly_public_key_tokens",
         "assembly_reference_public_key_tokens", "assembly_ref_tokens"], "list", refs(ref_token))
    for which, label in ((0, "first"), (-1, "last")):
        def at(get, which=which):
            def read(d, t):
                rows = _rows(d, t, TABLE["AssemblyRef"])
                return get(d, t, rows[which]) if rows else None
            return of_tables(read)
        reg([f"{label}_assembly_ref_name", f"{label}_assemblyref_name", f"{label}_referenced_assembly_name"], "text", at(ref_name))
        reg([f"{label}_assembly_ref_version", f"{label}_assemblyref_version", f"{label}_referenced_assembly_version"], "forms",
            at(lambda d, t, r: _quad(_version(r))))


# ------------------------------------------------------------------ the assembly's custom attributes

# (namespace, type) -> the names its one string argument is asked by, after `assembly_` or alone.
ATTRIBUTES = {
    ("System.Reflection", "AssemblyTitleAttribute"): ("title",),
    ("System.Reflection", "AssemblyDescriptionAttribute"): ("description",),
    ("System.Reflection", "AssemblyConfigurationAttribute"): ("configuration",),
    ("System.Reflection", "AssemblyCompanyAttribute"): ("company", "company_name"),
    ("System.Reflection", "AssemblyProductAttribute"): ("product", "product_name"),
    ("System.Reflection", "AssemblyCopyrightAttribute"): ("copyright",),
    ("System.Reflection", "AssemblyTrademarkAttribute"): ("trademark",),
    ("System.Reflection", "AssemblyFileVersionAttribute"): ("file_version",),
    ("System.Reflection", "AssemblyInformationalVersionAttribute"): ("informational_version",),
    ("System.Reflection", "AssemblyDefaultAliasAttribute"): ("default_alias",),
    ("System.Runtime.Versioning", "TargetFrameworkAttribute"): ("target_framework", "target_framework_name", "target_framework_moniker"),
    ("System.Runtime.InteropServices", "GuidAttribute"): ("guid_attribute", "com_guid", "typelib_guid"),
}
CTOR_STRING = b"\x20\x01\x01\x0e"   # a signature blob: HASTHIS, one parameter, returns void, takes string


@functools.lru_cache(maxsize=4)
def _attributes(d: bytes):
    """[((namespace, type name), constructor signature, value blob)] of the custom attributes on
    the Assembly row, in table order; None and () as _clr."""
    t = _tables(d)
    if not t:
        return t
    if not t["rows"].get(TABLE["Assembly"], 0) or not t["rows"].get(0x0C, 0):
        return []
    if t["rows"].get(0x05, 0):
        U("a MethodPtr table: the methods are not in the TypeDef table's order")
    out, typedefs = [], None
    for r in _rows(d, t, 0x0C):
        if _coded("HasCustomAttribute", r["Parent"]) != (TABLE["Assembly"], 1):
            continue
        table, row = _coded("CustomAttributeType", r["Type"])
        if table == 0x0A:
            ctor = _row(d, t, 0x0A, row)
            owner, owner_row = _coded("MemberRefParent", ctor["Class"])
            if owner not in (0x01, 0x02):
                U("an attribute constructor that belongs to no named type")
        elif table == 0x06:
            ctor = _row(d, t, 0x06, row)
            if typedefs is None:
                typedefs = _rows(d, t, 0x02)
            owners = [i + 1 for i, td in enumerate(typedefs) if td["MethodList"] <= row]
            if not owners:
                U("an attribute constructor that no type owns")
            owner, owner_row = 0x02, owners[-1]
        else:
            U("an attribute with no constructor")
        if _string(d, t, ctor["Name"]) != ".ctor":
            U("an attribute whose constructor is not a constructor")
        kind = _row(d, t, owner, owner_row)
        out.append(((_string(d, t, kind["TypeNamespace"]), _string(d, t, kind["TypeName"])), _blob(d, t, ctor["Signature"]),
                    _blob(d, t, r["Value"])))
    return out


def _ser_string(blob: bytes, p: int):
    """(text or None for the null string, the place after it) of a SerString (II.23.3)."""
    if p < len(blob) and blob[p] == 0xFF:
        return None, p + 1
    length, p = _compressed(blob, p, len(blob))
    if p + length > len(blob):
        U("an attribute string that runs past its value")
    return RM.text(blob[p:p + length]), p + length


def _string_attribute(d: bytes, kind: tuple):
    """(the one string argument, the value blob, the place after the argument) of the assembly's one
    attribute of this type; None when it has none. The constructor must take exactly (string)."""
    attrs = _attributes(d)
    if not attrs:
        return None
    hits = [a for a in attrs if a[0] == kind]
    if len(hits) > 1:
        U(f"several {kind[1]} attributes")
    if not hits:
        return None
    _, signature, value = hits[0]
    if signature != CTOR_STRING:
        U(f"a {kind[1]} constructor that does not take one string")
    if value[:2] != b"\x01\x00":
        U("an attribute value without its prolog")
    text, p = _ser_string(value, 2)
    return text, value, p


@section
def _reg_attributes():
    def fixed(kind):
        def fn(n, d):
            hit = _string_attribute(d, kind)
            if hit is None:
                return None
            text, value, p = hit
            if p + 2 > len(value):
                U("an attribute value that ends before its named arguments")
            return text
        return fn
    for kind, spellings in ATTRIBUTES.items():
        names = []
        for s in spellings:
            names += [s, f"assembly_{s}", f"{s}_attribute", f"assembly_{s}_attribute", f"attribute_{s}", f"assembly_attribute_{s}"]
        names += [snake(kind[1]), snake(kind[1][:-len("Attribute")])]
        reg([n for n in dict.fromkeys(names) if not n.endswith("attribute_attribute")], "text", fixed(kind))

    def display_name(n, d):
        """The FrameworkDisplayName named argument of TargetFrameworkAttribute: a string property."""
        hit = _string_attribute(d, ("System.Runtime.Versioning", "TargetFrameworkAttribute"))
        if hit is None:
            return None
        _, value, p = hit
        count = struct.unpack_from("<H", value, p)[0]
        p, found = p + 2, []
        for _ in range(count):
            if p + 2 > len(value) or value[p] not in (0x53, 0x54) or value[p + 1] != 0x0E:
                U("a named argument that is not a string")
            name, p = _ser_string(value, p + 2)
            text, p = _ser_string(value, p)
            if name == "FrameworkDisplayName":
                found.append(text)
        if p != len(value) or len(found) > 1:
            U("named arguments that are not read to their end, or one name twice")
        return found[0] if found else None
    reg(["target_framework_display_name", "framework_display_name", "assembly_target_framework_display_name",
         "target_framework_attribute_display_name"], "text", display_name)

    def kinds(n, d):
        attrs = _attributes(d)
        return attrs if attrs is None or attrs == () else [a[0][1] or U("an attribute type without a name") for a in attrs]
    reg(["assembly_attribute_names", "assembly_custom_attribute_names", "assembly_attributes", "assembly_custom_attributes",
         "assembly_attribute_types", "assembly_custom_attribute_types", "assembly_attribute_type_names"], "list",
        lambda n, d: kinds(n, d) or None)
    reg(["assembly_attribute_count", "assembly_custom_attribute_count", "assembly_attributes_count"], "integer",
        lambda n, d: (lambda k: None if k is None or k == () else len(k))(kinds(n, d)))


# ------------------------------------------------------------------ the debug directory's CodeView record

@section
def _reg_debug():
    def codeview(get):
        def fn(n, d):
            if not _clr(d):
                return None
            c = RM._pe_codeview(d)
            return None if not c else get(c)
        return fn
    reg(["pdb_path", "debug_pdb_path", "codeview_pdb_path", "pdb_file_name", "pdb_file_path", "codeview_path"], "text",
        codeview(lambda c: c[2] or None))
    reg(["pdb_guid", "debug_pdb_guid", "codeview_guid", "pdb_signature", "debug_directory_codeview_guid", "rsds_guid", "pdb_id_guid",
         "debug_guid"], "uuid", codeview(lambda c: c[0]))
    reg(["pdb_age", "debug_pdb_age", "codeview_age", "debug_directory_codeview_age", "rsds_age"], "integer", codeview(lambda c: c[1]))
    reg(["codeview_present", "has_codeview", "pdb_reference_present", "has_pdb_path", "codeview_record_present"], "bool",
        lambda n, d: (lambda c: None if c is None else bool(c))(RM._pe_codeview(d) if _clr(d) else None))


# ------------------------------------------------------------------ B-222: the other entries of the debug directory

# IMAGE_DEBUG_TYPE_<name> (PE/COFF specification; 17 and 19 by the portable PDB specification).
DEBUG_TYPES = {0: "UNKNOWN", 1: "COFF", 2: "CODEVIEW", 3: "FPO", 4: "MISC", 5: "EXCEPTION", 6: "FIXUP", 7: "OMAP_TO_SRC",
               8: "OMAP_FROM_SRC", 9: "BORLAND", 10: "RESERVED10", 11: "CLSID", 12: "VC_FEATURE", 13: "POGO", 14: "ILTCG",
               15: "MPX", 16: "REPRO", 17: "EMBEDDED_PORTABLE_PDB", 18: "SPGO", 19: "PDBCHECKSUM", 20: "EX_DLLCHARACTERISTICS"}
REPRO, EMBEDDED_PDB, PDB_CHECKSUM = 16, 17, 19
DEBUG_ENTRIES = 64


def _debug(d: bytes):
    """[(type, SizeOfData, PointerToRawData)] of the debug directory's entries in their order: None
    when the file is not a managed PE (the dotnet.* names say nothing of a native one), [] when the
    header names no debug directory."""
    if not _clr(d):
        return None
    x = RM._pex(d)
    if len(x["dirs"]) <= 6 or not x["dirs"][6][1]:
        return []
    rva, size = x["dirs"][6]
    if size % 28:
        U("a debug directory that is not a whole number of entries")
    if size // 28 > DEBUG_ENTRIES:
        U("more debug entries than are read")
    at = _off(x, d, rva, size)
    out = []
    for i in range(size // 28):
        typ, sz, _rva, ptr = struct.unpack_from("<IIII", d, at + 28 * i + 12)
        if sz and ptr + sz > len(d):
            U("a debug entry whose data runs past the file")
        out.append((typ, sz, ptr))
    return out


def _debug_data(d: bytes, typ: int):
    """The data of the one debug entry of this type: None when there is none, Unknown for two."""
    hits = [(sz, ptr) for t, sz, ptr in _debug(d) or () if t == typ]
    if len(hits) > 1:
        U(f"two {DEBUG_TYPES[typ]} debug entries")
    if not hits:
        return None
    sz, ptr = hits[0]
    return bytes(d[ptr:ptr + sz])


@section
def _reg_debug_entries():
    def over(get):
        def fn(n, d):
            entries = _debug(d)
            return None if entries is None else get(d, entries)
        return fn

    def names(d, entries):
        if any(t not in DEBUG_TYPES for t, _, _ in entries):
            U("a debug entry of a type the specification does not name")
        return [DEBUG_TYPES[t] for t, _, _ in entries] or None
    reg(["debug_types", "debug_directory_types", "debug_entry_types", "debug_directory_entry_types", "debug_type_names"], "list",
        over(names))
    reg(["debug_entry_count", "debug_directory_entry_count", "debug_directory_count", "number_of_debug_entries"], "integer",
        over(lambda d, e: len(e)))
    # A deterministic build (Roslyn /deterministic, the SDK's default) writes a Repro entry.
    reg(["is_deterministic", "deterministic", "deterministic_build", "is_reproducible", "reproducible", "has_repro_entry",
         "repro_entry_present", "repro_present", "has_repro_debug_entry", "repro_debug_entry_present"], "bool",
        over(lambda d, e: any(t == REPRO for t, _, _ in e)))

    def repro_hash(d, entries):
        data = _debug_data(d, REPRO)
        if not data:   # no entry, or one with no data: a build that wrote no hash
            return None
        if len(data) < 4 or struct.unpack_from("<I", data)[0] != len(data) - 4 or len(data) == 4:
            U("a Repro entry whose data is not a length and that many bytes of hash")
        return data[4:].hex()
    reg(["repro_hash", "repro_entry_hash", "deterministic_hash", "repro_hash_hex", "repro_debug_hash"], "hex", over(repro_hash))

    def checksum(d, entries):
        data = _debug_data(d, PDB_CHECKSUM)
        if data is None:
            return None
        end = data.find(b"\x00")
        if end <= 0 or end + 1 >= len(data):
            U("a PdbChecksum entry without an algorithm name and a checksum")
        return RM.text(data[:end]), data[end + 1:].hex()
    reg(["pdb_checksum_algorithm", "pdb_checksum_algorithm_name", "pdbchecksum_algorithm"], "text",
        over(lambda d, e: (lambda c: None if c is None else c[0])(checksum(d, e))))
    reg(["pdb_checksum", "pdb_checksum_hex", "pdbchecksum", "pdb_checksum_value"], "hex",
        over(lambda d, e: (lambda c: None if c is None else c[1])(checksum(d, e))))
    reg(["has_embedded_pdb", "embedded_pdb_present", "embedded_portable_pdb_present", "has_embedded_portable_pdb"], "bool",
        over(lambda d, e: any(t == EMBEDDED_PDB for t, _, _ in e)))


# ------------------------------------------------------------------ B-222: namespaces

@section
def _reg_namespaces():
    def namespaces(table):
        def get(d, t):
            seen = []
            for r in _rows(d, t, table):
                ns = _string(d, t, r["TypeNamespace"])
                if ns and ns not in seen:
                    seen.append(ns)
            return seen
        return get
    defined, referenced = namespaces(0x02), namespaces(0x01)
    reg(["namespaces", "typedef_namespaces", "type_namespaces", "defined_namespaces", "type_def_namespaces",
         "type_definition_namespaces", "namespace_names", "namespace_list"], "list", of_tables(lambda d, t: defined(d, t) or None))
    reg(["namespace_count", "typedef_namespace_count", "number_of_namespaces", "defined_namespace_count"], "integer",
        of_tables(lambda d, t: len(defined(d, t))))
    reg(["typeref_namespaces", "type_ref_namespaces", "referenced_namespaces", "type_reference_namespaces", "imported_namespaces"],
        "list", of_tables(lambda d, t: referenced(d, t) or None))


# ------------------------------------------------------------------ B-222: a .NET single-file bundle

_INTAKE = []


def _intake():
    """B-054's decompile_intake, loaded once by its exact file (`generic` and others exist in more than one
    lane, so never a flat import). A missing file raises ModuleNotFoundError naming it."""
    if not _INTAKE:
        from _shadowed import module_at   # solvers/common: on the lane's path (properties_strict puts it there)
        _INTAKE.append(module_at(INTAKE, "binary_decompile_intake"))
    return _INTAKE[0]


def _bundle(d: bytes):
    """B-054's manifest of a .NET single-file bundle (facts.dotnet_bundle), None for a file that is not
    an executable carrying one."""
    if not isinstance(d, bytes) or not d.startswith(EXEC_HEADS):
        return None
    facts = _intake()._runtime_facts()
    if facts.BUNDLE_SIG not in d:
        return None
    return facts.dotnet_bundle(d)


def _base(path: str) -> str:
    return path.replace("\\", "/").rsplit("/", 1)[-1]


def _bundle_entry(info: dict) -> dict:
    """The manifest entry of the bundle's application assembly: the one named by its deps.json /
    runtimeconfig.json (<app>.deps.json names <app>.dll), else its one application assembly (not a
    framework assembly, not a satellite .resources.dll). Unknown where that is not one file."""
    framework = _intake()._binary_generic().FRAMEWORK_DLL
    files = info["files"]
    stems = {re.sub(r"\.(?:deps|runtimeconfig)\.json$", "", _base(f["path"]), flags=re.I)
             for f in files if f["type"] in ("deps_json", "runtimeconfig_json")}
    if len(stems) > 1:
        U("a bundle whose deps.json and runtimeconfig.json name two applications")
    assemblies = [f for f in files if f["type"] == "assembly"]
    if stems:
        want = next(iter(stems)) + ".dll"
        hits = [f for f in assemblies if _base(f["path"]).lower() == want.lower()]
        if len(hits) != 1:
            U(f"a bundle whose deps.json names {want}, which it holds {len(hits)} times")
        return hits[0]
    own = [f for f in assemblies if not framework.fullmatch(_base(f["path"])) and not _base(f["path"]).lower().endswith(".resources.dll")]
    if len(own) != 1:
        U(f"a bundle with {len(own)} application assemblies and no deps.json or runtimeconfig.json naming one")
    return own[0]


@functools.lru_cache(maxsize=4)
def _bundled(d: bytes):
    """(the manifest entry, the bytes) of a single-file bundle's application assembly, None when the file
    carries no bundle. The bytes are B-054's bundle_members (it inflates a deflated member); a member it
    does not hand out (a stored one whose name looks like a framework assembly's) is the manifest's own
    slice of the file."""
    try:
        info = _bundle(d)
        if info is None:
            return None
        entry = _bundle_entry(info)
        body = dict(_intake().bundle_members(d)).get(entry["path"])
        if body is None and not entry["compressed"]:
            body = d[entry["offset"]:entry["offset"] + entry["size"]]
    except BUNDLE_PARSE_ERRORS as e:
        U(f"a bundle that does not read ({type(e).__name__})")
    if body is None or len(body) != entry["size"]:
        U("the bundle's application assembly is not taken out of it whole")
    return entry, body


def _subject(d):
    """The bytes a dotnet.* question about `d` is answered from: `d` itself, or, for an executable with no
    CLR header of its own that carries a single-file bundle, the bundle's application assembly."""
    if not isinstance(d, bytes) or not d.startswith(EXEC_HEADS):
        return d
    try:
        if _clr(d):
            return d
    except Exception:     # a PE that is cut or damaged: its own reader, under held(), says what is not settled
        return d
    hit = _bundled(d)
    if hit is None:
        return d
    try:
        managed = _clr(hit[1])
    except M.Unknown:
        raise
    except Exception as e:
        U(f"the bundle's application assembly does not read as a PE ({type(e).__name__})")
    if not managed:
        U("the bundle's application assembly has no CLR header")
    return hit[1]


@section
def _reg_bundle():
    def bundle(get):
        """An extractor over the bundle's manifest: None for a file that carries none."""
        def fn(n, d):
            info = _bundle(d)
            return None if info is None else get(d, info)
        return fn

    def is_bundle(n, d):
        """True for an executable carrying a bundle, False for another executable, None for a file that is no executable."""
        if not isinstance(d, bytes) or not d.startswith(EXEC_HEADS):
            return None
        return _bundle(d) is not None
    reg(["is_single_file_bundle", "single_file_bundle", "is_bundle", "bundle_present", "is_single_file", "has_bundle"], "bool",
        is_bundle, subject=False)
    reg(["bundle_entry_assembly", "bundle_main_assembly", "bundle_app_assembly", "bundle_application_assembly",
         "bundle_entry_assembly_name"], "text", bundle(lambda d, info: _bundle_entry(info)["path"]), subject=False)
    reg(["bundle_version", "bundle_header_version", "bundle_format_version"], "text", bundle(lambda d, info: info["version"]),
        subject=False)
    reg(["bundle_id", "bundle_identifier"], "text", bundle(lambda d, info: info["id"] or None), subject=False)
    reg(["bundle_file_count", "bundle_files_count", "bundle_member_count", "number_of_bundle_files"], "integer",
        bundle(lambda d, info: len(info["files"])), subject=False)
    reg(["bundle_file_names", "bundle_files", "bundle_member_names", "bundle_file_paths"], "list",
        bundle(lambda d, info: [f["path"] for f in info["files"]] or None), subject=False)


def read_mvid(data: bytes):
    """The Module table's Mvid as lowercase 8-4-4-4-12 text (Day 12's judged form), None where the bytes
    do not settle it: not a PE, no CLR header, a damaged structure. For callers outside the question
    path (speedrun/solvers/metadata_d12.py). The lane must be loaded: register() binds this file."""
    if M is None:
        raise RuntimeError("readers_dotnet.py is not registered: load the metadata lane (properties_strict) first")
    try:
        return held(mvid)("dotnet.mvid_guid", bytes(data))
    except (M.Unknown, M.Ambiguous):
        return None


# ------------------------------------------------------------------ registration

def register(module):
    global M, RM
    M = module
    RM = getattr(M, "MORE_MODULES", {}).get("readers_more.py")
    if RM is None:
        raise RuntimeError("readers_more.py is not loaded, and its PE parser is this file's")
    # B-054's decompile_intake is loaded on the first executable without a CLR header (_intake), not here: the
    # lane loads where the binary lane is not copied beside it (an ablated tree), and a bundle question there
    # raises ModuleNotFoundError naming the file rather than an Unknown.
    before = set(M.REG)
    families = len(M.FAMILIES)
    MINE.clear()
    for s in SECTIONS:
        s()
    M.NAMESPACES.add(NS)
    M.PACK_NAMESPACES.add(NS)
    M.CONTENT_TOKENS.update({NS, *NS_OTHER})
    M.RELATED.setdefault(NS, (NS,))
    M.NS_ALIAS.update({a: NS for a in NS_OTHER if a not in M.NS_ALIAS and a not in M.NAMESPACES})
    # The same readers under pe.dotnet_<name>, pe.clr_<name>, ...: one family per class, found by
    # lookup only when no pe.* name and no earlier family reads the name.
    by_class = {}
    for name, (fn, fmt) in MINE.items():
        by_class.setdefault(fmt, {})[name] = fn
    for fmt, fns in by_class.items():
        pattern = rf"pe_(?:{'|'.join(PE_PREFIXES)})_({'|'.join(sorted(map(re.escape, fns), key=len, reverse=True))})"
        M.family(pattern, fmt)(lambda n, d, name, fns=fns: fns[name](n, d))
        # ... and a name that says the runtime by itself needs no prefix: pe.clr_header_flags, pe.mvid.
        own = sorted((re.escape(x) for x in fns if x.startswith(PE_OWN)), key=len, reverse=True)
        if own:
            M.family(rf"pe_({'|'.join(own)})", fmt)(lambda n, d, name, fns=fns: fns[name](n, d))
    M.TIE_FREE.update(M.REG[k].fn for k in M.REG if k not in before)
    return len(M.REG) - len(before), len(M.FAMILIES) - families
