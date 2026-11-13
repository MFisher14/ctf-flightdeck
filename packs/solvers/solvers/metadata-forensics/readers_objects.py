#!/usr/bin/env python3
"""Metadata Forensics object-file pack (the Day 21 final prep): bare COFF objects and ar archives of objects.

properties_strict.py loads this file by name (MORE_FILES, after readers_macho.py) and calls register(M). The Day 21
look-ahead staged the object files a next `.bin`, `.o`, `.obj`, `.a` or `.lib` may be (stage.py, stage2.py beside
docs/retro/day21-prep-metadata/harness.py) and found, on the armed tree:

  - an ar archive of ELF ET_REL objects answered elf.e_machine_u16_hex None (the field is not in an archive);
  - a bare COFF object (.obj, or the same bytes as .bin) and a Windows .lib answered pe.coff_machine_u16_hex the
    unsure literal `none` alone, where the truth is 0x8664: a rejected probe and a STOP (BAD);
  - every coff.* name was None (no namespace).

What this pack does, all of it unsure (never plain before the judge has spoken under the key it names):

  coff.*      a namespace of its own: machine (code: IMAGE_FILE_MACHINE_*, integer, 0x), number_of_sections,
              time_date_stamp, pointer_to_symbol_table, number_of_symbols, size_of_optional_header, characteristics,
              section_names (long names through the string table). Read from a bare COFF object (offset 0), from a
              PE's file header (e_lfanew + 4), and from the COFF members of an ar archive (one value only where
              every object member agrees, under '<key>+archive'). Since B-248 also from a bigobj object
              (ANON_OBJECT_HEADER_BIGOBJ, 32-bit section count, 20-byte symbols), bare or as an archive member;
              a bigobj has no characteristics (Unknown).
  pe.*        on a bare COFF object (no MZ; a known IMAGE_FILE_MACHINE at offset 0; 1 to 96 sections whose headers,
              symbol table and raw data fit the file) a reader of a COFF file-header field (machine, sections,
              stamp, characteristics, optional-header size, symbols, section names) answers the object's value
              under '<key>+object', so the judged pe.coff_machine_u16_hex (0x_u16_4digits) stays plain only for a
              real PE; every other pe.* reader (a family's too) is Unknown there (None), never the literal `none`.
              The same on an ar archive with COFF members (a .lib), under '<key>+archive'.
  elf.*, macho.*  a reader that gives nothing for an ar archive reads its ELF (or Mach-O) members instead: one
              value, the class's first form only, under '<key>+archive', where every object member agrees; members
              that differ, or a member that does not have the field, are Unknown (None). Magic, fat and universal
              readers are left alone (an archive's magic is its own).
  collections an ar archive asked a collection name as a JSON array (`elf.e_machine_set`, `ar.member_e_machine_set`,
              `coff.machine_list`) gets the members' values as JSON arrays, as candidates (labels.candidates, row
              346) under 'metadata.format/<asked>+archive#candidates': member order first, then sorted, for each
              form of the field (the zero-padded hex at its registered width first); a `_set` or a plural keeps each
              value once, a `_list`, `_array`, `_values` or `_all` every member. One stderr line
              `ARCHIVE MEMBERS <id>: ...` (the day-review marker `metadata-objects`).

How: no registered extractor is replaced (tests and SPEC_FN, TIE_FREE, LATE_WIDTHS hold them by identity). Two of
properties_strict's functions are wrapped at register time, through their module globals: options_for (the one
reading every present path makes: a reading the core gives as ABSENT for an object file or an archive is read here,
in the ASKING property's class, u16hex for a `_u16_hex` name, and handed back as M.keyed_forms('+object' or
'+archive', ...) with `.shape` set, so present() judges it under '<key>+<shape>' and present_synonym()/present_guess()
under '<their key>+<shape>'), and present_collection (row 401's: an archive is read here first). Whatever goes wrong
in this pack is the core's answer, unchanged, and one NOTE line at most.

ar archives: the System V/GNU form ('/' and '/SYM64/' symbol tables, the '//' long-name table and '/<offset>' names,
'name/' short names) and the BSD form ('#1/<n>' names, '__.SYMDEF' tables). A header that does not parse makes the
file no archive here (the readers' own answer stands).
"""
import functools
import re
import struct

M = None
AR = b"!<arch>\n"
MAX_MEMBERS = 4096
AR_SKIP = {"/", "//", "/SYM64/", "__.SYMDEF", "__.SYMDEF SORTED", "__.SYMDEF_64", "__.SYMDEF_64 SORTED", "ARFILENAMES/"}

# IMAGE_FILE_MACHINE_* (the PE/COFF specification). 0 (UNKNOWN) is left out: an object of no machine is no evidence.
MACHINES = {0x14C: "IMAGE_FILE_MACHINE_I386", 0x8664: "IMAGE_FILE_MACHINE_AMD64", 0xAA64: "IMAGE_FILE_MACHINE_ARM64",
            0x1C0: "IMAGE_FILE_MACHINE_ARM", 0x1C2: "IMAGE_FILE_MACHINE_THUMB", 0x1C4: "IMAGE_FILE_MACHINE_ARMNT",
            0xA641: "IMAGE_FILE_MACHINE_ARM64EC", 0xA64E: "IMAGE_FILE_MACHINE_ARM64X", 0x200: "IMAGE_FILE_MACHINE_IA64",
            0x184: "IMAGE_FILE_MACHINE_ALPHA", 0x284: "IMAGE_FILE_MACHINE_ALPHA64", 0x1D3: "IMAGE_FILE_MACHINE_AM33",
            0xEBC: "IMAGE_FILE_MACHINE_EBC", 0x9041: "IMAGE_FILE_MACHINE_M32R", 0x166: "IMAGE_FILE_MACHINE_R4000",
            0x169: "IMAGE_FILE_MACHINE_WCEMIPSV2", 0x266: "IMAGE_FILE_MACHINE_MIPS16", 0x366: "IMAGE_FILE_MACHINE_MIPSFPU",
            0x466: "IMAGE_FILE_MACHINE_MIPSFPU16", 0x1F0: "IMAGE_FILE_MACHINE_POWERPC", 0x1F1: "IMAGE_FILE_MACHINE_POWERPCFP",
            0x1A2: "IMAGE_FILE_MACHINE_SH3", 0x1A3: "IMAGE_FILE_MACHINE_SH3DSP", 0x1A6: "IMAGE_FILE_MACHINE_SH4",
            0x1A8: "IMAGE_FILE_MACHINE_SH5", 0x5032: "IMAGE_FILE_MACHINE_RISCV32", 0x5064: "IMAGE_FILE_MACHINE_RISCV64",
            0x5128: "IMAGE_FILE_MACHINE_RISCV128", 0x6232: "IMAGE_FILE_MACHINE_LOONGARCH32",
            0x6264: "IMAGE_FILE_MACHINE_LOONGARCH64"}

COFF_NAMES = {
    "machine": (("coff.machine", "coff.machine_type", "coff.target_machine", "coff.file_header_machine"), "code", 16, None),
    "nsec": (("coff.number_of_sections", "coff.section_count", "coff.num_sections", "coff.nsections"), "integer", 16, None),
    "stamp": (("coff.time_date_stamp", "coff.timestamp", "coff.timedatestamp", "coff.link_time_date_stamp"), "number", 32,
              None),
    "symptr": (("coff.pointer_to_symbol_table", "coff.symbol_table_offset", "coff.symbol_table_pointer"), "number", 32,
               "offset"),
    "nsym": (("coff.number_of_symbols", "coff.symbol_count", "coff.num_symbols"), "integer", 32, None),
    "optsize": (("coff.size_of_optional_header", "coff.optional_header_size", "coff.optional_header_size_bytes"),
                "integer", 16, None),
    "chars": (("coff.characteristics", "coff.flags", "coff.file_characteristics"), "number", 16, None),
    "sections": (("coff.section_names", "coff.sections", "coff.section_name_list"), "list", None, None),
}
# The PE readers whose field is the COFF file header's, by a registered name of each (resolved to its extractor
# at register time; every alias of that extractor follows).
PE_FIELDS = {"pe_coff_machine_u16_hex": "machine", "pe_machine": "machine_code", "pe_section_count": "nsec",
             "pe_timestamp": "stamp", "pe_coff_time_date_stamp": "stamp", "pe_characteristics": "chars",
             "pe_size_of_optional_header": "optsize", "pe_number_of_symbols": "nsym",
             "pe_pointer_to_symbol_table": "symptr", "pe_section_names": "sections"}
PE_HEADS = ("pe", "exe", "dll", "portable_executable")
ARCHIVE_PREFIX = re.compile(r"ar_(?:members?|objects?|object_files?|entries|entry)_(.+)")
EVERY_WORDS = ("list", "array", "values", "all")

FIELD_OF = {}     # extractor -> ('pe', COFF field or None) | ('coff', field) | ('elf', None) | ('macho', None)


def U(msg):
    raise M.Unknown(msg)


# ------------------------------------------------------------------ COFF headers

def coff_header(d: bytes, at: int = 0):
    """The COFF file header at `at` as a dict, or None where it is cut."""
    if at < 0 or len(d) < at + 20:
        return None
    machine, nsec, stamp, symptr, nsym, optsize, chars = struct.unpack_from("<HHIIIHH", d, at)
    return {"at": at, "machine": machine, "nsec": nsec, "stamp": stamp, "symptr": symptr, "nsym": nsym,
            "optsize": optsize, "chars": chars}


def coff_object(d: bytes):
    """The header of a bare COFF object file, or None: no MZ, a known machine at offset 0, 1 to 96 sections whose
    headers, symbol table and raw data all fit the file."""
    if len(d) < 60 or d[:2] == b"MZ" or d[:4] == b"\x7fELF" or d[:8] == AR:
        return None
    if (d[0] | d[1] << 8) not in MACHINES:
        return None
    h = coff_header(d)
    if not 1 <= h["nsec"] <= 96:
        return None
    table = 20 + h["optsize"]
    if table + 40 * h["nsec"] > len(d):
        return None
    if (h["symptr"] and h["symptr"] + 18 * h["nsym"] > len(d)) or (not h["symptr"] and h["nsym"]):
        return None
    for i in range(h["nsec"]):
        size, ptr = struct.unpack_from("<II", d, table + 40 * i + 16)
        if size and ptr and ptr + size > len(d):
            return None
    return h


# B-248: the bigobj COFF object (cl /bigobj, ANON_OBJECT_HEADER_BIGOBJ). Sig1 0, Sig2 0xFFFF, Version >= 2, the
# fixed ClassID {D1BAA1C7-BAEE-4BA9-AF20-FAF66AA4DCB8}, then a 32-bit section count: a 56-byte header, 40-byte
# section headers and 20-byte symbol records (IMAGE_SYMBOL_EX), so the string table sits at PointerToSymbolTable +
# 20 * NumberOfSymbols. It has no Characteristics and no optional header. Every offset below is walked by the
# header's own size fields and must fit the file, or it is no bigobj here.
BIGOBJ_CLSID = bytes.fromhex("c7a1bad1eebaa94baf20faf66aa4dcb8")   # {D1BAA1C7-BAEE-4BA9-AF20-FAF66AA4DCB8}
BIGOBJ_HEADER = 56
BIGOBJ_SYMBOL = 20
BIGOBJ_MAX_SECTIONS = 1 << 16


def bigobj_object(d: bytes):
    """The header of a bigobj COFF object as coff_header's dict (plus version, flags, class id, table and symbol
    size), or None."""
    if len(d) < BIGOBJ_HEADER or d[:4] != b"\x00\x00\xff\xff" or d[12:28] != BIGOBJ_CLSID:
        return None
    version, machine, stamp = struct.unpack_from("<HHI", d, 4)
    if version < 2 or machine not in MACHINES:
        return None
    size_of_data, flags, md_size, md_off, nsec, symptr, nsym = struct.unpack_from("<7I", d, 28)
    if not 1 <= nsec <= BIGOBJ_MAX_SECTIONS or BIGOBJ_HEADER + 40 * nsec > len(d):
        return None
    if (symptr and symptr + BIGOBJ_SYMBOL * nsym > len(d)) or (not symptr and nsym):
        return None
    for i in range(nsec):
        size, ptr = struct.unpack_from("<II", d, BIGOBJ_HEADER + 40 * i + 16)
        if size and ptr and ptr + size > len(d):
            return None
    return {"at": 0, "machine": machine, "nsec": nsec, "stamp": stamp, "symptr": symptr, "nsym": nsym, "optsize": 0,
            "bigobj": True, "version": version, "flags": flags, "table": BIGOBJ_HEADER, "symsize": BIGOBJ_SYMBOL,
            "class_id": d[12:28]}


def any_object(d: bytes):
    """A bare COFF object's header, classic or bigobj, or None."""
    return coff_object(d) or bigobj_object(d)


def short_import(d: bytes):
    """The header of a short import object (an import library's member: Sig1 0, Sig2 0xFFFF, Version 0), or None.
    It has a machine and a stamp, and no section table."""
    if len(d) < 20 or d[:4] != b"\x00\x00\xff\xff" or d[4:6] != b"\x00\x00":
        return None
    machine, stamp = struct.unpack_from("<HI", d, 6)
    if machine not in MACHINES:
        return None
    return {"at": 0, "machine": machine, "stamp": stamp, "import": True}


def pe_header(d: bytes):
    """The COFF file header of a PE image (after 'PE\\0\\0'), or None."""
    if len(d) < 64 or d[:2] != b"MZ":
        return None
    at = struct.unpack_from("<I", d, 60)[0]
    if d[at:at + 4] != b"PE\x00\x00":
        return None
    return coff_header(d, at + 4)


def section_names(d: bytes, h: dict):
    """The section names of a COFF header in table order, long names ('/<offset>') read from the string table."""
    if h.get("import"):
        U("a short import object has no section table")
    table = h.get("table", h["at"] + 20 + h["optsize"])
    strtab = h["symptr"] + h.get("symsize", 18) * h["nsym"] if h["symptr"] else None
    out = []
    for i in range(h["nsec"]):
        name = M._at("8s", d, table + 40 * i)[0].rstrip(b"\x00")
        if name[:1] == b"/" and name[1:].isdigit():
            if strtab is None:
                U("a long section name with no string table")
            off = strtab + int(name[1:])
            end = d.find(b"\x00", off)
            if off >= len(d) or end < 0:
                U("a long section name outside the string table")
            name = d[off:end]
        try:
            text = name.decode("utf-8")
        except UnicodeDecodeError:
            U("a section name that is not UTF-8")
        if not text:
            U("an empty section name")
        out.append(text)
    return out


def field_value(field: str, d: bytes, h: dict, constants=None):
    """One COFF file-header field of the header `h` of `d`, in the form the matching reader returns."""
    if field == "sections":
        return section_names(d, h)
    if field == "machine_code":
        return (constants if constants is not None else M.PE_MACHINE).get(h["machine"]), h["machine"]
    if field not in h:
        U(f"a short import object has no {field}")
    return h[field]


# ------------------------------------------------------------------ ar archives

def ar_members(d: bytes):
    """((name, body), ...) of an ar archive, symbol tables left out, or None for no archive or a malformed one."""
    if d[:8] != AR:
        return None
    try:
        return _ar_members(d)
    except (ValueError, UnicodeDecodeError):
        return None


@functools.lru_cache(maxsize=8)
def _ar_members(d: bytes):
    out, i, longnames = [], len(AR), b""
    while i < len(d):
        if d[i:i + 1] == b"\n":
            i += 1
            continue
        h = d[i:i + 60]
        if len(h) < 60 or h[58:60] != b"`\n":
            raise ValueError("an ar member header is malformed")
        name = h[:16].decode("latin-1").rstrip()
        size = int(h[48:58].decode("ascii").strip() or "0")
        body = d[i + 60:i + 60 + size]
        if len(body) < size:
            raise ValueError("an ar member is cut")
        if name == "//":
            longnames = body
        elif name.startswith("#1/"):
            ln = int(name[3:])
            name, body = body[:ln].rstrip(b"\x00").decode("latin-1"), body[ln:]
        elif name.startswith("/") and name[1:].isdigit():
            off = int(name[1:])
            if off >= len(longnames):
                raise ValueError("a long member name outside the '//' table")
            end = longnames.find(b"/\n", off)
            name = longnames[off:end if end >= 0 else len(longnames)].decode("latin-1").rstrip("/\n")
        elif name.endswith("/") and name not in AR_SKIP:
            name = name[:-1]
        if name not in AR_SKIP:
            out.append((name, body))
        if len(out) > MAX_MEMBERS:
            raise ValueError("too many ar members")
        i += 60 + size + (size & 1)
    return tuple(out)


def member_kind(body: bytes):
    if body[:4] == b"\x7fELF":
        return "elf"
    if body[:4] in M.MACHO_MAGIC:
        return "macho"
    if any_object(body) is not None or short_import(body) is not None:
        return "coff"
    return None


def objects(d: bytes, kind: str):
    """The bodies of the archive's object members of `kind` (elf, coff, macho), in member order; [] for none."""
    mem = ar_members(d)
    if not mem:
        return []
    return [b for _, b in mem if member_kind(b) == kind]


def _member_header(body: bytes):
    h = any_object(body)
    return h if h is not None else short_import(body)


# ------------------------------------------------------------------ what a reader is, and a member's value

def reader_of(p):
    """(namespace, COFF field or None) of a Prop's extractor, or None for one this pack does not read. A family's
    pe reader (a fresh closure per lookup) is known by its name's namespace: its field is None (Unknown)."""
    got = FIELD_OF.get(p.fn)
    if got is not None:
        return got
    if M.canon(p.name).partition("_")[0] in PE_HEADS:
        return ("pe", None)
    return None


def member_value(kind_field, name, body, fn):
    """The value of one archive member for a reader (namespace, field) whose extractor is `fn`."""
    ns, field = kind_field
    if ns in ("elf", "macho"):
        return fn(name, body)
    h = _member_header(body)
    if h is None:
        U("not a COFF object")
    if field is None:
        U("a COFF object has no such field of a PE image")
    return field_value(field, body, h, MACHINES if ns == "coff" else None)


def _kind_of(ns):
    return "coff" if ns in ("pe", "coff") else ns


def _shaped(options, shape):
    out = M.keyed_forms("+" + shape, options)
    out.shape = shape
    return out


def container_options(p, name, d: bytes):
    """(options, False) for a reading the core gave as absent where the file is a COFF object or an archive of
    objects this reader reads; None where it is no such file (the core's answer stands). Raises Unknown where it is
    such a file and the field is not settled (members that differ, a field a COFF object has not)."""
    rf = reader_of(p)
    if rf is None:
        return None
    ns, field = rf
    if ns == "pe" and d[:2] != b"MZ":
        h = any_object(d)
        if h is not None:
            if field is None:
                U(f"a COFF object file (no MZ, no PE header) has no {p.name} of a PE image")
            return _shaped(list(M.FORMATS[p.fmt][1](field_value(field, d, h))), "object"), False
    if d[:8] != AR:
        return None
    bodies = objects(d, _kind_of(ns))
    if not bodies:
        return None
    raws = [member_value(rf, name, b, p.fn) for b in bodies]
    if any(r is None for r in raws):
        U(f"an object member of the archive has no {p.name}")
    if any(r != raws[0] for r in raws[1:]):
        U(f"the object members of the archive differ in {p.name}")
    return _shaped(list(M.FORMATS[p.fmt][1](raws[0]))[:1], "archive"), False


def _could_be(d) -> bool:
    """A cheap first look (two byte compares): an ar archive, or a known COFF machine at offset 0 with no MZ."""
    return d[:8] == AR or (len(d) >= 60 and d[:2] != b"MZ" and (d[0] | d[1] << 8) in MACHINES) or \
        (d[:4] == b"\x00\x00\xff\xff" and d[12:28] == BIGOBJ_CLSID)


def _options_hook(orig):
    def options_for(p, name, data):
        got = orig(p, name, data)
        if not got[1] or not isinstance(data, (bytes, bytearray)) or not _could_be(data):
            return got
        try:
            alt = container_options(p, name, bytes(data))
        except M.Unknown:
            raise
        except Exception as e:     # this pack's failure costs its own reading, never the core one
            M._say(f"NOTE readers_objects.py: {type(e).__name__}: {M._clean(e, 160)}; the core reading stands")
            alt = None
        return got if alt is None else alt
    options_for.objects_hook = orig
    return options_for


# ------------------------------------------------------------------ the coff namespace's own readers

def _coff_reader(field):
    def read(n, d):
        h = any_object(d) or pe_header(d)
        if h is not None:
            return field_value("machine_code" if field == "machine" else field, d, h, MACHINES)
        if d[:8] == AR and objects(d, "coff"):
            return None       # the options_for hook reads the archive's members (one agreed value, '+archive')
        U("not a COFF object, a PE image or an archive of COFF objects")
    return read


# ------------------------------------------------------------------ collections of an archive's members

_PASS = object()


def _element(name, text):
    if name in ("integer", "unix", "bits") and re.fullmatch(r"-?[0-9]+", text):
        return int(text)
    return text


def _sort_key(x):
    return (0, x, "") if isinstance(x, int) else (1, 0, str(x))


def _member_forms(hit, raw):
    forms = list(M.FORMATS[hit.fmt][1](raw))
    bits = hit.bits if isinstance(hit.bits, int) else None
    if hit.fmt in M.NUMERIC and bits in M.SIZED:
        try:
            pad = M.FORMATS[M.SIZED[bits]][1](raw)[0]
            forms = [pad] + [f for f in forms if f[1] != pad[1]]
        except Exception:
            pass
    return forms


def archive_collection(key, q, name, data):
    """The candidates for a collection name of an ar archive's object members, None, or _PASS (not ours)."""
    if not key or data is None or data[:8] != AR or not M._json_array_question(q):
        return _PASS
    key = M.canon(key)
    m = ARCHIVE_PREFIX.fullmatch(key)
    if m:
        tries = [f"{ns}_{m.group(1)}" for ns in ("elf", "coff", "pe", "macho")]
    elif key.partition("_")[0] in ("elf", "coff", "pe", "macho"):
        tries = [key]
    else:
        return _PASS
    aid = q.get("answer_id") or q.get("qid")
    asked = M.dotted(key)
    for full in tries:
        hit, reader, core = M._collection_reader(full)
        rf = reader_of(hit) if hit is not None else None
        if rf is None or (rf[0] == "pe" and rf[1] is None):
            continue
        bodies = objects(data, _kind_of(rf[0]))
        if not bodies:
            continue
        try:
            raws = [member_value(rf, name, b, hit.fn) for b in bodies]
            if any(r is None for r in raws):
                U("an object member does not have the field")
            per = [_member_forms(hit, r) for r in raws]
        except Exception as e:
            M._say(f"NOT ESTABLISHED {asked} (read as {M.dotted(core)} by {reader}) for {aid}: the archive's "
                   f"{_kind_of(rf[0])} members: {type(e).__name__}: {M._clean(e, 120)}")
            return None
        every_first = key.split("_")[-1] in EVERY_WORDS
        options, seen = [], set()

        def offer(n, arr):
            v = M._json(arr)
            if v not in seen and M._fits(q, v):
                seen.add(v)
                options.append((n, v))
        for form, _ in per[0]:
            col = []
            for f in per:
                v = dict(f).get(form)
                if v is None:
                    break
                col.append(_element(form, v))
            if len(col) != len(per):
                continue
            once = []
            for x in col:
                if x not in once:
                    once.append(x)
            primary, other = (col, once) if every_first else (once, col)
            offer(f"{form}+member_order", primary)
            offer(f"{form}+sorted", sorted(primary, key=_sort_key))
            offer(f"{form}+{'each_once' if every_first else 'every_member'}", other)
        if not options:
            M._say(f"FORMAT {aid}: {asked} (read as {M.dotted(core)} by {reader}) of the archive's members has no form "
                   f"that fits the answer format")
            return None
        ckey = M.labels.candidate_key(M.FORMAT_KEY + asked.lower() + "+archive")
        M._say(f"ARCHIVE MEMBERS {aid}: {asked} read from {len(bodies)} {_kind_of(rf[0])} member(s) of "
               f"{M._clean(M._base(name), 60)} by {reader}; candidates under {ckey}, member order first (Day 21 final prep)")
        return M.labels.candidates(ckey, options[:M.labels.MAX_OPTIONS])
    return _PASS


def _collection_hook(orig):
    def present_collection(key, q, name, data):
        try:
            got = archive_collection(key, q, name, data)
        except Exception as e:   # this pack's failure costs its own answer, never the core path
            M._say(f"NOTE readers_objects.py: {type(e).__name__}: {M._clean(e, 160)}; the core path answers")
            got = _PASS
        return orig(key, q, name, data) if got is _PASS else got
    present_collection.objects_hook = orig
    return present_collection


# ------------------------------------------------------------------ register

def register(module):
    """properties_strict calls this with its own module object. Returns (names, families) added."""
    global M
    M = module
    before, families = len(M.REG), len(M.FAMILIES)

    M.NAMESPACES.add("coff")
    M.PACK_NAMESPACES.add("coff")
    M.CONTENT_TOKENS.update({"coff", "obj"})
    M.RELATED.setdefault("coff", ("coff",))
    M.MORE_TYPES.append(("coff", coff_object))
    M.MORE_TYPES.append(("coff", bigobj_object))   # B-248
    M.NS_ALIAS.setdefault("obj", "coff")
    M.NS_ALIAS.setdefault("coff_object", "coff")
    for field, (names, fmt, bits, unit) in COFF_NAMES.items():
        fn = _coff_reader(field)
        for nm in names:
            if M.canon(nm) in M.REG:
                M.MORE_CLASHES.append(nm)
                continue
            M.prop(nm, fmt=fmt, bits=bits, unit=unit)(fn)
        M.TIE_FREE.add(fn)
        FIELD_OF[fn] = ("coff", "machine_code" if field == "machine" else field)

    pe_fields = {M.REG[k].fn: f for k, f in PE_FIELDS.items() if k in M.REG}
    mm = getattr(M, "MORE_MODULES", {}).get("readers_macho.py")
    macho_own = set(getattr(mm, "MINE", ()) or ())
    left_alone = set()
    for k, p in M.REG.items():
        ns = k.partition("_")[0]
        if ns in ("elf", "macho") and ("magic" in k or "fat" in k or "universal" in k or p.fn in macho_own):
            left_alone.add(p.fn)      # an archive's magic is its own; fat and universal facts are no member's
    for k, p in M.REG.items():
        ns = k.partition("_")[0]
        if p.fn in FIELD_OF or p.fn in left_alone:
            continue
        if ns == "pe":
            FIELD_OF[p.fn] = ("pe", pe_fields.get(p.fn))
        elif ns in ("elf", "macho"):
            FIELD_OF[p.fn] = (ns, None)

    g = M.lookup.__globals__     # properties_strict's own globals (never a hook's)
    if not getattr(g["options_for"], "objects_hook", None):
        g["options_for"] = _options_hook(g["options_for"])
    if not getattr(g["present_collection"], "objects_hook", None):
        g["present_collection"] = _collection_hook(g["present_collection"])
    return (len(M.REG) - before, len(M.FAMILIES) - families)
