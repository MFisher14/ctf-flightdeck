#!/usr/bin/env python3
"""Metadata Forensics reader pack of the Day 12 look-ahead (M2): the tables of a PE file.

properties_strict.py loads this file by name after the packs of 2026-10-08 and calls register(M)
with itself. Nothing here answers plain: every property is registered unconfirmed, so the strict
wrapper offers it through labels.pick until the judge has accepted a format for its key. A name an
earlier file registered keeps its reader (reg() leaves it out), and no name here has the words of
an earlier reader's name, so synonym() stays exact.

The contract of an extractor is the wrapper's: fn(name, data) returns the value read from the
bytes, None when the file is not a PE or does not hold the structure, or raises M.Unknown when it
does and the bytes do not settle the fact. The header, the data directories and the section table
are readers_more.py's own reading (_pex); the resource tree and the version resource are pefile's
(_pefile), which is in the venv and is asked only when such a question comes.

What is here (namespace pe), each field under the name of its structure in pefile:
  data directories  the sixteen entries of the optional header, each as data_directory_<name>_*,
                    <name>_directory_* and <name>_table_*: rva (VirtualAddress), size, present. An
                    entry of zeros is 0 and false, never none; none is an entry the file's own
                    NumberOfRvaAndSizes leaves out.
  version resource  VS_FIXEDFILEINFO (the file and product version as dotted quads, and each of
                    its thirteen u32 fields as version_fixed_<field> and version_<field>), the
                    translation and its two halves, the string table's key, the string names and
                    their count, and the StringFileInfo strings of readers_more.py under more
                    prefixes (version_string_, version_resource_, string_file_info_,
                    vs_version_info_, ...). Two version resources or a fixed block pefile did not
                    read establish nothing; two string tables or two translations establish no
                    string list and no translation.
  sections          section_<name>_<field>, <name>_section_<field> and first_/last_section_<field>
                    for the five fields a question may ask of one section (the name without its
                    dot, one of SECTION_NAMES); the first and last name, the table's entry count,
                    the lists of sizes and addresses. A section the file does not have is the
                    unsure none, never a number.
  resources         the type names of the root directory (RT_VERSION first, the id second), the
                    counts, and whether a version or a manifest resource is there. A file whose
                    header names no resource directory has no types, 0 resources and neither.

A name that ends in hex is found by lookup where a family here says so (the directories, the
sections, version_<field>): its first form is every digit of the u32, as the judge took on Days 9
and 10, and an absent structure is the unsure none there too.
"""
import functools
import re

M = None          # properties_strict, set by register()
RM = None         # readers_more.py as loaded by properties_strict: _pex, _pefile, _pe_version, text
SECTIONS = []


def section(fn):
    SECTIONS.append(fn)
    return fn


def U(msg):
    raise M.Unknown(msg)


def held(fn):
    """fn, with whatever a cut or damaged structure raises, in pefile too, turned into Unknown:
    nothing is established."""
    @functools.wraps(fn)
    def safe(*args):
        try:
            return fn(*args)
        except (M.Unknown, M.Ambiguous):
            raise
        except Exception as e:
            U(f"the bytes do not read as this structure ({type(e).__name__})")
    return safe


def reg(names, fmt, fn, bits=None, unit=None):
    """Register one extractor under every pe.<name> that no earlier reader holds. The names of
    this file are written as they are stored: pe_<name>."""
    held_by = M.REG
    free = [f"pe.{x}" for x in names if f"pe_{x}" not in held_by]
    if free:
        M.prop(*free, fmt=fmt, bits=bits, unit=unit)(held(fn))


def register(module):
    global M, RM
    M = module
    RM = getattr(M, "MORE_MODULES", {}).get("readers_more.py")
    if RM is None:
        raise RuntimeError("readers_more.py is not loaded, and its PE parsers are this file's")
    before = set(M.REG)
    families = len(M.FAMILIES)
    for s in SECTIONS:
        s()
    M.TIE_FREE.update(M.REG[k].fn for k in M.REG if k not in before)
    # The second reading of a two-reading list is a form the list class gives here, so it is named
    # among the class's forms: once the judge has accepted it, covers() counts the format as
    # accepted, as it does for the first reading, and the lane's clocks are not held for it.
    names, formatter = M.FORMATS["list"]
    second = tuple(f"{n}_{what}" for what in READINGS for n in M.FORMATS["intlist"][0])
    M.FORMATS["list"] = (names + tuple(n for n in second if n not in names), formatter)
    return len(M.REG) - len(before), len(M.FAMILIES) - families


READINGS = ("ids", "integers")   # what the numbers of a two-reading list are: resource type ids, addresses as integers


def _two_lists(first: list, what: str, second: list):
    """An answer that is a list under two readings of its items (RT_VERSION or 16, 0x00001000 or
    4096): every list form of the first, then every list form of the numbers under '<form>_<what>'
    (`what` is one of READINGS)."""
    raise M.Ambiguous(M._f_list(first) + [(f"{n}_{what}", v) for n, v in M._f_intlist(second)])


# ------------------------------------------------------------------ the data directories

# IMAGE_DIRECTORY_ENTRY_<NAME> in table order: the name pefile gives it, then the specification's.
DIRECTORIES = (("export",), ("import",), ("resource",), ("exception",), ("security", "certificate"),
               ("basereloc", "base_relocation"), ("debug",), ("copyright", "architecture"), ("globalptr", "global_ptr"),
               ("tls",), ("load_config",), ("bound_import",), ("iat", "import_address_table"), ("delay_import",),
               ("com_descriptor", "clr_runtime_header"), ("reserved",))


def _spellings(name: str) -> list:
    """A directory as the table's entry, as the directory, and as the specification's table."""
    whole = name == "iat" or name.endswith(("_table", "_header"))
    return [f"data_directory_{name}", f"{name}_directory", name if whole else f"{name}_table"]


def _directory(d: bytes, index: int):
    """(VirtualAddress, Size) of one data directory entry, None when the file is not a PE or its
    table ends before the entry."""
    x = RM._pex(d)
    if x is None or index >= len(x["dirs"]):
        return None
    return x["dirs"][index]


def _present(entry):
    if entry is None:
        return None
    if bool(entry[0]) != bool(entry[1]):
        U("a directory entry with an address and no size, or a size and no address")
    return bool(entry[0])


@section
def _reg_directories():
    index = {}

    def part(i, at):
        return lambda n, d: (lambda e: None if e is None else e[at])(_directory(d, i))
    for i, names in enumerate(DIRECTORIES):
        spell = [s for name in names for s in _spellings(name)]
        index.update({s: i for s in spell})
        # VirtualAddress by its own name under the entry's first name only: said of the
        # `import address table`, the same words would be the import directory's too.
        reg([f"{s}_rva" for s in spell] + [f"data_directory_{names[0]}_virtual_address"], "number", part(i, 0), bits=32, unit="rva")
        if names[0] != "security":   # its size is readers_formats.py's certificate table size, by name or by the name's words
            reg([f"{s}_size" for s in spell], "integer", part(i, 1), bits=32)
        reg([f"{s}_present" for s in spell], "bool", lambda n, d, i=i: _present(_directory(d, i)))

    # The same fields under a name that ends in hex: found by lookup, so the security directory's
    # size (whose untyped name is the certificate table's reader in readers_formats.py, which says
    # nothing for a file without one) is the header's number here too, zero included.
    @M.family(r"pe_(" + "|".join(sorted(index, key=len, reverse=True)) + r")_(rva|virtual_address(?:_rva)?|size(?:_bytes)?)(?:_u32)?_hex",
              "u32hex")
    @held
    def _typed(n, d, spelling, field):
        entry = _directory(d, index[spelling])
        return None if entry is None else entry[field.startswith("size")]


# ------------------------------------------------------------------ the version resource

RT_VERSION, RT_MANIFEST = 16, 24
FIXED = ("Signature", "StrucVersion", "FileVersionMS", "FileVersionLS", "ProductVersionMS", "ProductVersionLS", "FileFlagsMask",
         "FileFlags", "FileOS", "FileType", "FileSubtype", "FileDateMS", "FileDateLS")   # VS_FIXEDFILEINFO, every field a u32
FIXED_PREFIXES = ("version_fixed_", "fixed_file_info_", "version_fixed_file_info_", "vs_fixedfileinfo_")
STRING_PREFIXES = ("version_string_", "version_strings_", "version_resource_", "string_file_info_", "version_string_file_info_",
                   "vs_version_info_", "version_info_string_", "resource_version_")


def snake(name: str) -> str:
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()


def _resources(d: bytes):
    """pefile's resource tree: None when the file is not a PE, () when its header names no
    resource directory, else the root directory."""
    pe = RM._pefile(d)
    if pe is None:
        return None
    entry = _directory(d, 2)
    if entry is None or not _present(entry):
        return ()
    root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if root is None:
        U("a resource directory that pefile did not read")
    return root


@functools.lru_cache(maxsize=4)
def _version(d: bytes):
    """(fixed info, [(string table key, {name: value})], [(language, code page)]) of the one version
    resource: None when the file is not a PE, () when it has no version resource. A Translation
    value of several pairs, of which pefile keeps the last, is None in the list. pefile reads the
    version type's first id only, so a second resource under another id is counted in the tree."""
    root = _resources(d)
    if not root:
        return root
    pe = RM._pefile(d)
    kinds = [e for e in root.entries if e.id == RT_VERSION]
    if not kinds:
        return ()
    infos, fixed = getattr(pe, "VS_VERSIONINFO", None) or [], getattr(pe, "VS_FIXEDFILEINFO", None) or []
    if len(kinds) != 1 or not hasattr(kinds[0], "directory") or _leaves(kinds[0].directory) != 1:
        U("several version resources")
    if len(infos) != 1 or len(fixed) != 1 or fixed[0].Signature != 0xFEEF04BD:
        U("several version resources, or one that pefile did not read to its fixed block")
    tables, translations = [], []
    for entry in (getattr(pe, "FileInfo", None) or [[]])[0]:
        for table in getattr(entry, "StringTable", None) or []:
            tables.append((RM.text(table.LangID), {RM.text(k): RM.text(v) for k, v in table.entries.items()}))
        for var in getattr(entry, "Var", None) or []:
            for key, value in var.entry.items():
                if (key.decode("latin-1") if isinstance(key, bytes) else key) == "Translation":
                    words = (value.decode() if isinstance(value, bytes) else value).split()
                    translations.append(tuple(int(word, 16) for word in words) if var.ValueLength == 4 and len(words) == 2 else None)
    return fixed[0], tables, translations


def _fixed(get):
    def fn(n, d):
        v = _version(d)
        return None if not v else get(v[0])
    return fn


def _one(what: str, items: list):
    if len(items) > 1:
        U(f"several {what}")
    return items[0] if items else None


def _strings(get):
    def fn(n, d):
        v = _version(d)
        table = _one("string tables", v[1]) if v else None
        return None if table is None else get(table)
    return fn


def _translation(get):
    def fn(n, d):
        v = _version(d)
        if v and None in v[2]:
            U("several translations")
        pair = _one("translations", v[2]) if v else None
        return None if pair is None else get(*pair)
    return fn


def _quad(ms: int, ls: int) -> list:
    parts = (ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF)
    return [("dotted", ".".join(map(str, parts))), ("comma", ",".join(map(str, parts)))]


@section
def _reg_version():
    for what in ("file", "product"):
        reg([f"{p}{what}_version" for p in FIXED_PREFIXES] + [f"fixed_{what}_version"], "forms",
            _fixed(lambda f, what=what: _quad(getattr(f, f"{what.capitalize()}VersionMS"), getattr(f, f"{what.capitalize()}VersionLS"))))
    for field in FIXED:
        reg([f"{p}{snake(field)}" for p in FIXED_PREFIXES], "number", _fixed(lambda f, field=field: getattr(f, field)), bits=32)
    # version_<field> in that order of words only (a family reads a name whole): as a registered
    # name, version_file_os would take the words of the optional header's file_os_version too.
    by_name = {snake(field): field for field in FIXED}

    @held
    def short(n, d, name):
        return _fixed(lambda f: getattr(f, by_name[name]))(n, d)
    M.family(r"pe_version_(" + "|".join(by_name) + ")", "number")(short)
    M.family(r"pe_version_(" + "|".join(by_name) + ")(?:_u32)?_hex", "u32hex")(short)
    reg(["version_translation", "version_info_translation", "var_file_info_translation", "version_translation_hex"], "forms",
        _translation(lambda lang, page: [("hex_lower", f"{lang:04x}{page:04x}"), ("0x_hex_lower", f"0x{lang:04x}{page:04x}"),
                                         ("hex_upper", f"{lang:04X}{page:04X}"), ("space", f"0x{lang:04x} 0x{page:04x}")]))
    reg(["version_language_id", "version_translation_language", "version_translation_language_id", "version_language"], "number",
        _translation(lambda lang, page: lang), bits=16)
    reg(["version_code_page", "version_translation_codepage", "version_translation_code_page", "version_codepage"], "number",
        _translation(lambda lang, page: page), bits=16)
    reg(["version_string_table_key", "version_string_table_language", "version_string_table_lang_id", "string_table_key"], "text",
        _strings(lambda t: t[0] or None))
    reg(["version_string_names", "version_string_keys", "version_info_string_names", "string_file_info_string_names"], "list",
        _strings(lambda t: list(t[1]) or None))
    reg(["version_string_count", "version_info_string_count", "string_file_info_string_count"], "integer", _strings(lambda t: len(t[1])))
    # The StringFileInfo strings themselves are readers_more.py's family; here are more of the
    # prefixes a name may give them, each name its own key.
    M.family(r"pe_(?:" + "|".join(STRING_PREFIXES) + ")(" + "|".join(RM.PE_VERSION_KEYS) + ")", "text")(held(RM._pe_version))


# ------------------------------------------------------------------ the section table

# The fields of IMAGE_SECTION_HEADER a question asks of one section, each under its own name, the
# other names of the raw size, and the unit a name may add: its place in _pex's tuple.
SECTION_FIELDS = {"virtual_size": 1, "virtual_size_bytes": 1, "virtual_address": 2, "virtual_address_rva": 2,
                  "size_of_raw_data": 3, "size_of_raw_data_bytes": 3, "raw_size": 3, "raw_size_bytes": 3, "raw_data_size": 3,
                  "raw_data_size_bytes": 3, "pointer_to_raw_data": 4, "pointer_to_raw_data_file_offset": 4,
                  "pointer_to_raw_data_offset": 4, "characteristics": 5}


# The names a section is asked by, without the dot: what the linkers, Go and the common packers
# write. Any other word beside `section` is left to the readers it may select (the resolver drops
# `section`: pe.section_dll_characteristics, pe.code_section_raw_size), so a name is read here
# only when it names a section, and each other name is read as it was before this file.
SECTION_NAMES = ("text", "data", "rdata", "idata", "edata", "pdata", "xdata", "rsrc", "reloc", "tls", "bss", "debug", "symtab",
                 "crt", "didat", "sdata", "sbss", "srdata", "gfids", "00cfg", "ndata", "itext", "didata", "rodata", "ctors",
                 "dtors", "buildid", "cormeta", "retplne", "voltbl", "textbss", "noptrdata", "upx0", "upx1", "upx2", "mpress1",
                 "mpress2", "aspack", "adata", "vmp0", "vmp1")


# The section a name selects: section_<name>, <name>_section, first_section or last_section.
WHICH = "(?:section_({0})|({0})_section|(first|last)_section)".format("|".join(SECTION_NAMES))


def _sections(d: bytes):
    """_pex's section table, whole: (name, VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData, Characteristics)."""
    x = RM._pex(d)
    if x is None:
        return None
    if len(x["sections"]) != M._pe(d)[1]:
        U("a section table that is not walked to its end")
    return x["sections"]


def _section(d: bytes, name, other, edge):
    """The section a name selects: None when the file is not a PE or has no such section."""
    table = _sections(d)
    if not table:
        return None
    if edge:
        return table[0] if edge == "first" else table[-1]
    hits = [s for s in table if s[0].lower().lstrip(".") == (name or other)]
    if len(hits) > 1:
        U(f"several sections named {name or other}")
    return hits[0] if hits else None


@section
def _reg_sections():
    @held
    def one(n, d, name, other, edge, field):
        hit = _section(d, name, other, edge)
        return None if hit is None else hit[SECTION_FIELDS[field]]

    def name_of(edge):
        return lambda n, d: (lambda s: None if s is None else s[0] or None)(_section(d, None, None, edge))
    reg(["first_section_name", "section_table_first_name"], "text", name_of("first"))
    reg(["last_section_name", "section_table_last_name"], "text", name_of("last"))
    reg(["section_table_entry_count", "section_header_entry_count"], "integer", lambda n, d: M._pe(d)[1] if RM._pex(d) else None)
    reg(["section_names_ordered", "section_name_list"], "list",
        lambda n, d: (lambda t: None if t is None else [s[0] for s in t] or None)(_sections(d)))

    def column(at):
        return lambda n, d: (lambda t: None if t is None else [s[at] for s in t] or None)(_sections(d))
    reg(["section_virtual_sizes"], "intlist", column(1))
    reg(["section_raw_sizes", "section_sizes_of_raw_data", "section_raw_data_sizes"], "intlist", column(3))

    def addresses_of(at):
        def fn(n, d):
            values = column(at)(n, d)
            if values is not None:
                _two_lists([f"0x{v:08x}" for v in values], "integers", values)
        return fn
    reg(["section_virtual_addresses", "section_rvas"], "list", addresses_of(2))
    reg(["section_pointers_to_raw_data", "section_raw_offsets", "section_file_offsets"], "list", addresses_of(4))

    def fields(*places):
        return "|".join(sorted((f for f, at in SECTION_FIELDS.items() if at in places), key=len, reverse=True))
    M.family(rf"pe_{WHICH}_({fields(1, 3)})", "integer")(one)
    M.family(rf"pe_{WHICH}_({fields(2, 4, 5)})", "number")(one)
    # ... and under a name that ends in hex: found by lookup, every digit of the u32 first.
    M.family(rf"pe_{WHICH}_({fields(1, 2, 3, 4, 5)})(?:_u32)?_hex", "u32hex")(one)


# ------------------------------------------------------------------ the resource directory

# The resource types of winuser.h, by id.
RESOURCE_TYPES = {1: "RT_CURSOR", 2: "RT_BITMAP", 3: "RT_ICON", 4: "RT_MENU", 5: "RT_DIALOG", 6: "RT_STRING", 7: "RT_FONTDIR",
                  8: "RT_FONT", 9: "RT_ACCELERATOR", 10: "RT_RCDATA", 11: "RT_MESSAGETABLE", 12: "RT_GROUP_CURSOR",
                  14: "RT_GROUP_ICON", 16: "RT_VERSION", 17: "RT_DLGINCLUDE", 19: "RT_PLUGPLAY", 20: "RT_VXD", 21: "RT_ANICURSOR",
                  22: "RT_ANIICON", 23: "RT_HTML", 24: "RT_MANIFEST"}


def _leaves(root) -> int:
    """How many resources the tree holds: the data entries under type, name and language."""
    count, walk = 0, list(root.entries)
    while walk:
        entry = walk.pop()
        if len(walk) > 1 << 16:
            U("a resource tree that is not walked")
        if hasattr(entry, "directory"):
            walk.extend(entry.directory.entries)
        else:
            count += 1
    return count


def _of_resources(get, none):
    """An extractor over the resource tree: `none` for a PE whose header names no resource directory."""
    def fn(n, d):
        root = _resources(d)
        return root if root is None else (none if root == () else get(root))
    return fn


@section
def _reg_resources():
    def types(n, d):
        root = _resources(d)
        if not root:
            return None
        if any(e.id is None for e in root.entries):   # a type under a name of its own: the name is the fact, there is no id
            return [str(e.name) if e.id is None else RESOURCE_TYPES.get(e.id, str(e.id)) for e in root.entries] or None
        ids = [e.id for e in root.entries]
        if not ids:
            return None
        _two_lists([RESOURCE_TYPES.get(i, str(i)) for i in ids], "ids", ids)
    reg(["resource_type_names", "resource_types", "rsrc_type_names"], "list", types)
    reg(["resource_type_ids"], "intlist", _of_resources(lambda r: [e.id for e in r.entries if e.id is not None] or None, None))
    reg(["resource_type_count", "resource_directory_entry_count"], "integer", _of_resources(lambda r: len(r.entries), 0))
    reg(["resource_count", "number_of_resources", "resource_data_entry_count"], "integer", _of_resources(_leaves, 0))
    reg(["resource_directory_number_of_id_entries"], "integer", _of_resources(lambda r: r.struct.NumberOfIdEntries, None))
    reg(["resource_directory_number_of_named_entries"], "integer", _of_resources(lambda r: r.struct.NumberOfNamedEntries, None))
    for names, kind in ((["version_resource_present", "has_version_resource"], RT_VERSION),
                        (["manifest_present", "manifest_resource_present", "has_manifest"], RT_MANIFEST)):
        reg(names, "bool", _of_resources(lambda r, kind=kind: any(e.id == kind for e in r.entries), False))
