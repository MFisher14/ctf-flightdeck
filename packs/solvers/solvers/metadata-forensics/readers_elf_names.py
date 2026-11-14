#!/usr/bin/env python3
"""Metadata Forensics reader pack of the Day 12 look-ahead (M3): the names of an ELF header.

properties_strict.py loads this file by name after readers_pe_tables.py and calls register(M) with
itself. Nothing here answers plain: every name is registered unconfirmed, so the strict wrapper
offers it through labels.pick until the judge has accepted a format for its key. A name the earlier
files read keeps that reading (registered, a synonym, or the nearest reader's), with one exception
that is said below (elf.e_type) and two names that are registered here to keep their value (KEPT),
and no name here has the words of another extractor's name, so synonym() stays exact.

The contract of an extractor is the wrapper's: fn(name, data) returns the value read from the
bytes, None when the file is not ELF (the wrapper then offers the unsure `none`, never a number),
or raises M.Unknown when it is and the bytes do not settle the fact. The header is the wrapper's
own reading (M._elf) and readers_more.py's (_elfx, _elf_segments); nothing is parsed twice.

What is here (namespace elf):
  header fields     the thirteen fields after e_ident under the names a question may give the
                    structure: ehdr_e_<field>, ehdr_<field>, elf_header_e_<field>,
                    elf_header_<field>, and the bare <field> where only e_<field> was a name
                    (phnum, shoff, ...). Each is the reader of e_<field> or <field> under one more
                    name: the same extractor, class, width and unit.
  e_ident           EI_CLASS and EI_DATA as the byte they are (ELFCLASS64 and 2, ELFDATA2LSB and 1)
                    under e_ident_<byte>, ident_<byte> and e_ident_ei_<byte>, beside the wrapper's
                    readers of the same two bytes as a word (elf.class is ELF64, elf.ei_data is
                    little): two readers of one byte, each under words of its own. EI_VERSION,
                    EI_OSABI and EI_ABIVERSION were numbers already and get the same names. A
                    name of the wrapper's own that ends in hex (elf.ei_class_u8_hex) is the byte.
  e_type            elf.e_type was the number alone (2). It is the reader of elf.type now, a code:
                    asked as text the gABI's constant comes first (ET_EXEC, the form the Binary
                    lane's judge took), asked as an integer or as hex the number does, as before.
                    elf.e_machine stays the number first: the lane's selftest holds it there.
  program headers   program_header_types and four more spellings: the PT_ names in table order.
                    A type with no name in the gABI or the GNU extensions names no list.
  the rest          class_bits (32 or 64) and the entry point as entry_address.

WHERE['elf'] (the words that only say which structure a field lives in, dropped where a name
selects no reader with them) is ehdr and elf: elf.elf_class, elf.ehdr_section_header_count.
`ident` is not such a word: elf.version is e_version and elf.ident_version is EI_VERSION.

Second readings (the Day 21 build, round 2; properties_strict.SECOND, '<form>+<tag>', behind every option the
reader offered, never first, never plain):
  with_null_section  elf.section_names and elf.section_header_names as every section header lists them, index 0's
                     empty name first (pyelftools' iter_sections() and readelf -S): the JSON array, where the
                     reader's own reading leaves the null section out. Before this build readers_day14 registered
                     it with the class `list`, which refuses an empty name, so the option was never offered.
  pyelftools         elf.ei_osabi and every name of its reader: an OS ABI byte of 0 as ELFOSABI_SYSV (pyelftools'
                     name), after ELFOSABI_NONE, 0 and 0x0.
"""
import json
M = None          # properties_strict, set by register()
RM = None         # readers_more.py as loaded by properties_strict: _elfx, _elf_segments
SECTIONS = []
QUEUE = []        # (name, the registered name it is one more spelling of or None, class, extractor, bits) the sections ask for
PATTERNS = []     # (pattern, class, extractor) of the families
WHERE = ("ehdr", "elf")
PREFIXES = ("ehdr", "elf_header")   # the names a question may give the structure


def section(fn):
    SECTIONS.append(fn)
    return fn


def U(msg):
    raise M.Unknown(msg)


def also(target: str, names):
    """Ask for more names of a registered elf.<target>, each under its own key: the same
    extractor, class, width and unit, never confirmed."""
    QUEUE.extend((name, target, None, None, None) for name in names)


def new(names, fmt, fn, bits=None):
    """Ask for an extractor of this file under each name."""
    QUEUE.extend((name, None, fmt, fn, bits) for name in names)


# The names of the sections below that the earlier files read already, as the nearest reader's
# (elf.elf_header_size_bytes gives e_ehsize the word elf): they keep that reading. Asking the
# registry for them costs 0.1 s at every import, so they are listed, and
# tests/test_day12_metadata_elf.py asks it in a process without this file.
READ_BEFORE = ("elf_header_e_ehsize", "elf_header_ehsize")
# Two names the earlier files read by the words of one reader's own names taken together (row 203):
# elf.elf_header_e_size was e_ehsize while that reader alone had the word elf, and
# elf.ei_ident_version was EI_VERSION while that reader alone had the word ident. The names of this
# file give both words to other readers, which ends that reading (two readers, so none). So the two
# are registered here, (the reader, the name), and they and their other spellings (elf.elf_e_size,
# elf.ident_ei_version) keep the value they had.
KEPT = (("e_ehsize", "elf_header_e_size"), ("ei_version", "ei_ident_version"))


def register(module):
    global M, RM
    M = module
    RM = getattr(M, "MORE_MODULES", {}).get("readers_more.py")
    if RM is None:
        raise RuntimeError("readers_more.py is not loaded, and its ELF parsers are this file's")
    before = dict(M.REG)
    families = len(M.FAMILIES)
    del QUEUE[:], PATTERNS[:]
    for s in SECTIONS:
        s()
    # A name the earlier files read keeps that reading: registered, or the nearest reader's.
    free = [item for item in QUEUE if M.canon(f"elf.{item[0]}") not in M.REG and item[0] not in READ_BEFORE]
    code = M.REG["elf_type"]   # elf.e_type as the code elf.type is: the constant, the number, the number in hex
    M.REG["elf_e_type"] = M.Prop("elf.e_type", code.fn, code.fmt, False, code.bits, code.unit)
    for name, target, fmt, fn, bits in free:
        if target is None:
            M.prop(f"elf.{name}", fmt=fmt, bits=bits)(fn)
        else:
            p = M.REG[M.canon(f"elf.{target}")]
            M.REG[M.canon(f"elf.{name}")] = M.Prop(f"elf.{name}", p.fn, p.fmt, False, p.bits, p.unit)
    for pattern, fmt, fn in PATTERNS:
        M.family(pattern, fmt)(fn)
    # Only the extractors of this file are forecasts (tied_readers): a name that is one more
    # spelling of the wrapper's own reader leaves that reader where it stood.
    old = {p.fn for p in before.values()}
    M.TIE_FREE.update(M.REG[k].fn for k in M.REG if k not in before and M.REG[k].fn not in old)
    M.WHERE.setdefault("elf", set()).update(WHERE)
    _reg_second()
    return len(M.REG) - len(before), len(M.FAMILIES) - families


# ------------------------------------------------------------------ second readings (the Day 21 build, round 2)

NULL_TAG = "with_null_section"
SYSV_TAG = "pyelftools"
SECTION_NAMES = ("elf.section_names", "elf.section_header_names")


def _sections_with_null(n, d):
    """Every section header's name in table order, the null section's empty name included, as the forms class
    writes it (json_compact only: a comma or space list would start with a separator). None when not ELF."""
    secs = RM._elf_sections(d)
    if secs is None:
        return None
    text = json.dumps([s[0] for s in secs], separators=(",", ":"), ensure_ascii=False)
    if not text.isascii():
        U("a section name beyond ASCII: two JSON writings")
    return [("json_compact", text)]


def _osabi_sysv(n, d):
    """(ELFOSABI_SYSV, 0) where EI_OSABI is 0, else None (no second reading)."""
    return None if M._elf(d) is None or d[7] != 0 else ("ELFOSABI_SYSV", 0)


def _reg_second():
    for name in SECTION_NAMES:
        p = M.REG.get(M.canon(name))
        if p is not None and not p.confirmed:
            M.SECOND[M.canon(name)] = (_sections_with_null, "forms", NULL_TAG)
    osabi = M.REG.get("elf_ei_osabi")
    if osabi is not None:
        for k, p in M.REG.items():
            if k.startswith("elf_") and p.fn is osabi.fn and not p.confirmed:
                M.SECOND[k] = (_osabi_sysv, "code", SYSV_TAG)


# ------------------------------------------------------------------ the header's fields

# e_<field> in header order. The fields the earlier files name only as e_<field> get the bare name too.
FIELDS = ("type", "machine", "version", "entry", "phoff", "shoff", "flags", "ehsize", "phentsize", "phnum", "shentsize",
          "shnum", "shstrndx")


@section
def _reg_fields():
    for field in FIELDS:
        bare = field if M.canon(f"elf.{field}") in M.REG else f"e_{field}"   # elf.machine is a reader of its own, elf.phnum is e_phnum
        also(bare, [field] + [f"{prefix}_{field}" for prefix in PREFIXES])
        also(f"e_{field}", [f"{prefix}_e_{field}" for prefix in PREFIXES])
    also("e_entry", ["entry_address", "entry_point_address", "e_entry_address"])
    for target, name in KEPT:
        also(target, [name])


# ------------------------------------------------------------------ e_ident

ELF_CLASS = {1: "ELFCLASS32", 2: "ELFCLASS64"}
ELF_DATA = {1: "ELFDATA2LSB", 2: "ELFDATA2MSB"}


def _ident(at: int, constants: dict):
    """An extractor of one e_ident byte as (the gABI's constant, the byte). M._elf has refused a
    class or a byte order that is not a defined value before the byte is read."""
    def fn(n, d):
        return None if M._elf(d) is None else (constants[d[at]], d[at])
    return fn


def _spellings(byte: str) -> list:
    names = [f"e_ident_{byte}", f"ident_{byte}", f"e_ident_ei_{byte}"]
    return names + [f"{prefix}_{name}" for prefix in PREFIXES for name in names[:2]]


@section
def _reg_ident():
    for byte, at, constants in (("class", 4, ELF_CLASS), ("data", 5, ELF_DATA)):
        fn = _ident(at, constants)
        new(_spellings(byte), "code", fn, bits=8)
        # ... and under the wrapper's own name for the byte, which reads it as a word, when that
        # name ends in hex: found by lookup, every digit of the u8 first.
        PATTERNS.append((rf"elf_(?:(?:{'|'.join(PREFIXES)}|header)_)?ei_{byte}(?:_u8)?_hex", "u8hex", fn))
    for target, byte in (("ei_version", "version"), ("ei_osabi", "osabi"), ("ei_abiversion", "abiversion")):
        also(target, _spellings(byte))
    also("ei_abiversion", ["e_ident_abi_version", "ident_abi_version"])
    new(["class_bits"], "integer", lambda n, d: (lambda h: None if h is None else h[0])(M._elf(d)))


# ------------------------------------------------------------------ the program header table

# p_type by its name in the gABI and in the GNU extensions every Linux linker writes.
SEGMENT_TYPES = {0: "PT_NULL", 1: "PT_LOAD", 2: "PT_DYNAMIC", 3: "PT_INTERP", 4: "PT_NOTE", 5: "PT_SHLIB", 6: "PT_PHDR", 7: "PT_TLS",
                 0x6474E550: "PT_GNU_EH_FRAME", 0x6474E551: "PT_GNU_STACK", 0x6474E552: "PT_GNU_RELRO",
                 0x6474E553: "PT_GNU_PROPERTY"}
PN_XNUM = 0xFFFF   # e_phnum when the count is kept in the first section header


def _segment_types(n, d):
    x = RM._elfx(d)
    if x is None:
        return None
    if x["phnum"] >= min(PN_XNUM, 4096) or x["phentsize"] != (32 if x["bits"] == 32 else 56):
        U("a program header table that is not walked: too many entries, or entries of another size")
    types = [typ for typ, *_ in RM._elf_segments(d)]
    odd = sorted({typ for typ in types if typ not in SEGMENT_TYPES})
    if odd:
        U("a segment type with no name in the gABI or the GNU extensions: " + ", ".join(f"0x{typ:x}" for typ in odd[:4]))
    return [SEGMENT_TYPES[typ] for typ in types]


@section
def _reg_segments():
    new(["program_header_types", "segment_types", "phdr_types", "program_header_type_names", "segment_type_names"], "list", _segment_types)
