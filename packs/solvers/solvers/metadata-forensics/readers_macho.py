#!/usr/bin/env python3
"""Metadata Forensics Mach-O pack (the Day 21 build: Day 20's live fix folded in, and its neighbours).

properties_strict.py loads this file by name (MORE_FILES, last) and calls register(M). Day 20 asked
`macho.cpu_type_set` of a thin 64-bit Mach-O as a compact JSON array; no reader had the name and the lane
STOPped until day_patch.py answered it as a candidate pick (row 346). The judge took `cpu_type_hex`,
["0x0100000c"], and rejected the arch name ["arm64"], the constant ["CPU_TYPE_ARM64"] and the integer
[16777228] (challenges/_ledger/metadata.jsonl, promoted to conventions.json under
`metadata.format/macho.cpu_type_set#candidates`).

  macho.cpu_type_set   the CPU types of a thin Mach-O, of every slice of a universal file (fat and fat64), or of
                       the Mach-O members of an ar archive, each read from the slice's OWN header, in file order,
                       each type once. Answered under the judged candidate key, so it is plain (cpu_type_hex,
                       0x%08x) where that key has an accepted name, for a `json` question only (another answer
                       kind goes under a '+kind_<kind>' twin key). A file whose reading the thin base did not
                       settle is answered under a twin key that names what is open, never plain before the judge
                       has spoken there:
                         +archive   a type came from an ar archive's member (a static library, or a fat slice
                                    that is one)
                         +dups      two slices share a CPU type (arm64 and arm64e): each type once, or every slice
                         +mismatch  a slice's header names another type than its fat_arch entry: the header
                                    first, the table second
                         +order     file order differs from ascending order
                         +table     a slice could not be read (cut, or neither Mach-O nor ar): its fat_arch entry
  macho.cpu_subtype_set  the subtypes, the same way: 0x%08x as stored (capability bits kept), masked, integer.
                       Candidates, unsure until judged.
  macho.arch_set       the arch names (arm64, arm64e, x86_64, x86_64h, i386, armv7, ppc ...), each once.
  macho.slice_count    the number of fat_arch entries; a thin file is 1 or 0 (unsure, both offered).
  macho.is_universal   true for a fat or fat64 file, false for a thin one or an archive.
  macho.filetype_set   MH_* of every slice (and archive member), each once.
  macho.uuid_set       LC_UUID of every slice that has one, file order.

Every name but macho.cpu_type_set itself is unjudged: unsure through labels.pick or labels.candidates.

The per-slice reading (wrap_thin_readers): every registered macho.* reader that reads a thin header only
(ncmds, flags, uuid, minimum OS, segments, dylibs, code signature ...) raised Unknown on a universal file, so
the answer was None. On such a file it now reads every thin slice and offers the FIRST slice's value, unsure,
its forms named '<form>+first_slice' (and a JSON list of every slice's value, '+every_slice', when the slices
differ). A thin file, and every reader that already read a fat file, is answered exactly as before: the
wrapper only runs after the reader failed on a universal file. The magic readers are left alone (a universal
file's magic is its own), and so is a universal file with a slice that is cut, empty or an archive.

Since the Day 21 final prep (fat_options(), asked by a wrap of properties_strict.options_for for a universal file
only, with the ASKING property, so its class writes the value): a per-slice reader whose slices all give one value
offers it in the asked class (macho.flags_u32_hex: 0x00200085 first, as on a thin file), forms still named
'<form>+first_slice'; a magic reader (macho.magic, magic_u32_hex, magic_hex) offers the fat magic itself
(0xcafebabe, 0xcafebabf) first and, where every slice is a whole thin header and they agree, the slices' magic
second ('<form>+slices'), unsure under '<key>+fat'. macho.fat_arch_offsets, _sizes and _aligns (the stored
exponents first, then bytes) read the fat_arch table in table order, unsure. No registered extractor is replaced.
"""
import functools
import json
import struct

M = None
RM = None
MINE = set()   # this pack's own extractors (readers_objects.py leaves them alone: they read archives themselves)

PROPERTY = "macho.cpu_type_set"
KEY = "metadata.format/" + PROPERTY
JUDGED_KINDS = ("json",)
FAT = (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf")
AR = b"!<arch>\n"
AR_SYMTABS = {"/", "//", "/SYM64/", "__.SYMDEF", "__.SYMDEF SORTED", "__.SYMDEF_64", "__.SYMDEF_64 SORTED"}
MAX_SLICES = 64
MAX_MEMBERS = 4096
ARM_SUB = {6: "armv6", 9: "armv7", 11: "armv7s", 12: "armv7k", 13: "armv8", 14: "armv6m", 15: "armv7m", 16: "armv7em"}

ALIASES = ("macho.cpu_types", "macho.cpu_type_list", "macho.cputype_set", "macho.cputypes", "macho.cpu_type_array",
           "macho.slice_cpu_types", "macho.fat_cpu_type_set", "macho.architecture_cpu_types")
SUBTYPE_NAMES = ("macho.cpu_subtype_set", "macho.cpusubtype_set", "macho.cpu_subtypes", "macho.cpu_subtype_list")
ARCH_NAMES = ("macho.arch_set", "macho.arch_names", "macho.arch_name_set", "macho.architecture_names",
              "macho.architecture_set", "macho.archs", "macho.arch_list")
COUNT_NAMES = ("macho.slice_count", "macho.universal_slice_count", "macho.arch_count", "macho.architecture_count",
               "macho.fat_slice_count", "macho.slices", "macho.number_of_architectures")
UNIVERSAL_NAMES = ("macho.is_universal", "macho.universal", "macho.is_fat", "macho.is_fat_binary",
                   "macho.universal_binary", "macho.is_universal_binary")
FILETYPE_NAMES = ("macho.filetype_set", "macho.file_type_set", "macho.filetypes", "macho.file_types")
UUID_NAMES = ("macho.uuid_set", "macho.uuids", "macho.slice_uuids", "macho.uuid_list")
# The Day 21 final prep: the fat_arch table's own columns, in table order (fat and fat64), unsure.
OFFSET_NAMES = ("macho.fat_arch_offsets", "macho.fat_offsets", "macho.slice_offsets", "macho.arch_offsets",
                "macho.fat_arch_file_offsets")
SIZE_NAMES = ("macho.fat_arch_sizes", "macho.fat_sizes", "macho.slice_sizes", "macho.arch_sizes",
              "macho.fat_arch_size_bytes")
ALIGN_NAMES = ("macho.fat_arch_aligns", "macho.fat_arch_alignments", "macho.fat_aligns", "macho.fat_alignments",
               "macho.slice_aligns", "macho.slice_alignments", "macho.arch_aligns", "macho.arch_alignments")


def U(msg):
    raise M.Unknown(msg)


def _thin(d: bytes):
    """(cputype, cpusubtype, filetype) of a thin Mach-O header, unsigned, or None."""
    if len(d) < 16 or d[:4] not in M.MACHO_MAGIC:
        return None
    e, _ = M.MACHO_MAGIC[d[:4]]
    return struct.unpack_from(e + "III", d, 4)


def _ar(d: bytes):
    """[(member name, body)] of a BSD or System V ar archive, symbol tables left out; Unknown when malformed."""
    out, i = [], len(AR)
    while i < len(d):
        if d[i:i + 1] == b"\n":            # a padding byte before the next header
            i += 1
            continue
        h = d[i:i + 60]
        if len(h) < 60 or h[58:60] != b"`\n":
            U("an ar member header is malformed")
        name = h[:16].decode("latin-1").rstrip()
        try:
            size = int(h[48:58].decode("ascii").strip() or "0")
        except ValueError:
            U("an ar member size is not a number")
        body = d[i + 60:i + 60 + size]
        if len(body) < size:
            U("an ar member is cut")
        if name.startswith("#1/"):         # BSD: the name follows the header, inside the member's size
            try:
                ln = int(name[3:])
            except ValueError:
                U("an ar long name length is not a number")
            name, body = body[:ln].rstrip(b"\0").decode("latin-1"), body[ln:]
        elif name.endswith("/") and name not in AR_SYMTABS:
            name = name[:-1]
        if name not in AR_SYMTABS:
            out.append((name, body))
        if len(out) > MAX_MEMBERS:
            U("too many ar members")
        i += 60 + size + (size & 1)
    return out


def _ar_objects(d: bytes):
    """[(header triple, body)] of the Mach-O members of an archive, in member order."""
    return [(h, body) for _, body in _ar(d) for h in [_thin(body)] if h is not None]


class Layout:
    """What a Mach-O file holds: kind (thin, fat, archive), the (cputype, cpusubtype, filetype) of every
    slice or object in file order, the fat_arch entries, the thin bodies, and the readings left open."""

    def __init__(self, kind, slices, table, bodies, issues):
        self.kind, self.slices, self.table, self.bodies = kind, slices, table, bodies
        self.issues = set(issues)
        cts = [s[0] for s in slices]
        once = _once(cts)
        if len(once) < len(cts):
            self.issues.add("dups")
        if once != sorted(once):
            self.issues.add("order")


@functools.lru_cache(maxsize=8)
def layout(d: bytes):
    """The Layout of a thin Mach-O, a universal file or an ar archive of Mach-O objects; None for any other file."""
    h = _thin(d)
    if h is not None:
        return Layout("thin", [h], [], [d], ())
    if d[:4] in FAT and M._fat_count(d) is not None:
        n = M._fat_count(d)
        wide = d[3] == 0xBF
        width = 32 if wide else 20
        if n > MAX_SLICES or 8 + n * width > len(d):
            U("the fat_arch table does not fit the file")
        slices, table, bodies, issues = [], [], [], set()
        for k in range(n):
            o = 8 + k * width
            if wide:
                ct, st, off, size = struct.unpack_from(">IIQQ", d, o)
            else:
                ct, st, off, size = struct.unpack_from(">IIII", d, o)
            table.append((ct, st, None))
            body = d[off:off + size] if size and off + size <= len(d) else b""
            sh = _thin(body)
            if sh is not None:
                if sh[0] != ct:
                    issues.add("mismatch")
                slices.append(sh)
                bodies.append(body)
                continue
            objs = _ar_objects(body) if body.startswith(AR) else []
            if objs:
                issues.add("archive")
                slices.extend(oh for oh, _ in objs)
                continue
            issues.add("table")
            slices.append((ct, st, None))
        return Layout("fat", slices, table, bodies, issues)
    if d.startswith(AR):
        objs = _ar_objects(d)
        if not objs:
            return None
        return Layout("archive", [oh for oh, _ in objs], [], [], ("archive",))
    return None


def _once(xs):
    seen, out = set(), []
    for x in xs:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _js(v) -> str:
    return json.dumps(v, separators=(",", ":"))


def _hexes(xs) -> str:
    return _js([f"0x{x & 0xFFFFFFFF:08x}" for x in xs])


def arch(ct: int, st: int):
    """The arch name of (cputype, cpusubtype) as lipo and file(1) print it, or None for one not listed."""
    st &= 0x00FFFFFF
    if ct == 7:
        return "i386"
    if ct == 0x01000007:
        return "x86_64h" if st == 8 else "x86_64"
    if ct == 0x0100000C:
        return "arm64e" if st == 2 else "arm64"
    if ct == 0x0200000C:
        return "arm64_32"
    if ct == 12:
        return ARM_SUB.get(st, "arm")
    if ct == 18:
        return "ppc"
    if ct == 0x01000012:
        return "ppc64"
    return None


def _layout(d: bytes):
    lay = layout(d)
    if lay is None:
        U("not a Mach-O file, a universal file or an archive of Mach-O objects")
    return lay


def _cpu_set_reader(asked: str):
    """The extractor of one name of the CPU type set: judged under KEY for PROPERTY alone, every other
    name under its own candidate key (nothing accepted there: unsure)."""
    base = "metadata.format/" + asked

    def read(n, d):
        lay = _layout(d)
        cts = [s[0] for s in lay.slices]
        once = _once(cts)
        if not lay.issues:
            pairs = [("cpu_type_hex", _hexes(once))]
            names = [arch(c, s) for c, s, _ in lay.slices]
            if all(names):
                pairs.append(("arch_name", _js(_once(names))))
            if all(c in M.MACHO_CPU for c in once):
                pairs.append(("cpu_type_constant", _js([M.MACHO_CPU[c] for c in once])))
            pairs += [("cpu_type_integer", _js(once)), ("comma", ",".join(f"0x{c:08x}" for c in once))]
            return M.ledger_forms(M.labels.candidate_key(base), pairs, "", JUDGED_KINDS)
        shape = "+".join(sorted(lay.issues))
        pairs = [("file_order", _hexes(once)), ("sorted", _hexes(sorted(once))), ("every_slice", _hexes(cts))]
        if "mismatch" in lay.issues:
            pairs.append(("fat_table", _hexes(_once([t[0] for t in lay.table]))))
        return M.ledger_forms(M.labels.candidate_key(f"{base}+{shape}"), pairs, shape, JUDGED_KINDS)
    return read


def _subtype_reader(asked: str):
    key = "metadata.format/" + asked

    def read(n, d):
        lay = _layout(d)
        raw = _once([s[1] for s in lay.slices])
        masked = _once([s & 0x00FFFFFF for s in raw])
        return M.ledger_forms(M.labels.candidate_key(key), [
            ("cpu_subtype_hex", _hexes(raw)), ("cpu_subtype_masked_hex", _hexes(masked)),
            ("cpu_subtype_integer", _js(masked))])
    return read


def _arch_set(n, d):
    lay = _layout(d)
    names = [arch(c, s) for c, s, _ in lay.slices]
    if not all(names):
        U("a CPU type has no arch name here")
    return _once(names)


def _slice_count(n, d):
    lay = _layout(d)
    if lay.kind == "fat":
        return len(lay.table)
    if lay.kind == "thin":
        raise M.Ambiguous([("thin_one", "1"), ("thin_zero", "0")])
    U("an archive has no slices")


def _is_universal(n, d):
    return _layout(d).kind == "fat"


def _filetype_set(n, d):
    lay = _layout(d)
    out = []
    for _, _, ft in lay.slices:
        if ft is None:
            U("a slice could not be read")
        if ft not in M.MACHO_FILETYPE:
            U(f"filetype {ft} has no MH_ name here")
        out.append(M.MACHO_FILETYPE[ft])
    return _once(out)


def _uuid_set(n, d):
    lay = _layout(d)
    if lay.kind == "archive" or "table" in lay.issues or "archive" in lay.issues:
        U("a slice is not a thin Mach-O")
    out = []
    for body in lay.bodies:
        hit = RM._macho_one(body, 0x1B)
        if hit:
            u = hit[2][8:24].hex()
            out.append(f"{u[:8]}-{u[8:12]}-{u[12:16]}-{u[16:20]}-{u[20:]}")
    return out or None


def fat_table(d: bytes):
    """[(cputype, cpusubtype, offset, size, align)] of a fat or fat64 file's fat_arch table, in table order."""
    if not _is_fat(d):
        U("not a universal (fat) file: no fat_arch table")
    n = M._fat_count(d)
    wide = d[3] == 0xBF
    width = 32 if wide else 20
    if n > MAX_SLICES or 8 + n * width > len(d):
        U("the fat_arch table does not fit the file")
    out = []
    for k in range(n):
        o = 8 + k * width
        out.append(struct.unpack_from(">IIQQI" if wide else ">IIIII", d, o))
    return out


def _fat_offsets(n, d):
    return [e[2] for e in fat_table(d)]


def _fat_sizes(n, d):
    return [e[3] for e in fat_table(d)]


def _fat_aligns(n, d):
    """The align column as stored (a power of two's exponent) first, then as bytes."""
    aligns = [e[4] for e in fat_table(d)]
    if any(a > 63 for a in aligns):
        U("an align field is not a power-of-two exponent")
    return [("json_compact", _js(aligns)), ("bytes", _js([1 << a for a in aligns])),
            ("comma", ",".join(str(a) for a in aligns))]


MAGIC_FNS = set()   # the macho magic readers' extractors (of a number class), filled by register()


def _renamed(options, suffix):
    return [(n + suffix, t) for n, t in options]


def fat_options(p, name: str, d: bytes):
    """The Day 21 final prep, asked by the options_for hook (register()) before the core reading, with the asking
    property `p` (so its class, u32hex for a `_u32_hex` name, is the one that writes the value). For a universal
    file only, else None (the core reading stands):
      - a magic reader: the fat magic itself (0xcafebabe, 0xcafebabf) in p's class, the slices' own magic second
        ('<form>+slices') where every thin slice agrees, as a keyed_forms value judged under '<key>+fat';
      - a per-slice reader (wrap_thin_readers) whose own extractor gives nothing for the file and whose every thin
        slice gives one value: that value in p's class, every form named '<form>+first_slice' (macho.flags_u32_hex
        offers 0x00200085 first, as on a thin file). Slices that differ are per_slice()'s reading, as before."""
    if not _is_fat(d):
        return None
    fmt = M.FORMATS[p.fmt][1]
    if p.fn in MAGIC_FNS:
        magic = struct.unpack_from(">I", d, 0)[0]
        opts = list(fmt(magic))
        lay = _layout_or_none(d)
        if lay is not None and lay.bodies and not ({"table", "archive"} & lay.issues):
            inner = _each(p.fn, name, lay.bodies)
            if inner and inner[0] is not None and all(x == inner[0] for x in inner):
                have = {t for _, t in opts}
                more = [o for o in _renamed(list(fmt(inner[0]))[:1], "+slices") if o[1] not in have]
                opts = opts[:1] + more + opts[1:]
        out = M.keyed_forms("+fat", opts)
        out.shape = "fat"
        return out, False
    base = getattr(p.fn, "per_slice_of", None)
    if base is None:
        return None
    try:
        if base(name, d) is not None:
            return None             # the extractor reads the universal file itself
    except M.Unknown:
        pass
    except Exception:
        return None
    lay = _layout_or_none(d)
    if lay is None or not lay.bodies or {"table", "archive"} & lay.issues:
        return None
    raws = _each(base, name, lay.bodies)
    if not raws or raws[0] is None or any(r != raws[0] for r in raws[1:]):
        return None
    return _renamed(list(fmt(raws[0])), "+first_slice"), False


def _layout_or_none(d):
    try:
        return layout(d)
    except M.Unknown:
        return None


def _each(fn, name, bodies):
    out = []
    for b in bodies:
        try:
            out.append(fn(name, b))
        except Exception:
            out.append(None)
    return out


def _options_hook(orig):
    """properties_strict.options_for with fat_options() asked first for a universal file."""
    def options_for(p, name, data):
        if isinstance(data, (bytes, bytearray)) and data[:4] in FAT:
            try:
                got = fat_options(p, name, bytes(data))
            except Exception:
                got = None          # this pack's failure costs its own reading, never the core one
            if got is not None:
                return got
        return orig(p, name, data)
    options_for.macho_hook = orig
    return options_for


# ------------------------------------------------------------------ the per-slice reading of thin-only readers

def _is_fat(d: bytes) -> bool:
    return d[:4] in FAT and M._fat_count(d) is not None


def _slice_options(fn, fmt, n, body):
    """The formatted options of one slice, [] when the reader cannot read it."""
    try:
        raw = fn(n, body)
    except M.Ambiguous as e:
        return [(a, b) for a, b in e.options if isinstance(a, str) and isinstance(b, str)]
    except Exception:
        return []
    if raw is None:
        return []
    try:
        return list(M.FORMATS[fmt][1](raw))
    except Exception:
        return []


def per_slice(fn, fmt):
    """`fn` with a universal file read slice by slice where `fn` itself gives nothing for it: the first
    slice's forms, unsure ('<form>+first_slice'), and every slice's first form as a JSON list when the
    slices differ. Anything else is `fn`'s own answer, unchanged."""
    def read(n, d):
        try:
            v = fn(n, d)
        except M.Unknown:
            if not _is_fat(d):
                raise
            v, failed = None, True
        else:
            if v is not None or not _is_fat(d):
                return v
            failed = False
        try:
            lay = layout(d)
        except M.Unknown:
            lay = None
        if lay is None or not lay.bodies or "table" in lay.issues or "archive" in lay.issues:
            if failed:
                U("a universal file whose slices are not all thin Mach-O files")
            return None
        per = [_slice_options(fn, fmt, n, b) for b in lay.bodies]
        if not per[0]:
            if failed:
                U("the first slice does not settle it")
            return None
        options = [(f"{a}+first_slice", b) for a, b in per[0]]
        firsts = [p[0][1] if p else None for p in per]
        if len(set(firsts)) > 1 and all(f is not None for f in firsts):
            options.append(("json_compact+every_slice", _js(firsts)))
        raise M.Ambiguous(options)
    read.per_slice_of = fn
    return read


def wrap_thin_readers(skip):
    """Every macho.* reader in the registry (other than this pack's), wrapped once per extractor so that its
    aliases keep sharing one function (synonym() groups readers by extractor), with its spec table and its
    tie-free mark carried over."""
    done = {}
    for k, p in list(M.REG.items()):
        if not k.startswith("macho_") or p.fn in skip or getattr(p.fn, "per_slice_of", None) or "magic" in k:
            continue   # a universal file's magic is its own (cafebabe), never a slice's
        fn = done.get(p.fn)
        if fn is None:
            fn = done[p.fn] = per_slice(p.fn, p.fmt)
            if p.fn in M.TIE_FREE:
                M.TIE_FREE.add(fn)
            if p.fn in M.SPEC_FN:
                M.SPEC_FN[fn] = M.SPEC_FN[p.fn]
        M.REG[k] = M.Prop(p.name, fn, p.fmt, p.confirmed, p.bits, p.unit)
    return len(done)


def register(module):
    """properties_strict calls this with its own module object. Returns (names, families) added."""
    global M, RM
    M = module
    RM = getattr(M, "MORE_MODULES", {}).get("readers_more.py")
    before, families = len(M.REG), len(M.FAMILIES)
    mine = set()

    def add(names, fmt, make):
        for name in names:
            if M.canon(name) in M.REG:
                M.MORE_CLASHES.append(name)
                continue
            fn = make(name) if make.__name__.endswith("_reader") else make
            M.prop(name, fmt=fmt)(fn)
            M.TIE_FREE.add(fn)
            mine.add(fn)

    add((PROPERTY,) + ALIASES, "forms", _cpu_set_reader)
    add(SUBTYPE_NAMES, "forms", _subtype_reader)
    add(ARCH_NAMES, "list", _arch_set)
    add(COUNT_NAMES, "integer", _slice_count)
    add(UNIVERSAL_NAMES, "bool", _is_universal)
    add(FILETYPE_NAMES, "list", _filetype_set)
    if RM is not None:
        add(UUID_NAMES, "list", _uuid_set)
    add(OFFSET_NAMES, "intlist", _fat_offsets)     # the Day 21 final prep: the fat_arch table's columns
    add(SIZE_NAMES, "intlist", _fat_sizes)
    add(ALIGN_NAMES, "forms", _fat_aligns)
    MINE.update(mine)
    if M.canon(PROPERTY) in M.REG and M.REG[M.canon(PROPERTY)].fn in mine:
        M.JUDGED_LEDGER[M.canon(PROPERTY)] = M.labels.candidate_key(KEY)
        M.JUDGED_KINDS[M.canon(PROPERTY)] = JUDGED_KINDS
    wrap_thin_readers(mine)
    MAGIC_FNS.update(p.fn for k, p in M.REG.items() if k.startswith("macho_") and "magic" in k and p.fn not in mine
                     and p.fmt in M.HEX_CLASSES + ("integer",))
    g = M.lookup.__globals__   # properties_strict's own globals: the asking property's class reaches a fat file
    if not getattr(g["options_for"], "macho_hook", None):
        g["options_for"] = _options_hook(g["options_for"])
    return (len(M.REG) - before, len(M.FAMILIES) - families)
