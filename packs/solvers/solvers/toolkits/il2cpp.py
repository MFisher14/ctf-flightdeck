#!/usr/bin/env python3
"""Toolkit il2cpp: an offline reader for a Unity IL2CPP `global-metadata.dat` (reversing / mobile
insurance). Built as a NEW module beside the category toolkits (an idea-only hedge for a reversed
Unity game or app where the managed C# logic is AOT-compiled to native code and the only recoverable
source-level facts live in the metadata blob). Offline, static, stdlib only. Nothing is executed and
no byte of a delivery is ever run.

What it recovers, and nothing more:
  - the embedded string LITERALS, each read byte-exact at its (dataIndex, length) from the string
    literal table and the literal data blob;
  - the IDENTIFIER names of the type / method / field definition tables, read null-terminated from
    the string heap at each definition's nameIndex.
It parses the header (magic 0xFAB11BAF), the string-literal table and its data blob, the identifier
string heap, and the type/method/field definition tables. A paired `libil2cpp.so` / `GameAssembly.dll`
binary, when it ships beside the metadata, is NOTED (its format) but no code or address is read from it:
every source-level fact comes from the metadata.

NEVER-WRONG boundary (AGENTS.md "Uncertain answers", "New categories"):
  - A string LITERAL is a deterministic byte-exact read at a fixed (offset, length). It is PLAIN-eligible:
    returned plain when it decodes cleanly as UTF-8, or as a `labels.candidates` of its renderings
    (utf-8 / latin-1 / hex) when the bytes do not decode cleanly.
  - The metadata VERSION and the string-LITERAL table count are deterministic byte-exact reads
    (the literal table's struct size is fixed across v24-27): PLAIN-eligible.
  - A method / field / type definition COUNT is NOT byte-exact: the count of validated names
    undercounts (an empty/out-of-bounds/non-ASCII name is dropped), and the raw table-entry count
    (region size // struct stride) depends on the version-inferred stride. It is always UNSURE:
    `labels.candidates(key, [("table_entries", ...), ("names_read", ...)])`, never plain.
  - A type / method / field NAME is an author-chosen label whose spelling and namespace selection are
    unjudged, so it is always UNSURE: `labels.candidates(key, [(rendering, value), ...])`, never plain.
  - An unsupported metadata version, offsets inconsistent across the tables, or a truncated heap/blob
    yield None for the affected id. A behaviour question (what a method DOES) is None. A flag found in
    the literals is text-is-data and is None.

Bounded: at most MAX_FILE bytes, MAX_ENTRIES table entries scanned, MAX_* reported. Fail-closed: a
field out of the file's bounds, a nameIndex past the heap, or a literal past its data blob is dropped,
never guessed.

Keys: name candidates are offered under the `binary` lane prefix (IL2CPP global-metadata is a native
reversing artifact and `binary` is the reversing lane; `il2cpp` is not a registered toolkit prefix in
solvers/common/labels.py, so a `binary.il2cpp_*` key keeps every name an UNSURE candidate that
tools/verify.py probes on the untimed base). Literals, the version and counts carry no label.

This module is NOT wired into the toolkit registry (solvers/toolkits/registry.py) or
solvers/common/labels.TOOLKIT_PREFIXES: an integrator folds it in after review (see the module note at
the bottom). It exposes report(files), solve_set(questions, files, ctx), signals(questions, files) and
a CLI, so it already fits the solver contract.
"""
import json
import re
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(1, str(COMMON))
import labels    # noqa: E402

try:
    import triage    # noqa: E402
    _ARROW = triage.ARROW
except Exception:  # noqa: BLE001 - the module must load even if triage is unavailable
    triage = None
    _ARROW = " -> "

# ``binary`` is the lane a name candidate is remembered under; see the module docstring.
KEY = "binary"
MAGIC = 0xFAB11BAF
MAGIC_LE = struct.pack("<I", MAGIC)

MAX_FILE = 256 * 1024 * 1024
MAX_ENTRIES = 200_000          # table entries walked for names (bounded compute)
MAX_LITERAL_BYTES = 1 << 16    # a single literal longer than this is reported truncated, never read whole
MAX_REPORT = 64                # literals / names carried in a report()

# Supported metadata major versions. The early header fields this reader needs
# (sanity, version, stringLiteral, stringLiteralData, the string heap, methods, fields,
# typeDefinitions) share one stable ordering across IL2CPP versions 24 and 27. Versions this
# table does not name are UNSUPPORTED and every id is None (never-wrong: an unsupported version is
# None, not a guess). Each value is the int32 WORD index (4 bytes) of a header field; a paired
# (offset, size-in-bytes) field is given as a tuple.
_CLASSIC = {
    "string_literal": (2, 3),        # Il2CppStringLiteral[]  {uint32 length; int32 dataIndex} (8 bytes each)
    "string_literal_data": (4, 5),   # char[] literal bytes
    "string": (6, 7),                # identifier string heap, null-terminated UTF-8
    "methods": (12, 13),             # Il2CppMethodDefinition[]
    "fields": (24, 25),              # Il2CppFieldDefinition[]
    "type_definitions": (40, 41),    # Il2CppTypeDefinition[]
}
# Definition-struct stride (bytes) and the WORD offset of nameIndex / namespaceIndex within it.
# Only used to ENUMERATE names, which are UNSURE: a wrong stride yields a nameIndex that fails the
# heap-bounds / identifier check and is dropped, never emitted as a wrong plain answer.
_DEF = {
    "type_definitions": {"stride": 92, "name": 0, "namespace": 4},
    "methods": {"stride": 52, "name": 0, "namespace": None},
    "fields": {"stride": 12, "name": 0, "namespace": None},
}
_DEF_V27 = {
    **_DEF,
    "type_definitions": {**_DEF["type_definitions"], "stride": 88},
    "methods": {**_DEF["methods"], "stride": 32},
}
LAYOUTS = {24: {"words": _CLASSIC, "defs": _DEF}, 27: {"words": _CLASSIC, "defs": _DEF_V27}}

_IDENT = re.compile(r"\A[\x20-\x7e]{1,255}\Z")   # a name is printable ASCII (incl. <>.`$ of compiler names)


# ---------------------------------------------------------------------------- parsing (fail-closed)

def _u32(data: bytes, word: int):
    off = word * 4
    if off < 0 or off + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, off)[0]


def _i32(data: bytes, byte_off: int):
    if byte_off < 0 or byte_off + 4 > len(data):
        return None
    return struct.unpack_from("<i", data, byte_off)[0]


def _region(data: bytes, pair):
    """(offset, size) read from the header word pair, validated against the file. None when the field
    cannot be read or the region falls outside the file (inconsistent / truncated)."""
    off, size = _u32(data, pair[0]), _u32(data, pair[1])
    if off is None or size is None:
        return None
    if off > len(data) or size > len(data) or off + size > len(data):
        return None
    return (off, size)


def _read_literals(data: bytes, words) -> dict:
    """{'entries': [(dataIndex, length)], 'literals': [{'index','offset','length','text','bytes_hex',
    'clean'}], 'truncated': bool}. None when the literal table or its data blob is inconsistent."""
    tbl = _region(data, words["string_literal"])
    blob = _region(data, words["string_literal_data"])
    if tbl is None or blob is None:
        return None
    toff, tsize = tbl
    boff, bsize = blob
    count = tsize // 8
    if count > MAX_ENTRIES:
        return None
    out = {"entries": [], "literals": [], "truncated": False}
    for i in range(count):
        length, data_index = struct.unpack_from("<Ii", data, toff + i * 8)
        out["entries"].append((data_index, length))
        # Fail-closed: the literal must sit wholly inside the data blob (and the file).
        if data_index < 0 or length < 0 or data_index + length > bsize:
            continue
        start = boff + data_index
        if start < 0 or start + length > len(data):
            continue
        if length > MAX_LITERAL_BYTES:
            out["literals"].append({"index": i, "offset": start, "length": length,
                                    "text": None, "bytes_hex": None, "clean": False, "oversized": True})
            out["truncated"] = True
            continue
        raw = data[start:start + length]
        try:
            text = raw.decode("utf-8")
            out["literals"].append({"index": i, "offset": start, "length": length,
                                    "text": text, "bytes_hex": raw.hex(), "clean": True})
        except UnicodeDecodeError:
            out["literals"].append({"index": i, "offset": start, "length": length,
                                    "text": None, "bytes_hex": raw.hex(), "clean": False})
    return out


def _read_string(heap: bytes, name_index):
    """A null-terminated UTF-8 identifier at `name_index` in the heap, validated. None when it is out
    of bounds, unterminated, undecodable, or not a printable identifier."""
    if name_index is None or name_index < 0 or name_index >= len(heap):
        return None
    end = heap.find(b"\x00", name_index)
    if end == -1:                       # unterminated: a truncated heap
        return None
    raw = heap[name_index:end]
    if not raw or len(raw) > 255:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not _IDENT.match(text):
        return None
    return text


def _table_entry_count(data: bytes, words, defs, table: str):
    """The BYTE-EXACT entry count of a definition table: region size // struct stride. This is the
    count the question asks ("how many methods are defined"), NOT len(_read_names(...)), which drops
    every entry whose name fails heap/identifier validation. It is still STRIDE-DEPENDENT (the stride
    is version-inferred in `_DEF`, not read from the file), so it is never answered plain. None when
    the table region or the stride is inconsistent."""
    tbl = _region(data, words[table])
    if tbl is None:
        return None
    stride = defs[table].get("stride", 0)
    if stride <= 0:
        return None
    return tbl[1] // stride


def _read_names(data: bytes, words, defs, table: str) -> list:
    """[{'index','name','namespace'}] for a definition table, each name validated against the heap.
    [] when the heap or the table region is inconsistent. Bounded by MAX_ENTRIES."""
    heapr = _region(data, words["string"])
    tbl = _region(data, words[table])
    if heapr is None or tbl is None:
        return []
    hoff, hsize = heapr
    heap = data[hoff:hoff + hsize]
    toff, tsize = tbl
    spec = defs[table]
    stride = spec["stride"]
    if stride <= 0:
        return []
    count = min(tsize // stride, MAX_ENTRIES)
    out = []
    for i in range(count):
        base = toff + i * stride
        name = _read_string(heap, _i32(data, base + spec["name"]))
        ns = None
        if spec["namespace"] is not None:
            ns = _read_string(heap, _i32(data, base + spec["namespace"]))
        if name is not None:
            out.append({"index": i, "name": name, "namespace": ns})
    return out


def parse_metadata(data: bytes) -> dict:
    """The facts of one global-metadata.dat, fail-closed. None when it is not an IL2CPP metadata file.
    A supported, consistent file returns {'version','supported',...}; an unsupported version returns
    {'version','supported':False} with no facts; a truncated/inconsistent file returns the facts it
    could validate and None for the rest."""
    if not isinstance(data, (bytes, bytearray)):
        return None
    data = bytes(data)
    if len(data) < 8 or len(data) > MAX_FILE:
        return None
    sanity = _u32(data, 0)
    if sanity != MAGIC:
        return None
    version = _u32(data, 1)
    rep = {"version": version, "supported": version in LAYOUTS,
           "literals": None, "methods": [], "fields": [], "types": [],
           "counts": {}, "truncated": False}
    layout = LAYOUTS.get(version)
    if layout is None:
        return rep                      # unsupported version: every id is None
    words, defs = layout["words"], layout["defs"]
    lits = _read_literals(data, words)
    rep["literals"] = lits
    if lits is not None:
        rep["truncated"] = rep["truncated"] or lits["truncated"]
    rep["methods"] = _read_names(data, words, defs, "methods")
    rep["fields"] = _read_names(data, words, defs, "fields")
    rep["types"] = _read_names(data, words, defs, "type_definitions")
    rep["counts"] = {
        "string_literals": (len(lits["entries"]) if lits else None),
        "string_literals_read": (len(lits["literals"]) if lits else None),
        # `*_names` is the count of entries whose name VALIDATED (printable-ASCII, in-bounds, decodable):
        # it UNDERCOUNTS whenever an entry's name is empty/index-0, out of bounds, non-ASCII, or read at a
        # wrong per-version stride, so it is never the plain answer to "how many ... are defined".
        "method_names": len(rep["methods"]),
        "field_names": len(rep["fields"]),
        "type_names": len(rep["types"]),
        # `*_entries` is the byte-exact table-entry count (region size // struct stride). It is the count
        # the question asks, but the stride is version-inferred (not read from the file), so it too is
        # offered only as an UNSURE candidate, never plain.
        "method_entries": _table_entry_count(data, words, defs, "methods"),
        "field_entries": _table_entry_count(data, words, defs, "fields"),
        "type_entries": _table_entry_count(data, words, defs, "type_definitions"),
    }
    return rep


# ---------------------------------------------------------------------------- paired binary (noted only)

_BIN_MAGIC = ((b"\x7fELF", "elf"), (b"MZ", "pe"), (b"\xfe\xed\xfa\xce", "mach-o"),
              (b"\xfe\xed\xfa\xcf", "mach-o"), (b"\xce\xfa\xed\xfe", "mach-o"),
              (b"\xcf\xfa\xed\xfe", "mach-o"), (b"\xca\xfe\xba\xbe", "mach-o-fat"))


def _binary_format(data: bytes):
    head = data[:4]
    for magic, fmt in _BIN_MAGIC:
        if head.startswith(magic):
            return fmt
    return None


# ---------------------------------------------------------------------------- one report per file

def _iter_files(files):
    if triage is not None:
        try:
            return list(triage.unique_files(files or {}))
        except Exception:  # noqa: BLE001
            pass
    out, seen = [], set()
    for name in sorted(files or {}):
        data = files[name]
        if isinstance(data, (bytes, bytearray)) and id(data) not in seen:
            seen.add(id(data))
            out.append((name, bytes(data)))
    return out


def report(files) -> list:
    """[(display name, report dict)] for every global-metadata.dat among `files`, plus one row per
    paired IL2CPP binary ({'binary': <format>}). Never raises on a bad file."""
    out = []
    for name, data in _iter_files(files):
        try:
            rep = parse_metadata(data)
        except Exception:  # noqa: BLE001 - one unreadable file never costs the others
            rep = None
        if rep is not None:
            trimmed = dict(rep)
            if rep.get("literals") and rep["literals"].get("literals"):
                trimmed_lits = dict(rep["literals"])
                trimmed_lits["literals"] = rep["literals"]["literals"][:MAX_REPORT]
                trimmed["literals"] = trimmed_lits
            for k in ("methods", "fields", "types"):
                trimmed[k] = rep[k][:MAX_REPORT]
            out.append((name, trimmed))
            continue
        base = Path(name.split(_ARROW)[-1]).name.lower()
        fmt = _binary_format(data)
        if fmt is not None and ("il2cpp" in base or "gameassembly" in base):
            out.append((name, {"binary": fmt, "role": "paired_il2cpp_binary"}))
    return out


# ---------------------------------------------------------------------------- signals

_WORDS = re.compile(r"il2cpp|global[\-_ ]?metadata|unity|gameassembly|libil2cpp|managed|"
                    r"string literal|method name|type definition|field name|metadata version", re.I)


def signals(questions, files) -> float:
    """0..1: a real IL2CPP metadata magic in the bytes plus Unity/IL2CPP vocabulary. 0.0 when nothing
    validates, so it never competes on an unrelated blob."""
    try:
        has_meta = any(r[1].get("version") is not None for r in report(files or {}))
    except Exception:  # noqa: BLE001
        has_meta = False
    if not has_meta:
        return 0.0
    score = 0.5
    hits = set()
    for q in questions or []:
        f = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
        text = " ".join(str(x or "") for x in (q.get("question"), q.get("answer_id") or q.get("id"),
                                                f.get("syntax")))
        hits |= {m.group().lower() for m in _WORDS.finditer(text)}
    score += min(0.4, 0.1 * len(hits))
    return round(min(1.0, score), 2)


# ---------------------------------------------------------------------------- answers (never-guess)

def _meta_for(q, reps):
    """The metadata report a question is about: the one named member, else the single metadata file."""
    metas = [(n, r) for n, r in reps if r.get("version") is not None]
    member = q.get("member") or (str(q.get("artifact") or "").split(_ARROW)[-1] if q.get("artifact") else "")
    base = Path(str(member)).name if member else ""
    if base:
        hit = [r for n, r in metas if Path(n.split(_ARROW)[-1]).name == base]
        if len(hit) == 1:
            return hit[0]
        if hit:
            return None
    return metas[0][1] if len(metas) == 1 else None


def _candidates(field, version, renderings):
    """A name/literal-rendering candidate pick. `renderings` is [(hypothesis, value)], value None
    dropped. None when nothing is left. Never plain before the judge accepts a hypothesis."""
    opts = [(n, v) for n, v in renderings if v]
    if not opts:
        return None
    try:
        return labels.candidates(f"{KEY}.{field}/v{version}", opts)
    except ValueError:
        return None


def _count_candidates(field, version, table_entries, names_read):
    """A definition-table COUNT as an unsure candidate pick (row 346), never plain: the byte-exact
    table-entry count (`table_entries`, the question's own count, but stride-dependent) first, and the
    count of entries whose name validated (`names_read`, which undercounts) second when it differs.
    A count of 0 is a legitimate value and is kept (unlike `_candidates`, which drops falsy renderings).
    None only when neither count could be computed. Scoped to the metadata version in the key."""
    opts = []
    if table_entries is not None:
        opts.append(("table_entries", table_entries))
    if names_read is not None and names_read != table_entries:
        opts.append(("names_read", names_read))
    if not opts:
        return None
    try:
        return labels.candidates(f"{KEY}.{field}/v{version}", opts)
    except ValueError:
        return None


def _name_renderings(entry):
    name = entry.get("name")
    if not name:
        return []
    ns = entry.get("namespace")
    out = [("bare", name)]
    if ns:
        out.append(("namespace_dot", f"{ns}.{name}"))
    return out


def _literal_answer(lit, version):
    """A string literal: plain when it decoded cleanly as UTF-8, else a candidate of its renderings.
    None for an oversized / unread literal."""
    if lit.get("oversized") or lit.get("length") is None:
        return None
    if lit.get("clean") and lit.get("text") is not None:
        return lit["text"]                                  # byte-exact UTF-8: PLAIN-eligible
    hexs = lit.get("bytes_hex")
    if not hexs:
        return None
    raw = bytes.fromhex(hexs)
    renders = [("utf8_replace", raw.decode("utf-8", "replace")),
               ("latin1", raw.decode("latin-1")),
               ("hex", hexs)]
    return _candidates("il2cpp_literal", version, renders)


def _answer_one(q, rep):
    text = str(q.get("question") or "")
    aid = str(q.get("answer_id") or q.get("id") or q.get("qid") or "")
    t = (text + " " + aid).lower()

    def has(*words):
        return any(re.search(w, t) for w in words)

    if rep.get("version") is None or not rep.get("supported"):
        return None                                         # unsupported / unparsed: None
    version = rep["version"]

    if has(r"\bflag\b"):
        return None                                         # text-is-data
    # A behaviour question is about what the code DOES, which the metadata does not hold.
    if has(r"what does", r"\bdoes the\b", r"\bbehaviou?r\b", r"\bpurpose\b", r"\bfunctionalit",
           r"\breturn value\b", r"\bwhat is the (?:result|output|effect)\b"):
        return None

    # Deterministic integer facts: PLAIN-eligible.
    if has(r"metadata version", r"\bversion\b") and not has(r"name", r"literal"):
        return version
    if has(r"how many", r"\bcount\b", r"number of"):
        counts = rep.get("counts") or {}
        if has(r"literal"):
            # The string-literal table count is byte-exact (table size // 8, a struct size fixed
            # across v24-27): PLAIN-eligible.
            n = counts.get("string_literals")
            return n if n is not None else None
        # Definition-table counts are NOT byte-exact: `*_names` undercounts (name-validation-lossy)
        # and `*_entries` depends on the version-inferred stride. Both are ambiguous, so the count is
        # an UNSURE candidate pick (two different evidence-ranked hypotheses), never plain (row 346).
        if has(r"method"):
            return _count_candidates("il2cpp_method_count", version,
                                     counts.get("method_entries"), counts.get("method_names"))
        if has(r"field"):
            return _count_candidates("il2cpp_field_count", version,
                                     counts.get("field_entries"), counts.get("field_names"))
        if has(r"type", r"class"):
            return _count_candidates("il2cpp_type_count", version,
                                     counts.get("type_entries"), counts.get("type_names"))
        return None

    # String literal: byte-exact, PLAIN-eligible. Answer only when it is unambiguous (one literal).
    if has(r"literal", r"embedded string", r"string constant"):
        lits = (rep.get("literals") or {}).get("literals") or []
        usable = [lit for lit in lits if not lit.get("oversized")]
        if len(usable) == 1:
            return _literal_answer(usable[0], version)
        return None                                         # several/none: cannot say which -> None

    # Type / method / field NAME: author label, always UNSURE.
    if has(r"\bmethod\b") and has(r"\bname\b", r"\bcalled\b", r"identifier"):
        names = rep.get("methods") or []
        if len(names) == 1:
            return _candidates("il2cpp_method", version, _name_renderings(names[0]))
        return None
    if has(r"\bfield\b") and has(r"\bname\b", r"\bcalled\b", r"identifier"):
        names = rep.get("fields") or []
        if len(names) == 1:
            return _candidates("il2cpp_field", version, _name_renderings(names[0]))
        return None
    if has(r"\btype\b", r"\bclass\b") and has(r"\bname\b", r"\bcalled\b", r"identifier"):
        names = rep.get("types") or []
        if len(names) == 1:
            return _candidates("il2cpp_type", version, _name_renderings(names[0]))
        return None
    return None


def solve_set(questions, files, ctx) -> dict:
    reps = report(files)
    out = {}
    for q in questions or []:
        qid = q.get("qid") or q.get("id") or q.get("answer_id")
        if qid is None:
            continue
        rep = _meta_for(q, reps)
        try:
            out[qid] = None if rep is None else _answer_one(q, rep)
        except Exception:  # noqa: BLE001 - never-guess: a reader error is None, not a wrong answer
            out[qid] = None
    return out


# ---------------------------------------------------------------------------- CLI (offline triage)

def main(argv) -> int:
    as_json = "--json" in argv
    paths = [a for a in argv if not a.startswith("--")]
    if not paths:
        print("usage: il2cpp.py <global-metadata.dat>... [--json]   (RECON ONLY; names unsure, flag None)",
              file=sys.stderr)
        return 2
    files = {}
    for p in paths:
        try:
            files[p] = Path(p).read_bytes()
        except OSError as e:
            print(f"il2cpp.py: {p}: {e}", file=sys.stderr)
    reps = report(files)
    if as_json:
        print(json.dumps([{"file": n, **r} for n, r in reps], indent=1, default=str))
        return 0
    if not reps:
        print("no IL2CPP global-metadata.dat (magic 0xFAB11BAF) or paired binary recognised")
        return 0
    for name, rep in reps:
        if "binary" in rep:
            print(f"# {name}  [paired IL2CPP binary: {rep['binary']}]  (no code or address is read here)")
            continue
        sup = "supported" if rep.get("supported") else "UNSUPPORTED version (every id None)"
        print(f"# {name}  [IL2CPP metadata v{rep.get('version')}; {sup}]")
        if not rep.get("supported"):
            continue
        c = rep.get("counts") or {}
        print(f"    counts: literals={c.get('string_literals')} (read {c.get('string_literals_read')}) "
              f"methods={c.get('method_names')} fields={c.get('field_names')} types={c.get('type_names')}"
              + ("  [truncated]" if rep.get("truncated") else ""))
        lits = (rep.get("literals") or {}).get("literals") or []
        for lit in lits[:20]:
            shown = lit.get("text") if lit.get("clean") else ("<non-utf8: " + (lit.get("bytes_hex") or "")[:32] + ">")
            print(f"    literal[{lit['index']}] @0x{lit['offset']:x} len={lit['length']}: {shown!r} (PLAIN-eligible)")
        for label, key in (("method", "methods"), ("type", "types"), ("field", "fields")):
            for e in (rep.get(key) or [])[:20]:
                ns = f"{e['namespace']}." if e.get("namespace") else ""
                print(f"    {label} name[{e['index']}]: {ns}{e['name']!r} (UNSURE: author label)")
        print("  literals/version/counts are byte-exact; names are author labels (unsure); the flag is None.")
    return 0


# ---------------------------------------------------------------------------------------------------
# Integrator note: to enrol this as a matched toolkit, add a row to solvers/toolkits/registry.py
# (key "il2cpp"), a page docs/toolkits/il2cpp.md, a prefix to solvers/common/labels.TOOLKIT_PREFIXES
# (with its seed folder) OR keep the `binary` keys used here, and bump the count in
# tests/test_toolkit_registry.py. Until then it is a standalone hand/insurance module.
# ---------------------------------------------------------------------------------------------------

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
