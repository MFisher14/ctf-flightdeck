#!/usr/bin/env python3
"""One grammar for the Binary lane's question ids (B-216).

  .venv/bin/python solvers/binary/field_grammar.py ID [ID ...]   how each id parses

At Huntress the Binary lane stopped whenever a day asked a known fact under a new id shape: Day 9's
`hcfg_offset`, Day 10's `has_hcfg_section`, Day 15's per-build `d15_analysis_<role>_<field>`, Day 17's
COFF symbol forms. Each shape was then taught to one reader (field_catalog's `has_(\\w+)_section`,
generic's `_role_split_qid`, evidence's per-prefix SYMBOL_FIELDS). This module is the one parser every
reader can share, so a new spelling of a known family is read once, here. The readers that keep a vocabulary
of their own split and name through it: generic._role_split_qid is split_end() over generic's header fields,
field_catalog's has_<x>_section rule reads its section name through family(), and evidence.symbol_field and
speed_solver read parse().

    [set<N>.]<prefix>_<area>_[<role>_]<field>

  prefix   the day (`d17`) or any lowercase scope word without `_`
  area     analysis | artifact | structural | ... (any word; `analysis` and `artifact` are the lane's)
  role     a per-build word in front of the field (`d16_analysis_direct_machine`): found only when the
           field behind it belongs to a family that ends an id (see ROLE_ENDINGS), or when the caller
           passes the build words its member names carry (`builds=`), longest first
  field    the rest, parsed into a family:

  family        shapes (all equivalent spellings map to one family, name and attr)
  sha256        sha256_<n>, <n>_sha256, sha256 (attr: n)
  config        config_<member> (name: member)
  xor_key       xor_key_hex, xor_key
  has_section   has_<name>_section, has_section_<name>, <name>_section_present|exists,
                section_<name>_present|exists, contains_<name>_section (name: section, normalised)
  section_attr  <name>_section_<attr>, section_<name>_<attr> (attr: offset, size, address, flags, ...)
  symbol        has_symtab, is_stripped (attr presence); symbol_count, <x>_symbol_count (count);
                <x>_symbols (list); <x>_symbol, exported_symbol (name); recover_code and
                <x>_return_value (value: a constant read through a symbol the table names)
  overlay       has_overlay|trailer|footer, <overlay|trailer|footer|tail>_<attr> (attr: offset, size,
                length, magic, tag, sha256, record_count, present)
  has_mark      has_<x> (any other presence fact)
  count         <x>_count, num_<x>, number_of_<x>
  header        a header word (HEADER_WORDS: format, machine, elf_class, entry_point, ...)
  other         anything else: the grammar names no family, readers fall back to their own rules

parse() never raises on a string; a non-string or empty id parses to family `other` with no prefix.
Nothing here reads a file: which value a family has is the readers' business (speed_solver.py).
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field as _dc_field

SET_PREFIX = re.compile(r"^set(\d+)\.", re.I)
PREFIX = re.compile(r"[a-z][a-z0-9]*")
AREAS = ("analysis", "artifact", "structural", "static", "dynamic", "runtime", "meta")

HEADER_WORDS = frozenset({
    "format", "machine", "architecture", "arch", "elf_class", "elf_type", "endianness", "byte_order",
    "entry_point", "entry", "bits", "abi", "osabi", "file_type", "filetype", "subsystem", "image_base",
    "timestamp", "magic", "cpu", "cputype", "cpu_type", "interpreter", "linkage", "is_pie", "is_dll",
    "is_static", "pe_magic", "section_count", "segment_count", "language", "runtime", "compiler",
})

SECTION_ATTRS = {
    "offset": "offset", "file_offset": "offset", "raw_offset": "offset", "start": "offset",
    "size": "size", "length": "size", "raw_size": "size", "file_size": "size",
    "virtual_address": "address", "vaddr": "address", "address": "address", "addr": "address", "rva": "address",
    "va": "address", "flags": "flags", "characteristics": "flags", "type": "type", "index": "index",
    "name": "name", "sha256": "sha256", "entropy": "entropy",
}
OVERLAY_WORDS = ("overlay", "trailer", "footer", "tail")
OVERLAY_ATTRS = {
    "offset": "offset", "start": "offset", "file_offset": "offset", "size": "size", "length": "size",
    "len": "size", "bytes": "size", "magic": "tag", "tag": "tag", "sha256": "sha256", "present": "present",
    "exists": "present", "record_count": "record_count", "count": "record_count",
}

# The families whose shape ends an id unambiguously, so a role may stand in front of them.
ROLE_ENDINGS = ("config", "xor_key", "has_section", "section_attr", "header", "symbol", "sha256")


@dataclass(frozen=True)
class FieldId:
    qid: str
    set: int | None
    prefix: str | None
    area: str | None
    role: str | None
    field: str                  # the id after prefix, area and role
    family: str
    name: str | None = None     # the member, section or mark the family is about
    attr: str | None = None     # which fact of it: offset, size, presence, count, n, ...
    notes: tuple = _dc_field(default=())

    def canonical(self) -> str:
        """The family's one spelling of this field, without prefix, area or role (`has_hcfg_section` for
        `section_hcfg_present`), so readers keyed on the old spelling answer every synonym."""
        f, n, a = self.family, self.name, self.attr
        if f == "sha256":
            return f"sha256_{a}" if a else "sha256"
        if f == "config":
            return f"config_{n}"
        if f == "xor_key":
            return "xor_key_hex"
        if f == "has_section":
            return f"has_{n}_section"
        if f == "section_attr":
            return f"{n}_section_{a}"
        if f == "overlay":
            return f"{n}_{a}"
        if f == "has_mark":
            return f"has_{n}"
        if f == "count":
            return f"{n}_count"
        return self.field


def norm_section(name: str) -> str:
    """A section name as the readers compare it: lowercase, leading dots and underscores dropped."""
    return str(name or "").lower().rstrip("\x00 ").lstrip("._")


def _family(rest: str):
    """(family, name, attr) of a field with no role in front, or ("other", None, None)."""
    r = rest.lower()
    m = re.fullmatch(r"sha256(?:_(\d+))?|(\d+)_sha256", r)
    if m:
        return "sha256", None, (m.group(1) or m.group(2))
    m = re.fullmatch(r"config_(.+)", r)
    if m:
        return "config", m.group(1), None
    if r in ("xor_key_hex", "xor_key"):
        return "xor_key", None, None
    if r in ("has_symtab", "is_stripped", "stripped", "has_symbols", "has_symbol_table"):
        return "symbol", None, "presence"
    for pat in (r"has_(\w+?)_section", r"has_section_(\w+)", r"(\w+?)_section_(?:present|exists)",
                r"section_(\w+?)_(?:present|exists)", r"contains_(\w+?)_section"):
        m = re.fullmatch(pat, r)
        if m and norm_section(m.group(1)):
            return "has_section", norm_section(m.group(1)), "presence"
    attrs = "|".join(sorted(SECTION_ATTRS, key=len, reverse=True))
    m = re.fullmatch(rf"(\w+?)_section_({attrs})", r) or re.fullmatch(rf"section_(\w+?)_({attrs})", r)
    if m and norm_section(m.group(1)) and m.group(1) not in ("has", "is"):
        return "section_attr", norm_section(m.group(1)), SECTION_ATTRS[m.group(2)]
    m = re.fullmatch(r"has_(" + "|".join(OVERLAY_WORDS) + r")", r)
    if m:
        return "overlay", m.group(1), "present"
    oattrs = "|".join(sorted(OVERLAY_ATTRS, key=len, reverse=True))
    m = re.fullmatch(r"(" + "|".join(OVERLAY_WORDS) + rf")_({oattrs})", r)
    if m:
        return "overlay", m.group(1), OVERLAY_ATTRS[m.group(2)]
    if re.fullmatch(r"(?:\w+_)?symbol_count|symbols_count|num_symbols|number_of_symbols", r):
        return "symbol", (r[:-len("_symbol_count")] or None) if r.endswith("_symbol_count") else None, "count"
    m = re.fullmatch(r"(\w+_)?symbols", r)
    if m:
        return "symbol", (m.group(1) or "").rstrip("_") or None, "list"
    m = re.fullmatch(r"(\w+_)?symbol(?:_name)?", r)
    if m:
        return "symbol", (m.group(1) or "").rstrip("_") or None, "name"
    m = re.fullmatch(r"recover_code|(\w+?)_(?:return_value|returns|return_constant)", r)
    if m:
        return "symbol", m.group(1) or "recover_code", "value"
    if r in HEADER_WORDS:
        return "header", r, None
    m = re.fullmatch(r"has_(\w+)", r)
    if m:
        return "has_mark", m.group(1), "presence"
    m = re.fullmatch(r"(\w+?)_count|num_(\w+)|number_of_(\w+)", r)
    if m:
        return "count", m.group(1) or m.group(2) or m.group(3), "count"
    return "other", None, None


def _role_split(rest: str, endings=ROLE_ENDINGS):
    """(role, (family, name, attr), field) for `<role>_<field>` whose field is one of `endings`' families,
    the shortest role (the longest field) first; None when no such split exists."""
    segs = rest.split("_")
    for i in range(1, len(segs)):
        field = "_".join(segs[i:])
        fam = _family(field)
        if fam[0] == "sha256" and not fam[2]:
            continue        # a bare trailing sha256 is a digest OF something (`handler_symbols_sha256`), not a role's file
        if fam[0] in endings:
            return "_".join(segs[:i]), fam, field
    return None


def family(field) -> tuple:
    """(family, name, attr) of a bare field (no prefix, area or role in front), as parse() reads it. The readers
    that keep their own rule tables (field_catalog's has_<x>_section rule) read a field's name through it, so a
    section name means one thing to every reader."""
    return _family(str(field or ""))


ROLE_CONFIG = re.compile(r"(?:^|_)(config_[A-Za-z0-9_]+)$")


def split_end(qid, fields, area: str = "analysis") -> tuple:
    """(role, `<area>_<field>`) of a per-build id `<prefix>_<area>_<role>_<field>` whose trailing field is
    `config_<name>` or one of `fields` (matched at the END, in the order given: pass them longest first), the role
    the segment(s) in front; (None, None) for an id outside `area`, with no role in front, or that ends in none of
    them. A reader that answers a fixed vocabulary per build (generic._role_split_qid, row 307) splits its ids
    here: the id decides the build, never a member name. Case is kept: the vocabulary is the judge's."""
    qid = str(qid or "")
    body = qid.split("_", 1)[1] if "_" in qid else ""
    if not body.startswith(area + "_"):
        return None, None
    rest = body[len(area) + 1:]
    m = ROLE_CONFIG.search(rest)
    if m:
        role = rest[:m.start(1)].rstrip("_")
        return (role, f"{area}_{m.group(1)}") if role else (None, None)
    for f in fields:
        if rest == f:
            return None, None                   # no role in front: a prefix-level id
        if rest.endswith("_" + f):
            return rest[:-(len(f) + 1)], f"{area}_{f}"
    return None, None


def parse(qid, builds=None) -> FieldId:
    """The FieldId of a question id. `builds`: the build words the prefix's member names carry
    (lowercase, `_`-joined); a role is then preferred from them, longest first."""
    if not isinstance(qid, str) or not qid.strip():
        return FieldId(str(qid), None, None, None, None, "", "other")
    text = qid.strip()
    sid = None
    m = SET_PREFIX.match(text)
    if m:
        sid, text = int(m.group(1)), text[m.end():]
    head, _, body = text.partition("_")
    prefix = head.lower() if PREFIX.fullmatch(head.lower()) and body else None
    rest = body if prefix else text
    area = None
    a, _, after = rest.partition("_")
    if a.lower() in AREAS and after:
        area, rest = a.lower(), after
    rest_l = rest.lower()
    notes = []
    for b in sorted({str(w).lower().strip("_") for w in builds or () if w}, key=len, reverse=True):
        if rest_l.startswith(b + "_"):
            fam = _family(rest_l[len(b) + 1:])
            if fam[0] != "other":
                return FieldId(qid, sid, prefix, area, b, rest_l[len(b) + 1:], *fam, notes=("role from builds",))
    fam = _family(rest_l)
    if fam[0] in ("other", "has_mark", "count"):
        # An id that is no family as a whole may carry a role before any family; one that already reads
        # as a presence mark or a count only before a family that ends an id unambiguously.
        split = _role_split(rest_l, ROLE_ENDINGS + (("has_mark", "count") if fam[0] == "other" else ()))
        if split is not None:
            role, fam2, field = split
            if builds is not None and role not in {str(w).lower() for w in builds}:
                notes.append(f"role {role!r} is not a build word of the members")
            return FieldId(qid, sid, prefix, area, role, field, *fam2, notes=tuple(notes))
    return FieldId(qid, sid, prefix, area, None, rest_l, *fam, notes=tuple(notes))


def _main(argv) -> int:
    if not argv:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    for qid in argv:
        f = parse(qid)
        print(f"{qid}: family={f.family} name={f.name} attr={f.attr} role={f.role} prefix={f.prefix} "
              f"area={f.area} canonical={f.canonical()}" + (f" notes={list(f.notes)}" if f.notes else ""))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
