#!/usr/bin/env python3
"""A variant-proof speed solver for the Binary lane: byte facts by family, for any day (B-216).

  .venv/bin/python solvers/binary/speed_solver.py QUESTIONS.json FILE [FILE ...]   answers and reasons

The Huntress Binary lane's Layer 1 closed 14 of 33 modes on Days 20-30; the rest waited for an agent to teach
a reader one more id spelling, container or member name. This solver answers what the bytes prove by the id's
FAMILY (field_grammar.py), whatever the day, the member names or the container's magic:

  sha256          the SHA-256 of the prefix's Nth file, archive order (content_members.select)
  has_section     whether the one image's own section table names the section
  section_attr    that section's offset, size, address, flags, index or name (PE size only when the raw and
                  virtual sizes agree: which one is meant is otherwise not established)
  symbol          presence (has_symtab, is_stripped) from the container's own table (container_symbols.py);
                  count 0, and the literal `none` for a name, list or value, when the container PROVES no
                  table names a function and the question's syntax permits the literal none
  overlay         offset, size, presence and SHA-256 of the bytes after the image (overlay_records.py), and
                  the tag of the one verified record that starts it. Offset and size only when the image end
                  and the lane's judged reading (the magic's position, the member length minus it) agree: no
                  zero fill before the overlay's data, no certificate cut off after it (size)
  config          a member of the one distinct verified JSON record of the prefix's files (overlay_records),
                  any magic; the literal `none` for a member that record lacks, when the syntax permits it.
                  overlay_records sees only the containers it decodes, so in the lane (evidence.speed_filled)
                  this family is asked only when generic.choose_config, the lane's one config selector, finds
                  no CRC-valid container at all in the prefix's files (evidence.lane_config_hold)

Every value is plain because the family fixes its spelling: a number in the form the question asks (decimal;
0x-hex only under a lowercase-hex syntax, nothing under any other hex wording), a yes/no fact only when the
question fixes the pair (an integer, an enum that lists one of the pairs, or a syntax that names true and
false), a name read from the file. Everything else is None with a reason: header names, marks, counts the
lane's other readers own. The literal none is answered only under a syntax that permits it (B-010's
idresolve.permits_literal_none) and only for an absence the bytes prove; a file count is proven only when the
files were picked by name.

The work is struct reads and one SHA-256 per file, no layer walk and no program run: a set costs
milliseconds per megabyte, so it can run inside any timed window.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

import answer_kinds
import binfmt
import container_symbols
import content_members
import field_grammar
import overlay_records

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.append(str(_ROOT))
from ctf.idresolve import permits_literal_none  # noqa: E402

BOOL_PAIRS = (("true", "false"), ("yes", "no"), ("present", "absent"), ("1", "0"))
DAY = re.compile(r"d0*(\d+)")


# ---------------------------------------------------------------------------- forms

def _fmt(q) -> dict:
    return q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}


def number(n, fmt):
    """A number in the question's form, or None when the form is not established."""
    if n is None:
        return None
    kind, syntax = answer_kinds.kind_of(fmt), str(fmt.get("syntax") or "").lower()
    if kind == "integer":
        return str(n)
    if answer_kinds.wants_hex(fmt):
        return f"0x{n:x}"
    if "hex" in syntax:
        return None
    return str(n)


def boolean(flag, fmt):
    """A yes/no fact as the question fixes the pair, or None when it fixes none."""
    if flag is None:
        return None
    kind = answer_kinds.kind_of(fmt)
    if kind == "integer":
        return "1" if flag else "0"
    accepted = [a for a in fmt.get("accepted_values") or [] if isinstance(a, str)]
    low = {a.strip().lower(): a for a in accepted}
    for yes, no in BOOL_PAIRS:
        if yes in low and no in low:
            return low[yes] if flag else low[no]
    syntax = str(fmt.get("syntax") or "").lower()
    if not accepted and re.search(r"\btrue\b", syntax) and re.search(r"\bfalse\b", syntax):
        return "true" if flag else "false"
    return None


def _text(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return json.dumps(value)
    if isinstance(value, str):
        return value or None
    return json.dumps(value, separators=(",", ":"))


# ---------------------------------------------------------------------------- the prefix's files

def _segments(name: str) -> list:
    stem = re.sub(r"(?:\.[A-Za-z0-9]+)+$", "", name.split(" -> ")[-1].replace("\\", "/").rsplit("/", 1)[-1])
    return [s.lower() for s in re.split(r"[-_]+", stem) if s]


def _has_role(name: str, role: str) -> bool:
    words = [w for w in role.lower().split("_") if w]
    segs = _segments(name)
    return bool(words) and any(segs[i:i + len(words)] == words for i in range(len(segs) - len(words) + 1))


class Prefix:
    """The prefix's files and what is read from them, read once per set."""

    def __init__(self, prefix: str, files: dict, ctx):
        m = DAY.fullmatch(prefix)
        self.day = int(m.group(1)) if m else None
        if self.day is not None:
            sel = content_members.select(files or {}, ctx or {}, self.day)
            self.members, self.how, self.notes = list(sel.members), sel.how, list(sel.notes)
        else:
            import members
            self.members = members.day_members(files or {}, ctx or {}, prefix)
            self.how, self.notes = ("name" if self.members else None), []
        self._cfg = None

    def images(self, role=None) -> list:
        """The distinct image bodies of the prefix (of one role's files when `role` is given)."""
        out = []
        for name, data in self.members:
            if role and not _has_role(name, role):
                continue
            if container_symbols.container_of(bytes(data[:4])) and bytes(data) not in out:
                out.append(bytes(data))
        return out

    def config(self):
        """The one distinct verified JSON record of the prefix's files, or None."""
        if self._cfg is None:
            blobs = []
            for _, data in self.members:
                ov = overlay_records.overlay(data)
                blobs.append(ov.blob if ov is not None else bytes(data))
            self._cfg = (overlay_records.config(blobs),)
        return self._cfg[0]


def _sections(data: bytes):
    """[(name, offset, size or None, address, flags)] of an image's own section table, or None."""
    info = binfmt.elf(data)
    if info:
        if not info.get("sections"):
            return None
        return [(s.get("name") or "", s["offset"], s["size"], s["addr"], s["flags"]) for s in info["sections"]]
    info = binfmt.pe(data)
    if info is not None:
        return [(s["name"], s["raw"], s["rsize"] if s["rsize"] == s["vsize"] else None, s["va"], s["flags"])
                for s in info["sections"]]
    return None


# ---------------------------------------------------------------------------- families

def _one_image(P: Prefix, fid):
    imgs = P.images(fid.role)
    if len(imgs) != 1:
        return None, (f"{len(imgs)} distinct image(s) among the prefix's files"
                      + (f" for role {fid.role!r}" if fid.role else "") + ": the fact is not one file's")
    return imgs[0], ""


def _sha256(P, fid, q):
    if not fid.attr:
        return None, "no file number in the id"
    n = int(fid.attr)
    if 1 <= n <= len(P.members):
        return hashlib.sha256(bytes(P.members[n - 1][1])).hexdigest(), ""
    if n > len(P.members) and P.how == "name" and permits_literal_none(q):
        return "none", ""
    return None, f"file {n} of {len(P.members)} (picked by {P.how}): no absence is established"


def _has_section(P, fid, q):
    data, why = _one_image(P, fid)
    if data is None:
        return None, why
    secs = _sections(data)
    if secs is None:
        return None, "no readable section table: not proof of absence"
    got = boolean(any(field_grammar.norm_section(s[0]) == fid.name for s in secs), _fmt(q))
    return got, "" if got is not None else "the question fixes no yes/no pair"


def _section_attr(P, fid, q):
    data, why = _one_image(P, fid)
    if data is None:
        return None, why
    secs = _sections(data)
    if secs is None:
        return None, "no readable section table"
    hits = [(i, s) for i, s in enumerate(secs) if field_grammar.norm_section(s[0]) == fid.name]
    if not hits:
        if permits_literal_none(q):
            return "none", ""
        return None, f"no section {fid.name!r} and the syntax does not permit the literal none"
    if len(hits) > 1:
        return None, f"{len(hits)} sections are named {fid.name!r}"
    i, (name, off, size, addr, flags) = hits[0]
    fmt = _fmt(q)
    value = {"offset": off, "size": size, "address": addr, "flags": flags, "index": i}.get(fid.attr)
    if fid.attr == "name":
        return name, ""
    if value is None:
        return None, f"the section's {fid.attr} is not established"
    got = number(value, fmt)
    return got, "" if got is not None else "a hexadecimal wording this solver does not spell"


def _symbol(P, fid, q):
    data, why = _one_image(P, fid)
    if data is None:
        return None, why
    syms = container_symbols.read(data)
    if syms is None:
        return None, "not a readable ELF, PE or thin Mach-O"
    fmt = _fmt(q)
    if fid.attr == "presence":
        if syms.absent is None and syms.table is None:
            return None, syms.why
        has = syms.table is not None
        flag = (not has) if fid.field in ("is_stripped", "stripped") else has
        got = boolean(flag, fmt)
        return got, "" if got is not None else "the question fixes no yes/no pair"
    if syms.absent is not True:
        return None, f"the container does not prove the field absent ({syms.why})"
    if fid.attr == "count":
        return number(0, fmt), ""
    if permits_literal_none(q):
        return "none", ""
    return None, "the symbols are absent but the syntax does not permit the literal none"


def _overlay_bounds_differ(ov, lead: int, member_len: int, attr: str) -> str:
    """Why the overlay's `attr` (offset or size) is not one fact, or '' when it is.

    Two readings are in use: where the image ends (ov.start, the bytes after it), and the lane's judged one
    (generic.answer_field, the Day 20 build, row 366): the offset of the overlay's magic, and the member length
    minus it. They agree when the tail's first byte is its data: no zero fill before it, and (for the size)
    nothing cut off after it. A wrapper header at the image end with a verified record inside it (the Day 20-31
    RS20/PK19 builds: the HCFG record 42 bytes in) is no second reading: the saved keys judged the image end, the
    wrapper's magic, there (32 answers on the saved Huntress sets)."""
    if lead:
        return (f"{lead} zero byte(s) come before the overlay's first data: the image end ({ov.start}) and the "
                f"magic's position ({ov.start + lead}) are two readings, and nothing pins which is meant")
    if attr == "size" and ov.end != member_len:
        return (f"{member_len - ov.end} byte(s) after the overlay (a certificate table) are cut off: its size and "
                "the member length minus its offset are two readings")
    return ""


def _overlay(P, fid, q):
    data, why = _one_image(P, fid)
    if data is None:
        return None, why
    ov = overlay_records.overlay(data)
    if ov is None:
        return None, "not a readable ELF, PE or thin Mach-O"
    fmt = _fmt(q)
    if fid.attr == "present":
        got = boolean(bool(ov.blob), fmt)
        return got, "" if got is not None else "the question fixes no yes/no pair"
    if not ov.blob:
        if permits_literal_none(q):
            return "none", ""
        return None, "the image has no overlay and the syntax does not permit the literal none"
    lead = len(ov.blob) - len(ov.blob.lstrip(b"\0"))
    if fid.attr in ("offset", "size"):
        why = _overlay_bounds_differ(ov, lead, len(data), fid.attr)
        if why:
            return None, why
        return number(ov.start if fid.attr == "offset" else len(ov.blob), fmt), ""
    if fid.attr == "sha256":
        return hashlib.sha256(ov.blob).hexdigest(), ""
    if fid.attr == "tag":
        tags = {r.tag for r in overlay_records.records(ov.blob) if r.offset == lead}
        if len(tags) == 1:
            return tags.pop(), ""
        return None, f"{len(tags)} verified record tag(s) start the overlay"
    return None, f"overlay {fid.attr} is not read here"


def _config(P, fid, q):
    cfg = P.config()
    if cfg is None:
        return None, "no single distinct verified JSON record among the prefix's files"
    if fid.name in cfg:
        got = _text(cfg[fid.name])
        return got, "" if got is not None else "the member is empty"
    if permits_literal_none(q):
        return "none", ""
    return None, "the record lacks the member and the syntax does not permit the literal none"


FAMILIES = {"sha256": _sha256, "has_section": _has_section, "section_attr": _section_attr, "symbol": _symbol,
            "overlay": _overlay, "config": _config}


def solve(prefix: str, questions, files: dict, ctx=None) -> tuple:
    """({qid: answer or None}, {qid: why None}) for one prefix's questions."""
    P = Prefix(str(prefix).lower(), files, ctx)
    out, why = {}, {}
    for q in questions or []:
        qid = q.get("qid") or q.get("id")
        fid = field_grammar.parse(qid)
        fn = FAMILIES.get(fid.family)
        if fn is None:
            out[qid], why[qid] = None, f"family {fid.family}: owned by the lane's other readers"
            continue
        if fid.family == "sha256" and fid.area not in (None, "artifact"):
            out[qid], why[qid] = None, f"a sha256 of the {fid.area} area is not a file hash"
            continue
        try:
            got, reason = fn(P, fid, q)
        except Exception as e:      # a reader failing costs this id, never the set
            got, reason = None, f"{fn.__name__} raised {type(e).__name__}: {e}"
        out[qid] = got
        if got is None:
            why[qid] = reason
    return out, why


def answers(prefix: str, questions, files: dict, ctx=None) -> dict:
    return solve(prefix, questions, files, ctx)[0]


def _main(argv) -> int:
    if len(argv) < 2:
        print("usage: speed_solver.py QUESTIONS.json FILE [FILE ...]", file=sys.stderr)
        return 2
    questions = json.loads(Path(argv[0]).read_text())
    files = {Path(f).name: Path(f).read_bytes() for f in argv[1:]}
    groups = {}
    for q in questions:
        groups.setdefault(str(q.get("qid") or q.get("id")).split("_", 1)[0].lower(), []).append(q)
    for prefix, qs in groups.items():
        got, why = solve(prefix, qs, files, {})
        for qid, value in got.items():
            print(f"{qid}: {value!r}" + (f"   ({why[qid]})" if qid in why else ""))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
