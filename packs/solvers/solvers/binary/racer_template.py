#!/usr/bin/env python3
"""Template for a Binary day's complex-racer candidate, dNN_<role>_dev.py (B-258).

On a release morning the complex racer writes the day module for the new sample while the standard
lane answers what generic.py can. Five Huntress days began this file from nothing; this is the shape
they converged on. Make the candidate with

    python -m ctf scaffold racer --day 31            # solvers/binary/d31_cx_dev.py, PREFIX = "d31"

then fill RULES (start from EXAMPLE_RULES) and check it on the saved delivery:

    .venv/bin/python -I solvers/binary/d31_cx_dev.py --questions questions.json FILE...

A candidate is never written under the final name dNN.py by hand: the lane's promotion step replays
the saved attempts and only then copies it to dNN.py, which evidence.py loads for the prefix.

Under this name the file is inert: evidence.py loads <prefix>.py only for a prefix of letters and
digits that a question id carries, and generic.py loads only fields_<prefix>.py. No question id starts
with `racer_template_`, and the PREFIX here, "template", matches no id.

The contract (evidence.py): answers(questions, files, ctx) -> {qid: answer}, where `questions` are the
prefix's questions and `files` is every file of the delivery ({name: bytes}). In the result:

  an id LEFT OUT     not this module's: generic.py and the hooks answer it;
  an id set to None  this module read the sample and declines: the bytes do not settle it (two
                     candidates, a CRC that fails, a value outside the stated enum). Never a default.
  an id set to a value  the answer. A value that does not fit the answer_format (an enum value not
                     listed, an integer that is not one) is turned into None here, with a stderr line.

RULES rows are (field regex, text regex or None, reader). The first row whose field regex fullmatches
the id without its prefix (and whose text regex, if any, is found in the question text) decides; the
reader gets (q, match, state) and returns the answer, None, or LEAVE (not mine after all: the next row
is tried, and with none left the id is left out). `state.members` is [(name, bytes)] of the prefix's
top-level members (`<prefix>--name`), `state.cache` a dict shared across the questions of one call.

Nothing in a sample is executed; the readers parse bytes only.
"""
import json
import re
import struct
import sys
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "common"))

PREFIX = "template"
LEAVE = object()        # a reader's "not mine": try the next row, else leave the id out
_MISSING = object()

# The record layout five days stated (HCFG and its renamings HGRF, HGAU): 4-byte magic, version byte,
# XOR key byte, u16le payload length, u32le CRC-32 of the decoded payload, then the XOR-ed payload.
HEADER = 12
MAGIC_RE = re.compile(r"CRC-?32-valid ([A-Z0-9]{4}) record", re.I)
PROPERTY_RE = re.compile(r"JSON property ([A-Za-z0-9_.]+?)[,.]?(?:\s|$)", re.I)
SUFFIX_RE = re.compile(r"basename ends ([A-Za-z0-9._-]+)", re.I)


def _note(text):
    text = "".join(c if c.isprintable() else "?" for c in str(text))[:400]
    print(f"[{PREFIX}cx] {text}", file=sys.stderr)


# ------------------------------------------------------------------------------------------- members

def members(files):
    """[(name, bytes)] of the delivery's top-level <prefix>-- members (never an archive-nested name)."""
    out = []
    for n, b in (files or {}).items():
        if not isinstance(n, str) or " -> " in n or not isinstance(b, (bytes, bytearray)):
            continue
        if n.rsplit("/", 1)[-1].lower().startswith(PREFIX + "--"):
            out.append((n, bytes(b)))
    return out


def select(ms, *, suffix=None, magic=None):
    """The one member whose basename ends `suffix` and whose bytes start with `magic`, else None (with a
    note when more than one distinct body qualifies)."""
    hits = [(n, b) for n, b in ms
            if (suffix is None or n.rsplit("/", 1)[-1].lower().endswith(suffix.lower()))
            and (magic is None or b.startswith(magic))]
    if len({b for _, b in hits}) != 1:
        if len(hits) > 1:
            _note(f"{len(hits)} members match suffix={suffix!r} magic={magic!r}: not one, nothing read")
        return None
    return hits[0]


# ------------------------------------------------------------------------------------------- records

def records(data, magic, header=HEADER):
    """Every CRC-valid record under `magic` in `data`, highest offset first (a backward scan)."""
    out = []
    o = data.rfind(magic)
    while o >= 0:
        if o + header <= len(data):
            version, key = data[o + 4], data[o + 5]
            length = struct.unpack_from("<H", data, o + 6)[0]
            crc = struct.unpack_from("<I", data, o + 8)[0]
            enc = data[o + header:o + header + length]
            if length and len(enc) == length:
                plain = bytes(b ^ key for b in enc)
                if zlib.crc32(plain) & 0xFFFFFFFF == crc:
                    try:
                        obj = json.loads(plain.decode("utf-8"))
                    except (UnicodeDecodeError, ValueError):
                        obj = None
                    out.append({"offset": o, "version": version, "key": key, "length": length,
                                "crc32": crc, "plain": plain, "json": obj})
        o = data.rfind(magic, 0, o)
    return out


def unique_record(ms, magic):
    """The one CRC-valid record under `magic` across the members (equal bodies count once), else None."""
    found = {}
    for _, b in ms:
        for r in records(b, magic):
            found.setdefault(r["plain"] + r["crc32"].to_bytes(4, "little"), r)
    if len(found) != 1:
        if found:
            _note(f"{len(found)} CRC-valid {magic!r} records: not unique, nothing read")
        return None
    return next(iter(found.values()))


def json_path(obj, dotted):
    """The value at a dotted property path, or _MISSING when a step is missing."""
    cur = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return _MISSING
        cur = cur[part]
    return cur


# --------------------------------------------------------------------------------------- the readers

class Q:
    """One question: qid, field (the id without the prefix), text, fmt (the answer_format dict)."""

    def __init__(self, q):
        self.qid = q.get("qid") or q.get("id")
        self.field = self.qid.split("_", 1)[1] if isinstance(self.qid, str) and "_" in self.qid else ""
        self.text = q.get("question") or ""
        self.fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}


class State:
    def __init__(self, ms, ctx):
        self.members, self.ctx, self.cache = ms, ctx, {}


def _stated_record(q, state):
    """The question's stated record: the magic it names, in the member its suffix names (if any)."""
    mm = MAGIC_RE.search(q.text)
    if mm is None:
        return LEAVE
    magic = mm.group(1).upper().encode("ascii")
    sm = SUFFIX_RE.search(q.text)
    pool = state.members
    if sm is not None:
        one = select(pool, suffix=sm.group(1).rstrip("."))
        pool = [one] if one is not None else []
    key = (magic, sm.group(1) if sm else None)
    if key not in state.cache:
        state.cache[key] = unique_record(pool, magic) if pool else None
    return state.cache[key]


def read_crc32_hex(q, m, state):
    rec = _stated_record(q, state)
    if rec is LEAVE:
        return LEAVE
    return f"0x{rec['crc32']:08x}" if rec is not None else None


def read_property(q, m, state):
    pm = PROPERTY_RE.search(q.text)
    rec = _stated_record(q, state) if pm is not None else LEAVE
    if rec is LEAVE:
        return LEAVE
    if rec is None or not isinstance(rec["json"], dict):
        return None
    value = json_path(rec["json"], pm.group(1).rstrip("."))
    return value if isinstance(value, (str, int, float)) and not isinstance(value, bool) and value != "" else None


# Worked rows for the stated-record questions of the late Huntress days; copy the ones the day needs.
EXAMPLE_RULES = [
    (r"analysis_\w+_crc32_hex", r"header bytes 8\.\.11", read_crc32_hex),
    (r"analysis_\w+", r"JSON property", read_property),
]

RULES = []   # the day's rows: (field regex, text regex or None, reader)


# --------------------------------------------------------------------------------------- the contract

def fit(q, value):
    """The value, or None when it does not fit the stated answer_format (with a note)."""
    if value is None:
        return None
    kind = q.fmt.get("kind")
    if kind == "enum":
        allowed = [v for v in q.fmt.get("accepted_values") or [] if isinstance(v, str)]
        if allowed and value not in allowed:
            _note(f"{q.qid}: {value!r} is not one of the stated values; None")
            return None
    if kind == "integer" and (isinstance(value, bool) or not isinstance(value, int)):
        if not (isinstance(value, str) and re.fullmatch(r"-?\d+", value)):
            _note(f"{q.qid}: {value!r} is not an integer; None")
            return None
    return value


def answers(questions, files, ctx, rules=None):
    """{qid: answer} for the ids a row reads; every other id is left OUT."""
    rows = RULES if rules is None else rules
    out = {}
    state = State(members(files) if isinstance(files, dict) else [], ctx)
    for raw in questions or []:
        if not isinstance(raw, dict):
            continue
        q = Q(raw)
        if not isinstance(q.qid, str) or not q.qid.lower().startswith(PREFIX + "_"):
            continue
        for field_re, text_re, reader in rows:
            m = re.fullmatch(field_re, q.field)
            if m is None or (text_re is not None and re.search(text_re, q.text) is None):
                continue
            got = reader(q, m, state)
            if got is LEAVE:
                continue
            out[q.qid] = fit(q, got)
            break
    return out


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("files", nargs="+", type=Path, help="the delivery's members (read as bytes)")
    ap.add_argument("--questions", type=Path, help="a JSON list of questions; without it, list records")
    ap.add_argument("--magic", default="HCFG", help="the record magic to list (default HCFG)")
    ap.add_argument("--examples", action="store_true", help="answer with EXAMPLE_RULES instead of RULES")
    a = ap.parse_args()
    delivery = {p.name: p.read_bytes() for p in a.files}
    if a.questions is None:
        for name, blob in delivery.items():
            print(name, len(blob))
            for r in records(blob, a.magic.encode("ascii")):
                print(f"  record at {r['offset']:#x} v={r['version']} key={r['key']:#04x} "
                      f"crc32=0x{r['crc32']:08x}", json.dumps(r["json"], sort_keys=True))
        sys.exit(0)
    qs = json.loads(a.questions.read_text(encoding="utf-8"))
    got = answers(qs, delivery, {}, rules=EXAMPLE_RULES if a.examples else None)
    for qid in sorted(got):
        print(f"{qid} = {got[qid]!r}")
