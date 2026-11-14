#!/usr/bin/env python3
"""Sibling passphrase harvest for a steghide cover (B-076).

A stego cover (JPEG, BMP, WAV, AU) often ships with a note beside it whose quoted word is the
passphrase: the Spooky "Xenoglossophobia" Latin note named it as `"supermercado"`. This module reads
the small text files beside a cover, takes every quoted string in them (straight, curly, guillemet,
backtick and single quotes), then the sibling tokens B-074's harvest finds (solvers/common/harvest.py),
and hands them, in that order, to stego_tools.steghide_extract until one opens the cover.

  .venv/bin/python solvers/toolkits/passphrase_harvest.py <cover>                 the candidates, in order
  .venv/bin/python solvers/toolkits/passphrase_harvest.py --steghide <cover>      try them with steghide
  .venv/bin/python solvers/toolkits/passphrase_harvest.py --steghide --out DIR <cover>   keep the payload

    quoted(text)                   -> [str]: quoted strings in order of appearance (and a copy without
                                      trailing punctuation inside the quotes)
    sibling_texts(path)            -> [(name, text)]: the small text files beside `path`
    candidates(path, extra=())     -> [Candidate(value, source)]: quoted first, then B-074 tokens
    try_steghide(data, cands)      -> Attempt: the first candidate steghide opens the cover with
    payload_flags(payload)         -> (flags, how): flags in the payload as written, in its mixed numeric
                                      escapes (`\\x4d\\x65 ... 108 64 ...`, numeric_escapes; else the
                                      longest such run inside it, numeric_escape_run), or through
                                      the shared codec graph (ctf.codec)

Nothing is generated: every candidate is a string written in a sibling file (or in `extra` text the
caller passes, such as the brief). Clue-derived keys (a translation, a word the picture shows) are not
reached; that stays with the agent. steghide runs only in the sandbox (tools/sandbox.py via
stego_tools); intake cuts the docker socket, so at intake this lists the candidates and names the
`--steghide` step. A sandbox that is down, or a cover steghide cannot read, stops the tries with that
reason (`blocked`): it says nothing about the passphrases.

Output: `key = value` lines (values as Python literals), then one SolverResult JSON object as the last
line: solved for one flag in the payload, candidate for several, unsure for a payload with no flag or for
quoted candidates not tried yet, none when nothing is quoted or nothing opened the cover, blocked when
steghide could not read the cover.
"""
from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

try:
    from ctf import event as ctf_event, flagfmt
    from ctf.codec import FlagOracle, Graph
    from ctf.packs import load_module
    from ctf.result import Evidence, SolverResult
except ModuleNotFoundError:
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import event as ctf_event, flagfmt
    from ctf.codec import FlagOracle, Graph
    from ctf.packs import load_module
    from ctf.result import Evidence, SolverResult

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
ENGINE = "toolkits.passphrase_harvest"
MAX_QUOTED = 64                  # characters inside one pair of quotes
MAX_TRIES = 64                   # steghide calls for one cover by default
COVER_EXTS = (".jpg", ".jpeg", ".bmp", ".wav", ".au")

_QUOTES = [
    re.compile(r'"([^"\n]{1,%d})"' % MAX_QUOTED),
    re.compile(r"“([^”\n]{1,%d})”" % MAX_QUOTED),           # “ ”
    re.compile(r"„([^“”\n]{1,%d})[“”]" % MAX_QUOTED),   # „ “
    re.compile(r"«\s?([^»\n]{1,%d}?)\s?»" % MAX_QUOTED),     # « »
    re.compile(r"‘([^’\n]{1,%d})’" % MAX_QUOTED),           # ‘ ’
    re.compile(r"`([^`\n]{1,%d})`" % MAX_QUOTED),
    re.compile(r"(?<![\w'])'([^'\n]{1,%d})'(?![\w'])" % MAX_QUOTED),        # 'x', never an apostrophe
]
_TRAIL = ".,;:!?"


def _harvest():
    rel = "solvers/common/harvest.py"
    return load_module("ctf_common_harvest", ROOT / rel, pack=rel)


def _stego_tools():
    if str(HERE) not in sys.path:
        sys.path.insert(1, str(HERE))
    import stego_tools
    return stego_tools


def quoted(text: str) -> list[str]:
    """Every quoted string of `text`, in order of appearance, de-duplicated; a value with punctuation
    before its closing quote ("go!") is followed by the bare word (go)."""
    hits = []
    for rx in _QUOTES:
        for m in rx.finditer(text or ""):
            hits.append((m.start(), m.group(1)))
    out = []
    for _, v in sorted(hits):
        v = v.strip()
        for c in (v, v.rstrip(_TRAIL).strip()):
            if c and any(ch.isalnum() for ch in c) and c not in out and "\x00" not in c:
                out.append(c)
    return out


def _decode(blob: bytes) -> str:
    if blob[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return blob.decode("utf-16", "replace")
    try:
        return blob.decode("utf-8")
    except UnicodeDecodeError:
        return blob.decode("latin-1")


def sibling_texts(path) -> list[tuple[str, str]]:
    """[(name, text)] of the small text files beside `path`, by name: the rules of B-074's harvest
    (no link, no binary, at most MAX_SIBLINGS files of MAX_SIBLING bytes, never the harness's files),
    and no hidden file (the sweep's own .sweep.json, .lock)."""
    hv = _harvest()
    p = Path(path)
    folder = p.parent
    try:
        entries = sorted(e for e in folder.iterdir() if e.is_file() and not e.is_symlink())
    except OSError:
        return []
    out = []
    for e in entries:
        if e.name == p.name or e.name.startswith(".") or hv.SKIP_SIBLING.match(e.name):
            continue
        if len(out) >= hv.MAX_SIBLINGS:
            break
        try:
            if e.stat().st_size > hv.MAX_SIBLING:
                continue
            blob = e.read_bytes()
        except OSError:
            continue
        if b"\x00" in blob[:1024] and blob[:2] not in (b"\xff\xfe", b"\xfe\xff"):
            continue                    # binary: not a note
        out.append((e.name, _decode(blob)))
    return out


@dataclass(frozen=True)
class Candidate:
    value: str
    source: str


def candidates(path, extra=(), tokens: bool = True) -> list[Candidate]:
    """Passphrase candidates for the cover at `path`: quoted strings of its sibling notes, then of each
    `extra` text, then (tokens=True) B-074's sibling tokens. De-duplicated, first source kept."""
    hv = _harvest()
    out, seen = [], set()

    def add(value, source):
        if hv.valid(value) and value not in seen:
            seen.add(value)
            out.append(Candidate(value, source))

    for name, text in sibling_texts(path):
        for q in quoted(text):
            add(q, f"quoted in {name}")
    for i, text in enumerate(extra):
        for q in quoted(text):
            add(q, f"quoted in extra text {i + 1}")
    if tokens:
        for t in hv.siblings(path):
            add(t, "sibling token (B-074 harvest)")
    return out[:hv.MAX_CANDIDATES]


@dataclass
class Attempt:
    found: Candidate | None = None
    payload: bytes | None = None
    tried: int = 0
    blocked: str = ""                   # why steghide said nothing about the passphrases
    notes: list = field(default_factory=list)


def try_steghide(data: bytes, cands, extract=None, limit: int = MAX_TRIES) -> Attempt:
    """Try each candidate with `extract` (stego_tools.steghide_extract) in order; the first that opens
    the cover wins. A call that did not read the cover (sandbox down, killed, the cover not read whole)
    ends the tries: Attempt.blocked says why."""
    extract = extract or _stego_tools().steghide_extract
    att = Attempt()
    for c in list(cands)[:limit]:
        r = extract(data, c.value)
        att.tried += 1
        if r.ok and r.data is not None:
            att.found, att.payload = c, bytes(r.data)
            return att
        note = str(getattr(r, "note", "") or "")
        if r.code is None or note.endswith("not read") or "no reading of the passphrase" in note:
            att.blocked = note or "steghide did not run"
            return att
    if len(list(cands)) > limit:
        att.notes.append(f"{len(list(cands)) - limit} candidate(s) past the limit of {limit} not tried")
    return att


# A payload written as numbers: `\xHH` escapes, `0xHH`, decimal or octal-escape (`\NNN`) byte values, mixed
# in one text (Xenoglossophobia: `\x4d\x65...\x5f` then `108 64 110 ...`). White space and commas separate
# them; every other character makes the text no such list.
_ESC_TOKEN = re.compile(rb"\\x([0-9a-fA-F]{2})|0x([0-9a-fA-F]{2})(?![0-9a-fA-F])|\\([0-7]{3})|(?<![\w\\])(\d{1,3})(?!\w)|[\s,]+")
MIN_ESCAPES = 4


def numeric_escapes(data: bytes) -> bytes | None:
    """The bytes a text of mixed numeric escapes spells, or None when `data` is not wholly such a text (or
    has fewer than MIN_ESCAPES values, or a decimal above 255). Separators are never data: a space in the
    decoded text is written `\\x20` or `32`."""
    s = bytes(data).strip()
    out, pos, n = bytearray(), 0, 0
    for m in _ESC_TOKEN.finditer(s):
        if m.start() != pos:
            return None
        pos = m.end()
        hx, ox, oc, dec = m.group(1), m.group(2), m.group(3), m.group(4)
        if hx or ox:
            out.append(int(hx or ox, 16))
        elif oc:
            v = int(oc, 8)
            if v > 255:
                return None
            out.append(v)
        elif dec:
            v = int(dec)
            if v > 255:
                return None
            out.append(v)
        else:
            continue
        n += 1
    if pos != len(s) or n < MIN_ESCAPES:
        return None
    return bytes(out)


_ONE_ESC = rb"(?:\\x[0-9a-fA-F]{2}|0x[0-9a-fA-F]{2}(?![0-9a-fA-F])|\\[0-7]{3}|(?<![\w\\])\d{1,3}(?!\w))"
_ESC_RUN = re.compile(_ONE_ESC + rb"(?:[\s,]*" + _ONE_ESC + rb")*")


def numeric_escape_run(data: bytes) -> bytes | None:
    """The bytes the longest run of numeric escapes inside `data` spells, or None when no run qualifies.
    Each run is decoded by numeric_escapes, so it needs MIN_ESCAPES values and no value above 255. This is
    for a payload with a lead-in or a tail (`flag: \\x41\\x42...`); numeric_escapes, the strict whole-text
    form, is tried first. Ties go to the earliest run."""
    best: bytes | None = None
    for m in _ESC_RUN.finditer(bytes(data)):
        dec = numeric_escapes(m.group(0))
        if dec is not None and (best is None or len(dec) > len(best)):
            best = dec
    return best


def payload_flags(payload: bytes, profile=None) -> tuple[list[str], str]:
    """(flags, how) of a steghide payload: the flags written in it as they are, else in its mixed numeric
    escapes decoded (numeric_escapes on the whole text, else numeric_escape_run on its longest run), else what the shared codec graph (ctf.codec, B-163) reaches from the
    payload (or from those decoded bytes). The flag format is `profile`'s (default: the active event's;
    none raises flagfmt's EventError). ([], "") when no flag is found."""
    ff = flagfmt.for_profile(profile) if profile is not None else flagfmt.current()
    flags = ff.find_flags(bytes(payload))
    if flags:
        return list(dict.fromkeys(flags)), "as written"
    decoded, how_dec = numeric_escapes(payload), "numeric escapes"
    if decoded is None:
        decoded, how_dec = numeric_escape_run(payload), "numeric escape run"
    if decoded is not None:
        flags = ff.find_flags(decoded)
        if flags:
            return list(dict.fromkeys(flags)), f"{how_dec} decoded"
    for blob, how in ((payload, "codec graph"), (decoded, f"{how_dec}, then the codec graph")):
        if blob is None:
            continue
        found = Graph().search(bytes(blob), FlagOracle(profile)).answers
        if found:
            return list(dict.fromkeys(found)), how
    return [], ""


def _format():
    try:
        return flagfmt.current()
    except ctf_event.EventError as e:
        print(f"note = no event flag format ({e}): the payload is not searched for flags", flush=True)
        return None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="passphrase_harvest.py",
                                 description="Quoted-string passphrase harvest from a stego cover's sibling notes (B-076)")
    ap.add_argument("cover")
    ap.add_argument("--steghide", action="store_true", help="try the candidates with steghide (in the sandbox)")
    ap.add_argument("--no-tokens", action="store_true", help="quoted strings only, not B-074's sibling tokens")
    ap.add_argument("--extra", action="append", default=[], metavar="TEXT", help="more text to take quoted strings from (the brief)")
    ap.add_argument("--max", type=int, default=MAX_TRIES, help="steghide calls at most")
    ap.add_argument("--out", default=None, help="write the payload to this folder")
    a = ap.parse_args(argv)
    cover = Path(a.cover)
    if not cover.is_file():
        print(f"passphrase_harvest.py: no such file: {a.cover}", file=sys.stderr)
        return 2
    if a.max < 1:
        print("passphrase_harvest.py: --max takes a positive number", file=sys.stderr)
        return 2
    cands = candidates(cover, a.extra, tokens=not a.no_tokens)
    quoted_n = sum(c.source.startswith("quoted") for c in cands)
    print(f"== {cover.name}: {len(cands)} candidate(s), {quoted_n} quoted", flush=True)
    for c in cands[:40]:
        print(f"candidate = {c.value!r} ({c.source})", flush=True)
    if not a.steghide:
        if quoted_n:
            print(f"next = python solvers/toolkits/passphrase_harvest.py --steghide {cover.name}", flush=True)
            res = SolverResult("unsure", engine=ENGINE, notes=f"{cover.name}: {quoted_n} quoted passphrase candidate(s) "
                               f"from sibling notes, not tried: run --steghide (steghide runs in the sandbox)")
        else:
            res = SolverResult("none", engine=ENGINE, notes=f"{cover.name}: no quoted string in a sibling note "
                               f"({len(cands)} token candidate(s))")
        print(res.to_json(), flush=True)
        return 0
    att = try_steghide(cover.read_bytes(), cands, limit=a.max)
    print(f"tried = {att.tried}", flush=True)
    for n in att.notes:
        print(f"note = {n}", flush=True)
    if att.blocked:
        print(f"blocked = {att.blocked}", flush=True)
        print(SolverResult("blocked", engine=ENGINE, notes=f"{cover.name}: {att.blocked}").to_json(), flush=True)
        return 0
    if att.found is None:
        print(SolverResult("none", engine=ENGINE, notes=f"{cover.name}: none of {att.tried} candidate(s) opened it").to_json(),
              flush=True)
        return 0
    print(f"passphrase = {att.found.value!r} ({att.found.source})", flush=True)
    print(f"payload = {len(att.payload)} bytes: {att.payload[:400]!r}", flush=True)
    if a.out:
        out = Path(a.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / f"{cover.name}.steghide.bin").write_bytes(att.payload)
        print(f"written = {cover.name}.steghide.bin", flush=True)
    flags, how = payload_flags(att.payload) if _format() is not None else ([], "")
    ev = [Evidence("decode", f"steghide payload of {cover.name} under passphrase {att.found.value!r} ({att.found.source})"
                   + (f", flag {how}" if flags else ""), path=cover.name)]
    if flags:
        print(f"decoded = {how}", flush=True)
        res = SolverResult("solved" if len(flags) == 1 else "candidate", flags=flags,
                           evidence=ev, engine=ENGINE, notes=f"{cover.name}: opened with {att.found.value!r}; flag {how}")
    else:
        res = SolverResult("unsure", evidence=ev, engine=ENGINE,
                           notes=f"{cover.name}: opened with {att.found.value!r}; {len(att.payload)}-byte payload with no "
                                 f"flag in the event format, as written, as numeric escapes or through the codec graph")
    print(res.to_json(), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
