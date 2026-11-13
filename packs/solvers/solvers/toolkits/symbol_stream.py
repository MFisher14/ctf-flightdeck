#!/usr/bin/env python3
"""Toolkit `symbol_stream` (B-117): a text made of a few repeating symbols, read as a module grid.

A recurring stego shape is a text file of two emoji (or a handful of glyphs) that is really a
matrix code written out as a stream: the line breaks mean nothing, the symbols group into words,
one word marks the end of every row, and which words are dark modules has to be found. At the 2026
PINK event that took a solver pass, a handoff and a second pass; every step of it is mechanical:

  symbols   the text is cut into symbols (an emoji with its variation selector or joiner is one
            symbol; blanks separate, unless the drawing is one glyph against spaces). 2 to 16
            distinct symbols make a stream; anything else is not one.
  words     a two-symbol stream is read at every word size from 1 to 8 symbols (bits, nibbles,
            bytes); a stream of more symbols is read one symbol a word.
  layout    three ways to rows: the lines as written (all the same length); a delimiter word (a
            word whose every occurrence is one fixed step after the last, at a row start or a row
            end, the final one optional); a perfect square with no delimiter.
  modules   which words are dark: with two distinct words, either; else the k most common words
            for every k (the split with the widest count gap first), and for a two-symbol stream
            each symbol position of the word.
  read      a uniform border is cut, and the matrix goes to qr_matrix: the strict QR decode, the
            other matrix families (Data Matrix, Aztec, PDF417), and, when the QR's fixed structure
            is plausible but its finders are gone, the repair decode. Reed--Solomon is the
            acceptance boundary, so a reading is evidence, not a guess. The first reading ends
            the search.

  solve(challenge_dir, profile, **opts) -> SolverResult      the engine contract (python -m ctf run)
  examine(files, ff, ...) -> Report                          the same over {name: bytes}
  analyse(stream, deadline=None, skipped=None) -> [Candidate]   ranked, a reading first
  read_symbols(text) -> Stream | None
  layouts(stream) -> [Layout];  mappings(layout, alphabet) -> [(label, matrix)]
  trim_border(matrix) -> (matrix, (top, bottom, left, right))

  .venv/bin/python solvers/toolkits/symbol_stream.py FILE... [--event SLUG] [--out DIR] [--seconds S]

Status: one flag in a decoded symbol is `solved`, several are `candidate`. A symbol that decodes to
something else is `unsure`, the payload named. A grid that no decoder reads is `unsure` only when
it is worth a look (it shows QR structure, or a two-symbol stream has a clean delimiter word of
several symbols): the grids are named and the best are written as PNG for a human or model read.
Any other text of few symbols is `none`. Nothing is executed or sent.
"""
from __future__ import annotations

import argparse
import math
import sys
import time
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

try:
    from ctf import flagfmt
except ModuleNotFoundError:
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.append(str(HERE))

import _visual_stego as vs      # noqa: E402
import qr_matrix as qr          # noqa: E402

ENGINE = "toolkits.symbol_stream"
MAX_INPUT = 4 << 20                   # bytes of one text file
MAX_SYMBOLS = 16                      # distinct symbols a stream may have
MAX_CODEPOINTS = 64                   # distinct characters past which a text is prose, not a stream
MIN_SIDE = 8                          # rows and columns a grid needs
MAX_ROWS, MAX_COLS = 177, 708         # what qr_matrix takes
WORD_SIZES = (1, 2, 3, 4, 5, 6, 7, 8)
MAX_STREAM = MAX_ROWS * (MAX_COLS + 1) * max(WORD_SIZES)   # symbols of the largest grid, delimiters included
MAX_DOMINANT = 15                     # most-common-word splits tried for one layout
MAX_CANDIDATES = 96                   # matrices read for one file
MAX_WRITTEN = 3                       # unread grids written for one file
DEFAULT_SECONDS = 20.0
BLANKS = (" ", "\t")


# ---- symbols ---------------------------------------------------------------------------------------

@dataclass
class Stream:
    lines: list                       # [[symbol index, ...]], one per text line that has symbols
    alphabet: list                    # the symbols as written, in order of first appearance

    @property
    def flat(self) -> list:
        return [s for line in self.lines for s in line]


def _clusters(line: str) -> list:
    """One line cut into symbols: a character with the marks (variation selectors are marks),
    skin tones and zero-width-joined characters that follow it."""
    out, joined = [], False
    for ch in line:
        cp = ord(ch)
        glue = unicodedata.category(ch) in ("Mn", "Me", "Mc") or cp == 0x200D or 0x1F3FB <= cp <= 0x1F3FF
        if out and out[-1] not in BLANKS and (joined or glue):
            out[-1] += ch
        else:
            out.append(ch)
        joined = cp == 0x200D
    return out


def read_symbols(text: str) -> Stream | None:
    """The symbol stream of a text, or None when it is not one (fewer than 2 or more than
    MAX_SYMBOLS distinct symbols, or too few symbols for a MIN_SIDE grid). Blanks separate symbols;
    when a single glyph is drawn against spaces the space is the second symbol and short lines are
    padded with it."""
    text = text.replace("\r", "").lstrip("\ufeff")
    if len(set(text) - {"\n", " ", "\t"}) > MAX_CODEPOINTS:
        return None
    if len(text) > MAX_STREAM * 4:                      # no grid the decoders take is this long
        return None
    rows = [_clusters(line) for line in text.split("\n")]
    ink = {c for row in rows for c in row if c not in BLANKS}
    if len(ink) == 1 and not any("\t" in row for row in rows):
        while rows and not any(c != " " for c in rows[0]):
            rows.pop(0)
        while rows and not any(c != " " for c in rows[-1]):
            rows.pop()
        width = max((len(row) for row in rows), default=0)
        rows = [row + [" "] * (width - len(row)) for row in rows]
    else:
        rows = [[c for c in row if c not in BLANKS] for row in rows]
        rows = [row for row in rows if row]
    alphabet = list(dict.fromkeys(c for row in rows for c in row))
    if not 2 <= len(alphabet) <= MAX_SYMBOLS or sum(len(row) for row in rows) < MIN_SIDE * MIN_SIDE:
        return None
    index = {symbol: i for i, symbol in enumerate(alphabet)}
    return Stream([[index[c] for c in row] for row in rows], alphabet)


# ---- layouts ---------------------------------------------------------------------------------------

@dataclass
class Layout:
    kind: str                         # lines | delimiter | square
    word_size: int
    delimiter: tuple | None           # the delimiter word (symbol indices), for kind delimiter
    rows: list                        # [[word, ...]]; a word is a tuple of symbol indices


def _words(symbols: list, size: int) -> list:
    return [tuple(symbols[i:i + size]) for i in range(0, len(symbols) - size + 1, size)]


def _delimited(words: list, at: list) -> list | None:
    """The rows between the occurrences `at` of one word, or None unless they are a clean
    delimiter: evenly spaced, at least MIN_SIDE words apart, the stream starting and ending either
    on a delimiter or on a whole row."""
    if len(at) < MIN_SIDE - 1:
        return None
    step = at[1] - at[0]
    if step - 1 < MIN_SIDE or any(b - a != step for a, b in zip(at, at[1:])):
        return None
    head, tail = at[0], len(words) - 1 - at[-1]
    if head not in (0, step - 1) or tail not in (0, step - 1):
        return None
    rows = [words[:head]] if head else []
    rows += [words[a + 1:a + step] for a in at if a + step <= len(words)]
    return rows


def layouts(stream: Stream) -> list:
    """Every way the stream lays out as a grid of words (module docstring: lines, delimiter,
    square), for every word size, without duplicates."""
    out, seen = [], set()
    flat = stream.flat

    def add(kind, size, delimiter, rows):
        if not (MIN_SIDE <= len(rows) <= MAX_ROWS and rows and MIN_SIDE <= len(rows[0]) <= MAX_COLS):
            return
        if len({word for row in rows for word in row}) < 2:
            return
        key = tuple(tuple(row) for row in rows)
        if key not in seen:
            seen.add(key)
            out.append(Layout(kind, size, delimiter, rows))

    for size in (WORD_SIZES if len(stream.alphabet) == 2 else (1,)):
        if all(len(line) % size == 0 for line in stream.lines):
            rows = [_words(line, size) for line in stream.lines]
            if len({len(row) for row in rows}) == 1:
                add("lines", size, None, rows)
        words = _words(flat, size)
        where = {}
        for i, word in enumerate(words):
            where.setdefault(word, []).append(i)
        for word, at in where.items():
            rows = _delimited(words, at)
            if rows:
                add("delimiter", size, word, rows)
        side = math.isqrt(len(words))
        if side * side == len(words) and len(flat) % size == 0:
            add("square", size, None, [words[i * side:(i + 1) * side] for i in range(side)])
    return out


# ---- words to modules ------------------------------------------------------------------------------

def spell(word, alphabet) -> str:
    return "".join(alphabet[s] for s in word)


def mappings(layout: Layout, alphabet: list) -> list:
    """[(label, matrix)]: the ways a layout's words become dark and light modules. Polarity is not
    a choice here (every decoder reads a matrix both ways)."""
    rows = layout.rows
    counts = Counter(word for row in rows for word in row)
    ranked = sorted(counts, key=lambda word: (-counts[word], word))
    out = []
    if len(ranked) == 2:
        out.append((f"{spell(ranked[0], alphabet)} dark", [[word == ranked[0] for word in row] for row in rows]))
    else:
        splits = sorted(range(1, len(ranked)), key=lambda k: (counts[ranked[k]] - counts[ranked[k - 1]], k))
        for k in splits[:MAX_DOMINANT]:
            dark = set(ranked[:k])
            label = f"the {k} most common words dark ({' '.join(spell(w, alphabet) for w in ranked[:k])})"
            out.append((label, [[word in dark for word in row] for row in rows]))
    if len(alphabet) == 2 and layout.word_size > 1:
        for j in range(layout.word_size):
            out.append((f"symbol {j + 1} of each word, {alphabet[1]} dark", [[word[j] == 1 for word in row] for row in rows]))
    return out


def trim_border(matrix: list) -> tuple:
    """(matrix, (top, bottom, left, right)): the matrix with every uniform edge row and column
    cut off (a quiet zone), and how many were cut on each side."""
    rows = [list(row) for row in matrix]
    top = bottom = left = right = 0
    while len(rows) > 1 and len(set(rows[0])) == 1:
        rows.pop(0)
        top += 1
    while len(rows) > 1 and len(set(rows[-1])) == 1:
        rows.pop()
        bottom += 1
    while len(rows[0]) > 1 and len({row[0] for row in rows}) == 1:
        rows = [row[1:] for row in rows]
        left += 1
    while len(rows[0]) > 1 and len({row[-1] for row in rows}) == 1:
        rows = [row[:-1] for row in rows]
        right += 1
    return rows, (top, bottom, left, right)


# ---- reading ---------------------------------------------------------------------------------------

@dataclass
class Candidate:
    layout: Layout
    mapping: str
    matrix: list                      # the module matrix that was read (border cut when it had one)
    border: tuple                     # (top, bottom, left, right) modules cut
    structure: dict | None = None     # qr_matrix.probe's best orientation, for a QR-sized square
    readings: list = field(default_factory=list)

    @property
    def shape(self) -> str:
        return f"{len(self.matrix)}x{len(self.matrix[0])}"

    def describe(self, alphabet: list) -> str:
        lay = self.layout
        how = {"lines": "the lines as rows", "square": "a square with no delimiter",
               "delimiter": f"rows ended by the word {spell(lay.delimiter or (), alphabet)}"}[lay.kind]
        cut = f", border cut {'/'.join(map(str, self.border))} (top/bottom/left/right)" if any(self.border) else ""
        return (f"words of {lay.word_size} symbol(s), {how}: {len(lay.rows)}x{len(lay.rows[0])} words, "
                f"{self.mapping}{cut}, read as {self.shape}")


def _is_qr_size(matrix) -> bool:
    side = len(matrix)
    return side == len(matrix[0]) and 21 <= side <= 177 and (side - 17) % 4 == 0


def read_matrix(matrix: list) -> tuple:
    """(readings, structure) of one module matrix: the strict QR decode, the other matrix families,
    then the QR repair decode when the fixed structure is plausible. `structure` is the probe's
    best orientation for a QR-sized square that the strict decode did not read."""
    readings, structure = [], None
    if _is_qr_size(matrix):
        readings = qr.decode_matrix(matrix)
    if not readings and len(matrix) <= MAX_ROWS and len(matrix[0]) <= MAX_COLS:
        readings = [item for item in qr.recognize_other(matrix) if "bytes" in item]
    if not readings and _is_qr_size(matrix):
        report = qr.probe(matrix)
        structure = {**report["best"], "plausible": report["plausible"]}
        if report["plausible"]:
            readings = qr.decode_matrix(matrix, repair=True)
    return readings, structure


def _rank(candidate: Candidate) -> tuple:
    """Unread candidates, most worth a look first: a plausible QR structure, then a delimiter
    layout of multi-symbol words (a signature, not an accident), then how much QR structure."""
    s = candidate.structure
    return (bool(s and s["plausible"]), candidate.layout.kind == "delimiter" and candidate.layout.word_size > 1,
            (s["finder_score"] + s["timing_score"]) if s else -1)


def worth_a_look(candidate: Candidate, alphabet: list) -> bool:
    """Whether an unread grid is reported at all. A text of few symbols lays out as some grid far
    too easily (a hex dump, a repeated sentence, bits in fixed-width lines) to report every one:
    only a grid that shows QR structure, or a two-symbol stream whose multi-symbol words have a
    clean delimiter word, is material for a human or model read."""
    plausible, signature, _score = _rank(candidate)
    return plausible or (signature and len(alphabet) == 2)


def analyse(stream: Stream, deadline=None, skipped: list | None = None) -> list:
    """[Candidate] of a symbol stream, best first: a candidate that reads comes first and ends the
    search; the rest are ordered by how much they are worth a look (_rank). At most MAX_CANDIDATES
    matrices are read, and none after `deadline` (time.monotonic()); what was left out is named in
    `skipped`."""
    out, seen = [], set()
    for layout in layouts(stream):
        for label, full in mappings(layout, stream.alphabet):
            cut, border = trim_border(full)
            shapes = [(cut, border)] + ([(full, (0, 0, 0, 0))] if any(border) else [])
            for matrix, edges in shapes:
                if len(matrix) < MIN_SIDE or len(matrix[0]) < MIN_SIDE:
                    continue
                key = tuple(tuple(row) for row in matrix)
                inverse = tuple(tuple(not cell for cell in row) for row in matrix)
                if key in seen or inverse in seen:
                    continue
                seen.add(key)
                if len(seen) > MAX_CANDIDATES or (deadline is not None and time.monotonic() > deadline):
                    if skipped is not None:
                        why = f"{MAX_CANDIDATES} matrices read" if len(seen) > MAX_CANDIDATES else "out of time"
                        skipped.append(f"symbol stream: {why}; later layouts were not read")
                    return sorted(out, key=_rank, reverse=True)
                readings, structure = read_matrix(matrix)
                candidate = Candidate(layout, label, matrix, edges, structure, readings)
                if readings:
                    return [candidate] + sorted(out, key=_rank, reverse=True)
                out.append(candidate)
    return sorted(out, key=_rank, reverse=True)


# ---- one delivery ----------------------------------------------------------------------------------

@dataclass
class Finding:
    file: str
    alphabet: list
    symbols: int
    candidates: list                  # [Candidate], best first
    flags: list = field(default_factory=list)

    @property
    def read(self) -> Candidate | None:
        return self.candidates[0] if self.candidates and self.candidates[0].readings else None


@dataclass
class Report:
    findings: list = field(default_factory=list)        # [Finding], one per file that is a stream
    written: list = field(default_factory=list)         # [Path]
    skipped: list = field(default_factory=list)


def decode_text(data: bytes) -> str | None:
    """The text of a file: UTF-8 (with or without a BOM) or BOM-marked UTF-16, else None."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            return None
    if b"\x00" in data[:4096]:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def upright(candidate: Candidate) -> list:
    """The matrix of a candidate as a person or a camera decoder wants it: a QR reading turned
    upright with its fixed patterns painted back when it needed the repair; any other matrix as
    it was read."""
    first = candidate.readings[0] if candidate.readings else None
    if first and first.get("symbology") == "qr" and "transform" in first:
        matrix = qr.apply_transform(candidate.matrix, first["transform"])
        return qr.restore_finders(matrix) if first.get("repaired") else matrix
    return candidate.matrix


def examine(files: dict, ff, *, out_dir: Path | None = None, deadline=None) -> Report:
    """Read every file of {name: bytes} that is a symbol stream; write the read matrix, or the best
    unread grids, as PNG under out_dir."""
    rep = Report()
    for name in sorted(files):
        data = files[name]
        text = decode_text(data) if len(data) <= MAX_INPUT else None
        stream = read_symbols(text) if text is not None else None
        if stream is None:
            continue
        candidates = analyse(stream, deadline, rep.skipped)
        if not candidates or not (candidates[0].readings or worth_a_look(candidates[0], stream.alphabet)):
            continue
        finding = Finding(name, stream.alphabet, len(stream.flat), candidates)
        for reading in (finding.read.readings if finding.read else []):
            finding.flags += ff.find_flags(reading["text"] if reading.get("text") is not None else reading["bytes"])
        finding.flags = list(dict.fromkeys(finding.flags))
        rep.findings.append(finding)
        if out_dir is not None:
            out_dir.mkdir(parents=True, exist_ok=True)
            keep = [finding.read] if finding.read else [c for c in finding.candidates
                                                        if worth_a_look(c, stream.alphabet)][:MAX_WRITTEN]
            for k, candidate in enumerate(keep):
                lay = candidate.layout
                path = out_dir / f"{vs.safe_name(name)}.{lay.kind}-w{lay.word_size}-{candidate.shape}.{k}.png"
                path.write_bytes(qr.render_png(upright(candidate)))
                rep.written.append(path)
    return rep


def _reading_line(reading: dict) -> str:
    if reading.get("symbology") == "qr":
        kind = f"QR v{reading['version']}-{reading['ecl']} mask {reading['mask']}"
        kind += " (repair decode: finders or format damaged)" if reading.get("repaired") else ""
    else:
        kind = str(reading.get("symbology", "matrix code"))
    return kind


def result_of(rep: Report, *, challenge_id=None, seconds: float = 0.0, root: Path | None = None):
    """The SolverResult of a Report (status rules in the module docstring)."""
    from ctf.result import Cost, Evidence, SolverResult

    def rel(p):
        try:
            return str(Path(p).relative_to(root)) if root else str(p)
        except ValueError:
            return str(p)

    flags, evidence, notes = [], [], []
    for f in rep.findings:
        symbols = " ".join(f.alphabet)
        if f.read:
            for reading in f.read.readings:
                evidence.append(Evidence("decode", f"{_reading_line(reading)} from the symbol stream ({symbols}): "
                                                   f"{f.read.describe(f.alphabet)}", path=f.file))
                if not f.flags:
                    text = reading["text"] if reading.get("text") is not None else reading["bytes"].hex()
                    notes.append(f"{f.file}: the symbol stream decodes to a {_reading_line(reading)} with no flag "
                                 f"in it: {text[:200]!r}")
            flags += f.flags
        else:
            best = f.candidates[0]
            notes.append(f"{f.file}: {f.symbols} symbols of {len(f.alphabet)} kinds ({symbols}) lay out as "
                         f"{len(f.candidates)} grid(s), none read by a matrix decoder; best: {best.describe(f.alphabet)}")
    for p in rep.written:
        evidence.append(Evidence("carve", "matrix written", path=rel(p)))
    notes += rep.skipped
    flags = list(dict.fromkeys(flags))
    status = vs.status_of(flags, (), material=bool(rep.findings))
    return SolverResult(status=status, flags=flags, evidence=evidence, cost=Cost(seconds=round(seconds, 3)),
                        engine=ENGINE, challenge_id=challenge_id, notes="; ".join(notes))


# ---- the engine contract ---------------------------------------------------------------------------

def solve(challenge_dir: Path, profile, **opts):
    """Engine contract. opts: out (folder for the matrices; default <challenge>/recon/symbol_stream),
    seconds (budget, default 20)."""
    t0 = time.monotonic()
    challenge_dir = Path(challenge_dir)
    out_dir = Path(opts["out"]) if opts.get("out") else challenge_dir / "recon" / "symbol_stream"
    paths, skipped = vs.challenge_paths(challenge_dir, MAX_INPUT)
    files = {rel: path.read_bytes() for rel, path in paths}
    rep = examine(files, flagfmt.for_profile(profile), out_dir=out_dir,
                  deadline=t0 + float(opts.get("seconds", DEFAULT_SECONDS)))
    rep.skipped += skipped
    return result_of(rep, seconds=time.monotonic() - t0, root=challenge_dir)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="symbol_stream.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("files", nargs="+", type=Path)
    ap.add_argument("--event", help="event slug (default: the current event)")
    ap.add_argument("--out", type=Path, help="folder for the matrices as PNG (default: none written)")
    ap.add_argument("--seconds", type=float, default=DEFAULT_SECONDS)
    a = ap.parse_args(argv)
    from ctf import event
    profile = event.load(a.event) if a.event else event.current()
    missing = [str(p) for p in a.files if not p.is_file()]
    if missing:
        print(f"symbol_stream.py: no such file: {', '.join(missing)}", file=sys.stderr)
        return 2
    t0 = time.monotonic()
    rep = examine({str(p): p.read_bytes() for p in a.files}, flagfmt.for_profile(profile), out_dir=a.out,
                  deadline=t0 + a.seconds)
    for f in rep.findings:
        print(f"{f.file}: {f.symbols} symbols of {len(f.alphabet)} kinds, {len(f.candidates)} grid(s)")
        for candidate in f.candidates[:MAX_WRITTEN]:
            print(f"  {candidate.describe(f.alphabet)}")
            for reading in candidate.readings:
                print(f"    {_reading_line(reading)}: {reading.get('text')!r}")
    for p in rep.written:
        print(f"written: {p}")
    print(result_of(rep, seconds=time.monotonic() - t0).to_json())
    return 0


if __name__ == "__main__":
    sys.exit(main())
