#!/usr/bin/env python3
"""Keyed classical / book-cipher sweep with handout key harvest (B-062).

    python -m ctf run common.keyed_sweep <challenge_dir> [--opt key=WORD] [--opt corpus=FILE] [--opt seconds=N]

A keyed classical cipher (Vigenere, Beaufort, autokey, ...) or a book cipher ships its key in the
handout: a column of a table in a sibling file, a word a prose rule points at, a song or page the
indices count into. This engine does the mechanical half with no model:

  1. reads the handout's text files: the sweep's scratch copy `unpacked/` (B-013: originals plus
     every archive member) when there is one, else `files/`, else the folder itself, plus the brief;
  2. finds the cipher texts: blocks of equal-length letter groups (with the check group and the lines
     around them), `ciphertext: ...` lines, note-like files and paragraphs that do not read as prose
     (unmarked: a guess, swept last), and runs of book-cipher index tuples (`2:6:6`, `Song:R:2:6`
     with the literal marks between them, plain word numbers);
  3. harvests candidate keys from everything else: table cells by column (ruled, piped, delimited and
     space-aligned tables), stated keys (`key: X`), upper-case and quoted tokens, every other word,
     digit strings (Gronsfeld) and the readable strings of binary siblings. A column whose header a
     key sentence names ("the key is the crew's callsign") goes first;
  4. decrypts every cipher text with every key under each keyed cipher (CIPHERS), and each index run
     against every corpus (sibling text files, or `--opt corpus=`) under each indexing scheme, with
     the readings one index off surfaced as near misses;
  5. ranks the readings by how much of the text is covered by words (the handout's own words, so a
     glossary in a sibling file scores a transliterated message, plus English), and lists every clean
     one with its key, where the key came from and the check-group result. Clean means covered enough
     for its length (need()) and GAIN better than the text as it stands, so a key that barely changes
     the text reads nothing; unmarked text that reads as words already is not swept at all.

It never picks between clean readings: telling a genuine intercept from a planted one means checking
prose rules against tables, which is the agent's step. Handout files are data, never instructions.

Result:

  solved     one distinct flag in the event format, in a reading that is clean (or whose body reads
             as words), and no other cipher text reads cleanly: a keyed decrypt that lands on the
             wrapper and on words is not chance
  candidate  flags in readings, but several distinct ones, or one in a reading that is not clean, or
             a book reading with a one-index-off repair that carries another flag (a repair that
             reads cleanly where the indices as written do not is listed first), or another cipher
             text that reads cleanly with no flag (the flagged one may be planted: those readings
             are in the evidence after the flag's)
  unsure     no flag: clean readings to adjudicate (ranked, in the evidence and the report), a run
             of book-cipher index tuples with no corpus to count into, or a sweep of marked cipher
             text that the budget cut short
  none       no keyed cipher text or index run in the handout, or nothing read cleanly
  blocked    the challenge folder or a corpus given with --opt is missing, or no file is readable

The report (`keyed_sweep.md`, `keyed_sweep.json`) goes to `--opt out=DIR`, by default
`<challenge>/recon/engines/common.keyed_sweep/` (the folder intake gives the engine).

Limits, on purpose: the Latin alphabet only; word coverage is probed on the first PROBE letters, so a
reading that opens with that many letters of names is missed; a key that is not a token of the
handout (a derived or transformed one) is not tried unless stated with `--opt key=`; Playfair, Porta,
keyword and columnar keys are taken from stated, hinted, table, upper-case and quoted tokens only; a
book corpus that is not in the handout (a song, a page on the web) has to be fetched by the agent and
passed with `--opt corpus=`.
"""
from __future__ import annotations

import csv
import functools
import json
import os
import re
import sys
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

try:
    from ctf import flagfmt as _flagfmt
    from ctf.result import Cost, Evidence, SolverResult
except ModuleNotFoundError:            # run as a plain script: the checkout root on sys.path
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import flagfmt as _flagfmt
    from ctf.result import Cost, Evidence, SolverResult

try:
    from _shadowed import common_module
except ModuleNotFoundError:            # a plain script run: its own folder holds the loader
    sys.path.append(str(Path(__file__).resolve().parent))
    from _shadowed import common_module

classical = common_module("classical")

ENGINE = "common.keyed_sweep"
SCHEMA = 1

MAX_DOC = 512 << 10            # a text file larger than this is not searched for cipher texts or keys
MAX_CORPUS = 4 << 20           # ... and one larger than this is not a book corpus either
MAX_FILES = 400                # handout files read
MAX_BINARY = 1 << 20           # a binary sibling larger than this is not searched for strings
BINARY_KEYS = 200              # keys taken from one binary sibling's strings
BINARY_KEYS_TOTAL = 1000       # ... and from all of them
MAX_CIPHERTEXTS = 12
MAX_KEYS = 6000
GROUP_MIN, GROUP_MAX = 3, 10   # letters in one group of a group block
GROUPS_MIN = 4                 # groups in a block
MIN_LETTERS = 12               # letters of a group block
LOOSE_MIN = 20                 # letters of a file or paragraph taken as a cipher text (a title line is not one)
LABELLED_MIN = 6               # letters of a `ciphertext: ...` value
WHOLE_MAX = 4096               # non-blank characters of a file (or paragraph) taken whole as a cipher text
PARAS_MAX = 3                  # paragraphs of one file taken as cipher texts, the longest first
LOOSE_MAX = 6                  # unmarked cipher texts (whole files and paragraphs) in all
# Only a note-like file is taken whole or by paragraph: source code, markup and data files do not read
# as prose either, and are not messages.
LOOSE_EXT = frozenset({"", ".txt", ".text", ".md", ".enc", ".cipher", ".ct", ".msg", ".crypt", ".asc"})
MARKED = ("stated", "groups", "labelled")       # cipher texts the handout marks as such
PROSE = 0.5                    # dictionary word coverage at which a file is prose, not a cipher text
KEY_MIN, KEY_MAX = 3, 40       # letters of a key
DIGITS_MIN, DIGITS_MAX = 2, 16
CAP = 600                      # letters of a reading that are scored
PROBE = 48                     # letters scored first; under PROBE_FLOOR the rest is not scored
PROBE_FLOOR = 0.2
NEAR = 0.3                     # coverage from which a reading is kept for the report; unmarked text that
                               # reads this well as it stands is not a cipher text
GAIN = 0.25                    # coverage a clean reading must add to the text as it stands: a key that
                               # barely changes the text (a keyword alphabet two letters off) reads nothing
LOOSE_WORDS = 500              # more plain words than this in the handout: not tried on unmarked text
CHANCE = 0.01                  # expected chance hits above which an unproven flag-shaped reading is dropped
HEX_BODY = 16                  # characters of a flag body that reads as hex (with six letters or more)
KEEP = 200                     # readings kept
RUNNING_MAX = 1500             # running-key offsets tried per cipher text
INDEX_MIN = 4                  # index tuples in a run
NUMBERS_MIN = 8                # plain numbers in a run
CORPUS_WORDS = 40              # words of a text file that may be a book corpus
MAX_CORPORA = 24
BOOK_FAIL = 0.25               # share of indices that may fall outside the corpus in a kept reading
MEND_MIN = 2.5                 # letters of word coverage a one-off repair must add to be offered
MEND_FLAGS = 2                 # repairs of one reading whose flags are listed
LOOSE_FLAGS = 3                # unproven flag-shaped readings of one text that are listed
DEFAULT_SECONDS = 6.0          # CPU seconds
DEFAULT_WALL = 20.0            # wall seconds: under the manifest's intake timeout (30 s)
EVIDENCE_MAX = 8
QUOTE = 240                    # characters of a reading quoted in the evidence

SKIP_DIRS = {"recon", ".git", ".ctf", "__pycache__"}
# Skipped by name only where the harness or the sweep puts them: a handout file or archive member of the
# same name deeper down is read like any other.
HARNESS_FILES = {"challenge.json", "challenge.toml", "notes.md", "triage.md", "SOLVED", ".DS_Store"}  # folder top
SCRATCH_OWN = {".sweep.json", ".sweep-owner", ".lock"}     # the sweep's own files at the top of its scratch copy
ROOTS = (("unpacked", "the sweep's scratch copy"), ("files", "files/ (no sweep output)"))

TIERS = {0: "stated or hinted", 1: "table cell, upper-case or quoted token", 2: "word of the handout",
         3: "string of a binary sibling"}


def need(n: int) -> float:
    """The word coverage at which a reading of n letters is clean. Short readings need more: a wrong
    key lands on a word or two by chance, and over thousands of keys that is several readings."""
    if n < 6:
        return float("inf")
    return 0.8 if n < 30 else 0.65 if n < 60 else 0.5


# ---------------------------------------------------------------- the handout

@dataclass
class Doc:
    rel: str                       # relative to the challenge folder ("brief" for the brief)
    text: str
    lines: list = field(default_factory=list)

    def __post_init__(self):
        self.lines = self.text.split("\n")              # tabs kept: a tab-delimited table needs them


_CONTROL = re.compile(r"[\x00-\x08\x0b\x0e-\x1f]")
_C1 = re.compile(r"[\x7f-\x9f]")


def decode(data: bytes):
    """The text of a file, or None when it is not text (NUL or control bytes, or not UTF-8/16 and not
    clean Latin-1)."""
    if data[:3] == b"\xef\xbb\xbf":
        data = data[3:]
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            text = data.decode("utf-16")
        except UnicodeDecodeError:
            return None
    else:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("latin-1")
            if _C1.search(text):
                return None
    if _CONTROL.search(text):
        return None
    return text.replace("\r\n", "\n").replace("\r", "\n")


def handout_root(challenge_dir: Path):
    for name, what in ROOTS:
        if (challenge_dir / name).is_dir():
            return challenge_dir / name, what
    return challenge_dir, "the folder itself"


def read_brief(challenge_dir: Path, notes: list) -> str:
    """The brief of a pulled challenge (challenge.json) or a drop folder (challenge.toml): data only."""
    for name, load in (("challenge.json", json.loads), ("challenge.toml", tomllib.loads)):
        p = challenge_dir / name
        if not p.is_file() or p.is_symlink():
            continue
        try:
            info = load(p.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            notes.append(f"brief not read: {name} does not parse ({type(e).__name__})")
            continue
        if isinstance(info, dict):
            return "\n".join(str(info.get(k) or "") for k in ("name", "description")).strip()
    return ""


def read_handout(challenge_dir: Path, notes: list):
    """(docs, binaries, where): the text files as Docs, [(rel, path)] of the binary ones of MAX_BINARY
    bytes and less (read again only when there is a cipher text to try their strings on)."""
    root, where = handout_root(challenge_dir)
    docs, binaries, seen = [], [], 0
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not (here / d).is_symlink())
        for n in sorted(filenames):
            p = here / n
            if ((here == challenge_dir and n in HARNESS_FILES) or (here == root and n in SCRATCH_OWN)
                    or n.startswith(".env") or p.is_symlink() or not p.is_file()):
                continue
            rel = str(p.relative_to(challenge_dir))
            seen += 1
            if seen > MAX_FILES:
                notes.append(f"more than {MAX_FILES} handout files: the rest (from {rel}) is not read")
                return docs, binaries, where
            try:
                size = p.stat().st_size
                if size > max(MAX_CORPUS, MAX_BINARY):
                    notes.append(f"{rel}: {size} bytes, not read")
                    continue
                data = p.read_bytes()
            except OSError as e:
                notes.append(f"{rel}: unreadable ({type(e).__name__})")
                continue
            text = decode(data) if size <= MAX_CORPUS else None
            if text is None:
                if size <= MAX_BINARY:
                    binaries.append((rel, p))
            elif text.strip():
                docs.append(Doc(rel, text))
    return docs, binaries, where


# ---------------------------------------------------------------- cipher texts

@dataclass
class Ciphertext:
    id: str
    doc: str
    line: int                      # 1-based, the first line
    kind: str                      # stated | groups | labelled | whole | para
    text: str                      # what is decrypted
    label: str = ""
    context: tuple = ()
    groups: int | None = None
    group_len: int | None = None
    check: dict | None = None      # {"stated", "counted", "ok", "where"}
    base: float = 0.0              # word coverage of the text as it stands (no key)

    @property
    def marked(self) -> bool:
        return self.kind in MARKED

    def own_lines(self):
        """(doc, first line index, end) of an unmarked text's own lines, which its scorer leaves out of
        the handout words; None for a marked one (its lines are left out for every text)."""
        if self.marked:
            return None
        if self.kind == "whole":
            return (self.doc, 0, float("inf"))
        return (self.doc, self.line - 1, self.line - 1 + self.text.count("\n") + 1)

    @property
    def letters(self) -> int:
        return sum(1 for c in self.text if c.isascii() and c.isalpha())

    def check_line(self) -> str:
        if self.kind != "groups":
            return ""
        short = "" if self.group_len is None else f" of {self.group_len}"
        if not self.check:
            return f"{self.groups} groups{short}, no check group stated"
        c = self.check
        verdict = "ok" if c["ok"] else "MISMATCH"
        return f"check group {c['stated']} ({c['where']}) vs {c['counted']} groups{short} counted: {verdict}"

    def to_dict(self) -> dict:
        return {"id": self.id, "doc": self.doc, "line": self.line, "kind": self.kind, "letters": self.letters,
                "label": self.label, "context": list(self.context), "groups": self.groups,
                "group_len": self.group_len, "check": self.check, "check_line": self.check_line(),
                "base_coverage": self.base, "text": self.text}


def _group_tokens(line: str):
    toks = line.split()
    if not toks or not all(t.isascii() and t.isalpha() for t in toks):
        return None
    if not (all(t.isupper() for t in toks) or all(t.islower() for t in toks)):
        return None
    return toks


def _uniform(toks, n: int) -> bool:
    return all(len(t) == n for t in toks[:-1]) and 1 <= len(toks[-1]) <= n


_CHECK_WORD = re.compile(r"\b(?:GR|GRP|GROUPS?|CK|CHECK)\b\W{0,3}(\d{1,4})\b", re.I)


def group_blocks(lines) -> list:
    """[(first line index, end index, groups, group length)] of the blocks of equal-length letter groups
    (the last group may be short, and ends the block)."""
    out, i = [], 0
    while i < len(lines):
        toks = _group_tokens(lines[i])
        n = len(toks[0]) if toks else 0
        if not toks or len(toks) < 2 or not GROUP_MIN <= n <= GROUP_MAX or not _uniform(toks, n):
            i += 1
            continue
        upper, groups, j = toks[0].isupper(), list(toks), i + 1
        while j < len(lines) and len(groups[-1]) == n:
            more = _group_tokens(lines[j])
            if not more or more[0].isupper() != upper or not _uniform(more, n):
                break
            groups += more
            j += 1
        if len(groups) >= GROUPS_MIN and sum(map(len, groups)) >= MIN_LETTERS:
            out.append((i, j, groups, n))
            i = j
        else:
            i += 1
    return out


def _block_check(lines, i: int, j: int, counted: int):
    """The stated group count of the block lines[i:j]: a line of digits right after it, else a
    `GR 21`-style word in the lines right before it."""
    tail = lines[j].strip() if j < len(lines) else ""
    if re.fullmatch(r"\d{1,4}", tail):
        stated, where = int(tail), "the line after the groups"
    else:
        stated = where = None
        k = i - 1
        while k >= 0 and lines[k].strip() and i - k <= 3:
            m = _CHECK_WORD.search(lines[k])
            if m:
                stated, where = int(m.group(1)), "the preamble"
                break
            k -= 1
    if stated is None:
        return None
    return {"stated": stated, "counted": counted, "ok": stated == counted, "where": where}


_LABELLED = re.compile(r"^\s*(?:cipher[ _-]?text|cipher|encrypted(?:[ _-](?:text|message|flag))?|enc|ct|crypt(?:ed)?)"
                       r"\s*[:=]\s*(\S.*?)\s*$", re.I)


def _letters_in(text: str) -> int:
    return sum(1 for c in text if c.isascii() and c.isalpha())


def _cipherlike(text: str) -> bool:
    """Enough letters, short enough, and not prose by dictionary word coverage."""
    return (len("".join(text.split())) <= WHOLE_MAX and _letters_in(text) >= LOOSE_MIN
            and classical.word_coverage(text) < PROSE)


def _paragraphs(lines) -> list:
    """[(first line index, line count, text)] of the blocks of non-blank lines."""
    out, i = [], 0
    while i < len(lines):
        if not lines[i].strip():
            i += 1
            continue
        j = i
        while j < len(lines) and lines[j].strip():
            j += 1
        out.append((i, j - i, "\n".join(ln.strip() for ln in lines[i:j])))
        i = j
    return out


def _table_lines(lines) -> set:
    """The line indexes that belong to a table (header, rule and rows)."""
    out = set()
    for table in find_tables(lines):
        if table.header_line:
            out.add(table.header_line - 1)
            if table.kind == "ruled":
                out.add(table.header_line)
        out.update(n - 1 for n, _cells in table.rows)
    return out


def find_ciphertexts(docs, stated=(), notes=None):
    """(cipher texts, spans): spans is {doc: set of line indexes} holding cipher text, which the key
    harvest and the glossary leave out."""
    notes = [] if notes is None else notes
    found, spans = [], {}
    for k, text in enumerate(stated, 1):
        if _letters_in(text) >= LABELLED_MIN:
            found.append(Ciphertext(f"stated#{k}", "", 0, "stated", text, label="given with --opt ciphertext"))
        else:
            notes.append(f"--opt ciphertext #{k}: under {LABELLED_MIN} letters, not swept")
    loose = []
    for doc in docs:
        mine, used = [], set()
        for i, j, groups, n in group_blocks(doc.lines):
            head, k = [], i - 1
            while k >= 0 and doc.lines[k].strip() and len(head) < 3:
                head.insert(0, doc.lines[k].strip())
                k -= 1
            tail = doc.lines[j].strip() if j < len(doc.lines) else ""
            mine.append(Ciphertext("", doc.rel, i + 1, "groups", " ".join(groups), label=head[0] if head else "",
                                   context=tuple(head + ([tail] if tail else [])), groups=len(groups), group_len=n,
                                   check=_block_check(doc.lines, i, j, len(groups))))
            used.update(range(i, j))
        for i, line in enumerate(doc.lines):
            m = None if i in used else _LABELLED.match(line)
            if m and _letters_in(m.group(1)) >= LABELLED_MIN:
                mine.append(Ciphertext("", doc.rel, i + 1, "labelled", m.group(1).strip("\"'`"),
                                       label=line.strip()[:60]))
                used.add(i)
        mine.sort(key=lambda c: c.line)
        for k, c in enumerate(mine, 1):
            c.id = f"{doc.rel}#{k}"
        found += mine
        if used:
            spans[doc.rel] = used
            continue
        # No marked cipher text: the file as a whole, and each of its paragraphs, when it does not read as
        # prose and is not a table. These stay in the key harvest and the glossary (no span): a file of
        # names is a key source first.
        if doc.rel != "brief" and Path(doc.rel).suffix.lower() not in LOOSE_EXT:
            continue
        rows = _table_lines(doc.lines)
        filled = [i for i, ln in enumerate(doc.lines) if ln.strip()]
        if not filled or 2 * sum(1 for i in filled if i in rows) > len(filled):
            continue
        paras = _paragraphs(doc.lines)
        if _cipherlike(doc.text.strip()):
            loose.append(Ciphertext(f"{doc.rel}#whole", doc.rel, filled[0] + 1, "whole", doc.text.strip(),
                                    label="the whole file"))
        if len(paras) >= 2:
            cands = [(i, text) for i, n, text in paras
                     if not any(j in rows for j in range(i, i + n)) and _cipherlike(text)]
            for i, text in sorted(cands, key=lambda c: -_letters_in(c[1]))[:PARAS_MAX]:
                loose.append(Ciphertext(f"{doc.rel}#para{i + 1}", doc.rel, i + 1, "para", text,
                                        label=f"the paragraph at line {i + 1}"))
    if len(loose) > LOOSE_MAX:
        notes.append(f"{len(loose)} files or paragraphs do not read as prose: only the first {LOOSE_MAX} are swept "
                     f"(not swept: {', '.join(c.id for c in loose[LOOSE_MAX:])})")
    found += loose[:LOOSE_MAX]
    if len(found) > MAX_CIPHERTEXTS:
        notes.append(f"{len(found)} cipher texts found: only the first {MAX_CIPHERTEXTS} are swept "
                     f"(not swept: {', '.join(c.id for c in found[MAX_CIPHERTEXTS:])})")
        found = found[:MAX_CIPHERTEXTS]
    return found, spans


# ---------------------------------------------------------------- tables and keys

@dataclass
class Table:
    kind: str                      # ruled | piped | delimited | aligned
    header: list                   # column names ([] when the table has none)
    rows: list                     # [(1-based line, [cells])]
    header_line: int = 0           # 1-based


_RULE = re.compile(r"^\s*[-=]{2,}(?:\s+[-=]{2,})+\s*$")
_PIPE_RULE = re.compile(r":?-{2,}:?")


def _split_pipe(line: str):
    if line.count("|") < 1:
        return None
    cells = [c.strip() for c in line.strip().strip("|").split("|")]
    return cells if len(cells) >= 2 else None


def _split_delim(delim: str):
    def split(line: str):
        if delim not in line:
            return None
        try:
            cells = [c.strip() for c in next(csv.reader([line], delimiter=delim))]
        except (csv.Error, StopIteration):
            return None
        return cells if len(cells) >= 2 else None
    return split


def _split_aligned(line: str):
    cells = re.split(r"\s{2,}", line.strip())
    return cells if len(cells) >= 2 and all(cells) else None


def find_tables(lines, skip=()) -> list:
    """The tables of a text: ruled (a header over a line of dash runs: fixed-width columns), piped,
    delimited (tab, comma, semicolon) and space-aligned (two blanks and more between cells). Three
    consecutive lines of the same shape make a table; `skip` lines (cipher text) are never part of one."""
    used, out = set(skip), []
    wide = [ln.expandtabs(8) for ln in lines]          # fixed-width columns are cut by position
    for i, line in enumerate(wide):
        if i in used or i == 0 or not _RULE.match(line) or not wide[i - 1].strip() or i - 1 in used:
            continue
        starts = [m.start() for m in re.finditer(r"[-=]{2,}", line)]

        def cut(s, starts=starts):
            return [s[a:b].strip() for a, b in zip(starts, starts[1:] + [None])]
        rows, j = [], i + 1
        while j < len(wide) and wide[j].strip() and j not in used:
            rows.append((j + 1, cut(wide[j])))
            j += 1
        out.append(Table("ruled", cut(wide[i - 1]), rows, i))
        used.update(range(i - 1, j))
    for kind, split in (("piped", _split_pipe), ("delimited", _split_delim("\t")), ("delimited", _split_delim(",")),
                        ("delimited", _split_delim(";")), ("aligned", _split_aligned)):
        i = 0
        while i < len(lines):
            cells = None if i in used else split(lines[i])
            if not cells:
                i += 1
                continue
            rows, j = [(i + 1, cells)], i + 1
            while j < len(lines) and j not in used:
                more = split(lines[j])
                if not more or len(more) != len(cells):
                    break
                rows.append((j + 1, more))
                j += 1
            if len(rows) < 3:
                i += 1
                continue
            used.update(range(i, j))
            i = j
            if kind == "piped":
                rows = [r for r in rows if not all(_PIPE_RULE.fullmatch(c) for c in r[1])]
            if kind == "aligned":                      # no way to tell a header row: every row is data
                out.append(Table(kind, [], rows))
            elif rows:
                out.append(Table(kind, rows[0][1], rows[1:], rows[0][0]))
    return out


@dataclass
class Key:
    text: str                      # as written in the handout
    norm: str                      # lower-case letters, or the digits
    kind: str                      # alpha | digits
    tier: int
    why: str
    sources: list = field(default_factory=list)   # "file:line"

    @property
    def source(self) -> str:
        return f"{self.sources[0]} ({self.why})" if self.sources else self.why

    def to_dict(self) -> dict:
        return {"key": self.text, "kind": self.kind, "tier": self.tier, "why": self.why, "sources": self.sources}


_KEY_WORD = re.compile(r"\b(?:keys?|keyword|keyed|password|passphrase|passcode|primer|schl[uü]ssel|clave)\b", re.I)
_STATED_KEY = re.compile(r"\b(?:key|keyword|password|passphrase|passcode|primer)\b\s*(is|was|=|:)\s*"
                         r"([\"'“‘`]?)([A-Za-z0-9][\w-]{1,40})", re.I)
_HINT_STOP = frozenset("""that this with from each which encrypted cipher text message letters only table used using
alphabet assigned there their word words into what when where have will must same your been were they them then
than also""".split())
_TOKEN = re.compile(r"[A-Za-z]+(?:'[A-Za-z]+)?|\d+")
_QUOTED = re.compile(r"[\"“‘`]([^\"”’`\n]{3,60})[\"”’`]")
_SINGLE = re.compile(r"[A-Za-z0-9][\w'-]*")


def key_sentences(docs) -> list:
    """The sentences that talk about a key (paragraphs joined, so a wrapped sentence is whole)."""
    out = []
    for doc in docs:
        for para in re.split(r"\n\s*\n", doc.text):
            flat = " ".join(para.split())
            for sentence in re.split(r"(?<=[.!?])\s+", flat):
                if _KEY_WORD.search(sentence):
                    out.append((doc.rel, sentence))
    return out


def hint_words(sentences) -> dict:
    """{word: the key sentence that names it}: the nouns a key sentence points at."""
    out = {}
    for _rel, sentence in sentences:
        for w in re.findall(r"[A-Za-z]{4,}", sentence):
            w = w.lower()
            if w not in _HINT_STOP and not _KEY_WORD.fullmatch(w):
                out.setdefault(w, sentence)
    return out


def _named(header: str, hints: dict):
    h = "".join(c for c in header.lower() if c.isalpha())
    for form in (h, h[:-1] if h.endswith("s") else h, h + "s"):
        if len(form) >= 4 and form in hints:
            return hints[form]
    return None


class KeyRing:
    """The candidate keys, one per normal form, each with its best tier and where it was seen."""

    def __init__(self):
        self.keys: dict = {}
        self.cut = False

    def add(self, text: str, tier: int, why: str, doc: str = "", line: int = 0, digits: bool = False):
        text = text.strip()
        if digits:
            norm, kind = "".join(c for c in text if c.isdigit()), "digits"
            if not DIGITS_MIN <= len(norm) <= DIGITS_MAX or not norm.strip("0"):
                return
        else:
            norm, kind = classical.letters(text), "alpha"
            if not KEY_MIN <= len(norm) <= KEY_MAX or len(set(norm)) < 2:
                return
        where = f"{doc}:{line}" if line else doc
        key = self.keys.get((kind, norm))
        if key is None:
            if len(self.keys) >= MAX_KEYS:
                self.cut = True
                return
            key = self.keys[(kind, norm)] = Key(text, norm, kind, tier, why)
        elif tier < key.tier:
            key.text, key.tier, key.why = text, tier, why
            if where:                                  # the better sighting leads the list
                key.sources = [where] + [x for x in key.sources if x != where][:3]
                where = ""
        if where and where not in key.sources and len(key.sources) < 4:
            key.sources.append(where)

    def ordered(self) -> list:
        return sorted(self.keys.values(), key=lambda k: k.tier)        # stable: first seen first in a tier


_ASCII_TOKEN = re.compile(rb"(?<![A-Za-z0-9])[A-Za-z][A-Za-z0-9'_-]{2,39}(?![A-Za-z0-9])")
_WIDE_TOKEN = re.compile(rb"(?:[A-Za-z]\x00)(?:[A-Za-z0-9'_-]\x00){2,39}")


def binary_tokens(data: bytes) -> list:
    """The word-like strings of a binary file, ASCII then UTF-16LE, in file order, each once."""
    found = [m.decode("ascii") for m in _ASCII_TOKEN.findall(data)]
    found += [m.decode("utf-16-le") for m in _WIDE_TOKEN.findall(data)]
    return list(dict.fromkeys(found))


def harvest_keys(docs, spans=None, binaries=(), stated=(), notes=None, budget=None) -> list:
    """Every candidate key of the handout, best tier first. `spans` lines (cipher text) are left out."""
    spans, notes = spans or {}, [] if notes is None else notes
    ring = KeyRing()
    for k in stated:
        ring.add(str(k), 0, "given with --opt key", digits=str(k).strip().isdigit())
    hints = hint_words(key_sentences(docs))
    for doc in docs:
        skip = spans.get(doc.rel, set())
        for i, line in enumerate(doc.lines):
            if i in skip:
                continue
            for m in _STATED_KEY.finditer(line):
                verb, quote, value = m.groups()
                if quote or verb in "=:" or value.isupper():
                    ring.add(value, 0, "stated key", doc.rel, i + 1, digits=value.isdigit())
    for doc in docs:
        skip = spans.get(doc.rel, set())
        for table in find_tables(doc.lines, skip):
            for name in table.header:
                ring.add(name, 1, "table header", doc.rel, table.header_line)
            for lineno, cells in table.rows:
                for col, cell in enumerate(cells):
                    if not cell:
                        continue
                    name = table.header[col] if col < len(table.header) else ""
                    sentence = _named(name, hints) if name else None
                    label = f"column {name}" if name else f"column {col + 1}"
                    if sentence:
                        tier, why = 0, f"{label}, named by the key sentence {sentence[:120]!r}"
                    else:
                        tier, why = 1, f"{label} of a {table.kind} table"
                    if _SINGLE.fullmatch(cell):
                        ring.add(cell, tier, why, doc.rel, lineno, digits=cell.isdigit())
                    elif 2 <= len(cell.split()) <= 4:
                        ring.add(cell, min(tier + 1, 2), why + ", the whole cell", doc.rel, lineno)
    for doc in docs:
        skip = spans.get(doc.rel, set())
        for i, line in enumerate(doc.lines):
            if i in skip:
                continue
            for m in _QUOTED.finditer(line):
                ring.add(m.group(1), 1, "quoted", doc.rel, i + 1)
            for tok in _TOKEN.findall(line):
                if tok.isdigit():
                    ring.add(tok, 2, "number", doc.rel, i + 1, digits=True)
                elif tok.isupper():
                    ring.add(tok, 1, "upper-case token", doc.rel, i + 1)
                else:
                    ring.add(tok, 2, "word", doc.rel, i + 1)
        if doc.rel != "brief":
            for tok in _TOKEN.findall(Path(doc.rel).stem):
                ring.add(tok, 2, "file name", doc.rel, digits=tok.isdigit())
    total = 0
    for n, (rel, path) in enumerate(binaries):
        if total >= BINARY_KEYS_TOTAL or (budget is not None and budget.over()):
            notes.append(f"the strings of {len(binaries) - n} binary file(s) (from {rel}) are not tried as keys: "
                         + (f"{BINARY_KEYS_TOTAL} taken already" if total >= BINARY_KEYS_TOTAL else "the budget is spent"))
            break
        took = 0
        try:
            data = Path(path).read_bytes()
        except OSError as e:
            notes.append(f"{rel}: unreadable ({type(e).__name__}), its strings are not tried as keys")
            continue
        for cand in binary_tokens(data):
            if took >= BINARY_KEYS:
                notes.append(f"{rel}: more than {BINARY_KEYS} strings, the rest are not tried as keys")
                break
            before = len(ring.keys)
            ring.add(cand, 3, "string of a binary file", rel)
            took += len(ring.keys) > before
        total += took
    if ring.cut:
        notes.append(f"more than {MAX_KEYS} candidate keys: the rest are not tried")
    return ring.ordered()


# ---------------------------------------------------------------- scoring

_ENGLISH = None
MAX_WORD = 24
DICT_MIN = 5                   # letters of a system-dictionary word that counts as a word
_LEET = str.maketrans("013457@$", "oleastas")


def english() -> frozenset:
    """Common words of three letters and more, and dictionary words of DICT_MIN and more. A system
    dictionary's short entries (nesh, thee, ming) cover too much of a wrong reading to count: a
    reading one letter off would read as clean on them."""
    global _ENGLISH
    if _ENGLISH is None:
        _ENGLISH = frozenset({w for w in classical.COMMON_WORDS if len(w) >= 3}
                             | {w for w in classical.dictionary() if len(w) >= DICT_MIN})
    return _ENGLISH


def has_system_dictionary() -> bool:
    return len(classical.dictionary()) > len(set(classical.COMMON_WORDS))


def handout_words(docs, spans=None, without=None) -> set:
    """The lower-case words (three letters and more) of the handout outside the marked cipher-text lines
    and outside `without` (doc, first line index, end): an unmarked text's own lines."""
    spans, out = spans or {}, set()
    for doc in docs:
        skip = spans.get(doc.rel, set())
        for i, line in enumerate(doc.lines):
            if without and doc.rel == without[0] and without[1] <= i < without[2]:
                continue
            if i not in skip:
                out.update(w.lower() for w in re.findall(r"[A-Za-z]{3,}", line))
    return out


class Scorer:
    """Word coverage of a reading: the largest share of its letters that words laid end to end cover.
    The words are the handout's own (a glossary in a sibling file) and English."""

    def __init__(self, handout=(), cribs=()):
        cribs = {classical.letters(c) for c in cribs}
        self.handout = {w for w in handout if 3 <= len(w) <= MAX_WORD}
        self.strong = {w for w in self.handout if len(w) >= 4} | {c for c in cribs if len(c) >= 3}
        self.vocab = english() | self.handout | {c for c in cribs if len(c) >= 3}
        self.lens = sorted({len(w) for w in self.vocab if 3 <= len(w) <= MAX_WORD}, reverse=True)

    def _dp(self, t: str, trace: bool = False):
        best, back = [0] * (len(t) + 1), [0] * (len(t) + 1)
        vocab = self.vocab
        for i in range(1, len(t) + 1):
            b, n0 = best[i - 1], 0
            for n in self.lens:                            # longest first: a tie goes to the longer word
                if n > i:
                    continue
                if best[i - n] + n > b and t[i - n:i] in vocab:
                    b, n0 = best[i - n] + n, n
            best[i], back[i] = b, n0
        if not trace:
            return best[-1]
        words, i = [], len(t)
        while i > 0:
            if back[i]:
                words.append(t[i - back[i]:i])
                i -= back[i]
            else:
                i -= 1
        return best[-1], words[::-1]

    def cover(self, text: str) -> float:
        t = classical.letters(text)[:CAP]
        if not t:
            return 0.0
        if len(t) > PROBE:
            head = self._dp(t[:PROBE]) / PROBE
            if head < PROBE_FLOOR:
                return round(head, 4)
        return round(self._dp(t) / len(t), 4)

    def explain(self, text: str):
        """(coverage, the words of the best cover in order, the handout and crib words among them)."""
        t = classical.letters(text)[:CAP]
        if not t:
            return 0.0, [], []
        covered, words = self._dp(t, trace=True)
        hits = list(dict.fromkeys(w for w in words if w in self.strong))
        return round(covered / len(t), 4), words, hits

    def reads(self, text: str) -> bool:
        """A flag body reads as words (leet spelled back) or as hex: a wrong key leaves neither."""
        packed = re.sub(r"[-_ ]", "", text.lower())
        if len(packed) >= HEX_BODY and re.fullmatch(r"[0-9a-f]+", packed) and sum(c.isalpha() for c in packed) >= 6:
            return True
        t = classical.letters(text.translate(_LEET))
        return self._dp(t) / len(t) >= need(len(t)) if t else False


# ---------------------------------------------------------------- the keyed ciphers

@dataclass(frozen=True)
class Cipher:
    name: str
    key_kind: str                  # alpha | digits
    max_tier: int                  # tried with keys of this tier and better
    decrypt: object                # (text, key) -> str | None
    letters_only: bool = False     # the cipher works on the letters alone


def _vigenere(kind: str):
    return lambda text, key: classical.vigenere_decrypt(text, key, kind)


def _keyword(text: str, key: str):
    alphabet = classical.keyword_alphabet(key)
    return None if alphabet == classical.A else classical.substitution_decrypt(text, alphabet)


def _playfair(text: str, key: str):
    return classical.playfair_decrypt(text, key) if len(text) % 2 == 0 else None


def _columnar(text: str, key: str):
    order = sorted(range(len(key)), key=lambda i: (key[i], i))
    if order == list(range(len(key))) or len(key) >= len(text):
        return None                                    # the key leaves the text as it is
    return classical.columnar_decrypt(text, key)


CIPHERS = (
    Cipher("vigenere", "alpha", 3, _vigenere("vigenere")),
    Cipher("beaufort", "alpha", 3, _vigenere("beaufort")),
    Cipher("variant", "alpha", 3, _vigenere("variant")),
    Cipher("autokey", "alpha", 3, classical.autokey_decrypt),
    Cipher("porta", "alpha", 1, classical.porta),
    Cipher("keyword", "alpha", 1, _keyword),
    Cipher("playfair", "alpha", 1, _playfair, letters_only=True),
    Cipher("columnar", "alpha", 1, _columnar, letters_only=True),
    Cipher("gronsfeld", "digits", 3, classical.gronsfeld_decrypt),
)
CIPHER_NAMES = tuple(c.name for c in CIPHERS) + ("running-key",)


@dataclass
class Reading:
    ciphertext: str                # the cipher text's (or index run's) id
    cipher: str
    key: str
    key_source: str
    tier: int
    plaintext: str
    coverage: float = 0.0
    hits: tuple = ()
    flags: tuple = ()
    clean: bool = False
    check: str = ""
    also: list = field(default_factory=list)      # other keys or ciphers giving the same plain text
    near: list = field(default_factory=list)      # book cipher: the one-off repairs offered
    failed: int = 0                # book cipher: indices outside the corpus

    def rank_key(self):
        # A reading whose stated check group does not match sorts after its equals: ranked lower, still listed.
        return (not self.flags, not self.clean, "MISMATCH" in self.check, -self.coverage, -len(self.hits), self.tier)

    def to_dict(self) -> dict:
        return {"ciphertext": self.ciphertext, "cipher": self.cipher, "key": self.key, "key_source": self.key_source,
                "tier": self.tier, "coverage": self.coverage, "hits": list(self.hits), "flags": list(self.flags),
                "clean": self.clean, "check": self.check, "also": self.also, "near": self.near,
                "failed": self.failed, "plaintext": self.plaintext}


class Budget:
    """CPU and wall seconds for the whole sweep; the clocks are injectable so a test can step them."""

    def __init__(self, cpu: float = DEFAULT_SECONDS, wall: float = DEFAULT_WALL, cpu_clock=time.process_time,
                 wall_clock=time.monotonic):
        self.cpu, self.wall, self._cpu, self._wall = float(cpu), float(wall), cpu_clock, wall_clock
        self.c0, self.w0 = cpu_clock(), wall_clock()
        self.spent = ""

    def over(self) -> bool:
        if not self.spent:
            if self._cpu() - self.c0 >= self.cpu:
                self.spent = f"{self.cpu:g} CPU seconds"
            elif self._wall() - self.w0 >= self.wall:
                self.spent = f"{self.wall:g} wall seconds"
        return bool(self.spent)

    def seconds(self) -> float:
        return self._wall() - self.w0


def _flags_in(ff, text: str) -> tuple:
    return tuple(ff.find_flags(text)) if ff is not None and ff.known else ()


class Sweep:
    """The keyed sweep of the cipher texts: tiers outermost, so every cipher text sees the best keys
    before any sees the rest when the budget runs out."""

    def __init__(self, ciphertexts, keys, scorers, ff, budget, ciphers=CIPHER_NAMES, corpora=()):
        self.cts, self.keys, self.scorers, self.ff, self.budget = ciphertexts, keys, scorers, ff, budget
        # Unmarked text is a guess: stated, hinted, table, upper-case and quoted keys always, the plain
        # words of the handout only while they are few, the strings of binary files never.
        words = sum(1 for k in keys if k.tier == 2)
        self.loose_tier = 2 if words <= LOOSE_WORDS else 1
        self.ciphers = [c for c in CIPHERS if c.name in ciphers]
        self.running = "running-key" in ciphers
        self.corpora = corpora
        self.trials = self.planned = 0
        self.kept: dict = {}                    # (ciphertext id, plain text) -> Reading
        self.best: dict = {}                    # ciphertext id -> the best reading under NEAR

    def _texts(self, ct):
        raw = ct.text if ct.kind != "groups" else "".join(ct.text.split())
        return raw, "".join(c for c in raw if c.isascii() and c.isalpha())

    def _take(self, ct, cipher: str, key: str, source: str, tier: int, plain):
        self.trials += 1
        if not plain:
            return
        scorer = self.scorers[ct.id]
        flags = _flags_in(self.ff, plain)
        cover = scorer.cover(plain)
        if cover < NEAR and not flags:
            best = self.best.get(ct.id)
            if best is None or cover > best.coverage:
                self.best[ct.id] = Reading(ct.id, cipher, key, source, tier, plain, cover, check=ct.check_line())
            return
        same = self.kept.get((ct.id, plain))
        if same is not None:
            same.also.append(f"{cipher} key {key}")
            return
        cover, _words, hits = scorer.explain(plain)
        n = len(classical.letters(plain)[:CAP])
        self.kept[(ct.id, plain)] = Reading(ct.id, cipher, key, source, tier, plain, cover, tuple(hits), flags,
                                            cover >= need(n) and cover - ct.base >= GAIN, ct.check_line())

    def _tries(self, ct, key) -> bool:
        return ct.marked or key.tier <= self.loose_tier

    def _plan(self) -> int:
        n = 0
        for ct in self.cts:
            for key in self.keys:
                if self._tries(ct, key):
                    n += sum(1 for c in self.ciphers if c.key_kind == key.kind and key.tier <= c.max_tier)
        return n

    def run(self):
        self.planned = self._plan()
        texts = {ct.id: self._texts(ct) for ct in self.cts}
        for tier in sorted({k.tier for k in self.keys}):
            for ct in self.cts:
                raw, only = texts[ct.id]
                for key in self.keys:
                    if key.tier != tier or not self._tries(ct, key):
                        continue
                    if self.budget.over():
                        return
                    for c in self.ciphers:
                        if c.key_kind != key.kind or key.tier > c.max_tier:
                            continue
                        try:
                            plain = c.decrypt(only if c.letters_only else raw, key.norm)
                        except (ValueError, IndexError):
                            plain = None
                        self._take(ct, c.name, key.text, key.source, key.tier, plain)
        if self.running:
            self._running_keys(texts)

    def _running_keys(self, texts):
        """A sibling text as the key stream, started at each line, then at each word."""
        for ct in self.cts:
            raw, only = texts[ct.id]
            tried = 0
            for corpus in self.corpora:
                stream, starts = corpus.stream()
                for off, label in starts:
                    if tried >= RUNNING_MAX:
                        break
                    if len(stream) - off < len(only):
                        continue
                    if self.budget.over():
                        return
                    tried += 1
                    self.planned += 1
                    plain = classical.vigenere_decrypt(raw, stream[off:off + len(only)])
                    self._take(ct, "running-key", f"{corpus.name} from {label}", corpus.name, 2, plain)

    def readings(self) -> list:
        out = sorted(self.kept.values(), key=Reading.rank_key)[:KEEP]
        have = {r.ciphertext for r in out}
        return out + [r for cid, r in self.best.items() if cid not in have]


# ---------------------------------------------------------------- book ciphers

@dataclass
class IndexRun:
    id: str
    doc: str
    line: int
    arity: int
    items: list                    # an index (a tuple of fields: numbers, or a name or section label) or a
                                   # literal string that stands between the indices and is carried into the reading
    names: tuple = ()              # the distinct non-numeric first fields: the corpora the run names

    @property
    def tuples(self) -> list:
        return [x for x in self.items if isinstance(x, tuple)]

    def to_dict(self) -> dict:
        return {"id": self.id, "doc": self.doc, "line": self.line, "arity": self.arity, "count": len(self.tuples),
                "names": list(self.names),
                "items": [":".join(map(str, x)) if isinstance(x, tuple) else x for x in self.items]}


_SEP = r"[\s,;|]"
_LIT = r"[{}_!?()\[\]<>@#$%&*+=~^-]{1,3}"
_INDEX = re.compile(r"(?<![\w:./-])(?:[A-Za-z][\w']{0,30}|\d{1,5})(?P<sep>[:./-])(?:(?:\d{1,5}|[A-Za-z]{1,12})(?P=sep)){0,2}"
                    r"\d{1,5}(?=[\s,;)\]]|[.](?:\s|$)|$)")
_GAP = re.compile(_SEP + r"*(?:" + _LIT + _SEP + r"+)*")
_LEAD = re.compile(r"(?:^|(?<=" + _SEP + r"))((?:" + _LIT + _SEP + r"+)+)$")
_TRAIL = re.compile(r"((?:" + _SEP + r"+" + _LIT + r")+)(?=" + _SEP + r"|$)")
_NUMBER_LINE = re.compile(r"^\s*\d{1,5}(?:[\s,;]+\d{1,5})+[\s,;.]*$")


def _fields(token: str, sep: str) -> tuple:
    return tuple(int(f) if f.isdigit() else f for f in token.split(sep))


def find_index_runs(docs) -> tuple:
    """(runs, spans): runs of index tuples with one separator and one arity (`2:6:6 1:3:4 ...`; the
    first field may name a corpus and a middle one a titled section, `Song:R:2:5`), with the literal
    marks standing between them (`{`, `_`, `}`) kept in place; and runs of plain numbers on lines of
    their own."""
    runs, spans = [], {}
    for doc in docs:
        text = "\n".join(doc.lines)
        starts, pos = [], 0
        for line in doc.lines:
            starts.append(pos)
            pos += len(line) + 1

        def line_of(at, starts=starts):
            return max(k for k, o in enumerate(starts) if o <= at)

        groups, cur = [], []
        for m in _INDEX.finditer(text):
            sep = m.group("sep")
            fields = _fields(m.group(0), sep)
            shape = (sep, len(fields))
            if cur and (shape != cur[-1][1] or not _GAP.fullmatch(text, cur[-1][0].end(), m.start())):
                groups.append(cur)
                cur = []
            cur.append((m, shape, fields))
        groups.append(cur)
        for group in groups:
            if len(group) < INDEX_MIN:
                continue
            named = list(dict.fromkeys(f[0] for _m, _s, f in group if isinstance(f[0], str)))
            # A name and one number is a field list (`PRN:6 type:6`), and a name on every tuple a version
            # list: indices that name their corpus have two fields and more after it and repeat few names.
            if named and (group[0][1][1] < 3 or 2 * len(named) > len(group)):
                continue
            first, last = group[0][0], group[-1][0]
            lead = _LEAD.search(text, max(0, first.start() - 60), first.start())
            trail = _TRAIL.match(text, last.end())
            items = re.findall(_LIT, lead.group(1)) if lead else []
            for k, (m, _shape, fields) in enumerate(group):
                if k:
                    items += re.findall(_LIT, text[group[k - 1][0].end():m.start()])
                items.append(fields)
            items += re.findall(_LIT, trail.group(1)) if trail else []
            a = line_of(lead.start(1) if lead else first.start())
            b = line_of((trail.end(1) if trail else last.end()) - 1)
            runs.append(IndexRun("", doc.rel, line_of(first.start()) + 1, group[0][1][1], items, tuple(named)))
            spans.setdefault(doc.rel, set()).update(range(a, b + 1))
        taken, i = spans.get(doc.rel, set()), 0
        while i < len(doc.lines):
            j, numbers = i, []
            while j < len(doc.lines) and j not in taken and _NUMBER_LINE.match(doc.lines[j]):
                numbers += [int(x) for x in re.findall(r"\d+", doc.lines[j])]
                j += 1
            if len(numbers) >= NUMBERS_MIN and len(set(numbers)) > 2:
                runs.append(IndexRun("", doc.rel, i + 1, 1, [(n,) for n in numbers]))
                spans.setdefault(doc.rel, set()).update(range(i, j))
            i = max(j, i + 1)
    runs.sort(key=lambda r: (r.doc, r.line))
    per_doc: dict = {}
    for run in runs:
        per_doc[run.doc] = per_doc.get(run.doc, 0) + 1
        run.id = f"{run.doc}#idx{per_doc[run.doc]}"
    return runs, spans


_HEADING = re.compile(r"^[\[(#*\s]*([A-Za-z][A-Za-z'.-]*)(?:[ \t]+(\d{1,3}))?[\])\s:.*#-]*$")


def titled_sections(text: str) -> tuple:
    """((first word lower-cased, number or None, body), ...): the parts of a text under heading lines
    (`Verse 2`, `[Chorus]`, `Refrain:`): one word and an optional number, after a blank line (or at
    the top), with text right under it."""
    lines = text.split("\n")
    heads = [i for i, ln in enumerate(lines)
             if ln.strip() and _HEADING.match(ln)
             and (i == 0 or not lines[i - 1].strip()) and i + 1 < len(lines) and lines[i + 1].strip()]
    out = []
    for a, b in zip(heads, heads[1:] + [len(lines)]):
        m = _HEADING.match(lines[a])
        out.append((m.group(1).lower(), int(m.group(2)) if m.group(2) else None, "\n".join(lines[a + 1:b])))
    return tuple(out)


@functools.lru_cache(maxsize=4096)
def _units(name: str, text: str) -> tuple:
    if name == "titled":
        return titled_sections(text)
    if name == "section":
        return tuple(b for b in re.split(r"\n[ \t]*\n", text) if b.strip())
    if name == "line":
        return tuple(ln.strip() for ln in text.split("\n") if ln.strip())
    if name == "word":
        return tuple(text.split())
    if name == "letter":
        return tuple(c for c in text if c.isalnum())
    if name == "char":
        return tuple(text)
    raise ValueError(name)


def _titled(text: str, index, base: int):
    """The body of the titled section an index field names: a label is the first section whose heading
    word starts with it; a number is the section whose heading carries that number (`Verse 2`), or,
    when no heading carries a number, the section at that position."""
    sections = _units("titled", text)
    if isinstance(index, str):
        return next((body for word, _n, body in sections if word.startswith(index.lower())), None)
    if any(n is not None for _w, n, _b in sections):
        return next((body for _w, n, body in sections if n == index), None)
    return sections[index - base][2] if 0 <= index - base < len(sections) else None


# Index schemes by arity: the unit each field counts in, outermost first. `word>initial` gives the
# word's first letter, a final `word` the whole word (the reading is then words with blanks between),
# `titled` a section by its heading (the only unit a label field can name).
CHAINS = {
    1: (("word>initial",), ("word",), ("letter",), ("char",)),
    2: (("line", "word>initial"), ("line", "word"), ("line", "letter"), ("line", "char"), ("word", "letter"),
        ("section", "word>initial")),
    3: (("section", "line", "word>initial"), ("section", "line", "word"), ("section", "line", "letter"),
        ("section", "line", "char"), ("titled", "line", "char"), ("titled", "line", "letter"),
        ("titled", "line", "word>initial"), ("titled", "line", "word"), ("line", "word", "letter")),
    4: (("section", "line", "word", "letter"), ("titled", "line", "word", "letter")),
}
_PUNCT = "\"'“”‘’`.,;:!?()[]{}<>-—"


def pick(text: str, chain, index, base: int):
    """What the index tuple names in the text under the scheme, or None when it falls outside."""
    cur, emit = text, ""
    for unit, i in zip(chain, index):
        name, _, emit = unit.partition(">")
        if name == "titled":
            cur = _titled(cur, i, base)
            if cur is None:
                return None
            continue
        if not isinstance(i, int):
            return None                                 # only a titled section answers to a label
        items = _units(name, cur)
        if not 0 <= i - base < len(items):
            return None
        cur = items[i - base]
    if emit == "initial":
        return next((c for c in cur if c.isalnum()), None)
    if chain[-1] == "word":
        return cur.strip(_PUNCT) or None
    return cur


@dataclass
class Corpus:
    name: str
    text: str
    given: bool = False            # passed with --opt corpus, not a file of the handout

    @property
    def title(self) -> str:
        return next((ln.strip() for ln in self.text.split("\n") if ln.strip()), "")

    def answers_to(self, word: str) -> bool:
        w = classical.letters(word)
        return bool(w) and (w in classical.letters(Path(self.name).stem) or w in classical.letters(self.title))

    def stream(self):
        """(the letters, [(offset, label)]): the key-stream starts, each line first, then each word."""
        letters, lines, words, at = [], [], [], 0
        for n, line in enumerate(self.text.split("\n"), 1):
            first = True
            for w in line.split():
                ls = classical.letters(w)
                if not ls:
                    continue
                (lines if first else words).append((at, f"line {n}" if first else f"line {n} word {w.strip(_PUNCT)!r}"))
                first = False
                letters.append(ls)
                at += len(ls)
        return "".join(letters), lines + words


def _join(run: IndexRun, got: list, joiner: str) -> str:
    """The reading: what each index gave (`?` where it fell outside) with the literals in place."""
    parts, k = [], 0
    for item in run.items:
        if isinstance(item, tuple):
            parts.append("?" if got[k] is None else got[k])
            k += 1
        else:
            parts.append(item)
    return joiner.join(parts)


def book_readings(run: IndexRun, corpora, scorer: Scorer, ff, notes: list) -> list:
    """Every reading of an index run against the corpora that keeps most of its indices inside the
    text, with the one-off repairs that raise its word coverage offered as near misses."""
    out, plans, tuples = [], [], run.tuples             # plans: (label, [corpus per tuple], fields to skip)
    if run.names:
        chosen, missing = {}, []
        for name in run.names:
            match = [c for c in corpora if c.answers_to(name)]
            if len(match) == 1:
                chosen[name] = match[0]
            else:
                missing.append(f"{name!r} ({'no' if not match else 'more than one'} corpus answers to it)")
        if missing or any(not isinstance(t[0], str) for t in tuples):
            notes.append(f"{run.id}: book-cipher indices name their corpus ({', '.join(run.names)}) but "
                         + (", ".join(missing) or "some indices carry a number instead")
                         + ": put the texts in the handout folder or pass --opt corpus=<file>, named after them")
            return out
        plans.append(("by name", [chosen[t[0]] for t in tuples], 1))
    else:
        plans += [(corpus.name, [corpus] * len(tuples), 0) for corpus in corpora]
        firsts = [t[0] for t in tuples]
        if run.arity >= 2 and len(corpora) >= 2:
            for base in (1, 0):
                if all(0 <= f - base < len(corpora) for f in firsts):
                    plans.append((f"corpus number, base {base}", [corpora[f - base] for f in firsts], 1))
    for label, per_tuple, skip in plans:
        for chain in CHAINS.get(run.arity - skip, ()):
            for base in (1, 0):
                got = [pick(c.text, chain, t[skip:], base) for c, t in zip(per_tuple, tuples)]
                failed = sum(1 for g in got if g is None)
                if failed > BOOK_FAIL * len(got):
                    continue
                joiner = " " if chain[-1] == "word" else ""
                plain = _join(run, got, joiner)
                if not classical.letters(plain):
                    continue
                cover, _words, hits = scorer.explain(plain)
                n = len(classical.letters(plain)[:CAP])
                reading = Reading(run.id, f"book {'/'.join(chain)} base {base}", label,
                                  ", ".join(dict.fromkeys(c.name for c in per_tuple)), 1, plain, cover,
                                  tuple(hits), _flags_in(ff, plain) if not failed else (),
                                  failed == 0 and cover >= need(n), failed=failed)
                reading.near = _one_off(run, per_tuple, skip, chain, base, got, joiner, scorer, cover, ff)
                out.append(reading)
    return out


def _one_off(run, per_tuple, skip, chain, base, got, joiner, scorer, cover, ff) -> list:
    """The single-index repairs (last field one lower or higher) that add a word's worth of coverage
    (MEND_MIN letters): an author who miscounted by one leaves one wrong letter. Offered, never applied."""
    repairs = []
    for pos, (corpus, t) in enumerate(zip(per_tuple, run.tuples)):
        best = None
        for delta in (-1, 1):
            alt = pick(corpus.text, chain, t[skip:-1] + (t[-1] + delta,), base)
            if alt is None or alt == got[pos]:
                continue
            trial = _join(run, got[:pos] + [alt] + got[pos + 1:], joiner)
            gain = scorer.cover(trial) - cover
            if gain * len(classical.letters(trial)[:CAP]) >= MEND_MIN and (best is None or gain > best[0]):
                best = (gain, delta, alt, trial)
        if best:
            gain, delta, alt, trial = best
            n = len(classical.letters(trial)[:CAP])
            whole = all(g is not None for k, g in enumerate(got) if k != pos)    # no `?` left in the reading
            repairs.append({"position": pos + 1, "index": ":".join(map(str, t)), "delta": delta,
                            "from": "?" if got[pos] is None else got[pos], "to": alt,
                            "coverage": round(cover + gain, 4), "clean": whole and cover + gain >= need(n),
                            "flags": list(_flags_in(ff, trial)) if whole else [], "reading": trial})
    return sorted(repairs, key=lambda r: -r["coverage"])[:8]


# ---------------------------------------------------------------- the report

@dataclass
class Report:
    where: str = ""
    docs: int = 0
    binaries: int = 0
    ciphertexts: list = field(default_factory=list)
    index_runs: list = field(default_factory=list)
    keys: list = field(default_factory=list)
    readings: list = field(default_factory=list)       # keyed, ranked
    book: list = field(default_factory=list)           # book readings, ranked
    read_runs: set = field(default_factory=set)        # ids of the index runs some corpus gave a reading of
    unreached: set = field(default_factory=set)        # ids of the index runs the budget ended before
    notes: list = field(default_factory=list)
    trials: int = 0
    planned: int = 0
    cut: str = ""                                      # what budget was spent, when it was
    seconds: float = 0.0
    out: str = ""

    def clean(self) -> list:
        return [r for r in self.readings + self.book if r.clean]

    def flags(self) -> list:
        return list(dict.fromkeys(f for r in self.readings + self.book for f in r.flags))

    def to_dict(self) -> dict:
        tiers: dict = {}
        for k in self.keys:
            tiers[k.tier] = tiers.get(k.tier, 0) + 1
        return {"schema": SCHEMA, "engine": ENGINE, "handout": self.where, "text_files": self.docs,
                "binary_files": self.binaries, "ciphertexts": [c.to_dict() for c in self.ciphertexts],
                "index_runs": [r.to_dict() for r in self.index_runs],
                "keys": {"count": len(self.keys), "by_tier": {str(t): n for t, n in sorted(tiers.items())},
                         "first": [k.to_dict() for k in self.keys if k.tier == 0][:50]},
                "trials": self.trials, "planned": self.planned, "cut": self.cut, "seconds": round(self.seconds, 3),
                "candidates": [dict(r.to_dict(), rank=i) for i, r in enumerate(self.readings, 1)],
                "book": [dict(r.to_dict(), rank=i) for i, r in enumerate(self.book, 1)], "notes": self.notes}

    def markdown(self) -> str:
        out = ["# keyed sweep (common.keyed_sweep)", "",
               f"Handout: {self.where}; {self.docs} text file(s), {self.binaries} other. "
               f"{len(self.keys)} candidate key(s), {self.trials} of {self.planned} decrypts tried"
               + (f" (stopped: {self.cut} spent)" if self.cut else "") + ".",
               "", "Keys by tier: " + "; ".join(
                   f"{t} ({TIERS[t]}): {sum(1 for k in self.keys if k.tier == t)}" for t in sorted(TIERS)) + ".",
               "", "Ranked candidates, not a pick: a clean reading can still be a planted message. Check each "
               "against the handout's own rules (check group, times, tables) before answering.", ""]
        if self.ciphertexts:
            out += ["## cipher texts", ""]
            for c in self.ciphertexts:
                line = f"- `{c.id}` line {c.line}, {c.kind}, {c.letters} letters"
                if c.check_line():
                    line += f"; {c.check_line()}"
                if c.context:
                    line += "; around it: " + " | ".join(f"`{x}`" for x in c.context)
                out.append(line)
            out.append("")
        hinted = [k for k in self.keys if k.tier == 0]
        if hinted:
            out += ["## keys tried first", ""] + [f"- `{k.text}`: {k.source}" for k in hinted[:30]] + [""]
        for title, rows in (("## ranked decrypts", self.readings), ("## book cipher readings", self.book)):
            if not rows:
                continue
            out += [title, ""]
            for i, r in enumerate(rows[:40], 1):
                mark = "CLEAN" if r.clean else "near"
                out.append(f"{i}. **{mark}** `{r.ciphertext}` {r.cipher}, key `{r.key}` ({r.key_source}); "
                           f"coverage {r.coverage:.2f}"
                           + (f"; handout words: {', '.join(r.hits[:12])}" if r.hits else "")
                           + (f"; {r.check}" if r.check else "")
                           + (f"; {r.failed} index(es) outside the corpus" if r.failed else "")
                           + (f"; flag(s): {', '.join(r.flags)}" if r.flags else ""))
                out.append(f"   `{r.plaintext[:CAP]}`")
                if r.also:
                    out.append(f"   same reading from: {', '.join(r.also[:6])}")
                for fix in r.near[:4]:
                    out.append(f"   one off at index {fix['position']} ({fix['index']}, {fix['delta']:+d}): "
                               f"`{fix['from']}` -> `{fix['to']}`, coverage {fix['coverage']:.2f}: `{fix['reading'][:200]}`")
            out.append("")
        if self.index_runs:
            out += ["## index runs", ""] + [
                f"- `{r.id}` line {r.line}: {len(r.tuples)} indices of {r.arity} field(s)"
                + (f", naming {', '.join(r.names)}" if r.names else "") for r in self.index_runs] + [""]
        if self.notes:
            out += ["## notes", ""] + [f"- {n}" for n in self.notes] + [""]
        return "\n".join(out)


def _as_list(value) -> list:
    if value is None or value == "":
        return []
    return [str(v) for v in value] if isinstance(value, (list, tuple)) else [str(value)]


def load_corpora(docs, paths, notes: list) -> list:
    """Book corpora: the files given with --opt corpus (a file or a folder), then the handout's text
    files of CORPUS_WORDS words and more."""
    out = []
    for raw in paths:
        p = Path(raw).expanduser()
        files = sorted(f for f in p.rglob("*") if f.is_file() and not f.is_symlink()) if p.is_dir() else [p]
        if not p.exists() or not files:
            raise FileNotFoundError(f"--opt corpus: {raw} does not exist or holds no file")
        for f in files:
            text = decode(f.read_bytes()) if f.stat().st_size <= MAX_CORPUS else None
            if text is None:
                notes.append(f"--opt corpus: {f.name} is not text (or over {MAX_CORPUS} bytes), not used")
            else:
                out.append(Corpus(f.name, text, given=True))
    for doc in docs:
        if len(doc.text.split()) >= CORPUS_WORDS:
            out.append(Corpus(doc.rel, doc.text))
    if len(out) > MAX_CORPORA:
        notes.append(f"{len(out)} corpora: only the first {MAX_CORPORA} are used")
    return out[:MAX_CORPORA]


def sweep(challenge_dir, ff=None, **opts) -> Report:
    """Run the whole sweep and return the Report. Raises FileNotFoundError for a missing folder or
    corpus and ValueError for an unknown cipher name."""
    challenge_dir = Path(challenge_dir)
    if not challenge_dir.is_dir():
        raise FileNotFoundError(f"no such challenge folder: {challenge_dir}")
    ciphers = tuple(_as_list(opts.get("ciphers"))) or CIPHER_NAMES
    unknown = [c for c in ciphers if c not in CIPHER_NAMES]
    if unknown:
        raise ValueError(f"unknown cipher(s) {', '.join(unknown)}; known: {', '.join(CIPHER_NAMES)}")
    budget = opts.get("budget") or Budget(float(opts.get("seconds", DEFAULT_SECONDS)),
                                          float(opts.get("wall", DEFAULT_WALL)))
    rep = Report()
    docs, binaries, rep.where = read_handout(challenge_dir, rep.notes)
    rep.docs, rep.binaries = len(docs), len(binaries)
    brief = str(opts.get("brief") or "") or read_brief(challenge_dir, rep.notes)
    if brief.strip():
        docs.append(Doc("brief", brief.replace("\r\n", "\n")))
    small = [d for d in docs if len(d.text) <= MAX_DOC]
    rep.notes += [f"{d.rel}: over {MAX_DOC} characters, used as a book corpus only" for d in docs if d not in small]
    rep.index_runs, index_spans = find_index_runs(small)
    indexed = [Doc(d.rel, "\n".join("" if i in index_spans.get(d.rel, ()) else ln for i, ln in enumerate(d.lines)))
               for d in small]
    rep.ciphertexts, spans = find_ciphertexts(indexed, _as_list(opts.get("ciphertext")), rep.notes)
    for rel, lines in index_spans.items():
        spans.setdefault(rel, set()).update(lines)
    if not rep.ciphertexts and not rep.index_runs:
        rep.seconds = budget.seconds()
        return rep
    cribs = _as_list(opts.get("crib"))
    corpora = load_corpora([d for d in docs if d.rel != "brief"] + [d for d in docs if d.rel == "brief"],
                           _as_list(opts.get("corpus")), rep.notes)
    if not has_system_dictionary():
        rep.notes.append("no system dictionary on this host: readings are scored on the handout's own words and "
                         "a short list of common English words only")
    given = handout_words([Doc(c.name, c.text) for c in corpora if c.given])
    made: dict = {}

    def scorer_for(without=None) -> Scorer:           # one per set of words: building one is not free
        if without not in made:
            made[without] = Scorer(handout_words(small, spans, without) | given, cribs)
        return made[without]

    scorers = {ct.id: scorer_for(ct.own_lines()) for ct in rep.ciphertexts}
    for ct in rep.ciphertexts:
        ct.base = scorers[ct.id].cover(ct.text)
    reads = [ct.id for ct in rep.ciphertexts if not ct.marked and ct.base >= NEAR]
    if reads:                 # not prose by the dictionary, but words all the same (the handout's own, technical ones)
        rep.notes.append(f"{len(reads)} unmarked text(s) read as words as they stand and are not swept: "
                         + ", ".join(reads[:6]))
        rep.ciphertexts = [ct for ct in rep.ciphertexts if ct.id not in reads]
    scorer = scorer_for()
    if rep.ciphertexts:
        rep.keys = harvest_keys(small, spans, binaries, _as_list(opts.get("key")), rep.notes, budget)
        run = Sweep(rep.ciphertexts, rep.keys, scorers, ff, budget, ciphers, corpora)
        if run.loose_tier < 2 and any(not ct.marked for ct in rep.ciphertexts):
            rep.notes.append(f"more than {LOOSE_WORDS} plain words in the handout: on unmarked text only stated, "
                             "hinted, table, upper-case and quoted keys are tried")
        run.run()
        rep.readings, rep.trials, rep.planned = run.readings(), run.trials, run.planned
    for index_run in rep.index_runs:
        if budget.over():
            rep.unreached.add(index_run.id)
            continue
        got = book_readings(index_run, corpora, scorer, ff, rep.notes)
        if got:
            rep.read_runs.add(index_run.id)
        rep.book += got
    rep.book.sort(key=Reading.rank_key)
    rep.book = [r for r in rep.book if r.clean or r.flags or r.coverage >= NEAR
                or any(fix["clean"] for fix in r.near)][:KEEP] or rep.book[:3]
    rep.cut = budget.spent
    if rep.cut:
        rep.notes.append(f"budget spent ({rep.cut}) after {rep.trials} of {rep.planned} decrypts: the best keys went "
                         "first; rerun with --opt seconds=N --opt wall=N for the rest")
    rep.seconds = budget.seconds()
    return rep


def write_report(rep: Report, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "keyed_sweep.json").write_text(json.dumps(rep.to_dict(), indent=1) + "\n", encoding="utf-8")
    (out_dir / "keyed_sweep.md").write_text(rep.markdown(), encoding="utf-8")


def _evidence(r: Reading) -> Evidence:
    detail = (f"{r.ciphertext}: {r.cipher} with key {r.key!r} ({r.key_source}) reads {r.plaintext[:QUOTE]!r}; "
              f"word coverage {r.coverage:.2f}"
              + (f", handout words {', '.join(r.hits[:8])}" if r.hits else "")
              + (f"; {r.check}" if r.check else "")
              + (f"; one index off gives {r.near[0]['reading'][:80]!r}" if r.near else ""))
    doc = r.ciphertext.rsplit("#", 1)[0]
    return Evidence("decode", detail, path=doc if doc not in ("stated", "brief") else None)


def _wrapper_letters(flag: str) -> int:
    """The letters a decrypt has to land on for the flag's wrapper: those before the brace."""
    head = flag[:flag.find("{")] if "{" in flag else flag
    return sum(c.isalpha() for c in head)


def result_of(rep: Report, ff=None, challenge_id=None) -> SolverResult:
    """The SolverResult of a Report (module docstring: solved / candidate / unsure / none)."""
    cost = Cost(seconds=round(rep.seconds, 3))
    notes = list(rep.notes)
    if rep.out:
        notes.insert(0, f"report: {rep.out}")
    words = Scorer()
    holders = [r for r in rep.readings + rep.book if r.flags]
    proven = [r for r in holders if r.clean or any(words.reads(f[f.find("{") + 1:-1]) for f in r.flags)]

    def fixes(r, clean_only=False):
        return [f for fix in r.near if fix["flags"] and (fix["clean"] or not clean_only)
                for f in fix["flags"]][:MEND_FLAGS]

    # A book reading that reads cleanly only after a one-off repair: the repair is the likelier answer.
    mended = [r for r in rep.book if r not in proven and fixes(r, clean_only=True)]
    # Another flag-shaped reading of a text that has a proven (or mended) one is that text under the wrong
    # key or scheme (an autokey with the right primer gets the wrapper right and nothing after it): left
    # out. Of a text with neither, the best few are listed.
    settled, loose, per_text, chance = {r.ciphertext for r in proven + mended}, [], {}, 0
    for r in holders:
        if r.ciphertext in settled or r in proven:
            continue
        # A keyed decrypt lands on a short wrapper by chance: with T decrypts and a wrapper of p letters,
        # T / 26^p such readings are expected. Above CHANCE the reading is one of them, not a lead.
        if r in rep.readings and all(rep.trials / 26 ** _wrapper_letters(f) >= CHANCE for f in r.flags):
            chance += 1
        elif per_text.get(r.ciphertext, 0) < LOOSE_FLAGS:
            per_text[r.ciphertext] = per_text.get(r.ciphertext, 0) + 1
            loose.append(r)
    if chance:
        notes.append(f"{chance} flag-shaped reading(s) that do not read as words left out: over {rep.trials} "
                     "decrypts a wrapper that short comes up by chance")
    flags, offered = [], False
    for r in proven + loose:                            # as written first, then what one index off gives
        flags += list(r.flags) + fixes(r)
        offered = offered or bool(fixes(r))
    for r in mended:                                    # the clean repair first, then as written
        flags += fixes(r, clean_only=True) + list(r.flags)
    if flags:
        distinct = list(dict.fromkeys(ff.normalize(f) for f in flags)) if ff is not None else flags
        status = "solved" if len(distinct) == 1 and proven else "candidate"   # a repair's flag is a second one
        # Another cipher text that reads cleanly with no flag may be the genuine intercept, the flagged one
        # a planted message: which is which is the handout's call (its rules, times, check groups), not
        # this engine's. The flag stays a candidate and those readings go in the evidence beside it.
        flagged = {r.ciphertext for r in proven + mended + loose}
        rivals = [r for r in rep.clean() if r.ciphertext not in flagged]
        if rivals:
            status = "candidate"
        if mended:
            notes.insert(0, "a book reading one index off reads cleanly where the indices as written do not: its "
                            "flag is listed before the reading as written")
        elif offered:
            notes.insert(0, "a book reading one index off reads better than the indices as written: its flag is "
                            "listed after the reading as written")
        elif len(distinct) > 1:
            notes.insert(0, "several distinct flags")
        elif not proven:
            notes.insert(0, "the one flag sits in a reading that does not read as words: a chance hit is possible")
        if rivals:
            texts = list(dict.fromkeys(r.ciphertext for r in rivals))
            notes.insert(0, f"{len(texts)} other cipher text(s) also read cleanly with no flag ({', '.join(texts[:4])}"
                            f"{', ...' if len(texts) > 4 else ''}): the flagged one may be a planted message; "
                            "check each against the handout's rules before answering")
        room = min(len(rivals), EVIDENCE_MAX // 2)       # the flag-free clean readings are shown beside the flag
        shown = (mended + proven + loose)[:EVIDENCE_MAX - room]
        shown += rivals[:EVIDENCE_MAX - len(shown)]
        return SolverResult(status, flags=distinct, evidence=[_evidence(r) for r in shown],
                            cost=cost, engine=ENGINE, challenge_id=challenge_id, notes="; ".join(notes))
    clean = rep.clean()
    if clean:
        notes.insert(0, f"{len(clean)} clean reading(s) of {len({r.ciphertext for r in clean})} cipher text(s), "
                        "ranked, not picked: check each against the handout's rules")
        return SolverResult("unsure", evidence=[_evidence(r) for r in clean[:EVIDENCE_MAX]], cost=cost, engine=ENGINE,
                            challenge_id=challenge_id, notes="; ".join(notes))
    # A run of tuples nothing could count into is a lead (the agent fetches the text). A run of plain
    # numbers is not: any list of small numbers looks like one, so it stays a note.
    unread = [r for r in rep.index_runs if r.id not in rep.read_runs | rep.unreached and r.arity >= 2]
    plain = [r for r in rep.index_runs if r.id not in rep.read_runs | rep.unreached and r.arity == 1]
    if plain:
        notes.append(f"{len(plain)} run(s) of plain numbers ({', '.join(r.id for r in plain[:4])}) could be book-cipher "
                     "word numbers, but the handout has no text to count into (--opt corpus=<file>)")
    if unread:
        ev = [Evidence("match", f"{r.id}: {len(r.tuples)} book-cipher indices of {r.arity} field(s)"
                       + (f" naming {', '.join(r.names)}" if r.names else "") + ", no corpus read them",
                       path=r.doc if r.doc != "brief" else None) for r in unread[:EVIDENCE_MAX]]
        return SolverResult("unsure", evidence=ev, cost=cost, engine=ENGINE, challenge_id=challenge_id,
                            notes="; ".join(["book-cipher indices with no corpus to count into"] + notes))
    if rep.cut and (rep.index_runs or any(c.kind in MARKED for c in rep.ciphertexts)):
        return SolverResult("unsure", cost=cost, engine=ENGINE, challenge_id=challenge_id,
                            notes="; ".join(["nothing clean yet, and the sweep did not finish"] + notes))
    if rep.cut:           # only text this engine guessed to be cipher text: an unfinished guess is not a lead
        return SolverResult("none", cost=cost, engine=ENGINE, challenge_id=challenge_id,
                            notes="; ".join(["no marked cipher text; the files and paragraphs that do not read as "
                                             "prose gave nothing clean before the budget ended"] + notes))
    if not rep.ciphertexts and not rep.index_runs:
        return SolverResult("none", cost=cost, engine=ENGINE, challenge_id=challenge_id,
                            notes="; ".join(["no keyed cipher text or book-cipher index run in the handout"] + notes))
    return SolverResult("none", cost=cost, engine=ENGINE, challenge_id=challenge_id,
                        notes="; ".join([f"{len(rep.ciphertexts)} cipher text(s), {len(rep.index_runs)} index run(s), "
                                         f"{len(rep.keys)} key(s), {rep.trials} decrypts: nothing reads cleanly"] + notes))


def solve(challenge_dir, profile=None, **opts) -> SolverResult:
    """Engine contract. opts: key (a key or a list, tried first), corpus (a file or folder of book
    texts, or a list), ciphertext (a cipher text given by hand, or a list), crib (words that count as
    handout words), ciphers (a subset of CIPHER_NAMES), seconds (CPU budget), wall (wall budget), out
    (report folder), brief (the brief's text, when the folder has no challenge.json)."""
    challenge_dir = Path(challenge_dir)
    ff = _flagfmt.for_profile(profile) if profile is not None else None
    try:
        rep = sweep(challenge_dir, ff, **opts)
    except FileNotFoundError as e:
        return SolverResult("blocked", engine=ENGINE, notes=str(e))
    if not rep.docs and not rep.binaries and not rep.ciphertexts and not rep.index_runs:
        return SolverResult("blocked", engine=ENGINE,
                            notes="; ".join([f"no readable handout file under {rep.where}"] + rep.notes))
    if ff is None or not ff.known:
        rep.notes.append("the event's flag format is not known: readings were not searched for flags")
    if rep.ciphertexts or rep.index_runs:
        out_dir = Path(opts["out"]) if opts.get("out") else challenge_dir / "recon" / "engines" / ENGINE
        try:
            write_report(rep, out_dir)
            rep.out = str(out_dir / "keyed_sweep.md")
        except OSError as e:
            rep.notes.append(f"report not written to {out_dir} ({type(e).__name__}: {e})")
    cid = None
    meta = challenge_dir / "challenge.json"
    if meta.is_file() and not meta.is_symlink():
        try:
            cid = json.loads(meta.read_text(encoding="utf-8")).get("id")
        except (OSError, ValueError, AttributeError):
            cid = None
    return result_of(rep, ff, challenge_id=None if cid is None else str(cid))
