"""Numbered-record blobs: each record a fragment in its own encoding (B-163).

The Warmups Mastery shape: lines `NN<TAB>payload`, every payload a piece of one text (a known crib
sentence, then the answer slug) in its own encoding, the pieces joined in record order. Two things broke
it in Huntress: a piece too short to prove its own encoding (a 16-way cut leaves ~7 characters; a rot47
record could not be vouched), and an answer split across records (the slug's last word over records
13, 14 and 15). This module handles both without guessing:

  * **Readings.** Each payload is explored through the shared graph with no goal (`Graph.explore`):
    every printable state reached is a reading `(text, chains)`, the payload itself included.
  * **The true cut.** `assemble` places the records in order at character offsets of the target, a known
    crib followed by the answer. A reading fits at offset p when it equals the crib there (the part
    inside the crib) and is answer characters past it. The whole join must then satisfy the oracle (a
    slug after the crib, a flag). Pieces are judged where they actually fall, so a word split over three
    records is just three fits, never three failed words.
  * **Proof.** A reading is *vouched* when the crib proves it: it lies inside the crib, or reproduces at
    least `pin` crib characters. A reading past the crib is admissible only when its chain proves it
    instead: one or more representation steps and no keyless one (a loose step, or no step at all, passes
    letters through and proves nothing: `dpehu` read plain, or any of the 25 shifts of it, fits a slug
    word). A record that has only unproved readings where it falls is *unvouched*; the set has no answer
    and says which record stopped it.
  * **N-record consensus.** Over N sibling sets (cumulative sets: record k is encoded the same way in
    each; or every record of one set, `group="all"`), the chain the crib vouched for a record position in
    at least `min_n` places, with no rival as frequent, is that position's consensus chain. In a set with
    no answer (or several), the records with a consensus chain also get the reading that chain gives
    (`codecs.apply_chain`), admissible anywhere, and the set is assembled again at the true cut.
"""
from __future__ import annotations

import re
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

from . import codecs as C
from .graph import Graph
from .oracle import Oracle

RECORD = re.compile(rb"^ *(\d{1,4})\t(.*?)\r?$")
PIN = 4                  # crib characters a reading must reproduce to be vouched when it runs past the crib
MAX_ASSEMBLIES = 64      # complete assignments one set may have before it is called ambiguous
MAX_READINGS = 4000      # readings kept per record
ANSWER_CHARS = frozenset(range(0x21, 0x7F))   # what a piece past the crib may hold (printable, no space)


class RecordsError(ValueError):
    """The blob is not numbered records, or the options are unusable."""


@dataclass(frozen=True)
class Record:
    index: int
    payload: bytes


def chain_proves(chain, codecs=None) -> bool:
    """A chain proves its reading by itself: at least one step, every step a representation change."""
    return bool(chain) and len(C.representation_steps(chain, codecs)) == len(chain)


@dataclass
class Reading:
    text: bytes
    chains: list            # every chain that reached this text, proving chains first, then simplest
    proved: bool = False    # a chain of representation steps reached it, or a consensus chain did
    consensus: bool = False

    @property
    def chain(self) -> tuple:
        return self.chains[0]


@dataclass
class Assembly:
    text: bytes
    answers: list
    picks: list             # per record: (reading text, chain)
    vouched: list           # per record: the crib proves the reading


@dataclass
class SetResult:
    answer: Optional[str]
    assemblies: list = field(default_factory=list)
    unvouched: list = field(default_factory=list)      # record numbers that only unproved readings fit
    reason: str = ""
    consensus: dict = field(default_factory=dict)       # record number -> the consensus chain applied
    placed: dict = field(default_factory=dict)          # record position -> {(text, vouched)} on any path

    def to_json(self) -> dict:
        return {"answer": self.answer, "reason": self.reason, "unvouched": self.unvouched,
                "consensus": {str(k): list(v) for k, v in self.consensus.items()},
                "assemblies": [{"answers": a.answers, "chains": [list(c) for _, c in a.picks],
                                "vouched": a.vouched} for a in self.assemblies[:8]]}


def parse(blob: bytes) -> list[Record]:
    """The records of a blob, in record-number order. RecordsError when a non-empty line is not a record,
    a number repeats, or there are fewer than two records."""
    recs, seen = [], set()
    for line in bytes(blob).split(b"\n"):
        if not line.strip():
            continue
        m = RECORD.match(line)
        if not m:
            raise RecordsError(f"not a numbered record line: {line[:40]!r}")
        n = int(m.group(1))
        if n in seen:
            raise RecordsError(f"record {n} appears twice")
        seen.add(n)
        recs.append(Record(n, m.group(2)))
    if len(recs) < 2:
        raise RecordsError("fewer than two numbered records")
    return sorted(recs, key=lambda r: r.index)


def readings(payload: bytes, graph: Optional[Graph] = None, *, deadline: Optional[float] = None) -> list[Reading]:
    """Every printable text a payload decodes to (itself included, chain ()), each with the chains that
    reach it: proving readings first, then by fewest loose steps and shortest chain."""
    g = graph or Graph(max_depth=6, max_nodes=20000)
    codecs = g.codecs
    states, _ = g.explore(payload, deadline=deadline)
    by_text: dict = {}
    for data, chain in states:
        if not C.is_text(data):
            continue
        by_text.setdefault(data, []).append(tuple(chain))
        if len(by_text) >= MAX_READINGS:
            break

    def rank(ch):
        return (not chain_proves(ch, codecs), len(ch) - len(C.representation_steps(ch, codecs)), len(ch))
    out = []
    for text, chains in by_text.items():
        chains = sorted(set(chains), key=rank)
        out.append(Reading(text, chains, proved=chain_proves(chains[0], codecs)))
    out.sort(key=lambda r: rank(r.chain))
    return out


def _fit(rd: Reading, p: int, crib: bytes, pin: int):
    """(fits by characters, admissible, vouched) for reading rd placed at offset p of crib + answer."""
    text = rd.text
    inside = max(0, min(len(text), len(crib) - p))
    if inside and text[:inside] != crib[p:p + inside]:
        return False, False, False
    if any(c not in ANSWER_CHARS for c in text[inside:]):
        return False, False, False
    vouched = inside > 0 and inside >= min(pin, len(text))
    return True, vouched or rd.proved, vouched


def assemble(records: list[Record], oracle: Oracle, *, crib: bytes = b"", graph: Optional[Graph] = None,
             pin: int = PIN, reads: Optional[dict] = None, deadline: Optional[float] = None) -> SetResult:
    """Place every record's readings at the true cut of crib + answer and keep the joins the oracle accepts.

    reads: {record number: [Reading]} to use instead of exploring (the consensus pass adds to them)."""
    crib = crib.encode() if isinstance(crib, str) else bytes(crib)
    if pin < 1:
        raise RecordsError("pin must be at least 1")
    if reads is None:
        reads = {r.index: readings(r.payload, graph, deadline=deadline) for r in records}
    found: list[Assembly] = []
    over = [False]
    stuck: dict = {}            # record position -> it fit by characters but only unproved readings did
    placed: dict = {}           # record position -> every (text, vouched) a path placed there

    def walk(i: int, p: int, picks: list, vouched: list):
        if over[0]:
            return
        if i == len(records):
            if p < len(crib):
                return
            text = b"".join(t for t, _ in picks)
            answers = oracle.check(text)
            if answers:
                if len(found) >= MAX_ASSEMBLIES:
                    over[0] = True
                    return
                found.append(Assembly(text, answers, list(picks), list(vouched)))
            return
        for rd in reads.get(records[i].index, ()):
            chars, admissible, v = _fit(rd, p, crib, pin)
            if not chars:
                continue
            if not admissible:
                stuck[i] = True
                continue
            picks.append((rd.text, rd.chain))
            vouched.append(v)
            placed.setdefault(i, set()).add((rd.text, v))
            walk(i + 1, p + len(rd.text), picks, vouched)
            picks.pop()
            vouched.pop()

    walk(0, 0, [], [])
    res = SetResult(None, found, placed=placed)
    answers = []
    for a in found:
        for x in a.answers:
            if x not in answers:
                answers.append(x)
    loose = {i for a in found for i in range(len(records)) if not a.vouched[i]}
    if not found:
        loose = set(stuck)
    res.unvouched = [records[i].index for i in sorted(loose)]
    if over[0]:
        res.reason = f"more than {MAX_ASSEMBLIES} joins fit: ambiguous"
    elif not found:
        res.reason = "no join of the records' readings satisfies the oracle at the true cut"
        if stuck:
            res.reason += (f"; records {res.unvouched} fit only with unproved (keyless) readings where they fall: "
                           "a consensus chain can settle them")
    elif len(answers) > 1:
        res.reason = f"{len(answers)} distinct answers fit (records not vouched by the crib: {res.unvouched})"
    else:
        res.answer = answers[0]
        res.reason = "one answer"
    return res


def consensus(sets: list[list[Record]], oracle: Oracle, *, crib: bytes = b"", min_n: int = 3,
              group: str = "index", graph: Optional[Graph] = None, pin: int = PIN,
              deadline: Optional[float] = None) -> list[SetResult]:
    """Assemble every set; then settle each set without one answer by the chains N places agree on.

    group="index": record number k of every set shares one encoding (cumulative Mastery sets).
    group="all":   every record of every set shares one encoding (a single-encoding blob)."""
    if group not in ("index", "all"):
        raise RecordsError(f"group must be 'index' or 'all', not {group!r}")
    if not isinstance(min_n, int) or min_n < 1:
        raise RecordsError("min_n must be a positive integer")
    crib = crib.encode() if isinstance(crib, str) else bytes(crib)
    codecs = graph.codecs if graph is not None else None
    all_reads, results = [], []
    for recs in sets:
        reads = {r.index: readings(r.payload, graph, deadline=deadline) for r in recs}
        all_reads.append(reads)
        results.append(assemble(recs, oracle, crib=crib, pin=pin, reads=reads))

    def key(rec: Record):
        return "all" if group == "all" else rec.index

    votes: dict = {}
    for si, (recs, res) in enumerate(zip(sets, results)):
        for pos, rec in enumerate(recs):
            # a set with one answer votes with its joins; one without, with the records every path placed
            # the same way before it stopped (a record two paths read differently votes for nothing)
            picks = ({(a.picks[pos][0], a.vouched[pos]) for a in res.assemblies} if res.answer is not None
                     else res.placed.get(pos, set()) if not res.assemblies else set())
            if len(picks) != 1:
                continue
            text, vouched = next(iter(picks))
            if not vouched:
                continue
            rd = next(r for r in all_reads[si][rec.index] if r.text == text)
            for ch in rd.chains:
                if ch:
                    votes.setdefault(key(rec), Counter())[ch] += 1
    chosen = {}
    for k, counter in votes.items():
        ranked = counter.most_common()
        top_chain, top = ranked[0]
        if top >= min_n and not any(n == top for _, n in ranked[1:]):
            chosen[k] = top_chain
    by_index = {}
    for si, (recs, res) in enumerate(zip(sets, results)):
        if res.answer is not None:
            continue
        by_index = {r.index: r for r in recs}
        reads = {k: list(v) for k, v in all_reads[si].items()}
        applied: dict = {}
        cur = res
        # Settle the unvouched records one round at a time: the walk stops at the first record it cannot
        # place, so a later one is only named once the earlier one is read.
        for _ in range(len(recs)):
            todo = [i for i in cur.unvouched if i not in applied and key(by_index[i]) in chosen]
            if cur.answer is not None or not todo:
                break
            for idx in todo:
                ch = chosen[key(by_index[idx])]
                out = C.apply_chain(by_index[idx].payload, ch, codecs)
                applied[idx] = ch
                if out is None or not C.is_text(out):
                    continue
                extra = Reading(out, [ch], proved=True, consensus=True)
                reads[idx] = [extra] if cur.assemblies else [extra] + reads[idx]
            cur = assemble(recs, oracle, crib=crib, pin=pin, reads=reads)
        if not applied:
            res.reason += "; no consensus chain for them"
            continue
        cur.consensus = applied
        cur.reason += f"; records {sorted(applied)} also read by their consensus chain"
        results[si] = cur
    return results


def solve_blob(blob: bytes, oracle: Oracle, *, crib: bytes = b"", graph: Optional[Graph] = None,
               budget: Optional[float] = None, group_all: bool = False, min_n: int = 3) -> SetResult:
    """One numbered-record blob: assemble it; with group_all, a blob without one answer is settled by the
    chain its own vouched records agree on (`consensus(..., group="all")` over the one set)."""
    deadline = time.monotonic() + budget if budget else None
    recs = parse(blob)
    if not group_all:
        return assemble(recs, oracle, crib=crib, graph=graph, deadline=deadline)
    return consensus([recs], oracle, crib=crib, min_n=min_n, group="all", graph=graph, deadline=deadline)[0]
