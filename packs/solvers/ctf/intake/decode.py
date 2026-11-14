"""The fastlane decode step of intake, with the guards that keep decoder noise out of `solved` (B-012).

`ctf.fastlane` carries the warmups encoding-chain decoder (solvers/warmups/crib_decode.py). Run over a
few KB of base64 or hex noise, its loose steps (single-byte xor, rot13, the caesar shifts, swapcase,
reverse, ...) find a prefix-insensitive flag shape by chance at a rate of a few per hundred blobs:
`rot13+xor37` turns random base64 into `ctf{@\\x07xgr...}`. Base64 ciphertext is a common crypto
handout, so intake must never call such a reading `solved` (which auto-submit would send).

    hits = decode.decode_hits(detail, files_dir)   # every file and every brief blob, not the first hit
    for h in hits:
        h.verdict                                   # "flag" | "unconfirmed" | "noise"

Each hit is judged by `judge(flag, chain, reading)`:

  * **noise** -- the flag body holds a control or non-printable character. Excluded outright.
  * **unconfirmed** -- every step of the chain is a loose transform (nothing changed the representation:
    no base64, hex, url, compression, ...), and the decoded reading gives no crib support: the reading
    is not clean printable text, or the flag is less than half of it and the rest does not read as
    prose. The flag is kept, so the player sees it, but it makes the intake a `candidate`, never
    `solved`.
  * **flag** -- anything else: a representation decode reached it, or a loose chain whose whole
    reading is the flag or clean prose around it.

The decoder keeps its last result in a module global (crib_decode.LAST), so each blob is decoded and
its LAST read under the decoder's own solve lock: intakes run on threads (intake_many(spawn=False))
never read each other's readings.

A blob the crib decoder reads no flag from goes to the shared codec graph (B-163, `ctf.codec`): the
bounded recursive search with the event flag format as its oracle, which composes loose steps with
several strict codecs (ROT47(Base64(Base64(P))), Base64(XOR(Base64(P))), ...) and symbol alphabets over
hex. Every distinct flag it reaches becomes a hit (several make the intake a `candidate`), judged the
same way, with the graph's own representation steps counted as strict. GRAPH_BLOB_BUDGET bounds one
blob and GRAPH_BUDGET one intake; a cut search reports what it found.
"""
from __future__ import annotations

import string
import time
from dataclasses import dataclass
from pathlib import Path

NOISE = "noise"
UNCONFIRMED = "unconfirmed"
FLAG = "flag"

# Steps that only permute or shift characters: on a long blob they make flag shapes by chance. rot13 is
# a STRICT decoder inside crib_decode, but it is a classical shift, not a representation change.
_SHIFT_STRICT = frozenset({"rot13"})
_PRINTABLE = frozenset(chr(c) for c in range(0x20, 0x7f))
_TEXT_WS = frozenset("\t\r\n")
_WORDY = frozenset(string.ascii_letters + string.digits + " \t\r\n.,:;!?'\"-")
MIN_FLAG_SHARE = 0.5        # a loose-chain reading that is at least this much flag is the flag itself
MIN_WORDY = 0.95            # the rest of a loose-chain reading reads as prose: this share of plain chars
MIN_LETTERS = 0.6           # ... and this share of letters (noise is symbols and digits)
GRAPH_BLOB_BUDGET = 1.0     # seconds the codec graph may spend on one blob the crib decoder missed
GRAPH_BUDGET = 4.0          # seconds the codec graph may spend on one intake, all blobs together
CRIB = "crib_decode"
GRAPH = "codec_graph"


@dataclass
class Hit:
    flag: str
    chain: tuple                    # decoder step names, e.g. ("reverse", "b64")
    source: str                     # file name, or "description"
    reading: str | None             # the decoded text the flag sits in (None when the decoder gave none)
    verdict: str                    # FLAG | UNCONFIRMED | NOISE
    why: str
    decoder: str = CRIB             # CRIB | GRAPH: which decoder reached it

    @property
    def how(self) -> str:
        where = f"auto-decoded {self.source}" if self.source != "description" else "auto-decoded description blob"
        tail = " (codec graph)" if self.decoder == GRAPH else ""
        return f"{where} via {'+'.join(self.chain) or 'plain'}{tail}"


def _strict_steps(crib) -> frozenset:
    return frozenset(d.__name__[2:] for d in getattr(crib, "STRICT", ()) if d.__name__.startswith("d_")) - _SHIFT_STRICT


def body_is_printable(flag: str) -> bool:
    """True when every character of the flag body is printable ASCII (0x20..0x7e)."""
    i = flag.find("{")
    body = flag[i + 1:-1] if i >= 0 and flag.endswith("}") else flag
    return all(ch in _PRINTABLE for ch in body)


def crib_support(flag: str, reading: str | None) -> str | None:
    """None when the decoded reading supports the flag, else why not.

    Support = the reading is clean printable text, and either the flag is most of it or the rest of it
    reads as prose (plain characters, mostly letters)."""
    if reading is None:
        return "the decoder returned no reading to check the flag against"
    text = reading.strip()
    if not text:
        return "the decoded reading is empty"
    if not all(ch in _PRINTABLE or ch in _TEXT_WS for ch in text):
        return "the decoded reading around the flag is not clean text"
    if len(flag) >= MIN_FLAG_SHARE * len(text):
        return None
    rest = text.replace(flag, " ") if flag in text else text
    rest = rest.strip()
    if not rest:
        return None
    wordy = sum(ch in _WORDY for ch in rest) / len(rest)
    letters = sum(ch.isalpha() for ch in rest) / len(rest)
    if wordy >= MIN_WORDY and letters >= MIN_LETTERS:
        return None
    return (f"the decoded reading around the flag does not read as text ({wordy:.0%} plain characters, "
            f"{letters:.0%} letters)")


def judge(flag: str, chain, reading: str | None, strict_steps) -> tuple[str, str]:
    """(verdict, why) for one decoded flag; see the module docstring."""
    if not body_is_printable(flag):
        return NOISE, "fastlane decode noise: the flag body has control or non-printable characters"
    steps = tuple(chain or ())
    if any(s in strict_steps for s in steps):
        return FLAG, "a representation decode reached it"
    why = crib_support(flag, reading)
    if why is None:
        return FLAG, "a loose chain whose reading is the flag or clean text"
    return UNCONFIRMED, (f"unconfirmed fastlane decode: only loose steps ({'+'.join(steps) or 'plain'}), "
                         f"no crib support: {why}")


def _decode_one(fastlane, data: bytes):
    """(flag, chain tuple, reading) for one blob, or None. Run under the decoder's solve lock, so the
    decoder's LAST cannot be another thread's by the time it is read."""
    crib = fastlane._crib
    with crib._SOLVE_LOCK:
        got = fastlane._crib_flag(data)
        if not got:
            return None
        flag, chain_s = got
        readings = list(crib.LAST.get("flags") or [])
    best = None
    for r in readings:
        if not (isinstance(r, (tuple, list)) and len(r) >= 2 and isinstance(r[1], (tuple, list))):
            continue
        if fastlane._first_flag(str(r[0] or "")) != flag:
            continue
        if best is None or len(r[1]) < len(best[1]):
            best = r
    if best is None:
        steps = tuple(s for s in chain_s.split("+") if s and s not in ("plain", "decode"))
        return flag, steps, None
    reading = best[2] if len(best) >= 3 and isinstance(best[2], str) else None
    return flag, tuple(best[1]), reading


def _graph_hits(data: bytes, deadline: float):
    """(flag, chain, reading) for every distinct flag the shared codec graph reaches in one blob."""
    from ..codec import FlagOracle, Graph
    res = Graph().search(data, FlagOracle(), deadline=min(deadline, time.monotonic() + GRAPH_BLOB_BUDGET))
    out, seen = [], set()
    for h in res.hits:
        if h.answer in seen:
            continue
        seen.add(h.answer)
        out.append((h.answer, tuple(h.chain), h.data.decode("latin-1")))
    return out


def decode_hits(detail: dict, files_dir: Path, *, fastlane=None, graph: bool = True) -> list[Hit]:
    """Every flag the fastlane decoder reaches in the handout files and the brief's encoded blobs; a blob it
    misses goes to the shared codec graph (graph=False: the crib decoder alone).

    Raises RuntimeError when the decoder is not available (the caller names it; rule 6)."""
    from ..codec import codecs as _codecs
    if fastlane is None:
        from .. import fastlane
    if fastlane._crib is None:
        raise RuntimeError("the crib_decode decoder is unavailable (solvers/warmups/crib_decode.py)")
    strict = _strict_steps(fastlane._crib)
    blobs = [(name, data) for name, data in fastlane._read_small_files(files_dir)]
    blobs += [("description", b) for b in fastlane._encoded_blobs_from_desc(detail.get("description") or "")]
    hits: list[Hit] = []
    graph_deadline = time.monotonic() + GRAPH_BUDGET
    for source, data in blobs:
        got = _decode_one(fastlane, data)
        if got is not None:
            flag, chain, reading = got
            verdict, why = judge(flag, chain, reading, strict)
            hits.append(Hit(flag, chain, source, reading, verdict, why))
            continue
        if not graph or time.monotonic() >= graph_deadline:
            continue
        for flag, chain, reading in _graph_hits(data, graph_deadline):
            steps = strict | frozenset(_codecs.representation_steps(chain))
            verdict, why = judge(flag, chain, reading, steps)
            hits.append(Hit(flag, chain, source, reading, verdict, why, GRAPH))
    return hits
