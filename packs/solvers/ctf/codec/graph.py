"""The shared recursive codec graph (B-163): a bounded breadth-first search over decode steps.

Nodes are byte strings, edges are codecs (`ctf.codec.codecs`). The search starts at the input, takes
every codec that accepts the current state, and stops descending at a state the goal oracle
(`ctf.codec.oracle`) accepts. Every lane uses the same graph: intake's fastlane decode, `ctf codec`,
the `common.codec_graph` engine, and any lane that hands it a recognizer of its own final object.

    from ctf.codec import Graph, FlagOracle, CribOracle, Recognizer
    r = Graph().search(blob, FlagOracle(profile))
    r.unique            # the one answer, or None (none, or several distinct answers)
    r.hits              # every Hit(answer, chain, data, oracle, confirmed) at the shallowest goal depth
    r.truncated         # None when the bound was searched; "nodes" | "bytes" | "deadline" otherwise

What makes it a graph rather than a fixed peeler (the gaps it closes):

  * **Depth.** Strict and symbol codecs compose to `max_depth` (default 8) in any order: the Binary
    lane's 18-of-25 ordered wrapper pairs and the shared peeler's two-layer stop are just paths here.
  * **Loose steps in any position.** A loose transform (rot13/rot47/caesar/atbash/reverse/swapcase/xor)
    or a keyed one (rail fence) may sit before, between or after strict codecs, at most `max_loose` per
    chain and never two in a row. It is followed only when its output *reads on*: some strict codec
    accepts it and gives printable text, a known container magic, a state a printable-text xor key
    exists for, or a state the oracle accepts (the "form-valid" gate). A wrong caesar shift of base64 is
    still base64, but decodes to noise and dies there; ROT47(Base64(Base64(P))),
    Base64(ROT47(Base64(P))) and Base64(XOR(Base64(P))) are found. A partial escape decode (url,
    html) counts for the gate only when the escapes are most of the text.
  * **Keyed steps need a strong oracle.** A transposition permutes characters, so under a flag-shape
    oracle it could assemble `ctf{...}` from any text holding those letters: the rail family runs only
    under a crib, slug, or recognizer oracle (or `keyed=True`), and in `explore` (records check every
    reading at the true cut).
  * **xor is enumerated per state**, only over the keys that make every byte printable text
    (`codecs.xor_text_keys`), never all 255 blindly.
  * **Every hit at the goal depth is reported**, and `unique` is None when two distinct answers tie, so
    a first hit is never proof of selection.

Staged: the search first runs with representation steps only (strict, symbol, pack); only when that
finds no answer does it run again with loose and keyed steps, on the attempts left. A confirmed
representation-only answer is therefore never displaced by a shallower loose reading, and plain
compositions stay cheap however wide the loose alphabet is.

Bounds, all explicit: `max_depth`, `max_nodes` (decode attempts, refused ones included), `max_bytes` (total bytes
of the states kept), `max_state` (a state larger than this is not expanded), an optional deadline.
A search cut by a bound says so in `truncated`. Nothing is executed, nothing touches the network.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Iterable, Optional

from . import codecs as C
from .oracle import Oracle, is_strong

MAX_DEPTH = 8
MAX_NODES = 40000           # decode attempts (every codec call counts, accepted or refused)
MAX_BYTES = 64 << 20
MAX_STATE = 1 << 20          # a state larger than this is not expanded
LOOSE_MAX_STATE = 64 << 10   # loose and keyed steps are not tried on a state larger than this
PACK_MAX_STATE = 8 << 10     # breadth-pack codecs are asked only on states up to this size
MAX_LOOSE = 3
PARTIAL_DENSE = 0.6          # a partial escape decode passes the loose gate only when it shrinks the text this much
MAGICS = (b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00", b"PK\x03\x04", b"7z\xbc\xaf\x27\x1c", b"\x89PNG", b"%PDF",
          b"\x7fELF", b"MZ", b"Rar!", b"SQLite format 3\x00", b"\xd0\xcf\x11\xe0")


@dataclass(frozen=True)
class Hit:
    answer: str
    chain: tuple
    data: bytes
    oracle: str
    confirmed: bool

    @property
    def how(self) -> str:
        return "+".join(self.chain) or "plain"


@dataclass
class SearchResult:
    hits: list = field(default_factory=list)
    nodes: int = 0
    depth: int = 0
    truncated: Optional[str] = None
    errors: list = field(default_factory=list)
    skipped_large: int = 0

    @property
    def answers(self) -> list:
        out = []
        for h in self.hits:
            if h.answer not in out:
                out.append(h.answer)
        return out

    @property
    def unique(self) -> Optional[str]:
        a = self.answers
        return a[0] if len(a) == 1 else None

    def to_json(self) -> dict:
        return {"answers": self.answers, "unique": self.unique, "nodes": self.nodes, "depth": self.depth,
                "truncated": self.truncated, "errors": self.errors[:20],
                "hits": [{"answer": h.answer, "chain": list(h.chain), "oracle": h.oracle,
                          "confirmed": h.confirmed} for h in self.hits]}


class _Stop(Exception):
    def __init__(self, why):
        self.why = why


def _has_magic(b: bytes) -> bool:
    """A known container/compression magic, or a zlib header (CMF/FLG check)."""
    if b.startswith(MAGICS):
        return True
    return len(b) > 2 and b[0] & 0x0F == 8 and b[0] >> 4 <= 7 and ((b[0] << 8) | b[1]) % 31 == 0


class Graph:
    """A codec graph over `codecs` (default: the core set, plus any breadth pack's codecs passed in)."""

    def __init__(self, codecs: Optional[Iterable[C.Codec]] = None, *, max_depth: int = MAX_DEPTH,
                 max_nodes: int = MAX_NODES, max_bytes: int = MAX_BYTES, max_loose: int = MAX_LOOSE,
                 max_state: int = MAX_STATE, xor: bool = True, keyed: Optional[bool] = None):
        self.codecs = tuple(codecs) if codecs is not None else C.core()
        names = [c.name for c in self.codecs]
        dup = {n for n in names if names.count(n) > 1}
        if dup:
            raise C.CodecError(f"two codecs share a name: {sorted(dup)}")
        for n, v in (("max_depth", max_depth), ("max_nodes", max_nodes), ("max_bytes", max_bytes),
                     ("max_state", max_state)):
            if not isinstance(v, int) or v < 1:
                raise ValueError(f"{n} must be a positive integer, got {v!r}")
        if not isinstance(max_loose, int) or max_loose < 0:
            raise ValueError(f"max_loose must be a non-negative integer, got {max_loose!r}")
        self.max_depth, self.max_nodes, self.max_bytes = max_depth, max_nodes, max_bytes
        self.max_loose, self.max_state, self.xor, self.keyed = max_loose, max_state, xor, keyed
        self._strict = [c for c in self.codecs if c.kind in C.REPRESENTATION]
        self._loose = [c for c in self.codecs if c.kind in (C.LOOSE, C.KEYED)]

    # ------------------------------------------------------------------------------------ edges

    def _run(self, codec: C.Codec, b: bytes, st) -> Optional[bytes]:
        try:
            out = codec.decode(b)
        except Exception as e:          # untrusted input: a codec that raises refused it; say which
            if len(st.errors) < 50:
                st.errors.append(f"{codec.name}: {type(e).__name__}: {str(e)[:80]}")
            out = None
        st.count()                      # every attempt counts against max_nodes, a raised one included
        if out is None or not isinstance(out, (bytes, bytearray)) or not out or out == b:
            return None
        return bytes(out)

    def _strict_children(self, b: bytes, st) -> list:
        got = st.memo.get(b)
        if got is not None:
            return got
        out = []
        text = C.is_text(b)
        for c in self._strict:
            if c.text_only and not text:
                continue
            if c.kind == C.PACK and len(b) > PACK_MAX_STATE:
                continue
            o = self._run(c, b, st)
            if o is not None:
                out.append((c, o))
        if len(st.memo) < 4096:
            st.memo[b] = out
        return out

    def _loose_children(self, b: bytes, st, keyed: bool):
        if len(b) > LOOSE_MAX_STATE:
            return
        text = C.is_text(b)
        for c in self._loose:
            if c.text_only and not text:
                continue
            if c.kind == C.KEYED and not keyed:
                continue
            o = self._run(c, b, st)
            if o is not None:
                yield c, o
        if self.xor:
            for k in C.xor_text_keys(b):
                c = C.by_name(f"{C.XOR_PREFIX}{k:02x}")
                o = self._run(c, b, st)
                if o is not None:
                    yield c, o

    def _reads_on(self, b: bytes, oracle: Optional[Oracle], st) -> bool:
        """The form-valid gate for a loose step's output: some strict codec reads it into something worth
        following (text, a container magic, a state with a printable xor key, or an oracle answer). A
        partial escape codec (url, html) counts only when the escapes are most of the text: a rot47 of
        letters makes stray `%e5` sequences, which are not a url layer."""
        for codec, child in self._strict_children(b, st):
            if codec.name in C.PARTIAL and len(child) > PARTIAL_DENSE * len(b):
                continue
            if C.is_text(child) or _has_magic(child):
                return True
            if self.xor and len(child) <= LOOSE_MAX_STATE and C.xor_text_keys(child):
                return True
            if oracle is not None and oracle.check(child):
                return True
        return False

    # ------------------------------------------------------------------------------------ walk

    def _walk(self, data: bytes, oracle: Optional[Oracle], deadline: Optional[float], stop_at_goal_depth: bool,
              collect: Optional[list], max_loose: Optional[int] = None, max_nodes: Optional[int] = None):
        max_loose = self.max_loose if max_loose is None else max_loose
        # A transposition permutes characters: over a flag-shape oracle it can assemble `ctf{...}` out of
        # any text holding those letters, so keyed steps need a strong oracle (a crib, a slug after the crib,
        # a recognizer) or the records DP (no oracle: every reading is checked at the true cut).
        keyed = self.keyed if self.keyed is not None else (oracle is None or is_strong(oracle))
        st = _State(self.max_nodes if max_nodes is None else max_nodes, deadline)
        res = st.result
        data = bytes(data)
        if collect is not None:
            collect.append((data, ()))
        if oracle is not None:
            for a in oracle.check(data):
                res.hits.append(Hit(a, (), data, oracle.name, is_strong(oracle, data)))
            if res.hits:
                return res
        seen = {data}
        kept = len(data)
        frontier = [(data, (), 0, None)]
        try:
            for depth in range(1, self.max_depth + 1):
                res.depth = depth
                nxt = []
                for cur, chain, nloose, last in frontier:
                    st.tick()
                    if len(cur) > self.max_state:
                        res.skipped_large += 1
                        continue
                    edges = list(self._strict_children(cur, st))
                    loose_ok = nloose < max_loose and last not in (C.LOOSE, C.KEYED)
                    if loose_ok:
                        edges += list(self._loose_children(cur, st, keyed))
                    for codec, out in edges:
                        if out in seen:
                            continue
                        seen.add(out)
                        kept += len(out)
                        if kept > self.max_bytes:
                            raise _Stop("bytes")
                        ch = chain + (codec.name,)
                        is_loose = codec.kind in (C.LOOSE, C.KEYED)
                        if collect is not None:
                            collect.append((out, ch))
                        if oracle is not None:
                            answers = oracle.check(out)
                            if answers:
                                confirmed = bool(C.representation_steps(ch, self.codecs)) or is_strong(oracle, out)
                                for a in answers:
                                    res.hits.append(Hit(a, ch, out, oracle.name, confirmed))
                                continue
                        if is_loose and not self._reads_on(out, oracle, st):
                            continue
                        nxt.append((out, ch, nloose + is_loose, codec.kind))
                if res.hits and stop_at_goal_depth:
                    break
                frontier = nxt
                if not frontier:
                    break
        except _Stop as s:
            res.truncated = s.why
        return res

    def search(self, data: bytes, oracle: Oracle, *, deadline: Optional[float] = None,
               all_depths: bool = False) -> SearchResult:
        """Every state the oracle accepts, at the shallowest depth where one is found (every depth with
        all_depths=True), representation-only chains first (see the module text). `deadline` is a
        time.monotonic() value."""
        if oracle is None:
            raise ValueError("search needs a goal oracle (ctf.codec.oracle)")
        first = self._walk(data, oracle, deadline, not all_depths, None, max_loose=0)
        if first.hits or self.max_loose == 0:
            return first
        left = self.max_nodes - first.nodes
        if left <= 0:
            return first
        second = self._walk(data, oracle, deadline, not all_depths, None, max_nodes=left)
        second.nodes += first.nodes
        second.errors[:0] = first.errors
        if second.truncated is None and first.truncated is not None:
            second.truncated = first.truncated
        return second

    def explore(self, data: bytes, *, deadline: Optional[float] = None) -> tuple[list, SearchResult]:
        """Every state reached (data, chain), the input first, with no goal: the readings of a fragment
        whose oracle can only be checked after it is joined to others (`ctf.codec.records`). A loose
        step's output is listed even when it does not read on; it is only not expanded."""
        out: list = []
        res = self._walk(data, None, deadline, False, out)
        return out, res


class _State:
    def __init__(self, max_nodes: int, deadline: Optional[float]):
        self.result = SearchResult()
        self.errors = self.result.errors
        self.memo: dict = {}
        self.max_nodes, self.deadline = max_nodes, deadline

    def count(self):
        self.result.nodes += 1
        if self.result.nodes >= self.max_nodes:
            raise _Stop("nodes")
        if not self.result.nodes & 63:
            self.tick()

    def tick(self):
        if self.deadline is not None and time.monotonic() > self.deadline:
            raise _Stop("deadline")


def search(data: bytes, oracle: Oracle, *, codecs=None, deadline: Optional[float] = None, **bounds) -> SearchResult:
    """One-shot `Graph(codecs, **bounds).search(data, oracle, deadline=deadline)`."""
    return Graph(codecs, **bounds).search(data, oracle, deadline=deadline)
