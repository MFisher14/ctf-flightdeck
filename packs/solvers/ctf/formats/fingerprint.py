"""Fingerprint a member ctf.formats.identify could not name, then look it up offline (B-207).

The format catalog (catalog.toml / identify) parses the containers it knows. When it names nothing
`sure`, this is the step that runs: it reads a bounded prefix of the member and records what it can
measure without a reader --

    magic strings     the leading bytes (hex) and the printable ascii runs in the header window
    header fields     the integers at the head read u16/u32, little- and big-endian: candidate field
                      sizes / counts a record format carries up front
    record geometry   the dominant repeat period (record stride) found by self-correlation, and the
                      entropy profile across the prefix (flat high entropy = packed/encrypted; a low
                      band = a header or a string table)
    string table      the ascii and UTF-16LE strings in the prefix, deduped and bounded

Then an OFFLINE known-format lookup, BEFORE any remote search: identify() first (a sure match short-
circuits -- this step is only for members it cannot name), then the local magic table
(ctf/formats/magic.toml), a fixed-signature catalog that names a format or the tool that writes it,
then the known-format DB (B-087, ctf/formats/known.toml via ctf.formats.known): composite fingerprints
(signatures counted from either end, record geometry, base name, header ascii, an entropy floor) that
name a format and the public reference documenting its layout.

Only if the offline lookup names nothing and the caller passes an online code-search client (see
ctf.formats.codesearch, off by default and gated by event policy) are the short magic strings sent to
public code search. The ranked result is a 'likely tool/format' finding, always UNSURE evidence: a
lead for a human, never a verdict and never a flag.

Everything here is bounded: at most FP_BYTES of the member are read, the geometry probe runs on a
small window, and the string table is capped. Nothing is executed.
"""
from __future__ import annotations

import math
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from ..result import Evidence, SolverResult
from . import identify as _identify

__all__ = ["MagicError", "Magic", "Fingerprint", "Candidate", "FingerprintResult",
           "load_magic", "fingerprint", "magic_candidates", "analyze", "MAGIC_TABLE"]

MAGIC_TABLE = Path(__file__).with_name("magic.toml")

# Bounds (bytes). A member can be huge; this step never reads it whole.
FP_BYTES = 1 << 20          # the prefix read for the string table and entropy profile
HEAD_BYTES = 64             # the header window magic strings and header fields are read from
GEOM_BYTES = 1 << 13        # the window the record-stride probe runs on (8 KiB)
GEOM_MAX_STRIDE = 1024      # the largest record stride the probe considers
ENTROPY_WINDOW = 1024       # the entropy profile's window
MAX_STRINGS = 64            # the string table is capped at this many strings
MAX_STRING_LEN = 96         # each string is truncated to this many characters
MIN_STRING_LEN = 4          # a run shorter than this is not a string
MAX_MAGIC_STRINGS = 8       # at most this many short magic strings are offered to a code search
MAGIC_SEND_MAX = 48         # a magic string longer than this is never offered (it is not "short")

MAGIC_KEYS = {"id", "label", "tool", "sig", "at", "ext", "note"}
MAGIC_REQUIRED = ("id", "label", "sig")


class MagicError(ValueError):
    """The magic table cannot be used: the message names the file, the entry and the key."""


@dataclass(frozen=True)
class Magic:
    id: str
    label: str
    sig: bytes
    at: int = 0
    tool: str | None = None
    ext: tuple[str, ...] = ()
    note: str = ""


@dataclass(frozen=True)
class Fingerprint:
    name: str
    size: int
    head_hex: str                       # the first HEAD_BYTES bytes as hex
    magic_ascii: tuple[str, ...]        # printable ascii runs inside the header window
    header_fields: tuple[dict, ...]     # {offset, u16le, u16be, u32le, u32be} at 0, 4, 8, 12
    entropy: float                      # Shannon entropy (bits/byte) over the read prefix
    entropy_profile: tuple[float, ...]  # per-window entropy, left to right
    stride: int | None                  # the dominant record stride, or None
    stride_score: float                 # fraction of bytes that repeat at `stride` (0 when None)
    strings: tuple[str, ...]            # the bounded string table (ascii then utf-16le)


@dataclass(frozen=True)
class Candidate:
    source: str            # "identify" | "magic" | "known" | "codesearch"
    label: str
    why: str
    score: int
    tool: str | None = None
    ref: str | None = None  # a URL / repo for an online lead


@dataclass
class FingerprintResult:
    name: str
    named: tuple = ()                   # identify() sure matches (if any): then the step short-circuits
    fp: Fingerprint | None = None
    candidates: tuple = ()              # ranked Candidate, best first
    online_used: bool = False
    online_error: str | None = None
    sent_magics: tuple[str, ...] = field(default_factory=tuple)

    def to_result(self, *, engine: str = "formats.format_fingerprint",
                  challenge_id: str | None = None) -> SolverResult:
        """The ranked 'likely tool/format' finding as UNSURE evidence (never a flag)."""
        ev: list[Evidence] = []
        if self.named:
            top = self.named[0]
            ev.append(Evidence("match", f"ctf.formats.identify named it {top.format} ({top.why})",
                               path=self.name))
            return SolverResult(status="unsure", evidence=tuple(ev),
                                engine=engine, challenge_id=challenge_id,
                                notes=f"identify() already names {self.name}; fingerprint step skipped")
        if self.fp is not None:
            ev.append(Evidence("fingerprint",
                               f"magic {self.fp.head_hex[:16]}.. size {self.fp.size} "
                               f"entropy {self.fp.entropy:.2f} b/byte"
                               + (f" stride {self.fp.stride} ({self.fp.stride_score:.0%})"
                                  if self.fp.stride else ""),
                               path=self.name))
        for c in self.candidates:
            ref = f" [{c.ref}]" if c.ref else ""
            tool = f" (tool: {c.tool})" if c.tool else ""
            ev.append(Evidence("match", f"likely {c.label}{tool} -- {c.why}{ref}", path=self.name))
        notes = ("no offline or online lead; the fingerprint facts are for a human read"
                 if not self.candidates else "ranked tool/format leads; unsure, for a human to confirm")
        if self.online_error:
            notes += f" (code search: {self.online_error})"
        return SolverResult(status="unsure", evidence=tuple(ev), engine=engine,
                            challenge_id=challenge_id, notes=notes)


# ------------------------------------------------------------------ the local magic table

def _hexbytes(where: str, value) -> bytes:
    if not isinstance(value, str):
        raise MagicError(f"{where}: sig must be a hex string")
    s = value.strip()
    if not s or len(s) % 2 or any(c not in "0123456789abcdefABCDEF" for c in s):
        raise MagicError(f"{where}: sig {value!r} is not an even-length hex string")
    raw = bytes.fromhex(s)
    if not 1 <= len(raw) <= 16:
        raise MagicError(f"{where}: sig is {len(raw)} bytes; must be 1..16")
    return raw


def load_magic(path: Path | str | None = None) -> tuple:
    """The local magic table, longest signature first so the most specific wins. Every key is checked;
    a bad entry is a MagicError naming it, never a signature quietly dropped."""
    path = Path(path) if path is not None else MAGIC_TABLE
    if not path.is_file():
        raise MagicError(f"{path}: the magic table is not there")
    try:
        doc = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as e:
        raise MagicError(f"{path}: not TOML ({e})") from None
    if set(doc) != {"magic"} or not isinstance(doc["magic"], list) or not doc["magic"]:
        raise MagicError(f"{path}: the table is a non-empty list of [[magic]] entries and nothing else")
    out, ids = [], set()
    for i, m in enumerate(doc["magic"]):
        where = f"{path}: magic {m.get('id', i + 1)!r}"
        if not isinstance(m, dict):
            raise MagicError(f"{where}: not a table")
        if set(m) - MAGIC_KEYS:
            raise MagicError(f"{where}: unknown keys {sorted(set(m) - MAGIC_KEYS)}")
        for k in MAGIC_REQUIRED:
            if k not in m:
                raise MagicError(f"{where}: missing {k!r}")
        if not isinstance(m["id"], str) or not m["id"].strip():
            raise MagicError(f"{where}: id must be a non-empty string")
        if m["id"] in ids:
            raise MagicError(f"{where}: id listed twice")
        ids.add(m["id"])
        for k in ("label",):
            if not isinstance(m[k], str) or not m[k].strip():
                raise MagicError(f"{where}: {k} must be a non-empty string")
        sig = _hexbytes(where, m["sig"])
        at = m.get("at", 0)
        if not isinstance(at, int) or isinstance(at, bool) or at < 0:
            raise MagicError(f"{where}: at must be an integer offset >= 0")
        ext = m.get("ext", [])
        if not isinstance(ext, list) or not all(isinstance(e, str) and e.startswith(".") for e in ext):
            raise MagicError(f"{where}: ext must be a list of '.'-prefixed strings")
        tool = m.get("tool")
        if tool is not None and (not isinstance(tool, str) or not tool.strip()):
            raise MagicError(f"{where}: tool must be a non-empty string when present")
        note = m.get("note", "")
        if not isinstance(note, str):
            raise MagicError(f"{where}: note must be a string")
        out.append(Magic(m["id"], m["label"].strip(), sig, at, tool.strip() if tool else None,
                         tuple(ext), note.strip()))
    # Longest signature first: a more specific magic (e.g. the 8-byte PNG header) beats a short prefix.
    return tuple(sorted(out, key=lambda x: (-len(x.sig), x.at, x.id)))


# ------------------------------------------------------------------ the fingerprint

def _entropy(hist: list[int], total: int) -> float:
    if total <= 0:
        return 0.0
    h = 0.0
    for c in hist:
        if c:
            p = c / total
            h -= p * math.log2(p)
    return h


def _ascii_runs(data: bytes, minlen: int):
    run = bytearray()
    for b in data:
        if 32 <= b < 127:
            run.append(b)
        else:
            if len(run) >= minlen:
                yield run.decode("ascii")
            run = bytearray()
    if len(run) >= minlen:
        yield run.decode("ascii")


def _utf16le_runs(data: bytes, minlen: int):
    # A printable ascii character stored as UTF-16LE is one printable byte followed by a zero byte.
    run = bytearray()
    i, n = 0, len(data) - (len(data) % 2)
    while i < n:
        lo, hi = data[i], data[i + 1]
        if hi == 0 and 32 <= lo < 127:
            run.append(lo)
        else:
            if len(run) >= minlen:
                yield run.decode("ascii")
            run = bytearray()
        i += 2
    if len(run) >= minlen:
        yield run.decode("ascii")


def _stride(data: bytes, max_stride: int) -> tuple[int | None, float]:
    """The record stride: the period s that maximises the fraction of bytes equal to the byte s ahead.
    Equality is counted with a single big-int XOR per stride (zero bytes in a^b are the matches), so
    the probe is bounded C work, not a Python byte loop. A near-constant window reports no stride."""
    n = len(data)
    if n < 4:
        return None, 0.0
    best_s, best_frac = None, 0.0
    limit = min(max_stride, n // 2)
    for s in range(1, limit + 1):
        a, b = data[: n - s], data[s:]
        xb = (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")
        frac = xb.count(0) / len(a)
        if frac > best_frac:
            best_s, best_frac = s, frac
    # A flat region (all one byte) matches at every stride; demand a real, not trivial, period.
    if best_frac < 0.25:
        return None, 0.0
    return best_s, best_frac


def fingerprint(name: str, data: bytes) -> Fingerprint:
    """Measure a member without any reader. `data` is a buffer (bytes or an mmap); at most FP_BYTES are
    read for the string table and entropy, the header window is the first HEAD_BYTES."""
    size = len(data)
    prefix = bytes(data[:FP_BYTES])
    head = prefix[:HEAD_BYTES]
    head_hex = head.hex()
    magic_ascii = tuple(dict.fromkeys(_ascii_runs(head, MIN_STRING_LEN)))

    fields = []
    for off in (0, 4, 8, 12):
        if off + 4 <= len(prefix):
            chunk = prefix[off:off + 4]
            fields.append({
                "offset": off,
                "u16le": int.from_bytes(chunk[:2], "little"),
                "u16be": int.from_bytes(chunk[:2], "big"),
                "u32le": int.from_bytes(chunk, "little"),
                "u32be": int.from_bytes(chunk, "big"),
            })

    hist = [0] * 256
    for b in prefix:
        hist[b] += 1
    entropy = _entropy(hist, len(prefix))

    profile = []
    for i in range(0, len(prefix), ENTROPY_WINDOW):
        win = prefix[i:i + ENTROPY_WINDOW]
        if len(win) < ENTROPY_WINDOW // 2 and profile:
            break
        wh = [0] * 256
        for b in win:
            wh[b] += 1
        profile.append(round(_entropy(wh, len(win)), 3))
        if len(profile) >= 64:
            break

    stride, stride_score = _stride(prefix[:GEOM_BYTES], GEOM_MAX_STRIDE)

    seen, strings = set(), []
    for run in list(_ascii_runs(prefix, MIN_STRING_LEN)) + list(_utf16le_runs(prefix, MIN_STRING_LEN)):
        s = run[:MAX_STRING_LEN]
        if s not in seen:
            seen.add(s)
            strings.append(s)
            if len(strings) >= MAX_STRINGS:
                break

    return Fingerprint(name=name, size=size, head_hex=head_hex, magic_ascii=magic_ascii,
                       header_fields=tuple(fields), entropy=round(entropy, 3),
                       entropy_profile=tuple(profile), stride=stride,
                       stride_score=round(stride_score, 3), strings=tuple(strings))


def magic_candidates(fp: Fingerprint) -> tuple[str, ...]:
    """The short magic strings worth sending to a public code search: the printable runs at the very
    head, plus distinctive short strings from the table. Bounded in count and length so only a short
    non-content token can ever leave the host."""
    out, seen = [], set()
    for s in list(fp.magic_ascii) + list(fp.strings):
        s = s.strip()
        if MIN_STRING_LEN <= len(s) <= MAGIC_SEND_MAX and s not in seen:
            seen.add(s)
            out.append(s)
        if len(out) >= MAX_MAGIC_STRINGS:
            break
    return tuple(out)


# ------------------------------------------------------------------ offline lookup + the step

def _magic_hits(data: bytes, table) -> list[Candidate]:
    out = []
    for m in table:
        end = m.at + len(m.sig)
        if end <= len(data) and bytes(data[m.at:end]) == m.sig:
            why = f"magic {m.sig.hex()} at offset {m.at}"
            if m.note:
                why += f"; {m.note}"
            out.append(Candidate("magic", m.label, why, 60 + len(m.sig), tool=m.tool,
                                 ref=m.id))
    return out


def analyze(name: str, data, *, catalog=None, magic_table=None, client=None,
            profile=None, known=None) -> FingerprintResult:
    """The format_fingerprint step on one member.

    1. ctf.formats.identify: a `sure` match means the member is named -- the step short-circuits and
       does no fingerprint and no lookup (it exists only for members identify cannot name).
    2. Otherwise fingerprint the bytes and run the offline lookups: the magic table, then the
       known-format DB (B-087; `known` is a table from ctf.formats.known.load(), None loads the
       shipped one -- a bad table raises KnownError -- and an empty tuple turns the lookup off).
    3. Only if a `client` is given (ctf.formats.codesearch, off by default, event-policy gated) are the
       short magic strings sent to public code search; its hits are appended as lower-ranked leads.

    Candidates are ranked best-first and are always unsure leads.
    """
    buf = data if isinstance(data, (bytes, bytearray, memoryview)) else bytes(data)
    matches = _identify(name, buf, catalog)
    sure = [m for m in matches if m.sure]
    if sure:
        return FingerprintResult(name=name, named=tuple(sure))

    fp = fingerprint(name, buf)
    table = load_magic() if magic_table is None else magic_table
    candidates = _magic_hits(buf, table)
    from . import known as _known           # imported here: known builds on this module's Fingerprint
    candidates += _known.lookup(fp, buf, _known.load() if known is None else known)

    sent: tuple[str, ...] = ()
    online_used = False
    online_error = None
    if client is not None:
        magics = magic_candidates(fp)
        sent = magics
        online_used = True
        try:
            rows = client.search(magics, profile=profile)
        except Exception as e:                      # the client names its own refusals; never silent
            online_error = f"{type(e).__name__}: {e}"
            rows = []
        for r in rows:
            candidates.append(Candidate("codesearch", r.label, r.why, r.score, tool=r.tool, ref=r.ref))

    candidates.sort(key=lambda c: (-c.score, c.source, c.label))
    return FingerprintResult(name=name, fp=fp, candidates=tuple(candidates), online_used=online_used,
                             online_error=online_error, sent_magics=sent)
