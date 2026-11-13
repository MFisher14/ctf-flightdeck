"""Binary-first read (B-199): what a binary file is, in one capped screen, instead of a text dump.

Agents called Read on binaries, got a flood or a refusal, and then fell back to `xxd`. `ctf read` now
answers a binary with this summary by default: its identification, size, hash, entropy, a hex head
and its printable strings with offsets, all under the ctf.hygiene caps. `--strings` lists every
string, `--bytes N` is a longer hex view.

Identification is the master's own, offline and bounded: ctf.formats.identify (the structural
catalog: a `sure` match means the bytes have that structure) and the local magic table
(ctf/formats/magic.toml, ctf.formats.fingerprint.load_magic). Nothing is executed or decompressed. A
detector that fails is named in the summary (never a silent "unknown").

    from ctf import binsummary
    s = binsummary.summarize("a.bin", data)          # BinarySummary
    print(s.render())                                # the summary text (cap it with ctf.hygiene)
    binsummary.strings(data, min_len=4)              # [(offset, encoding, text)], ascii then utf-16le
    binsummary.hexdump(data, n)                      # the first n bytes as an offset/hex/ascii view
"""
from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass, field

__all__ = ["SCAN_BYTES", "ENTROPY_BYTES", "HEAD_BYTES", "SUMMARY_STRINGS", "MIN_STRING",
           "BinarySummary", "summarize", "strings", "hexdump", "entropy", "identify"]

SCAN_BYTES = 16 << 20       # strings are searched in at most this many leading bytes (named when cut)
ENTROPY_BYTES = 1 << 20     # entropy is measured over this many leading bytes
HEAD_BYTES = 64             # the hex head shown in a summary
SUMMARY_STRINGS = 24        # strings shown in a summary (the rest: --strings)
MIN_STRING = 6              # the shortest run a summary calls a string (--strings defaults to 4)
STRING_CHARS = 120          # each string shown at most this long


def hexdump(data: bytes, n: int) -> str:
    """The first `n` bytes as `offset  hex  ascii` rows of 16 (the B-034 --bytes view)."""
    chunk = bytes(data[:n])
    rows = []
    for off in range(0, len(chunk), 16):
        row = chunk[off:off + 16]
        hexs = " ".join(f"{b:02x}" for b in row)
        text = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in row)
        rows.append(f"{off:08x}  {hexs:<47}  {text}")
    return "\n".join(rows)


def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte of the first ENTROPY_BYTES bytes (0.0 for no data)."""
    chunk = bytes(data[:ENTROPY_BYTES])
    if not chunk:
        return 0.0
    n = len(chunk)
    return -sum(c / n * math.log2(c / n) for c in Counter(chunk).values())


def _entropy_word(h: float) -> str:
    if h >= 7.5:
        return "high: compressed, encrypted or packed"
    if h >= 5.5:
        return "mixed: code or structured data"
    return "low: text-like, sparse or padded"


def strings(data: bytes, *, min_len: int = 4, limit: int | None = None) -> list[tuple[int, str, str]]:
    """Printable runs of at least `min_len` characters in the first SCAN_BYTES bytes, as (offset,
    "ascii" | "utf16le", text), in offset order within each encoding (ascii first). `limit` stops after
    that many."""
    if min_len < 1:
        raise ValueError(f"min_len must be at least 1, got {min_len}")
    buf = bytes(data[:SCAN_BYTES])
    out: list[tuple[int, str, str]] = []
    ascii_ends: dict[int, int] = {}          # the last byte of each ascii run -> its start
    for m in re.finditer(rb"[\x20-\x7e\t]{%d,}" % min_len, buf):
        ascii_ends[m.end() - 1] = m.start()
        out.append((m.start(), "ascii", m.group().decode("ascii")))
        if limit is not None and len(out) >= limit:
            return out
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len, buf):
        start, text = m.start(), m.group()
        if start in ascii_ends:
            # "...so.2\0W\0I\0": the first pair is the ascii run's last character and its NUL
            # terminator, not the wide string's first character
            start, text = start + 2, text[2:]
            if len(text) // 2 < min_len:
                continue
        out.append((start, "utf16le", text.decode("utf-16-le")))
        if limit is not None and len(out) >= limit:
            return out
    return out


def identify(name: str, data: bytes) -> tuple[list[str], list[str]]:
    """(labels, problems): what the bytes are, best first -- the catalog's structural (`sure`) matches,
    then the local magic table's hits -- and any detector or table failure, named."""
    from . import formats as _formats
    from .formats import fingerprint as _fp
    labels: list[str] = []
    problems: list[str] = []
    try:
        for m in _formats.identify(name, data):
            if m.sure:
                labels.append(f"{m.format} (catalog: {m.why})")
    except (_formats.DetectorError, _formats.FormatLimit, _formats.CatalogError) as e:
        problems.append(f"format catalog: {type(e).__name__}: {e}")
    try:
        for mg in _fp.load_magic():
            end = mg.at + len(mg.sig)
            if end <= len(data) and bytes(data[mg.at:end]) == mg.sig:
                tool = f"; tool {mg.tool}" if mg.tool else ""
                labels.append(f"{mg.label} (magic {mg.sig.hex()} at {mg.at}{tool})")
    except _fp.MagicError as e:
        problems.append(f"magic table: {e}")
    return labels, problems


@dataclass
class BinarySummary:
    name: str
    size: int
    sha256: str
    entropy: float
    labels: list = field(default_factory=list)
    problems: list = field(default_factory=list)
    head: str = ""
    strings: list = field(default_factory=list)       # the shown (offset, encoding, text)
    strings_total: int = 0
    scanned: int = 0                                   # bytes searched for strings

    def render(self) -> str:
        out = [f"[binary] {self.name}: {self.size} bytes, sha256 {self.sha256[:16]}, "
               f"entropy {self.entropy:.2f} bits/byte ({_entropy_word(self.entropy)})"]
        if self.labels:
            out.append("type: " + "; ".join(self.labels))
        else:
            out.append("type: not identified by the format catalog or the magic table")
        out += [f"identify problem: {p}" for p in self.problems]
        out.append(f"head ({min(self.size, HEAD_BYTES)} bytes):")
        out.append(self.head)
        cut = (f" in the first {self.scanned} of {self.size} bytes" if self.scanned < self.size else "")
        out.append(f"strings (>= {MIN_STRING} chars, ascii then utf-16le{cut}): "
                   f"{len(self.strings)} shown of {self.strings_total}")
        for off, enc, text in self.strings:
            tag = "" if enc == "ascii" else " [utf16le]"
            shown = text if len(text) <= STRING_CHARS else text[:STRING_CHARS - 1] + "…"
            out.append(f"  0x{off:08x}{tag}  {shown}")
        out.append("[ctf: more with --strings (every string), --bytes N (hex), or a binary engine: "
                   "`python -m ctf engines route <category> \"<desc>\" --files <dir>`]")
        return "\n".join(out)


def summarize(name: str, data: bytes) -> BinarySummary:
    """The binary-first summary of one file's bytes (see the module docstring)."""
    data = bytes(data)
    labels, problems = identify(name, data)
    found = strings(data, min_len=MIN_STRING)
    return BinarySummary(name=name, size=len(data), sha256=hashlib.sha256(data).hexdigest(),
                         entropy=entropy(data), labels=labels, problems=problems,
                         head=hexdump(data, HEAD_BYTES), strings=found[:SUMMARY_STRINGS],
                         strings_total=len(found), scanned=min(len(data), SCAN_BYTES))
