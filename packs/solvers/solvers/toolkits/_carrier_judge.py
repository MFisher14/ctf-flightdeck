#!/usr/bin/env python3
"""The one verdict path of the B-245 carrier readers (audio_carriers, palette_stego, jpeg_stego_f8).

Every reading a carrier reader makes is a byte string. It goes through
stego_containers.validate_container, the lane's existing oracle, and through jpeg_stego._provable (a
proof must have some substance: at least 8 bytes and 4 distinct byte values). Nothing else can make a
value PLAIN:

  - PLAIN: validate_container proves the bytes (a stored length + CRC-32, or a gzip/zip whose sizer
    checks a payload checksum) and the payload is provable. A survey's answer is PLAIN only when exactly
    ONE distinct proven payload came out of every reading it made; two distinct proven payloads are
    ambiguous and both become candidates.
  - candidate: a structure-only file (png, jpeg, ... with no checksum), a length-prefixed or long
    printable start, a too-short checksum match, or a reading the reader itself flags as structurally
    strong (a phase-coded run, a rank-1 spread-spectrum fit) but that no container proves.
  - nothing: noise.

A Survey collects the verdicts of one reader over one carrier and renders the same dict shape the
existing readers return: {plain, method, channel, candidates, readings, notes}, plus judged (the
number of readings judged) and proven ({payload: [readings]}, every proven payload, so a caller that
merges surveys, as jpeg_stego.survey does, applies the one-payload rule over all of them).
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.append(str(HERE))

import stego_containers as sc      # noqa: E402
import jpeg_stego as js            # noqa: E402

MAX_CANDIDATES = 16
MIN_TEXT = 6                       # a printable reading shorter than this is not offered


def pack_bits(bits, msb_first=True) -> bytes:
    """Whole bytes from a 0/1 sequence (a list, bytes or a numpy array); a trailing partial byte is dropped."""
    arr = np.asarray(bits, dtype=np.uint8)
    n = (len(arr) // 8) * 8
    if not n:
        return b""
    return np.packbits(arr[:n] & 1, bitorder="big" if msb_first else "little").tobytes()


def printable_prefix(blob: bytes, minimum: int = MIN_TEXT):
    """The leading printable ASCII run of `blob` when it is at least `minimum` long and not one
    repeated character, else None."""
    run = bytearray()
    for b in blob:
        if 32 <= b < 127 or b in (9, 10, 13):
            run.append(b)
        else:
            break
    if len(run) >= minimum and len(set(run)) >= 3:
        return run.decode("ascii")
    return None


class Survey:
    """The verdicts of one reader over one carrier (see the module text)."""

    def __init__(self, channel: str, *, files_only: bool = False):
        """files_only: offer only complete file structures as candidates (no printable starts, no
        too-short checksum matches), for a reader with many readings over a carrier whose clean
        covers must give no candidate at all (jpeg_stego_f8 inside jpeg_stego.survey)."""
        self.channel = channel
        self.files_only = files_only
        self.plains: dict[bytes, list[str]] = {}
        self.candidates: list[tuple[str, object]] = []
        self.readings: list[str] = []
        self.notes: list[str] = []
        self.judged = 0

    def judge(self, blob: bytes, tag: str) -> str:
        """Judge one reading; returns 'plain', 'candidate' or 'none'."""
        self.judged += 1
        if not blob or len(blob) < 8:
            return "none"
        f = sc.validate_container(bytes(blob))
        if f.plain is not None and js._provable(f.plain):
            self.plains.setdefault(bytes(f.plain), []).append(f"{tag}; {f.method}")
            self.readings.append(f"PLAIN {tag}: {len(f.plain)} bytes ({f.method})")
            return "plain"
        if f.plain is not None:
            self.readings.append(f"degenerate {tag}: {len(f.plain)}-byte checksum match not trusted")
            if self.files_only:
                return "none"
            self.add_candidate(f"{tag} short_crc", bytes(f.plain))
            return "candidate"
        got = False
        for name, value in f.candidates or []:
            if self.files_only and name != "carved_file":
                continue
            if name == "decoded_text" and (not isinstance(value, str) or len(value) < MIN_TEXT):
                continue
            got = self.add_candidate(f"{tag} {name}", value) or got
        if got:
            self.readings.append(f"unsure {tag}: {[n for n, _ in f.candidates]}")
            return "candidate"
        return "none"

    def judge_bits(self, bits, tag: str) -> str:
        """Judge a bit stream packed both ways (MSB first, LSB first); the best verdict wins."""
        best = "none"
        for msb in (True, False):
            v = self.judge(pack_bits(bits, msb), f"{tag} {'msb' if msb else 'lsb'}-first")
            if v == "plain" or (v == "candidate" and best == "none"):
                best = v
        return best

    def add_candidate(self, name: str, value) -> bool:
        if value is None or (isinstance(value, (bytes, str)) and not value):
            return False
        key = value if isinstance(value, str) else bytes(value)
        if any(v == key for _, v in self.candidates):
            return False
        if len(self.candidates) >= MAX_CANDIDATES:
            return False
        self.candidates.append((name, key))
        return True

    def merge(self, other: "Survey"):
        for payload, methods in other.plains.items():
            self.plains.setdefault(payload, []).extend(methods)
        for name, value in other.candidates:
            self.add_candidate(name, value)
        self.readings += other.readings
        self.notes += other.notes
        self.judged += other.judged

    def result(self) -> dict:
        res = {"plain": None, "method": "", "channel": self.channel, "candidates": [],
               "readings": list(self.readings), "notes": list(self.notes), "judged": self.judged,
               "proven": {p: list(m) for p, m in self.plains.items()}}
        cands = list(self.candidates)
        if len(self.plains) == 1:
            payload, methods = next(iter(self.plains.items()))
            res["plain"], res["method"] = payload, methods[0]
        elif len(self.plains) > 1:
            res["notes"].append(f"ambiguous: {len(self.plains)} distinct proven payloads: none is plain")
            cands = [(f"proven_{i} ({m[0]})", p) for i, (p, m) in enumerate(self.plains.items())] + cands
        seen, out = set(), []
        for name, value in cands:
            if value in seen:
                continue
            seen.add(value)
            out.append((name, value))
        res["candidates"] = out[:MAX_CANDIDATES]
        return res


def jsonable(res: dict) -> dict:
    """A Survey result with its bytes as hex, for a CLI's JSON line."""
    out = dict(res)
    out["plain_hex"] = res["plain"].hex() if res["plain"] is not None else None
    out.pop("plain")
    out["candidates"] = [(n, v if isinstance(v, str) else bytes(v).hex()) for n, v in res["candidates"]]
    out["proven"] = {bytes(p).hex(): m for p, m in res.get("proven", {}).items()}
    return out


__all__ = ["Survey", "pack_bits", "printable_prefix", "jsonable", "MAX_CANDIDATES", "MIN_TEXT"]
