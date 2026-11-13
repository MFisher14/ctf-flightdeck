#!/usr/bin/env python3
"""Find single-byte-XOR-encoded ASCII strings hidden in a binary, offline.

A very common RE/forensics move: the flag (or a URL, key, or command) is stored in a binary XORed with
a one-byte key so a plain `strings` run misses it.  This scans every key 1..255 and reports the runs
that become printable ASCII — the FLOSS-"decoded strings" idea, pure-Python.  Distinct from
`xor_repeat.py` (which recovers ONE whole message under a repeating key) and from `malconfig.py` (which
decodes KNOWN malware-config formats).  Read-only, offline, ranked candidates — it never runs the
binary or submits anything.
"""
from __future__ import annotations

import argparse
import re
import sys
from typing import Iterable

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

MAX_INPUT = 1 << 24          # 16 MiB
_PRINTABLE = set(range(32, 127)) | {9}   # tab; strings are usually one line


def _translation(key: int) -> bytes:
    # byte b -> (b ^ key) if that is printable ASCII, else 0 (a run separator).
    return bytes((b ^ key) if (b ^ key) in _PRINTABLE else 0 for b in range(256))


def xor_strings(data: object, *, min_len: int = 5, keys: Iterable[int] | None = None,
                max_results: int = 200) -> list[dict]:
    """Ranked [{key, offset, text}] of single-byte-XOR runs that decode to printable ASCII >= min_len.

    `key=0` (plain strings) is skipped unless explicitly requested. Best-first by length then a small
    bonus for a flag-shaped run."""
    raw = data if isinstance(data, (bytes, bytearray)) else None
    if raw is None or not raw or len(raw) > MAX_INPUT or min_len < 3:
        return []
    raw = bytes(raw)
    key_range = list(keys) if keys is not None else range(1, 256)
    out = []
    seen = set()
    for key in key_range:
        if not 0 <= key <= 255:
            continue
        decoded = raw.translate(_translation(key))
        off = 0
        for chunk in decoded.split(b"\x00"):
            if len(chunk) >= min_len:
                text = chunk.decode("ascii")
                sig = (key, text)
                if sig not in seen:
                    seen.add(sig)
                    out.append({"key": key, "offset": off, "text": text})
            off += len(chunk) + 1
    flag = flagfmt.PACKED_TEXT       # runs carved from binary: no word boundary before a flag (R-16)

    def rank(d):
        return (-len(d["text"]), 0 if flag.search(d["text"]) else 1, d["key"])
    # push flag-shaped hits to the very top regardless of length.
    out.sort(key=lambda d: (0 if flag.search(d["text"]) else 1, -len(d["text"]), d["key"]))
    return out[:max_results]


def flag_candidates(data: object, pattern: str | None = None) -> list[dict]:
    """Only the XOR-decoded runs that hold a flag: the event's format (ctf.flagfmt), or `pattern` when a
    challenge states its own answer shape."""
    rx = re.compile(pattern) if pattern else flagfmt.PACKED_TEXT   # binary-carved runs (R-16)
    return [d for d in xor_strings(data, min_len=4) if rx.search(d["text"])]


# ---- stack strings (B-074) --------------------------------------------------------------------------
# A "stack string" is built character by character at runtime (mov byte ptr [rbp-x], 'C'; ... 'S'; ...),
# so a plain `strings` pass misses it: the bytes sit at a fixed stride among the instruction bytes that
# move them. We read every stride 1..max_stride and every phase, and keep a printable run only when at
# least one byte skipped between its characters is NON-printable -- i.e. a run `strings` would not
# already show at stride 1. Pure-python, offline; it never runs or disassembles the binary.


def stack_strings(data: object, *, min_len: int = 5, max_stride: int = 4,
                  max_results: int = 200) -> list[dict]:
    """Ranked [{stride, offset, text}] of printable runs read at a fixed byte stride (interleaved
    stack strings). stride==1 is the plain-strings case and is reported only when `max_stride` is 1;
    for stride>1 a run is kept only if a skipped inter-character byte is non-printable, so the result
    is what a plain `strings` run would miss. Best-first by length, then a flag-shaped bonus."""
    raw = data if isinstance(data, (bytes, bytearray)) else None
    if raw is None or not raw or len(raw) > MAX_INPUT or min_len < 3 or max_stride < 1:
        return []
    raw = bytes(raw)
    out, seen = [], set()
    strides = range(1, max_stride + 1) if max_stride > 1 else (1,)
    for stride in strides:
        for phase in range(stride):
            idx = list(range(phase, len(raw), stride))
            run_start = 0
            chars = bytearray()
            for pos, i in enumerate(idx):
                b = raw[i]
                if 0x20 <= b < 0x7f:
                    if not chars:
                        run_start = pos
                    chars.append(b)
                else:
                    _emit_stack_run(raw, idx, run_start, chars, stride, phase, min_len, out, seen)
                    chars = bytearray()
            _emit_stack_run(raw, idx, run_start, chars, stride, phase, min_len, out, seen)
    flag = flagfmt.PACKED_TEXT
    out.sort(key=lambda d: (0 if flag.search(d["text"]) else 1, -len(d["text"]), d["stride"], d["offset"]))
    return out[:max_results]


def _emit_stack_run(raw, idx, run_start, chars, stride, phase, min_len, out, seen):
    if len(chars) < min_len:
        return
    if stride > 1:
        # require at least one NON-printable byte skipped between the run's characters (else a plain
        # strings pass at stride 1 already shows it, and this is not a hidden stack string)
        hidden = False
        for pos in range(run_start, run_start + len(chars) - 1):
            gap_lo = idx[pos] + 1
            gap_hi = idx[pos + 1]
            if any(not (0x20 <= raw[g] < 0x7f) for g in range(gap_lo, gap_hi)):
                hidden = True
                break
        if not hidden:
            return
    text = chars.decode("ascii")
    off = idx[run_start]
    sig = (stride, text)
    if sig not in seen:
        seen.add(sig)
        out.append({"stride": stride, "offset": off, "text": text})


def stack_flag_candidates(data: object, pattern: str | None = None, *, max_stride: int = 4) -> list[dict]:
    """Only the stack-string runs that hold a flag: the event's format, or `pattern` when a challenge
    states its own answer shape (B-074: xor_strings + stack-string collection with a flag crib)."""
    rx = re.compile(pattern) if pattern else flagfmt.PACKED_TEXT
    return [d for d in stack_strings(data, min_len=4, max_stride=max_stride) if rx.search(d["text"])]


def main(argv: Iterable[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Find single-byte-XOR-encoded ASCII strings in a binary "
                                            "(offline, read-only; ranked candidates).")
    p.add_argument("file")
    p.add_argument("--min-len", type=int, default=5)
    p.add_argument("--flags-only", action="store_true", help="only runs holding a flag in the event format")
    p.add_argument("--crib", default=None, help="a flag pattern to match instead of the event format")
    p.add_argument("--key", type=lambda x: int(x, 0), default=None, help="only this XOR key")
    p.add_argument("--stack", action="store_true", help="collect interleaved stack strings, not XOR runs")
    p.add_argument("--max-stride", type=int, default=4, help="largest stride for --stack")
    p.add_argument("--json", action="store_true")
    try:
        a = p.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        with open(a.file, "rb") as fh:
            data = fh.read(MAX_INPUT + 1)
    except OSError as exc:
        print(f"xor_strings: {exc}", file=sys.stderr)
        return 1
    if a.stack:
        if a.flags_only or a.crib:
            results = stack_flag_candidates(data, a.crib, max_stride=a.max_stride)
        else:
            results = stack_strings(data, min_len=max(3, a.min_len), max_stride=a.max_stride)
    elif a.flags_only or a.crib:
        results = flag_candidates(data, a.crib)
    else:
        results = xor_strings(data, min_len=max(3, a.min_len),
                              keys=[a.key] if a.key is not None else None)
    if a.json:
        import json
        print(json.dumps(results, indent=1))
    else:
        for r in results[:60]:
            if "stride" in r:
                print(f"stride={r['stride']}  off={r['offset']:#x}  {r['text']}")
            else:
                print(f"key=0x{r['key']:02x}  off={r['offset']:#x}  {r['text']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
