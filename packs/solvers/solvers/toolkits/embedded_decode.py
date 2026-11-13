#!/usr/bin/env python3
"""Find and decode encoded blobs embedded inside mixed text, offline.

A common misc/forensics/web move: a flag (or key/url) is base64/base32/hex/base58-encoded and sits
INSIDE a larger file — an HTML comment, a JSON value, a log line, source code, a cookie.  A whole-blob
auto-decoder (`warmups/layered_decode.py`) assumes the ENTIRE input is one chain; this instead SCANS
mixed text for encoded substrings, decodes each, and reports the ones that yield printable / flag-shaped
content.  Offline, read-only, ranked candidates — never submits.
"""
from __future__ import annotations

import argparse
import base64
import binascii
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

MAX_INPUT = 1 << 22
_FLAG = flagfmt.BYTES

# (name, compiled regex over text, decoder) — thresholds keep random runs from matching.
_PATTERNS = [
    ("base64", re.compile(r"[A-Za-z0-9+/]{20,}={0,2}"), lambda s: base64.b64decode(_pad64(s), validate=True)),
    ("base64url", re.compile(r"[A-Za-z0-9_-]{20,}={0,2}"),
     lambda s: base64.urlsafe_b64decode(_pad64(s.replace("=", "")))),
    ("base32", re.compile(r"[A-Z2-7]{16,}={0,6}"), lambda s: base64.b32decode(s + "=" * ((-len(s)) % 8))),
    ("hex", re.compile(r"\b(?:[0-9a-fA-F]{2}){8,}\b"), lambda s: bytes.fromhex(s)),
    # (base58 is deliberately NOT scanned here — in mixed text it is indistinguishable from base62 /
    # long words and produces too many false positives; base58 addresses are handled by blockchain.py.)
]


def _pad64(s: str) -> str:
    s = s.rstrip("=")
    return s + "=" * ((-len(s)) % 4)


def _printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    return sum(1 for c in b if 32 <= c <= 126 or c in (9, 10, 13)) / len(b)


def _misaligned_b64(text: str):
    """(encoding, offset, token, decoder) for the three other alignments of every base64 run: a run glued
    to letters before it ("ab" + base64) decodes only from its true start, 1-3 characters in."""
    for m in _PATTERNS[0][1].finditer(text):
        run = m.group(0).rstrip("=")
        for k in (1, 2, 3):
            part = run[k:]
            if len(part) % 4 == 1:
                part = part[:-1]                 # one char past a whole group: no byte in it
            if len(part) < 16:
                continue
            yield f"base64+{k}", m.start() + k, part, lambda s: base64.b64decode(_pad64(s), validate=True)


def find_blobs(data: object, *, min_printable: float = 0.85, max_results: int = 100,
               flag_re=None, alignments: bool = False) -> list[dict]:
    """Ranked [{encoding, offset, match, decoded, printable_ratio, flag}] encoded substrings that decode
    to mostly-printable or flag-shaped content. Flag-shaped hits rank first, then by printability+length.

    flag_re: the bytes pattern that makes a decode "flag-shaped" (default: the active event's,
    ctf.flagfmt.BYTES, which needs CTF_EVENT or a single profile); a caller holding a profile passes
    flagfmt.for_profile(p).bregex so no active event is consulted. alignments: also decode every base64
    run from its 2nd, 3rd and 4th character (encoding "base64+1".."base64+3")."""
    flag_rx = _FLAG if flag_re is None else flag_re
    if isinstance(data, bytes):
        try:
            text = data.decode("latin-1")
        except Exception:
            return []
    elif isinstance(data, str):
        text = data
    else:
        return []
    if not text or len(text) > MAX_INPUT:
        return []
    out = []
    seen = set()

    def candidates():
        for name, rx, dec in _PATTERNS:
            for m in rx.finditer(text):
                token = m.group(0)
                if name == "hex" and len(token) % 2:
                    token = token[:-1]
                yield name, m.start(), token, dec
        if alignments:
            yield from _misaligned_b64(text)

    for name, start, token, dec in candidates():
        try:
            decoded = dec(token)
        except (ValueError, binascii.Error):
            continue
        if not decoded:
            continue
        pr = _printable_ratio(decoded)
        flag = bool(flag_rx.search(decoded))
        if not flag and pr < min_printable:
            continue
        key = (name, start, bytes(decoded))
        if key in seen:
            continue
        seen.add(key)
        out.append({"encoding": name, "offset": start, "match": token,
                    "decoded": decoded, "printable_ratio": round(pr, 3), "flag": flag})
    out.sort(key=lambda d: (0 if d["flag"] else 1, -d["printable_ratio"], -len(d["decoded"])))
    return out[:max_results]


def flags_in(data: object) -> list[bytes]:
    """Just the flag-shaped strings decoded from embedded blobs."""
    res = []
    for d in find_blobs(data, min_printable=0.0):
        for m in _FLAG.finditer(d["decoded"]):
            res.append(m.group(0))
    # dedupe preserving order
    seen, out = set(), []
    for f in res:
        if f not in seen:
            seen.add(f); out.append(f)
    return out


def _show(b: bytes, limit: int = 160) -> str:
    return "".join(chr(c) if 32 <= c <= 126 else "." for c in b[:limit])


def main(argv: Iterable[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Find and decode base64/base32/hex/base58 blobs embedded in "
                                            "mixed text (offline; ranked candidates).")
    p.add_argument("file")
    p.add_argument("--flags-only", action="store_true")
    p.add_argument("--json", action="store_true")
    try:
        a = p.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        with open(a.file, "rb") as fh:
            data = fh.read(MAX_INPUT + 1)
    except OSError as exc:
        print(f"embedded_decode: {exc}", file=sys.stderr)
        return 1
    if a.flags_only:
        flags = flags_in(data)
        if a.json:
            import json
            print(json.dumps([f.decode("latin-1") for f in flags], indent=1))
        else:
            for f in flags:
                print(f.decode("latin-1"))
        return 0
    results = find_blobs(data)
    if a.json:
        import json
        print(json.dumps([{"encoding": r["encoding"], "offset": r["offset"], "flag": r["flag"],
                           "printable_ratio": r["printable_ratio"], "decoded": _show(r["decoded"], 400)}
                          for r in results], indent=1))
    else:
        for r in results[:50]:
            tag = " FLAG" if r["flag"] else ""
            print(f"[{r['encoding']:9} off={r['offset']:#x} pr={r['printable_ratio']}{tag}] {_show(r['decoded'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
