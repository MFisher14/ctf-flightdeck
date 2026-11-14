#!/usr/bin/env python3
"""Keystream-reuse (two-time / many-time pad) recovery, offline.

When a stream cipher / one-time pad reuses the SAME keystream for different messages, the XOR of two
ciphertexts equals the XOR of their plaintexts (the key cancels).  Two tools:

* `crib_drag(c1, c2, crib)` — slide a guessed word across `c1 ^ c2`; at each offset it reveals what the
  OTHER message would read if the crib sat there, ranked by printability.  This is the interactive
  "I think 'the flag is' appears somewhere" attack, distinct from `stream_recovery.py` (which needs a
  FULL known plaintext for one message).
* `many_time_pad(ciphertexts)` — given several ciphertexts under one keystream, recover the keystream
  (and therefore every plaintext) with the classic "a space XORed with a letter stays a letter"
  heuristic, per column.

Everything is offline and returns ranked candidates for a human to read (`labels.py` style — no judge,
nothing auto-submitted).
"""
from __future__ import annotations

import argparse
import sys
from typing import Iterable, Sequence

MAX_LEN = 1 << 20
MAX_MSGS = 256


def _as_bytes(v: object) -> bytes | None:
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    if isinstance(v, str):
        try:
            return bytes.fromhex(v.strip()) if all(c in "0123456789abcdefABCDEF \n" for c in v) and v.strip() else v.encode("latin-1")
        except ValueError:
            return v.encode("latin-1")
    return None


def xor(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings up to the shorter length."""
    return bytes(x ^ y for x, y in zip(a, b))


def _printable_score(b: bytes) -> float:
    if not b:
        return -1e9
    good = sum(1 for c in b if 32 <= c <= 126 or c in (9, 10, 13))
    letters = sum(1 for c in b if 65 <= c <= 90 or 97 <= c <= 122 or c == 32)
    return (good / len(b)) + 0.5 * (letters / len(b))


def crib_drag(c1: object, c2: object, crib: object, *, top: int = 10) -> list[dict]:
    """Slide `crib` across `c1 ^ c2`; return ranked {offset, revealed, score} where `revealed` is what
    the other message reads at that offset if the crib is present there. Best-first by printability."""
    a, b, cr = _as_bytes(c1), _as_bytes(c2), _as_bytes(crib)
    if a is None or b is None or cr is None or not cr:
        return []
    if max(len(a), len(b)) > MAX_LEN:
        return []
    diff = xor(a, b)  # = p1 ^ p2
    if len(cr) > len(diff):
        return []
    out = []
    for off in range(0, len(diff) - len(cr) + 1):
        revealed = bytes(d ^ k for d, k in zip(diff[off:off + len(cr)], cr))
        out.append({"offset": off, "revealed": revealed, "score": _printable_score(revealed)})
    out.sort(key=lambda d: -d["score"])
    return out[:top]


def many_time_pad(ciphertexts: Sequence[object]) -> dict:
    """Recover the shared keystream (and plaintexts) from several same-keystream ciphertexts.

    Per column, assume each ciphertext in turn holds a SPACE there; that fixes a candidate key byte
    (c^0x20); apply it to the others and count how many become ASCII letters. The assumption with the
    most letter hits wins the column. Returns {keystream, plaintexts, confidence} (best-effort — low
    confidence where few ciphertexts overlap a column)."""
    msgs = []
    for c in ciphertexts:
        bb = _as_bytes(c)
        if bb is None:
            return {"keystream": b"", "plaintexts": [], "confidence": []}
        msgs.append(bb)
    if not (2 <= len(msgs) <= MAX_MSGS):
        return {"keystream": b"", "plaintexts": [], "confidence": []}
    width = max(len(m) for m in msgs)
    if width > MAX_LEN:
        return {"keystream": b"", "plaintexts": [], "confidence": []}
    key = bytearray(width)
    conf = [0.0] * width
    for pos in range(width):
        present = [m[pos] for m in msgs if pos < len(m)]
        if len(present) < 2:
            key[pos] = present[0] ^ 0x20 if present else 0
            conf[pos] = 0.0
            continue
        best_key, best_hits = 0, -1
        for assume_space in present:
            cand_key = assume_space ^ 0x20
            hits = sum(1 for c in present if 65 <= (c ^ cand_key) <= 90 or 97 <= (c ^ cand_key) <= 122
                       or (c ^ cand_key) == 32)
            if hits > best_hits:
                best_hits, best_key = hits, cand_key
        key[pos] = best_key
        conf[pos] = best_hits / len(present)
    plaintexts = [bytes(m[i] ^ key[i] for i in range(len(m))) for m in msgs]
    return {"keystream": bytes(key), "plaintexts": plaintexts, "confidence": conf}


def _show(b: bytes, limit: int = 120) -> str:
    return "".join(chr(c) if 32 <= c <= 126 else "." for c in b[:limit])


def main(argv: Iterable[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Keystream-reuse recovery: crib-drag two ciphertexts, or "
                                            "break a many-time pad (offline; ranked candidates).")
    sub = p.add_subparsers(dest="mode", required=True)
    d = sub.add_parser("drag", help="crib-drag c1 ^ c2")
    d.add_argument("c1"); d.add_argument("c2"); d.add_argument("crib")
    m = sub.add_parser("mtp", help="many-time pad: files of same-keystream ciphertexts")
    m.add_argument("files", nargs="+")
    p.add_argument("--hex", action="store_true", help="inputs are hex (drag mode)")
    try:
        a = p.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    if a.mode == "drag":
        c1 = bytes.fromhex(a.c1) if a.hex else a.c1.encode("latin-1")
        c2 = bytes.fromhex(a.c2) if a.hex else a.c2.encode("latin-1")
        for r in crib_drag(c1, c2, a.crib.encode("latin-1")):
            print(f"offset={r['offset']:4d}  score={r['score']:.2f}  other-reads: {_show(r['revealed'])}")
        return 0
    cts = []
    for f in a.files:
        try:
            with open(f, "rb") as fh:
                cts.append(fh.read(MAX_LEN + 1))
        except OSError as exc:
            print(f"crib_drag: {exc}", file=sys.stderr)
            return 1
    res = many_time_pad(cts)
    if not res["plaintexts"]:
        print("crib_drag: need 2+ same-length-ish ciphertexts", file=sys.stderr)
        return 1
    for i, pt in enumerate(res["plaintexts"]):
        print(f"msg[{i}]: {_show(pt, 200)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
