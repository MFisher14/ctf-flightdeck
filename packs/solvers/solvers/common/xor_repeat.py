#!/usr/bin/env python3
"""Crib-less repeating-key XOR cryptanalysis (the xortool archetype), offline.

Recovers the key and plaintext of data encrypted with a repeating multi-byte XOR key, with NO known
plaintext/crib — key length comes from the normalized Hamming distance between key-aligned blocks, and
each key byte from the single-byte XOR that maximizes an English/printability score of its column.
Distinct from `warmups/crib_decode.py` (XOR *with* a supplied crib) and from `common/classical.py`
(letter-alphabet Vigenère via IoC/Kasiski). Returns ranked `(key, plaintext, score)` candidates for a
human to read (`solvers/common/labels.py` style — no judge, nothing auto-submitted). Single-byte XOR
(key length 1) is handled as the natural special case.
"""
from __future__ import annotations

import argparse
import sys
from typing import Iterable

MAX_LEN = 1 << 22          # 4 MiB cap on input
MAX_KEYLEN = 64            # longest repeating key we search

# Relative frequency of printable English bytes (letters + space dominate); unlisted printable bytes
# get a small floor, non-printable bytes a penalty. Used only to SCORE candidates, never as a judge.
_FREQ = {ord(" "): 13.0, ord("e"): 12.7, ord("t"): 9.1, ord("a"): 8.2, ord("o"): 7.5, ord("i"): 7.0,
         ord("n"): 6.7, ord("s"): 6.3, ord("h"): 6.1, ord("r"): 6.0, ord("d"): 4.3, ord("l"): 4.0,
         ord("u"): 2.8, ord("c"): 2.8, ord("m"): 2.4, ord("w"): 2.4, ord("f"): 2.2, ord("g"): 2.0,
         ord("y"): 2.0, ord("p"): 1.9, ord("b"): 1.5, ord("v"): 1.0, ord("k"): 0.8, ord("j"): 0.15,
         ord("x"): 0.15, ord("q"): 0.1, ord("z"): 0.07}


def _as_bytes(data: object) -> bytes | None:
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    if isinstance(data, str):
        try:
            return data.encode("latin-1")
        except UnicodeEncodeError:
            return None
    return None


def _column_score(col: bytes) -> float:
    """Higher is more English-like. Letters/space by frequency; other printables small+; else penalty."""
    if not col:
        return -1e9
    score = 0.0
    for b in col:
        lower = b | 0x20  # fold case for letter scoring
        if lower in _FREQ and (65 <= b <= 90 or 97 <= b <= 122 or b == 32):
            score += _FREQ[lower]
        elif 32 <= b <= 126 or b in (9, 10, 13):
            score += 0.4
        else:
            score -= 6.0
    return score / len(col)


def _popcount(x: int) -> int:
    return bin(x).count("1")


def hamming(a: bytes, b: bytes) -> int:
    """Bitwise Hamming distance of two equal-length byte strings."""
    if len(a) != len(b):
        raise ValueError("hamming needs equal lengths")
    return sum(_popcount(x ^ y) for x, y in zip(a, b))


def key_length_candidates(data: bytes, *, max_keylen: int = MAX_KEYLEN, top: int = 6) -> list[int]:
    """Likely key lengths, best first, by the mean normalized Hamming distance between the first few
    key-aligned blocks. A true key length makes aligned blocks share the key, so their distance dips."""
    n = len(data)
    best: list[tuple[float, int]] = []
    hi = min(max_keylen, n // 4)
    for klen in range(1, hi + 1):
        blocks = [data[i:i + klen] for i in range(0, klen * 8, klen) if len(data[i:i + klen]) == klen]
        if len(blocks) < 2:
            continue
        pairs = 0
        total = 0.0
        for i in range(len(blocks)):
            for j in range(i + 1, len(blocks)):
                total += hamming(blocks[i], blocks[j]) / klen
                pairs += 1
        if pairs:
            best.append((total / pairs, klen))
    best.sort(key=lambda t: (t[0], t[1]))
    return [klen for _dist, klen in best[:top]]


def recover_with_keylen(data: bytes, keylen: int) -> tuple[bytes, bytes, float]:
    """Best `(key, plaintext, mean-column-score)` for a fixed key length via per-column single-byte XOR."""
    if keylen < 1:
        raise ValueError("keylen must be >= 1")
    key = bytearray(keylen)
    total = 0.0
    for pos in range(keylen):
        column = data[pos::keylen]
        best_b, best_s = 0, -1e18
        for guess in range(256):
            s = _column_score(bytes(c ^ guess for c in column))
            if s > best_s:
                best_s, best_b = s, guess
        key[pos] = best_b
        total += best_s
    plain = bytes(c ^ key[i % keylen] for i, c in enumerate(data))
    return bytes(key), plain, total / keylen


def solve(data: object, *, max_keylen: int = MAX_KEYLEN, top: int = 5) -> list[dict]:
    """Ranked repeating-key-XOR candidates: [{key, key_hex, plaintext, score, keylen}], best first.
    Empty list when the input is unusable. Never decides a single answer — you read the candidates."""
    raw = _as_bytes(data)
    if raw is None or len(raw) < 4 or len(raw) > MAX_LEN:
        return []
    out = []
    seen_keys = set()
    for klen in key_length_candidates(raw, max_keylen=max_keylen):
        key, plain, score = recover_with_keylen(raw, klen)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        out.append({"keylen": klen, "key": key, "key_hex": key.hex(), "plaintext": plain, "score": score})
    out.sort(key=lambda d: -d["score"])
    return out[:top]


def single_byte(data: object) -> list[dict]:
    """All 256 single-byte-XOR decodings ranked by English score (the classic keylen-1 case)."""
    raw = _as_bytes(data)
    if raw is None or not raw or len(raw) > MAX_LEN:
        return []
    scored = []
    for k in range(256):
        plain = bytes(c ^ k for c in raw)
        scored.append({"key": k, "plaintext": plain, "score": _column_score(plain)})
    scored.sort(key=lambda d: -d["score"])
    return scored[:5]


def _printable(b: bytes, limit: int = 120) -> str:
    return "".join(chr(c) if 32 <= c <= 126 else "." for c in b[:limit])


def main(argv: Iterable[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Crib-less repeating-key XOR cryptanalysis (offline, "
                                            "ranked candidates — never auto-submits).")
    p.add_argument("file", help="file of XOR-encrypted bytes")
    p.add_argument("--max-keylen", type=int, default=MAX_KEYLEN)
    p.add_argument("--single", action="store_true", help="only single-byte XOR (key length 1)")
    p.add_argument("--json", action="store_true")
    try:
        a = p.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        with open(a.file, "rb") as fh:
            data = fh.read(MAX_LEN + 1)
    except OSError as exc:
        print(f"xor_repeat: {exc}", file=sys.stderr)
        return 1
    if a.max_keylen < 1 or a.max_keylen > MAX_LEN:
        print("xor_repeat: invalid --max-keylen", file=sys.stderr)
        return 1
    results = single_byte(data) if a.single else solve(data, max_keylen=a.max_keylen)
    if a.json:
        import json
        print(json.dumps([{**{k: v for k, v in r.items() if k != "plaintext" and not isinstance(v, bytes)},
                           "plaintext": _printable(r["plaintext"], 200)} for r in results], indent=1))
    else:
        for r in results:
            if a.single:
                print(f"key=0x{r['key']:02x}  score={r['score']:.2f}  {_printable(r['plaintext'])}")
            else:
                print(f"keylen={r['keylen']}  key={r['key_hex']}  score={r['score']:.2f}  "
                      f"{_printable(r['plaintext'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
