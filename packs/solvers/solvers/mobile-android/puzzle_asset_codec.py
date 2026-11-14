#!/usr/bin/env python3
"""Recover the answer code that a Huntress mobile fixture APK carries in assets/huntress_puzzle.json.

Usage:
  python3 solvers/mobile-android/puzzle_asset_codec.py <file.apk> [...]

The APK's dex points at a loopback backend that only exists inside Homebase, but
the same answer code ships in the APK as a small puzzle document:

  {"schema": "huntress.mobile.puzzle.v1", "day": N, "codec": "<name>", "data": "<text>", ...params}

The solver applies the named codec (base64, xor with "key", hex, rot13, reverse,
and chains of them). If the codec name or its parameters are new, it falls back
to a bounded search over the same reversible transforms. Either way a result
only counts when it is exactly ANS- plus 16 uppercase hex characters, so nothing
is guessed and nothing about a particular APK is hardcoded.
"""
import base64
import binascii
import codecs
import io
import json
import re
import sys
import zipfile
from collections import deque

ANSWER = re.compile(r"ANS-[0-9A-F]{16}")
PUZZLE = "assets/huntress_puzzle.json"


def _b(v):
    return v if isinstance(v, bytes) else str(v).encode("utf-8", "surrogatepass")


def t_base64(d, p):
    t = re.sub(rb"\s+", b"", _b(d))
    if not t or not re.fullmatch(rb"[A-Za-z0-9+/_-]+={0,2}", t):
        return None
    t = t.rstrip(b"=").replace(b"-", b"+").replace(b"_", b"/")
    if len(t) % 4 == 1:
        return None
    try:
        return base64.b64decode(t + b"=" * (-len(t) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None


def t_base32(d, p):
    t = re.sub(rb"\s+", b"", _b(d)).upper().rstrip(b"=")
    if not t or not re.fullmatch(rb"[A-Z2-7]+", t):
        return None
    try:
        return base64.b32decode(t + b"=" * (-len(t) % 8))
    except (binascii.Error, ValueError):
        return None


def t_hex(d, p):
    t = re.sub(rb"0x|\\x|[\s:,]", b"", _b(d))
    if not t or len(t) % 2 or not re.fullmatch(rb"[0-9a-fA-F]+", t):
        return None
    return bytes.fromhex(t.decode())


def t_rot13(d, p):
    try:
        return codecs.decode(_b(d).decode("ascii"), "rot13").encode()
    except UnicodeDecodeError:
        return None


def t_reverse(d, p):
    return _b(d)[::-1]


def _keys(p):
    """Every byte string the puzzle's parameters could mean as a key."""
    out = []
    for name, v in p.items():
        if name in ("schema", "day", "codec", "data"):
            continue
        vals = v if isinstance(v, list) and all(isinstance(x, int) for x in v) else None
        if vals is not None:
            if vals and all(0 <= x < 256 for x in vals):
                out.append(bytes(vals))
            continue
        if isinstance(v, bool):
            continue
        if isinstance(v, int):
            if 0 <= v < 256:
                out.append(bytes([v]))
            if v >= 256:
                out.append(v.to_bytes((v.bit_length() + 7) // 8, "big"))
            continue
        if isinstance(v, str) and v:
            out.append(v.encode())
            for dec in (t_hex, t_base64):
                k = dec(v, {})
                if k:
                    out.append(k)
            if re.fullmatch(r"\d{1,3}", v) and int(v) < 256:
                out.append(bytes([int(v)]))
    seen, uniq = set(), []
    for k in out:
        if k and k not in seen:
            seen.add(k)
            uniq.append(k)
    return uniq


def _xor(data, key):
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(data))


def _shift(data, n):
    return bytes((c + n) % 256 for c in data)


def _caesar(data, n):
    return bytes((c - 65 + n) % 26 + 65 if 65 <= c <= 90 else (c - 97 + n) % 26 + 97 if 97 <= c <= 122 else c
                 for c in data)


def _text_layers(d):
    """The data as bytes, plus what it is underneath a text encoding."""
    raw = _b(d)
    outs = [raw]
    for dec in (t_base64, t_hex, t_base32):
        o = dec(raw, {})
        if o:
            outs.append(o)
    return outs


def t_xor(d, p):
    # Returned as a list: the key may apply to the raw text or to its base64/hex payload.
    return [_xor(x, k) for x in _text_layers(d) for k in _keys(p)]


NAMED = {
    "base64": t_base64, "b64": t_base64, "base64url": t_base64, "base32": t_base32, "b32": t_base32,
    "hex": t_hex, "base16": t_hex, "b16": t_hex, "rot13": t_rot13, "rot-13": t_rot13,
    "reverse": t_reverse, "reversed": t_reverse, "rev": t_reverse, "xor": t_xor,
    "plain": lambda d, p: _b(d), "none": lambda d, p: _b(d), "identity": lambda d, p: _b(d),
}


def answer_in(b):
    """The answer code if b is exactly one (surrounding whitespace allowed)."""
    try:
        t = _b(b).decode("ascii").strip()
    except UnicodeDecodeError:
        return None
    return t if ANSWER.fullmatch(t) else None


def by_codec(p):
    """Apply the codec the puzzle names. A list or a + | , > separated string is a chain."""
    codec = p.get("codec")
    steps = codec if isinstance(codec, list) else [c for c in re.split(r"\s*(?:\+|\||,|>|->|then)\s*", str(codec or "")) if c]
    for order in (steps, steps[::-1]):  # a chain may list encode order or decode order
        states = [_b(p.get("data", ""))]
        for name in order:
            fn = NAMED.get(str(name).strip().lower())
            if fn is None:
                states = []
                break
            nxt = []
            for st in states:
                o = fn(st, p)
                nxt.extend(o if isinstance(o, list) else [o] if o is not None else [])
            # a named codec may sit on top of a text encoding of its output or input
            states = nxt + [y for st in nxt for y in _text_layers(st)[1:]]
        for st in states:
            a = answer_in(st)
            if a:
                return a
    return None


def by_search(p, max_depth=4, max_nodes=6000):
    """Bounded breadth-first search over the reversible transforms, for an unfamiliar codec."""
    keys = _keys(p)
    moves = [lambda d: t_base64(d, p), lambda d: t_hex(d, p), lambda d: t_base32(d, p), lambda d: t_rot13(d, p),
             lambda d: t_reverse(d, p)]
    moves += [lambda d, k=k: _xor(d, k) for k in keys]
    moves += [lambda d, k=k: _shift(d, -k[0]) for k in keys if len(k) == 1]
    moves += [lambda d, k=k: _shift(d, k[0]) for k in keys if len(k) == 1]
    moves += [lambda d, k=k: _caesar(d, -k[0]) for k in keys if len(k) == 1]
    moves += [lambda d, k=k: _caesar(d, k[0]) for k in keys if len(k) == 1]
    start = _b(p.get("data", ""))
    seen, queue, nodes = {start}, deque([(start, 0)]), 0
    while queue and nodes < max_nodes:
        cur, depth = queue.popleft()
        nodes += 1
        a = answer_in(cur)
        if a:
            return a
        if depth >= max_depth:
            continue
        for mv in moves:
            try:
                out = mv(cur)
            except Exception:
                out = None
            if out and out not in seen:
                seen.add(out)
                queue.append((out, depth + 1))
    # last resort: a single-byte XOR whose key the document did not carry
    for layer in _text_layers(start):
        hits = {a for a in (answer_in(_xor(layer, bytes([k]))) for k in range(256)) if a}
        if len(hits) == 1:
            return hits.pop()
    return None


def solve_puzzle(doc: bytes):
    p = json.loads(doc.decode("utf-8-sig"))
    if not isinstance(p, dict):
        return None
    return by_codec(p) or by_search(p)


def solve_apk(apk: bytes):
    with zipfile.ZipFile(io.BytesIO(apk)) as zf:
        names = zf.namelist()
        picks = [n for n in names if n == PUZZLE] or [n for n in names if n.startswith("assets/") and n.endswith(".json")]
        for n in picks:
            try:
                a = solve_puzzle(zf.read(n))
            except (ValueError, KeyError):
                a = None
            if a:
                return a
    return None


def solve_set(questions, files, ctx):
    a = None
    if PUZZLE in files:
        try:
            a = solve_puzzle(files[PUZZLE])
        except ValueError:
            a = None
    if a is None and ctx.get("delivery"):
        a = solve_apk(ctx["delivery"])
    return {q["qid"]: a for q in questions}


def main(argv) -> int:
    if argv and argv[0] in ("-h", "--help"):
        print("usage: puzzle_asset_codec.py <file.apk> [...]")
        return 0
    if not argv:
        print("puzzle_asset_codec.py: expected at least one APK", file=sys.stderr)
        return 2
    try:
        for path in argv:
            with open(path, "rb") as fh:
                print(f"{path}: {solve_apk(fh.read())}")
    except Exception as exc:
        print(f"puzzle_asset_codec.py: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
