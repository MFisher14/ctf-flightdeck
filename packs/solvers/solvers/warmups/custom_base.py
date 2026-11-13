#!/usr/bin/env python3
"""Decode base-N with a CUSTOM / scrambled alphabet, and recover that alphabet from a crib, offline.

A frequent misc/crypto trick: the challenge uses base64 (or base32/base85/base58) but with a SHUFFLED
alphabet, so a stock decoder gives garbage.  Given the custom alphabet you decode directly; given a
known plaintext/ciphertext pair you can RECOVER the alphabet permutation.  The fixed named variants
(crockford32, z-base-32, base58-flickr/ripple) live in `codec_decoders.py`; this handles an ARBITRARY
caller-supplied alphabet.  Offline, returns bytes / the recovered alphabet — never submits.
"""
from __future__ import annotations

import argparse
import base64
import sys
from typing import Iterable

STD_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
STD_B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


class BaseError(Exception):
    """Malformed alphabet or input — fail closed, never emit an unchecked value."""


def _bits_per(n: int) -> int | None:
    b = n.bit_length() - 1
    return b if (1 << b) == n and n >= 2 else None


def _check_alphabet(alphabet: str) -> str:
    if not isinstance(alphabet, str) or len(alphabet) < 2:
        raise BaseError("alphabet must be a str of length >= 2")
    if len(set(alphabet)) != len(alphabet):
        raise BaseError("alphabet has duplicate symbols")
    return alphabet


def decode(text: object, alphabet: str, *, pad: str = "=") -> bytes | None:
    """Decode `text` using `alphabet` (base = len(alphabet)). Power-of-two sizes use bit-packing
    (base16/32/64); other sizes use big-integer decoding (base58/base85...). None on a bad symbol."""
    _check_alphabet(alphabet)
    if isinstance(text, bytes):
        try:
            text = text.decode("ascii")
        except UnicodeDecodeError:
            return None
    if not isinstance(text, str):
        return None
    s = text.strip().rstrip(pad)
    if not s:
        return b""
    n = len(alphabet)
    idx = {c: i for i, c in enumerate(alphabet)}
    bits = _bits_per(n)
    if bits is not None:
        acc = nbits = 0
        out = bytearray()
        for ch in s:
            v = idx.get(ch)
            if v is None:
                return None
            acc = (acc << bits) | v
            nbits += bits
            while nbits >= 8:
                nbits -= 8
                out.append((acc >> nbits) & 0xFF)
        return bytes(out)
    # non-power-of-two: big-integer (base58/base85 style), with leading-symbol zero handling
    num = 0
    for ch in s:
        v = idx.get(ch)
        if v is None:
            return None
        num = num * n + v
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad0 = len(s) - len(s.lstrip(alphabet[0]))
    return b"\x00" * pad0 + body


def encode(data: bytes, alphabet: str) -> str:
    """Encode `data` with `alphabet` (inverse of decode; power-of-two alphabets only). For tests/forging."""
    _check_alphabet(alphabet)
    bits = _bits_per(len(alphabet))
    if bits is None:
        raise BaseError("encode supports only power-of-two alphabets")
    acc = nbits = 0
    out = []
    for b in data:
        acc = (acc << 8) | b
        nbits += 8
        while nbits >= bits:
            nbits -= bits
            out.append(alphabet[(acc >> nbits) & ((1 << bits) - 1)])
    if nbits:
        out.append(alphabet[(acc << (bits - nbits)) & ((1 << bits) - 1)])
    return "".join(out)


def recover_alphabet(known_plaintext: bytes, custom_ciphertext: str, *, base: int = 64) -> dict:
    """Recover the custom alphabet from a known plaintext and its custom-encoded ciphertext.

    Returns {alphabet: str-with-'?'-for-gaps, known: int, complete: bool}. Works by encoding the known
    plaintext with the STANDARD alphabet and mapping, position by position, each standard symbol's value
    to the custom symbol that appears there."""
    if base == 64:
        std = STD_B64
        std_ct = base64.b64encode(known_plaintext).decode().rstrip("=")
    elif base == 32:
        std = STD_B32
        std_ct = base64.b32encode(known_plaintext).decode().rstrip("=")
    else:
        raise BaseError("recover_alphabet supports base 32 or 64")
    if len(std_ct) > len(custom_ciphertext):
        raise BaseError("custom ciphertext is shorter than the known plaintext encodes to")
    table = [None] * base
    for sc, cc in zip(std_ct, custom_ciphertext):
        val = std.index(sc)
        if table[val] is not None and table[val] != cc:
            raise BaseError("inconsistent alphabet mapping (wrong plaintext/ciphertext pair?)")
        table[val] = cc
    known = sum(1 for t in table if t is not None)
    alphabet = "".join(t if t is not None else "?" for t in table)
    return {"alphabet": alphabet, "known": known, "complete": known == base}


def main(argv: Iterable[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Decode base-N with a custom/scrambled alphabet, or recover "
                                            "the alphabet from a crib (offline).")
    sub = p.add_subparsers(dest="mode", required=True)
    d = sub.add_parser("decode", help="decode TEXT with ALPHABET")
    d.add_argument("text"); d.add_argument("alphabet")
    r = sub.add_parser("recover", help="recover the alphabet from a known plaintext + its ciphertext")
    r.add_argument("plaintext"); r.add_argument("ciphertext"); r.add_argument("--base", type=int, default=64)
    try:
        a = p.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        if a.mode == "decode":
            out = decode(a.text, a.alphabet)
            if out is None:
                print("custom_base: input has a symbol outside the alphabet", file=sys.stderr)
                return 1
            sys.stdout.buffer.write(out + b"\n")
        else:
            res = recover_alphabet(a.plaintext.encode("latin-1"), a.ciphertext, base=a.base)
            print(f"alphabet: {res['alphabet']}")
            print(f"known {res['known']}/{a.base}  complete={res['complete']}")
    except BaseError as exc:
        print(f"custom_base: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
