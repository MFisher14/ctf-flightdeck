#!/usr/bin/env python3
"""Bounded, callback-only cryptographic oracle attacks.

This module deliberately contains no transport code.  Every attack accepts a caller supplied
``check(ciphertext) -> bool`` callback; deciding how an assigned CTF target is contacted remains in
the scope-locked client.  The helpers here only perform the cryptographic state machine around that
callback and enforce a finite query budget.

Implemented attacks:

* CBC PKCS#7 padding-oracle plaintext recovery and chosen-plaintext ciphertext construction;
* RSA LSB/parity-oracle interval recovery;
* Bleichenbacher's adaptive PKCS#1 v1.5 attack; and
* Manger's leading-zero/OAEP attack, plus strict OAEP decoding.

RSA callbacks receive a fixed-width big-endian ciphertext by default.  Pass
``oracle_input="int"`` for a local integer callback.  CBC callbacks always receive bytes containing
``IV || ciphertext`` (or the shortest prefix ending at the block currently under attack).

No challenge data is evaluated or executed, no network API is imported, and all input sizes and
oracle calls are bounded.  A recovered RSA integer is returned only after public-key re-encryption
reproduces the supplied ciphertext.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys
from dataclasses import dataclass
from fractions import Fraction
from typing import Callable, Literal


MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_RSA_BITS = 16_384
MAX_QUERIES = 10_000_000


class OracleError(RuntimeError):
    """Base class for a malformed, exhausted, or inconsistent oracle."""


class OracleLimitError(OracleError):
    """The explicit query budget was exhausted."""


class OracleProtocolError(OracleError):
    """The callback did not return a boolean (or the integer 0/1)."""


@dataclass
class OracleBudget:
    """A finite-query wrapper shared by the attacks.

    ``calls`` is intentionally public so a solver can record the cost in its notes.  The wrapper
    does not catch callback exceptions: a transport or local-oracle failure is evidence the caller
    must handle, not something an attack should reinterpret as a negative answer.
    """

    check: Callable[[object], bool]
    limit: int
    calls: int = 0

    def __post_init__(self) -> None:
        if not callable(self.check):
            raise TypeError("oracle check must be callable")
        if not isinstance(self.limit, int) or not 0 < self.limit <= MAX_QUERIES:
            raise ValueError(f"max_queries must be in 1..{MAX_QUERIES}")

    def ask(self, value: object) -> bool:
        if self.calls >= self.limit:
            raise OracleLimitError(f"oracle query budget exhausted after {self.calls} calls")
        self.calls += 1
        answer = self.check(value)
        if isinstance(answer, bool):
            return answer
        if isinstance(answer, int) and answer in (0, 1):
            return bool(answer)
        raise OracleProtocolError("oracle must return bool or integer 0/1")


def _budget(check: Callable[[object], bool] | OracleBudget, max_queries: int) -> OracleBudget:
    if isinstance(check, OracleBudget):
        return check
    return OracleBudget(check, max_queries)


def _ceil_div(a: int, b: int) -> int:
    return -(-a // b)


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """PKCS#7-pad ``data`` after validating a practical block size."""
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not 1 < block_size <= 255:
        raise ValueError("block_size must be in 2..255")
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError("input exceeds allocation cap")
    amount = block_size - (len(data) % block_size)
    return data + bytes([amount]) * amount


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    """Strict PKCS#7 unpadding; malformed padding raises ``ValueError``."""
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not 1 < block_size <= 255:
        raise ValueError("block_size must be in 2..255")
    if not data or len(data) % block_size:
        raise ValueError("invalid PKCS#7 padded length")
    amount = data[-1]
    if amount == 0 or amount > block_size or data[-amount:] != bytes([amount]) * amount:
        raise ValueError("invalid PKCS#7 padding")
    return data[:-amount]


def _cbc_intermediate(
    target: bytes,
    budget: OracleBudget,
    *,
    block_size: int,
    prefix: bytes = b"",
) -> bytes:
    """Recover ``D_K(target)`` with a strict PKCS#7-validity oracle."""
    if len(target) != block_size or len(prefix) % block_size:
        raise ValueError("target/prefix is not block aligned")
    intermediate = bytearray(block_size)
    forged = bytearray(block_size)
    for index in range(block_size - 1, -1, -1):
        padding = block_size - index
        for j in range(index + 1, block_size):
            forged[j] = intermediate[j] ^ padding
        matches: list[int] = []
        for guess in range(256):
            forged[index] = guess
            candidate = prefix + bytes(forged) + target
            if not budget.ask(candidate):
                continue
            # A pad=1 hit can instead preserve an existing 02 02, 03 03 03, ... suffix.  Changing
            # the preceding byte preserves genuine 01 but invalidates every longer accidental pad.
            if padding == 1 and index:
                probe = bytearray(forged)
                probe[index - 1] ^= 1
                if not budget.ask(prefix + bytes(probe) + target):
                    continue
            matches.append(guess)
        if len(matches) != 1:
            why = "no" if not matches else "ambiguous"
            raise OracleProtocolError(f"{why} padding-oracle answer at block byte {index}")
        intermediate[index] = matches[0] ^ padding
    return bytes(intermediate)


def cbc_padding_oracle_decrypt(
    ciphertext: bytes,
    check: Callable[[bytes], bool] | OracleBudget,
    *,
    iv: bytes | None = None,
    block_size: int = 16,
    strip_padding: bool = True,
    max_queries: int = 1_000_000,
) -> bytes:
    """Recover CBC plaintext through a PKCS#7 padding-validity callback.

    When ``iv`` is omitted, ``ciphertext`` must be ``IV || C1 || ...``.  With an explicit ``iv``,
    ``ciphertext`` is ``C1 || ...``.  Queries preserve the original prefix and truncate after the
    target block, which works with oracles that accept more than two blocks.  The final plaintext is
    strictly unpadded by default.
    """
    if not isinstance(ciphertext, bytes) or len(ciphertext) > MAX_INPUT_BYTES:
        raise ValueError("ciphertext must be bounded bytes")
    if not 1 < block_size <= 255:
        raise ValueError("block_size must be in 2..255")
    if iv is None:
        combined = ciphertext
    else:
        if not isinstance(iv, bytes) or len(iv) != block_size:
            raise ValueError("IV must be exactly one block")
        combined = iv + ciphertext
    if len(combined) < 2 * block_size or len(combined) % block_size:
        raise ValueError("CBC input must contain an IV and at least one aligned ciphertext block")
    blocks = [combined[i:i + block_size] for i in range(0, len(combined), block_size)]
    budget = _budget(check, max_queries)
    plain = bytearray()
    for i in range(1, len(blocks)):
        # Keep blocks before the predecessor, then substitute the forged predecessor and make the
        # target final so its padding is what the callback checks.
        prefix = b"".join(blocks[:i - 1])
        inter = _cbc_intermediate(blocks[i], budget, block_size=block_size, prefix=prefix)
        plain.extend(a ^ b for a, b in zip(inter, blocks[i - 1]))
    raw = bytes(plain)
    return pkcs7_unpad(raw, block_size) if strip_padding else raw


def cbc_padding_oracle_encrypt(
    plaintext: bytes,
    check: Callable[[bytes], bool] | OracleBudget,
    *,
    block_size: int = 16,
    final_block: bytes | None = None,
    max_queries: int = 1_000_000,
) -> bytes:
    """Construct ``IV || ciphertext`` decrypting to chosen ``plaintext`` using only the oracle.

    The chain is built backwards.  ``final_block`` may be supplied for reproducible fixtures;
    otherwise a random block is used.  The callback must accept arbitrary two-block CBC messages.
    """
    if not isinstance(plaintext, bytes) or len(plaintext) > MAX_INPUT_BYTES:
        raise ValueError("plaintext must be bounded bytes")
    padded = pkcs7_pad(plaintext, block_size)
    if final_block is None:
        final_block = os.urandom(block_size)
    if not isinstance(final_block, bytes) or len(final_block) != block_size:
        raise ValueError("final_block must be exactly one block")
    budget = _budget(check, max_queries)
    wanted = [padded[i:i + block_size] for i in range(0, len(padded), block_size)]
    chain = [final_block]
    target = final_block
    for plain_block in reversed(wanted):
        inter = _cbc_intermediate(target, budget, block_size=block_size)
        predecessor = bytes(a ^ b for a, b in zip(inter, plain_block))
        chain.insert(0, predecessor)
        target = predecessor
    return b"".join(chain)


def _rsa_validate(n: int, e: int, ciphertext: int | bytes) -> tuple[int, int]:
    if not isinstance(n, int) or not isinstance(e, int) or n <= 3 or e <= 1:
        raise ValueError("invalid RSA public key")
    if n.bit_length() > MAX_RSA_BITS:
        raise ValueError(f"RSA modulus exceeds {MAX_RSA_BITS}-bit cap")
    size = (n.bit_length() + 7) // 8
    if isinstance(ciphertext, bytes):
        if not ciphertext or len(ciphertext) > size:
            raise ValueError("invalid RSA ciphertext width")
        c = int.from_bytes(ciphertext, "big")
    elif isinstance(ciphertext, int):
        c = ciphertext
    else:
        raise TypeError("RSA ciphertext must be int or bytes")
    if not 0 <= c < n:
        raise ValueError("RSA ciphertext is outside the modulus")
    return c, size


def _rsa_ask(
    budget: OracleBudget,
    value: int,
    size: int,
    oracle_input: Literal["bytes", "int"],
) -> bool:
    if oracle_input == "bytes":
        return budget.ask(value.to_bytes(size, "big"))
    if oracle_input == "int":
        return budget.ask(value)
    raise ValueError("oracle_input must be 'bytes' or 'int'")


def rsa_parity_oracle_recover(
    ciphertext: int | bytes,
    n: int,
    e: int,
    check: Callable[[object], bool] | OracleBudget,
    *,
    odd_is_true: bool = True,
    oracle_input: Literal["bytes", "int"] = "bytes",
    max_queries: int | None = None,
) -> int | None:
    """Recover an RSA plaintext from an oracle revealing its least-significant bit.

    The callback answer is interpreted as "odd" unless ``odd_is_true=False``.  Exact rational
    bounds avoid the rounding bug common in float implementations.  ``None`` is returned unless a
    candidate re-encrypts to the original ciphertext.
    """
    c, size = _rsa_validate(n, e, ciphertext)
    limit = max_queries if max_queries is not None else n.bit_length() + 4
    budget = _budget(check, limit)
    low, high = Fraction(0), Fraction(n)
    multiplier = pow(2, e, n)
    probe = c
    for _ in range(n.bit_length() + 2):
        probe = probe * multiplier % n
        odd = _rsa_ask(budget, probe, size, oracle_input)
        if not odd_is_true:
            odd = not odd
        middle = (low + high) / 2
        if odd:
            low = middle
        else:
            high = middle
        if high - low < 1:
            break
    start = max(0, low.numerator // low.denominator - 2)
    stop = min(n - 1, _ceil_div(high.numerator, high.denominator) + 2)
    for candidate in range(start, stop + 1):
        if pow(candidate, e, n) == c:
            return candidate
    return None


# Common spelling used by oracle tooling.
rsa_lsb_oracle_recover = rsa_parity_oracle_recover
rsa_lsb_oracle = rsa_parity_oracle_recover


def _merge_intervals(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    if not intervals:
        return []
    intervals.sort()
    out = [intervals[0]]
    for a, b in intervals[1:]:
        if a <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], b))
        else:
            out.append((a, b))
    return out


def bleichenbacher_pkcs1_v1_5_recover(
    ciphertext: int | bytes,
    n: int,
    e: int,
    check: Callable[[object], bool] | OracleBudget,
    *,
    oracle_input: Literal["bytes", "int"] = "bytes",
    max_queries: int = 2_000_000,
) -> bytes | None:
    """Bleichenbacher '98 adaptive recovery of a PKCS#1 v1.5 encoded message.

    ``check`` is true precisely for PKCS-conforming decrypted ciphertexts.  Blinding is supported
    when the supplied ciphertext itself is non-conforming.  On success the full fixed-width encoded
    message (``00 02 ... 00 M``) is returned after re-encryption proof.
    """
    c, size = _rsa_validate(n, e, ciphertext)
    if size < 11:
        raise ValueError("PKCS#1 v1.5 needs an RSA modulus of at least 11 bytes")
    budget = _budget(check, max_queries)
    B = 1 << (8 * (size - 2))
    two_b, three_b_minus_1 = 2 * B, 3 * B - 1

    # Step 1: optional blinding.  Most CTF inputs are already conforming and take s0=1.
    if _rsa_ask(budget, c, size, oracle_input):
        s0, c0 = 1, c
    else:
        s0 = 2
        while True:
            if math.gcd(s0, n) == 1:
                candidate = c * pow(s0, e, n) % n
                if _rsa_ask(budget, candidate, size, oracle_input):
                    c0 = candidate
                    break
            s0 += 1

    intervals = [(two_b, three_b_minus_1)]
    s = 0
    iteration = 1
    while True:
        # Step 2: locate the next conforming multiplier.
        if iteration == 1:
            candidate_s = _ceil_div(n, 3 * B)
            while not _rsa_ask(budget, c0 * pow(candidate_s, e, n) % n, size, oracle_input):
                candidate_s += 1
            s = candidate_s
        elif len(intervals) > 1:
            candidate_s = s + 1
            while not _rsa_ask(budget, c0 * pow(candidate_s, e, n) % n, size, oracle_input):
                candidate_s += 1
            s = candidate_s
        else:
            a, b = intervals[0]
            r = _ceil_div(2 * (b * s - 2 * B), n)
            found = False
            while not found:
                lo = _ceil_div(2 * B + r * n, b)
                hi = (3 * B - 1 + r * n) // a
                for candidate_s in range(lo, hi + 1):
                    if _rsa_ask(budget, c0 * pow(candidate_s, e, n) % n, size, oracle_input):
                        s = candidate_s
                        found = True
                        break
                r += 1

        # Step 3: narrow every possible interval.
        narrowed: list[tuple[int, int]] = []
        for a, b in intervals:
            r_min = _ceil_div(a * s - (3 * B - 1), n)
            r_max = (b * s - 2 * B) // n
            for r in range(r_min, r_max + 1):
                lower = max(a, _ceil_div(2 * B + r * n, s))
                upper = min(b, (3 * B - 1 + r * n) // s)
                if lower <= upper:
                    narrowed.append((lower, upper))
        intervals = _merge_intervals(narrowed)
        if not intervals:
            raise OracleProtocolError("PKCS#1 oracle answers produced an empty interval")
        if len(intervals) == 1 and intervals[0][0] == intervals[0][1]:
            blinded = intervals[0][0]
            try:
                recovered = blinded * pow(s0, -1, n) % n
            except ValueError as exc:  # guarded by gcd in blinding, defensive for custom ints
                raise OracleProtocolError("non-invertible blinding multiplier") from exc
            if pow(recovered, e, n) != c:
                return None
            return recovered.to_bytes(size, "big")
        iteration += 1


def decode_pkcs1_v1_5(encoded: bytes) -> bytes | None:
    """Strictly decode an encryption block; return ``None`` for malformed PKCS#1 v1.5."""
    if (not isinstance(encoded, bytes) or len(encoded) > MAX_INPUT_BYTES or len(encoded) < 11
            or encoded[:2] != b"\x00\x02"):
        return None
    separator = encoded.find(b"\x00", 2)
    if separator < 10 or any(x == 0 for x in encoded[2:separator]):
        return None
    return encoded[separator + 1:]


def manger_leading_zero_recover(
    ciphertext: int | bytes,
    n: int,
    e: int,
    check: Callable[[object], bool] | OracleBudget,
    *,
    oracle_input: Literal["bytes", "int"] = "bytes",
    max_queries: int = 100_000,
) -> int | None:
    """Manger's attack for an oracle answering whether RSA plaintext's top byte is zero.

    The callback must be true iff the decrypted integer is below ``B = 2^(8*(k-1))`` for a
    ``k``-byte modulus.  The recovered encoded integer is returned only after re-encryption proof.
    """
    c, size = _rsa_validate(n, e, ciphertext)
    if size < 2:
        raise ValueError("Manger attack needs a multi-byte RSA modulus")
    budget = _budget(check, max_queries)
    B = 1 << (8 * (size - 1))

    # Step 1: first power of two that moves m out of [0, B).
    f1 = 2
    while _rsa_ask(budget, c * pow(f1, e, n) % n, size, oracle_input):
        f1 *= 2

    # Step 2: a multiple whose decrypted representative wraps into [0, B).
    step = f1 // 2
    f2 = _ceil_div(n + B, B) * step
    while not _rsa_ask(budget, c * pow(f2, e, n) % n, size, oracle_input):
        f2 += step

    lower = _ceil_div(n, f2)
    upper = (n + B - 1) // f2
    if lower > upper:
        raise OracleProtocolError("Manger oracle produced an empty initial interval")

    # Step 3: choose each multiplier so the one-bit answer cuts the interval.
    while lower < upper:
        width = upper - lower
        f_tmp = max(2, (2 * B) // width)
        i = max(1, (f_tmp * lower) // n)
        f3 = _ceil_div(i * n, lower)
        boundary = _ceil_div(i * n + B, f3)
        if _rsa_ask(budget, c * pow(f3, e, n) % n, size, oracle_input):
            upper = min(upper, boundary - 1)
        else:
            lower = max(lower, boundary)
        if lower > upper:
            raise OracleProtocolError("Manger oracle answers produced an empty interval")

    return lower if pow(lower, e, n) == c else None


def mgf1(seed: bytes, length: int, hash_name: str = "sha1") -> bytes:
    """MGF1 used by OAEP, with bounded output."""
    if not isinstance(seed, bytes) or not 0 <= length <= MAX_INPUT_BYTES:
        raise ValueError("invalid MGF1 seed/output length")
    try:
        digest_size = hashlib.new(hash_name).digest_size
    except (ValueError, TypeError) as exc:
        raise ValueError("unknown hash algorithm") from exc
    if length > digest_size * (1 << 32):
        raise ValueError("MGF1 output is too long")
    out = bytearray()
    for counter in range(_ceil_div(length, digest_size)):
        out.extend(hashlib.new(hash_name, seed + counter.to_bytes(4, "big")).digest())
    return bytes(out[:length])


def oaep_decode(encoded: bytes, *, label: bytes = b"", hash_name: str = "sha1") -> bytes | None:
    """Strict EME-OAEP decode.  Integrity/structure failure returns ``None``."""
    if not isinstance(encoded, bytes) or not isinstance(label, bytes):
        raise TypeError("encoded message and label must be bytes")
    if len(encoded) > MAX_INPUT_BYTES or len(label) > MAX_INPUT_BYTES:
        raise ValueError("OAEP input exceeds allocation cap")
    try:
        hlen = hashlib.new(hash_name).digest_size
    except (ValueError, TypeError) as exc:
        raise ValueError("unknown hash algorithm") from exc
    if len(encoded) < 2 * hlen + 2 or encoded[0] != 0:
        return None
    masked_seed = encoded[1:1 + hlen]
    masked_db = encoded[1 + hlen:]
    seed_mask = mgf1(masked_db, hlen, hash_name)
    seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))
    db_mask = mgf1(seed, len(masked_db), hash_name)
    db = bytes(a ^ b for a, b in zip(masked_db, db_mask))
    if db[:hlen] != hashlib.new(hash_name, label).digest():
        return None
    rest = db[hlen:]
    separator = rest.find(b"\x01")
    if separator < 0 or any(rest[:separator]):
        return None
    return rest[separator + 1:]


def manger_oaep_recover(
    ciphertext: int | bytes,
    n: int,
    e: int,
    check: Callable[[object], bool] | OracleBudget,
    *,
    label: bytes = b"",
    hash_name: str = "sha1",
    oracle_input: Literal["bytes", "int"] = "bytes",
    max_queries: int = 100_000,
    encoded: bool = False,
) -> bytes | None:
    """Run Manger recovery and return verified OAEP plaintext (or the encoded block).

    ``encoded=True`` is useful when a challenge uses Manger's threshold oracle around a custom
    encoding.  Otherwise OAEP's label hash and delimiter are verified before plaintext is returned.
    """
    _c, size = _rsa_validate(n, e, ciphertext)
    value = manger_leading_zero_recover(
        ciphertext, n, e, check, oracle_input=oracle_input, max_queries=max_queries
    )
    if value is None:
        return None
    block = value.to_bytes(size, "big")
    return block if encoded else oaep_decode(block, label=label, hash_name=hash_name)


# Short aliases for challenge solve scripts.
bleichenbacher = bleichenbacher_pkcs1_v1_5_recover
manger = manger_oaep_recover
padding_oracle_decrypt = cbc_padding_oracle_decrypt
padding_oracle_encrypt = cbc_padding_oracle_encrypt
bleichenbacher_attack = bleichenbacher_pkcs1_v1_5_recover
manger_attack = manger_leading_zero_recover


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover - exercised through main
        raise ValueError(message)


def _description() -> dict[str, object]:
    return {
        "engine": "crypto_oracles",
        "transport": "none (caller-supplied bounded callback only)",
        "attacks": ["cbc-padding-decrypt", "cbc-padding-encrypt", "rsa-lsb", "bleichenbacher", "manger"],
        "caps": {"input_bytes": MAX_INPUT_BYTES, "rsa_bits": MAX_RSA_BITS, "queries": MAX_QUERIES},
    }


def main(argv: list[str] | None = None) -> int:
    """Small offline CLI for inspection and strict padding decoders.

    Adaptive attacks remain Python APIs because loading/executing a callback from challenge data
    would violate this engine's safety boundary.
    """
    parser = _Parser(prog="crypto_oracles.py", add_help=True)
    parser.add_argument("operation", nargs="?", default="describe",
                        choices=("describe", "pkcs7-unpad", "pkcs1-decode", "oaep-decode"))
    parser.add_argument("value", nargs="?", help="hex bytes for a strict offline decoder")
    parser.add_argument("--block-size", type=int, default=16)
    parser.add_argument("--hash", dest="hash_name", default="sha1")
    parser.add_argument("--label-hex", default="")
    parser.add_argument("--json", action="store_true")
    try:
        args = parser.parse_args(argv)
        if args.operation == "describe":
            if args.value is not None:
                raise ValueError("describe takes no value")
            result: object = _description()
        else:
            if args.value is None:
                raise ValueError(f"{args.operation} requires a hex value")
            try:
                raw = bytes.fromhex(args.value)
                label = bytes.fromhex(args.label_hex)
            except ValueError as exc:
                raise ValueError("value/label must be even-length hexadecimal") from exc
            if args.operation == "pkcs7-unpad":
                decoded = pkcs7_unpad(raw, args.block_size)
            elif args.operation == "pkcs1-decode":
                decoded = decode_pkcs1_v1_5(raw)
                if decoded is None:
                    raise ValueError("invalid PKCS#1 v1.5 encoding")
            else:
                decoded = oaep_decode(raw, label=label, hash_name=args.hash_name)
                if decoded is None:
                    raise ValueError("invalid OAEP encoding")
            result = {"candidate_hex": decoded.hex(), "verified": True}
        if args.json:
            print(json.dumps(result, sort_keys=True))
        elif isinstance(result, dict) and "candidate_hex" in result:
            print(f"CANDIDATE [verified decode] {result['candidate_hex']}")
        else:
            info = result
            print("crypto_oracles: offline callback-only engine")
            print("attacks: " + ", ".join(info["attacks"]))
            print("transport: " + str(info["transport"]))
        return 0
    except (OracleError, TypeError, ValueError) as exc:
        print(f"crypto_oracles: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
