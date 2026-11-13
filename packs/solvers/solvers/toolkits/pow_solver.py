#!/usr/bin/env python3
"""Bounded, offline proof-of-work and Hashcash solver.

The module solves a *stated* hash puzzle over ``prefix + suffix``.  It never opens a
socket and never submits anything; :mod:`tools.netplay` may call :func:`solve_prompt`
after the scope-locked quiz connection has delivered a PoW prompt.

Supported primitives:

* SHA-1/SHA-256/SHA-512 leading-zero bits or hexadecimal digits;
* decimal, hexadecimal, or fixed-width binary counters;
* Hashcash v1 minting for a supplied resource/date;
* common redpwn/pwntools prompt wording and explicit kCTF-style
  ``prefix/challenge + difficulty`` forms.

Every search has an explicit attempt and difficulty cap.  The returned candidate is
verified again before it is exposed to the caller.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import datetime as _dt
import hashlib
import json
import os
import re
import secrets
import sys
from typing import Iterable

MAX_DIFFICULTY_BITS = 30
MAX_ATTEMPTS = 50_000_000
MAX_PREFIX_BYTES = 1 << 16
MAX_WORKERS = 32
_ALGORITHMS = {"sha1": hashlib.sha1, "sha256": hashlib.sha256, "sha512": hashlib.sha512}


@dataclasses.dataclass(frozen=True)
class PowChallenge:
    """A bounded ``hash(prefix + encode(counter))`` search."""

    prefix: bytes
    difficulty_bits: int
    algorithm: str = "sha256"
    encoding: str = "decimal"
    start: int = 0
    width: int = 0

    def validate(self) -> None:
        if self.algorithm not in _ALGORITHMS:
            raise ValueError(f"unsupported hash algorithm {self.algorithm!r}")
        if not 1 <= self.difficulty_bits <= MAX_DIFFICULTY_BITS:
            raise ValueError(f"difficulty must be 1..{MAX_DIFFICULTY_BITS} bits")
        if len(self.prefix) > MAX_PREFIX_BYTES:
            raise ValueError("prefix is too large")
        if self.encoding not in {"decimal", "hex", "binary"}:
            raise ValueError("encoding must be decimal, hex, or binary")
        if self.start < 0 or self.width < 0 or self.width > 64:
            raise ValueError("invalid start/width")


@dataclasses.dataclass(frozen=True)
class PowSolution:
    counter: int
    suffix: bytes
    digest_hex: str
    attempts: int


def leading_zero_bits(data: bytes) -> int:
    """Return the number of zero bits before the first one bit."""
    total = 0
    for value in data:
        if value == 0:
            total += 8
            continue
        total += 8 - value.bit_length()
        break
    return total


def _counter_bytes(counter: int, encoding: str, width: int = 0) -> bytes:
    if encoding == "decimal":
        text = str(counter)
        return text.zfill(width).encode("ascii") if width else text.encode("ascii")
    if encoding == "hex":
        text = format(counter, "x")
        return text.zfill(width).encode("ascii") if width else text.encode("ascii")
    size = width or max(1, (counter.bit_length() + 7) // 8)
    if counter >= 1 << (8 * size):
        raise OverflowError("counter does not fit fixed binary width")
    return counter.to_bytes(size, "big")


def verify_pow(challenge: PowChallenge, suffix: bytes | str) -> bool:
    """Verify a suffix against a challenge without searching."""
    challenge.validate()
    if isinstance(suffix, str):
        suffix = suffix.encode("utf-8")
    if not isinstance(suffix, bytes) or len(suffix) > 256:
        return False
    digest = _ALGORITHMS[challenge.algorithm](challenge.prefix + suffix).digest()
    return leading_zero_bits(digest) >= challenge.difficulty_bits


def _search_stride(args: tuple[PowChallenge, int, int, int]) -> tuple[int, bytes, str, int] | None:
    challenge, begin, stop, stride = args
    digest_fn = _ALGORITHMS[challenge.algorithm]
    attempts = 0
    for counter in range(begin, stop, stride):
        attempts += 1
        try:
            suffix = _counter_bytes(counter, challenge.encoding, challenge.width)
        except OverflowError:
            break
        digest = digest_fn(challenge.prefix + suffix).digest()
        if leading_zero_bits(digest) >= challenge.difficulty_bits:
            return counter, suffix, digest.hex(), attempts
    return None


def solve_pow(challenge: PowChallenge, *, max_attempts: int = 5_000_000,
              workers: int = 1) -> PowSolution | None:
    """Find and re-verify one suffix, or ``None`` within ``max_attempts``.

    Parallel workers search disjoint arithmetic progressions.  Because workers may
    finish out of order, a parallel result is a valid candidate but not necessarily
    the numerically smallest candidate.
    """
    challenge.validate()
    if not 1 <= max_attempts <= MAX_ATTEMPTS:
        raise ValueError(f"max_attempts must be 1..{MAX_ATTEMPTS}")
    if not 1 <= workers <= min(MAX_WORKERS, os.cpu_count() or 1):
        raise ValueError("workers outside the supported range")
    stop = challenge.start + max_attempts
    if workers == 1:
        hit = _search_stride((challenge, challenge.start, stop, 1))
        if hit is None:
            return None
        counter, suffix, digest_hex, attempts = hit
    else:
        tasks = [(challenge, challenge.start + i, stop, workers) for i in range(workers)]
        hit = None
        with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(_search_stride, task) for task in tasks]
            for future in concurrent.futures.as_completed(futures):
                candidate = future.result()
                if candidate is not None:
                    hit = candidate
                    for other in futures:
                        other.cancel()
                    break
        if hit is None:
            return None
        counter, suffix, digest_hex, attempts = hit
    if not verify_pow(challenge, suffix):  # fail closed if an implementation changes
        return None
    return PowSolution(counter, suffix, digest_hex, attempts)


def mint_hashcash(resource: str, bits: int, *, date: str | None = None,
                  algorithm: str = "sha1", max_attempts: int = 5_000_000,
                  workers: int = 1, salt: str | None = None) -> str | None:
    """Mint a Hashcash-v1 stamp and verify it before returning.

    ``salt`` exists for reproducible fixtures; production callers get 64 random bits.
    Hashcash v1 uses SHA-1 by convention, but explicit SHA-256 puzzles are accepted.
    """
    if not resource or len(resource.encode("utf-8")) > 4096 or ":" in resource:
        raise ValueError("resource must be non-empty, bounded, and contain no colon")
    if date is None:
        date = _dt.datetime.now(_dt.timezone.utc).strftime("%y%m%d%H%M%S")
    if not re.fullmatch(r"\d{6}(?:\d{6})?", date):
        raise ValueError("Hashcash date must be YYMMDD or YYMMDDhhmmss")
    if salt is None:
        salt = secrets.token_hex(8)
    if not re.fullmatch(r"[A-Za-z0-9+/=_-]{1,128}", salt):
        raise ValueError("invalid Hashcash salt")
    header = f"1:{bits}:{date}:{resource}::{salt}:"
    challenge = PowChallenge(header.encode(), bits, algorithm, "hex")
    result = solve_pow(challenge, max_attempts=max_attempts, workers=workers)
    if result is None:
        return None
    stamp = header + result.suffix.decode("ascii")
    return stamp if verify_hashcash(stamp, algorithm=algorithm, min_bits=bits) else None


def verify_hashcash(stamp: str, *, algorithm: str = "sha1", min_bits: int | None = None) -> bool:
    """Strictly validate a v1 Hashcash stamp's shape and claimed work."""
    if algorithm not in _ALGORITHMS or len(stamp) > 8192:
        return False
    parts = stamp.split(":")
    if len(parts) != 7 or parts[0] != "1" or not parts[1].isdigit():
        return False
    bits = int(parts[1])
    if bits < 1 or bits > MAX_DIFFICULTY_BITS or (min_bits is not None and bits < min_bits):
        return False
    return leading_zero_bits(_ALGORITHMS[algorithm](stamp.encode()).digest()) >= bits


_QUOTED = r"(?:['\"])(.{1,4096}?)(?:['\"])"


def parse_prompt(prompt: str) -> tuple[PowChallenge, int] | None:
    """Parse common explicit PoW wording into ``(challenge, attempts_cap)``.

    Ambiguous prompts return ``None`` rather than guessing.  A prompt must name a
    supported hash, a prefix/challenge, and a leading-zero requirement.
    """
    if not isinstance(prompt, str) or len(prompt) > 64_000:
        return None
    low = prompt.lower()
    alg_m = re.search(r"\b(sha(?:-|_)?(?:1|256|512))\b", low)
    if not alg_m:
        return None
    algorithm = alg_m.group(1).replace("-", "").replace("_", "")

    bits = None
    m = re.search(r"(?:leading|starts?\s+with|begins?\s+with)\s+(\d{1,2})\s+zero\s+bits?", low)
    if m:
        bits = int(m.group(1))
    if bits is None:
        m = re.search(r"(?:leading|starts?\s+with|begins?\s+with)\s+(?:0x)?(0{1,16})\b", low)
        if m:
            bits = 4 * len(m.group(1))
    if bits is None:
        m = re.search(r"difficulty(?:_bits)?\s*[:=]\s*(\d{1,2})", low)
        if m:
            bits = int(m.group(1))
    if bits is None or not 1 <= bits <= MAX_DIFFICULTY_BITS:
        return None

    prefix = None
    patterns: Iterable[str] = (
        r"(?:prefix|challenge|string|token)\s*(?:is|=|:)?\s*" + _QUOTED,
        r"(?:prefix|challenge|string|token)\s*(?:is|=|:)\s*([^\s,;]{1,4096})",
        r"hash\s*\(\s*" + _QUOTED + r"\s*\+",
    )
    for pattern in patterns:
        hit = re.search(pattern, prompt, re.I | re.S)
        if hit:
            prefix = hit.group(1)
            break
    if prefix is None:
        return None
    # Challenge strings are data, never escape-decoded or evaluated.
    prefix_b = prefix.encode("utf-8")
    encoding = "hex" if re.search(r"\bhex(?:adecimal)?\s+(?:suffix|nonce|counter)", low) else "decimal"
    width_m = re.search(r"(?:width|length)\s*[:=]?\s*(\d{1,2})\s*(?:hex\s*)?(?:digits?|bytes?)", low)
    width = int(width_m.group(1)) if width_m else 0
    cap_m = re.search(r"max(?:imum)?\s+(?:attempts|iterations)\s*[:=]\s*(\d{1,9})", low)
    cap = min(int(cap_m.group(1)), MAX_ATTEMPTS) if cap_m else 5_000_000
    try:
        challenge = PowChallenge(prefix_b, bits, algorithm, encoding, width=width)
        challenge.validate()
    except ValueError:
        return None
    return challenge, cap


def solve_prompt(prompt: str, *, workers: int = 1,
                 max_attempts: int | None = None) -> str | None:
    """Parse and solve one explicit prompt; return the suffix text only."""
    parsed = parse_prompt(prompt)
    if parsed is None:
        return None
    challenge, prompt_cap = parsed
    cap = prompt_cap if max_attempts is None else min(max_attempts, prompt_cap, MAX_ATTEMPTS)
    result = solve_pow(challenge, max_attempts=cap, workers=workers)
    if result is None:
        return None
    try:
        return result.suffix.decode("ascii")
    except UnicodeDecodeError:
        return result.suffix.hex()


def _prefix_arg(value: str, as_hex: bool) -> bytes:
    if not as_hex:
        return value.encode("utf-8")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("--prefix-hex requires even-length hexadecimal") from exc


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _ArgumentParser(description="bounded offline proof-of-work solver")
    parser.add_argument("--prefix", help="literal prefix")
    parser.add_argument("--prefix-hex", action="store_true", help="interpret --prefix as hex bytes")
    parser.add_argument("--bits", type=int, help="required leading zero bits")
    parser.add_argument("--algorithm", choices=sorted(_ALGORITHMS), default=None,
                        help="default: SHA-1 for Hashcash, SHA-256 otherwise")
    parser.add_argument("--encoding", choices=("decimal", "hex", "binary"), default="decimal")
    parser.add_argument("--width", type=int, default=0)
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--max-attempts", type=int, default=5_000_000)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--prompt", help="parse a complete common PoW prompt")
    parser.add_argument("--hashcash-resource", help="mint a Hashcash v1 stamp")
    parser.add_argument("--date", help="Hashcash YYMMDD[hhmmss]")
    parser.add_argument("--json", action="store_true")
    try:
        args = parser.parse_args(argv)
        if args.hashcash_resource:
            algorithm = args.algorithm or "sha1"
            stamp = mint_hashcash(args.hashcash_resource, args.bits or 20, date=args.date,
                                  algorithm=algorithm, max_attempts=args.max_attempts,
                                  workers=args.workers)
            if stamp is None:
                raise RuntimeError("no solution within the attempt bound")
            output = {"kind": "hashcash", "stamp": stamp, "verified": True}
        elif args.prompt is not None:
            parsed = parse_prompt(args.prompt)
            if parsed is None:
                raise ValueError("prompt is ambiguous or unsupported")
            challenge, prompt_cap = parsed
            result = solve_pow(challenge, max_attempts=min(args.max_attempts, prompt_cap),
                               workers=args.workers)
            if result is None:
                raise RuntimeError("no solution within the attempt bound")
            output = dataclasses.asdict(result)
            output["suffix"] = result.suffix.hex() if challenge.encoding == "binary" else result.suffix.decode()
            output["verified"] = verify_pow(challenge, result.suffix)
        else:
            if args.prefix is None or args.bits is None:
                raise ValueError("give --prompt, --hashcash-resource, or both --prefix and --bits")
            challenge = PowChallenge(_prefix_arg(args.prefix, args.prefix_hex), args.bits,
                                     args.algorithm or "sha256", args.encoding, args.start, args.width)
            result = solve_pow(challenge, max_attempts=args.max_attempts, workers=args.workers)
            if result is None:
                raise RuntimeError("no solution within the attempt bound")
            output = dataclasses.asdict(result)
            output["suffix"] = result.suffix.hex() if args.encoding == "binary" else result.suffix.decode()
            output["verified"] = verify_pow(challenge, result.suffix)
        print(json.dumps(output, indent=2) if args.json else output["stamp"] if "stamp" in output else output["suffix"])
        return 0
    except (ValueError, RuntimeError, OSError) as exc:
        print(f"pow_solver: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
