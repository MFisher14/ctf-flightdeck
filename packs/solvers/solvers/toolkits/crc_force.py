#!/usr/bin/env python3
"""Force a file's CRC32 to a chosen value by patching four bytes, offline.

A recurring misc/forensics trick: a challenge checks that an artifact has a specific CRC32 (a PNG/zip
chunk checksum, a "make the CRC equal X" puzzle, a tamper check), and you must craft bytes that hash
to it.  CRC32 is affine over GF(2), so patching any four bytes can hit *any* target exactly.  This
solves for those four bytes by linear algebra, using the real `zlib.crc32` as the oracle (so the result
is correct by construction, not by a hand-rolled polynomial), then verifies before returning.  Pure
stdlib, offline — it rewrites bytes you supply and never submits.
"""
from __future__ import annotations

import argparse
import sys
import zlib
from typing import Iterable

MAX_INPUT = 1 << 24


class CrcError(Exception):
    """Impossible request — fail closed."""


def _crc(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def _solve_gf2(columns: list[int], rhs: int) -> int:
    """Solve XOR-of-selected-columns == rhs over GF(2). columns[i] is a 32-bit vector; returns the
    32-bit mask of selected indices, or raises if rhs is not in the column space."""
    # Gaussian elimination: keep a basis of (vector, mask) where mask is the x-combination making vector.
    basis: list[tuple[int, int]] = []
    for i, col in enumerate(columns):
        vec, mask = col, (1 << i)
        for bvec, bmask in basis:
            if vec ^ bvec < vec:        # reduce by the highest set bit
                vec ^= bvec
                mask ^= bmask
        if vec:
            basis.append((vec, mask))
            basis.sort(reverse=True)    # keep sorted by leading bit for stable reduction
    # reduce rhs against the basis, accumulating the mask
    vec, mask = rhs, 0
    for bvec, bmask in basis:
        if vec ^ bvec < vec:
            vec ^= bvec
            mask ^= bmask
    if vec != 0:
        raise CrcError("target CRC is unreachable from this offset (degenerate region)")
    return mask


def patch(data: object, offset: int, target: int) -> bytes:
    """Return a copy of `data` with the 4 bytes at `offset` set so crc32(result) == target."""
    if not isinstance(data, (bytes, bytearray)):
        raise CrcError("data must be bytes")
    data = bytearray(data)
    if len(data) > MAX_INPUT:
        raise CrcError("input too large")
    if not isinstance(offset, int) or offset < 0 or offset + 4 > len(data):
        raise CrcError("offset must leave room for a 4-byte patch inside the data")
    if not isinstance(target, int) or not 0 <= target <= 0xFFFFFFFF:
        raise CrcError("target must be a 32-bit unsigned int")
    # baseline: CRC with the 4-byte window zeroed
    for j in range(4):
        data[offset + j] = 0
    base = _crc(bytes(data))
    # column i = effect on the output CRC of setting exactly bit i of the 32-bit window
    columns = []
    for i in range(32):
        j, b = divmod(i, 8)
        data[offset + j] ^= (1 << b)
        columns.append(_crc(bytes(data)) ^ base)
        data[offset + j] ^= (1 << b)        # restore (window back to zero)
    mask = _solve_gf2(columns, target ^ base)
    for i in range(32):
        if mask & (1 << i):
            j, b = divmod(i, 8)
            data[offset + j] |= (1 << b)
    result = bytes(data)
    if _crc(result) != target:               # correctness gate — never return an unverified patch
        raise CrcError("internal error: patched CRC did not match target")
    return result


def append_patch(data: object, target: int) -> bytes:
    """Append 4 bytes to `data` chosen so crc32(result) == target."""
    if not isinstance(data, (bytes, bytearray)):
        raise CrcError("data must be bytes")
    base = bytes(data) + b"\x00\x00\x00\x00"
    return patch(base, len(base) - 4, target)


def main(argv: Iterable[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Force a file's CRC32 to a target by patching 4 bytes (offline).")
    p.add_argument("file")
    p.add_argument("target", help="target CRC32, e.g. 0xdeadbeef or decimal")
    p.add_argument("--offset", type=int, default=None,
                   help="byte offset of the 4-byte patch window (default: append 4 bytes at the end)")
    p.add_argument("--out", help="write the patched bytes here (default: stdout buffer)")
    try:
        a = p.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        target = int(a.target, 0)
        with open(a.file, "rb") as fh:
            data = fh.read(MAX_INPUT + 1)
        result = append_patch(data, target) if a.offset is None else patch(data, a.offset, target)
        if a.out:
            with open(a.out, "wb") as fh:
                fh.write(result)
            print(f"wrote {len(result)} bytes, crc32=0x{zlib.crc32(result) & 0xFFFFFFFF:08x}", file=sys.stderr)
        else:
            sys.stdout.buffer.write(result)
    except (OSError, ValueError, CrcError) as exc:
        print(f"crc_force: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
