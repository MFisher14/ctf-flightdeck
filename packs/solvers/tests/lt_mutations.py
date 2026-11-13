"""Seeded mutations of a file for the long-tail reader tests (B-251). Not a test module.

A reader of a hostile format may refuse a file in three declared ways (FormatError, which includes
NotThisFormat; NeedsTool; NeedsKey). Anything else it raises on a mutated file (TypeError, KeyError,
struct.error, RecursionError ...) is a bug: `only_declared_errors` lets exactly the declared ones pass.
"""
import random

from _lt_common import FormatError, NeedsKey, NeedsTool

DECLARED = (FormatError, NeedsTool, NeedsKey)


def mutations(data: bytes, count: int, seed: int):
    """`count` small mutations of `data`: bit flips, byte values at the edges of a range, cuts,
    insertions and a few bytes changed at once. The same seed gives the same files."""
    rnd = random.Random(seed)
    for _ in range(count):
        b = bytearray(data)
        kind = rnd.random()
        if kind < 0.45:
            b[rnd.randrange(len(b))] ^= 1 << rnd.randrange(8)
        elif kind < 0.7:
            b[rnd.randrange(len(b))] = rnd.choice((0, 1, 0x7F, 0x80, 0xFF, rnd.randrange(256)))
        elif kind < 0.8:
            del b[rnd.randrange(len(b)):]
        elif kind < 0.9:
            at = rnd.randrange(len(b))
            b[at:at] = bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 5)))
        else:
            for _ in range(rnd.randrange(2, 6)):
                b[rnd.randrange(len(b))] = rnd.randrange(256)
        yield bytes(b)


def bit_flips(data: bytes, start: int = 0, stop: int | None = None):
    """Every single-bit flip of data[start:stop]."""
    for bit in range(8 * start, 8 * (len(data) if stop is None else stop)):
        b = bytearray(data)
        b[bit >> 3] ^= 1 << (bit & 7)
        yield bytes(b)


def only_declared_errors(read, files) -> tuple:
    """Run `read` over the files. (read, refused): how many it read and how many it refused with a
    declared error. Any other exception propagates and fails the calling test."""
    done = refused = 0
    for f in files:
        try:
            read(f)
            done += 1
        except DECLARED:
            refused += 1
    return done, refused
