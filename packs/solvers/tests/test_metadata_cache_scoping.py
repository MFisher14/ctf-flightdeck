#!/usr/bin/env python3
"""Non-fake content scoping for Metadata's process-wide forensic parser memo."""
from __future__ import annotations

import sys
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
sys.dont_write_bytecode = True
sys.path[:0] = [str(REPO / "solvers" / "common"), str(REPO / "solvers" / "metadata-forensics")]

import readers_forensic_wiring as wiring  # noqa: E402


class SameHashBytes(bytes):
    """Two legitimate byte buffers with a deliberate Python-hash collision."""

    def __hash__(self):
        return 0x4D455441


def main():
    left = SameHashBytes(b"regf" + b"A" * 32)
    right = SameHashBytes(b"regf" + b"B" * 32)
    assert left != right and len(left) == len(right) and hash(left) == hash(right)

    calls = []

    def parse(data):
        calls.append(bytes(data))
        return bytes(data)[-1:]

    wiring._MEMO.clear()
    one = wiring._memo("collision-regression", left, parse)
    two = wiring._memo("collision-regression", right, parse)
    again = wiring._memo("collision-regression", left, parse)

    assert one == b"A" and two == b"B" and again == b"A", (one, two, again)
    assert calls == [bytes(left), bytes(right)], calls
    assert len(wiring._MEMO) == 2, wiring._MEMO
    print("PASS: Metadata forensic memo separates equal-length, equal-hash artifact bytes (3/3)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
