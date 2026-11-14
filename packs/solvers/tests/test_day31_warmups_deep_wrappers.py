#!/usr/bin/env python3
"""Day 31 finale look-ahead: bounded alternating base64/hex wrapper depth.

All positive cases enter through the lane's real ``solve_set``.  The test gives labels an empty temporary
challenge root, so every new wrapper-shape name must remain unsure and cannot inherit a local runtime verdict.

Before ``crib_decode._deep_b64_hex`` (same machine, fresh process):
  depth 7 None 0.942859 s; depth 8 None 0.352387 s;
  depth 9 None 0.352555 s; depth 10 None 0.171284 s; depth 11 None 0.177635 s.

Run offline with:
  PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest tests/test_day31_warmups_deep_wrappers.py -q
"""
from __future__ import annotations

import base64
import os
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
os.environ["CTF_WORKDIR"] = tempfile.mkdtemp(prefix="day31-warmups-deep-")
os.environ.setdefault("CTF_TESTING", "1")
sys.path[:0] = [str(REPO / "solvers" / "common"), str(REPO / "solvers" / "warmups")]

import crib_decode as C  # noqa: E402


SLUG = "fierce-final-flame-31"
PLAIN = (C.CRIB + SLUG).encode("ascii")
QUESTION = [{"id": "message", "artifact": "specimen.bin"}]
CONTEXT = {"challenge": "warmups-day-31"}


def _wrap(depth: int, first: str = "b64", plain: bytes = PLAIN):
    names = []
    value = plain
    name = first
    for _ in range(depth):
        names.append(name)
        value = base64.b64encode(value) if name == "b64" else value.hex().encode("ascii")
        name = "hex" if name == "b64" else "b64"
    return value, tuple(reversed(names))


def _solve(blob: bytes):
    C._READ_MEMO.clear()
    started = time.perf_counter()
    value = C.solve_set(QUESTION, {"specimen.bin": blob}, CONTEXT)["message"]
    return value, time.perf_counter() - started


def test_depths_seven_through_ten_are_truth_bearing_unsure_and_fast():
    seen = set()
    timings = []
    for first in ("b64", "hex"):
        for depth in range(7, 11):
            blob, chain = _wrap(depth, first)
            value, elapsed = _solve(blob)
            parsed = C.labels.parse(value)
            assert parsed is not None, (first, depth, value, C.LAST)
            assert parsed.options == [("exact_crib", SLUG)], (first, depth, parsed)
            assert parsed.key == "warmups.wrapper/" + "+".join(chain), (first, depth, parsed.key, chain)
            assert C.LAST["route"] == "deep_wrapper" and C.LAST["chains"] == [list(chain)]
            assert elapsed < 0.050, (first, depth, elapsed)
            seen.add(parsed.key)
            timings.append(elapsed)
    assert len(seen) == 8  # a verdict applies only to its exact depth and phase shape
    print("day31 warmups deep wrappers: depth7-10 max %.6fs" % max(timings))


def test_existing_depths_stay_on_the_established_plain_route():
    for first in ("b64", "hex"):
        for depth in (5, 6):
            blob, _chain = _wrap(depth, first)
            value, _elapsed = _solve(blob)
            assert value == SLUG and C.labels.parse(value) is None, (first, depth, value, C.LAST)
            assert C.LAST["route"] == "crib", (first, depth, C.LAST)


def test_depth_eleven_and_noncanonical_endpoints_fail_closed_fast():
    for first in ("b64", "hex"):
        blob, _chain = _wrap(11, first)
        value, elapsed = _solve(blob)
        assert value is None and "beyond the bounded 10-layer" in (C.LAST.get("note") or ""), C.LAST
        assert elapsed < 0.050, (first, elapsed)

    # Complete decoding is not enough: an extra line, a concatenation, and ignored whitespace are not exact
    # canonical wrapper/endpoint evidence.  Exercise the focused reader directly so these deliberate misses do
    # not pay the unrelated legacy graph's miss budget in this focused unit.
    extra, _ = _wrap(7, "b64", PLAIN + b"\nsecond-slug-line-00")
    valid, _ = _wrap(7, "b64")
    assert C._deep_b64_hex(extra) is None
    assert C._deep_b64_hex(valid + valid) is None
    assert C._deep_b64_hex(valid[:20] + b"\n" + valid[20:]) is None


def main() -> int:
    test_depths_seven_through_ten_are_truth_bearing_unsure_and_fast()
    test_existing_depths_stay_on_the_established_plain_route()
    test_depth_eleven_and_noncanonical_endpoints_fail_closed_fast()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
