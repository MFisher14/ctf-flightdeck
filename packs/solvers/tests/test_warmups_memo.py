#!/usr/bin/env python3
"""Offline test of backlog row 183: crib_decode.readings() memoized by payload.

  .venv/bin/python tests/test_warmups_memo.py

No network and no token. Every saved Warmups Mastery blob of Days 1 to 9 is split into its records
and each payload is read three ways: with the memo cleared, again from the memo, and after a caller
changed the copy it was given. All three must be the same dict. A call that ran out of time must
not be kept. The full replays to the keys are tools/preflight.py's regression (memo on, one process
per attempt). Skips cleanly when challenges/ holds no Warmups Mastery. Last line `ok`, or exit 1.
"""
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "warmups"))
import crib_decode as C  # noqa: E402

fails = []


def check(ok, what):
    if not ok:
        fails.append(what)
        print("FAIL", what)


def payloads():
    out = []
    for blob in sorted(REPO.glob("challenges/day-0*/warmups-day-0*/mastery/**/artifact/**/*.txt")):
        for line in blob.read_bytes().splitlines():
            line = line.strip()
            if b":" in line[:6]:
                line = line.split(b":", 1)[1].strip()
            if line:
                out.append(line)
    return out


def main():
    items = payloads()
    if not items:
        print("skip: no saved Warmups Mastery under challenges/")
        print("ok")
        return 0
    distinct = list(dict.fromkeys(items))
    for p in distinct:
        C._READ_MEMO.clear()
        fresh = C.readings(p, time.perf_counter() + 10)
        again = C.readings(p, time.perf_counter() + 10)
        check(fresh == again, f"memo hit differs for {p[:24]!r}")
        again["x"] = ("mutated",)
        check(C.readings(p, time.perf_counter() + 10) == fresh, f"caller's change leaked for {p[:24]!r}")
    C._READ_MEMO.clear()
    C.readings(distinct[0], time.perf_counter() - 1)        # deadline already passed
    check(distinct[0] not in C._READ_MEMO, "a call past its deadline was kept")
    C.READ_MEMO_MAX, keep = 3, C.READ_MEMO_MAX
    try:
        for p in distinct[:5]:
            C.readings(p, time.perf_counter() + 10)
        check(len(C._READ_MEMO) <= 3, "the memo grew past its bound")
    finally:
        C.READ_MEMO_MAX = keep
    print(f"payloads={len(items)} distinct={len(distinct)} fails={len(fails)}")
    print("ok" if not fails else "FAILED")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
