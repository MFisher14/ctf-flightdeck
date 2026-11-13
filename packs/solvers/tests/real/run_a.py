#!/usr/bin/env python3
"""Run every group-a real-artifact test and print one line each.

  .venv/bin/python tests/real/run_a.py            the eight tests (about 80 s with the cache, 5 s without)
  .venv/bin/python tests/real/run_a.py --toolkit  also the five toolkits' own synthetic tests (tests/test_tk_*.py)

Exit 0 when every test exits 0 (a test whose cache folder is absent SKIPs and exits 0). Offline.
"""
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
TESTS = ["test_fixes_a.py", "test_review_a.py", "test_real_network.py", "test_real_email.py", "test_real_maldoc.py", "test_real_windows.py",
         "test_real_memory.py", "test_real_drill_a.py"]
KITS = ["network", "email", "maldoc", "windows", "memory"]


def main(argv) -> int:
    jobs = [HERE / t for t in TESTS]
    if "--toolkit" in argv:
        jobs += [HERE.parent / f"test_tk_{k}.py" for k in KITS]
    bad = 0
    for path in jobs:
        t = time.time()
        r = subprocess.run([sys.executable, str(path)], capture_output=True, text=True, timeout=900)
        lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
        oks = sum(1 for ln in lines if ln.startswith("ok "))
        skip = next((ln for ln in lines if ln.startswith("SKIP")), "")
        fails = [ln for ln in lines if ln.startswith("FAIL")]
        state = "FAIL" if r.returncode else ("SKIP" if skip and not oks else "ok  ")
        print(f"{state} {path.name:<26} exit {r.returncode}  {oks} checks  {time.time() - t:5.1f} s  {(skip or (lines[-1] if lines else ''))[:90]}")
        for ln in fails[:8]:
            print("     " + ln[:200])
        if r.returncode and not fails:
            print("     " + (r.stderr.strip().splitlines() or ["no output"])[-1][:200])
        bad += bool(r.returncode)
    print(f"RUN_A tests={len(jobs)} failed={bad}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
