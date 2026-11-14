#!/usr/bin/env python3
"""A real .evtx whose FILE header is stale (the integration of round 2, 2026-10-08).

  .venv/bin/python tests/real/test_real_evtx_header.py

Group b's reviewer asked group a's reader to be checked against a file header that lags behind the
log (Windows updates it only on a clean close: a log copied from a running or crashed machine says
one chunk and record 1). solvers/toolkits/windows.py walks every ElfChnk by offset, so the header's
counts must not change what it reads. Here the header of each cached Security/Sysmon log is set to
"one chunk, next record 1, last chunk 0" and the events are compared with the untouched file's.

Reads the untracked cache <main checkout>/challenges/_realdata/windows (or $CTF_REALDATA);
prints SKIP and exits 0 without it. Nothing is written, nothing is run, no request is made.
"""
import importlib.util
import struct
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
FAILED = []


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f"   [{str(detail)[:300]}]"))
    if not ok:
        FAILED.append(name)


def main():
    import fetch_d
    folder = fetch_d.have("windows")
    logs = sorted(folder.glob("*.evtx"))[:8] if folder else []
    if not logs:
        print("SKIP no cache: challenges/_realdata/windows has no .evtx (tests/real/fetch_a.py fills it)")
        return 0
    spec = importlib.util.spec_from_file_location("huntress_real_windows", REPO / "solvers" / "toolkits" / "windows.py")
    w = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = w
    spec.loader.exec_module(w)
    read = 0
    for p in logs:
        data = p.read_bytes()
        if len(data) > 8 * 1024 * 1024 or data[:8] != b"ElfFile\x00":
            continue
        whole, complete = w.evtx_events(data, deadline=time.monotonic() + 20, src=p.name)
        stale = bytearray(data)
        struct.pack_into("<Q", stale, 0x10, 0)      # LastChunkNumber
        struct.pack_into("<Q", stale, 0x18, 1)      # NextRecordIdentifier
        struct.pack_into("<H", stale, 0x2A, 1)      # NumberOfChunks
        got, complete2 = w.evtx_events(bytes(stale), deadline=time.monotonic() + 20, src=p.name)
        read += 1
        check(f"{p.name}: {len(whole)} events, the same {len(got)} under a stale file header, as complete as before",
              whole == got and complete == complete2 and len(whole) > 0, (len(whole), len(got), complete, complete2))
        check(f"{p.name}: the record count does not come from the header",
              w.evtx_record_count(data) == w.evtx_record_count(bytes(stale)), (w.evtx_record_count(data), w.evtx_record_count(bytes(stale))))
    check("at least one log was read", read > 0, [p.name for p in logs])
    if FAILED:
        print(f"\n{len(FAILED)} FAILED: " + "; ".join(FAILED))
        print("TEST_REAL_EVTX_HEADER FAIL")
        return 1
    print(f"TEST_REAL_EVTX_HEADER PASS ({read} logs, pyevtx-rs {'loaded' if w.evtx_rs() else 'absent: python-evtx'})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
