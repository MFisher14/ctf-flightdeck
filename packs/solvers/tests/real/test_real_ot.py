#!/usr/bin/env python3
"""Oracle tests for the OT real-capture corpus (B-204).

  .venv/bin/python tests/real/test_real_ot.py        run every check, print ok/FAIL/SKIP, exit 1 on FAIL

Two sections:

  synthetic  builds a minimal valid capture of every supported protocol in memory
             (tests/real/_ot_fixtures.py) and asserts the matching repo parser recognises it, through
             the oracle dispatch (tests/real/_ot_oracle.py). Needs no corpus, so it gates every run.

  corpus     when $CTF_REALDATA/ot/ exists (the operator ran tests/real/fetch_ot.py), runs the same
             oracle on every real capture named in tests/real/manifest_ot.json and asserts the parser
             recognises the labelled protocol. A row whose file is absent is a FAIL (the corpus is
             incomplete); a protocol with no public capture is listed under 'missing' and reported, not
             failed. Without the corpus one SKIP line is printed (the realdata pytest item owns it).

The corpus is untrusted data: the oracle reads its bytes and runs nothing from it. Needs scapy (the
oracle reads pcaps with it); the pytest wrapper marks this needs_tool("py:scapy").
"""
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
os.environ.setdefault("CTF_EVENT", "csctf")      # the ICS parsers resolve the event flag format
os.environ.setdefault("CTF_TESTING", "1")
sys.path.insert(0, str(HERE))

import _corpus  # noqa: E402
import _ot_fixtures  # noqa: E402
import _ot_oracle  # noqa: E402

FAILED: list[str] = []


def check(label: str, ok: bool, detail="") -> bool:
    print(("ok   " if ok else "FAIL ") + label + ("" if ok or not detail else f"   [{str(detail)[:300]}]"))
    if not ok:
        FAILED.append(label)
    return ok


def run_synthetic(dest: Path) -> None:
    caps = _ot_fixtures.write_captures(dest)
    for proto in sorted(caps):
        engine = _ot_fixtures.ENGINE_FOR[proto]
        try:
            det = _ot_oracle.detect(engine, caps[proto])
        except _ot_oracle.OracleError as exc:
            check(f"synthetic {proto}: {engine}", False, exc)
            continue
        check(f"synthetic {proto}: {engine} recognises it", det.recognised(proto) and det.count >= 1, det)


def run_corpus() -> None:
    root = _corpus.root()
    ot = root / "ot"
    if not ot.is_dir() or not any(ot.iterdir()):
        print(f"SKIP tests/real: no OT corpus ({ot} absent); run tests/real/fetch_ot.py")
        return
    manifest = json.loads((HERE / "manifest_ot.json").read_text())
    for row in manifest["files"]:
        p = root / "ot" / row["proto"] / row["name"]
        if not p.is_file():
            check(f"corpus {row['proto']}/{row['name']} present", False,
                  "absent; complete tests/real/fetch_ot.py")
            continue
        try:
            det = _ot_oracle.detect(row["engine"], p)
        except Exception as exc:  # noqa: BLE001 - a parser crash on a real capture is a FAIL, reported
            check(f"corpus {row['proto']}: {row['engine']}", False, f"{type(exc).__name__}: {exc}")
            continue
        ok = det.recognised(row["expect"]) and det.count >= row.get("min_messages", 1)
        check(f"corpus {row['proto']}: {row['engine']} recognises {row['expect']}", ok, det)
    for m in manifest.get("missing", []):
        print(f"ok   corpus: {m.get('proto', '?')} has no public capture (listed missing): "
              f"{m.get('reason', '')}")


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="test_real_ot_"))
    try:
        run_synthetic(tmp / "syn")
        run_corpus()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if FAILED:
        print(f"\ntest_real_ot: {len(FAILED)} FAILED")
        for f in FAILED:
            print("  " + f)
        return 1
    print("\nok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
