#!/usr/bin/env python3
"""speed-1 review FIX (Binary): the hcfg.containers memo and generic._build_pool's `reuse` must never serve an
INCOMPLETE reading. A first reading that hit the long-key search cap (LONG_HEADERS / LONG_TOTAL) misses the real
long-key record; before the fix the memo (and _build_pool's reuse of `every`) returned that reading again, so a
decoy config was answered PLAIN where af3dbf7 answers None.

  .venv/bin/python tests/test_day27_speed1_review_binary.py

These are the two review repros (scratchpad/speed1_review/repro_containers.py and repro_pool.py) turned into a
deterministic, load-proof regression test. Timing is removed from the equation: hcfg.LONG_COSTLY is forced
negative so EVERY long-key search counts against LONG_HEADERS, so the per-pass cap trips on a fixed machine and a
loaded one alike. Checks:
 1. containers(): a first reading that hit the cap misses the real long-key record; it is NOT memoised, so a
    second reading finds it (before the fix: second reading served the stale [] again). And _LONG_STATE["skipped"]
    is set by the capped pass.
 2. _build_pool / _choose_config: the member holds a CRC-valid day-27 decoy and, behind the cap, the sample's real
    day-27 record with other contents. The first reading lists only the decoy; the fix forces a genuine re-read
    (reuse=None), both records enter the pool, they differ -> config None. Before the fix the decoy was the config
    (PLAIN).
 3. the settings memo is keyed on the objects held (identity, a is b), not id() (issue 2): _same_settings is
    identity-based.
The fix only RESTRICTS plain: it moves no saved answer (that is tools/preflight.py --regress's job, run separately).
Offline, no token, no Game Master request, nothing written under challenges/. Prints one line per check and
`ok N passed`; exits 1 on a failure.
"""
import json
import os
import random
import struct
import sys
import tempfile
import zlib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.dont_write_bytecode = True
TMP = Path(tempfile.mkdtemp(prefix="test_day27_speed1_review_binary_"))
os.environ["CTF_STATE_DIR"] = str(TMP / "state")
os.environ.setdefault("CTF_WORKDIR", str(TMP / "challenges"))
os.environ.pop("CTF_PLATFORM_URL", None)
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(REPO / "solvers" / "common"))
sys.path.insert(0, str(REPO / "solvers" / "binary"))
import generic   # noqa: E402
import hcfg       # noqa: E402

FAILED, PASSED = [], []


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f"   [{str(detail)[:600]}]"))
    (PASSED if ok else FAILED).append(name)


def _record(payload, crc, key=0x00, version=1):
    return hcfg.MAGIC + bytes([version, key]) + struct.pack("<HI", len(payload), crc) + payload


def _lk(js, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(js))


def _reset_long():
    hcfg._LONG_MEMO.clear()
    hcfg._CONTAINERS.clear()
    hcfg._LONG_STATE.update(spent=0.0, last=0.0, headers=0, skipped=False)


def _campaigns(cs):
    return [(c["offset"], c["how"], (c.get("json") or {}).get("campaign")) for c in cs]


# --------------------------------------------------------------------------- the member builders

def _long_decoys_then_real(rng, n_decoys):
    """n_decoys long-key records with a BROKEN CRC-32 (each a costly search that yields nothing), then the
    sample's real long-key record (CRC-32 valid, an 11-byte repeating key)."""
    blob = bytearray(b"\x00" * 64)
    for d in range(n_decoys):
        js = json.dumps({"campaign": f"BR27-decoy{d}", "family": "x", "note": "padding text " * 6},
                        separators=(",", ":")).encode()
        blob += _record(_lk(js, bytes(rng.randrange(1, 256) for _ in range(13))),
                        (zlib.crc32(js) ^ 0x5A5A) & 0xFFFFFFFF) + b"\x00" * 16
    real = json.dumps({"campaign": "BR27-real", "family": "stage", "c2_url": "https://real.example/x",
                       "note": "the operator keeps the beacon alive"}, separators=(",", ":")).encode()
    blob += _record(_lk(real, bytes(rng.randrange(1, 256) for _ in range(11))), zlib.crc32(real) & 0xFFFFFFFF)
    return bytes(blob)


def _decoy_then_capped_real(rng, n_decoys):
    """A non-ELF carrier (so no overlay re-read masks the bug), a RAW single-byte-XOR CRC-valid day-27 decoy, then
    n_decoys costly long-key decoys, then the real day-27 long-key record with OTHER contents."""
    decoy = json.dumps({"campaign": "BR27-003", "family": "stage", "c2_url": "https://decoy.example/a",
                        "domain": "decoy.example", "mutex": "Global_Decoy"}, separators=(",", ":")).encode()
    dk = 0x11 + 0x10 * (27 - 5) + 3 & 0xFF
    blob = bytearray(b"DATA" + b"\x00" * 60)
    blob += _record(bytes(b ^ dk for b in decoy), zlib.crc32(decoy) & 0xFFFFFFFF, key=dk) + b"\x00" * 16
    for d in range(n_decoys):
        js = json.dumps({"campaign": "BR27-00%d" % d, "family": "x", "note": "padding text " * 6},
                        separators=(",", ":")).encode()
        blob += _record(_lk(js, bytes(rng.randrange(1, 256) for _ in range(13))),
                        (zlib.crc32(js) ^ 0x5A5A) & 0xFFFFFFFF) + b"\x00" * 16
    real = json.dumps({"campaign": "BR27-003", "family": "stage", "c2_url": "https://real.example/x",
                       "domain": "real.example", "mutex": "Global_Real"}, separators=(",", ":")).encode()
    blob += _record(_lk(real, bytes(rng.randrange(1, 256) for _ in range(11))), zlib.crc32(real) & 0xFFFFFFFF)
    blob += b"\x00" * 64
    return bytes(blob)


# --------------------------------------------------------------------------- the checks

def main():
    saved_costly = hcfg.LONG_COSTLY
    hcfg.LONG_COSTLY = -1.0    # make EVERY long-key search count against LONG_HEADERS: the cap trips deterministically
    try:
        # warm the lazy module globals once, as an earlier solve in the process would
        hcfg._bigram()
        _reset_long()
        hcfg.containers(_long_decoys_then_real(random.Random(1), hcfg.LONG_HEADERS), others=True)

        # ---- check 1: the capped first reading is not memoised; a second reading finds the real record ----
        blob = _long_decoys_then_real(random.Random(11), hcfg.LONG_HEADERS)
        _reset_long()
        first = hcfg.containers(blob, others=True)
        skipped_after_first = hcfg._LONG_STATE.get("skipped")
        second = hcfg.containers(blob, others=True)
        got_first = [c for c in first if (c.get("json") or {}).get("campaign") == "BR27-real"]
        got_second = [c for c in second if (c.get("json") or {}).get("campaign") == "BR27-real"]
        check("the first reading hit the cap and missed the real long-key record",
              got_first == [], _campaigns(first))
        check("the capped pass set _LONG_STATE['skipped']", skipped_after_first is True, skipped_after_first)
        check("the second reading finds the real record (the incomplete reading was NOT served again)",
              len(got_second) == 1, _campaigns(second))

        # ---- check 2: _choose_config answers None for the decoy (not the decoy PLAIN) ----
        members = [("d27--sample-variant-003.bin", _decoy_then_capped_real(random.Random(5), hcfg.LONG_HEADERS))]
        _reset_long()
        cfg, idx, why = generic._choose_config(members, 27)
        answered = None if cfg is None else (cfg.get("json") or {}).get("c2_url")
        check("the decoy config is None, not answered PLAIN (the review HIGH issue)",
              cfg is None, f"answered c2_url={answered!r}; why={why[:160]}")

        # ---- check 3: the settings memo is identity-keyed (issue 2), not id()-keyed ----
        same = getattr(hcfg, "_same_settings", None)
        if same is None:
            check("issue 2: hcfg._same_settings exists (identity-keyed settings memo)", False, "missing")
        else:
            a, b = [0], [0]   # equal by value, distinct objects
            ok = same((a,), (a,)) is True and same((a,), (b,)) is False and same((a, b), (a,)) is False
            check("issue 2: _same_settings compares object identity (a is b), not value/id()", ok)
    finally:
        hcfg.LONG_COSTLY = saved_costly

    print(f"\n{'ok' if not FAILED else 'FAIL'} {len(PASSED)} passed" + (f", {len(FAILED)} failed" if FAILED else ""))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
