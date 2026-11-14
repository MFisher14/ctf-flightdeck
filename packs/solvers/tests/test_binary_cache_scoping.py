#!/usr/bin/env python3
"""Non-fake cross-artifact cache scoping for the Binary runtime.

Runs the shipped readers in one process.  It carries a fixed, real pair of different
105-byte blobs with the same CRC-32.  One contains a valid raw-DEFLATE HCFG record and
the other is junk.  It also builds two stated-layout members with the same name, length
and final 4096 bytes but with the stated magic present in only one.
"""
from __future__ import annotations
import sys as _b240_sys  # noqa: E402
if "pytest" in _b240_sys.modules and __name__ != "__main__":
    # B-240 carry: a check()-style script. Its checks never fail a pytest run and its module-level setup changes
    # os.environ for the whole worker, so pytest does not collect it; tests/test_carry_checklist.py runs it as a
    # script (exit code and FAIL lines) and reports its saved-data sections as not run.
    import pytest
    pytest.skip("script-style test: run as a script by tests/test_carry_checklist.py", allow_module_level=True)

import hashlib
import json
import os
import struct
import sys
import tempfile
import zlib
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
TMP = Path(tempfile.mkdtemp(prefix="binary-cache-scoping-"))
os.environ["CTF_WORKDIR"] = str(TMP / "challenges")
os.environ["CTF_STATE_DIR"] = str(TMP / "state")
os.environ.pop("CTF_PLATFORM_URL", None)
sys.dont_write_bytecode = True
sys.path[:0] = [str(REPO / "solvers" / "common"), str(REPO / "solvers" / "binary")]

import generic  # noqa: E402
import needles  # noqa: E402
import packed_tail  # noqa: E402
import patch_diff  # noqa: E402
import record_select  # noqa: E402
import stated_layout  # noqa: E402


FAILED = []


def check(label, condition, detail=""):
    print(("ok   " if condition else "FAIL ") + label
          + ("" if condition or not detail else "  [" + str(detail)[:500] + "]"))
    if not condition:
        FAILED.append(label)


# Fixed chosen-prefix collision, generated independently with two BLAKE2s-prefix
# families.  GOOD has a valid raw-DEFLATE HCFG record at byte 8; JUNK has none.
GOOD = bytes.fromhex(
    "ec9e35461cd60c49f3707673670cac65d0fca8fe5cabd8c8c046d1c0c2ccbe3"
    "8bb58983939b1263131b1b8b6d8d4cec6c00224666f676a0212ab3735d0484eac"
    "37d1042ab735a9b7b05737b0b53005aa5451b6052ab354555554caaeabc3afbcce"
    "40d1a20e6e8b0e00")
JUNK = bytes.fromhex("36606d6bffaeb7d8" + "a5" * 97)


def hcfg(cfg, key=0x61):
    plain = json.dumps(cfg, separators=(",", ":")).encode()
    return (b"HCFG" + struct.pack("<BBHI", 1, key, len(plain), zlib.crc32(plain))
            + bytes(byte ^ key for byte in plain))


P_A1 = (
    "Find the final TS21 overlay. Read HCFG stage length u32le at +8 and note length u16le at +12; "
    "bytes +16..+47 are the note SHA-256, the HCFG stage starts at +48, and note follows it. "
    "Verify exact end bounds and note SHA-256, then use the HCFG stage at offset 0. "
)


def stated_member(record, note, magic=b"TS21"):
    head = (magic + struct.pack("<I", 1) + struct.pack("<I", len(record))
            + struct.pack("<H", len(note)) + b"\0\0")
    return b"host-prefix\0" + head + hashlib.sha256(note).digest() + record + note


def main():
    check("fixture is a real equal-length CRC-32 collision",
          GOOD != JUNK and len(GOOD) == len(JUNK)
          and zlib.crc32(GOOD) == zlib.crc32(JUNK) == 0x80CC4DAA)

    # Public layer path: this was an observable wrong cross-artifact cache hit.
    packed_tail._CACHE.clear()
    good_layers = packed_tail.tail_layers(GOOD)
    junk_after = packed_tail.tail_layers(JUNK)
    packed_tail._CACHE.clear()
    junk_cold = packed_tail.tail_layers(JUNK)
    check("packed layer exists only in the artifact that carries it",
          len(good_layers) == 1 and good_layers[0][1].startswith(b"HCFG")
          and junk_after == junk_cold == [], (good_layers, junk_after, junk_cold))

    # The literal index used to reuse GOOD's places for JUNK because both the
    # artifact CRC and hash(needles) were only collision-prone summaries.
    mark = GOOD[:4]
    needles._CACHE.clear()
    good_places = needles.index(GOOD, [mark])[mark]
    junk_after = needles.index(JUNK, [mark])[mark]
    needles._CACHE.clear()
    junk_cold = needles.index(JUNK, [mark])[mark]
    check("needle places are scoped to exact artifact bytes",
          good_places == [0] and junk_after == junk_cold == [],
          (good_places, junk_after, junk_cold))

    member_good = record_select.members_digest([("same.bin", GOOD)])
    member_junk = record_select.members_digest([("same.bin", JUNK)])
    pool_good = record_select._pool_scope([
        {"_members_digest": member_good, "_member_name": "same.bin", "plain": GOOD}])
    pool_junk = record_select._pool_scope([
        {"_members_digest": member_junk, "_member_name": "same.bin", "plain": JUNK}])
    check("accepted-label delivery and record-pool scopes resist the CRC-32 collision",
          member_good != member_junk and pool_good != pool_junk,
          (member_good, member_junk, pool_good, pool_junk))

    patch_good = patch_diff._pair_scope(b"same-a", b"same-b", [("same.bin", GOOD)])
    patch_junk = patch_diff._pair_scope(b"same-a", b"same-b", [("same.bin", JUNK)])
    check("patch-difference accepted-label scope resists the CRC-32 collision",
          patch_good != patch_junk, (patch_good, patch_junk))

    # These three caches all feed production readers.  Even when both fixtures
    # happen to return None for a reader, the two exact artifacts must occupy
    # different slots; otherwise a valid result in one can bleed into the other.
    for label, cache, reader in (
        ("RC4 whole-record", generic._RC4W_CACHE, generic._rc4_children),
        ("SHA overlay", generic._OVERLAY_CACHE, generic._overlay_record),
        ("resource overlay", generic._RES_CACHE, generic.resource_overlay),
    ):
        cache.clear()
        reader(GOOD)
        reader(JUNK)
        check(label + " cache keeps the two CRC-colliding artifacts distinct",
              len(cache) == 2, list(cache))

    # stated_layout formerly hashed only the last 4096 bytes.  A long note puts
    # the magic/header before that suffix, so changing TS21 to US21 left the old
    # cache key identical and returned the first member's verified config.
    cfg = {"campaign": "BR21-cache", "domain": "cache.example.invalid"}
    note = b"N" * 5000
    valid = stated_member(hcfg(cfg), note)
    at = valid.find(b"TS21")
    invalid = valid[:at] + b"US21" + valid[at + 4:]
    spec = stated_layout._spec_of((P_A1,))
    check("stated-layout fixture shares name, length and final 4096 bytes",
          spec is not None and len(valid) == len(invalid) and valid[-4096:] == invalid[-4096:]
          and valid != invalid)
    stated_layout._CACHE.clear()
    first = stated_layout.read([("sample.bin", valid)], spec)
    second = stated_layout.read([("sample.bin", invalid)], spec)
    stated_layout._CACHE.clear()
    cold = stated_layout.read([("sample.bin", invalid)], spec)
    check("stated-layout result cannot bleed across an equal-tail artifact",
          first is not None and first.get("config", {}).get("json") == cfg
          and second == cold is None, (first and first.get("offset"), second, cold))

    if FAILED:
        print(f"FAILED: {len(FAILED)} of 10 checks")
        return 1
    print("PASS: 10 Binary cache-scoping checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
