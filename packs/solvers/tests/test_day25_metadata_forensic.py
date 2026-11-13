#!/usr/bin/env python3
"""Day 25 look-ahead build, Metadata Forensics (docs/retro/day-25/predictions-metadata-forensics.md).

  .venv/bin/python tests/test_day25_metadata_forensic.py

Offline; no Game Master request, no token. The labels state is the tracked seed alone (an empty runtime
ledger under a temp CTF_WORKDIR), so a natural-name EVTX field is never plain. What is held:

  GAP #1 (the measured STOP). The EVTX first-record follow-up fields under their NATURAL names
  (evtx.event_id, evtx.channel, evtx.provider_name, evtx.computer, evtx.record_id, evtx.level, evtx.task,
  evtx.user_id, evtx.time_created, and the channel_name/computer_name aliases) return UNSURE with the true
  value among the options, where the armed tree returned None; evtx.record_count stays PLAIN (judged Day 24);
  evtx.first_event_id is unchanged; a non-EVTX file is None. NEVER a wrong plain answer.

  Part 2 (readers_forensic.py extensions, unsure-only):
    * EWF / EnCase (.E01) classic EVF header: ewf.segment_number, ewf.format, ewf.first_section_type,
      ewf.signature_hex are unsure with the header's values; a non-EWF file and an EWF2/Ex01 header are None.
    * EVTX beyond the first record: evtx.record_<N>_<field> and evtx.second_record_<field> are unsure with
      the Nth record's value; a record past the end is None; a non-EVTX file is None.

The EVTX specimen is the real Day-24 events-001.evtx, found through git's common dir (so it works whether the
tests run from the main checkout or a worktree); if it is not present the EVTX checks are skipped, and the
EWF checks (built here from the specification) always run.
"""
import io
import subprocess
import sys
import tempfile
import struct
import zipfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
LANE = REPO / "solvers" / "metadata-forensics"
TMP = Path(tempfile.mkdtemp(prefix="test_day25_metadata_forensic_"))
EMPTY = TMP / "seed-only"
(EMPTY / "_ledger").mkdir(parents=True)
sys.path.insert(0, str(REPO / "solvers" / "common"))
sys.path.insert(0, str(LANE))
import os                        # noqa: E402
os.environ["CTF_WORKDIR"] = str(EMPTY)      # the tracked seed alone, never a runtime ledger
import labels                    # noqa: E402
labels._default_root = None
import properties_strict as M    # noqa: E402

FAILED = []
PASSED = [0]
EXACT = {"kind": "exact_text", "syntax": "exact artifact-derived value only, without quotes or explanation"}
INT = {"kind": "integer", "syntax": "a base-10 integer, digits only"}


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:300]}]"))
    if ok:
        PASSED[0] += 1
    else:
        FAILED.append(label)


def ask(data, prop, member, fmt=EXACT, stem="d25-x-001"):
    aid = f"{stem}-{prop.replace('.', '-').replace('_', '-')}"
    q = {"qid": aid, "answer_id": aid, "question": f"Inspect `{member}`. Determine {prop} for {member}.",
         "artifact": f"metadata-day-25-evidence.zip -> {member}", "member": member, "answer_format": fmt,
         "normalization": "trim"}
    zero = b"PK\x05\x06" + b"\x00" * 18
    files = {f"metadata-day-25-evidence.zip -> {member}": data, member: data, "metadata-day-25-evidence.zip": zero}
    ctx = {"set": 1, "delivery_name": "metadata-day-25-evidence.zip", "delivery": zero}
    old, sys.stderr = sys.stderr, io.StringIO()
    try:
        out = M.solve_set([q], files, ctx)
    finally:
        sys.stderr = old
    return out[aid]


def unsure(v):
    return labels.parse(v) if isinstance(v, str) and labels.is_unsure(v) else None


def values(v):
    u = unsure(v)
    return [str(x) for _, x in u.options] if u else []


def is_plain(v):
    return v is not None and unsure(v) is None


def check_unsure_has(prop, v, truth):
    """UNSURE with truth among the options, and never a wrong plain answer."""
    vals = values(v)
    check(f"{prop} unsure with truth {truth!r}", unsure(v) is not None and str(truth) in vals, f"got {v!r}")
    check(f"{prop} never wrong-plain", not is_plain(v), f"got {v!r}")


# ------------------------------------------------------------------ EWF / EnCase (synthetic classic EVF)

def evf(segment=1, first_section=b"header", sig=b"EVF\x09\x0d\x0a\xff\x00"):
    out = sig + b"\x01" + struct.pack("<H", segment) + struct.pack("<H", 0)
    out += first_section.ljust(16, b"\x00") + struct.pack("<QQ", 0, 76) + b"\x00" * 40 + b"\x00" * 4
    return out + b"\x00" * 200


def test_ewf():
    d = evf(segment=7, first_section=b"header")
    check_unsure_has("ewf.segment_number", ask(d, "ewf.segment_number", "image-001.E01", INT), 7)
    check_unsure_has("ewf.format", ask(d, "ewf.format", "image-001.E01"), "ewf")
    check_unsure_has("ewf.first_section_type", ask(d, "ewf.first_section_type", "image-001.E01"), "header")
    check_unsure_has("ewf.signature_hex", ask(d, "ewf.signature_hex", "image-001.E01"), "455646090d0aff00")
    # logical evidence (L01) signature -> format 'lef'
    dl = evf(first_section=b"header", sig=b"LVF\x09\x0d\x0a\xff\x00")
    check_unsure_has("lvf.format", ask(dl, "ewf.format", "logical-001.L01"), "lef")
    # a non-EWF file and an EWF2/Ex01 header are None (never a wrong read)
    check("ewf.segment_number None on non-EWF",
          ask(b"MZ" + b"\x00" * 300, "ewf.segment_number", "x.bin", INT) is None)
    ev2 = b"EVF2\x0d\x0a\x81\x00" + b"\x00" * 100
    check("ewf.segment_number None on EWF2/Ex01",
          ask(ev2, "ewf.segment_number", "x.Ex01", INT) is None)


# ------------------------------------------------------------------ EVTX (real Day-24 specimen)

def find_evtx():
    try:
        common = subprocess.run(["git", "rev-parse", "--git-common-dir"], cwd=str(REPO),
                                capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception:
        return None
    if not common:
        return None
    main_checkout = (REPO / common).resolve().parent
    zp = (main_checkout / "challenges" / "day-24" / "metadata-forensics-day-24-event-horizon"
          / "artifact" / "metadata-day-24-evidence.zip")
    if not zp.is_file():
        return None
    try:
        return zipfile.ZipFile(str(zp)).read("events-001.evtx")
    except Exception:
        return None


def nth_record_truth(evtx_bytes, n):
    """(event_id, channel, record_num) of the n-th (1-based) record, via python-evtx."""
    import Evtx.Evtx as E
    import re
    tf = tempfile.NamedTemporaryFile(suffix=".evtx", delete=False)
    tf.write(evtx_bytes)
    tf.close()
    try:
        old, sys.stderr = sys.stderr, io.StringIO()
        try:
            with E.Evtx(tf.name) as log:
                for i, rec in enumerate(log.records(), 1):
                    if i == n:
                        x = rec.xml()
                        eid = re.search(r"<EventID[^>]*>(\d+)</EventID>", x)
                        ch = re.search(r"<Channel>([^<]*)</Channel>", x)
                        return (eid.group(1) if eid else None, ch.group(1) if ch else None, rec.record_num())
        finally:
            sys.stderr = old
    finally:
        os.unlink(tf.name)
    return (None, None, None)


@pytest.fixture
def evtx_bytes():
    data = find_evtx()
    if data is None:
        pytest.skip("Day-24 events-001.evtx specimen not found (challenges/ absent in this checkout)")
    return data


def test_evtx(evtx_bytes):
    mem = "events-001.evtx"
    e1, c1, rid1 = nth_record_truth(evtx_bytes, 1)
    # GAP #1: natural-name first-record fields -> unsure with the truth (were None on the armed tree)
    check_unsure_has("evtx.event_id", ask(evtx_bytes, "evtx.event_id", mem, INT), e1)
    check_unsure_has("evtx.channel", ask(evtx_bytes, "evtx.channel", mem), c1)
    check_unsure_has("evtx.channel_name", ask(evtx_bytes, "evtx.channel_name", mem), c1)
    check_unsure_has("evtx.record_id", ask(evtx_bytes, "evtx.record_id", mem, INT), rid1)
    # fields present in this record -> unsure with the value; never wrong-plain
    for p in ("evtx.provider_name", "evtx.computer", "evtx.computer_name", "evtx.level", "evtx.task",
              "evtx.time_created", "evtx.first_event_id"):
        v = ask(evtx_bytes, p, mem)
        check(f"{p} answered (unsure, not None)", unsure(v) is not None, f"got {v!r}")
        check(f"{p} never wrong-plain", not is_plain(v), f"got {v!r}")
    # user_id may be absent on a system event (no <Security UserID>): None is correct, never a wrong plain
    v = ask(evtx_bytes, "evtx.user_id", mem)
    check("evtx.user_id unsure-or-None (never wrong-plain)", not is_plain(v), f"got {v!r}")
    # record_count carries the true count (3) and is never wrong. It is PLAIN once Day-24's name is in the
    # ledger/seed (the real runtime env); under this test's empty seed-only ledger it is unsure -- either way
    # the value is 3 and this build (new readers only) did not change it.
    rc = ask(evtx_bytes, "evtx.record_count", mem, INT)
    check("evtx.record_count value is the true 3 (plain or unsure), never wrong",
          (is_plain(rc) and str(rc) == "3") or ("3" in values(rc)), f"got {rc!r}")

    # Part 2: EVTX beyond the first record
    e2, c2, rid2 = nth_record_truth(evtx_bytes, 2)
    if e2 is not None:
        check_unsure_has("evtx.record_2_event_id", ask(evtx_bytes, "evtx.record_2_event_id", mem, INT), e2)
        check_unsure_has("evtx.second_record_event_id",
                         ask(evtx_bytes, "evtx.second_record_event_id", mem, INT), e2)
        if c2 is not None:
            check_unsure_has("evtx.record_2_channel", ask(evtx_bytes, "evtx.record_2_channel", mem), c2)
        check_unsure_has("evtx.record_2_record_id", ask(evtx_bytes, "evtx.record_2_record_id", mem, INT), rid2)
    # a record far past the end -> None (absent), never a guess
    check("evtx.record_999_event_id None (absent)",
          ask(evtx_bytes, "evtx.record_999_event_id", mem, INT) is None)
    # a non-EVTX file -> None on every reader
    check("evtx.event_id None on non-EVTX", ask(b"not an evtx file" * 8, "evtx.event_id", "x.bin", INT) is None)
    check("evtx.record_2_event_id None on non-EVTX",
          ask(b"not an evtx file" * 8, "evtx.record_2_event_id", "x.bin", INT) is None)


def main():
    test_ewf()
    evtx_bytes = find_evtx()
    if evtx_bytes is None:
        print("skip  EVTX checks: the Day-24 events-001.evtx specimen was not found (challenges/ absent)")
    else:
        test_evtx(evtx_bytes)
    print(f"\n{PASSED[0]} passed, {len(FAILED)} failed")
    if FAILED:
        for f in FAILED:
            print("  FAILED:", f)
        sys.exit(1)


if __name__ == "__main__":
    main()
