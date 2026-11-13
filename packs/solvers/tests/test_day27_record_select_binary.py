#!/usr/bin/env python3
"""Pins the Day 27 build KB-3 (Binary multi-record / patch-diff record selection):
solvers/binary/record_select.py (the added STATED selectors) and solvers/binary/patch_diff.py (the facts of the
difference between two records), wired into generic.answers.

  .venv/bin/python tests/test_day27_record_select_binary.py

Hermetic and offline: every sample is a synthetic HCFG record (re-encoded with the lane's own layout) in a
non-image member, a tmp challenges dir. The bright line (never-wrong): a PLAIN answer only when the stated
selector maps to EXACTLY ONE CRC-valid record that names the day; a soft reading (newest by timestamp, variant
N, the complement of a role) is a one-option labels.pick, never plain; ambiguity, an inversion word, a CRC-broken
record, a record of another day, and an unstated choice are None (or, for the established forms, a candidates
pick), NEVER a wrong plain value. Section G fuzzes random layouts: a plain answer must equal the intended record's.

Prints one line per check and `ok N passed`; exits 1 on a failure.
"""
import sys as _b240_sys  # noqa: E402
if "pytest" in _b240_sys.modules and __name__ != "__main__":
    # B-240 carry: a check()-style script. Its checks never fail a pytest run and its module-level setup changes
    # os.environ for the whole worker, so pytest does not collect it; tests/test_carry_checklist.py runs it as a
    # script (exit code and FAIL lines) and reports its saved-data sections as not run.
    import pytest
    pytest.skip("script-style test: run as a script by tests/test_carry_checklist.py", allow_module_level=True)
import io
import json
import os
import random
import struct
import sys
import tempfile
import zlib
from contextlib import redirect_stderr
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TMP = Path(tempfile.mkdtemp(prefix="test_day27_record_select_"))
sys.dont_write_bytecode = True
os.environ["CTF_STATE_DIR"] = str(TMP / "state")
os.environ["CTF_WORKDIR"] = str(TMP / "challenges")
for _n in ("CTF_PLATFORM_URL", "CTF_KINDS", "CTF_BINARY_FORMS"):
    os.environ.pop(_n, None)
sys.path.insert(0, str(REPO / "solvers" / "common"))
sys.path.insert(0, str(REPO / "solvers" / "binary"))
if str(REPO) not in sys.path:
    sys.path.append(str(REPO))          # the ctf package (appended: the engine dirs stay first)
from ctf import paths  # noqa: E402
# The saved Huntress attempts (read only), only from $CTF_REAL_CHALLENGES through ctf.paths; never derived from
# this checkout's location. Unset: None and the sections skip; set to a missing folder: FileNotFoundError.
SAVED_CHALLENGES = paths.saved_challenges_root()

import labels              # noqa: E402
import generic             # noqa: E402
import record_select as rs  # noqa: E402

DAY = 27
FAILED, PASSED = [], []


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f"   [{str(detail)[:400]}]"))
    (PASSED if ok else FAILED).append(name)


def make_record(obj, version=1, key=0x5a, crc_delta=0):
    payload = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    enc = bytes(b ^ key for b in payload)
    crc = (zlib.crc32(payload) + crc_delta) & 0xFFFFFFFF
    return b"HCFG" + bytes([version, key]) + struct.pack("<HI", len(enc), crc) + enc


def cfg(v=0, day=DAY, **extra):
    s = f"{v:03d}"
    obj = {"campaign": f"BR{day:02d}-{s}", "domain": f"node-{s}.day{day}.example.invalid",
           "url": f"https://node-{s}.day{day}.example.invalid/api/BR{day:02d}-{s}",
           "mutex": f"Global\\\\HuntressBR{day:02d}_{s}"}
    obj.update(extra)
    return obj


def member(records):
    out = b"\x00\x10junk-prefix\x00"
    for r in records:
        out += r + b"\x00\x00padding\x00\x00"
    return out


def answers_closed(prefix, questions, files, ctx=None):
    """generic.answers, then what evidence.closing() asks LAST for the ids still None: KB-3's patch-difference reader
    (generic.patch_diff_answers; fix round 2 of the review moved it out of generic.answers, after the stated wrapper,
    the sidecar, the stated definition and the tagged trailer). The two steps of the lane's path these checks read."""
    out = generic.answers(prefix, questions, files, ctx or {})
    still = [qq for qq in questions if out.get(generic._qid(qq)) is None]
    if still and hasattr(generic, "patch_diff_answers"):       # (a tree before fix round 2 read them in answers)
        out.update(generic.patch_diff_answers(prefix, still, files, ctx or {}))
    return out


def run(files, questions):
    buf = io.StringIO()
    with redirect_stderr(buf):
        return answers_closed(f"d{DAY}", questions, dict(files), {})


def q(qid, text, kind="exact_text"):
    return {"id": qid, "qid": qid, "question": text, "answer_format": {"kind": kind}}


def kind_of(v):
    if v is None:
        return "none"
    return "unsure" if labels.is_unsure(v) else "plain"


def opts(v):
    p = labels.parse(v)
    return [o[1] for o in (p.options if p else [])]


def plain_eq(v, want):
    return v == want and kind_of(v) == "plain"


def pick_eq(v, want):
    """A ONE-option pick of `want`, under a key tagged with the question text: the reading of a new hard selector
    in any wording but the generator's own, or a soft reading. Never plain until the judge accepts that wording."""
    p = labels.parse(v) if labels.is_unsure(v) else None
    return bool(p) and opts(v) == [want] and "+t" in p.key and not labels.is_candidate(v)


def is_frame(v):
    """Whether v is the generator's-frame reading of record_select (`.../recsel_frame_<kind>+t...`): a one-option pick
    like every other reading since the fourth review of fix round 2 (nothing of the module is plain)."""
    p = labels.parse(v) if labels.is_unsure(v) else None
    return bool(p) and "/recsel_frame_" in p.key


def frame_pick(v, want):
    """The generator's frame passed every check of the allow-list and offers the named record's value as its pick."""
    return pick_eq(v, want) and is_frame(v)


def not_frame(v):
    """Not plain, and not the frame reading: the allow-list refused the text as the generator's own wording."""
    return kind_of(v) != "plain" and not is_frame(v)


def answered_eq(v, want):
    """The record's own value as a plain answer or as a one-option pick, and never another value."""
    return plain_eq(v, want) or pick_eq(v, want)


def cid(f):
    return f"d{DAY}_analysis_config_{f}"


def ask(files, text, field="campaign"):
    return run(files, [q(cid(field), text)])[cid(field)]


def never_plain_wrong(v, allowed):
    """No wrong plain: v is None, unsure, or a plain value in `allowed`."""
    return v is None or kind_of(v) != "plain" or v in allowed


# records used throughout: three records of the day, distinct domains
R = [make_record(cfg(0), version=1, key=0x41), make_record(cfg(1), version=2, key=0x42),
     make_record(cfg(2), version=3, key=0x43)]
CAMP = ["BR27-000", "BR27-001", "BR27-002"]
DOM = [f"node-00{i}.day27.example.invalid" for i in range(3)]
ONE = {f"d{DAY}--sample.bin": member(R)}


def main():
    # ---------------------------------------------------------------- A. field-equality
    v = ask(ONE, f"Read the HCFG record whose domain is '{DOM[1]}' and submit its campaign property.")
    check("A1 field-equality exact -> record 1, a tagged one-option pick (plain only in the generator's own frames)",
          pick_eq(v, CAMP[1]), v)
    v = ask(ONE, "Use the record whose url ends with `/api/BR27-002` and submit the campaign property.")
    check("A2 field-equality endswith -> record 2, a tagged one-option pick", pick_eq(v, CAMP[2]), v)
    v = ask(ONE, "Use the HCFG record where mutex contains \"BR27_000\" and submit the domain property.", "domain")
    check("A3 field-equality contains -> record 0, a tagged one-option pick", pick_eq(v, DOM[0]), v)
    v = ask(ONE, "Use the record whose domain contains 'day27.example' and submit the campaign.")
    check("A4 literal matching all records -> None (never candidates)", v is None, v)
    v = ask(ONE, "Use the record whose domain is 'nope.invalid' and submit the campaign.")
    check("A5 literal matching no record -> None", v is None, v)
    v = ask(ONE, f"Use the record whose domain is {DOM[1]} and submit the campaign property.")
    check("A6 unquoted literal is not a selector -> None", v is None, v)
    v = ask(ONE, f"Use the record other than the one whose domain is '{DOM[1]}' and submit the campaign.")
    check("A7 inversion word beside a field selector -> None", v is None, v)
    v = ask(ONE, f"Use the record whose domain is not '{DOM[1]}' and submit the campaign.")
    check("A8 'is not' is no field-equality match -> None", v is None, v)
    for word in ("ignore", "skip", "discard", "disregard", "avoid"):
        v = ask(ONE, f"Submit the campaign of the first HCFG record, but {word} the record whose domain is '{DOM[1]}'.")
        check(f"A8b '{word}' beside a selector resolves nothing -> not plain", kind_of(v) != "plain", v)
    v = ask(ONE, f"The record whose domain is '{DOM[1]}' is a decoy. Submit the campaign of the second record.")
    check("A8c a decoy statement beside a selector -> not plain", kind_of(v) != "plain", v)
    # a field of the stated record that does not exist
    v = ask(ONE, "Use the record whose colour is 'red' and submit the campaign property.")
    check("A9 selector on a non-key -> None", v is None, v)
    # equal field in two records (two equally selected)
    dup = {f"d{DAY}--sample.bin": member([make_record(cfg(0, region="eu"), key=0x41),
                                          make_record(cfg(1, region="eu"), key=0x42)])}
    v = ask(dup, "Use the record whose region is 'eu' and submit the campaign property.")
    check("A10 two records equally selected -> None", v is None, v)
    v = ask(dup, "Use the record whose region is 'eu' and submit the region property.")
    # (no config_region id handled by a rule here: region is an unknown member -> generic's own absent-pick or
    # None; what matters is that it is never a wrong plain)
    check("A10b agreed field over equally selected records is never a wrong plain",
          never_plain_wrong(v, {"eu"}), v)
    # a decoy of another day carries the stated literal
    other = {f"d{DAY}--sample.bin": member([make_record(cfg(0), key=0x41), make_record(cfg(1), key=0x42),
                                            make_record(cfg(1, day=99, domain="decoy.example.invalid"), key=0x43)])}
    v = ask(other, "Use the record whose domain is 'decoy.example.invalid' and submit the campaign property.")
    check("A11 selector to a record of another day -> None, not BR99-001", v is None, v)
    # CRC-broken record carries the literal
    broken = {f"d{DAY}--sample.bin": member([make_record(cfg(0), key=0x41), make_record(cfg(1), key=0x42),
                                             make_record(cfg(2), key=0x43, crc_delta=1)])}
    v = ask(broken, f"Use the record whose domain is '{DOM[2]}' and submit the campaign property.")
    check("A12 the stated record is CRC-broken -> None", v is None, v)

    # ---------------------------------------------------------------- B. member selectors
    two = {f"d{DAY}--sample-original.bin": member([make_record(cfg(0), key=0x41)]),
           f"d{DAY}--sample-patched.bin": member([make_record(cfg(1), key=0x42)])}
    v = ask(two, "Use the unique d27-- member whose basename ends patched.bin and submit the campaign property.")
    check("B1 basename ends patched.bin (not the generator's frame) -> that member's record, a tagged pick",
          pick_eq(v, "BR27-001"), v)
    v = ask(two, "Use the unique d27-- member whose basename ends original.bin and submit the campaign property.")
    check("B2 basename ends original.bin -> its record, a tagged pick", pick_eq(v, "BR27-000"), v)
    v = ask(two, "Use the member whose basename ends .bin and submit the campaign property.")
    check("B3 basename clause matching both members -> None (no candidates)", v is None, v)
    v = ask(two, "Use the member whose basename starts d27-- and ends original.bin and submit the campaign.")
    check("B3b a two-condition basename clause is not half-read (day tag only) -> None", v is None, v)
    v = ask(two, "Use the file named d27--sample-patched.bin and submit the campaign property.")
    check("B4 'file named' -> that member's record, a tagged pick", pick_eq(v, "BR27-001"), v)
    v = ask(two, "Use member 2 in ZIP central-directory order and submit the campaign property.")
    ord_ok = plain_eq(v, "BR27-001") or plain_eq(v, "BR27-000")
    # members_of order is the archive order of the dict: original, patched
    check("B5 member N by the prefix's member order -> that member's record, a tagged pick",
          pick_eq(v, "BR27-001"), v)
    v = ask(two, "Use member 5 and submit the campaign property.")
    check("B6 member past the count -> None", v is None, v)
    v = ask(ONE, "Use member 1 and submit the campaign property.")
    check("B7 the one member holds three records -> None", v is None, v)
    del ord_ok
    three = {f"d{DAY}--sample-alpha.bin": member([make_record(cfg(0), key=0x41)]),
             f"d{DAY}--sample-beta.bin": member([make_record(cfg(1), key=0x42)]),
             f"d{DAY}--sample-gamma.bin": member([make_record(cfg(2), key=0x43)])}
    v = ask(three, "Report the campaign property of the beta build's HCFG record.")
    check("B8 a build word read from the sibling member names -> a tagged pick", pick_eq(v, "BR27-001"), v)
    v = ask(three, "Report the campaign property of the delta build's HCFG record.")
    check("B9 a build word no member carries -> None", v is None, v)
    v = ask(three, "Report the campaign property of the beta build, not the gamma build.")
    check("B10 two build words / an inversion -> None", v is None, v)
    v = ask(three, "Report the campaign property of the alpha build or the beta build.")
    check("B11 two different build words -> None", v is None, v)
    # a member that holds two records and is selected by name: ambiguous
    mixed = {f"d{DAY}--sample-alpha.bin": member([make_record(cfg(0), key=0x41), make_record(cfg(1), key=0x42)]),
             f"d{DAY}--sample-beta.bin": member([make_record(cfg(2), key=0x43)])}
    v = ask(mixed, "Use the member whose basename ends alpha.bin and submit the campaign property.")
    check("B12 selected member holds two records -> None", v is None, v)

    # ---------------------------------------------------------------- C. soft readings
    ts = {f"d{DAY}--sample.bin": member([make_record(cfg(0, built="2026-10-01T00:00:00Z"), key=0x41),
                                         make_record(cfg(1, built="2026-10-20T12:00:00Z"), key=0x42),
                                         make_record(cfg(2, built="2026-09-15T08:30:00Z"), key=0x43)])}
    v = ask(ts, "Use the newest HCFG record and submit the campaign property.")
    check("C1 newest by an ISO timestamp -> a one-option pick, never plain", kind_of(v) == "unsure"
          and opts(v) == ["BR27-001"], v)
    pk = labels.parse(v)
    check("C1b the pick's key names the reading", pk and pk.key.startswith("binary.config_campaign/recsel_newest_by_built"),
          pk and pk.key)
    v = ask(ts, "Use the oldest record and submit the campaign property.")
    check("C2 oldest -> pick of record 2", kind_of(v) == "unsure" and opts(v) == ["BR27-002"], v)
    v = ask(ts, "Use the record with the latest timestamp and submit the campaign property.")
    check("C3 'record with the latest timestamp' -> pick of record 1", kind_of(v) == "unsure"
          and opts(v) == ["BR27-001"], v)
    epoch = {f"d{DAY}--sample.bin": member([make_record(cfg(0, ts=1760000000), key=0x41),
                                            make_record(cfg(1, ts=1761000000), key=0x42)])}
    v = ask(epoch, "Use the most recent record and submit the campaign property.")
    check("C4 epoch seconds -> pick of the larger", kind_of(v) == "unsure" and opts(v) == ["BR27-001"], v)
    tie = {f"d{DAY}--sample.bin": member([make_record(cfg(0, ts=1760000000), key=0x41),
                                          make_record(cfg(1, ts=1760000000), key=0x42)])}
    v = ask(tie, "Use the newest record and submit the campaign property.")
    check("C5 tied timestamps -> None", v is None, v)
    half = {f"d{DAY}--sample.bin": member([make_record(cfg(0, ts=1760000000), key=0x41),
                                           make_record(cfg(1), key=0x42)])}
    v = ask(half, "Use the newest record and submit the campaign property.")
    check("C6 a record with no timestamp -> None", v is None, v)
    v = ask(ONE, "Use the newest record and submit the campaign property.")
    check("C7 no timestamp key at all -> None", v is None, v)
    two_ts = {f"d{DAY}--sample.bin": member([make_record(cfg(0, built=1760000000, updated=1762000000), key=0x41),
                                             make_record(cfg(1, built=1761000000, updated=1750000000), key=0x42)])}
    v = ask(two_ts, "Use the newest record and submit the campaign property.")
    check("C8 two timestamp keys, none named -> None", v is None, v)
    v = ask(two_ts, "Use the record with the latest updated time and submit the campaign property.")
    check("C8b two timestamp keys, the text names one ('updated') -> pick",
          kind_of(v) == "unsure" and opts(v) == ["BR27-000"], v)
    v = ask(ONE, "Use the record with the highest version and submit the campaign property.")
    check("C9 highest header version -> pick of record 2", kind_of(v) == "unsure" and opts(v) == ["BR27-002"], v)
    v = ask(ONE, "Use the record for variant 1 and submit the campaign property.")
    check("C10 variant N by the campaign suffix -> pick", kind_of(v) == "unsure" and opts(v) == ["BR27-001"], v)
    v = ask(ONE, "Use the record for variant 7 and submit the campaign property.")
    check("C11 variant with no record -> None", v is None, v)
    vdup = {f"d{DAY}--sample.bin": member([make_record(cfg(1), key=0x41), make_record(cfg(1, note="b"), key=0x42)])}
    vdup = {f"d{DAY}--sample.bin": member([make_record(cfg(1), key=0x41),
                                           make_record(cfg(1, domain="other.day27.example.invalid"), key=0x42)])}
    v = ask(vdup, "Use the record for variant 1 and submit the domain property.", "domain")
    check("C12 variant matching two records that differ -> None", v is None, v)
    v = ask(vdup, "Use the record for variant 1 and submit the campaign property.")
    check("C12b ...and a (soft, tagged) pick only for a field they agree on", pick_eq(v, "BR27-001"), v)
    role = {f"d{DAY}--sample-original.bin": member([make_record(cfg(0), key=0x41)]),
            f"d{DAY}--sample-vendor.bin": member([make_record(cfg(1), key=0x42)])}
    v = ask(role, "Use the record that differs from the original build and submit the campaign property.")
    check("C13 'differs from the original' -> pick of the other record", kind_of(v) == "unsure"
          and opts(v) == ["BR27-001"], v)
    v = ask(role, "Use the patched build and submit the campaign property.")
    check("C14 'the patched build' with only the original marked -> complement pick",
          kind_of(v) == "unsure" and opts(v) == ["BR27-001"], v)
    role3 = dict(role)
    role3[f"d{DAY}--sample-third.bin"] = member([make_record(cfg(2), key=0x43)])
    v = ask(role3, "Use the record that differs from the original build and submit the campaign property.")
    check("C15 complement over THREE records -> None", v is None, v)
    v = ask(role3, "Use the patched build and submit the campaign property.")
    check("C16 'patched build' complement over three records -> not plain", kind_of(v) != "plain", v)
    plain_role = {f"d{DAY}--sample-vulnerable.bin": member([make_record(cfg(0), key=0x41)]),
                  f"d{DAY}--sample-patched.bin": member([make_record(cfg(1), key=0x42)])}
    v = ask(plain_role, "Use the patched build and submit the campaign property.")
    # fix round 2 of the review: the established forms are never plain (they were plain in any wording the vocabulary
    # guard let through); the marked role's record is the reading's one-option pick tagged with the text
    check("C17 an explicit marker gives the role's record, as a tagged one-option pick (plain before fix round 2)",
          pick_eq(v, "BR27-001"), v)
    v = ask(plain_role, "Use the record that differs from the vulnerable build and submit the campaign property.")
    check("C18 'differs from the vulnerable build' -> pick of patched's record", kind_of(v) == "unsure"
          and opts(v) == ["BR27-001"], v)
    v = ask(plain_role, "Use the patched build, which differs from the vulnerable build, and submit the campaign.")
    check("C19 hard + agreeing soft selector: the record they agree on, a tagged pick (plain before fix round 2)",
          pick_eq(v, "BR27-001"), v)
    v = ask(plain_role, "Use the vulnerable build, which differs from the vulnerable build, and submit the campaign.")
    check("C20 a self-contradicting statement -> not plain", kind_of(v) != "plain", v)

    # ---------------------------------------------------------------- D. positions over a CRC-broken record
    spare = {f"d{DAY}--sample.bin": member([make_record(cfg(0), key=0x41), make_record(cfg(9), key=0x49, crc_delta=1),
                                            make_record(cfg(1), key=0x42)])}
    v = ask(spare, "Use the second HCFG record and submit the campaign property.")
    check("D1 'second record' beside a CRC-broken header is ambiguous -> not plain", kind_of(v) != "plain", v)
    v = ask(spare, "Use the record whose domain is '" + DOM[1] + "' and submit the campaign property.")
    check("D2 a field selector over the same file is still exact -> a tagged pick of record 1", pick_eq(v, "BR27-001"), v)
    v = ask(ONE, "Use the second HCFG record and submit the campaign property.")
    check("D3 the established ordinal on a clean file reads record 1, a tagged pick (plain before fix round 2)",
          pick_eq(v, "BR27-001"), v)

    # ---------------------------------------------------------------- E. unstated -> None
    for label, files in (("one member", ONE), ("two role members", plain_role)):
        v = ask(files, "Decode the HCFG record and submit the campaign property.")
        check(f"E1 unstated choice over {label} -> None (no key-formula guess)", v is None, v)
    v = ask(plain_role, "Decode both d27-- role members and require their config objects to be byte-for-byte "
                        "equal before using the common value. Submit the campaign property.")
    check("E2 common-config text with divergent builds -> None", v is None, v)

    # ---------------------------------------------------------------- F. patch-difference facts
    pd_files = {f"d{DAY}--sample-vulnerable.bin": member([make_record(cfg(0), key=0x41)]),
                f"d{DAY}--sample-patched.bin": member([make_record(dict(cfg(0), domain="fixed.day27.example.invalid"),
                                                                   key=0x41)])}

    def pd(ids_text):
        return run(pd_files, [q(f"d{DAY}_analysis_{i}", t) for i, t in ids_text])

    got = pd([("changed_field", "Name the config field whose value changed between the two builds."),
              ("changed_field_count", "How many config fields changed between the builds?"),
              ("patched_changed_value", "Value of the changed config field in the patched build."),
              ("vulnerable_changed_value", "Value of the changed config field in the vulnerable build."),
              ("patch_offset", "Byte offset of the first byte of the HCFG payload the patch changes."),
              ("patch_size", "How many bytes of the HCFG payload does the patch change?")])
    g = {k.split("analysis_")[1]: v for k, v in got.items()}
    check("F1 the changed field is a one-option pick 'domain'", kind_of(g["changed_field"]) == "unsure"
          and opts(g["changed_field"]) == ["domain"], g["changed_field"])
    check("F2 the changed count is a pick '1'", kind_of(g["changed_field_count"]) == "unsure"
          and opts(g["changed_field_count"]) == ["1"], g["changed_field_count"])
    check("F3 the patched side's value is read by its member-name marker",
          kind_of(g["patched_changed_value"]) == "unsure"
          and opts(g["patched_changed_value"]) == ["fixed.day27.example.invalid"], g["patched_changed_value"])
    check("F4 the original side's value is the vulnerable member's",
          opts(g["vulnerable_changed_value"]) == ["node-000.day27.example.invalid"], g["vulnerable_changed_value"])
    check("F5 the patch offset is a candidates pick (several readings), never plain",
          kind_of(g["patch_offset"]) == "unsure" and labels.is_candidate(g["patch_offset"]), g["patch_offset"])
    first = int([i for i, (a, b) in enumerate(zip(json.dumps(cfg(0), separators=(",", ":")).encode(),
                                                  json.dumps(dict(cfg(0), domain="fixed.day27.example.invalid"),
                                                             separators=(",", ":")).encode())) if a != b][0])
    check("F5b ...offering the payload offset of the first differing byte",
          str(first) in opts(g["patch_offset"]), (first, opts(g["patch_offset"])))
    check("F6 the patch size is a candidates pick", kind_of(g["patch_size"]) == "unsure"
          and labels.is_candidate(g["patch_size"]), g["patch_size"])
    # hex-first when the text asks for hex
    h = pd([("patch_offset", "Give the offset of the first byte of the HCFG payload the patch changes, as 0x-prefixed "
                             "lowercase hex.")])
    check("F7 a hex-asking text offers the hex form first",
          opts(next(iter(h.values())))[0].startswith("0x"), h)
    # no markers: the sides are not provable
    nomark = {f"d{DAY}--sample-a.bin": member([make_record(cfg(0), key=0x41)]),
              f"d{DAY}--sample-b.bin": member([make_record(dict(cfg(0), domain="x.invalid"), key=0x41)])}
    nm = run(nomark, [q(f"d{DAY}_analysis_patched_changed_value", "Value of the changed config field in the patched build."),
                      q(f"d{DAY}_analysis_changed_field", "The changed config field.")])
    check("F8 no role marker -> the side's value is None, the changed key still a pick",
          nm[f"d{DAY}_analysis_patched_changed_value"] is None
          and opts(nm[f"d{DAY}_analysis_changed_field"]) == ["domain"], nm)
    # two differing keys: no single field
    twok = {f"d{DAY}--sample-vulnerable.bin": member([make_record(cfg(0), key=0x41)]),
            f"d{DAY}--sample-patched.bin": member([make_record(dict(cfg(0), domain="x.invalid", mutex="m"), key=0x41)])}
    tk = run(twok, [q(f"d{DAY}_analysis_changed_field", "The changed config field."),
                    q(f"d{DAY}_analysis_changed_count", "How many config fields changed?")])
    check("F9 two changed keys -> no single changed field (None), the count is 2",
          tk[f"d{DAY}_analysis_changed_field"] is None and opts(tk[f"d{DAY}_analysis_changed_count"]) == ["2"], tk)
    # key sets differ
    ks = {f"d{DAY}--sample-vulnerable.bin": member([make_record(cfg(0), key=0x41)]),
          f"d{DAY}--sample-patched.bin": member([make_record(dict(cfg(0), extra="x"), key=0x41)])}
    kr = run(ks, [q(f"d{DAY}_analysis_changed_field", "The changed config field.")])
    check("F10 an added key is not a changed field -> None", kr[f"d{DAY}_analysis_changed_field"] is None, kr)
    # a third record of the day: not a pair
    third = dict(pd_files)
    third[f"d{DAY}--sample-extra.bin"] = member([make_record(cfg(5), key=0x45)])
    tr = run(third, [q(f"d{DAY}_analysis_changed_field", "The changed config field.")])
    check("F11 three day records -> not a pair, None", tr[f"d{DAY}_analysis_changed_field"] is None, tr)
    # a record of another day and a CRC-broken record beside the pair do not join it
    decoys = dict(pd_files)
    decoys[f"d{DAY}--sample-old.bin"] = member([make_record(cfg(0, day=26), key=0x41),
                                                make_record(cfg(7), key=0x47, crc_delta=3)])
    dr = run(decoys, [q(f"d{DAY}_analysis_changed_field", "The changed config field.")])
    check("F12 other-day and CRC-broken records stay outside the pair", opts(dr[f"d{DAY}_analysis_changed_field"]) == ["domain"], dr)
    # a per-build config id is not hijacked, a plain config id is not touched by the diff reader
    pb = run(pd_files, [q(f"d{DAY}_analysis_patched_config_domain", "Use the unique member whose basename ends "
                                                                     "patched.bin. Submit the domain property.")])
    check("F13 a per-build config id is not read as a diff fact", kind_of(next(iter(pb.values()))) != "unsure"
          or opts(next(iter(pb.values()))) != ["domain"], pb)
    one = run(ONE, [q(f"d{DAY}_analysis_changed_field", "The changed config field.")])
    check("F14 one pool with three records and no pair -> None", one[f"d{DAY}_analysis_changed_field"] is None, one)
    single = run({f"d{DAY}--sample.bin": member([make_record(cfg(0), key=0x41)])},
                 [q(f"d{DAY}_analysis_changed_field", "The changed config field.")])
    check("F15 a single record has no difference -> None", single[f"d{DAY}_analysis_changed_field"] is None, single)

    # ---------------------------------------------------------------- G. fuzz: an answer is the intended one
    # A plain answer is the intended record's (the established forms), a new hard selector or soft reading answers a
    # tagged one-option pick of it, and an ambiguous selector answers neither.
    rng = random.Random(27)
    wrong = 0
    plain_n = 0
    pick_n = 0
    cases = 0
    for trial in range(120):
        n = rng.choice([2, 3, 4])
        variants = rng.sample(range(0, 9), n)
        recs = [cfg(v, built=1760000000 + rng.randrange(0, 5) * 100000, region=rng.choice(["eu", "us"]))
                for v in variants]
        layout = rng.choice(["one", "split"])
        if layout == "one":
            files = {f"d{DAY}--sample.bin": member([make_record(c, version=1 + i, key=0x41 + i)
                                                    for i, c in enumerate(recs)])}
        else:
            files = {f"d{DAY}--sample-w{chr(97 + i)}x.bin": member([make_record(c, version=1 + i, key=0x41 + i)])
                     for i, c in enumerate(recs)}
        # selectors with a known intended record (or None when ambiguous by construction)
        target = rng.randrange(n)
        sels = [(f"the record whose domain is '{recs[target]['domain']}'", target),
                (f"the record whose url ends with '{recs[target]['campaign']}'", target),
                (f"the record for variant {variants[target]}", target),
                (f"the record whose region is '{recs[target]['region']}'",
                 target if sum(1 for c in recs if c['region'] == recs[target]['region']) == 1 else None),
                ("the newest record",
                 [i for i, c in enumerate(recs) if c["built"] == max(x["built"] for x in recs)][0]
                 if sum(1 for c in recs if c["built"] == max(x["built"] for x in recs)) == 1 else None),
                (f"the record other than the one whose domain is '{recs[target]['domain']}'", None),
                ("the third HCFG record", 2 if layout == "one" and n >= 3 else (2 if n >= 3 else None))]
        if layout == "split":
            sels.append((f"the member whose basename ends w{chr(97 + target)}x.bin", target))
        for text, want in sels:
            cases += 1
            v = ask(files, f"Use {text} and submit the campaign property.")
            if kind_of(v) == "plain":
                plain_n += 1
                if want is None or v != recs[want]["campaign"]:
                    wrong += 1
                    print("   WRONG PLAIN:", text, "->", v, "want", want)
            elif kind_of(v) == "unsure":
                p = labels.parse(v)
                if p.key.endswith("#candidates"):
                    continue                       # the established forms' candidate list is a guess, never a claim
                pick_n += 1
                if want is None or opts(v) != [recs[want]["campaign"]]:
                    wrong += 1
                    print("   WRONG PICK:", text, "->", opts(v), "want", want)
    # none of these wordings is the generator's own frame, so none is plain since fix round 2 (the established ordinal
    # "the third HCFG record" was the plain share before)
    check(f"G fuzz: {cases} stated selectors over random layouts, {plain_n} plain, {pick_n} picks, none wrong",
          wrong == 0 and plain_n == 0 and pick_n > 300, f"wrong={wrong} plain={plain_n} picks={pick_n}")

    guard_section()
    real_data_section()
    fix1_section()
    fix2_section()

    print(f"\n{'ok' if not FAILED else 'FAILED'} {len(PASSED)} passed, {len(FAILED)} failed")
    return 1 if FAILED else 0


# ---------------------------------------------------------------------------------------------------------
# I to M: the review of KB-3 (the context guard, the real generator frames, the build-word restrictions).
# The first build read a selector PHRASE as the selection wherever it stood. "anything but member 2",
# "the record that differs from member 1", "the member after member 1", "member 1, zero-based" and "the beta
# build's successor" answered the NAMED record plain (the base answered None for each of them: those phrases are
# new selectors), the base's own ordinal reading had the same hole ("the second-to-last record" answered the
# LAST one), and the generator's own frame ("whose basename ends corrected.jar." with the sentence's period right
# behind an unquoted literal) answered nothing at all.

def zip_of(files):
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        for n, b in files.items():             # insertion order = ZIP central-directory order
            z.writestr(n, b)
    return buf.getvalue()


def ask_zip(files, text, field="campaign"):
    """Asked with the delivery zip in ctx, so that `member N` is the central-directory order exactly as the judged
    artifact_sha256_N ids count it (without a delivery generic falls back to the names' alphabetical order)."""
    buf = io.StringIO()
    with redirect_stderr(buf):
        return answers_closed(f"d{DAY}", [q(cid(field), text)], dict(files), {"delivery": zip_of(files)})[cid(field)]


# the generator's own tail of a config question (Day 24/25 wording), after the sentence that names the member
REAL_TAIL = (" Parse every JAR classfile constant pool; for Base64-alphabet UTF-8 constants of at least 80 characters, "
             "Base64-decode and accept the first CRC32-valid HCFG JSON record. Locate the unique CRC32-valid HCFG "
             "record: bytes 0..3 are ASCII HCFG, byte 4 is version, byte 5 is the XOR key, bytes 6..7 are the "
             "little-endian payload length, bytes 8..11 are the little-endian CRC32 of the decoded payload, and the "
             "payload begins at byte 12. XOR every payload byte with the one-byte key, verify CRC32, then parse the "
             "decoded UTF-8 JSON. Submit the exact string value of the decoded HCFG JSON object's top-level campaign "
             "property, without JSON quotes.")

# the generator's tail with a LITERAL scan (the Day 4/5/22/23 procedure): it reads a raw record, which is how every
# synthetic member() here stores one. LIT_TAIL (the Day 24 jar wording) states a base64 procedure, and since the third
# review of fix round 2 a frame over a RAW record under it is a reading, not plain (record_select._read_as_stated: the
# walk reads a member that holds a raw record as raw only, and a base64 record beside it could go unseen).
# (The judged literal-first pair, not "accept the first record whose bounds ... validate": that sentence is itself the
# established ordinal "the first record", a second selector beside the frame.)
LIT_TAIL = (" First test literal HCFG occurrences in the member; then test every non-overlapping Latin-1 run matching "
            "[A-Za-z0-9+/]{100,}={0,2} by Base64-decoding it. Accept the first CRC32-valid HCFG JSON record in that order."
            " Locate the unique CRC32-valid HCFG record: bytes 0..3 are ASCII HCFG, byte 4 is "
            "version, byte 5 is the XOR key, bytes 6..7 are the little-endian payload length, bytes 8..11 are the "
            "little-endian CRC32 of the decoded payload, and the payload begins at byte 12. XOR every payload byte with "
            "the one-byte key, verify CRC32, then parse the decoded UTF-8 JSON. Submit the exact string value of the "
            "decoded HCFG JSON object's top-level campaign property, without JSON quotes.")


def b64member(records):
    """A member that stores each record as a base64 text constant (the walk reads it as `raw>base64`), the form
    LIT_TAIL's procedure reads."""
    import base64
    out = b"\x00\x10junk-prefix\x00"
    for r in records:
        out += base64.b64encode(r) + b"\x00\x00padding\x00\x00"
    return out


# frames that make the selector phrase the REFERENCE of something else, or count another way: a plain answer
# from the named record is wrong in every one of them
NEG_FRAMES = [
    "Use any record except {X} and submit the campaign property.",
    "Use the record other than {X} and submit the campaign property.",
    "Use the record that differs from {X} and submit the campaign property.",
    "Use the record that is different from {X} and submit the campaign property.",
    "Use the record that is not {X} and submit the campaign property.",
    "Use the record that comes after {X} and submit the campaign property.",
    "Use the record before {X} and submit the campaign property.",
    "Use the record next to {X} and submit the campaign property.",
    "Use the record adjacent to {X} and submit the campaign property.",
    "Use the record that shares its config with {X} and submit the campaign property.",
    "Use the record that matches {X} and submit the campaign property.",
    "Use the record equal to {X} and submit the campaign property.",
    "Use the record identical to {X} and submit the campaign property.",
    "Use the record that replaces {X} and submit the campaign property.",
    "Use the record newer than {X} and submit the campaign property.",
    "Use the successor of {X} and submit the campaign property.",
    "Use the predecessor of {X} and submit the campaign property.",
    "Use the sibling of {X} and submit the campaign property.",
    "Use the counterpart of {X} and submit the campaign property.",
    "Use the record that was derived from {X} and submit the campaign property.",
    "Use the record built from {X} and submit the campaign property.",
    "Use the record compiled from {X} and submit the campaign property.",
    "Use the record forked from {X} and submit the campaign property.",
    "Use the record that follows {X} and submit the campaign property.",
    "Use the opposite of {X} and submit the campaign property.",
    "Use the record unlike {X} and submit the campaign property.",
    "Use the record neither {X} nor the first one and submit the campaign property.",
    "Compare {X} with the other records and use the newer one; submit the campaign property.",
    "Ignore {X} and use the rest; submit the campaign property.",
    "Use everything but {X} and submit the campaign property.",
    "Use the record that fixes {X} and submit the campaign property.",
    "Use the record which patches {X} and submit the campaign property.",
    "Use the record whose config {X} copies and submit the campaign property.",
    "Use the record that depends on {X} and submit the campaign property.",
    "Use the record that goes with {X} and submit the campaign property.",
    "Use the record minus {X} and submit the campaign property.",
    "Use {X} sorted by size and submit the campaign property.",
    "Use {X} (zero-based) and submit the campaign property.",
    "Use {X}, counting from the end, and submit the campaign property.",
    "Use {X} in reverse order and submit the campaign property.",
    "Use {X} by name and submit the campaign property.",
    "Use {X}. The members are sorted by name.",
]
# an ordering by time blocks a HARD selector; it is the reading itself of a soft newest/oldest phrase
HARD_ONLY_NEG_FRAMES = [
    "Use {X} by date and submit the campaign property.",
    "Use {X} by time and submit the campaign property.",
    "Use {X}, ordered by age, and submit the campaign property.",
]
POS_FRAMES = [
    "Use {X} and submit the campaign property.",
    "In evidence.zip, Use {X}. Submit the campaign property.",
    "Report the campaign property of {X}.",
    "Read {X}; submit the campaign property.",
    "From {X}, submit the campaign property.",
    "Take {X} and submit its campaign property, without JSON quotes.",
    "Decode {X}. Submit the exact string value of the top-level campaign property, without JSON quotes.",
]


def guard_section():
    abg = {f"d{DAY}--sample-alpha.bin": member([R[0]]), f"d{DAY}--sample-beta.bin": member([R[1]]),
           f"d{DAY}--sample-gamma.bin": member([R[2]])}            # archive order alpha, beta, gamma; beta is #2
    selectors = {
        "member N": ("member 2", abg), "ordinal member": ("the second member", abg),
        "basename": ("the member whose basename ends beta.bin", abg),
        "file named": (f"the file named d{DAY}--sample-beta.bin", abg),
        "build word": ("the beta build", abg), "build word possessive": ("the beta build's record", abg),
        "field equality": (f"the record whose domain is '{DOM[1]}'", ONE),
        "ordinal record": ("the second HCFG record", ONE), "record #N": ("record #2", ONE),
        "version": ("the record with version 2", ONE), "campaign": ("the record for campaign BR27-001", ONE),
    }
    new_forms = ("member N", "ordinal member", "basename", "file named", "build word", "build word possessive",
                 "field equality")                    # KB-3's hard selectors: plain only in the generator's own frames
    leaks, lost, lost_new = [], [], []
    for name, (x, files) in selectors.items():
        for frame in NEG_FRAMES + HARD_ONLY_NEG_FRAMES:
            v = ask_zip(files, frame.replace("{X}", x))
            if kind_of(v) == "plain":
                leaks.append((name, frame, v))
        for frame in POS_FRAMES:
            v = ask_zip(files, frame.replace("{X}", x))
            if name in new_forms:
                if not pick_eq(v, CAMP[1]):
                    lost_new.append((name, frame, v))
            elif not pick_eq(v, CAMP[1]):
                lost.append((name, frame, v))
    check(f"I1 context guard: {len(selectors)} selector phrases x {len(NEG_FRAMES) + len(HARD_ONLY_NEG_FRAMES)} "
          f"negative/relational frames, no plain answer", not leaks, leaks[:3])
    check(f"I2 ...and the established phrases in {len(POS_FRAMES)} positive frames are tagged one-option picks of the "
          f"right record (plain before fix round 2: the established forms are never plain now)", not lost, lost[:3])
    check(f"I2n ...and the new hard phrases in the same frames are tagged one-option picks of the right record "
          f"(plain only in the generator's own frames: section J)", not lost_new, lost_new[:3])

    # the SOFT readings (newest by a timestamp, highest version, variant N): their pick becomes plain once the judge has
    # accepted its key, so the phrase needs the same positive context as a hard selector
    ts3 = {f"d{DAY}--sample.bin": member([make_record(cfg(0, built="2026-10-01T00:00:00Z"), version=1, key=0x41),
                                          make_record(cfg(1, built="2026-10-20T12:00:00Z"), version=2, key=0x42),
                                          make_record(cfg(2, built="2026-09-15T08:30:00Z"), version=3, key=0x43)])}
    soft_selectors = {"newest by a timestamp": ("the newest record", ts3, CAMP[1]),
                      "highest header version": ("the record with the highest version", ONE, CAMP[2]),
                      "variant N": ("the record for variant 1", ONE, CAMP[1])}
    soft_leaks, soft_lost = [], []
    for name, (x, files, want) in soft_selectors.items():
        for frame in NEG_FRAMES:
            v = ask_zip(files, frame.replace("{X}", x))
            if v is not None:
                soft_leaks.append((name, frame, v if not labels.is_unsure(v) else opts(v)))
        for frame in POS_FRAMES:
            v = ask_zip(files, frame.replace("{X}", x))
            if not (kind_of(v) == "unsure" and opts(v) == [want]):
                soft_lost.append((name, frame, v))
    check(f"I2b soft readings: {len(soft_selectors)} phrases x {len(NEG_FRAMES)} negative/relational frames resolve nothing",
          not soft_leaks, soft_leaks[:3])
    check(f"I2c ...and in {len(POS_FRAMES)} positive frames each is still its one-option pick", not soft_lost, soft_lost[:3])
    v = ask_zip(ts3, "Use the newest record by date and submit the campaign property.")
    check("I2d 'the newest record by date' is its one-option pick (an ordering by time IS the soft reading)",
          kind_of(v) == "unsure" and opts(v) == [CAMP[1]], v)

    # the base's own hole, closed with the same guard: a position counted from the end
    ordinal = {f"d{DAY}--sample.bin": member(R)}
    for text in ("Use the second-to-last HCFG record and submit the campaign property.",
                 "Use the last but one HCFG record and submit the campaign property."):
        check(f"I3 '{text[8:40]}...' is no 'last record'", kind_of(ask_zip(ordinal, text)) != "plain",
              ask_zip(ordinal, text))

    # the established boilerplate stays a selector: the generator's own scan sentence names the FIRST record
    rec_pool = [dict(r, _member_index=0, _member_name=f"d{DAY}--sample.bin") for r in generic.record_pool(
        [(f"d{DAY}--sample.bin", member(R))], DAY)]
    res = rs.resolve("Scan each literal HCFG occurrence in the Rust ELF and accept the first record whose bounds, "
                     "CRC32, and decoded JSON validate. Locate the unique CRC32-valid HCFG record.", rec_pool)
    check("I4 the generator's 'accept the first record whose ...' sentence still selects record 1 (unchanged)",
          res.idx == 0 and res.hard and not res.ext, vars_of(res))
    # two guarded phrases in two sentences: the one sentence that is risky poisons the whole reading
    check("I5 a risky sentence beside a clean one resolves nothing",
          kind_of(ask_zip(abg, "Use member 2. It differs from member 1.")) != "plain",
          ask_zip(abg, "Use member 2. It differs from member 1."))
    # the soft complement of a ROLE reference is unchanged (C13/C14/C18/C19 above); a differs-from reference that is
    # no role word is consumed by nothing, so it is a relation
    two = {f"d{DAY}--sample-original.bin": member([R[0]]), f"d{DAY}--sample-patched.bin": member([R[1]])}
    v = ask_zip(two, "Use the member that differs from the one whose basename ends original.bin and submit the campaign.")
    check("I6 'differs from the one whose basename ends original.bin' is no selection of original.bin",
          kind_of(v) != "plain", v)

    # a relation word inside a QUOTED literal is the value's own spelling, not the sentence's
    lit = {f"d{DAY}--sample.bin": member([make_record(cfg(0, domain="next-node.day27.example.invalid"), key=0x41),
                                          make_record(cfg(1), key=0x42)])}
    v = ask_zip(lit, "Use the record whose domain is 'next-node.day27.example.invalid' and submit the campaign property.")
    check("I7 'next' inside the quoted literal does not block the field selector (a tagged pick of record 0)",
          pick_eq(v, CAMP[0]), v)
    v = ask_zip(lit, "Use the record that comes after the record whose domain is 'next-node.day27.example.invalid' "
                     "and submit the campaign property.")
    check("I8 ...while the same selector as the reference of 'comes after' resolves nothing",
          kind_of(v) != "plain", v)

    # "no." before a digit is no sentence end: the words after it still belong to the selector's sentence
    v = ask_zip(abg, "Use member no. 2 instead and submit the campaign property.")
    check("I9 'member no. 2 instead' keeps 'instead' in the selector's sentence -> not plain", kind_of(v) != "plain", v)
    v = ask_zip(abg, "Use member no. 2 and submit the campaign property.")
    check("I10 ...and 'member no. 2' alone is still the second member (a tagged pick)", pick_eq(v, CAMP[1]), v)

    # ---------------------------------------------------------------- J. the generator's own frames
    vc = {f"d{DAY}--sample-vulnerable.jar": member([R[0]]), f"d{DAY}--sample-corrected.jar": member([R[1]])}
    sent = "In evidence.zip, Use the unique d27-- member whose basename ends {}."
    v = ask_zip(vc, sent.format("corrected.jar") + LIT_TAIL)
    check("J1 the real per-build frame (the period right behind the unquoted literal) selects corrected.jar (the frame "
          "reading's pick; plain before the fourth review)", frame_pick(v, CAMP[1]), v)
    v = ask_zip(vc, sent.format("vulnerable.jar") + LIT_TAIL)
    check("J2 ... and vulnerable.jar", frame_pick(v, CAMP[0]), v)
    v = ask_zip(vc, "In evidence.zip, Use the unique d27-- member whose basename ends 'corrected.jar'." + LIT_TAIL)
    check("J3 a quoted literal, the period behind the closing quote", frame_pick(v, CAMP[1]), v)
    v = ask_zip(vc, "In delivery 2: evidence.zip, Use the unique d27-- member whose basename ends corrected.jar."
                + LIT_TAIL)
    check("J3b a Mastery's 'In delivery N:' lead is no selector and no obstacle", frame_pick(v, CAMP[1]), v)
    v = ask_zip(vc, sent.format("corrected.jar") + LIT_TAIL.replace("campaign property", "domain property"), "domain")
    check("J4 the frame answers another field of the same record the same way",
          frame_pick(v, DOM[1]), v)
    # member N in ZIP central-directory order (1-based), the order the judged artifact_sha256_N ids use
    for order in ([f"d{DAY}--sample-vulnerable.jar", f"d{DAY}--sample-corrected.jar"],
                  [f"d{DAY}--sample-corrected.jar", f"d{DAY}--sample-vulnerable.jar"]):
        recs = {f"d{DAY}--sample-vulnerable.jar": (member([R[0]]), CAMP[0]),
                f"d{DAY}--sample-corrected.jar": (member([R[1]]), CAMP[1])}
        files = {n: recs[n][0] for n in order}
        for n in (1, 2):
            v = ask_zip(files, f"Use the HCFG record of member {n}, where members are the d27-- members in ZIP "
                               f"central-directory order (1-based)." + LIT_TAIL)
            check(f"J5 member {n} follows the central directory ({order[n - 1].split('-')[-1]} first={n == 1})",
                  frame_pick(v, recs[order[n - 1]][1]), v)
    # a trailing period is no part of a two-character-or-shorter literal
    check("J6 a one-character literal names no member", rs._basename_clauses("the member whose basename ends x.") == [])
    check("J7 a day tag is no basename clause", rs._basename_clauses("whose basename starts d27-- and ends .dll;") == [])

    # ---------------------------------------------------------------- L. build words: no file-type noun, a frame
    pj = {f"d{DAY}--primary.jar": member([R[0]]), f"d{DAY}--secondary.jar": member([R[1]])}
    day26 = ("In evidence.zip, Use all d27-- members in ZIP central-directory order. Parse the primary JAR classfile "
             "constant pool; for Base64-alphabet UTF-8 constants of at least 80 characters, Base64-decode it and "
             "accept the first CRC32-valid HCFG JSON record. Submit the top-level campaign property.")
    v = ask_zip(pj, day26)
    check("L1 the Day 26 boilerplate 'the primary JAR' is no selection of a member named primary.jar",
          kind_of(v) != "plain", v)
    v = ask_zip(pj, "Report the campaign property of the primary build.")
    check("L2 'the primary build' (a build noun, a selecting frame) still selects it (a tagged pick)", pick_eq(v, CAMP[0]), v)
    for text in ("The primary build is a decoy of the secondary build. Report the campaign property.",
                 "A primary build holds the record to report; submit the campaign property.",
                 "Report the campaign property of the primary build and the secondary build."):
        v = ask_zip(pj, text)
        check(f"L3 a build word mentioned outside a selecting frame resolves nothing ({text[:36]}...)",
              kind_of(v) != "plain", v)

    # ---------------------------------------------------------------- M. no KB-3 selector fires on a saved text
    saved_texts_section()


def vars_of(res):
    return {"idx": res.idx, "hard": res.hard, "ext": res.ext, "tags": res.tags}


def saved_texts_section():
    """M. Over every distinct HCFG config question the lane has saved (all days, timed modes and history), on layouts
    whose member names hold build words, no selector added by KB-3 fires and no plain answer appears that the base
    would not give: the new readings add answers only to a text that STATES a selector.  A later non-HCFG protocol
    can state a member selector too; prove that family is recognised exactly and resolves no synthetic HCFG record,
    then keep it out of the HCFG context-guard invariant. Skipped without the saved attempts."""
    import re
    root = SAVED_CHALLENGES
    atts = sorted(root.glob("day-*/binary-reverse-engineering-*")) if root is not None and root.is_dir() else []
    texts = {}
    for att in atts:
        for sub in ("", "time_trial", "mastery"):
            base = att / sub if sub else att
            for f in [base / "attempt.json"] + sorted(base.glob("history/*/attempt.json")):
                try:
                    qs = json.loads(f.read_text()).get("questions", [])
                except (OSError, ValueError):
                    continue
                for qq in qs:
                    qid = re.sub(r"^set\d+\.", "", qq.get("id") or qq.get("qid") or "")
                    if re.fullmatch(r"d\d+_(analysis_(?:config_.+|xor_key_hex|hcfg_version))", qid):
                        texts[(qid, qq.get("question") or "")] = 1
    if not texts:
        print("skip M saved-text invariant (no saved attempts)")
        return
    # Day 30's Neko/HGRF protocol is deliberately not an HCFG record-select contract.  Its questions state
    # ``basename ends config.n`` before asking about the capsule graph, so resolve() correctly reports that an
    # external selector was present.  On the synthetic HCFG pools below it must name no record.  Partition by both
    # the protocol word in the bytes contract and the exact field namespace, and pin the family to Day 30 so a new
    # unrelated shape cannot silently escape the saved-text sweep.
    foreign = {(qid, text) for qid, text in texts
               if "hgrf" in text.lower() or "config_capsule" in qid}
    check("M0 the saved non-HCFG selector family is exactly Day 30 Neko/HGRF",
          bool(foreign) and all(qid.startswith("d30_") and
                                ("hgrf" in text.lower() or "config_capsule" in qid)
                                for qid, text in foreign),
          sorted(qid for qid, _text in foreign))
    texts = {row: 1 for row in texts if row not in foreign}
    names = {"words": ("alpha", "beta", "gamma"), "primary": ("primary", "secondary"),
             "stripped": ("stripped", "symbolized"), "compact": ("compact", "direct"),
             "stable": ("stable", "nightly"), "oldnew": ("old", "new")}
    fired = []
    foreign_resolved = []
    for label, ws in names.items():
        files = [(f"d{DAY}--sample-{w}.bin", member([make_record(cfg(i), version=1 + i, key=0x41 + i)]))
                 for i, w in enumerate(ws)]
        pool = rs.annotate(generic.record_pool(files, DAY), files)
        for qid, text in foreign:
            res = rs.resolve(text, pool)
            if res.idx is not None:
                foreign_resolved.append((label, qid, res.idx, text[:90]))
        for (qid, text) in texts:
            res = rs.resolve(text, pool)
            if res.ext:
                fired.append((label, qid, text[:90]))
    check(f"M0b no non-HCFG selector resolves a record on {len(names)} synthetic HCFG layouts",
          not foreign_resolved, foreign_resolved[:3])
    check(f"M1 no KB-3 selector fires on any of {len(texts)} saved config questions over {len(names)} build-word layouts",
          not fired, fired[:3])

    # M2: the context guard blocks nothing of the generator's own wording. On a layout with three records in one
    # member the established "accept the first record whose ..." sentence selects record 1 (as on the base), and
    # the guard is asked about it; every answer must be "not bad" (a splitter that read the capital-letter rule on
    # a lower-cased copy once blocked 1,870 of 20,500 saved-text runs and no other check noticed).
    asked = []
    real = rs._context_bad

    def spy(text, spans, consumed=(), **kw):
        r = real(text, spans, consumed, **kw)
        asked.append((r, text[:90]))
        return r

    rs._context_bad = spy
    try:
        files = [(f"d{DAY}--sample.bin", member([make_record(cfg(i), version=1 + i, key=0x41 + i) for i in range(3)]))]
        pool = rs.annotate(generic.record_pool(files, DAY), files)
        for (qid, text) in texts:
            rs.resolve(text, pool)
    finally:
        rs._context_bad = real
    blocked = [t for r, t in asked if r]
    check(f"M2 the guard was asked {len(asked)} times over the saved config questions and blocked none",
          not blocked and len(asked) > 100, (len(asked), blocked[:2]))


def real_data_section():
    """H. Staged from the REAL saved Day 24 patch-diffing members: the real vulnerable jar (its real HCFG record
    behind a class-file constant pool) beside a re-encoded 'patched' record (the real config's JSON with one
    field changed). Skipped when the saved attempt is not on this machine."""
    real = (SAVED_CHALLENGES or Path(os.devnull)) / "day-24" / "binary-reverse-engineering-day-24-patch-diffing" / "members"
    vf = real / "d24--sample-vulnerable.jar"
    if not vf.is_file():
        print("skip H real-data section (no saved Day 24 members)")
        return
    vul = vf.read_bytes()
    base = generic.record_pool([(vf.name, vul)], 24)
    check("H0 the real vulnerable jar yields its one real record", len(base) == 1 and base[0]["json"]["campaign"] == "BR24-000")
    real_json = dict(base[0]["json"])
    patched = dict(real_json, service="HuntressLab-Day24-PATCHED")
    other_day = dict(real_json, campaign="BR23-000", domain="old.day23.example.invalid")

    def run24(files, qs):
        buf = io.StringIO()
        with redirect_stderr(buf):
            return answers_closed("d24", qs, dict(files), {})

    def c24(f, text, fl=None):
        qid = f"d24_analysis_config_{f}"
        return run24(files if fl is None else fl, [q(qid, text)])[qid]

    files = {"d24--sample-vulnerable.jar": vul,
             "d24--sample-corrected.bin": member([make_record(patched, key=0x71)])}
    v = c24("service", "Use the unique d24-- member whose basename ends corrected.bin and submit the service property.")
    check("H1 real+patched: basename ends corrected.bin -> the patched value (never the real one)",
          v is None or kind_of(v) != "plain" or v == patched["service"], v)
    # the generator's own frame (the sentence's period right behind the unquoted literal), over the real jar
    v = c24("service", "In evidence.zip, Use the unique d24-- member whose basename ends corrected.bin." +
            LIT_TAIL.replace("campaign property", "service property"))
    check("H1b real+patched, the real frame: the patched member's value, the frame reading's pick (plain before the "
          "fourth review)", frame_pick(v, patched["service"]), v)
    v = c24("campaign", "In evidence.zip, Use the unique d24-- member whose basename ends vulnerable.jar." + REAL_TAIL)
    check("H1c real+patched, the real frame: the real jar's own record, PLAIN and right",
          frame_pick(v, real_json["campaign"]), v)
    v = c24("domain", "Use the unique d24-- member whose basename ends corrected.bin and submit the domain property.")
    check("H2 real+patched: the agreed field (domain) of the stated member is right (a tagged pick), never another value",
          v is None or answered_eq(v, real_json["domain"]), v)
    v = c24("campaign", "Use the unique d24-- member whose basename ends vulnerable.jar and submit the campaign property.")
    check("H3 real+patched: the real jar's record is selected by its member name (a tagged pick)",
          v is None or answered_eq(v, "BR24-000"), v)
    v = c24("campaign", "Submit the campaign property of the config.")
    check("H4 real+patched: an UNSTATED choice stays None / not wrong plain",
          v is None or kind_of(v) != "plain" or v == "BR24-000", v)
    v = c24("domain", "Use the record whose service is 'HuntressLab-Day24-PATCHED' and submit the domain property.")
    check("H5 field-equality over a real record and a re-encoded one", v is None or answered_eq(v, real_json["domain"]), v)
    # decoys beside the real record
    files2 = dict(files)
    files2["d24--sample-decoy.bin"] = member([make_record(other_day, key=0x72)])
    v = c24("service", "Use the unique d24-- member whose basename ends corrected.bin and submit the service property.", files2)
    check("H6 a record of another day beside them never gives a wrong plain", v is None or kind_of(v) != "plain"
          or v in (patched["service"],), v)
    files3 = dict(files)
    files3["d24--sample-corrected.bin"] = member([make_record(patched, key=0x71, crc_delta=1)])
    v = c24("service", "Use the unique d24-- member whose basename ends corrected.bin and submit the service property.", files3)
    # the broken record is never read; the prefix's ONE CRC-valid record (the real jar's) stays the config, which is the
    # lane's established single-record rule (unchanged by KB-3), so the value is the real one or None, never the broken one
    check("H7 the stated member's record is CRC-broken -> never its value (the one valid record or None)",
          v is None or v == real_json["service"], v)
    # patch-difference facts over the real pair
    qs = [q("d24_analysis_patch_changed_field", "Which config field differs between the builds?"),
          q("d24_analysis_patch_changed_count", "How many config fields differ?", "integer")]
    got = run24(files, qs)
    check("H8 real patch diff: the changed field is a pick naming 'service' (never plain)",
          kind_of(got["d24_analysis_patch_changed_field"]) == "unsure"
          and opts(got["d24_analysis_patch_changed_field"]) == ["service"], got)
    check("H9 real patch diff: the changed count is a pick '1'",
          kind_of(got["d24_analysis_patch_changed_count"]) == "unsure"
          and opts(got["d24_analysis_patch_changed_count"]) == ["1"], got)
    two_changed = {"d24--sample-vulnerable.jar": vul,
                   "d24--sample-corrected.bin": member([make_record(dict(patched, host_model="server"), key=0x71)])}
    got = run24(two_changed, qs[:1])
    check("H10 two changed fields -> no single changed field (None)", got["d24_analysis_patch_changed_field"] is None, got)


# ---------------------------------------------------------------------------------------------------------
# N: the fix round of the review of KB-3 (the issues of the adversarial review of 7dc4a4b, numbered as the review lists
# them, each with a check that fails on that commit; the reviewer's scripts a1 to a12 are the cases). The rule they pin: an answer comes only from
# the record or records the selector itself names, plain only in the generator's own wording of it, and a reading the
# judge accepts is a reading of that id and that wording only.

# the 36 relational, exclusion, position, patch, malware, counting and redirect frames of the review's sweep (a2)
A2_FRAMES = [
    "Use the record that followed {X} and submit the campaign property.",
    "Use the record that preceded {X} and submit the campaign property.",
    "Use the record that succeeds {X} and submit the campaign property.",
    "Use the record succeeding {X} and submit the campaign property.",
    "Use the record ahead of {X} and submit the campaign property.",
    "Use the record behind {X} and submit the campaign property.",
    "Use the record one past {X} and submit the campaign property.",
    "Use the record beyond {X} and submit the campaign property.",
    "Use the record listed below {X} and submit the campaign property.",
    "Use the record listed above {X} and submit the campaign property.",
    "Use any record save {X} and submit the campaign property.",
    "Use every record aside from {X} and submit the campaign property.",
    "Use any record barring {X} and submit the campaign property.",
    "Use the alternative to {X} and submit the campaign property.",
    "Use the record that corrects {X} and submit the campaign property.",
    "Use the record that remediates {X} and submit the campaign property.",
    "Use the record that hardens {X} and submit the campaign property.",
    "Use the hotfix for {X} and submit the campaign property.",
    "Use the record that reverts {X} and submit the campaign property.",
    "Use the record that overrides {X} and submit the campaign property.",
    "Use the record that obsoletes {X} and submit the campaign property.",
    "Use the record that was rebuilt from {X} and submit the campaign property.",
    "Use the record recompiled from {X} and submit the campaign property.",
    "Use the record generated from {X} and submit the campaign property.",
    "Use the record repackaged from {X} and submit the campaign property.",
    "Use the payload dropped by {X} and submit the campaign property.",
    "Use the stage that {X} downloads and submit the campaign property.",
    "Use the module spawned by {X} and submit the campaign property.",
    "Use {X} in chronological order and submit the campaign property.",
    "Use {X} in size order and submit the campaign property.",
    "Use {X} (counted from zero) and submit the campaign property.",
    "Use {X}, numbering from 0, and submit the campaign property.",
    "Use {X} by modification time and submit the campaign property.",
    "Use {X} by timestamp and submit the campaign property.",
    "{X} is stale. Use the other one and submit the campaign property.",
    "{X} holds the old config. Report the campaign property of the remaining one.",
]


def accept_key(key, name):
    """The judge accepting `name` for `key`, in this test's own ledger."""
    labels.learn(key, name, "accepted", attempt_id="n-test", answer_ids=["n-test"])


def fix1_section():
    D = DAY
    V = make_record(cfg(0), key=0x41)
    V2 = make_record(dict(cfg(0), domain="fixed.day27.example.invalid", campaign="BR27-009"), key=0x41)

    # shared by the parts below
    abg = {f"d{D}--sample-alpha.bin": member([R[0]]), f"d{D}--sample-beta.bin": member([R[1]]),
           f"d{D}--sample-gamma.bin": member([R[2]])}
    T_CH = "Which config field changed between the two builds?"
    import importlib.util
    spec = importlib.util.spec_from_file_location("kb3_patch_diff", REPO / "solvers" / "binary" / "patch_diff.py")
    pdmod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pdmod)

    parts = []

    def part_n1():
        # N1 (issue 2, a1): a member that holds a copy of another member's record beside a record of its own holds TWO
        cp = {f"d{D}--sample-vulnerable.bin": member([V]), f"d{D}--sample-corrected.bin": member([V, V2])}
        pool = generic.record_pool(list(cp.items()), D)
        holders = {r["json"]["campaign"]: sorted(r.get("_member_indices") or []) for r in pool}
        check("N1a the pool says EVERY member that holds a record (the copy stands in both members)",
              holders == {"BR27-000": [0, 1], "BR27-009": [1]}, holders)
        names = {r["json"]["campaign"]: list(r.get("_member_names") or []) for r in pool}
        check("N1a2 ...and their names, in member order", names["BR27-000"] == [f"d{D}--sample-vulnerable.bin",
              f"d{D}--sample-corrected.bin"], names)
        texts = ["In evidence.zip, Use the unique d27-- member whose basename ends corrected.bin." + LIT_TAIL,
                 "Use the member whose basename ends corrected.bin and submit the campaign property.",
                 "Use the unique d27-- member whose basename ends corrected.bin, accept the first CRC32-valid HCFG record "
                 "in it, and submit the campaign property.",
                 "Use member 2 and submit the campaign property.",
                 "Use the file named d27--sample-corrected.bin and submit the campaign property."]
        got = [(t[:60], ask_zip(cp, t)) for t in texts]
        check("N1b a member holding a copy and a record of its own is not read as holding one: None, never its second record",
              all(v is None for _, v in got), got)
        v = ask_zip(cp, "Report the campaign property of the corrected build.")
        check("N1c the established role form over the same pool is no longer plain (both records carry the role)",
              kind_of(v) != "plain", v)
        check("N1d the role markers read every holder: 'corrected' marks both records, 'vulnerable' the copy only",
              rs._role_matches(pool, "corrected") == {0, 1} and rs._role_matches(pool, "vulnerable") == {0},
              (rs._role_matches(pool, "corrected"), rs._role_matches(pool, "vulnerable")))
    parts.append(("N1", part_n1))

    def part_n2():
        # N2 (issue 1, a7, a8, a9): a selector that names a record outside the day's readable pool answers nothing
        Dd = make_record(dict(cfg(0), domain="mirror.day27.example.invalid"), key=0x42)
        L = make_record(cfg(3, day=26), key=0x43)
        outside = {f"d{D}--sample-vulnerable.bin": member([V]), f"d{D}--sample-mirror.bin": member([Dd]),
                   f"d{D}--sample-legacy.bin": member([L])}
        texts = ["Use the unique d27-- member whose basename ends legacy.bin and submit the campaign property.",
                 "In evidence.zip, Use the unique d27-- member whose basename ends legacy.bin." + LIT_TAIL,
                 "Use member 3 and submit the campaign property.",
                 "Use the file named d27--sample-legacy.bin and submit the campaign property.",
                 "Report the campaign property of the legacy build.",
                 "Use the record whose url ends with '/api/BR26-003' and submit the campaign property."]
        got = [(t[:60], ask_zip(outside, t)) for t in texts]
        check("N2a a selector that names a record of ANOTHER day answers nothing, however the other day records agree",
              all(v is None for _, v in got), got)
        bytemap = bytes((b + 1) & 0xFF for b in make_record(cfg(5), key=0x45))          # BR27-005 under a +1 byte map
        unread = {f"d{D}--sample-vulnerable.bin": member([V]), f"d{D}--sample-mirror.bin": member([Dd]),
                  f"d{D}--sample-corrected.bin": member([bytemap])}
        got = [(t[:60], ask_zip(unread, t)) for t in (
            "Use the unique d27-- member whose basename ends corrected.bin and submit the campaign property.",
            "In evidence.zip, Use the unique d27-- member whose basename ends corrected.bin." + LIT_TAIL,
            "Use member 3 and submit the campaign property.")]
        check("N2b a named member whose record the walk cannot read answers nothing", all(v is None for _, v in got), got)
        # the established forms (the hole is on the base too): the third / version 3 / campaign BR26-003 name the day-26 record
        one3 = {f"d{D}--sample.bin": member([make_record(cfg(0), version=1, key=0x41),
                                             make_record(dict(cfg(0), domain="mirror.day27.example.invalid"),
                                                         version=2, key=0x42),
                                             make_record(cfg(3, day=26), version=3, key=0x43)])}
        got = [(t[:50], ask_zip(one3, t)) for t in ("Use the third HCFG record and submit the campaign property.",
                                                    "Use the HCFG record with version 3 and submit the campaign property.",
                                                    "Use the record for campaign BR26-003 and submit the campaign property.")]
        check("N2c the established forms name the day-26 record too: nothing is answered from the day-27 records' agreement",
              all(v is None or kind_of(v) != "plain" for _, v in got), got)
        got = [(t[:50], ask_zip(one3, t)) for t in ("Use the 9th HCFG record and submit the campaign property.",
                                                    "Use the HCFG record with version 9 and submit the campaign property.",
                                                    "Use the record for campaign BR27-777 and submit the campaign property.")]
        check("N2d ...and a position, a version or a campaign no record has is never plain from the others' agreement",
              all(kind_of(v) != "plain" for _, v in got), got)
        twin = {f"d{D}--sample-a.bin": member([make_record(cfg(0), key=0x41),
                                               make_record(dict(cfg(0), domain="b.day27.example.invalid"), key=0x42)]),
                f"d{D}--sample-b.bin": member([make_record(cfg(1), key=0x43)])}
        frame = "In evidence.zip, Use the unique d27-- member whose basename ends a.bin."
        v = ask_zip(twin, frame + LIT_TAIL)
        check("N2e positive control: a member of two day records that AGREE on the field answers it, plain, in the frame",
              frame_pick(v, "BR27-000"), v)
        v = ask_zip(twin, frame + LIT_TAIL.replace("campaign property", "domain property"), "domain")
        check("N2f ...and None on a field they differ on", v is None, v)
        real = (SAVED_CHALLENGES or Path(os.devnull)) / "day-24" / "binary-reverse-engineering-day-24-patch-diffing" / "members"
        if (real / "d24--sample-vulnerable.jar").is_file():
            vul = (real / "d24--sample-vulnerable.jar").read_bytes()
            rj = dict(generic.record_pool([("d24--sample-vulnerable.jar", vul)], 24)[0]["json"])
            files24 = {"d24--sample-vulnerable.jar": vul,
                       "d24--sample-mirror.bin": member([make_record(dict(rj, domain="mirror.day24.example.invalid"), key=0x72)]),
                       "d24--sample-legacy.bin": member([make_record(dict(rj, campaign="BR23-004",
                                                                          domain="old.day23.example.invalid"), key=0x73)])}
            buf = io.StringIO()
            with redirect_stderr(buf):
                v = generic.answers("d24", [q("d24_analysis_config_campaign",
                                              "In evidence.zip, Use the unique d24-- member whose basename ends legacy.bin."
                                              + LIT_TAIL)], dict(files24), {"delivery": zip_of(files24)})["d24_analysis_config_campaign"]
            check("N2g the real Day 24 jar beside a day-23 'legacy.bin': the generator's own frame names the day-23 record, "
                  "so nothing is answered (not the jar's BR24-000)", v is None, v)
        else:
            print("skip N2g (no saved Day 24 members)")
    parts.append(("N2", part_n2))

    def part_n3():
        # N3 (issue 3): plain is an allow-list, not a deny-list
        vc = {f"d{D}--sample-vulnerable.jar": member([R[0]]), f"d{D}--sample-corrected.jar": member([R[1]])}
        frame = "In evidence.zip, Use the unique d27-- member whose basename ends corrected.jar."
        check("N3a the generator's frame and its known tail are the frame reading", frame_pick(ask_zip(vc, frame + LIT_TAIL), CAMP[1]),
              ask_zip(vc, frame + LIT_TAIL))
        v = ask_zip(vc, frame + LIT_TAIL + " Use the build as it was released.")
        check("N3b ...the same with one sentence nobody judged is a tagged pick of that record, never plain",
              pick_eq(v, CAMP[1]), v)
        v = ask_zip(vc, "In evidence.zip, Use the unique d27-- member whose basename ends with corrected.jar." + LIT_TAIL)
        check("N3c ...'ends with' is not the generator's frame: a tagged pick", pick_eq(v, CAMP[1]), v)
        redirects = [" Its config was superseded. Submit the campaign property of the superseding build.",
                     " It is the reference build. Submit the campaign property of the build compared against it.",
                     " That member is a decoy-free baseline; report the campaign property of the remaining role member.",
                     " Then switch to the counterpart build and submit its campaign property.",
                     " Ignore it and submit the campaign property of the vulnerable role member.",
                     " Its config holds the old values. Report the campaign property of the build that replaced it."]
        got = [(x[:50], ask_zip(vc, frame + x)) for x in redirects]
        check("N3d the generator's frame followed by a sentence that redirects to the OTHER build is never plain",
              all(kind_of(v) != "plain" for _, v in got), got)
        disj = [("Use the member whose basename ends corrected.jar or vulnerable.jar and submit the campaign property.", vc),
                ("Use the file named d27--sample-corrected.jar or d27--sample-vulnerable.jar and submit the campaign "
                 "property.", vc),
                ("Use the member whose basename ends corrected.jar, vulnerable.jar and submit the campaign property.", vc),
                ("Use member 2 or member 1, whichever holds a record, and submit the campaign property.", vc),
                (f"Use the record whose domain is '{DOM[1]}' or '{DOM[0]}' and submit the campaign property.", ONE),
                (f"Use the record whose domain is '{DOM[1]}', '{DOM[0]}' and submit the campaign property.", ONE)]
        got = [(t[:60], ask_zip(files, t)) for t, files in disj]
        check("N3e a disjunction or a list of literals names several records: None", all(v is None for _, v in got), got)
        selectors = {"member N": ("member 2", abg), "ordinal member": ("the second member", abg),
                     "basename": ("the member whose basename ends beta.bin", abg),
                     "file named": (f"the file named d{D}--sample-beta.bin", abg), "build word": ("the beta build", abg),
                     "field equality": (f"the record whose domain is '{DOM[1]}'", ONE),
                     "ordinal record": ("the second HCFG record", ONE), "record #N": ("record #2", ONE),
                     "version": ("the record with version 2", ONE), "campaign": ("the record for campaign BR27-001", ONE)}
        leaks = [(n, f[:40], v) for n, (x, files) in selectors.items() for f in A2_FRAMES
                 for v in [ask_zip(files, f.replace("{X}", x))] if kind_of(v) == "plain"]
        check(f"N3f the review's sweep: {len(selectors)} selector phrases x {len(A2_FRAMES)} frames, no plain answer "
              f"(329 on 7dc4a4b)", not leaks, leaks[:3])
        # a held-out drill: frames with a random made-up word where a relation word would stand. A vocabulary cannot know
        # a word nobody has written; the new hard selectors do not need to: outside the generator's own wording they are
        # never plain
        rng = random.Random(2701)
        vowels, cons = "aeiou", "bcdfghjklmnprstvz"

        def word():
            return "".join(rng.choice(cons) + rng.choice(vowels) for _ in range(rng.randint(2, 4)))

        shapes = ["Use the record that {w} {X} and submit the campaign property.",
                  "Use the record {w} {X} and submit the campaign property.",
                  "Use the {w} of {X} and submit the campaign property.",
                  "Take the one that {w} {X}; submit the campaign property.",
                  "{X} {w}. Use the {w2} one and submit the campaign property.",
                  "Submit the campaign property of whatever {w} {X}.",
                  "Use {X} {w} {w2} and submit the campaign property."]
        leaks, total = [], 0
        for name in ("member N", "ordinal member", "basename", "file named", "build word", "field equality"):
            x, files = selectors[name]
            for _ in range(60):
                total += 1
                text = rng.choice(shapes).replace("{w2}", word()).replace("{w}", word()).replace("{X}", x)
                text = text[0].upper() + text[1:]
                v = ask_zip(files, text)
                if kind_of(v) == "plain":
                    leaks.append((name, text, v))
        check(f"N3g held-out drill: {total} frames with a made-up word in the relation slot, none plain for a new hard "
              f"selector", not leaks, leaks[:3])
        # a judged table that cannot be read knows no sentence: nothing is plain (it fails closed)
        loaded = generic._record_select_module()          # generic loads its own copy of record_select.py
        known = getattr(loaded, "_KNOWN", None)
        if known is None:
            check("N3h with no judged sentences known the generator's frame is a tagged pick, not plain", False,
                  "this record_select.py has no allow-list")
        else:
            saved = list(known)
            known[:] = [{}]                                 # no kind of config question has a known sentence
            try:
                v = ask_zip(vc, frame + LIT_TAIL)
            finally:
                known[:] = saved
            check("N3h with no judged sentences known the generator's frame is a tagged pick, not plain",
                  pick_eq(v, CAMP[1]), v)
        frame_of = getattr(rs, "_positive_frame", lambda *a: "no allow-list")
        check("N3i the frame is read from the normalised text (a Mastery's lead dropped), the prefix's own day named",
              frame_of("In delivery 3: evidence.zip, Use the unique d31-- member whose basename ends x1.jar." + LIT_TAIL,
                       "analysis_config_campaign", "d31") == ("basename", "x1.jar")
              and frame_of("In delivery 3: evidence.zip, Use the unique d31-- member whose basename ends x1.jar."
                           + LIT_TAIL, "analysis_config_campaign", "d27") is None,
              frame_of(frame + LIT_TAIL, "analysis_config_campaign", "d27"))
        # fix round 2: only the id's OWN property word is masked; a tail that asks another member's property is no
        # known sentence of this id
        check("N3j ...and the property word of the submit sentence is masked only for the id's own member, a sentence "
              "nobody judged is not known",
              frame_of(frame + LIT_TAIL.replace("campaign property", "region property"), "analysis_config_region", "d27")
              == ("basename", "corrected.jar")
              and frame_of(frame + LIT_TAIL.replace("campaign property", "region property"), "analysis_config_campaign",
                           "d27") is None
              and frame_of(frame + " Do something else entirely.", "analysis_config_campaign", "d27") is None, "")
    parts.append(("N3", part_n3))

    def part_n3t():
        # N3t (issue 3): a lead that selects members and a wrapper procedure are no known tail beside the generator's frame
        loaded = generic._record_select_module()
        ks = getattr(loaded, "_known_sentences", None)
        known = set().union(*(ks(k) for k in ("member", "crc", "version", "xor"))) if ks else None
        check("N3t1 the known sentences are the standard procedure and tail ones (no `in evidence.zip` lead, no overlay, "
              "packed, scratch, digest or `at +N` sentence)", bool(known) and len(known) > 20 and not any(
                  "in evidence.zip" in k or "overlay" in k or "scratch" in k or "packed" in k or "sha-256" in k
                  or "at +" in k for k in known), "no allow-list" if known is None else sorted(known)[:3])
        vc = {f"d{D}--sample-vulnerable.jar": member([R[0]]), f"d{D}--sample-corrected.jar": member([R[1]])}
        frame = "In evidence.zip, Use the unique d27-- member whose basename ends corrected.jar."
        for extra_sentence in (" Find the final RS20 overlay.",
                               " Read k1 at +5, k2 at +6, packed length u32le at +8, the 32-byte unpacked SHA-256 at +12, "
                               "and packed bytes at +44.",
                               " In evidence.zip, Use all d27-- members in ZIP central-directory order.",
                               " In evidence.zip, Use the d27-- plugin.cmxs member;"):
            v = ask_zip(vc, frame + LIT_TAIL + extra_sentence)
            check(f"N3t2 the generator's frame and tail followed by `{extra_sentence.strip()[:40]}...` is a tagged pick, "
                  f"never plain", pick_eq(v, CAMP[1]), v)
    parts.append(("N3t", part_n3t))

    def part_n4():
        # N4 (issues 3 and 5): a reading the judge accepts is a reading of that wording only
        tA = "Use member 2 and submit the campaign property."
        vA = ask_zip(abg, tA)
        check("N4a a new hard selector in another wording is a one-option pick whose key carries the text",
              pick_eq(vA, CAMP[1]) and labels.parse(vA).key.startswith("binary.config_campaign/recsel_member_number+t"), vA)
        accept_key(labels.parse(vA).key, labels.parse(vA).options[0][0])
        # fix round 2: the reading's name carries the pool's scope, so the acceptance is a fact of that delivery
        check("N4b ...and once the judge accepted that wording on this delivery, this delivery replays it plain",
              plain_eq(ask_zip(abg, tA), CAMP[1]), ask_zip(abg, tA))
        abg2 = {f"d{D}--sample-alpha.bin": member([R[0]]), f"d{D}--sample-beta.bin": member([R[2]]),
                f"d{D}--sample-gamma.bin": member([R[1]])}
        v2 = ask_zip(abg2, tA)
        check("N4b2 ...while another variant of the same wording is a pick again, not plain (fix round 2)",
              pick_eq(v2, CAMP[2]), v2)
        for t in ("Use member 2, then submit the campaign property.", "Use member 2 and report the campaign property.",
                  "Use member 2 and submit the campaign property, last of all.",
                  "Use member 2 and submit the domain property."):
            v = ask_zip(abg, t, "domain" if "domain" in t else "campaign")
            check(f"N4c ...but another wording of the same reading stays a pick ({t[:44]})", kind_of(v) != "plain", v)
    parts.append(("N4", part_n4))

    def part_n4s():
        # N4s (issue 5): the soft readings' keys, and the candidates key, name the wording too
        ts3 = {f"d{D}--sample.bin": member([make_record(cfg(0, built="2026-10-01T00:00:00Z"), version=1, key=0x41),
                                            make_record(cfg(1, built="2026-10-20T12:00:00Z"), version=2, key=0x42),
                                            make_record(cfg(2, built="2026-09-15T08:30:00Z"), version=3, key=0x43)])}
        tN = "Use the newest HCFG record and submit the campaign property."
        vN = ask_zip(ts3, tN)
        check("N4d a soft reading's key carries the text too", pick_eq(vN, CAMP[1])
              and labels.parse(vN).key.startswith("binary.config_campaign/recsel_newest_by_built+t"), vN)
        accept_key(labels.parse(vN).key, labels.parse(vN).options[0][0])
        check("N4e ...plain once that wording is accepted on this delivery", plain_eq(ask_zip(ts3, tN), CAMP[1]),
              ask_zip(ts3, tN))
        for t in ("Use the newest record. It was superseded; report the campaign property of the one it superseded.",
                  "Use the record released ahead of the newest record and submit the campaign property.",
                  "Use the second newest record and submit the campaign property.",
                  "Use the newest HCFG record, then submit the campaign property.",
                  "Use the record that followed the newest record and submit the campaign property."):
            v = ask_zip(ts3, t)
            check(f"N4f ...and no other wording is plain after it ({t[:44]})", kind_of(v) != "plain", v)
        for t in ("Use the second newest record and submit the campaign property.",
                  "Use the next-to-newest record and submit the campaign property.",
                  "Use the second most recent record and submit the campaign property.",
                  "Use the third oldest record and submit the campaign property.",
                  "Use the record with the second highest version and submit the campaign property."):
            check(f"N4g an ordinal before the extreme word names no record ({t[8:44]})", ask_zip(ts3, t) is None,
                  ask_zip(ts3, t))
        # the established candidates key carries the text as well (the hypothesis 'record_1' is the first value of THIS text)
        two = {f"d{D}--sample.bin": member([make_record(cfg(0), key=0x41), make_record(cfg(1), key=0x42)])}
        vC = ask_zip(two, "Use the 5th HCFG record and submit the campaign property.")
        check("N4h an unresolved established selector offers candidates under a text-tagged key",
              labels.is_candidate(vC) and "+t" in labels.parse(vC).key, vC)
        accept_key(labels.parse(vC).key, "record_1")
        vC2 = ask_zip(two, "Use the 6th HCFG record and submit the campaign property.")
        check("N4i ...whose accepted name answers no other wording", kind_of(vC2) != "plain", vC2)
    parts.append(("N4s", part_n4s))

    def part_n5():
        # N5 (issue 4): the patch-difference keys name the id and the wording
        pdf = {f"d{D}--sample-vulnerable.bin": member([make_record(cfg(0), key=0x41)]),
               f"d{D}--sample-patched.bin": member([make_record(dict(cfg(0), domain="fixed.day27.example.invalid"),
                                                                key=0x41)])}

        def pd(items):
            buf = io.StringIO()
            with redirect_stderr(buf):
                return answers_closed(f"d{D}", [q(f"d{D}_analysis_{i}", t, k) for i, t, k in items], dict(pdf), {})

        items = [("patch_changed_field", T_CH, "exact_text"),
                 ("diff_symbol_name", "Which exported symbol name differs between the vulnerable and the patched build?",
                  "exact_text"),
                 ("patch_member_name", "Name the d27-- member whose bytes the patch changed.", "exact_text"),
                 ("diff_count", "How many machine instructions does the patch change?", "integer"),
                 ("patch_changed_count", "How many bytes differ between the two builds' .text sections?", "integer")]
        got = pd(items)
        check("N5a only the id that asks about the config is claimed: the symbol, member, count and byte-count ids of an "
              "instruction patch are None", {k.split("analysis_")[1]: kind_of(v) for k, v in got.items()} ==
              {"patch_changed_field": "unsure", "diff_symbol_name": "none", "patch_member_name": "none",
               "diff_count": "none", "patch_changed_count": "none"}, got)
        k1 = labels.parse(got[f"d{D}_analysis_patch_changed_field"]).key
        check("N5b the key carries the id's field and the text's tag", k1.startswith("binary.patch_diff/changed_key+"
              "analysis_patch_changed_field+t") and not k1.endswith("#candidates"), k1)
        accept_key(k1, labels.parse(got[f"d{D}_analysis_patch_changed_field"]).options[0][0])   # `config_key@<pair>`
        got = pd(items + [("diff_key_name", T_CH, "exact_text"),
                          ("patch_changed_field_again", "Name the config key whose value the patch changed.", "exact_text")])
        shown = {k.split("analysis_")[1]: kind_of(v) for k, v in got.items()}
        check("N5c after ONE acceptance only that id and that wording are plain: another id of the same text, another "
              "wording of the id, and the four unrelated ids are not",
              shown == {"patch_changed_field": "plain", "diff_symbol_name": "none", "patch_member_name": "none",
                        "diff_count": "none", "patch_changed_count": "none", "diff_key_name": "unsure",
                        "patch_changed_field_again": "unsure"}, shown)
        check("N5d ...and the plain one is the changed key", got[f"d{D}_analysis_patch_changed_field"] == "domain",
              got[f"d{D}_analysis_patch_changed_field"])
        cls = [("d27_analysis_patch_changed_field", "Which config field changed?", ("key", None)),
               ("d27_analysis_patch_changed_field", "Which exported symbol changed?", None),
               ("d27_analysis_diff_symbol_name", "Which HCFG symbol name differs?", None),
               ("d27_analysis_patch_member_name", "Which config member changed?", None),
               ("d27_analysis_diff_config_member", "Which config member changed?", ("key", None)),
               ("d27_analysis_diff_count", "How many config keys differ?", ("count", None)),
               ("d27_analysis_diff_count", "How many machine instructions differ?", None),
               ("d27_analysis_patch_total", "How many bytes does the patch change?", None),
               ("d27_analysis_patch_total_fields", "How many config fields does the patch change?", ("count", None)),
               ("d27_analysis_patched_changed_value", "Value of the changed JSON member?", ("value", "patched")),
               ("d27_analysis_patched_changed_value", "Value of the changed header byte?", None),
               ("d27_analysis_patch_offset", "Byte offset of the first byte the patch changes in the HCFG payload.",
                ("offset", None)),
               ("d27_analysis_patch_offset", "Byte offset of the patch in the HCFG payload.", None),   # no difference word
               ("d27_analysis_patch_offset", "Read the u32le at file offset 0x40 of the corrected member.", None),
               ("d27_analysis_patch_offset", "Byte offset of the patch.", None),
               ("d27_analysis_patch_size", "How many bytes of the HCFG record does the patch change?", ("size", None)),
               ("d27_analysis_patch_size", "Size of the patch record.", None),                       # no difference word
               ("d27_analysis_patch_size", "How many instructions does the patch touch?", None),
               ("d27_analysis_import_count", "How many config imports?", None)]
        bad = [(i, t, pdmod.classify(i, t), want) for i, t, want in cls if pdmod.classify(i, t) != want]
        check("N5e classify: the weak words (member, name, attribute, number, total) need a config word in the id, and a "
              "fact of the config needs the text to name the config", not bad, bad)
    parts.append(("N5", part_n5))

    def part_n6():
        # N6 (issue 6, perf): one walk of the prefix, and the free build-word trigger is gone
        walks = [0]
        real_build = generic._build_pool

        def counted(*a, **k):
            walks[0] += 1
            return real_build(*a, **k)

        generic._build_pool = counted
        try:
            fresh = {f"d{D}--sample-alpha.bin": member([R[0]]), f"d{D}--sample-beta.bin": member([R[1]]),
                     f"d{D}--sample-gamma.bin": member([R[2]])}
            run(fresh, [q(cid("campaign"), "Use member 2 and submit the campaign property."),
                        q(cid("domain"), "Use member 2 and submit the domain property."),
                        q(f"d{D}_analysis_patch_changed_field", T_CH)])
            multi = walks[0]
            walks[0] = 0
            fresh = {f"d{D}--sample.bin": member([make_record(cfg(0), key=0x41), make_record(cfg(1), key=0x42)])}
            run(fresh, [q(cid(f), f"Decode the sample's HCFG record and submit the {f} property of the sample.")
                        for f in ("campaign", "domain", "url", "mutex", "crc32_hex")])
            boiler = walks[0]
        finally:
            generic._build_pool = real_build
        check("N6a one walk of the prefix's members for a whole answers() call that selects among records and reads a "
              "difference (2 on 7dc4a4b)", multi == 1, multi)
        check("N6b ...and one for five config ids left None under 'the sample' boilerplate (2 on 7dc4a4b)", boiler == 1,
              boiler)
        nm = [f"d{D}--sample-alpha.bin", f"d{D}--sample-beta.bin"]
        check("N6c the build-word trigger reads the member names: 'the beta build' with a beta member, not 'the sample' nor "
              "'a managed binary'", rs.states_selector("Report the campaign property of the beta build.", nm)
              and not rs.states_selector("Report the campaign property of the beta build.", [f"d{D}--sample-alpha.bin"])
              and not rs.states_selector("Report the campaign property of the beta build.")
              and not rs.states_selector("Decode the sample's HCFG record and submit the domain property of the sample.", nm)
              and not rs.states_selector("Parse a managed binary and submit the url.", nm), "")
        pools = [0]
        real_pool = generic.record_pool

        def counted_pool(*a, **k):
            pools[0] += 1
            return real_pool(*a, **k)

        walks[0] = 0
        generic._build_pool, generic.record_pool = counted, counted_pool
        try:
            blank = {f"d{D}--sample.elf": bytes(random.Random(5).getrandbits(8) for _ in range(4096))}
            out = run(blank, [q(cid("campaign"), "Use member 1 and submit the campaign property."),
                              q(cid("domain"), "Use the beta build and submit the domain property.")])
        finally:
            generic._build_pool, generic.record_pool = real_build, real_pool
        check("N6d a prefix whose walk read no record builds no record pool and walks once (a second walk on 7dc4a4b)",
              pools[0] == 0 and walks[0] == 1 and all(v is None for v in out.values()), (pools[0], walks[0], out))
    parts.append(("N6", part_n6))

    def part_n7():
        # N7 (issue 7, perf): the first difference is found a block at a time
        import numpy as np
        rng = random.Random(7)
        ok = True

        def reference(x, y):
            m = min(len(x), len(y))
            d = np.flatnonzero(np.frombuffer(x[:m], dtype=np.uint8) != np.frombuffer(y[:m], dtype=np.uint8))
            return int(d[0]) if len(d) else (m if len(x) != len(y) else None)

        for size in (0, 1, 5, 65535, 65536, 65537, 131072, 200003):
            base = bytes(rng.randrange(256) for _ in range(size))
            variants = [base, base + b"x", base[:-1] if size else base]
            for at in (0, size // 2, size - 1, 65535, 65536, 65537):
                if 0 <= at < size:
                    variants.append(base[:at] + bytes([(base[at] + 1) & 0xFF]) + base[at + 1:])
            for x in variants:
                for y in (base, base + b"zz"):
                    if pdmod._first_diff(x, y) != reference(x, y):
                        ok = False
                        print("   _first_diff differs", size, len(x), len(y), pdmod._first_diff(x, y), reference(x, y))
        check("N7a _first_diff equals an independent reference over block edges, prefixes, equal inputs and empty ones", ok, "")
        import time
        body = bytes(range(256)) * (16 * 1024 * 1024 // 256)
        x, y = body + b"\x00", body + b"\x01"
        best = 9.9
        for _ in range(3):
            t0 = time.perf_counter()
            at = pdmod._first_diff(x, y)
            best = min(best, time.perf_counter() - t0)
        check(f"N7b two 16 MiB builds that differ in the last byte: {best * 1000:.0f} ms (0.41 s as a byte loop)",
              at == len(body) and best < 0.2, (at, best))
    parts.append(("N7", part_n7))

    def part_n8():
        # N8 (issue 8, minor; fix round 2): the patch-difference reader is asked LAST, from evidence.closing() after the
        # stated wrapper, the sidecar, the stated definition and the tagged trailer (fix round 1 asked it at the end of
        # generic.answers, still BEFORE evidence.defined() and evidence.trailer(), which read only ids still None)
        import inspect
        import evidence
        src_g = "\n".join(line.split("#")[0] for line in inspect.getsource(generic.answers).splitlines())  # code only
        src_c = inspect.getsource(evidence.closing).split('"""')[-1]          # the body, not the docstring
        check("N8a generic.answers does not ask the patch-difference reader; evidence.closing asks it after defined() and "
              "trailer()", "diff_answers" not in src_g and "patch_diff_answers" not in src_g
              and src_c.index("patch_facts(") > max(src_c.index("trailer("), src_c.index("defined(")), src_c[-400:])
        pdf = {f"d{D}--sample-vulnerable.bin": member([make_record(cfg(0), key=0x41)]),
               f"d{D}--sample-patched.bin": member([make_record(dict(cfg(0), domain="fixed.day27.example.invalid"),
                                                                key=0x41)])}
        qid = f"d{D}_analysis_patch_changed_key"            # an id and a text no other check's ledger row names
        qs = [{"id": qid, "qid": qid, "question": "Which config key did the patch change?",
               "answer_format": {"kind": "exact_text"}}]

        def closed(**stubs):
            saved = {k: getattr(evidence, k) for k in stubs}
            for k, fn in stubs.items():
                setattr(evidence, k, fn)
            try:
                with redirect_stderr(io.StringIO()):
                    return evidence.closing(f"d{D}", qs, {qid: None}, dict(pdf), {})[qid]
            finally:
                for k, fn in saved.items():
                    setattr(evidence, k, fn)

        def answering(word):
            def stub(prefix, qs_, got, files, ctx):
                got = dict(got)
                for qq in qs_:
                    if got.get(qq["qid"]) is None:
                        got[qq["qid"]] = word
                return got
            return stub

        v = closed()
        check("N8b with nothing before it, evidence.closing gives the id the patch-difference pick",
              kind_of(v) == "unsure" and opts(v) == ["domain"], v)
        check("N8c a stated definition's answer for the same id stands: the diff reader never pre-empts it",
              closed(defined=answering("DEFINED")) == "DEFINED", closed(defined=answering("DEFINED")))
        check("N8d ...nor a tagged trailer's", closed(trailer=answering("TRAILER")) == "TRAILER",
              closed(trailer=answering("TRAILER")))
    parts.append(("N8", part_n8))

    def part_n9():
        # N9 (issues 1, 2, 3): a differential fuzz of the generator's frames over random layouts built from ground truth:
        # a record in two members, a record of another day, a CRC-broken record, a record under a byte map the walk does
        # not read. The oracle is read from the construction. A PLAIN answer must be the value it proves, whatever the
        # layout (the reviewed commit answered 234 of 2,710 such cases plain and wrong)
        rng = random.Random(11)
        sufs = ["alpha.bin", "beta.jar", "corrected.jar", "vulnerable.jar", "legacy.bin", "primary.jar", "mirror.bin"]
        world = {}
        for i in range(6):
            c = cfg(i, domain=f"node-{i:03d}.day27.example.invalid")
            world[f"r{i}"] = (make_record(c, version=1 + i, key=0x41 + i), dict(valid=True, day=True, camp=c["campaign"],
                                                                                 domain=c["domain"]))
        c = cfg(0, domain="twin.day27.example.invalid")
        world["twin"] = (make_record(c, version=9, key=0x4f), dict(valid=True, day=True, camp=c["campaign"], domain=c["domain"]))
        c = cfg(3, day=26)
        world["old"] = (make_record(c, version=3, key=0x43), dict(valid=True, day=False, camp=c["campaign"], domain=c["domain"]))
        c = cfg(4)
        world["broken"] = (make_record(c, version=4, key=0x44, crc_delta=1),
                           dict(valid=False, day=True, camp=c["campaign"], domain=c["domain"]))
        c = cfg(5)
        world["mapped"] = (bytes((b + 1) & 0xFF for b in make_record(c, version=5, key=0x45)),
                           dict(valid=False, day=True, camp=c["campaign"], domain=c["domain"]))

        def oracle(layout, field, suffix=None, number=None):
            names = list(layout)
            if suffix is not None:
                match = [n for n in names if n.lower().endswith(suffix)]
                if len(match) != 1:
                    return None
                mem = match[0]
            else:
                if not 1 <= number <= len(names):
                    return None
                mem = names[number - 1]
            seen, vals = set(), []
            for rid in layout[mem]:
                data, p = world[rid]
                if not p["valid"] or data in seen:
                    continue
                seen.add(data)
                if not p["day"]:
                    return None
                vals.append(p[field])
            return vals[0] if vals and len(set(vals)) == 1 else None

        bad, plain_n, frame_n, cases, skipped = [], 0, 0, 0, 0
        for _ in range(110):
            k = rng.randint(2, 4)
            layout = {f"d{DAY}--sample-{nm}": rng.sample(list(world), rng.randint(1, 3)) for nm in rng.sample(sufs, k)}
            if rng.random() < 0.5:
                a, b = rng.sample(list(layout), 2)
                layout[b] = layout[b] + [rng.choice(layout[a])]
            files = {n: member([world[r][0] for r in ids]) for n, ids in layout.items()}
            if generic.choose_config([(n, bytes(b)) for n, b in files.items()], DAY)[0] is not None:
                skipped += 1               # an established rule answers first, for any text: not this module's domain
                continue
            field = rng.choice(["camp", "domain"])
            qfield = "campaign" if field == "camp" else "domain"
            tail = LIT_TAIL.replace("campaign property", f"{qfield} property")
            frames = [(f"In evidence.zip, Use the unique d27-- member whose basename ends {suf}." + tail, dict(suffix=suf))
                      for suf in rng.sample(sufs, 3) + ["jar", "bin"]]
            frames += [(f"Use the HCFG record of member {num}, where members are the d27-- members in ZIP "
                        f"central-directory order (1-based)." + tail, dict(number=num)) for num in (1, 2, k, k + 1)]
            for text, kw in frames:
                cases += 1
                v = ask_zip(files, text, qfield)
                if kind_of(v) == "plain":
                    plain_n += 1           # never, since the fourth review of fix round 2
                    bad.append((layout, kw, v, "plain"))
                elif is_frame(v):
                    frame_n += 1           # the frame reading: its one option must be the value the construction proves
                    want = oracle(layout, field, **kw)
                    if want is None or opts(v) != [want]:
                        bad.append((layout, kw, v, want))
        check(f"N9 frames fuzz: {cases} frame cases over {110 - skipped} random layouts, {plain_n} plain, {frame_n} frame "
              f"readings, each the value the construction proves (plain before the fourth review)",
              not bad and plain_n == 0 and frame_n > 100, (len(bad), plain_n, frame_n, bad[:2]))
    parts.append(("N9", part_n9))

    def part_n10():
        # N10 (issue 1, the established forms): the same, for a position, a header version and a campaign. A position
        # counts only up to the first header that makes the file differ from the deduped pool (an identical copy of an
        # earlier header, a CRC-broken one), wherever that header stands, a member that holds nothing but a copy included
        rng = random.Random(5)
        world = {}
        for i in range(6):
            c = cfg(i)
            world[f"r{i}"] = (make_record(c, version=1 + i, key=0x41 + i), dict(valid=True, day=True, camp=c["campaign"],
                                                                                 ver=1 + i))
        c = cfg(0, domain="twin.day27.example.invalid")
        world["twin"] = (make_record(c, version=9, key=0x4f), dict(valid=True, day=True, camp=c["campaign"], ver=9))
        c = cfg(3, day=26)
        world["old"] = (make_record(c, version=3, key=0x43), dict(valid=True, day=False, camp=c["campaign"], ver=3))
        c = cfg(4)
        world["broken"] = (make_record(c, version=4, key=0x44, crc_delta=1),
                           dict(valid=False, day=True, camp=c["campaign"], ver=4))
        ordinal = {1: "first", 2: "second", 3: "third", 4: "fourth", 5: "fifth"}
        bad, plain_n, pick_n, cases = [], 0, 0, 0
        for _ in range(240):
            layout = {f"d{DAY}--sample-m{j}.bin": rng.sample(list(world), rng.randint(1, 3)) for j in range(rng.randint(1, 3))}
            if rng.random() < 0.4 and len(layout) >= 2:
                a, b = rng.sample(list(layout), 2)
                layout[b] = layout[b] + [rng.choice(layout[a])]
            files = {n: member([world[r][0] for r in ids]) for n, ids in layout.items()}
            if generic.choose_config([(n, bytes(b)) for n, b in files.items()], DAY)[0] is not None:
                continue
            flat = [r for n in layout for r in layout[n]]
            disturb = len(flat)
            for ix, r in enumerate(flat):
                if r in flat[:ix] or not world[r][1]["valid"]:
                    disturb = ix
                    break
            valid = []
            for r in flat:
                if world[r][1]["valid"] and world[r] not in [world[x] for x in valid]:
                    valid.append(r)
            texts = [(f"Use the {ordinal[k]} HCFG record and submit the campaign property.", ("pos", k)) for k in range(1, 6)]
            texts += [(f"Use the HCFG record with version {v} and submit the campaign property.", ("ver", v))
                      for v in (1, 2, 3, 4, 5, 9)]
            texts += [(f"Use the record for campaign {c} and submit the campaign property.", ("camp", c))
                      for c in ("BR27-000", "BR27-003", "BR26-003", "BR27-777")]
            for text, (kind, arg) in texts:
                cases += 1
                v = ask_zip(files, text)
                if kind_of(v) == "plain":
                    plain_n += 1           # never, since fix round 2: an established form is a reading, not a proof
                    bad.append((layout, text, v))
                    continue
                if kind_of(v) != "unsure" or labels.is_candidate(v):
                    continue
                pick_n += 1
                v = opts(v)[0] if len(opts(v)) == 1 else None
                if kind == "pos":
                    ok = arg - 1 < disturb and world[flat[arg - 1]][1]["day"] and world[flat[arg - 1]][1]["camp"] == v
                else:
                    key = "ver" if kind == "ver" else "camp"
                    hit = [r for r in valid if world[r][1][key] == arg]
                    ok = len(hit) >= 1 and all(world[r][1]["day"] and world[r][1]["camp"] == v for r in hit)
                if not ok:
                    bad.append((layout, text, v))
        check(f"N10 established forms fuzz: {cases} cases, {plain_n} plain, {pick_n} one-option picks, every pick the record "
              f"the text names (128 wrong plain of 7,275 on the reviewed commit; fix round 2: never plain)",
              not bad and plain_n == 0 and pick_n > 300, (len(bad), plain_n, pick_n, bad[:2]))
        # the member that holds only a copy of the first record has no record kept under it, and still shifts the positions
        shifted = {f"d{DAY}--sample-m0.bin": member([world["r0"][0]]), f"d{DAY}--sample-m1.bin": member([world["r0"][0]]),
                   f"d{DAY}--sample-m2.bin": member([world["r3"][0], world["r1"][0], world["r4"][0]])}
        v = ask_zip(shifted, "Use the second HCFG record and submit the campaign property.")
        check("N10b 'the second HCFG record' beside a member that holds only a copy of the first is not plain "
              "(it answered the deduped pool's second, BR27-003)", kind_of(v) != "plain", v)
        v = ask_zip(shifted, "Use the first HCFG record and submit the campaign property.")
        check("N10c ...nor is the first: a spare magic anywhere in the prefix refuses every position (conservative; "
              "the clean prefix of D3 still answers plain)", kind_of(v) != "plain", v)
    parts.append(("N10", part_n10))

    def part_n11():
        # N11 (issue 2, the role form): a role word marks every member that holds a record, and a plain answer is the one
        # distinct valid day record those members hold
        rng = random.Random(3)
        roles_all = ["vulnerable", "corrected", "patched", "original"]
        world = {}
        for i in range(5):
            c = cfg(i)
            world[f"r{i}"] = (make_record(c, version=1 + i, key=0x41 + i), dict(valid=True, day=True, camp=c["campaign"]))
        c = cfg(3, day=26)
        world["old"] = (make_record(c, version=3, key=0x43), dict(valid=True, day=False, camp=c["campaign"]))
        c = cfg(4)
        world["broken"] = (make_record(c, version=4, key=0x44, crc_delta=1), dict(valid=False, day=True, camp=c["campaign"]))
        bad, plain_n, pick_n, cases = [], 0, 0, 0
        for _ in range(200):
            roles = rng.sample(roles_all + ["alpha", "beta"], rng.randint(2, 4))
            layout = {f"d{DAY}--sample-{r}.bin": rng.sample(list(world), rng.randint(1, 3)) for r in roles}
            if rng.random() < 0.4:
                a, b = rng.sample(list(layout), 2)
                layout[b] = layout[b] + [rng.choice(layout[a])]
            files = {n: member([world[r][0] for r in ids]) for n, ids in layout.items()}
            if generic.choose_config([(n, bytes(b)) for n, b in files.items()], DAY)[0] is not None:
                continue
            for role in roles_all:
                cases += 1
                v = ask_zip(files, f"Report the campaign property of the {role} build.")
                if kind_of(v) == "plain":
                    plain_n += 1           # never, since fix round 2
                    bad.append((layout, role, v))
                    continue
                if kind_of(v) != "unsure" or labels.is_candidate(v) or "/recsel_role+" not in labels.parse(v).key:
                    continue               # a complement reading ("the patched build" with only an original marked) is
                    # a soft interpretation, pinned by C13/C14/C18, not by this oracle of the members a role word marks
                pick_n += 1
                v = opts(v)[0] if len(opts(v)) == 1 else None
                holders = [n for n in layout if role in n.lower().split("--sample-")[1].replace(".bin", "").split("-")]
                seen, vals, day_ok = [], [], True
                for n in holders:
                    for rid in layout[n]:
                        data, p = world[rid]
                        if p["valid"] and data not in seen:
                            seen.append(data)
                            day_ok = day_ok and p["day"]
                            vals.append(p["camp"])
                if not (holders and day_ok and vals and set(vals) == {v}):
                    bad.append((layout, role, v))
        check(f"N11 role fuzz: {cases} cases, {plain_n} plain, {pick_n} one-option picks, every pick the one record the "
              f"role's members hold (265 wrong plain of 2,976 on the reviewed commit; fix round 2: never plain)",
              not bad and plain_n == 0 and pick_n > 50, (len(bad), plain_n, pick_n, bad[:2]))
    parts.append(("N11", part_n11))

    def part_n12():
        # N12 (issue 3): a record's value that is already unsure (a number asked as text is a type-form pick under a key every
        # id of that form shares) is re-keyed under the wording when the selection is not proven, as a plain one is
        recs = [make_record(cfg(i, port=8000 + i), version=1 + i, key=0x41 + i) for i in range(3)]
        files = {f"d{D}--sample-alpha.bin": member([recs[0]]), f"d{D}--sample-beta.bin": member([recs[1]]),
                 f"d{D}--sample-gamma.bin": member([recs[2]])}
        frame = ("In evidence.zip, Use the unique d27-- member whose basename ends beta.bin."
                 + LIT_TAIL.replace("campaign property", "port property"))
        vf = ask_zip(files, frame, "port")
        pf = labels.parse(vf)
        # fourth review of fix round 2: the frame is a reading too, so its already-unsure value is re-keyed under the
        # frame reading like any other (it kept the shared type-form key while the frame was plain)
        inner = pf.options[0][0].split(":", 1)[1].split("@")[0] if pf and ":" in pf.options[0][0] else None
        check("N12a in the generator's frame the record's unsure value is re-keyed under the frame reading, named for the "
              "delivery", pf is not None and pf.key.startswith("binary.config_port/recsel_frame_basename+t")
              and opts(vf) == ["8001"] and pf.options[0][0].startswith("frame_basename:") and "@" in pf.options[0][0], vf)
        vn = ask_zip(files, "Use member 2 and submit the port property.", "port")
        pn = labels.parse(vn)
        check("N12b in another wording the same value is re-keyed under the wording, its options named for the reading "
              "and the pool's scope", pn is not None and pn.key.startswith("binary.config_port/recsel_member_number+t")
              and opts(vn) == ["8001"] and len(pn.options) == 1
              and pn.options[0][0].startswith(f"member_number:{inner}@"), vn)
        accept_key(pf.key, pf.options[0][0])
        check("N12c once the frame reading is accepted on this delivery, this delivery replays it plain",
              plain_eq(ask_zip(files, frame, "port"), "8001"), ask_zip(files, frame, "port"))
        vn2 = ask_zip(files, "Use member 2 and submit the port property.", "port")
        check("N12d ...and the other wording is still a tagged pick, not plain, whatever the shared key took",
              kind_of(vn2) == "unsure" and "+t" in labels.parse(vn2).key, vn2)
    parts.append(("N12", part_n12))

    def part_n13():
        # N13: generic.answers keeps calling the MODULE's member_names(files) for the members of every other config of the
        # delivery. A local of the same name once shadowed it (the first draft of this fix): every known() call raised and a
        # config member missing from the prefix's container was answered by the catalog's unsure pick instead of the
        # lane's plain `none` (found by solvers/binary/test_generic.py none_rules, which no KB-3 check exercised)
        present = cfg(0)
        absent = {k: v for k, v in cfg(0).items() if k != "url"}
        files = {f"d{D}--sample.bin": member([make_record(absent, key=0x41)]),
                 "d26--other.bin": member([make_record(cfg(0, day=26), key=0x42)])}
        out = run(files, [q(cid("url"), "Decode the HCFG record and submit the url property."),
                          q(cid("campaign"), "Decode the HCFG record and submit the campaign property.")])
        check("N13a a member absent from the prefix's container and present in another config of the delivery is the "
              "lane's plain `none`", out[cid("url")] == "none" and kind_of(out[cid("url")]) == "plain", out)
        check("N13b ...and the member it does hold is still read", plain_eq(out[cid("campaign")], "BR27-000"), out)
        import inspect
        src = inspect.getsource(generic.answers)
        check("N13c no local of generic.answers is named like a module function it calls (member_names)",
              "member_names =" not in src.replace("prefix_member_names =", ""), "")
    parts.append(("N13", part_n13))

    for name, fn in parts:
        try:
            fn()
        except Exception as e:           # one part's crash is a failure of that part, not of the run
            check(f"{name} part ran to its end", False, f"{type(e).__name__}: {e}")

def fix2_section():
    """P: fix round 2 of the review of KB-3, on the tree of fix round 1 (685c138). One check per review item on its
    repro (the reviewer's scripts a1 to a12), and the restrictions of the round: PLAIN is an allow-list (exactly one
    selector, a new hard one, in the generator's own frame, every other sentence a known one, no negation among them;
    the member-number frame only in the delivery's own central-directory order); every other wording, the established
    forms included, is a one-option pick tagged with the text, offered only when no other record renders its value;
    an unresolved established form is a candidates pick whose names carry the pool's scope; the patch-difference reader
    is asked last, and only for a text that states a difference with no negation, an offset only as the first one. Then
    an adversarial pass of new wordings: relations, exclusions, ordinals, "the other build", a selector named in one
    sentence and negated in another, a copy record."""
    D = DAY
    V = make_record(cfg(0), key=0x41)
    V2 = make_record(dict(cfg(0), domain="fixed.day27.example.invalid", campaign="BR27-009"), key=0x41)
    vc = {f"d{D}--sample-vulnerable.jar": member([R[0]]), f"d{D}--sample-corrected.jar": member([R[1]])}
    lead = "In evidence.zip, Use the unique d27-- member whose basename ends corrected.jar."

    # P1 (item 1, a7 and a8): a named record outside the day's readable pool answers nothing, whatever the wording
    mirror = make_record(dict(cfg(0), domain="mirror.day27.example.invalid"), key=0x42)
    legacy = make_record(cfg(3, day=26), key=0x43)
    files = {f"d{D}--sample-vulnerable.bin": member([V]), f"d{D}--sample-mirror.bin": member([mirror]),
             f"d{D}--sample-legacy.bin": member([legacy])}
    texts = ["Use the unique d27-- member whose basename ends legacy.bin and submit the campaign property.",
             "In evidence.zip, Use the unique d27-- member whose basename ends legacy.bin." + LIT_TAIL,
             "Use member 3 and submit the campaign property.",
             "Use the file named d27--sample-legacy.bin and submit the campaign property.",
             "Report the campaign property of the legacy build.",
             "Use the record whose url ends with '/api/BR26-003' and submit the campaign property."]
    got = [ask_zip(files, t) for t in texts]
    check("P1a (item 1, a7) a member whose own record names another day: all six wordings answer None (PLAIN BR27-000 "
          "on 7dc4a4b)", all(v is None for v in got), got)
    mapped = bytes((b + 1) & 0xFF for b in make_record(cfg(5), key=0x45))
    files2 = {f"d{D}--sample-vulnerable.bin": member([V]), f"d{D}--sample-mirror.bin": member([mirror]),
              f"d{D}--sample-corrected.bin": member([mapped])}
    got = [ask_zip(files2, t) for t in ("Use the unique d27-- member whose basename ends corrected.bin and submit the "
                                        "campaign property.", "Use member 3 and submit the campaign property.",
                                        lead.replace(".jar", ".bin") + LIT_TAIL)]
    check("P1b (item 1, a7) a member whose record the walk does not read answers None, the frame too", all(
        v is None for v in got), got)
    one = {f"d{D}--sample.bin": member([make_record(cfg(0), version=1, key=0x41),
                                        make_record(dict(cfg(0), domain="mirror.day27.example.invalid"), version=2,
                                                    key=0x42), make_record(cfg(3, day=26), version=3, key=0x43)])}
    got = [ask_zip(one, t) for t in ("Use the third HCFG record and submit the campaign property.",
                                     "Use the HCFG record with version 3 and submit the campaign property.",
                                     "Use the record for campaign BR26-003 and submit the campaign property.")]
    check("P1c (item 1, a8) the established forms naming a record of another day are never plain (PLAIN BR27-000 on "
          "6aa5104 and 7dc4a4b)", all(not_frame(v) for v in got), got)

    # P2 (item 2, a1): a member that holds a copy of another member's record beside its own holds two records
    cp = {f"d{D}--sample-vulnerable.bin": member([V]), f"d{D}--sample-corrected.bin": member([V, V2])}
    texts = ["In evidence.zip, Use the unique d27-- member whose basename ends corrected.bin." + LIT_TAIL,
             "Use the member whose basename ends corrected.bin and submit the campaign property.",
             "Use the unique d27-- member whose basename ends corrected.bin, accept the first CRC32-valid HCFG record "
             "in it, and submit the campaign property.",
             "Use member 2 and submit the campaign property.",
             "Report the campaign property of the corrected build.",
             "Use the file named d27--sample-corrected.bin and submit the campaign property."]
    got = [ask_zip(cp, t) for t in texts]
    check("P2a (item 2, a1) none of the six wordings answers the copy-holding member's second record plain (PLAIN "
          "BR27-009 on 7dc4a4b)", all(not_frame(v) for v in got), got)
    v = ask_zip(cp, "In evidence.zip, Use the unique d27-- member whose basename ends corrected.bin."
                + LIT_TAIL.replace("campaign property", "mutex property"), "mutex")
    check("P2b ...while a field both of its records agree on is plain in the generator's frame (either record is right)",
          frame_pick(v, cfg(0)["mutex"]), v)

    # P3 (item 3, a10 and a11): the frame beside any sentence that is not a known one, or a disjunction, is never plain
    extras = [" Its config was superseded. Submit the campaign property of the superseding build.",
              " It is the reference build. Submit the campaign property of the build compared against it.",
              " That member is a decoy-free baseline; report the campaign property of the remaining role member.",
              " Then switch to the counterpart build and submit its campaign property.",
              " Ignore it and submit the campaign property of the vulnerable role member.",
              # new wordings of the adversarial pass: a selector named in one sentence and negated or redirected in
              # another, an exclusion, an ordinal, the other build
              " Do not read its record; submit the campaign property of the build it was compared with.",
              " Its record is a decoy." + LIT_TAIL,
              LIT_TAIL + " The answer is the campaign of the build that precedes it in the archive.",
              LIT_TAIL + " Report the other build's campaign instead.",
              " Count builds from the end of the archive." + LIT_TAIL]
    got = [(e.strip()[:50], ask_zip(vc, lead + e)) for e in extras]
    check(f"P3a (item 3, a11 and the adversarial pass) the generator's frame beside {len(extras)} sentences that are not "
          "known ones is never plain", all(not_frame(v) for _, v in got), [g for g in got if kind_of(g[1]) ==
                                                                                       "plain"])
    texts = ["Use the member whose basename ends corrected.jar or vulnerable.jar and submit the campaign property.",
             "Use the file named d27--sample-corrected.jar or d27--sample-vulnerable.jar and submit the campaign property.",
             "Use member 2 or member 1, whichever holds a record, and submit the campaign property.",
             "In evidence.zip, Use the unique d27-- member whose basename ends corrected.jar or vulnerable.jar." + LIT_TAIL]
    got = [ask_zip(vc, t) for t in texts] + [ask_zip(ONE, f"Use the record whose domain is '{DOM[1]}' or '{DOM[0]}' and "
                                                          "submit the campaign property.")]
    check("P3b (item 3, a10) a disjunction or a list of literals names no record: None, the frame form too",
          all(v is None for v in got), got)
    # the established forms in the frame-like positive wordings: a reading, never plain (I2 holds the seven frames)
    got = [ask_zip(ONE, t) for t in ("Use the second HCFG record." + LIT_TAIL,
                                     "Use the HCFG record with version 2." + LIT_TAIL,
                                     "Use the record for campaign BR27-001." + LIT_TAIL)]
    check("P3c an established form beside the generator's own tail is its tagged pick, never plain",
          all(pick_eq(v, CAMP[1]) for v in got), got)
    v = ask_zip({f"d{D}--sample-loader.bin": member([R[0]]), f"d{D}--sample-plugin.bin": member([R[1]])},
                "In evidence.zip, Use the unique d27-- member whose basename ends loader.bin. The loader has no scored "
                "HCFG config." + LIT_TAIL)
    check("P3d a judged sentence with a negation ('The loader has no scored HCFG config.') is no neutral tail: the frame "
          "beside it is not plain", not_frame(v), v)
    two_order = {f"d{D}--sample-zulu.jar": member([R[0]]), f"d{D}--sample-alpha.jar": member([R[1]])}
    frame_n = ("Use the HCFG record of member 1, where members are the d27-- members in ZIP central-directory order "
               "(1-based)." + LIT_TAIL)
    v_cd = ask_zip(two_order, frame_n)
    v_nodelivery = ask(two_order, frame_n)
    check("P3e the member-number frame is plain in the delivery's central-directory order (zulu first) and not plain "
          "without a delivery (the names' alphabetical order would put alpha first)",
          frame_pick(v_cd, CAMP[0]) and not_frame(v_nodelivery), (v_cd, v_nodelivery))

    # P4 (item 4, a3): the patch-difference reader's text rules; one acceptance answers that id and wording only
    cls = [("d27_analysis_patch_unchanged_count", "How many config keys did the patch not change?"),
           ("d27_analysis_patch_key_count", "How many config keys does the patched build hold?"),
           ("d27_analysis_patch_changed_count", "How many config keys stayed the same after the patch changed it?"),
           ("d27_analysis_patch_offset", "Byte offset of the last byte of the HCFG payload the patch changes."),
           ("d27_analysis_patch_offset", "Byte offset of the HCFG payload byte the patch changes."),
           ("d27_analysis_patch_changed_field", "Which config field of the other build changed?"),
           ("d27_analysis_diff_size", "Size of the patched HCFG record."),
           ("d27_analysis_diff_offset", "Offset of the HCFG record in the patched build.")]
    import importlib.util
    spec = importlib.util.spec_from_file_location("kb3_patch_diff2", REPO / "solvers" / "binary" / "patch_diff.py")
    pdmod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pdmod)
    claimed = [(i, t) for i, t in cls if pdmod.classify(i, t) is not None]
    check("P4a (item 4) a text with a negation, no word of difference, another build, or an offset that is not the "
          "first difference claims no patch-difference id", not claimed, claimed)
    # two readings that render the same value on this variant are both dropped: the members first differ (a build
    # stamp in their head) exactly where the payloads first differ, so the payload and the member readings coincide
    ja = json.dumps(cfg(0), separators=(",", ":")).encode()
    jb = json.dumps(dict(cfg(0), domain="fixed.day27.example.invalid"), separators=(",", ":")).encode()
    d0 = next(i for i, (x, y) in enumerate(zip(ja, jb)) if x != y)
    head_a = bytearray(b"\x07" * 96)
    head_b = bytearray(head_a)
    head_b[d0] = 0x08
    co = {f"d{D}--sample-vulnerable.bin": bytes(head_a) + make_record(cfg(0), key=0x41),
          f"d{D}--sample-patched.bin": bytes(head_b) + make_record(dict(cfg(0), domain="fixed.day27.example.invalid"),
                                                                   key=0x41)}
    v = run(co, [q(f"d{D}_analysis_patch_offset", "Byte offset of the first byte of the HCFG payload the patch "
                                                  "changes.")])[f"d{D}_analysis_patch_offset"]
    names = [n for n, _ in labels.parse(v).options] if labels.is_unsure(v) else []
    check("P4b readings that coincide on this variant (the payload's and the member's first difference) are both left "
          "out of the candidates, the other reading kept", names and not any(n.startswith(("payload_first",
                                                                                          "member_first"))
                                                                             for n in names)
          and any(n.startswith("record_first") for n in names), (d0, names))

    # P5 (item 5, a4, and the two-step through a coincidence): a reading's pick is offered only when no other record
    # renders its value, so an acceptance always proves which record the wording asks
    same_camp = {f"d{D}--sample-alpha.bin": member([make_record(cfg(0), key=0x41)]),
                 f"d{D}--sample-beta.bin": member([make_record(dict(cfg(0), domain="beta.day27.example.invalid"),
                                                               key=0x42)])}
    differ = {f"d{D}--sample-alpha.bin": member([make_record(cfg(0), key=0x41)]),
              f"d{D}--sample-beta.bin": member([make_record(cfg(1), key=0x42)])}
    w = "Use the record that trails member 1's record and submit the campaign property."     # 'trails': no guard word
    va, vb = ask_zip(same_camp, w), ask_zip(differ, w)
    check("P5a a relation the guard does not know, over two records that share the campaign: no pick at all (its "
          "acceptance there would turn the next variant's named record plain)", va is None, va)
    check("P5b ...and over records that differ, the named record's pick, never plain (the judge rejects it)",
          pick_eq(vb, "BR27-000"), vb)
    got = [ask_zip(same_camp, t) for t in ("Use member 1 and submit the campaign property.",
                                           "Report the campaign property of the alpha build.",
                                           "Use the first HCFG record and submit the campaign property.")]
    check("P5c a selector whose record shares the asked value with another record offers nothing, the established "
          "ordinal too", all(v is None for v in got), got)
    ts = {f"d{D}--sample.bin": member([make_record(cfg(0, built="2026-10-01T00:00:00Z"), key=0x41),
                                       make_record(cfg(1, built="2026-10-20T12:00:00Z"), key=0x42),
                                       make_record(cfg(2, built="2026-09-15T08:30:00Z"), key=0x43)])}
    got = [ask_zip(ts, t) for t in ("Use the second newest record and submit the campaign property.",
                                    "Use the second most recent record and submit the campaign property.",
                                    "Use the next-to-newest record and submit the campaign property.")]
    check("P5d (a4) an ordinal before the extreme word names no record", all(v is None for v in got), got)

    # P6 (item 6, a12): the boilerplate builds no pool, and a word every member's name carries names no build
    nm = [f"d{D}--sample-alpha.bin", f"d{D}--sample-beta.bin"]
    check("P6 'the sample binary' beside sample-* members is no selector; 'the beta build' is",
          not rs.states_selector("Decode the sample binary's HCFG record and submit the domain property.", nm)
          and not rs.states_selector("Parse this sample member and submit the url.", nm)
          and rs.states_selector("Report the campaign property of the beta build.", nm), "")

    # P7: an unresolved established form's candidates are scoped to the pool: a position the judge accepts answers
    # that delivery only, never another variant plain
    pool_a = {f"d{D}--sample.bin": member([R[0], R[1]])}
    pool_b = {f"d{D}--sample.bin": member([R[1], R[0]])}
    w = "Use the record other than the first HCFG record and submit the campaign property."
    va = ask_zip(pool_a, w)
    pa = labels.parse(va) if labels.is_unsure(va) else None
    check("P7a an unresolved established form is a candidates pick whose names carry the pool's scope",
          pa is not None and labels.is_candidate(va) and all("@" in n for n, _ in pa.options), va)
    if pa is not None:
        accept_key(pa.key, pa.options[1][0])                       # the judge took the second value of pool A
        vb = ask_zip(pool_b, w)
        check("P7b ...and after the judge accepts a position on one pool, another pool's variant is not plain",
              not_frame(vb), vb)

    # P8: the adversarial pass, more wordings over the copy layout and the established forms: none is a wrong plain
    adv = [(cp, "Use the record the corrected build kept from the vulnerable build and submit the campaign property."),
           (cp, "Use the corrected build's own record, not the one it copied, and submit the campaign property."),
           (vc, "Use the build that is not the corrected build and submit the campaign property."),
           (vc, "Report the campaign property of the build opposite to member 2."),
           (vc, "Member 2 is the decoy. Report the campaign property of the real build."),
           (ONE, "Use the last-but-one HCFG record and submit the campaign property."),
           (ONE, "Use the HCFG record two places before the last one and submit the campaign property."),
           (ONE, "Use whichever HCFG record does not carry version 2 and submit the campaign property."),
           (ONE, "Use the record for campaign BR27-001's predecessor and submit the campaign property."),
           (vc, "Report the campaign property of the other build than the corrected build.")]
    wrong = [(t[:60], v) for files_, t in adv for v in [ask_zip(files_, t)] if kind_of(v) == "plain"]
    check(f"P8 {len(adv)} more adversarial wordings (a kept copy, an exclusion, 'the other build', a decoy sentence, "
          "positions from the end, a negated version, a campaign's predecessor): none is plain", not wrong, wrong)
    fix2b(vc, lead)


def fix2b(vc, lead):
    """P9 to P14: the second independent review of fix round 2 (88cfad1) forced wrong plains through the generator's
    frames and through one acceptance of a wording on a benign variant. Each repro, closed by restriction."""
    import base64
    import zipfile
    D = DAY
    fm = ("Use the HCFG record of member {n}, where members are the d27-- members in ZIP central-directory order "
          "(1-based).")
    ab = {f"d{D}--a.bin": member([R[0]]), f"d{D}--b.bin": member([R[1]])}

    def ask_cd(files, text, entries, field="campaign"):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                for n, b in entries:
                    z.writestr(n, b)
        with redirect_stderr(io.StringIO()):
            return answers_closed(f"d{D}", [q(cid(field), text)], dict(files), {"delivery": buf.getvalue()})[cid(field)]

    # P9: the member counts and the frames read only `dNN--` members, in the delivery's exact central directory
    got = []
    for side in (f"d{D}_notes.bin", f"d{D}.readme.txt", f"d{D}-manifest.json"):
        files = {side: b"side file, no record\n", **ab}
        got += [ask_zip(files, fm.format(n=2) + LIT_TAIL), ask_zip(files, "Report the campaign of the second member.")]
    check("P9a a side file the prefix's name rule takes (d27_notes.bin, d27.readme.txt, d27-manifest.json) beside the "
          "d27-- members: the member frame and the member reading count nothing (PLAIN BR27-000 on 88cfad1)",
          all(v is None for v in got), got)
    three = {f"d{D}--a.bin": member([R[0]]), f"d{D}--b.bin": member([R[1]]), f"d{D}--c.bin": member([R[2]])}
    miss = {k: v for k, v in three.items() if not k.endswith("b.bin")}
    v1 = ask_cd(miss, fm.format(n=2) + LIT_TAIL, list(three.items()))
    v2 = ask_cd({f"d{D}--a.bin": member([R[2]]), f"d{D}--b.bin": member([R[1]])}, fm.format(n=1) + LIT_TAIL,
                [(f"d{D}--a.bin", member([R[0]])), (f"d{D}--b.bin", member([R[1]])), (f"d{D}--a.bin", member([R[2]]))])
    check("P9b a central-directory entry the files lack, or one listed twice, shifts the numbers: the member frame is "
          "not plain (PLAIN BR27-002 on 88cfad1)", not_frame(v1) and not_frame(v2), (v1, v2))

    # P10: the frame's day, and the Game Master's own trailers only
    d26 = {f"d26--corrected.jar": member([make_record(cfg(5, day=26), key=0x45)]),
           f"d{D}--vulnerable.jar": member([R[0]]), f"d{D}--corrected.jar": member([R[1]])}
    got = [ask_zip(d26, "In evidence.zip, Use the unique d26-- member whose basename ends corrected.jar." + LIT_TAIL),
           ask_zip(d26, fm.format(n=1).replace("d27--", "d26--") + LIT_TAIL)]
    check("P10a a frame that names another day's members under a d27 id is not plain (PLAIN BR27-001 and BR27-000 on "
          "88cfad1; the right answer is the d26 record's)", all(not_frame(v) for v in got), got)
    v_bad = ask_zip(vc, lead + " Evidence case: use-the-vulnerable.jar-record." + LIT_TAIL)
    v_ok = ask_zip(vc, lead + LIT_TAIL + " Evidence case: d27-tt-0a1b2c3d4e5f.")
    check("P10b an `Evidence case:` token in any form but the Game Master's is no trailer: not plain (PLAIN BR27-001 on "
          "88cfad1); the Game Master's own trailer keeps the frame plain", not_frame(v_bad)
          and frame_pick(v_ok, CAMP[1]), (v_bad, v_ok))

    # P11: the known sentences of the id's own kind and property word only
    got = [ask_zip(vc, lead + LIT_TAIL.replace("campaign property", "domain property")),
           ask_zip(vc, lead + LIT_TAIL.replace("campaign property", "campaign property"), "mutex"),
           ask_zip(vc, lead + " Submit unsigned HCFG byte 4 as a base-10 integer."),
           ask_zip(vc, lead + " Render header byte 5 as 0x plus exactly two lowercase hexadecimal digits.")]
    check("P11 a frame whose tail asks another property (or the header version, or the XOR key) than the id's is not "
          "plain (PLAIN on 88cfad1)", all(not_frame(v) for v in got), got)

    # P12: the named member is a jar whose record the walk read RAW (a stored decoy beside a deflated classfile)
    def classfile(record):
        b64 = base64.b64encode(record)
        cp = [b"\x01" + struct.pack(">H", 4) + b"Main", b"\x01" + struct.pack(">H", len(b64)) + b64]
        return b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, 52, len(cp) + 1) + b"".join(cp) + b"\x00\x21" + b"\x00" * 16

    def jar(entries):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            for n, b, comp in entries:
                z.writestr(zipfile.ZipInfo(n), b, compress_type=comp)
        return buf.getvalue()

    defl, stored = zipfile.ZIP_DEFLATED, zipfile.ZIP_STORED
    vjar = jar([("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n", defl), ("a/Main.class", classfile(R[0]), defl)])
    cjar = jar([("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n", defl), ("a/Main.class", classfile(R[1]), defl),
                ("res/legacy.cfg", b"\x00" + R[2] + b"\x00", stored)])
    jars = {f"d{D}--vulnerable.jar": vjar, f"d{D}--corrected.jar": cjar}
    got = [ask_zip(jars, lead + REAL_TAIL), ask_zip(jars, fm.format(n=2) + REAL_TAIL)]
    clean = {f"d{D}--vulnerable.jar": vjar,
             f"d{D}--corrected.jar": jar([("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n", defl),
                                          ("a/Main.class", classfile(R[1]), defl)])}
    v_clean = ask_zip(clean, lead + REAL_TAIL)
    check("P12 a jar the walk read only raw (a stored decoy beside the deflated classfile the tail names) is not plain "
          "(PLAIN BR27-002 on 88cfad1); the same jar without the decoy is read through its entries and stays plain",
          all(not_frame(v) for v in got) and frame_pick(v_clean, CAMP[1]), (got, v_clean))

    # P13: a reading's acceptance is a fact of its delivery: the same wording on another variant is a pick again; a role
    # marker is a WHOLE value, never a token of one
    w = "Report the campaign of the corrected build."
    va = ask_zip({f"d{D}--sample-vulnerable.bin": member([R[0]]), f"d{D}--sample-corrected.bin": member([R[1]])}, w)
    pa = labels.parse(va) if labels.is_unsure(va) else None
    check("P13a a role reading's name carries the pool's scope", pa is not None and "@" in pa.options[0][0], va)
    if pa is not None:
        accept_key(pa.key, pa.options[0][0])
    marked = {f"d{D}--build-1.bin": member([make_record(cfg(0, status="not-corrected"), key=0x41)]),
              f"d{D}--build-2.bin": member([R[1]])}
    vb = ask_zip(marked, w)
    check("P13b ...so after that acceptance a variant whose vulnerable record says status 'not-corrected' is not plain "
          "(PLAIN BR27-000 on 88cfad1), and 'not-corrected' marks no corrected build", not_frame(vb)
          and not (labels.is_unsure(vb) and opts(vb) == [CAMP[0]] and "/recsel_role+" in labels.parse(vb).key), vb)
    comp = {f"d{D}--build-1.bin": member([R[0]]),
            f"d{D}--build-2.bin": member([make_record(cfg(1, track="replaces-original"), key=0x42)])}
    vc2 = ask_zip(comp, "Report the campaign of the record that differs from the original build.")
    check("P13c 'replaces-original' marks no original build: the complement reading names nothing",
          vc2 is None, vc2)

    # P14: the patch-difference facts are scoped to the pair too: one acceptance never answers another variant plain
    p1 = {f"d{D}--sample-vulnerable.bin": member([make_record(cfg(0, mutex="m"), key=0x41)]),
          f"d{D}--sample-corrected.bin": member([make_record(cfg(0, mutex=""), key=0x41)])}
    p2 = {f"d{D}--sample-vulnerable.bin": member([make_record(cfg(0, mutex="m"), key=0x41)]),
          f"d{D}--sample-corrected.bin": member([make_record(cfg(0, mutex="n"), key=0x41)])}
    qid = f"d{D}_analysis_patch_changed_count"
    t = "How many config fields did the patch change to an empty string?"
    v1 = run(p1, [q(qid, t)])[qid]
    k1 = labels.parse(v1) if labels.is_unsure(v1) else None
    if k1 is not None:
        accept_key(k1.key, k1.options[0][0])
    v2 = run(p2, [q(qid, t)])[qid]
    check("P14 a patch-difference fact accepted on one pair (the count coincided) is not plain on the next pair "
          "(PLAIN '1' on 88cfad1, where the right answer is 0)", k1 is not None and "@" in k1.options[0][0]
          and not_frame(v2), (v1, v2))

    # P15: the restrictions keep the generator's own wording plain: a judged support sentence that names a
    # `.runtimeconfig.json` (no config member) stays a known one, and a zip behind a stub counts as an archive
    vcb = {f"d{D}--sample-vulnerable.jar": b64member([R[0]]), f"d{D}--sample-corrected.jar": b64member([R[1]])}
    v = ask_zip(vcb, lead + REAL_TAIL.replace("constant pool; ", "constant pool; .runtimeconfig.json and dependency "
                                                                 "DLL members are delivery support only. "))
    stub = b"#!/bin/sh\nexit 0\n" + jar([("a.txt", b"x", stored)])
    check("P15 the frame beside the judged `.runtimeconfig.json ... delivery support only.` sentence is still plain, "
          "and a zip behind a stub is an archive", frame_pick(v, CAMP[1]) and rs._is_archive(stub)
          and not rs._is_archive(member([R[0]])), v)
    fix2c(vc, lead)


def fix2c(vc, lead):
    """P16 to P18: the third independent review of fix round 2 (da80071) forced wrong plains through the frame by a
    walk that never saw the record the text's procedure reads, and by config members named like header facts."""
    import base64
    D = DAY
    core = " Locate the unique" + LIT_TAIL.split(" Locate the unique", 1)[1]           # LOCATE + XOR + SUBMIT
    b64_proc = (" For each UTF-8 constant of at least 80 Base64-alphabet characters, Base64-decode it and accept the "
                "first CRC32-valid HCFG JSON record.")
    lit_proc = (" Scan the go executable final bytes for literal HCFG magic and accept only a record whose bounds, "
                "CRC32, and decoded JSON validate.")
    fa = "In evidence.zip, Use the unique d27-- member whose basename ends alpha.bin."
    A, B, C = R[0], R[1], R[2]

    # P16 (F1, F2): a raw decoy beside the record the base64 procedure reads, unseen by the walk
    f1 = {f"d{D}--sample-alpha.bin": b"\x00\x10junk\x00" + A + b"\x00\x00 " + base64.b64encode(b"\x01" + B) + b" \x00",
          f"d{D}--sample-beta.bin": member([C])}
    bombs = b"".join(b"\x00" + zlib.compress(b"\x00" * (8 << 20)) for _ in range(5))
    f2 = {f"d{D}--sample-alpha.bin": b"\x00\x10junk\x00" + A + b"\x00" + bombs + b"\x00 " + base64.b64encode(B)
                                     + b" \x00", f"d{D}--sample-beta.bin": member([C])}
    got = [ask_zip(f1, fa + b64_proc + core), ask_zip(f2, fa + b64_proc + core)]
    check("P16 a record read RAW beside a base64 record the walk did not decode (misaligned, or after a spent layer "
          "budget) is not plain under a base64 procedure (PLAIN BR27-000 on da80071, the base64 record BR27-001 right)",
          all(not_frame(v) for v in got), got)

    # P17: the procedure the text states must be the one the record was read by
    raw2 = {f"d{D}--sample-alpha.bin": member([A]), f"d{D}--sample-beta.bin": member([C])}
    b642 = {f"d{D}--sample-alpha.bin": b64member([A]), f"d{D}--sample-beta.bin": b64member([C])}
    cases = [(raw2, b64_proc, False), (raw2, lit_proc, True), (raw2, "", False),
             (b642, b64_proc, True), (b642, lit_proc, False), (b642, "", False)]
    got = [(proc[:24], ask_zip(files, fa + proc + core)) for files, proc, _ in cases]
    ok = all((frame_pick(v, CAMP[0]) if want else not_frame(v)) for (_, v), (_, _, want) in zip(got, cases))
    check("P17 raw record: plain only under a literal scan; base64 constant: only under a base64 procedure; no "
          "procedure stated: not plain", ok, got)

    # P18 (F3): config MEMBERS named like the header's facts take no header sentence as known
    named = {f"d{D}--sample-alpha.bin": member([make_record(cfg(0, crc32="0x12345678", xor_key_hex="0x99",
                                                                hcfg_version="7"), key=0x41)]),
             f"d{D}--sample-beta.bin": member([make_record(cfg(1, crc32="0x0badf00d", xor_key_hex="0x98",
                                                               hcfg_version="8"), key=0x42)])}
    pre = fa + " First test literal HCFG occurrences in the member; then test every non-overlapping Latin-1 run matching " \
               "[A-Za-z0-9+/]{100,}={0,2} by Base64-decoding it. Accept the first CRC32-valid HCFG JSON record in that order."
    got = [ask_zip(named, pre + " Read the little-endian uint32 at HCFG header bytes 8..11 and render it as 0x plus "
                                "exactly eight lowercase hexadecimal digits.", "crc32"),
           ask_zip(named, pre + " Render header byte 5 as 0x plus exactly two lowercase hexadecimal digits.", "xor_key_hex"),
           ask_zip(named, pre + " Submit unsigned HCFG byte 4 as a base-10 integer.", "hcfg_version")]
    check("P18 analysis_config_crc32 / _xor_key_hex / _hcfg_version (JSON members so named) beside the header's CRC, "
          "key and version sentences are not plain (PLAIN 0x12345678, 0x99, 7 on da80071)",
          all(not_frame(v) for v in got), got)

    # P19: the fourth review (de67fd3) passed every check of the frame with a record the stated procedure does not
    # accept: an ADD-encoded literal record (CRC-valid under another reading) beside the base64 record the procedure
    # reads; two members whose records differ only in the header version byte (the pool keeps one header); a jar entry
    # over the inflate limit; the procedures stated in the other order. Since then the frame is a reading: none of
    # these, and nothing of the module, answers plain.
    import json as _json
    import zipfile as _zip

    def add_record(obj, k):
        payload = _json.dumps(obj, separators=(",", ":")).encode()
        return (b"HCFG" + bytes([1, k]) + struct.pack("<HI", len(payload), zlib.crc32(payload))
                + bytes((b + k) & 0xFF for b in payload))

    r1 = {f"d{D}--sample-alpha.bin": b"\x00\x10junk\x00" + add_record(cfg(1), 0x41) + b"\x00\x00 "
                                     + base64.b64encode(b"\x01" + make_record(cfg(2), key=0x42)) + b" \x00",
          f"d{D}--sample-beta.bin": member([make_record(cfg(3), key=0x44)])}
    v_r1 = ask_zip(r1, pre + core)
    ver = {f"d{D}--sample-vulnerable.bin": member([make_record(cfg(1), version=1, key=0x41)]),
           f"d{D}--sample-corrected.bin": member([make_record(cfg(1), version=2, key=0x41)]),
           f"d{D}--sample-gamma.bin": member([make_record(cfg(3), version=3, key=0x44)])}
    v_ver = ask_zip(ver, "In evidence.zip, Use the unique d27-- member whose basename ends corrected.bin." + lit_proc
                    + " Submit unsigned HCFG byte 4 as a base-10 integer.", "hcfg_version")
    order = {f"d{D}--sample-alpha.bin": b"\x00\x10junk\x00" + make_record(cfg(1), version=1, key=0x41) + b"\x00 "
                                        + base64.b64encode(make_record(cfg(2), version=2, key=0x42)) + b" \x00",
             f"d{D}--sample-beta.bin": member([make_record(cfg(3), key=0x44)])}
    v_ord = ask_zip(order, fa + " Test every non-overlapping Latin-1 run matching [A-Za-z0-9+/]{100,}={0,2} by "
                               "Base64-decoding it, and accept the first decoded byte string that begins with a "
                               "CRC32-valid HCFG JSON record." + lit_proc + " Submit unsigned HCFG byte 4 as a base-10 "
                               "integer.", "hcfg_version")
    big = io.BytesIO()
    with _zip.ZipFile(big, "w", _zip.ZIP_DEFLATED) as z:
        b64 = base64.b64encode(make_record(cfg(2), key=0x42))
        z.writestr("a/First.class", b"\xca\xfe\xba\xbe" + b"\x01" + struct.pack(">H", len(b64)) + b64
                   + b"-" * (8 << 20) + b"\x00")
        b64w = base64.b64encode(make_record(cfg(1), key=0x41))
        z.writestr("a/Second.class", b"\xca\xfe\xba\xbe" + b"\x01" + struct.pack(">H", len(b64w)) + b64w + b"\x00")
    jar1 = {f"d{D}--sample-alpha.jar": big.getvalue(), f"d{D}--sample-beta.bin": member([make_record(cfg(3), key=0x44)])}
    v_jar = ask_zip(jar1, "In evidence.zip, Use the unique d27-- member whose basename ends alpha.jar." + REAL_TAIL)
    got = [v_r1, v_ver, v_ord, v_jar]
    check("P19 the fourth review's layouts (an other-reading literal beside the procedure's base64 record, a header "
          "version two members' records alone differ in, the procedures stated base64-first, a jar entry over the "
          "inflate limit) answer nothing plain (the first and the last PLAIN BR27-001 on de67fd3, where BR27-002 is right; "
          "the review's own scripts reproduce the other two)",
          all(kind_of(v) != "plain" for v in got), got)


if __name__ == "__main__":
    sys.exit(main())
