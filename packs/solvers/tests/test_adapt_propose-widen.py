#!/usr/bin/env python3
"""The adaptability build, wave70: the widened PROPOSER value-finder (solvers/common/propose.py).

A genuinely-new id gets a strong evidence-ranked UNSURE answer whose FIRST probed option is correct, so it
closes in one probe on the regular/no-deadline attempt. These checks pin the widenings and prove they are
never-wrong (candidates only, scoped per delivery, never a plain value):

  INTEGER   a bare-width typed field (`u32` with no endian) read little-endian first, big second;
            the number of a stated magic's copies for a count/number-of id (`count:<TOK>`)
  PATTERN   a stated `/regex/` scope, and a prefix+exactly-N-characters form with no class word (defaults alnum)
  ENUM      ranked by evidence strength: a WHOLE-token hit beats a mere substring of a co-occurring longer
            value (the uniqueness-guarded read: `arm64` over `arm`), then occurrence count, then first place
  (and the established INTEGER/PATTERN/ENUM/kv shapes are unchanged: no regression)
"""
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "common"))
import propose  # noqa: E402

FAILS = []


def check(name, ok, detail=""):
    if not ok:
        FAILS.append(name)
    print(("ok   " if ok else "FAIL ") + name + ("" if ok or not detail else f"  [{str(detail)[:600]}]"), flush=True)


LANE = "binary-reverse-engineering"
INT = {"kind": "integer", "syntax": "base-10 integer; no units or separators"}


def first_value(opts):
    return opts[0][1] if opts else None


def values(opts):
    return [v for _, v in opts]


# ------------------------------------------------------------------ INTEGER: bare-width endian
mem = b"H" * 16 + b"RS40" + (4096).to_bytes(4, "little") + b"Z" * 10
q = {"id": "d30_analysis_resource_length",
     "question": "Locate RS40. Read the resource length u32 at +4 and submit it in base 10.", "answer_format": INT}
o = propose.propose(q, {"d30--s.bin": mem}, LANE, propose.stated_by([q], q))
check("INT bare u32: little-endian read is first candidate", first_value(o) == "4096", o)
check("INT bare u32: big-endian read is also offered (never-wrong: one of the two is right)",
      any(n.endswith("~be") for n, _ in o) and "1048576" in values(o), o)
# an explicit endian is still read exactly as stated, no be twin
memle = b"A" * 8 + b"CF99" + (1337).to_bytes(4, "little") + b"B" * 4
qle = {"id": "d30_analysis_record_size",
       "question": "Find CF99. Read record size u32le at +4. Submit in base 10.", "answer_format": INT}
ole = propose.propose(qle, {"d30--s.bin": memle}, LANE, propose.stated_by([qle], qle))
check("INT explicit u32le: value first, no ~be twin", first_value(ole) == "1337"
      and not any(n.endswith("~be") for n, _ in ole), ole)

# ------------------------------------------------------------------ INTEGER: magic-occurrence count
memc = b"....XY21....x....XY21....y....XY21...."
qc = {"id": "d30_analysis_record_count",
      "question": "Count how many XY21 records the file contains. Submit the count in base 10.", "answer_format": INT}
oc = propose.propose(qc, {"d30--s.bin": memc}, LANE, propose.stated_by([qc], qc))
check("INT count id: the magic's occurrence count is first (3)", first_value(oc) == "3"
      and oc[0][0] == "count:XY21", oc)
qn = {"id": "d30_analysis_entry_number", "question": "How many ENT7 entries are present? Submit the number.",
      "answer_format": INT}
memn = b"\x00ENT7\x00ENT7\x00ENT7"
on = propose.propose(qn, {"d30--s.bin": memn}, LANE, propose.stated_by([qn], qn))
check("INT number-of id: occurrence count first (3)", first_value(on) == "3", on)
# a NON-count integer id with the same magic does NOT rank count first (count is never a plain-size answer)
qsz = {"id": "d30_analysis_overlay_offset",
       "question": "Find the final XY21 overlay and submit its zero-based byte offset.", "answer_format": INT}
osz = propose.propose(qsz, {"d30--s.bin": memc}, LANE, propose.stated_by([qsz], qsz))
check("INT offset id: an offset leads, not the count", osz[0][0].startswith("offset_"), osz)

# ------------------------------------------------------------------ PATTERN: stated /regex/ scope
rq = {"id": "d30_analysis_token",
      "question": r"Submit the token matching /HTB\{[a-f0-9]{8}\}/ found in the member.",
      "answer_format": {"kind": "pattern", "syntax": r"a token matching /HTB\{[a-f0-9]{8}\}/"}}
ro = propose.propose(rq, {"d30--s.bin": b"noise HTB{deadbeef} noise"}, LANE)
check("PAT /regex/: the one match is first, scoped to the member (only_in)", first_value(ro) == "HTB{deadbeef}"
      and ro[0][0].startswith("only_in:"), ro)
check("PAT /regex/: no match, no option", propose.propose(rq, {"d30--s.bin": b"nothing here"}, LANE) == [])

# prefix + exactly-N-characters with NO class word -> defaults alnum
kq = {"id": "d30_analysis_key", "question": "Submit the key.",
      "answer_format": {"kind": "pattern", "syntax": "KEY- followed by exactly 8 characters; no spaces"}}
ko = propose.propose(kq, {"d30--s.bin": b"....KEY-AB12cd34...."}, LANE)
check("PAT prefix no-class: the 8-char code is found", first_value(ko) == "KEY-AB12cd34", ko)

# ------------------------------------------------------------------ ENUM: evidence-strength ranking
# the correct value is a WHOLE token; a shorter accepted value is only a substring of the longer one present
ea = {"id": "d30_analysis_machine", "question": "Which CPU architecture?",
      "answer_format": {"kind": "enum", "accepted_values": ["arm", "arm64", "x86"]}}
eo = propose.propose(ea, {"d30--s.bin": b"\x00target cpu is arm64 build\x00"}, LANE)
check("ENUM whole-word: arm64 (a whole token) outranks arm (its substring)", first_value(eo) == "arm64", eo)
check("ENUM whole-word: the rank name is a hypothesis scoped to the delivery, never the value",
      eo[0][0].startswith("listed_rank@") and "arm64" not in eo[0][0] and eo[0][0].endswith("#1"), eo)
# more occurrences win when both are whole tokens
ec = {"id": "d30_analysis_format", "question": "Which format?",
      "answer_format": {"kind": "enum", "accepted_values": ["pe", "elf", "macho"]}}
eco = propose.propose(ec, {"d30--s.bin": b"pe here\nelf\nsection elf\nelf again"}, LANE)
check("ENUM count: the more-frequent whole token (elf x3) is first", first_value(eco) == "elf", eco)
# exactly one present -> only_listed (carries to the next variant), unchanged
e1 = {"id": "d30_analysis_lang", "question": "Which language?",
      "answer_format": {"kind": "enum", "accepted_values": ["go", "rust", "nim"]}}
e1o = propose.propose(e1, {"d30--s.bin": b"compiled with rust 1.70"}, LANE)
check("ENUM one present: only_listed, its own value", e1o == [("only_listed", "rust")], e1o)
# two DISJOINT values -> first place, unchanged (no whole-word differentiation)
ed = {"id": "d30_analysis_storage", "question": "Which storage?",
      "answer_format": {"kind": "enum", "accepted_values": ["raw", "base64", "zlib"]}}
edo = propose.propose(ed, {"d30--a.bin": b"....zlib....raw...."}, LANE)
check("ENUM disjoint: ranked by first place (zlib then raw), unchanged", values(edo) == ["zlib", "raw"]
      and edo[0][0].endswith("#1"), edo)

# ------------------------------------------------------------------ never-wrong: nothing is ever plain
import labels  # noqa: E402
key = propose.key_for(LANE, ea)
cand = propose.candidates_for(ea, {"d30--s.bin": b"\x00arm64\x00"}, key, LANE)
check("NEVER-WRONG: candidates_for returns an unsure ?? candidate pick, never a plain value",
      isinstance(cand, str) and cand.startswith("??") and "#candidates" in cand, cand)
check("NEVER-WRONG: the proposer strips every value out of the names it offers",
      all(not re.fullmatch(r"-?\d+", n) for n, _ in oc + o + eo), "a name must never be the value")
# a bare delivery archive is never read as the member asked (per-delivery scope, no cross-variant leak)
noev = propose.propose({"id": "d30_analysis_x", "question": "What is x?", "answer_format": INT},
                       {"evidence.zip": b"PK\x03\x04nothing stated"}, LANE)
check("NEVER-WRONG: no stated evidence, no proposal", noev == [], noev)

# ------------------------------------------------------------------ measured first-candidate-correct rate
SPECS = [o, ole, oc, on, osz, ro, ko, eo, eco, e1o, edo]
TRUTHS = ["4096", "1337", "3", "3", None, "HTB{deadbeef}", "KEY-AB12cd34", "arm64", "elf", "rust", "zlib"]
hit1 = sum(1 for opts, t in zip(SPECS, TRUTHS) if t is not None and first_value(opts) == t)
n = sum(1 for t in TRUTHS if t is not None)
check(f"MEASURE: first-candidate-correct on the widened specimens ({hit1}/{n})", hit1 == n, (hit1, n))



def test_all_checks_pass():
    """pytest entry: the module-level checks above ran at import; none may fail."""
    assert not FAILS, "failed checks: " + ", ".join(FAILS)


if __name__ == "__main__":
    print(f"\n{'PASS' if not FAILS else 'FAIL'} test_adapt_propose-widen: {len(FAILS)} failed"
          + ("" if not FAILS else " " + ", ".join(FAILS)))
    sys.exit(1 if FAILS else 0)
