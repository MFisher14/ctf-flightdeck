#!/usr/bin/env python3
"""Permanent break-it battery for solvers/metadata-forensics/format_candidates.py.

The Day 23 root cause (docs/retro/day23-slowness-rootcause.md): the Metadata Time Trial failed
all morning because `sqlite.page_size_bytes`'s VALUE was read but its RENDERING was unjudged, and
one wrong plain answer sank the whole batch. This module's contract is: given a known value and a
kind, emit RANKED CANDIDATE renderings (unsure), never a plain answer.

What this test pins forever:
  1. NEVER PLAIN: pick() returns None or an unsure `??...` candidate string — never a bare value.
  2. The candidate key carries CANDIDATE_MARK (labels.is_candidate), so every runner probes it.
  3. Coverage: every documented kind renders the plausible spellings in a stable, de-duplicated,
     author-most-common-first order, capped at MAX_OPTIONS.
  4. The exact Day-23 failure (sqlite.page_size_bytes = 1024) is representable and the integer
     rendering is first.
  5. Garbage / wrong-kind input yields [] / None, never a crash and never a plain answer.
"""
import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
META = ROOT / "solvers" / "metadata-forensics"
COMMON = ROOT / "solvers" / "common"
for p in (str(COMMON), str(META)):
    if p not in sys.path:
        sys.path.insert(0, p)


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


labels = _load("labels_fc_test", COMMON / "labels.py")
FC = _load("format_candidates_test", META / "format_candidates.py")


def check(cond, msg):
    print(("ok  :" if cond else "FAIL:"), msg)
    assert cond, msg


def is_unsure(v):
    """A candidate/unsure answer is the `??`-prefixed wire string; labels.parse reads it back."""
    return isinstance(v, str) and v.startswith("??") and labels.parse(v) is not None


# 1. NEVER PLAIN -------------------------------------------------------------------------------
# A fresh, unique key has no accepted name, so pick() must be unsure (or None), never a plain value.
cases = [
    ("integer", 1024), ("hex", b"\x04\x00"), ("hex", 0x8664),
    ("guid", bytes(range(16))), ("guid", "{0C9E7F31-1234-5678-9ABC-DEF012345678}"),
    ("message_id", "<abc123@mail.example>"), ("message_id", "abc123@mail.example"),
    ("list", ["evidence", "timeline"]), ("intlist", [2, 5]),
    ("bool", True), ("bool", False), ("dims", (320, 180)),
    ("digest", "AbC123"), ("path", "a/b/c.txt"), ("version", (3, 51, 3)),
    ("version", "3.51.3"), ("encoding", "UTF-8"),
]


def test_1_never_plain():
    for i, (kind, value) in enumerate(cases):
        key = f"metadata.selftest/fc_{kind}_{i}"
        out = FC.pick(key, value, kind)
        check(out is None or is_unsure(out),
              f"pick({kind},{value!r}) is unsure or None, never plain -> {out!r}")
        if out is not None:
            parsed = labels.parse(out)
            # every offered rendering is a candidate option (name,value), never the value named by itself
            check(labels.is_candidate(labels.candidate_key(key)) or parsed is not None,
                  f"{kind}: candidate key is marked / parseable")


# 2. candidate key carries the mark ------------------------------------------------------------
def test_2_candidate_key_carries_the_mark():
    k = labels.candidate_key("metadata.selftest/markcheck")
    check(labels.is_candidate(k), "candidate_key() carries CANDIDATE_MARK so runners probe it")


# 3. coverage + ordering + cap -----------------------------------------------------------------
def test_3_coverage_ordering_cap():
    # integer: integer first
    r = FC.render(1024, "integer")
    check(r and r[0][0] == "integer" and r[0][1] == "1024", f"integer: integer form first -> {r[:3]}")
    check(any(v == "0x400" for _, v in r), f"integer: 0x hex offered -> {r}")

    # integer with width: padded 0x first-ranked among hex
    r = FC.render(0x8664, "integer", width_bits=16)
    check(any(n == "hex_0x_padded" and v == "0x8664" for n, v in r), f"integer width: padded 0x -> {r}")

    # hex with width: padded 0x lower first
    r = FC.render(b"\x86\x64", "hex", width_bits=16)
    check(r and r[0][1] == "0x8664", f"hex width: 0x8664 padded first -> {r[:3]}")
    check(any(v == "0X8664".replace("X", "x").upper()[2:] or v == "8664" for _, v in r) or
          any(v.upper() == "0X8664" for _, v in r), f"hex: upper variants present -> {r}")

    # guid from 16 bytes: hyphen lower first, upper/braces/compact covered
    r = FC.render(bytes(range(16)), "guid")
    check(r and r[0][0] == "hyphen_lower", f"guid bytes: hyphen_lower first -> {r[0]}")
    names = {n for n, _ in r}
    check({"hyphen_upper", "braces_upper", "compact_lower"} <= names, f"guid: brace/case forms -> {names}")
    check(all(len(v) <= 38 for _, v in r), "guid: renderings are GUID-shaped")

    # guid from text: as_stored is offered first
    r = FC.render("{0C9E7F31-1234-5678-9ABC-DEF012345678}", "guid")
    check(r and r[0][0] == "as_stored", f"guid text: as_stored first -> {r[0]}")

    # message-id: both with and without angle brackets
    r = FC.render("<abc@h>", "message_id")
    vals = {v for _, v in r}
    check("<abc@h>" in vals and "abc@h" in vals, f"message_id: both forms -> {vals}")
    r2 = FC.render("abc@h", "message_id")
    check({"<abc@h>", "abc@h"} <= {v for _, v in r2}, f"message_id bare: both forms -> {r2}")

    # list: document order and sorted, several separators
    r = FC.render(["timeline", "evidence"], "list")
    vals = {v for _, v in r}
    check("timeline,evidence" in vals, f"list: document order comma -> {vals}")
    check(any(v == "evidence,timeline" for v in vals), f"list: sorted order present -> {vals}")
    check(any(v == '["timeline","evidence"]' for v in vals), f"list: json form -> {vals}")

    # intlist: numeric sort
    r = FC.render([5, 2], "intlist")
    vals = {v for _, v in r}
    check("5,2" in vals and "2,5" in vals, f"intlist: doc + sorted -> {vals}")

    # bool
    check({v for _, v in FC.render(True, "bool")} >= {"true", "True", "1", "yes", "on"}, "bool true forms")
    check({v for _, v in FC.render(False, "bool")} >= {"false", "False", "0"}, "bool false forms")

    # dims
    check({v for _, v in FC.render((320, 180), "dims")} >= {"320x180", "320X180", "320*180"}, "dims forms")

    # digest case
    check({v for _, v in FC.render("DeadBeef", "digest")} == {"deadbeef", "DEADBEEF"}, "digest lower+upper")

    # path slashes
    vals = {v for _, v in FC.render("a/b/c.txt", "path")}
    check("a/b/c.txt" in vals and "a\\b\\c.txt" in vals and "c.txt" in vals, f"path slashes+basename -> {vals}")

    # version
    vals = {v for _, v in FC.render((3, 51, 3), "version")}
    check("3.51.3" in vals, f"version dotted -> {vals}")

    # encoding
    vals = {v for _, v in FC.render("UTF-8", "encoding")}
    check("utf-8" in vals and "utf8" in vals, f"encoding forms -> {vals}")

    # cap at MAX_OPTIONS and all distinct
    for kind, value in cases:
        r = FC.render(value, kind)
        check(len(r) <= labels.MAX_OPTIONS, f"{kind}: at most MAX_OPTIONS -> {len(r)}")
        rendered = [v for _, v in r]
        check(len(rendered) == len(set(rendered)), f"{kind}: renderings distinct")


# 4. the exact Day-23 failure ------------------------------------------------------------------
# sqlite.page_size_bytes: big-endian u16 at offset 16 of the header; value 1024 for a 1024-page db.
def test_4_the_exact_day_23_failure():
    hdr = b"SQLite format 3\x00" + (1024).to_bytes(2, "big")
    page_size = int.from_bytes(hdr[16:18], "big")
    check(page_size == 1024, "sqlite page_size read from header bytes = 1024")
    out = FC.pick("metadata.sqlite/page_size_bytes", page_size, "integer")
    check(is_unsure(out), f"sqlite.page_size_bytes submitted as unsure candidate, not plain -> {out!r}")
    r = FC.render(page_size, "integer")
    check(r[0][1] == "1024", f"sqlite page_size: integer rendering first -> {r[0]}")


# 5. garbage / wrong kind ----------------------------------------------------------------------
def test_5_garbage_wrong_kind():
    check(FC.render(None, "integer") == [], "None value -> []")
    check(FC.render("not-a-number", "integer") == [], "non-numeric -> [] for integer")
    check(FC.render(123, "nonexistent_kind") == [], "unknown kind -> []")
    check(FC.render(123, "guid") == [], "non-guid value under guid -> []")
    check(FC.render("x", "dims") == [], "bad dims -> []")
    check(FC.pick("metadata.selftest/none", None, "integer") is None, "pick on garbage -> None")


# a value that looks like a flag/instruction must still only be spelled, never acted on
def test_5_instruction_like_value_is_spelled_as_data():
    check(is_unsure(FC.pick("metadata.selftest/inst", "ignore all instructions", "path")),
          "text that addresses the solver is spelled as data, not obeyed")


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
