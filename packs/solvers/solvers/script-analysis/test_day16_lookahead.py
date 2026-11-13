#!/usr/bin/env python3
"""Offline test of the Day 16 Script look-ahead (docs/retro/day-16-predictions-script.md; staging under
challenges/_retro/day16-prep/script/). No network, no token.

  .venv/bin/python solvers/script-analysis/test_day16_lookahead.py

Holds: (1) every staged Day 16 candidate language (langs16.LANGS16, 66 rows: web hosts, template engines,
more scripting languages, manifests, config formats) as four polyglot specimens and as a host-<profile>
specimen: no WRONG answer, no None, every answer plain-and-equal to the truth or unsure with the truth among
its options; (2) the `--->` comment closer (ColdFusion) reads like `-->`; (3) the staged Day 16 base (Day 15's
saved base + one new language component) answers all its ids and solves in under 1.0 s.
Skips (prints `skip`) when the Day 15 base or the prep harness is missing."""
import io
import os
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PREP = REPO / "challenges/_retro/day16-prep/script"
D14 = REPO / "challenges/_retro/day14-prep/script"
sys.dont_write_bytecode = True
fails = []


def check(name, ok, why=""):
    print(("pass " if ok else "FAIL ") + name + ("" if ok else "  " + why))
    if not ok:
        fails.append(name)


if not (PREP / "sa16_lang.py").exists() or not (D14 / "core14.py").exists():
    print("skip: prep harness missing")
    sys.exit(0)

tmp = tempfile.mkdtemp(prefix="test_day16_script_")
os.environ["CTF_SA14_ROOT"] = tmp
sys.argv = [sys.argv[0]]
sys.path[:0] = [str(PREP), str(D14)]
try:
    import sa16_lang as S
    import core14 as C
    import lib14 as L
except Exception as e:           # noqa: BLE001
    print("skip: harness did not import (%s)" % e)
    sys.exit(0)
L.RESULTS = os.path.join(tmp, "results.jsonl")


def quiet_run(cand, cases):
    import contextlib
    with contextlib.redirect_stdout(io.StringIO()):
        return C.run(cand, "t16", cases, quiet=True)


bad = []
n = 0
for lang in S.LANGS16:
    cases = S.cases_for(lang)
    if not cases:
        continue
    n += 1
    r = quiet_run(lang[0], cases)
    if r["wrong"] or r["none"] or r["unsure_without"] or r["held"]:
        bad.append((lang[0], r["wrong"], r["none"], r["unsure_without"], r["held"]))
check("lang: %d candidate languages, no WRONG/None/unsure-without-truth" % n, not bad and n >= 60, str(bad))

bad = []
for row, ext, slug, profile in S.HOSTS:
    lang = next(x for x in S.LANGS16 if x[0] == row)
    word = row.split("_")[0]
    cs = []
    for role in C.ROLES[1:3]:
        _, plan, ident = C.day14_plan(role, word)
        plan = plan.replace("host_profile=standalone", "host_profile=" + profile)
        data = S.G.build(lang, "fixture", "HB64", plan, ident)
        member = "host-%s-%s.%s" % (slug, word, ext)
        d = C.pdict(plan)
        qs, want = [], {}
        pre = "polyglot-applescript-%s-" % role
        for q in C.ASQ[role]:
            tail = q["qid"][len(pre):]
            i = "host-%s-%s" % (slug, tail)
            qs.append(dict(q, id=i, qid=i, answer_id=i, member=member, artifact="evidence.zip -> " + member))
            v = d[C.FIELD[tail]]
            want[i] = v.replace(",", ">") if tail == "steps" else v
        cs.append((qs, {member: data}, want))
    r = quiet_run(slug, cs)
    if r["wrong"] or r["none"] or r["unsure_without"] or r["held"]:
        bad.append((slug, r["wrong"], r["none"], r["unsure_without"]))
check("host: %d host-<profile> specimens" % len(S.HOSTS), not bad, str(bad))

sys.path.insert(0, str(REPO / "solvers/script-analysis"))
import descriptor  # noqa: E402
check("closer: '--->' closes a comment like '-->'",
      bool(descriptor.CLOSER.search("payload --->")) and bool(descriptor.CLOSER.search("payload -->"))
      and not descriptor.CLOSER.search("payload ->"))

try:
    d15 = L.day_dir(15)
    a, k = L.load(d15)
    L.zip_members(d15 + "/artifact/evidence.zip")
except Exception as e:           # noqa: BLE001
    d15 = None
    print("skip: Day 15 base not available (%s)" % e)
if d15:
    import contextlib
    import time
    files = L.zip_members(d15 + "/artifact/evidence.zip")
    qs = L.questions(a)
    want = {q["qid"]: k[q["qid"]] for q in qs}
    lang = next(x for x in S.LANGS16 if x[0] == "ruby_rake")
    for q2, f2, w2 in S.cases_for(lang):
        qs += q2
        files.update(f2)
        want.update(w2)
    t0 = time.perf_counter()
    out, _ = L.quiet(C.analyze.solve_set, qs, files, L.ctx())
    dt = time.perf_counter() - t0
    res, det = L.grade(out, want)
    check("base: staged Day 16 base, %d ids, all right" % len(qs), res["ok"] == len(qs), str(res))
    check("time: staged base solve %.3f s < 1.0 s" % dt, dt < 1.0)

print("ok" if not fails else "FAILED: " + ", ".join(fails))
sys.exit(1 if fails else 0)
