#!/usr/bin/env python3
"""Offline test of the Script Analysis safety net: plan_codec.py, generic.py, shapes_text.py, analyze.py.

Usage:
  PYTHONDONTWRITEBYTECODE=1 .venv/bin/python solvers/script-analysis/test_generic.py [-v]

No Game Master request and no token. It reads the saved Script Analysis attempts of Days 1 to
5 through gm.CHALLENGES and writes only under tempfile.mkdtemp() (hook files, a synthetic
base attempt, the wire-state folder). The runtime label ledger is pointed at an empty
scratch folder, so the result depends on the tracked seed alone.

What it proves (the numbers are those of docs/day5/plan.md, package B8):

  plans       every plan recovered from the text equals the modules' plan (372 before the harvest of 2026-10-06)
  unknown     each language with its module hidden, against the four Day 4 keys: 0 wrong, and
              at least 240/288 VBScript, 204/288 Batch, 168/288 JScript
  hide        CTF_HIDE=vbscript: 60 plain, 3 unsure script.attack (T1059.005 first), 9 None per set
  failures    vbscript.parse raising, batch.Cmd.run raising on one specimen, and each module's
              analyze raising: 0 answers lost, 0 changed
  text path   equals the modules on 2,592 of 2,592 answers; no 'paths disagree' line
  regression  924 of 924 against the four keys, and every other saved variant unchanged
  hooks       hooks_<ext>.py (a crib, a label pattern), shapes_<ext>.py, lang_<ext>.py, census.py
  the rest    a new language end to end, wrapped scripts, covers(), ctx['partial'], ONLY, speed

And, from the Day 5 retro (challenges/_retro/day5-retro/layer1-script.txt), the general path on a
component nobody has seen:

  fields      the field of an answer id read from its end; ids of four to six parts, a v=2 plan
  material    plans of the versions 1 to 9; adjacent literals, escapes, url-safe base64, a number
              list ending in a comma; a plan read from a piece comes without its last field
  cut forms   what the review of that guard found: a second number list, a wrapped block, a join
              cut by a comment, chunks encoded on their own or out of order: never a cut plan whole
  unseen      the saved Day 5 base, Time Trial and Mastery without shapes_py.py, hooks_py.py and
              the .py names: per set 112 plain answers equal to the key and 0 wrong; 2 unsure and
              12 missing with OFFER_UNSEEN_ROLES off, 14 unsure (the judged name first) and none
              missing with it on
  stress      a sample of the retro's re-encoding run and of the review's forms (6,552 cases): 0
              plain wrong answers

And, from the review of the merged tree (docs/day5/review-findings.json, findings 9, 10, 11):

  live shapes  shapes_<ext>.py is asked about a specimen of a KNOWN language too, for the ids
               that have no plain answer, and for nothing else
  declined     an answer the Batch module declines (two wrappers at once, an unjudged join, a
               value holding this machine's %VAR%, trailing blanks) is never filled with the
               text path's own plain reading: a shape name goes out unsure, a plan value stays None
  unread key   the default branch is keyed by the construct that was not read, so a name the
               judge accepts for `if exist` answers `if exist` again and no other form

A key.json (grade A) is judge evidence. A golden.json (grade G) is the solver's own output at
commit a51fec1, so against it the test proves "unchanged", not "right". The Day 4 base has
only a snapshot: its attempt was CORRECT, but the submitted answers were not kept apart.

And rows 49 and 51 (2026-10-07): label_plan's other spellings of `Material_`/`Codec_`, and a
.ps1/.js/.bat/.vbs specimen of a new component answered by the general path, never by a guess.

Last line: `TEST_GENERIC passed=<n> failed=<n>`. Exit 0 when nothing failed, 1 otherwise, 2
when the saved attempts are not there.
"""
import base64
import contextlib
import io
import json
import os
import re
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SCRATCH = Path(tempfile.mkdtemp(prefix="test_generic_"))
os.environ["CTF_STATE_DIR"] = str(SCRATCH / "state")     # tools/judge.py state, if gm touches it
for _name in ("ONLY", "CTF_HIDE", "CTF_LEDGER_MASK", "CTF_PLATFORM_URL", "BATCH_RULE", "BATCH_FIELDS",
              "BATCH_IF_DEFINED", "BATCH_ERRORLEVEL"):
    os.environ.pop(_name, None)
os.environ["CTF_TESTING"] = "1"
for _p in (HERE.parent.parent / "tools", HERE.parent / "common", HERE):
    sys.path.insert(0, str(_p))

import gm    # noqa: E402 - resolves the real challenges folder, also from a worktree
import run   # noqa: E402 - load_offline and split_sets: the runner's own reading of an attempt

# From here on the label ledger lives in an empty scratch folder; gm.CHALLENGES keeps the real one.
os.environ["CTF_WORKDIR"] = str(SCRATCH / "challenges")

import analyze      # noqa: E402
import generic      # noqa: E402
import labels       # noqa: E402
import plan_codec   # noqa: E402
import shapes_text  # noqa: E402

VERBOSE = "-v" in sys.argv[1:]
CORPUS_DAYS = ("day-02", "day-03", "day-04")     # the 16 variants of the plan; Day 1 is PowerShell only
LANGS = ("jscript", "batch", "vbscript")
results = []


def check(name: str, ok: bool, detail: str = ""):
    results.append((name, bool(ok)))
    print(f"{'ok  ' if ok else 'FAIL'} {name}" + (f": {detail}" if detail and (VERBOSE or not ok) else ""))


@contextlib.contextmanager
def env(**values):
    """Set (or, with None, remove) environment variables for the block."""
    old = {k: os.environ.get(k) for k in values}
    try:
        for k, v in values.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        yield
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def solve(v, questions=None, ctx=None):
    """(answers, stderr text) of analyze.solve_set on one variant."""
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        out = analyze.solve_set(v["qs"] if questions is None else questions, v["files"],
                                {"set": v["set"]} if ctx is None else ctx)
    return out, err.getvalue()


# ---------------------------------------------------------------- the saved corpus

def load_variants(days):
    """One entry per set of every saved Script Analysis attempt of `days`, history included."""
    out = []
    for day in days:
        for base in sorted((gm.CHALLENGES / day).glob("script-analysis-*")):
            dirs = [base, base / "time_trial"] + sorted((base / "time_trial" / "history").glob("*")) + [base / "mastery"]
            for d in dirs:
                if not (d / "attempt.json").exists():
                    continue
                try:
                    with contextlib.redirect_stdout(io.StringIO()):
                        attempt, blobs, _ = run.load_offline("", str(d))
                except SystemExit as e:
                    print(f"NOTE {d}: not readable offline ({e.code}); skipped")
                    continue
                frozen = next((json.loads((d / n).read_text()) for n in ("key.json", "golden.json") if (d / n).exists()), None)
                if frozen is None:
                    print(f"NOTE {d}: no key.json or golden.json (run tools/freeze_keys.py); skipped")
                    continue
                for n, qs, files, ctx in run.split_sets(attempt, blobs):
                    out.append({"name": f"{d.relative_to(gm.CHALLENGES)}#{n}", "dir": d, "set": n, "qs": qs, "files": files,
                                "grade": frozen.get("grade"), "day": day,
                                "key": {q["qid"]: frozen["answers"].get(q["answer_id"]) for q in qs}})
    return out


def specimens(v):
    """(member, questions) of a variant, in question order."""
    by = {}
    for q in v["qs"]:
        by.setdefault(q["member"], []).append(q)
    return by.items()


def lang_of(member: str):
    return analyze.LANGUAGE.get(Path(member).suffix.lower())


# ---------------------------------------------------------------- tests on the corpus

def test_plans(corpus):
    """The text-only plan of every specimen equals the plan its module reconstructs."""
    import batch
    import jscript
    import powershell
    import vbscript
    same, total, bad = 0, 0, []
    for v in corpus:
        for member, _ in specimens(v):
            data, lang = v["files"][member], lang_of(member)
            text = plan_codec.text_of(data)
            got = plan_codec.recover(text)
            total += 1
            try:
                if lang == "jscript":
                    ok = got is not None and got[0] == jscript.analyze(data.decode("utf-8", "replace"))["text"]
                elif lang == "vbscript":
                    ok = got is not None and got[0] == vbscript.analyze(vbscript.text_of(data))["text"]
                elif lang == "batch":
                    ok = got is not None and got[0] == batch.analyze(data.decode("utf-8", "replace"))["plan_text"]
                else:
                    ok = got is not None and json.loads(got[0]) == powershell.Specimen(member, data).descriptor
            except Exception as e:  # noqa: BLE001
                ok = False
                bad.append(f"{v['name']} {member}: module raised {type(e).__name__}")
            same += ok
            if not ok:
                bad.append(f"{v['name']} {member}")
    check(f"plans: {same} of {total} text-only plans equal the modules' plans", same == total and total >= 372,
          "; ".join(bad[:5]) or f"{total} specimens (at least 372 expected)")


def test_regression(everything, corpus, keyed):
    """Healthy modules: every saved variant answers exactly as frozen, with nothing on stderr."""
    right, total, noisy, bad = 0, 0, [], []
    for v in everything:
        out, err = solve(v)
        for q in v["qs"]:
            total += 1
            if out.get(q["qid"]) == v["key"][q["qid"]]:
                right += 1
            else:
                bad.append(f"{v['name']} {q['qid']}: {out.get(q['qid'])!r} != {v['key'][q['qid']]!r}")
        if err.strip():
            noisy.append(f"{v['name']}: {err.strip().splitlines()[0]}")
    check(f"regression: {right} of {total} answers equal the frozen key or snapshot ({len(everything)} sets, Days 1 to 4)",
          right == total, "; ".join(bad[:5]))
    k_right = 0
    for v in keyed:         # one solve per set: the comprehension that stood here solved the set once per question
        out, _ = solve(v)
        k_right += sum(out.get(q["qid"]) == v["key"][q["qid"]] for q in v["qs"])
    k_total = sum(len(v["qs"]) for v in keyed)
    check(f"regression: {k_right} of {k_total} against the four Day 4 keys "
          f"(grades {', '.join(str(v['grade']) for v in keyed)})", k_right == k_total == 924)
    disagree = [n for n in noisy if "paths disagree" in n]
    check("regression: no 'paths disagree' line on the 16 variants", not disagree, "; ".join(disagree[:3]))
    check("regression: healthy modules print nothing on stderr", not noisy, "; ".join(noisy[:3]))


def test_text_path(corpus):
    """The interpreter-free reading gives the modules' answers, question by question."""
    same, total, bad = 0, 0, []
    for v in corpus:
        out, _ = solve(v)
        for member, qs in specimens(v):
            lang = lang_of(member)
            if lang not in LANGS:
                continue
            text = analyze.text_answers(lang, qs, plan_codec.text_of(v["files"][member]), Path(member).suffix.lower())
            for q in qs:
                total += 1
                if text.get(q["qid"]) == out.get(q["qid"]):
                    same += 1
                else:
                    bad.append(f"{v['name']} {q['qid']}: module={out.get(q['qid'])!r} text={text.get(q['qid'])!r}")
    check(f"text path: equals the modules on {same} of {total} answers", same == total and total >= 2592, "; ".join(bad[:5]))


def tally(v, lang, out):
    """Counter of plain-right, plain-wrong, unsure and missing answers of one language."""
    c = Counter()
    for q in v["qs"]:
        if lang_of(q["member"]) != lang:
            continue
        a = out.get(q["qid"])
        if a is None:
            c["none"] += 1
        elif labels.is_unsure(a):
            c["unsure"] += 1
        elif a == v["key"][q["qid"]]:
            c["right"] += 1
        else:
            c["wrong"] += 1
            c[f"wrong:{q['qid']}={a!r}"] += 1
    return c


def test_unknown(keyed):
    """Each language as if it had no module, on the four judged Day 4 sets."""
    floor = {"vbscript": 240, "batch": 204, "jscript": 168}
    for lang in LANGS:
        for mask, label in (("script.attack/*", "seed masked"), (None, "seed as shipped")):
            c = Counter()
            with env(CTF_HIDE=f"{lang},census", CTF_LEDGER_MASK=mask):
                for v in keyed:
                    c += tally(v, lang, solve(v)[0])
            total = c["right"] + c["wrong"] + c["unsure"] + c["none"]
            check(f"unknown: {lang} hidden, {label}: {c['right']}/{total} right, {c['wrong']} wrong, "
                  f"{c['unsure']} unsure, {c['none']} unanswered",
                  c["wrong"] == 0 and total == 288 and c["right"] >= floor[lang],
                  ", ".join(k for k in c if k.startswith("wrong:"))[:400])


def test_hide(corpus):
    """CTF_HIDE=vbscript, set by set."""
    sets = [v for v in corpus if any(lang_of(m) == "vbscript" for m, _ in specimens(v))]
    bad, first = [], set()
    with env(CTF_HIDE="vbscript,census", CTF_LEDGER_MASK="script.attack/vbs"):
        for v in sets:
            out, err = solve(v)
            ids = [q["qid"] for q in v["qs"] if lang_of(q["member"]) == "vbscript"]
            plain = [i for i in ids if out.get(i) is not None and not labels.is_unsure(out[i])]
            unsure = [i for i in ids if labels.is_unsure(out.get(i))]
            none = [i for i in ids if out.get(i) is None]
            parsed = [labels.parse(out[i]) for i in unsure]
            first |= {p.options[0][0] for p in parsed if p.options}
            wrong = [i for i in plain if out[i] != v["key"][i]]
            if (len(plain), len(unsure), len(none)) != (60, 3, 9) or wrong \
                    or any(p.key != "script.attack/vbs" for p in parsed) \
                    or not all(i.endswith("-attack") for i in unsure) or not all(i.endswith("-control") for i in none):
                bad.append(f"{v['name']}: {len(plain)} plain, {len(unsure)} unsure, {len(none)} None, {len(wrong)} wrong")
            if "[generic]" not in err or "unanswered:" not in err:
                bad.append(f"{v['name']}: no triage block on stderr")
    check(f"hide: CTF_HIDE=vbscript gives 60 plain, 3 unsure script.attack and 9 None in each of {len(sets)} sets",
          not bad and len(sets) == 8, "; ".join(bad[:4]))
    check("hide: the first option of every unsure script.attack answer is T1059.005", first == {"T1059.005"}, str(first))
    with env(CTF_HIDE="vbscript,census", CTF_LEDGER_MASK=None):
        v = sets[0]
        out, _ = solve(v)
        attack = [out.get(q["qid"]) for q in v["qs"] if lang_of(q["member"]) == "vbscript" and q["qid"].endswith("-attack")]
    check("hide: with the seed as shipped the three attack answers are the accepted T1059.005, plain",
          attack.count("T1059.005") == 3 and not any(labels.is_unsure(a) for a in attack), str(attack))
    with env(CTF_HIDE="vbscript", CTF_TESTING=None):
        out, err = solve(sets[0])
    check("hide: the knob is inert without CTF_TESTING=1", out == sets[0]["key"] and not err.strip())
    if plan_codec.optional("census") is None:
        print("NOTE census.py is not in this checkout: the control answers of a hidden language stay None")
        return
    bad, counts = [], Counter()
    with env(CTF_HIDE="vbscript", CTF_LEDGER_MASK="script.attack/vbs"):
        for v in sets:
            out, _ = solve(v)
            for q in v["qs"]:
                if lang_of(q["member"]) == "vbscript" and q["qid"].endswith("-control"):
                    a = out.get(q["qid"])
                    kind = "none" if a is None else "unsure" if labels.is_unsure(a) else "plain"
                    counts[kind] += 1
                    if kind == "plain" and a != v["key"][q["qid"]]:
                        bad.append(f"{v['name']} {q['qid']}: {a!r} != {v['key'][q['qid']]!r}")
    check(f"hide: with census.py the hidden language's control answers are {dict(counts)}, none of them plain and wrong",
          not bad, "; ".join(bad[:4]))


def lost_and_changed(corpus):
    lost, changed, lines = [], [], 0
    for v in corpus:
        out, err = solve(v)
        lines += sum("filled from the text path" in ln for ln in err.splitlines())
        for q in v["qs"]:
            a, k = out.get(q["qid"]), v["key"][q["qid"]]
            if a is None:
                lost.append(f"{v['name']} {q['qid']}")
            elif a != k:
                changed.append(f"{v['name']} {q['qid']}: {a!r} != {k!r}")
    return lost, changed, lines


def test_failures(corpus):
    """A module that breaks costs no answer: its own fallback or the text path fills in."""
    import batch
    import jscript
    import vbscript

    def raising(exc):
        def boom(*a, **k):
            raise exc("simulated failure")
        return boom

    original = vbscript.parse
    vbscript.parse = raising(vbscript.VBSError)
    try:
        lost, changed, _ = lost_and_changed(corpus)
    finally:
        vbscript.parse = original
    check(f"failures: vbscript.parse raising: {len(lost)} lost, {len(changed)} changed", not lost and not changed,
          "; ".join((lost + changed)[:4]))

    original, calls = batch.Cmd.run, {"n": 0}

    def first_fails(self, *a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("simulated walker failure")
        return original(self, *a, **k)

    lost, changed, fills = [], [], 0
    batch.Cmd.run = first_fails
    try:
        for v in corpus:
            calls["n"] = 0       # the first Batch specimen of every set
            one_lost, one_changed, lines = lost_and_changed([v])
            lost, changed, fills = lost + one_lost, changed + one_changed, fills + lines
    finally:
        batch.Cmd.run = original
    check(f"failures: batch.Cmd.run raising on one specimen per set: {len(lost)} lost, {len(changed)} changed, "
          f"{fills} answers filled from the text path", not lost and not changed, "; ".join((lost + changed)[:4]))

    for mod, n_expected in ((vbscript, 576), (batch, 864), (jscript, 1152)):
        original = mod.analyze
        mod.analyze = raising(RuntimeError)
        try:
            lost, changed, fills = lost_and_changed(corpus)
        finally:
            mod.analyze = original
        check(f"failures: {mod.__name__}.analyze raising on every specimen: {len(lost)} lost, {len(changed)} changed, "
              f"{fills} filled", not lost and not changed and fills >= n_expected and fills % 8 == 0, "; ".join((lost + changed)[:4]))

    # A module that fails WITHOUT raising. vbscript.py catches its own failures, and it answers
    # the role from the question id even when it recovered no configuration, so its answers are
    # never empty: the plan values it could not evaluate must still come from the text path.
    # (Only batch.py leaves a plan value open on purpose; see analyze.DECLINES_PLAN.)
    saved = vbscript.evaluate_into, vbscript.label_decode
    vbscript.evaluate_into, vbscript.label_decode = raising(RuntimeError), raising(RuntimeError)
    try:
        lost, changed, fills = lost_and_changed(corpus)
        v = next(v for v in corpus if any(lang_of(m) == "vbscript" for m, _ in specimens(v)))
        member, qs = next((m, qs) for m, qs in specimens(v) if lang_of(m) == "vbscript")
        with contextlib.redirect_stderr(io.StringIO()):
            alone = analyze.clean(vbscript.answers(qs, v["files"], {}))
    finally:
        vbscript.evaluate_into, vbscript.label_decode = saved
    check(f"failures: vbscript's evaluator and its label decoder both failing (it still answers {len(alone)} of {len(qs)} "
          f"questions of a specimen by itself): {len(lost)} lost, {len(changed)} changed, {fills} plan values filled from the text path",
          not lost and not changed and 0 < len(alone) < len(qs) and fills == 216 and "batch" in analyze.DECLINES_PLAN
          and "vbscript" not in analyze.DECLINES_PLAN and "jscript" not in analyze.DECLINES_PLAN, "; ".join((lost + changed)[:4]))
    original = jscript.answer
    jscript.answer = lambda q, info: None if generic.tail_of(q) == "campaign" else original(q, info)
    try:
        lost, changed, fills = lost_and_changed(corpus)
    finally:
        jscript.answer = original
    asked = sum(lang_of(q["member"]) == "jscript" and generic.tail_of(q) == "campaign" for v in corpus for q in v["qs"])
    check(f"failures: jscript.py leaving the campaign open on every specimen: {len(lost)} lost, {len(changed)} changed, "
          f"{fills} of {asked} filled from the text path", not lost and not changed and fills == asked > 100,
          "; ".join((lost + changed)[:4]))

    # A module whose value differs from the text reading is reported, and its value stands.
    v = next(v for v in corpus if any(lang_of(m) == "batch" for m, _ in specimens(v)))
    original = shapes_text.bat_shapes
    shapes_text.READERS["batch"] = lambda t: {**original(t), "expansion": "not_a_form"}
    try:
        out, err = solve(v)
    finally:
        shapes_text.READERS["batch"] = original
    lines = [ln for ln in err.splitlines() if ln.startswith("[analyze] paths disagree on batch-")]
    check("failures: a text reading that differs prints 'paths disagree' and the module's value stands",
          len(lines) == 9 and out == v["key"] and "text=not_a_form" in lines[0], f"{len(lines)} lines")


def test_speed(corpus):
    """Two Mastery sets (462 answers) inside half a second."""
    sets = [v for v in corpus if v["name"].startswith("day-04") and "/mastery#" in v["name"]]
    best = None
    for _ in range(3):
        t = time.perf_counter()
        n = sum(len(solve(v)[0]) for v in sets)
        dt = time.perf_counter() - t
        best = dt if best is None else min(best, dt)
    check(f"speed: {n} answers in {best:.3f} s (limit 0.5 s)", n == 462 and best < 0.5)


def test_partial_and_only(corpus):
    v = next(v for v in corpus if v["name"].startswith("day-04"))
    ctx = {"set": v["set"], "partial": {}}
    out, _ = solve(v, ctx=ctx)
    check("partial: ctx['partial'] holds every answer when the runner passes that key", ctx["partial"] == out and len(out) == 231)
    ctx = {"set": v["set"]}
    solve(v, ctx=ctx)
    check("partial: a ctx without the key is left alone", "partial" not in ctx)
    with env(ONLY="vbscript,batch"):
        out, _ = solve(v)
    check("only: ONLY=vbscript,batch answers those two languages and nothing else",
          len(out) == 144 and {i.split("-")[0] for i in out} == {"vbscript", "batch"})


# ---------------------------------------------------------------- synthetic specimens

PLAN = ("v=1|steps=locate_local,dispatch_process|adapter=mshta.exe|stage_count=1|graph=single|next_language=none|"
        "campaign_id=campaign-0123456789|file_path=C:\\Users\\Public\\HuntressLab\\stage-0123456789.dat")


def hex_colon(plain: str, key: int) -> str:
    return ":".join(f"{b ^ key:02x}" for b in plain.encode())


def question(qid, member, text, **more):
    return {"id": qid, "qid": qid, "answer_id": qid, "member": member, "artifact": f"evidence.zip -> {member}",
            "question": text, **more}


def new_language_questions(lang, member):
    return [
        question(f"{lang}-launcher-role", member, f"Classify {member} by its ordered behavior graph."),
        question(f"{lang}-launcher-attack", member, "Recover the primary MITRE ATT&CK technique ID, or none."),
        question(f"{lang}-launcher-adapter", member, "Recover the exact adapter named by the reconstructed plan."),
        question(f"{lang}-launcher-campaign", member, "Recover the exact synthetic campaign identifier."),
        question(f"{lang}-launcher-file-path", member, "Recover the exact file_path indicator."),
        question(f"{lang}-launcher-graph", member, "Identify the exact stage-graph topology."),
        question(f"{lang}-launcher-representation", member, "Identify the exact material representation."),
        question(f"{lang}-launcher-transform", member, "Identify the exact reversible byte transform."),
        question(f"{lang}-launcher-control", member, "Identify the exact control-flow form."),
    ]


def labelled(value, ext, field, word) -> bool:
    """Whether `value` is the in-file codec label's word held unsure for an extension where no such name was
    judged (Day 13 preparation, generic.LABEL_JUDGED): `script.<field>/<ext>.codec_label`, the label first."""
    parsed = labels.parse(value) if isinstance(value, str) else None
    return parsed is not None and parsed.key == f"script.{field}/{ext}.codec_label" \
        and list(parsed.options[0]) == ["label", word]


def test_new_language():
    """A language nobody has seen: everything the plan holds is answered, nothing is guessed."""
    member = "local-dispatch.xyz"
    body = f"# HUNTRESS-CODEC:hex_colon|single_byte_xor|5a\nmaterial = '{hex_colon(PLAN, 0x5a)}'\nrun(decode(material))\n"
    qs = new_language_questions("xyz", member)
    err = io.StringIO()
    with env(CTF_HIDE="census"), contextlib.redirect_stderr(err):
        out = analyze.solve_set(qs, {member: body.encode()}, {"set": 0})
    want = {"xyz-launcher-role": "launcher", "xyz-launcher-adapter": "mshta.exe",
            "xyz-launcher-campaign": "campaign-0123456789", "xyz-launcher-graph": "single",
            "xyz-launcher-file-path": "C:\\Users\\Public\\HuntressLab\\stage-0123456789.dat"}
    check("new language: role, adapter, campaign, indicator and graph are plain; the labelled codec's two words are "
          "unsure under script.<field>/xyz.codec_label, the label first (no day judged them for this extension)",
          all(out.get(k) == v for k, v in want.items())
          and labelled(out.get("xyz-launcher-representation"), "xyz", "representation", "hex_colon")
          and labelled(out.get("xyz-launcher-transform"), "xyz", "transform", "single_byte_xor"),
          str({k: out.get(k) for k in list(want) + ["xyz-launcher-representation", "xyz-launcher-transform"]})[:400])
    attack = labels.parse(out.get("xyz-launcher-attack"))
    check("new language: a launcher's technique is unsure under script.attack/<ext>: the six interpreters in order, then "
          "the parent technique and the other sub-techniques, 12 names in all",
          attack is not None and attack.key == "script.attack/xyz" and attack.names == generic.ANY_INTERPRETER
          and attack.names[:7] == ["T1059.001", "T1059.003", "T1059.005", "T1059.006", "T1059.007", "T1059.004", "T1059"]
          and len(attack.names) == len(set(attack.names)) == 12 == labels.MAX_OPTIONS == generic.MAX_OPTIONS, str(attack))
    check("new language: the control form is None (never a default)", "xyz-launcher-control" not in out)
    text = err.getvalue()
    check("new language: one triage block names the plan, the label and the unanswered id",
          "plan decoded as hex_: | xor_5a" in text and "label: hex_colon|single_byte_xor|5a" in text
          and "unanswered: xyz-launcher-control" in text, text[:300])

    # The table itself is asked, not the ledger: a day that judges one of these extensions (as Day 5 did for .py), or
    # rejects a first candidate, must not turn the check red. The round trip through labels is the .xyz check above.
    for ext, first in ((".hta", ["T1218.005", "T1059.005", "T1059.007"]), (".wsf", ["T1059.005", "T1059.007"]),
                       (".sct", ["T1218.010", "T1059.007"]), (".py", ["T1059.006"]), (".sh", ["T1059.004"]),
                       (".lua", ["T1059.011"]), (".au3", ["T1059.010"]), (".rb", ["T1059", "T1059.004"])):
        names = generic.techniques(ext)
        check(f"new language: {ext} technique candidates start with {', '.join(first)}, then the other interpreters (12 at most)",
              names[:len(first)] == first and set(names) <= set(generic.ANY_INTERPRETER) | set(first)
              and len(names) == len(set(names)) == 12 and generic.techniques(ext[1:].upper()) == names, str(names))
    with contextlib.redirect_stderr(io.StringIO()):
        got = generic.answers(new_language_questions("py", "local-dispatch.py")[1:2], {"local-dispatch.py": body.encode()}, {})
    check("new language: with the seed as shipped a .py launcher's technique is the accepted T1059.006, plain",
          got.get("py-launcher-attack") == "T1059.006", str(got))

    # Without a label the decode is known and its name is not.
    bare = f"material = '{hex_colon(PLAN, 0x5a)}'\n"
    with contextlib.redirect_stderr(io.StringIO()):
        got = generic.answers(qs, {member: bare.encode()}, {})
    rep, tr = labels.parse(got.get("xyz-launcher-representation")), labels.parse(got.get("xyz-launcher-transform"))
    check("new language: an unlabelled codec is unsure, with the names the known label tables use for the same decode",
          rep is not None and rep.key == "script.representation/xyz.hex_colon" and rep.names == ["hex_colon", "reversed_hex"]
          and tr is not None and tr.key == "script.transform/xyz.xor" and tr.names == ["single_byte_xor", "xor_5a"],
          f"{rep} {tr}")

    # A graph the lane has never seen is a new fact: with the switch off, no role, no technique, one line.
    odd = PLAN.replace("locate_local,dispatch_process", "locate_local,persist_registry")
    err = io.StringIO()
    with offering(False), contextlib.redirect_stderr(err):
        got = generic.answers(qs, {member: f"m = '{hex_colon(odd, 0x21)}'\n".encode()}, {})
    check("new language: with OFFER_UNSEEN_ROLES off, a steps tuple judged nowhere gives no role and no technique, "
          "and says so on stderr",
          "xyz-launcher-role" not in got and "xyz-launcher-attack" not in got and got.get("xyz-launcher-adapter") == "mshta.exe"
          and "steps not in the role table: locate_local,persist_registry" in err.getvalue(), err.getvalue()[:300])
    check("new language: OFFER_UNSEEN_ROLES ships switched on (the player's yes of 2026-10-05)",
          generic.OFFER_UNSEEN_ROLES is True)
    test_unseen_steps(member, qs, odd)

    # Two plan keys that fit one question are two facts.
    two = PLAN + "|registry_path=HKCU\\Software\\HuntressLab"
    notes = []
    q = question("xyz-launcher-path", member, "What exact local path is reconstructed?")
    check("new language: a question two plan keys fit is not answered",
          generic.plan_answer(q, plan_codec.flatten(two), None, notes) is None and len(notes) == 1
          and generic.plan_answer(q, plan_codec.flatten(PLAN), None) == plan_codec.flatten(PLAN)["file_path"])

    # A role outside the question's accepted values is not sent.
    q = question("xyz-launcher-role", member, "Classify it.", answer_format={"kind": "enum", "accepted_values": ["stager"]})
    check("new language: a role the question's enum does not list is None",
          generic.plan_answer(q, plan_codec.flatten(PLAN)) is None)

    # A truncated or merely plan-like decode is not a plan.
    cut = "v=1|steps=locate_local,dispatch_process|adapter"
    check("plan codec: the strict grammar is the only acceptance",
          plan_codec.recover(f"m = '{hex_colon(cut, 0x5a)}'") is None and plan_codec.recover("nothing here") is None
          and plan_codec.plan_of("nothing here") == {})


@contextlib.contextmanager
def offering(on: bool):
    """generic.OFFER_UNSEEN_ROLES set for the block (the solver reads it at call time)."""
    old = generic.OFFER_UNSEEN_ROLES
    generic.OFFER_UNSEEN_ROLES = on
    try:
        yield
    finally:
        generic.OFFER_UNSEEN_ROLES = old


# What the role question has listed since Day 4.
ROLE_ENUM = ["benign_utility", "downloader", "dropper", "impact", "launcher", "persistence_descriptor", "relay",
             "staged_chain", "stager", "uploader", "advanced_syntax"]


def test_unseen_steps(member, qs, odd):
    """A step list outside the role table is never answered plain: a name the judge accepted for
    the same steps under another extension is offered; candidates from the question's own list
    only when OFFER_UNSEEN_ROLES is switched on."""
    def ask(plan, ext, offer, mask="script.role/*,script.attack/*"):
        m = "local-dispatch." + ext
        asked = new_language_questions(ext, m)
        asked[0]["answer_format"] = {"kind": "enum", "accepted_values": list(ROLE_ENUM)}
        with env(CTF_LEDGER_MASK=mask), offering(offer), contextlib.redirect_stderr(io.StringIO()):
            got = generic.answers(asked, {m: f"m = '{hex_colon(plan, 0x21)}'\n".encode()}, {})
        return got.get(f"{ext}-launcher-role"), got.get(f"{ext}-launcher-attack"), got

    role, attack, got = ask(odd, "xyz", True)
    r, a = labels.parse(role), labels.parse(attack)
    check("unseen steps: switched on, a list judged nowhere gets the question's own role names, unsure under "
          "script.role/<ext>.<steps>: the id's specimen word, then two shared step words, then names no list has taken",
          r is not None and r.key == "script.role/xyz.locate_local+persist_registry" and sorted(r.names) == sorted(ROLE_ENUM)
          and r.names[:5] == ["launcher", "uploader", "persistence_descriptor", "relay", "advanced_syntax"]
          and got.get("xyz-launcher-adapter") == "mshta.exe", str(r))
    check("unseen steps: and the techniques of those roles in the same order under script.attack/<ext>.<steps>, the own "
          "interpreter for a role that has none, `none` where the question permits it, 12 at most",
          a is not None and a.key == "script.attack/xyz.locate_local+persist_registry" and a.names[:2] == ["T1059.001", "T1041"]
          and "none" in a.names and {"T1105", "T1140", "T1486"} <= set(a.names) and len(a.names) == len(set(a.names)) <= 12,
          str(a))
    quiet = new_language_questions("xyz", member)[1]
    quiet["question"] = "Recover the primary MITRE ATT&CK technique ID."
    with env(CTF_LEDGER_MASK="script.role/*,script.attack/*"), offering(True), contextlib.redirect_stderr(io.StringIO()):
        a = labels.parse(generic.answers([quiet], {member: f"m = '{hex_colon(odd, 0x21)}'\n".encode()}, {}).get(quiet["qid"]))
    check("unseen steps: `none` is not offered to a question that does not permit it", a is not None and "none" not in a.names, str(a))

    # A name judged for the same steps under ANOTHER extension's key is offered first, switched on or off.
    send = PLAN.replace("locate_local,dispatch_process", "collect_fixture,send_remote")
    wake = PLAN.replace("locate_local,dispatch_process", "wake_host,run_next")
    with scratch_ledger():
        for key, name in (("script.role/abc.collect_fixture+send_remote", "uploader"),
                          ("script.attack/abc.collect_fixture+send_remote", "T1041"),
                          ("script.role/abc.wake_host+run_next", "relay"),
                          ("script.attack/abc.wake_host+run_next", "T1059.004")):
            labels.learn(key, name, "accepted", scope="key", attempt_id="test-generic", answer_ids=["abc-x"], left=None)
        role, attack, _ = ask(send, "xyz", False, mask=None)
        r, a = labels.parse(role), labels.parse(attack)
        check("unseen steps: switched off, a role and a technique judged for the same steps under another extension are "
              "offered under this extension's own key, unsure and alone",
              r is not None and r.key == "script.role/xyz.collect_fixture+send_remote" and r.names == ["uploader"]
              and a is not None and a.key == "script.attack/xyz.collect_fixture+send_remote" and a.names == ["T1041"], f"{r} {a}")
        role, attack, _ = ask(wake, "xyz", False, mask=None)
        r, a = labels.parse(role), labels.parse(attack)
        check("unseen steps: a T1059 technique judged for another extension stands for that extension's interpreter: this "
              "extension's own candidates are offered in its place",
              r is not None and r.names == ["relay"] and a is not None and a.names == generic.techniques("xyz")
              and a.key == "script.attack/xyz.wake_host+run_next", f"{r} {a}")
        role, attack, _ = ask(send, "xyz", True, mask=None)
        r = labels.parse(role)
        check("unseen steps: switched on, the name judged elsewhere still comes first",
              r is not None and r.names[0] == "uploader" and sorted(r.names) == sorted(ROLE_ENUM)
              and labels.parse(attack).names[0] == "T1041", str(r))
        role, attack, _ = ask(send, "abc", False, mask=None)
        check("unseen steps: for the extension whose own key holds the accepted name the answer is that name, plain",
              role == "uploader" and attack == "T1041", f"{role!r} {attack!r}")
        pack = PLAN.replace("locate_local,dispatch_process", "pack_fixture,ship_remote")
        for verdict in ("accepted", "split"):
            labels.learn("script.role/abc.pack_fixture+ship_remote", "uploader", verdict, scope="key", attempt_id="test-generic",
                         answer_ids=["abc-x"], left=None)
        role, _, _ = ask(pack, "xyz", False, mask=None)
        check("unseen steps: the name of a key that is split (it no longer answers every id) is not carried to another extension",
              role is None and labels.state("script.role/abc.pack_fixture+ship_remote")["split"]
              and ("pack_fixture", "ship_remote") not in [g for _, g, _ in generic.judged("role")], repr(role))
    role, attack, _ = ask(send, "xyz", False, mask=None)
    check("unseen steps: without those verdicts the same steps give no role and no technique", role is None and attack is None,
          f"{role!r} {attack!r}")


def test_fields():
    """The field of an answer id is read from its end: the id without the words all ids of its
    specimen share. Ids of four to six parts, a version 2 plan."""
    member = "current-build.xyz"
    v2 = PLAN.replace("v=1|", "v=2|") + "|windows_chain=cmd_to_script|carrier=zip_bundle"
    body = f"# HUNTRESS-CODEC:hex_colon|single_byte_xor|5a\nmaterial = '{hex_colon(v2, 0x5a)}'\n"
    prefix = "xyz-current-build-launcher"
    fields = ("role", "attack", "adapter", "campaign", "file-path", "graph", "windows-chain", "carrier", "representation",
              "transform", "control")
    # The question text says nothing: only the id can name the field.
    qs = [question(f"{prefix}-{f}", member, "Recover the value.") for f in fields]
    check("fields: fields_of takes off the words all ids of a specimen share; one question, or no shared word, gives nothing",
          generic.fields_of(qs) == {f"{prefix}-{f}": f for f in fields} and generic.fields_of(qs[:1]) == {}
          and generic.fields_of([question("a-b-role", member, "?"), question("c-d-attack", member, "?")]) == {}
          and generic.fields_of([{"qid": "set2.python-zipapp-relay-role"}, {"qid": "set2.python-zipapp-relay-next-stage"}])
          == {"python-zipapp-relay-role": "role", "python-zipapp-relay-next-stage": "next-stage"}
          # an id that is the start of another keeps its last word
          and generic.fields_of([{"qid": "a-b-role"}, {"qid": "a-b-role-extra"}]) == {"a-b-role": "role", "a-b-role-extra": "role-extra"})
    four = [question(f"xyz-zipapp-launcher-{f}", member, "Recover the value.") for f in ("role", "adapter", "graph", "campaign")]
    with env(CTF_HIDE="census"), contextlib.redirect_stderr(io.StringIO()):
        out = analyze.solve_set(four, {member: body.encode()}, {"set": 0})
    check("fields: ids of four parts are answered by the id alone",
          out == {"xyz-zipapp-launcher-role": "launcher", "xyz-zipapp-launcher-adapter": "mshta.exe",
                  "xyz-zipapp-launcher-graph": "single", "xyz-zipapp-launcher-campaign": "campaign-0123456789"}, str(out))
    check("fields: a question alone keeps the old rule (the third part of the id); with its specimen's questions it carries the field",
          generic.tail_of(qs[6]) == "build-launcher-windows-chain" and generic.tail_of(generic.with_fields(qs)[6]) == "windows-chain"
          and generic.tail_of(question("xyz-launcher-file-path", member, "?")) == "file-path"
          and generic.with_fields(generic.with_fields(qs)) == generic.with_fields(qs))
    with env(CTF_HIDE="census"), contextlib.redirect_stderr(io.StringIO()):
        out = analyze.solve_set(qs, {member: body.encode()}, {"set": 0})
    want = {"role": "launcher", "adapter": "mshta.exe", "campaign": "campaign-0123456789", "graph": "single",
            "file-path": "C:\\Users\\Public\\HuntressLab\\stage-0123456789.dat", "windows-chain": "cmd_to_script",
            "carrier": "zip_bundle"}
    attack = labels.parse(out.get(f"{prefix}-attack"))
    check("fields: ids of four to six parts with a v=2 plan: role, adapter, campaign, the indicator, graph, windows-chain "
          "and carrier are plain; the labelled codec and the technique are unsure; the control form is None",
          all(out.get(f"{prefix}-{f}") == a for f, a in want.items()) and attack is not None and attack.key == "script.attack/xyz"
          and labelled(out.get(f"{prefix}-representation"), "xyz", "representation", "hex_colon")
          and labelled(out.get(f"{prefix}-transform"), "xyz", "transform", "single_byte_xor")
          and f"{prefix}-control" not in out and len(out) == 10, str({f: out.get(f"{prefix}-{f}") for f in fields})[:400])
    check("fields: the runner's question tables are left as they were", not any("field" in q for q in qs))


def test_material():
    """What plan_codec reads as material, and what it keeps of a plan that was read from a piece."""
    v2 = PLAN.replace("v=1|", "v=2|")
    kept = v2[:v2.rfind("|") + 1]             # the plan without its last field
    key = next(k for k in range(1, 256) if {"-", "_"} <= set(base64.urlsafe_b64encode(bytes(b ^ k for b in v2.encode())).decode()))
    raw = bytes(b ^ key for b in v2.encode())
    b64, hexa = base64.b64encode(raw).decode(), raw.hex()
    n = len(b64) // 3 // 4 * 4
    chunks = [b64[:n], b64[n:2 * n], b64[2 * n:]]
    numbers = ", ".join(map(str, raw))

    def read(body):
        got, note = plan_codec.reading(body)
        return (got[0] if got else None), note

    versions = [n for n in range(1, 10)
                if (plan_codec.decode(f"m = '{hex_colon(PLAN.replace('v=1|', f'v={n}|'), 0x33)}'") or [None])[0]
                == PLAN.replace("v=1|", f"v={n}|")]
    check("material: a plan of any version 1 to 9 is read by the built-in cribs; version 12 is not",
          versions == list(range(1, 10)) and plan_codec.decode(f"m = '{hex_colon(PLAN.replace('v=1|', 'v=12|'), 0x33)}'") is None,
          str(versions))
    forms = {"string literals with only white space between them": 'M = ("' + '"\n     "'.join(chunks) + '")\n',
             "the same with a b prefix on each": 'M = (b"' + '"\n     b"'.join(chunks) + '")\n',
             "a literal of \\xNN escapes": 'M = b"' + "".join(f"\\x{b:02x}" for b in raw) + '"\n',
             "a literal of octal escapes": "M = '" + "".join(f"\\{b:03o}" for b in raw) + "'\n",
             "url-safe base64": 'M = "' + base64.urlsafe_b64encode(raw).decode() + '"\n',
             "a number list that ends in a comma": f"M = ({numbers},)\n",
             "a number list over several lines that ends in a comma": "M = [\n    " + numbers.replace(", ", ",\n    ") + ",\n]\n"}
    for what, body in forms.items():
        check(f"material: {what}: the whole plan, with no note", read(body) == (v2, None), str(read(body))[:200])
    check("material: unescaped() reads numeric escapes only, and nothing it does not know",
          plan_codec.unescaped("\\x41\\102\\u0043d\\n") == [65, 66, 67, 100, 10] and plan_codec.unescaped("plain text") is None
          and plan_codec.unescaped("\\x41\\q") is None and plan_codec.unescaped("\\x41\\") is None
          and plan_codec.unescaped("\\x41\u0141") is None and plan_codec.unescaped("C:\\Users\\Public\\x41") is None)

    # The grammar has no end mark. A plan read from a piece keeps its exact fields and loses the last one.
    pieces = {"a list of chunks": 'M = ["' + '", "'.join(chunks) + '"]\n',
              "one variable per chunk": "".join(f'P{i} = "{c}"\n' for i, c in enumerate(chunks)),
              "chunks joined by an operator this reader does not know": 'M = "' + '" ~~\n    "'.join(chunks) + '"\n',
              "three number lists": "".join(f"L{i} = [{', '.join(map(str, raw[a:b]))}]\n"
                                            for i, (a, b) in enumerate(((0, 60), (60, 120), (120, len(raw)))))}
    lua = 'local M = "' + '" ..\n    "'.join(chunks) + '"\n'   # Lua's `..` is a join it knows (2026-10-06)
    check("material: chunks joined by Lua's `..`: the whole plan, with no note", read(lua) == (v2, None), str(read(lua))[:200])
    for what, body in pieces.items():
        got, note = read(body)
        check(f"cut guard: {what}: the plan comes without its last field, and the note says so",
              got == kept and note is not None and "'file_path'" in note and "is left out" in note, f"{got!r} {note!r}"[:300])
    token = base64.urlsafe_b64encode(raw).decode()
    got, note = read(f"# material {token}\n")
    check("cut guard: a bare url-safe token is cut at its first `_`: what is read from it ends at a field boundary",
          "_" in token and (got is None or (kept.startswith(got) and got.endswith("|") and got != v2)), f"{got!r} {note!r}"[:300])
    member = "local-dispatch.xyz"
    err = io.StringIO()
    with env(CTF_HIDE="census"), contextlib.redirect_stderr(err):
        out = generic.answers(new_language_questions("xyz", member), {member: pieces["a list of chunks"].encode()}, {})
    check("cut guard: the answers of such a plan: every field but the last, and the triage block names what was left out",
          out.get("xyz-launcher-adapter") == "mshta.exe" and out.get("xyz-launcher-campaign") == "campaign-0123456789"
          and "xyz-launcher-file-path" not in out and "note: the last field of the plan ('file_path') is left out" in err.getvalue()
          and "plan decoded as" in err.getvalue(), err.getvalue()[:400])

    # Two literals with only white space between them: one literal in some languages, two arguments in others.
    tail = f"{ord('x') ^ key:02x}"            # a second literal that decodes to one printable character
    got, note = read(f'run "{hexa}" "{tail}"\n')
    check("cut guard: a join that only lengthens the last value of a plan one literal gives alone: that value is left out",
          got == kept and note is not None and "white space" in note, f"{got!r} {note!r}"[:300])
    at = 2 * v2.index("|campaign_id")
    check("cut guard: a join that begins a field no literal holds alone is the plan",
          read(f'M = ("{hexa[:at]}"\n     "{hexa[at:]}")\n') == (v2, None))
    check("cut guard: a whole literal beside a short one (a key, a label) is whole; the same material stored twice is one plan",
          read(f'run(decode("{hexa}", "{key:02x}"))\n') == (v2, None) and read(f'A = "{hexa}"\nB = "{hexa}"\n') == (v2, None)
          and read(f'M = ("{hexa}"\n     "{hexa}")\n') == (v2, None))
    grades = {how: g for how, _, g in plan_codec.sources(pieces["a list of chunks"])}
    check("cut guard: candidates() is sources() without the grade",
          [(h, d) for h, d, _ in plan_codec.sources(forms["url-safe base64"])] == list(plan_codec.candidates(forms["url-safe base64"]))
          and set(grades.values()) == {plan_codec.PIECE})
    test_cut_forms(v2, kept, key)


def test_cut_forms(v2, kept, key):
    """The forms the review of the cut guard found: each gave a plan cut inside its last value, whole and with no note."""
    raw = bytes(b ^ key for b in v2.encode())
    b64, hexa = base64.b64encode(raw).decode(), raw.hex()

    def read(body):
        got, note = plan_codec.reading(body)
        return (got[0] if got else None), note

    def cut(body):
        """Nothing, or a plan that ends at a field boundary before the last field, with the note."""
        got, note = read(body)
        return got is None or (note is not None and "is left out" in note and kept.startswith(got) and got.endswith("|"))

    def decoded(body):
        return {t for _, data in plan_codec.candidates(body) for t in plan_codec._plans(data)}

    # A second number list that is no part of the material: the eight numbers of `chr_join` behind a Python specimen's.
    helper = '\n\ndef load():\n    return "".join(chr(value) for value in (99, 104, 114, 95, 106, 111, 105, 110))\n'
    for what, k, opening, closing in (("a number list", 0, "[", "]"), ("a number tuple that ends in a comma", 5, "(", ",)")):
        body = f"M = {opening}{', '.join(str(b ^ k) for b in v2.encode())}{closing}{helper}"
        got, note = read(body)
        check(f"cut guard: {what} and a second list that only lengthens its last value (key {k}): the last field is left "
              f"out, and the join is no candidate (shapes_<ext>.py reads candidates() too)",
              got == kept and note is not None and "'file_path'" in note and decoded(body) == {v2}, f"{got!r} {note!r} {decoded(body)}"[:400])
    at = len(v2) - 9                           # the second list holds the end of the last value: the same two readings
    two = f"A = [{', '.join(map(str, v2.encode()[:at]))}]\nB = [{', '.join(map(str, v2.encode()[at:]))}]\n"
    half = len(v2) // 2
    halves = f"A = [{', '.join(map(str, v2.encode()[:half]))}]\nB = [{', '.join(map(str, v2.encode()[half:]))}]\n"
    check("cut guard: two lists whose second holds only the end of the last value: that value is left out; two halves are the plan",
          read(two)[0] == kept and read(two)[1] is not None and read(halves) == (v2, None), f"{read(two)} {read(halves)}"[:300])
    long = bytes(b ^ key for b in (v2 + "|upload_url=https://campaign.example.invalid/" + "u" * 100).encode())
    nine = "".join(f"L{i} = [{', '.join(map(str, long[i * 32:(i + 1) * 32 if i < 8 else len(long)]))}]\n" for i in range(9))
    check(f"cut guard: more number lists than are tried as runs ({plan_codec.MAX_LISTS}): two of them give a plan without its "
          f"last field, with the note", plan_codec.MAX_LISTS == 8 and read(nine)[0] is not None and cut(nine), str(read(nine))[:300])

    def wrapped(text, width):
        return "\n".join(text[i:i + width] for i in range(0, len(text), width))

    # Row 56 (2026-10-07): a here-document's body is ONE value, its lines joined; the cut guard keeps the rest.
    heredoc = "cat <<'EOF'\n" + wrapped(b64, 100) + "\nEOF\n"
    check("row 56: base64 wrapped at 100 columns in a here-document is one value: the whole plan, with no note",
          read(heredoc) == (v2, None), str(read(heredoc))[:300])
    blocks = {"base64 wrapped at 120 columns in a triple-quoted block": 'M = """\n' + wrapped(b64, 120) + '\n"""\n',
              "base64 wrapped at 100 columns in a here-document, a blank line in it": "cat <<'EOF'\n" + wrapped(b64, 100).replace(
                  "\n", "\n\n", 1) + "\nEOF\n",
              "hex wrapped at 200 columns in a comment block": "# " + wrapped(hexa, 200).replace("\n", "\n# ") + "\n",
              "base64 wrapped with \\n escapes inside one literal": 'M = "' + wrapped(b64, 80).replace("\n", "\\n") + '"\n'}
    for what, body in blocks.items():
        got, note = read(body)
        check(f"cut guard: {what}: a line of it is a piece (a plan without its last field, with the note)",
              got is not None and cut(body), f"{got!r} {note!r}"[:300])

    # A join with one more literal behind an operator or a comment is a piece of a longer join.
    short = [b64[i:i + 20] for i in range(0, len(b64), 20)]
    mid = len(short) // 2
    for what, glue in (("joined with +", " +\n     "), ("with only white space between them", "\n     ")):
        body = ('M = ("' + f'"{glue}"'.join(short[:mid]) + f'"{glue.rstrip(" ")}  # the second half\n     "'
                + f'"{glue}"'.join(short[mid:]) + '")\n')
        got, note = read(body)
        check(f"cut guard: 20-character chunks {what}, a comment after half of them: the join before the comment is a piece",
              got is not None and cut(body), f"{got!r} {note!r}"[:300])

    # Chunks of one material in separate literals, whatever stands between them and in whatever order.
    n = len(raw) // 3
    own = [base64.b64encode(raw[i:i + n]).decode() for i in range(0, len(raw), n)]
    third = len(b64) // 3 // 4 * 4
    parts = [b64[:third], b64[third:2 * third], b64[2 * third:]]
    colon = [":".join(f"{b:02x}" for b in raw[i:i + n]) for i in range(0, len(raw), n)]
    chunked = {"each chunk base64-encoded on its own, one variable per chunk": "".join(f'P{i} = "{c}"\n' for i, c in enumerate(own)),
               "a list of chunks, each base64-encoded on its own": 'M = ["' + '", "'.join(own) + '"]\n',
               "base64 chunks assigned out of order": "".join(f'P{i} = "{parts[i]}"\n' for i in (1, 0, 2)) + "M = P0 + P[1] + P2\n",
               "one variable per hex-colon chunk": "".join(f'P{i} = "{c}"\n' for i, c in enumerate(colon))}
    for what, body in chunked.items():
        got, note = read(body)
        check(f"cut guard: {what}: the chunk that starts the plan is a piece", got is not None and cut(body), f"{got!r} {note!r}"[:300])
    # The same chunks joined by a statement that names each one: the join is the value, in its order
    # (plan_codec.whole_values), so the plan is whole; one more variable after it makes it a piece again.
    ordered = "".join(f'P{i} = "{parts[i]}"\n' for i in (1, 0, 2))
    check("cut guard: chunks assigned out of order and joined by M = P0 + P1 + P2: the join is the whole plan",
          read(ordered + "M = P0 + P1 + P2\n") == (v2, None), str(read(ordered + "M = P0 + P1 + P2\n"))[:300])
    check("cut guard: ... and with M joined to something else later, the join is a piece",
          cut(ordered + "M = P0 + P1 + P2\nN = M + tail()\n"), str(read(ordered + "M = P0 + P1 + P2\nN = M + tail()\n"))[:300])
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    check("cut guard: a whole literal beside a much shorter one of its alphabet (the base64 alphabet, a long name) is whole",
          read(f'ALPHABET = "{alphabet}"\nNAME = "HUNTRESS_FIXTURE_CONTEXT"\nM = "{b64}"\n') == (v2, None)
          and read(f'M = "{hexa}"\nDIGEST = "{"0123456789abcdef" * 4}"\n') == (v2, None))

    # The text path of a known language keeps what is exact of such a plan (analyze.text_reading).
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        text, _ = analyze.text_reading("vbscript", new_language_questions("vbs", "local-dispatch.vbs"), chunked[
            "a list of chunks, each base64-encoded on its own"], ".vbs")
    check("cut guard: the text path of a known language answers from the shorter plan and says so",
          text.get("vbs-launcher-adapter") == "mshta.exe" and "vbs-launcher-file-path" not in text
          and "the text path reads a shorter plan" in err.getvalue(), f"{text} {err.getvalue()[:200]}"[:400])

    # A near key must not stand in for the field the guard left out.
    q = question("xyz-launcher-path", "local-dispatch.xyz", "What exact local path is reconstructed?")
    both = plan_codec.flatten(PLAN.replace("|file_path=", "|archive_path=C:\\Temp\\a.zip|file_path="))
    left = {k: v for k, v in both.items() if k != "file_path"}
    check("cut guard: a plan that lost its last field gives no near-key answer (`path` fitted two keys before the cut)",
          generic.plan_answer(q, both) is None and generic.plan_answer(q, left) == "C:\\Temp\\a.zip"
          and generic.plan_answer(q, left, cut=True) is None
          and generic.plan_answer(question("xyz-launcher-archive-path", "local-dispatch.xyz", "?"), left, cut=True) == "C:\\Temp\\a.zip")


def test_hooks(corpus):
    """Live fixes are new files loaded by name: a crib, a label pattern, shapes, a whole module."""
    hooks = SCRATCH / "hooks"
    hooks.mkdir()
    member = "local-dispatch.xyz"
    # The versions 1 to 9 are built in; a plan of version 12 stands for "a start nobody has seen".
    v12 = PLAN.replace("v=1|", "v=12|")
    body = f"codec <<hex_colon|single_byte_xor|33>>\nmaterial = '{hex_colon(v12, 0x33)}'\n"
    check("hooks: a plan that starts 'v=12|' is not recovered by the built-in cribs",
          plan_codec.recover(body, ".xyz") is None and plan_codec.label_of(body, ".xyz") is None)
    plan_codec.HOOK_DIRS.append(hooks)
    try:
        (hooks / "hooks_xyz.py").write_text('EXTRA_CRIBS = [b"v=12|steps="]\nLABEL_PATTERNS = [r"codec <<([^>]+)>>"]\n')
        got = plan_codec.recover(body, ".xyz")
        check("hooks: hooks_xyz.py adding one crib is picked up", got is not None and got[0] == v12 and got[2] == "xor_33", str(got))
        check("hooks: its label pattern is picked up", plan_codec.label_of(body, ".xyz") == ["hex_colon", "single_byte_xor", "33"])
        check("hooks: another extension does not see it", plan_codec.recover(body, ".abc") is None)
        cut = f"material = '{hex_colon('v=12|steps=locate_local|adapter', 0x33)}'"
        check("hooks: a hook's crib does not loosen the grammar", plan_codec.recover(cut, ".xyz") is None)

        qs = new_language_questions("xyz", member)
        (hooks / "shapes_xyz.py").write_text(
            "import labels\n"
            "def shapes(text, questions):\n"
            "    return {q['qid']: labels.pick('script.control/xyz.while', ['while_once', 'while_loop'])\n"
            "            for q in questions if q['qid'].endswith('-control')}\n")
        with contextlib.redirect_stderr(io.StringIO()):
            out = analyze.solve_set(qs, {member: body.encode()}, {})
        parsed = labels.parse(out.get("xyz-launcher-control"))
        check("hooks: shapes_xyz.py answers what generic left open, and only that",
              parsed is not None and parsed.key == "script.control/xyz.while" and out.get("xyz-launcher-role") == "launcher"
              and labelled(out.get("xyz-launcher-representation"), "xyz", "representation", "hex_colon"),
              str(out.get("xyz-launcher-control")))

        (hooks / "lang_xyz.py").write_text(
            "def answers(questions, files, ctx):\n"
            "    return {q['qid']: 'from_lang_xyz' for q in questions if q['qid'].endswith(('-control', '-graph'))}\n")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            out = analyze.solve_set(qs, {member: body.encode()}, {})
        check("hooks: lang_xyz.py is asked first and generic fills what it leaves",
              out.get("xyz-launcher-control") == "from_lang_xyz" and out.get("xyz-launcher-graph") == "from_lang_xyz"
              and out.get("xyz-launcher-adapter") == "mshta.exe"
              and "xyz-launcher-adapter: filled by generic" in err.getvalue())
        check("hooks: covers() accepts an extension that has a lang_<ext>.py",
              analyze.covers([question("new-thing-role", member, "Classify it.")]) == [])

        (hooks / "lang_xyz.py").write_text("def answers(questions, files, ctx):\n    raise RuntimeError('broken fix')\n")
        plan_codec._optional.clear()
        sys.modules.pop("lang_xyz", None)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            out = analyze.solve_set(qs, {member: body.encode()}, {})
        check("hooks: a lang_<ext>.py that raises costs nothing generic can answer",
              out.get("xyz-launcher-adapter") == "mshta.exe" and "lang_xyz raised" in err.getvalue())

        (hooks / "hooks_abc.py").write_text("this is not python\n")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            got = plan_codec.recover(body, ".abc"), plan_codec.hooks(".abc")
        check("hooks: a hook file that does not import is reported once and read as absent",
              got[1] == ([], []) and err.getvalue().count("hooks_abc.py did not load") == 1, err.getvalue()[:200])

        (hooks / "census.py").write_text(
            "import labels\n"
            "def census(text, ext):\n"
            "    return {'klass': 'loop', 'keyword': 'while', 'inner': None}\n"
            "def answer(q, text, ext):\n"
            "    return labels.pick('script.control/' + ext.lstrip('.') + '.while', ['while_once', 'while_loop'])\n")
        (hooks / "shapes_xyz.py").unlink()
        (hooks / "lang_xyz.py").unlink()
        plan_codec._optional.clear()
        if plan_codec.optional("census") is not None and Path(plan_codec.optional("census").__file__).parent == hooks:
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                out = generic.answers(qs, {member: (body + "\n").encode()}, {})
            parsed = labels.parse(out.get("xyz-launcher-control"))
            check("hooks: census.py is asked for a control-flow question, and its reading is in the triage block",
                  parsed is not None and parsed.key == "script.control/xyz.while" and "'keyword': 'while'" in err.getvalue())
            with env(CTF_HIDE="census"), contextlib.redirect_stderr(io.StringIO()):
                out = generic.answers(qs, {member: body.encode()}, {})
            check("hooks: CTF_HIDE=census makes it absent again", "xyz-launcher-control" not in out)
            # Inside a wrapper the block's own module has parsed the script: its name leads the census options.
            v = next(v for v in corpus if v["name"].startswith("day-04"))
            vbs, vqs = next((m, q) for m, q in specimens(v) if lang_of(m) == "vbscript")
            q = next(q for q in vqs if q["qid"].endswith("-control"))
            wsf = vbs.rsplit(".", 1)[0] + ".wsf"
            wrapped = b'<job><script language="VBScript"><![CDATA[\n' + v["files"][vbs] + b"\n]]></script></job>"
            with contextlib.redirect_stderr(io.StringIO()):
                out = analyze.solve_set([{**q, "qid": "wsf-x-control", "member": wsf}], {wsf: wrapped}, {})
            parsed = labels.parse(out.get("wsf-x-control"))
            want = [v["key"][q["qid"]]] + [n for n in ("while_once", "while_loop") if n != v["key"][q["qid"]]]
            check("hooks: in a wrapper the module's name goes first among the census options, under the census key",
                  parsed is not None and parsed.key == "script.control/wsf.while" and parsed.names == want, str(parsed))
        else:
            print("NOTE the checkout has its own census.py; the stand-in census test is skipped")
    finally:
        plan_codec.HOOK_DIRS.remove(hooks)
        plan_codec._optional.clear()
        for name in ("hooks_xyz", "hooks_abc", "shapes_xyz", "lang_xyz", "census"):
            mod = sys.modules.get(name)
            if mod is not None and Path(getattr(mod, "__file__", "") or "").parent == hooks:
                sys.modules.pop(name, None)


def test_default_branch(corpus):
    """A control form no pattern names is unsure, never `direct` by default."""
    v = next(v for v in corpus if v["name"].startswith("day-04"))
    member, text = next((m, v["files"][m].decode()) for m, qs in specimens(v)
                        if lang_of(m) == "batch" and v["key"][next(q["qid"] for q in qs if q["qid"].endswith("-control"))] == "direct")
    plain = shapes_text.shapes("batch", text)
    lines = text.split("\n")
    at = next(i for i, ln in enumerate(lines) if ln.strip().lower().startswith("echo(") and i > 8)
    odd = "\n".join(lines[:at] + ["choice /c yn /n >nul"] + lines[at:])
    parsed = labels.parse(shapes_text.shapes("batch", odd).get("control"))
    check("default branch: an explicit Batch pattern is plain; an unknown line between fragments and echo is unsure, "
          "under the key of that line's construct",
          plain.get("control") == "direct" and parsed is not None and parsed.key == "script.control/batch.unread_choice_c"
          and "direct" in parsed.names and "goto_dispatch" in parsed.names and len(parsed.names) <= 12, str(parsed))
    check("default branch: read() says which answers the default branch gave; shapes() is its first half",
          shapes_text.read("batch", odd) == (shapes_text.shapes("batch", odd), {"control"})
          and shapes_text.read("batch", text) == (plain, set()) and shapes_text.read("python", text) == ({}, set())
          and "unread" not in shapes_text.shapes("batch", odd))
    parsed = labels.parse(shapes_text.shapes("vbscript", "Function A()\nEnd Function\n").get("control"))
    check("default branch: VBScript with no decoder call is unsure under script.control/vbs.unknown",
          parsed is not None and parsed.key == "script.control/vbs.unknown", str(parsed))
    check("default branch: JScript styles without their pattern are absent", shapes_text.shapes("jscript", "var a = 1;") == {})


def test_wrapped(corpus):
    """A .wsf or .hta around a known language: the plan as usual, the module's names held unsure."""
    v = next(v for v in corpus if v["name"].startswith("day-04"))
    bad, seen = [], Counter()
    for member, qs in specimens(v):
        lang = lang_of(member)
        if lang == "vbscript":
            new = member.rsplit(".", 1)[0] + ".wsf"
            body = b'<?xml version="1.0"?>\n<job id="fixture">\n<script language="VBScript"><![CDATA[\n' + v["files"][member] \
                + b"\n]]></script>\n</job>\n"
            prefix, techniques = "wsf", ["T1059.005", "T1059.007"]
        elif lang == "jscript":
            new = member.rsplit(".", 1)[0] + ".hta"
            body = b'<html><head><hta:application id="fixture"/>\n<script language="JScript">\n' + v["files"][member] \
                + b"\n</script></head><body></body></html>\n"
            prefix, techniques = "hta", ["T1218.005", "T1059.005", "T1059.007"]
        else:
            continue
        new_qs = [{**q, "qid": prefix + q["qid"][len(lang):], "member": new} for q in qs]
        with env(CTF_HIDE="census"), contextlib.redirect_stderr(io.StringIO()):
            out = analyze.solve_set(new_qs, {new: body}, {})
        for q, nq in zip(qs, new_qs):
            a, k, tail = out.get(nq["qid"]), v["key"][q["qid"]], generic.tail_of(q)
            parsed = labels.parse(a) if a is not None else None
            if tail == "attack" and k.startswith("T1059"):
                # The container's own candidates first, then the other interpreters.
                ok = parsed is not None and parsed.key == f"script.attack/{prefix}" and parsed.names[:len(techniques)] == techniques \
                    and parsed.names == generic.techniques(prefix) and k in parsed.names
                seen["attack unsure"] += ok
            elif tail == "control":
                ok = parsed is not None and parsed.key.startswith(f"script.control/{prefix}.") and parsed.names == [k]
                seen["control unsure"] += ok
            elif tail in ("representation", "transform"):
                # Day 13 preparation: the codec label's words were judged for .vbs, not for the container.
                # Unsure under the container's own key, the VBScript module's (judged) name first, and no
                # option is the method's name `label` itself.
                ok = parsed is not None and parsed.key == f"script.{tail}/{prefix}.codec_label" \
                    and parsed.options[0][1] == k and all(v != "label" for _n, v in parsed.options)
                seen["codec unsure"] += ok
            else:
                ok = a == k
                seen["plain"] += ok
            if not ok:
                bad.append(f"{nq['qid']}: {a!r} (key {k!r})")
    check(f"wrapped: 9 VBScript in .wsf and 9 JScript in .hta: {seen['plain']} plain and right, "
          f"{seen['attack unsure']} own-interpreter techniques unsure, {seen['control unsure']} control names held unsure, "
          f"{seen['codec unsure']} codec label words held unsure",
          not bad and seen["plain"] == 111 and seen["attack unsure"] == 6 and seen["control unsure"] == 9
          and seen["codec unsure"] == 18, "; ".join(bad[:5]))
    check("wrapped: unwrap reads the language attribute and the CDATA body",
          analyze.unwrap('<job><script language="VBScript"><![CDATA[x = 1]]></script></job>') == ("x = 1", "vbscript")
          and analyze.unwrap('<script language="VBScript">a = "b" &amp; "c"</script>', ".wsf") == ('a = "b" & "c"', "vbscript")
          and analyze.unwrap('<script language="VBScript">a = "b" &amp; "c"</script>', ".hta")[0] == 'a = "b" &amp; "c"'
          and analyze.unwrap('<script type="text/javascript">var a;</script>') == ("var a;", "jscript")
          and analyze.unwrap("<html></html>") == (None, None)
          and analyze.unwrap('<script language="Python">pass</script>') == ("pass", None))
    # Several blocks: an include and a helper come before the specimen.
    v = next(v for v in corpus if v["name"].startswith("day-04"))
    vbs, vqs = next((m, q) for m, q in specimens(v) if lang_of(m) == "vbscript")
    wsf = vbs.rsplit(".", 1)[0] + ".wsf"
    body = b'<job>\n<script language="VBScript" src="lib.vbs"/>\n<script language="VBScript" src="more.vbs"></script>\n' \
        b'<script language="JScript">var helper = 1;</script>\n<script language="VBScript"><![CDATA[\n' + v["files"][vbs] \
        + b"\n]]></script>\n</job>\n"
    new_qs = [{**q, "qid": "wsf" + q["qid"][len("vbscript"):], "member": wsf} for q in vqs]
    with env(CTF_HIDE="census"), contextlib.redirect_stderr(io.StringIO()):
        out = analyze.solve_set(new_qs, {wsf: body}, {})
    control = next(q for q in vqs if q["qid"].endswith("-control"))
    parsed = labels.parse(out.get("wsf" + control["qid"][len("vbscript"):]))
    blocks = analyze.script_blocks(body.decode(), ".wsf")
    check("wrapped: an include and a helper block before the specimen: the block that carries the plan is read",
          [m for _, m in blocks] == ["jscript", "vbscript"] and analyze.unwrap(body.decode(), ".wsf")[1] == "vbscript"
          and parsed is not None and parsed.names == [v["key"][control["qid"]]], f"{[m for _, m in blocks]} {parsed}")
    t = time.perf_counter()
    analyze.unwrap("<script " * 20000, ".hta")
    check("wrapped: 20,000 unclosed script tags are read in well under a second", time.perf_counter() - t < 0.5)
    t = time.perf_counter()
    none = plan_codec.decode("\n" * 20000 + (" " * 50 + "\n") * 5000 + "set x=1\n")
    check("plan codec: a file of blank lines costs the fragment reader no time", none is None and time.perf_counter() - t < 0.5)


def test_covers(corpus):
    """The contract check before a clock."""
    timed = next(v for v in corpus if v["name"].startswith("day-04") and "/time_trial#" in v["name"] and "history" not in v["name"])
    bare = [{k: q[k] for k in ("id", "question", "artifact") if k in q} for q in timed["qs"]]
    check("covers: the Day 4 timed contract (ids and artifacts only) has no problem", analyze.covers(bare) == [])
    mastery = [v for v in corpus if v["name"].startswith("day-04") and "/mastery#" in v["name"]]
    raw = json.loads((mastery[0]["dir"] / "attempt.json").read_text())["questions"]
    check("covers: the Day 4 Mastery contract (setN. ids) has no problem", analyze.covers(raw) == [] and len(raw) == 462)

    member = "local-dispatch.hta"
    qs = new_language_questions("hta", member)
    problems = analyze.covers(qs)
    check("covers: a new extension whose component nobody has seen is one problem per question",
          len(problems) == len(qs) and "no module for .hta" in problems[0] and "hta" in problems[0], str(problems[:1]))
    base = SCRATCH / "challenges" / "day-05" / "script-analysis-day-05-synthetic"
    base.mkdir(parents=True)
    (base / "attempt.json").write_text(json.dumps({"answer_ids": [q["id"] for q in qs], "questions": []}))
    check("covers: the same ids pass once today's base attempt has asked that component", analyze.covers(qs) == [])
    (base / "attempt.json").unlink()

    good = {member: f"m = '{hex_colon(PLAN, 0x5a)}'".encode()}
    check("covers: with files, a recoverable plan is a route", analyze.covers(qs, good) == [])
    problems = analyze.covers(qs, {member: b"<html>nothing encoded here</html>"})
    check("covers: with files, a member without a recoverable plan is a problem",
          len(problems) == len(qs) and "no plan is recovered" in problems[0], str(problems[:1]))
    with env(CTF_HIDE="generic"):
        problems = analyze.covers(qs, good)
    check("covers: without generic there is no route", len(problems) == len(qs))
    with env(CTF_HIDE="vbscript"):
        problems = analyze.covers(bare)
        (base / "attempt.json").write_text(json.dumps({"answer_ids": [q["id"] for q in bare]}))
        on_base = analyze.covers(bare)
        (base / "attempt.json").unlink()
    check("covers: a language whose module is missing is a problem by ids, unless today's base asked it",
          len(problems) == 72 and all(p.startswith("vbscript-") for p in problems) and on_base == [], str(problems[:1]))


def test_one_plan(corpus):
    """decode() gives the ONE plan of a file: the longest of cut copies, nothing when two plans differ."""
    same, total, noted = 0, 0, []
    for v in corpus:
        for member, _ in specimens(v):
            text = plan_codec.text_of(v["files"][member])
            got, note = plan_codec.reading(text, Path(member).suffix.lower())
            total += 1
            same += got is not None and got == plan_codec.recover(text) == plan_codec.decode(text)
            if note:
                noted.append(f"{v['name']} {member}: {note}")
    check(f"one plan: decode equals recover on {same} of {total} saved specimens, none read as two plans",
          same == total and total >= 372 and not noted, "; ".join(noted[:3]))

    # The k=v grammar has no end mark: the first of two number arrays passes it as a cut plan.
    raw = PLAN.encode()
    at = PLAN.index("|stage_count") + 9
    body = (f"var a = [{', '.join(str(b) for b in raw[:at])}];\nvar b = [{', '.join(str(b) for b in raw[at:])}];\n"
            "run(a.concat(b));\n")
    first, whole = plan_codec.recover(body), plan_codec.decode(body)
    check("one plan: of candidates that are a prefix of one another the longest is the plan (recover alone takes the cut one)",
          first is not None and first[0] == PLAN[:at] and whole is not None and whole[0] == PLAN, f"{first} / {whole}")

    # Two plans with different values for one key: no established fact, so no answer at all.
    member = "local-dispatch.xyz"
    qs = new_language_questions("xyz", member)
    decoy = PLAN.replace("mshta.exe", "rundll32.exe").replace("campaign-0123456789", "campaign-9999999999-decoy")
    body = f"decoy = '{hex_colon(decoy, 0x11)}'\nmaterial = '{hex_colon(PLAN, 0x5a)}'\nrun(decode(material))\n"
    err = io.StringIO()
    with env(CTF_HIDE="census"), contextlib.redirect_stderr(err):
        out = analyze.solve_set(qs, {member: body.encode()}, {})
    check("one plan: a file that decodes to two different plans is answered by neither, and the triage block says why",
          out == {} and plan_codec.decode(body) is None and plan_codec.recover(body) is not None
          and "two different plans decode" in err.getvalue() and "NO PLAN RECOVERED" in err.getvalue(), f"{out} {err.getvalue()[:300]}")
    same_twice = f"copy = '{hex_colon(PLAN, 0x11)}'\nmaterial = '{hex_colon(PLAN, 0x5a)}'\n"
    blob = "settings = '" + __import__("base64").b64encode(json.dumps({"adapter": "other.exe", "pad": "x" * 400}).encode()).decode() + "'\n"
    check("one plan: the same plan stored twice, and a JSON blob without steps beside the plan, are still one plan",
          (plan_codec.decode(same_twice) or [None])[0] == PLAN
          and (plan_codec.decode(blob + f"material = '{hex_colon(PLAN, 0x5a)}'\n") or [None])[0] == PLAN)

    # The same net under a known language: a module that raises is not replaced by a coin toss.
    v = next(v for v in corpus if v["name"].startswith("day-04"))
    vbs, vqs = next((m, q) for m, q in specimens(v) if lang_of(m) == "vbscript")
    real = plan_codec.decode(plan_codec.text_of(v["files"][vbs]))[0]
    other = real.replace("campaign_id=campaign-", "campaign_id=campaign-decoy-")
    two = v["files"][vbs] + f"\n' note \"{hex_colon(other, 0x11)}\"\n".encode()
    import vbscript
    original = vbscript.analyze

    def boom(*a, **k):
        raise RuntimeError("simulated failure")
    vbscript.analyze = boom
    err = io.StringIO()
    try:
        with contextlib.redirect_stderr(err):
            out = analyze.solve_set(vqs, {**v["files"], vbs: two}, {})
    finally:
        vbscript.analyze = original
    plan_fields = [q["qid"] for q in vqs if generic.tail_of(q) not in analyze.SHAPE_FIELDS["vbscript"]]
    check("one plan: with the module down and two plans in the text, the text path fills no plan answer",
          other != real and not any(i in out for i in plan_fields) and "two different plans decode" in err.getvalue(),
          str({i: out[i] for i in plan_fields if i in out})[:300])

    # Two codec labels that name different codecs: the name is not established either.
    body = (f"# HUNTRESS-CODEC:base64_literal|identity\n# HUNTRESS-CODEC:hex_colon|single_byte_xor|5a\n"
            f"material = '{hex_colon(PLAN, 0x5a)}'\n")
    err = io.StringIO()
    with env(CTF_HIDE="census"), contextlib.redirect_stderr(err):
        out = generic.answers(qs, {member: body.encode()}, {})
    rep, tr = labels.parse(out.get("xyz-launcher-representation")), labels.parse(out.get("xyz-launcher-transform"))
    check("labels: two labels that differ give no plain codec name (the decode's candidates, unsure), and a note",
          rep is not None and rep.names == ["hex_colon", "reversed_hex"] and tr is not None
          and plan_codec.label_of(body) is None and "2 codec labels that differ" in err.getvalue()
          and plan_codec.label_of(body.replace("base64_literal|identity", "hex_colon|single_byte_xor|5a"))
          == ["hex_colon", "single_byte_xor", "5a"], f"{rep} {tr}")


def test_question_enum():
    """A question that lists its accepted values has said what a right answer looks like."""
    member = "local-dispatch.xyz"
    body = f"# HUNTRESS-CODEC:hex_colon|single_byte_xor|5a\nmaterial = '{hex_colon(PLAN, 0x5a)}'\n"
    qs = new_language_questions("xyz", member)
    by_tail = {generic.tail_of(q): q for q in qs}
    by_tail["role"]["answer_format"] = "enum"                                    # not a table: must not cost the answer
    by_tail["adapter"]["answer_format"] = {"kind": "enum", "accepted_values": ["rundll32.exe", "wscript.exe"]}
    by_tail["representation"]["answer_format"] = {"kind": "enum", "accepted_values": ["hex_pairs", "base64_literal"]}
    by_tail["transform"]["answer_format"] = {"kind": "enum", "accepted_values": ["single_byte_xor", "identity"]}
    by_tail["attack"]["answer_format"] = {"kind": "enum", "accepted_values": ["T1059.006", "T1059.004", "none"]}
    err = io.StringIO()
    with env(CTF_HIDE="census"), contextlib.redirect_stderr(err):
        out = analyze.solve_set(qs, {member: body.encode()}, {})
    attack = labels.parse(out.get("xyz-launcher-attack"))
    check("enum: a plain answer the question's own list excludes is None, with a note; a listed one stands",
          "xyz-launcher-adapter" not in out and "xyz-launcher-representation" not in out
          and labelled(out.get("xyz-launcher-transform"), "xyz", "transform", "single_byte_xor")
          and [v for _n, v in labels.parse(out["xyz-launcher-transform"]).options] == ["single_byte_xor"]
          and out.get("xyz-launcher-campaign") == "campaign-0123456789"
          and "xyz-launcher-adapter: mshta.exe is not among the values the question lists" in err.getvalue(),
          str(out)[:300])
    check("enum: an unsure answer keeps only the options the question lists",
          attack is not None and attack.key == "script.attack/xyz" and attack.names == ["T1059.006", "T1059.004"], str(attack))
    check("enum: an answer format that is not a table does not cost the role", out.get("xyz-launcher-role") == "launcher")
    q = question("x", member, "?", answer_format={"kind": "enum", "accepted_values": ["a", "b"]})
    check("enum: listed() passes what it cannot judge and drops an unsure answer with nothing left",
          generic.listed(question("x", member, "?"), "zzz") == "zzz" and generic.listed(q, ["zzz"]) == ["zzz"]
          and generic.listed(q, "a") == "a" and generic.listed(q, "zzz") is None
          and generic.listed(q, labels.unsure("script.control/xyz.for", ["for_once", "for_loop"])) is None
          and generic.listed(q, "??not json") is None)


def test_hook_order():
    """shapes_<ext>.py and census.py are asked question by question, not file instead of file."""
    hooks = SCRATCH / "hooks_order"
    hooks.mkdir()
    member = "local-dispatch.xyz"
    body = f"# HUNTRESS-CODEC:hex_colon|single_byte_xor|5a\nmaterial = '{hex_colon(PLAN, 0x5a)}'\n"
    qs = new_language_questions("xyz", member) + [question("xyz-launcher-expansion", member, "Identify the expansion form.")]
    (hooks / "census.py").write_text(
        "import labels\n"
        "def census(text, ext):\n"
        "    return {'klass': 'loop', 'keyword': 'while', 'inner': None}\n"
        "def answer(q, text, ext):\n"
        "    return labels.pick('script.control/' + ext.lstrip('.') + '.while', ['while_once', 'while_loop'])\n")
    saved = list(plan_codec.HOOK_DIRS)
    plan_codec.HOOK_DIRS[:] = [hooks]          # the stand-in census, also in a checkout that has the real one
    plan_codec._optional.clear()
    try:
        for label, source in (
                ("answers another field", "def shapes(text, questions):\n"
                                          "    return {q['qid']: 'delayed' for q in questions if q['qid'].endswith('-expansion')}\n"),
                ("raises", "def shapes(text, questions):\n    raise RuntimeError('broken fix')\n"),
                ("returns no table", "def shapes(text, questions):\n    return ['not', 'a', 'table']\n")):
            (hooks / "shapes_xyz.py").write_text(source)
            plan_codec._optional.clear()
            sys.modules.pop("shapes_xyz", None)     # a rewritten file is a new module only in a new process
            with contextlib.redirect_stderr(io.StringIO()):
                out = generic.answers(qs, {member: body.encode()}, {})
            parsed = labels.parse(out.get("xyz-launcher-control"))
            check(f"hook order: a shapes_<ext>.py that {label} leaves the control question to census.py",
                  parsed is not None and parsed.key == "script.control/xyz.while" and out.get("xyz-launcher-role") == "launcher"
                  and (out.get("xyz-launcher-expansion") == "delayed") == (label == "answers another field"), str(out)[:300])
        (hooks / "shapes_xyz.py").write_text("def shapes(text, questions):\n"
                                             "    return {q['qid']: 'from_shapes' for q in questions}\n")
        plan_codec._optional.clear()
        sys.modules.pop("shapes_xyz", None)
        with contextlib.redirect_stderr(io.StringIO()):
            out = generic.answers(qs, {member: body.encode()}, {})
        check("hook order: what shapes_<ext>.py answers is not asked of census.py",
              out.get("xyz-launcher-control") == "from_shapes"
              and labelled(out.get("xyz-launcher-representation"), "xyz", "representation", "hex_colon"))
    finally:
        plan_codec.HOOK_DIRS[:] = saved
        plan_codec._optional.clear()
        for name in ("shapes_xyz", "census"):
            mod = sys.modules.get(name)
            if mod is not None and Path(getattr(mod, "__file__", "") or "").parent == hooks:
                sys.modules.pop(name, None)


def test_partial_before_text_path(corpus):
    """A time limit that falls inside the text path keeps the answers the module already gave."""
    class Stop(BaseException):      # how the runner's time limit arrives: not an Exception
        pass

    def stop(*a, **k):
        raise Stop()

    v = next(v for v in corpus if v["name"].startswith("day-04"))
    member, qs = next((m, q) for m, q in specimens(v) if lang_of(m) in LANGS)
    want, _ = solve(v, questions=qs)
    ctx, stopped = {"set": v["set"], "partial": {}}, False
    original = plan_codec.reading
    plan_codec.reading = stop
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            analyze.solve_set(qs, v["files"], ctx)
    except Stop:
        stopped = True
    finally:
        plan_codec.reading = original
    check("partial: the module's answers are in ctx['partial'] before the text path starts",
          stopped and analyze.plan_codec is plan_codec and len(want) == len(qs) and ctx["partial"] == want,
          f"stopped={stopped} partial={len(ctx['partial'])} of {len(want)}")


def test_own_generic(corpus):
    """solvers/binary has a generic.py too: analyze.py must use the one beside it, in any import order."""
    import subprocess
    v = next(v for v in corpus if v["name"].startswith("day-04"))
    member, qs = next((m, q) for m, q in specimens(v) if lang_of(m) == "vbscript")
    want, _ = solve(v, questions=qs)
    new = "local-dispatch.xyz"
    new_qs = new_language_questions("xyz", new)
    work = SCRATCH / "own_generic"
    (work / "other").mkdir(parents=True)
    (work / "other" / "generic.py").write_text("MARK = 'another lane'\n\ndef answers(questions, files, ctx):\n    return {}\n")
    (work / "specimen.bin").write_bytes(v["files"][member])
    (work / "new.bin").write_text(f"# HUNTRESS-CODEC:hex_colon|single_byte_xor|5a\nmaterial = '{hex_colon(PLAN, 0x5a)}'\n")
    (work / "questions.json").write_text(json.dumps({"known": qs, "new": new_qs, "member": member, "new_member": new}))
    code = (
        "import importlib.util, json, sys\n"
        "work, here = sys.argv[1], sys.argv[2]\n"
        "sys.path.insert(0, here)\n"
        "sys.path.insert(0, work + '/other')            # another lane's folder is ahead on the import path\n"
        "if sys.argv[3] == 'loaded':\n"
        "    import generic                             # and its generic is already loaded\n"
        "    assert generic.MARK == 'another lane'\n"
        "spec = importlib.util.spec_from_file_location('solver_under_run', here + '/analyze.py')\n"
        "analyze = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(analyze)\n"
        "q = json.load(open(work + '/questions.json'))\n"
        "out = analyze.solve_set(q['known'], {q['member']: open(work + '/specimen.bin', 'rb').read()}, {})\n"
        "out.update(analyze.solve_set(q['new'], {q['new_member']: open(work + '/new.bin', 'rb').read()}, {}))\n"
        "other = sys.modules.get('generic')\n"
        "print(json.dumps({'out': out, 'other_kept': getattr(other, 'MARK', None) == 'another lane' if sys.argv[3] == 'loaded' else True}))\n")
    for order in ("loaded", "on the path"):
        p = subprocess.run([sys.executable, "-c", code, str(work), str(HERE), order], capture_output=True, text=True, timeout=120,
                           env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "CTF_HIDE": "census"})
        try:
            got = json.loads(p.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            got = {"out": {}, "other_kept": False}
        out = got["out"]
        check(f"own generic: with another lane's generic.py {order}, a known specimen and a new language answer as usual",
              p.returncode == 0 and all(out.get(k) == a for k, a in want.items()) and len(want) == len(qs)
              and out.get("xyz-launcher-role") == "launcher"
              and labelled(out.get("xyz-launcher-representation"), "xyz", "representation", "hex_colon")
              and got["other_kept"], (p.stderr or p.stdout)[-400:])


# ---------------------------------------------------------------- the review's fix wave (findings 9, 10, 11)

# The line that calls the recovery subroutine, with or without its FOR /L wrapper.
CALL_GATE = re.compile(r"(?mi)^(?:for /l %%\w in \([^)\r\n]*\) do )?call :(\w+)[ \t]*\r?$")
PLAN_TAILS = ("role", "attack", "adapter", "campaign", "graph")


def batch_specimens(v):
    """[(member, questions, text, the control form in the key)] of the Batch specimens of one set."""
    out = []
    for member, qs in specimens(v):
        if lang_of(member) == "batch":
            out.append((member, qs, v["files"][member].decode("utf-8"), v["key"][field_id(qs, "control")]))
    return out


def field_id(qs, tail):
    return next(q["qid"] for q in qs if generic.tail_of(q) == tail)


def qs_ids(qs):
    return [q["qid"] for q in qs]


def solve_text(v, member, qs, text):
    """(answers, stderr text) of analyze.solve_set on one specimen whose text is replaced by `text`."""
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        out = analyze.solve_set(qs, {**v["files"], member: text.encode("utf-8")}, {"set": v["set"]})
    return out, err.getvalue()


def module_alone(member, qs, text):
    """What batch.py itself answers on `text`: the ids it declines are left out."""
    import batch
    with contextlib.redirect_stderr(io.StringIO()):
        return analyze.clean(batch.answers(qs, {member: text.encode("utf-8")}, {}))


def text_alone(member, qs, text):
    with contextlib.redirect_stderr(io.StringIO()):
        return analyze.text_answers("batch", qs, text, Path(member).suffix.lower())


def join_at(lines):
    """Index of the line that joins the numbered fragments, found as shapes_text.bat_shapes finds it."""
    names = [m.group(1) for m in (shapes_text.FRAGMENT_RE.match(ln.strip()) for ln in lines) if m]
    prefix = max(set(names), key=names.count)
    return next(i for i, ln in enumerate(lines)
                if re.search(r'(?i)\bset\s+"?\w+=.*[%!]' + re.escape(prefix) + r'(\d|%%)', ln))


def gated(text, gate, before=None):
    """`text` with `gate` written in front of its join, and the line `before` put ahead of that."""
    lines = text.split("\n")
    at = join_at(lines)
    lines[at] = gate + lines[at].strip()
    if before:
        lines.insert(at, before)
    return "\n".join(lines)


def without_material(text):
    """`text` without its MATERIAL comment: nothing independent then confirms the walk's plan."""
    return "\n".join(ln for ln in text.split("\n") if "HUNTRESS-MATERIAL" not in ln)


@contextlib.contextmanager
def scratch_ledger():
    """What labels.learn records inside the block is forgotten after it (the ledger is this
    test's own scratch file, and the tests that follow expect the seed alone)."""
    path = labels.ledger_path("script")
    had = path.read_bytes() if path.exists() else None
    try:
        yield
    finally:
        if had is None:
            path.unlink(missing_ok=True)
        else:
            path.write_bytes(had)


def test_declined(corpus):
    """An answer the module declines is never filled with the text path's own plain reading."""
    v = next(v for v in corpus if v["name"].startswith("day-04"))
    family = labels.family("script.control/batch.")
    member, qs, text, _ = next(s for s in batch_specimens(v) if s[3] == "call_subroutine" and CALL_GATE.search(s[2]))
    label, control = CALL_GATE.search(text).group(1), field_id(qs, "control")

    # Two wrappers at once: the judge has named neither pair, and the text reader takes one by precedence.
    two = {"an errorlevel guard in front of the CALL": (f"ver >nul\nif errorlevel 1 exit /b 1\ncall :{label}", "call_subroutine"),
           "IF DEFINED around the CALL": (f'set "HUNTRESS_READY=1"\nif defined HUNTRESS_READY call :{label}', "if_guard")}
    for what, (lines, reading) in two.items():
        odd = CALL_GATE.sub(lambda m: lines, text, count=1)
        mod = module_alone(member, qs, odd)
        out, err = solve_text(v, member, qs, odd)
        parsed = labels.parse(out.get(control))
        check(f"declined: {what}: batch.py gives no control form and the text path's {reading} goes out unsure, never plain",
              odd != text and sorted(set(qs_ids(qs)) - set(mod)) == [control] and text_alone(member, qs, odd).get(control) == reading
              and parsed is not None and parsed.key == f"script.control/batch.declined.{reading}"
              and parsed.names[0] == reading and sorted(parsed.names) == sorted(family) and len(family) == 5
              and all(out.get(i) == a for i, a in mod.items())
              and f"{control}: filled from the text path (batch gave no answer), unsure" in err,
              f"module={mod.get(control)!r} answer={out.get(control)!r}")
    with scratch_ledger():
        odd = CALL_GATE.sub(lambda m: two["an errorlevel guard in front of the CALL"][0], text, count=1)
        labels.learn("script.control/batch.declined.call_subroutine", "errorlevel_guard", "accepted", scope="key",
                     attempt_id="test-generic", answer_ids=[control], left=3.0)
        out, _ = solve_text(v, member, qs, odd)
        check("declined: once the judge has accepted a name for that key, the replay answers it plain (what the gates need)",
              out.get(control) == "errorlevel_guard", repr(out.get(control)))
    out, _ = solve_text(v, member, qs, CALL_GATE.sub(lambda m: two["an errorlevel guard in front of the CALL"][0], text, count=1))
    check("declined: and without that verdict it is unsure again", labels.is_unsure(out.get(control)), repr(out.get(control)))

    # A join the judge has not named: one-letter fragments joined by FOR without CALL.
    member, qs, text, _ = next(s for s in batch_specimens(v) if shapes_text.FOR_JOIN_RE.search(s[2]))
    lines = text.split("\n")
    at = join_at(lines)
    m = re.search(r'(?i)for %%(\w) in \(([^)]*)\) do call set "(\w+)=%%\3%%%%(\w+)%%\1%%"', lines[at])
    odd, expansion = None, field_id(qs, "expansion")
    if m:
        letter, numbers, var, prefix = m.groups()
        lines[at] = f'for %%{letter} in ({numbers}) do set "{var}=!{var}!!h%%{letter}!"'
        odd = "\n".join(lines).replace(prefix, "h") if prefix != "h" else "\n".join(lines)
    mod = module_alone(member, qs, odd) if odd else {}
    out, err = solve_text(v, member, qs, odd) if odd else ({}, "")
    parsed = labels.parse(out.get(expansion))
    check("declined: a FOR join of one-letter fragments without CALL: no expansion from batch.py, and the text path's "
          "`delayed` goes out unsure",
          odd is not None and sorted(set(qs_ids(qs)) - set(mod)) == [expansion] and text_alone(member, qs, odd).get(expansion) == "delayed"
          and parsed is not None and parsed.key == "script.expansion/batch.declined.delayed" and parsed.names == ["delayed"]
          and all(out.get(i) == a for i, a in mod.items()), f"module={mod.get(expansion)!r} answer={out.get(expansion)!r}")

    # Plan values: a value that would hold this machine's %USERNAME%, and trailing blanks that give two plans.
    found = None
    for member, qs, text, _ in batch_specimens(v):
        bare = without_material(text).split("\n")
        for q in qs:
            value = v["key"][q["qid"]]
            if generic.tail_of(q) in PLAN_TAILS + analyze.SHAPE_FIELDS["batch"] or not isinstance(value, str):
                continue
            hits = [i for i, ln in enumerate(bare) if shapes_text.FRAGMENT_RE.match(ln.strip()) and value in ln]
            if len(hits) == 1 and found is None:
                bare[hits[0]] = bare[hits[0]].replace(value, "%USERNAME%" + value)
                found = (member, qs, "\n".join(bare), q["qid"])
    member, qs, odd, qid = found or (None, [], "", None)
    mod = module_alone(member, qs, odd) if found else {}
    out, err = solve_text(v, member, qs, odd) if found else ({}, "")
    check("declined: a plan value that would hold this machine's %USERNAME% stays None (the text path reads it plain)",
          found is not None and qid not in mod and len(mod) == len(qs) - 1 and analyze.plain(text_alone(member, qs, odd).get(qid))
          and qid not in out and all(out.get(i) == a for i, a in mod.items())
          and f"{qid}: batch declined it; the text path's plain answer" in err, f"answer={out.get(qid)!r}")

    found = None
    for member, qs, text, _ in batch_specimens(v):
        bare = without_material(text)
        m = re.search(r'(?m)^set \w+?0=[^\r\n"]*[^ \t\r\n]$', bare)      # an unquoted first fragment: a blank after it may be data
        if m and found is None:
            found = (member, qs, bare[:m.end()] + " " + bare[m.end():])
    member, qs, odd = found or (None, [], "")
    mod = module_alone(member, qs, odd) if found else {}
    out, err = solve_text(v, member, qs, odd) if found else ({}, "")
    declined = [i for i in qs_ids(qs) if i not in mod]
    reads = text_alone(member, qs, odd) if found else {}
    check(f"declined: trailing blanks that give two plans: the {len(declined)} plan values batch.py leaves open stay None "
          f"(the text path reads {sum(analyze.plain(reads.get(i)) for i in declined)} of them plain)",
          found is not None and len(declined) >= 5 and mod and all(analyze.plain(reads.get(i)) for i in declined)
          and not any(i in out for i in declined) and all(out.get(i) == a for i, a in mod.items())
          and err.count("batch declined it; the text path's plain answer") == len(declined), str({i: out.get(i) for i in declined})[:300])

    # What must not change: a module that broke is still filled in full, and plain.
    import batch
    member, qs, text, _ = next(s for s in batch_specimens(v) if s[3] == "call_subroutine")
    want, _ = solve_text(v, member, qs, text)
    original = batch.Cmd.run

    def boom(self, *a, **k):
        raise RuntimeError("simulated walker failure")
    batch.Cmd.run = boom
    try:
        out, err = solve_text(v, member, qs, text)
    finally:
        batch.Cmd.run = original
    check("declined: a walk that fails is not a decline: both shape answers are still filled from the text path, plain",
          out == want and len(want) == len(qs) and err.count("filled from the text path (batch gave no answer)") == 2
          and not any(labels.is_unsure(a) for a in out.values()), str({i: out.get(i) for i in want if out.get(i) != want[i]}))


def test_unread_key(corpus):
    """The default branch is keyed by the construct that was not read: one accepted name answers
    that construct again, and no other."""
    check("unread key: the construct of a line is its command words, without NOT, switches included, two at most",
          [shapes_text.bat_construct(s) for s in ('if exist "%~f0" echo x', 'if not exist "%temp%\\x" echo x', 'pushd "%~dp0"',
                                                  '@(for %%z in (1 2) do echo x', 'choice /c yn /n >nul', '>nul ver',
                                                  'a' * 80 + ' x', 'if /i "%os%"=="windows_nt" echo x')]
          == ["if_exist", "if_exist", "pushd", "for", "choice_c", "", "", "if_i"])
    check("unread key: an operand is never part of the construct, even when it reads like a word (it is the specimen's own text)",
          [shapes_text.bat_construct(s) for s in ("echo hello", "title x", "setlocal enabledelayedexpansion", "if x equ y echo z",
                                                  "start notepad", "if not defined x echo y", "for /f %%a in (x) do echo y",
                                                  'cd /d "%~dp0"', "if not errorlevel 1 echo y", "echo not hello", "type plan")]
          == ["echo", "title", "setlocal", "if", "start", "if_defined", "for_f", "cd_d", "if_errorlevel", "echo", "type"])
    v = next(v for v in corpus if v["name"].startswith("day-04"))
    direct = [s for s in batch_specimens(v) if s[3] == "direct"]
    looped = next((s for s in direct if shapes_text.FOR_JOIN_RE.search(s[2])), None)     # a second FOR in front is then not an assignment
    others = [s for s in direct if s is not looped]
    if looped is None or len(others) < 2:
        check("unread key: the Day 4 base has three Batch specimens keyed `direct`, one of them with a FOR join", False,
              f"{len(direct)} direct specimens")
        return
    cases = {"if exist": (others[0], 'if exist "%~f0" '), "if not exist": (others[1], 'if not exist "%TEMP%\\x" '),
             "for": (looped, "for %%Z in (1 2) do ")}

    def control(name):
        (member, qs, text, _), gate = cases[name]
        odd = gated(text, gate)
        out, err = solve_text(v, member, qs, odd)
        return out.get(field_id(qs, "control")), module_alone(member, qs, odd).get(field_id(qs, "control")), err

    before = {name: control(name) for name in cases}
    parsed = {name: labels.parse(a) for name, (a, _, _) in before.items()}
    names = labels.family("script.control/")
    check("unread key: a gate in front of the join that batch.py does not name is unsure, never `direct`",
          all(mod is None for _, mod, _ in before.values()) and all(p is not None for p in parsed.values())
          and all(p.names == names for p in parsed.values() if p) and 5 < len(names) <= 12, str(parsed)[:300])
    keys = {name: p.key if p else None for name, p in parsed.items()}
    check("unread key: `if exist` and `if not exist` share script.control/batch.unread_if_exist; a FOR is batch.unread_for",
          keys == {"if exist": "script.control/batch.unread_if_exist", "if not exist": "script.control/batch.unread_if_exist",
                   "for": "script.control/batch.unread_for"}, str(keys))
    with scratch_ledger():
        labels.learn("script.control/batch.unread_if_exist", "if_guard", "accepted", scope="key", attempt_id="test-generic",
                     answer_ids=[field_id(cases["if exist"][0][1], "control")], left=3.0)
        after = {name: control(name) for name in cases}
        still = labels.parse(after["for"][0])
        check("unread key: a name the judge accepts for one construct answers that construct again, plain (the gates stay open)",
              after["if exist"][0] == "if_guard" and after["if not exist"][0] == "if_guard"
              and "filled from the text path (batch gave no answer)\n" in after["if not exist"][2],
              f"{after['if exist'][0]!r} {after['if not exist'][0]!r}")
        check("unread key: and no other construct: the FOR gate is still unsure under its own key",
              still is not None and still.key == "script.control/batch.unread_for", repr(after["for"][0])[:200])
        parsed = labels.parse(shapes_text.shapes("vbscript", "Function A()\nEnd Function\n").get("control"))
        check("unread key: nor the forms with no line to name (script.control/vbs.unknown stays unsure)",
              parsed is not None and parsed.key == "script.control/vbs.unknown", str(parsed))
    check("unread key: the verdict was this test's own: without it the answer is unsure again",
          labels.is_unsure(control("if exist")[0]))

    # A gate on the join line itself is the construct that matters, whatever unread line came first.
    member, qs, text, _ = others[0]
    both = gated(text, 'if exist "%~f0" ', before='pushd "%~dp0"')
    alone = gated(text, "", before='pushd "%~dp0"')
    a = labels.parse(solve_text(v, member, qs, both)[0].get(field_id(qs, "control")))
    b = labels.parse(shapes_text.shapes("batch", alone).get("control"))
    out, err = solve_text(v, member, qs, alone)
    check("unread key: with `pushd` ahead of an `if exist` join the key is batch.unread_if_exist; `pushd` alone is "
          "batch.unread_pushd in the text reading, and batch.py's own `direct` stands",
          a is not None and a.key == "script.control/batch.unread_if_exist" and b is not None
          and b.key == "script.control/batch.unread_pushd" and out.get(field_id(qs, "control")) == "direct"
          and "paths disagree" not in err, f"{a} {b}")

    # Two variants whose unread line differs only in its operand are one construct, so one key.
    keys = {labels.parse(shapes_text.shapes("batch", gated(text, "", before=line)).get("control")).key
            for line in ("echo alpha", "echo beta", "@echo gamma delta")}
    check("unread key: `echo alpha` and `echo beta` ahead of the join share script.control/batch.unread_echo",
          keys == {"script.control/batch.unread_echo"}, str(keys))

    # The expansion is read where the join stands, also behind a gate.
    hostile = 'set "a0=x"\nset "a1=y"\nset "P=%a0%%a1%" ' + "for %%a in ( x " * 32000 + "\necho(%P%\n"
    start = time.perf_counter()
    read = shapes_text.shapes("batch", hostile)
    took = time.perf_counter() - start
    check(f"unread key: a join line with 32000 unclosed FOR lists is read once, not squared ({took:.3f} s, limit 1 s)",
          took < 1.0 and read.get("expansion") == "delayed", str(read)[:120])
    member, qs, text, _ = looped
    expansion, bad = field_id(qs, "expansion"), []
    for gate in ('if not exist "%TEMP%\\x" ', 'if /i "%OS%"=="Windows_NT" ', "for %%Z in (1 2) do "):
        odd = gated(text, gate)
        mod, out_err = module_alone(member, qs, odd).get(expansion), solve_text(v, member, qs, odd)
        if not (mod == v["key"][expansion] == text_alone(member, qs, odd).get(expansion)) or "paths disagree" in out_err[1]:
            bad.append(f"{gate!r}: module={mod!r} text={text_alone(member, qs, odd).get(expansion)!r}")
    odd = gated(text, 'if exist "%~f0" ')
    out, _ = solve_text(v, member, qs, odd)
    check(f"unread key: a FOR join behind a gate is still read as {v['key'][expansion]}: the text path equals batch.py where "
          f"it answers, and fills that name where the walk skips the join",
          not bad and v["key"][expansion] == "for_indirect" and expansion not in module_alone(member, qs, odd)
          and out.get(expansion) == "for_indirect", "; ".join(bad) or repr(out.get(expansion)))


def test_live_shapes(corpus):
    """shapes_<ext>.py is asked about a specimen of a KNOWN language too: the ids that have no
    plain answer after the module and the text path, and nothing else."""
    hooks = SCRATCH / "hooks_known"
    hooks.mkdir()
    v = next(v for v in corpus if v["name"].startswith("day-04"))
    first = {}
    for member, qs in specimens(v):
        first.setdefault(Path(member).suffix.lower().lstrip("."), (member, qs))
    exts = [e for e in ("ps1", "js", "cmd", "bat", "vbs") if e in first]
    # A field nobody has asked before, on one specimen of every known extension.
    new = {e: question(first[e][1][0]["qid"].rsplit("-", 1)[0] + "-string-style", first[e][0], "Identify the exact string style.")
           for e in exts}
    asked = v["qs"] + list(new.values())

    def install(ext, body):
        (hooks / f"shapes_{ext}.py").write_text("CALLS = []\n\n\ndef shapes(text, questions):\n"
                                                "    CALLS.append([q['qid'] for q in questions])\n" + body)
        plan_codec._optional.clear()
        sys.modules.pop(f"shapes_{ext}", None)       # a rewritten file is a new module only in a new process

    def calls(ext):
        return plan_codec.optional(f"shapes_{ext}").CALLS

    out, _ = solve(v, questions=asked)
    check("live shapes: without a shapes_<ext>.py a new field on a known language is None, and the old answers stand",
          len(exts) == 5 and not any(q["qid"] in out for q in new.values()) and all(out.get(i) == a for i, a in v["key"].items()))
    # The scratch hooks go to the FRONT of HOOK_DIRS so they win over any real shapes_<ext>.py the
    # lane now ships (wave123 reinstated shapes_js/shapes_bat/shapes_cmd/shapes_ps1): this test drives
    # the loading + dispatch mechanism with its own CALLS-recording files, so it must load those.
    plan_codec.HOOK_DIRS.insert(0, hooks)
    try:
        for e in exts:
            install(e, f"    return {{q['qid']: 'from_shapes_{e}' for q in questions if q['qid'].endswith('-string-style')}}\n")
        out, err = solve(v, questions=asked)
        check("live shapes: shapes_ps1.py, shapes_js.py, shapes_cmd.py, shapes_bat.py and shapes_vbs.py each answer the new field",
              all(out.get(new[e]["qid"]) == f"from_shapes_{e}" for e in exts)
              and all(f"{new[e]['qid']}: answered by shapes_{e}.py" in err for e in exts),
              str({e: out.get(new[e]["qid"]) for e in exts}))
        check("live shapes: each file is called once, for the one specimen with an open id, and is handed that id only",
              all(calls(e) == [[new[e]["qid"]]] for e in exts), str({e: calls(e) for e in exts}))
        check("live shapes: no answer of a module is changed by it", all(out.get(i) == a for i, a in v["key"].items()))
        out, err = solve(v)
        check("live shapes: with nothing open the files are not called: the base answers as its key, with nothing on stderr",
              out == v["key"] and len(out) == 231 and not err.strip() and all(len(calls(e)) == 1 for e in exts), err[:200])

        member, qs = first["js"]
        q = new["js"]
        want, _ = solve(v, questions=qs)
        for what, body, said in (
                ("raises", "    raise RuntimeError('broken fix')\n", "shapes_js raised on"),
                ("calls sys.exit", "    import sys\n    sys.exit(3)\n", "shapes_js raised on"),
                ("returns no table", "    return ['not', 'a', 'table']\n", "not a table"),
                ("gives a malformed unsure answer", "    return {q['qid']: '??not json' for q in questions}\n", "is not used"),
                ("gives something that is no JSON value", "    return {q['qid']: {1, 2} for q in questions}\n", "is not used")):
            install("js", body)
            out, err = solve(v, questions=qs + [q])
            check(f"live shapes: a shapes_<ext>.py that {what} costs its own answer only, and one line says so",
                  q["qid"] not in out and all(out.get(i) == a for i, a in want.items()) and len(want) == len(qs) and said in err,
                  err[-300:])
        # The runner's time limit arrives as a BaseException: it passes through, and by then the
        # solver's own answers for the specimen are already in ctx['partial'].
        install("js", "    raise BaseException('time limit')\n")
        ctx, stopped = {"set": v["set"], "partial": {}}, False
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                analyze.solve_set(qs + [q], v["files"], ctx)
        except BaseException:  # noqa: BLE001 - the stand-in for run.SolverTimeout
            stopped = True
        check("live shapes: a time limit that falls inside the file passes through, with the solver's answers already in ctx['partial']",
              stopped and ctx["partial"] == want, f"stopped={stopped} partial={len(ctx['partial'])} of {len(want)}")
        install("js", "    import labels\n"
                      "    return {q['qid']: labels.pick('script.string_style/js.concat', ['plus_concat', 'concat']) for q in questions}\n")
        out, err = solve(v, questions=qs + [q])
        parsed = labels.parse(out.get(q["qid"]))
        check("live shapes: its labels.pick answer goes out unsure, under its own key",
              parsed is not None and parsed.key == "script.string_style/js.concat" and parsed.names == ["plus_concat", "concat"]
              and f"{q['qid']}: answered by shapes_js.py, unsure" in err, str(parsed))
        install("js", "    return {q['qid']: 'plus_concat' for q in questions}\n")
        listed = {**q, "answer_format": {"kind": "enum", "accepted_values": ["template", "concat"]}}
        out, err = solve(v, questions=qs + [listed])
        check("live shapes: an answer the question's own list excludes is not used",
              q["qid"] not in out and "is not used" in err and all(out.get(i) == a for i, a in want.items()))

        # What the module declined is open too: a plan value left None, a shape name held unsure.
        member, qs, text, _ = next(s for s in batch_specimens(v) if s[3] == "call_subroutine" and CALL_GATE.search(s[2]))
        ext, control = Path(member).suffix.lower().lstrip("."), field_id(qs, "control")
        label = CALL_GATE.search(text).group(1)
        odd = CALL_GATE.sub(lambda m: f"ver >nul\nif errorlevel 1 exit /b 1\ncall :{label}", text, count=1)
        install(ext, "    return {}\n")
        out, _ = solve_text(v, member, qs, odd)
        held = labels.parse(out.get(control))
        check("live shapes: an id the solver answers unsure is handed to the file, and stays as it is when the file has no answer",
              calls(ext) == [[control]] and held is not None and held.key == "script.control/batch.declined.call_subroutine",
              f"{calls(ext)} {held}")
        install(ext, "    import labels\n"
                     "    return {q['qid']: labels.pick('script.control/batch.errorlevel_call', ['errorlevel_guard', 'guarded_call'])\n"
                     "            for q in questions if q['qid'].endswith('-control')}\n")
        out, err = solve_text(v, member, qs, odd)
        parsed = labels.parse(out.get(control))
        check("live shapes: the file's answer for that id replaces the solver's unsure one",
              parsed is not None and parsed.key == "script.control/batch.errorlevel_call"
              and parsed.names == ["errorlevel_guard", "guarded_call"]
              and f"{control}: answered by shapes_{ext}.py, unsure (in place of the unsure answer of the solver)" in err, str(parsed))
        bare = without_material(text).split("\n")
        qid = next((q["qid"] for q in qs if generic.tail_of(q) not in PLAN_TAILS + analyze.SHAPE_FIELDS["batch"]
                    and sum(v["key"][q["qid"]] in ln for ln in bare if shapes_text.FRAGMENT_RE.match(ln.strip())) == 1), None)
        value = v["key"].get(qid)
        odd = "\n".join(ln.replace(value, "%USERNAME%" + value) if qid and shapes_text.FRAGMENT_RE.match(ln.strip()) else ln
                        for ln in bare)
        install(ext, "    return {q['qid']: 'read_by_hand' for q in questions}\n")
        out, _ = solve_text(v, member, qs, odd)
        check("live shapes: a plan value the module declined is handed to the file, and nothing the module answered is",
              qid is not None and calls(ext) == [[qid]] and out.get(qid) == "read_by_hand"
              and sum(a == "read_by_hand" for a in out.values()) == 1 and len(out) == len(qs), f"{qid} {calls(ext)}")
    finally:
        plan_codec.HOOK_DIRS.remove(hooks)
        plan_codec._optional.clear()
        for e in exts:
            mod = sys.modules.get(f"shapes_{e}")
            if mod is not None and Path(getattr(mod, "__file__", "") or "").parent == hooks:
                sys.modules.pop(f"shapes_{e}", None)


# ---------------------------------------------------------------- the unseen component (the saved Day 5 attempts)

# Day 5 as it was at 09:00. Every role and technique key is masked, not only the .py ones: a later day that judges
# one of these step lists under another extension's key must not change what this replay counts.
UNSEEN = {"CTF_HIDE": "shapes_py,hooks_py", "CTF_LEDGER_MASK": "script.*/py*,script.role/*,script.attack/*"}
# A specimen's material and its codec label, as the Day 5 specimens write them.
MATERIAL_RE = re.compile(r'(?ms)^([ \t]*MATERIAL_(\w+)[ \t]*=[ \t]*)(.+?)(^[ \t]*CODEC_\2[ \t]*=[ \t]*)"[^"\r\n]*"')


def py_specimens(v):
    return [(m, qs) for m, qs in specimens(v) if m.endswith(".py")]


def tally_py(v, out):
    """(Counter, missing ids) of the .py answers of one set against its key; `old` counts the other ids that equal it."""
    c, missing = Counter(), []
    for q in v["qs"]:
        a, k = out.get(q["qid"]), v["key"][q["qid"]]
        if not q["member"].endswith(".py"):
            c["old"] += a == k
        elif a is None:
            missing.append(q["qid"])
        elif labels.is_unsure(a):
            c["unsure"] += 1
            c["offered"] += k in [value for _, value in labels.parse(a).options]
            c["first"] += k == labels.parse(a).options[0][1]
        else:
            c["right" if a == k else "wrong"] += 1
    return c, missing


def test_unseen_component(day5):
    """The Day 5 base, Time Trial and Mastery as Layer 1 met them: no shapes_py.py, no hooks_py.py, no .py name judged."""
    counts = {False: [], True: []}
    bad = []
    for v in day5:
        new = set()         # the role and attack ids of the specimens whose step list is not in the role table
        for member, qs in py_specimens(v):
            got = plan_codec.reading(plan_codec.text_of(v["files"][member]), ".py")[0]
            if got is None or generic.steps_of(plan_codec.flatten(got[0])) not in generic.ROLE:
                new |= {q["qid"] for q in qs if q["qid"].endswith(("-role", "-attack"))}
        for offer in (False, True):
            with env(**UNSEEN), offering(offer):
                out, _ = solve(v)
            c, missing = tally_py(v, out)
            counts[offer].append((c["right"], c["unsure"], len(missing), c["wrong"]))
            want = (112, 14, 0, 0) if offer else (112, 2, 12, 0)
            if (c["right"], c["unsure"], len(missing), c["wrong"]) != want or c["offered"] != c["unsure"] or c["old"] != 231 \
                    or c["first"] != c["unsure"] or set(missing) != (set() if offer else new) or len(new) != 12:
                bad.append(f"{v['name']} offer={offer}: {dict(c)} missing={missing[:3]}")
    check(f"unseen component: {len(day5)} Day 5 sets without the live fixes and the .py names, OFFER_UNSEEN_ROLES off: per set "
          f"112 plain answers equal to the key, 2 unsure, and the 12 role and attack ids of the four new step lists missing; "
          f"no plain wrong answer; the 231 older answers unchanged",
          len(day5) == 4 and not [b for b in bad if "offer=False" in b] and counts[False] == [(112, 2, 12, 0)] * 4,
          "; ".join(bad[:3]) or str(counts[False]))
    check("unseen component: switched on: 112 plain, 14 unsure with the name the judge accepted as the FIRST option (the "
          "order of role_candidates: the id's specimen word leads), nothing missing, no plain wrong answer",
          not [b for b in bad if "offer=True" in b] and counts[True] == [(112, 14, 0, 0)] * 4, "; ".join(bad[:3]) or str(counts[True]))
    right = total = 0
    for v in day5:
        with env(CTF_HIDE=UNSEEN["CTF_HIDE"]):
            out, _ = solve(v)
        right += sum(out.get(q["qid"]) == v["key"][q["qid"]] for q in v["qs"])
        total += len(v["qs"])
    check(f"unseen component: with the judged names in the seed the general path alone answers {right} of {total} as the keys",
          right == total == 1428)
    right = 0
    for v in day5:
        out, _ = solve(v)
        right += sum(out.get(q["qid"]) == v["key"][q["qid"]] for q in v["qs"])
    check(f"unseen component: and in the normal state (shapes_py.py and hooks_py.py present) {right} of {total}", right == total)


def test_stress(day5):
    """A bounded sample of the retro's re-encoding run: every Day 5 specimen's own plan stored again in its text under other
    forms, keys and transforms. Counted: a case where any of the nine answers is plain and not the unchanged specimen's."""
    keys = (0x01, 0x5b, 0xc7)
    tally, examples = Counter(), []
    with env(**UNSEEN):
        for v in day5:
            for member, qs in py_specimens(v):
                original = plan_codec.text_of(v["files"][member])
                truth = plan_codec.reading(original, ".py")[0]
                reference, _ = solve(v, questions=qs)
                if truth is None or not MATERIAL_RE.search(original):
                    tally["skipped"] += 1
                    continue
                plan = truth[0].encode("ascii")
                for k in keys:
                    for stored in (bytes(b ^ k for b in plan), bytes(b ^ k for b in reversed(plan)), bytes((b + k) % 256 for b in plan)):
                        t = base64.b64encode(stored).decode("ascii")
                        n = len(t) // 4 // 4 * 4
                        chunks = [t[i * n:(i + 1) * n] for i in range(3)] + [t[3 * n:]]
                        third = len(stored) // 3
                        numbers = ", ".join(map(str, stored))
                        own = [base64.b64encode(stored[a:b]).decode("ascii") for a, b in ((0, third), (third, 2 * third), (2 * third, len(stored)))]
                        lines = "\n".join(t[i:i + 120] for i in range(0, len(t), 120))
                        short = [t[i:i + 20] for i in range(0, len(t), 20)]
                        forms = (
                            ("whole", "url-safe base64", '"' + base64.urlsafe_b64encode(stored).decode("ascii") + '"'),
                            ("whole", "four adjacent chunks", '("' + '"\n    "'.join(chunks) + '")'),
                            # The generator's own number forms: four of the fourteen carriers hold a second number list.
                            ("list", "a number list", f"[{numbers}]"),
                            ("list", "a number tuple that ends in a comma", f"({numbers},)"),
                            ("piece", "each chunk encoded on its own, one variable per chunk",
                             "0\n" + "\n".join(f'PART{i} = "{c}"' for i, c in enumerate(own))),
                            ("piece", "chunks assigned out of order", "0\n" + "\n".join(f'PART{i} = "{chunks[i]}"' for i in (2, 0, 3, 1))),
                            ("piece", "wrapped at 120 columns in a triple-quoted block", '"""\n' + lines + '\n"""'),
                            ("piece", "20-character chunks joined with +, a comment after half of them",
                             '("' + '" +\n    "'.join(short[:len(short) // 2]) + '" +  # the second half\n    "'
                             + '" +\n    "'.join(short[len(short) // 2:]) + '")'),
                            ("piece", "a list of chunks", '["' + '", "'.join(chunks) + '"]'),
                            ("piece", "one variable per chunk", "0\n" + "\n".join(f'PART{i} = "{c}"' for i, c in enumerate(chunks))),
                            ("piece", "three number lists", " + ".join("[" + ", ".join(map(str, stored[a:b])) + "]" for a, b in
                                                                       ((0, third), (third, 2 * third), (2 * third, len(stored))))),
                            ("piece", "a bare url-safe token", "0  # " + base64.urlsafe_b64encode(stored).decode("ascii")),
                            ("piece", "material and a word", '"' + t.rstrip("=") + '" "' + "QUJD"[:2 + k % 3] + '"'),
                        )
                        for kind, what, literal in forms:
                            text = MATERIAL_RE.sub(lambda m: m.group(1) + literal + "\n" + m.group(4) + '"stored_again|x|"', original, count=1)
                            out, _ = solve({**v, "files": {**v["files"], member: text.encode("utf-8")}}, questions=qs)
                            # Plain where the unchanged specimen has another plain answer, or none at all.
                            wrong = [q["qid"] for q in qs if out.get(q["qid"]) is not None and not labels.is_unsure(out[q["qid"]])
                                     and not labels.is_unsure(reference.get(q["qid"])) and out[q["qid"]] != reference.get(q["qid"])]
                            read = plan_codec.reading(text, ".py")[0]
                            tally[kind] += 1
                            tally[f"{kind} read whole"] += read is not None and read[0] == truth[0]
                            tally[f"{kind} read as a prefix"] += read is None or truth[0].startswith(read[0])
                            tally["wrong"] += bool(wrong)
                            if wrong and len(examples) < 3:
                                examples.append(f"{v['name']} {member} {what} key {k:02x}: {wrong[0]}={out[wrong[0]]!r}")
    check(f"stress: {tally['whole']} cases of the two forms of the retro's run (url-safe base64, four adjacent chunks): "
          f"{tally['whole read whole']} plans read whole, {tally['wrong']} cases with a plain wrong answer",
          tally["whole"] == tally["whole read whole"] == 56 * 18 and not tally["wrong"] and not tally["skipped"], "; ".join(examples))
    check(f"stress: {tally['piece']} cases of nine forms no reading joins (a list of chunks, one variable per chunk, three "
          f"number lists, a bare url-safe token, material beside a word; chunks encoded on their own, chunks out of order, "
          f"a wrapped block, a join cut by a comment): {tally['piece read whole']} read whole, every other one as a prefix "
          f"of the plan, no plain wrong answer",
          tally["piece"] == tally["piece read as a prefix"] == 56 * 81 and not tally["wrong"], "; ".join(examples))
    check(f"stress: {tally['list']} cases of the generator's two number forms, on specimens that hold a second number list "
          f"too: {tally['list read whole']} read whole, the others without their last field, no plain wrong answer",
          tally["list"] == tally["list read as a prefix"] == 56 * 18 and 0 < tally["list read whole"] < tally["list"]
          and not tally["wrong"], "; ".join(examples))
    # What the general path leaves of such a specimen, today's judged shapes_py.py still answers.
    v = day5[0]
    member, qs = py_specimens(v)[0]
    original = plan_codec.text_of(v["files"][member])
    plan = plan_codec.reading(original, ".py")[0][0].encode("ascii")
    t = base64.b64encode(bytes(b ^ 0x5b for b in plan)).decode("ascii")
    n = len(t) // 4 // 4 * 4
    literal = '["' + '", "'.join([t[i * n:(i + 1) * n] for i in range(3)] + [t[3 * n:]]) + '"]'
    text = MATERIAL_RE.sub(lambda m: m.group(1) + literal + "\n" + m.group(4) + '"stored_again|x|"', original, count=1)
    files = {**v["files"], member: text.encode("utf-8")}
    with env(CTF_HIDE="shapes_py,hooks_py"):
        alone, _ = solve({**v, "files": files}, questions=qs)
    both, err = solve({**v, "files": files}, questions=qs)
    check("stress: a .py specimen whose plan the general path reads from a piece: it answers 8 of 9 by itself, and "
          "shapes_py.py still answers the field that was left out",
          len(alone) == 8 and all(alone[i] == v["key"][i] for i in alone) and len(both) == 9
          and all(both[q["qid"]] == v["key"][q["qid"]] for q in qs), f"{len(alone)} alone, {len(both)} with shapes_py; {err[-300:]}")


# ---------------------------------------------------------------- the codec label as a second plan source (row 37)

LP_PLAN = ("v=1|steps=acquire_remote,dispatch_memory|adapter=Lab.Adapter|stage_count=2|campaign_id=campaign-4242424242|"
           "url=https://lab.invalid/stage-4242424242.bin")
LP_ADV = "v=1|feature=indirect_expansion|primitive=pointer|campaign_id=campaign-7777777777|stage_count=1|steps=recognize_syntax,reconstruct_intent"


def lp_forward(tr: str, key: list, data: list) -> list:
    """The bytes a specimen stores for clear bytes `data` under transform `tr` (label_plan._undo reversed)."""
    if tr == "identity":
        return list(data)
    if tr == "reverse_bytes":
        return data[::-1]
    if tr == "single_byte_xor":
        return [b ^ key[0] for b in data]
    if tr == "reverse_then_xor":
        return [b ^ key[0] for b in data[::-1]]
    if tr == "repeating_key_xor":
        return [b ^ key[i % len(key)] for i, b in enumerate(data)]
    if tr == "add_modulo_256":
        return [(b + key[0]) % 256 for b in data]
    if tr == "subtract_modulo_256":
        return [(b - key[0]) % 256 for b in data]
    if tr == "rolling_xor":
        k, out = key[0], []
        for b in data:
            out.append(b ^ k)
            k = out[-1]
        return out
    if tr == "rotate_left":
        r = key[0] % 8
        return [((b << r) | (b >> (8 - r))) & 255 for b in data]
    raise ValueError(tr)


def lp_spell(rep: str, data: list) -> str:
    """The literal (with its quotes) that spells `data` as representation `rep`."""
    b = bytes(data)
    if rep == "hex_compact":
        return f'"{b.hex()}"'
    if rep in ("hex_colon", "hex_dash", "hex_space", "hex_comma"):
        return '"' + {"hex_colon": ":", "hex_dash": "-", "hex_space": " ", "hex_comma": ","}[rep].join(f"{x:02x}" for x in b) + '"'
    if rep == "reversed_hex":
        return '"' + ":".join(f"{x:02x}" for x in b[::-1]) + '"'
    if rep == "percent_hex":
        return '"' + "".join(f"%{x:02X}" for x in b) + '"'
    if rep == "hex_array":
        return '"[' + ",".join(f'\\"{x:02x}\\"' for x in b) + ']"'
    if rep == "hex_buffer":
        return f"'{b.hex()}'"
    if rep == "escaped_octets":
        return '"' + "".join(f"\\x{x:02x}" for x in b) + '"'
    if rep == "unicode_escapes":
        return '"' + "".join(f"\\u{x:04x}" for x in b) + '"'
    if rep == "octal_escapes":
        return '"' + "".join(f"\\{x:03o}" for x in b) + '"'
    if rep == "binary_bits":
        return '"' + " ".join(f"{x:08b}" for x in b) + '"'
    if rep == "base64_literal":
        return f'"{base64.b64encode(b).decode()}"'
    if rep == "reversed_base64":
        return f'"{base64.b64encode(b).decode()[::-1]}"'
    if rep == "base32":
        return f'"{base64.b32encode(b).decode()}"'
    if rep == "reversed_base32":       # a spelling plan_codec does not read without its label (row 57 reads base32)
        return f'"{base64.b32encode(b).decode()[::-1]}"'
    if rep == "base85":
        return f"'{base64.b85encode(b).decode()}'"
    if rep in ("decimal_space", "decimal_comma", "decimal_colon", "decimal_pipe", "decimal_dash"):
        sep = {"decimal_space": " ", "decimal_comma": ",", "decimal_colon": ":", "decimal_pipe": "|", "decimal_dash": "-"}[rep]
        return '"' + sep.join(str(x) for x in b) + '"'
    if rep == "reversed_decimal":
        return '"' + " ".join(str(x) for x in b[::-1]) + '"'
    if rep == "json_numbers":
        return "[" + ", ".join(str(x) for x in b) + "]"
    raise ValueError(rep)


LP_REPS = ("hex_compact", "hex_colon", "hex_dash", "hex_space", "hex_comma", "reversed_hex", "percent_hex", "hex_array",
           "hex_buffer", "escaped_octets", "unicode_escapes", "octal_escapes", "binary_bits", "base64_literal",
           "reversed_base64", "base32", "base85", "decimal_space", "decimal_comma", "decimal_colon", "decimal_pipe",
           "decimal_dash", "reversed_decimal", "json_numbers")
LP_TRANSFORMS = ("identity", "reverse_bytes", "single_byte_xor", "reverse_then_xor", "repeating_key_xor", "add_modulo_256",
                 "subtract_modulo_256", "rolling_xor", "rotate_left")
LP_KEYS = {"hex": ([0xc3], "c3", [0xaf, 0x9e, 0xf2, 0x0a, 0x9b], "af,9e,f2,0a,9b"),
           "0x": ([0xc3], "0xc3", [0xaf, 0x9e, 0xf2, 0x0a, 0x9b], "0xaf,0x9e,0xf2,0x0a,0x9b"),
           "decimal": ([195], "195", [175, 158, 242, 10, 155], "175,158,242,10,155")}


def lp_file(rep, tr, key, label, plan=LP_PLAN, ident="5a17c0de"):
    stored = lp_forward(tr, key, list(plan.encode()))
    return (f"// Huntress Script Triage -- inert static-analysis fixture\nconst Material_{ident} = {lp_spell(rep, stored)};\n"
            f"const Codec_{ident} = \"{label}\";\nfunction Load_{ident}() {{ return decode(Material_{ident}); }}\n")


def test_label_forms():
    """label_plan.read_text over every representation x transform x key notation, as labelled and
    under a label in another form; multi-line material; the agreement rule inside generic."""
    import label_plan
    want = LP_PLAN
    labelled, bad, fused_ok, fused_bad, n_fused = 0, [], 0, [], 0
    t0 = time.perf_counter()
    for rep in LP_REPS:
        for tr in LP_TRANSFORMS:
            keyed = tr not in ("identity", "reverse_bytes")
            for notation, (k1, s1, kn, sn) in (LP_KEYS.items() if keyed else [("none", ([], "", [], ""))]):
                key, spelled = (kn, sn) if tr == "repeating_key_xor" else (k1, s1)
                got = label_plan.read_text(lp_file(rep, tr, key, f"{rep}|{tr}|{spelled}"))
                labelled += 1
                if got != want:
                    bad.append(f"{rep}|{tr}|{notation}: {str(got)[:60]}")
                if notation in ("none", "hex", "decimal"):
                    # The same material under a label in another form: a fused name, the key alone.
                    n_fused += 1
                    got = label_plan.read_text(lp_file(rep, tr, key, f"{tr}_{rep}_v2|{spelled}" if keyed else f"{rep}_v2|"))
                    (fused_ok := fused_ok + 1) if got == want else fused_bad.append(f"{rep}|{tr}|{notation}: {str(got)[:60]}")
    took = time.perf_counter() - t0
    check(f"label forms: {labelled - len(bad)} of {labelled} labelled specimens (24 representations x 9 transforms x hex, "
          f"0x and decimal keys) read to the plan", not bad, "; ".join(bad[:6]))
    check(f"label forms: {fused_ok} of {n_fused} under a label in another form (fused name, unknown representation) read "
          f"by the every-reading fallback ({took:.1f} s for all)", not fused_bad, "; ".join(fused_bad[:6]))
    # The harvest checklist's known misses: a reversal stacked on add, subtract, rolling or repeating
    # xor (before or after it), and the text of a representation written backwards.
    stacked, stacked_bad = 0, []
    plain = list(LP_PLAN.encode())
    for tr, key, spelled in (("add_modulo_256", [0x2b], "2b"), ("subtract_modulo_256", [0x2b], "43"),
                             ("rolling_xor", [0x91], "0x91"), ("repeating_key_xor", [1, 2, 3, 4, 5], "01,02,03,04,05")):
        for order in ("after", "before"):
            data = lp_forward(tr, key, plain)[::-1] if order == "after" else lp_forward(tr, key, plain[::-1])
            for rep in ("hex_compact", "hex_colon", "decimal_space", "base64_literal", "base32"):
                for text_rev in (False, True):
                    lit = lp_spell(rep, data)
                    if text_rev:
                        lit = lit[0] + lit[1:-1][::-1] + lit[-1]
                    body = (f"const Material_77 = {lit};\nconst Codec_77 = \"stacked_{rep}|{spelled}\";\n")
                    stacked += 1
                    got = label_plan.read_text(body)
                    if got != want:
                        stacked_bad.append(f"{tr}/{order}/{rep}/{'text reversed' if text_rev else 'as is'}: {str(got)[:40]}")
    check(f"label forms: {stacked - len(stacked_bad)} of {stacked} with a reversal stacked on add, subtract, rolling or "
          f"repeating xor, or the representation's text written backwards, under an unknown label", not stacked_bad,
          "; ".join(stacked_bad[:6]))
    adv = label_plan.read_text(lp_file("hex_compact", "single_byte_xor", [0xcd], "xor_hex|cd", plan=LP_ADV))
    check("label forms: Day 7's fused `xor_hex|cd` and an advanced plan `v=1|feature=...`", adv == LP_ADV, str(adv))
    ml = ("const Material_ab12 = [\n" + ",\n".join(f'  "{x:02x}"' for x in LP_PLAN.encode()) + "\n];\n"
          'const Codec_ab12 = "hex_array|identity|";\n')
    vb = ('Const Material_cd34 = "' + LP_PLAN.encode().hex()[:120] + '" & _\n  "' + LP_PLAN.encode().hex()[120:] + '"\n'
          'Const Codec_cd34 = "hex_compact|identity|"\n')
    tl = "Material_ef56 = (\n    '" + base64.b64encode(LP_PLAN.encode()).decode()[:40] + "'\n    '" + \
         base64.b64encode(LP_PLAN.encode()).decode()[40:] + "'\n)\nCodec_ef56 = 'base64_literal|identity|'\n"
    check("label forms: material over several lines (an open bracket, a VB `& _`, adjacent literals in brackets)",
          [label_plan.read_text(x) for x in (ml, vb, tl)] == [want] * 3,
          str([label_plan.read_text(x) for x in (ml, vb, tl)]))
    comment = ('const Material_aa = "' + LP_PLAN.encode().hex() + '"; // decoy, see the next line,\n'
               'const Codec_aa = "hex_compact|identity|";\n')
    check("label forms: a trailing comment that ends in a comma does not join the next line", label_plan.read_text(comment) == want)
    import label_plan as lpm
    head = LP_PLAN.encode().hex()
    piece = ("readonly Material_ab=\"$(printf '" + "".join(f"\\x{ord(c):02x}" for c in head[:8]) + "')\"'" + head[8:]
             + "'\nreadonly Codec_ab='hex_compact|identity|'\n")
    call = 'const Material_cd = Buffer.from("' + head + '", "hex");\nconst Codec_cd = "hex_buffer|identity|";\n'
    got_piece, got_call = lpm.reading(piece), lpm.reading(call)
    cut_plan = LP_PLAN[:LP_PLAN.rfind("|") + 1]
    check("label forms: material built partly by code (a $(printf) head, a call around the literal) is a piece: "
          "its plan comes cut, without the last field", got_call == (cut_plan, True) and got_piece in ((None, False), (cut_plan, True)),
          f"{got_piece} {got_call}")
    other = LP_PLAN.replace("4242424242", "9999999999")
    two = lp_file("hex_compact", "identity", [], "hex_compact|identity|") + \
        lp_file("base64_literal", "identity", [], "base64_literal|identity|", plan=other, ident="0b0b0b0b")
    check("label forms: two labelled materials with different plans are no plan", label_plan.read_text(two) is None)
    blob = '{"a": 1, "b": "settings"}'
    check("label forms: a JSON object without steps is no plan",
          label_plan.read_text(lp_file("base64_literal", "identity", [], "base64_literal|identity|", plan=blob)) is None)

    # Inside generic: a new extension, and the agreement rule.
    member = "remote-stage.zz8"
    qs = [question("zz8-stager-campaign", member, "Recover the exact synthetic campaign identifier."),
          question("zz8-stager-adapter", member, "Recover the exact adapter named by the reconstructed plan."),
          question("zz8-stager-url", member, "Recover the exact url indicator."),
          question("zz8-stager-role", member, "Classify remote-stage.zz8 by its ordered behavior graph.")]
    # 90 is the key in decimal. (Reversed base32: since row 57 plan_codec reads plain base32 by itself.)
    body = lp_file("reversed_base32", "add_modulo_256", [0x5a], "reversed_base32|add_modulo_256|90")
    with contextlib.redirect_stderr(io.StringIO()) as err:
        out = generic.answers(qs, {member: body.encode()}, {})
    check("label forms: a language no day has seen, its key in decimal: generic answers the plan from the label",
          out == {"zz8-stager-campaign": "campaign-4242424242", "zz8-stager-adapter": "Lab.Adapter",
                  "zz8-stager-url": "https://lab.invalid/stage-4242424242.bin", "zz8-stager-role": "stager"}
          and "plan read by its codec label" in err.getvalue(), f"{out} {err.getvalue()[-300:]}")
    old = generic.LABEL_PLAN
    try:
        generic.LABEL_PLAN = False
        with contextlib.redirect_stderr(io.StringIO()):
            off = generic.answers(qs, {member: body.encode()}, {})
    finally:
        generic.LABEL_PLAN = old
    check("label forms: with LABEL_PLAN off the same file gives nothing", off == {}, str(off))
    # plan_codec reads the first half of a plan from a decoy literal (cut), the label a different one.
    decoy = LP_PLAN.replace("Lab.Adapter", "Other.Adapter")
    clash = f"// note\nconst seed = \"{decoy.encode().hex()}\" + more;\n" + \
        lp_file("base64_literal", "single_byte_xor", [0x33], "base64_literal|single_byte_xor|33")
    with contextlib.redirect_stderr(io.StringIO()) as err:
        info = generic.read(member, clash.encode())
        clashed = generic.answers(qs, {member: clash.encode()}, {})
    check("label forms: a label plan that differs from a field plan_codec read is a second plan: no plan answer",
          info["cut"] is False and info["plan"] == {} and "zz8-stager-adapter" not in clashed
          and "zz8-stager-campaign" not in clashed, f"{info['notes']} {clashed}")
    agree = f"// note\nconst seed = \"{LP_PLAN.encode().hex()}\" + more;\n" + \
        lp_file("base64_literal", "single_byte_xor", [0x33], "base64_literal|single_byte_xor|33")
    with contextlib.redirect_stderr(io.StringIO()):
        info = generic.read(member, agree.encode())
    check("label forms: a cut plan the label plan agrees with is replaced by the whole label plan",
          info["plan"] == plan_codec.flatten(LP_PLAN) and not info["cut"], f"{info['plan']} {info['notes']}")

    # Row 42: a JSON array of quoted hex bytes inside a string, with no label at all.
    arr = '"[' + ",".join(f'\\"{x:02x}\\"' for x in LP_PLAN.encode()) + ']"'
    short = '"[' + ",".join(f'\\"{x:02x}\\"' for x in LP_PLAN.encode()[:20]) + ']"'
    got = plan_codec.decode(f"const blob = {arr};\nrun(JSON.parse(blob));\n", ".zz8")
    check("hex_array: plan_codec reads a string holding a JSON array of 24+ quoted hex bytes, unlabelled",
          got is not None and got[0] == LP_PLAN and got[1] == "hex_array", str(got))
    check("hex_array: an array of fewer than 24 items is not read as one",
          not any(how == "hex_array" for how, _ in plan_codec.candidates(f"const blob = {short};\n")))


def day7_variants():
    """One entry per set of every saved Day 7 Script attempt: base, Time Trial, Mastery and every
    history/ variant. The reference is key.json, else what verdicts.jsonl shows accepted."""
    import judge
    out = []
    for base in sorted((gm.CHALLENGES / "day-07").glob("script-analysis-*")):
        dirs = [base]
        for mode in ("time_trial", "mastery"):
            dirs += [base / mode] + sorted((base / mode / "history").glob("*"))
        for d in dirs:
            if not (d / "attempt.json").exists():
                continue
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    attempt, blobs, _ = run.load_offline("", str(d))
            except SystemExit:
                continue
            if (d / "key.json").exists():
                ref = json.loads((d / "key.json").read_text())["answers"]
            else:
                ref = judge.ledger(d)[0]
            for n, qs, files, _ctx in run.split_sets(attempt, blobs):
                out.append({"name": f"{d.relative_to(gm.CHALLENGES)}#{n}", "dir": d, "set": n, "qs": qs, "files": files,
                            "key": {q["qid"]: ref.get(q["answer_id"]) for q in qs}})
    return out


def test_day7(day7):
    """Row 37 on Day 7's saved attempts: the label plan in generic replaces shapes_mjs/shapes_sh."""
    def tally(v, out):
        miss = [q["qid"] for q in v["qs"] if out.get(q["qid"]) is None]
        wrong = [i for i, a in out.items() if isinstance(a, str) and not a.startswith("??")
                 and v["key"].get(i) is not None and a != v["key"][i]]
        unsure = [i for i, a in out.items() if isinstance(a, str) and a.startswith("??")]
        unsure = [i for i in unsure if v["key"].get(i) is not None]      # a failed variant's open id has no reference
        hit = [i for i in unsure if v["key"][i] in [o[1] for o in labels.parse(out[i]).options]]
        return miss, wrong, unsure, hit

    rows, slow = [], 0.0
    for v in day7:
        t0 = time.perf_counter()
        out, _ = solve(v)
        slow = max(slow, time.perf_counter() - t0)
        rows.append((v, *tally(v, out)))
    check(f"day 7: {len(day7)} sets (base, Time Trials, Masteries, every history variant): 0 missing, 0 plain wrong, 0 unsure "
          f"with the seed as shipped; slowest set {slow:.2f} s",
          len(day7) >= 13 and all(not m and not w and not u for _, m, w, u, _h in rows),
          "; ".join(f"{v['name']}: missing {m[:3]} wrong {w[:3]} unsure {u[:3]}" for v, m, w, u, _h in rows if m or w or u)[:900])
    mask = ",".join(["script.role/mjs.*", "script.attack/mjs.*", "script.attack/mjs", "script.role/sh.recognize_syntax*",
                     "script.attack/sh.recognize_syntax*"])
    with env(CTF_LEDGER_MASK=mask):
        masked = [(v, *tally(v, solve(v)[0])) for v in day7]
    check("day 7: with Day 7's names masked (as at 09:00): 0 missing, 0 plain wrong, and every unsure answer holds the "
          "judge's value among its options",
          all(not m and not w and len(h) == len(u) for _, m, w, u, h in masked) and any(u for *_, u, _h in masked),
          "; ".join(f"{v['name']}: missing {m[:3]} wrong {w[:3]} unsure {len(u)} hit {len(h)}"
                    for v, m, w, u, h in masked if m or w or len(h) != len(u))[:900])
    old = generic.LABEL_PLAN
    try:
        generic.LABEL_PLAN = False
        off = [(v, *tally(v, solve(v)[0])) for v in day7[:1]]
    finally:
        generic.LABEL_PLAN = old
    # Before row 101 (2026-10-08) this left 14 ids or more open: plan_codec read no plan that opens
    # `v=1|feature=`. Its grammar now does, so with the label plan off only what the label alone gives is
    # open (2 ids on the saved base), and nothing may be wrong.
    check("day 7: with LABEL_PLAN off (and shapes_mjs/shapes_sh doing nothing) the base leaves only label-only ids "
          "open, none wrong (row 101: plan_codec reads the feature-first plans itself)",
          off and 1 <= len(off[0][1]) < 14 and not off[0][2], f"{len(off[0][1])} missing, {len(off[0][2])} wrong")


R51_PLAN = ("v=1|steps=acquire_remote,write_file|adapter=net_http_get|stage_count=2|campaign_id=RUBY-4C260462"
            "|url=https://ruby-4c26046275a3.example.invalid/api|file_path=/tmp/huntress-ruby/.stage-4c26.rb")
R51_WANT = {"role": "downloader", "attack": "T1105", "adapter": "net_http_get", "campaign": "RUBY-4C260462",
            "url": "https://ruby-4c26046275a3.example.invalid/api", "file-path": "/tmp/huntress-ruby/.stage-4c26.rb",
            "stage-count": "2", "steps": "acquire_remote>write_file"}
R51_STEPS_FMT = {"kind": "ordered_tokens", "syntax": "exact tokens joined by > with no surrounding spaces or explanatory text"}


def r51_questions(prefix, member, want):
    qs = []
    for f in want:
        text = {"role": f"Classify {member} by its ordered behavior graph.",
                "attack": "Recover the primary MITRE ATT&CK technique ID, or none.",
                "steps": "Recover the ordered behavior graph using > separators.",
                "stage-count": "Recover the exact modeled stage count.",
                "adapter": "Recover the exact adapter.", "campaign": "Recover the exact campaign."}.get(
            f, f"Recover the exact {f.replace('-', '_')} indicator.")
        more = {"answer_format": R51_STEPS_FMT} if f == "steps" else {}
        qs.append(question(f"{prefix}-{f}", member, text, **more))
    return qs


def r51_specimens(material, codec):
    """{extension: text} of one labelled material in the four languages that have a module."""
    return {"ps1": f"$Material_ab12 = '{material}'\n$Codec_ab12 = '{codec}'\n",
            "js": f'var Material_ab12 = "{material}";\nvar Codec_ab12 = "{codec}";\n',
            "vbs": f'Const Material_ab12 = "{material}"\nConst Codec_ab12 = "{codec}"\n',
            "bat": f'@echo off\nset "Material_ab12={material}"\nset "Codec_ab12={codec}"\n'}


def test_rows_49_51(corpus, day1):
    """Row 49: label_plan reads `Material_`/`Codec_` in any case, Batch's quoted set and PHP's
    define. Row 51: a known-language specimen of a new component goes to the general path, and
    the modules' last guesses (T1496, benign_utility, a comma-joined step list) are gone."""
    import label_plan
    import powershell
    import vbscript
    b64 = base64.b64encode(LP_ADV.encode()).decode()
    forms = {"batch quoted set": f'@echo off\nset "Material_ab12={b64}"\nset "Codec_ab12=base64_literal|"\n',
             "batch SET, unquoted label": f'SET "MATERIAL_ab12={b64}"\r\nset Codec_AB12=base64_literal|\n',
             "php define": f"<?php\ndefine('Material_ab12', '{b64}');\ndefine(\"Codec_ab12\", 'base64_literal|');\n",
             "python upper case": f'MATERIAL_ab12 = "{b64}"\nCODEC_ab12 = "base64_literal|"\n',
             "typed, upper case": f'MATERIAL_ab12: str = "{b64}"\nCODEC_ab12: str = "base64_literal|"\n'}
    for name, text in forms.items():
        got = label_plan.reading(text)
        check(f"row 49: {name} reads the whole plan", got == (LP_ADV, False), repr(got))
    expanded = f'set "Material_ab12={b64}%TAIL%"\nset "Codec_ab12=base64_literal|"\n'
    got = label_plan.reading(expanded)
    check("row 49: a Batch value that expands %VAR% is a piece (cut, or no plan)", got[0] is None or got[1], repr(got))
    other = base64.b64encode(LP_ADV.replace("7777", "8888").encode()).decode()
    two = forms["python upper case"] + f'Material_cd = "{other}"\nCodec_cd = "base64_literal|"\n'
    check("row 49: two different plans are still no plan", label_plan.reading(two) == (None, False))
    check("row 49: a comparison is no assignment",
          label_plan.reading(f'if (Material_ab12 == "{b64}") x\nCodec_ab12 = "base64_literal|"\n') == (None, False))

    # Every saved specimen of the four languages is of a component its module was built on.
    stray = [f"{v['dir'].name}:{m}" for v in list(corpus) + list(day1) for m, qs in specimens(v)
             if analyze.LANGUAGE.get(Path(m).suffix.lower())
             and not analyze.known_component(analyze.LANGUAGE[Path(m).suffix.lower()], generic.with_fields(qs))]
    check("row 51: every saved .ps1/.js/.bat/.vbs specimen (Days 1-4, history too) stays with its module",
          not stray, ", ".join(stray[:5]))
    check("row 51: vbscript.role_of gives None for steps with no marker", vbscript.role_of(("odd_step",)) is None)
    sp = powershell.Specimen("sample.ps1", b"Write-Output 'hello'\n")
    check("row 51: a PowerShell specimen with no signal has no technique (was T1496)", sp.attack() is None, repr(sp.attack()))

    hexed = bytes(lp_forward("single_byte_xor", [0x3b], list(R51_PLAN.encode()))).hex()
    lang = {"ps1": "powershell", "js": "jscript", "vbs": "vbscript", "bat": "batch"}
    for ext, text in r51_specimens(hexed, "hex_buffer|single_byte_xor|3b").items():
        member = f"module-remote-write.{ext}"
        prefix = f"{'powershell' if ext == 'ps1' else lang[ext]}-downloader"
        qs = r51_questions(prefix, member, R51_WANT)
        out, _err = solve({"files": {member: text.encode()}, "set": 1}, qs)
        wrong = {k: v for k, v in out.items() if analyze.plain(v) and v != R51_WANT[k[len(prefix) + 1:]]}
        right = sum(1 for k, v in out.items() if v == R51_WANT[k[len(prefix) + 1:]])
        # batch-downloader is a known component, so batch.py answers it, and batch.py reads no plan
        # from a `set "Material_..."` file: nothing, which is not wrong. The others answer all eight.
        # Day 13 preparation (2026-10-12): `steps` and `stage-count` are fields no day has asked of the JScript
        # or VBScript component (analyze.MODULE_FIELDS). The plan's own value goes out unsure with one option,
        # in the question's form (joined by >), never plain. PowerShell's new component is the general path's.
        if ext in ("js", "vbs"):
            held = {f: labels.parse(out.get(f"{prefix}-{f}") or "") for f in ("steps", "stage-count")}
            whole = right == len(R51_WANT) - 2 and all(
                h is not None and h.key == f"script.{f.replace('-', '_')}/{ext}.plan_key"
                and [v for _n, v in h.options] == [R51_WANT[f]] for f, h in held.items())
            what = ", six right, steps (joined by >) and stage-count unsure with the plan's value"
        else:
            whole = ext == "bat" or out.get(f"{prefix}-steps") == R51_WANT["steps"] and right == len(R51_WANT)
            what = "" if ext == "bat" else ", all eight right, steps joined by >"
        check(f"row 51: a new {lang[ext]} graph ({prefix}-*): no plain answer wrong{what}", not wrong and whole,
              f"{right}/8 wrong={wrong}")
    adv = {"role": "advanced_syntax", "attack": None, "feature": "indirect_expansion", "primitive": "pointer",
           "campaign": "campaign-7777777777", "stage-count": "1", "steps": "recognize_syntax>reconstruct_intent"}
    for ext, text in r51_specimens(b64, "base64_literal|").items():
        member = f"advanced-expansion.{ext}"
        prefix = f"{'powershell' if ext == 'ps1' else lang[ext]}-advanced"
        qs = r51_questions(prefix, member, adv)
        out, _err = solve({"files": {member: text.encode()}, "set": 1}, qs)
        wrong = {k: v for k, v in out.items() if analyze.plain(v) and v != adv[k[len(prefix) + 1:]]}
        check(f"row 51: an advanced {lang[ext]} fixture: no plain answer wrong (no T1496, no benign_utility)",
              not wrong and out.get(f"{prefix}-campaign") == adv["campaign"], f"wrong={wrong}")


def test_row_71():
    """Row 71: the general path reads a plan written in the languages of the language pack (Go, TypeScript,
    CommonJS, R, AutoHotkey, PowerShell modules, VBA, Tcl) from synthetic fixtures. A whole value gives the
    whole plan; a value built over statements whose head is a literal (`:=`, a typed `let`, `<-`) is never
    read as whole from its head alone: then the plan comes cut (its last field left out), never with a
    shortened last value."""
    import label_plan
    plan = "v=1|steps=decode_configuration,return_configuration|adapter=fixture_adapter|campaign_id=LAB-71|note_name=readme-lab.txt|"
    hx = plan.encode().hex()
    head, tail = hx[:-10], hx[-10:]
    c6 = ", ".join(str(ord(c)) for c in hx[:6])      # the material's first characters as character calls
    rest = hx[6:]
    whole = {
        "go raw string": ("x.go", f"package main\nfunc main() {{\nm := `{hx}`\n_ = m\n}}\n"),
        "go strings.Join": ("x.go", f'm := strings.Join([]string{{"{hx[:40]}", "{hx[40:80]}", "{hx[80:]}"}}, "")\n'),
        "go byte chars": ("x.go", f'm := string([]byte{{{c6}}}) + "{rest}"\n'),
        "ts template": ("x.ts", f"const m: string = `{hx}`;\n"),
        "r paste0": ("x.r", f'm <- paste0("{hx[:40]}", "{hx[40:80]}", "{hx[80:]}")\n'),
        "r collapse": ("x.r", f'm <- paste(c("{hx[:40]}", "{hx[40:]}"), collapse = "")\n'),
        "r raw string": ("x.r", f'm <- r"({hx})"\n'),
        "r intToUtf8": ("x.r", f'm <- paste0(intToUtf8(c({c6})), "{rest}")\n'),
        "ps here-string": ("x.psm1", f"$m = @'\n{hx}\n'@\n"),
        "ps char join": ("x.psm1", f"$m = (-join [char[]]({c6})) + '{rest}'\n"),
        "ahk continuation": ("x.ahk", f'm := "\n(\n{hx}\n)"\n'),
    }
    for name, (member, text) in whole.items():
        got = plan_codec.decode(text, Path(member).suffix)
        check(f"row 71: {name} reads the whole plan", bool(got) and got[0] == plan, str(got)[:120])
    pieces = {
        "go := then +=": ("x.go", f'm := "{head}"\nm += "{tail}"\n'),
        "ts typed let then +=": ("x.ts", f"let m: string = '{head}';\nm += '{tail}';\n"),
        "ahk := then .=": ("x.ahk", f'm := "{head}"\nm .= "{tail}"\n'),
        "r <- then paste0(m, ..)": ("x.r", f'm <- "{head}"\nm <- paste0(m, "{tail}")\n'),
        "r paste0 of variables": ("x.r", f'a <- "{head}"\nb <- "{tail}"\nm <- paste0(a, b)\n'),
    }
    for name, (member, text) in pieces.items():
        got = plan_codec.decode(text, Path(member).suffix)
        ok = bool(got) and (got[0] == plan or (got[0].endswith("|") and plan.startswith(got[0])))
        check(f"row 71: {name} gives the plan whole or without its last field, never a shortened value", ok, str(got)[:120])
    labels_seen = {
        "go :=": 'Codec_ab := "hex_compact|identity"\n',
        "r <-": 'Codec_ab <- "hex_compact|identity"\n',
        "ts typed": 'const Codec_ab: string = "hex_compact|identity";\n',
        "vba As String": 'Const Codec_ab As String = "hex_compact|identity"\n',
    }
    for name, text in labels_seen.items():
        check(f"row 71: the codec label behind {name} is read", plan_codec.label_of(text) == ["hex_compact", "identity"],
              str(plan_codec.label_of(text)))
    late = "v=1|adapter=fixture_adapter|campaign_id=LAB-71|steps=decode_configuration,return_configuration"
    for name, text in {
        "tcl set": f'set Codec_ab "hex_compact|identity"\nset Material_ab "{late.encode().hex()}"\n',
        "tcl braces": f'set Codec_ab "hex_compact|identity"\nset Material_ab {{{late.encode().hex()}}}\n',
        "vba Dim and Const": f'Const Codec_ab As String = "hex_compact|identity"\nDim Material_ab As String\n'
                             f'Material_ab = "{late.encode().hex()}"\n',
    }.items():
        got = label_plan.read_text(text)
        check(f"row 71: label_plan reads the {name} material by its label", got == late, str(got)[:120])
    applescript = 'set Codec_ab to "hex_compact|identity"\nset Material_ab to "' + late.encode().hex() + '"\n'
    check("row 71: AppleScript's `set .. to` is still read by its ` to `", label_plan.read_text(applescript) == late,
          str(label_plan.read_text(applescript))[:120])


def test_row_213():
    """Row 213: label_plan's bare-number readers read every number of a material or none. A decimal_space and a
    bare octal material with two numbers run together (the separator lost at a line end) give no plan, where they
    gave a whole plan with a campaign and a file path cut short."""
    import label_plan

    def run_together(nums):
        out = list(nums)
        for i in (PLAN.index("campaign-") + 12, PLAN.index("stage-") + 8):
            out[i], out[i + 1] = out[i] + out[i + 1], None
        return " ".join(x for x in out if x is not None)

    def spec(material, codec):
        return f'Codec_ab12="{codec}"\nMaterial_ab12="{material}"\necho "$Material_ab12"\n'

    dec = [str((b + 9) % 256) for b in PLAN.encode()]
    octs = [f"{b:03o}" for b in PLAN.encode()]
    whole = (label_plan.reading(spec(" ".join(dec), "decimal_space|add_modulo_256|09"))[0],
             label_plan.reading(spec(" ".join(octs), "octal|none|"))[0])
    check("row 213: a decimal_space and a bare octal material, every number written apart: the plan",
          whole == (PLAN, PLAN), str(whole)[:200])
    holed = [label_plan.reading(spec(run_together(dec), "decimal_space|add_modulo_256|09"))[0],
             label_plan.reading(spec(run_together(octs), "octal|none|"))[0],
             label_plan.reading(spec(run_together(octs), "zz|zz|zz"))[0]]
    check("row 213: the same with two numbers run together (labelled, and octal by the fallback): no plan",
          holed == [None, None, None], str(holed)[:200])
    member = "memory-stage.sh"
    qs = [question(f"sh-memory-stage-{f}", member, "?") for f in ("campaign", "adapter", "file-path")]
    with contextlib.redirect_stderr(io.StringIO()):
        out = generic.answers(qs, {member: spec(run_together(dec), "decimal_space|add_modulo_256|09").encode()}, {})
    check("row 213: every id of such a specimen None", all(v is None for v in out.values()), str(out)[:200])


def test_rows_56_58():
    """Rows 56 to 58 (2026-10-07), on synthetic fixtures of the languages a later day may bring.

    56  a material written over several lines (a here-document, a long bracket, a template or raw string,
        a here-string, a continuation section, a list over several lines joined with nothing) is read as
        ONE value, white space stripped: the whole plan, by plan_codec and by its codec label;
    57  base32, base85, z85, zlib and gzip streams, octal and 8-bit binary groups, one nested base64/hex level;
    58  material spelled one character a call (chr . chr, Chr & Chr, n.chr + n.chr, [char]n + ..), whatever
        the values.

    And the guard: such a value joined to other code, or holding what the language would expand, is never read
    whole: its plan comes without its last field, or not at all, never with a shortened last value."""
    import gzip
    import zlib
    import label_plan
    plan = ("v=1|steps=acquire_remote,write_file|adapter=curl_fetch|campaign_id=LAB-56-0042|"
            "url=https://cdn.example.invalid/a/b.bin|file_path=C:/ProgramData/lab/b.bin")
    kept = plan[:plan.rfind("|") + 1]
    raw = bytes(b ^ 0x5A for b in plan.encode())
    b64, hx = base64.b64encode(raw).decode(), raw.hex()

    def lines(s, n=48):
        return [s[i:i + n] for i in range(0, len(s), n)]

    def body(s, indent=""):
        return "\n".join(indent + x for x in lines(s))

    def whole(text, ext):
        got = plan_codec.decode(text, ext)
        return bool(got) and got[0] == plan

    def as_material(text):
        """The fixture with its variable `m` renamed Material_ab (`$m = `, `m := `, `const m: string = `, `m=$(`)."""
        return re.sub(r"(?m)^([ \t]*(?:const |local |my )?\$?)m(?=[ \t]*(?:[:=<]))", r"\1Material_ab", text, count=1)

    def never_short(text, ext):
        got = plan_codec.decode(text, ext)
        return got is None or (got[0] != plan and plan.startswith(got[0]) and got[0].endswith("|"))

    for rep, s in (("base64", b64), ("hex", hx)):
        blocks = {
            "php nowdoc": (".php", f"<?php\n$m = <<<'EOT'\n{body(s)}\nEOT;\n"),
            "php heredoc": (".php", f"<?php\n$m = <<<EOT\n{body(s)}\nEOT;\n"),
            "php indented closing marker": (".php", f"<?php\n$m = <<<'EOT'\n{body(s, '    ')}\n    EOT;\n"),
            "ruby <<~ with .delete(\"\\n\")": (".rb", f"m = <<~'EOT'.delete(\"\\n\")\n{body(s, '  ')}\n  EOT\n"),
            "perl here-document": (".pl", f"my $m = <<'EOT';\n{body(s)}\nEOT\nchomp $m;\n"),
            "shell here-document": (".sh", f"m=$(cat <<'EOF'\n{body(s)}\nEOF\n)\n"),
            "lua long bracket": (".lua", f"local m = [==[\n{body(s)}\n]==]\n"),
            "go raw string": (".go", f"package main\nfunc main() {{\n\tm := `\n{body(s)}\n`\n\t_ = m\n}}\n"),
            "typescript template": (".ts", f"const m: string = `\n{body(s)}\n`;\n"),
            "powershell here-string": (".psm1", f"$m = @'\n{body(s)}\n'@\n"),
            "powershell expandable here-string": (".psm1", f'$m = @"\n{body(s)}\n"@\n'),
            "r raw string": (".r", f'm <- r"(\n{body(s)}\n)"\n'),
            "autohotkey continuation": (".ahk", f'm := "\n(\n{body(s)}\n)"\n'),
            "php implode over lines": (".php", "<?php\n$m = implode('', [\n" + ",\n".join(f"    '{x}'" for x in lines(s)) + "\n]);\n"),
            "ruby list .join over lines": (".rb", "m = [\n" + ",\n".join(f"  '{x}'" for x in lines(s)) + "\n].join\n"),
            "typescript list .join('') over lines": (".ts", "const m: string = [\n" + ",\n".join(f"  '{x}'" for x in lines(s)) + "\n].join('');\n"),
            "go strings.Join over lines": (".go", "m := strings.Join([]string{\n" + ",\n".join(f'\t"{x}"' for x in lines(s)) + ',\n}, "")\n'),
            "r paste(c(..), collapse) over lines": (".r", "m <- paste(c(\n" + ",\n".join(f'  "{x}"' for x in lines(s)) + '\n), collapse = "")\n'),
            "vba Join(Array(..)) over lines": (".bas", "m = Join(Array( _\n" + ", _\n".join(f'    "{x}"' for x in lines(s)) + '), "")\n'),
            "powershell -join @(..) one item a line": (".psm1", "$m = -join @(\n" + "\n".join(f"    '{x}'" for x in lines(s)) + "\n)\n"),
        }
        for name, (ext, text) in blocks.items():
            check(f"row 56: {rep} in a {name}: the whole plan", whole(text, ext), str(plan_codec.reading(text, ext))[:160])
            labelled = as_material(text) + f'Codec_ab = "{rep}|single_byte_xor|5a"\n'
            check(f"row 56: {rep} in a {name}: the whole plan by its codec label", label_plan.reading(labelled) == (plan, False),
                  str(label_plan.reading(labelled))[:160])
    pieces = {
        "php heredoc joined after its closing marker": (".php", f"<?php\n$m = <<<'EOT'\n{body(b64[:-8])}\nEOT . '{b64[-8:]}';\n"),
        "ruby here-document joined on its opener's line": (".rb", f"m = <<~'EOT' + '{b64[-8:]}'\n{body(b64[:-8], '  ')}\n  EOT\n"),
        "typescript template joined after it": (".ts", f"const m: string = `\n{body(b64[:-8])}\n` + '{b64[-8:]}';\n"),
        "php heredoc appended to later": (".php", f"<?php\n$m = <<<'EOT'\n{body(b64[:-8])}\nEOT;\n$m .= '{b64[-8:]}';\n"),
        "a template with a substitution in it": (".ts", f"const m: string = `\n{body(b64[:-8])}${{tail}}\n`;\n"),
        "php heredoc with a variable in it": (".php", f"<?php\n$m = <<<EOT\n{body(b64[:-8])}$tail\nEOT;\n"),
        "php implode over lines with a variable item": (".php", "<?php\n$m = implode('', [\n" + ",\n".join(
            f"    '{x}'" for x in lines(b64[:-8])) + ",\n    $tail\n]);\n"),
    }
    # Review of row 56: the material split across two blocks (or a block and a variable) joined in ways the
    # operator guard does not see. Main read these cut (a wrapped bare block is always a piece); they must stay cut.
    h = len(b64) // 2 // 4 * 4
    A, B = body(b64[:h]), body(b64[h:])
    pieces.update({
        "two templates in a list joined": (".js", f"const m = [`\n{A}\n`, `\n{B}\n`].join('');\n"),
        "two templates in a list variable": (".js", f"const parts = [\n`\n{A}\n`,\n`\n{B}\n`\n];\nconst m = parts.join('');\n"),
        "two long brackets in table.concat": (".lua", f"local m = table.concat({{[[\n{A}\n]], [[\n{B}\n]]}})\n"),
        "two ruby here-documents joined as a list": (".rb", f"a = <<~E\n{A}\nE\nb = <<~E\n{B}\nE\nm = [a, b].join\n"),
        "two here-strings in -join @(..)": (".ps1", f"$a = @'\n{A}\n'@\n$b = @'\n{B}\n'@\n$m = -join @($a, $b)\n"),
        "two here-strings in -f": (".ps1", f"$a = @'\n{A}\n'@\n$m = '{{0}}{{1}}' -f $a, $tail\n"),
        "a template and a variable in .concat": (".ts", f"const a = `\n{A}\n`;\nconst m = a.concat(tail);\n"),
        "a template and a variable in a list": (".ts", f"const m = [`\n{A}\n`, tail].join('');\n"),
        "a template in a substitution": (".js", f"var a = `\n{A}\n`;\nvar m = `${{a}}${{tail}}`;\n"),
        "a nowdoc in {$a}{$tail}": (".php", f"<?php\n$a = <<<'EOT'\n{A}\nEOT;\n$m = \"{{$a}}{{$tail}}\";\n"),
        "a nowdoc in sprintf": (".php", f"<?php\n$a = <<<'EOT'\n{A}\nEOT;\n$m = sprintf('%s%s', $a, $tail);\n"),
        "two shell here-documents, the second appended": (".sh", f"cat > /tmp/x <<EOF\n{A}\nEOF\ncat >> /tmp/x <<EOF\n{B}\nEOF\n"),
        "a shell here-document, then printf >>": (".sh", f"cat > /tmp/x <<'EOF'\n{A}\nEOF\nprintf %s \"$tail\" >> /tmp/x\n"),
        # The neighbour guard alone: no join is visible, a second block of the alphabet is.
        "two blocks, the join out of sight": (".rb", f"a = <<~E\n{A}\nE\nb = <<~E\n{B}\nE\nm = assemble(:a)\n"),
        "a block and a one-line literal of its alphabet": (".rb", f"a = <<~E\n{A}\nE\nb = '{b64[h:]}'\nm = assemble(:a)\n"),
    })
    for name, (ext, text) in pieces.items():
        check(f"row 56 guard: {name}: never a shortened last value", never_short(text, ext), str(plan_codec.reading(text, ext))[:160])
    lp_piece = f"<?php\n$Material_ab = <<<'EOT'\n{body(b64[:-8])}\nEOT . $tail;\n$Codec_ab = 'base64|single_byte_xor|5a';\n"
    check("row 56 guard: a labelled here-document joined after its closing marker: label_plan gives it cut",
          label_plan.reading(lp_piece) in ((kept, True), (None, False)), str(label_plan.reading(lp_piece))[:160])

    forms = {
        "base32": base64.b32encode(raw).decode(), "base32 without padding": base64.b32encode(raw).decode().rstrip("="),
        "base85": base64.b85encode(raw).decode(),
        "z85": base64.b85encode(raw).decode().translate(str.maketrans(label_plan._B85, label_plan._Z85)),
        "zlib in base64": base64.b64encode(zlib.compress(raw)).decode(), "gzip in base64": base64.b64encode(gzip.compress(raw, mtime=0)).decode(),
        "zlib in hex": zlib.compress(raw).hex(), "octal groups": " ".join(f"{b:03o}" for b in raw),
        "octal groups with commas": ",".join(f"{b:03o}" for b in raw), "binary groups": " ".join(f"{b:08b}" for b in raw),
        "binary groups written together": "".join(f"{b:08b}" for b in raw),
        "base64 of hex text": base64.b64encode(hx.encode()).decode(), "hex of base64 text": b64.encode().hex(),
        "base64 of base64 text": base64.b64encode(b64.encode()).decode(),
    }
    for name, s in forms.items():
        q = "'" if '"' in s or "$" in s or "`" in s else '"'
        if q in s and q == "'":
            continue                       # the text holds both quotes: no plain literal spells it
        for ext, text in ((".rb", f"m = {q}{s}{q}\n"), (".bas", f'm = "{s}"\n' if '"' not in s else None)):
            if text is None:
                continue
            check(f"row 57: {name} ({ext}): the whole plan", whole(text, ext), str(plan_codec.reading(text, ext))[:160])
        lp = f"Material_ab = {q}{s}{q}\nCodec_ab = \"{name.replace(' ', '_')}|single_byte_xor|5a\"\n"
        check(f"row 57: {name}: the whole plan by its codec label", label_plan.read_text(lp) == plan, str(label_plan.read_text(lp))[:160])

    n = list(raw)
    chains = {
        "php chr(n) . chr(n)": (".php", "<?php\n$m = " + " . ".join(f"chr({x})" for x in n) + ";\n"),
        "php chr(n).chr(n) with no spaces": (".php", "<?php\n$m = " + ".".join(f"chr({x})" for x in n) + ";\n"),
        "vba Chr(n) & ChrW(n) over continued lines": (".bas", "m = " + " & _\n    ".join(
            " & ".join(f"ChrW({x})" for x in n[i:i + 12]) for i in range(0, len(n), 12)) + "\n"),
        "vba Chr(&Hnn)": (".bas", "m = " + " & ".join(f"Chr(&H{x:02X})" for x in n) + "\n"),
        "autohotkey Chr(n) . Chr(n)": (".ahk", "m := " + " . ".join(f"Chr({x})" for x in n) + "\n"),
        "ruby n.chr + n.chr": (".rb", "m = " + " + ".join(f"{x}.chr" for x in n) + "\n"),
        "lua string.char(..) .. string.char(..)": (".lua", "local m = " + " .. ".join(
            "string.char(" + ", ".join(map(str, n[i:i + 16])) + ")" for i in range(0, len(n), 16)) + "\n"),
        "typescript String.fromCharCode(..) + .. over lines": (".ts", "const m: string = " + " +\n  ".join(
            "String.fromCharCode(" + ", ".join(map(str, n[i:i + 16])) + ")" for i in range(0, len(n), 16)) + ";\n"),
        "powershell [char]n + [char]n": (".psm1", "$m = [string]'' + " + " + ".join(f"[char]{x}" for x in n) + "\n"),
    }
    for name, (ext, text) in chains.items():
        expect_whole = "powershell" not in name    # `[string]'' + ..`: a literal before the run, so the run is a piece
        ok = whole(text, ext) if expect_whole else never_short(text, ext)
        check(f"row 58: {name}: " + ("the whole plan" if expect_whole else "never a shortened last value"), ok,
              str(plan_codec.reading(text, ext))[:160])
        lp = as_material(text) + 'Codec_ab = "bytes|single_byte_xor|5a"\n'
        if expect_whole:
            check(f"row 58: {name}: the whole plan by its codec label", label_plan.reading(lp) == (plan, False),
                  str(label_plan.reading(lp))[:160])
    glued_chain = "<?php\n$m = " + " . ".join(f"chr({x})" for x in n[:-6]) + " . $tail;\n"
    check("row 58 guard: a run of chr() calls joined to a variable: never a shortened last value",
          never_short(glued_chain, ".php"), str(plan_codec.reading(glued_chain, ".php"))[:160])


def main() -> int:
    if not gm.CHALLENGES.is_dir():
        print(f"test_generic: no saved attempts under {gm.CHALLENGES}", file=sys.stderr)
        return 2
    with contextlib.redirect_stderr(io.StringIO()):
        corpus = load_variants(CORPUS_DAYS)
        day1 = load_variants(("day-01",))
        day5 = load_variants(("day-05",))
        day7 = day7_variants()
    keyed = [v for v in corpus if v["dir"].parent.name == "day-04" or
             (v["dir"].parent.parent.name == "day-04" and v["dir"].name in ("time_trial", "mastery"))]
    n = sum(len(list(specimens(v))) for v in corpus)
    print(f"corpus: {len(corpus)} sets, {n} specimens, {sum(len(v['qs']) for v in corpus)} answers under {gm.CHALLENGES}; "
          f"plus {len(day1)} Day 1 sets")
    # At least the 16 sets and 4 keyed Day 4 sets of before the variant harvest of 2026-10-06, which added more
    if len(corpus) < 16 or len(keyed) < 4:
        print(f"test_generic: expected at least the 16 saved sets of Days 2 to 4 with 4 keyed Day 4 sets, found {len(corpus)} and "
              f"{len(keyed)}", file=sys.stderr)
        return 2
    test_plans(corpus)
    test_regression(day1 + corpus, corpus, keyed)
    test_text_path(corpus)
    test_unknown(keyed)
    test_hide(corpus)
    test_failures(corpus)
    test_partial_and_only(corpus)
    test_default_branch(corpus)
    test_declined(corpus)
    test_unread_key(corpus)
    test_live_shapes(corpus)
    test_new_language()
    test_fields()
    test_material()
    if len(day5) == 4:
        test_unseen_component(day5)
        test_stress(day5)
    else:
        check("unseen component: the saved Day 5 base, Time Trial and Mastery (4 sets with their keys) are there", False,
              f"{len(day5)} sets found")
    test_hooks(corpus)
    test_wrapped(corpus)
    test_covers(corpus)
    test_one_plan(corpus)
    test_question_enum()
    test_hook_order()
    test_partial_before_text_path(corpus)
    test_own_generic(corpus)
    test_label_forms()
    test_day7(day7)
    test_rows_49_51(corpus, day1)
    test_row_71()
    test_row_213()
    test_rows_56_58()
    test_speed(corpus)
    failed = [name for name, ok in results if not ok]
    print(f"TEST_GENERIC passed={len(results) - len(failed)} failed={len(failed)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
