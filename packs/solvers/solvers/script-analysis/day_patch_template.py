#!/usr/bin/env python3
"""Template for a Script Analysis day's day_patch.py: replace or withdraw answers the shipped solver
gives, a module's PLAIN ones too. The last resort of a run, after shapes_<ext>.py and lang_<ext>.py.

Copy this whole file to your unique role-owned candidate beside it, for example
`day_patch_helper1_dev.py` (`owner`, `helper2` and racers use their own role). Under that name it is inert:
analyze.py loads only `day_patch.py`, once per specimen, last. As shipped it also changes nothing
(patch() returns {}). Never write the final name by hand.

    # edit solvers/script-analysis/day_patch_<role>_dev.py, then:
    .venv/bin/python tools/promote.py script-analysis --day N solvers/script-analysis/day_patch_<role>_dev.py
    .venv/bin/python tools/resume_ready.py publish --day N --lane script-analysis   # helper adds --require-exact

Promotion serializes competing full candidates and replays every saved variant. Owner/standby publication keeps
the untimed unsure-probing path; a helper's `--require-exact` refuses any unsure/skipped saved answer. The consumer
alone runs the ordinary lane resume.

When this is the right file, and when it is not:

  shapes_<ext>.py   is asked only what is still open (None or unsure). Use it for a new field.
  lang_<ext>.py     answers an extension that has no module (through tools/promote.py, as `_dev` first).
  day_patch.py      the only file that can replace a plain answer of a shipped module or of the general
                    path. Use it when the judge rejects answers the solver gives plain: a re-worded
                    question, a rule that changed for an old component (Day 12, 2026-10-12: 219 old ids
                    were re-worded; 22 attack answers and 18 Batch answers were plain and wrong).

The call (analyze.solve_set, at the end of every specimen):

    patch(member, questions, answers, files) -> {qid: value}

  member      the specimen's file name as the readers saw it (`x.docm.bas` for a routed Office file)
  questions   the questions of this ONE specimen. q["qid"] is the id the answer goes under,
              q["field"] the id's field word (`attack`, `control`, `host-id`), q["answer_format"] the
              judge's own format (kind, syntax, accepted_values), q["question"] the text
  answers     {qid: value} so far, a copy: plain values, unsure ones (they start with `??`), and no
              entry for an id nobody answered
  files       {name: bytes} of the delivery as the readers saw it
  returns     {qid: value} for the ids to change and nothing else: a plain value, a labels.pick(..)
              or None to withdraw an answer. An id you leave out keeps its answer; an id of another
              specimen is ignored. One stderr line is printed per replaced answer.

Rules (AGENTS.md, "Uncertain answers"; the lesson of Day 12):

  - Choose the questions by their ID's field word and their answer format, never by a word of the
    question text: q["field"] == "attack", q["answer_format"]["kind"]. A text is re-worded without
    notice, and a patch keyed on a sentence stops working the day the sentence changes.
  - plain only for a fact read from the bytes under a name the judge has accepted for its key;
    labels.pick(key, options) for a fact whose name is not judged (options are spellings of ONE fact,
    best first; tools/verify.py probes them on the base); None when the fact is not established.
  - labels.candidates(key, options) when the bytes narrow a fact to a few DIFFERENT values and nothing
    proves which one the judge asks (backlog row 346: a stated attack beside the graph's). Each
    option's name names the HYPOTHESIS, never the value, best evidence first, at most 12; unsure until
    the judge accepts a name (verify.py probes it on the base; the ladder only on an attempt with no
    deadline), then plain on the next variant with that variant's value:
        labels.candidates("script.attack/xyz.v3", [("stated", plan.get("attack")), ("graph", from_steps)])
  - A patch that raises costs nothing: the solver's answers stand. Keep it fast, it runs inside the
    timed window for every specimen.
  - After the day the patch is folded into the modules and this file's copy is deleted
    (tests/test_script_rewording.py holds the folded reading against every saved key).

Before resuming the lane (no Game Master request is made):

  .venv/bin/python tools/preflight.py --replay <attempt dir>      # equals_key, missing, unsure
"""
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
for _p in (HERE, HERE.parent / "common"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import labels  # noqa: E402,F401  (labels.pick for an unsure answer)


def _generic():
    """The lane's own generic.py as analyze.py loaded it (solvers/binary has a generic.py too), or None."""
    for key in ("generic", "script_analysis_generic"):
        mod = sys.modules.get(key)
        try:
            if mod is not None and Path(getattr(mod, "__file__", "") or "").resolve() == HERE / "generic.py":
                return mod
        except OSError:
            pass
    return None


def field(q) -> str:
    """The id's field word: q["field"] (analyze.py sets it), else the id without its first two words."""
    got = q.get("field")
    if isinstance(got, str) and got:
        return got
    parts = re.sub(r"^set\d+\.", "", str(q.get("qid") or q.get("id") or "")).split("-", 2)
    return parts[2] if len(parts) == 3 else "-".join(parts)


def plain(value) -> bool:
    return isinstance(value, str) and value != "" and not value.startswith("??")


# ----------------------------------------------------------------------------- fill in

def answer(q, member, current, files):
    """The new value for ONE question, `KEEP` to leave its answer as it is, or None to withdraw it.

    `current` is the solver's answer (plain, unsure, or None when there is none). Example skeletons:

        # the plan of the specimen, as the general path reads it:
        # gen = _generic(); data = gen.find(files, member) if gen else None
        # plan = gen.read(member, data).get("plan") or {} if data is not None else {}

        # one field of one extension, unsure until the judge accepts a name:
        # if field(q) == "attack" and member.endswith(".xyz"):
        #     return labels.pick("script.attack/xyz.new_rule", [("stated", plan.get("attack"))])

        # withdraw a plain answer the judge rejected, so that it is not sent again:
        # if field(q) == "control" and current == "for_once":
        #     return None
    """
    return KEEP    # <- write the day's reading here
# ----------------------------------------------------------------------------- fixed


KEEP = "\x00keep"


def patch(member, questions, answers, files):
    out = {}
    for q in questions or ():
        qid = q.get("qid")
        try:
            got = answer(q, member, answers.get(qid), files)
        except Exception as e:  # noqa: BLE001 - one question must not cost the specimen
            print(f"[day_patch] {qid} raised {type(e).__name__}: {e}", file=sys.stderr)
            continue
        if got != KEEP and got != answers.get(qid):
            out[qid] = got
    return out


if __name__ == "__main__":
    sys.exit(__doc__)
