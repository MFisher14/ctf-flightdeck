#!/usr/bin/env python3
"""Template for a new Script Analysis day's shapes_<ext>.py: answer ONE open field of a specimen,
read from the bytes, never guessed.

Backlog row 193, the companion of fields_template.py (Binary) and day_patch_template.py
(Metadata, Mobile). Copy this file to shapes_<ext>.py (`<ext>` the lowercase extension of the
file the open ids name: shapes_php.py, shapes_lua.py). Under its own name this file is inert:
generic.py loads only `shapes_<ext>.py` for an `<ext>` a specimen carries, and `template` is never
a real extension, so nothing imports or runs it. As shipped it also answers nothing (FIELD is
blank and answer() returns None), so copying it and running the replay changes no base.

    cp solvers/script-analysis/shapes_template.py solvers/script-analysis/shapes_php.py   # then edit

What generic.py does with it (see solvers/script-analysis/generic.py and the worked examples
shapes_py.py, shapes_text.py): for a specimen whose extension has no language module it calls

    shapes(text, questions) -> {qid: value}

once, with the specimen's decoded text and the questions it could not already answer. A plain
answer given here is FINAL for that specimen, so this file is asked only what the general path
left open. Return a value only for the one field you came to answer; leave everything else out.

Never guess (AGENTS.md, "Uncertain answers"). The answer names are the judge's own vocabulary:

  plain            only a fact you read from the bytes whose name or format the judge has already
                   accepted for that key. A shape name the judge has not seen is NEVER plain.
  labels.pick(key, options)
                   the fact is established from the bytes but its name is not judged: `options`
                   are spellings of that ONE fact, best first, snake_case first, in the author's
                   style. tools/verify.py probes them on the untimed base; the accepted name is
                   then plain on this variant and the next.
  None             the fact is not established. Never a default, never the most common value.

Key spellings (so Layer 1 and the racers share your key for the same construct):

  control flow     script.control/<ext>.<keyword>   (<keyword> from the names already in
                   conventions.json: none, if_guard, goto_dispatch, call_subroutine,
                   errorlevel_guard, select, do, while, for, on_error)
  ATT&CK           script.attack/<ext>              (a launcher/staged_chain takes the script's
                   own interpreter technique)
  role (new steps) script.role/<ext>.<steps>        (a step list the judged table does not hold)
  stated role/attack in an extension the judge has not seen
                   script.role/<ext>.stated_v<n>, script.attack/<ext>.stated_v<n>

Before resuming the lane (no Game Master request is made):

  .venv/bin/python tools/missing_field.py <attempt dir> <missing answer id>   # candidate readings
  .venv/bin/python solvers/script-analysis/shapes_template.py <specimen>      # your reading of a file
  .venv/bin/python tools/preflight.py --replay <attempt dir> --solver solvers/script-analysis/analyze.py
"""
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
for _p in (HERE, HERE.parent / "common"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import labels  # noqa: E402

# ----------------------------------------------------------------------------- fill in
EXT = "<ext>"      # the specimen's extension, lowercase (set it when you rename the file)
FIELD = ""         # the id suffix of the ONE field this file answers ("control", "role", ...);
                   # blank keeps the file inert


def answer(q, text):
    """The value for ONE question `q` of a specimen whose text is `text`, or None.

    Read the fact from `text`, then return labels.pick(<key>, [(name, value), ...]) (unsure) or a
    plain value only for a name the judge has already accepted. Return None for every other
    question, and for this one when the fact is not established. Example skeletons:

        # a control-flow shape, unsure until the judge accepts a name:
        # return labels.pick(f"script.control/{EXT}.{keyword}", labels.patterns(keyword, "control"))

        # a role read from a new step list:
        # return labels.pick(f"script.role/{EXT}.{'+'.join(steps)}", role_names)
    """
    return None    # <- write the reading of your one field here
# ----------------------------------------------------------------------------- fixed


def _qid(q) -> str:
    return re.sub(r"^set\d+\.", "", str(q.get("qid") or q.get("id") or ""))


def _wanted(q) -> bool:
    """Whether this question is the one field FIELD names (its id is exactly FIELD or ends in it)."""
    if not FIELD:
        return False
    qid = _qid(q)
    return qid == FIELD or qid.endswith("-" + FIELD) or qid.endswith("_" + FIELD)


def shapes(text, questions) -> dict:
    """{qid: value} for the open questions this file answers. Empty while FIELD is blank or
    answer() returns None, so the file is inert as shipped (generic.py keeps its own answers)."""
    out = {}
    for q in questions or ():
        if not isinstance(q, dict) or not _wanted(q):
            continue
        try:
            value = answer(q, text)
        except Exception as e:  # noqa: BLE001 - one question must not cost the specimen
            print(f"[shapes_{EXT}] {_qid(q)} raised {type(e).__name__}: {e}", file=sys.stderr)
            continue
        if value is not None and value != "":
            out[q.get("qid") or q.get("id")] = value
    return out


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        sys.exit(__doc__)
    for arg in sys.argv[1:]:
        try:
            raw = Path(arg).read_bytes()
        except OSError as e:
            print(f"{arg}: cannot be read ({e.strerror or e})")
            continue
        body = raw.decode("utf-16", "replace") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") \
            else raw.decode("utf-8", "replace")
        got = answer({"qid": FIELD or "<field>"}, body) if FIELD else None
        print(f"{arg}: FIELD={FIELD or '(unset: template is inert)'} -> {got!r}")
