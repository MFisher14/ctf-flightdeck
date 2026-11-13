"""Day 8 (owner): the `HUNTRESS_ANALYSIS_V1:<TAG>-<payload>` descriptor of the polyglot PHP and host specimens.

The specimen stores its whole plan (v=3|language=...|role=...|attack=...|adapter=...|host_profile=...|
obfuscation_profile=...|stage_profile=...|next_language=...|stage_count=...|steps=a,b|campaign_id=...|url=...|
file_path=...) in a comment tagged by its encoding (B64, HEX, HB64 = hex of base64, FRAG = hex pieces joined by
'.') and again in a `$descriptor_<id>` / string literal. Nothing is run.

Since rows 101 and 113 (2026-10-08) the reading is descriptor.py's, which generic.py asks first for every
extension; this file stays as the by-name net of .php and answers only what the general path left open
(shapes_js.py and shapes_vbs.py, which re-exported it for the host specimens, are gone: the general path
reads those itself, and their names shadowed the scratch files of test_generic.py). It no longer has a reader
of its own: the
Day 8 one stopped a payload at the first character outside its set and took a plan's prefix for a plan, so a
mangled copy was answered with cut values (`host-profile=hta_js`, `url=https://php-`). Now a descriptor is
read whole or not at all (descriptor.reading: the comment to its line end, the literal as the whole right-hand
side, both the same plan, stage_count equal to the number of steps), and nothing is answered unless every
asked field is in the plan.

shapes(text, questions) -> {qid: value}: each question's field is read from the end of its id.
"""
import sys
from pathlib import Path

_here = str(Path(__file__).resolve().parent)
if _here not in sys.path:
    sys.path.insert(0, _here)

import plan_codec  # noqa: E402

FIELDS = [  # id suffix -> plan key, longest first
    ("next-language", "next_language"),
    ("stage-profile", "stage_profile"),
    ("host-profile", "host_profile"),
    ("stage-count", "stage_count"),
    ("obfuscation", "obfuscation_profile"),
    ("file-path", "file_path"),
    ("campaign", "campaign_id"),
    ("adapter", "adapter"),
    ("attack", "attack"),
    ("steps", "steps"),
    ("role", "role"),
    ("url", "url"),
]
# The plan version whose own role= and attack= the judge accepted in these three extensions (Day 8).
STATED_VERSION = "3"


def read(text):
    """The flat plan of the file's descriptor when it is ONE whole plan, else None."""
    mod = plan_codec.optional("descriptor")
    if mod is None or not hasattr(mod, "reading"):
        return None
    got = mod.reading(text)
    if not got or got[0] is None:
        return None
    return {k: str(v) for k, v in plan_codec.flatten(got[0]).items()}


def _field(qid, q=None):
    # An id whose specimen's ids were compared (generic.with_fields) names its field exactly: `graph-attack`
    # is not the attack question (Day 13 preparation; generic.renamed holds such a field unsure, and this
    # net must not answer it plain when that answer is withdrawn).
    field = q.get("field") if isinstance(q, dict) else None
    if isinstance(field, str) and field:
        return dict(FIELDS).get(field)
    for suf, key in FIELDS:
        if qid == suf or qid.endswith("-" + suf):
            return key
    return None


def shapes(text, questions):
    plan = read(text)
    out = {}
    if not plan:
        return out
    asked = {(q.get("qid") or q.get("id")): _field(q.get("qid") or q.get("id") or "", q) for q in questions}
    if any(key and key not in plan for key in asked.values()):
        return out                  # row 113: an asked field the plan lacks is a plan cut between two fields
    for q in questions:
        qid = q.get("qid") or q.get("id")
        key = asked.get(qid)
        if not key:
            continue
        v = plan[key]
        if v == "" or (key in ("role", "attack") and plan.get("v") != STATED_VERSION):
            continue
        if key == "steps":
            v = ">".join(x for x in v.split(","))
        acc = ((q.get("answer_format") or {}).get("accepted_values"))
        if acc and v not in acc:
            continue
        out[qid] = v
    return out


if __name__ == "__main__":
    for path in sys.argv[1:]:
        print(path, read(open(path, encoding="utf-8", errors="replace").read()))
