#!/usr/bin/env python3
"""Mobile live fix: the skeleton to copy to a role-owned day_patch_*_dev.py and fill in. Nothing loads this file.

  1. Copy the whole file beside codec_search.py as your unique candidate, for example
     day_patch_helper1_dev.py (owner/standby/helper2 use their own role).
  2. Set CODEC to the codec name in the puzzle document, HOW to one word for the reading,
     and write decode(). Shortest patch first: no essay here.
  3. Run `tools/promote.py mobile-android --day N <candidate>`; never write day_patch.py by hand.
  4. After PROMOTE OK, an owner/standby runs `tools/resume_ready.py publish --day N --lane mobile-android`;
     a helper adds `--require-exact`. The helper flag refuses any unsure/skipped saved answer; the ordinary
     path preserves untimed probing. Its consumer alone resumes the lane.

The contract (codec_search.py): answer(q, files, ctx) is asked only where the shipped
answer is None or unsure, never for a plain one. None declines, and the shipped answer
stays. Anything else is used, so return labels.pick(...) and only for an exact answer
code: unsure until the judge accepts the route on the untimed base, plain after that on
every variant. Never a default.

A WRONG PLAIN ANSWER of the shipped solver (the judge rejected it) is replaced one way only:
define override(q, answer, files, ctx) in day_patch.py (the commented function at the end of
this file). When it exists it is asked about EVERY question, after answer(), with the answer
that would be returned. What it returns:
  a text         replaces the answer: a plain value, or labels.pick(key, options)
  WITHDRAW       the answer becomes None (nothing is sent for the id)
  anything else  (None, the same answer) leaves the answer as it is
Each replacement prints `NOTE <id>: <old> replaced by day_patch.py (<new>)` on stderr; a raise
costs nothing, the answer stands. It is asked on every variant and every set of a Mastery, so
derive the replacement from the delivery, never from one variant's value. This template
defines no override, so as it stands it changes no answer.

When the package narrows the answer to a few DIFFERENT codes and nothing proves which one is
asked (backlog row 346), return a candidate pick, never one of them plain. Each option's name
names the HYPOTHESIS (where the code was read), never the value, best evidence first, at most 12:
    labels.candidates("mobile.codec/" + CODEC, [("document", code), ("asset_string", other)])
It stays unsure until the judge accepts a name (verify.py probes it on the base; run.py only on
an attempt with no deadline), and the accepted name answers the next variant plain.
"""
import io
import json
import re
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE.parent / "common") not in sys.path:
    sys.path.insert(0, str(HERE.parent / "common"))
import labels  # noqa: E402

PUZZLE = "assets/huntress_puzzle.json"
ANSWER = re.compile(r"ANS-[0-9A-F]{16}")
CODEC = "<name>"   # the document's codec name, lowercase
HOW = "<how>"      # the ledger remembers the route as <name>:<how>


def decode(p):
    """The answer code read from the parsed puzzle document `p`, or None."""
    return None  # <- write the decoding here


def document(files, ctx):
    """The puzzle document, parsed: from the set's delivery (the APK), else from what the runner unpacked."""
    try:
        with zipfile.ZipFile(io.BytesIO(ctx.get("delivery") or b"")) as zf:
            body = zf.read(PUZZLE)
    except Exception:
        body = files.get(PUZZLE)
    try:
        return json.loads(bytes(body).decode("utf-8-sig"))
    except Exception:
        return None


def answer(q, files, ctx):
    if "ANS-" not in json.dumps(q.get("answer_format") or "ANS-", default=str):
        return None  # the question asks for something other than the code
    p = document(files, ctx)
    if not isinstance(p, dict) or str(p.get("codec")).strip().lower() != CODEC:
        return None
    value = decode(p)
    if not (isinstance(value, str) and ANSWER.fullmatch(value)):
        return None
    return labels.pick("mobile.codec/" + CODEC, [("%s:%s" % (CODEC, HOW), value)])


WITHDRAW = "<<withdraw>>"   # what override() returns to take an answer back (codec_search.PATCH_WITHDRAW)

# Uncomment and fill in ONLY to replace or withdraw an answer the shipped solver gives plain and
# the judge rejected. `shipped` is what would be returned without this function.
# Write it exactly as `def override(` at the start of a line (column 0): the Metadata load check looks
# for that text in day_patch.py before it loads the patch, and a patch without it is never asked.
#
# def override(q, shipped, files, ctx):
#     p = document(files, ctx)
#     if not isinstance(p, dict) or str(p.get("codec")).strip().lower() != CODEC:
#         return None                               # every other document: leave it
#     value = decode(p)                             # the right reading of this codec
#     if not (isinstance(value, str) and ANSWER.fullmatch(value)):
#         return WITHDRAW                           # better no answer than the rejected one
#     return labels.pick("mobile.codec/" + CODEC, [("%s:%s" % (CODEC, HOW), value)])
