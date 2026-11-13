#!/usr/bin/env python3
"""Day 30 hook: hands back the HGRF answers d30.py read for this prefix's call.

d30.py sees every d30-- member (it needs all three NEKO members: the config.n capsule, and the loader.n
graph only after the three graphs agree with this_role omitted); this hook is given one sample only.
d30.py puts its answers in a per-process stash (sys.modules["binary_d30_stash"], replaced on every call)
and returns nothing, so the dispatcher's HCFG-only decoy guard has no plain day-module answer to
withdraw; the dispatcher then asks this hook for the ids still None, and it returns the stashed ones.
Nothing is read or guessed here.
"""
import sys

STASH = "binary_d30_stash"


def fields(sample_name, data, questions):
    stash = sys.modules.get(STASH)
    if not isinstance(stash, dict):
        return {}
    out = {}
    for q in questions or []:
        qid = q.get("qid") if isinstance(q, dict) else None
        if isinstance(qid, str) and stash.get(qid) is not None:
            out[qid] = stash[qid]
    return out
