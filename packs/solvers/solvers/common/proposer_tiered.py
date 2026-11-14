"""The two-tier proposer (the proposer families build, step 4): the deterministic enumerator first, the model after it.

    propose(questions, files, ctx, deadline) -> {qid: [(hypothesis_name, value), ...]}   (best first, <= 12)

The enumerator (proposer_enum.py with proposer_families.py) answers every open id. The model tier
(proposer_model.py, the headless Claude CLI) is asked ONLY for the ids of the two families it is better at:

  (d) author vocabulary labels: an enum that is not true/false, or a text answer whose id names a classification
      (storage, class, kind, type, label, category, method, technique, role, transform, encoding, carrier, ...);
  (e) unknowns: an id the enumerator has nothing or only weak evidence for (no candidate, or its best one scored
      under WEAK), or a slug / ANS- code its decoders did not reach.

Its prompt (proposer_model.SYSTEM, the paragraph on labels and unknowns) asks for label candidates read from the
question's own wording and from the bytes, and for values DIFFERENT from what the enumerator already offers (sent
as `already_offered`). Its candidates are merged AFTER the enumerator's: the enumerator's first KEEP (8) stay where
they are, the model's new values follow, then the enumerator's rest, cut to 12. One exception, for an enum only: the
model's first pick, when the enumerator lists it lower, moves to rank 2 (the model breaks the enumerator's ties; the
enumerator's own first stays first). `CTF_TIER_PROMOTE=0` turns that off.

Without the CLI (no binary, no login, CTF_PROPOSER_MODEL=off) or past the deadline it is exactly the
enumerator. Never plain, never raises; the model's calls are cut at the deadline (proposer_model's rules: no tools,
an empty folder, only HOME/PATH/USER/LOGNAME/TMPDIR/LANG in its environment, never the Game Master token).
"""
import importlib.util
import os
import re
import sys
import time
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import env as ctf_env
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import env as ctf_env

HERE = Path(__file__).resolve().parent
MAX = 12
KEEP = 8
WEAK = 18.0
PROMOTE = ctf_env.get("CTF_TIER_PROMOTE", "1") != "0"
LABEL_WORDS = {"storage", "class", "classification", "kind", "type", "label", "category", "method", "technique", "role",
               "family", "form", "mode", "style", "transform", "encoding", "carrier", "layout", "scheme", "profile",
               "strategy", "obfuscation", "expansion", "control", "packing", "placement", "location", "container"}


def _load(name):
    spec = importlib.util.spec_from_file_location(f"tier_{name}_{abs(hash(str(HERE)))}", HERE / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_MODS = {}


def _mod(name):
    if name not in _MODS:
        _MODS[name] = _load(name)
    return _MODS[name]


def family_of(q, ctx, enum_cands, top):
    """'d', 'e' or None: which ids go to the model tier."""
    E = _mod("proposer_enum")
    spec = E.Spec(q, ctx)
    if spec.accepted and {a.lower() for a in spec.accepted} != {"true", "false"}:
        return "d"
    if spec.form == "text" and set(spec.field_toks) & LABEL_WORDS:
        return "d"
    if not enum_cands or top is None or top < WEAK:
        return "e"
    if spec.form in ("slug", "ans") and top < 30:
        return "e"
    return None


def merge(spec_accepted, enum_cands, model_cands, rejected=()):
    out, seen = [], set()

    def key(v):
        return v.strip().casefold()

    for nm, v in enum_cands[:KEEP]:
        if key(v) not in seen:
            seen.add(key(v))
            out.append((nm, v))
    new = [(nm, v) for nm, v in model_cands if key(v) not in seen and v not in rejected
           and (not spec_accepted or v in spec_accepted)]
    if PROMOTE and spec_accepted and model_cands:
        first = model_cands[0][1]
        idx = next((i for i, (_, v) in enumerate(out) if key(v) == key(first)), None)
        if idx is not None and idx > 1:
            out.insert(1, out.pop(idx))
    for nm, v in new:
        if key(v) not in seen:
            seen.add(key(v))
            out.append((nm, v))
    for nm, v in enum_cands[KEEP:]:
        if key(v) not in seen:
            seen.add(key(v))
            out.append((nm, v))
    return out[:MAX]


def propose(questions, files, ctx, deadline):
    E = _mod("proposer_enum")
    t0 = time.time()
    sink = {}
    # the enumerator gets at most half the budget (it needs a fraction of a second almost always)
    e_deadline = min(float(deadline), t0 + max(1.0, (float(deadline) - t0) * 0.5))
    try:
        got = E.propose(questions, files, dict(ctx, _score_sink=sink), e_deadline)
    except Exception as e:
        print(f"proposer_tiered: enumerator: {type(e).__name__}: {e}", file=sys.stderr)
        got = {}
    want = [q for q in questions if q.get("qid") in set(ctx.get("open") or [])]
    fam = {q["qid"]: family_of(q, ctx, got.get(q["qid"]), sink.get(q["qid"])) for q in want}
    ask = [q["qid"] for q in want if fam[q["qid"]]]
    if not ask or time.time() > float(deadline) - 2.0:
        return got
    try:
        M = _mod("proposer_model")
        if not M.cli_ok():
            return got
        mctx = dict(ctx, open=ask, tier_model_only=True,
                    tier_offered={qid: [v for _, v in got.get(qid, [])][:12] for qid in ask},
                    tier_family={qid: fam[qid] for qid in ask})
        model = M.propose(questions, files, mctx, deadline)
    except Exception as e:
        print(f"proposer_tiered: model: {type(e).__name__}: {e}", file=sys.stderr)
        return got
    out = dict(got)
    rej = ctx.get("rejected") or {}
    for q in want:
        qid = q["qid"]
        if qid not in ask:
            continue
        acc = [str(a) for a in ((q.get("answer_format") or {}).get("accepted_values") or [])]
        out[qid] = merge(acc, got.get(qid, []), model.get(qid, []), [str(x) for x in rej.get(qid, [])])
    return out
