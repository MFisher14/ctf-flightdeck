#!/usr/bin/env python3
"""Mobile lane wiring for the deception machinery (wave3; adaptable-solver-upgrade-plan T2 + T4).

Makes two shared primitives LIVE in this lane with NO change to any judged answer:

  * render_candidates (solvers/common): a value the reader READ but whose RENDERING/label the judge
    has not yet accepted is offered as MORE unsure candidates. `enrich()` is wired into the UNSURE
    branch of codec_search's day_patch path (_overridden): it touches ONLY an answer that is already
    an ordinary unsure `labels.pick` (a read value whose name is unjudged), never a plain (judged)
    answer, never a `None` (no read value to re-spell), and NEVER emits a plain value; it keeps the
    same key, so probing is unchanged. `auto()` exposes render_candidates.pick_auto for a day_patch
    or a reader that read a value but cannot name its rendering (row 346, never plain).

  * override_guard (tools/override_guard.py): a day_patch override() may never replace or withdraw a
    judge-accepted plain answer. `guard_value()` is wired around codec_search._overridden(): it
    engages ONLY when the current answer is provably the judge's own for its key (a family-prior
    answer, or a plain value that is itself an accepted label of the id's derived key). Otherwise it
    is a no-op, so a BAD/unjudged/None id (a WRONG plain code the day_patch means to fix) is replaced
    or withdrawn exactly as before.

Both are fail-safe: a helper that cannot be imported leaves the answer exactly as the reader produced
it. Nothing here reads bytes or the network; the caller already read the value. This is a NEW file --
no shipped solver's answer logic is changed.
"""
import importlib.util
import re
import sys
from pathlib import Path

LANE = "mobile"
_HERE = Path(__file__).resolve().parent
if str(_HERE.parent / "common") not in sys.path:
    sys.path.insert(0, str(_HERE.parent / "common"))
import labels  # noqa: E402

WITHDRAW = "<<withdraw>>"
_SET = re.compile(r"^set\d+\.")

_RC = {}


def _rc():
    if "m" not in _RC:
        try:
            import render_candidates as m  # noqa: E402
            _RC["m"] = m
        except Exception:
            _RC["m"] = None
    return _RC["m"]


_OG = {}


def _og():
    """tools/override_guard.py (carried by B-001b), loaded by path once. A day_patch override is never
    applied without it: a guard that is not there or does not import raises PackMissing / PackLoadError
    (ctf/packs.py), where the forks applied the override unguarded (a judge-accepted answer could be
    replaced: the Day 23 msi.product_code_guid case, row 496)."""
    if "m" not in _OG:
        root = _HERE.parent.parent
        if str(root) not in sys.path:
            sys.path.append(str(root))     # appended, never first: the repo root must not shadow a lane module
        from ctf.packs import load_module
        _OG["m"] = load_module("mobile_override_guard", root / "tools" / "override_guard.py",
                               pack="tools/override_guard.py")
    return _OG["m"]


# --------------------------------------------------------------------------- wiring #1: render_candidates

def auto(key, value, answer_format=None, field=None):
    """render_candidates.pick_auto: an unsure candidate re-spelling of a KNOWN value (row 346). None
    if the module is absent or nothing renders. For a day_patch / reader that read a value but cannot
    name its rendering."""
    rc = _rc()
    if rc is None:
        return None
    try:
        return rc.pick_auto(key, value, answer_format, field=field)
    except Exception:
        return None


def enrich(answer, q=None, field=None):
    """Offer render_candidates' re-spellings of a read-but-unjudged value as MORE unsure candidates.
    Returns `answer` unchanged unless it is an ORDINARY unsure labels.pick; never emits plain and
    never changes the key. (An ANS- code classifies to no kind, so a codec answer is left as it is.)"""
    if not labels.is_unsure(answer):
        return answer
    parsed = labels.parse(answer)
    if parsed is None or parsed.candidate or not parsed.options:
        return answer
    rc = _rc()
    if rc is None:
        return answer
    af = q.get("answer_format") if isinstance(q, dict) else None
    value = parsed.options[0][1]
    try:
        kind = rc.classify(af, value, field)
        extra = rc.render(value, kind) if kind else []
    except Exception:
        return answer
    if not extra:
        return answer
    have = {v for _, v in parsed.options}
    names = {n for n, _ in parsed.options}
    merged = list(parsed.options)
    for n, v in extra:
        if v in have:
            continue
        nm, i = n, 2
        while nm in names:
            nm = f"{n}_{i}"
            i += 1
        merged.append((nm, v))
        have.add(v)
        names.add(nm)
        if len(merged) >= labels.MAX_OPTIONS:
            break
    if len(merged) == len(parsed.options):
        return answer
    try:
        return labels.unsure(parsed.key, merged)
    except Exception:
        return answer


# --------------------------------------------------------------------------- wiring #2: override_guard

def _field(qid) -> str:
    return _SET.sub("", str(qid or ""))


def _accepted(key):
    if not key:
        return set()
    try:
        st = labels.state(key)
        return set() if st.get("split") else set(st.get("accepted_names") or ())
    except Exception:
        return set()


def _family_label(key, proposed) -> bool:
    """True when the PROPOSED override value is itself a judge-accepted LABEL of the SAME field family
    (a sibling `mobile.<field>/*` accepted set). A label->label refinement (a more specific accepted
    label read from the same bytes) is a correction the day_patch is permitted to make, so the guard
    must not block it; only a demotion/withdrawal, or a replacement with a value that is NO family
    label (a genuinely wrong value for a judged id), is stopped. new-code audit H3."""
    if not isinstance(proposed, str) or proposed == WITHDRAW or labels.is_unsure(proposed):
        return False
    val = proposed.strip()
    if not val or not key or "/" not in key:
        return False
    try:
        return val in set(labels.family(key.split("/", 1)[0] + "/"))
    except Exception:
        return False


def derive_key(qid, current):
    """The labels key `current` was produced under, as precisely as this lane cheaply can:
    labels.prior_of(current), else a best-effort `mobile.<field>/apk`. (A mobile codec answer's key
    is `mobile.codec/<codec>`, a format key whose name is not the value, so the engagement rule below
    does not protect it -- that is the safe choice: it is never wrongly blocked.)"""
    try:
        hit = labels.prior_of(current)
        if hit:
            return hit[0]
    except Exception:
        pass
    field = _field(qid)
    return f"{LANE}.{field}/apk" if field and field != "answer" else None


def guard_value(qid, current, proposed):
    """override_guard.guard(...) with a safe engagement rule: engage only when `current` is provably
    the judge's own -- a family-prior answer, or a plain value that is itself an accepted LABEL of the
    derived key. Otherwise the accepted set is empty and the guard is a no-op, so a WRONG plain code
    (a BAD id) the day_patch means to fix is replaced/withdrawn exactly as before.

    Returns (value, blocked, note)."""
    key = derive_key(qid, current)
    acc = _accepted(key)
    # Engage (protect) ONLY when `current` is itself an accepted LABEL of the key (value == name): a WRONG
    # plain value (a BAD id) is not in `acc`, so the fix proceeds. A mobile codec answer is a method key
    # (name != value), so it is not protected -- the safe choice: it is never wrongly blocked.
    engaged = acc if (acc and isinstance(current, str) and current in acc) else set()
    if engaged and _family_label(key, proposed):          # a label->label refinement: permitted, not blocked
        engaged = set()
    og = _og()
    if og is None:
        if not isinstance(proposed, str) or not proposed or (proposed != WITHDRAW and proposed == current):
            return current, False, ""
        return (None if proposed == WITHDRAW else proposed), False, ""
    return og.guard(key or f"{LANE}.unknown/x", current, proposed, engaged, withdraw=WITHDRAW)
