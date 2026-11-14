#!/usr/bin/env python3
"""Script Analysis lane wiring for the deception machinery (wave3; adaptable-solver-upgrade-plan T2 + T4).

Makes two shared primitives LIVE in this lane with NO change to any judged answer:

  * render_candidates (solvers/common): a value the reader READ but whose RENDERING/label the judge
    has not yet accepted is offered as MORE unsure candidates. `enrich()` is wired into the UNSURE
    branch of analyze's day_patch path: it touches ONLY an answer that is already an ordinary unsure
    `labels.pick` (a read value whose name is unjudged), never a plain (judged) answer, never a `None`,
    and NEVER emits a plain value; it keeps the same key. `auto()` exposes render_candidates.pick_auto
    for a day_patch / reader that read a value but cannot name its rendering (row 346, never plain).

  * override_guard (tools/override_guard.py): a day_patch patch() may never replace or withdraw a
    judge-accepted plain answer. `guard_value()` is wired around analyze's day_patch patch application:
    it engages ONLY when the current answer is itself an accepted LABEL of the id's derived key (value
    == name) -- provably the judge's own. Otherwise it is a no-op, so a BAD/unjudged/None id, and a
    family-prior answer (whose key has no accepted name, so it stays overridable), are fixed as before.
    NOTE this lane withdraws with `None` (not the `<<withdraw>>` sentinel), so guard_value maps a
    proposed `None` to the guard's withdraw sentinel and hands `None` back for an allowed withdrawal.

Both are fail-safe: a helper that cannot be imported leaves the answer exactly as the reader produced
it. Nothing here reads bytes or the network; the caller already read the value. This is a NEW file --
no shipped solver's answer logic is changed.
"""
import importlib.util
import re
import sys
from pathlib import Path

LANE = "script"
_HERE = Path(__file__).resolve().parent
if str(_HERE.parent / "common") not in sys.path:
    sys.path.insert(0, str(_HERE.parent / "common"))
import labels  # noqa: E402

WITHDRAW = "<<withdraw>>"              # the guard's withdraw sentinel (this lane uses None instead)
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
        _OG["m"] = load_module("script_override_guard", root / "tools" / "override_guard.py",
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
    Returns `answer` unchanged unless it is an ORDINARY unsure labels.pick; never emits plain and never
    changes the key."""
    if not labels.is_unsure(answer):
        return answer
    parsed = labels.parse(answer)
    if parsed is None or parsed.candidate or not parsed.options:
        return answer
    rc = _rc()
    if rc is None:
        return answer
    af = q.get("answer_format") if isinstance(q, dict) else None
    if field is None and isinstance(q, dict):
        field = q.get("field")
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
    (a sibling `script.<field>/*` accepted set). A label->label refinement (a more specific accepted
    label read from the same bytes) is a correction the day_patch is permitted to make, so the guard
    must not block it; only a demotion/withdrawal (`None` here), or a replacement with a value that is
    NO family label (a genuinely wrong value for a judged id), is stopped. new-code audit H3. The
    withdrawal sentinel and an unsure labels value are never treated as a label."""
    if proposed is None or not isinstance(proposed, str) or proposed == WITHDRAW or labels.is_unsure(proposed):
        return False
    val = proposed.strip()
    if not val or not key or "/" not in key:
        return False
    try:
        return val in set(labels.family(key.split("/", 1)[0] + "/"))
    except Exception:
        return False


def derive_key(current):
    """The labels key `current` was produced under when that is cheaply knowable: labels.prior_of for a
    family-prior answer (whose key has no accepted name, so it stays overridable), else None. Script
    keys carry an ext and a shape (`script.attack/<ext>.stated_v3`) that cannot be reconstructed from
    the value alone, so the engagement rule below only protects an answer that IS an accepted label."""
    try:
        hit = labels.prior_of(current)
        if hit:
            return hit[0]
    except Exception:
        pass
    return None


def guard_value(qid, current, proposed, key=None):
    """override_guard.guard(...) for analyze's day_patch patch(), which withdraws with None (not the
    sentinel). Engages (protects) ONLY when `current` is itself an accepted LABEL of the derived (or
    passed) key -- provably the judge's own; a BAD/unjudged value and a family-prior answer are not,
    so the patch proceeds exactly as before. Returns (value, blocked, note): `value` is None for an
    allowed withdrawal, else the value to apply."""
    if key is None:
        key = derive_key(current)
    acc = _accepted(key)
    engaged = acc if (acc and isinstance(current, str) and current in acc) else set()
    if engaged and _family_label(key, proposed):          # a label->label refinement: permitted, not blocked
        engaged = set()
    og = _og()
    sent = WITHDRAW if proposed is None else proposed       # this lane withdraws with None
    if og is None:
        return proposed, False, ""                          # analyze's old behavior: apply as given
    value, blocked, note = og.guard(key or f"{LANE}.unknown/x", current, sent, engaged, withdraw=WITHDRAW)
    return value, blocked, note
