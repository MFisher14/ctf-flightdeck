# Carried verbatim by B-001b from huntress:tools/override_guard.py (16394a2c). The merge plan archived
# it as Huntress-specific, but it kept the day_patch override path it guards (solvers/{binary,mobile-android,
# script-analysis}/respell.py), which applied overrides unguarded, silently, without this file.
"""override_guard - a day_patch override() / patch() may never replace or withdraw a judge-accepted answer.

Adaptable-solver-upgrade-plan T4; backlog row 496. A lane's `day_patch.py` exists to answer, replace or
withdraw an UNJUDGED answer on a release morning: a new component, a drifted rendering, a shipped solver's
wrong PLAIN answer. It may never touch an answer the judge has already accepted for its key. On Day 23 a
Metadata owner's `override()` demoted a correct, Day-13-judged `msi.product_code_guid` value into the
all-or-nothing Time Trial batch and cost +57 min; nothing guarded the judge-accepted answer. This module is
the one guard a lane's override path routes through, so the mistake cannot recur.

It is pure (it reads only the arguments it is handed, plus a tracked seed dict and ledger rows when asked for
the accepted names), so a lane reader imports it and wraps its override with `guard(...)`; tests exercise it
directly. It only ever RESTRICTS an override (it keeps the current answer, it never changes one), so it can
never introduce a wrong answer.

Allowed, unchanged:
  - an override of an UNJUDGED answer (no accepted name for its key): this includes a genuinely-BAD id, whose
    plain answer the judge rejected, so its key has no accepted name and `is_judged()` is False -> the fix
    stands;
  - an override that adds an UNSURE value (labels.pick / labels.candidates) for an unjudged key, as before.

Blocked:
  - an override that would REPLACE or WITHDRAW a plain answer whose key the judge has accepted (the answer is
    the judge's own by the never-guess contract: a solver gives a plain answer under a judged key only when the
    fact and its rendering are accepted).
"""

WITHDRAW = "<<withdraw>>"        # what override() returns to take an answer back (the lanes' sentinel)
UNSURE_SENTINEL = "??"           # labels.SENTINEL: an unsure answer (labels.pick / labels.candidates)


def _is_unsure(value) -> bool:
    return isinstance(value, str) and value.lstrip().startswith(UNSURE_SENTINEL)


def accepted_names(key, *, ledger=None, seed=None) -> set:
    """The judge-accepted names for `key`, from a tracked seed (`solvers/<lane>/conventions.json` as a dict:
    `{key: {"accepted": name, "rejected": [...], "split": bool, ...}}`) and/or a sequence of ledger rows
    (`{"key", "name", "verdict", ...}` from `challenges/_ledger/<lane>.jsonl`). A name is accepted when the
    seed names it or a ledger row accepted it (`accepted`/`CORRECT`); a later `incorrect` on that very name
    for the key removes it. A `split` key keeps its accepted names, as `labels.pick` does."""
    out, rejected = set(), set()
    if isinstance(seed, dict):
        ent = seed.get(key)
        if isinstance(ent, dict):
            if ent.get("accepted"):
                out.add(ent["accepted"])
            for n in ent.get("rejected") or []:
                rejected.add(n)
    for row in ledger or ():
        if not isinstance(row, dict) or row.get("key") != key:
            continue
        name, verdict = row.get("name"), row.get("verdict")
        if not name:
            continue
        if verdict in ("accepted", "CORRECT"):
            out.add(name)
        elif verdict == "incorrect":
            rejected.add(name)
    return out - rejected


def is_judged(key, current, accepted) -> bool:
    """True when `current` is an answer the judge has accepted for `key`, which a day_patch override may not
    change: the key has at least one accepted name (`accepted` is a non-empty set, e.g. from accepted_names)
    and `current` is a plain answer (not None, not an unsure labels.pick / labels.candidates value). By the
    never-guess contract a solver gives a plain answer under a judged key only when the rendering is accepted,
    so such an answer IS the judge's; a BAD or unjudged id has no accepted name and is not protected.

    It deliberately checks only that `accepted` is non-empty, NOT that `current in accepted`: for a FORMAT or
    method key the accepted NAME (`braces_upper`) differs from the plain VALUE (`{AB-CD}`), yet that value is
    still the judge's and must be protected (the Day-23 msi.product_code_guid case this module exists for).
    The new-code audit's H3 fix lives entirely in the lane `respell.guard_value`, which does not engage the
    guard for a label->label refinement; `is_judged` is left as-is so format keys stay protected."""
    if current is None or _is_unsure(current):
        return False
    return bool(accepted)


def guard(key, current, proposed, accepted, *, withdraw=WITHDRAW):
    """Apply the override-guard to a day_patch's proposed change. Returns (value, blocked, note):

      - (current, True, <why>)  when `proposed` would REPLACE or WITHDRAW a judge-accepted answer: the
        override is refused and the judge's answer stands;
      - (<the override's normal result>, False, "")  otherwise: the answer is unjudged, or the override does
        not change it, so the override proceeds exactly as it did before this guard.

    `proposed` follows the override contract: a non-empty str replaces (a plain value or an unsure labels
    value), the withdraw sentinel makes the answer None, and anything else (None, "", the same value) leaves
    it. The caller uses `value` as the answer and may print `note` (one stderr line) when `blocked`."""
    # What the override would do on its own; only a real change is ever guarded.
    if not isinstance(proposed, str) or not proposed:
        return current, False, ""
    if proposed != withdraw and proposed == current:
        return current, False, ""
    if is_judged(key, current, accepted):
        verb = "withdraw" if proposed == withdraw else "replace"
        return current, True, (f"day_patch override refused for {key}: it would {verb} a judge-accepted answer; "
                               f"a live fix may change only an UNJUDGED answer (override-guard, row 496)")
    return (None if proposed == withdraw else proposed), False, ""
