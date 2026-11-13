#!/usr/bin/env python3
"""Binary lane wiring for the deception machinery (wave3; adaptable-solver-upgrade-plan T2 + T4).

Makes two shared primitives LIVE in this lane with NO change to any judged answer:

  * render_candidates (solvers/common): a value the reader READ but whose RENDERING/label the judge
    has not yet accepted is offered as MORE unsure candidates. `enrich()` is wired into the reader's
    UNSURE branch (evidence.solve_set, last): it touches ONLY an answer that is already an ordinary
    unsure `labels.pick` (a read value whose name is unjudged), never a plain (judged) answer and
    never a `None` (no read value to re-spell), and it NEVER emits a plain value. It keeps the same
    key, so probing is unchanged, and only ever APPENDS spellings that were not offered.
    `auto()` exposes render_candidates.pick_auto for a reader or a day_patch that read a value but
    cannot name its rendering (an unsure candidate set, row 346, never plain).

  * override_guard (tools/override_guard.py): a day_patch override() may never replace or withdraw a
    judge-accepted plain answer. `guard_value()` is wired around evidence.overridden(): it engages
    ONLY when the current answer is provably the judge's own for its key -- a family-prior answer
    (labels.prior_of carries the key), or a plain value that is itself an accepted label of the id's
    derived key (value == name). Otherwise it is a no-op, so a BAD/unjudged/None id is still fixed.

Both are fail-safe: a helper that cannot be imported leaves the answer exactly as the reader produced
it. Nothing here reads bytes or the network; the caller already read the value (that is where the
never-guess contract lives). This file is a NEW file -- no shipped solver's answer logic is changed.
"""
import importlib.util
import re
import sys
from pathlib import Path

LANE = "binary"                       # the labels lane prefix for this folder
_HERE = Path(__file__).resolve().parent
if str(_HERE.parent / "common") not in sys.path:
    sys.path.insert(0, str(_HERE.parent / "common"))
import labels  # noqa: E402  (the unsure-answer contract; parse/pick/unsure/state/prior_of)

WITHDRAW = "<<withdraw>>"              # what a day_patch override() returns to take an answer back
_SET = re.compile(r"^set\d+\.")

# --------------------------------------------------------------------------- lazy, fail-safe imports

_RC = {}


def _rc():
    """render_candidates from solvers/common (on sys.path), loaded once. None if it cannot load."""
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
        _OG["m"] = load_module("binary_override_guard", root / "tools" / "override_guard.py",
                               pack="tools/override_guard.py")
    return _OG["m"]


# --------------------------------------------------------------------------- wiring #1: render_candidates

def auto(key, value, answer_format=None, field=None):
    """render_candidates.pick_auto(key, value, answer_format, field): an unsure candidate re-spelling
    of a KNOWN value (row 346), never plain before the judge accepts a hypothesis. None if the module
    is absent or nothing can be rendered. For a reader / day_patch that read a value but cannot name
    its rendering."""
    rc = _rc()
    if rc is None:
        return None
    try:
        return rc.pick_auto(key, value, answer_format, field=field)
    except Exception:
        return None


def enrich(answer, q=None, field=None):
    """Offer render_candidates' re-spellings of a read-but-unjudged value as MORE unsure candidates.

    Returns `answer` unchanged unless it is an ORDINARY unsure `labels.pick` (a read value whose name
    is unjudged): a plain answer (judged), a `None`, an unparseable `??` string and a candidate pick
    are all returned untouched. The established value is taken from the pick's best option, classified
    by render_candidates, and the spellings not already offered are APPENDED under the SAME key (at
    most labels.MAX_OPTIONS). It never emits a plain value and never changes the key, so a judged
    answer can never move and the runner probes the reader's own spellings first."""
    if not labels.is_unsure(answer):
        return answer                                   # plain (judged) or None: never touched
    parsed = labels.parse(answer)
    if parsed is None or parsed.candidate or not parsed.options:
        return answer                                   # unparseable, or already a candidate set
    rc = _rc()
    if rc is None:
        return answer
    af = q.get("answer_format") if isinstance(q, dict) else None
    value = parsed.options[0][1]                         # the established fact, in its best spelling
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
        return answer                                    # nothing new: byte-identical
    try:
        return labels.unsure(parsed.key, merged)
    except Exception:
        return answer


def field_of(qid) -> str:
    """The binary field word of a question id: the id without any `setN.` and `dNN_analysis_`/`dNN_`
    prefix (`set2.d05_analysis_machine` -> `machine`)."""
    s = _SET.sub("", str(qid or ""))
    s = re.sub(r"^d\d+_analysis_", "", s)
    return re.sub(r"^d\d+_", "", s)


_MAGICS = (
    (b"\x7fELF", "elf"),
    (b"\0asm", "wasm"),
    (b"dex\n", "dex"),
    (b"\xfe\xed\xfa\xce", "macho"), (b"\xfe\xed\xfa\xcf", "macho"),
    (b"\xce\xfa\xed\xfe", "macho"), (b"\xcf\xfa\xed\xfe", "macho"),
    (b"\xca\xfe\xba\xbe", "macho_fat"),
    (b"PK\x03\x04", "zip"), (b"PK\x05\x06", "zip"), (b"PK\x07\x08", "zip"),
)


def container_of(files, prefix):
    """A cheap container word for the prefix's one sample (its leading magic), or None. Used only to
    build the derived key the override-guard looks up; a wrong guess just means no protection."""
    data = None
    try:
        for name, body in (files or {}).items():
            if not isinstance(body, (bytes, bytearray)):
                continue
            base = str(name).split(" -> ")[-1].split("/")[-1].lower()
            if base.startswith(str(prefix).lower()):
                data = bytes(body)
                break
    except Exception:
        return None
    if not data:
        return None
    for magic, tag in _MAGICS:
        if data[:len(magic)] == magic:
            return tag
    if data[:2] == b"MZ":
        return "pe"
    return None


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
    (a sibling `binary.<field>/*` accepted set). The derived key is container-shaped (magic bytes), so a
    native PE (`pe`) and a .NET PE (`pe_cli`) both collapse to `binary.format/pe`: `current` being an
    accepted label of that coarse key does NOT prove it is the judge's answer FOR THIS ID. A label->label
    refinement (`pe` -> `pe_cli`, more specific, read from the same bytes on an obfuscated .NET build the
    container check misread) is exactly the correction a day_patch is permitted to make, so the guard must
    not block it; only a demotion/withdrawal, or a replacement with a value that is NO family label (a
    genuinely wrong value for a judged id), is stopped. new-code audit H3."""
    if not isinstance(proposed, str) or proposed == WITHDRAW or labels.is_unsure(proposed):
        return False
    val = proposed.strip()
    if not val or not key or "/" not in key:
        return False
    try:
        return val in set(labels.family(key.split("/", 1)[0] + "/"))
    except Exception:
        return False


def derive_key(qid, current, files=None):
    """The labels key `current` was produced under, as precisely as this lane cheaply can:
    labels.prior_of(current) when it is a family-prior answer, else `binary.<field>/<container>`."""
    try:
        hit = labels.prior_of(current)
        if hit:
            return hit[0]
    except Exception:
        pass
    field = field_of(qid)
    if not field:
        return None
    prefix = _SET.sub("", str(qid or "")).split("_", 1)[0]
    container = container_of(files, prefix)
    return f"{LANE}.{field}/{container}" if container else None


def guard_value(qid, current, proposed, files=None):
    """override_guard.guard(...) with a safe engagement rule: engage (hand the guard the accepted
    names) ONLY when `current` is provably the judge's own for its key -- a family-prior answer, or a
    plain value that is itself an accepted LABEL of the derived key. Otherwise the accepted set is
    empty and the guard is a no-op, so a BAD/unjudged/None id is replaced/withdrawn exactly as before.

    Returns (value, blocked, note): `value` is the answer to keep, `blocked` True when a judge-accepted
    answer was protected, `note` a one-line reason to print when blocked."""
    key = derive_key(qid, current, files)
    acc = _accepted(key)
    # Engage (protect) ONLY when `current` is itself an accepted LABEL of the key (value == name): it is
    # then provably the judge's own rendering. A WRONG plain value of a judged field (a BAD id the patch
    # means to fix) is NOT in `acc`, so the fix proceeds; a family-prior answer's key has no accepted name
    # (acc is empty), so a prior guess stays overridable. This never wrongly blocks a fix.
    engaged = acc if (acc and isinstance(current, str) and current in acc) else set()
    if engaged and _family_label(key, proposed):          # a label->label refinement (pe -> pe_cli): permitted
        engaged = set()
    og = _og()
    if og is None:                                       # module absent: apply as the shipped code did
        if not isinstance(proposed, str) or not proposed or (proposed != WITHDRAW and proposed == current):
            return current, False, ""
        return (None if proposed == WITHDRAW else proposed), False, ""
    return og.guard(key or f"{LANE}.unknown/x", current, proposed, engaged, withdraw=WITHDRAW)
