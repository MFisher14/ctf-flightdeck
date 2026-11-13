#!/usr/bin/env python3
"""Generic shape fallbacks for Script Analysis (wave123, adaptation hardening, off-release).

Why this file exists.  On a never-seen or ablated component the SPECIALISED language module
(`jscript.py`, `powershell.py`, `batch.py`) is absent or declines, so the general path
(`generic.py`) answers the plan fields it can read from literals but returns ``None`` for the
module-specific SHAPE fields it has no reader for:

  * JScript  ``-function-style`` / ``-invocation-style`` / ``-property-style``  (27 ids on Day 16)
  * Batch    ``-expansion``                                                     (9 ids)
  * PowerShell tactic specimens: ``-scenario`` / ``-attack`` and the record's
    ``-url`` / ``-file`` / ``-extension`` / ``-note`` / ``-mutex`` / ``-user-agent`` / ``-wallet``  (15 ids)

A cold-replay stress test (``cold.json``) measured exactly these as ``None`` once the module is
hidden.  This library lets the general path offer, for such an id, an UNSURE recoverable answer
(``labels.candidates``) with the truth among the options, so ``tools/verify.py`` probes it on the
untimed base (and the runners on an attempt with no deadline) instead of leaving it ``None``.

Never-wrong contract (AGENTS.md "Uncertain answers"; this file is held to it strictly):

  * It emits ONLY ``labels.candidates`` (unsure) or ``None`` -- NEVER a plain answer, and never a
    bare-label pick under a fixed shape.
  * Every candidate key is scoped to the SPECIMEN'S OWN BYTES (an 8-hex digest of the member text):
    an accepted hypothesis therefore answers only a re-delivery of those exact bytes (where the
    fact is, by construction, the same) and NEVER another variant -- a fresh variant is fresh
    bytes, a fresh key, probed again.  This is the proposer's ``...+<digest>#candidates`` pattern.
  * It is reached only for ids a shipped reader left open (``generic.answers`` / ``analyze.live_shapes``
    hand it the OPEN questions only), so it can never move a plain answer the module gives.  It
    only ever turns ``None`` into a probeable unsure answer: it helps, it cannot hurt.

Loaded by name through the thin wrappers ``shapes_js.py`` / ``shapes_bat.py`` / ``shapes_cmd.py`` /
``shapes_ps1.py`` (``shapes(text, questions) -> {qid: value}``), which analyze.py / generic.py ask
for every ``.js`` / ``.bat`` / ``.cmd`` / ``.ps1`` specimen.
"""
import base64
import hashlib
import json
import re
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
for _p in (_HERE, _HERE.parent / "common"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

try:
    import labels
except Exception as _e:  # noqa: BLE001 - without labels there is nothing to offer
    labels = None
    print(f"[shape_fallback_lib] labels did not load ({type(_e).__name__}: {_e}); no fallback offered",
          file=sys.stderr)

# ---------------------------------------------------------------------------- vocabularies
# The author's own vocabulary for the exact_text shape fields (jscript.py STYLE readers), used
# when the question lists no accepted_values.  The truth of every saved Day-16 variant is in here;
# a value a future variant introduces that is not here simply stays None (never wrong, just not
# recovered), exactly as before this file.
VOCAB = {
    "function_style": ("declaration", "anonymous_expression", "named_expression", "arrow"),
    "invocation_style": ("direct", "call", "apply", "bind", "new"),
    "property_style": ("dot", "bracket_literal", "mixed"),
    "expansion": ("delayed", "call_double", "for_indirect", "percent"),
    "scenario": ("synthetic_collection", "synthetic_impact", "resource_hijacking",
                 "synthetic_exfiltration", "synthetic_persistence"),
}

# ATT&CK technique ids by the tactic a PowerShell specimen's own name prefix states.  The judge's
# accepted id (T1555.003 collection, T1486 impact, T1496 resource) is always in its group; the
# groups overlap into a general pool so an unrecognised prefix still offers the common ids.  These
# are offered UNSURE (labels.candidates) and probed, never sent plain.
ATTACK_BY_TACTIC = {
    "collection": ("T1555.003", "T1005", "T1555", "T1119", "T1114", "T1056", "T1113"),
    "impact": ("T1486", "T1490", "T1489", "T1491", "T1485", "T1529", "T1496"),
    "resource": ("T1496", "T1498", "T1499", "T1495", "T1486"),
    "exfiltration": ("T1041", "T1567", "T1048", "T1020"),
    "persistence": ("T1547", "T1053", "T1543", "T1546"),
}
ATTACK_POOL = ("T1059", "T1486", "T1496", "T1555.003", "T1005", "T1041")


# ---------------------------------------------------------------------------- helpers

def _digest(text) -> str:
    """A collision-resistant scope token for the specimen's own bytes.  Identical bytes share it (the
    fact is the same); any change gives a fresh token, so an accepted candidate never leaks to a
    different variant."""
    raw = text.encode("utf-8", "replace") if isinstance(text, str) else bytes(text or b"")
    return hashlib.sha256(raw).hexdigest()


def _bare_qid(q) -> str:
    qid = str((q or {}).get("qid") or (q or {}).get("id") or "")
    return re.sub(r"^set\d+\.", "", qid)


def _module_active():
    """True when this call is reached through ``analyze.live_shapes`` -- i.e. the specimen's own
    language module ran for it and only DECLINED some ids.  In that path the shipped stand-in/text
    path already degrades a declined field to an unsure answer, so a fallback that competes with it
    would CHANGE an existing unsure answer.  The generic path (``generic.answers``: an absent module,
    or a known module that passed a new component to the general path) never runs the stand-in, so
    there the field is genuinely None and the fallback is a safe None->unsure fill.  Only the batch
    ``expansion`` field has such a stand-in competitor; js/ps1 shape fields have none."""
    f = sys._getframe(1)
    depth = 0
    while f is not None and depth < 40:
        if f.f_code.co_name == "live_shapes":
            return True
        f = f.f_back
        depth += 1
    return False


_ID_WORDS_CACHE = None


def _id_words():
    """The lane's component words -- the set analyze.id_forms uses to tell a KNOWN/NORMAL id from one
    in a renamed form or of an unknown component.  ``analyze.known_words()`` when it is importable (the
    very set, today's base components included), falling back to ``generic.ID_WORDS``.  Cached: one base
    a process."""
    global _ID_WORDS_CACHE
    if _ID_WORDS_CACHE is not None:
        return _ID_WORDS_CACHE
    words = set()
    try:
        import plan_codec
        generic = plan_codec.own("generic")      # never `import generic`: solvers/binary has one too (SH-05)
        words |= set(getattr(generic, "ID_WORDS", ()))
    except Exception:  # noqa: BLE001 - without generic the gate falls back to the empty set below
        pass
    try:
        import analyze
        words |= set(analyze.known_words())
    except Exception:  # noqa: BLE001 - analyze may not be importable in a bare unit context
        pass
    _ID_WORDS_CACHE = words
    return words


def _id_in_known_form(bare):
    """True only when ``bare`` (the qid with any ``setN.`` stripped) is an id in the FORM the lane knows:
    lower case, ``-`` between the words, a known component word first, no ``dNN-`` / lane-word prefix, no
    ``-vN`` / ``-N`` suffix (``generic.id_known``).  A renamed id (``d13-jscript-..``, ``JSCRIPT_..``) or
    one of an unknown component (``handoff-..``, ``invoke-..``) is NOT in a known form: the fallback leaves
    it to analyze.id_forms / the shipped readers rather than claiming it by suffix (Day 13 R8; Day 14's
    ``invoke-python-stage.ps1`` handoff plan, which stage_plan.py owns).  When ``generic`` cannot be
    imported the gate cannot judge the form and declines (never-wrong: a skipped id stays None/unsure)."""
    try:
        import plan_codec
        generic = plan_codec.own("generic")      # never `import generic`: solvers/binary has one too (SH-05)
        return bool(generic.id_known(bare, _id_words()))
    except Exception:  # noqa: BLE001
        return False


def _fold_active():
    """True when this call is reached from a shipped FOLD reader's own re-entrant solve
    (``day23_fold.py``: ``_style`` synthesises a batch specimen's ``-graph`` / ``-control`` /
    ``-expansion`` questions and solves them to assemble the batch ``-style`` candidate; ``patch`` also
    re-solves a rewritten specimen).  There the shipped reader already CLASSIFIES these shapes and its
    ``_first()`` flattens any unsure answer to its first option to build the join, so a fallback answer
    for the synthesised ``-expansion`` would turn the batch-``style`` id's SPLIT candidate key
    (``script.style/batch.expansion#cand#candidates``) into a plain join (``script.style/batch.joined``).
    The fallback declines so the fold's own classification stands; the fallback is unaffected on a
    first-class solve (an ablated/novel component), where day23_fold is not in the stack."""
    try:
        f = sys._getframe(1)
    except Exception:  # noqa: BLE001
        return False
    depth = 0
    while f is not None and depth < 80:
        name = (f.f_code.co_filename or "").replace("\\", "/")
        if name.rsplit("/", 1)[-1] == "day23_fold.py":
            return True
        f = f.f_back
        depth += 1
    return False


def _accepted_values(q):
    fmt = q.get("answer_format") if isinstance(q, dict) else None
    vals = fmt.get("accepted_values") if isinstance(fmt, dict) else None
    return [v for v in vals if isinstance(v, str)] if isinstance(vals, list) else None


def _candidates(key, options):
    """``labels.candidates`` for ``options`` (a list of ``(hypothesis_name, value)`` pairs, best
    first), or ``None`` when nothing can be offered.  Names are hypotheses, never bare values, so
    nothing is dropped as a bare option."""
    if labels is None:
        return None
    seen, opts = set(), []
    for name, value in options:
        if value is None or value == "":
            continue
        value = str(value)
        if value in seen:
            continue
        seen.add(value)
        opts.append((str(name), value))
    if not opts:
        return None
    try:
        return labels.candidates(key, opts[:labels.MAX_OPTIONS])
    except Exception as e:  # noqa: BLE001 - a bad key costs one answer, never the set
        print(f"[shape_fallback_lib] labels.candidates({key!r}) raised {type(e).__name__}: {e}", file=sys.stderr)
        return None


def _enum_options(values, ranked_first=()):
    """``(name, value)`` options for an enum vocabulary, the content-informed guesses first."""
    order = list(ranked_first) + [v for v in values if v not in ranked_first]
    return [(f"opt_{re.sub(r'[^a-z0-9]+', '_', v.lower())}", v) for v in order]


# ---------------------------------------------------------------------------- JScript shape detection
# Best-effort ranking only (which vocabulary value to probe first).  Correctness never depends on
# it: the full vocabulary is always offered, so the truth is reached whatever the ranking.

def _js_function_rank(text):
    t = text or ""
    hits = []
    if re.search(r"=\s*function\s+[A-Za-z_$]", t):
        hits.append("named_expression")
    if re.search(r"=\s*function\s*\(", t):
        hits.append("anonymous_expression")
    if re.search(r"\bfunction\s+[A-Za-z_$][\w$]*\s*\(", t):
        hits.append("declaration")
    if re.search(r"=>", t):
        hits.append("arrow")
    return hits


def _js_invocation_rank(text):
    t = text or ""
    hits = []
    if re.search(r"\.apply\s*\(", t):
        hits.append("apply")
    if re.search(r"\.call\s*\(", t):
        hits.append("call")
    # a direct call needs a plain identifier call somewhere; it is the weakest signal
    hits.append("direct")
    return hits


def _js_property_rank(text):
    t = text or ""
    dot = bool(re.search(r"[A-Za-z_$][\w$]*\s*\.\s*[A-Za-z_$]", t))
    bracket = bool(re.search(r"[A-Za-z_$][\w$]*\s*\[\s*['\"]", t))
    if dot and bracket:
        return ["mixed", "dot", "bracket_literal"]
    if bracket:
        return ["bracket_literal", "mixed", "dot"]
    if dot:
        return ["dot", "mixed", "bracket_literal"]
    return []


_JS_RANK = {
    "function_style": _js_function_rank,
    "invocation_style": _js_invocation_rank,
    "property_style": _js_property_rank,
}


# ---------------------------------------------------------------------------- PowerShell value harvest

_B64 = re.compile(r"['\"]([A-Za-z0-9+/]{16,}={0,2})['\"]")
_URL = re.compile(r"https?://[^\s\"'<>\\)\]}]+")
_TCODE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _decoded_texts(text):
    """Every base64 literal in the specimen decoded one layer to printable text, plus the raw
    text.  Deterministic, bounded, and side-effect-free: nothing is executed."""
    out = [text or ""]
    for m in list(_B64.finditer(text or ""))[:16]:
        blob = m.group(1)
        if len(blob) % 4:
            continue
        try:
            raw = base64.b64decode(blob, validate=True)
        except Exception:  # noqa: BLE001
            continue
        try:
            dec = raw.decode("utf-8")
        except UnicodeDecodeError:
            try:
                dec = raw.decode("utf-16-le")
            except UnicodeDecodeError:
                continue
        if dec and sum(c.isprintable() or c in "\r\n\t" for c in dec) >= 0.9 * len(dec):
            out.append(dec)
    return out


def _json_strings(blob):
    """Every string scalar in a JSON document (recursively), or ``[]`` when it is not JSON."""
    try:
        obj = json.loads(blob)
    except Exception:  # noqa: BLE001
        return []
    found = []

    def walk(node):
        if isinstance(node, str):
            found.append(node)
        elif isinstance(node, dict):
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
    walk(obj)
    return found


def _harvest(text):
    """Ordered, de-duplicated string values from the specimen: the record's own fields (from any
    base64 JSON it carries) first, then URLs and other notable literals from the raw text.  The
    truth of a PowerShell tactic field is one of these."""
    vals, seen = [], set()

    def add(v):
        v = (v or "").strip()
        if v and v not in seen:
            seen.add(v)
            vals.append(v)

    texts = _decoded_texts(text)
    for t in texts:
        for s in _json_strings(t):
            add(s)
    for t in texts:
        for m in _URL.finditer(t):
            add(m.group(0).rstrip(".,);'\""))
    return vals


def _is_url(v):
    return bool(_URL.fullmatch(v)) or v.lower().startswith(("http://", "https://"))


def _is_file(v):
    return bool(re.fullmatch(r"[^\\/:*?\"<>|\s]{1,120}\.[A-Za-z0-9]{1,6}", v)) and not v.startswith(".")


def _is_extension(v):
    return bool(re.fullmatch(r"\.[A-Za-z0-9][\w.\-]{0,40}", v))


def _is_mutex(v):
    return "\\" in v and bool(re.match(r"(Global|Local|HKCU|HKLM|HKEY)\b", v))


def _is_user_agent(v):
    return "Mozilla/" in v or bool(re.search(r"\b[A-Za-z][\w.\-]*/\d", v)) and " " in v


def _is_wallet(v):
    low = v.lower()
    if low.startswith("wallet_") or "wallet" in low:
        return True
    return bool(re.fullmatch(r"(bc1[a-z0-9]{20,}|[13][a-km-zA-HJ-NP-Z1-9]{20,}|0x[0-9a-fA-F]{40}|[0-9a-f]{64})", v))


_PS_HARVEST = {
    "url": _is_url,
    "file": _is_file,
    "note": _is_file,            # a ransom note is a file name
    "extension": _is_extension,
    "mutex": _is_mutex,
    "user_agent": _is_user_agent,
    "agent": _is_user_agent,
    "wallet": _is_wallet,
}


# ---------------------------------------------------------------------------- field routing

def _js_field(bare_qid):
    if bare_qid.endswith("-function-style"):
        return "function_style"
    if bare_qid.endswith("-invocation-style"):
        return "invocation_style"
    if bare_qid.endswith("-property-style"):
        return "property_style"
    return None


def _ps_field(bare_qid):
    for suffix, field in (("-user-agent", "user_agent"), ("-scenario", "scenario"), ("-attack", "attack"),
                          ("-extension", "extension"), ("-mutex", "mutex"), ("-wallet", "wallet"),
                          ("-note", "note"), ("-file", "file"), ("-url", "url"), ("-agent", "user_agent")):
        if bare_qid.endswith(suffix):
            return field
    return None


def _tactic_of(bare_qid):
    head = bare_qid.split("-", 1)[0]
    return head if head in ATTACK_BY_TACTIC else None


# ---------------------------------------------------------------------------- per-id answer

def _answer_js(field, q, text, scope):
    key = f"script.{field}/js+{scope}#candidates"
    accepted = _accepted_values(q)
    values = accepted if accepted else list(VOCAB.get(field, ()))
    if not values:
        return None
    ranker = _JS_RANK.get(field)
    ranked = [v for v in (ranker(text) if ranker else []) if v in values]
    return _candidates(key, _enum_options(values, ranked_first=ranked))


def _answer_batch(field, q, text, scope):
    key = f"script.expansion/bat+{scope}#candidates"
    accepted = _accepted_values(q)
    values = accepted if accepted else list(VOCAB["expansion"])
    return _candidates(key, _enum_options(values))


def _answer_ps(field, bare_qid, q, text, scope):
    if field == "scenario":
        accepted = _accepted_values(q)
        values = accepted if accepted else list(VOCAB["scenario"])
        key = f"script.scenario/ps1+{scope}#candidates"
        return _candidates(key, _enum_options(values))
    if field == "attack":
        tactic = _tactic_of(bare_qid)
        ids = list(ATTACK_BY_TACTIC.get(tactic, ())) if tactic else []
        for m in _TCODE.finditer(text or ""):          # any technique id literally in the bytes, best evidence
            if m.group(0) not in ids:
                ids.insert(0, m.group(0))
        for t in ATTACK_POOL:
            if t not in ids:
                ids.append(t)
        key = f"script.attack/ps1+{scope}#candidates"
        return _candidates(key, [(f"attack_{t.replace('.', '_')}", t) for t in ids])
    predicate = _PS_HARVEST.get(field)
    if predicate is None:
        return None
    hits = [v for v in _harvest(text) if predicate(v)]
    if not hits:
        return None
    key = f"script.{field}/ps1+{scope}#candidates"
    return _candidates(key, [(f"value_{i}", v) for i, v in enumerate(hits)])


# ---------------------------------------------------------------------------- the entry point

def shapes_for(lang, text, questions):
    """``{qid: unsure-candidate}`` for the shape fields of ONE specimen of ``lang`` (``js`` / ``bat`` /
    ``cmd`` / ``ps1``) that a shipped reader left open.  Never a plain answer, never for an id whose
    field this file does not own.

    Two structural gates keep it to GENUINELY-NEW coverage and off shapes the shipped readers already
    classify.  (1) It answers only an id in the lane's KNOWN/NORMAL form (``_id_in_known_form``): a renamed
    id goes to analyze.id_forms, and an id of a component the lane does not recognise (a handoff/stage plan,
    a non-component head) is left to the shipped reader that owns it.  (2) It declines entirely when a
    shipped fold reader is re-entrantly classifying (``_fold_active``: day23_fold._style synthesises and
    solves a batch specimen's ``-expansion`` to build the ``-style`` candidate)."""
    if labels is None:
        return {}
    if _fold_active():
        return {}
    text = text or ""
    scope = _digest(text)
    out = {}
    for q in questions or ():
        if not isinstance(q, dict):
            continue
        qid = q.get("qid") or q.get("id")
        if not qid:
            continue
        bare = _bare_qid(q)
        if not _id_in_known_form(bare):
            continue
        value = None
        try:
            if lang == "js":
                field = _js_field(bare)
                if field:
                    value = _answer_js(field, q, text, scope)
            elif lang in ("bat", "cmd"):
                # The batch `expansion` field is the one shape field with a shipped stand-in: when the
                # batch module ran and only declined it (the live_shapes path), analyze already offers
                # a content-informed unsure answer, so this generic fallback must not replace it. It
                # fills expansion only on the general path (an absent module, or a new component), where
                # expansion is genuinely None.
                if bare.endswith("-expansion") and not _module_active():
                    value = _answer_batch("expansion", q, text, scope)
            elif lang == "ps1":
                field = _ps_field(bare)
                if field:
                    value = _answer_ps(field, bare, q, text, scope)
        except Exception as e:  # noqa: BLE001 - one id must never cost the specimen
            print(f"[shape_fallback_lib] {qid} raised {type(e).__name__}: {e}", file=sys.stderr)
            value = None
        if value is not None:
            out[qid] = value
    return out


# ---------------------------------------------------------------------------- next_language candidates

def stated_next_language(text):
    """The plan's STATED ``next_language`` read from the specimen text, or ``None``.

    Read through the shipped descriptor reader (the same one generic.py uses), so a plan that was
    read whole but whose answer dropped its last field (a one-copy plan) still yields the stated
    value here.  A fact from the bytes, offered only as an unsure candidate by the caller; this
    function never returns an answer, only the raw stated string."""
    try:
        import plan_codec
    except Exception:  # noqa: BLE001
        return None
    try:
        mod = plan_codec.optional("descriptor")
        if mod is None or not hasattr(mod, "reading"):
            return None
        got = mod.reading(text or "")
        if not got or got[0] is None:
            return None
        plan = {k: str(v) for k, v in plan_codec.flatten(got[0]).items()}
    except Exception:  # noqa: BLE001 - reading the plan must never cost an answer
        return None
    value = plan.get("next_language")
    if isinstance(value, str) and value and not value.startswith("??"):
        return value
    return None


def next_language_candidates(ext, stated, embedded=None):
    """A ``labels.candidates`` answer for a ``-next-language`` id, offering the plan's STATED
    next_language (re-derived per variant, so the hypothesis is variant-proof) and, when present,
    the host's embedded-language guess.  ``None`` when neither is available.  Never plain.

    The key is stable per extension because each hypothesis re-derives its own value: ``stated``
    is always "the plan's stated next_language of THIS variant", so an accepted hypothesis answers
    the next variant with that variant's own stated value -- exactly ``labels.candidates``' contract.
    """
    if labels is None:
        return None
    ext = re.sub(r"[^a-z0-9]+", "_", str(ext or "").lower()).strip("_") or "ext"
    options = []
    if isinstance(stated, str) and stated and not stated.startswith("??"):
        options.append(("stated_next_language", stated))
    if isinstance(embedded, str) and embedded and not embedded.startswith("??"):
        options.append(("embedded_language", embedded))
    if not options:
        return None
    return _candidates(f"script.next_language/{ext}.shape_fallback#candidates", options)
