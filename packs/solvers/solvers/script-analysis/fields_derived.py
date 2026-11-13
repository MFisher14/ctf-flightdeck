"""fields_derived.py -- DERIVED field registry for Script Analysis (buildplan T3, backlog row 492).

Loaded BY NAME from `generic.derived` (`plan_codec.optional("fields_derived")`), at the one point where
`generic.derived`'s own step-derived table (`DERIVED` / `DERIVED_LIST`) falls through to `return None`. It is
asked only for a question id that is still open after every reader, the census and `generic.derived`'s own
step words, so it can never move an answer another path already gave.

It answers NEW field words no day has judged, computed from the reconstructed version-3 plan dict and
`urllib.parse` ONLY, chosen by the id's FIELD WORD (`generic.tail_of(q)`) and its answer format, NEVER by a
word of the question text (the Day 12 lesson). The field words it closes, each a Day-25 look-ahead class-C gap
(`docs/retro/day-25-predictions-script-analysis.md`, specimens under
`challenges/_retro/day25-prep/script-analysis/specimens/C`):

  * url parts   -- `url-host` / `-hostname` / `-domain`, `url-port`, `url-scheme` / `-protocol`,
                   and `url-filename` / `url-leaf` (a single established fact: a part of the plan's url);
  * composite   -- a hyphenated field word that names a join of two plan profile fields
                   (`carrier-obfuscation` -> `base64|two_stage_download_execute`): offered as
                   `labels.candidates` of the pipe-joins of distinct plan profile fields, ranked by the field
                   word's own token hints (never plain before the judge accepts one hypothesis);
  * campaign    -- `campaign-prefix` / `-suffix` (the campaign identifier before the first / after the last dash).

Every value is UNSURE: `labels.pick` for a single established fact, `labels.candidates` for the composite. So
it is never plain until the judge accepts a name for the key, and can therefore NEVER answer WRONG. `None`
when any part it needs is missing, and `None` for a field word it does not recognise. Across variants the
field word is stable (the judge's vocabulary) while the value is recomputed from each variant's own plan, so
one accepted name answers the next variant with that variant's own value.
"""
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
for _p in (HERE, HERE.parent / "common"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

try:
    import labels
except Exception:  # noqa: BLE001 - without labels.py nothing can be unsure, so these answers stay None
    labels = None


def _slug(tail: str) -> str:
    return re.sub(r"[^a-z0-9_]", "_", str(tail or "").lower()).strip("_") or "field"


def _tail(q: dict) -> str:
    """The field word of the question, from generic.tail_of (its id's field), lowercased."""
    try:
        import plan_codec
        generic = plan_codec.own("generic")      # never `import generic`: solvers/binary has one too (SH-05)
        return (generic.tail_of(q) or "").lower()
    except Exception:  # noqa: BLE001
        return ""


def _kind(q: dict) -> str:
    fmt = q.get("answer_format")
    return str((fmt or {}).get("kind") or "").lower() if isinstance(fmt, dict) else ""


def _pick(key, options):
    """labels.pick over options whose value is a non-empty string; None without labels or options."""
    if labels is None:
        return None
    opts = [(n, v) for n, v in options if isinstance(v, str) and v != ""]
    if not opts:
        return None
    try:
        return labels.pick(key, opts)
    except Exception as e:  # noqa: BLE001 - a bad key costs one answer, not the set
        print(f"[fields_derived] labels.pick({key!r}) raised {type(e).__name__}: {e}", file=sys.stderr)
        return None


def _candidates(key, options):
    if labels is None:
        return None
    opts = [(n, v) for n, v in options if isinstance(v, str) and v != ""]
    if not opts:
        return None
    try:
        return labels.candidates(key, opts)
    except Exception as e:  # noqa: BLE001
        print(f"[fields_derived] labels.candidates({key!r}) raised {type(e).__name__}: {e}", file=sys.stderr)
        return None


# ----------------------------------------------------------------- url parts

def _url_part(tail: str, url: str):
    """(what, value) for a url-derived field word, or None. `what` is the hypothesis/rendering name; `value`
    is the single established fact. `None` value when the url has no such part."""
    toks = set(tail.split("-"))
    # Day 30 judged ``path-leaf`` as the last segment of the plan's file_path,
    # not of its URL.  Require URL to be explicit whenever the field also says
    # path; this removes a candidate only and can never widen a plain answer.
    if "path" in toks and "url" not in toks:
        return None
    if "url" not in toks and not (toks & {"host", "hostname", "domain", "port", "scheme", "protocol",
                                          "leaf", "filename", "basename"}):
        # not a url field word: 'url' must be present, or an unambiguous url-part token
        return None
    try:
        parts = urlsplit(url)
    except Exception:  # noqa: BLE001
        return None
    if not parts.scheme and not parts.netloc:
        return None
    if toks & {"scheme", "protocol"}:
        return ("scheme", parts.scheme or None)
    if "port" in toks:
        try:
            port = parts.port
        except ValueError:
            port = None
        return ("port", str(port) if port is not None else None)
    if toks & {"host", "hostname", "domain"}:
        return ("host", parts.hostname or None)
    if toks & {"leaf", "filename", "basename"} or tail.endswith("-leaf"):
        segs = [s for s in (parts.path or "").split("/") if s]
        return ("leaf", segs[-1] if segs else None)
    return None


# ----------------------------------------------------------------- composite a|b of two plan fields

# The plan's "profile"-shaped fields, in a stable order, each with the field-word tokens that point at it.
PROFILE_ORDER = ["obfuscation_profile", "stage_profile", "host_profile", "adapter"]
FIELD_TOKENS = {
    "obfuscation_profile": {"obfuscation", "obfuscate", "obfuscated", "encoding", "encode", "encoded",
                            "carrier", "packer", "packing"},
    "stage_profile": {"stage", "stages", "staged", "multistage", "multi", "relationship", "chain"},
    "host_profile": {"host", "container", "source"},
    "adapter": {"adapter", "adapt"},
}


def _composite(tail: str, plan: dict):
    """A labels.candidates options list of pipe-joins of two distinct plan profile fields, ranked by the field
    word's own token hints, or None when the field word hints no profile field. Each candidate's name is the
    HYPOTHESIS `a|b` (the pair of plan keys), never the value."""
    toks = set(tail.split("-"))
    if len(toks) < 2:
        return None
    present = [f for f in PROFILE_ORDER if isinstance(plan.get(f), str) and plan.get(f)]
    if len(present) < 2:
        return None
    if not any(FIELD_TOKENS[f] & toks for f in present):
        return None
    scored = []
    for i, a in enumerate(present):
        for j, b in enumerate(present):
            if a == b:
                continue
            score = 0.0
            if FIELD_TOKENS[a] & toks:
                score += 3.0
            if FIELD_TOKENS[b] & toks:
                score += 1.0
            if (a, b) == ("obfuscation_profile", "stage_profile"):
                score += 0.5          # the common encoding|multi-stage pairing, as a tie-break default
            scored.append((-score, i, j, a, b))
    scored.sort()
    return [(f"{a}|{b}", f"{plan[a]}|{plan[b]}") for _, _, _, a, b in scored]


# ----------------------------------------------------------------- the registry entry point

def derived(q: dict, info: dict):
    """The one call `generic.derived` makes. Returns an unsure answer (labels.pick / labels.candidates) for a
    NEW url / composite / campaign field word, or None. Never a plain answer of its own, so never WRONG."""
    try:
        plan = info.get("plan")
        if not isinstance(plan, dict) or str(plan.get("v")) != "3":
            return None
        tail = _tail(q)
        if not tail or tail.replace("-", "_") in plan:
            return None          # a plan key is answered by the general path, never derived here
        # An id in a form the lane does not know (a trailing `-vN` / `-N` / `.N` version or numeric suffix) is
        # NOT a new field word: `analyze.id_forms` renormalises it and re-asks under the known form, then wraps
        # the answer under `script.id_form/<transform>`. This hook must leave such an id alone, or it steals it
        # from id_forms (Day 13 preparation, the `-v2`-behind-every-id case; `tests/test_day13_script_gaps.py`,
        # R8). `host-profile-v2` tokenises to {host, profile, v2}, which would otherwise match a url/composite
        # field word by loose token membership. It never reaches a real base id (none is of an unknown form).
        if re.search(r"[-_.](?:v\d{1,3}|\d{1,3})$", tail):
            return None
        # "A word that is only a part of a version-3 plan key answers nothing" (lane rule, backlog row 273 b;
        # same test file, 273b): a single-token field word that is a component of a plan key -- `host` of
        # `host_profile`, `profile`/`stage`/`file` of the *_profile / file_path keys -- is not a derived field,
        # so e.g. a bare `-host` is never read as the url's host. A compound word (`url-host`, `path-leaf`) still
        # is, and a whole plan key was already returned above.
        if "-" not in tail and tail in {t for k in plan for t in str(k).split("_")}:
            return None
        import plan_codec
        ext = plan_codec.ext_name(info.get("ext")) or "ext"
        slug = _slug(tail)
        kind = _kind(q)
        toks = set(tail.split("-"))

        # campaign prefix / suffix (before the first / after the last dash of campaign_id)
        if "campaign" in toks and (toks & {"prefix", "suffix"}):
            camp = plan.get("campaign_id")
            if isinstance(camp, str) and "-" in camp:
                if "prefix" in toks:
                    return _pick(f"script.{slug}/{ext}.derived_campaign_prefix",
                                 [("prefix", camp.split("-", 1)[0])])
                return _pick(f"script.{slug}/{ext}.derived_campaign_suffix",
                             [("suffix", camp.rsplit("-", 1)[-1])])
            return None

        # url parts (scheme / port / host / path leaf)
        url = plan.get("url")
        if isinstance(url, str) and url:
            part = _url_part(tail, url)
            if part is not None:
                what, value = part
                if value is None:
                    return None
                return _pick(f"script.{slug}/{ext}.derived_url_{what}", [(what, value)])

        # composite a|b of two plan profile fields -- a bounded candidate list, exact_text only
        if kind != "integer":
            comp = _composite(tail, plan)
            if comp:
                return _candidates(f"script.{slug}/{ext}.derived_composite", comp)
        return None
    except Exception:  # noqa: BLE001 - a field nobody can derive is not answered (generic.derived also guards)
        return None
