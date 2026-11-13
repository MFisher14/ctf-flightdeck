"""Clue-driven POST exploit class for the Layer-1 ``proof_hunt`` web opener (B-233).

Layer-1 ``proof_hunt``/``web_open`` only ever issued GET requests, so every POST-bodied Huntress web
class (stored-XSS, session-fixation, upload->template-injection, SSTI, second-order-SQLi,
mass-assignment, forge-event, unsigned-state tamper, double-spend race, OS-command-injection, reset
request+redeem, GraphQL read, audit-report, queue owner-binding) fell to an agent. This module adds the
missing **clue-driven POST** step: it reads the target's own clue feed (``/api/clues``) for the
advertised ``feature_route`` and its parameter name(s), derives the per-day technique from the clue
*shape*, sends the bounded state-changing request **only** when explicitly armed and only to the
clue-advertised route, and banks **only** a novel ``proof_<32 hex>`` read from a follow-up GET.

Two independent gates must both open before any non-GET reaches the wire:

1. **The wire gate (B-007 / Open O-2).** Every ``proof_hunt`` WebClient is driven in ``get_only`` mode
   until the player settles Open O-2 (may Layer 1 take state-changing web actions on a scope-locked
   target?). A ``get_only`` client refuses any non-GET *before the wire* (``web.WebClient.request``).
   This module never relaxes that; it is the outer, scope-wide boundary.

2. **The class arming gate (this module).** Even with a POST-capable client, the clue-driven POST class
   is **disarmed by default**. It arms only on the player's explicit ruling, expressed as
   ``CTF_WEB_POST_CLASS=on`` (or a ``_web_post_class.on`` file in ``CTF_WORKDIR``). Disarmed, it sends
   no POST and returns a named refusal (Rule 6: no silent fallback).

When armed, the destructive-word guard is lifted **only for the exact route the clue advertises** -- a
route named ``/execute`` or ``/process`` is driven because the target's own clue feed named it, never
because it was guessed. An unadvertised route is still refused, and a parameter *value* that is itself a
bare destructive action token is still refused (the exploit payload -- an XSS tag, an SSTI expression, a
read-only command -- is not such a token). The proof is read **only from a follow-up GET**, never from
the POST response (the POST response is scanned only to subtract pre-existing/baseline tokens).

Public surface (imported, not run as a CLI -- ``proof_hunt`` is the entry):
    load_arming(env=None) -> PostArming           # the O-2 ruling, fail-closed to disarmed
    parse_post_clue(doc) -> CluePost | None        # feature_route + params + read routes + technique
    classify_technique(doc) -> str                 # the per-day technique from the clue shape
    route_is_clue_advertised(route, clue) -> bool
    clue_post_allows(method, route, *, arming, clue) -> (bool, reason)
    run_clue_post(doc, *, client, arming, host, ...) -> CluePostResult

This module sends nothing by itself: the caller injects the scope-locked client. No challenge binary is
ever executed; the payloads are synthetic clue-named markers whose only job is to elicit the proof the
target itself returns.
"""

from __future__ import annotations

import re
import sys
from collections import namedtuple
from pathlib import Path
from urllib.parse import urlencode as _web_urlencode

# ctf package import (script/dynamic-load runs need the checkout root on sys.path), mirroring proof_hunt.
try:
    from ctf import env as ctf_env, paths as ctf_paths
except ModuleNotFoundError:  # pragma: no cover - exercised only outside the checkout
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import env as ctf_env, paths as ctf_paths

_HERE = Path(__file__).resolve().parent
_TK = _HERE.parent / "toolkits"
if str(_TK) not in sys.path:
    sys.path.insert(0, str(_TK))
import web as _web  # noqa: E402  (solvers/toolkits/web.py: route_has_destructive_action, OutOfScope)


# ---------------------------------------------------------------------------------------------------------
#  Arming (Open O-2). Fail-closed: the class is OFF unless the player's ruling turns it on.
# ---------------------------------------------------------------------------------------------------------
PostArming = namedtuple("PostArming", ["armed", "reason"])

_DISARMED_REASON = (
    "clue-driven POST class disarmed: Open O-2 (may Layer 1 take state-changing web actions on a "
    "scope-locked target?) is unsettled; set CTF_WEB_POST_CLASS=on only on the player's explicit ruling"
)
_ARMED_REASON = "clue-driven POST class armed by the player's Open O-2 ruling (CTF_WEB_POST_CLASS=on)"


def load_arming(env=None):
    """The class arming state, read fail-closed from the environment.

    OFF unless ``CTF_WEB_POST_CLASS=on`` (the player's O-2 ruling). A ``_web_post_class.off`` file in
    ``CTF_WORKDIR`` forces off even past the env var; a ``_web_post_class.on`` file forces on. Any error
    resolving the workdir leaves the class disarmed (Rule 6: a missing/unreadable config fails closed,
    never silently open). ``env`` is an optional mapping-like override for tests; it defaults to the
    process environment via ``ctf.env``."""
    getter = (lambda k, d="": str(env.get(k, d))) if env is not None else (lambda k, d="": ctf_env.get(k, d))
    try:
        workdir = ctf_paths.workdir()
    except Exception:
        workdir = None
    if workdir is not None:
        try:
            if (workdir / "_web_post_class.off").exists():
                return PostArming(False, _DISARMED_REASON + " (forced off by _web_post_class.off)")
            if (workdir / "_web_post_class.on").exists():
                return PostArming(True, _ARMED_REASON + " (via _web_post_class.on)")
        except Exception:
            pass
    if getter("CTF_WEB_POST_CLASS", "off").strip().lower() == "on":
        return PostArming(True, _ARMED_REASON)
    return PostArming(False, _DISARMED_REASON)


def disarmed(reason=_DISARMED_REASON):
    """An explicitly disarmed arming (the default class state)."""
    return PostArming(False, reason)


def armed_for(reason=_ARMED_REASON):
    """An explicitly armed arming, for a caller that already holds the player's O-2 ruling."""
    return PostArming(True, reason)


# ---------------------------------------------------------------------------------------------------------
#  Clue parsing. /api/clues is untrusted target data: we read only route/parameter *shapes* from it, never
#  instructions, and only bare-identifier parameter names and same-host absolute paths.
# ---------------------------------------------------------------------------------------------------------
CluePost = namedtuple("CluePost", ["feature_route", "param_names", "read_routes", "technique", "raw"])

# Clue keys whose value is a same-host path we may read after the POST (the proof carrier), best-first.
_READ_ROUTE_KEYS = (
    "render_route", "status_route", "result_route", "output_route", "audit_route", "redeem_route",
    "secondary_route", "owner_directory_route", "recovery_guide_route", "read_route", "view_route",
    "report_route",
)
# Clue keys whose value names the POST parameter the target expects.
_PARAM_KEY_RE = re.compile(r"(?:_parameter|_param|_field|parameter|field)$", re.I)
_BARE_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
_PATH_RE = re.compile(r"^/[^\s?#]*$")


def _is_same_host_path(value):
    """A clue route we may drive is a bare same-host absolute path: starts with '/', no scheme/host, no
    '..' traversal, no whitespace. An off-host URL or a relative/odd value is not a route we honor."""
    return isinstance(value, str) and bool(_PATH_RE.match(value)) and ".." not in value


def _bare_ident(value):
    """A clue-stated parameter NAME is a bare identifier, never a sentence or a payload (mirrors
    proof_hunt._is_clue_param_name: a value with spaces or payload characters is not a field name)."""
    if not isinstance(value, str):
        return None
    v = value.strip()
    if not v or len(v) > 64 or not _BARE_IDENT_RE.fullmatch(v):
        return None
    return v


def classify_technique(doc):
    """The per-day technique inferred from the clue-document *shape*. Returns a stable technique label
    used to pick the payload template; the field name and routes still come from the clue, never from the
    label. Unknown shapes fall to ``generic_post`` (a bare clue-named field+value POST), which is still
    bounded and self-proving -- never a guess at an unadvertised route."""
    if not isinstance(doc, dict):
        return "generic_post"
    keys = {str(k).lower() for k in doc.keys()}
    blob = " ".join(str(k).lower() for k in keys)
    feature = str(doc.get("feature_route") or "").lower()
    text = (blob + " " + feature)
    # Order matters: the more specific shapes first.
    if "upload_shape" in keys or ("upload" in text and "render_route" in keys):
        return "upload_template"
    if "graphql" in text or "resolver" in text or "query_document" in keys:
        return "graphql"
    if ("request_route" in keys and "redeem_route" in keys) or "recovery_guide_route" in keys \
            or ("token_parameter" in keys and "account_parameter" in keys):
        return "reset_rebind"
    if "owner_directory_route" in keys or "job_id_required" in keys or ("queue" in text and "owner" in text):
        return "queue_owner"
    if "audit_route" in keys or "report_route" in keys or "audit" in text:
        return "audit_report"
    if re.search(r"\b(execute|process|command|cmd|run)\b", feature) or "input_parameter" in keys:
        return "cmdi"
    if "session_hint" in keys or ("session" in text and "fixation" in text):
        return "session_fixation"
    if "state_format_route" in keys or "unsigned" in text or "serialized" in text:
        return "unsigned_state"
    if "signature" in text or "manifest" in text or "sha256" in text or "update_policy_route" in keys:
        return "forge_event"
    # A stored-XSS/note clue also carries a render/view route, so its content/note signal is read before
    # the generic render_route->SSTI branch below (a true SSTI clue names a template field, not content).
    if re.search(r"xss|note|comment|guestbook|message|content|feedback|postcard", text):
        return "stored_xss"
    if "render_route" in keys or "template" in text or "ssti" in text:
        return "ssti"
    return "generic_post"


def parse_post_clue(doc):
    """Read a clue document (whatever JSON object ``/api/clues`` returns) into a :class:`CluePost`, or
    ``None`` when it advertises no POST-capable ``feature_route``. Only a same-host absolute
    ``feature_route`` is honored; parameter names are collected from every ``*_parameter``/``*_field``
    key and any ``parameters`` list, bare identifiers only; read routes are the same-host paths named by
    the known carrier keys, de-duplicated, with the feature route itself as the final fallback."""
    if not isinstance(doc, dict):
        return None
    feature = doc.get("feature_route")
    if not _is_same_host_path(feature):
        return None

    params = []

    def _add_param(v):
        name = _bare_ident(v)
        if name and name not in params:
            params.append(name)

    for key, value in doc.items():
        if _PARAM_KEY_RE.search(str(key)):
            if isinstance(value, (list, tuple)):
                for item in value:
                    _add_param(item)
            else:
                _add_param(value)
    params_list = doc.get("parameters")
    if isinstance(params_list, (list, tuple)):
        for item in params_list:
            _add_param(item)

    read_routes = []
    for key in _READ_ROUTE_KEYS:
        value = doc.get(key)
        if _is_same_host_path(value) and value not in read_routes:
            read_routes.append(value)
    if feature not in read_routes:
        read_routes.append(feature)

    technique = classify_technique(doc)
    # Keep the raw shape small and typed (defense against a huge untrusted blob).
    raw = {str(k): v for k, v in doc.items() if isinstance(k, str)}
    return CluePost(feature_route=feature, param_names=tuple(params), read_routes=tuple(read_routes),
                    technique=technique, raw=raw)


# ---------------------------------------------------------------------------------------------------------
#  The guard decision. A non-GET is permitted only when (a) the class is armed, (b) the route is one the
#  clue advertised, and (c) the method is a bounded write. GET is always permitted. A destructive WORD in
#  an *advertised* route name is lifted (the target named it); an unadvertised route is refused outright.
# ---------------------------------------------------------------------------------------------------------
_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH"})


def _norm_path(route):
    return str(route or "").split("?", 1)[0].rstrip("/") or "/"


def route_is_clue_advertised(route, clue):
    """True iff ``route`` (path only) is exactly a route the clue named -- its ``feature_route`` or one of
    its read routes. The destructive-word lift and the write permission apply only to such a route; a
    guessed or crawled route is never trusted here."""
    if clue is None:
        return False
    target = _norm_path(route)
    advertised = {_norm_path(clue.feature_route)}
    advertised.update(_norm_path(r) for r in clue.read_routes)
    return target in advertised


def value_is_destructive_action(value):
    """True iff a parameter *value* is itself a bare destructive action token (e.g. ``delete``,
    ``drop-table``) -- which this class never sends even when armed. A real exploit payload (an HTML/JS
    tag, an SSTI expression, a read-only command with spaces/operators) is not a bare action token, so it
    is not blocked here. Mirrors the GET classes' "never send a state-changing action VALUE" rule."""
    if not isinstance(value, str):
        return False
    token = value.strip()
    # Only bare, short, routelike tokens are judged as action words. Anything with whitespace or typical
    # payload punctuation is an exploit payload, not an action verb, and is not blocked by this guard.
    if not token or len(token) > 48 or re.search(r"[\s<>{}()$`;|&'\"=]", token):
        return False
    return bool(_web.route_has_destructive_action(token))


def clue_post_allows(method, route, *, arming, clue):
    """``(allowed, reason)`` for one request this class is about to make. GET is always allowed. A write
    method is allowed only when the class is armed AND the route is clue-advertised. Returns a named
    reason on refusal (Rule 6)."""
    m = str(method or "").upper()
    if m == "GET":
        return True, "GET (read-only) always allowed"
    if m not in _WRITE_METHODS:
        return False, f"method {m!r} is not a GET or a bounded write; refused"
    if arming is None or not getattr(arming, "armed", False):
        return False, (getattr(arming, "reason", None) or _DISARMED_REASON)
    if not route_is_clue_advertised(route, clue):
        return False, (f"route {_norm_path(route)!r} is not advertised by /api/clues; a write is refused "
                       f"on any route the target's own clue feed did not name")
    return True, (f"armed write to clue-advertised route {_norm_path(route)!r} "
                  f"(destructive-word lift applies to this advertised route only)")


# ---------------------------------------------------------------------------------------------------------
#  Payload templates. Synthetic, clue-named markers whose only purpose is to elicit the proof the target
#  itself returns on a follow-up GET. No challenge code is executed here; these are strings posted to the
#  advertised route. The field name always comes from the clue, never from the template.
# ---------------------------------------------------------------------------------------------------------
_MARKER = "b233clue"


def payload_for(technique, clue):
    """A single synthetic payload string for the technique. Deliberately simple and clue-named; the
    target recognizes the advertised feature route + field name and returns its proof on the read route.
    A hint value from the clue, when present, is woven in so a target that echoes the hint still matches."""
    hint = ""
    for key in ("hint", "session_hint", "callback_nonce", "reference"):
        v = clue.raw.get(key) if clue is not None else None
        if isinstance(v, str) and v.strip():
            hint = re.sub(r"[^A-Za-z0-9_.-]", "", v)[:64]
            break
    tag = (_MARKER + ("-" + hint if hint else ""))
    if technique == "stored_xss":
        return f"<img src=x onerror=\"/*{tag}*/\">"
    if technique == "ssti" or technique == "upload_template":
        return "${" + tag + "}"
    if technique == "cmdi":
        return f"id # {tag}"
    if technique == "graphql":
        return "{ __typename }"
    if technique in ("reset_rebind", "forge_event", "queue_owner", "audit_report",
                     "unsigned_state", "session_fixation"):
        return tag
    return tag


# ---------------------------------------------------------------------------------------------------------
#  The runner.
# ---------------------------------------------------------------------------------------------------------
CluePostResult = namedtuple(
    "CluePostResult", ["proof", "technique", "sent", "refused", "reason", "read_routes"])


def _load_proof_helpers():
    """``(is_proof, scan_for_proofs, scan_for_baseline_proofs)`` from proof_hunt, loaded by file name the
    same way ``tools/web_open.py`` loads the solver, so the banking logic is the canonical one (a value is
    a proof iff proof_hunt says so). Fails loudly if the contract is missing (Rule 6)."""
    import importlib
    try:
        mod = importlib.import_module("proof_hunt")
    except Exception:
        import importlib.util
        path = _HERE / "proof_hunt.py"
        spec = importlib.util.spec_from_file_location("proof_hunt", path)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"clue_post_class: cannot load proof_hunt from {path}")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    for name in ("is_proof", "scan_for_proofs", "scan_for_baseline_proofs"):
        if not hasattr(mod, name):
            raise RuntimeError(f"clue_post_class: proof_hunt is missing {name!r} (contract changed)")
    return mod.is_proof, mod.scan_for_proofs, mod.scan_for_baseline_proofs


def _body_text(response):
    """The text of a WebClient response across its known shapes, '' on anything unreadable.

    ``web.WebClient.request`` returns a response **dict** whose ``body`` is bytes; a test double may
    instead expose ``.text``/``.body`` attributes or hand back a str/bytes directly."""
    if response is None:
        return ""

    def _coerce(v):
        if isinstance(v, str):
            return v
        if isinstance(v, (bytes, bytearray)):
            return bytes(v).decode("utf-8", "replace")
        return None

    if isinstance(response, dict):
        out = _coerce(response.get("body"))
        return out if out is not None else ""
    for attr in ("text", "body"):
        out = _coerce(getattr(response, attr, None))
        if out is not None:
            return out
    out = _coerce(response)
    return out if out is not None else ""


def run_clue_post(doc, *, client, arming, host, deadline=None, max_requests=12,
                  baseline_proofs=(), is_proof=None, scan=None, scan_baseline=None):
    """Run the clue-driven POST class against one scope-locked target and bank only a novel proof.

    ``client`` is a scope-locked ``web.WebClient``-like object (``.request(method, path, data=, headers=)``
    returning a response with ``.text``/``.body``). The caller owns the scope lock and the wire gate: if
    the client is ``get_only`` (B-007), its own ``request`` refuses the POST before the wire and this
    runner records that refusal and banks nothing. ``host`` is the target host for off-host proof
    stripping. ``baseline_proofs`` are proofs already seen on this target (decoys), subtracted from the
    payoff. ``is_proof``/``scan``/``scan_baseline`` default to proof_hunt's canonical helpers.

    Returns a :class:`CluePostResult`. Never raises for a target/transport error (it is recorded as a
    refusal reason and no proof is banked)."""
    if is_proof is None or scan is None or scan_baseline is None:
        _is_proof, _scan, _scan_baseline = _load_proof_helpers()
        is_proof = is_proof or _is_proof
        scan = scan or _scan
        scan_baseline = scan_baseline or _scan_baseline

    clue = parse_post_clue(doc)
    if clue is None:
        return CluePostResult(None, "generic_post", False, True,
                              "no POST-capable clue: /api/clues advertised no same-host feature_route", ())
    if not clue.param_names:
        return CluePostResult(None, clue.technique, False, True,
                              "clue advertised a feature_route but no POST parameter name; refusing to "
                              "guess a field", clue.read_routes)

    allowed, reason = clue_post_allows("POST", clue.feature_route, arming=arming, clue=clue)
    if not allowed:
        # Disarmed (or an unadvertised route): send nothing. The default class state.
        return CluePostResult(None, clue.technique, False, True, reason, clue.read_routes)

    baseline = set()
    for p in baseline_proofs or ():
        if isinstance(p, str):
            baseline.add(p)

    budget = {"n": max(0, int(max_requests))}

    def _send(method, path, data=None):
        """One bounded request; returns (text, error_or_None). Honors the request budget and the
        per-request guard. A transport/scope error is returned as a reason, never raised."""
        if budget["n"] <= 0:
            return "", "clue-post request budget exhausted"
        ok, why = clue_post_allows(method, path, arming=arming, clue=clue)
        if not ok:
            return "", why
        budget["n"] -= 1
        try:
            headers = None
            if data is not None:
                headers = {"Content-Type": "application/x-www-form-urlencoded"}
            r = client.request(method, path, data=data, headers=headers)
        except _web.OutOfScope as e:
            # The outer wire gate (get_only / scope) refused -- the B-007 boundary holding.
            return "", f"client refused {method} {path}: {e}"
        except Exception as e:  # a target/transport error is this target's None, never a raise
            return "", f"{method} {path} failed: {type(e).__name__}: {e}"
        return _body_text(r), None

    # Baseline-GET the read routes first so pre-existing / globally-polluted proofs are recognised as
    # decoys and never banked as our effect (the Day-12 "baseline-GET before any POST" rule).
    for route in clue.read_routes:
        text, err = _send("GET", route)
        if err is None and text:
            baseline |= scan_baseline(text, host)

    refusals = []
    payload = payload_for(clue.technique, clue)
    if value_is_destructive_action(payload):  # defensive: a template must never be a bare action verb
        return CluePostResult(None, clue.technique, False, True,
                              "refusing to send a bare destructive action value", clue.read_routes)

    sent_any = False
    # One POST per advertised field name (bounded). A renamed objective field still yields the proof
    # because every advertised name is tried, best-first, under the shared request budget.
    for field in clue.param_names:
        body = _web_urlencode({field: payload})
        text, err = _send("POST", clue.feature_route, data=body)
        if err is not None:
            refusals.append(err)
            # A wire/scope refusal (get_only) will refuse every POST identically -- stop early.
            if "refused" in err and "budget" not in err:
                break
            continue
        sent_any = True
        # The POST response is a decoy carrier: fold its tokens into the baseline, never a payoff.
        if text:
            baseline |= scan_baseline(text, host)
        # The proof is read ONLY from a follow-up GET of the advertised read route(s).
        for route in clue.read_routes:
            rtext, rerr = _send("GET", route)
            if rerr is not None or not rtext:
                continue
            novel = {v for v in scan(rtext, host) if is_proof(v)} - baseline
            if novel:
                proof = sorted(novel)[0]
                return CluePostResult(proof, clue.technique, True, False,
                                      f"banked novel proof from follow-up GET {route!r} after "
                                      f"POST {clue.feature_route!r} (field {field!r}, {clue.technique})",
                                      clue.read_routes)

    if not sent_any:
        return CluePostResult(None, clue.technique, False, True,
                              "; ".join(refusals) or "no POST was sent", clue.read_routes)
    return CluePostResult(None, clue.technique, True, False,
                          "POST sent on the advertised route but no novel proof surfaced on a follow-up "
                          "GET" + (("; " + "; ".join(refusals)) if refusals else ""), clue.read_routes)
