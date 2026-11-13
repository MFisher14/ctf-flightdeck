#!/usr/bin/env python3
"""B-184: web contract library, fingerprint-first router and request minimization.

Layer 1 closed none of the observed web modes cold -- every one was an agent
path.  The classes that recurred (POST event forgery with wire field names
unlike the clue display labels, clue-advertised routes containing guarded words,
self-describing control/mutation contracts, SSRF->internal->IDOR, signed-manifest
bypass, double-spend races, WebSocket proof delivery, and the new-on-the-day
protocol classes) are catalogued here as a **contract library**: one fingerprint
per class, a cold/agent/none disposition, the handler that closes it, and a
synthetic offline fixture.

This module is the *front door*, not another reader.  It:

* ranks a discovery snapshot against every class (``fingerprint`` /
  :func:`route`) and, when nothing clears the threshold, falls through to the
  ``novel_web`` agent class so a novel bug is never silently "cold-solved";
* keeps the per-class cold/agent/none matrix as a tested artifact
  (:func:`disposition_matrix`);
* applies a generic **route-trust** rule for clue-advertised URLs
  (:func:`route_trust`): a same-origin route the clue advertises verbatim is
  trusted to send even when its path carries a guarded word, while an off-origin
  advertised URL never is;
* builds a **simplest-first forge grid** with label-to-wire name mutation
  (:func:`forge_grid`) -- the lesson of the event-forge row, where the accepted
  payload was a flat ``{event, owner}`` and the agents anchored on an HMAC guess
  and the clue labels;
* turns an observed accepted request into an **evidence-driven minimization
  plan** (:func:`minimize`) that drops the auth-looking noise first;
* delegates a target-described contract to B-149 (``web.contract_executor``); and
* drives an ordered request plan for timed modes with an injected client and an
  injected step clock (:func:`replay`) -- never any network of its own.

Nothing here opens a socket.  The fingerprint, trust, grid and minimizer are
pure; :func:`replay` sends only through a caller-supplied ``client`` callable, so
the only transport in a test is a fake on ``127.0.0.1`` or an in-memory stub.
Recovered proofs are RETURNED for the player to submit through the gate; nothing
auto-submits.
"""
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt as _flagfmt
except ModuleNotFoundError:  # pragma: no cover - exercised only outside the venv
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import flagfmt as _flagfmt

_HERE = Path(__file__).resolve().parent
_TK = _HERE.parent / "toolkits"
for _p in (_TK, _HERE):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import web as _web  # noqa: E402 -- shared scope/route/guarded-word policy
if not hasattr(_web, "route_has_destructive_action"):
    # Imported as the package module ``web.contract_library`` (solvers/web/__init__.py, solvers/ on
    # sys.path, as tools/import_gate.py does), ``web`` is this lane's package, not the toolkit: load
    # solvers/toolkits/web.py by file (the flow_recorder.py precedent).
    import importlib.util as _ilu
    _spec = _ilu.spec_from_file_location("_contract_library_web", _TK / "web.py")
    _web = _ilu.module_from_spec(_spec)
    sys.modules[_spec.name] = _web  # register so dataclasses in the module resolve
    _spec.loader.exec_module(_web)
# The live forge engine's label->wire mutation (prefix/suffix stripping plus its
# semantic synonym table) is the base this planner extends; never a fork of it.
import forge_event as _forge_event  # noqa: E402

MATRIX_PATH = _HERE / "contract_matrix.json"

# Field names a forge payload should never need and a minimizer should drop
# first: the automation fixated on exactly these on the event-forge row.
AUTH_NOISE = frozenset({
    "signature", "sig", "hmac", "mac", "token", "_token", "csrf", "csrftoken",
    "csrf_token", "nonce", "timestamp", "ts", "time", "hash", "checksum",
    "digest", "auth", "authorization", "apikey", "api_key", "key",
})

# Small, bounded *extra* synonym table for label->wire mutation.  Keys are
# canonical lowercase labels; values are identifier-style wire names
# (``owner_id``, ``uid``, ...) that ``forge_event.name_variants`` does not emit.
# They rank after the mechanical mutations and after forge_event's variants.
_SYNONYMS = {
    "owner": ("user", "username", "account", "owner_id", "user_id", "uid"),
    "event": ("type", "event_type", "action", "name", "kind"),
    "user": ("username", "account", "owner", "user_id", "uid"),
    "amount": ("value", "qty", "quantity", "total"),
    "id": ("uuid", "ref", "identifier"),
    "target": ("url", "dest", "destination", "to"),
    "role": ("group", "scope", "privilege", "level"),
    "name": ("title", "label"),
}

# Payload shapes, simplest first.  A wrapper nests the flat body under one key.
_SHAPES = ("flat", "wrap_data", "wrap_payload", "wrap_event")
# Transports, simplest first.
_TRANSPORTS = ("json", "form", "query")


class ContractLibraryError(RuntimeError):
    """The contract matrix is missing or malformed (no silent fallback)."""


# ---------------------------------------------------------------------------
#  The contract library (data-driven; loud on a missing or broken file)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ContractClass:
    """One observed web contract class and how Layer 1 should treat it."""

    id: str
    title: str
    disposition: str          # cold | agent | none
    handler: str              # engine id, "web.contract_library.<fn>", or "agent"
    fingerprint: dict
    fixture: str
    source: str = ""
    notes: str = ""

    @property
    def is_catch_all(self) -> bool:
        return bool(self.fingerprint.get("catch_all"))


@dataclass(frozen=True)
class ContractMatrix:
    """The loaded library: the classes plus the match threshold."""

    classes: tuple
    threshold: int
    fixtures: dict

    def by_id(self, cid: str) -> Optional[ContractClass]:
        for c in self.classes:
            if c.id == cid:
                return c
        return None


_DISPOSITIONS = ("cold", "agent", "none")


def load_matrix(path: Optional[Path] = None) -> ContractMatrix:
    """Load the contract matrix, failing loudly with a named reason.

    Never falls back to a default: a missing or malformed library is a build
    error, not an empty router (contract 6).
    """
    p = Path(path) if path is not None else MATRIX_PATH
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise ContractLibraryError(f"contract matrix not readable at {p}: {exc}") from exc
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise ContractLibraryError(f"contract matrix at {p} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("classes"), list):
        raise ContractLibraryError(f"contract matrix at {p} has no 'classes' list")
    threshold = data.get("threshold", 3)
    if not isinstance(threshold, int) or threshold < 1:
        raise ContractLibraryError(f"contract matrix threshold {threshold!r} is not a positive int")
    classes = []
    seen = set()
    for i, entry in enumerate(data["classes"]):
        if not isinstance(entry, dict):
            raise ContractLibraryError(f"contract matrix class #{i} is not a table")
        cid = entry.get("id")
        if not cid or not isinstance(cid, str):
            raise ContractLibraryError(f"contract matrix class #{i} has no id")
        if cid in seen:
            raise ContractLibraryError(f"contract matrix has a duplicate class id {cid!r}")
        seen.add(cid)
        disp = entry.get("disposition")
        if disp not in _DISPOSITIONS:
            raise ContractLibraryError(
                f"contract class {cid!r} has disposition {disp!r}, not one of {_DISPOSITIONS}")
        fp = entry.get("fingerprint")
        if not isinstance(fp, dict):
            raise ContractLibraryError(f"contract class {cid!r} has no fingerprint table")
        handler = entry.get("handler")
        if disp == "cold" and not handler:
            # A cold class with no handler would silently default to the agent
            # path -- a cold disposition that in fact escalates is a loud bug.
            raise ContractLibraryError(
                f"cold contract class {cid!r} has no handler: a cold class must name the engine "
                f"or module function that closes it, never fall through to 'agent'")
        handler = handler or "agent"
        classes.append(ContractClass(
            id=cid, title=entry.get("title", cid), disposition=disp, handler=handler,
            fingerprint=fp, fixture=entry.get("fixture", ""), source=entry.get("source", ""),
            notes=entry.get("notes", "")))
    if not classes:
        raise ContractLibraryError(f"contract matrix at {p} lists no classes")
    if not any(c.is_catch_all for c in classes):
        raise ContractLibraryError(
            f"contract matrix at {p} has no catch_all class: a novel bug would fail closed to nothing")
    fixtures = data.get("fixtures", {})
    if not isinstance(fixtures, dict):
        raise ContractLibraryError(f"contract matrix at {p} 'fixtures' is not a table")
    return ContractMatrix(classes=tuple(classes), threshold=threshold, fixtures=fixtures)


def disposition_matrix(matrix: Optional[ContractMatrix] = None) -> dict:
    """The per-class cold/agent/none matrix as a plain dict (a tested artifact)."""
    m = matrix or load_matrix()
    return {c.id: {"disposition": c.disposition, "handler": c.handler, "title": c.title}
            for c in m.classes}


# ---------------------------------------------------------------------------
#  Fingerprint-first router
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ClassMatch:
    """A scored contract class for one discovery snapshot."""

    cls: ContractClass
    score: int
    reasons: tuple
    disposition: str
    handler: str


def _evidence_text(evidence: dict) -> str:
    """Lower-cased concatenation of the clue and every response body/header."""
    parts = [str(evidence.get("clue", ""))]
    for resp in evidence.get("responses", []) or []:
        if isinstance(resp, dict):
            parts.append(str(resp.get("body", "")))
            for k, v in (resp.get("headers") or {}).items():
                parts.append(f"{k}: {v}")
    for route in evidence.get("advertised_routes", []) or []:
        parts.append(str(route))
    return "\n".join(parts).lower()


def _status_codes(evidence: dict) -> set:
    out = set()
    for resp in evidence.get("responses", []) or []:
        if isinstance(resp, dict) and isinstance(resp.get("status"), int):
            out.add(resp["status"])
    return out


def _score_class(cls: ContractClass, evidence: dict, text: str, statuses: set,
                 base_url: str) -> ClassMatch:
    fp = cls.fingerprint
    score = 0
    reasons = []
    if cls.is_catch_all:
        # Never scores on signals; it is the floor the router falls through to.
        return ClassMatch(cls=cls, score=0, reasons=("catch-all",),
                          disposition=cls.disposition, handler=cls.handler)

    cats = [str(c).lower() for c in fp.get("category", [])]
    ev_cat = str(evidence.get("category", "")).lower()
    if cats and ev_cat and ev_cat in cats:
        score += 1
        reasons.append(f"category={ev_cat}")

    for kw in fp.get("clue_keywords", []):
        if str(kw).lower() in text:
            score += 1
            reasons.append(f"kw:{kw}")

    methods = [str(x).upper() for x in fp.get("methods", [])]
    ev_method = str(evidence.get("method", "")).upper()
    if methods and ev_method and ev_method in methods:
        score += 1
        reasons.append(f"method={ev_method}")

    for marker in fp.get("response_markers", []):
        if str(marker).lower() in text:
            score += 2
            reasons.append(f"marker:{marker}")

    codes = set(fp.get("status_codes", []))
    if codes and (codes & statuses):
        score += 2
        reasons.append(f"status:{sorted(codes & statuses)}")

    if fp.get("has_contract_graph") and isinstance(evidence.get("contract_graph"), dict):
        score += 4
        reasons.append("contract-graph")

    if fp.get("has_advertised_route") and evidence.get("advertised_routes"):
        score += 1
        reasons.append("advertised-route")

    if fp.get("advertised_route_guarded"):
        guarded = any(_route_is_guarded(r, base_url) for r in evidence.get("advertised_routes", []))
        if guarded:
            score += 3
            reasons.append("advertised-route-guarded")

    if fp.get("novel_protocol") and _mentions_novel_protocol(text):
        score += 2
        reasons.append("novel-protocol")

    return ClassMatch(cls=cls, score=score, reasons=tuple(reasons),
                      disposition=cls.disposition, handler=cls.handler)


def _mentions_novel_protocol(text: str) -> bool:
    return any(w in text for w in ("handshake", "fail open", "fail-open", "frame protocol",
                                   "custom protocol", "binary protocol"))


def fingerprint(evidence: dict, matrix: Optional[ContractMatrix] = None) -> list:
    """Rank every contract class against one discovery snapshot, best first.

    ``evidence`` is a dict with optional keys ``category``, ``clue`` (text),
    ``method``, ``advertised_routes`` (list), ``responses`` (list of
    ``{status, headers, body, route}``) and ``contract_graph``.  Returns a list
    of :class:`ClassMatch`, highest score first, ties broken by the class order
    in the library.  The catch-all ``novel_web`` class is always last.
    """
    m = matrix or load_matrix()
    base_url = str(evidence.get("base_url", ""))
    text = _evidence_text(evidence)
    statuses = _status_codes(evidence)
    scored = [_score_class(c, evidence, text, statuses, base_url) for c in m.classes]
    order = {c.id: i for i, c in enumerate(m.classes)}
    scored.sort(key=lambda mt: (-mt.score, mt.cls.is_catch_all, order[mt.cls.id]))
    return scored


def route(evidence: dict, matrix: Optional[ContractMatrix] = None) -> dict:
    """Fingerprint-first routing decision for one discovery snapshot.

    Returns a JSON-able dict: the ranked classes, the chosen class and its
    disposition, the route-trust verdict for every advertised URL, and a
    handler-specific ``plan`` (a forge-grid preview, a B-149 delegation, a reader
    hand-off, or an agent escalation).  This is the operator-facing entry; the
    module is a ``library`` engine, so ``ctf run`` refuses it and callers import
    this instead.
    """
    m = matrix or load_matrix()
    ranked = fingerprint(evidence, m)
    base_url = str(evidence.get("base_url", ""))
    top = ranked[0] if ranked else None
    # Fall through to the catch-all when nothing clears the threshold.
    chosen = top
    if top is None or (top.score < m.threshold and not top.cls.is_catch_all):
        catch = next((mt for mt in ranked if mt.cls.is_catch_all), None)
        chosen = catch or top

    trust = [route_trust(r, base_url, advertised=evidence.get("advertised_routes", []),
                         clue=str(evidence.get("clue", "")))
             for r in evidence.get("advertised_routes", []) or []]

    result = {
        "classes": [{"id": mt.cls.id, "score": mt.score, "disposition": mt.disposition,
                     "handler": mt.handler, "reasons": list(mt.reasons)} for mt in ranked],
        "chosen": None if chosen is None else {
            "id": chosen.cls.id, "score": chosen.score, "disposition": chosen.disposition,
            "handler": chosen.handler, "title": chosen.cls.title},
        "route_trust": [t.to_dict() for t in trust],
        "plan": _plan_for(chosen, evidence, m) if chosen is not None else None,
    }
    return result


def _plan_for(match: ClassMatch, evidence: dict, matrix: ContractMatrix) -> dict:
    """A handler-specific next step for the chosen class."""
    cls = match.cls
    if cls.disposition == "agent":
        return {"action": "escalate-agent", "reason": cls.notes or "no cold reader for this class",
                "class": cls.id}
    handler = cls.handler
    if handler == "web.contract_executor":
        delegation = {"action": "delegate", "engine": "web.contract_executor",
                      "reason": "target-described contract (B-149)"}
        graph = evidence.get("contract_graph")
        base_url = str(evidence.get("base_url", ""))
        if isinstance(graph, dict):
            delegation["contract"] = _describe_contract(graph, base_url)
        return delegation
    if handler == "web.contract_library.forge_grid":
        fields = evidence.get("fields") or _fields_from_clue(str(evidence.get("clue", "")))
        if not fields:
            # Never a silent empty plan: say why, and hand the class to an agent.
            return {"action": "escalate-agent", "class": cls.id, "handler": handler,
                    "reason": "no field labels found in clue or evidence 'fields': "
                              "the forge grid needs at least one label"}
        grid = forge_grid(fields)
        if not grid:
            return {"action": "escalate-agent", "class": cls.id, "handler": handler,
                    "reason": "every field label is auth/signature noise: "
                              "nothing left to forge"}
        return {"action": "forge", "handler": handler,
                "candidates": [c.to_dict() for c in grid[:8]], "total": len(grid)}
    if handler == "web.contract_library.route_trust":
        base_url = str(evidence.get("base_url", ""))
        clue = str(evidence.get("clue", ""))
        verdicts = [route_trust(r, base_url, advertised=evidence.get("advertised_routes", []),
                                clue=clue)
                    for r in evidence.get("advertised_routes", []) or []]
        trusted = [t.to_dict() for t in verdicts if t.trusted]
        return {"action": "trust-route", "handler": handler, "routes": trusted}
    # A carried cold reader (recon_router, double_spend, realtime_read, ...).
    return {"action": "reader", "engine": handler, "reason": cls.notes or cls.title}


def _describe_contract(graph: dict, base_url: str) -> dict:
    """Validate a clue graph through B-149 without sending anything."""
    try:
        import contract_executor as _ce  # noqa: E402 -- peer solvers/web module
    except ModuleNotFoundError:
        return {"status": "unavailable", "reason": "web.contract_executor not importable"}
    built = _ce.build_contract(graph, base_url)
    if isinstance(built, dict):  # an {"incomplete": reason} finding
        return {"status": "incomplete", "reason": built.get("incomplete", "incomplete")}
    return {"status": "ready", "action_route": built.action_route,
            "action_method": built.action_method}


# ---------------------------------------------------------------------------
#  Route-trust rule for clue-advertised URLs
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RouteTrust:
    """Whether one candidate URL may be sent, and why."""

    url: str
    trusted: bool
    reason: str
    route: Optional[str] = None     # the normalized same-origin route, when any
    guarded: bool = False           # whether the path carries a destructive word

    def to_dict(self) -> dict:
        return {"url": self.url, "trusted": self.trusted, "reason": self.reason,
                "route": self.route, "guarded": self.guarded}

    def __bool__(self) -> bool:
        return self.trusted


def _same_origin_route(url: str, base_url: str) -> Optional[str]:
    """The normalized same-origin path(+query) for ``url`` under ``base_url``.

    Uses the shared guard for structure (no traversal, no authority confusion,
    no embedded URL, no unfinished encoding) but **not** the destructive-word
    check: that is the one guard :func:`route_trust` decides about.
    """
    return _web.safe_same_origin_route(url, base_url, allow_query=True)


def _route_is_guarded(url, base_url: str) -> bool:
    """Whether a same-origin route's path carries a destructive/guarded word."""
    route_s = _same_origin_route(str(url), base_url)
    if route_s is None:
        return False
    path = route_s.split("?", 1)[0]
    layers = _web.canonical_route_layers(path) or (path,)
    return any(_web.route_has_destructive_action(layer) for layer in layers)


# Catastrophic, irreversible infrastructure actions that are NEVER trusted, even
# when the clue advertises the route verbatim: naming a route does not make
# shutting the host down or wiping the database a sanctioned read.  This is the
# fatal floor (the same principle as proof_hunt's _TRUSTED_FATAL_PATH); the
# ordinary guarded words a clue may waive (reset, delete-session, ...) are left
# out so the advertised-route exception still holds for them.
_FATAL_ROUTE_WORDS = frozenset({
    "shutdown", "poweroff", "reboot", "restart", "destroy", "wipe", "purge",
    "nuke", "format", "kill", "drop", "truncate", "uninstall", "deactivate",
    "flush", "erase",
})
# The fatal words the shared guard already knows: detection for these is
# delegated to ``web.route_has_destructive_action`` (NFKC folding, camelCase,
# action/object and modifier compounds such as ``wipedb``, ``shutdownnow``,
# ``dropall``) by exempting every *other* shared destructive word.
_SHARED_DESTRUCTIVE = _web._ROUTE_DESTRUCTIVE_ACTIONS
_NON_FATAL_SHARED = _SHARED_DESTRUCTIVE - _FATAL_ROUTE_WORDS
# ``format`` is a common harmless route word (``/api/format``), so it is fatal
# only next to a storage object.
_FORMAT_EXTRA = "format"
_FORMAT_OBJECTS = frozenset({
    "disk", "disks", "drive", "drives", "volume", "volumes", "partition", "partitions",
    "fs", "filesystem", "db", "database", "databases", "storage", "system", "all",
})
# Every other fatal word the shared set lacks (today: poweroff, nuke) is fatal
# on its own and in any compound.  Computed, not listed, so a word the shared
# guard later drops still stays on the floor.
_FATAL_EXTRA_UNAMBIGUOUS = tuple(sorted(_FATAL_ROUTE_WORDS - _SHARED_DESTRUCTIVE - {_FORMAT_EXTRA}))
# Shared modifier list: ``nukeall`` / ``allnuke`` strip to ``nuke``.
_FATAL_MODIFIERS = tuple(sorted(_web._ROUTE_ACTION_MODIFIERS, key=len, reverse=True))
# Words that negate an invitation: "do NOT call /admin/shutdown" names the route
# but forbids it, so a clue-text mention in a sentence with one of these is not trust.
_NEGATION_WORD = re.compile(
    r"(?i)\b(?:do not|don't|dont|never|avoid|must not|mustn't|should not|"
    r"shouldn't|cannot|can't|without|except|not)\b")
# A route-looking token in clue text (path plus an optional query string).
_CLUE_ROUTE = re.compile(r"/[A-Za-z0-9_\-./%~]+(?:\?[A-Za-z0-9_\-./%~=&+]*)?")
# Sentence ends: terminal punctuation followed by whitespace or end of text.  A
# dot inside a path (``/file.txt``) is not followed by whitespace, so it stays.
_SENTENCE_END = re.compile(r"(?<=[.!?])(?:\s+|$)")


def _layer_has_extra_fatal(layer: str) -> bool:
    """Fatal words the shared guard does not carry (poweroff, nuke, format+object).

    No NFKC fold here: :func:`web.canonical_route_layers` already yields the
    NFKC-folded spelling as one of the layers the caller iterates.
    """
    camel = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", layer)
    tokens = [t for t in re.split(r"[^A-Za-z0-9]+", camel.lower()) if t]
    expanded = []
    for token in tokens:
        pending, seen = [token], set()
        while pending:
            cand = pending.pop()
            if not cand or cand in seen:
                continue
            seen.add(cand)
            expanded.append(cand)
            for mod in _FATAL_MODIFIERS:
                if cand.startswith(mod) and len(cand) > len(mod):
                    pending.append(cand[len(mod):])
                if cand.endswith(mod) and len(cand) > len(mod):
                    pending.append(cand[:-len(mod)])
    for tok in expanded:
        if any(tok.startswith(w) or tok.endswith(w) for w in _FATAL_EXTRA_UNAMBIGUOUS):
            return True
        if tok.startswith(_FORMAT_EXTRA) and tok[len(_FORMAT_EXTRA):] in _FORMAT_OBJECTS:
            return True
        if tok.endswith(_FORMAT_EXTRA) and tok[:-len(_FORMAT_EXTRA)] in _FORMAT_OBJECTS:
            return True
    if _FORMAT_EXTRA in tokens and any(t in _FORMAT_OBJECTS for t in tokens):
        return True
    return False


def _route_has_fatal_word(route_s: Optional[str]) -> bool:
    """Whether a same-origin route carries a word on the never-trusted fatal floor.

    Every decode layer is checked the way the shared guard checks destructive
    words (NFKC, camelCase, compounds), restricted to the fatal subset, plus
    the fatal words the shared set lacks.
    """
    if route_s is None:
        return False
    path = route_s.split("?", 1)[0]
    layers = _web.canonical_route_layers(path) or (path,)
    for layer in layers:
        if _web.route_has_destructive_action(layer, allowed_actions=_NON_FATAL_SHARED):
            return True
        if _layer_has_extra_fatal(layer):
            return True
    return False


def _clue_sentences(text: str) -> list:
    """Split clue text into sentences (keeping dots inside paths intact)."""
    return [s for s in _SENTENCE_END.split(text or "") if s and s.strip()]


def _clue_route_mentions(sentence: str, base_url: str) -> list:
    """Same-origin routes (path+query) named in one clue sentence."""
    out = []
    for m in _CLUE_ROUTE.finditer(sentence):
        token = m.group(0).rstrip(".,;:!?)")
        r = _same_origin_route(token, base_url)
        if r is not None:
            out.append(r)
    return out


def _negated_paths(clue: str, base_url: str) -> set:
    """Paths named in any clue sentence that carries a negation word."""
    out = set()
    for sentence in _clue_sentences(clue):
        if _NEGATION_WORD.search(sentence):
            out.update(r.split("?", 1)[0] for r in _clue_route_mentions(sentence, base_url))
    return out


def _advertised_set(advertised, clue: str, base_url: str) -> set:
    """Canonical same-origin routes (path+query) the clue advertises.

    Sources: the explicit ``advertised`` list and route tokens in ``clue``.  A
    route named anywhere in a sentence that carries a negation ("do not call
    /admin/delete-all", "/admin/delete-all must never be called") is a warning,
    not an invitation: its path is removed from the set **even when it is also
    in the explicit list**, because that list is usually extracted from the
    same clue.  Entries keep their query string, so trust needs an exact
    path+query match (``/admin/reset`` does not advertise ``/admin/reset?all=1``).
    """
    out = set()
    for item in advertised or []:
        r = _same_origin_route(str(item), base_url)
        if r is not None:
            out.add(r)
    for sentence in _clue_sentences(clue):
        if not _NEGATION_WORD.search(sentence):
            out.update(_clue_route_mentions(sentence, base_url))
    negated = _negated_paths(clue, base_url)
    return {r for r in out if r.split("?", 1)[0] not in negated}


def route_trust(url: str, base_url: str, *, advertised=(), clue: str = "") -> RouteTrust:
    """Decide whether a clue-advertised URL is trusted to send.

    The generic scope guard refuses any route whose path carries a destructive
    word, which forced an agent onto every clue-advertised ``/admin/reset`` style
    route.  This rule is the sanctioned exception, and only this: a route is
    trusted when it is

    * same-origin to ``base_url`` (structure already validated by the shared
      guard: no traversal, no authority confusion, no embedded URL), **and**
    * either non-destructive, or carries a guarded word **but is advertised
      verbatim** by the clue (the ``advertised`` list or a path token in
      ``clue``).

    An off-origin advertised URL is never trusted (that is the SSRF the author
    did not intend), and a guarded route the clue does not name stays refused.
    Further floors apply: a route carrying a *catastrophic* word
    (``_FATAL_ROUTE_WORDS``: shutdown, wipe, drop, ..., detected through
    compounds and camelCase like the shared guard: ``wipedb``, ``dropTables``) is
    never trusted even when advertised; a route named anywhere in a negated clue
    sentence ("do not call /admin/x", "/admin/x must never be called") is not
    advertised even when the ``advertised`` list carries it; and a guarded route
    is trusted only on an exact path+query match (``/admin/reset`` advertised
    does not trust ``/admin/reset?all=1``).
    """
    route_s = _same_origin_route(url, base_url)
    if route_s is None:
        return RouteTrust(url=url, trusted=False,
                          reason="off-origin or structurally unsafe route", route=None)
    path = route_s.split("?", 1)[0]
    if _route_has_fatal_word(route_s):
        # The fatal floor, checked first: naming a catastrophic route never
        # trusts it, and a fatal word the shared guard lacks (poweroff, nuke)
        # must not pass as "non-destructive".
        return RouteTrust(url=url, trusted=False,
                          reason="catastrophic route never trusted even when advertised",
                          route=route_s, guarded=True)
    layers = _web.canonical_route_layers(path) or (path,)
    guarded = any(_web.route_has_destructive_action(layer) for layer in layers)
    if not guarded:
        return RouteTrust(url=url, trusted=True, reason="same-origin non-destructive route",
                          route=route_s, guarded=False)
    if route_s in _advertised_set(advertised, clue, base_url):
        return RouteTrust(url=url, trusted=True,
                          reason="guarded route advertised verbatim by the clue",
                          route=route_s, guarded=True)
    if path in _negated_paths(clue, base_url):
        return RouteTrust(url=url, trusted=False,
                          reason="guarded route named in a negated clue sentence",
                          route=route_s, guarded=True)
    return RouteTrust(url=url, trusted=False,
                      reason="guarded route not advertised by the clue",
                      route=route_s, guarded=True)


# ---------------------------------------------------------------------------
#  Simplest-first forge grid with label-to-wire name mutation
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ForgeCandidate:
    """One candidate forge payload."""

    fields: dict
    transport: str
    shape: str
    complexity: int
    rationale: str

    def to_dict(self) -> dict:
        return {"fields": self.fields, "transport": self.transport, "shape": self.shape,
                "complexity": self.complexity, "rationale": self.rationale}


def _canon_label(label: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(label).lower())


def _snake(label: str) -> str:
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(label))
    s = re.sub(r"[\s\-]+", "_", s).lower()
    return re.sub(r"[^a-z0-9_]+", "", s).strip("_")


def _camel(label: str) -> str:
    parts = [p for p in re.split(r"[\s\-_]+", str(label)) if p]
    if not parts:
        return ""
    head = parts[0].lower()
    return head + "".join(p[:1].upper() + p[1:].lower() for p in parts[1:])


def wire_name_variants(label: str) -> list:
    """Ranked wire-name candidates for a clue display label, simplest first.

    Order: the mechanical spellings of the label itself (identity, lowercase,
    snake_case, camelCase, no separators), then the live forge engine's
    mutation (:func:`forge_event.name_variants`: ``Desired Role`` -> ``role``,
    ``desired_role`` and its semantic synonyms), then the identifier-style
    extras in ``_SYNONYMS``.  Duplicates are dropped keeping the first
    (lowest-rank) spelling.  The order *is* the simplest-first contract the
    grid relies on.  The two modules differ only in what this one adds: the
    planner keeps the exact display spelling first (the live engine sends
    snake_case only) and appends the extras.
    """
    raw = str(label).strip()
    ordered = []
    for cand in (raw, raw.lower(), _snake(raw), _camel(raw), _canon_label(raw)):
        if cand and cand not in ordered:
            ordered.append(cand)
    for cand in _forge_event.name_variants(raw):  # shared base mutation
        if cand and cand not in ordered:
            ordered.append(cand)
    for syn in _SYNONYMS.get(_canon_label(raw), ()):  # extras ranked last
        if syn and syn not in ordered:
            ordered.append(syn)
    return ordered


# Capitalized words that are never a form field: HTTP verbs, protocol/format
# nouns, and sentence-leading function words.  Without this filter the regex
# `[A-Z][a-zA-Z]{2,}` grabs every capitalized word, so "POST an Event ... The
# form shows Event and Owner" yielded {POST, Event, The, Owner} and the accepted
# flat {event, owner} payload never reached the forge grid.
_CLUE_NON_FIELDS = frozenset({
    "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT",
    "HTTP", "HTTPS", "API", "URL", "URI", "JSON", "XML", "HTML", "FORM", "FIELD",
    "FIELDS", "BODY", "HEADER", "HEADERS", "PARAM", "PARAMS", "PARAMETER",
    "PARAMETERS", "THE", "AND", "OR", "AN", "FOR", "TO", "OF", "IN", "ON", "WITH",
    "YOUR", "YOU", "THIS", "THAT", "SHOWS", "SHOW", "SUBMIT", "SEND", "USE",
})
# A cue after which a clue lists the field labels ("the form shows Event and
# Owner", "fields: Event, Owner").
_FIELD_CUE = re.compile(r"(?i)\b(?:form shows|shows|fields?|parameters?|form)\b\s*:?\s*(.+)")


def _fields_from_clue(clue: str) -> dict:
    """Best-effort form-field labels pulled from a clue.

    Prefers the labels that follow an explicit cue ("the form shows Event and
    Owner"); otherwise scans the whole clue.  HTTP verbs, protocol/format nouns
    and sentence function words (``_CLUE_NON_FIELDS``) are never taken as fields,
    so a clue phrased as a POST instruction does not forge a ``POST`` field.
    """
    text = clue or ""
    cue = _FIELD_CUE.search(text)
    segment = cue.group(1) if cue else text
    fields = {}
    for word in re.findall(r"\b([A-Z][a-zA-Z]{2,})\b", segment):
        if word.upper() in _CLUE_NON_FIELDS:
            continue
        fields.setdefault(word, "")
    return fields


def forge_grid(fields: dict, *, transports=_TRANSPORTS, shapes=_SHAPES,
               max_candidates: int = 64) -> list:
    """A simplest-first forge grid for a POST-forge contract.

    ``fields`` maps a clue display label to the value to forge (an empty string
    when unknown).  The grid enumerates, in increasing complexity:

    * one wire-name mutation per label (:func:`wire_name_variants`),
    * the payload shape (flat, then one-key wrappers), and
    * the transport (json, form, query),

    omitting every signature field by construction.  The accepted payload on the
    event-forge row -- a flat ``{event, owner}`` json body with wire names -- is
    among the first candidates.  Bounded to ``max_candidates``.
    """
    if not isinstance(fields, dict) or not fields:
        return []
    labels = list(fields.keys())
    variants = {lbl: wire_name_variants(lbl) for lbl in labels}
    # Drop labels that look like auth noise: a forge payload should not carry one.
    labels = [lbl for lbl in labels
              if _canon_label(lbl) not in AUTH_NOISE and _snake(lbl) not in AUTH_NOISE]
    if not labels:
        return []

    shape_rank = {s: i for i, s in enumerate(shapes)}
    transport_rank = {t: i for i, t in enumerate(transports)}

    candidates = []
    seen = set()
    # Enumerate name combinations by total variant rank (simplest first).
    combos = _combinations_by_rank(labels, variants)
    for name_choice, name_cost in combos:
        payload = {name_choice[i]: fields[labels[i]] for i in range(len(labels))}
        for shape in shapes:
            body = _shape_body(payload, shape)
            for transport in transports:
                if transport == "query" and shape != "flat":
                    continue  # a nested body cannot ride the query string
                key = (json.dumps(body, sort_keys=True), shape, transport)
                if key in seen:
                    continue
                seen.add(key)
                complexity = name_cost + shape_rank[shape] * 2 + transport_rank[transport]
                rationale = _rationale(name_choice, labels, shape, transport)
                candidates.append(ForgeCandidate(fields=body, transport=transport, shape=shape,
                                                 complexity=complexity, rationale=rationale))
                if len(candidates) >= max_candidates * 4:
                    break
    candidates.sort(key=lambda c: (c.complexity, c.shape, c.transport))
    return candidates[:max_candidates]


def _combinations_by_rank(labels, variants, cap: int = 24):
    """(name tuple, total rank) combinations, lowest total rank first, bounded."""
    ranks = [list(enumerate(variants[lbl])) for lbl in labels]  # [(rank, name), ...] per label

    combos = []

    def rec(i, chosen, cost):
        if len(combos) >= cap:
            return
        if i == len(labels):
            combos.append((tuple(n for _, n in chosen), cost))
            return
        for r, name in ranks[i]:
            rec(i + 1, chosen + [(r, name)], cost + r)

    rec(0, [], 0)
    combos.sort(key=lambda c: c[1])
    return combos[:cap]


def _shape_body(payload: dict, shape: str) -> dict:
    if shape == "flat":
        return dict(payload)
    wrapper = {"wrap_data": "data", "wrap_payload": "payload", "wrap_event": "event"}[shape]
    return {wrapper: dict(payload)}


def _rationale(name_choice, labels, shape, transport) -> str:
    mapping = ", ".join(f"{labels[i]}->{name_choice[i]}" for i in range(len(labels)))
    return f"{shape}/{transport}: {mapping}"


# ---------------------------------------------------------------------------
#  Evidence-driven request minimization
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ReducedRequest:
    """One reduced request in a minimization plan."""

    fields: dict
    transport: str
    dropped: tuple
    rationale: str

    def to_dict(self) -> dict:
        return {"fields": self.fields, "transport": self.transport,
                "dropped": list(self.dropped), "rationale": self.rationale}


@dataclass(frozen=True)
class MinimizationPlan:
    """An ordered list of reduced requests to try against the target."""

    candidates: tuple

    def to_dict(self) -> dict:
        return {"candidates": [c.to_dict() for c in self.candidates]}


def minimize(request: dict) -> MinimizationPlan:
    """Turn an observed accepted request into an ordered minimization plan.

    ``request`` is ``{"fields": {name: value}, "transport": "json"|...}``.  The
    plan is ordered to try the *most reduced, least superstitious* request first:

    1. drop every auth-looking field (``signature``/``hmac``/``token``/... -- the
       exact noise the agents fixated on) -> the smallest core request;
    2. if the core still has more than one field, each single-core-field ablation
       (to find whether even fewer fields are accepted), smallest first;
    3. the core request with each dropped auth field added back one at a time
       (in case one really is required); and
    4. the full original request, last, as the fallback.

    A driver (or :func:`replay`) sends them in order and stops at the first the
    target accepts.  Nothing here sends.
    """
    fields = dict(request.get("fields", {}) or {})
    transport = str(request.get("transport", "json"))
    noise = [k for k in fields if _canon_label(k) in AUTH_NOISE or _snake(k) in AUTH_NOISE]
    core = {k: v for k, v in fields.items() if k not in noise}

    out = []
    seen = set()

    def add(f: dict, dropped, rationale):
        key = tuple(sorted(f))
        if key in seen:
            return
        seen.add(key)
        out.append(ReducedRequest(fields=dict(f), transport=transport,
                                  dropped=tuple(dropped), rationale=rationale))

    if core and noise:
        add(core, noise, "drop auth/signature fields the automation fixated on")
    elif core:
        add(core, (), "core fields only")

    core_keys = list(core)
    if len(core_keys) > 1:
        for k in core_keys:
            smaller = {x: v for x, v in core.items() if x != k}
            add(smaller, noise + [k], f"ablate core field {k!r}")

    for k in noise:  # add one auth field back at a time, in case one is required
        restored = dict(core)
        restored[k] = fields[k]
        add(restored, [n for n in noise if n != k], f"keep only auth field {k!r}")

    add(fields, (), "full original request (fallback)")
    return MinimizationPlan(candidates=tuple(out))


# ---------------------------------------------------------------------------
#  Web replay runner for timed modes
# ---------------------------------------------------------------------------

@dataclass
class ReplayStep:
    index: int
    request: dict
    status: Optional[int]
    proof: Optional[str]
    clock: float

    def to_dict(self) -> dict:
        return {"index": self.index, "status": self.status, "proof": self.proof,
                "clock": self.clock}


@dataclass
class ReplayResult:
    sent: int
    proof: Optional[str]
    stopped_reason: str
    steps: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"sent": self.sent, "proof": self.proof, "stopped_reason": self.stopped_reason,
                "steps": [s.to_dict() for s in self.steps]}


class _StepClock:
    """A monotonic step counter: the default timed-mode clock.

    Production passes a real ``time.process_time``/``thread_time`` reading; a
    test passes this or its own injected clock, so nothing here depends on wall
    time (the suite runs under heavy, variable load).
    """

    def __init__(self):
        self._n = 0

    def __call__(self) -> float:
        self._n += 1
        return float(self._n)


def default_proof(response: dict, profile=None) -> Optional[str]:
    """The default proof predicate: the active event's payoff token.

    Reads the flag/proof format from the event profile (``profile`` when given,
    else the active event via :func:`ctf.flagfmt.current`) -- never a hardcoded
    pattern.  A flag-format match wins; when the event defines a ``[proof]`` token
    (Huntress ``proof_<32 hex>``), a proof match is returned too.  No event
    resolving raises loudly (``ctf.event.EventError``), not a silent fallback.
    """
    body = "" if not isinstance(response, dict) else str(response.get("body", ""))
    headers = (response or {}).get("headers") or {}
    for header_val in headers.values():
        body += "\n" + str(header_val)
    fmt = _flagfmt.for_profile(profile) if profile is not None else _flagfmt.current()
    found = fmt.find_flags(body)
    if found:
        return found[0]
    if fmt.proof is not None:
        proofs = fmt.find_proofs(body)
        if proofs:
            return proofs[0]
    return None


def replay(plan, client: Callable[[dict], dict], *, budget: Optional[int] = None,
           clock: Optional[Callable[[], float]] = None, deadline: Optional[float] = None,
           proof_predicate: Optional[Callable[[dict], Optional[str]]] = None,
           profile=None) -> ReplayResult:
    """Drive an ordered request plan for a timed mode and stop at the first proof.

    ``plan`` is an iterable of request dicts (from :func:`forge_grid`,
    :func:`minimize`, or a recorded sequence).  ``client`` is a caller-supplied
    ``request -> response`` callable -- this module never opens a socket; a test
    passes a fake, a live run a scope-locked client.  ``budget`` caps the number
    of sends (a step budget, not seconds).  ``clock`` is an injected reading
    (default: a step counter); when ``deadline`` is set the run stops once
    ``clock() >= deadline`` *before* the next send, so timed modes are measured
    in the injected clock's units, never wall-clock seconds.

    Returns a :class:`ReplayResult` with the proof (or ``None``), how many were
    sent, and why it stopped.
    """
    requests = list(plan)
    tick = clock or _StepClock()
    predicate = proof_predicate or (lambda r: default_proof(r, profile))
    steps = []
    sent = 0
    stopped = "exhausted"
    for i, req in enumerate(requests):
        now = tick()
        if deadline is not None and now >= deadline:
            stopped = "deadline"
            break
        if budget is not None and sent >= budget:
            stopped = "budget"
            break
        response = client(req)
        sent += 1
        proof = predicate(response)
        status = response.get("status") if isinstance(response, dict) else None
        steps.append(ReplayStep(index=i, request=req, status=status, proof=proof, clock=now))
        if proof:
            stopped = "proof"
            return ReplayResult(sent=sent, proof=proof, stopped_reason=stopped, steps=steps)
    return ReplayResult(sent=sent, proof=None, stopped_reason=stopped, steps=steps)
