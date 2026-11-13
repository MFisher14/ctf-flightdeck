#!/usr/bin/env python3
"""B-149: a bounded, target-described contract executor for web Layer 1.

Layer 1 (``proof_hunt``) and its sibling readers each hard-code one exact
contract shape: ``remote_policy`` knows the fail-open policy decoder, the
``post_chain`` audit reader knows the export/report chain.  When a target
advertises a *coherent, self-describing* contract whose shape matches none of
those hand-coded classes, Layer 1 found the routes and then stopped (Day 28
"Pass the Identity": the routes were in hand and the answer was 0/1).

This module closes that gap with one **generic** executor.  It never invents a
contract: it reads a complete, same-origin clue graph the target itself
published and does exactly four things, in order:

  1. **Establish a control.**  Read the advertised follow-up (if any) and send
     the advertised action with the contract's *control* value.  Every proof
     visible in those ordinary responses is recorded as a baseline and
     subtracted; a proof the target shows anyway is never the answer.
  2. **Perform the advertised action** with the contract's *mutation* value.
  3. **Perform the advertised follow-up** (a GET), or, when the contract names
     none, read the action's own response.
  4. **Accept only a new proof from the mutated request** -- a single strict
     ``proof_`` wire token that is novel against the control baseline and that
     occupies one coherent carrier; two novel values, or a value already shown
     by the control, are surfaced as candidates and never auto-returned.

Safety (the B-149 blocker, tied to Open O-2 "may Layer 1 take state-changing
web actions without a human?"):

  * A :class:`MutationPolicy` is the *strict rule* for which advertised action
    methods run unattended.  The default is GET-only, so an advertised
    **mutation** (POST/PUT/PATCH/DELETE) is **not sent**: the executor stops at
    a structured finding naming the gate.  ``ctx['get_only']`` (set by the web
    lane while O-2 is unsettled) forces GET-only regardless of the caller's
    policy.  A human widens the policy explicitly, per method.
  * Every route is validated same-origin and non-destructive through
    ``solvers/toolkits/web`` before any request; a cross-origin or incomplete
    graph stops at a structured finding and sends nothing.
  * The executor never submits; it returns a proof or ``None`` and writes a
    structured summary into ``ctx['result_sink']`` so the live agent sees the
    exact reason it stopped.

The caller supplies the scope-locked ``WebClient`` (tests inject a compatible
fake), a deadline, a request budget and a stop event.  Target bytes are parsed
as bounded text/JSON and are never evaluated or deserialized.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
import sys
import threading
import time
import urllib.parse
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import env as ctf_env, event as ctf_event, paths as ctf_paths
except ModuleNotFoundError:
    from pathlib import Path as _Path
    sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
    from ctf import env as ctf_env, event as ctf_event, paths as ctf_paths

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "toolkits"))

import web as _web  # noqa: E402 -- sole production transport and route guard
import post_chain as _shared  # noqa: E402 -- shared proof/carrier/baseline policy

DEFAULT_MAX_REQUESTS = 10
DEFAULT_SECONDS = 20.0
DEADLINE_PAD = 0.2
#: a small time floor reserved so a permitted mutation always has its follow-up read
SEQUENCE_RESERVE = 0.5
MAX_ROUTE_BYTES = 4096
MAX_TEXT = 200_000

#: methods this executor will ever consider sending; anything else is refused
KNOWN_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
#: the one method that never changes server state, always permitted
READ_METHODS = frozenset({"GET"})
#: an advertised action header name must be a simple HTTP token (no injection)
_HEADER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,63}$")
#: headers a target-described contract may never carry its value in: the hunter's
#: credentials (a target-chosen ``Cookie``/``Authorization`` would replace the
#: scope-locked session, since ``WebClient.request`` merges caller headers last),
#: the request target (``Host``) and hop-by-hop / message-framing headers
#: (smuggling or desync).  Compared case-insensitively.
DENIED_HEADERS = frozenset({
    "host", "cookie", "cookie2", "authorization", "proxy-authorization",
    "content-length", "transfer-encoding", "content-encoding", "content-type",
    "connection", "keep-alive", "proxy-connection", "te", "trailer", "upgrade",
    "expect",
})


def _class_on(name: str) -> bool:
    env = "CTF_WEB_" + name.upper()
    value = ctf_env.get(env)
    if value is not None:
        return value.strip().lower() not in {"off", "0", "false", "no"}
    # Fail closed, like the sibling ``post_chain._class_on``: if the kill-switch
    # location cannot be read we refuse rather than silently run (Rule 10).
    try:
        root = ctf_paths.workdir()
        if (root / ("_" + name.lower() + ".off")).exists():
            return False
    except Exception:
        return False
    return True


def _has_destructive(value) -> bool:
    """Whether any string leaf of a contract value names a destructive action
    (``delete``/``drop``/``purge``/...), recursing dict/list structures.  A
    non-string scalar is safe; a destructive leaf refuses the whole contract."""
    if isinstance(value, str):
        return _web.route_has_destructive_action(value)
    if isinstance(value, dict):
        return any(_has_destructive(k) or _has_destructive(v) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return any(_has_destructive(item) for item in value)
    return False


def enabled() -> bool:
    return _class_on("contract_executor")


class MutationPolicy:
    """The strict rule for which advertised action methods run without a human.

    The executor consults the policy once, before any request, with the
    contract's advertised action method.  ``get_only`` (the default) permits
    only GET -- a read -- so no advertised state-changing action is ever sent
    unattended while Open O-2 is unsettled.  A human widens the policy by naming
    the exact methods allowed; the executor still never sends a method outside
    :data:`KNOWN_METHODS` and still requires the whole graph to be coherent.
    """

    __slots__ = ("allowed", "reason")

    def __init__(self, allowed=("GET",), reason="GET-only (Open O-2 unsettled)"):
        normalized = frozenset(str(m).upper() for m in allowed) & KNOWN_METHODS
        # GET is always a read and always permitted; it cannot be removed.
        self.allowed = frozenset(normalized | READ_METHODS)
        self.reason = str(reason)

    @classmethod
    def get_only(cls, reason="GET-only (Open O-2 unsettled)"):
        return cls(("GET",), reason)

    def permits(self, method) -> bool:
        return str(method).upper() in self.allowed

    def is_read_only(self) -> bool:
        return self.allowed <= READ_METHODS

    def deny_reason(self, method) -> str:
        m = str(method).upper()
        if m not in KNOWN_METHODS:
            return f"unknown advertised method {m!r}"
        return (f"advertised {m} action gated: policy permits only "
                f"{sorted(self.allowed)} ({self.reason})")


def _origin(value):
    return _shared._origin(value)


def _event_allows_state_change():
    """``(allowed, reason)`` from the active event profile's ``web_state_changing``
    rule (CONTRACTS.md: the BUILD-PLAN O-2 switch).  Fails closed with a named
    reason when no profile is loaded, so a non-GET policy never runs by default."""
    try:
        profile = ctf_event.current()
    except Exception as exc:
        return False, f"no event profile loaded ({type(exc).__name__}); state-changing web refused"
    slug = getattr(profile, "slug", "?")
    if bool(getattr(getattr(profile, "rules", None), "web_state_changing", False)):
        return True, f"event {slug!r} sets web_state_changing=true"
    return False, f"event {slug!r} sets web_state_changing=false (BUILD-PLAN O-2 unsettled)"


def _resolve_policy(ctx: dict) -> MutationPolicy:
    """The effective policy.

    ``get_only`` forces the read-only policy regardless of any caller-supplied
    one, so the web lane's GET-only guarantee holds.  A caller may widen the
    policy to a non-GET method, but that only takes effect when the active event
    profile sets ``web_state_changing=true``; otherwise it is narrowed back to
    GET-only with a named reason.  This makes the event profile -- not an
    arbitrary caller -- the single O-2 switch."""
    if ctx.get("get_only"):
        return MutationPolicy.get_only("GET-only (web lane get_only flag)")
    policy = ctx.get("mutation_policy")
    if not isinstance(policy, MutationPolicy):
        return MutationPolicy.get_only()
    if policy.is_read_only():
        return policy
    allowed, reason = _event_allows_state_change()
    if not allowed:
        return MutationPolicy.get_only(
            f"GET-only: a non-GET policy needs web_state_changing=true ({reason})")
    return policy


def _clue_graph(ctx: dict, base_url: str):
    """The target-published contract graph, from ``ctx['contract']`` or the
    cached ``/api/clues`` document under a ``contract`` key.  Returns the raw
    dict or ``None`` -- completeness is validated by :func:`build_contract`."""
    explicit = ctx.get("contract")
    if isinstance(explicit, dict):
        return explicit
    for raw_path, raw_response in list((ctx.get("preloaded") or {}).items())[:80]:
        key = _web.safe_preloaded_route_key(raw_path, base_url, max_bytes=MAX_ROUTE_BYTES)
        if key is None or not key.endswith("/api/clues"):
            continue
        doc = _shared._json_document(raw_response)
        if isinstance(doc, dict) and isinstance(doc.get("contract"), dict):
            return doc["contract"]
    return None


class Contract:
    """A validated, same-origin, executable contract. See :func:`build_contract`."""

    __slots__ = ("action_route", "action_method", "action_param", "action_header",
                 "control", "mutation", "follow_up_route", "effect")

    def __init__(self, *, action_route, action_method, action_param, action_header,
                 control, mutation, follow_up_route, effect):
        self.action_route = action_route
        self.action_method = action_method
        self.action_param = action_param
        self.action_header = action_header
        self.control = control
        self.mutation = mutation
        self.follow_up_route = follow_up_route
        self.effect = effect


def build_contract(graph, base_url):
    """Validate a raw clue graph into a :class:`Contract`, or return a structured
    ``{"incomplete": <reason>}`` finding.  Never raises.

    Required: a same-origin ``action_route`` and a distinct ``control`` /
    ``mutation`` pair.  Optional carriers for the value (exactly one may be
    named): ``action_param`` (a query parameter) or ``action_header`` (a request
    header, e.g. the ``X-Delegated-User`` trusted-identity class); with neither
    the value is a JSON/text body.  Also optional: ``action_method`` (default
    GET), a same-origin ``follow_up_route``, and an asserted ``effect`` token the
    mutated payoff must coherently carry.  A ``control``, ``mutation`` or
    parameter name that carries a destructive action token is refused.  A header
    carrier must be a plain token outside :data:`DENIED_HEADERS` (credentials,
    ``Host``, hop-by-hop and framing headers), and both of its values must be
    control-character-free header text; all of this is checked before any send.
    """
    if not isinstance(graph, dict):
        return {"incomplete": "no target-described contract graph"}
    action_route = _shared._same_origin_route(graph.get("action_route"), base_url)
    if action_route is None:
        return {"incomplete": "no same-origin, non-destructive advertised action route"}
    method = str(graph.get("action_method") or "GET").upper()
    if method not in KNOWN_METHODS:
        return {"incomplete": f"advertised action method {method!r} is not a known HTTP method"}
    param = graph.get("action_param")
    if param is not None:
        param = str(param)
        # safe_route_query_component also refuses a destructive action word
        # (route_has_destructive_action on every decoded layer), so one check
        # covers nested targets, traversal and destructive parameter names.
        if not param or not _web.safe_route_query_component(param, max_bytes=256):
            return {"incomplete": "advertised action parameter name is unusable "
                                  "(nested target, traversal or destructive action)"}
    header = graph.get("action_header")
    if header is not None:
        header = str(header)
        if not _HEADER_NAME.match(header):
            return {"incomplete": "advertised action header name is unusable"}
        if header.lower() in DENIED_HEADERS:
            return {"incomplete": f"advertised action header {header!r} is a denied "
                                  "credential/framing header"}
    if param is not None and header is not None:
        return {"incomplete": "contract names both a query and a header carrier (ambiguous)"}
    if "control" not in graph or "mutation" not in graph:
        return {"incomplete": "contract lacks an explicit control/mutation pair"}
    control, mutation = graph.get("control"), graph.get("mutation")
    if control == mutation:
        return {"incomplete": "control and mutation are identical (no differential to execute)"}
    if _has_destructive(control) or _has_destructive(mutation):
        return {"incomplete": "advertised control/mutation carries a destructive action token"}
    if header is not None and (_header_text(control) is None or _header_text(mutation) is None):
        # Validated here, before any send, so a bad mutation value can never
        # leave after its control already went out.
        return {"incomplete": "advertised header value is unusable (control character "
                              "or not serializable)"}
    follow_up = None
    if graph.get("follow_up_route") is not None:
        follow_up = _shared._same_origin_route(graph.get("follow_up_route"), base_url)
        if follow_up is None:
            return {"incomplete": "advertised follow-up route is not same-origin"}
    effect = graph.get("effect")
    effect = _shared._snake(effect) if isinstance(effect, str) and effect.strip() else None
    return Contract(action_route=action_route, action_method=method, action_param=param,
                    action_header=header, control=control, mutation=mutation,
                    follow_up_route=follow_up, effect=effect)


def _header_text(value):
    """The string form of a header-carried contract value, or ``None`` when it
    cannot be a safe header value (a C0 control such as CR/LF, DEL, or a value
    that does not serialize).  Destructive tokens are refused separately, on the
    raw value, by :func:`_has_destructive` in :func:`build_contract`."""
    text = value if isinstance(value, str) else _value_to_body(value)
    if text is None or any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in text):
        return None
    return text


def _value_to_body(value):
    """A non-string contract body is sent as compact JSON; a string is sent as-is."""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, separators=(",", ":"))
    except (TypeError, ValueError):
        return None


def _effect_confirmed(response, effect_token):
    """Whether the payoff response coherently carries the asserted effect.

    The effect must appear as the value of an ``effect``/``status``/``result``/
    ``outcome``/``decision`` field in the sole coherent JSON view.
    ``_json_document`` returns a document only when exactly one coherent JSON
    carrier exists (``security_json.loads_unique``), so an ambiguous multi-view
    or duplicate-carrier parser differential yields ``None`` here and is never
    confirmed -- the coherence gate lives in that single parse, not in a second,
    redundant anchor recheck.
    """
    doc = _shared._json_document(response)
    if not isinstance(doc, (dict, list)):
        return False
    for path, value in _shared._walk(doc):
        if (path and _shared._snake(path[-1]) in {"effect", "status", "result", "outcome", "decision"}
                and _shared._snake(value) == effect_token):
            return True
    return False


class _Runner:
    """One target. Sequential, bounded, never raises out of :meth:`run`."""

    def __init__(self, target, ctx):
        self.target = dict(target) if isinstance(target, dict) else {"url": str(target)}
        self.url = str(self.target.get("url") or "")
        self.ctx = dict(ctx or {})
        try:
            self.deadline = (float(self.ctx["deadline"]) if self.ctx.get("deadline") is not None
                             else time.time() + DEFAULT_SECONDS)
        except (TypeError, ValueError):
            self.deadline = time.time() + DEFAULT_SECONDS
        try:
            self.max_requests = max(0, int(self.ctx.get("max_requests", DEFAULT_MAX_REQUESTS)))
        except (TypeError, ValueError):
            self.max_requests = DEFAULT_MAX_REQUESTS
        self.external_stop = self.ctx.get("stop")
        self.policy = _resolve_policy(self.ctx)
        self.baselines = []
        for value in list(self.ctx.get("baseline_texts") or [])[:80]:
            text = str(value or "")[:MAX_TEXT]
            if text and text not in self.baselines:
                self.baselines.append(text)
        self.preloaded = dict(self.ctx.get("preloaded") or {})
        self.requests = 0
        self.posts = 0            # non-GET sends actually put on the wire
        self.responses = []
        self.candidates = []
        self.uuid4 = False
        self.success = False
        self.where = None
        self.stopped = None
        self.finding = None
        self.t0 = time.time()
        self._gate = threading.Lock()
        self._stopped = False
        self.client = None

    # -- transport gate -------------------------------------------------------
    def _left(self):
        return self.deadline - time.time() if self.deadline is not None else None

    def stop_now(self):
        with self._gate:
            self._stopped = True

    def _may_send_locked(self):
        if self._stopped or (hasattr(self.external_stop, "is_set") and self.external_stop.is_set()):
            self.stopped = self.stopped or "stopped"
            return False
        if self.requests >= self.max_requests:
            self.stopped = self.stopped or "max_requests"
            return False
        left = self._left()
        if left is not None and left <= DEADLINE_PAD:
            self.stopped = self.stopped or "deadline"
            return False
        return True

    def _acquire_client(self):
        if self.client is not None:
            return self.client
        wanted = _origin(self.url)
        if wanted is None:
            self.stopped = "invalid target origin"
            return None
        try:
            candidate = self.ctx.get("client")
            if candidate is None and callable(self.ctx.get("client_factory")):
                candidate = self.ctx["client_factory"](self.url, DEFAULT_SECONDS)
            if candidate is None:
                # A self-built client inherits the web lane's GET-only guarantee
                # when the caller set it, so a mutation never escapes on this path.
                kwargs = {"get_only": True} if self.ctx.get("get_only") else {}
                candidate = _web.WebClient(self.url, timeout=DEFAULT_SECONDS, **kwargs)
            if _origin(getattr(candidate, "base", None)) != wanted:
                self.stopped = "client scope mismatch"
                return None
            self.client = candidate
            return candidate
        except Exception as exc:
            self.stopped = f"no scoped client: {type(exc).__name__}"
            return None

    def _can_run_sequence(self, requests, posts):
        """Atomically reserve a bounded step count before the first action send."""
        with self._gate:
            if self._acquire_client() is None or not self._may_send_locked():
                return False
            if self.requests + requests > self.max_requests:
                self.stopped = self.stopped or "insufficient request budget for contract sequence"
                return False
            left = self._left()
            if posts > 0 and left is not None and left <= DEADLINE_PAD + SEQUENCE_RESERVE:
                self.stopped = self.stopped or "insufficient time for mutation and follow-up"
                return False
            return True

    def _route_ok(self, path, method):
        """Second, independent scope/read-action check: the hunter's own
        ``ctx['route_allowed']`` (the sibling readers all honor it).  A refusal
        stops the sequence with a named finding before any send."""
        callback = self.ctx.get("route_allowed")
        if not callable(callback):
            return True
        clean = str(path).split("?", 1)[0]
        try:
            ok = callback(clean, method)
        except TypeError:
            try:
                ok = callback(clean)
            except Exception:
                ok = False
        except Exception:
            ok = False
        if not ok:
            self.finding = self.finding or f"route_allowed refused {method} {clean}"
            self.stopped = self.stopped or self.finding
        return bool(ok)

    def _send(self, method, route, *, data=None, headers=None, role="plain"):
        method = str(method).upper()
        if method not in KNOWN_METHODS:
            self.stopped = self.stopped or f"refused verb {method}"
            return None
        if not self._route_ok(route, method):
            return None
        with self._gate:
            client = self._acquire_client()
            if client is None or not self._may_send_locked():
                return None
            try:
                left = self._left()
                client.timeout = (DEFAULT_SECONDS if left is None
                                  else max(0.2, min(DEFAULT_SECONDS, left - 0.1)))
            except Exception:
                pass
            self.requests += 1
            if method not in READ_METHODS:
                self.posts += 1
            try:
                response = client.request(method, route, data=data, headers=headers,
                                          allow_redirects=False)
            except Exception as exc:
                self.responses.append({"role": role, "method": method,
                                       "path": str(route).split("?", 1)[0],
                                       "status": None, "error": type(exc).__name__})
                self.stopped = self.stopped or f"transport: {type(exc).__name__}"
                self._stopped = True
                return None
            response = _shared._normal_response(response) or response
            self.responses.append({"role": role, "method": method,
                                   "path": str(route).split("?", 1)[0],
                                   "status": response.get("status") if isinstance(response, dict) else None})
            return response

    # -- action builders ------------------------------------------------------
    def _action_request(self, contract, value, role):
        """Send the advertised action carrying ``value`` (control or mutation) in
        the one declared carrier: a query parameter, a request header, or a body.
        The guarded query keeps ``guard_query`` on, so a destructive action word
        that reached the assembled query is still refused."""
        if contract.action_header is not None:
            # build_contract already proved both values usable as header text.
            return self._send(contract.action_method, contract.action_route,
                              headers={contract.action_header: _header_text(value)}, role=role)
        if contract.action_param is not None:
            query = urllib.parse.urlencode({contract.action_param: "" if value is None else str(value)})
            route = _web.safe_same_origin_route(
                contract.action_route + ("&" if "?" in contract.action_route else "?") + query,
                self.url, allow_query=True, guard_query=True, max_bytes=MAX_ROUTE_BYTES)
            if route is None:
                self.stopped = self.stopped or "assembled action query was not in scope"
                return None
            return self._send(contract.action_method, route, role=role)
        body = _value_to_body(value)
        if body is None:
            self.stopped = self.stopped or "contract body value was not serializable"
            return None
        headers = {"Content-Type": "application/json"} if not isinstance(contract.control, str) else None
        return self._send(contract.action_method, contract.action_route,
                          data=body, headers=headers, role=role)

    def _absorb_baseline(self, response):
        if isinstance(response, dict):
            text = _shared._baseline_text(response)
            if text and text not in self.baselines:
                self.baselines.append(text)

    # -- the executor ---------------------------------------------------------
    def run(self):
        if not enabled():
            self.stopped = "off"
            return None
        graph = _clue_graph(self.ctx, self.url)
        built = build_contract(graph, self.url)
        if isinstance(built, dict):
            self.finding = built["incomplete"]
            self.stopped = "contract incomplete: " + built["incomplete"]
            return None
        contract = built

        # Safety gate before any request: an advertised mutation runs only when
        # the effective policy permits its method (GET is always allowed).
        if not self.policy.permits(contract.action_method):
            self.finding = self.policy.deny_reason(contract.action_method)
            self.stopped = self.finding
            return None

        is_mutation = contract.action_method not in READ_METHODS
        # Step budget: pre-follow-up read (if any) + control action + control
        # follow-up read (if any) + mutation action + payoff follow-up read.
        steps = 2 + (3 if contract.follow_up_route else 0)
        posts = 2 if is_mutation else 0  # control action + mutation action
        if not self._can_run_sequence(steps, posts):
            return None

        host = urllib.parse.urlsplit(self.url).hostname

        # 1. establish the control -------------------------------------------
        if contract.follow_up_route:
            self._absorb_baseline(self._send("GET", contract.follow_up_route, role="pre-follow-up"))
        control = self._action_request(contract, contract.control, "control-action")
        self._absorb_baseline(control)
        if not isinstance(control, dict):
            # No control response (a wire failure, a refused route or query):
            # without a baseline the mutation's novelty cannot be judged, so the
            # sequence halts before the mutation and the finding says so.
            on_wire = bool(self.stopped and self.stopped.startswith("transport"))
            self.finding = self.finding or (
                "control action failed on the wire; mutation not attempted" if on_wire
                else f"control action not sent ({self.stopped or 'refused'}); "
                     "mutation not attempted")
            self.stopped = self.stopped or self.finding
            return None
        if contract.follow_up_route:
            self._absorb_baseline(self._send("GET", contract.follow_up_route, role="control-follow-up"))

        # 2. perform the advertised action with the mutation -----------------
        action = self._action_request(contract, contract.mutation, "mutation-action")
        if not isinstance(action, dict):
            self.stopped = self.stopped or "mutated action produced no readable response"
            return None

        # 3. perform the advertised follow-up (GET), else read the action -----
        if contract.follow_up_route:
            payoff = self._send("GET", contract.follow_up_route, role="payoff-follow-up")
        else:
            payoff = action
        if not isinstance(payoff, dict):
            self.stopped = self.stopped or "advertised follow-up produced no readable response"
            return None

        # 4. assert the advertised effect, then accept only a novel proof -----
        if contract.effect is not None and not _effect_confirmed(payoff, contract.effect):
            self.finding = f"advertised effect {contract.effect!r} was not confirmed in one coherent carrier"
            self.stopped = self.finding
            return None

        info = _shared.extract_anchored(payoff, self.baselines, anchored=True, host=host)
        self.where = "contract_executor:" + (contract.action_method.lower())
        self.uuid4 = bool(info.get("uuid4"))
        self.candidates = list(info.get("candidates") or [])[:12]
        auto = info.get("auto")
        # ``success`` means the run yielded a result worth banking -- a novel
        # proof or at least a surfaced candidate.  A sequence that completed but
        # found neither is NOT a success: reporting it so lets ``_run_peer`` treat
        # this reader as non-terminal, so a later GET wave can still find the
        # proof instead of the hunt stopping on an empty contract run.
        self.success = bool(auto) or bool(self.candidates)
        if auto is None:
            self.stopped = self.stopped or (
                "mutated follow-up carried no single novel strict proof")
        return auto

    def summary(self, proof):
        return {"proof": proof, "class": "target_described_contract", "success": self.success,
                "terminal": False, "finding": self.finding,
                "candidates": list(dict.fromkeys(self.candidates))[:12], "uuid4": self.uuid4,
                "requests": self.requests, "posts": self.posts,
                "policy": sorted(self.policy.allowed),
                "seconds": round(time.time() - self.t0, 3), "where": self.where,
                "stopped": self.stopped, "responses": self.responses[:12]}


def _surface(runner, ctx):
    evidence = ctx.get("evidence") if isinstance(ctx, dict) else None
    if not isinstance(evidence, list):
        return
    aid = runner.target.get("answer_id") or "target"
    for value in list(dict.fromkeys(runner.candidates))[:6]:
        line = _web.safe_display_text(
            f"WEB CONTRACT CANDIDATE {aid}: {value} (mutated follow-up; not auto-submitted)", 600)
        if line not in evidence:
            evidence.append(line)
    if runner.finding and not runner.success:
        line = _web.safe_display_text(
            f"WEB CONTRACT FINDING {aid}: {runner.finding}", 600)
        if line not in evidence:
            evidence.append(line)


def solve(target, ctx=None):
    """Execute one target-described contract; never raises and never submits."""
    ctx = dict(ctx or {})
    runner = _Runner(target, ctx)
    proof = None
    try:
        proof = runner.run()
    except Exception as exc:
        runner.stopped = runner.stopped or f"error: {type(exc).__name__}"
    finally:
        runner.stop_now()
    _surface(runner, ctx)
    summary = runner.summary(proof)
    aid = runner.target.get("answer_id") or "target"
    sink = ctx.get("result_sink")
    if isinstance(sink, dict):
        sink[aid] = summary
    _write_log(ctx.get("log_dir"), ctx.get("challenge"), aid, summary)
    return proof


def solve_targets(targets, ctx=None):
    out = {}
    for index, target in enumerate(list(targets or [])):
        if not isinstance(target, dict):
            continue
        item = dict(target)
        aid = str(item.get("answer_id") or item.get("id") or f"target-{index + 1}")
        item["answer_id"] = aid
        out[aid] = solve(item, ctx)
    return out


def _write_log(log_dir, challenge, aid, summary):
    if not log_dir:
        return
    try:
        folder = Path(log_dir)
        folder.mkdir(parents=True, exist_ok=True)
        row = {"at": _dt.datetime.now().astimezone().isoformat(timespec="seconds"),
               "challenge": challenge, "answer_id": aid, **summary}
        with (folder / "contract_executor.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, separators=(",", ":"), default=str) + "\n")
    except Exception:
        pass


__all__ = ["DEFAULT_MAX_REQUESTS", "DEFAULT_SECONDS", "MutationPolicy", "Contract",
           "build_contract", "enabled", "solve", "solve_targets"]
