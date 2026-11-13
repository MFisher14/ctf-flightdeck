#!/usr/bin/env python3
"""Exact, bounded stateful read transactions for the live Web lane.

This is a small execution engine plus two conservative adapters:
``upload_preview`` (generated inert text -> correlated preview) and
``single_use_redemption`` (challenge-synthetic one-shot -> correlated audit).
It consumes only a complete ``state_transaction`` object from the target's
duplicate-safe ``/api/clues`` JSON.  No prose inference, route guessing, raw
request recipe, arbitrary body, retry, concurrency or off-origin request is
accepted.

The complete request group is reserved before mutation.  Once a POST begins,
transport failure, 408/425/429, or an unstructured 5xx is the terminal
``ambiguous_mutation`` state and no readback or sibling action is attempted.
"""

from __future__ import annotations

import hashlib
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
TOOLKITS = HERE.parent / "toolkits"
if str(TOOLKITS) not in sys.path:
    sys.path.insert(0, str(TOOLKITS))
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import web as _web  # noqa: E402
import security_json as _security_json  # noqa: E402

try:
    import forge_event as _proofs  # noqa: E402
except Exception:
    _proofs = None


DEFAULT_SECONDS = 20.0
DEFAULT_MAX_REQUESTS = 5
REQUEST_TIMEOUT = 6.0
DEADLINE_PAD = 0.4
READBACK_RESERVE_SECONDS = 1.0
MAX_BODY = 128 * 1024
MAX_TOTAL_BYTES = 384 * 1024
MAX_REQUEST_BYTES = 16 * 1024
NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
SAFE_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\.txt$")
FATAL_ROUTE = re.compile(
    r"(?i)(?:^|[/_.-])(?:delete|destroy|drop|wipe|purge|truncate|erase|revoke|logout|"
    r"signout|disable|deactivate|uninstall|kill|shutdown|reboot|ban|suspend|cancel|"
    r"transfer|pay|admin|account|password)(?=$|[/_.-]|\d)"
)
PROOF = flagfmt.PROOF_TEXT

COMMON_KEYS = {
    "kind", "challenge_synthetic", "control_route", "action_route", "readback_route",
    "encoding", "precondition_field", "precondition_equals", "csrf_source_field",
    "csrf_field", "action_id_source_field", "action_id_field", "idempotency_header",
    "object_id_field", "readback_id_parameter", "readback_object_id_field",
    "readback_action_id_field", "effect_field", "effect", "invariant_field",
    "invariant_value",
}
UPLOAD_KEYS = COMMON_KEYS | {"absence_field", "content_field", "filename_field", "filename"}
REDEEM_KEYS = COMMON_KEYS | {"reference_field", "reference"}


def enabled():
    raw = ctf_env.get("CTF_WEB_STATE_TRANSACTION")
    if raw is not None:
        return raw.strip().lower() not in ("off", "0", "false", "no")
    try:
        root = ctf_paths.workdir()
        return not (root / "_web_state_transaction.off").exists()
    except Exception:
        return False


def _origin(value):
    try:
        parts = urllib.parse.urlsplit(str(value or ""))
        if (parts.scheme not in ("http", "https") or not parts.hostname
                or parts.username is not None or parts.password is not None or parts.fragment):
            return None
        return parts.scheme, parts.hostname.lower(), parts.port or (443 if parts.scheme == "https" else 80)
    except Exception:
        return None


def _route(value, base_url):
    try:
        route = _web.safe_same_origin_route(
            value, base_url, allow_query=False, guard_query=True, max_bytes=1024)
        if not route:
            return None
        for layer in _web.canonical_route_layers(route, max_bytes=1024) or ():
            if FATAL_ROUTE.search(layer):
                return None
        return route
    except Exception:
        return None


def _response(value):
    if not isinstance(value, dict):
        return None
    if "body" in value:
        return value
    if "text" in value:
        out = dict(value)
        out["body"] = str(value.get("text") or "").encode("utf-8")
        out["response_headers"] = dict(value.get("headers") or {})
        return out
    return None


def _text(response):
    if not isinstance(response, dict):
        return ""
    if _proofs is not None and hasattr(_proofs, "response_text_views"):
        try:
            views = _proofs.response_text_views(response)
            return str(views[0])[:MAX_BODY] if views else ""
        except Exception:
            return ""
    raw = response.get("body", response.get("text", b""))
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw[:MAX_BODY]).decode("utf-8", "replace")
    return str(raw or "")[:MAX_BODY]


def _baseline_text(response):
    if _proofs is not None and hasattr(_proofs, "response_baseline_text"):
        try:
            return _proofs.response_baseline_text(response)
        except Exception:
            return ""
    return _text(response)


def _json(response):
    try:
        views = (_proofs.response_text_views(response)
                 if _proofs is not None and hasattr(_proofs, "response_text_views") else [_text(response)])
        value = _security_json.loads_unique(views, max_chars=MAX_BODY)
        return value if isinstance(value, dict) else None
    except Exception:
        return None


def _scalar(value, *, max_bytes=512):
    return (value is not None and not isinstance(value, (dict, list))
            and not isinstance(value, float)
            and 0 < len(str(value).encode("utf-8", "strict")) <= max_bytes)


def _same(left, right):
    return type(left) is type(right) and left == right


def _compile(raw, base_url):
    if not isinstance(raw, dict):
        return None
    kind = raw.get("kind")
    keys = UPLOAD_KEYS if kind == "upload_preview" else REDEEM_KEYS if kind == "single_use_redemption" else None
    if keys is None or set(raw) - keys or raw.get("challenge_synthetic") is not True:
        return None
    required = {
        "kind", "challenge_synthetic", "control_route", "action_route", "readback_route",
        "encoding", "precondition_field", "precondition_equals", "csrf_source_field",
        "csrf_field", "action_id_source_field", "action_id_field", "object_id_field",
        "readback_id_parameter", "readback_object_id_field", "readback_action_id_field",
        "effect_field", "effect", "invariant_field", "invariant_value",
    }
    if kind == "upload_preview":
        required |= {"absence_field", "content_field", "filename_field", "filename"}
    else:
        required |= {"reference_field", "reference"}
    if not required <= set(raw) or raw.get("encoding") not in ("json", "form"):
        return None
    routes = {name: _route(raw.get(name), base_url)
              for name in ("control_route", "action_route", "readback_route")}
    if any(value is None for value in routes.values()) or len(set(routes.values())) != 3:
        return None
    name_keys = [key for key in required if key.endswith("_field") or key.endswith("_parameter")]
    if any(not isinstance(raw.get(key), str) or not NAME.fullmatch(raw[key]) for key in name_keys):
        return None
    if len({raw["csrf_field"], raw["action_id_field"]}) != 2:
        return None
    for key in ("precondition_equals", "effect", "invariant_value"):
        if not _scalar(raw.get(key)):
            return None
    header = raw.get("idempotency_header")
    if header is not None and header != "Idempotency-Key":
        return None
    if kind == "upload_preview":
        if (not isinstance(raw.get("filename"), str) or not SAFE_FILENAME.fullmatch(raw["filename"])
                or len({raw["content_field"], raw["filename_field"], raw["csrf_field"],
                        raw["action_id_field"]}) != 4):
            return None
    else:
        if not _scalar(raw.get("reference")) or len({raw["reference_field"], raw["csrf_field"],
                                                     raw["action_id_field"]}) != 3:
            return None
    out = dict(raw)
    out.update(routes)
    return out


class _Engine:
    def __init__(self, target, ctx):
        self.target = dict(target) if isinstance(target, dict) else {"url": str(target)}
        self.url = str(self.target.get("url") or "")
        self.ctx = dict(ctx or {})
        try:
            self.deadline = float(self.ctx.get("deadline")) if self.ctx.get("deadline") is not None \
                else time.time() + DEFAULT_SECONDS
        except (TypeError, ValueError):
            self.deadline = time.time() + DEFAULT_SECONDS
        try:
            self.max_requests = max(0, min(DEFAULT_MAX_REQUESTS,
                                           int(self.ctx.get("max_requests", DEFAULT_MAX_REQUESTS))))
        except (TypeError, ValueError):
            self.max_requests = DEFAULT_MAX_REQUESTS
        try:
            self.max_bytes = max(0, min(
                MAX_TOTAL_BYTES, int(self.ctx.get("max_bytes", MAX_TOTAL_BYTES) or 0)))
        except (TypeError, ValueError, OverflowError):
            self.max_bytes = MAX_TOTAL_BYTES
        self.requests = self.posts = self.bytes = 0
        self.responses = []
        self.baselines = [str(value or "")[:MAX_BODY]
                          for value in list(self.ctx.get("baseline_texts") or [])[:40]]
        self.preloaded = dict(self.ctx.get("preloaded") or {})
        self.stop = self.ctx.get("stop")
        self.terminal = False
        self.ambiguous_mutation = False
        self.mutation_started = False
        self.success = False
        self.candidates = []
        self.stopped = None
        self.kind = None
        self.marker = None
        self._lock = threading.Lock()
        self._reserved = 0
        self.client = None
        try:
            candidate = self.ctx.get("client")
            if candidate is None and callable(self.ctx.get("client_factory")):
                candidate = self.ctx["client_factory"](self.url, REQUEST_TIMEOUT)
            if candidate is None:
                candidate = _web.WebClient(self.url, timeout=REQUEST_TIMEOUT)
            if _origin(getattr(candidate, "base", None)) != _origin(self.url):
                raise _web.OutOfScope("injected client scope mismatch")
            self.client = candidate
        except Exception as exc:
            self.stopped = f"no scoped client: {type(exc).__name__}"

    def _may_send(self):
        reserved_readback = (self.mutation_started and self._reserved > 0
                             and not self.ambiguous_mutation)
        if self.client is None or (self.terminal and not reserved_readback):
            return False
        if hasattr(self.stop, "is_set") and self.stop.is_set():
            self.stopped = self.stopped or "stopped"
            return False
        if self.requests >= self.max_requests:
            self.stopped = self.stopped or "max_requests"
            return False
        if self.deadline - time.time() <= DEADLINE_PAD:
            self.stopped = self.stopped or "deadline"
            return False
        return True

    def _reserve_group(self, count):
        with self._lock:
            if (not self._may_send() or count <= 0
                    or self.requests + count > self.max_requests
                    or self.deadline - time.time() <= READBACK_RESERVE_SECONDS + DEADLINE_PAD):
                self.stopped = self.stopped or "cannot reserve complete transaction"
                return False
            self._reserved = count
            return True

    def _send(self, method, route, *, data=None, headers=None, role="read"):
        with self._lock:
            if not self._may_send():
                return None
            if self.mutation_started and method != "POST" and self._reserved <= 0:
                self.stopped = "readback was not reserved before mutation"
                self.terminal = True
                return None
            encoded = data.encode("utf-8") if isinstance(data, str) else bytes(data or b"")
            if len(encoded) > MAX_REQUEST_BYTES or self.bytes + len(encoded) > self.max_bytes:
                self.stopped = "byte budget"
                return None
            self.requests += 1
            self.posts += int(method == "POST")
            self.bytes += len(encoded)
            if self._reserved:
                self._reserved -= 1
            if method == "POST":
                self.mutation_started = True
                self.terminal = True
            try:
                self.client.timeout = max(0.2, min(
                    REQUEST_TIMEOUT, self.deadline - time.time() - DEADLINE_PAD))
                response = self.client.request(
                    method, route, data=data, headers=dict(headers or {}), allow_redirects=False)
            except Exception as exc:
                self.responses.append({"role": role, "method": method, "status": None,
                                       "error": type(exc).__name__})
                if method == "POST":
                    self.ambiguous_mutation = True
                    self.stopped = "ambiguous_mutation"
                else:
                    self.stopped = f"transport: {type(exc).__name__}"
                self.terminal = True
                return None
        body = response.get("body", b"") if isinstance(response, dict) else b""
        size = len(body) if isinstance(body, (bytes, bytearray)) else len(str(body).encode())
        self.bytes += size
        status = response.get("status") if isinstance(response, dict) else None
        self.responses.append({"role": role, "method": method, "status": status, "bytes": size})
        if (not isinstance(response, dict) or response.get("truncated")
                or self.bytes > self.max_bytes):
            if method == "POST":
                self.ambiguous_mutation = True
                self.stopped = "ambiguous_mutation"
            else:
                self.stopped = "incomplete/oversized response"
            self.terminal = True
            return None
        if method == "POST" and (status in (408, 425, 429) or status is None
                                 or (isinstance(status, int) and status >= 500)):
            self.ambiguous_mutation = True
            self.stopped = "ambiguous_mutation"
            return None
        return response

    def run(self):
        if not enabled() or self.client is None or self.max_requests <= 0 or self.max_bytes <= 0:
            self.stopped = self.stopped or "off/unavailable"
            return None
        clue_response = _response(self.preloaded.get("/api/clues"))
        clues = _json(clue_response)
        if not isinstance(clues, dict) or "state_transaction" not in clues:
            self.stopped = "no state transaction contract"
            return None
        plan = _compile(clues.get("state_transaction"), self.url)
        if plan is None:
            self.stopped = "invalid state transaction contract"
            self.terminal = True
            return None
        route_gate = self.ctx.get("route_allowed")
        if callable(route_gate):
            try:
                action_word = "upload" if plan["kind"] == "upload_preview" else "redeem"
                route_checks = (
                    # A route family may carry the action noun in all three
                    # paths (for example /redeem/control and /redeem/audit).
                    # The caller still receives the exact method and may waive
                    # only this adapter's closed upload/redeem verb set.
                    (plan["control_route"], "GET", (action_word,)),
                    (plan["action_route"], "POST", (action_word,)),
                    (plan["readback_route"], "GET", (action_word,)),
                )
                if not all(bool(route_gate(path, method=method, allowed_actions=actions))
                           for path, method, actions in route_checks):
                    self.stopped = "caller route guard refused transaction"
                    self.terminal = True
                    return None
            except Exception:
                self.stopped = "caller route guard failed"
                self.terminal = True
                return None
        self.kind = plan["kind"]
        control = _response(self.preloaded.get(plan["control_route"]))
        if control is None:
            control = self._send("GET", plan["control_route"], role="precondition")
        if control is None or not isinstance(control.get("status"), int) \
                or not 200 <= control["status"] < 300:
            self.stopped = self.stopped or "precondition unavailable"
            return None
        self.baselines.append(_baseline_text(control))
        cdoc = _json(control)
        if (not isinstance(cdoc, dict)
                or not _same(cdoc.get(plan["precondition_field"]), plan["precondition_equals"])):
            self.stopped = "precondition mismatch"
            return None
        csrf = cdoc.get(plan["csrf_source_field"])
        action_id = cdoc.get(plan["action_id_source_field"])
        if not _scalar(csrf) or not _scalar(action_id):
            self.stopped = "missing csrf/action identity"
            return None
        if self.kind == "upload_preview":
            if cdoc.get(plan["absence_field"]) is not True:
                self.stopped = "inert marker absence not established"
                return None
            seed = "|".join((self.url, str(self.target.get("answer_id") or "target"),
                             str(action_id), plan["filename"]))
            self.marker = "huntress-inert-" + hashlib.sha256(seed.encode()).hexdigest()[:20]
            body = {plan["content_field"]: self.marker, plan["filename_field"]: plan["filename"],
                    plan["csrf_field"]: csrf, plan["action_id_field"]: action_id}
        else:
            body = {plan["reference_field"]: plan["reference"], plan["csrf_field"]: csrf,
                    plan["action_id_field"]: action_id}
        if not self._reserve_group(2):
            return None
        if plan["encoding"] == "json":
            encoded = json.dumps(body, separators=(",", ":"), ensure_ascii=False)
            headers = {"Content-Type": "application/json"}
        else:
            encoded = urllib.parse.urlencode(list(body.items()))
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if plan.get("idempotency_header"):
            headers["Idempotency-Key"] = str(action_id)
        action = self._send("POST", plan["action_route"], data=encoded, headers=headers, role="action")
        if action is None:
            return None
        if not isinstance(action.get("status"), int) or not 200 <= action["status"] < 300:
            self.stopped = "action explicitly rejected"
            return None
        self.baselines.append(_baseline_text(action))
        adoc = _json(action)
        object_id = adoc.get(plan["object_id_field"]) if isinstance(adoc, dict) else None
        if (not isinstance(adoc, dict) or not _scalar(object_id)
                or not _same(adoc.get(plan["action_id_field"]), action_id)):
            self.stopped = "uncorrelated action receipt"
            return None
        query = urllib.parse.urlencode([(plan["readback_id_parameter"], str(object_id))])
        readback_path = plan["readback_route"] + "?" + query
        readback = self._send("GET", readback_path, role="correlated-readback")
        if readback is None or not isinstance(readback.get("status"), int) \
                or not 200 <= readback["status"] < 300:
            self.stopped = self.stopped or "readback unavailable"
            return None
        rdoc = _json(readback)
        if (not isinstance(rdoc, dict)
                or not _same(rdoc.get(plan["readback_object_id_field"]), object_id)
                or not _same(rdoc.get(plan["readback_action_id_field"]), action_id)
                or not _same(rdoc.get(plan["effect_field"]), plan["effect"])
                or not _same(rdoc.get(plan["invariant_field"]), plan["invariant_value"])):
            self.stopped = "readback invariant/correlation mismatch"
            return None
        if self.marker is not None and self.marker not in _text(readback):
            self.stopped = "uploaded inert marker absent from preview"
            return None
        if _proofs is None:
            return None
        try:
            outcome = _proofs.extract_success(
                readback, self.baselines, host=urllib.parse.urlsplit(self.url).hostname)
        except Exception:
            outcome = {"auto": None, "candidates": []}
        self.candidates = [str(value)[:256] for value in outcome.get("candidates") or []]
        proof = outcome.get("auto")
        if isinstance(proof, str) and PROOF.fullmatch(proof):
            self.success = True
            self.stopped = None
            return proof
        if proof or self.candidates or outcome.get("wire"):
            self.success = True
        self.stopped = self.stopped or "no unambiguous readback proof"
        return None

    def result(self):
        baseline_proofs = list(dict.fromkeys(
            match.group(0) for text in self.baselines for match in PROOF.finditer(str(text or ""))))[:24]
        return {"class": "state_transaction", "kind": self.kind, "requests": self.requests,
                "posts": self.posts, "bytes": self.bytes, "success": self.success,
                "terminal": self.terminal, "mutation_started": self.mutation_started,
                "ambiguous_mutation": self.ambiguous_mutation,
                "candidates": list(dict.fromkeys(self.candidates))[:12],
                "baseline_proofs": baseline_proofs, "responses": self.responses[:8],
                "stopped": self.stopped}


def _publish(engine, target, ctx):
    aid = str(target.get("answer_id") or "target") if isinstance(target, dict) else "target"
    summary = engine.result()
    sink = ctx.get("result_sink") if isinstance(ctx, dict) else None
    if isinstance(sink, dict):
        sink[aid] = summary
    evidence = ctx.get("evidence") if isinstance(ctx, dict) else None
    if isinstance(evidence, list) and summary.get("kind"):
        line = _web.safe_display_text(
            f"WEB STATE {summary['kind']}: requests={summary['requests']} posts={summary['posts']} "
            f"terminal={summary['terminal']} ambiguous={summary['ambiguous_mutation']}", 500)
        if line not in evidence:
            evidence.append(line)


def solve(target, ctx=None):
    ctx = dict(ctx or {})
    engine = _Engine(target, ctx)
    proof = None
    try:
        proof = engine.run()
    except Exception as exc:
        engine.stopped = engine.stopped or f"error: {type(exc).__name__}"
        if engine.mutation_started:
            engine.ambiguous_mutation = True
            engine.terminal = True
    _publish(engine, target, ctx)
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
