#!/usr/bin/env python3
"""Clue-gated, read-only CORS/redirect/OIDC checks for a web target.

This module intentionally covers only protocols that can be checked without a
victim browser, credential replay, an off-origin request, or a state-changing
verb:

* CORS: compare one plain GET with one GET carrying a fixed ``.invalid``
  Origin.  A finding requires that exact origin plus credentials in the
  response.  A proof is eligible only when it is novel in that confirmed
  response.
* Open redirect: put a fixed ``.invalid`` URL in the *advertised* route and
  parameter, disable redirects, and compare ``Location``.  This is a finding,
  never an auto-answer.
* OIDC/OAuth discovery: read only an explicitly advertised or target-locally
  signalled well-known document and, when same-origin, its JWKS.  Key material
  is never copied into the result; only public metadata is summarized.

Every request goes through the scope-locked :mod:`solvers.toolkits.web`
``WebClient``.  The clue document is data, not executable instructions.  The
request count, absolute deadline, response size, route shapes, and result size
are all bounded.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import sys
import threading
import time
import urllib.parse
from pathlib import Path


# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import env as ctf_env, paths as ctf_paths, event as ctf_event
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import env as ctf_env, paths as ctf_paths, event as ctf_event

HERE = Path(__file__).resolve().parent
TOOLKITS = HERE.parent / "toolkits"
if str(TOOLKITS) not in sys.path:
    sys.path.insert(0, str(TOOLKITS))
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import web as _web  # noqa: E402
import security_json as _security_json  # noqa: E402 -- fail-closed policy JSON

try:
    import forge_event as _proofs  # noqa: E402
except Exception:
    _proofs = None


BASELINE_INCOMPLETE = getattr(
    _proofs, "BASELINE_STRICT_INCOMPLETE",
    "<!-- csctf-baseline-strict-set:incomplete -->",
)


DEFAULT_SECONDS = 20.0
DEFAULT_MAX_REQUESTS = 6
REQUEST_TIMEOUT = 6.0
MAX_BODY = 400_000
PAD = 0.25
PARAM = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
OIDC_WORDS = re.compile(r"(?i)\b(?:openid(?: connect)?|oidc|oauth(?:2)?|jwks?|pkce)\b")
CORS_WORDS = re.compile(r"(?i)\b(?:cors|cross[- ]origin|access-control-allow-origin)\b")
REDIRECT_WORDS = re.compile(r"(?i)\b(?:open redirect|redirect(?:ion)? endpoint|return[_ -]?url)\b")
BLOCKED_PATH = re.compile(
    r"(?i)(?:^|[/_.-])(?:delete|destroy|drop|wipe|purge|truncate|erase|revoke|logout|signout|"
    r"disable|deactivate|uninstall|kill|shutdown|reboot|ban|suspend|cancel|transfer|pay|"
    r"create|update|write|upload|redeem|reset|issue|promote|approve)(?=$|[/_.-]|\d)"
)


def enabled():
    """Default-on read-only checks with the same immediate off switch style as the other web peers."""
    raw = ctf_env.get("CTF_WEB_PASSIVE_CHECKS")
    if raw is not None:
        return raw.strip().lower() not in ("off", "0", "false", "no")
    try:
        root = ctf_paths.workdir()
        return not (root / "_web_passive_checks.off").exists()
    except Exception:
        return False


def _origin(value):
    try:
        parts = urllib.parse.urlsplit(str(value or ""))
        if (parts.scheme not in ("http", "https") or not parts.hostname
                or parts.username is not None or parts.password is not None
                or parts.fragment or "@" in parts.netloc):
            return None
        return parts.scheme, parts.hostname.lower(), parts.port or (443 if parts.scheme == "https" else 80)
    except Exception:
        return None


def _same_origin_route(value, base_url, *, allow_query=False):
    try:
        result = _web.safe_same_origin_route(
            value, base_url, allow_query=allow_query, guard_query=True, max_bytes=1_000)
        if result is None:
            return None
        path = urllib.parse.urlsplit(result).path or "/"
        for decoded in _web.canonical_route_layers(path, max_bytes=1_000) or ():
            camel = re.sub(r"([a-z0-9])([A-Z])", r"\1/\2", decoded)
            if (BLOCKED_PATH.search(decoded) or BLOCKED_PATH.search(camel)
                    or _web.route_has_destructive_action(decoded)):
                return None
        return result
    except Exception:
        return None


def _body(response):
    if not isinstance(response, dict):
        return b""
    raw = response.get("body", response.get("text", b""))
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "replace")
    return bytes(raw or b"")[:MAX_BODY]


def _text(response):
    if _proofs is not None and hasattr(_proofs, "response_text_views"):
        try:
            views = _proofs.response_text_views(response)
            return str(views[0])[:MAX_BODY] if views else ""
        except Exception:
            return ""
    return _body(response).decode("utf-8", "replace")


def _baseline_text(response):
    if _proofs is not None and hasattr(_proofs, "response_baseline_text"):
        return _proofs.response_baseline_text(response)
    text = _text(response)
    raw = response.get("response_headers", response.get("headers", {})) if isinstance(response, dict) else {}
    headers = "\n".join(str(value)[:4096] for value in raw.values()) if isinstance(raw, dict) else ""
    return (text + ("\n" + headers if headers else ""))[:MAX_BODY]


def _json(response):
    views = None
    if _proofs is not None and hasattr(_proofs, "response_text_views"):
        try:
            views = _proofs.response_text_views(response)
        except Exception:
            return None
    try:
        value = _security_json.loads_unique(
            views if views is not None else [_text(response)], max_chars=MAX_BODY)
        return value if isinstance(value, dict) else None
    except Exception:
        return None


def _ok(response):
    return (isinstance(response, dict) and isinstance(response.get("status"), int)
            and 200 <= response["status"] < 300)


def _headers(response):
    if not isinstance(response, dict):
        return {}
    pairs = response.get("response_header_pairs")
    rows = []
    if isinstance(pairs, (list, tuple)):
        rows = [item for item in pairs[:512]
                if isinstance(item, (list, tuple)) and len(item) == 2]
    else:
        raw = response.get("response_headers", response.get("headers", {}))
        if isinstance(raw, dict):
            for key, value in list(raw.items())[:512]:
                values = value if isinstance(value, (list, tuple)) else (value,)
                rows.extend((key, item) for item in values[:16])
    grouped = {}
    for key, value in rows:
        name = str(key).lower().strip()
        text = str(value).strip()[:2_000]
        if not name or any(ch in text for ch in ("\r", "\n", "\x00")):
            continue
        grouped.setdefault(name, []).append(text)
    # Headers used as policy (ACAO/ACAC/Location) have no safe duplicate
    # merge rule here. Even repeated-identical fields are omitted rather than
    # relying on one intermediary's comma/first/last interpretation.
    return {name: values[0] for name, values in grouped.items() if len(values) == 1}


def _response(raw):
    if not isinstance(raw, dict):
        return None
    if "body" in raw:
        return raw
    if "text" in raw:
        out = dict(raw)
        out["body"] = str(raw.get("text") or "").encode("utf-8")
        return out
    return None


def _flatten_strings(value, depth=0):
    if depth > 5:
        return []
    if isinstance(value, dict):
        out = []
        for key, child in list(value.items())[:100]:
            out.append(str(key))
            out.extend(_flatten_strings(child, depth + 1))
        return out
    if isinstance(value, list):
        out = []
        for child in value[:100]:
            out.extend(_flatten_strings(child, depth + 1))
        return out
    return [str(value)] if isinstance(value, (str, int, float, bool)) else []


_MISSING = object()
_CONFLICT = object()


def _coherent_alias(document, keys, normalizer, *, types=(str,)):
    """Normalize every present alias; never let key order choose authority."""
    values = []
    for key in keys:
        if key not in document:
            continue
        raw = document.get(key)
        if isinstance(raw, bool) or not isinstance(raw, types):
            return _CONFLICT
        try:
            value = normalizer(raw)
        except Exception:
            return _CONFLICT
        if value is None:
            return _CONFLICT
        if value not in values:
            values.append(value)
    if not values:
        return _MISSING
    return values[0] if len(values) == 1 else _CONFLICT


class _Checks:
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
            self.max_requests = max(0, min(DEFAULT_MAX_REQUESTS, int(self.ctx.get("max_requests", DEFAULT_MAX_REQUESTS))))
        except (TypeError, ValueError):
            self.max_requests = DEFAULT_MAX_REQUESTS
        self.stop = self.ctx.get("stop")
        self.preloaded = dict(self.ctx.get("preloaded") or {})
        supplied_baselines = list(self.ctx.get("baseline_texts") or [])
        baseline_overflow = len(supplied_baselines) > 40
        self.baselines = []
        for value in supplied_baselines[:40]:
            raw = str(value or "")
            baseline_overflow |= len(raw) > MAX_BODY
            self.baselines.append(raw[:MAX_BODY])
        if baseline_overflow and BASELINE_INCOMPLETE not in self.baselines:
            self.baselines.append(BASELINE_INCOMPLETE)
        self.requests = 0
        self.responses = []
        self.findings = []
        self.candidates = []
        self.success = False
        self.stopped = None
        self._lock = threading.Lock()
        nonce = secrets.token_hex(8)
        # Canary hosts carry the active event slug (RFC 2606 .invalid: never resolvable).
        slug = ctf_event.current().slug
        self.origin_canary = f"https://{nonce}.cors.{slug}.invalid"
        self.redirect_canary = f"https://{nonce}.redirect.{slug}.invalid/callback"
        try:
            supplied = self.ctx.get("client")
            if supplied is not None:
                client_origin = _origin(getattr(supplied, "base", None))
                target_origin = _origin(self.url)
                self.client = supplied if (client_origin is not None and target_origin is not None
                                           and client_origin == target_origin) else None
            elif callable(self.ctx.get("client_factory")):
                made = self.ctx["client_factory"](self.url, REQUEST_TIMEOUT)
                client_origin = _origin(getattr(made, "base", None))
                target_origin = _origin(self.url)
                self.client = made if (client_origin is not None and target_origin is not None
                                       and client_origin == target_origin) else None
            else:
                self.client = _web.WebClient(self.url, timeout=REQUEST_TIMEOUT)
        except Exception:
            self.client = None

    def _may_send(self):
        if self.client is None or self.requests >= self.max_requests:
            self.stopped = self.stopped or ("unavailable" if self.client is None else "max_requests")
            return False
        if hasattr(self.stop, "is_set") and self.stop.is_set():
            self.stopped = self.stopped or "stopped"
            return False
        if self.deadline - time.time() <= PAD:
            self.stopped = self.stopped or "deadline"
            return False
        return True

    def get(self, path, role, *, headers=None, cached=True, baseline=False):
        if cached and not headers and path in self.preloaded:
            response = _response(self.preloaded[path])
            if response is not None and baseline:
                self.baselines.append(_baseline_text(response))
            return response
        with self._lock:
            if not self._may_send():
                return None
            self.requests += 1
            try:
                left = self.deadline - time.time()
                self.client.timeout = max(0.2, min(REQUEST_TIMEOUT, left - 0.1))
                response = self.client.request("GET", path, headers=dict(headers or {}), allow_redirects=False)
            except Exception as exc:
                self.responses.append({"role": role, "path": path.split("?", 1)[0],
                                       "status": None, "error": type(exc).__name__})
                self.stopped = self.stopped or f"transport: {type(exc).__name__}"
                return None
        self.responses.append({"role": role, "path": path.split("?", 1)[0],
                               "status": response.get("status") if isinstance(response, dict) else None})
        if response is not None and baseline:
            self.baselines.append(_baseline_text(response))
        return response

    def _cors(self, clues, prose):
        route = _coherent_alias(
            clues, ("cors_route", "cross_origin_route"),
            lambda value: _same_origin_route(value, self.url))
        if route is _CONFLICT:
            return None
        if route is _MISSING and CORS_WORDS.search(prose):
            route = _coherent_alias(
                clues, ("protected_route", "read_route", "feature_route", "endpoint"),
                lambda value: _same_origin_route(value, self.url))
        if route in (_MISSING, _CONFLICT):
            return None
        control = self.get(route, "cors-control", baseline=True)
        control_incomplete = True
        if _ok(control) and _proofs is not None \
                and hasattr(_proofs, "baseline_set_incomplete"):
            try:
                control_incomplete = bool(
                    _proofs.baseline_set_incomplete([_baseline_text(control)]))
            except Exception:
                control_incomplete = True
        if not _ok(control) or control_incomplete:
            self.findings.append({"class": "cors", "confirmed": False,
                                  "evidence": "control_unavailable_or_incomplete",
                                  "path": route})
            self.stopped = self.stopped or "CORS control unavailable or incomplete"
            return None
        attack = self.get(route, "cors-origin", headers={"Origin": self.origin_canary}, cached=False)
        headers = _headers(attack)
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "").lower()
        confirmed = acao == self.origin_canary and acac == "true"
        self.findings.append({"class": "cors", "confirmed": confirmed,
                              "evidence": "credentialed_exact_origin" if confirmed else "not_confirmed",
                              "path": route})
        if not confirmed or attack is None or _proofs is None:
            return None
        outcome = _proofs.extract_success(attack, self.baselines, host=urllib.parse.urlsplit(self.url).hostname)
        self.candidates.extend(str(value)[:256] for value in outcome.get("candidates") or [])
        self.success = bool(outcome.get("success"))
        proof = outcome.get("auto")
        if proof:
            return proof
        return None

    def _redirect(self, clues, prose):
        # The helper supplies the only query member.  A target-authored query
        # could otherwise activate an unrelated inner URL or state-changing
        # action while we merely intend to test a redirect parameter.
        route = _coherent_alias(
            clues, ("redirect_route", "redirect_endpoint", "return_route"),
            lambda value: _same_origin_route(value, self.url))
        param = _coherent_alias(
            clues, ("redirect_parameter", "return_url_parameter", "redirect_param", "return_parameter"),
            lambda value: value if PARAM.fullmatch(value) else None)
        if route is _MISSING and REDIRECT_WORDS.search(prose):
            route = _coherent_alias(
                clues, ("feature_route", "endpoint"),
                lambda value: _same_origin_route(value, self.url))
        if route in (_MISSING, _CONFLICT) or param in (_MISSING, _CONFLICT):
            return
        parts = urllib.parse.urlsplit(route)
        query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        query.append((param, self.redirect_canary))
        path = urllib.parse.urlunsplit(("", "", parts.path, urllib.parse.urlencode(query), ""))
        response = self.get(path, "redirect", cached=False)
        location = _headers(response).get("location", "")
        try:
            got = urllib.parse.urlsplit(urllib.parse.urljoin(self.url, location))
            want = urllib.parse.urlsplit(self.redirect_canary)
            confirmed = response is not None and 300 <= int(response.get("status") or 0) < 400 and \
                (got.scheme, got.hostname, got.path) == (want.scheme, want.hostname, want.path)
        except Exception:
            confirmed = False
        self.findings.append({"class": "open_redirect", "confirmed": confirmed,
                              "evidence": "external_location" if confirmed else "not_confirmed",
                              "path": parts.path, "param": param})

    def _oidc(self, clues, prose):
        explicit = _coherent_alias(
            clues,
            ("oidc_configuration_route", "openid_configuration_route", "oauth_metadata_route"),
            lambda value: _same_origin_route(value, self.url))
        routes = []
        if explicit is _CONFLICT:
            return  # an explicit but unusable route is a refusal, not permission to guess fallbacks
        if explicit is not _MISSING:
            routes.append(explicit)
        elif OIDC_WORDS.search(prose):
            routes.extend(("/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"))
        document = None
        used = None
        for candidate in routes[:2]:
            response = self.get(candidate, "oidc-discovery", baseline=True)
            value = _json(response)
            if isinstance(value, dict) and any(key in value for key in ("issuer", "jwks_uri", "authorization_endpoint")):
                document, used = value, candidate
                break
        if document is None:
            return
        metadata = {key: document.get(key) for key in (
            "issuer", "authorization_endpoint", "token_endpoint", "jwks_uri",
            "registration_endpoint", "userinfo_endpoint", "revocation_endpoint", "introspection_endpoint"
        ) if isinstance(document.get(key), str)}
        algorithms = []
        for key in ("id_token_signing_alg_values_supported", "request_object_signing_alg_values_supported",
                    "token_endpoint_auth_signing_alg_values_supported"):
            for value in document.get(key) or []:
                if isinstance(value, str) and value not in algorithms:
                    algorithms.append(value[:40])
        finding = {"class": "oidc", "confirmed": True, "evidence": "discovery_document",
                   "path": used, "metadata_keys": sorted(metadata), "algorithms": algorithms[:24]}
        jwks = _same_origin_route(document.get("jwks_uri"), self.url)
        if jwks:
            keys = _json(self.get(jwks, "oidc-jwks", baseline=True))
            public = []
            for item in (keys.get("keys") if isinstance(keys, dict) else []) or []:
                if not isinstance(item, dict):
                    continue
                public.append({key: str(item.get(key))[:100] for key in ("kid", "kty", "alg", "use", "crv")
                               if isinstance(item.get(key), (str, int))})
            finding["jwks"] = jwks
            finding["public_key_summaries"] = public[:16]
        self.findings.append(finding)

    def run(self):
        if not enabled():
            self.stopped = "off"
            return None
        if self.client is None or self.max_requests <= 0:
            self.stopped = "unavailable"
            return None
        landing = self.get("/", "landing", baseline=True)
        if isinstance(landing, dict) and landing.get("status") == 410:
            self.stopped = "completed"
            return None
        clues_response = self.get("/api/clues", "clues", baseline=True)
        clues = _json(clues_response)
        if not _ok(clues_response) or not isinstance(clues, dict):
            self.stopped = "no clue document"
            return None
        prose = " ".join(_flatten_strings(clues))[:100_000]
        proof = self._cors(clues, prose)
        if proof:
            return proof
        self._redirect(clues, prose)
        self._oidc(clues, prose)
        if not self.findings:
            self.stopped = "no passive protocol contract"
        return None

    def result(self):
        baseline_incomplete = True
        if _proofs is not None and hasattr(_proofs, "baseline_set_incomplete"):
            try:
                baseline_incomplete = bool(_proofs.baseline_set_incomplete(self.baselines))
            except Exception:
                baseline_incomplete = True
        return {"class": self.findings[0]["class"] if len(self.findings) == 1 else "passive_protocols",
                "requests": self.requests, "posts": 0, "success": self.success,
                "findings": self.findings[:12], "candidates": list(dict.fromkeys(self.candidates))[:12],
                "baseline_incomplete": baseline_incomplete,
                "baseline_proofs": (_proofs.baseline_proofs(self.baselines)
                                    if _proofs is not None and hasattr(_proofs, "baseline_proofs") else []),
                "responses": self.responses[:12], "stopped": self.stopped}


def _publish(checks, target, ctx):
    summary = checks.result()
    sink = ctx.get("result_sink") if isinstance(ctx, dict) else None
    aid = str(target.get("answer_id") or "target") if isinstance(target, dict) else "target"
    if isinstance(sink, dict):
        sink[aid] = summary
    evidence = ctx.get("evidence") if isinstance(ctx, dict) else None
    if isinstance(evidence, list):
        for finding in summary["findings"]:
            line = _web.safe_display_text(
                f"WEB PASSIVE {finding.get('class')}: confirmed={bool(finding.get('confirmed'))} "
                f"evidence={finding.get('evidence')} path={finding.get('path', '-')}", 500)
            if line not in evidence:
                evidence.append(line)
        for value in summary["candidates"]:
            line = _web.safe_display_text(
                f"WEB FLAG CANDIDATE {aid}: {value} (confirmed CORS response; not auto-submitted)", 500)
            if line not in evidence:
                evidence.append(line)


def solve(target, ctx=None):
    ctx = dict(ctx or {})
    checks = _Checks(target, ctx)
    proof = None
    try:
        proof = checks.run()
    except Exception as exc:
        checks.stopped = checks.stopped or f"error: {type(exc).__name__}"
    _publish(checks, target, ctx)
    return proof


def solve_targets(targets, ctx=None):
    out = {}
    for index, target in enumerate(list(targets or [])):
        if not isinstance(target, dict):
            continue
        aid = str(target.get("answer_id") or target.get("id") or f"target-{index + 1}")
        item = dict(target)
        item["answer_id"] = aid
        out[aid] = solve(item, ctx)
    return out
