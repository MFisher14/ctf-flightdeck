#!/usr/bin/env python3
"""B-124: business-logic abuse state-invariant harness (BUILD-PLAN hard-tail fallback #10).

The harness does NOT find a business-logic flaw.  Choosing the invariant that a coupon, order,
idempotency key or multi-step workflow should keep is model/human reasoning; the spec carries it
(with ``stated_by`` naming who stated it) and the harness only *exercises* it:

1. ``check(invariants, before, after, accepted=N)`` -- pure evaluation of a stated invariant over a
   before/after snapshot pair.  No I/O.  This is the offline core and what ``ctf invariant check``
   runs on hand-captured snapshots.
2. ``run_harness(spec, client_factory, base_url=...)`` -- the live driver.  It reads the declared
   snapshot routes twice (a baseline plus an idle noise control), refuses to mutate when the stated
   invariant is already false or a referenced field moves on its own, then climbs the smallest
   ladder of transitions: one transition, then two sequential (double-apply / idempotency), ...,
   then (optionally) one bounded concurrent burst through the B-048 race engine
   (``double_spend.race`` / ``burst_separate`` / ``burst_single_packet``).  After each rung it
   snapshots, evaluates, sends the declared ``reverse`` step once per accepted transition and
   confirms the state was restored before going further.  It stops at the first violation, so the
   rung that reports it is the smallest transition that breaks the stated invariant.

Safety shape (carried from ``state_transaction`` and ``double_spend``):

* Reserve-before-mutate: a rung's whole request group (transitions, the after-snapshot, the
  reversals and the restore-snapshot) is reserved against ``max_requests`` and the deadline before
  its first mutation; a rung that cannot be reserved is never started.
* A transition answered by a transport error, 408/425/429, 5xx, a truncated body or no status is an
  ``ambiguous_mutation``: the harness reads the after-snapshot it reserved, sends nothing else and
  stops (no reversal is attempted blind; ``state_restored`` then says whether that after-read is at
  the baseline).  One ambiguous slot makes a whole burst ambiguous, and a burst primitive that fails
  after sending counts its whole width as sent and ambiguous.
* A transition without a declared ``reverse`` needs ``irreversible_ack: true`` and can never burst.
  Mutation routes whose path names a destructive verb (state_transaction's FATAL_ROUTE family) are
  refused unless the spec lists that verb in ``allow_actions``, and the HTTP method DELETE counts as
  the verb ``delete`` whatever the route says; a short never-waivable subset (password, logout,
  shutdown, ...) is refused outright.
* Every route must be on the scope-locked client's own origin.  Reports carry methods, routes,
  statuses and the values at the invariant's paths -- never request headers or bodies.

Never submits, never guesses an invariant, never runs a model.  Live use is event-gated:
``run_harness`` sends nothing unless the active profile's ``rules.web_state_changing`` is true
(Open O-2), and the ``web.WebClient`` the CLI builds (``ctf invariant run``) enforces the profile's
live-service scope before any connection.
"""

from __future__ import annotations

import json
import re
import sys
import time
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
_TK = HERE.parent / "toolkits"
if str(_TK) not in sys.path:
    sys.path.insert(0, str(_TK))
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import web as _web  # noqa: E402
import security_json as _security_json  # noqa: E402
import double_spend as _race  # noqa: E402 -- B-048 burst/race primitives (reused, never duplicated)

try:
    from ctf import event as _event, scope as _scope
except ModuleNotFoundError:  # script run: the checkout root is not on sys.path yet
    sys.path.append(str(HERE.parents[1]))
    from ctf import event as _event, scope as _scope

HARNESS = "business_logic_invariant"
DEFAULT_MAX_REQUESTS = 60
HARD_MAX_REQUESTS = 200
MAX_SEQUENTIAL = 4
MAX_BURST = 16
MAX_SNAPSHOTS = 4
MAX_INVARIANTS = 16
MAX_ROUTE_BYTES = 1024
MAX_BODY_BYTES = 16 * 1024
MAX_SNAPSHOT_CHARS = 256 * 1024
REQUEST_TIMEOUT = 8.0
DEADLINE_PAD = 0.3
VALUE_REPR = 200

NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
STATED_BY = frozenset({"model", "agent", "human", "player"})
KINDS = frozenset({"absolute", "delta", "unchanged", "sum_conserved", "monotonic"})
OPS = frozenset({"==", "!=", "<", "<=", ">", ">=", "in", "not_in"})
NUMERIC_OPS = frozenset({"<", "<=", ">", ">="})
MEASURES = frozenset({"value", "len"})
PER = frozenset({"once", "accepted"})
DIRECTIONS = frozenset({"nondecreasing", "nonincreasing"})
METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
ENCODINGS = frozenset({"json", "form", "raw"})
BURST_MODES = frozenset({"separate", "single-packet"})
SPEC_KEYS = frozenset({
    "name", "stated_by", "invariants", "snapshot", "snapshots", "transition", "reverse",
    "irreversible_ack", "allow_actions", "ladder", "max_requests", "note",
})
INVARIANT_KEYS = frozenset({
    "id", "kind", "path", "paths", "measure", "op", "value", "per", "tolerance", "direction",
    "note",
})
STEP_KEYS = frozenset({"method", "route", "body", "encoding", "headers"})
LADDER_KEYS = frozenset({"sequential_max", "burst_width", "burst_mode"})

# The destructive-verb family of state_transaction.FATAL_ROUTE, with the verb captured so the spec
# can waive exactly the verbs it names.  NEVER_WAIVABLE stays refused whatever the spec says.
_ACTION_WORD = re.compile(
    r"(?i)(?:^|[/_.-])(delete|destroy|drop|wipe|purge|truncate|erase|revoke|logout|signout|"
    r"disable|deactivate|uninstall|kill|shutdown|reboot|ban|suspend|cancel|transfer|pay|admin|"
    r"account|password)(?=$|[/_.-]|\d)"
)
NEVER_WAIVABLE = frozenset({
    "password", "logout", "signout", "shutdown", "reboot", "uninstall", "kill", "drop",
    "truncate", "wipe", "purge", "erase", "destroy",
})


_COMPILED = object()  # marks a compiled invariant; JSON input can never carry it


class InvariantSpecError(ValueError):
    """A stated invariant / harness spec is malformed or unsafe -- always named, never guessed."""


def active_profile():
    """The event profile in force: the one ctf.scope pinned, else ``event.current()``."""
    prof = _scope.pinned()
    return prof if prof is not None else _event.current()


def state_change_refusal():
    """None when the active event allows state-changing web requests, else the named reason.

    Every harness transition changes target state, so ``run_harness`` sends nothing unless the
    profile's ``rules.web_state_changing`` is true (Open O-2; the B-183 flow recorder's gate)."""
    try:
        prof = active_profile()
    except Exception as exc:  # no resolvable event: refuse, loudly
        return f"no event profile in force ({type(exc).__name__}: {exc})"
    if not bool(prof.rules.web_state_changing):
        return (f"event {prof.slug!r} has rules.web_state_changing = false (Open O-2): the harness "
                f"drives state-changing transitions; set it true only with the player's yes")
    return None


# ---------------------------------------------------------------------------------------------------
# paths and values
# ---------------------------------------------------------------------------------------------------
def _is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _split_path(path):
    if isinstance(path, str):
        parts = path.split(".")
    elif isinstance(path, list):
        parts = list(path)
    else:
        raise InvariantSpecError(f"path must be a dotted string or a list, got {type(path).__name__}")
    if not parts or len(parts) > 16:
        raise InvariantSpecError(f"path {path!r} must have 1..16 segments")
    out = []
    for part in parts:
        if isinstance(part, bool) or not isinstance(part, (str, int)) or part == "":
            raise InvariantSpecError(f"path {path!r} has an empty or non-string segment")
        out.append(part)
    return tuple(out)


def _lookup(doc, segments):
    """(found, value) for a path into a JSON document; never raises."""
    current = doc
    for seg in segments:
        if isinstance(current, dict):
            key = seg if isinstance(seg, str) else str(seg)
            if key not in current:
                return False, None
            current = current[key]
        elif isinstance(current, list):
            try:
                index = int(seg)
            except (TypeError, ValueError):
                return False, None
            if isinstance(seg, str) and not seg.isdigit():
                return False, None
            if index < 0 or index >= len(current):
                return False, None
            current = current[index]
        else:
            return False, None
    return True, current


def _measure(doc, segments, measure):
    """(found, value, reason) -- the measured value at a path."""
    found, value = _lookup(doc, segments)
    if not found:
        return False, None, f"path {'.'.join(map(str, segments))} is absent from the snapshot"
    if measure == "len":
        if not isinstance(value, (list, dict, str)):
            return False, None, (f"len() of {'.'.join(map(str, segments))} needs a list, object or "
                                 f"string, got {type(value).__name__}")
        return True, len(value), None
    return True, value, None


def _same(left, right):
    """Exact JSON equality: a bool is never equal to 1, an int equals the same-valued float."""
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if _is_number(left) and _is_number(right):
        return left == right
    return type(left) is type(right) and left == right


def _compare(actual, op, expected, tolerance=0.0):
    """(holds, reason) for ``actual op expected``; reason names why it cannot be evaluated."""
    if op in ("in", "not_in"):
        if not isinstance(expected, list):
            return None, f"{op} needs a list value"
        member = any(_same(actual, item) for item in expected)
        return (member if op == "in" else not member), None
    if op in NUMERIC_OPS or (tolerance and op in ("==", "!=")
                             and _is_number(actual) and _is_number(expected)):
        if not _is_number(actual) or not _is_number(expected):
            return None, f"{op} needs numbers, got {type(actual).__name__} and {type(expected).__name__}"
        if op == "<":
            return actual < expected - tolerance, None
        if op == "<=":
            return actual <= expected + tolerance, None
        if op == ">":
            return actual > expected + tolerance, None
        if op == ">=":
            return actual >= expected - tolerance, None
        equal = abs(actual - expected) <= tolerance
        return (equal if op == "==" else not equal), None
    if op == "==":
        return _same(actual, expected), None
    if op == "!=":
        return not _same(actual, expected), None
    return None, f"unknown operator {op!r}"


def _short(value):
    try:
        text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        text = repr(value)
    return text if len(text) <= VALUE_REPR else text[:VALUE_REPR] + "..."


# ---------------------------------------------------------------------------------------------------
# compile: invariants and spec
# ---------------------------------------------------------------------------------------------------
def _compile_invariant(raw, index):
    where = f"invariant #{index + 1}"
    if not isinstance(raw, dict):
        raise InvariantSpecError(f"{where} must be an object")
    extra = set(raw) - INVARIANT_KEYS
    if extra:
        raise InvariantSpecError(f"{where} has unknown field(s): {', '.join(sorted(extra))}")
    inv_id = raw.get("id")
    if not isinstance(inv_id, str) or not NAME.fullmatch(inv_id):
        raise InvariantSpecError(f"{where} needs an id (letters, digits, _ . -)")
    where = f"invariant {inv_id!r}"
    kind = raw.get("kind", "absolute")
    if kind not in KINDS:
        raise InvariantSpecError(f"{where}: kind must be one of {sorted(KINDS)}, got {kind!r}")
    measure = raw.get("measure", "value")
    if measure not in MEASURES:
        raise InvariantSpecError(f"{where}: measure must be one of {sorted(MEASURES)}")
    tolerance = raw.get("tolerance", 0)
    if not _is_number(tolerance) or tolerance < 0:
        raise InvariantSpecError(f"{where}: tolerance must be a number >= 0")
    out = {"id": inv_id, "kind": kind, "measure": measure, "tolerance": float(tolerance),
           "_compiled": _COMPILED}
    if kind == "sum_conserved":
        paths = raw.get("paths")
        if "path" in raw or not isinstance(paths, list) or not 2 <= len(paths) <= 8:
            raise InvariantSpecError(f"{where}: sum_conserved takes 'paths' (2..8), not 'path'")
        out["paths"] = [_split_path(p) for p in paths]
    else:
        if "paths" in raw or "path" not in raw:
            raise InvariantSpecError(f"{where}: kind {kind!r} takes one 'path'")
        out["path"] = _split_path(raw["path"])
    allowed = {
        "absolute": {"op", "value"},
        "delta": {"op", "value", "per"},
        "unchanged": set(),
        "sum_conserved": set(),
        "monotonic": {"direction"},
    }[kind]
    for key in ("op", "value", "per", "direction"):
        if key in raw and key not in allowed:
            raise InvariantSpecError(f"{where}: kind {kind!r} does not take {key!r}")
    if kind in ("absolute", "delta"):
        op = raw.get("op")
        if op not in OPS:
            raise InvariantSpecError(f"{where}: op must be one of {sorted(OPS)}, got {op!r}")
        if "value" not in raw:
            raise InvariantSpecError(f"{where}: kind {kind!r} needs a 'value'")
        value = raw["value"]
        if op in ("in", "not_in") and not isinstance(value, list):
            raise InvariantSpecError(f"{where}: op {op!r} needs a list value")
        if (op in NUMERIC_OPS or kind == "delta") and op not in ("in", "not_in") \
                and not _is_number(value):
            raise InvariantSpecError(f"{where}: op {op!r} on kind {kind!r} needs a numeric value")
        if kind == "delta" and op in ("in", "not_in"):
            raise InvariantSpecError(f"{where}: a delta compares numbers; use ==, !=, <, <=, >, >=")
        out["op"] = op
        out["value"] = value
    if kind == "delta":
        per = raw.get("per", "once")
        if per not in PER:
            raise InvariantSpecError(f"{where}: per must be one of {sorted(PER)}")
        out["per"] = per
    if kind == "monotonic":
        direction = raw.get("direction")
        if direction not in DIRECTIONS:
            raise InvariantSpecError(f"{where}: direction must be one of {sorted(DIRECTIONS)}")
        out["direction"] = direction
    return out


def compile_invariants(raw):
    """Validate a list of stated invariants; raise :class:`InvariantSpecError` naming the problem."""
    if not isinstance(raw, list) or not 1 <= len(raw) <= MAX_INVARIANTS:
        raise InvariantSpecError(f"invariants must be a list of 1..{MAX_INVARIANTS} objects")
    out = [_compile_invariant(item, i) for i, item in enumerate(raw)]
    ids = [inv["id"] for inv in out]
    if len(set(ids)) != len(ids):
        raise InvariantSpecError("invariant ids must be unique")
    return out


def invariant_paths(invariants):
    """Every snapshot path the invariants read (for the noise control and restore check)."""
    seen = []
    for inv in invariants:
        for path in inv.get("paths") or [inv["path"]]:
            if path not in seen:
                seen.append(path)
    return seen


def _origin(value):
    try:
        parts = urllib.parse.urlsplit(str(value or ""))
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return None
        return parts.scheme, parts.hostname.lower(), parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        return None


def _safe_route(value, base_url, what):
    route = _web.safe_same_origin_route(
        value, base_url, allow_query=True, guard_query=True, max_bytes=MAX_ROUTE_BYTES)
    if not route:
        raise InvariantSpecError(f"{what} route {value!r} is not a safe path on the target origin")
    return route


def action_words(route):
    """The destructive verbs a route's canonical layers name (lower-case, ordered, unique)."""
    words = []
    layers = _web.canonical_route_layers(route, max_bytes=MAX_ROUTE_BYTES) or [route]
    for layer in layers:
        for match in _ACTION_WORD.finditer(str(layer)):
            word = match.group(1).lower()
            if word not in words:
                words.append(word)
    return words


def _compile_step(raw, base_url, allow_actions, what):
    if not isinstance(raw, dict):
        raise InvariantSpecError(f"{what} must be an object")
    extra = set(raw) - STEP_KEYS
    if extra:
        raise InvariantSpecError(f"{what} has unknown field(s): {', '.join(sorted(extra))}")
    method = str(raw.get("method") or "POST").upper()
    if method not in METHODS:
        raise InvariantSpecError(f"{what}: method must be one of {sorted(METHODS)}")
    route = _safe_route(raw.get("route"), base_url, what)
    for word in action_words(route):
        if word in NEVER_WAIVABLE:
            raise InvariantSpecError(
                f"{what} route {route!r} names {word!r}, which the harness never drives")
        if word not in allow_actions:
            raise InvariantSpecError(
                f"{what} route {route!r} names the destructive verb {word!r}; list it in "
                f"allow_actions only if this self-owned transition is meant to send it")
    if method == "DELETE" and "delete" not in allow_actions:
        # the method is itself the destructive verb: a bare-route DELETE is gated like /x/delete
        raise InvariantSpecError(
            f"{what} uses method DELETE on {route!r}; list 'delete' in allow_actions only if this "
            f"self-owned transition is meant to send it")
    encoding = raw.get("encoding", "json")
    if encoding not in ENCODINGS:
        raise InvariantSpecError(f"{what}: encoding must be one of {sorted(ENCODINGS)}")
    body = raw.get("body")
    if body is None:
        data = None
    elif encoding == "json":
        data = json.dumps(body, separators=(",", ":"), ensure_ascii=False)
    elif encoding == "form":
        if not isinstance(body, dict) or any(isinstance(v, (dict, list)) for v in body.values()):
            raise InvariantSpecError(f"{what}: a form body must be a flat object")
        data = urllib.parse.urlencode([(str(k), "" if v is None else str(v)) for k, v in body.items()])
    else:
        if not isinstance(body, str):
            raise InvariantSpecError(f"{what}: a raw body must be a string")
        data = body
    if data is not None and len(data.encode("utf-8")) > MAX_BODY_BYTES:
        raise InvariantSpecError(f"{what}: body exceeds {MAX_BODY_BYTES} bytes")
    headers = raw.get("headers") or {}
    if not isinstance(headers, dict) or any(
            not isinstance(k, str) or not isinstance(v, str) or "\n" in k + v or "\r" in k + v
            for k, v in headers.items()):
        raise InvariantSpecError(f"{what}: headers must be single-line string pairs")
    headers = dict(headers)
    if data is not None and not any(k.lower() == "content-type" for k in headers):
        headers["Content-Type"] = {"json": "application/json",
                                   "form": "application/x-www-form-urlencoded",
                                   "raw": "text/plain"}[encoding]
    return {"method": method, "route": route, "data": data, "headers": headers}


def compile_spec(raw, base_url):
    """Validate a full harness spec against the target ``base_url``.

    Returns the compiled spec (routes canonical and same-origin).  Raises
    :class:`InvariantSpecError` for anything malformed or unsafe; nothing is ever guessed or
    defaulted into a mutation."""
    if not isinstance(raw, dict):
        raise InvariantSpecError("spec must be a JSON object")
    extra = set(raw) - SPEC_KEYS
    if extra:
        raise InvariantSpecError(f"spec has unknown field(s): {', '.join(sorted(extra))}")
    if _origin(base_url) is None:
        raise InvariantSpecError(f"base url {base_url!r} is not an http(s) origin")
    name = raw.get("name")
    if not isinstance(name, str) or not name.strip():
        raise InvariantSpecError("spec needs a 'name' stating what the invariant protects")
    stated_by = raw.get("stated_by")
    if stated_by not in STATED_BY:
        raise InvariantSpecError(
            f"spec needs 'stated_by' in {sorted(STATED_BY)}: the harness never chooses the invariant")
    invariants = compile_invariants(raw.get("invariants"))
    if ("snapshot" in raw) == ("snapshots" in raw):
        raise InvariantSpecError("give exactly one of 'snapshot' (one route) or 'snapshots' (name -> route)")
    snapshots = raw.get("snapshots") if "snapshots" in raw else {"state": raw.get("snapshot")}
    if not isinstance(snapshots, dict) or not 1 <= len(snapshots) <= MAX_SNAPSHOTS:
        raise InvariantSpecError(f"snapshots must map 1..{MAX_SNAPSHOTS} names to GET routes")
    snap = {}
    for key, route in snapshots.items():
        if not isinstance(key, str) or not NAME.fullmatch(key) or "." in key:
            raise InvariantSpecError(f"snapshot name {key!r} must be a plain identifier")
        snap[key] = _safe_route(route, base_url, f"snapshot {key!r}")
    for path in invariant_paths(invariants):
        if str(path[0]) not in snap:
            raise InvariantSpecError(
                f"path {'.'.join(map(str, path))} must start with a snapshot name ({', '.join(snap)})")
    allow = raw.get("allow_actions") or []
    if not isinstance(allow, list) or any(not isinstance(w, str) for w in allow):
        raise InvariantSpecError("allow_actions must be a list of verbs")
    allow = {w.strip().lower() for w in allow}
    waived_never = sorted(allow & NEVER_WAIVABLE)
    if waived_never:
        raise InvariantSpecError(f"allow_actions cannot waive {', '.join(waived_never)}")
    if "transition" not in raw:
        raise InvariantSpecError("spec needs a 'transition' (the smallest synthetic state change)")
    transition = _compile_step(raw["transition"], base_url, allow, "transition")
    reverse = None
    if raw.get("reverse") is not None:
        reverse = _compile_step(raw["reverse"], base_url, allow, "reverse")
    ack = raw.get("irreversible_ack", False)
    if not isinstance(ack, bool):
        raise InvariantSpecError("irreversible_ack must be true or false")
    if reverse is None and not ack:
        raise InvariantSpecError(
            "the transition has no 'reverse' step; declare one, or set irreversible_ack: true after "
            "confirming the change is self-owned and harmless to leave")
    ladder_raw = raw.get("ladder") or {}
    if not isinstance(ladder_raw, dict) or set(ladder_raw) - LADDER_KEYS:
        raise InvariantSpecError(f"ladder takes only {sorted(LADDER_KEYS)}")
    seq = ladder_raw.get("sequential_max", 2)
    if isinstance(seq, bool) or not isinstance(seq, int) or not 1 <= seq <= MAX_SEQUENTIAL:
        raise InvariantSpecError(f"ladder.sequential_max must be 1..{MAX_SEQUENTIAL}")
    width = ladder_raw.get("burst_width", 0)
    if isinstance(width, bool) or not isinstance(width, int) or not (width == 0 or 2 <= width <= MAX_BURST):
        raise InvariantSpecError(f"ladder.burst_width must be 0 (off) or 2..{MAX_BURST}")
    mode = ladder_raw.get("burst_mode", "separate")
    if mode not in BURST_MODES:
        raise InvariantSpecError(f"ladder.burst_mode must be one of {sorted(BURST_MODES)}")
    if width and reverse is None:
        raise InvariantSpecError("a burst rung needs a declared 'reverse' step (never burst an "
                                 "irreversible transition)")
    max_requests = raw.get("max_requests", DEFAULT_MAX_REQUESTS)
    if isinstance(max_requests, bool) or not isinstance(max_requests, int) \
            or not 1 <= max_requests <= HARD_MAX_REQUESTS:
        raise InvariantSpecError(f"max_requests must be 1..{HARD_MAX_REQUESTS}")
    return {
        "name": name.strip()[:200], "stated_by": stated_by, "base_url": str(base_url),
        "invariants": invariants, "snapshots": snap, "transition": transition, "reverse": reverse,
        "irreversible_ack": ack, "allow_actions": sorted(allow),
        "ladder": {"sequential_max": seq, "burst_width": width, "burst_mode": mode},
        "max_requests": max_requests,
    }


# ---------------------------------------------------------------------------------------------------
# evaluation (pure)
# ---------------------------------------------------------------------------------------------------
def _eval_one(inv, before, after, accepted):
    kind = inv["kind"]
    measure = inv["measure"]
    tol = inv["tolerance"]
    row = {"id": inv["id"], "kind": kind}

    def fail(reason):
        row.update(status="unevaluable", reason=reason)
        return row

    if kind == "sum_conserved":
        totals = []
        for doc, label in ((before, "before"), (after, "after")):
            total = 0
            for path in inv["paths"]:
                found, value, reason = _measure(doc, path, measure)
                if not found:
                    return fail(f"{label}: {reason}")
                if not _is_number(value):
                    return fail(f"{label}: {'.'.join(map(str, path))} is not a number")
                total += value
            totals.append(total)
        holds = abs(totals[1] - totals[0]) <= tol
        row.update(status="holds" if holds else "violated", before=totals[0], after=totals[1],
                   detail=f"sum before {_short(totals[0])} -> after {_short(totals[1])}")
        return row

    path = inv["path"]
    found, now, reason = _measure(after, path, measure)
    if not found:
        return fail(f"after: {reason}")
    row["after"] = _short(now)
    if kind == "absolute":
        holds, why = _compare(now, inv["op"], inv["value"], tol)
        if holds is None:
            return fail(why)
        row.update(status="holds" if holds else "violated",
                   detail=f"{_short(now)} {inv['op']} {_short(inv['value'])}")
        return row
    found, then, reason = _measure(before, path, measure)
    if not found:
        return fail(f"before: {reason}")
    row["before"] = _short(then)
    if kind == "unchanged":
        # a tolerance widens numeric equality only; any value equal to itself is unchanged
        holds = _same(then, now) or bool(
            tol and _is_number(then) and _is_number(now) and abs(now - then) <= tol)
        row.update(status="holds" if holds else "violated",
                   detail=f"{_short(then)} -> {_short(now)} (must not change)")
        return row
    if not _is_number(then) or not _is_number(now):
        return fail(f"{kind} needs numbers, got {type(then).__name__} -> {type(now).__name__}")
    if kind == "monotonic":
        holds = (now >= then - tol) if inv["direction"] == "nondecreasing" else (now <= then + tol)
        row.update(status="holds" if holds else "violated",
                   detail=f"{_short(then)} -> {_short(now)} (must be {inv['direction']})")
        return row
    # delta
    scale = accepted if inv["per"] == "accepted" else 1
    expected = inv["value"] * scale
    change = now - then
    holds, why = _compare(change, inv["op"], expected, tol)
    if holds is None:
        return fail(why)
    row.update(status="holds" if holds else "violated", delta=change, expected=expected,
               detail=f"delta {_short(change)} {inv['op']} {_short(expected)}"
                      + (f" ({_short(inv['value'])} x {accepted} accepted)" if inv["per"] == "accepted" else ""))
    return row


def check(invariants, before, after, *, accepted=0):
    """Evaluate stated invariants over one before/after snapshot pair (pure; no I/O).

    ``invariants`` is the raw list or the output of :func:`compile_invariants`.  ``accepted`` is how
    many transitions the target accepted (a ``per: accepted`` delta scales by it).  Returns
    ``{"verdict": "violated"|"holds"|"unevaluable", "violations", "unevaluable", "checks"}``: a
    violation outranks an unevaluable row, and an unevaluable row is never reported as holding."""
    if isinstance(accepted, bool) or not isinstance(accepted, int) or accepted < 0:
        raise InvariantSpecError("accepted must be a non-negative integer")
    if not (isinstance(invariants, list) and invariants
            and all(isinstance(inv, dict) and inv.get("_compiled") is _COMPILED for inv in invariants)):
        invariants = compile_invariants(invariants)
    rows = [_eval_one(inv, before, after, accepted) for inv in invariants]
    violations = [r["id"] for r in rows if r["status"] == "violated"]
    unevaluable = [r["id"] for r in rows if r["status"] == "unevaluable"]
    verdict = "violated" if violations else "unevaluable" if unevaluable else "holds"
    return {"verdict": verdict, "violations": violations, "unevaluable": unevaluable,
            "accepted": accepted, "checks": rows}


def check_baseline(invariants, snapshot):
    """The single-snapshot (absolute) invariants evaluated on the pre-transition state.

    A stated invariant that is already false (or unreadable) before anything is sent is mis-stated
    or the state is already broken: the harness refuses to mutate on it."""
    single = [inv for inv in invariants if inv["kind"] == "absolute"]
    if not single:
        return {"verdict": "holds", "violations": [], "unevaluable": [], "accepted": 0, "checks": []}
    return check(single, snapshot, snapshot, accepted=0)


def unstable_paths(invariants, first, second):
    """Invariant paths whose value differs (or appears/disappears) between two idle snapshots."""
    moved = []
    for path in invariant_paths(invariants):
        a = _lookup(first, path)
        b = _lookup(second, path)
        if a[0] != b[0] or (a[0] and not _same(a[1], b[1])):
            moved.append(".".join(map(str, path)))
    return moved


def restored(invariants, reference, current):
    """True when every invariant path reads the same value as in ``reference``."""
    return not unstable_paths(invariants, reference, current)


def ladder(compiled):
    """The rung plan with each rung's reserved request count (sends nothing)."""
    reads = len(compiled["snapshots"])
    rev = compiled["reverse"] is not None
    rungs = [{"rung": "baseline", "kind": "control", "count": 0, "reserve": 2 * reads}]
    for k in range(1, compiled["ladder"]["sequential_max"] + 1):
        rungs.append({"rung": f"sequential-{k}", "kind": "sequential", "count": k,
                      "reserve": k + reads + ((k + reads) if rev else 0)})
    width = compiled["ladder"]["burst_width"]
    if width:
        rungs.append({"rung": f"burst-{width}", "kind": "burst", "count": width,
                      "mode": compiled["ladder"]["burst_mode"],
                      "reserve": width + reads + width + reads})
    return rungs


# ---------------------------------------------------------------------------------------------------
# live driver
# ---------------------------------------------------------------------------------------------------
def _status(response):
    value = response.get("status") if isinstance(response, dict) else None
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _ambiguous(response):
    """True when a mutation's outcome is unknown: no status, transport error, 408/425/429, 5xx."""
    if not isinstance(response, dict) or response.get("error") or response.get("truncated"):
        # a truncated body was not read whole: the mutation's outcome is not known
        return True
    status = _status(response)
    return status is None or status in (408, 425, 429) or status >= 500


def _accepted(response):
    status = _status(response)
    return status is not None and 200 <= status < 300


class _Driver:
    def __init__(self, compiled, client_factory, *, clock, sleep, deadline, stop):
        self.spec = compiled
        self.factory = client_factory
        self.clock = clock or time.time
        self.sleep = sleep or time.sleep
        self.deadline = deadline
        self.stop = stop
        self.max_requests = compiled["max_requests"]
        self.requests = 0
        self.mutations = 0
        self.reserved = 0
        self.stopped = None
        self.lead = None

    # -- budget ------------------------------------------------------------------------------
    def _halted(self):
        if hasattr(self.stop, "is_set") and self.stop.is_set():
            return "stopped"
        if self.deadline is not None and self.deadline - self.clock() <= DEADLINE_PAD:
            return "deadline"
        return None

    def reserve(self, count, what):
        """Reserve a whole request group before any of it is sent (reserve-before-mutate)."""
        halted = self._halted()
        if halted:
            self.stopped = self.stopped or halted
            return False
        if self.requests + self.reserved + count > self.max_requests:
            self.stopped = self.stopped or (
                f"cannot reserve {what} ({count} requests; {self.max_requests - self.requests} left)")
            return False
        self.reserved += count
        return True

    def release(self):
        self.reserved = 0

    def untake(self, count):
        """Give ``count`` taken mutation requests back: only for a send refused before the wire."""
        self.requests -= count
        self.mutations -= count
        self.reserved += count

    def _take(self, count=1):
        if self.reserved < count:
            raise RuntimeError("harness bug: a request was sent without a reservation")
        self.reserved -= count
        self.requests += count

    # -- wire ----------------------------------------------------------------------------------
    def send(self, method, route, *, data=None, headers=None, mutation=False):
        self._take()
        if mutation:
            self.mutations += 1
        try:
            resp = self.lead.request(method, route, data=data, headers=dict(headers or {}),
                                     allow_redirects=False)
        except Exception as exc:  # the transport failed: a named error response, never a raise
            return {"status": None, "body": b"", "headers": {}, "error": type(exc).__name__}
        out = _race._normalize_response(resp)
        if isinstance(resp, dict) and resp.get("truncated"):
            out["truncated"] = True  # _normalize_response drops the flag; _ambiguous needs it
        return out

    def snapshot(self):
        """(doc, error) -- one read of every declared snapshot route, combined by name."""
        combined = {}
        for name, route in self.spec["snapshots"].items():
            resp = self.send("GET", route)
            status = _status(resp)
            if resp.get("error") or status is None or not 200 <= status < 300:
                return None, f"snapshot {name!r} unavailable ({resp.get('error') or f'HTTP {status}'})"
            body = resp.get("body") or b""
            text = bytes(body[:MAX_SNAPSHOT_CHARS]).decode("utf-8", "replace") \
                if isinstance(body, (bytes, bytearray)) else str(body)[:MAX_SNAPSHOT_CHARS]
            try:
                combined[name] = _security_json.loads(text, max_chars=MAX_SNAPSHOT_CHARS)
            except ValueError as exc:
                return None, f"snapshot {name!r} is not unambiguous JSON ({type(exc).__name__})"
        return combined, None


def _empty_report(compiled):
    return {
        "harness": HARNESS, "name": compiled.get("name") if compiled else None,
        "stated_by": compiled.get("stated_by") if compiled else None,
        "verdict": "inconclusive", "violation": None, "baseline": None, "rungs": [],
        "requests": 0, "mutations": 0, "state_restored": None, "stopped": None, "error": None,
        "note": ("the invariant was stated by the caller; the harness exercised it and did not "
                 "choose it. Nothing was submitted."),
    }


def run_harness(spec, client_factory, *, base_url, clock=None, sleep=None, deadline=None, stop=None):
    """Drive the smallest-transition ladder for one stated invariant against a scope-locked target.

    ``spec`` is the raw spec (validated by :func:`compile_spec`); ``client_factory(url, timeout)``
    builds scope-locked clients for the one assigned target (a ``web.WebClient`` with ``get_only``
    off -- the transition is state-changing by design).  ``deadline`` is an absolute ``clock()``
    value.  Returns the report dict; a bad spec or missing client comes back with ``error`` named
    and no request sent.  Never raises for a recoverable problem, never submits."""
    try:
        compiled = compile_spec(spec, base_url)
    except InvariantSpecError as exc:
        report = _empty_report(None)
        report.update(error="invalid spec", stopped=str(exc))
        return report
    report = _empty_report(compiled)
    report["ladder"] = ladder(compiled)
    refusal = state_change_refusal()
    if refusal:
        report.update(error="refused", stopped=refusal)
        return report
    if not callable(client_factory):
        report.update(error="no client factory", stopped="no client factory")
        return report
    drv =_Driver(compiled, client_factory, clock=clock, sleep=sleep, deadline=deadline, stop=stop)
    try:
        try:
            drv.lead = client_factory(base_url, REQUEST_TIMEOUT)
        except TypeError:
            drv.lead = client_factory(base_url)
        if _origin(getattr(drv.lead, "base", None)) != _origin(base_url):
            raise _web.OutOfScope("client scope does not match the spec's base url")
    except Exception as exc:
        report.update(error="no scoped client", stopped=f"no scoped client: {type(exc).__name__}")
        return report
    try:
        _climb(drv, compiled, report)
    finally:
        report["requests"] = drv.requests
        report["mutations"] = drv.mutations
        report["stopped"] = report["stopped"] or drv.stopped
    return report


def _climb(drv, compiled, report):
    invariants = compiled["invariants"]
    reads = len(compiled["snapshots"])
    if not drv.reserve(2 * reads, "the baseline"):
        return
    before, err = drv.snapshot()
    if err:
        report["stopped"] = err
        return
    noise, err = drv.snapshot()
    drv.release()
    if err:
        report["stopped"] = err
        return
    base_check = check_baseline(invariants, before)
    moved = unstable_paths(invariants, before, noise)
    report["baseline"] = {"check": base_check, "unstable_paths": moved}
    if base_check["verdict"] != "holds":
        report["stopped"] = ("the stated invariant is already "
                             + ("false" if base_check["verdict"] == "violated" else "unreadable")
                             + " before any transition (mis-stated or pre-broken); nothing was sent")
        return
    if moved:
        report["stopped"] = (f"invariant path(s) changed between two idle reads: {', '.join(moved)}; "
                             f"state the invariant on stable fields; nothing was sent")
        return
    origin_state = before
    for rung in report["ladder"][1:]:
        if rung["kind"] == "sequential":
            row = _sequential_rung(drv, compiled, rung, before)
        else:
            row = _burst_rung(drv, compiled, rung, before)
        if row is None:  # could not reserve / unsupported: nothing of this rung was sent
            break
        report["rungs"].append(row)
        if row["check"] and row["check"]["verdict"] == "violated":
            report["verdict"] = "violated"
            report["violation"] = {"rung": row["rung"], "count": row["count"],
                                   "accepted": row["accepted"],
                                   "invariants": row["check"]["violations"],
                                   "checks": [c for c in row["check"]["checks"]
                                              if c["status"] == "violated"]}
        if row.get("restore_snapshot") is not None:
            before = row.pop("restore_snapshot")
            report["state_restored"] = restored(invariants, origin_state, before)
        elif row.get("after_snapshot") is not None and (compiled["reverse"] is None
                                                         or row.get("ambiguous")):
            # No reversal was sent.  The next rung (if any) starts from the after-state, and with a
            # declared reverse the after-read itself says whether the target is at its baseline.
            before = row.pop("after_snapshot")
            report["state_restored"] = (None if compiled["reverse"] is None
                                        else restored(invariants, origin_state, before))
        row.pop("after_snapshot", None)
        row.pop("restore_snapshot", None)
        if row.get("restored") is False:
            report["state_restored"] = False
        if report["verdict"] == "violated":
            if row.get("ambiguous"):  # the violation stands; say that no reversal was sent
                report["stopped"] = f"{row['rung']}: ambiguous_mutation (no reversal sent)"
            report["stopped"] = report["stopped"] or drv.stopped
            return
        if row["check"] and row["check"]["verdict"] == "unevaluable":
            report["stopped"] = f"{row['rung']}: invariant unevaluable after the transition"
            return
        if row.get("ambiguous"):
            report["stopped"] = f"{row['rung']}: ambiguous_mutation (no reversal sent)"
            return
        if row.get("restored") is False:
            report["stopped"] = f"{row['rung']}: state not restored after the reverse step"
            return
        if row.get("stopped"):
            report["stopped"] = f"{row['rung']}: {row['stopped']}"
            return
    else:
        report["verdict"] = "holds"
        return
    report["stopped"] = report["stopped"] or drv.stopped


def _reverse_and_restore(drv, compiled, row, accepted, before):
    """Send the declared reverse once per accepted transition, then read the restore snapshot."""
    rev = compiled["reverse"]
    if rev is None:
        return
    row["reversed"] = 0
    for _ in range(accepted):
        resp = drv.send(rev["method"], rev["route"], data=rev["data"], headers=rev["headers"],
                        mutation=True)
        row["reverse_statuses"].append(_status(resp))
        if not _accepted(resp):
            row["restored"] = False
            row["stopped"] = ("reverse step " + ("ambiguous" if _ambiguous(resp) else "rejected")
                              + f" (HTTP {_status(resp)})")
            return
        row["reversed"] += 1
    snap, err = drv.snapshot()
    if err:
        row["restored"] = False
        row["stopped"] = f"restore check: {err}"
        return
    row["restore_snapshot"] = snap
    row["restored"] = restored(compiled["invariants"], before, snap)


def _new_row(rung):
    return {"rung": rung["rung"], "kind": rung["kind"], "count": rung["count"], "accepted": 0,
            "rejected": 0, "ambiguous": False, "statuses": [], "reverse_statuses": [],
            "reversed": None, "restored": None, "check": None, "stopped": None}


def _sequential_rung(drv, compiled, rung, before):
    if not drv.reserve(rung["reserve"], rung["rung"]):
        return None
    row = _new_row(rung)
    step = compiled["transition"]
    try:
        for _ in range(rung["count"]):
            resp = drv.send(step["method"], step["route"], data=step["data"],
                            headers=step["headers"], mutation=True)
            row["statuses"].append(_status(resp))
            if _ambiguous(resp):
                row["ambiguous"] = True
                break
            if _accepted(resp):
                row["accepted"] += 1
            else:
                row["rejected"] += 1
        after, err = drv.snapshot()
        if err:
            row["stopped"] = err
            row["restored"] = False if compiled["reverse"] is not None else None
            return row
        row["after_snapshot"] = after
        row["check"] = check(compiled["invariants"], before, after, accepted=row["accepted"])
        if not row["ambiguous"]:
            _reverse_and_restore(drv, compiled, row, row["accepted"], before)
        return row
    finally:
        drv.release()


def _burst_rung(drv, compiled, rung, before):
    if not drv.reserve(rung["reserve"], rung["rung"]):
        return None
    row = _new_row(rung)
    row["mode"] = rung["mode"]
    step = compiled["transition"]
    width = rung["count"]
    holder = {}

    def transport(_attempt):
        clients = None
        if rung["mode"] == "separate":
            clients = _race._build_burst_clients(drv.factory, compiled["base_url"], width,
                                                 seed=drv.lead)
            for client in clients:
                if _origin(getattr(client, "base", None)) != _origin(compiled["base_url"]):
                    raise _race.RaceUnsupported("a burst client is not scope-locked to the target")
        # Count the whole burst before any of it can leave, so a primitive that fails mid-send
        # can never make the report undercount what went out.
        drv._take(width)
        drv.mutations += width
        try:
            if clients is None:
                burst = _race.burst_single_packet(drv.lead, step["method"], step["route"],
                                                  width=width, body=step["data"],
                                                  headers=step["headers"])
            else:
                burst = _race.burst_separate(clients, step["method"], step["route"],
                                             body=step["data"], headers=step["headers"])
        except _race.RaceUnsupported:
            # B-048's burst primitives raise RaceUnsupported only from their pre-send checks
            # (client scope, TLS, same-origin route): nothing left, so the count goes back.
            drv.untake(width)
            raise
        except Exception as exc:  # failed after the burst may have left: every slot is ambiguous
            burst = [{"status": None, "body": b"", "headers": {}, "error": type(exc).__name__}
                     for _ in range(width)]
        holder["burst"] = burst
        return burst

    def readback():
        snap, err = drv.snapshot()
        holder["after"], holder["err"] = snap, err
        if err:
            return {"status": None, "body": b"", "headers": {}, "error": "snapshot"}
        return {"status": 200, "body": json.dumps(snap).encode("utf-8"), "headers": {}}

    def violated(_state, burst, _authoritative):
        if holder.get("err"):
            return False
        accepted = sum(1 for r in burst if _accepted(r))
        holder["check"] = check(compiled["invariants"], before, holder["after"], accepted=accepted)
        return holder["check"]["verdict"] == "violated"

    try:
        try:
            race_report, _winner = _race.race(
                transport=transport, width=width, success=violated, readback=readback, retries=0,
                clock=drv.clock, sleep=drv.sleep, deadline=None, max_requests=None,
                stop=drv.stop, mode=rung["mode"])
        except _race.RaceUnsupported as exc:
            if "burst" not in holder:  # refused before anything left: nothing of this rung was sent
                drv.stopped = drv.stopped or f"burst unsupported: {exc}"
                return None
            raise
        if "burst" not in holder:  # race() stopped before the burst: nothing of this rung was sent
            drv.stopped = drv.stopped or f"burst not fired: {race_report.get('stopped')}"
            return None
        burst = holder["burst"]
        row["race"] = {k: race_report.get(k) for k in ("mode", "width", "attempts", "transitions",
                                                       "requests", "stopped")}
        row["statuses"] = [_status(r) for r in burst]
        row["accepted"] = sum(1 for r in burst if _accepted(r))
        row["ambiguous"] = any(_ambiguous(r) for r in burst)
        row["rejected"] = sum(1 for r in burst if not _accepted(r) and not _ambiguous(r))
        if holder.get("err"):
            row["stopped"] = holder["err"]
            row["restored"] = False
            return row
        row["after_snapshot"] = holder["after"]
        row["check"] = holder.get("check") or check(
            compiled["invariants"], before, holder["after"], accepted=row["accepted"])
        if not row["ambiguous"]:
            _reverse_and_restore(drv, compiled, row, row["accepted"], before)
        return row
    finally:
        drv.release()


def summary_lines(report):
    """Short operator lines for a report (no headers, no bodies)."""
    lines = [f"invariant {report.get('name')!r} (stated by {report.get('stated_by')}): "
             f"{report.get('verdict')}; {report.get('requests')} requests, "
             f"{report.get('mutations')} mutations"]
    violation = report.get("violation")
    if violation:
        lines.append(f"  smallest violating transition: {violation['rung']} "
                     f"({violation['accepted']}/{violation['count']} accepted)")
        for row in violation["checks"]:
            lines.append(f"    {row['id']}: {row.get('detail')}")
    for row in report.get("rungs") or []:
        lines.append(f"  {row['rung']}: statuses {row['statuses']} accepted {row['accepted']} "
                     f"verdict {(row.get('check') or {}).get('verdict')} restored {row.get('restored')}")
    if report.get("state_restored") is False:
        lines.append("  WARNING: the target state was NOT restored to its baseline")
    if report.get("stopped"):
        lines.append(f"  stopped: {report['stopped']}")
    return lines
