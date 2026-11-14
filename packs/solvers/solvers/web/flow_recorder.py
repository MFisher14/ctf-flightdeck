#!/usr/bin/env python3
"""Stateful HTTP flow recorder for the squad's single assigned live web target (B-183).

A web challenge is often a *sequence*, not a single request: GET a login page, read its hidden
CSRF token, POST the login, carry the Set-Cookie session, GET a protected page, read the flag.
One request never reaches the flag; the recorder threads state between steps so the whole sequence
is driven once and can be replayed deterministically.

It drives a scope-locked ``solvers.toolkits.web.WebClient`` -- one cookie jar across every step, each
route re-validated against the attempt's scheme+host+port -- so it can touch only the one target the
caller passes. A step whose method is not a read (GET -- the same single-method set a ``get_only``
WebClient allows, so the two never disagree; HEAD counts as a state change here) is a
*state-changing* web action; the recorder refuses to run it unless the active event profile's ``rules.web_state_changing`` is true
(Open O-2), naming the rule. Nothing here auto-submits: a flag the scan notices is returned for the
player to submit through the gate.

A flow is a list of step dicts (caller-authored, trusted):

    [
      {"name": "login_page", "method": "GET", "path": "/login",
       "extract": {"csrf": {"form_hidden": "csrf_token"}}},
      {"name": "login", "method": "POST", "path": "/login",
       "body": "user=admin&csrf={csrf}",
       "content_type": "application/x-www-form-urlencoded",
       "expect_status": [200, 302]},
      {"name": "flag", "method": "GET", "path": "/account"},
    ]

``{var}`` placeholders in ``path``/``body``/``headers`` are filled from the variable store, which
starts from the caller's ``seed`` and grows as each step's extractors fire. A placeholder with no
value is a loud stop (``FlowError``), never a silent empty string. Extractors read one bounded layer
of the untrusted response:

    header         <name>            the response header's value (case-insensitive)
    location_param <query key>       a query parameter of the Location header (OAuth code/state)
    json           <dotted key>      a value from the JSON body (bounded; parsed fail-closed through
                                     solvers/web/security_json.py, so a duplicate key or a hostile
                                     nesting depth records the var as missing, never crashes)
    regex          <pattern>         first capture group of a regex over the bounded body text
    form_hidden    <input name>      a hidden <input>'s value (CSRF-token threading)
    cookie         <name>            a cookie value from the client's jar

Each step appends a transcript entry (name, method, url, status, which vars it set or missed, flags
seen); the run returns a ``FlowResult`` with the transcript, the final variable store, every flag
seen, and whether it completed. Replaying a recorded flow is just running the same steps again on a
fresh client.

This is a *library* engine: import it from a script or from the OIDC driver (solvers/web/oidc_driver.py);
``ctf run`` refuses a library engine.
"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path

# The scope guard and the event profile (for the O-2 state-change gate), loaded from this checkout.
try:  # package import
    from ctf import event as _event, scope as _scope
except Exception:  # pragma: no cover - direct solver-directory import
    import sys as _sys

    _root = Path(__file__).resolve().parents[2]
    if str(_root) not in _sys.path:
        _sys.path.insert(0, str(_root))
    from ctf import event as _event, scope as _scope

# The scope-locked live HTTP client and the event flag reader live in the web toolkit.
try:  # package import
    from ..toolkits import web as _web  # type: ignore
except Exception:  # pragma: no cover - direct solver-directory import
    try:
        import web as _web  # type: ignore  # flat import (conftest puts solvers/toolkits on sys.path)
        # `web` can also be solvers/web itself (imported as the package `web`, solvers/ on sys.path,
        # as the import gate does): that is not the toolkit, so load the toolkit by file instead.
        _web.WebClient  # noqa: B018
    except Exception:
        import importlib.util as _ilu
        import sys as _sys2

        _spec = _ilu.spec_from_file_location(
            "_flow_recorder_web", Path(__file__).resolve().parents[1] / "toolkits" / "web.py")
        _web = _ilu.module_from_spec(_spec)  # type: ignore[assignment]
        _sys2.modules[_spec.name] = _web  # register so dataclasses in the module resolve
        _spec.loader.exec_module(_web)  # type: ignore[union-attr]

# The shared fail-closed parser for target JSON that steers live actions (duplicate/colliding keys,
# member/node/depth caps).
try:  # package import
    from . import security_json as _sj  # type: ignore
except Exception:  # pragma: no cover - direct solver-directory import
    try:
        import security_json as _sj  # type: ignore  # flat import (conftest puts solvers/web on path)
    except Exception:
        import importlib.util as _ilu3
        import sys as _sys4

        _spec3 = _ilu3.spec_from_file_location(
            "_flow_recorder_security_json", Path(__file__).resolve().parent / "security_json.py")
        _sj = _ilu3.module_from_spec(_spec3)  # type: ignore[assignment]
        _sys4.modules[_spec3.name] = _sj
        _spec3.loader.exec_module(_sj)  # type: ignore[union-attr]


# One read-method set, shared with the WebClient's get_only guard: a method the recorder calls a read
# is exactly a method a get_only client puts on the wire (GET only; HEAD is gated like any write).
READ_METHODS = _web.WebClient.READ_METHODS
EXTRACTOR_KINDS = ("header", "location_param", "json", "regex", "form_hidden", "cookie")
MAX_STEPS = 64
MAX_BODY_SCAN = 2 << 20          # bytes of a response body read by an extractor or the flag scan
MAX_JSON_BYTES = 4 << 20         # bytes of a response body parsed as JSON by the `json` extractor
MAX_JSON_MEMBERS = 200_000       # object members / nodes the `json` extractor accepts
MAX_JSON_NODES = 400_000
DEFAULT_USER_AGENT = "ctf-tools-flow-recorder/1"   # neutral: master code is not event-branded

_VAR = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


class FlowError(ValueError):
    """A malformed flow, or an unresolved ``{var}`` placeholder. The message is one line."""


class StateChangeRefused(_web.OutOfScope):
    """A state-changing step the event profile does not authorise (Open O-2). A subclass of the web
    toolkit's OutOfScope, so ``except ctf.scope.OutOfScope`` catches it before any request is sent."""


# --------------------------------------------------------------------------------- the O-2 gate

def _active_profile() -> _event.EventProfile:
    """The event profile in force: the one scope pinned (tests, a pinned run), else event.current()."""
    prof = _scope.pinned()
    if prof is not None:
        return prof
    return _event.current()


def state_changes_allowed() -> bool:
    """Whether the active event profile authorises state-changing web actions (rules.web_state_changing)."""
    return bool(_active_profile().rules.web_state_changing)


def is_state_changing(method: str) -> bool:
    return str(method or "").upper() not in READ_METHODS


# ------------------------------------------------------------------------------ target JSON

def parse_target_json(raw, *, max_chars: int, what: str = "target JSON",
                      max_members: int = _sj.DEFAULT_MAX_MEMBERS,
                      max_nodes: int = _sj.DEFAULT_MAX_NODES):
    """Parse untrusted target JSON fail-closed (solvers/web/security_json.py).

    Raises ValueError with a one-line named reason for malformed, oversized, duplicate/colliding-key
    or too-deeply-nested input -- a hostile nesting depth that would blow the C scanner's recursion
    limit is converted to a ValueError, never an uncaught RecursionError."""
    if isinstance(raw, (bytes, bytearray)):
        if len(raw) > max_chars:
            raise ValueError(f"{what} is larger than {max_chars} bytes")
        try:
            raw = bytes(raw).decode("utf-8-sig", "strict")
        except UnicodeDecodeError as e:
            raise ValueError(f"{what} is not UTF-8: {e}") from e
    if not isinstance(raw, str):
        raise ValueError(f"{what} is not text")
    try:
        return _sj.loads(raw, max_chars=max_chars, max_members=max_members, max_nodes=max_nodes)
    except RecursionError as e:
        raise ValueError(f"{what} nests too deeply to parse") from e
    except ValueError as e:
        raise ValueError(f"{what} rejected: {e}") from e


# ------------------------------------------------------------------------------- templating

def fill(template, variables: dict):
    """Substitute every ``{name}`` in a caller-authored template from `variables`.

    A placeholder with no value raises FlowError (a loud stop), never a silent empty string. A
    template that is not a string (or is None) is returned unchanged."""
    if not isinstance(template, str):
        return template

    def sub(match):
        name = match.group(1)
        if name not in variables:
            raise FlowError(
                f"flow step references {{{name}}} but no earlier step set it "
                f"(known: {', '.join(sorted(variables)) or 'none'})")
        return str(variables[name])

    return _VAR.sub(sub, template)


# ------------------------------------------------------------------------------- extraction

class _HiddenInput(HTMLParser):
    """Collect every ``<input name=... value=...>`` (hidden or otherwise) by name, first wins."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.values: dict[str, str] = {}

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "input":
            return
        a = {k.lower(): (v or "") for k, v in attrs}
        name = a.get("name")
        if name is not None and name not in self.values:
            self.values[name] = a.get("value", "")


def _body_text(resp: dict) -> str:
    body = resp.get("body") or b""
    if isinstance(body, str):
        return body[:MAX_BODY_SCAN]
    return bytes(body)[:MAX_BODY_SCAN].decode("utf-8", "replace")


def _header(resp: dict, name: str):
    want = str(name).lower()
    for key, value in resp.get("response_header_pairs") or []:
        if str(key).lower() == want:
            return value
    # Fall back to the dict form when pairs are absent (injected test responses).
    for key, value in (resp.get("response_headers") or {}).items():
        if str(key).lower() == want:
            return value
    return None


def _json_path(resp: dict, dotted: str):
    body = resp.get("body") or b""
    raw = body if isinstance(body, (bytes, bytearray)) else str(body).encode("utf-8", "replace")
    try:
        obj = parse_target_json(raw, max_chars=MAX_JSON_BYTES, what="json extractor body",
                                max_members=MAX_JSON_MEMBERS, max_nodes=MAX_JSON_NODES)
    except ValueError:
        return None  # malformed / ambiguous / hostile: the var is recorded missing, not guessed
    cur = obj
    for part in str(dotted).split("."):
        if not part:
            continue
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.lstrip("-").isdigit():
            try:
                cur = cur[int(part)]
            except IndexError:
                return None
        else:
            return None
    if isinstance(cur, (dict, list)):
        return None
    if isinstance(cur, bool):
        return "true" if cur else "false"
    return None if cur is None else str(cur)


def _cookie(client, name: str):
    jar = getattr(client, "_jar", None)
    if jar is None:
        return None
    for cookie in jar:
        if cookie.name == name:
            return cookie.value
    return None


def extract_one(spec: dict, resp: dict, client):
    """Run one extractor spec ({kind: arg}) against a response. Returns the value or None."""
    if not isinstance(spec, dict) or len(spec) != 1:
        raise FlowError(f"an extractor is exactly one of {EXTRACTOR_KINDS}, got {spec!r}")
    (kind, arg), = spec.items()
    if kind not in EXTRACTOR_KINDS:
        raise FlowError(f"unknown extractor {kind!r}; use one of {EXTRACTOR_KINDS}")
    if kind == "header":
        return _header(resp, arg)
    if kind == "location_param":
        loc = _header(resp, "Location")
        if not loc:
            return None
        query = urllib.parse.urlsplit(loc).query
        values = urllib.parse.parse_qs(query, keep_blank_values=True)
        got = values.get(str(arg))
        return got[0] if got else None
    if kind == "json":
        return _json_path(resp, arg)
    if kind == "regex":
        try:
            match = re.search(str(arg), _body_text(resp))
        except re.error as e:
            raise FlowError(f"bad regex extractor {arg!r}: {e}") from e
        if not match:
            return None
        return match.group(1) if match.lastindex else match.group(0)
    if kind == "form_hidden":
        parser = _HiddenInput()
        try:
            parser.feed(_body_text(resp))
        except Exception:  # pragma: no cover - HTMLParser is lenient; guard anyway
            return None
        return parser.values.get(str(arg))
    if kind == "cookie":
        return _cookie(client, arg)
    return None  # pragma: no cover - EXTRACTOR_KINDS is exhaustive


# ------------------------------------------------------------------------------- the flow

def _normalize_step(step: dict, index: int) -> dict:
    if not isinstance(step, dict):
        raise FlowError(f"step {index} is not a dict: {step!r}")
    method = str(step.get("method", "GET")).upper()
    if not method.isalpha():
        raise FlowError(f"step {index} has a non-alphabetic method {step.get('method')!r}")
    if "path" not in step:
        raise FlowError(f"step {index} ({step.get('name')!r}) has no path")
    extract = step.get("extract") or {}
    if not isinstance(extract, dict):
        raise FlowError(f"step {index} extract must be a name->spec map, got {extract!r}")
    return {
        "name": step.get("name") or f"step{index}",
        "method": method,
        "path": step["path"],
        "body": step.get("body"),
        "headers": dict(step.get("headers") or {}),
        "content_type": step.get("content_type"),
        "extract": extract,
        "expect_status": step.get("expect_status"),
        "follow_redirects": bool(step.get("follow_redirects", True)),
    }


@dataclass
class FlowResult:
    """The outcome of one recorded flow run."""

    transcript: list = field(default_factory=list)
    variables: dict = field(default_factory=dict)
    flags: list = field(default_factory=list)
    completed: bool = False
    stopped_reason: str | None = None

    def to_dict(self) -> dict:
        return {
            "transcript": self.transcript,
            "variables": dict(self.variables),
            "flags": list(self.flags),
            "completed": self.completed,
            "stopped_reason": self.stopped_reason,
        }


def run_flow(client, steps, *, seed: dict | None = None, flag_scan: bool = True,
             stop_on_mismatch: bool = True, max_steps: int = MAX_STEPS) -> FlowResult:
    """Drive `steps` on a scope-locked `client`, threading state between them.

    `client` is a ``solvers.toolkits.web.WebClient`` (or an object with the same ``request`` surface
    and cookie jar). `seed` seeds the variable store. A state-changing step raises StateChangeRefused
    unless the active profile's rules.web_state_changing is true. An ``expect_status`` mismatch stops
    the flow (``stop_on_mismatch``) with a named reason. Returns a FlowResult; never auto-submits."""
    normalized = [_normalize_step(s, i) for i, s in enumerate(steps)]
    if len(normalized) > max_steps:
        raise FlowError(f"flow has {len(normalized)} steps; the cap is {max_steps}")
    variables: dict = dict(seed or {})
    flags: set[str] = set()
    result = FlowResult(variables=variables, flags=[])

    for step in normalized:
        if is_state_changing(step["method"]) and not state_changes_allowed():
            raise StateChangeRefused(
                f"flow step {step['name']!r} is a {step['method']} (a state-changing web action) but "
                f"event {_active_profile().slug!r} has rules.web_state_changing = false (Open O-2): "
                "set it true in the event profile only with the player's yes")
        path = fill(step["path"], variables)
        body = fill(step["body"], variables)
        headers = {k: fill(v, variables) for k, v in step["headers"].items()}
        if step["content_type"] and not any(k.lower() == "content-type" for k in headers):
            headers["Content-Type"] = step["content_type"]
        resp = client.request(step["method"], path, data=body, headers=headers or None,
                              allow_redirects=step["follow_redirects"])

        set_vars: dict = {}
        missing: list = []
        for var, spec in step["extract"].items():
            value = extract_one(spec, resp, client)
            if value is None:
                missing.append(var)
            else:
                variables[var] = value
                set_vars[var] = value

        step_flags: list = []
        if flag_scan:
            step_flags = sorted(_web.find_flags(resp.get("body") or b""))
            flags.update(step_flags)

        expect = step["expect_status"]
        expect_ok = None
        if expect is not None:
            allowed = {int(x) for x in (expect if isinstance(expect, (list, tuple, set)) else [expect])}
            expect_ok = resp.get("status") in allowed

        result.transcript.append({
            "name": step["name"],
            "method": step["method"],
            "url": resp.get("url"),
            "status": resp.get("status"),
            "set": set_vars,
            "missing": missing,
            "flags": step_flags,
            "redirect_not_followed": resp.get("redirect_not_followed"),
            "expect_ok": expect_ok,
            "elapsed": resp.get("elapsed"),
        })

        if expect_ok is False and stop_on_mismatch:
            result.stopped_reason = (
                f"step {step['name']!r} got status {resp.get('status')}, expected "
                f"{sorted(allowed)}")
            result.flags = sorted(flags)
            return result

    result.flags = sorted(flags)
    result.completed = True
    return result


class FlowRecorder:
    """Build a scope-locked client for one target and record/replay flows on it.

    ``get_only`` is derived from the O-2 gate: when the active profile forbids state-changing web
    actions the underlying WebClient is built GET-only, so even a direct client use cannot mutate the
    target. Pass ``get_only=`` to override only when you know what you are doing."""

    def __init__(self, base_url, *, timeout: float = 10.0,
                 user_agent: str = DEFAULT_USER_AGENT, get_only=None):
        if get_only is None:
            get_only = not state_changes_allowed()
        self.base_url = base_url
        self.client = _web.WebClient(base_url, timeout=timeout, user_agent=user_agent,
                                     get_only=bool(get_only))

    def record(self, steps, **kw) -> FlowResult:
        return run_flow(self.client, steps, **kw)

    def replay(self, flow_or_steps, **kw) -> FlowResult:
        """Run a flow again on a fresh client (a replay is deterministic given the steps and seed)."""
        steps = flow_or_steps.get("steps") if isinstance(flow_or_steps, dict) else flow_or_steps
        fresh = FlowRecorder(self.base_url, timeout=self.client.timeout,
                             user_agent=self.client.user_agent, get_only=self.client.get_only)
        return run_flow(fresh.client, steps, **kw)
