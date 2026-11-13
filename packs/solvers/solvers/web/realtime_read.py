#!/usr/bin/env python3
"""Bounded server-first WebSocket and SSE proof reader.

This is deliberately not a general real-time client. It follows only an exact route from the target's own
clue document, sends no WebSocket application/control frame, reads one bounded server-first response, and never
reconnects. WebSocket needs an exact scalar reference plus a 426 upgrade control; SSE needs an explicit
server-sent-event contract. All wire work is delegated to the target-pinned :class:`web.WebClient`.
"""

from __future__ import annotations

import json
import os
import re
import sys
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
import security_json as _security_json  # noqa: E402 -- fail-closed policy JSON
import ws_client_trust as _ws_core  # noqa: E402 -- B-049 stateful sequence/nonce core (offline)

try:
    import forge_event as _proofs  # noqa: E402
except Exception:
    _proofs = None

BASELINE_INCOMPLETE = getattr(
    _proofs, "BASELINE_STRICT_INCOMPLETE",
    "<!-- csctf-baseline-strict-set:incomplete -->",
)

REQUEST_TIMEOUT = 6.0
DEFAULT_SECONDS = 15.0
DEFAULT_MAX_REQUESTS = 5
PAD = 0.3
MAX_BODY = 65_536
MAX_FRAMES = 4
MAX_CONVERSATION_FRAMES = 12
MAX_EVENTS = 6
# The event's payoff token in any case (ctf.flagfmt): a proof under a proof event, else a flag.
PAYOFF_SEEN = flagfmt.PAYOFF_ANYCASE
PARAM = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
FATAL_PATH = re.compile(
    r"(?i)(?:^|[/_.-])(?:delete|destroy|drop|wipe|purge|truncate|erase|revoke|logout|signout|"
    r"disable|deactivate|uninstall|kill|shutdown|reboot|ban|suspend|cancel|transfer|pay|reset)"
    r"(?=$|[/_.-]|\d)"
)
WS_REQUIRED = re.compile(r"(?i)\b(?:websocket[_ -]?upgrade[_ -]?required|upgrade[_ -]?required)\b")
WS_EFFECT = re.compile(r"(?i)\b(?:unauthori[sz]ed[_ -]?event[_ -]?stream|event[_ -]?stream[_ -]?read|"
                       r"stream[_ -]?(?:access|disclosure|bypass))\b")
SSE_WORDS = re.compile(r"(?i)\b(?:server[-_ ]sent[-_ ]events?|event[-_ ]stream|sse)\b")
READ_OPERATION = re.compile(r"(?i)^(?:read|get|fetch|inspect|query|subscribe)$")


OFF_FILE = "_web_realtime.off"


def disabled_reason():
    """None when the real-time class may run, else the named reason it is off (B-237: never silent).

    The player's policy switch is ``CTF_WEB_REALTIME`` (off/0/false/no) or a ``_web_realtime.off`` file in
    the event workdir.  When the workdir cannot be resolved the switch cannot be checked, so the class stays
    off (fail-closed) and says why."""
    raw = ctf_env.get("CTF_WEB_REALTIME")
    if raw is not None:
        if raw.strip().lower() in ("off", "0", "false", "no"):
            return f"CTF_WEB_REALTIME={raw.strip()[:16]} turns the real-time class off"
        return None
    try:
        root = ctf_paths.workdir()
    except Exception as exc:
        return (f"the event workdir could not be resolved ({type(exc).__name__}), so the {OFF_FILE} switch "
                "cannot be checked; set CTF_WEB_REALTIME=on to run the class anyway")
    try:
        if (root / OFF_FILE).exists():
            return f"{OFF_FILE} in the event workdir turns the real-time class off"
    except OSError as exc:
        return f"the {OFF_FILE} switch could not be checked ({type(exc).__name__})"
    return None


def enabled():
    return disabled_reason() is None


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


def _route(value, base_url):
    try:
        route = _web.safe_same_origin_route(value, base_url, allow_query=False,
                                            guard_query=True, max_bytes=1024)
        if route is None:
            return None
        path = urllib.parse.urlsplit(route).path or "/"
        for layer in _web.canonical_route_layers(path, max_bytes=1024) or ():
            camel = re.sub(r"([a-z0-9])([A-Z])", r"\1/\2", layer)
            if (FATAL_PATH.search(layer) or FATAL_PATH.search(camel)
                    or _web.route_has_destructive_action(layer)):
                return None
        return route
    except Exception:
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
    value = response.get("body", response.get("text", ""))
    if isinstance(value, (bytes, bytearray)):
        return bytes(value[:MAX_BODY]).decode("utf-8", "replace")
    return str(value or "")[:MAX_BODY]


def _headers(response):
    raw = response.get("response_headers", response.get("headers", {})) if isinstance(response, dict) else {}
    return {str(key).lower(): str(value).strip()[:2000] for key, value in raw.items()} \
        if isinstance(raw, dict) else {}


def _baseline_text(response):
    """All bounded control bytes, including proof-shaped response-header decoys."""
    if _proofs is not None and hasattr(_proofs, "response_baseline_text"):
        return _proofs.response_baseline_text(response)
    text = _text(response)
    headers = "\n".join(_headers(response).values())
    return (text + (("\n" + headers) if headers else ""))[:MAX_BODY]


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


def _preloaded(preloaded, path):
    return _response(preloaded.get(path))


def _with_query(route, name, value):
    if not PARAM.fullmatch(str(name or "")):
        return None
    parts = urllib.parse.urlsplit(route)
    if parts.query or parts.fragment:
        return None
    query = urllib.parse.urlencode([(name, str(value))])
    return urllib.parse.urlunsplit(("", "", parts.path or "/", query, ""))


def _safe_scalar(value, *, max_bytes=256):
    return (not isinstance(value, (dict, list, bool)) and value is not None
            and 0 < len(str(value).encode("utf-8", "strict")) <= max_bytes)


def _client_ws_contract(clues, base_url):
    """Compile an explicit structured clue into one generated JSON read."""
    if "websocket_read" not in clues:
        return None, False
    raw = clues.get("websocket_read")
    if not isinstance(raw, dict) or set(raw) - {
            "route", "request", "response", "subprotocol", "compression", "fragment_bytes"}:
        return None, True
    route = _route(raw.get("route"), base_url)
    request, response = raw.get("request"), raw.get("response")
    if not isinstance(request, dict) or not isinstance(response, dict):
        return None, True
    if set(request) != {"id_field", "id", "operation_field", "operation",
                        "reference_field", "reference"}:
        return None, True
    if set(response) != {"id_field", "effect_field", "effect"}:
        return None, True
    names = [request.get("id_field"), request.get("operation_field"),
             request.get("reference_field"), response.get("id_field"),
             response.get("effect_field")]
    if route is None or any(not isinstance(name, str) or not PARAM.fullmatch(name) for name in names):
        return None, True
    if len(set(names[:3])) != 3 or response["id_field"] != request["id_field"]:
        return None, True
    if (not _safe_scalar(request.get("id")) or not _safe_scalar(request.get("reference"))
            or not isinstance(request.get("operation"), str)
            or not READ_OPERATION.fullmatch(request["operation"])
            or not _safe_scalar(response.get("effect"))):
        return None, True
    subprotocol = raw.get("subprotocol")
    if subprotocol is not None and (not isinstance(subprotocol, str)
                                    or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}", subprotocol)):
        return None, True
    compression = raw.get("compression", False)
    if compression not in (False, "permessage-deflate"):
        return None, True
    fragment = raw.get("fragment_bytes", 0)
    if isinstance(fragment, bool) or not isinstance(fragment, int) or not 0 <= fragment <= 4096:
        return None, True
    message = {
        request["id_field"]: request["id"],
        request["operation_field"]: request["operation"],
        request["reference_field"]: request["reference"],
    }
    return {
        "route": route, "message": json.dumps(message, separators=(",", ":"), ensure_ascii=False),
        "id_field": response["id_field"], "id": request["id"],
        "effect_field": response["effect_field"], "effect": response["effect"],
        "subprotocol": subprotocol, "compression": compression == "permessage-deflate",
        "fragment_bytes": fragment,
    }, True


def _client_ws_stateful_contract(clues, base_url):
    """Compile a stateful WebSocket read clue into a sequenced set of generated JSON frames (B-049).

    Unlike ``websocket_read`` (one frame), a stateful protocol rejects any frame whose
    sequence/nonce counter is wrong.  This contract adds a ``sequence_field`` (and an optional
    ``nonce_field``) and a bounded ``steps`` count; the client renders ``steps`` monotonically
    sequenced frames from one exact schema.  Returns ``(plan, present)``: ``present`` is True once
    the clue key exists, so a malformed stateful clue is a named terminal decline, never a silent
    fall-through to another class.
    """
    if "websocket_stateful_read" not in clues:
        return None, False
    raw = clues.get("websocket_stateful_read")
    if not isinstance(raw, dict) or set(raw) - {
            "route", "request", "response", "steps", "sequence_start", "sequence_step",
            "subprotocol", "compression", "fragment_bytes"}:
        return None, True
    route = _route(raw.get("route"), base_url)
    request, response = raw.get("request"), raw.get("response")
    if not isinstance(request, dict) or not isinstance(response, dict):
        return None, True
    has_nonce = "nonce_field" in request
    allowed = {"id_field", "id", "operation_field", "operation", "reference_field", "reference",
               "sequence_field"}
    if has_nonce:
        allowed = allowed | {"nonce_field"}
    if set(request) != allowed:
        return None, True
    if set(response) != {"id_field", "effect_field", "effect"}:
        return None, True
    names = [request.get("id_field"), request.get("operation_field"),
             request.get("reference_field"), request.get("sequence_field"),
             response.get("id_field"), response.get("effect_field")]
    if has_nonce:
        names.append(request.get("nonce_field"))
    if route is None or any(not isinstance(name, str) or not PARAM.fullmatch(name) for name in names):
        return None, True
    # Field names on the request frame must be distinct, and the response id must echo the request id.
    request_names = [request["id_field"], request["operation_field"], request["reference_field"],
                     request["sequence_field"]] + ([request["nonce_field"]] if has_nonce else [])
    if len(set(request_names)) != len(request_names) or response["id_field"] != request["id_field"]:
        return None, True
    if (not _safe_scalar(request.get("id")) or not _safe_scalar(request.get("reference"))
            or not isinstance(request.get("operation"), str)
            or not READ_OPERATION.fullmatch(request["operation"])
            or not _safe_scalar(response.get("effect"))):
        return None, True
    steps = raw.get("steps", 1)
    if isinstance(steps, bool) or not isinstance(steps, int) or not 1 <= steps <= _ws_core.MAX_MESSAGES:
        return None, True
    start = raw.get("sequence_start", 1)
    step = raw.get("sequence_step", 1)
    if (isinstance(start, bool) or not isinstance(start, int)
            or isinstance(step, bool) or not isinstance(step, int) or step == 0):
        return None, True
    subprotocol = raw.get("subprotocol")
    if subprotocol is not None and (not isinstance(subprotocol, str)
                                    or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}", subprotocol)):
        return None, True
    compression = raw.get("compression", False)
    if compression not in (False, "permessage-deflate"):
        return None, True
    fragment = raw.get("fragment_bytes", 0)
    if isinstance(fragment, bool) or not isinstance(fragment, int) or not 0 <= fragment <= 4096:
        return None, True
    try:
        state = _ws_core.SequenceState(start=start, step=step)
        messages = _ws_core.build_sequenced_messages(
            {request["id_field"]: request["id"],
             request["operation_field"]: request["operation"],
             request["reference_field"]: request["reference"]},
            request["sequence_field"], steps, state,
            nonce_field=request.get("nonce_field") if has_nonce else None)
    except _ws_core.WSClientTrustError:
        return None, True
    return {
        "route": route, "messages": messages,
        "id_field": response["id_field"], "id": request["id"],
        "effect_field": response["effect_field"], "effect": response["effect"],
        "subprotocol": subprotocol, "compression": compression == "permessage-deflate",
        "fragment_bytes": fragment, "steps": steps,
    }, True


def _client_sse_contract(clues, base_url):
    if "sse_read" not in clues:
        return None, False
    raw = clues.get("sse_read")
    if not isinstance(raw, dict) or set(raw) - {
            "route", "request_id_field", "request_id", "reference_field", "reference",
            "response_id_field", "event", "max_events", "resume_required"}:
        return None, True
    names = [raw.get("request_id_field"), raw.get("reference_field"), raw.get("response_id_field")]
    if any(not isinstance(name, str) or not PARAM.fullmatch(name) for name in names):
        return None, True
    if raw["request_id_field"] != raw["response_id_field"] \
            or raw["request_id_field"] == raw["reference_field"]:
        return None, True
    route = _route(raw.get("route"), base_url)
    if route is None or not _safe_scalar(raw.get("request_id")) \
            or not _safe_scalar(raw.get("reference")):
        return None, True
    event = raw.get("event")
    if event is not None and (not isinstance(event, str) or not PARAM.fullmatch(event)):
        return None, True
    count = raw.get("max_events", MAX_EVENTS)
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= MAX_EVENTS:
        return None, True
    resume = raw.get("resume_required", False)
    if not isinstance(resume, bool):
        return None, True
    parts = urllib.parse.urlsplit(route)
    if parts.query:
        return None, True
    query = urllib.parse.urlencode([
        (raw["request_id_field"], str(raw["request_id"])),
        (raw["reference_field"], str(raw["reference"])),
    ])
    path = urllib.parse.urlunsplit(("", "", parts.path or "/", query, ""))
    return {"route": route, "path": path, "id_field": raw["response_id_field"],
            "id": raw["request_id"], "event": event, "max_events": count,
            "resume_required": resume}, True


class _Reader:
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
            self.max_requests = max(0, min(DEFAULT_MAX_REQUESTS,
                                           int(self.ctx.get("max_requests", DEFAULT_MAX_REQUESTS))))
        except (TypeError, ValueError):
            self.max_requests = DEFAULT_MAX_REQUESTS
        self.stop = self.ctx.get("stop")
        self.preloaded = dict(self.ctx.get("preloaded") or {})
        supplied_baselines = list(self.ctx.get("baseline_texts") or [])
        self.baselines = [str(value or "")[:MAX_BODY] for value in supplied_baselines[:40]]
        if len(supplied_baselines) > 40 and BASELINE_INCOMPLETE not in self.baselines:
            self.baselines.append(BASELINE_INCOMPLETE)
        self.requests = 0
        self.responses = []
        self.candidates = []
        self.success = False
        self.terminal = False
        self.protocol = None
        self.stopped = None
        self.websocket = None              # B-237: the WebSocket class report (outcome + named reason)
        self.client = None
        try:
            candidate = self.ctx.get("client")
            if candidate is None and callable(self.ctx.get("client_factory")):
                candidate = self.ctx["client_factory"](self.url, REQUEST_TIMEOUT)
            if candidate is None:
                candidate = _web.WebClient(self.url, timeout=REQUEST_TIMEOUT)
            client_origin = _origin(getattr(candidate, "base", None))
            target_origin = _origin(self.url)
            if client_origin is None or target_origin is None or client_origin != target_origin:
                raise _web.OutOfScope("injected client scope does not match target")
            self.client = candidate
        except Exception as exc:
            self.stopped = f"no scoped client: {type(exc).__name__}"

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

    def _call(self, method, path, role, **options):
        if not self._may_send():
            return None
        self.requests += 1
        try:
            self.client.timeout = max(0.2, min(REQUEST_TIMEOUT, self.deadline - time.time() - 0.1))
            if method == "get":
                response = self.client.request("GET", path, allow_redirects=False)
            elif method == "websocket":
                response = self.client.websocket_receive(path, deadline=self.deadline,
                                                         max_frames=MAX_FRAMES, max_bytes=MAX_BODY)
            elif method == "websocket-conversation":
                response = self.client.websocket_conversation(
                    path, options.pop("messages"), deadline=self.deadline,
                    max_frames=MAX_CONVERSATION_FRAMES, max_bytes=MAX_BODY, **options)
            elif method == "sse":
                response = self.client.sse_first_event(path, deadline=self.deadline, max_bytes=MAX_BODY)
            elif method == "sse-events":
                response = self.client.sse_events(
                    path, deadline=self.deadline, max_bytes=MAX_BODY, **options)
            else:
                return None
        except Exception as exc:
            self.responses.append({"role": role, "path": path.split("?", 1)[0],
                                   "status": None, "error": type(exc).__name__})
            self.stopped = self.stopped or f"transport: {type(exc).__name__}"
            return None
        self.responses.append({"role": role, "path": path.split("?", 1)[0],
                               "status": response.get("status") if isinstance(response, dict) else None})
        return response

    def _outcome(self, response):
        if _proofs is None:
            return {"auto": None, "candidates": []}
        try:
            # A validated 101 plus the class-specific effect is the application success anchor. Normalize the
            # status only after those checks so the generic success extractor keeps its ordinary 2xx rule.
            payoff = dict(response or {})
            payoff["status"] = 200
            outcome = _proofs.extract_success(payoff, self.baselines,
                                              host=urllib.parse.urlsplit(self.url).hostname)
            self.candidates.extend(str(value)[:256] for value in outcome.get("candidates") or [])
            return outcome
        except Exception:
            return {"auto": None, "candidates": []}

    @staticmethod
    def _same_scalar(left, right):
        if isinstance(left, (dict, list, bool)) or isinstance(right, (dict, list, bool)):
            return False
        return type(left) is type(right) and left == right

    def _client_websocket(self, clues):
        contract, present = _client_ws_contract(clues, self.url)
        if not present:
            return None, False
        if contract is None or not self._route_allowed(contract["route"]):
            self.stopped = "invalid client WebSocket read contract"
            self.terminal = True
            self.protocol = "websocket-client"
            return None, True
        control = _preloaded(self.preloaded, contract["route"]) \
            or self._call("get", contract["route"], "upgrade-control")
        if isinstance(control, dict):
            self.baselines.append(_baseline_text(control))
        headers = _headers(control)
        if not (isinstance(control, dict) and control.get("status") == 426
                and (headers.get("upgrade", "").lower() == "websocket"
                     or WS_REQUIRED.search(_text(control)))):
            self.stopped = "client WebSocket upgrade control missing"
            self.terminal = True
            return None, True
        self.terminal = True
        self.protocol = "websocket-client"
        response = self._call(
            "websocket-conversation", contract["route"], "client-read-conversation",
            messages=[contract["message"]], fragment_bytes=contract["fragment_bytes"],
            subprotocol=contract["subprotocol"], compression=contract["compression"])
        if response is None and str(self.stopped or "").startswith("transport: OutOfScope"):
            # B-237: a get_only client (the web lane until Open O-2) refuses the conversation before any
            # connection, because it sends client application frames.  Say so instead of a bare stop.
            self.websocket = {"route": contract["route"].split("?", 1)[0], "references": [], "tries": [],
                              "outcome": "declined",
                              "reason": "the clue's websocket_read contract needs client application frames, "
                                        "which this GET-only client refuses (Open O-2)"}
            return None, True
        if not isinstance(response, dict) or response.get("status") != 101 \
                or response.get("protocol_error") or response.get("truncated") \
                or response.get("idle_timeout") \
                or not (response.get("server_closed") or response.get("read_quiescent")):
            self.stopped = "incomplete client WebSocket conversation"
            return None, True
        messages = response.get("websocket_messages")
        if not isinstance(messages, list) or len(messages) > 16 \
                or any(not isinstance(message, str) for message in messages) \
                or response.get("websocket_binary_messages_b64"):
            self.stopped = "ambiguous WebSocket message set"
            return None, True
        correlated_responses = []
        for message in messages:
            local_response = dict(response)
            local_response["body"] = message.encode("utf-8", "strict")
            local_response["websocket_messages"] = [message]
            doc = _json(local_response)
            correlated = (isinstance(doc, dict)
                          and self._same_scalar(doc.get(contract["id_field"]), contract["id"])
                          and self._same_scalar(doc.get(contract["effect_field"]), contract["effect"]))
            if not correlated:
                # An unsolicited proof-looking frame is a control/decoy, not
                # evidence for this request.
                self.baselines.append(_baseline_text(local_response))
                continue
            correlated_responses.append(local_response)
        autos, ambiguous = [], False
        for local_response in correlated_responses:
            outcome = self._outcome(local_response)
            if outcome.get("auto"):
                autos.append(str(outcome["auto"]))
            if outcome.get("candidates") or (not outcome.get("auto") and outcome.get("wire")):
                ambiguous = True
        unique = list(dict.fromkeys(autos))
        if len(unique) == 1 and not ambiguous:
            self.success = True
            return unique[0], True
        if unique or ambiguous:
            self.success = True
        self.stopped = self.stopped or "no unambiguous correlated WebSocket reply"
        return None, True

    def _client_websocket_stateful(self, clues):
        """Drive a stateful WebSocket read: the sequenced-frame counterpart of ``_client_websocket``.

        It renders ``steps`` monotonically sequenced client frames (B-049) and sends them in one
        bounded conversation, then correlates the server's effect-bearing reply exactly as the single
        -frame client path does.  Every exit names its outcome so the first pass can say why it did
        not read.
        """
        contract, present = _client_ws_stateful_contract(clues, self.url)
        if not present:
            return None, False
        if contract is None or not self._route_allowed(contract["route"]):
            self.stopped = "invalid client stateful WebSocket read contract"
            self.terminal = True
            self.protocol = "websocket-stateful"
            return None, True
        control = _preloaded(self.preloaded, contract["route"]) \
            or self._call("get", contract["route"], "upgrade-control")
        if isinstance(control, dict):
            self.baselines.append(_baseline_text(control))
        headers = _headers(control)
        if not (isinstance(control, dict) and control.get("status") == 426
                and (headers.get("upgrade", "").lower() == "websocket"
                     or WS_REQUIRED.search(_text(control)))):
            self.stopped = "client stateful WebSocket upgrade control missing"
            self.terminal = True
            self.protocol = "websocket-stateful"
            return None, True
        self.terminal = True
        self.protocol = "websocket-stateful"
        response = self._call(
            "websocket-conversation", contract["route"], "stateful-read-conversation",
            messages=contract["messages"], fragment_bytes=contract["fragment_bytes"],
            subprotocol=contract["subprotocol"], compression=contract["compression"])
        if response is None and str(self.stopped or "").startswith("transport: OutOfScope"):
            # B-237 parity: a get_only client (the live web lane) refuses the conversation before any
            # connection, because a stateful read sends client application frames.
            self.websocket = {"route": contract["route"].split("?", 1)[0],
                              "references": [], "tries": [], "outcome": "declined",
                              "reason": "the clue's websocket_stateful_read contract needs client "
                                        "application frames, which this GET-only client refuses (Open O-2)"}
            return None, True
        if not isinstance(response, dict) or response.get("status") != 101 \
                or response.get("protocol_error") or response.get("truncated") \
                or response.get("idle_timeout") \
                or not (response.get("server_closed") or response.get("read_quiescent")):
            self.stopped = "incomplete client stateful WebSocket conversation"
            return None, True
        messages = response.get("websocket_messages")
        if not isinstance(messages, list) or len(messages) > 16 \
                or any(not isinstance(message, str) for message in messages) \
                or response.get("websocket_binary_messages_b64"):
            self.stopped = "ambiguous stateful WebSocket message set"
            return None, True
        correlated_responses = []
        for message in messages:
            local_response = dict(response)
            local_response["body"] = message.encode("utf-8", "strict")
            local_response["websocket_messages"] = [message]
            doc = _json(local_response)
            correlated = (isinstance(doc, dict)
                          and self._same_scalar(doc.get(contract["id_field"]), contract["id"])
                          and self._same_scalar(doc.get(contract["effect_field"]), contract["effect"]))
            if not correlated:
                self.baselines.append(_baseline_text(local_response))
                continue
            correlated_responses.append(local_response)
        autos, ambiguous = [], False
        for local_response in correlated_responses:
            outcome = self._outcome(local_response)
            if outcome.get("auto"):
                autos.append(str(outcome["auto"]))
            if outcome.get("candidates") or (not outcome.get("auto") and outcome.get("wire")):
                ambiguous = True
        unique = list(dict.fromkeys(autos))
        if len(unique) == 1 and not ambiguous:
            self.success = True
            return unique[0], True
        if unique or ambiguous:
            self.success = True
        self.stopped = self.stopped or "no unambiguous correlated stateful WebSocket reply"
        return None, True

    def _client_sse(self, clues):
        contract, present = _client_sse_contract(clues, self.url)
        if not present:
            return None, False
        if contract is None or not self._route_allowed(contract["path"]):
            self.stopped = "invalid client SSE read contract"
            self.terminal = True
            self.protocol = "sse-client"
            return None, True
        self.terminal = True
        self.protocol = "sse-client"
        last_event_id = None
        for attempt in range(2 if contract["resume_required"] else 1):
            response = self._call(
                "sse-events", contract["path"],
                "event-read" if attempt == 0 else "event-resume",
                max_events=contract["max_events"], last_event_id=last_event_id)
            if not isinstance(response, dict) or response.get("protocol_error") \
                    or response.get("truncated") or response.get("incomplete"):
                return None, True
            events = response.get("sse_events")
            if not isinstance(events, list) or len(events) > MAX_EVENTS:
                return None, True
            correlated_responses = []
            for event in events:
                if not isinstance(event, dict) or not isinstance(event.get("data"), str):
                    return None, True
                data = event["data"]
                local_response = dict(response)
                local_response["body"] = data.encode("utf-8", "strict")
                doc = _json(local_response)
                correlated = (isinstance(doc, dict)
                              and str(doc.get(contract["id_field"])) == str(contract["id"])
                              and (contract["event"] is None
                                   or event.get("event") == contract["event"]))
                if not correlated:
                    self.baselines.append(_baseline_text(local_response))
                    continue
                correlated_responses.append(local_response)
            autos, ambiguous = [], False
            for local_response in correlated_responses:
                outcome = self._outcome(local_response)
                if outcome.get("auto"):
                    autos.append(str(outcome["auto"]))
                if outcome.get("candidates") or (not outcome.get("auto") and outcome.get("wire")):
                    ambiguous = True
            unique = list(dict.fromkeys(autos))
            if len(unique) == 1 and not ambiguous:
                self.success = True
                return unique[0], True
            if unique or ambiguous:
                self.success = True
                return None, True
            ids = [event.get("id") for event in events
                   if isinstance(event, dict) and isinstance(event.get("id"), str)
                   and event.get("id")]
            if attempt == 0 and contract["resume_required"]:
                if not ids or len(set(ids[-1:])) != 1:
                    self.stopped = "explicit SSE resume has no unambiguous event id"
                    return None, True
                last_event_id = ids[-1]
        self.stopped = self.stopped or "no correlated SSE event"
        return None, True

    def _websocket(self, clues):
        route = _route(clues.get("feature_route"), self.url)
        refs = []
        for key, value in clues.items():
            name = str(key)
            if (name.lower().endswith("_reference") and re.search(r"(?i)stream|event|channel", name)
                    and isinstance(value, (str, int)) and not isinstance(value, bool)
                    and 1 <= len(str(value)) <= 128):
                refs.append((name, str(value)))
        if refs:
            # B-237: the class is indicated by a stream/event/channel reference; every exit below names
            # its outcome so the web first pass can say why it did not read (Day 22 lost ~40 s to that).
            self.websocket = {"route": (route or "").split("?", 1)[0] or None,
                              "references": [name for name, _value in refs][:4], "tries": []}
        # Distinct reference aliases are independent authority claims. The
        # old first-success loop could auto-select whichever parameter the
        # server happened to honor first. Reject the ambiguous contract before
        # even fetching its upgrade control.
        if len(refs) > 1:
            return self._ws_decline(f"ambiguous: {len(refs)} stream/event/channel references; the class "
                                    "reads only one exact reference")
        if not refs:
            return None
        if route is None:
            return self._ws_decline("the clue names no feature_route the route guard accepts")
        if not self._route_allowed(route):
            return self._ws_decline("proof_hunt's route guard refused the feature route")
        tries = []
        for key, value in refs:
            stem = re.sub(r"_reference$", "", key, flags=re.I)
            for param in (stem, key):
                path = _with_query(route, param, value)
                if path and path not in tries and self._route_allowed(path):
                    tries.append(path)
        if not tries:
            return self._ws_decline("no safe query form for the reference")
        control = _preloaded(self.preloaded, route) or self._call("get", route, "upgrade-control")
        if isinstance(control, dict):
            self.baselines.append(_baseline_text(control))
        headers = _headers(control)
        upgrade_header = headers.get("upgrade", "").lower() == "websocket"
        self.websocket["control"] = control.get("status") if isinstance(control, dict) else None
        if not (isinstance(control, dict) and control.get("status") == 426
                and (upgrade_header or WS_REQUIRED.search(_text(control)))):
            got = control.get("status") if isinstance(control, dict) else None
            return self._ws_decline(f"the feature route answered {got if got is not None else 'nothing'}, "
                                    "not a 426 WebSocket upgrade control")
        for path in tries[:4]:
            if not self._may_send():
                return self._ws_decline(f"stopped before every query form was tried ({self.stopped})")
            self.terminal = True
            self.protocol = "websocket"
            response = self._call("websocket", path, "server-first-frame")
            query = urllib.parse.urlsplit(path).query.split("=", 1)[0]
            status = response.get("status") if isinstance(response, dict) else None
            self.websocket["tries"].append({"query": query, "status": status})
            if not isinstance(response, dict) or response.get("status") != 101:
                if isinstance(response, dict):
                    # A refusal's own bytes are a control: a proof-shaped decoy in a 403 body can never be
                    # banked from a later 101 on another query form.
                    self.baselines.append(_baseline_text(response))
                continue
            raw_messages = response.get("websocket_messages")
            if isinstance(raw_messages, (list, tuple)):
                if len(raw_messages) > 16 or any(not isinstance(value, str)
                                                 for value in raw_messages):
                    self.stopped = "ambiguous WebSocket message set"
                    return None
                messages = [str(value)[:MAX_BODY] for value in raw_messages[:16]
                            if isinstance(value, str)]
            else:
                # Compatibility clients may expose one server-first message as
                # body only. Treat it as one coherent application message,
                # never as newline-joined sibling evidence.
                messages = [_text(response)] if _text(response) else []
            autos, ambiguous = [], False
            for message in messages:
                local_response = dict(response)
                local_response["body"] = message.encode("utf-8", "strict")
                local_response["websocket_messages"] = [message]
                doc = _json(local_response)
                local = (json.dumps(doc, separators=(",", ":"), default=str)
                         if isinstance(doc, dict) else message)
                outcome = self._outcome(local_response)
                effect = bool(WS_EFFECT.search(local))
                # Every complete server-first message is an independent
                # sibling. Only an effect-bearing message may establish
                # success, but proof/flag/evidence in any other message makes
                # the choice ambiguous instead of disappearing.
                if not effect:
                    if outcome.get("candidates") or outcome.get("wire"):
                        ambiguous = True
                        self.candidates.extend(
                            str(value)[:256] for value in outcome.get("wire") or [])
                    continue
                if outcome.get("auto"):
                    autos.append(str(outcome["auto"]))
                if outcome.get("candidates") or (not outcome.get("auto") and outcome.get("wire")):
                    ambiguous = True
            unique = list(dict.fromkeys(autos))
            if len(unique) == 1 and not ambiguous:
                self.success = True
                self.websocket.update(outcome="read", reason=f"?{query} answered 101 with one proof")
                return unique[0]
            if unique or ambiguous:
                self.success = True
                self.websocket.update(outcome="ambiguous",
                                      reason=f"?{query} answered 101 but its frames held no single "
                                             "effect-bearing proof (candidate surfaced, not banked)")
                return None
        tried = ", ".join(f"?{t['query']} -> {t['status'] if t['status'] is not None else 'no answer'}"
                          for t in self.websocket["tries"])
        return self._ws_decline(f"no upgrade yielded an effect-bearing proof ({tried})")

    def _ws_decline(self, reason):
        """Record why the server-first WebSocket class did not read, and return None."""
        if self.websocket is None:
            self.websocket = {"route": None, "references": [], "tries": []}
        self.websocket.update(outcome="declined", reason=str(reason)[:300])
        return None

    def _sse(self, clues):
        prose = json.dumps(clues, separators=(",", ":"), default=str)[:50_000]
        explicit = any(key in clues for key in ("sse_route", "event_stream_route"))
        routes = []
        for key in ("sse_route", "event_stream_route", "stream_route", "feature_route"):
            if key not in clues or (key == "feature_route" and not SSE_WORDS.search(prose)):
                continue
            candidate = _route(clues.get(key), self.url)
            if candidate is None:
                return None
            if candidate not in routes:
                routes.append(candidate)
        route = routes[0] if len(routes) == 1 else None
        if (route is None or not (explicit or SSE_WORDS.search(prose))
                or not self._route_allowed(route)):
            return None
        self.terminal = True
        self.protocol = "sse"
        response = self._call("sse", route, "first-event")
        headers = _headers(response)
        if not (isinstance(response, dict) and isinstance(response.get("status"), int)
                and 200 <= response["status"] < 300
                and headers.get("content-type", "").lower().split(";", 1)[0].strip() == "text/event-stream"):
            return None
        event = response.get("sse_event") if isinstance(response.get("sse_event"), dict) else {}
        data = event.get("data")
        if not isinstance(data, str):
            return None
        payoff = dict(response)
        payoff["body"] = data.encode("utf-8", "replace")
        outcome = self._outcome(payoff)
        if outcome.get("auto"):
            self.success = True
            return outcome["auto"]
        if outcome.get("candidates") or outcome.get("wire"):
            self.success = True
        return None

    def _route_allowed(self, route):
        """Apply proof_hunt's full trusted-route policy in addition to this peer's local guard."""
        gate = self.ctx.get("route_allowed")
        if not callable(gate):
            return True
        try:
            return bool(gate(route))
        except Exception:
            self.stopped = self.stopped or "caller route guard failed"
            return False

    def run(self):
        off = disabled_reason()
        if off is not None:
            self.stopped = f"off: {off}"
            return None
        if self.client is None or self.max_requests <= 0:
            self.stopped = self.stopped or ("unavailable: no request budget" if self.client is not None
                                            else "unavailable: no scoped client")
            return None
        clues = _json(_preloaded(self.preloaded, "/api/clues"))
        if not isinstance(clues, dict):
            self.stopped = "no clue document"
            return None
        proof, present = self._client_websocket_stateful(clues)
        if present:
            return proof
        proof, present = self._client_websocket(clues)
        if present:
            return proof
        proof, present = self._client_sse(clues)
        if present:
            return proof
        proof = self._websocket(clues)
        if proof or self.terminal:
            return proof
        return self._sse(clues)

    def result(self):
        baseline_proofs = list(dict.fromkeys(
            match.group(0) for text in self.baselines for match in PAYOFF_SEEN.finditer(str(text or ""))
        ))[:24]
        return {"class": "realtime_read", "protocol": self.protocol,
                "requests": self.requests, "posts": 0, "success": self.success,
                "terminal": self.terminal, "candidates": list(dict.fromkeys(self.candidates))[:12],
                "baseline_proofs": baseline_proofs,
                "responses": self.responses[:12], "stopped": self.stopped,
                "websocket": (dict(self.websocket, tries=list(self.websocket.get("tries") or [])[:4])
                              if isinstance(self.websocket, dict) else None)}


def _publish(reader, target, ctx):
    summary = reader.result()
    aid = str(target.get("answer_id") or "target") if isinstance(target, dict) else "target"
    sink = ctx.get("result_sink") if isinstance(ctx, dict) else None
    if isinstance(sink, dict):
        sink[aid] = summary
    evidence = ctx.get("evidence") if isinstance(ctx, dict) else None
    if isinstance(evidence, list) and summary.get("protocol"):
        line = _web.safe_display_text(
            f"WEB REALTIME {summary['protocol']}: requests={summary['requests']} "
            f"success={summary['success']} terminal={summary['terminal']}", 500)
        if line not in evidence:
            evidence.append(line)


def solve(target, ctx=None):
    ctx = dict(ctx or {})
    reader = _Reader(target, ctx)
    proof = None
    try:
        proof = reader.run()
    except Exception as exc:
        reader.stopped = reader.stopped or f"error: {type(exc).__name__}"
    _publish(reader, target, ctx)
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
