#!/usr/bin/env python3
"""Descriptor-driven API invocation engine (AsyncAPI / OpenRPC / SOAP / gRPC-web) (B-123).

The descriptor recon engines (:mod:`descriptor_inventory` for AsyncAPI/OpenRPC,
:mod:`service_descriptors` for WSDL/protobuf/gRPC-web) parse descriptors *recon-only*: every
operation they surface carries ``requestable=False`` and nothing is ever connected, sent or called.
This engine takes one such *already-inventoried, exact-linked* descriptor and drives exactly
**one bounded read-only operation** against the descriptor's own same-origin server, then surfaces the
proof.  It is the gated reader that turns descriptor recon into a solve path -- never a cold Layer-1
move.

Hard invariants (the blocker in the spec: invocation is a state action with no universal safe
default, so it stays a *gated* reader):

* **Gated off by default.**  :func:`disabled_reason` fails closed: the engine does nothing unless the
  player explicitly turns it on (``CTF_WEB_APICALL=on`` or a ``_web_api_invoke.on`` file in the event
  workdir).  Recon stays cold; invocation is an opt-in.
* **Read-only only; writes blocked.**  :func:`classify_operation` labels the chosen operation
  ``read`` / ``write`` / ``unknown`` from the descriptor's own structure (AsyncAPI by its *action*,
  read per the descriptor's spec version; the RPC/SOAP families by a verb-first method name).  Only a
  provably-``read`` operation is ever invoked; a ``write`` or ``unknown`` operation is *surfaced* for
  the model and never sent.
* **Same-origin / on-host only.**  The target used is the descriptor's own ``same_origin`` server,
  routed through :func:`web.safe_same_origin_route`; an external / off-host server is refused, never
  contacted.
* **One bounded request.**  A single request through the scope-locked :class:`web.WebClient`, no
  retry, no argument fabrication: an operation whose required inputs cannot be filled from an
  enumerated-safe value in the descriptor is surfaced, not guessed.

Interface (the same peer contract as the cold readers and the proof-chain harness it composes with)::

    solve(target, ctx) -> proof | None

``ctx`` supplies the scope-locked ``client`` (when ``proof_chain`` dispatches an ``api_invoke`` layer
to this engine the client is its chain-injecting wrapper), cached ``preloaded`` discovery responses,
an absolute ``deadline``, a ``max_requests`` budget, a ``stop`` event, an optional ``route_allowed``
guard and a ``result_sink``.  This module opens no socket of its own and executes no challenge code.

The descriptor and the single operation to drive are read from the target's duplicate-safe
``/api/clues`` JSON under an ``api_invoke`` object carrying exactly one descriptor form::

    {"api_invoke": {"descriptor": <inventory record>, "operation": "<operation_id|name|path>"}}
    {"api_invoke": {"document": <AsyncAPI/OpenRPC JSON object>, "path": "/asyncapi.json", ...}}
    {"api_invoke": {"source": "<WSDL / .proto / *_grpc_web_pb.js text>", "path": "/svc.wsdl", ...}}

A ``document`` or ``source`` is re-parsed here by the recon engine itself
(:func:`descriptor_inventory.parse_document` / :func:`service_descriptors.parse`) against this
engine's own target URL, so the same-origin flags are computed, not trusted.  A pre-parsed
``descriptor`` record is accepted only after a shape check (:func:`record_problem`) refuses a
contradictory or mistyped record (for instance an off-host server row that still carries an endpoint).
"""

from __future__ import annotations

import base64
import json
import re
import sys
import time
import urllib.parse
import xml.etree.ElementTree as _ET
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import env as ctf_env, paths as ctf_paths, flagfmt  # noqa: F401 -- flagfmt via peers
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import env as ctf_env, paths as ctf_paths, flagfmt  # noqa: F401

HERE = Path(__file__).resolve().parent
TOOLKITS = HERE.parent / "toolkits"
for _path in (TOOLKITS, HERE):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import web as _web  # noqa: E402 -- shared scope/route policy
import security_json as _security_json  # noqa: E402 -- duplicate-key rejecting JSON
import api_protocols as _api  # noqa: E402 -- inert gRPC-web frame builder
import descriptor_inventory as _di  # noqa: E402 -- AsyncAPI/OpenRPC recon normalizer (re-parse)
import service_descriptors as _sd  # noqa: E402 -- WSDL/protobuf/gRPC-web recon parser (re-parse)

# Optional peers.  A failed import is never silent: the exception type is kept and every path that
# needs the peer refuses with a named reason that carries it (Rule 6).
try:
    import forge_event as _proofs  # noqa: E402 -- shared proof/baseline policy
    _PROOFS_IMPORT_ERROR = None
except Exception as _exc:  # pragma: no cover - exercised by monkeypatching _proofs
    _proofs = None
    _PROOFS_IMPORT_ERROR = type(_exc).__name__
try:
    import realtime_read as _realtime_read  # noqa: E402 -- owns the player's real-time off switch
    _REALTIME_IMPORT_ERROR = None
except Exception as _exc:  # pragma: no cover - exercised by monkeypatching _realtime_read
    _realtime_read = None
    _REALTIME_IMPORT_ERROR = type(_exc).__name__


OFF_FILE = "_web_api_invoke.on"
ENV_SWITCH = "CTF_WEB_APICALL"

DEFAULT_SECONDS = 20.0
DEFAULT_MAX_REQUESTS = 3
REQUEST_TIMEOUT = 6.0
DEADLINE_PAD = 0.3
MAX_BODY = 65_536
MAX_REQUEST_BYTES = 16 * 1024
MAX_OPERATIONS = 512
MAX_PARAM_VALUE = 256
MAX_WS_FRAMES = 4
MAX_GRPC_FRAMES = 16
MAX_XML_NODES = 2_000
MAX_SOURCE_BYTES = 512 * 1024

# A descriptor record kind this engine knows how to invoke.
_KINDS = frozenset(("openrpc", "asyncapi", "wsdl", "protobuf", "grpc-web"))

# --------------------------------------------------------------------------------------------------
# Verb-first read / write lexicon for RPC- and SOAP-style operation names.
#
# Only the FIRST token can make a name ``read``, and only when it is a plain fetch verb.  A write is
# recognised three ways: a strong state-changing verb anywhere in the name; a leading verb that is
# state-changing as a verb but usually a noun later in a name (``openSession`` vs ``getOpenTickets``);
# or any verb after a conjunction (``getAndIncrement``).  A conjunction without a recognised write
# verb is ``unknown``: a chained name does two things and the engine cannot prove the second is a read.
# Ambiguous fetch-or-act verbs (resolve, report, load, poll, watch) are deliberately not read verbs.
# --------------------------------------------------------------------------------------------------
_READ_VERBS = frozenset((
    "get", "list", "read", "fetch", "query", "describe", "search", "find", "lookup",
    "status", "info", "version", "health", "healthcheck", "ping", "echo", "show", "view", "count",
    "exists", "has", "stat", "whoami", "introspect", "capabilities", "metadata", "retrieve",
    "summary", "preview", "peek",
))
_WRITE_VERBS = frozenset((
    "set", "create", "update", "delete", "remove", "add", "write", "send", "publish", "push",
    "exec", "execute", "invoke", "transfer", "pay", "charge", "purchase", "submit", "insert", "drop",
    "truncate", "reset", "revoke", "grant", "upload", "modify", "patch", "edit", "save", "enqueue",
    "dispatch", "trigger", "restart", "reboot", "shutdown", "kill", "login", "logout", "signin",
    "signout", "register", "unregister", "enable", "disable", "activate", "deactivate", "approve",
    "reject", "cancel", "confirm", "generate", "rotate", "provision", "deploy", "apply", "sync",
    "flush", "clear", "purge", "destroy", "wipe", "rename", "mutate", "mutation",
    # Side effects that are not CRUD words: counters, tokens, money, flags, moderation, queues.
    "increment", "decrement", "incr", "decr", "bump", "burn", "ack", "acknowledge", "nack", "consume",
    "redeem", "refund", "withdraw", "deposit", "mint", "toggle", "upsert", "append", "prepend",
    "subscribe", "unsubscribe", "ban", "unban", "kick", "unlock", "unlink", "unfollow", "unshare",
    "unarchive", "restore", "buy", "sell", "mark", "unmark",
    "assign", "unassign", "attach", "detach", "refill", "topup", "erase", "suspend", "uninstall",
    "migrate", "rollback", "notify",
))
# Verbs that are state-changing as a leading verb but are usually nouns later in a name
# (``openSession`` is a write; ``getOpenTickets`` / ``getCommit`` / ``getVoteCount`` are reads).
_LEADING_WRITE_VERBS = frozenset((
    "order", "issue", "post", "call", "run", "start", "stop", "store", "copy", "move", "change",
    "open", "close", "lock", "link", "share", "like", "follow", "book", "reserve", "use", "put",
    "import", "claim", "join", "leave", "invite", "merge", "split", "replace", "touch", "pop", "take",
    "give", "accept", "decline", "award", "vote", "spend", "swap", "seed", "install", "commit",
    "checkout", "verify", "validate", "archive", "log", "track", "record", "emit", "fire",
    "schedule",
))
_CONJUNCTIONS = frozenset(("and", "or", "then", "plus", "also", "after", "before", "while", "else"))

_TOKEN = re.compile(r"[A-Za-z][a-z0-9]*|[A-Z]+(?![a-z])|[0-9]+")


# ======================================================================================
#  1. Gate (fail-closed; recon-first, invocation opt-in)
# ======================================================================================
def disabled_reason():
    """None when descriptor invocation may run, else the named reason it is off (never silent).

    Fail-closed: unlike the cold readers, descriptor *invocation* is a state action, so it is off by
    default and must be turned on deliberately -- ``CTF_WEB_APICALL`` truthy, or a ``_web_api_invoke.on``
    marker file in the event workdir.  Any ambiguity (unresolvable workdir) stays off and says why.
    """
    raw = ctf_env.get(ENV_SWITCH)
    if raw is not None:
        if raw.strip().lower() in ("on", "1", "true", "yes", "enable", "enabled"):
            return None
        return (f"{ENV_SWITCH}={raw.strip()[:16]} does not enable descriptor invocation "
                "(recon-first is the default; set it to 'on' to invoke)")
    try:
        root = ctf_paths.workdir()
    except Exception as exc:
        return (f"descriptor invocation is gated off by default and the event workdir could not be "
                f"resolved ({type(exc).__name__}), so the {OFF_FILE} marker cannot be checked; set "
                f"{ENV_SWITCH}=on to invoke")
    try:
        if (root / OFF_FILE).exists():
            return None
    except OSError as exc:
        return (f"descriptor invocation is gated off by default and the {OFF_FILE} marker could not "
                f"be checked ({type(exc).__name__}); set {ENV_SWITCH}=on to invoke")
    return (f"descriptor invocation is gated off by default (recon-first); set {ENV_SWITCH}=on or "
            f"create {OFF_FILE} in the event workdir to invoke one bounded read-only operation")


def enabled():
    return disabled_reason() is None


# ======================================================================================
#  2. Read-only classification (the safety heart)
# ======================================================================================
def _name_tokens(name):
    if not isinstance(name, str):
        return ()
    # The RPC method path (``/pkg.Svc/Method``) and dotted names reduce to their final element.
    tail = name.replace("\\", "/").split("/")[-1].split(".")[-1]
    return tuple(t.lower() for t in _TOKEN.findall(tail))


def _verb_verdict(name):
    """Classify a verb-first operation name as read / write / unknown.

    ``read`` only when the first token is a fetch verb, no token is a state-changing verb, and the
    name chains no second action.  Everything else is ``write`` (a side-effect verb was seen) or
    ``unknown`` (nothing proves the call is read-only).
    """
    tokens = _name_tokens(name)
    if not tokens:
        return "unknown", "operation name is empty or unparseable"
    # A strong write verb anywhere in the name is disqualifying.
    for token in tokens:
        if token in _WRITE_VERBS:
            return "write", f"name token {token!r} is a state-changing verb"
    if tokens[0] in _LEADING_WRITE_VERBS:
        return "write", f"name begins with the state-changing verb {tokens[0]!r}"
    for index, token in enumerate(tokens):
        if token in _CONJUNCTIONS:
            following = tokens[index + 1] if index + 1 < len(tokens) else None
            if following in _LEADING_WRITE_VERBS:
                return "write", f"name chains the state-changing verb {following!r} after {token!r}"
            return "unknown", (f"name chains a second action after {token!r}; a chained call cannot "
                               "be proven read-only")
    if tokens[0] in _READ_VERBS:
        return "read", f"name begins with the read verb {tokens[0]!r}"
    return "unknown", f"leading token {tokens[0]!r} is not a recognised read verb"


def _asyncapi_major(operation):
    spec = str(operation.get("spec_version") or "").strip().lower()
    match = re.fullmatch(r"asyncapi-(\d+)(?:\.\d+){0,2}", spec)
    return int(match.group(1)) if match else None


def classify_operation(kind, operation):
    """Return ``(verdict, reason)`` for one inventoried operation; ``verdict`` in read/write/unknown.

    AsyncAPI is classified by its *action*, read per the record's ``spec_version``, because a channel
    name carries no verb and the two major versions describe opposite sides of the channel:

    * v2 ``subscribe`` -- the application publishes, a client subscribes and only receives: read.
      v2 ``publish`` -- a client publishes to the application: write.
    * v3 actions describe what the *application* does.  v3 ``send`` -- the application sends, a client
      only receives: read.  v3 ``receive`` -- the application receives, so a client must send: write.

    A v2 word in a v3 record (or the reverse), or an action with no spec version, is ``unknown``.
    The RPC/SOAP families are classified by a verb-first operation name.  A gRPC/protobuf method that
    streams *from the client* is a write regardless of name.  Only a ``read`` verdict is ever invoked.
    """
    if not isinstance(operation, dict):
        return "unknown", "operation is not a descriptor record"
    if kind == "asyncapi":
        action = str(operation.get("action") or "").strip().lower()
        major = _asyncapi_major(operation)
        if action in ("subscribe", "publish"):
            if major != 2:
                return "unknown", (f"AsyncAPI v2 action {action!r} in a record whose spec version is "
                                   f"{operation.get('spec_version')!r}; direction is ambiguous")
            if action == "subscribe":
                return "read", "AsyncAPI v2 'subscribe': the application publishes, a client receives (read)"
            return "write", "AsyncAPI v2 'publish': a client publishes to the application (write)"
        if action in ("send", "receive"):
            if major != 3:
                return "unknown", (f"AsyncAPI v3 action {action!r} in a record whose spec version is "
                                   f"{operation.get('spec_version')!r}; direction is ambiguous")
            if action == "send":
                return "read", "AsyncAPI v3 'send': the application sends, a client only receives (read)"
            return "write", "AsyncAPI v3 'receive': the application receives, so a client must send (write)"
        return "unknown", f"AsyncAPI action {action!r} is not a recognised read/write action"
    # The RPC/SOAP families: client-streaming is a push regardless of the name.
    if operation.get("client_streaming"):
        return "write", "method streams from the client (a push); never invoked read-only"
    name = operation.get("operation_id") or operation.get("name") or operation.get("path")
    return _verb_verdict(name)


# ======================================================================================
#  3. Descriptor intake, record shape check, operation selection and same-origin resolution
# ======================================================================================
def _descriptor_kind(descriptor):
    if not isinstance(descriptor, dict):
        return None
    kind = descriptor.get("kind")
    return kind if isinstance(kind, str) and kind in _KINDS else None


def _operations(descriptor):
    ops = descriptor.get("operations")
    if isinstance(ops, list):
        return [op for op in ops[:MAX_OPERATIONS] if isinstance(op, dict)]
    # service_descriptors records carry rpcs / operations under family keys.
    collected = []
    for key in ("rpcs", "operations"):
        rows = descriptor.get(key)
        if isinstance(rows, list):
            collected.extend(op for op in rows[:MAX_OPERATIONS] if isinstance(op, dict))
    return collected[:MAX_OPERATIONS]


def record_problem(descriptor):
    """Name why a pre-parsed descriptor record cannot be trusted, or return None.

    The recon engines never emit these shapes; a record that has them was forged or corrupted, and the
    classification and same-origin fields it carries would otherwise be taken on trust.
    """
    if not isinstance(descriptor, dict):
        return "descriptor record is not an object"
    servers = descriptor.get("servers")
    if servers is not None and not isinstance(servers, list):
        return "descriptor servers is not a list"
    for row in servers or []:
        if not isinstance(row, dict):
            return "a descriptor server row is not an object"
        if "same_origin" in row and not isinstance(row["same_origin"], bool):
            return "a server row's same_origin flag is not a boolean"
        if row.get("same_origin") is not True and "endpoint" in row:
            return "an off-host server row carries an endpoint (contradictory record)"
    addresses = descriptor.get("addresses")
    if addresses is not None and not isinstance(addresses, list):
        return "descriptor addresses is not a list"
    for row in addresses or []:
        if not isinstance(row, dict):
            return "a SOAP address row is not an object"
        if "off_origin" in row and not isinstance(row["off_origin"], bool):
            return "a SOAP address off_origin flag is not a boolean"
        if row.get("off_origin") is True and row.get("same_origin") is True:
            return "a SOAP address is both off-origin and same-origin (contradictory record)"
    for op in _operations(descriptor):
        for key in ("client_streaming", "server_streaming", "address_known"):
            if key in op and not isinstance(op[key], bool):
                return f"an operation's {key} flag is not a boolean"
        for key in ("action", "spec_version", "name", "operation_id", "path", "channel", "input"):
            if key in op and op[key] is not None and not isinstance(op[key], str):
                return f"an operation's {key} is not a string"
        if "input_fields" in op and not isinstance(op["input_fields"], list):
            return "an operation's input_fields is not a list"
        if "params" in op and not isinstance(op["params"], list):
            return "an operation's params is not a list"
    return None


def descriptor_from_spec(spec, base_url):
    """Return ``(descriptor, reason)`` from an ``api_invoke`` clue (exactly one descriptor form).

    ``document`` (an AsyncAPI/OpenRPC mapping) and ``source`` (WSDL / .proto / gRPC-web JS text) are
    re-parsed here by the recon engines against ``base_url``; a pre-parsed ``descriptor`` must pass
    :func:`record_problem`.
    """
    forms = [key for key in ("descriptor", "document", "source") if key in spec]
    if len(forms) != 1:
        return None, ("api_invoke must carry exactly one of descriptor / document / source "
                      f"(found {forms or 'none'})")
    path = spec.get("path")
    path = path if isinstance(path, str) and path else "<descriptor>"
    if forms == ["document"]:
        record = _di.parse_document(spec["document"], base_url=base_url, path=path)
        if record is None:
            return None, "the api_invoke document is not an AsyncAPI/OpenRPC descriptor the recon engine accepts"
        return record, None
    if forms == ["source"]:
        raw = spec["source"]
        if not isinstance(raw, str):
            return None, "the api_invoke source is not text"
        data = raw.encode("utf-8", "strict")
        if len(data) > MAX_SOURCE_BYTES:
            return None, "the api_invoke source exceeds the descriptor size bound"
        record = _sd.parse(data, path=path, base_url=base_url)
        if record is None:
            return None, "the api_invoke source is not a WSDL/protobuf/gRPC-web descriptor the recon engine accepts"
        return record, None
    record = spec["descriptor"]
    problem = record_problem(record)
    if problem is not None:
        return None, f"pre-parsed descriptor record refused: {problem}"
    return record, None


def _op_identity(op):
    for key in ("operation_id", "name", "path", "channel"):
        value = op.get(key)
        if isinstance(value, str) and value:
            yield value


def select_operation(descriptor, selector):
    """Find the single inventoried operation named by ``selector`` (exact, unambiguous), or None.

    Returns ``(operation, reason)``; ``operation`` is None when the selector resolves to zero or more
    than one operation -- the engine never guesses which operation the player meant.
    """
    if not isinstance(selector, str) or not selector.strip():
        return None, "no operation selector supplied"
    want = selector.strip()
    matches = [op for op in _operations(descriptor) if want in set(_op_identity(op))]
    if not matches:
        return None, f"selector {want!r} matched no inventoried operation"
    if len(matches) > 1:
        return None, f"selector {want!r} is ambiguous ({len(matches)} operations); refusing to guess"
    return matches[0], "exact operation match"


def _servers(descriptor):
    servers = descriptor.get("servers")
    return [s for s in servers if isinstance(s, dict)] if isinstance(servers, list) else []


def _safe_route(value, base_url):
    return _web.safe_same_origin_route(value, base_url, allow_query=False,
                                       guard_query=True, max_bytes=1024)


OFF_HOST_SERVER = "the descriptor's server(s) are external/off-host; refusing to contact one"
OFF_HOST_SOAP = "the WSDL SOAP address(es) are external/off-host; refusing to contact one"


def same_origin_endpoint(descriptor, base_url, operation=None):
    """Resolve the same-origin endpoint path to invoke, or ``(None, reason)``.

    An endpoint is taken only from a ``same_origin`` server the descriptor itself inventoried (or,
    for gRPC-web, from the operation's own exact path; for SOAP, from a WSDL address not flagged
    off-origin), routed through the shared same-origin guard.  An external / off-host server is
    refused; this engine never contacts one.
    """
    # gRPC-web methods carry an exact same-origin-rooted path (``/pkg.Svc/Method``) on the operation.
    if operation is not None:
        op_path = operation.get("path")
        if isinstance(op_path, str) and op_path.startswith("/"):
            route = _safe_route(op_path, base_url)
            if route is not None:
                return route, "operation path (same origin)"
    servers = _servers(descriptor)
    if not servers:
        # SOAP WSDL records keep their endpoints under ``addresses`` (``resolved``/``location``
        # plus an ``off_origin`` flag).  A flagged address is never used, and the same-origin guard
        # is authoritative over an unflagged one.
        off_host = False
        for row in descriptor.get("addresses") or []:
            if not isinstance(row, dict):
                continue
            if row.get("off_origin"):
                off_host = True
                continue
            candidate = row.get("resolved") or row.get("location")
            if not isinstance(candidate, str):
                continue
            route = _safe_route(candidate, base_url)
            if route is not None:
                return route, "same-origin SOAP address"
            off_host = True  # an unflagged address the same-origin guard still refused
        if off_host:
            return None, OFF_HOST_SOAP
        return None, "descriptor inventoried no same-origin server or SOAP address"
    off_host = False
    for row in servers:
        if not row.get("same_origin"):
            off_host = True
            continue
        endpoint = row.get("endpoint")
        if isinstance(endpoint, str):
            route = _safe_route(endpoint, base_url)
            if route is not None:
                return route, "same-origin server"
    if off_host:
        return None, OFF_HOST_SERVER
    return None, "no same-origin server endpoint could be resolved from the descriptor"


_STREAM_BY_PROTOCOL = {"ws": "websocket", "wss": "websocket",
                       "http": "sse", "https": "sse", "sse": "sse"}


def asyncapi_channel(descriptor, base_url, operation):
    """Resolve the AsyncAPI channel to read: ``(route, stream, reason)``; ``route`` None on refusal.

    The route is the selected operation's own channel address joined onto the path of the
    descriptor's same-origin server; ``stream`` is ``websocket`` (ws/wss server) or ``sse``
    (http/https/sse server).  A templated channel (``{param}``) is refused -- no parameter is ever
    fabricated -- and more than one distinct same-origin reading is refused as ambiguous.
    """
    channel = operation.get("channel") if isinstance(operation, dict) else None
    if not isinstance(channel, str) or not channel.strip() or channel.strip() == "-":
        return None, None, "the AsyncAPI operation names no channel address"
    channel = channel.strip()
    known = operation.get("address_known")
    v3 = str(operation.get("spec_version") or "").startswith("asyncapi-3")
    if known is False or (v3 and known is not True):
        # An AsyncAPI v3 channel whose address is null (or absent) is dynamic/unknown; the record's
        # ``channel`` then carries only the channel id.  Joining that id onto the server path would
        # invent a route, so the operation is surfaced instead of read.
        return None, None, (f"channel {channel!r} has no known address (AsyncAPI v3 null or absent "
                            "address: dynamic/unknown); refusing to fabricate a route from the "
                            "channel id")
    if "{" in channel or "}" in channel:
        return None, None, (f"channel {channel!r} is templated; refusing to fabricate a channel "
                            "parameter")
    if "?" in channel or "#" in channel or "://" in channel:
        return None, None, f"channel {channel!r} is not a plain path address"
    servers = _servers(descriptor)
    if not servers:
        return None, None, "the AsyncAPI descriptor inventoried no server"
    same = [row for row in servers if row.get("same_origin") is True]
    if not same:
        return None, None, OFF_HOST_SERVER
    picks, problems = [], []
    for row in same:
        protocol = str(row.get("protocol") or "").strip().lower()
        stream = _STREAM_BY_PROTOCOL.get(protocol)
        if stream is None:
            problems.append(f"server protocol {protocol or 'unstated'!r} has no bounded read transport")
            continue
        endpoint = row.get("endpoint")
        if not isinstance(endpoint, str) or "?" in endpoint:
            problems.append("same-origin server has no plain endpoint path")
            continue
        base_path = (urllib.parse.urlsplit(endpoint).path or "/").rstrip("/")
        joined = f"{base_path}/{channel.lstrip('/')}" if channel.strip("/") else (base_path or "/")
        route = _safe_route(joined, base_url)
        if route is None:
            problems.append(f"channel route {joined!r} fails the same-origin guard")
            continue
        if (route, stream) not in picks:
            picks.append((route, stream))
    if len(picks) > 1:
        return None, None, (f"{len(picks)} same-origin servers give different channel readings; "
                            "refusing to guess")
    if not picks:
        return None, None, "; ".join(problems) or "no same-origin channel route"
    route, stream = picks[0]
    return route, stream, f"channel {channel!r} on a same-origin {stream} server"


def _destructive(route):
    try:
        path = urllib.parse.urlsplit(route).path or "/"
        for layer in _web.canonical_route_layers(path, max_bytes=1024) or ():
            if _web.route_has_destructive_action(layer):
                return True
    except Exception:
        return True
    return False


# ======================================================================================
#  4. Build one bounded invocation (reuse api_protocols frame builders)
# ======================================================================================
def _safe_param_value(values):
    """One enumerated-safe scalar for a required parameter, or None when none can be chosen."""
    if not isinstance(values, (list, tuple)):
        return None
    scalars = [v for v in values if isinstance(v, (str, int, float)) and not isinstance(v, bool)]
    if len(scalars) != 1:
        return None  # zero, or an ambiguous choice: never fabricate or pick arbitrarily.
    value = scalars[0]
    if isinstance(value, str) and len(value.encode("utf-8", "replace")) > MAX_PARAM_VALUE:
        return None
    return value


def _json_rpc_params(operation):
    """Build a safe JSON-RPC params object, or ``(None, reason)`` when a required arg is unsafe."""
    params = operation.get("params")
    if not isinstance(params, list) or not params:
        return {}, None  # no parameters: the safest read call.
    out = {}
    for param in params:
        if not isinstance(param, dict):
            continue
        name = param.get("name")
        if not isinstance(name, str) or not name:
            continue
        if not param.get("required"):
            continue  # optional parameters are omitted; a read call needs none.
        value = _safe_param_value(param.get("values"))
        if value is None:
            return None, (f"required parameter {name!r} has no single enumerated-safe value; "
                          "refusing to fabricate an argument")
        out[name] = value
    return out, None


def build_invocation(kind, operation, route, *, stream=None):
    """Build one bounded, read-only wire request plan, or ``(None, reason)``.

    Returns a plan dict ``{transport, method, route, headers, body}`` (``transport`` is ``http`` for
    the RPC/SOAP families and ``realtime`` for AsyncAPI channels, which also carry ``stream``).  No
    argument is ever invented: an operation whose required inputs cannot be filled from an
    enumerated-safe descriptor value is refused here.
    """
    if kind == "openrpc":
        name = operation.get("name") or operation.get("operation_id")
        if not isinstance(name, str) or not name:
            return None, "OpenRPC method has no name"
        params, reason = _json_rpc_params(operation)
        if params is None:
            return None, reason
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": name, "params": params},
                          separators=(",", ":"), ensure_ascii=True).encode("ascii")
        if len(body) > MAX_REQUEST_BYTES:
            return None, "JSON-RPC request exceeds the request bound"
        return ({"transport": "http", "method": "POST", "route": route, "body": body,
                 "headers": {"Content-Type": "application/json", "Accept": "application/json"}},
                None)
    if kind in ("protobuf", "grpc-web"):
        # Only a method whose request message carries no field can be invoked with an empty frame;
        # this engine never fabricates protobuf field bytes.
        input_name = operation.get("input")
        if not _empty_message(input_name, operation):
            return None, (f"gRPC method input {input_name!r} is not a known-empty message; refusing "
                          "to fabricate protobuf fields")
        frame = _api.build_grpc_web_frame(b"")
        encoded = base64.b64encode(frame)
        if len(encoded) > MAX_REQUEST_BYTES:
            return None, "gRPC-web request exceeds the request bound"
        return ({"transport": "http", "method": "POST", "route": route, "body": encoded,
                 "headers": {"Content-Type": "application/grpc-web-text", "X-Grpc-Web": "1",
                             "Accept": "application/grpc-web-text"}},
                None)
    if kind == "wsdl":
        name = operation.get("name") or operation.get("operation_id")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}", name or ""):
            return None, "SOAP operation name is missing or not a safe element name"
        namespace = operation.get("namespace") or operation.get("target_namespace") or ""
        ns_attr = f' xmlns="{_xml_escape(namespace)}"' if isinstance(namespace, str) and namespace else ""
        body = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
            f'<soap:Body><{name}{ns_attr}/></soap:Body></soap:Envelope>'
        ).encode("utf-8")
        if len(body) > MAX_REQUEST_BYTES:
            return None, "SOAP request exceeds the request bound"
        action = operation.get("soap_action")
        headers = {"Content-Type": "text/xml; charset=utf-8"}
        headers["SOAPAction"] = f'"{action}"' if isinstance(action, str) and _header_safe(action) else '""'
        return ({"transport": "http", "method": "POST", "route": route, "body": body,
                 "headers": headers}, None)
    if kind == "asyncapi":
        if stream not in ("websocket", "sse"):
            return None, f"AsyncAPI channel read needs a websocket or sse stream, not {stream!r}"
        return ({"transport": "realtime", "stream": stream, "method": "GET", "route": route,
                 "body": None, "headers": {}}, None)
    return None, f"descriptor kind {kind!r} is not invocable"


def _empty_message(input_name, operation):
    if not isinstance(input_name, str):
        return False
    tail = input_name.split(".")[-1]
    if tail in ("Empty",) or input_name in ("google.protobuf.Empty",):
        return True
    # An explicit descriptor hint that the input message has no fields.
    fields = operation.get("input_fields")
    return isinstance(fields, list) and len(fields) == 0


def _xml_escape(value):
    return (str(value).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _header_safe(value):
    return isinstance(value, str) and bool(re.fullmatch(r"[\x20-\x7e]{0,256}", value)) and '"' not in value


# ======================================================================================
#  5. Response views: SOAP XML and gRPC-web frames -> a JSON view the shared extractor reads
# ======================================================================================
def _local(tag):
    return str(tag).rsplit("}", 1)[-1]


def _xml_value(element, budget):
    budget[0] -= 1
    if budget[0] < 0:
        raise ValueError("SOAP response exceeds the XML node bound")
    children = list(element)
    if not children:
        return (element.text or "").strip()[:4096]
    out = {}
    for child in children:
        key = _local(child.tag)[:128]
        value = _xml_value(child, budget)
        if key in out:
            if not isinstance(out[key], list):
                out[key] = [out[key]]
            out[key].append(value)
        else:
            out[key] = value
    return out


def soap_view(body):
    """Return ``(doc, fault, reason)`` for a SOAP response body.

    ``doc`` is the SOAP Body as a nested mapping of element local names (a JSON view the shared,
    JSON-oriented proof extractor can read), ``fault`` is True when the Body carries a SOAP Fault.
    A body declaring a DTD or entity is never parsed (no entity expansion); malformed XML or a
    non-envelope is ``(None, False, reason)``.
    """
    try:
        raw = bytes(body or b"")[:MAX_BODY]
    except (TypeError, ValueError):
        return None, False, "SOAP response body is not bytes"
    if re.search(rb"(?i)<!\s*(?:DOCTYPE|ENTITY)", raw):
        return None, False, "SOAP response declares a DTD/entity; not parsed"
    try:
        root = _ET.fromstring(raw)
    except _ET.ParseError as exc:
        return None, False, f"SOAP response is not well-formed XML ({type(exc).__name__})"
    if _local(root.tag) != "Envelope":
        return None, False, "SOAP response is not a SOAP Envelope"
    bodies = [child for child in root if _local(child.tag) == "Body"]
    if len(bodies) != 1:
        return None, False, "SOAP Envelope does not carry exactly one Body"
    try:
        doc = _xml_value(bodies[0], [MAX_XML_NODES])
    except (ValueError, RecursionError) as exc:
        return None, False, str(exc) if isinstance(exc, ValueError) else "SOAP response nests too deeply"
    fault = isinstance(doc, dict) and "Fault" in doc
    return doc if isinstance(doc, dict) else {"Body": doc}, fault, None


def _varint(data, index):
    value, shift = 0, 0
    while index < len(data) and shift < 64:
        byte = data[index]
        index += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, index
        shift += 7
    return None, index


def _printable(text):
    return bool(text) and all(ch.isprintable() or ch in "\t\r\n" for ch in text)


def proto_strings(data, depth=0, out=None):
    """Collect the printable UTF-8 strings of a schema-less protobuf message (bounded walk).

    Returns ``(strings, ok)``; ``ok`` is False when the bytes are not a well-formed protobuf message.
    A length-delimited field that is printable UTF-8 is a string; one that is not is walked as a
    nested message (depth-bounded).  No field bytes are ever interpreted beyond this.
    """
    out = [] if out is None else out
    index = 0
    while index < len(data):
        if len(out) >= 64:
            break
        key, index = _varint(data, index)
        if key is None or key >> 3 == 0:
            return out, False
        wire = key & 7
        if wire == 0:
            value, index = _varint(data, index)
            if value is None:
                return out, False
        elif wire == 1:
            index += 8
        elif wire == 5:
            index += 4
        elif wire == 2:
            length, index = _varint(data, index)
            if length is None or index + length > len(data):
                return out, False
            chunk = bytes(data[index:index + length])
            index += length
            try:
                text = chunk.decode("utf-8", "strict")
            except UnicodeDecodeError:
                text = None
            if text is not None and _printable(text):
                out.append(text[:4096])
            elif depth < 4 and chunk:
                proto_strings(chunk, depth + 1, out)
        else:
            return out, False
        if index > len(data):
            return out, False
    return out, True


def grpc_view(body, content_type):
    """Return ``(doc, error, reason)`` for a gRPC-web response.

    ``doc`` is ``{"messages": [[strings...], ...]}`` from each data frame's protobuf strings;
    ``error`` is the non-zero ``grpc-status`` from the trailer frame (None when OK or absent).  A
    compressed, truncated or non-protobuf frame is ``(None, None, reason)``.
    """
    try:
        raw = bytes(body or b"")[:MAX_BODY]
    except (TypeError, ValueError):
        return None, None, "gRPC-web response body is not bytes"
    if "grpc-web-text" in str(content_type or "").lower():
        compact = re.sub(rb"\s+", b"", raw)
        chunks = re.findall(rb"[A-Za-z0-9+/]+={0,2}", compact)
        if b"".join(chunks) != compact:
            return None, None, "gRPC-web-text response is not base64"
        try:
            raw = b"".join(base64.b64decode(chunk, validate=True) for chunk in chunks)
        except (ValueError, base64.binascii.Error):
            return None, None, "gRPC-web-text response is not canonical base64"
    messages, status, index = [], None, 0
    while index < len(raw):
        if len(messages) >= MAX_GRPC_FRAMES:
            return None, None, "gRPC-web response exceeds the frame bound"
        if len(raw) - index < 5:
            return None, None, "gRPC-web response has a truncated frame header"
        flags = raw[index]
        length = int.from_bytes(raw[index + 1:index + 5], "big")
        index += 5
        if length > len(raw) - index:
            return None, None, "gRPC-web response has a truncated frame"
        payload = raw[index:index + length]
        index += length
        if flags & 0x80:
            for line in payload.decode("latin-1").replace("\r\n", "\n").split("\n"):
                name, _, value = line.partition(":")
                if name.strip().lower() == "grpc-status":
                    status = value.strip()
            continue
        if flags & 0x01:
            return None, None, "gRPC-web data frame is compressed; not decoded"
        strings, ok = proto_strings(payload)
        if not ok:
            return None, None, "gRPC-web data frame is not a well-formed protobuf message"
        messages.append(strings)
    error = status if status not in (None, "0") else None
    return {"messages": messages}, error, None


def _json_view(response, doc):
    return {"status": response.get("status"),
            "body": json.dumps(doc, separators=(",", ":"), ensure_ascii=False).encode("utf-8"),
            "response_headers": {"Content-Type": "application/json"}}


def _header(response, name):
    headers = response.get("response_headers") or response.get("headers") or {}
    if not isinstance(headers, dict):
        return ""
    for key, value in headers.items():
        if str(key).lower() == name:
            return str(value)
    return ""


# ======================================================================================
#  6. Discovery helper
# ======================================================================================
def _response(raw):
    if not isinstance(raw, dict):
        return None
    if "body" in raw:
        return raw
    if "text" in raw:
        out = dict(raw)
        out["body"] = str(raw.get("text") or "").encode("utf-8", "replace")
        out.setdefault("response_headers", dict(raw.get("headers") or {}))
        return out
    return None


def _clues_from(preloaded):
    response = _response((preloaded or {}).get("/api/clues"))
    if response is None:
        return None
    views = None
    if _proofs is not None and hasattr(_proofs, "response_text_views"):
        try:
            views = _proofs.response_text_views(response)
        except Exception:
            views = None
    if views is None:
        body = response.get("body", b"")
        try:
            text = bytes(body).decode("utf-8", "strict") if isinstance(body, (bytes, bytearray)) \
                else str(body or "")
        except Exception:
            return None
        views = [text]
    try:
        value = _security_json.loads_unique(views, max_chars=MAX_BODY)
    except Exception:
        return None
    return value if isinstance(value, dict) else None


# ======================================================================================
#  7. The engine driver
# ======================================================================================
class _Invoker:
    def __init__(self, target, ctx):
        self.target = dict(target) if isinstance(target, dict) else {"url": str(target)}
        self.url = str(self.target.get("url") or "")
        self.aid = str(self.target.get("answer_id") or "target")
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
        self.baselines = [str(v or "")[:MAX_BODY] for v in list(self.ctx.get("baseline_texts") or [])[:120]]
        self.route_allowed = self.ctx.get("route_allowed")
        self.requests = 0
        self.kind = None
        self.operation_id = None
        self.verdict = None
        self.route = None
        self.transport = None
        self.success = False
        self.terminal = False
        self.stopped = None
        self.surfaced = None
        self.payoff = None
        self.candidates = []

    def _may_send(self):
        if hasattr(self.stop, "is_set") and self.stop.is_set():
            self.stopped = self.stopped or "stopped"
            return False
        if self.deadline - time.time() <= DEADLINE_PAD:
            self.stopped = self.stopped or "deadline"
            return False
        if self.requests >= self.max_requests:
            self.stopped = self.stopped or "max_requests"
            return False
        return True

    def _surface(self, reason, **extra):
        row = {"reason": reason}
        row.update(extra)
        self.surfaced = row
        self.terminal = True
        return None

    def _client(self):
        client = self.ctx.get("client")
        if client is None and callable(self.ctx.get("client_factory")):
            try:
                client = self.ctx["client_factory"](self.url, REQUEST_TIMEOUT)
            except Exception as exc:
                self.stopped = f"no scoped client: {type(exc).__name__}"
                return None
        if client is None:
            self.stopped = "no scoped client for descriptor invocation"
        return client

    def _extract(self, response):
        """Run the shared extractor; a raise is a named stop, never a silent 'no payoff'."""
        host = urllib.parse.urlsplit(self.url).hostname
        try:
            outcome = _proofs.extract_success(response, self.baselines, host=host)
        except Exception as exc:  # noqa: BLE001
            self.stopped = (f"shared proof extractor forge_event.extract_success raised "
                            f"{type(exc).__name__}; the invocation response was not judged")
            return None, [], False
        return outcome.get("auto"), [str(v)[:256] for v in outcome.get("candidates") or []], True

    def run(self):
        reason = disabled_reason()
        if reason is not None:
            self.stopped = reason
            return None
        if _proofs is None or not hasattr(_proofs, "extract_success"):
            why = _PROOFS_IMPORT_ERROR or "extract_success missing"
            self.stopped = (f"shared proof extractor unavailable: forge_event failed to import ({why}); "
                            "descriptor invocation sends nothing it cannot judge")
            return None
        clues = _clues_from(self.preloaded)
        if not isinstance(clues, dict):
            self.stopped = "no /api/clues JSON to read an api_invoke descriptor from"
            return None
        spec = clues.get("api_invoke")
        if not isinstance(spec, dict):
            self.stopped = "no api_invoke descriptor in /api/clues"
            return None
        descriptor, intake_reason = descriptor_from_spec(spec, self.url)
        if descriptor is None:
            return self._surface(intake_reason)
        kind = _descriptor_kind(descriptor)
        if kind is None:
            return self._surface("api_invoke descriptor is missing or not an inventoried "
                                 "AsyncAPI/OpenRPC/WSDL/protobuf/gRPC-web record")
        self.kind = kind
        operation, op_reason = select_operation(descriptor, spec.get("operation"))
        if operation is None:
            return self._surface(f"operation not uniquely selected: {op_reason}")
        self.operation_id = next(iter(_op_identity(operation)), None)
        verdict, why = classify_operation(kind, operation)
        self.verdict = verdict
        if verdict != "read":
            # Writes and unknowns are never invoked: surface the operation for the model.
            return self._surface(f"operation is not provably read-only ({verdict}): {why}; "
                                 "descriptor invocation sends only read-only operations",
                                 verdict=verdict, operation=self.operation_id)
        stream = None
        if kind == "asyncapi":
            route, stream, route_reason = asyncapi_channel(descriptor, self.url, operation)
        else:
            route, route_reason = same_origin_endpoint(descriptor, self.url, operation)
        if route is None:
            return self._surface(f"no same-origin endpoint: {route_reason}")
        if _destructive(route):
            return self._surface(f"endpoint route {route!r} names a destructive action; refused")
        if callable(self.route_allowed):
            try:
                if not bool(self.route_allowed(route)):
                    return self._surface("route guard refused the invocation endpoint")
            except Exception as exc:  # noqa: BLE001
                return self._surface(f"route guard failed on the invocation endpoint "
                                     f"({type(exc).__name__})")
        self.route = route
        if kind == "wsdl" and operation.get("namespace") is None:
            # The WSDL target namespace lives on the record, not the operation: carry it through so
            # the SOAP body element is namespaced as the service expects.
            ns = descriptor.get("target_namespace")
            if isinstance(ns, str) and ns:
                operation = dict(operation, namespace=ns)
        plan, build_reason = build_invocation(kind, operation, route, stream=stream)
        if plan is None:
            return self._surface(f"cannot build a bounded read-only request: {build_reason}")
        self.transport = plan["transport"]
        if plan["transport"] == "realtime":
            return self._invoke_realtime(plan)
        return self._invoke_http(plan)

    def _judge(self, views, demote_reason=None):
        """Turn the response view(s) into the payoff; ``demote_reason`` keeps any hit a candidate."""
        autos, candidates = [], []
        for view in views:
            auto, found, ok = self._extract(view)
            if not ok:
                return None
            if auto:
                autos.append(str(auto))
            candidates.extend(found)
        unique = list(dict.fromkeys(autos))
        self.candidates = list(dict.fromkeys(candidates))[:16]
        if len(unique) == 1 and not self.candidates and demote_reason is None:
            self.success = True
            self.payoff = unique[0]
            return self.payoff
        if unique or self.candidates:
            self.success = True  # evidence of a reachable read, but no single unambiguous payoff.
            self.candidates = list(dict.fromkeys(unique + self.candidates))[:16]
        self.stopped = self.stopped or demote_reason or "invocation returned no unambiguous payoff"
        return None

    def _invoke_http(self, plan):
        client = self._client()
        if client is None:
            return None
        if getattr(client, "get_only", False) and str(plan["method"]).upper() not in ("GET", "HEAD"):
            # A GET-only lane cannot carry an RPC/SOAP POST: a named refusal, not a silent skip.
            return self._surface("the web client is GET-only (B-007); this RPC/SOAP invocation needs "
                                 "POST and is blocked while the GET-only lane is in force")
        if not self._may_send():
            return None
        try:
            self.requests += 1
            response = client.request(plan["method"], plan["route"], data=plan["body"],
                                      headers=plan["headers"], allow_redirects=False)
        except _web.OutOfScope as exc:
            return self._surface(f"invocation route left the locked scope: {exc}")
        except Exception as exc:  # noqa: BLE001 -- transport fault is terminal, never retried
            self.stopped = f"invocation transport: {type(exc).__name__}"
            self.terminal = True
            return None
        self.terminal = True
        if not isinstance(response, dict):
            self.stopped = "invocation returned no response record"
            return None
        if self.kind == "wsdl":
            doc, fault, reason = soap_view(response.get("body"))
            if doc is None:
                self.stopped = reason
                return self._judge([response], demote_reason=reason)
            return self._judge([_json_view(response, doc)],
                               demote_reason="SOAP Fault returned" if fault else None)
        if self.kind in ("grpc-web", "protobuf"):
            doc, error, reason = grpc_view(response.get("body"), _header(response, "content-type"))
            header_status = _header(response, "grpc-status").strip()
            if header_status and header_status != "0":
                error = error or header_status
            if doc is None:
                self.stopped = reason
                return self._judge([response], demote_reason=reason)
            # Schema-less protobuf has no field names, so no string carries a target-authored label.
            # Each decoded string is judged as its own body: the shared policy accepts a body that
            # is exactly the wire-format payoff as self-describing, and a second distinct payoff in
            # any other string makes the answer ambiguous (so nothing is auto-returned).
            strings = [text for message in doc["messages"] for text in message][:64]
            if not strings:
                self.stopped = "gRPC-web response carried no string field"
                return None
            views = [{"status": response.get("status"), "body": text.encode("utf-8"),
                      "response_headers": {}} for text in strings]
            return self._judge(views, demote_reason=f"grpc-status {error}" if error else None)
        return self._judge([response])

    def _invoke_realtime(self, plan):
        # AsyncAPI channels are WebSocket/SSE reads.  The player's real-time switch belongs to
        # realtime_read, so a player who turned the real-time class off is honoured here too.
        if _realtime_read is None:
            return self._surface(f"AsyncAPI channel read needs realtime_read's off switch, but "
                                 f"realtime_read failed to import ({_REALTIME_IMPORT_ERROR}); "
                                 "surfacing the channel as a lead", channel=plan["route"])
        reason = _realtime_read.disabled_reason()
        if reason is not None:
            return self._surface(f"AsyncAPI channel read is off because the real-time class is off: "
                                 f"{reason}", channel=plan["route"])
        client = self._client()
        if client is None:
            return None
        if not self._may_send():
            return None
        stream = plan["stream"]
        try:
            self.requests += 1
            if stream == "websocket":
                # Server-first only: the upgrade, then no client frame at all (a read, never a send).
                response = client.websocket_receive(plan["route"], deadline=self.deadline,
                                                    max_frames=MAX_WS_FRAMES, max_bytes=MAX_BODY)
            else:
                response = client.sse_first_event(plan["route"], deadline=self.deadline,
                                                  max_bytes=MAX_BODY)
        except _web.OutOfScope as exc:
            return self._surface(f"channel route left the locked scope: {exc}")
        except Exception as exc:  # noqa: BLE001 -- transport fault is terminal, never retried
            self.stopped = f"channel read transport: {type(exc).__name__}"
            self.terminal = True
            return None
        self.terminal = True
        if not isinstance(response, dict) or response.get("protocol_error"):
            detail = response.get("protocol_error") if isinstance(response, dict) else None
            self.stopped = f"channel {stream} read did not complete ({detail or 'no response'})"
            return None
        if stream == "websocket":
            messages = response.get("websocket_messages")
            if response.get("status") != 101 or not response.get("upgraded") \
                    or not isinstance(messages, list):
                self.stopped = f"channel websocket upgrade answered {response.get('status')}, not 101"
                return None
        else:
            event = response.get("sse_event") if isinstance(response.get("sse_event"), dict) else {}
            data = event.get("data")
            if response.get("status") != 200 or not isinstance(data, str):
                self.stopped = f"channel SSE read answered {response.get('status')} with no event"
                return None
            messages = [data]
        views = [{"status": 200, "body": str(message).encode("utf-8", "replace"),
                  "response_headers": {}} for message in messages[:16] if isinstance(message, str)]
        if not views:
            self.stopped = "channel read returned no message"
            return None
        return self._judge(views)

    def result(self):
        return {
            "class": "api_invoke", "kind": self.kind, "operation": self.operation_id,
            "verdict": self.verdict, "transport": self.transport, "route": self.route,
            "requests": self.requests, "success": self.success, "terminal": self.terminal,
            "stopped": self.stopped, "surfaced": self.surfaced,
            "candidates": list(self.candidates)[:16],
        }


def _publish(invoker, target, ctx):
    aid = str(target.get("answer_id") or "target") if isinstance(target, dict) else "target"
    summary = invoker.result()
    sink = ctx.get("result_sink") if isinstance(ctx, dict) else None
    if isinstance(sink, dict):
        sink[aid] = summary
    evidence = ctx.get("evidence") if isinstance(ctx, dict) else None
    if isinstance(evidence, list):
        line = _web.safe_display_text(
            f"WEB API-INVOKE: kind={summary['kind']} op={summary['operation']} "
            f"verdict={summary['verdict']} success={summary['success']} "
            f"requests={summary['requests']}", 500)
        if line not in evidence:
            evidence.append(line)


def solve(target, ctx=None):
    """Drive one bounded read-only descriptor operation and return its payoff, or None.

    Gated off by default; reads the inventoried descriptor and chosen operation from ``/api/clues``;
    invokes only a provably read-only operation against the descriptor's own same-origin server;
    surfaces a write/unknown/off-host/unbuildable operation for the model instead of sending it.
    """
    ctx = dict(ctx or {})
    invoker = _Invoker(target, ctx)
    proof = None
    try:
        proof = invoker.run()
    except Exception as exc:  # noqa: BLE001
        invoker.stopped = invoker.stopped or f"error: {type(exc).__name__}"
    _publish(invoker, target, ctx)
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


__all__ = ["disabled_reason", "enabled", "classify_operation", "select_operation", "record_problem",
           "descriptor_from_spec", "same_origin_endpoint", "asyncapi_channel", "build_invocation",
           "soap_view", "grpc_view", "proto_strings", "solve", "solve_targets"]
