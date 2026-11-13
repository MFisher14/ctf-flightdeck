#!/usr/bin/env python3
"""Multi-layer proof-replay / mesh-protocol chain harness (B-107).

A proof-replay gauntlet (the CSCTF "Velora" 31-layer shape, a binary WebSocket mesh) gates each of
many heterogeneous single-vuln layers behind a *sequential proof protocol*: solving layer *k* yields
a proof token, and that token must be replayed -- in order, with every earlier token -- in an
ordered proof header (X-Chain style) before layer *k+1* is reachable at all.  Each individual layer
is an ordinary Web vulnerability the existing single-vuln engines already own; the novelty is only
the bookkeeping that threads them together and the per-layer reasoning about *which* class a reached
layer is.

This module is a **harness over those engines, not a new vulnerability engine** (B-107 is
``automatable: no``; see BUILD-PLAN.md's hard-tail entry 4).  It automates exactly the plumbing the
fallback names:

* **Ordered-proof-header bookkeeping** (:class:`ProofChain`): the X-Chain accumulator.  It records
  each layer's proof in order, validates every token is header-safe (no request smuggling), and
  renders the exact header the next layer's requests must carry.
* **Per-layer dispatch** (:func:`engine_for`, :class:`_ChainClient`): a reached layer whose class the
  harness recognizes is dispatched to the matching engine -- ``recon_router`` (SSRF->IDOR, signed
  manifest and the ranked cold classes), ``realtime_read`` (WebSocket / SSE reads),
  ``state_transaction`` (upload-preview / single-use redemption), ``api_invoke`` (one gated,
  read-only descriptor operation, B-123) -- with a transparent client that
  injects the accumulated proof header on every HTTP request the engine makes.
* **Surface-the-rest**: a layer whose class is not recognized (or a recognized layer the engine could
  not close) is *surfaced* with its evidence and stops the automated walk, leaving per-layer
  reasoning to the model.  The harness never guesses a class it does not know.
* **WS mesh negotiation** (:func:`negotiate_subprotocol`, :func:`infer_binary_framing`): offline leads
  for the binary mesh variant -- which offered subprotocol the server agreed to, and the inner
  application framing of saved binary frames -- reusing ``api_protocols``.  Leads, never answers.

Interface (the same peer contract as the cold readers it drives)::

    solve(target, ctx) -> proof | None

``ctx`` supplies the scope-locked client, cached discovery responses, absolute deadline, request
budget, stop event, a route guard and a result sink.  This module opens no socket of its own, sends
no Game Master credential, and executes no challenge code.

Offline CLI (triage a saved mesh descriptor; leads only, never an answer)::

    python solvers/web/proof_chain.py mesh.json [--json]
"""

from __future__ import annotations

import base64
import json
import re
import sys
import time
import urllib.parse
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

HERE = Path(__file__).resolve().parent
TOOLKITS = HERE.parent / "toolkits"
for _path in (TOOLKITS, HERE):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import web as _web  # noqa: E402 -- shared scope/route policy
import security_json as _security_json  # noqa: E402 -- duplicate-key rejecting JSON
import api_protocols as _api  # noqa: E402 -- offline WS/gRPC framing (no socket)

try:
    import recon_router as _recon_router  # noqa: E402
except Exception:  # pragma: no cover - a partial export fails closed
    _recon_router = None
try:
    import realtime_read as _realtime_read  # noqa: E402
except Exception:  # pragma: no cover
    _realtime_read = None
try:
    import state_transaction as _state_transaction  # noqa: E402
except Exception:  # pragma: no cover
    _state_transaction = None
try:
    import api_invoke as _api_invoke  # noqa: E402 -- B-123 descriptor-driven invocation (gated)
except Exception:  # pragma: no cover
    _api_invoke = None
try:
    import forge_event as _proofs  # noqa: E402 -- shared proof/carrier policy
except Exception:  # pragma: no cover
    _proofs = None


MAX_LAYERS = 64
MAX_PRELOADED = 160
MAX_BODY = 65_536
MAX_HEADER_BYTES = 8 * 1024
DEADLINE_PAD = 0.3

# An HTTP header name (RFC 7230 token).
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$")
# A header-safe proof token: printable, no whitespace, no separator the join would collide with.  A
# proof token that cannot be rendered into the ordered header without ambiguity or smuggling is a
# hard refusal, never silently dropped.
_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9!#$%&'*+./:=?@_~-]{1,512}$")
_WS_TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$")
PAYOFF_SEEN = flagfmt.PAYOFF_ANYCASE


class ProofChainError(ValueError):
    """A malformed chain protocol, an unsafe proof token, or an oversize header."""


# ======================================================================================
#  1. The X-Chain ordered-proof-header accumulator
# ======================================================================================
class ProofChain:
    """Ordered proof-header bookkeeping for a proof-replay gauntlet.

    Solving layer *k* yields a proof token; :meth:`append` records it *in order* (each layer index
    once, strictly increasing), validates it is header-safe, and :meth:`headers` renders the exact
    ordered header the next layer's requests must carry.  State is explicit (:meth:`snapshot`,
    :attr:`tokens`) for an audit trail.  Nothing is sent here.
    """

    def __init__(self, *, header="X-Chain-Proof", join=",", indexed=False, always_send=False):
        if not isinstance(header, str) or not _HEADER_NAME.fullmatch(header):
            raise ProofChainError(f"chain header name {header!r} is not an HTTP token")
        if not isinstance(join, str) or len(join) != 1 or join not in ",;| ":
            raise ProofChainError("chain join must be one of ',', ';', '|' or a space")
        self._header = header
        self._join = join
        self._indexed = bool(indexed)
        self._always_send = bool(always_send)
        self._entries: list[tuple[int, str]] = []

    @property
    def header_name(self):
        return self._header

    @property
    def tokens(self):
        return [token for _index, token in self._entries]

    @property
    def depth(self):
        return len(self._entries)

    def append(self, index, token):
        """Record layer ``index``'s proof ``token``; enforce order, uniqueness and header-safety."""
        if isinstance(index, bool) or not isinstance(index, int):
            raise ProofChainError("layer index must be an int")
        if self._entries and index <= self._entries[-1][0]:
            raise ProofChainError(
                f"layer index {index} is not strictly after {self._entries[-1][0]}")
        if len(self._entries) >= MAX_LAYERS:
            raise ProofChainError(f"chain exceeds {MAX_LAYERS} layers")
        if not isinstance(token, str) or not _SAFE_TOKEN.fullmatch(token):
            # A token that cannot be placed in a header without ambiguity/smuggling is refused loudly
            # (Rule 6): the harness never replays bytes it cannot render safely.
            raise ProofChainError("proof token is empty, oversize, or not header-safe")
        if self._join in token:
            raise ProofChainError(
                f"proof token contains the chain separator {self._join!r}; it cannot be ordered")
        self._entries.append((index, token))
        if len(self.header_value().encode("utf-8")) > MAX_HEADER_BYTES:
            self._entries.pop()
            raise ProofChainError(f"ordered proof header exceeds {MAX_HEADER_BYTES} bytes")
        return self.header_value()

    def header_value(self):
        """The ordered header value: the proofs joined by the separator (indexed when configured)."""
        if self._indexed:
            parts = [f"{index}:{token}" for index, token in self._entries]
        else:
            parts = [token for _index, token in self._entries]
        return self._join.join(parts)

    def headers(self):
        """The header dict to inject into the next layer's requests, or empty before any proof."""
        if not self._entries and not self._always_send:
            return {}
        return {self._header: self.header_value()}

    def snapshot(self):
        return {"header": self._header, "join": self._join, "indexed": self._indexed,
                "depth": len(self._entries), "entries": list(self._entries),
                "value": self.header_value()}


# ======================================================================================
#  2. The chain protocol descriptor (parsed from the target's own clue document)
# ======================================================================================
class _Layer:
    __slots__ = ("index", "cls", "preloaded", "target_url", "note")

    def __init__(self, index, cls, preloaded, target_url, note):
        self.index = index
        self.cls = cls
        self.preloaded = preloaded
        self.target_url = target_url
        self.note = note


class ChainProtocol:
    """A parsed, validated proof-replay protocol descriptor.

    It is read from the target's duplicate-safe ``/api/clues`` JSON under a ``proof_chain`` key:

    ``header``      the ordered-proof header name (an HTTP token; default ``X-Chain-Proof``);
    ``join``        the separator between proofs (one of ``,;|`` or a space; default ``,``);
    ``indexed``     whether each proof is prefixed with its 1-based layer index;
    ``always_send`` whether the (possibly empty) header is sent even on layer 1;
    ``final_route`` optional same-origin route the full header is replayed against for the payoff;
    ``layers``      the ordered layer list; each is ``{"index", "class", "clue": {path: body}}``.

    Every route is same-origin validated; a malformed descriptor raises :class:`ProofChainError` so a
    bad clue is a named terminal decline, never a silent fall-through.
    """

    def __init__(self, *, header, join, indexed, always_send, final_route, layers):
        self.header = header
        self.join = join
        self.indexed = indexed
        self.always_send = always_send
        self.final_route = final_route
        self.layers = layers

    def new_chain(self):
        return ProofChain(header=self.header, join=self.join, indexed=self.indexed,
                          always_send=self.always_send)

    @classmethod
    def from_clues(cls, clues, base_url):
        if not isinstance(clues, dict) or "proof_chain" not in clues:
            return None
        raw = clues.get("proof_chain")
        if not isinstance(raw, dict):
            raise ProofChainError("proof_chain clue is not an object")
        allowed = {"header", "join", "indexed", "always_send", "final_route", "layers"}
        if set(raw) - allowed:
            raise ProofChainError(f"proof_chain has unexpected keys: {sorted(set(raw) - allowed)}")
        header = raw.get("header", "X-Chain-Proof")
        join = raw.get("join", ",")
        indexed = raw.get("indexed", False)
        always_send = raw.get("always_send", False)
        if not isinstance(header, str) or not _HEADER_NAME.fullmatch(header):
            raise ProofChainError("proof_chain.header is not an HTTP token")
        if not isinstance(join, str) or len(join) != 1 or join not in ",;| ":
            raise ProofChainError("proof_chain.join must be one of ',', ';', '|' or a space")
        if not isinstance(indexed, bool) or not isinstance(always_send, bool):
            raise ProofChainError("proof_chain.indexed/always_send must be booleans")
        final_route = None
        if raw.get("final_route") is not None:
            final_route = _safe_route(raw.get("final_route"), base_url)
            if final_route is None:
                raise ProofChainError("proof_chain.final_route is not a safe same-origin route")
        layers_raw = raw.get("layers")
        if not isinstance(layers_raw, list) or not 1 <= len(layers_raw) <= MAX_LAYERS:
            raise ProofChainError(f"proof_chain.layers must be a list of 1..{MAX_LAYERS}")
        layers = []
        seen_index = None
        for position, item in enumerate(layers_raw, 1):
            if not isinstance(item, dict) or set(item) - {"index", "class", "clue", "note"}:
                raise ProofChainError(f"layer {position} is malformed")
            index = item.get("index", position)
            if isinstance(index, bool) or not isinstance(index, int) or index < 1:
                raise ProofChainError(f"layer {position} has a bad index")
            if seen_index is not None and index <= seen_index:
                raise ProofChainError(f"layer {position} index {index} is not strictly increasing")
            seen_index = index
            cls_name = item.get("class")
            if not isinstance(cls_name, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", cls_name):
                raise ProofChainError(f"layer {position} class is not a conservative name")
            clue = item.get("clue", {})
            if not isinstance(clue, dict) or len(clue) > MAX_PRELOADED:
                raise ProofChainError(f"layer {position} clue is not a bounded path->body map")
            preloaded = {}
            for path, body in clue.items():
                if not isinstance(path, str) or "\x00" in path:
                    raise ProofChainError(f"layer {position} clue has a bad path")
                preloaded[path] = body
            note = item.get("note")
            if note is not None and not isinstance(note, str):
                raise ProofChainError(f"layer {position} note is not a string")
            layers.append(_Layer(index, cls_name, preloaded, base_url, (note or "")[:300]))
        return cls(header=header, join=join, indexed=indexed, always_send=always_send,
                   final_route=final_route, layers=layers)


# ======================================================================================
#  3. Per-layer dispatch to the existing single-vuln engines
# ======================================================================================
# A recognized layer class -> (engine module, the single public callable).  ``recon_router`` owns its
# own class table (``DISPATCH_PLAN``); the real-time and state-transaction peers own the exact clue
# keys they compile.  Everything else is surfaced for the model.
_REALTIME_CLASSES = frozenset({"websocket_read", "websocket_stateful_read", "sse_read",
                               "websocket", "sse", "realtime_read"})
_STATE_CLASSES = frozenset({"upload_preview", "single_use_redemption", "state_transaction"})
# B-123: a layer whose clue names one inventoried descriptor operation (``api_invoke``); the engine
# stays gated (CTF_WEB_APICALL) and read-only, so dispatching it never widens what may be sent.
_API_INVOKE_CLASSES = frozenset({"api_invoke"})


def engine_for(cls_name):
    """Return the engine module that owns a reached layer's class, or ``None`` to surface it.

    The harness recognizes exactly the classes the existing engines can execute; it never maps a
    class to an engine that would merely rank or guess it.
    """
    if not isinstance(cls_name, str):
        return None
    if _recon_router is not None and cls_name in getattr(_recon_router, "DISPATCH_PLAN", {}):
        spec = _recon_router.DISPATCH_PLAN.get(cls_name) or {}
        # recon_router only *executes* its exact classes; the ranked/cold ones it merely surfaces, so
        # the harness cannot close them and must leave them to the model too.
        if spec.get("mode") == "exact":
            return _recon_router
        return None
    if _realtime_read is not None and cls_name in _REALTIME_CLASSES:
        return _realtime_read
    if _state_transaction is not None and cls_name in _STATE_CLASSES:
        return _state_transaction
    if _api_invoke is not None and cls_name in _API_INVOKE_CLASSES:
        return _api_invoke
    return None


def _unavailable_engine(cls_name):
    """Name the engine a recognized class needs when that engine failed to import, else ``None``.

    Rule 6: a missing peer engine is a named, loud reason, never silently re-labelled as an
    unrecognized class.  Only the real-time, state-transaction and api_invoke families carry their
    class sets in this module, so only those can be told apart from a genuinely unknown class when the module is
    absent; ``recon_router``'s class table lives on the module itself, so an unimportable
    ``recon_router`` cannot be distinguished here and its classes read as unrecognized.
    """
    if not isinstance(cls_name, str):
        return None
    if cls_name in _REALTIME_CLASSES and _realtime_read is None:
        return "realtime_read"
    if cls_name in _STATE_CLASSES and _state_transaction is None:
        return "state_transaction"
    if cls_name in _API_INVOKE_CLASSES and _api_invoke is None:
        return "api_invoke"
    return None


class _ChainClient:
    """Transparent WebClient guard that injects the accumulated proof header on every HTTP request.

    A proof-replay layer is only reachable once the ordered header carries every earlier proof, so the
    harness wraps the scope-locked client and merges :class:`ProofChain`'s current header into each
    ``request``/``get``/``post`` a dispatched engine makes.  WebSocket/SSE *stream* primitives take no
    custom headers through the public client API, so the header rides their same-origin control GET
    (which does go through ``request``); the live stream frame itself is a documented gap.  Every wire
    call is counted so the harness can share the request budget across layers.
    """

    _LOCAL = frozenset(("_client", "_chain", "_counter"))

    def __init__(self, client, chain, counter):
        object.__setattr__(self, "_client", client)
        object.__setattr__(self, "_chain", chain)
        object.__setattr__(self, "_counter", counter)

    def __getattr__(self, name):
        return getattr(self._client, name)

    def __setattr__(self, name, value):
        if name in self._LOCAL:
            object.__setattr__(self, name, value)
        else:
            setattr(self._client, name, value)

    def _inject(self, headers):
        merged = dict(headers or {})
        # The chain header is authoritative: a dispatched engine never sets it, and it must not be
        # overridable by one, so it wins the merge.
        merged.update(self._chain.headers())
        return merged

    def _count(self):
        self._counter[0] = self._counter[0] + 1

    def request(self, method, path, data=None, headers=None, allow_redirects=True):
        self._count()
        return self._client.request(method, path, data=data, headers=self._inject(headers),
                                    allow_redirects=allow_redirects)

    def get(self, path, **kw):
        self._count()
        kw["headers"] = self._inject(kw.get("headers"))
        return self._client.get(path, **kw)

    def post(self, path, data=None, **kw):
        self._count()
        kw["headers"] = self._inject(kw.get("headers"))
        return self._client.post(path, data=data, **kw)

    def websocket_receive(self, *args, **kwargs):
        self._count()
        return self._client.websocket_receive(*args, **kwargs)

    def websocket_conversation(self, *args, **kwargs):
        self._count()
        return self._client.websocket_conversation(*args, **kwargs)

    def sse_first_event(self, *args, **kwargs):
        self._count()
        return self._client.sse_first_event(*args, **kwargs)

    def sse_events(self, *args, **kwargs):
        self._count()
        return self._client.sse_events(*args, **kwargs)


# ======================================================================================
#  4. WebSocket mesh helpers (offline; leads only)
# ======================================================================================
def negotiate_subprotocol(offered, selected):
    """Resolve a WebSocket subprotocol negotiation (RFC 6455 section 1.3 / 4.2.2).

    ``offered`` is the client's ``Sec-WebSocket-Protocol`` list (from the bundle or clue); ``selected``
    is the server's chosen token from a saved handshake (``None``/"" when the server omitted it).
    Returns a lead dict: ``agreed`` is the token both sides accept, or ``None`` when the server picked
    none; ``status`` is ``agreed`` | ``none`` | ``invalid``.  A server token the client never offered
    is ``invalid`` -- exactly the ``WebClient`` upgrade check, surfaced as an offline lead.
    """
    if isinstance(offered, str):
        offered = [offered]
    offered = [token for token in list(offered or []) if isinstance(token, str)]
    for token in offered:
        if not _WS_TOKEN.fullmatch(token):
            raise ProofChainError(f"offered subprotocol {token!r} is not a WebSocket token")
    if len(set(offered)) != len(offered):
        raise ProofChainError("offered subprotocols must be distinct")
    chosen = (selected or "").strip() if isinstance(selected, str) else ""
    if not chosen:
        return {"agreed": None, "status": "none", "offered": offered,
                "reason": "the server selected no subprotocol; the connection runs unframed"}
    if not _WS_TOKEN.fullmatch(chosen):
        return {"agreed": None, "status": "invalid", "offered": offered,
                "reason": f"the server's selection {chosen!r} is not a WebSocket token"}
    if chosen not in offered:
        return {"agreed": None, "status": "invalid", "offered": offered,
                "reason": f"the server selected {chosen!r}, which the client never offered -- reject"}
    return {"agreed": chosen, "status": "agreed", "offered": offered,
            "reason": f"both sides agreed on {chosen!r}"}


def _classify_payload_framing(payload):
    """Name the inner application framing of one binary WebSocket payload (a lead, never a claim)."""
    n = len(payload)
    if n >= 5:
        # Delegate gRPC-web recognition to the canonical parser so this never drifts from
        # ``api_protocols.parse_grpc_web_frames``.  A payload is gRPC-web only when it is exactly one
        # complete data/compressed-data envelope (not a trailer frame) that spans the whole payload.
        try:
            frames = _api.parse_grpc_web_frames(bytes(payload))
        except _api.APIProtocolError:
            frames = ()
        if (len(frames) == 1 and frames[0].complete and frames[0].flags in (0, 1)
                and 5 + frames[0].declared_length == n):
            return "grpc-web"
    if n >= 4 and int.from_bytes(payload[:4], "big") == n - 4:
        return "length-prefixed-u32"
    if n >= 2 and int.from_bytes(payload[:2], "big") == n - 2:
        return "length-prefixed-u16"
    return "opaque"


def infer_binary_framing(capture):
    """Infer the inner framing of a saved binary WebSocket capture (RFC 6455 frames in, leads out).

    ``capture`` is raw RFC 6455 frame bytes (or base64 text of them).  It reuses ``api_protocols`` to
    split the frames locally, then classifies each binary (opcode 0x2) payload's inner application
    framing -- a length prefix or a gRPC-web header -- and reports the consensus.  Opens no socket and
    returns only a lead.
    """
    if isinstance(capture, str):
        stripped = re.sub(r"\s+", "", capture)
        try:
            capture = base64.b64decode(stripped, validate=True)
        except Exception as exc:
            raise ProofChainError(f"binary capture is not base64: {exc}") from exc
    if not isinstance(capture, (bytes, bytearray, memoryview)):
        raise ProofChainError("binary capture must be bytes or base64 text")
    frames = _api.parse_websocket_frames(bytes(capture))
    binary = [f for f in frames if f.opcode == 0x2 and f.complete]
    per_frame = []
    kinds = set()
    for frame in binary:
        kind = _classify_payload_framing(frame.payload)
        per_frame.append({"index": frame.index, "bytes": len(frame.payload), "framing": kind,
                          "payload_sha256": frame.payload_sha256})
        kinds.add(kind)
    non_opaque = kinds - {"opaque"}
    if not binary:
        consensus = "no-binary-frames"
    elif len(non_opaque) == 1 and "opaque" not in kinds:
        consensus = next(iter(non_opaque))
    elif len(non_opaque) == 1:
        consensus = "mixed"
    elif not non_opaque:
        consensus = "opaque"
    else:
        consensus = "mixed"
    return {"frames": len(frames), "binary_frames": len(binary), "framing": consensus,
            "per_frame": per_frame, "note": "offline lead only -- never an answer"}


# ======================================================================================
#  5. Harness helpers
# ======================================================================================
def _safe_route(value, base_url):
    try:
        return _web.safe_same_origin_route(value, base_url, allow_query=False,
                                           guard_query=True, max_bytes=1024)
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
        out["response_headers"] = dict(raw.get("headers") or {})
        return out
    return None


def _as_preloaded(mapping):
    """Render a layer's ``{path: body}`` clue map into the ``{path: response}`` an engine consumes."""
    out = {}
    for path, body in list(mapping.items())[:MAX_PRELOADED]:
        if not isinstance(path, str) or "\x00" in path:
            continue
        if isinstance(body, dict) and ("body" in body or "status" in body or "text" in body):
            response = _response(body) if ("body" in body or "text" in body) else dict(body)
            if response is not None and "body" not in response:
                response["body"] = b""
            if response is not None:
                out[path] = response
            continue
        encoded = json.dumps(body, separators=(",", ":"), ensure_ascii=False,
                             default=str).encode("utf-8")
        out[path] = {"status": 200, "body": encoded,
                     "response_headers": {"Content-Type": "application/json"}}
    return out


def _clues_from(preloaded, base_url):
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


def _left(deadline):
    return None if deadline is None else float(deadline) - time.time()


def _text_of(response):
    if _proofs is not None and hasattr(_proofs, "response_text_views"):
        try:
            views = _proofs.response_text_views(response)
            return "\n".join(str(v) for v in views)[:MAX_BODY]
        except Exception:
            return ""
    body = response.get("body", response.get("text", "")) if isinstance(response, dict) else ""
    try:
        return (bytes(body).decode("utf-8", "replace") if isinstance(body, (bytes, bytearray))
                else str(body or ""))[:MAX_BODY]
    except Exception:
        return ""


def _extract_payoff(response, baselines, host):
    if _proofs is not None and hasattr(_proofs, "extract_success"):
        try:
            outcome = _proofs.extract_success(response, baselines, host=host)
            return outcome.get("auto"), list(outcome.get("candidates") or [])
        except Exception:
            return None, []
    # Minimal fallback: the unique payoff token not already seen in a baseline control.
    text = _text_of(response)
    seen = {m.group(0) for b in baselines for m in PAYOFF_SEEN.finditer(str(b or ""))}
    hits = list(dict.fromkeys(m.group(0) for m in PAYOFF_SEEN.finditer(text)
                              if m.group(0) not in seen))
    auto = hits[0] if len(hits) == 1 else None
    return auto, (hits[1:] if auto else hits)


# ======================================================================================
#  6. The harness driver
# ======================================================================================
class _Harness:
    def __init__(self, target, ctx):
        self.target = dict(target) if isinstance(target, dict) else {"url": str(target)}
        self.url = str(self.target.get("url") or "")
        self.aid = str(self.target.get("answer_id") or "target")
        self.ctx = dict(ctx or {})
        self.deadline = self.ctx.get("deadline")
        try:
            self.max_requests = max(0, int(self.ctx.get("max_requests", 0) or 0))
        except (TypeError, ValueError):
            self.max_requests = 0
        self.stop = self.ctx.get("stop")
        self.preloaded = dict(self.ctx.get("preloaded") or {})
        self.baselines = [str(v or "")[:MAX_BODY] for v in list(self.ctx.get("baseline_texts") or [])[:120]]
        self.route_allowed = self.ctx.get("route_allowed")
        self.counter = [0]
        self.layers_total = 0
        self.layers_solved = 0
        self.surfaced = []
        self.per_layer = []
        self.success = False
        self.terminal = False
        self.stopped = None
        self.chain = None
        self.final_proof = None

    def _can_send(self):
        if self.stop is not None and hasattr(self.stop, "is_set") and self.stop.is_set():
            self.stopped = self.stopped or "stopped"
            return False
        left = _left(self.deadline)
        if left is not None and left <= DEADLINE_PAD:
            self.stopped = self.stopped or "deadline"
            return False
        if self.counter[0] >= self.max_requests:
            self.stopped = self.stopped or "max_requests"
            return False
        return True

    def _dispatch(self, layer, engine):
        """Run one recognized layer through its engine with the chain-injecting client."""
        client = self.ctx.get("client")
        if client is None:
            return None, {"stopped": "no scoped client"}
        wrapped = _ChainClient(client, self.chain, self.counter)
        remaining = max(0, self.max_requests - self.counter[0])
        sub_sink = {}
        layer_target = dict(self.target)
        layer_target["answer_id"] = f"{self.aid}#L{layer.index}"
        layer_ctx = dict(self.ctx)
        layer_ctx.update({
            "client": wrapped,
            "preloaded": _as_preloaded(layer.preloaded),
            "baseline_texts": list(self.baselines),
            "max_requests": remaining,
            "result_sink": sub_sink,
            "deadline": self.deadline,
            "stop": self.stop,
            "route_allowed": self.route_allowed,
        })
        # A dispatched engine must never build its own direct client: the chain header would be lost.
        layer_ctx.pop("client_factory", None)
        before = self.counter[0]
        try:
            proof = engine.solve(layer_target, layer_ctx)
        except Exception as exc:  # noqa: BLE001 -- one layer's fault never crashes the walk
            return None, {"stopped": f"engine error: {type(exc).__name__}",
                          "requests": max(0, self.counter[0] - before)}
        summary = sub_sink.get(layer_target["answer_id"]) or sub_sink.get("target") or {}
        summary = dict(summary)
        summary.setdefault("requests", max(0, self.counter[0] - before))
        return proof, summary

    def run(self):
        clues = _clues_from(self.preloaded, self.url)
        try:
            protocol = ChainProtocol.from_clues(clues, self.url)
        except ProofChainError as exc:
            self.stopped = f"invalid proof-replay protocol: {exc}"
            self.terminal = True
            return None
        if protocol is None:
            self.stopped = "no proof-replay protocol"
            return None
        self.chain = protocol.new_chain()
        self.layers_total = len(protocol.layers)
        engine_name = {id(_recon_router): "recon_router", id(_realtime_read): "realtime_read",
                       id(_state_transaction): "state_transaction", id(_api_invoke): "api_invoke"}
        for layer in protocol.layers:
            if not self._can_send():
                self.surfaced.append({"index": layer.index, "class": layer.cls,
                                      "reason": f"budget/stop closed before this layer ({self.stopped})"})
                return None
            engine = engine_for(layer.cls)
            if engine is None:
                missing = _unavailable_engine(layer.cls)
                if missing is not None:
                    # Rule 6: a recognized class whose engine failed to import is a named, loud
                    # environment break -- never misattributed to the model as an unknown class.
                    self.surfaced.append({
                        "index": layer.index, "class": layer.cls,
                        "reason": f"engine unavailable: {missing} failed to import; this layer's "
                                  "class is recognized but cannot be dispatched",
                        "note": layer.note, "chain_depth": self.chain.depth,
                        "chain_header": self.chain.header_name})
                    self.terminal = True
                    return None
                # The core fallback: surface an unrecognized layer for the model and stop the walk.
                self.surfaced.append({
                    "index": layer.index, "class": layer.cls,
                    "reason": "unrecognized layer class; the harness dispatches only classes an "
                              "existing engine can execute -- the model must reason this layer",
                    "note": layer.note, "chain_depth": self.chain.depth,
                    "chain_header": self.chain.header_name})
                self.terminal = True
                return None
            proof, summary = self._dispatch(layer, engine)
            self.per_layer.append({"index": layer.index, "class": layer.cls,
                                   "engine": engine_name.get(id(engine), "?"),
                                   "success": bool(proof), "requests": summary.get("requests", 0),
                                   "stopped": summary.get("stopped")})
            if not proof:
                self.surfaced.append({
                    "index": layer.index, "class": layer.cls,
                    "engine": engine_name.get(id(engine), "?"),
                    "reason": "the dispatched engine did not close this layer; its summary is attached "
                              "for the model", "engine_stopped": summary.get("stopped"),
                    "candidates": list(summary.get("candidates") or [])[:8],
                    "chain_depth": self.chain.depth})
                self.terminal = True
                return None
            try:
                self.chain.append(layer.index, str(proof))
            except ProofChainError as exc:
                self.surfaced.append({"index": layer.index, "class": layer.cls,
                                      "reason": f"engine proof is not header-safe: {exc}"})
                self.terminal = True
                return None
            self.layers_solved += 1
        # Every layer solved: the chain is complete.
        return self._finish(protocol)

    def _finish(self, protocol):
        if protocol.final_route is None:
            # No replay route: the deepest proof is the chain's own answer.
            self.success = True
            self.terminal = True
            self.final_proof = self.chain.tokens[-1] if self.chain.tokens else None
            return self.final_proof
        if callable(self.route_allowed):
            try:
                if not bool(self.route_allowed(protocol.final_route)):
                    self.stopped = "route guard refused the final replay route"
                    self.terminal = True
                    return None
            except Exception:
                self.stopped = "route guard failed on the final replay route"
                self.terminal = True
                return None
        if not self._can_send():
            return None
        client = self.ctx.get("client")
        if client is None:
            self.stopped = "no scoped client for the final replay"
            return None
        wrapped = _ChainClient(client, self.chain, self.counter)
        try:
            response = wrapped.request("GET", protocol.final_route, allow_redirects=False)
        except Exception as exc:  # noqa: BLE001
            self.stopped = f"final replay transport: {type(exc).__name__}"
            self.terminal = True
            return None
        self.terminal = True
        auto, candidates = _extract_payoff(response, self.baselines,
                                           urllib.parse.urlsplit(self.url).hostname)
        if auto:
            self.success = True
            self.final_proof = str(auto)
            return self.final_proof
        if candidates:
            self.success = True
        self.stopped = self.stopped or "final replay yielded no unambiguous payoff"
        return None

    def result(self):
        baseline_proofs = list(dict.fromkeys(
            m.group(0) for t in self.baselines for m in PAYOFF_SEEN.finditer(str(t or ""))))[:24]
        return {
            "class": "proof_chain", "layers_total": self.layers_total,
            "layers_solved": self.layers_solved, "requests": self.counter[0],
            "success": self.success, "terminal": self.terminal, "stopped": self.stopped,
            "chain": (self.chain.snapshot() if self.chain is not None else None),
            "surfaced": self.surfaced[:16], "per_layer": self.per_layer[:MAX_LAYERS],
            "baseline_proofs": baseline_proofs,
        }


def _publish(harness, target, ctx):
    aid = str(target.get("answer_id") or "target") if isinstance(target, dict) else "target"
    summary = harness.result()
    sink = ctx.get("result_sink") if isinstance(ctx, dict) else None
    if isinstance(sink, dict):
        sink[aid] = summary
    evidence = ctx.get("evidence") if isinstance(ctx, dict) else None
    if isinstance(evidence, list):
        line = _web.safe_display_text(
            f"WEB PROOF-CHAIN: layers {summary['layers_solved']}/{summary['layers_total']} "
            f"requests={summary['requests']} success={summary['success']} "
            f"surfaced={len(summary['surfaced'])}", 500)
        if line not in evidence:
            evidence.append(line)


def solve(target, ctx=None):
    """Walk a proof-replay gauntlet: maintain the ordered proof header, dispatch recognizable layers
    to the matching engine, surface the rest, and return the terminal payoff when the chain completes.
    """
    ctx = dict(ctx or {})
    harness = _Harness(target, ctx)
    proof = None
    try:
        proof = harness.run()
    except Exception as exc:  # noqa: BLE001
        harness.stopped = harness.stopped or f"error: {type(exc).__name__}"
    _publish(harness, target, ctx)
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


# ======================================================================================
#  CLI (offline mesh triage: subprotocol negotiation + binary framing; leads only)
# ======================================================================================
def _main(argv):
    args = [a for a in argv if a != "--json"]
    as_json = "--json" in argv
    if not args:
        print(__doc__)
        return 64
    reports = {}
    for path in args:
        try:
            # Read untrusted saved descriptors as bytes; this never executes challenge code.
            raw = Path(path).read_bytes()
            descriptor = json.loads(raw.decode("utf-8", "replace"))
        except (OSError, ValueError) as exc:
            print(f"skip {path}: {exc}", file=sys.stderr)
            continue
        report = {}
        if isinstance(descriptor, dict):
            offered = descriptor.get("offered")
            if offered is not None:
                try:
                    report["subprotocol"] = negotiate_subprotocol(offered, descriptor.get("selected"))
                except ProofChainError as exc:
                    report["subprotocol"] = {"error": str(exc)}
            capture = descriptor.get("frames_b64") or descriptor.get("capture")
            if capture is not None:
                try:
                    report["framing"] = infer_binary_framing(capture)
                except (ProofChainError, _api.APIProtocolError) as exc:
                    report["framing"] = {"error": str(exc)}
        reports[Path(path).name] = report or {"note": "no 'offered' or 'frames_b64' field found"}
    if as_json:
        print(json.dumps(reports, indent=2, default=str))
        return 0
    for name, report in reports.items():
        print(f"PROOF-CHAIN MESH {name} (leads only -- never an answer):")
        sub = report.get("subprotocol")
        if sub:
            print(f"  subprotocol: {sub.get('status')} agreed={sub.get('agreed')!r} "
                  f"-- {sub.get('reason', sub.get('error'))}")
        framing = report.get("framing")
        if framing:
            print(f"  framing: {framing.get('framing')} over {framing.get('binary_frames')} "
                  f"binary frame(s) -- {framing.get('note', framing.get('error'))}")
        if not sub and not framing:
            print(f"  {report.get('note', '')}")
    return 0


__all__ = ["ProofChain", "ProofChainError", "ChainProtocol", "engine_for",
           "negotiate_subprotocol", "infer_binary_framing", "solve", "solve_targets"]


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
