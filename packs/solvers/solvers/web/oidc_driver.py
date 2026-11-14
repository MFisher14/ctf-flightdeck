#!/usr/bin/env python3
"""OIDC / OAuth2 authorization-code flow driver for a scope-locked live web target (B-183).

The web ``oidc`` class stayed recon-only after every build: inventory the discovery metadata, the
signing algorithms and the same-origin JWKs, but no login, no code exchange, no token replay. This
driver moves past recon when the player authorises it: it drives a real authorization-code flow --
discovery, the authorization request (with ``state``, ``nonce`` and PKCE S256), capture of the code
from the redirect, and the code->token exchange -- against hosts the event profile puts in scope.

Every endpoint it touches is checked against the event profile's ``rules.live_service_scope`` (no
external issuer contact: an authorization or token endpoint on an out-of-scope host is refused before
any connection). Discovery keys the driver never contacts (jwks_uri, userinfo, end_session, ...) are
recorded with their scope verdict in ``endpoint_scope`` rather than aborting the drive. Each origin gets its own scope-locked ``solvers.toolkits.web.WebClient``, so a flow
that spans an app host and an IdP host stays locked to exactly those. The *reads* -- discovery and
the authorization GET -- always run. The *state-changing* steps -- a login POST and the token-exchange
POST -- run only when ``rules.web_state_changing`` is true (Open O-2); otherwise the driver refuses,
naming the rule. Nothing here verifies a signature or auto-submits: the id_token is decoded for its
claims (which may carry the flag) and returned for the player. The id_token ``nonce`` claim is
compared with the nonce the driver sent; a mismatch or a missing claim is recorded as a named finding
(``OIDCResult.findings``) -- for an attacker-side client a replayed id_token is evidence, not a stop.
Target JSON (discovery, token response) is parsed fail-closed through solvers/web/security_json.py.

The pure builders (``generate_pkce``, ``build_authorization_request``, ``parse_discovery``,
``parse_authorization_redirect``, ``build_token_request``, ``parse_token_response``) take no network
and are unit-testable on their own. ``OIDCDriver`` wires them onto the live clients.

Library engine: import it; ``ctf run`` refuses a library engine.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

try:  # package import
    from ctf import scope as _scope
except Exception:  # pragma: no cover - direct solver-directory import
    import sys as _sys

    _root = Path(__file__).resolve().parents[2]
    if str(_root) not in _sys.path:
        _sys.path.insert(0, str(_root))
    from ctf import scope as _scope

try:  # package import
    from ..toolkits import web as _web  # type: ignore
except Exception:  # pragma: no cover - direct solver-directory import
    try:
        import web as _web  # type: ignore
        # `web` can also be solvers/web itself (imported as the package `web`, solvers/ on sys.path,
        # as the import gate does): that is not the toolkit, so load the toolkit by file instead.
        _web.WebClient  # noqa: B018
    except Exception:
        import importlib.util as _ilu
        import sys as _sys2

        _spec = _ilu.spec_from_file_location(
            "_oidc_web", Path(__file__).resolve().parents[1] / "toolkits" / "web.py")
        _web = _ilu.module_from_spec(_spec)  # type: ignore[assignment]
        _sys2.modules[_spec.name] = _web
        _spec.loader.exec_module(_web)  # type: ignore[union-attr]

try:  # package import
    from . import flow_recorder as _flow  # type: ignore
except Exception:  # pragma: no cover - direct solver-directory import
    try:
        import flow_recorder as _flow  # type: ignore  # flat import (conftest puts solvers/web on path)
    except Exception:
        import importlib.util as _ilu2
        import sys as _sys3

        _spec2 = _ilu2.spec_from_file_location(
            "_oidc_flow", Path(__file__).resolve().parent / "flow_recorder.py")
        _flow = _ilu2.module_from_spec(_spec2)  # type: ignore[assignment]
        _sys3.modules[_spec2.name] = _flow
        _spec2.loader.exec_module(_flow)  # type: ignore[union-attr]


DEFAULT_DISCOVERY_PATH = "/.well-known/openid-configuration"
DEFAULT_USER_AGENT = "ctf-tools-oidc-driver/1"   # neutral: master code is not event-branded
MAX_DISCOVERY_BYTES = 1 << 20
MAX_TOKEN_RESPONSE_BYTES = 1 << 20
# The discovery endpoints the driver contacts: these must be in scope or the drive is refused.
CONTACTED_ENDPOINT_KEYS = ("authorization_endpoint", "token_endpoint")
# Discovery keys the driver records but never contacts: their scope verdict is reported, not enforced.
RECORDED_ENDPOINT_KEYS = ("userinfo_endpoint", "jwks_uri", "registration_endpoint",
                          "end_session_endpoint", "introspection_endpoint", "revocation_endpoint",
                          "issuer")
ENDPOINT_KEYS = CONTACTED_ENDPOINT_KEYS + RECORDED_ENDPOINT_KEYS


class OIDCError(ValueError):
    """A malformed discovery document, redirect or token response. The message is one line."""


# ------------------------------------------------------------------------ pure builders (no network)

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def generate_pkce(code_verifier: str | None = None) -> dict:
    """A PKCE pair: a high-entropy ``code_verifier`` and its S256 ``code_challenge`` (RFC 7636).

    A supplied verifier is used as given (43-128 chars of the unreserved set); otherwise one is
    minted. The challenge is base64url(sha256(verifier)) with no padding."""
    if code_verifier is None:
        code_verifier = _b64url(secrets.token_bytes(48))  # 64 unreserved chars
    verifier = str(code_verifier)
    if not 43 <= len(verifier) <= 128:
        raise OIDCError(f"PKCE code_verifier must be 43-128 characters, got {len(verifier)}")
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return {"code_verifier": verifier, "code_challenge": challenge, "code_challenge_method": "S256"}


def generate_state() -> str:
    return _b64url(secrets.token_bytes(18))


def generate_nonce() -> str:
    return _b64url(secrets.token_bytes(18))


def _is_abs_http(url: str) -> bool:
    parts = urllib.parse.urlsplit(str(url or ""))
    return parts.scheme.lower() in ("http", "https") and bool(parts.hostname)


def parse_discovery(doc, *, scope_check: bool = True, profile=None) -> dict:
    """Normalise an OIDC discovery document to its endpoint map.

    `doc` is the JSON text, bytes, or an already-parsed dict; text is parsed fail-closed (duplicate
    or colliding keys, hostile nesting -> OIDCError). The endpoints the driver contacts
    (``CONTACTED_ENDPOINT_KEYS``) must be absolute http(s) URLs and, when `scope_check` is true, pass
    ``ctf.scope.check_url`` against rules.live_service_scope, so an out-of-scope authorization or
    token endpoint raises OutOfScope here, before any connection. The other endpoint keys are never
    contacted: each is recorded with its verdict in ``endpoint_scope`` (``in-scope`` /
    ``out-of-scope`` / ``not-checked``), and a non-URL value is listed in ``invalid_endpoints``.
    Also carries ``response_types_supported`` / ``code_challenge_methods_supported`` /
    ``id_token_signing_alg_values_supported`` (and a few more lists) when present."""
    if isinstance(doc, (bytes, bytearray, str)):
        try:
            doc = _flow.parse_target_json(doc, max_chars=MAX_DISCOVERY_BYTES,
                                          what="discovery document")
        except ValueError as e:
            raise OIDCError(str(e)) from e
    if not isinstance(doc, dict):
        raise OIDCError("discovery document is not a JSON object")

    out: dict = {}
    endpoint_scope: dict = {}
    invalid: list = []
    for key in CONTACTED_ENDPOINT_KEYS:
        value = doc.get(key)
        if value is None:
            continue
        if not isinstance(value, str) or not _is_abs_http(value):
            raise OIDCError(f"discovery {key} is not an absolute http(s) URL: {value!r}")
        if scope_check:
            _scope.check_url(value, what=f"OIDC discovery {key} {value!r}", profile=profile,
                             error=_web.OutOfScope)
            endpoint_scope[key] = "in-scope"
        else:
            endpoint_scope[key] = "not-checked"
        out[key] = value
    for key in RECORDED_ENDPOINT_KEYS:
        value = doc.get(key)
        if value is None:
            continue
        if not isinstance(value, str) or not _is_abs_http(value):
            invalid.append(key)
            continue
        if scope_check:
            try:
                _scope.check_url(value, what=f"OIDC discovery {key} {value!r}", profile=profile,
                                 error=_web.OutOfScope)
                endpoint_scope[key] = "in-scope"
            except _scope.OutOfScope:
                endpoint_scope[key] = "out-of-scope"
        else:
            endpoint_scope[key] = "not-checked"
        out[key] = value
    out["endpoint_scope"] = endpoint_scope
    if invalid:
        out["invalid_endpoints"] = invalid
    for key in ("response_types_supported", "code_challenge_methods_supported",
                "id_token_signing_alg_values_supported", "scopes_supported",
                "grant_types_supported", "token_endpoint_auth_methods_supported"):
        if isinstance(doc.get(key), list):
            out[key] = [str(x) for x in doc[key]]
    if "authorization_endpoint" not in out or "token_endpoint" not in out:
        raise OIDCError("discovery document lacks an authorization_endpoint or token_endpoint")
    return out


def build_authorization_request(authorization_endpoint: str, *, client_id: str, redirect_uri: str,
                                scope: str = "openid", state: str, nonce: str | None = None,
                                code_challenge: str | None = None,
                                code_challenge_method: str = "S256", response_type: str = "code",
                                extra: dict | None = None, scope_check: bool = True,
                                profile=None) -> str:
    """The full authorization-request URL (query appended to the endpoint).

    When `scope_check` is true the endpoint is checked against rules.live_service_scope first."""
    if not _is_abs_http(authorization_endpoint):
        raise OIDCError(f"authorization_endpoint is not an absolute http(s) URL: {authorization_endpoint!r}")
    if scope_check:
        _scope.check_url(authorization_endpoint, what="OIDC authorization_endpoint",
                         profile=profile, error=_web.OutOfScope)
    params = [("response_type", response_type), ("client_id", client_id),
              ("redirect_uri", redirect_uri), ("scope", scope), ("state", state)]
    if nonce is not None:
        params.append(("nonce", nonce))
    if code_challenge is not None:
        params.append(("code_challenge", code_challenge))
        params.append(("code_challenge_method", code_challenge_method))
    for key, value in (extra or {}).items():
        params.append((str(key), str(value)))
    parts = urllib.parse.urlsplit(authorization_endpoint)
    merged = urllib.parse.parse_qsl(parts.query, keep_blank_values=True) + params
    query = urllib.parse.urlencode(merged)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def parse_authorization_redirect(location: str, *, expected_state: str | None = None) -> dict:
    """Pull ``code``/``state``/``error`` from the authorization redirect's Location (query or fragment).

    When `expected_state` is given and the returned state differs, raises OIDCError (a CSRF / IdP
    mix-up stop): the code is never returned under a mismatched state."""
    if not location:
        raise OIDCError("no authorization redirect Location to parse")
    parts = urllib.parse.urlsplit(location)
    fields = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
    if parts.fragment:
        fields.update(urllib.parse.parse_qsl(parts.fragment, keep_blank_values=True))
    if fields.get("error"):
        raise OIDCError(f"authorization endpoint returned error={fields['error']} "
                        f"{fields.get('error_description', '')}".strip())
    state = fields.get("state")
    if expected_state is not None and state != expected_state:
        raise OIDCError(f"authorization redirect state {state!r} does not match the request state "
                        f"{expected_state!r}: refusing the code (possible CSRF / IdP mix-up)")
    if not fields.get("code"):
        raise OIDCError(f"authorization redirect carries no code: {sorted(fields)}")
    return {"code": fields["code"], "state": state,
            "iss": fields.get("iss"), "fields": fields}


def build_token_request(token_endpoint: str, *, code: str, redirect_uri: str, client_id: str,
                        code_verifier: str | None = None, client_secret: str | None = None,
                        grant_type: str = "authorization_code", extra: dict | None = None,
                        scope_check: bool = True, profile=None) -> tuple:
    """(url, body, headers) for the code->token exchange POST.

    The body is ``application/x-www-form-urlencoded``. When `scope_check` is true the endpoint is
    checked against rules.live_service_scope first."""
    if not _is_abs_http(token_endpoint):
        raise OIDCError(f"token_endpoint is not an absolute http(s) URL: {token_endpoint!r}")
    if scope_check:
        _scope.check_url(token_endpoint, what="OIDC token_endpoint", profile=profile,
                         error=_web.OutOfScope)
    form = [("grant_type", grant_type), ("code", code), ("redirect_uri", redirect_uri),
            ("client_id", client_id)]
    if code_verifier is not None:
        form.append(("code_verifier", code_verifier))
    if client_secret is not None:
        form.append(("client_secret", client_secret))
    for key, value in (extra or {}).items():
        form.append((str(key), str(value)))
    headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
    return token_endpoint, urllib.parse.urlencode(form), headers


def parse_token_response(doc) -> dict:
    """Parse a token-endpoint response. Decodes (never verifies) an ``id_token`` for its claims."""
    if isinstance(doc, (bytes, bytearray, str)):
        try:
            doc = _flow.parse_target_json(doc, max_chars=MAX_TOKEN_RESPONSE_BYTES,
                                          what="token response")
        except ValueError as e:
            raise OIDCError(str(e)) from e
    if not isinstance(doc, dict):
        raise OIDCError("token response is not a JSON object")
    if doc.get("error"):
        raise OIDCError(f"token endpoint returned error={doc['error']} "
                        f"{doc.get('error_description', '')}".strip())
    out = {k: doc.get(k) for k in ("access_token", "token_type", "expires_in", "refresh_token",
                                   "id_token", "scope") if doc.get(k) is not None}
    if out.get("id_token"):
        decoded = _web.decode_jwt(str(out["id_token"]))
        if decoded is not None:
            out["id_token_claims"] = decoded.get("payload")
            out["id_token_header"] = decoded.get("header")
    return out


# --------------------------------------------------------------------------------- the live driver

@dataclass
class OIDCResult:
    endpoints: dict = field(default_factory=dict)
    state: str | None = None
    nonce: str | None = None
    code: str | None = None
    tokens: dict = field(default_factory=dict)
    flags: list = field(default_factory=list)
    transcript: list = field(default_factory=list)
    # Named findings for the player, e.g. {"name": "id_token_nonce_mismatch", ...}.
    findings: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"endpoints": self.endpoints, "state": self.state, "nonce": self.nonce,
                "code": self.code, "tokens": self.tokens, "flags": list(self.flags),
                "transcript": self.transcript, "findings": list(self.findings)}


def check_id_token_nonce(tokens: dict, sent_nonce: str | None) -> dict | None:
    """Compare the id_token's ``nonce`` claim with the nonce the request sent.

    Returns None when they match (or when there is no id_token to check), else a named finding:
    ``id_token_undecodable``, ``id_token_nonce_missing`` (the claim is absent) or
    ``id_token_nonce_mismatch``."""
    if not tokens.get("id_token") or sent_nonce is None:
        return None
    claims = tokens.get("id_token_claims")
    if not isinstance(claims, dict):
        return {"name": "id_token_undecodable",
                "detail": "the id_token could not be decoded, so its nonce was not checked"}
    if "nonce" not in claims:
        return {"name": "id_token_nonce_missing", "sent": sent_nonce,
                "detail": "the id_token carries no nonce claim (replay protection absent)"}
    if claims.get("nonce") != sent_nonce:
        return {"name": "id_token_nonce_mismatch", "sent": sent_nonce,
                "received": claims.get("nonce"),
                "detail": "the id_token nonce differs from the request nonce (replayed or "
                          "mixed-up token)"}
    return None


class OIDCDriver:
    """Drive an authorization-code flow against in-scope hosts.

    `issuer_base_url` is the issuer/application origin (where discovery lives). Each origin the flow
    touches gets its own scope-locked WebClient, built through the scope guard, so an out-of-scope
    endpoint is refused before any connection. State-changing steps obey the O-2 gate
    (rules.web_state_changing)."""

    def __init__(self, issuer_base_url, *, client_id: str, redirect_uri: str, scope: str = "openid",
                 client_secret: str | None = None, timeout: float = 10.0,
                 user_agent: str = DEFAULT_USER_AGENT):
        self.issuer_base_url = issuer_base_url
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.scope = scope
        self.client_secret = client_secret
        self.timeout = timeout
        self.user_agent = user_agent
        self._clients: dict[tuple, object] = {}
        self._base_client = self._client_for(issuer_base_url)

    def _origin(self, url) -> tuple:
        parts = urllib.parse.urlsplit(str(url))
        host = (parts.hostname or "").lower()
        port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
        return parts.scheme.lower(), host, port

    def _client_for(self, url):
        """A WebClient locked to `url`'s origin, reused per origin. Built GET-only unless the O-2
        gate allows state changes, so even a direct use cannot mutate the target."""
        key = self._origin(url)
        if key not in self._clients:
            host = f"[{key[1]}]" if ":" in key[1] else key[1]  # an IPv6 literal keeps its brackets
            origin = urllib.parse.urlunsplit((key[0], f"{host}:{key[2]}", "/", "", ""))
            get_only = not _flow.state_changes_allowed()
            self._clients[key] = _web.WebClient(origin, timeout=self.timeout,
                                                user_agent=self.user_agent, get_only=get_only)
        return self._clients[key]

    def discover(self, discovery_path: str = DEFAULT_DISCOVERY_PATH, *, result: OIDCResult | None = None) -> dict:
        """GET the discovery document (a read) and return its scope-checked endpoint map."""
        resp = self._base_client.request("GET", discovery_path, allow_redirects=True)
        if result is not None:
            result.transcript.append({"step": "discover", "url": resp.get("url"),
                                      "status": resp.get("status")})
        endpoints = parse_discovery(resp.get("body") or b"")
        return endpoints

    def authorize(self, endpoints: dict, *, state: str, nonce: str, pkce: dict,
                  login_flow=None, login_seed: dict | None = None,
                  result: OIDCResult | None = None) -> dict:
        """Drive the authorization request and capture the redirect code.

        The authorization GET is a read. When the IdP needs a login first, pass `login_flow` (a
        flow_recorder step list); it runs on the authorization endpoint's origin and obeys the O-2
        gate, then the authorization GET is retried once. The login runs whenever the answer is not
        the code redirect (a 3xx whose Location carries ``code``/``error`` or points at
        redirect_uri), so a 302 to the IdP's own login page triggers it and an already-issued code
        skips it. If the final answer is still not the code redirect, OIDCError names that. A login sub-flow that stops (an
        ``expect_status`` mismatch) raises OIDCError naming its stop reason; its steps are appended
        to ``result.transcript`` as ``login:<step name>`` entries."""
        auth_url = build_authorization_request(
            endpoints["authorization_endpoint"], client_id=self.client_id,
            redirect_uri=self.redirect_uri, scope=self.scope, state=state, nonce=nonce,
            code_challenge=pkce["code_challenge"], code_challenge_method=pkce["code_challenge_method"])
        client = self._client_for(endpoints["authorization_endpoint"])

        def fetch():
            return client.request("GET", auth_url, allow_redirects=False)

        resp = fetch()
        location = _flow._header(resp, "Location")
        if login_flow and not self._is_code_redirect(resp, location, auth_url):
            # The IdP served a login page, or redirected to its own login page (the usual IdP
            # behaviour), instead of redirecting to redirect_uri: run the login sub-flow (state
            # changing, O-2 gated) on this origin, then retry the authorization request once.
            # An already-issued code (a live IdP session) skips the login.
            login_result = _flow.run_flow(client, login_flow, seed=login_seed or {}, flag_scan=False)
            if result is not None:
                for entry in login_result.transcript:
                    result.transcript.append({"step": f"login:{entry['name']}", "url": entry.get("url"),
                                              "status": entry.get("status")})
            if not login_result.completed:
                raise OIDCError(f"the IdP login sub-flow stopped before the authorization retry: "
                                f"{login_result.stopped_reason}")
            resp = fetch()
            location = _flow._header(resp, "Location")
        if result is not None:
            result.transcript.append({"step": "authorize", "url": resp.get("url"),
                                      "status": resp.get("status"), "location": location})
        if not self._is_code_redirect(resp, location, auth_url):
            shown = (location or "")[:200]
            hint = ("even after the login sub-flow ran" if login_flow
                    else "the IdP likely needs a login first: pass login_flow")
            raise OIDCError(f"the authorization endpoint answered {resp.get('status')} with Location "
                            f"{shown!r}, not a redirect to redirect_uri carrying code or error: {hint}")
        parsed = parse_authorization_redirect(location, expected_state=state)
        return parsed

    _REDIRECT_STATUSES = (301, 302, 303, 307, 308)

    def _is_code_redirect(self, resp: dict, location, auth_url: str) -> bool:
        """True when `resp` is the authorization redirect back to the client: a 3xx whose Location
        carries ``code`` or ``error`` (query or fragment), or points at redirect_uri. A 3xx to
        anywhere else (the IdP's own /login page) or a 200 login page is not."""
        if resp.get("status") not in self._REDIRECT_STATUSES or not location:
            return False
        target = urllib.parse.urlsplit(urllib.parse.urljoin(auth_url, str(location)))
        fields = dict(urllib.parse.parse_qsl(target.query, keep_blank_values=True))
        if target.fragment:
            fields.update(urllib.parse.parse_qsl(target.fragment, keep_blank_values=True))
        if "code" in fields or "error" in fields:
            return True
        want = urllib.parse.urlsplit(self.redirect_uri)
        return (self._origin(target.geturl()) == self._origin(self.redirect_uri)
                and (target.path or "/") == (want.path or "/"))

    def exchange(self, endpoints: dict, *, code: str, pkce: dict,
                 result: OIDCResult | None = None) -> dict:
        """POST the code->token exchange (a state-changing action, O-2 gated) and parse the tokens."""
        if not _flow.state_changes_allowed():
            raise _flow.StateChangeRefused(
                "OIDC code->token exchange is a POST (a state-changing web action) but "
                f"event {_flow._active_profile().slug!r} has rules.web_state_changing = "
                "false (Open O-2): set it true in the event profile only with the player's yes")
        url, body, headers = build_token_request(
            endpoints["token_endpoint"], code=code, redirect_uri=self.redirect_uri,
            client_id=self.client_id, code_verifier=pkce["code_verifier"],
            client_secret=self.client_secret)
        client = self._client_for(url)
        resp = client.request("POST", url, data=body, headers=headers, allow_redirects=False)
        if result is not None:
            result.transcript.append({"step": "exchange", "url": resp.get("url"),
                                      "status": resp.get("status")})
        tokens = parse_token_response(resp.get("body") or b"")
        return tokens

    def drive(self, *, discovery_path: str = DEFAULT_DISCOVERY_PATH, login_flow=None,
              login_seed: dict | None = None) -> OIDCResult:
        """Run discovery -> authorize -> exchange and return the full OIDCResult.

        The reads (discovery, authorize) always run; the exchange runs only when the O-2 gate allows
        it (otherwise StateChangeRefused is raised at the exchange). Flags seen in the id_token claims
        are collected for the player; nothing is submitted."""
        result = OIDCResult()
        result.endpoints = self.discover(discovery_path, result=result)
        result.state = generate_state()
        result.nonce = generate_nonce()
        pkce = generate_pkce()
        parsed = self.authorize(result.endpoints, state=result.state, nonce=result.nonce,
                                pkce=pkce, login_flow=login_flow, login_seed=login_seed,
                                result=result)
        result.code = parsed["code"]
        result.tokens = self.exchange(result.endpoints, code=result.code, pkce=pkce, result=result)
        finding = check_id_token_nonce(result.tokens, result.nonce)
        if finding is not None:
            result.findings.append(finding)
        result.flags = sorted(_web.find_flags(json.dumps(result.tokens.get("id_token_claims") or {})))
        if result.tokens.get("access_token"):
            result.flags = sorted(set(result.flags)
                                  | _web.find_flags(str(result.tokens.get("access_token"))))
        return result
