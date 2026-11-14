#!/usr/bin/env python3
"""Offline WebAuthn, identity trust-boundary, and API authorization depth.

This complements :mod:`identity_flows` and :mod:`api_protocols` rather
than replacing them.  Inputs are bounded saved metadata/text.  JSON-like data
is inspected lexically, authenticator data is only split at fixed byte offsets,
and no signature verification, signing, decryption, fetch, socket, browser,
process, schema runtime, or unsafe deserializer is used.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import re
from typing import Iterable, Sequence
from urllib.parse import parse_qsl, urlsplit


MAX_TEXT_BYTES = 2_000_000
MAX_FIELDS = 512
MAX_VALUE = 131_072
MAX_BINARY = 1_000_000
MAX_FINDINGS = 512
MAX_QUERY_FIELDS = 1024


class IdentityAPIDepthError(ValueError):
    """Raised for malformed or over-limit saved evidence."""


@dataclass(frozen=True)
class DepthFinding:
    finding_id: str
    family: str
    title: str
    severity: str
    confidence: str
    evidence: tuple[str, ...]
    remediation: str


@dataclass(frozen=True)
class InertPlan:
    rank: int
    family: str
    name: str
    artifact: str
    hypothesis: str
    inert: bool = True
    offline: bool = True
    network_requests: int = 0


def _utf8_size(value: str, label: str) -> int:
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise IdentityAPIDepthError(f"{label} is not valid UTF-8 text") from exc


def _text(value: str | bytes | bytearray | memoryview, label: str) -> str:
    if isinstance(value, str):
        text = value
        size = _utf8_size(text, label)
    elif isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        size = len(raw)
        text = raw.decode("utf-8", "replace")
    else:
        raise IdentityAPIDepthError(f"{label} must be text or bytes")
    if size > MAX_TEXT_BYTES:
        raise IdentityAPIDepthError(f"{label} exceeds {MAX_TEXT_BYTES} bytes")
    if "\x00" in text:
        raise IdentityAPIDepthError(f"{label} contains NUL")
    return text


def _pairs(fields: Sequence[tuple[str, str]], label: str) -> tuple[tuple[str, str], ...]:
    if not isinstance(fields, Sequence) or isinstance(fields, (str, bytes, bytearray)):
        raise IdentityAPIDepthError(f"{label} must be a sequence of pairs")
    if len(fields) > MAX_FIELDS:
        raise IdentityAPIDepthError(f"{label} field count exceeds {MAX_FIELDS}")
    result: list[tuple[str, str]] = []
    for item in fields:
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            raise IdentityAPIDepthError(f"{label} contains a non-pair")
        name, value = item
        if (not isinstance(name, str) or not name or len(name) > 128
                or any(char in name for char in "\r\n\x00")):
            raise IdentityAPIDepthError(f"{label} contains an invalid field name")
        _utf8_size(name, f"{label} field name")
        if not isinstance(value, str):
            raise IdentityAPIDepthError(f"{label} field {name!r} is invalid or over cap")
        if (_utf8_size(value, f"{label} field {name!r}") > MAX_VALUE
                or any(char in value for char in "\r\n\x00")):
            raise IdentityAPIDepthError(f"{label} field {name!r} is invalid or over cap")
        result.append((name, value))
    return tuple(result)


def _values(fields: Sequence[tuple[str, str]], name: str) -> tuple[str, ...]:
    wanted = name.casefold()
    return tuple(value for key, value in fields if key.casefold() == wanted)


def _one(fields: Sequence[tuple[str, str]], name: str) -> str | None:
    values = _values(fields, name)
    return values[0] if len(values) == 1 else None


def _b64u(value: str, label: str) -> bytes:
    if not isinstance(value, str) or len(value) > (MAX_BINARY * 2):
        raise IdentityAPIDepthError(f"{label} is over cap")
    if not re.fullmatch(r"[A-Za-z0-9_-]*={0,2}", value):
        raise IdentityAPIDepthError(f"{label} is not base64url")
    try:
        result = base64.urlsafe_b64decode(value.rstrip("=") + "=" * (-len(value.rstrip("=")) % 4))
    except (ValueError, binascii.Error) as exc:
        raise IdentityAPIDepthError(f"{label} is not valid base64url") from exc
    if len(result) > MAX_BINARY:
        raise IdentityAPIDepthError(f"{label} decodes beyond {MAX_BINARY} bytes")
    return result


def _lexical_json_fields(text: str) -> tuple[tuple[str, str], ...]:
    """Extract bounded string/bool/number members without loading JSON."""

    rows: list[tuple[str, str]] = []
    pattern = re.compile(
        r'"([A-Za-z_][A-Za-z0-9_.-]{0,127})"\s*:\s*'
        r'(?:("(?:[^"\\]|\\.){0,65536}")|(true|false|null|-?[0-9]{1,20}))'
    )
    for match in pattern.finditer(text):
        if len(rows) >= MAX_FIELDS:
            raise IdentityAPIDepthError(f"lexical JSON field count exceeds {MAX_FIELDS}")
        raw_string, scalar = match.group(2), match.group(3)
        if raw_string is not None:
            value = re.sub(r'\\(["\\/])', r'\1', raw_string[1:-1])
        else:
            value = scalar
        rows.append((match.group(1), value))
    return tuple(rows)


def analyze_webauthn_ceremony(fields: Sequence[tuple[str, str]], *, ceremony: str,
                              expected_challenge: str | None = None,
                              expected_origin: str | None = None,
                              expected_rp_id_hash: str | bytes | None = None,
                              previous_sign_count: int | None = None,
                              expected_user_handle: str | None = None) -> tuple[DepthFinding, ...]:
    """Correlate saved WebAuthn registration/assertion metadata."""

    rows = _pairs(fields, "WebAuthn fields")
    if ceremony not in {"registration", "assertion"}:
        raise IdentityAPIDepthError("ceremony must be registration or assertion")
    for label, value in (("expected_challenge", expected_challenge),
                         ("expected_origin", expected_origin),
                         ("expected_user_handle", expected_user_handle)):
        if value is not None:
            if (not isinstance(value, str)
                    or _utf8_size(value, label) > MAX_VALUE
                    or any(char in value for char in "\r\n\x00")):
                raise IdentityAPIDepthError(f"{label} is invalid or over cap")
    if previous_sign_count is not None and (not isinstance(previous_sign_count, int) or previous_sign_count < 0):
        raise IdentityAPIDepthError("previous_sign_count must be a non-negative integer")
    if isinstance(expected_rp_id_hash, str) and len(expected_rp_id_hash) != 64:
        raise IdentityAPIDepthError("expected_rp_id_hash must contain 32 bytes")
    if isinstance(expected_rp_id_hash, bytes) and len(expected_rp_id_hash) != 32:
        raise IdentityAPIDepthError("expected_rp_id_hash must contain 32 bytes")
    if expected_rp_id_hash is not None and not isinstance(expected_rp_id_hash, (str, bytes)):
        raise IdentityAPIDepthError("expected_rp_id_hash must be hex text or bytes")
    findings: list[DepthFinding] = []

    def add(code: str, title: str, severity: str, confidence: str,
            evidence: Iterable[str], remediation: str) -> None:
        if len(findings) >= MAX_FINDINGS:
            raise IdentityAPIDepthError("finding cap exceeded")
        findings.append(DepthFinding(code, "webauthn", title, severity, confidence,
                                     tuple(evidence), remediation))

    for name in sorted({name.casefold() for name, _value in rows}):
        values = _values(rows, name)
        if len(values) > 1:
            add(f"webauthn-duplicate-{name}", "Duplicate WebAuthn metadata field", "high", "high",
                (f"{name}: {values!r}",), "Reject duplicate credential/client metadata before verification.")
    client_value = _one(rows, "clientDataJSON")
    if client_value is None:
        add("webauthn-client-data-cardinality", "clientDataJSON is missing or ambiguous", "high", "high",
            (f"count: {len(_values(rows, 'clientDataJSON'))}",),
            "Require one clientDataJSON and bind its type, challenge, and origin.")
        client_fields: tuple[tuple[str, str], ...] = ()
    else:
        client_raw = _b64u(client_value, "clientDataJSON")
        client_text = client_raw.decode("utf-8", "replace")
        client_fields = _lexical_json_fields(client_text)
        for name in ("type", "challenge", "origin", "crossOrigin"):
            values = _values(client_fields, name)
            if len(values) > 1:
                add(f"webauthn-client-duplicate-{name}", "clientDataJSON repeats a binding field", "high", "high",
                    (f"{name}: {values!r}",), "Use a duplicate-rejecting JSON parser before WebAuthn validation.")
        expected_type = "webauthn.create" if ceremony == "registration" else "webauthn.get"
        if _one(client_fields, "type") != expected_type:
            add("webauthn-type-mismatch", "WebAuthn client-data type mismatches ceremony", "high", "high",
                (f"observed {_one(client_fields, 'type')!r}", f"expected {expected_type!r}"),
                "Bind the client-data type to the server-side ceremony state.")
        if expected_challenge is not None and _one(client_fields, "challenge") != expected_challenge:
            add("webauthn-challenge-mismatch", "Challenge does not match saved ceremony state", "critical", "high",
                (f"observed {_one(client_fields, 'challenge')!r}",),
                "Require the exact single-use server challenge and invalidate it after completion.")
        if expected_origin is not None and _one(client_fields, "origin") != expected_origin:
            add("webauthn-origin-mismatch", "WebAuthn origin differs from expected origin", "critical", "high",
                (f"observed {_one(client_fields, 'origin')!r}", f"expected {expected_origin!r}"),
                "Require exact scheme/host/effective-port origin binding.")
        if (_one(client_fields, "crossOrigin") or "false").casefold() == "true":
            add("webauthn-cross-origin", "clientDataJSON records a cross-origin ceremony", "high", "high",
                ("crossOrigin=true",), "Allow cross-origin ceremonies only for explicitly validated related origins.")

    auth_value = _one(rows, "authenticatorData")
    if auth_value is None:
        add("webauthn-authenticator-data-cardinality", "authenticatorData is missing or ambiguous", "high", "high",
            (f"count: {len(_values(rows, 'authenticatorData'))}",),
            "Require one authenticator-data value and verify its signature/bindings in the real verifier.")
    else:
        auth = _b64u(auth_value, "authenticatorData")
        if len(auth) < 37:
            add("webauthn-authenticator-data-short", "Authenticator data is shorter than the fixed header", "high", "high",
                (f"bytes: {len(auth)}",), "Reject authenticator data shorter than 37 bytes.")
        else:
            rp_hash, flags, sign_count = auth[:32], auth[32], int.from_bytes(auth[33:37], "big")
            if expected_rp_id_hash is not None:
                if isinstance(expected_rp_id_hash, str):
                    try:
                        expected_hash = bytes.fromhex(expected_rp_id_hash)
                    except ValueError as exc:
                        raise IdentityAPIDepthError("expected_rp_id_hash is not hex") from exc
                elif isinstance(expected_rp_id_hash, bytes):
                    expected_hash = expected_rp_id_hash
                else:
                    raise IdentityAPIDepthError("expected_rp_id_hash must be hex text or bytes")
                if len(expected_hash) != 32:
                    raise IdentityAPIDepthError("expected_rp_id_hash must contain 32 bytes")
                if rp_hash != expected_hash:
                    add("webauthn-rp-id-hash", "RP ID hash differs from expected metadata", "critical", "high",
                        (f"observed {rp_hash.hex()}",), "Verify the RP ID hash against server configuration.")
            if not flags & 0x01:
                add("webauthn-user-presence", "User-presence flag is absent", "high", "high",
                    (f"flags 0x{flags:02x}",), "Require UP and, where policy demands, UV.")
            if not flags & 0x04:
                add("webauthn-user-verification", "User-verification flag is absent", "medium", "high",
                    (f"flags 0x{flags:02x}",), "Require UV for the configured assurance level.")
            if flags & 0x10 and not flags & 0x08:
                add("webauthn-backup-flags", "Backup-state is set without backup-eligibility", "high", "high",
                    (f"flags 0x{flags:02x}",), "Reject inconsistent BE/BS authenticator flags.")
            if ceremony == "assertion" and flags & 0x40:
                add("webauthn-attested-data-on-assertion", "Assertion unexpectedly carries attested-credential flag",
                    "medium", "high", (f"flags 0x{flags:02x}",), "Parse ceremony-specific authenticator-data extensions.")
            if previous_sign_count is not None and sign_count and sign_count <= previous_sign_count:
                add("webauthn-sign-count-rollback", "Signature counter did not increase", "high", "high",
                    (f"previous {previous_sign_count}", f"observed {sign_count}"),
                    "Apply clone-detection policy while accounting for authenticators that always report zero.")
    if ceremony == "assertion":
        signature = _one(rows, "signature")
        if signature is None or not _b64u(signature, "signature"):
            add("webauthn-signature-missing", "Assertion signature is missing or empty", "critical", "high",
                ("no non-empty saved signature bytes",), "Require cryptographic verification in the relying party.")
        if expected_user_handle is not None and _one(rows, "userHandle") != expected_user_handle:
            add("webauthn-user-handle", "User handle differs from expected account binding", "high", "high",
                (f"observed {_one(rows, 'userHandle')!r}",), "Bind credential ID and user handle to one RP account.")
    else:
        attestation = _one(rows, "attestationObject")
        if attestation is None or not _b64u(attestation, "attestationObject"):
            add("webauthn-attestation-missing", "Registration attestation object is missing or empty", "high", "high",
                ("no opaque attestation bytes",), "Parse and validate the attestation object in a hardened FIDO library.")
        fmt = _one(rows, "fmt")
        if fmt in {"none", "self"}:
            add("webauthn-attestation-assurance", "Saved attestation metadata has no external attestation chain",
                "low", "high", (f"fmt {fmt!r}",), "Match attestation conveyance/trust to the RP assurance policy.")
    return tuple(sorted(findings, key=lambda item: item.finding_id))


def _url_boundary(value: str, label: str) -> tuple[str, str, int, str]:
    if not isinstance(value, str):
        raise IdentityAPIDepthError(f"{label} is invalid or over cap")
    if (not value or _utf8_size(value, label) > 8192
            or any(char in value for char in "\r\n\x00")):
        raise IdentityAPIDepthError(f"{label} is invalid or over cap")
    try:
        parsed = urlsplit(value)
        port = parsed.port or (443 if parsed.scheme.casefold() == "https" else 80)
    except ValueError as exc:
        raise IdentityAPIDepthError(f"{label} is malformed") from exc
    if (parsed.scheme.casefold() != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.fragment):
        raise IdentityAPIDepthError(f"{label} must be an HTTPS URL without userinfo/fragment")
    resource = parsed.path or "/"
    if parsed.query:
        resource += "?" + parsed.query
    return parsed.scheme.casefold(), parsed.hostname.casefold(), port, resource


def analyze_jwks_trust_boundary(header_fields: Sequence[tuple[str, str]], *,
                                configured_issuer: str,
                                configured_jwks_uri: str,
                                saved_keys: Sequence[tuple[str, str, str, str]] = ()) -> tuple[DepthFinding, ...]:
    """Analyze kid/jku/x5u/key-selection trust without fetching or verifying."""

    fields = _pairs(header_fields, "JOSE header fields")
    issuer_boundary = _url_boundary(configured_issuer, "configured_issuer")
    jwks_boundary = _url_boundary(configured_jwks_uri, "configured_jwks_uri")
    if (not isinstance(saved_keys, Sequence)
            or isinstance(saved_keys, (str, bytes, bytearray, memoryview))):
        raise IdentityAPIDepthError("saved_keys must be a sequence of key tuples")
    if len(saved_keys) > 128:
        raise IdentityAPIDepthError("saved key count exceeds 128")
    keys: list[tuple[str, str, str, str]] = []
    for item in saved_keys:
        if not isinstance(item, (tuple, list)) or len(item) != 4 or any(not isinstance(value, str) for value in item):
            raise IdentityAPIDepthError("saved_keys entries must be kid/kty/alg/use text tuples")
        if any(_utf8_size(value, "saved_keys value") > 4096
               or any(char in value for char in "\r\n\x00")
               for value in item):
            raise IdentityAPIDepthError("saved_keys entry is invalid or over cap")
        keys.append(tuple(item))
    findings: list[DepthFinding] = []

    def add(code: str, title: str, severity: str, confidence: str,
            evidence: Iterable[str], remediation: str) -> None:
        findings.append(DepthFinding(code, "jwks-trust", title, severity, confidence,
                                     tuple(evidence), remediation))

    for name in ("alg", "kid", "jku", "x5u", "jwk", "x5c"):
        values = _values(fields, name)
        if len(values) > 1:
            add(f"jwks-duplicate-{name}", "JOSE key-selection field is duplicated", "critical", "high",
                (f"{name}: {values!r}",), "Reject duplicate protected-header members before key selection.")
    kid = _one(fields, "kid")
    matches: tuple[tuple[str, str, str, str], ...] = ()
    if kid is not None:
        if len(kid) > 256 or not kid or kid != kid.strip() or re.search(r"(?:[/\\]|\.\.|://|[%?&#*])", kid):
            add("jwks-structured-kid", "kid contains path/query/wildcard or normalization syntax", "high", "high",
                (f"kid {kid!r}",), "Treat kid as an opaque exact identifier, never a path/query/template.")
        matches = tuple(key for key in keys if key[0] == kid)
        if keys and len(matches) != 1:
            add("jwks-kid-cardinality", "kid does not select exactly one saved configured key", "high", "high",
                (f"kid {kid!r}", f"matches {len(matches)}"), "Require one exact configured-key match; never fallback by trial.")
    header_alg = _one(fields, "alg")
    if len(matches) == 1:
        _key_kid, _key_kty, key_alg, key_use = matches[0]
        if header_alg and key_alg and header_alg != key_alg:
            add("jwks-alg-key-mismatch", "JOSE alg differs from the selected saved key policy", "critical", "high",
                (f"header alg {header_alg!r}", f"key alg {key_alg!r}"),
                "Pin permitted algorithms to issuer/key metadata and reject algorithm mismatch before verification.")
        if key_use and key_use.casefold() != "sig":
            add("jwks-key-use", "Selected saved key is not marked for signatures", "high", "high",
                (f"key use {key_use!r}",), "Select only a uniquely matched key permitted for signature verification.")
    for locator_name in ("jku", "x5u"):
        locator = _one(fields, locator_name)
        if locator is None:
            continue
        try:
            boundary = _url_boundary(locator, locator_name)
        except IdentityAPIDepthError:
            add(f"jwks-{locator_name}-url", f"{locator_name} is not a strict HTTPS trust location", "high", "high",
                (f"value {locator!r}",), "Ignore header-supplied key URLs; use pinned issuer metadata.")
            continue
        if boundary[:3] != jwks_boundary[:3]:
            add(f"jwks-{locator_name}-boundary", f"{locator_name} crosses the configured JWKS authority", "critical", "high",
                (f"configured {configured_jwks_uri!r}", f"header {locator!r}"),
                "Never fetch header-selected key material; pin the issuer/JWKS authority and path policy.")
        elif boundary[3] != jwks_boundary[3]:
            add(f"jwks-{locator_name}-path", f"{locator_name} changes the configured JWKS path", "high", "high",
                (f"configured path {jwks_boundary[3]!r}", f"header path {boundary[3]!r}"),
                "Use the configured discovery-derived JWKS URI exactly.")
    if _one(fields, "jwk") is not None:
        add("jwks-embedded-key", "Header embeds key material at the verification trust boundary", "high", "high",
            ("jwk member is present",), "Ignore untrusted embedded keys unless an explicit pinned profile requires them.")
    if _one(fields, "jku") and _one(fields, "jwk"):
        add("jwks-multiple-key-sources", "Header supplies multiple competing key sources", "critical", "high",
            ("both jku and jwk are present",), "Configure one deterministic key source and reject alternatives.")
    if issuer_boundary[1] != jwks_boundary[1]:
        add("jwks-cross-host-configuration", "Configured issuer and JWKS use different hosts", "low", "high",
            (f"issuer host {issuer_boundary[1]!r}", f"JWKS host {jwks_boundary[1]!r}"),
            "Confirm the cross-host relationship is explicitly pinned in trusted discovery metadata.")
    return tuple(sorted(findings, key=lambda item: item.finding_id))


def correlate_sso_metadata(fields: Sequence[tuple[str, str]]) -> tuple[DepthFinding, ...]:
    """Correlate already-saved OIDC/SAML metadata across trust transitions."""

    rows = _pairs(fields, "SSO metadata")
    findings: list[DepthFinding] = []

    def add(code: str, family: str, title: str, severity: str, evidence: Iterable[str], remediation: str) -> None:
        findings.append(DepthFinding(code, family, title, severity, "high", tuple(evidence), remediation))

    for name in sorted({name.casefold() for name, _value in rows}):
        values = _values(rows, name)
        if len(values) > 1:
            add(f"sso-duplicate-{name}", "sso", "Saved correlation field is duplicated", "high",
                (f"{name}: {values!r}",), "Require one authoritative value per flow transition.")
    issuer_names = ("oidc.discovery.issuer", "oidc.authorization.issuer", "oidc.callback.iss", "oidc.token.iss")
    issuers = tuple((name, _one(rows, name)) for name in issuer_names if _one(rows, name) is not None)
    if len({value for _name, value in issuers}) > 1:
        add("sso-oidc-issuer-mixup", "oidc", "OIDC issuer changes across saved flow stages", "critical",
            (f"issuers: {issuers!r}",), "Bind authorization response, token endpoint, ID token, and keys to one issuer.")
    state_request, state_callback = _one(rows, "oidc.request.state"), _one(rows, "oidc.callback.state")
    if state_request is not None and state_callback != state_request:
        add("sso-state-correlation", "oidc", "OIDC callback state does not match request state", "critical",
            (f"request {state_request!r}", f"callback {state_callback!r}"), "Bind state to the initiating browser session.")
    nonce_request, nonce_token = _one(rows, "oidc.request.nonce"), _one(rows, "oidc.id_token.nonce")
    if nonce_request is not None and nonce_token != nonce_request:
        add("sso-nonce-correlation", "oidc", "OIDC ID-token nonce does not match request nonce", "critical",
            (f"request {nonce_request!r}", f"ID token {nonce_token!r}"),
            "Bind a single-use nonce to the browser flow and require it in the ID token.")
    client_id, audience = _one(rows, "oidc.request.client_id"), _one(rows, "oidc.id_token.aud")
    if client_id is not None and audience != client_id:
        add("sso-audience-correlation", "oidc", "OIDC ID-token audience differs from the client ID", "critical",
            (f"client_id {client_id!r}", f"aud {audience!r}"),
            "Require the configured client ID in aud and validate azp for multi-audience tokens.")
    redirect_request, redirect_token = (_one(rows, "oidc.request.redirect_uri"),
                                        _one(rows, "oidc.token.redirect_uri"))
    if redirect_request is not None and redirect_token != redirect_request:
        add("sso-redirect-uri-correlation", "oidc", "Authorization and token redirect_uri values differ", "high",
            (f"authorization {redirect_request!r}", f"token {redirect_token!r}"),
            "Use the exact same pre-registered redirect URI throughout the code flow.")
    saml_request, saml_response = _one(rows, "saml.request.id"), _one(rows, "saml.response.in_response_to")
    if saml_request is not None and saml_response != saml_request:
        add("sso-saml-request-correlation", "saml", "SAML InResponseTo does not match the saved request ID", "critical",
            (f"request {saml_request!r}", f"response {saml_response!r}"), "Require exact request/response correlation.")
    relay_request, relay_response = _one(rows, "saml.request.relay_state"), _one(rows, "saml.response.relay_state")
    if relay_request is not None and relay_response != relay_request:
        add("sso-saml-relay-state", "saml", "SAML RelayState changes across the flow", "high",
            (f"request {relay_request!r}", f"response {relay_response!r}"), "Integrity-bind RelayState to the browser session.")
    destination, acs = _one(rows, "saml.response.destination"), _one(rows, "saml.sp.acs")
    if acs is not None and destination != acs:
        add("sso-saml-destination", "saml", "SAML Destination differs from configured ACS", "critical",
            (f"Destination {destination!r}", f"ACS {acs!r}"), "Require exact Destination/Recipient/ACS binding.")
    recipient = _one(rows, "saml.assertion.recipient")
    if acs is not None and recipient is not None and recipient != acs:
        add("sso-saml-recipient", "saml", "SAML assertion Recipient differs from configured ACS", "critical",
            (f"Recipient {recipient!r}", f"ACS {acs!r}"), "Require exact bearer Recipient and ACS binding.")
    sp_entity, audience_value = _one(rows, "saml.sp.entity_id"), _one(rows, "saml.assertion.audience")
    if sp_entity is not None and audience_value is not None and audience_value != sp_entity:
        add("sso-saml-audience", "saml", "SAML Audience differs from the SP entity ID", "critical",
            (f"Audience {audience_value!r}", f"SP {sp_entity!r}"), "Require the configured SP entity ID in AudienceRestriction.")
    idp_entity, response_issuer = _one(rows, "saml.idp.entity_id"), _one(rows, "saml.response.issuer")
    if idp_entity is not None and response_issuer is not None and response_issuer != idp_entity:
        add("sso-saml-issuer", "saml", "SAML response Issuer differs from configured IdP", "critical",
            (f"Issuer {response_issuer!r}", f"IdP {idp_entity!r}"), "Pin response/assertion issuers to trusted IdP metadata.")
    response_mode = _one(rows, "oidc.request.response_mode")
    same_site = (_one(rows, "session.cookie.samesite") or "").casefold()
    if response_mode == "form_post" and same_site == "strict":
        add("sso-form-post-cookie", "oidc", "form_post callback may not receive a Strict SameSite session cookie",
            "medium", ("response_mode=form_post", "SameSite=Strict"),
            "Use a correlation design compatible with cross-site POST callbacks.")
    return tuple(sorted(findings, key=lambda item: item.finding_id))


def _mask_graphql(text: str) -> str:
    return re.sub(r'"(?:[^"\\]|\\.)*"|#[^\r\n]*', lambda match: " " * len(match.group(0)), text)


def _mask_parenthesized(text: str) -> str:
    """Blank argument/variable lists while retaining field-alias syntax."""

    result: list[str] = []
    depth = 0
    for char in text:
        if char == "(":
            depth += 1
            result.append(" ")
        elif char == ")" and depth:
            result.append(" ")
            depth -= 1
        else:
            result.append(" " if depth else char)
    return "".join(result)


def analyze_graphql_field_policy(schema: str | bytes | bytearray | memoryview,
                                 query: str | bytes | bytearray | memoryview, *,
                                 source: str | bytes | bytearray | memoryview = "") -> tuple[DepthFinding, ...]:
    """Correlate schema directives, selected fields, resolver clues, and cost."""

    schema_text = _text(schema, "GraphQL schema")
    query_text = _text(query, "GraphQL query")
    source_text = _text(source, "GraphQL resolver source")
    masked = _mask_graphql(query_text)
    findings: list[DepthFinding] = []
    sensitive = re.compile(r"(?i)(?:admin|role|permission|secret|token|password|email|billing|balance|owner|user)")
    protected: set[str] = set()
    unprotected_sensitive: set[str] = set()
    mutations: set[str] = set()
    in_mutation = False
    for line in schema_text.splitlines():
        if re.match(r"\s*type\s+Mutation\b", line):
            in_mutation = True
            continue
        if re.match(r"\s*type\s+\w+\b", line):
            in_mutation = False
        match = re.match(r"\s*([_A-Za-z][_0-9A-Za-z]*)\s*(?:\([^)]*\))?\s*:\s*[^#]+", line)
        if not match:
            continue
        name = match.group(1)
        has_auth = bool(re.search(r"(?i)@(auth|authorize|requiresRole|hasRole|permission|protect)\b", line))
        if has_auth:
            protected.add(name)
        elif sensitive.search(name):
            unprotected_sensitive.add(name)
        if in_mutation and not has_auth:
            mutations.add(name)
    selected = tuple(re.findall(r"(?m)(?<![$@])\b([_A-Za-z][_0-9A-Za-z]*)\b\s*(?:\([^{}]*\))?\s*(?=[{@\n\r,}])", masked))
    selected_unprotected = tuple(sorted(set(selected).intersection(unprotected_sensitive)))
    if selected_unprotected:
        findings.append(DepthFinding(
            "graphql-field-authz", "graphql-authz", "Selected sensitive fields lack an inline schema auth directive",
            "high", "medium", (f"fields: {selected_unprotected!r}",),
            "Enforce object and field authorization in resolvers/policy middleware; schema annotations are evidence only.",
        ))
    selected_mutations = tuple(sorted(set(selected).intersection(mutations)))
    if selected_mutations:
        findings.append(DepthFinding(
            "graphql-mutation-authz", "graphql-authz", "Selected mutation fields lack an inline auth directive",
            "high", "medium", (f"mutations: {selected_mutations!r}",),
            "Require function/object authorization for every mutation resolver.",
        ))
    alias_surface = _mask_parenthesized(masked)
    aliases = len(re.findall(r"\b[_A-Za-z][_0-9A-Za-z]*\s*:\s*[_A-Za-z][_0-9A-Za-z]*", alias_surface))
    spreads = len(re.findall(r"\.\.\.[_A-Za-z][_0-9A-Za-z]*", masked))
    page_values = [int(value) for value in re.findall(r"(?i)\b(?:first|last|limit|take)\s*:\s*([0-9]{1,9})", masked)]
    multiplier = min(max(page_values, default=1), 10_000)
    brace_depth = maximum_depth = 0
    for char in masked:
        if char == "{":
            brace_depth += 1
            maximum_depth = max(maximum_depth, brace_depth)
        elif char == "}":
            brace_depth = max(0, brace_depth - 1)
    estimated = min(1_000_000_000, max(1, len(selected) + aliases * 2 + spreads * 3) * multiplier)
    if estimated >= 10_000 or aliases >= 16 or spreads >= 32 or maximum_depth >= 16:
        findings.append(DepthFinding(
            "graphql-cost-evidence", "graphql-cost", "Lexical query cost indicators exceed a conservative threshold",
            "medium", "medium", (f"estimated units: {estimated}", f"aliases {aliases}",
                                  f"fragment spreads {spreads}", f"page multiplier {multiplier}",
                                  f"brace depth {maximum_depth}"),
            "Use schema-aware expanded-operation cost accounting with hard depth/list/batch budgets.",
        ))
    batch_members = len(re.findall(r'(?i)"(?:query|operationName)"\s*:', query_text))
    if query_text.lstrip().startswith("[") and batch_members >= 2:
        findings.append(DepthFinding(
            "graphql-batch-evidence", "graphql-cost", "Saved artifact has a GraphQL batch-array shape",
            "medium", "high", (f"query/operation members: {batch_members}",),
            "Disable batching where unnecessary and apply authentication plus aggregate batch/cost limits.",
        ))
    if (re.search(r"(?i)find(?:ById|One)\s*\([^)]*(?:args|input|id)", source_text)
            and not re.search(r"(?i)authorize|permission|owner|tenant|policy|context\.user", source_text)):
        findings.append(DepthFinding(
            "graphql-resolver-idor", "IDOR", "Resolver source shows identifier lookup without nearby auth tokens",
            "high", "medium", ("findById/findOne-style lookup", "no ownership/policy token in saved source"),
            "Authorize the authenticated subject against the resolved object inside the resolver/service.",
        ))
    return tuple(sorted(findings, key=lambda item: item.finding_id))


def analyze_parameter_authorization(request: str | bytes | bytearray | memoryview, *,
                                    source: str | bytes | bytearray | memoryview = "") -> tuple[DepthFinding, ...]:
    """Find HPP, mass-assignment, and IDOR patterns in a saved HTTP request."""

    text = _text(request, "saved request")
    source_text = _text(source, "saved source")
    head, separator, body = text.partition("\r\n\r\n")
    if not separator:
        head, separator, body = text.partition("\n\n")
    lines = head.replace("\r\n", "\n").split("\n")
    if not lines or len(lines[0].split(" ")) != 3:
        raise IdentityAPIDepthError("saved request line is malformed")
    method, target, version = lines[0].split(" ")
    if not re.fullmatch(r"[A-Z]{1,16}", method.upper()) or not re.fullmatch(r"HTTP/[0-9.]+", version, re.I):
        raise IdentityAPIDepthError("saved request line is malformed")
    try:
        split = urlsplit(target)
    except ValueError as exc:
        raise IdentityAPIDepthError("saved target is malformed") from exc
    header_rows: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line or line.startswith((" ", "\t")) or ":" not in line:
            continue
        name, value = line.split(":", 1)
        header_rows.append((name.strip().casefold(), value.strip()))
    content_types = tuple(value.split(";", 1)[0].strip().casefold()
                          for name, value in header_rows if name == "content-type")
    try:
        query = tuple(parse_qsl(split.query, keep_blank_values=True, max_num_fields=MAX_QUERY_FIELDS))
        form = (tuple(parse_qsl(body, keep_blank_values=True, max_num_fields=MAX_QUERY_FIELDS))
                if len(content_types) == 1 and content_types[0] == "application/x-www-form-urlencoded" else ())
    except ValueError as exc:
        raise IdentityAPIDepthError("query/body field count exceeds cap") from exc
    json_fields = (_lexical_json_fields(body) if len(content_types) == 1
                   and (content_types[0] == "application/json" or content_types[0].endswith("+json")) else ())
    pairs = tuple(("query", name, value) for name, value in query) + tuple(
        ("body", name, value) for name, value in form
    ) + tuple(("json-body", name, value) for name, value in json_fields)
    findings: list[DepthFinding] = []
    if len(content_types) > 1 and len(set(content_types)) > 1:
        findings.append(DepthFinding(
            "parameter-content-type-ambiguity", "HPP", "Saved request has conflicting Content-Type fields",
            "high", "high", (f"types: {content_types!r}",),
            "Reject duplicate/conflicting Content-Type before selecting a body parser.",
        ))
    grouped: dict[str, list[tuple[str, str, str]]] = {}
    for location, name, value in pairs:
        grouped.setdefault(name.casefold(), []).append((location, name, value))
    conflicts = tuple((name, tuple(values)) for name, values in grouped.items()
                      if len(values) > 1 and len({value for _loc, _raw, value in values}) > 1)
    if conflicts:
        findings.append(DepthFinding(
            "hpp-conflicting-values", "HPP", "Parameters repeat with conflicting values", "high", "high",
            (f"conflicts: {conflicts[:32]!r}",),
            "Reject duplicate security-relevant parameters and canonicalize query/body ownership.",
        ))
    case_variants = tuple((name, tuple(raw for _loc, raw, _value in values))
                          for name, values in grouped.items() if len({raw for _loc, raw, _value in values}) > 1)
    bracketed = tuple(name for _loc, name, _value in pairs if "[" in name or "]" in name)
    if case_variants or bracketed:
        findings.append(DepthFinding(
            "hpp-normalization", "HPP", "Parameter names exercise case/bracket normalization", "medium", "high",
            (f"case variants: {case_variants!r}", f"bracketed names: {bracketed!r}"),
            "Define one parser/canonical name model and reject ambiguous scalar/object encodings.",
        ))
    sensitive_re = re.compile(r"(?i)^(?:role|isadmin|permissions?|ownerid|userid|accountid|tenantid|status|balance)$")
    sensitive = tuple((location, name) for location, name, _value in pairs if sensitive_re.fullmatch(name))
    if sensitive and method.upper() in {"POST", "PUT", "PATCH"}:
        findings.append(DepthFinding(
            "parameter-mass-assignment", "mass-assignment", "Saved state-changing parameters include authority fields",
            "high", "medium", (f"fields: {sensitive!r}",),
            "Bind allowlisted DTO fields and derive identity/role/ownership server-side.",
        ))
    path_ids = tuple(segment for segment in split.path.split("/") if re.fullmatch(
        r"(?:[0-9]{1,20}|[0-9A-Fa-f-]{16,})", segment
    ))
    source_lookup = bool(re.search(r"(?i)find(?:ById|One)|where\s*[:=].*(?:id|uuid)", source_text))
    source_auth = bool(re.search(r"(?i)authorize|permission|owner|tenant|policy|currentUser|session\.user", source_text))
    if path_ids and source_lookup and not source_auth:
        findings.append(DepthFinding(
            "parameter-idor-source", "IDOR", "Object identifier reaches lookup code without saved authz tokens",
            "high", "medium", (f"path identifiers: {path_ids!r}", "lookup token present; ownership token absent"),
            "Authorize the current subject for the resolved object and requested action.",
        ))
    if sensitive and re.search(r"(?i)Object\.assign|\.update\s*\(\s*(?:req|request)\.body|\.\.\.(?:req|request)\.body", source_text):
        findings.append(DepthFinding(
            "parameter-whole-body-binding", "mass-assignment", "Source suggests whole-body binding of sensitive input",
            "high", "high", ("whole-body binding token in saved source",),
            "Map input through an explicit writable-field allowlist.",
        ))
    return tuple(sorted(findings, key=lambda item: item.finding_id))


def build_identity_api_plans(marker: str = "R5D_INERT") -> tuple[InertPlan, ...]:
    """Return non-wire metadata plans; no valid token/assertion/signature is created."""

    if not isinstance(marker, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]{3,63}", marker):
        raise IdentityAPIDepthError("marker must be a bounded inert token")
    specs = (
        ("webauthn", "binding-matrix", f"R5D_INERT_WEBAUTHN challenge={marker} origin=https://r5d.invalid rp_hash={marker}",
         "compare saved type/challenge/origin/RP/counter bindings"),
        ("jwks-trust", "locator-matrix", f"R5D_INERT_JOSE kid={marker} jku=https://r5d.invalid/{marker}",
         "key locators must never select a network trust source"),
        ("sso", "correlation-matrix", f"R5D_INERT_SSO state={marker} nonce={marker} RelayState={marker}",
         "correlate browser, issuer, and SAML request state"),
        ("graphql-authz", "field-policy", f"query {marker} {{ object(id:\"{marker}\") {{ role ownerId }} }}",
         "field/object authorization must be resolver-enforced"),
        ("HPP", "duplicate-parameter", f"GET /?id={marker}&id=R5D_OTHER HTTP/1.1\r\nHost: r5d.invalid\r\n\r\n",
         "duplicate security parameters require one canonical policy"),
    )
    return tuple(InertPlan(index, family, name, artifact, hypothesis)
                 for index, (family, name, artifact, hypothesis) in enumerate(specs, 1))


__all__ = [
    "DepthFinding", "IdentityAPIDepthError", "InertPlan", "analyze_graphql_field_policy",
    "analyze_jwks_trust_boundary", "analyze_parameter_authorization", "analyze_webauthn_ceremony",
    "build_identity_api_plans", "correlate_sso_metadata",
]
