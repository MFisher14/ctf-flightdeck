#!/usr/bin/env python3
"""Offline OAuth/OIDC edge and multi-flow correlation analyzer.

The existing identity engine handles ordinary saved authorization-code flows.
This companion focuses on RFC 9700 PKCE downgrade evidence, contextual CSRF
defenses, registered redirect policy, response-mode leakage, JAR/PAR/JARM
edge binding, OIDC subject/authorized-party binding, and reuse across saved flows.  Input
is local JSON or caller-supplied mappings; no endpoint is contacted.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit


MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_FLOWS = 128
MAX_FIELDS = 256
MAX_TEXT_BYTES = 16 * 1024
MAX_FINDINGS = 1024
MAX_CLAIM_NODES = 2048
MAX_CLAIM_DEPTH = 16


class WebauthOAuthError(ValueError):
    """Saved OAuth evidence is malformed, ambiguous, or exceeds a hard bound."""


def _duplicate_reject(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise WebauthOAuthError(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def load_flows(value: str | bytes | bytearray | memoryview) -> list[dict[str, Any]]:
    """Strictly load a JSON object/array of saved flow records."""

    if isinstance(value, str):
        try:
            raw = value.encode("utf-8", "strict")
        except UnicodeError as exc:
            raise WebauthOAuthError("flow JSON is not UTF-8") from exc
    elif isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
    else:
        raise WebauthOAuthError("flow JSON must be text or bytes")
    if not raw or len(raw) > MAX_INPUT_BYTES:
        raise WebauthOAuthError(f"flow JSON is empty or exceeds {MAX_INPUT_BYTES} bytes")
    try:
        parsed = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_duplicate_reject,
            parse_constant=lambda item: (_ for _ in ()).throw(
                WebauthOAuthError(f"non-standard JSON number {item}")
            ),
        )
    except WebauthOAuthError:
        raise
    except (UnicodeError, ValueError, OverflowError, RecursionError) as exc:
        raise WebauthOAuthError("invalid flow JSON") from exc
    if isinstance(parsed, dict) and "flows" in parsed:
        parsed = parsed["flows"]
    if isinstance(parsed, dict):
        parsed = [parsed]
    if not isinstance(parsed, list) or not 1 <= len(parsed) <= MAX_FLOWS:
        raise WebauthOAuthError(f"flow input must contain 1..{MAX_FLOWS} records")
    if any(not isinstance(item, dict) for item in parsed):
        raise WebauthOAuthError("every flow record must be an object")
    return parsed


def _text(value: Any, label: str, *, allow_empty: bool = True) -> str:
    if not isinstance(value, str):
        raise WebauthOAuthError(f"{label} must be text")
    try:
        size = len(value.encode("utf-8", "strict"))
    except UnicodeError as exc:
        raise WebauthOAuthError(f"{label} is not valid Unicode") from exc
    if size > MAX_TEXT_BYTES or (not allow_empty and not value) or "\x00" in value:
        raise WebauthOAuthError(f"{label} is empty, contains NUL, or exceeds its cap")
    return value


def _mapping(flow: Mapping[str, Any], name: str) -> dict[str, str]:
    value = flow.get(name, {})
    if value is None:
        return {}
    if not isinstance(value, Mapping) or len(value) > MAX_FIELDS:
        raise WebauthOAuthError(f"{name} must be a bounded object")
    result: dict[str, str] = {}
    for key, item in value.items():
        key_text = _text(key, f"{name} field name", allow_empty=False)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.:#-]{0,127}", key_text):
            raise WebauthOAuthError(f"invalid {name} field name {key_text!r}")
        if isinstance(item, bool):
            item = "true" if item else "false"
        elif isinstance(item, (int, float)) and not isinstance(item, bool):
            if isinstance(item, float) and (item != item or item in {float("inf"), float("-inf")}):
                raise WebauthOAuthError(f"{name}.{key_text} contains a non-finite number")
            item = str(item)
        result[key_text] = _text(item, f"{name}.{key_text}")
    return result


def _validate_ignored_claim(value: Any, label: str) -> None:
    """Bound irrelevant claim JSON without rejecting standard arrays/objects."""

    stack: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_CLAIM_NODES or depth > MAX_CLAIM_DEPTH:
            raise WebauthOAuthError(f"{label} exceeds the claim tree bounds")
        if isinstance(item, Mapping):
            if len(item) > MAX_FIELDS:
                raise WebauthOAuthError(f"{label} object is over cap")
            for key, child in item.items():
                _text(key, f"{label} object key", allow_empty=False)
                stack.append((child, depth + 1))
        elif isinstance(item, (list, tuple)):
            if len(item) > MAX_FIELDS:
                raise WebauthOAuthError(f"{label} array is over cap")
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            _text(item, label)
        elif item is None or isinstance(item, (bool, int)):
            continue
        elif isinstance(item, float):
            if item != item or item in {float("inf"), float("-inf")}:
                raise WebauthOAuthError(f"{label} contains a non-finite number")
        else:
            raise WebauthOAuthError(f"{label} contains a non-JSON value")


def _oidc_claims(flow: Mapping[str, Any], name: str) -> dict[str, Any]:
    """Load correlated claims and safely bound all other standard claim JSON."""

    value = flow.get(name, {})
    if value is None:
        return {}
    if not isinstance(value, Mapping) or len(value) > MAX_FIELDS:
        raise WebauthOAuthError(f"{name} must be a bounded object")
    result: dict[str, Any] = {}
    for key, item in value.items():
        key_text = _text(key, f"{name} field name", allow_empty=False)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.:#-]{0,127}", key_text):
            raise WebauthOAuthError(f"invalid {name} field name {key_text!r}")
        if key_text == "aud" and isinstance(item, list):
            if not 1 <= len(item) <= MAX_FIELDS:
                raise WebauthOAuthError(f"{name}.aud must be a bounded non-empty string array")
            result[key_text] = tuple(
                _text(audience, f"{name}.aud item", allow_empty=False) for audience in item
            )
            continue
        if key_text not in {"aud", "iss", "sub", "nonce", "azp"}:
            _validate_ignored_claim(item, f"{name}.{key_text}")
            continue
        result[key_text] = _text(item, f"{name}.{key_text}")
    return result


def _string_list(flow: Mapping[str, Any], name: str) -> tuple[str, ...]:
    value = flow.get(name, [])
    if value is None:
        return ()
    if not isinstance(value, list) or len(value) > MAX_FIELDS:
        raise WebauthOAuthError(f"{name} must be a bounded string array")
    return tuple(_text(item, f"{name} item", allow_empty=False) for item in value)


def pkce_s256(verifier: str) -> str:
    """Calculate RFC 7636 S256 for one syntactically valid verifier."""

    verifier = _text(verifier, "code_verifier", allow_empty=False)
    if not re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", verifier):
        raise WebauthOAuthError("code_verifier must be 43..128 RFC 7636 unreserved ASCII characters")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _finding(
    code: str,
    severity: str,
    flow_ids: Sequence[str],
    evidence: str,
    requirement: str,
) -> dict[str, Any]:
    return {
        "code": code,
        "severity": severity,
        "flow_ids": list(flow_ids),
        "evidence": evidence[:512],
        "requirement": requirement[:512],
    }


def _url(value: str, label: str):
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError as exc:
        raise WebauthOAuthError(f"malformed {label}") from exc
    if not parsed.scheme:
        raise WebauthOAuthError(f"{label} must be an absolute URI")
    if parsed.scheme.casefold() in {"http", "https"} and not parsed.hostname:
        raise WebauthOAuthError(f"HTTP(S) {label} must include a host")
    if parsed.netloc and not parsed.hostname:
        raise WebauthOAuthError(f"{label} has a malformed authority")
    return parsed


def _loopback_match(actual: str, registered: str) -> bool:
    """RFC 8252 loopback redirect match with a variable ephemeral port."""

    try:
        left, right = _url(actual, "redirect_uri"), _url(registered, "registered redirect URI")
    except WebauthOAuthError:
        return False
    hosts = {"127.0.0.1", "::1"}
    return (
        left.scheme == right.scheme == "http"
        and left.hostname in hosts
        and right.hostname == left.hostname
        and left.path == right.path
        and left.query == right.query
        and not left.fragment
        and not right.fragment
        and left.username is None
        and right.username is None
    )


def _registered_redirect_findings(
    flow_id: str,
    authorization: dict[str, str],
    registered: tuple[str, ...],
) -> list[dict[str, Any]]:
    redirect = authorization.get("redirect_uri")
    if redirect is None:
        return []
    rows: list[dict[str, Any]] = []
    parsed = _url(redirect, "redirect_uri")
    if parsed.scheme.casefold() not in {"http", "https"} and "." not in parsed.scheme:
        rows.append(_finding(
            "native_redirect_scheme_not_reverse_domain",
            "high",
            (flow_id,),
            redirect,
            "RFC 8252 private-use redirect schemes should be based on a domain name controlled by the app publisher",
        ))
    if parsed.username is not None or parsed.password is not None:
        rows.append(_finding("redirect_userinfo", "high", (flow_id,), redirect, "URI parser disagreement or unsafe registration policy"))
    if parsed.fragment:
        rows.append(_finding("redirect_fragment", "high", (flow_id,), redirect, "authorization redirect URIs must not contain a fragment"))
    if "\\" in redirect or re.search(r"%(?:2f|5c|2e|23|3f|40)", redirect, re.I):
        rows.append(_finding(
            "redirect_parser_boundary",
            "medium",
            (flow_id,),
            redirect,
            "different components must not normalize encoded delimiters, traversal, or backslashes differently",
        ))
    for item in registered:
        if "*" in item or re.search(r"\{[^}]+\}", item):
            rows.append(_finding(
                "registered_redirect_pattern",
                "high",
                (flow_id,),
                item,
                "RFC 9700 requires exact string matching except native loopback port numbers",
            ))
    if registered and redirect not in registered and not any(_loopback_match(redirect, item) for item in registered):
        rows.append(_finding(
            "redirect_not_exactly_registered",
            "critical",
            (flow_id,),
            redirect,
            "the authorization server accepts a URI outside the exact registered set",
        ))
    return rows


_BOUND_PARAMETERS = (
    "client_id",
    "redirect_uri",
    "response_type",
    "response_mode",
    "scope",
    "state",
    "nonce",
    "code_challenge",
    "code_challenge_method",
    "code",
    "iss",
    "error",
    "access_token",
    "id_token",
)


def _conflicts(
    flow_id: str,
    outer: dict[str, str],
    signed: dict[str, str],
    code: str,
) -> list[dict[str, Any]]:
    rows = []
    for name in _BOUND_PARAMETERS:
        if name in outer and name in signed and outer[name] != signed[name]:
            rows.append(_finding(
                code,
                "critical",
                (flow_id,),
                f"{name}: outer={outer[name]!r}, protected={signed[name]!r}",
                "the implementation must define one protected value and reject conflicting copies",
            ))
    return rows


def _one_flow(flow: Mapping[str, Any], index: int) -> tuple[dict[str, Any], dict[str, str]]:
    flow_id = _text(flow.get("id", f"flow-{index}"), "flow id", allow_empty=False)
    authorization = _mapping(flow, "authorization")
    callback = _mapping(flow, "callback")
    token = _mapping(flow, "token_request")
    metadata = _mapping(flow, "metadata")
    id_token = _oidc_claims(flow, "id_token_claims")
    userinfo = _oidc_claims(flow, "userinfo_claims")
    request_object = _mapping(flow, "request_object_claims")
    jarm = _mapping(flow, "jarm_claims")
    par = _mapping(flow, "par")
    registered = _string_list(flow, "registered_redirect_uris")
    findings: list[dict[str, Any]] = []

    challenge = authorization.get("code_challenge")
    method = authorization.get("code_challenge_method") or ("plain" if challenge else None)
    verifier = token.get("code_verifier")
    pkce_bound = False
    if verifier is not None and challenge is None:
        findings.append(_finding(
            "pkce_downgrade_verifier_without_challenge",
            "critical",
            (flow_id,),
            "token request has code_verifier but authorization request had no code_challenge",
            "RFC 9700 requires the authorization server to reject this downgrade shape",
        ))
    elif challenge is not None:
        if method != "S256":
            findings.append(_finding(
                "pkce_method_not_s256",
                "high",
                (flow_id,),
                f"code_challenge_method={method!r}",
                "S256 is the only currently registered method that does not expose the verifier",
            ))
        if verifier is None:
            findings.append(_finding(
                "pkce_verifier_missing",
                "high",
                (flow_id,),
                "authorization request has a challenge but token request has no verifier",
                "the token exchange must be bound to the authorization request",
            ))
        else:
            try:
                derived = pkce_s256(verifier) if method == "S256" else verifier
            except WebauthOAuthError as exc:
                findings.append(_finding("pkce_verifier_invalid", "high", (flow_id,), str(exc), "RFC 7636 verifier syntax is required"))
            else:
                if derived != challenge:
                    findings.append(_finding(
                        "pkce_verifier_mismatch",
                        "critical",
                        (flow_id,),
                        "saved verifier does not reproduce saved challenge",
                        "the authorization code must be bound to the same PKCE transaction",
                    ))
                elif method == "S256":
                    pkce_bound = True

    state = authorization.get("state")
    returned_state = callback.get("state") or jarm.get("state")
    expected_state = flow.get("session_state")
    if expected_state is not None:
        expected_state = _text(expected_state, "session_state", allow_empty=False)
    nonce = authorization.get("nonce")
    returned_nonce = id_token.get("nonce")
    nonce_bound = bool(nonce and returned_nonce == nonce)
    if nonce is not None and returned_nonce is None:
        findings.append(_finding(
            "oidc_nonce_missing",
            "high",
            (flow_id,),
            "authorization request supplied nonce but the saved ID-token claims do not",
            "OIDC clients must require the nonce claim and compare it exactly to the session-bound request value",
        ))
    elif nonce is not None and returned_nonce != nonce:
        findings.append(_finding(
            "oidc_nonce_mismatch",
            "critical",
            (flow_id,),
            f"request nonce={nonce!r}, ID-token nonce={returned_nonce!r}",
            "OIDC clients must compare the nonce exactly before accepting the ID token",
        ))
    if state is None:
        if pkce_bound or nonce_bound:
            findings.append(_finding(
                "state_absent_with_alternate_binding",
                "info",
                (flow_id,),
                f"PKCE-bound={pkce_bound}, OIDC-nonce-bound={nonce_bound}",
                "confirm the alternate defense is transaction-specific and enforced by the authorization server",
            ))
        else:
            findings.append(_finding(
                "csrf_binding_absent",
                "high",
                (flow_id,),
                "no state and no demonstrated transaction-bound PKCE/OIDC nonce",
                "bind the callback to the initiating user agent using an RFC 9700 defense",
            ))
    elif returned_state != state or (expected_state is not None and state != expected_state):
        findings.append(_finding(
            "state_binding_mismatch",
            "critical",
            (flow_id,),
            f"request={state!r}, callback={returned_state!r}, session={expected_state!r}",
            "state must be single-use and bound to the initiating browser session",
        ))

    findings.extend(_registered_redirect_findings(flow_id, authorization, registered))
    response_types = set(authorization.get("response_type", "").split())
    location = _text(flow.get("callback_location", "query"), "callback_location", allow_empty=False)
    if location not in {"query", "fragment", "form_post", "jarm"}:
        raise WebauthOAuthError("callback_location must be query, fragment, form_post, or jarm")
    if "token" in response_types:
        findings.append(_finding(
            "implicit_access_token_flow",
            "high",
            (flow_id,),
            f"response_type={authorization.get('response_type')!r}",
            "RFC 9700 deprecates the implicit grant because browser-delivered tokens leak and cannot be sender constrained",
        ))
    if location == "query" and ("access_token" in callback or "id_token" in callback):
        findings.append(_finding(
            "token_in_query",
            "critical",
            (flow_id,),
            "authorization response token appears in URL query",
            "query values enter history, logs, and Referer surfaces",
        ))
    if location in {"query", "fragment"} and "code" in callback:
        findings.append(_finding(
            "front_channel_code_exposure",
            "low",
            (flow_id,),
            f"authorization code returned via {location}",
            "use one-time short-lived codes, PKCE, exact redirects, and a restrictive Referrer-Policy",
        ))

    findings.extend(_conflicts(flow_id, authorization, request_object, "jar_parameter_conflict"))
    findings.extend(_conflicts(flow_id, callback, jarm, "jarm_parameter_conflict"))
    request_uri = authorization.get("request_uri")
    if request_uri and not request_uri.startswith("urn:ietf:params:oauth:request_uri:"):
        findings.append(_finding(
            "external_request_uri_requires_pinning",
            "medium",
            (flow_id,),
            request_uri,
            "a preregistered/pinned JAR URI is valid; arbitrary retrieval can create SSRF or parameter-validation differences",
        ))
    if par and authorization.get("client_id") and par.get("client_id") != authorization.get("client_id"):
        findings.append(_finding(
            "par_client_binding_mismatch",
            "critical",
            (flow_id,),
            f"authorization client={authorization.get('client_id')!r}, PAR client={par.get('client_id')!r}",
            "the pushed request URI must be bound to the authenticated client",
        ))

    if id_token.get("sub") and userinfo.get("sub") and id_token["sub"] != userinfo["sub"]:
        findings.append(_finding(
            "userinfo_subject_mismatch",
            "critical",
            (flow_id,),
            f"ID token sub={id_token['sub']!r}, UserInfo sub={userinfo['sub']!r}",
            "OIDC Core requires exact subject equality before UserInfo is consumed",
        ))
    audience = id_token.get("aud")
    if isinstance(audience, tuple):
        audiences = list(audience)
    elif isinstance(audience, str) and audience:
        audiences = [audience]
    else:
        audiences = []
    client_id = authorization.get("client_id")
    authorized_party = id_token.get("azp")
    if len(audiences) > 1 and authorized_party is None:
        findings.append(_finding(
            "authorized_party_missing",
            "high",
            (flow_id,),
            f"aud={audiences!r} has multiple values but azp is absent",
            "OIDC Core requires an authorized-party claim for the multi-audience case",
        ))
    if authorized_party is not None and authorized_party != client_id:
        findings.append(_finding(
            "authorized_party_mismatch",
            "high",
            (flow_id,),
            f"aud={audiences!r}, azp={authorized_party!r}, client_id={client_id!r}",
            "whenever azp is present, the client must verify that it identifies this client",
        ))

    issuers = {
        name: value
        for name, value in (
            ("metadata", metadata.get("issuer")),
            ("callback", callback.get("iss")),
            ("jarm", jarm.get("iss")),
            ("id_token", id_token.get("iss")),
        )
        if value
    }
    expected_issuer = flow.get("expected_issuer")
    if expected_issuer is not None:
        issuers["expected"] = _text(expected_issuer, "expected_issuer", allow_empty=False)
    if len(set(issuers.values())) > 1:
        findings.append(_finding(
            "authorization_server_mixup",
            "critical",
            (flow_id,),
            repr(issuers),
            "bind authorization response, token exchange, ID token, and keys to one configured issuer",
        ))

    summary = {
        "id": flow_id,
        "pkce_method": method,
        "pkce_bound": pkce_bound,
        "nonce_bound": nonce_bound,
        "response_types": sorted(response_types),
        "callback_location": location,
    }
    reuse = {
        "state": state or "",
        "nonce": nonce or "",
        "code_challenge": challenge or "",
        "authorization_code": callback.get("code") or jarm.get("code", ""),
        "code_verifier": verifier or "",
        "request_uri": request_uri or "",
    }
    if len(findings) > MAX_FINDINGS:
        raise WebauthOAuthError("finding cap exceeded")
    return {"summary": summary, "findings": findings}, reuse


def _analyze_flows(flows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Analyze 1..128 already-saved OAuth/OIDC flow records."""

    if not isinstance(flows, Sequence) or isinstance(flows, (str, bytes, bytearray)):
        raise WebauthOAuthError("flows must be a sequence of objects")
    if not 1 <= len(flows) <= MAX_FLOWS:
        raise WebauthOAuthError(f"flows must contain 1..{MAX_FLOWS} records")
    reports: list[dict[str, Any]] = []
    reuse_rows: list[tuple[str, dict[str, str]]] = []
    all_findings: list[dict[str, Any]] = []
    for index, flow in enumerate(flows, 1):
        if not isinstance(flow, Mapping):
            raise WebauthOAuthError("every flow must be an object")
        report, reuse = _one_flow(flow, index)
        reports.append(report["summary"])
        all_findings.extend(report["findings"])
        reuse_rows.append((report["summary"]["id"], reuse))
    severity = {
        "authorization_code": "critical",
        "state": "high",
        "nonce": "high",
        "code_challenge": "medium",
        "code_verifier": "medium",
        "request_uri": "high",
    }
    for field in severity:
        groups: dict[str, list[str]] = {}
        for flow_id, values in reuse_rows:
            if values[field]:
                groups.setdefault(values[field], []).append(flow_id)
        for value, flow_ids in groups.items():
            if len(flow_ids) > 1:
                all_findings.append(_finding(
                    f"reused_{field}",
                    severity[field],
                    flow_ids,
                    f"same {field} appears in {len(flow_ids)} saved flows: {value[:80]!r}",
                    "transaction identifiers, codes, nonces, PKCE values, and PAR URIs need appropriate uniqueness/replay policy",
                ))
    if len(all_findings) > MAX_FINDINGS:
        raise WebauthOAuthError("finding cap exceeded")
    return {
        "flows": reports,
        "findings": sorted(all_findings, key=lambda row: (row["code"], row["flow_ids"], row["evidence"])),
        "offline": True,
        "network_requests": 0,
        "tokens_verified": False,
    }


def analyze_flows(flows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Analyze saved flows and expose only the declared malformed-input error."""

    try:
        return _analyze_flows(flows)
    except WebauthOAuthError:
        raise
    except Exception as exc:
        raise WebauthOAuthError("malformed OAuth/OIDC flow evidence") from exc


def _read(path: str) -> bytes:
    try:
        item = Path(path)
        if not item.is_file() or item.stat().st_size > MAX_INPUT_BYTES:
            raise WebauthOAuthError(f"input is absent or exceeds {MAX_INPUT_BYTES} bytes")
        with item.open("rb") as handle:
            raw = handle.read(MAX_INPUT_BYTES + 1)
    except WebauthOAuthError:
        raise
    except OSError as exc:
        raise WebauthOAuthError("cannot read input") from exc
    if len(raw) > MAX_INPUT_BYTES:
        raise WebauthOAuthError(f"input exceeds {MAX_INPUT_BYTES} bytes")
    return raw


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("analyze", help="analyze a local flow JSON file")
    analyze.add_argument("input")
    pkce = sub.add_parser("pkce", help="calculate RFC 7636 S256 offline")
    pkce.add_argument("verifier")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        try:
            args = _parser().parse_args(argv)
        except SystemExit as exc:
            return exc.code if isinstance(exc.code, int) else 2
        if args.command == "pkce":
            result: Any = {"S256": pkce_s256(args.verifier), "offline": True, "network_requests": 0}
        else:
            result = analyze_flows(load_flows(_read(args.input)))
        print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
        return 0
    except WebauthOAuthError as exc:
        print(f"webauth_oauth_edge: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
