#!/usr/bin/env python3
"""Offline OAuth/OIDC non-happy-path policy correlator.

The input is normalized JSON containing deployment policy and observations from
already-saved flows.  This module deliberately does *not* parse compact tokens,
verify signatures, discover endpoints, exchange authorization codes, access a
protected resource, or make any network request.  Cryptographic results such as
``signature_valid`` and ``ath_matches`` must come from a separate trusted
analyzer and are correlated here with policy.

Schema version 1 has this shape (all observation fields are optional, so an
omitted value means unknown rather than false)::

    {
      "schema_version": 1,
      "policy": {
        "registered_response_types": [["code"], ["code", "id_token"]],
        "allowed_response_modes": ["query", "form_post"],
        "multiple_authorization_servers": true,
        "mixup_defense": "iss",
        "issuer_endpoint_tuple_bound": true,
        "issuer_selection_source": "transaction",
        "pkce_used_as_csrf_defense": true,
        "pkce_enforcement": "required",
        "reject_verifier_without_challenge": true,
        "require_par": true,
        "require_signed_jar": true,
        "require_dpop": true
      },
      "flows": [{
        "id": "saved-flow-1",
        "authorization": {}, "hybrid": {}, "browser": {},
        "cookie": {}, "redirect": {}, "par": {}, "jar": {}, "dpop": {}
      }]
    }

Only documented keys are accepted.  This catches misspelled evidence fields
instead of silently treating them as proof that a control is safe.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
import math
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Sequence


MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_FLOWS = 128
MAX_OBJECT_FIELDS = 64
MAX_LIST_ITEMS = 128
MAX_TEXT_BYTES = 16 * 1024
MAX_JSON_NODES = 20_000
MAX_JSON_DEPTH = 24
MAX_FINDINGS = 2_048

_TOKEN = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._~:+/-]{0,127}\Z")
_FIELD = re.compile(r"\A[A-Za-z_][A-Za-z0-9_.:-]{0,127}\Z")
_RESPONSE_MODES = frozenset({
    "query", "fragment", "form_post", "jwt", "query.jwt",
    "fragment.jwt", "form_post.jwt",
})
_MIXUP_DEFENSES = frozenset({
    "none", "iss", "jarm", "frontchannel_id_token", "distinct_redirects",
})


class WPGAPOAuthPolicyError(ValueError):
    """The sole public failure type for malformed or over-limit evidence."""


@dataclass(frozen=True)
class PolicyFinding:
    code: str
    severity: str
    flow_ids: tuple[str, ...]
    summary: str
    evidence: tuple[str, ...]
    reference: str
    remediation: str

    def as_dict(self) -> dict[str, object]:
        row = asdict(self)
        row["flow_ids"] = list(self.flow_ids)
        row["evidence"] = list(self.evidence)
        return row


@dataclass(frozen=True)
class PolicyReport:
    schema_version: int
    flow_ids: tuple[str, ...]
    findings: tuple[PolicyFinding, ...]
    offline: bool = True
    network_requests: int = 0
    token_exchanges: int = 0
    tokens_verified: bool = False

    def as_dict(self) -> dict[str, object]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return {
            "schema_version": self.schema_version,
            "flow_ids": list(self.flow_ids),
            "findings": [finding.as_dict() for finding in self.findings],
            "severity_counts": dict(sorted(counts.items())),
            "offline": self.offline,
            "network_requests": self.network_requests,
            "token_exchanges": self.token_exchanges,
            "tokens_verified": self.tokens_verified,
        }


@dataclass(frozen=True)
class _Policy:
    registered_response_types: frozenset[tuple[str, ...]]
    allowed_response_modes: frozenset[str]
    multiple_authorization_servers: bool | None
    mixup_defense: str | None
    issuer_endpoint_tuple_bound: bool | None
    issuer_selection_source: str | None
    pkce_used_as_csrf_defense: bool | None
    pkce_enforcement: str | None
    reject_verifier_without_challenge: bool | None
    require_par: bool | None
    require_signed_jar: bool | None
    require_dpop: bool | None


def _duplicate_reject(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise WPGAPOAuthPolicyError(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def _bounded_json_tree(value: object) -> None:
    stack: list[tuple[object, int]] = [(value, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise WPGAPOAuthPolicyError(f"JSON node cap exceeded ({MAX_JSON_NODES})")
        if depth > MAX_JSON_DEPTH:
            raise WPGAPOAuthPolicyError(f"JSON nesting exceeds {MAX_JSON_DEPTH}")
        if isinstance(item, Mapping):
            if len(item) > MAX_OBJECT_FIELDS:
                raise WPGAPOAuthPolicyError("JSON object field cap exceeded")
            for key, child in item.items():
                if not isinstance(key, str):
                    raise WPGAPOAuthPolicyError("JSON object keys must be text")
                stack.append((child, depth + 1))
        elif isinstance(item, (list, tuple)):
            if len(item) > max(MAX_FLOWS, MAX_LIST_ITEMS):
                raise WPGAPOAuthPolicyError("JSON array cap exceeded")
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            _text(item, "JSON string")
        elif isinstance(item, float) and not math.isfinite(item):
            raise WPGAPOAuthPolicyError("JSON contains a non-finite number")
        elif item is not None and not isinstance(item, (bool, int, float)):
            raise WPGAPOAuthPolicyError("JSON contains a non-JSON value")


def _load_evidence(value: str | bytes | bytearray | memoryview) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            raw = value.encode("utf-8", "strict")
        except UnicodeError as exc:
            raise WPGAPOAuthPolicyError("evidence JSON is not valid Unicode") from exc
    elif isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
    else:
        raise WPGAPOAuthPolicyError("evidence JSON must be text or bytes")
    if not raw or len(raw) > MAX_INPUT_BYTES:
        raise WPGAPOAuthPolicyError(
            f"evidence JSON is empty or exceeds {MAX_INPUT_BYTES} bytes"
        )
    try:
        parsed = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_duplicate_reject,
            parse_constant=lambda name: (_ for _ in ()).throw(
                WPGAPOAuthPolicyError(f"non-standard JSON number {name}")
            ),
        )
    except WPGAPOAuthPolicyError:
        raise
    except (UnicodeError, ValueError, OverflowError, RecursionError) as exc:
        raise WPGAPOAuthPolicyError("invalid evidence JSON") from exc
    _bounded_json_tree(parsed)
    if not isinstance(parsed, dict):
        raise WPGAPOAuthPolicyError("evidence JSON must be an object")
    return parsed


def load_evidence(value: str | bytes | bytearray | memoryview) -> dict[str, Any]:
    """Load duplicate-free, bounded JSON and expose only the declared error."""

    try:
        return _load_evidence(value)
    except WPGAPOAuthPolicyError:
        raise
    except Exception as exc:  # defensive normalization for public callers
        raise WPGAPOAuthPolicyError("malformed OAuth/OIDC policy evidence") from exc


def _text(value: object, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise WPGAPOAuthPolicyError(f"{label} must be text")
    try:
        size = len(value.encode("utf-8", "strict"))
    except UnicodeError as exc:
        raise WPGAPOAuthPolicyError(f"{label} is not valid Unicode") from exc
    if (
        size > MAX_TEXT_BYTES
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)
        or (not allow_empty and not value)
    ):
        raise WPGAPOAuthPolicyError(
            f"{label} is empty, contains a control character, or exceeds its cap"
        )
    return value


def _object(value: object, label: str, allowed: frozenset[str]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or len(value) > MAX_OBJECT_FIELDS:
        raise WPGAPOAuthPolicyError(f"{label} must be a bounded object")
    result: dict[str, Any] = {}
    for key, item in value.items():
        key = _text(key, f"{label} key")
        if key not in allowed:
            raise WPGAPOAuthPolicyError(f"unknown {label} field {key!r}")
        result[key] = item
    return result


def _optional_object(
    parent: Mapping[str, Any], key: str, allowed: frozenset[str], label: str
) -> dict[str, Any] | None:
    if key not in parent:
        return None
    return _object(parent[key], label, allowed)


def _optional_bool(value: Mapping[str, Any], key: str, label: str) -> bool | None:
    if key not in value:
        return None
    item = value[key]
    if not isinstance(item, bool):
        raise WPGAPOAuthPolicyError(f"{label}.{key} must be true or false")
    return item


def _optional_int(
    value: Mapping[str, Any], key: str, label: str, *, minimum: int, maximum: int
) -> int | None:
    if key not in value:
        return None
    item = value[key]
    if isinstance(item, bool) or not isinstance(item, int) or not minimum <= item <= maximum:
        raise WPGAPOAuthPolicyError(
            f"{label}.{key} must be an integer in {minimum}..{maximum}"
        )
    return item


def _optional_text(value: Mapping[str, Any], key: str, label: str) -> str | None:
    if key not in value:
        return None
    return _text(value[key], f"{label}.{key}")


def _optional_enum(
    value: Mapping[str, Any], key: str, label: str, choices: frozenset[str]
) -> str | None:
    item = _optional_text(value, key, label)
    if item is not None and item not in choices:
        raise WPGAPOAuthPolicyError(
            f"{label}.{key} must be one of {', '.join(sorted(choices))}"
        )
    return item


def _string_list(
    value: object,
    label: str,
    *,
    maximum: int = MAX_LIST_ITEMS,
    token_syntax: bool = False,
) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or isinstance(value, (str, bytes)):
        raise WPGAPOAuthPolicyError(f"{label} must be a string array")
    if len(value) > maximum:
        raise WPGAPOAuthPolicyError(f"{label} exceeds {maximum} items")
    result = tuple(_text(item, f"{label} item") for item in value)
    if token_syntax and any(_TOKEN.fullmatch(item) is None for item in result):
        raise WPGAPOAuthPolicyError(f"{label} contains an invalid protocol token")
    if len(result) != len(set(result)):
        raise WPGAPOAuthPolicyError(f"{label} contains duplicate values")
    return result


def _optional_string_list(
    value: Mapping[str, Any],
    key: str,
    label: str,
    *,
    token_syntax: bool = False,
) -> tuple[str, ...] | None:
    if key not in value:
        return None
    return _string_list(value[key], f"{label}.{key}", token_syntax=token_syntax)


def _response_type(value: object, label: str) -> tuple[str, ...]:
    items = _string_list(value, label, maximum=8, token_syntax=True)
    if not items:
        raise WPGAPOAuthPolicyError(f"{label} must not be empty")
    return tuple(sorted(items))


def _optional_response_type(
    value: Mapping[str, Any], key: str, label: str
) -> tuple[str, ...] | None:
    if key not in value:
        return None
    return _response_type(value[key], f"{label}.{key}")


def _parse_policy(value: object) -> _Policy:
    allowed = frozenset({
        "registered_response_types", "allowed_response_modes",
        "multiple_authorization_servers", "mixup_defense",
        "issuer_endpoint_tuple_bound", "issuer_selection_source",
        "pkce_used_as_csrf_defense", "pkce_enforcement",
        "reject_verifier_without_challenge", "require_par",
        "require_signed_jar", "require_dpop",
    })
    policy = _object(value, "policy", allowed)

    registered: set[tuple[str, ...]] = set()
    if "registered_response_types" in policy:
        rows = policy["registered_response_types"]
        if not isinstance(rows, (list, tuple)) or not rows or len(rows) > MAX_LIST_ITEMS:
            raise WPGAPOAuthPolicyError(
                "policy.registered_response_types must be a bounded non-empty array"
            )
        for index, row in enumerate(rows):
            normalized = _response_type(row, f"policy.registered_response_types[{index}]")
            if normalized in registered:
                raise WPGAPOAuthPolicyError("policy has a duplicate registered response type")
            registered.add(normalized)

    modes = frozenset()
    if "allowed_response_modes" in policy:
        values = _string_list(
            policy["allowed_response_modes"], "policy.allowed_response_modes",
            maximum=len(_RESPONSE_MODES),
        )
        if not values or any(item not in _RESPONSE_MODES for item in values):
            raise WPGAPOAuthPolicyError("policy.allowed_response_modes contains an unsupported mode")
        modes = frozenset(values)

    return _Policy(
        registered_response_types=frozenset(registered),
        allowed_response_modes=modes,
        multiple_authorization_servers=_optional_bool(
            policy, "multiple_authorization_servers", "policy"
        ),
        mixup_defense=_optional_enum(
            policy, "mixup_defense", "policy", _MIXUP_DEFENSES
        ),
        issuer_endpoint_tuple_bound=_optional_bool(
            policy, "issuer_endpoint_tuple_bound", "policy"
        ),
        issuer_selection_source=_optional_enum(
            policy, "issuer_selection_source", "policy",
            frozenset({"transaction", "session", "callback"}),
        ),
        pkce_used_as_csrf_defense=_optional_bool(
            policy, "pkce_used_as_csrf_defense", "policy"
        ),
        pkce_enforcement=_optional_enum(
            policy, "pkce_enforcement", "policy",
            frozenset({"required", "conditional", "none"}),
        ),
        reject_verifier_without_challenge=_optional_bool(
            policy, "reject_verifier_without_challenge", "policy"
        ),
        require_par=_optional_bool(policy, "require_par", "policy"),
        require_signed_jar=_optional_bool(policy, "require_signed_jar", "policy"),
        require_dpop=_optional_bool(policy, "require_dpop", "policy"),
    )


def _finding(
    code: str,
    severity: str,
    flow_ids: Sequence[str],
    summary: str,
    evidence: Sequence[str],
    reference: str,
    remediation: str,
) -> PolicyFinding:
    if severity not in {"critical", "high", "medium", "low", "info"}:
        raise WPGAPOAuthPolicyError("internal finding severity is invalid")
    return PolicyFinding(
        code=code,
        severity=severity,
        flow_ids=tuple(flow_ids),
        summary=_text(summary, "finding summary")[:512],
        evidence=tuple(_text(item, "finding evidence")[:512] for item in evidence),
        reference=_text(reference, "finding reference")[:256],
        remediation=_text(remediation, "finding remediation")[:512],
    )


def _append(rows: list[PolicyFinding], finding: PolicyFinding) -> None:
    if len(rows) >= MAX_FINDINGS:
        raise WPGAPOAuthPolicyError(f"finding cap exceeded ({MAX_FINDINGS})")
    rows.append(finding)


def _policy_findings(policy: _Policy, rows: list[PolicyFinding]) -> None:
    target = ("$policy",)
    if policy.multiple_authorization_servers is True:
        if policy.mixup_defense in (None, "none"):
            _append(rows, _finding(
                "mixup_defense_missing", "critical", target,
                "Multi-AS client policy has no authorization-server mix-up defense",
                (f"mixup_defense={policy.mixup_defense!r}",),
                "RFC 9700 §4.4.2",
                "Bind each transaction to an issuer and validate iss/ID Token/JARM, or use distinct redirect URIs.",
            ))
        if policy.issuer_endpoint_tuple_bound is False:
            _append(rows, _finding(
                "issuer_endpoint_tuple_not_bound", "critical", target,
                "Issuer policy does not bind authorization and token endpoints as one tuple",
                ("issuer_endpoint_tuple_bound=false",), "RFC 9700 §4.4.2",
                "Store the selected issuer and its endpoint tuple with the initiating transaction.",
            ))
        elif policy.issuer_endpoint_tuple_bound is None:
            _append(rows, _finding(
                "issuer_endpoint_binding_not_evidenced", "medium", target,
                "Multi-AS policy does not state whether the issuer endpoint tuple is transaction-bound",
                ("issuer_endpoint_tuple_bound is absent",), "RFC 9700 §4.4.2",
                "Record and enforce the authorization/token endpoint tuple selected before the callback.",
            ))
        if policy.issuer_selection_source == "callback":
            _append(rows, _finding(
                "issuer_selected_from_callback", "critical", target,
                "Issuer selection is sourced from attacker-influenced callback data",
                ("issuer_selection_source=callback",), "RFC 9700 §4.4.2",
                "Select and bind the issuer before redirecting the browser; only validate callback issuer evidence against it.",
            ))
        elif policy.issuer_selection_source is None:
            _append(rows, _finding(
                "issuer_selection_source_not_evidenced", "medium", target,
                "Multi-AS policy does not state where issuer selection is bound",
                ("issuer_selection_source is absent",), "RFC 9700 §4.4.2",
                "Record the selected issuer in transaction/session state before the authorization redirect.",
            ))

    if policy.pkce_used_as_csrf_defense is True and policy.pkce_enforcement != "required":
        _append(rows, _finding(
            "pkce_csrf_reliance_with_conditional_enforcement", "critical", target,
            "Client relies on PKCE for CSRF protection without mandatory AS enforcement",
            (f"pkce_enforcement={policy.pkce_enforcement!r}",), "RFC 9700 §§4.7.1, 4.8",
            "Require PKCE for every applicable request or retain a separate browser-bound state/nonce defense.",
        ))
    if policy.reject_verifier_without_challenge is False:
        _append(rows, _finding(
            "pkce_downgrade_policy", "critical", target,
            "AS policy accepts a verifier when the authorization request had no challenge",
            ("reject_verifier_without_challenge=false",), "RFC 9700 §4.8",
            "Reject token requests carrying a verifier unless the original request carried its challenge.",
        ))


_AUTH_KEYS = frozenset({
    "requested_response_type", "actual_response_type", "returned_members",
    "requested_response_mode", "actual_response_mode", "prompt",
    "id_token_hint_available", "id_token_hint_present", "interaction_observed",
    "silent_prerequisites_met", "silent_success", "silent_redirect_trusted",
    "fragment_open_redirect_observed", "form_post_not_stored",
})
_HYBRID_KEYS = frozenset({
    "tokens_used_before_backchannel_validation", "token_endpoint_nonce_validated",
    "c_hash_valid", "at_hash_valid", "front_back_issuer_match",
    "front_back_subject_match",
})
_BROWSER_KEYS = frozenset({
    "page_role", "url_component", "sensitive_url_fields",
    "third_party_resources", "external_links", "referrer_policy",
    "history_entry_persisted",
})
_COOKIE_KEYS = frozenset({
    "name", "host_only", "domain_attribute_present", "secure", "http_only",
    "path", "prefix", "same_name_count", "integrity_protected",
    "browser_session_bound",
})
_REDIRECT_KEYS = frozenset({
    "incoming_method", "credentials_in_body", "status", "target_role",
})
_PAR_KEYS = frozenset({
    "used", "endpoint_https", "pushed_contains_request_uri",
    "browser_parameters", "expired", "swap_defense_inside",
})
_JAR_KEYS = frozenset({
    "transport", "signed", "signature_valid", "algorithm_acceptable",
    "source_authenticated", "encrypted_only",
})
_DPOP_KEYS = frozenset({
    "context", "proof_present", "typ_valid", "algorithm_acceptable",
    "public_jwk_only", "signature_valid", "jti", "replay_context", "method_matches",
    "uri_matches", "fresh", "nonce_required", "nonce_matches",
    "ath_matches", "proof_jkt", "token_cnf_jkt", "token_type",
    "authorization_scheme", "refresh_key_matches",
})
_FLOW_KEYS = frozenset({
    "id", "authorization", "hybrid", "browser", "cookie", "redirect",
    "par", "jar", "dpop",
})


def _analyze_authorization(
    section: dict[str, Any], flow_id: str, policy: _Policy, rows: list[PolicyFinding]
) -> None:
    requested = _optional_response_type(section, "requested_response_type", "authorization")
    actual = _optional_response_type(section, "actual_response_type", "authorization")
    returned = _optional_string_list(
        section, "returned_members", "authorization", token_syntax=True
    )
    requested_mode = _optional_enum(
        section, "requested_response_mode", "authorization", _RESPONSE_MODES
    )
    actual_mode = _optional_enum(
        section, "actual_response_mode", "authorization", _RESPONSE_MODES
    )

    for label, response_type in (("requested", requested), ("actual", actual)):
        if (
            response_type is not None
            and policy.registered_response_types
            and response_type not in policy.registered_response_types
        ):
            _append(rows, _finding(
                "response_type_not_registered", "critical", (flow_id,),
                f"{label.capitalize()} response type is outside client policy",
                (f"{label}={' '.join(response_type)}",), "RFC 9700 §2.1.2",
                "Allow only preregistered response-type sets and prefer authorization code flow.",
            ))
        if response_type is not None and "none" in response_type and len(response_type) != 1:
            _append(rows, _finding(
                "response_type_none_combined", "high", (flow_id,),
                "response_type=none is combined with another response type",
                (f"{label}={' '.join(response_type)}",),
                "OAuth Multiple Response Types §5",
                "Reject response_type values that combine none with code, token, or id_token.",
            ))
    if requested is not None and actual is not None and requested != actual:
        _append(rows, _finding(
            "response_type_changed", "critical", (flow_id,),
            "Observed response type differs from the requested type",
            (f"requested={' '.join(requested)}", f"actual={' '.join(actual)}"),
            "RFC 9700 §§2.1.2, 4.6",
            "Reject response-type downgrade or substitution instead of inferring a type from returned members.",
        ))

    effective = actual or requested
    if effective is not None and returned is not None and "error" not in returned:
        expected_members = {
            "code" if item == "code" else
            "access_token" if item == "token" else
            "id_token" if item == "id_token" else item
            for item in effective
            if item != "none"
        }
        unexpected = sorted(
            set(returned).intersection({"code", "access_token", "id_token"})
            .difference(expected_members)
        )
        if unexpected:
            _append(rows, _finding(
                "unexpected_frontchannel_member", "critical", (flow_id,),
                "Authorization response contains members not authorized by response_type",
                (f"response_type={' '.join(effective)}", f"unexpected={unexpected!r}"),
                "RFC 9700 §§2.1.2, 4.6",
                "Reject extra front-channel code/token/ID-token members and bind the response to the requested type.",
            ))

    for label, mode in (("requested", requested_mode), ("actual", actual_mode)):
        if mode is not None and policy.allowed_response_modes and mode not in policy.allowed_response_modes:
            _append(rows, _finding(
                "response_mode_not_allowed", "high", (flow_id,),
                f"{label.capitalize()} response mode is outside client policy",
                (f"{label}_response_mode={mode}",),
                "OAuth Multiple Response Types §2.1; RFC 9700 §§4.2–4.3",
                "Reject modes outside the registered policy and choose a mode appropriate to the response type.",
            ))
    if requested_mode is not None and actual_mode is not None and requested_mode != actual_mode:
        _append(rows, _finding(
            "response_mode_changed", "high", (flow_id,),
            "Authorization response arrived in a different mode than requested",
            (f"requested={requested_mode}", f"actual={actual_mode}"),
            "OAuth Multiple Response Types §2.1",
            "Require the selected response mode and reject cross-mode fallback.",
        ))

    if _optional_bool(section, "fragment_open_redirect_observed", "authorization") is True:
        _append(rows, _finding(
            "fragment_open_redirect_chain", "critical", (flow_id,),
            "Fragment authorization response can traverse an open redirect",
            ("fragment_open_redirect_observed=true",), "RFC 9700 §4.1.2",
            "Use exact redirect matching, remove open redirectors, and avoid front-channel tokens.",
        ))
    form_post_not_stored = _optional_bool(section, "form_post_not_stored", "authorization")
    if actual_mode == "form_post" and form_post_not_stored is False:
        _append(rows, _finding(
            "form_post_response_reusable", "high", (flow_id,),
            "Form-post response is allowed to be stored or reused",
            ("actual_response_mode=form_post", "form_post_not_stored=false"),
            "OAuth Form Post Response Mode §2",
            "Mark the one-use form response non-cacheable and reject replay.",
        ))

    prompt = _optional_string_list(section, "prompt", "authorization", token_syntax=True)
    if prompt is not None and "none" in prompt:
        if len(prompt) != 1:
            _append(rows, _finding(
                "prompt_none_combined", "high", (flow_id,),
                "prompt=none is combined with another prompt value",
                (f"prompt={list(prompt)!r}",), "OpenID Connect Core §3.1.2.1",
                "Reject requests that combine none with any other prompt value.",
            ))
        if _optional_bool(section, "interaction_observed", "authorization") is True:
            _append(rows, _finding(
                "prompt_none_interaction", "high", (flow_id,),
                "Authentication or consent UI was shown during prompt=none",
                ("interaction_observed=true",), "OpenID Connect Core §3.1.2.1",
                "Return an OIDC interaction error without displaying UI.",
            ))
        if (
            _optional_bool(section, "silent_success", "authorization") is True
            and _optional_bool(section, "silent_prerequisites_met", "authorization") is False
        ):
            _append(rows, _finding(
                "prompt_none_without_prerequisites", "critical", (flow_id,),
                "Silent authentication succeeded without an authenticated/pre-consented session",
                ("silent_success=true", "silent_prerequisites_met=false"),
                "OpenID Connect Core §3.1.2.1",
                "Return login_required/consent_required/interaction_required instead of silently succeeding.",
            ))
        if (
            _optional_bool(section, "id_token_hint_available", "authorization") is True
            and _optional_bool(section, "id_token_hint_present", "authorization") is False
        ):
            _append(rows, _finding(
                "prompt_none_missing_id_token_hint", "low", (flow_id,),
                "A usable ID-token hint was available but omitted from prompt=none",
                ("id_token_hint_available=true", "id_token_hint_present=false"),
                "OpenID Connect Core §3.1.2.1",
                "Supply the prior ID token as id_token_hint when available and validate the resulting subject.",
            ))
        trusted = _optional_bool(section, "silent_redirect_trusted", "authorization")
        if trusted is False:
            _append(rows, _finding(
                "prompt_none_untrusted_redirect", "critical", (flow_id,),
                "prompt=none automatically redirects to a URI not trusted for silent use",
                ("silent_redirect_trusted=false",), "RFC 9700 §4.11.2",
                "Permit automatic redirects only to explicitly trusted, exactly registered redirect URIs.",
            ))
        elif trusted is None and _optional_bool(section, "silent_success", "authorization") is True:
            _append(rows, _finding(
                "prompt_none_redirect_trust_not_evidenced", "medium", (flow_id,),
                "Successful prompt=none flow lacks supplied redirect-trust evidence",
                ("silent_success=true", "silent_redirect_trusted is absent"), "RFC 9700 §4.11.2",
                "Record and enforce an explicit trusted-silent-redirect decision.",
            ))


def _analyze_hybrid(section: dict[str, Any], flow_id: str, rows: list[PolicyFinding]) -> None:
    used_early = _optional_bool(
        section, "tokens_used_before_backchannel_validation", "hybrid"
    )
    nonce_valid = _optional_bool(section, "token_endpoint_nonce_validated", "hybrid")
    if used_early is True and nonce_valid is not True:
        _append(rows, _finding(
            "hybrid_tokens_used_before_backchannel_validation", "critical", (flow_id,),
            "Hybrid-flow tokens were used before token-endpoint nonce validation",
            ("tokens_used_before_backchannel_validation=true", f"token_endpoint_nonce_validated={nonce_valid!r}"),
            "RFC 9700 §4.5.3.2",
            "Validate the nonce in the token-endpoint ID token before using any returned token.",
        ))
    if nonce_valid is False:
        _append(rows, _finding(
            "hybrid_backchannel_nonce_validation_failed", "critical", (flow_id,),
            "Token-endpoint ID-token nonce validation failed",
            ("token_endpoint_nonce_validated=false",), "RFC 9700 §4.5.3.2",
            "Discard the complete response and all associated tokens.",
        ))

    failed_hashes = [
        name for name in ("c_hash_valid", "at_hash_valid")
        if _optional_bool(section, name, "hybrid") is False
    ]
    if failed_hashes:
        _append(rows, _finding(
            "hybrid_hash_binding_failed", "critical", (flow_id,),
            "Hybrid ID-token hash binding failed",
            (f"failed={failed_hashes!r}",), "OpenID Connect Core §3.3.2.11",
            "Reject substituted authorization codes/access tokens when c_hash or at_hash validation fails.",
        ))
    failed_identity = [
        name for name in ("front_back_issuer_match", "front_back_subject_match")
        if _optional_bool(section, name, "hybrid") is False
    ]
    if failed_identity:
        _append(rows, _finding(
            "hybrid_identity_binding_failed", "critical", (flow_id,),
            "Front- and back-channel hybrid identity claims disagree",
            (f"failed={failed_identity!r}",), "OpenID Connect Core §3.3.3.6",
            "Require identical issuer and subject identity across front- and back-channel ID tokens.",
        ))


def _analyze_browser(section: dict[str, Any], flow_id: str, rows: list[PolicyFinding]) -> None:
    role = _optional_enum(
        section, "page_role", "browser", frozenset({"authorization", "callback"})
    )
    component = _optional_enum(
        section, "url_component", "browser", frozenset({"query", "fragment", "post_body"})
    )
    sensitive = _optional_string_list(
        section, "sensitive_url_fields", "browser", token_syntax=True
    ) or ()
    resources = _optional_string_list(section, "third_party_resources", "browser") or ()
    links = _optional_string_list(section, "external_links", "browser") or ()
    policy = _optional_text(section, "referrer_policy", "browser")
    if policy is not None:
        policy = policy.casefold().strip()
    parameter_safe_policies = {
        "no-referrer", "origin", "strict-origin", "origin-when-cross-origin",
        "strict-origin-when-cross-origin", "same-origin",
    }
    if (
        sensitive
        and component == "query"
        and (resources or links)
        and policy not in parameter_safe_policies
    ):
        _append(rows, _finding(
            "referer_exposure_sink", "high", (flow_id,),
            "Sensitive authorization URL has a concrete outbound Referer sink",
            (
                f"page_role={role!r}", f"sensitive_fields={list(sensitive)!r}",
                f"third_party_resources={len(resources)}", f"external_links={len(links)}",
                f"referrer_policy={policy!r}",
            ),
            "RFC 9700 §4.2",
            "Remove third-party content/links from sensitive pages and send Referrer-Policy: no-referrer.",
        ))
    if (
        sensitive
        and component in {"query", "fragment"}
        and _optional_bool(section, "history_entry_persisted", "browser") is True
    ):
        _append(rows, _finding(
            "sensitive_browser_history_entry", "medium", (flow_id,),
            "Authorization response values persist in browser history",
            (f"component={component}", f"sensitive_fields={list(sensitive)!r}"),
            "RFC 9700 §4.3",
            "Prefer form_post where appropriate and promptly replace/clear sensitive callback URLs.",
        ))


def _analyze_cookie(section: dict[str, Any], flow_id: str, rows: list[PolicyFinding]) -> None:
    name = _optional_text(section, "name", "cookie") or "<unnamed correlation cookie>"
    count = _optional_int(section, "same_name_count", "cookie", minimum=1, maximum=64)
    if count is not None and count > 1:
        _append(rows, _finding(
            "correlation_cookie_duplicate_name", "critical", (flow_id,),
            "Callback receives multiple same-name correlation cookies",
            (f"cookie={name!r}", f"same_name_count={count}"), "RFC 6265 §§5.4, 8.6",
            "Reject ambiguous duplicates; use a host-only correlation cookie with a unique deployment-wide name.",
        ))
    host_only = _optional_bool(section, "host_only", "cookie")
    domain_present = _optional_bool(section, "domain_attribute_present", "cookie")
    if host_only is False or domain_present is True:
        _append(rows, _finding(
            "correlation_cookie_domain_scoped", "high", (flow_id,),
            "OAuth correlation cookie can be scoped by a parent Domain",
            (f"cookie={name!r}", f"host_only={host_only!r}", f"domain_attribute_present={domain_present!r}"),
            "RFC 6265 §§4.1.2.3, 8.6",
            "Omit Domain and reject duplicate cookies so sibling subdomains cannot toss transaction state.",
        ))
    if _optional_bool(section, "secure", "cookie") is False:
        _append(rows, _finding(
            "correlation_cookie_insecure", "high", (flow_id,),
            "OAuth correlation cookie lacks Secure",
            (f"cookie={name!r}",), "RFC 10017 §6.1.3.2",
            "Set Secure and deliver the callback only over HTTPS.",
        ))
    if _optional_bool(section, "http_only", "cookie") is False:
        _append(rows, _finding(
            "correlation_cookie_not_httponly", "medium", (flow_id,),
            "OAuth correlation cookie is readable by script",
            (f"cookie={name!r}",), "RFC 10017 §6.1.3.2",
            "Set HttpOnly when the browser application does not need script access to the cookie.",
        ))
    path = _optional_text(section, "path", "cookie")
    prefix = _optional_enum(
        section, "prefix", "cookie",
        frozenset({"__Host-Http-", "__Host-", "other", "none"}),
    )
    if path not in (None, "/") or prefix in {"other", "none"}:
        _append(rows, _finding(
            "correlation_cookie_weak_path_or_prefix", "low", (flow_id,),
            "Correlation cookie lacks the strongest host/path naming constraints",
            (f"cookie={name!r}", f"path={path!r}", f"prefix={prefix!r}"),
            "RFC 10017 §6.1.3.2; RFC 6265 §8",
            "Use Path=/, omit Domain, set Secure, and prefer a __Host-Http- cookie name.",
        ))
    if _optional_bool(section, "integrity_protected", "cookie") is False:
        _append(rows, _finding(
            "correlation_cookie_not_integrity_protected", "high", (flow_id,),
            "Client-side OAuth transaction state lacks integrity protection",
            (f"cookie={name!r}",), "RFC 9700 §4.7.1",
            "Authenticate/encrypt application state or retain it server-side under an opaque transaction identifier.",
        ))
    if _optional_bool(section, "browser_session_bound", "cookie") is False:
        _append(rows, _finding(
            "correlation_cookie_not_session_bound", "high", (flow_id,),
            "OAuth transaction state is not bound to the initiating browser session",
            (f"cookie={name!r}",), "RFC 9700 §4.7.1",
            "Bind transaction state to the initiating user-agent session and consume it once.",
        ))


def _analyze_redirect(section: dict[str, Any], flow_id: str, rows: list[PolicyFinding]) -> None:
    method = _optional_text(section, "incoming_method", "redirect")
    if method is not None:
        method = method.upper()
        if _TOKEN.fullmatch(method) is None:
            raise WPGAPOAuthPolicyError("redirect.incoming_method is not an HTTP method token")
    credentials = _optional_bool(section, "credentials_in_body", "redirect")
    status = _optional_int(section, "status", "redirect", minimum=300, maximum=399)
    target = _optional_enum(
        section, "target_role", "redirect", frozenset({"client", "other"})
    )
    if method == "POST" and credentials is True and target == "client":
        if status in {307, 308}:
            code = "credential_post_307_forwarding" if status == 307 else "credential_post_308_forwarding"
            _append(rows, _finding(
                code, "critical", (flow_id,),
                "Method-preserving redirect forwards a credential-bearing POST to the client",
                (f"status={status}", "incoming_method=POST", "credentials_in_body=true"),
                "RFC 9700 §4.12; RFC 9110 §§15.4.8–15.4.9",
                "Use HTTP 303 after credential submission so the user agent performs a GET without the credential body.",
            ))
        elif status == 302:
            _append(rows, _finding(
                "credential_post_302_ambiguous", "medium", (flow_id,),
                "302 does not unambiguously require credential POST rewriting",
                ("status=302", "incoming_method=POST", "credentials_in_body=true"),
                "RFC 9700 §4.12",
                "Use HTTP 303 explicitly after credential submission.",
            ))


def _analyze_par(
    section: dict[str, Any] | None, flow_id: str, policy: _Policy, rows: list[PolicyFinding]
) -> None:
    if section is None:
        if policy.require_par is True:
            _append(rows, _finding(
                "par_requirement_not_evidenced", "medium", (flow_id,),
                "Policy requires PAR but this flow has no supplied PAR observation",
                ("require_par=true", "par section absent"), "RFC 9126 §6",
                "Supply and enforce evidence that the authorization request used a client-bound pushed request URI.",
            ))
        return
    used = _optional_bool(section, "used", "par")
    if policy.require_par is True and used is False:
        _append(rows, _finding(
            "par_required_but_bypassed", "critical", (flow_id,),
            "Client policy requires PAR but the observed flow used a plain front-channel request",
            ("require_par=true", "par.used=false"), "RFC 9126 §6",
            "Reject authorization requests that do not carry an AS-issued pushed request URI.",
        ))
    elif policy.require_par is True and used is None:
        _append(rows, _finding(
            "par_requirement_not_evidenced", "medium", (flow_id,),
            "Policy requires PAR but the supplied section does not say whether PAR was used",
            ("require_par=true", "par.used is absent"), "RFC 9126 §6",
            "Supply and enforce evidence that the authorization request used a client-bound pushed request URI.",
        ))
    if used is True and _optional_bool(section, "endpoint_https", "par") is False:
        _append(rows, _finding(
            "par_endpoint_not_https", "critical", (flow_id,),
            "Pushed authorization request used a non-HTTPS endpoint",
            ("par.used=true", "endpoint_https=false"), "RFC 9126 §2",
            "Send pushed requests only to the HTTPS endpoint advertised by trusted AS metadata.",
        ))
    if _optional_bool(section, "pushed_contains_request_uri", "par") is True:
        _append(rows, _finding(
            "par_contains_request_uri", "high", (flow_id,),
            "Pushed authorization request itself contains request_uri",
            ("pushed_contains_request_uri=true",), "RFC 9126 §2.1",
            "Reject nested request_uri in a pushed authorization request.",
        ))
    browser_parameters = _optional_string_list(
        section, "browser_parameters", "par", token_syntax=True
    )
    if browser_parameters is not None:
        supplied = set(browser_parameters)
        extras = sorted(supplied.difference({"client_id", "request_uri"}))
        if extras:
            _append(rows, _finding(
                "par_frontchannel_parameter_smuggling", "critical", (flow_id,),
                "PAR browser request carries authorization parameters outside the pushed object",
                (f"extra_parameters={extras!r}",), "RFC 9126 §4",
                "Accept only client_id and the issued request_uri in the browser request.",
            ))
        missing = sorted({"client_id", "request_uri"}.difference(supplied))
        if used is True and missing:
            _append(rows, _finding(
                "par_frontchannel_parameter_missing", "critical", (flow_id,),
                "PAR browser request omits a required client/handle parameter",
                (f"missing_parameters={missing!r}",), "RFC 9126 §4",
                "Require both client_id and the AS-issued request_uri in the browser authorization request.",
            ))
    if _optional_bool(section, "expired", "par") is True:
        _append(rows, _finding(
            "par_handle_expired", "high", (flow_id,),
            "Authorization request used an expired pushed request URI",
            ("expired=true",), "RFC 9126 §2.2",
            "Reject expired handles and require a freshly pushed request.",
        ))
    if used is True and _optional_bool(section, "swap_defense_inside", "par") is False:
        _append(rows, _finding(
            "par_swap_defense_missing", "high", (flow_id,),
            "Pushed request lacks the configured transaction-swapping defense",
            ("swap_defense_inside=false",), "RFC 9126 §7.5",
            "Put PKCE and/or unique state/nonce transaction binding inside the pushed request.",
        ))
    if policy.require_par is True and used is True:
        missing = [
            name for name in (
                "endpoint_https", "pushed_contains_request_uri", "browser_parameters",
                "expired", "swap_defense_inside",
            )
            if name not in section
        ]
        if missing:
            _append(rows, _finding(
                "par_validation_not_evidenced", "medium", (flow_id,),
                "Required PAR flow lacks supplied validation facts",
                (f"missing={missing!r}",), "RFC 9126 §§2, 4, 7.5",
                "Record endpoint transport, front-channel parameters, expiry, and swap-defense validation.",
            ))


def _analyze_jar(
    section: dict[str, Any] | None, flow_id: str, policy: _Policy, rows: list[PolicyFinding]
) -> None:
    if section is None:
        if policy.require_signed_jar is True:
            _append(rows, _finding(
                "signed_jar_requirement_not_evidenced", "medium", (flow_id,),
                "Policy requires signed JAR but this flow has no supplied Request Object observation",
                ("require_signed_jar=true", "jar section absent"), "RFC 9101 §6.3",
                "Supply and enforce signed Request Object validation evidence.",
            ))
        return
    transport = _optional_enum(
        section, "transport", "jar", frozenset({"none", "request", "request_uri", "both"})
    )
    if policy.require_signed_jar is True and transport == "none":
        _append(rows, _finding(
            "signed_jar_required_but_absent", "critical", (flow_id,),
            "Policy requires a signed Request Object but the flow used none",
            ("require_signed_jar=true", "jar.transport=none"), "RFC 9101 §6.3",
            "Reject plain authorization requests when signed Request Objects are required.",
        ))
    elif policy.require_signed_jar is True and transport is None:
        _append(rows, _finding(
            "signed_jar_requirement_not_evidenced", "medium", (flow_id,),
            "Policy requires signed JAR but Request Object transport is not supplied",
            ("require_signed_jar=true", "jar.transport is absent"), "RFC 9101 §6.3",
            "Supply and enforce signed Request Object transport and validation evidence.",
        ))
    if transport == "both":
        _append(rows, _finding(
            "jar_transport_conflict", "high", (flow_id,),
            "Authorization request supplies both request and request_uri",
            ("jar.transport=both",), "RFC 9101 §5",
            "Require exactly one Request Object transport.",
        ))
    if transport in {"request", "request_uri", "both"}:
        signed = _optional_bool(section, "signed", "jar")
        signature_valid = _optional_bool(section, "signature_valid", "jar")
        algorithm_ok = _optional_bool(section, "algorithm_acceptable", "jar")
        if signed is False or signature_valid is False or algorithm_ok is False:
            _append(rows, _finding(
                "jar_signature_policy_failed", "critical", (flow_id,),
                "Request Object failed supplied signature/algorithm policy",
                (
                    f"signed={signed!r}", f"signature_valid={signature_valid!r}",
                    f"algorithm_acceptable={algorithm_ok!r}",
                ),
                "RFC 9101 §§6.2–6.3",
                "Require an acceptable signed Request Object and reject any failed validation result.",
            ))
        source_auth = _optional_bool(section, "source_authenticated", "jar")
        if source_auth is False:
            _append(rows, _finding(
                "jar_source_unauthenticated", "high", (flow_id,),
                "Request Object source is not authenticated",
                ("source_authenticated=false",), "RFC 9101 §10.2",
                "Authenticate the Request Object source with a validated signature and trusted client key.",
            ))
        if _optional_bool(section, "encrypted_only", "jar") is True and source_auth is not True:
            _append(rows, _finding(
                "jar_encryption_without_authentication", "high", (flow_id,),
                "Encrypted Request Object is accepted without authenticated origin",
                ("encrypted_only=true", f"source_authenticated={source_auth!r}"),
                "RFC 9101 §§10.2, 10.5",
                "Do not treat encryption to a public key as client authentication; require a validated signature/source.",
            ))
        if policy.require_signed_jar is True:
            missing = [
                name for name in (
                    "signed", "signature_valid", "algorithm_acceptable", "source_authenticated",
                )
                if name not in section
            ]
            if missing:
                _append(rows, _finding(
                    "signed_jar_validation_not_evidenced", "medium", (flow_id,),
                    "Required signed Request Object lacks supplied validation facts",
                    (f"missing={missing!r}",), "RFC 9101 §§6.2–6.3",
                    "Record signature, algorithm, key, and source-authentication validation results.",
                ))


def _analyze_dpop(
    section: dict[str, Any] | None,
    flow_id: str,
    policy: _Policy,
    rows: list[PolicyFinding],
) -> tuple[str, str, str] | None:
    if section is None:
        if policy.require_dpop is True:
            _append(rows, _finding(
                "dpop_requirement_not_evidenced", "medium", (flow_id,),
                "Policy requires DPoP but this flow has no supplied proof observation",
                ("require_dpop=true", "dpop section absent"), "RFC 9449 §§5, 7",
                "Supply proof-validation and token-binding evidence for each applicable request.",
            ))
        return None
    context = _optional_enum(
        section, "context", "dpop", frozenset({"token", "resource", "refresh"})
    )
    proof_present = _optional_bool(section, "proof_present", "dpop")
    token_type = _optional_text(section, "token_type", "dpop")
    token_is_dpop = token_type is not None and token_type.casefold() == "dpop"
    active = policy.require_dpop is True or token_is_dpop
    if active and context is None:
        _append(rows, _finding(
            "dpop_context_not_evidenced", "medium", (flow_id,),
            "DPoP evidence does not identify whether this is a token, resource, or refresh request",
            ("dpop.context is absent",), "RFC 9449 §§5, 7",
            "Label the request context so token-hash, scheme, and refresh-key requirements can be enforced.",
        ))
    if active and proof_present is False:
        _append(rows, _finding(
            "dpop_required_but_absent", "critical", (flow_id,),
            "DPoP policy applies but the request carries no proof",
            (f"context={context!r}", "proof_present=false"), "RFC 9449 §§5, 7",
            "Reject the request unless it carries a valid DPoP proof.",
        ))
    elif active and proof_present is None:
        _append(rows, _finding(
            "dpop_requirement_not_evidenced", "medium", (flow_id,),
            "DPoP policy applies but proof presence is not supplied",
            (f"context={context!r}", "proof_present is absent"), "RFC 9449 §§5, 7",
            "Supply proof-presence and proof-validation evidence for the request.",
        ))
    if proof_present is True:
        typ = _optional_bool(section, "typ_valid", "dpop")
        public_only = _optional_bool(section, "public_jwk_only", "dpop")
        if typ is False or public_only is False:
            _append(rows, _finding(
                "dpop_proof_header_invalid", "critical", (flow_id,),
                "DPoP proof has an invalid type or exposes non-public JWK material",
                (f"typ_valid={typ!r}", f"public_jwk_only={public_only!r}"),
                "RFC 9449 §§4.2–4.3",
                "Require typ=dpop+jwt and a public-only JWK before validating the proof.",
            ))
        algorithm = _optional_bool(section, "algorithm_acceptable", "dpop")
        signature = _optional_bool(section, "signature_valid", "dpop")
        if algorithm is False or signature is False:
            _append(rows, _finding(
                "dpop_signature_policy_failed", "critical", (flow_id,),
                "DPoP proof failed asymmetric-algorithm or signature validation",
                (f"algorithm_acceptable={algorithm!r}", f"signature_valid={signature!r}"),
                "RFC 9449 §4.3",
                "Require an acceptable asymmetric algorithm and a signature valid under the proof JWK.",
            ))
        if _optional_bool(section, "method_matches", "dpop") is False:
            _append(rows, _finding(
                "dpop_method_mismatch", "critical", (flow_id,),
                "DPoP htm claim does not match the HTTP request method",
                ("method_matches=false",), "RFC 9449 §4.3",
                "Reject proofs whose htm does not match the current request.",
            ))
        if _optional_bool(section, "uri_matches", "dpop") is False:
            _append(rows, _finding(
                "dpop_uri_mismatch", "critical", (flow_id,),
                "DPoP htu claim does not match the HTTP target URI",
                ("uri_matches=false",), "RFC 9449 §4.3",
                "Reject proofs whose normalized htu does not match the current request target.",
            ))
        if _optional_bool(section, "fresh", "dpop") is False:
            _append(rows, _finding(
                "dpop_stale", "high", (flow_id,),
                "DPoP proof is outside the accepted freshness window",
                ("fresh=false",), "RFC 9449 §§4.3, 11.1",
                "Accept proofs only for a brief freshness window and track replay identifiers where feasible.",
            ))
        nonce_required = _optional_bool(section, "nonce_required", "dpop")
        nonce_matches = _optional_bool(section, "nonce_matches", "dpop")
        if nonce_required is True and nonce_matches is not True:
            _append(rows, _finding(
                "dpop_nonce_missing_or_mismatch", "critical", (flow_id,),
                "Server issued a DPoP nonce but the proof does not demonstrate an exact match",
                ("nonce_required=true", f"nonce_matches={nonce_matches!r}"),
                "RFC 9449 §§4.3, 11.3",
                "After issuing DPoP-Nonce, reject every proof that omits or mismatches it.",
            ))
        if context == "resource" and _optional_bool(section, "ath_matches", "dpop") is not True:
            _append(rows, _finding(
                "dpop_ath_missing_or_mismatch", "critical", (flow_id,),
                "Protected-resource proof does not demonstrate a valid access-token hash",
                (f"ath_matches={_optional_bool(section, 'ath_matches', 'dpop')!r}",),
                "RFC 9449 §§4.2, 7",
                "Require ath to equal the SHA-256 hash of the exact presented access token.",
            ))
        proof_jkt = _optional_text(section, "proof_jkt", "dpop")
        token_jkt = _optional_text(section, "token_cnf_jkt", "dpop")
        if proof_jkt is not None and token_jkt is not None and proof_jkt != token_jkt:
            _append(rows, _finding(
                "dpop_key_binding_mismatch", "critical", (flow_id,),
                "DPoP proof key does not match the token cnf.jkt binding",
                ("proof_jkt differs from token_cnf_jkt",), "RFC 9449 §§6.1, 7",
                "Reject the request unless the proof key thumbprint exactly matches the token binding.",
            ))
        if active:
            required_facts = [
                "typ_valid", "algorithm_acceptable", "public_jwk_only",
                "signature_valid", "jti", "method_matches", "uri_matches", "fresh",
            ]
            if context == "resource":
                required_facts.extend((
                    "ath_matches", "proof_jkt", "token_cnf_jkt",
                    "token_type", "authorization_scheme",
                ))
            elif context == "refresh":
                required_facts.append("refresh_key_matches")
            missing = [name for name in required_facts if name not in section]
            if missing:
                _append(rows, _finding(
                    "dpop_validation_not_evidenced", "medium", (flow_id,),
                    "DPoP-required request lacks supplied validation facts",
                    (f"missing={missing!r}",), "RFC 9449 §§4.2–4.3, 7",
                    "Record header/signature, request binding, freshness, token hash, and key-binding checks.",
                ))

    scheme = _optional_text(section, "authorization_scheme", "dpop")
    if policy.require_dpop is True and token_type is not None and token_type.casefold() != "dpop":
        _append(rows, _finding(
            "dpop_token_type_downgrade", "critical", (flow_id,),
            "DPoP-required policy observed a non-DPoP token type",
            (f"token_type={token_type!r}",), "RFC 9449 §5",
            "Issue a DPoP-bound token with token_type=DPoP or fail the request.",
        ))
    if token_type is not None and token_type.casefold() == "dpop" and scheme is not None and scheme.casefold() == "bearer":
        _append(rows, _finding(
            "dpop_bearer_downgrade", "critical", (flow_id,),
            "DPoP-bound access token is presented with the Bearer scheme",
            ("token_type=DPoP", "authorization_scheme=Bearer"), "RFC 9449 §7.2",
            "Reject DPoP-bound tokens as Bearer and require the DPoP authorization scheme plus proof.",
        ))
    if context == "refresh" and _optional_bool(section, "refresh_key_matches", "dpop") is False:
        _append(rows, _finding(
            "dpop_refresh_key_mismatch", "critical", (flow_id,),
            "Refresh request uses a different DPoP key than the bound refresh token",
            ("refresh_key_matches=false",), "RFC 9449 §5",
            "Require the same proof key when a DPoP-bound refresh token is used.",
        ))
    if proof_present is not True:
        return None
    jti = _optional_text(section, "jti", "dpop")
    replay_context = _optional_text(section, "replay_context", "dpop")
    proof_jkt = _optional_text(section, "proof_jkt", "dpop")
    if jti is None or replay_context is None or proof_jkt is None:
        return None
    return replay_context, proof_jkt, jti


def _analyze_document(document: Mapping[str, Any]) -> PolicyReport:
    top = _object(
        document,
        "document",
        frozenset({"schema_version", "policy", "flows"}),
    )
    version = top.get("schema_version")
    if type(version) is not int or version != 1:
        raise WPGAPOAuthPolicyError("schema_version must be integer 1")
    if "policy" not in top or "flows" not in top:
        raise WPGAPOAuthPolicyError("document requires policy and flows")
    policy = _parse_policy(top["policy"])
    flows = top["flows"]
    if not isinstance(flows, (list, tuple)) or isinstance(flows, (str, bytes)):
        raise WPGAPOAuthPolicyError("flows must be an array")
    if not 1 <= len(flows) <= MAX_FLOWS:
        raise WPGAPOAuthPolicyError(f"flows must contain 1..{MAX_FLOWS} records")

    findings: list[PolicyFinding] = []
    _policy_findings(policy, findings)
    flow_ids: list[str] = []
    jtis: dict[tuple[str, str, str], list[str]] = {}
    for index, raw_flow in enumerate(flows):
        flow = _object(raw_flow, f"flows[{index}]", _FLOW_KEYS)
        if "id" not in flow:
            raise WPGAPOAuthPolicyError(f"flows[{index}] requires id")
        flow_id = _text(flow["id"], f"flows[{index}].id")
        if flow_id in flow_ids:
            raise WPGAPOAuthPolicyError(f"duplicate flow id {flow_id!r}")
        flow_ids.append(flow_id)

        authorization = _optional_object(flow, "authorization", _AUTH_KEYS, "authorization")
        hybrid = _optional_object(flow, "hybrid", _HYBRID_KEYS, "hybrid")
        browser = _optional_object(flow, "browser", _BROWSER_KEYS, "browser")
        cookie = _optional_object(flow, "cookie", _COOKIE_KEYS, "cookie")
        redirect = _optional_object(flow, "redirect", _REDIRECT_KEYS, "redirect")
        par = _optional_object(flow, "par", _PAR_KEYS, "par")
        jar = _optional_object(flow, "jar", _JAR_KEYS, "jar")
        dpop = _optional_object(flow, "dpop", _DPOP_KEYS, "dpop")

        if authorization is not None:
            _analyze_authorization(authorization, flow_id, policy, findings)
        if hybrid is not None:
            _analyze_hybrid(hybrid, flow_id, findings)
        if browser is not None:
            _analyze_browser(browser, flow_id, findings)
        if cookie is not None:
            _analyze_cookie(cookie, flow_id, findings)
        if redirect is not None:
            _analyze_redirect(redirect, flow_id, findings)
        _analyze_par(par, flow_id, policy, findings)
        _analyze_jar(jar, flow_id, policy, findings)
        replay_key = _analyze_dpop(dpop, flow_id, policy, findings)
        if replay_key is not None:
            jtis.setdefault(replay_key, []).append(flow_id)

    for repeated_flow_ids in jtis.values():
        if len(repeated_flow_ids) > 1:
            _append(findings, _finding(
                "dpop_jti_reuse", "high", tuple(repeated_flow_ids),
                "The same DPoP proof identifier appears in multiple saved requests",
                (f"reused across {len(repeated_flow_ids)} flows",), "RFC 9449 §11.1",
                "Use a unique jti for each proof and reject a repeated value during the proof acceptance window.",
            ))

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda item: (order[item.severity], item.code, item.flow_ids, item.evidence))
    return PolicyReport(1, tuple(flow_ids), tuple(findings))


def analyze_policy(evidence: Mapping[str, Any]) -> PolicyReport:
    """Correlate one normalized policy document, never leaking stdlib errors."""

    try:
        if not isinstance(evidence, Mapping):
            raise WPGAPOAuthPolicyError("policy evidence must be an object")
        _bounded_json_tree(evidence)
        return _analyze_document(evidence)
    except WPGAPOAuthPolicyError:
        raise
    except Exception as exc:  # normalize arbitrary Mapping/list implementation failures
        raise WPGAPOAuthPolicyError("malformed OAuth/OIDC policy evidence") from exc


def analyze_json(value: str | bytes | bytearray | memoryview) -> PolicyReport:
    """Load and analyze one schema-version-1 JSON document offline."""

    try:
        return analyze_policy(load_evidence(value))
    except WPGAPOAuthPolicyError:
        raise
    except Exception as exc:
        raise WPGAPOAuthPolicyError("malformed OAuth/OIDC policy evidence") from exc


def _read(path: str) -> bytes:
    try:
        item = Path(path)
        if not item.is_file() or item.stat().st_size > MAX_INPUT_BYTES:
            raise WPGAPOAuthPolicyError(
                f"input is absent or exceeds {MAX_INPUT_BYTES} bytes"
            )
        with item.open("rb") as handle:
            raw = handle.read(MAX_INPUT_BYTES + 1)
    except WPGAPOAuthPolicyError:
        raise
    except (OSError, TypeError) as exc:
        raise WPGAPOAuthPolicyError("cannot read input") from exc
    if len(raw) > MAX_INPUT_BYTES:
        raise WPGAPOAuthPolicyError(f"input exceeds {MAX_INPUT_BYTES} bytes")
    return raw


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="local normalized OAuth/OIDC policy JSON")
    parser.add_argument("--compact", action="store_true", help="emit one-line JSON")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        try:
            args = _parser().parse_args(argv)
        except SystemExit as exc:
            return exc.code if isinstance(exc.code, int) else 2
        report = analyze_json(_read(args.input))
        if args.compact:
            print(json.dumps(report.as_dict(), sort_keys=True, separators=(",", ":")))
        else:
            print(json.dumps(report.as_dict(), indent=2, sort_keys=True))
        return 0
    except WPGAPOAuthPolicyError as exc:
        print(f"wpgap_oauth_policy: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
