"""Published-scenario fixtures for the offline OAuth/OIDC policy correlator."""

from __future__ import annotations

import ast
import copy
import json
import math
from pathlib import Path

import pytest

import wpgap_oauth_policy as oauth


def _document(*flows, policy=None):
    base_policy = {
        "registered_response_types": [["code"]],
        "allowed_response_modes": ["query", "form_post"],
        "multiple_authorization_servers": False,
        "pkce_used_as_csrf_defense": True,
        "pkce_enforcement": "required",
        "reject_verifier_without_challenge": True,
        "require_par": False,
        "require_signed_jar": False,
        "require_dpop": False,
    }
    if policy:
        base_policy.update(policy)
    if not flows:
        flows = (_clean_flow(),)
    return {"schema_version": 1, "policy": base_policy, "flows": list(flows)}


def _clean_flow(flow_id="clean"):
    return {
        "id": flow_id,
        "authorization": {
            "requested_response_type": ["code"],
            "actual_response_type": ["code"],
            "returned_members": ["code"],
            "requested_response_mode": "query",
            "actual_response_mode": "query",
        },
    }


def _codes(report):
    return {finding.code for finding in report.findings}


@pytest.fixture
def rfc9700_frontchannel_downgrade():
    """RFC 9700 §§2.1.2/4.6: code policy is changed to a token response."""

    changed = _clean_flow("changed-type")
    changed["authorization"].update({
        "actual_response_type": ["token"],
        "returned_members": ["access_token"],
        "actual_response_mode": "fragment",
    })
    injected = _clean_flow("extra-member")
    injected["authorization"]["returned_members"] = ["code", "access_token"]
    return _document(
        changed,
        injected,
        policy={"allowed_response_modes": ["query", "fragment"]},
    )


@pytest.fixture
def rfc9700_hybrid_code_injection():
    """RFC 9700 §4.5: do not use hybrid tokens before back-channel nonce checks."""

    flow = _clean_flow("hybrid")
    flow["authorization"].update({
        "requested_response_type": ["code", "id_token"],
        "actual_response_type": ["id_token", "code"],
        "returned_members": ["code", "id_token"],
    })
    flow["hybrid"] = {
        "tokens_used_before_backchannel_validation": True,
        "token_endpoint_nonce_validated": False,
        "c_hash_valid": False,
        "at_hash_valid": False,
        "front_back_issuer_match": False,
        "front_back_subject_match": False,
    }
    return _document(
        flow,
        policy={"registered_response_types": [["code", "id_token"]]},
    )


@pytest.fixture
def rfc9700_mixup_configuration():
    """RFC 9700 §4.4.2: multi-AS client with no transaction-bound defense."""

    return _document(policy={
        "multiple_authorization_servers": True,
        "mixup_defense": "none",
        "issuer_endpoint_tuple_bound": False,
        "issuer_selection_source": "callback",
        "pkce_used_as_csrf_defense": True,
        "pkce_enforcement": "conditional",
        "reject_verifier_without_challenge": False,
    })


@pytest.fixture
def rfc9700_prompt_none_phishing():
    """RFC 9700 §4.11.2 and OIDC Core prompt=none failure semantics."""

    flow = _clean_flow("silent")
    flow["authorization"].update({
        "prompt": ["none", "login"],
        "interaction_observed": True,
        "silent_success": True,
        "silent_prerequisites_met": False,
        "silent_redirect_trusted": False,
        "id_token_hint_available": True,
        "id_token_hint_present": False,
    })
    return _document(flow)


@pytest.fixture
def rfc9700_credential_forwarding():
    """RFC 9700 §4.12: 307 repeats the credential POST at the client."""

    vulnerable = _clean_flow("redirect-307")
    vulnerable["redirect"] = {
        "incoming_method": "POST",
        "credentials_in_body": True,
        "status": 307,
        "target_role": "client",
    }
    safe = _clean_flow("redirect-303")
    safe["redirect"] = {
        "incoming_method": "POST",
        "credentials_in_body": True,
        "status": 303,
        "target_role": "client",
    }
    ambiguous = _clean_flow("redirect-302")
    ambiguous["redirect"] = {
        "incoming_method": "POST",
        "credentials_in_body": True,
        "status": 302,
        "target_role": "client",
    }
    return _document(vulnerable, safe, ambiguous)


@pytest.fixture
def rfc9700_referer_leakage():
    """RFC 9700 §§4.2–4.3: callback URL plus a real third-party sink."""

    vulnerable = _clean_flow("leaky-page")
    vulnerable["browser"] = {
        "page_role": "callback",
        "url_component": "query",
        "sensitive_url_fields": ["code", "state"],
        "third_party_resources": ["https://cdn.invalid/tracker.js"],
        "external_links": [],
        "referrer_policy": "unsafe-url",
        "history_entry_persisted": True,
    }
    safe = _clean_flow("no-referrer")
    safe["browser"] = {
        "page_role": "callback",
        "url_component": "query",
        "sensitive_url_fields": ["code"],
        "third_party_resources": ["https://cdn.invalid/style.css"],
        "external_links": [],
        "referrer_policy": "no-referrer",
        "history_entry_persisted": False,
    }
    return _document(vulnerable, safe)


def test_clean_normalized_flow_has_no_findings_and_is_offline():
    report = oauth.analyze_policy(_document())
    assert report.findings == ()
    assert report.as_dict()["severity_counts"] == {}
    assert report.offline is True
    assert report.network_requests == report.token_exchanges == 0
    assert report.tokens_verified is False


def test_rfc9700_response_type_downgrade_and_extra_member(rfc9700_frontchannel_downgrade):
    report = oauth.analyze_policy(rfc9700_frontchannel_downgrade)
    assert {
        "response_type_not_registered",
        "response_type_changed",
        "unexpected_frontchannel_member",
    } <= _codes(report)
    assert all("implicit_access_token_flow" != finding.code for finding in report.findings)

    extension = _clean_flow("extension-member")
    extension["authorization"]["returned_members"] = ["code", "custom_extension"]
    assert "unexpected_frontchannel_member" not in _codes(
        oauth.analyze_policy(_document(extension))
    )


def test_rfc9700_hybrid_validation_sequence_and_bindings(rfc9700_hybrid_code_injection):
    report = oauth.analyze_policy(rfc9700_hybrid_code_injection)
    assert {
        "hybrid_tokens_used_before_backchannel_validation",
        "hybrid_backchannel_nonce_validation_failed",
        "hybrid_hash_binding_failed",
        "hybrid_identity_binding_failed",
    } <= _codes(report)

    safe = copy.deepcopy(rfc9700_hybrid_code_injection)
    safe["flows"][0]["hybrid"] = {
        "tokens_used_before_backchannel_validation": False,
        "token_endpoint_nonce_validated": True,
        "c_hash_valid": True,
        "at_hash_valid": True,
        "front_back_issuer_match": True,
        "front_back_subject_match": True,
    }
    assert not {code for code in _codes(oauth.analyze_policy(safe)) if code.startswith("hybrid_")}


def test_rfc9700_mixup_and_pkce_policy_sufficiency(rfc9700_mixup_configuration):
    assert {
        "mixup_defense_missing",
        "issuer_endpoint_tuple_not_bound",
        "issuer_selected_from_callback",
        "pkce_csrf_reliance_with_conditional_enforcement",
        "pkce_downgrade_policy",
    } <= _codes(oauth.analyze_policy(rfc9700_mixup_configuration))

    safe = copy.deepcopy(rfc9700_mixup_configuration)
    safe["policy"].update({
        "mixup_defense": "iss",
        "issuer_endpoint_tuple_bound": True,
        "issuer_selection_source": "transaction",
        "pkce_enforcement": "required",
        "reject_verifier_without_challenge": True,
    })
    assert not _codes(oauth.analyze_policy(safe))


def test_prompt_none_non_happy_paths(rfc9700_prompt_none_phishing):
    assert {
        "prompt_none_combined",
        "prompt_none_interaction",
        "prompt_none_without_prerequisites",
        "prompt_none_untrusted_redirect",
        "prompt_none_missing_id_token_hint",
    } <= _codes(oauth.analyze_policy(rfc9700_prompt_none_phishing))

    safe = copy.deepcopy(rfc9700_prompt_none_phishing)
    safe["flows"][0]["authorization"].update({
        "prompt": ["none"],
        "interaction_observed": False,
        "silent_prerequisites_met": True,
        "silent_redirect_trusted": True,
        "id_token_hint_present": True,
    })
    assert not {code for code in _codes(oauth.analyze_policy(safe)) if code.startswith("prompt_none_")}


def test_response_mode_policy_and_form_post_storage():
    flow = _clean_flow("mode")
    flow["authorization"].update({
        "requested_response_mode": "form_post",
        "actual_response_mode": "fragment",
        "form_post_not_stored": False,
    })
    report = oauth.analyze_policy(_document(
        flow,
        policy={"allowed_response_modes": ["query"]},
    ))
    assert {"response_mode_not_allowed", "response_mode_changed"} <= _codes(report)

    form = _clean_flow("form")
    form["authorization"].update({
        "requested_response_mode": "form_post",
        "actual_response_mode": "form_post",
        "form_post_not_stored": False,
    })
    assert "form_post_response_reusable" in _codes(oauth.analyze_policy(_document(form)))


def test_rfc9700_307_303_and_302_outcomes(rfc9700_credential_forwarding):
    report = oauth.analyze_policy(rfc9700_credential_forwarding)
    by_flow = {
        flow_id: {finding.code for finding in report.findings if flow_id in finding.flow_ids}
        for flow_id in report.flow_ids
    }
    assert "credential_post_307_forwarding" in by_flow["redirect-307"]
    assert not by_flow["redirect-303"]
    assert "credential_post_302_ambiguous" in by_flow["redirect-302"]


def test_rfc9700_referer_sink_and_history_are_concrete(rfc9700_referer_leakage):
    report = oauth.analyze_policy(rfc9700_referer_leakage)
    by_flow = {
        flow_id: {finding.code for finding in report.findings if flow_id in finding.flow_ids}
        for flow_id in report.flow_ids
    }
    assert {"referer_exposure_sink", "sensitive_browser_history_entry"} <= by_flow["leaky-page"]
    assert not by_flow["no-referrer"]

    origin_only = copy.deepcopy(rfc9700_referer_leakage)
    origin_only["flows"] = [origin_only["flows"][0]]
    origin_only["flows"][0]["browser"].update({
        "referrer_policy": "strict-origin",
        "history_entry_persisted": False,
    })
    assert "referer_exposure_sink" not in _codes(oauth.analyze_policy(origin_only))


def test_rfc9126_par_policy_scenarios():
    bypass = _clean_flow("par-bypass")
    bypass["par"] = {"used": False}
    malformed = _clean_flow("par-malformed")
    malformed["par"] = {
        "used": True,
        "endpoint_https": False,
        "pushed_contains_request_uri": True,
        "browser_parameters": ["client_id", "redirect_uri"],
        "expired": True,
        "swap_defense_inside": False,
    }
    report = oauth.analyze_policy(_document(
        bypass,
        malformed,
        policy={"require_par": True},
    ))
    assert {
        "par_required_but_bypassed",
        "par_endpoint_not_https",
        "par_contains_request_uri",
        "par_frontchannel_parameter_smuggling",
        "par_frontchannel_parameter_missing",
        "par_handle_expired",
        "par_swap_defense_missing",
    } <= _codes(report)

    safe = _clean_flow("par-safe")
    safe["par"] = {
        "used": True,
        "endpoint_https": True,
        "pushed_contains_request_uri": False,
        "browser_parameters": ["client_id", "request_uri"],
        "expired": False,
        "swap_defense_inside": True,
    }
    assert not {code for code in _codes(oauth.analyze_policy(_document(
        safe, policy={"require_par": True},
    ))) if code.startswith("par_")}


def test_rfc9101_signed_jar_policy_scenarios():
    flow = _clean_flow("jar-bad")
    flow["jar"] = {
        "transport": "both",
        "signed": False,
        "signature_valid": False,
        "algorithm_acceptable": False,
        "source_authenticated": False,
        "encrypted_only": True,
    }
    assert {
        "jar_transport_conflict",
        "jar_signature_policy_failed",
        "jar_source_unauthenticated",
        "jar_encryption_without_authentication",
    } <= _codes(oauth.analyze_policy(_document(
        flow, policy={"require_signed_jar": True},
    )))

    absent = _clean_flow("jar-absent")
    absent["jar"] = {"transport": "none"}
    assert "signed_jar_required_but_absent" in _codes(oauth.analyze_policy(_document(
        absent, policy={"require_signed_jar": True},
    )))


def test_rfc9449_dpop_validation_binding_and_replay():
    def bad_dpop(flow_id, context="resource"):
        flow = _clean_flow(flow_id)
        flow["dpop"] = {
            "context": context,
            "proof_present": True,
            "typ_valid": False,
            "algorithm_acceptable": False,
            "public_jwk_only": False,
            "signature_valid": False,
            "jti": "reused-proof-id",
            "replay_context": (
                "GET https://api.invalid/items"
                if context == "resource"
                else "POST https://as.invalid/token"
            ),
            "method_matches": False,
            "uri_matches": False,
            "fresh": False,
            "nonce_required": True,
            "nonce_matches": False,
            "ath_matches": False,
            "proof_jkt": "proof-key",
            "token_cnf_jkt": "token-key",
            "token_type": "DPoP",
            "authorization_scheme": "Bearer",
        }
        return flow

    first = bad_dpop("dpop-one")
    second = bad_dpop("dpop-two")
    refresh = bad_dpop("dpop-refresh", context="refresh")
    refresh["dpop"].update({
        "jti": "unique-refresh-proof",
        "refresh_key_matches": False,
    })
    report = oauth.analyze_policy(_document(
        first,
        second,
        refresh,
        policy={"require_dpop": True},
    ))
    assert {
        "dpop_proof_header_invalid",
        "dpop_signature_policy_failed",
        "dpop_method_mismatch",
        "dpop_uri_mismatch",
        "dpop_stale",
        "dpop_nonce_missing_or_mismatch",
        "dpop_ath_missing_or_mismatch",
        "dpop_key_binding_mismatch",
        "dpop_bearer_downgrade",
        "dpop_refresh_key_mismatch",
        "dpop_jti_reuse",
    } <= _codes(report)


def test_rfc9449_all_valid_dpop_observation_is_clean():
    flow = _clean_flow("dpop-safe")
    flow["dpop"] = {
        "context": "resource",
        "proof_present": True,
        "typ_valid": True,
        "algorithm_acceptable": True,
        "public_jwk_only": True,
        "signature_valid": True,
        "jti": "unique-proof-id",
        "replay_context": "GET https://api.invalid/items",
        "method_matches": True,
        "uri_matches": True,
        "fresh": True,
        "nonce_required": True,
        "nonce_matches": True,
        "ath_matches": True,
        "proof_jkt": "same-key",
        "token_cnf_jkt": "same-key",
        "token_type": "DPoP",
        "authorization_scheme": "DPoP",
    }
    assert not {code for code in _codes(oauth.analyze_policy(_document(
        flow, policy={"require_dpop": True},
    ))) if code.startswith("dpop_")}


def test_dpop_bound_token_activates_proof_policy_without_global_requirement():
    flow = _clean_flow("bound-token")
    flow["dpop"] = {
        "context": "resource",
        "proof_present": False,
        "token_type": "DPoP",
        "authorization_scheme": "Bearer",
    }
    codes = _codes(oauth.analyze_policy(_document(flow)))
    assert {"dpop_required_but_absent", "dpop_bearer_downgrade"} <= codes


def test_dpop_jti_reuse_is_scoped_by_target_and_proof_key():
    def observed(flow_id, target, key):
        flow = _clean_flow(flow_id)
        flow["dpop"] = {
            "context": "token",
            "proof_present": True,
            "jti": "same-jti",
            "replay_context": target,
            "proof_jkt": key,
        }
        return flow

    report = oauth.analyze_policy(_document(
        observed("one", "POST https://as.invalid/token", "key-a"),
        observed("other-target", "POST https://as.invalid/par", "key-a"),
        observed("other-key", "POST https://as.invalid/token", "key-b"),
    ))
    assert "dpop_jti_reuse" not in _codes(report)


def test_rfc6265_cookie_tossing_and_transaction_state_policy():
    bad = _clean_flow("cookie-bad")
    bad["cookie"] = {
        "name": "oauth_tx",
        "host_only": False,
        "domain_attribute_present": True,
        "secure": False,
        "http_only": False,
        "path": "/oauth",
        "prefix": "none",
        "same_name_count": 2,
        "integrity_protected": False,
        "browser_session_bound": False,
    }
    assert {
        "correlation_cookie_duplicate_name",
        "correlation_cookie_domain_scoped",
        "correlation_cookie_insecure",
        "correlation_cookie_not_httponly",
        "correlation_cookie_weak_path_or_prefix",
        "correlation_cookie_not_integrity_protected",
        "correlation_cookie_not_session_bound",
    } <= _codes(oauth.analyze_policy(_document(bad)))

    safe = _clean_flow("cookie-safe")
    safe["cookie"] = {
        "name": "__Host-Http-oauth_tx",
        "host_only": True,
        "domain_attribute_present": False,
        "secure": True,
        "http_only": True,
        "path": "/",
        "prefix": "__Host-Http-",
        "same_name_count": 1,
        "integrity_protected": True,
        "browser_session_bound": True,
    }
    assert not {code for code in _codes(oauth.analyze_policy(_document(safe))) if code.startswith("correlation_cookie_")}


@pytest.mark.parametrize(
    "value",
    [
        None,
        [],
        {"schema_version": True, "policy": {}, "flows": [{"id": "x"}]},
        {"schema_version": 1.0, "policy": {}, "flows": [{"id": "x"}]},
        {"schema_version": 1, "policy": {"unknown": True}, "flows": [{"id": "x"}]},
        {"schema_version": 1, "policy": {"mixup_defense": "id_token"}, "flows": [{"id": "x"}]},
        {"schema_version": 1, "policy": {}, "flows": [{"id": "x", "redirect": {"status": True}}]},
        {"schema_version": 1, "policy": {}, "flows": [{"id": "x", "dpop": {"context": "other"}}]},
        {"schema_version": 1, "policy": {}, "flows": [{"id": "x"}, {"id": "x"}]},
    ],
)
def test_public_mapping_api_fails_closed_with_declared_error(value):
    with pytest.raises(oauth.WPGAPOAuthPolicyError):
        oauth.analyze_policy(value)


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\xff",
        b'{"schema_version":1,"schema_version":1,"policy":{},"flows":[]}',
        b'{"schema_version":1,"policy":{"require_par":NaN},"flows":[]}',
        b'{"schema_version":1,"policy":{"require_par":1e999},"flows":[]}',
    ],
)
def test_json_loader_fails_closed_with_declared_error(raw):
    with pytest.raises(oauth.WPGAPOAuthPolicyError):
        oauth.analyze_json(raw)


def test_guarded_cli_unique_surface_and_no_network_imports(tmp_path, capsys):
    assert oauth.main([]) == 2
    assert oauth.main(["--not-an-option"]) == 2

    fixture = tmp_path / "policy.json"
    fixture.write_text(json.dumps(_document()), encoding="utf-8")
    assert oauth.main([str(fixture)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["offline"] is True
    assert result["network_requests"] == result["token_exchanges"] == 0
    assert result["tokens_verified"] is False

    source = Path(oauth.__file__).read_text("utf-8")
    tree = ast.parse(source)
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imports.update(
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    )
    assert not imports.intersection({
        "socket", "requests", "urllib.request", "http.client", "subprocess",
        "ftplib", "telnetlib",
    })
    assert "urlopen(" not in source
    assert "requests." not in source


def test_nonfinite_direct_mapping_is_rejected_not_leaked():
    value = _document()
    value["flows"][0]["authorization"]["silent_success"] = math.nan
    with pytest.raises(oauth.WPGAPOAuthPolicyError):
        oauth.analyze_policy(value)


def test_required_controls_treat_omitted_observations_as_unknown_not_safe():
    flow = _clean_flow("missing-proof-facts")
    flow.update({"par": {}, "jar": {}, "dpop": {}})
    report = oauth.analyze_policy(_document(
        flow,
        policy={"require_par": True, "require_signed_jar": True, "require_dpop": True},
    ))
    assert {
        "par_requirement_not_evidenced",
        "signed_jar_requirement_not_evidenced",
        "dpop_requirement_not_evidenced",
    } <= _codes(report)
