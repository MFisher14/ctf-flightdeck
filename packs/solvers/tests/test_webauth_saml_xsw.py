"""Published-layout and independent-encoder tests for the offline SAML analyzer."""

from __future__ import annotations

import base64
import hashlib
import json
import random
import sys
import urllib.parse
import zlib
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "web"))

import webauth_saml_xsw as saml  # noqa: E402


NS = (
    'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
    'xmlns:ds="http://www.w3.org/2000/09/xmldsig#"'
)
EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"


def response_signed_fixture() -> bytes:
    """OASIS browser-SSO-shaped response, written independently of the engine."""
    cert = base64.b64encode(b"independent fake DER fixture").decode()
    return f"""<samlp:Response {NS} ID="_response" Version="2.0"
      Destination="https://sp.example/acs" InResponseTo="REQ-7"
      IssueInstant="2026-11-05T12:00:00Z">
      <saml:Issuer>https://idp.example</saml:Issuer>
      <ds:Signature>
        <ds:SignedInfo>
          <ds:CanonicalizationMethod Algorithm="{EXC_C14N}"/>
          <ds:SignatureMethod Algorithm="{RSA_SHA256}"/>
          <ds:Reference URI="#_response">
            <ds:Transforms>
              <ds:Transform Algorithm="{ENVELOPED}"/>
              <ds:Transform Algorithm="{EXC_C14N}"/>
            </ds:Transforms>
            <ds:DigestMethod Algorithm="{SHA256}"/>
            <ds:DigestValue>AA==</ds:DigestValue>
          </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>AA==</ds:SignatureValue>
        <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate>
        </ds:X509Data></ds:KeyInfo>
      </ds:Signature>
      <saml:Assertion ID="_assertion" Version="2.0">
        <saml:Issuer>https://idp.example</saml:Issuer>
        <saml:Subject>
          <saml:NameID>operator@example.test</saml:NameID>
          <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml:SubjectConfirmationData Recipient="https://sp.example/acs"
              InResponseTo="REQ-7" NotOnOrAfter="2026-11-05T12:05:00Z"/>
          </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="2026-11-05T11:59:00Z"
          NotOnOrAfter="2026-11-05T12:05:00Z">
          <saml:AudienceRestriction><saml:Audience>urn:sp</saml:Audience>
          </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AttributeStatement><saml:Attribute Name="role">
          <saml:AttributeValue>operator</saml:AttributeValue>
        </saml:Attribute></saml:AttributeStatement>
      </saml:Assertion>
    </samlp:Response>""".encode()


def raw_deflate(data: bytes) -> bytes:
    """Independent RFC 1951 encoder used as the HTTP-Redirect oracle."""
    compressor = zlib.compressobj(level=9, wbits=-15)
    return compressor.compress(data) + compressor.flush()


def codes(report: dict) -> set[str]:
    return {row["code"] for row in report["findings"]}


def test_response_signature_covers_assertion_and_inventories_ceremony_fields():
    xml = response_signed_fixture()
    report = saml.analyze_saml_artifact(xml, binding="xml")

    assert report["binding"] == "xml"
    assert report["counts"] == {
        "elements": report["counts"]["elements"],
        "responses": 1,
        "assertions": 1,
        "signatures": 1,
        "references": 1,
    }
    assert report["references"][0]["status"] == "unique"
    assert report["references"][0]["target_paths"] == ["/samlp:Response[1]"]
    assert report["consumed_candidates"][0]["signature_coverage"] == "response"
    assert "assertion_outside_signed_subtree" not in codes(report)

    assertion = report["assertions"][0]
    assert assertion["issuer"] == "https://idp.example"
    assert assertion["name_ids"] == ["operator@example.test"]
    assert assertion["conditions"] == [{
        "not_before": "2026-11-05T11:59:00Z",
        "not_on_or_after": "2026-11-05T12:05:00Z",
        "audiences": ["urn:sp"],
    }]
    assert assertion["subject_confirmations"][0]["recipient"] == "https://sp.example/acs"
    assert assertion["attributes"][0]["values"] == ["operator"]

    signature = report["signatures"][0]
    assert signature["owner_path"] == "/samlp:Response[1]"
    assert signature["canonicalization_method"] == EXC_C14N
    assert signature["signature_method"] == RSA_SHA256
    assert signature["key_info_present"] is True
    assert signature["x509_certificate_count"] == 1
    expected_fingerprint = hashlib.sha256(b"independent fake DER fixture").hexdigest()
    assert signature["x509_sha256"] == [expected_fingerprint]
    assert report["verified"] is False
    assert report["transforms_executed"] == 0
    assert report["offline_only"] is True and report["network_requests"] == 0


def test_http_post_form_base64_is_decoded_by_independent_encoder():
    xml = response_signed_fixture()
    encoded = base64.b64encode(xml).decode()
    body = "RelayState=opaque&SAMLResponse=" + urllib.parse.quote_plus(encoded)

    decoded = saml.decode_saml_artifact(body, binding="post")
    assert decoded["binding"] == "http-post"
    assert decoded["parameter"] == "SAMLResponse"
    assert decoded["xml"] == xml

    report = saml.analyze_saml_artifact(body)
    assert report["binding"] == "http-post"
    assert report["parameter"] == "SAMLResponse"
    assert report["counts"]["assertions"] == 1


def test_http_redirect_raw_deflate_urlencoding_is_decoded():
    request = (
        f'<samlp:AuthnRequest {NS} ID="REQ-42" Version="2.0" '
        'AssertionConsumerServiceURL="https://sp.example/acs">'
        '<saml:Issuer>urn:sp</saml:Issuer></samlp:AuthnRequest>'
    ).encode()
    encoded = base64.b64encode(raw_deflate(request)).decode()
    url = "https://idp.example/sso?SAMLRequest=" + urllib.parse.quote_plus(encoded) + "&RelayState=R7"

    decoded = saml.decode_saml_artifact(url, binding="redirect")
    assert decoded["binding"] == "http-redirect"
    assert decoded["parameter"] == "SAMLRequest"
    assert decoded["xml"] == request

    report = saml.analyze_saml_artifact(url, binding="auto")
    assert report["root"]["tag"] == "samlp:AuthnRequest"
    assert report["counts"]["responses"] == 0
    assert report["offline_only"] and report["network_requests"] == 0


def test_samlraider_style_signed_and_unsigned_siblings_are_exact_candidates():
    xml = f"""<samlp:Response {NS} ID="R">
      <ds:Signature><ds:SignedInfo><ds:Reference URI="#SIGNED">
        <ds:Transforms><ds:Transform Algorithm="{ENVELOPED}"/></ds:Transforms>
        <ds:DigestMethod Algorithm="{SHA256}"/>
      </ds:Reference></ds:SignedInfo></ds:Signature>
      <saml:Assertion ID="SIGNED"><saml:Subject><saml:NameID>user</saml:NameID>
      </saml:Subject></saml:Assertion>
      <saml:Assertion ID="INJECTED"><saml:Subject><saml:NameID>administrator</saml:NameID>
      </saml:Subject></saml:Assertion>
    </samlp:Response>"""
    report = saml.analyze_saml_artifact(xml)
    assert report["references"][0]["target_paths"] == [
        "/samlp:Response[1]/saml:Assertion[1]",
    ]
    assert [row["signature_coverage"] for row in report["consumed_candidates"]] == [
        "assertion", "none",
    ]
    assert [row["name_ids"] for row in report["consumed_candidates"]] == [
        ["user"], ["administrator"],
    ]
    assert {"multiple_assertions", "assertion_outside_signed_subtree",
            "signed_consumed_node_mismatch_candidate"} <= codes(report)


def test_nonstandard_id_collision_is_parser_differential_not_normative_ambiguity():
    xml = f"""<samlp:Response {NS} ID="R">
      <ds:Signature><ds:SignedInfo><ds:Reference URI="#DUP"/></ds:SignedInfo></ds:Signature>
      <saml:Assertion ID="DUP"><saml:Subject><saml:NameID>signed</saml:NameID></saml:Subject></saml:Assertion>
      <saml:Assertion Id="DUP"><saml:Subject><saml:NameID>forged</saml:NameID></saml:Subject></saml:Assertion>
    </samlp:Response>"""
    report = saml.analyze_saml_artifact(xml)
    assert report["references"][0]["status"] == "unique"
    assert report["references"][0]["target_paths"] == [
        "/samlp:Response[1]/saml:Assertion[1]",
    ]
    assert {"nonstandard_id_attribute", "id_resolution_differential",
            "signed_consumed_node_mismatch_candidate"} <= codes(report)
    assert "duplicate_id" not in codes(report)
    assert [row["signature_coverage"] for row in report["consumed_candidates"]] == [
        "assertion", "none",
    ]


def test_duplicate_normative_ids_remain_ambiguous_and_xml_id_is_normative():
    duplicate = f"""<samlp:Response {NS} ID="R">
      <ds:Signature><ds:SignedInfo><ds:Reference URI="#DUP"/></ds:SignedInfo></ds:Signature>
      <saml:Assertion ID="DUP"/><saml:Assertion ID="DUP"/>
    </samlp:Response>"""
    report = saml.analyze_saml_artifact(duplicate)
    assert report["references"][0]["status"] == "ambiguous"
    assert {"duplicate_id", "ambiguous_reference"} <= codes(report)
    assert all(row["signature_coverage"] == "none" for row in report["consumed_candidates"])

    xml_id = f"""<samlp:Response {NS} ID="R">
      <ds:Signature><ds:SignedInfo><ds:Reference URI="#XML-ID"/></ds:SignedInfo></ds:Signature>
      <saml:Assertion xml:id="XML-ID"><saml:Subject><saml:NameID>user</saml:NameID>
      </saml:Subject></saml:Assertion>
    </samlp:Response>"""
    xml_report = saml.analyze_saml_artifact(xml_id)
    assert xml_report["references"][0]["status"] == "unique"
    assert xml_report["assertions"][0]["ids"] == [{
        "attribute": "xml:id", "value": "XML-ID", "normative": True, "kind": "xml:id",
    }]
    assert xml_report["consumed_candidates"][0]["signature_coverage"] == "assertion"


def test_foreign_namespace_signature_lookalikes_never_establish_coverage():
    xml = f"""<samlp:Response {NS} xmlns:e="urn:attacker" ID="R">
      <e:Signature><e:SignedInfo><e:Reference URI="#R"/></e:SignedInfo></e:Signature>
      <saml:Assertion ID="A"><saml:Subject><saml:NameID>admin</saml:NameID>
      </saml:Subject></saml:Assertion>
    </samlp:Response>"""
    report = saml.analyze_saml_artifact(xml)
    assert report["counts"]["signatures"] == 0
    assert report["counts"]["references"] == 0
    assert report["references"] == []
    assert report["consumed_candidates"][0]["signature_coverage"] == "none"
    assert {"namespace_confusion", "assertion_outside_signed_subtree"} <= codes(report)


def test_real_ds_reference_outside_signed_info_is_ignored_for_coverage():
    xml = f"""<samlp:Response {NS} ID="R">
      <ds:Signature><ds:Object><ds:Reference URI="#R"/></ds:Object></ds:Signature>
      <saml:Assertion ID="A"><saml:Subject><saml:NameID>user</saml:NameID>
      </saml:Subject></saml:Assertion>
    </samlp:Response>"""
    report = saml.analyze_saml_artifact(xml)
    assert report["counts"]["signatures"] == 1
    assert report["counts"]["references"] == 1
    assert report["references"] == []
    assert report["signatures"][0]["references"] == []
    assert report["ignored_references"] == [
        "/samlp:Response[1]/ds:Signature[1]/ds:Object[1]/ds:Reference[1]",
    ]
    assert report["consumed_candidates"][0]["signature_coverage"] == "none"
    assert "reference_outside_signed_info" in codes(report)


def test_hidden_signed_node_risky_transform_and_sha1_are_catalogued_not_executed():
    xpath = "http://www.w3.org/TR/1999/REC-xpath-19991116"
    rsa_sha1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
    digest_sha1 = "http://www.w3.org/2000/09/xmldsig#sha1"
    xml = f"""<samlp:Response {NS} ID="R">
      <ds:Signature><ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="{EXC_C14N}"/>
        <ds:SignatureMethod Algorithm="{rsa_sha1}"/>
        <ds:Reference URI="#HIDDEN"><ds:Transforms><ds:Transform Algorithm="{xpath}"/>
        </ds:Transforms><ds:DigestMethod Algorithm="{digest_sha1}"/></ds:Reference>
      </ds:SignedInfo></ds:Signature>
      <samlp:Extensions><ds:Object><saml:Assertion ID="HIDDEN">
        <saml:Subject><saml:NameID>old-user</saml:NameID></saml:Subject>
      </saml:Assertion></ds:Object></samlp:Extensions>
      <saml:Assertion ID="LIVE"><saml:Subject><saml:NameID>admin</saml:NameID>
      </saml:Subject></saml:Assertion>
    </samlp:Response>"""
    report = saml.analyze_saml_artifact(xml)
    assert {"signed_node_hidden", "risky_transform", "sha1_algorithm",
            "signed_consumed_node_mismatch_candidate"} <= codes(report)
    assert report["transforms_executed"] == 0
    hidden = next(row for row in report["findings"] if row["code"] == "signed_node_hidden")
    assert any("ds:Object" in path for path in hidden["evidence"]["container_paths"])


@pytest.mark.parametrize("artifact,binding", [
    (b"", "auto"),
    (123, "auto"),
    ("<Response><broken></Response>", "xml"),
    ("%%%%", "post"),
    ("SAMLResponse=%GG", "post"),
    (base64.b64encode(b"not xml").decode(), "post"),
    (base64.b64encode(b"not deflate").decode(), "redirect"),
])
def test_malformed_public_inputs_raise_only_declared_error(artifact, binding):
    with pytest.raises(saml.WebauthSamlError):
        saml.analyze_saml_artifact(artifact, binding=binding)


def test_dtd_entities_and_overdeep_documents_fail_closed():
    with pytest.raises(saml.WebauthSamlError, match="DTD|ENTITY"):
        saml.analyze_saml_artifact(
            '<!DOCTYPE Response [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            '<Response>&xxe;</Response>',
        )
    deep = "<x>" * (saml.MAX_DEPTH + 2) + "ok" + "</x>" * (saml.MAX_DEPTH + 2)
    with pytest.raises(saml.WebauthSamlError, match="depth"):
        saml.analyze_saml_artifact(deep)


def test_seeded_hostile_bytes_have_one_public_error_boundary():
    rng = random.Random(0x5A4D4C)
    alphabet = bytes(range(256))
    for _ in range(200):
        raw = bytes(rng.choice(alphabet) for _ in range(rng.randrange(1, 128)))
        try:
            result = saml.analyze_saml_artifact(raw)
            assert result["offline_only"] is True
        except saml.WebauthSamlError:
            pass


def test_cli_file_mode_and_guarded_argparse(tmp_path, capsys):
    path = tmp_path / "response.xml"
    path.write_bytes(response_signed_fixture())
    assert saml.main([str(path), "--file", "--binding", "xml"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["counts"]["assertions"] == 1
    assert report["network_requests"] == 0

    assert saml.main([]) == 2
    captured = capsys.readouterr()
    assert "Traceback" not in captured.err
    assert saml.main(["--help"]) == 0

