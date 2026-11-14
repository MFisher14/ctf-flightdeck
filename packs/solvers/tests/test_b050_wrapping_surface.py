"""B-050: lexical signature-wrapping surface summary.

signature_wrapping_surface consumes an existing SamlLexicalReport (it does not
re-parse) and groups the lexical conditions that let a wrapped SAML document
validate under one node while the application consumes another.
"""

from __future__ import annotations

import dataclasses

import pytest

import wpgap_saml_lexical as saml


SAML_PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol"
SAML_ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
DSIG = "http://www.w3.org/2000/09/xmldsig#"


def test_clean_document_has_no_wrapping_surface():
    xml = f"""<samlp:Response xmlns:samlp="{SAML_PROTOCOL}"
                xmlns:saml="{SAML_ASSERTION}" xmlns:ds="{DSIG}" ID="R">
      <saml:Assertion ID="A"><saml:Issuer>urn:idp</saml:Issuer></saml:Assertion>
    </samlp:Response>"""
    report = saml.lint_saml_xml(xml)
    surface = saml.signature_wrapping_surface(report)
    assert surface["wrapping_surface_present"] is False
    assert surface["signals"] == [] and surface["categories"] == []
    assert surface["max_severity"] is None
    assert surface["canonicalization_stable"] is True
    assert surface["network_requests"] == 0 and surface["offline_only"] is True


def test_namespace_collision_surfaces_as_a_critical_wrapping_signal():
    # "Assertion" appears in both the SAML assertion namespace and a foreign one:
    # exactly the confusion a wrapping attack relies on.
    xml = f"""<samlp:Response xmlns:samlp="{SAML_PROTOCOL}"
                xmlns:saml="{SAML_ASSERTION}" xmlns:evil="urn:evil" ID="R">
      <saml:Assertion ID="A"><saml:Issuer>urn:idp</saml:Issuer></saml:Assertion>
      <evil:Assertion ID="B"><saml:Issuer>urn:attacker</saml:Issuer></evil:Assertion>
    </samlp:Response>"""
    report = saml.lint_saml_xml(xml)
    surface = saml.signature_wrapping_surface(report)
    assert surface["wrapping_surface_present"] is True
    assert "namespace_confusion" in surface["categories"]
    assert surface["max_severity"] == "critical"
    codes = {signal["code"] for signal in surface["signals"]}
    assert "sensitive_element_namespace_collision" in codes
    # signals are ranked most-severe first
    severities = [saml._SEVERITY_RANK[s["severity"]] for s in surface["signals"]]
    assert severities == sorted(severities, reverse=True)


def test_prefix_rebinding_is_classified_as_a_wrapping_signal():
    xml = f"""<samlp:Response xmlns:samlp="{SAML_PROTOCOL}"
                xmlns:saml="{SAML_ASSERTION}" ID="R">
      <saml:Assertion xmlns:saml="urn:evil" ID="A">x</saml:Assertion>
    </samlp:Response>"""
    report = saml.lint_saml_xml(xml)
    surface = saml.signature_wrapping_surface(report)
    assert surface["wrapping_surface_present"] is True
    assert "prefix_rebinding" in surface["categories"]


def test_failed_canonicalization_marks_surface_unstable():
    # A relative namespace URI has no standards-compliant canonical form: every
    # probe errors, so the surface must not report canonicalization as stable.
    xml = f"""<samlp:Response xmlns:samlp="{SAML_PROTOCOL}" xmlns:r="relative/ns" ID="R">
      <r:x/></samlp:Response>"""
    report = saml.lint_saml_xml(xml)
    assert {probe.status for probe in report.probes} == {"error"}
    surface = saml.signature_wrapping_surface(report)
    assert surface["canonicalization_stable"] is False
    assert "canonicalization_gap" in surface["categories"]
    codes = {signal["code"] for signal in surface["signals"]}
    assert {"canonicalization_error", "relative_namespace_uri"} <= codes


@pytest.mark.parametrize("status", ["drift", "empty"])
def test_one_drifting_or_empty_probe_marks_surface_unstable(status):
    xml = f"""<samlp:Response xmlns:samlp="{SAML_PROTOCOL}" ID="R">
      <samlp:Status/></samlp:Response>"""
    report = saml.lint_saml_xml(xml)
    assert {probe.status for probe in report.probes} == {"ok"}
    assert saml.signature_wrapping_surface(report)["canonicalization_stable"] is True
    # The surface reads probe status from the report it is given: one bad probe
    # among otherwise clean ones is enough to call canonicalization unstable.
    probes = list(report.probes)
    probes[2] = dataclasses.replace(probes[2], status=status)
    drifted = dataclasses.replace(report, probes=tuple(probes))
    assert saml.signature_wrapping_surface(drifted)["canonicalization_stable"] is False


def test_non_report_input_is_rejected():
    with pytest.raises(saml.WpgapSamlError, match="SamlLexicalReport"):
        saml.signature_wrapping_surface({"findings": []})
