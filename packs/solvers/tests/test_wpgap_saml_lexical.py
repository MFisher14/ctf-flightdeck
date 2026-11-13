"""Published differential and canonicalization cases for the SAML lexical linter.

Primary oracles:
* PortSwigger, "The Fragile Lock" and the published Golden SAML Response
* GHSL-2024-329/330 / CVE-2025-25291 and CVE-2025-25292
* W3C Canonical XML 1.0 section 3.3, example e5
* W3C Exclusive XML Canonicalization section 1.3 (QName-valued attributes)
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import FrozenInstanceError

import pytest

import wpgap_saml_lexical as saml


SAML_PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol"
SAML_ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
DSIG = "http://www.w3.org/2000/09/xmldsig#"
XML_NS = "http://www.w3.org/XML/1998/namespace"
XMLNS_NS = "http://www.w3.org/2000/xmlns/"
XSI = "http://www.w3.org/2001/XMLSchema-instance"
XSD = "http://www.w3.org/2001/XMLSchema"
EXC = "http://www.w3.org/2001/10/xml-exc-c14n#"


def _codes(report) -> set[str]:
    return {finding.code for finding in report.findings}


def _finding(report, code: str):
    return next(finding for finding in report.findings if finding.code == code)


def _probes(report):
    for name in ("probes", "canonicalization_probes", "c14n_probes"):
        value = getattr(report, name, None)
        if value is not None:
            return value
    raise AssertionError("report exposes no canonicalization probes")


def _probe(report, mode: str, with_comments: bool = False):
    for probe in _probes(report):
        if probe.mode == mode and probe.with_comments is with_comments:
            return probe
    raise AssertionError(f"missing {mode}, comments={with_comments} probe")


def test_clean_saml_arbitrary_prefix_and_same_value_redeclaration_are_clean():
    xml = f"""<proto:Response xmlns:proto="{SAML_PROTOCOL}"
                 xmlns:claim="{SAML_ASSERTION}" xml:lang="en" ID="R">
      <claim:Assertion ID="A">
        <claim:Issuer>urn:idp</claim:Issuer>
        <sig:Signature xmlns:sig="{DSIG}">
          <sig:SignedInfo xmlns:sig="{DSIG}"/>
        </sig:Signature>
      </claim:Assertion>
    </proto:Response>"""
    report = saml.lint_saml_xml(xml)
    assert report.findings == ()
    assert all(probe.status == "ok" for probe in _probes(report))


def test_portswigger_golden_relative_namespace_is_a_void_c14n_risk():
    # d0ge/XSW samples/Golden-SAMLResponse.xml begins with this unused relative
    # declaration. The published full sample hashes an empty c14n result.
    xml = f'<samlp:Response xmlns:samlp="{SAML_PROTOCOL}" xmlns:example="1"/>'
    report = saml.lint_saml_xml(xml)
    assert {"relative_namespace_uri", "canonicalization_void_risk"} <= _codes(report)
    assert all(probe.status != "ok" for probe in _probes(report))
    assert all(probe.output_bytes in (None, 0) for probe in _probes(report))


def test_portswigger_reserved_xmlns_and_signature_hiding_forms():
    direct = saml.lint_saml_xml(
        f'<Root><Signature xml:xmlns="{DSIG}"/></Root>'
    )
    assert "reserved_namespace_attribute" in _codes(direct)

    hiding = saml.lint_saml_xml(
        f'<Root><Parent xmlns="{DSIG}"><Child xml:xmlns="#anything">'
        "<Signature/></Child></Parent></Root>"
    )
    assert {"reserved_namespace_attribute", "relative_namespace_uri"} <= _codes(hiding)


@pytest.mark.parametrize(
    "attributes, expected_order",
    [
        ('ID="1" samlp:ID="2"', (("ID", "1"), ("samlp:ID", "2"))),
        ('samlp:ID="2" ID="1"', (("samlp:ID", "2"), ("ID", "1"))),
    ],
)
def test_published_attribute_pollution_orders_preserve_lexical_evidence(
    attributes, expected_order
):
    # PortSwigger's namespace-insensitive getter differential: the source
    # order changes which ID some REXML/libxml2 APIs return.
    report = saml.lint_saml_xml(
        f'<samlp:Response xmlns:samlp="{SAML_PROTOCOL}" {attributes}/>'
    )
    finding = _finding(report, "attribute_local_name_collision")
    evidence = dict(finding.evidence)
    qnames = json.loads(evidence["ordered_qnames"])
    values = json.loads(evidence["ordered_values"])
    assert tuple(zip(qnames, values)) == expected_order


def test_descendant_rebind_and_simultaneous_aliases_without_prefix_false_positives():
    rebound = saml.lint_saml_xml(
        f'<Root xmlns:ds="{DSIG}"><ds:Signature/>'
        '<Wrap xmlns:ds="urn:attacker"><ds:Signature/></Wrap></Root>'
    )
    assert {"sensitive_prefix_rebinding", "sensitive_element_namespace_collision"} <= _codes(rebound)

    same = saml.lint_saml_xml(
        f'<Root xmlns:ds="{DSIG}"><Wrap xmlns:ds="{DSIG}"><ds:Signature/>'
        "</Wrap></Root>"
    )
    assert same.findings == ()

    normal_default_switch = saml.lint_saml_xml(
        f'<Response xmlns="{SAML_PROTOCOL}"><Assertion xmlns="{SAML_ASSERTION}"/>'
        "</Response>"
    )
    assert normal_default_switch.findings == ()

    aliases = saml.lint_saml_xml(
        f'<Root xmlns:a="{DSIG}" xmlns:b="{DSIG}"><a:Signature/><b:SignedInfo/></Root>'
    )
    assert "namespace_alias_pollution" in _codes(aliases)

    arbitrary = saml.lint_saml_xml(
        f'<Root xmlns:arbitrary="{DSIG}"><arbitrary:Signature/></Root>'
    )
    assert arbitrary.findings == ()


def test_reserved_bindings_and_namespace_well_formedness_fail_closed():
    correct = saml.lint_saml_xml(
        f'<r xmlns:xml="{XML_NS}" xml:lang="en"/>'
    )
    assert not ({"reserved_namespace_binding", "reserved_namespace_attribute"} & _codes(correct))

    bad_documents = (
        '<r xmlns:xml="urn:not-xml"/>',
        '<r xmlns:xmlns="urn:attacker"/>',
        f'<r xmlns:evil="{XMLNS_NS}"/>',
        '<r xmlns:empty=""/>',
    )
    for xml in bad_documents:
        try:
            report = saml.lint_saml_xml(xml)
        except saml.WpgapSamlError:
            continue
        assert {"reserved_namespace_binding", "empty_prefixed_namespace"} & _codes(report)

    for xml, code in (
        ("<p:r/>", "undeclared_prefix"),
        ('<r xmlns:a="urn:u" xmlns:b="urn:u" a:x="1" b:x="2"/>',
         "duplicate_expanded_attribute"),
    ):
        try:
            report = saml.lint_saml_xml(xml)
        except saml.WpgapSamlError:
            continue
        assert code in _codes(report)


def test_w3c_c14n_section_3_3_e5_exact_inclusive_oracle():
    # W3C Canonical XML 1.0 section 3.3, e5 input/output. Attribute and
    # declaration order here is deliberately non-canonical.
    xml = (
        '<e5 a:attr="out" b:attr="sorted" attr2="all" attr="I\'m" '
        'xmlns:b="http://www.ietf.org" xmlns:a="http://www.w3.org" '
        'xmlns="http://example.org"/>'
    )
    expected = (
        b'<e5 xmlns="http://example.org" xmlns:a="http://www.w3.org" '
        b'xmlns:b="http://www.ietf.org" attr="I\'m" attr2="all" '
        b'b:attr="sorted" a:attr="out"></e5>'
    )
    report = saml.lint_saml_xml(xml)
    probe = _probe(report, "inclusive", False)
    assert probe.status == "ok"
    assert probe.output_bytes == len(expected)
    assert probe.sha256 == hashlib.sha256(expected).hexdigest()
    assert probe.semantic_roundtrip is True
    assert probe.idempotent is True


def _qname_value_document(prefix_list: str | None) -> str:
    inclusive = ""
    if prefix_list is not None:
        inclusive = f'<ec:InclusiveNamespaces PrefixList="{prefix_list}"/>'
    return f"""<Root xmlns:ds="{DSIG}" xmlns:ec="{EXC}"
      xmlns:xsi="{XSI}" xmlns:xsd="{XSD}">
      <ds:Signature><ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="{EXC}">{inclusive}</ds:CanonicalizationMethod>
      </ds:SignedInfo></ds:Signature>
      <Value xsi:type="xsd:decimal">10.09</Value>
    </Root>"""


def test_w3c_exclusive_c14n_qname_value_dependency_and_prefix_list():
    # Exclusive C14N section 1.3: xsd is semantically used inside xsi:type,
    # but is not "visibly utilized" by an element/attribute QName.
    vulnerable = saml.lint_saml_xml(_qname_value_document(None))
    assert "qname_value_namespace_dependency" in _codes(vulnerable)

    included = saml.lint_saml_xml(_qname_value_document("xsd"))
    assert "qname_value_namespace_dependency" not in _codes(included)

    duplicate = saml.lint_saml_xml(_qname_value_document("xsd xsd"))
    assert "inclusive_prefix_duplicate" in _codes(duplicate)
    unbound = saml.lint_saml_xml(_qname_value_document("missing"))
    assert "inclusive_prefix_unbound" in _codes(unbound)

    unicode_prefix = f"""<Root xmlns:ds="{DSIG}" xmlns:xsi="{XSI}"
      xmlns:π="urn:decimal">
      <ds:CanonicalizationMethod Algorithm="{EXC}"/>
      <Value xsi:type="π:decimal">10.09</Value>
    </Root>"""
    assert "qname_value_namespace_dependency" in _codes(
        saml.lint_saml_xml(unicode_prefix)
    )

    default_dependency = f"""<Root xmlns:ds="{DSIG}" xmlns:ec="{EXC}"
      xmlns:v="urn:value" xmlns:xsi="{XSI}">
      <ds:CanonicalizationMethod Algorithm="{EXC}"/>
      <v:Value xmlns="urn:type" xsi:type="decimal">10.09</v:Value>
    </Root>"""
    assert "qname_value_namespace_dependency" in _codes(
        saml.lint_saml_xml(default_dependency)
    )

    default_inclusive = default_dependency.replace(
        f'<ds:CanonicalizationMethod Algorithm="{EXC}"/>',
        f'<ds:CanonicalizationMethod Algorithm="{EXC}">'
        '<ec:InclusiveNamespaces PrefixList="#default"/>'
        "</ds:CanonicalizationMethod>",
    )
    default_report = saml.lint_saml_xml(default_inclusive)
    assert "qname_value_namespace_dependency" not in _codes(default_report)
    assert "inclusive_prefix_unbound" not in _codes(default_report)


def test_qualified_algorithm_and_unrelated_prefix_list_cannot_suppress_qname_risk():
    qualified_decoy = f"""<Root xmlns:ds="{DSIG}" xmlns:ec="{EXC}"
      xmlns:e="urn:decoy" xmlns:xsi="{XSI}" xmlns:xsd="{XSD}">
      <ds:CanonicalizationMethod e:Algorithm="urn:no" Algorithm="{EXC}"/>
      <Value xsi:type="xsd:decimal">10.09</Value>
    </Root>"""
    decoy_report = saml.lint_saml_xml(qualified_decoy)
    assert EXC in decoy_report.declared_c14n_algorithms
    assert "qname_value_namespace_dependency" in _codes(decoy_report)

    unrelated = f"""<Root xmlns:ds="{DSIG}" xmlns:ec="{EXC}"
      xmlns:xsi="{XSI}" xmlns:xsd="{XSD}">
      <ec:InclusiveNamespaces PrefixList="xsd"/>
      <ds:CanonicalizationMethod Algorithm="{EXC}"/>
      <Value xsi:type="xsd:decimal">10.09</Value>
    </Root>"""
    unrelated_report = saml.lint_saml_xml(unrelated)
    assert {
        "orphan_inclusive_namespaces",
        "qname_value_namespace_dependency",
    } <= _codes(unrelated_report)

    qualified_prefix_list = f"""<Root xmlns:ds="{DSIG}" xmlns:ec="{EXC}"
      xmlns:e="urn:decoy" xmlns:xsi="{XSI}" xmlns:xsd="{XSD}">
      <ds:CanonicalizationMethod Algorithm="{EXC}">
        <ec:InclusiveNamespaces e:PrefixList="xsd"/>
      </ds:CanonicalizationMethod>
      <Value xsi:type="xsd:decimal">10.09</Value>
    </Root>"""
    qualified_report = saml.lint_saml_xml(qualified_prefix_list)
    assert "qname_value_namespace_dependency" in _codes(qualified_report)

    for parameters in (
        '<ec:InclusiveNamespaces PrefixList=""/>'
        '<ec:InclusiveNamespaces PrefixList="xsd"/>',
        '<ec:InclusiveNamespaces PrefixList="xsd"/>'
        '<ec:InclusiveNamespaces PrefixList=""/>',
    ):
        multiple = f"""<Root xmlns:ds="{DSIG}" xmlns:ec="{EXC}"
          xmlns:xsi="{XSI}" xmlns:xsd="{XSD}">
          <ds:CanonicalizationMethod Algorithm="{EXC}">{parameters}
          </ds:CanonicalizationMethod>
          <Value xsi:type="xsd:decimal">10.09</Value>
        </Root>"""
        multiple_report = saml.lint_saml_xml(multiple)
        assert {
            "multiple_inclusive_namespaces",
            "qname_value_namespace_dependency",
        } <= _codes(multiple_report)


def test_whole_document_c14n_keeps_top_level_processing_instructions_and_comments():
    xml = "<!--pre--><?pre x?><r/><?post y?><!--post-->"
    without_comments = b"<?pre x?>\n<r></r>\n<?post y?>"
    with_comments = (
        b"<!--pre-->\n<?pre x?>\n<r></r>\n<?post y?>\n<!--post-->"
    )
    report = saml.lint_saml_xml(xml)
    plain = _probe(report, "inclusive", False)
    commented = _probe(report, "inclusive", True)
    assert plain.status == "ok"
    assert plain.sha256 == hashlib.sha256(without_comments).hexdigest()
    assert commented.status == "ok"
    assert commented.sha256 == hashlib.sha256(with_comments).hexdigest()


def test_ordinary_xmlns_local_name_and_alias_evidence_are_bounded():
    ordinary = saml.lint_saml_xml('<r xmlns:foo="urn:foo" foo:xmlns="value"/>')
    assert "reserved_namespace_attribute" not in _codes(ordinary)
    assert ordinary.namespace_well_formed is True

    reserved_family = saml.lint_saml_xml('<r xmlns:xmlTool="urn:tool"/>')
    assert "reserved_namespace_prefix" in _codes(reserved_family)
    assert reserved_family.namespace_well_formed is True

    misbound = saml.lint_saml_xml(
        '<r xmlns:ds="urn:attacker"><ds:Signature/></r>'
    )
    assert "sensitive_prefix_misbinding" in _codes(misbound)

    declarations = " ".join(f'xmlns:p{index}="{DSIG}"' for index in range(64))
    aliases = saml.lint_saml_xml(f"<r {declarations}/>")
    alias_findings = [
        finding
        for finding in aliases.findings
        if finding.code == "namespace_alias_pollution"
    ]
    assert len(alias_findings) == 1
    evidence = dict(alias_findings[0].evidence)
    assert evidence["prefix_count"] == "64"
    assert len(json.loads(evidence["prefixes"])) == saml.MAX_EVIDENCE_ITEMS


def test_many_qname_values_do_not_copy_the_full_namespace_scope():
    fixed = [
        f'xmlns:ds="{DSIG}"',
        f'xmlns:ec="{EXC}"',
        f'xmlns:xsi="{XSI}"',
        'xmlns:v="urn:value"',
        'xmlns:p0="urn:type"',
    ]
    filler = [f'xmlns:p{index}="urn:filler:{index}"' for index in range(1, 496)]
    declarations = " ".join(fixed + filler)
    values = '<v:Value xsi:type="p0:T"/>' * 2_000
    xml = f"""<Root {declarations}>
      <ds:CanonicalizationMethod Algorithm="{EXC}">
        <ec:InclusiveNamespaces PrefixList="p0"/>
      </ds:CanonicalizationMethod>{values}</Root>"""
    started = time.perf_counter()
    with pytest.raises(saml.WpgapSamlError):
        saml.lint_saml_xml(xml)
    elapsed = time.perf_counter() - started
    assert elapsed < 2.0


def test_comments_cdata_and_escaping_have_stable_semantic_round_trips():
    xml = '<r xmlns:x="urn:x" z="2" a="&amp;">before<!--comment--><![CDATA[mid]]><x:c/>after</r>'
    report = saml.lint_saml_xml(xml)
    assert not ({
        "canonicalization_roundtrip_drift",
        "canonicalization_non_idempotent",
        "canonicalization_error",
    } & _codes(report))
    assert all(probe.status == "ok" for probe in _probes(report))


def test_doctype_attlist_and_external_entity_are_rejected_without_resolution(tmp_path):
    secret = "DO_NOT_READ_THIS_SENTINEL"
    sentinel = tmp_path / "sentinel.txt"
    sentinel.write_text(secret, encoding="utf-8")
    cases = (
        '<!DOCTYPE Response [<!ATTLIST Signature xmlns CDATA #FIXED "urn:one" '
        'xmlns CDATA "urn:two">]><Response/>',
        f'<!DOCTYPE r [<!ENTITY x SYSTEM "{sentinel.as_uri()}">]><r>&x;</r>',
    )
    for xml in cases:
        with pytest.raises(saml.WpgapSamlError) as caught:
            saml.lint_saml_xml(xml)
        assert secret not in str(caught.value)


def test_declared_error_contract_caps_and_frozen_results():
    malformed = (
        None,
        7,
        object(),
        b"",
        b"not xml",
        b"<r>",
        b"\x00<r/>",
        b"<r>\xff</r>",
        b"<r>" + b"x" * (saml.MAX_XML_BYTES + 1) + b"</r>",
    )
    for value in malformed:
        with pytest.raises(saml.WpgapSamlError):
            saml.lint_saml_xml(value)

    too_deep = "<r>" * (saml.MAX_DEPTH + 2) + "x" + "</r>" * (saml.MAX_DEPTH + 2)
    with pytest.raises(saml.WpgapSamlError):
        saml.lint_saml_xml(too_deep)

    remaining = saml.MAX_NAMESPACE_DECLARATIONS + 1
    opens = []
    level = 0
    prefix = 0
    while remaining:
        count = min(500, remaining)
        declarations = " ".join(
            f'xmlns:n{index}="urn:n{index}"'
            for index in range(prefix, prefix + count)
        )
        opens.append(f"<level{level} {declarations}>")
        remaining -= count
        prefix += count
        level += 1
    over_namespaces = "".join(opens) + "x" + "".join(
        f"</level{index}>" for index in reversed(range(level))
    )
    with pytest.raises(saml.WpgapSamlError):
        saml.lint_saml_xml(over_namespaces)

    for repeated_node in ("<!---->", "<?p x?>"):
        too_many_misc_nodes = (
            "<r>" + repeated_node * (saml.MAX_MISC_XML_NODES + 1) + "</r>"
        )
        with pytest.raises(saml.WpgapSamlError):
            saml.lint_saml_xml(too_many_misc_nodes)

    for seed in range(24):
        raw = bytes(((seed * 29 + index * 113) & 0xFF) for index in range(1, 48))
        try:
            saml.lint_saml_xml(raw)
        except saml.WpgapSamlError:
            pass
        else:
            raise AssertionError("hostile random bytes unexpectedly parsed as XML")

    report = saml.lint_saml_xml("<r/>")
    with pytest.raises(FrozenInstanceError):
        report.xml_bytes = 1
    probe = _probes(report)[0]
    with pytest.raises(FrozenInstanceError):
        probe.status = "changed"


def test_file_cli_guard_and_explicit_offline_contract(tmp_path, capsys):
    path = tmp_path / "response.xml"
    path.write_text("<r/>", encoding="utf-8")
    assert saml.main([str(path)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["offline_only"] is True
    assert payload["network_access"] is False
    assert payload["external_entities"] is False
    assert payload["xinclude"] is False
    assert payload["schema_validation"] is False
    assert payload["signature_verification"] is False
    assert payload["reference_resolution"] is False
    assert payload["transforms_executed"] == 0

    assert saml.main([]) == 2
    assert saml.main([str(tmp_path / "missing.xml")]) == 2
    assert saml.main(["--help"]) == 0
