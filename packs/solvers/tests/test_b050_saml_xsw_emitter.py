"""B-050: XML signature-wrapping (XSW) variant emitter.

Fixtures are written independently of the emitter. Every emitted variant is fed
back through the offline analyzer to prove it stays well-formed, DTD-free, and
keeps the real signature while adding an unsigned forgery.
"""

from __future__ import annotations

import json
import sys
import xml.etree.ElementTree as ET
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
EXC = "http://www.w3.org/2001/10/xml-exc-c14n#"
ENV = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"


def _signature(reference_id: str) -> str:
    return (
        "<ds:Signature><ds:SignedInfo>"
        f'<ds:CanonicalizationMethod Algorithm="{EXC}"/>'
        f'<ds:Reference URI="#{reference_id}">'
        f'<ds:Transforms><ds:Transform Algorithm="{ENV}"/></ds:Transforms>'
        "<ds:DigestValue>AA==</ds:DigestValue></ds:Reference>"
        "</ds:SignedInfo><ds:SignatureValue>AA==</ds:SignatureValue></ds:Signature>"
    )


def enveloped_assertion() -> bytes:
    """Response wrapping an Assertion whose enveloped signature covers it."""
    return (
        f'<samlp:Response {NS} ID="_response" Version="2.0">'
        f'<saml:Assertion ID="_assertion" Version="2.0">'
        "<saml:Issuer>https://idp.example</saml:Issuer>"
        f"{_signature('_assertion')}"
        "<saml:Subject><saml:NameID>operator@example.test</saml:NameID></saml:Subject>"
        "</saml:Assertion></samlp:Response>"
    ).encode()


def detached_assertion() -> bytes:
    """Signature is a sibling of the Assertion it references (detached)."""
    return (
        f'<samlp:Response {NS} ID="_response" Version="2.0">'
        f"{_signature('_assertion')}"
        f'<saml:Assertion ID="_assertion" Version="2.0">'
        "<saml:Issuer>https://idp.example</saml:Issuer>"
        "<saml:Subject><saml:NameID>operator@example.test</saml:NameID></saml:Subject>"
        "</saml:Assertion></samlp:Response>"
    ).encode()


def signed_root_response() -> bytes:
    return (
        f'<samlp:Response {NS} ID="_response" Version="2.0">'
        "<saml:Issuer>https://idp.example</saml:Issuer>"
        f"{_signature('_response')}"
        "</samlp:Response>"
    ).encode()


SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
SAML_A = "urn:oasis:names:tc:SAML:2.0:assertion"
DS = "http://www.w3.org/2000/09/xmldsig#"


def _parse(document: str) -> ET.Element:
    """Parse a variant keeping comments (the forged-node marker is a comment)."""
    parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))
    parser.feed(document)
    return parser.close()


def _signed_info_bytes(document: str) -> bytes:
    """Canonical-ish bytes of ds:SignedInfo, independent of prefix spelling."""
    root = _parse(document)
    signed_info = next(root.iter(f"{{{DS}}}SignedInfo"))
    # rewrite_prefixes: ns0:/ds: spellings canonicalize alike, so the result does
    # not depend on which prefixes ElementTree's registry holds when this runs.
    return ET.canonicalize(ET.tostring(signed_info, encoding="unicode"),
                           strip_text=True, rewrite_prefixes=True).encode()


def _by_name(result):
    return {variant["name"]: variant for variant in result["variants"]}


def _skipped(result):
    return {row["name"]: row["reason"] for row in result["skipped"]}


def test_enveloped_assertion_emits_sibling_and_shadow_variants():
    result = saml.emit_signature_wrapping_variants(enveloped_assertion())
    assert result["signed_target"] == {
        "path": "/samlp:Response[1]/saml:Assertion[1]",
        "local_name": "Assertion",
        "id": "_assertion",
    }
    assert result["signature_enveloped_in_target"] is True
    names = _by_name(result)
    assert set(names) == {"wrap_sibling_pre", "wrap_sibling_post",
                          "wrap_id_shadow", "wrap_id_shadow_post"}
    skipped = _skipped(result)
    # enveloping is impossible when the signature lives inside the signed element
    assert "enveloped inside the signed element" in skipped["wrap_enveloping_object"]
    # root wrappers apply only when the signed element is the document root
    assert set(skipped) == {"wrap_enveloping_object", "wrap_root_xsw1", "wrap_root_xsw2"}
    assert "not the document root" in skipped["wrap_root_xsw1"]
    assert result["signatures_verified"] == 0
    assert result["offline_only"] is True and result["network_requests"] == 0


def test_emitted_variants_are_wellformed_keep_one_signature_add_a_forgery():
    result = saml.emit_signature_wrapping_variants(enveloped_assertion())
    for variant in result["variants"]:
        analyzed = saml.analyze_saml_artifact(variant["document"], binding="xml")
        # a forgery was added (2 assertions) but the single real signature stayed,
        # and the forgery carries no signature of its own.
        assert analyzed["counts"]["assertions"] == 2
        assert analyzed["counts"]["signatures"] == 1
        assert "<!DOCTYPE" not in variant["document"] and "<!ENTITY" not in variant["document"]
        assert variant["requires_byte_exact_signed_subtree"] is True


def test_sibling_variant_keeps_reference_on_original_id():
    result = saml.emit_signature_wrapping_variants(enveloped_assertion())
    pre = _by_name(result)["wrap_sibling_pre"]
    assert pre["forged_id"] == "_assertion-xsw"
    assert pre["signed_id"] == "_assertion"
    assert pre["reference_uri"] == "#_assertion"
    # forged copy precedes the signed one and both IDs are present
    assert 'ID="_assertion-xsw"' in pre["document"]
    assert pre["document"].index("_assertion-xsw") < pre["document"].index('URI="#_assertion"')


def test_sibling_post_places_forgery_after_the_signed_element():
    result = saml.emit_signature_wrapping_variants(enveloped_assertion())
    variants = _by_name(result)
    for name, forged_first in (("wrap_sibling_pre", True), ("wrap_sibling_post", False)):
        response = _parse(variants[name]["document"])
        order = [child.get("ID") for child in response if child.tag == f"{{{SAML_A}}}Assertion"]
        expected = ["_assertion-xsw", "_assertion"] if forged_first else ["_assertion", "_assertion-xsw"]
        assert order == expected, name
    assert variants["wrap_sibling_pre"]["document"] != variants["wrap_sibling_post"]["document"]


def test_id_shadow_duplicates_the_signed_id_and_leaves_signed_info_untouched():
    # Reference/@URI is inside ds:SignedInfo, which SignatureValue signs: no
    # variant may edit it.  The shadow is a second, unsigned element that
    # carries the SAME ID as the signed one.
    source = enveloped_assertion()
    original_signed_info = _signed_info_bytes(source.decode())
    result = saml.emit_signature_wrapping_variants(source)
    variants = _by_name(result)
    for name, forged_first in (("wrap_id_shadow", True), ("wrap_id_shadow_post", False)):
        shadow = variants[name]
        assert shadow["forged_id"] == "_assertion" and shadow["signed_id"] == "_assertion"
        assert shadow["reference_uri"] == "#_assertion"
        assert "-xsw" not in shadow["document"]
        assert _signed_info_bytes(shadow["document"]) == original_signed_info
        response = _parse(shadow["document"])
        assertions = [child for child in response if child.tag == f"{{{SAML_A}}}Assertion"]
        assert [a.get("ID") for a in assertions] == ["_assertion", "_assertion"]
        signed_flags = [a.find(f"{{{DS}}}Signature") is not None for a in assertions]
        # forgery (unsigned) before the signed copy for pre, after it for post
        assert signed_flags == ([False, True] if forged_first else [True, False]), name
        analyzed = saml.analyze_saml_artifact(shadow["document"], binding="xml")
        codes = {f["code"] for f in analyzed["findings"]}
        assert {"duplicate_id", "ambiguous_reference"} <= codes
        assert analyzed["counts"]["signatures"] == 1


def test_detached_signature_enables_enveloping_object_variant():
    result = saml.emit_signature_wrapping_variants(detached_assertion())
    assert result["signature_enveloped_in_target"] is False
    env = _by_name(result)["wrap_enveloping_object"]
    assert env["strategy"] == "enveloping_object_hide_signed"
    # the real assertion is hidden inside a ds:Object under the signature
    assert "Object" in env["document"]
    analyzed = saml.analyze_saml_artifact(env["document"], binding="xml")
    assert any(f["code"] == "signed_node_hidden" for f in analyzed["findings"])
    assert analyzed["counts"]["assertions"] == 2


def test_signed_root_response_emits_xsw1_and_xsw2_root_wrappers():
    source = signed_root_response()
    original_signed_info = _signed_info_bytes(source.decode())
    result = saml.emit_signature_wrapping_variants(source)
    assert result["signed_target"]["local_name"] == "Response"
    variants = _by_name(result)
    assert set(variants) == {"wrap_root_xsw1", "wrap_root_xsw2"}
    reasons = _skipped(result)
    assert set(reasons) == {
        "wrap_sibling_pre", "wrap_sibling_post", "wrap_id_shadow", "wrap_id_shadow_post",
        "wrap_enveloping_object",
    }
    assert all("document root" in reason for reason in reasons.values())

    for name in ("wrap_root_xsw1", "wrap_root_xsw2"):
        variant = variants[name]
        assert variant["forged_id"] == "_response-xsw"
        assert variant["signed_id"] == "_response"
        assert variant["reference_uri"] == "#_response"
        assert _signed_info_bytes(variant["document"]) == original_signed_info
        root = _parse(variant["document"])
        # new forged Response root with a fresh ID; the original is nested in it
        assert root.tag == f"{{{SAMLP}}}Response" and root.get("ID") == "_response-xsw"
        signature = root.find(f"{{{DS}}}Signature")
        assert signature is not None
        nested = [el for el in root.iter(f"{{{SAMLP}}}Response") if el.get("ID") == "_response"]
        assert len(nested) == 1
        # the nested original lost its enveloped signature (the digest excluded it)
        assert nested[0].find(f"{{{DS}}}Signature") is None
        analyzed = saml.analyze_saml_artifact(variant["document"], binding="xml")
        assert analyzed["counts"]["responses"] == 2 and analyzed["counts"]["signatures"] == 1
        (reference,) = analyzed["references"]
        assert reference["status"] == "unique"
        assert reference["target_paths"] != ["/samlp:Response[1]"]  # resolves to the nested original

    xsw1 = _parse(variants["wrap_root_xsw1"]["document"])
    sig1 = xsw1.find(f"{{{DS}}}Signature")
    # XSW1: the original rides inside the signature, as its last child
    assert sig1[-1].tag == f"{{{SAMLP}}}Response" and sig1[-1].get("ID") == "_response"
    xsw2 = _parse(variants["wrap_root_xsw2"]["document"])
    children = list(xsw2)
    sig2_pos = next(i for i, c in enumerate(children) if c.tag == f"{{{DS}}}Signature")
    # XSW2: the original is a detached sibling immediately before the signature
    assert children[sig2_pos - 1].tag == f"{{{SAMLP}}}Response"
    assert children[sig2_pos - 1].get("ID") == "_response"
    assert xsw2.find(f"{{{DS}}}Signature").find(f"{{{SAMLP}}}Response") is None


def test_every_variant_marks_its_forged_node_with_a_comment():
    for source in (enveloped_assertion(), detached_assertion(), signed_root_response()):
        result = saml.emit_signature_wrapping_variants(source)
        assert result["variants"]
        for variant in result["variants"]:
            root = _parse(variant["document"])
            markers = [(parent, i) for parent in root.iter() for i, child in enumerate(parent)
                       if child.tag is ET.Comment and "XSW forged node" in (child.text or "")]
            assert len(markers) == 1, variant["name"]
            parent, position = markers[0]
            if variant["name"].startswith("wrap_root_"):
                # the forged node is the document element; the marker is its first child
                assert parent is root and position == 0
                assert root.get("ID") == variant["forged_id"]
            else:
                forged = parent[position + 1]
                assert forged.get("ID") == variant["forged_id"], variant["name"]
                assert forged.find(f".//{{{DS}}}Signature") is None, variant["name"]


def test_cli_emit_variants_prints_variant_json(capsys, tmp_path):
    rc = saml.main(["--emit-variants", "--forged-id", "evil1", "--binding", "xml",
                    enveloped_assertion().decode()])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    names = {variant["name"] for variant in out["variants"]}
    assert names == {"wrap_sibling_pre", "wrap_sibling_post", "wrap_id_shadow", "wrap_id_shadow_post"}
    assert {v["forged_id"] for v in out["variants"]
            if v["name"].startswith("wrap_sibling")} == {"evil1"}
    assert out["offline_only"] is True
    # --file reads the artifact bytes; without --emit-variants it analyzes instead
    doc = tmp_path / "signed.xml"
    doc.write_bytes(signed_root_response())
    assert saml.main(["--file", "--emit-variants", str(doc)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert {v["name"] for v in out["variants"]} == {"wrap_root_xsw1", "wrap_root_xsw2"}
    assert saml.main(["--file", str(doc)]) == 0
    assert "variants" not in json.loads(capsys.readouterr().out)
    # a bad forged ID fails loudly with exit 2 and a named reason
    assert saml.main(["--emit-variants", "--forged-id", "1 bad", "--binding", "xml",
                      enveloped_assertion().decode()]) == 2
    assert "NCName" in capsys.readouterr().err


def test_custom_forged_id_is_used_and_validated():
    result = saml.emit_signature_wrapping_variants(enveloped_assertion(), forged_id="evil1")
    assert _by_name(result)["wrap_sibling_pre"]["forged_id"] == "evil1"
    with pytest.raises(saml.WebauthSamlError, match="NCName"):
        saml.emit_signature_wrapping_variants(enveloped_assertion(), forged_id="1 bad id")


def test_unsigned_document_has_no_wrapping_anchor():
    unsigned = (
        f'<samlp:Response {NS} ID="_r"><saml:Assertion ID="_a">'
        "<saml:Issuer>i</saml:Issuer></saml:Assertion></samlp:Response>"
    ).encode()
    with pytest.raises(saml.WebauthSamlError, match="no uniquely-signed"):
        saml.emit_signature_wrapping_variants(unsigned)


def test_two_independently_signed_assertions_are_ambiguous():
    doc = (
        f'<samlp:Response {NS} ID="_r">'
        f'<saml:Assertion ID="_a1">{_signature("_a1")}'
        "<saml:Subject><saml:NameID>a</saml:NameID></saml:Subject></saml:Assertion>"
        f'<saml:Assertion ID="_a2">{_signature("_a2")}'
        "<saml:Subject><saml:NameID>b</saml:NameID></saml:Subject></saml:Assertion>"
        "</samlp:Response>"
    ).encode()
    with pytest.raises(saml.WebauthSamlError, match="ambiguous"):
        saml.emit_signature_wrapping_variants(doc)


def test_emitter_leaves_the_global_elementtree_prefix_registry_untouched(monkeypatch):
    # _serialize needs ds:/saml:/samlp: prefixes, but ElementTree keeps them in
    # a process-wide registry; leaking them would change every later
    # ET.tostring in the process (and made these tests depend on run order).
    # Start from a registry without the SAML/DSig prefixes, whatever ran before.
    clean = {uri: prefix for uri, prefix in ET._namespace_map.items()
             if uri not in (DS, SAML_A, SAMLP)}
    monkeypatch.setattr(ET, "_namespace_map", clean)
    probe = ET.Element(f"{{{DS}}}SignedInfo")
    ET.SubElement(probe, f"{{{SAML_A}}}Assertion")
    before_registry = dict(ET._namespace_map)
    before_text = ET.tostring(probe, encoding="unicode")
    result = saml.emit_signature_wrapping_variants(enveloped_assertion())
    assert dict(ET._namespace_map) == before_registry
    assert ET.tostring(probe, encoding="unicode") == before_text
    # ...while the emitted documents still carry the conventional prefixes
    for variant in result["variants"]:
        assert "<samlp:Response" in variant["document"], variant["name"]
        assert "<ds:Signature" in variant["document"], variant["name"]
        assert "ns0:" not in variant["document"], variant["name"]


def test_signed_reference_to_a_non_saml_element_is_not_a_wrapping_anchor():
    # The only unique signed reference targets elements that merely share a
    # SAML local name (or are SAML-adjacent): a foreign-namespace Assertion and
    # a samlp:Extensions.  Neither is an auth element the SP releases on.
    foreign = (
        f'<samlp:Response {NS} xmlns:evil="urn:example:not-saml" ID="_r">'
        f'<evil:Assertion ID="_a">{_signature("_a")}'
        "<saml:Subject><saml:NameID>a</saml:NameID></saml:Subject></evil:Assertion>"
        "</samlp:Response>"
    ).encode()
    with pytest.raises(saml.WebauthSamlError, match="no uniquely-signed"):
        saml.emit_signature_wrapping_variants(foreign)
    extensions = (
        f'<samlp:Response {NS} ID="_r">'
        f'<samlp:Extensions ID="_x">{_signature("_x")}</samlp:Extensions>'
        "</samlp:Response>"
    ).encode()
    with pytest.raises(saml.WebauthSamlError, match="no uniquely-signed"):
        saml.emit_signature_wrapping_variants(extensions)
    # control: the same shape with a real saml:Assertion IS an anchor
    genuine = foreign.replace(b"evil:Assertion", b"saml:Assertion")
    assert saml.emit_signature_wrapping_variants(genuine)["signed_target"]["id"] == "_a"
