"""Offline lexical namespace and canonicalization linting for supplied SAML XML.

This module deliberately does not verify signatures, resolve references, apply
XMLDSig transforms, load schemas, or fetch anything.  It keeps a namespace-
unaware Expat view of the source before asking a locked-down lxml parser to
perform four diagnostic canonicalization probes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import unicodedata
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Sequence
from xml.parsers import expat

try:
    from lxml import etree
except ImportError:  # pragma: no cover - reported without weakening parsing
    etree = None  # type: ignore[assignment]


MAX_XML_BYTES = 1_048_576
MAX_ELEMENTS = 8_192
MAX_DEPTH = 64
MAX_ATTRIBUTES = 32_768
MAX_ATTRIBUTES_PER_ELEMENT = 512
MAX_NAMESPACE_DECLARATIONS = 2_048
MAX_ATTRIBUTE_BYTES = 65_536
MAX_TEXT_BYTES = 1_048_576
MAX_CANONICAL_BYTES = 2_097_152
MAX_FINDINGS = 4_096
MAX_EVIDENCE_ITEMS = 32
MAX_NAMESPACE_SCOPE_WORK = 250_000
MAX_MISC_XML_NODES = 8_192

XML_URI = "http://www.w3.org/XML/1998/namespace"
XMLNS_URI = "http://www.w3.org/2000/xmlns/"
DSIG_URI = "http://www.w3.org/2000/09/xmldsig#"
DSIG11_URI = "http://www.w3.org/2009/xmldsig11#"
SAML_ASSERTION_URI = "urn:oasis:names:tc:SAML:2.0:assertion"
SAML_PROTOCOL_URI = "urn:oasis:names:tc:SAML:2.0:protocol"
XSI_URI = "http://www.w3.org/2001/XMLSchema-instance"
XSD_URI = "http://www.w3.org/2001/XMLSchema"
XMLENC_URI = "http://www.w3.org/2001/04/xmlenc#"
EXC_C14N_URI = "http://www.w3.org/2001/10/xml-exc-c14n#"
EXC_C14N_COMMENTS_URI = EXC_C14N_URI + "WithComments"

C14N_ALGORITHMS = frozenset(
    {
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments",
        EXC_C14N_URI,
        EXC_C14N_COMMENTS_URI,
        "http://www.w3.org/2006/12/xml-c14n11",
        "http://www.w3.org/2006/12/xml-c14n11#WithComments",
    }
)
EXCLUSIVE_C14N_ALGORITHMS = frozenset({EXC_C14N_URI, EXC_C14N_COMMENTS_URI})
SECURITY_URIS = frozenset(
    {
        DSIG_URI,
        DSIG11_URI,
        SAML_ASSERTION_URI,
        SAML_PROTOCOL_URI,
        XSI_URI,
        XMLENC_URI,
    }
)
SENSITIVE_PREFIXES = frozenset(
    {"ds", "dsig", "saml", "saml2", "samlp", "saml2p", "xsi", "xenc"}
)
EXPECTED_PREFIX_URIS = {
    "ds": frozenset({DSIG_URI, DSIG11_URI}),
    "dsig": frozenset({DSIG_URI, DSIG11_URI}),
    "saml": frozenset({SAML_ASSERTION_URI}),
    "saml2": frozenset({SAML_ASSERTION_URI}),
    "samlp": frozenset({SAML_PROTOCOL_URI}),
    "saml2p": frozenset({SAML_PROTOCOL_URI}),
    "xsi": frozenset({XSI_URI}),
    "xenc": frozenset({XMLENC_URI}),
}
SENSITIVE_ELEMENT_LOCAL_NAMES = frozenset(
    {
        "Assertion",
        "Response",
        "AuthnRequest",
        "Issuer",
        "Subject",
        "Conditions",
        "Signature",
        "SignedInfo",
        "Reference",
        "DigestValue",
        "SignatureValue",
    }
)

_XML_DECL_RE = re.compile(br"^(?:\xef\xbb\xbf)?\s*<\?xml\s+([^?]*)\?>", re.I)
_ENCODING_RE = re.compile(br"\bencoding\s*=\s*(['\"])([^'\"]+)\1", re.I)
_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_BAD_PERCENT_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")


class WpgapSamlError(Exception):
    """The only exception exposed for malformed or unsupported input."""


@dataclass(frozen=True)
class SamlLexicalFinding:
    code: str
    severity: str
    message: str
    path: str
    line: int
    column: int
    evidence: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class SamlNamespaceDeclaration:
    prefix: str
    uri: str
    path: str
    line: int
    column: int
    order: int
    previous_uri: str | None = None


@dataclass(frozen=True)
class SamlC14nProbe:
    mode: str
    with_comments: bool
    status: str
    output_bytes: int
    sha256: str | None
    semantic_roundtrip: bool | None
    idempotent: bool | None
    error: str | None = None


@dataclass(frozen=True)
class SamlLexicalReport:
    xml_bytes: int
    elements: int
    attributes: int
    namespace_declarations: tuple[SamlNamespaceDeclaration, ...]
    max_depth: int
    namespace_well_formed: bool
    declared_c14n_algorithms: tuple[str, ...]
    inclusive_namespace_prefixes: tuple[str, ...]
    probes: tuple[SamlC14nProbe, ...]
    findings: tuple[SamlLexicalFinding, ...]
    offline_only: bool = True
    network_access: bool = False
    external_entities: bool = False
    xinclude: bool = False
    schema_validation: bool = False
    signature_verification: bool = False
    reference_resolution: bool = False
    transforms_executed: int = 0
    limitations: tuple[str, ...] = (
        "offline static analysis only",
        "no network or file entity resolution",
        "no DTD, external entity, XInclude, or schema processing",
        "no XML signature verification",
        "no XMLDSig reference resolution",
        "no declared XMLDSig transforms executed",
        "C14N probes use libxml2 Canonical XML 1.0/exclusive 1.0; declared C14N 1.1 is inventoried only",
    )


@dataclass(frozen=True)
class _Attribute:
    qname: str
    uri: str
    local: str
    value: str
    order: int


@dataclass(frozen=True)
class _Node:
    qname: str
    uri: str
    local: str
    path: str
    line: int
    column: int
    attributes: tuple[_Attribute, ...]


@dataclass
class _Frame:
    qname: str
    path: str
    scope: dict[str, str]
    child_counts: dict[str, int]


class _LexicalAbort(Exception):
    pass


def _ev(**values: Any) -> tuple[tuple[str, str], ...]:
    return tuple((key, str(value)) for key, value in values.items())


def _clean_error(exc: BaseException) -> str:
    message = " ".join(str(exc).split())
    return message[:300] if message else exc.__class__.__name__


def _coerce_xml(data: bytes | bytearray | memoryview | str) -> bytes:
    if isinstance(data, str):
        try:
            raw = data.encode("utf-8")
        except UnicodeError as exc:
            raise WpgapSamlError("XML text is not encodable as UTF-8") from exc
    elif isinstance(data, (bytes, bytearray, memoryview)):
        raw = bytes(data)
    else:
        raise WpgapSamlError("XML input must be bytes or text")
    if not raw:
        raise WpgapSamlError("XML input is empty")
    if len(raw) > MAX_XML_BYTES:
        raise WpgapSamlError(f"XML exceeds {MAX_XML_BYTES} byte limit")
    try:
        decoded = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise WpgapSamlError("XML must be UTF-8 or UTF-8 with BOM") from exc
    if "\x00" in decoded:
        raise WpgapSamlError("NUL bytes are not accepted")
    declaration = _XML_DECL_RE.match(raw)
    if declaration:
        encoding = _ENCODING_RE.search(declaration.group(1))
        if encoding and encoding.group(2).lower().replace(b"_", b"-") not in {
            b"utf-8",
            b"utf8",
        }:
            raise WpgapSamlError("only UTF-8 XML declarations are accepted")
    return raw


def _split_qname(qname: str) -> tuple[str, str]:
    if ":" not in qname:
        return "", qname
    return tuple(qname.split(":", 1))  # type: ignore[return-value]


def _uri_problem(uri: str) -> str | None:
    if any(ch.isspace() or unicodedata.category(ch) == "Cc" for ch in uri):
        return "namespace URI contains whitespace or a control character"
    if "\\" in uri or _BAD_PERCENT_RE.search(uri):
        return "namespace URI has an invalid escape or backslash"
    return None


def _is_relative_uri(uri: str) -> bool:
    return bool(uri) and _SCHEME_RE.match(uri) is None


class _LexicalCollector:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.nodes: list[_Node] = []
        self.declarations: list[SamlNamespaceDeclaration] = []
        self.findings: list[SamlLexicalFinding] = []
        self.stack: list[_Frame] = []
        self.element_count = 0
        self.attribute_count = 0
        self.text_bytes = 0
        self.misc_nodes = 0
        self.max_depth = 0
        self.namespace_scope_work = 0
        self.namespace_well_formed = True
        self.algorithms: list[str] = []
        self.inclusive_prefixes: list[str] = []
        self._exclusive_prefix_lists: dict[str, list[set[str]]] = {}
        self._qname_values: list[
            tuple[str, str, str, str, str | None, int, int]
        ] = []
        self.relative_namespace_declaration = False

    def _finding(
        self,
        code: str,
        severity: str,
        message: str,
        path: str,
        line: int,
        column: int,
        **evidence: Any,
    ) -> None:
        if len(self.findings) >= MAX_FINDINGS:
            raise _LexicalAbort("finding limit exceeded")
        self.findings.append(
            SamlLexicalFinding(
                code, severity, message, path, line, column, _ev(**evidence)
            )
        )

    def _uri_findings(
        self, uri: str, path: str, line: int, column: int, attribute: str
    ) -> None:
        problem = _uri_problem(uri)
        if problem:
            self.namespace_well_formed = False
            self._finding(
                "invalid_namespace_uri",
                "high",
                problem,
                path,
                line,
                column,
                attribute=attribute,
                uri=uri,
            )
        if _is_relative_uri(uri):
            self._finding(
                "relative_namespace_uri",
                "high",
                "namespace name is relative and cannot be safely canonicalized",
                path,
                line,
                column,
                attribute=attribute,
                uri=uri,
            )

    def _declaration(
        self,
        prefix: str,
        uri: str,
        qname: str,
        scope: dict[str, str],
        path: str,
        line: int,
        column: int,
        order: int,
    ) -> None:
        self._uri_findings(uri, path, line, column, qname)
        if _is_relative_uri(uri):
            self.relative_namespace_declaration = True
        previous = scope.get(prefix)
        self.declarations.append(
            SamlNamespaceDeclaration(
                prefix, uri, path, line, column, len(self.declarations), previous
            )
        )
        if len(self.declarations) > MAX_NAMESPACE_DECLARATIONS:
            raise _LexicalAbort("too many namespace declarations")

        reserved = False
        if prefix == "xmlns" or uri == XMLNS_URI:
            reserved = True
        if prefix == "xml" and uri != XML_URI:
            reserved = True
        if prefix != "xml" and uri == XML_URI:
            reserved = True
        if ":" in prefix:
            reserved = True
        if reserved:
            self.namespace_well_formed = False
            self._finding(
                "reserved_namespace_binding",
                "critical",
                "namespace declaration violates reserved xml/xmlns binding rules",
                path,
                line,
                column,
                prefix=prefix or "#default",
                uri=uri,
            )
        elif prefix and prefix.lower().startswith("xml") and prefix != "xml":
            self._finding(
                "reserved_namespace_prefix",
                "medium",
                "prefixes beginning with xml in any letter case are reserved for XML specifications",
                path,
                line,
                column,
                prefix=prefix,
                uri=uri,
            )
        if prefix and not uri:
            self.namespace_well_formed = False
            self._finding(
                "empty_prefixed_namespace",
                "high",
                "a prefixed namespace cannot be undeclared with an empty URI",
                path,
                line,
                column,
                prefix=prefix,
            )
        if prefix and previous is not None and previous != uri:
            sensitive = (
                prefix.lower() in SENSITIVE_PREFIXES
                or previous in SECURITY_URIS
                or uri in SECURITY_URIS
            )
            self._finding(
                "sensitive_prefix_rebinding" if sensitive else "prefix_rebinding",
                "critical" if sensitive else "medium",
                "an in-scope prefix is rebound to a different namespace",
                path,
                line,
                column,
                prefix=prefix,
                previous_uri=previous,
                uri=uri,
            )
        expected_uris = EXPECTED_PREFIX_URIS.get(prefix.lower())
        if expected_uris is not None and uri not in expected_uris:
            self._finding(
                "sensitive_prefix_misbinding",
                "high",
                "a conventional security prefix is bound to an unexpected namespace",
                path,
                line,
                column,
                prefix=prefix,
                uri=uri,
                expected_uris=sorted(expected_uris),
            )
        scope[prefix] = uri

    @staticmethod
    def _expanded(
        qname: str, scope: dict[str, str], *, attribute: bool
    ) -> tuple[str | None, str, str]:
        prefix, local = _split_qname(qname)
        if prefix:
            return scope.get(prefix), local, prefix
        return ("" if attribute else scope.get("", "")), local, ""

    def start(self, qname: str, raw_attrs: list[str]) -> None:
        self.element_count += 1
        if self.element_count > MAX_ELEMENTS:
            raise _LexicalAbort("too many elements")
        if len(raw_attrs) % 2:
            raise _LexicalAbort("parser returned an odd attribute vector")
        attr_pairs = list(zip(raw_attrs[0::2], raw_attrs[1::2]))
        if len(attr_pairs) > MAX_ATTRIBUTES_PER_ELEMENT:
            raise _LexicalAbort("too many attributes on one element")
        self.attribute_count += len(attr_pairs)
        if self.attribute_count > MAX_ATTRIBUTES:
            raise _LexicalAbort("too many attributes")
        for name, value in attr_pairs:
            if len(name.encode("utf-8")) + len(value.encode("utf-8")) > MAX_ATTRIBUTE_BYTES:
                raise _LexicalAbort("attribute exceeds size limit")

        line = self.parser.CurrentLineNumber
        column = self.parser.CurrentColumnNumber
        if self.stack:
            parent = self.stack[-1]
            index = parent.child_counts.get(qname, 0) + 1
            parent.child_counts[qname] = index
            path = f"{parent.path}/{qname}[{index}]"
            scope = parent.scope
        else:
            path = f"/{qname}[1]"
            scope = {"xml": XML_URI}

        declaration_prefixes: list[str] = []
        if self.stack and any(
            name == "xmlns" or name.startswith("xmlns:")
            for name, _value in attr_pairs
        ):
            scope = dict(scope)
        for order, (name, value) in enumerate(attr_pairs):
            if name == "xmlns":
                prefix = ""
            elif name.startswith("xmlns:"):
                prefix = name[6:]
            else:
                continue
            declaration_prefixes.append(prefix)
            self._declaration(prefix, value, name, scope, path, line, column, order)

        self.namespace_scope_work += len(scope)
        if self.namespace_scope_work > MAX_NAMESPACE_SCOPE_WORK:
            raise _LexicalAbort("cumulative namespace-scope work limit exceeded")

        declared_security_uris = {
            scope.get(prefix, "")
            for prefix in declaration_prefixes
            if scope.get(prefix, "") in SECURITY_URIS
        }
        for uri in sorted(declared_security_uris):
            aliases = sorted(p or "#default" for p, value in scope.items() if value == uri)
            if len(aliases) > 1:
                self._finding(
                    "namespace_alias_pollution",
                    "high",
                    "multiple in-scope prefixes identify the same security namespace",
                    path,
                    line,
                    column,
                    uri=uri,
                    prefix_count=len(aliases),
                    prefixes=json.dumps(
                        aliases[:MAX_EVIDENCE_ITEMS], separators=(",", ":")
                    ),
                )

        element_uri, element_local, element_prefix = self._expanded(
            qname, scope, attribute=False
        )
        if element_uri is None:
            self.namespace_well_formed = False
            self._finding(
                "undeclared_prefix",
                "critical",
                "element QName uses an undeclared prefix",
                path,
                line,
                column,
                qname=qname,
                prefix=element_prefix,
            )
            element_uri = ""

        attributes: list[_Attribute] = []
        expanded_seen: dict[tuple[str, str], str] = {}
        locals_seen: dict[str, list[_Attribute]] = {}
        for order, (name, value) in enumerate(attr_pairs):
            is_declaration = name == "xmlns" or name.startswith("xmlns:")
            reserved_lookalike = not is_declaration and name == "xml:xmlns"
            if reserved_lookalike:
                self._finding(
                    "reserved_namespace_attribute",
                    "critical",
                    "reserved xmlns spelling is used as an ordinary attribute",
                    path,
                    line,
                    column,
                    qname=name,
                    value=value,
                )
                # Parser-differential hiding cases use xml:xmlns as namespace-like
                # lexical evidence even though it is not a legal declaration.
                self._uri_findings(value, path, line, column, name)
            if is_declaration:
                continue
            uri, local, prefix = self._expanded(name, scope, attribute=True)
            if uri is None:
                self.namespace_well_formed = False
                self._finding(
                    "undeclared_prefix",
                    "critical",
                    "attribute QName uses an undeclared prefix",
                    path,
                    line,
                    column,
                    qname=name,
                    prefix=prefix,
                )
                uri = ""
            item = _Attribute(name, uri, local, value, order)
            attributes.append(item)
            expanded = (uri, local)
            if expanded in expanded_seen:
                self.namespace_well_formed = False
                self._finding(
                    "duplicate_expanded_attribute",
                    "critical",
                    "attributes collapse to the same expanded name",
                    path,
                    line,
                    column,
                    first_qname=expanded_seen[expanded],
                    second_qname=name,
                    uri=uri,
                    local_name=local,
                )
            else:
                expanded_seen[expanded] = name
            locals_seen.setdefault(local, []).append(item)
            if uri == XSI_URI and local == "type":
                candidate = value.strip()
                value_prefix, separator, value_local = candidate.partition(":")
                if (
                    separator
                    and value_prefix
                    and value_local
                    and ":" not in value_local
                    and not any(character.isspace() for character in candidate)
                ):
                    self._qname_values.append(
                        (
                            path,
                            name,
                            candidate,
                            value_prefix,
                            scope.get(value_prefix),
                            line,
                            column,
                        )
                    )
                elif (
                    candidate
                    and not separator
                    and not any(character.isspace() for character in candidate)
                    and scope.get("")
                ):
                    self._qname_values.append(
                        (
                            path,
                            name,
                            candidate,
                            "#default",
                            scope.get(""),
                            line,
                            column,
                        )
                    )

        for local, items in locals_seen.items():
            if len(items) < 2 or len({(item.uri, item.local) for item in items}) < 2:
                continue
            ordered = sorted(items, key=lambda item: item.order)
            self._finding(
                "attribute_local_name_collision",
                "high",
                "multiple attributes share a local name but have different expanded names",
                path,
                line,
                column,
                local_name=local,
                attribute_count=len(ordered),
                ordered_qnames=json.dumps(
                    [item.qname for item in ordered[:MAX_EVIDENCE_ITEMS]]
                ),
                ordered_values=json.dumps(
                    [item.value for item in ordered[:MAX_EVIDENCE_ITEMS]]
                ),
            )

        node = _Node(
            qname,
            element_uri,
            element_local,
            path,
            line,
            column,
            tuple(attributes),
        )
        self.nodes.append(node)

        algorithm = next(
            (
                item.value
                for item in attributes
                if item.uri == "" and item.local == "Algorithm"
            ),
            None,
        )
        if (
            algorithm in C14N_ALGORITHMS
            and element_uri == DSIG_URI
            and (element_local == "CanonicalizationMethod" or element_local == "Transform")
        ):
            if algorithm not in self.algorithms:
                self.algorithms.append(algorithm)
            if algorithm in EXCLUSIVE_C14N_ALGORITHMS:
                self._exclusive_prefix_lists[path] = []

        if element_uri == EXC_C14N_URI and element_local == "InclusiveNamespaces":
            prefix_list = next(
                (
                    item.value
                    for item in attributes
                    if item.uri == "" and item.local == "PrefixList"
                ),
                "",
            )
            tokens = tuple(prefix_list.split())
            parent_path = self.stack[-1].path if self.stack else ""
            if parent_path in self._exclusive_prefix_lists:
                prefix_lists = self._exclusive_prefix_lists[parent_path]
                prefix_lists.append(set(tokens))
                if len(prefix_lists) > 1:
                    self._finding(
                        "multiple_inclusive_namespaces",
                        "high",
                        "one exclusive C14N operation has multiple InclusiveNamespaces parameters",
                        path,
                        line,
                        column,
                        parameter_count=len(prefix_lists),
                    )
                seen_tokens: set[str] = set()
                for token in tokens:
                    if token in seen_tokens:
                        self._finding(
                            "inclusive_prefix_duplicate",
                            "medium",
                            "InclusiveNamespaces PrefixList repeats a prefix",
                            path,
                            line,
                            column,
                            prefix=token,
                        )
                    seen_tokens.add(token)
                    if (
                        token not in {"#default", "xml"}
                        and token not in scope
                    ):
                        self._finding(
                            "inclusive_prefix_unbound",
                            "high",
                            "InclusiveNamespaces PrefixList names an unbound prefix",
                            path,
                            line,
                            column,
                            prefix=token,
                        )
                for token in tokens:
                    if token not in self.inclusive_prefixes:
                        self.inclusive_prefixes.append(token)
            else:
                self._finding(
                    "orphan_inclusive_namespaces",
                    "medium",
                    "InclusiveNamespaces is not a direct child of a declared exclusive C14N operation",
                    path,
                    line,
                    column,
                )

        self.stack.append(_Frame(qname, path, scope, {}))
        self.max_depth = max(self.max_depth, len(self.stack))
        if len(self.stack) > MAX_DEPTH:
            raise _LexicalAbort("XML nesting exceeds depth limit")

    def end(self, qname: str) -> None:
        if not self.stack or self.stack[-1].qname != qname:
            raise _LexicalAbort("mismatched XML end tag")
        self.stack.pop()

    def text(self, value: str) -> None:
        self.text_bytes += len(value.encode("utf-8"))
        if self.text_bytes > MAX_TEXT_BYTES:
            raise _LexicalAbort("XML character data exceeds size limit")

    def comment(self, value: str) -> None:
        self.misc_nodes += 1
        if self.misc_nodes > MAX_MISC_XML_NODES:
            raise _LexicalAbort("comment/processing-instruction node limit exceeded")
        self.text(value)

    def processing_instruction(self, target: str, value: str) -> None:
        self.misc_nodes += 1
        if self.misc_nodes > MAX_MISC_XML_NODES:
            raise _LexicalAbort("comment/processing-instruction node limit exceeded")
        self.text(target)
        self.text(value)

    @staticmethod
    def forbidden(*_args: Any) -> None:
        raise _LexicalAbort("DTD, entity, or notation declarations are forbidden")

    @staticmethod
    def external(*_args: Any) -> int:
        raise _LexicalAbort("external entities are forbidden; no resolver was invoked")

    def _postprocess(self) -> None:
        by_local: dict[str, list[_Node]] = {}
        for node in self.nodes:
            if node.local in SENSITIVE_ELEMENT_LOCAL_NAMES:
                by_local.setdefault(node.local, []).append(node)
        for local, nodes in by_local.items():
            uris = sorted({node.uri for node in nodes})
            if len(uris) > 1:
                first = nodes[0]
                self._finding(
                    "sensitive_element_namespace_collision",
                    "critical",
                    "security-sensitive element local name appears in multiple namespaces",
                    first.path,
                    first.line,
                    first.column,
                    local_name=local,
                    namespaces=json.dumps(uris),
                    occurrence_count=len(nodes),
                    qnames=json.dumps(
                        [node.qname for node in nodes[:MAX_EVIDENCE_ITEMS]]
                    ),
                )

        effective_prefix_sets: list[set[str]] = []
        for prefix_lists in self._exclusive_prefix_lists.values():
            if not prefix_lists:
                effective_prefix_sets.append(set())
                continue
            effective = set(prefix_lists[0])
            for prefix_list in prefix_lists[1:]:
                effective.intersection_update(prefix_list)
            effective_prefix_sets.append(effective)
        exclusive_prefix_sets = tuple(effective_prefix_sets)
        if exclusive_prefix_sets:
            for (
                path,
                attribute,
                value,
                prefix,
                resolved_uri,
                line,
                column,
            ) in self._qname_values:
                if prefix == "xml":
                    continue
                if not resolved_uri:
                    self._finding(
                        "qname_value_undeclared_prefix",
                        "high",
                        "QName-valued attribute uses an unbound prefix",
                        path,
                        line,
                        column,
                        attribute=attribute,
                        value=value,
                        prefix=prefix,
                    )
                elif any(prefix not in prefixes for prefixes in exclusive_prefix_sets):
                    self._finding(
                        "qname_value_namespace_dependency",
                        "high",
                        "exclusive canonicalization may omit a namespace used only in an attribute value",
                        path,
                        line,
                        column,
                        attribute=attribute,
                        value=value,
                        prefix=prefix,
                        uri=resolved_uri,
                    )

    def parse(self) -> None:
        parser = expat.ParserCreate()
        self.parser = parser
        parser.ordered_attributes = True
        parser.specified_attributes = True
        parser.buffer_text = True
        parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
        parser.StartElementHandler = self.start
        parser.EndElementHandler = self.end
        parser.CharacterDataHandler = self.text
        parser.CommentHandler = self.comment
        parser.ProcessingInstructionHandler = self.processing_instruction
        parser.StartDoctypeDeclHandler = self.forbidden
        parser.EntityDeclHandler = self.forbidden
        parser.UnparsedEntityDeclHandler = self.forbidden
        parser.NotationDeclHandler = self.forbidden
        parser.ExternalEntityRefHandler = self.external
        parser.SkippedEntityHandler = self.forbidden
        try:
            parser.Parse(self.raw, True)
        except _LexicalAbort:
            raise
        except expat.ExpatError as exc:
            raise _LexicalAbort(
                f"malformed XML at line {exc.lineno}, column {exc.offset}: {exc}"
            ) from exc
        if self.stack or not self.nodes:
            raise _LexicalAbort("XML document has no complete root element")
        self._postprocess()


if etree is not None:

    class _RejectingResolver(etree.Resolver):  # type: ignore[misc]
        """Last-resort guard: no URL or local path may ever be resolved."""

        def resolve(self, url: str, public_id: str, context: Any) -> Any:
            del url, public_id, context
            raise WpgapSamlError("external resource resolution is forbidden")


def _hardened_parser() -> Any:
    if etree is None:
        raise WpgapSamlError("lxml is required for canonicalization diagnostics")
    parser = etree.XMLParser(
        resolve_entities=False,
        load_dtd=False,
        attribute_defaults=False,
        dtd_validation=False,
        no_network=True,
        recover=False,
        huge_tree=False,
        collect_ids=False,
        remove_comments=False,
        remove_pis=False,
        strip_cdata=False,
    )
    parser.resolvers.add(_RejectingResolver())
    return parser


def _semantic_snapshot(document: Any, with_comments: bool) -> tuple[Any, ...]:
    """Capture the mode-relevant document information set.

    Expanded names are compared instead of prefixes. Processing instructions
    are always retained, comments only in with-comments mode, and adjacent text
    is coalesced when an omitted comment sat between text nodes.
    """

    root = document.getroot() if hasattr(document, "getroot") else document

    def special(node: Any) -> tuple[Any, ...] | None:
        if etree is not None and isinstance(node, etree._Comment):
            return ("comment", node.text or "") if with_comments else None
        if etree is not None and isinstance(node, etree._ProcessingInstruction):
            return ("pi", node.target, node.text or "")
        return None

    def append_text(content: list[tuple[Any, ...]], value: str | None) -> None:
        if not value:
            return
        if content and content[-1][0] == "text":
            content[-1] = ("text", content[-1][1] + value)
        else:
            content.append(("text", value))

    def visit(element: Any) -> tuple[Any, ...]:
        content: list[tuple[Any, ...]] = []
        append_text(content, element.text)
        for child in element:
            if isinstance(getattr(child, "tag", None), str):
                content.append(visit(child))
            else:
                token = special(child)
                if token is not None:
                    content.append(token)
            append_text(content, child.tail)
        attributes = tuple(
            sorted((str(name), value) for name, value in element.attrib.items())
        )
        return "element", str(element.tag), attributes, tuple(content)

    before: list[tuple[Any, ...]] = []
    node = root.getprevious()
    while node is not None:
        token = special(node)
        if token is not None:
            before.append(token)
        node = node.getprevious()
    before.reverse()
    after: list[tuple[Any, ...]] = []
    node = root.getnext()
    while node is not None:
        token = special(node)
        if token is not None:
            after.append(token)
        node = node.getnext()
    return tuple(before), visit(root), tuple(after)


def _probe_c14n(
    document: Any,
    mode: str,
    with_comments: bool,
    *,
    relative_namespace_seen: bool,
) -> SamlC14nProbe:
    exclusive = mode == "exclusive"
    try:
        output = etree.tostring(
            document,
            method="c14n",
            exclusive=exclusive,
            with_comments=with_comments,
        )
        if not isinstance(output, bytes):
            raise ValueError("canonicalizer returned a non-byte result")
        if not output:
            return SamlC14nProbe(
                mode=mode,
                with_comments=with_comments,
                status="empty",
                output_bytes=0,
                sha256=hashlib.sha256(b"").hexdigest(),
                semantic_roundtrip=None,
                idempotent=None,
                error="canonicalizer returned empty output",
            )
        if len(output) > MAX_CANONICAL_BYTES:
            raise ValueError("canonical output exceeds the configured limit")
        digest = hashlib.sha256(output).hexdigest()
        if relative_namespace_seen:
            return SamlC14nProbe(
                mode=mode,
                with_comments=with_comments,
                status="error",
                output_bytes=len(output),
                sha256=digest,
                semantic_roundtrip=None,
                idempotent=None,
                error="relative namespace declarations have no standards-compliant canonical form",
            )
        reparsed_root = etree.fromstring(output, parser=_hardened_parser())
        reparsed_document = reparsed_root.getroottree()
        semantic_roundtrip = _semantic_snapshot(
            document, with_comments
        ) == _semantic_snapshot(reparsed_document, with_comments)
        second = etree.tostring(
            reparsed_document,
            method="c14n",
            exclusive=exclusive,
            with_comments=with_comments,
        )
        idempotent = isinstance(second, bytes) and second == output
        return SamlC14nProbe(
            mode=mode,
            with_comments=with_comments,
            status="ok" if semantic_roundtrip and idempotent else "drift",
            output_bytes=len(output),
            sha256=digest,
            semantic_roundtrip=semantic_roundtrip,
            idempotent=idempotent,
        )
    except WpgapSamlError:
        raise
    except Exception as exc:
        return SamlC14nProbe(
            mode=mode,
            with_comments=with_comments,
            status="error",
            output_bytes=0,
            sha256=None,
            semantic_roundtrip=None,
            idempotent=None,
            error=_clean_error(exc),
        )


def _add_c14n_findings(
    collector: _LexicalCollector, probes: Sequence[SamlC14nProbe]
) -> None:
    for probe in probes:
        if probe.status == "error":
            collector._finding(
                "canonicalization_error",
                "high",
                "canonicalization failed and must never be treated as empty success",
                "/",
                0,
                0,
                mode=probe.mode,
                with_comments=probe.with_comments,
                error=probe.error or "unknown canonicalization error",
            )
        elif probe.status == "empty":
            collector._finding(
                "canonicalization_empty_output",
                "critical",
                "a nonempty XML document canonicalized to empty output",
                "/",
                0,
                0,
                mode=probe.mode,
                with_comments=probe.with_comments,
            )
        elif probe.status == "drift":
            if probe.semantic_roundtrip is False:
                collector._finding(
                    "canonicalization_roundtrip_drift",
                    "critical",
                    "canonicalization changed expanded-name document structure",
                    "/",
                    0,
                    0,
                    mode=probe.mode,
                    with_comments=probe.with_comments,
                )
            if probe.idempotent is False:
                collector._finding(
                    "canonicalization_non_idempotent",
                    "critical",
                    "canonicalization was not idempotent after reparsing",
                    "/",
                    0,
                    0,
                    mode=probe.mode,
                    with_comments=probe.with_comments,
                )

    if collector.relative_namespace_declaration:
        if any(probe.status in {"error", "empty"} for probe in probes):
            collector._finding(
                "canonicalization_void_risk",
                "critical",
                "relative namespace input caused failed/empty canonicalization; never hash an empty fallback",
                "/",
                0,
                0,
            )


def _lint_saml_xml(raw: bytes) -> SamlLexicalReport:
    if etree is None:
        raise WpgapSamlError("lxml is required for canonicalization diagnostics")
    collector = _LexicalCollector(raw)
    try:
        collector.parse()
    except _LexicalAbort as exc:
        raise WpgapSamlError(str(exc)) from exc

    probes: list[SamlC14nProbe] = []
    try:
        root = etree.fromstring(raw, parser=_hardened_parser())
        document = root.getroottree()
    except WpgapSamlError:
        raise
    except Exception as exc:
        collector.namespace_well_formed = False
        error = _clean_error(exc)
        collector._finding(
            "namespace_parser_differential",
            "critical",
            "the lexical parser accepted XML rejected by the strict namespace-aware parser",
            "/",
            0,
            0,
            error=error,
        )
        probes.extend(
            SamlC14nProbe(mode, comments, "error", 0, None, None, None, error)
            for mode in ("inclusive", "exclusive")
            for comments in (False, True)
        )
    else:
        probes.extend(
            _probe_c14n(
                document,
                mode,
                comments,
                relative_namespace_seen=collector.relative_namespace_declaration,
            )
            for mode in ("inclusive", "exclusive")
            for comments in (False, True)
        )

    _add_c14n_findings(collector, probes)
    return SamlLexicalReport(
        xml_bytes=len(raw),
        elements=collector.element_count,
        attributes=collector.attribute_count,
        namespace_declarations=tuple(collector.declarations),
        max_depth=collector.max_depth,
        namespace_well_formed=collector.namespace_well_formed,
        declared_c14n_algorithms=tuple(collector.algorithms),
        inclusive_namespace_prefixes=tuple(collector.inclusive_prefixes),
        probes=tuple(probes),
        findings=tuple(collector.findings),
    )


def lint_saml_xml(data: bytes | bytearray | memoryview | str) -> SamlLexicalReport:
    """Lint supplied raw SAML/XML without resolving or executing anything.

    Unsafe, malformed, unsupported, and resource-exhausting input raises only
    :class:`WpgapSamlError`. Safely retained parser-differential constructs are
    represented as immutable findings instead of being silently normalized.
    """

    try:
        return _lint_saml_xml(_coerce_xml(data))
    except WpgapSamlError:
        raise
    except Exception as exc:
        raise WpgapSamlError(f"SAML lexical analysis failed: {_clean_error(exc)}") from exc


def report_to_dict(report: SamlLexicalReport) -> dict[str, Any]:
    """Serialize a report and state the non-execution guarantees explicitly."""

    if not isinstance(report, SamlLexicalReport):
        raise WpgapSamlError("report must be a SamlLexicalReport")
    try:
        payload = asdict(report)
        payload.update(
            {
                "network_requests": 0,
                "external_entities_resolved": 0,
                "xinclude_processed": False,
                "schema_validation_performed": False,
                "signature_verification_performed": False,
                "reference_resolution_performed": False,
            }
        )
        return payload
    except Exception as exc:
        raise WpgapSamlError(f"could not serialize report: {_clean_error(exc)}") from exc


# Lexical finding codes that bear on XML signature wrapping: namespace/prefix
# tricks that let a parser-differential or canonicalization gap validate one node
# while the application consumes another (the CVE-2025-25291/25292 class).
_WRAPPING_SIGNAL_CATEGORIES: dict[str, str] = {
    "sensitive_element_namespace_collision": "namespace_confusion",
    "namespace_alias_pollution": "namespace_confusion",
    "sensitive_prefix_rebinding": "prefix_rebinding",
    "prefix_rebinding": "prefix_rebinding",
    "sensitive_prefix_misbinding": "prefix_rebinding",
    "duplicate_expanded_attribute": "attribute_collision",
    "attribute_local_name_collision": "attribute_collision",
    "reserved_namespace_attribute": "parser_differential",
    "namespace_parser_differential": "parser_differential",
    "undeclared_prefix": "parser_differential",
    "canonicalization_error": "canonicalization_gap",
    "canonicalization_roundtrip_drift": "canonicalization_gap",
    "canonicalization_non_idempotent": "canonicalization_gap",
    "canonicalization_empty_output": "canonicalization_gap",
    "canonicalization_void_risk": "canonicalization_gap",
    "qname_value_namespace_dependency": "canonicalization_gap",
    "relative_namespace_uri": "canonicalization_gap",
}
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def signature_wrapping_surface(report: SamlLexicalReport) -> dict[str, Any]:
    """Summarize the lexical conditions that enable XML signature wrapping.

    Consumes a :class:`SamlLexicalReport` (it does not re-parse) and groups the
    findings that let a wrapped SAML document validate under one node while the
    application consumes another: namespace/prefix confusion, attribute
    collisions, parser differentials, and canonicalization gaps.  Pure and
    offline; returns a compact triage view for the signature-wrapping workflow.
    """

    if not isinstance(report, SamlLexicalReport):
        raise WpgapSamlError("report must be a SamlLexicalReport")
    signals: list[dict[str, Any]] = []
    categories: set[str] = set()
    max_rank = 0
    max_severity: str | None = None
    for finding in report.findings:
        category = _WRAPPING_SIGNAL_CATEGORIES.get(finding.code)
        if category is None:
            continue
        categories.add(category)
        rank = _SEVERITY_RANK.get(finding.severity, 0)
        if rank > max_rank:
            max_rank, max_severity = rank, finding.severity
        signals.append({
            "code": finding.code,
            "category": category,
            "severity": finding.severity,
            "message": finding.message,
            "path": finding.path,
        })
    signals.sort(key=lambda row: (-_SEVERITY_RANK.get(row["severity"], 0),
                                  row["category"], row["code"], row["path"]))
    canonicalization_stable = all(
        probe.status not in {"drift", "empty", "error"} for probe in report.probes
    )
    return {
        "wrapping_surface_present": bool(signals),
        "signal_count": len(signals),
        "categories": sorted(categories),
        "max_severity": max_severity,
        "signals": signals,
        "canonicalization_stable": canonicalization_stable,
        "namespace_well_formed": report.namespace_well_formed,
        "offline_only": True,
        "network_requests": 0,
    }


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Offline SAML lexical namespace/canonicalization linter"
    )
    parser.add_argument("xml", help="path to raw UTF-8 SAML/XML")
    parser.add_argument("--pretty", action="store_true", help="indent JSON output")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _argument_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        with Path(args.xml).open("rb") as handle:
            raw = handle.read(MAX_XML_BYTES + 1)
        report = lint_saml_xml(raw)
        print(
            json.dumps(
                report_to_dict(report),
                indent=2 if args.pretty else None,
                sort_keys=True,
            )
        )
        return 0
    except (OSError, WpgapSamlError) as exc:
        print(f"error: {_clean_error(exc)}", file=sys.stderr)
        return 2
    except Exception as exc:  # Preserve the CLI's fail-closed contract.
        print(f"error: {_clean_error(exc)}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
