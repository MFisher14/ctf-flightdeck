"""Tests for inert XXE/XInclude and SSRF metadata catalogs."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
WEB = REPO / "solvers" / "web"
sys.path.insert(0, str(WEB))

import xml_ssrf_catalog as catalog  # noqa: E402


def test_xxe_xinclude_depth_is_stable_local_and_inert():
    rows = catalog.xxe_xinclude_catalog("/etc/hostname", "ROUND5")
    assert [(row.family, row.name) for row in rows] == [
        ("xxe", "general_entity_local_file"),
        ("xxe", "internal_parameter_entity"),
        ("xxe", "nested_internal_entity_control"),
        ("xinclude", "xinclude_text"),
        ("xinclude", "xinclude_fallback_control"),
        ("xinclude", "soap_body_xinclude"),
        ("xinclude", "svg_xinclude"),
    ]
    assert 'SYSTEM "file:///etc/hostname"' in rows[0].document
    assert "<!ENTITY % define" in rows[1].document
    assert "ROUND5:ROUND5" not in rows[2].document
    assert "&two;" in rows[2].document
    assert 'parse="text"' in rows[3].document
    assert all(row.to_dict()["inert"] for row in rows)
    assert all(row.to_dict()["network_requests"] == 0 for row in rows)


def test_xxe_catalog_rejects_remote_or_delimiter_bearing_resources():
    with pytest.raises(catalog.CatalogInputError, match="local file resources only"):
        catalog.xxe_xinclude_catalog("https://outside.invalid/probe")
    with pytest.raises(catalog.CatalogInputError, match="empty authority"):
        catalog.xxe_xinclude_catalog("file://outside.invalid/share")
    with pytest.raises(catalog.CatalogInputError, match="XML/control delimiter"):
        catalog.xxe_xinclude_catalog('/etc/host"name')
    with pytest.raises(catalog.CatalogInputError, match="conservative ASCII"):
        catalog.xxe_xinclude_catalog(marker="bad marker")


def test_cloud_metadata_contracts_include_methods_headers_and_chain_order():
    rows = catalog.cloud_metadata_catalog()
    assert [row.provider for row in rows] == [
        "aws",
        "aws",
        "aws",
        "aws-ecs",
        "gcp",
        "azure",
        "oracle",
        "alibaba",
    ]
    aws = catalog.cloud_metadata_catalog("aws")
    assert [row.name for row in aws] == [
        "imds_v2_token",
        "imds_v2_metadata",
        "imds_v1_control",
    ]
    assert aws[0].method == "PUT" and aws[0].chain_step == 1
    assert aws[0].headers == (("X-aws-ec2-metadata-token-ttl-seconds", "60"),)
    assert aws[1].chain_step == 2
    assert catalog.cloud_metadata_catalog("gcp")[0].headers == (
        ("Metadata-Flavor", "Google"),
    )
    with pytest.raises(catalog.CatalogInputError, match="unknown provider"):
        catalog.cloud_metadata_catalog("digital-ocean")


def test_metadata_bypass_matrix_is_exact_ranked_and_string_only():
    rows = catalog.metadata_bypass_encodings("169.254.169.254", "/latest/meta-data/")
    assert [row.name for row in rows] == [
        "canonical",
        "single_decimal",
        "single_hex",
        "single_octal",
        "dotted_hex",
        "dotted_octal",
        "ipv6_mapped",
        "percent_encoded_dots",
        "double_encoded_dots",
        "trailing_dot",
        "userinfo_authority",
        "fragment_authority_decoy",
    ]
    values = {row.name: row.url for row in rows}
    assert values["single_hex"].startswith("http://0xa9fea9fe/")
    assert values["ipv6_mapped"].startswith("http://[::ffff:169.254.169.254]/")
    assert "%252e" in values["double_encoded_dots"]
    assert values["userinfo_authority"].startswith("http://allowed.invalid@")
    assert all(isinstance(row.url, str) and row.method == "GET" for row in rows)
    with pytest.raises(catalog.CatalogInputError, match="IPv4 literal"):
        catalog.metadata_bypass_encodings("metadata.google.internal")


def test_chain_catalog_uses_reserved_marker_and_never_claims_execution():
    rows = catalog.ssrf_chain_catalog("probe.r5d.invalid")
    assert [row["rank"] for row in rows] == [1, 2, 3, 4, 5]
    assert rows[0]["name"] == "allowlist_redirect_to_metadata"
    assert all(row["offline"] and row["network_requests"] == 0 for row in rows)
    assert "probe.r5d.invalid" in " ".join(rows[0]["steps"])
    with pytest.raises(catalog.CatalogInputError, match=r"reserved \.invalid"):
        catalog.ssrf_chain_catalog("real.example")


def test_static_analyzer_reports_source_evidence_in_source_order():
    supplied = """
def proxy(url):
    if url.startswith('https://allowed.invalid'):
        return requests.get(url, allow_redirects=True)
# diagnostic references 169.254.169.254 and Metadata-Flavor
if address.is_private: reject()
"""
    rows = catalog.analyze_saved_ssrf_evidence(supplied)
    assert [row.name for row in rows] == [
        "raw_prefix_allowlist",
        "url_fetch_api",
        "redirect_following",
        "link_local_address",
        "provider_header",
        "private_address_check",
    ]
    assert [row.offset for row in rows] == sorted(row.offset for row in rows)
    assert all(len(row.evidence) < 180 for row in rows)
    with pytest.raises(catalog.CatalogInputError, match="exceeds"):
        catalog.analyze_saved_ssrf_evidence("x" * (catalog.MAX_TEXT + 1))


def test_module_imports_no_transport_parser_or_deserializer():
    tree = ast.parse((WEB / "xml_ssrf_catalog.py").read_text(encoding="utf-8"))
    imports: set[str] = set()
    calls: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                calls.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                calls.add(node.func.attr)
    assert not imports.intersection(
        {
            "socket",
            "requests",
            "http.client",
            "urllib.request",
            "xml.etree.ElementTree",
            "lxml",
            "pickle",
            "marshal",
        }
    )
    assert not calls.intersection(
        {"connect", "send", "sendall", "urlopen", "request", "parse", "loads", "eval", "exec"}
    )
