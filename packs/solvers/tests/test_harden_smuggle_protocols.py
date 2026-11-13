"""RFC-locked hardening tests for the offline HTTP desync engines.

The HTTP/1 expected boundaries come from RFC 9112 sections 6.1, 6.3, and 7.1.
The pseudo-header rules come from RFC 9113 section 8.3 and RFC 9114 section
4.3.  QPACK limits come from RFC 9204 sections 2.1.2 and 3.2.3.  The tiny
reference readers below are test-only implementations of those documented
wire rules; no output from an engine under test is used as an oracle.
"""

from __future__ import annotations

import base64
import json
import random

import pytest

import h2_h3_evidence as modern
import http_desync as desync
import http_smuggling as smuggle


def _ids(findings):
    return {finding.finding_id for finding in findings}


def _reference_http1(raw: bytes) -> tuple[bytes, list[tuple[bytes, bytes]], bytes]:
    """Minimal independent RFC 9112 header/body splitter for generated vectors."""
    head, body = raw.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    headers = []
    for line in lines[1:]:
        name, value = line.split(b":", 1)
        headers.append((name, value.strip(b" \t")))
    return lines[0], headers, body


def _header_values(headers: list[tuple[bytes, bytes]], name: bytes) -> list[bytes]:
    wanted = name.lower()
    return [value for field, value in headers if field.lower() == wanted]


def _reference_chunked_extent(body: bytes) -> int:
    """Return the first byte after a strict RFC 9112 chunked body."""
    at = 0
    while True:
        line_end = body.index(b"\r\n", at)
        size = int(body[at:line_end].split(b";", 1)[0], 16)
        at = line_end + 2
        if size == 0:
            if body[at:at + 2] == b"\r\n":
                return at + 2
            trailer_end = body.index(b"\r\n\r\n", at)
            return trailer_end + 4
        assert body[at + size:at + size + 2] == b"\r\n"
        at += size + 2


HTTP1_VECTORS = [
    pytest.param(
        b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 3\r\n\r\nabc",
        set(),
        id="content-length-exact",
    ),
    pytest.param(
        b"POST / HTTP/1.1\r\nHost: example.test\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
        set(),
        id="transfer-encoding-exact",
    ),
    pytest.param(
        b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        {"cl-te-coexist"},
        id="cl-te-or-te-cl-ambiguity",
    ),
    pytest.param(
        b"POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: identity\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        {"duplicate-transfer-encoding"},
        id="te-te-duplicate",
    ),
]


@pytest.mark.parametrize("raw, expected_ids", HTTP1_VECTORS)
def test_saved_request_classification_matches_rfc9112(raw, expected_ids):
    assert _ids(smuggle.analyze_saved_request(raw)) == expected_ids


def test_saved_request_parser_and_report_vector_lock():
    raw = b"POST /submit HTTP/1.1\r\nHost: example.test\r\nContent-Length: 3\r\n\r\nabc"
    parsed = smuggle.parse_saved_request(raw)
    assert (parsed.method, parsed.target, parsed.version) == ("POST", "/submit", "HTTP/1.1")
    assert parsed.values("host") == ("example.test",)
    assert parsed.values("content-length") == ("3",)
    assert parsed.body == b"abc"
    assert parsed.anomalies == ()

    report = smuggle.report_dict(raw)
    assert report["request"]["body_length"] == 3
    assert report["request"]["method"] == "POST"
    assert report["findings"] == []
    assert report["offline"] is True and report["network_requests"] == 0


def test_variant_matrix_has_documented_parser_boundaries():
    rows = smuggle.build_variant_matrix(
        b"GET /account HTTP/1.1\r\nHost: example.test\r\n\r\n"
    )
    by_key = {(row.family, row.name): row for row in rows}
    assert {row.family for row in rows} == {
        "CL.TE", "TE.CL", "TE.TE", "HTTP2-downgrade"
    }
    assert all(row.offline and row.network_requests == 0 for row in rows)

    clte = by_key[("CL.TE", "canonical")].request.encode("latin-1")
    _, headers, body = _reference_http1(clte)
    assert int(_header_values(headers, b"content-length")[0]) == len(body)
    assert _header_values(headers, b"transfer-encoding") == [b"chunked"]
    consumed = _reference_chunked_extent(body)
    assert consumed == len(b"0\r\n\r\n")
    assert body[consumed:].startswith(b"OPTIONS /__r5d_inert_boundary__ HTTP/1.1\r\n")

    tecl = by_key[("TE.CL", "canonical")].request.encode("latin-1")
    _, headers, body = _reference_http1(tecl)
    cl_boundary = int(_header_values(headers, b"content-length")[0])
    assert body[:cl_boundary].endswith(b"\r\n")
    assert body[cl_boundary:].startswith(b"OPTIONS /__r5d_inert_boundary__ HTTP/1.1\r\n")
    assert _reference_chunked_extent(body) == len(body)


def test_desync_generator_locks_clte_tecl_tete_and_cl0_boundaries():
    rows = desync.generate_desync_candidates("example.test")
    assert [row["technique"] for row in rows] == [
        "CL.TE", "TE.CL",
        "TE.TE", "TE.TE", "TE.TE", "TE.TE", "TE.TE", "TE.TE",
        "CL.0", "H2.CL", "H2.TE",
    ]
    assert [row["variant"] for row in rows[2:8]] == [
        "name_space", "value_prefix", "value_suffix", "comma_identity",
        "duplicate_identity_first", "duplicate_chunked_first",
    ]
    assert all(row["candidate_only"] and row["offline"] for row in rows)
    assert all(row["network_requests"] == 0 for row in rows)

    decoded = {
        (row["technique"], row["variant"]): base64.b64decode(row["request_base64"])
        for row in rows
    }
    clte = decoded[("CL.TE", "canonical")]
    _, headers, body = _reference_http1(clte)
    assert int(_header_values(headers, b"content-length")[0]) == len(body)
    boundary = _reference_chunked_extent(body)
    assert body[boundary:].startswith(b"GET /__csctf_desync_marker__ HTTP/1.1\r\n")

    tecl = decoded[("TE.CL", "canonical")]
    _, headers, body = _reference_http1(tecl)
    cl_boundary = int(_header_values(headers, b"content-length")[0])
    assert body[cl_boundary:].startswith(b"GET /__csctf_desync_marker__ HTTP/1.1\r\n")
    assert _reference_chunked_extent(body) == len(body)

    cl0 = decoded[("CL.0", "body_ignored")]
    _, headers, body = _reference_http1(cl0)
    assert int(_header_values(headers, b"content-length")[0]) == len(body)
    assert body.startswith(b"GET /__csctf_desync_marker__ HTTP/1.1\r\n")


def test_http1_builder_and_transfer_encoding_catalog_vector_lock():
    raw = desync.build_http1_request(
        "post", "/x", "example.test", (("X-Test", "one"), ("X-Test", "two")), b"abc"
    )
    assert raw == (
        b"POST /x HTTP/1.1\r\nHost: example.test\r\n"
        b"X-Test: one\r\nX-Test: two\r\n\r\nabc"
    )
    variants = desync.transfer_encoding_variants()
    assert [row["name"] for row in variants] == [
        "canonical", "ows_tab", "name_space", "value_prefix", "value_suffix",
        "comma_identity", "duplicate_identity_first", "duplicate_chunked_first", "mixed_case",
    ]
    assert variants[0]["headers"] == [{"name": "Transfer-Encoding", "value": "chunked"}]
    assert variants[-1]["headers"] == [{"name": "Transfer-encoding", "value": "cHuNkEd"}]


def test_cache_candidate_entrypoints_are_deterministic_and_offline():
    poisoning = desync.cache_poisoning_candidates(
        "example.test", path="/account", marker_host="marker.invalid"
    )
    deception = desync.cache_deception_candidates("/account")
    combined = desync.cache_candidates("example.test", marker_host="marker.invalid")
    assert [row["name"] for row in poisoning] == [
        "x_forwarded_host", "x_host", "forwarded_host", "x_original_url",
        "x_rewrite_url", "x_forwarded_scheme", "absolute_form",
    ]
    assert [row["name"] for row in deception] == [
        "path_info_css", "semicolon_css", "encoded_question", "encoded_semicolon",
        "encoded_slash", "double_slash", "dot_segment",
    ]
    assert combined["poisoning"] == poisoning and combined["deception"] == deception
    assert combined["offline"] is True and combined["network_requests"] == 0


def test_desync_cli_is_guarded_and_never_requests_a_network(capsys):
    assert desync.main(["te", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result[0]["name"] == "canonical"
    assert all(row["network_requests"] == 0 for row in result)
    assert desync.main(["desync", "bad host"]) == 2
    assert "http_desync:" in capsys.readouterr().err


def test_structural_trace_parser_vector_lock():
    records = modern.parse_structural_trace(
        'HEADER stream=1 name=:path value="/with space" value=/second protocol=h2\n'
    )
    assert len(records) == 1
    assert records[0].kind == "HEADER"
    assert records[0].fields == (
        ("stream", "1"), ("name", ":path"), ("value", "/with space"),
        ("value", "/second"), ("protocol", "h2"),
    )


@pytest.mark.parametrize("protocol", ["h2", "h3"])
def test_pseudo_header_order_and_duplicates_match_rfc(protocol):
    prefix = "HEADER" if protocol == "h2" else "H3_HEADER"
    stream = 1 if protocol == "h2" else 0
    trace = "\n".join((
        f"{prefix} stream={stream} block=initial name=x-first value=1 protocol={protocol}",
        f"{prefix} stream={stream} block=initial name=:method value=GET protocol={protocol}",
        f"{prefix} stream={stream} block=initial name=:method value=POST protocol={protocol}",
        f"{prefix} stream={stream} block=initial name=:scheme value=https protocol={protocol}",
        f"{prefix} stream={stream} block=initial name=:path value=/ protocol={protocol}",
    ))
    analyze = modern.analyze_http2_trace if protocol == "h2" else modern.analyze_http3_trace
    ids = _ids(analyze(trace))
    assert f"{protocol}-pseudo-after-regular-s{stream}-initial" in ids
    assert f"{protocol}-duplicate-pseudo-s{stream}-initial" in ids


@pytest.mark.parametrize("protocol", ["h2", "h3"])
def test_clean_request_and_response_pseudo_headers(protocol):
    prefix = "HEADER" if protocol == "h2" else "H3_HEADER"
    stream = 1 if protocol == "h2" else 0
    request = "\n".join((
        f"{prefix} stream={stream} block=initial role=request name=:method value=GET protocol={protocol}",
        f"{prefix} stream={stream} block=initial role=request name=:scheme value=https protocol={protocol}",
        f"{prefix} stream={stream} block=initial role=request name=:authority value=example.test protocol={protocol}",
        f"{prefix} stream={stream} block=initial role=request name=:path value=/ protocol={protocol}",
    ))
    response = "\n".join((
        f"{prefix} stream={stream} block=initial role=response name=:status value=204 protocol={protocol}",
        f"{prefix} stream={stream} block=initial role=response name=content-type value=text/plain protocol={protocol}",
    ))
    analyze = modern.analyze_http2_trace if protocol == "h2" else modern.analyze_http3_trace
    assert analyze(request) == ()
    assert analyze(response, direction="server") == ()


def test_qpack_blocking_and_capacity_evidence_matches_rfc9204():
    bad = (
        "QPACK required_insert_count=9 insert_count=2 blocked_streams=5 "
        "max_blocked_streams=1 dynamic_table_capacity=4096 max_table_capacity=128"
    )
    assert _ids(modern.analyze_http3_trace(bad)) == {
        "h3-qpack-blocked-1", "h3-qpack-block-limit-1", "h3-qpack-capacity-1"
    }
    clean = (
        "QPACK required_insert_count=2 insert_count=2 blocked_streams=1 "
        "max_blocked_streams=1 dynamic_table_capacity=128 max_table_capacity=128"
    )
    assert modern.analyze_http3_trace(clean) == ()


def test_modern_variant_catalog_is_stable_inert_evidence():
    rows = modern.build_modern_http_variants("LOCKED_VECTOR")
    assert [(row.protocol, row.name) for row in rows] == [
        ("h2", "pseudo-order"), ("h2", "content-length-downgrade"),
        ("h2", "reset-volume"), ("h3", "qpack-block"),
        ("h3", "zero-rtt"), ("h3", "migration-alt-svc"),
    ]
    assert all(row.inert and row.offline and row.network_requests == 0 for row in rows)


def _clean_or_declared(call, error_type):
    try:
        call()
    except error_type:
        pass


SMUGGLE_RAW_ENTRYPOINTS = (
    smuggle.parse_saved_request,
    smuggle.analyze_saved_request,
    smuggle.build_variant_matrix,
    smuggle.report_dict,
)


def test_http1_malformed_truncated_bitflipped_random_and_oversized_fail_closed():
    valid = b"POST /x HTTP/1.1\r\nHost: example.test\r\nContent-Length: 3\r\n\r\nabc"
    corpus = [b"", b"\x00"] + [valid[:cut] for cut in range(len(valid))]
    corpus += [valid[:at] + bytes((valid[at] ^ 1,)) + valid[at + 1:] for at in range(len(valid))]
    rng = random.Random(0xC1A0)
    corpus += [bytes(rng.randrange(256) for _ in range(size)) for size in range(1, 257, 7)]
    corpus.append(b"A" * (smuggle.MAX_CAPTURE_BYTES + 1))
    for entrypoint in SMUGGLE_RAW_ENTRYPOINTS:
        for raw in corpus:
            _clean_or_declared(lambda entrypoint=entrypoint, raw=raw: entrypoint(raw), smuggle.SavedHTTPError)


MODERN_RAW_ENTRYPOINTS = (
    modern.parse_structural_trace,
    modern.analyze_http2_trace,
    modern.analyze_http3_trace,
)


def test_h2_h3_malformed_truncated_bitflipped_random_and_oversized_fail_closed():
    valid = (
        b"HEADER stream=1 block=initial name=:method value=GET protocol=h2\n"
        b"HEADER stream=1 block=initial name=:scheme value=https protocol=h2\n"
        b"HEADER stream=1 block=initial name=:path value=/ protocol=h2\n"
    )
    corpus = [b"", b"\x00"] + [valid[:cut] for cut in range(len(valid))]
    corpus += [valid[:at] + bytes((valid[at] ^ 1,)) + valid[at + 1:] for at in range(0, len(valid), 3)]
    rng = random.Random(0x9204)
    corpus += [bytes(rng.randrange(256) for _ in range(size)) for size in range(1, 257, 7)]
    corpus.append(b"A" * (modern.MAX_TRACE_BYTES + 1))
    for entrypoint in MODERN_RAW_ENTRYPOINTS:
        for raw in corpus:
            _clean_or_declared(lambda entrypoint=entrypoint, raw=raw: entrypoint(raw), modern.ModernHTTPError)


def test_desync_generators_reject_empty_random_weird_and_oversized_inputs():
    bad_hosts = (None, b"host", "", "bad host", "snowman-☃.test", "a" * 254)
    for host in bad_hosts:
        with pytest.raises(desync.DesyncInputError):
            desync.generate_desync_candidates(host)
        with pytest.raises(desync.DesyncInputError):
            desync.cache_poisoning_candidates(host)
    for path in (None, b"/", "", "relative", "/bad path", "/" + "x" * (desync.MAX_FIELD + 1)):
        with pytest.raises(desync.DesyncInputError):
            desync.cache_deception_candidates(path)
    with pytest.raises(desync.DesyncInputError):
        desync.build_http1_request("POST", "/", "example.test", body=b"x" * (desync.MAX_BODY + 1))


@pytest.mark.parametrize("protocol", ["h2", "h3"])
def test_bug_missing_required_scheme_is_classified_as_malformed(protocol):
    prefix = "HEADER" if protocol == "h2" else "H3_HEADER"
    stream = 1 if protocol == "h2" else 0
    trace = "\n".join((
        f"{prefix} stream={stream} block=initial name=:method value=GET protocol={protocol}",
        f"{prefix} stream={stream} block=initial name=:path value=/ protocol={protocol}",
    ))
    analyze = modern.analyze_http2_trace if protocol == "h2" else modern.analyze_http3_trace
    findings = analyze(trace)
    assert any("scheme" in finding.finding_id.casefold() or "scheme" in finding.title.casefold()
               for finding in findings)


@pytest.mark.parametrize("entrypoint", SMUGGLE_RAW_ENTRYPOINTS)
def test_bug_smuggling_weird_unicode_raises_only_declared_error(entrypoint):
    with pytest.raises(smuggle.SavedHTTPError):
        entrypoint("snowman-☃-\ud800")


@pytest.mark.parametrize("entrypoint", SMUGGLE_RAW_ENTRYPOINTS)
def test_bug_smuggling_released_memoryview_raises_only_declared_error(entrypoint):
    released = memoryview(b"GET / HTTP/1.1\r\n\r\n")
    released.release()
    with pytest.raises(smuggle.SavedHTTPError):
        entrypoint(released)


@pytest.mark.parametrize("entrypoint", MODERN_RAW_ENTRYPOINTS)
def test_bug_modern_weird_unicode_raises_only_declared_error(entrypoint):
    with pytest.raises(modern.ModernHTTPError):
        entrypoint("snowman-☃-\ud800")


@pytest.mark.parametrize("entrypoint", MODERN_RAW_ENTRYPOINTS)
def test_bug_modern_released_memoryview_raises_only_declared_error(entrypoint):
    released = memoryview(b"HEADER")
    released.release()
    with pytest.raises(modern.ModernHTTPError):
        entrypoint(released)


@pytest.mark.parametrize("entrypoint", (modern.analyze_http2_trace, modern.analyze_http3_trace))
def test_bug_modern_unhashable_direction_raises_only_declared_error(entrypoint):
    with pytest.raises(modern.ModernHTTPError):
        entrypoint(b"", direction={})


def test_bug_desync_unicode_body_raises_only_declared_error():
    with pytest.raises(desync.DesyncInputError):
        desync.build_http1_request("POST", "/", "example.test", body="snowman-☃")


def test_bug_desync_invalid_header_collection_raises_only_declared_error():
    with pytest.raises(desync.DesyncInputError):
        desync.build_http1_request("GET", "/", "example.test", headers=None)
