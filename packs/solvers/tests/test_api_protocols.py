"""Deterministic offline tests for GraphQL, gRPC-web, and WebSocket analysis."""

from __future__ import annotations

import ast
import base64
from pathlib import Path
import sys

import pytest


REPO = Path(__file__).resolve().parents[1]
WEB = REPO / "solvers" / "web"
sys.path.insert(0, str(WEB))

import api_protocols as api  # noqa: E402


def _ids(findings):
    return {item.finding_id for item in findings}


def test_graphql_masks_strings_comments_and_detects_real_introspection():
    benign = 'query R5D { echo(value: "mutation __schema") } # __type\n'
    assert "graphql-introspection" not in _ids(api.analyze_graphql_document(benign))
    real = "query R5D { __schema { queryType { name } } }"
    finding = next(item for item in api.analyze_graphql_document(real)
                   if item.finding_id == "graphql-introspection")
    assert finding.confidence == "high" and "__schema" in finding.evidence


def test_graphql_complexity_get_mutation_pagination_and_balance_evidence():
    aliases = " ".join(f"a{i}: node(first: 5001) {{ child {{ child {{ value }} }} }}"
                       for i in range(8))
    document = "mutation R5D { " + aliases + " }"
    findings = api.analyze_graphql_document(document, method="GET")
    ids = _ids(findings)
    assert {"graphql-alias-amplification", "graphql-get-mutation", "graphql-pagination-limit"} <= ids
    alias = next(item for item in findings if item.finding_id == "graphql-alias-amplification")
    assert alias.severity == "medium" and alias.confidence == "high"
    broken = api.analyze_graphql_document("query X { viewer { name }", method="POST")
    assert "graphql-unbalanced" in _ids(broken)

    arguments = "query Args { search(" + ", ".join(f"arg{i}: value{i}" for i in range(10)) + ") { name } }"
    assert "graphql-alias-amplification" not in _ids(api.analyze_graphql_document(arguments))


def test_graphql_depth_batch_duplicate_metadata_and_multiple_operations():
    deep = "query D { " + "child { " * 8 + "value" + " }" * 8 + " }"
    assert "graphql-depth" in _ids(api.analyze_graphql_document(deep))
    batch = '[{"query":"query A { __typename }"},{"query":"query B { __typename }"}]'
    findings = api.analyze_graphql_document(
        batch,
        headers=(("Content-Type", "application/json"), ("Content-Type", "application/graphql")),
    )
    assert {"graphql-batching", "graphql-duplicate-content-type"} <= _ids(findings)
    multiple = api.analyze_graphql_document("query A { __typename } query B { __typename }")
    assert "graphql-multiple-operations" in _ids(multiple)


def test_graphql_builders_are_stable_bounded_and_inert():
    rows = api.build_graphql_variants(root_field="node", id_argument="id", marker="R5D_INERT")
    assert rows == api.build_graphql_variants(root_field="node", id_argument="id", marker="R5D_INERT")
    assert [row.rank for row in rows] == list(range(1, len(rows) + 1))
    assert {row.name for row in rows} == {
        "typename-control", "alias-fanout", "fragment-reuse", "multi-operation", "lexical-batch",
    }
    assert all(row.offline and row.network_requests == 0 and row.hypothesis for row in rows)
    with pytest.raises(api.APIProtocolError, match="GraphQL name"):
        api.build_graphql_variants(root_field="bad-field")


def test_grpc_frames_leave_messages_opaque_and_preserve_duplicate_trailers():
    message = b"\x08\x96\x01R5D"
    data = api.build_grpc_web_frame(message)
    trailers = api.build_grpc_web_trailers((
        ("grpc-status", "0"), ("grpc-status", "7"), ("x-r5d", "marker"),
    ))
    frames = api.parse_grpc_web_frames(data + trailers)
    assert len(frames) == 2
    assert frames[0].kind == "data" and frames[0].payload_length == len(message)
    assert frames[0].payload_sha256 and "R5D" in frames[0].ascii_preview
    assert [item.name for item in frames[1].trailers].count("grpc-status") == 2
    findings = api.analyze_grpc_web_capture(data + trailers)
    assert "grpc-duplicate-status" in _ids(findings)


def test_grpc_malformed_flags_compression_truncation_and_terminal_order():
    reserved = bytes((0x40, 0, 0, 0, 1)) + b"x"
    compressed = api.build_grpc_web_frame(b"opaque", compressed=True)
    trailer = api.build_grpc_web_trailers((("x-r5d", "no-status"),))
    later = api.build_grpc_web_frame(b"later")
    findings = api.analyze_grpc_web_capture(reserved + compressed + trailer + later)
    assert {
        "grpc-reserved-flags", "grpc-compression-without-encoding",
        "grpc-missing-status", "grpc-data-after-trailers",
    } <= _ids(findings)
    truncated = bytes((0, 0, 0, 0, 10)) + b"short"
    frame = api.parse_grpc_web_frames(truncated)[0]
    assert frame.complete is False and frame.declared_length == 10 and frame.payload_length == 5
    assert "grpc-truncated-frame" in _ids(api.analyze_grpc_web_capture(truncated))

    uppercase_trailer = api.build_grpc_web_frame(b"Grpc-Status: 0\r\n", trailers=True)
    assert "grpc-malformed-trailers" in _ids(api.analyze_grpc_web_capture(uppercase_trailer))


def test_grpc_text_mode_content_type_and_canonical_base64():
    wire = api.build_grpc_web_frame(b"R5D") + api.build_grpc_web_trailers((("grpc-status", "0"),))
    text = base64.b64encode(wire)
    frames = api.parse_grpc_web_frames(text, text_mode=True)
    assert len(frames) == 2 and frames[-1].trailers[0].value == "0"
    findings = api.analyze_grpc_web_capture(
        text, text_mode=True,
        headers=(("Content-Type", "application/grpc-web-text"),
                 ("Content-Type", "application/octet-stream")),
    )
    assert "grpc-duplicate-content-type" in _ids(findings)
    with pytest.raises(api.APIProtocolError, match="base64"):
        api.parse_grpc_web_frames(b"not base64!", text_mode=True)


def test_grpc_variant_catalog_round_trips_without_protobuf_runtime():
    rows = api.build_grpc_web_variants()
    assert [row.rank for row in rows] == [1, 2, 3]
    assert all(row.offline and row.network_requests == 0 for row in rows)
    for row in rows:
        frames = api.parse_grpc_web_frames(base64.b64decode(row.value))
        assert frames and all(frame.payload_sha256 for frame in frames)
    with pytest.raises(api.APIProtocolError, match="ASCII"):
        api.build_grpc_web_trailers((("grpc-message", "snowman-☃"),))


def _valid_handshake(extra: bytes = b"") -> bytes:
    return (
        b"GET /socket HTTP/1.1\r\nHost: app.test\r\nUpgrade: websocket\r\n"
        b"Connection: keep-alive, Upgrade\r\n"
        b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        b"Sec-WebSocket-Version: 13\r\nOrigin: https://app.test\r\n" + extra + b"\r\n"
    )


def test_handshake_preserves_duplicates_and_surfaces_cswsh_and_extensions():
    raw = (
        b"GET /socket HTTP/1.1\r\nHost: app.test\r\nUpgrade: websocket\r\n"
        b"Connection: Upgrade\r\nSec-WebSocket-Key: bad\r\nSec-WebSocket-Key: also-bad\r\n"
        b"Sec-WebSocket-Version: 12\r\nCookie: sid=opaque\r\n"
        b"Sec-WebSocket-Protocol: chat, chat\r\n"
        b"Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n"
    )
    handshake = api.parse_saved_handshake(raw)
    assert handshake.values("sec-websocket-key") == ("bad", "also-bad")
    ids = _ids(api.analyze_websocket_handshake(raw))
    assert {"ws-key", "ws-version", "ws-cswsh-origin", "ws-duplicate-subprotocol",
            "ws-compression-context"} <= ids

    duplicate_origin = _valid_handshake(b"Origin: https://other.test\r\n")
    assert "ws-duplicate-origin" in _ids(api.analyze_websocket_handshake(duplicate_origin))


def test_valid_handshake_and_expected_origin_comparison():
    assert api.analyze_websocket_handshake(
        _valid_handshake(), expected_origin="https://app.test"
    ) == ()
    mismatch = api.analyze_websocket_handshake(
        _valid_handshake(), expected_origin="https://other.test"
    )
    assert "ws-origin-mismatch" in _ids(mismatch)


def test_websocket_frame_roundtrip_and_message_abuse_evidence():
    message = '{"type":"R5D_DELETE","role":"user","role":"admin","userId":"7"}'
    wire = api.build_websocket_frame(message, masked=True, mask_key=b"R5D!")
    frame = api.parse_websocket_frames(wire)[0]
    assert frame.complete and frame.masked and frame.payload.decode() == message
    ids = _ids(api.analyze_websocket_frames(wire, direction="client"))
    assert {"ws-duplicate-message-keys", "ws-client-authority-fields",
            "ws-state-changing-message"} <= ids


def test_websocket_fragment_reassembly_and_object_scoped_duplicate_keys():
    first = api.build_websocket_frame('{"role":', opcode=1, fin=False)
    second = api.build_websocket_frame('"admin"}', opcode=0, fin=True)
    ids = _ids(api.analyze_websocket_frames(first + second))
    assert "ws-client-authority-fields" in ids
    assert "ws-incomplete-message" not in ids

    separate_objects = api.build_websocket_frame('{"a":{"id":1},"b":{"id":2}}')
    assert "ws-duplicate-message-keys" not in _ids(api.analyze_websocket_frames(separate_objects))

    compressed = bytearray(api.build_websocket_frame(b"\xff", opcode=1))
    compressed[0] |= 0x40
    compressed_ids = _ids(api.analyze_websocket_frames(
        bytes(compressed), extensions=("permessage-deflate",)
    ))
    assert "ws-invalid-text" not in compressed_ids
    assert "ws-rsv-without-extension" not in compressed_ids


def test_websocket_protocol_framing_anomalies_and_truncation():
    unmasked = api.build_websocket_frame("x", masked=False)
    orphan = api.build_websocket_frame("part", opcode=0, masked=True)
    invalid_reserved = bytes((0x83, 0x80, 0, 0, 0, 0))
    truncated = bytes((0x81, 0x85)) + b"R5D!" + b"x"
    ids = _ids(api.analyze_websocket_frames(unmasked + orphan + invalid_reserved + truncated))
    assert {"ws-client-unmasked", "ws-orphan-continuation", "ws-reserved-opcode",
            "ws-truncated-frame"} <= ids
    with pytest.raises(api.APIProtocolError, match="control frames"):
        api.build_websocket_frame(b"x" * 126, opcode=9)


def test_websocket_graphql_utf8_rsv_and_variants():
    graphql = api.build_websocket_frame('{"query":"mutation R5D { __schema { types { name } } }"}')
    invalid_utf8 = api.build_websocket_frame(b"\xff", opcode=1)
    rsv_wire = bytes((0xC1, 0x80, *b"R5D!"))
    ids = _ids(api.analyze_websocket_frames(graphql + invalid_utf8 + rsv_wire))
    assert {"ws-graphql-operation", "ws-invalid-text", "ws-rsv-without-extension"} <= ids
    rows = api.build_websocket_variants()
    assert [row.rank for row in rows] == list(range(1, len(rows) + 1))
    for row in rows:
        parsed = api.parse_websocket_frames(base64.b64decode(row.value))
        assert len(parsed) == 1 and parsed[0].complete and parsed[0].masked


def test_protocol_inputs_are_bounded_and_fail_closed():
    with pytest.raises(api.APIProtocolError, match="exceeds"):
        api.analyze_graphql_document("x" * (api.MAX_TEXT + 1))
    with pytest.raises(api.APIProtocolError, match="header count"):
        api.analyze_graphql_document("query X { __typename }", headers=(("X-A", "x"),) * 257)
    with pytest.raises(api.APIProtocolError, match="empty"):
        api.parse_saved_handshake(b"")
    with pytest.raises(api.APIProtocolError, match="mask_key"):
        api.build_websocket_frame("x", mask_key=b"bad")


def test_protocol_module_has_no_transport_process_or_deserialisation_surface():
    tree = ast.parse((WEB / "api_protocols.py").read_text(encoding="utf-8"))
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
    assert not imports.intersection({
        "socket", "requests", "http.client", "urllib.request", "websocket", "subprocess",
        "pickle", "marshal", "google.protobuf", "grpc", "yaml", "json",
    })
    assert not calls.intersection({
        "connect", "request", "send", "sendall", "urlopen", "Popen", "run",
        "loads", "load", "ParseFromString", "eval", "exec",
    })
