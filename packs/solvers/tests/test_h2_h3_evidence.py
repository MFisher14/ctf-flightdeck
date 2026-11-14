"""Deterministic tests for offline HTTP/2 and HTTP/3 structural evidence."""

from __future__ import annotations

import ast
from pathlib import Path
import sys

import pytest


REPO = Path(__file__).resolve().parents[1]
WEB = REPO / "solvers" / "web"
sys.path.insert(0, str(WEB))

import h2_h3_evidence as modern  # noqa: E402


def _ids(rows):
    return {row.finding_id for row in rows}


def test_trace_parser_preserves_duplicate_keys_order_and_quotes():
    rows = modern.parse_structural_trace(
        'HEADER stream=1 name=:path value="/r5d path" value=/second protocol=h2\n'
    )
    assert len(rows) == 1
    assert rows[0].values("value") == ("/r5d path", "/second")
    assert rows[0].fields[0] == ("stream", "1")


def test_h2_pseudo_order_duplicates_authority_and_connection_fields():
    trace = """
FRAME type=HEADERS stream=1 protocol=h2
HEADER stream=1 block=initial name=x-r5d value=inert protocol=h2
HEADER stream=1 block=initial name=:method value=POST protocol=h2
HEADER stream=1 block=initial name=:method value=GET protocol=h2
HEADER stream=1 block=initial name=:path value=/ protocol=h2
HEADER stream=1 block=initial name=:authority value=edge.test protocol=h2
HEADER stream=1 block=initial name=host value=origin.test protocol=h2
HEADER stream=1 block=initial name=connection value=keep-alive protocol=h2
HEADER stream=1 block=initial name=transfer-encoding value=chunked protocol=h2
"""
    ids = _ids(modern.analyze_http2_trace(trace))
    assert {
        "h2-pseudo-after-regular-s1-initial", "h2-duplicate-pseudo-s1-initial",
        "h2-authority-host-s1", "h2-connection-fields-s1-initial",
    } <= ids


def test_h2_content_length_data_downgrade_and_capture_mismatch():
    trace = """
FRAME type=HEADERS stream=1 protocol=h2
HEADER stream=1 block=initial name=:method value=POST protocol=h2
HEADER stream=1 block=initial name=:path value=/upload protocol=h2
HEADER stream=1 block=initial name=content-length value=0 protocol=h2
FRAME type=DATA stream=1 length=5 captured=4 flags=END_STREAM protocol=h2 translated_to=h1
"""
    ids = _ids(modern.analyze_http2_trace(trace))
    assert {"h2-content-length-data-s1", "h2-data-capture-mismatch-5",
            "h2-downgrade-evidence"} <= ids


def test_h2_settings_priority_stream_parity_reset_volume_and_churn():
    trace = "\n".join([
        "FRAME type=DATA stream=0 length=0 protocol=h2",
        "FRAME type=HEADERS stream=2 protocol=h2",
        "FRAME type=PRIORITY stream=3 dependency=3 weight=0 protocol=h2",
        "FRAME type=SETTINGS stream=0 id=ENABLE_PUSH value=2 protocol=h2",
        "FRAME type=SETTINGS stream=0 id=MAX_FRAME_SIZE value=100 protocol=h2",
        "FRAME type=SETTINGS stream=0 id=MAX_FRAME_SIZE value=20000 protocol=h2",
        *(f"FRAME type=RST_STREAM stream={index * 2 + 1} error=CANCEL protocol=h2" for index in range(8)),
    ])
    ids = _ids(modern.analyze_http2_trace(trace))
    assert "h2-stream-zero-1" in ids
    assert "h2-client-even-stream-2" in ids
    assert "h2-priority-invalid-3" in ids
    assert {"h2-setting-range-4", "h2-setting-range-5", "h2-reset-volume",
            "h2-settings-churn"} <= ids


def test_h2_clean_control_has_no_findings():
    trace = """
FRAME type=HEADERS stream=1 protocol=h2
HEADER stream=1 block=initial name=:method value=POST protocol=h2
HEADER stream=1 block=initial name=:path value=/ protocol=h2
HEADER stream=1 block=initial name=:scheme value=https protocol=h2
HEADER stream=1 block=initial name=:authority value=app.test protocol=h2
HEADER stream=1 block=initial name=content-length value=3 protocol=h2
FRAME type=DATA stream=1 length=3 captured=3 flags=END_STREAM protocol=h2
FRAME type=SETTINGS stream=0 id=MAX_FRAME_SIZE value=16384 protocol=h2
"""
    assert modern.analyze_http2_trace(trace) == ()


def test_h2_response_roles_trailers_reset_settings_ack_and_priority_cycles():
    clean_response = """
HEADER stream=1 block=initial role=response name=:status value=200 protocol=h2
HEADER stream=1 block=initial role=response name=content-type value=text/plain protocol=h2
"""
    assert modern.analyze_http2_trace(clean_response, direction="server") == ()
    trace = """
HEADER stream=1 block=initial role=response name=:method value=GET protocol=h2
HEADER stream=1 block=initial role=response name=:status value=200 protocol=h2
HEADER stream=1 block=trailers role=response name=:status value=204 protocol=h2
FRAME type=RST_STREAM stream=1 protocol=h2
FRAME type=DATA stream=1 length=1 protocol=h2
FRAME type=SETTINGS stream=0 flags=ACK id=MAX_FRAME_SIZE value=16384 protocol=h2
FRAME type=PRIORITY stream=3 dependency=5 weight=10 protocol=h2
FRAME type=PRIORITY stream=5 dependency=3 weight=10 protocol=h2
"""
    ids = _ids(modern.analyze_http2_trace(trace, direction="server"))
    assert {"h2-response-pseudo-set-s1", "h2-pseudo-in-trailers-s1-trailers",
            "h2-frame-after-reset-5", "h2-settings-ack-payload-6",
            "h2-priority-cycle"} <= ids
    bad_role = "HEADER stream=1 block=initial role=response role=request name=:status value=200 protocol=h2"
    assert "h2-message-role-s1-initial" in _ids(modern.analyze_http2_trace(bad_role))


def test_h3_qpack_early_data_migration_alt_svc_and_stream_types():
    trace = """
H3_FRAME type=SETTINGS stream=0 stream_type=request protocol=h3
H3_FRAME type=SETTINGS stream=2 stream_type=control protocol=h3
H3_FRAME type=DATA stream=2 stream_type=control protocol=h3
QPACK required_insert_count=9 insert_count=2 blocked_streams=5 max_blocked_streams=1 dynamic_table_capacity=4096 max_table_capacity=128
H3_FRAME type=HEADERS stream=0 method=POST early_data=true credentials=true protocol=h3
CONNECTION event=MIGRATION old=a new=b validated=false
ALT_SVC origin=app.test authority=alt.test ma=63072000
"""
    ids = _ids(modern.analyze_http3_trace(trace))
    assert {
        "h3-settings-stream-1", "h3-request-frame-control-3", "h3-duplicate-settings",
        "h3-qpack-blocked-4", "h3-qpack-block-limit-4", "h3-qpack-capacity-4",
        "h3-early-data-replay-5", "h3-unvalidated-migration-6",
        "h3-alt-svc-authority-7", "h3-alt-svc-lifetime-7",
    } <= ids


def test_h3_header_rules_and_clean_structural_control():
    bad = """
H3_HEADER stream=0 block=initial name=host value=origin.test
H3_HEADER stream=0 block=initial name=:method value=GET
H3_HEADER stream=0 block=initial name=:path value=/
H3_HEADER stream=0 block=initial name=:authority value=edge.test
"""
    ids = _ids(modern.analyze_http3_trace(bad))
    assert {"h3-pseudo-after-regular-s0-initial", "h3-authority-host-s0"} <= ids
    clean = """
H3_HEADER stream=0 block=initial name=:method value=GET
H3_HEADER stream=0 block=initial name=:path value=/
H3_HEADER stream=0 block=initial name=:scheme value=https
H3_HEADER stream=0 block=initial name=:authority value=app.test
H3_FRAME type=SETTINGS stream=2 stream_type=control protocol=h3
QPACK required_insert_count=2 insert_count=2 blocked_streams=0 max_blocked_streams=1 dynamic_table_capacity=128 max_table_capacity=128
"""
    assert modern.analyze_http3_trace(clean) == ()


def test_variants_are_inert_stable_and_cover_h2_h3():
    rows = modern.build_modern_http_variants()
    assert rows == modern.build_modern_http_variants()
    assert [row.rank for row in rows] == list(range(1, len(rows) + 1))
    assert {row.protocol for row in rows} == {"h2", "h3"}
    assert all(row.inert and row.offline and row.network_requests == 0 for row in rows)
    assert any(modern.analyze_http2_trace(row.trace) for row in rows if row.protocol == "h2")
    assert any(modern.analyze_http3_trace(row.trace) for row in rows if row.protocol == "h3")


def test_trace_caps_and_malformed_input_fail_closed():
    with pytest.raises(modern.ModernHTTPError, match="malformed"):
        modern.parse_structural_trace("FRAME type=DATA broken")
    with pytest.raises(modern.ModernHTTPError, match="record count"):
        modern.parse_structural_trace("\n".join("FRAME" for _ in range(modern.MAX_RECORDS + 1)))
    with pytest.raises(modern.ModernHTTPError, match="marker"):
        modern.build_modern_http_variants("bad marker")


def test_modern_http_module_has_no_transport_crypto_or_execution_surface():
    tree = ast.parse((WEB / "h2_h3_evidence.py").read_text(encoding="utf-8"))
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
    assert not imports.intersection({"socket", "requests", "http.client", "urllib.request", "ssl",
                                     "subprocess", "pickle", "marshal", "hpack", "qpack", "aioquic"})
    assert not calls.intersection({"connect", "request", "send", "sendall", "urlopen", "Popen",
                                   "run", "loads", "load", "eval", "exec"})
