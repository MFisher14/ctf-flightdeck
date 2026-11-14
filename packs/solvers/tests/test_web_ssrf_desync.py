#!/usr/bin/env python3
"""Synthetic, transport-free tests for SSRF/desync payload generators."""

from __future__ import annotations

import ast
import base64
import importlib.util
import json
import struct
import sys
import urllib.parse
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "web"))
import http_desync as hd  # noqa: E402
import ssrf_chains as ssrf  # noqa: E402


def gopher_payload(result: dict) -> bytes:
    path = urllib.parse.urlsplit(result["url"]).path
    assert path.startswith("/_")
    return urllib.parse.unquote_to_bytes(path[2:])


def test_redis_resp_and_gopher_are_byte_exact_and_offline():
    result = ssrf.build_redis_gopher(
        "127.0.0.1", [["SET", "marker", "hello world"], [b"GET", b"marker"]]
    )
    expected = (b"*3\r\n$3\r\nSET\r\n$6\r\nmarker\r\n$11\r\nhello world\r\n"
                b"*2\r\n$3\r\nGET\r\n$6\r\nmarker\r\n")
    assert gopher_payload(result) == expected
    assert base64.b64decode(result["payload_base64"]) == expected
    assert result["command_count"] == 2
    assert result["network_requests"] == 0 and result["offline"] is True


def test_mysql_packet_has_little_endian_length_and_explicit_post_auth_scope():
    packet = ssrf.mysql_com_query_packet("SELECT 7", sequence_id=3)
    assert int.from_bytes(packet[:3], "little") == len(packet) - 4
    assert packet[3] == 3 and packet[4] == 3 and packet[5:] == b"SELECT 7"
    result = ssrf.build_mysql_gopher("db.internal", "SELECT 7", sequence_id=3)
    assert gopher_payload(result) == packet
    assert "already authenticated" in result["requirement"]


def test_smtp_normalizes_lines_dot_stuffs_and_rejects_header_injection():
    raw = ssrf.smtp_transaction(
        "sender@example.test", "box@example.test", "Subject: marker\n\n.line\nend"
    )
    assert raw.startswith(b"EHLO ctf.local\r\nMAIL FROM:<sender@example.test>\r\n")
    assert b"\r\n..line\r\n" in raw
    assert raw.endswith(b"\r\n.\r\nQUIT\r\n")
    with pytest.raises(ssrf.SSRFInputError, match="without CR/LF"):
        ssrf.smtp_transaction("a@b.test\r\nRCPT TO:<x@y.test>", "x@y.test", "x")


def _fastcgi_records(raw: bytes):
    records = []
    offset = 0
    while offset < len(raw):
        version, kind, request_id, size, padding, reserved = struct.unpack(
            "!BBHHBB", raw[offset:offset + 8]
        )
        assert version == 1 and reserved == 0 and request_id == 1
        content = raw[offset + 8:offset + 8 + size]
        records.append((kind, content))
        offset += 8 + size + padding
    assert offset == len(raw)
    return records


def test_fastcgi_records_params_and_stdin_are_well_formed():
    raw = ssrf.fastcgi_request(
        "/var/www/html/index.php", method="POST", query_string="a=7", stdin="x=marker",
        extra_params={"CONTENT_TYPE": "application/x-www-form-urlencoded"},
    )
    records = _fastcgi_records(raw)
    assert [kind for kind, _ in records] == [1, 4, 4, 5, 5]
    assert records[2][1] == b"" and records[3][1] == b"x=marker" and records[4][1] == b""
    params = records[1][1]
    assert b"SCRIPT_FILENAME" in params and b"/var/www/html/index.php" in params
    assert b"CONTENT_LENGTH" in params and b"8" in params
    result = ssrf.build_fastcgi_gopher("[::1]", "/index.php")
    assert result["url"].startswith("gopher://[::1]:9000/_")
    assert gopher_payload(result) == ssrf.fastcgi_request("/index.php")


def test_host_encodings_probes_confusion_and_redirect_are_ranked_metadata():
    table = ssrf.host_encoding_table("127.0.0.1")
    values = {row["name"]: row["value"] for row in table}
    assert values["single_decimal"] == "2130706433"
    assert values["single_hex"] == "0x7f000001"
    assert values["ipv6_mapped"] == "[::ffff:127.0.0.1]"
    assert values["unspecified"] == "0.0.0.0"
    assert all(row["rank"] == index and row["network_requests"] == 0
               for index, row in enumerate(table, 1))
    assert [row["name"] for row in ssrf.host_encoding_table("internal.example")] == [
        "canonical", "trailing_dot",
    ]

    probes = ssrf.scheme_probe_candidates("127.0.0.1", path="admin marker")
    assert {urllib.parse.urlsplit(row["value"]).scheme for row in probes} == {
        "file", "dict", "ftp", "gopher",
    }
    confusion = ssrf.url_parser_confusion_candidates(
        "http://127.0.0.1/admin?a=1", public_url="https://allowed.example/start"
    )
    assert {"userinfo_at", "crlf_authority", "double_encoded_at"} <= {
        row["name"] for row in confusion
    }
    assert all(row["offline"] and row["network_requests"] == 0 for row in confusion)

    redirect = ssrf.redirect_to_internal(
        "https://redirect.example/go?campaign=ctf", "http://127.0.0.1/admin", parameter="next"
    )
    query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(redirect["url"]).query))
    assert query == {"campaign": "ctf", "next": "http://127.0.0.1/admin"}
    assert redirect["server_started"] is False


def test_ssrf_bounds_generators_and_cli_fail_closed(capsys):
    def endless_commands():
        while True:
            yield ["PING"]

    with pytest.raises(ssrf.SSRFInputError, match="count exceeds"):
        ssrf.build_redis_gopher("127.0.0.1", endless_commands())
    with pytest.raises(ssrf.SSRFInputError, match="port must be between"):
        ssrf.gopher_url("127.0.0.1", 0, b"x")
    with pytest.raises(ssrf.SSRFInputError, match="parameter name"):
        ssrf.fastcgi_request("/index.php", extra_params={"bad-name": "x"})
    assert ssrf.main(["mysql", "127.0.0.1", "--query", "SELECT 1", "--port", "0"]) == 2
    assert capsys.readouterr().err.startswith("ssrf_chains: ")
    assert ssrf.main(["host", "127.0.0.1", "--json"]) == 0
    assert isinstance(json.loads(capsys.readouterr().out), list)


def _split_http(raw: bytes) -> tuple[bytes, bytes]:
    head, body = raw.split(b"\r\n\r\n", 1)
    return head, body


def _content_length(head: bytes) -> int:
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            return int(line.split(b":", 1)[1].strip())
    raise AssertionError("missing Content-Length")


def test_desync_families_have_consistent_wire_encodings_and_boundaries():
    rows = hd.generate_desync_candidates("app.internal", marker="ROUND2")
    assert {row["technique"] for row in rows} == {
        "CL.TE", "TE.CL", "TE.TE", "CL.0", "H2.CL", "H2.TE",
    }
    assert [row["rank"] for row in rows] == list(range(1, len(rows) + 1))
    for row in rows:
        raw = base64.b64decode(row["request_base64"])
        assert raw.decode("latin-1") == row["request"]
        assert len(raw) == row["wire_length"]
        assert row["candidate_only"] and row["network_requests"] == 0

    clte = next(row for row in rows if row["technique"] == "CL.TE")
    head, body = _split_http(base64.b64decode(clte["request_base64"]))
    assert _content_length(head) == len(body)
    assert body.startswith(b"0\r\n\r\nGET /__csctf_desync_marker__")

    tecl = next(row for row in rows if row["technique"] == "TE.CL")
    head, body = _split_http(base64.b64decode(tecl["request_base64"]))
    prefix_length = _content_length(head)
    assert body[:prefix_length].endswith(b"\r\n")
    assert body[prefix_length:].startswith(b"GET /__csctf_desync_marker__")


def test_te_catalog_cache_candidates_and_request_validation():
    variants = hd.transfer_encoding_variants()
    assert len(variants) <= hd.MAX_CANDIDATES
    assert {row["name"] for row in variants} >= {
        "canonical", "name_space", "duplicate_identity_first", "mixed_case",
    }
    assert all(row["network_requests"] == 0 for row in variants)

    cache = hd.cache_candidates("app.internal", path="/account", marker_host="marker.invalid")
    assert {row["name"] for row in cache["poisoning"]} >= {
        "x_forwarded_host", "x_original_url", "absolute_form",
    }
    assert {row["name"] for row in cache["deception"]} >= {
        "path_info_css", "semicolon_css", "encoded_question",
    }
    assert all(row["path"].startswith("/account") for row in cache["deception"])

    with pytest.raises(hd.DesyncInputError, match="CR, LF"):
        hd.generate_desync_candidates("good.test\r\nHost: bad.test")
    with pytest.raises(hd.DesyncInputError, match="must start"):
        hd.generate_desync_candidates("good.test", path="absolute")
    with pytest.raises(hd.DesyncInputError, match="header count"):
        hd.build_http1_request("GET", "/", "good.test", [("X-A", "x")] * 65)


def test_desync_cli_json_and_errors_have_no_traceback(capsys):
    assert hd.main(["desync", "app.internal", "--technique", "h2", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert {row["technique"] for row in result} == {"H2.CL", "H2.TE"}
    assert hd.main(["cache", "bad host"]) == 2
    captured = capsys.readouterr()
    assert captured.err.startswith("http_desync: ") and "Traceback" not in captured.err


def test_modules_import_no_network_clients_and_define_no_submission_path():
    for path in (REPO / "solvers/web/ssrf_chains.py", REPO / "solvers/web/http_desync.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports = set()
        calls = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                calls.add(node.func.attr)
        assert not imports.intersection({"requests", "socket", "http.client", "urllib.request"})
        assert not calls.intersection({"urlopen", "connect", "send", "sendall", "submit"})
