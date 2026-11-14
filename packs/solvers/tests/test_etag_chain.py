"""Synthetic, offline tests for solvers/web/etag_chain.py."""

import json
import subprocess
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "web"))

import etag_chain as ec  # noqa: E402


RAW = (b"HTTP/1.1 200 OK\r\n"
       b"Content-Type: application/json\r\n"
       b"ETag: W/\"rev-7\"\r\n"
       b"Last-Modified: Wed, 21 Oct 2015 07:28:00 GMT\r\n"
       b"X-Repeat: one\r\nX-Repeat: two\r\n\r\n"
       b'{"id":7}')


def test_parse_saved_response_preserves_body_and_validators():
    snap = ec.parse_saved_response(RAW)
    assert snap["status"] == 200
    assert snap["reason"] == "OK"
    assert snap["headers"]["etag"] == 'W/"rev-7"'
    assert snap["header_values"]["x-repeat"] == ["one", "two"]
    assert snap["body"] == b'{"id":7}'
    assert snap["body_length"] == 8
    vals = ec.extract_validators(snap)
    assert vals == {"etag": 'W/"rev-7"',
                    "last_modified": "Wed, 21 Oct 2015 07:28:00 GMT",
                    "warnings": []}


def test_get_sequence_orders_control_etag_date_and_combined():
    plan = ec.build_replay_sequence(RAW, path="/api/items/7", methods=("GET",))
    assert plan["offline"] is True and plan["sent"] is False
    rows = plan["requests"]
    assert [x["condition"] for x in rows] == [
        "baseline", "if_none_match", "if_modified_since", "combined"
    ]
    assert rows[1]["headers"] == {"If-None-Match": 'W/"rev-7"'}
    assert rows[2]["headers"] == {"If-Modified-Since": "Wed, 21 Oct 2015 07:28:00 GMT"}
    assert set(rows[3]["headers"]) == {"If-None-Match", "If-Modified-Since"}
    assert all(row["sent"] is False and row["body"] is None for row in rows)


def test_rest_method_descriptors_are_bodyless_and_explicit():
    plan = ec.build_replay_sequence(RAW, path="/v1/object", methods="HEAD,PUT")
    put = [row for row in plan["requests"] if row["method"] == "PUT"]
    assert put
    assert all(row["body_required"] and row["body"] is None for row in put)
    assert any(row["headers"] == {"If-None-Match": "*"} for row in put)
    assert "Content-Length: <PLAYER_SUPPLIED>" in ec.render_request(put[0])
    assert all("412 Precondition Failed" in row["expected"]
               for row in put if row["condition"] in ("if_none_match", "combined", "if_none_match_star"))


def test_missing_or_malformed_validators_refuse_to_invent_values():
    no_validator = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    with pytest.raises(ValueError, match="neither ETag nor Last-Modified"):
        ec.build_replay_sequence(no_validator)
    malformed = ec.parse_saved_response(
        b"HTTP/1.1 200 OK\r\nETag: unquoted\r\nLast-Modified: yesterday\r\n\r\n"
    )
    vals = ec.extract_validators(malformed)
    assert vals["etag"] is None and vals["last_modified"] is None
    assert len(vals["warnings"]) == 2
    with pytest.raises(ValueError, match="cannot build"):
        ec.build_replay_sequence(malformed)


def test_duplicate_validators_are_ambiguous_and_etag_opaque_grammar_is_exact():
    duplicated = ec.parse_saved_response(
        b'HTTP/1.1 200 OK\r\nETag: "first"\r\nETag: "second"\r\n\r\n'
    )
    values = ec.extract_validators(duplicated)
    assert values["etag"] is None
    assert any("multiple ETag" in warning for warning in values["warnings"])
    with pytest.raises(ValueError, match="cannot build"):
        ec.build_replay_sequence(duplicated)

    literal_backslash = ec.parse_saved_response(
        b'HTTP/1.1 200 OK\r\nETag: "ends-in-backslash\\"\r\n\r\n'
    )
    assert ec.extract_validators(literal_backslash)["etag"] == '"ends-in-backslash\\"'
    escaped_quote = ec.parse_saved_response(
        b'HTTP/1.1 200 OK\r\nETag: "not\\"an-escape"\r\n\r\n'
    )
    assert ec.extract_validators(escaped_quote)["etag"] is None


def test_parser_and_request_header_injection_guards():
    with pytest.raises(ValueError, match="status line"):
        ec.parse_saved_response(b"ETag: \"x\"\r\n\r\n")
    with pytest.raises(ValueError, match="folded"):
        ec.parse_saved_response(b"HTTP/1.1 200 OK\r\nETag: \"x\"\r\n injected\r\n\r\n")
    with pytest.raises(ValueError, match="relative-origin"):
        ec.build_replay_sequence(RAW, path="https://off-target.example/x")
    plan = ec.build_replay_sequence(RAW)
    with pytest.raises(ValueError):
        ec.render_request(plan["requests"][0], "bad\r\nInjected: yes")
    for unsafe_path in ("/has space", "/tab\there", "/nul\x00here", "/fragment#part"):
        with pytest.raises(ValueError):
            ec.build_replay_sequence(RAW, path=unsafe_path)
    malicious = dict(plan["requests"][0], headers={"X-Good": "ok\r\nInjected: yes"})
    with pytest.raises(ValueError, match="control byte"):
        ec.render_request(malicious)


def test_cli_json_reads_only_saved_fixture(tmp_path):
    fixture = tmp_path / "response.txt"
    fixture.write_bytes(RAW)
    proc = subprocess.run(
        [sys.executable, str(REPO / "solvers" / "web" / "etag_chain.py"), str(fixture),
         "--path", "/api/items/7", "--methods", "GET,PUT", "--json"],
        check=True, capture_output=True, text=True,
    )
    doc = json.loads(proc.stdout)
    assert doc["offline"] is True and doc["sent"] is False
    assert any(row["method"] == "PUT" for row in doc["requests"])
    assert all("ASSIGNED_TARGET" in row["raw"] for row in doc["requests"])
