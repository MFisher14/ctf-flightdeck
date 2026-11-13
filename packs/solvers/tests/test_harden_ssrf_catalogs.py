"""Independent wire vectors and fail-closed probes for offline SSRF helpers.

Oracles: the Redis RESP2 specification, MySQL packet/COM_QUERY layout,
RFC 5321 DATA transparency, the FastCGI 1.0 record/name-value format, and
Python's independent URL/base64 codecs.  No test opens a socket or performs a
request; the POST-body engine is supplied only saved response dictionaries.
"""
from __future__ import annotations

import base64
import json
import random
import struct
import urllib.parse

import pytest

import ssrf_body as body
import ssrf_chains as chains


def _gopher_bytes(report):
    parsed = urllib.parse.urlsplit(report["url"])
    assert parsed.scheme == "gopher" and parsed.path.startswith("/_")
    return urllib.parse.unquote_to_bytes(parsed.path[2:])


def _fcgi_records(raw):
    """Independent FastCGI record decoder transcribed from the 1.0 spec."""
    rows, offset = [], 0
    while offset < len(raw):
        assert len(raw) - offset >= 8
        version, kind, request_id, length, padding, reserved = struct.unpack_from(
            "!BBHHBB", raw, offset)
        offset += 8
        assert version == 1 and reserved == 0
        assert len(raw) - offset >= length + padding
        content = raw[offset:offset + length]
        assert raw[offset + length:offset + length + padding] == b"\0" * padding
        rows.append((kind, request_id, content))
        offset += length + padding
    assert offset == len(raw)
    return rows


def _fcgi_length(raw, offset):
    first = raw[offset]
    if first & 0x80:
        return int.from_bytes(raw[offset:offset + 4], "big") & 0x7FFFFFFF, offset + 4
    return first, offset + 1


def _fcgi_params(raw):
    result, offset = {}, 0
    while offset < len(raw):
        name_size, offset = _fcgi_length(raw, offset)
        value_size, offset = _fcgi_length(raw, offset)
        name = raw[offset:offset + name_size].decode()
        offset += name_size
        value = raw[offset:offset + value_size].decode()
        offset += value_size
        result[name] = value
    assert offset == len(raw)
    return result


def test_resp2_binary_vector_from_redis_protocol_spec():
    # RESP2 requests are arrays of binary-safe bulk strings. Byte length, not
    # Unicode code-point count, establishes the $<length> field.
    expected = b"*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$2\r\n\xcf\x80\r\n"
    assert chains.redis_resp_command(["SET", "key", "π"]) == expected
    report = chains.build_redis_gopher("127.0.0.1", [["SET", "key", "π"]])
    assert _gopher_bytes(report) == expected
    assert base64.b64decode(report["payload_base64"], validate=True) == expected
    assert report["payload_length"] == len(expected)
    assert report["offline"] is True and report["network_requests"] == 0


def test_mysql_com_query_published_packet_layout():
    query = "SELECT 'π'".encode()
    expected_body = b"\x03" + query  # command byte COM_QUERY = 0x03
    expected = len(expected_body).to_bytes(3, "little") + b"\x7f" + expected_body
    assert chains.mysql_com_query_packet(query, sequence_id=127) == expected
    report = chains.build_mysql_gopher("db.internal", query, sequence_id=127)
    assert _gopher_bytes(report) == expected
    assert "authentication" in report["requirement"]


def test_smtp_rfc5321_data_transparency_and_line_normalization():
    transaction = chains.smtp_transaction(
        "sender@example.test", "box@example.test", b"first\r.second\n..third\r\nlast")
    expected = (
        b"EHLO ctf.local\r\nMAIL FROM:<sender@example.test>\r\n"
        b"RCPT TO:<box@example.test>\r\nDATA\r\n"
        b"first\r\n..second\r\n...third\r\nlast\r\n.\r\nQUIT\r\n"
    )
    assert transaction == expected
    report = chains.build_smtp_gopher(
        "mail.internal", "sender@example.test", "box@example.test",
        b"first\r.second\n..third\r\nlast")
    assert _gopher_bytes(report) == expected


def test_fastcgi_records_and_name_value_lengths_against_spec():
    long_value = "v" * 128  # forces the four-byte FastCGI length form
    raw = chains.fastcgi_request(
        "/srv/app.php", method="POST", query_string="a=1", stdin=b"x=7",
        extra_params={"CONTENT_TYPE": long_value})
    rows = _fcgi_records(raw)
    assert [kind for kind, _request, _content in rows] == [1, 4, 4, 5, 5]
    assert all(request == 1 for _kind, request, _content in rows)
    assert rows[0][2] == struct.pack("!HB5s", 1, 0, b"\0" * 5)
    assert rows[2][2] == b"" and rows[3][2] == b"x=7" and rows[4][2] == b""
    params = _fcgi_params(rows[1][2])
    assert params["SCRIPT_FILENAME"] == "/srv/app.php"
    assert params["REQUEST_METHOD"] == "POST"
    assert params["QUERY_STRING"] == "a=1"
    assert params["CONTENT_LENGTH"] == "3"
    assert params["CONTENT_TYPE"] == long_value
    assert _gopher_bytes(chains.build_fastcgi_gopher(
        "127.0.0.1", "/srv/app.php", method="POST", query_string="a=1",
        stdin=b"x=7", extra_params={"CONTENT_TYPE": long_value})) == raw


def test_host_and_gopher_encodings_crosscheck_stdlib():
    rows = {row["name"]: row for row in chains.host_encoding_table("169.254.169.254")}
    integer = int.from_bytes(bytes((169, 254, 169, 254)), "big")
    assert rows["single_decimal"]["value"] == str(integer)
    assert rows["single_hex"]["value"] == f"0x{integer:08x}"
    assert rows["single_octal"]["value"] == f"0{integer:o}"
    assert rows["dotted_hex"]["value"] == "0xa9.0xfe.0xa9.0xfe"
    assert rows["dotted_octal"]["value"] == "0251.0376.0251.0376"
    assert all(row["offline"] and row["network_requests"] == 0 for row in rows.values())

    payload = bytes(range(256))
    report = chains.gopher_url("::1", 70, payload)
    assert report["url"] == "gopher://[::1]:70/_" + urllib.parse.quote_from_bytes(payload, safe="")
    assert _gopher_bytes(report) == payload


def test_redirect_and_catalog_rows_are_inert_descriptors():
    redirect = chains.redirect_to_internal(
        "https://redirect.example/go?campaign=ctf", "http://127.0.0.1:8080/status",
        parameter="next", status=307)
    query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(redirect["url"]).query))
    assert query == {"campaign": "ctf", "next": "http://127.0.0.1:8080/status"}
    assert redirect["redirect_response_template"] == (
        "HTTP/1.1 307 Redirect\r\nLocation: http://127.0.0.1:8080/status\r\n"
        "Content-Length: 0\r\n\r\n")
    assert redirect["server_started"] is False and redirect["network_requests"] == 0

    schemes = chains.scheme_probe_candidates("127.0.0.1", port=8080, path="/a b")
    assert {urllib.parse.urlsplit(row["value"]).scheme for row in schemes} == {
        "file", "dict", "ftp", "gopher"}
    assert all(row["offline"] and row["network_requests"] == 0 for row in schemes)


def _response(document):
    return {"status": 200, "body": json.dumps(document).encode(), "headers": {}}


def _contract_document():
    return {
        "post_ssrf_route": "/fetch",
        "post_ssrf_field": "request.url",
        "post_ssrf_content_type": "application/json",
        "post_ssrf_method": "POST",
        "post_ssrf_internal_url": "http://127.0.0.1:8080/status",
        "description": "server side URL fetch reader",
    }


def test_saved_post_body_contract_and_payload_semantics():
    base = "https://challenge.example/"
    docs = body._preloaded_docs({"/api/clues": _response(_contract_document())}, base)
    assert docs == {"/api/clues": _contract_document()}
    contract = body._contract(docs, base)
    assert contract == {
        "route": "/fetch", "field": ("request", "url"),
        "media": "application/json", "inner": "http://127.0.0.1:8080/status",
        "source": "ssrf-keys",
    }
    payload = body._payload(contract["field"], contract["inner"], contract["media"])
    assert json.loads(payload) == {"request": {"url": "http://127.0.0.1:8080/status"}}

    form_doc = dict(_contract_document(), post_ssrf_field="url",
                    post_ssrf_content_type="application/x-www-form-urlencoded")
    form_contract = body._contract({"/api/clues": form_doc}, base)
    assert urllib.parse.parse_qs(body._payload(
        form_contract["field"], form_contract["inner"], form_contract["media"])) == {
            "url": ["http://127.0.0.1:8080/status"]}


def test_post_body_rejects_metadata_destructive_or_ambiguous_destinations():
    base = "https://challenge.example/"
    unsafe = [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://127.0.0.1/delete/users",
        "file:///etc/passwd",
        "https://public.example/status",
    ]
    for destination in unsafe:
        doc = dict(_contract_document(), post_ssrf_internal_url=destination)
        assert body._contract({"/api/clues": doc}, base) is None
    conflict = dict(_contract_document(), internal_url="http://127.0.0.1:8081/status")
    assert body._contract({"/api/clues": conflict}, base) is None


def test_post_body_zero_budget_never_constructs_a_network_client(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("network client constructed")

    monkeypatch.setattr(body, "enabled", lambda: True)
    monkeypatch.setattr(body._web, "WebClient", forbidden)
    sink = {}
    proof = body.solve(
        {"url": "https://challenge.example/", "answer_id": "offline"},
        {"max_requests": 0, "preloaded": {"/api/clues": _response(_contract_document())},
         "result_sink": sink})
    assert proof is None
    assert sink["offline"]["requests"] == 0 and sink["offline"]["posts"] == 0
    assert sink["offline"]["stopped"] == "insufficient budget for SSRF controls"


@pytest.mark.parametrize("raw", [
    b"", b"\xff" * 128, random.Random(0x55AF).randbytes(257),
    b'{"post_ssrf_route":"/fetch"',
    b'{"post_ssrf_route":"/fdtch"}',
    b"{" + b'"x":' + b'"a"' * (body.MAX_TEXT + 1) + b"}",
])
def test_saved_json_parser_fail_closed_without_requests(raw):
    result = body._json({"status": 200, "body": raw, "headers": {}}, strict=True)
    assert result is None or isinstance(result, dict)


def _chain_text_corpus():
    rng = random.Random(0x55AF)
    # Empty, valid, truncated-valid, a fixed one-character mutation, NUL,
    # non-ASCII, over-limit, and seeded printable inputs. The over-limit case
    # is only 4097 characters, so the full wrapper matrix stays cheap.
    return ["", "x", "127.0.0.1", "127.0.0.", "127.0.0.0",
            "http://127.0.0.1/a", "http://127.0.0.1/", "\0", "\uffff",
            "A" * (chains.MAX_TEXT + 1)] + [
        "".join(chr(rng.randrange(0x20, 0x7f)) for _ in range(size))
        for size in (1, 7, 31, 127)]


@pytest.mark.parametrize("value", _chain_text_corpus())
def test_chain_public_text_entrypoints_raise_only_declared_error(value):
    calls = (
        lambda: chains.host_encoding_table(value),
        lambda: chains.gopher_url(value, 80, value),
        lambda: chains.redis_resp_command([value]),
        lambda: chains.build_redis_gopher(value, [[value]]),
        lambda: chains.mysql_com_query_packet(value),
        lambda: chains.build_mysql_gopher(value, value),
        lambda: chains.smtp_transaction(value, "box@example.test", value),
        lambda: chains.build_smtp_gopher(
            value, "sender@example.test", "box@example.test", value),
        lambda: chains.fastcgi_request(value, query_string=value),
        lambda: chains.build_fastcgi_gopher(value, value, query_string=value),
        lambda: chains.scheme_probe_candidates(value, path=value),
        lambda: chains.url_parser_confusion_candidates(value),
        lambda: chains.redirect_to_internal(value, "http://127.0.0.1/status"),
    )
    for call in calls:
        try:
            call()
        except chains.SSRFInputError:
            pass


def test_chain_oversized_binary_and_cli_fail_closed(capsys):
    with pytest.raises(chains.SSRFInputError):
        chains.gopher_url("127.0.0.1", 80, b"x" * (chains.MAX_PAYLOAD + 1))
    with pytest.raises(chains.SSRFInputError):
        chains.redis_resp_command([b"x" * (64 * 1024 + 1)])
    assert chains.main([]) == 2
    assert "ssrf_chains:" in capsys.readouterr().err
    assert chains.main(["mysql", "127.0.0.1", "--query", "SELECT 1", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["network_requests"] == 0


@pytest.mark.parametrize("value", [None, 7])
def test_bug_redis_noniterable_uses_declared_error(value):
    with pytest.raises(chains.SSRFInputError):
        chains.redis_resp_command(value)


@pytest.mark.parametrize("value", [None, 7, b"PING"])
def test_bug_redis_builder_malformed_iterable_uses_declared_error(value):
    with pytest.raises(chains.SSRFInputError):
        chains.build_redis_gopher("127.0.0.1", value)


@pytest.mark.parametrize("call", [
    lambda: chains.mysql_com_query_packet("\ud800"),
    lambda: chains.fastcgi_request("\ud800"),
])
def test_bug_surrogate_payload_uses_declared_error(call):
    with pytest.raises(chains.SSRFInputError):
        call()


@pytest.mark.parametrize("ctx", [1, "bad", b"bad"])
def test_bug_solve_malformed_context_never_raises(ctx):
    assert body.solve({"url": "https://challenge.example/"}, ctx) is None


def test_bug_solve_targets_noniterable_never_raises():
    assert body.solve_targets(7, {"max_requests": 0}) == {}
