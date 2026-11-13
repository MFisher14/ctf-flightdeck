#!/usr/bin/env python3
"""Offline tests for session_replay (B-046): HTTP session-theft + HMAC-replay.

Every capture is built synthetically inside the test (never a real challenge file): the keys, session
ids, timestamps and command bodies below are made up here and match no challenge.  Every signature is
checked against an independent stdlib HMAC computation, and no fixture opens a socket.  The machine
runs under heavy load, so nothing here asserts a wall-clock bound -- correctness only.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import json
import struct
import sys
import zlib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "solvers" / "web"))
import session_replay as sr  # noqa: E402


# --------------------------------------------------------------------------- synthetic capture helpers
# The scheme shape of the csctf 9112 class: HMAC-SHA256(key=hex-decoded, "METHOD\npath\nts\nbody").
# All values are synthetic: the key is a hash of a fixed made-up label, never a recovered key.
HEX_KEY = hashlib.sha256(b"B-046 synthetic test key; not from any challenge").hexdigest()
ADMIN_SESSION = "adm-test-0001"
TS1, TS2, TS3 = "1700000100", "1700000200", "1700000300"
FRESH_TS = "1700009999"
FRESH_BODY = '{"cmd":"NOOP","arg":"Z9"}'


def newline_sig(key_hex, method, path, ts, body, *, digest=hashlib.sha256):
    msg = f"{method}\n{path}\n{ts}\n{body}".encode()
    return hmac.new(bytes.fromhex(key_hex), msg, digest).hexdigest()


def login_response(session, key, role, *, encoding="gzip", key_field="key"):
    body = json.dumps({"session": session, key_field: key, "role": role}).encode()
    headers = []
    if encoding == "gzip":
        body = gzip.compress(body)
        headers.append(b"Content-Encoding: gzip")
    elif encoding == "deflate-zlib":
        body = zlib.compress(body)
        headers.append(b"Content-Encoding: deflate")
    elif encoding == "deflate-raw":
        c = zlib.compressobj(wbits=-15)
        body = c.compress(body) + c.flush()
        headers.append(b"Content-Encoding: deflate")
    headers.append(f"Content-Length: {len(body)}".encode())
    head = b"\r\n".join([b"HTTP/1.1 200 OK", *headers]) + b"\r\n\r\n"
    return head + body


def signed_command(session, key_hex, ts, body, *, method="POST", path="/api/command", sig=None,
                   query=""):
    if sig is None:
        sig = newline_sig(key_hex, method, path, ts, body)
    b = body.encode()
    target = f"{path}?{query}" if query else path
    head = b"\r\n".join([
        f"{method} {target} HTTP/1.1".encode(),
        b"Host: 192.0.2.20:8080",
        f"X-Session: {session}".encode(),
        f"X-Timestamp: {ts}".encode(),
        f"X-Signature: {sig}".encode(),
        f"Content-Length: {len(b)}".encode(),
    ]) + b"\r\n\r\n" + b
    return head


LOGIN_REQUEST = b"POST /api/login HTTP/1.1\r\nHost: 192.0.2.20:8080\r\nContent-Length: 2\r\n\r\n{}"
COMMANDS = [(TS1, '{"cmd":"PING"}'), (TS2, '{"cmd":"SET_MODE","unit":"U1"}'),
            (TS3, '{"cmd":"REPORT"}')]


def text_capture(*, encoding="gzip"):
    parts = [LOGIN_REQUEST, login_response(ADMIN_SESSION, HEX_KEY, "administrator", encoding=encoding)]
    parts += [signed_command(ADMIN_SESSION, HEX_KEY, ts, body) for ts, body in COMMANDS]
    return b"".join(parts)


def custom_capture(sign, requests, *, key=HEX_KEY, session=ADMIN_SESSION):
    """A capture whose signatures come from ``sign(req_dict) -> hex``; requests are dicts."""
    cap = login_response(session, key, "administrator")
    for r in requests:
        cap += signed_command(session, key, r["ts"], r["body"], method=r.get("method", "POST"),
                              path=r.get("path", "/api/command"), query=r.get("query", ""),
                              sig=sign(r))
    return cap


# ------------------------------------------------------------------------------ synthetic pcap helpers
CLIENT, SERVER = "192.0.2.10", "198.51.100.20"


def _checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ip4(src, dst, payload, ident):
    header = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0x4000, 64, 6,
                                   0, bytes(map(int, src.split("."))), bytes(map(int, dst.split(".")))))
    struct.pack_into("!H", header, 10, _checksum(bytes(header)))
    return bytes(header) + payload


def _frame(src, dst, sport, dport, seq, flags, payload=b"", ident=1):
    # TCP checksum 0 = offloaded/not captured (accepted by the strict reader).
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 0x50, flags, 65535, 0, 0) + payload
    return b"\x02\x00\x00\x00\x00\x20\x02\x00\x00\x00\x00\x10\x08\x00" + _ip4(src, dst, tcp, ident)


def _pcap(frames):
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for i, f in enumerate(frames):
        out += struct.pack("<IIII", 1_700_000_000 + i, 0, len(f), len(f)) + f
    return bytes(out)


def _ng_block(block_type, body):
    length = 12 + len(body)
    return struct.pack("<II", block_type, length) + body + struct.pack("<I", length)


def _pcapng(frames):
    out = _ng_block(0x0A0D0D0A, b"\x4d\x3c\x2b\x1a" + struct.pack("<HHq", 1, 0, -1))
    out += _ng_block(1, struct.pack("<HHI", 1, 0, 65535))
    for i, f in enumerate(frames):
        out += _ng_block(6, struct.pack("<IIIII", 0, 0, i + 1, len(f), len(f)) + f + b"\x00" * ((-len(f)) & 3))
    return out


def tcp_frames(client_msgs, server_msgs, *, cport=40000, sport=8080):
    """SYN / SYN-ACK, then each message as one segment in its own direction (ordered by seq)."""
    cseq, sseq, ident = 1000, 9000, 1
    frames = [_frame(CLIENT, SERVER, cport, sport, cseq, 0x02, ident=1),
              _frame(SERVER, CLIENT, sport, cport, sseq, 0x12, ident=2)]
    cpos, spos, ident = cseq + 1, sseq + 1, 3
    for i in range(max(len(client_msgs), len(server_msgs))):
        if i < len(client_msgs):
            frames.append(_frame(CLIENT, SERVER, cport, sport, cpos, 0x18, client_msgs[i], ident))
            cpos += len(client_msgs[i])
            ident += 1
        if i < len(server_msgs):
            frames.append(_frame(SERVER, CLIENT, sport, cport, spos, 0x18, server_msgs[i], ident))
            spos += len(server_msgs[i])
            ident += 1
    return frames


def capture_frames():
    client = [LOGIN_REQUEST] + [signed_command(ADMIN_SESSION, HEX_KEY, ts, body) for ts, body in COMMANDS]
    server = [login_response(ADMIN_SESSION, HEX_KEY, "administrator")]
    return tcp_frames(client, server)


# ----------------------------------------------------------------------------------- capture parsing
def test_parse_capture_splits_messages_and_frames_bodies():
    msgs = sr.parse_http_capture(text_capture())
    kinds = [m.kind for m in msgs]
    assert kinds == ["request", "response", "request", "request", "request"]
    # The signed request bodies are framed by Content-Length, not merged with the next message.
    cmd = msgs[3]
    assert cmd.method == "POST" and cmd.path == "/api/command"
    assert cmd.body == b'{"cmd":"SET_MODE","unit":"U1"}'
    assert cmd.header("X-Timestamp") == TS2


def test_parse_capture_handles_chunked_response():
    payload = b'{"session":"s1","key":"' + HEX_KEY.encode() + b'","role":"administrator"}'
    chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
    chunked += f"{len(payload):x}\r\n".encode() + payload + b"\r\n0\r\n\r\n"
    # a following request must still parse: the dechunker must stop at the 0-chunk.
    cap = chunked + b"GET /next HTTP/1.1\r\nHost: h\r\n\r\n"
    msgs = sr.parse_http_capture(cap)
    assert [m.kind for m in msgs] == ["response", "request"]
    assert msgs[0].body == payload
    assert msgs[1].path == "/next"


def test_unframed_response_does_not_swallow_next_message():
    # a response with neither Content-Length nor chunked must take no body.
    cap = (b"HTTP/1.1 500 Err\r\nConnection: close\r\n\r\n"
           b"POST /api/command HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\n{}")
    msgs = sr.parse_http_capture(cap)
    assert [m.kind for m in msgs] == ["response", "request"]
    assert msgs[1].path == "/api/command"


# --------------------------------------------------------------------- bad input fails loudly, named
def test_pcap_bytes_given_to_the_text_parser_are_named_not_parsed_as_empty():
    blob = _pcap(capture_frames())
    with pytest.raises(sr.ReplayError, match="pcap"):
        sr.parse_http_capture(blob)


def test_non_http_input_raises_instead_of_returning_no_messages():
    with pytest.raises(sr.ReplayError, match="not an HTTP start-line at byte 0"):
        sr.parse_http_capture(b"this is not http at all\r\n\r\nmore")


def test_garbage_after_a_valid_message_raises_with_its_offset():
    first = b"GET /a HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n"
    with pytest.raises(sr.ReplayError, match=f"at byte {len(first)}"):
        sr.parse_http_capture(first + b"\x00\x01garbage\r\n\r\n")


def test_invalid_content_length_raises():
    cap = b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: ten\r\n\r\n0123456789"
    with pytest.raises(sr.ReplayError, match="invalid Content-Length"):
        sr.parse_http_capture(cap)


def test_oversized_content_length_raises():
    cap = f"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: {sr.MAX_BODY + 1}\r\n\r\n{{}}".encode()
    with pytest.raises(sr.ReplayError, match="body limit"):
        sr.parse_http_capture(cap)


def test_truncated_body_raises():
    cap = b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 50\r\n\r\n{}"
    with pytest.raises(sr.ReplayError, match="truncated body"):
        sr.parse_http_capture(cap)


def test_truncated_chunked_body_raises():
    cap = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n20\r\nshort"
    with pytest.raises(sr.ReplayError, match="chunked"):
        sr.parse_http_capture(cap)


def test_corrupt_gzip_body_raises_not_returned_raw():
    cap = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 8\r\n\r\nnotgzip!"
    msgs = sr.parse_http_capture(cap)
    with pytest.raises(sr.ReplayError, match="corrupt gzip"):
        msgs[0].decoded_body()


def test_cli_inspect_names_the_reason_for_non_http_input(tmp_path, capsys):
    cap = tmp_path / "capture.bin"
    cap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 40)   # pcap magic, not a valid capture
    rc = sr.main(["inspect", str(cap)])
    err = capsys.readouterr().err
    assert rc == 1
    assert "pcap could not be strictly reassembled" in err


# --------------------------------------------------------------------------------- pcap / pcapng input
@pytest.mark.parametrize("container", [_pcap, _pcapng])
def test_pcap_capture_is_reassembled_and_solved_end_to_end(container):
    rec = sr.recover(container(capture_frames()))
    assert len(rec.material) == 1 and rec.material[0]["key"] == HEX_KEY
    assert [r.timestamp for r in rec.signed_requests] == [TS1, TS2, TS3]
    assert len(rec.pairs) == 3
    assert len(rec.templates) == 1
    tmpl = rec.templates[0]
    assert (tmpl.fields, tmpl.separator, tmpl.key_form) == (
        ("method", "target", "timestamp", "body"), "\n", "hex")


def test_pcap_messages_match_the_text_parser():
    from_pcap = sr.load_capture(_pcap(capture_frames()))
    from_text = sr.parse_http_capture(text_capture())
    def view(ms):
        return sorted((m.kind, m.method, m.path, m.body, m.header("x-signature")) for m in ms)
    assert view(from_pcap) == view(from_text)


def test_pcap_without_any_http_stream_raises():
    frames = tcp_frames([b"\x16\x03\x01binary-not-http"], [], sport=5555)
    with pytest.raises(sr.ReplayError, match="none is HTTP"):
        sr.load_capture(_pcap(frames))


def test_pcap_http_stream_that_does_not_decode_raises():
    bad = b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 99\r\n\r\n{}"   # declared body absent
    with pytest.raises(sr.ReplayError, match="does not decode"):
        sr.load_capture(_pcap(tcp_frames([bad], [])))


def test_cli_solve_accepts_a_pcap(tmp_path, capsys):
    cap = tmp_path / "capture.pcap"
    cap.write_bytes(_pcap(capture_frames()))
    rc = sr.main(["solve", str(cap), "--command-body", FRESH_BODY, "--timestamp", FRESH_TS])
    out = capsys.readouterr().out
    assert rc == 0
    assert newline_sig(HEX_KEY, "POST", "/api/command", FRESH_TS, FRESH_BODY) in out
    assert HEX_KEY not in out


# ------------------------------------------------------------------------------- session material pull
def test_extracts_key_from_gzip_login_body():
    msgs = sr.parse_http_capture(text_capture(encoding="gzip"))
    material = sr.extract_session_material(msgs)
    assert len(material) == 1
    assert material[0]["session"] == ADMIN_SESSION
    assert material[0]["key"] == HEX_KEY
    assert material[0]["role"] == "administrator"


def test_extracts_key_from_cleartext_login_body():
    msgs = sr.parse_http_capture(text_capture(encoding=None))
    material = sr.extract_session_material(msgs)
    assert material and material[0]["key"] == HEX_KEY


@pytest.mark.parametrize("encoding", ["deflate-zlib", "deflate-raw"])
def test_extracts_key_from_deflate_login_body(encoding):
    msgs = sr.parse_http_capture(text_capture(encoding=encoding))
    assert msgs[1].header("Content-Encoding") == "deflate"
    material = sr.extract_session_material(msgs)
    assert len(material) == 1 and material[0]["key"] == HEX_KEY


def test_decoded_body_is_gzip_transparent():
    msgs = sr.parse_http_capture(text_capture(encoding="gzip"))
    resp = msgs[1]
    assert resp.header("Content-Encoding") == "gzip"
    assert b'"key"' in resp.decoded_body() and resp.decoded_body() != resp.body


def test_repeated_login_body_is_deduplicated():
    one = login_response(ADMIN_SESSION, HEX_KEY, "administrator")
    msgs = sr.parse_http_capture(one + one + one)
    assert len(msgs) == 3
    material = sr.extract_session_material(msgs)
    assert len(material) == 1


# ------------------------------------------------------------------------------- template inference
def test_infers_the_newline_signing_template():
    rec = sr.recover(text_capture())
    assert len(rec.pairs) == 3
    assert len(rec.templates) == 1, [t.describe() for t in rec.templates]
    tmpl = rec.templates[0]
    assert tmpl.fields == ("method", "target", "timestamp", "body")
    assert tmpl.separator == "\n"
    assert tmpl.digest == "sha256"
    assert tmpl.key_form == "hex"
    assert tmpl.body_form == "raw"
    assert tmpl.target_form == "path"


def test_inferred_template_reproduces_every_captured_signature():
    rec = sr.recover(text_capture())
    tmpl = rec.templates[0]
    for req, key in rec.pairs:
        # independent gold-standard HMAC, computed here, must equal the template's signature.
        gold = newline_sig(key, req.method, req.path, req.timestamp, req.body.decode())
        assert tmpl.sign(key, req) == gold == req.signature


def test_a_template_must_fit_every_signature_not_just_the_first():
    # Request 1 has an empty body, so with the '' separator "method target ts body" and
    # "method target ts" give the SAME signing string for it.  Request 2 has a body and rules the
    # body-less template out.  Checking only the first request would keep both.
    def sign(r):
        msg = (r.get("method", "POST") + "/api/command" + r["ts"] + r["body"]).encode()
        return hmac.new(bytes.fromhex(HEX_KEY), msg, hashlib.sha256).hexdigest()

    reqs = [{"ts": "100", "body": ""}, {"ts": "200", "body": '{"cmd":"A"}'}]
    rec = sr.recover(custom_capture(sign, reqs))
    first_only = sr.infer_template(rec.pairs[:1])
    assert any("body" not in t.fields for t in first_only), "precondition: request 1 is ambiguous"
    assert len(rec.templates) == 1, [t.describe() for t in rec.templates]
    assert rec.templates[0].fields == ("method", "target", "timestamp", "body")
    assert rec.templates[0].separator == ""


def test_infers_query_string_in_the_signed_target():
    def sign(r):
        msg = f"POST\n/api/command?{r['query']}\n{r['ts']}\n{r['body']}".encode()
        return hmac.new(bytes.fromhex(HEX_KEY), msg, hashlib.sha256).hexdigest()

    reqs = [{"ts": "100", "body": '{"cmd":"A"}', "query": "unit=1"},
            {"ts": "200", "body": '{"cmd":"BB"}', "query": "unit=2&v=x"}]
    rec = sr.recover(custom_capture(sign, reqs))
    assert len(rec.templates) == 1, [t.describe() for t in rec.templates]
    assert rec.templates[0].target_form == "path_query"
    signed = sr.sign_command(rec.templates[0], HEX_KEY, method="POST", path="/api/command",
                             query="unit=3", body='{"cmd":"C"}', timestamp="300")
    gold = hmac.new(bytes.fromhex(HEX_KEY), b'POST\n/api/command?unit=3\n300\n{"cmd":"C"}',
                    hashlib.sha256).hexdigest()
    assert signed.headers["X-Signature"] == gold
    assert signed.target == "/api/command?unit=3"


def test_infers_compact_json_body_when_the_wire_body_is_re_spaced():
    def sign(r):
        compact = json.dumps(json.loads(r["body"]), separators=(",", ":"))
        msg = f"POST\n/api/command\n{r['ts']}\n{compact}".encode()
        return hmac.new(bytes.fromhex(HEX_KEY), msg, hashlib.sha256).hexdigest()

    reqs = [{"ts": "100", "body": '{"cmd": "A", "n": 1}'},
            {"ts": "200", "body": '{ "cmd" : "BB" }'}]
    rec = sr.recover(custom_capture(sign, reqs))
    assert len(rec.templates) == 1, [t.describe() for t in rec.templates]
    assert rec.templates[0].body_form == "compact_json"


def test_infers_a_base64_key():
    raw_key = hashlib.sha256(b"B-046 synthetic base64 key").digest()
    b64_key = base64.b64encode(raw_key).decode()
    assert any(c not in "0123456789abcdefABCDEF" for c in b64_key)   # not also valid hex

    def sign(r):
        msg = f"POST\n/api/command\n{r['ts']}\n{r['body']}".encode()
        return hmac.new(raw_key, msg, hashlib.sha256).hexdigest()

    reqs = [{"ts": "100", "body": '{"cmd":"A"}'}, {"ts": "200", "body": '{"cmd":"BB"}'}]
    rec = sr.recover(custom_capture(sign, reqs, key=b64_key))
    assert len(rec.templates) == 1, [t.describe() for t in rec.templates]
    assert rec.templates[0].key_form == "base64"


def test_infers_the_session_id_as_a_signed_field():
    def sign(r):
        msg = f"POST\n/api/command\n{ADMIN_SESSION}\n{r['ts']}\n{r['body']}".encode()
        return hmac.new(bytes.fromhex(HEX_KEY), msg, hashlib.sha256).hexdigest()

    reqs = [{"ts": "100", "body": '{"cmd":"A"}'}, {"ts": "200", "body": '{"cmd":"BB"}'}]
    rec = sr.recover(custom_capture(sign, reqs))
    assert len(rec.templates) == 1, [t.describe() for t in rec.templates]
    assert rec.templates[0].fields == ("method", "target", "session", "timestamp", "body")


def test_inference_discriminates_digest_sha1_vs_sha256():
    # a capture signed with SHA1 must yield a SHA1 template, never the SHA256 one.
    def sign(r):
        return newline_sig(HEX_KEY, "POST", "/api/command", r["ts"], r["body"], digest=hashlib.sha1)

    reqs = [{"ts": "100", "body": '{"cmd":"A"}'}, {"ts": "200", "body": '{"cmd":"BB"}'}]
    rec = sr.recover(custom_capture(sign, reqs))
    assert rec.templates, "sha1 scheme should be inside the searched space"
    assert all(t.digest == "sha1" for t in rec.templates)


def test_scheme_outside_search_space_is_not_inferred():
    # Sign with a DERIVED key (sha256 of the hex key bytes) -- not one of the key_forms -- so no
    # template in the bounded space can reproduce it. The engine must report nothing, never guess.
    derived = hashlib.sha256(bytes.fromhex(HEX_KEY)).digest()

    def sign(r):
        return hmac.new(derived, f"POST\n/api/command\n{r['ts']}\n{r['body']}".encode(),
                        hashlib.sha256).hexdigest()

    reqs = [{"ts": "100", "body": '{"cmd":"A"}'}, {"ts": "200", "body": '{"cmd":"BB"}'}]
    rec = sr.recover(custom_capture(sign, reqs))
    assert rec.pairs and rec.templates == []


def test_infer_template_raises_without_a_signature():
    req = sr.SignedRequest(method="POST", path="/x", timestamp="1", body=b"{}")
    with pytest.raises(sr.ReplayError):
        sr.infer_template([(req, HEX_KEY)])


# --------------------------------------------------------------------------- multi-session pairing
def two_session_capture():
    op_key = "11" * 32
    adm_key = "22" * 32
    cap = login_response("op-1", op_key, "operator")
    cap += login_response("adm-1", adm_key, "administrator")
    cap += signed_command("op-1", op_key, "10", '{"cmd":"STATUS"}')
    cap += signed_command("adm-1", adm_key, "20", '{"cmd":"DISABLE"}')
    cap += signed_command("adm-1", adm_key, "30", '{"cmd":"Q"}')
    return cap, op_key, adm_key


def test_pairs_each_request_with_its_own_session_key():
    cap, op_key, adm_key = two_session_capture()
    rec = sr.recover(cap)
    assert len(rec.pairs) == 3
    keys = {req.session: key for req, key in rec.pairs}
    assert keys == {"op-1": op_key, "adm-1": adm_key}
    assert len(rec.templates) == 1


def test_request_without_a_recovered_key_is_unpaired():
    cap = login_response("adm-1", HEX_KEY, "administrator")
    cap += signed_command("adm-1", HEX_KEY, "20", '{"cmd":"OK"}')
    cap += signed_command("ghost", HEX_KEY, "21", '{"cmd":"NO"}')
    msgs = sr.parse_http_capture(cap)
    material = sr.extract_session_material(msgs)
    reqs = sr.extract_signed_requests(msgs)
    pairs, unpaired = sr.pair_requests_with_keys(material, reqs)
    # two sessions in play (adm-1 keyed, ghost unkeyed): ghost cannot borrow adm-1's key.
    assert [r.session for r in unpaired] == ["ghost"]
    assert len(pairs) == 1


# -------------------------------------------------------------------------------- the fresh signer
def test_sign_command_matches_independent_hmac_and_self_verifies():
    rec = sr.recover(text_capture())
    tmpl = rec.templates[0]
    signed = sr.sign_command(tmpl, HEX_KEY, method="POST", path="/api/command",
                             body=FRESH_BODY, timestamp=FRESH_TS, session=ADMIN_SESSION)
    gold = newline_sig(HEX_KEY, "POST", "/api/command", FRESH_TS, FRESH_BODY)
    assert signed.headers["X-Signature"] == gold
    assert signed.headers["X-Timestamp"] == FRESH_TS
    assert signed.headers["X-Session"] == ADMIN_SESSION
    assert signed.method == "POST" and signed.body == FRESH_BODY.encode()


def test_sign_command_never_returns_the_key():
    rec = sr.recover(text_capture())
    signed = sr.sign_command(rec.templates[0], HEX_KEY, method="POST", path="/api/command",
                             body='{"cmd":"X"}', timestamp="1", session=ADMIN_SESSION)
    blob = json.dumps(signed.headers) + signed.body.decode() + signed.method + signed.target
    assert HEX_KEY not in blob


def test_template_verify_rejects_wrong_key():
    rec = sr.recover(text_capture())
    tmpl = rec.templates[0]
    req, key = rec.pairs[0]
    assert tmpl.verify(key, req, req.signature) is True
    assert tmpl.verify("00" * 32, req, req.signature) is False


# --------------------------------------------------------------------------------- replay helper
class _FakeClient:
    """Stands in for solvers.toolkits.web.WebClient: records the single request it is handed."""
    def __init__(self):
        self.calls = []

    def request(self, method, path, data=None, headers=None, allow_redirects=True):
        self.calls.append({"method": method, "path": path, "data": data,
                           "headers": dict(headers or {})})
        return {"status": 200, "method": method, "body": b"ok"}


class _RefusingClient:
    """A get_only-style client: refuses a non-GET method before the wire, like WebClient does."""
    class OutOfScope(Exception):
        pass

    def request(self, method, path, data=None, headers=None, allow_redirects=True):
        if method.upper() != "GET":
            raise self.OutOfScope("get_only client refuses a non-GET request")
        return {"status": 200}


def test_send_signed_command_passes_signed_request_through_unchanged():
    rec = sr.recover(text_capture())
    signed = sr.sign_command(rec.templates[0], HEX_KEY, method="POST", path="/api/command",
                             body=FRESH_BODY, timestamp=FRESH_TS, session=ADMIN_SESSION)
    client = _FakeClient()
    resp = sr.send_signed_command(client, signed)
    assert resp["status"] == 200
    assert len(client.calls) == 1
    call = client.calls[0]
    assert call["method"] == "POST"            # method is not downgraded
    assert call["data"] == signed.body
    assert call["headers"]["X-Signature"] == signed.headers["X-Signature"]


def test_send_signed_command_propagates_a_scope_refusal():
    rec = sr.recover(text_capture())
    signed = sr.sign_command(rec.templates[0], HEX_KEY, method="POST", path="/api/command",
                             body='{"cmd":"X"}', timestamp="1", session=ADMIN_SESSION)
    with pytest.raises(_RefusingClient.OutOfScope):
        sr.send_signed_command(_RefusingClient(), signed)


# ---------------------------------------------------------------------------------- redaction / CLI
def test_key_fingerprint_is_not_the_key():
    fp = sr.key_fingerprint(HEX_KEY)
    assert HEX_KEY not in fp and fp.startswith("sha256:")


def test_cli_inspect_reports_without_printing_the_key(tmp_path, capsys):
    cap = tmp_path / "capture.http"
    cap.write_bytes(text_capture())
    rc = sr.main(["inspect", str(cap)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "HMAC-SHA256" in out
    assert HEX_KEY not in out                  # the recovered key is never printed


def test_cli_solve_emits_a_signed_command_without_the_key(tmp_path, capsys):
    cap = tmp_path / "capture.http"
    cap.write_bytes(text_capture())
    rc = sr.main(["solve", str(cap), "--command-body", FRESH_BODY,
                  "--timestamp", FRESH_TS, "--session", ADMIN_SESSION])
    out = capsys.readouterr().out
    assert rc == 0
    gold = newline_sig(HEX_KEY, "POST", "/api/command", FRESH_TS, FRESH_BODY)
    assert gold in out
    assert HEX_KEY not in out


def test_cli_solve_refuses_to_pick_a_session_when_several_are_recovered(tmp_path, capsys):
    cap = tmp_path / "capture.http"
    cap.write_bytes(two_session_capture()[0])
    rc = sr.main(["solve", str(cap), "--command-body", '{"cmd":"X"}', "--timestamp", "1"])
    captured = capsys.readouterr()
    assert rc == 1
    assert "multiple sessions recovered" in captured.err
    assert "X-Signature" not in captured.out   # nothing was signed


def test_cli_solve_refuses_when_canonicalization_not_inferred(tmp_path, capsys):
    # a scheme outside the searched space (key derived by an extra hash) must make solve refuse,
    # never guess a signature.
    derived = hashlib.sha256(bytes.fromhex(HEX_KEY)).digest()

    def sign(r):
        return hmac.new(derived, f"POST\n/api/command\n{r['ts']}\n{r['body']}".encode(),
                        hashlib.sha256).hexdigest()

    cap = tmp_path / "capture.http"
    cap.write_bytes(custom_capture(sign, [{"ts": "10", "body": '{"cmd":"A"}'},
                                          {"ts": "20", "body": '{"cmd":"BB"}'}]))
    rc = sr.main(["solve", str(cap), "--command-body", '{"cmd":"X"}', "--timestamp", "1",
                  "--session", ADMIN_SESSION])
    err = capsys.readouterr().err
    assert rc == 1
    assert "NOT INFERRED" in err


def test_cli_solve_refuses_when_underdetermined(tmp_path, capsys, monkeypatch):
    # when more than one template fits the captures, solve must refuse rather than pick one.
    cap = tmp_path / "capture.http"
    cap.write_bytes(text_capture())
    real = sr.recover

    def two_templates(*args, **kwargs):
        rec = real(*args, **kwargs)
        rec.templates = rec.templates + [rec.templates[0]]   # force an ambiguous (>1) result
        return rec

    monkeypatch.setattr(sr, "recover", two_templates)
    rc = sr.main(["solve", str(cap), "--command-body", '{"cmd":"X"}', "--timestamp", "1",
                  "--session", ADMIN_SESSION])
    err = capsys.readouterr().err
    assert rc == 1
    assert "under-determined" in err


# --------------------------------------------------------------- round 2: lone key, pcap query, LF-only
def sessionless_capture(*, session_header=None):
    """A login body with a key but no session id; signed commands with no (or one) X-Session header."""
    body = json.dumps({"key": HEX_KEY, "role": "operator"}).encode()
    cap = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body
    for ts, cmd in COMMANDS[:2]:
        b = cmd.encode()
        lines = [b"POST /api/command HTTP/1.1", b"Host: 192.0.2.20:8080"]
        if session_header:
            lines.append(f"X-Session: {session_header}".encode())
        lines += [f"X-Timestamp: {ts}".encode(),
                  f"X-Signature: {newline_sig(HEX_KEY, 'POST', '/api/command', ts, cmd)}".encode(),
                  f"Content-Length: {len(b)}".encode()]
        cap += b"\r\n".join(lines) + b"\r\n\r\n" + b
    return cap


def test_cli_solve_signs_with_the_lone_key_when_no_session_id_was_recovered(tmp_path, capsys):
    cap = tmp_path / "capture.http"
    cap.write_bytes(sessionless_capture())
    rc = sr.main(["solve", str(cap), "--command-body", FRESH_BODY, "--timestamp", FRESH_TS, "--json"])
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    out = json.loads(captured.out)
    assert out["headers"]["X-Signature"] == newline_sig(HEX_KEY, "POST", "/api/command", FRESH_TS,
                                                        FRESH_BODY)
    assert "X-Session" not in out["headers"]     # no session id was recovered or seen: no header
    assert HEX_KEY not in captured.out


def test_cli_solve_lone_key_reuses_the_session_header_the_captures_carried(tmp_path, capsys):
    cap = tmp_path / "capture.http"
    cap.write_bytes(sessionless_capture(session_header="hdr-only-7"))
    rc = sr.main(["solve", str(cap), "--command-body", FRESH_BODY, "--timestamp", FRESH_TS, "--json"])
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    out = json.loads(captured.out)
    assert out["headers"]["X-Session"] == "hdr-only-7"
    assert out["headers"]["X-Signature"] == newline_sig(HEX_KEY, "POST", "/api/command", FRESH_TS,
                                                        FRESH_BODY)


def test_cli_solve_lone_key_honours_an_explicit_session(tmp_path, capsys):
    cap = tmp_path / "capture.http"
    cap.write_bytes(sessionless_capture())
    rc = sr.main(["solve", str(cap), "--command-body", FRESH_BODY, "--timestamp", FRESH_TS,
                  "--session", "given-9", "--json"])
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    assert json.loads(captured.out)["headers"]["X-Session"] == "given-9"


def _bare_recovery(pairs):
    return sr.Recovery(material=[{"key": k} for _, k in pairs], signed_requests=[r for r, _ in pairs],
                       pairs=list(pairs), unpaired=[], templates=[])


def test_pick_refuses_sessionless_keys_it_cannot_choose_between():
    req = sr.SignedRequest(method="POST", path="/p", signature="00", timestamp="1")
    session, key, why = sr._pick_session_and_key(_bare_recovery([(req, "aa"), (req, "bb")]), None)
    assert key is None and "no session id recovered and 2 keys" in why
    assert "multiple sessions" not in why


def test_pick_refuses_sessionless_key_when_captures_carried_several_session_values():
    def req(s):
        return sr.SignedRequest(method="POST", path="/p", signature="00", timestamp="1", session=s)
    pairs = [(req("s1"), "aa"), (req("s2"), "aa")]
    session, key, why = sr._pick_session_and_key(_bare_recovery(pairs), None)
    assert key is None and "2 session values" in why and "--session" in why
    assert sr._pick_session_and_key(_bare_recovery(pairs), "s2") == ("s2", "aa", "")


def test_pcap_capture_with_query_strings_infers_a_path_query_scheme():
    def sig(ts, body, query):
        msg = f"POST\n/api/command?{query}\n{ts}\n{body}".encode()
        return hmac.new(bytes.fromhex(HEX_KEY), msg, hashlib.sha256).hexdigest()

    reqs = [("100", '{"cmd":"A"}', "unit=1"), ("200", '{"cmd":"BB"}', "unit=2&v=x")]
    client = [LOGIN_REQUEST] + [signed_command(ADMIN_SESSION, HEX_KEY, ts, body, query=q,
                                               sig=sig(ts, body, q)) for ts, body, q in reqs]
    server = [login_response(ADMIN_SESSION, HEX_KEY, "administrator")]
    rec = sr.recover(_pcap(tcp_frames(client, server)))
    assert [(r.path, r.query) for r in rec.signed_requests] == [("/api/command", "unit=1"),
                                                                ("/api/command", "unit=2&v=x")]
    assert len(rec.templates) == 1, [t.describe() for t in rec.templates]
    assert rec.templates[0].target_form == "path_query"


def test_lf_only_hand_copied_capture_is_parsed_and_inferred():
    lf = text_capture(encoding="none").replace(b"\r\n", b"\n")
    assert b"\r" not in lf
    msgs = sr.parse_http_capture(lf)
    assert [m.kind for m in msgs] == ["request", "response", "request", "request", "request"]
    assert msgs[3].body == b'{"cmd":"SET_MODE","unit":"U1"}'
    rec = sr.recover(lf)
    assert len(rec.pairs) == 3 and len(rec.templates) == 1
    tmpl = rec.templates[0]
    assert (tmpl.fields, tmpl.separator, tmpl.key_form) == (
        ("method", "target", "timestamp", "body"), "\n", "hex")
