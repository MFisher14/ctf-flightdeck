#!/usr/bin/env python3
"""Loopback runtime tests for ``solvers/web/recon_advanced.py``.

These tests use the production ``WebClient`` and peer ``solve`` function.  No
fake Game Master or fake-wire shortcut is involved.  The loopback service
checks the actual method, route, body/header relay, forged Flask cookie and
generated inert serialization bytes.  Negative contracts use a bomb client
and therefore prove zero exploit requests, rather than merely proving that no
answer was returned.

Run directly::

    .venv/bin/python tests/test_web_recon_advanced.py
"""

from __future__ import annotations

import event_pin  # noqa: E402  (tests/event_pin.py)
event_pin.pin(globals(), "huntress")  # Huntress web tests: proof_<32 hex> payoffs (events/huntress [proof])

import base64
import json
import pickle
import sys
import threading
import time
import urllib.parse
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
sys.path.insert(0, str(REPO / "solvers" / "web"))

import flask_tools  # noqa: E402
import recon_advanced as advanced  # noqa: E402
import web  # noqa: E402


def _proof(tag):
    # Stable lowercase wire shape; the value is test-owned, not read from the
    # solver or target object under test.
    import hashlib
    return "proof_" + hashlib.md5(("advanced:" + tag).encode()).hexdigest()


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format, *_args):
        return

    def _body(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        return self.rfile.read(length) if length else b""

    def _send(self, status, body, content_type="application/json"):
        raw = body if isinstance(body, bytes) else str(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _json(self, value, status=200):
        self._send(status, json.dumps(value, separators=(",", ":")))

    @property
    def site(self):
        return self.server.site

    def _outer(self, body=None):
        split = urllib.parse.urlsplit(self.path)
        if self.command == "GET":
            values = dict(urllib.parse.parse_qsl(split.query, keep_blank_values=True))
        elif self.headers.get("Content-Type", "").startswith("application/json"):
            values = json.loads((body or b"").decode("utf-8"))
        else:
            values = dict(urllib.parse.parse_qsl((body or b"").decode("ascii"), keep_blank_values=True))
        headers = values.get("relay_headers", values.get("headers", {}))
        if isinstance(headers, str):
            headers = json.loads(headers)
        return values, headers

    def _fetch(self, body=None):
        values, headers = self._outer(body)
        target = values.get("target")
        verb = values.get("verb")
        self.site.events.append((self.command, urllib.parse.urlsplit(self.path).path,
                                 target, verb, headers))
        mode = self.site.mode
        if mode in ("imdsv2", "mixed"):
            if (target == "http://169.254.169.254/latest/api/token" and verb == "PUT"
                    and headers == {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}):
                self._send(200, self.site.imds_token, "text/plain")
                return
            if (target == "http://169.254.169.254/latest/meta-data/huntress/evidence"
                    and verb == "GET"
                    and headers == {"X-aws-ec2-metadata-token": self.site.imds_token}):
                if mode == "mixed":
                    self._json({"ok": False, "message": "metadata read denied"})
                else:
                    self._json({"ok": True, "evidence": self.site.proof})
                return
        elif mode == "redirect":
            try:
                redirect = urllib.parse.urlsplit(target)
                query = dict(urllib.parse.parse_qsl(redirect.query))
            except Exception:
                redirect, query = None, {}
            if (redirect and redirect.hostname == "127.0.0.1"
                    and redirect.port == self.server.server_port
                    and redirect.path == "/redirect"
                    and query.get("next") == "http://case-service.internal/evidence"):
                self._json({"success": True, "evidence": self.site.proof})
                return
        elif mode == "rebind":
            if target == "http://unit.rebind.test/evidence":
                self.site.rebind_count += 1
                if self.site.rebind_count == 2:
                    self._json({"success": True, "evidence": self.site.proof})
                else:
                    self._json({"ok": False, "message": "public address first"})
                return
        self._json({"ok": False, "error": "relay contract mismatch"}, status=400)

    def do_GET(self):  # noqa: N802
        split = urllib.parse.urlsplit(self.path)
        if split.path == "/api/clues":
            self._json({"advanced_contract": self.site.contract})
            return
        if split.path == "/fetch":
            self._fetch()
            return
        if split.path == "/admin/read":
            raw_cookie = self.headers.get("Cookie", "")
            value = raw_cookie.partition("session=")[2].split(";", 1)[0]
            claims = flask_tools.verify(value, self.site.flask_secret)
            self.site.events.append(("GET", split.path, "cookie", bool(claims), {}))
            if claims and claims.get("role") == "admin":
                self._json({"ok": True, "evidence": self.site.proof})
            else:
                self._json({"ok": False, "error": "guest"}, status=403)
            return
        if split.path == "/state":
            obj = dict(self.site.proto_state)
            if self.site.mode == "proto_reflect" and obj:
                self.site.events.append(("GET", split.path, None, None, {}))
                self._json({"ok": True,
                            "message": f"received {self.site.proto_canary}={self.site.proto_value}",
                            "evidence": self.site.proof})
                return
            response = {"ok": True, "object": obj}
            if obj:
                response["evidence"] = self.site.proof
            self.site.events.append(("GET", split.path, None, None, {}))
            self._json(response)
            return
        self._json({"ok": False, "error": "not found"}, status=404)

    def do_POST(self):  # noqa: N802
        split = urllib.parse.urlsplit(self.path)
        body = self._body()
        if split.path == "/fetch":
            self._fetch(body)
            return
        if split.path == "/merge":
            try:
                doc = json.loads(body.decode("utf-8"))
            except Exception:
                self._json({"ok": False}, status=400)
                return
            nested = doc.get("__proto__", {}) if isinstance(doc, dict) else {}
            if (isinstance(nested, dict) and len(nested) == 1
                    and next(iter(nested)) == self.site.proto_canary
                    and nested[self.site.proto_canary] == self.site.proto_value):
                self.site.proto_state.update(nested)
                self.site.events.append(("POST", split.path, "benign-canary", None, {}))
                self._json({"ok": True, "effect": "merged"})
            else:
                self._json({"ok": False, "error": "bad canary"}, status=400)
            return
        if split.path == "/parse":
            try:
                if self.site.mode == "deser_php_form":
                    form = dict(urllib.parse.parse_qsl(body.decode("ascii"), keep_blank_values=True))
                    raw = base64.b64decode(form["blob"], validate=True)
                    key = "huntress_canary"
                    canary = self.site.deser_canary
                    expected = (f'a:1:{{s:{len(key.encode())}:"{key}";'
                                f's:{len(canary.encode())}:"{canary}";}}').encode("ascii")
                    event = "inert-php"
                elif self.site.mode == "deser_java_raw":
                    raw = body
                    data = self.site.deser_canary.encode("ascii")
                    expected = b"\xac\xed\x00\x05\x74" + len(data).to_bytes(2, "big") + data
                    event = "inert-java"
                else:
                    doc = json.loads(body.decode("utf-8"))
                    raw = base64.b64decode(doc["blob"], validate=True)
                    expected = pickle.dumps({"huntress_canary": self.site.deser_canary}, protocol=4)
                    event = "inert-pickle"
            except Exception:
                self._json({"ok": False}, status=400)
                return
            self.site.events.append(("POST", split.path, event, None, {}))
            if raw == expected:
                if self.site.mode == "deser_reflect":
                    self._json({"success": True, "echo": doc["blob"],
                                "evidence": self.site.proof})
                else:
                    self._json({"success": True, "decoded_canary": self.site.deser_canary,
                                "evidence": self.site.proof})
            else:
                self._json({"ok": False, "error": "not the primitive map"}, status=400)
            return
        self._json({"ok": False, "error": "not found"}, status=404)


class _Site:
    def __init__(self, contract, mode, proof):
        self.contract = contract
        self.mode = mode
        self.proof = proof
        self.events = []
        self.imds_token = "synthetic-imdsv2-token-47"
        self.rebind_count = 0
        self.flask_secret = "synthetic-flask-challenge-key"
        self.proto_canary = "hzpp0123456789ab"
        self.proto_value = "v47cafe"
        self.proto_state = {}
        self.deser_canary = "hzds0123456789ab"


@contextmanager
def _server(contract, mode, proof):
    site = _Site(contract, mode, proof)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.site = site
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        origin = f"http://127.0.0.1:{server.server_port}"
        yield site, origin
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _run(contract, mode, proof, ctx_extra=None):
    with _server(contract, mode, proof) as (site, origin):
        client = web.WebClient(origin, timeout=2.0)
        clues = client.get("/api/clues", allow_redirects=False)
        # Count only requests made by the advanced peer, not fixture setup.
        site.events.clear()
        sink, evidence = {}, []
        started = time.monotonic()
        ctx = {"client": client, "route_allowed": lambda route: route.startswith("/"),
               "preloaded": {"/api/clues": clues}, "baseline_texts": [],
               "deadline": time.time() + 5, "result_sink": sink, "evidence": evidence}
        ctx.update(dict(ctx_extra or {}))
        got = advanced.solve(
            {"url": origin, "answer_id": "answer"},
            ctx,
        )
        elapsed = time.monotonic() - started
        return got, site, sink, evidence, elapsed


def test_imdsv2_header_relay_post_runtime():
    expected = _proof("imdsv2")
    contract = {
        "contract": "imdsv2_ssrf", "route": "/fetch", "outer_method": "POST",
        "transport": "json", "url_field": "target", "method_field": "verb",
        "headers_field": "relay_headers",
        "metadata_path": "/latest/meta-data/huntress/evidence", "token_source": "body",
    }
    got, site, sink, evidence, elapsed = _run(contract, "imdsv2", expected)
    assert got == expected, (got, sink)
    assert [row[3] for row in site.events] == ["PUT", "GET"], site.events
    assert sink["answer"]["requests"] == 2 and sink["answer"]["posts"] == 2
    assert evidence[-1]["class"] == "cloud_metadata" and evidence[-1]["confirmed"] is True
    assert elapsed < 2.0, elapsed


def test_same_origin_redirect_to_ssrf_runtime():
    expected = _proof("redirect")
    contract = {
        "contract": "open_redirect_ssrf", "route": "/fetch", "outer_method": "GET",
        "transport": "query", "url_field": "target", "redirect_route": "/redirect",
        "redirect_method": "GET", "redirect_parameter": "next",
        "redirect_destination": "http://case-service.internal/evidence",
    }
    got, site, sink, _evidence, elapsed = _run(contract, "redirect", expected)
    assert got == expected, (got, sink)
    assert len(site.events) == 1 and site.events[0][:2] == ("GET", "/fetch"), site.events
    assert elapsed < 2.0, elapsed


def test_target_advertised_dns_rebind_runtime():
    expected = _proof("rebind")
    contract = {
        "contract": "dns_rebind_ssrf", "route": "/fetch", "outer_method": "GET",
        "transport": "query", "url_field": "target",
        "rebind_url": "http://unit.rebind.test/evidence", "request_count": 2,
    }
    got, site, sink, _evidence, elapsed = _run(contract, "rebind", expected)
    assert got == expected, (got, sink)
    assert site.rebind_count == 2 and len(site.events) == 2, site.events
    assert elapsed < 2.0, elapsed


def test_confirm_first_flask_signed_session_runtime():
    expected = _proof("flask")
    secret = "synthetic-flask-challenge-key"
    cookie = flask_tools.sign({"role": "guest", "user": "fixture"}, secret)
    contract = {
        "contract": "flask_signed_session", "route": "/admin/read", "method": "GET",
        "cookie_name": "session", "session_cookie": cookie, "secret_key": secret,
        "claim": "role", "value": "admin",
    }
    got, site, sink, _evidence, elapsed = _run(contract, "flask", expected)
    assert got == expected, (got, sink)
    assert len(site.events) == 1 and site.events[0][3] is True, site.events
    # No secret, cookie or forged value is copied to peer metadata.
    rendered = json.dumps(sink, sort_keys=True)
    assert secret not in rendered and cookie not in rendered
    assert elapsed < 2.0, elapsed


def test_inert_deserialization_runtime():
    expected = _proof("deser")
    contract = {
        "contract": "deserialization_inert", "route": "/parse", "method": "POST",
        "transport": "json", "field": "blob", "format": "python_pickle",
        "encoding": "base64", "inert_shape": "primitive_map",
        "canary": "hzds0123456789ab", "readback_field": "decoded_canary",
    }
    got, site, sink, _evidence, elapsed = _run(contract, "deser", expected)
    assert got == expected, (got, sink)
    assert site.events == [("POST", "/parse", "inert-pickle", None, {})], site.events
    assert sink["answer"]["posts"] == 1
    assert elapsed < 2.0, elapsed


def test_inert_php_form_and_java_raw_deserialization_runtime():
    cases = (
        ("deser_php_form", "php", "form", "base64", "primitive_map", "inert-php", True),
        ("deser_java_raw", "java", "raw", "raw", "string", "inert-java", False),
    )
    for mode, fmt, transport, encoding, shape, event, needs_field in cases:
        expected = _proof(mode)
        contract = {
            "contract": "deserialization_inert", "route": "/parse", "method": "POST",
            "transport": transport, "format": fmt, "encoding": encoding,
            "inert_shape": shape, "canary": "hzds0123456789ab",
            "readback_field": "decoded_canary",
        }
        if needs_field:
            contract["field"] = "blob"
        got, site, sink, _evidence, elapsed = _run(contract, mode, expected)
        assert got == expected, (mode, got, sink)
        assert site.events == [("POST", "/parse", event, None, {})], (mode, site.events)
        assert sink["answer"]["posts"] == 1 and elapsed < 2.0, (mode, elapsed, sink)


def test_isolated_prototype_canary_readback_runtime():
    expected = _proof("prototype")
    contract = {
        "contract": "prototype_pollution_canary", "write_route": "/merge",
        "readback_route": "/state", "write_method": "POST", "read_method": "GET",
        "transport": "json", "payload_variant": "proto_json",
        "canary": "hzpp0123456789ab", "value": "v47cafe",
        "isolated_instance": True, "effect": "canary_readback",
    }
    got, site, sink, _evidence, elapsed = _run(contract, "proto", expected)
    assert got == expected, (got, sink)
    assert [row[:2] for row in site.events] == [
        ("GET", "/state"), ("POST", "/merge"), ("GET", "/state")], site.events
    assert sink["answer"]["requests"] == 3 and sink["answer"]["posts"] == 1
    assert elapsed < 2.0, elapsed


def test_post_contract_is_terminal_before_mixed_class_fallthrough():
    expected = _proof("mixed-terminal")
    imds = {
        "contract": "imdsv2_ssrf", "route": "/fetch", "outer_method": "POST",
        "transport": "json", "url_field": "target", "method_field": "verb",
        "headers_field": "relay_headers",
        "metadata_path": "/latest/meta-data/huntress/evidence", "token_source": "body",
    }
    secret = "synthetic-flask-challenge-key"
    flask = {
        "contract": "flask_signed_session", "route": "/admin/read", "method": "GET",
        "cookie_name": "session",
        "session_cookie": flask_tools.sign({"role": "guest"}, secret),
        "secret_key": secret, "claim": "role", "value": "admin",
    }
    got, site, sink, _evidence, _elapsed = _run([imds, flask], "mixed", expected)
    assert got is None, (got, sink)
    assert [row[:2] for row in site.events] == [("POST", "/fetch"), ("POST", "/fetch")], site.events
    summary = sink["answer"]
    assert summary["terminal"] is True and summary["stopped"] == "terminal_post", summary


def test_get_backed_imdsv2_is_terminal_before_mixed_class_fallthrough():
    expected = _proof("mixed-get-terminal")
    imds = {
        "contract": "imdsv2_ssrf", "route": "/fetch", "outer_method": "GET",
        "transport": "query", "url_field": "target", "method_field": "verb",
        "headers_field": "relay_headers",
        "metadata_path": "/latest/meta-data/huntress/evidence", "token_source": "body",
    }
    secret = "synthetic-flask-challenge-key"
    flask = {
        "contract": "flask_signed_session", "route": "/admin/read", "method": "GET",
        "cookie_name": "session",
        "session_cookie": flask_tools.sign({"role": "guest"}, secret),
        "secret_key": secret, "claim": "role", "value": "admin",
    }
    got, site, sink, _evidence, _elapsed = _run([imds, flask], "mixed", expected)
    assert got is None, (got, sink)
    assert [row[:2] for row in site.events] == [("GET", "/fetch"), ("GET", "/fetch")], site.events
    summary = sink["answer"]
    assert summary["posts"] == 0 and summary["terminal"] is True
    assert summary["stopped"] == "terminal_protocol", summary


def test_router_rank_selects_the_first_complete_advanced_contract():
    expected = _proof("ranked-flask-first")
    imds = {
        "contract": "imdsv2_ssrf", "route": "/fetch", "outer_method": "GET",
        "transport": "query", "url_field": "target", "method_field": "verb",
        "headers_field": "relay_headers",
        "metadata_path": "/latest/meta-data/huntress/evidence", "token_source": "body",
    }
    secret = "synthetic-flask-challenge-key"
    flask = {
        "contract": "flask_signed_session", "route": "/admin/read", "method": "GET",
        "cookie_name": "session",
        "session_cookie": flask_tools.sign({"role": "guest"}, secret),
        "secret_key": secret, "claim": "role", "value": "admin",
    }
    plan = [
        {"class": "flask_werkzeug", "phase": "peer:recon-advanced", "rank": 1},
        {"class": "cloud_metadata", "phase": "peer:recon-advanced", "rank": 2},
    ]
    got, site, sink, _evidence, _elapsed = _run(
        [imds, flask], "mixed", expected, {"dispatch_plan": plan})
    assert got == expected, (got, sink)
    assert [row[:2] for row in site.events] == [("GET", "/admin/read")], site.events
    assert sink["answer"]["class"] == "flask_werkzeug", sink


def test_reflection_only_proto_and_deser_proofs_are_rejected():
    proto_contract = {
        "contract": "prototype_pollution_canary", "write_route": "/merge",
        "readback_route": "/state", "write_method": "POST", "read_method": "GET",
        "transport": "json", "payload_variant": "proto_json",
        "canary": "hzpp0123456789ab", "value": "v47cafe",
        "isolated_instance": True, "effect": "canary_readback",
    }
    got, site, sink, _evidence, _elapsed = _run(
        proto_contract, "proto_reflect", _proof("proto-reflect"))
    assert got is None and len(site.events) == 3, (got, site.events, sink)
    assert sink["answer"]["terminal"] is True

    deser_contract = {
        "contract": "deserialization_inert", "route": "/parse", "method": "POST",
        "transport": "json", "field": "blob", "format": "python_pickle",
        "encoding": "base64", "inert_shape": "primitive_map",
        "canary": "hzds0123456789ab", "readback_field": "decoded_canary",
    }
    got, site, sink, _evidence, _elapsed = _run(
        deser_contract, "deser_reflect", _proof("deser-reflect"))
    assert got is None and len(site.events) == 1, (got, site.events, sink)
    assert sink["answer"]["terminal"] is True


class _BombClient:
    def __init__(self):
        self.calls = []

    def request(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        raise AssertionError("zero-wire contract attempted an HTTP request")


def _json_response(value):
    return {"status": 200, "response_headers": {"Content-Type": "application/json"},
            "body": json.dumps(value, separators=(",", ":")).encode("utf-8")}


def _zero_wire(doc, *, allowed=lambda _route: True, max_requests=None):
    bomb = _BombClient()
    sink = {}
    ctx = {"client": bomb, "route_allowed": allowed,
           "preloaded": {"/api/clues": _json_response(doc)}, "baseline_texts": [],
           "deadline": time.time() + 2, "result_sink": sink}
    if max_requests is not None:
        ctx["max_requests"] = max_requests
    got = advanced.solve(
        {"url": "http://127.0.0.1:31337", "answer_id": "answer"},
        ctx,
    )
    assert got is None and bomb.calls == [], (got, bomb.calls, sink)
    return sink


def test_ambiguous_or_incomplete_contracts_are_zero_wire():
    complete = {
        "contract": "imdsv2_ssrf", "route": "/fetch", "outer_method": "POST",
        "transport": "json", "url_field": "target", "method_field": "verb",
        "headers_field": "headers", "metadata_path": "/latest/meta-data/evidence",
        "token_source": "body",
    }
    other = dict(complete, route="/other")
    sink = _zero_wire({"contracts": [complete, other]})
    assert sink["answer"]["ambiguous"] == ["imdsv2_ssrf"], sink
    incomplete = dict(complete)
    incomplete.pop("headers_field")
    _zero_wire({"advanced_contract": incomplete})


def test_unsafe_active_contracts_are_zero_wire():
    _zero_wire({"advanced_contract": {
        "contract": "dns_rebind_ssrf", "route": "/fetch", "outer_method": "GET",
        "transport": "query", "url_field": "target",
        "rebind_url": "http://169.254.169.254/latest/meta-data/", "request_count": 2,
    }})
    _zero_wire({"advanced_contract": {
        "contract": "prototype_pollution_canary", "write_route": "/merge",
        "readback_route": "/state", "write_method": "POST", "read_method": "GET",
        "transport": "json", "payload_variant": "proto_json", "canary": "isAdmin",
        "value": "true", "isolated_instance": True, "effect": "canary_readback",
    }})
    _zero_wire({"advanced_contract": {
        "contract": "deserialization_inert", "route": "/parse", "method": "POST",
        "transport": "json", "field": "blob", "format": "node_serialize",
        "encoding": "base64", "inert_shape": "gadget", "canary": "hzds0123456789ab",
        "readback_field": "decoded_canary",
    }})


def test_wrong_flask_key_and_route_denial_are_zero_wire():
    cookie = flask_tools.sign({"role": "guest"}, "right-key")
    _zero_wire({"advanced_contract": {
        "contract": "flask_signed_session", "route": "/admin/read", "method": "GET",
        "cookie_name": "session", "session_cookie": cookie, "secret_key": "wrong-key",
        "claim": "role", "value": "admin",
    }})
    _zero_wire({"advanced_contract": {
        "contract": "open_redirect_ssrf", "route": "/fetch", "outer_method": "GET",
        "transport": "query", "url_field": "target", "redirect_route": "/redirect",
        "redirect_method": "GET", "redirect_parameter": "next",
        "redirect_destination": "http://case-service.internal/evidence",
    }}, allowed=lambda _route: False)


def test_remaining_request_budget_is_reserved_before_any_protocol_send():
    """A multi-step contract never begins when proof_hunt cannot finish it."""
    _zero_wire({"advanced_contract": {
        "contract": "prototype_pollution_canary", "write_route": "/merge",
        "readback_route": "/state", "write_method": "POST", "read_method": "GET",
        "transport": "json", "payload_variant": "proto_json",
        "canary": "hzpp0123456789ab", "value": "v47cafe",
        "isolated_instance": True, "effect": "canary_readback",
    }}, max_requests=2)
    _zero_wire({"advanced_contract": {
        "contract": "imdsv2_ssrf", "route": "/fetch", "outer_method": "POST",
        "transport": "json", "url_field": "target", "method_field": "verb",
        "headers_field": "relay_headers",
        "metadata_path": "/latest/meta-data/huntress/evidence", "token_source": "body",
    }}, max_requests=1)


class _PrototypeControlClient:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def request(self, method, route, **_kwargs):
        self.calls.append((method, route))
        if len(self.calls) > 1:
            raise AssertionError("invalid prototype control authorized a mutation")
        return self.response


def test_prototype_requires_complete_successful_json_negative_control():
    contract = {
        "contract": "prototype_pollution_canary", "write_route": "/merge",
        "readback_route": "/state", "write_method": "POST", "read_method": "GET",
        "transport": "json", "payload_variant": "proto_json",
        "canary": "hzpp0123456789ab", "value": "v47cafe",
        "isolated_instance": True, "effect": "canary_readback",
    }
    for response in (
            {"status": 500, "response_headers": {"Content-Type": "application/json"},
             "body": b'{"error":"backend unavailable"}'},
            {"status": 200, "response_headers": {"Content-Type": "application/json"},
             "body": b'{"object":'},
            {"status": 200, "response_headers": {"Content-Type": "text/html"},
             "body": b'<html>empty state</html>'}):
        client = _PrototypeControlClient(response)
        sink = {}
        got = advanced.solve(
            {"url": "http://127.0.0.1:31337", "answer_id": "answer"},
            {"client": client, "route_allowed": lambda _route: True,
             "preloaded": {"/api/clues": _json_response({"advanced_contract": contract})},
             "baseline_texts": [], "deadline": time.time() + 2,
             "max_requests": 3, "result_sink": sink},
        )
        assert got is None and client.calls == [("GET", "/state")], (got, client.calls, sink)


def main():
    tests = [value for name, value in sorted(globals().items())
             if name.startswith("test_") and callable(value)]
    started = time.monotonic()
    for test in tests:
        test()
        print("ok  " + test.__name__)
    elapsed = time.monotonic() - started
    print(f"PASS: recon_advanced loopback runtime ({len(tests)} tests, {elapsed:.2f}s)")


if __name__ == "__main__":
    main()
