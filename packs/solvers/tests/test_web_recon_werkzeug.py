#!/usr/bin/env python3
"""Real WebClient loopback checks for the exact Werkzeug PIN peer."""
from __future__ import annotations

import event_pin  # noqa: E402  (tests/event_pin.py)
event_pin.pin(globals(), "huntress")  # Huntress web tests: proof_<32 hex> payoffs (events/huntress [proof])

import base64
import hashlib
import json
import sys
import threading
import time
import urllib.parse
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(REPO / "solvers" / "web"), str(REPO / "solvers" / "toolkits")]

import recon_werkzeug as reader  # noqa: E402
import web  # noqa: E402
import werkzeug_pin  # noqa: E402


def _proof(tag):
    return "proof_" + hashlib.md5(("werkzeug:" + tag).encode()).hexdigest()


def _contract(**changes):
    row = {
        "contract": "werkzeug_debug_pin", "console_route": "/console",
        "debugger_secret": "fixture-debugger-secret-47", "werkzeug_version": "3.1.3",
        "pin_algorithm": "sha1", "username": "web3_user", "modname": "flask.app",
        "appname": "Flask", "appfile": "/usr/local/lib/python3.5/dist-packages/flask/app.py",
        "mac": 279275995014060, "machine_id": "d4e6cb65d59544f3331ea0425dc555a1",
        "objective_path": "/run/huntress/objective.txt", "frame": 0,
    }
    row.update(changes)
    return row


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    @property
    def site(self):
        return self.server.site

    def send(self, status, body, ctype, cookie=None):
        raw = body if isinstance(body, bytes) else str(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # noqa: N802
        split = urllib.parse.urlsplit(self.path)
        if split.path == "/api/clues":
            self.send(200, json.dumps({"advanced_contract": self.site.contract}), "application/json")
            return
        if split.path != "/console":
            self.send(404, "missing", "text/plain")
            return
        query = dict(urllib.parse.parse_qsl(split.query, keep_blank_values=True))
        self.site.events.append((self.command, split.path, query, dict(self.headers)))
        if query.get("cmd") == "pinauth":
            good = query.get("pin") == self.site.pin and query.get("s") == self.site.secret
            body = json.dumps({"auth": good, "exhausted": False})
            status = 500 if self.site.mode == "auth_500" else 200
            ctype = "text/html" if self.site.mode == "auth_html" else "application/json"
            self.send(status, body, ctype,
                      cookie="__wzdfixture=trusted; Path=/; HttpOnly" if good else None)
            return
        cookie = self.headers.get("Cookie", "")
        code = query.get("cmd", "")
        if ("__wzdfixture=trusted" not in cookie or query.get("s") != self.site.secret
                or query.get("frm") != "0" or reader.MARKER in code
                or code != reader._expression(self.site.path)):
            self.send(403, "denied", "text/plain")
            return
        if self.site.mode == "ambiguous":
            objective = f"{self.site.proof}\nproof_{'f' * 32}"
            payload = base64.b64encode(objective.encode()).decode()
            body = f"<div>{reader.MARKER}{payload}</div>"
        elif self.site.mode == "offhost":
            objective = f"see https://evil.example/{self.site.proof}"
            payload = base64.b64encode(objective.encode()).decode()
            body = f"<div>{reader.MARKER}{payload}</div>"
        elif self.site.mode == "unbound":
            payload = base64.b64encode(b"not-the-proof").decode()
            body = f"<p>{reader.MARKER}{payload}</p><p>{self.site.proof}</p>"
        elif self.site.mode == "echo_secrets":
            payload = base64.b64encode(self.site.proof.encode()).decode()
            body = (f"<pre>{code} pin={self.site.pin} secret={self.site.secret}</pre>"
                    f"<div>{reader.MARKER}{payload}</div>")
        else:
            payload = base64.b64encode(self.site.proof.encode()).decode()
            body = f"<div class=console-output>{reader.MARKER}{payload}</div>"
        self.send(200, body, "text/html; charset=utf-8")


class Site:
    def __init__(self, contract, proof, mode="ok"):
        self.contract, self.proof, self.mode = contract, proof, mode
        self.events = []
        self.secret = contract["debugger_secret"]
        self.path = contract["objective_path"]
        inputs = {key: contract[key] for key in werkzeug_pin.INPUT_FIELDS}
        self.pin = werkzeug_pin.derive_pin_from_inputs(inputs, contract["pin_algorithm"])[0]


class CaptureClient:
    """The response-copy behavior of proof_hunt._PeerClient."""
    def __init__(self, client):
        self.client = client
        self._captured = []

    @property
    def log(self):
        return self.client.log

    def get(self, *args, **kwargs):
        response = self.client.get(*args, **kwargs)
        self._captured.append(dict(response))
        return response


@contextmanager
def server(contract, proof, mode="ok"):
    site = Site(contract, proof, mode)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.site = site
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield site, f"http://127.0.0.1:{httpd.server_port}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2)


def run(contract, proof, mode="ok", **extra):
    with server(contract, proof, mode) as (site, origin):
        transport = web.WebClient(origin, timeout=2)
        clues = transport.get("/api/clues", allow_redirects=False)
        client = CaptureClient(transport)
        site.events.clear()
        sink = {}
        ctx = {"client": client,
               "route_allowed": lambda path: path == "/console" and "?" not in path,
               "preloaded": {"/api/clues": clues}, "baseline_texts": [],
               "deadline": time.time() + 3, "max_requests": 2, "result_sink": sink}
        ctx.update(extra)
        got = reader.solve({"url": origin, "answer_id": "answer"}, ctx)
        site.client_log = [dict(row) for row in client.log]
        site.captured = [dict(row) for row in client._captured]
        return got, site, sink


def test_real_webclient_unlock_and_bounded_read():
    contract, expected = _contract(), _proof("success")
    got, site, sink = run(contract, expected, mode="echo_secrets")
    assert got == expected and len(site.events) == 2, (got, site.events, sink)
    assert all(row[0] == "GET" and row[1] == "/console" for row in site.events)
    assert not any("authorization" in {key.lower() for key in row[3]} for row in site.events)
    rendered = json.dumps(sink)
    assert contract["debugger_secret"] not in rendered and site.pin not in rendered
    # The setup discovery response necessarily contains the target-published
    # secret; the peer must redact both debugger request URLs it creates.
    retained = repr(site.client_log[-2:])
    assert contract["debugger_secret"] not in retained and site.pin not in retained, retained
    assert reader._expression(contract["objective_path"]) not in retained, retained
    assert "__wzdfixture=trusted" not in retained, retained
    assert all("%3Credacted%3E" in row["url"] for row in site.client_log[-2:])
    captured = repr(site.captured)
    assert contract["debugger_secret"] not in captured and site.pin not in captured, captured
    assert reader._expression(contract["objective_path"]) not in captured, captured
    assert "__wzdfixture=trusted" not in captured, captured
    assert sink["answer"]["requests"] == 2 and sink["answer"]["terminal"] is True


def test_auth_failure_is_terminal_and_never_evaluates():
    contract, expected = _contract(mac=279275995014061), _proof("auth-fail")
    # Server derives the same changed contract, so make its expected PIN from
    # the canonical contract while the reader derives the changed one.
    with server(_contract(), expected) as (site, origin):
        client = web.WebClient(origin, timeout=2)
        site.contract = contract
        clues = client.get("/api/clues", allow_redirects=False)
        site.events.clear()
        sink = {}
        got = reader.solve({"url": origin, "answer_id": "answer"}, {
            "client": client, "route_allowed": lambda path: path.startswith("/console"),
            "preloaded": {"/api/clues": clues}, "baseline_texts": [],
            "deadline": time.time() + 3, "max_requests": 2, "result_sink": sink})
        assert got is None and len(site.events) == 1, (got, site.events, sink)
        assert sink["answer"]["terminal"] is True and sink["answer"]["requests"] == 1


def test_auth_requires_complete_2xx_json_response():
    for mode in ("auth_500", "auth_html"):
        got, site, sink = run(_contract(), _proof(mode), mode=mode)
        assert got is None and len(site.events) == 1, (mode, got, site.events, sink)
        assert sink["answer"]["terminal"] is True and sink["answer"]["requests"] == 1


def test_ambiguous_eval_never_returns_a_proof():
    expected = _proof("ambiguous")
    got, site, sink = run(_contract(), expected, mode="ambiguous")
    assert got is None and len(site.events) == 2, (got, site.events, sink)
    assert sink["answer"]["terminal"] is True and sink["answer"]["candidates"]


def test_eval_proof_must_be_own_host_and_directly_marker_bound():
    for mode in ("offhost", "unbound"):
        expected = _proof(mode)
        got, site, sink = run(_contract(), expected, mode=mode)
        assert got is None and len(site.events) == 2, (mode, got, site.events, sink)
        assert sink["answer"]["terminal"] is True
        assert sink["answer"]["success"] is False


class Bomb:
    def __init__(self):
        self.calls = []

    def get(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        raise AssertionError("invalid Werkzeug contract reached transport")


def response(value):
    return {"status": 200, "response_headers": {"Content-Type": "application/json"},
            "body": json.dumps(value, separators=(",", ":")).encode()}


def zero_wire(contract, **ctx_changes):
    client, sink = Bomb(), {}
    ctx = {"client": client, "route_allowed": lambda _path: True,
           "preloaded": {"/api/clues": response({"advanced_contract": contract})},
           "baseline_texts": [], "deadline": time.time() + 3,
           "max_requests": 2, "result_sink": sink}
    ctx.update(ctx_changes)
    got = reader.solve({"url": "http://127.0.0.1:31337", "answer_id": "answer"}, ctx)
    assert got is None and client.calls == [], (got, client.calls, sink)


def test_unsafe_ambiguous_and_low_budget_contracts_are_zero_wire():
    zero_wire(_contract(objective_path="/run/huntress/../secret"))
    zero_wire(_contract(pin_algorithm="md5"))
    zero_wire(_contract(code="open('/etc/passwd').read()"))
    zero_wire(_contract(mac=True))
    zero_wire(_contract(), max_requests=1)
    client, sink = Bomb(), {}
    rows = [_contract(), _contract(objective_path="/run/huntress/other.txt")]
    got = reader.solve({"url": "http://127.0.0.1:31337", "answer_id": "answer"}, {
        "client": client, "route_allowed": lambda _path: True,
        "preloaded": {"/api/clues": response({"contracts": rows})},
        "deadline": time.time() + 3, "max_requests": 2, "result_sink": sink})
    assert got is None and client.calls == []


def main():
    tests = [value for name, value in sorted(globals().items())
             if name.startswith("test_") and callable(value)]
    started = time.monotonic()
    for test in tests:
        test()
        print("ok  " + test.__name__)
    print(f"PASS: recon_werkzeug loopback runtime ({len(tests)} tests, {time.monotonic()-started:.2f}s)")


if __name__ == "__main__":
    main()
