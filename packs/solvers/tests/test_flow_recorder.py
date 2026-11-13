"""B-183: the stateful HTTP flow recorder (solvers/web/flow_recorder.py).

Every test drives the recorder against a loopback (127.0.0.1) fake app and asserts a real effect:
a CSRF token threaded from one step into the next, a session cookie carried across steps, each
extractor returning the exact value, and -- the O-2 gate -- a state-changing step refused unless the
pinned event profile's rules.web_state_changing is true, with the downstream flag proven unreachable
when it is refused. 127.0.0.1 only; no challenge binary is run.
"""
import contextlib
import datetime as dt
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import types

import pytest

import flow_recorder as fr
import web as _webtk
from ctf import event as _event, scope as _scope

FLAG = "csctf{flow_recorder_threaded_state}"


def _profile(web_state_changing):
    return _event.parse({
        "slug": "flow-test", "name": "flow recorder test",
        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 12, 31)},
        "platform": {"kind": "ctfd", "base_url": "https://board.flow-platform.test"},
        "flag": {"prefixes": []},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "web_state_changing": bool(web_state_changing),
                  "live_service_scope": ["127.0.0.0/8", "localhost"]},
    }, src="tests/test_flow_recorder.py")


@contextlib.contextmanager
def pinned(web_state_changing):
    prev = _scope.pinned()
    _scope.pin(_profile(web_state_changing))
    try:
        yield
    finally:
        if prev is not None:
            _scope.pin(prev)
        else:  # pragma: no cover - the suite always has a pinned profile
            _scope.unpin()


# --------------------------------------------------------------------------- a fake stateful app

class _App:
    """A tiny login->session->protected app. Thread-safe; records nothing but the session set."""

    CSRF = "csrf-ab12cd34"
    SID = "sess-9f8e7d"

    def __init__(self):
        self.lock = threading.Lock()
        self.hits = []          # (method, path) of every request that reached the wire
        self.user_agents = []

    def handle(self, method, raw, headers, body):
        with self.lock:
            self.hits.append((method, raw.partition("?")[0]))
            self.user_agents.append(headers.get("User-Agent"))
        path, _, q = raw.partition("?")
        query = dict(urllib.parse.parse_qsl(q, keep_blank_values=True))
        cookies = {}
        for part in (headers.get("Cookie") or "").split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                cookies[k] = v
        logged_in = cookies.get("sid") == self.SID

        if path == "/login" and method == "GET":
            html = (f"<form method=post action=/login>"
                    f"<input type=hidden name=csrf_token value='{self.CSRF}'>"
                    f"<input name=user></form>")
            return 200, "text/html", html, {}
        if path == "/login" and method == "POST":
            fields = dict(urllib.parse.parse_qsl(body, keep_blank_values=True))
            if fields.get("csrf") == self.CSRF and fields.get("user") == "admin":
                return 302, "text/plain", "ok", {"Set-Cookie": f"sid={self.SID}; Path=/",
                                                  "Location": "/account"}
            return 403, "text/plain", "bad csrf or user", {}
        if path == "/account" and method == "GET":
            if logged_in:
                return 200, "text/html", f"<h1>Welcome admin</h1><pre>{FLAG}</pre>", {}
            return 401, "text/html", "<p>please log in</p>", {}
        # extractor fixtures
        if path == "/headers":
            return 200, "text/plain", "ok", {"X-Token": "hdr-value-77"}
        if path == "/go":
            return 302, "text/plain", "", {"Location": "/cb?code=CODE123&state=ST9"}
        if path == "/data.json":
            return 200, "application/json", '{"outer": {"inner": "json-deep-42"}, "n": 7, "arr": ["a", "b"]}', {}
        if path == "/text":
            return 200, "text/plain", "prefix TOKEN=rx-value-88 suffix", {}
        if path == "/setcookie":
            return 200, "text/plain", "ok", {"Set-Cookie": "flavor=choc-chip; Path=/"}
        if path == "/deep.json":   # hostile nesting: blows the C JSON scanner's recursion limit
            return 200, "application/json", "[" * 200_000 + "]" * 200_000, {}
        if path == "/dup.json":    # duplicate key: last-wins json.loads would say "second"
            return 200, "application/json", '{"k": "first", "k": "second"}', {}
        if path == "/mutate":
            return 200, "text/plain", "mutated", {}
        return 404, "text/plain", "nope", {}


def _serve(app):
    class H(BaseHTTPRequestHandler):
        def _go(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            st, ctype, payload, hdrs = app.handle(self.command, self.path, self.headers, body)
            data = payload.encode() if isinstance(payload, str) else payload
            self.send_response(st)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            for k, v in hdrs.items():
                self.send_header(k, v)
            self.end_headers()
            with contextlib.suppress(Exception):
                self.wfile.write(data)

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = _go

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/"


@pytest.fixture
def served():
    the_app = _App()
    srv, url = _serve(the_app)
    try:
        yield types.SimpleNamespace(url=url, app=the_app)
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.fixture
def app(served):
    return served.url


# ------------------------------------------------------------------------------------- the tests

LOGIN_FLOW = [
    {"name": "login_page", "method": "GET", "path": "/login",
     "extract": {"csrf": {"form_hidden": "csrf_token"}}},
    {"name": "login", "method": "POST", "path": "/login",
     "body": "user=admin&csrf={csrf}",
     "content_type": "application/x-www-form-urlencoded",
     "expect_status": [302], "follow_redirects": False},
    {"name": "account", "method": "GET", "path": "/account"},
]


def test_threads_csrf_and_carries_cookie_to_reach_flag(app):
    with pinned(web_state_changing=True):
        rec = fr.FlowRecorder(app)
        result = rec.record(LOGIN_FLOW)
    assert result.completed is True
    # The hidden CSRF token was extracted and threaded into the POST body.
    assert result.variables["csrf"] == _App.CSRF
    # The session cookie from the POST was carried to the protected GET, which returned the flag.
    assert FLAG in result.flags
    account = next(e for e in result.transcript if e["name"] == "account")
    assert account["status"] == 200


def test_state_change_refused_when_profile_forbids_and_flag_unreachable(served):
    with pinned(web_state_changing=False):
        rec = fr.FlowRecorder(served.url)
        with pytest.raises(fr.StateChangeRefused) as exc:
            rec.record(LOGIN_FLOW)
    msg = str(exc.value)
    assert "web_state_changing" in msg and "'login'" in msg
    # The refusal happened at the POST: only the login page GET reached the wire, so the POST and
    # the protected account GET never ran and no flag leaked.
    assert served.app.hits == [("GET", "/login")]


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH", "HEAD"])
def test_every_non_get_method_is_refused_by_the_recorder_gate(served, method):
    """Only the recorder's O-2 gate stands between the step and the wire: the client is NOT get_only."""
    client = _webtk.WebClient(served.url, get_only=False)
    with pinned(web_state_changing=False):
        with pytest.raises(fr.StateChangeRefused) as exc:
            fr.run_flow(client, [{"name": "m", "method": method, "path": "/mutate"}])
    msg = str(exc.value)
    # The recorder's own refusal (naming the step and the rule), not the client's generic one.
    assert f"flow step 'm' is a {method}" in msg and "web_state_changing" in msg
    assert served.app.hits == []


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH"])
def test_non_get_method_reaches_the_wire_when_the_gate_is_open(served, method):
    with pinned(web_state_changing=True):
        result = fr.FlowRecorder(served.url).record([{"name": "m", "method": method, "path": "/mutate"}])
    assert result.completed is True
    assert served.app.hits == [(method, "/mutate")]


def test_recorder_read_methods_agree_with_get_only_client():
    # One set: a method the recorder treats as a read is exactly what a get_only client sends.
    assert fr.READ_METHODS == _webtk.WebClient.READ_METHODS == frozenset({"GET"})
    assert fr.is_state_changing("HEAD") and not fr.is_state_changing("get")


def test_recorder_client_is_get_only_exactly_when_the_gate_is_closed(served):
    with pinned(web_state_changing=False):
        closed = fr.FlowRecorder(served.url)
        assert closed.client.get_only is True
        # A direct client use cannot mutate the target either: refused before the wire.
        with pytest.raises(_webtk.OutOfScope):
            closed.client.request("POST", "/mutate", data="x=1")
    assert served.app.hits == []
    with pinned(web_state_changing=True):
        assert fr.FlowRecorder(served.url).client.get_only is False


def test_step_cap_refuses_an_oversized_flow_before_any_request(served):
    too_many = [{"name": f"s{i}", "method": "GET", "path": "/headers"} for i in range(fr.MAX_STEPS + 1)]
    with pinned(web_state_changing=True):
        with pytest.raises(fr.FlowError) as exc:
            fr.FlowRecorder(served.url).record(too_many)
        assert f"the cap is {fr.MAX_STEPS}" in str(exc.value)
        assert served.app.hits == []
        # Exactly at the cap is allowed.
        result = fr.FlowRecorder(served.url).record(too_many[:fr.MAX_STEPS])
    assert result.completed is True and len(served.app.hits) == fr.MAX_STEPS


def test_recorder_sends_a_neutral_user_agent(served):
    with pinned(web_state_changing=True):
        fr.FlowRecorder(served.url).record([{"name": "h", "method": "GET", "path": "/headers"}])
    assert served.app.user_agents == [fr.DEFAULT_USER_AGENT]
    assert "csctf" not in fr.DEFAULT_USER_AGENT.lower()


def test_wrong_csrf_mismatch_stops_the_flow(app):
    bad = [
        {"name": "login_page", "method": "GET", "path": "/login",
         "extract": {"csrf": {"form_hidden": "csrf_token"}}},
        {"name": "login", "method": "POST", "path": "/login",
         "body": "user=admin&csrf=WRONG",
         "content_type": "application/x-www-form-urlencoded",
         "expect_status": [302], "follow_redirects": False},
        {"name": "account", "method": "GET", "path": "/account"},
    ]
    with pinned(web_state_changing=True):
        result = fr.FlowRecorder(app).record(bad)
    assert result.completed is False
    assert "login" in result.stopped_reason
    assert FLAG not in result.flags
    assert all(e["name"] != "account" for e in result.transcript)


def test_unresolved_placeholder_is_a_loud_stop(app):
    with pinned(web_state_changing=True):
        with pytest.raises(fr.FlowError) as exc:
            fr.FlowRecorder(app).record([{"name": "x", "method": "GET", "path": "/account?u={missing}"}])
    assert "missing" in str(exc.value)


@pytest.mark.parametrize("step,var,expected", [
    ({"path": "/headers", "extract": {"v": {"header": "X-Token"}}}, "v", "hdr-value-77"),
    ({"path": "/go", "follow_redirects": False,
      "extract": {"v": {"location_param": "code"}}}, "v", "CODE123"),
    ({"path": "/data.json", "extract": {"v": {"json": "outer.inner"}}}, "v", "json-deep-42"),
    ({"path": "/text", "extract": {"v": {"regex": "TOKEN=(\\S+)"}}}, "v", "rx-value-88"),
    ({"path": "/login", "extract": {"v": {"form_hidden": "csrf_token"}}}, "v", _App.CSRF),
])
def test_each_extractor_returns_the_exact_value(app, step, var, expected):
    step = {"name": "e", "method": "GET", **step}
    with pinned(web_state_changing=True):
        result = fr.FlowRecorder(app).record([step])
    assert result.variables.get(var) == expected


def test_cookie_extractor_reads_the_jar(app):
    steps = [
        {"name": "set", "method": "GET", "path": "/setcookie"},
        {"name": "read", "method": "GET", "path": "/headers", "extract": {"v": {"cookie": "flavor"}}},
    ]
    with pinned(web_state_changing=True):
        result = fr.FlowRecorder(app).record(steps)
    assert result.variables.get("v") == "choc-chip"


def test_json_extractor_absent_key_records_missing_not_crash(app):
    with pinned(web_state_changing=True):
        result = fr.FlowRecorder(app).record(
            [{"name": "e", "method": "GET", "path": "/data.json", "extract": {"v": {"json": "outer.nope"}}}])
    assert "v" not in result.variables
    assert result.transcript[0]["missing"] == ["v"]


@pytest.mark.parametrize("dotted", ["outer", "arr"])
def test_json_extractor_refuses_a_container_value(app, dotted):
    """A dict or list is not a variable value: it is recorded missing, never str()'d into later
    placeholders."""
    with pinned(web_state_changing=True):
        result = fr.FlowRecorder(app).record(
            [{"name": "e", "method": "GET", "path": "/data.json", "extract": {"v": {"json": dotted}}}])
    assert result.completed is True
    assert "v" not in result.variables
    assert result.transcript[0]["missing"] == ["v"]


def test_json_extractor_indexes_into_a_list(app):
    with pinned(web_state_changing=True):
        result = fr.FlowRecorder(app).record(
            [{"name": "e", "method": "GET", "path": "/data.json", "extract": {"v": {"json": "arr.1"}}}])
    assert result.variables.get("v") == "b"


@pytest.mark.parametrize("path", ["/deep.json", "/dup.json"])
def test_json_extractor_hostile_body_records_missing_not_crash(app, path):
    # A hostile nesting depth must not escape as RecursionError, and a duplicate key must not be
    # resolved last-wins: either way the var is recorded missing and the flow completes.
    with pinned(web_state_changing=True):
        result = fr.FlowRecorder(app).record(
            [{"name": "e", "method": "GET", "path": path, "extract": {"v": {"json": "k"}}}])
    assert result.completed is True
    assert "v" not in result.variables
    assert result.transcript[0]["missing"] == ["v"]


def test_parse_target_json_names_the_rejection():
    with pytest.raises(ValueError) as exc:
        fr.parse_target_json("[" * 200_000 + "]" * 200_000, max_chars=1 << 20, what="probe body")
    assert "probe body nests too deeply" in str(exc.value)
    with pytest.raises(ValueError) as exc:
        fr.parse_target_json('{"a": 1, "a": 2}', max_chars=1000, what="probe body")
    assert "probe body rejected" in str(exc.value)
    assert fr.parse_target_json(b'{"a": [1, 2]}', max_chars=1000) == {"a": [1, 2]}
