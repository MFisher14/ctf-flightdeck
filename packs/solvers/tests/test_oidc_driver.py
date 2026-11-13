"""B-183: the OIDC / OAuth2 authorization-code flow driver (solvers/web/oidc_driver.py).

Covers the pure builders (PKCE S256, authorization URL, redirect parsing with state check, token
request/response, each builder's scope check) and live drives against a loopback (127.0.0.1) fake
OIDC provider that records every request it receives: discovery -> login sub-flow -> authorization
code -> PKCE-checked token exchange -> an id_token claim carrying the flag. The O-2 gate is proven at
each state-changing step separately: the login POST is refused inside the login sub-flow, and the
code->token exchange is refused by its own gate (called directly, and reached through drive() against
a provider that needs no login), with the fake recording zero /token hits. The id_token nonce is
checked against the sent nonce. Scope is proven: out-of-scope contacted endpoints are refused before
any connection, uncontacted ones are only recorded. 127.0.0.1 only.
"""
import base64
import contextlib
import datetime as dt
import hashlib
import json
import threading
import types
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import oidc_driver as od
import flow_recorder as fr
from ctf import event as _event, scope as _scope
from ctf.scope import OutOfScope

FLAG = "csctf{oidc_code_exchanged_for_token}"
FLAG_AT = "csctf{oidc_flag_in_access_token}"
CSRF = "csrf-oidc-55"
PASSWORD = "hunter2"


def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _profile(web_state_changing, scope=("127.0.0.0/8", "localhost")):
    return _event.parse({
        "slug": "oidc-test", "name": "oidc driver test",
        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 12, 31)},
        "platform": {"kind": "ctfd", "base_url": "https://board.oidc-platform.test"},
        "flag": {"prefixes": []},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "web_state_changing": bool(web_state_changing), "live_service_scope": list(scope)},
    }, src="tests/test_oidc_driver.py")


@contextlib.contextmanager
def pinned(web_state_changing, scope=("127.0.0.0/8", "localhost")):
    prev = _scope.pinned()
    _scope.pin(_profile(web_state_changing, scope))
    try:
        yield
    finally:
        if prev is not None:
            _scope.pin(prev)
        else:  # pragma: no cover
            _scope.unpin()


# ---------------------------------------------------------------------------- a fake OIDC provider

class _Provider:
    SID = "oidc-sess-abc"

    def __init__(self):
        self.lock = threading.Lock()
        self.codes = {}            # code -> (code_challenge, nonce from the authorization request)
        self.hits = []             # (method, path) of every request that reached the wire
        self.user_agents = []
        self.open_authorize = False   # True: /authorize issues a code without a login
        self.login_redirect = False   # True: an anonymous /authorize 302s to /login (usual IdP)
        self.nonce_mode = "echo"      # echo | fixed | absent
        self.flag_in = "id_token"     # id_token | access_token

    def _discovery(self, host):
        base = f"http://{host}"
        return {
            "issuer": base,
            "authorization_endpoint": base + "/authorize",
            "token_endpoint": base + "/token",
            "jwks_uri": base + "/jwks",
            "response_types_supported": ["code"],
            "code_challenge_methods_supported": ["S256"],
            "id_token_signing_alg_values_supported": ["none"],
        }

    def _id_token(self, nonce):
        header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
        claims = {"sub": "admin", "email": "admin@oidc.test"}
        if self.nonce_mode == "echo":
            claims["nonce"] = nonce
        elif self.nonce_mode == "fixed":
            claims["nonce"] = "n"
        if self.flag_in == "id_token":
            claims["flag"] = FLAG
        payload = _b64url(json.dumps(claims).encode())
        return f"{header}.{payload}."

    def handle(self, method, raw, headers, body):
        host = headers.get("Host") or "127.0.0.1"
        path, _, q = raw.partition("?")
        with self.lock:
            self.hits.append((method, path))
            self.user_agents.append(headers.get("User-Agent"))
        query = dict(urllib.parse.parse_qsl(q, keep_blank_values=True))
        cookies = {}
        for part in (headers.get("Cookie") or "").split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                cookies[k] = v
        logged_in = cookies.get("sid") == self.SID

        if path == "/.well-known/openid-configuration":
            return 200, "application/json", json.dumps(self._discovery(host)), {}
        if path == "/login" and method == "GET":
            return 200, "text/html", (f"<form method=post action=/login>"
                                      f"<input type=hidden name=csrf value='{CSRF}'></form>"), {}
        if path == "/login" and method == "POST":
            fields = dict(urllib.parse.parse_qsl(body, keep_blank_values=True))
            if fields.get("csrf") == CSRF and fields.get("password") == PASSWORD:
                return 200, "text/plain", "ok", {"Set-Cookie": f"sid={self.SID}; Path=/"}
            return 403, "text/plain", "login failed", {}
        if path == "/authorize":
            if not logged_in and not self.open_authorize:
                if self.login_redirect:
                    nxt = urllib.parse.quote(raw, safe="")
                    return 302, "text/plain", "", {"Location": f"/login?next={nxt}"}
                return 200, "text/html", "<p>login required</p>", {}
            import secrets
            code = "code-" + secrets.token_hex(6)
            with self.lock:
                self.codes[code] = (query.get("code_challenge"), query.get("nonce"))
            loc = query.get("redirect_uri", "/cb")
            sep = "&" if "?" in loc else "?"
            loc = f"{loc}{sep}code={code}&state={urllib.parse.quote(query.get('state', ''))}"
            return 302, "text/plain", "", {"Location": loc}
        if path == "/token" and method == "POST":
            fields = dict(urllib.parse.parse_qsl(body, keep_blank_values=True))
            code = fields.get("code")
            verifier = fields.get("code_verifier", "")
            with self.lock:
                challenge, nonce = self.codes.get(code, (None, None))
            expect = _b64url(hashlib.sha256(verifier.encode()).digest()) if verifier else None
            if challenge is None or challenge != expect:
                return 400, "application/json", json.dumps({"error": "invalid_grant"}), {}
            access = FLAG_AT if self.flag_in == "access_token" else "at-" + code
            tok = {"access_token": access, "token_type": "Bearer", "expires_in": 3600,
                   "id_token": self._id_token(nonce)}
            return 200, "application/json", json.dumps(tok), {}
        return 404, "text/plain", "nope", {}


def _serve(provider):
    class H(BaseHTTPRequestHandler):
        def _go(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            st, ctype, payload, hdrs = provider.handle(self.command, self.path, self.headers, body)
            data = payload.encode() if isinstance(payload, str) else payload
            self.send_response(st)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            for k, v in hdrs.items():
                self.send_header(k, v)
            self.end_headers()
            with contextlib.suppress(Exception):
                self.wfile.write(data)

        do_GET = do_POST = _go

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/"


@pytest.fixture
def served():
    prov = _Provider()
    srv, url = _serve(prov)
    try:
        yield types.SimpleNamespace(url=url, prov=prov)
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.fixture
def provider(served):
    return served.url


def _driver(base):
    return od.OIDCDriver(base, client_id="app-1",
                         redirect_uri=base.rstrip("/") + "/cb", scope="openid profile")


LOGIN_FLOW = [
    {"name": "login_page", "method": "GET", "path": "/login",
     "extract": {"csrf": {"form_hidden": "csrf"}}},
    {"name": "login", "method": "POST", "path": "/login",
     "body": f"password={PASSWORD}&csrf={{csrf}}",
     "content_type": "application/x-www-form-urlencoded"},
]


# ------------------------------------------------------------------------------ pure builder tests

def test_pkce_challenge_is_s256_of_verifier():
    p = od.generate_pkce()
    want = _b64url(hashlib.sha256(p["code_verifier"].encode()).digest())
    assert p["code_challenge"] == want
    assert p["code_challenge_method"] == "S256"
    assert 43 <= len(p["code_verifier"]) <= 128


def test_authorization_request_carries_pkce_state_nonce():
    p = od.generate_pkce()
    url = od.build_authorization_request(
        "http://127.0.0.1:1/authorize", client_id="c", redirect_uri="http://127.0.0.1:1/cb",
        state="S1", nonce="N1", code_challenge=p["code_challenge"], scope_check=False)
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
    assert q["response_type"] == "code" and q["client_id"] == "c"
    assert q["state"] == "S1" and q["nonce"] == "N1"
    assert q["code_challenge"] == p["code_challenge"] and q["code_challenge_method"] == "S256"


def test_builders_scope_check_the_endpoint_they_build_for():
    with pinned(web_state_changing=True):
        with pytest.raises(OutOfScope):
            od.build_authorization_request("http://evil.example/authorize", client_id="c",
                                           redirect_uri="http://127.0.0.1/cb", state="S")
        with pytest.raises(OutOfScope):
            od.build_token_request("http://evil.example/token", code="C",
                                   redirect_uri="http://127.0.0.1/cb", client_id="c")
        # The same calls against an in-scope endpoint build normally.
        url = od.build_authorization_request("http://127.0.0.1/authorize", client_id="c",
                                             redirect_uri="http://127.0.0.1/cb", state="S")
        tok_url, body, _ = od.build_token_request("http://127.0.0.1/token", code="C",
                                                  redirect_uri="http://127.0.0.1/cb", client_id="c")
    assert url.startswith("http://127.0.0.1/authorize?")
    assert tok_url == "http://127.0.0.1/token" and "code=C" in body


def test_redirect_state_mismatch_refuses_the_code():
    with pytest.raises(od.OIDCError):
        od.parse_authorization_redirect("http://127.0.0.1:1/cb?code=C&state=BAD", expected_state="GOOD")
    ok = od.parse_authorization_redirect("http://127.0.0.1:1/cb?code=C&state=GOOD", expected_state="GOOD")
    assert ok["code"] == "C"


def test_parse_token_response_decodes_id_token_claims():
    header = _b64url(json.dumps({"alg": "none"}).encode())
    payload = _b64url(json.dumps({"flag": FLAG}).encode())
    doc = json.dumps({"access_token": "A", "id_token": f"{header}.{payload}."})
    out = od.parse_token_response(doc)
    assert out["access_token"] == "A"
    assert out["id_token_claims"]["flag"] == FLAG


def test_parse_token_response_raises_on_a_token_error():
    with pytest.raises(od.OIDCError) as exc:
        od.parse_token_response('{"error": "invalid_grant", "error_description": "bad code"}')
    assert "error=invalid_grant" in str(exc.value) and "bad code" in str(exc.value)


@pytest.mark.parametrize("parser", [od.parse_discovery, od.parse_token_response])
def test_hostile_target_json_is_a_named_oidc_error_not_a_crash(parser):
    with pinned(web_state_changing=True):
        with pytest.raises(od.OIDCError) as exc:
            parser("[" * 200_000 + "]" * 200_000)
        assert "nests too deeply" in str(exc.value)
        # A duplicate key is rejected, never resolved last-wins.
        with pytest.raises(od.OIDCError) as exc:
            parser('{"token_endpoint": "http://127.0.0.1/a", "token_endpoint": "http://127.0.0.1/b",'
                   ' "access_token": "x", "access_token": "y"}')
        assert "rejected" in str(exc.value)


def test_discovery_rejects_out_of_scope_endpoint():
    doc = {"issuer": "http://127.0.0.1/", "authorization_endpoint": "http://127.0.0.1/authorize",
           "token_endpoint": "http://evil.example/token"}
    with pinned(web_state_changing=True):
        with pytest.raises(OutOfScope):
            od.parse_discovery(doc)
        # the same document with an in-scope token endpoint parses
        doc["token_endpoint"] = "http://127.0.0.1/token"
        got = od.parse_discovery(doc)
    assert got["token_endpoint"] == "http://127.0.0.1/token"


def test_discovery_records_but_does_not_enforce_uncontacted_endpoints():
    doc = {"issuer": "http://127.0.0.1/", "authorization_endpoint": "http://127.0.0.1/authorize",
           "token_endpoint": "http://127.0.0.1/token", "jwks_uri": "https://idp.external.example/jwks",
           "userinfo_endpoint": "not a url"}
    with pinned(web_state_changing=True):
        got = od.parse_discovery(doc)
        unchecked = od.parse_discovery(doc, scope_check=False)
    assert got["jwks_uri"] == "https://idp.external.example/jwks"
    assert got["endpoint_scope"] == {"authorization_endpoint": "in-scope", "token_endpoint": "in-scope",
                                     "jwks_uri": "out-of-scope", "issuer": "in-scope"}
    assert got["invalid_endpoints"] == ["userinfo_endpoint"] and "userinfo_endpoint" not in got
    assert set(unchecked["endpoint_scope"].values()) == {"not-checked"}


def test_nonce_check_names_each_outcome():
    sent = "N-sent"
    assert od.check_id_token_nonce({"id_token": "x", "id_token_claims": {"nonce": sent}}, sent) is None
    assert od.check_id_token_nonce({}, sent) is None   # no id_token: nothing to check
    assert od.check_id_token_nonce(
        {"id_token": "x", "id_token_claims": {"nonce": "other"}}, sent)["name"] == "id_token_nonce_mismatch"
    assert od.check_id_token_nonce(
        {"id_token": "x", "id_token_claims": {}}, sent)["name"] == "id_token_nonce_missing"
    assert od.check_id_token_nonce({"id_token": "x"}, sent)["name"] == "id_token_undecodable"


# ---------------------------------------------------------------------------------- live drive tests

def test_full_flow_recovers_flag_when_state_changes_allowed(served):
    with pinned(web_state_changing=True):
        result = _driver(served.url).drive(login_flow=LOGIN_FLOW)
    assert result.code and result.code.startswith("code-")
    assert result.tokens.get("access_token", "").startswith("at-")
    assert result.tokens["id_token_claims"]["flag"] == FLAG
    assert FLAG in result.flags
    # The login sub-flow's steps are kept in the transcript, in order.
    steps = [t["step"] for t in result.transcript]
    assert steps == ["discover", "login:login_page", "login:login", "authorize", "exchange"]
    # The provider echoed the sent nonce: no finding.
    assert result.tokens["id_token_claims"]["nonce"] == result.nonce
    assert result.findings == []
    # Every request carried the neutral, non-event-branded User-Agent.
    assert set(served.prov.user_agents) == {od.DEFAULT_USER_AGENT}
    assert "csctf" not in od.DEFAULT_USER_AGENT.lower()


@pytest.mark.parametrize("mode,finding", [("fixed", "id_token_nonce_mismatch"),
                                          ("absent", "id_token_nonce_missing")])
def test_drive_records_an_id_token_nonce_problem(served, mode, finding):
    served.prov.nonce_mode = mode
    with pinned(web_state_changing=True):
        result = _driver(served.url).drive(login_flow=LOGIN_FLOW)
    assert [f["name"] for f in result.findings] == [finding]
    assert result.findings[0]["sent"] == result.nonce
    assert FLAG in result.flags   # recorded, not a stop: the flag is still returned


def test_flag_only_in_access_token_is_collected(served):
    served.prov.flag_in = "access_token"
    with pinned(web_state_changing=True):
        result = _driver(served.url).drive(login_flow=LOGIN_FLOW)
    assert "flag" not in result.tokens["id_token_claims"]
    assert result.flags == [FLAG_AT]


def test_login_post_refused_when_state_changes_forbidden(served):
    """The login sub-flow's POST is refused by the recorder's gate; exchange() is never reached."""
    with pinned(web_state_changing=False):
        drv = _driver(served.url)
        endpoints = drv.discover()           # a read: allowed
        assert endpoints["token_endpoint"].endswith("/token")
        with pytest.raises(fr.StateChangeRefused) as exc:
            drv.drive(login_flow=LOGIN_FLOW)
    assert "flow step 'login'" in str(exc.value) and "web_state_changing" in str(exc.value)
    assert ("POST", "/login") not in served.prov.hits
    assert ("POST", "/token") not in served.prov.hits


def test_exchange_gate_refuses_a_direct_exchange_and_mints_no_token(served):
    with pinned(web_state_changing=False):
        drv = _driver(served.url)
        endpoints = drv.discover()
        with pytest.raises(fr.StateChangeRefused) as exc:
            drv.exchange(endpoints, code="x", pkce=od.generate_pkce())
    msg = str(exc.value)
    assert "code->token exchange" in msg and "web_state_changing" in msg and "'oidc-test'" in msg
    assert [h for h in served.prov.hits if h[1] == "/token"] == []


def test_drive_without_login_is_refused_at_the_exchange(served):
    """The provider issues a code with no login, so drive() reaches exchange() and its gate refuses."""
    served.prov.open_authorize = True
    with pinned(web_state_changing=False):
        with pytest.raises(fr.StateChangeRefused) as exc:
            _driver(served.url).drive()
    assert "code->token exchange" in str(exc.value)
    assert ("GET", "/authorize") in served.prov.hits      # the reads ran
    assert [h for h in served.prov.hits if h[1] == "/token"] == []


def test_exchange_with_a_bad_code_raises_the_token_error(served):
    with pinned(web_state_changing=True):
        drv = _driver(served.url)
        endpoints = drv.discover()
        with pytest.raises(od.OIDCError) as exc:
            drv.exchange(endpoints, code="bogus", pkce=od.generate_pkce())
    assert "error=invalid_grant" in str(exc.value)
    assert ("POST", "/token") in served.prov.hits


def test_login_sub_flow_stop_is_named(served):
    bad_login = [
        LOGIN_FLOW[0],
        {"name": "login", "method": "POST", "path": "/login", "body": "password=wrong&csrf={csrf}",
         "content_type": "application/x-www-form-urlencoded", "expect_status": [200]},
    ]
    with pinned(web_state_changing=True):
        drv = _driver(served.url)
        result = od.OIDCResult()
        endpoints = drv.discover(result=result)
        with pytest.raises(od.OIDCError) as exc:
            drv.authorize(endpoints, state="S", nonce="N", pkce=od.generate_pkce(),
                          login_flow=bad_login, result=result)
    msg = str(exc.value)
    assert "login sub-flow stopped" in msg and "'login'" in msg and "403" in msg
    assert [t["step"] for t in result.transcript] == ["discover", "login:login_page", "login:login"]
    assert result.transcript[-1]["status"] == 403


def test_driver_refuses_out_of_scope_issuer():
    # The issuer host is outside the pinned scope: building the client must refuse before any socket.
    with pinned(web_state_changing=True):
        with pytest.raises(OutOfScope):
            od.OIDCDriver("http://evil.example/", client_id="c",
                          redirect_uri="http://evil.example/cb")


# ------------------------------------------------- authorize: login redirect vs an issued code (round 2)

def test_authorize_302_to_the_idp_login_page_runs_the_login_sub_flow(served):
    """The usual IdP answers an anonymous /authorize with a 302 to its own /login: that is not the
    code redirect, so the login sub-flow runs and the authorization request is retried."""
    served.prov.login_redirect = True
    with pinned(web_state_changing=True):
        result = _driver(served.url).drive(login_flow=LOGIN_FLOW)
    steps = [t["step"] for t in result.transcript]
    assert steps == ["discover", "login:login_page", "login:login", "authorize", "exchange"]
    assert ("POST", "/login") in served.prov.hits
    assert served.prov.hits.count(("GET", "/authorize")) == 2
    assert FLAG in result.flags


def test_an_already_issued_code_skips_the_login_sub_flow(served):
    """A live IdP session issues the code straight away: the login sub-flow must not run."""
    served.prov.open_authorize = True
    with pinned(web_state_changing=True):
        result = _driver(served.url).drive(login_flow=LOGIN_FLOW)
    assert [t["step"] for t in result.transcript] == ["discover", "authorize", "exchange"]
    assert ("GET", "/login") not in served.prov.hits
    assert ("POST", "/login") not in served.prov.hits
    assert served.prov.hits.count(("GET", "/authorize")) == 1
    assert FLAG in result.flags


def test_login_redirect_without_a_login_flow_is_named_not_a_csrf_stop(served):
    served.prov.login_redirect = True
    with pinned(web_state_changing=True):
        drv = _driver(served.url)
        endpoints = drv.discover()
        with pytest.raises(od.OIDCError) as exc:
            drv.authorize(endpoints, state="S", nonce="N", pkce=od.generate_pkce())
    msg = str(exc.value)
    assert "pass login_flow" in msg and "/login?next=" in msg
    assert "CSRF" not in msg
    assert ("GET", "/login") not in served.prov.hits


def test_login_that_does_not_take_is_named_after_the_retry(served):
    """A login POST that fails without an expect_status lets the sub-flow complete; the retried
    /authorize still 302s to /login, and that is named, not misread as a state mismatch."""
    served.prov.login_redirect = True
    weak_login = [LOGIN_FLOW[0],
                  {"name": "login", "method": "POST", "path": "/login",
                   "body": "password=wrong&csrf={csrf}",
                   "content_type": "application/x-www-form-urlencoded"}]
    with pinned(web_state_changing=True):
        drv = _driver(served.url)
        endpoints = drv.discover()
        with pytest.raises(od.OIDCError) as exc:
            drv.authorize(endpoints, state="S", nonce="N", pkce=od.generate_pkce(),
                          login_flow=weak_login)
    msg = str(exc.value)
    assert "even after the login sub-flow ran" in msg and "CSRF" not in msg
    assert served.prov.hits.count(("GET", "/authorize")) == 2


@pytest.mark.parametrize("status,location,expected", [
    (302, "/login?next=%2Fauthorize%3Fcode_challenge%3Dx", False),   # the IdP's own login page
    (302, "https://idp.oidc.test/login", False),
    (302, "http://127.0.0.1:9/cb?code=abc&state=S", True),           # code in the query
    (302, "http://127.0.0.1:9/implicit#code=abc&state=S", True),     # code in the fragment
    (303, "https://elsewhere.test/x?error=access_denied", True),     # an error is an answer too
    (302, "http://127.0.0.1:9/cb", True),                            # bare redirect_uri
    (302, "http://127.0.0.1:10/cb", False),                          # same path, another port
    (302, "http://127.0.0.1:9/cbx", False),                          # another path
    (200, "http://127.0.0.1:9/cb?code=abc", False),                  # not a redirect at all
    (302, None, False),
])
def test_is_code_redirect_classifies_the_authorize_answer(status, location, expected):
    with pinned(web_state_changing=False):
        drv = od.OIDCDriver("http://127.0.0.1:9/", client_id="c", redirect_uri="http://127.0.0.1:9/cb")
    got = drv._is_code_redirect({"status": status}, location, "http://127.0.0.1:9/authorize?x=1")
    assert got is expected


def test_ipv6_issuer_in_scope_builds_a_bracketed_origin():
    with pinned(web_state_changing=False, scope=("::1/128",)):
        drv = od.OIDCDriver("http://[::1]:8080/", client_id="c", redirect_uri="http://[::1]:8080/cb")
    assert drv._base_client.origin == "http://[::1]:8080"


def test_ipv6_issuer_out_of_scope_is_refused_for_scope_not_url_shape():
    with pinned(web_state_changing=False, scope=("127.0.0.0/8",)):
        with pytest.raises(OutOfScope) as exc:
            od.OIDCDriver("http://[::1]:8080/", client_id="c", redirect_uri="http://[::1]:8080/cb")
    assert "not a usable target URL" not in str(exc.value)


@pytest.mark.parametrize("allowed", [False, True])
def test_driver_clients_are_get_only_exactly_when_the_gate_is_closed(served, allowed):
    """Defence in depth: each per-origin WebClient is built get_only while web_state_changing is
    false, so even a direct use of a driver client cannot send a POST."""
    with pinned(web_state_changing=allowed):
        drv = _driver(served.url)
        tok_client = drv._client_for(served.url.rstrip("/") + "/token")
    assert drv._base_client.get_only is (not allowed)
    assert tok_client is drv._base_client
