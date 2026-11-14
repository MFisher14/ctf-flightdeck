#!/usr/bin/env python3
"""B-235: the web field x action authorization-matrix class (BOLA / access) and the remote-policy fail-open
class, both reached through the public ``proof_hunt.solve_targets`` entry point.

Every target is a local fake HTTP server bound to 127.0.0.1 inside the test; the scope-locked ``WebClient``
owns every request. No platform, instance or model is contacted. The fakes reproduce the recorded shapes:

  * day-14 "The API Has Opinions": /api/clues names a /execute-<hex> (or /process-<hex>) feature route, an
    inventory route and a protected_reference; the inventory names query_parameters [id, fields, action], a
    fields list and an actions list; only ONE field+action combo on the protected reference returns the proof.
  * day-24 "Fail Open Friday": /api/clues names a feature route, a policy_format_route and a deny-on-failure
    expected_behavior; the format route names the parameter, a ``remote:<hex>:`` prefix and a base64url JSON
    sample; an undecodable value after the prefix fails open and returns the proof.

What each test pins is in its name and docstring.
"""

from __future__ import annotations

import event_pin  # noqa: E402  (tests/event_pin.py)
event_pin.pin(globals(), "huntress")  # Huntress web tests: proof_<32 hex> payoffs (events/huntress [proof])

import base64
import json
import sys
import threading
import time
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO / "solvers" / "web"), str(REPO / "solvers" / "toolkits")]
sys.dont_write_bytecode = True

import proof_hunt  # noqa: E402


# ---------------------------------------------------------------------------------------------------------
#  a tiny route-table HTTP fake on 127.0.0.1
# ---------------------------------------------------------------------------------------------------------
def _proof():
    return "proof_" + uuid.uuid4().hex


def js(value, status=200):
    return status, "application/json", json.dumps(value, separators=(",", ":"))


def html(text):
    return 200, "text/html; charset=utf-8", text


class Site:
    """A route table: path -> (status, ctype, body) or a callable(query_dict) returning one."""

    def __init__(self, routes):
        self.routes = dict(routes)
        self.hits = []                      # (method, raw path)
        self.lock = threading.Lock()

    def record(self, method, path):
        with self.lock:
            self.hits.append((method, path))

    def answer(self, path):
        parsed = urllib.parse.urlsplit(path)
        route = self.routes.get(parsed.path)
        if route is None:
            return js({"error": "not_found"}, 404)
        if callable(route):
            return route(dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)))
        return route

    def gets(self):
        return [p for m, p in self.hits if m == "GET"]

    def non_gets(self):
        return [(m, p) for m, p in self.hits if m != "GET"]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def _send(self, status, ctype, body):
        data = body.encode("utf-8") if isinstance(body, str) else bytes(body)
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True

    def do_GET(self):  # noqa: N802
        self.server.site.record("GET", self.path)
        self._send(*self.server.site.answer(self.path))

    def _other(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        self.server.site.record(self.command, self.path)
        self._send(*js({"error": "method_not_allowed"}, 405))

    do_POST = do_PUT = do_DELETE = do_PATCH = _other  # noqa: N815


@pytest.fixture
def serve():
    servers = []

    def start(site):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.site = site
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        host, port = server.server_address
        return f"http://{host}:{port}/"

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


def hunt(urls, max_requests=60):
    """solve_targets over one or more loopback targets. The deadline is generous (the machine runs at a high
    load average); a solving hunt returns as soon as it banks, and every negative test bounds the work by
    max_requests, so no test depends on wall-clock speed."""
    items = [{"answer_id": f"proof-{i + 1}", "url": url, "question": f"Recover the proof from Target {i + 1}."}
             for i, url in enumerate(urls)]
    return proof_hunt.solve_targets(items, {"deadline": time.time() + 120, "max_requests": max_requests})


def q(raw, name):
    return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(raw).query, keep_blank_values=True)).get(name)


# ---------------------------------------------------------------------------------------------------------
#  day-14 access site
# ---------------------------------------------------------------------------------------------------------
def access_site(proof, *, feature="/execute-8fcc90", fields=("title", "note"), actions=("view", "export"),
                protected=15564, public=6480, win=("note", "export"), landing_proof="",
                inv_route="/api/inventory", params=("id", "fields", "action"), params_in_inventory=True,
                error_token="id_fields_action_required", clue_extra=None, inv_extra=None):
    clues = {"framework": "Jakarta Servlet", "feature_route": feature, "inventory_route": inv_route,
             "current_role": "analyst", "protected_reference": protected}
    clues.update(clue_extra or {})
    inv = {"route": feature, "fields": list(fields), "actions": list(actions), "public_reference": public,
           "sample": {params[0]: public, params[1]: "title", params[2]: "view"}}
    if params_in_inventory:
        inv["query_parameters"] = list(params)
    inv.update(inv_extra or {})
    id_p, fld_p, act_p = params

    def execute(query):
        idv, f, a = query.get(id_p), query.get(fld_p), query.get(act_p)
        if idv is None or f is None or a is None:
            return js({"error": error_token}, 400)
        if str(idv) == str(public) and (f, a) == ("title", "view"):
            return js({"id": public, "title": "Ordinary workspace case"})
        if str(idv) == str(protected) and (f, a) == tuple(win):
            return js({"ok": True, "effect": "api_field_action_authorization_bypassed", "evidence": proof})
        return js({"error": "field_action_forbidden"}, 403)

    body = "<h1>WAR Room</h1><a href='/api/clues'>clues</a>" + (f"<!-- {landing_proof} -->" if landing_proof else "")
    return Site({"/": html(body), "/api/clues": js(clues), inv_route: js(inv), feature: execute})


def access_shaped(site, params=("id", "fields", "action")):
    """GETs carrying all three access roles, as (path, id, field, action), in send order."""
    out = []
    for raw in site.gets():
        vals = [q(raw, p) for p in params]
        if all(v is not None for v in vals):
            out.append((raw.split("?", 1)[0], *vals))
    return out


# ---------------------------------------------------------------------------------------------------------
#  day-24 fail-open site
# ---------------------------------------------------------------------------------------------------------
def failopen_site(proof, *, feature="/inspect-c5e973", prefix="remote:40b12d94f983:", landing_proof=""):
    sample = base64.urlsafe_b64encode(b'{"Scope":"public","Allow":true}').decode().rstrip("=")
    clues = {"feature_route": feature, "policy_format_route": "/api/policy-format", "current_role": "analyst",
             "expected_behavior": "deny access when the policy service is unavailable"}
    fmt = {"query_parameter": "policy", "prefix": prefix, "encoding": "base64url UTF-8 JSON",
           "sample_decision": {"scope": "public", "allow": True}, "sample_encoded": sample}

    def inspect(query):
        value = query.get("policy")
        if value is None or not value.startswith(prefix):
            return js({"error": "remote_policy_required"}, 400)
        rest = value[len(prefix):]
        try:
            doc = json.loads(base64.urlsafe_b64decode(rest + "=" * (-len(rest) % 4)).decode("utf-8"))
            if not isinstance(doc, dict):
                raise ValueError("not an object")
        except Exception:
            # the decode-failure path FAILS OPEN (the recorded day-24 behaviour)
            return js({"ok": True, "effect": "exceptional_condition_fail_open", "evidence": proof})
        if doc.get("Scope") == "public" and doc.get("Allow") is True:
            return js({"ok": True, "policy": "standard"})
        return js({"error": "policy_denied"}, 403)

    body = "<h1>Fail Open Friday</h1><a href='/api/clues'>clues</a>" + (
        f"<!-- {landing_proof} -->" if landing_proof else "")
    return Site({"/": html(body), "/api/clues": js(clues), "/api/policy-format": js(fmt), feature: inspect}), sample


def policy_values(site, feature="/inspect-c5e973"):
    return [q(raw, "policy") for raw in site.gets() if raw.split("?", 1)[0] == feature and q(raw, "policy")]


# ---------------------------------------------------------------------------------------------------------
#  unit: the error-token split and the read-only action allowlist
# ---------------------------------------------------------------------------------------------------------
def test_required_params_splits_a_multi_parameter_error_token():
    assert proof_hunt.required_params('{"error":"id_fields_action_required"}') == ("id", "fields", "action")
    assert proof_hunt.required_params("case_select_op_missing") == ("case", "select", "op")
    assert proof_hunt.required_params("session_id_required") == ("session", "id")
    # one-word tokens, no token, two different tokens, a repeated part: nothing to split
    assert proof_hunt.required_params("id_required") == ()
    assert proof_hunt.required_params("field_action_forbidden") == ()
    assert proof_hunt.required_params("id_fields_required and action_mode_required") == ()
    assert proof_hunt.required_params("id_id_action_required") == ()
    assert proof_hunt.required_params(None) == ()


@pytest.mark.parametrize("action", ["view", "export", "download", "read", "preview", "export_csv", "viewAll",
                                    "show-details", "raw"])
def test_read_only_action_values_are_allowed(action):
    assert proof_hunt.access_action_ok(action), action


@pytest.mark.parametrize("action", ["delete", "update", "execute", "run", "submit", "reset", "approve",
                                    # state-changing verbs the generic blocklist alone lets through:
                                    "publish", "grant", "promote", "assign", "rename", "enable", "set",
                                    "export_publish", "view_and_send", "all", "csv", "%64elete", "", "x" * 65,
                                    None, 7])
def test_state_changing_or_unknown_action_values_are_refused(action):
    assert not proof_hunt.access_action_ok(action), action


def test_blocklist_alone_would_have_sent_these_verbs():
    # Documents why the allowlist exists: the generic guard does not refuse these, the access guard does.
    for verb in ("publish", "grant", "promote", "assign", "rename", "enable"):
        assert not proof_hunt.is_destructive(verb), verb
        assert not proof_hunt.access_action_ok(verb), verb


@pytest.mark.parametrize("action", ["report", "open", "load", "audit", "check", "view_report", "open_file",
                                    "load_all", "audit_log", "export_audit", "check_status"])
def test_read_like_verbs_with_common_side_effects_are_refused(action):
    # report hands a URL to an admin bot, open/load start a session or job, audit/check trigger a run:
    # none of them may ride on the trusted feature route, alone or as a word of a compound value.
    assert not proof_hunt.access_action_ok(action), action


def test_no_allowlisted_word_is_destructive():
    # The allowlist must stay inside the generic guard: every word on it passes `is_destructive`.
    words = proof_hunt.ACCESS_READ_VERBS | proof_hunt.ACCESS_READ_MODIFIERS
    assert words and not [w for w in words if proof_hunt.is_destructive(w)]


def test_a_destructive_word_added_to_the_allowlist_is_still_refused(monkeypatch):
    # Defence in depth: access_action_ok also asks `is_destructive`, so a future edit that puts a
    # state-changing verb on the read list does not open it up.
    monkeypatch.setattr(proof_hunt, "ACCESS_READ_VERBS", proof_hunt.ACCESS_READ_VERBS | {"delete", "submit", "run"})
    assert proof_hunt.access_action_ok("view")
    for verb in ("delete", "submit", "run", "view_delete"):
        assert not proof_hunt.access_action_ok(verb), verb


def test_route_name_waiver_is_only_for_an_advertised_route():
    hunter = object.__new__(proof_hunt._Hunter)
    path = "/execute-8fcc90?id=15564&fields=note&action=export"
    assert not hunter.allowed(path, offered=False)                 # a guessed /execute- route is refused
    assert hunter.allowed(path, offered=False, trusted=True)      # the advertised one is driven
    assert not hunter.allowed("/delete-8fcc90?id=1", offered=False, trusted=True)


# ---------------------------------------------------------------------------------------------------------
#  day-14 access class, end to end
# ---------------------------------------------------------------------------------------------------------
def test_access_base_solves_get_only_on_the_advertised_execute_route(serve):
    p = _proof()
    site = access_site(p)
    got = hunt([serve(site)])
    assert got.get("proof-1") == p, site.hits
    assert not site.non_gets(), site.non_gets()
    assert ("/execute-8fcc90", "15564", "note", "export") in access_shaped(site)
    # every access-shaped request went to the advertised route with the protected reference
    assert {row[0] for row in access_shaped(site)} == {"/execute-8fcc90"}
    assert {row[1] for row in access_shaped(site)} == {"15564"}


def test_access_walks_fields_by_actions_in_inventory_order(serve):
    p = _proof()
    site = access_site(p)            # the winner, note+export, is the LAST of the four combos
    got = hunt([serve(site)])
    assert got.get("proof-1") == p
    combos = [(f, a) for _route, _id, f, a in access_shaped(site)]
    assert combos == [("title", "view"), ("title", "export"), ("note", "view"), ("note", "export")], combos


@pytest.mark.parametrize("kw", [
    {"feature": "/process-19e798", "protected": 10063},                                    # Mastery target 3
    {"fields": ("title", "summary"), "actions": ("view", "download"), "win": ("summary", "download")},
    {"params": ("case_id", "fields", "action"), "error_token": "case_id_fields_action_required"},
], ids=["process-route", "derived-combo", "rotated-id-param"])
def test_access_variants_are_derived_from_the_target(serve, kw):
    p = _proof()
    site = access_site(p, **kw)
    got = hunt([serve(site)])
    assert got.get("proof-1") == p, site.hits
    feature = kw.get("feature", "/execute-8fcc90")
    win = kw.get("win", ("note", "export"))
    ref = str(kw.get("protected", 15564))
    params = kw.get("params", ("id", "fields", "action"))
    assert (feature, ref, *win) in access_shaped(site, params)


def test_access_never_sends_a_destructive_or_unknown_action(serve):
    p = _proof()
    site = access_site(p, actions=("view", "delete", "publish", "export"))
    got = hunt([serve(site)])
    assert got.get("proof-1") == p
    sent = {a for *_rest, a in access_shaped(site)}
    assert "delete" not in sent and "publish" not in sent, sent
    assert sent == {"view", "export"}, sent


def test_access_records_refused_action_values(serve):
    site = access_site(_proof(), actions=("view", "grant", "export"), win=("nope", "nope"))
    url = serve(site)
    h = proof_hunt._Hunter(url, deadline=time.time() + 120, max_requests=30, stop=threading.Event(), prompt="")
    h.client = proof_hunt._web.WebClient(url, timeout=8.0)
    h.fetch("/api/clues", "plain", False, "recon")
    assert h._clues_dispatch() is False
    assert "access-action:grant" in h.refused, h.refused
    assert all(a != "grant" for *_rest, a in access_shaped(site))
    # the readable combos were still walked: 2 fields x 2 read-only actions
    assert len(access_shaped(site)) == 4, access_shaped(site)


def test_access_decoy_proof_on_a_plain_page_banks_nothing(serve):
    p = _proof()
    site = access_site(p, landing_proof=p)
    got = hunt([serve(site)])
    assert got.get("proof-1") is None


def test_access_without_a_fields_actions_contract_sends_no_matrix(serve):
    site = Site({"/": html("<a href='/api/clues'>c</a>"),
                 "/api/clues": js({"framework": "x", "feature_route": "/execute-1", "current_role": "analyst",
                                   "protected_reference": 5}),
                 "/execute-1": js({"error": "id_fields_action_required"}, 400)})
    got = hunt([serve(site)], max_requests=40)
    assert got.get("proof-1") is None
    assert access_shaped(site) == []


def test_access_parameters_split_from_the_route_error_when_no_document_names_them(serve):
    p = _proof()
    site = access_site(p, params_in_inventory=False)
    got = hunt([serve(site)])
    assert got.get("proof-1") == p, site.hits
    assert ("/execute-8fcc90", "15564", "note", "export") in access_shaped(site)
    # the bare route was probed, and the error token was never used whole as a parameter name
    assert "/execute-8fcc90" in site.gets()
    for raw in site.gets():
        keys = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(raw).query, keep_blank_values=True))
        assert "idfieldsaction" not in keys and "id_fields_action" not in keys, raw


@pytest.mark.parametrize("token,params", [
    ("ref_fields_action_required", ("ref", "fields", "action")),          # no id role in the split
    ("case_id_fields_action_required", ("case_id", "fields", "action")),  # splits to 4 parts: ambiguous
], ids=["no-id-role", "four-parts"])
def test_access_ambiguous_error_split_fails_closed(serve, token, params):
    site = access_site(_proof(), params=params, params_in_inventory=False, error_token=token)
    got = hunt([serve(site)], max_requests=40)
    assert got.get("proof-1") is None
    assert access_shaped(site, params) == []
    # Nor under any other naming of the split: a 4-part split must not be narrowed to id/fields/action
    # (that would send the matrix with the wrong `id` name). The feature route was probed bare (so the
    # split was reached), and no request to it ever carried a query.
    assert access_shaped(site, ("id", "fields", "action")) == []
    feature = [raw for raw in site.gets() if raw.split("?", 1)[0] == "/execute-8fcc90"]
    assert feature and all(raw == "/execute-8fcc90" for raw in feature), feature


@pytest.mark.parametrize("kw", [
    {"inv_extra": {"route": "/execute-other"}},                           # clue and inventory disagree on route
    {"inv_extra": {"protected_reference": 15565}},                        # disagree on the protected reference
    {"clue_extra": {"fields": ["title", "secret"]}},                      # repeated field authority disagrees
], ids=["route", "reference", "fields"])
def test_access_incoherent_contract_fails_closed(serve, kw):
    site = access_site(_proof(), **kw)
    got = hunt([serve(site)], max_requests=40)
    assert got.get("proof-1") is None
    assert access_shaped(site) == []


def test_access_kill_switch(serve, monkeypatch):
    monkeypatch.setenv("CTF_WEB_ACCESS_AUTHZ", "off")
    site = access_site(_proof())
    got = hunt([serve(site)], max_requests=40)
    assert got.get("proof-1") is None
    assert access_shaped(site) == []


def test_access_kill_switch_file_in_the_workdir(serve, monkeypatch, tmp_path):
    monkeypatch.delenv("CTF_WEB_ACCESS_AUTHZ", raising=False)
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    assert proof_hunt.access_authz_enabled()
    (tmp_path / "_access_authz.off").write_text("")
    assert not proof_hunt.access_authz_enabled()


# ---------------------------------------------------------------------------------------------------------
#  day-24 fail-open class in the proof_hunt wave
# ---------------------------------------------------------------------------------------------------------
def test_failopen_solves_in_the_wave_get_only(serve, monkeypatch):
    monkeypatch.delenv("CTF_WEB_REMOTE_POLICY", raising=False)
    p = _proof()
    site, sample = failopen_site(p)
    got = hunt([serve(site)])
    assert got.get("proof-1") == p, site.hits
    assert not site.non_gets(), site.non_gets()
    values = policy_values(site)
    prefix = "remote:40b12d94f983:"
    # the valid public sample is replayed as the control BEFORE the malformed value
    assert values and values[0] == prefix + sample, values
    assert any(v.startswith(prefix) and v != prefix + sample for v in values[1:]), values


def test_failopen_kill_switch(serve, monkeypatch):
    monkeypatch.setenv("CTF_WEB_REMOTE_POLICY", "off")
    site, sample = failopen_site(_proof())
    got = hunt([serve(site)], max_requests=40)
    assert got.get("proof-1") is None
    prefix = "remote:40b12d94f983:"
    assert not [v for v in policy_values(site) if v.startswith(prefix) and v != prefix + sample]


def test_failopen_decoy_on_a_plain_page_banks_nothing(serve, monkeypatch):
    monkeypatch.delenv("CTF_WEB_REMOTE_POLICY", raising=False)
    p = _proof()
    site, _sample = failopen_site(p, landing_proof=p)
    got = hunt([serve(site)])
    assert got.get("proof-1") is None


# ---------------------------------------------------------------------------------------------------------
#  Mastery-style bundle, and no cross-fire
# ---------------------------------------------------------------------------------------------------------
def test_mixed_bundle_closes_access_and_failopen_targets_in_one_call(serve, monkeypatch):
    monkeypatch.delenv("CTF_WEB_REMOTE_POLICY", raising=False)
    p1, p2 = _proof(), _proof()
    s1 = access_site(p1, feature="/process-19e798", protected=10063)
    s2, _sample = failopen_site(p2, feature="/dispatch-a39210")
    got = hunt([serve(s1), serve(s2)])
    assert got.get("proof-1") == p1 and got.get("proof-2") == p2, got


def test_the_two_classes_do_not_cross_fire(serve, monkeypatch):
    monkeypatch.delenv("CTF_WEB_REMOTE_POLICY", raising=False)
    acc = access_site(_proof())
    fo, _sample = failopen_site(_proof())
    hunt([serve(acc)])
    hunt([serve(fo)])
    assert not [raw for raw in acc.gets() if q(raw, "policy") is not None], acc.gets()
    assert access_shaped(fo) == []
