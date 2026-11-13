#!/usr/bin/env python3
"""Cross-module regressions for fail-closed target-authored route decoding."""

from __future__ import annotations

import sys
import json
import threading
import time
import urllib.parse
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
WEB = REPO / "solvers" / "web"
TOOLKITS = REPO / "solvers" / "toolkits"
sys.path[:0] = [str(WEB), str(TOOLKITS)]
sys.dont_write_bytecode = True

import endpoint_inventory as endpoint  # noqa: E402
import double_spend as double  # noqa: E402
import forge_event as forge  # noqa: E402
import graphql_read as graphql  # noqa: E402
import hpp_read as hpp  # noqa: E402
import passive_checks as passive  # noqa: E402
import post_chain as post  # noqa: E402
import proof_hunt as hunt  # noqa: E402
import realtime_read as realtime  # noqa: E402
import reset_rebind as reset  # noqa: E402
import ssrf_body as ssrf  # noqa: E402
import web  # noqa: E402
import xxe_read as xxe  # noqa: E402


BASE = "https://target.test/"


def encoded(value, count):
    for _ in range(count):
        value = urllib.parse.quote(value, safe="")
    return value


def guards(path):
    """Every executable target-route guard must reject the same bad path."""
    hunter = object.__new__(hunt._Hunter)
    endpoint_path = endpoint._safe_path(BASE, path)
    return {
        "toolkit": web.safe_same_origin_route(path, BASE),
        "endpoint": endpoint_path if endpoint_path and endpoint._safe_to_fetch(endpoint_path) else None,
        "forge": forge._route_value(path, BASE),
        "post": post._same_origin_route(path, BASE),
        "reset": reset._route(path, BASE),
        "passive": passive._same_origin_route(path, BASE),
        "graphql": graphql._same_origin_route(path, BASE),
        "xss": hunt._xss_path(path),
        "stateful": hunt._stateful_path(path),
        "spec": path if hunter._spec_route_safe(path) else None,
    }


def test_safe_historical_routes_survive():
    values = {
        "toolkit": web.safe_same_origin_route("/api/case-1", BASE),
        "endpoint": endpoint._safe_path(BASE, "/contracts/case.wsdl"),
        "forge": forge._route_value("/api/webhook?v=2", BASE),
        "post": post._same_origin_route("/api/profile", BASE),
        "reset": reset._route("/recovery/redeem", BASE),
        "passive": passive._same_origin_route("/api/private", BASE),
        "graphql": graphql._same_origin_route("/graphql", BASE),
        "xss": hunt._xss_path("/notes"),
        "stateful": hunt._stateful_path("/dispatch-case"),
        "spec": "/v1/cases" if hunt._Hunter._spec_route_safe("/v1/cases") else None,
    }
    assert all(values.values()), values
    assert web.safe_route_path("/api/cases/v1")
    assert web.safe_route_query_component("case-17")
    assert web.safe_same_origin_route("/api/search?q=case-17", BASE, allow_query=True)
    for route in ("/candidate", "/credit", "/report"):
        assert not web.route_has_destructive_action(route), route
        values = guards(route)
        assert all(values.values()), (route, values)


def test_embedded_urls_rejected_at_every_encoding_depth():
    inner = "http://169.254.169.254/latest/meta-data"
    for depth in (0, 1, 4, 6, 10, 13):
        path = "/proxy/" + encoded(inner, depth)
        result = guards(path)
        assert not any(result.values()), (depth, path, result)


def test_traversal_query_fragment_and_authority_rejected_deeply():
    hunter = object.__new__(hunt._Hunter)
    payloads = ("../admin", "?url=http://169.254.169.254/", "#fragment", "//evil.invalid/x",
                "g://evil.invalid/x", "g:opaque", "\x7fcontrol", "\u200bhidden")
    for raw in payloads:
        for depth in (1, 4, 10, 13):
            path = "/safe/" + encoded(raw, depth)
            result = guards(path)
            assert not any(result.values()), (raw, depth, path, result)
            assert not hunter.allowed(path, offered=False), (raw, depth, path)
            assert not hunter.allowed(path, offered=False, trusted=True), (raw, depth, path)


def test_offered_query_inner_url_never_outlasts_decode_cap():
    hunter = object.__new__(hunt._Hunter)
    inner = "http://169.254.169.254/latest/meta-data"
    for depth in (0, 1, 4, 6, 10, 13):
        value = encoded(inner, depth)
        assert not web.safe_route_query_component(value), (depth, value)
        assert not hunter.allowed("/proxy?url=" + value, offered=True), (depth, value)
    assert not web.safe_route_query_component("g://evil.invalid/x")
    assert not web.safe_route_query_component('{"url":"//169.254.169.254/latest"}')
    assert not web.safe_route_query_component('{"url":"https:evil.example/x"}')
    assert not web.safe_same_origin_route(
        "/fetch?payload=%7B%22url%22%3A%22%2F%2F169.254.169.254%2Flatest%22%7D",
        "http://target.local/", allow_query=True, guard_query=True)
    assert not web.safe_same_origin_route(
        "/fetch?payload=%7B%22url%22%3A%22https%3Aevil.example%2Fx%22%7D",
        "http://target.local/", allow_query=True, guard_query=True)
    assert not hunter.allowed("/proxy?url=g%3A%2F%2Fevil.invalid%2Fx", offered=True)
    # Locally generated, explicitly scoped exploit payloads retain the old
    # offered=False path; only target-authored query authority gained the new
    # whole-wire strictness check.
    assert hunter.allowed("/read?file=..%2Fetc%2Fpasswd", offered=False)


def test_trusted_clue_routes_waive_only_observed_benign_actions():
    hunter = object.__new__(hunt._Hunter)
    for route in ("/delete-all", "/reset-account", "/revoke-token", "/shutdown",
                  "/%2564%2565%256c%2565%2574%2565-all"):
        assert not hunter.allowed(route, offered=False, trusted=True), route
    for route in ("/execute-case", "/submit-note", "/upload-template",
                  "/process-case", "/inspect-case", "/dispatch-case"):
        assert hunter.allowed(route, offered=False, trusted=True), route


def test_fatal_feature_clue_never_reaches_transport():
    class Client:
        base = BASE
        timeout = 8

        def __init__(self):
            self.log = []

        def request(self, method, path, **_kwargs):
            self.log.append((method, path))
            if path == "/api/clues":
                body = json.dumps({
                    "feature_route": "/delete-all",
                    "fields": ["proof"], "actions": ["read"],
                    "protected_reference": "case-1",
                }).encode()
                return {"status": 200, "body": body,
                        "response_headers": {"Content-Type": "application/json"},
                        "final_url": BASE.rstrip("/") + path}
            return {"status": 404, "body": b"not found", "response_headers": {},
                    "final_url": BASE.rstrip("/") + path}

    client = Client()
    h = hunt._Hunter(BASE, deadline=time.time() + 5, max_requests=10,
                     stop=threading.Event(), prompt="")
    h.client = client
    h.fetch("/api/clues", "plain", False, "recon")
    assert h._clues_dispatch() is False
    assert all(path != "/delete-all" for _method, path in client.log), client.log


def test_unfinished_canonicalization_fails_closed():
    benign_but_excessive = encoded("/ordinary", web.ROUTE_DECODE_ROUNDS + 2)
    assert web.canonical_route_layers(benign_but_excessive) is None
    assert not web.safe_route_query_component(benign_but_excessive)
    for value in (" /ordinary", "/ordinary ", "/ordi\tnary"):
        assert web.safe_same_origin_route(value, BASE) is None
        assert forge._route_value(value, BASE) is None
        assert post._same_origin_route(value, BASE) is None
        assert reset._route(value, BASE) is None
        assert passive._same_origin_route(value, BASE) is None
        assert graphql._same_origin_route(value, BASE) is None
        assert hunt._xss_path(value) is None
        assert hunt._stateful_path(value) is None
        hunter = object.__new__(hunt._Hunter)
        hunter.url = BASE
        assert hunter._same_host(value, "/") is None


def test_compound_delimited_and_malformed_destructive_routes_fail_closed():
    """Every peer rejects semantic actions, not merely regex-delimited words."""
    destructive = (
        "/deleteuser", "/userdelete", "/deleteaccountbyid", "/deleteallusers",
        "/preview;delete", "/preview%3Bdelete", "/preview,delete", "/preview+delete",
        "/bulkdeleteusers", "/userdeletebyid", "/ｄｅｌｅｔｅuser",
        "/" + encoded("ｄｅｌｅｔｅuser", 1),
        "/deletecart", "/deleteinvoice", "/deletemessage", "/deletebucket",
        "/deleterepository", "/deletepolicy", "/cartdelete", "/invoicedelete",
        "/policydelete",
    )
    for path in destructive:
        values = guards(path)
        # The low-level toolkit parser only establishes structural same-origin
        # scope. Every executable consumer adds the shared destructive floor.
        values.pop("toolkit", None)
        values.update({
            "double": double._route(path, BASE),
            "hpp": hpp._safe_route(path, BASE),
            "realtime": realtime._route(path, BASE),
            "ssrf": ssrf._safe_route(path, BASE),
            "xxe": xxe._safe_route(path, BASE),
        })
        assert not any(values.values()), (path, values)

    for malformed in ("/%u002fdelete", "/%c0%afdelete", "/%ed%a0%80"):
        values = guards(malformed)
        values.update({
            "double": double._route(malformed, BASE),
            "hpp": hpp._safe_route(malformed, BASE),
            "realtime": realtime._route(malformed, BASE),
            "ssrf": ssrf._safe_route(malformed, BASE),
            "xxe": xxe._safe_route(malformed, BASE),
        })
        assert not any(values.values()), (malformed, values)

    for traversal in (
            "/safe／．．／admin",
            "/safe%EF%BC%8F%EF%BC%8E%EF%BC%8E%EF%BC%8Fadmin"):
        values = guards(traversal)
        values.update({
            "double": double._route(traversal, BASE),
            "hpp": hpp._safe_route(traversal, BASE),
            "realtime": realtime._route(traversal, BASE),
            "ssrf": ssrf._safe_route(traversal, BASE),
            "xxe": xxe._safe_route(traversal, BASE),
        })
        assert not any(values.values()), (traversal, values)


def test_recursive_query_action_is_rejected_at_every_layer():
    hunter = object.__new__(hunt._Hunter)
    for depth in (0, 1, 3, 7, 11):
        key = encoded("deleteuser", depth)
        value = encoded("deleteaccountbyid", depth)
        route = "/safe?" + key + "=" + value
        assert web.safe_same_origin_route(route, BASE, allow_query=True) is None, route
        assert forge._route_value(route, BASE) is None, route
        assert passive._same_origin_route(route, BASE, allow_query=True) is None, route
        assert not endpoint._safe_to_fetch(route), route
        assert not hunter.allowed(route, offered=True), route

    for malformed in ("%", "%2", "%GG", "%u002f", "%c0%afordinary", "%ed%a0%80", "%ff"):
        route = "/safe?value=" + malformed
        assert web.safe_same_origin_route(route, BASE, allow_query=True) is None, route
        assert forge._route_value(route, BASE) is None, route
        assert passive._same_origin_route(route, BASE, allow_query=True) is None, route
        assert not hunter.allowed(route, offered=True), route

    smuggled = (
        "/safe?value=ordinary;action=deleteuser",
        "/safe?value=ordinary%3Baction%3Ddeleteuser",
        "/safe?value=ordinary%26action%3Ddeleteuser",
        "/safe?value=ordinary%2526action%253Ddeleteuser",
        "/safe?ordinary%26deleteuser=1",
    )
    for route in smuggled:
        assert web.safe_same_origin_route(route, BASE, allow_query=True) is None, route
        assert forge._route_value(route, BASE) is None, route
        assert passive._same_origin_route(route, BASE, allow_query=True) is None, route
        assert not hunter.allowed(route, offered=True), route


def main():
    tests = (
        test_safe_historical_routes_survive,
        test_embedded_urls_rejected_at_every_encoding_depth,
        test_traversal_query_fragment_and_authority_rejected_deeply,
        test_offered_query_inner_url_never_outlasts_decode_cap,
        test_trusted_clue_routes_waive_only_observed_benign_actions,
        test_fatal_feature_clue_never_reaches_transport,
        test_unfinished_canonicalization_fails_closed,
        test_compound_delimited_and_malformed_destructive_routes_fail_closed,
        test_recursive_query_action_is_rejected_at_every_layer,
    )
    failed = []
    for test in tests:
        try:
            test()
            print("ok  ", test.__name__)
        except Exception as exc:  # noqa: BLE001 - standalone regression reports all cases
            failed.append(test.__name__)
            print("FAIL", test.__name__, type(exc).__name__, str(exc)[:1000])
    print(("FAIL" if failed else "PASS"), "test_web_route_canonicalization", len(failed), "failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
