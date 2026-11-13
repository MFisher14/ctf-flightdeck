#!/usr/bin/env python3
"""Regression tests for bounded CORS/open-redirect/OIDC passive checks."""

import event_pin  # noqa: E402  (tests/event_pin.py)
event_pin.pin(globals(), "huntress")  # Huntress web tests: proof_<32 hex> payoffs (events/huntress [proof])

import json
import sys
import time
import urllib.parse
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "web"))
import passive_checks as P  # noqa: E402


PROOF = "proof_0123456789ab4def8abc0123456789ab"
DECOY = "proof_aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa"


def page(value, status=200, headers=None, pairs=None):
    body = value if isinstance(value, bytes) else json.dumps(value).encode() if not isinstance(value, str) else value.encode()
    out = {"status": status, "body": body, "response_headers": dict(headers or {})}
    if pairs is not None:
        out["response_header_pairs"] = list(pairs)
    return out


class Client:
    def __init__(self, routes, base="http://target.test"):
        self.base = base
        self.routes = routes
        self.calls = []
        self.timeout = 5

    def request(self, method, path, data=None, headers=None, allow_redirects=True):
        self.calls.append((method, path, dict(headers or {}), allow_redirects))
        key = (path, (headers or {}).get("Origin"))
        answer = self.routes.get(key)
        if answer is None and (headers or {}).get("Origin"):
            answer = self.routes.get((path, "*"))
        if answer is None:
            answer = self.routes.get(path, self.routes.get(path.split("?", 1)[0], page({}, 404)))
        if callable(answer):
            answer = answer(path, dict(headers or {}))
        return dict(answer)


def run(clues, routes=None, max_requests=6, client_base="http://target.test", clue_status=200,
        baseline_texts=None):
    client = Client(routes or {}, client_base)
    sink, evidence = {}, []
    ctx = {
        "client": client,
        "deadline": time.time() + 10,
        "max_requests": max_requests,
        "preloaded": {"/": page({"landing": DECOY}), "/api/clues": page(clues, clue_status)},
        "baseline_texts": ([json.dumps({"landing": DECOY}), json.dumps(clues)]
                           if baseline_texts is None else list(baseline_texts)),
        "result_sink": sink,
        "evidence": evidence,
    }
    proof = P.solve({"url": "http://target.test", "answer_id": "a"}, ctx)
    return proof, sink["a"], client.calls, evidence


def check(name, condition, detail=None):
    if not condition:
        raise AssertionError(f"{name}: {detail!r}")
    print("PASS", name)


def test_no_contract_zero_wire():
    proof, summary, calls, _ = run({"feature": "ordinary search"})
    check("no contract returns no proof", proof is None)
    check("no contract uses cached recon and sends zero requests", summary["requests"] == 0 and calls == [], summary)

    proof, summary, calls, _ = run({"cors_route": "/api/private"}, clue_status=403)
    check("non-2xx clue JSON cannot authorize a passive protocol probe",
          proof is None and summary["requests"] == 0 and calls == [], summary)


def test_cors_novel_proof():
    def cors(_path, headers):
        origin = headers["Origin"]
        return page({"proof": PROOF}, headers={"Access-Control-Allow-Origin": origin,
                                                "Access-Control-Allow-Credentials": "true"})

    routes = {
        "/api/private": page({"role": "user"}),
        ("/api/private", "*"): cors,
    }
    proof, summary, calls, _ = run({"cors_route": "/api/private"}, routes)
    check("confirmed credentialed exact-origin CORS returns novel proof", proof == PROOF, summary)
    check("distinct landing decoy does not hide CORS payoff", DECOY not in summary["candidates"], summary)
    check("CORS uses one control and one fixed-origin GET", len(calls) == 2 and
          calls[1][2].get("Origin", "").endswith(".cors.huntress.invalid")
          and all(c[0] == "GET" for c in calls), calls)
    check("CORS never follows redirects", all(c[3] is False for c in calls), calls)


def test_cors_requires_credentials_and_exact_origin():
    routes = {
        "/api/private": page({"role": "user"}),
        ("/api/private", "*"): page(
            {"proof": PROOF}, headers={"Access-Control-Allow-Origin": "*"}),
    }
    proof, summary, _calls, _ = run({"feature": "CORS", "protected_route": "/api/private"}, routes)
    check("wildcard/noncredentialed CORS is not a solve", proof is None)
    check("failed CORS evidence is explicit", summary["findings"][0]["confirmed"] is False, summary)


def test_cors_requires_complete_control_and_complete_baselines():
    def cors(_path, headers):
        origin = headers["Origin"]
        return page({"proof": PROOF}, headers={"Access-Control-Allow-Origin": origin,
                                                "Access-Control-Allow-Credentials": "true"})

    def dropped_control(_path, _headers):
        raise OSError("control connection dropped")

    proof, summary, calls, _ = run({"cors_route": "/api/private"}, {
        "/api/private": dropped_control,
        ("/api/private", "*"): cors,
    })
    check("CORS transport failure on the plain control prevents the Origin probe",
          proof is None and len(calls) == 1
          and summary["findings"][0]["evidence"] == "control_unavailable_or_incomplete",
          (summary, calls))

    proof, summary, calls, _ = run(
        {"cors_route": "/api/private"},
        {"/api/private": page({"role": "user"}), ("/api/private", "*"): cors},
        baseline_texts=[f"ordinary-{index}" for index in range(40)] + [PROOF],
    )
    check("CORS baseline cap+1 is marked incomplete and cannot promote the dropped decoy",
          proof is None and len(calls) == 2 and summary["baseline_incomplete"] is True,
          (summary, calls))


def test_cors_conflicting_or_repeated_policy_headers_fail_closed():
    def cors(_path, headers):
        origin = headers["Origin"]
        return page({"ok": True, "proof": PROOF}, headers={
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
        }, pairs=[
            ("Access-Control-Allow-Origin", origin),
            ("Access-Control-Allow-Origin", "https://other.invalid"),
            ("Access-Control-Allow-Credentials", "true"),
            ("Access-Control-Allow-Credentials", "true"),
        ])

    proof, summary, calls, _ = run({"cors_route": "/api/private"}, {
        "/api/private": page({"role": "user"}),
        ("/api/private", "*"): cors,
    })
    check("duplicate CORS policy fields cannot auto-authorize a proof",
          proof is None and len(calls) == 2
          and summary["findings"][0]["confirmed"] is False, summary)


def test_open_redirect_detection_only():
    def redirect(raw, _headers):
        value = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(raw).query))["next"]
        return page("", 302, {"Location": value})

    proof, summary, calls, _ = run(
        {"redirect_route": "/go", "redirect_parameter": "next"},
        {"/go": redirect},
    )
    check("open redirect is surfaced but never auto-answered", proof is None)
    finding = next(row for row in summary["findings"] if row["class"] == "open_redirect")
    check("open redirect exact external Location confirms", finding["confirmed"] is True, finding)
    redirect_value = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(calls[0][1]).query)).get("next")
    check("redirect probe is one nonce GET and is not followed",
          len(calls) == 1 and calls[0][0] == "GET" and calls[0][3] is False
          and urllib.parse.urlsplit(redirect_value).hostname.endswith(".invalid"), calls)


def test_open_redirect_rejects_target_authored_query():
    for route in ("/go?url=http%3A%2F%2Finternal%2F", "/go?action=delete", "/go?next=already-set"):
        proof, summary, calls, _ = run(
            {"redirect_route": route, "redirect_parameter": "next"},
            {"/go": page("", 302, {"Location": "https://unexpected.invalid/"})},
        )
        check("open redirect route query is never activated", proof is None and calls == [], (route, summary, calls))


def test_oidc_versions_and_jwks_metadata_only():
    config = {
        "issuer": "http://target.test",
        "authorization_endpoint": "http://target.test/oauth/authorize",
        "token_endpoint": "http://target.test/oauth/token",
        "jwks_uri": "http://target.test/keys",
        "id_token_signing_alg_values_supported": ["RS256", "ES256"],
    }
    keys = {"keys": [
        {"kid": "rsa-1", "kty": "RSA", "alg": "RS256", "n": "public-modulus", "e": "AQAB"},
        {"kid": "ec-1", "kty": "EC", "crv": "P-256", "x": "x", "y": "y"},
        {"kid": "symmetric", "kty": "oct", "k": "never-copy-this-secret"},
    ]}
    proof, summary, calls, _ = run(
        {"oidc_configuration_route": "/.well-known/openid-configuration"},
        {"/.well-known/openid-configuration": page(config), "/keys": page(keys)},
    )
    check("OIDC discovery is recon only", proof is None)
    finding = next(row for row in summary["findings"] if row["class"] == "oidc")
    check("OIDC algorithms and RSA/EC/OKP-style metadata are summarized",
          finding["algorithms"] == ["RS256", "ES256"] and len(finding["public_key_summaries"]) == 3, finding)
    check("JWKS coordinates and symmetric key bytes are never copied",
          "public-modulus" not in json.dumps(finding) and "never-copy-this-secret" not in json.dumps(finding), finding)
    check("OIDC reads only same-origin discovery and JWKS", [c[1] for c in calls] ==
          ["/.well-known/openid-configuration", "/keys"], calls)


def test_offorigin_destructive_and_scope_mismatch_fail_closed():
    proof, summary, calls, _ = run({
        "cors_route": "https://evil.example/private",
        "redirect_route": "/delete/account",
        "redirect_parameter": "next",
        "oidc_configuration_route": "https://issuer.example/.well-known/openid-configuration",
    })
    check("off-origin and destructive contracts send nothing", proof is None and calls == [], (summary, calls))
    for route in ("/deleteUser", "/transferFunds", "/createJob", "/rebootNow"):
        proof, summary, calls, _ = run({"cors_route": route, "feature": "CORS"})
        check("camelCase destructive passive route sends nothing",
              proof is None and calls == [], (route, summary, calls))
    proof, summary, calls, _ = run({"cors_route": "/api/private"}, client_base="http://other.test")
    check("injected client with a different origin is refused", proof is None and summary["requests"] == 0 and calls == [], summary)


def test_conflicting_passive_aliases_are_zero_wire():
    cases = (
        {"cors_route": "/api/a", "cross_origin_route": "/api/b", "feature": "CORS"},
        {"feature": "CORS", "protected_route": "/api/a", "read_route": "/api/b"},
        {"redirect_route": "/go", "redirect_endpoint": "/elsewhere",
         "redirect_parameter": "next"},
        {"redirect_route": "/go", "redirect_parameter": "next",
         "return_url_parameter": "return_to"},
        {"oidc_configuration_route": "/.well-known/openid-configuration",
         "openid_configuration_route": "/oauth/metadata"},
    )
    for clues in cases:
        proof, summary, calls, _ = run(clues)
        check("conflicting passive aliases never select a first route/parameter",
              proof is None and calls == [] and summary["requests"] == 0,
              (clues, summary, calls))

    proof, summary, calls, _ = run({
        "redirect_route": "/go", "redirect_endpoint": "/go",
        "redirect_parameter": "next", "return_url_parameter": "next",
    }, {"/go": page("", 302, {"Location": "https://not-the-canary.invalid/"})})
    check("equivalent passive aliases retain one bounded probe",
          proof is None and len(calls) == 1 and summary["requests"] == 1, (summary, calls))


def test_global_request_bound():
    clues = {
        "cors_route": "/api/private",
        "redirect_route": "/go",
        "redirect_parameter": "next",
        "oidc_configuration_route": "/.well-known/openid-configuration",
    }
    def cors(_path, headers):
        return page({}, headers={"Access-Control-Allow-Origin": headers["Origin"]})

    def redirect(raw, _headers):
        value = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(raw).query))["next"]
        return page("", 302, {"Location": value})

    routes = {
        "/api/private": page({}),
        ("/api/private", "*"): cors,
        "/go": redirect,
        "/.well-known/openid-configuration": page({"issuer": "http://target.test", "jwks_uri": "/keys"}),
        "/keys": page({"keys": []}),
    }
    _proof, summary, calls, _ = run(clues, routes, max_requests=3)
    check("one absolute request cap covers every protocol", summary["requests"] == 3 and len(calls) == 3, summary)


if __name__ == "__main__":
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_") and callable(value)]
    failures = 0
    for test in tests:
        try:
            test()
        except Exception as exc:
            failures += 1
            print("FAIL", test.__name__, type(exc).__name__, exc)
    print(f"RESULT {len(tests) - failures}/{len(tests)}")
    raise SystemExit(1 if failures else 0)
