#!/usr/bin/env python3
"""Focused fake-server tests for the exact-contract in-band XXE peer."""

import event_pin  # noqa: E402  (tests/event_pin.py)
event_pin.pin(globals(), "huntress")  # Huntress web tests: proof_<32 hex> payoffs (events/huntress [proof])

import io
import json
import os
import re
import sys
import threading
import time
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "web"))
os.environ["CTF_WEB_XXE_READ"] = "on"
import xxe_read as X  # noqa: E402


TARGET = "https://xml-unit.2026.huntress.ctf.games/"
OBJECTIVE = "/run/huntress/objective.txt"
PRIVATE_TARGET = "http://10.22.0.9:8080/app/"
PROOF = "proof_0123456789ab4def8abc0123456789ab"
DECOY = "proof_aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa"
PASSWD = b"root:x:0:0:root:/root:/bin/sh\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"


def page(value, status=200, headers=None):
    if isinstance(value, bytes):
        body = value
    elif isinstance(value, str):
        body = value.encode()
    else:
        body = json.dumps(value, separators=(",", ":")).encode()
    return {"status": status, "body": body, "response_headers": dict(headers or {})}


class XMLClient:
    def __init__(self, *, base=TARGET, negative_leaks=False, passwd_works=True,
                 baseline=None, objective_proof=PROOF):
        self.base = base
        self.timeout = 5
        self.calls = []
        self.negative_leaks = negative_leaks
        self.passwd_works = passwd_works
        self.baseline = page({"ok": True, "parsed": "huntress-xxe-baseline"}) \
            if baseline is None else baseline
        self.objective_proof = objective_proof

    def request(self, method, path, data=None, headers=None, allow_redirects=True):
        body = data.decode() if isinstance(data, bytes) else str(data or "")
        self.calls.append((method, path, body, dict(headers or {}), allow_redirects))
        match = re.search(r'SYSTEM\s+"file://([^"\r\n]+)"', body)
        if match is None:
            return dict(self.baseline)
        filename = match.group(1)
        if filename == "/etc/passwd":
            return page(PASSWD if self.passwd_works else b"entity disabled")
        if "huntress_absent_" in filename:
            return page(PASSWD if self.negative_leaks else b"file not found")
        if filename == OBJECTIVE:
            return page({"ok": True, "proof": self.objective_proof})
        return page({"error": "unrecognized local file"}, 404)


def clues(**updates):
    value = {
        "xml_route": "/api/parse-8f2",
        "xml_method": "POST",
        "xml_content_type": "application/xml",
        "xml_root": "document",
        "xml_field": "content",
        "objective_file": OBJECTIVE,
    }
    value.update(updates)
    return value


def run(*, clue=None, preloaded=None, prompt="", client=None, max_requests=8,
        target=TARGET, stop=None, baseline_texts=None, clue_status=200,
        route_allowed=None):
    client = client or XMLClient(base=target)
    cached = {
        "/": page({"service": "xml", "decoy": DECOY}),
        "/api/clues": page(clues() if clue is None else clue, clue_status),
    } if preloaded is None else dict(preloaded)
    sink, evidence = {}, []
    ctx = {
        "client": client,
        "deadline": time.time() + 10,
        "max_requests": max_requests,
        "preloaded": cached,
        "baseline_texts": list(baseline_texts or []),
        "result_sink": sink,
        "evidence": evidence,
        "prompt": prompt,
        "stop": stop,
    }
    if route_allowed is not None:
        ctx["route_allowed"] = route_allowed
    proof = X.solve({"url": target, "answer_id": "answer"}, ctx)
    return proof, sink["answer"], client.calls, evidence


def check(name, condition, detail=None):
    if not condition:
        raise AssertionError(f"{name}: {detail!r}")
    print("PASS", name)


def test_clue_contract_happy_path():
    proof, summary, calls, _ = run()
    check("exact clue XML contract returns objective proof", proof == PROOF, summary)
    check("XXE sequence is exactly four POSTs", summary["requests"] == 4
          and summary["posts"] == 4 and len(calls) == 4
          and all(row[0] == "POST" for row in calls), (summary, calls))
    check("entity-bearing sequence is terminal", summary["terminal"] is True
          and summary["entity_requests"] == 3 and summary["confirmed"] is True, summary)
    check("all XML requests use one exact route and never follow redirects",
          {row[1] for row in calls} == {"/api/parse-8f2"}
          and all(row[3].get("Content-Type") == "application/xml" for row in calls)
          and all(row[4] is False for row in calls), calls)
    systems = [re.findall(r'SYSTEM\s+"file://([^"\r\n]+)"', row[2]) for row in calls]
    check("sequence is benign, passwd, nonexistent control, objective",
          systems[0] == [] and systems[1] == ["/etc/passwd"]
          and len(systems[2]) == 1 and "huntress_absent_" in systems[2][0]
          and systems[3] == [OBJECTIVE], systems)
    check("no OOB or wrapper entity is generated",
          all("http://" not in row[2] and "https://" not in row[2]
              and "php://" not in row[2] for row in calls), calls)


def test_openapi_only_exact_contract():
    spec = {
        "openapi": "3.1.0",
        "paths": {
            "/xml/read-3": {
                "post": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/xml": {
                                "schema": {
                                    "type": "object",
                                    "xml": {"name": "parcel"},
                                    "properties": {"payload": {"type": "string"}},
                                    "required": ["payload"],
                                }
                            }
                        },
                    }
                }
            }
        },
    }
    client = XMLClient()
    proof, summary, calls, _ = run(
        preloaded={"/": page({"service": "xml"}), "/openapi.json": page(spec)},
        prompt=f"The proof is in the objective file {OBJECTIVE}\n",
        client=client,
    )
    check("one OpenAPI XML POST plus prompt objective is sufficient", proof == PROOF, summary)
    check("OpenAPI schema supplies exact root and field",
          len(calls) == 4 and all(row[1] == "/xml/read-3" for row in calls)
          and all("<parcel><payload>" in row[2] for row in calls), calls)


def test_clue_negative_authority_cannot_be_overridden_by_openapi():
    spec = {
        "openapi": "3.1.0",
        "paths": {
            "/api/parse-8f2": {
                "post": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/xml": {
                                "schema": {
                                    "type": "object",
                                    "xml": {"name": "document"},
                                    "properties": {"content": {"type": "string"}},
                                    "required": ["content"],
                                }
                            }
                        },
                    }
                }
            }
        },
    }
    for label, bad_clues in (
        ("GET method", clues(xml_method="GET")),
        ("JSON media", clues(xml_content_type="application/json")),
    ):
        proof, summary, calls, _ = run(
            preloaded={"/": page({"service": "xml"}),
                       "/api/clues": page(bad_clues),
                       "/openapi.json": page(spec)},
            client=XMLClient(),
        )
        check(f"OpenAPI cannot override explicit clue {label}",
              proof is None and summary["requests"] == 0 and calls == [], summary)

    conflicting = clues(xml_root="clueRoot")
    proof, summary, calls, _ = run(
        preloaded={"/api/clues": page(conflicting), "/openapi.json": page(spec)},
        client=XMLClient(),
    )
    check("two complete XML authorities must agree on the request shape",
          proof is None and summary["requests"] == 0 and calls == [], summary)


def _xml_operation(*, security_marker=False):
    operation = {
        "requestBody": {"required": True, "content": {
            "application/xml": {"schema": {
                "type": "object", "xml": {"name": "parcel"},
                "properties": {"payload": {"type": "string"}},
                "required": ["payload"],
            }}
        }}
    }
    if security_marker is not False:
        operation["security"] = security_marker
    return operation


def test_openapi_tail_ambiguity_and_security_are_zero_wire():
    paths = {"/first": {"post": _xml_operation()}}
    paths.update((f"/filler-{index}", {"get": {}}) for index in range(199))
    paths["/second"] = {"post": _xml_operation()}
    ambiguous = {"openapi": "3.1.0", "paths": paths}
    proof, summary, calls, _ = run(
        preloaded={"/openapi.json": page(ambiguous)},
        prompt=f"The proof is in the objective file {OBJECTIVE}", client=XMLClient())
    check("an eligible OpenAPI route beyond the old 200-path prefix remains ambiguous",
          proof is None and summary["requests"] == 0 and calls == [], summary)

    protected = {"openapi": "3.1.0", "security": [{"bearerAuth": []}],
                 "paths": {"/xml/read": {"post": _xml_operation()}}}
    proof, summary, calls, _ = run(
        preloaded={"/openapi.json": page(protected)},
        prompt=f"The proof is in the objective file {OBJECTIVE}", client=XMLClient())
    check("root OpenAPI security is inherited and blocks the cookie-bearing POST",
          proof is None and summary["requests"] == 0 and calls == [], summary)

    public_override = {"openapi": "3.1.0", "security": [{"bearerAuth": []}],
                       "paths": {"/xml/read": {"post": _xml_operation(security_marker=[])}}}
    proof, summary, calls, _ = run(
        preloaded={"/openapi.json": page(public_override)},
        prompt=f"The proof is in the objective file {OBJECTIVE}", client=XMLClient())
    check("an explicit empty operation security override remains eligible",
          proof == PROOF and len(calls) == 4, summary)

    referenced = {"openapi": "3.1.0", "paths": {
        "/xml/read": {"post": {
            **_xml_operation(),
            "parameters": [{"$ref": "#/components/parameters/Auth"}],
        }}}, "components": {"parameters": {
            "Auth": {"in": "header", "name": "X-API-Key", "required": True,
                     "schema": {"type": "string"}}
        }}}
    proof, summary, calls, _ = run(
        preloaded={"/openapi.json": page(referenced)},
        prompt=f"The proof is in the objective file {OBJECTIVE}", client=XMLClient())
    check("a required local-ref OpenAPI parameter blocks an incomplete request",
          proof is None and summary["requests"] == 0 and calls == [], summary)


def test_exact_gates_are_zero_wire():
    cases = [
        (clues(xml_method="GET"), 200, TARGET, XMLClient()),
        (clues(xml_content_type="application/json"), 200, TARGET, XMLClient()),
        (clues(xml_route="/api/parse/{id}"), 200, TARGET, XMLClient()),
        ({key: value for key, value in clues().items() if key != "xml_root"}, 200, TARGET, XMLClient()),
        ({key: value for key, value in clues().items() if key != "xml_field"}, 200, TARGET, XMLClient()),
        (clues(objective_file="/run/../etc/shadow"), 200, TARGET, XMLClient()),
        (clues(xml_route="/deleteUser"), 200, TARGET, XMLClient()),
        (clues(xml_route="/transferFunds"), 200, TARGET, XMLClient()),
        (clues(request_method="GET"), 200, TARGET, XMLClient()),
        (clues(parser_route="/different-route"), 200, TARGET, XMLClient()),
        (clues(request_content_type="text/xml"), 200, TARGET, XMLClient()),
        (clues(), 403, TARGET, XMLClient()),
        (clues(), 200, "file:///tmp/not-a-target", XMLClient(base="file:///tmp/not-a-target")),
    ]
    for clue, status, target, client in cases:
        proof, summary, calls, _ = run(
            clue=clue, clue_status=status, target=target, client=client)
        check("invalid/off-scope XML contract sends nothing",
              proof is None and summary["requests"] == 0 and calls == [], summary)


def test_destructive_route_compounds_and_separators_are_zero_wire():
    routes = (
        "/deleteuser", "/resetpassword", "/createjob", "/transferfunds",
        "/delete;foo", "/reset,confirm", "/logout+now",
    )
    for route in routes:
        proof, summary, calls, _ = run(clue=clues(xml_route=route))
        check("lowercase compound/separated destructive XML route sends nothing",
              proof is None and summary["requests"] == 0 and calls == [],
              (route, summary))


def test_dtd_path_metacharacters_are_zero_wire_and_private_targets_work():
    bad = (
        '/run/huntress/x" ]><!ENTITY p SYSTEM "file:///etc/passwd">',
        "/run/huntress/<objective>",
        "/run/huntress/a&b", "/run/huntress/a b", "/run/huntress/a\tb",
        "/run/huntress/[objective]", "/run/huntress/a;b",
        "/run/huntress/%22objective", "/run/huntress/objective?.txt",
    )
    for path in bad:
        proof, summary, calls, _ = run(clue=clues(objective_file=path))
        check("DTD/objective path metacharacter sends nothing",
              proof is None and summary["requests"] == 0 and calls == [], (path, summary))

    client = XMLClient(base=PRIVATE_TARGET)
    proof, summary, calls, _ = run(client=client, target=PRIVATE_TARGET)
    check("scope-matched GM private-IP target is accepted",
          proof == PROOF and len(calls) == 4, summary)


def test_objective_tail_conflict_is_zero_wire():
    clue = {"objective_file": OBJECTIVE}
    clue.update((f"filler_{index}", "x") for index in range(199))
    clue["target_file"] = "/etc/shadow"
    clue.update({key: value for key, value in clues().items()
                 if key != "objective_file"})
    proof, summary, calls, _ = run(clue=clue)
    check("a conflicting objective beyond the old member prefix blocks the sequence",
          proof is None and summary["requests"] == 0 and calls == [], summary)


def test_ambiguous_openapi_body_shapes_are_zero_wire():
    def spec(properties, required):
        return {
            "openapi": "3.1.0",
            "paths": {"/xml/read": {"post": {"requestBody": {"content": {
                "application/xml": {"schema": {"type": "object", "xml": {"name": "parcel"},
                                                "properties": properties, "required": required}}
            }}}}},
        }

    variants = (
        spec({"payload": {"type": "string"}, "tenant": {"type": "string"}}, ["payload", "tenant"]),
        spec({"payload": {"type": "string"}, "note": {"type": "string"}}, []),
        {"openapi": "3.1.0", "paths": {"/xml/read": {"post": {"requestBody": {"content": {
            "application/xml": {"schema": {"type": "object", "properties": {
                "payload": {"type": "string"}}, "required": ["payload"]}}
        }}}}}},
    )
    for doc in variants:
        client = XMLClient()
        proof, summary, calls, _ = run(
            preloaded={"/openapi.json": page(doc)},
            prompt=f"The proof is in the objective file {OBJECTIVE}\n",
            client=client,
        )
        check("ambiguous/incomplete OpenAPI XML body shape sends nothing",
              proof is None and summary["requests"] == 0 and calls == [], summary)


def test_controls_fail_closed():
    client = XMLClient(negative_leaks=True)
    proof, summary, calls, _ = run(client=client)
    check("nonexistent-file marker reflection blocks objective",
          proof is None and len(calls) == 3 and summary["entity_requests"] == 2
          and summary["terminal"] is True and summary["confirmed"] is False, summary)

    client = XMLClient(passwd_works=False)
    proof, summary, calls, _ = run(client=client)
    check("missing passwd marker stops before negative and objective",
          proof is None and len(calls) == 2 and summary["entity_requests"] == 1
          and summary["terminal"] is True, summary)

    client = XMLClient(baseline=page(PASSWD))
    proof, summary, calls, _ = run(client=client)
    check("passwd marker in benign baseline prevents any entity request",
          proof is None and len(calls) == 1 and summary["entity_requests"] == 0
          and summary["terminal"] is False, summary)


def test_container_filename_or_mime_header_cannot_confirm_passwd_read():
    marker = "root:x:0:0:root:/root:/bin/sh"
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr(marker, b"harmless")
    mime = (f"--B\r\nContent-Type: text/plain\r\n"
            f"Content-Disposition: attachment; filename=\"{marker}\"\r\n\r\n"
            "harmless\r\n--B--\r\n").encode()

    class CarrierClient(XMLClient):
        def __init__(self, forged):
            super().__init__()
            self.forged = forged

        def request(self, method, path, data=None, headers=None, allow_redirects=True):
            body = data.decode() if isinstance(data, bytes) else str(data or "")
            if 'SYSTEM "file:///etc/passwd"' not in body:
                return super().request(method, path, data, headers, allow_redirects)
            self.calls.append((method, path, body, dict(headers or {}), allow_redirects))
            return dict(self.forged)

    cases = (
        page(archive.getvalue(), headers={"Content-Type": "application/zip"}),
        page(mime, headers={"Content-Type": "multipart/mixed; boundary=B"}),
        page(b"harmless", headers={"X-Decoy": marker}),
    )
    for forged in cases:
        client = CarrierClient(forged)
        proof, summary, calls, _ = run(client=client)
        check("container/header metadata does not confirm the passwd marker",
              proof is None and len(calls) == 2 and summary["confirmed"] is False
              and summary["entity_requests"] == 1, (summary, calls))


def test_unsafe_archive_sibling_poisoned_contract_is_zero_wire():
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("clue.json", json.dumps(clues(), separators=(",", ":")))
        bundle.writestr("../outside.txt", b"poison sibling")
    proof, summary, calls, _ = run(preloaded={
        "/api/clues": page(archive.getvalue(), headers={"Content-Type": "application/zip"}),
    })
    check("unsafe ZIP sibling poisons an otherwise valid XML POST authority document",
          proof is None and summary["requests"] == 0 and calls == [], summary)


def test_query_specific_and_colliding_cache_entries_are_not_authority():
    for cached in (
            {"/api/clues?mode=privileged": page(clues())},
            {"/api/clues": page(clues()), "/%61pi/clues": page(clues())}):
        proof, summary, calls, _ = run(preloaded=cached)
        check("query-view or normalized-collision XML authority is zero-wire",
              proof is None and summary["requests"] == 0 and calls == [], summary)
    late = {"/api/clues": page(clues())}
    late.update({f"/filler-{index}": page({"ordinary": index}) for index in range(39)})
    late["/%61pi/clues"] = page(clues())
    proof, summary, calls, _ = run(preloaded=late)
    check("an XML cache collision after the old 40-entry prefix is zero-wire",
          proof is None and summary["requests"] == 0 and calls == [], summary)


def test_shared_controls_and_baseline_novelty():
    proof, summary, calls, _ = run(max_requests=3)
    check("incomplete four-call budget sends nothing",
          proof is None and summary["requests"] == 0 and calls == [], summary)

    stopped = threading.Event()
    stopped.set()
    proof, summary, calls, _ = run(stop=stopped)
    check("shared stop event sends nothing",
          proof is None and summary["requests"] == 0 and calls == [], summary)

    proof, summary, calls, _ = run(baseline_texts=[json.dumps({"proof": PROOF})])
    check("proof already present in baseline is never returned",
          proof is None and len(calls) == 4 and summary["proof"] is None, summary)

    mismatched = XMLClient(base="https://other.2026.huntress.ctf.games/")
    proof, summary, calls, _ = run(client=mismatched)
    check("mismatched scoped client sends nothing",
          proof is None and summary["requests"] == 0 and calls == [], summary)

    proof, summary, calls, _ = run(route_allowed=lambda _route: False)
    check("caller route policy denial sends nothing",
          proof is None and summary["requests"] == 0 and calls == [], summary)


def test_uppercase_baseline_proof_is_recorded_in_baseline_proofs():
    # R-06: the baseline scan is the any-case payoff (flagfmt.PAYOFF_ANYCASE), so an uppercase proof on a
    # public page is recorded as a baseline proof; an exact lowercase scan would miss it.
    upper = DECOY.upper()
    cached = {"/": page({"service": "xml", "decoy": upper}), "/api/clues": page(clues())}
    proof, summary, _calls, _ = run(preloaded=cached)
    check("uppercase baseline proof is listed in baseline_proofs",
          upper in summary["baseline_proofs"], summary)
    check("the novel lowercase proof is still the answer", proof == PROOF, summary)


def main():
    test_clue_contract_happy_path()
    test_openapi_only_exact_contract()
    test_clue_negative_authority_cannot_be_overridden_by_openapi()
    test_openapi_tail_ambiguity_and_security_are_zero_wire()
    test_exact_gates_are_zero_wire()
    test_destructive_route_compounds_and_separators_are_zero_wire()
    test_ambiguous_openapi_body_shapes_are_zero_wire()
    test_dtd_path_metacharacters_are_zero_wire_and_private_targets_work()
    test_objective_tail_conflict_is_zero_wire()
    test_controls_fail_closed()
    test_container_filename_or_mime_header_cannot_confirm_passwd_read()
    test_unsafe_archive_sibling_poisoned_contract_is_zero_wire()
    test_query_specific_and_colliding_cache_entries_are_not_authority()
    test_shared_controls_and_baseline_novelty()
    test_uppercase_baseline_proof_is_recorded_in_baseline_proofs()
    print("PASS all web XXE reader tests")


if __name__ == "__main__":
    main()
