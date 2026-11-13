#!/usr/bin/env python3
"""Offline regressions for metadata-only AsyncAPI/OpenRPC inventory."""

import json
import sys
import time
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "web"))
import descriptor_inventory as di  # noqa: E402
import endpoint_inventory as ei  # noqa: E402
import proof_hunt as ph  # noqa: E402


FAILS = []


def check(name, condition, detail=""):
    print(("ok   " if condition else "FAIL ") + name + ("" if condition else f" [{str(detail)[:1000]}]"))
    if not condition:
        FAILS.append(name)


def test_asyncapi_2_and_3():
    doc2 = {
        "asyncapi": "2.6.0",
        "servers": {
            "local": {"url": "wss://target.test/socket", "protocol": "wss"},
            "foreign": {"url": "https://evil.invalid/events", "protocol": "https"},
        },
        "channels": {
            "case.changed": {
                "publish": {"operationId": "publishCase", "message": {"$ref": "#/components/messages/Case"}},
            },
        },
        "components": {"messages": {"Case": {
            "name": "CaseChanged", "payload": {"type": "object", "required": ["event"],
                "properties": {"event": {"enum": ["case.changed"]}, "owner": {"type": "string"}}},
        }}},
    }
    result2 = di.parse_document(doc2, base_url="https://target.test/", path="/events.json")
    operation2 = result2["operations"][0]
    check("AsyncAPI 2.x version and publish operation", result2["version"] == "2.6.0"
          and operation2["action"] == "publish" and operation2["channel"] == "case.changed", result2)
    check("AsyncAPI 2.x local message ref and payload fields", operation2["messages"] == ["Case"]
          and {row["name"] for row in operation2["fields"]} == {"event", "owner"}
          and next(row for row in operation2["fields"] if row["name"] == "event")["values"] == ["case.changed"],
          operation2)
    check("AsyncAPI servers remain non-requestable metadata", all(row["requestable"] is False
          for row in result2["servers"]) and result2["servers"][0]["same_origin"] is True
          and result2["servers"][1]["same_origin"] is False
          and "endpoint" not in result2["servers"][1], result2["servers"])

    doc3 = {
        "asyncapi": "3.0.0",
        "channels": {"caseUpdates": {"address": "/bus/cases/{caseId}", "messages": {
            "Case": {"$ref": "#/components/messages/Case"},
        }}},
        "operations": {"receiveCase": {"action": "receive", "channel": {"$ref": "#/channels/caseUpdates"},
            "messages": [{"$ref": "#/channels/caseUpdates/messages/Case"}]}},
        "components": {"messages": {"Case": {"name": "CaseEvent", "payload": {
            "type": "object", "properties": {"proof": {"type": "string"}},
        }}}},
    }
    result3 = di.parse_document(doc3, base_url="https://target.test/", path="/asyncapi-3.json")
    operation3 = result3["operations"][0]
    check("AsyncAPI 3.x top-level operation and channel ref", operation3["action"] == "receive"
          and operation3["channel"] == "/bus/cases/{caseId}" and operation3["requestable"] is False,
          operation3)
    check("AsyncAPI 3.x message ref metadata", operation3["messages"] == ["Case"]
          and operation3["fields"] == [{"name": "proof", "required": False, "values": []}], operation3)


def test_openrpc_1_and_ref_cycles():
    doc = {
        "openrpc": "1.3.2",
        "servers": [{"name": "same", "url": "https://target.test/rpc"},
                    {"name": "foreign", "url": "https://evil.invalid/rpc"}],
        "methods": [{"$ref": "#/components/methods/getCase"}, {
            "name": "cyclic.result", "params": [], "result": {"schema": {"$ref": "#/components/schemas/A"}},
        }],
        "components": {
            "methods": {"getCase": {"name": "case.get", "params": [
                {"$ref": "#/components/contentDescriptors/CaseId"},
            ], "result": {"schema": {"type": "object", "required": ["evidence"], "properties": {
                "evidence": {"type": "string"}, "status": {"enum": ["open", "closed"]},
            }}}, "tags": [{"name": "cases"}]}},
            "contentDescriptors": {"CaseId": {"name": "caseId", "required": True,
                "schema": {"type": "string", "examples": ["case-7"]}}},
            "schemas": {"A": {"$ref": "#/components/schemas/B"},
                        "B": {"$ref": "#/components/schemas/A"}},
        },
    }
    result = di.parse_document(doc, base_url="https://target.test/", path="/openrpc.json")
    get_case = result["operations"][0]
    cyclic = result["operations"][1]
    check("OpenRPC 1.x methods and contentDescriptor refs", result["methods"] == ["case.get", "cyclic.result"]
          and get_case["params"] == [{"name": "caseId", "required": True, "values": ["case-7"]}], get_case)
    check("OpenRPC result fields and enum metadata", {row["name"] for row in get_case["response_fields"]}
          == {"evidence", "status"} and next(row for row in get_case["response_fields"]
          if row["name"] == "status")["values"] == ["open", "closed"], get_case)
    check("OpenRPC local ref cycle terminates empty", cyclic["response_fields"] == [], cyclic)
    check("OpenRPC server URLs never become request targets", result["servers"][0]["endpoint"] == "/rpc"
          and result["servers"][1]["same_origin"] is False and "endpoint" not in result["servers"][1],
          result["servers"])


def test_parser_bounds_and_versions():
    cyclic = {"asyncapi": "3.0.0", "channels": {}}
    cyclic["self"] = cyclic
    check("recursive in-memory descriptor fails closed",
          di.parse_document(cyclic, base_url="https://target.test/") is None)

    too_many = {"asyncapi": "3.0.0", "channels": {"events": {"address": "events"}}, "operations": {
        f"op{index}": {"action": "send", "channel": {"$ref": "#/channels/events"}}
        for index in range(di.MAX_OPERATIONS + 40)
    }}
    bounded = di.parse_document(too_many, base_url="https://target.test/")
    check("AsyncAPI operations hard-capped", len(bounded["operations"]) == di.MAX_OPERATIONS,
          len(bounded["operations"]))
    check("unsupported and ambiguous versions fail closed",
          di.parse_document({"asyncapi": "1.2.0", "channels": {}}, base_url="https://target.test/") is None
          and di.parse_document({"openrpc": "2.0.0", "methods": []}, base_url="https://target.test/") is None
          and di.parse_document({"asyncapi": "3.0.0", "openrpc": "1.3.2"},
                                base_url="https://target.test/") is None)

    yaml_cycle = b"asyncapi: 3.0.0\nchannels: &node\n  loop: *node\n"
    page = {"status": 200, "body": yaml_cycle, "response_headers": {"Content-Type": "application/yaml"}}
    check("recursive YAML alias fails closed", di.parse_page("https://target.test/", "/events.yaml", page) is None)
    huge = {"status": 200, "body": b"{" + b" " * di.MAX_DOCUMENT + b"}", "response_headers": {}}
    check("oversized descriptor fails closed", di.parse_page("https://target.test/", "/huge.json", huge) is None)


def test_ambiguous_descriptor_documents_fail_closed():
    def page(body, ctype="application/json"):
        return {"status": 200, "body": body.encode(),
                "response_headers": {"Content-Type": ctype}}

    duplicate_json = ('{"asyncapi":"3.0.0","channels":{},'
                      '"channels":{"danger":{"address":"/must-not-request"}}}')
    colliding_json = ('{"asyncapi":"3.0.0","channels":{},'
                      '"Channels":{"danger":{"address":"/must-not-request"}}}')
    malformed_json = '{"asyncapi":"3.0.0","channels":'
    nonfinite_json = '{"asyncapi":"3.0.0","channels":{},"weight":NaN}'
    check("duplicate/canonical-collision descriptor JSON is rejected",
          di.parse_page("https://target.test/", "/duplicate.json", page(duplicate_json)) is None
          and di.parse_page("https://target.test/", "/collision.json", page(colliding_json)) is None)
    check("malformed/non-finite JSON-looking descriptors never fall through to YAML",
          di.parse_page("https://target.test/", "/broken.json", page(malformed_json)) is None
          and di.parse_page("https://target.test/", "/nan.json", page(nonfinite_json)) is None)

    yaml_header = "application/yaml"
    duplicate_yaml = "asyncapi: 3.0.0\nchannels: {}\nchannels:\n  danger: {}\n"
    colliding_yaml = "asyncapi: 3.0.0\nchannels: {}\nChannels:\n  danger: {}\n"
    merge_yaml = ("base: &base\n  channels: {}\nasyncapi: 3.0.0\n"
                  "<<: *base\nchannels: {}\n")
    complex_yaml = "asyncapi: 3.0.0\n? [channels]\n: {}\nchannels: {}\n"
    typed_collision_yaml = ("asyncapi: 3.0.0\nchannels:\n"
                            "  1: {address: /one}\n"
                            "  true: {address: /boolean}\n")
    oversized_number_yaml = ("asyncapi: 3.0.0\nchannels: {}\nweight: "
                             + "7" * (di._security_json.DEFAULT_MAX_NUMBER_CHARS + 1) + "\n")
    rejected = [duplicate_yaml, colliding_yaml, merge_yaml, complex_yaml,
                typed_collision_yaml, oversized_number_yaml]
    check("YAML duplicate/canonical/merge/complex keys and huge numbers are rejected",
          all(di.parse_page("https://target.test/", "/events.yaml", page(doc, yaml_header)) is None
              for doc in rejected))
    if di._yaml is not None:
        valid = "asyncapi: 3.0.0\nchannels:\n  events:\n    address: /events\n"
        parsed = di.parse_page("https://target.test/", "/events.yaml", page(valid, yaml_header))
        check("unambiguous descriptor YAML remains supported",
              parsed is not None and parsed["encoding"] == "yaml" and parsed["kind"] == "asyncapi", parsed)


class ExactLeadClient:
    base = "https://target.test/"
    timeout = 10

    def __init__(self):
        self.seen = []

    @staticmethod
    def async_doc(version="2.6.0"):
        return {"asyncapi": version, "servers": {"foreign": {
            "url": "wss://evil.invalid/bus", "protocol": "wss",
        }}, "channels": {"/must-not-request": {"publish": {"operationId": "send"}}}}

    @staticmethod
    def rpc_doc(name):
        return {"openrpc": "1.3.2", "methods": [{"name": name, "params": [],
                "result": {"name": "result", "schema": {"type": "string"}}}],
                "servers": [{"url": "https://evil.invalid/rpc"}]}

    def request(self, method, path, **kwargs):
        assert method == "GET" and kwargs.get("allow_redirects") is False
        assert path.startswith("/") and not path.startswith("//")
        self.seen.append((method, path))
        pages = {
            "/": ("text/html", b'''<html><head>
                <link rel="alternate service-desc" href="/contracts/events.json">
                <a rel="service-desc" href="https://evil.invalid/openrpc.json">foreign</a>
                <link rel="alternate" href="/generic.json">
                <script src="/assets/app.js"></script></head></html>'''),
            "/robots.txt": ("text/plain", b""),
            "/openapi.json": ("application/json", b"{}"),
            "/contracts/events.json": ("application/json", json.dumps(self.async_doc()).encode()),
            "/prompt/rpc-contract.json": ("application/json", json.dumps(self.rpc_doc("prompt.read")).encode()),
            "/assets/app.js": ("application/javascript", b"const openrpcDocument='/meta/openrpc.json';"
                                + b" " * 300 + b"const generic='/unrelated.json';"),
            "/meta/openrpc.json": ("application/json", json.dumps(self.rpc_doc("js.read")).encode()),
            "/sitemap.xml": ("application/xml", b"<urlset></urlset>"),
        }
        ctype, body = pages.get(path, ("text/plain", b"not found"))
        return {"status": 200 if path in pages else 404, "body": body,
                "response_headers": {"Content-Type": ctype}}


def test_exact_lead_integration_and_no_calls():
    client = ExactLeadClient()
    target = {"url": client.base,
              "question": "The OpenRPC service descriptor is exactly /prompt/rpc-contract.json"}
    result = ei.discover(target, {"client": client, "max_requests": 12, "deadline": time.time() + 10})
    requested = [path for _method, path in client.seen]
    docs = {row["path"]: row for row in result["descriptor_docs"]}
    check("prompt, service-desc and linked-JS descriptors fetched", set(docs) == {
        "/prompt/rpc-contract.json", "/contracts/events.json", "/meta/openrpc.json",
    }, (docs, requested))
    check("no descriptor default guessing or generic JSON fetch", not any("asyncapi" in path.lower()
          for path in requested) and "/generic.json" not in requested and "/unrelated.json" not in requested,
          requested)
    check("off-host descriptor/server and application surfaces never contacted",
          not any("evil.invalid" in path for path in requested)
          and "/must-not-request" not in requested and "/rpc" not in requested, requested)
    check("protocol surfaces never enter route inventory", "/must-not-request" not in result["route_paths"]
          and all(row.get("requestable") is False for row in result["event_operations"])
          and {row.get("surface") for row in result["event_operations"]} == {"asyncapi", "openrpc"},
          result["event_operations"])
    hunter = object.__new__(ph._Hunter)
    check("proof-hunt contract GET builder rejects every protocol operation",
          hunter._spec_get_items(result["event_operations"]) == [], result["event_operations"])
    classes = {row.get("class") for row in result["findings"]}
    check("machine-dispatch findings name both recon classes", {"asyncapi", "json_rpc"} <= classes,
          result["findings"])
    check("all wire traffic stays bounded GET-only", result["requests"] <= 12
          and len(client.seen) == result["requests"] and {method for method, _path in client.seen} == {"GET"},
          (result["requests"], client.seen))


def test_offhost_links_and_budget():
    leads = di.html_leads("https://target.test/", "/", '''
        <link rel="service-desc" href="https://evil.invalid/asyncapi.json">
        <a rel="service-desc" href="//evil.invalid/openrpc.json">bad</a>
        <a rel="service-desc" href="/safe/openrpc.json">good</a>
    ''', ei._safe_path)
    check("off-host and scheme-relative service-desc links fail closed", leads == ["/safe/openrpc.json"], leads)

    client = ExactLeadClient()
    result = ei.discover({"url": client.base,
                          "question": "OpenRPC descriptor: /prompt/rpc-contract.json"},
                         {"client": client, "max_requests": 4, "deadline": time.time() + 10})
    check("shared request cap bounds exact descriptor fetch", result["requests"] == 4
          and len(client.seen) == 4 and result["stopped"] == "max_requests", (result, client.seen))


if __name__ == "__main__":
    tests = [test_asyncapi_2_and_3, test_openrpc_1_and_ref_cycles, test_parser_bounds_and_versions,
             test_ambiguous_descriptor_documents_fail_closed,
             test_exact_lead_integration_and_no_calls, test_offhost_links_and_budget]
    for test in tests:
        try:
            test()
        except Exception as exc:
            check(test.__name__, False, repr(exc))
    print(("FAIL" if FAILS else "PASS"), "test_web_descriptor_inventory", len(FAILS), "failed")
    raise SystemExit(bool(FAILS))
