#!/usr/bin/env python3
"""Regressions for fail-closed JSON used by policy-bearing web readers."""

from __future__ import annotations

import base64
import importlib
import sys
import time
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
WEB = REPO / "solvers" / "web"
if str(WEB) not in sys.path:
    sys.path.insert(0, str(WEB))

security_json = importlib.import_module("security_json")


class SecurityJSONTests(unittest.TestCase):
    def test_valid_document_preserves_normal_json(self):
        value = security_json.loads(
            '{"ok":true,"data":{"proof_value":"proof_0123456789abcdef0123456789abcdef"},'
            '"items":[1,2,null]}')
        self.assertIs(value["ok"], True)
        self.assertEqual(value["items"], [1, 2, None])

    def test_exact_duplicate_is_rejected_at_every_depth(self):
        for text in (
            '{"ok":false,"ok":true}',
            '{"outer":{"effect":"denied","effect":"allowed"}}',
            '{"items":[{"errors":[],"errors":null}]}',
        ):
            with self.subTest(text=text), self.assertRaises(security_json.AmbiguousJSON):
                security_json.loads(text)

    def test_case_punctuation_and_camel_collisions_are_rejected(self):
        for text in (
            '{"effect":"denied","Effect":"allowed"}',
            '{"proof-value":"decoy","proof_value":"real"}',
            '{"proofValue":"decoy","proof_value":"real"}',
            '{"access.control":"no","access-control":"yes"}',
        ):
            with self.subTest(text=text), self.assertRaises(security_json.AmbiguousJSON):
                security_json.loads(text)

    def test_nonfinite_and_resource_limits_fail_closed(self):
        for text in ('{"n":NaN}', '{"n":Infinity}', '{"n":-Infinity}',
                     '{"n":1e999999}'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                security_json.loads(text)
        huge_integer = '{"n":' + ('9' * 100_000) + '}'
        started = time.monotonic()
        with self.assertRaises(security_json.AmbiguousJSON):
            security_json.loads(huge_integer)
        self.assertLess(time.monotonic() - started, 0.5,
                        "the lexical cap must run before decimal integer conversion")
        with self.assertRaises(security_json.AmbiguousJSON):
            security_json.loads('{"a":1,"b":2}', max_members=1)
        with self.assertRaises(security_json.AmbiguousJSON):
            security_json.loads('[[[0]]]', max_depth=2)
        with self.assertRaises(security_json.AmbiguousJSON):
            security_json.loads('[0,1,2]', max_nodes=2)
        with self.assertRaises(security_json.AmbiguousJSON):
            security_json.loads('{"long":"value"}', max_chars=4)

    def test_unique_structural_view_ignores_text_but_rejects_json_siblings(self):
        self.assertEqual(
            security_json.loads_unique(["diagnostic", '{"ok":true}']), {"ok": True})
        with self.assertRaises(security_json.AmbiguousJSON):
            security_json.loads_unique(['{"ok":false}', '{"ok":true}'])
        with self.assertRaises(security_json.AmbiguousJSON):
            security_json.loads_unique(['{"ok":', '{"ok":true}'])

    def test_every_policy_reader_rejects_duplicate_authorization_fields(self):
        response = {
            "status": 200,
            "body": b'{"ok":false,"ok":true,"effect":"denied","Effect":"allowed",'
                    b'"errors":["blocked"],"errors":null,"data":{"proof":"proof_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}',
            "response_headers": {"Content-Type": "application/json"},
        }
        readers = {
            "double_spend": lambda module: module._json(response),
            "graphql_read": lambda module: module._json(response),
            "post_chain": lambda module: module._json_document(response),
            "ssrf_body": lambda module: module._json(response),
            "xxe_read": lambda module: module._json(response),
            "hpp_read": lambda module: module._json(response),
            "passive_checks": lambda module: module._json(response),
            "realtime_read": lambda module: module._json(response),
            "reset_rebind": lambda module: module._json(response),
        }
        for name, read in readers.items():
            with self.subTest(reader=name):
                module = importlib.import_module(name)
                self.assertIsNone(read(module))

    def test_forge_rejects_ambiguous_or_split_mutation_authority(self):
        forge = importlib.import_module("forge_event")
        duplicate = (b'{"framework":"Starlette","feature_route":"/harmless",'
                     b'"feature_route":"/dispatch-x","current_role":"analyst",'
                     b'"event_type":"case.promoted","owner_scope":"executive"}')
        self.assertEqual(forge._security_json_objects(duplicate.decode()), [])

        encoded = base64.urlsafe_b64encode(
            b'{"user":"analyst","role":"analyst","role":"administrator"}'
        ).decode().rstrip("=")
        self.assertIsNone(forge._decode_b64url_json(encoded))

        boundary = "split-forge-contract"
        split = (
            f"--{boundary}\r\nContent-Type: application/json\r\n\r\n"
            '{"event_type":"case.promoted","owner_scope":"executive"}\r\n'
            f"--{boundary}\r\nContent-Type: application/json\r\n\r\n"
            '{"method":"POST","feature_route":"/dispatch-x","current_role":"analyst"}\r\n'
            f"--{boundary}--\r\n"
        ).encode()

        class Client:
            base = "https://target.test/"
            timeout = 1.0

            def __init__(self, clue, content_type):
                self.clue = clue
                self.content_type = content_type
                self.calls = []

            def request(self, method, path, data=None, headers=None, allow_redirects=True):
                self.calls.append((method, path, data))
                if path == "/":
                    return {"status": 404, "body": b'{"error":"not_found"}',
                            "response_headers": {"Content-Type": "application/json"}}
                if path == "/api/clues":
                    return {"status": 200, "body": self.clue,
                            "response_headers": {"Content-Type": self.content_type}}
                if method == "GET":
                    return {"status": 405, "body": b'{"error":"method_not_allowed"}',
                            "response_headers": {"Content-Type": "application/json"}}
                return {"status": 200,
                        "body": b'{"ok":true,"proof":"proof_0123456789abcdef0123456789abcdef"}',
                        "response_headers": {"Content-Type": "application/json"}}

        for clue, content_type in (
            (duplicate, "application/json"),
            (split, f"multipart/mixed; boundary={boundary}"),
        ):
            with self.subTest(content_type=content_type):
                client = Client(clue, content_type)
                sink = {}
                result = forge.solve(
                    {"url": client.base, "answer_id": "proof-1",
                     "question": "Forge the unsigned event."},
                    {"client": client, "deadline": time.time() + 5,
                     "max_requests": 8, "result_sink": sink,
                     "prompt": "Forge the unsigned event."},
                )
                self.assertIsNone(result)
                self.assertFalse(any(method == "POST" for method, _path, _data in client.calls),
                                 client.calls)

    def test_core_clues_cookies_and_jwts_reject_last_wins_policy(self):
        hunt = importlib.import_module("proof_hunt")
        toolkit = importlib.import_module("web")
        clue_page = {
            "text": '{"feature_route":"/safe","feature_route":"/execute-x",'
                    '"method":"GET","Method":"POST"}'
        }
        self.assertIsNone(hunt._Hunter.json_of(clue_page))
        self.assertEqual(hunt.cookie_raises('{"role":"user","role":"admin"}'), [])

        header = base64.urlsafe_b64encode(
            b'{"alg":"HS256","Alg":"none","typ":"JWT"}').decode().rstrip("=")
        payload = base64.urlsafe_b64encode(
            b'{"role":"user","role":"admin"}').decode().rstrip("=")
        token = f"{header}.{payload}.c2ln"
        self.assertIsNone(toolkit.decode_jwt(token))
        self.assertIsNone(hunt.jwt_crack(token))

    def test_post_bridge_never_assembles_authority_across_clue_objects(self):
        patch = importlib.import_module("web_patch")
        response = {
            "status": 200,
            "body": (b'{"feature_route":"/safe","feature_route":"/execute-x",'
                     b'"fields":["role"]}'),
            "response_headers": {"Content-Type": "application/json"},
        }
        self.assertEqual(patch._as_dicts(response), [])

        # Each object is valid by itself, but two independent authorities must
        # not be merged or silently selected to authorize a POST.
        clues = [
            {"feature_route": "/execute-a"},
            {"feature_route": "/execute-b", "fields": ["role"]},
        ]
        self.assertEqual(patch.derive_hints(clues, {}), {})

        # A wrapper is fine when one nested object contains the whole contract.
        nested = {"contract": {"feature_route": "/execute-a", "request_method": "POST",
                               "fields": ["display_name"]}}
        hints = patch.derive_hints(patch._as_dicts({
            "status": 200,
            "body": __import__("json").dumps(nested).encode(),
            "response_headers": {"Content-Type": "application/json"},
        }), {})
        self.assertEqual(hints.get("state_path"), "/execute-a")
        self.assertEqual(hints.get("state_fields"), {"display_name": ""})

    def test_post_hand_tool_rejects_duplicate_paths_and_locations(self):
        post = importlib.import_module("post_exploit")
        self.assertIsNone(post._json_document(
            '{"ok":true,"path":"/safe","path":"/other"}'))
        self.assertIsNone(post._path_from_upload_response({
            "body": b'{"ok":true,"path":"/safe","path":"/other"}',
            "response_header_pairs": [],
        }))
        self.assertIsNone(post._path_from_upload_response({
            "body": b"uploaded",
            "response_header_pairs": [("Location", "/a"), ("location", "/b")],
        }))


if __name__ == "__main__":
    unittest.main(verbosity=2)
