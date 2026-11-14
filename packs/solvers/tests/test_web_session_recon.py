#!/usr/bin/env python3
"""Offline adversarial tests for session_recon; no fixture opens a socket."""

from __future__ import annotations

import base64
import json
import sys
import threading
import time
import unittest
import zlib
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "solvers" / "web"))
import session_recon as sr  # noqa: E402


def b64u(raw):
    if isinstance(raw, (dict, list)):
        raw = json.dumps(raw, separators=(",", ":")).encode()
    elif isinstance(raw, str):
        raw = raw.encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64(raw):
    if isinstance(raw, dict):
        raw = json.dumps(raw, separators=(",", ":")).encode()
    elif isinstance(raw, str):
        raw = raw.encode()
    return base64.b64encode(raw).decode()


def cookie(result, name):
    return next(item for item in result["cookies"] if item["name"] == name)


class CookieParsingTests(unittest.TestCase):
    def test_ordered_duplicates_expires_comma_quotes_and_shadowing(self):
        pairs = [
            ("Date", "Tue, 27 Oct 2026 12:00:00 GMT"),
            ("Set-Cookie", 'sid="abc,def"; Expires=Wed, 21 Oct 2099 07:28:00 GMT; '
                           'Path=/; Secure; HttpOnly; SameSite=None; Partitioned'),
            ("Set-Cookie", "sid=second; Path=/app; Domain=example.test; Secure; SameSite=Lax"),
            ("Set-Cookie", 'alias="abc,def"; Path=/; Secure'),
        ]
        result = sr.analyze(pairs, source_url="https://app.example.test/account/view")
        self.assertEqual(result["headers"]["set_cookie_fields"], 3)
        self.assertEqual(len(result["cookies"]), 3)
        first = cookie(result, "sid")
        self.assertTrue(first["value_metadata"]["quoted"])
        self.assertEqual(first["attributes"]["samesite"], "none")
        self.assertTrue(first["attributes"]["partitioned"])
        self.assertTrue(first["attributes"]["secure"])
        self.assertTrue(first["attributes"]["httponly"])
        self.assertEqual(first["attributes"]["expires"], "2099-10-21T07:28:00+00:00")
        self.assertFalse(first["deletion"])

        duplicate = result["duplicate_names"][0]
        self.assertEqual(duplicate["name"], "sid")
        self.assertIn("path_shadowing", duplicate["relations"])
        self.assertIn("domain_shadowing_or_host_only_ambiguity", duplicate["relations"])
        self.assertFalse(duplicate["same_value"])
        shared = next(row for row in result["duplicate_values"] if len(row["cookie_indices"]) == 2)
        self.assertEqual(shared["names"], ["sid", "alias"])
        rendered = json.dumps(result)
        self.assertNotIn("abc,def", rendered)
        self.assertNotIn("second", rendered)

    def test_repeated_attributes_are_ambiguous_not_silently_last_wins(self):
        value = ("a=value; Path=/; Path=/admin; Domain=example.test; Domain=sub.example.test; "
                 "SameSite=Lax; SameSite=None; Secure=1; Secure; HttpOnly; HttpOnly")
        result = sr.analyze([("Set-Cookie", value)], source_url="https://sub.example.test/x/y")
        got = result["cookies"][0]
        self.assertEqual(got["repeated_attributes"],
                         ["domain", "httponly", "path", "samesite", "secure"])
        self.assertIsNone(got["attributes"]["path"])
        self.assertIsNone(got["attributes"]["effective_path"])
        self.assertEqual(got["attributes"]["domain"]["assessment"], "repeated_domain_ambiguous")
        self.assertIsNone(got["attributes"]["samesite"])
        self.assertTrue(got["attributes"]["secure"])
        self.assertIn("flag_has_value:secure", got["attribute_issues"])
        self.assertIn("scope_undetermined", sr.analyze(
            [("Set-Cookie", value), ("Set-Cookie", "a=other; Path=/")],
            source_url="https://sub.example.test/x/y")["duplicate_names"][0]["relations"])

    def test_prefix_invariants_samesite_partitioned_and_origin(self):
        pairs = [
            ("Set-Cookie", "__Host-good=x; Secure; Path=/; HttpOnly"),
            ("Set-Cookie", "__Host-bad=x; Path=/app; Domain=example.test"),
            ("Set-Cookie", "__Secure-bad=x; Path=/"),
            ("Set-Cookie", "plain=x; SameSite=None; Partitioned"),
            ("Set-Cookie", "__host-lookalike=x; Secure; Path=/"),
        ]
        secure = sr.analyze(pairs, source_url="https://example.test/app")
        self.assertEqual(cookie(secure, "__Host-good")["prefix_violations"], [])
        host_bad = cookie(secure, "__Host-bad")
        self.assertEqual(set(host_bad["prefix_violations"]), {
            "__Host_forbids_Domain", "__Host_requires_Path_root", "__Host_requires_Secure",
        })
        self.assertEqual(cookie(secure, "__Secure-bad")["prefix_violations"],
                         ["__Secure_requires_Secure"])
        self.assertEqual(set(cookie(secure, "plain")["prefix_violations"]), {
            "Partitioned_without_Secure", "SameSite_None_without_Secure",
        })
        self.assertEqual(cookie(secure, "__host-lookalike")["prefix"], "case_mismatch_lookalike")

        insecure = sr.analyze([("Set-Cookie", "__Secure-x=v; Secure")],
                              source_url="http://example.test/")
        self.assertEqual(set(insecure["cookies"][0]["prefix_violations"]), {
            "Secure_set_from_non_https_origin", "__Secure_requires_secure_origin",
        })

    def test_controls_combined_fields_bad_quotes_and_limits_fail_closed(self):
        attrs = "; ".join(f"x{i}=v" for i in range(sr.MAX_ATTRIBUTES + 1))
        huge = "x=" + "a" * (sr.MAX_HEADER_VALUE + 1)
        pairs = [
            ("Set-Cookie", "ctl=a\rb"),
            ("Set-Cookie", huge),
            ("Set-Cookie", 'broken="unterminated; Path=/'),
            ("Set-Cookie", "a=1, b=2; Path=/"),
            ("Set-Cookie", "combined=x; Expires=Wed, 21 Oct 2099 07:28:00 GMT, b=2; Path=/"),
            ("Set-Cookie", "combined2=x; Expires=invalid, b=2; Path=/"),
            ("Set-Cookie", "bad name=x"),
            ("Set-Cookie", "many=x; " + attrs),
            ("Set-Cookie", 'quoted="a\\\"b"; Path=/'),
        ]
        result = sr.analyze(pairs, source_url="https://example.test/")
        self.assertEqual([item["name"] for item in result["cookies"]], ["quoted"])
        self.assertEqual(result["cookies"][0]["value_metadata"]["length"], 3)
        header_reasons = {row["reason"] for row in result["headers"]["rejected"]}
        self.assertIn("header_value_contains_control", header_reasons)
        self.assertIn("header_value_too_large", header_reasons)
        cookie_reasons = {row["reason"] for row in result["rejected_cookies"]}
        self.assertTrue({"malformed_cookie_pair", "ambiguous_combined_set_cookie",
                         "invalid_cookie_name", "too_many_cookie_attributes"} <= cookie_reasons)

    def test_domain_public_suffix_idn_and_mismatch_are_declined_or_reported(self):
        pairs = [
            ("Set-Cookie", "a=x; Domain=com"),
            ("Set-Cookie", "b=x; Domain=xn--bcher-kva.example"),
            ("Set-Cookie", "c=x; Domain=bücher.example"),
            ("Set-Cookie", "d=x; Domain=evil.example"),
            ("Set-Cookie", "e=x; Domain=.example.test"),
            ("Set-Cookie", "f=x; Domain=127.0.0.1"),
        ]
        result = sr.analyze(pairs, source_url="https://app.example.test/path")
        assessments = {item["name"]: item["attributes"]["domain"]["assessment"]
                       for item in result["cookies"]}
        self.assertEqual(assessments["a"], "declined_public_suffix_ambiguity")
        self.assertEqual(assessments["b"], "declined_idn_ambiguity")
        self.assertEqual(assessments["c"], "declined_idn_ambiguity")
        self.assertEqual(assessments["d"], "syntactic_domain_mismatch")
        self.assertEqual(assessments["e"], "syntactic_domain_match_psl_unchecked")
        self.assertEqual(assessments["f"], "declined_ip_domain_ambiguity")
        self.assertEqual(cookie(result, "e")["attributes"]["domain"]["effective"], "example.test")

    def test_host_prefix_rejects_even_repeated_domain_attributes(self):
        result = sr.analyze([
            ("Set-Cookie", "__Host-x=v; Secure; Path=/; Domain=example.test; Domain=example.test"),
        ], source_url="https://example.test/")
        got = result["cookies"][0]
        self.assertIn("__Host_forbids_Domain", got["prefix_violations"])
        self.assertEqual(got["attributes"]["domain"]["assessment"],
                         "repeated_domain_ambiguous")

    def test_deletion_and_malformed_lifetime(self):
        result = sr.analyze([
            ("Set-Cookie", "empty=; Path=/"),
            ("Set-Cookie", "age=x; Max-Age=0"),
            ("Set-Cookie", "past=x; Expires=Thu, 01 Jan 1970 00:00:00 GMT"),
            ("Set-Cookie", "precedence=x; Max-Age=3600; Expires=Thu, 01 Jan 1970 00:00:00 GMT"),
            ("Set-Cookie", "ambiguous=x; Max-Age=0; Max-Age=3600"),
            ("Set-Cookie", "bad=x; Max-Age=tomorrow; Expires=not-a-date"),
        ], source_url="https://example.test/")
        self.assertFalse(cookie(result, "empty")["deletion"])
        self.assertEqual(cookie(result, "empty")["deletion_assessment"], "retain_empty_value")
        self.assertTrue(all(cookie(result, name)["deletion"] for name in ("age", "past")))
        self.assertFalse(cookie(result, "precedence")["deletion"])
        self.assertEqual(cookie(result, "precedence")["deletion_assessment"], "retain")
        self.assertFalse(cookie(result, "ambiguous")["deletion"])
        self.assertEqual(cookie(result, "ambiguous")["deletion_assessment"],
                         "ambiguous_repeated_lifetime_attribute")
        bad = cookie(result, "bad")
        self.assertFalse(bad["deletion"])
        self.assertEqual(set(bad["attribute_issues"]), {"invalid_expires", "invalid_max_age"})


class EnvelopeTests(unittest.TestCase):
    def test_framework_envelopes_are_structural_unverified_and_names_are_only_hints(self):
        secret_proof = "proof_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        jwt = ".".join((b64u({"alg": "HS256", "typ": "JWT"}),
                        b64u({"sub": "guest", "proof": secret_proof}), b64u(b"signature")))
        jwe = ".".join((b64u({"alg": "dir", "enc": "A256GCM"}), "", b64u(b"iv"),
                        b64u(b"ciphertext"), b64u(b"tagtagtagtagtag")))
        flask = ".".join((b64u({"user": "guest", "role": "user"}), b64u(b"\x01\x02\x03\x04"),
                          b64u(b"0123456789abcdef")))
        django = f"{b64u({'user': 'guest'})}:AbC123:{b64u(b'0123456789abcdef0123')}"
        rails = b64({"user": "guest"}) + "--" + "a" * 40
        express = "s:opaque-session-id." + b64u(b"0123456789abcdef")
        laravel = b64({"iv": b64(b"0123456789abcdef"), "value": b64(b"cipher"),
                       "mac": "b" * 64, "tag": ""})
        aspnet = b64u(b"\x09\xf0\xc9\xf0" + b"protected-data" * 3)
        paseto = "v4.local." + b64u(b"encrypted payload bytes")
        macaroon = b64(b"0001identifier guest\n0001signature " + b"x" * 32)
        opaque = b64u(bytes(range(64)))
        pairs = [
            ("Set-Cookie", f"jwt={jwt}"), ("Set-Cookie", f"jwe={jwe}"),
            ("Set-Cookie", f"session={flask}"), ("Set-Cookie", f"sessionid={django}"),
            ("Set-Cookie", f"_rails_session={rails}"),
            ("Set-Cookie", f"connect.sid={express}"),
            ("Set-Cookie", f"laravel_session={laravel}"),
            ("Set-Cookie", f".AspNetCore.Cookies={aspnet}"),
            ("Set-Cookie", f"paseto={paseto}"), ("Set-Cookie", f"mac={macaroon}"),
            ("Set-Cookie", f"opaque={opaque}"),
            ("Set-Cookie", "ASP.NET_SessionId=plain-name-only"),
        ]
        result = sr.analyze(pairs, source_url="https://example.test/")
        expected = {
            "jwt": "jwt_jws", "jwe": "jwe_compact", "session": "flask_itsdangerous",
            "sessionid": "django_signed_cookie", "_rails_session": "rails_signed_message",
            "connect.sid": "express_cookie_signature", "laravel_session": "laravel_encrypted_cookie",
            ".AspNetCore.Cookies": "aspnet_core_data_protection", "paseto": "paseto",
            "mac": "macaroon_v1", "opaque": "opaque_or_encrypted",
        }
        for name, kind in expected.items():
            with self.subTest(name=name):
                got = cookie(result, name)
                self.assertIn(kind, [item["kind"] for item in got["envelopes"]])
                self.assertTrue(all(item["verified"] is False for item in got["envelopes"]))
                self.assertTrue(all(item["decoding"] == "unverified_structure_only"
                                    for item in got["envelopes"]))
        self.assertEqual(cookie(result, "jwt")["envelopes"][0]["segments"], 3)
        self.assertEqual(cookie(result, "jwe")["envelopes"][0]["segments"], 5)
        name_only = cookie(result, "ASP.NET_SessionId")
        self.assertEqual(name_only["envelopes"], [])
        self.assertEqual(name_only["framework_hints"][0]["confidence"], "hint_only")
        rendered = json.dumps(result)
        self.assertNotIn(secret_proof, rendered)
        self.assertNotIn("opaque-session-id", rendered)

    def test_malformed_compact_tokens_fail_closed(self):
        jwt_bad_signature = ".".join((b64u({"alg": "HS256"}), b64u({"sub": "x"}), "%%%"))
        jwe_missing_tag = ".".join((b64u({"alg": "dir", "enc": "A256GCM"}), "",
                                    b64u(b"iv"), b64u(b"ciphertext"), ""))
        paseto_extra = "v4.local." + b64u(b"payload") + ".footer.extra"
        paseto_empty_footer = "v4.local." + b64u(b"payload") + "."
        result = sr.analyze([
            ("Set-Cookie", f"a={jwt_bad_signature}"),
            ("Set-Cookie", f"b={jwe_missing_tag}"),
            ("Set-Cookie", f"c={paseto_extra}"),
            ("Set-Cookie", f"d={paseto_empty_footer}"),
        ])
        self.assertTrue(all(not item["envelopes"] for item in result["cookies"]))

        packed = zlib.compress(b'{"user":"guest","role":"user"}')
        valid_flask = ".".join(("", b64u(packed), b64u(b"\x01\x02\x03\x04"),
                                b64u(b"0123456789abcdef")))
        truncated_flask = ".".join(("", b64u(packed[:-5]), b64u(b"\x01\x02\x03\x04"),
                                    b64u(b"0123456789abcdef")))
        valid_django = f".{b64u(packed)}:AbC123:{b64u(b'0123456789abcdef0123')}"
        truncated_django = f".{b64u(packed[:-5])}:AbC123:{b64u(b'0123456789abcdef0123')}"
        compressed = sr.analyze([
            ("Set-Cookie", f"valid_flask={valid_flask}"),
            ("Set-Cookie", f"bad_flask={truncated_flask}"),
            ("Set-Cookie", f"valid_django={valid_django}"),
            ("Set-Cookie", f"bad_django={truncated_django}"),
        ])
        self.assertIn("flask_itsdangerous",
                      [item["kind"] for item in cookie(compressed, "valid_flask")["envelopes"]])
        self.assertIn("django_signed_cookie",
                      [item["kind"] for item in cookie(compressed, "valid_django")["envelopes"]])
        self.assertEqual(cookie(compressed, "bad_flask")["envelopes"], [])
        self.assertEqual(cookie(compressed, "bad_django")["envelopes"], [])

    def test_duplicate_or_canonically_colliding_json_envelopes_fail_closed(self):
        duplicate_header = b64u(b'{"alg":"HS256","alg":"none"}')
        colliding_header = b64u(b'{"alg":"HS256","ALG":"none"}')
        payload = b64u({"sub": "guest"})
        signature = b64u(b"0123456789abcdef")
        duplicate_payload = b64u(b'{"role":"guest","role":"admin"}')
        result = sr.analyze([
            ("Set-Cookie", f"dup={duplicate_header}.{payload}.{signature}"),
            ("Set-Cookie", f"collision={colliding_header}.{payload}.{signature}"),
            ("Set-Cookie", f"payload={b64u({'alg': 'HS256'})}.{duplicate_payload}.{signature}"),
        ])
        self.assertEqual(cookie(result, "dup")["envelopes"], [])
        self.assertEqual(cookie(result, "collision")["envelopes"], [])
        payload_envelope = cookie(result, "payload")["envelopes"][0]
        self.assertFalse(payload_envelope["payload_json"])
        self.assertEqual(payload_envelope["claim_keys"], [])


class CSRFAndSafetyTests(unittest.TestCase):
    def test_csrf_locations_exact_and_url_decoded_double_submit_are_metadata_only(self):
        exact = "A1b2C3d4E5f6G7h8"
        encoded = "url%2Dencoded%2Dtoken"
        body = f"""
          <form><input type=hidden name=csrf_token value="{exact}"></form>
          <meta name="csrf-token" content="meta-token-123456">
          <script>window.xsrfToken = "url-encoded-token";
                  const csrfConfig = "javascript-token-98765";
                  window.config = {{"csrf_json":"json-token-123456"}};</script>
        """
        result = sr.analyze([
            ("Set-Cookie", f"csrf_token={exact}; Path=/; SameSite=Lax"),
            ("Set-Cookie", f"XSRF-TOKEN={encoded}; Path=/"),
            ("X-CSRF-Token", exact),
        ], body=body, source_url="https://example.test/settings")
        kinds = {location["kind"] for token in result["csrf"]["tokens"]
                 for location in token["locations"]}
        self.assertTrue({"cookie", "response_header", "html_hidden_input", "html_meta",
                         "javascript_literal", "json_literal"} <= kinds)
        comparisons = {item["comparison"] for item in result["csrf"]["bindings"]}
        self.assertEqual(comparisons, {"exact", "url_decoded_unverified"})
        self.assertTrue(all(item["verified_binding"] is False for item in result["csrf"]["bindings"]))
        rendered = json.dumps(result)
        for secret in (exact, encoded, "meta-token-123456", "javascript-token-98765",
                       "json-token-123456"):
            self.assertNotIn(secret, rendered)

    def test_response_dict_prefers_ordered_pairs_and_never_extracts_proof(self):
        proof = "proof_0123456789abcdef0123456789abcdef"
        response = {
            "url": "https://example.test/",
            "response_headers": {"Set-Cookie": "collapsed=wrong"},
            "response_header_pairs": [
                ("Set-Cookie", f"sid={proof}; Path=/; HttpOnly"),
                ("Set-Cookie", f"csrf={proof}; Path=/"),
            ],
            "body": f'<input name="csrf_token" value="{proof}">',
        }
        result = sr.analyze_response(response)
        self.assertEqual([item["name"] for item in result["cookies"]], ["sid", "csrf"])
        self.assertFalse(result["headers"]["ordered_pairs_degraded"])
        self.assertIsNone(result["proof"])
        self.assertEqual(result["network_requests"], 0)
        self.assertFalse(result["credentials_forged_or_replayed"])
        self.assertNotIn(proof, json.dumps(result))

    def test_caps_and_malformed_body_type(self):
        pairs = [("X-Test", str(index)) for index in range(sr.MAX_HEADERS + 20)]
        result = sr.analyze(pairs, body="x" * (sr.MAX_BODY + 100))
        self.assertTrue(result["headers"]["truncated"])
        self.assertLessEqual(result["headers"]["accepted_pairs"], sr.MAX_HEADERS)
        self.assertTrue(result["body"]["truncated"])
        malformed = sr.analyze([], body={"not": "text"})
        self.assertTrue(malformed["body"]["rejected_type"])
        self.assertEqual(malformed["body"]["inspected_bytes"], 0)

    def test_normalized_header_mapping_is_explicitly_degraded(self):
        result = sr.analyze({"response_headers": {"Set-Cookie": "a=x; Path=/"}, "body": b""},
                            source_url="https://example.test/")
        self.assertTrue(result["headers"]["ordered_pairs_degraded"])
        self.assertEqual(result["summary"]["cookies"], 1)

        direct = sr.analyze({"Set-Cookie": "b=y; Path=/"}, source_url="https://example.test/")
        self.assertTrue(direct["headers"]["ordered_pairs_degraded"])
        self.assertEqual([item["name"] for item in direct["cookies"]], ["b"])

    def test_utf8_body_cap_is_bytes_not_characters(self):
        result = sr.analyze([], body="é" * sr.MAX_BODY)
        self.assertTrue(result["body"]["truncated"])
        self.assertLessEqual(result["body"]["inspected_bytes"], sr.MAX_BODY + 3)

    def test_source_contains_no_network_or_execution_path(self):
        source = Path(sr.__file__).read_text()
        forbidden = ("urllib.request", "socket.", "requests.", "subprocess", "pickle.loads",
                     "yaml.load", "eval(", "exec(")
        self.assertFalse([word for word in forbidden if word in source])
        self.assertEqual(sr.__all__, ["analyze", "analyze_response"])

    def test_local_artifact_scopes_use_complete_sha256(self):
        first = sr._fingerprint("opaque-session-a")
        second = sr._fingerprint("opaque-session-b")
        self.assertRegex(first, r"^[0-9a-f]{64}$")
        self.assertNotEqual(first, second)

    def test_cooperative_stop_and_deadline_skip_sensitive_material(self):
        stop = threading.Event()
        stop.set()
        stopped = sr.analyze(
            [("Set-Cookie", "sid=opaque-session; Path=/")],
            body='<input name="csrf_token" value="abcdefgh12345678">',
            source_url="https://example.test/", stop=stop)
        self.assertTrue(stopped["stopped_early"])
        self.assertEqual(stopped["cookies"], [])
        self.assertEqual(stopped["csrf"]["tokens"], [])

        expired = sr.analyze(
            [("Set-Cookie", "sid=opaque-session; Path=/")],
            deadline=time.time() - 1)
        self.assertTrue(expired["stopped_early"])
        self.assertEqual(expired["cookies"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
