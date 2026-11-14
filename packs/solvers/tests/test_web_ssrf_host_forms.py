#!/usr/bin/env python3
"""Adversarial no-DNS tests for shared SSRF inner-URL classification."""

from __future__ import annotations

import socket
import sys
import unittest
from pathlib import Path
from unittest import mock


REPO = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path[:0] = [str(REPO / "solvers" / "web"), str(REPO / "solvers" / "toolkits")]
import web  # noqa: E402
import proof_hunt  # noqa: E402


class InternalHostTests(unittest.TestCase):
    def test_internal_ip_name_and_legacy_forms(self):
        accepted = (
            "127.0.0.1", "127.1", "2130706433", "0x7f000001",
            "0177.0.0.1", "0x7f.0.0.1", "127.0.00.1",
            "10.0.0.1", "10.1", "172.16.0.1", "192.168.1.1",
            "169.254.1.2", "169.254.169.254", "100.64.0.1", "100.127.255.254",
            "0.0.0.0", "::", "::1", "fc00::1", "fdff:ffff::1", "fe80::1",
            "::ffff:127.0.0.1", "::ffff:10.0.0.1", "[::1]",
            "localhost", "api.localhost", "service.internal", "printer.local",
            "inventory", "evil-local", "LOCALHOST.", "service.internal.", "127.0.0.1.",
        )
        for host in accepted:
            with self.subTest(host=host):
                self.assertTrue(web.internal_host(host))
                self.assertEqual(proof_hunt.internal_host(host), web.internal_host(host))

    def test_public_lookalikes_zones_malformed_and_overflow_are_rejected(self):
        rejected = (
            "", " 127.0.0.1", "127.0.0.1 ", "8.8.8.8", "134744072", "0x08080808",
            "010.0.0.1", "172.32.0.1", "192.169.0.1", "100.128.0.1",
            "169.253.255.255", "2001:4860:4860::8888", "::ffff:8.8.8.8",
            "localhost.evil.example", "internal.example", "local.example",
            "127.0.0.1.nip.io", "service.internal.evil", "localhost..", ".localhost",
            "inventory-", "-inventory", "a..internal", "foo_bar", "user@localhost",
            "fe80::1%eth0", "fe80::1%25eth0", "[fe80::1%25eth0]",
            "[::1", "::1]", "[[::1]]", "127.0.0.1\\evil", "127.0.0.1\n",
            "4294967296", "0x100000000", "256.0.0.1", "127.0.0.0x100",
            "08.0.0.1", "0x.0.0.1", "1.2.3.4.5", "1..1",
        )
        for host in rejected:
            with self.subTest(host=host):
                self.assertFalse(web.internal_host(host))

    def test_legacy_parser_widths_and_overflow(self):
        cases = {
            "2130706433": "127.0.0.1", "0x7f000001": "127.0.0.1",
            "017700000001": "127.0.0.1", "127.1": "127.0.0.1",
            "0177.01": "127.0.0.1", "0x7f.0x1": "127.0.0.1",
            "10.1": "10.0.0.1", "10.1.1": "10.1.0.1",
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(str(web.legacy_ipv4(value)), expected)
                self.assertEqual(proof_hunt._legacy_internal_ip(value), web.legacy_ipv4(value))
        for value in ("", "08", "+127", "-1", "0x", "1.16777216", "1.2.65536",
                      "1.2.3.256", "4294967296"):
            with self.subTest(value=value):
                self.assertIsNone(web.legacy_ipv4(value))

    def test_classification_never_resolves_dns(self):
        with mock.patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS called")):
            self.assertTrue(web.internal_host("inventory"))
            self.assertTrue(web.internal_host("service.internal"))
            self.assertFalse(web.internal_host("example.com"))
            self.assertIsNotNone(web.safe_internal_url("http://inventory/proof"))


class SafeInternalURLTests(unittest.TestCase):
    def test_safe_forms_normalize_authority_but_retain_encoded_route(self):
        cases = {
            "http://127.1/": "http://127.1/",
            "http://0177.0.0.1/a": "http://0177.0.0.1/a",
            "http://0x7f.0x0.0.1/a": "http://0x7f.0x0.0.1/a",
            "http://[::1]/a": "http://[::1]/a",
            "http://[::ffff:127.0.0.1]/a": "http://[::ffff:127.0.0.1]/a",
            "HTTP://LOCALHOST.:8080/a%2Fb?q=x": "http://localhost.:8080/a%2Fb?q=x",
            "https://service.internal/v1/proof": "https://service.internal/v1/proof",
            "http://printer.local/a&sol;b": "http://printer.local/a&sol;b",
            "http://inventory/": "http://inventory/",
            "file:///var/run/huntress/objective.txt": "file:///var/run/huntress/objective.txt",
            "file://localhost/etc/hosts": "file://localhost/etc/hosts",
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(web.safe_internal_url(value), expected)
                self.assertTrue(web.inner_url_ok(value))
                self.assertTrue(proof_hunt.inner_ok(value))

    def test_public_authority_and_parser_confusion_are_rejected(self):
        rejected = (
            "http://example.com/", "http://8.8.8.8/", "http://134744072/",
            "http://localhost.evil/", "http://127.0.0.1.nip.io/",
            "http://user@127.0.0.1/", "http://user:pass@127.0.0.1/",
            "http://127.0.0.1#fragment", "http://127.0.0.1/#",
            "http://127.0.0.1:bad/", "http://127.0.0.1:/", "http://127.0.0.1:00080/",
            "http://[::1/", "http://[::1]junk/", "http://[fe80::1%25eth0]/",
            "http://127.0.0.1\\@evil/", "http://127.0.0.1/a\\b",
            " http://127.0.0.1/", "http://127.0.0.1/\nnext",
            "//127.0.0.1/x", "gopher://127.0.0.1/", "ftp://127.0.0.1/",
            "file://inventory/etc/hosts", "file://user@localhost/etc/hosts", "file://localhost:80/x",
        )
        for value in rejected:
            with self.subTest(value=value):
                self.assertIsNone(web.safe_internal_url(value))
                self.assertFalse(proof_hunt.inner_ok(value))

    def test_fixed_point_traversal_scheme_destructive_and_unfinished_encodings(self):
        rejected = (
            "http://127.0.0.1/a/../b",
            "http://127.0.0.1/a/%2e%2e/b",
            "http://127.0.0.1/a/%252e%252e/b",
            "http://127.0.0.1/a/&period;&period;/b",
            "http://127.0.0.1/a/%255Cu002e%255Cu002e/b",
            "http://127.0.0.1/safe／．．／admin",
            "http://127.0.0.1/safe%EF%BC%8F%EF%BC%8E%EF%BC%8E%EF%BC%8Fadmin",
            "http://127.0.0.1/next%253dhttp%253a%252f%252f8.8.8.8/",
            "http://127.0.0.1/?next=http%253a%252f%252f8.8.8.8",
            "http://127.0.0.1/fetch?url=//169.254.169.254/latest/meta-data",
            "http://127.0.0.1/fetch?url=%2F%2F169.254.169.254/latest/meta-data",
            "http://127.0.0.1/fetch?url=%252F%252F169.254.169.254/latest/meta-data",
            "http://127.0.0.1/fetch?outer=next%3D%252F%252F169.254.169.254/x",
            "http://127.0.0.1/fetch?payload=%7B%22url%22%3A%22%2F%2F169.254.169.254%2Flatest%22%7D",
            "http://127.0.0.1/fetch?x=(//169.254.169.254/x)",
            "http://127.0.0.1/fetch?url=／／169.254.169.254/latest",
            "http://127.0.0.1/fetch?url=%EF%BC%8F%EF%BC%8F169.254.169.254/latest",
            "http://127.0.0.1/fetch?p=%7B%22url%22%3A%22https%3Aevil.example%2Fx%22%7D",
            "http://127.0.0.1/fetch?p=(http:169.254.169.254/latest)",
            "http://127.0.0.1/admin/delete",
            "http://127.0.0.1/admin/de%256cete",
            "http://127.0.0.1/?action=re%2573et",
            "http://localhost/run", "http://localhost/deleteUser",
            "http://localhost/createJob", "http://localhost/rebootNow",
            "http://localhost/runTask", "http://localhost/?action=deleteUser",
            "http://localhost/deleteuser", "http://localhost/resetpassword",
            "http://localhost/createjob", "http://localhost/transferfunds",
            "http://localhost/delete;foo", "http://localhost/reset,confirm",
            "http://localhost/logout+now",
            "http://127.0.0.1/%", "http://127.0.0.1/%2", "http://127.0.0.1/%GG",
            "http://127.0.0.1/%25", "http://127.0.0.1/%255Cu002",
        )
        for value in rejected:
            with self.subTest(value=value):
                self.assertIsNone(web.safe_internal_url(value))
                self.assertFalse(proof_hunt.inner_ok(value))

        encoded_benign = "http://127.0.0.1/a%252fb?name=alpha%252Dbeta"
        self.assertEqual(web.safe_internal_url(encoded_benign), encoded_benign)
        self.assertIsNone(web.safe_internal_url("http://127.0.0.1/private/secret",
                                                destructive=lambda text: "secret" in text))

    def test_decode_and_size_bounds_fail_closed(self):
        nested = "http://127.0.0.1/" + "%25" * 13 + "2e"
        self.assertIsNone(web.safe_internal_url(nested))
        self.assertIsNone(web.safe_internal_url("http://127.0.0.1/abcd", max_bytes=16))
        self.assertIsNone(web.safe_internal_url("http://127.0.0.1/", max_bytes=0))
        self.assertIsNone(web.safe_internal_url("http://127.0.0.1/", max_bytes="bad"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
