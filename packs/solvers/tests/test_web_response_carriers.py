#!/usr/bin/env python3
"""Offline adversarial tests for solvers/web/response_carriers.py."""

from __future__ import annotations

import base64
import gzip
import importlib.util
import io
import json
import stat
import sys
import tarfile
import time
import unittest
import zipfile
import zlib
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
MODULE = REPO / "solvers" / "web" / "response_carriers.py"
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("response_carriers", MODULE)
if spec is None or spec.loader is None:
    raise RuntimeError(f"cannot load {MODULE}")
R = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = R
spec.loader.exec_module(R)

PROOF = b"proof_0123456789abcdef0123456789abcdef"


def content(result):
    return [(leaf.data, leaf.provenance, leaf.kind, leaf.metadata_dict())
            for leaf in result.content_leaves()]


def issue_codes(result):
    return [issue.code for issue in result.issues]


def zip_bytes(entries):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for entry in entries:
            if len(entry) == 2:
                archive.writestr(entry[0], entry[1])
            else:
                archive.writestr(entry[0], entry[1], compress_type=entry[2])
    return out.getvalue()


def tar_bytes(entries):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as archive:
        for name, value, kind in entries:
            info = tarfile.TarInfo(name)
            if kind == "file":
                info.size = len(value)
                archive.addfile(info, io.BytesIO(value))
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = value.decode()
                archive.addfile(info)
            elif kind == "device":
                info.type = tarfile.CHRTYPE
                archive.addfile(info)
    return out.getvalue()


class ResponseCarrierTests(unittest.TestCase):
    def test_raw_body_is_exact_and_plain_text_is_a_separate_leaf(self):
        body = b"prefix\x00binary\xff"
        result = R.decode_response(body)
        self.assertEqual(result.raw_body, body)
        self.assertFalse(result.content_leaves())
        self.assertTrue(any(leaf.kind == "opaque" for leaf in result.leaves))

        plain = R.decode_response(PROOF, {"Content-Type": "text/plain; charset=utf-8"})
        self.assertEqual(plain.raw_body, PROOF)
        self.assertEqual([leaf.data for leaf in plain.content_leaves()], [PROOF])

    def test_chained_content_encoding_is_decoded_in_reverse_order(self):
        # gzip was applied first, raw DEFLATE second; the wire header records that order.
        first = gzip.compress(PROOF)
        compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
        wire = compressor.compress(first) + compressor.flush()
        result = R.decode_response(wire, {
            "Content-Encoding": "gzip, deflate",
            "Content-Type": "text/plain; charset=utf-8",
        })
        self.assertIn(PROOF, [leaf.data for leaf in result.content_leaves()])
        decoded = next(leaf for leaf in result.leaves if leaf.kind == "content-decoded")
        self.assertEqual(decoded.provenance[-2:], ("content-encoding:deflate", "content-encoding:gzip"))

    def test_http_raw_deflate_and_nested_gzip_zlib_base64(self):
        compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
        raw = compressor.compress(PROOF) + compressor.flush()
        result = R.decode_response(raw, {"Content-Encoding": "deflate", "Content-Type": "text/plain"})
        self.assertIn(PROOF, [leaf.data for leaf in result.content_leaves()])

        nested = base64.b64encode(zlib.compress(gzip.compress(PROOF)))
        result = R.decode_response(nested, {"Content-Type": "text/plain; charset=us-ascii"})
        self.assertIn(PROOF, [leaf.data for leaf in result.content_leaves()])
        proof_leaf = next(leaf for leaf in result.content_leaves() if leaf.data == PROOF)
        self.assertEqual(proof_leaf.provenance[-4:],
                         ("base64", "nested:zlib", "nested:gzip", "text:utf-8"))

        unpadded = base64.b64encode(PROOF).rstrip(b"=")
        result = R.decode_response(unpadded, {"Content-Type": "text/plain"})
        self.assertIn(PROOF, [leaf.data for leaf in result.content_leaves()])

    def test_optional_brotli_and_zstandard_content_encodings(self):
        try:
            import brotli
        except ImportError:
            brotli = None
        if brotli is not None:
            result = R.decode_response(brotli.compress(PROOF), {
                "Content-Encoding": "br", "Content-Type": "text/plain",
            })
            self.assertIn(PROOF, [leaf.data for leaf in result.content_leaves()])
        try:
            import zstandard
        except ImportError:
            zstandard = None
        if zstandard is not None:
            wire = zstandard.ZstdCompressor().compress(PROOF)
            result = R.decode_response(wire, {
                "Content-Encoding": "zstd", "Content-Type": "text/plain",
            })
            self.assertIn(PROOF, [leaf.data for leaf in result.content_leaves()])
            for malformed in (wire[:-1], wire + b"trailing"):
                result = R.decode_response(malformed, {
                    "Content-Encoding": "zstd", "Content-Type": "text/plain",
                })
                self.assertEqual(result.content_leaves(), ())
                self.assertIn("malformed_compression", issue_codes(result))

        unsupported = R.decode_response(b"anything", {"Content-Encoding": "compress"})
        self.assertEqual(unsupported.content_leaves(), ())
        self.assertIn("unsupported_encoding", issue_codes(unsupported))

    def test_utf_boms_override_conflicting_charset_and_single_byte_charsets(self):
        text = "snowman \u2603"
        body = text.encode("utf-16")
        result = R.decode_response(body, {"Content-Type": "text/plain; charset=windows-1252"})
        self.assertEqual([leaf.data for leaf in result.content_leaves()], [text.encode()])
        self.assertIn("charset_bom_conflict", issue_codes(result))

        legacy = R.decode_response(b"caf\xe9", {"Content-Type": "text/plain; charset=iso-8859-1"})
        self.assertEqual([leaf.data for leaf in legacy.content_leaves()], ["caf\xe9".encode()])

        utf32 = R.decode_response("wide".encode("utf-32"), {"Content-Type": "text/plain"})
        self.assertEqual([leaf.data for leaf in utf32.content_leaves()], [b"wide"])

        unknown = R.decode_response("bom wins".encode("utf-8-sig"),
                                    {"Content-Type": "text/plain; charset=x-made-up"})
        self.assertEqual([leaf.data for leaf in unknown.content_leaves()], [b"bom wins"])
        self.assertIn("unsupported_charset", issue_codes(unknown))

    def test_declared_json_never_normalizes_invalid_utf8_through_legacy_text(self):
        body = (b'{"ok":true,"effect":"forged_event_consumed","note":"\x80",'
                b'"proof":"' + PROOF + b'"}')
        result = R.decode_response(body, {"Content-Type": "application/json"})
        self.assertEqual(result.content_leaves(), ())
        self.assertIn("malformed_text", issue_codes(result))

        vendor = R.decode_response(body, {"Content-Type": "application/problem+json"})
        self.assertEqual(vendor.content_leaves(), ())
        self.assertIn("malformed_text", issue_codes(vendor))

    def test_weak_binary_magic_cannot_erase_explicit_plain_text(self):
        zlib_collision = b"x evidence: " + PROOF
        self.assertTrue(R._looks_zlib(zlib_collision))
        result = R.decode_response(zlib_collision, {"Content-Type": "text/plain"})
        self.assertEqual([leaf.data for leaf in result.content_leaves()], [zlib_collision])
        self.assertNotIn("malformed_compression", issue_codes(result))

        tar_collision = bytearray(b"A" * 600)
        tar_collision[:len(PROOF)] = PROOF
        tar_collision[257:263] = b"ustar\x00"
        self.assertTrue(R._looks_tar(bytes(tar_collision)))
        result = R.decode_response(bytes(tar_collision), {"Content-Type": "text/plain"})
        self.assertEqual([leaf.data for leaf in result.content_leaves()], [bytes(tar_collision)])
        self.assertNotIn("malformed_archive", issue_codes(result))

    def test_multipart_transfer_encodings_duplicate_names_and_nested_parts(self):
        body = (
            b"--OUT\r\nContent-Disposition: form-data; name=\"same\"\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
            base64.b64encode(b"first") +
            b"\r\n--OUT\r\nContent-Disposition: form-data; name=\"same\"\r\n"
            b"Content-Type: multipart/alternative; boundary=IN\r\n\r\n"
            b"--IN\r\nContent-Type: text/plain; charset=utf-8\r\n"
            b"Content-Transfer-Encoding: quoted-printable\r\n\r\nsecond=20part\r\n"
            b"--IN--\r\n--OUT--\r\n"
        )
        result = R.decode_response(body, {"Content-Type": "multipart/form-data; boundary=OUT"})
        leaves = result.content_leaves()
        self.assertEqual([leaf.data for leaf in leaves], [b"first", b"second part"])
        self.assertNotEqual(leaves[0].provenance, leaves[1].provenance)
        self.assertEqual(leaves[0].metadata_dict()["name"], "same")
        self.assertEqual(leaves[1].metadata_dict()["name"], "same")
        self.assertFalse(result.issues, result.issues)

    def test_malformed_multipart_and_transfer_encoding_fail_closed(self):
        cut = b"--B\r\nContent-Type: text/plain\r\n\r\nsecret"
        result = R.decode_response(cut, {"Content-Type": "multipart/mixed; boundary=B"})
        self.assertEqual(result.content_leaves(), ())
        self.assertIn("malformed_mime", issue_codes(result))

        bad = (b"--B\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n"
               b"%%%%\r\n--B--\r\n")
        result = R.decode_response(bad, {"Content-Type": "multipart/mixed; boundary=B"})
        self.assertEqual(result.content_leaves(), ())
        self.assertIn("malformed_transfer_encoding", issue_codes(result))

    def test_multipart_fanout_is_refused_before_stdlib_tree_construction(self):
        body = b"".join(
            b"--B\r\nContent-Type: text/plain\r\n\r\nx\r\n"
            for _ in range(300)
        ) + b"--B--\r\n"
        limits = R.CarrierLimits(
            max_input_bytes=1 << 20, max_leaf_bytes=1024,
            max_total_expanded_bytes=4096, max_leaves=8, max_depth=4,
            max_compression_ratio=32, max_work_bytes=1 << 20,
            max_archive_members=8, max_jwts=2,
        )
        result = R.decode_response(
            body, {"Content-Type": "multipart/mixed; boundary=B"}, limits=limits)
        self.assertEqual(result.content_leaves(), ())
        self.assertIn("leaf_count_limit", issue_codes(result))
        self.assertEqual(result.stats.work_bytes, 0,
                         "fanout must be rejected before BytesParser builds the MIME tree")

    def test_conflicting_or_invalid_critical_headers_fail_closed(self):
        body = b'{"ok":true,"proof":"' + PROOF + b'"}'
        conflicting = R.decode_response(body, [
            ("Content-Type", "application/json"), ("Content-Type", "text/plain")])
        self.assertEqual(conflicting.content_leaves(), ())
        self.assertIn("conflicting_content_type", issue_codes(conflicting))

        invalid = R.decode_response(body, [("Content-Encoding", "gzip\r\nX-Evil: yes")])
        self.assertEqual(invalid.content_leaves(), ())
        self.assertIn("invalid_critical_header", issue_codes(invalid))

        duplicate = R.decode_response(body, [
            ("Content-Type", "application/json"), ("Content-Type", "application/json")])
        self.assertEqual(duplicate.content_leaves(), ())
        self.assertIn("conflicting_content_type", issue_codes(duplicate))

        twice = base64.b85encode(base64.b85encode(body))
        duplicate_encoding = R.decode_response(twice, [
            ("Content-Type", "application/json"),
            ("Content-Encoding", "base85"), ("Content-Encoding", "base85")])
        self.assertEqual(duplicate_encoding.content_leaves(), ())
        self.assertIn("ambiguous_content_encoding", issue_codes(duplicate_encoding))

    def test_duplicate_content_type_parameters_and_mime_headers_fail_closed(self):
        body = (b"--A\r\nContent-Type: text/plain\r\n\r\n" + PROOF
                + b"\r\n--A--\r\n")
        duplicate_boundary = R.decode_response(
            body, {"Content-Type": "multipart/mixed; boundary=A; boundary=B"})
        self.assertEqual(duplicate_boundary.content_leaves(), ())
        self.assertIn("ambiguous_content_type", issue_codes(duplicate_boundary))

        duplicate_charset = R.decode_response(
            PROOF, {"Content-Type": "text/plain; charset=utf-8; charset=us-ascii"})
        self.assertEqual(duplicate_charset.content_leaves(), ())
        self.assertIn("ambiguous_content_type", issue_codes(duplicate_charset))

        # Python 3.9's email parser joins these RFC2231 continuations into a
        # seemingly ordinary boundary.  The raw syntax must remain visible to
        # the policy layer and fail closed on every supported interpreter.
        continued_boundary = R.decode_response(
            body, {"Content-Type": "multipart/mixed; boundary*0=A; boundary*1=B"})
        self.assertEqual(continued_boundary.content_leaves(), ())
        self.assertIn("ambiguous_content_type", issue_codes(continued_boundary))

        malformed_bare = R.decode_response(
            PROOF, {"Content-Type": "text/plain; charset"})
        self.assertEqual(malformed_bare.content_leaves(), ())
        self.assertIn("ambiguous_content_type", issue_codes(malformed_bare))

        inner = (b"--A\r\nContent-Type: application/json\r\n"
                 b"Content-Type: text/plain\r\n\r\n" + PROOF + b"\r\n--A--\r\n")
        duplicate_part = R.decode_response(
            inner, {"Content-Type": "multipart/mixed; boundary=A"})
        self.assertEqual(duplicate_part.content_leaves(), ())
        self.assertIn("ambiguous_mime_header", issue_codes(duplicate_part))

    def test_json_scalars_stay_separate_duplicates_survive_and_surrogates_join(self):
        body = br'{"left":"proof_0123456789abcdef","right":"0123456789abcdef","dup":1,"dup":2,"face":"\ud83d\ude00"}'
        result = R.decode_response(body, {"Content-Type": "application/json"})
        values = [leaf.data for leaf in result.content_leaves()]
        self.assertIn(b"proof_0123456789abcdef", values)
        self.assertIn(b"0123456789abcdef", values)
        self.assertNotIn(PROOF, values, "unrelated JSON strings must never be concatenated")
        self.assertEqual(values.count(b"1"), 1)
        self.assertEqual(values.count(b"2"), 1)
        self.assertIn("\U0001f600".encode(), values)
        duplicates = [leaf.provenance[-1] for leaf in result.content_leaves() if leaf.data in (b"1", b"2")]
        self.assertEqual(duplicates, ["json:/dup#0", "json:/dup#1"])

        lone = R.decode_response(br'{"bad":"\ud800"}', {"Content-Type": "application/json"})
        self.assertFalse(lone.content_leaves())
        self.assertIn("malformed_json_string", issue_codes(lone))

        null = R.decode_response(b"null", {"Content-Type": "application/json"})
        self.assertEqual([leaf.data for leaf in null.content_leaves()], [b"null"])

        huge_number = b'{"n":' + (b"9" * 100_000) + b'}'
        started = time.monotonic()
        huge = R.decode_response(huge_number, {"Content-Type": "application/json"})
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertFalse(huge.content_leaves())
        self.assertIn("malformed_json", issue_codes(huge))

        overflow = R.decode_response(b'{"n":1e999999}', {"Content-Type": "application/json"})
        self.assertFalse(overflow.content_leaves())
        self.assertIn("malformed_json", issue_codes(overflow))

    def test_json_scalar_fanout_keeps_complete_structural_document(self):
        document = {f"filler_{index}": "ordinary" for index in range(700)}
        raw = json.dumps(document, separators=(",", ":")).encode()
        result = R.decode_response(raw, {"Content-Type": "application/json"})
        documents = [leaf for leaf in result.leaves if leaf.kind == "json-document"]
        self.assertEqual([leaf.data for leaf in documents], [raw])
        self.assertNotIn("leaf_count_limit", issue_codes(result))

    def test_explicit_javascript_is_not_json_or_accidental_jwt(self):
        samples = (
            b"const x = window.location.hash;",
            b"[foo].forEach(render);",
            b'["use strict"]; location.hash;',
        )
        for body in samples:
            for media_type in ("application/javascript", "text/javascript"):
                with self.subTest(body=body, media_type=media_type):
                    result = R.decode_response(body, {"Content-Type": media_type})
                    self.assertIn(body, [leaf.data for leaf in result.content_leaves()])
                    self.assertNotIn("malformed_json", issue_codes(result))

    def test_mime_child_parameters_are_validated_before_email_normalization(self):
        cases = (
            ("Content-Type: text/plain; charset*0=utf-; charset*1=8", b"proof"),
            ("Content-Type: text/plain; charset=utf-8; charset=latin-1", b"proof"),
            ("Content-Type: multipart/mixed; boundary*0=IN",
             b"--IN\r\nContent-Type: text/plain\r\n\r\nproof\r\n--IN--\r\n"),
        )
        for child_header, payload in cases:
            body = (b"--OUT\r\n" + child_header.encode() + b"\r\n\r\n" + payload
                    + b"\r\n--OUT--\r\n")
            with self.subTest(child_header=child_header):
                result = R.decode_response(
                    body, {"Content-Type": "multipart/mixed; boundary=OUT"})
                self.assertFalse(result.content_leaves())
                self.assertIn("ambiguous_mime_header", issue_codes(result))

    def test_text_templates_are_not_misclassified_as_malformed_json(self):
        for body in (b"{{objective}}", b"{ color: red; }", b"{function call() {}}"):
            with self.subTest(body=body):
                result = R.decode_response(body, {"Content-Type": "text/plain"})
                self.assertIn(body, [leaf.data for leaf in result.content_leaves()])
                self.assertNotIn("malformed_json", issue_codes(result))

        malformed = R.decode_response(b'{"ok":', {"Content-Type": "text/plain"})
        self.assertEqual(malformed.content_leaves(), ())
        self.assertIn("malformed_json", issue_codes(malformed))

    def test_compact_jwt_claims_are_unverified_separate_leaves(self):
        enc = lambda value: base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode().rstrip("=")
        token = enc({"alg": "none", "kid": "demo"}) + "." + enc({"role": "admin", "proof": PROOF.decode()}) + "."
        result = R.decode_response(("bearer " + token).encode(), {"Content-Type": "text/plain"})
        jwt_leaves = [leaf for leaf in result.content_leaves() if "unverified" in "|".join(leaf.provenance)]
        self.assertIn(PROOF, [leaf.data for leaf in jwt_leaves])
        self.assertTrue(all(leaf.metadata_dict().get("unverified") == "true" for leaf in jwt_leaves))
        self.assertTrue(any(leaf.metadata_dict().get("jwt_section") == "header" for leaf in jwt_leaves))
        self.assertTrue(any(leaf.metadata_dict().get("jwt_section") == "payload" for leaf in jwt_leaves))

    def test_zip_regular_content_is_searchable_but_names_links_and_traversal_are_not(self):
        proof_name = PROOF.decode() + ".txt"
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("safe/content.txt", PROOF)
            archive.writestr(proof_name, b"benign")
            archive.writestr("../escape.txt", PROOF)
            link = zipfile.ZipInfo("link")
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(link, b"safe/content.txt")
        result = R.decode_response(out.getvalue(), {"Content-Type": "application/zip"})
        self.assertEqual([leaf.data for leaf in result.content_leaves()].count(PROOF), 1)
        self.assertFalse(any(proof_name.encode() in leaf.data for leaf in result.content_leaves()))
        self.assertGreaterEqual(issue_codes(result).count("unsafe_archive_member"), 2)
        proof_leaf = next(leaf for leaf in result.content_leaves() if leaf.data == PROOF)
        self.assertEqual(proof_leaf.metadata_dict()["filename"], "safe/content.txt")

    def test_tar_regular_content_is_searchable_but_special_members_are_not(self):
        body = tar_bytes([
            ("safe.txt", PROOF, "file"),
            ("../escape.txt", PROOF, "file"),
            ("link", b"safe.txt", "symlink"),
            ("tty", b"", "device"),
        ])
        result = R.decode_response(body, {"Content-Type": "application/x-tar"})
        self.assertEqual([leaf.data for leaf in result.content_leaves()].count(PROOF), 1)
        self.assertGreaterEqual(issue_codes(result).count("unsafe_archive_member"), 3)

    def test_truncated_compression_and_archive_fail_closed(self):
        compressed = gzip.compress(PROOF)
        result = R.decode_response(compressed[:-4], {"Content-Encoding": "gzip", "Content-Type": "text/plain"})
        self.assertEqual(result.content_leaves(), ())
        self.assertIn("malformed_compression", issue_codes(result))

        archive = zip_bytes([("proof.txt", PROOF)])
        result = R.decode_response(archive[:-12], {"Content-Type": "application/zip"})
        self.assertEqual(result.content_leaves(), ())
        self.assertIn("malformed_archive", issue_codes(result))

        wrong_magic = R.decode_response(b"not a zip", {"Content-Type": "application/zip"})
        self.assertEqual(wrong_magic.content_leaves(), ())
        self.assertIn("malformed_archive", issue_codes(wrong_magic))

    def test_gzip_and_zip_bombs_stop_at_ratio_bound(self):
        huge = b"A" * (256 << 10)
        limits = R.CarrierLimits(max_input_bytes=1 << 20, max_leaf_bytes=1 << 20,
                                 max_total_expanded_bytes=2 << 20, max_leaves=32,
                                 max_depth=4, max_compression_ratio=4,
                                 max_work_bytes=4 << 20, max_archive_members=8, max_jwts=4)
        gz = R.decode_response(gzip.compress(huge), {"Content-Encoding": "gzip"}, limits=limits)
        self.assertEqual(gz.content_leaves(), ())
        self.assertIn("compression_ratio", issue_codes(gz))
        self.assertLessEqual(gz.stats.expanded_bytes, len(gzip.compress(huge)) * 4)

        bomb = R.decode_response(zip_bytes([("bomb.txt", huge)]), limits=limits)
        self.assertEqual(bomb.content_leaves(), ())
        self.assertIn("compression_ratio", issue_codes(bomb))
        self.assertEqual(bomb.stats.expanded_bytes, 0)

    def test_input_aggregate_leaf_depth_and_work_caps(self):
        tiny = R.CarrierLimits(max_input_bytes=4, max_leaf_bytes=64,
                               max_total_expanded_bytes=128, max_leaves=8,
                               max_depth=3, max_compression_ratio=128,
                               max_work_bytes=512, max_archive_members=8, max_jwts=2)
        too_big = R.decode_response(b"12345", limits=tiny)
        self.assertEqual(too_big.raw_body, b"12345")
        self.assertEqual(too_big.leaves, ())
        self.assertIn("input_limit", issue_codes(too_big))

        aggregate = R.decode_response(b'["aaaaaaaa","bbbbbbbb","cccccccc"]',
            {"Content-Type": "application/json"},
            limits=R.CarrierLimits(max_input_bytes=128, max_leaf_bytes=64,
                                   max_total_expanded_bytes=48, max_leaves=20,
                                   max_depth=5, max_compression_ratio=32,
                                   max_work_bytes=1024, max_archive_members=8, max_jwts=2))
        self.assertIn("aggregate_limit", issue_codes(aggregate))

        many = R.decode_response(b"[1,2,3,4,5]", {"Content-Type": "application/json"},
            limits=R.CarrierLimits(max_input_bytes=64, max_leaf_bytes=64,
                                   max_total_expanded_bytes=256, max_leaves=3,
                                   max_depth=5, max_compression_ratio=32,
                                   max_work_bytes=1024, max_archive_members=8, max_jwts=2))
        self.assertEqual(len(many.leaves), 3)
        self.assertEqual(many.leaves[0].kind, "json-document")
        self.assertNotIn("leaf_count_limit", issue_codes(many),
                         "optional scalar fan-out cannot poison a complete JSON document")

        deep = base64.b64encode(base64.b64encode(base64.b64encode(base64.b64encode(PROOF))))
        limited = R.decode_response(deep, {"Content-Type": "text/plain"},
            limits=R.CarrierLimits(max_input_bytes=1024, max_leaf_bytes=1024,
                                   max_total_expanded_bytes=4096, max_leaves=32,
                                   max_depth=2, max_compression_ratio=128,
                                   max_work_bytes=8192, max_archive_members=8, max_jwts=2))
        self.assertNotIn(PROOF, [leaf.data for leaf in limited.content_leaves()])
        self.assertIn("depth_limit", issue_codes(limited))

        work = R.decode_response(base64.b64encode(PROOF), {"Content-Type": "text/plain"},
            limits=R.CarrierLimits(max_input_bytes=1024, max_leaf_bytes=1024,
                                   max_total_expanded_bytes=4096, max_leaves=32,
                                   max_depth=4, max_compression_ratio=128,
                                   max_work_bytes=60, max_archive_members=8, max_jwts=2))
        self.assertIn("work_limit", issue_codes(work))

    def test_wide_json_cannot_allocate_one_issue_per_remaining_scalar(self):
        # The leaf cap must stop traversal too.  Merely refusing each output
        # while walking the rest of an enormous array creates its own memory
        # bomb through per-index diagnostics.
        body = b"[" + b",".join([b"0"] * 400_000) + b"]"
        result = R.decode_response(body, {"Content-Type": "application/json"})
        self.assertLessEqual(len(result.leaves), R.DEFAULT_LIMITS.max_leaves)
        self.assertLessEqual(len(result.issues), R.DEFAULT_LIMITS.max_issues)
        self.assertIn("leaf_count_limit", issue_codes(result))

    def test_public_header_iterables_are_bounded(self):
        consumed = []

        def headers():
            index = 0
            while True:
                consumed.append(index)
                if index > 600:
                    raise AssertionError("header decoder failed to stop its iterable")
                yield (f"X-{index}", "value")
                index += 1

        result = R.decode_response(b"plain", headers())
        self.assertIn("header_limit", issue_codes(result))
        self.assertLessEqual(len(consumed), 513)

        values = R.decode_response(b"plain", {"X-Many": ["v"] * 1000})
        self.assertIn("header_limit", issue_codes(values))

    def test_provenance_and_output_are_deterministic(self):
        body = zip_bytes([("a.json", b'{"x":"one","x":"two"}'), ("b.txt", b"three")])
        one = R.decode_response(body)
        two = R.decode_response(body)
        self.assertEqual(one, two)
        self.assertEqual([leaf.provenance for leaf in one.leaves],
                         [leaf.provenance for leaf in two.leaves])


if __name__ == "__main__":
    unittest.main(verbosity=2)
