#!/usr/bin/env python3
"""No-network integration checks for the Day-27 web coverage expansion."""

from __future__ import annotations

import event_pin  # noqa: E402  (tests/event_pin.py)
event_pin.pin(globals(), "huntress")  # Huntress web tests: proof_<32 hex> payoffs (events/huntress [proof])

import gzip
import io
import json
import sys
import threading
import time
import zipfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path[:0] = [str(REPO / "solvers" / "web"), str(REPO / "solvers" / "toolkits")]

import proof_hunt as PH  # noqa: E402


BASE = "http://fake.local/"
PROOF = "proof_0123456789abcdef0123456789abcdef"


class Client:
    base = BASE
    timeout = 8.0

    def __init__(self, replies):
        self.replies = replies
        self.calls = []

    def request(self, method, path, data=None, headers=None, allow_redirects=True):
        self.calls.append({"method": method, "path": path, "data": data,
                           "headers": dict(headers or {}), "redirects": allow_redirects})
        reply = self.replies(method, path, data, dict(headers or {})) \
            if callable(self.replies) else self.replies[path]
        out = dict(reply)
        out.setdefault("response_headers", {})
        out.setdefault("response_header_pairs", list(out["response_headers"].items()))
        out.setdefault("final_url", BASE.rstrip("/") + path)
        return out


def hunter(client, budget=80):
    h = PH._Hunter(BASE, deadline=time.time() + 10, max_requests=budget,
                   stop=threading.Event(), prompt="Recover the proof.")
    h.client = client
    h.forge_target = {"answer_id": "proof-1", "url": BASE, "index": 1,
                      "question": "Recover the proof."}
    h.forge_ctx = {}
    return h


def response(body, status=200, headers=None, pairs=None):
    out = {"status": status, "body": body,
           "response_headers": dict(headers or {})}
    if pairs is not None:
        out["response_header_pairs"] = list(pairs)
    return out


def success_doc():
    return json.dumps({"ok": True, "effect": "internal_read", "proof": PROOF},
                      separators=(",", ":")).encode()


def test_hunter_decodes_compressed_and_archive_payoffs_but_fails_closed_malformed():
    encoded = response(gzip.compress(success_doc()), headers={
        "Content-Type": "application/json", "Content-Encoding": "gzip"})
    h = hunter(Client({"/read": encoded}), budget=1)
    h.fetch("/read", "test", True, "carrier")
    assert h.answer() == PROOF and h.pages["/read"]["carrier_view_count"] >= 1, h.pages

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("objective.json", success_doc())
    h = hunter(Client({"/read": response(buf.getvalue(), headers={
        "Content-Type": "application/zip"})}), budget=1)
    h.fetch("/read", "test", True, "carrier")
    assert h.answer() == PROOF, h.pages

    malformed = b"not-gzip " + PROOF.encode()
    h = hunter(Client({"/read": response(malformed, headers={
        "Content-Type": "application/json", "Content-Encoding": "gzip"})}), budget=1)
    h.fetch("/read", "test", True, "carrier")
    assert h.answer() is None and PROOF not in h.payoff, h.pages


def test_hunter_never_joins_sibling_carriers_into_a_proof():
    boundary = "parts"
    body = (f"--{boundary}\r\nContent-Type: text/plain\r\n\r\n"
            "proof_0123456789abcdef\r\n"
            f"--{boundary}\r\nContent-Type: text/plain\r\n\r\n"
            "0123456789abcdef\r\n"
            f"--{boundary}--\r\n").encode()
    h = hunter(Client({"/read": response(body, headers={
        "Content-Type": f"multipart/mixed; boundary={boundary}"})}), budget=1)
    h.fetch("/read", "test", True, "multipart")
    assert h.answer() is None and PROOF not in h.payoff, h.pages


def test_zip_filename_is_metadata_and_never_proof_evidence():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(PROOF, b"harmless member body")
    h = hunter(Client({"/read": response(buf.getvalue(), headers={
        "Content-Type": "application/zip"})}), budget=1)
    h.fetch("/read", "test", True, "archive-name")
    assert h.answer() is None and PROOF not in h.payoff, h.pages


def test_browser_recon_is_recorded_offline_and_never_promoted_to_proof():
    html = b"""<!doctype html><html><body>
      <div v-html="location.hash"></div>
      <script>function f(){const x=location.search; out.innerHTML=x;}</script>
      </body></html>"""
    reply = response(gzip.compress(html), headers={"Content-Type": "text/html",
                                                   "Content-Encoding": "gzip"}, pairs=[
        ("Content-Type", "text/html"), ("Content-Encoding", "gzip"),
        ("Content-Security-Policy-Report-Only", "default-src 'self'; script-src 'unsafe-inline'"),
    ])
    client = Client({"/": reply})
    h = hunter(client, budget=1)
    h.fetch("/", "plain", False, "recon")
    kinds = {row.get("kind") for row in h.recon_findings
             if row.get("class") == "browser_recon"}
    sinks = {row.get("sink") for row in h.recon_findings
             if row.get("class") == "browser_recon"}
    assert "csp_report_only_without_enforcement" in kinds, h.recon_findings
    assert {"vue_v_html", "innerHTML"} <= sinks, h.recon_findings
    assert h.answer() is None and len(client.calls) == 1


def test_session_cookie_recon_is_offline_value_redacted_and_carrier_local():
    token = "A1b2C3d4E5f6G7h8"
    html = (f'<form><input type="hidden" name="csrf_token" value="{token}"></form>').encode()
    reply = response(html, headers={"Content-Type": "text/html"}, pairs=[
        ("Content-Type", "text/html"),
        ("Set-Cookie", f"csrf_token={token}; Path=/; SameSite=Lax"),
        ("Set-Cookie", "sid=one; Path=/; Secure; HttpOnly"),
        ("Set-Cookie", "sid=two; Path=/admin; Secure; HttpOnly"),
    ])
    client = Client({"/login": reply})
    h = hunter(client, budget=1)
    h.fetch("/login", "plain", False, "recon")
    rows = [row for row in h.recon_findings if row.get("class") == "session_recon"]
    reports = h.pages["/login"].get("session_recon") or []
    assert rows and reports, (h.recon_findings, h.pages["/login"])
    assert rows[0]["summary"]["cookies"] == 3 and rows[0]["csrf_bindings"] >= 1, rows
    assert rows[0]["duplicate_names"] == ["sid"], rows
    rendered = json.dumps({"rows": rows, "reports": reports})
    assert token not in rendered, rendered
    assert all(report["network_requests"] == 0 and report["proof"] is None for report in reports)
    assert h.answer() is None and len(client.calls) == 1


def test_ambiguous_http_framing_is_baseline_only_never_payoff():
    reply = response(success_doc(), headers={"Content-Type": "application/json"}, pairs=[
        ("Content-Type", "application/json"),
        ("Content-Length", str(len(success_doc()))),
        ("Content-Length", "5"),
    ])
    h = hunter(Client({"/read": reply}), budget=1)
    page = h.fetch("/read", "test", True, "framing")
    assert page.get("framing_error") and not page["payoff"], page
    assert h.answer() is None and PROOF not in h.payoff, (h.pages, h.payoff)


def test_truncated_direct_control_poisons_plain_and_decoded_novelty():
    replies = {
        "/": dict(response(b"visible prefix", headers={"Content-Type": "text/plain"}),
                  truncated=True),
        "/read": response(success_doc(), headers={"Content-Type": "application/json"}),
    }
    h = hunter(Client(replies), budget=2)
    h.fetch("/", "plain", False, "root")
    h.fetch("/read", "test", True, "payoff")
    assert h.baseline_incomplete and h.pages["/"]["baseline_incomplete"], h.pages
    assert h.answer() is None, (h.payoff, h.plain)

    # The same poison gate protects A3's offline encoded-token recovery.
    encoded = __import__("base64").b64encode(PROOF.encode())
    h = hunter(Client({"/": replies["/"], "/encoded": response(encoded)}), budget=2)
    h.fetch("/", "plain", False, "root")
    h.fetch("/encoded", "test", True, "payoff")
    assert h._recover_decoded() is None


def test_failed_peer_malformed_carrier_poisons_later_novelty():
    class FailedMalformedPeer:
        @staticmethod
        def solve(target, ctx):
            ctx["client"].request("GET", "/bad-carrier")
            ctx["result_sink"][target["answer_id"]] = {
                "requests": 1, "success": False, "terminal": False,
                "candidates": [], "baseline_proofs": [], "stopped": "malformed",
            }
            return None

    replies = {
        "/bad-carrier": response(b"opaque body", headers={
            "Content-Type": "application/octet-stream", "Content-Encoding": "x-unknown"}),
        "/read": response(success_doc(), headers={"Content-Type": "application/json"}),
    }
    h = hunter(Client(replies), budget=2)
    handled, proof = h._run_peer(FailedMalformedPeer, "malformed-peer", stateful=False)
    assert not handled and proof is None and h.baseline_incomplete, h.peer_meta
    h.fetch("/read", "test", True, "payoff")
    assert h.answer() is None, (h.payoff, h.plain)


def test_peer_cannot_return_a_proof_after_an_incomplete_control():
    class LegacyUnsafePeer:
        @staticmethod
        def solve(target, ctx):
            ctx["client"].request("GET", "/truncated-control")
            # Model an older/custom peer that forgot to propagate the new
            # baseline-integrity flag and would otherwise return immediately.
            ctx["result_sink"][target["answer_id"]] = {
                "requests": 1, "success": True, "terminal": False,
                "candidates": [], "baseline_proofs": [], "stopped": None,
            }
            return PROOF

    reply = dict(response(b"visible prefix", headers={"Content-Type": "text/plain"}),
                 truncated=True)
    h = hunter(Client({"/truncated-control": reply}), budget=1)
    handled, proof = h._run_peer(LegacyUnsafePeer, "legacy-peer", stateful=False)
    assert handled and proof is None and h.baseline_incomplete, (h.peer_meta, h.stopped)
    assert h.answer() is None


def test_valid_empty_carrier_does_not_poison_novelty():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w"):
        pass
    replies = {
        "/empty.zip": response(buf.getvalue(), headers={"Content-Type": "application/zip"}),
        "/read": response(success_doc(), headers={"Content-Type": "application/json"}),
    }
    h = hunter(Client(replies), budget=2)
    h.fetch("/empty.zip", "plain", False, "control")
    assert not h.baseline_incomplete, h.pages["/empty.zip"]
    h.fetch("/read", "test", True, "payoff")
    assert h.answer() == PROOF, (h.pages, h.payoff)


def test_partial_export_has_no_weaker_archive_or_replacement_decoder():
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("evidence.txt", PROOF)
    client = Client({
        "/archive": response(archive.getvalue(), headers={"Content-Type": "application/zip"}),
        "/malformed": response(
            ('{"ok":true,"proof":"' + PROOF).encode(),
            headers={"Content-Type": "application/json"}),
    })
    old = PH._forge_event
    try:
        PH._forge_event = None
        h = hunter(client, budget=2)
        archive_page = h.fetch("/archive", "test", True, "partial-archive")
        malformed_page = h.fetch("/malformed", "test", True, "partial-json")
    finally:
        PH._forge_event = old
    assert archive_page is not None and archive_page.get("text") == ""
    assert archive_page.get("baseline_incomplete") is True
    assert malformed_page is not None and malformed_page.get("text") == ""
    assert PROOF not in h.payoff and h.answer() is None, (h.pages, h.payoff)


def test_optional_offline_recon_is_skipped_near_deadline():
    html = b'<script>const x=location.hash; out.innerHTML=x;</script><input name="csrf_token" value="abcdefgh12345678">'
    reply = response(html, pairs=[
        ("Content-Type", "text/html"),
        ("Set-Cookie", "csrf_token=abcdefgh12345678; Path=/"),
    ])
    client = Client({"/near-deadline": reply})
    h = hunter(client, budget=1)
    h.deadline = time.time() + 0.5
    page = h.fetch("/near-deadline", "plain", False, "deadline")
    assert page is not None and len(client.calls) == 1
    assert not page.get("browser_findings") and not page.get("session_recon"), page
    assert h.offline_analysis["browser"]["items"] == 0
    assert h.offline_analysis["session"]["items"] == 0


def test_timed_coordinator_never_unbounded_joins_offline_work():
    release = threading.Event()

    class SlowOfflineHunter:
        def __init__(self, *_args, stop=None, **_kwargs):
            self.stop = stop
            self.candidates = []

        def run(self):
            release.wait(2.0)
            return PROOF

        def stop_now(self):
            return None

    original = PH._Hunter
    started = time.monotonic()
    try:
        PH._Hunter = SlowOfflineHunter
        answer = PH.solve_targets(
            [{"answer_id": "proof-1", "url": BASE, "question": "Recover proof."}],
            {"deadline": time.time() + 0.05, "max_requests": 1},
        )
    finally:
        elapsed = time.monotonic() - started
        release.set()
        PH._Hunter = original
    assert elapsed < 0.5, elapsed
    assert answer == {"proof-1": None}, answer


def test_conflicting_duplicate_locations_are_not_followed():
    redirect = response(b"", 302, headers={"Location": "/one"}, pairs=[
        ("Location", "/one"), ("Location", "/two")])
    client = Client({"/start": redirect})
    h = hunter(client, budget=3)
    h.fetch("/start", "plain", False, "redirect")
    assert [row["path"] for row in client.calls] == ["/start"], client.calls


def test_linked_openapi_retries_zero_wire_post_ssrf_peer_once():
    # The clue supplies the values but deliberately omits an explicit POST
    # method.  It is zero-wire until the linked OpenAPI schema corroborates the
    # exact route, media type and sole required URL slot.
    clue = {"feature": "server-side URL fetch preview",
            "feature_route": "/api/preview-41", "url_field": "url",
            "content_type": "application/json",
            "internal_url": "http://127.0.0.1:8111/internal/proof"}
    spec = {
        "openapi": "3.1.0",
        "paths": {"/api/preview-41": {"post": {
            "summary": "Fetch a remote URL and return its response",
            "requestBody": {"required": True, "content": {"application/json": {"schema": {
                "type": "object", "required": ["url"],
                "properties": {"url": {"type": "string", "format": "uri"}},
            }}}},
        }}},
    }

    def replies(method, path, data, _headers):
        if method == "POST" and path == "/api/preview-41":
            doc = json.loads(data.decode() if isinstance(data, bytes) else str(data))
            if doc["url"].endswith(".invalid/"):
                return response(b'{"error":"getaddrinfo ENOTFOUND ssrf-control.invalid"}', 502,
                                {"Content-Type": "application/json"})
            return response(success_doc(), 200, {"Content-Type": "application/json"})
        rows = {
            "/": response(b'<link rel="service-desc" href="/spec.json">', 200,
                          {"Content-Type": "text/html"}),
            "/robots.txt": response(b"not found", 404, {"Content-Type": "text/plain"}),
            "/api/clues": response(json.dumps(clue).encode(), 200,
                                   {"Content-Type": "application/json"}),
            "/openapi.json": response(b'{"error":"not_found"}', 404,
                                      {"Content-Type": "application/json"}),
            "/spec.json": response(json.dumps(spec).encode(), 200,
                                   {"Content-Type": "application/json"}),
            "/sitemap.xml": response(b"not found", 404, {"Content-Type": "text/plain"}),
        }
        return rows.get(path, response(b"not found", 404, {"Content-Type": "text/plain"}))

    client = Client(replies)
    h = hunter(client)
    got = h.run()
    posts = [row for row in client.calls if row["method"] == "POST"]
    assert got == PROOF, (got, h.peer_meta, h.endpoint_inventory,
                          {key: value.get("text") for key, value in h.pages.items()
                           if isinstance(value, dict)}, client.calls)
    assert len(posts) == 2 and h.peer_meta["post-body-ssrf"]["requests"] == 2, client.calls
    assert [row["path"] for row in posts] == ["/api/preview-41", "/api/preview-41"]


def test_descriptor_retry_never_repeats_a_peer_that_used_wire():
    class MustNotRun:
        @staticmethod
        def solve(_target, _ctx):
            raise AssertionError("spent peer was repeated")

    h = hunter(Client({}), budget=10)
    h.peer_meta["post-body-ssrf"] = {"requests": 1, "success": False}
    old = PH._ssrf_body
    try:
        PH._ssrf_body = MustNotRun
        handled, proof = h._retry_descriptor_peers()
    finally:
        PH._ssrf_body = old
    assert handled is False and proof is None


def main():
    tests = [value for name, value in sorted(globals().items())
             if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
        print("PASS", test.__name__)
    print(f"PASS all {len(tests)} hunter-expansion tests")


if __name__ == "__main__":
    main()
