#!/usr/bin/env python3
"""URL resolution, duplicate headers, and fail-closed stream regressions."""

from __future__ import annotations

import base64
import concurrent.futures as cf
import gzip
import hashlib
import http.client
import io
import json
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import urllib.response
from email.message import Message
from pathlib import Path
from unittest import mock


REPO = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path[:0] = [str(REPO / "solvers" / "web"), str(REPO / "solvers" / "toolkits")]
import web  # noqa: E402
import proof_hunt  # noqa: E402


class _Response:
    status = 200

    def __init__(self, url):
        self._url = url
        self.headers = Message()
        for name, value in (
            ("Content-Type", "text/plain"),
            ("Set-Cookie", "a=1; Path=/"), ("Set-Cookie", "b=2; Path=/app"),
            ("WWW-Authenticate", 'Basic realm="first"'),
            ("WWW-Authenticate", 'Bearer realm="second"'),
        ):
            self.headers.add_header(name, value)

    def read(self, _amount):
        return b"ok"

    def geturl(self):
        return self._url


class _Opener:
    def __init__(self):
        self.urls = []

    def open(self, request, timeout=None):
        self.urls.append((request.full_url, timeout))
        return _Response(request.full_url)


class _SlowDripResponse(_Response):
    """Never reaches EOF, but yields often enough to defeat per-read timeouts."""

    def __init__(self, url):
        super().__init__(url)
        self.reads = 0
        self.closed = False

    def read1(self, _amount):
        self.reads += 1
        time.sleep(0.01)
        return b"x"

    def close(self):
        self.closed = True


class _SlowDripOpener:
    def __init__(self):
        self.response = None

    def open(self, request, timeout=None):
        del timeout
        self.response = _SlowDripResponse(request.full_url)
        return self.response


class _AmbiguousResponse(_Response):
    def __init__(self, url):
        self._url = url
        self.headers = Message()
        self.headers.add_header("Content-Type", "text/plain")
        self.headers.add_header("Content-Length", str(len(PROOF_BODY)))
        self.headers.add_header("Content-Length", "5")

    def read(self, _amount):
        return PROOF_BODY.encode()


class _AmbiguousOpener:
    def open(self, request, timeout=None):
        return _AmbiguousResponse(request.full_url)


class _UnsupportedTransferResponse(_Response):
    def __init__(self, url):
        self._url = url
        self.headers = Message()
        self.headers.add_header("Content-Type", "text/plain")
        self.headers.add_header("Transfer-Encoding", "gzip, chunked")

    def read(self, _amount):
        return ("20\r\n" + PROOF_BODY[:32] + "\r\n0\r\n\r\n").encode()


class _UnsupportedTransferOpener:
    def open(self, request, timeout=None):
        return _UnsupportedTransferResponse(request.full_url)


class _AmbiguousRedirectTransport(urllib.request.BaseHandler):
    """One synthetic 302; no socket. The opener's real processors still run."""

    handler_order = 0

    def __init__(self):
        self.urls = []

    def http_open(self, request):
        self.urls.append(request.full_url)
        headers = Message()
        headers.add_header("Location", "/must-not-follow")
        headers.add_header("Set-Cookie", "authenticated=yes; Path=/")
        headers.add_header("Content-Length", "9")
        headers.add_header("Content-Length", "2")
        return urllib.response.addinfourl(io.BytesIO(b"redirect!"), headers,
                                          request.full_url, code=302)


class _DefectiveHeaderTransport(urllib.request.BaseHandler):
    """Synthesize syntax http.client drops/normalizes on Python 3.9."""

    handler_order = 0

    def __init__(self, raw_headers):
        self.raw_headers = raw_headers

    def http_open(self, request):
        headers = http.client.parse_headers(io.BytesIO(self.raw_headers))
        return urllib.response.addinfourl(io.BytesIO(PROOF_BODY.encode()), headers,
                                          request.full_url, code=200)


class _DuplicateLocationTransport(urllib.request.BaseHandler):
    handler_order = 0

    def __init__(self):
        self.urls = []

    def http_open(self, request):
        self.urls.append(request.full_url)
        headers = Message()
        headers.add_header("Location", "/first")
        headers.add_header("Location", "/second")
        headers.add_header("Content-Length", "0")
        response = urllib.response.addinfourl(io.BytesIO(b""), headers,
                                              request.full_url, code=302)
        response.msg = "Found"
        return response


class _RedirectRaceOpener:
    """Force two redirect decisions into the old client's shared-state race window."""

    def __init__(self, client):
        self.handler = web._ScopedRedirects(client)
        self.no_follow_entered = threading.Event()
        self.allow_entered = threading.Event()
        self.no_follow_decided = threading.Event()
        self.allow_decided = threading.Event()

    @staticmethod
    def _headers(location):
        headers = Message()
        headers.add_header("Location", location)
        return headers

    @staticmethod
    def _error(request, headers):
        return urllib.error.HTTPError(request.full_url, 302, "Found", headers,
                                      io.BytesIO(b"redirect"))

    def open(self, request, timeout=None):
        del timeout
        if request.full_url.endswith("/no-follow"):
            location = "http://example.test/refused-no-follow"
            headers = self._headers(location)
            self.no_follow_entered.set()
            if not self.allow_entered.wait(2):
                raise AssertionError("allowing request did not enter the race")
            redirected = self.handler.redirect_request(
                request, None, 302, "Found", headers, location)
            self.no_follow_decided.set()
            if not self.allow_decided.wait(2):
                raise AssertionError("other refusal did not finish the race")
            if redirected is not None:
                return _Response(redirected.full_url)
            raise self._error(request, headers)

        if request.full_url.endswith("/allow-off-scope"):
            location = "http://outside.test/refused-off-scope"
            headers = self._headers(location)
            if not self.no_follow_entered.wait(2):
                raise AssertionError("non-following request did not enter the race")
            self.allow_entered.set()
            if not self.no_follow_decided.wait(2):
                raise AssertionError("non-following decision did not finish")
            redirected = self.handler.redirect_request(
                request, None, 302, "Found", headers, location)
            self.allow_decided.set()
            if redirected is not None:
                return _Response(redirected.full_url)
            raise self._error(request, headers)

        raise AssertionError("unexpected request: " + request.full_url)


class _Socket:
    def settimeout(self, _timeout):
        pass

    def recv(self, _amount):
        return b""

    def close(self):
        pass


class _TimeoutSocket(_Socket):
    def recv(self, _amount):
        raise TimeoutError("fixture timeout")


class _GraceSensitiveSocket(_Socket):
    """Only releases its next bytes when the caller preserves a real deadline."""

    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.timeout = None
        self.timeouts = []

    def settimeout(self, timeout):
        self.timeout = timeout
        self.timeouts.append(timeout)

    def recv(self, _amount):
        if self.timeout is not None and self.timeout < 0.5:
            raise TimeoutError("fixture models a continuation delayed past grace")
        return self.chunks.pop(0) if self.chunks else b""


class _Connection:
    def close(self):
        pass


PROOF_BODY = "proof_0123456789abcdef0123456789abcdef"
PROOF_HEADER = "proof_fedcba9876543210fedcba9876543210"


class _PeerRawClient:
    def __init__(self, base="https://example.test/"):
        self.base = base
        self.timeout = 10
        self._jar = object()
        self.calls = []

    def request(self, method, path, **_kwargs):
        self.calls.append((method, path))
        return {"status": 403, "body": ("control " + PROOF_BODY).encode(),
                "response_headers": {"X-Decoy": PROOF_HEADER},
                "response_header_pairs": [("X-Decoy", PROOF_HEADER),
                                          ("Set-Cookie", "a=1"),
                                          ("Set-Cookie", "b=2")]}


class _FailedReadPeer:
    @staticmethod
    def solve(target, ctx):
        ctx["client"].timeout = 1.25
        ctx["client"].request("GET", "/one")
        made = ctx["client_factory"](target["url"], 0.5)
        made.request("GET", "/two")
        ctx["result_sink"][target["answer_id"]] = {
            "requests": 2, "success": False, "terminal": True,
            "candidates": [], "baseline_proofs": [], "stopped": "protocol_error",
        }
        return None


class _SummaryPeer:
    summary = {}

    @classmethod
    def solve(cls, target, ctx):
        ctx["result_sink"][target["answer_id"]] = dict(cls.summary)
        return None


class _SendThenRaisePeer:
    @staticmethod
    def solve(_target, ctx):
        ctx["client"].request("POST", "/one", data=b"mutate")
        raise RuntimeError("lost response handling")


class _InspectPreloadedPeer:
    document = None
    baselines = None

    @classmethod
    def solve(cls, target, ctx):
        raw = ctx["preloaded"]["/api/clues"]
        cls.document = proof_hunt._double_spend._json(
            proof_hunt._double_spend._response(raw))
        cls.baselines = list(ctx.get("baseline_texts") or [])
        ctx["result_sink"][target["answer_id"]] = {
            "requests": 0, "success": False, "terminal": False,
            "candidates": [], "stopped": None,
        }
        return None


class URLAndHeaderTests(unittest.TestCase):
    def test_application_prefix_root_absolute_query_and_empty_resolution(self):
        client = web.WebClient("https://example.test/app?cap=one")
        self.assertEqual(client.origin, "https://example.test")
        self.assertEqual(client.application_base, "https://example.test/app?cap=one")
        self.assertEqual(client.base, client.application_base)
        cases = {
            "": "https://example.test/app?cap=one",
            "/x?y=1": "https://example.test/x?y=1",
            "x?y=1": "https://example.test/app/x?y=1",
            "nested/x": "https://example.test/app/nested/x",
            "?next=two": "https://example.test/app?next=two",
            "?": "https://example.test/app",
            "https://example.test/absolute": "https://example.test/absolute",
            "https://example.test:443/explicit": "https://example.test:443/explicit",
        }
        for reference, expected in cases.items():
            with self.subTest(reference=reference):
                self.assertEqual(client._resolve_url(reference)[0], expected)

        root = web.WebClient("http://example.test")
        self.assertEqual(root.base, "http://example.test/")
        self.assertEqual(root._resolve_url("")[0], "http://example.test/")
        self.assertEqual(root._resolve_url("x")[0], "http://example.test/x")
        self.assertEqual(root._resolve_url("/x")[0], "http://example.test/x")

    def test_normal_and_stream_transports_share_the_resolver(self):
        client = web.WebClient("https://example.test/app?cap=one")
        normal = client._resolve_url("events?stream=7")[0]
        stream = client._stream_target("events?stream=7", websocket=False)
        websocket = client._stream_target("events?stream=7", websocket=True)
        self.assertEqual(normal, "https://example.test/app/events?stream=7")
        self.assertEqual(stream[0], normal)
        self.assertEqual(stream[2], "/app/events?stream=7")
        self.assertEqual(websocket[0], normal)
        self.assertEqual(websocket[1], "wss://example.test/app/events?stream=7")
        self.assertEqual(client._stream_target("/events")[0], "https://example.test/events")
        self.assertEqual(client._stream_target("wss://example.test/socket", websocket=True)[:3],
                         ("https://example.test/socket", "wss://example.test/socket", "/socket"))
        with self.assertRaises(web.OutOfScope):
            client._stream_target("wss://example.test/socket", websocket=False)

    def test_windows_traversal_is_query_data_never_path_or_authority(self):
        client = web.WebClient("https://example.test/app")
        wire, _alias = client._resolve_url(r"/read?file=..\..\Windows\win.ini")
        self.assertEqual(
            wire,
            "https://example.test/read?file=..%5C..%5CWindows%5Cwin.ini",
        )
        for unsafe in (r"/read\..\secret?x=1", r"https://example.test\@evil.test/?x=1"):
            with self.subTest(unsafe=unsafe), self.assertRaises(web.OutOfScope):
                client._resolve_url(unsafe)

    def test_invalid_bases_and_references_fail_before_transport(self):
        invalid_bases = (
            "ftp://example.test/", "//example.test/", "http:///missing-host",
            "http://user@example.test/", "http://:pass@example.test/",
            "http://example.test/#fragment", "http://example.test:/",
            "http://example.test:bad/", "http://[::1/", "http://[::1]junk/",
            "http://example.test\\@evil.test/", " http://example.test/",
            "http://example.test/\nnext",
        )
        for value in invalid_bases:
            with self.subTest(base=value), self.assertRaises(web.OutOfScope):
                web.WebClient(value)

        client = web.WebClient("https://example.test/app")
        invalid_references = (
            "https://evil.test/x", "http://example.test/x", "https://example.test:444/x",
            "https://user@example.test/x", "//example.test/x", "http:x",
            "ftp://example.test/x", "x#fragment", "/x\\@evil.test", " /x",
            "wss://example.test/x",
        )
        for value in invalid_references:
            with self.subTest(reference=value), self.assertRaises(web.OutOfScope):
                client._resolve_url(value)

    def test_urllib_response_retains_ordered_duplicate_pairs_and_serializes(self):
        client = web.WebClient("https://example.test/app")
        opener = _Opener()
        client._opener = opener
        got = client.get("child")
        self.assertEqual(opener.urls[0][0], "https://example.test/app/child")
        self.assertEqual(got["response_header_pairs"], [
            ("Content-Type", "text/plain"),
            ("Set-Cookie", "a=1; Path=/"), ("Set-Cookie", "b=2; Path=/app"),
            ("WWW-Authenticate", 'Basic realm="first"'),
            ("WWW-Authenticate", 'Bearer realm="second"'),
        ])
        with tempfile.TemporaryDirectory() as folder:
            path = client.save_log(Path(folder) / "requests.json")
            saved = json.loads(Path(path).read_text())
        self.assertEqual(saved[0]["response_header_pairs"][2], ["Set-Cookie", "<redacted>"])

    def test_normal_response_body_uses_one_absolute_deadline(self):
        client = web.WebClient("https://example.test/", timeout=0.045)
        opener = _SlowDripOpener()
        client._opener = opener
        started = time.monotonic()
        with self.assertRaises(web.VPNRequired):
            client.get("/slow-drip")
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 0.35, "one-byte progress must not reset the request budget")
        self.assertIsNotNone(opener.response)
        self.assertTrue(opener.response.closed)
        self.assertLess(opener.response.reads, 20)
        self.assertEqual(client.log[-1]["status"], None)

    def test_normal_transport_rejects_ambiguous_framing_before_exposing_body(self):
        client = web.WebClient("https://example.test/")
        client._opener = _AmbiguousOpener()
        with self.assertRaisesRegex(ValueError, "ambiguous HTTP response framing"):
            client.get("/proof")
        self.assertEqual(len(client.log), 1)
        self.assertEqual(client.log[0]["body"], b"")
        self.assertEqual(client.log[0]["framing_error"], "conflicting Content-Length")

        client = web.WebClient("https://example.test/")
        client._opener = _UnsupportedTransferOpener()
        with self.assertRaisesRegex(ValueError, "ambiguous HTTP response framing"):
            client.get("/unsupported-transfer")
        self.assertEqual(client.log[0]["body"], b"")
        self.assertEqual(client.log[0]["framing_error"],
                         "unsupported or ambiguous Transfer-Encoding")

    def test_framing_guard_precedes_cookie_commit_and_redirect_following(self):
        client = web.WebClient("http://example.test/")
        transport = _AmbiguousRedirectTransport()
        client._opener = urllib.request.build_opener(
            transport, web._FramingGuard(),
            urllib.request.HTTPCookieProcessor(client._jar),
            web._ScopedRedirects(client),
        )
        with self.assertRaisesRegex(ValueError, "ambiguous HTTP response framing"):
            client.get("/start")
        self.assertEqual(transport.urls, ["http://example.test/start"])
        self.assertEqual(list(client._jar), [], "ambiguous Set-Cookie must never enter the jar")
        self.assertEqual(client.log[-1]["body"], b"")
        self.assertEqual(client.log[-1]["status"], 302)

    def test_header_parser_defects_fail_before_body_evidence(self):
        malformed = (
            b"Content-Length : 5\r\n\r\n",
            b" continuation\r\nContent-Length: 5\r\n\r\n",
        )
        for raw in malformed:
            with self.subTest(raw=raw):
                client = web.WebClient("http://example.test/")
                client._opener = urllib.request.build_opener(
                    _DefectiveHeaderTransport(raw), web._FramingGuard(),
                    urllib.request.HTTPCookieProcessor(client._jar),
                    web._ScopedRedirects(client),
                )
                with self.assertRaisesRegex(ValueError, "ambiguous HTTP response framing"):
                    client.get("/defective")
                self.assertEqual(client.log[-1]["body"], b"")
                self.assertIn("malformed response headers", client.log[-1]["framing_error"])

    def test_duplicate_location_is_never_followed(self):
        client = web.WebClient("http://example.test/")
        transport = _DuplicateLocationTransport()
        client._opener = urllib.request.build_opener(
            transport, web._FramingGuard(),
            urllib.request.HTTPCookieProcessor(client._jar),
            web._ScopedRedirects(client),
        )
        result = client.get("/start")
        self.assertEqual(result["status"], 302)
        self.assertEqual(transport.urls, ["http://example.test/start"])
        self.assertEqual(result.get("redirect_not_followed"), "http://example.test/first")

    def test_concurrent_redirect_policy_and_refusal_attribution_are_request_scoped(self):
        client = web.WebClient("http://example.test/")
        opener = _RedirectRaceOpener(client)
        client._opener = opener

        with cf.ThreadPoolExecutor(max_workers=2) as pool:
            no_follow = pool.submit(client.get, "/no-follow", allow_redirects=False)
            self.assertTrue(opener.no_follow_entered.wait(2))
            allow = pool.submit(client.get, "/allow-off-scope", allow_redirects=True)
            no_follow_result = no_follow.result(timeout=3)
            allow_result = allow.result(timeout=3)

        self.assertEqual(no_follow_result["status"], 302,
                         "another request must not enable redirect following")
        self.assertEqual(
            no_follow_result.get("redirect_not_followed"),
            "http://example.test/refused-no-follow",
        )
        self.assertEqual(allow_result["status"], 302)
        self.assertEqual(
            allow_result.get("redirect_not_followed"),
            "http://outside.test/refused-off-scope",
        )

    def test_private_target_reachability_probe_is_single_flight(self):
        client = web.WebClient("http://127.0.0.1:8123/")
        calls = []

        def connect(address, timeout=None):
            calls.append((address, timeout))
            time.sleep(0.01)
            return _Connection()

        with mock.patch("socket.create_connection", side_effect=connect):
            with cf.ThreadPoolExecutor(max_workers=12) as pool:
                list(pool.map(lambda _index: client._check_private(), range(24)))
        self.assertEqual(calls, [(('127.0.0.1', 8123), 3.0)])

    def test_raw_head_preserves_duplicates_and_rejects_ambiguous_framing(self):
        raw = (b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n"
               b"WWW-Authenticate: Basic realm=a\r\nWWW-Authenticate: Bearer realm=b\r\n"
               b"Content-Length: 4\r\nContent-Length: 4\r\n")
        status, reason, headers, pairs = web._parse_response_head_details(raw)
        self.assertEqual((status, reason, headers["Content-Length"]), (200, "OK", "4"))
        self.assertEqual([v for k, v in pairs if k.lower() == "set-cookie"], ["a=1", "b=2"])
        self.assertEqual(len([1 for k, _ in pairs if k.lower() == "www-authenticate"]), 2)

        bad = (
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Length: 5\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, chunked\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: foo\r\nTransfer-Encoding: chunked\r\n",
            b"HTTP/1.1 101 Switching Protocols\r\nContent-Length: 1\r\n",
            b"HTTP/1.1 101 Switching Protocols\r\nContent-Length: 0\r\n",
            b"HTTP/1.1 100 Continue\r\nContent-Length: 1\r\n",
            b"HTTP/1.1 103 Early Hints\r\nTransfer-Encoding: chunked\r\n",
            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n",
            b"HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n",
        )
        for head in bad:
            with self.subTest(head=head), self.assertRaises(ValueError):
                web._parse_response_head_details(head)

    def test_legacy_socket_timeout_is_a_bounded_stream_timeout(self):
        class LegacySocketTimeout(OSError):
            pass

        class SendTimeoutSocket(_Socket):
            def sendall(self, _request):
                raise LegacySocketTimeout("legacy write timeout")

        class HeadTimeoutSocket(_Socket):
            def sendall(self, _request):
                pass

            def recv(self, _amount):
                raise LegacySocketTimeout("legacy header timeout")

        headers = {"Host": "example.test", "Connection": "close"}
        with mock.patch.object(web.socket, "timeout", LegacySocketTimeout):
            with self.assertRaisesRegex(web._StreamTimeout, "write timed out"):
                web.WebClient._stream_send_and_head(
                    SendTimeoutSocket(), "/events", headers, time.time() + 1)
            with self.assertRaisesRegex(web._StreamTimeout, "headers timed out"):
                web.WebClient._stream_send_and_head(
                    HeadTimeoutSocket(), "/events", headers, time.time() + 1)

    @staticmethod
    def _upgrade_head(request_headers, rest, extra=()):
        accept = base64.b64encode(hashlib.sha1(
            (request_headers["Sec-WebSocket-Key"] + web._WS_GUID).encode("ascii")
        ).digest()).decode("ascii")
        lines = ["HTTP/1.1 101 Switching Protocols", "Upgrade: websocket", "Connection: Upgrade",
                 f"Sec-WebSocket-Accept: {accept}"]
        lines.extend(f"{name}: {value}" for name, value in extra)
        parsed = web._parse_response_head_details("\r\n".join(lines).encode("ascii"))
        return (*parsed, rest)

    def test_stream_results_carry_duplicate_header_pairs(self):
        client = web.WebClient("https://example.test/app")
        client._stream_socket = lambda *_args: _Socket()
        event = b"data: hello\n\n"
        raw = (b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
               b"Set-Cookie: a=1\r\nSet-Cookie: b=2\r\nContent-Length: "
               + str(len(event)).encode() + b"\r\n")
        parsed = web._parse_response_head_details(raw)
        client._stream_send_and_head = lambda *_args: (*parsed, event)
        got = client.sse_first_event("events", deadline=time.time() + 1)
        self.assertTrue(got["event_received"])
        self.assertEqual([v for k, v in got["response_header_pairs"] if k.lower() == "set-cookie"],
                         ["a=1", "b=2"])

        client._stream_send_and_head = lambda _sock, _target, headers, _end: self._upgrade_head(
            headers, b"\x81\x02ok", (("Set-Cookie", "ws=1"), ("Set-Cookie", "ws=2")))
        got = client.websocket_receive("socket", deadline=time.time() + 1, max_frames=2)
        self.assertTrue(got["upgraded"])
        self.assertEqual(got["body"], b"ok")
        self.assertEqual([v for k, v in got["response_header_pairs"] if k.lower() == "set-cookie"],
                         ["ws=1", "ws=2"])

    def test_chunked_stream_reader_rejects_extensions_ows_and_trailers(self):
        class Source:
            def __init__(self, wire):
                self.wire = bytearray(wire)

            def line(self, limit, _end):
                at = self.wire.find(b"\r\n")
                if at < 0 or at > limit:
                    raise ValueError("bad test stream line")
                out = bytes(self.wire[:at])
                del self.wire[:at + 2]
                return out

            def exact(self, amount, _end):
                if len(self.wire) < amount:
                    raise ValueError("short test stream")
                out = bytes(self.wire[:amount])
                del self.wire[:amount]
                return out

        def consume(wire):
            reader = web._HTTPBodyReader(Source(wire), {"Transfer-Encoding": "chunked"})
            while not reader.done:
                reader.read(64, time.time() + 1)

        malformed = (
            b"1; @@@\r\nx\r\n0\r\n\r\n",
            b" 1 \r\nx\r\n0\r\n\r\n",
            b"1\r\nx\r\n0\r\nX-Proof: proof_0123456789abcdef0123456789abcdef\r\n\r\n",
        )
        for wire in malformed:
            with self.subTest(wire=wire), self.assertRaises(ValueError):
                consume(wire)
        consume(b"1\r\nx\r\n0\r\n\r\n")

    def test_websocket_errors_clear_all_application_evidence(self):
        good = b'{"effect":"event_stream_read","evidence":"proof_0123456789abcdef0123456789abcdef"}'

        def frame(opcode, payload, first=0x80):
            return bytes((first | opcode, len(payload))) + payload

        bad_streams = {
            "binary-json": frame(2, good),
            "invalid-utf8": frame(1, b"\xff"),
            "rsv": frame(1, b"ok", first=0xC0),
            "masked": b"\x81\x82\x00\x00\x00\x00ok",
            "non-minimal-16": b"\x81\x7e\x00\x02ok",
            "non-minimal-64": b"\x81\x7f" + (2).to_bytes(8, "big") + b"ok",
            "incomplete-fragment": frame(1, good, first=0),
            "valid-then-invalid": frame(1, good) + b"\x81\x81\x00\x00\x00\x00x",
        }
        for label, wire in bad_streams.items():
            with self.subTest(label=label):
                client = web.WebClient("https://example.test/app")
                client._stream_socket = lambda *_args: _Socket()
                client._stream_send_and_head = \
                    lambda _sock, _target, headers, _end, wire=wire: self._upgrade_head(headers, wire)
                got = client.websocket_receive("socket", deadline=time.time() + 1, max_frames=3)
                self.assertEqual(got["body"], b"")
                self.assertEqual(got["websocket_messages"], [])
                self.assertTrue(got.get("protocol_error"))
                self.assertFalse(any("payload_b64" in item or "text" in item
                                     for item in got["websocket_frames"]))

        client = web.WebClient("https://example.test/app")
        client._stream_socket = lambda *_args: _Socket()
        client._stream_send_and_head = \
            lambda _sock, _target, headers, _end: self._upgrade_head(headers, b"\x81\x7e\x10\x00")
        limited = client.websocket_receive("socket", deadline=time.time() + 1, max_bytes=64)
        self.assertEqual(limited["body"], b"")
        self.assertTrue(limited["truncated"])
        self.assertTrue(limited["limit_error"])
        self.assertTrue(limited["incomplete"])

        client = web.WebClient("https://example.test/app")
        client._stream_socket = lambda *_args: _TimeoutSocket()
        client._stream_send_and_head = \
            lambda _sock, _target, headers, _end: self._upgrade_head(headers, b"\x81")
        partial = client.websocket_receive("socket", deadline=time.time() + 1)
        self.assertEqual(partial["body"], b"")
        self.assertTrue(partial["timed_out"])
        self.assertTrue(partial["incomplete"])

        client = web.WebClient("https://example.test/app")
        client._stream_socket = lambda *_args: _TimeoutSocket()
        client._stream_send_and_head = lambda _sock, _target, headers, _end: self._upgrade_head(
            headers, frame(1, good) + b"\x81")
        after_message = client.websocket_receive("socket", deadline=time.time() + 1)
        self.assertEqual(after_message["body"], b"",
                         "a complete message must not survive a partial following frame")
        self.assertEqual(after_message["websocket_messages"], [])
        self.assertTrue(after_message["timed_out"])
        self.assertTrue(after_message["incomplete"])

    def test_first_websocket_message_keeps_deadline_across_control_and_fragments(self):
        cases = {
            "fragment-first": (b"\x01\x02he", b"\x80\x03llo", b"hello"),
            "control-first": (b"\x89\x00", b"\x81\x05hello", b"hello"),
        }
        for label, (first, delayed, expected) in cases.items():
            with self.subTest(label=label):
                sock = _GraceSensitiveSocket([delayed])
                client = web.WebClient("https://example.test/app")
                client._stream_socket = lambda *_args, sock=sock: sock
                client._stream_send_and_head = (
                    lambda _sock, _target, headers, _end, first=first:
                    self._upgrade_head(headers, first)
                )
                got = client.websocket_receive(
                    "socket", deadline=time.time() + 1.5, max_frames=4)
                self.assertEqual(got["body"], expected)
                self.assertEqual(got["websocket_messages"], [expected.decode()])
                self.assertFalse(got.get("protocol_error"), got)
                self.assertTrue(sock.timeouts and sock.timeouts[0] >= 0.5,
                                sock.timeouts)

    def test_frame_cap_is_truncation_not_partial_success(self):
        client = web.WebClient("https://example.test/app")
        client._stream_socket = lambda *_args: _Socket()
        client._stream_send_and_head = lambda _sock, _target, headers, _end: self._upgrade_head(
            headers, b"\x81\x02ok")
        got = client.websocket_receive("socket", deadline=time.time() + 1, max_frames=1)
        self.assertEqual(got["body"], b"")
        self.assertEqual(got["websocket_messages"], [])
        self.assertTrue(got["truncated"])
        self.assertTrue(got["limit_error"])


class PeerClientGateTests(unittest.TestCase):
    def setUp(self):
        # proof_<32 hex> is the Huntress event's proof token (events/huntress/event.toml [proof]).
        patcher = mock.patch.dict("os.environ", {"CTF_EVENT": "huntress"})
        patcher.start()
        self.addCleanup(patcher.stop)

    def hunter(self):
        hunter = proof_hunt._Hunter("https://example.test/", deadline=time.time() + 5,
                                    max_requests=10)
        hunter.forge_target = {"url": "https://example.test/", "answer_id": "answer"}
        hunter.forge_ctx = {}
        return hunter

    def test_failed_read_peer_falls_through_and_captured_tokens_become_plain(self):
        hunter = self.hunter()
        primary = _PeerRawClient()
        hunter.client = primary
        made = []

        def factory(url, timeout=10, get_only=False):   # proof_hunt builds get_only clients (B-007)
            client = _PeerRawClient(url)
            client.timeout = timeout
            made.append(client)
            return client

        with mock.patch.object(proof_hunt._web, "WebClient", side_effect=factory):
            handled, proof = hunter._run_peer(_FailedReadPeer, "failed-read", stateful=False)
        self.assertFalse(handled, "read-only terminal metadata alone must fall through")
        self.assertIsNone(proof)
        self.assertEqual(primary.timeout, 1.25, "timeout assignment must reach the wrapped client")
        self.assertEqual(primary.calls, [("GET", "/one")])
        self.assertEqual(made[0].calls, [("GET", "/two")])
        self.assertEqual(hunter._active_sends, 0)
        self.assertIn(PROOF_BODY, hunter.plain)
        self.assertIn(PROOF_HEADER, hunter.plain)
        self.assertEqual(hunter.requests, 2)

    def test_guard_exposes_cookie_jar_and_refuses_after_drain_gate_closes(self):
        hunter = self.hunter()
        raw = _PeerRawClient()
        captured = []
        guarded = proof_hunt._PeerClient(hunter, raw, captured)
        self.assertIs(guarded._jar, raw._jar)
        guarded.timeout = 2
        self.assertEqual(raw.timeout, 2)
        hunter.stop_now()
        with self.assertRaises(RuntimeError):
            guarded.request("GET", "/must-not-send")
        self.assertEqual(raw.calls, [])
        self.assertEqual(captured, [])
        self.assertEqual(hunter._active_sends, 0)

    def test_guard_rechecks_stop_after_blocked_accounting(self):
        hunter = self.hunter()
        raw = _PeerRawClient()
        guarded = proof_hunt._PeerClient(hunter, raw, [])
        errors = []
        hunter.lock.acquire()
        sender = threading.Thread(
            target=lambda: self._capture_error(
                errors, lambda: guarded.request("POST", "/must-not-send")),
            daemon=True,
        )
        sender.start()
        limit = time.time() + 2
        while hunter._active_sends != 1 and time.time() < limit:
            time.sleep(0.001)
        stopper = threading.Thread(target=hunter.stop_now, daemon=True)
        stopper.start()
        while not hunter._send_closed and time.time() < limit:
            time.sleep(0.001)
        hunter.lock.release()
        sender.join(2)
        stopper.join(2)
        self.assertEqual(raw.calls, [])
        self.assertTrue(errors and isinstance(errors[0], RuntimeError), errors)
        self.assertFalse(sender.is_alive())
        self.assertFalse(stopper.is_alive())
        self.assertEqual(hunter._active_sends, 0)

    def test_shared_mastery_prompt_cannot_authorize_double_spend_on_a_sibling(self):
        hunter = self.hunter()
        hunter.prompt_text = "Target 1 requires a double-spend race against one credit."
        hunter.post_prompt = "Recover the ordinary read-only proof from Target 2."
        hunter.forge_target = {"question": hunter.post_prompt}
        hunter._clues_doc = lambda: {
            "feature_route": "/feature", "secondary_route": "/audit",
            "framework": "generic",
        }
        hunter._page = lambda _path: None
        self.assertFalse(hunter._double_spend_indicated())

        hunter.forge_target = {
            "question": "Race two purchases so the one credit is spent twice."
        }
        self.assertTrue(hunter._double_spend_indicated())

    def test_peer_preload_preserves_original_compressed_entity_and_page_baseline(self):
        hunter = self.hunter()
        hunter.client = _PeerRawClient()
        hunter.forge_target = {
            "answer_id": "answer", "url": "https://example.test/",
            "question": "Inspect the clue document.",
        }
        document = {"framework": "RaceApp", "feature_route": "/execute",
                    "secondary_route": "/audit"}
        raw = gzip.compress(json.dumps(document).encode())
        hunter.pages["/api/clues"] = {
            "path": "/api/clues", "status": 200, "text": json.dumps(document),
            "evidence_text": "control future-proof-format", "payoff": False,
            "headers": {"Content-Type": "application/json", "Content-Encoding": "gzip"},
            "_peer_response": {
                "status": 200, "body": raw,
                "response_headers": {"Content-Type": "application/json",
                                     "Content-Encoding": "gzip"},
                "response_header_pairs": [("Content-Type", "application/json"),
                                          ("Content-Encoding", "gzip")],
            },
        }
        handled, value = hunter._run_peer(_InspectPreloadedPeer, "inspect", stateful=False)
        self.assertFalse(handled)
        self.assertIsNone(value)
        self.assertEqual(_InspectPreloadedPeer.document, document)
        self.assertIn("control future-proof-format", _InspectPreloadedPeer.baselines)

        adopted = self.hunter()
        adopted.client = _PeerRawClient()
        adopted.forge_target = dict(hunter.forge_target)
        adopted._adopt_inventory_pages({"/api/clues": {
            "status": 200, "body": raw,
            "response_headers": {"Content-Type": "application/json",
                                 "Content-Encoding": "gzip"},
            "response_header_pairs": [("Content-Type", "application/json"),
                                      ("Content-Encoding", "gzip")],
        }})
        self.assertEqual(adopted.pages["/api/clues"]["_peer_response"]["body"], raw)
        handled, value = adopted._run_peer(_InspectPreloadedPeer, "inspect-adopted", stateful=False)
        self.assertFalse(handled)
        self.assertIsNone(value)
        self.assertEqual(_InspectPreloadedPeer.document, document)

    @staticmethod
    def _capture_error(sink, call):
        try:
            call()
        except Exception as exc:
            sink.append(exc)

    def test_candidate_and_exhausted_deadline_remain_terminal(self):
        hunter = self.hunter()
        hunter.client = _PeerRawClient()
        _SummaryPeer.summary = {"requests": 0, "success": False, "terminal": False,
                                "candidates": ["future-proof"], "stopped": None}
        handled, _ = hunter._run_peer(_SummaryPeer, "candidate", stateful=False)
        self.assertTrue(handled)

        hunter = self.hunter()
        hunter.client = _PeerRawClient()
        _SummaryPeer.summary = {"requests": 0, "success": False, "terminal": False,
                                "candidates": [], "stopped": "deadline"}
        handled, _ = hunter._run_peer(_SummaryPeer, "deadline", stateful=False)
        self.assertTrue(handled)
        self.assertEqual(hunter.stopped, "deadline")

    def test_send_then_raise_is_charged_adopted_and_stateful_terminal(self):
        hunter = self.hunter()
        raw = _PeerRawClient()
        hunter.client = raw
        handled, proof = hunter._run_peer(_SendThenRaisePeer, "raising-stateful", stateful=True)
        self.assertTrue(handled)
        self.assertIsNone(proof)
        self.assertEqual(hunter.requests, 1)
        self.assertEqual(raw.calls, [("POST", "/one")])
        self.assertEqual(hunter.peer_meta["raising-stateful"]["requests"], 1)
        self.assertTrue(hunter.peer_meta["raising-stateful"]["terminal"])
        self.assertIn(PROOF_BODY, hunter.plain)
        self.assertIn(PROOF_HEADER, hunter.plain)

    def test_read_only_exception_falls_through_but_cannot_erase_wire_accounting(self):
        hunter = self.hunter()
        hunter.client = _PeerRawClient()
        handled, proof = hunter._run_peer(_SendThenRaisePeer, "raising-read", stateful=False)
        self.assertFalse(handled)
        self.assertIsNone(proof)
        self.assertEqual(hunter.requests, 1)
        self.assertEqual(hunter.peer_meta["raising-read"]["requests"], 1)
        self.assertFalse(hunter.peer_meta["raising-read"]["terminal"])
        self.assertIn(PROOF_BODY, hunter.plain)


if __name__ == "__main__":
    unittest.main(verbosity=2)
