"""Loopback fakes for the scan-index providers (B-114): one small HTTP server per provider on
127.0.0.1, dummy keys, and synthetic answers in the shape each provider's API documents.

Nothing here is a recorded real answer: every address is from a documentation range (RFC 5737), every
title and token is made up, and the keys are obvious dummies. The fakes record each request they get
(method, path, query, headers, body), which is how the tests see what a key was sent to.
"""
from __future__ import annotations

import datetime as dt
import json
import threading
import urllib.parse
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ctf import event

ORIGIN = "203.0.113.5"          # the synthetic origin
OTHER = "198.51.100.77"         # a second candidate only FOFA lists
EDGE = "104.16.9.9"             # inside a Cloudflare edge range: a CDN, never an origin
PANEL_UUID = "0f8fad5b-d9cb-469f-a165-70867728950e"
CERT_SHA256 = "ab" * 32
CERT_SHA1 = "cd" * 20
CERT_SERIAL = "6FDBE5407014B76F"
ICON_MMH3 = -1840324437
ICON_MD5 = "0123456789abcdef0123456789abcdef"
ICON_SHA256 = "ef" * 32
TITLE = "Synthetic Capital"

KEYS = {
    "shodan": "dummy-shodan-key-0001",
    "censys": "dummy-censys-pat-0002",
    "fofa": "dummy-fofa-key-0003",
    "netlas": "dummy-netlas-key-0004",
}
ENV = {
    "CTF_SCAN_INDEX_SHODAN_KEY": KEYS["shodan"],
    "CTF_SCAN_INDEX_CENSYS_TOKEN": KEYS["censys"],
    "CTF_SCAN_INDEX_FOFA_KEY": KEYS["fofa"],
    "CTF_SCAN_INDEX_NETLAS_KEY": KEYS["netlas"],
}
PANEL_BODY = (f"<html><head><title>Synthetic Internal Ops</title></head><body><h1>Ops</h1>"
              f"<p>recovery token: <code>{PANEL_UUID}</code></p></body></html>")

# ---- synthetic answers, one per provider and call, in the provider's documented shape ----------------

SHODAN_SEARCH = {"total": 1, "matches": [{
    "ip_str": ORIGIN, "port": 443, "transport": "tcp", "hostnames": ["origin.synthetic.test"],
    "org": "Synthetic Hosting", "timestamp": "2026-11-01T10:00:00.000000",
    "_shodan": {"module": "https"},
    "http": {"title": TITLE, "status": 200, "html": "<html><title>Synthetic Capital</title></html>"},
    "ssl": {"cert": {"fingerprint": {"sha256": CERT_SHA256, "sha1": CERT_SHA1}}}}]}

SHODAN_HOST = {"ip_str": ORIGIN, "ports": [22, 443], "hostnames": ["origin.synthetic.test"],
               "org": "Synthetic Hosting", "last_update": "2026-10-20T08:00:00.000000", "data": [
                   {"ip_str": ORIGIN, "port": 443, "transport": "tcp", "timestamp": "2026-10-20T08:00:00.000000",
                    "org": "Synthetic Hosting", "_shodan": {"module": "https"},
                    "http": {"title": TITLE, "status": 403, "html": "<html>forbidden</html>"}}]}

CENSYS_SEARCH = {"result": {"total_hits": 1, "next_page_token": "", "hits": [{"host_v1": {
    "resource": {"ip": ORIGIN, "dns": {"names": ["origin.synthetic.test"]},
                 "autonomous_system": {"asn": 64500, "name": "SYNTHETIC-AS"},
                 "services": [{"port": 22, "protocol": "SSH", "transport_protocol": "tcp"},
                              {"port": 443, "protocol": "HTTP", "transport_protocol": "tcp"}]},
    "matched_services": [{"port": 443, "protocol": "HTTP", "transport_protocol": "tcp",
                          "scan_time": "2026-11-06T12:00:00Z",
                          "cert": {"fingerprint_sha256": CERT_SHA256},
                          "endpoints": [{"endpoint_type": "HTTP",
                                         "http": {"html_title": TITLE, "status_code": 200}}]}]}}]}}

CENSYS_HOST = {"result": {"resource": {
    "ip": ORIGIN, "autonomous_system": {"asn": 64500, "name": "SYNTHETIC-AS"}, "service_count": 3,
    "services": [
        {"port": 22, "protocol": "SSH", "transport_protocol": "tcp", "scan_time": "2026-11-06T11:00:00Z"},
        {"port": 443, "protocol": "HTTP", "transport_protocol": "tcp", "scan_time": "2026-11-06T12:00:00Z",
         "endpoints": [{"http": {"html_title": TITLE, "status_code": 403, "body": "<html>forbidden</html>"}}]},
        {"port": 8080, "protocol": "HTTP", "transport_protocol": "tcp", "scan_time": "2026-11-07T09:30:00Z",
         "endpoints": [{"http": {"html_title": "Synthetic Internal Ops", "status_code": 200,
                                 "body": PANEL_BODY}}]}]}, "extensions": {}}}

FOFA_SEARCH = {"error": False, "size": 3, "page": 1, "mode": "extended", "query": "", "results": [
    [ORIGIN, "443", "https", f"https://{ORIGIN}", TITLE, "Synthetic Hosting"],
    [OTHER, "8443", "https", "https://alt.synthetic.test:8443", TITLE, "Elsewhere Net"],
    [EDGE, "443", "https", "https://www.synthetic.test", TITLE, "CLOUDFLARENET"]]}

FOFA_HOST = {"error": False, "size": 2, "page": 1, "results": [
    [ORIGIN, "443", "https", f"https://{ORIGIN}", TITLE, "Synthetic Hosting"],
    [ORIGIN, "8080", "http", f"{ORIGIN}:8080", "Synthetic Internal Ops", "Synthetic Hosting"]]}

NETLAS_SEARCH = {"items": [{"highlight": {}, "data": {
    "ip": ORIGIN, "port": 443, "protocol": "https", "prot4": "tcp", "host": "origin.synthetic.test",
    "uri": "https://origin.synthetic.test:443/", "isp": "Synthetic Hosting",
    "last_updated": "2026-11-05T03:00:00.000Z",
    "http": {"title": TITLE, "status_code": 200, "body": "<html><title>Synthetic Capital</title></html>"},
    "certificate": {"fingerprint_sha256": CERT_SHA256}}}], "took": 3}

NETLAS_HOST = {"items": [
    {"data": {"ip": ORIGIN, "port": 443, "protocol": "https", "prot4": "tcp", "host": ORIGIN,
              "last_updated": "2026-11-05T03:00:00.000Z", "http": {"title": TITLE, "status_code": 403}}},
    {"data": {"ip": ORIGIN, "port": 8080, "protocol": "http", "prot4": "tcp", "host": ORIGIN,
              "last_updated": "2026-11-04T01:00:00.000Z",
              "http": {"title": "Synthetic Admin", "status_code": 200, "body": "<html>old panel</html>"}}}]}

INTERNETDB_HOST = {"ip": ORIGIN, "ports": [22, 443, 8080], "hostnames": ["origin.synthetic.test"],
                   "cpes": [], "tags": [], "vulns": []}


@dataclass
class Recorded:
    method: str
    path: str
    query: dict          # name -> list of values, as urllib.parse.parse_qs gives them
    headers: dict        # lower-cased name -> value
    body: bytes
    raw_path: str        # path and query exactly as sent


class FakeIndex:
    """One provider's API on 127.0.0.1. `handler(rec)` returns (status, payload[, headers]); a dict
    payload is sent as JSON, bytes as they are. Every request is appended to `requests`."""

    def __init__(self, handler):
        self.handler = handler
        self.requests: list[Recorded] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _serve(self):
                parts = urllib.parse.urlsplit(self.path)
                length = int(self.headers.get("Content-Length") or 0)
                rec = Recorded(self.command, parts.path, urllib.parse.parse_qs(parts.query),
                               {k.lower(): v for k, v in self.headers.items()},
                               self.rfile.read(length) if length else b"", self.path)
                outer.requests.append(rec)
                answer = outer.handler(rec)
                status, payload = answer[0], answer[1]
                extra = answer[2] if len(answer) > 2 else {}
                data = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
                self.send_response(status)
                for k, v in extra.items():
                    self.send_header(k, v)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = _serve

            def log_message(self, *_a):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.02},
                                       daemon=True)
        self.thread.start()

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.httpd.server_port}"

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


def _by_path(table):
    """A handler that answers by exact path; an unlisted path is a 404 with the provider's wording."""
    def handler(rec: Recorded):
        if rec.path in table:
            return 200, table[rec.path]
        return 404, {"error": "No information available"}
    return handler


DEFAULT_TABLES = {
    "shodan": {"/shodan/host/search": SHODAN_SEARCH, f"/shodan/host/{ORIGIN}": SHODAN_HOST},
    "censys": {"/v3/global/search/query": CENSYS_SEARCH, f"/v3/global/asset/host/{ORIGIN}": CENSYS_HOST},
    "netlas": {},
    "fofa": {},
    "internetdb": {f"/{ORIGIN}": INTERNETDB_HOST},
}


def _fofa(rec: Recorded):
    import base64
    q = base64.b64decode(rec.query.get("qbase64", [""])[0]).decode("utf-8")
    return 200, (FOFA_HOST if q.startswith("ip=") else FOFA_SEARCH)


def _netlas(rec: Recorded):
    if rec.path != "/api/responses/":
        return 404, {"detail": "Not found."}
    q = rec.query.get("q", [""])[0]
    return 200, (NETLAS_HOST if q.startswith("ip:") else NETLAS_SEARCH)


class Indexes:
    """All five fakes, started together. `endpoints` is what ScanIndexClient(endpoints=...) takes."""

    def __init__(self, overrides=None):
        handlers = {name: _by_path(tbl) for name, tbl in DEFAULT_TABLES.items()}
        handlers["fofa"], handlers["netlas"] = _fofa, _netlas
        handlers.update(overrides or {})
        self.fakes = {name: FakeIndex(h) for name, h in handlers.items()}
        self.endpoints = {name: f.base for name, f in self.fakes.items()}

    def __getitem__(self, name: str) -> FakeIndex:
        return self.fakes[name]

    def total_requests(self) -> int:
        return sum(len(f.requests) for f in self.fakes.values())

    def close(self) -> None:
        for f in self.fakes.values():
            f.close()


def profile(public=("127.0.0.1",), slug="scan-index-test"):
    """A test-only event profile whose rules.public_fetch_allow lists the loopback fakes (or nothing)."""
    return event.parse({
        "slug": slug, "name": "scan-index test",
        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 12, 31)},
        "platform": {"kind": "ctfd", "base_url": "https://board.scan-index.test"},
        "flag": {"prefixes": []},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "live_service_scope": [], "public_fetch_allow": list(public)},
    }, src="<scan-index test>")
