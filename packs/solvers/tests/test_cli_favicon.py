"""B-089: the `ctf favicon` fetch command (ctf/cli/favicon.py).

A loopback HTTP server on 127.0.0.1 (in the suite scope, tests/conftest.py) stands in for a service.
The tests prove the fetch parses the declared `<link rel=icon>`, falls back to /favicon.ico, hashes a
local file offline, runs the scope guard before any request, re-checks redirects, and refuses .onion
hosts to B-091. No test contacts a real service, so none is marked `live`.
"""
from __future__ import annotations

import argparse
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ctf import favicon, scope
from ctf.cli import favicon as cli

ICON = b"\x00\x00\x01\x00" + b"\x7f" * 400          # ICO magic + body
OTHER_ICON = b"\x00\x00\x01\x00" + b"\x10" * 128


class Server:
    def __init__(self, routes):
        self.routes = routes
        self.hits = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                outer.hits.append(self.path)
                route = outer.routes.get(self.path)
                if route is None:
                    self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers()
                    return
                status, ctype, data, extra = route
                self.send_response(status)
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *_a):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    @property
    def base(self):
        return f"http://127.0.0.1:{self.httpd.server_port}"

    def __exit__(self, *_exc):
        self.httpd.shutdown()
        self.thread.join(timeout=5)


def test_fetch_parses_declared_icon_link():
    page = (b'<html><head><link rel="shortcut icon" href="/assets/brand.ico"></head></html>')
    with Server({
        "/": (200, "text/html", page, None),
        "/assets/brand.ico": (200, "image/x-icon", ICON, None),
    }) as s:
        body, icon_url = cli.fetch_favicon(s.base + "/")
    assert body == ICON
    assert icon_url.endswith("/assets/brand.ico")
    assert favicon.fingerprint(body).md5 == favicon.fingerprint(ICON).md5


def test_fetch_defaults_to_favicon_ico():
    with Server({
        "/": (200, "text/html", b"<html><head></head></html>", None),
        "/favicon.ico": (200, "image/x-icon", ICON, None),
    }) as s:
        body, icon_url = cli.fetch_favicon(s.base + "/")
    assert body == ICON
    assert icon_url.endswith("/favicon.ico")


def test_fetch_icon_url_directly_without_fetching_a_page():
    with Server({"/favicon.ico": (200, "image/x-icon", ICON, None)}) as s:
        body, icon_url = cli.fetch_favicon(s.base + "/favicon.ico")
        assert body == ICON
        # Only the icon was fetched; no page GET happened.
        assert s.hits == ["/favicon.ico"]


def test_fetch_follows_redirect_and_rechecks_scope():
    with Server({
        "/favicon.ico": (302, "text/plain", b"", {"Location": "/real.ico"}),
        "/real.ico": (200, "image/x-icon", OTHER_ICON, None),
    }) as s:
        body, icon_url = cli.fetch_favicon(s.base + "/favicon.ico")
    assert body == OTHER_ICON
    assert icon_url.endswith("/real.ico")


def test_redirect_to_off_scope_host_is_refused_before_the_off_scope_get():
    # A 302 whose Location walks off-scope must be refused by the redirect scope re-check
    # (_ScopedRedirect.redirect_request), before the off-scope target is ever fetched. The in-scope
    # loopback server is hit once for /favicon.ico; the off-scope host is never contacted because
    # scope.check_url raises OutOfScope inside redirect_request.
    off = "http://not-in-scope.example.org/x.ico"
    with Server({
        "/favicon.ico": (302, "text/plain", b"", {"Location": off}),
        # /real.ico is NOT routed: were the redirect allowed on-host it would 404, but it must not
        # even get that far -- the off-scope Location is rejected first.
    }) as s:
        with pytest.raises(scope.OutOfScope):
            cli.fetch_favicon(s.base + "/favicon.ico")
        # Only the first hop was contacted; the redirect was refused before any further GET.
        assert s.hits == ["/favicon.ico"]


def test_body_over_cap_is_rejected_as_not_a_favicon():
    # A response body larger than MAX_ICON_BYTES is not a favicon: _get caps the read and raises.
    big = b"\x00\x00\x01\x00" + b"\x00" * cli.MAX_ICON_BYTES
    assert len(big) > cli.MAX_ICON_BYTES
    with Server({"/favicon.ico": (200, "image/x-icon", big, None)}) as s:
        with pytest.raises(cli.FetchError, match=r"not a favicon|over "):
            cli.fetch_favicon(s.base + "/favicon.ico")


def test_onion_is_refused_to_b091():
    with pytest.raises(cli.FetchError, match=r"onion|B-091"):
        cli.fetch_favicon("http://schpqwdfzcmdcbim7w24jj5ph5h6fqvcbj5zhkhof3z3v75ydljkzsad.onion/favicon.ico")


def test_out_of_scope_host_is_refused_before_any_request():
    with pytest.raises(scope.OutOfScope):
        cli.fetch_favicon("http://not-in-scope.example.org/favicon.ico")


def test_run_hashes_a_local_file_offline(tmp_path, capsys):
    f = tmp_path / "favicon.ico"
    f.write_bytes(ICON)
    args = argparse.Namespace(target=str(f), timeout=5.0, json=False)
    rc = cli.run(args)
    out = capsys.readouterr().out
    assert rc == 0
    assert str(favicon.fingerprint(ICON).mmh3) in out
    assert favicon.fingerprint(ICON).md5 in out


def test_run_onion_exit_code(capsys):
    args = argparse.Namespace(
        target="http://schpqwdfzcmdcbim7w24jj5ph5h6fqvcbj5zhkhof3z3v75ydljkzsad.onion/", timeout=5.0, json=False)
    rc = cli.run(args)
    assert rc == cli.ONION_EXIT


def test_run_rejects_bare_nonexistent_argument(capsys):
    args = argparse.Namespace(target="not-a-url-or-file", timeout=5.0, json=False)
    rc = cli.run(args)
    assert rc == cli.ERROR_EXIT


def test_command_is_discoverable():
    # HELP + add_arguments + run make it a `ctf` subcommand (ctf/cli/__init__.py discovery).
    assert isinstance(cli.HELP, str) and cli.HELP
    p = argparse.ArgumentParser()
    cli.add_arguments(p)
    ns = p.parse_args(["http://host/"])
    assert ns.target == "http://host/"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
