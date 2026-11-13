#!/usr/bin/env python3
"""The web toolkit on real artifacts and a real live target. The live target is a small vulnerable app this
test starts on loopback (127.0.0.1) itself and stops at the end; it is never a host on the internet, and the
WebClient is pointed only at that loopback port. The offline readers run on the group-c cache (scanner logs,
HARs) when it is present, and on fixtures built here otherwise.

  .venv/bin/python tests/real/test_real_web.py       the cache groups SKIP when challenges/_realdata/web_evidence is absent

No Game Master, no internet. The loopback server binds 127.0.0.1 on a port the OS picks.
"""
import http.server
import re
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import realdata_c as R  # noqa: E402

web, ROOT = R.start("web_evidence")       # the web toolkit shares the web_evidence cache; load web itself:
web = R.load("web")
check, q = R.check, R.q


# ---- a deliberately vulnerable app on loopback (our own; started and stopped here) ----
class _Vuln(http.server.BaseHTTPRequestHandler):
    FLAG = "flag{loopback_reflected_xss_demo}"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html"):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Set-Cookie", "session=abc; HttpOnly")
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path == "/":
            self._send(200, "<html><body><h1>Guestbook</h1><a href=/search>search</a></body></html>")
        elif self.path.startswith("/search"):
            from urllib.parse import urlsplit, parse_qs, unquote
            qs = parse_qs(urlsplit(self.path).query)
            term = unquote(qs.get("q", [""])[0])
            # a reflected XSS: the query value goes into the page unescaped
            self._send(200, f"<html><body>Results for: {term}</body></html>")
        elif self.path == "/robots.txt":
            self._send(200, "User-agent: *\nDisallow: /admin\n", "text/plain")
        elif self.path == "/admin":
            self._send(403, "forbidden")
        else:
            self._send(404, "not found")


def live_target():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Vuln)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        base = f"http://127.0.0.1:{port}"
        c = web.WebClient(base)
        r = c.get("/")
        check("live: GET / returns 200 and is logged", r["status"] == 200 and len(c.log) == 1, r.get("status"))
        check("live: target_needs_vpn is true for a loopback target (a private address)", web.target_needs_vpn(base) is True)
        try:
            c.get("http://example.com/")
            check("live: an off-scope host is refused", False)
        except web.OutOfScope:
            check("live: an off-scope host is refused (OutOfScope), never contacted", True)
        found = c.discover()
        paths = {p for p, _ in found}
        check("live: discover finds / and /robots.txt and not the 404s", "/" in paths and "/robots.txt" in paths and "/nope" not in paths, sorted(paths))
        # a reflected value comes back in the page; the toolkit CLASSIFIES a string, it does not inject
        r = c.get("/search?q=%3Cscript%3Ealert(1)%3C/script%3E")
        cls, scores = web.classify_payload(web._unescape_all(r["body"].decode()))
        check("live: the reflected <script> in the response classifies as xss", cls == "xss", (cls, scores))
        cookies = web.parse_set_cookies("Set-Cookie: " + r["response_headers"].get("Set-Cookie", ""))
        check("live: the Set-Cookie is read (session, HttpOnly)", any(c["name"] == "session" and c["httponly"] for c in cookies), cookies)
        gm = c.log and all(e["url"].startswith(base) for e in c.log)
        check("live: every logged request went to the loopback target only", gm, [e["url"] for e in c.log])
    finally:
        srv.shutdown()


def unreachable_is_vpn_stop():
    # nothing listens on this loopback port: the client raises VPNRequired (a stop for the player)
    c = web.WebClient("http://127.0.0.1:1/")
    try:
        c.get("/")
        check("an unreachable loopback target raises VPNRequired", False)
    except web.VPNRequired:
        check("an unreachable loopback target raises VPNRequired (the player's stop)", True)
    except Exception as e:
        check("an unreachable loopback target raises VPNRequired", False, type(e).__name__)


def refuses_game_master():
    for url in ("https://2026.huntress.ctf.games/", "https://2026.huntress.ctf.games/x"):
        try:
            web.WebClient(url)
            check(f"WebClient refuses the Game Master host ({url})", False)
        except Exception:
            check(f"WebClient refuses the Game Master host ({url})", True)


def offline_readers():
    # the same scanner log the web_evidence test uses, read by the web toolkit's own parser
    d = R.data(ROOT, "logs/acunetix.txt")
    rows = web.parse_access_log(d)
    check("web.parse_access_log reads the quoted-line Acunetix log: 6539 rows, one host",
          len(rows) == 6539 and len({r["host"] for r in rows}) == 1, (len(rows), len({r["host"] for r in rows})))
    hosts = {r["host"] for r in rows}
    per = [web.classify_payload(web._unescape_all(web._request_target(r)))[0] for r in rows]
    check("web: the Acunetix log carries several payload classes (so a single class is not claimed)",
          len({c for c in per if c}) >= 3, {c for c in per if c})
    d = R.data(ROOT, "logs/apache_logs")
    rows = web.parse_access_log(d)
    classes = {web.classify_payload(web._unescape_all(web._request_target(r)))[0] for r in rows} - {None}
    got = web.solve_set([q("v", "Which payload class was used?")], {"apache_logs": d}, {})
    check("web: ordinary traffic is not called a single attack class (mixed or None, never plain)",
          not R.plain(got["v"]), (got["v"], classes))


def built_in_memory():
    for text, cls in ("/x?q=<script>alert(1)</script>", "xss"), ("/?id=1 UNION SELECT password FROM users", "sqli"), \
                     ("/load?file=../../../../etc/passwd", "lfi"), ("/p?u=http://169.254.169.254/latest/meta-data/", "ssrf"), \
                     ("/r?c=;cat /etc/shadow", "rce"):
        c, _ = web.classify_payload(web._unescape_all(text))
        check(f"classify_payload: {cls} for {text[:30]!r}", c == cls, c)
    for benign in ("/articles?url=http://www.example.com/a", "/img/../img/logo.png", "/page?next=/home", "/q?s=hello world"):
        c, _ = web.classify_payload(web._unescape_all(benign))
        check(f"classify_payload: benign {benign[:30]!r} is not flagged", c is None, c)


R.section(built_in_memory)
R.section(refuses_game_master)
R.section(unreachable_is_vpn_stop)
R.section(live_target)
R.section(offline_readers)
sys.exit(R.finish("test_real_web"))
