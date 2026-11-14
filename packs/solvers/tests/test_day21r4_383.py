#!/usr/bin/env python3
"""Day 21 build, round 4: backlog row 383's READ-ONLY half in solvers/web/proof_hunt.py (SSTI, command injection,
forged JWTs, same-host GET redirects).

  .venv/bin/python tests/test_day21r4_383.py        (TEST_KEEP=1 keeps the scratch folder; WEB_TIMING=1 prints
                                                     per-shape timings with 0 and 150 ms per request)

Local fake targets only (http.server on 127.0.0.1); no Game Master request, no live target.

  A. SSTI: a Jinja-like reflector (the curly syntax, emulated), a REAL Mako template (`${a*b}`, `${open(F).read()}`
     reading a temporary file the prompt names); a page that reflects raw (no template) gets no read payload; a
     template that evaluates but does not reflect the marker gets none; a proof on the reflection is None
  B. command injection: a lookup page whose `host` reaches a real /bin/sh (in a scratch folder; bare, single- and
     double-quoted argument fakes): the echo marker is computed, then `cat` of the prompt's path / objective.txt
     only; a page that echoes the input raw gets no `cat`; a `host` parameter that runs nothing gets none
  C. JWT: a cookie token accepted with alg none; a weak HS256 secret (forged with the cracked secret only);
     kid traversal to /dev/null only when the header has a kid (and never without one); a bearer token named in a
     page; the original token already showing the proof is None; a strong secret and a server that refuses none
     is None
  D. nothing destructive: GET only, a forged token's 302 followed only on the same host and never to a
     destructive path, a destructive READ-worded endpoint never requested, no POST form sent
  E. the hard deadline and the stop flag on a slow SSTI target; the request budget
  F. the six earlier shapes cost the same GETs (round 4 sends nothing once they answer); no round-4 request on
     a target where a proof-like value was already seen
"""

import event_pin  # noqa: E402  (tests/event_pin.py)
event_pin.pin(globals(), "huntress")  # Huntress web tests: proof_<32 hex> payoffs (events/huntress [proof])
import base64
import hashlib
import hmac
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tests"))
import web_fakes as T  # noqa: E402  -- the round-1 Site/serve/hunt fakes (that test was archived with web_open)
PH = T.PH
Site, page, js, uuid_proof, hunt = T.Site, T.page, T.js, T.uuid_proof, T.hunt

SCRATCH = Path(tempfile.mkdtemp(prefix="day21r4-web-"))
FAILS = []


def check(name, ok, detail=""):
    if not ok:
        FAILS.append(name)
    print(("ok   " if ok else "FAIL ") + name + ("" if ok or not detail else f"  [{str(detail)[:900]}]"), flush=True)


def qval(raw, name):
    return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(raw).query, keep_blank_values=True)).get(name)


READ_WORDS = re.compile(r"open\(|File\.read|readFileSync|source\(|fetch file|file_get_contents")


# ---------------------------------------------------------------------------------------------------------
#  A. SSTI
# ---------------------------------------------------------------------------------------------------------
def jinja_like(fs, reflect=True, evaluate=True, extra=""):
    """/greet?name=: a template built from the input (the curly syntax only, emulated)."""
    def greet(q):
        v = q.get("name", "guest")

        def sub(m):
            expr = m.group(1).strip()
            mm = re.fullmatch(r"(\d+)\s*\*\s*(\d+)", expr)
            if mm and evaluate:
                return str(int(mm.group(1)) * int(mm.group(2)))
            mm = re.fullmatch(r"(?:lipsum\.__globals__\['__builtins__'\]\['open'\]|"
                              r"cycler\.__init__\.__globals__\.__builtins__\.open)\('([^']+)'\)\.read\(\)", expr)
            if mm and evaluate:
                return fs.get(mm.group(1), "")
            return "" if evaluate else m.group(0)
        out = re.sub(r"\{\{(.*?)\}\}", sub, v)
        return page("Greeter", f"<p>Hello {out if reflect else 'friend'}!</p>{extra}")
    return {"/": page("Greeter", "<a href='/greet?name=guest'>Say hello</a>"), "/greet": greet}


def mako_site():
    from mako.template import Template

    def greet(q):
        v = q.get("name", "guest")
        try:
            body = Template("<p>Hello " + v + "</p>").render()
        except Exception as e:
            return 500, "text/html", f"<pre>{type(e).__name__}</pre>"
        return page("Mako Greeter", body)
    return {"/": page("Mako Greeter", "<form action='/greet'><input name='name'></form>"), "/greet": greet}


def test_ssti():
    p = uuid_proof("ssti-jinja")
    site = Site(jinja_like({"/run/huntress/objective.txt": p + "\n"}))
    out, secs, _ = hunt([site])
    paths = [raw for _t, _m, raw in site.hits]
    reads = [r for r in paths if READ_WORDS.search(urllib.parse.unquote_plus(r))]
    first_read = min((i for i, r in enumerate(paths) if READ_WORDS.search(urllib.parse.unquote_plus(r))), default=None)
    arith = [i for i, r in enumerate(paths) if re.search(r"\{\{\d+\*\d+\}\}", urllib.parse.unquote_plus(r))]
    check(f"A jinja-like reflector: the proof through a read payload ({len(paths)} GETs, {secs:.2f} s)",
          out == {"proof-1": p}, (out, paths[-6:]))
    check("A the read payloads come only after the arithmetic marker", first_read is not None and arith
          and first_read > min(arith), (first_read, arith))
    check("A the read payloads read only /run/huntress/objective.txt", reads and all(
        "/run/huntress/objective.txt" in urllib.parse.unquote_plus(r) for r in reads), reads)
    check("A no read payload of another syntax was sent (only the confirmed curly one)", all(
        urllib.parse.unquote_plus(qval(r, "name") or "").startswith("{{") for r in reads), reads)
    # a prompt path: a real Mako template reads a temporary file the prompt names
    pf = SCRATCH / "mako" / "proof.txt"
    pf.parent.mkdir(parents=True, exist_ok=True)
    p2 = uuid_proof("ssti-mako")
    pf.write_text(p2 + "\n")
    site = Site(mako_site())
    out, secs, _ = hunt([site], files_prompt=f"The attempt proof is mounted at {pf}.")
    paths = [urllib.parse.unquote_plus(raw) for _t, _m, raw in site.hits]
    check(f"A a real Mako template: `${{a*b}}` confirmed, `${{open(F).read()}}` reads the prompt's file "
          f"({len(paths)} GETs, {secs:.2f} s)", out == {"proof-1": p2}, (out, paths[-6:]))
    check("A Mako: no read payload of the curly, erb, hash or smarty syntax", not any(
        re.search(r"name=(\{\{|<%|#\{|\{')", x) and READ_WORDS.search(x) for x in paths),
        [x for x in paths if READ_WORDS.search(x)])
    # a raw reflector (no template): markers only, no read payload
    site = Site(jinja_like({"/run/huntress/objective.txt": p + "\n"}, evaluate=False))
    out, _s, _ = hunt([site])
    paths = [urllib.parse.unquote_plus(raw) for _t, _m, raw in site.hits]
    check(f"A a page that reflects raw: None, no read payload ({len(paths)} GETs)",
          out == {"proof-1": None} and not any(READ_WORDS.search(x) for x in paths), paths)
    # a template that evaluates but does not reflect the marker: not a reflected parameter, no read payload
    site = Site(jinja_like({"/run/huntress/objective.txt": p + "\n"}, reflect=False))
    out, _s, _ = hunt([site])
    paths = [urllib.parse.unquote_plus(raw) for _t, _m, raw in site.hits]
    check("A a parameter the page does not reflect: None, no read payload",
          out == {"proof-1": None} and not any(READ_WORDS.search(x) for x in paths), paths)
    # a proof the reflection page shows anyway is the site's own: None
    site = Site(jinja_like({"/run/huntress/objective.txt": p + "\n"}, extra=f"<!-- {p} -->"))
    out, _s, _ = hunt([site])
    check("A the proof shown on the greeting page anyway: None", out == {"proof-1": None}, out)


# ---------------------------------------------------------------------------------------------------------
#  B. command injection (a real /bin/sh in a scratch folder; our own payloads only)
# ---------------------------------------------------------------------------------------------------------
SH_DIR = SCRATCH / "sh"


def sh_site(quote="", runs=True, objective=None, page_word="Ping a host"):
    SH_DIR.mkdir(parents=True, exist_ok=True)
    obj = SCRATCH / "sh-objective.txt"
    if objective:
        obj.write_text(objective + "\n")
    elif obj.exists():
        obj.unlink()                 # no objective file: an earlier case's proof must not stand there

    def ping(q):
        host = q.get("host", "")
        if not runs:
            return page("Ping", f"<pre>PING {host}</pre>")
        # the fake's "ping": echo, with the input in a bare, single- or double-quoted argument; the objective
        # path is mapped to a scratch file so /run is never read on this machine
        line = f"echo PING {quote}{host}{quote}".replace("/run/huntress/objective.txt", str(obj))
        try:
            r = subprocess.run(["/bin/sh", "-c", line], capture_output=True, text=True, timeout=3, cwd=SH_DIR,
                               env={"PATH": "/usr/bin:/bin"})
            out = r.stdout + r.stderr
        except Exception as e:
            out = type(e).__name__
        return page("Ping", f"<pre>{out}</pre>")
    return {"/": page("Net Tools", f"<h1>{page_word}</h1><form action='/tools/ping'><input name='host' "
                                   "value='127.0.0.1'><button>Go</button></form>"),
            "/tools/ping": ping}


def cat_targets(site):
    out = []
    for _t, _m, raw in site.hits:
        v = qval(raw, "host") or ""
        for m in re.finditer(r"\bcat\s+(\S+?)(?=[)`'\"\s;|&]|$)", v):
            out.append(m.group(1))
    return out


def test_cmdi():
    for quote, label in (("", "bare"), ("'", "single-quoted"), ('"', "double-quoted")):
        p = uuid_proof("cmdi" + label)
        site = Site(sh_site(quote, objective=p))
        out, secs, _ = hunt([site])
        cats = cat_targets(site)
        check(f"B a lookup page, {label} argument: the proof through `cat` ({len(site.hits)} GETs, {secs:.2f} s)",
              out == {"proof-1": p}, (out, [urllib.parse.unquote_plus(r) for _t, _m, r in site.hits][-5:]))
        check(f"B {label}: `cat` only of /run/huntress/objective.txt", cats and set(cats) == {"/run/huntress/objective.txt"},
              cats)
    # the prompt's path first
    pf = SCRATCH / "prompted" / "proof.txt"
    pf.parent.mkdir(parents=True, exist_ok=True)
    p = uuid_proof("cmdi-prompt")
    pf.write_text(p + "\n")
    site = Site(sh_site(""))
    out, _s, _ = hunt([site], files_prompt=f"The proof is mounted at {pf} on the box.")
    cats = cat_targets(site)
    check("B a prompt path: `cat` of it (and objective.txt), nothing else", out == {"proof-1": p}
          and set(cats) <= {str(pf), "/run/huntress/objective.txt"} and str(pf) in cats, (out, cats))
    # echoes the input raw (no shell): no cat
    site = Site(sh_site("", runs=False, objective=uuid_proof("raw")))
    out, _s, _ = hunt([site])
    check(f"B a page that only echoes the input: None, no `cat` sent ({len(site.hits)} GETs)",
          out == {"proof-1": None} and not cat_targets(site), cat_targets(site))
    # a single-field form on a page with no lookup word and a name that is no lookup word: no cmdi probe
    routes = {"/": page("Guestbook", "<form action='/sign'><input name='comment'></form>"),
              "/sign": lambda q: page("Thanks", f"<p>Thanks for: {q.get('comment', '')}</p>")}
    site = Site(routes)
    hunt([site])
    check("B a field that is no lookup's: no echo marker sent", not any("echo" in (qval(r, "comment") or "")
                                                                      for _t, _m, r in site.hits), "")


# ---------------------------------------------------------------------------------------------------------
#  C. JWT
# ---------------------------------------------------------------------------------------------------------
def b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def mint(header, payload, key):
    h, p = b64e(json.dumps(header).encode()), b64e(json.dumps(payload).encode())
    sig = b"" if key is None else hmac.new(key, f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{b64e(sig)}"


def verify(tok, secret, accept_none=False, kid_keys=None):
    try:
        h, p, s = tok.split(".")
        hdr, pl = json.loads(b64d(h)), json.loads(b64d(p))
    except Exception:
        return None
    alg = str(hdr.get("alg", ""))
    if alg.lower() == "none":
        return pl if accept_none and not s else None
    if alg != "HS256":
        return None
    key = secret
    if kid_keys is not None and "kid" in hdr:
        norm = os.path.normpath("/srv/app/" + str(hdr["kid"]))
        if norm not in kid_keys:
            return None
        key = kid_keys[norm]
    want = hmac.new(key, f"{h}.{p}".encode(), hashlib.sha256).digest()
    return pl if hmac.compare_digest(want, b64d(s)) else None


def jwt_site(proof, secret=b"secret", accept_none=False, kid=None, via="cookie", orig_admin=False,
             admin_path="/api/admin/report", redirect=None):
    """A cookie (or a page-named bearer token) for guest; admin_path answers the proof to an admin token only."""
    header = {"alg": "HS256", "typ": "JWT"}
    kid_keys = None
    if kid:
        header["kid"] = kid
        kid_keys = {os.path.normpath("/srv/app/" + kid): secret, "/dev/null": b""}
    tok = mint(header, {"user": "guest", "role": "admin" if orig_admin else "user", "iat": 1}, secret)
    hits = {"forged_ok": 0}

    def token_of(hdrs_cookie, auth):
        if auth and auth.startswith("Bearer "):
            return auth[7:]
        m = re.search(r"(?:^|;\s*)session=([^;]+)", hdrs_cookie or "")
        return m.group(1) if m else None

    def admin(q, headers):
        t = token_of(headers.get("Cookie"), headers.get("Authorization"))
        pl = verify(t, secret, accept_none, kid_keys) if t else None
        if not pl or pl.get("role") != "admin":
            return 403, "application/json", json.dumps({"error": "admins only"}), {}
        hits["forged_ok"] += 1
        if redirect:
            return 302, "text/html", "", {"Location": redirect}
        return 200, "application/json", json.dumps({"report": "quarterly", "proof": proof}), {}

    root_body = (f"<a href='{admin_path}'>Admin report</a><a href='/api/profile'>Profile</a>"
                 "<a href='/api/admin/delete-user'>x</a>")
    root_hdrs = {}
    if via == "cookie":
        root_hdrs = {"Set-Cookie": f"session={tok}; Path=/"}
    else:
        root_body += f"<script>localStorage.setItem('token', '{tok}')</script>"
    routes = {"/": (200, "text/html", T.HTML.format(t="Ops Portal", b=root_body), root_hdrs),
              "/api/profile": js({"user": "guest"}),
              admin_path: admin,
              "/admin/view-7": page("Report", f"<pre>{proof}</pre>")}
    return routes, hits, tok


class HSite(Site):
    """Site whose handlers may take (query, headers)."""

    def handle_h(self, method, raw, headers):
        with self.lock:
            self.hits.append((time.time(), method, raw, dict(headers)))
        if self.latency:
            time.sleep(self.latency)
        if method != "GET":
            return 405, "text/plain", "no", {}
        path, _, q = raw.partition("?")
        query = dict(urllib.parse.parse_qsl(q, keep_blank_values=True))
        fn = self.routes.get(path) or self.default
        if fn is None:
            return 404, "text/html", "<p>not found</p>", {}
        if callable(fn):
            try:
                r = fn(query, headers)
            except TypeError:
                r = fn(query)
        else:
            r = fn
        return (tuple(r) + ({},))[:4]


def hserve(site):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class H(BaseHTTPRequestHandler):
        def _go(self):
            st, ctype, body, hdrs = site.handle_h(self.command, self.path, {k: v for k, v in self.headers.items()})
            data = body.encode() if isinstance(body, str) else body
            self.send_response(st)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            for k, v in (hdrs or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        do_GET = do_POST = do_PUT = do_DELETE = _go

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/"


def hhunt(site, deadline_s=20.0, max_requests=400):
    srv, url = hserve(site)
    t0 = time.time()
    out = PH.solve_targets([{"answer_id": "proof-1", "url": url, "index": 1, "question": ""}],
                           {"deadline": time.time() + deadline_s, "max_requests": max_requests, "log_dir": None,
                            "challenge": "t"})
    secs = time.time() - t0
    srv.shutdown()
    srv.server_close()
    return out, secs


def sent_tokens(site):
    out = []
    for h in site.hits:
        hd = h[3] if len(h) > 3 else {}
        a = hd.get("Authorization", "")
        if a.startswith("Bearer "):
            t = a[7:]
            try:
                out.append((h[2], json.loads(b64d(t.split(".")[0])), json.loads(b64d(t.split(".")[1])), t))
            except Exception:
                pass
    return out


def test_jwt():
    p = uuid_proof("jwt-none")
    routes, hits, _tok = jwt_site(p, secret=os.urandom(16), accept_none=True)
    site = HSite(routes)
    out, secs = hhunt(site)
    toks = sent_tokens(site)
    check(f"C a cookie token, the server takes alg none: the proof ({len(site.hits)} GETs, {secs:.2f} s)",
          out == {"proof-1": p}, (out, [h[2] for h in site.hits]))
    check("C no kid forgery for a header without a kid", not any("kid" in h for _p, h, _pl, _t in toks), toks[:3])
    check("C no HS forgery when the secret is not cracked", not any(h.get("alg") == "HS256" and _pl.get("role") == "admin"
                                                                    for _p, h, _pl, _t in toks), "")
    p = uuid_proof("jwt-weak")
    routes, hits, _tok = jwt_site(p, secret=b"changeme")
    site = HSite(routes)
    out, secs = hhunt(site)
    check(f"C a weak HS256 secret (changeme): cracked offline, the forged token reads the proof ({secs:.2f} s)",
          out == {"proof-1": p}, (out, [h[2] for h in site.hits]))
    check("C PH.jwt_crack finds the secret, and None for a strong one",
          PH.jwt_crack(_tok) == "changeme" and PH.jwt_crack(mint({"alg": "HS256"}, {"a": 1}, os.urandom(20))) is None, "")
    p = uuid_proof("jwt-kid")
    routes, hits, _tok = jwt_site(p, secret=os.urandom(16), kid="keys/main.key")
    site = HSite(routes)
    out, _s = hhunt(site)
    toks = sent_tokens(site)
    check("C kid traversal (the header shows a kid): /dev/null and an empty key read the proof",
          out == {"proof-1": p} and any(h.get("kid") == PH.JWT_KID for _p, h, _pl, _t in toks), (out, len(toks)))
    p = uuid_proof("jwt-bearer")
    routes, hits, _tok = jwt_site(p, secret=b"secret", via="page", accept_none=False)
    site = HSite(routes)
    out, _s = hhunt(site)
    check("C a token a page names (bearer), weak secret: the proof", out == {"proof-1": p}, out)
    # decoys and refusals
    p = uuid_proof("jwt-orig")
    routes, hits, _tok = jwt_site(p, secret=b"secret", orig_admin=True)
    site = HSite(routes)
    out, _s = hhunt(site)
    check("C the original token already reads the proof: None (the site's own page)", out == {"proof-1": None}, out)
    routes, hits, _tok = jwt_site(uuid_proof("jwt-strong"), secret=os.urandom(24), accept_none=False)
    site = HSite(routes)
    out, _s = hhunt(site)
    check(f"C a strong secret, none refused: None ({len(site.hits)} GETs)", out == {"proof-1": None}, out)
    # unit: the forgeries
    tok = mint({"alg": "HS256", "typ": "JWT"}, {"sub": "guest", "roles": ["user"], "is_admin": False}, b"secret")
    forged = dict(PH.jwt_forgeries(tok, PH._web.decode_jwt(tok)))
    pl = json.loads(b64d(forged["none-a"].split(".")[1]))
    plb = json.loads(b64d(forged["none-b"].split(".")[1]))
    check("C jwt_forgeries: none-a raises roles and is_admin, none-b the identity too, hs signed with the cracked secret",
          pl["roles"][0] == "admin" and pl["is_admin"] is True and pl["sub"] == "guest" and plb["sub"] == "admin"
          and forged["none-a"].endswith(".") and verify(forged["hs-a"], b"secret") is not None
          and not any(k.startswith("kid") for k in forged), sorted(forged))


# ---------------------------------------------------------------------------------------------------------
#  D. nothing destructive; redirects
# ---------------------------------------------------------------------------------------------------------
BAD = re.compile(r"(?i)delete|logout|reset|wipe|elsewhere")


def test_safe():
    p = uuid_proof("jwt-redirect")
    routes, hits, _tok = jwt_site(p, secret=b"secret", redirect="/admin/view-7")
    routes["/admin/view-7"] = lambda q, h: (200, "text/html", f"<pre>{p}</pre>") if "Authorization" in h else (403, "text/html", "no")
    site = HSite(routes)
    out, _s = hhunt(site)
    paths = [h[2] for h in site.hits]
    check("D a forged token's 302 to the same host is followed (with the token) and read",
          out == {"proof-1": p} and "/admin/view-7" in paths, (out, paths))
    check("D the READ-worded destructive link /api/admin/delete-user is never requested",
          not any(BAD.search(x) for x in paths), [x for x in paths if BAD.search(x)])
    for loc in ("https://elsewhere.example/admin", "/admin/delete-everything"):
        routes, hits, _tok = jwt_site(uuid_proof("r" + loc), secret=b"secret", redirect=loc)
        site = HSite(routes)
        out, _s = hhunt(site)
        paths = [h[2] for h in site.hits]
        check(f"D a forged token's 302 to {loc}: not followed, None", out == {"proof-1": None}
              and not any(BAD.search(x) for x in paths) and hits["forged_ok"] > 0, (out, paths))
    # every method GET; a POST form on a lookup page is never sent
    routes = sh_site("", objective=uuid_proof("post"))
    routes["/"] = page("Net Tools", "<h1>Ping a host</h1><form method='post' action='/tools/ping'><input name='host'></form>")
    site = Site(routes)
    out, _s, _ = hunt([site])
    methods = {m for _t, m, _p in site.hits}
    check("D a POST lookup form: never sent, never turned into a GET (no echo marker)", methods == {"GET"}
          and out == {"proof-1": None} and not any("echo" in (qval(r, "host") or "") for _t, _m, r in site.hits),
          (methods, [r for _t, _m, r in site.hits]))
    src = (REPO / "solvers" / "web" / "proof_hunt.py").read_text()
    _m = re.findall(r"client\.request\(\s*\"(\w+)\"", src)
    check("D the source sends GET (plus the one player-approved stored-XSS POST), redirects by hand",
          set(_m) == {"GET", "POST"} and _m.count("POST") == 1 and "STORED_XSS_ENABLED" in src
          and "allow_redirects=False" in src, _m)
    payloads = " ".join(t for v in PH.SSTI_READS.values() for t in v)
    check("D the SSTI read payloads read a file and run nothing", not re.search(
        r"popen|system|subprocess|exec|spawn|child_process|`|\bIO\.|Runtime", payloads), payloads)


# ---------------------------------------------------------------------------------------------------------
#  E. deadline, stop flag, budget
# ---------------------------------------------------------------------------------------------------------
def test_deadline():
    p = uuid_proof("slow-ssti")
    slow = Site(jinja_like({"/run/huntress/objective.txt": p}), latency=0.6)
    srv, url = T.serve(slow)
    t0 = time.time()
    out = PH.solve_targets([{"answer_id": "proof-1", "url": url, "index": 1, "question": ""}],
                           {"deadline": time.time() + 2.0, "max_requests": 400, "log_dir": None, "challenge": "t"})
    took = time.time() - t0
    ret = time.time()
    time.sleep(1.5)
    late = [h for h in slow.hits if h[0] > ret + 0.05]
    srv.shutdown()
    srv.server_close()
    check(f"E a slow SSTI target (0.6 s a request), deadline 2 s: returns by it ({took:.2f} s), None",
          took <= 2.6 and out == {"proof-1": None}, (took, out))
    check(f"E nothing is sent after the return ({len(late)} late)", not late, late)
    s = Site(sh_site("", objective=uuid_proof("budget")))
    out, _s, _ = hunt([s], max_requests=12)
    check(f"E max_requests 12 is kept on a cmdi target ({len(s.hits)} GETs)", len(s.hits) <= 12, len(s.hits))


# ---------------------------------------------------------------------------------------------------------
#  F. the earlier shapes: the same GETs; nothing after a proof-like value
# ---------------------------------------------------------------------------------------------------------
HEAD_GETS = {"backup": 6, "idor": 10, "sqli": 9, "lfi": 15, "route": 4}   # HEAD (round 2) on these fakes


def test_earlier():
    for name, mk in T.SHAPES.items():
        p = uuid_proof("f" + name)
        site = Site(mk(p), latency=0.05)
        out, secs, _ = hunt([site])
        r4 = [r for _t, _m, r in site.hits if re.search(r"hz[0-9a-f]{10}|echo|%7B%7B|eyJ", r)]
        check(f"F {name}: the proof, {len(site.hits)} GETs (HEAD {HEAD_GETS[name]}), {secs:.2f} s, no round-4 request",
              out == {"proof-1": p} and len(site.hits) <= HEAD_GETS[name] + 1 and not r4, (out, len(site.hits), r4))
    q = uuid_proof("decoy")
    site = Site(T.site_route(uuid_proof("real"), root_extra=f"<p>{q}</p><a href='/greet?name=x'>g</a>"))
    hunt([site])
    r4 = [r for _t, _m, r in site.hits if re.search(r"hz[0-9a-f]{10}|echo|%7B%7B", r)]
    check("F a proof already seen (a decoy): round 4 sends nothing", not r4, r4)


def timings():
    print("timing  shape    latency  GETs  seconds")
    for lat in (0.0, 0.15):
        for name, mk in list(T.SHAPES.items()):
            site = Site(mk(uuid_proof(name)), latency=lat)
            out, secs, _ = hunt([site])
            print(f"timing  {name:<8} {lat:>5.2f} s  {len(site.hits):>4}  {secs:6.2f}  {'ok' if out['proof-1'] else 'NONE'}")
        site = Site(jinja_like({"/run/huntress/objective.txt": uuid_proof("t") + "\n"}), latency=lat)
        out, secs, _ = hunt([site])
        print(f"timing  ssti     {lat:>5.2f} s  {len(site.hits):>4}  {secs:6.2f}  {'ok' if out['proof-1'] else 'NONE'}")
        site = Site(sh_site("", objective=uuid_proof("t2")), latency=lat)
        out, secs, _ = hunt([site])
        print(f"timing  cmdi     {lat:>5.2f} s  {len(site.hits):>4}  {secs:6.2f}  {'ok' if out['proof-1'] else 'NONE'}")
        routes, _h, _t = jwt_site(uuid_proof("t3"), secret=b"secret")
        site = HSite(routes, latency=lat)
        out, secs = hhunt(site)
        print(f"timing  jwt      {lat:>5.2f} s  {len(site.hits):>4}  {secs:6.2f}  {'ok' if out['proof-1'] else 'NONE'}")


def main():
    try:
        test_ssti()
        test_cmdi()
        test_jwt()
        test_safe()
        test_deadline()
        test_earlier()
        if os.environ.get("WEB_TIMING"):
            timings()
    finally:
        if not os.environ.get("TEST_KEEP"):
            shutil.rmtree(SCRATCH, ignore_errors=True)
            shutil.rmtree(T.SCRATCH, ignore_errors=True)
    print(f"RESULT {'FAIL' if FAILS else 'PASS'} ({len(FAILS)} failed)")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
