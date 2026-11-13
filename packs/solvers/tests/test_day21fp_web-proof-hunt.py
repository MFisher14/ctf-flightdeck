#!/usr/bin/env python3
"""Day 21 final prep, group web-proof-hunt: four more READ-ONLY shapes in solvers/web/proof_hunt.py.

  .venv/bin/python tests/test_day21fp_web-proof-hunt.py     (TEST_KEEP=1 keeps the scratch folders; WEB_TIMING=1
                                                              prints GETs and seconds with 0 and 150 ms a request)

Local fake targets only (http.server on 127.0.0.1); no Game Master request, no live target. The fakes EMULATE the
inner network of an SSRF (a dict of inner URL -> body); nothing is ever fetched from an inner URL by the test.

  A. SSRF after wave 6, GET only: (a) an internal URL a page names joined with the route the prompt names;
     (b) file:///run/huntress/objective.txt; (c) the metadata endpoint's '/' listing -> its role (second hop);
     (d) an internal root's JSON route list -> the route (second hop), on a parameter named by its http:// value;
     decoys: the baseline already shows the proof; two proofs through the inner network; never a dotted or public
     inner host, never *.huntress.ctf.games, never a destructive inner path, no Authorization header
  B. header and cookie access control: X-Forwarded-For on a 403 path; X-Original-URL on '/'; a role cookie
     (analyst -> admin); a base64 JSON cookie raised with jwt_raise (standard and URL-safe); decoy: the ORIGINAL
     cookie, replayed as the control, already shows the proof
  C. SSTI config and env: {{config}} and cycler...os.environ behind a confirmed curly syntax; Node
     ${JSON.stringify(process.env)}; /proc/self/environ through an LFI reader (wave 6b); decoy: a config with two
     proofs; the env payloads are never sent when a file read already answered
  D. unlinked paths: /internal/objective the prompt names (wave 2), /.git/logs/HEAD, /.env, /backup.zip (a deflated
     member); decoys: the landing page links the prompt's route and shows the proof (plain), .env and /config.json
     with two proofs; the 410 target sends no guessed path; a destructive prompt route is never requested
  E. helpers: inner_ok, internal_host, cookie_raises, prompt_routes
"""

import event_pin  # noqa: E402  (tests/event_pin.py)
event_pin.pin(globals(), "huntress")  # Huntress web tests: proof_<32 hex> payoffs (events/huntress [proof])
import base64
import importlib.util
import io
import json
import os
import re
import shutil
import sys
import time
import urllib.parse
import zipfile
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import event, flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[1]))
    from ctf import event, flagfmt

REPO = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("t21r4", REPO / "tests" / "test_day21r4_383.py")
R4 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(R4)          # HSite/hserve (headers) and, through it, the round-1 fakes
T = R4.T
PH = R4.PH
page, js, uuid_proof, Site = T.page, T.js, T.uuid_proof, T.Site
HSite, hserve = R4.HSite, R4.hserve

FAILS = []
TIMES = []
# The day_review marker "web-proof-hunt-fp" (tools/day_review_markers.json, archived with the Huntress day
# tooling), pinned here so the proof_hunt.jsonl row shape it matched stays checked.
PROOF_HUNT_FP_MARKERS = ['"shape": "(ssrf|header|cookie|exposed|promptroute)"',
                         '"proof": "' + flagfmt.for_profile(event.load("huntress")).proof.pattern
                         + '".*"where": "wave6b"']


def check(name, ok, detail=""):
    if not ok:
        FAILS.append(name)
    print(("ok   " if ok else "FAIL ") + name + ("" if ok or not detail else f"  [{str(detail)[:900]}]"), flush=True)


def hunt(site, prompt=None, deadline_s=20.0, max_requests=400, log_dir=None):
    """One target on an HSite (headers recorded); returns (answer, seconds)."""
    srv, url = hserve(site)
    ctx = {"deadline": time.time() + deadline_s, "max_requests": max_requests, "log_dir": log_dir, "challenge": "t"}
    if prompt:
        ctx["prompt"] = prompt
    t0 = time.time()
    out = PH.solve_targets([{"answer_id": "proof-1", "url": url, "index": 1, "question": "Recover the proof."}], ctx)
    secs = time.time() - t0
    srv.shutdown()
    srv.server_close()
    return out.get("proof-1"), secs


def raws(site):
    return [h[2] for h in site.hits]


def inner_sent(site, param="url"):
    out = []
    for h in site.hits:
        sp = urllib.parse.urlsplit(h[2])
        v = dict(urllib.parse.parse_qsl(sp.query, keep_blank_values=True)).get(param)
        if v is not None:
            out.append(v)
    return out


def only_get(site):
    return all(h[1] == "GET" for h in site.hits)


def no_auth(site):
    return not any("Authorization" in (h[3] if len(h) > 3 else {}) for h in site.hits)


def record(name, site, secs, ans):
    TIMES.append((name, len(site.hits), secs, "ok" if ans else "NONE"))


# ---------------------------------------------------------------------------------------------------------
#  A. SSRF
# ---------------------------------------------------------------------------------------------------------
def ssrf_site(inner, fs=None, root_extra="", param="url", offered="", path="/fetch", baseline_body=None):
    """/fetch?<param>=<inner URL>: the inner network is the dict `inner` (URL -> body), file:// reads `fs`."""
    fs = fs or {}

    def fetch(q):
        u = q.get(param, "")
        if baseline_body is not None and u == offered:
            body = baseline_body
        elif u.startswith("file://"):
            body = fs.get(urllib.parse.urlsplit(u).path)
        else:
            body = inner.get(u)
            if body is None and u.rstrip("/") + "/" in inner:
                body = inner[u.rstrip("/") + "/"]
        if body is None:
            return 502, "text/html", "<p>upstream fetch failed</p>"
        esc = body.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return page("Link preview", f"<h2>Preview of {u.replace('<', '')}</h2><pre>{esc}</pre>")
    link = f"{path}?{param}=" + urllib.parse.quote(offered, safe="")
    return {"/": page("Link Previewer", f"<a href='{link}'>Preview a link</a>{root_extra}"), path: fetch}


def test_ssrf():
    # (a) the page names an internal service, the prompt names the route
    p = uuid_proof("ssrf-a")
    inner = {"http://10.20.0.7:8080/internal/objective": json.dumps({"proof": p}),
             "http://10.20.0.7:8080/": "status service"}
    site = HSite(ssrf_site(inner, root_extra="<p>Mirrors are synced from http://10.20.0.7:8080/ hourly. See also "
                                              "https://docs.example.com/x and https://web-a.2026.huntress.ctf.games/x"
                                              " and http://10.20.0.7:8080/admin/delete-all</p>"))
    ans, secs = hunt(site, prompt="The status mirror keeps its objective at /internal/objective on the inside.")
    sent = [u for u in inner_sent(site) if "://" in u or not u]      # (the SSTI markers on `url` are no URLs)
    record("ssrf-a internal+route", site, secs, ans)
    check(f"A (a) an internal URL a page names + the prompt's route: the proof ({len(site.hits)} GETs, {secs:.2f} s)",
          ans == p, (ans, sent))
    bad = [u for u in sent if u and not PH.inner_ok(u)]
    dotted = [u for u in sent if re.match(r"(?i)https?://[^/:]*[a-z][^/:]*\.[a-z]", u)]
    check("A (a) no inner URL to a dotted/public host, none to *.huntress.ctf.games, none destructive",
          not bad and not dotted and not any("huntress.ctf.games" in u or "delete" in u for u in sent), (bad, dotted))
    check("A (a) GET only, no Authorization header, the baseline (the offered empty value) first of the SSRF GETs",
          only_get(site) and no_auth(site) and "" in sent and sent.index("") == 0, sent[:3])

    # (b) file:///run/huntress/objective.txt
    p = uuid_proof("ssrf-b")
    site = HSite(ssrf_site({}, fs={"/run/huntress/objective.txt": p + "\n"}, param="image", path="/avatar"))
    logd = R4.SCRATCH / "fp-ssrf-b" / "web_l1"
    ans, secs = hunt(site, log_dir=str(logd))
    record("ssrf-b file://", site, secs, ans)
    check(f"A (b) file:///run/huntress/objective.txt through `image`: the proof ({len(site.hits)} GETs, {secs:.2f} s)",
          ans == p, (ans, inner_sent(site, "image")))
    line = (logd / "proof_hunt.jsonl").read_text().splitlines()[-1]
    row = json.loads(line)
    marks = PROOF_HUNT_FP_MARKERS
    check("A (b) the JSONL row says shape ssrf, where wave7; the day_review marker web-proof-hunt-fp matches it",
          row.get("shape") == "ssrf" and row.get("where") == "wave7" and any(re.search(m, line) for m in marks),
          (row.get("shape"), row.get("where")))
    check("A (b) at most 12 inner URLs besides the baseline", len(set(inner_sent(site, "image")) - {""}) <= 12,
          inner_sent(site, "image"))

    # (c) the metadata endpoint's listing -> the role (second hop)
    p = uuid_proof("ssrf-c")
    md = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    inner = {md: "huntress-reader\n", md + "huntress-reader": json.dumps({"Code": "Success", "Token": p})}
    site = HSite(ssrf_site(inner, param="webhook", path="/hooks/test"))
    ans, secs = hunt(site)
    record("ssrf-c metadata hop", site, secs, ans)
    check(f"A (c) the metadata listing's role, second hop: the proof ({len(site.hits)} GETs, {secs:.2f} s)",
          ans == p and md + "huntress-reader" in inner_sent(site, "webhook"), (ans, inner_sent(site, "webhook")))

    # (d) an internal root's JSON route list, on a parameter named only by its http:// value
    p = uuid_proof("ssrf-d")
    inner = {"http://inventory/health": "ok", "http://inventory/": json.dumps({"service": "inventory", "routes": [
        "/health", "/v1/proof"]}), "http://inventory/v1/proof": json.dumps({"evidence": p})}
    site = HSite(ssrf_site(inner, param="loc", offered="http://inventory/health", path="/check"))
    ans, secs = hunt(site)
    record("ssrf-d json hop", site, secs, ans)
    sent = inner_sent(site, "loc")
    check(f"A (d) `loc=http://inventory/health`: root -> JSON routes -> /v1/proof ({len(site.hits)} GETs, {secs:.2f} s)",
          ans == p and sent[0] == "http://inventory/health", (ans, sent))

    # decoy: the baseline (the offered internal value) already shows the proof
    inner = {"http://inventory/health": json.dumps({"ok": p}), "http://inventory/": json.dumps({"routes": ["/v1/proof"]}),
             "http://inventory/v1/proof": json.dumps({"evidence": p})}
    site = HSite(ssrf_site(inner, param="loc", offered="http://inventory/health", path="/check"))
    ans, _s = hunt(site)
    check("A decoy: the baseline already shows the proof: None", ans is None, ans)
    # decoy: two proofs through the inner network
    q = uuid_proof("ssrf-decoy")
    site = HSite(ssrf_site({"http://127.0.0.1/": f"debug {q}"}, fs={"/run/huntress/objective.txt": p}))
    ans, _s = hunt(site)
    check("A decoy: two proofs through the inner network (loopback root and objective.txt): None", ans is None, ans)
    # a site with no SSRF parameter sends no inner URL at all
    site = HSite(T.site_sqli(uuid_proof("ssrf-none")))
    hunt(site)
    check("A no SSRF parameter: no URL-valued request", not any("%3A%2F%2F" in r or "://" in r for r in raws(site)),
          raws(site)[-5:])


# ---------------------------------------------------------------------------------------------------------
#  B. headers and cookies
# ---------------------------------------------------------------------------------------------------------
def hget(h, name):
    """A request header, case-insensitively (urllib sends X-Original-Url, X-Real-Ip)."""
    return next((v for k, v in (h or {}).items() if k.lower() == name.lower()), None)


def denied_site(proof, allow, root_cookie=None, control_shows=False):
    """/admin answers 403 unless allow(headers) (or, with control_shows, whenever a Cookie header is sent)."""
    def admin(q, h):
        if allow(h) or (control_shows and hget(h, "Cookie")):
            return page("Admin", f"<pre>{proof}</pre>")
        return 403, "text/html", "<p>staff only</p>"

    def root(q, h):
        xo = hget(h, "X-Original-URL")
        if xo == "/admin" and allow({"X-Original-URL": xo}):
            return page("Admin", f"<pre>{proof}</pre>")
        hd = {"Set-Cookie": root_cookie} if root_cookie else {}
        return 200, "text/html", T.HTML.format(t="Ops", b="<a href='/admin'>Staff only</a>"), hd
    return {"/": root, "/admin": admin}


def cookie_val(h, name):
    for part in (hget(h, "Cookie") or "").split(";"):
        k, _, v = part.strip().partition("=")
        if k == name:
            return v
    return None


def test_access():
    p = uuid_proof("xff")
    site = HSite(denied_site(p, lambda h: hget(h, "X-Forwarded-For") == "127.0.0.1"))
    ans, secs = hunt(site)
    record("header xff", site, secs, ans)
    check(f"B X-Forwarded-For: 127.0.0.1 on the 403 path: the proof ({len(site.hits)} GETs, {secs:.2f} s)", ans == p, ans)
    p = uuid_proof("xou")
    site = HSite(denied_site(p, lambda h: hget(h, "X-Original-URL") == "/admin"))
    ans, _s = hunt(site)
    check("B X-Original-URL: /admin on '/': the proof", ans == p, ans)

    p = uuid_proof("role")
    site = HSite(denied_site(p, lambda h: cookie_val(h, "role") == "admin", root_cookie="role=analyst; Path=/"))
    ans, secs = hunt(site)
    record("cookie role", site, secs, ans)
    vals = [cookie_val(h[3], "role") for h in site.hits if len(h) > 3 and h[2] == "/admin"]
    check(f"B a role cookie analyst -> admin: the proof ({len(site.hits)} GETs, {secs:.2f} s); the original sent too",
          ans == p and "analyst" in vals and "admin" in vals, (ans, vals))

    for url in (False, True):
        p = uuid_proof(f"b64-{url}")
        claims = {"user": "jules", "role": "viewer", "exp": 4102444800}
        raw = json.dumps(claims, separators=(",", ":")).encode()
        val = (base64.urlsafe_b64encode(raw).decode().rstrip("=") if url else base64.b64encode(raw).decode())

        def allow(h, url=url):
            v = cookie_val(h, "session")
            if not v:
                return False
            try:
                v = urllib.parse.unquote(v)
                d = json.loads((base64.urlsafe_b64decode if url else base64.b64decode)(v + "=" * (-len(v) % 4)))
                return d.get("role") == "admin" and d.get("user") == "jules"
            except Exception:
                return False
        site = HSite(denied_site(p, allow, root_cookie=f"session={val}; Path=/"))
        ans, secs = hunt(site)
        record(f"cookie b64 json{' urlsafe' if url else ''}", site, secs, ans)
        check(f"B a base64{' (URL-safe)' if url else ''} JSON cookie raised with jwt_raise: the proof "
              f"({len(site.hits)} GETs, {secs:.2f} s)", ans == p, ans)

    # decoy: the original cookie (the control) already opens it
    p = uuid_proof("ctl")
    site = HSite(denied_site(p, lambda h: False, root_cookie="role=analyst; Path=/", control_shows=True))
    ans, _s = hunt(site)
    check("B decoy: the original cookie replayed as the control shows the proof: None", ans is None, ans)
    check("B GET only, no Authorization header on the header/cookie fakes", only_get(site) and no_auth(site))


# ---------------------------------------------------------------------------------------------------------
#  C. SSTI config and env; /proc/self/environ through LFI
# ---------------------------------------------------------------------------------------------------------
def jinja_cfg(config=None, environ=None, files=None):
    """/greet?name=: the curly syntax emulated; {{config}}, {{config.items()}}, cycler...os.environ, open()."""
    files = files or {}

    def greet(q):
        v = q.get("name", "guest")

        def sub(m):
            e = m.group(1).strip()
            mm = re.fullmatch(r"(\d+)\s*\*\s*(\d+)", e)
            if mm:
                return str(int(mm.group(1)) * int(mm.group(2)))
            if e in ("config", "config.items()") and config is not None:
                return "&lt;Config " + repr(config).replace("<", "") + "&gt;"
            if e == "cycler.__init__.__globals__.os.environ" and environ is not None:
                return "environ(" + repr(environ) + ")"
            mm = re.fullmatch(r"(?:lipsum\.__globals__\['__builtins__'\]\['open'\]|"
                              r"cycler\.__init__\.__globals__\.__builtins__\.open)\('([^']+)'\)\.read\(\)", e)
            if mm:
                return files.get(mm.group(1), "")
            return ""
        return page("Greeter", f"<p>Hello {re.sub(r'{{(.*?)}}', sub, v)}!</p>")
    return {"/": page("Greeter", "<a href='/greet?name=guest'>Say hello</a>"), "/greet": greet}


def node_env(environ):
    """/hi?who=: ${a*b} and ${JSON.stringify(process.env)} emulated."""
    def hi(q):
        v = q.get("who", "")

        def sub(m):
            e = m.group(1).strip()
            mm = re.fullmatch(r"(\d+)\s*\*\s*(\d+)", e)
            if mm:
                return str(int(mm.group(1)) * int(mm.group(2)))
            if e == "JSON.stringify(process.env)":
                return json.dumps(environ)
            if e == "process.env":
                return "[object Object]"
            return ""
        return page("Hi", f"<p>Hi {re.sub(r'[$][{](.*?)[}]', sub, v)}</p>")
    return {"/": page("Hi", "<a href='/hi?who=ann'>hi</a>"), "/hi": hi}


def test_ssti_env():
    p = uuid_proof("cfg")
    site = HSite(jinja_cfg(config={"SECRET_KEY": "dev", "OBJECTIVE": p}))
    ans, secs = hunt(site)
    record("ssti config", site, secs, ans)
    check(f"C {{{{config}}}} behind a confirmed curly syntax: the proof ({len(site.hits)} GETs, {secs:.2f} s)",
          ans == p, ans)
    p = uuid_proof("env")
    site = HSite(jinja_cfg(environ={"PATH": "/usr/bin", "CTF_PROOF": p}))
    ans, _s = hunt(site)
    check("C cycler.__init__.__globals__.os.environ: the proof", ans == p, ans)
    p = uuid_proof("node")
    site = HSite(node_env({"NODE_ENV": "production", "PROOF": p}))
    ans, _s = hunt(site)
    check("C Node ${JSON.stringify(process.env)}: the proof", ans == p, ans)
    q = uuid_proof("cfg-decoy")
    site = HSite(jinja_cfg(config={"OBJECTIVE": p, "EXAMPLE": q}))
    ans, _s = hunt(site)
    check("C decoy: a config with two proofs: None", ans is None, ans)
    # a file read answers in wave 6: no config/env payload goes out, so an env decoy cannot cost the answer
    site = HSite(jinja_cfg(config={"X": q}, environ={"Y": q}, files={"/run/huntress/objective.txt": p}))
    ans, _s = hunt(site)
    sent = [urllib.parse.unquote_plus(r) for r in raws(site)]
    check("C objective.txt read in wave 6: the proof, and no config/environ payload was sent",
          ans == p and not any("config" in s or "environ" in s for s in sent), (ans, [s for s in sent if "{{" in s][-4:]))
    # /proc/self/environ through the LFI reader (wave 6b), objective.txt absent
    p = uuid_proof("lfi-env")
    fs = T.site_lfi(uuid_proof("unused"), reader="/reader.php")
    rd = fs["/reader.php"]

    def reader(q):
        st, ct, body = rd(q)
        body = body.replace(uuid_proof("unused") + "\n", "")
        if os.path.normpath("/var/www/html/pages/" + q.get("doc", "")) == "/proc/self/environ":
            body += f"PATH=/usr/bin\x00HUNTRESS_PROOF={p}\x00"
        return st, ct, body
    fs["/reader.php"] = reader
    site = HSite(fs)
    logd = R4.SCRATCH / "fp-lfi-env" / "web_l1"
    ans, secs = hunt(site, log_dir=str(logd))
    record("lfi environ", site, secs, ans)
    line = (logd / "proof_hunt.jsonl").read_text().splitlines()[-1]
    marks = PROOF_HUNT_FP_MARKERS
    check(f"C /proc/self/environ through the LFI reader after objective.txt found nothing: the proof "
          f"({len(site.hits)} GETs, {secs:.2f} s); where wave6b, the marker matches",
          ans == p and json.loads(line).get("where") == "wave6b" and any(re.search(m, line) for m in marks),
          (ans, line[:300]))


# ---------------------------------------------------------------------------------------------------------
#  D. unlinked paths
# ---------------------------------------------------------------------------------------------------------
def plain_site(extra=None, root_body="<p>Nothing to see.</p>"):
    r = {"/": page("Quiet", root_body)}
    r.update(extra or {})
    return r


def test_unlinked():
    p = uuid_proof("route")
    site = HSite(plain_site({"/internal/objective": js({"objective": p})}))
    ans, secs = hunt(site, prompt="The ops note says /internal/objective was never meant to be public.")
    record("prompt route", site, secs, ans)
    first = [i for i, r in enumerate(raws(site)) if r == "/internal/objective"]
    check(f"D the prompt's route /internal/objective: the proof in wave 2 ({len(site.hits)} GETs, {secs:.2f} s)",
          ans == p and first and first[0] < 8, (ans, raws(site)[:10]))
    ans, _s = hunt(HSite(plain_site({"/internal/objective": js({"objective": p})})))
    check("D the same target with no prompt: None (nobody names the route)", ans is None, ans)
    site = HSite(plain_site({"/internal/objective": js({"objective": p})},
                            root_body="<a href='/internal/objective'>objective</a>"))
    ans, _s = hunt(site, prompt="The ops note says /internal/objective was never meant to be public.")
    check("D decoy: the landing page links the prompt's route (a plain page): None", ans is None, ans)
    site = HSite(plain_site({"/internal/objective": js({"objective": p})}))
    hunt(site, prompt="Never call /admin/reset-all; the route is /internal/objective.")
    check("D a destructive prompt route is never requested", not any("reset" in r for r in raws(site)), raws(site))

    p = uuid_proof("git")
    logs = (f"0000000000000000000000000000000000000000 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b dev <dev@ops> "
            f"1760000000 +0000\tcommit (initial): seed {p}\n")
    site = HSite(plain_site({"/.git/HEAD": (200, "text/plain", "ref: refs/heads/main\n"),
                             "/.git/logs/HEAD": (200, "text/plain", logs)}))
    ans, secs = hunt(site)
    record(".git/logs/HEAD", site, secs, ans)
    check(f"D /.git/logs/HEAD: the proof ({len(site.hits)} GETs, {secs:.2f} s)", ans == p, ans)
    p = uuid_proof("env-file")
    site = HSite(plain_site({"/.env": (200, "text/plain", f"APP_ENV=prod\nOBJECTIVE={p}\n")}))
    ans, secs = hunt(site)
    record(".env", site, secs, ans)
    check(f"D /.env: the proof ({len(site.hits)} GETs, {secs:.2f} s)", ans == p, ans)
    q = uuid_proof("env-decoy")
    site = HSite(plain_site({"/.env": (200, "text/plain", f"OBJECTIVE={p}\n"), "/config.json": js({"sample": q})}))
    ans, _s = hunt(site)
    check("D decoy: /.env and /config.json hold two proofs: None", ans is None, ans)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("site/settings.py", "DEBUG = False\n" * 50 + f"OBJECTIVE = '{p}'\n")
    site = HSite(plain_site({"/backup.zip": (200, "application/zip", buf.getvalue())}))
    ans, secs = hunt(site)
    record("backup.zip", site, secs, ans)
    check(f"D /backup.zip (a deflated member): the proof ({len(site.hits)} GETs, {secs:.2f} s)", ans == p, ans)

    done = HSite({}, latency=0.0)
    done.default = lambda q: js({"state": "completed"}, 410)
    ans, secs = hunt(done, prompt="The route is /internal/objective.")
    check(f"D a finished target (410 everywhere) with a prompt route: None, {len(done.hits)} GETs (no guessed path)",
          ans is None and len(done.hits) <= 6 and "/internal/objective" not in raws(done) and "/.env" not in raws(done),
          raws(done))


# ---------------------------------------------------------------------------------------------------------
#  E. helpers
# ---------------------------------------------------------------------------------------------------------
def test_helpers():
    ok = ["http://127.0.0.1/", "http://localhost:8080/x", "http://10.1.2.3/a", "http://172.20.0.5/",
          "http://192.168.1.10/", "http://169.254.169.254/latest/meta-data/", "http://inventory/v1/proof",
          "file:///run/huntress/objective.txt", "http://[::1]/", "https://admin-svc:8443/",
          "http://169.254.1.1/", "http://localhost./"]
    bad = ["http://example.com/", "https://web-a.2026.huntress.ctf.games/", "http://2026.huntress.ctf.games/",
           "http://8.8.8.8/", "http://172.32.0.1/", "http://10.0.0.1/admin/delete",
           "http://10.0.0.1/a/../b", "file://evil.example/etc/passwd", "gopher://127.0.0.1/", "ftp://10.0.0.1/",
           "http://user@10.0.0.1/", "http://127.0.0.1.nip.io/", "http://10.0.0.1/?action=reset",
           "file:///opt/app/reset.sh", "http://inventory-/"]
    check("E inner_ok: loopback, RFC1918/link-local, metadata, localhost, single-label, file:// only",
          all(PH.inner_ok(u) for u in ok) and not any(PH.inner_ok(u) for u in bad),
          ([u for u in ok if not PH.inner_ok(u)], [u for u in bad if PH.inner_ok(u)]))
    check("E inner_ok: the FHS name `run` in a file path is not a destructive word",
          PH.inner_ok("file:///var/run/huntress/proof"))
    raw = base64.b64encode(json.dumps({"user": "a", "role": "user"}, separators=(",", ":")).encode()).decode()
    got = PH.cookie_raises(raw)
    dec = json.loads(base64.b64decode(got[0])) if got else {}
    check("E cookie_raises: role words, b64 JSON raised, a JWT and plain text untouched",
          PH.cookie_raises("analyst") == ["admin"] and PH.cookie_raises("Guest") == ["Admin"]
          and dec.get("role") == "admin" and dec.get("user") == "a"
          and PH.cookie_raises("eyJhbGciOiJub25lIn0.eyJhIjoxfQ.") == [] and PH.cookie_raises("hello") == []
          and PH.cookie_raises("abcdef0123456789") == [], (got, dec))
    keep, refused = PH.prompt_routes("Use /internal/objective and /api/v2/flag; read /run/huntress/objective.txt; "
                                     "never /admin/delete-user; see http://10.0.0.1/x and and/or 24/7.")
    check("E prompt_routes: no filesystem path, no URL part, a destructive one refused",
          keep == ["/internal/objective", "/api/v2/flag"] and refused == ["/admin/delete-user"], (keep, refused))
    check("E DEFAULT_FILES ends with /proc/self/environ", PH.DEFAULT_FILES[-1] == "/proc/self/environ")


def timings():
    print("timing  case                     GETs  seconds  (150 ms a request)")
    for name, n, secs, res in TIMES:
        print(f"timing  {name:<24} {n:>4}  {secs:7.2f}  {res}")


def main():
    lat = 0.15 if os.environ.get("WEB_TIMING") else 0.0
    orig_init = HSite.__init__

    def init(self, routes, latency=lat, default=None):
        orig_init(self, routes, latency=latency, default=default)
    HSite.__init__ = init
    try:
        test_helpers()
        test_ssrf()
        test_access()
        test_ssti_env()
        test_unlinked()
        if os.environ.get("WEB_TIMING"):
            timings()
    finally:
        if not os.environ.get("TEST_KEEP"):
            shutil.rmtree(R4.SCRATCH, ignore_errors=True)
            shutil.rmtree(T.SCRATCH, ignore_errors=True)
    print(f"RESULT {'FAIL' if FAILS else 'PASS'} ({len(FAILS)} failed)")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
