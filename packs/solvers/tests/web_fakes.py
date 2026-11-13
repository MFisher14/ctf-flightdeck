"""Loopback fake web targets shared by the proof_hunt tests (tests/test_day21r4_383.py and, through it,
tests/test_day21fp_web-proof-hunt.py).

Carried from the Huntress round-1 test tests/test_day21_web_solver.py, which was archived with
tools/web_open.py: only its fakes (Site/serve/hunt, page/js, uuid_proof and the five site shapes) are kept
here, none of its web_open contract checks and none of its saved-evidence replays. 127.0.0.1 only.
"""
import importlib.util
import json
import os
import re
import sqlite3
import tempfile
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRATCH = Path(tempfile.mkdtemp(prefix="web-fakes-"))

def load_solver():
    """Exactly as tools/web_open.py loads it: by file name."""
    spec = importlib.util.spec_from_file_location("proof_hunt", REPO / "solvers" / "web" / "proof_hunt.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


PH = load_solver()


def uuid_proof(seed):
    import hashlib
    h = hashlib.sha256(seed.encode()).hexdigest()[:32]
    h = h[:12] + "4" + h[13:16] + "9" + h[17:]
    return "proof_" + h


# ---------------------------------------------------------------------------------------------------------
#  a fake target
# ---------------------------------------------------------------------------------------------------------
class Site:
    """routes: {path: handler(query_dict) -> (status, ctype, body[, headers])}; `default` for the rest."""

    def __init__(self, routes, latency=0.0, default=None):
        self.routes = routes
        self.latency = latency
        self.default = default
        self.hits = []          # (time, method, raw path)
        self.lock = threading.Lock()

    def handle(self, method, raw):
        with self.lock:
            self.hits.append((time.time(), method, raw))
        if self.latency:
            time.sleep(self.latency)
        if method != "GET":
            return 405, "text/plain", "no", {}
        path, _, q = raw.partition("?")
        query = dict(urllib.parse.parse_qsl(q, keep_blank_values=True))
        fn = self.routes.get(path) or self.default
        if fn is None:
            return 404, "text/html", "<p>not found</p>", {}
        r = fn(query) if callable(fn) else fn
        return (tuple(r) + ({},))[:4]


def serve(site):
    class H(BaseHTTPRequestHandler):
        def _go(self):
            st, ctype, body, hdrs = site.handle(self.command, self.path)
            data = body.encode() if isinstance(body, str) else body
            self.send_response(st)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            for k, v in (hdrs or {}).items():
                self.send_header(k, v)
            self.end_headers()
            try:
                self.wfile.write(data)
            except Exception:
                pass

        do_GET = do_POST = do_PUT = do_DELETE = _go

        def do_HEAD(self):
            site.handle("HEAD", self.path)
            self.send_response(405)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/"


def hunt(sites, deadline_s=20.0, max_requests=400, log_dir=None, files_prompt=None):
    """Serve each site, run solve_targets on them all; returns (answers, seconds, urls)."""
    servers, targets = [], []
    for i, site in enumerate(sites, 1):
        srv, url = serve(site)
        servers.append(srv)
        targets.append({"answer_id": f"proof-{i}", "url": url, "index": i, "question": f"Recover the proof from Target {i}."})
    ctx = {"deadline": time.time() + deadline_s, "max_requests": max_requests, "log_dir": log_dir, "challenge": "t"}
    if files_prompt:
        ctx["prompt"] = files_prompt
    t0 = time.time()
    out = PH.solve_targets(targets, ctx)
    secs = time.time() - t0
    for s in servers:
        s.shutdown()
        s.server_close()
    return out, secs, [t["url"] for t in targets]


HTML = "<!doctype html><html><head><title>{t}</title><link rel='stylesheet' href='/assets/style.css'></head><body>{b}</body></html>"


def page(title, body):
    return 200, "text/html; charset=utf-8", HTML.format(t=title, b=body)


def js(obj, status=200):
    return status, "application/json", json.dumps(obj)


# --- the six shapes ---------------------------------------------------------------------------------------
def site_backup(proof, extra_bak=None, root_extra=""):
    d = "/vault-9c1e2/"
    files = {"customer-dump-77ab01.json.bak": {"environment": "production", "support_note": proof},
             "deploy-notes.txt": "Deployment completed.\n"}
    if extra_bak:
        files["older-copy-0001.json.bak"] = {"support_note": extra_bak}
    links = "".join(f"<div class='record'><a href='{d}{n}'>{n}</a></div>" for n in files)
    routes = {"/": page("Tiny Uptime", "<h1>Tiny Uptime</h1><!-- remember to review crawler policy -->" + root_extra),
              "/robots.txt": (200, "text/plain", f"User-agent: *\nDisallow: {d}\n"),
              d: page("Deployment archive", f"<h1>Directory index</h1>{links}")}
    for n, body in files.items():
        routes[d + n] = (200, "application/octet-stream", json.dumps(body, indent=2) if isinstance(body, dict) else body)
    return routes


def site_idor(proof, own_note="Confirm the sender."):
    briefs = {4217: {"owner": "Jules", "note": own_note}, 7625: {"owner": "Jules", "note": "Follow up."},
              17377: {"owner": "executive", "note": proof}}
    routes = {"/": page("Incident Picnic", "<div>Signed in as Jules</div>"
                        "<a href='/briefs/4217'>Open case</a><a href='/briefs/7625'>Open case</a>"
                        "<a class='button' href='/api/timeline'>Open activity feed</a>"),
              "/api/timeline": js({"current_user": "Jules", "events": [
                  {"case_id": 4217, "owner": "Jules", "visibility": "workspace"},
                  {"case_id": 17377, "owner": "executive", "visibility": "reference_only"},
                  {"case_id": 7625, "owner": "Jules", "visibility": "workspace"}]})}
    for i, b in briefs.items():
        routes[f"/briefs/{i}"] = page(f"Case {i}", f"<h1>Case <code>{i}</code></h1><pre id='record'>Loading /api/briefs/{i}...</pre>")
        routes[f"/api/briefs/{i}"] = js(dict(id=i, title="t", status="s", **b))
    return routes


def site_sqli(proof, path="/explore", plain_shows=False):
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("CREATE TABLE notes (id INTEGER, tag TEXT, title TEXT, body TEXT, restricted INTEGER)")
    db.executemany("INSERT INTO notes VALUES (?,?,?,?,?)", [
        (2438, "identity", "Identity field note", "Collect the smallest artifact first.", 0),
        (4547, "persistence", "Persistence field note", "Write down what would disprove it.", 0),
        (17472, "restricted", "Private escalation", proof, 0 if plain_shows else 1)])
    lock = threading.Lock()

    def search(q):
        term = q.get("q", "")
        sql = f"SELECT id, tag, title, body FROM notes WHERE restricted = 0 AND (title LIKE '%{term}%')"
        try:
            with lock:
                rows = db.execute(sql).fetchall()
        except sqlite3.Error as e:
            return 500, "text/html", f"<div class='alert'>query failed: {e}</div>"
        cards = "".join(f"<article><h3>{r[2]}</h3><p>{r[3]}</p><div class='meta'>Record {r[0]}</div></article>" for r in rows)
        return page("Results", f"<form class='inline'><input name='q' value='{term}'><button>Search</button></form>"
                               + (cards or "<div class='alert'>Nothing matched.</div>"))
    return {"/": page("Search Party", f"<form class='inline' action='{path}'><input name='q' placeholder='Search'>"
                                      "<button>Search</button></form>"),
            path: search}


def site_lfi(proof, reader="/notes.php"):
    fs = {"/var/www/html/pages/about.php": "<p>About the runbooks.</p>",
          "/var/www/html/pages/checklist.php": "<p>Checklist.</p>",
          "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
          "/run/huntress/objective.txt": proof + "\n"}

    def read(q):
        doc = q.get("doc", "about.php")
        full = "/var/www/html/pages/" + doc
        norm = os.path.normpath(full)
        body = fs.get(norm)
        if body is None:
            body = (f"<b>Warning</b>: include({full}): Failed to open stream: No such file or directory in "
                    f"/var/www/html{reader} on line 51")
        return page("Runbook Nook", f"<nav><a href='{reader}?doc=about.php'>About</a>"
                                    f"<a href='{reader}?doc=checklist.php'>Checklist</a></nav>"
                                    f"<article><span>Document viewer</span>{body}</article>")
    return {"/": (302, "text/html", "", {"Location": reader}), reader: read}


def site_route(proof, root_extra="", clue_route="/process-77aa11", route_body=None):
    return {"/": page("Django Dispatch", "<a class='button' href='/api/clues'>Open workspace notes</a>" + root_extra),
            "/api/clues": js({"framework": "Django", "feature_route": clue_route, "current_role": "analyst"}),
            clue_route: js(route_body or {"ok": True, "effect": "framework_authorization_bypassed", "evidence": proof})}


SHAPES = {"backup": site_backup, "idor": site_idor, "sqli": site_sqli, "lfi": site_lfi, "route": site_route}

