#!/usr/bin/env python3
"""wave3/web-recon (tickets #5, #6, #7): the SAFE web-recon detectors, offline fakes only.

  .venv/bin/python tests/test_wave3_web_recon.py        (TEST_KEEP=1 keeps the scratch folder)

No Game Master request and no live target. The one network use is a local http.server on 127.0.0.1
that serves bytes we built, to drive the GET-only .git/.DS_Store/.svn reconstruction of ticket #6.

It proves the wave3/web-recon contract for each detector:
  - #5 js_recon: a JS bundle with endpoints/params/source-map/config -> recon LEADS; a planted
    secret/flag is a LEAD under `secrets`, never a plain lead field, and the top-level `flag` is None.
  - #7 sourcemap: a .map -> reconstructed source names + content, with routes/params surfaced; a
    malformed map yields empty leads and no false flag.
  - #6 vcs_exposure: a fake .git (loose objects) -> commit table + files via repo_supply_chain, both
    offline and over a GET-only local server (asserts no POST/HEAD ever left); a .DS_Store -> hidden
    names; an .svn wc.db -> NODES + a pristine secret LEAD. The top-level `flag` is always None.
  - no false flag: benign input yields no secret lead and flag None everywhere.
"""
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "web"))
import js_recon            # noqa: E402
import sourcemap           # noqa: E402
import vcs_exposure as vx  # noqa: E402

SCRATCH = Path(tempfile.mkdtemp(prefix="wave3-web-recon-"))
FAILS = []


def check(name, ok, detail=""):
    if not ok:
        FAILS.append(name)
    print(("ok   " if ok else "FAIL ") + name + ("" if ok or not detail else f"  [{str(detail)[:600]}]"), flush=True)


# ---- git object helpers ----------------------------------------------------------------------------

def gobj(typ, body):
    raw = (f"{typ} {len(body)}").encode() + b"\x00" + body
    return hashlib.sha1(raw).hexdigest(), zlib.compress(raw)


def build_git_tree():
    """A tiny but real git directory: one commit of one blob (`secret.txt`) that carries a flag and a
    password. Returns ({git-dir-relative path: bytes}, expected file name, expected flag)."""
    flag = "flag{git_dumper_lead}"
    blob = (f"DB_PASSWORD = 'hunter2'\n{flag}\n").encode()
    bo, bz = gobj("blob", blob)
    tree = b"100644 secret.txt\x00" + bytes.fromhex(bo)
    to, tz = gobj("tree", tree)
    commit = (f"tree {to}\nauthor Dev <dev@x> 1700000000 +0000\n"
              f"committer Dev <dev@x> 1700000000 +0000\n\nadd secret\n").encode()
    co, cz = gobj("commit", commit)
    tree_files = {
        "HEAD": b"ref: refs/heads/master\n",
        "refs/heads/master": (co + "\n").encode(),
        f"objects/{bo[:2]}/{bo[2:]}": bz,
        f"objects/{to[:2]}/{to[2:]}": tz,
        f"objects/{co[:2]}/{co[2:]}": cz,
    }
    return tree_files, "secret.txt", flag


def build_svn():
    """A wc.db (one NODES row) + its pristine blob (carrying an AWS key). Returns (wcdb, pristine_path,
    pristine_bytes, node_path)."""
    body = b"host=db.internal\nAKIAIOSFODNN7EXAMPLE\n"
    sha = hashlib.sha1(body).hexdigest()
    fd, name = tempfile.mkstemp(suffix=".db", dir=SCRATCH)
    os.close(fd)
    con = sqlite3.connect(name)
    con.execute("CREATE TABLE NODES (local_relpath TEXT, kind TEXT, revision INTEGER, changed_author TEXT, "
                "changed_date INTEGER, checksum TEXT, presence TEXT, op_depth INTEGER)")
    con.execute("INSERT INTO NODES VALUES (?,?,?,?,?,?,?,?)",
                ("config/prod.ini", "file", 7, "dev", 0, "$sha1$" + sha, "normal", 0))
    con.commit(); con.close()
    wcdb = Path(name).read_bytes()
    return wcdb, f"/.svn/pristine/{sha[:2]}/{sha}.svn-base", body, "config/prod.ini"


# ---- #5 js_recon -----------------------------------------------------------------------------------

def test_js_recon():
    js = b"""
    const base = "/api/v1/users?role=admin&id=1";
    fetch("/api/orders");
    axios.get("https://backend.internal/api/secret");
    const baseURL = "https://cdn.example.com/app";
    new URLSearchParams().append("token_name");
    const AWS = "AKIAIOSFODNN7EXAMPLE";  // secret-scan: allow
    const cfg = { apiKey: "flag{js_recon_lead}" };
    var pw = "password=sup3rsecret!";
    //# sourceMappingURL=app.js.map
    """
    r = js_recon.scan({"app.js": js})
    check("#5 js_recon flag is None", r["flag"] is None, r["flag"])
    check("#5 api path lead", any(p.startswith("/api/v1/users") for p in r["api_paths"]), r["api_paths"])
    check("#5 absolute url lead", "https://backend.internal/api/secret" in r["urls"], r["urls"])
    check("#5 params from query + setter", {"role", "id", "token_name"} <= set(r["params"]), r["params"])
    check("#5 sourcemap url", "app.js.map" in r["sourcemap_urls"], r["sourcemap_urls"])
    check("#5 config hint baseurl", r["config_hints"].get("baseurl") == "https://cdn.example.com/app", r["config_hints"])
    kinds = {s["kind"] for s in r["secrets"]}
    check("#5 flag is a LEAD not an answer", "flag" in kinds and r["flag"] is None, kinds)
    check("#5 aws key is a LEAD", "aws_access_key_id" in kinds, kinds)
    plain = r["endpoints"] + r["routes"] + r["params"] + r["api_paths"] + r["urls"]
    check("#5 secret never in a plain lead field", "flag{js_recon_lead}" not in plain
          and "AKIAIOSFODNN7EXAMPLE" not in plain, plain)  # secret-scan: allow
    check("#5 has_secret_leads set", r["has_secret_leads"] is True)


def test_js_recon_no_false_flag():
    benign = b'const x = "/home"; fetch("/api/ping"); const n = 2 + 2;'
    r = js_recon.scan({"clean.js": benign})
    check("#5 benign: flag None", r["flag"] is None)
    check("#5 benign: no secret leads", r["secrets"] == [] and r["has_secret_leads"] is False, r["secrets"])
    check("#5 benign: still finds endpoint", "/api/ping" in r["api_paths"], r["api_paths"])


# ---- #7 sourcemap ----------------------------------------------------------------------------------

def test_sourcemap():
    mp = json.dumps({
        "version": 3, "file": "app.js", "sourceRoot": "",
        "sources": ["webpack:///src/routes/admin.js", "webpack:///src/api.js", "webpack:///src/vendor.js"],
        "sourcesContent": ["const r = '/admin/panel'; fetch('/api/admin?x=1');",
                           "export const KEY = 'flag{from_sourcemap}';",
                           None],
        "names": [], "mappings": "AAAA",
    }).encode()
    s = sourcemap.reconstruct(mp, "app.js.map")
    check("#7 flag is None", s["flag"] is None, s["flag"])
    check("#7 names reconstructed (scheme+authority stripped, path kept)",
          {"src/routes/admin.js", "src/api.js", "src/vendor.js"} <= set(s["source_names"]), s["source_names"])
    check("#7 content reconstructed", any(x["name"] == "src/api.js" and x["content"] for x in s["sources"]), None)
    check("#7 missing content is None, not fabricated",
          any(x["name"] == "src/vendor.js" and x["content"] is None for x in s["sources"]), None)
    check("#7 routes/api surfaced from sources", "/api/admin?x=1" in s["api_paths"], s["api_paths"])
    check("#7 param surfaced", "x" in s["params"], s["params"])
    kinds = {x["kind"] for x in s["secrets"]}
    check("#7 flag in source is a LEAD only", "flag" in kinds and s["flag"] is None, kinds)
    check("#7 flag value not a plain field",
          "flag{from_sourcemap}" not in (s["routes"] + s["api_paths"] + s["params"] + s["source_names"]))


def test_sourcemap_malformed():
    for bad in (b"not json at all", b'{"no":"sources"}', b"[]", b"",
                b'{"version":3,"sources":[],"sources":["evil.js"],"sourcesContent":[]}',
                b'{"version":3,"sourceRoot":"","source-root":"/evil",'
                b'"sources":[],"sourcesContent":[]}'):
        s = sourcemap.reconstruct(bad, "x.map")
        if not (s["flag"] is None and s["sources"] == [] and s["secrets"] == []):
            check("#7 malformed map -> empty, no false flag", False, (bad[:20], s))
            return
    check("#7 malformed map -> empty, no false flag", True)


# ---- #6 vcs_exposure (offline) ---------------------------------------------------------------------

def test_git_offline():
    tree, want_file, want_flag = build_git_tree()
    r = vx.reconstruct(tree)
    check("#6 git offline flag None", r["flag"] is None, r["flag"])
    check("#6 git offline one commit", bool(r["repos"]) and r["repos"][0]["commit_count"] == 1,
          r["repos"][0]["commit_count"] if r["repos"] else None)
    check("#6 git offline file at head", r["repos"] and want_file in r["repos"][0]["files_at_head"],
          r["repos"][0]["files_at_head"] if r["repos"] else None)
    vals = [s["value"] for s in r["secrets"]]
    check("#6 git offline flag is a LEAD", want_flag in vals and r["flag"] is None, vals)
    check("#6 git offline password lead", "hunter2" in vals, vals)


def test_vcs_reconstruct_no_false_flag():
    for tree in ({}, {"HEAD": b"garbage"}, {"objects/ab/cd": b"not zlib"}):
        r = vx.reconstruct(tree)
        if r["flag"] is not None or r["secrets"]:
            check("#6 empty/garbage tree -> no repo, no false flag", False, (list(tree)[:2], r))
            return
    check("#6 empty/garbage tree -> no repo, no false flag", True)


# ---- #6 vcs_exposure (live, GET-only) --------------------------------------------------------------

def _server(routes, methods):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, m):
            methods.append(m)
            body = routes.get(self.path)
            if body is None:
                self.send_response(404)
                self.end_headers()
                if m == "GET":
                    self.wfile.write(b"not found")
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if m == "GET":
                self.wfile.write(body)

        def do_GET(self):
            self._send("GET")

        def do_POST(self):
            self._send("POST")

        def do_HEAD(self):
            self._send("HEAD")

        def do_PUT(self):
            self._send("PUT")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/"


def test_live_get_only():
    tree, want_file, want_flag = build_git_tree()
    dsfix = REPO / "tests" / "fixtures" / "tk_nix_host" / "DS_Store"
    ds_bytes = dsfix.read_bytes() if dsfix.exists() else b""
    wcdb, pristine_path, _pbytes, node_path = build_svn()

    routes = {"/.DS_Store": ds_bytes, "/.svn/wc.db": wcdb, pristine_path: _pbytes}
    for k, v in tree.items():
        routes["/.git/" + k] = v
    methods = []
    srv, url = _server(routes, methods)
    try:
        d = vx.dump(url, max_requests=300)
        check("#6 live git flag None", d["flag"] is None, d["flag"])
        rep = d["repos"][0] if d["repos"] else {}
        check("#6 live git one commit (GET-only reconstruct)", rep.get("commit_count") == 1, rep.get("commit_count"))
        check("#6 live git file at head", want_file in rep.get("files_at_head", []), rep.get("files_at_head"))
        check("#6 live git flag is a LEAD", want_flag in [s["value"] for s in d["secrets"]], d["secrets"])

        ds = vx.ds_store(url)
        check("#6 live ds_store flag None", ds["flag"] is None, ds["flag"])
        if ds_bytes:
            check("#6 live ds_store names found", bool(ds["names"]), ds["names"])
        else:
            check("#6 live ds_store (no fixture) -> empty, no crash", ds["names"] == [])

        sv = vx.svn(url)
        check("#6 live svn flag None", sv["flag"] is None, sv["flag"])
        check("#6 live svn node path", bool(sv["nodes"]) and sv["nodes"][0]["path"] == node_path, sv["nodes"])
        check("#6 live svn pristine secret LEAD", "aws_access_key_id" in {s["kind"] for s in sv["secrets"]}, sv["secrets"])

        check("#6 GET ONLY: no POST/HEAD/PUT ever sent", set(methods) == {"GET"}, sorted(set(methods)))
    finally:
        srv.shutdown()


def test_ds_store_no_false_flag():
    # a path that is not a DS_Store (404 / garbage) -> empty names, flag None, no crash
    routes = {"/.DS_Store": b"this is not a Bud1 store"}
    methods = []
    srv, url = _server(routes, methods)
    try:
        ds = vx.ds_store(url)
        check("#6 non-DS_Store -> empty names, flag None", ds["flag"] is None and ds["names"] == [], ds)
        check("#6 ds_store GET-only", set(methods) <= {"GET"}, sorted(set(methods)))
    finally:
        srv.shutdown()


def main():
    test_js_recon()
    test_js_recon_no_false_flag()
    test_sourcemap()
    test_sourcemap_malformed()
    test_git_offline()
    test_vcs_reconstruct_no_false_flag()
    test_live_get_only()
    test_ds_store_no_false_flag()
    print(f"\n{'FAIL' if FAILS else 'PASS'} test_wave3_web_recon: {len(FAILS)} failed")
    for f in FAILS:
        print("  -", f)
    if not (FAILS or os.environ.get("TEST_KEEP")):
        shutil.rmtree(SCRATCH, ignore_errors=True)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
