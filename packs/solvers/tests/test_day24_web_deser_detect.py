#!/usr/bin/env python3
"""Day-24 web look-ahead (ticket W-d detector half): the offline serialized-object recognizer.

    .venv/bin/python tests/test_day24_web_deser_detect.py

No Game Master request, no live target, no network at all. It proves the GET-safe offline-detector
contract of `solvers/web/deser_detect.py`:
  - each known serialized format (Java / PHP object injection / Python pickle / Ruby Marshal /
    .NET BinaryFormatter + ViewState / node-serialize / unsafe YAML / jsonpickle) is recognized from
    bytes already in hand, through the transport encodings (base64/base64url/url/hex/gzip);
  - a JWT is filed as an informational TOKEN, never as a serialized object (no false deser);
  - NEVER-WRONG: benign input (plain base64 JSON, a random token, a plain session cookie, a
    malformed blob) yields NO serialized finding, and the top-level `flag` is None everywhere;
  - NEVER-EXECUTE: a pickle whose reduce would run code is recognized WITHOUT being unpickled (a
    sentinel the payload would create is proven absent afterwards);
  - cookies and a saved response are mined into per-blob findings, GET-only / offline.
"""
import base64
import gzip
import os
import pickle
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "web"))
import deser_detect as dd  # noqa: E402

FAILS = []


def check(name, ok, detail=""):
    if not ok:
        FAILS.append(name)
    print(("ok   " if ok else "FAIL ") + name + ("" if ok or not detail else f"  [{str(detail)[:400]}]"), flush=True)


def fmts(findings):
    return {f["format"] for f in findings}


def one(findings, fmt):
    return next((f for f in findings if f["format"] == fmt), None)


# ---- specimens -------------------------------------------------------------------------------------

JAVA_RAW = b"\xac\xed\x00\x05sr\x00\x0bExploit.Foo\x00\x00\x00\x00\x00\x00\x00\x01"
PHP_OBJ = b'O:4:"User":2:{s:4:"name";s:3:"bob";s:7:"isAdmin";b:1;}'
PHP_ARR = b'a:2:{i:0;s:3:"foo";i:1;s:3:"bar";}'
RUBY = b"\x04\x08o:\x0bObject\x00"
DOTNET_BF = b"\x00\x01\x00\x00\x00\xff\xff\xff\xff\x01\x00\x00\x00\x00\x00\x00\x00System.Data"
VIEWSTATE = b"/wEPDwUKLTE2MjY5MzU0OWRk"           # ASP.NET __VIEWSTATE (binary-serialized head)
NODE = b'{"rce":"_$$ND_FUNC$$_function(){return 1}()"}'
YAML_UNSAFE = b"!!python/object/apply:os.system ['id']\n"
JSONPICKLE = b'{"py/object": "mod.Cls", "py/reduce": [null, null]}'
JWT = b"eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYm9iIn0.c2ln"


def run():
    sc = tempfile.mkdtemp(prefix="day24-deser-")

    # --- Java: raw, base64 (rO0AB...), and gzip+base64 all recognized, with the encoding chain -----
    f = dd.detect(JAVA_RAW, "raw")
    jr = one(f, "java_serialized_stream")
    check("java raw recognized", jr is not None and jr["outer_encoding"] == [] and jr["gated"], fmts(f))
    check("java raw high confidence + class hint",
          jr and jr["confidence"] == "high" and any("Exploit.Foo" in c for c in jr["class_hint"]), jr)

    b64 = base64.b64encode(JAVA_RAW)
    check("java base64 starts rO0AB", b64.startswith(b"rO0AB"), b64[:8])
    f = dd.detect(b64, "b64")
    jb = one(f, "java_serialized_stream")
    check("java via base64", jb is not None and jb["outer_encoding"] == ["base64"], f)

    gzb64 = base64.b64encode(gzip.compress(JAVA_RAW))
    f = dd.detect(gzb64, "gzb64")
    jg = one(f, "java_serialized_stream")
    check("java via base64+gzip", jg is not None and jg["outer_encoding"] == ["base64", "gzip"], jg and jg["outer_encoding"])

    # --- PHP object injection vs plain serialized array --------------------------------------------
    f = dd.detect(PHP_OBJ, "php")
    po = one(f, "php_object_injection")
    check("php object injection recognized", po is not None and po["confidence"] == "high"
          and po["class_hint"] == ["User"], f)
    f = dd.detect(PHP_ARR, "phparr")
    check("php array is serialized (not object injection)",
          one(f, "php_serialized") is not None and one(f, "php_object_injection") is None, fmts(f))

    # --- Python pickle: raw proto-4 and base64 -----------------------------------------------------
    pk = pickle.dumps({"a": [1, 2, 3]}, protocol=4)
    f = dd.detect(pk, "pk")
    pf = one(f, "python_pickle")
    check("pickle proto-4 recognized", pf is not None and pf["confidence"] == "high", fmts(f))
    f = dd.detect(base64.b64encode(pk), "pkb64")
    check("pickle via base64", one(f, "python_pickle") is not None, f)

    # --- Ruby Marshal (base64), .NET BinaryFormatter, ViewState ------------------------------------
    f = dd.detect(base64.b64encode(RUBY), "ruby")
    check("ruby marshal via base64", one(f, "ruby_marshal") is not None, f)
    f = dd.detect(DOTNET_BF, "bf")
    check("dotnet binaryformatter", one(f, "dotnet_binaryformatter") is not None, fmts(f))
    f = dd.detect(VIEWSTATE, "vs")
    vs = one(f, "aspnet_viewstate")
    check("aspnet viewstate (/wEP)", vs is not None and "binary-serialized" in vs["note"], f)

    # --- node-serialize, unsafe YAML, jsonpickle ---------------------------------------------------
    check("node-serialize marker", one(dd.detect(NODE, "n"), "node_serialize") is not None, "")
    check("unsafe yaml tag", one(dd.detect(YAML_UNSAFE, "y"), "unsafe_yaml") is not None, "")
    check("jsonpickle py/object", one(dd.detect(JSONPICKLE, "j"), "jsonpickle") is not None, "")

    # --- JWT is informational, NOT a serialized object (no false deser, not gated) -----------------
    f = dd.detect(JWT, "jwt")
    jw = one(f, "jwt")
    check("jwt recognized as token, not deser",
          jw is not None and jw["gated"] is False and not any(x["gated"] for x in f), f)

    # --- NEVER-WRONG controls: benign input -> no serialized finding, flag None --------------------
    benign = {
        "plain_json_b64": base64.b64encode(b'{"user":"bob","role":"user"}'),
        "random_token": b"3f9a1c2b4d5e6f7a8b9c0d1e2f3a4b5c",
        "session_cookie": b"abcdef0123456789abcdef0123456789",
        "short": b"hello",
        "malformed": b"\x00\x01\x02not-a-stream",
        "url_text": b"https://example.com/a/b?x=1",
    }
    out = dd.scan(benign)
    check("benign: no serialized surface", out["has_serialized"] is False, [l["format"] for l in out["leads"]])
    check("benign: flag is None", out["flag"] is None, out["flag"])
    check("benign: no leads", out["leads"] == [], out["leads"])

    # --- NEVER-EXECUTE: a pickle that would run code is recognized without being unpickled ---------
    sentinel = os.path.join(sc, "pwned")

    class _Boom:
        def __reduce__(self):
            # os.system is captured here only to BUILD the specimen bytes; detect() must never run it.
            return (os.system, (f"touch {sentinel}",))

    evil = pickle.dumps(_Boom())
    f = dd.detect(evil, "evil")
    ep = one(f, "python_pickle")
    check("evil pickle recognized as pickle", ep is not None, fmts(f))
    check("evil pickle shows REDUCE hint",
          ep is not None and any("REDUCE" in h for h in ep["class_hint"]), ep and ep["class_hint"])
    check("NEVER-EXECUTE: detect() did not unpickle (no sentinel)", not os.path.exists(sentinel), sentinel)

    # --- cookies: a serialized value inside a Cookie header ----------------------------------------
    hdr = b"Cookie: sid=abc123; profile=" + base64.b64encode(JAVA_RAW) + b"; theme=dark"
    out = dd.scan_cookies(hdr, "req")
    check("cookie scan finds the java profile cookie",
          out["has_serialized"] and any("profile" in l["source"] for l in out["leads"]), out["leads"])
    check("cookie scan: benign sid/theme not flagged",
          not any(("sid" in l["source"] or "theme" in l["source"]) for l in out["leads"]), out["leads"])

    # --- a saved HTTP response: Set-Cookie + a hidden __VIEWSTATE input -----------------------------
    resp = (b"HTTP/1.1 200 OK\r\n"
            b"Set-Cookie: auth=" + base64.b64encode(pickle.dumps([1, 2], protocol=4)) + b"; Path=/; HttpOnly\r\n"
            b"Content-Type: text/html\r\n\r\n"
            b'<form><input type="hidden" name="__VIEWSTATE" value="' + VIEWSTATE + b'"></form>')
    out = dd.from_response(resp, "page")
    got = fmts(out["findings"])
    check("response: pickle auth cookie + viewstate input",
          "python_pickle" in got and "aspnet_viewstate" in got, got)
    check("response: flag None", out["flag"] is None, out["flag"])

    # --- the top-level flag is None on every public entry point ------------------------------------
    check("flag None on scan/scan_cookies/from_response",
          dd.scan([JAVA_RAW])["flag"] is None and dd.scan_cookies(hdr)["flag"] is None
          and dd.from_response(resp)["flag"] is None, "")

    import shutil
    shutil.rmtree(sc, ignore_errors=True)


if __name__ == "__main__":
    run()
    print()
    if FAILS:
        print(f"FAILED {len(FAILS)}: {', '.join(FAILS)}")
        raise SystemExit(1)
    print("ALL OK")
