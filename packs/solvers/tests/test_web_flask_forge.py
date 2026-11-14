#!/usr/bin/env python3
"""Offline tests for the Flask/itsdangerous signed-session forge in solvers/toolkits/web.py (wave120).

No network and no token: the signing math is pure (flask_tools.py, row 206), and these exercise the
confirm-first gate web.py adds on top -- a round-trip, a forge with a modified claim, and the
never-wrong refusal (a wrong key returns None, never a bogus cookie). It also asserts, by grep, that
nothing in Layer 1 / proof_hunt / web_open auto-calls the new capability: it is agent-only.

  .venv/bin/python tests/test_web_flask_forge.py
"""
import os
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
os.environ["CTF_PLATFORM_URL"] = "http://127.0.0.1:9/"   # nothing here makes a request; make sure of it
os.environ.pop("CTF_TOKEN", None)
os.environ["CTF_TESTING"] = "1"
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
sys.path.insert(0, str(REPO / "solvers" / "common"))

import web            # noqa: E402  (the client the web agent drives)
import flask_tools as ft  # noqa: E402  (the established signer, used only to BUILD original cookies here)

FAILED = []
KEY = "s3cr3t-flask-key"          # a SECRET_KEY the agent would have recovered from /.env or /.git
WRONG = "not-the-key"
TS = 1700000000                   # a fixed, realistic timestamp so decode_cookie's regex round-trips


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:400]}]"))
    if not ok:
        FAILED.append(label)


# ------------------------------------------------------------------ parse (no key)

def test_parse_flask_session():
    cookie = ft.sign({"user": "guest", "admin": False}, KEY, timestamp=TS)
    claims = web.parse_flask_session(cookie)
    check("parse reads the claims without a key", claims == {"user": "guest", "admin": False}, claims)
    check("parse returns None for a non-Flask value", web.parse_flask_session("not-a-cookie") is None)
    check("parse returns None for a bare JWT-ish string", web.parse_flask_session("eyJ.eyJ.sig") is None)


# ------------------------------------------------------------------ confirm-first gate

def test_confirm_flask_key():
    cookie = ft.sign({"role": "user"}, KEY, timestamp=TS)
    check("confirm returns the digest under the right key", web.confirm_flask_key(cookie, KEY) == "sha1")
    check("confirm returns None under a wrong key", web.confirm_flask_key(cookie, WRONG) is None)
    c256 = ft.sign({"role": "user"}, KEY, digest="sha256", timestamp=TS)
    check("confirm auto-detects sha256", web.confirm_flask_key(c256, KEY) == "sha256")
    check("confirm honours an explicit wrong digest (None)", web.confirm_flask_key(c256, KEY, digest="sha1") is None)


# ------------------------------------------------------------------ round-trip: sign -> parse -> re-sign

def test_roundtrip_resign():
    claims = {"user": "guest", "admin": False, "n": 7}
    cookie = ft.sign(claims, KEY, timestamp=TS)
    # parse recovers the claims, and a re-sign (no changes) is a valid cookie for the SAME claims
    check("round-trip: parse recovers the claims", web.parse_flask_session(cookie) == claims, web.parse_flask_session(cookie))
    resigned = web.forge_flask_session(cookie, KEY)
    check("round-trip: re-sign returns a cookie", isinstance(resigned, str) and resigned, resigned)
    check("round-trip: the re-signed cookie verifies under the key", ft.verify(resigned, KEY) == claims, ft.verify(resigned, KEY))
    check("round-trip: the re-signed cookie carries the same claims", web.parse_flask_session(resigned) == claims)
    # pinning the timestamp reproduces the ORIGINAL cookie byte-for-byte (the signature is deterministic)
    pinned = ft.forge(cookie, KEY, timestamp=TS)
    check("round-trip: same key+claims+timestamp reproduce the cookie exactly", pinned == cookie, (pinned, cookie))


def test_roundtrip_sha256():
    claims = {"role": "member"}
    cookie = ft.sign(claims, KEY, digest="sha256", timestamp=TS)
    forged = web.forge_flask_session(cookie, KEY)   # digest auto-detected as sha256
    check("sha256 round-trip returns a cookie", isinstance(forged, str) and forged, forged)
    check("sha256 round-trip verifies under sha256", ft.verify(forged, KEY, digest="sha256") == claims)


# ------------------------------------------------------------------ forge with a modified claim

def test_forge_modified_claim():
    cookie = ft.sign({"user": "guest", "admin": False, "role": "user"}, KEY, timestamp=TS)
    forged = web.forge_flask_session(cookie, KEY, claims={"admin": True, "role": "admin"})
    check("forge returns a cookie for the right key", isinstance(forged, str) and forged, forged)
    data = ft.verify(forged, KEY)
    check("forge flips admin and keeps the other claims",
          data == {"user": "guest", "admin": True, "role": "admin"}, data)
    # the merge argument is a second dict applied over claims
    forged2 = web.forge_flask_session(cookie, KEY, claims={"admin": True}, merge={"id": 1})
    check("forge applies claims then merge", ft.verify(forged2, KEY) ==
          {"user": "guest", "admin": True, "role": "user", "id": 1}, ft.verify(forged2, KEY))


# ------------------------------------------------------------------ never-wrong: a wrong key refuses

def test_wrong_key_refuses():
    cookie = ft.sign({"user": "guest", "admin": False}, KEY, timestamp=TS)
    out = web.forge_flask_session(cookie, WRONG, claims={"admin": True})
    check("a wrong key returns None, never a bogus cookie", out is None, out)
    # and never silently signs with the wrong key: nothing it emits verifies under either key
    check("a wrong key forges nothing that verifies under the wrong key", out is None or ft.verify(out, WRONG) is None)
    # an empty / garbage cookie is refused too
    check("forge on a non-Flask cookie returns None", web.forge_flask_session("garbage", KEY) is None)
    check("forge on an empty cookie returns None", web.forge_flask_session("", KEY) is None)
    # a right key but a mismatched explicit digest must refuse (the key is not confirmed under it)
    c256 = ft.sign({"user": "guest"}, KEY, digest="sha256", timestamp=TS)
    check("right key, wrong explicit digest refuses", web.forge_flask_session(c256, KEY, digest="sha1") is None)


# ------------------------------------------------------------------ optional: real itsdangerous compatibility

def test_real_itsdangerous_if_present():
    try:
        import itsdangerous  # noqa: F401
    except Exception:
        check("itsdangerous not installed: compatibility branch skipped", True)
        return
    # build the original cookie with the REAL library (as a live Flask server would), then confirm+forge
    cookie = ft.sign({"user": "guest", "admin": False}, KEY)   # ft.sign uses itsdangerous when present
    forged = web.forge_flask_session(cookie, KEY, claims={"admin": True})
    check("real itsdangerous: confirm+forge returns a cookie", isinstance(forged, str) and forged, forged)
    check("real itsdangerous: the forged cookie verifies", ft.verify(forged, KEY) == {"user": "guest", "admin": True})
    check("real itsdangerous: a wrong key still refuses", web.forge_flask_session(cookie, WRONG) is None)


# ------------------------------------------------------------------ agent-only: not wired into Layer 1

def test_not_auto_wired_into_layer1():
    # the capability must be AGENT-INVOKED only: nothing on the unattended path may auto-call it.
    names = ("forge_flask_session", "parse_flask_session", "confirm_flask_key")
    targets = [
        REPO / "solvers" / "web" / "proof_hunt.py",
        REPO / "tools" / "web_open.py",
        REPO / "tools" / "open_day.py",
        REPO / "tools" / "run.py",
        REPO / "solvers" / "web" / "post_exploit.py",
    ]
    for t in targets:
        if not t.exists():
            continue
        text = t.read_text(errors="replace")
        for n in names:
            check(f"{t.name} does not call web.{n}", not re.search(r"\b" + re.escape(n) + r"\b", text),
                  f"{n} appears in {t.name}")
    # and importing web.py does not import flask_tools (the lazy-import contract): only calling does
    mod = sys.modules.copy()
    for m in ("web", "flask_tools"):
        sys.modules.pop(m, None)
    import importlib
    importlib.import_module("web")
    check("importing web.py does not import flask_tools", "flask_tools" not in sys.modules)
    sys.modules.update({k: v for k, v in mod.items() if k in ("web", "flask_tools")})


# B-001d: the runner below used to run at import, so pytest ran every check twice and a failure
# aborted collection (sys.exit). Pytest runs the test functions; this block is the script path.
if __name__ == "__main__":
    for fn in (test_parse_flask_session, test_confirm_flask_key, test_roundtrip_resign, test_roundtrip_sha256,
               test_forge_modified_claim, test_wrong_key_refuses, test_real_itsdangerous_if_present,
               test_not_auto_wired_into_layer1):
        fn()

    if FAILED:
        print(f"\n{len(FAILED)} FAILED: " + "; ".join(FAILED))
        sys.exit(1)
    print("\nall web flask-forge tests passed")
