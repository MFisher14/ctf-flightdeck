#!/usr/bin/env python3
"""Offline tests for solvers/toolkits/flask_tools.py (backlog row 206). No network and no token: the
SSTI confirmation is exercised with a fake in-memory client, and the signing/recovery is pure math.

  .venv/bin/python tests/test_tk_flask_tools.py
"""
import importlib.util
import json
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import flask_tools as ft  # noqa: E402

FAILED = []
TS = 1700000000           # a fixed, realistic timestamp so decode_cookie's regex round-trips


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:400]}]"))
    if not ok:
        FAILED.append(label)


# ------------------------------------------------------------------ (a) sign / decode / verify / forge

def test_sign_decode_roundtrip_plain():
    obj = {"user": "guest", "admin": False, "n": 42}
    cookie = ft.sign(obj, "topsecret", timestamp=TS)
    dec = ft.decode(cookie)
    check("sign->decode round-trips (no zlib)", dec.get("data") == obj, dec)
    check("plain cookie is not marked compressed", dec.get("compressed") is False, dec.get("compressed"))
    check("decode goes through web_evidence (kind flask_session)", dec.get("kind") == "flask_session", dec.get("kind"))


def test_sign_decode_roundtrip_zlib():
    obj = {"blob": "A" * 300, "ok": True}        # long enough that the Flask heuristic compresses it
    cookie = ft.sign(obj, "k", compress=True, timestamp=TS)
    check("a compressed cookie begins with '.'", cookie.startswith("."), cookie[:4])
    dec = ft.decode(cookie)
    check("sign->decode round-trips (zlib)", dec.get("data") == obj, dec.get("data", {}).get("ok"))
    check("zlib cookie is marked compressed", dec.get("compressed") is True, dec.get("compressed"))


def test_verify():
    cookie = ft.sign({"role": "user"}, "the-key", timestamp=TS)
    check("verify returns the data under the right key", ft.verify(cookie, "the-key") == {"role": "user"})
    check("verify returns None under a wrong key", ft.verify(cookie, "wrong") is None)
    # sha256 cookies verify under the matching digest only
    c256 = ft.sign({"role": "user"}, "the-key", digest="sha256", timestamp=TS)
    check("sha256 cookie verifies under digest=sha256", ft.verify(c256, "the-key", digest="sha256") == {"role": "user"})
    check("sha256 cookie does not verify as sha1", ft.verify(c256, "the-key", digest="sha1") is None)


def test_forge():
    cookie = ft.sign({"user": "guest", "admin": False}, "known-secret", timestamp=TS)
    forged = ft.forge(cookie, "known-secret", changes={"admin": True}, timestamp=TS)
    data = ft.verify(forged, "known-secret")
    check("forge sets a field and re-signs so verify accepts it", data == {"user": "guest", "admin": True}, data)
    # forging from a bare dict works too
    forged2 = ft.forge({"user": "admin"}, "known-secret", timestamp=TS)
    check("forge from a dict signs a fresh cookie", ft.verify(forged2, "known-secret") == {"user": "admin"})
    # a forged cookie is never verifiable under a different key (it is tool output, not a free pass)
    check("forged cookie is worthless without the key", ft.verify(forged, "other") is None)


# ------------------------------------------------------------------ (b) SECRET_KEY recovery

def test_recover_from_wordlist():
    right = "sup3r-s3cret-flask-key"
    cookie = ft.sign({"logged_in": True}, right, timestamp=TS)
    with tempfile.TemporaryDirectory() as d:
        wl = Path(d) / "keys.txt"
        wl.write_text("\n".join(["password", "admin", "changeme", right, "letmein"]) + "\n")
        hit = ft.crack_secret_key(cookie, wordlist=str(wl))
        check("crack_secret_key finds the key in an in-delivery wordlist",
              hit and hit["secret_key"] == right and hit["digest"] == "sha1", hit)
        # a wordlist that does not contain the key -> None, never a false hit
        wl2 = Path(d) / "nope.txt"
        wl2.write_text("a\nb\nc\n")
        check("crack_secret_key returns None when the key is absent", ft.crack_secret_key(cookie, wordlist=str(wl2)) is None)
        # an external/system wordlist is refused by name (brute is bounded to the delivery)
        rock = Path(d) / "rockyou.txt"
        rock.write_text(right + "\n")
        try:
            ft.wordlist_candidates(str(rock))
            check("rockyou.txt is refused", False)
        except ValueError as e:
            check("rockyou.txt refused (brute bounded to the delivery)", "rockyou" in str(e).lower(), str(e))


def test_recover_from_text_and_ssti():
    right = "leaked-config-secret-9f"
    cookie = ft.sign({"u": 1}, right, timestamp=TS)
    # from challenge text / source
    cands = ft.secret_keys_from_text(f"# config\napp.secret_key = '{right}'\nDEBUG = True\n")
    check("secret_keys_from_text parses app.secret_key", right in cands, cands)
    check("recover from text", ft.crack_secret_key(cookie, text=f"SECRET_KEY = \"{right}\"")["secret_key"] == right)
    # from a {{config}} SSTI leak (dict repr)
    leak = "<Config {'ENV': 'production', 'SECRET_KEY': '%s', 'DEBUG': False}>" % right
    check("secret_keys_from_ssti_leak parses a config dump", right in ft.secret_keys_from_ssti_leak(leak), leak)
    check("recover from an SSTI leak", ft.crack_secret_key(cookie, ssti=leak)["secret_key"] == right)
    # a bytes-valued SECRET_KEY in the leak is parsed as DATA (literal_eval, no exec)
    byteskey = b"\x00\x01rawkey"
    cb = ft.sign({"u": 1}, byteskey, timestamp=TS)
    bl = "{'SECRET_KEY': %r}" % byteskey
    got = ft.secret_keys_from_ssti_leak(bl)
    check("ssti leak parses a bytes SECRET_KEY", byteskey in got, got)
    check("recover a bytes key from the leak", ft.crack_secret_key(cb, ssti=bl)["secret_key"] == byteskey)


# ------------------------------------------------------------------ (c) SSTI confirm / payloads

class FakeClient:
    """A stand-in for web.py WebClient: records every .request() and returns a canned response.
    Proves confirm_ssti DRIVES a client without any network."""

    def __init__(self, body=b"", status=200):
        self.body, self.status, self.calls = body, status, []

    def request(self, method, path, data=None, headers=None, allow_redirects=True):
        self.calls.append({"method": method, "path": path, "data": data, "headers": headers})
        return {"status": self.status, "body": self.body}


def test_ssti_classifier():
    check("is_evaluated True when the result is present", ft.is_evaluated("the answer is 49!", "{{7*7}}", "49"))
    check("is_evaluated False when the payload is only reflected", not ft.is_evaluated("you sent {{7*7}}", "{{7*7}}", "49"))
    check("is_evaluated handles bytes bodies", ft.is_evaluated(b"<p>49</p>", "{{7*7}}", "49"))
    check("is_evaluated False when nothing matches", not ft.is_evaluated("hello world", "{{7*7}}", "49"))


def test_confirm_ssti_drives_client():
    fake = FakeClient(body=b"<html>result: 49</html>")
    out = ft.confirm_ssti(fake, "/greet", param="name")
    check("confirm_ssti confirms on a canned 49 response", out["confirmed"] is True, out)
    check("confirm_ssti names the jinja2 engine first", out["engine"] == "jinja2", out["engine"])
    check("confirm_ssti sent every probe through the client", len(fake.calls) == len(ft.SSTI_PROBES), len(fake.calls))
    check("confirm_ssti put the probe in the named GET parameter", "name=" in fake.calls[0]["path"], fake.calls[0]["path"])
    # a reflecting-only server is NOT confirmed
    refl = FakeClient(body=b"you sent {{7*7}} and ${7*7}")
    out2 = ft.confirm_ssti(refl, "/echo", param="q")
    check("confirm_ssti does not false-positive on reflection", out2["confirmed"] is False, out2)
    # POST path and header path also drive the client
    fp = FakeClient(body=b"49")
    ft.confirm_ssti(fp, "/p", param="x", method="POST")
    check("confirm_ssti POSTs a form body", fp.calls[0]["method"] == "POST" and "x=" in (fp.calls[0]["data"] or ""), fp.calls[0])


def test_payload_builders():
    r = ft.jinja_read_payload("/etc/passwd")
    check("jinja_read_payload embeds the target path", "/etc/passwd" in r and r.startswith("{{"), r)
    check("jinja_read variants are listed", "config_globals" in ft.jinja_read_variants() and "builtins_open" in ft.jinja_read_variants())
    c = ft.jinja_rce_payload("id", variant="cycler")
    check("jinja_rce_payload embeds the command", "id" in c and "cycler" in c, c)
    try:
        ft.jinja_read_payload("/x", variant="nope")
        check("an unknown read variant raises", False)
    except ValueError:
        check("an unknown read variant raises ValueError", True)


# ------------------------------------------------------------------ hand-tool discipline

def test_no_runner_contract():
    check("flask_tools exposes no signals()/solve_set()",
          not hasattr(ft, "signals") and not hasattr(ft, "solve_set"))


def test_not_in_match_registry():
    spec = importlib.util.spec_from_file_location("ft_registry", REPO / "solvers" / "toolkits" / "registry.py")
    reg = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reg)
    check("flask_tools is not a registered match toolkit", "flask_tools" not in reg.BY_KEY, list(reg.BY_KEY)[:3])


def test_reuses_web_evidence_decoder():
    # the decode side must be web_evidence.decode_cookie, not a local reimplementation
    import web_evidence
    check("decode delegates to web_evidence.decode_cookie", ft._decode_cookie is web_evidence.decode_cookie)


def test_cli():
    with tempfile.TemporaryDirectory() as d:
        df = Path(d) / "s.json"
        df.write_text(json.dumps({"user": "admin"}))
        check("CLI: sign exits 0", ft.main(["sign", "--key", "k", "--data-file", str(df), "--ts", str(TS)]) == 0)
        cookie = ft.sign({"user": "admin"}, "k", timestamp=TS)
        check("CLI: decode exits 0", ft.main(["decode", cookie]) == 0)
        check("CLI: verify (right key) exits 0", ft.main(["verify", cookie, "--key", "k"]) == 0)
        check("CLI: verify (wrong key) exits 1", ft.main(["verify", cookie, "--key", "nope"]) == 1)
        check("CLI: forge exits 0", ft.main(["forge", cookie, "--key", "k", "--set", "admin=true"]) == 0)
        wl = Path(d) / "w.txt"
        wl.write_text("a\nk\nb\n")
        check("CLI: recover exits 0", ft.main(["recover", cookie, "--wordlist", str(wl)]) == 0)
        check("CLI: ssti-payload --read exits 0", ft.main(["ssti-payload", "--read", "/etc/passwd"]) == 0)
        check("CLI: probes exits 0", ft.main(["probes"]) == 0)


# B-001d: the runner below used to run at import, so pytest ran every check twice and a failure
# aborted collection (sys.exit). Pytest runs the test functions; this block is the script path.
if __name__ == "__main__":
    for fn in (test_sign_decode_roundtrip_plain, test_sign_decode_roundtrip_zlib, test_verify, test_forge,
               test_recover_from_wordlist, test_recover_from_text_and_ssti, test_ssti_classifier,
               test_confirm_ssti_drives_client, test_payload_builders, test_no_runner_contract,
               test_not_in_match_registry, test_reuses_web_evidence_decoder, test_cli):
        fn()

    if FAILED:
        print(f"\n{len(FAILED)} FAILED: " + "; ".join(FAILED))
        sys.exit(1)
    print("\nall flask_tools toolkit tests passed")
