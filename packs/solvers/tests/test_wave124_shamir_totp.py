#!/usr/bin/env python3
"""Offline tests for wave124: Shamir Secret Sharing + TOTP/HOTP in the `modern_crypto` toolkit.

  .venv/bin/python tests/test_wave124_shamir_totp.py

Covers solvers/common/shamir_totp.py (the GF(256) field, Lagrange interpolation, reconstruction
with over-determination, share/modulus/threshold parsing, RFC 4226/6238 codes, otpauth parsing)
and the wiring in solvers/toolkits/modern_crypto.py (the `shamir` and `otp` intents, _shamir_answer
and _otp_answer, signals). No network, no token; every fixture is synthesized here.

Never-wrong is the contract under test: a Shamir secret is reconstructed ONLY when it is proven by
over-determination (or exactly a stated threshold), disagreeing k-subsets give None, and the value
is always an UNSURE labels.pick, never plain; an OTP code needs a stated time/counter and is always
unsure. Prints one line per check and `ok` at the end; exits 1 when a check fails.
"""
import base64
import importlib.util
import json
import os
import random
import re
import shutil
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TMP = Path(tempfile.mkdtemp(prefix="test_wave124_"))
os.environ["CTF_WORKDIR"] = str(TMP / "challenges")
os.environ["CTF_PLATFORM_URL"] = "http://127.0.0.1:9/"
os.environ.pop("CTF_TOKEN", None)
os.environ["CTF_TESTING"] = "1"
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "solvers" / "common"))


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


sss = _load(REPO / "solvers" / "common" / "shamir_totp.py", "sss")
tk = _load(REPO / "solvers" / "toolkits" / "modern_crypto.py", "tk_modern_crypto")

FAILED = []
RND = random.Random(20261024)


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:400]}]"))
    if not ok:
        FAILED.append(label)


def q(question, aid="answer", kind="exact_text", pattern=None, syntax=None):
    fmt = {"kind": kind}
    if pattern:
        fmt["pattern"] = pattern
    if syntax:
        fmt["syntax"] = syntax
    return {"id": aid, "qid": aid, "answer_id": aid, "question": question, "answer_format": fmt}


def solve(question, files, **ctx):
    return tk.solve_set([question], files, dict(ctx))[question["qid"]]


def is_unsure(v, key=None):
    if not (isinstance(v, str) and v.startswith("??")):
        return False
    body = json.loads(v[2:])
    return key is None or body["k"].rstrip("#candidates") == key.rstrip("#candidates")


def opts(v):
    return [tuple(o) for o in json.loads(v[2:])["o"]] if isinstance(v, str) and v.startswith("??") else None


def opt_names(v):
    return [n for n, _ in (opts(v) or [])]


def opt_val(v, name):
    return next((val for n, val in (opts(v) or []) if n == name), None)


# ---- the GF(256) field --------------------------------------------------------------------------

def test_gf256_field():
    check("gf_mul(3,7)==9 (AES field)", sss._gf_mul(3, 7) == 9)
    check("gf_mul identity", all(sss._gf_mul(a, 1) == a for a in range(256)))
    check("gf_mul zero", all(sss._gf_mul(a, 0) == 0 for a in range(256)))
    check("gf_inv is a two-sided inverse for every nonzero element",
          all(sss._gf_mul(a, sss._gf_inv(a)) == 1 for a in range(1, 256)))
    check("gf log/exp cover the whole multiplicative group",
          sorted(sss._GF_EXP[:255]) == list(range(1, 256)))


# ---- Lagrange / prime-field reconstruction ------------------------------------------------------

def _poly_prime(coeffs, x, p):
    return sum(c * pow(x, i, p) for i, c in enumerate(coeffs)) % p


def test_lagrange_prime():
    p = 2 ** 127 - 1
    coeffs = [RND.randrange(p) for _ in range(3)]          # degree 2, threshold 3
    pts = [(x, _poly_prime(coeffs, x, p)) for x in range(1, 6)]
    check("eval_prime recovers the constant term", sss.eval_prime(pts[:3], 0, p) == coeffs[0])
    check("eval_prime matches the polynomial at a held-out x",
          sss.eval_prime(pts[:3], 9, p) == _poly_prime(coeffs, 9, p))


def test_recover_prime():
    p = 2 ** 521 - 1
    secret = int.from_bytes(b"flag{shamir_prime_ok}", "big")
    coeffs = [secret] + [RND.randrange(p) for _ in range(2)]
    pts = [(x, _poly_prime(coeffs, x, p)) for x in range(1, 7)]      # 6 shares, threshold 3

    r = sss.recover_prime(pts, p)
    check("prime: over-determined reconstruction, no threshold stated", r and r["secret_int"] == secret and r["verified"])
    check("prime: inferred threshold is 3", r and r["threshold"] == 3)

    r2 = sss.recover_prime(pts[:3], p, threshold=3)
    check("prime: exactly the stated threshold reconstructs (unverified)",
          r2 and r2["secret_int"] == secret and not r2["verified"])

    check("prime: exactly threshold with NO stated threshold -> None (cannot prove)",
          sss.recover_prime(pts[:3], p) is None)

    bad = pts[:5] + [(6, (pts[5][1] + 1) % p)]
    check("prime: one corrupt share among extras -> None (disagreeing k-subsets)",
          sss.recover_prime(bad, p) is None)

    check("prime: a wrong (non-prime, no-inverse) modulus -> None",
          sss.recover_prime(pts, 1000) is None)
    check("prime: a share y outside the field -> that set is refused",
          sss.recover_prime([(1, 5), (2, p + 10), (3, 7)], p) is None)
    check("prime: a repeated x-coordinate -> None",
          sss.recover_prime([(1, 5), (1, 6), (2, 7), (3, 8)], p) is None)
    check("prime: fewer than two shares -> None", sss.recover_prime([(1, 5)], p) is None)

    # a small prime, integer secret
    sp = 7919
    sc = [1234, 55, 9]
    spts = [(x, _poly_prime(sc, x, sp)) for x in range(1, 6)]
    rs = sss.recover_prime(spts, sp)
    check("prime: small field integer secret", rs and rs["secret_int"] == 1234 and rs["verified"])


def test_recover_gf256():
    def horner(co, x):
        acc = 0
        for c in reversed(co):
            acc = sss._gf_mul(acc, x) ^ c
        return acc

    secret = b"S3cr3t!Key"
    polys = [[b] + [RND.randrange(256) for _ in range(2)] for b in secret]   # threshold 3
    pts = [(x, bytes(horner(polys[i], x) for i in range(len(secret)))) for x in range(1, 6)]

    r = sss.recover_gf256(pts)
    check("gf256: over-determined reconstruction", r and r["secret_bytes"] == secret and r["verified"])
    check("gf256: inferred threshold 3", r and r["threshold"] == 3)

    r2 = sss.recover_gf256(pts[:3], threshold=3)
    check("gf256: exactly stated threshold (unverified)", r2 and r2["secret_bytes"] == secret and not r2["verified"])
    check("gf256: exactly threshold, none stated -> None", sss.recover_gf256(pts[:3]) is None)

    bad = pts[:4] + [(5, bytes((b ^ 1) for b in pts[4][1]))]
    check("gf256: one corrupt share among extras -> None", sss.recover_gf256(bad) is None)

    check("gf256: unequal share lengths -> None",
          sss.recover_gf256([(1, b"\x01\x02"), (2, b"\x03"), (3, b"\x04\x05")]) is None)


# ---- parsing ------------------------------------------------------------------------------------

def test_parsing_shares():
    p = 2 ** 127 - 1
    coeffs = [12345, 67, 8]
    pts = [(x, _poly_prime(coeffs, x, p)) for x in range(1, 5)]

    json_text = json.dumps({"prime": str(p), "shares": [[x, str(y)] for x, y in pts]})
    r = sss.recover([json_text])
    check("parse: JSON {prime, shares:[[x,y]]}", r and r["secret_int"] == 12345)

    tuple_text = "prime = %d\n" % p + "\n".join("(%d, %d)" % s for s in pts)
    check("parse: (x, y) tuples with a labelled prime", sss.recover([tuple_text])["secret_int"] == 12345)

    line_text = "modulus: %d\n" % p + "\n".join("%d: %d" % s for s in pts)
    check("parse: 'x: y' per line", sss.recover([line_text])["secret_int"] == 12345)

    xy_text = "p = %d\n" % p + "\n".join("x=%d y=%d" % s for s in pts)
    check("parse: 'x=.. y=..' lines", sss.recover([xy_text])["secret_int"] == 12345)

    hexy = "prime = 0x%x\n" % p + "\n".join("(%d, 0x%x)" % s for s in pts)
    check("parse: hex shares and hex prime", sss.recover([hexy])["secret_int"] == 12345)

    check("parse: mersenne prime written as 2^127 - 1",
          sss.recover(["field 2^127 - 1\n" + "\n".join("(%d,%d)" % s for s in pts)])["secret_int"] == 12345)

    check("parse: no modulus at all -> None (prime field unprovable)",
          sss.recover(["\n".join("(%d, %d)" % s for s in pts)]) is None)
    check("parse: a wrong extra prime candidate is ignored (verification picks the real field)",
          sss.recover(["prime = 7919\nmodulus = %d\n" % p + "\n".join("(%d,%d)" % s for s in pts)])["secret_int"] == 12345)


def test_parsing_thresholds():
    check("threshold: 'threshold = 3'", 3 in sss.find_thresholds("the threshold = 3"))
    check("threshold: '3 of 5'", 3 in sss.find_thresholds("you need 3 of 5 shares"))
    check("threshold: '2-of-3'", 2 in sss.find_thresholds("a 2-of-3 scheme"))
    check("threshold: none stated -> []", sss.find_thresholds("just some shares here") == [])


# ---- TOTP / HOTP (the RFC test vectors) ---------------------------------------------------------

def test_hotp_rfc4226():
    secret = b"12345678901234567890"
    expect = [755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489]
    got = [sss.hotp(secret, c, 6, "sha1") for c in range(10)]
    check("HOTP: RFC 4226 Appendix D test vectors", got == expect, got)


def test_totp_rfc6238():
    s1 = b"12345678901234567890"
    s256 = b"12345678901234567890123456789012"
    s512 = b"1234567890123456789012345678901234567890123456789012345678901234"
    vectors = [
        (59, s1, "sha1", 94287082), (59, s256, "sha256", 46119246), (59, s512, "sha512", 90693936),
        (1111111109, s1, "sha1", 7081804), (1111111111, s1, "sha1", 14050471),
        (1234567890, s1, "sha1", 89005924), (2000000000, s1, "sha1", 69279037), (20000000000, s1, "sha1", 65353130),
    ]
    ok = all(sss.totp(sec, t, 30, 0, 8, algo) == code for t, sec, algo, code in vectors)
    check("TOTP: RFC 6238 Appendix B test vectors (SHA1/256/512, 8 digits)", ok,
          [(t, algo, sss.totp(sec, t, 30, 0, 8, algo)) for t, sec, algo, code in vectors])


def test_b32_and_otpauth():
    secret = b"Hello!" * 3
    b32 = base64.b32encode(secret).decode()
    check("b32_secret round-trips", sss.b32_secret(b32) == secret)
    check("b32_secret tolerates spaces and lowercase", sss.b32_secret(b32.lower().replace("", " ").strip()) == secret)
    check("b32_secret rejects a too-short string", sss.b32_secret("AB") is None)
    check("b32_secret rejects non-base32", sss.b32_secret("not-base-32!!!!") is None)

    uri = "otpauth://totp/ACME%%20Co:alice@example.com?secret=%s&issuer=ACME&algorithm=SHA256&digits=8&period=60" % b32
    spec = sss.parse_otpauth(uri)
    check("otpauth: totp parsed with algo/digits/period", spec and spec["type"] == "totp"
          and spec["algo"] == "sha256" and spec["digits"] == 8 and spec["period"] == 60 and spec["secret"] == secret)
    huri = "otpauth://hotp/x?secret=%s&counter=5" % b32
    hspec = sss.parse_otpauth(huri)
    check("otpauth: hotp parsed with counter", hspec and hspec["type"] == "hotp" and hspec.get("counter") == 5)
    check("otpauth: bad secret -> None", sss.parse_otpauth("otpauth://totp/x?secret=!!!!") is None)

    check("otp_specs: one from a URI", len(sss.otp_specs("here: " + uri)) == 1)
    check("otp_specs: one from a labelled base32 secret",
          len(sss.otp_specs("the shared secret is %s thanks" % b32)) == 1)


def test_find_time_counter():
    check("find_unix_time: a labelled epoch", sss.find_unix_time("at unix time 1700000000") == 1700000000)
    check("find_unix_time: a bare 10-digit epoch in range", sss.find_unix_time("timestamp 1111111111 here") == 1111111111)
    check("find_unix_time: an ISO UTC datetime",
          sss.find_unix_time("2023-11-14T22:13:20Z") == 1700000000)
    check("find_unix_time: two different times -> None (ambiguous)",
          sss.find_unix_time("1111111111 and 2000000000") is None)
    check("find_unix_time: none stated -> None", sss.find_unix_time("the current code please") is None)
    check("find_counter: labelled counter", sss.find_counter("counter = 7") == 7)
    check("find_counter: none -> None", sss.find_counter("no moving factor here") is None)


# ---- toolkit integration (never-wrong) ----------------------------------------------------------

def test_toolkit_shamir():
    p = 2 ** 521 - 1
    secret = int.from_bytes(b"flag{w4v3_124}", "big")
    coeffs = [secret] + [RND.randrange(p) for _ in range(2)]
    pts = [(x, _poly_prime(coeffs, x, p)) for x in range(1, 6)]
    body = "prime = %d\n" % p + "\n".join("(%d, %d)" % s for s in pts)

    a = solve(q("Reconstruct the shared secret from these Shamir shares."), {"shares.txt": body.encode()})
    check("tk shamir: answer is UNSURE, never plain", is_unsure(a, "modern_crypto.secret/shamir_prime"), a)
    check("tk shamir: the ascii/flag form is offered and correct", opt_val(a, "ascii") == "flag{w4v3_124}", opts(a))

    a2 = solve(q("Recover the secret flag by combining the shares.", pattern=r"^flag\{[a-z0-9_]+\}$"),
               {"s.txt": body.encode()})
    check("tk shamir: with a flag pattern, only the matching form survives (still unsure)",
          is_unsure(a2) and opt_val(a2, "ascii") == "flag{w4v3_124}", opts(a2))

    bad = pts[:4] + [(5, (pts[4][1] + 1) % p)]
    bbody = "prime = %d\n" % p + "\n".join("(%d, %d)" % s for s in bad)
    check("tk shamir: a corrupted share set -> None",
          solve(q("Reconstruct the secret from the shares."), {"s.txt": bbody.encode()}) is None)

    # an integer secret with kind=integer stays unsure (never plain)
    sp, sc = 7919, [4242, 13, 2]
    spts = [(x, _poly_prime(sc, x, sp)) for x in range(1, 6)]
    sbody = "modulus: %d\nthreshold 3\n" % sp + "\n".join("%d, %d" % s for s in spts)
    ai = solve(q("Combine the Shamir shares. What is the reconstructed secret value?", kind="integer"), {"s.txt": sbody.encode()})
    check("tk shamir: integer-kind secret is UNSURE with decimal/hex options",
          is_unsure(ai) and opt_val(ai, "decimal") == "4242", opts(ai))

    # Exactly threshold-many shares reconstruct but do not verify the polynomial degree.  That
    # candidate key is delivery/question scoped by the full SHA-256, never a truncated identity.
    short = "modulus: %d\nthreshold 3\n" % sp + "\n".join("%d, %d" % s for s in spts[:3])
    au = solve(q("Combine the Shamir shares. What is the reconstructed secret value?", kind="integer"),
               {"short.txt": short.encode()})
    parsed = json.loads(au[2:]) if isinstance(au, str) and au.startswith("??") else {}
    key = parsed.get("k") if isinstance(parsed, dict) else None
    check("tk shamir: unverified candidate scope carries the full SHA-256",
          re.fullmatch(r"modern_crypto\.secret/shamir_prime\.unverified@[0-9a-f]{64}#candidates",
                       key or "") is not None,
          key or au)


def test_toolkit_gf256():
    def horner(co, x):
        acc = 0
        for c in reversed(co):
            acc = sss._gf_mul(acc, x) ^ c
        return acc
    secret = b"MyByteKey!"
    polys = [[b] + [RND.randrange(256) for _ in range(2)] for b in secret]
    pts = [(x, bytes(horner(polys[i], x) for i in range(len(secret)))) for x in range(1, 6)]
    body = "GF(256) byte shares:\n" + "\n".join("%d-%s" % (x, yb.hex()) for x, yb in pts)
    a = solve(q("Recombine the shares to recover the secret key."), {"g.txt": body.encode()})
    check("tk gf256: UNSURE, correct ascii", is_unsure(a, "modern_crypto.secret/shamir_gf256")
          and opt_val(a, "ascii") == "MyByteKey!", opts(a))


def test_toolkit_otp():
    secret = b"12345678901234567890"
    b32 = base64.b32encode(secret).decode()
    uri = "otpauth://totp/ACME:a?secret=%s&algorithm=SHA1&digits=6&period=30" % b32

    a = solve(q("Given this authenticator and Unix time 1111111111, what is the TOTP code?", pattern=r"^\d{6}$"),
              {"c.txt": ("config " + uri).encode()})
    check("tk otp: TOTP code is UNSURE and correct (050471)",
          is_unsure(a, "modern_crypto.otp/totp") and opt_val(a, "zero_padded") == "050471", opts(a))

    ah = solve(q("Compute the HOTP code for counter 3 using the authenticator secret.", pattern=r"^\d{6}$"),
               {"c.txt": ("secret: " + b32).encode()})
    check("tk otp: HOTP code is UNSURE and correct (969429)",
          is_unsure(ah, "modern_crypto.otp/hotp") and opt_val(ah, "zero_padded") == "969429", opts(ah))

    an = solve(q("What is the current TOTP code?"), {"c.txt": ("secret=" + b32).encode()})
    check("tk otp: no stated time -> None (a 'current' code is not byte-derivable)", an is None)

    asec = solve(q("Recover the shared secret (base32) from this otpauth URI."), {"c.txt": uri.encode()})
    check("tk otp: the secret is answered UNSURE under its own key",
          is_unsure(asec, "modern_crypto.otp_secret/base32") and opt_val(asec, "base32") == b32, opts(asec))

    # two distinct secrets -> None (ambiguous)
    b32b = base64.b32encode(b"another20byteseed!!!").decode()
    atwo = solve(q("What is the TOTP code at unix time 1111111111?"),
                 {"c.txt": ("secret: %s\nsecret: %s" % (b32, b32b)).encode()})
    check("tk otp: two secrets -> None", atwo is None)

    # a transform of the code is not answered
    atr = solve(q("What is the SHA-256 of the TOTP code at unix time 1111111111?"),
                {"c.txt": ("secret=" + b32).encode()})
    check("tk otp: a hash-of-the-code question -> None", atr is None)


def test_intent_precision():
    check("intent: plain RSA 'recover the secret message' is NOT shamir",
          tk.intent(q("Recover the secret message by decrypting the RSA ciphertext.")) != "shamir")
    check("intent: 'one-time pad' XOR is NOT otp",
          tk.intent(q("The message was encrypted with a one-time pad. Recover the plaintext.")) != "otp")
    check("intent: 'HMAC-based one-time password' is otp (not hmac_struct)",
          tk.intent(q("Compute the HMAC-based one-time password for counter 1.")) == "otp")
    check("intent: 'combine the shares' is shamir",
          tk.intent(q("Combine the shares to reveal the value.")) == "shamir")
    check("intent: a bare HMAC question is not hijacked by otp or shamir",
          tk.intent(q("Which hash algorithm underlies this HMAC?")) not in ("otp", "shamir"))
    check("intent: 'shared secret' alone (no shares) is not shamir",
          tk.intent(q("Two parties derived a shared secret. What is it?")) != "shamir")


def test_signals():
    secret = b"12345678901234567890"
    b32 = base64.b32encode(secret).decode()
    check("signals: a Shamir question scores > 0",
          tk.signals([q("Reconstruct the Shamir secret from the shares.")], {"s.txt": b"(1,2)\n(2,3)\n"}) > 0)
    check("signals: a TOTP question scores > 0",
          tk.signals([q("What is the TOTP code at this time?")], {"c.txt": b32.encode()}) > 0)
    # an unrelated question/file must not be dragged up by the new terms
    check("signals: an unrelated set stays 0",
          tk.signals([q("What colour is the sky?")], {"x.txt": b"hello world"}) == 0.0)


def test_never_plain_property():
    """Across many random Shamir and OTP fixtures, solve_set never returns a plain (non-??) string
    while the ledger holds no accepted name. A plain return here would be a never-wrong violation."""
    violations = []
    for _ in range(40):
        p = [2 ** 127 - 1, 2 ** 521 - 1, 7919, 2 ** 61 - 1][RND.randrange(4)]
        t = RND.randrange(2, 4)
        secret = RND.randrange(min(p, 2 ** 80))
        coeffs = [secret] + [RND.randrange(p) for _ in range(t - 1)]
        n = t + RND.randrange(1, 3)
        pts = [(x, _poly_prime(coeffs, x, p)) for x in range(1, n + 1)]
        body = "prime = %d\n" % p + "\n".join("(%d, %d)" % s for s in pts)
        a = solve(q("Reconstruct the shared secret from the shares."), {"s.txt": body.encode()})
        if a is not None and not is_unsure(a):
            violations.append(("shamir", a))
    for _ in range(40):
        secret = bytes(RND.randrange(256) for _ in range(RND.randrange(10, 20)))
        b32 = base64.b32encode(secret).decode()
        t = RND.randrange(1, 3_000_000_000)
        a = solve(q("What is the TOTP code at unix time %d?" % t, pattern=r"^\d{6}$"),
                  {"c.txt": ("secret: " + b32).encode()})
        if a is not None and not is_unsure(a):
            violations.append(("otp", a))
    check("never-wrong: no plain answer is ever emitted for Shamir/OTP without a judged name",
          not violations, violations[:3])


def main():
    try:
        for fn in (test_gf256_field, test_lagrange_prime, test_recover_prime, test_recover_gf256,
                   test_parsing_shares, test_parsing_thresholds, test_hotp_rfc4226, test_totp_rfc6238,
                   test_b32_and_otpauth, test_find_time_counter, test_toolkit_shamir, test_toolkit_gf256,
                   test_toolkit_otp, test_intent_precision, test_signals, test_never_plain_property):
            fn()
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
    print("ok" if not FAILED else f"FAILED {len(FAILED)}: " + "; ".join(FAILED))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
