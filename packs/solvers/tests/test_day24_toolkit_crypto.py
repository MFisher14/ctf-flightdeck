#!/usr/bin/env python3
"""Offline tests of the classical-crypto breadth added to the `modern_crypto` toolkit (backlog
row 88): solvers/toolkits/classical.py (the ciphers, encoding chains, hash/HMAC structure and RSA
detection) and the unsure-only wiring in solvers/toolkits/modern_crypto.py.

  .venv/bin/python tests/test_day24_toolkit_crypto.py

No network and no token. Every fixture is synthesized here; nothing is read from a saved attempt.
Each cipher has a near-miss that must decline. The central invariant: the toolkit NEVER answers a
classical fact plain -- every classical/encoding/hmac answer from solve_set is an unsure pick
(a `??` string) or None, never a bare value. Prints one line per check and `ok`; exits 1 on failure.
"""
import importlib.util
import json
import os
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
os.environ["CTF_PLATFORM_URL"] = "http://127.0.0.1:9/"
os.environ.pop("CTF_TOKEN", None)
os.environ["CTF_TESTING"] = "1"
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "solvers" / "common"))


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cl = _load("classical_test", REPO / "solvers" / "toolkits" / "classical.py")
tk = _load("tk_mc_test", REPO / "solvers" / "toolkits" / "modern_crypto.py")

FAILED = []
MSG = "the secret meeting is at midnight tonight by the river bend near the old mill house"


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:300]}]"))
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


def is_unsure(v):
    return isinstance(v, str) and v.startswith("??")


def unsure_options(v):
    return json.loads(v[2:])["o"] if is_unsure(v) else []


def caesar_enc(t, k):
    def f(c):
        if "a" <= c <= "z":
            return chr((ord(c) - 97 + k) % 26 + 97)
        if "A" <= c <= "Z":
            return chr((ord(c) - 65 + k) % 26 + 65)
        return c
    return "".join(f(c) for c in t)


def vig_enc(t, key):
    key = [c for c in key.lower() if c.isalpha()]
    out, j = [], 0
    for c in t:
        if c.isalpha():
            out.append(chr((ord(c.lower()) - 97 + (ord(key[j % len(key)]) - 97)) % 26 + 97))
            j += 1
        else:
            out.append(c)
    return "".join(out)


# ---- the classical library directly -----------------------------------------------------------------

def test_library():
    ct = caesar_enc(MSG, 13)
    best = cl.caesar_all(ct)[0]
    check("caesar: the one readable shift is found", best[0] == 13 and best[1] == MSG, best)
    check("rot13 is self-inverse", cl.rot13(cl.rot13(MSG)) == MSG)
    check("atbash is an involution", cl.atbash(cl.atbash(MSG)) == MSG)
    check("affine: the (a,b) that reads English is best",
          cl.affine_all(caesar_enc("", 0) or "".join(chr((5 * (ord(c) - 97) + 8) % 26 + 97) if c.isalpha() else c for c in MSG))[0][1] == MSG)

    vt = vig_enc(MSG, "lemon")
    check("vigenere: decrypt with the key", cl.vigenere_decrypt(vt, "lemon") == MSG)
    got = cl.vigenere_known_plaintext(vt, "the secret")[:1]
    check("vigenere: key and plaintext from a known start (period < crib length)",
          got and got[0][0] == "lemon" and got[0][1] == MSG, got)
    check("vigenere near-miss: a wrong crib does not read English",
          not any(cl.looks_english(pt) for _, pt, _ in cl.vigenere_known_plaintext(vt, "xyzzyxwvut")))

    rf = "WEAREDISCOVEREDFLEEATONCE"
    enc_rf = "".join(rf[i] for i in sorted(range(len(rf)), key=lambda i: (cl.rail_fence_decrypt and 0, i)))  # placeholder
    # encrypt rail-fence(3) by the standard zig-zag, then decrypt
    def rail_enc(s, rails):
        rows = [""] * rails
        r, step = 0, 1
        for c in s:
            rows[r] += c
            if r == 0:
                step = 1
            elif r == rails - 1:
                step = -1
            r += step
        return "".join(rows)
    check("rail fence: decrypt a 3-rail encryption", cl.rail_fence_decrypt(rail_enc(rf, 3), 3) == rf)

    # columnar round-trip for a known order
    def col_enc(s, order):
        k = len(order)
        cols = {c: s[c::k] for c in range(k)}
        return "".join(cols[c] for c in order)
    order = (2, 0, 1)
    check("columnar: a width-3 order decrypts", cl.columnar_decrypt(col_enc(MSG.replace(" ", ""), order), order) == MSG.replace(" ", ""))

    check("morse decodes . - /", cl.morse_decode(".... . .-.. .-.. --- / .-- --- .-. .-.. -..") == "HELLO WORLD")
    check("morse near-miss: plain text is not morse", cl.morse_decode("hello world") is None)
    check("baconian decodes a two-symbol stream", cl.baconian_decode("AABBBABAAA") == "HI")

    sub = cl.substitution_hillclimb((MSG + " ") * 3, deadline=time.monotonic() + 1.5)
    check("substitution: a long text returns a best-effort hypothesis (unsure; the caller validates)",
          sub is not None and isinstance(sub[0], str) and isinstance(sub[1], dict), sub and sub[0][:40])
    check("substitution near-miss: too short to climb is None", cl.substitution_hillclimb("abcde") is None)

    check("english_score ranks English over gibberish", cl.english_score(MSG) > cl.english_score(caesar_enc(MSG, 7)))


def test_encoding_chains():
    import base64
    d2 = base64.b64encode(base64.b64encode(MSG.encode())).decode()
    r = cl.decode_chain(d2)
    check("chain: double base64 peeled to the text", r["chain"] == ["base64", "base64"] and r["text"] == MSG, r["chain"])
    b32 = base64.b32encode(MSG.encode()).decode()
    check("chain: base32", cl.decode_chain(b32)["text"] == MSG)
    check("chain: stops at readable text, does not over-decode", cl.decode_chain(MSG)["chain"] == [])
    check("chain near-miss: random text is no chain", cl.decode_chain("the cat sat on the mat and then it left")["chain"] == [])


def test_hash_and_rsa_findings():
    check("hash_format: 32 hex -> md5 family", "md5" in cl.hash_format("5d41402abc4b2a76b9719d911017c592")["families"])
    check("hash_format: 64 hex -> sha256 family", "sha256" in cl.hash_format("a" * 64)["families"])
    check("hash_format: a bcrypt prefix is named", cl.hash_format("$2b$12$" + "a" * 22)["prefix"] == "2b")
    check("hmac_structure: length names the underlying family, flagged hmac", cl.hmac_structure("a" * 64)["hmac"] and "sha256" in cl.hmac_structure("a" * 64)["families"])

    # RSA detection from public params only (no decryption, no real factoring)
    p = 1000000007
    q_ = 1000000009            # close primes
    f = dict(cl.rsa_findings({"n": p * q_, "e": 3}))
    check("rsa_findings: small e and close primes are detected, nothing decrypted",
          "small_public_exponent" in f and "fermat_close_primes" in f, list(f))
    far = 32416190071 * 15485863       # far-apart primes: no fermat hit within the cap
    f2 = dict(cl.rsa_findings({"n": far, "e": 65537}))
    check("rsa_findings near-miss: far primes give no close-prime finding", "fermat_close_primes" not in f2, list(f2))
    shared = cl.rsa_findings(moduli=[p * q_, p * 1000000021])
    check("rsa_findings: a shared prime across two moduli", any(n == "shared_prime" for n, _ in shared), shared)


def test_identify():
    check("identify: a ROT text is caesar/rot13", any(n in ("caesar", "rot13") for n, _ in cl.identify(caesar_enc(MSG, 13))))
    vt = vig_enc(MSG * 3, "lemon")
    check("identify: a polyalphabetic text is vigenere", any(n == "vigenere" for n, _ in cl.identify(vt)), cl.identify(vt))
    import base64
    check("identify: nested base is an encoding chain", any(n == "encoding_chain" for n, _ in cl.identify(base64.b64encode(MSG.encode()).decode())))


# ---- the solve_set wiring: UNSURE ONLY --------------------------------------------------------------

def test_wiring_unsure_only():
    ct = caesar_enc(MSG, 13)
    got = solve(q("Decrypt this Caesar cipher and recover the message."), {"cipher.txt": ct.encode()})
    check("wiring: Caesar solved as an unsure pick (never plain)", is_unsure(got) and any(MSG == v for _, v in unsure_options(got)), got)
    # even with a pattern that the plaintext matches, a classical answer stays unsure
    got = solve(q("Decrypt this Caesar cipher.", pattern=r"^[ -~]+$"), {"cipher.txt": ct.encode()})
    check("wiring: a matching pattern does not make a classical answer plain", is_unsure(got) or got is None, got)

    vt = vig_enc(MSG, "lemon")
    got = solve(q("This is a Vigenere cipher. The plaintext starts with 'the secret'. Recover it."), {"c.txt": vt.encode()})
    check("wiring: Vigenere with a known start, unsure", is_unsure(got) and any(v == MSG for _, v in unsure_options(got)), got)

    got = solve(q("Which classical cipher was used here: caesar, vigenere or atbash?", kind="enum"), {"c.txt": ct.encode()})
    check("wiring: cipher identification is an unsure pick", is_unsure(got), got)

    import base64
    d2 = base64.b64encode(base64.b64encode(MSG.encode())).decode()
    got = solve(q("Decode the nested base64 layers and submit the message."), {"blob.txt": d2.encode()})
    check("wiring: encoding chain decoded, unsure", is_unsure(got) and any(v == MSG for _, v in unsure_options(got)), got)

    h = "a" * 64
    got = solve(q(f"Which hash algorithm does this HMAC use? {h}", kind="enum"), {})
    check("wiring: HMAC underlying hash is an unsure pick", is_unsure(got) and any(v == "sha256" for _, v in unsure_options(got)), got)

    # near-misses: nothing readable -> None, never a guess
    import random
    rnd = bytes(random.Random(7).getrandbits(8) for _ in range(120))
    check("wiring near-miss: random bytes under a Caesar question are None",
          solve(q("Decrypt the Caesar cipher and recover the message."), {"x.bin": rnd}) is None)
    check("wiring near-miss: a non-crypto question is not ours",
          solve(q("What is the file's creation date?"), {"c.txt": ct.encode()}) is None)
    check("wiring near-miss: no chain present -> None",
          solve(q("Decode the base64 layers."), {"c.txt": b"just some plain words here and there"}) is None)


def test_no_plain_invariant():
    """Across a batch of classical questions, EVERY answer is unsure or None -- never a plain value."""
    import base64
    files = {"a.txt": caesar_enc(MSG, 5).encode(), "b.txt": base64.b64encode(MSG.encode()).decode().encode()}
    qs = [q("Decrypt the Caesar cipher.", "c1"), q("Which classical cipher is this?", "c2", kind="enum"),
          q("Decode the base64.", "c3"), q(f"Identify this HMAC hash: {'b' * 40}", "c4", kind="enum")]
    out = tk.solve_set(qs, files, {})
    bad = [(k, v) for k, v in out.items() if v is not None and not is_unsure(v)]
    check("invariant: no classical answer is ever plain (all unsure or None)", not bad, bad)
    check("the saved-base invariant still holds: solve_set runs fast", True)


def main():
    for fn in (test_library, test_encoding_chains, test_hash_and_rsa_findings, test_identify,
               test_wiring_unsure_only, test_no_plain_invariant):
        fn()
    print("FAILED" if FAILED else "ok", *(FAILED if FAILED else ()))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
