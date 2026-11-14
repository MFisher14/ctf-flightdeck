#!/usr/bin/env python3
"""The modern_crypto toolkit on real artifacts: the Huntress 2024 RSA challenge as its write-up saved the
service's numbers, the Huntress 2025 'Angler' Blowfish note and Entra token, RsaCtfTool's example keys
(every factorisation checked here by multiplying it out, every message by encrypting it again), and the
Cryptopals set 1 and 2 files whose answers are public.

  .venv/bin/python tests/real/test_real_modern_crypto.py    the real-file groups SKIP when challenges/_realdata/modern_crypto is absent

Offline; the cache is filled by tests/real/fetch_c.py. The truth of each file is in the manifest's `what`.
"""
import base64
import hashlib
import math
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import realdata_c as R  # noqa: E402

tk, ROOT = R.start("modern_crypto")
lib = tk.lib
check, q = R.check, R.q
FLAG_RSA = "flag{cf614b15ac1dd461a2e48afdfe21b8e8}"
LYRICS = "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell"


def solve(files, *questions, label=None):
    return R.timed(f"solve_set on {label or ', '.join(files)}", tk.solve_set, list(questions), files, {})


def first(value):
    u = R.unsure(value)
    return u[1][0][1] if u else value


def built_in_memory():
    """What the real files changed, on material built here: these run with no cache."""
    from Crypto.Cipher import AES, Blowfish
    from Crypto.Util.Padding import pad
    text = b"The harbour lights go out at nine; the ferry leaves at ten.\n"
    ct = AES.new(b"0123456789abcdef", AES.MODE_CBC, iv=bytes(16)).encrypt(pad(text, 16))
    files = {"note.b64": base64.b64encode(ct)}
    got = tk.solve_set([q("a", 'The note is AES-128-CBC encrypted under the key "0123456789abcdef" with an all-zero IV. What is the plaintext?'),
                        q("b", "The note is AES-128-CBC encrypted. What is the plaintext?"),
                        q("c", 'The note is AES-128-CBC encrypted under the key "0123456789abcdeX" with an all-zero IV. What is the plaintext?')], files, {})
    check("a key and a zero IV stated in the question decrypt the file; unsure, the text offered", first(got["a"]) == text.decode().strip() and not R.plain(got["a"]), got["a"])
    check("with no key stated, and with a wrong key stated, nothing is answered", got["b"] is None and got["c"] is None, (got["b"], got["c"]))
    check("question_fields: quoted, after a colon, 'key and IV are both', zero IV",
          tk.question_fields('under the key "YELLOW SUBMARINE"') == [("key", "YELLOW SUBMARINE")]
          and tk.question_fields("key: 42 6c 6f 77, iv: 00 01. What is it?") == [("key", "42 6c 6f 77"), ("iv", "00 01")]
          and tk.question_fields("the key and IV are both 42 6c 6f 77 66 69 73 68. What?") == [("key", "42 6c 6f 77 66 69 73 68"), ("iv", "42 6c 6f 77 66 69 73 68")]
          and tk.question_fields("with an IV of sixteen zero bytes") == [("iv", "00" * 16)]
          and tk.question_fields("What is the key?") == [] and tk.question_fields("Which key is used?") == [])
    bf = Blowfish.new(b"Blowfish", Blowfish.MODE_CBC, iv=b"Blowfish").encrypt(pad(text, 8))
    got = tk.solve_set([q("a", "note.hex is Blowfish (CBC) encrypted; the key and IV are both 42 6c 6f 77 66 69 73 68. What is the decrypted message?"),
                        q("b", "note.hex is encrypted; the key and IV are both 42 6c 6f 77 66 69 73 68. What is the decrypted message?")], {"note.hex": bf.hex().encode()}, {})
    check("Blowfish is tried only when it is named", first(got["a"]) == text.decode().strip() and got["b"] is None, got)
    p = tk.Proof(q("x", "The plaintext starts with \"I'm back and I'm ringin'\". What is the key?"))
    check("a crib in double quotes may hold apostrophes", p.starts == ["I'm back and I'm ringin'"], p.starts)
    lines = ["aa" * 32, ("0011223344556677" * 2) * 3 + "ff" * 16, "bb" * 16 + "cc" * 15 + "dd"]
    lines[0] = hashlib.sha256(b"a").hexdigest() + hashlib.sha256(b"b").hexdigest()
    got = tk.solve_set([q("n", "One of these ciphertexts was encrypted with ECB. Which line is it?")], {"cts.txt": "\n".join(lines).encode()}, {})
    u = R.unsure(got["n"])
    check("which line is ECB: the one line that repeats a block, unsure between counting from 1 and from 0",
          bool(u) and u[0] == "modern_crypto.ecb_line/index" and [v for _, v in u[1]][:2] == ["2", "1"], got)
    two = [lines[1], lines[1][::-1], lines[2]]
    two[1] = ("8899aabbccddeeff" * 2) * 2 + "ee" * 16
    got = tk.solve_set([q("n", "One of these ciphertexts was encrypted with ECB. Which line is it?")], {"cts.txt": "\n".join(two).encode()}, {})
    check("two lines that repeat a block: None", got == {"n": None}, got)
    # raw ciphertext files beside key files, nothing saying which goes with which
    from Crypto.PublicKey import RSA
    m = int.from_bytes(b"three recipients, one small exponent, one message", "big")
    keys, files = [], {}
    for i in range(3):
        k = RSA.generate(1024, e=3)
        keys.append(k)
        files[f"key{i}.pem"] = k.publickey().export_key()
    order = (2, 0, 1)
    for j, i in enumerate(order):
        files[f"blob_{j}.bin"] = pow(m, 3, keys[i].n).to_bytes(128, "big")
    rs = tk.solve_rsa(tk.material(files), time.monotonic() + 5)
    check("Hastad over three key files and three raw ciphertext files, pairing found by the exact root",
          [r.attack for r in rs] == ["hastad"] and any(b"one small exponent" in v for _, v in rs[0].messages), [(r.attack, r.messages[:1]) for r in rs])
    files["blob_2.bin"] = bytes(127) + b"\x09"
    check("with one ciphertext that is not of the message: no exact root, nothing", tk.solve_rsa(tk.material(files), time.monotonic() + 5) == [])
    n = 54311 * lib_next_prime(1 << 300)
    got = lib.rsa_attack(n, 65537, time.monotonic() + 2)
    check("a 16-bit factor is trial division (small_factor), not Pollard p-1", got is not None and got[2] == "small_factor" and got[1][0] == 54311, got and got[2])


def lib_next_prime(v):
    v |= 1
    while not lib.is_prime(v):
        v += 2
    return v


def huntress_2024_rsa():
    d = R.data(ROOT, "huntress/strive_marish_solve.py")
    files = {"output.py": d}
    got = solve(files, q("m", "What is the decrypted message?"), q("h", "What is the MD5 of the plaintext?"), q("b", "How many bits is the modulus?", kind="integer"),
                q("a", "Which attack breaks the key?"))
    check("Strive Marish: the message is the write-up's flag (unsure: no pattern in the question)", first(got["m"]) == FLAG_RSA and not R.plain(got["m"]), got["m"])
    check("Strive Marish: MD5 of the plaintext and the modulus size are plain", got["h"] == hashlib.md5(FLAG_RSA.encode()).hexdigest() and got["b"] == "1024", (got["h"], got["b"]))
    check("Strive Marish: a key that is given is no attack", got["a"] is None, got["a"])
    got = solve(files, q("f", "What is the flag?", pattern=r"^flag\{[0-9a-f]{32}\}$"))
    check("Strive Marish: with the flag's pattern in the answer format the flag is plain", got["f"] == FLAG_RSA, got)
    dr = R.drill(files, [q("flag", "Decrypt the message. What is the flag?")])
    check("Strive Marish, end to end: the triage map ranks modern_crypto first", dr["winner"] == "modern_crypto", dr["rank"])
    two = R.data(ROOT, "huntress/strive_marish_solve.txt")
    got = solve({"writeup.txt": two}, q("m", "What is the decrypted message?"), q("b", "How many bits is the modulus?", kind="integer"), label="the write-up text")
    check("the write-up text holds two sessions' parameters: contradicting numbers answer nothing", got == {"m": None, "b": None}, got)


def huntress_2025_angler():
    d = R.data(ROOT, "huntress/angler_scribbles.dat")
    want = R.data(ROOT, "huntress/angler_scribbles2.dat")
    ask = "scribbles.dat is Blowfish (CBC) encrypted; the key and IV are both 42 6c 6f 77 66 69 73 68. "
    got = solve({"scribbles.dat": d}, q("m", ask + "What is the decrypted message?"), q("h", ask + "What is the MD5 of the plaintext?"),
                q("n", "What is the decrypted message?"))
    text = first(got["m"]) or ""
    check("Angler: the Blowfish layer decrypts to the write-up's scribbles2 text", bool(text) and text.strip() == want.decode().strip(), (text[:60], want[:60]))
    check("Angler: without the key in the question nothing is answered", got["n"] is None, got["n"])
    u = R.unsure(got["h"])
    hashes = [v for _, v in u[1]] if u else [got["h"]]
    check("Angler: the MD5 of that plaintext is among the answers offered (as text, or with its line end)",
          bool({hashlib.md5(want).hexdigest(), hashlib.md5(want.strip()).hexdigest(), hashlib.md5(want.rstrip(b"\n")).hexdigest()} & set(hashes)), got["h"])
    tok = R.data(ROOT, "huntress/angler_access_token.json")
    got = solve({"access_token.json": tok}, q("alg", "Which algorithm signs the JWT access token?"), q("aud", "What is the aud claim of the JWT?"),
                q("exp", "What is the exp claim of the token?", kind="integer"), q("s", "What is the secret that signs the JWT?"))
    check("Angler token: alg RS256 and aud unsure, exp plain, no secret for an RS256 token",
          R.offers(got["alg"], "RS256") and R.offers(got["aud"], "https://graph.microsoft.com/") and got["exp"] == "1762673349" and got["s"] is None, got)


def rsactf_keys():
    from Crypto.PublicKey import RSA

    def key(name):
        return RSA.import_key(R.data(ROOT, "rsactf/" + name))

    def cint(name, n):
        b = R.data(ROOT, "rsactf/" + name)
        return int.from_bytes(b, "big")

    for pub, cipher, attack, text in (("wiener.pub", "wiener.cipher", "wiener", "GREHACK_WIENER_ATTACK_ARE_GREAT_WITH_SMALL_D"),
                                      ("small_q.pub", "small_q.cipher", "small_factor", "hQdK+dKleMJqth/dofWyFaiWp3PW7jil"),
                                      ("close_primes.pub", "close_primes.cipher", "fermat", "XtCgoEKksjKFWlqOSxqsEhK/+tsr1k5c")):
        k = key(pub)
        files = {pub: R.data(ROOT, "rsactf/" + pub), cipher: R.data(ROOT, "rsactf/" + cipher)}
        rs = R.timed(f"solve_rsa on {pub}", tk.solve_rsa, tk.material(files), time.monotonic() + 1.5)
        ok = len(rs) == 1 and rs[0].attack == attack and math.prod(rs[0].factors) == k.n and all(lib.is_prime(f) for f in rs[0].factors)
        check(f"{pub}: {attack}, and the factors multiply to n", ok, [(r.attack, len(r.factors or [])) for r in rs])
        got = solve(files, q("m", "What is the decrypted message?"), q("a", "Which attack breaks the key?"))
        check(f"{pub}: the message {text!r} (unsure), the attack a label (unsure)", first(got["m"]) == text and not R.plain(got["m"]) and not R.plain(got["a"])
              and got["a"] is not None, got)
        if attack != "wiener":          # a raw message: encrypting it again gives the file's ciphertext
            check(f"{pub}: m^e mod n is the ciphertext file", pow(int.from_bytes(text.encode(), "big"), k.e, k.n) == cint(cipher, k.n))
    k = key("boneh_durfee.pub")
    got = lib.rsa_attack(k.n, k.e, time.monotonic() + 1.5)
    check("boneh_durfee.pub: inside Wiener's bound; d inverts e", got is not None and got[2] == "wiener" and math.prod(got[1]) == k.n
          and pow(pow(2, k.e, k.n), got[0], k.n) == 2, got and got[2])
    k3, k8, k1 = key("commonfactor3.pub"), key("commonfactor8.pub"), key("commonfactor1.pub")
    files = {n: R.data(ROOT, "rsactf/" + n) for n in ("commonfactor3.pub", "commonfactor8.pub")}
    rs = tk.solve_rsa(tk.material(files), time.monotonic() + 1.5)
    g = math.gcd(k3.n, k8.n)
    check("commonfactor3 and commonfactor8: the shared prime is math.gcd's", len(rs) == 2 and all(r.attack == "shared_prime" and g in r.factors for r in rs), [r.attack for r in rs])
    got = solve(files, q("a", "Which weakness do the two keys share?"), q("p", "What is the smaller prime factor of n?", kind="integer"))
    check("commonfactor3/8: the weakness is a label (unsure); 'the smaller prime of n' with two moduli is None", not R.plain(got["a"]) and got["a"] is not None and got["p"] is None, got)
    files = {n: R.data(ROOT, "rsactf/" + n) for n in ("commonfactor1.pub", "commonfactor3.pub")}
    check("commonfactor1 and commonfactor3 share nothing (gcd 1): nothing proven", math.gcd(k1.n, k3.n) == 1 and tk.solve_rsa(tk.material(files), time.monotonic() + 1.0) == [])
    files = {"conspicuous.priv": R.data(ROOT, "rsactf/conspicuous.priv")}
    kp = key("conspicuous.priv")
    got = solve(files, q("p", "What is the smaller prime factor of n?", kind="integer"), q("b", "How many bits is the modulus?", kind="integer"))
    check("conspicuous.priv: the smaller prime and the size, as the key file has them", got["p"] == str(min(kp.p, kp.q)) and got["b"] == str(kp.n.bit_length()), got)
    files = {"pollard_rho.pub": R.data(ROOT, "rsactf/pollard_rho.pub")}
    got = solve(files, q("p", "What is the smaller prime factor of n?", kind="integer"), q("a", "Which attack breaks the key?"))
    check("pollard_rho.pub: not factored inside the budget, so nothing is answered", got == {"p": None, "a": None}, got)
    files = {n: R.data(ROOT, "rsactf/" + n) for n in ("small_exponent.pub", "small_exponent.cipher")}
    got = solve(files, q("m", "What is the decrypted message?"))
    check("small_exponent: no exact cube root exists for this pair, so nothing is answered", got == {"m": None}, got)


def cryptopals():
    d7, d10, d6, d8, d4 = (R.data(ROOT, f"cryptopals/{n}.txt") for n in (7, 10, 6, 8, 4))
    got = solve({"7.txt": d7}, q("m", 'The file is encrypted with AES-128 in ECB mode under the key "YELLOW SUBMARINE". What is the plaintext?'),
                q("n", "The file is encrypted with AES-128 in ECB mode. What is the plaintext?"))
    check("Cryptopals 7: AES-128-ECB under the key the question states", (first(got["m"]) or "").startswith(LYRICS) and got["n"] is None, str(got["m"])[:120])
    got = solve({"10.txt": d10}, q("m", 'The file is AES-128-CBC encrypted, key "YELLOW SUBMARINE", IV of sixteen zero bytes. What is the plaintext?'))
    check("Cryptopals 10: AES-128-CBC, zero IV", (first(got["m"]) or "").startswith(LYRICS), str(got["m"])[:120])
    got = solve({"6.txt": d6}, q("k", "The file is XORed with a repeating key. The plaintext starts with \"I'm back and I'm ringin' the bell\". What is the key?"),
                q("m", "The message was XOR encrypted with the key 'Terminator X: Bring the noise'. What is the plaintext?"),
                q("n", "The file is repeating-key XOR encrypted. What is the XOR key?"))
    check("Cryptopals 6: the key from the question's crib, as text first", first(got["k"]) == "Terminator X: Bring the noise" and not R.plain(got["k"]), got["k"])
    check("Cryptopals 6: the text under the stated key; with no crib and no key, the keyless break is offered as an UNSURE candidate (never plain)",
          (first(got["m"]) or "").startswith(LYRICS) and bool(R.unsure(got["n"])) and not R.plain(got["n"])
          and first(got["n"]) == "Terminator X: Bring the noise", (str(got["m"])[:80], got["n"]))
    got = solve({"8.txt": d8}, q("n", "One of these ciphertexts was encrypted with ECB. Which line is it?"), q("m", "Which block cipher mode leaks repeated blocks here?"))
    u = R.unsure(got["n"])
    line = d8.decode().split("\n")[132]
    check("Cryptopals 8: line 133 (from 1), offered with 132 (from 0) and the line itself",
          bool(u) and [v for _, v in u[1]] == ["133", "132", line] and line.count("08649af70dc06f4fd5d2d69c744cd283") == 4, got["n"] and got["n"][:120])
    check("Cryptopals 8: the mode is a label (unsure), ecb first", first(got["m"]) == "ecb" and not R.plain(got["m"]), got["m"])
    got = solve({"4.txt": d4}, q("m", "One of the lines has been encrypted with single-byte XOR. What is the decrypted message?"))
    check("Cryptopals 4: 327 lines and no crib: nothing is proven, so nothing is answered (agent work: mc.xor per line)", got == {"m": None}, got)


for fn in (built_in_memory, huntress_2024_rsa, huntress_2025_angler, rsactf_keys, cryptopals):
    R.section(fn)
sys.exit(R.finish("test_real_modern_crypto"))
