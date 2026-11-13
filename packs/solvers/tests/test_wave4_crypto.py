#!/usr/bin/env python3
"""Offline tests of the wave-4 deterministic, never-wrong crypto primitives (tickets C9 and C5):

  C9a  keystream reuse / two-time pad (solvers/common/modern_crypto.py: keystream_from_known,
       two_time_pad; solvers/toolkits/modern_crypto.py: solve_reuse / solve_set) -- a known
       plaintext or a crib recovers the other message deterministically; plain only when a crib
       confirms, else None.
  C9b  Merkle-Damgard hash length extension (solvers/common/modern_crypto.py: md_hash, md_padding,
       length_extension, length_extension_verified; solvers/toolkits/modern_crypto.py:
       solve_length_ext / solve_set) -- the forged digest+message, computed without the secret,
       round-trips against a known secret; plain only when the secret length is stated AND the
       premise is proven offline, else None. Covers MD4, MD5, SHA-1, SHA-256 and SHA-512 (the five
       full-state hashes); the truncated SHA-224/384 are rejected as not length-extendable.
  C9c  MD5 / SHA-1 collision detection (solvers/common/modern_crypto.py: hash_collisions,
       _diff_structure; solvers/toolkits/modern_crypto.py: solve_collision / solve_set) -- two or
       more delivered members that share an MD5/SHA-1 digest are a finding; the colliding-member
       count and differing-block count are plain integers, the first-difference offset is a
       candidates pick, the hash algorithm an unsure pick, and the construction method is never
       named. Answered only when a collision is really present, so a plain answer can never be wrong.
  C5   TLS/QUIC decryption when the key log SHIPS in the delivery (solvers/toolkits/network.py:
       find_keylog, tls_decrypt, tls_decrypt_bundle) -- detect a bundled SSLKEYLOG member or a
       pcapng decryption-secrets block, decrypt through the sandbox's tshark; no keylog -> defer.

  .venv/bin/python tests/test_wave4_crypto.py

No network, no token, no docker: every fixture is synthesized here from a fixed seed, the hash
forgeries round-trip against hashlib, and the sandbox is faked (no tshark is ever run). Prints one
line per check and `ok` at the end; exits 1 when a check fails.
"""
import hashlib
import importlib.util
import json
import os
import struct
import sys
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
os.environ["CTF_PLATFORM_URL"] = "http://127.0.0.1:9/"       # nothing here makes a request; this makes sure
os.environ.pop("CTF_TOKEN", None)
os.environ["CTF_TESTING"] = "1"
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "solvers" / "common"))


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


tk = _load("wave4_tk", REPO / "solvers" / "toolkits" / "modern_crypto.py")
mc = tk.lib
nw = _load("wave4_nw", REPO / "solvers" / "toolkits" / "network.py")

FAILED = []
FLAG = "flag{3f9a1c0de5b7a2946d18c0ffee42beef}"
FLAG_RX = flagfmt.for_profile(event.load("huntress")).pattern   # the Huntress flag format, stated
RND = __import__("random").Random(20261023)


def rb(n):
    return bytes(RND.getrandbits(8) for _ in range(n))


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:400]}]"))
    if not ok:
        FAILED.append(label)


def q(question, aid="answer", kind="exact_text", pattern=None, **more):
    af = {"kind": kind}
    if pattern:
        af["pattern"] = pattern
    af.update({k: v for k, v in more.items() if k in ("syntax", "accepted_values")})
    return {"qid": aid, "answer_id": aid, "question": question, "answer_format": af}


def solve(question, files, **ctx):
    c = {"partial": {}}
    c.update(ctx)
    return tk.solve_set([question], files, c)[question["qid"]]


# ---- C9a: keystream reuse / two-time pad -------------------------------------------------------------

def test_c9a_library():
    ks = rb(96)
    p1 = b"Quarterly report: all accounts reconciled, no discrepancies found anywhere."
    p2 = FLAG.encode() + b" -- shred after reading"
    c1 = mc.xor(p1, ks[:len(p1)])
    c2 = mc.xor(p2, ks[:len(p2)])
    # the keystream recovered from a known pair decrypts the other ciphertext deterministically
    recovered_ks = mc.keystream_from_known(p1, c1)
    check("C9a lib: keystream_from_known is ct XOR pt", recovered_ks == bytes(a ^ b for a, b in zip(c1, p1)))
    check("C9a lib: the recovered keystream decrypts the other message", mc.xor(c2, recovered_ks[:len(p2)]) == p2)
    # a crib dragged across C1 XOR C2 reveals the OTHER plaintext at the crib's offset
    hits = mc.two_time_pad(c1, c2, p1[:len(p2)])
    check("C9a lib: two_time_pad at offset 0 recovers the other message's window", hits[0] == (0, p2))
    # a crib in the middle of one message reveals that window of the other, deterministically
    crib = p2[5:5 + 12]                 # a slice of message 2
    mid = dict(mc.two_time_pad(c1, c2, crib))
    check("C9a lib: a mid-message crib recovers the opposite window", mid.get(5) == p1[5:5 + 12])
    check("C9a lib: two_time_pad is empty for a crib longer than the overlap", mc.two_time_pad(c1[:8], c2[:8], p1[:20]) == [])
    # keystream_reuse: a whole known message, and its near-miss (a too-short known)
    check("C9a lib: keystream_reuse recovers the other from a whole known message", mc.keystream_reuse(p1, c1, c2) == p2)
    check("C9a lib near-miss: a known message shorter than the target is None", mc.keystream_reuse(p1[:10], c1[:10], c2) is None)


def test_c9a_solve_set():
    ks = rb(96)
    p1 = b"Dear Alice, the meeting is at noon tomorrow by the river bend near the mill."
    p2 = FLAG.encode() + b" -- destroy after reading this message"   # the flag is the first 38 bytes
    c1 = mc.xor(p1, ks[:len(p1)])
    c2 = mc.xor(p2, ks[:len(p2)])
    files = {"c1.enc": c1, "c2.enc": c2,
             "hint.json": json.dumps({"known_plaintext": p1[:len(FLAG)].decode()}).encode()}
    ask = q("The two ciphertexts reuse the same keystream (two-time pad). Recover the flag.", "reuse", pattern=FLAG_RX)
    check("C9a solve_set: a crib (shorter than the ciphertext) recovers the flag, plain", solve(ask, files) == FLAG)
    check("C9a solve_set near-miss: no crib and no known message -> None", solve(ask, {"c1.enc": c1, "c2.enc": c2}) is None)
    # a different keystream on the second message proves nothing
    bad = {"c1.enc": c1, "c2.enc": mc.xor(p2, ks[5:5 + len(p2)]),
           "hint.json": files["hint.json"]}
    check("C9a solve_set near-miss: a mismatched keystream -> None", solve(ask, bad) is None)
    # a WHOLE known message recovers the other deterministically; confirmed only by the flag FORM
    # (not a specific pattern) -> unsure, never plain
    whole = {"msg1.txt": p1, "msg1.enc": c1, "msg2.enc": mc.xor((FLAG + " and nothing else matters here").encode(), ks[:38 + 30])}
    got = solve(q("Both files share a keystream; the first plaintext is msg1.txt. Recover the flag (flag{...}) in message 2.", "say"), whole)
    check("C9a solve_set: a reuse recovery confirmed only by the flag form is unsure (never plain)",
          isinstance(got, str) and got.startswith(tk.SENTINEL), got)


# ---- C9b: hash length extension ----------------------------------------------------------------------
# MD4 (RFC 1320) known-answer vectors prove the pure-Python compression independently of any library,
# so the MD4 length-extension round-trip is not circular. hashlib has no md4.
MD4_KAT = {b"": "31d6cfe0d16ae931b73c59d7e0c089c0", b"a": "bde52cb31de33e46245e05fbdbd6fb24",
           b"abc": "a448017aaf21d8525fc10ae87aa6729d", b"message digest": "d9130a8164549fe818874806e1c7014b",
           b"abcdefghijklmnopqrstuvwxyz": "d79e1c308aa5bbcdeea8ed63df412da9",
           b"12345678901234567890123456789012345678901234567890123456789012345678901234567890": "e33b4ddc9c38f2199c3e7b164fcc0536"}


def _refhex(algo, b):
    """The digest of `algo` as hex, from hashlib where it has it and md_hash (KAT-proven) for md4."""
    return mc.md_hash("md4", b).hex() if algo == "md4" else hashlib.new(algo, b).hexdigest()


def test_c9b_library():
    for data, want in MD4_KAT.items():
        check(f"C9b lib: md_hash(md4) matches the RFC 1320 vector for {data[:16]!r}", mc.md_hash("md4", data).hex() == want)
    # md_hash matches hashlib across block boundaries (64-byte block for md5/sha1/sha256; 128 for sha512)
    for algo, hl in (("md5", hashlib.md5), ("sha1", hashlib.sha1), ("sha256", hashlib.sha256), ("sha512", hashlib.sha512)):
        ok = True
        for data in (b"", b"abc", b"a" * 55, b"a" * 56, b"a" * 64, b"a" * 111, b"a" * 112, b"a" * 119, b"a" * 128, rb(1000)):
            ok = ok and mc.md_hash(algo, data) == hl(data).digest()
        check(f"C9b lib: md_hash({algo}) matches hashlib across block boundaries", ok)
    # a glue padding ends a message on its own block boundary (64 bytes; 128 for sha512)
    for algo, block in (("md4", 64), ("md5", 64), ("sha1", 64), ("sha256", 64), ("sha512", 128)):
        for n in (0, 1, 55, 56, 63, 64, 111, 112, 127, 128):
            pad = mc.md_padding(n, algo)
            check(f"C9b lib: md_padding({algo}, {n}) lands on a {block}-byte boundary", (n + len(pad)) % block == 0 and pad[:1] == b"\x80")
    # the forgery round-trips against a known secret, for every extendable algorithm and several secret lengths
    for algo in ("md4", "md5", "sha1", "sha256", "sha512"):
        ok = True
        for slen in (0, 1, 8, 14, 16, 31, 55, 56, 63, 64, 100, 111, 112, 127, 128, 200):
            secret = rb(slen)
            data = b"user=guest&role=user"
            append = b"&role=admin"
            orig = _refhex(algo, secret + data)
            fmsg, fhex = mc.length_extension(algo, orig, data, append, slen)
            ok = ok and fmsg.startswith(data) and fmsg.endswith(append) and _refhex(algo, secret + fmsg) == fhex
        check(f"C9b lib: length_extension({algo}) forges a digest that round-trips (no secret used)", ok)
    # length_extension accepts hex or bytes for the original digest
    secret, data, append = rb(16), b"amount=10", b"&to=mallory"
    orig_hex = hashlib.sha256(secret + data).hexdigest()
    a, b = mc.length_extension("sha256", orig_hex, data, append, 16)
    c, d = mc.length_extension("sha256", bytes.fromhex(orig_hex), data, append, 16)
    check("C9b lib: length_extension takes the digest as hex or bytes", (a, b) == (c, d))
    check("C9b lib: length_extension_verified is True for the right secret", mc.length_extension_verified("sha256", secret, data, orig_hex))
    check("C9b lib: length_extension_verified is False for a wrong secret", not mc.length_extension_verified("sha256", secret + b"x", data, orig_hex))
    # a sha512 round-trip that also checks the verifier
    s5, d5 = rb(20), b"id=7"
    o5 = hashlib.sha512(s5 + d5).hexdigest()
    check("C9b lib: length_extension_verified holds for sha512", mc.length_extension_verified("sha512", s5, d5, o5))
    # guards: the truncated SHA-224/384 are NOT length-extendable and are rejected, as are wrong lengths
    for bad in (("sha224", "00" * 28, 8), ("sha384", "00" * 48, 8), ("sha512_256", "00" * 32, 8),
                ("sha512", "00" * 20, 8), ("md5", "00" * 8, 8), ("sha1", "00" * 20, -1)):
        raised = False
        try:
            mc.length_extension(bad[0], bad[1], b"x", b"y", bad[2])
        except ValueError:
            raised = True
        check(f"C9b lib: length_extension rejects {bad[0]} / bad input", raised)


def test_c9b_solve_set():
    secret = rb(16)
    data = b"amount=100&to=alice"
    append = b"&to=attacker&admin=1"
    for algo, rx in (("md4", r"^[0-9a-f]{32}$"), ("md5", r"^[0-9a-f]{32}$"), ("sha1", r"^[0-9a-f]{40}$"),
                     ("sha256", r"^[0-9a-f]{64}$"), ("sha512", r"^[0-9a-f]{128}$")):
        orig = _refhex(algo, secret + data)
        _, fhex = mc.length_extension(algo, orig, data, append, 16)
        files = {"token.json": json.dumps({"data": data.decode(), "mac": orig, "append": append.decode(),
                                           "secret": secret.hex(), "secret_length": 16}).encode()}
        ask = q(f"The MAC is {algo}(secret || data). Use a hash length extension attack to forge the MAC for the extended message.", "mac", pattern=rx)
        check(f"C9b solve_set: {algo} length-extension forgery, plain and verified", solve(ask, files) == fhex)
    # an unnamed md4 digest is disambiguated from md5 by the round-trip (only md4 verifies)
    orig4 = _refhex("md4", secret + data)
    _, fhex4 = mc.length_extension("md4", orig4, data, append, 16)
    files4 = {"t.json": json.dumps({"data": data.decode(), "mac": orig4, "append": append.decode(),
                                    "secret": secret.hex(), "secret_length": 16}).encode()}
    ask4 = q("Forge the MAC for the extended message with a hash length extension attack.", "mac", pattern=r"^[0-9a-f]{32}$")
    check("C9b solve_set: an md4 digest (no algo named) is disambiguated by the round-trip", solve(ask4, files4) == fhex4)
    # None without a stated secret length
    orig = hashlib.sha256(secret + data).hexdigest()
    ask = q("Forge the sha256 MAC with a length extension attack.", "mac", pattern=r"^[0-9a-f]{64}$")
    no_len = {"token.json": json.dumps({"data": data.decode(), "mac": orig, "append": append.decode(), "secret": secret.hex()}).encode()}
    check("C9b solve_set: no stated secret length -> None", solve(ask, no_len) is None)
    # None when the present secret does not verify (premise unproven)
    bad_sec = {"token.json": json.dumps({"data": data.decode(), "mac": orig, "append": append.decode(),
                                         "secret": (b"x" * 16).hex(), "secret_length": 16}).encode()}
    check("C9b solve_set: a secret that does not reproduce the digest -> None", solve(ask, bad_sec) is None)
    # None without an append to forge
    no_app = {"token.json": json.dumps({"data": data.decode(), "mac": orig, "secret": secret.hex(), "secret_length": 16}).encode()}
    check("C9b solve_set: no append/suffix to forge -> None", solve(ask, no_app) is None)
    # the forged MESSAGE itself, asked as hex (explicitly, so it is not the digest)
    fmsg, _ = mc.length_extension("sha256", orig, data, append, 16)
    files = {"t.json": json.dumps({"data": data.decode(), "mac": orig, "append": append.decode(),
                                   "secret": secret.hex(), "secret_length": 16}).encode()}
    ask_msg = q("Perform a hash length extension and return the forged message as hex.", "m", pattern=r"^[0-9a-f]+$")
    check("C9b solve_set: the forged message as hex, plain", solve(ask_msg, files) == fmsg.hex())


# ---- C9c: MD5 / SHA-1 collision detection -------------------------------------------------------------
# The public Wang 2004 identical-prefix MD5 collision: two distinct 128-byte strings, one MD5.
WANG_A = bytes.fromhex("d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70")
WANG_B = bytes.fromhex("d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70")


def test_c9c_collision_library():
    check("C9c lib: the Wang pair is distinct bytes with one MD5", WANG_A != WANG_B and hashlib.md5(WANG_A).digest() == hashlib.md5(WANG_B).digest())
    cols = mc.hash_collisions({"a.bin": WANG_A, "b.bin": WANG_B})
    check("C9c lib: hash_collisions finds exactly one MD5 collision group", len(cols) == 1 and cols[0]["algo"] == "md5")
    c = cols[0]
    check("C9c lib: the reported digest is the real shared MD5", c["digest"] == hashlib.md5(WANG_A).hexdigest())
    check("C9c lib: the group has two colliding members", c["count"] == 2)
    pair = c["pairs"][0]
    check("C9c lib: the pair is equal length and differs at byte 19", pair["equal_length"] and pair["first_diff_offset"] == 19)
    check("C9c lib: two aligned 64-byte blocks differ (blocks 0 and 1)", pair["diff_block_count"] == 2 and pair["diff_blocks"] == [0, 1])
    check("C9c lib: only md5/sha1 are scanned (no sha256 false finding)", all(x["algo"] in ("md5", "sha1") for x in cols))
    # a shared common suffix is preserved: the collision stands, the suffix is identical bytes
    suf = b"TRAILER BYTES THAT ARE IDENTICAL" * 4
    cols2 = mc.hash_collisions([("x", WANG_A + suf), ("y", WANG_B + suf)])
    check("C9c lib: a common suffix keeps the collision and is identical", cols2 and cols2[0]["pairs"][0]["common_suffix_len"] >= len(suf))
    # no collision among distinct, non-colliding files
    check("C9c lib: distinct non-colliding files are no collision", mc.hash_collisions({"p": b"hello", "q": b"world", "r": b"!!!"}) == [])
    # the same bytes delivered twice are one input, never a self-collision
    check("C9c lib: the same file twice is not a self-collision", mc.hash_collisions({"one.bin": WANG_A, "copy.bin": WANG_A}) == [])
    # _diff_structure marks an identical-prefix collision when only a middle block differs
    d = mc._diff_structure(b"A" * 64 + b"X" * 64 + b"B" * 64, b"A" * 64 + b"Y" * 64 + b"B" * 64, 64)
    check("C9c lib: _diff_structure flags an identical-prefix middle-block diff",
          d["identical_prefix"] and d["diff_blocks"] == [1] and d["first_diff_block_offset"] == 64 and d["diff_block_count"] == 1)


def test_c9c_collision_solve_set():
    col = {"file_a.bin": WANG_A, "file_b.bin": WANG_B}
    # how many members share the hash: a byte-unambiguous integer, plain
    check("C9c solve_set: the count of colliding files is plain (integer)",
          solve(q("How many files in this delivery share the same MD5 hash?", "c", kind="integer"), col) == "2")
    # how many 64-byte blocks differ: plain integer
    check("C9c solve_set: the differing-block count is plain (integer)",
          solve(q("How many 64-byte blocks differ between the two colliding files?", "c", kind="integer"), col) == "2")
    # the hash algorithm: an unsure pick over its spellings, never plain
    algo = solve(q("Which hashing algorithm do the two files collide under?", "c"), col)
    check("C9c solve_set: the collision algorithm is unsure (never plain)", isinstance(algo, str) and algo.startswith(tk.SENTINEL) and "collision_algo/md5" in algo)
    # the first-difference offset: different readings (byte/block/index) -> candidates, never plain
    off = solve(q("At what byte offset do the two colliding files first differ?", "c", kind="integer"), col)
    check("C9c solve_set: the first-difference offset is a candidates pick (never plain)",
          isinstance(off, str) and off.startswith(tk.SENTINEL) and "#candidates" in off and '"byte_offset","19"' in off)
    # the construction method/tool is never named
    check("C9c solve_set: the construction method is never named -> None", solve(q("Which tool or construction method produced this MD5 collision?", "c"), col) is None)
    # a generic yes/no collision question answers nothing plain
    check("C9c solve_set: a generic 'do these collide' question -> None", solve(q("Do these two files form an MD5 collision?", "c"), col) is None)
    # NO collision present: even a well-formed collision question answers None (no false finding)
    plain_files = {"a.txt": b"the quick brown fox", "b.txt": b"jumps over the lazy dog"}
    check("C9c solve_set: no collision present -> None (count)", solve(q("How many files share the same MD5 hash?", "c", kind="integer"), plain_files) is None)
    check("C9c solve_set: no collision present -> None (algo)", solve(q("Which hash algorithm do the files collide under?", "c"), plain_files) is None)
    # a pair-count variant is not answered (we report member count, not pair count)
    check("C9c solve_set: a count-of-pairs question -> None", solve(q("How many colliding pairs are there?", "c", kind="integer"), col) is None)


# ---- C5: TLS/QUIC decryption with a shipped key log --------------------------------------------------

KEYLOG = (b"# SSL/TLS secrets log file\n"
          b"CLIENT_RANDOM " + b"a" * 64 + b" " + b"b" * 96 + b"\n"
          b"CLIENT_RANDOM " + b"c" * 64 + b" " + b"d" * 96 + b"\n")
SERVER_OBJ = b"<html><body>the transferred secret file</body></html>"


def _shb():
    body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    blen = 8 + len(body) + 4
    return struct.pack("<II", 0x0A0D0D0A, blen) + body + struct.pack("<I", blen)


def _dsb(secret_bytes, stype=0x544C534B):
    pad = (-len(secret_bytes)) % 4
    body = struct.pack("<II", stype, len(secret_bytes)) + secret_bytes + b"\x00" * pad
    blen = 8 + len(body) + 4
    return struct.pack("<II", 0x0000000A, blen) + body + struct.pack("<I", blen)


class _FakeDown(RuntimeError):
    pass


class _FakeSandbox:
    SandboxDown = _FakeDown

    def __init__(self, mode="ok"):
        self.mode = mode

    def run(self, tool, args, inputs=None, timeout=None):
        assert tool == "tshark" and "tls.keylog_file:{in1}" in args and len(inputs) == 2

        class R:
            note = ""
        r = R()
        if self.mode == "down":
            raise _FakeDown("the sandbox is not up")
        if "--export-objects" in args:
            r.code, r.stdout, r.stderr, r.files = 0, b"", b"", {"objects/report.html": SERVER_OBJ}
        else:
            r.code = 0
            r.stdout = b"3\tGET\tvault.example\t/secret.txt\t200\thttps://vault.example/secret.txt\n"
            r.stderr, r.files = b"", {}
        return r


def _with_sandbox(mode, fn):
    orig = nw._sandbox
    nw._sandbox = lambda: _FakeSandbox(mode)
    try:
        return fn()
    finally:
        nw._sandbox = orig


def test_c5_find_keylog():
    pcapng = _shb() + _dsb(KEYLOG)
    check("C5: a pcapng with a decryption-secrets block is a capture", nw.is_capture(pcapng))
    kl = nw.find_keylog({"traffic.pcap": _shb(), "sslkeylog.txt": KEYLOG})
    check("C5: find_keylog detects a bundled SSLKEYLOG member", len(kl) == 1 and kl[0][1] == KEYLOG)
    kl2 = nw.find_keylog({"capture.pcapng": pcapng})
    check("C5: find_keylog reads a pcapng decryption-secrets block", len(kl2) == 1 and b"CLIENT_RANDOM" in kl2[0][1])
    check("C5: find_keylog is empty when no key material ships", nw.find_keylog({"t.pcap": _shb(), "notes.txt": b"nothing here"}) == [])


def test_c5_decrypt():
    r = _with_sandbox("ok", lambda: nw.tls_decrypt(_shb(), KEYLOG))
    check("C5: tls_decrypt reports decrypted when application data parses", r.ok and r.decrypted)
    check("C5: tls_decrypt reads the decrypted HTTP request", bool(r.http) and r.http[0].host == "vault.example" and r.http[0].uri == "/secret.txt")
    check("C5: tls_decrypt hashes an exported object (self-validating, plain-eligible)",
          bool(r.objects) and r.objects[0].sha256 == hashlib.sha256(SERVER_OBJ).hexdigest())
    rd = _with_sandbox("down", lambda: nw.tls_decrypt(_shb(), KEYLOG))
    check("C5: tls_decrypt with the sandbox down -> not ok, not decrypted", (not rd.ok) and (not rd.decrypted))


def test_c5_bundle():
    pcapng = _shb() + _dsb(KEYLOG)
    rows = _with_sandbox("ok", lambda: nw.tls_decrypt_bundle({"traffic.pcap": _shb(), "sslkeylog.txt": KEYLOG}))
    check("C5: tls_decrypt_bundle decrypts with a bundled keylog member", len(rows) == 1 and rows[0].decrypted and rows[0].keylog_source == "bundle member")
    rows2 = _with_sandbox("ok", lambda: nw.tls_decrypt_bundle({"capture.pcapng": pcapng}))
    check("C5: tls_decrypt_bundle decrypts with a pcapng decryption-secrets block",
          len(rows2) == 1 and rows2[0].decrypted and rows2[0].keylog_source == "pcapng decryption secrets")
    rows3 = nw.tls_decrypt_bundle({"traffic.pcap": _shb()})
    check("C5: no keylog in the bundle -> defer (decrypted False, unchanged)",
          len(rows3) == 1 and rows3[0].decrypted is False and "no key log" in rows3[0].note)
    check("C5: tls_decrypt_bundle with no capture -> []", nw.tls_decrypt_bundle({"readme.txt": b"hello"}) == [])


def main():
    test_c9a_library()
    test_c9a_solve_set()
    test_c9b_library()
    test_c9b_solve_set()
    test_c9c_collision_library()
    test_c9c_collision_solve_set()
    test_c5_find_keylog()
    test_c5_decrypt()
    test_c5_bundle()
    print("ok" if not FAILED else f"FAILED {len(FAILED)}: {FAILED}")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
