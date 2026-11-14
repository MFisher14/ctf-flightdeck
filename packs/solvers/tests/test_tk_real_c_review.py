#!/usr/bin/env python3
"""Offline tests of the review fixes to the group-c toolkits (web_evidence, carve_stego, modern_crypto, web).

  .venv/bin/python tests/test_tk_real_c_review.py

Each group is a question that narrows, negates or qualifies what a toolkit matches, and that came back as a
wrong plain answer (or a wrong offer) before the fix. No network, no token, no cache: every fixture is made
here in memory. Prints one line per check and `ok` at the end; exits 1 when a check fails.
"""
import base64
import hashlib
import hmac
import io
import json
import os
import struct
import sys
import zipfile
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "real"))
import realdata_c as R                  # noqa: E402  (points the environment at a dead port and an empty folder)

# ------------------------------------------------------------------ fixture builders
# Carried from the archived tests/test_tk_carve_stego.py (Huntress), which imported day data at module
# level: only the in-memory FAT12 / PNG / ZIP builders this file uses (PNG trimmed to filter 0 RGB, volume
# label renamed; the files, clusters and deleted entry are as before).

PNG_SIG = b"\x89PNG\r\n\x1a\n"


def _chunk(typ: bytes, body: bytes) -> bytes:
    return struct.pack(">I", len(body)) + typ + body + struct.pack(">I", zlib.crc32(typ + body) & 0xFFFFFFFF)


def make_png(w, h, rgb: bytes) -> bytes:
    """An 8-bit RGB PNG written by hand, every row with filter type 0."""
    stride = w * 3
    raw = b"".join(b"\x00" + rgb[y * stride:(y + 1) * stride] for y in range(h))
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
    return PNG_SIG + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", zlib.compress(raw)) + _chunk(b"IEND", b"")


def make_zip(members: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, body in members.items():
            z.writestr(name, body)
    return buf.getvalue()


def _lfn_checksum(short11: bytes) -> int:
    s = 0
    for c in short11:
        s = (((s & 1) << 7) + (s >> 1) + c) & 0xFF
    return s


def _lfn_entries(long_name: str, short11: bytes, deleted=False) -> bytes:
    units = long_name.encode("utf-16-le") + b"\x00\x00"
    units += b"\xff" * ((-len(units)) % 26)
    pieces = [units[i:i + 26] for i in range(0, len(units), 26)]
    out = b""
    for n in range(len(pieces), 0, -1):
        p = pieces[n - 1]
        seq = n | (0x40 if n == len(pieces) else 0)
        out += (bytes([0xE5 if deleted else seq]) + p[0:10] + b"\x0f\x00" + bytes([_lfn_checksum(short11)])
                + p[10:22] + b"\x00\x00" + p[22:26])
    return out


def _dirent(short11: bytes, attr, cluster, size, deleted=False) -> bytes:
    name = (b"\xe5" + short11[1:]) if deleted else short11
    date, tm = ((2026 - 1980) << 9) | (10 << 5) | 8, (9 << 11) | (30 << 5)
    return name + bytes([attr, 0, 0]) + struct.pack("<HHHHHHHI", tm, date, date, 0, tm, date, cluster, size)


def make_fat12() -> tuple:
    """(image, facts) of a 1.44 MB FAT12 floppy: README.TXT, DOCS/NOTE.TXT, and a deleted file
    'secret-plans.txt' (long name kept, clusters intact, FAT entries freed)."""
    img = bytearray(2880 * 512)
    bpb = b"\xeb\x3c\x90" + b"MSDOS5.0" + struct.pack("<HBHBHHBHHHII", 512, 1, 1, 2, 224, 2880, 0xF0, 9, 18, 2, 0, 0)
    bpb += bytes([0, 0, 0x29]) + struct.pack("<I", 0x1234ABCD) + b"TESTDISK   " + b"FAT12   "
    img[:len(bpb)] = bpb
    img[510:512] = b"\x55\xaa"
    fat = [0xFF0, 0xFFF] + [0] * 30

    def put(cluster, body):
        off = (33 + cluster - 2) * 512
        img[off:off + len(body)] = body

    readme = b"This disk holds nothing of interest.\r\n"
    secret = b"flag{deleted_but_not_gone}\r\n" + b"x" * 700          # two clusters
    note = b"see the other folder\r\n"
    put(2, readme)
    fat[2] = 0xFFF
    put(3, secret)                                                   # clusters 3 and 4: freed
    docs = (_dirent(b".          ", 0x10, 5, 0) + _dirent(b"..         ", 0x10, 0, 0)
            + _dirent(b"NOTE    TXT", 0x20, 6, len(note)))
    put(5, docs)
    fat[5] = 0xFFF
    put(6, note)
    fat[6] = 0xFFF
    root = _dirent(b"TESTDISK   ", 0x08, 0, 0)
    root += _dirent(b"README  TXT", 0x20, 2, len(readme))
    root += (_lfn_entries("secret-plans.txt", b"SECRET~1TXT", deleted=True)
             + _dirent(b"SECRET~1TXT", 0x20, 3, len(secret), deleted=True))
    root += _dirent(b"DOCS       ", 0x10, 5, 0)
    img[19 * 512:19 * 512 + len(root)] = root
    table = bytearray(9 * 512)
    for c in range(0, len(fat), 2):
        a, b = fat[c], fat[c + 1]
        table[c // 2 * 3:c // 2 * 3 + 3] = bytes([a & 0xFF, (a >> 8) | ((b & 0xF) << 4), b >> 4])
    img[512:512 + len(table)] = table
    img[10 * 512:10 * 512 + len(table)] = table
    return bytes(img), {"readme": readme, "secret": secret, "note": note}

check, q = R.check, R.q


def plain(v):
    return R.plain(v)


APP = b'''from flask import Flask, request
import sqlite3
app = Flask(__name__)

@app.route("/health")
def health():
    return "ok"

@app.route("/search", methods=["GET"])
def search():
    term = request.args.get("q")
    db = sqlite3.connect("x.db")
    rows = db.execute(f"SELECT * FROM items WHERE name = '{term}'").fetchall()
    return str(rows)

@app.route("/login", methods=["POST"])
def login():
    user = request.form.get("username")
    pw = request.form["password"]
    db = sqlite3.connect("x.db")
    row = db.execute("SELECT * FROM users WHERE u = ? AND p = ?", (user, pw)).fetchone()
    return "ok" if row else "no"
'''


def web_evidence_qualified():
    we = R.load("web_evidence")
    straight = {"r": ("Which route is vulnerable?", "/search"), "p": ("Which parameter is vulnerable to SQL injection?", "q"),
                "m": ("Which HTTP method does the vulnerable endpoint use?", "GET"), "l": ("What line is the vulnerable call on?", "13")}
    got = we.solve_set([q(k, t) for k, (t, _) in straight.items()], {"app.py": APP}, {})
    check("web_evidence: the one sink's route, parameter, method and line are still answered",
          all(got[k] == want for k, (_, want) in straight.items()), got)
    twisted = ["Which route is not vulnerable?", "Which route is safe from SQL injection?", "Which route uses parameterised queries?",
               "Which parameter of the login route is injectable?", "What is the second parameter the login route reads?",
               "What parameter does the health route read?", "What is the vulnerable route in the patched version?",
               "Which route isn't vulnerable?", "Which HTTP method does the /login endpoint use?",
               "On what line is the query that is not injectable?", "Which other route is vulnerable?"]
    got = we.solve_set([q(f"t{i}", t) for i, t in enumerate(twisted)], {"app.py": APP}, {})
    bad = {twisted[i]: got[f"t{i}"] for i in range(len(twisted)) if got[f"t{i}"] is not None}
    check("web_evidence: a negated, ranked or other-route source question is None, never the sink's fact", not bad, bad)
    row = '10.0.0.5 - - [10/Oct/2026:13:55:36 +0000] "GET /a HTTP/1.1" 200 12 "-" "curl/8"'
    log = ("\n".join([row] * 3 + ["", ""] + [row] * 4) + "\n").encode()
    got = we.solve_set([q("n", "How many requests are in the log?", kind="integer"), q("l", "How many lines are in the file?", kind="integer")],
                       {"access.log": log}, {})
    check("web_evidence: 7 requests in a log of 9 lines: the requests are counted, the lines are not answered", got == {"n": "7", "l": None}, got)


def _jwt() -> bytes:
    def b64(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    h = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "k1"}).encode())
    p = b64(json.dumps({"sub": "alice", "role": "admin", "exp": 1762673349, "iat": 1762670000}).encode())
    return (h + "." + p + "." + b64(hmac.new(b"secret", (h + "." + p).encode(), hashlib.sha256).digest())).encode()


def tokens_negated():
    files = {"token.txt": _jwt()}
    for key in ("web_evidence", "web"):
        mod = R.load(key)
        got = mod.solve_set([q("a", "What algorithm does the JWT use?"), q("n", "What algorithm does the JWT not use?"),
                             q("s", "What algorithm should the JWT use instead?"), q("k", "Which kid isn't in the token header?")], files, {})
        check(f"{key}: the JWT's alg is still plain", got["a"] == "HS256", got)
        check(f"{key}: the alg it does NOT use, or should use, is None", got["n"] is None and got["s"] is None and got["k"] is None, got)


def rf_and_malconfig_negated():
    rf = R.load("rf")
    sub = (b"Filetype: Flipper SubGhz Key File\nVersion: 1\nFrequency: 433920000\nPreset: FuriHalSubGhzPresetOok650Async\n"
           b"Protocol: Princeton\nBit: 24\nKey: 00 00 00 00 00 95 D5 D4\nTE: 400\n")
    got = rf.solve_set([q("f", "What frequency was the signal captured at?"), q("b", "How many bits is the key?", kind="integer"),
                        q("nf", "What frequency was NOT used?"), q("np", "Which protocol is not used?"), q("t", "What is twice the TE?"),
                        q("o", "What is the frequency of the other remote?")], {"gate.sub": sub}, {})
    check("rf: the frequency is still offered and the bit count plain", R.offers(got["f"], "433920000") and got["b"] == "24", got)
    check("rf: a negated, other-device or arithmetic question gets no offer (an offer would spend the field's names)",
          all(got[k] is None for k in ("nf", "np", "t", "o")), got)
    ml = R.load("malconfig")
    ini = (b"[HTTP]\r\nGatewayAddress=evil.example.net:443\r\nGSK=GM;O@EDFHB:P>MBN\r\nSecondaryGateway=backup.example.org:443\r\n"
           b"Port=443\r\n[_License]\r\nlicensee=EVALUSION\r\nserial_no=NSM165348\r\n")
    got = ml.solve_set([q("c", "What is the C2 server address?"), q("s", "What is the secondary gateway?"),
                        q("n", "Which gateway is not the primary one?"), q("h", "How many C2 servers are configured?")], {"client32.ini": ini}, {})
    check("malconfig: the gateway is still offered, unsure", R.offers(got["c"], "evil.example.net:443") and not plain(got["c"]), got)
    check("malconfig: the secondary gateway, the one that is NOT primary and a count are not answered with the primary",
          got["s"] is None and got["n"] is None and got["h"] is None, got)


def _mbr(parts) -> bytes:
    """A disk image: an MBR and the given [(type byte, bytes)] partitions, each on a sector boundary."""
    table, body, lba = b"", b"", 1
    for ptype, blob in parts:
        blob += bytes((-len(blob)) % 512)
        table += struct.pack("<B3sB3sII", 0, b"\0\0\0", ptype, b"\0\0\0", lba, len(blob) // 512)
        body += blob
        lba += len(blob) // 512
    return bytes(446) + table.ljust(64, b"\0") + b"\x55\xaa" + body


def carve_stego_named_and_partitions():
    cs = R.load("carve_stego")
    img, facts = make_fat12()
    want = hashlib.sha256(facts["readme"]).hexdigest()
    got = cs.solve_set([q("h", "What is the SHA-256 of README.TXT on the disk image?")], {"disk.img": img}, {})
    check("carve_stego: the hash OF a named live file in a disk image is still plain", got["h"] == want, got)
    twisted = ["What is the SHA-256 of the disk image that holds README.TXT?", "What is the SHA-256 of the data hidden inside README.TXT?",
               "What is the SHA-256 of the deleted version of README.TXT?", "What is the SHA-256 of the file that is not README.TXT?",
               "What is the SHA-256 of the first line of README.TXT?", "What is the SHA-256 of the file stored next to README.TXT?",
               "README.TXT names a password; what is the SHA-256 of it?", "What is the SHA-256 of the slack space after README.TXT?"]
    got = cs.solve_set([q(f"t{i}", t) for i, t in enumerate(twisted)], {"disk.img": img}, {})
    bad = {twisted[i]: got[f"t{i}"] for i in range(len(twisted)) if plain(got[f"t{i}"])}
    check("carve_stego: a question that only mentions the file (its image, what hides in it, its deleted version) has no plain hash", not bad, bad)
    # the image has ONE deleted file: "the one hidden item" must not answer questions about the image or about what is live
    hidden = hashlib.sha256(facts["secret"]).hexdigest()
    got = cs.solve_set([q("h", "What is the SHA-256 of the deleted file?"), q("s", "What is the size in bytes of the deleted file?", kind="integer"),
                        q("n", "How many deleted files are on the disk image?", kind="integer")], {"disk.img": img}, {})
    check("carve_stego: the deleted file's hash, size and count are still plain", got == {"h": hidden, "s": str(len(facts["secret"])), "n": "1"}, got)
    twisted = ["What is the SHA-256 of the disk image?", "What is the size in bytes of the disk image?", "How many bytes long is the disk image?",
               "How many bytes is the file that was not deleted?", "What is the SHA-256 of the file that was not deleted?",
               "How many files were not deleted?", "How many files are on the disk image, including deleted ones?",
               "What is the name of the file that was not deleted?", "What is the MD5 of the whole image?"]
    got = cs.solve_set([q(f"t{i}", t) for i, t in enumerate(twisted)], {"disk.img": img}, {})
    bad = {twisted[i]: got[f"t{i}"] for i in range(len(twisted)) if got[f"t{i}"] is not None}
    check("carve_stego: the image's own hash or size, what was NOT deleted, and deleted-plus-live counts are None", not bad, bad)
    png = make_png(8, 8, bytes(8 * 8 * 3)) + make_zip({"inner.txt": b"flag{in_the_zip}\n"})
    got = cs.solve_set([q("a", "What is the size in bytes of the file appended to the picture?", kind="integer"),
                        q("b", "What is the size in bytes of the picture?", kind="integer"), q("c", "What is the MD5 of the picture?"),
                        q("d", "What is the MD5 of the archive appended to the picture?")], {"cover.png": png}, {})
    check("carve_stego: the appended archive's size and hash are plain, the picture's own are None",
          plain(got["a"]) and plain(got["d"]) and got["b"] is None and got["c"] is None, got)

    disk = _mbr([(0x01, img)])
    one = cs.solve_set([q("h", "What is the SHA-256 of README.TXT on the disk image?"),
                        q("d", "How many directories are on the disk image?", kind="integer")], {"disk.img": disk}, {})
    alone = cs.solve_set([q("d", "How many directories are on the disk image?", kind="integer")], {"disk.img": img}, {})
    check("carve_stego: a file inside the one partition of an MBR disk is hashed as on the bare volume", one["h"] == want, one)
    check("carve_stego: a partition is not counted as a directory (the MBR disk answers as its one volume does)", one["d"] == alone["d"], (one, alone))
    unread = _mbr([(0x01, img), (0x07, os.urandom(4096))])
    got = cs.solve_set([q("n", "How many files are on the disk image?", kind="integer"),
                        q("d", "How many directories are on the disk image?", kind="integer")], {"disk.img": unread}, {})
    check("carve_stego: a disk with a partition that holds unread data answers no count", got == {"n": None, "d": None}, got)
    blind = _mbr([(0x07, os.urandom(8192)), (0x83, os.urandom(8192))])
    got = cs.solve_set([q("n", "How many files are on the disk image?", kind="integer")], {"disk.img": blind}, {})
    check("carve_stego: a disk none of whose partitions is read does not answer 0 files", got == {"n": None}, got)
    empty = _mbr([(0x01, img), (0x83, bytes(8192)), (0x82, os.urandom(4096))])
    got = cs.solve_set([q("h", "What is the SHA-256 of README.TXT on the disk image?")], {"disk.img": empty}, {})
    check("carve_stego: an all-zero partition and a swap partition do not block the volume that was read", got["h"] == want, got)


def modern_crypto_negations():
    mc = R.load("modern_crypto")
    zero = ("iv", "00" * 16)
    for text in ("Decrypt with a non-zero IV.", "It uses a non zero IV", "The IV is not zero.", "The IV is null-terminated text"):
        check(f"modern_crypto: {text!r} states no zero IV", zero not in mc.question_fields(text), mc.question_fields(text))
    for text in ("under the key \"YELLOW SUBMARINE\" with a zero IV", "an all-zero IV", "The IV is sixteen zero bytes."):
        check(f"modern_crypto: {text!r} still states a zero IV", zero in mc.question_fields(text), mc.question_fields(text))
    from Crypto.Cipher import AES
    rows = [hashlib.sha512(bytes([i])).digest().hex() for i in range(12)]
    rows[5] = AES.new(b"k" * 16, AES.MODE_ECB).encrypt(b"A" * 64).hex()
    files = {"cts.txt": ("\n".join(rows) + "\n").encode()}
    got = mc.solve_set([q("a", "Which line was encrypted with ECB?"), q("b", "Which line was not encrypted with ECB?"),
                        q("c", "Which line is NOT the ECB one?")], files, {})
    check("modern_crypto: the ECB line is offered (line 6 or index 5), unsure", R.offers(got["a"], "6") and R.offers(got["a"], "5") and not plain(got["a"]), got["a"])
    check("modern_crypto: the lines that are NOT ECB are not answered with the ECB line", got["b"] is None and got["c"] is None, got)


def web_game_master_host():
    web = R.load("web")
    for url in ("https://2026.huntress.ctf.games./", "https://2026.HUNTRESS.ctf.games./x", "http://user@2026.huntress.ctf.games/"):
        try:
            web.WebClient(url)          # the constructor opens no connection
            check(f"web: WebClient refuses the Game Master under the spelling {url}", False)
        except web.OutOfScope:
            check(f"web: WebClient refuses the Game Master under the spelling {url}", True)


def main() -> int:
    for fn in (web_evidence_qualified, tokens_negated, rf_and_malconfig_negated, carve_stego_named_and_partitions,
               modern_crypto_negations, web_game_master_host):
        R.section(fn)
    print("ok" if not R.FAILED else f"FAILED {len(R.FAILED)}: " + "; ".join(R.FAILED[:8]))
    return 1 if R.FAILED else 0


def test_review_fixes():
    """pytest entry: runs every group; any check that fails fails this test, by name."""
    before = len(R.FAILED)
    main()
    assert R.FAILED[before:] == [], R.FAILED[before:]


if __name__ == "__main__":
    sys.exit(main())
