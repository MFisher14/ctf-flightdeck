#!/usr/bin/env python3
"""Day 9 hardening checks for the Mobile lane, part of solvers/mobile-android/selftest.py.

  .venv/bin/python solvers/mobile-android/selftest_day9.py [-v]      # these checks alone
  .venv/bin/python solvers/mobile-android/selftest.py                # the whole lane, these included

Offline, no token; everything is built here from random answer codes. What is checked:

  more codecs   every codec codec_more.py adds (base36, base62, base45, base91, quoted-printable,
                HTML entities, backslash escapes, Morse, zstd, lz4, brotli, snappy, columnar and
                scytale, delta and the running xor, per-character offsets, chacha20, des3, fernet,
                jwt, a custom base64 alphabet): unsure under mobile.codec/<name>, the right code
                among the options and first nearly always; never plain; a near miss is None; none
                of them is a search move; position moves under one text layer
  shapes        a schema other than v1 makes a judged codec unsure (`:schema-v2`) and plain again
                once the judge accepts that route; codec and steps written as objects; steps under
                `pipeline` with no codec; pieces that are documents of their own (`fragments`)
  documents     the same puzzle fields as a plist (XML and binary), compiled XML, resources.arsc,
                text XML (SharedPreferences, strings.xml), SQLite, properties, YAML, TOML,
                MessagePack, CBOR, protobuf; in an Android backup, a tar, a gzip; in the manifest's
                meta-data: solved, unsure, the format named in the route, never plain
  keys          a key that only resources.arsc, a compiled res/xml file, a native library or a
                small text asset holds is found (`key-apk`), and a named key resource first
  package       the one answer code of the package outside any document (dex, resources, a native
                library, META-INF, the signing block, UTF-16) is unsure under apk-string:<where>;
                two different codes are None; a code cut in two pieces (files by name, strings) is
                unsure under apk-pieces; three loose string pieces are None
  facts         apk_facts.py on a real manifest built here: each fact a question id names is
                unsure under mobile.<fact>/apk with the manifest's value first; hashes and sizes
                are plain and right; an id that names no fact or two is None; a delivery that is
                no APK answers nothing; `answer` keeps the code beside fact questions
  mastery       a set's budget shrinks with the number of deliveries (5 and 8), and a judged codec
                is still plain in each of 8 sets inside the lane's solve cap
  fail closed   truncated and random bytes for every reader: no exception, no answer, in budget

Prints one line per check; standalone it ends with `SELFTEST mobile-day9: <passed>/<checks> ...`.
"""
import base64
import gzip
import hashlib
import io
import json
import os
import plistlib
import re
import sqlite3
import struct
import sys
import tarfile
import time
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent

S = None      # selftest.py, the lane's self-test: its helpers (check, solve, kind, doc, ans, ...) are used here
C = None      # codec_search under test
labels = None


def _bind(selftest):
    global S, C, labels
    S, C, labels = selftest, selftest.C, selftest.labels


# ---------------------------------------------------------------------------- encoders

B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
B45 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
B91 = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
       "!#$%&()*+,./:;<=>?@[]^_`{|}~\"")
MORSE = {"A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.", "N": "-.", "S": "...", "-": "-....-",
         "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-", "5": ".....", "6": "-....",
         "7": "--...", "8": "---..", "9": "----."}


def radix(b, alphabet):
    n, s = int.from_bytes(b, "big"), ""
    while n:
        n, r = divmod(n, len(alphabet))
        s = alphabet[r] + s
    return s


def b45(b):
    out = ""
    for i in range(0, len(b), 2):
        chunk = b[i:i + 2]
        n = int.from_bytes(chunk, "big")
        for _ in range(3 if len(chunk) == 2 else 2):
            n, r = divmod(n, 45)
            out += B45[r]
    return out


def b91(data):
    b = n = 0
    out = ""
    for byte in data:
        b |= byte << n
        n += 8
        if n > 13:
            v = b & 8191
            if v > 88:
                b >>= 13
                n -= 13
            else:
                v = b & 16383
                b >>= 14
                n -= 14
            out += B91[v % 91] + B91[v // 91]
    if n:
        out += B91[b % 91]
        if n > 7 or b > 90:
            out += B91[b // 91]
    return out


def columnar(s, perm):
    n = len(perm)
    by_rank = sorted(range(n), key=lambda c: perm[c])
    return "".join(s[i] for c in by_rank for i in range(c, len(s), n))


def key_perm(word):
    order = sorted(range(len(word)), key=lambda i: (word[i].upper(), i))
    perm = [0] * len(word)
    for rank, i in enumerate(order):
        perm[i] = rank
    return perm


def pool(strings, utf8=True):
    """One ResStringPool chunk."""
    offs, data = [], b""
    for s in strings:
        offs.append(len(data))
        if utf8:
            raw = s.encode("utf-8")
            assert len(s) < 128 and len(raw) < 128
            data += bytes([len(s), len(raw)]) + raw + b"\0"
        else:
            data += struct.pack("<H", len(s)) + s.encode("utf-16le") + b"\0\0"
    data += b"\0" * (-len(data) % 4)
    start = 28 + 4 * len(strings)
    return struct.pack("<HHIIIIII", 1, 28, start + len(data), len(strings), 0, 0x100 if utf8 else 0, start, 0) \
        + b"".join(struct.pack("<I", o) for o in offs) + data


def axml(elements, utf8=True):
    """A compiled XML file: elements as (tag, {attr: value}, depth); a value is str, int or bool."""
    strings = []

    def sid(s):
        if s not in strings:
            strings.append(s)
        return strings.index(s)

    for tag, attrs, _ in elements:
        sid(tag)
        for k, v in attrs.items():
            sid(k)
            if isinstance(v, str):
                sid(v)
    body, stack = b"", []
    for tag, attrs, depth in elements + [("", {}, 0)]:
        while stack and (not tag or stack[-1][1] >= depth):
            name, _ = stack.pop()
            body += struct.pack("<HHIIi", 0x0103, 16, 24, 1, -1) + struct.pack("<ii", -1, sid(name))
        if not tag:
            break
        ext = struct.pack("<iiHHHHHH", -1, sid(tag), 20, 20, len(attrs), 0, 0, 0)
        for k, v in attrs.items():
            if isinstance(v, bool):
                ext += struct.pack("<iiiHBBI", -1, sid(k), -1, 8, 0, 0x12, 0xFFFFFFFF if v else 0)
            elif isinstance(v, int):
                ext += struct.pack("<iiiHBBI", -1, sid(k), -1, 8, 0, 0x10, v & 0xFFFFFFFF)
            else:
                ext += struct.pack("<iiiHBBI", -1, sid(k), sid(v), 8, 0, 0x03, sid(v))
        body += struct.pack("<HHIIi", 0x0102, 16, 16 + len(ext), 1, -1) + ext
        stack.append((tag, depth))
    sp = pool(strings, utf8)
    return struct.pack("<HHI", 3, 8, 8 + len(sp) + len(body)) + sp + body


def arsc(strings=None, integers=None):
    """A resources.arsc with one package: string resources {name: text} and integer resources {name: n}."""
    strings, integers = strings or {}, integers or {}
    values = list(strings.values())
    keys = list(strings) + list(integers)

    def type_chunk(tid, entries):
        offs, data = [], b""
        for key, kind, value in entries:
            offs.append(len(data))
            data += struct.pack("<HHI", 8, 0, keys.index(key)) + struct.pack("<HBBI", 8, 0, kind, value & 0xFFFFFFFF)
        config = struct.pack("<I", 28) + b"\0" * 24
        hsize = 8 + 12 + len(config)
        start = hsize + 4 * len(entries)
        return struct.pack("<HHI", 0x0201, hsize, start + len(data)) + struct.pack("<BBHII", tid, 0, 0, len(entries), start) \
            + config + b"".join(struct.pack("<I", o) for o in offs) + data

    tpool, kpool = pool(["string", "integer"]), pool(keys)
    chunks = type_chunk(1, [(k, 0x03, values.index(v)) for k, v in strings.items()])
    if integers:
        chunks += type_chunk(2, [(k, 0x10, v) for k, v in integers.items()])
    name = "com.huntress.fixture".encode("utf-16le").ljust(256, b"\0")
    psize = 288 + len(tpool) + len(kpool) + len(chunks)
    package = struct.pack("<HHII", 0x0200, 288, psize, 0x7F) + name \
        + struct.pack("<IIIII", 288, 0, 288 + len(tpool), 0, 0) + tpool + kpool + chunks
    vpool = pool(values, utf8=False)
    return struct.pack("<HHII", 2, 12, 12 + len(vpool) + len(package), 1) + vpool + package


def uleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def dex(strings):
    """A dex file that holds only a string table (enough for every reader here)."""
    strings = sorted(strings)
    data, offs = b"", []
    base_off = 0x70 + 4 * len(strings)
    for s in strings:
        offs.append(base_off + len(data))
        raw = s.encode("utf-8")
        data += uleb(len(s)) + raw + b"\0"
    head = bytearray(b"dex\n035\0" + b"\0" * 0x68)
    struct.pack_into("<II", head, 0x38, len(strings), 0x70)
    return bytes(head) + b"".join(struct.pack("<I", o) for o in offs) + data


def elf(strings):
    return b"\x7fELF\x02\x01\x01" + b"\0" * 57 + b"\0".join(s.encode() for s in strings) + b"\0" * 8


def msgpack(d):
    def enc(v):
        if isinstance(v, bool):
            return b"\xc3" if v else b"\xc2"
        if isinstance(v, int):
            return bytes([v]) if 0 <= v < 128 else b"\xcd" + struct.pack(">H", v)
        if isinstance(v, str):
            raw = v.encode()
            return (bytes([0xa0 | len(raw)]) if len(raw) < 32 else b"\xd9" + bytes([len(raw)])) + raw
        if isinstance(v, list):
            return bytes([0x90 | len(v)]) + b"".join(enc(x) for x in v)
        return bytes([0x80 | len(v)]) + b"".join(enc(k) + enc(x) for k, x in v.items())
    return enc(d)


def cbor(d):
    def head(major, n):
        return bytes([major << 5 | n]) if n < 24 else bytes([major << 5 | 24, n]) if n < 256 \
            else bytes([major << 5 | 25]) + struct.pack(">H", n)

    def enc(v):
        if isinstance(v, bool):
            return b"\xf5" if v else b"\xf4"
        if isinstance(v, int):
            return head(0, v)
        if isinstance(v, str):
            return head(3, len(v.encode())) + v.encode()
        if isinstance(v, list):
            return head(4, len(v)) + b"".join(enc(x) for x in v)
        return head(5, len(v)) + b"".join(enc(k) + enc(x) for k, x in v.items())
    return enc(d)


def protobuf(fields):
    """[(number, value)] as a protobuf message: str and bytes length-delimited, int as a varint."""
    out = b""
    for number, v in fields:
        if isinstance(v, int):
            out += uleb(number << 3) + uleb(v)
        else:
            raw = v.encode() if isinstance(v, str) else v
            out += uleb(number << 3 | 2) + uleb(len(raw)) + raw
    return out


def sqlite_db(rows, table="prefs"):
    con = sqlite3.connect(":memory:")
    con.execute('CREATE TABLE "%s" (key TEXT PRIMARY KEY, value TEXT)' % table)
    con.executemany('INSERT INTO "%s" VALUES (?, ?)' % table, [(k, str(v)) for k, v in rows.items()])
    con.commit()
    blob = con.serialize()
    con.close()
    return bytes(blob)


def tar_of(members):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for name, body in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(body)
            tf.addfile(info, io.BytesIO(body))
    return out.getvalue()


def android_backup(members):
    return b"ANDROID BACKUP\n5\n1\nnone\n" + zlib.compress(tar_of(members))


def manifest(package="com.huntress.mobile.d09.vabc123", extra=()):
    """The fixture's manifest shape (Days 1 to 8), compiled."""
    return axml([
        ("manifest", {"versionCode": 9, "versionName": "1.0", "package": package}, 0),
        ("uses-sdk", {"minSdkVersion": 23, "targetSdkVersion": 23}, 1),
        ("uses-permission", {"name": "android.permission.INTERNET"}, 1),
        ("application", {"label": "Day 09", "debuggable": False, "allowBackup": True, "usesCleartextTraffic": True}, 1),
        ("meta-data", {"name": "huntress.day", "value": 9}, 2),
        ("meta-data", {"name": "huntress.mechanic", "value": "a new boundary"}, 2),
        *extra,
        ("activity", {"name": ".MainActivity", "exported": True}, 2),
        ("intent-filter", {}, 3),
        ("action", {"name": "android.intent.action.MAIN"}, 4),
        ("category", {"name": "android.intent.category.LAUNCHER"}, 4),
        ("activity", {"name": ".ChallengeActivity", "exported": True}, 2),
        ("intent-filter", {}, 3),
        ("action", {"name": "android.intent.action.VIEW"}, 4),
        ("category", {"name": "android.intent.category.BROWSABLE"}, 4),
        ("data", {"scheme": "huntress09", "host": "new-boundary", "pathPrefix": "/unlock"}, 4),
    ])


DEX_STRINGS = ["&client_secret=SECRET-0123456789ABCDEF012345&proof=", "CODEC", "DAY",
               "DAY-09:new_control:a new boundary", "Lcom/huntress/mobile/d09/vabc123/MainActivity;",
               "Case reference: MOB-09-ABC1230000", "answer", "case_id",
               "http://127.0.0.1:19090/mobile/attempt/d09-00112233aabbccdd/evidence?case_id="]


def shell(**members):
    """The members of a small but real-shaped APK: a compiled manifest and a dex, plus what is given."""
    return {"AndroidManifest.xml": manifest(), "classes.dex": dex(DEX_STRINGS),
            **{k.replace("__", "/"): v for k, v in members.items()}}


def jdoc(d):
    return json.dumps(d, separators=(",", ":")).encode()


def tally(build_apk, trials=None):
    """({kind: count}, the first option names seen) over random answers; build_apk(answer) -> APK bytes."""
    counts, firsts = {}, set()
    for _ in range(trials or S.TRIALS):
        a = S.ans()
        got, _ = S.solve(build_apk(a))
        k = S.kind(got, a)
        counts[k] = counts.get(k, 0) + 1
        firsts.update(S.options_of(got)[:1])
    return counts, firsts


def offered(counts, n=None):
    """Every trial gave an unsure answer that holds the right code."""
    n = n or S.TRIALS
    return counts.get("unsure-ok", 0) + counts.get("unsure-first", 0) + counts.get("unsure-later", 0) == n


# ---------------------------------------------------------------------------- checks

def more_codecs():
    doc, b64, xor = S.doc, S.b64, S.xor
    import brotli
    import lz4.frame
    import snappy
    import zstandard
    from cryptography.fernet import Fernet
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    k32, n16, k24 = hashlib.sha256(b"k").digest(), hashlib.md5(b"n").digest(), hashlib.sha256(b"d").digest()[:24]
    fkey = base64.urlsafe_b64encode(k32).decode()
    custom = "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba9876543210+/"
    std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    def chacha(a):
        return Cipher(algorithms.ChaCha20(k32, n16), None).encryptor().update(a.encode())

    def tdes(a):
        e = Cipher(TripleDES(k24), modes.ECB()).encryptor()
        return e.update(S._pad(a.encode())[:24]) + e.finalize()

    def jwt(a):
        seg = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
        return "%s.%s.%s" % (seg({"alg": "none"}), seg({"sub": "case", "code": a}), "c2ln")

    def delta(b):
        return bytes([b[0]] + [(b[i] - b[i - 1]) % 256 for i in range(1, len(b))])

    def xchain(b):
        return bytes([b[0]] + [b[i] ^ b[i - 1] for i in range(1, len(b))])

    offs = [3, 141, 59, 26, 5, 35, 89, 79, 32, 38, 46, 26, 43, 38, 32, 79, 50, 28, 84, 19]
    rows = [
        ("base36", lambda a: doc("base36", radix(a.encode(), "0123456789abcdefghijklmnopqrstuvwxyz"))),
        ("base62", lambda a: doc("base62", radix(a.encode(), B62))),
        ("base62 lower first", lambda a: doc("base62", radix(a.encode(), B62[:10] + B62[36:] + B62[10:36]))),
        ("base45", lambda a: doc("base45", b45(a.encode()))),
        ("base91", lambda a: doc("base91", b91(a.encode()))),
        ("quoted-printable", lambda a: doc("quoted-printable", "".join("=%02X" % c for c in a.encode()))),
        ("html entities", lambda a: doc("html-entities", "".join("&#%d;" % c for c in a.encode()))),
        ("hex escapes", lambda a: doc("hex-escape", "".join("\\x%02x" % c for c in a.encode()))),
        ("unicode escapes", lambda a: doc("unicode-escape", "".join("\\u%04x" % c for c in a.encode()))),
        ("morse", lambda a: doc("morse", " ".join(MORSE[c] for c in a))),
        ("zstd under base64", lambda a: doc("zstd", b64(zstandard.ZstdCompressor().compress(a.encode())))),
        ("lz4 under hex", lambda a: doc("lz4", lz4.frame.compress(a.encode()).hex())),
        ("brotli under base64", lambda a: doc("brotli", b64(brotli.compress(a.encode())))),
        ("snappy under base64", lambda a: doc("snappy", b64(snappy.compress(a.encode())))),
        ("columnar by keyword", lambda a: doc("columnar", columnar(a, key_perm("HUNTRESS")), key="HUNTRESS")),
        ("columnar by column numbers", lambda a: doc("transposition", columnar(a, [2, 0, 3, 1, 4, 6, 5]), columns=[2, 0, 3, 1, 4, 6, 5])),
        ("scytale, the count in a field", lambda a: doc("scytale", columnar(a, list(range(6))), turns=6)),
        ("delta under base64", lambda a: doc("delta", b64(delta(a.encode())))),
        ("running xor under hex", lambda a: doc("xor-chain", xchain(a.encode()).hex())),
        ("per-character offsets", lambda a: doc("offsets", b64(bytes((c + o) % 256 for c, o in zip(a.encode(), offs))), offsets=offs)),
        ("offsets subtracted by the author", lambda a: doc("offset", b64(bytes((c - o) % 256 for c, o in zip(a.encode(), offs))), offsets=offs)),
        ("chacha20 key and nonce in the document", lambda a: doc("chacha20", b64(chacha(a)), key=k32.hex(), nonce=n16.hex())),
        ("3des key in the document", lambda a: doc("3des", b64(tdes(a)), key=k24.hex())),
        ("fernet key in the document", lambda a: doc("fernet", Fernet(fkey.encode()).encrypt(a.encode()).decode(), key=fkey)),
        ("jwt payload", lambda a: doc("jwt", jwt(a))),
        ("base64 in the document's own alphabet", lambda a: doc("base64", b64(a.encode()).translate(str.maketrans(std, custom)), alphabet=custom)),
        ("chain base91+reverse", lambda a: doc("base91+reverse", b91(a[::-1].encode()))),
        ("chain list zstd then xor with key", lambda a: doc(["zstd", "xor"], b64(zstandard.ZstdCompressor().compress(xor(a.encode(), b"\x2a"))), key=42)),
    ]
    bad, plain, firsts_ok, keys = [], [], 0, []
    for name, f in rows:
        counts, firsts = tally(lambda a: S.mini_apk(f(a)))
        if S.VERBOSE:
            print(f"   {name:44} {counts} {sorted(firsts)}")
        if not offered(counts):
            bad.append(f"{name}: {counts}")
        if counts.get("plain-ok") or counts.get("plain-wrong"):
            plain.append(name)
        firsts_ok += counts.get("unsure-ok", 0) + counts.get("unsure-first", 0)
        codec = f(S.ans())["codec"]
        want = C.KEY + C._slug("+".join(codec) if isinstance(codec, list) else codec)
        if C.LAST.get("key") != want:
            keys.append(f"{name}: {C.LAST.get('key')} != {want}")
    S.check(not bad, f"day 9 codecs: every one is unsure with the right code among its options: {len(rows)} documents", "; ".join(bad[:4]))
    S.check(not plain, "day 9 codecs: none is answered plain before the judge accepts it", str(plain))
    S.check(firsts_ok >= 0.95 * S.TRIALS * len(rows), "day 9 codecs: the right code is the first option nearly always",
            f"{firsts_ok} of {S.TRIALS * len(rows)}")
    S.check(not keys, "day 9 codecs: each is offered under mobile.codec/<the document's codec name>", "; ".join(keys[:3]))
    # near misses: the step decodes, but not to a code; and the same data under an opaque name
    a = S.ans()
    near = a[:-1] + "G"
    misses = [
        ("base62 of a near miss", doc("base62", radix(near.encode(), B62))),
        ("base91 of a near miss", doc("base91", b91(near.encode()))),
        ("morse of a short text", doc("morse", " ".join(MORSE[c] for c in a[:-2]))),
        ("zstd of a near miss", doc("zstd", b64(zstandard.ZstdCompressor().compress(near.encode())))),
        ("columnar with the wrong keyword", doc("columnar", columnar(a, key_perm("HUNTRESS")), key="ZEBRAS")),
        ("offsets with no list", doc("offsets", b64(bytes((c + 9) % 256 for c in a.encode())))),
        ("jwt with two codes", doc("jwt", "x." + base64.urlsafe_b64encode(json.dumps({"a": a, "b": S.ans()}).encode()).decode().rstrip("=") + ".y")),
        ("fernet under the wrong key", doc("fernet", Fernet(Fernet.generate_key()).encrypt(a.encode()).decode(), key=fkey)),
        ("base62 under an opaque name", doc("mystery", radix(a.encode(), B62))),
        ("base91 under an opaque name", doc("mystery", b91(a.encode()))),
        ("base45 under an opaque name", doc("mystery", b45(a.encode()))),
    ]
    wrong = []
    for name, d in misses:
        got, _ = S.solve(S.mini_apk(d), name)
        # None, or what the general search offered before this module existed (`search:...`), which is
        # no reading of the named step; under an opaque name nothing at all
        routes = S.options_of(got)
        if got is not None and (labels.parse(got) is None or "mystery" in name or not all(r.startswith("search:") for r in routes)):
            wrong.append(f"{name}: {str(got)[:80]}")
    S.check(not wrong, f"day 9 codecs: a near miss is None, and none of them is a search move: {len(misses)} documents",
            "; ".join(wrong[:3]))
    moves = set(n for n, _ in C.STEP.items() if n not in C.BLIND + C.NAME_ONLY)
    S.check(not moves & set(C.codec_more.STEP_NAMES) and all(n in C.KEYED for n in C.codec_more.STEP_NAMES),
            "day 9 codecs: registered as named steps only, the search's moves are as before", str(sorted(moves & set(C.codec_more.STEP_NAMES))))
    # position moves under one text layer
    rows = [("rotated, under base64", lambda a: doc("rotate", b64((a[7:] + a[:7]).encode())), "rotate:rotate@base64"),
            ("4-character chunks reversed, under hex", lambda a: doc("chunk-reverse", "".join(a[i:i + 4][::-1] for i in range(0, 20, 4)).encode().hex()),
             "chunk-reverse:chunks4-reversed@hex")]
    bad = []
    for name, f, route in rows:
        counts, firsts = tally(lambda a: S.mini_apk(f(a)))
        if not offered(counts) or firsts != {route}:
            bad.append(f"{name}: {counts} {sorted(firsts)}")
    S.check(not bad, "day 9 codecs: a position move under one text layer is unsure, the layer named in the route", "; ".join(bad))


def shapes():
    doc, b64, xor, H = S.doc, S.b64, S.xor, S.H
    v2 = "huntress.mobile.puzzle.v2"
    rows = [
        ("schema v2, codec reverse", lambda a: {**doc("reverse", a[::-1]), "schema": v2}, {"reverse:schema-v2"}),
        ("schema v2, codec xor", lambda a: {**doc("xor", b64(xor(a.encode(), b"\x1d")), key=29), "schema": v2}, {"xor:schema-v2"}),
        ("another schema name", lambda a: {**doc("plain", a), "schema": "huntress.mobile.capsule.v1"}, {"plain:schema-huntress.mobile.capsule.v1"}),
        ("codec written as an object", lambda a: {**H, "codec": {"name": "xor", "key": 29}, "data": b64(xor(a.encode(), b"\x1d"))}, {"xor:codec-object"}),
        ("codec object, plain", lambda a: {**H, "codec": {"name": "plain"}, "data": a}, {"plain:codec-object"}),
        ("steps written as objects under pipeline", lambda a: {**H, "pipeline": [{"op": "base64"}, {"op": "xor", "key": 29}],
                                                                "data": b64(xor(a.encode(), b"\x1d"))}, None),
        ("steps as objects under codec", lambda a: {**H, "codec": [{"name": "reverse"}, {"name": "base64"}], "data": b64(a[::-1].encode())}, None),
        ("step names under pipeline, no codec", lambda a: {**H, "pipeline": ["base64", "reverse"], "data": b64(a[::-1].encode())}, None),
        ("fragments with their own codecs", lambda a: {**H, "codec": "fragments", "fragments": [
            {"codec": "plain", "data": a[:5]}, {"codec": "hex", "data": a[5:12].encode().hex()},
            {"codec": "base64", "data": b64(a[12:].encode())}]}, {"fragments:plain+hex+base64:listed:@fragments"}),
        ("fragments placed by index", lambda a: {**H, "pieces": [
            {"encoding": "hex", "value": a[12:].encode().hex(), "index": 2}, {"encoding": "reverse", "value": a[:5][::-1], "index": 0},
            {"encoding": "base64", "value": b64(a[5:12].encode()), "index": 1}]}, {"fragments:hex+reverse+base64:by-index:@pieces"}),
    ]
    bad = []
    for name, f, routes in rows:
        counts, firsts = tally(lambda a: S.mini_apk(f(a)))
        if S.VERBOSE:
            print(f"   {name:44} {counts} {sorted(firsts)}")
        if counts.get("unsure-ok") != S.TRIALS or (routes is not None and firsts != routes):
            bad.append(f"{name}: {counts} {sorted(firsts)}")
    S.check(not bad, f"day 9 shapes: a new schema, object steps and fragment documents are unsure under their own route: {len(rows)} documents",
            "; ".join(bad[:4]))
    # once the judge accepts the v2 route it is plain, on this variant and the next; v1 was plain all along
    S.scratch_ledger("challenges-day9-schema")
    try:
        a, b = S.ans(), S.ans()
        first, _ = S.solve(S.mini_apk({**doc("reverse", a[::-1]), "schema": v2}))
        parsed = labels.parse(first)
        ok = parsed is not None and labels.learn(parsed.key, parsed.options[0][0], "accepted", attempt_id="selftest", answer_ids=["answer"])
        again, _ = S.solve(S.mini_apk({**doc("reverse", a[::-1]), "schema": v2}))
        nxt, _ = S.solve(S.mini_apk({**doc("reverse", b[::-1]), "schema": v2}))
        v1, _ = S.solve(S.mini_apk(doc("reverse", b[::-1])))
        v3, _ = S.solve(S.mini_apk({**doc("reverse", b[::-1]), "schema": "huntress.mobile.puzzle.v3"}))
        S.check(ok and again == a and nxt == b and v1 == b and S.kind(v3, b) == "unsure-ok",
                "day 9 shapes: an accepted schema-v2 route is plain afterwards; v1 stays plain; v3 is unsure again",
                f"{again!r} {nxt!r} {v1!r} {str(v3)[:60]!r}")
    finally:
        S.scratch_ledger("challenges-day9")
    # fragments that do not give a code, and pieces with no codec of their own, are not this reading
    a = S.ans()
    short, _ = S.solve(S.mini_apk({**H, "fragments": [{"codec": "plain", "data": a[:5]}, {"codec": "hex", "data": a[5:11].encode().hex()}]}))
    S.check(short is None, "day 9 shapes: fragments that do not give a whole code are None", str(short)[:80])


def other_documents():
    doc, b64, xor, H = S.doc, S.b64, S.xor, S.H
    PZ = S.PZ
    x = lambda a: b64(xor(a.encode(), b"\x1d"))
    fields = lambda a: {"schema": "huntress.mobile.puzzle.v1", "day": 9, "codec": "xor", "data": x(a), "key": 29}
    props = lambda a: ("# puzzle\nschema=huntress.mobile.puzzle.v1\nday=9\ncodec=xor\ndata=%s\nkey=29\n" % x(a)).encode()
    yaml_doc = lambda a: ("schema: huntress.mobile.puzzle.v1\nday: 9\ncodec: split\ndata: ''\nparts:\n  - %s\n  - %s\n  - %s\norder: [2, 0, 1]\n"
                          % (a[11:], a[:5], a[5:11])).encode()
    toml_doc = lambda a: ('schema = "huntress.mobile.puzzle.v1"\nday = 9\ncodec = "reverse"\ndata = "%s"\n' % a[::-1]).encode()
    prefs = lambda a: ('<?xml version="1.0" encoding="utf-8"?>\n<map>\n  <string name="codec">xor</string>\n'
                       '  <string name="data">%s</string>\n  <int name="key" value="29" />\n</map>\n' % x(a)).encode()
    strings_xml = lambda a: ('<resources><string name="puzzle_codec">base64</string><string name="puzzle_data">%s</string>'
                             '</resources>' % b64(a.encode())).encode()
    rows = [
        ("XML plist at the puzzle's path", lambda a: {PZ: plistlib.dumps(fields(a))}, "plist"),
        ("binary plist in assets", lambda a: {"assets/puzzle.plist": plistlib.dumps(fields(a), fmt=plistlib.FMT_BINARY)}, "plist"),
        ("an IPA's Info.plist", lambda a: {"Payload/Fixture.app/Info.plist": plistlib.dumps({"CFBundleIdentifier": "com.huntress.d09", "HuntressCodec": "reverse",
                                                                                         "HuntressData": a[::-1]}, fmt=plistlib.FMT_BINARY)}, "plist"),
        ("binary plist with a data value", lambda a: {"assets/p.plist": plistlib.dumps({"codec": "xor", "data": xor(a.encode(), b"\x1d"), "key": 29},
                                                                                     fmt=plistlib.FMT_BINARY)}, "plist"),
        ("properties", lambda a: {"assets/huntress_puzzle.properties": props(a)}, "properties"),
        ("YAML with pieces and an order", lambda a: {"assets/huntress_puzzle.yaml": yaml_doc(a)}, "yaml"),
        ("TOML", lambda a: {"assets/puzzle.toml": toml_doc(a)}, "toml"),
        ("SharedPreferences XML", lambda a: {"assets/shared_prefs/puzzle.xml": prefs(a)}, "xml"),
        ("strings.xml as text in res/raw", lambda a: {"res/raw/strings.xml": strings_xml(a)}, "xml"),
        ("compiled XML in res/xml", lambda a: {"res/xml/puzzle.xml": axml([("puzzle", {"codec": "xor", "data": x(a), "key": 29}, 0)])}, "axml"),
        ("compiled XML, UTF-16 pool, named items", lambda a: {"res/xml/config.xml": axml([
            ("config", {}, 0), ("item", {"name": "codec", "value": "reverse"}, 1), ("item", {"name": "data", "value": a[::-1]}, 1)], utf8=False)}, "axml"),
        ("resources.arsc string and integer resources", lambda a: {"resources.arsc": arsc({"puzzle_codec": "xor", "puzzle_data": x(a), "app_name": "Day 09"},
                                                                                         {"puzzle_key": 29})}, "arsc"),
        ("SQLite key/value table", lambda a: {"assets/databases/app.db": sqlite_db({"codec": "xor", "data": x(a), "key": 29})}, "sqlite"),
        ("MessagePack map", lambda a: {"assets/puzzle.msgpack": msgpack(fields(a))}, "msgpack"),
        ("CBOR map", lambda a: {"assets/puzzle.cbor": cbor(fields(a))}, "cbor"),
        ("protobuf, fields with no names", lambda a: {"assets/puzzle.pb": protobuf([(1, "huntress.mobile.puzzle.v1"), (2, 9), (3, "xor"), (4, x(a)), (5, 29)])}, "protobuf"),
        ("manifest meta-data", lambda a: {"AndroidManifest.xml": manifest(extra=(("meta-data", {"name": "huntress.codec", "value": "reverse"}, 2),
                                                                                    ("meta-data", {"name": "huntress.data", "value": a[::-1]}, 2)))}, "axml"),
        ("JSON inside an Android backup", lambda a: {"assets/backup.ab": android_backup({"apps/com.huntress/f/huntress_puzzle.json": jdoc(fields(a))})}, ""),
        ("SharedPreferences inside a backup's tar", lambda a: {"assets/backup.tar": tar_of({"apps/com.huntress/sp/puzzle.xml": prefs(a)})}, "xml"),
        ("the puzzle document gzipped", lambda a: {"assets/huntress_puzzle.json.gz": gzip.compress(jdoc(fields(a)))}, ""),
    ]
    bad = []
    for name, f, fmt in rows:
        counts, firsts = tally(lambda a: S.build({**shell(), **f(a)}), trials=8)
        if S.VERBOSE:
            print(f"   {name:44} {counts} {sorted(firsts)}")
        named = all(("doc-" + fmt in r) if fmt else ("doc-inner" in r) for r in firsts)
        if counts.get("unsure-ok") != 8 or not named:
            bad.append(f"{name}: {counts} {sorted(firsts)}")
    S.check(not bad, f"day 9 documents: the puzzle's fields in another container are solved, unsure, the format in the route: {len(rows)} shapes",
            "; ".join(bad[:4]))
    # an encrypted backup, a document with YAML anchors, an XML with entities: nothing is read from them
    a = S.ans()
    closed = [
        ("an encrypted Android backup", {"assets/backup.ab": b"ANDROID BACKUP\n5\n1\nAES-256\n" + b"\x00" * 200}),
        ("YAML with anchors", {"assets/p.yaml": ("base: &b {codec: reverse}\ncodec: reverse\ndata: %s\nmore: *b\n" % a[::-1]).encode()}),
        ("XML that declares an entity", {"assets/p.xml": ('<!DOCTYPE m [<!ENTITY c "reverse">]><map><string name="codec">&c;</string>'
                                                         '<string name="data">%s</string></map>' % a[::-1]).encode()}),
    ]
    got = {name: S.solve(S.build({**shell(), **m}), name)[0] for name, m in closed}
    S.check(all(v is None or labels.parse(v) is not None for v in got.values()) and got["an encrypted Android backup"] is None,
            "day 9 documents: an encrypted backup, YAML anchors and XML entities are never answered plain",
            str({k: str(v)[:50] for k, v in got.items()}))
    # the real manifest and dex of the fixture hold no puzzle field: no document is made of them
    none, _ = S.solve(S.build(shell()), "a real-shaped APK with no asset")
    S.check(none is None and C.LAST.get("confidence") == "none", "day 9 documents: the fixture's own manifest and dex are no puzzle document",
            f"{none!r} {C.LAST.get('route')}")


def key_sources():
    doc, b64, xor = S.doc, S.b64, S.xor
    key = b"hunter2-9A7C"
    cipher = lambda a: {S.PZ: jdoc(doc("xor", b64(xor(a.encode(), key))))}
    rows = [
        ("the key is a string resource", lambda a: {**cipher(a), "resources.arsc": arsc({"app_name": "Day 09", "puzzle_key": key.decode()})}),
        ("the key is an attribute of res/xml/network_security_config.xml",
         lambda a: {**cipher(a), "res/xml/network_security_config.xml": axml([("network-security-config", {}, 0),
                                                                             ("domain-config", {"cleartextTrafficPermitted": True, "pinKey": key.decode()}, 1)])}),
        ("the key is a manifest meta-data value", lambda a: {**cipher(a), "AndroidManifest.xml": manifest(
            extra=(("meta-data", {"name": "huntress.puzzle.key", "value": key.decode()}, 2),))}),
        ("the key is a string of a native library", lambda a: {**cipher(a), "lib/arm64-v8a/libpuzzle.so": elf(["JNI_OnLoad", key.decode(), "libc.so"])}),
        ("the key is a small text asset", lambda a: {**cipher(a), "assets/key.txt": key + b"\n"}),
        ("the key is in res/raw", lambda a: {**cipher(a), "res/raw/secret": key}),
    ]
    bad = []
    for name, f in rows:
        counts, firsts = tally(lambda a: S.build({**shell(), **f(a)}), trials=8)
        if S.VERBOSE:
            print(f"   {name:60} {counts} {sorted(firsts)}")
        if counts.get("unsure-ok") != 8 or firsts != {"xor:key-apk"}:
            bad.append(f"{name}: {counts} {sorted(firsts)}")
    S.check(not bad, f"day 9 keys: a key held only by the resources, compiled XML, a native library or a text member is found: {len(rows)} places",
            "; ".join(bad[:3]))
    named = C.named_keys({"resources.arsc": arsc({"app_name": "Day 09", "puzzle_key": key.decode(), "api_secret": "s3cr3t"})})
    S.check(key in named and b"s3cr3t" in named and b"Day 09" not in named, "day 9 keys: a resource named key or secret is a key candidate, others are not",
            str(named)[:120])
    vals = C.apk_resources.arsc_values(arsc({"a": "one", "b": "two"}, {"n": 7}))
    tree = C.apk_resources.axml_tree(manifest())
    S.check(vals == {("string", "a"): "one", ("string", "b"): "two", ("integer", "n"): 7} and tree[0]["attrs"]["package"].startswith("com.huntress.")
            and [e["attrs"].get("scheme") for e in tree if e["tag"] == "data"] == ["huntress09"],
            "day 9 keys: the resource table and the compiled manifest are read back as built", str(vals))


def package_strings():
    a_enc = lambda a: a.encode()
    rows = [
        ("a dex string, as it stands", lambda a: {"classes.dex": dex(DEX_STRINGS + [a])}, "apk-string:dex"),
        ("a string resource", lambda a: {"resources.arsc": arsc({"flag": a})}, "apk-string:resources:utf16"),
        ("a native library string", lambda a: {"lib/arm64-v8a/libx.so": elf(["init", a])}, "apk-string:lib"),
        ("a file in META-INF", lambda a: {"META-INF/huntress.txt": a_enc(a)}, "apk-string:meta-inf"),
        ("a text asset, base64", lambda a: {"assets/note.txt": base64.b64encode(a_enc(a))}, "apk-string:asset:base64"),
        ("a dex string, hex", lambda a: {"classes.dex": dex(DEX_STRINGS + [a.encode().hex()])}, "apk-string:dex:hex"),
        ("an attribute of a compiled XML file", lambda a: {"res/xml/cfg.xml": axml([("cfg", {"token": a}, 0)])}, "apk-string:res-xml"),
    ]
    bad = []
    for name, f, route in rows:
        counts, firsts = tally(lambda a: S.build({**shell(), **f(a)}), trials=8)
        if S.VERBOSE:
            print(f"   {name:44} {counts} {sorted(firsts)}")
        if counts.get("unsure-ok") != 8 or firsts != {route}:
            bad.append(f"{name}: {counts} {sorted(firsts)}")
    S.check(not bad, f"day 9 package: the one code the package holds outside a document is unsure under apk-string:<where>: {len(rows)} places",
            "; ".join(bad[:3]))
    a, b = S.ans(), S.ans()
    apk = S.build({**shell(), "assets/empty.txt": b"nothing"})
    tail, _ = S.solve(apk + b"")     # control: nothing anywhere
    # bytes between the last member and the central directory, where an APK signing block sits
    cd = struct.unpack_from("<I", apk, len(apk) - 6)[0]
    block = b"\0" * 8 + a.encode() + b"\0" * 4 + b"APK Sig Block 42"
    signed = apk[:cd] + block + apk[cd:-6] + struct.pack("<I", cd + len(block)) + apk[-2:]
    sig, _ = S.solve(signed, "a code outside the members")
    two, _ = S.solve(S.build({**shell(), "classes.dex": dex(DEX_STRINGS + [a]), "assets/n.txt": b.encode()}), "two codes")
    same, _ = S.solve(S.build({**shell(), "classes.dex": dex(DEX_STRINGS + [a]), "assets/n.txt": a.encode()}), "one code twice")
    S.check(tail is None and S.kind(two, a) == "none" and C.LAST.get("confidence") in ("low", "medium") and S.kind(same, a) == "unsure-ok",
            "day 9 package: two different codes in the package are None; the same code in two places is one",
            f"{tail!r} {str(two)[:40]!r} {str(same)[:60]!r}")
    S.check(S.kind(sig, a) == "unsure-ok" and S.options_of(sig) == ["apk-string:archive"],
            "day 9 package: a code in the archive's bytes outside its members (the signing block) is unsure under apk-string:archive",
            str(sig)[:80])
    # a puzzle document that names a codec nobody can apply, and a code elsewhere: one probe, never plain
    odd, _ = S.solve(S.build({**shell(), S.PZ: jdoc(S.doc("backend-only", "see the backend")), "classes.dex": dex(DEX_STRINGS + [a])}))
    S.check(S.kind(odd, a) == "unsure-ok", "day 9 package: beside a document that holds no code, the package's one code is offered unsure", str(odd)[:80])
    # pieces
    rows = [
        ("two files by name", lambda a: {"assets/part1.txt": a[:9].encode(), "assets/part2.txt": a[9:].encode()}, "apk-pieces:files-by-name"),
        ("three files by name", lambda a: {"assets/p01": a[:6].encode(), "assets/p02": a[6:13].encode(), "assets/p10": a[13:].encode()}, "apk-pieces:files-by-name"),
        ("files across assets, res/raw and META-INF", lambda a: {"META-INF/c.part": a[13:].encode(), "assets/a.part": a[:6].encode(),
                                                                 "res/raw/b.part": a[6:13].encode()}, "apk-pieces:files-by-name"),
        ("two dex strings", lambda a: {"classes.dex": dex(DEX_STRINGS + [a[:9], a[9:]])}, "apk-pieces:strings"),
        ("a dex string and a string resource", lambda a: {"classes.dex": dex(DEX_STRINGS + [a[:12]]), "resources.arsc": arsc({"tail": a[12:]})}, "apk-pieces:strings"),
    ]
    bad = []
    for name, f, route in rows:
        counts, firsts = tally(lambda a: S.build({**shell(), **f(a)}), trials=8)
        if S.VERBOSE:
            print(f"   {name:44} {counts} {sorted(firsts)}")
        if counts.get("unsure-ok") != 8 or firsts != {route}:
            bad.append(f"{name}: {counts} {sorted(firsts)}")
    S.check(not bad, f"day 9 package: a code cut in pieces across files or two strings is unsure under apk-pieces: {len(rows)} shapes", "; ".join(bad[:3]))
    three, _ = S.solve(S.build({**shell(), "classes.dex": dex(DEX_STRINGS + [a[:8], a[8:14], a[14:]])}), "three loose pieces")
    twoheads, _ = S.solve(S.build({**shell(), "classes.dex": dex(DEX_STRINGS + [a[:9], b[:9], a[9:]])}), "two heads")
    S.check(three is None and twoheads is None, "day 9 package: three loose string pieces, or two that could start the code, are None",
            f"{str(three)[:50]!r} {str(twoheads)[:50]!r}")


def facts():
    import apk_facts as F
    members = shell(**{"assets__huntress_puzzle.json": jdoc(S.doc("reverse", S.ans()[::-1]))})
    blob = S.build(members)
    text = {"kind": "exact_text", "syntax": "the value exactly as the package states it"}
    pkg = "com.huntress.mobile.d09.vabc123"
    want = {
        "package_name": pkg, "version_name": "1.0", "version_code": "9", "min_sdk": "23", "target_sdk_version": "23",
        "exported_activity": ".ChallengeActivity", "launcher_activity": ".MainActivity", "deep_link_scheme": "huntress09",
        "deep_link_host": "new-boundary", "deep_link_path": "/unlock", "deep_link_uri": "huntress09://new-boundary/unlock",
        "permission": "android.permission.INTERNET", "allow_backup": "true", "debuggable": "false", "uses_cleartext_traffic": "true",
        "control": "new_control", "mechanic": "a new boundary", "case_reference": "MOB-09-ABC1230000",
        "client_secret": "SECRET-0123456789ABCDEF012345", "backend_port": "19090", "backend_host": "127.0.0.1",
        "attempt_id": "d09-00112233aabbccdd", "codec": "reverse", "app_label": "Day 09",
        "permission_count": "1", "activity_count": "2",
    }
    qs = [{"qid": k, "answer_format": text} for k in want] + [{"qid": "answer"}]
    with S.quiet():
        out = C.solve_set(qs, {}, {"set": 1, "delivery": blob})
    bad = []
    for k, v in want.items():
        parsed = labels.parse(out.get(k)) if out.get(k) else None
        if parsed is None or not parsed.key.startswith("mobile.") or not parsed.key.endswith("/apk") or parsed.options[0][1] != v:
            bad.append(f"{k}: {str(out.get(k))[:70]}")
    S.check(not bad and out["answer"] and labels.parse(out["answer"]) is None,
            f"day 9 facts: {len(want)} facts are unsure under mobile.<fact>/apk, the package's value first; `answer` keeps its plain code",
            "; ".join(bad[:4]))
    hashes = {"apk_sha256": hashlib.sha256(blob).hexdigest(), "sha256": hashlib.sha256(blob).hexdigest(), "apk_md5": hashlib.md5(blob).hexdigest(),
              "dex_sha256": hashlib.sha256(members["classes.dex"]).hexdigest(), "manifest_sha1": hashlib.sha1(members["AndroidManifest.xml"]).hexdigest(),
              "apk_size_bytes": str(len(blob))}
    with S.quiet():
        got = C.solve_set([{"qid": k} for k in hashes], {}, {"set": 1, "delivery": blob})
        upper = C.solve_set([{"qid": "apk_sha256", "answer_format": {"kind": "pattern", "syntax": "64 uppercase hex characters"}},
                             {"qid": "apk_sha1", "answer_format": {"kind": "pattern", "pattern": "[0-9a-f]{64}"}}], {}, {"set": 1, "delivery": blob})
    S.check(got == hashes and upper == {"apk_sha256": hashes["sha256"].upper(), "apk_sha1": None},
            "day 9 facts: hashes and sizes are plain and right; upper-case when the syntax says so; None when the pattern refuses the value",
            str({k: (got.get(k), v) for k, v in hashes.items() if got.get(k) != v})[:200] + str(upper)[:120])
    # review fix: a hash or a size is plain only when the id names the package (or one member) and
    # nothing else. A word left over names another object, and a sentence is never read that closely.
    loose = ["native_lib_sha256", "payload_sha256", "answer_sha256", "key_size", "icon_size", "session_token_sha1",
             "config_md5", "dex_string_sha256", "sha256_of_decoded_answer", "c2_host"]
    tight = {"d09_apk_sha256": hashes["sha256"], "file_size_bytes": str(len(blob)), "classes_dex_sha256": hashes["dex_sha256"],
             "package_sha256_hex": hashes["sha256"]}
    with S.quiet():
        lo = C.solve_set([{"qid": k} for k in loose] + [{"qid": k} for k in tight], {}, {"set": 1, "delivery": blob})
        said = C.solve_set([{"qid": "q1", "question": "What is the SHA-256 of the string hidden in classes.dex?"},
                            {"qid": "q2", "question": "What is the size in bytes of the session key?"}], {}, {"set": 1, "delivery": blob})
        two_assets = C.solve_set([{"qid": "asset_sha256"}], {}, {"set": 1, "delivery": S.build({**members, "assets/other.bin": b"x" * 40})})
    parsed = {k: labels.parse(lo.get(k) or "") for k in loose}
    keys = {k: (p.key if p else None) for k, p in parsed.items()}
    sk = {k: (labels.parse(v).key if v and labels.parse(v) else v) for k, v in said.items()}
    S.check(all(p is not None and re.fullmatch(r"mobile\.[a-z0-9_]+/apk:[a-z0-9\-]+", p.key) for p in parsed.values())
            and len(set(keys.values())) == len(loose) and keys["c2_host"] == "mobile.host/apk:c2"
            and all(lo.get(k) == v for k, v in tight.items())
            and sk == {"q1": "mobile.dex_sha256/apk:q=q1", "q2": "mobile.apk_size/apk:q=q2"} and two_assets["asset_sha256"] is None,
            "day 9 facts: a hash or size id with a word left over, or read from a sentence, is unsure under a key of its own, never plain; "
            "`asset` is the puzzle only when it is the one asset",
            f"{keys} {str({k: lo.get(k) for k in tight})[:120]} {sk} {str(two_assets)[:60]}")
    silent = ["notes", "exported_provider", "provider_path", "favorite_color", "exported_service", "cert_sha256", "q7", "authority"]
    with S.quiet():
        none = C.solve_set([{"qid": k, "answer_format": text} for k in silent], {}, {"set": 1, "delivery": blob})
        listed = C.solve_set([{"qid": "permissions", "answer_format": {"kind": "json"}}, {"qid": "allow_backup", "answer_format": {"kind": "enum", "options": ["yes", "no"]}}],
                             {}, {"set": 1, "delivery": blob})
        sentence = C.solve_set([{"qid": "q1", "question": "What is the package name of the delivered APK?", "answer_format": text},
                                {"qid": "q2", "question": "Which scheme and which host does it use?", "answer_format": text}], {}, {"set": 1, "delivery": blob})
    S.check(all(v is None for v in none.values()), "day 9 facts: an id that names no fact, two facts, or a fact the package does not hold once is None",
            str({k: str(v)[:40] for k, v in none.items() if v is not None}))
    lp = labels.parse(listed.get("allow_backup") or "")
    sp = labels.parse(sentence.get("q1") or "")
    S.check(listed["permissions"] is None and lp is not None and lp.options == [("yes-no", "yes")] and sp is not None and sp.options[0][1] == pkg
            and sentence["q2"] is None,
            "day 9 facts: a list-valued question is None; only a listed form is offered; an id that says nothing is read from its sentence",
            f"{listed} {str(sentence)[:120]}")
    # no APK: nothing; one question with a fact id and no format is not given the code; an ANS- format is
    with S.quiet():
        zipped = C.solve_set([{"qid": "sha256"}, {"qid": "package_name"}], {}, {"set": 1, "delivery": S.build({"notes.txt": b"hello", "a.json": b"{}"})})
        lone = C.solve_set([{"qid": "package_name"}], {}, {"set": 1, "delivery": blob})
        code = C.solve_set([{"qid": "case_code", "answer_format": {"kind": "pattern", "syntax": "ANS- followed by 16 hex"}}], {}, {"set": 1, "delivery": blob})
    S.check(zipped == {"sha256": None, "package_name": None} and labels.parse(lone["package_name"] or "") is not None
            and code["case_code"] and labels.parse(code["case_code"]) is None,
            "day 9 facts: a delivery that is no APK answers nothing; a lone fact id is not given the code; an ANS- format is",
            f"{zipped} {str(lone)[:60]} {code}")
    # an iOS package: the same questions from Payload/<name>.app/Info.plist
    info = {"CFBundleIdentifier": "com.huntress.mobile.d09.ios", "CFBundleShortVersionString": "2.1", "CFBundleVersion": "42",
            "MinimumOSVersion": "15.0", "CFBundleDisplayName": "Day 09", "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
            "CFBundleURLTypes": [{"CFBundleURLSchemes": ["huntress09"]}]}
    ipa = S.build({"Payload/Fixture.app/Info.plist": plistlib.dumps(info, fmt=plistlib.FMT_BINARY), "Payload/Fixture.app/Fixture": b"\xcf\xfa\xed\xfe" + b"\0" * 64})
    ios_want = {"bundle_id": "com.huntress.mobile.d09.ios", "version_name": "2.1", "version_code": "42", "minimum_os_version": "15.0",
                "url_scheme": "huntress09", "cleartext_allowed": "true"}
    with S.quiet():
        ios = C.solve_set([{"qid": k, "answer_format": text} for k in ios_want] + [{"qid": "ipa_sha256"}, {"qid": "sha256"}], {}, {"set": 1, "delivery": ipa})
    first = {k: (labels.parse(ios[k]).options[0][1] if ios.get(k) and labels.parse(ios[k]) else ios.get(k)) for k in ios_want}
    S.check(first == ios_want and ios["sha256"] == hashlib.sha256(ipa).hexdigest(),
            "day 9 facts: an iOS package's Info.plist answers the same questions, unsure; its hash is plain", f"{first} {ios.get('sha256')}")
    # a package inside another archive: its facts are read, the delivery's hash and size are not the package's
    outer = S.build({"evidence/app.apk": blob, "readme.txt": b"see the app"})
    with S.quiet():
        nested = C.solve_set([{"qid": "package_name", "answer_format": text}, {"qid": "apk_sha256"}, {"qid": "apk_size"}], {}, {"set": 1, "delivery": outer})
    np = labels.parse(nested.get("package_name") or "")
    S.check(np is not None and np.options[0][1] == pkg and nested["apk_sha256"] is None and nested["apk_size"] is None,
            "day 9 facts: for a package inside another archive the facts are read; the delivery's hash and size are not offered as the package's",
            str(nested)[:160])
    S.check(F.match("deep_link_host")[0] == "host" and F.match("signing_certificate_sha256")[0] == "cert_sha256" and F.match("provider_path") is None
            and F.match("answer") is None and F.match("message") is None,
            "day 9 facts: the most specific words decide, a tie is no match, and the lanes' own ids name no fact")


def mastery_budget():
    a = S.ans()
    att = lambda n: {"artifacts": [{"filename": "m%02d.apk" % i} for i in range(n)],
                     "questions": [{"id": "set%d.answer" % (i + 1), "set": i + 1} for i in range(n)]}
    budgets = {n: C.set_budget({"attempt": att(n)}) for n in (1, 3, 5, 8, 20)}
    S.check(budgets[1] == budgets[3] == C.BUDGET and 0.2 < budgets[5] < C.BUDGET and abs(budgets[8] - 0.15) < 1e-9
            and budgets[20] == C.MIN_BUDGET and C.set_budget({}) == C.BUDGET and all(n * b <= max(1.2, 3 * C.BUDGET) + 1e-9 for n, b in budgets.items() if n <= 10),
            "day 9 mastery: a set's budget shrinks with the deliveries so that all of them fit the lane's solve cap", str(budgets))
    # eight sets: seven judged (plain at once), one that is a miss and may use only its share
    junk = bytes(S.rnd.randrange(256) for _ in range(2400))
    codes = [S.ans() for _ in range(8)]
    apks = [S.mini_apk(S.doc("reverse", c[::-1])) for c in codes]
    apks[3] = S.mini_apk(S.doc("mystery", S.b64(junk), key="huntress", shift=7, k2=[1, 2, 3]))
    t, outs = time.perf_counter(), []
    with S.quiet():
        for i, apk in enumerate(apks):
            outs.append(C.solve_set([{"qid": "answer", "answer_id": "set%d.answer" % (i + 1)}], {},
                                    {"set": i + 1, "delivery": apk, "attempt": att(8)})["answer"])
    dt = time.perf_counter() - t
    S.check(outs[3] is None and [o for i, o in enumerate(outs) if i != 3] == [c for i, c in enumerate(codes) if i != 3] and dt < 0.6,
            "day 9 mastery: eight deliveries, seven judged and one a miss: seven plain answers inside 0.6 s", f"{dt * 1000:.0f} ms {outs[3]!r}")
    del a


def fail_closed():
    R, D = C.apk_resources, C.asset_docs
    good = {
        "axml": manifest(), "arsc": arsc({"a": "b"}, {"n": 1}), "bplist": plistlib.dumps({"codec": "x", "data": "y"}, fmt=plistlib.FMT_BINARY),
        "sqlite": sqlite_db({"codec": "x", "data": "y"}), "msgpack": msgpack({"codec": "x", "data": "y"}), "cbor": cbor({"codec": "x", "data": "y"}),
        "protobuf": protobuf([(1, "xor"), (2, 5), (3, "abcd")]), "backup": android_backup({"a/b.json": b"{}"}), "tar": tar_of({"a.json": b"{}"}),
        "gzip": gzip.compress(b"{}"), "dex": dex(DEX_STRINGS), "elf": elf(["abcd", "efgh"]),
    }
    raised, t = [], time.perf_counter()
    for name, body in good.items():
        cuts = [body[:n] for n in (0, 1, 7, 8, 12, 20, len(body) // 2, len(body) - 1)]
        flips = [body[:i] + bytes([body[i] ^ 0xFF]) + body[i + 1:] for i in range(0, min(len(body), 160), 7)]
        big = [body[:8] + b"\xff" * 64 + body[8:], body + bytes(S.rnd.randrange(256) for _ in range(64))]
        for blob in cuts + flips + big:
            for label, fn in (("axml_tree", lambda b: R.axml_tree(b)), ("arsc_values", lambda b: R.arsc_values(b)),
                              ("arsc_strings", lambda b: R.arsc_strings(b)), ("pool", lambda b: R.pool_strings(b, 8)),
                              ("elf", lambda b: R.elf_strings(b)), ("expand", lambda b: R.expand("m", b)),
                              ("parse", lambda b: D.parse("m", b, known=lambda n: False)),
                              ("package_strings", lambda b: C.package_strings({"classes.dex": b, "res/x.xml": b, "lib/a.so": b}))):
                try:
                    fn(blob)
                except Exception as e:
                    raised.append(f"{label} on {name}: {type(e).__name__}")
    dt = time.perf_counter() - t
    S.check(not raised, "day 9 fail closed: truncated, flipped and padded bytes raise nothing in any reader", "; ".join(sorted(set(raised))[:4]))
    bad = []
    for name, body in good.items():
        for blob in (body[:len(body) // 2], body[:16] + bytes(S.rnd.randrange(256) for _ in range(400))):
            for member in (S.PZ, "assets/x.bin", "resources.arsc", "AndroidManifest.xml", "classes.dex"):
                try:
                    with S.quiet():
                        out = C.solve_set([{"qid": "answer"}, {"qid": "package_name"}], {}, {"set": 1, "delivery": S.build({member: blob})})
                except Exception as e:
                    bad.append(f"{name} as {member}: raised {type(e).__name__}")
                    continue
                # a manifest cut after its first element still states its package: unsure, never plain
                fact = out.get("package_name")
                if out.get("answer") is not None or (fact is not None and labels.parse(fact) is None) or set(out) != {"answer", "package_name"}:
                    bad.append(f"{name} as {member}: {str(out)[:60]}")
    S.check(not bad, "day 9 fail closed: broken members give no code, no plain fact and no exception", "; ".join(bad[:4]))
    # a binary plist that lists one object over and over: small on disk, not copied out
    x = ["codec", "data"]
    for _ in range(8):
        x = [x] * 60
    bomb = plistlib.dumps({"codec": "plain", "data": x}, fmt=plistlib.FMT_BINARY)
    t = time.perf_counter()
    parsed = D.parse("assets/bomb.plist", bomb, known=lambda n: False)
    got, dt3 = S.solve(S.build({**shell(), "assets/bomb.plist": bomb}), "a plist that repeats one object")
    S.check(len(bomb) < 65536 and parsed == [] and got is None and time.perf_counter() - t < 1.0,
            "day 9 fail closed: a plist that refers to one object 60^8 times is not expanded", f"{len(bomb)} bytes, {dt3 * 1000:.0f} ms")
    # a long run of members in other formats is a miss inside the budget
    many = {f"assets/f{i}.plist": plistlib.dumps({"k%d" % j: S.b64(bytes(S.rnd.randrange(256) for _ in range(40))) for j in range(20)},
                                                 fmt=plistlib.FMT_BINARY) for i in range(60)}
    many.update({f"assets/g{i}.properties": ("a=%s\nb=%s\n" % (S.b64(b"x" * 90), S.b64(b"y" * 90))).encode() for i in range(60)})
    got, dt2 = S.solve(S.build({**shell(), **many}), "120 members in other formats")
    S.check(got is None and dt2 < S.MISS_LIMIT, "day 9 fail closed: 120 members in other formats are a miss inside the budget", f"{dt2 * 1000:.0f} ms {got!r}")
    del dt


def checks(selftest):
    """Run every Day 9 check with the lane selftest's helpers (and its scratch ledger)."""
    _bind(selftest)
    S.scratch_ledger("challenges-day9")     # the seed and an empty ledger of its own
    try:
        more_codecs()
        shapes()
        other_documents()
        key_sources()
        package_strings()
        facts()
        mastery_budget()
        fail_closed()
    finally:
        S.scratch_ledger("challenges-synthetic")


def main() -> int:
    import shutil
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(HERE))
    import selftest
    try:
        checks(selftest)
    finally:
        shutil.rmtree(selftest.TMP, ignore_errors=True)
    passed = sum(1 for ok, _, _ in selftest.checks if ok)
    print(f"SELFTEST mobile-day9: {passed}/{len(selftest.checks)} checks passed, worst miss {selftest.worst['seconds'] * 1000:.0f} ms")
    return 0 if passed == len(selftest.checks) else 1


if __name__ == "__main__":
    # mobile.codec/apk-string:dex was promoted after Day 20 (Day 21 build): run against the seed these
    # checks were written for (only when run as a script; an importer keeps its own seed)
    os.environ["CTF_TESTING"] = "1"
    os.environ["CTF_LEDGER_MASK"] = "mobile.codec/apk-string:dex"
    sys.exit(main())
