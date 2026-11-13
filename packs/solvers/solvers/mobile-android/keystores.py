#!/usr/bin/env python3
"""Keystore files an APK may ship, read in plain Python: PKCS12, JKS, JCEKS and BKS (Day 14 look-ahead).

  .venv/bin/python solvers/mobile-android/keystores.py <keystore file or APK> [password ...]

What it gives: the SECRET entries of a keystore as bytes, each with the store's format and the entry's
alias. A secret entry is where an app that "uses the Keystore" would put a token or a data key:

  pkcs12   a secretBag (keytool -importpass, -genseckey): PBES2 (PBKDF2 with HMAC-SHA1/256/384/512,
           AES-CBC) or pbeWithSHAAnd3-KeyTripleDES-CBC
  jceks    a secret key entry: Sun's sealed object, PBEWithMD5AndTripleDES
  bks      BouncyCastle's store, versions 1 and 2: a KEY entry (stored in clear), a SECRET entry (in
           clear), a SEALED entry (PBEWithSHAAnd3-KeyTripleDES-CBC)
  jks      holds private keys and certificates only: no secret entry, so nothing is returned (its
           aliases are text in the file, and codec_search.py reads a code that stands there as it is)

Passwords: the ones the caller states (codec_search.keystore_passwords: what the package itself names
as a password), then USUAL. Nothing is generated and nothing is searched: a store that opens with none
of them is not read. A password is known to be right when the decrypted entry has the structure its
format says (a PKCS#8 body, a serialized key, a key record); nothing else is returned.

codec_search.py uses the secrets three ways, all unsure (never-guess): a secret that is an answer code
is offered under `keystore:<format>`; beside a puzzle document that gives another code it is the
second code; and every secret is key material for a document that names a cipher (`key-apk`).

No request, no file written, nothing executed. `cryptography` is imported only when a store is there.
"""
import hashlib
import struct
import sys
import time

USUAL = ("changeit", "android", "password", "")
MAX_STORE = 1 << 20          # bytes of a member that is read as a keystore
MAX_ITERATIONS = 200_000     # a key derivation that asks for more is not run (it would outlast the APK's time)
MAX_ENTRIES = 64
# Work, counted in hash iterations (review of 2026-10-13: a crafted BKS of 64 sealed entries at 200,000
# iterations each cost 9 to 10 s, and nothing looked at a deadline inside a store). Every key derivation is
# paid for before it is run; one that does not fit is not run, and the store is then "not read" for good.
STORE_WORK = 400_000         # iterations one store may cost (about 0.1 s): keytool's own JCEKS entry is one try of exactly this
APK_WORK = 400_000           # ... and all the stores of one APK together
CHECK_EVERY = 2048           # iterations between two looks at the deadline inside a derivation written in Python


class Cut(Exception):
    """The work this store may cost is used up, or the deadline has passed: the store is not read."""


class Work:
    """A meter for one call of secrets(): iterations left, and the deadline. pay(n) before a derivation of n
    iterations; tick(i) inside a Python loop."""

    def __init__(self, budget=APK_WORK, deadline=None):
        self.left, self.deadline, self.cut = int(budget), deadline, False

    def pay(self, n):
        if n > self.left or (self.deadline is not None and time.perf_counter() >= self.deadline):
            self.cut = True
            raise Cut()
        self.left -= n

    def paid(self, n):
        """Pay for a whole entry (n iterations over several derivations) and return a meter that only
        watches the deadline: an entry is derived whole or not begun (half of one bought nothing)."""
        self.pay(n)
        return Work(1 << 62, self.deadline)

    def tick(self, i):
        if self.deadline is not None and i % CHECK_EVERY == 0 and time.perf_counter() >= self.deadline:
            self.cut = True
            raise Cut()


_FREE = Work(budget=1 << 62)   # for a caller that sets no bound (the command line, a test of one derivation)
_PKCS7_DATA = bytes.fromhex("06092a864886f70d010701")
_PKCS7_ENCRYPTED = bytes.fromhex("06092a864886f70d010706")
_NAMES = (".p12", ".pfx", ".pkcs12", ".jks", ".jceks", ".bks", ".keystore", ".ks", ".uber")
_cache = {}


def kind(name, body) -> str:
    """'pkcs12', 'jks', 'jceks', 'bks' or '' for one member, by its first bytes (and for BKS its name too)."""
    if len(body) < 16 or len(body) > MAX_STORE:
        return ""
    if body[:4] == b"\xfe\xed\xfe\xed":
        return "jks"
    if body[:4] == b"\xce\xce\xce\xce":
        return "jceks"
    if body[:1] == b"\x30" and _PKCS7_DATA in body[:40]:
        return "pkcs12"
    if body[:4] in (b"\x00\x00\x00\x01", b"\x00\x00\x00\x02") and 4 <= struct.unpack(">I", body[4:8])[0] <= 64:
        low = str(name).lower()
        if low.endswith((".bks", ".keystore", ".ks")) or "bks" in low:
            return "bks"
    return ""


# ---------------------------------------------------------------------------- DER

def _tlv(b, at):
    """(tag, value start, value end) of the DER element at `at`. ValueError on anything that does not fit."""
    if at + 2 > len(b):
        raise ValueError("short")
    tag, n = b[at], b[at + 1]
    at += 2
    if n & 0x80:
        size = n & 0x7F
        if not 1 <= size <= 4 or at + size > len(b):
            raise ValueError("length")
        n = int.from_bytes(b[at:at + size], "big")
        at += size
    if at + n > len(b):
        raise ValueError("overrun")
    return tag, at, at + n


def _children(b, start, end):
    out, at = [], start
    while at < end:
        tag, s, e = _tlv(b, at)
        out.append((tag, s, e))
        at = e
    return out


def _oid(b) -> str:
    if not b:
        return ""
    parts, n = [b[0] // 40, b[0] % 40], 0
    for c in b[1:]:
        n = n << 7 | c & 0x7F
        if not c & 0x80:
            parts.append(n)
            n = 0
    return ".".join(str(x) for x in parts)


def _octets(b, tag, s, e) -> bytes:
    """The bytes of an OCTET STRING, also one written in pieces (constructed, 0x24 or [0] 0xA0)."""
    if tag in (0x04, 0x80):
        return b[s:e]
    return b"".join(_octets(b, t, s2, e2) for t, s2, e2 in _children(b, s, e))


# ---------------------------------------------------------------------------- key derivation and ciphers

def _pkcs12_kdf(alg, password, salt, count, ident, size, work=_FREE) -> bytes:
    """RFC 7292 appendix B: the key (ident 1), the IV (2) or the MAC key (3) from a BMPString password."""
    h = hashlib.new(alg)
    work.pay(count * -(-size // h.digest_size))
    u, v = h.digest_size, h.block_size
    pw = password.encode("utf-16-be") + b"\0\0" if password is not None else b""
    d = bytes([ident]) * v
    s = (salt * (v // len(salt) + 1))[:v * -(-len(salt) // v)] if salt else b""
    p = (pw * (v // len(pw) + 1))[:v * -(-len(pw) // v)] if pw else b""
    i, out = bytearray(s + p), b""
    while len(out) < size:
        a = hashlib.new(alg, d + bytes(i)).digest()
        for n in range(count - 1):
            a = hashlib.new(alg, a).digest()
            work.tick(n)
        out += a
        if len(out) >= size:
            break
        bb = int.from_bytes((a * (v // u + 1))[:v], "big") + 1
        for j in range(0, len(i), v):
            x = (int.from_bytes(i[j:j + v], "big") + bb) % (1 << (8 * v))
            i[j:j + v] = x.to_bytes(v, "big")
    return out[:size]


def _unpad(pt, block):
    if not pt or not 1 <= pt[-1] <= block or pt[-pt[-1]:] != bytes([pt[-1]]) * pt[-1]:
        return None
    return pt[:-pt[-1]]


def _cbc(name, key, iv, data):
    """AES or Triple DES in CBC with PKCS#5 padding taken off; None when the padding is not there."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    if name == "aes":
        alg = algorithms.AES(key)
    else:
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
        except ImportError:
            from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
        alg = TripleDES(key)
    block = 16 if name == "aes" else 8
    if not data or len(data) % block:
        return None
    dec = Cipher(alg, modes.CBC(iv)).decryptor()
    return _unpad(dec.update(data) + dec.finalize(), block)


_PRF = {"1.2.840.113549.2.7": "sha1", "1.2.840.113549.2.9": "sha256", "1.2.840.113549.2.10": "sha384",
        "1.2.840.113549.2.11": "sha512"}
_AES = {"2.16.840.1.101.3.4.1.2": 16, "2.16.840.1.101.3.4.1.22": 24, "2.16.840.1.101.3.4.1.42": 32}
_PBE_3DES = "1.2.840.113549.1.12.1.3"
_PBES2 = "1.2.840.113549.1.5.13"


def _pbe_decrypt(b, alg_s, alg_e, data, password, work=_FREE):
    """`data` decrypted under the AlgorithmIdentifier at b[alg_s:alg_e] with `password`; None when the
    scheme is not one this module reads, asks for too many iterations, or the padding does not come out."""
    kids = _children(b, alg_s, alg_e)
    if not kids or kids[0][0] != 0x06:
        return None
    oid = _oid(b[kids[0][1]:kids[0][2]])
    if oid == _PBE_3DES and len(kids) > 1:
        par = _children(b, kids[1][1], kids[1][2])
        salt, count = b[par[0][1]:par[0][2]], int.from_bytes(b[par[1][1]:par[1][2]], "big")
        if not 1 <= count <= MAX_ITERATIONS:
            return None
        work = work.paid(3 * count)      # two SHA-1 blocks of key and one of IV
        return _cbc("3des", _pkcs12_kdf("sha1", password, salt, count, 1, 24, work), _pkcs12_kdf("sha1", password, salt, count, 2, 8, work), data)
    if oid == _PBES2 and len(kids) > 1:
        par = _children(b, kids[1][1], kids[1][2])
        kdf, enc = _children(b, par[0][1], par[0][2]), _children(b, par[1][1], par[1][2])
        if _oid(b[kdf[0][1]:kdf[0][2]]) != "1.2.840.113549.1.5.12":
            return None
        kp = _children(b, kdf[1][1], kdf[1][2])
        salt, count = b[kp[0][1]:kp[0][2]], int.from_bytes(b[kp[1][1]:kp[1][2]], "big")
        prf = "sha1"
        for tag, s, e in kp[2:]:
            if tag == 0x30:
                prf = _PRF.get(_oid(b[_children(b, s, e)[0][1]:_children(b, s, e)[0][2]]))
        size = _AES.get(_oid(b[enc[0][1]:enc[0][2]]))
        if not prf or not size or not 1 <= count <= MAX_ITERATIONS:
            return None
        work.pay(count)     # one call into C: paid for whole, before it is made
        key = hashlib.pbkdf2_hmac(prf, password.encode("utf-8"), salt, count, size)
        return _cbc("aes", key, b[enc[1][1]:enc[1][2]], data)
    return None


# ---------------------------------------------------------------------------- PKCS12

_BAG_SHROUDED = "1.2.840.113549.1.12.10.1.2"
_BAG_SECRET = "1.2.840.113549.1.12.10.1.5"
_FRIENDLY = "1.2.840.113549.1.9.20"


def _pkcs8_key(pt):
    """The key bytes of a PKCS#8 PrivateKeyInfo (SEQUENCE {0, AlgorithmIdentifier, OCTET STRING}); None for anything else."""
    try:
        tag, s, e = _tlv(pt, 0)
        kids = _children(pt, s, e)
        if tag != 0x30 or e != len(pt) or len(kids) < 3 or kids[0][0] != 0x02 or kids[1][0] != 0x30 or kids[2][0] != 0x04:
            return None
        return pt[kids[2][1]:kids[2][2]]
    except (ValueError, IndexError):
        return None


def _alias(b, attrs) -> str:
    try:
        for tag, s, e in attrs:
            for _, s2, e2 in _children(b, s, e):
                kid = _children(b, s2, e2)
                if _oid(b[kid[0][1]:kid[0][2]]) == _FRIENDLY:
                    val = _children(b, kid[1][1], kid[1][2])[0]
                    return b[val[1]:val[2]].decode("utf-16-be", "replace")
    except (ValueError, IndexError):
        pass
    return ""


def _safe_contents(sc, password, out, work=_FREE):
    tag, s, e = _tlv(sc, 0)
    for btag, bs, be in _children(sc, s, e):
        bag = _children(sc, bs, be)
        if len(bag) < 2 or bag[0][0] != 0x06:
            continue
        oid = _oid(sc[bag[0][1]:bag[0][2]])
        alias = _alias(sc, [x for x in bag[2:] if x[0] == 0x31])
        inner = _children(sc, bag[1][1], bag[1][2])
        if oid == _BAG_SECRET and inner:
            sb = _children(sc, inner[0][1], inner[0][2])
            kind_oid = _oid(sc[sb[0][1]:sb[0][2]])
            value = _children(sc, sb[1][1], sb[1][2])[0]
            raw = _octets(sc, *value)
            if kind_oid == _BAG_SHROUDED:
                # the JDK's form: an EncryptedPrivateKeyInfo whose plain text is a PKCS#8 body round the secret
                t2, s2, e2 = _tlv(raw, 0)
                epki = _children(raw, s2, e2)
                pt = _pbe_decrypt(raw, epki[0][1], epki[0][2], raw[epki[1][1]:epki[1][2]], password, work)
                key = _pkcs8_key(pt) if pt else None
                if key is not None:
                    out.append((alias, key))
            elif raw:
                out.append((alias, raw))


def _pkcs12(body, password, work=_FREE) -> list:
    """[(alias, secret bytes)] of a PFX under one password. [] when nothing opens; ValueError on a file that is no PFX."""
    out = []
    tag, s, e = _tlv(body, 0)
    top = _children(body, s, e)
    auth = _children(body, top[1][1], top[1][2])
    if _oid(body[auth[0][1]:auth[0][2]]) != "1.2.840.113549.1.7.1":
        raise ValueError("authSafe")
    safes = _octets(body, *_children(body, auth[1][1], auth[1][2])[0])
    tag, s, e = _tlv(safes, 0)
    for _, cs, ce in _children(safes, s, e):
        ci = _children(safes, cs, ce)
        oid = _oid(safes[ci[0][1]:ci[0][2]])
        try:
            if oid == "1.2.840.113549.1.7.1":
                _safe_contents(_octets(safes, *_children(safes, ci[1][1], ci[1][2])[0]), password, out, work)
            elif oid == "1.2.840.113549.1.7.6":
                ed = _children(safes, *_children(safes, ci[1][1], ci[1][2])[0][1:])
                eci = _children(safes, ed[1][1], ed[1][2])
                data = _octets(safes, *eci[2]) if len(eci) > 2 else b""
                pt = _pbe_decrypt(safes, eci[1][1], eci[1][2], data, password, work)
                if pt and pt[:1] == b"\x30":
                    _safe_contents(pt, password, out, work)
        except (ValueError, IndexError):
            continue
    return out


# ---------------------------------------------------------------------------- JKS and JCEKS

_BYTES_CLASS = b"ur\x00\x02[B\xac\xf3\x17\xf8\x06\x08T\xe0\x02\x00\x00xp"


def _utf(b, at):
    n = struct.unpack(">H", b[at:at + 2])[0]
    return b[at + 2:at + 2 + n].decode("utf-8", "replace"), at + 2 + n


def _sun_3des(password, salt, count, data, work=_FREE):
    """Sun's PBEWithMD5AndTripleDES (com.sun.crypto.provider.PBES1Core): each half of the salt hashed with the
    password `count` times, the first half mirrored when both halves are equal; 24 key bytes and 8 of IV."""
    if len(salt) != 8 or not 1 <= count <= MAX_ITERATIONS:
        return None
    salt = bytearray(salt)
    if salt[:4] == salt[4:]:
        salt[0], salt[3] = salt[3], salt[0]
        salt[1], salt[2] = salt[2], salt[1]
    pw, derived = password.encode("ascii", "replace"), b""
    work.pay(2 * count)
    for half in (bytes(salt[:4]), bytes(salt[4:])):
        d = half
        for n in range(count):
            d = hashlib.md5(d + pw).digest()
            work.tick(n)
        derived += d
    return _cbc("3des", derived[:24], derived[24:32], data)


def _jceks(body, password, work=_FREE) -> list:
    """[(alias, secret bytes)] of a JKS or JCEKS store: the secret key entries (tag 3). A JKS has none."""
    out, at = [], 12
    count = struct.unpack(">I", body[8:12])[0]
    for _ in range(min(count, MAX_ENTRIES)):
        tag = struct.unpack(">I", body[at:at + 4])[0]
        alias, at = _utf(body, at + 4)
        at += 8
        if tag == 1:
            n = struct.unpack(">I", body[at:at + 4])[0]
            at += 4 + n
            chain = struct.unpack(">I", body[at:at + 4])[0]
            at += 4
            for _ in range(min(chain, 16)):
                _, at = _utf(body, at)
                n = struct.unpack(">I", body[at:at + 4])[0]
                at += 4 + n
        elif tag == 2:
            _, at = _utf(body, at)
            n = struct.unpack(">I", body[at:at + 4])[0]
            at += 4 + n
        elif tag == 3:
            # a Java-serialized sealed object: its two byte arrays are the PBE parameters and the cipher text,
            # and it ends behind the name of the sealing algorithm
            a = body.find(_BYTES_CLASS, at)
            if a < 0:
                break
            a += len(_BYTES_CLASS)
            n = struct.unpack(">I", body[a:a + 4])[0]
            params, a = body[a + 4:a + 4 + n], a + 4 + n
            if body[a:a + 1] != b"u":     # the second array: TC_ARRAY and a reference to the class above
                break
            a += 6 if body[a + 1:a + 2] == b"q" else 1
            n = struct.unpack(">I", body[a:a + 4])[0]
            sealed, a = body[a + 4:a + 4 + n], a + 4 + n
            end = body.find(b"PBEWithMD5AndTripleDES", a)
            if end < 0:
                break
            at = end + len(b"PBEWithMD5AndTripleDES")
            try:
                tag2, s, e = _tlv(params, 0)
                kids = _children(params, s, e)
                pt = _sun_3des(password, params[kids[0][1]:kids[0][2]], int.from_bytes(params[kids[1][1]:kids[1][2]], "big"), sealed, work)
            except (ValueError, IndexError):
                pt = None
            if pt and pt[:2] == b"\xac\xed":
                k = pt.find(_BYTES_CLASS)
                if k >= 0:
                    k += len(_BYTES_CLASS)
                    n = struct.unpack(">I", pt[k:k + 4])[0]
                    if 0 < n <= len(pt) - k - 4:
                        out.append((alias, pt[k + 4:k + 4 + n]))
        else:
            break
    return out


# ---------------------------------------------------------------------------- BKS

def _bks_key(b, at=0):
    """(key bytes, end) of BouncyCastle's key record: type byte, format, algorithm, length, bytes."""
    if b[at] > 2:
        raise ValueError("key type")
    _, at = _utf(b, at + 1)
    _, at = _utf(b, at)
    n = struct.unpack(">I", b[at:at + 4])[0]
    if n > len(b) - at - 4:
        raise ValueError("key length")
    return b[at + 4:at + 4 + n], at + 4 + n


def _bks(body, password, work=_FREE) -> list:
    """[(alias, secret bytes)] of a BKS store, versions 1 and 2: KEY (2) and SECRET (3) entries as they stand,
    SEALED (4) entries decrypted with PBEWithSHAAnd3-KeyTripleDES-CBC under the password."""
    out = []
    n = struct.unpack(">I", body[4:8])[0]
    at = 8 + n + 4
    for _ in range(MAX_ENTRIES):
        kind_ = body[at]
        if kind_ == 0:
            break
        alias, at = _utf(body, at + 1)
        at += 8
        chain = struct.unpack(">I", body[at:at + 4])[0]
        at += 4
        for _ in range(min(chain, 16)):
            _, at = _utf(body, at)
            n = struct.unpack(">I", body[at:at + 4])[0]
            at += 4 + n
        if kind_ == 1:
            _, at = _utf(body, at)
            n = struct.unpack(">I", body[at:at + 4])[0]
            at += 4 + n
        elif kind_ == 2:
            key, at = _bks_key(body, at)
            out.append((alias, key))
        elif kind_ in (3, 4):
            n = struct.unpack(">I", body[at:at + 4])[0]
            blob, at = body[at + 4:at + 4 + n], at + 4 + n
            if kind_ == 3:
                out.append((alias, blob))
                continue
            sn = struct.unpack(">I", blob[:4])[0]
            salt, count = blob[4:4 + sn], struct.unpack(">I", blob[4 + sn:8 + sn])[0]
            if not 1 <= count <= MAX_ITERATIONS or not salt:
                continue
            try:
                entry = work.paid(3 * count)     # two SHA-1 blocks of key and one of IV, or nothing
                pt = _cbc("3des", _pkcs12_kdf("sha1", password, salt, count, 1, 24, entry), _pkcs12_kdf("sha1", password, salt, count, 2, 8, entry),
                          blob[8 + sn:])
            except Cut:
                work.cut = True
                continue    # this entry's derivation does not fit the work left: it is not read (work.cut says so); the clear ones still are
            if pt:
                try:
                    out.append((alias, _bks_key(pt)[0]))
                except (ValueError, IndexError, struct.error):
                    pass
        else:
            break
    return out


_READ = {"pkcs12": _pkcs12, "jks": _jceks, "jceks": _jceks, "bks": _bks}


def read(name, body, passwords, deadline=None, work=None) -> list:
    """[(format, alias, secret bytes)] of one keystore file: the first password of `passwords` under which
    a secret entry comes out. A BKS store's clear entries need none. [] for anything else, and [] with
    work.cut set when the store's work (STORE_WORK iterations, or what the caller's meter has left) or the
    deadline ran out first: the caller then knows the store was not read."""
    fmt = kind(name, body)
    if not fmt or fmt == "jks":
        return []
    outer = work if work is not None else Work(APK_WORK, deadline)
    mine = Work(min(STORE_WORK, outer.left), outer.deadline)
    try:
        for pw in passwords:
            try:
                got = _READ[fmt](body, pw, mine)
            except Cut:
                raise
            except Exception:   # a hostile or cut file costs this store, never the answer
                got = []
            got = [(fmt, alias, bytes(secret)) for alias, secret in got if secret and len(secret) <= 4096]
            if got:
                outer.cut = outer.cut or mine.cut
                return got
        outer.cut = outer.cut or mine.cut
        return []
    except Cut:
        outer.cut = True
        return []
    finally:
        outer.left -= min(STORE_WORK, outer.left) - mine.left


def secrets(members, stated=(), deadline=None, budget=APK_WORK, state=None) -> list:
    """[(format, alias, secret bytes)] over every keystore among an APK's members, the stated passwords
    first and USUAL after them, for at most `budget` iterations of key derivation in all (and STORE_WORK a
    store). Remembered per exact store, password list and effective remaining budget. A deadline-bound result is
    additionally scoped to that exact deadline: an expired/short clock can therefore avoid repeated work inside
    its own solve without poisoning a later replay with more time. `state`, when the caller gives a dict, gets
    state["cut"] = True if any store was not read."""
    out = []
    passwords = list(dict.fromkeys([p for p in stated if isinstance(p, str)] + list(USUAL)))[:12]
    work = Work(budget, deadline)
    for n, body in members.items():
        fmt = kind(n, body)
        if not fmt:
            continue
        # `work` is shared by every store in member order.  The declared APK budget is not the allowance this
        # store necessarily receives: an earlier store may have consumed part or all of it.  Scoping a cut result
        # only to `budget` poisoned a later replay in which the same store stood alone with the full allowance.
        # Record the logical work spent as well, so a cache hit leaves following stores with the same allowance as
        # a cold run rather than making cached derivations free for purposes of the all-store cap.
        available = int(work.left)
        stable = (hashlib.sha256(body).digest(), fmt, tuple(passwords), available)
        slot = stable if deadline is None else stable + (float(deadline),)
        if slot not in _cache:
            if len(_cache) > 64:
                _cache.clear()
            before = work.cut
            work.cut = False
            got = read(n, body, passwords, deadline, work)
            _cache[slot] = (got, work.cut, available - int(work.left))
            work.cut = work.cut or before
        got, cut, spent = _cache[slot]
        if int(work.left) == available:
            work.left = max(0, int(work.left) - int(spent))
        if cut and state is not None:
            state["cut"] = True
        out += got
    return out


def main(argv) -> int:
    import zipfile
    if argv and argv[0] in ("-h", "--help"):
        print("usage: keystores.py <keystore-file-or-apk> [password ...]")
        return 0
    if not argv:
        print("keystores.py: expected a keystore file or APK", file=sys.stderr)
        return 2
    try:
        path, stated = argv[0], argv[1:]
        body = open(path, "rb").read()
        members = {path: body}
        if body[:2] == b"PK":
            with zipfile.ZipFile(path) as z:
                members = {i.filename: z.read(i) for i in z.infolist() if i.file_size <= MAX_STORE}
        found = [(n, kind(n, b)) for n, b in members.items() if kind(n, b)]
        for n, fmt in found:
            print("STORE %s format=%s bytes=%d" % (n, fmt, len(members[n])))
        for fmt, alias, secret in secrets(members, stated):
            shown = secret.decode("ascii") if secret.isascii() and secret.decode("ascii").isprintable() else secret.hex()
            print("SECRET format=%s alias=%r bytes=%d value=%s" % (fmt, alias, len(secret), shown[:80]))
        if not found:
            print("no keystore among %d member(s)" % len(members))
        return 0
    except Exception as exc:
        print(f"keystores.py: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
