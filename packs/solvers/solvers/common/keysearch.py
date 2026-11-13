#!/usr/bin/env python3
"""Resumable key search (B-215): candidate banks, an exact verifier, and a crash-safe ledger.

A key-derivation search ("the key is md5 of the friend's SID and a word from the note, or a PBKDF2 of
them, or their UTF-16 forms ...") was rebuilt by hand at least eight times across two harnesses on one
challenge, each pass re-testing what the last had already ruled out. This harness makes such a search a
job on disk that any agent can continue:

    <workdir>/keysearch/<id>/job.json      the frozen job: banks, templates, derivations, verifier
                                           (written once, atomically, mode 0600; it holds candidate atoms)
    <workdir>/keysearch/<id>/ledger.jsonl  the progress ledger: one line per finished chunk, per hit,
                                           per run start and stop (append-only, flock, one os.write each)
    <workdir>/keysearch/<id>/run.lock      held by the one process searching the job

The space. A *bank* is a named list of atoms: literal values, hex values, the lines of a file (frozen by
sha256), candidates harvested from a handout (B-074 `harvest`), the archive-password store
(`archive_passwords`), or the configured wordlist (`hashcrack.wordlist()`, CTF_WORDLIST). Each text atom
is expanded into its variants: case (as-is, lower, upper, title) x encoding (utf8, utf16le, utf16be,
latin1) x NUL terminator. A *template* joins one atom from each of its slots with a separator (all
slot orders with orders = "all"). A *derivation* turns the joined bytes into a key: raw, pad0, a hash
(md4 md5 sha1 sha256 ...; iterated as sha256*1000), hmac:ALG (key = candidate, msg = salt),
hmac-salt:ALG (key = salt, msg = candidate), pbkdf2:ALG:ITERS, scrypt:N:R:P, each salted derivation
once per salt. The space is every (template, atoms, separator, derivation): a mixed-radix index, so a
candidate is a number, a chunk is a range of numbers, and a resumed run skips exactly the chunks the
ledger says are done.

The verifier is exact: it says yes or no, it never scores. hash (the derived key equals a target),
hmac (HMAC(key, msg) equals a tag), aes-gcm (the tag authenticates), crib (aes-ecb/cbc/ctr, xor or rc4
decrypts a known plaintext at an offset; optional PKCS#7 check of the last block), zip (the key opens an
encrypted member of a zip: AES verifier then HMAC, or ZipCrypto check byte then CRC). Each states the
bits it checks; `new` refuses a job whose expected chance hits over the whole space
(candidates x 2^-bits) exceed MAX_CHANCE unless allow_weak is set, so a hit means the key.

Never a plaintext key in a log: the ledger and every printed line show a mask (length and first
character) and the recipe (bank names, separator length, derivation). `show --reveal` reconstructs a
hit's candidate from its index on request, to stdout only. A zip hit found with the raw derivation is
added to the archive-password store, so the sweep and the archive lane open that archive next time.

    python solvers/common/keysearch.py new ID --spec SPEC.toml [--replace] [--allow-weak]
    python solvers/common/keysearch.py run ID [--workers N] [--max-chunks N] [--cpu-seconds S] [--all]
    python solvers/common/keysearch.py status ID [--json]
    python solvers/common/keysearch.py show ID [--hit N | --index I] [--reveal]
    python solvers/common/keysearch.py list
    python -m ctf keysearch ...             (the same commands)

Exit codes: new 0, run 0 a hit (now or already), 1 the space is exhausted with no hit, 3 stopped early
(--max-chunks, --cpu-seconds, interrupted: run it again to resume), 2 error (a named reason).
Offline; nothing here starts a program or touches the network.
"""
from __future__ import annotations

import argparse
import bisect
import contextlib
import fcntl
import hashlib
import hmac as _hmac
import io
import itertools
import json
import os
import re
import signal
import sys
import tempfile
import time
import zipfile
from pathlib import Path

try:
    from ctf import event as ctf_event, ledger as ctf_ledger, packs as ctf_packs, paths as ctf_paths
except ModuleNotFoundError:          # a script run: put the checkout root on sys.path
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import event as ctf_event, ledger as ctf_ledger, packs as ctf_packs, paths as ctf_paths

SCHEMA = 1
DIR_NAME = "keysearch"
JOB_NAME = "job.json"
LOCK_NAME = "run.lock"
PROGRESS_NAME = ctf_ledger.LEDGER_NAME       # ctf.ledger.append(workdir=<search dir>) writes it
DEFAULT_CHUNK = 2048
MAX_CHANCE = 1e-3          # expected chance hits over the whole space above this: refused unless allow_weak
CASES = ("as-is", "lower", "upper", "title")
ENCODINGS = ("utf8", "utf16le", "utf16be", "latin1")
_CODEC = {"utf8": "utf-8", "utf16le": "utf-16-le", "utf16be": "utf-16-be", "latin1": "latin-1"}
CIPHERS = ("aes-ecb", "aes-cbc", "aes-ctr", "xor", "rc4")
VERIFY_KINDS = ("hash", "hmac", "aes-gcm", "crib", "zip")
AES_KEYS = (16, 24, 32)
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,31}$")

EXIT_HIT, EXIT_EXHAUSTED, EXIT_ERROR, EXIT_STOPPED = 0, 1, 2, 3


class KeySearchError(RuntimeError):
    """The job, its inputs or the request are unusable; the message names why."""


# ---------------------------------------------------------------------------- siblings (B-074 lane)

def _sibling(name: str, lane: str = "common"):
    """A sibling engine module under its flat name (the name the lanes and the suite import it by)."""
    if name in sys.modules:
        return sys.modules[name]
    return ctf_packs.load_module(name, ctf_paths.repo_root() / "solvers" / lane / f"{name}.py", pack=name)


def mask(value: bytes | str | None) -> str:
    """All a line ever shows of a candidate or key: its length and first character."""
    if value is None:
        return "<none>"
    if isinstance(value, str):
        value = value.encode("utf-8")
    if not value:
        return "<empty>"
    c = chr(value[0])
    first = c if c.isascii() and c.isalnum() else "?"
    return f"<{len(value)} bytes, starts {first}>"


def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _unhex(value, what: str) -> bytes:
    try:
        return bytes.fromhex(str(value).replace(" ", ""))
    except ValueError:
        raise KeySearchError(f"{what}: not hex: {value!r}") from None


# ---------------------------------------------------------------------------- derivations

def _hash_fn(alg: str):
    if alg == "md4":
        md4 = _sibling("hashcrack", "toolkits").md4        # B-074: pure-Python MD4 (OpenSSL 3 dropped it)
        return md4
    if alg.startswith("shake"):
        raise KeySearchError(f"hash {alg!r} has no fixed length: not a derivation")
    if alg not in hashlib.algorithms_available:
        raise KeySearchError(f"unknown hash {alg!r} (hashlib has: md5, sha1, sha256, sha512, sha3_256, "
                             "blake2b, ... ; md4 comes from hashcrack)")
    return lambda b, _a=alg: hashlib.new(_a, b).digest()


def _hmac_alg(alg: str) -> str:
    if alg not in hashlib.algorithms_available or alg.startswith("shake"):
        raise KeySearchError(f"unknown HMAC hash {alg!r}")
    return alg


def parse_kdf(spec: str, key_len: int | None):
    """(function(candidate, salt) -> bytes or None, salted?) for one derivation spec. A None output
    means the derivation does not apply to this candidate (raw with the wrong length)."""
    s = str(spec).strip()
    if s == "raw":
        if key_len is None:
            return (lambda x, salt: x), False
        return (lambda x, salt, _n=key_len: x if len(x) == _n else None), False
    if s == "pad0":
        if key_len is None:
            raise KeySearchError("derivation pad0 needs key_len")
        return (lambda x, salt, _n=key_len: x[:_n].ljust(_n, b"\x00")), False
    parts = s.split(":")
    try:
        if parts[0] == "hmac" and len(parts) == 2:
            alg = _hmac_alg(parts[1])
            return (lambda x, salt, _a=alg: _hmac.new(x, salt, _a).digest()), True
        if parts[0] == "hmac-salt" and len(parts) == 2:
            alg = _hmac_alg(parts[1])
            return (lambda x, salt, _a=alg: _hmac.new(salt, x, _a).digest()), True
        if parts[0] == "pbkdf2" and len(parts) == 3:
            alg, iters = _hmac_alg(parts[1]), int(parts[2])
            if iters < 1:
                raise ValueError
            dk = key_len or hashlib.new(alg).digest_size
            return (lambda x, salt, _a=alg, _i=iters, _d=dk: hashlib.pbkdf2_hmac(_a, x, salt, _i, _d)), True
        if parts[0] == "scrypt" and len(parts) == 4:
            n, r, p = int(parts[1]), int(parts[2]), int(parts[3])
            if n < 2 or n & (n - 1) or r < 1 or p < 1:
                raise ValueError
            dk = key_len or 32
            return (lambda x, salt, _n=n, _r=r, _p=p, _d=dk:
                    hashlib.scrypt(x, salt=salt, n=_n, r=_r, p=_p, dklen=_d, maxmem=1 << 30)), True
    except ValueError:
        raise KeySearchError(f"bad derivation {s!r} (pbkdf2:ALG:ITERS, scrypt:N:R:P with N a power of 2)") from None
    if len(parts) == 1:
        alg, rounds = s, 1
        if "*" in s:
            alg, _, r = s.partition("*")
            try:
                rounds = int(r)
            except ValueError:
                raise KeySearchError(f"bad derivation {s!r} (ALG*ROUNDS)") from None
            if rounds < 1:
                raise KeySearchError(f"bad derivation {s!r}: rounds must be >= 1")
        fn = _hash_fn(alg)
        if rounds == 1:
            return (lambda x, salt, _f=fn: _f(x)), False

        def iterated(x, salt, _f=fn, _r=rounds):
            for _ in range(_r):
                x = _f(x)
            return x
        return iterated, False
    raise KeySearchError(f"unknown derivation {s!r} (raw, pad0, ALG, ALG*N, hmac:ALG, hmac-salt:ALG, "
                         "pbkdf2:ALG:ITERS, scrypt:N:R:P)")


# ---------------------------------------------------------------------------- verifiers

class Verifier:
    """Exact: check(key) is True only for the key. `bits` is how many bits of evidence a pass carries."""
    kind = "?"
    bits = 0

    def check(self, key: bytes) -> bool:            # pragma: no cover - every kind overrides it
        raise NotImplementedError

    def describe(self) -> str:
        return f"{self.kind} ({self.bits} bits checked)"


class HashVerifier(Verifier):
    kind = "hash"

    def __init__(self, target: bytes):
        self.target, self.bits = target, 8 * len(target)

    def check(self, key):
        return _hmac.compare_digest(key, self.target)


class HmacVerifier(Verifier):
    kind = "hmac"

    def __init__(self, alg: str, msg: bytes, tag: bytes):
        self.alg, self.msg, self.tag, self.bits = _hmac_alg(alg), msg, tag, 8 * len(tag)

    def check(self, key):
        return _hmac.compare_digest(_hmac.new(key, self.msg, self.alg).digest()[:len(self.tag)], self.tag)


def _crypto():
    try:
        from Crypto.Cipher import AES, ARC4
    except ImportError:
        raise KeySearchError("pycryptodome is not importable: it is pinned in requirements.in; "
                             "install it into the venv") from None
    return AES, ARC4


class GcmVerifier(Verifier):
    kind = "aes-gcm"

    def __init__(self, nonce: bytes, ct: bytes, tag: bytes, aad: bytes):
        self.AES = _crypto()[0]
        self.nonce, self.ct, self.tag, self.aad, self.bits = nonce, ct, tag, aad, 8 * len(tag)

    def check(self, key):
        if len(key) not in AES_KEYS:
            return False
        c = self.AES.new(key, self.AES.MODE_GCM, nonce=self.nonce, mac_len=len(self.tag))
        c.update(self.aad)
        try:
            c.decrypt_and_verify(self.ct, self.tag)
        except ValueError:
            return False
        return True


class CribVerifier(Verifier):
    kind = "crib"

    def __init__(self, cipher: str, ct: bytes, crib: bytes, offset: int, iv: bytes, nonce: bytes,
                 initial: int, pkcs7_tail: bytes | None):
        self.AES, self.ARC4 = _crypto()
        self.cipher, self.ct, self.crib, self.offset = cipher, ct, crib, offset
        self.iv, self.nonce, self.initial, self.tail = iv, nonce, initial, pkcs7_tail
        self.bits = 8 * len(crib) + (8 if pkcs7_tail is not None else 0)

    def describe(self):
        return f"crib {self.cipher} ({self.bits} bits checked)"

    def _plain(self, key: bytes) -> bytes | None:
        ct, A = self.ct, self.AES
        if self.cipher == "xor":
            if not key:
                return None
            return bytes(c ^ key[i % len(key)] for i, c in enumerate(ct))
        if self.cipher == "rc4":
            try:
                return self.ARC4.new(key).decrypt(ct)
            except ValueError:                    # a key length ARC4 refuses
                return None
        if len(key) not in AES_KEYS:
            return None
        if self.cipher == "aes-ecb":
            return A.new(key, A.MODE_ECB).decrypt(ct)
        if self.cipher == "aes-cbc":
            return A.new(key, A.MODE_CBC, iv=self.iv).decrypt(ct)
        return A.new(key, A.MODE_CTR, nonce=self.nonce, initial_value=self.initial).decrypt(ct)

    def _pkcs7_ok(self, key: bytes) -> bool:
        prev, last = self.tail[:16], self.tail[16:]
        A = self.AES
        block = A.new(key, A.MODE_ECB).decrypt(last)
        if self.cipher == "aes-cbc":
            block = bytes(a ^ b for a, b in zip(block, prev))
        n = block[-1]
        return 1 <= n <= 16 and block.endswith(bytes([n]) * n)

    def check(self, key):
        p = self._plain(key)
        if p is None or p[self.offset:self.offset + len(self.crib)] != self.crib:
            return False
        return self.tail is None or self._pkcs7_ok(key)


class ZipVerifier(Verifier):
    kind = "zip"

    def __init__(self, data: bytes):
        self.ap = _sibling("archive_passwords")
        self.data = data
        try:
            self.zf = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            raise KeySearchError("zip verifier: the file is not a zip") from None
        enc = [i for i in self.zf.infolist() if not i.is_dir() and self.ap.encrypted(i)]
        if not enc:
            raise KeySearchError("zip verifier: the zip has no encrypted member")
        self.info = min(enc, key=lambda i: i.compress_size)
        self.aes = self.info.compress_type == self.ap.AES_METHOD
        if self.aes and self.ap.pyzipper is None:
            raise KeySearchError("zip verifier: the member is WinZip-AES and pyzipper is not importable "
                                 "(pinned in requirements.in)")
        # AES: 16-bit password verifier + 80-bit HMAC; ZipCrypto: 8-bit check byte + CRC-32
        self.bits = 96 if self.aes else 40

    def describe(self):
        return f"zip {'aes' if self.aes else 'zipcrypto'} member ({self.bits} bits checked)"

    def check(self, key):
        if self.aes and not self.ap.aes_verifier_ok(self.data, self.info, key):
            return False
        return self.ap.Opener(self.data, zf=self.zf, cands=[key]).read(self.info) is not None


# ---------------------------------------------------------------------------- freezing a spec into a job

def _strs(value, what: str) -> list:
    if value is None:
        return []
    if isinstance(value, str) or not isinstance(value, list):
        raise KeySearchError(f"{what} must be a list")
    return value


def _choice(values, allowed, what: str, default) -> list:
    vals = _strs(values, what) or list(default)
    bad = [v for v in vals if v not in allowed]
    if bad:
        raise KeySearchError(f"{what}: unknown {bad} (one of {', '.join(map(str, allowed))})")
    return list(dict.fromkeys(vals))


def _path(value, base: Path, what: str) -> Path:
    p = Path(str(value)).expanduser()
    p = (p if p.is_absolute() else base / p).resolve()
    if not p.is_file():
        raise KeySearchError(f"{what}: no such file: {p}")
    return p


def _file_ref(p: Path, limit) -> dict:
    if limit is not None and (not isinstance(limit, int) or limit < 1):
        raise KeySearchError(f"bank file limit must be a positive integer, not {limit!r}")
    return {"path": str(p), "sha256": _sha256_file(p), "limit": limit}


def _freeze_bank(b: dict, base: Path) -> dict:
    if not isinstance(b, dict):
        raise KeySearchError("each bank must be a table")
    name = b.get("name")
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise KeySearchError(f"bad bank name {name!r} (letters, digits, _ -; max 32)")
    known = {"name", "values", "hex", "file", "limit", "harvest", "siblings", "store", "wordlist",
             "case", "encodings", "nul"}
    extra = sorted(set(b) - known)
    if extra:
        raise KeySearchError(f"bank {name}: unknown key(s) {extra}")
    values = [str(v) for v in _strs(b.get("values"), f"bank {name} values")]
    hexes = [_unhex(v, f"bank {name} hex").hex() for v in _strs(b.get("hex"), f"bank {name} hex")]
    if b.get("harvest") is not None:
        src = _path(b["harvest"], base, f"bank {name} harvest")
        values += _sibling("harvest").harvest(src, include_siblings=bool(b.get("siblings", True)))
    if b.get("store"):
        values += [c.decode("utf-8", "surrogateescape") for c in _sibling("archive_passwords").candidates()]
    files = []
    if b.get("file") is not None:
        files.append(_file_ref(_path(b["file"], base, f"bank {name} file"), b.get("limit")))
    if b.get("wordlist"):
        hc = _sibling("hashcrack", "toolkits")
        try:
            wl = hc.wordlist()
        except hc.WordlistMissing as e:
            raise KeySearchError(f"bank {name}: {e}") from None
        files.append(_file_ref(Path(wl), b.get("limit")))
    nul = b.get("nul", [False])
    nul = [nul] if isinstance(nul, bool) else _strs(nul, f"bank {name} nul")
    if not nul or any(not isinstance(x, bool) for x in nul):
        raise KeySearchError(f"bank {name}: nul must be true, false or a list of them")
    return {"name": name, "values": list(dict.fromkeys(values)), "hex": list(dict.fromkeys(hexes)),
            "files": files,
            "case": _choice(b.get("case"), CASES, f"bank {name} case", ["as-is"]),
            "encodings": _choice(b.get("encodings"), ENCODINGS, f"bank {name} encodings", ["utf8"]),
            "nul": list(dict.fromkeys(nul))}


def _byte_list(spec: dict, text_key: str, hex_key: str, what: str) -> list[str]:
    """A list of byte strings, stated as text (utf-8) and/or hex, frozen as hex."""
    out = [str(v).encode("utf-8").hex() for v in _strs(spec.get(text_key), f"{what} {text_key}")]
    out += [_unhex(v, f"{what} {hex_key}").hex() for v in _strs(spec.get(hex_key), f"{what} {hex_key}")]
    return list(dict.fromkeys(out))


def _freeze_template(t: dict, banks: set) -> dict:
    if not isinstance(t, dict):
        raise KeySearchError("each template must be a table")
    extra = sorted(set(t) - {"slots", "seps", "seps_hex", "orders"})
    if extra:
        raise KeySearchError(f"template: unknown key(s) {extra}")
    slots = _strs(t.get("slots"), "template slots")
    if not slots:
        raise KeySearchError("a template needs at least one slot")
    missing = [s for s in slots if s not in banks]
    if missing:
        raise KeySearchError(f"template slots name no bank: {missing}")
    seps = _byte_list(t, "seps", "seps_hex", "template") or [""]
    orders = t.get("orders", "given")
    if orders not in ("given", "all"):
        raise KeySearchError(f"template orders must be 'given' or 'all', not {orders!r}")
    return {"slots": list(slots), "seps": seps, "orders": orders}


def _blob(v: dict, key: str, base: Path, what: str) -> bytes | None:
    """`<key>_hex` or `<key>_file` (read now and frozen) of a verifier table; None when neither."""
    if v.get(f"{key}_hex") is not None and v.get(f"{key}_file") is not None:
        raise KeySearchError(f"{what}: give {key}_hex or {key}_file, not both")
    if v.get(f"{key}_hex") is not None:
        return _unhex(v[f"{key}_hex"], f"{what} {key}_hex")
    if v.get(f"{key}_file") is not None:
        return _path(v[f"{key}_file"], base, f"{what} {key}_file").read_bytes()
    return None


def _need(value, what):
    if value is None:
        raise KeySearchError(f"verify: {what} is required")
    return value


def _freeze_verifier(v: dict, base: Path, key_len: int | None) -> tuple[dict, int | None]:
    """The frozen verifier table and the key length it implies."""
    if not isinstance(v, dict):
        raise KeySearchError("the job needs a [verify] table")
    kind = v.get("kind")
    if kind not in VERIFY_KINDS:
        raise KeySearchError(f"verify kind {kind!r} unknown (one of {', '.join(VERIFY_KINDS)})")
    out: dict = {"kind": kind}
    if kind == "hash":
        target = _need(_blob(v, "target", base, "verify"), "target_hex")
        if not target:
            raise KeySearchError("verify: target_hex is empty")
        if key_len is not None and key_len != len(target):
            raise KeySearchError(f"verify hash: key_len {key_len} is not the target's length {len(target)}")
        out["target"] = target.hex()
        return out, len(target)
    if kind == "hmac":
        out["alg"] = _hmac_alg(str(_need(v.get("alg"), "alg")))
        out["msg"] = _need(_blob(v, "msg", base, "verify"), "msg_hex").hex()
        tag = _need(_blob(v, "tag", base, "verify"), "tag_hex")
        if not tag:
            raise KeySearchError("verify: tag_hex is empty")
        out["tag"] = tag.hex()
        return out, key_len
    if kind == "zip":
        p = _path(_need(v.get("file"), "file"), base, "verify zip file")
        out.update(path=str(p), sha256=_sha256_file(p))
        ZipVerifier(p.read_bytes())                  # refuse a non-zip / unencrypted zip now, not at run
        return out, key_len
    if kind == "aes-gcm":
        if key_len not in AES_KEYS:
            raise KeySearchError(f"verify aes-gcm needs key_len 16, 24 or 32 (got {key_len})")
        out["nonce"] = _need(_blob(v, "nonce", base, "verify"), "nonce_hex").hex()
        out["ct"] = _need(_blob(v, "ct", base, "verify"), "ct_hex").hex()
        tag = _need(_blob(v, "tag", base, "verify"), "tag_hex")
        if not 4 <= len(tag) <= 16:
            raise KeySearchError("verify aes-gcm: the tag must be 4 to 16 bytes")
        out["tag"] = tag.hex()
        out["aad"] = (_blob(v, "aad", base, "verify") or b"").hex()
        return out, key_len
    # crib
    cipher = v.get("cipher")
    if cipher not in CIPHERS:
        raise KeySearchError(f"verify crib: cipher {cipher!r} unknown (one of {', '.join(CIPHERS)})")
    if cipher.startswith("aes") and key_len not in AES_KEYS:
        raise KeySearchError(f"verify crib {cipher} needs key_len 16, 24 or 32 (got {key_len})")
    if (v.get("crib") is None) == (v.get("crib_hex") is None):
        raise KeySearchError("verify crib: give crib (text) or crib_hex, one of them")
    crib = str(v["crib"]).encode("utf-8") if v.get("crib") is not None else _unhex(v["crib_hex"], "verify crib_hex")
    if not crib:
        raise KeySearchError("verify crib: the crib is empty")
    offset = v.get("offset", 0)
    if not isinstance(offset, int) or offset < 0:
        raise KeySearchError("verify crib: offset must be a non-negative integer")
    ct = _need(_blob(v, "ct", base, "verify"), "ct_hex or ct_file")
    end = offset + len(crib)
    if len(ct) < end:
        raise KeySearchError(f"verify crib: the ciphertext ({len(ct)} bytes) ends before the crib (byte {end})")
    block = cipher in ("aes-ecb", "aes-cbc")
    if block and len(ct) % 16:
        raise KeySearchError(f"verify crib {cipher}: the ciphertext length {len(ct)} is not a multiple of 16")
    need = -(-end // 16) * 16 if block else end
    iv = b""
    if cipher == "aes-cbc":
        iv = _blob(v, "iv", base, "verify")
        if iv is None:
            if len(ct) < 32:
                raise KeySearchError("verify crib aes-cbc: no iv_hex, and the ciphertext is too short to "
                                     "carry the IV as its first block")
            iv, ct = ct[:16], ct[16:]
            if len(ct) < end:
                raise KeySearchError("verify crib aes-cbc: after the leading IV the ciphertext ends before the crib")
        if len(iv) != 16:
            raise KeySearchError("verify crib aes-cbc: the IV must be 16 bytes")
    nonce, initial = b"", 0
    if cipher == "aes-ctr":
        nonce = _blob(v, "nonce", base, "verify") or b""
        if len(nonce) >= 16:
            raise KeySearchError("verify crib aes-ctr: the nonce must be shorter than 16 bytes")
        initial = v.get("initial", 0)
        if not isinstance(initial, int) or initial < 0:
            raise KeySearchError("verify crib aes-ctr: initial must be a non-negative integer")
    tail = None
    if v.get("pkcs7"):
        if not block:
            raise KeySearchError(f"verify crib: pkcs7 applies to aes-ecb/aes-cbc, not {cipher}")
        prev = ct[-32:-16] if len(ct) >= 32 else iv if cipher == "aes-cbc" else b"\x00" * 16
        tail = (prev + ct[-16:]).hex()
    out.update(cipher=cipher, ct=ct[:need].hex(), crib=crib.hex(), offset=offset, iv=iv.hex(),
               nonce=nonce.hex(), initial=initial, pkcs7_tail=tail)
    return out, key_len


def build_verifier(v: dict) -> Verifier:
    kind = v["kind"]
    if kind == "hash":
        return HashVerifier(bytes.fromhex(v["target"]))
    if kind == "hmac":
        return HmacVerifier(v["alg"], bytes.fromhex(v["msg"]), bytes.fromhex(v["tag"]))
    if kind == "aes-gcm":
        return GcmVerifier(bytes.fromhex(v["nonce"]), bytes.fromhex(v["ct"]), bytes.fromhex(v["tag"]),
                           bytes.fromhex(v["aad"]))
    if kind == "zip":
        p = Path(v["path"])
        if not p.is_file():
            raise KeySearchError(f"zip verifier: {p} is gone")
        data = p.read_bytes()
        if hashlib.sha256(data).hexdigest() != v["sha256"]:
            raise KeySearchError(f"zip verifier: {p} changed since the job was made (sha256 differs)")
        return ZipVerifier(data)
    if kind == "crib":
        tail = bytes.fromhex(v["pkcs7_tail"]) if v.get("pkcs7_tail") else None
        return CribVerifier(v["cipher"], bytes.fromhex(v["ct"]), bytes.fromhex(v["crib"]), v["offset"],
                            bytes.fromhex(v["iv"]), bytes.fromhex(v["nonce"]), v["initial"], tail)
    raise KeySearchError(f"verify kind {kind!r} unknown")


def freeze(spec: dict, base: Path, *, allow_weak: bool = False) -> dict:
    """The job for a spec: every source read now (harvest, store, literal values), every file pinned by
    sha256, so the space is the same on every resume. Raises KeySearchError naming what is wrong."""
    if not isinstance(spec, dict):
        raise KeySearchError("the spec must be a table")
    known = {"key_len", "chunk", "kdf", "salts", "salts_hex", "bank", "template", "verify", "allow_weak",
             "note"}
    extra = sorted(set(spec) - known)
    if extra:
        raise KeySearchError(f"spec: unknown key(s) {extra}")
    key_len = spec.get("key_len")
    if key_len is not None and (not isinstance(key_len, int) or isinstance(key_len, bool) or key_len < 1):
        raise KeySearchError(f"key_len must be a positive integer, not {key_len!r}")
    chunk = spec.get("chunk", DEFAULT_CHUNK)
    if not isinstance(chunk, int) or isinstance(chunk, bool) or chunk < 1:
        raise KeySearchError(f"chunk must be a positive integer, not {chunk!r}")
    banks = [_freeze_bank(b, base) for b in _strs(spec.get("bank"), "bank")]
    names = [b["name"] for b in banks]
    if not banks:
        raise KeySearchError("the spec has no [[bank]]")
    if len(set(names)) != len(names):
        raise KeySearchError(f"bank names repeat: {names}")
    templates = [_freeze_template(t, set(names)) for t in _strs(spec.get("template"), "template")]
    if not templates:
        raise KeySearchError("the spec has no [[template]]")
    verify, key_len = _freeze_verifier(spec.get("verify"), base, key_len)
    kdfs = [str(k) for k in _strs(spec.get("kdf"), "kdf")] or ["raw"]
    kdfs = list(dict.fromkeys(kdfs))
    for k in kdfs:
        fn, _ = parse_kdf(k, key_len)
        out = fn(b"keysearch-probe" if k != "raw" or key_len is None else b"k" * key_len, b"salt")
        if key_len is not None and k not in ("raw", "pad0") and len(out) < key_len:
            raise KeySearchError(f"derivation {k} gives {len(out)} bytes, fewer than key_len {key_len}")
    salts = _byte_list(spec, "salts", "salts_hex", "spec") or [""]
    job = {"schema": SCHEMA, "key_len": key_len, "chunk": chunk, "kdf": kdfs, "salts": salts,
           "banks": banks, "templates": templates, "verify": verify,
           "allow_weak": bool(allow_weak or spec.get("allow_weak", False)),
           "note": str(spec.get("note", ""))[:200]}
    space = Space(job)                                # loads files, builds the verifier: fails now, not at run
    if space.total == 0:
        raise KeySearchError("the key space is empty (a template slot names an empty bank)")
    job["total"] = space.total
    job["bits"] = space.verifier.bits
    job["chance"] = chance_hits(space.total, space.verifier.bits)
    if job["chance"] > MAX_CHANCE and not job["allow_weak"]:
        raise KeySearchError(
            f"the verifier is not exact over this space: {space.verifier.describe()} over {space.total} "
            f"candidates expects {job['chance']:.3g} chance hits (max {MAX_CHANCE}); give a longer crib, "
            "a full tag or a smaller space, or allow_weak to accept false positives")
    job["fp"] = fingerprint(job)
    return job


def chance_hits(total: int, bits: int) -> float:
    return float(total) * 2.0 ** (-bits)


def fingerprint(job: dict) -> str:
    body = {k: v for k, v in job.items() if k not in ("fp", "created")}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------- the space

def _variants(atom: bytes, raw: bool, case, encodings, nul) -> list[bytes]:
    if raw:
        return [atom]
    try:
        text = atom.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    out = []
    for terminate in nul:
        if text is None:                      # not UTF-8 (a wordlist line): only its own bytes
            out.append(atom + (b"\x00" if terminate else b""))
            continue
        for c in case:
            t = text if c == "as-is" else getattr(text, c)()
            if terminate:
                t += "\x00"
            for enc in encodings:
                try:
                    out.append(t.encode(_CODEC[enc]))
                except UnicodeEncodeError:   # latin1 cannot spell it: that variant does not exist
                    continue
    return out


def _file_lines(ref: dict) -> list[bytes]:
    p = Path(ref["path"])
    if not p.is_file():
        raise KeySearchError(f"bank file {p} is gone")
    if _sha256_file(p) != ref["sha256"]:
        raise KeySearchError(f"bank file {p} changed since the job was made (sha256 differs)")
    out = []
    with open(p, "rb") as fh:
        for line in fh:
            line = line.rstrip(b"\r\n")
            if line:
                out.append(line)
                if ref.get("limit") and len(out) >= ref["limit"]:
                    break
    return out


def expand_bank(bank: dict) -> list[bytes]:
    """Every atom of the bank in every variant, de-duplicated, in a fixed order."""
    seen, out = set(), []
    atoms = [(v.encode("utf-8", "surrogateescape"), False) for v in bank["values"]]
    atoms += [(bytes.fromhex(h), True) for h in bank["hex"]]
    for ref in bank["files"]:
        atoms += [(line, False) for line in _file_lines(ref)]
    for atom, raw in atoms:
        for form in _variants(atom, raw, bank["case"], bank["encodings"], bank["nul"]):
            if form not in seen:
                seen.add(form)
                out.append(form)
    return out


class Space:
    """The mixed-radix key space of a job. index -> (template, atoms, separator, derivation)."""

    def __init__(self, job: dict):
        self.job = job
        self.key_len = job["key_len"]
        self.banks = {b["name"]: expand_bank(b) for b in job["banks"]}
        self.templates = []            # (slot names, [atom lists], [seps])
        seen = set()
        for t in job["templates"]:
            orders = itertools.permutations(t["slots"]) if t["orders"] == "all" else [tuple(t["slots"])]
            for order in orders:
                key = (order, tuple(t["seps"]))
                if key in seen:
                    continue
                seen.add(key)
                self.templates.append((order, [self.banks[s] for s in order],
                                       [bytes.fromhex(s) for s in t["seps"]]))
        salts = [bytes.fromhex(s) for s in job["salts"]]
        self.derivs = []               # (spec, fn, salt, salt index)
        for k in job["kdf"]:
            fn, salted = parse_kdf(k, self.key_len)
            if salted:
                self.derivs += [(k, fn, s, i) for i, s in enumerate(salts)]
            else:
                self.derivs.append((k, fn, b"", None))
        nd = len(self.derivs)
        self.sizes = []
        for _, lists, seps in self.templates:
            n = nd * len(seps)
            for lst in lists:
                n *= len(lst)
            self.sizes.append(n)
        self.offsets = [0]
        for n in self.sizes:
            self.offsets.append(self.offsets[-1] + n)
        self.total = self.offsets[-1]
        self.verifier = build_verifier(job["verify"])

    @property
    def chunks(self) -> int:
        return -(-self.total // self.job["chunk"])

    def chunk_range(self, c: int) -> tuple[int, int]:
        start = c * self.job["chunk"]
        return start, min(start + self.job["chunk"], self.total)

    def decode(self, i: int) -> tuple[int, tuple, int, int]:
        """(template index, atom index per slot, separator index, derivation index)."""
        if not 0 <= i < self.total:
            raise KeySearchError(f"index {i} is outside the space (0..{self.total - 1})")
        t = bisect.bisect_right(self.offsets, i) - 1
        local = i - self.offsets[t]
        _, lists, seps = self.templates[t]
        d = local % len(self.derivs)
        local //= len(self.derivs)
        s = local % len(seps)
        local //= len(seps)
        picks = []
        for lst in reversed(lists):          # the last slot varies fastest
            picks.append(local % len(lst))
            local //= len(lst)
        return t, tuple(reversed(picks)), s, d

    def candidate(self, i: int) -> bytes:
        t, picks, s, _ = self.decode(i)
        _, lists, seps = self.templates[t]
        return seps[s].join(lst[p] for lst, p in zip(lists, picks))

    def key(self, i: int) -> bytes | None:
        _, _, _, d = self.decode(i)
        spec, fn, salt, _ = self.derivs[d]
        out = fn(self.candidate(i), salt)
        if out is None:
            return None
        return out[:self.key_len] if self.key_len is not None and spec not in ("raw", "pad0") else out

    def recipe(self, i: int) -> dict:
        """What made candidate i, with nothing secret in it."""
        t, picks, s, d = self.decode(i)
        order, _, seps = self.templates[t]
        spec, _, _, si = self.derivs[d]
        return {"slots": list(order), "sep_len": len(seps[s]), "kdf": spec, "salt": si}

    def test_range(self, start: int, end: int, stop_on_hit: bool = True) -> tuple[list[int], int]:
        """(hit indices, candidates tested) over [start, end)."""
        hits, tested = [], 0
        check = self.verifier.check
        for i in range(start, end):
            tested += 1
            k = self.key(i)
            if k is not None and check(k):
                hits.append(i)
                if stop_on_hit:
                    break
        return hits, tested


# ---------------------------------------------------------------------------- the job on disk

def root_dir(root: Path | None = None) -> Path:
    return Path(root) if root is not None else ctf_paths.workdir() / DIR_NAME


def job_dir(sid: str, root: Path | None = None) -> Path:
    if not isinstance(sid, str) or not _ID_RE.match(sid):
        raise KeySearchError(f"bad search id {sid!r} (lower-case letters, digits, . _ -; max 64)")
    return root_dir(root) / sid


def load_spec(path: Path) -> dict:
    path = Path(path)
    if not path.is_file():
        raise KeySearchError(f"no spec file {path}")
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            raise KeySearchError(f"{path}: bad JSON: {e}") from None
    import tomllib
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise KeySearchError(f"{path}: bad TOML: {e}") from None


def _atomic_json(dest: Path, obj: dict) -> None:
    fd, tmp = tempfile.mkstemp(prefix=f".{dest.name}.", dir=str(dest.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=1, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, dest)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def create(sid: str, spec: dict, *, base: Path, root: Path | None = None, replace: bool = False,
           allow_weak: bool = False, now=time.time) -> dict:
    """Freeze the spec into <root>/<sid>/job.json. An existing job is kept unless replace, which moves
    it (and its ledger) aside as <sid>.replaced-<time>, never deletes it."""
    d = job_dir(sid, root)
    job = freeze(spec, Path(base), allow_weak=allow_weak)
    job["id"] = sid
    job["fp"] = fingerprint(job)
    job["created"] = now()
    if d.exists():
        if not replace:
            raise KeySearchError(f"search {sid} exists at {d}: resume it with `run`, or give --replace")
        if (d / LOCK_NAME).exists() and _lock_held(d / LOCK_NAME):
            raise KeySearchError(f"search {sid} is running now; it cannot be replaced")
        os.replace(d, d.with_name(f"{sid}.replaced-{int(now())}"))
    d.mkdir(parents=True, mode=0o700)
    _atomic_json(d / JOB_NAME, job)
    return job


def load_job(sid: str, root: Path | None = None) -> tuple[Path, dict]:
    d = job_dir(sid, root)
    p = d / JOB_NAME
    if not p.is_file():
        raise KeySearchError(f"no search {sid} (no {p}); make it with `new`")
    try:
        job = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise KeySearchError(f"{p}: corrupt job ({e})") from None
    if not isinstance(job, dict) or job.get("schema") != SCHEMA:
        raise KeySearchError(f"{p}: not a schema-{SCHEMA} key-search job")
    if fingerprint(job) != job.get("fp"):
        raise KeySearchError(f"{p} was edited after it was made (fingerprint differs): its ledger no longer "
                             "describes it; make a new job with `new --replace`")
    return d, job


def _lock_held(p: Path) -> bool:
    fd = os.open(p, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------- the progress ledger

def heal_tail(d: Path, warn=None) -> bool:
    """A crash mid-append can leave a last line with no newline. Cut it (the chunk it named is redone)
    so the next append does not glue onto it. True when something was cut."""
    p = d / PROGRESS_NAME
    if not p.exists():
        return False
    data = p.read_bytes()
    if not data or data.endswith(b"\n"):
        return False
    keep = data.rfind(b"\n") + 1
    with open(p, "r+b") as fh:
        fh.truncate(keep)
    if warn:
        warn(f"keysearch: cut a torn last line ({len(data) - keep} bytes) from {p}; that record is redone")
    return True


def read_progress(d: Path) -> list[dict]:
    """The ledger's records. A torn last line (no newline) is left out; a bad line anywhere else is
    corruption and raises."""
    p = d / PROGRESS_NAME
    if not p.exists():
        return []
    lines = p.read_bytes().split(b"\n")
    lines.pop()                                   # b"" after the last newline, or a torn last line
    out = []
    for n, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError as e:
            raise KeySearchError(f"{p}:{n}: corrupt ledger line ({e})") from None
    return out


class Progress:
    def __init__(self, records: list[dict], fp: str):
        self.done: set[int] = set()
        self.hits: list[dict] = []
        self.tested = 0
        self.cpu = 0.0
        self.runs = 0
        self.last_stop: dict | None = None
        seen_hits = set()
        for r in records:
            if r.get("fp") != fp:
                raise KeySearchError(f"the ledger has a record for another job (fp {r.get('fp')!r}, the job is "
                                     f"{fp!r}): it no longer describes this job")
            ev = r.get("event")
            if ev == "keysearch.chunk" and r["chunk"] not in self.done:
                self.done.add(r["chunk"])
                self.tested += r.get("tested", 0)
                self.cpu += r.get("cpu", 0.0)
            elif ev == "keysearch.hit" and r["index"] not in seen_hits:
                seen_hits.add(r["index"])
                self.hits.append(r)
            elif ev == "keysearch.start":
                self.runs += 1
            elif ev == "keysearch.stop":
                self.last_stop = r


def progress(sid: str, root: Path | None = None) -> tuple[dict, Progress]:
    d, job = load_job(sid, root)
    return job, Progress(read_progress(d), job["fp"])


# ---------------------------------------------------------------------------- running

_WORKER_SPACE: Space | None = None


def _worker_init(job: dict) -> None:
    global _WORKER_SPACE
    signal.signal(signal.SIGTERM, signal.SIG_DFL)   # the CLI's stop handler is the parent's, not a worker's
    signal.signal(signal.SIGINT, signal.SIG_IGN)    # ^C reaches the parent, which stops the pool
    _WORKER_SPACE = Space(job)


def _worker_chunk(arg: tuple[int, bool]) -> tuple[int, list[int], int, float]:
    c, stop_on_hit = arg
    t0 = time.process_time()
    start, end = _WORKER_SPACE.chunk_range(c)
    hits, tested = _WORKER_SPACE.test_range(start, end, stop_on_hit)
    return c, hits, tested, time.process_time() - t0


def _get_context():
    import multiprocessing
    for method in ("fork", "forkserver", "spawn"):
        try:
            return multiprocessing.get_context(method)
        except ValueError:
            continue
    raise KeySearchError("multiprocessing has no start method here: run with --workers 1")


def _event_ledger(event: str, **fields) -> None:
    """The run's summary in the event ledger, beside every other engine's. Says why when it cannot."""
    try:
        wd = ctf_paths.workdir()
    except (ctf_event.EventError, OSError) as e:  # no event and no CTF_WORKDIR: the search still ran
        print(f"keysearch: not recorded in the event ledger ({type(e).__name__}: {e})", file=sys.stderr)
        return
    ctf_ledger.append(event, workdir=wd, **fields)


def run(sid: str, *, root: Path | None = None, workers: int = 1, max_chunks: int | None = None,
        cpu_seconds: float | None = None, all_hits: bool = False, out=print, warn=None) -> dict:
    """Search the chunks the ledger does not list as done. Returns {"reason", "hits", "tested", ...}.
    reason: hit, already-hit, exhausted, max-chunks, cpu-budget, interrupted."""
    warn = warn or (lambda m: print(m, file=sys.stderr))
    d, job = load_job(sid, root)
    lock_fd = os.open(d / LOCK_NAME, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise KeySearchError(f"search {sid} is already running (another process holds {d / LOCK_NAME})") from None
        return _run_locked(d, job, workers=workers, max_chunks=max_chunks, cpu_seconds=cpu_seconds,
                           all_hits=all_hits, out=out, warn=warn)
    finally:
        os.close(lock_fd)


def _run_locked(d: Path, job: dict, *, workers, max_chunks, cpu_seconds, all_hits, out, warn) -> dict:
    sid, fp = job["id"], job["fp"]
    heal_tail(d, warn)
    prog = Progress(read_progress(d), fp)
    if prog.hits and not all_hits:
        out(f"keysearch {sid}: already found ({len(prog.hits)} hit(s)); `show {sid}` lists them, "
            "`run --all` keeps searching")
        return {"reason": "already-hit", "hits": prog.hits, "tested": 0, "chunks": 0, "cpu": 0.0}
    space = Space(job)
    if space.total != job["total"]:
        raise KeySearchError(f"the space now has {space.total} candidates, the job was made with {job['total']}")
    if max_chunks is not None and max_chunks < 1:
        raise KeySearchError("--max-chunks must be at least 1")
    if workers < 1:
        raise KeySearchError("--workers must be at least 1")
    # The chunks to search, lazily: a multi-slot wordlist template can have 1e9 chunks, and a list of
    # them (or of pool tasks) would exhaust memory before the first chunk ran.
    left = space.chunks - sum(1 for c in prog.done if 0 <= c < space.chunks)
    n_todo = left if max_chunks is None else min(left, max_chunks)
    todo = itertools.islice((c for c in range(space.chunks) if c not in prog.done), n_todo)
    run_no = prog.runs + 1
    ctf_ledger.append("keysearch.start", workdir=d, fp=fp, run=run_no, workers=workers,
                      done_before=len(prog.done), todo=n_todo)
    out(f"keysearch {sid}: run {run_no}, {len(prog.done)}/{space.chunks} chunks already done, "
        f"{n_todo} to search with {workers} worker(s)")
    stats = {"tested": 0, "chunks": 0, "cpu": 0.0}
    new_hits: list[dict] = []
    known = {h["index"] for h in prog.hits}
    reason = None

    def record(c: int, hits: list[int], tested: int, cpu: float) -> bool:
        """Write the chunk's hits, then the chunk if it was searched to its end (a chunk cut short by a
        hit is not done: `run --all` searches it again). True when the search should stop on a hit."""
        for i in hits:
            if i in known:
                continue
            known.add(i)
            rec = {"index": i, "chunk": c, "masked": mask(space.candidate(i)), "recipe": space.recipe(i)}
            stored = _store_hit(space, i, sid, warn)
            if stored is not None:
                rec["stored"] = stored
            ctf_ledger.append("keysearch.hit", workdir=d, fp=fp, **rec)
            new_hits.append(rec)
            r = rec["recipe"]
            out(f"HIT {sid}: index {i} candidate {rec['masked']} = {'+'.join(r['slots'])} "
                f"(sep {r['sep_len']} bytes) via {r['kdf']}" + (f" salt #{r['salt']}" if r["salt"] is not None else ""))
        start, end = space.chunk_range(c)
        if tested == end - start:
            ctf_ledger.append("keysearch.chunk", workdir=d, fp=fp, chunk=c, tested=tested, cpu=round(cpu, 6))
            stats["chunks"] += 1
        stats["tested"] += tested
        stats["cpu"] += cpu
        return bool(hits) and not all_hits

    try:
        if workers == 1:
            for c in todo:
                t0 = time.process_time()
                start, end = space.chunk_range(c)
                hits, tested = space.test_range(start, end, not all_hits)
                if record(c, hits, tested, time.process_time() - t0):
                    reason = "hit"
                    break
                if cpu_seconds is not None and stats["cpu"] >= cpu_seconds:
                    reason = "cpu-budget"
                    break
        else:
            ctx = _get_context()
            pool = ctx.Pool(processes=workers, initializer=_worker_init, initargs=(job,))
            try:
                # A generator, not a list: the pool's task thread pulls from it only as fast as the
                # pipe to the workers drains, so the tasks in flight stay bounded.
                tasks = ((c, not all_hits) for c in todo)
                for c, hits, tested, cpu in pool.imap_unordered(_worker_chunk, tasks):
                    if record(c, hits, tested, cpu):
                        reason = "hit"
                        break
                    if cpu_seconds is not None and stats["cpu"] >= cpu_seconds:
                        reason = "cpu-budget"
                        break
            finally:
                pool.terminate()
                pool.join()
    except KeyboardInterrupt:
        reason = "interrupted"
    done_now = len(prog.done) + stats["chunks"]
    if reason is None:
        reason = "exhausted" if done_now >= space.chunks else "max-chunks"
    ctf_ledger.append("keysearch.stop", workdir=d, fp=fp, run=run_no, reason=reason, chunks=stats["chunks"],
                      tested=stats["tested"], cpu=round(stats["cpu"], 6), done=done_now, of=space.chunks)
    _event_ledger("keysearch.stop", search=sid, reason=reason, hits=len(new_hits) + len(prog.hits),
                  tested=stats["tested"], done=done_now, of=space.chunks)
    out(f"keysearch {sid}: stopped ({reason}) after {stats['chunks']} chunk(s), {stats['tested']} candidates, "
        f"cpu {stats['cpu']:.2f} s; {done_now}/{space.chunks} chunks done")
    if reason in ("max-chunks", "cpu-budget", "interrupted"):
        out(f"resume: python -m ctf keysearch run {sid}")
    return {"reason": reason, "hits": prog.hits + new_hits if all_hits else new_hits, **stats}


def _store_hit(space: Space, i: int, sid: str, warn) -> bool | None:
    """A zip opened by a raw candidate is an archive password: put it in the store (B-074 lane) so the
    sweep opens that archive next time. None when the hit is not one."""
    if space.verifier.kind != "zip":
        return None
    _, _, _, d = space.decode(i)
    if space.derivs[d][0] != "raw":
        return None
    ap = _sibling("archive_passwords")
    try:
        value = space.candidate(i).decode("utf-8")
        return bool(ap.add(value, source=f"keysearch:{sid}"))
    except (ctf_event.EventError, OSError) as e:   # before ValueError: EventError is one
        # the password is fine; the store has nowhere to live (no CTF_WORKDIR, no single event) or
        # cannot be written. The hit itself is recorded in the search ledger either way.
        warn(f"keysearch: the hit was not added to the archive-password store: the store has no usable "
             f"workdir ({type(e).__name__}: {e}); set CTF_WORKDIR or CTF_EVENT and `show --reveal` it")
        return False
    except (UnicodeDecodeError, ValueError) as e:
        warn(f"keysearch: the hit is not a storable archive password ({type(e).__name__}); not stored")
        return False


def reveal(sid: str, index: int, root: Path | None = None) -> tuple[bytes, bytes | None, dict]:
    """(candidate bytes, derived key, recipe) of one index: what `show --reveal` prints."""
    _, job = load_job(sid, root)
    space = Space(job)
    return space.candidate(index), space.key(index), space.recipe(index)


# ---------------------------------------------------------------------------- command line

def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--root", type=Path, help="where searches live (default <workdir>/keysearch)")
    sub = p.add_subparsers(dest="action", required=True)
    n = sub.add_parser("new", help="freeze a spec into a resumable job")
    n.add_argument("id")
    n.add_argument("--spec", type=Path, required=True, help="the job spec (.toml or .json)")
    n.add_argument("--replace", action="store_true", help="move an existing job of this id aside")
    n.add_argument("--allow-weak", action="store_true", help="accept a verifier that is not exact over the space")
    r = sub.add_parser("run", help="search what the ledger has not done (a resume is the same command)")
    r.add_argument("id")
    r.add_argument("--workers", type=int, default=1)
    r.add_argument("--max-chunks", type=int)
    r.add_argument("--cpu-seconds", type=float, help="stop once this much CPU time is spent (summed over workers)")
    r.add_argument("--all", action="store_true", help="keep searching after a hit")
    s = sub.add_parser("status", help="progress, hits (masked) and the resume command")
    s.add_argument("id")
    s.add_argument("--json", action="store_true")
    w = sub.add_parser("show", help="a hit's recipe; --reveal prints its plaintext to stdout")
    w.add_argument("id")
    g = w.add_mutually_exclusive_group()
    g.add_argument("--hit", type=int, default=1, help="which hit (1-based, default 1)")
    g.add_argument("--index", type=int, help="any index of the space")
    w.add_argument("--reveal", action="store_true", help="print the candidate and key (stdout only)")
    sub.add_parser("list", help="the searches under the root")


def _status_lines(job: dict, prog: Progress) -> list[str]:
    total_chunks = -(-job["total"] // job["chunk"])
    pct = 100.0 * len(prog.done) / total_chunks
    lines = [f"keysearch {job['id']}: {len(prog.done)}/{total_chunks} chunks ({pct:.1f}%), "
             f"{prog.tested} of {job['total']} candidates tested, cpu {prog.cpu:.2f} s, {prog.runs} run(s)",
             f"  verifier: {job['verify']['kind']} ({job['bits']} bits checked); chance hits over the space "
             f"{job['chance']:.3g}" + ("  [allow_weak]" if job.get("allow_weak") else "")]
    if prog.tested and len(prog.done) < total_chunks:
        left = job["total"] - prog.tested
        lines.append(f"  remaining: {left} candidates, about {prog.cpu / prog.tested * left:.1f} cpu-seconds")
    if prog.hits:
        for n, h in enumerate(prog.hits, 1):
            r = h["recipe"]
            lines.append(f"  hit #{n}: index {h['index']} {h['masked']} = {'+'.join(r['slots'])} via {r['kdf']}")
    else:
        lines.append("  hits: none")
    if prog.last_stop:
        lines.append(f"  last stop: {prog.last_stop.get('reason')} (run {prog.last_stop.get('run')})")
    if not prog.hits and len(prog.done) < total_chunks:
        lines.append(f"  resume: python -m ctf keysearch run {job['id']}")
    return lines


@contextlib.contextmanager
def _term_as_interrupt():
    """SIGTERM stops a run like ^C: the chunks already finished stay in the ledger and the stop is
    recorded as interrupted. Outside the main thread the handler cannot be set, and is not."""
    def handler(signum, frame):
        raise KeyboardInterrupt
    try:
        old = signal.signal(signal.SIGTERM, handler)
    except ValueError:
        yield
        return
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, old)


def dispatch(a: argparse.Namespace, out=print) -> int:
    try:
        if a.action == "new":
            spec_path = Path(a.spec)
            job = create(a.id, load_spec(spec_path), base=spec_path.resolve().parent, root=a.root,
                         replace=a.replace, allow_weak=a.allow_weak)
            out(f"keysearch {a.id}: {job['total']} candidates in {-(-job['total'] // job['chunk'])} chunks; "
                f"verifier {job['verify']['kind']} ({job['bits']} bits), chance hits {job['chance']:.3g}")
            out(f"run: python -m ctf keysearch run {a.id}")
            return 0
        if a.action == "run":
            with _term_as_interrupt():
                res = run(a.id, root=a.root, workers=a.workers, max_chunks=a.max_chunks,
                          cpu_seconds=a.cpu_seconds, all_hits=a.all, out=out)
            if res["reason"] in ("hit", "already-hit") or (a.all and res["hits"]):
                return EXIT_HIT
            return EXIT_EXHAUSTED if res["reason"] == "exhausted" else EXIT_STOPPED
        if a.action == "status":
            job, prog = progress(a.id, a.root)
            if a.json:
                total_chunks = -(-job["total"] // job["chunk"])
                out(json.dumps({"id": job["id"], "chunks_done": len(prog.done), "chunks": total_chunks,
                                "tested": prog.tested, "total": job["total"], "cpu": prog.cpu,
                                "runs": prog.runs, "hits": prog.hits,
                                "last_stop": (prog.last_stop or {}).get("reason")}, sort_keys=True))
            else:
                for line in _status_lines(job, prog):
                    out(line)
            return 0
        if a.action == "show":
            job, prog = progress(a.id, a.root)
            if a.index is not None:
                index = a.index
            else:
                if not prog.hits:
                    raise KeySearchError(f"search {a.id} has no hit yet")
                if not 1 <= a.hit <= len(prog.hits):
                    raise KeySearchError(f"search {a.id} has {len(prog.hits)} hit(s); no #{a.hit}")
                index = prog.hits[a.hit - 1]["index"]
            cand, key, recipe = reveal(a.id, index, a.root)
            out(f"index {index}: {'+'.join(recipe['slots'])} sep {recipe['sep_len']} bytes, kdf {recipe['kdf']}"
                + (f", salt #{recipe['salt']}" if recipe["salt"] is not None else ""))
            if a.reveal:
                out(f"candidate: {cand!r}")
                out(f"candidate hex: {cand.hex()}")
                out(f"key hex: {key.hex() if key is not None else '-'}")
            else:
                out(f"candidate: {mask(cand)}   key: {mask(key)}   (--reveal prints them)")
            return 0
        if a.action == "list":
            r = root_dir(a.root)
            for d in sorted(r.iterdir()) if r.is_dir() else []:
                if (d / JOB_NAME).is_file():
                    try:
                        job, prog = progress(d.name, a.root)
                    except KeySearchError as e:
                        out(f"{d.name}: unreadable ({e})")
                        continue
                    total_chunks = -(-job["total"] // job["chunk"])
                    out(f"{d.name}: {len(prog.done)}/{total_chunks} chunks, {len(prog.hits)} hit(s)")
            return 0
    except KeySearchError as e:
        print(f"keysearch: {e}", file=sys.stderr)
        return EXIT_ERROR
    raise AssertionError(a.action)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="keysearch", description="Resumable key search: candidate banks, an "
                                "exact verifier and a crash-safe ledger (B-215).")
    add_arguments(p)
    return dispatch(p.parse_args(list(argv) if argv is not None else None))


if __name__ == "__main__":
    raise SystemExit(main())
