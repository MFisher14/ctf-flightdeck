"""In-memory zip reading and the saved-attempt shapes of the speed runner.

What the master keeps of Huntress speedrun/common.py (SPEC L4), per the hand-merge decision: the
in-memory ZipView and its fast WinZip-AES reader, plus the small saved-attempt helpers that
speedrun/corpus.py and the carried speedrun solvers read. The Game Master answer guesser (Answers)
and the accepted-answer store (KeyStore) were dropped: a first solve never guesses, so nothing in
the master may fill an answer from a table of past keys. The Mastery set-to-delivery mapping
(Source, set_sources) went with them; nothing in the master used it.

    ZipView(data) / open_zip(data)   read-only view of one zip held in memory: stored, deflate,
                                     bzip2, LZMA, WinZip AES (AE-1/AE-2), ZipCrypto
    passwords()                      the archive passwords to try (solvers/common/archive_passwords)
    Delivery, compact, questions     the saved-attempt shapes corpus.py replays
    data_root(), attempt_folders()   where saved attempts live ($CTF_SPEED_DATA, else the challenges root)

Nothing here touches the network. A missing AES backend (Cryptodome) raises ZipError naming it.
"""
from __future__ import annotations

import bz2
import json
import lzma
import os
import re
import struct
import threading
import hashlib
import zlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

try:  # WinZip AES needs a little-endian CTR counter; `cryptography` only counts big-endian
    from Cryptodome.Cipher import AES as _AES          # pycryptodomex (requirements.lock.txt)
    from Cryptodome.Util import Counter as _Counter
except ImportError:  # pragma: no cover - the same library under its pycryptodome name (requirements.in)
    try:
        from Crypto.Cipher import AES as _AES
        from Crypto.Util import Counter as _Counter
    except ImportError:
        _AES = _Counter = None   # an AES member then raises ZipError naming the missing package

from solvers.common import archive_passwords as _archive_passwords

__all__ = ["Delivery", "compact", "questions", "open_zip", "is_zip", "ZipView", "ZipError", "warm_pool",
           "data_root", "speed_variants_root", "attempt_folders", "LANES", "lane_name", "lane_of",
           "base_of", "mode_of", "day_of", "passwords"]

HERE = Path(__file__).resolve().parent
PASSWORD = _archive_passwords.DEFAULT


def passwords() -> list:
    """b"infected", then every stored archive password, newest first, each once.

    The master's one password store (solvers/common/archive_passwords.candidates(): the file
    <challenges root>/_passwords.json, read from disk on every call, so a password added mid-run is
    used by the next decrypt). The Huntress copy of that reader read $CTF_WORKDIR; the
    master reads $CTF_WORKDIR through archive_passwords. Nothing here prints a password."""
    return list(_archive_passwords.candidates())


# ---- small shared facts ---------------------------------------------------------------------------

# short lane name -> (base-id prefix, solvers/<dir> of the seeds, challenges/_ledger/<name>.jsonl)
LANES = {
    "warmups": ("warmups-day-", "warmups", "warmups"),
    "mobile": ("mobile-android-day-", "mobile-android", "mobile"),
    "metadata": ("metadata-forensics-day-", "metadata-forensics", "metadata"),
    "script": ("script-analysis-day-", "script-analysis", "script"),
    "binary": ("binary-reverse-engineering-day-", "binary", "binary"),
}
_ALIASES = {"mobile-android": "mobile", "metadata-forensics": "metadata", "script-analysis": "script",
            "binary-reverse-engineering": "binary"}


def lane_name(lane: str) -> str:
    """'script', 'script-analysis' or 'script-analysis-day-' -> 'script'."""
    s = str(lane).strip().lower().rstrip("-")
    s = re.sub(r"-day(-\d+.*)?$", "", s)
    s = _ALIASES.get(s, s)
    if s not in LANES:
        raise ValueError(f"unknown lane {lane!r}")
    return s


def lane_of(cid: str) -> str | None:
    base = base_of(cid)
    for name, (prefix, _, _) in LANES.items():
        if base.startswith(prefix):
            return name
    return None


def base_of(cid: str) -> str:
    return re.sub(r"/(time_trial|mastery)$", "", str(cid).strip().rstrip("/"))


def mode_of(cid: str) -> str:
    m = re.search(r"/(time_trial|mastery)$", str(cid).strip().rstrip("/"))
    return m.group(1) if m else "base"


def day_of(cid: str) -> int | None:
    m = re.search(r"-day-(\d+)", str(cid))
    return int(m.group(1)) if m else None


# ---- attempt shapes ------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Delivery:
    index: int        # 0-based, as in ?op=artifact&delivery=
    filename: str     # Content-Disposition, else artifacts[i].filename, else delivery-NN.bin
    data: bytes

    def __repr__(self):
        return f"Delivery({self.index}, {self.filename!r}, {len(self.data)} bytes)"


def compact(value) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


_SET_RE = re.compile(r"set(\d+)\.(.+)$")
_DELIV_RE = re.compile(r"^\s*delivery\s+(\d+)\s*:\s*", re.I)


def _answer_ids(attempt: dict) -> list:
    qs, ids = attempt.get("questions") or [], attempt.get("answer_ids") or []
    return list(ids) if len(ids) == len(qs) else [q.get("id") for q in qs]


def questions(attempt: dict) -> list[dict]:
    """One dict per position of answer_ids[] (questions[] is aligned with it one-for-one)."""
    out = []
    for q, aid in zip(attempt.get("questions") or [], _answer_ids(attempt)):
        qid_raw = str(q.get("id") or aid or "")
        m = _SET_RE.match(qid_raw)
        if m:
            n, qid = int(m.group(1)), m.group(2)
        else:
            qid = qid_raw
            n = q["set"] if isinstance(q.get("set"), int) and not isinstance(q.get("set"), bool) else None
        art = q.get("artifact") or ""
        rest = _DELIV_RE.sub("", art)
        file_, _, member = rest.partition("->")
        fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
        out.append({
            "answer_id": aid, "qid": qid, "set": n, "text": q.get("question") or "", "artifact": art,
            "file": file_.strip() or None, "member": member.strip() or None if "->" in rest else None,
            "kind": fmt.get("kind"), "syntax": fmt.get("syntax"),
            "accepted_values": fmt.get("accepted_values"), "normalization": q.get("normalization"),
        })
    return out


# ---- zip reading (stored, deflate, WinZip AES) --------------------------------------------------------

class ZipError(ValueError):
    pass


_POOL = None
_POOL_LOCK = threading.Lock()
POOL_WORKERS = 8


def _pool() -> ThreadPoolExecutor:
    """One shared pool, started on first use (prepare() warms it, so it is running before a clock)."""
    global _POOL
    if _POOL is None:
        with _POOL_LOCK:
            if _POOL is None:
                p = ThreadPoolExecutor(max_workers=POOL_WORKERS, thread_name_prefix="speed-zip")
                for f in [p.submit(int) for _ in range(POOL_WORKERS)]:   # start every worker now
                    f.result()
                _POOL = p
    return _POOL


def warm_pool():
    _pool()


_AES_KEYLEN = {1: 16, 2: 24, 3: 32}
def _derive(password: bytes, salt: bytes, keylen: int) -> bytes:
    """WinZip AES key material. No cache: a new variant never repeats a salt, and a cache would
    make repeated offline replays look faster than a real window."""
    return hashlib.pbkdf2_hmac("sha1", password, salt, 1000, 2 * keylen + 2)


def _inflate(method: int, data: bytes, size: int) -> bytes:
    if method == 0:
        return data
    if method == 8:
        d = zlib.decompressobj(-15)
        out = d.decompress(data)
        return out + d.flush()
    if method == 12:
        return bz2.decompress(data)
    if method == 14:   # zip's LZMA: 2-byte version, 2-byte props size, props, then raw LZMA1
        psize = struct.unpack_from("<H", data, 2)[0]
        filt = lzma._decode_filter_properties(lzma.FILTER_LZMA1, data[4:4 + psize])
        return lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[filt]).decompress(data[4 + psize:])[:size]
    raise ZipError(f"compression method {method} is not supported")


@dataclass
class _Entry:
    name: str
    method: int          # the real compression method (from 0x9901 for AES)
    flags: int
    csize: int
    size: int
    offset: int          # of the local header
    crc: int
    aes: int             # 0, or strength 1/2/3
    aes_version: int     # 1 (AE-1) or 2 (AE-2)
    zipcrypto: bool


class ZipView:
    """A read-only view of one zip held in memory. The central directory is parsed at once (cheap);
    members are read, decrypted and inflated on demand and cached."""

    def __init__(self, data: bytes, password: bytes = PASSWORD):
        self.data = data
        self.password = password
        self._entries: dict[str, _Entry] = {}
        self._order: list[str] = []
        self._cache: dict[str, bytes] = {}
        self._lock = threading.Lock()
        self._parse()

    # -- directory
    def _parse(self):
        data = self.data
        mv = memoryview(data)
        start = max(0, len(data) - 22 - 65535)
        pos = data.rfind(b"PK\x05\x06", start)
        if pos < 0:
            raise ZipError("no end of central directory")
        (_, _, _, _, count, cd_size, cd_off, _) = struct.unpack_from("<IHHHHIIH", data, pos)
        if count == 0xFFFF or cd_off == 0xFFFFFFFF or cd_size == 0xFFFFFFFF:
            loc = data.rfind(b"PK\x06\x07", 0, pos)
            if loc >= 0:
                z64 = struct.unpack_from("<Q", data, loc + 8)[0]
                if data[z64:z64 + 4] == b"PK\x06\x06":
                    count, cd_size, cd_off = struct.unpack_from("<QQQ", data, z64 + 32)
        # A zip with bytes before it (self-extractor, prefix): shift by the difference.
        shift = pos - cd_size - cd_off if cd_off + cd_size <= pos else 0
        p = cd_off + shift
        for _ in range(int(count) if count != 0xFFFF else 1 << 30):
            if data[p:p + 4] != b"PK\x01\x02":
                break
            (flags, method, _t, _d, crc, csize, size, nlen, xlen, clen, _disk, _ia, _ea,
             off) = struct.unpack_from("<HHHHIIIHHHHHII", data, p + 8)
            raw = bytes(mv[p + 46:p + 46 + nlen])
            name = raw.decode("utf-8" if flags & 0x800 else "cp437", "replace")
            extra = bytes(mv[p + 46 + nlen:p + 46 + nlen + xlen])
            aes, aes_ver, real = 0, 0, method
            i = 0
            while i + 4 <= len(extra):
                hid, hlen = struct.unpack_from("<HH", extra, i)
                body = extra[i + 4:i + 4 + hlen]
                if hid == 0x0001:   # zip64 sizes, in the order of the fields that were 0xFFFFFFFF
                    vals = list(struct.unpack_from("<" + "Q" * (len(body) // 8), body))
                    if size == 0xFFFFFFFF and vals:
                        size = vals.pop(0)
                    if csize == 0xFFFFFFFF and vals:
                        csize = vals.pop(0)
                    if off == 0xFFFFFFFF and vals:
                        off = vals.pop(0)
                elif hid == 0x9901 and len(body) >= 7:
                    aes_ver = struct.unpack_from("<H", body, 0)[0]
                    aes = body[4]
                    real = struct.unpack_from("<H", body, 5)[0]
                i += 4 + hlen
            if method == 99 and not aes:
                raise ZipError(f"{name}: method 99 without an AES extra field")
            p += 46 + nlen + xlen + clen
            if name.endswith("/"):
                continue
            e = _Entry(name, real, flags, csize, size, off + shift, crc, aes if method == 99 else 0,
                       aes_ver, bool(flags & 1) and method != 99)
            if name not in self._entries:
                self._order.append(name)
            self._entries[name] = e

    def names(self) -> list[str]:
        return list(self._order)

    def __contains__(self, name):
        return name in self._entries

    def info(self, name) -> tuple[int, int, bool]:
        e = self._entries[name]
        return e.size, e.method, bool(e.aes)

    def entry(self, name) -> _Entry:
        return self._entries[name]

    # -- members
    def _raw(self, e: _Entry) -> bytes:
        data = self.data
        p = e.offset
        if data[p:p + 4] != b"PK\x03\x04":
            raise ZipError(f"{e.name}: no local header")
        nlen, xlen = struct.unpack_from("<HH", data, p + 26)
        s = p + 30 + nlen + xlen
        return data[s:s + e.csize]

    def _read(self, e: _Entry) -> bytes:
        raw = self._raw(e)
        if e.aes:
            if _AES is None:
                raise ZipError(f"{e.name}: AES member needs pycryptodome(x), which is not installed")
            klen = _AES_KEYLEN.get(e.aes)
            if not klen:
                raise ZipError(f"{e.name}: AES strength {e.aes}")
            slen = klen // 2
            salt, body = raw[:slen], raw[slen + 2:len(raw) - 10]
            dk = _derive(self.password, salt, klen)
            if dk[2 * klen:] != raw[slen:slen + 2]:
                dk = self._other_password(e, salt, klen, raw[slen:slen + 2])
            ctr = _Counter.new(128, initial_value=1, little_endian=True)
            raw = _AES.new(dk[:klen], _AES.MODE_CTR, counter=ctr).decrypt(body)
        elif e.zipcrypto:
            return self._zipcrypto_read(e, raw)
        return _inflate(e.method, raw, e.size)

    def _other_password(self, e: _Entry, salt: bytes, klen: int, verifier: bytes) -> bytes:
        """Key material of the first known password (passwords(), read now) that passes the
        member's 2-byte verifier; it becomes this view's password. ZipError when none does."""
        for pwd in passwords():
            if pwd == self.password:
                continue
            dk = _derive(pwd, salt, klen)
            if dk[2 * klen:] == verifier:
                self.password = pwd
                return dk
        raise ZipError(f"{e.name}: wrong password (no known archive password fits)")

    def _zipcrypto_read(self, e: _Entry, raw: bytes) -> bytes:
        tries = [self.password] + [p for p in passwords() if p != self.password]
        for pwd in tries:
            try:
                body = _inflate(e.method, _zipcrypto(pwd, raw, e), e.size)
            except Exception:
                continue
            if zlib.crc32(body) & 0xFFFFFFFF == e.crc:
                self.password = pwd
                return body
        raise ZipError(f"{e.name}: wrong password (no known archive password fits)")

    def read(self, name) -> bytes:
        got = self._cache.get(name)
        if got is None:
            got = self._read(self._entries[name])
            self._cache[name] = got
        return got

    def read_many(self, names, workers: int = 8) -> dict[str, bytes]:
        names = [n for n in dict.fromkeys(names)]
        todo = [n for n in names if n not in self._cache]
        if len(todo) > 1 and workers > 1:
            pool = _pool()
            futs = {n: pool.submit(self._read, self._entries[n]) for n in todo}
            for n, f in futs.items():
                self._cache[n] = f.result()
        else:
            for n in todo:
                self.read(n)
        return {n: self._cache[n] for n in names}

    def check(self, name) -> bool:
        """CRC-32 (and for AE-2, where the CRC is zero, the HMAC) of one member. Tests only."""
        import hmac
        e = self._entries[name]
        body = self.read(name)
        if e.aes:
            raw = self._raw(e)
            klen = _AES_KEYLEN[e.aes]
            slen = klen // 2
            dk = _derive(self.password, raw[:slen], klen)
            mac = hmac.new(dk[klen:2 * klen], raw[slen + 2:len(raw) - 10], hashlib.sha1).digest()[:10]
            if mac != raw[-10:]:
                return False
            if e.aes_version == 2:
                return True
        return zlib.crc32(body) & 0xFFFFFFFF == e.crc


def _zipcrypto(password: bytes, raw: bytes, e: _Entry) -> bytes:
    """Traditional PKWARE encryption (rare here; slow pure Python, kept for completeness)."""
    import zipfile
    dec = zipfile._ZipDecrypter(password)   # noqa: SLF001 - stdlib helper, copied use
    head = dec(raw[:12])
    return dec(raw[12:]) if head is not None else b""


def open_zip(data: bytes, password: bytes = PASSWORD) -> ZipView:
    return ZipView(data, password)


def is_zip(data: bytes) -> bool:
    return data[:4] in (b"PK\x03\x04", b"PK\x05\x06")


# ---- where saved data lives ---------------------------------------------------------------------------

def repo_root() -> Path:
    return HERE.parent


def data_root() -> Path:
    """$CTF_SPEED_DATA, else the challenges root of archive_passwords ($CTF_WORKDIR, a worktree's
    main checkout, else <repo>/challenges). Read on every call."""
    env = os.environ.get("CTF_SPEED_DATA")
    if env:
        return Path(env).expanduser()
    return _archive_passwords.challenges_root()


def speed_variants_root() -> Path:
    """The speed runner's own saved variants: $CTF_SPEED_OUT/variants, else speedrun/variants."""
    env = os.environ.get("CTF_SPEED_OUT")
    return (Path(env).expanduser() if env else HERE) / "variants"


# ---- what the judge accepted before ---------------------------------------------------------------------

def _key_answers(folder: Path, attempt_id=None):
    """The answers of key.json, else golden.json, in one attempt folder; None if neither (or if the
    file names another attempt than attempt_id)."""
    for name in ("key.json", "golden.json"):
        p = folder / name
        if not p.is_file():
            continue
        try:
            row = json.loads(p.read_text())
        except (OSError, ValueError):
            continue
        if not isinstance(row, dict) or not isinstance(row.get("answers"), dict):
            continue
        if attempt_id and row.get("attempt_id") and row["attempt_id"] != attempt_id:
            continue
        return {str(k): compact(v) for k, v in row["answers"].items()}, name
    return None


_NOT_VARIANTS = {"artifact", "members", "history", "x"}


def attempt_folders(base_glob_root: Path, prefix: str):
    """Every saved attempt folder of a lane: base, time_trial, mastery, and their history/*/."""
    for day in sorted(base_glob_root.glob("day-*")):
        if not day.is_dir():
            continue
        for base in sorted(day.glob(prefix + "*")):
            if not base.is_dir():
                continue
            for mode in ("", "time_trial", "mastery"):
                d = base / mode if mode else base
                if not d.is_dir():
                    continue
                yield base.name, (mode or "base"), d
                hist = d / "history"
                if hist.is_dir():
                    for h in sorted(hist.iterdir()):
                        if h.is_dir():
                            yield base.name, (mode or "base"), h
                if mode:   # the speed runner's layout: <mode>/<attempt id>/
                    for h in sorted(d.iterdir()):
                        if h.is_dir() and h.name not in _NOT_VARIANTS and (h / "attempt.json").is_file():
                            yield base.name, mode, h
