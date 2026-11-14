"""Archive passwords: the one list every reader of an encrypted delivery tries (backlog row 75).

    passwords()      [None, b"infected", <every stored password, newest first>], de-duplicated.
                     None stands for "no password" (an unencrypted member).
    candidates()     the same without None.
    add(value, source="player")   store one; True when it was new.
    add_many(values, source="harvest")  store a batch (B-074 harvest); returns the values that were new.
    stored()         the stored rows, as in the file.
    mask(value)      how a password is shown anywhere: its length and first character, never more.
    Opener(data)     read the members of one zip with the candidates (AES and ZipCrypto).
    stated(obj)      the passwords a Game Master response states, read from all of its text.
    learn(obj, source)  add what stated() finds; returns the new values.

The store is <challenges>/_passwords.json:

    {"passwords": [{"value": "...", "added": "<iso time>", "source": "player|gm|<attempt id>"}]}

It is read from disk on EVERY call to passwords(): there is no cache, so a password the player adds
with tools/password.py while a run is going is used by the next decrypt of every process that is
already running. A missing or damaged file gives the two built-in candidates and nothing else. It
is written atomically (a temporary file and os.replace, under a lock file, mode 0600), and only by
add(): tools/password.py, and a password a Game Master response states.

<challenges> follows the rules of gm.CHALLENGES and labels.challenges_root(): $CTF_WORKDIR
wins; a linked git worktree uses its main checkout's challenges/; otherwise <repo>/challenges.

A candidate is never generated: only `infected` and the stored values are tried. For an AES
(WinZip AE-1/AE-2) member the two-byte password verifier is checked first (one PBKDF2, no
decryption), so a wrong candidate costs well under a millisecond; a ZipCrypto member is tried with
zipfile, whose check byte does the same. A password value is never printed or logged in full:
mask() is what any line shows.

Plain Python and the stdlib (pyzipper when it is installed, for AES). No Game Master request.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import re
import struct
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import env as ctf_env, paths as ctf_paths
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import env as ctf_env, paths as ctf_paths

DEFAULT = b"infected"
FILE_NAME = "_passwords.json"
SOURCES_FIXED = ("player", "gm")
MAX_LEN = 128                      # a stated or stored value longer than this is not a password
ROOT = Path(__file__).resolve().parents[2]
AES_METHOD = 99
AES_KEYLEN = {1: 16, 2: 24, 3: 32}

try:  # AES members in process; without it a caller falls back to 7-Zip with password_for()
    import pyzipper
except ImportError:  # pragma: no cover - the .venv has it
    pyzipper = None


# Backlog row 338 (Day 17 retro; built 2026-10-17 for Day 18). pyzipper derives every AES member's key with
# Cryptodome's PBKDF2 (HMAC-SHA1, 1000 rounds), about 0.57 ms a member; hashlib.pbkdf2_hmac gives the same
# bytes in about half the time. A Script Mastery opens 1270 AES members (635, twice: row 225), so key
# derivation was about 0.72 s of its 0.75 s split. The module's name is rebound to a function of the same
# signature: HMAC-SHA1 with bytes in goes to hashlib, anything else (another prf or hash module, a str
# password) to Cryptodome as before. pyzipper still checks the 2-byte verifier and the HMAC of every member,
# so a wrong key is still refused. CTF_AES_KDF=cryptodome in front of a command leaves pyzipper as it was.
def _fast_kdf():
    if ctf_env.get("CTF_AES_KDF", "").strip().lower() == "cryptodome":
        return False
    try:
        import pyzipper.zipfile_aes as zaes
    except Exception:  # noqa: BLE001 - no pyzipper: nothing to rebind
        return False
    orig = getattr(zaes, "PBKDF2", None)
    if orig is None or getattr(orig, "huntress_fast", False):
        return bool(orig is not None)

    def PBKDF2(password, salt, dkLen=16, count=1000, prf=None, hmac_hash_module=None):  # noqa: N802 - pyzipper's name
        if prf is None and hmac_hash_module is None and type(password) is bytes and type(salt) is bytes \
                and type(dkLen) is int and type(count) is int and dkLen > 0 and count > 0:
            return hashlib.pbkdf2_hmac("sha1", password, salt, count, dkLen)
        return orig(password, salt, dkLen, count, prf, hmac_hash_module)

    PBKDF2.huntress_fast = True
    PBKDF2.huntress_orig = orig
    zaes.PBKDF2 = PBKDF2
    return True


FAST_KDF = _fast_kdf() if pyzipper is not None else False


# ---------------------------------------------------------------------------- where

def challenges_root() -> Path:
    """The event workdir, ctf.paths.workdir(): $CTF_WORKDIR, else ~/ctf-work/<event>. Resolved on every
    call (a test or rehearsal moves it after import); raises ctf.event.EventError when neither resolves."""
    return ctf_paths.workdir()


def store_path() -> Path:
    return challenges_root() / FILE_NAME


# ---------------------------------------------------------------------------- the store

def _valid(value) -> bool:
    return isinstance(value, str) and 0 < len(value) <= MAX_LEN and "\n" not in value and "\x00" not in value


def stored() -> list:
    """The rows of the file that carry a usable value, in file order. [] when it is missing or damaged."""
    try:
        body = json.loads(store_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    rows = body.get("passwords") if isinstance(body, dict) else None
    return [r for r in rows if isinstance(r, dict) and _valid(r.get("value"))] if isinstance(rows, list) else []


def passwords() -> list:
    """[None, b"infected", stored values newest first], each once. Read from disk on every call."""
    rows = list(enumerate(stored()))
    rows.sort(key=lambda p: (str(p[1].get("added") or ""), p[0]), reverse=True)
    out, seen = [None, DEFAULT], {DEFAULT}
    for _, row in rows:
        value = row["value"].encode("utf-8")
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def candidates() -> list:
    return passwords()[1:]


def mask(value) -> str:
    """'<8 chars, starts i>': all a log line, an alert or a listing ever shows of a password."""
    if value is None:
        return "<none>"
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    value = str(value)
    if not value:
        return "<empty>"
    first = value[0] if value[0].isalnum() else "?"
    return f"<{len(value)} chars, starts {first}>"


@contextlib.contextmanager
def _locked(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path) + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX)
        except (ImportError, OSError):
            pass
        yield
    finally:
        os.close(fd)


def add(value, source: str = "player", at: str = None) -> bool:
    """Store one password. True when it was new; False when it is `infected` or already stored.
    ValueError for an empty, multi-line or overlong value. The write is atomic and mode 0600."""
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if not _valid(value):
        raise ValueError(f"not a usable password ({mask(value)}): empty, more than {MAX_LEN} characters, or more than one line")
    if value.encode("utf-8") == DEFAULT:
        return False
    path = store_path()
    with _locked(path):
        try:
            body = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            body = {}
        rows = body.get("passwords") if isinstance(body, dict) else None
        rows = [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []
        if any(r.get("value") == value for r in rows):
            return False
        rows.append({"value": value, "added": at or datetime.now(timezone.utc).isoformat(timespec="microseconds"),
                     "source": re.sub(r"[^\w.:@-]+", "_", str(source or "player"))[:80]})
        fd, tmp = tempfile.mkstemp(prefix=".passwords.", dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"passwords": rows}, f, indent=2)
                f.write("\n")
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
    return True


def add_many(values, source: str = "harvest") -> list:
    """Store a batch of candidate passwords (B-074: harvested from appended bytes, strings and sibling
    files). Returns the values that were new to the store, in the order given. An unusable value (empty,
    multi-line or overlong) is skipped, not raised on: a harvest is best-effort and one bad token must
    not lose the rest. `infected` and already-stored values add nothing, as with add()."""
    new = []
    for value in values or []:
        try:
            if add(value, source=source):
                new.append(value if isinstance(value, str) else value.decode("utf-8", "replace"))
        except (OSError, ValueError):
            continue
    return new


# ---------------------------------------------------------------------------- what a response states

# "password: X", "password = `X`", "the password is X", "zip password: X", "the password to try is `X`",
# "archive passphrase X". The value is the quoted text, or the next word.
_STATED = re.compile(
    r"\bpass(?:word|phrase)\b"
    r"(?:\s+(?:to\s+(?:use|try)|for\s+(?:the\s+|this\s+|each\s+)?[\w.-]+(?:\s+(?:archive|file|zip))?))?"
    r"\s*(\b(?:is|was)\b|[:=])?\s*"
    r"(?:`([^`\n]{1,128})`|\"([^\"\n]{1,128})\"|'([^'\n]{1,128})'|“([^”\n]{1,128})”|([^\s`\"'“”<>]{1,128}))",
    re.I)
_NOT_A_VALUE = {"is", "was", "to", "for", "of", "the", "a", "an", "and", "or", "not", "no", "none", "null", "required",
                "needed", "protected", "unknown", "provided", "given", "below", "above", "same", "set", "reset",
                "hint", "field", "prompt", "used", "use", "try", "it", "this", "that", "here", "there", "with",
                "on", "in", "if", "when", "are", "be", "you", "your", "please", "will", "can", "must", "should"}


def _strings(obj, depth=0):
    if depth > 12:
        return
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str):
                yield k
            yield from _strings(v, depth + 1)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _strings(v, depth + 1)


def stated(obj) -> list:
    """The passwords a response (any JSON value, or a text) states, in the order they appear.
    `infected` is included when it is stated; a word such as `required` is not a value."""
    out = []
    for text in _strings(obj):
        if "ass" not in text and "ASS" not in text:   # cheap: almost no text names a password
            continue
        for m in _STATED.finditer(text):
            sep, groups = m.group(1), m.groups()[1:]
            quoted = next((g for g in groups[:4] if g is not None), None)
            if quoted is None and not sep:
                continue    # a bare next word ("what password does ...") is prose, not a value: it needs is, : or =
            value = quoted.strip() if quoted is not None else (groups[4] or "").rstrip(".,;:!?)]}")
            if not _valid(value) or value.lower() in _NOT_A_VALUE or not re.search(r"[A-Za-z0-9]", value):
                continue
            if value not in out:
                out.append(value)
    return out


def learn(obj, source: str = "gm") -> list:
    """Add every password the response states. Returns the values that were new to the store.
    It never raises: a store that cannot be written loses the value, not the run."""
    new = []
    for value in stated(obj):
        try:
            if add(value, source=source):
                new.append(value)
        except (OSError, ValueError):
            continue
    return new


# ---------------------------------------------------------------------------- reading a zip

def _local_body(data: bytes, info) -> int:
    """Offset of a member's (encrypted) bytes: after its local header, name and extra field."""
    p = info.header_offset
    if data[p:p + 4] != b"PK\x03\x04":
        raise ValueError("no local header")
    nlen, xlen = struct.unpack_from("<HH", data, p + 26)
    return p + 30 + nlen + xlen


def _aes_strength(info) -> int:
    extra, i = info.extra or b"", 0
    while i + 4 <= len(extra):
        hid, hlen = struct.unpack_from("<HH", extra, i)
        if hid == 0x9901 and hlen >= 7:
            return extra[i + 4 + 4]
        i += 4 + hlen
    return 0


def aes_verifier_ok(data: bytes, info, pwd: bytes) -> bool:
    """True when pwd passes the member's WinZip AES password verifier (2 bytes after the salt).
    One PBKDF2-HMAC-SHA1 of 1000 rounds, no decryption. A pass is right with odds 65535 in 65536;
    the read that follows checks the HMAC."""
    klen = AES_KEYLEN.get(_aes_strength(info))
    if not klen or pwd is None:
        return False
    try:
        s = _local_body(data, info)
    except (ValueError, struct.error):
        return False
    salt, pv = data[s:s + klen // 2], data[s + klen // 2:s + klen // 2 + 2]
    return hashlib.pbkdf2_hmac("sha1", pwd, salt, 1000, 2 * klen + 2)[-2:] == pv


def encrypted(info) -> bool:
    return bool(info.flag_bits & 1) or info.compress_type == AES_METHOD


class Opener:
    """Read the members of one zip held in memory with the known passwords.

        op = Opener(data)          # the candidates are read from the store once, here
        body = op.read(info)       # bytes, or None
        op.locked                  # names of encrypted members no candidate opens
        op.used                    # the password that opened the last encrypted member (or None)

    read() returns None for a member it cannot read: one in `locked` (encrypted, and no candidate
    passes its check), or one that is damaged or needs a library this process lacks (7-Zip is then
    the caller's fallback, with password_for()). The password that worked is tried first on the
    next member. zf is the archive's zipfile.ZipFile when the caller already has one."""

    def __init__(self, data: bytes, zf=None, cands=None):
        self.data = data
        self.zf = zf if zf is not None else zipfile.ZipFile(io.BytesIO(data))
        self._cands = cands
        self._aes = None
        self.used = None
        self.locked = []
        self.verified = {}     # member name -> the candidate that passed its verifier (no pyzipper)

    @property
    def cands(self) -> list:
        if self._cands is None:
            self._cands = candidates()
        return self._cands

    def _order(self) -> list:
        return ([self.used] + [c for c in self.cands if c != self.used]) if self.used else list(self.cands)

    def read(self, info):
        if not encrypted(info):
            try:
                return self.zf.read(info)
            except Exception:
                return None
        if info.compress_type == AES_METHOD:
            return self._read_aes(info)
        return self._read_zipcrypto(info)

    def _read_zipcrypto(self, info):
        damaged = False
        for pwd in self._order():
            try:
                body = self.zf.read(info, pwd=pwd)
            except RuntimeError as e:          # "Bad password": the check byte says no
                if "password" not in str(e).lower():
                    damaged = True
                continue
            except Exception:                  # the check byte passed (1 in 256) but the bytes did not
                damaged = True
                continue
            self.used = pwd
            return body
        if not damaged:
            self.locked.append(info.filename)
        return None

    def _read_aes(self, info):
        if pyzipper is None:
            passing = [pwd for pwd in self._order() if aes_verifier_ok(self.data, info, pwd)]
            if passing:
                self.verified[info.filename] = passing[0]
            else:
                self.locked.append(info.filename)
            return None
        # pyzipper checks the same 2-byte verifier before it decrypts anything and raises
        # RuntimeError('Bad password'): that is the pre-check, with no second key derivation.
        damaged = False
        for pwd in self._order():
            try:
                self._aes = self._aes or pyzipper.AESZipFile(io.BytesIO(self.data))
                body = self._aes.read(info.filename, pwd=pwd)
            except RuntimeError as e:
                if "password" not in str(e).lower():
                    damaged = True
                continue
            except Exception:                  # passed the verifier (1 in 65536) but not the HMAC, or damaged
                damaged = True
                continue
            self.used = pwd
            return body
        if not damaged:
            self.locked.append(info.filename)
        return None

    def password_for(self):
        """The candidate that opened, or passed the verifier of, an encrypted member: what to hand
        7-Zip. None when there is none."""
        return self.used or next(iter(self.verified.values()), None)


def read_all(data: bytes, cands=None) -> tuple:
    """({member name: bytes}, [locked member names]) of one zip; ({}, []) when it is no zip."""
    try:
        op = Opener(data, cands=cands)
    except Exception:
        return {}, []
    out = {}
    for info in op.zf.infolist():
        if info.is_dir():
            continue
        body = op.read(info)
        if body is not None:
            out[info.filename] = body
    return out, op.locked
