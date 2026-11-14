#!/usr/bin/env python3
"""Android unlock-crypto chain solver (B-086): decrypt a flag an APK locks behind a derived key.

A VaultKeeper-class Mobile challenge ships the flag as an AES ciphertext inside the package (a
base64 ``R.string`` or an asset blob) and derives the key from facts of the package itself:

  * the signing certificate (its DER, read from the v1 ``META-INF/*.RSA`` block or, when the APK
    is v2/v3-only, from the APK Signing Block),
  * ``R.string`` / dex string constants (a recovery-token template, a passcode card code), and
    short codes from small text files shipped next to the APK (a "handover card"),
  * broadcast/receiver action names (preimages), and
  * a small brute space -- a 4-digit archive PIN -- sometimes pinned down first by matching an
    HMAC-SHA256 prefix the package states.

The key is ``SHA256(<some concatenation of those atoms, with the PIN spliced in>)``.  Recognising
*which* concatenation from decompiled Smali/Java is the part a model still reads best (the row is
"partly" automatable); what is mechanical -- and what this engine does -- is to:

  1. locate every candidate ciphertext blob (over *all* string constants, ranked),
  2. extract and rank the key atoms (cert DER + digest spellings, string constants, actions),
  3. enumerate a ranked, bounded set of composition recipes with the PIN brute spliced in
     (optionally pre-gated by an HMAC-SHA256 prefix stated in the package), and
  4. try AES-GCM and AES-CBC with ``cryptography``.

A result is accepted only on hard proof: AES-GCM on **tag verification** plus a flag in the event
format, AES-CBC on **valid PKCS#7 padding** plus a flag.  So the brute may be broad without ever
returning a wrong answer: a wrong key fails the tag or the padding.

When the dex holds a static method that hashes its String arguments with ``MessageDigest`` (a
``deriveKey(token, pin, passcode)``), the engine does not guess the composition: it runs that method
in dex_chain_codec's Dalvik VM with the atoms and each PIN as arguments and uses the ``byte[]`` it
returns as the key (``_kdf_methods`` / ``_derive_via_vm``), before the enumerated recipes.

Split packages (``.apks``, ``.xapk``) are opened: every ``*.apk`` member is searched as a package
of its own (``outer!inner.apk``).

Every way the search can end is named in the result:
  * ``solved`` -- a blob verified and held a flag;
  * ``none`` -- the bounded space was searched to the end and nothing verified;
  * ``unsure`` -- the trial budget, the CPU time budget or the wall-clock budget ran out first, or
    the recipe list was cut by ``MAX_RECIPES``: the notes say which, how many trials ran and how
    large the space was ("search incomplete");
  * ``blocked`` -- ``cryptography`` is missing, or an option is malformed (named).

Two clocks bound a run.  ``time_budget`` is CPU seconds (``process_time``): the work the search may
spend.  ``wall_budget`` is wall-clock seconds (``time.monotonic``) and exists only because the
[intake] runner kills the engine on a *wall-clock* timeout (300 s, ``proc.wait``): on a machine at a
load of 50-170 on 14 cores, 200 CPU seconds take far longer than 300 wall seconds, so without a
wall deadline below the intake timeout the engine would be killed before writing its ``unsure``.

This is the CSCTF flag-format chain, not the ANS- code chain: the plaintext is matched against the
event flag format (``ctf.flagfmt``), never routed through ``codec_search``'s ANS gate.

Contract entry: ``solve(challenge_dir, profile, **opts) -> SolverResult`` (CONTRACTS 6-7).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import io
import os
import re
import struct
import sys
import time
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
for _p in (HERE.parent / "common", HERE):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

try:
    from ctf import flagfmt
except ModuleNotFoundError:  # a bare script run needs the checkout root on sys.path
    sys.path.append(str(HERE.parents[1]))
    from ctf import flagfmt
from ctf.result import Cost, Evidence, SolverResult

import apk_facts  # noqa: E402  (reuses manifest_facts, _cert, _dex_strings, _digest_forms)
import apk_resources as R  # noqa: E402  (arsc_values, axml_tree)

# ---- bounds (every search space is explicitly capped; a cap that cuts is named in the notes) ----
MAX_APK_BYTES = 128 << 20
MAX_MEMBER_BYTES = 8 << 20
MAX_BLOBS = 64            # candidate ciphertexts considered (after ranking)
MIN_BLOB_BYTES = 29      # 12-byte GCM nonce + 16-byte tag + 1 byte; CBC needs 32
MAX_BLOB_BYTES = 1 << 20
MAX_STRING_ATOMS = 40    # distinct string constants kept as key material (after ranking)
MAX_TEMPLATE_ATOMS = 12  # format-string templates kept (each expands with cert digests)
MAX_ACTION_ATOMS = 16
MAX_RECIPES = 2048       # composition recipes (atom placements) tried, best-ranked first
MAX_HMAC_TARGETS = 32    # stated HMAC-prefix targets checked (all of them per HMAC computed)
MAX_GATE_KEYS = 24       # candidate HMAC keys (best-ranked string atoms, then cert tokens)
MAX_LOOSE_FILES = 32     # small text files next to the APK read for key atoms
MAX_LOOSE_FILE_BYTES = 4096
MAX_LOOSE_ATOMS = 64
DEFAULT_PINS = 10000     # 4-digit archive PIN space
DEFAULT_BUDGET = 8_000_000   # trials (an HMAC of the gate, or one key x blob cipher attempt)
DEFAULT_TIME_BUDGET = 200.0  # CPU seconds (process_time): the work a default run may spend
# Wall-clock seconds (time.monotonic).  The [intake] timeout (300 s in the manifest) is wall clock, and
# under load CPU seconds lag wall seconds by far, so this deadline -- not the CPU cap -- is what makes
# the engine stop and print its own `unsure` before intake kills it; 60 s are left for interpreter
# start-up, imports and the JSON line.
DEFAULT_WALL_BUDGET = 240.0
CLOCK_EVERY = 1024       # trials between clock reads
MAX_NESTED_APKS = 16     # inner *.apk members of one .apks/.xapk searched as packages
_BIG_MEMBER_OK = (".apk", ".dex", ".arsc", "AndroidManifest.xml")   # may exceed MAX_MEMBER_BYTES
# dex VM evaluation of a static KDF method (dex_chain_codec's Dalvik VM)
MAX_KDF_METHODS = 4      # candidate KDF methods evaluated per package
MAX_KDF_PARAMS = 3       # String/int parameters a KDF method may take (one of them is the PIN)
MAX_KDF_ARGS = 12        # ranked atoms tried in the non-PIN parameter slots
KDF_MAX_STEPS = 200_000  # VM steps one KDF call may take
_MD = "Ljava/security/MessageDigest;"

_TEMPLATE = re.compile(r"%0?\d*[sdxX]|%s|\{\}|\{0\}|__CERT__|<cert>|<digest>")
_HEX_TARGET = re.compile(r"^[0-9A-Fa-f]{6,32}$")
_B64 = re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")
_B64URL = re.compile(r"^[A-Za-z0-9_-]{20,}={0,2}$")
_DESCRIPTOR = re.compile(r"^\[*L[^;\s]+;$|^\(.*\)\S+$|^<c?l?init>$")
_SHORTY = re.compile(r"^[VZBSCIJFDL]{1,8}$")
_KEYLIKE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-:.#@!$+/=]{2,63}$")
_IDENT = re.compile(r"^[a-z][A-Za-z]*$|^[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z0-9_.$]+$")
_HINT_NAME = re.compile(r"pass|pin|key|token|secret|code|salt|card|seed|vault|unlock|recover", re.I)
_SKIP_MAGIC = (b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"\x7fELF", b"RIFF", b"PK\x03\x04", b"dex\n",
               b"OggS", b"fLaC", b"\x1f\x8b\x08", b"wOFF", b"wOF2", b"\x00\x01\x00\x00", b"OTTO", b"%PDF",
               b"\xca\xfe\xba\xbe")   # a Java class file (Kotlin's DebugProbesKt.bin) is not a ciphertext
_SKIP_SUFFIX = (".dex", ".arsc", ".xml", ".MF", ".SF", ".RSA", ".DSA", ".EC", ".so", ".png", ".webp",
                ".jpg", ".jpeg", ".gif", ".ttf", ".otf", ".kotlin_builtins", ".kotlin_module", ".version")

_cpu = time.process_time   # the CPU clock the time budget reads (a test injects a step clock)
_wall = time.monotonic     # the wall clock the wall budget reads (a test injects a step clock)


class CryptoMissing(RuntimeError):
    """`cryptography` is absent (named in the message)."""


class BadOption(ValueError):
    """A malformed option (named in the message)."""


def _require_crypto():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
        from cryptography.hazmat.primitives.ciphers import Cipher  # noqa: F401
    except ImportError as exc:  # no silent fallback
        raise CryptoMissing("cryptography is required for the AES unlock chain; pip install cryptography") from exc


# --------------------------------------------------------------------------- file walking

def _walk(challenge_dir: Path):
    """Every regular file under the challenge dir, sorted; symlinks (files or dirs) and hidden
    directories (``.ctf``, ``.git``) are never followed or read."""
    out = []
    for root, dirs, files in os.walk(challenge_dir, followlinks=False):
        dirs[:] = sorted(d for d in dirs if not d.startswith("."))   # followlinks=False: no symlinked dir
        for f in sorted(files):
            p = Path(root) / f
            if not p.is_symlink() and p.is_file():
                out.append(p)
    return out


def _head(path: Path, n: int = 4) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(n)


# --------------------------------------------------------------------------- APK loading

def _load_members(blob: bytes):
    """(members, skipped): the zip's members by name, and the names of those left out for size.  A
    member over MAX_MEMBER_BYTES is skipped (and named) unless it is structural -- a nested ``.apk``,
    a ``.dex``, ``resources.arsc`` or the manifest -- which may be as large as MAX_APK_BYTES."""
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            out, skipped = {}, []
            for info in zf.infolist():
                if info.is_dir():
                    continue
                cap = MAX_APK_BYTES if info.filename.endswith(_BIG_MEMBER_OK) else MAX_MEMBER_BYTES
                if info.file_size > cap:
                    skipped.append(info.filename)
                    continue
                out[info.filename] = zf.read(info)
            return out, skipped
    except (zipfile.BadZipFile, OSError, EOFError, NotImplementedError, RuntimeError):
        return {}, []


def _expand(name: str, members: dict, blob: bytes, skipped: list) -> list:
    """The package itself, or -- for a split bundle (``.apks``/``.xapk``: a zip of ``*.apk``) -- each
    inner APK as a package named ``outer!inner.apk``, plus the outer zip's remaining members when there
    are any.  Inner APKs past MAX_NESTED_APKS are named in the outer package's skipped list."""
    inner = sorted(n for n, b in members.items() if n.lower().endswith(".apk") and b[:4] == b"PK\x03\x04")
    if not inner:
        return [(name, members, blob, skipped)]
    out = []
    for n in inner[:MAX_NESTED_APKS]:
        imembers, iskipped = _load_members(members[n])
        if imembers:
            out.append(("%s!%s" % (name, n), imembers, members[n], iskipped))
        else:
            skipped = skipped + ["%s (unreadable zip)" % n]
    skipped = skipped + ["%s (past %d nested APKs)" % (n, MAX_NESTED_APKS) for n in inner[MAX_NESTED_APKS:]]
    rest = {n: b for n, b in members.items() if n not in inner}
    if rest or skipped:
        out.insert(0, (name, rest, blob, skipped))
    return out


def _packages(challenge_dir: Path, files=None):
    """[(name, members, blob, skipped)] for every APK/ZIP: the given ``files`` only, or every regular
    file under the challenge dir (no symlinks).  The 4-byte magic is read before the whole file.  A
    split bundle (``.apks``/``.xapk``) yields each of its inner APKs (``_expand``)."""
    paths = [Path(f) for f in files] if files is not None else _walk(challenge_dir)
    seen = []
    for path in paths:
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_APK_BYTES:
                continue
            if _head(path) != b"PK\x03\x04":
                continue
            blob = path.read_bytes()
        except OSError:
            continue
        members, skipped = _load_members(blob)
        if members:
            seen.extend(_expand(path.name, members, blob, skipped))
    return seen


def _loose_atoms(challenge_dir: Path) -> list:
    """Short codes from the small text files next to the APK (a handover card, a note): each short
    line, the value of each ``label: value`` / ``label = value`` line, and each whitespace token.
    Data only -- these strings become key bytes, never instructions."""
    out, n = [], 0
    for path in _walk(challenge_dir):
        if n >= MAX_LOOSE_FILES:
            break
        try:
            if path.stat().st_size > MAX_LOOSE_FILE_BYTES or path.stat().st_size == 0:
                continue
            text = path.read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if text.startswith("PK") or "\x00" in text:
            continue
        n += 1
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            m = re.match(r"^[^:=]{1,40}[:=]\s*(\S.*)$", line)
            if m:
                out.append(m.group(1).strip())
            if len(line) <= 64:
                out.append(line)
            out.extend(t.strip(".,;\"'()[]") for t in line.split())
    return list(dict.fromkeys(a for a in out if 3 <= len(a) <= 64))[: MAX_LOOSE_ATOMS * 4]


# --------------------------------------------------------------------------- cert DER (v1 and v2/v3)

def _v1_cert_der(members: dict):
    """The signing cert DER from a v1 ``META-INF/*.RSA`` PKCS#7 block, via apk_facts._cert."""
    got = apk_facts._cert({"members": members})
    return got[1] if got else None


def _lp32(buf: bytes, off: int):
    """(payload, next_off) of a uint32 little-endian length-prefixed field; None on overrun."""
    if off + 4 > len(buf):
        return None
    n = struct.unpack_from("<I", buf, off)[0]
    if n > len(buf) - off - 4:
        return None
    return buf[off + 4:off + 4 + n], off + 4 + n


_APK_SIG_MAGIC = b"APK Sig Block 42"
_V2_SCHEME_ID = 0x7109871A
_V3_SCHEME_ID = 0xF05368C0


def _v2_cert_der(blob: bytes):
    """The first signer's leaf cert DER from the APK Signing Block (v2/v3), or None.

    The block sits between the last ZIP entry and the Central Directory.  Only the certificate is
    read; signatures are never verified (that is not this engine's job, and the DER is a key atom).
    """
    eocd = blob.rfind(b"PK\x05\x06")
    if eocd < 0 or eocd + 22 > len(blob):
        return None
    cd_off = struct.unpack_from("<I", blob, eocd + 16)[0]
    if cd_off < 24 or cd_off > len(blob):
        return None
    if blob[cd_off - 16:cd_off] != _APK_SIG_MAGIC:
        return None
    size2 = struct.unpack_from("<Q", blob, cd_off - 24)[0]
    block_start = cd_off - 8 - size2
    if block_start < 0 or block_start + 8 > len(blob):
        return None
    size1 = struct.unpack_from("<Q", blob, block_start)[0]
    if size1 != size2:
        return None
    off, end = block_start + 8, cd_off - 24
    while off + 12 <= end:
        pair_len = struct.unpack_from("<Q", blob, off)[0]
        if pair_len < 4 or off + 8 + pair_len > end + 8:
            break
        scheme_id = struct.unpack_from("<I", blob, off + 8)[0]
        value = blob[off + 12:off + 8 + pair_len]
        if scheme_id in (_V2_SCHEME_ID, _V3_SCHEME_ID):
            der = _v2_value_leaf_cert(value)
            if der:
                return der
        off += 8 + pair_len
    return None


def _v2_value_leaf_cert(value: bytes):
    """Walk signers -> signer -> signed_data -> certificates[0] (all uint32 length-prefixed)."""
    signers = _lp32(value, 0)
    if not signers:
        return None
    signer = _lp32(signers[0], 0)
    if not signer:
        return None
    signed_data = _lp32(signer[0], 0)
    if not signed_data:
        return None
    sd = signed_data[0]
    digests = _lp32(sd, 0)          # digests sequence, skipped
    if not digests:
        return None
    certs = _lp32(sd, digests[1])   # certificates sequence
    if not certs:
        return None
    leaf = _lp32(certs[0], 0)       # first certificate
    if not leaf or len(leaf[0]) < 16:
        return None
    return leaf[0]


def _cert_der(members: dict, blob: bytes):
    return _v1_cert_der(members) or _v2_cert_der(blob)


# --------------------------------------------------------------------------- fact extraction

def _arsc_strings(members: dict) -> list:
    """[(entry name, value)] of the R.string values in resources.arsc."""
    arsc = members.get("resources.arsc")
    if not arsc:
        return []
    return [(key, val) for (tname, key), val in R.arsc_values(arsc).items()
            if tname == "string" and isinstance(val, str) and val]


def _dex_string_list(members: dict) -> list:
    out = []
    for name in sorted(n for n in members if n.endswith(".dex") and members[n][:4] == b"dex\n"):
        out.extend(apk_facts._dex_strings(members[name]))
    return [s for s in out if isinstance(s, str) and s]


def _string_constants(members: dict) -> list:
    """R.string / arsc string values and dex string constants, de-duplicated, in a stable order."""
    return list(dict.fromkeys([v for _k, v in _arsc_strings(members)] + _dex_string_list(members)))


def _actions(members: dict) -> list:
    """Broadcast/receiver action names declared in the manifest (intent-filter preimages)."""
    body = members.get("AndroidManifest.xml")
    if not body or not R.is_axml(body):
        return []
    m = apk_facts.manifest_facts(body)
    actions = []
    for comp in m.get("components", ()):
        for flt in comp.get("filters", ()):
            actions.extend(flt.get("actions", ()))
    return list(dict.fromkeys(a for a in actions if isinstance(a, str) and a))


def _shape_score(s: str):
    """How key-like a string is (lower is likelier); None for code-shaped strings never used."""
    if not 1 <= len(s) <= 64 or _DESCRIPTOR.match(s):
        return None
    if _SHORTY.match(s):
        return 5
    if any(c.isspace() for c in s):
        return 3
    if _KEYLIKE.match(s) and (any(c.isdigit() for c in s) or "-" in s or ":" in s):
        return 0
    if _IDENT.match(s):
        return 4             # a bare identifier (onCreate) or a dotted class name
    return 1


def _rank_atoms(arsc: list, loose: list, dex: list, exclude=()) -> list:
    """Key-atom strings ranked before any cap: loose-file codes and hint-named R.string values
    (passcode, pin, token...) first, then other R.string values, then dex constants; inside each
    source, key-like shapes (``CARD-7731``) before words, sentences and identifiers."""
    excl = set(exclude)
    scored = []
    for i, (name, val) in enumerate(arsc):
        sh = _shape_score(val)
        if sh is not None and val not in excl:
            scored.append((sh + (0 if _HINT_NAME.search(name or "") else 1), 0, i, val))
    for i, val in enumerate(loose):
        sh = _shape_score(val)
        if sh is not None and val not in excl:
            scored.append((sh, 1, i, val))
    for i, val in enumerate(dex):
        sh = _shape_score(val)
        if sh is not None and val not in excl:
            scored.append((sh + 2, 2, i, val))
    scored.sort()
    return list(dict.fromkeys(v for *_r, v in scored))


def _rank_templates(strings: list) -> list:
    """Format-string templates, no-whitespace ones (``KJSC-%s-RECOVERY``) before sentences."""
    tm = [s for s in strings if _TEMPLATE.search(s) and len(s) <= 64]
    return sorted(dict.fromkeys(tm), key=lambda s: (any(c.isspace() for c in s), tm.index(s)))


def _cert_digests(der: bytes) -> list:
    """(label, text) spellings of the cert digest an unlock chain tends to use: sha256 and sha1, each
    as apk_facts._digest_forms spells it (hex, HEX, colon forms), 8-char prefixes, and base64."""
    out = []
    for algo in ("sha256", "sha1"):
        raw = hashlib.new(algo, der).digest()
        hx = raw.hex()
        out.append(("%s8" % algo, hx[:8].upper()))
        out.append(("%s8" % algo, hx[:8]))
        out.extend(("%s-%s" % (algo, form), v) for form, v in apk_facts._digest_forms(hx))
        out.append(("%s-b64" % algo, base64.b64encode(raw).decode()))
    seen, uniq = set(), []
    for lab, v in out:
        if v not in seen:
            seen.add(v)
            uniq.append((lab, v))
    return uniq


def _cert_tokens(templates: list, digests: list) -> list:
    """Every ``...%s...``/``...__CERT__...`` template expanded with every cert-digest spelling first
    (a recovery token is often ``PREFIX-<digest8>-SUFFIX``), then the bare digests."""
    vals = [d for _l, d in digests]
    out = []
    for tmpl in templates[:MAX_TEMPLATE_ATOMS]:
        for dg in vals:
            out.append(_TEMPLATE.sub(lambda _m, dg=dg: dg, tmpl, count=1))
    out.extend(vals)
    return list(dict.fromkeys(out))


def _b64_rank(t: str) -> int:
    """Random base64 has digits and both cases; an identifier that happens to parse does not."""
    return 0 if (any(c.isdigit() for c in t) and any(c.isupper() for c in t) and any(c.islower() for c in t)) else 1


def _decode_b64(s: str):
    """(label, bytes) of a base64 / base64url string constant, or None when it is not one."""
    t = s.strip()
    try:
        if _B64.match(t) and len(t) % 4 == 0:
            return "b64:%s" % t[:16], base64.b64decode(t, validate=True)
        if _B64URL.match(t):
            return "b64url:%s" % t[:16], base64.urlsafe_b64decode(t + "=" * (-len(t) % 4))
    except ValueError:  # binascii.Error is a ValueError: a non-base64 string is simply not a blob
        return None
    return None


def _candidate_blobs(members: dict, strings: list) -> list:
    """(label, bytes) ciphertext candidates over *all* strings: base64 string constants first
    (random-looking ones before identifier-shaped ones), then raw binary members, smallest first,
    skipping known media/ELF/zip/dex magics."""
    str_c, seen = [], set()

    def ok(data):
        return MIN_BLOB_BYTES <= len(data) <= MAX_BLOB_BYTES and data not in seen

    for idx, s in enumerate(strings):
        got = _decode_b64(s)
        if got and ok(got[1]):
            seen.add(got[1])
            str_c.append((_b64_rank(s.strip()), idx, got[0], got[1]))
    str_c.sort(key=lambda r: (r[0], r[1]))
    out = [(label, data) for _r, _i, label, data in str_c]

    files = []
    for name in sorted(members):
        if name.endswith(_SKIP_SUFFIX):
            continue
        body = members[name]
        if body[:4].startswith(_SKIP_MAGIC) or body[4:8] == b"ftyp" or not _looks_binary(body) or not ok(body):
            continue
        seen.add(body)
        files.append(("file:%s" % name, body))
    files.sort(key=lambda r: len(r[1]))
    return (out + files)[:MAX_BLOBS]


def _looks_binary(body: bytes) -> bool:
    """A member is a ciphertext candidate when it is not plain text: a null byte, or many bytes
    outside the printable range in its first block."""
    if not body:
        return False
    head = body[:256]
    if b"\x00" in head:
        return True
    nonprint = sum(1 for c in head if c < 9 or (13 < c < 32) or c >= 127)
    return nonprint * 4 >= len(head)


# --------------------------------------------------------------------------- the meter

class _Meter:
    """Trials spent against the trial budget, the CPU time budget and the wall-clock budget; ``stop``
    names why it ended ("budget", "time" or "wall").  Both clocks are read every CLOCK_EVERY trials."""

    def __init__(self, budget: int, time_budget: float, t0: float, wall_budget: float = 0.0, w0: float = 0.0):
        self.trials, self.budget, self.time_budget, self.t0 = 0, budget, time_budget, t0
        self.wall_budget, self.w0 = wall_budget, w0
        self.stop = None
        self._next_clock = CLOCK_EVERY

    def spend(self, n: int = 1) -> bool:
        self.trials += n
        if self.trials >= self.budget:
            self.stop = "budget"
            return True
        if (self.time_budget or self.wall_budget) and self.trials >= self._next_clock:
            self._next_clock = self.trials + CLOCK_EVERY
            if self.time_budget and _cpu() - self.t0 > self.time_budget:
                self.stop = "time"
                return True
            if self.wall_budget and _wall() - self.w0 > self.wall_budget:
                self.stop = "wall"
                return True
        return False


# --------------------------------------------------------------------------- PIN gate (HMAC prefix)

def _pin_strings(n: int) -> list:
    return ["%04d" % i for i in range(n)]


def _hmac_targets(strings: list) -> list:
    out = [t.strip() for t in strings if _HEX_TARGET.match((t or "").strip()) and len(t.strip()) % 2 == 0]
    return list(dict.fromkeys(out))[:MAX_HMAC_TARGETS]


def _hmac_gated_pins(targets: list, atoms: list, pins: list, meter: "_Meter | None" = None) -> list:
    """PINs whose HMAC-SHA256(<some atom as key>, pin) starts with one of the stated hex prefixes.

    Each HMAC is computed once and checked against every target (grouped by prefix length), and
    each one counts as a trial against ``meter``: the gate is part of the budget.  Returns the
    matching PINs (to try first); the full brute still runs after them.
    """
    if not targets:
        return []
    by_len = {}
    for t in targets[:MAX_HMAC_TARGETS]:
        by_len.setdefault(len(t) // 2, set()).add(bytes.fromhex(t))
    keys = [a.encode("utf-8", "surrogatepass") for a in atoms[:MAX_GATE_KEYS] if a]
    hits = []
    for key in keys:
        for pin in pins:
            d = hmac.digest(key, pin.encode(), "sha256")
            for n, want in by_len.items():
                if d[:n] in want:
                    hits.append(pin)
            if meter is not None and meter.spend():
                return list(dict.fromkeys(hits))
    return list(dict.fromkeys(hits))


# --------------------------------------------------------------------------- composition recipes

def _recipes(cert_tokens, string_atoms, actions):
    """(recipes, total): ranked (parts-before-PIN, parts-after-PIN) recipes, best first, cut to
    MAX_RECIPES; ``total`` is how many there were before the cut (the caller names a cut).

    Each atom carries its rank (its index in its ranked list); a recipe scores the sum of its atoms'
    ranks plus one per atom, so the cap spreads across every family instead of exhausting the first
    one.  VaultKeeper's own recipe -- ``recovery_token || PIN || passcode`` -- is in the
    token+PIN+string family.
    """
    tokens = list(dict.fromkeys(cert_tokens))
    strings = list(dict.fromkeys(string_atoms))
    acts = list(dict.fromkeys(actions))
    cand = []

    def push(score, before, after):
        cand.append((score, len(cand), (tuple(p for p in before if p), tuple(p for p in after if p))))

    push(0, [], [])                                        # PIN alone
    for r, tk in enumerate(tokens):                       # token || PIN, PIN || token
        push(r + 1, [tk], [])
        push(r + 1, [], [tk])
    for r, st in enumerate(strings):                      # string || PIN, PIN || string
        push(r + 1, [st], [])
        push(r + 1, [], [st])
    for r, ac in enumerate(acts):                         # action || PIN, PIN || action
        push(r + 1, [ac], [])
        push(r + 1, [], [ac])
    for rt, tk in enumerate(tokens):                      # token || PIN || string (VaultKeeper), reverse
        for rs, st in enumerate(strings):
            push(rt + rs + 2, [tk], [st])
            push(rt + rs + 2, [st], [tk])
    for ra, ac in enumerate(acts):                        # action preimages with a token
        for rt, tk in enumerate(tokens):
            push(ra + rt + 2, [tk, ac], [])
            push(ra + rt + 2, [ac], [tk])
    cand.sort(key=lambda c: (c[0], c[1]))
    recipes = list(dict.fromkeys(c[2] for c in cand))
    return recipes[:MAX_RECIPES], len(recipes)


# --------------------------------------------------------------------------- the ciphers

def _try_gcm(key: bytes, blob: bytes):
    """AES-GCM plaintext under `key`, trying the two common layouts, or None on tag failure."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    aes = AESGCM(key)
    layouts = []
    if len(blob) >= 12 + 16 + 1:
        layouts.append((blob[:12], blob[12:]))                       # nonce || ct || tag
        layouts.append((blob[:12], blob[28:] + blob[12:28]))         # nonce || tag || ct
    for nonce, ctwithtag in layouts:
        try:
            return aes.decrypt(nonce, ctwithtag, None)
        except InvalidTag:
            continue
    return None


def _try_cbc(key: bytes, blob: bytes):
    """AES-CBC (iv prefix) plaintext with PKCS#7 padding removed, or None when padding is absent.

    The padding is checked on the last block alone first (one ECB block decrypt), so a wrong key
    costs the same on a 1 MiB asset as on a 32-byte string."""
    import keystores
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    if len(blob) < 32 or (len(blob) - 16) % 16:
        return None
    dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    last = bytes(a ^ b for a, b in zip(dec.update(blob[-16:]), blob[-32:-16]))
    pad = last[-1]
    if not 1 <= pad <= 16 or last[-pad:] != bytes([pad]) * pad:
        return None
    return keystores._cbc("aes", key, blob[:16], blob[16:])


def _key_forms(seed: bytes):
    """AES-256 (full digest) and AES-128 (first 16 bytes) keys from a SHA-256 seed."""
    return (seed, seed[:16])


# --------------------------------------------------------------------------- KDF method in the dex VM

_INVOKE_OPS = frozenset(range(0x6e, 0x73)) | frozenset(range(0x74, 0x79))


def _invoked(insns: list, widths) -> set:
    """Method indices a code item invokes (invoke-kind and invoke-kind/range), walking instruction
    widths and skipping switch / array payloads."""
    out, i, n = set(), 0, len(insns)
    while i < n:
        u = insns[i]
        if u == 0x0100 and i + 1 < n:                     # packed-switch payload
            i += insns[i + 1] * 2 + 4
            continue
        if u == 0x0200 and i + 1 < n:                     # sparse-switch payload
            i += insns[i + 1] * 4 + 2
            continue
        if u == 0x0300 and i + 3 < n:                     # fill-array-data payload
            size = insns[i + 2] | (insns[i + 3] << 16)
            i += (size * insns[i + 1] + 1) // 2 + 4
            continue
        op = u & 0xFF
        if op in _INVOKE_OPS and i + 1 < n:
            out.add(insns[i + 1])
        i += max(1, widths[op])
    return out


def _load_vm():
    """dex_chain_codec (the lane's Dalvik VM), imported on first use; raises ImportError named."""
    import dex_chain_codec  # noqa: E402  (solvers/mobile-android, on sys.path above)
    return dex_chain_codec


def _kdf_methods(members: dict):
    """([(label, dcc, Dex, method index, param kinds)], note): static methods that call
    ``MessageDigest.digest`` (or call such a method), take 1..MAX_KDF_PARAMS parameters that are all
    String (``L``) or at most one ``int`` (``I``, the PIN), and return an object (``byte[]``).

    ``note`` names why no method is offered when the VM could not be used (import failure, a dex the
    VM cannot read); it is "" when there simply is none."""
    dexes = [n for n in sorted(members) if n.endswith(".dex") and members[n][:4] == b"dex\n"
             and _MD.encode() in members[n]]
    if not dexes:
        return [], ""
    try:
        dcc = _load_vm()
    except Exception as exc:  # no silent fallback: the notes say the VM path did not run, and why
        return [], "dex VM unavailable (%s: %s); KDF methods not evaluated" % (type(exc).__name__, exc)
    found, bad = [], []
    for name in dexes:
        try:
            dx = dcc.Dex(members[name])
            digest = {i for i in range(dx.meth_size) if dx.meth(i) == (_MD, "digest")}
            calls = {m: _invoked(code[2], dcc._W) for m, code in dx.code.items()}
        except Exception as exc:
            bad.append("%s (%s)" % (name, type(exc).__name__))
            continue
        direct = {m for m, inv in calls.items() if inv & digest}
        hop = {m for m, inv in calls.items() if inv & direct} | direct
        for m in sorted(hop):
            shorty = dx.meth_shorty(m) or ""
            params = shorty[1:]
            regs, ins, _insns = dx.code[m]
            if (not shorty or shorty[0] != "L" or not 1 <= len(params) <= MAX_KDF_PARAMS
                    or set(params) - {"L", "I"} or params.count("I") > 1 or ins != len(params)):
                continue                                 # ins == params: static (no `this` register)
            cls, meth = dx.meth(m)
            found.append(("%s->%s" % (cls, meth), dcc, dx, m, params))
    note = ("dex VM could not read %s" % ", ".join(bad)) if bad else ""
    return found[:MAX_KDF_METHODS], note


def _kdf_args(cert_tokens, string_atoms, actions) -> list:
    """The ranked atoms for the non-PIN parameter slots: cert tokens, strings and actions interleaved
    best-first (so the best of each family is in the cut), cut to MAX_KDF_ARGS."""
    fams = [list(dict.fromkeys(cert_tokens)), list(dict.fromkeys(string_atoms)), list(dict.fromkeys(actions))]
    out, i = [], 0
    while any(i < len(f) for f in fams):
        out.extend(f[i] for f in fams if i < len(f))
        i += 1
    return list(dict.fromkeys(out))[:MAX_KDF_ARGS]


def _kdf_calls(params: str, pool: list) -> list:
    """[(pin slot, {slot: atom})]: every placement of the PIN (the ``int`` slot when there is one)
    and of distinct pool atoms in the other slots, ranked by the atoms' ranks."""
    import itertools
    n = len(params)
    slots = [params.index("I")] if "I" in params else list(range(n))
    cand = []
    for p in slots:
        others = [k for k in range(n) if k != p]
        for combo in itertools.permutations(range(len(pool)), len(others)):
            cand.append((sum(combo), p, len(cand), dict(zip(others, (pool[c] for c in combo)))))
    cand.sort(key=lambda c: (c[0], c[2]))
    return [(p, fill) for _r, p, _i, fill in cand]


def _vm_keys(ret):
    """AES keys from a KDF method's return value (a Java byte[] as signed ints): the value itself
    when it is 16/24/32 bytes, and its 32- and 16-byte prefixes."""
    if not isinstance(ret, list) or not ret or not all(isinstance(c, int) and not isinstance(c, bool) for c in ret):
        return ()
    raw = bytes(c & 0xFF for c in ret)
    keys = [raw] if len(raw) in (16, 24, 32) else []
    keys += [raw[:k] for k in (32, 16) if len(raw) > k]
    return tuple(dict.fromkeys(keys))


def _derive_via_vm(kdfs, pool, pin_passes, blobs, ff, meter):
    """(flag, Evidence, note): run each KDF method in the dex VM with every placement of the PIN and
    the ranked atoms, and try the returned key on every blob.  Every VM call and every cipher attempt
    is a trial.  A method the VM declines on its first call is dropped (named in the note)."""
    notes, live = [], []
    for label, dcc, dx, m, params in kdfs:
        calls = _kdf_calls(params, pool)
        if not calls:
            notes.append("%s: no atoms for its %d parameter(s)" % (label, len(params)))
            continue
        vm = dcc.VM(dx)
        p, fill = calls[0]
        try:
            vm.steps, vm.max_steps = 0, KDF_MAX_STEPS
            vm.run(m, [0 if params[k] == "I" else fill.get(k, "0000") for k in range(len(params))])
        except Exception as exc:
            notes.append("%s declined by the dex VM (%s)" % (label, str(exc)[:80] or type(exc).__name__))
            continue
        live.append((label, vm, m, params, calls))
    declined = 0
    for pins in pin_passes:
        for label, vm, m, params, calls in live:
            for p, fill in calls:
                for pin in pins:
                    args = [(int(pin) if params[k] == "I" else pin) if k == p else fill[k]
                            for k in range(len(params))]
                    try:
                        vm.steps, vm.max_steps = 0, KDF_MAX_STEPS
                        keys = _vm_keys(vm.run(m, args))
                    except Exception:
                        keys = ()
                        declined += 1
                    if meter.spend():
                        return None, None, _vm_note(live, notes, declined)
                    for key in keys:
                        for blabel, blob in blobs:
                            pt = _try_gcm(key, blob)
                            mode = "aes-gcm"
                            if pt is None:
                                pt = _try_cbc(key, blob)
                                mode = "aes-cbc"
                            if pt is not None:
                                flags = ff.find_flags(pt)
                                if flags:
                                    shown = ", ".join(("PIN=%s" % pin) if k == p else fill[k] for k in range(len(params)))
                                    ev = Evidence("decrypt", "%s (AES-%d) of %s under key=%s(%s) evaluated in the "
                                                  "dex VM -> %s" % (mode, len(key) * 8, blabel, label, shown, flags[0]))
                                    return flags[0], ev, _vm_note(live, notes, declined)
                            if meter.spend():
                                return None, None, _vm_note(live, notes, declined)
    return None, None, _vm_note(live, notes, declined)


def _vm_note(live, notes, declined) -> str:
    parts = ["%d KDF method(s) evaluated in the dex VM (%s)" % (len(live), ", ".join(x[0] for x in live))] if live else []
    if declined:
        parts.append("%d VM call(s) declined" % declined)
    return "; ".join(parts + notes)


# --------------------------------------------------------------------------- the engine

def _derive_and_try(recipes, pin_passes, blob_groups, ff, meter):
    """Core brute: (flag, Evidence) on the first hard-verified decrypt, else (None, None) with
    ``meter.stop`` set to "budget"/"time" when it was cut short (None when the space was covered).

    ``blob_groups`` are tried in order (base64 string blobs over every recipe and PIN before any raw
    file blob); ``pin_passes`` too (HMAC-gated PINs over every recipe before the full space).
    """
    for blobs in blob_groups:
        if not blobs:
            continue
        for pins in pin_passes:
            if not pins:
                continue
            for before, after in recipes:
                pre = "".join(before).encode("utf-8", "surrogatepass")
                post = "".join(after).encode("utf-8", "surrogatepass")
                for pin in pins:
                    seed = hashlib.sha256(pre + pin.encode() + post).digest()
                    for key in _key_forms(seed):
                        for label, blob in blobs:
                            pt = _try_gcm(key, blob)
                            mode = "aes-gcm"
                            if pt is None:
                                pt = _try_cbc(key, blob)
                                mode = "aes-cbc"
                            if pt is not None:
                                flags = ff.find_flags(pt)
                                if flags:
                                    meter.spend()
                                    recipe = " || ".join(list(before) + ["PIN=%s" % pin] + list(after))
                                    ev = Evidence("decrypt", "%s (AES-%d) of %s under key=SHA256(%s) -> %s" % (
                                        mode, len(key) * 8, label, recipe, flags[0]))
                                    return flags[0], ev
                            if meter.spend():
                                return None, None
    return None, None


def _int_opt(opts, name, default, lo, hi):
    raw = opts.get(name, default)
    try:
        val = int(raw)
    except (TypeError, ValueError):
        raise BadOption("option %s=%r is not an integer" % (name, raw)) from None
    if not lo <= val <= hi:
        raise BadOption("option %s=%d is outside %d..%d" % (name, val, lo, hi))
    return val


def _seconds_opt(opts, name, default, what):
    raw = opts.get(name, default)
    try:
        val = float(raw)
    except (TypeError, ValueError):
        raise BadOption("option %s=%r is not a number of %s seconds" % (name, raw, what)) from None
    if not val >= 0:
        raise BadOption("option %s=%r must be >= 0 (0 = no %s cap)" % (name, raw, what))
    return val


def _options(opts):
    n_pins = _int_opt(opts, "pins", DEFAULT_PINS, 1, 100000)
    budget = _int_opt(opts, "budget", DEFAULT_BUDGET, 1, 10 ** 12)
    time_budget = _seconds_opt(opts, "time_budget", DEFAULT_TIME_BUDGET, "CPU")
    wall_budget = _seconds_opt(opts, "wall_budget", DEFAULT_WALL_BUDGET, "wall-clock")
    return n_pins, budget, time_budget, wall_budget


def solve(challenge_dir, profile, **opts) -> SolverResult:
    """Decrypt the APK's locked flag by extracting its key atoms and bruting the small spaces.

    Options: ``pins`` (PIN space size, default 10000), ``budget`` (max trials, gate HMACs and dex VM
    calls included), ``time_budget`` (CPU seconds, default 200; 0 = no CPU cap), ``wall_budget``
    (wall-clock seconds, default 240, below the 300 s [intake] timeout; 0 = no wall cap),
    ``challenge_id``.  A malformed option is a ``blocked`` naming it.
    """
    return _solve(challenge_dir, profile, None, **opts)


def _solve(challenge_dir, profile, files, **opts) -> SolverResult:
    t0 = _cpu()
    w0 = _wall()
    wall0 = time.monotonic()
    cid = opts.get("challenge_id")
    me = "mobile_android.apk_unlock_crypto"
    challenge_dir = Path(challenge_dir)

    def cost():
        return Cost(seconds=round(time.monotonic() - wall0, 3))

    try:
        _require_crypto()
    except CryptoMissing as exc:
        return SolverResult("blocked", engine=me, challenge_id=cid, notes=str(exc), cost=cost())
    try:
        n_pins, budget, time_budget, wall_budget = _options(opts)
    except BadOption as exc:
        return SolverResult("blocked", engine=me, challenge_id=cid, notes=str(exc), cost=cost())

    packages = _packages(challenge_dir, files)
    if not packages:
        return SolverResult("none", engine=me, challenge_id=cid,
                            notes="no APK/ZIP package in the challenge files", cost=cost())
    loose = _loose_atoms(challenge_dir) if files is None else []

    ff = flagfmt.for_profile(profile)
    meter = _Meter(budget, time_budget, t0, wall_budget, w0)
    notes = []
    space = 0
    capped = []          # packages whose recipe list MAX_RECIPES cut
    n_blob_pkgs = 0
    for name, members, blob, skipped in packages:
        if skipped:
            notes.append("%s: %d member(s) not read (%s)" % (name, len(skipped), ", ".join(skipped[:4])
                                                              + (", ..." if len(skipped) > 4 else "")))
        arsc = _arsc_strings(members)
        dex = _dex_string_list(members)
        strings = list(dict.fromkeys([v for _k, v in arsc] + loose + dex))
        der = _cert_der(members, blob)
        actions = _actions(members)[:MAX_ACTION_ATOMS]
        blobs = _candidate_blobs(members, strings)
        if not blobs:
            notes.append("%s: no ciphertext candidate in %d string(s) / %d member(s)" % (name, len(strings), len(members)))
            continue
        n_blob_pkgs += 1

        blob_set = {d for _l, d in blobs}
        blob_strs = {s for s in strings if (_decode_b64(s) or ("", None))[1] in blob_set}
        templates = _rank_templates([v for _k, v in arsc] + dex)
        digests = _cert_digests(der) if der else []
        cert_tokens = _cert_tokens(templates, digests) if digests else []
        string_atoms = _rank_atoms(arsc, loose, dex, exclude=blob_strs | set(templates))[:MAX_STRING_ATOMS]

        pin_space = _pin_strings(n_pins)
        targets = _hmac_targets([v for _k, v in arsc] + loose + dex)
        mark = meter.trials
        gated = _hmac_gated_pins(targets, string_atoms + cert_tokens, pin_space, meter) if meter.stop is None else []
        gate_hmacs, mark = meter.trials - mark, meter.trials
        pin_passes = ([gated] if gated else []) + [pin_space]   # gated PINs over all recipes first
        recipes, n_recipes = _recipes(cert_tokens, string_atoms, actions)
        if n_recipes > len(recipes):
            capped.append("%s: %d of %d" % (name, len(recipes), n_recipes))
        str_blobs = [b for b in blobs if not b[0].startswith("file:")]
        file_blobs = [b for b in blobs if b[0].startswith("file:")]
        pkg_space = sum(len(p) for p in pin_passes) * len(recipes) * 2 * len(blobs)
        space += pkg_space + (min(len(string_atoms + cert_tokens), MAX_GATE_KEYS) * n_pins if targets else 0)

        flag = ev = None
        kdfs, vm_note = _kdf_methods(members)
        if kdfs and meter.stop is None:              # a KDF the dex states is evaluated before any guess
            pool = _kdf_args(cert_tokens, string_atoms, actions)
            space += sum(len(_kdf_calls(k[4], pool)) for k in kdfs) * sum(len(p) for p in pin_passes) * (1 + 2 * len(blobs))
            flag, ev, vm_note = _derive_via_vm(kdfs, pool, pin_passes, str_blobs + file_blobs, ff, meter)
        if vm_note:
            notes.append("%s: %s" % (name, vm_note))
        vm_trials, mark = meter.trials - mark, meter.trials
        if flag is None and meter.stop is None:
            flag, ev = _derive_and_try(recipes, pin_passes, [str_blobs, file_blobs], ff, meter)
        notes.append("%s: %d blob(s) (%d string, %d file), %d recipe(s)%s, %d PIN(s)%s, %d atom(s), %s, "
                     "%d gate HMACs, %d dex VM trials, %d cipher trials, %d trials" % (
                         name, len(blobs), len(str_blobs), len(file_blobs), len(recipes),
                         " (capped at %d of %d)" % (MAX_RECIPES, n_recipes) if n_recipes > len(recipes) else "",
                         len(set(gated) | set(pin_space)),
                         " (%d HMAC-gated first)" % len(gated) if gated else "",
                         len(string_atoms), "cert" if der else "no cert", gate_hmacs, vm_trials,
                         meter.trials - mark, meter.trials))
        if flag is not None:
            ev = Evidence(ev.kind, ev.detail, path=name)
            return SolverResult("solved", flags=(flag,), evidence=(ev,), engine=me, challenge_id=cid,
                                notes="; ".join(notes), cost=cost())
        if meter.stop is not None:
            why = {"budget": "trial budget %d" % budget, "time": "CPU time budget %gs" % time_budget,
                   "wall": "wall-clock budget %gs" % wall_budget}[meter.stop]
            return SolverResult("unsure", engine=me, challenge_id=cid, cost=cost(),
                                notes="; ".join(notes) + "; search incomplete: %s exhausted after %d trials of a "
                                      "space of at least %d -- nothing verified so far; raise budget/time_budget/"
                                      "wall_budget or read the KDF from the decompiled code" % (why, meter.trials, space))

    if not n_blob_pkgs:
        return SolverResult("none", engine=me, challenge_id=cid, cost=cost(),
                            notes="; ".join(notes) + "; no ciphertext candidate in any of %d package(s): nothing "
                                  "to decrypt" % len(packages))
    if capped:
        return SolverResult("unsure", engine=me, challenge_id=cid, cost=cost(),
                            notes="; ".join(notes) + "; search incomplete: searched the capped space only -- the "
                                  "composition recipes were cut by MAX_RECIPES=%d (%s); nothing verified in the "
                                  "recipes kept; read the KDF from the decompiled code" % (MAX_RECIPES, "; ".join(capped)))
    return SolverResult("none", engine=me, challenge_id=cid,
                        notes="; ".join(notes) + "; searched the whole bounded space: no key composition "
                              "decrypted a blob to a flag (the composition may need a model read of the "
                              "decompiled code)",
                        cost=cost())


__all__ = ["solve", "main", "_cert_der", "_v2_cert_der", "_candidate_blobs", "_recipes", "_kdf_methods"]

_USAGE = "usage: apk_unlock_crypto.py <challenge dir | apk> [--event <slug>] [--opt key=value]..."


def main(argv) -> int:
    from ctf import event

    args = list(argv)
    target = slug = None
    opts = {}
    while args:
        a = args.pop(0)
        if a in ("--event", "--opt"):
            if not args:
                print("apk_unlock_crypto.py: %s needs a value\n%s" % (a, _USAGE), file=sys.stderr)
                return 2
            val = args.pop(0)
            if a == "--event":
                slug = val
            elif "=" not in val:
                print("apk_unlock_crypto.py: --opt %r is not key=value\n%s" % (val, _USAGE), file=sys.stderr)
                return 2
            else:
                k, v = val.split("=", 1)
                opts[k] = v
        elif a.startswith("-") or target is not None:
            print("apk_unlock_crypto.py: unexpected argument %r\n%s" % (a, _USAGE), file=sys.stderr)
            return 2
        else:
            target = Path(a)
    if target is None or not target.exists():
        print(_USAGE, file=sys.stderr)
        return 2
    try:
        profile = event.load(slug) if slug else event.current()
    except event.EventError as exc:
        print("apk_unlock_crypto.py: no event profile (%s); pass --event <slug>" % exc, file=sys.stderr)
        return 2
    if target.is_dir():
        res = solve(target, profile, **opts)
    else:  # one APK named: read that file only, never its siblings or the folder it sits in
        res = _solve(target.parent, profile, [target], **opts)
    print(res.to_json())
    return 0 if res.status in ("solved", "candidate") else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
