#!/usr/bin/env python3
"""Toolkit `modern_crypto`: RSA/Paillier/Rabin from parameters, XOR and stream reuse, ciphers with a stated key,
JWT, ECDSA nonce reuse, ECB and generator checks. The maths is solvers/common/modern_crypto.py.

  .venv/bin/python solvers/toolkits/modern_crypto.py <file>... [--budget SECONDS]

prints a triage of the files: the keys and labelled parameters found, whether they agree, what
attack is proven and the plaintext it gives, JWTs, hash-shaped strings, repeated cipher blocks.
Offline; no Game Master request.

For an agent, by hand:  material(files), solve_rsa(M, deadline), solve_sym(M, q), solve_xor(M, q),
solve_ecc(M, q) (weak-curve private scalar, proven d*G==Q), and everything in the library (`lib`):
lib.read_params, lib.read_keys, lib.rsa_attack, ...; the weak-curve maths is `eccw`
(solvers/common/ecc_weak.py): eccw.recover_scalar(p, a, b, G, Q, order).

signals(questions, files) -> 0..1   how strongly a set looks like this category (cheap)
solve_set(questions, files, ctx)    the runner contract (tools/run.py, tools/verify.py)

What solve_set answers, and how sure (AGENTS.md, "Uncertain answers"):

  plain   a fact proven from the bytes in a form the question itself fixes: a plaintext that
          matches the answer_format's own pattern, a number where the kind is `integer` (or the
          pattern or the words allow one form only), md5/sha of a proven plaintext when asked
  unsure  labels.pick('modern_crypto.<field>/<shape>', ...) for a proven fact whose spelling or
          form is not judged: a plaintext with no pattern (text / flag / inner), a number that may
          be decimal or hex, d modulo phi or lambda, the name of the attack, the block mode, the
          hash type (by length: never more than a pick), a JWT claim; every discrete-log value
          (Day 27: an exponent, a DH shared secret, an ElGamal plaintext) is a candidate pick
          under a key of its own instance, never plain (_dlog_answer, KB-10 fix round 4)
  None    everything else. An attack answers only when its precondition is proven (exact root,
          gcd > 1, a convergent that factors n, factors that multiply to n, a nonce that
          reproduces r, a generator that reproduces an output it was not built from); written
          parameters that contradict each other are answered only after the ONE single-digit
          repair that makes them agree; a search (single-byte XOR, a crib, the readings of a
          written key) answers only when exactly one candidate passes the question's own proof.
          Stated-key classical ciphers are unsure-only; incomplete/conflicting tables are None.

Nothing slow: one set has BUDGET seconds (0.8; ctx["budget"] or $CTF_TK_BUDGET changes it),
shared by every attack, and an attack that runs out of it is None. Supplied Paillier/Rabin moduli
are capped at 2,048 bits before private-key multiplication, primality testing or exponentiation.
"""
import base64
import binascii
import bisect
import hashlib
import importlib.util
import json
import math
import os
import re
import sys
import time
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import env as ctf_env, flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import env as ctf_env, flagfmt

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
KEY = "modern_crypto"
BUDGET = 0.8
LATTICE_BUDGET = 60.0           # each lattice RSA attack set (Day 26) is capped at this many seconds
HNP_BUDGET = 2.5                # the ECDSA HNP lattice runs at most once per set
# Supplied private-key operations use Python's non-interruptible modular exponentiation.  A
# deadline check alone therefore cannot bound one hostile operation; 2,048 bits keeps a single
# pure-Python primality/modexp step comfortably inside the toolkit's 0.8 s set budget while still
# accepting the standard-size static CTF keys this reader is intended to solve.
PAILLIER_MAX_MODULUS_BITS = 2048
RABIN_MAX_MODULUS_BITS = 2048
SUPPLIED_KEY_OPERATION_RESERVE = 0.10
ARROW = " -> "
SENTINEL = "??"
MAX_OPTIONS = 12
MAX_TEXT = 512 * 1024           # a text file read for parameters
MAX_BLOB = 1024 * 1024          # a file tried as a ciphertext
MAX_FILES = 64


def _load(name: str, alias: str):
    if alias in sys.modules:
        return sys.modules[alias]
    spec = importlib.util.spec_from_file_location(alias, COMMON / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[alias] = mod
    spec.loader.exec_module(mod)
    return mod


lib = _load("modern_crypto", "modern_crypto_lib")
sss = _load("shamir_totp", "shamir_totp_lib")       # Shamir SSS + TOTP/HOTP (offline maths, no network)
try:
    eccw = _load("ecc_weak", "ecc_weak_lib")        # weak-curve private-scalar recovery
except Exception:               # pragma: no cover - the weak-curve answers are simply skipped
    eccw = None
try:
    labels = _load("labels", "labels")
except Exception:               # pragma: no cover
    labels = None


def _load_here(name: str, alias: str):
    """A module beside this one (solvers/toolkits/), by file path."""
    if alias in sys.modules:
        return sys.modules[alias]
    spec = importlib.util.spec_from_file_location(alias, HERE / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[alias] = mod
    spec.loader.exec_module(mod)
    return mod


try:
    classical = _load_here("classical", "classical_tk")     # backlog row 88: the classical half
except Exception:               # pragma: no cover - classical answers are simply skipped
    classical = None


try:
    rsal = _load("rsa_lattice", "rsa_lattice_lib")          # day26: Coppersmith, partial prime, Boneh-Durfee, ROCA
except Exception:               # pragma: no cover - the lattice attacks are simply skipped
    rsal = None

try:
    dlog = _load("dlog", "dlog_lib")                        # day27: discrete logs in Z_p (ElGamal / Diffie-Hellman)
except Exception:               # pragma: no cover - the discrete-log answers are simply skipped
    dlog = None

try:
    depth = _load("crypto_depth", "crypto_depth")           # wave124: GCM nonce-reuse + ECDSA HNP
except Exception:               # pragma: no cover - the two depth attacks are simply skipped
    depth = None


def _pick(key: str, options):
    """labels.pick; the same wire form written here while labels.py does not know the lane
    `modern_crypto` (gm.session() strips every `??` value, so it can never be sent as an answer)."""
    pairs, seen = [], set()
    for o in options or []:
        name, value = (o if isinstance(o, (tuple, list)) and len(o) == 2 else (o, o))
        if value is None or value == "" or name in seen:
            continue
        seen.add(name)
        pairs.append((str(name), value))
    pairs = pairs[:MAX_OPTIONS]
    if not pairs:
        return None
    if labels is not None:
        try:
            return labels.pick(key, pairs)
        except ValueError:
            pass                # the lane is not registered: nothing is known about the key
    return SENTINEL + json.dumps({"k": key.lower(), "o": [[n, v] for n, v in pairs]}, separators=(",", ":"))


def _candidates(key: str, options):
    """labels.candidates for a fact the bytes narrow to a few DIFFERENT values with nothing proving
    which one the judge asks (backlog row 346): never plain before a judge-accepted name, so no
    accepted name can inherit to a different fact under a shared key. The same wire form is written
    here while labels.py does not know the lane (the key ends in CANDIDATE_MARK so every runner
    reads it as a candidate pick)."""
    pairs, seen = [], set()
    for o in options or []:
        name, value = (o if isinstance(o, (tuple, list)) and len(o) == 2 else (o, o))
        if value is None or value == "" or name in seen:
            continue
        seen.add(name)
        pairs.append((str(name), value))
    pairs = pairs[:MAX_OPTIONS]
    if not pairs:
        return None
    if labels is not None:
        try:
            return labels.candidates(key, pairs)
        except ValueError:
            pass                # the lane is not registered: nothing is known about the key
    ckey = key.lower()
    if not ckey.endswith("#candidates"):
        ckey += "#candidates"
    return SENTINEL + json.dumps({"k": ckey, "o": [[n, v] for n, v in pairs]}, separators=(",", ":"))


# ---- the material of one set -------------------------------------------------------------------------

_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"7z\xbc\xaf", b"\x7fELF", b"MZ", b"\x89PNG", b"\xff\xd8\xff", b"%PDF", b"GIF8",
          b"\x1f\x8b", b"Rar!", b"dex\n", b"SQLite", b"\xd0\xcf\x11\xe0", b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe", b"\x00asm",
          b"HCFG", b"BZh", b"\xfd7zXZ", b"RIFF", b"OggS", b"ID3")


def _unique(files: dict) -> list:
    seen, out = set(), []
    for key in sorted(files, key=lambda k: (ARROW not in k, k)):
        data = files[key]
        if isinstance(data, (bytes, bytearray)) and id(data) not in seen:
            seen.add(id(data))
            out.append((key.split(ARROW)[-1], bytes(data)))
    return out[:MAX_FILES]


def _text(data: bytes):
    if len(data) > MAX_TEXT or not data:
        return None
    try:
        text = data.decode("utf-16") if data[:2] in (b"\xff\xfe", b"\xfe\xff") else data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None
    return text if all(c.isprintable() or c in "\r\n\t" for c in text) else None


def _int_lists(text: str) -> list:
    """Lists of integers a text holds: runs of lines that are one integer each, and [..] lists."""
    out, run = [], []
    for line in text.splitlines():
        s = line.strip().rstrip(",")
        if re.fullmatch(r"\d{1,80}", s):
            run.append(int(s))
        else:
            if len(run) >= 3:
                out.append(run)
            run = []
    if len(run) >= 3:
        out.append(run)
    for m in re.finditer(r"\[\s*(\d{1,80}(?:\s*,\s*\d{1,80}){2,})\s*,?\s*\]", text):
        out.append([int(v) for v in re.findall(r"\d+", m.group(1))])
    return out


class Material:
    """What a set's files (and one question's own text) hold: keys, labelled parameters, labelled
    fields, tokens, integer lists, and the byte strings that may be ciphertexts."""

    def __init__(self, files: dict, extra_text: str = ""):
        self.texts, self.bins, self.keys, self.jwts, self.int_lists = [], [], [], [], []
        self.raw_texts = []         # text files as bytes: an XOR of text with one byte is often still text
        self.params = lib.Params()
        self.fields = {}
        self.names = []
        self.cache = {}
        holders = {k.split(ARROW)[0] for k in files if ARROW in k}
        items = _unique(files)
        self.members = list(items)      # every delivered member (name, bytes), magic-header files too
        if extra_text:
            items.append(("<question>", extra_text.encode("utf-8")))
        for name, data in items:
            self.names.append(name)
            if name in holders or Path(name).name in holders or any(data.startswith(m) for m in _MAGIC):
                continue
            keys = [k for k in lib.read_keys(data)] if (b"-----BEGIN" in data or data[:1] in (b"\x30", b"{") or b"ssh-" in data[:64]
                                                        or b"ecdsa-sha2" in data[:64]) and len(data) <= MAX_TEXT else []
            for k in keys:
                self.keys.append((name, k))
            text = _text(data)
            if text is None:
                if not keys and len(data) <= MAX_BLOB and name != "<question>":
                    self.bins.append((name, data))
                continue
            if keys and "-----BEGIN" not in text:
                continue                # a JWK or an SSH key line: its numbers are the key's, read above
            # what stands beside a PEM block in the same file is read; the block itself is not
            text = re.sub(r"-----BEGIN ([A-Z0-9 ]+)-----.*?-----END \1-----", "", text, flags=re.S)
            if not text.strip():
                continue
            self.texts.append((name, text))
            if name != "<question>" and not keys:
                self.raw_texts.append((name, data))
            self.jwts += lib.find_jwts(text)
            self.params = self.params.merged(lib.read_params(text, name))
            for k, vals in lib.read_fields(text, name).items():
                self.fields.setdefault(k, []).extend(vals)
            if name != "<question>":
                self.int_lists += _int_lists(text)
            if name != "<question>" and not keys:
                compact = re.sub(r"\s+", "", text)
                if len(compact) >= 8 and not _int_lists(text) and (re.fullmatch(r"(?:0[xX])?[0-9a-fA-F]+", compact) and len(compact) % 2 == 0
                                          or re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", compact) and not compact.isdigit()):
                    for reading, b in lib.blobs(compact):
                        if reading != "raw":
                            self.bins.append((f"{name} ({reading})", b))
        for k, v in question_fields(extra_text):
            self.fields.setdefault(k, [])
            if v not in self.fields[k]:
                self.fields[k].append(v)
        self.jwts = list(dict.fromkeys(self.jwts))
        self.all_text = "\n".join(t for _, t in self.texts)

    # labelled fields, by the last words of the name -------------------------------------------------
    def field(self, *suffixes, exclude=()) -> list:
        slot = ("field", suffixes, tuple(exclude))
        if slot not in self.cache:
            self.cache[slot] = self._field(suffixes, exclude)
        return list(self.cache[slot])

    def _field(self, suffixes, exclude) -> list:
        out = []
        for name, vals in self.fields.items():
            if any(name == s or name.endswith("_" + s) for s in suffixes) and not any(x in name for x in exclude):
                out += vals
        return list(dict.fromkeys(out))

    def hint(self, rx: str) -> bool:
        blob = " ".join(self.names) + " " + " ".join(self.fields) + " " + self.all_text[:20000]
        return re.search(rx, blob, re.I) is not None


_QF_NAME = r"(?<![A-Za-z0-9_])(key|iv|nonce|password|passphrase|secret)(?![A-Za-z0-9_])"
_QF_QUOTED = re.compile(_QF_NAME + r"(?:\s+(?:is|was|of|being|used is))?\s*[:=]?\s*(?:\"([^\"\n]{1,256})\"|'([^'\n]{1,256})'|`([^`\n]{1,256})`)", re.I)
_QF_BARE = re.compile(_QF_NAME + r"\s*(?:[:=]|\bis\b)\s*([^\n\"'`?;]{1,120}?)(?=\s*(?:[?;]|\.(?:\s|$)|$|,\s*(?:and\s+)?(?:the\s+)?(?:key|iv|nonce|password)\b))", re.I)
_QF_ZERO_IV = re.compile(r"(?<!non-)(?<!non )(?<!not )(?<!no )\b(?:all[- ]zero|zero|null|zeroed)\s+(?:iv|nonce|initiali[sz]ation vector)\b"
                         r"|\b(?:iv|nonce|initiali[sz]ation vector)\s+"
                         r"(?:is|of|was)?\s*(?:all[- ]?)?(?:(?:sixteen|eight|16|8)\s+)?(?:zero(?:e?s)?|null)(?:\s+bytes)?\b(?!-)", re.I)
_QF_BOTH = re.compile(r"\bkey\s+and\s+(?:the\s+)?(iv|nonce)\b(?:\s+(?:are|is))?(?:\s+both)?\s*[:=]?\s*([^\n\"'`?;]{1,120}?)(?=\s*(?:[?;]|\.(?:\s|$)|$))", re.I)


def question_fields(text: str) -> list:
    """[(field, value as written)] of what a question states in its own words: a quoted key, IV,
    nonce, password or secret (`under the key "YELLOW SUBMARINE"`), one written after a colon, an
    equals sign or `is` up to the end of its clause (`key: 42 6c 6f 77`, `iv = 000102`), `key and
    IV are both ...`, and an IV said to be all zeros (written here as sixteen zero bytes in hex;
    a cipher of 8-byte blocks takes the first eight). Which reading of a value is the key (hex,
    base64, the text) is settled by the decryption's own proof, as for a key in a file."""
    out = []
    if not text:
        return out
    for m in _QF_QUOTED.finditer(text):
        out.append((m.group(1).lower(), next(v for v in m.groups()[1:] if v is not None)))
    for m in _QF_BARE.finditer(text):
        v = m.group(2).strip()
        if v and not re.match(r"(?:the|a|an|not|unknown|used|given|stated|of|is|was|in|that|which)\b", v, re.I):
            out.append((m.group(1).lower(), v))
    for m in _QF_BOTH.finditer(text):
        v = m.group(2).strip()
        if v:
            out += [("key", v), (m.group(1).lower(), v)]
    if _QF_ZERO_IV.search(text):
        out.append(("iv", "00" * 16))
    return list(dict.fromkeys(out))


def material(files: dict, extra_text: str = "") -> Material:
    return Material(files, extra_text)


# ---- the question: what is asked, and what proves a plaintext ----------------------------------------

def _fmt(q) -> dict:
    f = q.get("answer_format")
    return f if isinstance(f, dict) else {}


def _words(q) -> str:
    f = _fmt(q)
    return " ".join(str(x or "") for x in (q.get("question"), f.get("syntax")))


def _qtext(q) -> str:
    return " ".join(str(q.get("question") or "").split())


_JUNK = ("Zq7 xK2,vL9!", "the quick brown fox 0123456789 abcdef ABCDEF", "a1-b2_c3", "Hello, World", "x")
_FLAG = flagfmt.SHAPE_TEXT    # any-prefix shape (ctf.flagfmt.shape): the question states which prefixes count
# The shape a "flag" ANSWER FORM is cut from: never a CSS rule (btn{color:red}) unless it is the event's
# own format (R-16). _FLAG stays the broad seen scan (a flag inside a text leaves a choice).
_FLAG_FORM = flagfmt.Filtered(flagfmt.SHAPE_TEXT, flagfmt.shape_reportable, "reportable")


def _flag_prefix(m) -> str:
    return m.group(0).split("{", 1)[0]


def _flag_inner(m) -> str:
    return m.group(0).split("{", 1)[1][:-1]


class Proof:
    """What the question itself says a right plaintext looks like.

    pattern   answer_format.pattern (or .regex). `specific` when it refuses ordinary text.
    grammar   a flag form the question's words show (`flag{...}`): prefix and braces
    cribs     text the question says the plaintext starts with or contains
    """

    def __init__(self, q):
        f = _fmt(q)
        rx = f.get("pattern") or f.get("regex")
        self.pattern = self.inner = None
        self.specific = False
        if isinstance(rx, str) and rx.strip():
            try:
                self.pattern = re.compile(rx)
                core = re.sub(r"^(?:\^|\\A)", "", re.sub(r"(?:\$|\\Z|\\z)$", "", rx))
                self.inner = re.compile(core)
                self.specific = not any(self.inner.search(j) for j in _JUNK)
            except re.error:
                self.pattern = self.inner = None
        words = _words(q)
        self.prefixes = list(dict.fromkeys(m.group(1) for m in re.finditer(r"(?<![A-Za-z0-9_])([A-Za-z][A-Za-z0-9_]{1,15})\{", words)))
        self.starts = [next(g for g in m.groups() if g is not None) for m in re.finditer(
            r"\b(?:starts?|begins?|beginning|prefixed)\s+with\s+(?:\"([^\"]{2,80})\"|'([^']{2,80})'|`([^`]{2,80})`)", words, re.I)]
        self.signature = (rx if self.pattern is not None else None, words if re.search(r"\{|[`'\"]", words) else "")
        self.contains = [m.group(1) for m in re.finditer(r"\b(?:contains?|includes?|crib|known[- ]plaintext)\s*(?:is|of|:|the (?:string|text|word|phrase))?\s*[`'\"]([^`'\"]{3,80})[`'\"]", words, re.I)]

    @property
    def cribs(self) -> list:
        """(crib bytes, at the start only) for a search."""
        out = [(s.encode(), True) for s in self.starts] + [(s.encode(), False) for s in self.contains]
        out += [((p + "{").encode(), False) for p in self.prefixes]
        return out

    @staticmethod
    def readable(pt: bytes):
        try:
            text = pt.decode("utf-8")
        except UnicodeDecodeError:
            return None
        if not text.strip() or not all(c.isprintable() or c in "\r\n\t" for c in text):
            return None
        return text

    def judge(self, pt: bytes):
        """None, or {text, value, level, plain}: text the stripped plaintext; value what the
        question's form picks out of it; level 3 a specific pattern, 2 a crib or the stated
        grammar, 1 readable text only; plain True when the pattern itself fixes the value."""
        text = self.readable(pt)
        if text is None:
            return None
        s = text.strip()
        level, value, plain = 1, s, False
        if self.pattern is not None:
            if self.pattern.fullmatch(s):
                # a pattern that ordinary text passes does not say whether the whole text or the
                # flag inside it is wanted: plain only when there is no such choice
                inside = {m.group(0) for m in _FLAG.finditer(s)} - {s}
                value, plain, level = s, self.specific or not inside, 3 if self.specific else 1
            else:
                found = list(dict.fromkeys(m.group(0) for m in self.inner.finditer(text) if m.group(0)))
                if len(found) == 1 and self.specific and self.pattern.fullmatch(found[0]):
                    # a greedy pattern can run past the flag it was written for (`flag\{.*\}` over
                    # "flag{a} and {b}"): a flag strictly inside what it took leaves a choice
                    inside = {m.group(0) for m in _FLAG.finditer(found[0])} - {found[0]}
                    value, plain, level = found[0], not inside, 3
                else:
                    return None         # the question's own form refuses this text
        if level < 2:
            if any(s.startswith(c) for c in self.starts) or any(c in s for c in self.contains):
                level = 2
            flags = [m for m in _FLAG.finditer(s) if _flag_prefix(m) in self.prefixes]
            if len({m.group(0) for m in flags}) == 1:
                level = 2
        return {"text": s, "value": value, "level": level, "plain": plain, "raw": pt}


def _one_flag(text: str):
    """(flag, inside) when the text holds exactly one distinct flag-shaped value that may be offered
    as a flag answer (never a CSS rule, _FLAG_FORM), else None."""
    flags = list(dict.fromkeys(m.group(0) for m in _FLAG_FORM.finditer(text)))
    if len(flags) != 1:
        return None
    return flags[0], _flag_inner(_FLAG_FORM.search(text))


def _options(found: dict, proof: Proof) -> list:
    """The forms one proven plaintext may be asked in, best first: the flag in it, the whole
    text, the flag's inside."""
    s = found["text"]
    one = _one_flag(s)
    out = []
    if one is not None:
        flags, inner = [one[0]], one[1]
        if flags[0] != s:
            out.append(("flag", flags[0]))
        out.append(("text", s))
        out.append(("flag_inner", inner))
    else:
        out.append(("text", s))
    return out


_HASHED = re.compile(r"\b(md5|sha-?1|sha-?256|sha-?512)\b(?:\s+(?:hash|sum|digest|checksum|hex ?digest))?\s*(?:\(|of|for)\s*(?:the\s+)?"
                     r"(?:(?:decrypted|recovered|decoded|resulting|original)\s+)?(plaintext|message|flag|secret|text|result|answer|key)", re.I)


def _finish(q, key: str, found: dict, proof: Proof):
    """The answer for one proven plaintext: its hash when the question asks for that, the plain
    value when the pattern fixes it, else an unsure pick over its forms."""
    words = _words(q)
    m = _HASHED.search(words)
    if m and m.group(2).lower() != "key":
        algo = m.group(1).lower().replace("-", "")
        opts = _options(found, proof)
        forms = [(name, hashlib.new(algo, v.encode("utf-8")).hexdigest()) for name, v in opts if name != "flag_inner"]
        if found["raw"] != found["text"].encode("utf-8"):
            forms.append(("raw_bytes", hashlib.new(algo, found["raw"]).hexdigest()))
        if re.search(r"\bupper-?case\b", words, re.I):
            forms = [(n, v.upper()) for n, v in forms]
        forms = [(n, v) for n, v in forms if _fits(q, v)]
        if len({v for _, v in forms}) == 1:
            return forms[0][1]
        return _pick(f"{KEY}.plaintext_hash/{algo}", forms)
    if found["plain"]:
        return found["value"]
    return _pick(key, [(n, v) for n, v in _options(found, proof) if _fits(q, v)])


def _fits(q, value: str) -> bool:
    f = _fmt(q)
    rx = f.get("pattern") or f.get("regex")
    if isinstance(rx, str) and rx.strip():
        try:
            return re.fullmatch(rx, str(value)) is not None
        except re.error:
            return False
    return True


def _field_ints(M, name: str) -> list:
    """Every value written under a generic field name (read_fields lowercases names and joins
    spaces/hyphens with '_'), parsed as a decimal or 0x-hex integer. Used for generator parameters
    read.py's RSA-style param reader does not keep (a PCG stream increment/multiplier, a truncation
    shift). A value that is not a clean integer literal is skipped."""
    out = []
    for raw in M.fields.get(name, []):
        s = str(raw).strip().strip("'\"")
        try:
            out.append(int(s, 0) if s[:2].lower() in ("0x", "0o", "0b") else int(s))
        except (ValueError, IndexError):
            continue
    return out


def _int_answer(q, key: str, value: int, unverified: bool = False, extra=()):
    """A proven integer in the form the question fixes: plain decimal for kind `integer`, plain
    when the pattern or the words leave one form, else a pick over decimal and hex forms."""
    if value is None:
        return None
    f = _fmt(q)
    kind, words = str(f.get("kind") or ""), _words(q)
    forms = [("decimal", str(value)), ("hex", f"{value:x}"), ("0x_hex", f"0x{value:x}"), ("hex_upper", f"{value:X}")] + list(extra)
    stated = False
    has_pattern = isinstance(f.get("pattern") or f.get("regex"), str)
    if has_pattern:
        forms = [(n, v) for n, v in forms if _fits(q, v)]
    if kind == "integer" or re.search(r"\b(?:decimal|base[- ]?10|as an integer|as a number)\b", words, re.I):
        forms, stated = [(n, v) for n, v in forms if n == "decimal"], True
    elif re.search(r"\bhex(?:adecimal)?\b", words, re.I):
        forms = [(n, v) for n, v in forms if n != "decimal"]
        if re.search(r"\b0x", words):
            forms, stated = [(n, v) for n, v in forms if n == "0x_hex"], True
        elif re.search(r"\bupper-?case\b", words, re.I):
            forms = [(n, v) for n, v in forms if n == "hex_upper"]
    distinct = list(dict.fromkeys(v for _, v in forms))
    if not distinct:
        return None
    if len(distinct) == 1 and (stated or has_pattern) and not unverified:
        return distinct[0]
    return _pick(key, forms)


def _text_answer(q, key: str, value: str, extra=()):
    proof = Proof(q)
    if proof.pattern is not None:
        if not proof.pattern.fullmatch(value):
            alt = [(n, v) for n, v in extra if proof.pattern.fullmatch(str(v))]
            return _pick(key, alt) if alt else None
        if proof.specific:
            return value
    return _pick(key, [("raw", value)] + [(n, v) for n, v in extra if _fits(q, v)])


# ---- supplied-key Paillier and Rabin ---------------------------------------------------------------

_SUPPLIED_KEY_MR_BASES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37,
                          41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89)


def _before_deadline(deadline) -> bool:
    return deadline is None or time.monotonic() < deadline


def _room_for_supplied_key_operation(deadline) -> bool:
    """Leave enough wall time for one capped, non-interruptible integer operation."""

    return deadline is None or deadline - time.monotonic() >= SUPPLIED_KEY_OPERATION_RESERVE


def _supplied_key_prime(value: int, deadline=None):
    """The common library's prime tests with a deadline between bounded modexps.

    The installed gmpy2 30-round test is preserved and a positive result is also checked with
    the common library's 24 fixed Miller-Rabin bases.  When gmpy2 is absent or unusable, the
    fixed-base pass is the same fallback as ``lib.is_prime``, but interruptible between its
    modular exponentiations.  Callers apply the bit caps before entering here.
    """

    if not isinstance(value, int) or isinstance(value, bool) or value < 2:
        return False
    if not _before_deadline(deadline):
        return None
    for small in _SUPPLIED_KEY_MR_BASES:
        if value % small == 0:
            return value == small
    native = getattr(lib, "gmpy2", None)
    if native is not None:
        if not _room_for_supplied_key_operation(deadline):
            return None
        try:
            native_result = bool(native.is_prime(value, 30))
        except Exception:
            native_result = None
        if not _before_deadline(deadline):
            return None
        if native_result is False:
            return False
    d, shifts = value - 1, 0
    while d % 2 == 0:
        d //= 2
        shifts += 1
    for base in _SUPPLIED_KEY_MR_BASES:
        if not _room_for_supplied_key_operation(deadline):
            return None
        witness = pow(base, d, value)
        if not _before_deadline(deadline):
            return None
        if witness in (1, value - 1):
            continue
        for _ in range(shifts - 1):
            if not _room_for_supplied_key_operation(deadline):
                return None
            witness = witness * witness % value
            if witness == value - 1:
                break
        else:
            return False
    return True


def _one_material_int(M: Material, *names):
    """One clean integer written under any of *names*, or None on disagreement."""

    values = []
    for name in names:
        if name in M.params:
            values.extend(M.params.many(name))
        values.extend(_field_ints(M, name))
    values = list(dict.fromkeys(v for v in values if isinstance(v, int) and not isinstance(v, bool)))
    return values[0] if len(values) == 1 else None


def _int_plaintext_answer(q, key: str, value: int, proof: Proof):
    """Render one mathematically proven message without guessing its author's form."""

    if str(_fmt(q).get("kind") or "") == "integer":
        return _int_answer(q, key, value)
    width = max(1, (value.bit_length() + 7) // 8)
    found = proof.judge(value.to_bytes(width, "big"))
    if found is not None:
        return _finish(q, key, found, proof)
    return _int_answer(q, key, value)


def _paillier_plain(M: Material, deadline=None):
    """Decrypt a Paillier ciphertext only from a coherent supplied private key.

    Either the prime factors or lambda must be present.  Every supplied
    relation (including mu when present) is cross-checked; ``g = n + 1`` is
    never assumed.
    """

    if not _before_deadline(deadline):
        return None
    slot = "supplied_paillier_plain"
    if slot in M.cache:
        return M.cache[slot]

    n = _one_material_int(M, "n", "modulus")
    g = _one_material_int(M, "g", "generator")
    c = _one_material_int(M, "c", "ciphertext", "ct")
    p = _one_material_int(M, "p", "prime_p", "prime1")
    qv = _one_material_int(M, "q", "prime_q", "prime2")
    supplied_lam = _one_material_int(M, "lambda", "lambda_n", "private_lambda")
    supplied_mu = _one_material_int(M, "mu", "private_mu")
    if not _before_deadline(deadline) or any(v is None for v in (n, g, c)) or n <= 2:
        return None
    if n.bit_length() > PAILLIER_MAX_MODULUS_BITS:
        return None
    if (g <= 0 or g.bit_length() > 2 * PAILLIER_MAX_MODULUS_BITS
            or c < 0 or c.bit_length() > 2 * PAILLIER_MAX_MODULUS_BITS):
        return None
    # Check every attacker-controlled exponent/factor before multiplication or pow.  For a valid
    # Paillier key lambda and mu are both positive and below n; g and c are below n^2.
    if supplied_lam is not None and not (0 < supplied_lam < n):
        return None
    if supplied_mu is not None and not (0 < supplied_mu < n):
        return None
    n2 = n * n
    if not (0 < g < n2 and 0 <= c < n2) or math.gcd(c, n) != 1:
        return None
    lam = supplied_lam
    if p is not None or qv is not None:
        if (p is None or qv is None or p <= 1 or qv <= 1 or p == qv
                or p.bit_length() > PAILLIER_MAX_MODULUS_BITS
                or qv.bit_length() > PAILLIER_MAX_MODULUS_BITS
                or not _before_deadline(deadline) or p * qv != n):
            return None
        if _supplied_key_prime(p, deadline) is not True or _supplied_key_prime(qv, deadline) is not True:
            return None
        derived = math.lcm(p - 1, qv - 1)
        if lam is not None and lam != derived:
            return None
        lam = derived
    if lam is None or not (0 < lam < n) or not _room_for_supplied_key_operation(deadline):
        return None
    u = pow(g, lam, n2)
    if not _before_deadline(deadline) or (u - 1) % n:
        return None
    l_of_g = (u - 1) // n
    if not _room_for_supplied_key_operation(deadline):
        return None
    mu = lib.inverse(l_of_g % n, n)
    if not _before_deadline(deadline) or mu is None or (supplied_mu is not None and supplied_mu != mu):
        return None
    if not _room_for_supplied_key_operation(deadline):
        return None
    v = pow(c, lam, n2)
    if not _before_deadline(deadline) or (v - 1) % n:
        return None
    message = ((v - 1) // n * mu) % n
    if not _before_deadline(deadline):
        return None
    M.cache[slot] = message
    return message


def _paillier_answer(q, M: Material, proof: Proof, deadline=None):
    message = _paillier_plain(M, deadline)
    if message is None or not _before_deadline(deadline):
        return None
    return _int_plaintext_answer(q, f"{KEY}.plaintext/paillier", message, proof)


def _rabin_roots(M: Material, deadline=None):
    """The verified roots of a supplied Blum-integer Rabin ciphertext."""

    if not _before_deadline(deadline):
        return None
    slot = "supplied_rabin_roots"
    if slot in M.cache:
        return M.cache[slot]

    n = _one_material_int(M, "n", "modulus")
    c = _one_material_int(M, "c", "ciphertext", "ct")
    p = _one_material_int(M, "p", "prime_p", "prime1")
    qv = _one_material_int(M, "q", "prime_q", "prime2")
    if not _before_deadline(deadline) or any(v is None for v in (n, c, p, qv)):
        return None
    if (n <= 2 or n.bit_length() > RABIN_MAX_MODULUS_BITS or p <= 1 or qv <= 1 or p == qv
            or p.bit_length() > RABIN_MAX_MODULUS_BITS or qv.bit_length() > RABIN_MAX_MODULUS_BITS
            or c < 0 or c.bit_length() > RABIN_MAX_MODULUS_BITS or c >= n or p * qv != n):
        return None
    if p % 4 != 3 or qv % 4 != 3:
        return None
    if _supplied_key_prime(p, deadline) is not True or _supplied_key_prime(qv, deadline) is not True:
        return None
    if not _before_deadline(deadline):
        return None
    if not _room_for_supplied_key_operation(deadline):
        return None
    rp = pow(c, (p + 1) // 4, p)
    if not _before_deadline(deadline):
        return None
    if not _room_for_supplied_key_operation(deadline):
        return None
    rq = pow(c, (qv + 1) // 4, qv)
    if not _before_deadline(deadline):
        return None
    if rp * rp % p != c % p or rq * rq % qv != c % qv:
        return None
    if not _room_for_supplied_key_operation(deadline):
        return None
    q_inverse = pow(qv, -1, p)
    if not _before_deadline(deadline):
        return None
    if not _room_for_supplied_key_operation(deadline):
        return None
    p_inverse = pow(p, -1, qv)
    if not _before_deadline(deadline):
        return None
    a = (rp * qv * q_inverse + rq * p * p_inverse) % n
    b = (rp * qv * q_inverse - rq * p * p_inverse) % n
    roots = sorted({a, (-a) % n, b, (-b) % n})
    for root in roots:
        if not _before_deadline(deadline) or root * root % n != c:
            return None
    if not roots or not _before_deadline(deadline):
        return None
    result = (n, c, roots)
    M.cache[slot] = result
    return result


def _rabin_answer(q, M: Material, proof: Proof, deadline=None):
    got = _rabin_roots(M, deadline)
    if not got or not _before_deadline(deadline):
        return None
    n, c, roots = got
    words = _words(q)
    if re.search(r"\b(?:smallest|least|minimum|lowest)\s+(?:positive\s+)?(?:rabin\s+)?root\b", words, re.I):
        positive = [root for root in roots if root > 0]
        return _int_answer(q, f"{KEY}.root/rabin_smallest", positive[0]) if positive else None
    if re.search(r"\b(?:largest|greatest|maximum|highest)\s+(?:positive\s+)?(?:rabin\s+)?root\b", words, re.I):
        positive = [root for root in roots if root > 0]
        return _int_answer(q, f"{KEY}.root/rabin_largest", positive[-1]) if positive else None

    # A specific answer pattern/crib may select exactly one of the four roots.
    selected = []
    for index, root in enumerate(roots, 1):
        if not _before_deadline(deadline):
            return None
        width = max(1, (root.bit_length() + 7) // 8)
        found = proof.judge(root.to_bytes(width, "big"))
        if found is not None:
            selected.append((index, root, found))
    unique_values = {item[2]["value"] for item in selected}
    if len(selected) == 1 and len(unique_values) == 1 and selected[0][2].get("plain"):
        return _finish(q, f"{KEY}.plaintext/rabin", selected[0][2], proof)

    scope_doc = json.dumps({"n": str(n), "c": str(c), "q": _qtext(q), "fmt": _fmt(q)},
                           sort_keys=True, separators=(",", ":"))
    scope = hashlib.sha256(scope_doc.encode()).hexdigest()[:16]
    options = []
    for index, root in enumerate(roots, 1):
        if not _before_deadline(deadline):
            return None
        width = max(1, (root.bit_length() + 7) // 8)
        try:
            text_value = root.to_bytes(width, "big").decode("utf-8")
        except UnicodeDecodeError:
            text_value = None
        if text_value and all(ch.isprintable() or ch in "\r\n\t" for ch in text_value) and _fits(q, text_value.strip()):
            options.append((f"root_{index}_text", text_value.strip()))
        value = str(root)
        if _fits(q, value):
            options.append((f"root_{index}_decimal", value))
    return _candidates(f"{KEY}.plaintext/rabin@inst-{scope}", options)


def _enum(q) -> tuple:
    """(the names the question lists, True when its answer_format lists them itself)."""
    f = _fmt(q)
    for k in ("accepted_values", "options", "choices", "values", "enum"):
        if isinstance(f.get(k), list):
            return [str(v) for v in f[k]][:50], True
    if labels is not None:
        try:
            return list(labels.enum_from_question(str(q.get("question") or "") + " " + str(f.get("syntax") or "")))[:50], False
        except Exception:
            return [], False
    return [], False


def _vocab(q, names: list) -> list:
    """Our names for a fact, narrowed to the ones the question lists. A list in the answer_format
    that holds none of ours leaves nothing to offer; words read out of the question's prose that
    hold none of ours were not a list of names, and ours stand."""
    listed, formal = _enum(q)
    if listed:
        norm = {re.sub(r"[^a-z0-9]+", "_", n.lower()).strip("_"): n for n in listed}
        hit = [norm[n] for n in names if n in norm]
        if hit or formal:
            return hit
    return names


# ---- RSA ----------------------------------------------------------------------------------------------

ATTACK_NAMES = {
    "wiener": ["wiener", "wiener_attack", "small_private_exponent", "small_d", "wieners_attack"],
    "fermat": ["fermat", "fermat_factorization", "close_primes", "fermat_attack", "fermat_factorisation"],
    "small_e_root": ["small_exponent", "low_public_exponent", "small_e", "cube_root", "eth_root", "small_public_exponent", "low_exponent"],
    "hastad": ["hastad_broadcast", "hastad", "broadcast_attack", "hastads_broadcast_attack", "hastad_broadcast_attack"],
    "common_modulus": ["common_modulus", "common_modulus_attack", "same_modulus", "shared_modulus"],
    "shared_prime": ["common_factor", "shared_prime", "common_prime", "gcd", "batch_gcd", "shared_factor", "common_factor_attack"],
    "pollard_p_minus_1": ["pollard_p_minus_1", "pollard_p1", "smooth_prime", "pollards_p_minus_1", "p_minus_1"],
    "pollard_rho": ["pollard_rho", "small_factor", "small_modulus", "pollards_rho", "factorization"],
    "small_factor": ["small_factor", "trial_division", "small_prime", "small_prime_factor", "factorization"],
    "prime_modulus": ["prime_modulus", "prime_n", "n_is_prime"],
    "square_modulus": ["square_modulus", "repeated_prime", "p_equals_q", "square_n"],
    "prime_power_modulus": ["prime_power_modulus", "prime_power", "repeated_prime"],
    "dp_leak": ["dp_leak", "crt_exponent_leak", "partial_key_exposure", "leaked_dp"],
    "digit_repair": ["corrupted_parameter", "digit_repair", "garbled_parameter", "typo"],
    "bellcore": ["bellcore", "bellcore_attack", "crt_fault", "fault_attack", "fault_injection",
                 "rsa_crt_fault", "crt_fault_attack", "faulty_signature"],
    "multi_prime": ["multi_prime", "multiprime", "multi_prime_rsa", "multiprime_rsa", "multi_factor"],
    "franklin_reiter": ["franklin_reiter", "franklin_reiter_attack", "related_message",
                        "related_message_attack", "franklinreiter"],
}


class RSAResult:
    def __init__(self, attack, n=None, e=None, d=None, factors=None, messages=(), repaired=None):
        self.attack, self.n, self.e, self.d, self.factors = attack, n, e, d, factors
        self.messages = list(messages)      # [(reading, bytes)]
        self.repaired = repaired


def _cipher_ints(M: Material, n: int = None) -> list:
    cs = list(dict.fromkeys(M.params.many("c")))
    if cs:
        return cs
    out = []
    for _, b in M.bins:
        forms = [b]
        if b[-1:] in (b"\n", b"\r") and (n is None or len(b) > (n.bit_length() + 7) // 8):
            forms.append(b.rstrip(b"\r\n"))       # a raw ciphertext saved with a line end after it
        for f in forms:
            if 0 < len(f) <= 1100:
                v = lib.to_int(f)
                if v > 1 and (n is None or v < n) and v not in out:
                    out.append(v)
                    break
    return out[:8]


def _decrypt(n, d, factors, c, singles=None):
    if d is None and singles and all(singles.get(k) for k in ("p", "q", "dp", "dq")):
        p, q = singles["p"], singles["q"]
        qinv = pow(q, -1, p)
        m1, m2 = pow(c % p, singles["dp"], p), pow(c % q, singles["dq"], q)
        return m2 + q * ((m1 - m2) * qinv % p)
    return pow(c, d, n) if d is not None else None


# ---- fault and related-message RSA readers (each attack verifies itself in `lib`) -------------------
# A read value that is not what the attack expects cannot pass the attack's own check (the Bellcore
# factor must divide n, the multi-prime factors must multiply to n and d must decrypt a probe, the
# Franklin-Reiter message must re-encrypt to its ciphertext), so these readers try every plausible
# reading of the bytes and trust only what verifies; ambiguity (two different verified answers) is None.

def _as_ints(values) -> list:
    """Integer readings of written values: 0x-hex, decimal, bare hex, else base64/hex blobs. Both a
    decimal and a bare-hex reading are offered where they differ; the attack's own check discards a
    wrong one, so this never introduces a false answer."""
    out = []

    def add(iv):
        if isinstance(iv, int) and iv > 1 and iv not in out:
            out.append(iv)

    for v in values:
        if isinstance(v, int):
            add(v)
            continue
        s = str(v).strip().replace("_", "")
        if re.fullmatch(r"0[xX][0-9a-fA-F]+", s):
            add(int(s, 16))
        elif re.fullmatch(r"\d+", s):
            add(int(s))
        elif re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) % 2 == 0:
            add(int(s, 16))
        else:
            for reading, b in lib.blobs(s):
                if reading != "raw":
                    add(lib.to_int(b))
    return out[:12]


def _fields_matching(M: Material, rx: str) -> list:
    out = []
    for name, vals in M.fields.items():
        if re.fullmatch(rx, name):
            out += vals
    return out


def _sig_candidates(M: Material) -> list:
    """Signature integers the delivery names (signature, sig, faulty_signature, s, s1, s2, ...)."""
    vals = list(M.params.many("s"))
    vals += _fields_matching(M, r"(?:faulty_?|faulted_?|corrupt(?:ed)?_?|bad_?|invalid_?|good_?|"
                                r"correct_?|valid_?|fault_?|glitched_?)?(?:sig|signature)s?\d*")
    return _as_ints(vals)


def _msg_candidates(M: Material) -> list:
    """Message integers the delivery names (message, msg, m, hash, digest, z, em, ...). The hash of a
    signed message is canonicalised to `z` by read_params, so both `m` and `z` are read."""
    vals = list(M.params.many("m")) + list(M.params.many("z"))
    vals += _fields_matching(M, r"(?:padded_?|hashed_?|signed_?|original_?)?"
                                r"(?:message|msg|hash|digest|m|z|h|em|data)\d*")
    return [v for v in _as_ints(vals) if v >= 0]


def _complete_factors(n: int, known: int, deadline=None):
    """Every prime factor of n (ascending, with multiplicity) given one known divisor `known`, or
    None when the cofactor could not be fully factored in time. Verified: the product equals n."""
    fs = []
    for part in (known, n // known):
        if part < 2:
            return None
        if lib.is_prime(part):
            fs.append(part)
        else:
            sub = lib.factor(part, deadline)
            if not sub:
                return None
            fs += sub
    fs.sort()
    prod = 1
    for p in fs:
        prod *= p
    return fs if prod == n else None


def _bellcore(M: Material, n: int, e: int, deadline=None):
    """(sorted factors, d) from a faulty CRT-RSA signature that factors n (lib.bellcore), or None.
    Every (message, signature) reading is tried; the factorisation is accepted only when exactly one
    distinct complete factorisation is proven and d = e**-1 mod phi exists."""
    msgs, sigs = _msg_candidates(M), _sig_candidates(M)
    if not msgs or not sigs:
        return None
    facts = {}
    for sig in sigs:
        if not 1 < sig < n:
            continue
        for m in msgs:
            p = lib.bellcore(m % n, e, n, sig)
            if not p:
                continue
            fs = _complete_factors(n, p, deadline)
            if fs:
                facts[tuple(fs)] = True
    if len(facts) != 1:
        return None
    fs = list(next(iter(facts)))
    d = lib.inverse(e, lib.phi_of(fs))
    return (fs, d) if d is not None else None


def _multiprime_given(M: Material, ns: list, es: list, deadline=None):
    """(n, d, sorted factors, e) when the delivery states the prime factors of a single modulus and
    they are a genuine multi-prime set (three or more factors with multiplicity; two primes are
    rsa_private's job), or None. The stated primes that divide n are peeled off with multiplicity;
    the key is proven only when they account for all of n and d decrypts a probe (lib.rsa_multiprime).
    Runs before the two-prime consistency check, because n != prime1*prime2 for a three-prime modulus."""
    if len(ns) != 1 or len(es) != 1:
        return None
    n, e = ns[0], es[0]
    stated = _as_ints(_fields_matching(M, r"(?:prime|factor|p|q|r)_?\d*")
                      + _fields_matching(M, r"primes|factors"))
    for nm in ("p", "q"):
        stated += list(M.params.many(nm))
    stated = sorted({p for p in stated if p > 1})
    if len(stated) < 2:
        return None             # nothing that could be a multi-prime factor list
    kept, rem = [], n
    for p in stated:
        if lib.is_prime(p):
            while rem % p == 0:
                kept.append(p)
                rem //= p
    if rem != 1 or len(kept) < 3:
        return None             # the stated primes do not fully factor n, or it is only two-prime
    got = lib.rsa_multiprime(n, e, sorted(kept))
    return (got[0], got[1], got[2], e) if got else None


_FR_B_FIELDS = ("b", "offset", "padding", "pad", "delta", "difference", "diff", "shift", "beta")
_FR_A_FIELDS = ("a", "coeff", "coefficient", "multiplier", "alpha", "scale")


def _franklin(M: Material, n: int, e: int) -> set:
    """Every message proven by the Franklin-Reiter related-message attack (small e, two ciphertexts
    of m and a*m + b under one n, with the linear relation stated in the bytes). An empty set when
    the shape is absent or no candidate re-encrypts to its ciphertext. b MUST be stated (never
    guessed); a defaults to 1."""
    if not 2 <= e <= lib.FR_MAX_E:
        return set()
    cs = list(dict.fromkeys(M.params.many("c"))) or _cipher_ints(M, n)
    cs = [c for c in dict.fromkeys(cs) if 1 < c < n]
    if len(cs) != 2:
        return set()
    a_vals = _as_ints([v for f in _FR_A_FIELDS for v in M.fields.get(f, [])])
    a_vals += [v for v in M.params.many("a") if v not in a_vals]
    b_vals = _as_ints([v for f in _FR_B_FIELDS for v in M.fields.get(f, [])])
    b_vals += [v for v in M.params.many("b") if v not in b_vals]
    if not b_vals:
        return set()
    a_cands = [1] + [a for a in a_vals if a != 1]
    found = set()
    c0, c1 = cs
    for a in a_cands[:4]:
        for b0 in b_vals[:4]:
            for b in (b0 % n, (-b0) % n):
                for ci, cj in ((c0, c1), (c1, c0)):
                    m = lib.franklin_reiter(ci, cj, e, n, a % n, b)
                    if m is not None:
                        found.add(m)
    return found


def solve_rsa(M: Material, deadline=None) -> list:
    """[RSAResult] of everything that is proven for the material's RSA parameters and keys.
    An empty list when nothing is, or when the parameters contradict each other and no single
    one-digit repair explains it."""
    if "rsa" in M.cache:
        return M.cache["rsa"]
    out = M.cache["rsa"] = []
    P = M.params.copy()
    rsa_keys = [k for _, k in M.keys if k.get("type") == "rsa"]
    for k in rsa_keys:
        for name in ("n", "e", "d", "p", "q", "dp", "dq"):
            if k.get(name) and k[name] not in P.many(name):
                P.add(name, k[name], source="key")
    # 0. multi-prime RSA: the delivery states three or more prime factors of one modulus. This runs
    # before the two-prime consistency check, which would read prime1/prime2 as p/q and reject the
    # (true) n != prime1*prime2. The factorisation is proven inside _multiprime_given / rsa_multiprime.
    mp = _multiprime_given(M, list(dict.fromkeys(P.many("n"))), list(dict.fromkeys(P.many("e"))), deadline)
    if mp:
        n, d, factors, e = mp
        msgs = []
        for c in _cipher_ints(M, n):
            if c < n:
                m = _decrypt(n, d, factors, c)
                if m is not None:
                    msgs += lib.rsa_messages(m, n)
        out.append(RSAResult("multi_prime", n, e, d, factors, msgs))
        return out
    names = ("n", "e", "d", "p", "q", "phi", "dp", "dq", "qinv")
    singles = {k: P.one(k) for k in names if P.one(k) is not None}
    holes = [k for k in names if P.raw.get(k + "?")]
    repaired = None
    checked, broken = lib.consistency(singles)
    if broken or holes:
        fix = lib.repair_digit(P, deadline)
        if not fix:
            return out              # contradicting parameters: nothing is proven
        repaired, singles = fix[0], fix[3]
    ns = list(dict.fromkeys(P.many("n"))) if not repaired else [singles.get("n")] if singles.get("n") else []
    es = list(dict.fromkeys(P.many("e"))) if not (repaired == "e") else [singles["e"]]
    if repaired == "n":
        ns = [singles["n"]]

    def emit(attack, n, e, d, factors, cs, sing=None):
        msgs = []
        for c in cs:
            if n and c >= n:
                continue
            m = _decrypt(n, d, factors, c, sing)
            if m is not None:
                msgs += lib.rsa_messages(m, n)
        out.append(RSAResult(attack, n, e, d, factors, msgs, repaired))

    # 1. the private key is given, whole or in parts
    priv = lib.rsa_private(singles)
    if priv:
        n, d, factors, how = priv
        emit("digit_repair" if repaired else ("dp_leak" if how == "dp_leak" else "given_key"), n, singles.get("e"), d, factors,
             _cipher_ints(M, n), singles)
        return out
    if not ns:
        return out
    # 2. several moduli: a shared prime, or one message under one small exponent
    all_c = list(M.params.many("c"))
    if len(ns) >= 2:
        shared = lib.shared_primes(ns)
        for i, (p, q) in sorted(shared.items()):
            e = es[i] if len(es) == len(ns) else (es[0] if len(es) == 1 else None)
            if e is None or not (lib.is_prime(p) and lib.is_prime(q)):
                continue
            d = lib.inverse(e, (p - 1) * (q - 1))
            if d is None:
                continue
            cs = [all_c[i]] if len(all_c) == len(P.many("n")) and len(ns) == len(P.many("n")) else _cipher_ints(M, ns[i])
            emit("shared_prime", ns[i], e, d, sorted((p, q)), cs)
        if not shared and len(es) == 1 and len(all_c) == len(ns) == len(P.many("n")):
            m = lib.hastad(list(zip(ns, all_c)), es[0])
            if m is not None:
                out.append(RSAResult("hastad", None, es[0], None, None, lib.rsa_messages(m)))
        elif not shared and len(es) == 1 and not all_c and 2 <= len(ns) <= 4:
            # key files and as many raw ciphertext files, with nothing saying which goes with which: every
            # pairing is tried, and the message is proven only when exactly one of them has an exact root
            raw = _cipher_ints(M)
            if len(raw) == len(ns):
                import itertools
                roots = {}
                for perm in itertools.permutations(raw):
                    if all(c < n_ for n_, c in zip(ns, perm)):
                        m = lib.hastad(list(zip(ns, perm)), es[0])
                        if m is not None:
                            roots[m] = True
                if len(roots) == 1:
                    out.append(RSAResult("hastad", None, es[0], None, None, lib.rsa_messages(next(iter(roots)))))
        if out:
            return out
    # 3. one modulus, two exponents
    if len(ns) == 1 and len(es) >= 2 and len(all_c) == len(P.many("e")) >= 2:
        pe = P.many("e")
        for i in range(len(pe)):
            for j in range(i + 1, len(pe)):
                if pe[i] != pe[j]:
                    m = lib.common_modulus(ns[0], pe[i], all_c[i], pe[j], all_c[j])
                    if m is not None:
                        out.append(RSAResult("common_modulus", ns[0], None, None, None, lib.rsa_messages(m, ns[0])))
                        return out
    if len(ns) != 1 or len(es) != 1:
        return out
    n, e = ns[0], es[0]
    cs = _cipher_ints(M, n)
    # 3b. Bellcore CRT-fault: a faulty signature factors n (a correct + faulty pair, or m + one fault)
    bc = _bellcore(M, n, e, deadline)
    if bc:
        factors, d = bc
        emit("bellcore", n, e, d, factors, cs)
        return out
    # 3c. Franklin-Reiter related message: two ciphertexts of m and a*m + b under one small e
    for m in sorted(_franklin(M, n, e)):
        out.append(RSAResult("franklin_reiter", n, e, None, None, lib.rsa_messages(m, n)))
    if out:
        return out
    # 4. an exact root (m^e below n), then the key's own weaknesses, cheapest first
    for c in cs:
        m = lib.small_e_root(c, e)
        if m is not None:
            out.append(RSAResult("small_e_root", n, e, None, None, lib.rsa_messages(m, n)))
    if out:
        return out
    got = lib.rsa_attack(n, e, deadline, level=1)
    if not got and e <= 17:
        for c in cs:
            m = lib.small_e_root(c, e, n, max_k=4096, deadline=deadline)
            if m is not None:
                out.append(RSAResult("small_e_root", n, e, None, None, lib.rsa_messages(m, n)))
        if out:
            return out
    if not got and rsal is not None and (deadline is None or time.monotonic() < deadline):
        _lattice_rsa(M, n, e, cs, deadline, emit, out, "hints")      # before level 2, which can use the whole deadline
        if out:
            return out
    if not got and (deadline is None or time.monotonic() < deadline):
        got = lib.rsa_attack(n, e, deadline, level=2)
    if got:
        d, factors, how = got
        emit(how, n, e, d, factors, cs)
    if not out and rsal is not None and (deadline is None or time.monotonic() < deadline):
        _lattice_rsa(M, n, e, cs, deadline, emit, out, "search")
    return out


def _fint(v: str):
    v = v.strip()
    try:
        if v[:2].lower() == "0x":
            return int(v, 16)
        return int(v) if re.fullmatch(r"\d+", v) else (int(v, 16) if re.fullmatch(r"[0-9a-fA-F]+", v) else None)
    except ValueError:
        return None


def _fbytes(v: str) -> bytes:
    v = v.strip()
    if v[:2].lower() == "0x" and re.fullmatch(r"0[xX]([0-9a-fA-F]{2})+", v):
        return bytes.fromhex(v[2:])
    return v.encode("utf-8")


def _lattice_rsa(M, n, e, cs, deadline, emit, out, phase="hints"):
    """Day 26: partial-prime, stereotyped-message, Boneh-Durfee and ROCA attacks, each bounded and each
    verified inside rsa_lattice (p*q == n; pow(m, e, n) == c; d round-trips). Every call is capped
    (LATTICE_BUDGET s) and a failure or a timeout is None: nothing unverified is ever emitted."""
    cap = time.monotonic() + LATTICE_BUDGET
    dl = min(cap, deadline) if deadline else cap
    bits = n.bit_length()

    def finish(how, pq):
        p, q = pq
        d = lib.inverse(e, (p - 1) * (q - 1))
        if d is not None and p * q == n and lib.is_prime(p) and lib.is_prime(q):
            emit(how, n, e, d, sorted((p, q)), cs)
            return True
        return False

    # 1. partial prime: a labelled run of the high or low bits of p (or q)
    for who in (("p", "q") if phase == "hints" else ()):
        for kind, names in (("high", ("high", "msb", "hi", "prefix", "known_high", "upper")),
                            ("low", ("low", "lsb", "lo", "suffix", "known_low", "lower"))):
            for nm in names:
                for raw in M.field(who + "_" + nm, nm + "_" + who):
                    known = _fint(raw)
                    if not known or known < 2:
                        continue
                    kb = None
                    for bn in M.field(who + "_" + nm + "_bits", who + "_known_bits", "known_bits", "bits_known"):
                        kb = _fint(bn) if re.fullmatch(r"\d+", bn.strip()) else None
                        if kb:
                            break
                    if kb is None and kind == "high":
                        kb = known.bit_length()
                    if not kb:
                        continue
                    got = rsal.partial_prime(n, known, kb, kind, deadline=dl)
                    if got and finish("partial_prime_" + kind, got):
                        return
    # 2. stereotyped message: a known prefix / suffix of the plaintext, a short unknown part, small e
    if phase == "hints" and e <= 17 and cs:
        pres = [b for nm in ("prefix", "known_prefix", "plaintext_prefix", "message_prefix", "flag_prefix", "known_plaintext", "known")
                for b in (_fbytes(r) for r in M.field(nm))]
        sufs = [b for nm in ("suffix", "known_suffix", "plaintext_suffix", "message_suffix", "flag_suffix") for b in (_fbytes(r) for r in M.field(nm))]
        ulens = [_fint(r) for nm in ("unknown_len", "unknown_bytes", "unknown_length", "secret_len", "secret_length", "flag_len") for r in M.field(nm)]
        ulens = [u for u in ulens if u and 0 < u < 4096]
        pres, sufs = pres[:2] or [b""], sufs[:2] or [b""]
        if pres != [b""] or sufs != [b""]:
            maxl = max(1, bits // (8 * e))
            for c in cs[:2]:
                for pre in pres:
                    for suf in sufs:
                        for L in (ulens or range(1, maxl + 1)):
                            if time.monotonic() > dl:
                                return
                            pt = rsal.stereotyped_message(n, e, c, pre, suf, L, deadline=dl)
                            if pt is not None:
                                m_int = int.from_bytes(pt, "big")
                                if pow(m_int, e, n) == c:
                                    out.append(RSAResult("stereotyped_message", n, e, None, None, lib.rsa_messages(m_int, n)))
                                    return
    # 3. Boneh-Durfee: a large e (a small d is likely) beyond Wiener, which has already failed
    if phase == "search" and bits <= 512 and e.bit_length() >= bits // 2 and time.monotonic() < dl:    # pure-Python LLL: a larger n cannot finish
        got = rsal.boneh_durfee(n, e, delta=0.27, m=4, t=2, deadline=dl)
        if got:
            d, p, q = got
            if finish("boneh_durfee", (p, q)):
                return
    # 4. ROCA: only a modulus of the Infineon form is searched, and only toy sizes finish
    if phase == "search" and rsal.roca_fingerprint(n) and time.monotonic() < dl:
        got = rsal.roca_factor(n, deadline=dl)
        if got:
            finish("roca", got)


def _rsa_plain(M, q, proof, deadline, need=1):
    """The one proven plaintext of the RSA results, or None."""
    found = {}
    for r in solve_rsa(M, deadline):
        for _, pt in r.messages:
            j = proof.judge(pt)
            if j and j["level"] >= need:
                found.setdefault(j["value"], j)
    return next(iter(found.values())) if len(found) == 1 else None


def _rsa_plain_integer(M, deadline):
    """The one raw RSA message representative, as an integer, or None.

    ``Proof.judge`` deliberately reads printable plaintext as text.  That is the right path for
    ordinary message/flag questions, but it used to make an explicitly-integer question about a
    textbook RSA specimen offer ``"A"`` for the proven integer 65.  The raw message from
    ``solve_rsa`` has already been verified by the corresponding RSA attack/decryption.  It is
    nevertheless safe to expose as an integer only when there is one value and no padding reader
    also produced a different, unpadded interpretation; in that case the word "plaintext" alone
    does not establish which layer the author means.
    """
    found = set()
    for result in solve_rsa(M, deadline):
        for reading, plaintext in result.messages:
            if reading != "raw":
                return None
            found.add(int.from_bytes(plaintext, "big"))
    return next(iter(found)) if len(found) == 1 else None


def _one_key(M, deadline):
    rs = [r for r in solve_rsa(M, deadline) if r.n]
    return rs[0] if len({r.n for r in rs}) == 1 else None


# ---- ciphers with a stated key, XOR, stream reuse ------------------------------------------------------

_KEYF = ("key", "aes_key", "secret_key", "k", "password", "passphrase", "secret")
_IVF = ("iv", "nonce", "initialization_vector", "init_vector", "counter")
_CTF = ("ciphertext", "ct", "cipher", "encrypted", "enc", "data", "payload", "cipher_text", "message", "msg", "flag", "c", "blob", "token")
_ALGS = (("aes", r"\baes|rijndael"), ("des", r"(?<![3a-z])des\b(?!c)|\bdes[-_ ](?:ecb|cbc)"), ("3des", r"3des|triple[- ]?des|des3|des-ede"),
         ("rc4", r"\brc4\b|arc4|arcfour"), ("chacha20", r"chacha"), ("salsa20", r"salsa"), ("blowfish", r"\bblowfish\b|\bbf[-_](?:cbc|ecb)\b"), ("xor", r"\bxor(?:ed|ing)?\b|exclusive[- ]or"))
_MODES = ("ecb", "cbc", "ctr", "gcm", "cfb", "ofb")


def _stated_in(blob: str) -> tuple:
    return ({a for a, rx in _ALGS if re.search(rx, blob, re.I)},
            {m for m in _MODES if re.search(r"(?<![a-z])" + m + r"(?![a-z])", blob, re.I)})


def _stated(M: Material, q) -> tuple:
    """(ciphers, modes) named by the question, the file names, the field names and short values,
    and the first of the text."""
    if "stated" not in M.cache:
        M.cache["stated"] = _stated_in(" ".join(M.names) + " " + " ".join(M.fields) + " "
                                       + " ".join(v for vs in M.fields.values() for v in vs if len(v) < 40) + " " + M.all_text[:20000])
    a, m = _stated_in(_words(q))
    return a | M.cache["stated"][0], m | M.cache["stated"][1]


def _cts(M: Material, with_text: bool = False) -> list:
    """The byte strings that may be a ciphertext: labelled values (hex or base64), files that are
    not text, text files that are all hex or base64; with_text, text files as they are too."""
    out, seen = [], set()
    for v in M.field(*_CTF, exclude=("key",)):
        for reading, b in lib.blobs(v):
            if reading != "raw" and b not in seen and len(b) >= 4:
                seen.add(b)
                out.append(b)
    for _, b in M.bins + (M.raw_texts if with_text else []):
        if b not in seen:
            seen.add(b)
            out.append(b)
    return out[:8]


def _line_cts(M: Material) -> list:
    """[(line index from 0, the line as written, bytes)] when exactly one text file of the delivery
    is a list of ciphertexts, one a line: 2 to 5000 non-empty lines, every one of them hex of an
    even length (or every one base64) of 8 bytes or more. [] otherwise."""
    if "line_cts" in M.cache:
        return M.cache["line_cts"]
    found = []
    for name, text in M.texts:
        if name == "<question>":
            continue
        lines = [(i, ln.strip()) for i, ln in enumerate(text.splitlines())]
        full = [(i, ln) for i, ln in lines if ln]
        if not 2 <= len(full) <= 5000:
            continue
        rows = []
        if all(len(ln) % 2 == 0 and len(ln) >= 16 and re.fullmatch(r"[0-9a-fA-F]+", ln) for _, ln in full):
            rows = [(i, ln, bytes.fromhex(ln)) for i, ln in full]
        elif all(len(ln) >= 12 and len(ln) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", ln) for _, ln in full) \
                and len({len(ln) for _, ln in full}) > 1:        # equal-length lines are one wrapped base64 text
            try:
                rows = [(i, ln, base64.b64decode(ln, validate=True)) for i, ln in full]
            except (binascii.Error, ValueError):
                rows = []
        if rows:
            found.append(rows)
    M.cache["line_cts"] = found[0] if len(found) == 1 else []
    return M.cache["line_cts"]


def solve_sym(M: Material, q, proof: Proof = None, deadline=None):
    """(the one proven plaintext {text, value, ...}, cipher name, key bytes) for a key the
    artifact states, or None. Every reading of the written key, IV and ciphertext (hex, base64,
    the text itself) and every mode the sizes and the stated names allow is decrypted; exactly
    one distinct plaintext must pass: PKCS#7 that unpads plus readable text for a block mode,
    readable text of 16 bytes or more (or the question's crib or pattern) for a stream."""
    proof = proof or Proof(q)
    slot = ("sym", proof.signature, tuple(sorted(_stated(M, q)[0])), tuple(sorted(_stated(M, q)[1])))
    if slot not in M.cache:
        M.cache[slot] = _solve_sym(M, q, proof, deadline)
    return M.cache[slot]


def _solve_sym(M: Material, q, proof: Proof, deadline=None):
    keys = [b for v in M.field(*_KEYF, exclude=("public", "pub_")) for _, b in lib.blobs(v)]
    keys += [k["k"] for _, k in M.keys if k.get("type") == "oct"]
    # a written passphrase that is no key size: its SHA-256 and MD5, the two usual derivations
    # (the padding and the text of the result prove a derivation as they prove a key)
    for v in M.field(*_KEYF, exclude=("public", "pub_"))[:2]:
        raw = v.encode("utf-8")
        if len(raw) not in (8, 16, 24, 32) and not any(len(b) in (8, 16, 24, 32) for _, b in lib.blobs(v)):
            keys += [hashlib.sha256(raw).digest(), hashlib.md5(raw).digest()]
    # Day 26 AES modes (key wrap, XTS): a labelled KEK, and key1 || key2 for XTS, come first
    extra_keys = [b for v in M.field("kek", "wrapping_key", "wrap_key") for r, b in lib.blobs(v) if r != "raw" or len(b) in (16, 24, 32)]
    k1s = [b for v in M.field("key1", "key_1", "xts_key1", "data_key") for r, b in lib.blobs(v) if r != "raw"]
    k2s = [b for v in M.field("key2", "key_2", "xts_key2", "tweak_key") for r, b in lib.blobs(v) if r != "raw"]
    for a in k1s[:2]:
        for b in k2s[:2]:
            if len(a) == len(b) and len(a) in (16, 32):
                extra_keys.append(a + b)
    keys = list(dict.fromkeys(extra_keys + keys))
    if not keys:
        return None
    algs, modes = _stated(M, q)
    xts_stated = re.search(r"(?<![a-z])xts(?![a-z])", " ".join(M.names) + " " + " ".join(M.fields) + " " + _words(q) + " " + M.all_text[:20000], re.I) is not None
    tweaks = []
    if xts_stated:
        for v in M.field("tweak", "sector", "sector_number", "sector_index", "data_unit", "lba", "sector_no", "data_unit_number") + M.field(*_IVF):
            if re.fullmatch(r"\d{1,30}", v.strip()) and int(v) < 1 << 128:
                tweaks.append(int(v).to_bytes(16, "little"))
            tweaks += [b for r, b in lib.blobs(v) if len(b) == 16 and r != "raw"]
        tweaks.append(bytes(16))        # sector 0, the last resort; the plaintext proof still decides
        tweaks = list(dict.fromkeys(tweaks))
    ivs = [b for v in M.field(*_IVF) for r, b in lib.blobs(v)] or [None]
    ivs += [b[:8] for b in ivs if b and len(b) == 16 and not any(b) and b[:8] not in ivs]
    tags = [b for v in M.field("tag", "auth_tag", "mac", "siv", "synthetic_iv") for r, b in lib.blobs(v) if r != "raw"] or [None]
    aads = [b for v in M.field("aad", "ad", "associated_data", "additional_data", "header") for r, b in lib.blobs(v)
            if r != "raw"][:2] + [b""]
    cipher_algs = (algs - {"xor"}) or None
    found = {}
    wrapped = [b for v in M.field("wrapped", "wrapped_key", "wrapped_flag", "wrapped_secret", "wrapped_data", "wrapped_ct")
               for r, b in lib.blobs(v) if r != "raw"]
    cts = list(_cts(M))
    cts += [b for b in wrapped[:4] if b not in cts]
    for ct in cts:
        for key in keys[:8]:
            if deadline is not None and time.monotonic() > deadline:
                return None         # not finished: 'exactly one' cannot be said
            cands = []
            if "xor" in algs:
                cands.append(("xor", lib.xor(ct, key)))
            if algs != {"xor"}:
                for iv in ivs[:4]:
                    for tag in tags[:2]:
                        for aad in aads:
                            cands += lib.sym_candidates(key, ct, iv, tag, cipher_algs, modes or None, aad=aad,
                                                        tweaks=tweaks or None)
            for name, pt in cands:
                if name.endswith("-xts"):
                    # no tag: only the proof decides. A data unit's zero padding comes off, and the text
                    # must be 32 bytes or more of readable text, or meet the question's own crib or pattern
                    pt = pt.rstrip(b"\x00") if proof.readable(pt) is None else pt
                    j = proof.judge(pt)
                    if j and (j["level"] >= 2 or len(pt) >= 32):
                        found.setdefault(j["value"], (j, name, key))
                    continue
                j = proof.judge(pt)
                if not j:
                    continue
                # a block mode that unpads, or 16 readable bytes of a stream, cannot be a wrong key by
                # chance; a last block that is not PKCS#7 needs the question's own proof
                if j["level"] >= 2 or (":nopad" not in name and (len(pt) >= 16 or re.search(r"-(?:ecb|cbc|gcm|ccm|siv|kwp?)(?![a-z])|poly1305", name))):
                    found.setdefault(j["value"], (j, name, key))
    return next(iter(found.values())) if len(found) == 1 else None


def solve_xor(M: Material, q, proof: Proof = None, deadline=None):
    """(the one proven plaintext, key bytes) of an XOR with no stated key: every single-byte key
    but 0, and every repeating key the question's cribs give. A candidate counts only with the
    question's own proof (a specific pattern, a crib, the stated flag form); exactly one distinct
    plaintext must be left."""
    proof = proof or Proof(q)
    slot = ("xor", proof.signature)
    if slot not in M.cache:
        M.cache[slot] = _solve_xor(M, proof, deadline)
    return M.cache[slot]


def _solve_xor(M: Material, proof: Proof, deadline=None):
    found = {}
    for ct in _cts(M, with_text=True):
        if len(ct) > 65536:
            continue
        if deadline is not None and time.monotonic() > deadline:
            return None
        cands = [(bytes([k]), lib.xor(ct, bytes([k])), 3) for k in range(1, 256)]
        for crib, at_start in proof.cribs:
            # a key the crib covers once only has nothing checking it: the specific pattern must
            cands += [(key, pt, 3 if len(crib) - len(key) >= (1 if at_start else 2) else 0)
                      for key, _, pt in lib.xor_crib(ct, crib, anywhere=not at_start) if any(key)]
        for key, pt, checked in cands:
            j = proof.judge(pt)
            if j and (j["level"] == 3 or (j["level"] >= 2 and checked)):
                found.setdefault(j["value"], (j, key))
    return next(iter(found.values())) if len(found) == 1 else None


# ---- keyless repeating-key XOR break (buildlist row 2): no crib, ranked by fitness --------------------
#
# A repeating-key XOR ciphertext of English text is broken with no crib and no stated key: the key
# length is found by the normalized Hamming distance between blocks (bounded 2..40), each column is
# a single-byte XOR solved by an English-fitness score, and the whole plaintext is scored to rank the
# candidate keys. The recovered key and plaintext are GUESSES ranked by fitness -- never a byte-proven
# fact under a judge-accepted label -- so every caller offers them ONLY as labels.candidates (row 346,
# the never-wrong class `unsure`), probed on an untimed / no-deadline attempt and plain on no variant
# until the judge accepts a hypothesis name. Deterministic, stdlib only, no network.

# English monogram frequency (percent), with space, newline and tab; the basis of the fitness score.
_ENGLISH_FREQ = {
    " ": 13.00, "e": 12.70, "t": 9.06, "a": 8.17, "o": 7.51, "i": 6.97, "n": 6.75, "s": 6.33,
    "h": 6.09, "r": 5.99, "d": 4.25, "l": 4.03, "c": 2.78, "u": 2.76, "m": 2.41, "w": 2.36,
    "f": 2.23, "g": 2.02, "y": 1.97, "p": 1.93, "b": 1.49, "v": 0.98, "k": 0.77, "j": 0.15,
    "x": 0.15, "q": 0.10, "z": 0.07,
}
# Per-plaintext-byte weight for SINGLE-BYTE column recovery (Cryptopals style): frequent letters
# and space reward, other printable a small reward, a control or high byte a strong penalty. This
# reliably recovers one column's key byte. It is NOT used to rank whole decodes across key lengths
# (there it would reward a corrupted text with extra high-frequency letters); _score_counts does that.
_BYTE_WEIGHT = tuple(
    0.6 if b in (0x0A, 0x09) else
    0.0 if b == 0x0D else
    _ENGLISH_FREQ.get(chr(b).lower(), 0.08) if 0x20 <= b < 0x7F else
    -8.0
    for b in range(256)
)
# Expected letter proportion AMONG the 26 letters (space dropped): the chi-squared reference.
_LETTER_EXP = {c: f / sum(v for k, v in _ENGLISH_FREQ.items() if k != " ")
               for c, f in _ENGLISH_FREQ.items() if c != " "}
XOR_KEYLEN_MIN = 2
XOR_KEYLEN_MAX = 40
XOR_KEYSIZES = 5                 # how many candidate key lengths to break and rank
XOR_CT_MIN = 32                  # a ciphertext shorter than this is not broken as repeating-key


def _score_counts(counts: dict, total: int) -> float:
    """English-fitness of a byte-count histogram, higher is better: the negative per-letter
    chi-squared distance of the letter distribution from English, with a strong penalty for
    non-printable bytes. Chi-squared is used (not a monogram weight-sum) because a weight-sum
    merely rewards having more high-frequency letters, so it would rank a corrupted decode with
    extra e's/t's ABOVE the true plaintext; chi-squared penalizes over- and under-representation
    alike. Deterministic; no external table beyond the monogram frequencies; no network."""
    letters, bad, lc = 0, 0, {}
    for b, c in counts.items():
        if b in (0x0A, 0x0D, 0x09):
            continue
        if 0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A:
            lc[b | 0x20] = lc.get(b | 0x20, 0) + c
            letters += c
        elif not (0x20 <= b < 0x7F):
            bad += c
    if letters == 0:
        return -1e18
    chi = 0.0
    for ch, prop in _LETTER_EXP.items():
        exp = letters * prop
        obs = lc.get(ord(ch), 0)
        chi += (obs - exp) * (obs - exp) / exp
    return -(chi / letters) - 40.0 * (bad / total if total else 1.0)


def _english_score(data: bytes) -> float:
    """Deterministic English-fitness of candidate plaintext bytes, higher is better."""
    if not data:
        return -1e18
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    return _score_counts(counts, len(data))


def _hamming(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def _min_period(key: bytes) -> bytes:
    """`key` reduced to its shortest repeating period: SPARTASPARTA -> SPARTA. A key length the
    Hamming step favours is often a multiple of the true one, and they encrypt identically, so the
    minimal period is the key candidate offered."""
    n = len(key)
    for p in range(1, n):
        if n % p == 0 and key == key[:p] * (n // p):
            return key[:p]
    return key


def _rank_keylengths(ct: bytes, lo: int, hi: int, take: int) -> list:
    """The best `take` candidate key lengths of a repeating-XOR ciphertext (lo..hi, bounded by the
    length so at least four blocks exist), by the average normalized Hamming distance between
    consecutive blocks -- lowest distance first. Ties keep the shorter length first (a true key of
    length k also reads clean at 2k)."""
    hi = min(hi, len(ct) // 4)
    scored = []
    for k in range(lo, hi + 1):
        pairs, total, prev = 0, 0.0, None
        for i in range(0, (len(ct) // k) * k, k):
            block = ct[i:i + k]
            if prev is not None:
                total += _hamming(prev, block) / k
                pairs += 1
                if pairs >= 20:
                    break
            prev = block
        if pairs:
            scored.append((total / pairs, k))
    scored.sort()
    return [k for _, k in scored[:take]]


def _plausible_english(pt: bytes) -> bool:
    """True when a recovered plaintext reads as natural-language text. Three gates together, so the
    keyless break offers candidates only for a real text ciphertext and never guesses on a non-text
    (Binary/Metadata) delivery that merely names an 'xor key':
      - fully printable (the technique's domain is English prose);
      - mostly letters and spaces (a random/binary blob XORed by one byte per column stays ~random,
        only about a tenth of its bytes land on a letter, so it fails here);
      - at least ten DISTINCT letters (a low-entropy blob, e.g. an int array of zeros, breaks to a
        repetitive run like 'E EFE EGE...' with a high letter ratio but only a few distinct
        letters, so the ratio gate alone would pass it -- real prose uses many letters)."""
    if not pt or Proof.readable(pt) is None:
        return False
    letters = sum(1 for b in pt if 0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A)
    spaces = pt.count(0x20)
    distinct = len({b | 0x20 for b in pt if 0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A})
    return letters / len(pt) >= 0.55 and (letters + spaces) / len(pt) >= 0.60 and distinct >= 10


def _solve_column(column: bytes) -> int:
    """The single byte that makes one transposed column most English, by the monogram weight-sum
    (reliable for single-byte recovery). Works off the column's byte histogram, so the cost is at
    most 256*256 per column, not per byte. Ties keep the smaller key byte, so the break is
    deterministic."""
    hist = {}
    for v in column:
        hist[v] = hist.get(v, 0) + 1
    best_b, best_s = 0, -1e18
    for b in range(256):
        s = 0.0
        for v, c in hist.items():
            s += c * _BYTE_WEIGHT[v ^ b]
        if s > best_s:
            best_s, best_b = s, b
    return best_b


def break_repeating_xor(ct: bytes, lo: int = XOR_KEYLEN_MIN, hi: int = XOR_KEYLEN_MAX,
                        keysizes: int = XOR_KEYSIZES, deadline=None) -> list:
    """[(key length, key bytes, plaintext bytes, fitness)] of the best repeating-XOR keys for `ct`,
    best fitness first. Keyless and crib-free; deterministic; key length bounded to lo..hi; stdlib
    only; no network. For each candidate key length each column is solved as a single-byte XOR by
    English fitness, the plaintext is reassembled with lib.xor and scored."""
    if len(ct) < max(XOR_CT_MIN, 2 * lo):
        return []
    best = {}
    for k in _rank_keylengths(ct, lo, hi, keysizes):
        if deadline is not None and time.monotonic() > deadline:
            break
        key = _min_period(bytes(_solve_column(ct[col::k]) for col in range(k)))
        pt = lib.xor(ct, key)
        score = _english_score(pt)
        prev = best.get(key)            # a key length and its multiple reduce to one key: keep it once
        if prev is None or score > prev[3]:
            best[key] = (len(key), key, pt, score)
    return sorted(best.values(), key=lambda t: (-t[3], t[0]))   # best fitness first; shorter key wins a tie


def solve_repeating_xor(M: Material, q=None, proof: Proof = None, deadline=None) -> list:
    """Ranked repeating-key XOR breaks for the ONE suitable ciphertext of the delivery, kept only
    when they recover plausible English text, or []. For the keyless, crib-free case only: it
    returns [] when a key is stated (solve_sym/solve_xor prove that), when the delivery does not
    hold exactly one blob long enough to break, or when no break reads as natural-language text
    (so it never guesses on a non-text / Binary delivery that merely names an 'xor key'). The
    result is offered by callers as labels.candidates only (never plain)."""
    slot = "repeating_xor"
    if slot in M.cache:
        return M.cache[slot]
    M.cache[slot] = []
    if M.field(*_KEYF, exclude=("public", "pub_")) or any(k.get("type") == "oct" for _, k in M.keys):
        return M.cache[slot]        # a key is stated: this path is for NO key
    # a ciphertext is scrambled, not readable: break only a blob that looks encrypted (a raw byte
    # blob, or the decoded bytes of a hex/base64 field), never a plaintext text file that merely
    # sits in the delivery -- so the break does not fire on a readable config of another lane
    blobs = [b for b in _cts(M) if XOR_CT_MIN <= len(b) <= 65536 and Proof.readable(b) is None]
    if len(blobs) != 1:
        return M.cache[slot]        # exactly one ciphertext, or the break is ambiguous
    # Scope the candidate key to THIS ciphertext (its sha256): the recovered key/plaintext is a
    # fitness guess, established-but-unjudged, so a hypothesis name the judge accepts for one
    # variant must NEVER promote a DIFFERENT variant's guess to plain (never-wrong fix; mirrors the
    # proposer's attempt-scoped candidates -- an accepted one is banked but does not replay).
    M.cache["repeating_xor_disc"] = hashlib.sha256(blobs[0]).hexdigest()
    ranked = [r for r in break_repeating_xor(blobs[0], deadline=deadline) if _plausible_english(r[2])]
    M.cache[slot] = ranked
    return ranked


def _repeating_xor_candidates(q, key: str, ranked: list, want: str):
    """An UNSURE candidate pick (row 346) over the best repeating-XOR breaks, best fitness first.
    `want` is 'plaintext' or 'key'; each option is named by its hypothesised key length (never by
    its value). Returns None when nothing survives the question's own answer_format. Never plain:
    a keyless XOR break is a guess, so even a candidate that matches a specific pattern stays unsure
    until the judge accepts a hypothesis name."""
    if not ranked:
        return None
    force_hex = want == "key" and bool(re.search(r"\bhex", _words(q), re.I))
    opts = []
    for keysize, kbytes, pt, _score in ranked:
        if want == "key":
            printable = bool(kbytes) and all(32 <= b < 127 for b in kbytes) and kbytes.strip() == kbytes
            value = kbytes.decode("ascii") if printable and not force_hex else kbytes.hex()
        else:
            text = Proof.readable(pt)
            value = text.strip() if text else None
        if value is None or value == "" or not _fits(q, value):
            continue
        opts.append((f"keylen_{keysize}", value))
    return _candidates(key, opts)


def solve_reuse(M: Material, q, proof: Proof = None):
    """The one proven plaintext of a reused keystream (two-time pad, C9a). Two routes, both
    deterministic and crib-confirmed:
      (a) a whole known message P and two ciphertexts A, B under one keystream recover the other
          message as P xor A xor B, kept under the question's own proof (level 2 or more);
      (b) a crib (a known substring/prefix of one message, from the question or a field) dragged
          across A xor B: at the one offset where the recovered OTHER-message window fullmatches
          the question's specific pattern (level 3), that window is the answer.
    Nothing is answered unless exactly one distinct value is proven."""
    proof = proof or Proof(q)
    blobs = _cts(M)
    known = [t.encode("utf-8") for n, t in M.texts if n != "<question>"] + [v.encode() for v in M.field("plaintext", "known", "known_plaintext", "pt")]
    found = {}
    for pt in known[:6]:
        for variant in dict.fromkeys((pt, pt.rstrip(b"\r\n"))):
            for a in blobs:
                for b in blobs:
                    if a is b:
                        continue
                    got = lib.keystream_reuse(variant, a, b)
                    j = proof.judge(got) if got else None
                    if j and j["level"] >= 2:
                        found.setdefault(j["value"], j)
    if not found:
        # (b) a shorter crib: the recovered window alone must carry the question's specific pattern
        cribs = [c for c, _ in proof.cribs] + [v.encode("utf-8", "ignore") for v in M.field("crib", "known_plaintext", "known", "prefix", "pt")]
        for crib in dict.fromkeys(c for c in cribs if 4 <= len(c) <= 4096):
            for a in blobs:
                for b in blobs:
                    if a is b:
                        continue
                    for _, seg in lib.two_time_pad(a, b, crib):
                        j = proof.judge(seg)
                        if j and j["level"] >= 3:
                            found.setdefault(j["value"], j)
    return next(iter(found.values())) if len(found) == 1 else None


# ---- hash length extension (Merkle-Damgard, C9b) ----------------------------------------------------------

_LE_ALGOS = (("sha512", r"sha-?512"), ("sha256", r"sha-?256"), ("sha1", r"\bsha-?1\b"),
             ("md5", r"\bmd-?5\b"), ("md4", r"\bmd-?4\b"))
_LE_DIGLEN = {"md4": 32, "md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}
_LE_DIG_FIELDS = ("mac", "hmac", "tag", "signature", "sig", "hash", "digest", "checksum", "mac1", "known_mac", "known_tag", "original_mac")
_LE_DATA_FIELDS = ("data", "message", "msg", "known", "known_data", "original", "original_message", "query", "input", "cookie", "token")
_LE_APPEND_FIELDS = ("append", "suffix", "extension", "extra", "add", "additional", "payload", "command", "cmd", "inject")
_LE_SECRET_FIELDS = ("secret", "key", "password", "passphrase", "secret_key")
_LE_LEN_FIELDS = ("secret_length", "secret_len", "key_length", "key_len", "keylen", "secretlen", "secret_bytes", "key_bytes")


def _field_bytes(M: Material, names) -> list:
    """Every byte reading (hex, base64, raw) of the fields under `names`, de-duplicated."""
    out, seen = [], set()
    for v in M.field(*names):
        for _, b in lib.blobs(v):
            if b and b not in seen:
                seen.add(b)
                out.append(b)
    return out


def _lenext_secret_len(M: Material, q) -> list:
    """The secret/key length in BYTES the delivery states: a labelled field or integer, or a phrase
    (`the key is 14 bytes`, `16-byte secret`). [] when none, more than one distinct value (never a
    guess), or a range."""
    out = []
    for n in _LE_LEN_FIELDS:
        out += [int(v) for v in M.params.many(n)]
        for v in M.field(n):
            s = str(v).strip()
            if s.isdigit():
                out.append(int(s))
    text = _qtext(q) + " " + M.all_text[:20000]
    for m in re.finditer(r"\b(?:secret|key|password|passphrase)\b[^.?\n]{0,40}?\b(\d{1,5})[-\s]?byte", text, re.I):
        out.append(int(m.group(1)))
    for m in re.finditer(r"\b(\d{1,5})[-\s]?byte[- ]?(?:long\s+)?(?:secret|key|password|passphrase)\b", text, re.I):
        out.append(int(m.group(1)))
    out = [v for v in dict.fromkeys(out) if 0 <= v <= 65536]
    return out


def _lenext_digest(M: Material, q, algo: str) -> list:
    """The original digest (hex) of the right length for `algo`, from a labelled field or a
    hash-shaped string in the material. [] when none or more than one distinct."""
    want = _LE_DIGLEN[algo]
    labelled = []
    for v in M.field(*_LE_DIG_FIELDS):
        s = re.sub(r"\s+", "", str(v))
        s = s[2:] if s[:2].lower() == "0x" else s
        if re.fullmatch(rf"[0-9a-fA-F]{{{want}}}", s):
            labelled.append(s.lower())
    if labelled:
        return list(dict.fromkeys(labelled))
    # only when no field is labelled as the digest: a hash-shaped string of the right length that is
    # not a secret/key reading (a 16-byte secret's hex is 32 hex, the md5 digest length)
    secret_hex = {b.hex() for b in _field_bytes(M, _LE_SECRET_FIELDS)}
    out = []
    for s in _hash_strings(M, q):
        s = s.strip().lower()
        if re.fullmatch(rf"[0-9a-f]{{{want}}}", s) and s not in secret_hex:
            out.append(s)
    return list(dict.fromkeys(out))


_LE_WANTS_MESSAGE = re.compile(
    r"\bforged message\b|\bnew message\b|\bpadded message\b|\bfull message\b|\bforged payload\b"
    r"|\bmessage\b[^.?\n]{0,20}\b(?:bytes|hex|base64|value)\b|\b(?:bytes|hex|base64)\b[^.?\n]{0,20}\bmessage\b", re.I)


def _lenext_answer(q, forged_hex: str, forged_message: bytes):
    """The forged value in the form the question fixes. The digest is the usual ask (forge a valid
    MAC/signature); the forged MESSAGE is returned only when the question explicitly asks for it
    ('the forged message as hex', 'message bytes'), so 'forge the MAC for the extended message'
    stays the digest. None when neither form fits the answer_format."""
    words = _words(q)
    msg_forms = (forged_message.hex(), base64.b64encode(forged_message).decode(), "0x" + forged_message.hex())
    dig_forms = (forged_hex,) + ((forged_hex.upper(),) if re.search(r"\bupper-?case\b", words, re.I) else ()) + ("0x" + forged_hex,)
    order = (msg_forms, dig_forms) if _LE_WANTS_MESSAGE.search(words) else (dig_forms, msg_forms)
    for group in order:
        for form in group:
            if _fits(q, form):
                return form
    return None


def solve_length_ext(M: Material, q, proof: Proof = None):
    """A Merkle-Damgard length-extension forgery (C9b), PLAIN only when the delivery proves the
    premise offline: a secret of the stated length whose <algo>(secret||data) reproduces the given
    digest, so the full forgery round-trips. The algorithm is the one the text names, or -- when it
    names none -- the one whose digest length matches and whose verification holds (a sha3/blake
    digest, not length-extendable, verifies under no MD algo and yields None). Returns None on an
    unstated secret length, an ambiguous input, or no verifier -- never a guess. The deterministic
    forgery itself is lib.length_extension."""
    words = _words(q) + " " + M.all_text[:20000] + " " + " ".join(M.names)
    named = list(dict.fromkeys(a for a, rx in _LE_ALGOS if re.search(rx, words, re.I)))
    if len(named) > 1:
        return None            # the text names two algorithms: ambiguous
    # md4 shares its digest length with md5 and sha512 is new (C9b extension): the round-trip
    # verification below picks the one true algorithm, so an unnamed digest is tried against all.
    candidate_algos = named or ["md5", "sha1", "sha256", "sha512", "md4"]
    secret_lens = _lenext_secret_len(M, q)
    datas = _field_bytes(M, _LE_DATA_FIELDS)
    appends = _field_bytes(M, _LE_APPEND_FIELDS)
    secrets = _field_bytes(M, _LE_SECRET_FIELDS)
    if len(secret_lens) != 1 or not datas or not appends or not secrets:
        return None            # the length must be stated once, and a secret must be present to verify
    secret_len = secret_lens[0]
    found = {}
    for algo in candidate_algos:
        digests = _lenext_digest(M, q, algo)
        if len(digests) != 1:
            continue
        orig_digest = digests[0]
        for secret in secrets:
            if len(secret) != secret_len:
                continue
            for data in datas:
                if not lib.length_extension_verified(algo, secret, data, orig_digest):
                    continue       # the hash round-trip proves both the premise AND the algorithm
                for appd in appends:
                    try:
                        forged_message, forged_hex = lib.length_extension(algo, orig_digest, data, appd, secret_len)
                    except ValueError:
                        continue
                    if lib.md_hash(algo, secret + forged_message).hex() != forged_hex:
                        continue
                    ans = _lenext_answer(q, forged_hex, forged_message)
                    if ans is not None:
                        found.setdefault(ans, ans)
    return next(iter(found.values())) if len(found) == 1 else None


# ---- MD5 / SHA-1 collision detection (C9c) ----------------------------------------------------------------
# A FINDING: two or more delivered members that share an MD5 or SHA-1 digest. Every answer is read
# straight from the bytes and gated on a collision actually being present, so a plain answer can never
# be wrong. The construction method/tool (fastcoll, UniColl, SHAttered, chosen-prefix) is NOT named:
# it is not byte-provable here. The first-difference offset is a candidates pick (byte vs block vs
# index are different readings of the fact); the count of colliding members and the count of differing
# 64-byte blocks are byte-unambiguous integers.

_COLL_ALGO_SPELL = {
    "md5": [("md5", "md5"), ("md_5", "md-5"), ("md5_upper", "MD5")],
    "sha1": [("sha1", "sha1"), ("sha_1", "sha-1"), ("sha1_upper", "SHA1"), ("sha_1_upper", "SHA-1")],
}
_COLL_COUNT_PHRASE = re.compile(r"\b(?:how many|number of|count of|total (?:number )?of)\b", re.I)
_COLL_FILE_NOUN = re.compile(r"\b(?:files?|inputs?|members?|messages?|objects?|samples?|documents?)\b", re.I)
# a count noun that, standing between the count phrase and the file-noun, is the REAL counted subject:
# "how many BYTES do the two colliding files share" counts bytes, not files
_COLL_COUNT_NOUN = re.compile(r"\b(?:bytes?|blocks?|bits?|char(?:acter)?s?|digits?|nibbles?|words?|pairs?|"
                              r"differences?|positions?|offsets?|rounds?)\b", re.I)


def _wants_file_count(words: str) -> bool:
    """True only when a count phrase ('how many', 'number of', ...) counts the FILE-noun itself: the
    file-noun is the first countable noun after the phrase and no competing count noun (bytes, blocks,
    bits, characters, ...) sits between the phrase and it. So 'how many colliding files' is a file
    count, while 'how many bytes do the two colliding files share as a common prefix' is NOT (it
    counts bytes) and must not take the member count."""
    m = _COLL_COUNT_PHRASE.search(words)
    if not m:
        return False
    rest = words[m.end(): m.end() + 60]
    fm = _COLL_FILE_NOUN.search(rest)
    if not fm:
        return False
    return not _COLL_COUNT_NOUN.search(rest[:fm.start()])


_COLL_BLOCK = re.compile(r"\bblocks?\b", re.I)
_COLL_HOWMANY = re.compile(r"\b(?:how many|number of|count of)\b", re.I)
_COLL_DIFFWORD = re.compile(r"\b(?:differ\w*|diverge\w*|colliding|collision|modified|changed|altered|distinct)\b", re.I)
# the offset fact needs an explicit place word (offset/position/index/location) or a "first differ"
# phrase -- never the bare word "collision", which every question in this intent carries
_COLL_OFFSET = re.compile(r"\b(?:offset|position|location)\b|\b(?:byte|block)\s+index\b"
                          r"|\bwhere\b[^.?\n]{0,30}\b(?:differ|diverge)"
                          r"|\b(?:first|starting|initial)\b[^.?\n]{0,30}\b(?:differ\w*|diverge\w*|difference)\b", re.I)
_COLL_ALGO_ASK = re.compile(r"\b(?:which|what|name|identify)\b[^.?\n]{0,48}\b(?:hash(?:ing)?|algorithm|digest|function)\b"
                            r"|\b(?:hash|digest)\s+(?:algorithm|type|function)\b", re.I)
_COLL_PAIRS = re.compile(r"\bpairs?\b", re.I)


def _collision_algo_pick(q, algo: str):
    """An UNSURE pick over the spellings of the ONE hash the files collide under (never plain: md5 /
    sha1 is the judge's own vocabulary)."""
    opts = [(n, v) for n, v in _COLL_ALGO_SPELL.get(algo, [(algo, algo)]) if _fits(q, v)]
    return _pick(f"{KEY}.collision_algo/{algo}", opts)


def solve_collision(M: Material, q):
    """An MD5/SHA-1 collision finding, answered ONLY when the delivery really holds a collision
    (lib.hash_collisions proves it by recomputing the digests): the number of colliding members or
    of differing 64-byte blocks plain (byte-unambiguous, kind=integer), the first-difference offset
    as a candidates pick (byte/block/index readings), the hash algorithm as an unsure pick. The
    construction method is never named. None when no collision is present, the question is ambiguous,
    or the fact is not proven."""
    cols = lib.hash_collisions(getattr(M, "members", None) or [])
    if not cols or str(_fmt(q).get("kind") or "") in ("ordered_tokens", "json"):
        return None
    words = _words(q)
    algos = {c["algo"] for c in cols}
    # a block-count question ("how many blocks differ") names "files" too ("the colliding files"),
    # so blocks are resolved first and a file-count needs blocks NOT to be the counted subject
    wants_blocks = bool(_COLL_BLOCK.search(words) and _COLL_HOWMANY.search(words) and _COLL_DIFFWORD.search(words))
    wants_count = _wants_file_count(words) and not wants_blocks
    wants_offset = bool(_COLL_OFFSET.search(words))
    wants_algo = bool(_COLL_ALGO_ASK.search(words))
    # the hash algorithm the files collide under: unsure, only when every finding agrees and no
    # numeric fact is also asked
    if wants_algo and not (wants_count or wants_blocks or wants_offset):
        return _collision_algo_pick(q, next(iter(algos))) if len(algos) == 1 else None
    # the numeric/structural facts need a single collision group and a single equal-length pair
    if len(cols) != 1 or len(cols[0]["pairs"]) != 1:
        return None
    c = cols[0]
    pair = c["pairs"][0]
    algo = c["algo"]
    # how many members share the digest: unambiguous integer (but not a count of pairs)
    if wants_count and not wants_blocks and not _COLL_PAIRS.search(words):
        return _int_answer(q, f"{KEY}.collision_file_count/{algo}", c["count"])
    if not pair.get("equal_length"):
        return None            # the aligned-block diff is only read for equal-length colliding files
    # how many aligned 64-byte blocks differ: unambiguous integer
    if wants_blocks and not wants_count:
        return _int_answer(q, f"{KEY}.collision_block_count/{algo}", pair["diff_block_count"])
    # where the two files first differ: byte offset, block offset or block index -- different
    # readings of one fact, so candidates only (never plain before the judge accepts a reading)
    if wants_offset and pair.get("first_diff_offset") is not None:
        opts = [("byte_offset", str(pair["first_diff_offset"]))]
        if pair.get("first_diff_block_offset") is not None:
            opts.append(("block_offset", str(pair["first_diff_block_offset"])))
            opts.append(("block_index", str(pair["first_diff_block_offset"] // 64)))
        opts = [(n, v) for n, v in opts if _fits(q, v)]
        return _candidates(f"{KEY}.collision_offset/{algo}", opts)
    return None


# ---- ECDSA, generators, hashes, JWT ----------------------------------------------------------------------

def _sig_pairs(M: Material) -> list:
    """[(r, s)] of the signatures written: r/s labels, or sig fields (DER or r||s, hex/base64)."""
    rs, ss = M.params.many("r"), M.params.many("s")
    out = []
    if rs and ss and (len(rs) == len(ss) or len(set(rs)) == 1):
        out = [(rs[i] if len(rs) == len(ss) else rs[0], s) for i, s in enumerate(ss)]
    for v in M.field("sig", "signature", "sig1", "sig2", "signature1", "signature2"):
        for reading, b in lib.blobs(v):
            if reading == "raw":
                continue
            if b[:1] == b"\x30":
                ints = lib._der_ints(b)
                if len(ints) == 2:
                    out.append((ints[0], ints[1]))
                    break
            elif len(b) == 64:
                out.append((lib.to_int(b[:32]), lib.to_int(b[32:])))
                break
    return list(dict.fromkeys(out))


def solve_ecdsa(M: Material, q):
    """(d, k, curve) of two signatures with one r, or None (lib.ecdsa_nonce_reuse's proof). The
    hashes are the written z/h values, or the hash of the written messages: the hash function is
    whichever makes the recovered nonce reproduce r, and exactly one may."""
    if "ecdsa" in M.cache:
        return M.cache["ecdsa"]
    M.cache["ecdsa"] = None
    sigs = _sig_pairs(M)
    same = {}
    for r, s in sigs:
        same.setdefault(r, []).append(s)
    pairs = [(r, ss) for r, ss in same.items() if len(ss) >= 2]
    if len(pairs) != 1:
        return None
    r, ss = pairs[0]
    idx = [i for i, (rr, _) in enumerate(sigs) if rr == r][:2]
    blob = _words(q) + " " + M.all_text[:20000] + " " + " ".join(M.names)
    curve = next((c for name, c in lib.CURVE_NAMES.items() if re.search(r"(?<![a-z0-9])" + re.escape(name) + r"(?![0-9])", blob, re.I)), None)
    public = None
    for _, k in M.keys:
        if k.get("type") == "ec" and k.get("x"):
            public = (k["x"], k["y"])
            curve = lib.CURVE_NAMES.get(str(k.get("curve") or "").lower(), curve)
    zsets = []
    zs = M.params.many("z")
    if len(zs) == len(sigs):
        zsets.append((zs[idx[0]], zs[idx[1]]))
    msgs = M.field("m1", "m2", "msg1", "msg2", "message1", "message2", "msg", "message", "m")
    if len(msgs) == len(sigs) and not zsets:
        for h in ("sha256", "sha1", "sha512", "md5", "sha384"):
            pair = []
            for i in idx:
                dg = hashlib.new(h, msgs[i].encode("utf-8")).digest()
                z = lib.to_int(dg)
                pair.append(z >> max(0, len(dg) * 8 - 256))
            zsets.append(tuple(pair))
    found = {}
    for z1, z2 in zsets:
        got = lib.ecdsa_nonce_reuse(r, ss[0], z1, ss[1], z2, curve, public)
        if got:
            found.setdefault(got[0], got)
    if len(found) == 1:
        M.cache["ecdsa"] = next(iter(found.values()))
    return M.cache["ecdsa"]


def solve_dsa(M: Material, q):
    """The DSA (finite-field) private key x of two signatures with one r, or None. Needs the written
    domain parameters p, q, g and the public key y; the hash is the written z values, or the hash
    of the written messages cut to q's size (whichever function reproduces r, and exactly one x may
    come out). lib.dsa_nonce_reuse proves it: pow(g, k, p) % q == r and pow(g, x, p) == y."""
    if "dsa" in M.cache:
        return M.cache["dsa"]
    M.cache["dsa"] = None

    def ints(*names):
        out = []
        for n in names:
            out += _field_ints(M, n) + M.params.many(n)
        return list(dict.fromkeys(out))

    ps, qs, gs = ints("p", "dsa_p"), ints("q", "dsa_q"), ints("g", "dsa_g")
    ys = ints("y", "pub", "public", "public_key", "pubkey")
    if len(ps) != 1 or len(qs) != 1 or len(gs) != 1 or len(ys) != 1:
        return None
    p_, q_, g_, y_ = ps[0], qs[0], gs[0], ys[0]
    sigs = _sig_pairs(M)
    same = {}
    for r, s_ in sigs:
        same.setdefault(r, []).append(s_)
    pairs = [(r, ss) for r, ss in same.items() if len(ss) >= 2]
    if len(pairs) != 1:
        return None
    r, ss = pairs[0]
    idx = [i for i, (rr, _) in enumerate(sigs) if rr == r][:2]
    qbits = q_.bit_length()
    zsets = []
    zs = M.params.many("z") + [z for z in _field_ints(M, "h") if z not in M.params.many("z")]
    if len(zs) == len(sigs):
        zsets.append((zs[idx[0]], zs[idx[1]]))
    msgs = M.field("m1", "m2", "msg1", "msg2", "message1", "message2", "msg", "message", "m")
    if len(msgs) == len(sigs) and not zsets:
        for h in ("sha256", "sha1", "sha512", "md5", "sha384", "sha224"):
            pair = []
            for i in idx:
                dg = hashlib.new(h, msgs[i].encode("utf-8")).digest()
                z = lib.to_int(dg)
                pair.append(z >> max(0, len(dg) * 8 - qbits))
            zsets.append(tuple(pair))
    found = set()
    for z1, z2 in zsets:
        x = lib.dsa_nonce_reuse(p_, q_, g_, y_, (r, ss[0], z1), (r, ss[1], z2))
        if x is not None:
            found.add(x)
    if len(found) == 1:
        M.cache["dsa"] = (next(iter(found)), qbits)
    return M.cache["dsa"]


# ---- AES-GCM nonce-reuse forgery (wave124) ---------------------------------------------------------------

def _blob_bytes(value, lengths=None, prefer=("hex", "base64", "base64url")):
    """The bytes of a written blob (hex/base64), the first reading that fits a
    wanted length (or any non-raw reading). None when nothing decodes."""
    best = None
    for reading, b in lib.blobs(value):
        if reading == "raw":
            continue
        if lengths and len(b) in lengths:
            return b
        if best is None and (reading in prefer or best is None):
            best = b
    return None if lengths else best


_CT_NAME = re.compile(r"^(?:ciphertext|ct|c)(?:[_-]?(\d+|[a-z]))?$", re.I)
_TAG_NAME = re.compile(r"^(?:auth(?:entication)?[_-]?tag|tag|mac|gmac|t)(?:[_-]?(\d+|[a-z]))?$", re.I)
_AAD_NAME = re.compile(r"^(?:aad|ad|associated[_-]?data|additional[_-]?data|header)(?:[_-]?(\d+|[a-z]))?$", re.I)


def _order_key(token):
    if token is None:
        return (0, "")
    token = str(token)
    return (int(token), "") if token.isdigit() else (0, token.lower())


def _named_blobs(M: Material, rx, lengths=None):
    """(order, bytes) for every field whose name matches `rx`, decoded as a blob,
    sorted by the trailing index/letter so pairs line up."""
    out = []
    for name, vals in M.fields.items():
        mm = rx.match(name)
        if not mm:
            continue
        for v in vals:
            b = _blob_bytes(v, lengths=lengths)
            if b is not None and len(b) <= MAX_BLOB:
                out.append((_order_key(mm.group(1)), b))
                break
    out.sort(key=lambda it: it[0])
    return [b for _, b in out]


def _gcm_pairs(M: Material):
    """[(aad_bytes, ct_bytes, tag_bytes)] read from the delivery: ciphertext and
    tag fields (ct/ciphertext/c1/c2/.., tag/tag1/tag2/mac/..), aad optional, each
    sorted by its trailing index. The nonce is not read: the forbidden attack
    needs only that the pairs share one key+nonce, and gcm_recover_subkey
    verifies that by reproducing every tag -- so a wrong pairing yields nothing."""
    cts = _named_blobs(M, _CT_NAME)
    tags = _named_blobs(M, _TAG_NAME, lengths={16})
    aads = _named_blobs(M, _AAD_NAME)
    if len(cts) < 2 or len(tags) < 2 or len(cts) != len(tags):
        return []
    if aads and len(aads) != len(cts):
        aads = []
    return [(aads[i] if aads else b"", cts[i], tags[i]) for i in range(len(cts))]


def solve_gcm(M: Material, q):
    """Recover the AES-GCM authentication subkey H by the forbidden attack and,
    when a target message is given, a forged tag. Returns a dict cached on M:
      {"H": [int, ...], "unique": bool, "forge": {"aad":bytes,"ct":bytes} or None,
       "forged_tag": bytes or None}
    or None when there is no nonce-reuse material or nothing verifies. Nothing
    here is ever emitted plain: H and a forged tag are the author's bytes, under
    a name the judge has not shown, so the caller offers them unsure only."""
    if depth is None:
        return None
    if "gcm" in M.cache:
        return M.cache["gcm"]
    M.cache["gcm"] = None
    pairs = _gcm_pairs(M)
    if len(pairs) < 2:
        return None
    try:
        got = depth.gcm_recover_subkey(pairs)
    except Exception:
        return None
    if not got:
        return None
    Hs = [h for h, _ in got]
    unique = len(Hs) == 1 and len(pairs) >= 3
    result = {"H": Hs, "unique": unique, "forge": None, "forged_tag": None}
    # a forged tag, only when a single H is pinned and a target (aad, ct) is given
    if unique:
        fct = None
        for v in M.field("forge_ciphertext", "forge_ct", "target_ciphertext", "target_ct", "forged_ciphertext",
                         "chosen_ciphertext", "message_ciphertext"):
            fct = _blob_bytes(v)
            if fct is not None:
                break
        if fct is not None and len(fct) <= MAX_BLOB:
            faad = b""
            for v in M.field("forge_aad", "target_aad", "forge_ad", "chosen_aad"):
                got_aad = _blob_bytes(v)
                if got_aad is not None:
                    faad = got_aad
                    break
            try:
                h0, s0 = got[0]
                result["forge"] = {"aad": faad, "ct": fct}
                result["forged_tag"] = depth.gcm_tag(h0, s0, faad, fct)
            except Exception:
                result["forged_tag"] = None
    M.cache["gcm"] = result
    return result


_GCM_FORGE = re.compile(r"\bforge\w*\b|\bforged\b|\bvalid (?:tag|mac)\b|\bforge(?:d)? (?:a )?(?:tag|mac)\b", re.I)
_GCM_AUTHKEY = re.compile(
    r"\bghash\b|\bgmac\b|\bforbidden attack\b|\bauthentication\s+(?:sub)?key\b|\bauth\s+(?:sub)?key\b"
    r"|\bsubkey\s+h\b|\bhash\s+(?:sub)?key\b|\b(?:value of|recover|find|what is)\s+(?:the\s+)?(?:gcm\s+)?[`'\"]?h[`'\"]?(?![\w-])", re.I)


_KW_ASK = re.compile(r"\bunwrap\w*|\bkey[- ]?wrap\w*|\baes[- ]?kwp?\b|\brfc[- ]?(?:3394|5649)\b|\bkwp?\b", re.I)


def solve_keywrap(M: Material) -> list:
    """[(mode, kek, wrapped, unwrapped)] for every KEK and wrapped blob the delivery labels, kept ONLY
    when the RFC 3394 integrity register (KW) or the RFC 5649 AIV, length and zero padding (KWP) verify
    in code. A wrong KEK or a changed byte leaves nothing."""
    if "keywrap" in M.cache:
        return M.cache["keywrap"]
    keks = [b for v in M.field("kek", "wrapping_key", "wrap_key", "key") for r, b in lib.blobs(v) if len(b) in (16, 24, 32)]
    keks += [k["k"] for _, k in M.keys if k.get("type") == "oct" and len(k["k"]) in (16, 24, 32)]
    wr = [b for v in M.field("wrapped", "wrapped_key", "wrapped_flag", "wrapped_secret", "wrapped_data", "wrapped_ct")
          for r, b in lib.blobs(v) if r != "raw" and len(b) % 8 == 0 and len(b) >= 16]
    wr += [b for b in _cts(M) if len(b) % 8 == 0 and len(b) >= 16 and b not in wr]
    out = []
    for kek in list(dict.fromkeys(keks))[:6]:
        for w in wr[:6]:
            for mode, fn in (("kw", lib.aes_kw_unwrap), ("kwp", lib.aes_kwp_unwrap)):
                pt = fn(kek, w)
                if pt is not None:
                    out.append((mode, kek, w, pt))
    M.cache["keywrap"] = out
    return out


def _keywrap_answer(q, M: Material, words: str, proof: Proof):
    """The unwrapped key as an UNSURE pick (its written form is the author's choice), only for a
    question that asks to unwrap, only when exactly one distinct value passed the key-wrap integrity
    check, and only when it is no readable text (readable text goes the ordinary decrypt road, plain
    under the question's own proof). Else None (fall through)."""
    if not _KW_ASK.search(words):
        return None
    got = solve_keywrap(M)
    vals = list(dict.fromkeys(g[3] for g in got))
    if len(vals) != 1 or proof.judge(vals[0]):
        return None
    k = vals[0]
    forms = [("hex", k.hex()), ("hex_upper", k.hex().upper()), ("0x_hex", "0x" + k.hex()), ("base64", base64.b64encode(k).decode())]
    return _pick(f"{KEY}.aeskw/unwrapped_key", [(n, v) for n, v in forms if _fits(q, v)])


def _gcm_answer(q, M: Material, words: str):
    """The GCM forbidden-attack answer for one question, or None (fall through).
    Fires only when the question asks for the GCM authentication key H or a forged
    tag AND two or more ciphertext+tag pairs are present, so no other question is
    ever intercepted."""
    qt = _qtext(q)
    wants_key = bool(_GCM_AUTHKEY.search(words))
    wants_forge = bool(_GCM_FORGE.search(words)) and re.search(r"\bgcm\b|\bgmac\b|\bghash\b", words, re.I)
    if not (wants_key or wants_forge):
        return None
    got = solve_gcm(M, q)
    if not got:
        return None
    if wants_forge and got.get("forged_tag") is not None:
        tag = got["forged_tag"]
        forms = [("hex", tag.hex()), ("hex_upper", tag.hex().upper()), ("0x_hex", "0x" + tag.hex()),
                 ("base64", base64.b64encode(tag).decode())]
        return _pick(f"{KEY}.gcm/forged_tag", [(n, v) for n, v in forms if _fits(q, v)])
    if wants_key:
        Hs = got["H"]
        if not Hs:
            return None
        if got["unique"]:
            h = Hs[0]
            blk = h.to_bytes(16, "big")
            forms = [("hex", blk.hex()), ("hex_upper", blk.hex().upper()), ("0x_hex", "0x" + blk.hex()),
                     ("decimal", str(h)), ("base64", base64.b64encode(blk).decode())]
            return _pick(f"{KEY}.gcm/auth_key", [(n, v) for n, v in forms if _fits(q, v)])
        # several candidate roots, nothing to pin one: each is a DIFFERENT value
        opts = []
        for i, h in enumerate(Hs[:MAX_OPTIONS]):
            blk = h.to_bytes(16, "big")
            val = blk.hex()
            if _fits(q, val):
                opts.append((f"root_{i}", val))
        return _candidates(f"{KEY}.gcm/auth_key_candidate", opts) if opts else None
    return None


# ---- ECDSA biased-nonce key recovery, the Hidden Number Problem (wave124) ----------------------------------

def _hnp_leak_bits(M: Material, q, nbits: int):
    """Candidate nonce bit-lengths L (k < 2^L) stated by the question or fields.
    'nonce is 128 bits' -> 128; 'top 128 bits are zero/known' -> nbits-128."""
    blob = " ".join([_qtext(q), M.all_text[:20000]] + list(M.fields))
    cands = []
    for mm in re.finditer(r"(?:nonce|k|ephemeral)[^.?\n]{0,40}?(\d{1,3})[\s-]*bit", blob, re.I):
        cands.append(int(mm.group(1)))
    for mm in re.finditer(r"(\d{1,3})[\s-]*bit[^.?\n]{0,30}?(?:nonce|k\b|ephemeral)", blob, re.I):
        cands.append(int(mm.group(1)))
    for mm in re.finditer(r"(?:top|high|upper|most significant|msb|leading)[^.?\n]{0,30}?(\d{1,3})[\s-]*bit", blob, re.I):
        cands.append(nbits - int(mm.group(1)))
    for mm in re.finditer(r"(?:top|high|upper|leading)[^.?\n]{0,6}(\d{1,3})\b", blob, re.I):
        cands.append(nbits - int(mm.group(1)))
    for mm in re.finditer(r"2\s*\^\s*\{?\s*(\d{1,3})", blob):
        cands.append(int(mm.group(1)))
    for name in ("nonce_bits", "k_bits", "leak_bits", "known_bits", "bias_bits", "msb", "msb_bits"):
        for v in M.field(name):
            try:
                cands.append(int(str(v).strip()))
            except ValueError:
                pass
    out, seen = [], set()
    for c in cands:
        if 1 <= c < nbits and c not in seen:
            seen.add(c)
            out.append(c)
    return out[:3]


def _hnp_derived(text: str) -> bool:
    """_DERIVED, but after removing the nonce-leak size phrases ('the nonces are
    only 128 bits', 'top 128 bits known', '2^128'), so stating the leak does not
    look like a question that asks for a value computed from d."""
    t = re.sub(r"(?:nonces?|ephemeral|\bk\b|leak\w*|bias\w*|known|msb|lsb|top|high|upper|lower|leading|trailing|most significant)"
               r"[^.?\n]{0,45}?\d{1,3}[\s-]*bits?", " ", text, flags=re.I)
    t = re.sub(r"\d{1,3}[\s-]*bits?[^.?\n]{0,30}?(?:nonces?|ephemeral|\bk\b|leak\w*|bias\w*|known|zero)", " ", t, flags=re.I)
    t = re.sub(r"2\s*\^\s*\{?\s*\d{1,3}", " ", t)
    return bool(_DERIVED.search(t))


def solve_ecdsa_hnp(M: Material, q, deadline=None):
    """(d, curve name) recovered from biased/partial ECDSA nonces via the Hidden
    Number Problem, or None. The private scalar d is accepted ONLY when d*G ==
    the given public key (crypto_depth.ecdsa_hnp_recover's guard), on secp256k1
    or P-256; so a wrong lattice reduction or a misread leak can only give None."""
    if depth is None:
        return None
    if "ecdsa_hnp" in M.cache:
        return M.cache["ecdsa_hnp"]
    M.cache["ecdsa_hnp"] = None
    sigs = _sig_pairs(M)
    if len(sigs) < 3:               # HNP needs several signatures to reduce
        return None
    # a public key is mandatory for the never-wrong check
    public, curve = None, None
    for _, k in M.keys:
        if k.get("type") == "ec" and k.get("x"):
            public = (k["x"], k["y"])
            curve = lib.CURVE_NAMES.get(str(k.get("curve") or "").lower())
    if public is None:
        px, py = M.params.one("x"), M.params.one("y")
        if px is not None and py is not None:
            public = (px, py)
    if public is None:
        return None
    blob = _words(q) + " " + M.all_text[:20000] + " " + " ".join(M.names)
    if curve is None:
        curve = next((c for name, c in lib.CURVE_NAMES.items()
                      if re.search(r"(?<![a-z0-9])" + re.escape(name) + r"(?![0-9])", blob, re.I)), None)
    curves = [curve] if curve else ["secp256k1", "secp256r1"]
    # z per signature: written z values aligned with the signatures, else the
    # hash of written messages
    zs = M.params.many("z")
    zlists = []
    if len(zs) == len(sigs):
        zlists.append(zs)
    msgs = M.field("message", "msg", "m", "messages")
    if len(msgs) == len(sigs) and not zlists:
        for h in ("sha256", "sha1", "sha512"):
            lst = []
            for mtext in msgs:
                dg = hashlib.new(h, mtext.encode("utf-8")).digest()
                z = lib.to_int(dg)
                lst.append(z >> max(0, len(dg) * 8 - 256))
            zlists.append(lst)
    if not zlists:
        return None
    # The lattice reduction needs ~0.5 s for a handful of signatures; it is run
    # at most once per set (cached) and only on genuine HNP material, so give it
    # a budget of its own rather than the tight per-question one.
    now = time.monotonic()
    want = max(now + HNP_BUDGET, deadline if deadline is not None else 0.0)
    for name in curves:
        key = lib.CURVE_NAMES.get(str(name or "").lower(), name)
        if key not in depth.CURVES:
            continue
        n = depth.CURVES[key]["n"]
        for L in _hnp_leak_bits(M, q, n.bit_length()):
            for zlist in zlists:
                if time.monotonic() > want:
                    return None
                triples = [(sigs[i][0], sigs[i][1], zlist[i]) for i in range(len(sigs))]
                try:
                    d = depth.ecdsa_hnp_recover(key, public, triples, L, deadline=want)
                except Exception:
                    d = None
                if d is not None:
                    M.cache["ecdsa_hnp"] = (d, key)
                    return M.cache["ecdsa_hnp"]
    return None
# ---- weak-curve private-scalar recovery (solvers/common/ecc_weak.py) --------------------------------

_EC_NUM = r"(?:0[xX][0-9a-fA-F]+|[0-9]+)"
_EC_POINT = re.compile(r"(?<![A-Za-z0-9_])((?:public|base|private|secret|the)[ _])?([A-Za-z][A-Za-z_]{0,13})"
                       r"\s*(?:=|:|:=)?\s*\(\s*(" + _EC_NUM + r")\s*,\s*(" + _EC_NUM + r")\s*\)", re.I)
_EC_COMP = re.compile(r"(?<![A-Za-z0-9_])([A-Za-z][A-Za-z_]{0,9})[._ ]?([xXyY])\s*(?:=|:|:=)\s*(" + _EC_NUM + r")")
_EC_BASE_LABELS = ("g", "generator", "base", "basepoint", "base_point", "gen", "point", "p")
_EC_PUB_LABELS = ("q", "pub", "public", "publickey", "public_key", "pubkey", "pk", "pubpoint", "public_point")


def _ecint(s: str) -> int:
    s = s.strip()
    return int(s, 16) if s[:2].lower() == "0x" else int(s)


def _ec_scalar(text: str, names):
    """The single distinct value written for any of `names` (`p = ..`, `order: ..`, `#E = ..`), or
    None when none or several different values are written (ambiguous: never guessed)."""
    rx = re.compile(r"(?<![A-Za-z0-9_])(?:" + "|".join(names) + r")\s*(?:=|:=|:)\s*(" + _EC_NUM + r")", re.I)
    vals = {_ecint(m.group(1)) for m in rx.finditer(text)}
    return next(iter(vals)) if len(vals) == 1 else None


def _read_curve(M: Material, q):
    """(p, a, b, order, G, Q) read from the material, or None. Short Weierstrass y^2=x^3+ax+b over
    F_p; G the base point, Q = [d]G the public point, order optional. Declines unless p, a, b and
    both points resolve to a single value each (ambiguity is None, not a guess)."""
    text = (M.all_text + "\n" + _qtext(q))[:400000]
    p = _ec_scalar(text, [r"modulus", r"prime modulus", r"field prime", r"field_prime", r"prime", r"p"])
    a = _ec_scalar(text, [r"coefficient a", r"coeff a", r"coefficient_a", r"a4", r"a"])
    b = _ec_scalar(text, [r"coefficient b", r"coeff b", r"coefficient_b", r"a6", r"b"])
    order = _ec_scalar(text, [r"\#e", r"group order", r"group_order", r"curve order", r"curve_order",
                              r"cardinality", r"order", r"n"])
    pairs, comps = {}, {}
    for m in _EC_POINT.finditer(text):
        qual = (m.group(1) or "").strip().replace(" ", "_").lower().strip("_")
        word = m.group(2).lower()
        pt = (_ecint(m.group(3)), _ecint(m.group(4)))
        labs = {word} if qual in ("", "the") else {qual + "_" + word, word}
        for lab in labs:
            pairs.setdefault(lab, pt)
    for m in _EC_COMP.finditer(text):
        comps.setdefault(m.group(1).lower(), {})[m.group(2).lower()] = _ecint(m.group(3))

    def resolve(labels):
        got = set()
        for lab in labels:
            if lab in pairs:
                got.add(pairs[lab])
            elif lab in comps and {"x", "y"} <= set(comps[lab]):
                got.add((comps[lab]["x"], comps[lab]["y"]))
        return next(iter(got)) if len(got) == 1 else None

    G = resolve(_EC_BASE_LABELS)
    Q = resolve(_EC_PUB_LABELS)
    if p is None or a is None or b is None or G is None or Q is None or G == Q:
        return None
    return p, a, b, order, G, Q


def solve_ecc(M: Material, q, deadline=None):
    """(d, weakness) with [d]G == Q proven on a weak curve, or None. The scalar is emitted only
    after ec_weak.recover_scalar checks d*G == Q, so a wrong value is never returned (the lib tries
    the singular, anomalous and smooth-order routes and verifies each)."""
    if eccw is None:
        return None
    if "ecc_weak" in M.cache:
        return M.cache["ecc_weak"]
    M.cache["ecc_weak"] = None
    got = _read_curve(M, q)
    if not got:
        return None
    p, a, b, order, G, Q = got
    try:
        d = eccw.recover_scalar(p, a, b, G, Q, order=order, deadline=deadline)
    except Exception:               # the maths declining is no answer
        d = None
    if d is None:
        return None
    M.cache["ecc_weak"] = (d, eccw.weakness(p, a, b, order))
    return M.cache["ecc_weak"]


def _hash_strings(M: Material, q) -> list:
    out = []
    for text in [_qtext(q)] + [t for n, t in M.texts if n != "<question>"]:
        for m in re.finditer(r"(?<![0-9A-Za-z$./])(\$[0-9a-zA-Z-]{1,16}\$[^\s\"']{8,200}|[0-9a-fA-F]{32,128})(?![0-9A-Za-z])", text[:200000]):
            v = m.group(1)
            if lib.hash_candidates(v) and v not in out:
                out.append(v)
    return out


def _jwt_strings(M: Material) -> list:
    cands = []
    for _, text in M.texts:
        for line in text.splitlines()[:5000]:
            line = line.strip()
            if line:
                cands.append(line)
                cands += re.findall(r"[^\s\"'=:,;]{3,128}", line)[:50]
    for vals in M.fields.values():
        cands += vals
    out = []
    for c in dict.fromkeys(cands):
        if len(out) >= 60000:
            break
        out.append(c.encode("utf-8"))
    return out


# ---- one question -------------------------------------------------------------------------------------------

_INTENTS = (
    # TOTP/HOTP (RFC 6238 / RFC 4226): compute a code from a base32 secret / otpauth URI and a
    # stated time or counter. Deterministic given the time; answered unsure (padding unjudged).
    # First: HOTP = "HMAC-based one-time password" would otherwise match hmac_struct, and its
    # "shared secret" would match shamir.
    ("otp", r"\b(?:totp|hotp|otpauth)\b|\b(?:time[- ]based|hmac[- ]based|counter[- ]based)\s+(?:one[- ]time\s+)?(?:password|code|otp)\b"
            r"|\bone[- ]time\s+password\b|\b2fa\b|\btwo[- ]factor\b|\b(?:authenticator|google authenticator)\s+(?:code|app|secret|seed)\b"),
    # Shamir Secret Sharing (buildlist, modern_crypto): reconstruct f(0) from shares over a prime
    # field or GF(256). The secret is proven by over-determination; answered unsure (form unjudged).
    # Early: its words ("recover the secret", "shares") overlap plaintext and hmac. It requires an
    # explicit share/shard/threshold/lagrange context so an ordinary "recover the secret" is not it.
    ("shamir", r"\bshamir\b|\bsss\b|\bsecret[- ]shar\w*\b|\bkey[- ]shar\w*\b"
               r"|\b(?:reconstruct\w*|recombin\w*|reassembl\w*|combin\w*|recover\w*|rebuild\w*|merg\w*)\b[^.?]{0,40}\b(?:shares?|shards?)\b"
               r"|\b(?:shares?|shards?)\b[^.?]{0,40}\b(?:threshold|lagrange|reconstruct\w*|recombin\w*|combin\w*|interpolat\w*|secret)\b"
               r"|\blagrange\b|\bthreshold\b[^.?]{0,40}\bshares?\b"),
    ("jwt_secret", r"\b(?:jwt|json web token|token)\b.*\b(?:secret|signing key|hmac key|key (?:used )?to sign|signed with)\b|\b(?:secret|signing key)\b.*\b(?:jwt|token)\b"),
    ("jwt_alg", r"\b(?:jwt|json web token|token)\b.*\b(?:alg|algorithm)\b|\b(?:alg|algorithm)\b.*\b(?:jwt|token)\b"),
    ("jwt_claim", r"\b(?:jwt|json web token|token)\b.*\b(?:claim|payload|field|header)\b|\b(?:claim)\b"),
    # AES-GCM nonce-reuse (wave124): GCM-specific wording only, so a generic
    # "forge a MAC" (length extension) or "HMAC authentication key" is untouched.
    # The answer is produced by answer()'s material-gated special case, not here;
    # this entry only makes solve_set hand the question to answer() at all.
    ("gcm", r"\bghash\b|\bgmac\b|\bforbidden attack\b"
            r"|\b(?:authentication|hash)\s+subkey\b|\bsubkey\s+h\b"
            r"|\b(?:gcm|gmac|ghash)\b[^.?]{0,90}\b(?:authentication|auth)[\s-]*(?:sub)?key\b"
            r"|\b(?:authentication|auth)[\s-]*(?:sub)?key\b[^.?]{0,90}\b(?:gcm|gmac|ghash)\b"
            r"|\b(?:gcm|gmac|ghash)\b[^.?]{0,100}\b(?:forge\w*|forged)\b"
            r"|\b(?:forge\w*|forged)\b[^.?]{0,100}\b(?:gcm|gmac|ghash)\b"
            r"|\b(?:gcm|gmac|ghash)\b[^.?]{0,90}\bnonce[- ]?reuse\b"
            r"|\bnonce[- ]?reuse\b[^.?]{0,90}\b(?:gcm|gmac|ghash)\b"),
    ("ecc_d", r"\b(?:elliptic[- ]?curve|ecdlp|ecc|weak curve|anomalous|singular|smooth[- ]?order|pohlig[- ]?hellman|smart'?s? attack|discrete log(?:arithm)?)\b"
              r".{0,80}\b(?:private key|secret key|signing key|private scalar|secret scalar|scalar|multiplier|discrete log(?:arithm)?)\b"
              r"|\b(?:private key|secret key|signing key|private scalar|secret scalar|scalar)\b"
              r".{0,80}\b(?:elliptic[- ]?curve|ecdlp|weak curve|anomalous|singular|smooth[- ]?order|pohlig[- ]?hellman|discrete log(?:arithm)?)\b"
              r"|\brecover\b.{0,40}\b(?:private )?scalar\b.{0,40}\b(?:curve|point)\b"),
    ("ecdsa_d", r"\b(?:ecdsa|nonce|signatures?)\b.*\b(?:private key|secret key|signing key|private scalar)\b|\b(?:private key|signing key)\b.*\b(?:ecdsa|nonce|signatures?)\b"),
    ("ecdsa_k", r"\b(?:ecdsa|signatures?)\b.*\bnonce\b|\bnonce\b.*\b(?:ecdsa|signatures?)\b|\b(?:reused|repeated|shared) nonce\b|\bnonce\b.*\b(?:reused|repeated)\b"),
    ("mt_next", r"\b(?:mersenne|mt19937|twister|getrandbits)\b"),
    ("pcg_next", r"\bpcg(?:32|64)?\b|\bpermuted[\s_-]?congruential\b"),
    ("xorshift_next", r"\bxor[\s_-]?shift\d*\+?\b|\bxorshift\b"),
    ("lcg_next", r"\b(?:lcg|linear congruential)\b"),
    # MD5 / SHA-1 collision detection (C9c): a question about two or more inputs that share a hash.
    # Answered only when the delivery really holds such a collision (solve_collision); the method is
    # never named.
    ("collision", r"\bcollisions?\b|\bcolliding\b|\bcollide[sd]?\b"
                  r"|\b(?:same|identical|equal|matching|shared|common)\s+(?:md-?5|sha-?1|hash(?:\s+value)?|digest|checksum|fingerprint)\b"
                  r"|\b(?:md-?5|sha-?1|hash|digest|checksum)\s+collisions?\b"
                  r"|\bshares?\s+(?:the\s+|a\s+|an\s+)?(?:same\s+|identical\s+)?(?:md-?5|sha-?1|hash|digest|checksum|fingerprint)\b"),
    ("hash_type", r"\b(?:which|what|identify|name)\b.{0,60}\bhash(?:ing)?\b.{0,20}\b(?:algorithm|type|function|kind)\b|\bhash (?:type|algorithm)\b|\btype of hash\b"),
    ("ecb_line", r"\bwhich\b.{0,40}\b(?:line|ciphertext|row|entry|one)\b.{0,80}\becb\b|\becb\b.{0,80}\bwhich\s+(?:line|ciphertext|row|entry|one)\b"
                 r"|\bline (?:number|index)\b.{0,80}\becb\b|\becb\b.{0,60}\bline (?:number|index)\b"),
    ("ecb_count", r"\bhow many\b.{0,60}\b(?:duplicate|repeat|identical)\w*\b.{0,30}\bblocks?\b|\b(?:number|count) of\b.{0,30}\b(?:duplicate|repeat|identical)\w*\b.{0,30}\bblocks?\b"),
    ("mode", r"\b(?:block cipher mode|mode of operation|cipher mode|which mode|what mode)\b"),
    ("rsa_bits", r"\b(?:how many bits|bit[- ]?length|key (?:size|length)|modulus (?:size|length)|size of the modulus)\b"),
    ("rsa_d", r"\bprivate exponent\b|\b(?:value of|compute|recover|find|what is)\s+(?:the\s+)?[`'\"]?d[`'\"]?(?![\w-])"),
    ("rsa_phi", r"\b(?:phi|totient)\b"),
    ("rsa_small", r"\b(?:smaller|smallest|lesser) (?:prime|factor)\b"),
    ("rsa_large", r"\b(?:larger|largest|greater|bigger) (?:prime|factor)\b"),
    ("rsa_p", r"\b(?:value of|recover|find|what is)\s+(?:the\s+)?(?:prime\s+)?[`'\"]?p[`'\"]?(?![\w-])"),
    ("rsa_q", r"\b(?:value of|recover|find|what is)\s+(?:the\s+)?(?:prime\s+)?[`'\"]?q[`'\"]?(?![\w-])"),
    ("rsa_factors", r"\b(?:prime factors|factors of|factori[sz]e|factori[sz]ation of|p and q)\b"),
    ("rsa_e", r"\bpublic exponent\b|\b(?:value of|what is)\s+(?:the\s+)?[`'\"]?e[`'\"]?(?![\w-])"),
    ("paillier_plain", r"\bpaillier\b.{0,100}\b(?:decrypt\w*|plaintext|message|recover\w*)\b"
                       r"|\b(?:decrypt\w*|plaintext|message|recover\w*)\b.{0,100}\bpaillier\b"),
    ("rabin_plain", r"\brabin\b.{0,100}\b(?:decrypt\w*|plaintext|message|roots?|recover\w*)\b"
                    r"|\b(?:decrypt\w*|plaintext|message|roots?|recover\w*)\b.{0,100}\brabin\b"),
    ("attack", r"\b(?:which|what|name)\b.{0,40}\b(?:attack|weakness|vulnerability|flaw|technique)\b|\b(?:attack|weakness|vulnerability) (?:name|type|class)\b"),
    ("xor_key", r"\b(?:what|which)\b[^.?]{0,30}\b(?:xor[- ])?key\b|\b(?:find|recover|identify|determine|submit|give)\s+the\s+"
                r"(?:(?:xor|single[- ]byte|repeating|encryption)[- ]?\s*)*key\b"),
    # classical ciphers (backlog row 88): identification, then solving a named one, then encoding
    # chains and HMAC structure. All answered unsure-only by the classical module.
    ("hmac_struct", r"\bhmac\b"),
    ("classical_identify", r"\b(?:which|what(?:\s+kind| type)?|identify|name)\b[^.?]{0,40}\b(?:classical cipher|cipher|cypher|encoding scheme|encoding)\b"),
    ("classical_solve", r"\b(?:caesar|rot-?13|rot-?47|vigen[eè]re|vigenere|substitution cipher|monoalphabetic|atbash|affine cipher|"
                        r"rail[- ]?fence|columnar|transposition cipher|scytale|baconian|bacon'?s cipher|morse(?:\s+code)?|playfair|"
                        r"trifid|four[\s_-]*square|foursquare|two[\s_-]*square|twosquare|double[\s_-]*playfair|"
                        r"straddling[\s_-]*checkerboard|checkerboard)\b"),
    ("encoding_chain", r"\b(?:base64|base32|base16|base85|ascii85)\b|\b(?:nested|layered|multiple|several|chain of|layers of)\s+(?:encodings?|base ?64)\b"
                       r"|\bencoded (?:multiple|several|many|repeatedly|\d+)\s*times?\b"),
    # hash length extension (C9b): a Merkle-Damgard forgery, deterministic when the secret length
    # is given. Answered plain only when the premise is proven offline (solve_length_ext).
    ("length_ext", r"\blength[- ]?extension\b|\bhash[- ]?length[- ]?extension\b|\bmerkle[- ]?damg\w*\b"
                   r"|\bextend(?:ing|ed)?\s+(?:the\s+)?(?:mac|hash|hmac|digest|signature|tag)\b"
                   r"|\bforge\s+(?:a\s+|the\s+)?(?:valid\s+)?(?:mac|signature|hash|tag|digest)\b"),
    ("plaintext", r"\b(?:decrypt\w*|plaintext|plain text|cleartext|message|flag|secret|recover\w*|decipher\w*|original text|hidden)\b"),
    # AES key wrap (Day 26): LAST, so it only claims a question no earlier intent (and not the broad
    # plaintext one) already reads; _keywrap_answer or the ordinary plaintext road answers it.
    ("keywrap", r"\bunwrap\w*|\bkey[- ]?wrap\w*|\baes[- ]?kwp?\b|\brfc[- ]?(?:3394|5649)\b"),
)
# discrete logs in Z_p (Day 27, KB-10): NOT in _INTENTS. intent() names it `dlog` only when no older intent reads the question's
# words OR its answer id (fix round 4: as the last entry of _INTENTS it was tried on the question's words before the older intents
# saw the answer id's, so a question the armed tree routed by its id, `What is the shared secret?` under `rsa-flag`, changed route).
# Only the discrete-log pass of solve_set reads such a question; the older paths never see it, as on the armed tree.
_DLOG_INTENT = (r"\bdiscrete[- ]log\w*|\bdlog\b|\bdiffie[- ]?hellman\b|\bdh\b|\bel[- ]?gamal\b|\bkey (?:exchange|agreement)\b"
                r"|\bshared (?:secret|key)\b|\bg\s*\^\s*x\b|\b(?:private|secret)\s+(?:key|exponent)\b")
# A number is answered only when the question asks for the number itself. Words that ask for
# something computed from it (d mod (p-1), the last 8 digits, the sum of the digits, p minus 1,
# the SHA-256 of d, the year a token expires) leave no proven answer here.
_DERIVED = re.compile(
    r"\b(?:mod(?:ulo)?|sum|product|difference|minus|plus|times|multipl\w*|divid\w*|added|subtract\w*|squared?|cubed?|"
    r"xor(?:ed)?|digits?|bytes?|bits?|length|long|last|first|middle|leading|trailing|reversed?|encoded?|base ?64|"
    r"year|month|day|date|hours?|minutes?|seconds?|how many|how long|count|number of)\b"
    r"|\b(?:md5|sha-?\d+|hash|digest|checksum|crc\w*)\b\s*(?:hash|sum|digest)?\s*(?:\(|of\b)"
    r"|[-+*/%^]\s*\d|\)\s*(?:mod\b|[-+*/%^])", re.I)
_PRNG_ASK = r"\b(?:next|predict\w*|\d+(?:st|nd|rd|th))\b|\b(?:following|subsequent)\s+(?:output|value|number|integer)\b"
# what a generator question asks that is not its next 32-bit output
_PRNG_OTHER = re.compile(
    r"\b(?:seed\w*|modulus|multiplier|increment|state|previous|before|preceding|earlier|rand(?:range|int)|uniform|choice|shuffle|"
    r"sample|float|token_\w+|urandom|64[- ]?bits?|16[- ]?bits?|8[- ]?bits?)\b|\brandom\s*\(\s*\)|getrandbits\s*\(\s*(?!32\s*\))"
    r"|\b(?:next|following|subsequent)\s+(?:\d+|two|three|four|five|six|seven|eight|nine|ten|few|several)\b"
    r"|\b(?:outputs|values|numbers|integers)\s+(?:after|that follow)\b", re.I)


def _prng_next_asked(words: str, given: int) -> bool:
    """True when the words ask for the one output after the `given` listed ones, and nothing else."""
    if not re.search(_PRNG_ASK, words, re.I) or _PRNG_OTHER.search(words):
        return False
    ordinals = [int(v) for v in re.findall(r"\b(\d+)(?:st|nd|rd|th)\b", words)]
    if any(v != given + 1 for v in ordinals):
        return False            # the 700th output of 624 given is not the next one
    return bool(ordinals) or re.search(r"\b(?:next|predict\w*|following|subsequent)\b", words, re.I) is not None


def intent(q) -> str:
    """What one question asks, by its words and its answer id; '' when it is none of ours. `dlog` only for a question no older
    intent reads by either (Day 27, KB-10 fix round 4: every older route is the armed tree's)."""
    sources = (_words(q).lower(), re.sub(r"[-_.]+", " ", str(q.get("answer_id") or q.get("qid") or "")).lower())
    for words in sources:
        for name, rx in _INTENTS:       # the id's words only when the question's own say nothing
            if re.search(rx, words, re.I | re.S):
                return name
    for words in sources:
        if re.search(_DLOG_INTENT, words, re.I | re.S):
            return "dlog"
    return ""


_CIPHER_SYNONYMS = {
    "caesar": ["caesar", "caesar_cipher", "shift_cipher", "rot"],
    "rot13": ["rot13", "rot_13", "caesar"],
    "atbash": ["atbash", "atbash_cipher"],
    "vigenere": ["vigenere", "vigenere_cipher", "polyalphabetic", "polyalphabetic_substitution"],
    "monoalphabetic_substitution": ["substitution", "monoalphabetic_substitution", "substitution_cipher", "monoalphabetic"],
    "transposition": ["transposition", "columnar_transposition", "rail_fence", "columnar"],
    "morse": ["morse", "morse_code"],
    "baconian": ["baconian", "bacon", "baconian_cipher"],
    "encoding_chain": ["encoding", "base64", "nested_encoding"],
}


def _classical_texts(M: Material, q) -> list:
    """Candidate classical-ciphertext strings: each non-question text member, plus a quoted run or
    the text after a colon in the question itself (an inline cipher)."""
    out = []
    for name, text in M.texts:
        if name == "<question>":
            continue
        t = text.strip()
        if 8 <= len(classical._letters_only(t)) and len(t) <= classical.MAX_TEXT:
            out.append(t)
    qt = _qtext(q)
    for m in re.finditer(r"[`'\"]([^`'\"]{10,400})[`'\"]", qt):
        out.append(m.group(1).strip())
    tail = re.split(r":\s*", qt, 1)
    if len(tail) == 2 and len(classical._letters_only(tail[1])) >= 10:
        out.append(tail[1].strip())
    seen, res = set(), []
    for t in out:
        if t and t not in seen:
            seen.add(t)
            res.append(t)
    return res[:6]


def _classical_plaintext_pick(q, pt: str, proof: Proof, key: str):
    """An UNSURE pick over the forms (flag, text, flag_inner) of one classical plaintext. Classical
    answers are never plain before a judge-accepted name (backlog row 88, the task's rule)."""
    found = {"text": pt, "value": pt, "raw": pt.encode("utf-8", "ignore"), "level": 2, "plain": False}
    opts = [(n, v) for n, v in _options(found, proof) if _fits(q, v)]
    return _pick(key, opts) if opts else None


def _stated_classical_answer(q, M: Material, proof: Proof, deadline=None):
    """Strict stated-key Trifid/four-square/two-square/checkerboard path.  Even one deterministic
    reading remains an instance-scoped candidate: the ciphers discard spacing/punctuation and their
    table conventions are not judge-vocabulary facts that may safely transfer to another variant."""
    # `_DERIVED` includes "squared" for arithmetic asks; do not mistake the cipher family names
    # four-square/two-square for a request to square the plaintext.
    ask_without_family = re.sub(r"\b(?:four|two)[\s_-]*square\b|\bfoursquare\b|\btwosquare\b|\bdouble[\s_-]*playfair\b",
                                "", _qtext(q), flags=re.I)
    if classical is None or not _stated_classical_named(q, M) or _DERIVED.search(ask_without_family):
        return None
    sources = [(name, text) for name, text in M.texts if name != "<question>"]
    readings = classical.stated_key_decodings(sources, _qtext(q), deadline=deadline)
    if not readings:
        return None
    options = []
    for convention, plaintext in readings:
        found = {"text": plaintext, "value": plaintext, "raw": plaintext.encode("utf-8", "ignore"),
                 "level": 2, "plain": False}
        for form, value in _options(found, proof):
            if _fits(q, value):
                options.append((f"{convention}:{form}", value))
    if not options:
        return None
    # Bind accepted candidates to every byte, the full question and its format.  A convention
    # accepted for one delivery can therefore replay that delivery, never answer a new variant.
    digest = hashlib.sha256()
    digest.update(json.dumps(q, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8"))
    for name, data in M.members:
        digest.update(len(name.encode("utf-8", "surrogatepass")).to_bytes(4, "big"))
        digest.update(name.encode("utf-8", "surrogatepass"))
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    family = next((name for name in ("straddling_checkerboard", "four_square", "two_square", "trifid")
                   if readings[0][0].startswith(name)), readings[0][0].split("_", 1)[0])
    return _candidates(f"{KEY}.plaintext/stated_{family}@inst-{digest.hexdigest()}", options)


def _stated_classical_named(q, M: Material):
    if classical is None:
        return False
    question_named = classical.stated_cipher_named((), _qtext(q))
    if "stated_classical_named" not in M.cache:
        sources = [(name, text) for name, text in M.texts if name != "<question>"]
        M.cache["stated_classical_named"] = classical.stated_cipher_named(sources)
    return question_named or bool(M.cache["stated_classical_named"])


def _classical_answer(what, q, M: Material, proof: Proof, deadline=None):
    """Classical ciphers, encoding chains and HMAC structure, all UNSURE-only. Answers only when
    exactly one fact is proven (one readable plaintext, one identified cipher, one decoded chain)."""
    if what == "hmac_struct":
        found = _hash_strings(M, q)
        if len(found) != 1 or _DERIVED.search(_qtext(q)):
            return None
        info = classical.hmac_structure(found[0])
        fams = info.get("families") or []
        if not fams:
            return None
        if len(fams) > 1:
            # digest LENGTH cannot tell these algorithms apart (len64 fits sha256, sha3_256,
            # blake2s, sha512_256 alike), so an accepted name must never answer a different
            # algorithm plain: a candidate key scoped to THIS digest (never plain across variants).
            return _candidates(f"{KEY}.hmac_alg/len{info['length']}.{found[0][:8]}",
                               [(n, n) for n in _vocab(q, fams)])
        return _pick(f"{KEY}.hmac_alg/len{info['length']}", _vocab(q, fams))

    texts = _classical_texts(M, q)

    if what == "classical_identify":
        fams = []
        for t in texts:
            fams += [name for name, _ in classical.identify(t) if name != "encoding_chain"]
        fams = list(dict.fromkeys(fams))
        if len(fams) != 1:
            return None
        # the identified family VARIES per variant (caesar vs vigenere), so it goes in the shape:
        # an accepted name only ever answers the variant whose identified cipher shares it.
        return _pick(f"{KEY}.classical_cipher/{fams[0]}", _vocab(q, _CIPHER_SYNONYMS.get(fams[0], [fams[0]])))

    if what == "encoding_chain":
        srcs = texts + [b.decode("latin-1", "ignore") for _, b in M.bins[:4]]
        results = []
        for t in srcs:
            ch = classical.decode_chain(t)
            if ch["chain"] and ch["text"] and classical.looks_english(ch["text"]):
                results.append(ch["text"].strip())
        distinct = list(dict.fromkeys(results))
        if len(distinct) != 1:
            return None
        return _classical_plaintext_pick(q, distinct[0], proof, f"{KEY}.decoded/chain")

    if what == "classical_solve":
        stated = _stated_classical_answer(q, M, proof, deadline)
        if stated is not None:
            return stated
        if _stated_classical_named(q, M):
            return None             # explicit but incomplete/conflicting/malformed: never fall through
        cribs = list(dict.fromkeys(proof.starts + proof.contains))
        key = None
        for fk, fv in question_fields(_qtext(q)):
            if fk == "key" and fv:
                key = fv
        plains = {}
        for t in texts:
            if deadline is not None and time.monotonic() > deadline and plains:
                break
            for crib in [None] + cribs:
                for hyp, pt in classical.solve_classical(t, crib=crib, key=key, deadline=deadline):
                    plains.setdefault(pt, hyp)
        if len(plains) != 1:
            return None
        return _classical_plaintext_pick(q, next(iter(plains)), proof, f"{KEY}.plaintext/classical")
    return None


def _shamir_answer(q, M: Material):
    """A Shamir secret reconstructed from the delivery and the question, answered UNSURE (the form
    the judge wants -- integer, bytes or a flag -- is not fixed). None when nothing is proven, or
    the question asks for something computed from the secret."""
    if _DERIVED.search(_qtext(q)):
        return None
    texts = [t for name, t in M.texts if name != "<question>"]
    r = sss.recover(texts, _qtext(q))
    if not r:
        return None
    field = r["field"]
    secret_int = r.get("secret_int")
    secret_bytes = r.get("secret_bytes")
    words = _words(q)
    asks_int = str(_fmt(q).get("kind") or "") == "integer" \
        or re.search(r"\b(?:as an integer|as a (?:decimal\s+)?number|integer value|decimal value|numeric)\b", words, re.I)
    forms = []
    text = None
    if secret_bytes:
        try:
            cand = secret_bytes.decode("utf-8")
            if cand and all(c.isprintable() or c in "\r\n\t" for c in cand):
                text = cand.strip()
        except UnicodeDecodeError:
            text = None
    if text and not asks_int:                   # a secret that is a string / flag comes first
        one = _one_flag(text)
        if one is not None and one[0] != text:
            forms.append(("flag", one[0]))
            forms.append(("flag_inner", one[1]))
        forms.append(("ascii", text))
    if secret_int is not None:
        forms += [("decimal", str(secret_int)), ("hex", f"{secret_int:x}"), ("0x_hex", f"0x{secret_int:x}")]
    if secret_bytes and not asks_int:
        forms.append(("bytes_hex", secret_bytes.hex()))
    if asks_int:
        forms = [(n, v) for n, v in forms if n in ("decimal", "hex", "0x_hex")]
    elif re.search(r"\bhex(?:adecimal)?\b", words, re.I):
        hexed = [(n, v) for n, v in forms if "hex" in n]
        forms = hexed or forms
    forms = [(n, v) for n, v in forms if _fits(q, v)]
    if not r.get("verified"):
        # exactly-threshold reconstruction: n == k, so there is NO extra share to confirm the
        # polynomial degree. f(0) is then a guess the bytes do not prove -- a different true degree,
        # or a decoy/contradictory threshold or modulus, yields a different secret -- so it must never
        # be plain-promotable. Offer it only as an attempt-scoped candidate pick (row 346: never plain
        # before a judged name, never promoted to the seed), keyed by THIS delivery's shares so an
        # accepted format name for one proven secret can never make a different, unverified
        # reconstruction plain under a shared key. Only a verified (over-determined) secret is a pick.
        scope = hashlib.sha256(("\n".join(texts) + "\x00" + _qtext(q)).encode("utf-8", "replace")).hexdigest()
        return _candidates(f"{KEY}.secret/shamir_{field}.unverified@{scope}", forms)
    return _pick(f"{KEY}.secret/shamir_{field}", forms)


def _otp_answer(q, M: Material):
    """A TOTP/HOTP code (or the shared secret) computed from a base32 secret / otpauth:// URI and a
    STATED time or counter, answered UNSURE (zero-padded vs unpadded). None when there is not
    exactly one secret, no stated time/counter, or the question asks for a transform of the code."""
    texts = [t for name, t in M.texts if name != "<question>"]
    blob = "\n".join(texts) + "\n" + _qtext(q)
    specs = sss.otp_specs(blob)
    if len(specs) != 1:
        return None
    spec = specs[0]
    qt, words = _qtext(q), _words(q)
    asks_secret = re.search(r"\b(?:secret|seed|shared secret|base32|the key)\b", words, re.I) \
        and not re.search(r"\b(?:code|otp|token|digit|password|2fa|value of the)\b", words, re.I)
    if asks_secret and spec.get("secret_b32"):
        forms = [("base32", spec["secret_b32"]), ("hex", spec["secret"].hex()), ("0x_hex", "0x" + spec["secret"].hex())]
        return _pick(f"{KEY}.otp_secret/base32", [(n, v) for n, v in forms if _fits(q, v)])
    if re.search(r"\b(?:sum|md5|sha-?\d+|hash|digest|checksum|reversed?|xor(?:ed)?)\b", qt, re.I):
        return None                             # a transform of the code, not the code
    digits, algo, period, typ = spec["digits"], spec["algo"], spec["period"], spec["type"]
    md = re.search(r"\b([678])[- ]digit", qt)
    if md:
        digits = int(md.group(1))
    if typ is None:                             # a bare secret (no otpauth type): infer, or refuse
        if re.search(r"\bhotp\b|\bcounter[- ]based\b|\bhmac[- ]based\b", words, re.I):
            typ = "hotp"
        elif re.search(r"\btotp\b|\btime[- ]based\b|\botpauth\b|\b2fa\b|\bauthenticator\b|\btwo[- ]factor\b", words, re.I):
            typ = "totp"
        else:
            has_t = sss.find_unix_time(blob) is not None
            has_c = sss.find_counter(blob) is not None
            if has_c and not has_t:
                typ = "hotp"
            elif has_t and not has_c:
                typ = "totp"
            # both, or neither, stated: the mode is ambiguous -> None below
    try:
        if typ == "hotp":
            counter = spec.get("counter")
            if counter is None:
                counter = sss.find_counter(blob)
            if counter is None:
                return None
            code = sss.hotp(spec["secret"], counter, digits, algo)
        elif typ == "totp":
            t = sss.find_unix_time(blob)
            if t is None:
                return None
            code = sss.totp(spec["secret"], t, period, 0, digits, algo)
        else:
            return None
    except (ValueError, OverflowError):
        return None
    forms = [("zero_padded", str(code).zfill(digits)), ("unpadded", str(code))]
    return _pick(f"{KEY}.otp/{typ}", [(n, v) for n, v in forms if _fits(q, v)])


# ---- discrete logs in Z_p: ElGamal / Diffie-Hellman in a weak group (Day 27, solvers/common/dlog.py) ----------
# KB-10 fix round 4, convergence by restriction. Five review rounds each found more questions whose words the router misread
# (which operand, which party, which target, an expression of it, a range of another variable, an operator symbol), and each
# misreading was a WRONG PLAIN answer. So the hook no longer answers anything plain: every value it derives (an exponent, a
# shared secret, a plaintext) is a candidate pick (labels.candidates, row 346: at most 12 evidence-ranked values, probed only on
# an untimed attempt or one with no deadline) under a key fingerprinted per INSTANCE (_dlog_fingerprint: the question's words,
# its answer_format, the group, the public values, the ciphertext and the whole material), so a name the judge accepts answers
# plain only that very question on that very delivery, a replay, and never another instance, wording or delivery. The router's
# reading of the question now only picks WHICH values are offered; a misreading costs a rejected probe on the untimed base,
# never a batch. The pass runs after every older reader of the set (solve_set), inside its own share of the set's budget.

DLOG_BUDGET = 0.5               # seconds for one discrete-log problem; a harder one declines (None)
DLOG_SET_CAP = 0.5              # seconds the discrete-log pass may use over ALL the questions of one set
DLOG_MIN = 0.1                  # a problem is not started with less than this left (one 4096-bit primality test is 0.09 s)
_DLOG_NOT = re.compile(r"\b(?:elliptic|ecdh|ecdsa|dsa|secp\w*|curve|weierstrass|signatures?|rsa|schnorr)\b", re.I)
# signature pairs in the material (r1/s1, r2/s2, sig, signature): a DSA / ElGamal-signature delivery, never a DH one
_DLOG_SIG_MATERIAL = re.compile(r"(?<![A-Za-z0-9_])[rs]_?[12](?![A-Za-z0-9_])\s*[:=]|\bsignatures?\b|\bsig(?:_?[rs12])?\s*[:=]", re.I)
# a question that names the discrete-log problem itself: asked before the older intents, which never read it
_DLOG_EXPLICIT = re.compile(r"\bdiscrete[- ]log\w*|\bdlog\b|\bdiffie[- ]?hellman\b|\bel[- ]?gamal\b|\bshared secret\b|\bg\s*\^\s*\(?(?:x|ab)\)?", re.I)
# the shared SECRET (g^ab) itself; "session / shared / common / agreed key" is a name for a key that is usually DERIVED
# from it (hashed, a KDF): never plain, an unsure pick at best
_DLOG_SHARED_STRONG = re.compile(r"\bshared (?:secret|value)\b|\bcommon secret\b|\bagreed secret\b|\bg\s*\^\s*\(?ab\)?", re.I)
_DLOG_SHARED = re.compile(_DLOG_SHARED_STRONG.pattern + r"|\bshared key\b|\bcommon key\b|\bsession key\b|\bagreed key\b", re.I)
# the asked `x` follows its verb through lead-in words only (`Find the discrete log x`, `What is x`, `Solve for x`): the first
# build let it reach over anything (`What is g^x where x is Alice's private key?` found the second x, and the target looked
# like the exponent while the question asked for g^x)
_DLOG_PRIV = re.compile(r"\bdiscrete[- ]log\w*|\bdlog\b|\b(?:private|secret) (?:exponent|key|value|number|scalar)\b"
                        r"|\b(?:find|recover|compute|determine|solve for|what is|what's)\b(?:\s+(?:the|a|an|value|values|of|for|number|integer|"
                        r"unknown|exponent|discrete|log|logarithm|private|secret|key|smallest|least|positive|nonnegative|non-negative|minimal|"
                        r"unique|natural|whole|me|us))*\s+x(?![A-Za-z0-9_])"
                        r"|\b(?:alice|bob)(?:'s|s)?\s+(?:private|secret)\b", re.I)
_DLOG_DECRYPT = re.compile(r"\bdecrypt\w*|\bplaintext\b|\bcleartext\b|\brecover\w*\s+(?:the\s+)?(?:message|flag|plaintext)\b"
                           r"|\bwhat (?:is|was) the (?:message|flag)\b", re.I)
# the discrete-log statement's own notation (g^x, 7^3, N-bit, `= h mod p`, p-1): read as the problem, not as a derived ask.
# `mod p` is stripped only inside such a statement; a bare `mod q`, `modulo the prime q` or `reduced modulo ...` stays and declines.
_DLOG_STRIP_HEAD = (r"[A-Za-z0-9)]\s*(?:\^|\*\*)\s*\(?[A-Za-z0-9+*]+\)?(?:\s*(?:\(\s*)?\bmod(?:ulo)?\s+(?:the\s+)?(?:prime\s+)?(?:p|modulus)\b\)?)?"
                    r"|(?:=|≡|\bequals?\b)\s*[A-Za-z0-9_]+\s*\(?\s*\bmod(?:ulo)?\s+(?:the\s+)?(?:prime\s+)?(?:p|modulus)\b\)?")
_DLOG_STRIP_TAIL = (r"\b\w+\s*=\s*\S+(?:\s*\(?\s*\bmod(?:ulo)?\s+(?:the\s+)?(?:prime\s+)?(?:p|modulus)\b\)?)?"
                    r"|\b[pq]\s*-\s*1\b")
_DLOG_STRIP = re.compile(_DLOG_STRIP_HEAD + r"|\b\d+[- ]?bits?\b|" + _DLOG_STRIP_TAIL, re.I)
# a hash, a KDF or a key derived from the logarithm / secret: asked on the question as WRITTEN (the statement's own
# `K = SHA256(s)` is not stripped away first)
_DLOG_HASHY = re.compile(r"\b(?:sha-?\d*|md5|hash\w*|kdf|hkdf|pbkdf\w*|digest|blake\w*|aes[- ]?key|(?:encryption|symmetric|derived) key|"
                         r"(?:key|iv|secret)\s+deriv\w*|deriv\w*\s+(?:from|using|via|with|by|of))\b", re.I)
# a variant of ElGamal whose plaintext is not c2 * c1^-x: exponential / additive / hashed / XOR masks / a KEM
_DLOG_ELG_VARIANT = re.compile(r"\bexponential\b|\badditive(?:ly)?\b|\bhomomorphic\w*|\bhashed\b|\bhash(?:ed)?[- ]?el[- ]?gamal|\bxor\w*|\bkem\b|"
                               r"\bg\s*\^\s*\{?\s*m\b|\bg\*\*\s*m\b|\bencoded as g\b|\bsha-?\d+|\bmd5\b|\bkdf\b|\bhkdf\b|\bmasked? by hash", re.I)
# a third party or a group: the shared secret of the A/B pair is not what is asked
_DLOG_THIRD = re.compile(r"\b(?:eve|mallory|mallet|carol|charlie|dave|trudy|attacker|adversary|eavesdropper|mitm|man[- ]in[- ]the[- ]middle|"
                         r"third|three|group (?:shared|secret|key)|multi[- ]?party|all (?:parties|participants)|each (?:party|participant))\b", re.I)


def _dlog_derived(qt: str) -> bool:
    """True when the question asks for something computed FROM the logarithm or secret (a hash, a digit sum,
    the secret mod something): that is not the number itself. Hash / KDF / derived-key words are looked for on the
    question as written; the discrete-log statement's own notation (exponent notation, `N-bit`, `= h mod p`,
    `p-1`) is stripped before the other derived words are."""
    if _DLOG_HASHY.search(qt):
        return True
    return _DERIVED.search(_DLOG_STRIP.sub(" ", qt)) is not None


# ---- the router's reading of the question -----------------------------------------------------------------------------
# (Fix round 4 removed the plain-ask machinery of rounds 2 to 3, the closed vocabulary, the head and conjunction tests, the program
# and prose detectors and the range attribution: they only decided plain against unsure, and nothing here is plain any more. What
# stays only decides None, or which values are offered.)
_DLOG_ROLE_PROSE = re.compile(r"\b(?:client|server|sender|receiver|recipient|initiator|responder|peer)s?\b", re.I)
_DLOG_BASE_ANY = re.compile(r"\b(?:base|with respect to|w\.r\.t\.?|wrt|relative to)\s+([A-Za-z0-9_]+)", re.I)


def _dlog_clauses(qt: str):
    """The question's clauses: sentences (a full stop, `?`, `!` or a line end), split again at a comma, semicolon or colon."""
    for sent in re.split(r"(?<=[.?!])\s+|\n", qt):
        for clause in re.split(r"[,;:]\s*", sent):
            if clause.strip():
                yield clause


_DLOG_ASK = re.compile(r"\b(?:what(?:'s| is| was| are)?|which|find|recover|compute|calculate|determine|give|submit|enter|provide|report|"
                       r"solve for|derive|decrypt\w*|obtain|extract|tell me|show|return|state|name|break|crack|reveal|retrieve|identify|"
                       r"deduce|produce|work out|figure out)\b[^.?!]*", re.I)
# a second thing named as a MEANS, not asked: `decrypt the message with the private key`, `... given the shared secret`
_DLOG_INSTR = re.compile(r"\b(?:using|use|uses|used|with|given|by|via|from|under|knowing|know|if|once|after|when|for|assuming|where)\b[^.?!]{0,40}$", re.I)


_DLOG_CLASSES = (("shared", _DLOG_SHARED), ("priv", _DLOG_PRIV), ("dec", _DLOG_DECRYPT))


def _dlog_sentences(text: str):
    """(offset, sentence) for each sentence of the text: a full stop, `?`, `!` or a line end closes one."""
    pos = 0
    for m in re.finditer(r"(?<=[.?!])\s+|\n", text):
        yield pos, text[pos:m.start()]
        pos = m.end()
    yield pos, text[pos:]


def _dlog_first_class(text: str):
    best = None
    for name, rx in _DLOG_CLASSES:
        m = rx.search(text)
        if m and (best is None or m.start() < best[0]):
            best = (m.start(), name)
    return best[1] if best else None


def _dlog_asks_two(sentence: str) -> bool:
    """Two different things named in ONE sentence (`the shared secret and Alice's private key`): two values are asked and
    one number cannot answer. A thing named as a means (`decrypt the message WITH the private key`, `given the shared
    secret`, `Using Alice's private key, find ...`) is no ask, and the same words (`shared secret value` holds
    `secret value`) are one mention."""
    found = sorted((m.start(), m.end(), name) for name, rx in _DLOG_CLASSES for m in rx.finditer(sentence))
    hits = []
    for st, en, nm in found:
        if hits and st < hits[-1][1]:
            continue
        if _DLOG_INSTR.search(sentence[:st]):
            continue
        hits.append((st, en, nm))
    return len({n for _, _, n in hits}) > 1


# an ask phrase that names no target is allowed only as a FORMAT instruction (`Give it in decimal.`, `Submit it as an integer.`):
# a verb, pronouns, articles, prepositions and a format word, nothing else (a sentence that asks for the generator, a public
# value or `it` with no format word names another quantity or none, and the question is not a plain ask of the target)
_DLOG_FMT = frozenset("give submit enter provide report return state show tell me us it them that this the a an as in to with using by of for "
                      "decimal integer number value answer result final exact numeric plain please now then here below above".split())
_DLOG_FMT_KEY = frozenset("decimal integer number value answer result numeric".split())


def _dlog_format_only(phrase: str) -> bool:
    words = re.findall(r"[^\W\d_]+", phrase.lower())
    return bool(words) and all(w in _DLOG_FMT for w in words) and any(w in _DLOG_FMT_KEY for w in words)


# a sentence that OPENS with an imperative verb the plain-ask vocabulary allows (`Get the generator.`, `Share Bob's value.`) is an ask
# though the ask search does not know the verb; so is a yes / no question (`Is the shared secret the generator?`: no number answers it)
_DLOG_IMPER = re.compile(r"^\W*(?:(?:and|then|also|now|next|please|finally|but|so)\s+)*(?:get|make|run|perform|carry|reach|use|answer|share|"
                         r"agree|arrive|come|yield)\b", re.I)
_DLOG_AUX = re.compile(r"^\W*(?:is|are|was|were|does|do|did|can|could|will|would|shall|should|may|might|has|have|had|must)\b", re.I)


def _dlog_asks(text: str) -> list:
    """The ask phrases of a text, as dicts {phrase, sent, bare, yesno, start, end}: from an ask verb to the end of its sentence,
    for a sentence that opens with an imperative the ask search does not know the whole sentence, and, for a sentence that has no
    ask verb but ends in `?`, the whole sentence (`bare`: a verb-less interrogative; `yesno` when it opens with an auxiliary). A
    sentence with none of these is a statement (a preamble), not an ask."""
    out = []
    for off, s in _dlog_sentences(text):
        if not s.strip():
            continue
        found = list(_DLOG_ASK.finditer(s))
        for m in found:
            out.append({"phrase": m.group(0), "sent": s, "bare": False, "yesno": False, "start": off + m.start(), "end": off + m.end()})
        if not found and _DLOG_IMPER.match(s):
            out.append({"phrase": s, "sent": s, "bare": False, "yesno": False, "start": off, "end": off + len(s)})
        elif not found and s.rstrip().endswith("?"):
            out.append({"phrase": s, "sent": s, "bare": True, "yesno": _DLOG_AUX.match(s) is not None, "start": off, "end": off + len(s)})
    return out


def _dlog_target(qt: str):
    """'shared' | 'priv' | 'dec' | None: which of the three things the QUESTION asks for. Every ask phrase (a verb like find /
    what is / decrypt and the rest of its sentence) must name the target or be a format instruction, and at least one must name
    it: a question whose asks name another quantity (`The shared secret is known to both parties. What is the generator?`,
    `What is Bob's public value? The shared secret is computed by Alice.`) is NOT read from the preamble's mention (the first
    build fell back to the mentions: 122 wrong plain answers of 128 such questions in the review of 95699e2). The question is
    read only when its asks all name the SAME one (`Decrypt the message. What is the private key?` asks two things: None), and,
    with no ask phrase at all, only when it is one clause that names exactly one."""
    sentences = [s for _, s in _dlog_sentences(qt) if s.strip()]
    if any(_dlog_asks_two(s) for s in sentences):
        return None
    asks = _dlog_asks(qt)
    if asks:
        named = set()
        for a in asks:
            if a["yesno"]:
                return None
            t = _dlog_first_class(a["phrase"])
            if t:
                if a["bare"] and len(list(_dlog_clauses(a["sent"]))) != 1:
                    return None
                named.add(t)
            elif not _dlog_format_only(a["phrase"]):
                return None
        return next(iter(named)) if len(named) == 1 else None
    if len(sentences) != 1 or len(list(_dlog_clauses(qt))) != 1:
        return None
    return _dlog_first_class(qt)


# ---- symbols, numbers and the statements a question may carry besides its ask (review of 95699e2, classes 2, 4 and 5) ----
# The words of a question were checked against a closed vocabulary but its SYMBOLS and NUMBERS were not: `>>`, `<<`, `&`, `|`
# and a trailing `% 2**64` were not words, the notation strip deleted `2**64` itself, `g^x` was stripped as notation although
# it was the thing asked, and a number the question stated as its own operand (`g^x = <N> mod p`, a ciphertext pair) was
# never compared with the one the material states. So: the recognised statements below are taken out first, and then no
# operator, no digit and no odd character may remain.
_DLOG_ID = r"[A-Za-z][A-Za-z0-9_]{0,10}"
_DLOG_MODP = r"(?:\s*\(?\s*mod(?:ulo)?\s+(?:the\s+)?(?:prime\s+)?(?:p|modulus)\s*\)?)?"
_DLOG_PW = r"\s*(?:\^|\*\*)\s*"
# the discrete-log equation  g^x = h (mod p): taken out like any statement, but its base and its right-hand symbol are OPERANDS: `g^x = c1`
# asks the logarithm of c1 and `h^x = g` one in another base, so _dlog_bind reads both (they are never hidden by the strip)
_DLOG_EQ = re.compile(r"(?<![A-Za-z0-9_^*])(?P<base>" + _DLOG_ID + r")" + _DLOG_PW + r"\(?\s*[A-Za-z]\s*\)?" + _DLOG_MODP
                      + r"\s*(?:=|≡|==)\s*(?P<rhs>" + _DLOG_ID + r")" + _DLOG_MODP, re.I)
# an assignment of a power  A = g^a mod p,  s = g^(ab) mod p: its left-hand symbol and its base are operands too (`c1 = g^k` asks k)
_DLOG_ASG = re.compile(r"(?<![A-Za-z0-9_^*])(?P<lhs>" + _DLOG_ID + r")\s*(?::=|=|≡)\s*(?P<base>" + _DLOG_ID + r")" + _DLOG_PW
                       + r"\(?\s*[A-Za-z]\s*\*?\s*[A-Za-z]?\s*\)?" + _DLOG_MODP, re.I)
# the shared-secret formula itself  g^(ab) mod p  (and nothing else: a bare g^x is the thing ASKED when it stands alone)
_DLOG_FORM = re.compile(r"(?<![A-Za-z0-9_^*])(?P<base>" + _DLOG_ID + r")" + _DLOG_PW + r"\(?\s*(?:a\s*\*?\s*b|b\s*\*?\s*a)\s*\)?" + _DLOG_MODP, re.I)
_DLOG_UNITS = (_DLOG_EQ, _DLOG_ASG, _DLOG_FORM)
_DLOG_GEN_NAMES = ("g", "gen", "generator", "alpha")
_DLOG_OPS = re.compile(r"[%&|~^<>=+*/\\×÷⊕∘∗·⋅≡≤≥−±]|(?<![A-Za-z])[-–—]|[-–—](?![A-Za-z])")
_DLOG_BENIGN = re.compile(r"(?:[^\W\d_]|[\s'’.,;:?!()\"“”\-–—])*")
_DLOG_NUMTOK = re.compile(r"(?<![A-Za-z0-9_.])(?:0[xX][0-9a-fA-F]+|\d+)(?![A-Za-z0-9_])")
_DLOG_SYMTOK = re.compile(r"(?<![\w'’])([^\W\d_][0-9]?)(?![\w'’])")
# another operand than a public value of the pair: a ciphertext, an ephemeral key, a nonce, a commitment, a signature
_DLOG_OPERAND_OTHER = re.compile(r"(?<![A-Za-z0-9_])(?i:c_?[12]|ct_?[12]|ciphertexts?|ephemeral|nonce|commit\w*|signatures?|blind\w*|"
                                 r"randomness)(?![A-Za-z0-9_])|(?<![A-Za-z0-9_])[kr](?![A-Za-z0-9_])")      # k, r only in lower case: `K` may name the secret
_DLOG_MEANS = re.compile(r"\b(?:using|use|uses|used|with|given|via|knowing|know|assuming|after|once|when|if|where)\b", re.I)
_DLOG_SYM_OK = {"shared": {"a", "A", "b", "B", "g", "p", "q", "s", "S", "K", "I"},        # S and K name the secret itself
                "x": {"a", "A", "b", "B", "g", "p", "q", "x", "h", "y", "Y", "X", "I"},
                "plain": {"a", "A", "c", "m", "g", "p", "h", "y", "Y", "x", "I", "c1", "c2"}}
_DLOG_SYM_VOTE = {"A": "a", "B": "b", "h": "one", "y": "one", "Y": "one", "X": "one"}
# the lower-case letter that names the exponent asked (`the private exponent a`, `private key b of Bob`): it never picks a slot on its
# own, but where the party or the symbol picked another one the question contradicts itself (`Bob's private exponent a`, `What
# is Alice's private exponent b?`: the convention a = Alice's would answer the wrong party) and nothing is plain
_DLOG_EXP_LETTER = re.compile(r"\b(?:key|exponent|secret|value|log|logarithm|number|scalar)\s+([ab])(?![A-Za-z0-9_'’])")


def _dlog_blank(text: str, spans) -> str:
    chars = list(text)
    for a, b in spans:
        for i in range(max(0, a), min(len(chars), b)):
            chars[i] = " "
    return "".join(chars)


def _dlog_units_out(text: str) -> str:
    """The text with the statements a plain ask may carry blanked: the discrete-log equation, a power assigned to a symbol,
    the shared-secret formula, a bound statement about a private value (`x < 2^40`, `Alice's private key is less than p-1`,
    `x is a 28-bit number`) and a labelled parameter the instance reader models (`p = 23`)."""
    spans = []
    for rx in _DLOG_UNITS:
        spans += [m.span() for m in rx.finditer(text)]
    spans += dlog.bound_spans(text)
    spans += dlog.modelled_spans(text)
    return _dlog_blank(text, spans)


def _dlog_operator(qt: str, syntax: str = "") -> bool:
    """True when the question (statements taken out) or its answer-format text carries an operator: the number asked is then
    computed from the one the router has (`s >> 64`, `& 255`, `% 2**128`, `s // 2^32`, `s + 1`). The answer-format text may
    hold an example number; only its operator symbols count."""
    if _DLOG_OPS.search(_dlog_units_out(qt)):
        return True
    return bool(syntax) and re.search(r"[%&|~^]|<<|>>|\*\*|//|[×÷⊕∘−]", _dlog_units_out(syntax)) is not None


def _dlog_pick_pub(pubs: dict, lw: str, votes=frozenset()):
    """(slot, named) of the public value the question asks about, or None; `named` is False when the slot is only the one public
    value there is. The roles stay apart: Alice / party a / user a is slot
    `a`, Bob slot `b`, the client slot `client`, the server slot `server` (a transcript may print the server's value first
    under the bare label A, so `client means A` was a guess). A question that names a role takes that role's labelled slot and
    nothing else, two roles (or a role and a symbol / number of another slot) take none, any other party word (sender,
    receiver, peer, ...) takes none, and a question that names nothing takes the one public value there is."""
    named = set(votes)
    for slot, rx in (("a", r"\balice\b|\bparty a\b|\buser a\b"), ("b", r"\bbob\b|\bparty b\b|\buser b\b"),
                     ("client", r"\bclient\b"), ("server", r"\bserver\b")):
        if re.search(rx, lw):
            named.add(slot)
    if re.search(r"\b(?:sender|receiver|recipient|peer|initiator|responder|owner)(?:'s|’s)?\b", lw):
        return None
    if len(named) > 1:
        return None
    if named:
        slot = next(iter(named))
        return (slot, True) if slot in pubs else None
    return (next(iter(pubs)), False) if len(pubs) == 1 else None


def _dlog_bind(qt: str, lw: str, kind: str, inst: dict):
    """(slot, clean) or None: what the question's operands are bound to. None (no answer at all) when the question names another
    operand than the one the router reads (`the discrete log of c1`, `of the ephemeral key`, `of C`), a symbol that is none
    of the instance's (`the shared secret of A and C`), a number it does not state under a label of the instance
    (`g^x = <N> mod p`, `Decrypt the ciphertext (<d1>, <d2>)`), or when the material states a group element the instance does
    not model (a Pedersen commitment C, a second ciphertext, a value under a label nobody reads) and the question does not
    name its operand. `slot` is the public value a private-exponent ask is about; `clean` is False when what is left of the
    question after its statements (digits, brackets, odd characters) is not a plain ask."""
    pubs = inst["pubs"]
    for m in (_DLOG_BASE_ANY.finditer(qt) if kind == "x" else ()):
        if m.group(1).lower() not in ("g", "alpha", "gen", "generator"):
            return None                 # `the discrete log of g to base A`: a logarithm in another base (a numeral base on the
                                        # shared secret, `in base 7`, is only not plain: the vocabulary check says so)
    # the numbers a question may state inside its ask: the public values of the pair (a shared secret, a private exponent), the
    # ciphertext and the public key (a plaintext); a ciphertext component is no operand of `the discrete log`, nor a parameter of any
    known_pub = ({v for v in (inst.get("c1"), inst.get("c2"), pubs.get("one")) if v is not None} if kind == "plain" else set(pubs.values()))
    params = {v for v in (inst.get("p"), inst.get("g"), inst.get("order")) if v is not None}
    t = _dlog_units_out(qt)
    # the asks of the question AS WRITTEN (the shared-secret formula `Recover g^(ab) mod p` may itself be the target, and the statement
    # strip blanks it): the strip keeps every offset, so each ask is read from `t` (statements out), and its symbols, numbers and
    # operands are bound there
    asks = [a for a in _dlog_asks(qt) if _dlog_first_class(a["phrase"])]
    if not asks and _dlog_first_class(qt):
        # a bare statement of the target with no ask verb and no `?` (`The shared secret of A and C`, `The discrete log of B for
        # Alice`): _dlog_target read it as one sentence of one clause, so all of it is the ask and its operands are bound like
        # any other ask's (its symbols, numbers and the operands another quantity names)
        asks = [{"phrase": qt, "start": 0, "end": len(qt)}]
    ask_texts = [t[a["start"]:a["end"]] for a in asks]
    # (a capital A that opens an ask phrase and is followed by a word is the article, not Alice's public value: `A discrete log of ...?`)
    ask_text = " ".join(re.sub(r"^(\W*)A(?=\s+[a-z]{2})", r"\1 ", s) for s in ask_texts)
    ask_spans = [(a["start"], a["end"]) for a in asks]
    votes = set()
    if kind in ("x", "shared"):
        for s in ask_texts:
            head = _DLOG_MEANS.split(s, 1)[0]
            if _DLOG_OPERAND_OTHER.search(head):
                return None
    blank = []
    for m in _DLOG_NUMTOK.finditer(t):
        v = dlog._ival(m.group(0))
        inside = any(a <= m.start() < b for a, b in ask_spans)
        if v is not None and v in known_pub:
            if inside and kind == "x":
                votes |= {s for s, pv in pubs.items() if pv == v}
            blank.append(m.span())
        elif v is not None and v in params and not inside:
            blank.append(m.span())                        # a parameter restated in a sentence that is no ask
        elif len(m.group(0)) >= 6:
            return None                                   # a long number the instance does not read as an operand (a short one, `in base 7`, only leaves the ask not plain)
    eq_syms = []
    for m in _DLOG_EQ.finditer(qt):
        if m.group("base").lower() not in _DLOG_GEN_NAMES:
            return None                 # `h^x = g`: a logarithm in another base
        eq_syms.append(m.group("rhs"))
    for m in _DLOG_ASG.finditer(qt):
        # `c1 = g^k`: the left-hand symbol is the element whose logarithm is asked (an operand); `s = B^a` computes the shared secret from B
        if m.group("base").lower() not in _DLOG_GEN_NAMES and not (kind == "shared" and m.group("base") in ("A", "B")):
            return None
        eq_syms.append(m.group("lhs"))
    for m in _DLOG_FORM.finditer(qt):
        if m.group("base").lower() not in _DLOG_GEN_NAMES:
            return None
    for tok in eq_syms + _DLOG_SYMTOK.findall(re.sub(r"\b(?:e\.g|i\.e)\.", " ", ask_text, flags=re.I)):
        if tok not in _DLOG_SYM_OK[kind]:
            return None                 # (the equation's right-hand side is a symbol of the instance or another operand: c1, c2, C, k, H ...)
        if kind == "x" and tok in _DLOG_SYM_VOTE:
            votes.add(_DLOG_SYM_VOTE[tok])
    rest = _dlog_blank(t, blank)
    clean = _DLOG_BENIGN.fullmatch(rest) is not None
    if kind == "x":
        got = _dlog_pick_pub(pubs, lw, votes)
        if got is None:
            return None
        slot, explicit = got
        lslots = {m.group(1) for m in _DLOG_EXP_LETTER.finditer(ask_text)}
        if lslots and slot in ("a", "b", "client", "server") and lslots != {slot}:
            return None                 # the letter and the party / symbol name different exponents
        if not explicit and inst.get("unread"):
            return None
        return slot, clean
    if inst.get("unread"):
        return None
    return "", clean


def _dlog_instance(M: Material, qt: str) -> dict:
    """What the material and the question state together. The material is parsed ONCE per Material (cached), and
    only the question's own words are parsed per question."""
    base = M.cache.get("dlog_inst")
    if base is None:
        base = (dlog.read_instance(M.all_text) if dlog.may_state_group(M.all_text)
                else {"p": None, "g": None, "order": None, "pubs": {}, "privs": [], "c1": None,
                      "c2": None, "ambiguous": [], "third": [], "raw": [], "pairs": []})
        base["unread"] = dlog.unread_elements(base) if base.get("p") else []
        M.cache["dlog_inst"] = base
    if not re.search(r"\d", qt):                    # (any digit: `when a = 5` has no two-digit run and still restates a private value)
        return base
    qinst = dlog.read_instance(qt)
    inst = dlog.merge_instances(base, qinst)
    inst["unread"] = dlog.unread_elements(inst) if inst.get("p") else []
    inst["qprivs"] = list(qinst["privs"])           # private values the QUESTION states: each must reproduce a public value
    return inst


# ---- the answer: a candidate pick under a key of this instance's own (fix round 4) ------------------------------------------

_PEM_LABEL = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ")


def _pem_tags(text: str, head: str) -> list:
    """[(start, label, end)] of every `<head><label>-----` in text, label one or more of [A-Z0-9 ], at EVERY start where one
    begins (overlapping ones included, as a regex scan that retries at each position meets them). Linear: the occurrences of
    `-----BEGIN ` (or `-----END `) cannot overlap, and each label run is read once."""
    out, n, hl = [], len(text), len(head)
    i = text.find(head)
    while i >= 0:
        j = k = i + hl
        while k < n and text[k] in _PEM_LABEL:
            k += 1
        if k > j and text.startswith("-----", k):
            out.append((i, text[j:k], k + 5))
        i = text.find(head, i + 1)
    return out


def _strip_pem(text: str) -> str:
    """The text with its PEM blocks taken out: exactly Material's re.sub(r"-----BEGIN ([A-Z0-9 ]+)-----.*?-----END \\1-----",
    "", text, flags=re.S), leftmost first, the first END of the same label, the scan going on after each block, in O(n log n).
    The regex retries its lazy scan to the end of the text at every BEGIN that has no END: a member of unmatched headers took
    1.4 s at 100 KB, growing with the square of its size (review of 7f4ad82)."""
    if "-----BEGIN " not in text:
        return text
    ends = {}
    for e, label, after in _pem_tags(text, "-----END "):
        ends.setdefault(label, []).append((e, after))
    out, pos = [], 0
    for b, label, hdr_end in _pem_tags(text, "-----BEGIN "):
        if b < pos:
            continue                    # inside the block just taken out: the regex goes on after it
        lst = ends.get(label)
        if not lst:
            continue
        idx = bisect.bisect_left(lst, (hdr_end, -1))
        if idx == len(lst):
            continue                    # no END of this label after the header: no block starts here
        out.append(text[pos:b])
        pos = lst[idx][1]
    out.append(text[pos:])
    return "".join(out)


class _DlogMaterial:
    """What the discrete-log pass reads of a set's files (fix round 4c, review of eddb777): the members, names and texts exactly
    as Material selects them (archive holders and magic-header files skipped, key files and PEM blocks taken out, the question
    as the last member), without the older readers' parameter, field, token and blob parsing: built by solve_set's pass 2 for
    the questions no older reader asked, it cost Material about 1.8 s a megabyte of word-like text, outside every deadline, on a
    set the armed tree did not read at all. Decoding stops once the texts pass dlog.READ_LIMIT (`oversize`: the instance reader
    calls such a text ambiguous anyway) or the deadline passes (`incomplete`); either makes the discrete-log answer None.
    `files` is kept for the instance fingerprint (_dlog_material_digest), and `base` lends the decoded files to a question's own
    material (only the question member is read again)."""

    def __init__(self, files: dict, extra_text: str = "", deadline=None, base=None):
        self.cache = {}
        self.files = files
        if base is not None:
            self.members, self.names, self.texts = base.members, list(base.names), list(base.texts)
            self.oversize, self.incomplete, holders = base.oversize, base.incomplete, base.holders
            todo = []
        else:
            self.oversize = self.incomplete = False
            holders = {k.split(ARROW)[0] for k in files if ARROW in k}
            todo = _unique(files)
            self.members, self.names, self.texts = list(todo), [], []
        self.holders = holders
        if extra_text:
            todo = todo + [("<question>", extra_text.encode("utf-8"))]
        size = sum(len(t) for _, t in self.texts) + max(0, len(self.texts) - 1)
        for name, data in todo:
            self.names.append(name)
            if self.oversize or self.incomplete:
                continue
            if deadline is not None and time.monotonic() > deadline:
                self.incomplete = True
                continue
            if name in holders or Path(name).name in holders or any(data.startswith(m) for m in _MAGIC):
                continue
            text = _text(data)
            if text is None:
                continue
            # Material skips a text when lib.read_keys found a key in it and the text holds no PEM header: only then does the
            # key matter, so it is read only then (a member of unmatched `-----BEGIN` headers took read_keys 1.4 s at 100 KB,
            # growing with the square of its size; review of 7f4ad82)
            if "-----BEGIN" not in text and (data[:1] in (b"\x30", b"{") or b"ssh-" in data[:64] or b"ecdsa-sha2" in data[:64]
                                             or b"-----BEGIN" in data) and len(data) <= MAX_TEXT and any(True for _ in lib.read_keys(data)):
                continue
            text = _strip_pem(text)
            if not text.strip():
                continue
            size += len(text) + (1 if self.texts else 0)
            self.texts.append((name, text))
            if size > dlog.READ_LIMIT:
                self.oversize = True
        self.all_text = "\n".join(t for _, t in self.texts)


def _dlog_material_digest(M) -> str:
    """The SHA-256 of the delivery as the discrete-log pass met it: every delivered file, archive key and bytes, sorted by key
    (a member moved into or out of the archive, a magic-header file, a key file, a binary over 1 MiB, a 65th file: each is part
    of it; the review of eddb777 found the texts and binaries Material keeps leave those out), then every member Material kept
    and every text in the order the reader read them, and the member names. Every field goes in with its length first, so no
    two different deliveries give the same bytes (a NUL inside a key or a file cannot imitate a record boundary). Cached per
    material."""
    md = M.cache.get("dlog_md")
    if md is None:
        d = hashlib.sha256()

        def field(tag: bytes, *parts: bytes):
            d.update(tag)
            for part in parts:
                d.update(len(part).to_bytes(8, "big") + part)

        def enc(s) -> bytes:
            return str(s).encode("utf-8", "surrogatepass")

        files = getattr(M, "files", None)
        if isinstance(files, dict):
            for k in sorted(files, key=str):
                v = files[k]
                field(b"F", enc(k), bytes(v) if isinstance(v, (bytes, bytearray)) else enc(repr(v)))
        for name, data in getattr(M, "members", ()):
            field(b"M", enc(name), bytes(data))
        for name, text in M.texts:
            field(b"T", enc(name), enc(text))
        for name in M.names:
            field(b"N", enc(name))
        md = M.cache["dlog_md"] = d.hexdigest()
    return md


def _dlog_fingerprint(q, M: Material, inst: dict, kind: str, slot: str) -> str:
    """The full SHA-256 of everything one discrete-log answer depends on: the question's words (blanks folded, the
    case kept: `A` and `a` are different values), its whole answer_format, the member it names (`artifact`, `member`), the kind
    and slot the router read, the group (p, g, the stated order), every public value, the ciphertext, the stated private
    values in the order the reader met them (the `stated` option is the first that reproduces the public value), and the whole
    delivery (_dlog_material_digest: every file and member, text and bytes, with its key, and the texts in the order they were
    read). The candidate key carries it, so a name the judge accepts answers plain only this very question on this very
    delivery (a replay of what the judge accepted), never another instance, wording, format or delivery, nor the same files
    arranged otherwise (review of eddb777: a member moved into the archive changed the reading order and so the `stated` value
    under an unchanged key). What the reviews called latent keys (a least residue, an integer plaintext, a program's number, a
    session key, each shared across deliveries and plain everywhere after one acceptance) cannot be written any more."""
    md = _dlog_material_digest(M)
    try:
        fmt = json.dumps(q.get("answer_format"), sort_keys=True, default=str)
    except (TypeError, ValueError):
        fmt = repr(q.get("answer_format"))
    h = hashlib.sha256()
    for part in (_qtext(q), fmt, str(q.get("artifact") or ""), str(q.get("member") or ""), kind, slot, inst.get("p"), inst.get("g"),
                 inst.get("order"), sorted(inst["pubs"].items()), inst.get("c1"), inst.get("c2"), list(inst.get("privs") or ()), md):
        h.update(repr(part).encode("utf-8", "surrogatepass"))
        h.update(b"\x00")
    return h.hexdigest()


def _dlog_int_forms(q):
    """[(form, fn)] an integer of this question may be written in, best first: decimal only for an `integer` kind or words that
    say decimal; the hex forms for words that say hex (0x or upper case when they say so); else all four."""
    f = _fmt(q)
    kind, words = str(f.get("kind") or ""), _words(q)
    forms = [("decimal", str), ("hex", lambda v: f"{v:x}"), ("0x_hex", lambda v: f"0x{v:x}"), ("hex_upper", lambda v: f"{v:X}")]
    if kind == "integer" or re.search(r"\b(?:decimal|base[- ]?10|as an integer|as a number)\b", words, re.I):
        return forms[:1]
    if re.search(r"\bhex(?:adecimal)?\b", words, re.I):
        forms = forms[1:]
        if re.search(r"\b0x", words):
            return [fm for fm in forms if fm[0] == "0x_hex"]
        if re.search(r"\bupper-?case\b", words, re.I):
            return [fm for fm in forms if fm[0] == "hex_upper"]
    return forms


def _dlog_pt_forms(q, m: int) -> list:
    """[(form, value)] of an ElGamal plaintext m: its text forms when it reads as text (the flag in it, the whole text, the flag's
    inside), then its integer forms; only the integer forms for a question that asks for an integer."""
    ints = [(fname, fn(m)) for fname, fn in _dlog_int_forms(q)]
    f = _fmt(q)
    if str(f.get("kind") or "") == "integer" or re.search(r"\b(?:as an integer|as a number|decimal|numeric)\b", _words(q), re.I):
        return ints
    text = Proof.readable(lib.to_bytes(m))
    texts = _options({"text": text.strip()}, Proof(q)) if text is not None and text.strip() else []
    return texts + ints


def _dlog_offer(q, key: str, hyps: list):
    """The candidate pick (row 346) of `hyps`, [(hypothesis, [(form, value), ...])] best first (the value the router computed
    and verified first, then the alternatives): the first hypothesis in each of its forms, then every other hypothesis in its
    first form, then their other forms. A value is offered once (under its first name); a form the answer_format's pattern
    refuses is left out; at most MAX_OPTIONS. Never plain before the judge accepts a name for this instance's own key."""
    rows = []
    for i, (hyp, forms) in enumerate(hyps):
        for j, (form, value) in enumerate(forms):
            rows.append((0 if i == 0 else 1 if j == 0 else 2, i, j, f"{hyp}:{form}", value))
    rows.sort(key=lambda r: r[:3])
    opts, seen = [], set()
    for _, _, _, name, value in rows:
        if value in seen or not _fits(q, value):
            continue
        seen.add(value)
        opts.append((name, value))
    return _candidates(key, opts[:MAX_OPTIONS]) if opts else None


_DLOG_KIND_KEY = {"x": "dlog_x", "shared": "dlog_shared", "plain": "dlog_plaintext"}


def _dlog_answer(q, M: Material, words: str, deadline=None):
    """The answer of a question about a discrete logarithm in Z_p^* (ElGamal / Diffie-Hellman): a CANDIDATE pick, or None.
    Never plain (fix round 4). Claims a question ONLY when its asks name a shared secret, a private exponent / discrete log or
    an ElGamal plaintext, the material states p, g and the public values the question needs, every operand the question names
    is one the instance reads, and the maths is proven in code (solvers/common/dlog.py: pow(g, x, p) == h, and the base lies
    in <g>). The options: the computed value first (for an exponent the least residue modulo ord(g), the subgroup order), then
    the alternatives the reviews named where they are well defined (a stated private value that reproduces the public value,
    the other party's exponent, the shared secret; for a plaintext the reading with c1 and c2 swapped). Everything else falls
    through untouched (None). Elliptic-curve, DSA and
    RSA questions are left to their own paths. `deadline` bounds every step (dlog.py checks it inside each loop)."""
    if dlog is None or (deadline is not None and time.monotonic() > deadline):
        return None
    if getattr(M, "oversize", False) or getattr(M, "incomplete", False):
        return None                         # (a _DlogMaterial that stopped reading: past READ_LIMIT, or out of time)
    lw = words.lower()
    if _DLOG_NOT.search(lw) or _DLOG_NOT.search(" ".join(M.names)):
        return None
    qt = _qtext(q)
    syntax = str(_fmt(q).get("syntax") or "")
    target = _dlog_target(qt)
    if target is None:
        return None
    shared, priv, dec = target == "shared", target == "priv", target == "dec"
    if _dlog_derived(qt) or _DLOG_HASHY.search(syntax) or _dlog_operator(qt, syntax):
        return None
    if _DLOG_SIG_MATERIAL.search(M.all_text[:20000]) and not _DLOG_EXPLICIT.search(lw):
        return None                         # a signature delivery (DSA nonce reuse and the like) is another path's
    if (shared or priv) and _DLOG_THIRD.search(lw):
        return None                         # a third party or a group: not the A/B pair's secret, nobody's single exponent
    inst = _dlog_instance(M, qt)
    p, g = inst["p"], inst["g"]
    if p is None or g is None or inst["ambiguous"] or p.bit_length() > dlog.MAX_P_BITS or not 1 < g < p:
        return None
    if shared and inst.get("third"):
        return None                         # the material labels a third public value: which pair is asked is not known
    for i, v in enumerate(inst.get("qprivs", ())):
        # the question restates a private value (`... for a = 5`): it is the exchange's own only when g^v is one of the public
        # values; otherwise the question describes another instance and the material's is not the one asked about. Each check is
        # one exponentiation: at most 16, inside the deadline, and a value wider than p (plus slack) is never raised.
        if i >= 16 or (deadline is not None and time.monotonic() > deadline):
            return None
        if not dlog.plausible_priv(p, v) or not any(dlog._pw(g, v, p) == pub % p for pub in inst["pubs"].values()):
            return None
    order = inst["order"]
    if order is not None and (order < 2 or order > p or dlog._pw(g, order, p) != 1):
        order = None                    # a `q` or `order` the group does not honour (an RSA q, say): not a stated order
    pubs, c1, c2 = inst["pubs"], inst["c1"], inst["c2"]
    privs = inst["privs"]
    kind = ("shared" if shared else "plain" if (dec and c1 is not None and c2 is not None and not priv) else "x" if priv else None)
    if kind is None:
        return None
    if kind == "plain" and (_DLOG_ELG_VARIANT.search(lw) or _DLOG_ELG_VARIANT.search(M.all_text[:20000])
                            or _DLOG_ELG_VARIANT.search(" ".join(M.names))):
        return None                     # exponential / hashed / XOR-masked ElGamal: c2 * c1^-x is not the message
    bound_q = dlog.parse_bound(qt)      # a bound the QUESTION states: a log found above it contradicts the question
    bound = bound_q if bound_q is not None else dlog.parse_bound(M.all_text[:20000])    # one the material states only steers the search
    bind = _dlog_bind(qt, lw, kind, inst)
    if bind is None:
        return None
    slot = bind[0]
    if slot in ("a", "b") and _DLOG_ROLE_PROSE.search(M.all_text[:200000]):
        return None                         # the material talks of a client / server / sender ...: that the bare labels A and B are Alice's
                                            # and Bob's is then not a convention to rely on (`# the server sends its public value first` over A = ...)
    cache = M.cache.setdefault("dlog", {})
    ckey = (kind, p, g, tuple(sorted(pubs.items())), c1, c2, order, bound, bound_q, slot, tuple(privs))
    if ckey not in cache:
        dl = deadline if deadline is not None else time.monotonic() + DLOG_BUDGET
        if time.monotonic() > dl - DLOG_MIN:
            return None
        cache[ckey] = _dlog_solve(kind, slot, p, g, pubs, privs, c1, c2, order, bound, bound_q, dl)
    hyps = cache[ckey]
    if not hyps:
        return None
    key = f"{KEY}.{_DLOG_KIND_KEY[kind]}/zp@inst-{_dlog_fingerprint(q, M, inst, kind, slot)}"
    if kind == "plain":
        return _dlog_offer(q, key, [(hyp, _dlog_pt_forms(q, m)) for hyp, m in hyps])
    forms = _dlog_int_forms(q)
    return _dlog_offer(q, key, [(hyp, [(fname, fn(v)) for fname, fn in forms]) for hyp, v in hyps])


_DLOG_OTHER_SLOT = {"a": "b", "b": "a", "client": "server", "server": "client"}


def _dlog_solve(kind, slot, p, g, pubs, privs, c1, c2, order, bound, bound_q, dl):
    """[(hypothesis, value)] for one problem, best first, or None. Every value is verified in code (dlog.py: pow(g, x, p) == h,
    the base in <g>); the first is the value the question's reading asks for, the rest are the alternatives the reviews named,
    each computed only where it is well defined and while the deadline `dl` allows (they share it with the first)."""
    if kind == "shared":
        pairs = []
        if "a" in pubs and "b" in pubs:
            pairs.append((pubs["a"], pubs["b"]))
        if "client" in pubs and "server" in pubs:
            pairs.append((pubs["client"], pubs["server"]))
        if len(set(pairs)) != 1:
            return None                 # no pair, or two different ones (Alice / Bob and client / server): which is asked is not known
        A, B = pairs[0]
        pa = dlog.stated_priv(privs, g, p, A, dl)
        pb = dlog.stated_priv(privs, g, p, B, dl)
        got = dlog.dh_shared(p, g, A, B, priv_a=pa, priv_b=pb, order=order, bound=bound, deadline=dl)
        return [("shared_secret", got[0])] if got else None
    if kind == "plain":
        h = pubs.get("one") if "one" in pubs else (next(iter(pubs.values())) if len(pubs) == 1 else None)
        if h is None:
            return None
        pr = dlog.stated_priv(privs, g, p, h, dl)
        got = dlog.elgamal_decrypt(p, g, h, c1, c2, priv=pr, order=order, bound=bound, deadline=dl)
        if not got:
            return None
        out = [("message", got[0])]
        if time.monotonic() < dl - DLOG_MIN:
            # the labels c1 and c2 swapped by the author (review R4): the same decryption with the two read the other way round,
            # verified the same way (the new c1 in <g>, g^x == h)
            sw = dlog.elgamal_decrypt(p, g, h, c2, c1, priv=pr, order=order, bound=bound, deadline=dl)
            if sw:
                out.append(("swapped", sw[0]))
        return out
    h = pubs.get(slot)
    if h is None:
        return None
    res = dlog.solve_dlog(p, g, h, order=order, bound=bound, deadline=dl)
    if res is None or dlog._pw(g, res.x, p) != h % p or (bound_q is not None and res.x >= bound_q):
        return None
    # `log` is the least residue modulo ord(g) (Pohlig-Hellman's x mod ord(g), or a kangaroo find checked below ord(g)): the one
    # canonical logarithm, so the same instance always gives it the same value. A kangaroo find whose ord(g) was not determined
    # in time may be another logarithm of h (x + k * ord(g)) on another run, so it is offered under a name of its own and an
    # accepted `log` never answers it.
    out = [("log" if res.order is not None else "log_bounded", res.x)]
    v = dlog.stated_priv(privs, g, p, h, dl)
    if v is not None and v != res.x:
        out.append(("stated", v))                            # a stated private value that reproduces h (g^v == h checked), not reduced
    other = _DLOG_OTHER_SLOT.get(slot)
    if other in pubs and time.monotonic() < dl - DLOG_MIN:
        r2 = dlog.solve_dlog(p, g, pubs[other], order=order, bound=bound, deadline=dl)
        if r2 is not None and dlog._pw(g, r2.x, p) == pubs[other] % p:
            out.append(("other_party" if r2.order is not None else "other_party_bounded", r2.x))
    if other in pubs and res.order is not None and time.monotonic() < dl and dlog._pw(pubs[other], res.order, p) == 1:
        out.append(("shared_secret", dlog._pw(pubs[other], res.x, p)))     # the other public value in <g>: B^x = g^(ab)
    return out


_DLOG_SKIP_KINDS = ("ordered_tokens", "json", "mitre_attack_id")


def _dlog_fallback(q, M: Material, deadline=None):
    """The discrete-log pass for one question the older paths left None: a candidate pick or None, inside `deadline` and at
    most DLOG_BUDGET seconds. Only for a question solve_set hands it (or answer(), for one question)."""
    if dlog is None or str(_fmt(q).get("kind") or "") in _DLOG_SKIP_KINDS:
        return None
    now = time.monotonic()
    dl = now + DLOG_BUDGET if deadline is None else min(deadline, now + DLOG_BUDGET)
    if dl - now < DLOG_MIN:
        return None
    return _dlog_answer(q, M, _words(q), dl)


def answer(q, M: Material, deadline=None):
    """One question's answer under the never-guess rule (see the module text), or None. The older paths answer first
    (`_answer_core`, the armed tree's); the discrete-log path (Day 27) only fills a question they left None, with a
    candidate pick, never plain, so it can never replace an answer of an older path (a toy DSA nonce reuse worded without
    `DSA`). For a whole set, solve_set runs that path after EVERY question's older paths (fix round 4: here, called question by
    question with one deadline, a slow group could still use time a later question of the set needs)."""
    val = _answer_core(q, M, deadline)
    if val is None and intent(q) and (deadline is None or time.monotonic() <= deadline):
        val = _dlog_fallback(q, M, deadline)
    return val


def _answer_core(q, M: Material, deadline=None):
    """The older answer paths (everything but the discrete-log fallback): exactly the armed tree's answer()."""
    kind = str(_fmt(q).get("kind") or "")
    if kind == "mitre_attack_id":
        return None
    words = _words(q)
    structured = kind in ("ordered_tokens", "json")

    # AES-GCM nonce-reuse forgery (wave124): claims a question ONLY when it asks
    # for the authentication key H or a forged tag AND the reuse material (>=2
    # ciphertext+tag pairs) is present; otherwise falls through untouched. Runs
    # before intent routing, since "the GHASH subkey H" matches no other intent.
    if not structured and (deadline is None or time.monotonic() <= deadline):
        gcm_val = _gcm_answer(q, M, words)
        if gcm_val is not None:
            return gcm_val
    if not structured and (deadline is None or time.monotonic() <= deadline):
        kw_val = _keywrap_answer(q, M, words, Proof(q))
        if kw_val is not None:
            return kw_val

    what = intent(q)
    if not what:
        return None
    if what == "dlog":
        return None                 # (never reached from solve_set, which hands such a question only to the discrete-log pass)
    if what == "keywrap":
        what = "plaintext"          # no key-wrap-specific answer applied above: the ordinary proven-text road
    if deadline is not None and time.monotonic() > deadline and not (what.startswith("rsa") or what in ("attack", "plaintext")) \
            or deadline is not None and time.monotonic() > deadline and "rsa" not in M.cache:
        return None                 # out of time, unless the set's one RSA result is already worked out (a 4096-bit
                                    # Wiener key takes the whole budget once: its other questions cost nothing more)
    proof = Proof(q)

    if what == "paillier_plain":
        return _paillier_answer(q, M, proof, deadline)
    if what == "rabin_plain":
        return _rabin_answer(q, M, proof, deadline)

    if what.startswith("jwt"):
        tokens = list(dict.fromkeys(M.jwts + lib.find_jwts(_qtext(q))))
        if len(tokens) != 1 or structured:
            return None
        parts = lib.jwt_parts(tokens[0])
        if not parts:
            return None
        if what == "jwt_alg":
            alg = parts["header"].get("alg")
            if not isinstance(alg, str) or not alg:
                return None
            return _text_answer(q, f"{KEY}.jwt_alg/header", alg, [("lower", alg.lower())] if alg.lower() != alg else [])
        if what == "jwt_secret":
            got = lib.jwt_secret(tokens[0], _jwt_strings(M))
            if len(got) != 1:
                return None
            try:
                return _text_answer(q, f"{KEY}.jwt_secret/{str(parts['header'].get('alg')).lower()}", got[0].decode("utf-8"))
            except UnicodeDecodeError:
                return None
        space = dict(parts["header"])
        if isinstance(parts["payload"], dict):
            space.update(parts["payload"])
        named = [k for k in space if re.search(r"(?<![\w-])[`'\"]?" + re.escape(str(k)) + r"[`'\"]?(?![\w-])", _qtext(q))]
        named = [k for k in named if not any(k != o and str(k) in str(o) for o in named)]
        if len(named) != 1:
            return None
        v = space[named[0]]
        key = f"{KEY}.jwt_claim/{re.sub(r'[^a-z0-9_]+', '_', str(named[0]).lower())}"
        if isinstance(v, bool):
            return _pick(key, [("lower", str(v).lower())]) if _fits(q, str(v).lower()) else None
        if isinstance(v, int):
            if _DERIVED.search(_qtext(q)):
                return None
            return _int_answer(q, key, v) if kind == "integer" else _pick(key, [("decimal", str(v))] if _fits(q, str(v)) else [])
        if isinstance(v, str):
            return _text_answer(q, key, v)
        return _pick(key, [("json", json.dumps(v, separators=(",", ":"), ensure_ascii=False))])

    if what == "ecc_d":
        # the Weierstrass equation (y^2 = x^3 + a*x + b) carries exponents that look like a value
        # derived from d; strip the exponent notation before the derived-answer guard.
        dtext = re.sub(r"(?:\^|\*\*)\s*\d+|[²³⁰-⁹]", " ", _qtext(q))
        if structured or _DERIVED.search(dtext):
            return None
        got = solve_ecc(M, q, deadline)
        if not got:
            return None
        d, weak = got
        both = [(f"{d:x}", "hex"), (f"0x{d:x}", "0x_hex")]
        return _int_answer(q, f"{KEY}.ecc_d/{weak or 'curve'}", d, extra=[(n, v) for v, n in both if _fits(q, v)])
    if what == "shamir":
        if structured:
            return None
        return _shamir_answer(q, M)

    if what == "otp":
        if structured:
            return None
        return _otp_answer(q, M)

    if what in ("ecdsa_d", "ecdsa_k"):
        if structured:
            return None
        got = solve_ecdsa(M, q)
        if not got:
            # biased/partial-nonce recovery via the Hidden Number Problem: only
            # for the private scalar d (the nonce differs per signature), and d
            # is proven by d*G == the public key before it is ever returned. The
            # derived-value guard ignores the stated nonce-leak size ("128 bits").
            if what == "ecdsa_d" and not _hnp_derived(_qtext(q)):
                hnp = solve_ecdsa_hnp(M, q, deadline=deadline)
                if hnp is not None:
                    d, curve = hnp
                    both = [(f"{d:064x}", "hex64"), (f"0x{d:064x}", "0x_hex64")]
                    return _int_answer(q, f"{KEY}.ecdsa_d/{curve}", d,
                                       extra=[(n, v) for v, n in both if _fits(q, v)])
            if what == "ecdsa_d" and not _DERIVED.search(_qtext(q)):
                dsa = solve_dsa(M, q)
                if dsa is not None:
                    x, qbits = dsa
                    both = [(f"{x:x}", "hex"), (f"0x{x:x}", "0x_hex")]
                    return _int_answer(q, f"{KEY}.dsa_x/{qbits}", x, extra=[(n, v) for v, n in both if _fits(q, v)])
            return None
        if _DERIVED.search(_qtext(q)):
            return None
        d, k, curve = got
        value = d if what == "ecdsa_d" else k
        if what == "ecdsa_k":
            # k and n - k give the same r, and a signature may have been written low-s: which of
            # the two the signer drew is not in the bytes
            other = lib.CURVES[curve]["n"] - k
            hexed = re.search(r"\bhex", words, re.I) and kind != "integer"
            form = (lambda v: f"{v:064x}") if hexed else str
            return _pick(f"{KEY}.ecdsa_k/{curve}", [(n, v) for n, v in (("as_written", form(k)), ("negated", form(other))) if _fits(q, v)])
        both = [(f"{value:064x}", "hex64"), (f"0x{value:064x}", "0x_hex64")]
        return _int_answer(q, f"{KEY}.{what}/{curve}", value, extra=[(n, v) for v, n in both if _fits(q, v)])

    if what in ("mt_next", "lcg_next", "xorshift_next", "pcg_next"):
        if structured:
            return None
        lists = [x for x in M.int_lists]
        if len(lists) != 1:
            return None
        xs = lists[0]
        # the question must ask for the one output after the given ones (not the seed, the state,
        # the previous output, the next N, or a value computed from the next output)
        if not _prng_next_asked(words, len(xs)) or _DERIVED.search(_qtext(q)):
            return None
        if what == "mt_next":
            got = lib.mt_clone(xs, 1)
            if not got:
                return None
            return _int_answer(q, f"{KEY}.next/mt19937", got[0][0], unverified=got[1] == 0)
        if what == "xorshift_next":
            got = lib.xorshift_predict(xs)      # (next, width, variant, verified), roundtrip-gated
            if not got:
                return None
            return _int_answer(q, f"{KEY}.next/xorshift{got[1]}", got[0], unverified=got[3] <= 0)
        P = M.params
        if what == "pcg_next":
            # the stream increment is the author's; use any stated one, then the PCG default. The
            # multiplier defaults to the standard PCG constant unless the delivery states one. Read.py
            # only keeps RSA-style param names, so these come from the generic fields.
            incs = [v for nm in ("inc", "increment", "stream", "seq") for v in _field_ints(M, nm)][:3]
            incs = (incs + [lib.PCG32_DEFAULT_INC]) if incs else None
            mults = _field_ints(M, "mult") or _field_ints(M, "multiplier")
            mult = mults[0] if mults else lib.PCG32_MULT
            got = lib.pcg32_predict(xs, incs=incs, mult=mult, deadline=deadline)
            if not got:
                return None
            return _int_answer(q, f"{KEY}.next/pcg32", got[0], unverified=got[1] <= 0)
        # lcg_next: the affine recurrence on full outputs, then the truncated form (top bits only)
        m = P.one("m") or P.one("n")
        a = P.one("a")
        c = P.one("c") if P.one("c") is not None else P.one("b")
        got = lib.lcg_recover(xs, m, a, c)
        if got:
            return _int_answer(q, f"{KEY}.next/lcg", got[3], unverified=got[4] <= 0)
        # truncated LCG: fires only when the multiplier, increment, modulus AND the truncation shift
        # are all stated in the delivery; the shift is never guessed (never-wrong).
        shifts = (_field_ints(M, "shift") or _field_ints(M, "drop")
                  or _field_ints(M, "truncate") or _field_ints(M, "truncation"))
        shift = shifts[0] if shifts else None
        if a is not None and c is not None and m is not None and shift is not None and shift > 0:
            got = lib.lcg_truncated_predict(xs, a, c, m, int(shift), deadline=deadline)
            if got:
                return _int_answer(q, f"{KEY}.next/lcg_truncated", got[0], unverified=got[1] <= 0)
        return None

    if what == "hash_type":
        found = _hash_strings(M, q)
        if len(found) != 1:
            return None
        names = lib.hash_candidates(found[0])
        shape = "prefix" if found[0].startswith(("$", "{")) or "$" in found[0] else f"hex{len(found[0])}"
        return _pick(f"{KEY}.hash_type/{shape}", _vocab(q, names))

    if what == "ecb_line":
        rows = _line_cts(M)
        hits = [(i, line) for i, line, b in rows if len(b) % 16 == 0 and len(b) >= 32 and lib.ecb_duplicates(b)["repeats"]]
        if len(hits) != 1 or structured or re.search(r"\bnot\b|n't\b|\bnon-", _qtext(q), re.I):
            return None             # no list of ciphertexts, not exactly one of them repeats a block, or the others are asked
        i, line = hits[0]
        # proven: this one line repeats a 16-byte block. How the author counts lines is not
        return _pick(f"{KEY}.ecb_line/index", [(n, v) for n, v in (("from_1", str(i + 1)), ("from_0", str(i)), ("ciphertext", line)) if _fits(q, v)])

    if what in ("ecb_count", "mode"):
        cts = [b for b in _cts(M) if len(b) % 16 == 0 and len(b) >= 32]
        rows = _line_cts(M) if len(cts) != 1 else []
        if rows:                    # a list of ciphertexts, one a line: the one line that repeats a block
            hits = [b for _, _, b in rows if len(b) % 16 == 0 and len(b) >= 32 and lib.ecb_duplicates(b)["repeats"]]
            cts = hits if len(hits) == 1 else []
        if len(cts) != 1 or structured:
            return None
        info = lib.ecb_duplicates(cts[0])
        if what == "mode":
            if not info["repeats"]:
                return None
            return _pick(f"{KEY}.mode/duplicate_blocks", _vocab(q, ["ecb", "aes_ecb", "electronic_codebook", "electronic_code_book"]))
        a, b = info["repeats"], info["repeated_values"]
        if a == b == 0:
            # no repeat at 16 bytes says nothing about a cipher of 8-byte blocks (DES, 3DES)
            if lib.ecb_duplicates(cts[0], 8)["repeats"]:
                return None
            return "0" if _fits(q, "0") else None
        return _pick(f"{KEY}.ecb_count/reading", [("repeats", str(a)), ("repeated_values", str(b)),
                                                  ("blocks_in_repeated_groups", str(a + b))])

    if what in ("rsa_bits", "rsa_e"):
        ns = list(dict.fromkeys(M.params.many("n") + [k["n"] for _, k in M.keys if k.get("type") == "rsa"]))
        es = list(dict.fromkeys(M.params.many("e") + [k["e"] for _, k in M.keys if k.get("type") == "rsa"]))
        if what == "rsa_bits":
            if not re.search(r"\b(?:rsa|modulus|public key|private key)\b|(?<![\w-])n(?![\w-])", words, re.I) \
                    or re.search(r"\b(?:aes|des|3des|chacha\w*|rc4|hmac|symmetric|session key|iv|nonce|ec|ecdsa|curve)\b", words, re.I):
                return None         # the size of some other key
            if re.search(r"\b(?:exponent|primes?|factors?|ciphertext|plaintext|message|signature|hash|digest|block|d|p|q|e|c|phi|"
                         r"totient|sum|product|difference|minus|plus|times|mod(?:ulo)?)\b|[-+*/%^]\s*\d", _qtext(q), re.I):
                return None         # the size of something that is not the modulus, or arithmetic on it
            if len(ns) != 1 or lib.consistency({k: M.params.one(k) for k in ("n", "p", "q") if M.params.one(k)})[1]:
                return None
            actual = ns[0].bit_length()
            # audit #6: a question that NAMES the modulus (or the bare symbol n) asks the actual modulus bit
            # length -- unambiguous, so plain. A question that asks the RSA "key size/length/bits" WITHOUT naming
            # the modulus is ambiguous: ~61% of nominal-2048 keys have n.bit_length()==2047 (only the top bit of
            # n need be set), and an author may key the "key size" on the nominal 2048. Only when the actual and
            # nominal sizes differ is the answer offered unsure (actual vs nominal); when they agree, plain is safe.
            if re.search(r"\bmodulus\b|(?<![\w-])n(?![\w-])", words, re.I):
                return _int_answer(q, f"{KEY}.bits/rsa", actual)
            nominal = next((s for s in (512, 1024, 2048, 3072, 4096, 6144, 8192) if actual <= s), actual)
            if actual == nominal:
                return _int_answer(q, f"{KEY}.bits/rsa", actual)
            return _pick(f"{KEY}.bits/rsa", [("actual", str(actual)), ("nominal", str(nominal))])
        if _DERIVED.search(_qtext(q)):
            return None
        return _int_answer(q, f"{KEY}.public_exponent/rsa", es[0]) if len(es) == 1 else None

    if what in ("rsa_d", "rsa_phi", "rsa_small", "rsa_large", "rsa_p", "rsa_q", "rsa_factors"):
        r = _one_key(M, deadline)
        if not r or _DERIVED.search(_qtext(q)):
            return None
        fs = r.factors
        if what == "rsa_d":
            if r.d is None or not r.e:
                return None
            opts = {r.d}
            if fs and len(set(fs)) >= 2:
                # d is convention-ambiguous: inverse(e, phi) (Euler) and inverse(e, lambda)
                # (Carmichael) both round-trip, so verification cannot tell them apart and the
                # author's choice is unknown. This holds for ANY factor count: a multi-prime
                # (3+ factor) d must offer BOTH conventions as an unsure pick, never a single
                # convention plain (the 2-prime path's rule, generalised). phi_of handles the
                # product with multiplicity; lambda is the lcm of (p-1) over the distinct primes.
                phi = lib.phi_of(fs)
                lam = math.lcm(*[p - 1 for p in dict.fromkeys(fs)])
                opts = {lib.inverse(r.e, phi), lib.inverse(r.e, lam)}
            elif not fs:
                return _pick(f"{KEY}.private_exponent/given", [("decimal", str(r.d))] if _fits(q, str(r.d)) else [])
            opts.discard(None)
            if not opts:
                return None
            if len(opts) == 1:
                return _int_answer(q, f"{KEY}.private_exponent/rsa", next(iter(opts)))
            lo, hi = sorted(opts)
            dec = _fmt(q).get("kind") == "integer" or not re.search(r"\bhex", words, re.I)
            form = (lambda v: str(v)) if dec else (lambda v: f"{v:x}")
            return _pick(f"{KEY}.private_exponent/modulus", [(n, v) for n, v in (("mod_phi", form(hi)), ("mod_lambda", form(lo))) if _fits(q, v)])
        if not fs or structured and what != "rsa_factors":
            return None
        if what == "rsa_phi":
            if re.search(r"\b(?:carmichael|lambda)\b|λ", words, re.I):
                return None
            return _int_answer(q, f"{KEY}.phi/rsa", lib.phi_of(fs))
        if what in ("rsa_small", "rsa_large"):
            return _int_answer(q, f"{KEY}.prime/rsa", fs[0] if what == "rsa_small" else fs[-1])
        if what in ("rsa_p", "rsa_q"):
            if len(fs) != 2:
                return None
            given = M.params.one(what[-1])
            if given in fs and not r.repaired:
                return _int_answer(q, f"{KEY}.prime/rsa", given)
            if fs[0] == fs[1]:
                return _int_answer(q, f"{KEY}.prime/rsa", fs[0])
            a, b = (fs[0], fs[1]) if what == "rsa_p" else (fs[1], fs[0])
            dec = _fmt(q).get("kind") == "integer" or not re.search(r"\bhex", words, re.I)
            form = (lambda v: str(v)) if dec else (lambda v: f"{v:x}")
            return _pick(f"{KEY}.prime/order", [(n, v) for n, v in (("smaller_first", form(a)), ("larger_first", form(b))) if _fits(q, v)])
        forms = [("json_ascending", json.dumps(fs, separators=(",", ":"))), ("comma_ascending", ",".join(map(str, fs))),
                 ("comma_descending", ",".join(map(str, reversed(fs)))), ("space_ascending", " ".join(map(str, fs)))]
        if kind == "json":
            forms = forms[:1]
        return _pick(f"{KEY}.factors/rsa", [(n, v) for n, v in forms if _fits(q, v)])

    if what == "attack":
        if structured:
            return None
        rs = solve_rsa(M, deadline)
        attacks = list(dict.fromkeys(r.attack for r in rs if r.attack != "given_key"))
        if len(attacks) != 1 or attacks[0] not in ATTACK_NAMES:
            return None
        names = list(ATTACK_NAMES[attacks[0]])
        if attacks[0] == "small_e_root" and rs[0].e != 3:
            names.remove("cube_root")
        return _pick(f"{KEY}.attack/{attacks[0]}", _vocab(q, names))

    if what == "xor_key":
        if structured or "xor" not in _stated(M, q)[0]:
            return None
        if M.field(*_KEYF, exclude=("public", "pub_")):
            return None
        got = solve_xor(M, q, proof, deadline)
        if not got:
            # no single-byte proof and no crib: break the repeating key keyless, ranked by fitness,
            # and offer it as candidates only (buildlist row 2 / row 346) -- never plain. The key is
            # scoped per-ciphertext (repeating_xor_disc), so an accepted hypothesis name cannot
            # promote another variant's recovered-but-unproven value to plain (never-wrong fix).
            ranked = solve_repeating_xor(M, q, proof, deadline)
            disc = M.cache.get("repeating_xor_disc")
            return _repeating_xor_candidates(q, f"{KEY}.xor_key/repeating_keyless.{disc}", ranked, "key")
        key = got[1]
        forms = [("hex", key.hex()), ("0x_hex", "0x" + key.hex())]
        if all(32 <= b < 127 for b in key) and key.strip() == key:
            forms.insert(0, ("text", key.decode("ascii")))      # a key with spaces inside it is still a text
        if len(key) == 1:
            forms.append(("decimal", str(key[0])))
        if re.search(r"\bhex", words, re.I):
            forms = [(n, v) for n, v in forms if "hex" in n]
        return _pick(f"{KEY}.xor_key/{'single_byte' if len(key) == 1 else 'repeating'}", [(n, v) for n, v in forms if _fits(q, v)])

    if what == "length_ext":
        # a length-extension question names "length" and "bytes" by nature, so _DERIVED does not
        # apply here; the forged MAC/message is exactly what is asked, proven offline.
        if structured:
            return None
        return solve_length_ext(M, q, proof)

    if what == "collision":
        # a collision question names "how many", "offset", "blocks" by nature, so _DERIVED does not
        # apply; solve_collision answers only a byte-proven fact and only when a collision is present.
        if structured:
            return None
        return solve_collision(M, q)

    if what in ("hmac_struct", "classical_identify", "classical_solve", "encoding_chain"):
        if structured or classical is None:
            return None
        return _classical_answer(what, q, M, proof, deadline)

    # the plaintext: every family whose material is present; exactly one proven text over all
    if structured:
        return None
    if what == "plaintext" and classical is not None:
        stated = _stated_classical_answer(q, M, proof, deadline)
        if stated is not None:
            return stated
        if _stated_classical_named(q, M):
            return None             # do not let another family reinterpret a malformed declaration
    has_rsa = bool(M.params.many("n") or any(k.get("type") == "rsa" for _, k in M.keys))
    asks_rsa_integer = kind == "integer" or re.search(
        r"\b(?:plaintext|message)\s+(?:as\s+an?\s+)?(?:decimal\s+)?integer\b|\bplaintext integer\b",
        words, re.I)
    if has_rsa and what == "plaintext" and asks_rsa_integer:
        if _DERIVED.search(_qtext(q)):
            return None
        value = _rsa_plain_integer(M, deadline)
        return _int_answer(q, f"{KEY}.plaintext_integer/rsa", value) if value is not None else None

    found = {}
    if has_rsa:
        j = _rsa_plain(M, q, proof, deadline)
        if j:
            found[j["value"]] = (j, "rsa")
    algs, _ = _stated(M, q)
    if M.field(*_KEYF, exclude=("public", "pub_")) or any(k.get("type") == "oct" for _, k in M.keys) \
            or M.field("kek", "key1", "key_1"):
        got = solve_sym(M, q, proof, deadline)
        if got:
            found.setdefault(got[0]["value"], (got[0], "xor" if got[1] == "xor" else "cipher"))
    elif "xor" in algs:
        got = solve_xor(M, q, proof, deadline)
        if got:
            found.setdefault(got[0]["value"], (got[0], "xor"))
    if not found and re.search(r"\b(?:key ?stream|nonce reuse|key reuse|reused?|two[- ]time|many[- ]time|one[- ]time pad|otp|same (?:key|nonce|keystream))\b",
                               words + " " + " ".join(M.names), re.I):
        j = solve_reuse(M, q, proof)
        if j:
            found[j["value"]] = (j, "stream_reuse")
    if not found and "xor" in algs and not (M.field(*_KEYF, exclude=("public", "pub_"))
                                            or any(k.get("type") == "oct" for _, k in M.keys)):
        # XOR is named but no key is stated and no single-byte/crib proof held: the keyless
        # repeating-key break, offered as candidates only (buildlist row 2 / row 346), never plain.
        # The key is scoped per-ciphertext (repeating_xor_disc), so an accepted hypothesis name
        # cannot promote another variant's recovered-but-unproven value to plain (never-wrong fix).
        ranked = solve_repeating_xor(M, q, proof, deadline)
        disc = M.cache.get("repeating_xor_disc")
        cand = _repeating_xor_candidates(q, f"{KEY}.plaintext_xor/repeating_keyless.{disc}", ranked, "plaintext")
        if cand is not None:
            return cand
    if len(found) != 1:
        return None
    j, family = next(iter(found.values()))
    return _finish(q, f"{KEY}.plaintext/{family}", j, proof)


# ---- signals and the runner contract ------------------------------------------------------------------------

_Q_STRONG = re.compile(r"\b(?:rsa|paillier|rabin|modulus|ciphertext|decrypt\w*|xor(?:ed)?|aes|jwt|json web token|ecdsa|nonce|mersenne|mt19937|hmac|"
                       r"plaintext|keystream|private exponent|public exponent|private key|public key|block cipher|initiali[sz]ation vector|"
                       r"one[- ]time pad|linear congruential|chacha20?|rc4|3des|prime factors?|totient|"
                       r"caesar|rot-?13|rot-?47|vigen[eè]re|vigenere|substitution cipher|monoalphabetic|atbash|affine cipher|rail[- ]?fence|"
                       r"columnar|transposition cipher|scytale|baconian|bacon'?s cipher|morse code|playfair|trifid|"
                       r"four[\s_-]*square|foursquare|two[\s_-]*square|twosquare|double[\s_-]*playfair|"
                       r"straddling[\s_-]*checkerboard|checkerboard|classical cipher|"
                       r"base32|base85|ascii85|shamir|secret shar\w*|lagrange|totp|hotp|otpauth|one[- ]time password|2fa|two[- ]factor|authenticator|"
                       r"el[- ]?gamal|diffie[- ]?hellman|discrete[- ]log\w*)\b", re.I)


def signals(questions, files) -> float:
    """0..1: how strongly a set looks like modern crypto. Words of the questions (rsa, modulus,
    ciphertext, decrypt, xor, aes, jwt, ecdsa, nonce, ...) and marks in small text files (a PEM or
    SSH key, labelled n/e/c, a key with an iv, a JWT). Cheap: no attack is run."""
    qs = list(questions or [])
    hit = sum(1 for q in qs if _Q_STRONG.search(_words(q) + " " + re.sub(r"[-_.]+", " ", str(q.get("answer_id") or q.get("id") or ""))))
    q_score = hit / len(qs) if qs else 0.0
    marks = 0
    for name, data in _unique(files or {})[:MAX_FILES]:
        if len(data) > MAX_TEXT or any(data.startswith(m) for m in _MAGIC):
            continue
        head = data[:65536]
        if b"-----BEGIN" in head and (b"KEY-----" in head or b"CERTIFICATE-----" in head) or head.startswith((b"ssh-rsa ", b"ecdsa-sha2-")):
            marks += 2
            continue
        text = _text(head)
        if text is None:
            continue
        P = lib.read_params(text)
        if P.get("n") and (P.get("e") or P.get("c")):
            marks += 2
        elif P.get("r") and P.get("s"):
            marks += 2
        F = lib.read_fields(text)
        if any(k == "key" or k.endswith("_key") for k in F) and any(k in ("iv", "nonce", "ciphertext", "ct") or k.endswith(("_iv", "_nonce")) for k in F):
            marks += 2
        if lib.find_jwts(text):
            marks += 1
        if re.search(r"\.(?:pem|pub|enc|key|der|jwk)$", name, re.I):
            marks += 1
    f_score = min(1.0, marks / 2.0)
    if not hit and not marks:
        return 0.0
    return round(min(1.0, 0.6 * q_score + 0.4 * f_score), 3)


def _known_lane(questions, files) -> bool:
    """True when the set carries the marks of Binary, Mobile or Metadata (solvers/common/triage.py
    lane_signals: dNN_ ids or an HCFG container, an ANS- answer or assets/huntress_puzzle.json,
    `Determine <property> for <file>`): such a set is that lane's, whatever its words. The marks
    of Script Analysis (an id that ends -attack) and Warmups (an id `message`) are not used: a
    crypto set may well carry them, and an ATT&CK answer is refused per question."""
    try:
        tri = _load("triage", "triage")
        return bool(set(tri.lane_signals(questions, files)) - {"script-analysis", "warmups"})
    except Exception:
        return False


def solve_set(questions, files, ctx) -> dict:
    ctx = ctx if isinstance(ctx, dict) else {}
    partial = ctx.get("partial") if isinstance(ctx.get("partial"), dict) else {}
    out = {}
    try:
        budget = float(ctx.get("budget") or ctf_env.get("CTF_TK_BUDGET") or BUDGET)
    except (TypeError, ValueError):
        budget = BUDGET
    deadline = time.monotonic() + budget
    intents = [intent(q) for q in questions]
    asked = [q for q, what in zip(questions, intents) if what and str(_fmt(q).get("kind") or "") != "mitre_attack_id"]
    if asked and _known_lane(questions, files):
        asked = []              # a set with a known lane's marks is that lane's, whatever its words
    mats = {}

    def material_of(i, q):
        # a question that states material of its own (numbers, a token, a hash) adds it
        if i not in mats:
            text = _qtext(q)
            if re.search(r"\d{6,}|0x[0-9a-fA-F]{6,}|eyJ|[0-9a-fA-F]{24,}", text) or question_fields(text):
                mats[i] = Material(files, text)
            else:
                if "base" not in mats:
                    mats["base"] = Material(files)
                mats[i] = mats["base"]
        return mats[i]

    # pass 1: the older readers, exactly as the armed tree runs them (a `dlog` question, which no older intent reads, is not
    # handed to them: on the armed tree it was not asked at all)
    for i, q in enumerate(questions):
        qid = q.get("qid") or q.get("id")
        value = None
        if q in asked and intents[i] != "dlog":
            try:
                value = _answer_core(q, material_of(i, q), deadline)
            except Exception:           # a fact that cannot be read is no answer
                value = None
        out[qid] = value
        partial[qid] = value
    # pass 2 (Day 27, KB-10 fix round 4): the discrete-log fallback, AFTER every question's older readers, for the questions they
    # left None, inside its own share of what is left of the set's budget (DLOG_SET_CAP in all, DLOG_BUDGET a problem). It only
    # fills a None with a candidate pick, so no answer of the older readers can be lost to it, whatever a group costs (review
    # of 95699e2: a 4-kbit group took the set's whole budget and an RSA question the armed tree answered got None).
    # The pass reads its own material (_DlogMaterial: the same texts as Material, without the older readers' parsing, inside the
    # pass's deadline), never the older readers' Material: what it answers does not depend on the set's other questions, and a
    # set the armed tree did not read at all costs no Material (review of eddb777: 0.9 s a 500 KB text, outside every deadline).
    if dlog is not None:
        began = time.monotonic()
        end = min(deadline, began + DLOG_SET_CAP)
        light = {}

        def dlog_material_of(i, q):
            if i not in light:
                if "base" not in light:
                    light["base"] = _DlogMaterial(files, deadline=end)
                text = _qtext(q)
                if re.search(r"\d{6,}|0x[0-9a-fA-F]{6,}|eyJ|[0-9a-fA-F]{24,}", text) or question_fields(text):
                    light[i] = _DlogMaterial(files, text, deadline=end, base=light["base"])
                else:
                    light[i] = light["base"]
            return light[i]

        for i, q in enumerate(questions):
            qid = q.get("qid") or q.get("id")
            if out.get(qid) is not None or q not in asked or str(_fmt(q).get("kind") or "") in _DLOG_SKIP_KINDS:
                continue
            if end - time.monotonic() < DLOG_MIN:
                break
            try:
                value = _dlog_fallback(q, dlog_material_of(i, q), end)
            except Exception:
                value = None
            if value is not None:
                out[qid] = value
                partial[qid] = value
    return out


# ---- the command ----------------------------------------------------------------------------------------------

def _short(v, n=72) -> str:
    s = str(v)
    return s if len(s) <= n else f"{s[:n // 2]}...{s[-n // 3:]} ({len(s)} chars)"


def triage(paths, budget: float = 10.0) -> str:
    files = {}
    for p in paths:
        p = Path(p)
        files[p.name] = p.read_bytes()
    M = Material(files)
    lines = [f"# modern_crypto triage of {', '.join(Path(p).name for p in paths)}", ""]
    lines.append(f"signals (files only): {signals([], files)}")
    for name, k in M.keys:
        if k.get("type") == "rsa":
            lines.append(f"KEY {name}: rsa {k['kind']} {'private' if k.get('private') else 'public'} bits={k['bits']} e={_short(k['e'], 24)}"
                         + (" (read from DER: the library refuses it)" if k.get("weak") else ""))
        elif k.get("type") == "ec":
            lines.append(f"KEY {name}: ec {k['kind']} {'private' if k.get('private') else 'public'} curve={k.get('curve')}")
        else:
            lines.append(f"KEY {name}: {k.get('type')} {k.get('kind')} {k.get('why', '')}")
    for pname, vals in M.params.items():
        for v in vals[:6]:
            lines.append(f"PARAM {pname} = {_short(v)}  ({v.bit_length()} bits)")
    for pname, raws in M.params.raw.items():
        if pname.endswith("?"):
            lines.append(f"PARAM {pname[:-1]} is written with a missing digit: {_short(raws[0][0])}")
    singles = {k: M.params.one(k) for k in ("n", "e", "d", "p", "q", "phi", "dp", "dq", "qinv") if M.params.one(k) is not None}
    checked, broken = lib.consistency(singles)
    if checked:
        lines.append(f"CONSISTENCY {checked} relation(s) checked, {broken} broken")
    for fname, vals in M.fields.items():
        if any(fname == s or fname.endswith("_" + s) for s in _KEYF + _IVF + ("tag", "ciphertext", "ct")):
            lines.append(f"FIELD {fname} = {_short(vals[0])}  readings: " + ", ".join(f"{r}:{len(b)}B" for r, b in lib.blobs(vals[0])))
    deadline = time.monotonic() + budget
    t0 = time.monotonic()
    for r in solve_rsa(M, deadline):
        lines.append(f"RSA attack={r.attack}" + (f" repaired={r.repaired}" if r.repaired else "") + (f" d={_short(r.d, 40)}" if r.d else "")
                     + (f" factors={[_short(f, 30) for f in r.factors]}" if r.factors else ""))
        for reading, pt in r.messages:
            text = Proof.readable(pt)
            lines.append(f"  message ({reading}): {_short(text.strip() if text else pt.hex(), 100)}{'' if text else '  [not text]'}")
    if (M.params.get("n") or any(k.get('type') == 'rsa' for _, k in M.keys)) and not M.cache.get("rsa"):
        lines.append(f"RSA nothing proven in {time.monotonic() - t0:.1f} s (parameters that contradict each other, or no weakness found)")
    q = {"question": "decrypt", "answer_format": {}}
    got = solve_sym(M, q)
    if got:
        lines.append(f"CIPHER {got[1]} with the stated key: {_short(got[0]['text'], 100)}")
    ec = solve_ecdsa(M, q)
    if ec:
        lines.append(f"ECDSA nonce reuse on {ec[2]}: d=0x{ec[0]:064x} k=0x{ec[1]:064x}")
    for tok in M.jwts[:5]:
        parts = lib.jwt_parts(tok)
        if parts:
            lines.append(f"JWT header={json.dumps(parts['header'])} payload={_short(json.dumps(parts['payload']), 200)} "
                         f"signature={len(parts['signature'])}B")
            secrets = lib.jwt_secret(tok, _jwt_strings(M))
            if secrets:
                lines.append(f"  HMAC verifies with a string of the delivery: {secrets[0]!r}")
    for h in _hash_strings(M, {"question": ""})[:10]:
        lines.append(f"HASH-SHAPED {_short(h, 48)}: {', '.join(lib.hash_candidates(h))} (shape only)")
    for col in lib.hash_collisions(M.members):
        names = ", ".join(f"{n} ({sz}B)" for n, sz in col["members"])
        lines.append(f"COLLISION {col['algo']} digest {col['digest']} shared by {col['count']} member(s): {names}")
        for pair in col["pairs"]:
            if pair.get("equal_length"):
                lines.append(f"  {pair['names'][0]} vs {pair['names'][1]}: first differ at byte {pair['first_diff_offset']}, "
                             f"{pair['diff_block_count']} of the 64-byte blocks differ (blocks {pair['diff_blocks']}), "
                             f"identical-prefix={pair['identical_prefix']} (construction method NOT identified)")
            else:
                lines.append(f"  {pair['names'][0]} vs {pair['names'][1]}: different lengths {pair['sizes']}")
    for xs in M.int_lists[:3]:
        note = f"INTS {len(xs)} integers"
        mt = lib.mt_clone(xs, 1) if len(xs) >= 624 else None
        if mt:
            note += f"; MT19937 clone: next={mt[0][0]} ({mt[1]} verified)"
        lcg = lib.lcg_recover(xs) if 6 <= len(xs) < 624 else None
        if lcg:
            note += f"; LCG m={lcg[0]} a={lcg[1]} c={lcg[2]} next={lcg[3]} ({lcg[4]} verified)"
        lines.append(note)
    for name, b in M.bins[:8]:
        info = lib.ecb_duplicates(b) if len(b) >= 32 else None
        lines.append(f"BYTES {name}: {len(b)} bytes" + (f", 16-byte blocks repeated: {info['repeats']} (of {info['blocks']})" if info and info["aligned"] else ""))
    return "\n".join(lines)


def main(argv) -> int:
    budget = 10.0
    if "--budget" in argv:
        i = argv.index("--budget")
        try:
            budget = float(argv[i + 1])
        except (IndexError, ValueError):
            print("usage: modern_crypto.py <file>... [--budget SECONDS]", file=sys.stderr)
            return 2
        argv = argv[:i] + argv[i + 2:]
    paths = [a for a in argv if not a.startswith("--")]
    if not paths or any(not Path(p).is_file() for p in paths):
        print("usage: modern_crypto.py <file>... [--budget SECONDS]", file=sys.stderr)
        return 2
    print(triage(paths, budget))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
