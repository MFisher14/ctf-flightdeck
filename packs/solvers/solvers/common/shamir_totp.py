#!/usr/bin/env python3
"""Shamir's Secret Sharing reconstruction and TOTP/HOTP, for the `modern_crypto` toolkit.

Pure, offline maths and parsing: no Game Master request, no network, nothing run. The caller
(solvers/toolkits/modern_crypto.py) wraps every value this module returns as an UNSURE
`labels.pick`, never plain, because the form the judge wants (a Shamir secret as an integer, as
bytes or as a flag; an OTP code zero-padded or not) is the author's choice, not the bytes'.

Never-wrong design:

- Shamir: Lagrange-interpolate f(0) over a prime field or GF(256). A reconstruction is returned
  ONLY when it is proven -- either the shares are OVER-DETERMINED (strictly more than the
  threshold) and every extra share lies on the interpolated polynomial (disagreeing k-subsets
  give None), or the threshold is stated in the bytes and exactly that many shares are read (the
  value is then determined, and the caller still answers it unsure). Two verified reconstructions
  that disagree on the secret give None.
- TOTP/HOTP: the code is computed from a base32 secret / otpauth:// URI and a STATED time or
  counter (RFC 6238 / RFC 4226). A question with no explicit time (a "current code") or no secret,
  or more than one secret, gives None. The code is deterministic, so it is still answered unsure
  (zero-padded vs unpadded) until a name is judged.
"""
import base64
import binascii
import hashlib
import hmac
import json
import re
import struct
from datetime import datetime, timezone

try:
    import gmpy2 as _gmpy2
except Exception:  # pragma: no cover - optional acceleration/probable-prime strengthening
    _gmpy2 = None

MAX_SHARES = 256
MAX_PRIME_BITS = 8192           # a field prime larger than this is not a Shamir field we read
MAX_SECRET_BYTES = 4096
_MR_BASES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
             59, 61, 67, 71, 73, 79, 83, 89)


def _prime_modulus(value: int) -> bool:
    """Reject composite rings before calling prime-field interpolation."""
    if value < 2:
        return False
    for prime in _MR_BASES:
        if value % prime == 0:
            return value == prime
    if _gmpy2 is not None:
        try:
            return bool(_gmpy2.is_prime(value, 30))
        except Exception:
            pass
    divisor, shifts = value - 1, 0
    while divisor % 2 == 0:
        divisor //= 2
        shifts += 1
    for base in _MR_BASES:
        witness = pow(base, divisor, value)
        if witness in (1, value - 1):
            continue
        for _ in range(shifts - 1):
            witness = witness * witness % value
            if witness == value - 1:
                break
        else:
            return False
    return True


# ---- GF(256) arithmetic (the AES reducing polynomial x^8 + x^4 + x^3 + x + 1) -------------------------

def _gf_tables():
    # generator 3 (0x02 is not a primitive element of GF(2^8) / 0x11b); exp/log over the whole group
    exp = [0] * 512
    log = [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        d = x << 1
        if d & 0x100:
            d ^= 0x11B
        x = d ^ x                               # x <- x * 3
    for i in range(255, 512):
        exp[i] = exp[i - 255]
    return exp, log


_GF_EXP, _GF_LOG = _gf_tables()


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def _gf_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("GF(256) inverse of 0")
    return _GF_EXP[255 - _GF_LOG[a]]


# ---- Lagrange interpolation --------------------------------------------------------------------------

def eval_prime(points, x: int, p: int) -> int:
    """The unique polynomial through `points` (distinct x), evaluated at `x`, over GF(p)."""
    total = 0
    for i, (xi, yi) in enumerate(points):
        num = 1
        den = 1
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            num = (num * (x - xj)) % p
            den = (den * (xi - xj)) % p
        total = (total + yi * num * pow(den, -1, p)) % p
    return total % p


def eval_gf256(points, x: int) -> int:
    """The same, over GF(256): points are (x_byte, y_byte)."""
    total = 0
    for i, (xi, yi) in enumerate(points):
        num = 1
        den = 1
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            num = _gf_mul(num, x ^ xj)          # (x - xj) == (x ^ xj) in characteristic 2
            den = _gf_mul(den, xi ^ xj)
        total ^= _gf_mul(yi, _gf_mul(num, _gf_inv(den)))
    return total


# ---- reconstruction (with verification) --------------------------------------------------------------

def recover_prime(points, prime: int, threshold=None):
    """f(0) over GF(prime) from (x, y) integer shares. Returns {secret_int, verified, threshold, n}
    or None. Over-determination (n > threshold with every extra share consistent) is the proof; a
    stated threshold equal to the share count is accepted unverified (deterministic)."""
    if (not isinstance(prime, int) or isinstance(prime, bool) or prime < 3 or
            prime.bit_length() > MAX_PRIME_BITS or not _prime_modulus(prime)):
        return None
    if threshold is not None and (not isinstance(threshold, int) or isinstance(threshold, bool)):
        return None
    try:
        pts = _dedup_prime(points, prime)
    except (TypeError, ValueError):
        return None
    n = len(pts)
    if n < 2:
        return None
    try:
        if threshold is not None:
            if not (2 <= threshold <= n):
                return None
            base = pts[:threshold]
            for x, y in pts[threshold:]:
                if eval_prime(base, x, prime) != y:
                    return None                 # disagreeing k-subset
            secret = eval_prime(base, 0, prime)
            return {"secret_int": secret, "verified": n > threshold, "threshold": threshold, "n": n}
        # threshold unknown: the smallest degree for which every extra share is consistent, and
        # there IS at least one extra share to confirm it
        for deg in range(1, n - 1):
            base = pts[:deg + 1]
            if all(eval_prime(base, x, prime) == y for x, y in pts[deg + 1:]):
                return {"secret_int": eval_prime(base, 0, prime), "verified": True,
                        "threshold": deg + 1, "n": n}
    except (ValueError, ZeroDivisionError):
        return None                             # the modulus gave no inverse: not this field
    return None


def recover_gf256(points, threshold=None):
    """f(0) over GF(256), per byte, from (x_byte, y_bytes) shares. Same proof rule as recover_prime."""
    if threshold is not None and (not isinstance(threshold, int) or isinstance(threshold, bool)):
        return None
    try:
        pts = _dedup_gf256(points)
    except (TypeError, ValueError):
        return None
    n = len(pts)
    if n < 2:
        return None
    L = len(pts[0][1])
    if not (1 <= L <= MAX_SECRET_BYTES) or any(len(y) != L for _, y in pts):
        return None

    def recon(t):
        base = pts[:t]
        out = bytearray(L)
        for pos in range(L):
            bp = [(x, y[pos]) for x, y in base]
            for x, y in pts[t:]:
                if eval_gf256(bp, x) != y[pos]:
                    return None                 # disagreeing k-subset at this byte
            out[pos] = eval_gf256(bp, 0)
        return bytes(out)

    try:
        if threshold is not None:
            if not (2 <= threshold <= n):
                return None
            s = recon(threshold)
            if s is None:
                return None
            return {"secret_bytes": s, "verified": n > threshold, "threshold": threshold, "n": n}
        for deg in range(1, n - 1):
            s = recon(deg + 1)
            if s is not None:
                return {"secret_bytes": s, "verified": True, "threshold": deg + 1, "n": n}
    except (ValueError, ZeroDivisionError):
        return None
    return None


def _dedup_prime(points, prime):
    out, seen = [], set()
    for x, y in points:
        if (not isinstance(x, int) or isinstance(x, bool) or
                not isinstance(y, int) or isinstance(y, bool)):
            return []
        if not (0 < x < prime) or not (0 <= y < prime):      # x=0 would reveal the secret directly
            return []
        if x in seen:
            return []                           # a repeated x-coordinate: refuse the whole set
        if len(out) >= MAX_SHARES:
            return []                           # never verify a prefix while ignoring extra shares
        seen.add(x)
        out.append((x, y))
    return out


def _dedup_gf256(points):
    out, seen = [], set()
    for x, y in points:
        if not isinstance(x, int) or isinstance(x, bool) or not isinstance(y, (bytes, bytearray)):
            return []
        if not (0 < x <= 255):
            return []
        if x in seen:
            return []
        if len(out) >= MAX_SHARES:
            return []
        seen.add(x)
        out.append((x, bytes(y)))
    return out


# ---- parsing the bytes -------------------------------------------------------------------------------

_INT = r"(?:0[xX][0-9a-fA-F]+|[0-9]+)"


def _to_int(tok: str):
    tok = tok.strip()
    try:
        return int(tok, 16) if tok[:2].lower() == "0x" else int(tok)
    except (ValueError, IndexError):
        return None


def find_moduli(text: str) -> list:
    """Candidate field primes written in the text: a labelled prime/modulus, GF(p)/Z_p/F_p, and
    2^k +/- c forms. GF(256)/GF(2^8) is a byte-field hint, not a prime, so it is left out."""
    out = []
    for m in re.finditer(r"\b(?:prime|modulus|field\s*(?:prime|size|order)?|order|p)\b[\"']?\s*(?:=|:|is|of)?\s*[\"']?(" + _INT + r")", text, re.I):
        v = _to_int(m.group(1))
        if v is not None:
            out.append(v)
    for m in re.finditer(r"\b(?:GF|Z|F|Z_|GF_)\s*[\(_]?\s*(" + _INT + r")\s*\)?", text):
        v = _to_int(m.group(1))
        if v is not None and v != 256:
            out.append(v)
    for m in re.finditer(r"2\s*(?:\*\*|\^)\s*(\d{1,5})\s*(?:([+-])\s*(\d{1,20}))?", text):
        k = int(m.group(1))
        if k > MAX_PRIME_BITS:
            continue
        base = 1 << k
        if m.group(2):
            base += int(m.group(3)) if m.group(2) == "+" else -int(m.group(3))
        out.append(base)
    return [v for v in dict.fromkeys(out) if 3 <= v.bit_length() <= MAX_PRIME_BITS or v > 2][:16]


def find_thresholds(text: str) -> list:
    """Candidate thresholds (the minimum shares to reconstruct) written in the text."""
    out = []
    for m in re.finditer(r"\b(?:threshold|quorum|minimum(?:\s+(?:number\s+)?of\s+shares)?|at\s+least|need(?:ed|s)?|require[sd]?|k|t)\s*(?:=|:|is|of)?\s*(\d{1,3})\b", text, re.I):
        out.append(int(m.group(1)))
    for m in re.finditer(r"\b(\d{1,3})\s*(?:-|\s)?(?:of|out\s+of|/)\s*(?:-\s*)?\d{1,3}\b", text, re.I):
        out.append(int(m.group(1)))
    return [v for v in dict.fromkeys(out) if 2 <= v <= MAX_SHARES]


def _json_prime_shares(obj) -> list:
    """(x, y) integer pairs from a decoded JSON structure."""
    out = []
    if isinstance(obj, dict):
        inner = obj.get("shares") or obj.get("points") or obj.get("shards")
        if inner is not None:
            return _json_prime_shares(inner)
        # {"1": 123, "2": 456}  -- x -> y mapping
        pairs = []
        for k, v in obj.items():
            xi, yi = _to_int(str(k)), (v if isinstance(v, int) else _to_int(str(v)))
            if xi is not None and yi is not None:
                pairs.append((xi, yi))
        return pairs
    if isinstance(obj, list):
        for item in obj:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                xi = item[0] if isinstance(item[0], int) else _to_int(str(item[0]))
                yi = item[1] if isinstance(item[1], int) else _to_int(str(item[1]))
                if xi is not None and yi is not None:
                    out.append((xi, yi))
            elif isinstance(item, dict):
                xi = item.get("x")
                yi = item.get("y") if "y" in item else item.get("value")
                xi = xi if isinstance(xi, int) else _to_int(str(xi)) if xi is not None else None
                yi = yi if isinstance(yi, int) else _to_int(str(yi)) if yi is not None else None
                if xi is not None and yi is not None:
                    out.append((xi, yi))
    return out


def parse_prime_shares(text: str) -> list:
    """(x, y) integer pairs from text: JSON, `(x, y)` tuples, `x: y` / `x, y` lines, `x=.. y=..`."""
    candidates = []
    stripped = text.strip()
    if stripped[:1] in "{[":
        try:
            pairs = _json_prime_shares(json.loads(stripped))
            if len(pairs) >= 2:
                candidates.append(pairs)
        except (ValueError, TypeError):
            pass
    # x=1, y=12345  (both labelled, on one line)
    xy = []
    for m in re.finditer(r"(?:x|share)\s*[_#]?\d*\s*=\s*(" + _INT + r")[^\n]*?\by\s*=\s*(" + _INT + r")", text, re.I):
        xi, yi = _to_int(m.group(1)), _to_int(m.group(2))
        if xi is not None and yi is not None:
            xy.append((xi, yi))
    if len(xy) >= 2:
        candidates.append(xy)
    # (x, y) tuples
    tup = []
    for m in re.finditer(r"\(\s*(" + _INT + r")\s*,\s*(" + _INT + r")\s*\)", text):
        xi, yi = _to_int(m.group(1)), _to_int(m.group(2))
        if xi is not None and yi is not None:
            tup.append((xi, yi))
    if len(tup) >= 2:
        candidates.append(tup)
    # one pair per line:  "1: 12345" / "1, 12345" / "1 -> 12345"
    line = []
    for raw in text.splitlines():
        m = re.fullmatch(r"\s*(?:share\s*)?(\d{1,4})\s*(?:[,:]|->|=>|\t| )\s*(" + _INT + r")\s*", raw, re.I)
        if m:
            xi, yi = _to_int(m.group(1)), _to_int(m.group(2))
            if xi is not None and yi is not None:
                line.append((xi, yi))
    if len(line) >= 2:
        candidates.append(line)
    # the first candidate set with at least two distinct x wins its strategy slot; return all so
    # the caller can try each against each prime and threshold
    return candidates


def parse_gf256_shares(text: str) -> list:
    """(x_byte, y_bytes) shares from the `x-hexbytes` / `x:hexbytes` line format and JSON maps."""
    stripped = text.strip()
    if stripped[:1] in "{[":
        try:
            obj = json.loads(stripped)
            inner = obj.get("shares") if isinstance(obj, dict) else obj
            out = []
            if isinstance(inner, dict):
                for k, v in inner.items():
                    xi = _to_int(str(k))
                    yb = _hexbytes(str(v))
                    if xi is not None and yb is not None:
                        out.append((xi, yb))
            elif isinstance(inner, list):
                for item in inner:
                    s = item if isinstance(item, str) else None
                    if s is not None:
                        pair = _split_x_hex(s)
                        if pair:
                            out.append(pair)
            if len(out) >= 2:
                return out
        except (ValueError, TypeError, AttributeError):
            pass
    out = []
    for raw in text.splitlines():
        pair = _split_x_hex(raw.strip())
        if pair:
            out.append(pair)
    return out if len(out) >= 2 else []


def _split_x_hex(s: str):
    m = re.fullmatch(r"(?:share\s*)?(\d{1,3})\s*[-:]\s*([0-9a-fA-F]{2,})", s)
    if not m:
        return None
    xi = int(m.group(1))
    yb = _hexbytes(m.group(2))
    return (xi, yb) if yb is not None and len(yb) >= 1 else None


def _hexbytes(s: str):
    s = re.sub(r"\s|:", "", s)
    if s[:2].lower() == "0x":
        s = s[2:]
    if len(s) >= 2 and len(s) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", s):
        try:
            return bytes.fromhex(s)
        except ValueError:
            return None
    return None


def recover(texts, question_text: str = ""):
    """Reconstruct a Shamir secret from the delivery's text members and the question's own text.

    Returns {field, secret_int, secret_bytes, verified, threshold, n, prime?} or None. A verified
    (over-determined) reconstruction is preferred; two verified reconstructions that disagree on
    the secret give None (ambiguous)."""
    all_text = "\n".join(t for t in texts if t) + "\n" + (question_text or "")
    primes = find_moduli(all_text)
    thresholds = find_thresholds(all_text)
    results = []

    share_sets = []
    for t in list(texts) + ([question_text] if question_text else []):
        if t:
            share_sets.extend(parse_prime_shares(t))
    for pts in share_sets:
        for prime in primes:
            for thr in [None] + thresholds:
                r = recover_prime(pts, prime, thr)
                if r:
                    r["field"] = "prime"
                    r["prime"] = prime
                    r["secret_bytes"] = _int_to_bytes(r["secret_int"])
                    results.append(r)

    gf = []
    for t in list(texts) + ([question_text] if question_text else []):
        if t:
            g = parse_gf256_shares(t)
            if g:
                gf.append(g)
    for pts in gf:
        for thr in [None] + thresholds:
            r = recover_gf256(pts, thr)
            if r:
                r["field"] = "gf256"
                r["secret_int"] = int.from_bytes(r["secret_bytes"], "big") if r["secret_bytes"] else 0
                results.append(r)

    if not results:
        return None
    tier = [r for r in results if r["verified"]] or results
    secrets = {(r["field"], r["secret_int"]) for r in tier}
    if len(secrets) != 1:
        return None                             # contradictory reconstructions: refuse
    best = sorted(tier, key=lambda r: (-r["n"], r["threshold"]))[0]
    return best


def _int_to_bytes(n: int) -> bytes:
    if n < 0:
        return b""
    return n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")


# ---- TOTP / HOTP (RFC 4226 / RFC 6238) ---------------------------------------------------------------

_HASHES = {"sha1": hashlib.sha1, "sha256": hashlib.sha256, "sha512": hashlib.sha512}


def hotp(secret: bytes, counter: int, digits: int = 6, algo: str = "sha1") -> int:
    """RFC 4226 HOTP: dynamic-truncation of HMAC-<algo>(secret, counter)."""
    fn = _HASHES.get(algo.lower())
    if fn is None or counter < 0:
        raise ValueError("unsupported HOTP parameters")
    mac = hmac.new(secret, struct.pack(">Q", counter), fn).digest()
    off = mac[-1] & 0x0F
    code = ((mac[off] & 0x7F) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3]
    return code % (10 ** digits)


def totp(secret: bytes, unix_time: int, period: int = 30, t0: int = 0, digits: int = 6, algo: str = "sha1") -> int:
    """RFC 6238 TOTP: HOTP with counter = floor((unix_time - t0) / period)."""
    if period <= 0:
        raise ValueError("period must be positive")
    return hotp(secret, (unix_time - t0) // period, digits, algo)


def b32_secret(s: str):
    """The bytes of a base32 secret, or None. Spaces removed, case-folded, padding fixed."""
    s = re.sub(r"\s", "", s or "").upper().rstrip("=")
    if len(s) < 8 or not re.fullmatch(r"[A-Z2-7]+", s):
        return None
    try:
        return base64.b32decode(s + "=" * (-len(s) % 8))
    except (binascii.Error, ValueError):
        return None


_OTPAUTH = re.compile(r"otpauth://(totp|hotp)/([^?\s]*)\?([^\s\"'`<>]+)", re.I)


def parse_otpauth(uri: str):
    """One otpauth:// URI -> a spec dict, or None."""
    m = _OTPAUTH.match(uri.strip())
    if not m:
        return None
    typ = m.group(1).lower()
    query = {}
    for part in m.group(3).split("&"):
        if "=" in part:
            k, v = part.split("=", 1)
            query[k.lower()] = _url_unquote(v)
    secret = b32_secret(query.get("secret", ""))
    if secret is None:
        return None
    spec = {"type": typ, "secret": secret, "secret_b32": re.sub(r"\s", "", query.get("secret", "")).upper().rstrip("="),
            "algo": (query.get("algorithm") or "sha1").lower(), "digits": _int_or(query.get("digits"), 6),
            "period": _int_or(query.get("period"), 30)}
    if "counter" in query:
        spec["counter"] = _int_or(query.get("counter"), None)
    if spec["algo"] not in _HASHES or spec["digits"] not in (6, 7, 8) or spec["period"] <= 0:
        return None
    return spec


def _url_unquote(s: str) -> str:
    def rep(m):
        try:
            return bytes.fromhex(m.group(1)).decode("latin-1")
        except ValueError:
            return m.group(0)
    return re.sub(r"%([0-9a-fA-F]{2})", rep, s.replace("+", " "))


def _int_or(v, default):
    if v is None:
        return default
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def otp_specs(text: str) -> list:
    """Every OTP secret the text offers, each a spec dict. otpauth:// URIs first, then a single
    labelled base32 secret. A spec from a bare secret carries only the defaults."""
    out = []
    seen = set()
    for m in _OTPAUTH.finditer(text):
        spec = parse_otpauth(m.group(0))
        if spec and spec["secret"] not in seen:
            seen.add(spec["secret"])
            out.append(spec)
    if out:
        return out
    for m in re.finditer(r"\b(?:secret|seed|shared[\s_-]?secret|otp[\s_-]?secret|key|token[\s_-]?seed)\b\s*(?:key)?\s*(?:=|:|is)?\s*[\"'`]?([A-Z2-7]{8,}=*)[\"'`]?", text, re.I):
        secret = b32_secret(m.group(1))
        if secret is not None and secret not in seen:
            seen.add(secret)
            out.append({"type": None, "secret": secret, "secret_b32": re.sub(r"\s", "", m.group(1)).upper().rstrip("="),
                        "algo": "sha1", "digits": 6, "period": 30})
    return out


def find_unix_time(text: str):
    """A single stated Unix time (a 10-digit epoch, or an epoch labelled by a time word, or an ISO
    8601 UTC datetime). None when none, or more than one distinct value, is stated."""
    found = set()
    for m in re.finditer(r"\b(?:unix\s*time|unixtime|timestamp|epoch|time|at\s+time|current\s+time|now)\b[^\d]{0,16}(\d{9,11})\b", text, re.I):
        found.add(int(m.group(1)))
    for m in re.finditer(r"\b(\d{10})\b", text):
        v = int(m.group(1))
        if 1_000_000_000 <= v <= 4_102_444_800:        # 2001-09 .. 2100
            found.add(v)
    for m in re.finditer(r"\b(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}))?\s*(?:Z|UTC)?\b", text):
        try:
            dt = datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4)),
                          int(m.group(5)), int(m.group(6) or 0), tzinfo=timezone.utc)
            found.add(int(dt.timestamp()))
        except ValueError:
            pass
    return next(iter(found)) if len(found) == 1 else None


def find_counter(text: str):
    """A single stated HOTP counter (moving factor). None when absent or ambiguous."""
    found = set()
    for m in re.finditer(r"\b(?:counter|moving\s*factor|count|sequence)\b\s*(?:value)?\s*(?:=|:|is|of)?\s*(\d{1,12})\b", text, re.I):
        found.add(int(m.group(1)))
    return next(iter(found)) if len(found) == 1 else None
