"""Extra deterministic encoding readers for Warmups (breadth build, 2026-10-23).

Why this file exists
--------------------
Day 23's Warmups Mastery closed +15m: three `message` ids came back None at the gate and
were only recovered by a proven-day-walk day_patch. The lane's weakness is morning-of
adaptation to a NEW encoding. This file pre-builds the base-N / encoding shapes that were NOT
already shipped, so the next release needs no in-run adaptation for them.

Coverage audit (2026-10-23)
---------------------------
crib_decode.py, layered_decode.py and formats_more.py already read a very wide family, and
this build confirmed each of these is SHIPPED (and so NOT duplicated here):

  hex, binary, octal, decimal, radix 3-36, base32 (RFC4648), base32hex, base45, base64,
  base64url, base85 (RFC1924), ascii85/adobe (a85), Z85, base91, base92, base100,
  base58 bitcoin (d_b58) AND Flickr (b58f) AND Ripple (b58r), base62 in four alphabets
  (0-9A-Za-z, 0-9a-zA-Z, a-zA-Z0-9 = b62u, A-Za-z0-9), base36, Crockford base32 (crock32),
  z-base-32 (zb32), uuencode, xxencode, yEnc, quoted-printable, UTF-7/16/32, EBCDIC cp037/
  500/273, base65536/32768/2048, Ecoji 1/2, Morse (many variants), NATO/phonetic, Vigenere /
  Beaufort / variant-Beaufort / Gronsfeld / Porta / autokey / running-key / Trithemius,
  rail-fence (with offsets) / columnar (keyword) / scytale / redefence / route / double
  columnar / Myszkowski / decimation, Hill, bifid, ADFGX/ADFGVX, Nihilist, Playfair, the lossy
  codes (Polybius, tap, A1Z26, Bacon, Braille, leetspeak), random monoalphabetic substitution.

The only DETERMINISTIC encodings from the target list that were genuinely missing:

  gray      reflected-binary (Gray code) byte transform
  b58check  Base58Check (bitcoin alphabet, trailing 4-byte double-SHA256 checksum verified)

Both are the kind of deterministic encoding the Warmups lane answers PLAIN (the full-sentence
crib proves the reading), so they are strict readers here. (The remaining genuine gaps are the
KEYED classical ciphers trifid, four-square, two-square and straddling checkerboard; those are
lossy / unsure-only and belong in solvers/warmups/lossy_ciphers.py with its known-plaintext
machinery -- see the build report. They are NOT shipped here, to avoid speculative crypto.)

NEVER WRONG
-----------
* Nothing here is answered on the codec's own name: a reading is plain only because
  crib_decode's search confirms the decoded bytes continue the exact sentence
  (crib_decode.CRIB). The `read()` helper applies that same crib gate for standalone / test
  use, so a decoy that merely shares a shape yields NOTHING, never a wrong plain slug.
* `b58check` verifies the double-SHA256 checksum, so a non-Base58Check payload is refused
  before the crib is even consulted -- a very strong signature.
* `gray` has no alphabet signature (a deterministic byte bijection, like the shipped `rot47`):
  it reads any input, is gated only by a printable-ASCII decode and, past the solver, by the
  crib, and preserves digits one-for-one (so the slug's digits are plain, never digit-unsure).
  The plain sentence Gray-decodes to non-crib garbage, so it never steals a read.

warm() safety
-------------
Pure functions, no I/O, no global mutable state, no clock, no import of crib_decode. Bounded by
the payload length (MAX_TEXT) and `hashlib` only. Safe to call from crib_decode.warm() on a
thread and from a timed solve alike.

Wiring (for the build-lead; this module changes no shipped file)
----------------------------------------------------------------
This file follows byte_order.py's interface exactly:

    BY_NAME   {step name: decoder(bytes) -> bytes | None}
    NAMES     frozenset(BY_NAME)
    _which(cur) -> tuple of applicable step names (cheap signature gate)
    steps(cur) -> list[(name, bytes)]
    step_fn(name) -> decoder(bytes) -> bytes | None

To make the readers live in crib_decode.py, mirror the byte_order (BO) hookup:
    1. `import base_extra as BE` with the same try/except guard as `import byte_order as BO`.
    2. in `_strict_steps`, after `yield from BO.steps(cur)`, add `if BE is not None:
       yield from BE.steps(cur)`.
    3. add `_STRICT_NAMES |= set(BE.NAMES)` next to the BO line.
    4. in `_step_fn`, add `if BE is not None and name in BE.NAMES: return BE.step_fn(name)`.
Both names here are strict, so each is in _STRICT_NAMES and its chain is answered plain.
Alternatively, each reader can be registered at import time with
`crib_decode.add_strict(fn, name)` (what the test does), which both `_strict_steps` and
`_step_fn` already honour. The step name `gray` reads any byte input, so (like rot47) the
build-lead may prefer to keep it last among the strict readers; `b58check` has a strong
signature and costs only a checksum. No saved day of Days 1-22 is read by either reader
(the test proves it), so no earlier day can move.
"""

import hashlib

MAX_TEXT = 1 << 16        # characters of a text payload looked at (base-N blobs are ~110-250 chars)
_MIN_CHECK = 10           # base58check: 4 checksum bytes + at least a little payload

B58_BITCOIN = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


# -- Gray-code (reflected binary) decode table -----------------------------------------------
def _gray_decode_byte(g: int) -> int:
    """binary = g ^ (g>>1) ^ (g>>2) ^ ... over an 8-bit byte (the doubling method)."""
    g ^= g >> 1
    g ^= g >> 2
    g ^= g >> 4
    return g & 0xFF


_GRAY = bytes(_gray_decode_byte(x) for x in range(256))
_GRAY_ENCODE = bytes((x ^ (x >> 1)) & 0xFF for x in range(256))   # for encoders / tests


# -- helpers ---------------------------------------------------------------------------------
def _compact(b):
    """A text payload as a whitespace-free ASCII str, or None when it is not ASCII text."""
    if not isinstance(b, (bytes, bytearray, memoryview)):
        return None
    b = bytes(b)
    if len(b) > MAX_TEXT:
        return None
    try:
        t = b.decode("ascii")
    except UnicodeDecodeError:
        return None
    return "".join(t.split())


def _is_text(b: bytes) -> bool:
    """True when every byte is printable ASCII or a common white-space byte."""
    return all(c in (0x09, 0x0A, 0x0D) or 0x20 <= c <= 0x7E for c in b)


def _int_bytes(n: int) -> bytes:
    """A non-negative integer as its big-endian bytes (empty for 0)."""
    return n.to_bytes((n.bit_length() + 7) // 8, "big") if n > 0 else b""


# -- b58check --------------------------------------------------------------------------------
def _b58_raw(t: str, alphabet: str):
    """The full base58 decode of `t` under `alphabet`, leading-zero bytes included, or None."""
    idx = {c: i for i, c in enumerate(alphabet)}
    n = 0
    for c in t:
        v = idx.get(c)
        if v is None:
            return None
        n = n * 58 + v
    pad = len(t) - len(t.lstrip(alphabet[0]))   # each leading zero-symbol is a leading 0x00 byte
    return b"\x00" * pad + _int_bytes(n)


def d_b58check(b: bytes):
    """Base58Check (bitcoin alphabet): the payload with its trailing 4-byte double-SHA256
    checksum verified and stripped. Self-verifying, so a non-Base58Check payload is refused
    outright. A version/prefix byte, if the encoder used one, stays part of the payload and
    the crib then does not match (None, never wrong)."""
    t = _compact(b)
    if not t or len(t) < _MIN_CHECK:
        return None
    raw = _b58_raw(t, B58_BITCOIN)
    if raw is None or len(raw) < 5:
        return None
    payload, checksum = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != checksum:
        return None
    return payload or None


# -- gray ------------------------------------------------------------------------------------
def d_gray(b):
    """Reflected-binary (Gray code) decode of every byte.

    Gray has no alphabet signature: it is a deterministic byte bijection, like the shipped
    `rot47`, so it reads any input (the already-plain sentence decodes to garbage the crib
    then rejects). It is gated only by a printable-ASCII output and, past the solver, by the
    crib. Hex/binary of Gray-coded bytes is the usual warmup shape, so the bytes reaching this
    reader may well be printable -- which is why no input-text gate is possible. Digits are
    preserved one-for-one (a bijection on bytes), so the answer is plain, never digit-unsure.
    """
    if not isinstance(b, (bytes, bytearray, memoryview)):
        return None
    b = bytes(b)
    if not b or len(b) > MAX_TEXT:
        return None
    out = b.translate(_GRAY)
    if not _is_text(out):
        return None
    # Prose gate (Day 24 wiring): the sentence and a slug are letters, digits, spaces and a little
    # punctuation, so the decode must be at least 90% of those. Gray-decoding anything that was not
    # Gray-coded gives noise that fails this, which keeps the loose reader from fanning the search.
    good = sum(1 for c in out if (48 <= c <= 57 or 65 <= c <= 90 or 97 <= c <= 122 or c in b" -,.!:"))
    return out if good * 10 >= len(out) * 9 else None


# -- registry (byte_order.py interface) ------------------------------------------------------
BY_NAME = {"b58check": d_b58check, "gray": d_gray}
NAMES = frozenset(BY_NAME)

_B58_SET = set(B58_BITCOIN)


def _which(cur) -> tuple:
    """The step names whose signature a payload could match: a cheap gate so steps() runs only
    the plausible decoders. Each decoder still checks itself exactly."""
    names = []
    t = _compact(cur)
    if t and len(t) >= _MIN_CHECK and set(t) <= _B58_SET:
        names.append("b58check")
    # gray has no signature (a byte bijection like rot47); offer it for any byte input and let
    # d_gray gate on a printable decode. It is the one loose reader here.
    if isinstance(cur, (bytes, bytearray, memoryview)) and len(cur):
        names.append("gray")
    return tuple(names)


def steps(cur) -> list:
    """[(name, bytes)]: what the readers of this module make of one payload."""
    out = []
    for name in _which(cur):
        try:
            o = BY_NAME[name](cur)
        except Exception:
            o = None
        if o:
            out.append((name, o))
    return out


def step_fn(name: str):
    """The decoder (bytes -> bytes or None) of one step by its name, or None. Like
    byte_order.step_fn, the returned function re-checks the signature with _which."""
    fn = BY_NAME.get(name)
    if fn is None:
        return None

    def f(b):
        return fn(b) if name in _which(b) else None
    f.__name__ = "d_" + name
    return f


# -- crib-gated reader (standalone / test use; mirrors crib_decode's search) ------------------
CRIB = "Nice work decoding this warmup! To solve, submit this exact answer to the Game Master: "


def read(blob, crib: str = CRIB):
    """Every (name, decoded text) this module reads whose decode CONTINUES the crib sentence.

    This is the never-wrong gate the full solver applies: a reader is answered plain only when
    its bytes reproduce the exact sentence. Returns a list so a decoy that merely shares a
    shape (and so decodes to garbage) yields NOTHING, not a wrong reading.
    """
    found = []
    for name, out in steps(blob):
        try:
            text = out.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if text.startswith(crib):
            found.append((name, text))
    return found


# -- encoders (tests and round-trip only; never used by the solver) --------------------------
def enc_b58(data: bytes, alphabet: str = B58_BITCOIN) -> str:
    pad = len(data) - len(data.lstrip(b"\x00"))
    n = int.from_bytes(data, "big") if data else 0
    s = ""
    while n > 0:
        n, r = divmod(n, 58)
        s = alphabet[r] + s
    return alphabet[0] * pad + s


def enc_b58check(data: bytes) -> str:
    checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    return enc_b58(data + checksum, B58_BITCOIN)


def enc_gray(data: bytes) -> bytes:
    return bytes(data).translate(_GRAY_ENCODE)


ENCODERS = {
    "b58check": lambda d: enc_b58check(d).encode(),
    "gray": enc_gray,
}


if __name__ == "__main__":
    import sys
    if not sys.argv[1:] or any(a in ("-h", "--help") for a in sys.argv[1:]):
        print("usage: base_extra.py <file> [...]", file=sys.stderr if not sys.argv[1:] else sys.stdout)
        raise SystemExit(2 if not sys.argv[1:] else 0)
    for path in sys.argv[1:]:
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            print(f"base_extra.py: {exc}", file=sys.stderr)
            raise SystemExit(2)
        print(path, "->", read(data) or steps(data))
