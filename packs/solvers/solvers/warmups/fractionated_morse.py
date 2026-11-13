"""Fail-closed known-plaintext reader for classical Fractionated Morse.

Fractionated Morse replaces each Morse trigram over ``. - x`` (``x`` is the
letter/word separator) with one letter of a keyed alphabet.  The Warmups
sentence is long enough to exercise 25 of the 26 legal trigrams.  That gives a
particularly narrow recovery rule:

* infer a bijection only from complete crib trigrams;
* require every ciphertext symbol used anywhere in the artifact to have been
  established by that crib (the one unseen trigram is never guessed);
* decode the complete stream, including punctuation and padding, in exactly
  one way; and
* return only one full ``word-word-word-NN`` slug after the exact sentence.

The caller keeps the result unsure under a hash of this artifact.  A verdict
for one keyed alphabet therefore cannot make another artifact plain.  This
module performs no I/O and every loop is bounded by ``MAX_CIPHER`` and the
caller's deadline.
"""
from __future__ import annotations

import hashlib
import itertools
import re
import time


MAX_CIPHER = 4096
CUT = object()
SLUG = re.compile(r"[a-z]+-[a-z]+-[a-z]+-[0-9]{2}")

_CODES = (
    ".- -... -.-. -.. . ..-. --. .... .. .--- -.- .-.. -- -. --- .--. --.- .-. ... - "
    "..- ...- .-- -..- -.-- --.."
).split()
MORSE = dict(zip("ABCDEFGHIJKLMNOPQRSTUVWXYZ", _CODES))
MORSE.update(dict(zip("0123456789", "----- .---- ..--- ...-- ....- ..... -.... --... ---.. ----.".split())))
MORSE.update({
    ".": ".-.-.-", ",": "--..--", "?": "..--..", "'": ".----.", "!": "-.-.--",
    "/": "-..-.", "(": "-.--.", ")": "-.--.-", "&": ".-...", ":": "---...",
    ";": "-.-.-.", "=": "-...-", "+": ".-.-.", "-": "-....-", "_": "..--.-",
    '"': ".-..-.", "$": "...-..-", "@": ".--.-.",
})
FROM_MORSE = {value: key for key, value in MORSE.items()}
TRIGRAMS = frozenset("".join(chars) for chars in itertools.product(".-x", repeat=3)
                     if "".join(chars) != "xxx")


def _stream(text: str, trailing_space: bool = False):
    """Canonical Morse/separator stream, without fractionation padding."""
    if not isinstance(text, str):
        return None
    stripped = text.rstrip(" ")
    if not stripped or any(ch != " " and ch.upper() not in MORSE for ch in stripped):
        return None
    words = stripped.split(" ")
    if any(not word for word in words):
        return None
    try:
        stream = "xx".join("x".join(MORSE[ch.upper()] for ch in word) for word in words)
    except KeyError:
        return None
    if trailing_space or text.endswith(" "):
        stream += "xx"
    return stream


def _decode(stream: str):
    """The exact text represented by an unpadded Morse/separator stream."""
    if not stream or stream.startswith("x") or stream.endswith("x") or "xxx" in stream:
        return None
    words = stream.split("xx")
    if any(not word for word in words):
        return None
    out = []
    for word in words:
        codes = word.split("x")
        if any(not code or code not in FROM_MORSE for code in codes):
            return None
        out.append("".join(FROM_MORSE[code] for code in codes))
    return " ".join(out)


def read(text: str, crib: str, deadline: float):
    """Return one artifact-scoped Fractionated-Morse reading, ``CUT``, or None.

    The return is ``{"slug", "fingerprint", "chain"}``.  It contains no
    confidence decision; ``crib_decode`` deliberately turns it into a
    truth-bearing unsure answer under the fingerprinted key.
    """
    if time.perf_counter() > deadline:
        return CUT
    if not isinstance(text, str) or not isinstance(crib, str) or not crib.endswith(" "):
        return None
    if not (1 <= len(text) <= MAX_CIPHER):
        return None
    # Whitespace is presentation grouping only.  Every other character must be
    # one classical ciphertext letter, and mixed case is refused rather than
    # silently treated as a second alphabet.
    compact = "".join(text.split())
    if not compact or not compact.isascii() or not compact.isalpha():
        return None
    if not (compact.isupper() or compact.islower()):
        return None
    cipher = compact.upper()

    known = _stream(crib, trailing_space=True)
    if known is None:
        return None
    groups = [known[index:index + 3] for index in range(0, len(known) - 2, 3)]
    if len(cipher) <= len(groups):
        return None

    symbol_to_group, group_to_symbol = {}, {}
    for index, (symbol, group) in enumerate(zip(cipher, groups)):
        if index % 64 == 0 and time.perf_counter() > deadline:
            return CUT
        if group not in TRIGRAMS:
            return None
        before_group = symbol_to_group.get(symbol)
        before_symbol = group_to_symbol.get(group)
        if ((before_group is not None and before_group != group)
                or (before_symbol is not None and before_symbol != symbol)):
            return None
        symbol_to_group[symbol] = group
        group_to_symbol[group] = symbol

    # The fixed sentence presently proves 25 legal trigrams.  Recompute that
    # fact instead of hard-coding an alphabet/key: a shortened or changed crib
    # cannot silently weaken the gate.
    proved = set(groups)
    if (len(proved) != len(TRIGRAMS) - 1
            or TRIGRAMS - proved != {".xx"}
            or len(symbol_to_group) != len(proved)):
        return None
    if any(symbol not in symbol_to_group for symbol in cipher):
        return None                         # unseen key entry: never fill/guess it

    stream_parts = []
    for index, symbol in enumerate(cipher):
        if index % 128 == 0 and time.perf_counter() > deadline:
            return CUT
        stream_parts.append(symbol_to_group[symbol])
    padded = "".join(stream_parts)

    readings = set()
    expected = crib.upper()
    for padding in (0, 1, 2):
        if padding and not padded.endswith("x" * padding):
            continue
        raw = padded[:-padding] if padding else padded
        decoded = _decode(raw)
        if decoded is None or not decoded.startswith(expected):
            continue
        tail = decoded[len(expected):].lower()
        if SLUG.fullmatch(tail):
            readings.add(tail)
    if len(readings) != 1:
        return None
    slug = next(iter(readings))
    fingerprint = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
    return {"slug": slug, "fingerprint": fingerprint, "chain": "fractionated_morse:crib-map"}
