"""Strict, offline character and base-N decoder candidates for CSCTF.

The module deliberately does not guess plaintext.  A reader returns a :class:`Candidate`
only after its syntax is complete and, where an inverse exists, the decoded value encodes
back to the exact input.  Text codecs additionally require a strict byte round trip and a
printability check.  Ambiguous historical encodings return *candidates* rather than silently
choosing an alphabet.

Nothing here performs I/O.  ``steps`` and ``step_fn`` provide the small registry interface
used by the existing warmup search; integration is intentionally left to the build lead.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import encodings
import encodings.aliases
import importlib
import pkgutil
import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from typing import Callable, Iterable


MAX_INPUT = 8 * 1024 * 1024


@dataclass(frozen=True)
class Candidate:
    """One structurally valid decoding, not a claim that its plaintext is the answer."""

    codec: str
    payload: bytes
    confidence: float = 1.0
    note: str = ""


def _as_bytes(value: object) -> bytes | None:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        return None
    data = bytes(value)
    return data if 0 < len(data) <= MAX_INPUT else None


def _ascii(value: object, *, compact: bool = False) -> str | None:
    data = _as_bytes(value)
    if data is None:
        return None
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return None
    return "".join(text.split()) if compact else text.strip()


def _text_quality(text: str) -> float:
    """A conservative language-agnostic text check.

    Letters from every script, numbers, punctuation and ordinary separators count.  C0/C1,
    surrogates, unassigned and private-use characters do not.  This is only a shape gate;
    callers still receive candidates for ambiguous single-byte code pages.
    """

    if not text:
        return 0.0
    good = visible = 0
    for char in text:
        category = unicodedata.category(char)
        if char in "\t\r\n" or category == "Zs":
            good += 1
        elif char.isprintable() and category[0] in "LMNPSZ" and category not in {"Co", "Cs", "Cn"}:
            good += 1
            visible += 1
    return (good / len(text)) * (1.0 if visible else 0.25)


_BINARY_CODECS = {
    "base64_codec", "base64", "bz2_codec", "bz2", "hex_codec", "hex",
    "quopri_codec", "quopri", "uu_codec", "uu", "zlib_codec", "zlib",
}


@lru_cache(maxsize=1)
def python_character_codecs() -> tuple[str, ...]:
    """Every installed Python codec whose strict decoder maps bytes to ``str``.

    The stdlib codec registry has no public enumeration API, so the set is formed from the
    ``encodings`` package modules, its alias table, and the optional ``ebcdic`` package.  Each
    name is then probed through :func:`codecs.lookup`; binary transforms are excluded.
    """

    names = set(encodings.aliases.aliases) | set(encodings.aliases.aliases.values())
    names.update(m.name.rsplit(".", 1)[-1] for m in pkgutil.iter_modules(encodings.__path__))
    try:
        package = importlib.import_module("ebcdic")
        path = getattr(package, "__path__", ())
        names.update(m.name.rsplit(".", 1)[-1] for m in pkgutil.iter_modules(path))
    except Exception:
        pass
    # Names provided by Python even when the optional EBCDIC package is absent.
    names.update({"cp037", "cp273", "cp424", "cp500", "cp875", "cp1026", "cp1140"})

    found: dict[str, str] = {}
    for name in sorted(names):
        key = name.lower().replace("-", "_")
        if key in _BINARY_CODECS or key.startswith("undefined"):
            continue
        try:
            info = codecs.lookup(name)
            # Probe from Unicode first so fixed-width codecs which require a BOM or a complete
            # code unit (UTF-16/32) are not accidentally omitted.  Binary transforms reject a
            # str input or return non-bytes and are therefore excluded naturally.
            encoded, used = info.encode("A", "strict")
            if not isinstance(encoded, (bytes, bytearray)) or used != 1:
                continue
            decoded, consumed = info.decode(bytes(encoded), "strict")
            if not isinstance(decoded, str) or decoded != "A" or consumed != len(encoded):
                continue
        except Exception:
            continue
        found.setdefault(info.name, name)
    return tuple(sorted(found))


def decode_python_codec(data: object, name: str, *, min_quality: float = 0.88) -> Candidate | None:
    """Strictly decode one character codec and require byte-for-byte re-encoding."""

    raw = _as_bytes(data)
    if raw is None or not isinstance(name, str) or not name:
        return None
    try:
        info = codecs.lookup(name)
        text, consumed = info.decode(raw, "strict")
        if not isinstance(text, str) or consumed != len(raw) or _text_quality(text) < min_quality:
            return None
        rebuilt, used = info.encode(text, "strict")
        if used != len(text) or bytes(rebuilt) != raw:
            return None
    except Exception:
        return None
    payload = text.encode("utf-8")
    if not payload:
        return None
    bom = raw.startswith((codecs.BOM_UTF8, codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE,
                          codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE))
    ebcdic = info.name.startswith("cp0") or info.name in {"cp273", "cp424", "cp500", "cp875", "cp1026", "cp1140"}
    score = 1.0 if bom else (0.94 if ebcdic and any(b >= 0x80 for b in raw) else 0.82)
    return Candidate(f"charset:{info.name}", payload, score, "strict decode and exact encode round-trip")


def decode_character_encodings(
    data: object,
    names: Iterable[str] | None = None,
    *,
    min_quality: float = 0.88,
) -> list[Candidate]:
    """Try all installed character codecs (or ``names``), retaining distinct codec readings."""

    selected = python_character_codecs() if names is None else tuple(dict.fromkeys(names))
    out: list[Candidate] = []
    seen: set[tuple[str, bytes]] = set()
    for name in selected:
        candidate = decode_python_codec(data, name, min_quality=min_quality)
        if candidate is not None and (candidate.codec, candidate.payload) not in seen:
            seen.add((candidate.codec, candidate.payload))
            out.append(candidate)
    return sorted(out, key=lambda item: (-item.confidence, item.codec))


# -- ITA2 / Baudot -------------------------------------------------------------

_ITA2_LTRS = {
    1: "E", 2: "\n", 3: "A", 4: " ", 5: "S", 6: "I", 7: "U", 8: "\r",
    9: "D", 10: "R", 11: "J", 12: "N", 13: "F", 14: "C", 15: "K",
    16: "T", 17: "Z", 18: "L", 19: "W", 20: "H", 21: "Y", 22: "P",
    23: "Q", 24: "O", 25: "B", 26: "G", 28: "M", 29: "X", 30: "V",
}
_ITA2_FIGS = {
    1: "3", 2: "\n", 3: "-", 4: " ", 5: "'", 6: "8", 7: "7", 8: "\r",
    9: "$", 10: "4", 11: "\a", 12: ",", 13: "!", 14: ":", 15: "(",
    16: "5", 17: '"', 18: ")", 19: "2", 20: "#", 21: "6", 22: "0",
    23: "1", 24: "9", 25: "?", 26: "&", 28: ".", 29: "/", 30: ";",
}


def _ita2_values(data: bytes, bit_order: str) -> list[int] | None:
    try:
        text = data.decode("ascii").strip()
    except UnicodeDecodeError:
        text = ""
    if text and re.fullmatch(r"[01\s,;:_-]+", text):
        bits = "".join(c for c in text if c in "01")
    elif text and re.fullmatch(r"(?:\d{1,2}[\s,;:_-]*)+", text):
        vals = [int(x) for x in re.findall(r"\d+", text)]
        return vals if vals and all(0 <= x < 32 for x in vals) else None
    else:
        bits = "".join(f"{byte:08b}" for byte in data)
    if len(bits) < 20 or len(bits) % 5:
        return None
    groups = [bits[i:i + 5] for i in range(0, len(bits), 5)]
    return [int(group if bit_order == "msb" else group[::-1], 2) for group in groups]


def decode_ita2(data: object) -> list[Candidate]:
    """Decode ITA2 bit groups, decimal code groups, or packed bytes in both bit orders."""

    raw = _as_bytes(data)
    if raw is None:
        return []
    out: list[Candidate] = []
    for order in ("msb", "lsb"):
        values = _ita2_values(raw, order)
        if not values:
            continue
        table, chars, printable = _ITA2_LTRS, [], 0
        valid = True
        for value in values:
            if value == 0:
                continue
            if value == 31:
                table = _ITA2_LTRS
                continue
            if value == 27:
                table = _ITA2_FIGS
                continue
            char = table.get(value)
            if char is None:
                valid = False
                break
            chars.append(char)
            printable += char.isprintable() or char in "\r\n"
        text = "".join(chars)
        if valid and len(text.strip()) >= 3 and printable / max(1, len(chars)) >= 0.9:
            out.append(Candidate(f"ita2:{order}", text.encode(), 0.88, "all 5-bit symbols valid"))
    return _unique(out)


# -- Morse and manual substitution codes --------------------------------------

_MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
    "--..": "Z", "-----": "0", ".----": "1", "..---": "2", "...--": "3",
    "....-": "4", ".....": "5", "-....": "6", "--...": "7", "---..": "8",
    "----.": "9", ".-.-.-": ".", "--..--": ",", "..--..": "?",
    ".----.": "'", "-.-.--": "!", "-..-.": "/", "-.--.": "(",
    "-.--.-": ")", ".-...": "&", "---...": ":", "-.-.-.": ";",
    "-...-": "=", ".-.-.": "+", "-....-": "-", "..--.-": "_",
    ".-..-.": '"', "...-..-": "$", ".--.-.": "@",
}


def _morse_tokens(text: str) -> list[str] | None:
    normalized = text.lower().replace("dah", "-").replace("dash", "-")
    normalized = normalized.replace("dit", ".").replace("dot", ".")
    normalized = normalized.replace("_", "-").replace("•", ".").strip()
    if not normalized or re.search(r"[^.\-01/|\s]", normalized):
        return None
    # Preserve word boundaries as a sentinel while accepting 2+ spaces as a word gap.
    normalized = re.sub(r"\s*(?:/|\|)\s*|\s{2,}", " / ", normalized)
    return normalized.split()


def decode_morse(data: object) -> list[Candidate]:
    """International Morse, swapped Morse, and binary-symbol Morse candidates."""

    raw = _as_bytes(data)
    if raw is None:
        return []
    try:
        original = raw.decode("utf-8")
    except UnicodeDecodeError:
        return []
    tokens = _morse_tokens(original)
    if not tokens or len([x for x in tokens if x != "/"]) < 2:
        return []
    variants: list[tuple[str, Callable[[str], str]]] = [
        ("morse", lambda token: token),
        ("morse:swapped", lambda token: token.translate(str.maketrans(".-", "-."))),
    ]
    if all(set(token) <= set("01") for token in tokens if token != "/"):
        variants.extend([
            ("morse:01", lambda token: token.translate(str.maketrans("01", ".-"))),
            ("morse:10", lambda token: token.translate(str.maketrans("10", ".-"))),
        ])
    out: list[Candidate] = []
    for name, transform in variants:
        chars, valid = [], True
        for token in tokens:
            if token == "/":
                chars.append(" ")
                continue
            char = _MORSE.get(transform(token))
            if char is None:
                valid = False
                break
            chars.append(char)
        if valid and chars:
            out.append(Candidate(name, "".join(chars).encode(), 0.9, "every Morse token is defined"))
    return _unique(out)


_POLYBIUS = "ABCDEFGHIKLMNOPQRSTUVWXYZ"


def decode_polybius(data: object) -> list[Candidate]:
    raw = _as_bytes(data)
    text = _ascii(raw) if raw is not None else None
    if text is None or not re.fullmatch(r"[1-5\s,;:./|-]+", text):
        return []
    digits = "".join(re.findall(r"[1-5]", text))
    if len(digits) < 4 or len(digits) % 2:
        return []
    out = bytearray()
    for i in range(0, len(digits), 2):
        row, col = int(digits[i]) - 1, int(digits[i + 1]) - 1
        out.append(ord(_POLYBIUS[row * 5 + col]))
    return [Candidate("polybius:5x5", bytes(out), 0.84, "all coordinates are in a 5x5 square")]


def decode_tap_code(data: object) -> list[Candidate]:
    readings = decode_polybius(data)
    return [Candidate("tap:5x5", item.payload, item.confidence, item.note) for item in readings]


def decode_bacon(data: object) -> list[Candidate]:
    raw = _as_bytes(data)
    text = _ascii(raw) if raw is not None else None
    if text is None:
        return []
    compact = "".join(c for c in text.upper() if c in "AB01")
    if len(compact) < 10 or len(compact) % 5 or re.sub(r"[AB01\s,;:_|/-]", "", text.upper()):
        return []
    bits = compact.translate(str.maketrans("AB", "01"))
    values = [int(bits[i:i + 5], 2) for i in range(0, len(bits), 5)]
    out = []
    if all(value < 26 for value in values):
        out.append(Candidate("bacon:26", bytes(65 + value for value in values), 0.84,
                             "complete five-symbol groups in the 26-letter range"))
    alpha24 = "ABCDEFGHIKLMNOPQRSTUWXYZ"
    if all(value < len(alpha24) for value in values):
        out.append(Candidate("bacon:24", "".join(alpha24[value] for value in values).encode(), 0.8,
                             "complete five-symbol groups in Bacon's 24-letter alphabet"))
    return _unique(out)


_MULTITAP = {"2": "ABC", "3": "DEF", "4": "GHI", "5": "JKL", "6": "MNO",
             "7": "PQRS", "8": "TUV", "9": "WXYZ", "0": " ", "1": ".,?!"}


def decode_dtmf_text(data: object) -> list[Candidate]:
    """Decode separated multi-tap keypad/DTMF key runs.

    A separator between runs is mandatory; without timing or separators a repeated digit is
    inherently ambiguous and is therefore declined.
    """

    raw = _as_bytes(data)
    text = _ascii(raw) if raw is not None else None
    if text is None or not re.fullmatch(r"[0-9*#A-Da-d\s,;:/|.-]+", text):
        return []
    pieces = [piece for piece in re.split(r"[\s,;:|./-]+", text) if piece]
    if len(pieces) < 2:
        return []
    chars = []
    for piece in pieces:
        if len(set(piece)) != 1 or piece[0] not in _MULTITAP:
            return []
        letters = _MULTITAP[piece[0]]
        if not 1 <= len(piece) <= len(letters):
            return []
        chars.append(letters[len(piece) - 1])
    return [Candidate("dtmf:multitap", "".join(chars).encode(), 0.86,
                      "each separated run selects one key symbol")]


# -- Base-N families -----------------------------------------------------------

BASE58_ALPHABETS = {
    "base58": "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
    "base58:flickr": "123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ",
    "base58:ripple": "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz",
}
BASE62_ALPHABETS = {
    "base62": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "base62:lower": "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "base62:letters": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
}
Z85_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"
BASE91_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\""
BASE92_ALPHABET = "!" + "".join(chr(i) for i in range(35, 96)) + "".join(chr(i) for i in range(97, 126))
ZBASE32_ALPHABET = "ybndrfg8ejkmcpqxot1uwisza345h769"
CROCKFORD32_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _numeric_decode(text: str, alphabet: str, *, preserve_zeroes: bool = True) -> bytes | None:
    if not text or len(set(alphabet)) != len(alphabet):
        return None
    lookup = {char: i for i, char in enumerate(alphabet)}
    number = 0
    for char in text:
        value = lookup.get(char)
        if value is None:
            return None
        number = number * len(alphabet) + value
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    zeroes = len(text) - len(text.lstrip(alphabet[0])) if preserve_zeroes else 0
    return b"\x00" * zeroes + body


def _numeric_encode(data: bytes, alphabet: str, *, preserve_zeroes: bool = True) -> str:
    zeroes = len(data) - len(data.lstrip(b"\x00")) if preserve_zeroes else 0
    number = int.from_bytes(data, "big")
    chars = []
    while number:
        number, rem = divmod(number, len(alphabet))
        chars.append(alphabet[rem])
    return alphabet[0] * zeroes + "".join(reversed(chars))


def _decode_base45(text: str) -> bytes | None:
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
    lookup = {char: i for i, char in enumerate(alphabet)}
    if len(text) % 3 == 1 or any(char not in lookup for char in text):
        return None
    out = bytearray()
    for i in range(0, len(text), 3):
        chunk = text[i:i + 3]
        value = lookup[chunk[0]] + 45 * lookup[chunk[1]]
        if len(chunk) == 3:
            value += 45 * 45 * lookup[chunk[2]]
            if value > 0xFFFF:
                return None
            out.extend(value.to_bytes(2, "big"))
        else:
            if value > 0xFF:
                return None
            out.append(value)
    return bytes(out)


def _encode_base45(data: bytes) -> str:
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
    out = []
    for i in range(0, len(data), 2):
        chunk = data[i:i + 2]
        value = int.from_bytes(chunk, "big")
        out.append(alphabet[value % 45])
        out.append(alphabet[(value // 45) % 45])
        if len(chunk) == 2:
            out.append(alphabet[value // (45 * 45)])
    return "".join(out)


def _decode_base91(text: str) -> bytes | None:
    lookup = {char: i for i, char in enumerate(BASE91_ALPHABET)}
    value = -1
    queue = bits = 0
    out = bytearray()
    for char in text:
        digit = lookup.get(char)
        if digit is None:
            return None
        if value < 0:
            value = digit
        else:
            value += digit * 91
            queue |= value << bits
            bits += 13 if (value & 8191) > 88 else 14
            while bits >= 8:
                out.append(queue & 255)
                queue >>= 8
                bits -= 8
            value = -1
    if value >= 0:
        queue |= value << bits
        bits += 7
        while bits >= 8:
            out.append(queue & 255)
            queue >>= 8
            bits -= 8
    return bytes(out)


def _encode_base91(data: bytes) -> str:
    queue = bits = 0
    out = []
    for byte in data:
        queue |= byte << bits
        bits += 8
        if bits > 13:
            value = queue & 8191
            if value > 88:
                queue >>= 13
                bits -= 13
            else:
                value = queue & 16383
                queue >>= 14
                bits -= 14
            out.extend((BASE91_ALPHABET[value % 91], BASE91_ALPHABET[value // 91]))
    if bits:
        out.append(BASE91_ALPHABET[queue % 91])
        if bits > 7 or queue > 90:
            out.append(BASE91_ALPHABET[queue // 91])
    return "".join(out)


def _decode_base92(text: str) -> bytes | None:
    lookup = {char: i for i, char in enumerate(BASE92_ALPHABET)}
    values = [lookup.get(char, -1) for char in text]
    if not values or min(values) < 0:
        return None
    bits = []
    for i in range(0, len(values) - 1, 2):
        value = values[i] * 91 + values[i + 1]
        if value > 8191:
            return None
        bits.append(f"{value:013b}")
    if len(values) % 2:
        if values[-1] > 63:
            return None
        bits.append(f"{values[-1]:06b}")
    stream = "".join(bits)
    return bytes(int(stream[i:i + 8], 2) for i in range(0, len(stream) - 7, 8))


def _encode_base92(data: bytes) -> str:
    bits = "".join(f"{byte:08b}" for byte in data)
    out = []
    while len(bits) >= 13:
        value, bits = int(bits[:13], 2), bits[13:]
        out.extend((BASE92_ALPHABET[value // 91], BASE92_ALPHABET[value % 91]))
    if len(bits) >= 7:
        value = int(bits.ljust(13, "0"), 2)
        out.extend((BASE92_ALPHABET[value // 91], BASE92_ALPHABET[value % 91]))
    elif bits:
        value = int(bits.ljust(6, "0")[:6], 2)
        out.append(BASE92_ALPHABET[value])
    return "".join(out)


_B122_ILLEGAL = (0, 10, 13, 34, 38, 92)


def _seven_bit_groups(data: bytes) -> list[int]:
    value = int.from_bytes(data, "big")
    count = (len(data) * 8 + 6) // 7
    padding = count * 7 - len(data) * 8
    value <<= padding
    return [(value >> (7 * (count - i - 1))) & 0x7F for i in range(count)]


def _encode_base122(data: bytes) -> bytes:
    groups = _seven_bit_groups(data)
    out = bytearray()
    i = 0
    while i < len(groups):
        value = groups[i]
        if value not in _B122_ILLEGAL:
            out.append(value)
            i += 1
            continue
        index = _B122_ILLEGAL.index(value)
        if i + 1 < len(groups):
            following = groups[i + 1]
            out.extend((0xC2 | (index << 2) | (following >> 6), 0x80 | (following & 0x3F)))
            i += 2
        else:
            out.extend((0xC2 | (7 << 2) | (value >> 6), 0x80 | (value & 0x3F)))
            i += 1
    return bytes(out)


def _decode_base122(data: bytes) -> bytes | None:
    groups, i = [], 0
    while i < len(data):
        first = data[i]
        if first < 0x80:
            if first in _B122_ILLEGAL:
                return None  # non-canonical: these bytes must use the escape form
            groups.append(first)
            i += 1
            continue
        if i + 1 >= len(data) or first & 0xE2 != 0xC2 or data[i + 1] & 0xC0 != 0x80:
            return None
        index = (first >> 2) & 7
        following = ((first & 1) << 6) | (data[i + 1] & 0x3F)
        if index < len(_B122_ILLEGAL):
            groups.extend((_B122_ILLEGAL[index], following))
        elif index == 7:
            groups.append(following)
        else:
            return None
        i += 2
    bitstream = "".join(f"{value:07b}" for value in groups)
    decoded = bytes(int(bitstream[j:j + 8], 2) for j in range(0, len(bitstream) - 7, 8))
    return decoded if decoded and _encode_base122(decoded) == data else None


def _decode_z85(text: str) -> bytes | None:
    if not text or len(text) % 5:
        return None
    lookup = {char: i for i, char in enumerate(Z85_ALPHABET)}
    out = bytearray()
    for i in range(0, len(text), 5):
        value = 0
        for char in text[i:i + 5]:
            digit = lookup.get(char)
            if digit is None:
                return None
            value = value * 85 + digit
        if value > 0xFFFFFFFF:
            return None
        out.extend(value.to_bytes(4, "big"))
    return bytes(out)


def _encode_z85(data: bytes) -> str:
    if len(data) % 4:
        raise ValueError("Z85 input length must be divisible by four")
    out = []
    for i in range(0, len(data), 4):
        value = int.from_bytes(data[i:i + 4], "big")
        chars = [""] * 5
        for j in range(4, -1, -1):
            value, rem = divmod(value, 85)
            chars[j] = Z85_ALPHABET[rem]
        out.extend(chars)
    return "".join(out)


def _decode_custom_base32(text: str, alphabet: str) -> bytes | None:
    lookup = {char: i for i, char in enumerate(alphabet)}
    values = []
    for char in text:
        value = lookup.get(char)
        if value is None:
            return None
        values.append(value)
    bits = "".join(f"{value:05b}" for value in values)
    if any(bit == "1" for bit in bits[(len(bits) // 8) * 8:]):
        return None
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - 7, 8))


def _encode_custom_base32(data: bytes, alphabet: str) -> str:
    bits = "".join(f"{byte:08b}" for byte in data)
    return "".join(alphabet[int(bits[i:i + 5].ljust(5, "0"), 2)] for i in range(0, len(bits), 5))


def decode_base(data: object, name: str) -> Candidate | None:
    """Decode one named base alphabet and require its canonical representation."""

    raw = _as_bytes(data)
    if raw is None:
        return None
    normalized = name.lower().replace("_", "-")
    text = _ascii(raw, compact=True)
    decoded: bytes | None = None
    rebuilt: str | bytes | None = None
    try:
        if normalized in {"base16", "hex"} and text is not None and len(text) % 2 == 0:
            decoded = base64.b16decode(text.upper(), casefold=True)
            rebuilt = base64.b16encode(decoded).decode()
            text = text.upper()
        elif normalized in {"base32", "base32hex"} and text is not None:
            padded = text.upper() + "=" * ((-len(text)) % 8)
            fn = base64.b32hexdecode if normalized == "base32hex" else base64.b32decode
            enc = base64.b32hexencode if normalized == "base32hex" else base64.b32encode
            decoded = fn(padded, casefold=True)
            rebuilt = enc(decoded).decode().rstrip("=")
            text = text.upper().rstrip("=")
        elif normalized in {"crockford32", "base32-crockford"} and text is not None:
            canonical = text.upper().replace("O", "0").replace("I", "1").replace("L", "1").replace("-", "")
            decoded = _decode_custom_base32(canonical, CROCKFORD32_ALPHABET)
            rebuilt = _encode_custom_base32(decoded, CROCKFORD32_ALPHABET) if decoded is not None else None
            text = canonical
        elif normalized in {"zbase32", "z-base-32"} and text is not None:
            text = text.lower()
            decoded = _decode_custom_base32(text, ZBASE32_ALPHABET)
            rebuilt = _encode_custom_base32(decoded, ZBASE32_ALPHABET) if decoded is not None else None
        elif normalized == "base45":
            # base45's alphabet (RFC 9285) includes the SPACE character as a data symbol, so ANY
            # whitespace stripping (compact OR .strip()) would silently drop real bytes. Decode from
            # the raw ascii with no whitespace removal and verify the canonical round-trip against
            # THAT (a stray non-alphabet whitespace char just makes _decode_base45 decline — safe).
            try:
                b45 = raw.decode("ascii")
            except UnicodeDecodeError:
                b45 = None
            if b45 is not None:
                decoded = _decode_base45(b45)
                rebuilt = _encode_base45(decoded) if decoded is not None else None
                text = b45
        elif normalized in BASE58_ALPHABETS and text is not None:
            alphabet = BASE58_ALPHABETS[normalized]
            decoded = _numeric_decode(text, alphabet)
            rebuilt = _numeric_encode(decoded, alphabet) if decoded is not None else None
        elif normalized == "base58check" and text is not None:
            alphabet = BASE58_ALPHABETS["base58"]
            raw_check = _numeric_decode(text, alphabet)
            if raw_check is not None and len(raw_check) >= 5:
                import hashlib
                payload, checksum = raw_check[:-4], raw_check[-4:]
                if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == checksum:
                    decoded = payload
                    rebuilt = text
        elif normalized in BASE62_ALPHABETS and text is not None:
            alphabet = BASE62_ALPHABETS[normalized]
            decoded = _numeric_decode(text, alphabet)
            rebuilt = _numeric_encode(decoded, alphabet) if decoded is not None else None
        elif normalized in {"base64", "base64url"} and text is not None:
            padded = text + "=" * ((-len(text)) % 4)
            if normalized == "base64url":
                decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
                rebuilt = base64.urlsafe_b64encode(decoded).decode().rstrip("=")
            else:
                decoded = base64.b64decode(padded, validate=True)
                rebuilt = base64.b64encode(decoded).decode().rstrip("=")
            text = text.rstrip("=")
        elif normalized in {"ascii85", "a85"} and text is not None:
            adobe = text.startswith("<~") and text.endswith("~>")
            decoded = base64.a85decode(text, adobe=adobe)
            rebuilt = base64.a85encode(decoded, adobe=adobe).decode()
        elif normalized in {"base85", "b85", "rfc1924"} and text is not None:
            decoded = base64.b85decode(text)
            rebuilt = base64.b85encode(decoded).decode()
        elif normalized == "z85" and text is not None:
            decoded = _decode_z85(text)
            rebuilt = _encode_z85(decoded) if decoded is not None else None
        elif normalized == "base91" and text is not None:
            decoded = _decode_base91(text)
            rebuilt = _encode_base91(decoded) if decoded is not None else None
        elif normalized == "base92" and text is not None:
            decoded = _decode_base92(text)
            rebuilt = _encode_base92(decoded) if decoded is not None else None
        elif normalized == "base122":
            decoded = _decode_base122(raw)
            rebuilt = _encode_base122(decoded) if decoded is not None else None
    except (ValueError, UnicodeError, binascii.Error, OverflowError):
        return None
    if not decoded or rebuilt is None:
        return None
    if isinstance(rebuilt, str):
        if text is None or rebuilt != text:
            return None
    elif rebuilt != raw:
        return None
    return Candidate(normalized, decoded, 0.96, "alphabet, length, padding and canonical round-trip valid")


BASE_NAMES = (
    "base16", "base32", "base32hex", "crockford32", "zbase32", "base45",
    "base58", "base58:flickr", "base58:ripple", "base58check", "base62",
    "base62:lower", "base62:letters", "base64", "base64url", "ascii85",
    "base85", "z85", "base91", "base92", "base122",
)


def decode_bases(data: object, names: Iterable[str] = BASE_NAMES) -> list[Candidate]:
    return _unique(candidate for name in names if (candidate := decode_base(data, name)) is not None)


def _unique(candidates: Iterable[Candidate]) -> list[Candidate]:
    out, seen = [], set()
    for candidate in candidates:
        key = (candidate.codec, candidate.payload)
        if candidate.payload and key not in seen:
            seen.add(key)
            out.append(candidate)
    return out


# Registry intentionally contains only explicit, bounded readers.  The all-Python-codecs walk is
# available as ``decode_character_encodings`` but should be a late candidate generator, not a
# branching strict step in a recursive auto-decoder.
BY_NAME: dict[str, Callable[[object], list[Candidate]]] = {
    "ita2": decode_ita2,
    "morse": decode_morse,
    "polybius": decode_polybius,
    "tap": decode_tap_code,
    "bacon": decode_bacon,
    "dtmf-text": decode_dtmf_text,
    **{name: (lambda value, selected=name: [candidate] if (candidate := decode_base(value, selected)) else [])
       for name in BASE_NAMES},
}
NAMES = frozenset(BY_NAME)


def steps(data: object) -> list[tuple[str, bytes]]:
    """All checked explicit readings as ``(decoder name, payload)`` pairs."""

    out: list[tuple[str, bytes]] = []
    seen: set[tuple[str, bytes]] = set()
    for name, decoder in BY_NAME.items():
        try:
            candidates = decoder(data)
        except Exception:
            candidates = []
        for candidate in candidates:
            key = (name, candidate.payload)
            if candidate.payload and key not in seen:
                seen.add(key)
                out.append(key)
    return out


def step_fn(name: str) -> Callable[[object], bytes | None] | None:
    """A single-output adapter; ambiguous readers decline rather than choosing."""

    decoder = BY_NAME.get(name)
    if decoder is None:
        return None

    def read(value: object) -> bytes | None:
        candidates = _unique(decoder(value))
        payloads = {item.payload for item in candidates}
        return next(iter(payloads)) if len(payloads) == 1 else None

    read.__name__ = "decode_" + re.sub(r"\W+", "_", name)
    return read


__all__ = [
    "BASE_NAMES", "BY_NAME", "Candidate", "NAMES", "decode_bases", "decode_base",
    "decode_bacon", "decode_character_encodings", "decode_dtmf_text", "decode_ita2",
    "decode_morse", "decode_polybius", "decode_python_codec", "decode_tap_code",
    "python_character_codecs", "step_fn", "steps",
]
