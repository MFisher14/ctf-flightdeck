"""Strict offline readers for uncommon visual, biological, and manual codes.

The broad warmup search already contains deliberately lossy readers for several of these
families.  This module is the conservative counterpart used when challenge evidence names a
family: every public reader consumes caller-supplied data, validates the complete notation, and
returns a :class:`ExoticCandidate` only after a structural inverse or an explicit crib/source
check succeeds.  It never searches the network, opens a file, or guesses a key corpus.
"""

from __future__ import annotations

import re
import unicodedata
import zlib
from dataclasses import dataclass
from typing import Mapping, Sequence

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt


MAX_INPUT = 8 * 1024 * 1024
MAX_BOOK = 32 * 1024 * 1024
MAX_TOKENS = 1_000_000
MAX_SOURCES = 64


@dataclass(frozen=True, slots=True)
class ExoticCandidate:
    codec: str
    payload: bytes
    confidence: float
    evidence: tuple[str, ...]


def _text(value: object, *, limit: int = MAX_INPUT) -> str | None:
    if isinstance(value, str):
        text = value
    elif isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        if not raw or len(raw) > limit:
            return None
        try:
            text = raw.decode("utf-8", "strict")
        except UnicodeDecodeError:
            return None
    else:
        return None
    try:
        encoded_length = len(text.encode("utf-8", "strict"))
    except UnicodeEncodeError:
        return None
    if not text or encoded_length > limit:
        return None
    return text


def _payload_shape(payload: bytes, expected_crc32: object = None) -> bool:
    if not payload or len(payload) > MAX_INPUT:
        return False
    if expected_crc32 is not None:
        if not isinstance(expected_crc32, int) or isinstance(expected_crc32, bool):
            return False
        if not 0 <= expected_crc32 <= 0xFFFFFFFF:
            return False
        return zlib.crc32(payload) & 0xFFFFFFFF == expected_crc32
    signatures = (
        b"\x89PNG\r\n\x1a\n", b"PK\x03\x04", b"%PDF-",
        b"GIF87a", b"GIF89a", b"\x7fELF", b"MZ",
    )
    if payload.startswith(signatures):
        return True
    # The active event's flag lead (`PREFIX{`, under its case rule) is a signature too (R-16).
    if flagfmt.LEAD_BYTES.match(payload):
        return True
    try:
        decoded = payload.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return False
    if len(decoded) < 3:
        return False
    visible = sum(
        char in "\t\r\n" or (
            char.isprintable() and unicodedata.category(char) not in {"Cc", "Cs", "Co", "Cn"}
        )
        for char in decoded
    )
    return visible == len(decoded) and any(not char.isspace() for char in decoded)


def decode_dna_2bit(
    data: object,
    *,
    alphabet: str = "ACGT",
    expected_crc32: int | None = None,
) -> ExoticCandidate | None:
    """Decode four explicitly ordered bases as 00, 01, 10, and 11.

    Whitespace is permitted between bases.  The mapping is never permuted implicitly; callers
    must supply a different four-character ``alphabet`` when challenge evidence defines one.
    The decoded bytes must be printable/recognizable or match the supplied CRC.
    """

    text = _text(data)
    if text is None or not isinstance(alphabet, str):
        return None
    symbols = alphabet.upper()
    if len(symbols) != 4 or set(symbols) != set("ACGT"):
        return None
    if not re.fullmatch(r"[ACGTacgt\s]+", text):
        return None
    compact = "".join(text.split()).upper()
    if len(compact) < 12 or len(compact) % 4 or len(compact) > MAX_TOKENS:
        return None
    values = {base: index for index, base in enumerate(symbols)}
    out = bytearray()
    for offset in range(0, len(compact), 4):
        byte = 0
        for base in compact[offset:offset + 4]:
            byte = (byte << 2) | values[base]
        out.append(byte)
    payload = bytes(out)
    rebuilt = "".join(symbols[(byte >> shift) & 3] for byte in payload for shift in (6, 4, 2, 0))
    if rebuilt != compact or not _payload_shape(payload, expected_crc32):
        return None
    check = "CRC-32 matches supplied value" if expected_crc32 is not None else "complete 2-bit inverse and payload shape"
    return ExoticCandidate("dna:2bit:" + symbols, payload, 1.0 if expected_crc32 is not None else 0.86,
                            (check, f"{len(compact)} canonical bases"))


_CODON_TABLE = {
    # Standard genetic code, DNA spelling.
    "TTT": "F", "TTC": "F", "TTA": "L", "TTG": "L",
    "TCT": "S", "TCC": "S", "TCA": "S", "TCG": "S",
    "TAT": "Y", "TAC": "Y", "TAA": "*", "TAG": "*",
    "TGT": "C", "TGC": "C", "TGA": "*", "TGG": "W",
    "CTT": "L", "CTC": "L", "CTA": "L", "CTG": "L",
    "CCT": "P", "CCC": "P", "CCA": "P", "CCG": "P",
    "CAT": "H", "CAC": "H", "CAA": "Q", "CAG": "Q",
    "CGT": "R", "CGC": "R", "CGA": "R", "CGG": "R",
    "ATT": "I", "ATC": "I", "ATA": "I", "ATG": "M",
    "ACT": "T", "ACC": "T", "ACA": "T", "ACG": "T",
    "AAT": "N", "AAC": "N", "AAA": "K", "AAG": "K",
    "AGT": "S", "AGC": "S", "AGA": "R", "AGG": "R",
    "GTT": "V", "GTC": "V", "GTA": "V", "GTG": "V",
    "GCT": "A", "GCC": "A", "GCA": "A", "GCG": "A",
    "GAT": "D", "GAC": "D", "GAA": "E", "GAG": "E",
    "GGT": "G", "GGC": "G", "GGA": "G", "GGG": "G",
}


def translate_codons(
    data: object,
    *,
    require_start: bool = True,
    require_stop: bool = True,
) -> ExoticCandidate | None:
    """Translate a complete standard-code DNA open reading frame.

    Ambiguous bases and internal stops decline.  By default the exact sequence must start with
    ATG and end with one stop codon; these checks prevent arbitrary DNA strings from being
    presented as hidden text.
    """

    text = _text(data)
    if text is None or not isinstance(require_start, bool) or not isinstance(require_stop, bool):
        return None
    if not re.fullmatch(r"[ACGTacgt\s]+", text):
        return None
    compact = "".join(text.split()).upper()
    if len(compact) < 9 or len(compact) % 3 or len(compact) > MAX_TOKENS:
        return None
    codons = [compact[index:index + 3] for index in range(0, len(compact), 3)]
    if require_start and codons[0] != "ATG":
        return None
    translated = [_CODON_TABLE[codon] for codon in codons]
    terminal_stop = translated[-1] == "*"
    if (require_stop and not terminal_stop) or "*" in translated[:-1]:
        return None
    if terminal_stop:
        translated.pop()
    if len(translated) < 2:
        return None
    payload = "".join(translated).encode("ascii")
    return ExoticCandidate("dna:standard-codon", payload, 0.98,
                            ("complete open reading frame", "standard genetic code", "no internal stop"))


_BRAILLE_ASCII = " A1B'K2L@CIF/MSP\"E3H9O6R^DJG>NTQ,*5<-U8V.%[$+X!&;:4\\0Z7(_?W]#Y)="
_BRAILLE_G1 = {index: char.lower() for index, char in enumerate(_BRAILLE_ASCII) if char.isalpha()}
_BRAILLE_G1.update({0x00: " ", 0x02: ",", 0x06: ";", 0x12: ":", 0x32: ".",
                    0x16: "!", 0x26: "?", 0x24: "-", 0x04: "'"})
_BRAILLE_DIGITS = {index: str("abcdefghij".index(char) + 1)[-1]
                   for index, char in _BRAILLE_G1.items() if char in "abcdefghij"}
_BRAILLE_NUMBER, _BRAILLE_CAPITAL, _BRAILLE_LETTER = 0x3C, 0x20, 0x30


def decode_braille_grade1(data: object) -> ExoticCandidate | None:
    """Read complete Unicode six-dot English Grade-1 Braille."""

    text = _text(data)
    if text is None:
        return None
    cells: list[int | str] = []
    count = 0
    for char in text.strip():
        value = ord(char) - 0x2800
        if 0 <= value <= 0x3F:
            cells.append(value)
            count += 1
        elif char.isspace():
            cells.append(" ")
        else:
            return None
    if count < 4 or count > MAX_TOKENS:
        return None
    out: list[str] = []
    number = capital = word_capital = number_pending = False
    for cell in cells:
        if not isinstance(cell, int) or cell == 0:
            if number_pending or capital:
                return None
            out.append(" ")
            number = capital = word_capital = number_pending = False
            continue
        if cell == _BRAILLE_NUMBER:
            if number or capital:
                return None
            number = True
            number_pending = True
            continue
        if cell == _BRAILLE_LETTER:
            if not number or number_pending:
                return None
            number = False
            continue
        if cell == _BRAILLE_CAPITAL:
            if number or word_capital:
                return None
            if capital:
                word_capital = True
                capital = False
            else:
                capital = True
            continue
        if number:
            digit = _BRAILLE_DIGITS.get(cell)
            if digit is None:
                return None
            out.append(digit)
            number_pending = False
            continue
        char = _BRAILLE_G1.get(cell)
        if char is None:
            return None
        if (capital or word_capital) and not char.isalpha():
            return None
        out.append(char.upper() if capital or word_capital else char)
        capital = False
    # Numeric mode naturally remains active through the end of a word; only a prefix sign with
    # no following cell is incomplete.  A capital sign, in contrast, must consume a letter.
    if capital or number_pending:
        return None
    payload = "".join(out).encode("utf-8")
    if not _payload_shape(payload):
        return None
    return ExoticCandidate("braille:grade1", payload, 0.96,
                            ("all cells are six-dot Grade-1 symbols", "numeric/capital state complete"))


def decode_braille8(
    data: object,
    *,
    expected_crc32: int | None = None,
) -> ExoticCandidate | None:
    """Read eight-dot Unicode Braille cells as byte values.

    ASCII whitespace may separate cells but is not data.  Because arbitrary eight-dot cells can
    encode arbitrary bytes, the result must either have a recognizable/printable payload shape or
    match an explicitly supplied CRC-32.
    """

    text = _text(data)
    if text is None:
        return None
    values: list[int] = []
    for char in text:
        value = ord(char) - 0x2800
        if 0 <= value <= 0xFF:
            values.append(value)
        elif char in " \t\r\n":
            continue
        else:
            return None
    if not 3 <= len(values) <= MAX_TOKENS:
        return None
    payload = bytes(values)
    if not _payload_shape(payload, expected_crc32):
        return None
    check = "CRC-32 matches supplied value" if expected_crc32 is not None else "complete eight-dot byte cells"
    return ExoticCandidate("braille:8dot", payload, 1.0 if expected_crc32 is not None else 0.88,
                            (check, f"{len(values)} cells"))


_DIRECTIONS = {
    "n": 0, "ne": 1, "e": 2, "se": 3, "s": 4, "sw": 5, "w": 6, "nw": 7,
    "up": 0, "upright": 1, "right": 2, "downright": 3,
    "down": 4, "downleft": 5, "left": 6, "upleft": 7,
    "↑": 0, "↗": 1, "→": 2, "↘": 3, "↓": 4, "↙": 5, "←": 6, "↖": 7,
}
_ARROW_DIRECTIONS = {char: _DIRECTIONS[char] for char in "↑↗→↘↓↙←↖"}
_SEMAPHORE_VIEW = {
    "a": (4, 5), "b": (4, 6), "c": (4, 7), "d": (4, 0), "e": (4, 1),
    "f": (4, 2), "g": (4, 3), "h": (5, 6), "i": (5, 7), "j": (0, 2),
    "k": (5, 0), "l": (5, 1), "m": (5, 2), "n": (5, 3), "o": (6, 7),
    "p": (6, 0), "q": (6, 1), "r": (6, 2), "s": (6, 3), "t": (7, 0),
    "u": (7, 1), "v": (0, 3), "w": (1, 2), "x": (1, 3), "y": (7, 2),
    "z": (3, 2), "#": (0, 1),
}
_SEMAPHORE_DIGITS = dict(zip("abcdefghik", "1234567890"))


def _semaphore_pair(token: str) -> tuple[int, int] | None:
    if len(token) == 2 and all(char in _ARROW_DIRECTIONS for char in token):
        return _ARROW_DIRECTIONS[token[0]], _ARROW_DIRECTIONS[token[1]]
    parts = [part for part in re.split(r"[-+,&:]", token.lower()) if part]
    if len(parts) != 2 or any(part not in _DIRECTIONS for part in parts):
        return None
    return _DIRECTIONS[parts[0]], _DIRECTIONS[parts[1]]


def decode_semaphore(data: object, *, mirror: bool = False) -> ExoticCandidate | None:
    """Decode flag-semaphore direction pairs; ``|`` or ``/`` separates words."""

    text = _text(data)
    if text is None or not isinstance(mirror, bool):
        return None
    table_source = {
        frozenset(((-left) % 8, (-right) % 8) if mirror else (left, right)): char
        for char, (left, right) in _SEMAPHORE_VIEW.items()
    }
    raw_tokens = re.split(r"(\||/)|\s+", text.strip())
    tokens = [token for token in raw_tokens if token]
    if not 4 <= sum(token not in {"|", "/"} for token in tokens) <= MAX_TOKENS:
        return None
    out: list[str] = []
    number = False
    number_digits = 0
    for token in tokens:
        if token in {"|", "/"}:
            if not out or out[-1] == " ":
                return None
            if number and number_digits == 0:
                return None
            out.append(" ")
            number = False
            number_digits = 0
            continue
        pair = _semaphore_pair(token)
        if pair is None or pair[0] == pair[1]:
            return None
        char = table_source.get(frozenset(pair))
        if char is None:
            return None
        if char == "#":
            if number:
                return None
            number = True
            number_digits = 0
        elif number and char == "j":
            if number_digits == 0:
                return None
            number = False
        elif number:
            digit = _SEMAPHORE_DIGITS.get(char)
            if digit is None:
                return None
            out.append(digit)
            number_digits += 1
        else:
            out.append(char)
    if (number and number_digits == 0) or not out or out[-1] == " ":
        return None
    payload = "".join(out).encode("ascii")
    return ExoticCandidate("semaphore:mirror" if mirror else "semaphore:view", payload, 0.95,
                            ("every arm pair has one semaphore meaning", "mode shifts are complete"))


_ICAO = {
    "alfa": "A", "alpha": "A", "bravo": "B", "charlie": "C", "delta": "D",
    "echo": "E", "foxtrot": "F", "golf": "G", "hotel": "H", "india": "I",
    "juliett": "J", "juliet": "J", "kilo": "K", "lima": "L", "mike": "M",
    "november": "N", "oscar": "O", "papa": "P", "quebec": "Q", "romeo": "R",
    "sierra": "S", "tango": "T", "uniform": "U", "victor": "V", "whiskey": "W",
    "x-ray": "X", "xray": "X", "yankee": "Y", "zulu": "Z",
    "zero": "0", "one": "1", "two": "2", "three": "3", "four": "4",
    "five": "5", "six": "6", "seven": "7", "eight": "8", "nine": "9",
    "niner": "9", "fife": "5", "fower": "4", "tree": "3",
}


def decode_nato_phonetic(data: object) -> ExoticCandidate | None:
    """Decode a complete ICAO/NATO spelling-alphabet stream."""

    text = _text(data)
    if text is None or not text.isascii():
        return None
    normalized = re.sub(r"\s*([/|])\s*", r" \1 ", text.strip().lower())
    tokens = normalized.split()
    if not 3 <= sum(token not in {"/", "|"} for token in tokens) <= MAX_TOKENS:
        return None
    out: list[str] = []
    for token in tokens:
        if token in {"/", "|"}:
            if not out or out[-1] == " ":
                return None
            out.append(" ")
            continue
        char = _ICAO.get(token)
        if char is None:
            return None
        out.append(char)
    if not out or out[-1] == " ":
        return None
    payload = "".join(out).encode("ascii")
    return ExoticCandidate("phonetic:icao", payload, 0.98,
                            ("all tokens are ICAO/NATO code words", f"{len(tokens)} complete tokens"))


_QWERTY_ROWS = (
    "`1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./",
    "~!@#$%^&*()_+", "QWERTYUIOP{}|", 'ASDFGHJKL:"', "ZXCVBNM<>?",
)


def _keyboard_transform(text: str, offset: int) -> str | None:
    out: list[str] = []
    for char in text:
        if char.isspace():
            out.append(char)
            continue
        found = False
        for row in _QWERTY_ROWS:
            index = row.find(char)
            if index < 0:
                continue
            target = index + offset
            if not 0 <= target < len(row):
                return None
            out.append(row[target])
            found = True
            break
        if not found:
            return None
    return "".join(out)


def decode_keyboard_shift(
    data: object,
    *,
    written_offset: int,
    expected_prefix: bytes | str | None = None,
) -> ExoticCandidate | None:
    """Undo an explicitly supplied horizontal QWERTY key offset.

    ``written_offset=1`` means the ciphertext was typed one key to the right.  The inverse must
    re-encode byte-for-byte.  An optional expected prefix supplies a semantic check.
    """

    text = _text(data)
    if text is None or not isinstance(written_offset, int) or isinstance(written_offset, bool):
        return None
    if not text.isascii():
        return None
    if written_offset == 0 or not -4 <= written_offset <= 4:
        return None
    plain = _keyboard_transform(text, -written_offset)
    if plain is None or _keyboard_transform(plain, written_offset) != text:
        return None
    payload = plain.encode("utf-8")
    if expected_prefix is not None:
        if isinstance(expected_prefix, str):
            try:
                prefix = expected_prefix.encode("utf-8", "strict")
            except UnicodeEncodeError:
                return None
        else:
            prefix = expected_prefix
        if not isinstance(prefix, bytes) or not prefix or not payload.startswith(prefix):
            return None
        confidence = 1.0
        evidence = ("exact keyboard inverse", "supplied plaintext prefix matches")
    else:
        if not _payload_shape(payload):
            return None
        confidence = 0.82
        evidence = ("exact keyboard inverse", "complete printable payload")
    return ExoticCandidate(f"keyboard:qwerty:{written_offset:+d}", payload, confidence, evidence)


_COORDINATE = re.compile(r"([1-9][0-9]*)(?:[.:,-])([1-9][0-9]*)(?:[.:,-])([1-9][0-9]*)")


def decode_book_coordinates(data: object, book: object) -> ExoticCandidate | None:
    """Resolve canonical one-based ``line:word:letter`` book-cipher coordinates."""

    encoded = _text(data)
    source = _text(book, limit=MAX_BOOK)
    if encoded is None or source is None:
        return None
    normalized = re.sub(r"\s*([/|])\s*", r" \1 ", encoded.strip())
    tokens = normalized.split()
    coordinate_count = sum(token not in {"/", "|"} for token in tokens)
    if not 3 <= coordinate_count <= MAX_TOKENS:
        return None
    lines = source.splitlines()
    if not lines:
        return None
    out: list[str] = []
    for token in tokens:
        if token in {"/", "|"}:
            if not out or out[-1] == " ":
                return None
            out.append(" ")
            continue
        match = _COORDINATE.fullmatch(token)
        if match is None:
            return None
        if any(len(value) > 10 for value in match.groups()):
            return None
        try:
            line_index, word_index, letter_index = (int(value) - 1 for value in match.groups())
        except (TypeError, ValueError, OverflowError):
            return None
        if line_index >= len(lines):
            return None
        words = re.findall(r"[^\W_]+(?:['’-][^\W_]+)*", lines[line_index], re.UNICODE)
        if word_index >= len(words) or letter_index >= len(words[word_index]):
            return None
        out.append(words[word_index][letter_index])
    if not out or out[-1] == " ":
        return None
    payload = "".join(out).encode("utf-8")
    if not _payload_shape(payload):
        return None
    return ExoticCandidate("book:line-word-letter", payload, 0.96,
                            ("every one-based coordinate resolves", f"{coordinate_count} coordinates"))


def _letters(value: str) -> tuple[int, ...]:
    return tuple(ord(char.lower()) - 97 for char in value if char.isascii() and char.isalpha())


def _runkey_key(cipher: int, plain: int, mode: str) -> int:
    if mode == "vigenere":
        return (cipher - plain) % 26
    if mode == "beaufort":
        return (cipher + plain) % 26
    return (plain - cipher) % 26  # variant Beaufort


def _runkey_plain(cipher: int, key: int, mode: str) -> int:
    if mode == "vigenere":
        return (cipher - key) % 26
    if mode == "beaufort":
        return (key - cipher) % 26
    return (cipher + key) % 26


def _runkey_cipher(plain: int, key: int, mode: str) -> int:
    if mode == "vigenere":
        return (plain + key) % 26
    if mode == "beaufort":
        return (key - plain) % 26
    return (plain - key) % 26


def detect_running_key(
    ciphertext: object,
    crib: object,
    sources: Mapping[str, str],
    *,
    modes: Sequence[str] = ("vigenere", "beaufort", "variant"),
) -> tuple[ExoticCandidate, ...]:
    """Prove a running key by locating crib-derived key letters in supplied source text.

    The crib is aligned to the first ciphertext letters.  A result is returned only when exactly
    one ``(mode, source, offset)`` match exists, the source continues for the complete ciphertext,
    the plaintext begins with the crib letters, and re-encryption reproduces every ciphertext
    letter.  No built-in books or language guessing are used.
    """

    cipher_text = _text(ciphertext)
    crib_text = _text(crib)
    if cipher_text is None or crib_text is None or not isinstance(sources, Mapping):
        return ()
    if not isinstance(modes, Sequence) or isinstance(modes, (str, bytes, bytearray)):
        return ()
    if any(char.isalpha() and not char.isascii() for char in cipher_text + crib_text):
        return ()
    selected = tuple(modes)
    if not selected or len(selected) > 3 or any(mode not in {"vigenere", "beaufort", "variant"} for mode in selected):
        return ()
    cipher_values = _letters(cipher_text)
    crib_values = _letters(crib_text)
    if not 8 <= len(crib_values) <= len(cipher_values) <= MAX_TOKENS:
        return ()
    if len(sources) == 0 or len(sources) > MAX_SOURCES:
        return ()
    cleaned: list[tuple[str, tuple[int, ...]]] = []
    total = 0
    for name, source in sources.items():
        if not isinstance(name, str) or not name or len(name) > 256 or not isinstance(source, str):
            return ()
        try:
            if len(source.encode("utf-8", "strict")) > MAX_BOOK:
                return ()
        except UnicodeEncodeError:
            return ()
        if any(char.isalpha() and not char.isascii() for char in source):
            return ()
        values = _letters(source)
        total += len(values)
        if not values or total > MAX_BOOK:
            return ()
        cleaned.append((name, values))
    matches: list[tuple[str, str, int, tuple[int, ...]]] = []
    for mode in selected:
        derived = tuple(_runkey_key(cipher, plain, mode) for cipher, plain in zip(cipher_values, crib_values))
        needle = bytes(derived)
        for name, source_values in cleaned:
            haystack = bytes(source_values)
            start = 0
            while True:
                offset = haystack.find(needle, start)
                if offset < 0:
                    break
                if offset + len(cipher_values) <= len(source_values):
                    matches.append((mode, name, offset, source_values))
                    if len(matches) > 1:
                        return ()
                start = offset + 1
    if len(matches) != 1:
        return ()
    mode, name, offset, source_values = matches[0]
    keys = source_values[offset:offset + len(cipher_values)]
    plains = tuple(_runkey_plain(cipher, key, mode) for cipher, key in zip(cipher_values, keys))
    if plains[:len(crib_values)] != crib_values:
        return ()
    if tuple(_runkey_cipher(plain, key, mode) for plain, key in zip(plains, keys)) != cipher_values:
        return ()
    iterator = iter(plains)
    rebuilt: list[str] = []
    for char in cipher_text:
        if char.isascii() and char.isalpha():
            value = next(iterator)
            rebuilt.append(chr(value + (65 if char.isupper() else 97)))
        else:
            rebuilt.append(char)
    payload = "".join(rebuilt).encode("utf-8")
    if not _payload_shape(payload):
        return ()
    candidate = ExoticCandidate(
        f"running-key:{mode}:{name}@{offset}", payload, 1.0,
        ("crib-derived key occurs uniquely in supplied source", "full ciphertext re-encrypts exactly"),
    )
    return (candidate,)

