"""Verified advanced classical-cipher helpers for the CSCTF r5c lane.

All text APIs return *normalised* text: alphabet symbols are upper-case and
spaces/punctuation are discarded; an alphanumeric symbol outside the selected
alphabet is rejected.  Breakers are finite, collect every passing candidate,
and return only one strictly best candidate.  Equal scores, incomplete search
spaces, contradictory cribs, malformed padding, or failed re-encryption yield
``None`` rather than a guess.

Nothing here performs I/O or contacts an oracle.  Hill matrices use exact
integer cofactors modulo the alphabet size and are cross-checked with SymPy's
``inv_mod`` when that optional library is installed.
"""

from __future__ import annotations

import itertools
import math
from collections import Counter
from typing import Callable, Iterable, Optional, Sequence


ALPHABET26 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHABET25 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
ALPHABET36 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
ADFGVX_LABELS = "ADFGVX"
MAX_TEXT = 100_000
MAX_CANDIDATES = 10_000

__all__ = [
    "hill_encrypt",
    "hill_decrypt",
    "hill_recover_key",
    "hill_break_bounded",
    "adfgvx_encrypt",
    "adfgvx_decrypt",
    "adfgvx_break",
    "running_key_encrypt",
    "running_key_decrypt",
    "running_key_break",
    "book_cipher_encode",
    "book_cipher_decode",
    "book_cipher_break",
    "playfair_encrypt",
    "playfair_decrypt",
    "playfair_break",
    "two_square_transform",
    "two_square_break",
    "autokey_encrypt",
    "autokey_decrypt",
    "autokey_recover_primer",
    "checkerboard_encode",
    "checkerboard_decode",
    "checkerboard_break",
]


def _ints(*values: object) -> bool:
    return all(isinstance(v, int) and not isinstance(v, bool) for v in values)


def _bounded(values: object, cap: int = MAX_CANDIDATES) -> Optional[list[object]]:
    if not _ints(cap) or cap < 0:
        return None
    try:
        out = list(itertools.islice(iter(values), cap + 1))
    except Exception:
        return None
    return out if len(out) <= cap else None


def _alphabet(value: object, expected: Optional[int] = None) -> Optional[str]:
    if not isinstance(value, str):
        return None
    text = value.upper()
    if not text or len(text) > 64 or len(set(text)) != len(text) or not text.isalnum():
        return None
    if expected is not None and len(text) != expected:
        return None
    return text


def _normalise(value: object, alphabet: str, *, merge_j: bool = False) -> Optional[str]:
    if not isinstance(value, str):
        return None
    if len(value) > MAX_TEXT * 4:
        return None
    out = []
    for raw in value.upper():
        ch = "I" if merge_j and raw == "J" else raw
        if ch in alphabet:
            out.append(ch)
        elif ch.isalnum():
            return None
        # Spaces and punctuation are explicitly formatting and are discarded.
    return "".join(out) if len(out) <= MAX_TEXT else None


_FREQ = {
    "E": 12.70, "T": 9.06, "A": 8.17, "O": 7.51, "I": 6.97, "N": 6.75,
    "S": 6.33, "H": 6.09, "R": 5.99, "D": 4.25, "L": 4.03, "C": 2.78,
    "U": 2.76, "M": 2.41, "W": 2.36, "F": 2.23, "G": 2.02, "Y": 1.97,
    "P": 1.93, "B": 1.49, "V": 0.98, "K": 0.77, "J": 0.15, "X": 0.15,
    "Q": 0.10, "Z": 0.07,
}
_COMMON = ("THE", "ING", "ION", "TH", "HE", "ER", "AN", "RE", "ED", "TO")


def _english_score(text: str) -> float:
    letters = [ch for ch in text if ch in ALPHABET26]
    if not letters:
        return -1e100
    counts = Counter(letters)
    n = len(letters)
    chi = sum((counts.get(ch, 0) - n * pct / 100.0) ** 2 / (n * pct / 100.0 + 1e-9)
              for ch, pct in _FREQ.items())
    upper = "".join(letters)
    bonus = sum(upper.count(gram) * len(gram) * 2.0 for gram in _COMMON)
    return bonus - chi - 3.0 * sum(ch.isdigit() for ch in text)


def _passes(text: str, crib: str, crib_position: Optional[int], verifier: Optional[Callable[[str], bool]]) -> bool:
    if crib_position is not None:
        if not _ints(crib_position) or crib_position < 0 or text[crib_position:crib_position + len(crib)] != crib:
            return False
    elif crib and crib not in text:
        return False
    if verifier is not None:
        if not callable(verifier):
            return False
        try:
            if verifier(text) is not True:
                return False
        except Exception:
            return False
    return True


def _pick(candidates: dict[object, tuple[float, object]]) -> object:
    if not candidates:
        return None
    top = max(score for score, _ in candidates.values())
    winners = [value for score, value in candidates.values() if math.isclose(score, top, rel_tol=0.0, abs_tol=1e-12)]
    return winners[0] if len(winners) == 1 else None


def _score(scorer: object, text: str) -> Optional[float]:
    if not callable(scorer):
        return None
    try:
        value = float(scorer(text))
    except Exception:
        return None
    return value if math.isfinite(value) else None


# ---- Hill -----------------------------------------------------------------------------------------

def _det(matrix: Sequence[Sequence[int]]) -> int:
    n = len(matrix)
    if n == 1:
        return matrix[0][0]
    if n == 2:
        return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]
    return sum(((-1) ** col) * matrix[0][col] * _det(
        [list(row[:col]) + list(row[col + 1:]) for row in matrix[1:]]) for col in range(n))


def _matrix(value: object, n: Optional[int], modulus: int) -> Optional[tuple[tuple[int, ...], ...]]:
    if isinstance(value, str):
        if len(value) > 64:
            return None
        flat = [ord(ch) - 65 for ch in value.upper() if "A" <= ch <= "Z"]
        if len(flat) != len(value.replace(" ", "")):
            return None
        if n is None:
            n = math.isqrt(len(flat))
        rows = [flat[i * n:(i + 1) * n] for i in range(n)] if _ints(n) and n > 0 else []
    else:
        raw = _bounded(value, 16)
        if raw is None:
            return None
        if raw and all(isinstance(row, (list, tuple)) for row in raw):
            rows = [list(row) for row in raw]
            n = len(rows)
        else:
            if n is None:
                n = math.isqrt(len(raw))
            rows = [raw[i * n:(i + 1) * n] for i in range(n)] if _ints(n) and n > 0 else []
    if not _ints(n) or not (2 <= n <= 4) or len(rows) != n or any(len(row) != n for row in rows):
        return None
    if any(not _ints(item) for row in rows for item in row):
        return None
    return tuple(tuple(item % modulus for item in row) for row in rows)


def _mat_mul(a: Sequence[Sequence[int]], b: Sequence[Sequence[int]], modulus: int) -> tuple[tuple[int, ...], ...]:
    return tuple(tuple(sum(a[i][k] * b[k][j] for k in range(len(b))) % modulus
                       for j in range(len(b[0]))) for i in range(len(a)))


def _matrix_inverse(
    matrix: Sequence[Sequence[int]],
    modulus: int,
    *,
    crosscheck: bool = True,
) -> Optional[tuple[tuple[int, ...], ...]]:
    n = len(matrix)
    determinant = _det(matrix)
    if math.gcd(determinant, modulus) != 1:
        return None
    inv_det = pow(determinant, -1, modulus)
    cofactors = []
    for row in range(n):
        current = []
        for col in range(n):
            minor = [[matrix[r][c] for c in range(n) if c != col] for r in range(n) if r != row]
            current.append(((-1) ** (row + col)) * _det(minor))
        cofactors.append(current)
    inverse = tuple(tuple(inv_det * cofactors[col][row] % modulus for col in range(n)) for row in range(n))
    identity = tuple(tuple(int(i == j) for j in range(n)) for i in range(n))
    if _mat_mul(matrix, inverse, modulus) != identity or _mat_mul(inverse, matrix, modulus) != identity:
        return None
    if crosscheck:
        try:
            import sympy
        except ImportError:  # pragma: no cover - optional cross-check
            pass
        else:
            try:
                independent = tuple(tuple(int(v) % modulus for v in row)
                                    for row in sympy.Matrix(matrix).inv_mod(modulus).tolist())
            except Exception:
                return None
            if independent != inverse:
                return None
    return inverse


def _hill_apply(text: str, matrix: Sequence[Sequence[int]], alphabet: str) -> str:
    modulus, n = len(alphabet), len(matrix)
    out = []
    for start in range(0, len(text), n):
        vector = [alphabet.index(ch) for ch in text[start:start + n]]
        out.extend(alphabet[sum(matrix[row][col] * vector[col] for col in range(n)) % modulus]
                   for row in range(n))
    return "".join(out)


def hill_encrypt(text: str, key: object, *, alphabet: str = ALPHABET26, pad: str = "X") -> Optional[str]:
    alpha = _alphabet(alphabet)
    matrix = _matrix(key, None, len(alpha)) if alpha else None
    plain = _normalise(text, alpha) if alpha else None
    if matrix is None or plain is None:
        return None
    if _matrix_inverse(matrix, len(alpha)) is None:
        return None
    if len(plain) % len(matrix):
        padding = _normalise(pad, alpha)
        if padding is None or len(padding) != 1:
            return None
        plain += padding * (len(matrix) - len(plain) % len(matrix))
    return _hill_apply(plain, matrix, alpha)


def hill_decrypt(
    ciphertext: str,
    key: object,
    *,
    alphabet: str = ALPHABET26,
    pad: str = "X",
    plaintext_length: Optional[int] = None,
) -> Optional[str]:
    alpha = _alphabet(alphabet)
    matrix = _matrix(key, None, len(alpha)) if alpha else None
    cipher = _normalise(ciphertext, alpha) if alpha else None
    inverse = _matrix_inverse(matrix, len(alpha)) if matrix is not None else None
    if inverse is None or cipher is None or len(cipher) % len(matrix):
        return None
    padded = _hill_apply(cipher, inverse, alpha)
    result = padded
    if plaintext_length is not None:
        padding = _normalise(pad, alpha)
        if not _ints(plaintext_length) or not (0 <= plaintext_length <= len(padded)):
            return None
        if padding is None or len(padding) != 1:
            return None
        if any(ch != padding for ch in padded[plaintext_length:]):
            return None
        result = padded[:plaintext_length]
    if plaintext_length is None:
        verified = _hill_apply(result, matrix, alpha)
    else:
        verified = hill_encrypt(result, matrix, alphabet=alpha, pad=padding)
    if verified != cipher:
        return None
    return result


def hill_recover_key(
    plaintext: str,
    ciphertext: str,
    n: int,
    *,
    alphabet: str = ALPHABET26,
    max_combinations: int = 10_000,
) -> Optional[tuple[tuple[int, ...], ...]]:
    alpha = _alphabet(alphabet)
    plain = _normalise(plaintext, alpha) if alpha else None
    cipher = _normalise(ciphertext, alpha) if alpha else None
    if not _ints(n, max_combinations) or not (2 <= n <= 4) or max_combinations < 1:
        return None
    if plain is None or cipher is None or len(plain) != len(cipher) or len(plain) % n or len(plain) < n * n:
        return None
    blocks = len(plain) // n
    combos = itertools.combinations(range(blocks), n)
    candidates = set()
    for count, selected in enumerate(combos, 1):
        if count > max_combinations:
            return None
        pmat = tuple(tuple(alpha.index(plain[block * n + row]) for block in selected) for row in range(n))
        cmat = tuple(tuple(alpha.index(cipher[block * n + row]) for block in selected) for row in range(n))
        # Crib recovery is low-volume, so cross-check every productive modular
        # inverse with SymPy rather than reserving that check for the final key.
        pinv = _matrix_inverse(pmat, len(alpha), crosscheck=True)
        if pinv is None:
            continue
        key = _mat_mul(cmat, pinv, len(alpha))
        if hill_encrypt(plain, key, alphabet=alpha) == cipher:
            candidates.add(key)
    return next(iter(candidates)) if len(candidates) == 1 else None


def hill_break_bounded(
    ciphertext: str,
    *,
    n: int = 2,
    alphabet: str = ALPHABET26,
    candidate_keys: Optional[Iterable[object]] = None,
    max_keys: int = 26 ** 4,
    crib: str = "",
    crib_position: Optional[int] = None,
    verifier: Optional[Callable[[str], bool]] = None,
    scorer: Callable[[str], float] = _english_score,
) -> Optional[tuple[str, tuple[tuple[int, ...], ...]]]:
    alpha = _alphabet(alphabet)
    cipher = _normalise(ciphertext, alpha) if alpha else None
    clue = _normalise(crib, alpha) if alpha else None
    if not cipher or clue is None or not _ints(n, max_keys) or not (2 <= n <= 4) or max_keys < 1 or not callable(scorer):
        return None
    if candidate_keys is None:
        full = len(alpha) ** (n * n)
        if n != 2 or max_keys < full:
            return None
        raw_keys: Iterable[object] = itertools.product(range(len(alpha)), repeat=4)
    else:
        materialised = _bounded(candidate_keys, max_keys)
        if materialised is None:
            return None
        raw_keys = materialised
    found = {}
    for raw in raw_keys:
        key = _matrix(raw, n, len(alpha))
        if key is None:
            continue
        inverse = _matrix_inverse(key, len(alpha), crosscheck=False)
        plain = _hill_apply(cipher, inverse, alpha) if inverse is not None and len(cipher) % n == 0 else None
        if plain is None or not _passes(plain, clue, crib_position, verifier):
            continue
        if hill_encrypt(plain, key, alphabet=alpha) != cipher:
            continue
        score = _score(scorer, plain)
        if score is None:
            return None
        found[key] = (score, (plain, key))
    result = _pick(found)
    if result is None:
        return None
    plain, key = result
    return result if hill_decrypt(cipher, key, alphabet=alpha) == plain else None


# ---- ADFGVX ---------------------------------------------------------------------------------------

def _keyed_alphabet(key: object, alphabet: str, *, merge_j: bool = False) -> Optional[str]:
    cleaned = _normalise(key, alphabet, merge_j=merge_j)
    if cleaned is None:
        return None
    return "".join(dict.fromkeys(cleaned + alphabet))


def _column_key(key: object) -> Optional[tuple[tuple[int, ...], str]]:
    if isinstance(key, str):
        if len(key) > 256:
            return None
        cleaned = "".join(ch for ch in key.upper() if ch.isalnum())
        if not (2 <= len(cleaned) <= 64):
            return None
        return tuple(sorted(range(len(cleaned)), key=lambda i: (cleaned[i], i))), cleaned
    materialised = _bounded(key, 64)
    if materialised is None:
        return None
    order = tuple(materialised)
    if not (2 <= len(order) <= 64) or any(not _ints(v) for v in order) or set(order) != set(range(len(order))):
        return None
    return order, ".".join(map(str, order))


def _transpose(text: str, order: Sequence[int]) -> str:
    width = len(order)
    columns = [text[col::width] for col in range(width)]
    return "".join(columns[col] for col in order)


def _untranspose(text: str, order: Sequence[int]) -> str:
    width, length = len(order), len(text)
    rows, extra = divmod(length, width)
    sizes = [rows + int(col < extra) for col in range(width)]
    columns, cursor = {}, 0
    for col in order:
        columns[col] = text[cursor:cursor + sizes[col]]
        cursor += sizes[col]
    return "".join(columns[col][row] for row in range(rows + bool(extra))
                   for col in range(width) if row < len(columns[col]))


def _square36(key: object) -> Optional[str]:
    if isinstance(key, str) and len(key) == 36 and set(key.upper()) == set(ALPHABET36):
        return key.upper()
    return _keyed_alphabet(key, ALPHABET36)


def adfgvx_encrypt(text: str, square_key: object, column_key: object) -> Optional[str]:
    square, column = _square36(square_key), _column_key(column_key)
    plain = _normalise(text, ALPHABET36)
    if square is None or column is None or plain is None:
        return None
    positions = {ch: divmod(i, 6) for i, ch in enumerate(square)}
    fractionated = "".join(ADFGVX_LABELS[row] + ADFGVX_LABELS[col]
                           for ch in plain for row, col in (positions[ch],))
    return _transpose(fractionated, column[0])


def adfgvx_decrypt(ciphertext: str, square_key: object, column_key: object) -> Optional[str]:
    square, column = _square36(square_key), _column_key(column_key)
    cipher = _normalise(ciphertext, ADFGVX_LABELS)
    if square is None or column is None or cipher is None or len(cipher) % 2:
        return None
    stream = _untranspose(cipher, column[0])
    out = []
    for i in range(0, len(stream), 2):
        row, col = ADFGVX_LABELS.find(stream[i]), ADFGVX_LABELS.find(stream[i + 1])
        if row < 0 or col < 0:
            return None
        out.append(square[row * 6 + col])
    plain = "".join(out)
    return plain if adfgvx_encrypt(plain, square, column[0]) == cipher else None


def adfgvx_break(
    ciphertext: str,
    square_keys: Iterable[object],
    column_keys: Iterable[object],
    *,
    crib: str = "",
    crib_position: Optional[int] = None,
    verifier: Optional[Callable[[str], bool]] = None,
    scorer: Callable[[str], float] = _english_score,
    max_candidates: int = MAX_CANDIDATES,
) -> Optional[tuple[str, str, tuple[int, ...]]]:
    squares, columns = _bounded(square_keys, max_candidates), _bounded(column_keys, max_candidates)
    cipher, clue = _normalise(ciphertext, ADFGVX_LABELS), _normalise(crib, ALPHABET36)
    # Require a real anchor (non-empty crib, an explicit position, or a verifier). The per-key
    # re-encrypt check is tautological for ADFGVX (decrypt only returns on a round-trip), so without
    # an anchor a lone score winner would be labelled "confident" with nothing actually proving it.
    if (squares is None or columns is None or not cipher or clue is None or not callable(scorer)
            or (not clue and crib_position is None and verifier is None)):
        return None
    if len(squares) * len(columns) > max_candidates:
        return None
    found = {}
    for sq_raw, col_raw in itertools.product(squares, columns):
        square, column = _square36(sq_raw), _column_key(col_raw)
        if square is None or column is None:
            continue
        plain = adfgvx_decrypt(cipher, square, column[0])
        if plain is None or not _passes(plain, clue, crib_position, verifier):
            continue
        if adfgvx_encrypt(plain, square, column[0]) != cipher:
            continue
        identity = (square, column[0])
        score = _score(scorer, plain)
        if score is None:
            return None
        found[identity] = (score, (plain, square, column[0]))
    return _pick(found)


# ---- Running-key and book ciphers -----------------------------------------------------------------

def running_key_encrypt(text: str, key_stream: str, *, alphabet: str = ALPHABET26) -> Optional[str]:
    alpha = _alphabet(alphabet)
    plain, key = (_normalise(text, alpha), _normalise(key_stream, alpha)) if alpha else (None, None)
    if plain is None or key is None or len(key) < len(plain):
        return None
    return "".join(alpha[(alpha.index(ch) + alpha.index(key[i])) % len(alpha)] for i, ch in enumerate(plain))


def running_key_decrypt(ciphertext: str, key_stream: str, *, alphabet: str = ALPHABET26) -> Optional[str]:
    alpha = _alphabet(alphabet)
    cipher, key = (_normalise(ciphertext, alpha), _normalise(key_stream, alpha)) if alpha else (None, None)
    if cipher is None or key is None or len(key) < len(cipher):
        return None
    plain = "".join(alpha[(alpha.index(ch) - alpha.index(key[i])) % len(alpha)] for i, ch in enumerate(cipher))
    return plain if running_key_encrypt(plain, key, alphabet=alpha) == cipher else None


def running_key_break(
    ciphertext: str,
    corpora: Iterable[str],
    *,
    crib: str,
    crib_position: Optional[int] = None,
    verifier: Optional[Callable[[str], bool]] = None,
    scorer: Callable[[str], float] = _english_score,
    max_positions: int = 100_000,
) -> Optional[tuple[str, int, int]]:
    sources = _bounded(corpora, 64)
    cipher, clue = _normalise(ciphertext, ALPHABET26), _normalise(crib, ALPHABET26)
    if sources is None or not cipher or clue is None or not clue or not _ints(max_positions) or max_positions < 1:
        return None
    found, tried = {}, 0
    for source_index, source in enumerate(sources):
        corpus = _normalise(source, ALPHABET26)
        if corpus is None:
            continue
        for offset in range(max(0, len(corpus) - len(cipher) + 1)):
            tried += 1
            if tried > max_positions:
                return None
            key = corpus[offset:offset + len(cipher)]
            plain = running_key_decrypt(cipher, key)
            if plain is None or not _passes(plain, clue, crib_position, verifier):
                continue
            if running_key_encrypt(plain, key) != cipher:
                continue
            identity = (source_index, offset)
            score = _score(scorer, plain)
            if score is None:
                return None
            found[identity] = (score, (plain, source_index, offset))
    return _pick(found)


def _words(corpus: object) -> Optional[list[str]]:
    if not isinstance(corpus, str) or len(corpus) > MAX_TEXT * 4:
        return None
    words = ["".join(ch for ch in token.upper() if "A" <= ch <= "Z") for token in corpus.split()]
    words = [word for word in words if word]
    return words if len(words) <= MAX_TEXT else None


def book_cipher_encode(
    plaintext: str,
    corpus: str,
    *,
    start_word: int = 0,
    index_base: int = 1,
) -> Optional[tuple[int, ...]]:
    plain, words = _normalise(plaintext, ALPHABET26), _words(corpus)
    if plain is None or words is None or not _ints(start_word, index_base) or start_word < 0:
        return None
    result, cursor = [], start_word
    for ch in plain:
        found = next((pos for pos in range(cursor, len(words)) if words[pos][0] == ch), None)
        if found is None:
            return None
        result.append(found + index_base)
        cursor = found + 1
    return tuple(result)


def book_cipher_decode(
    indices: Iterable[int],
    corpus: str,
    *,
    offset: int = 0,
    index_base: int = 1,
) -> Optional[str]:
    values, words = _bounded(indices, MAX_TEXT), _words(corpus)
    if values is None or words is None or not _ints(offset, index_base) or offset < 0:
        return None
    if any(not _ints(value) for value in values):
        return None
    positions = [offset + value - index_base for value in values]
    if any(position < 0 or position >= len(words) for position in positions):
        return None
    return "".join(words[position][0] for position in positions)


def book_cipher_break(
    indices: Iterable[int],
    corpora: Iterable[str],
    offsets: Iterable[int],
    *,
    crib: str,
    crib_position: Optional[int] = None,
    index_bases: Iterable[int] = (0, 1),
    verifier: Optional[Callable[[str], bool]] = None,
    scorer: Callable[[str], float] = _english_score,
) -> Optional[tuple[str, int, int, int]]:
    values, sources, starts, bases = (_bounded(indices, MAX_TEXT), _bounded(corpora, 64),
                                      _bounded(offsets, MAX_CANDIDATES), _bounded(index_bases, 8))
    clue = _normalise(crib, ALPHABET26)
    if any(item is None for item in (values, sources, starts, bases)) or not values or clue is None or not clue:
        return None
    if len(sources) * len(starts) * len(bases) > MAX_CANDIDATES:
        return None
    found = {}
    for source_index, source in enumerate(sources):
        for offset, base in itertools.product(starts, bases):
            plain = book_cipher_decode(values, source, offset=offset, index_base=base)
            if plain is None or not _passes(plain, clue, crib_position, verifier):
                continue
            # Re-project every original index; no heuristic word selection is accepted.
            words = _words(source)
            projected = "".join(words[offset + value - base][0] for value in values)
            if projected != plain:
                continue
            identity = (source_index, offset, base)
            score = _score(scorer, plain)
            if score is None:
                return None
            found[identity] = (score, (plain, source_index, offset, base))
    return _pick(found)


# ---- Playfair and two-square ----------------------------------------------------------------------

def _square25(key: object) -> Optional[str]:
    if isinstance(key, str):
        if len(key) > 256:
            return None
        raw = key.upper().replace("J", "I")
        letters = [ch for ch in raw if ch in ALPHABET25]
        if any(ch.isalnum() and ch not in ALPHABET25 and ch != "J" for ch in raw):
            return None
        return "".join(dict.fromkeys("".join(letters) + ALPHABET25))
    return None


def _playfair_prepare(text: str, filler: str = "X") -> Optional[str]:
    plain, fill = _normalise(text, ALPHABET25, merge_j=True), _normalise(filler, ALPHABET25, merge_j=True)
    if plain is None or fill is None or len(fill) != 1:
        return None
    out, index = [], 0
    while index < len(plain):
        first = plain[index]
        if index + 1 >= len(plain):
            second = fill if first != fill else ("Q" if fill != "Q" else "X")
            index += 1
        elif plain[index + 1] == first:
            second = fill if first != fill else ("Q" if fill != "Q" else "X")
            index += 1
        else:
            second, index = plain[index + 1], index + 2
        out.extend((first, second))
    return "".join(out)


def _playfair_apply(text: str, square: str, direction: int) -> str:
    positions = {ch: divmod(i, 5) for i, ch in enumerate(square)}
    out = []
    for i in range(0, len(text), 2):
        a, b = text[i], text[i + 1]
        r1, c1 = positions[a]
        r2, c2 = positions[b]
        if r1 == r2:
            out.extend((square[r1 * 5 + (c1 + direction) % 5], square[r2 * 5 + (c2 + direction) % 5]))
        elif c1 == c2:
            out.extend((square[((r1 + direction) % 5) * 5 + c1], square[((r2 + direction) % 5) * 5 + c2]))
        else:
            out.extend((square[r1 * 5 + c2], square[r2 * 5 + c1]))
    return "".join(out)


def playfair_encrypt(text: str, key: str, *, filler: str = "X") -> Optional[str]:
    square, prepared = _square25(key), _playfair_prepare(text, filler)
    return _playfair_apply(prepared, square, 1) if square and prepared is not None else None


def playfair_decrypt(ciphertext: str, key: str) -> Optional[str]:
    square, cipher = _square25(key), _normalise(ciphertext, ALPHABET25, merge_j=True)
    if square is None or cipher is None or len(cipher) % 2:
        return None
    plain = _playfair_apply(cipher, square, -1)
    return plain if playfair_encrypt(plain, square) == cipher else None


def playfair_break(
    ciphertext: str,
    keys: Iterable[str],
    *,
    crib: str = "",
    crib_position: Optional[int] = None,
    verifier: Optional[Callable[[str], bool]] = None,
    scorer: Callable[[str], float] = _english_score,
    max_candidates: int = MAX_CANDIDATES,
) -> Optional[tuple[str, str]]:
    raw_keys, cipher = _bounded(keys, max_candidates), _normalise(ciphertext, ALPHABET25, merge_j=True)
    clue = _normalise(crib, ALPHABET25, merge_j=True)
    if raw_keys is None or not cipher or clue is None:
        return None
    found = {}
    for raw in raw_keys:
        square = _square25(raw)
        plain = playfair_decrypt(cipher, square) if square else None
        if plain is None or not _passes(plain, clue, crib_position, verifier):
            continue
        if playfair_encrypt(plain, square) != cipher:
            continue
        score = _score(scorer, plain)
        if score is None:
            return None
        found[square] = (score, (plain, square))
    return _pick(found)


def two_square_transform(
    text: str,
    first_key: str,
    second_key: str,
    *,
    orientation: str = "horizontal",
    pad: Optional[str] = None,
) -> Optional[str]:
    first, second = _square25(first_key), _square25(second_key)
    body = _normalise(text, ALPHABET25, merge_j=True)
    if first is None or second is None or body is None or not isinstance(orientation, str):
        return None
    if orientation not in {"horizontal", "vertical"}:
        return None
    if len(body) % 2:
        padding = _normalise(pad, ALPHABET25, merge_j=True) if pad is not None else None
        if padding is None or len(padding) != 1:
            return None
        body += padding
    pos1 = {ch: divmod(i, 5) for i, ch in enumerate(first)}
    pos2 = {ch: divmod(i, 5) for i, ch in enumerate(second)}
    out = []
    for i in range(0, len(body), 2):
        a, b = body[i], body[i + 1]
        r1, c1 = pos1[a]
        r2, c2 = pos2[b]
        if orientation == "horizontal":
            out.extend((a, b) if r1 == r2 else (first[r2 * 5 + c1], second[r1 * 5 + c2]))
        else:
            out.extend((a, b) if c1 == c2 else (first[r1 * 5 + c2], second[r2 * 5 + c1]))
    return "".join(out)


def two_square_break(
    ciphertext: str,
    key_pairs: Iterable[tuple[str, str]],
    *,
    orientations: Iterable[str] = ("horizontal", "vertical"),
    crib: str = "",
    verifier: Optional[Callable[[str], bool]] = None,
    scorer: Callable[[str], float] = _english_score,
) -> Optional[tuple[str, str, str, str]]:
    pairs, layouts = _bounded(key_pairs), _bounded(orientations, 2)
    cipher, clue = _normalise(ciphertext, ALPHABET25, merge_j=True), _normalise(crib, ALPHABET25, merge_j=True)
    # two-square is an involution, so the re-encrypt guard is vacuous; require a real anchor
    # (non-empty crib / position / verifier) before returning a lone "confident" answer.
    if (pairs is None or layouts is None or not cipher or clue is None
            or (not clue and verifier is None)):
        return None
    if len(pairs) * len(layouts) > MAX_CANDIDATES:
        return None
    found = {}
    for pair, layout in itertools.product(pairs, layouts):
        if not isinstance(pair, (tuple, list)) or len(pair) != 2:
            continue
        first, second = _square25(pair[0]), _square25(pair[1])
        plain = two_square_transform(cipher, first, second, orientation=layout) if first and second else None
        if plain is None or not _passes(plain, clue, None, verifier):
            continue
        if two_square_transform(plain, first, second, orientation=layout) != cipher:
            continue
        identity = (first, second, layout)
        score = _score(scorer, plain)
        if score is None:
            return None
        found[identity] = (score, (plain, first, second, layout))
    return _pick(found)


# ---- Plaintext-autokey ----------------------------------------------------------------------------

def autokey_encrypt(text: str, primer: str, *, alphabet: str = ALPHABET26) -> Optional[str]:
    alpha = _alphabet(alphabet)
    plain, seed = (_normalise(text, alpha), _normalise(primer, alpha)) if alpha else (None, None)
    if plain is None or seed is None or not seed:
        return None
    stream = (seed + plain)[:len(plain)]
    return "".join(alpha[(alpha.index(ch) + alpha.index(stream[i])) % len(alpha)] for i, ch in enumerate(plain))


def autokey_decrypt(ciphertext: str, primer: str, *, alphabet: str = ALPHABET26) -> Optional[str]:
    alpha = _alphabet(alphabet)
    cipher, seed = (_normalise(ciphertext, alpha), _normalise(primer, alpha)) if alpha else (None, None)
    if cipher is None or seed is None or not seed:
        return None
    recovered = []
    for i, ch in enumerate(cipher):
        key_ch = seed[i] if i < len(seed) else recovered[i - len(seed)]
        recovered.append(alpha[(alpha.index(ch) - alpha.index(key_ch)) % len(alpha)])
    plain = "".join(recovered)
    return plain if autokey_encrypt(plain, seed, alphabet=alpha) == cipher else None


def autokey_recover_primer(
    ciphertext: str,
    plaintext_crib: str,
    *,
    max_primer: int = 32,
    alphabet: str = ALPHABET26,
    verifier: Optional[Callable[[str], bool]] = None,
) -> Optional[tuple[str, str]]:
    alpha = _alphabet(alphabet)
    cipher, crib = (_normalise(ciphertext, alpha), _normalise(plaintext_crib, alpha)) if alpha else (None, None)
    if cipher is None or crib is None or not crib or not _ints(max_primer) or max_primer < 1:
        return None
    candidates = {}
    # At least one crib symbol must be encrypted by recovered plaintext feedback;
    # otherwise any crib-length primer is a tautological fit.
    for length in range(1, min(max_primer, len(crib) - 1, len(cipher)) + 1):
        primer = "".join(alpha[(alpha.index(cipher[i]) - alpha.index(crib[i])) % len(alpha)] for i in range(length))
        plain = autokey_decrypt(cipher, primer, alphabet=alpha)
        if plain is None or not plain.startswith(crib) or not _passes(plain, crib, 0, verifier):
            continue
        if autokey_encrypt(plain, primer, alphabet=alpha) != cipher:
            continue
        candidates[primer] = (_english_score(plain), (plain, primer))
    return _pick(candidates)


# ---- Straddling checkerboard ----------------------------------------------------------------------

def _checkerboard(
    alphabet: object,
    columns: object,
    row_digits: object,
) -> Optional[tuple[dict[str, str], dict[str, str]]]:
    alpha = _alphabet(alphabet)
    if not isinstance(columns, str) or len(columns) != 10 or set(columns) != set("0123456789"):
        return None
    rows = _bounded(row_digits, 2)
    if rows is None:
        return None
    rows = tuple(rows)
    if alpha is None or not (1 <= len(alpha) <= 28) or len(rows) != 2 or any(not isinstance(x, str) for x in rows):
        return None
    if len(set(rows)) != 2 or any(len(x) != 1 or x not in columns for x in rows):
        return None
    codes = [digit for digit in columns if digit not in rows]
    codes += [row + digit for row in rows for digit in columns]
    encode = dict(zip(alpha, codes))
    decode = {code: ch for ch, code in encode.items()}
    return encode, decode


def checkerboard_encode(
    text: str,
    *,
    alphabet: str = ALPHABET26,
    columns: str = "0123456789",
    row_digits: Sequence[str] = ("2", "6"),
) -> Optional[str]:
    alpha = _alphabet(alphabet)
    rows = _bounded(row_digits, 2)
    board = _checkerboard(alpha, columns, rows) if alpha and rows is not None else None
    plain = _normalise(text, alpha) if alpha else None
    if board is None or plain is None:
        return None
    return "".join(board[0][ch] for ch in plain)


def checkerboard_decode(
    ciphertext: str,
    *,
    alphabet: str = ALPHABET26,
    columns: str = "0123456789",
    row_digits: Sequence[str] = ("2", "6"),
) -> Optional[str]:
    alpha = _alphabet(alphabet)
    rows_list = _bounded(row_digits, 2)
    board = _checkerboard(alpha, columns, rows_list) if alpha and rows_list is not None else None
    if board is None or not isinstance(ciphertext, str):
        return None
    digits = "".join(ch for ch in ciphertext if not ch.isspace())
    if any(ch not in columns for ch in digits) or len(digits) > MAX_TEXT * 2:
        return None
    rows, out, index = set(rows_list), [], 0
    while index < len(digits):
        if digits[index] in rows:
            if index + 1 >= len(digits):
                return None
            code, index = digits[index:index + 2], index + 2
        else:
            code, index = digits[index], index + 1
        if code not in board[1]:
            return None
        out.append(board[1][code])
    plain = "".join(out)
    return plain if checkerboard_encode(plain, alphabet=alpha, columns=columns, row_digits=rows_list) == digits else None


def checkerboard_break(
    ciphertext: str,
    configurations: Iterable[tuple[str, str, Sequence[str]]],
    *,
    crib: str = "",
    verifier: Optional[Callable[[str], bool]] = None,
    scorer: Callable[[str], float] = _english_score,
) -> Optional[tuple[str, str, str, tuple[str, str]]]:
    configs = _bounded(configurations)
    # The re-encrypt guard below is tautological, so require a real anchor (crib or verifier) before
    # this returns a lone "confident" answer; otherwise it would overclaim a crib-less score winner.
    if (configs is None or not isinstance(ciphertext, str) or not ciphertext.strip()
            or not (crib or verifier is not None)):
        return None
    found = {}
    for config in configs:
        if not isinstance(config, (tuple, list)) or len(config) != 3:
            continue
        alphabet, columns, raw_rows = config
        rows = _bounded(raw_rows, 2)
        if rows is None:
            continue
        canonical_alphabet = _alphabet(alphabet)
        clue = _normalise(crib, canonical_alphabet) if canonical_alphabet else None
        plain = checkerboard_decode(ciphertext, alphabet=alphabet, columns=columns, row_digits=rows)
        if plain is None or clue is None or not _passes(plain, clue, None, verifier):
            continue
        canonical_rows = tuple(rows)
        normalised_cipher = "".join(ch for ch in ciphertext if not ch.isspace())
        if checkerboard_encode(
            plain,
            alphabet=canonical_alphabet,
            columns=columns,
            row_digits=canonical_rows,
        ) != normalised_cipher:
            continue
        identity = (canonical_alphabet, columns, canonical_rows)
        score = _score(scorer, plain)
        if score is None:
            return None
        found[identity] = (score, (plain, canonical_alphabet, columns, canonical_rows))
    return _pick(found)
