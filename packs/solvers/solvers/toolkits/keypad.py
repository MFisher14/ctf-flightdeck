#!/usr/bin/env python3
"""Phone-keypad decoders: DTMF from a tone list, and T9 / multitap (ABC) decode.

Two small, offline, dependency-free helpers for the 2024 Stegano "Call me" archetype (a screenshot of
phone-key ciphers -> tesseract OCR -> DTMF digits + multitap letters). The audio-side DTMF reader lives
in `carve_stego.dtmf` (Goertzel over a PCM WAV); THIS module is the symbolic side -- you already have a
LIST of tone pairs (from a table, a spectrogram readout, or OCR) or a string of key presses, and want
the digits/letters they spell.

  dtmf_from_frequencies(pairs) -> "digits" | None       # [(low_hz, high_hz), ...] -> DTMF keys
  dtmf_key(low, high)          -> "5" | None            # one tone pair -> one key
  multitap_decode(presses)     -> "TEXT" | None         # "44 33 555 555 666" -> "HELLO"
  keypad_letters(digit)        -> "JKL"                  # the letters on one key

These RETURN candidate strings for you to read and reason about; nothing is submitted here. Pure
standard library.
"""
import math
import re

__all__ = ["dtmf_from_frequencies", "dtmf_key", "multitap_decode", "keypad_letters",
           "DTMF_LOW", "DTMF_HIGH", "DTMF_KEYS", "MULTITAP"]

# ---- DTMF (dual-tone multi-frequency) --------------------------------------------------------------
DTMF_LOW = (697, 770, 852, 941)
DTMF_HIGH = (1209, 1336, 1477, 1633)
DTMF_KEYS = ("123A", "456B", "789C", "*0#D")     # [row][col], row=low index, col=high index


def _nearest(freq, table, tol):
    """Index of the table frequency closest to `freq`, if within `tol` (relative). Else None, and
    None if two table entries tie as closest (ambiguous -> never guess)."""
    try:
        f = float(freq)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(f):          # NaN / inf are not DTMF frequencies
        return None
    best = sorted(range(len(table)), key=lambda i: abs(table[i] - f))
    i0 = best[0]
    if abs(table[i0] - f) > tol * table[i0]:
        return None
    if len(best) > 1 and abs(table[best[1]] - f) == abs(table[i0] - f):
        return None
    return i0


def dtmf_key(low, high, tol: float = 0.035):
    """The single DTMF key for one (low_hz, high_hz) tone pair, snapping each to the nearest standard
    DTMF frequency within `tol` (relative, default 3.5%). None when either tone is not a DTMF
    frequency. Order-insensitive: a (high, low) pair is accepted too."""
    li = _nearest(low, DTMF_LOW, tol)
    hi = _nearest(high, DTMF_HIGH, tol)
    if li is None or hi is None:
        # tolerate a swapped pair (high given first)
        li2 = _nearest(high, DTMF_LOW, tol)
        hi2 = _nearest(low, DTMF_HIGH, tol)
        if li2 is None or hi2 is None:
            return None
        li, hi = li2, hi2
    return DTMF_KEYS[li][hi]


def dtmf_from_frequencies(pairs, tol: float = 0.035):
    """Decode a list of (low_hz, high_hz) tone pairs to a DTMF key string. Returns the string, or None
    if ANY pair is not a valid DTMF tone pair (so a partial/garbled list fails loudly rather than
    silently dropping keys -- raise `tol` or clean the list and retry)."""
    try:
        iterator = iter(pairs)
    except TypeError:
        return None
    out = []
    for pair in iterator:
        if not (isinstance(pair, (tuple, list)) and len(pair) == 2):
            return None
        k = dtmf_key(pair[0], pair[1], tol)
        if k is None:
            return None
        out.append(k)
    return "".join(out)


# ---- T9 / multitap (ABC) ---------------------------------------------------------------------------
MULTITAP = {
    "2": "ABC", "3": "DEF", "4": "GHI", "5": "JKL",
    "6": "MNO", "7": "PQRS", "8": "TUV", "9": "WXYZ",
}
# keys that map to a literal, not to a cycle of letters
_LITERAL = {"0": " ", "1": "1"}


def keypad_letters(digit):
    """The letters printed on a phone key, e.g. keypad_letters('5') == 'JKL'. '' for a key with no
    letters (0, 1)."""
    d = str(digit)
    return MULTITAP.get(d, _LITERAL.get(d, "") if d in _LITERAL else "")


def multitap_decode(presses):
    """Decode old-phone multitap text. `presses` is the key presses with a SEPARATOR between letters
    (a pause): a string like "44 33 555 555 666" / "44-33-555-555-666" (-> "HELLO"), or an iterable of
    runs like ["44", "33", "555"]. Each run is one key pressed 1..4 times; the count selects the letter
    on that key (wrapping: "7777" -> 'S', "77777" -> 'P'). '0' decodes to a space, '1' to '1'.

    Separators are REQUIRED between runs -- multitap is ambiguous without the pause ("2222" alone could
    be "AA", "CA", ...). Returns the decoded text, or None if a run mixes different digits or uses an
    unknown key. Case of the output is upper (phone keycaps)."""
    if isinstance(presses, str):
        runs = [r for r in re.split(r"[^0-9*#]+", presses) if r]
    else:
        try:
            runs = [str(r).strip() for r in presses]
            runs = [r for r in runs if r]
        except TypeError:
            return None
    out = []
    for run in runs:
        if not run or any(c != run[0] for c in run):
            return None                              # a run must be one repeated key
        d = run[0]
        if d in _LITERAL:
            out.append(_LITERAL[d])
            continue
        letters = MULTITAP.get(d)
        if not letters:
            return None                              # '*' / '#' / unknown: no letter mapping
        out.append(letters[(len(run) - 1) % len(letters)])
    return "".join(out)


if __name__ == "__main__":
    import sys
    arg = " ".join(sys.argv[1:])
    if arg:
        print("multitap:", multitap_decode(arg))
    else:
        print("usage: keypad.py '44 33 555 555 666'   (-> HELLO)")
