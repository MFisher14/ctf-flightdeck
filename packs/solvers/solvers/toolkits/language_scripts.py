#!/usr/bin/env python3
"""Offline linguistic/script and character-encoding analysis.

The engine emits ranked candidates and exact transform evidence for human review.  It never selects
the highest-scoring charset, transliteration, or Caesar shift as an answer.  Every charset candidate
must encode back to the original bytes; every Caesar/substitution candidate must round-trip through
the inverse transform.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import math
import re
import sys
import unicodedata
from pathlib import Path
from typing import Any


MAX_INPUT = 4 << 20
MAX_TEXT = 2 << 20
MAX_CANDIDATES = 64

CODECS = (
    "utf-8-sig", "utf-8", "utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-le", "utf-32-be",
    "ascii", "cp1252", "iso8859-1", "iso8859-2", "iso8859-5", "iso8859-7", "iso8859-9",
    "cp437", "cp850", "cp852", "mac_roman", "koi8-r", "koi8-u", "cp866",
    "cp037", "cp500", "cp875", "cp1026", "shift_jis", "euc_jp", "gb18030", "big5", "euc_kr",
)

SCRIPT_PREFIXES = {
    "LATIN": "Latin", "GREEK": "Greek", "CYRILLIC": "Cyrillic", "HEBREW": "Hebrew",
    "ARABIC": "Arabic", "DEVANAGARI": "Devanagari", "BENGALI": "Bengali", "GURMUKHI": "Gurmukhi",
    "GUJARATI": "Gujarati", "TAMIL": "Tamil", "TELUGU": "Telugu", "KANNADA": "Kannada",
    "MALAYALAM": "Malayalam", "THAI": "Thai", "LAO": "Lao", "GEORGIAN": "Georgian",
    "ARMENIAN": "Armenian", "HIRAGANA": "Hiragana", "KATAKANA": "Katakana", "HANGUL": "Hangul",
    "CJK": "Han", "IDEOGRAPH": "Han", "YI ": "Yi", "CHEROKEE": "Cherokee", "ETHIOPIC": "Ethiopic",
    "RUNIC": "Runic", "OGHAM": "Ogham", "BRAILLE": "Braille", "GOTHIC": "Gothic",
    "CUNEIFORM": "Cuneiform", "EGYPTIAN": "Egyptian Hieroglyphs", "DESERET": "Deseret",
}

CONFUSABLE = str.maketrans({
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "І": "I", "Ј": "J", "К": "K",
    "М": "M", "О": "O", "Р": "P", "Ѕ": "S", "Т": "T", "Х": "X", "а": "a", "с": "c",
    "е": "e", "і": "i", "ј": "j", "о": "o", "р": "p", "ѕ": "s", "х": "x", "у": "y",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M",
    "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X", "Υ": "Y", "ο": "o", "ρ": "p",
})

GREEK_LOWER = "αβγδεζηθικλμνξοπρστυφχψω"
GREEK_UPPER = "ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩ"
CYRILLIC_LOWER = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя"
CYRILLIC_UPPER = CYRILLIC_LOWER.upper()

TRANSLIT = {
    **dict(zip(GREEK_LOWER, ("a v g d e z i th i k l m n x o p r s t y f ch ps o").split())),
    **dict(zip(GREEK_UPPER, ("A V G D E Z I Th I K L M N X O P R S T Y F Ch Ps O").split())),
    **dict(zip(CYRILLIC_LOWER, ("a b v g d e yo zh z i y k l m n o p r s t u f h ts ch sh shch '' y ' e yu ya").split())),
}
TRANSLIT.update({key.upper(): value.title() for key, value in list(TRANSLIT.items()) if key in CYRILLIC_LOWER})


def _bounded_text(text: str) -> str:
    if not isinstance(text, str) or len(text.encode("utf-8", "surrogatepass")) > MAX_TEXT:
        raise ValueError("text exceeds the 2 MiB bound")
    return text


def _text_score(text: str) -> float:
    if not text:
        return -100.0
    printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text) / len(text)
    controls = sum(unicodedata.category(ch) in {"Cc", "Cs"} and ch not in "\r\n\t" for ch in text)
    letters = sum(ch.isalpha() for ch in text) / len(text)
    nul = text.count("\x00") / len(text)
    return round(100 * printable + 15 * letters - 120 * nul - 10 * controls, 3)


def encoding_candidates(data: bytes) -> list[dict[str, Any]]:
    """Strict-decode common Unicode/legacy/EBCDIC/CJK codecs and require byte-exact re-encoding."""
    if not isinstance(data, bytes) or len(data) > MAX_INPUT:
        raise ValueError("input exceeds the 4 MiB bound")
    grouped: dict[str, dict[str, Any]] = {}
    for codec in CODECS:
        try:
            text = data.decode(codec, "strict")
            if text.encode(codec, "strict") != data:
                continue
        except (UnicodeError, LookupError):
            continue
        row = grouped.setdefault(text, {"text": text, "codecs": [], "score": _text_score(text),
                                        "verified_roundtrip": True, "candidate_only": True})
        row["codecs"].append(codec)
    rows = sorted(grouped.values(), key=lambda row: (-row["score"], row["codecs"]))
    return rows[:MAX_CANDIDATES]


def _script(char: str) -> str:
    if not char.isalpha() and not (0x2800 <= ord(char) <= 0x28FF):
        return "Common"
    name = unicodedata.name(char, "")
    for prefix, script in SCRIPT_PREFIXES.items():
        if name.startswith(prefix) or prefix in name:
            return script
    return "Unknown"


def script_profile(text: str) -> dict[str, Any]:
    text = _bounded_text(text)
    counts: dict[str, int] = {}
    bidi = []
    invisibles = []
    for index, char in enumerate(text):
        script = _script(char)
        counts[script] = counts.get(script, 0) + 1
        if unicodedata.bidirectional(char) in {"RLO", "LRO", "RLE", "LRE", "PDF", "RLI", "LRI", "FSI", "PDI"}:
            bidi.append({"index": index, "codepoint": f"U+{ord(char):04X}", "name": unicodedata.name(char, "")})
        if char in "\u200b\u200c\u200d\u2060\ufeff" or 0xE0000 <= ord(char) <= 0xE007F:
            invisibles.append({"index": index, "codepoint": f"U+{ord(char):04X}", "name": unicodedata.name(char, "")})
    letter_scripts = {key for key, value in counts.items() if value and key not in {"Common", "Unknown"}}
    mixed_confusable = "Latin" in letter_scripts and bool(letter_scripts & {"Greek", "Cyrillic"})
    skeleton = text.translate(CONFUSABLE)
    return {"scripts": dict(sorted(counts.items(), key=lambda item: (-item[1], item[0]))),
            "mixed_scripts": sorted(letter_scripts) if len(letter_scripts) > 1 else [],
            "mixed_confusable_scripts": mixed_confusable, "confusable_skeleton": skeleton,
            "skeleton_changed": skeleton != text, "bidi_controls": bidi[:512],
            "invisible_controls": invisibles[:2048], "candidate_only": True}


def normalization_views(text: str) -> list[dict[str, Any]]:
    text = _bounded_text(text)
    rows = []
    for form in ("NFC", "NFD", "NFKC", "NFKD"):
        value = unicodedata.normalize(form, text)
        rows.append({"form": form, "text": value, "changed": value != text,
                     "idempotent": unicodedata.normalize(form, value) == value})
    return rows


def hidden_unicode(text: str) -> list[dict[str, Any]]:
    """Decode Unicode tags and two zero-width bit conventions as explicit candidates."""
    text = _bounded_text(text)
    rows = []
    # Preserve run boundaries.  Concatenating distinct tag runs across visible text manufactures a
    # string that never occurred in the artifact while misleadingly calling the mapping verified.
    current: list[str] = []
    start = None

    def flush(end: int, terminated: bool) -> None:
        nonlocal current, start
        if current and sum(row.get("kind") == "unicode_tags" for row in rows) < 8:
            rows.append({"kind": "unicode_tags", "text": "".join(current),
                         "start": start, "end": end, "terminated": terminated,
                         "verified_mapping": True, "candidate_only": True})
        current, start = [], None

    for index, char in enumerate(text):
        codepoint = ord(char)
        if 0xE0020 <= codepoint <= 0xE007E:
            if start is None:
                start = index
            current.append(chr(codepoint - 0xE0000))
        elif codepoint == 0xE007F:
            flush(index + 1, True)
        else:
            flush(index, False)
    flush(len(text), False)
    stream = "".join(ch for ch in text if ch in "\u200b\u200c")
    if len(stream) >= 8:
        for zero, label in (("\u200b", "ZWSP=0"), ("\u200c", "ZWNJ=0")):
            bits = "".join("0" if ch == zero else "1" for ch in stream)
            raw = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - 7, 8))
            decoded = raw.decode("utf-8", "replace")
            rows.append({"kind": "zero_width_bits", "convention": label, "bytes_hex": raw.hex(),
                         "text": decoded, "verified_mapping": False, "candidate_only": True})
    return rows


def transliteration_candidate(text: str) -> dict[str, Any]:
    text = _bounded_text(text)
    value = "".join(TRANSLIT.get(char, char) for char in text)
    return {"text": value, "changed": value != text, "verified": False, "candidate_only": True,
            "note": "approximate modern Greek/Cyrillic transliteration; not a reversible identity"}


def _shift(text: str, shift: int, lower: str, upper: str) -> str:
    out = []
    for char in text:
        alphabet = lower if char in lower else upper if char in upper else None
        if alphabet is None:
            out.append(char)
        else:
            out.append(alphabet[(alphabet.index(char) + shift) % len(alphabet)])
    return "".join(out)


def nonlatin_caesar_candidates(text: str, script: str) -> list[dict[str, Any]]:
    text = _bounded_text(text)
    normalized = script.strip().lower()
    if normalized == "greek":
        if "ς" in text:
            raise ValueError("Greek final sigma makes a reversible one-alphabet shift ambiguous")
        lower, upper = GREEK_LOWER, GREEK_UPPER
    elif normalized in {"cyrillic", "russian"}:
        lower, upper = CYRILLIC_LOWER, CYRILLIC_UPPER
    else:
        raise ValueError("script must be greek or cyrillic")
    rows = []
    for encoded_shift in range(1, len(lower)):
        decoded = _shift(text, -encoded_shift, lower, upper)
        verified = _shift(decoded, encoded_shift, lower, upper) == text
        # Ranking is only a weak language lead, never a choice.
        common = ("και", "το", "της", "εί") if normalized == "greek" else ("что", "это", "на", "не", "пр")
        score = sum(decoded.lower().count(token) * len(token) for token in common)
        rows.append({"encoded_shift": encoded_shift, "decoded": decoded, "language_score": score,
                     "verified_roundtrip": verified, "candidate_only": True})
    return sorted(rows, key=lambda row: (-row["language_score"], row["encoded_shift"]))


def substitute(text: str, mapping: dict[str, str]) -> dict[str, Any]:
    text = _bounded_text(text)
    if not isinstance(mapping, dict) or not 1 <= len(mapping) <= 4096:
        raise ValueError("mapping must be a bounded object")
    clean = {}
    for key, value in mapping.items():
        if not isinstance(key, str) or not isinstance(value, str) or len(key) != 1 or len(value) != 1:
            raise ValueError("substitution keys and values must be one character")
        clean[key] = value
    if len(set(clean.values())) != len(clean):
        raise ValueError("substitution must be one-to-one for round-trip verification")
    decoded = "".join(clean.get(char, char) for char in text)
    inverse = {value: key for key, value in clean.items()}
    verified = "".join(inverse.get(char, char) for char in decoded) == text
    if not verified:
        raise ValueError("mapping collides with unchanged characters; exact inversion failed")
    return {"decoded": decoded, "verified_roundtrip": True, "candidate_only": False,
            "note": "value is exact under the caller-supplied one-to-one mapping"}


def recognize_scripts(text: str) -> list[dict[str, Any]]:
    profile = script_profile(text)
    rows = []
    descriptions = {
        "Braille": "Unicode braille cells; try the existing braille decoder and test dot orientation",
        "Runic": "Unicode runes; transliteration depends on futhark and period",
        "Ogham": "Unicode Ogham; read stem-line direction before transliteration",
        "Gothic": "Unicode Gothic alphabet; transliteration is language-specific",
        "Cuneiform": "Unicode cuneiform signs; sign values require a specialist table",
        "Egyptian Hieroglyphs": "Unicode hieroglyphs; reading order and phonetic values need human review",
        "Deseret": "Deseret alphabet; transliteration is largely phonemic English",
        "Cherokee": "Cherokee syllabary; decode syllables rather than letter substitution",
    }
    for script, count in profile["scripts"].items():
        if script in descriptions:
            rows.append({"script": script, "count": count, "evidence": "exact Unicode character names",
                         "next_step": descriptions[script], "semantic_decode_verified": False})
    return rows


def analyze(text: str) -> dict[str, Any]:
    return {"normalizations": normalization_views(text), "profile": script_profile(text),
            "hidden": hidden_unicode(text), "transliteration": transliteration_candidate(text),
            "recognition": recognize_scripts(text), "answer": None, "requires_human_review": True}


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description="offline character encoding and linguistic/script analysis")
    parser.add_argument("operation", choices=("analyze", "encodings", "caesar", "substitute"))
    parser.add_argument("input")
    parser.add_argument("--script", choices=("greek", "cyrillic"))
    parser.add_argument("--mapping", help="JSON object or @file for exact substitution")
    try:
        args = parser.parse_args(argv)
        raw = Path(args.input).read_bytes()
        if len(raw) > MAX_INPUT:
            raise ValueError("input exceeds 4 MiB")
        if args.operation == "encodings":
            result = {"candidates": encoding_candidates(raw), "answer": None}
        else:
            text = raw.decode("utf-8", "strict")
            if args.operation == "analyze":
                result = analyze(text)
            elif args.operation == "caesar":
                if not args.script:
                    raise ValueError("caesar requires --script")
                result = {"candidates": nonlatin_caesar_candidates(text, args.script), "answer": None}
            else:
                if not args.mapping:
                    raise ValueError("substitute requires --mapping")
                source = Path(args.mapping[1:]).read_text() if args.mapping.startswith("@") else args.mapping
                result = substitute(text, json.loads(source))
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError,
            RecursionError, MemoryError, OverflowError) as exc:
        print(f"language_scripts: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
