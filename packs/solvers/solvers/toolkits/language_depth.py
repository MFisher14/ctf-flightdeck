#!/usr/bin/env python3
"""Offline Unicode, script, transliteration, and cipher-script evidence helpers.

This is deliberately an evidence lane, not an answer picker.  It adds charset
families and scripts that the round-5 ``language_scripts`` module does not cover,
audits combining/bidi/tag behavior, and recognizes *possible* constructed-script
surfaces without claiming that a visual glyph inventory has been decoded.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata
from pathlib import Path
from typing import Any


MAX_BYTES = 4 << 20
MAX_TEXT = 2 << 20
MAX_IDENTIFIERS = 20_000
MAX_FINDINGS = 4096


class Refuse(ValueError):
    pass


CHARSETS = (
    "utf-8", "utf-8-sig", "utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be",
    "cp1250", "cp1251", "cp1255", "cp1256", "cp1257", "cp1258", "cp874",
    "iso8859-6", "iso8859-8", "iso8859-15", "mac_cyrillic", "koi8-r", "koi8-u",
    "shift_jis", "euc_jp", "gb18030", "big5", "euc_kr",
)

SCRIPT_PREFIXES = {
    "LATIN": "Latin", "GREEK": "Greek", "CYRILLIC": "Cyrillic", "HEBREW": "Hebrew",
    "ARABIC": "Arabic", "ARMENIAN": "Armenian", "GEORGIAN": "Georgian",
    "DEVANAGARI": "Devanagari", "BENGALI": "Bengali", "GURMUKHI": "Gurmukhi",
    "GUJARATI": "Gujarati", "ORIYA": "Odia", "TAMIL": "Tamil", "TELUGU": "Telugu",
    "KANNADA": "Kannada", "MALAYALAM": "Malayalam", "SINHALA": "Sinhala",
    "THAI": "Thai", "LAO": "Lao", "TIBETAN": "Tibetan", "MYANMAR": "Myanmar",
    "HIRAGANA": "Hiragana", "KATAKANA": "Katakana", "HANGUL": "Hangul",
    "CJK": "Han", "IDEOGRAPH": "Han", "CHEROKEE": "Cherokee", "ETHIOPIC": "Ethiopic",
    "RUNIC": "Runic", "OGHAM": "Ogham", "BRAILLE": "Braille", "SHAVIAN": "Shavian",
    "DESERET": "Deseret", "OSMANYA": "Osmanya", "OLD ITALIC": "Old Italic",
}

# Curated high-value identifier lookalikes beyond the small Greek/Cyrillic table
# already shipped in round 5.  NFKC is applied first, catching fullwidth and most
# mathematical alphanumerics.  A skeleton is evidence only: it is not UTS #39.
CONFUSABLES = str.maketrans({
    "Α": "A", "А": "A", "Ꭺ": "A", "Β": "B", "В": "B", "Ᏼ": "B",
    "Ϲ": "C", "С": "C", "Ꮯ": "C", "Ꭰ": "D", "Ε": "E", "Е": "E",
    "Ꭼ": "E", "Ϝ": "F", "Ғ": "F", "Η": "H", "Н": "H", "Ꮋ": "H",
    "Ι": "I", "І": "I", "Ӏ": "I", "Ꮖ": "I", "Ј": "J", "Ꭻ": "J",
    "Κ": "K", "К": "K", "Ꮶ": "K", "ᒪ": "L", "Μ": "M", "М": "M",
    "Ꮇ": "M", "Ν": "N", "Ν": "N", "О": "O", "Ο": "O", "Օ": "O",
    "Ꮎ": "O", "Ρ": "P", "Р": "P", "Ꮲ": "P", "Ԛ": "Q", "Ѕ": "S",
    "Տ": "S", "Τ": "T", "Т": "T", "Ꭲ": "T", "Ս": "U", "Ѵ": "V",
    "Ꮩ": "V", "Ԝ": "W", "Χ": "X", "Х": "X", "᙭": "X", "Υ": "Y",
    "Ү": "Y", "Ζ": "Z", "Ꮓ": "Z",
    "а": "a", "ɑ": "a", "Ь": "b", "Ꮟ": "b", "ϲ": "c", "с": "c",
    "ԁ": "d", "е": "e", "ҽ": "e", "һ": "h", "і": "i", "ӏ": "l",
    "ј": "j", "κ": "k", "к": "k", "Ӏ": "l", "м": "m", "ո": "n",
    "ο": "o", "о": "o", "օ": "o", "ρ": "p", "р": "p", "զ": "q",
    "ѕ": "s", "տ": "t", "υ": "u", "ս": "u", "ѵ": "v", "ν": "v",
    "ԝ": "w", "χ": "x", "х": "x", "у": "y", "ү": "y", "ᴢ": "z",
})

BIDI_CONTROLS = {
    "\u202a": "LRE", "\u202b": "RLE", "\u202c": "PDF", "\u202d": "LRO",
    "\u202e": "RLO", "\u2066": "LRI", "\u2067": "RLI", "\u2068": "FSI",
    "\u2069": "PDI", "\u200e": "LRM", "\u200f": "RLM", "\u061c": "ALM",
}

HEBREW = "אבגדהוזחטיכלמנסעפצקרשת"
HEBREW_FINALS = "ךםןףץ"
ARABIC = "ابتثجحخدذرزسشصضطظعغفقكلمنهوي"
ARMENIAN_UPPER = "ԱԲԳԴԵԶԷԸԹԺԻԼԽԾԿՀՁՂՃՄՅՆՇՈՉՊՋՌՍՎՏՐՑՒՓՔՕՖ"
ARMENIAN_LOWER = "աբգդեզէըթժիլխծկհձղճմյնշոչպջռսվտրցւփքօֆ"
GEORGIAN = "აბგდევზთიკლმნოპჟრსტუფქღყშჩცძწჭხჯჰ"

ROMAN = {
    "hebrew": dict(zip(HEBREW, "ʾ b g d h w z kh t y k l m n s ʿ p ts q r sh t".split())),
    "arabic": dict(zip(ARABIC, "ʾ b t th j h kh d dh r z s sh s d t z ʿ gh f q k l m n h w y".split())),
    "armenian": dict(zip(ARMENIAN_LOWER, (
        "a b g d e z ē ə t' ž i l x c k h j ł č m y n š o č' p ǰ ṙ s v t r c' w p' k' ō f"
    ).split())),
    "georgian": dict(zip(GEORGIAN, (
        "a b g d e v z t k' i l m n o p ž r s t' u p' k g q š č c dz c' č' x j h"
    ).split())),
}
ROMAN["armenian"].update({upper: ROMAN["armenian"][lower].upper()
                           for upper, lower in zip(ARMENIAN_UPPER, ARMENIAN_LOWER)})
ROMAN["hebrew"].update(dict(zip(HEBREW_FINALS, ("k", "m", "n", "p", "ts"))))

# ``zip`` silently truncates a bad table.  Fail at import instead of presenting a
# partial transliteration/shift alphabet as if it were complete.
if not (len(HEBREW) == len(set(HEBREW)) == 22
        and len(ARABIC) == len(set(ARABIC)) == 28
        and len(ARMENIAN_LOWER) == len(set(ARMENIAN_LOWER)) == 38
        and len(ARMENIAN_UPPER) == len(set(ARMENIAN_UPPER)) == 38
        and len(GEORGIAN) == len(set(GEORGIAN)) == 33
        and len(ROMAN["hebrew"]) == 27 and len(ROMAN["arabic"]) == 28
        and len(ROMAN["armenian"]) == 76 and len(ROMAN["georgian"]) == 33):
    raise RuntimeError("r5g language alphabet/transliteration table invariant failed")

CAESAR_ALPHABETS = {
    "hebrew": (HEBREW, None), "arabic": (ARABIC, None),
    "armenian": (ARMENIAN_LOWER, ARMENIAN_UPPER), "georgian": (GEORGIAN, None),
}

# Visual inventories only.  These sets intentionally do not carry a plaintext
# mapping: font variants and rotations make an automatic semantic decode unsafe.
PIGPEN_GLYPHS = frozenset("⌜⌝⌞⌟┌┐└┘├┤┬┴┼╳×△▽◁▷<>^v•·∙")
SGA_GLYPHS = frozenset("ᔑʖᓵ↸ᒷ⎓⊣⍑╎⋮ꖌꖎᒲリ𝙹¡ᑑ∷ᓭℸ⚍⍊∴⨅")


def _bounded(text: str) -> str:
    if not isinstance(text, str) or len(text.encode("utf-8", "surrogatepass")) > MAX_TEXT:
        raise Refuse("text exceeds 2 MiB")
    return text


def script_of(char: str) -> str:
    if not isinstance(char, str) or len(char) != 1:
        raise Refuse("script_of requires one Unicode character")
    codepoint = ord(char)
    if (0xE000 <= codepoint <= 0xF8FF or 0xF0000 <= codepoint <= 0xFFFFD
            or 0x100000 <= codepoint <= 0x10FFFD):
        return "Private Use"
    name = unicodedata.name(char, "")
    for prefix, label in SCRIPT_PREFIXES.items():
        if name.startswith(prefix) or prefix in name:
            return label
    return "Inherited" if unicodedata.combining(char) else "Common"


def charset_evidence(data: bytes) -> dict[str, Any]:
    """Return every strict, byte-roundtripping reading plus independent byte cues."""
    if not isinstance(data, bytes) or len(data) > MAX_BYTES:
        raise Refuse("input exceeds 4 MiB")
    bom_names = ((b"\xef\xbb\xbf", "utf-8"), (b"\xff\xfe\x00\x00", "utf-32-le"),
                 (b"\x00\x00\xfe\xff", "utf-32-be"), (b"\xff\xfe", "utf-16-le"),
                 (b"\xfe\xff", "utf-16-be"))
    bom = next((name for prefix, name in bom_names if data.startswith(prefix)), None)
    grouped: dict[str, dict[str, Any]] = {}
    for codec in CHARSETS:
        try:
            text = data.decode(codec, "strict")
            if text.encode(codec, "strict") != data:
                continue
        except (UnicodeError, LookupError):
            continue
        row = grouped.setdefault(text, {"text": text, "codecs": [], "roundtrip_verified": True,
                                        "candidate_only": True})
        row["codecs"].append(codec)
    null_mod = {str(width): [sum(1 for index in range(offset, len(data), width) if data[index] == 0)
                             for offset in range(width)] for width in (2, 4)}
    return {"bom": bom, "null_position_counts": null_mod,
            "candidates": sorted(grouped.values(), key=lambda row: row["codecs"]),
            "answer": None, "requires_human_review": True}


def confusable_skeleton(text: str) -> dict[str, Any]:
    text = _bounded(text)
    normalized = unicodedata.normalize("NFKC", text)
    skeleton = normalized.translate(CONFUSABLES)
    return {"original": text, "nfkc": normalized, "skeleton": skeleton,
            "changed": skeleton != text, "mapping_scope": "curated_high_value_not_full_uts39",
            "candidate_only": True}


def combining_audit(text: str) -> dict[str, Any]:
    text = _bounded(text)
    clusters, current = [], None
    orphan = []
    for index, char in enumerate(text):
        # Some meaningful marks (notably variation selectors) have canonical
        # combining class zero, so category M is the correct inclusion test.
        mark = unicodedata.category(char).startswith("M")
        if mark and current is None:
            orphan.append(index)
            current = {"start": index, "base": "", "marks": []}
        elif not mark:
            if current is not None:
                clusters.append(current)
            current = {"start": index, "base": char, "marks": []}
        if mark:
            current["marks"].append({"index": index, "codepoint": f"U+{ord(char):04X}",
                                     "name": unicodedata.name(char, ""),
                                     "combining_class": unicodedata.combining(char),
                                     "category": unicodedata.category(char)})
    if current is not None:
        clusters.append(current)
    marked = [row for row in clusters if row["marks"]]
    suspicious = [row for row in marked if len(row["marks"]) >= 3 or not row["base"]]
    return {"marked_clusters": marked[:MAX_FINDINGS], "orphan_mark_indices": orphan[:MAX_FINDINGS],
            "stacked_mark_clusters": suspicious[:MAX_FINDINGS],
            "nfc_changed": unicodedata.normalize("NFC", text) != text,
            "nfkc_changed": unicodedata.normalize("NFKC", text) != text,
            "candidate_only": True}


def bidi_audit(text: str) -> dict[str, Any]:
    """Expose controls and directional runs; visual reconstruction is explicitly approximate."""
    text = _bounded(text)
    controls = []
    stack: list[tuple[str, int, str]] = []
    unmatched = []
    implicitly_closed = []
    for index, char in enumerate(text):
        label = BIDI_CONTROLS.get(char)
        if not label:
            continue
        controls.append({"index": index, "codepoint": f"U+{ord(char):04X}", "name": label})
        if label in {"LRE", "RLE", "LRO", "RLO"}:
            stack.append(("embedding", index, label))
        elif label == "PDF":
            # PDF cannot cross an isolate boundary.
            if stack and stack[-1][0] == "embedding":
                stack.pop()
            else:
                unmatched.append({"index": index, "name": label})
        elif label in {"LRI", "RLI", "FSI"}:
            stack.append(("isolate", index, label))
        elif label == "PDI":
            isolate_at = next((at for at in range(len(stack) - 1, -1, -1)
                               if stack[at][0] == "isolate"), None)
            if isolate_at is None:
                unmatched.append({"index": index, "name": label})
            else:
                implicitly_closed.extend({"index": item[1], "name": item[2], "closed_by_pdi": index}
                                         for item in stack[isolate_at + 1:] if item[0] == "embedding")
                del stack[isolate_at:]
    stripped = "".join(char for char in text if char not in BIDI_CONTROLS)
    runs = []
    for char in stripped:
        bidi = unicodedata.bidirectional(char)
        direction = "rtl" if bidi in {"R", "AL", "AN"} else "ltr" if bidi in {"L", "EN"} else "neutral"
        if not runs or runs[-1]["direction"] != direction:
            runs.append({"direction": direction, "text": char})
        else:
            runs[-1]["text"] += char
    approximate = "".join(row["text"][::-1] if row["direction"] == "rtl" else row["text"] for row in runs)
    embedding = [(index, label) for kind, index, label in stack if kind == "embedding"]
    isolates = [(index, label) for kind, index, label in stack if kind == "isolate"]
    return {"controls": controls[:MAX_FINDINGS], "unclosed_embeddings": embedding[:MAX_FINDINGS],
            "unclosed_isolates": isolates[:MAX_FINDINGS], "unmatched_closers": unmatched[:MAX_FINDINGS],
            "implicitly_closed_by_pdi": implicitly_closed[:MAX_FINDINGS],
            "directional_runs": runs[:MAX_FINDINGS],
            "views": [{"kind": "logical_controls_stripped", "text": stripped, "verified": True},
                      {"kind": "rtl_runs_reversed_approximation", "text": approximate,
                       "verified": False, "note": "not a Unicode Bidirectional Algorithm renderer"}],
            "candidate_only": True}


def tag_run_audit(text: str) -> dict[str, Any]:
    text = _bounded(text)
    runs, active, start = [], [], None
    orphan_cancels = []
    for index, char in enumerate(text):
        cp = ord(char)
        if 0xE0020 <= cp <= 0xE007E:
            if start is None:
                start = index
            active.append(chr(cp - 0xE0000))
        elif cp == 0xE007F:
            if start is not None:
                runs.append({"start": start, "end": index + 1, "payload": "".join(active),
                             "cancelled": True, "mapping_verified": True})
            else:
                orphan_cancels.append(index)
            active, start = [], None
        elif start is not None:
            runs.append({"start": start, "end": index, "payload": "".join(active),
                         "cancelled": False, "mapping_verified": True})
            active, start = [], None
    if start is not None:
        runs.append({"start": start, "end": len(text), "payload": "".join(active),
                     "cancelled": False, "mapping_verified": True})
    visible = "".join(char for char in text if not 0xE0020 <= ord(char) <= 0xE007F)
    return {"runs": runs[:MAX_FINDINGS], "visible_text": visible,
            "orphan_cancel_indices": orphan_cancels[:MAX_FINDINGS], "has_unterminated_run":
            any(not row["cancelled"] for row in runs), "candidate_only": True}


def transliteration_evidence(text: str, script: str) -> dict[str, Any]:
    text = _bounded(text)
    script = script.lower()
    if script not in ROMAN:
        raise Refuse("script must be hebrew, arabic, armenian, or georgian")
    mapping = ROMAN[script]
    readable = "".join(mapping.get(char, char) for char in text)
    codepoints = " ".join(f"U+{ord(char):04X}" for char in text)
    recovered = "".join(chr(int(token[2:], 16)) for token in codepoints.split()) if codepoints else ""
    return {"script": script, "readable": readable, "readable_reversible": False,
            "lossless_codepoints": codepoints, "lossless_roundtrip_verified": recovered == text,
            "changed": readable != text, "candidate_only": True,
            "note": "readable romanization is approximate; codepoint rendering is exact"}


def _shift(text: str, amount: int, lower: str, upper: str | None) -> str:
    out = []
    for char in text:
        alphabet = lower if char in lower else upper if upper and char in upper else None
        out.append(alphabet[(alphabet.index(char) + amount) % len(alphabet)] if alphabet else char)
    return "".join(out)


def nonlatin_caesar(text: str, script: str) -> list[dict[str, Any]]:
    text = _bounded(text)
    script = script.lower()
    if script not in CAESAR_ALPHABETS:
        raise Refuse("script must be hebrew, arabic, armenian, or georgian")
    if script == "hebrew" and any(char in HEBREW_FINALS for char in text):
        raise Refuse("Hebrew final forms make a single-alphabet Caesar shift ambiguous")
    lower, upper = CAESAR_ALPHABETS[script]
    rows = []
    for encoded_shift in range(1, len(lower)):
        decoded = _shift(text, -encoded_shift, lower, upper)
        rows.append({"script": script, "encoded_shift": encoded_shift, "decoded": decoded,
                     "roundtrip_verified": _shift(decoded, encoded_shift, lower, upper) == text,
                     "candidate_only": True})
    return rows


def identifier_audit(text: str) -> dict[str, Any]:
    text = _bounded(text)
    rows, collisions = [], {}

    def spans():
        start = None
        for index, char in enumerate(text + "\0"):
            category = unicodedata.category(char) if char != "\0" else "Cc"
            begins = char == "_" or category.startswith("L") or category == "Nl"
            continues = begins or category.startswith(("M", "N")) or category == "Pc"
            if start is None and begins:
                start = index
            elif start is not None and not continues:
                yield start, index, text[start:index]
                start = None

    for start, _end, value in spans():
        if len(rows) >= MAX_IDENTIFIERS:
            break
        scripts = sorted({script_of(char) for char in value if char.isalpha()} - {"Common", "Inherited"})
        skeleton = confusable_skeleton(value)["skeleton"]
        row = {"start": start, "text": value, "scripts": scripts,
               "mixed_scripts": len(scripts) > 1, "skeleton": skeleton,
               "skeleton_changed": skeleton != value}
        rows.append(row)
        collisions.setdefault(skeleton.casefold(), set()).add(value)
    collision_rows = [{"skeleton": key, "spellings": sorted(values)} for key, values in collisions.items()
                      if len(values) > 1]
    return {"identifiers": rows, "skeleton_collisions": collision_rows[:MAX_FINDINGS],
            "truncated": len(rows) == MAX_IDENTIFIERS, "candidate_only": True}


def recognize_constructed(text: str, *, font_hint: str = "") -> list[dict[str, Any]]:
    """Recognize inventories, never derive plaintext from appearance alone."""
    text = _bounded(text)
    visible = [char for char in text if not char.isspace()]
    rows = []
    if visible:
        pigpen = sum(char in PIGPEN_GLYPHS for char in visible)
        sga = sum(char in SGA_GLYPHS for char in visible)
        pigpen_distinct = {char for char in visible if char in PIGPEN_GLYPHS}
        sga_distinct = {char for char in visible if char in SGA_GLYPHS}
        geometric = any(ord(char) > 127 and char in PIGPEN_GLYPHS for char in visible)
        if pigpen >= 4 and len(pigpen_distinct) >= 3 and geometric and pigpen / len(visible) >= 0.5:
            rows.append({"candidate": "pigpen-like geometric inventory", "matched": pigpen,
                         "confidence": "medium", "semantic_decode_verified": False})
        if sga >= 4 and len(sga_distinct) >= 3 and sga / len(visible) >= 0.5:
            rows.append({"candidate": "Standard Galactic Alphabet Unicode transcription", "matched": sga,
                         "confidence": "medium", "semantic_decode_verified": False})
    hint = font_hint.casefold()
    pua = [char for char in text if script_of(char) == "Private Use"]
    conventions = []
    if any(0xF8D0 <= ord(char) <= 0xF8FF for char in pua):
        conventions.append("Klingon pIqaD ConScript convention")
    if any(0xE000 <= ord(char) <= 0xE07F for char in pua):
        conventions.append("Tengwar-style ConScript convention")
    if pua:
        rows.append({"candidate": "font-dependent private-use cipher/constructed script",
                     "matched": len(pua), "conventions": conventions, "confidence": "low",
                     "semantic_decode_verified": False})
    for name in ("aurebesh", "pigpen", "tengwar", "klingon", "standard galactic"):
        if name in hint:
            rows.append({"candidate": name, "evidence": "caller-supplied font hint",
                         "confidence": "medium", "semantic_decode_verified": False})
    if not rows and hint:
        rows.append({"candidate": "unknown font-defined cipher script", "evidence": font_hint,
                     "confidence": "low", "semantic_decode_verified": False})
    for row in rows:
        row.update(candidate_only=True, requires_human_glyph_review=True, decoded_text=None)
    return rows


def analyze(text: str, *, font_hint: str = "") -> dict[str, Any]:
    text = _bounded(text)
    scripts: dict[str, int] = {}
    for char in text:
        label = script_of(char)
        scripts[label] = scripts.get(label, 0) + 1
    transliterations = [transliteration_evidence(text, script) for script in ROMAN
                        if any(char in ROMAN[script] for char in text)]
    return {"scripts": dict(sorted(scripts.items(), key=lambda item: (-item[1], item[0]))),
            "confusables": confusable_skeleton(text), "identifiers": identifier_audit(text),
            "combining": combining_audit(text), "bidi": bidi_audit(text),
            "unicode_tags": tag_run_audit(text), "transliterations": transliterations,
            "constructed_scripts": recognize_constructed(text, font_hint=font_hint),
            "answer": None, "requires_human_review": True}


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise Refuse(message)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description="offline Unicode/script and constructed-script evidence")
    parser.add_argument("operation", choices=("analyze", "charset", "caesar", "constructed"))
    parser.add_argument("input")
    parser.add_argument("--script", choices=tuple(CAESAR_ALPHABETS))
    parser.add_argument("--font-hint", default="")
    try:
        args = parser.parse_args(argv)
        raw = Path(args.input).read_bytes()
        if len(raw) > MAX_BYTES:
            raise Refuse("input exceeds 4 MiB")
        if args.operation == "charset":
            result = charset_evidence(raw)
        else:
            text = raw.decode("utf-8", "strict")
            if args.operation == "analyze":
                result = analyze(text, font_hint=args.font_hint)
            elif args.operation == "constructed":
                result = {"candidates": recognize_constructed(text, font_hint=args.font_hint), "answer": None}
            else:
                if not args.script:
                    raise Refuse("caesar requires --script")
                result = {"candidates": nonlatin_caesar(text, args.script), "answer": None}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (OSError, UnicodeError, Refuse, ValueError, TypeError, OverflowError, MemoryError) as exc:
        print(f"language_depth: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
