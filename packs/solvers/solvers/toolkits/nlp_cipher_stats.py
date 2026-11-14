#!/usr/bin/env python3
"""Transparent multilingual and ciphertext statistics for offline triage.

This module ranks hypotheses only.  It deliberately does not crack ciphers or
turn a statistical score into an answer.  Existing classical-cipher machinery
is reused for the legacy English IoC/chi-square reference values.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Mapping, Sequence

from solvers.common import classical as _classical


MAX_TEXT_CHARS = 1_000_000
MAX_ANALYSIS_SYMBOLS = 200_000
MAX_AUTOCORRELATION_SHIFT = 128
MAX_PERIOD = 32
MAX_REPEATED_NGRAM_ROWS = 64


class Refuse(ValueError):
    """Input is malformed or exceeds an explicit deterministic bound."""


# Small, auditable marker profiles.  These are not opaque trained models.
_PROFILES: Mapping[str, Mapping[str, Any]] = {
    "english": {
        "stop": "the of and to in is it that for on are with as this be from or by not you have".split(),
        "grams": "the and ing ion tio ent her for tha nth".split(),
        "distinctive": "",
        "frequent": "etaoinshrdlu",
    },
    "romanian": {
        "stop": "și de în este la cu pentru un o că pe din nu se care".split(),
        "grams": "are ent rea ului ție str îna".split(),
        "distinctive": "ăâîșț",
        "frequent": "eairntulsodc",
    },
    "french": {
        "stop": "le la les de des du et est un une dans pour que qui avec sur pas ce".split(),
        "grams": "ent que les ion des est ait eur".split(),
        "distinctive": "àâçéèêëîïôùûüÿœ",
        "frequent": "esaitnruolcd",
    },
    "german": {
        "stop": "der die das und ist ein eine nicht mit auf für von zu den dem im".split(),
        "grams": "der die und sch ich ein den che".split(),
        "distinctive": "äöüß",
        "frequent": "enisratdhucl",
    },
    "spanish": {
        "stop": "el la los las de del y es un una que en por con para no se como".split(),
        "grams": "que ent los del con est las ión".split(),
        "distinctive": "ñáéíóúü¿¡",
        "frequent": "eaosrnidlctu",
    },
    "italian": {
        "stop": "il lo la gli le di del e è un una che in per con non si da".split(),
        "grams": "che del ell ion per ent gli".split(),
        "distinctive": "àèéìòù",
        "frequent": "eaionlrtscdu",
    },
    "portuguese": {
        "stop": "o a os as de do da e é um uma que em para com não por se".split(),
        "grams": "que ent ção não com dos est".split(),
        "distinctive": "ãõáéíóúâêôç",
        "frequent": "aeosridmntcu",
    },
    "dutch": {
        "stop": "de het een en van is dat op te voor met niet zijn als aan".split(),
        "grams": "het een van ing sch der".split(),
        "distinctive": "ĳ",
        "frequent": "enairtodslgv",
    },
    "polish": {
        "stop": "i w z na nie jest to że do się dla jak od po przez".split(),
        "grams": "nie prz cze się owa dzi".split(),
        "distinctive": "ąćęłńóśźż",
        "frequent": "aioenrzwscty",
    },
    "turkish": {
        "stop": "ve bir bu için ile değil olan da de mi ne olarak çok".split(),
        "grams": "bir lar ler ini eri dan".split(),
        "distinctive": "çğıöşü",
        "frequent": "aeinrlıkdmtu",
    },
    "russian": {
        "stop": "и в не на я что с это по из для как но он она мы вы".split(),
        "grams": "про ост ени ого что это ова".split(),
        "distinctive": "ыэёъьйщжцчшюя",
        "frequent": "оеаинтсрвлкм",
    },
    "greek": {
        "stop": "και το η ο σε από που είναι για με δεν την του τα ως".split(),
        "grams": "και του την εις στο για".split(),
        "distinctive": "αβγδεζηθικλμνξοπρστυφχψω",
        "frequent": "αοειτνρσκπμη",
    },
}


def _bounded_text(text: str) -> str:
    if not isinstance(text, str):
        raise Refuse("text must be a string")
    if len(text) > MAX_TEXT_CHARS:
        raise Refuse(f"text exceeds {MAX_TEXT_CHARS} characters")
    return unicodedata.normalize("NFKC", text)


def _words(text: str) -> list[str]:
    return re.findall(r"[^\W\d_]+", text.casefold(), flags=re.UNICODE)


def _script_counts(letters: str) -> Counter[str]:
    counts: Counter[str] = Counter()
    for char in letters:
        name = unicodedata.name(char, "")
        script = next(
            (candidate for candidate in ("LATIN", "CYRILLIC", "GREEK", "ARABIC", "HEBREW") if candidate in name),
            "OTHER",
        )
        counts[script.casefold()] += 1
    return counts


def _frequency_similarity(letters: str, expected_order: str) -> float:
    observed = [char for char, _ in Counter(letters).most_common(12)]
    if not observed:
        return 0.0
    expected = list(dict.fromkeys(expected_order))
    weighted = 0.0
    possible = 0.0
    for rank, char in enumerate(observed):
        weight = 12 - rank
        possible += weight
        if char in expected:
            distance = abs(rank - expected.index(char))
            weighted += weight * max(0.0, 1.0 - distance / 12.0)
    return weighted / possible if possible else 0.0


def rank_languages(text: str, *, limit: int = 5) -> dict[str, Any]:
    """Rank language candidates from explicit lexical/character statistics."""

    normalized = _bounded_text(text).casefold()
    words = _words(normalized)
    letters = "".join(words)
    if type(limit) is not int or not 1 <= limit <= len(_PROFILES):
        raise Refuse(f"limit must be in 1..{len(_PROFILES)}")
    scripts = _script_counts(letters)
    if len(letters) < 20:
        return {
            "candidates": [],
            "reason": "insufficient_sample",
            "letter_count": len(letters),
            "word_count": len(words),
            "script_counts": dict(sorted(scripts.items())),
            "candidate_only": True,
        }

    token_counts = Counter(words)
    rows: list[dict[str, Any]] = []
    for language, profile in _PROFILES.items():
        stop_hits = sum(token_counts[word] for word in profile["stop"])
        gram_counts = {gram: normalized.count(gram) for gram in profile["grams"]}
        gram_hits = sum(gram_counts.values())
        distinctive_counts = {
            char: normalized.count(char) for char in profile["distinctive"] if char in normalized
        }
        distinctive_hits = sum(distinctive_counts.values())
        frequency_similarity = _frequency_similarity(letters, profile["frequent"])
        lexical_density = stop_hits / max(1, len(words))
        gram_density = gram_hits * 100.0 / max(1, len(letters))
        score = (
            9.0 * lexical_density
            + 1.6 * gram_density
            + min(3.0, distinctive_hits * 0.45)
            + 1.2 * frequency_similarity
        )
        rows.append({
            "language": language,
            "score": round(score, 6),
            "evidence": {
                "stopword_hits": stop_hits,
                "lexical_density": round(lexical_density, 6),
                "ngram_hits": gram_hits,
                "ngram_density_per_100_letters": round(gram_density, 6),
                "matched_ngrams": {key: value for key, value in gram_counts.items() if value},
                "distinctive_character_hits": distinctive_hits,
                "matched_distinctive_characters": distinctive_counts,
                "frequency_order_similarity": round(frequency_similarity, 6),
            },
        })
    rows.sort(key=lambda row: (-row["score"], row["language"]))

    # Do not let a relative ranking manufacture confidence from random text.
    top = rows[0]
    top_signal = (
        top["evidence"]["stopword_hits"]
        + top["evidence"]["ngram_hits"]
        + top["evidence"]["distinctive_character_hits"]
    )
    sufficient = len(letters) >= 40 and top_signal >= 2 and top["score"] >= 1.0
    if sufficient:
        weights = [math.exp(min(20.0, row["score"] - top["score"])) for row in rows]
        total = sum(weights)
        for row, weight in zip(rows, weights):
            row["relative_confidence"] = round(weight / total, 6)
        candidates = rows[:limit]
        reason = "ranked_evidence"
    else:
        candidates = []
        reason = "insufficient_discriminating_evidence"
    return {
        "candidates": candidates,
        "reason": reason,
        "letter_count": len(letters),
        "word_count": len(words),
        "script_counts": dict(sorted(scripts.items())),
        "candidate_only": True,
        "requires_human_confirmation": True,
    }


def _index_of_coincidence(stream: str) -> float:
    n = len(stream)
    if n < 2:
        return 0.0
    return sum(count * (count - 1) for count in Counter(stream).values()) / (n * (n - 1))


def _longest_run(stream: str) -> tuple[int, int]:
    if not stream:
        return 0, 0
    longest = current = 1
    repeated_runs = 0
    for previous, char in zip(stream, stream[1:]):
        if char == previous:
            current += 1
        else:
            if current >= 2:
                repeated_runs += 1
            longest = max(longest, current)
            current = 1
    if current >= 2:
        repeated_runs += 1
    return max(longest, current), repeated_runs


def _repeated_ngrams(stream: str) -> tuple[list[dict[str, Any]], int | None]:
    rows: list[dict[str, Any]] = []
    all_distances: list[int] = []
    for size in range(2, 6):
        positions: defaultdict[str, list[int]] = defaultdict(list)
        counts: Counter[str] = Counter()
        for offset in range(0, max(0, len(stream) - size + 1)):
            gram = stream[offset : offset + size]
            counts[gram] += 1
            bucket = positions[gram]
            # Enough positions to expose periods without unbounded hot buckets.
            if len(bucket) < 256:
                bucket.append(offset)
        for gram, offsets in positions.items():
            if len(offsets) < 2:
                continue
            distances = [right - left for left, right in zip(offsets, offsets[1:])]
            all_distances.extend(distances)
            rows.append({
                "ngram": gram,
                "size": size,
                "count": counts[gram],
                "positions": offsets[:16],
                "successive_distances": distances[:16],
            })
    rows.sort(key=lambda row: (-row["size"], -row["count"], row["ngram"]))
    gcd_value: int | None = None
    for distance in all_distances:
        gcd_value = distance if gcd_value is None else math.gcd(gcd_value, distance)
    return rows[:MAX_REPEATED_NGRAM_ROWS], gcd_value


def ciphertext_statistics(
    text: str,
    *,
    max_shift: int = MAX_AUTOCORRELATION_SHIFT,
    max_period: int = MAX_PERIOD,
) -> dict[str, Any]:
    """Compute auditable entropy, IoC, repetition, run, and period features."""

    normalized = _bounded_text(text).casefold()
    if type(max_shift) is not int or not 1 <= max_shift <= MAX_AUTOCORRELATION_SHIFT:
        raise Refuse(f"max_shift must be in 1..{MAX_AUTOCORRELATION_SHIFT}")
    if type(max_period) is not int or not 2 <= max_period <= MAX_PERIOD:
        raise Refuse(f"max_period must be in 2..{MAX_PERIOD}")
    stream = "".join(char for char in normalized if not char.isspace())
    if len(stream) > MAX_ANALYSIS_SYMBOLS:
        raise Refuse(f"non-space stream exceeds {MAX_ANALYSIS_SYMBOLS} symbols")
    letters = "".join(char for char in normalized if char.isalpha())
    n = len(stream)
    counts = Counter(stream)
    alphabet_size = len(counts)

    entropy = 0.0
    if n:
        entropy = -sum((count / n) * math.log2(count / n) for count in counts.values())
    normalized_entropy = entropy / math.log2(alphabet_size) if alphabet_size > 1 else 0.0
    uniform_chi_square = (
        sum((count - n / alphabet_size) ** 2 / (n / alphabet_size) for count in counts.values())
        if n and alphabet_size
        else 0.0
    )
    maximum_share = max(counts.values(), default=0) / max(1, n)
    excess_max_share = maximum_share - (1.0 / alphabet_size if alphabet_size else 0.0)
    longest_run, repeated_run_count = _longest_run(stream)

    autocorrelation: list[dict[str, Any]] = []
    for shift in range(1, min(max_shift, n - 1) + 1):
        comparisons = n - shift
        matches = sum(left == right for left, right in zip(stream[:-shift], stream[shift:]))
        autocorrelation.append({
            "shift": shift,
            "matches": matches,
            "comparisons": comparisons,
            "rate": round(matches / comparisons, 8),
        })
    autocorrelation.sort(key=lambda row: (-row["rate"], row["shift"]))

    period_rows: list[dict[str, Any]] = []
    for period in range(2, min(max_period, max(2, len(letters))) + 1):
        columns = [letters[offset::period] for offset in range(period)]
        usable = [column for column in columns if len(column) >= 2]
        average = sum(_index_of_coincidence(column) for column in usable) / len(usable) if usable else 0.0
        period_rows.append({
            "period": period,
            "average_column_ioc": round(average, 8),
            "shortest_column": min((len(column) for column in columns), default=0),
        })
    period_rows.sort(key=lambda row: (-row["average_column_ioc"], row["period"]))

    repeated, distance_gcd = _repeated_ngrams(stream)
    letter_ioc = _index_of_coincidence(letters)
    friedman: float | None = None
    if len(letters) >= 2:
        denominator = (len(letters) - 1) * letter_ioc - 0.038 * len(letters) + 0.065
        if denominator > 0:
            estimate = 0.027 * len(letters) / denominator
            if math.isfinite(estimate) and 0.25 <= estimate <= 10_000:
                friedman = estimate

    # Reuse the existing classical lane rather than silently forking its
    # English-only definitions.  These values intentionally use A-Z only.
    legacy_ioc = _classical.ioc(normalized)
    legacy_chi = _classical.chi2(normalized)
    return {
        "stream_length": n,
        "letter_count": len(letters),
        "alphabet_size": alphabet_size,
        "symbol_counts": dict(sorted(counts.items(), key=lambda item: (-item[1], item[0]))),
        "shannon_entropy_bits_per_symbol": round(entropy, 8),
        "normalized_entropy": round(normalized_entropy, 8),
        "index_of_coincidence": round(_index_of_coincidence(stream), 8),
        "letter_index_of_coincidence": round(letter_ioc, 8),
        "uniform_chi_squared": round(uniform_chi_square, 8),
        "frequency_skew": {
            "maximum_symbol_share": round(maximum_share, 8),
            "excess_over_uniform_share": round(excess_max_share, 8),
        },
        "runs": {"longest_identical_run": longest_run, "repeated_run_count": repeated_run_count},
        "autocorrelation_peaks": autocorrelation[:16],
        "period_column_ioc_rank": period_rows[:16],
        "friedman_key_length_estimate": round(friedman, 6) if friedman is not None else None,
        "repeated_ngrams": repeated,
        "repeated_ngram_distance_gcd": distance_gcd,
        "legacy_classical_reference": {
            "implementation": "solvers.common.classical",
            "ascii_letter_ioc": round(legacy_ioc, 8),
            "english_chi_squared": round(legacy_chi, 8) if math.isfinite(legacy_chi) else None,
        },
        "bounded": True,
    }


def rank_cipher_families(text: str) -> dict[str, Any]:
    """Return broad, deliberately non-exclusive cipher/encoding hypotheses."""

    normalized = _bounded_text(text)
    stats = ciphertext_statistics(normalized)
    language = rank_languages(normalized, limit=3)
    compact = "".join(char for char in normalized if not char.isspace())
    rows: list[dict[str, Any]] = []

    def add(family: str, score: float, evidence: list[str], caveat: str) -> None:
        rows.append({
            "family": family,
            "score": round(min(1.0, max(0.0, score)), 4),
            "evidence": evidence,
            "caveat": caveat,
        })

    n = stats["stream_length"]
    alphabet = stats["alphabet_size"]
    entropy = stats["normalized_entropy"]
    letter_ioc = stats["letter_index_of_coincidence"]
    if n >= 20 and alphabet <= 5:
        add(
            "small-alphabet encoding or symbolic cipher",
            0.72,
            [f"alphabet has only {alphabet} symbols"],
            "Could be ordinary low-alphabet data; inspect delimiters and provenance.",
        )
    if compact and re.fullmatch(r"(?:[0-9a-fA-F]{2})+", compact):
        add(
            "hexadecimal representation",
            0.93,
            ["even-length stream consists entirely of hexadecimal digit pairs"],
            "Representation is not itself proof of encryption.",
        )
    if len(compact) >= 16 and len(compact) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", compact):
        add(
            "base64-like representation",
            0.82,
            ["alphabet and padding shape match conventional Base64"],
            "Many identifiers accidentally match; decode only as a candidate transform.",
        )
    if language["candidates"]:
        top_language = language["candidates"][0]
        add(
            "natural-language plaintext",
            min(0.88, 0.45 + top_language["relative_confidence"] * 0.45),
            [f"ranked {top_language['language']} from explicit lexical/ngram evidence"],
            "Language statistics are evidence, never answer proof.",
        )
    if stats["letter_count"] >= 40 and letter_ioc >= 0.052:
        add(
            "monoalphabetic substitution or transposition",
            min(0.8, 0.48 + (letter_ioc - 0.052) * 5),
            [f"letter IoC {letter_ioc:.4f} preserves natural-language-like collisions"],
            "IoC cannot distinguish substitution from transposition or plaintext.",
        )
    period_rows = stats["period_column_ioc_rank"]
    best_period = period_rows[0] if period_rows else None
    if (
        stats["letter_count"] >= 60
        and letter_ioc < 0.052
        and best_period is not None
        and best_period["average_column_ioc"] >= letter_ioc + 0.008
    ):
        add(
            "periodic polyalphabetic cipher",
            min(0.82, 0.5 + (best_period["average_column_ioc"] - letter_ioc) * 5),
            [
                f"period {best_period['period']} raises mean column IoC to "
                f"{best_period['average_column_ioc']:.4f} from {letter_ioc:.4f}"
            ],
            "Short samples and repeated templates can create the same peak.",
        )
    if n >= 64 and entropy >= 0.94 and not language["candidates"]:
        add(
            "high-entropy encoded, compressed, or polyalphabetic data",
            min(0.75, 0.45 + (entropy - 0.94) * 4),
            [f"normalized symbol entropy is {entropy:.4f} with no ranked language"],
            "Entropy alone cannot distinguish encryption, compression, and random data.",
        )
    if stats["repeated_ngram_distance_gcd"] not in {None, 1}:
        add(
            "periodic or block-structured transform",
            0.52,
            [f"repeated-ngram distance GCD is {stats['repeated_ngram_distance_gcd']}"],
            "Formatting or repeated words may create the same distance structure.",
        )

    rows.sort(key=lambda row: (-row["score"], row["family"]))
    return {
        "candidates": rows,
        "verdict": None,
        "candidate_only": True,
        "requires_human_confirmation": True,
        "statistics": stats,
        "language_ranking": language,
    }


def analyze(text: str) -> dict[str, Any]:
    return rank_cipher_families(text)


# Descriptive aliases for callers that search by the terms used in prompts.
language_id = rank_languages
cipher_statistics = ciphertext_statistics
cipher_family_candidates = rank_cipher_families


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path")
    parser.add_argument("--mode", choices=("all", "language", "statistics"), default="all")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        with Path(args.path).open(encoding="utf-8", errors="replace") as stream:
            text = stream.read(MAX_TEXT_CHARS + 1)
        if args.mode == "language":
            result = rank_languages(text)
        elif args.mode == "statistics":
            result = ciphertext_statistics(text)
        else:
            result = rank_cipher_families(text)
        print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
        return 0
    except (Refuse, OSError, ValueError) as exc:
        print(f"nlp_cipher_stats: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = [
    "Refuse",
    "analyze",
    "cipher_family_candidates",
    "cipher_statistics",
    "ciphertext_statistics",
    "language_id",
    "rank_cipher_families",
    "rank_languages",
]
