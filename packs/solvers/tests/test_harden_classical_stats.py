"""Independent numerical oracles and fail-closed probes for existing NLP stats.

Oracles: scipy.stats.entropy/chisquare, exhaustive unordered-pair collision
probability, RFC 4648 section 10 examples, and the labelled English first
sentence of UDHR Article 1. No expected statistic uses engine-generated output.
https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.entropy.html
https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.chisquare.html
https://www.rfc-editor.org/rfc/rfc4648#section-10
https://www.un.org/en/about-us/universal-declaration-of-human-rights
"""
import base64
from collections import Counter
from itertools import combinations
import json
import random

import pytest
from scipy.stats import chisquare, entropy

import nlp_cipher_stats as engine


ENGLISH = "All human beings are born free and equal in dignity and rights."
STAT_APIS = (engine.ciphertext_statistics, engine.cipher_statistics)
LANG_APIS = (engine.rank_languages, engine.language_id)
FAMILY_APIS = (engine.rank_cipher_families, engine.cipher_family_candidates, engine.analyze)
ALL_APIS = STAT_APIS + LANG_APIS + FAMILY_APIS


def _collision_probability(symbols):
    """Independent combinatorial oracle; deliberately not the count formula."""
    pairs = list(combinations(symbols, 2))
    return sum(left == right for left, right in pairs) / len(pairs) if pairs else 0.0


def _clean_or_declared_error(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except engine.Refuse:
        return None


@pytest.mark.parametrize("function", STAT_APIS, ids=("ciphertext_statistics", "cipher_statistics"))
@pytest.mark.parametrize("sample", ("ABBCCCDDDD", "ABABABAB", "A!A!BBCC", "XYZ", "AAAAA"))
def test_statistics_independent_scipy_and_collision_vectors(function, sample):
    stream = sample.lower()
    letters = "".join(c for c in stream if c.isalpha())
    counts = list(Counter(stream).values())
    result = function(sample, max_shift=4, max_period=4)
    assert result["symbol_counts"] == dict(Counter(stream))
    assert result["shannon_entropy_bits_per_symbol"] == pytest.approx(entropy(counts, base=2), abs=5e-9)
    assert result["uniform_chi_squared"] == pytest.approx(chisquare(counts).statistic, abs=5e-9)
    assert result["index_of_coincidence"] == pytest.approx(_collision_probability(stream), abs=5e-9)
    assert result["letter_index_of_coincidence"] == pytest.approx(_collision_probability(letters), abs=5e-9)
    assert result["legacy_classical_reference"]["ascii_letter_ioc"] == pytest.approx(_collision_probability(letters), abs=5e-9)
    assert result["stream_length"] == len(stream)
    assert result["alphabet_size"] == len(counts)


def test_period_and_repetition_hand_worked_vector():
    # ABABABAB: shifts 2,4 match every position; shifts1,3 none. Every second
    # letter is constant, so the period2 columns have collision probability1.
    result = engine.ciphertext_statistics("ABABABAB", max_shift=4, max_period=4)
    assert result["autocorrelation_peaks"] == [
        {"shift": 2, "matches": 6, "comparisons": 6, "rate": 1.0},
        {"shift": 4, "matches": 4, "comparisons": 4, "rate": 1.0},
        {"shift": 1, "matches": 0, "comparisons": 7, "rate": 0.0},
        {"shift": 3, "matches": 0, "comparisons": 5, "rate": 0.0},
    ]
    periods = {r["period"]: r for r in result["period_column_ioc_rank"]}
    assert periods[2]["average_column_ioc"] == 1.0
    assert periods[3]["average_column_ioc"] == pytest.approx((1/3 + 1/3 + 0)/3, abs=5e-9)
    assert result["repeated_ngram_distance_gcd"] == 2
    assert result["runs"] == {"longest_identical_run": 1, "repeated_run_count": 0}
    grams = {r["ngram"]: r for r in result["repeated_ngrams"]}
    assert grams["ab"]["count"] == 4
    assert grams["ab"]["positions"] == [0, 2, 4, 6]


@pytest.mark.parametrize("function", LANG_APIS, ids=("rank_languages", "language_id"))
def test_published_english_language_label(function):
    result = function(ENGLISH)
    # UN's English publication is the independent label, not an engine score.
    assert result["candidates"][0]["language"] == "english"
    assert result["word_count"] == 12
    assert result["letter_count"] == 51
    assert result["script_counts"] == {"latin": 51}
    assert result["candidate_only"] is True


@pytest.mark.parametrize("function", LANG_APIS, ids=("rank_languages", "language_id"))
def test_unicode_known_scripts_and_nfkc(function):
    # Fullwidth A becomes Latin A; Greek alpha and Cyrillic a stay distinct.
    result = function("ＡΑА")
    assert result["letter_count"] == 3
    assert result["script_counts"] == {"latin": 1, "greek": 1, "cyrillic": 1}
    assert result["candidates"] == []


@pytest.mark.parametrize("function", FAMILY_APIS, ids=("rank_cipher_families", "cipher_family_candidates", "analyze"))
def test_rfc4648_representation_vectors(function):
    # RFC4648 test vector: BASE64('foobar') = Zm9vYmFy. Twelve input bytes
    # align the two published blocks without padding inside the final encoding.
    raw = b"foobarfoobar"
    encoded = base64.b64encode(raw).decode("ascii")
    assert encoded == "Zm9vYmFyZm9vYmFy"
    result = function(encoded)
    assert "base64-like representation" in {r["family"] for r in result["candidates"]}
    assert result["statistics"]["stream_length"] == 16
    assert result["verdict"] is None
    hexadecimal = function("666F6F626172")  # RFC4648 BASE16('foobar').
    assert "hexadecimal representation" in {r["family"] for r in hexadecimal["candidates"]}


@pytest.mark.parametrize("mode", ("statistics", "language", "all"))
def test_main_valid_file_vector(mode, tmp_path, capsys):
    path = tmp_path / "input.txt"
    source = "ABBCCCDDDD" if mode == "statistics" else ENGLISH
    path.write_text(source)
    assert engine.main([str(path), "--mode", mode]) == 0
    result = json.loads(capsys.readouterr().out)
    if mode == "statistics":
        assert result["shannon_entropy_bits_per_symbol"] == pytest.approx(entropy([1, 2, 3, 4], base=2), abs=5e-9)
    elif mode == "language":
        assert result["candidates"][0]["language"] == "english"
    else:
        assert result["language_ranking"]["candidates"][0]["language"] == "english"


_rng = random.Random(0xC1A551CA1)
JUNK_CASES = [
    pytest.param("", id="empty"),
    pytest.param("\x00\x01\x1f\x7f", id="controls"),
    pytest.param("\ud800\udfff\ufffe\uffff", id="surrogates-noncharacters"),
    pytest.param("ßİﬃKＡαЖعא\u0301\u200d🙂", id="unicode-normalization-scripts"),
    pytest.param(" \t\r\n" * 1000, id="whitespace"),
    pytest.param("".join(chr(_rng.randrange(128)) for _ in range(512)), id="random-ascii-seed"),
    pytest.param("".join(chr(_rng.randrange(0x110000)) for _ in range(512)), id="random-unicode-seed"),
    pytest.param("AB09!?" * 1000, id="long-under-limit"),
    pytest.param("A" * 1_000_001, id="over-text-limit"),
    pytest.param(None, id="none"),
    pytest.param(b"ABC", id="bytes"),
    pytest.param({}, id="mapping"),
    pytest.param(17, id="integer"),
]


@pytest.mark.parametrize("function", ALL_APIS, ids=("ciphertext_statistics", "cipher_statistics", "rank_languages", "language_id", "rank_cipher_families", "cipher_family_candidates", "analyze"))
@pytest.mark.parametrize("junk", JUNK_CASES)
def test_fail_closed_text_fuzz(function, junk):
    result = _clean_or_declared_error(function, junk)
    assert result is None or isinstance(result, dict)


@pytest.mark.parametrize("option", ("max_shift", "max_period"))
@pytest.mark.parametrize("value", (-1, 0, 1000, float("nan"), float("inf")))
def test_numeric_option_boundaries_refuse_cleanly(option, value):
    with pytest.raises(engine.Refuse):
        engine.ciphertext_statistics("ABCDE", **{option: value})


@pytest.mark.parametrize("value", (None, "5", [], 1.5))
def test_bug_language_limit_noninteger_fails_closed(value):
    with pytest.raises(engine.Refuse):
        engine.rank_languages(ENGLISH, limit=value)


@pytest.mark.parametrize("option", ("max_shift", "max_period"))
@pytest.mark.parametrize("value", (None, "2", [], 2.5))
def test_bug_statistics_noninteger_options_fail_closed(option, value):
    with pytest.raises(engine.Refuse):
        engine.ciphertext_statistics("ABCDE", **{option: value})


def test_bug_repeated_ngram_count_not_bucket_cap():
    sample = "AB" * 300
    expected = sum(sample[i:i+2] == "AB" for i in range(len(sample)-1))
    assert expected == 300
    result = engine.ciphertext_statistics(sample, max_shift=2, max_period=2)
    row = next(r for r in result["repeated_ngrams"] if r["ngram"] == "ab")
    assert row["count"] == expected
    assert row["positions"] == list(range(0, 32, 2))
    assert row["successive_distances"] == [2] * 16


@pytest.mark.parametrize("argv,expected", (([], 2), (["--help"], 0), (["--bad-option"], 2)))
def test_bug_main_argparse_guard(argv, expected):
    assert engine.main(argv) == expected


def test_bug_main_missing_file_fail_closed(tmp_path):
    assert engine.main([str(tmp_path / "absent.txt")]) == 2


def test_bug_main_nul_path_fail_closed():
    assert engine.main(["\x00"]) == 2
