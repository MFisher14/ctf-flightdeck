from __future__ import annotations

import importlib.util
import json
import random
import string
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))
import language_scripts as L  # noqa: E402
import transcript_automation as T  # noqa: E402

spec = importlib.util.spec_from_file_location("round5_brainflak", ROOT / "solvers" / "warmups" / "esolang_round5.py")
B = importlib.util.module_from_spec(spec)
assert spec and spec.loader
sys.modules[spec.name] = B
spec.loader.exec_module(B)


def test_encoding_candidates_include_strict_ebcdic_roundtrip():
    raw = "CSCTF{ebcdic}".encode("cp037")
    rows = L.encoding_candidates(raw)
    row = next(row for row in rows if row["text"] == "CSCTF{ebcdic}")
    assert "cp037" in row["codecs"] and row["verified_roundtrip"] is True
    assert row["candidate_only"] is True


def test_script_profile_normalization_tags_confusables_and_recognition():
    mixed = "pаypal"  # second character is Cyrillic a
    profile = L.script_profile(mixed)
    assert profile["mixed_confusable_scripts"] is True
    assert profile["confusable_skeleton"] == "paypal"
    assert L.normalization_views("Ａ")[2]["text"] == "A"  # NFKC
    tags = "".join(chr(0xE0000 + ord(ch)) for ch in "FLAG") + chr(0xE007F)
    assert L.hidden_unicode(tags)[0]["text"] == "FLAG"
    recognition = L.recognize_scripts("ᚠᚢᚦᚨᚱᚲ")
    assert recognition and recognition[0]["script"] == "Runic"
    assert recognition[0]["semantic_decode_verified"] is False


def test_separate_unicode_tag_runs_are_not_falsely_concatenated():
    encode = lambda value: "".join(chr(0xE0000 + ord(char)) for char in value) + chr(0xE007F)
    rows = [row for row in L.hidden_unicode(encode("ONE") + " visible " + encode("TWO"))
            if row["kind"] == "unicode_tags"]
    assert [row["text"] for row in rows] == ["ONE", "TWO"]
    assert all(row["terminated"] and row["verified_mapping"] for row in rows)


def test_nonlatin_caesar_roundtrip_and_exact_substitution():
    plain = "κρυπτο"
    encoded = L._shift(plain, 7, L.GREEK_LOWER, L.GREEK_UPPER)
    rows = L.nonlatin_caesar_candidates(encoded, "greek")
    hit = next(row for row in rows if row["encoded_shift"] == 7)
    assert hit["decoded"] == plain and hit["verified_roundtrip"] is True
    sub = L.substitute("αβγ", {"α": "a", "β": "b", "γ": "c"})
    assert sub["decoded"] == "abc" and sub["verified_roundtrip"] is True
    with pytest.raises(ValueError):
        L.substitute("ab", {"a": "b"})  # unchanged b collides with mapped output


def test_saved_prompt_math_and_mismatch_never_promoted():
    assert T.extended_math("What is factorial of 20?") == str(2432902008176640000)
    assert T.extended_math("Find GCD of 84 and 126") == "42"
    assert T.extended_math("Round 5: Find GCD of 84 and 126") == "42"
    assert T.extended_math("What is 30 choose 7?") == str(2035800)
    assert T.extended_math("Find modular inverse of 7 mod 101") == "29"
    row = T.answer_prompt("What is the 25th prime?")
    assert row["candidate_answer"] == "97" and row["sent"] is False
    report = T.analyze_transcript([
        {"direction": "recv", "data": "Convert ff from base 16 to base 10"},
        {"direction": "send", "data": "WRONG"},
    ])
    assert report["rounds"][0]["recorded_matches"] is False
    assert report["rounds"][0]["deterministic_replay_verified"] is True
    assert report["rounds"][0]["semantic_answer_verified"] is False
    assert report["rounds"][0]["candidate_consistent_with_recording"] is False


def test_literal_state_machine_replay_produces_unsent_plan():
    machine = {"states": [
        {"name": "prime", "expect_contains": "prime", "handler": "auto", "next": "fixed"},
        {"name": "fixed", "expect_contains": "ready", "send": "continue", "next": None},
    ]}
    report = T.replay_state_machine(machine, ["What is the 10th prime?", "ready >"])
    assert [row["candidate_send"] for row in report["steps"]] == ["29", "continue"]
    assert report["terminal"] is True and report["sent"] is False
    with pytest.raises(ValueError):
        T.replay_state_machine(machine, ["not the expected prompt"])


def test_brainflak_stack_candidates_include_exact_fixture_but_decline_convention():
    marker = b"CSCTF{brain_flak}"
    program = B.encode_fixture(marker)
    report = B.analyze(program)
    values = {bytes.fromhex(row["bytes_hex"]) for row in report["output_candidates"]}
    assert marker in values and marker[::-1] in values
    assert report["answer"] is None and report["requires_human_convention"] is True
    assert all(row["candidate_only"] for row in report["output_candidates"])
    with pytest.raises(B.Refuse):
        B.execute("([)]")


def test_brainflak_curly_monad_returns_sum_of_loop_evaluations():
    # (()) pushes 1; {{}} loops once and pops/evaluates 1.  The outer (...) therefore pushes 2.
    assert B.execute("((()){{}})")["stacks"][0] == [2]


def test_language_parser_mutation_fuzz_5000_cases():
    rng = random.Random(0x1A6A6E)
    alphabet = string.printable + "αβγЖЯᚠ\u200b\u202e\ud800\U000e0041"
    for _ in range(5000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 160)))
        profile = L.script_profile(text)
        views = L.normalization_views(text)
        hidden = L.hidden_unicode(text)
        assert isinstance(profile["scripts"], dict) and len(views) == 4 and len(hidden) <= 10


def test_transcript_parser_mutation_fuzz_5000_cases():
    rng = random.Random(0x7A45C)
    alphabet = string.ascii_letters + string.digits + " []{}:+-*/!?\n"
    for _ in range(5000):
        prompt = "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 140)))
        report = T.analyze_transcript([{"direction": "recv", "data": prompt}])
        assert report["sent"] is False and len(report["rounds"]) <= 1


def test_brainflak_parser_mutation_fuzz_5000_cases():
    rng = random.Random(0xBFA5)
    alphabet = "()[]{}<> xyz\n\t"
    for _ in range(5000):
        source = "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 100)))
        try:
            report = B.analyze(source)
            assert report["answer"] is None and report["steps"] <= B.MAX_STEPS
        except B.Refuse:
            pass


def test_guarded_clis(tmp_path, capsys):
    assert L.main([]) == 2
    assert "language_scripts:" in capsys.readouterr().err
    assert T.main([]) == 2
    assert "transcript_automation:" in capsys.readouterr().err
    assert B.main([]) == 2
    assert "esolang_round5:" in capsys.readouterr().err
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("What is 10 choose 2?", encoding="utf-8")
    assert T.main(["prompt", str(prompt)]) == 0
