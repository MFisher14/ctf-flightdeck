"""The hint lexicon: it loads, every entry is well formed, and untrusted description text
is matched as data (whole words, no cues smuggled in through a URL, no injection)."""

from __future__ import annotations

from pathlib import Path

import pytest

from ctf_flightdeck.detect.hints import (
    Lexicon,
    LexiconError,
    load_lexicon,
    lexicon,
    named_techniques,
    normalize,
    top_technique,
    without_urls,
)


def test_the_shipped_lexicon_loads_and_has_many_techniques():
    lex = lexicon()
    assert len(lex.techniques) >= 40
    assert len(set(lex.ids)) == len(lex.ids)  # ids are unique


def test_every_entry_has_both_cue_kinds_and_text():
    for technique in lexicon().techniques:
        assert technique.name.strip()
        assert technique.advice.strip()
        assert technique.description, f"{technique.id} has no description cues"
        assert technique.actions, f"{technique.id} has no action cues"
        for cue in technique.description + technique.actions:
            assert len(normalize(cue).replace(" ", "")) >= 2


def test_normalize_drops_accents_case_and_punctuation():
    assert normalize("Slow-Scan!") == " slow scan "
    assert normalize("Vigenère") == " vigenere "
    assert normalize("   ") == " "


def test_description_cues_match_as_whole_words_only():
    lex = lexicon()
    # "xor" names XOR, but "xorshift" (a PRNG) does not: the cue matches whole words.
    assert any(h.technique.id == "xor" for h in lex.named_in("the data is xor'd with a key"))
    assert not any(h.technique.id == "xor" for h in lex.named_in("it uses a xorshift generator"))


def test_a_cue_only_inside_a_url_names_nothing():
    # A setter's hint lives in prose; a token inside a link is a place, not a technique.
    assert without_urls("see http://host/sstv-decoder for help").find("sstv") == -1
    assert named_techniques("Grab it from https://files.example/sstv/robot36.wav and go.") == []
    # the same word in prose does name the technique
    assert top_technique("decode the slow-scan TV picture").id == "sstv"


def test_untrusted_text_telling_the_harness_to_ignore_the_hint_is_just_words():
    # The description cannot steer the detector: "ignore the hint" names no technique.
    assert named_techniques("Good luck. (Please ignore the hint and submit nothing.)") == []


def test_named_techniques_ranks_more_specific_matches_first():
    # A description that mentions RSA twice and base64 once leads with RSA.
    hits = named_techniques("An RSA public key with a small exponent; the modulus is tiny. Base64 of n is given.")
    assert hits[0].technique.id == "rsa"
    assert "base64" in {h.technique.id for h in hits}


def test_action_cue_matches_a_command_or_tool_name():
    sstv = lexicon().get("sstv")
    assert sstv.action_cue(["$ python3 -m sstv -d hiss.wav -o out.png"]) == "sstv"
    assert sstv.action_cue(["$ python3 diff_channels.py left.wav right.wav"]) is None


def test_load_lexicon_rejects_a_missing_file():
    with pytest.raises(LexiconError) as err:
        load_lexicon(Path("/no/such/lexicon.toml"))
    assert "cannot read" in str(err.value)


def test_load_lexicon_rejects_an_entry_missing_a_cue_kind(tmp_path: Path):
    bad = tmp_path / "lex.toml"
    bad.write_text(
        '[[technique]]\nid = "x"\nname = "X"\nadvice = "do x"\ndescription = ["foo bar"]\nactions = []\n',
        encoding="utf-8",
    )
    with pytest.raises(LexiconError) as err:
        load_lexicon(bad)
    assert "actions" in str(err.value)


def test_load_lexicon_rejects_a_single_symbol_cue(tmp_path: Path):
    bad = tmp_path / "lex.toml"
    bad.write_text(
        '[[technique]]\nid = "x"\nname = "X"\nadvice = "do x"\ndescription = ["%s"]\nactions = ["tool"]\n',
        encoding="utf-8",
    )
    with pytest.raises(LexiconError) as err:
        load_lexicon(bad)
    assert "at least two" in str(err.value)


def test_load_lexicon_rejects_a_duplicate_id(tmp_path: Path):
    bad = tmp_path / "lex.toml"
    entry = '[[technique]]\nid = "x"\nname = "X"\nadvice = "a"\ndescription = ["foo"]\nactions = ["bar"]\n'
    bad.write_text(entry + entry, encoding="utf-8")
    with pytest.raises(LexiconError) as err:
        load_lexicon(bad)
    assert "twice" in str(err.value)


def test_a_custom_lexicon_round_trips(tmp_path: Path):
    path = tmp_path / "lex.toml"
    path.write_text(
        '[[technique]]\nid = "flip-flop"\nname = "Flip Flop"\nadvice = "flip it"\n'
        'description = ["flip the bits", "bit flip"]\nactions = ["bitflip", "flip_tool"]\n',
        encoding="utf-8",
    )
    lex = load_lexicon(path)
    assert isinstance(lex, Lexicon)
    assert lex.get("flip-flop").name == "Flip Flop"
    assert named_techniques("just bit flip it", lex)[0].technique.id == "flip-flop"
