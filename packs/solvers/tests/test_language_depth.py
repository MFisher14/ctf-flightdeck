from __future__ import annotations

import random

import pytest

from solvers.toolkits import language_depth as L


def _tags(value: str, cancel: bool = True) -> str:
    encoded = "".join(chr(0xE0000 + ord(char)) for char in value)
    return encoded + (chr(0xE007F) if cancel else "")


def test_charset_evidence_is_roundtrip_only_and_keeps_byte_cues():
    raw = "مرحبا".encode("cp1256")
    report = L.charset_evidence(raw)
    hit = next(row for row in report["candidates"] if "cp1256" in row["codecs"])
    assert hit["text"] == "مرحبا" and hit["roundtrip_verified"] is True
    assert report["answer"] is None and report["null_position_counts"].keys() == {"2", "4"}
    assert L.charset_evidence(b"\xff\xfeA\x00")["bom"] == "utf-16-le"


def test_identifier_confusables_normalization_and_collisions():
    # Second spelling uses Cyrillic a; the fullwidth A is separately handled by NFKC.
    text = "paypal pаypal Ａdmin"
    report = L.identifier_audit(text)
    collision = next(row for row in report["skeleton_collisions"] if row["skeleton"] == "paypal")
    assert set(collision["spellings"]) == {"paypal", "pаypal"}
    skeleton = L.confusable_skeleton("Ａdmin")
    assert skeleton["skeleton"] == "Admin" and skeleton["candidate_only"] is True


def test_combining_bidi_and_unicode_tag_audits_preserve_evidence():
    combining = L.combining_audit("\u0301a\u0301\u0300\u0327")
    assert combining["orphan_mark_indices"] == [0]
    assert any(len(row["marks"]) == 3 for row in combining["stacked_mark_clusters"])

    bidi = L.bidi_audit("safe\u202eexe")
    assert bidi["controls"][0]["name"] == "RLO"
    assert bidi["unclosed_embeddings"] == [(4, "RLO")]
    assert bidi["views"][1]["verified"] is False

    tagged = L.tag_run_audit("x" + _tags("ONE") + "y" + _tags("TWO", cancel=False))
    assert [row["payload"] for row in tagged["runs"]] == ["ONE", "TWO"]
    assert tagged["visible_text"] == "xy" and tagged["has_unterminated_run"] is True


def test_zero_class_marks_nested_bidi_isolates_and_orphan_tag_cancel():
    variation = L.combining_audit("A\ufe0f")
    assert variation["marked_clusters"][0]["marks"][0]["combining_class"] == 0
    assert variation["marked_clusters"][0]["marks"][0]["category"] == "Mn"

    nested = L.bidi_audit("\u2066\u202eX\u2069")
    assert nested["unclosed_embeddings"] == [] and nested["unclosed_isolates"] == []
    assert nested["implicitly_closed_by_pdi"] == [{"index": 1, "name": "RLO", "closed_by_pdi": 3}]
    blocked_pdf = L.bidi_audit("\u202a\u2066\u202c\u2069\u202c")
    assert blocked_pdf["unmatched_closers"] == [{"index": 2, "name": "PDF"}]
    assert blocked_pdf["unclosed_embeddings"] == []

    cancel = chr(0xE007F)
    assert L.tag_run_audit(cancel)["orphan_cancel_indices"] == [0]


@pytest.mark.parametrize("script,plain", [
    ("hebrew", "אבגד"), ("arabic", "ابتث"), ("armenian", "աբգդ"), ("georgian", "აბგდ"),
])
def test_new_script_transliteration_and_caesar_are_explicit_about_scope(script, plain):
    evidence = L.transliteration_evidence(plain, script)
    assert evidence["changed"] is True and evidence["readable_reversible"] is False
    assert evidence["lossless_roundtrip_verified"] is True
    candidates = L.nonlatin_caesar(plain, script)
    assert candidates and all(row["roundtrip_verified"] for row in candidates)
    assert all(row["candidate_only"] for row in candidates)


def test_ambiguous_hebrew_finals_decline_and_constructed_scripts_never_decode():
    with pytest.raises(L.Refuse, match="final forms"):
        L.nonlatin_caesar("מלך", "hebrew")
    pigpen = L.recognize_constructed("⌜⌝⌞⌟┼•")
    assert pigpen[0]["candidate"].startswith("pigpen")
    assert pigpen[0]["decoded_text"] is None and pigpen[0]["semantic_decode_verified"] is False
    sga = L.recognize_constructed("ᔑʖᓵ↸ᒷ")
    assert "Galactic" in sga[0]["candidate"] and sga[0]["requires_human_glyph_review"]
    aurebesh = L.recognize_constructed("ABC", font_hint="Aurebesh Regular")
    assert aurebesh[0]["candidate"] == "aurebesh" and aurebesh[0]["decoded_text"] is None
    assert L.recognize_constructed("<<<<>>>>") == []


def test_decomposed_identifiers_surrogates_and_full_alphabet_caesar_edges():
    identifiers = L.identifier_audit("é e\u0301")
    collision = next(row for row in identifiers["skeleton_collisions"] if row["skeleton"] == "é")
    assert set(collision["spellings"]) == {"é", "e\u0301"}
    assert L.analyze("\ud800")["answer"] is None
    with pytest.raises(L.Refuse):
        L.script_of("ab")
    assert L.script_of(chr(0xF0000)) == "Private Use"
    assert L.script_of(chr(0xFFFFE)) != "Private Use"

    for script, (lower, upper) in L.CAESAR_ALPHABETS.items():
        text = lower + (upper or "")
        assert all(row["roundtrip_verified"] for row in L.nonlatin_caesar(text, script))
    assert (len(L.HEBREW), len(L.ARABIC), len(L.ARMENIAN_LOWER), len(L.ARMENIAN_UPPER),
            len(L.GEORGIAN)) == (22, 28, 38, 38, 33)


def test_seeded_unicode_audit_is_bounded_and_deterministic():
    rng = random.Random(0xA11CE)
    alphabet = "abcΑВСאבגابتաաբგ" + "\u0301\u200f\u202e"
    for _ in range(500):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 48)))
        report = L.analyze(text)
        assert report["answer"] is None and report["requires_human_review"] is True
        assert len(report["bidi"]["controls"]) <= len(text)


def test_guarded_cli(tmp_path, capsys):
    assert L.main([]) == 2
    assert "language_depth:" in capsys.readouterr().err
    path = tmp_path / "text.txt"
    path.write_text("אבגד", encoding="utf-8")
    assert L.main(["caesar", str(path), "--script", "hebrew"]) == 0
    assert '"answer": null' in capsys.readouterr().out
