"""The commit guard's denylist: names a player must never commit match however they are written."""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path

HOOK = Path(__file__).resolve().parents[1] / ".githooks" / "secret_scan.py"


def _load():
    spec = importlib.util.spec_from_file_location("secret_scan", HOOK)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scan_mod = _load()


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def hits(data: bytes, *names: str) -> list[str]:
    blocks, _ = scan_mod.scan("notes.md", data, {digest(name) for name in names})
    return [rule for rule in blocks if rule.startswith("denylisted value")]


def test_a_short_handle_is_caught_in_any_case_and_next_to_punctuation():
    for text in (b"thanks zed!", b"Zed: try again", b"(ZED)", b"handle=zed\n"):
        assert hits(text, "zed") == [f"denylisted value [sha256:{digest('zed')[:8]}]"], text


def test_a_two_word_team_name_is_caught_however_its_words_are_joined():
    for text in (b"we are Quokka Crew.", b"quokka  crew", b"Quokka\ncrew", b"quokka-crew", b"Quokka_Crew rocks"):
        assert hits(text, "quokka crew"), text


def test_a_joined_name_can_be_denylisted_as_written():
    assert hits(b"team: quokka-crew", "quokka-crew")
    assert hits(b"team: Quokka_Crew", "quokka_crew")


def test_words_that_merely_contain_a_name_are_not_hits():
    assert hits(b"zedonk and amazed", "zed") == []
    assert hits(b"quokka crewmate", "quokka crew") == []


def test_a_name_four_words_long_is_caught_and_the_report_never_shows_it():
    name = "the quiet quokka crew"
    blocks, _ = scan_mod.scan("notes.md", b"by The Quiet Quokka Crew, 2026", {digest(name)})
    assert blocks == [f"denylisted value [sha256:{digest(name)[:8]}]"]
    assert all("quokka" not in rule.lower() for rule in blocks)


def test_the_allow_pragma_never_overrides_a_denylist_hit():
    assert hits(b"zed  # secret-scan: allow", "zed")


def test_token_shaped_values_still_match_exactly_as_written():
    token = "Ab3dEf6hIj9kLm2nOp5q"  # 20 characters, mixed case
    assert hits(f"key={token}".encode(), token)
    assert hits(f"key={token.lower()}".encode(), token) == []
